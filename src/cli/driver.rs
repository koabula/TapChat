use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use futures_util::StreamExt;
use reqwest::Client;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Duration, Instant};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};

use crate::ffi_api::{
    CoreCommand, CoreEffect, CoreEngine, CoreEvent, CoreOutput, HttpMethod, PersistStateEffect,
    RealtimeEvent, RealtimeSessionSnapshot, RecoveryContextSnapshot, RecoveryDiagnostics,
    SyncCheckpointSnapshot,
};
use crate::model::{DeviceStatusKind, Envelope, IdentityBundle, MessageType, MlsStateStatus};
use crate::persistence::CorePersistenceSnapshot;
use crate::platform_ports::{
    execute_platform_effect, BlobIoPort, NotificationPort, PersistencePort, RealtimePort,
    SecureStoragePort, TimerPort, TransportPort,
};
use crate::transport_contract::{
    AppendEnvelopeRequest, AppendGroupEnvelopeRequest, AppendGroupEnvelopeResult,
    BlobDownloadRequest, BlobUploadRequest, CreateGroupInviteRequest, CreateGroupInviteResult,
    DecideGroupJoinRequest, DecideGroupJoinResult, FetchAllowlistRequest, FetchGroupInviteRequest,
    FetchGroupInviteResult, FetchGroupOutboxRequest, FetchGroupOutboxResult,
    FetchIdentityBundleRequest, FetchMessageRequestsRequest, FetchWelcomePickupRequest,
    FetchWelcomePickupResult, GetGroupJoinRequestStatusRequest, GetGroupJoinRequestStatusResult,
    GetGroupOutboxHeadRequest, GetGroupOutboxHeadResult, ListGroupJoinRequestsRequest,
    ListGroupJoinRequestsResult, MessageRequestActionRequest, PrepareBlobUploadRequest,
    PublishSharedStateRequest, PutWelcomePickupRequest, PutWelcomePickupResult,
    RealtimeSubscriptionRequest, ReplaceAllowlistRequest, RevokeGroupInviteRequest,
    RevokeGroupInviteResult, SealGroupOutboxRequest, SealGroupOutboxResult, SubmitGroupJoinRequest,
    SubmitGroupJoinResult,
};

use super::util::{
    extract_error_code, extract_sealed_at, to_camel_case_json_string, to_snake_case_json_string,
};

pub struct DriverRuntime {
    client: Client,
    websocket_tx: UnboundedSender<CoreEvent>,
    websocket_rx: UnboundedReceiver<CoreEvent>,
    websocket_tasks: BTreeMap<String, JoinHandle<()>>,
    latest_snapshot: Option<CorePersistenceSnapshot>,
    notifications: Vec<String>,
    scheduled_timers: Vec<ScheduledTimer>,
    storage_prepare_url: Option<String>,
    contact_share_url: Option<String>,
    recent_appends: Vec<Envelope>,
    recent_messages: Vec<(String, MessageType)>,
}

pub struct CoreDriver {
    engine: CoreEngine,
    runtime: DriverRuntime,
    suppress_realtime: bool,
}

#[derive(Debug, Clone)]
struct ScheduledTimer {
    timer_id: String,
    delay_ms: u64,
    scheduled_at: Instant,
}

const MAX_TIMER_EVENTS_PER_RUN: usize = 256;
const MAX_TIMER_EVENTS_PER_ID: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ContactDeviceSnapshot {
    pub device_id: String,
    pub status: DeviceStatusKind,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ConversationMemberSnapshot {
    pub user_id: String,
    pub device_id: String,
    pub status: DeviceStatusKind,
}

#[allow(dead_code)]
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PendingMlsArtifacts {
    pub pending_welcome_count: usize,
    pub pending_commit_count: usize,
}

impl CoreDriver {
    pub fn from_snapshot(
        snapshot: CorePersistenceSnapshot,
        base_url: Option<String>,
        contact_share_url: Option<String>,
    ) -> Result<Self> {
        let latest_snapshot = snapshot.clone();
        let (websocket_tx, websocket_rx) = mpsc::unbounded_channel();
        Ok(Self {
            engine: CoreEngine::from_restored_state(snapshot),
            runtime: DriverRuntime {
                client: Client::builder()
                    .build()
                    .context("build driver reqwest client")?,
                websocket_tx,
                websocket_rx,
                websocket_tasks: BTreeMap::new(),
                latest_snapshot: Some(latest_snapshot),
                notifications: Vec::new(),
                scheduled_timers: Vec::new(),
                storage_prepare_url: base_url.map(|value| {
                    format!("{}/v1/storage/prepare-upload", value.trim_end_matches('/'))
                }),
                contact_share_url,
                recent_appends: Vec::new(),
                recent_messages: Vec::new(),
            },
            suppress_realtime: false,
        })
    }

    pub fn latest_snapshot(&self) -> Option<&CorePersistenceSnapshot> {
        self.runtime.latest_snapshot.as_ref()
    }

    pub fn notifications(&self) -> &[String] {
        &self.runtime.notifications
    }

    pub fn pending_outbox_count(&self) -> usize {
        self.runtime
            .latest_snapshot
            .as_ref()
            .map(|snapshot| snapshot.pending_outbox.len())
            .unwrap_or_default()
    }

    pub fn pending_blob_upload_count(&self) -> usize {
        self.runtime
            .latest_snapshot
            .as_ref()
            .map(|snapshot| snapshot.pending_blob_transfers.len())
            .unwrap_or_default()
    }

    pub fn local_identity(&self) -> Option<&crate::identity::LocalIdentityState> {
        self.engine.local_identity()
    }

    pub fn local_bundle(&self) -> Option<&IdentityBundle> {
        self.engine.local_bundle()
    }

    pub fn local_display_name(&self) -> Option<String> {
        self.engine.local_display_name()
    }

    pub fn contact_bundle(&self, user_id: &str) -> Option<&IdentityBundle> {
        self.engine.contact_bundle(user_id)
    }

    pub fn conversation_state(
        &self,
        conversation_id: &str,
    ) -> Option<&crate::conversation::LocalConversationState> {
        self.engine.conversation_state(conversation_id)
    }

    pub fn mls_status(&self, conversation_id: &str) -> Option<MlsStateStatus> {
        self.engine
            .mls_summary(conversation_id)
            .map(|summary| summary.status)
    }

    pub fn contact_devices(&self, user_id: &str) -> Vec<ContactDeviceSnapshot> {
        self.engine
            .contact_bundle(user_id)
            .map(|bundle| {
                bundle
                    .devices
                    .iter()
                    .map(|device| ContactDeviceSnapshot {
                        device_id: device.device_id.clone(),
                        status: device.status,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn conversation_members(&self, conversation_id: &str) -> Vec<ConversationMemberSnapshot> {
        self.engine
            .conversation_state(conversation_id)
            .map(|state| {
                state
                    .conversation
                    .member_devices
                    .iter()
                    .map(|member| ConversationMemberSnapshot {
                        user_id: member.user_id.clone(),
                        device_id: member.device_id.clone(),
                        status: member.status,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    #[allow(dead_code)]
    pub fn conversation_recovery_status(
        &self,
        conversation_id: &str,
    ) -> Option<crate::conversation::RecoveryStatus> {
        self.engine
            .conversation_state(conversation_id)
            .map(|state| state.recovery_status)
    }

    #[allow(dead_code)]
    pub fn snapshot_has_recovery_context(&self, conversation_id: &str) -> bool {
        self.runtime
            .latest_snapshot
            .as_ref()
            .map(|snapshot| {
                snapshot
                    .recovery_contexts
                    .iter()
                    .any(|context| context.conversation_id == conversation_id)
            })
            .unwrap_or(false)
    }

    #[allow(dead_code)]
    pub fn pending_mls_artifacts(&self, conversation_id: &str) -> PendingMlsArtifacts {
        let mut artifacts = PendingMlsArtifacts::default();
        let Some(snapshot) = self.runtime.latest_snapshot.as_ref() else {
            for envelope in &self.runtime.recent_appends {
                if envelope.conversation_id != conversation_id {
                    continue;
                }
                match envelope.message_type {
                    MessageType::MlsWelcome => {
                        artifacts.pending_welcome_count =
                            artifacts.pending_welcome_count.saturating_add(1);
                    }
                    MessageType::MlsCommit => {
                        artifacts.pending_commit_count =
                            artifacts.pending_commit_count.saturating_add(1);
                    }
                    _ => {}
                }
            }
            for (recent_conversation_id, message_type) in &self.runtime.recent_messages {
                if recent_conversation_id != conversation_id {
                    continue;
                }
                match message_type {
                    MessageType::MlsWelcome => {
                        artifacts.pending_welcome_count =
                            artifacts.pending_welcome_count.saturating_add(1);
                    }
                    MessageType::MlsCommit => {
                        artifacts.pending_commit_count =
                            artifacts.pending_commit_count.saturating_add(1);
                    }
                    _ => {}
                }
            }
            return artifacts;
        };
        for item in &snapshot.pending_outbox {
            if item.envelope.conversation_id != conversation_id {
                continue;
            }
            match item.envelope.message_type {
                MessageType::MlsWelcome => {
                    artifacts.pending_welcome_count =
                        artifacts.pending_welcome_count.saturating_add(1);
                }
                MessageType::MlsCommit => {
                    artifacts.pending_commit_count =
                        artifacts.pending_commit_count.saturating_add(1);
                }
                _ => {}
            }
        }
        for envelope in &self.runtime.recent_appends {
            if envelope.conversation_id != conversation_id {
                continue;
            }
            match envelope.message_type {
                MessageType::MlsWelcome => {
                    artifacts.pending_welcome_count =
                        artifacts.pending_welcome_count.saturating_add(1);
                }
                MessageType::MlsCommit => {
                    artifacts.pending_commit_count =
                        artifacts.pending_commit_count.saturating_add(1);
                }
                _ => {}
            }
        }
        for (recent_conversation_id, message_type) in &self.runtime.recent_messages {
            if recent_conversation_id != conversation_id {
                continue;
            }
            match message_type {
                MessageType::MlsWelcome => {
                    artifacts.pending_welcome_count =
                        artifacts.pending_welcome_count.saturating_add(1);
                }
                MessageType::MlsCommit => {
                    artifacts.pending_commit_count =
                        artifacts.pending_commit_count.saturating_add(1);
                }
                _ => {}
            }
        }
        artifacts
    }

    pub fn recovery_context_snapshot(
        &self,
        conversation_id: &str,
    ) -> Option<RecoveryContextSnapshot> {
        self.engine.recovery_context_snapshot(conversation_id)
    }

    pub fn recovery_conversations(&self) -> Vec<RecoveryDiagnostics> {
        self.engine.recovery_conversations_snapshot()
    }

    pub fn sync_checkpoint_snapshot(&self, device_id: &str) -> Option<SyncCheckpointSnapshot> {
        self.engine.sync_checkpoint_snapshot(device_id)
    }

    pub fn realtime_session_snapshot(&self, device_id: &str) -> Option<RealtimeSessionSnapshot> {
        self.engine.realtime_session_snapshot(device_id)
    }

    pub async fn run_command_until_idle(&mut self, command: CoreCommand) -> Result<CoreOutput> {
        self.suppress_realtime = false;
        let output = self.engine.handle_command(command)?;
        let output = self.execute_until_idle(output).await?;
        self.sync_latest_snapshot();
        self.record_observed_output(&output);
        Ok(output)
    }

    pub async fn run_command_until_idle_without_realtime(
        &mut self,
        command: CoreCommand,
    ) -> Result<CoreOutput> {
        self.suppress_realtime = true;
        let output = self.engine.handle_command(command)?;
        let output = self.execute_until_idle(output).await?;
        self.suppress_realtime = false;
        self.sync_latest_snapshot();
        self.record_observed_output(&output);
        Ok(output)
    }

    pub async fn inject_event_until_idle(&mut self, event: CoreEvent) -> Result<CoreOutput> {
        let output = self.engine.handle_event(event)?;
        let output = self.execute_until_idle(output).await?;
        self.sync_latest_snapshot();
        self.record_observed_output(&output);
        Ok(output)
    }

    pub async fn pump_until_idle(&mut self, max_wait: Duration) -> Result<Vec<CoreOutput>> {
        let deadline = Instant::now() + max_wait;
        let mut outputs = Vec::new();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let event = match timeout(
                remaining.min(Duration::from_millis(250)),
                self.runtime.websocket_rx.recv(),
            )
            .await
            {
                Ok(Some(event)) => event,
                Ok(None) => break,
                Err(_) => break,
            };
            outputs.push(self.inject_event_until_idle(event).await?);
        }
        Ok(outputs)
    }

    pub async fn close_realtime(&mut self, device_id: &str) -> Result<()> {
        if let Some(task) = self.runtime.websocket_tasks.remove(device_id) {
            task.abort();
        }
        self.engine.clear_realtime_reconnect(device_id);
        self.sync_latest_snapshot();
        Ok(())
    }

    async fn execute_until_idle(&mut self, mut output: CoreOutput) -> Result<CoreOutput> {
        let mut processed_timers = 0usize;
        let mut timer_counts = BTreeMap::<String, usize>::new();
        loop {
            let effects = std::mem::take(&mut output.effects);
            if effects.is_empty() {
                if let Some(timer_event) =
                    self.take_due_timer_event(&mut processed_timers, &mut timer_counts)?
                {
                    output = merge_outputs(
                        output,
                        self.engine
                            .handle_event(timer_event.clone())
                            .map_err(|error| {
                                anyhow!("event {:?} failed: {}", timer_event, error)
                            })?,
                    );
                    continue;
                }
                break;
            }
            let mut processed_any_event = false;
            for effect in effects {
                let emitted_events = self.execute_effect(effect).await?;
                for event in emitted_events {
                    processed_any_event = true;
                    output = merge_outputs(
                        output,
                        self.engine
                            .handle_event(event.clone())
                            .map_err(|error| anyhow!("event {:?} failed: {}", event, error))?,
                    );
                }
            }
            while let Some(timer_event) =
                self.take_due_timer_event(&mut processed_timers, &mut timer_counts)?
            {
                processed_any_event = true;
                output = merge_outputs(
                    output,
                    self.engine
                        .handle_event(timer_event.clone())
                        .map_err(|error| anyhow!("event {:?} failed: {}", timer_event, error))?,
                );
            }
            if !processed_any_event {
                break;
            }
        }
        Ok(output)
    }

    async fn execute_effect(&mut self, effect: CoreEffect) -> Result<Vec<CoreEvent>> {
        if self.suppress_realtime {
            match effect {
                CoreEffect::OpenRealtimeConnection { .. }
                | CoreEffect::CloseRealtimeConnection { .. } => {
                    return Ok(Vec::new());
                }
                _ => {}
            }
        }
        execute_platform_effect(self, effect).await
    }

    async fn execute_http_request(
        &mut self,
        request: crate::ffi_api::HttpRequestEffect,
    ) -> Result<Vec<CoreEvent>> {
        let method = match request.method {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
            HttpMethod::Put => reqwest::Method::PUT,
            HttpMethod::Delete => reqwest::Method::DELETE,
        };
        let mut builder = self.runtime.client.request(method, &request.url);
        for (key, value) in &request.headers {
            let header_value = if key.eq_ignore_ascii_case("X-Tapchat-Capability") {
                to_camel_case_json_string(value)?
            } else {
                value.clone()
            };
            builder = builder.header(key, header_value);
        }
        if let Some(body) = request.body.as_deref() {
            if request.url.contains("/messages") {
                let mut append_request: AppendEnvelopeRequest = serde_json::from_str(body)?;
                if append_request.sender_bundle_share_url.is_none() {
                    append_request.sender_bundle_share_url = self.runtime.contact_share_url.clone();
                }
                if append_request.sender_bundle_hash.is_none() {
                    append_request.sender_bundle_hash = self
                        .engine
                        .local_bundle()
                        .map(|bundle| bundle.signature.clone());
                }
                self.runtime
                    .recent_appends
                    .push(append_request.envelope.clone());
                let converted =
                    to_camel_case_json_string(&serde_json::to_string(&append_request)?)?;
                builder = builder.body(converted);
                return match builder.send().await {
                    Ok(response) => {
                        let status = response.status().as_u16();
                        let content_type = response
                            .headers()
                            .get(reqwest::header::CONTENT_TYPE)
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or_default()
                            .to_string();
                        let body = response
                            .text()
                            .await
                            .ok()
                            .filter(|value| !value.is_empty())
                            .map(|value| {
                                if content_type.contains("application/json") {
                                    to_snake_case_json_string(&value).unwrap_or(value)
                                } else {
                                    value
                                }
                            });
                        Ok(vec![CoreEvent::HttpResponseReceived {
                            request_id: request.request_id,
                            status,
                            body,
                        }])
                    }
                    Err(error) => Ok(vec![CoreEvent::HttpRequestFailed {
                        request_id: request.request_id,
                        retryable: true,
                        detail: Some(error.to_string()),
                    }]),
                };
            }
            let converted = if looks_like_json(body) {
                to_camel_case_json_string(body)?
            } else {
                body.to_string()
            };
            builder = builder.body(converted);
        }
        match builder.send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                let content_type = response
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                let body = response
                    .text()
                    .await
                    .ok()
                    .filter(|value| !value.is_empty())
                    .map(|value| {
                        if content_type.contains("application/json") {
                            to_snake_case_json_string(&value).unwrap_or(value)
                        } else {
                            value
                        }
                    });
                Ok(vec![CoreEvent::HttpResponseReceived {
                    request_id: request.request_id,
                    status,
                    body,
                }])
            }
            Err(error) => Ok(vec![CoreEvent::HttpRequestFailed {
                request_id: request.request_id,
                retryable: true,
                detail: Some(error.to_string()),
            }]),
        }
    }

    async fn open_realtime(
        &mut self,
        subscription: RealtimeSubscriptionRequest,
    ) -> Result<Vec<CoreEvent>> {
        let endpoint = subscription
            .endpoint
            .replace("{deviceId}", &urlencoding::encode(&subscription.device_id));
        let mut request = endpoint.into_client_request()?;
        for (key, value) in &subscription.headers {
            request.headers_mut().insert(
                reqwest::header::HeaderName::from_bytes(key.as_bytes())?,
                reqwest::header::HeaderValue::from_str(value)?,
            );
        }
        let (stream, _) = connect_async(request)
            .await
            .context("open realtime websocket")?;
        let device_id = subscription.device_id.clone();
        let sender = self.runtime.websocket_tx.clone();
        let task_device_id = device_id.clone();
        let handle = tokio::spawn(async move {
            let (_, mut read) = stream.split();
            while let Some(message) = read.next().await {
                match message {
                    Ok(Message::Text(text)) => {
                        if let Ok(event) = parse_realtime_event(&task_device_id, &text) {
                            let _ = sender.send(event);
                        }
                    }
                    Ok(Message::Close(_)) => break,
                    Ok(_) => {}
                    Err(error) => {
                        let _ = sender.send(CoreEvent::WebSocketDisconnected {
                            device_id: task_device_id.clone(),
                            reason: Some(error.to_string()),
                        });
                        return;
                    }
                }
            }
            let _ = sender.send(CoreEvent::WebSocketDisconnected {
                device_id: task_device_id,
                reason: Some("remote closed".into()),
            });
        });
        self.runtime
            .websocket_tasks
            .insert(device_id.clone(), handle);
        Ok(vec![CoreEvent::WebSocketConnected { device_id }])
    }

    async fn fetch_identity_bundle(
        &mut self,
        fetch: FetchIdentityBundleRequest,
    ) -> Result<Vec<CoreEvent>> {
        let reference = fetch
            .reference
            .ok_or_else(|| anyhow!("identity bundle fetch missing reference"))?;
        match self.runtime.client.get(reference).send().await {
            Ok(response) if response.status().is_success() => {
                let body = response.text().await?;
                let bundle: IdentityBundle =
                    serde_json::from_str(&to_snake_case_json_string(&body)?)?;
                Ok(vec![CoreEvent::IdentityBundleFetched {
                    user_id: fetch.user_id,
                    bundle,
                }])
            }
            Ok(response) => Ok(vec![CoreEvent::IdentityBundleFetchFailed {
                user_id: fetch.user_id,
                retryable: false,
                detail: Some(format!("status {}", response.status())),
            }]),
            Err(error) => Ok(vec![CoreEvent::IdentityBundleFetchFailed {
                user_id: fetch.user_id,
                retryable: true,
                detail: Some(error.to_string()),
            }]),
        }
    }

    async fn fetch_message_requests(
        &mut self,
        fetch: FetchMessageRequestsRequest,
    ) -> Result<Vec<CoreEvent>> {
        let mut request = self.runtime.client.get(fetch.endpoint);
        for (key, value) in &fetch.headers {
            request = request.header(key, value);
        }
        match request.send().await {
            Ok(response) if response.status().is_success() => {
                let body = response.text().await?;
                let normalized = to_snake_case_json_string(&body)?;
                let value: serde_json::Value = serde_json::from_str(&normalized)?;
                let requests = serde_json::from_value(
                    value
                        .get("requests")
                        .cloned()
                        .unwrap_or_else(|| serde_json::json!([])),
                )?;
                Ok(vec![CoreEvent::MessageRequestsFetched { requests }])
            }
            Ok(response) => Ok(vec![CoreEvent::MessageRequestsFetchFailed {
                retryable: false,
                detail: Some(format!(
                    "list message requests failed with status {}",
                    response.status()
                )),
            }]),
            Err(error) => Ok(vec![CoreEvent::MessageRequestsFetchFailed {
                retryable: true,
                detail: Some(error.to_string()),
            }]),
        }
    }

    async fn act_on_message_request(
        &mut self,
        action: MessageRequestActionRequest,
    ) -> Result<Vec<CoreEvent>> {
        let mut request = self.runtime.client.post(format!(
            "{}/{}/{}",
            action.endpoint.trim_end_matches('/'),
            urlencoding::encode(&action.request_id),
            match action.action {
                crate::transport_contract::MessageRequestAction::Accept => "accept",
                crate::transport_contract::MessageRequestAction::Reject => "reject",
            }
        ));
        for (key, value) in &action.headers {
            request = request.header(key, value);
        }
        match request.send().await {
            Ok(response) if response.status().is_success() => {
                let body = response.text().await?;
                let normalized = to_snake_case_json_string(&body)?;
                let value: serde_json::Value = serde_json::from_str(&normalized)?;
                let result = crate::transport_contract::MessageRequestActionResult {
                    accepted: value
                        .get("accepted")
                        .and_then(|field| field.as_bool())
                        .unwrap_or(false),
                    request_id: value
                        .get("request_id")
                        .and_then(|field| field.as_str())
                        .unwrap_or(&action.request_id)
                        .to_string(),
                    sender_user_id: value
                        .get("sender_user_id")
                        .and_then(|field| field.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    promoted_count: value
                        .get("promoted_count")
                        .and_then(|field| field.as_u64())
                        .unwrap_or_default(),
                    action: action.action,
                    sender_bundle_share_url: value
                        .get("sender_bundle_share_url")
                        .and_then(|field| field.as_str())
                        .map(|value| value.to_string()),
                    sender_bundle_hash: value
                        .get("sender_bundle_hash")
                        .and_then(|field| field.as_str())
                        .map(|value| value.to_string()),
                    sender_display_name: value
                        .get("sender_display_name")
                        .and_then(|field| field.as_str())
                        .map(|value| value.to_string()),
                    promoted_conversation_ids: value
                        .get("promoted_conversation_ids")
                        .and_then(|field| field.as_array())
                        .map(|items| {
                            items
                                .iter()
                                .filter_map(|item| item.as_str().map(ToOwned::to_owned))
                                .collect()
                        })
                        .unwrap_or_default(),
                };
                Ok(vec![CoreEvent::MessageRequestActionCompleted { result }])
            }
            Ok(response) => Ok(vec![CoreEvent::MessageRequestActionFailed {
                request_id: action.request_id,
                action: action.action,
                retryable: false,
                detail: Some(format!(
                    "message request action failed with status {}",
                    response.status()
                )),
            }]),
            Err(error) => Ok(vec![CoreEvent::MessageRequestActionFailed {
                request_id: action.request_id,
                action: action.action,
                retryable: true,
                detail: Some(error.to_string()),
            }]),
        }
    }

    async fn fetch_allowlist(&mut self, fetch: FetchAllowlistRequest) -> Result<Vec<CoreEvent>> {
        let mut request = self.runtime.client.get(fetch.endpoint);
        for (key, value) in &fetch.headers {
            request = request.header(key, value);
        }
        match request.send().await {
            Ok(response) if response.status().is_success() => {
                let body = response.text().await?;
                let document = serde_json::from_str(&to_snake_case_json_string(&body)?)?;
                Ok(vec![CoreEvent::AllowlistFetched { document }])
            }
            Ok(response) => Ok(vec![CoreEvent::AllowlistFetchFailed {
                retryable: false,
                detail: Some(format!(
                    "get allowlist failed with status {}",
                    response.status()
                )),
            }]),
            Err(error) => Ok(vec![CoreEvent::AllowlistFetchFailed {
                retryable: true,
                detail: Some(error.to_string()),
            }]),
        }
    }

    async fn replace_allowlist(
        &mut self,
        update: ReplaceAllowlistRequest,
    ) -> Result<Vec<CoreEvent>> {
        let mut request = self.runtime.client.put(update.endpoint);
        for (key, value) in &update.headers {
            request = request.header(key, value);
        }
        let body = serde_json::to_string(&serde_json::json!({
            "allowedSenderUserIds": update.document.allowed_sender_user_ids,
            "rejectedSenderUserIds": update.document.rejected_sender_user_ids,
        }))?;
        match request
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                let body = response.text().await?;
                let document = serde_json::from_str(&to_snake_case_json_string(&body)?)?;
                Ok(vec![CoreEvent::AllowlistReplaced { document }])
            }
            Ok(response) => Ok(vec![CoreEvent::AllowlistReplaceFailed {
                retryable: false,
                detail: Some(format!(
                    "put allowlist failed with status {}",
                    response.status()
                )),
            }]),
            Err(error) => Ok(vec![CoreEvent::AllowlistReplaceFailed {
                retryable: true,
                detail: Some(error.to_string()),
            }]),
        }
    }

    async fn publish_shared_state(
        &mut self,
        publish: PublishSharedStateRequest,
    ) -> Result<Vec<CoreEvent>> {
        let mut request = self.runtime.client.put(publish.reference.clone());
        for (key, value) in &publish.headers {
            request = request.header(key, value);
        }
        match request
            .header("Content-Type", "application/json")
            .body(to_camel_case_json_string(&publish.body)?)
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                Ok(vec![CoreEvent::SharedStatePublished {
                    document_kind: publish.document_kind,
                    reference: publish.reference,
                }])
            }
            Ok(response) => Ok(vec![CoreEvent::SharedStatePublishFailed {
                document_kind: publish.document_kind,
                reference: publish.reference,
                retryable: false,
                detail: Some(format!(
                    "shared state publish failed with status {}",
                    response.status()
                )),
            }]),
            Err(error) => Ok(vec![CoreEvent::SharedStatePublishFailed {
                document_kind: publish.document_kind,
                reference: publish.reference,
                retryable: true,
                detail: Some(error.to_string()),
            }]),
        }
    }

    async fn prepare_blob_upload(
        &self,
        upload: PrepareBlobUploadRequest,
    ) -> Result<Vec<CoreEvent>> {
        let url = self
            .runtime
            .storage_prepare_url
            .clone()
            .ok_or_else(|| anyhow!("storage prepare url is not configured"))?;
        let mut request = self.runtime.client.post(url);
        for (key, value) in &upload.headers {
            request = request.header(key, value);
        }
        let body = serde_json::to_string(&upload)?;
        match request.body(to_camel_case_json_string(&body)?).send().await {
            Ok(response) if response.status().is_success() => {
                let body = response.text().await?;
                let result = serde_json::from_str(&to_snake_case_json_string(&body)?)?;
                Ok(vec![CoreEvent::BlobUploadPrepared {
                    task_id: upload.task_id,
                    result,
                }])
            }
            Ok(response) => Ok(vec![CoreEvent::BlobTransferFailed {
                task_id: upload.task_id,
                retryable: false,
                detail: Some(format!(
                    "prepare upload failed with status {}",
                    response.status()
                )),
            }]),
            Err(error) => Ok(vec![CoreEvent::BlobTransferFailed {
                task_id: upload.task_id,
                retryable: true,
                detail: Some(error.to_string()),
            }]),
        }
    }

    async fn read_attachment_bytes(
        &self,
        read: crate::ffi_api::ReadAttachmentBytesEffect,
    ) -> Result<Vec<CoreEvent>> {
        let bytes = tokio::fs::read(&read.attachment_id)
            .await
            .context("read attachment bytes")?;
        Ok(vec![CoreEvent::AttachmentBytesLoaded {
            task_id: read.task_id,
            plaintext_b64: STANDARD.encode(bytes),
        }])
    }

    async fn upload_blob(&self, upload: BlobUploadRequest) -> Result<Vec<CoreEvent>> {
        let bytes = STANDARD
            .decode(&upload.blob_ciphertext_b64)
            .context("decode upload blob ciphertext")?;
        let mut request = self.runtime.client.put(upload.upload_target.clone());
        for (key, value) in &upload.upload_headers {
            request = request.header(key, value);
        }
        match request.body(bytes).send().await {
            Ok(response) if response.status().is_success() => Ok(vec![CoreEvent::BlobUploaded {
                task_id: upload.task_id,
            }]),
            Ok(response) => Ok(vec![CoreEvent::BlobTransferFailed {
                task_id: upload.task_id,
                retryable: false,
                detail: Some(format!("upload failed with status {}", response.status())),
            }]),
            Err(error) => Ok(vec![CoreEvent::BlobTransferFailed {
                task_id: upload.task_id,
                retryable: true,
                detail: Some(error.to_string()),
            }]),
        }
    }

    async fn download_blob(&self, download: BlobDownloadRequest) -> Result<Vec<CoreEvent>> {
        let mut request = self.runtime.client.get(download.download_target.clone());
        for (key, value) in &download.download_headers {
            request = request.header(key, value);
        }
        match request.send().await {
            Ok(response) if response.status().is_success() => {
                let bytes = response.bytes().await?;
                Ok(vec![CoreEvent::BlobDownloaded {
                    task_id: download.task_id,
                    blob_ciphertext: Some(STANDARD.encode(&bytes)),
                }])
            }
            Ok(response) => Ok(vec![CoreEvent::BlobTransferFailed {
                task_id: download.task_id,
                retryable: false,
                detail: Some(format!("download failed with status {}", response.status())),
            }]),
            Err(error) => Ok(vec![CoreEvent::BlobTransferFailed {
                task_id: download.task_id,
                retryable: true,
                detail: Some(error.to_string()),
            }]),
        }
    }

    async fn write_downloaded_attachment(
        &self,
        write: crate::ffi_api::WriteDownloadedAttachmentEffect,
    ) -> Result<Vec<CoreEvent>> {
        let bytes = STANDARD
            .decode(&write.plaintext_b64)
            .context("decode downloaded attachment plaintext")?;
        if let Some(parent) = PathBuf::from(&write.destination_id).parent() {
            tokio::fs::create_dir_all(parent).await.ok();
        }
        tokio::fs::write(&write.destination_id, &bytes).await?;
        Ok(Vec::new())
    }

    fn persist_state(&mut self, persist: PersistStateEffect) -> Result<()> {
        if let Some(snapshot) = persist.snapshot {
            self.runtime.latest_snapshot = Some(snapshot);
        }
        Ok(())
    }

    fn take_due_timer_event(
        &mut self,
        processed_timers: &mut usize,
        timer_counts: &mut BTreeMap<String, usize>,
    ) -> Result<Option<CoreEvent>> {
        let now = Instant::now();
        let Some(index) =
            self.runtime.scheduled_timers.iter().position(|timer| {
                now >= timer.scheduled_at + Duration::from_millis(timer.delay_ms)
            })
        else {
            return Ok(None);
        };

        let timer = self.runtime.scheduled_timers.remove(index);
        *processed_timers += 1;
        if *processed_timers > MAX_TIMER_EVENTS_PER_RUN {
            return Err(anyhow!("timer guard exceeded while driving core effects"));
        }
        let count = timer_counts.entry(timer.timer_id.clone()).or_default();
        *count += 1;
        if *count > MAX_TIMER_EVENTS_PER_ID {
            return Err(anyhow!(
                "timer guard exceeded for {} while driving core effects",
                timer.timer_id
            ));
        }
        Ok(Some(CoreEvent::TimerTriggered {
            timer_id: timer.timer_id,
        }))
    }

    fn record_observed_output(&mut self, output: &CoreOutput) {
        let Some(view_model) = output.view_model.as_ref() else {
            return;
        };
        self.runtime.recent_messages.extend(
            view_model
                .messages
                .iter()
                .map(|message| (message.conversation_id.clone(), message.message_type)),
        );
    }

    fn sync_latest_snapshot(&mut self) {
        self.runtime.latest_snapshot = Some(self.engine.refresh_snapshot());
    }
}

impl TransportPort for CoreDriver {
    async fn execute_http_request(
        &mut self,
        request: crate::ffi_api::HttpRequestEffect,
    ) -> Result<Vec<CoreEvent>> {
        CoreDriver::execute_http_request(self, request).await
    }

    async fn fetch_identity_bundle(
        &mut self,
        fetch: FetchIdentityBundleRequest,
    ) -> Result<Vec<CoreEvent>> {
        CoreDriver::fetch_identity_bundle(self, fetch).await
    }

    async fn fetch_message_requests(
        &mut self,
        fetch: FetchMessageRequestsRequest,
    ) -> Result<Vec<CoreEvent>> {
        CoreDriver::fetch_message_requests(self, fetch).await
    }

    async fn act_on_message_request(
        &mut self,
        action: MessageRequestActionRequest,
    ) -> Result<Vec<CoreEvent>> {
        CoreDriver::act_on_message_request(self, action).await
    }

    async fn fetch_allowlist(&mut self, fetch: FetchAllowlistRequest) -> Result<Vec<CoreEvent>> {
        CoreDriver::fetch_allowlist(self, fetch).await
    }

    async fn replace_allowlist(
        &mut self,
        update: ReplaceAllowlistRequest,
    ) -> Result<Vec<CoreEvent>> {
        CoreDriver::replace_allowlist(self, update).await
    }

    async fn publish_shared_state(
        &mut self,
        publish: PublishSharedStateRequest,
    ) -> Result<Vec<CoreEvent>> {
        CoreDriver::publish_shared_state(self, publish).await
    }

    async fn append_group_envelope(
        &mut self,
        append: AppendGroupEnvelopeRequest,
    ) -> Result<Vec<CoreEvent>> {
        let endpoint = self
            .engine
            .refresh_snapshot()
            .group_states
            .iter()
            .find(|state| state.group_id == append.group_id)
            .map(|state| state.manifest.outbox.endpoint.clone())
            .ok_or_else(|| anyhow!("group outbox endpoint is missing"))?;
        let request = self
            .runtime
            .client
            .post(endpoint)
            .header(
                "Authorization",
                format!("Bearer {}", append.capability.signature),
            )
            .header(
                "X-Tapchat-Group-Capability",
                to_camel_case_json_string(&serde_json::to_string(&append.capability)?)?,
            )
            .header("Content-Type", "application/json")
            .body(to_camel_case_json_string(&serde_json::to_string(&append)?)?);
        match request.send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                let body = response.text().await.unwrap_or_default();
                if !(200..300).contains(&status) {
                    return Ok(vec![CoreEvent::GroupEnvelopeAppendFailed {
                        group_id: append.group_id,
                        message_id: append.envelope.message_id,
                        retryable: status >= 500,
                        detail: Some(body),
                    }]);
                }
                let body = to_snake_case_json_string(&body).unwrap_or(body);
                let result: AppendGroupEnvelopeResult = serde_json::from_str(&body)?;
                Ok(vec![CoreEvent::GroupEnvelopeAppended {
                    group_id: append.group_id,
                    message_id: append.envelope.message_id,
                    seq: result.seq,
                }])
            }
            Err(error) => Ok(vec![CoreEvent::GroupEnvelopeAppendFailed {
                group_id: append.group_id,
                message_id: append.envelope.message_id,
                retryable: true,
                detail: Some(error.to_string()),
            }]),
        }
    }

    async fn fetch_group_outbox(
        &mut self,
        fetch: FetchGroupOutboxRequest,
    ) -> Result<Vec<CoreEvent>> {
        let base = self
            .engine
            .refresh_snapshot()
            .deployment
            .map(|deployment| deployment.deployment_bundle.inbox_http_endpoint)
            .ok_or_else(|| anyhow!("deployment bundle is missing"))?;
        let url = format!(
            "{}/v1/groups/{}/outbox/messages?fromSeq={}&limit={}",
            base.trim_end_matches('/'),
            fetch.group_id,
            fetch.from_seq,
            fetch.limit
        );
        let request = self
            .runtime
            .client
            .get(url)
            .header(
                "Authorization",
                format!("Bearer {}", fetch.capability.signature),
            )
            .header(
                "X-Tapchat-Group-Capability",
                to_camel_case_json_string(&serde_json::to_string(&fetch.capability)?)?,
            );
        match request.send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                let body = response.text().await.unwrap_or_default();
                if !(200..300).contains(&status) {
                    return Ok(vec![CoreEvent::GroupOutboxFetchFailed {
                        group_id: fetch.group_id,
                        retryable: status >= 500,
                        detail: Some(body),
                    }]);
                }
                let body = to_snake_case_json_string(&body).unwrap_or(body);
                let result: FetchGroupOutboxResult = serde_json::from_str(&body)?;
                Ok(vec![CoreEvent::GroupOutboxFetched {
                    group_id: fetch.group_id,
                    records: result.records,
                    to_seq: result.to_seq,
                }])
            }
            Err(error) => Ok(vec![CoreEvent::GroupOutboxFetchFailed {
                group_id: fetch.group_id,
                retryable: true,
                detail: Some(error.to_string()),
            }]),
        }
    }

    async fn get_group_outbox_head(
        &mut self,
        get: GetGroupOutboxHeadRequest,
    ) -> Result<Vec<CoreEvent>> {
        let base = self
            .engine
            .refresh_snapshot()
            .deployment
            .map(|deployment| deployment.deployment_bundle.inbox_http_endpoint)
            .ok_or_else(|| anyhow!("deployment bundle is missing"))?;
        let url = format!(
            "{}/v1/groups/{}/outbox/head",
            base.trim_end_matches('/'),
            get.group_id
        );
        let response = match self
            .runtime
            .client
            .get(url)
            .header(
                "Authorization",
                format!("Bearer {}", get.capability.signature),
            )
            .header(
                "X-Tapchat-Group-Capability",
                to_camel_case_json_string(&serde_json::to_string(&get.capability)?)?,
            )
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                return Ok(vec![CoreEvent::GroupOutboxHeadFetchFailed {
                    group_id: get.group_id,
                    retryable: true,
                    detail: Some(error.to_string()),
                }]);
            }
        };
        let status = response.status().as_u16();
        let body_text = response.text().await.unwrap_or_default();
        if !(200..300).contains(&status) {
            return Ok(vec![CoreEvent::GroupOutboxHeadFetchFailed {
                group_id: get.group_id,
                retryable: status >= 500,
                detail: Some(body_text),
            }]);
        }
        let body = to_snake_case_json_string(&body_text).unwrap_or(body_text);
        let result: GetGroupOutboxHeadResult = match serde_json::from_str(&body) {
            Ok(result) => result,
            Err(error) => {
                return Ok(vec![CoreEvent::GroupOutboxHeadFetchFailed {
                    group_id: get.group_id,
                    retryable: false,
                    detail: Some(error.to_string()),
                }]);
            }
        };
        Ok(vec![CoreEvent::GroupOutboxHeadFetched {
            group_id: get.group_id,
            head_seq: result.head_seq,
        }])
    }

    /// Owner-signed seal of a group outbox. Issues `POST /v1/groups/<id>/
    /// outbox/seal` with the same capability/bearer pattern as the other
    /// group endpoints. Maps:
    ///   - 200 → `CoreEvent::GroupOutboxSealed { was_already_sealed: false }`
    ///   - 409 `already_sealed` → `GroupOutboxSealed { was_already_sealed: true }`
    ///     (terminal state identical)
    ///   - 403 → `GroupOutboxSealFailed { retryable: false }`
    ///   - 5xx / network → `GroupOutboxSealFailed { retryable: true }`
    ///   - body parse errors → `GroupOutboxSealFailed { retryable: false }`
    async fn seal_group_outbox(&mut self, seal: SealGroupOutboxRequest) -> Result<Vec<CoreEvent>> {
        let base = self
            .engine
            .refresh_snapshot()
            .deployment
            .map(|deployment| deployment.deployment_bundle.inbox_http_endpoint)
            .ok_or_else(|| anyhow!("deployment bundle is missing"))?;
        let url = format!(
            "{}/v1/groups/{}/outbox/seal",
            base.trim_end_matches('/'),
            seal.group_id
        );

        let response = match self
            .runtime
            .client
            .post(url)
            .header(
                "Authorization",
                format!("Bearer {}", seal.capability.signature),
            )
            .header(
                "X-Tapchat-Group-Capability",
                to_camel_case_json_string(&serde_json::to_string(&seal.capability)?)?,
            )
            .header("Content-Type", "application/json")
            .body("{}")
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                return Ok(vec![CoreEvent::GroupOutboxSealFailed {
                    group_id: seal.group_id,
                    retryable: true,
                    status: None,
                    code: None,
                    detail: Some(error.to_string()),
                }]);
            }
        };

        let status = response.status().as_u16();
        let body_text = response.text().await.unwrap_or_default();
        Ok(map_seal_group_outbox_response(
            seal.group_id,
            status,
            &body_text,
        ))
    }

    async fn put_welcome_pickup(&mut self, put: PutWelcomePickupRequest) -> Result<Vec<CoreEvent>> {
        let response = self
            .runtime
            .client
            .put(&put.descriptor.endpoint)
            .header(
                "Authorization",
                format!("Bearer {}", put.descriptor.capability),
            )
            .header("Content-Type", "application/json")
            .body(to_camel_case_json_string(&serde_json::to_string(&put)?)?)
            .send()
            .await;
        match response {
            Ok(response) => {
                let status = response.status().as_u16();
                if !(200..300).contains(&status) {
                    return Ok(vec![CoreEvent::WelcomePickupPutFailed {
                        descriptor: put.descriptor,
                        retryable: status >= 500,
                        detail: response.text().await.ok(),
                    }]);
                }
                let body = to_snake_case_json_string(&response.text().await.unwrap_or_default())?;
                let _result: PutWelcomePickupResult = serde_json::from_str(&body)?;
                Ok(vec![CoreEvent::WelcomePickupPut {
                    descriptor: put.descriptor,
                }])
            }
            Err(error) => Ok(vec![CoreEvent::WelcomePickupPutFailed {
                descriptor: put.descriptor,
                retryable: true,
                detail: Some(error.to_string()),
            }]),
        }
    }

    async fn fetch_welcome_pickup(
        &mut self,
        fetch: FetchWelcomePickupRequest,
    ) -> Result<Vec<CoreEvent>> {
        let response = self
            .runtime
            .client
            .get(&fetch.descriptor.endpoint)
            .header(
                "Authorization",
                format!("Bearer {}", fetch.descriptor.capability),
            )
            .header(
                "X-Tapchat-Welcome-Pickup",
                to_camel_case_json_string(&serde_json::to_string(&fetch.descriptor)?)?,
            )
            .send()
            .await;
        match response {
            Ok(response) => {
                let status = response.status().as_u16();
                let body = response.text().await.unwrap_or_default();
                if !(200..300).contains(&status) {
                    return Ok(vec![CoreEvent::WelcomePickupFetchFailed {
                        descriptor: fetch.descriptor,
                        retryable: status >= 500,
                        detail: Some(body),
                    }]);
                }
                let body = to_snake_case_json_string(&body).unwrap_or(body);
                let result: FetchWelcomePickupResult = serde_json::from_str(&body)?;
                Ok(vec![CoreEvent::WelcomePickupFetched {
                    descriptor: fetch.descriptor,
                    welcome_b64: result.welcome_b64,
                    manifest: result.manifest,
                }])
            }
            Err(error) => Ok(vec![CoreEvent::WelcomePickupFetchFailed {
                descriptor: fetch.descriptor,
                retryable: true,
                detail: Some(error.to_string()),
            }]),
        }
    }

    async fn create_group_invite(
        &mut self,
        create: CreateGroupInviteRequest,
    ) -> Result<Vec<CoreEvent>> {
        let base = self
            .engine
            .refresh_snapshot()
            .deployment
            .map(|deployment| deployment.deployment_bundle.inbox_http_endpoint)
            .ok_or_else(|| anyhow!("deployment bundle is missing"))?;
        let response = self
            .runtime
            .client
            .post(format!(
                "{}/v1/groups/{}/invites",
                base.trim_end_matches('/'),
                create.group_id
            ))
            .header(
                "Authorization",
                format!("Bearer {}", create.capability.signature),
            )
            .header("Content-Type", "application/json")
            .body(to_camel_case_json_string(&serde_json::to_string(&create)?)?)
            .send()
            .await;
        match response {
            Ok(response) => {
                let status = response.status().as_u16();
                let body = response.text().await.unwrap_or_default();
                if !(200..300).contains(&status) {
                    return Ok(vec![CoreEvent::GroupInviteCreateFailed {
                        group_id: create.group_id,
                        retryable: status >= 500,
                        detail: Some(body),
                    }]);
                }
                let body = to_snake_case_json_string(&body).unwrap_or(body);
                let result: CreateGroupInviteResult = serde_json::from_str(&body)?;
                Ok(vec![CoreEvent::GroupInviteCreated {
                    invite_url: result.invite_url,
                    invite: result.invite,
                }])
            }
            Err(error) => Ok(vec![CoreEvent::GroupInviteCreateFailed {
                group_id: create.group_id,
                retryable: true,
                detail: Some(error.to_string()),
            }]),
        }
    }

    async fn fetch_group_invite(
        &mut self,
        fetch: FetchGroupInviteRequest,
    ) -> Result<Vec<CoreEvent>> {
        let response = self.runtime.client.get(&fetch.invite_url).send().await;
        match response {
            Ok(response) => {
                let status = response.status().as_u16();
                let body = response.text().await.unwrap_or_default();
                if !(200..300).contains(&status) {
                    return Ok(vec![CoreEvent::GroupInviteFetchFailed {
                        invite_url: fetch.invite_url,
                        retryable: status >= 500,
                        detail: Some(body),
                    }]);
                }
                let body = to_snake_case_json_string(&body).unwrap_or(body);
                let result: FetchGroupInviteResult = serde_json::from_str(&body)?;
                Ok(vec![CoreEvent::GroupInviteFetched {
                    invite_url: fetch.invite_url,
                    invite: result.invite,
                }])
            }
            Err(error) => Ok(vec![CoreEvent::GroupInviteFetchFailed {
                invite_url: fetch.invite_url,
                retryable: true,
                detail: Some(error.to_string()),
            }]),
        }
    }

    async fn submit_group_join_request(
        &mut self,
        submit: SubmitGroupJoinRequest,
    ) -> Result<Vec<CoreEvent>> {
        let response = self
            .runtime
            .client
            .post(&submit.join_request_endpoint)
            .header("Authorization", format!("Bearer {}", submit.invite_token))
            .header("Content-Type", "application/json")
            .body(to_camel_case_json_string(&serde_json::to_string(&submit)?)?)
            .send()
            .await;
        match response {
            Ok(response) => {
                let status = response.status().as_u16();
                let body = response.text().await.unwrap_or_default();
                if !(200..300).contains(&status) {
                    return Ok(vec![CoreEvent::GroupJoinRequestSubmitFailed {
                        invite_url: submit.invite_token,
                        retryable: status >= 500,
                        detail: Some(body),
                    }]);
                }
                let body = to_snake_case_json_string(&body).unwrap_or(body);
                let result: SubmitGroupJoinResult = serde_json::from_str(&body)?;
                Ok(vec![CoreEvent::GroupJoinRequestSubmitted {
                    request: result.request,
                }])
            }
            Err(error) => Ok(vec![CoreEvent::GroupJoinRequestSubmitFailed {
                invite_url: submit.invite_token,
                retryable: true,
                detail: Some(error.to_string()),
            }]),
        }
    }

    async fn revoke_group_invite(
        &mut self,
        revoke: RevokeGroupInviteRequest,
    ) -> Result<Vec<CoreEvent>> {
        let base = self
            .engine
            .refresh_snapshot()
            .deployment
            .map(|deployment| deployment.deployment_bundle.inbox_http_endpoint)
            .ok_or_else(|| anyhow!("deployment bundle is missing"))?;
        let response = self
            .runtime
            .client
            .post(format!(
                "{}/v1/groups/{}/invites/{}/revoke",
                base.trim_end_matches('/'),
                revoke.group_id,
                revoke.invite_id
            ))
            .header(
                "Authorization",
                format!("Bearer {}", revoke.capability.signature),
            )
            .header("Content-Type", "application/json")
            .body(to_camel_case_json_string(&serde_json::to_string(&revoke)?)?)
            .send()
            .await?;
        if !(200..300).contains(&response.status().as_u16()) {
            anyhow::bail!("group invite revoke failed: {}", response.text().await?);
        }
        let body = to_snake_case_json_string(&response.text().await.unwrap_or_default())?;
        let result: RevokeGroupInviteResult = serde_json::from_str(&body)?;
        Ok(vec![CoreEvent::GroupInviteRevoked {
            group_id: revoke.group_id,
            invite_id: result.invite_id,
        }])
    }

    async fn list_group_join_requests(
        &mut self,
        list: ListGroupJoinRequestsRequest,
    ) -> Result<Vec<CoreEvent>> {
        let base = self
            .engine
            .refresh_snapshot()
            .deployment
            .map(|deployment| deployment.deployment_bundle.inbox_http_endpoint)
            .ok_or_else(|| anyhow!("deployment bundle is missing"))?;
        let response = self
            .runtime
            .client
            .get(format!(
                "{}/v1/groups/{}/join-requests",
                base.trim_end_matches('/'),
                list.group_id
            ))
            .header(
                "Authorization",
                format!("Bearer {}", list.capability.signature),
            )
            .header(
                "X-Tapchat-Group-Capability",
                to_camel_case_json_string(&serde_json::to_string(&list.capability)?)?,
            )
            .send()
            .await?;
        if !(200..300).contains(&response.status().as_u16()) {
            anyhow::bail!("group join list failed: {}", response.text().await?);
        }
        let body = to_snake_case_json_string(&response.text().await.unwrap_or_default())?;
        let result: ListGroupJoinRequestsResult = serde_json::from_str(&body)?;
        Ok(vec![CoreEvent::GroupJoinRequestsListed {
            group_id: list.group_id,
            requests: result.requests,
        }])
    }

    async fn get_group_join_request_status(
        &mut self,
        get: GetGroupJoinRequestStatusRequest,
    ) -> Result<Vec<CoreEvent>> {
        let response = self
            .runtime
            .client
            .get(&get.endpoint)
            .header(
                "Authorization",
                format!("Bearer {}", get.request_capability),
            )
            .send()
            .await?;
        if !(200..300).contains(&response.status().as_u16()) {
            anyhow::bail!("group join status failed: {}", response.text().await?);
        }
        let body = to_snake_case_json_string(&response.text().await.unwrap_or_default())?;
        let result: GetGroupJoinRequestStatusResult = serde_json::from_str(&body)?;
        Ok(vec![CoreEvent::GroupJoinRequestStatusFetched {
            request: result.request,
            welcome_pickup: result.welcome_pickup,
            manifest: result.manifest,
            start_cursor: result.start_cursor,
        }])
    }

    async fn decide_group_join_request(
        &mut self,
        decide: DecideGroupJoinRequest,
    ) -> Result<Vec<CoreEvent>> {
        let base = self
            .engine
            .refresh_snapshot()
            .deployment
            .map(|deployment| deployment.deployment_bundle.inbox_http_endpoint)
            .ok_or_else(|| anyhow!("deployment bundle is missing"))?;
        let response = self
            .runtime
            .client
            .post(format!(
                "{}/v1/groups/{}/join-requests/{}/decision",
                base.trim_end_matches('/'),
                decide.group_id,
                decide.request_id
            ))
            .header(
                "Authorization",
                format!("Bearer {}", decide.capability.signature),
            )
            .header("Content-Type", "application/json")
            .body(to_camel_case_json_string(&serde_json::to_string(&decide)?)?)
            .send()
            .await;
        match response {
            Ok(response) => {
                let status = response.status().as_u16();
                let body = response.text().await.unwrap_or_default();
                if !(200..300).contains(&status) {
                    return Ok(vec![CoreEvent::GroupJoinDecisionFailed {
                        group_id: decide.group_id,
                        request_id: decide.request_id,
                        retryable: status >= 500,
                        detail: Some(body),
                    }]);
                }
                let body = to_snake_case_json_string(&body).unwrap_or(body);
                let result: DecideGroupJoinResult = serde_json::from_str(&body)?;
                Ok(vec![CoreEvent::GroupJoinDecisionApplied {
                    request: result.request,
                }])
            }
            Err(error) => Ok(vec![CoreEvent::GroupJoinDecisionFailed {
                group_id: decide.group_id,
                request_id: decide.request_id,
                retryable: true,
                detail: Some(error.to_string()),
            }]),
        }
    }
}

impl RealtimePort for CoreDriver {
    async fn open_realtime(
        &mut self,
        subscription: RealtimeSubscriptionRequest,
    ) -> Result<Vec<CoreEvent>> {
        CoreDriver::open_realtime(self, subscription).await
    }

    async fn close_realtime(&mut self, device_id: String) -> Result<Vec<CoreEvent>> {
        if let Some(task) = self.runtime.websocket_tasks.remove(&device_id) {
            task.abort();
        }
        Ok(Vec::new())
    }
}

impl BlobIoPort for CoreDriver {
    async fn read_attachment_bytes(
        &mut self,
        read: crate::ffi_api::ReadAttachmentBytesEffect,
    ) -> Result<Vec<CoreEvent>> {
        CoreDriver::read_attachment_bytes(self, read).await
    }

    async fn prepare_blob_upload(
        &mut self,
        upload: PrepareBlobUploadRequest,
    ) -> Result<Vec<CoreEvent>> {
        CoreDriver::prepare_blob_upload(self, upload).await
    }

    async fn upload_blob(&mut self, upload: BlobUploadRequest) -> Result<Vec<CoreEvent>> {
        CoreDriver::upload_blob(self, upload).await
    }

    async fn download_blob(&mut self, download: BlobDownloadRequest) -> Result<Vec<CoreEvent>> {
        CoreDriver::download_blob(self, download).await
    }

    async fn write_downloaded_attachment(
        &mut self,
        write: crate::ffi_api::WriteDownloadedAttachmentEffect,
    ) -> Result<Vec<CoreEvent>> {
        CoreDriver::write_downloaded_attachment(self, write).await
    }
}

impl PersistencePort for CoreDriver {
    fn persist_state(&mut self, persist: PersistStateEffect) -> Result<()> {
        CoreDriver::persist_state(self, persist)
    }
}

impl TimerPort for CoreDriver {
    fn schedule_timer(&mut self, timer_id: String, delay_ms: u64) -> Result<Vec<CoreEvent>> {
        self.runtime.scheduled_timers.push(ScheduledTimer {
            timer_id,
            delay_ms,
            scheduled_at: Instant::now(),
        });
        Ok(Vec::new())
    }
}

impl NotificationPort for CoreDriver {
    fn emit_user_notification(
        &mut self,
        notification: crate::ffi_api::UserNotificationEffect,
    ) -> Result<Vec<CoreEvent>> {
        self.runtime.notifications.push(notification.message);
        Ok(Vec::new())
    }
}

impl SecureStoragePort for CoreDriver {}

fn looks_like_json(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.starts_with('{') || trimmed.starts_with('[')
}

/// Pure mapping from a `POST /outbox/seal` HTTP response (status + body)
/// to the `CoreEvent` the engine expects.
///
/// Rules (mirrors `SealGroupOutboxService` on the Cloudflare side):
///   - 200 JSON with `sealed_at` → `GroupOutboxSealed { was_already_sealed: false }`
///   - 409 with `code == "already_sealed"` → `GroupOutboxSealed { was_already_sealed: true }`
///     (the terminal state is identical; this is the idempotent-repeat path)
///   - 409 with any other code → `GroupOutboxSealFailed { retryable: false }`
///   - 4xx (non-409) → `GroupOutboxSealFailed { retryable: false }`
///   - 5xx → `GroupOutboxSealFailed { retryable: true }`
///   - 200 body parse error → `GroupOutboxSealFailed { retryable: false }`
///
/// Kept as a standalone pure function so unit tests can exercise it
/// without spinning up a real HTTP server.
pub(crate) fn map_seal_group_outbox_response(
    group_id: String,
    status: u16,
    body_text: &str,
) -> Vec<CoreEvent> {
    // 409 `already_sealed` is semantically equivalent to a successful
    // seal — both end with the server-side `sealed` flag in effect —
    // so we map to `GroupOutboxSealed { was_already_sealed: true }` and
    // let the engine transition `dissolved_at` normally.
    if status == 409 {
        let body = to_snake_case_json_string(body_text).unwrap_or_else(|_| body_text.to_string());
        let code = extract_error_code(&body);
        if code.as_deref() == Some("already_sealed") {
            let sealed_at = extract_sealed_at(&body).unwrap_or(0);
            return vec![CoreEvent::GroupOutboxSealed {
                group_id,
                sealed_at,
                was_already_sealed: true,
            }];
        }
        return vec![CoreEvent::GroupOutboxSealFailed {
            group_id,
            retryable: false,
            status: Some(status),
            code,
            detail: Some(body_text.to_string()),
        }];
    }

    if !(200..300).contains(&status) {
        let body = to_snake_case_json_string(body_text).unwrap_or_else(|_| body_text.to_string());
        let code = extract_error_code(&body);
        let retryable = status >= 500;
        return vec![CoreEvent::GroupOutboxSealFailed {
            group_id,
            retryable,
            status: Some(status),
            code,
            detail: Some(body_text.to_string()),
        }];
    }

    let body = to_snake_case_json_string(body_text).unwrap_or_else(|_| body_text.to_string());
    let result: SealGroupOutboxResult = match serde_json::from_str(&body) {
        Ok(result) => result,
        Err(error) => {
            return vec![CoreEvent::GroupOutboxSealFailed {
                group_id,
                retryable: false,
                status: Some(status),
                code: None,
                detail: Some(error.to_string()),
            }];
        }
    };
    vec![CoreEvent::GroupOutboxSealed {
        group_id,
        sealed_at: result.sealed_at,
        was_already_sealed: result.was_already_sealed,
    }]
}

fn parse_realtime_event(device_id: &str, text: &str) -> Result<CoreEvent> {
    let normalized = to_snake_case_json_string(text)?;
    let value: serde_json::Value = serde_json::from_str(&normalized)?;
    let event_type = value
        .get("event")
        .and_then(|value| value.as_str())
        .ok_or_else(|| anyhow!("missing realtime event kind"))?;
    let event = match event_type {
        "head_updated" => RealtimeEvent::HeadUpdated {
            seq: value
                .get("seq")
                .and_then(|value| value.as_u64())
                .ok_or_else(|| anyhow!("missing seq"))?,
        },
        "inbox_record_available" => RealtimeEvent::InboxRecordAvailable {
            seq: value
                .get("seq")
                .and_then(|value| value.as_u64())
                .ok_or_else(|| anyhow!("missing seq"))?,
            record: value
                .get("record")
                .map(|record| serde_json::from_value(record.clone()))
                .transpose()?,
        },
        "message_request_changed" => RealtimeEvent::MessageRequestChanged {
            sender_user_id: value
                .get("sender_user_id")
                .and_then(|value| value.as_str())
                .ok_or_else(|| anyhow!("missing sender_user_id"))?
                .to_string(),
            request_id: value
                .get("request_id")
                .and_then(|value| value.as_str())
                .ok_or_else(|| anyhow!("missing request_id"))?
                .to_string(),
            change: value
                .get("change")
                .cloned()
                .map(serde_json::from_value)
                .transpose()?
                .ok_or_else(|| anyhow!("missing change"))?,
        },
        other => return Err(anyhow!("unsupported realtime event {other}")),
    };
    Ok(CoreEvent::RealtimeEventReceived {
        device_id: device_id.to_string(),
        event,
    })
}

fn merge_outputs(mut left: CoreOutput, right: CoreOutput) -> CoreOutput {
    left.state_update.conversations_changed |= right.state_update.conversations_changed;
    left.state_update.messages_changed |= right.state_update.messages_changed;
    left.state_update.contacts_changed |= right.state_update.contacts_changed;
    left.state_update.checkpoints_changed |= right.state_update.checkpoints_changed;
    left.state_update
        .system_statuses_changed
        .extend(right.state_update.system_statuses_changed);
    left.effects.extend(right.effects);
    match (&mut left.view_model, right.view_model) {
        (Some(left_view), Some(mut right_view)) => {
            left_view
                .conversations
                .append(&mut right_view.conversations);
            left_view.messages.append(&mut right_view.messages);
            left_view.contacts.append(&mut right_view.contacts);
            left_view.banners.append(&mut right_view.banners);
            left_view
                .message_requests
                .append(&mut right_view.message_requests);
            left_view
                .group_invites
                .append(&mut right_view.group_invites);
            left_view
                .group_join_requests
                .append(&mut right_view.group_join_requests);
            left_view
                .welcome_pickups
                .append(&mut right_view.welcome_pickups);
            if right_view.allowlist.is_some() {
                left_view.allowlist = right_view.allowlist.take();
            }
            if right_view.message_request_action.is_some() {
                left_view.message_request_action = right_view.message_request_action.take();
            }
            if right_view.append_result.is_some() {
                left_view.append_result = right_view.append_result.take();
            }
        }
        (None, Some(right_view)) => {
            left.view_model = Some(right_view);
        }
        _ => {}
    }
    left
}

#[cfg(test)]
mod tests {
    use super::{parse_realtime_event, ScheduledTimer};
    use tokio::time::{Duration, Instant};

    #[test]
    fn websocket_payload_maps_to_core_event() {
        let event = parse_realtime_event("device:bob:phone", r#"{"event":"head_updated","seq":7}"#)
            .expect("parse");
        match event {
            crate::CoreEvent::RealtimeEventReceived { device_id, event } => {
                assert_eq!(device_id, "device:bob:phone");
                assert!(matches!(
                    event,
                    crate::ffi_api::RealtimeEvent::HeadUpdated { seq: 7 }
                ));
            }
            _ => panic!("unexpected event"),
        }
    }

    #[test]
    fn websocket_message_request_payload_maps_to_core_event() {
        let event = parse_realtime_event(
            "device:bob:phone",
            r#"{"event":"message_request_changed","sender_user_id":"user:alice","request_id":"request:user:alice","change":"queued"}"#,
        )
        .expect("parse");
        match event {
            crate::CoreEvent::RealtimeEventReceived { device_id, event } => {
                assert_eq!(device_id, "device:bob:phone");
                assert!(matches!(
                    event,
                    crate::ffi_api::RealtimeEvent::MessageRequestChanged {
                        sender_user_id,
                        request_id,
                        change: crate::transport_contract::MessageRequestRealtimeChange::Queued,
                    } if sender_user_id == "user:alice" && request_id == "request:user:alice"
                ));
            }
            _ => panic!("unexpected event"),
        }
    }

    #[test]
    fn zero_delay_timer_is_due_immediately() {
        let timer = ScheduledTimer {
            timer_id: "sync:device:bob".into(),
            delay_ms: 0,
            scheduled_at: Instant::now(),
        };
        assert!(Instant::now() >= timer.scheduled_at + Duration::from_millis(timer.delay_ms));
    }

    #[test]
    fn nonzero_delay_timer_is_not_due_immediately() {
        let timer = ScheduledTimer {
            timer_id: "retry_append:msg:1".into(),
            delay_ms: 50,
            scheduled_at: Instant::now(),
        };
        assert!(Instant::now() < timer.scheduled_at + Duration::from_millis(timer.delay_ms));
    }

    #[test]
    fn seal_group_outbox_driver_maps_200_to_sealed_event() {
        let events = super::map_seal_group_outbox_response(
            "group:project".into(),
            200,
            "{\"sealed\":true,\"sealedAt\":1700000000000,\"wasAlreadySealed\":false}",
        );
        assert_eq!(events.len(), 1);
        match &events[0] {
            crate::CoreEvent::GroupOutboxSealed {
                group_id,
                sealed_at,
                was_already_sealed,
            } => {
                assert_eq!(group_id, "group:project");
                assert_eq!(*sealed_at, 1_700_000_000_000);
                assert!(!*was_already_sealed);
            }
            other => panic!("expected GroupOutboxSealed, got {:?}", other),
        }
    }

    #[test]
    fn seal_group_outbox_driver_maps_409_to_sealed_event_not_failure() {
        // 409 `already_sealed` is a success — both endpoints end up in the
        // same terminal state, the only difference is observability.
        let events = super::map_seal_group_outbox_response(
            "group:project".into(),
            409,
            "{\"error\":\"already_sealed\",\"sealed_at\":1700000000500}",
        );
        assert_eq!(events.len(), 1);
        match &events[0] {
            crate::CoreEvent::GroupOutboxSealed {
                group_id,
                sealed_at,
                was_already_sealed,
            } => {
                assert_eq!(group_id, "group:project");
                assert_eq!(*sealed_at, 1_700_000_000_500);
                assert!(*was_already_sealed);
            }
            other => panic!(
                "expected GroupOutboxSealed for 409 already_sealed, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn seal_group_outbox_driver_maps_403_to_non_retryable_failure() {
        let events = super::map_seal_group_outbox_response(
            "group:project".into(),
            403,
            "{\"error\":\"unauthorized\",\"message\":\"capability rejected\"}",
        );
        assert_eq!(events.len(), 1);
        match &events[0] {
            crate::CoreEvent::GroupOutboxSealFailed {
                group_id,
                retryable,
                status,
                code,
                detail: _,
            } => {
                assert_eq!(group_id, "group:project");
                assert!(!*retryable, "403 must be non-retryable");
                assert_eq!(*status, Some(403));
                assert_eq!(code.as_deref(), Some("unauthorized"));
            }
            other => panic!("expected GroupOutboxSealFailed for 403, got {:?}", other),
        }
    }

    #[test]
    fn seal_group_outbox_driver_maps_5xx_to_retryable_failure() {
        let events = super::map_seal_group_outbox_response(
            "group:project".into(),
            503,
            "{\"error\":\"temporary_unavailable\"}",
        );
        assert_eq!(events.len(), 1);
        match &events[0] {
            crate::CoreEvent::GroupOutboxSealFailed {
                group_id,
                retryable,
                status,
                code,
                ..
            } => {
                assert_eq!(group_id, "group:project");
                assert!(*retryable, "5xx must be retryable");
                assert_eq!(*status, Some(503));
                assert_eq!(code.as_deref(), Some("temporary_unavailable"));
            }
            other => panic!(
                "expected retryable GroupOutboxSealFailed for 503, got {:?}",
                other
            ),
        }
    }
}

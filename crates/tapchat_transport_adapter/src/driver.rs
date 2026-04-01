use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures_util::StreamExt;
use reqwest::Client;
use tapchat_core::conversation::RecoveryStatus;
use tapchat_core::ffi_api::{
    CoreCommand, CoreEffect, CoreEngine, CoreEvent, CoreOutput, HttpMethod, PersistStateEffect,
    RealtimeEvent,
};
use tapchat_core::model::{DeviceStatusKind, Envelope, IdentityBundle, MessageType};
use tapchat_core::persistence::CorePersistenceSnapshot;
use tapchat_core::transport_contract::{
    AppendEnvelopeRequest, BlobDownloadRequest, BlobUploadRequest, FetchIdentityBundleRequest,
    PrepareBlobUploadRequest, RealtimeSubscriptionRequest,
};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant, timeout};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};

use crate::util::{to_camel_case_json_string, to_snake_case_json_string};

pub struct DriverRuntime {
    client: Client,
    websocket_tx: UnboundedSender<CoreEvent>,
    websocket_rx: UnboundedReceiver<CoreEvent>,
    websocket_tasks: BTreeMap<String, JoinHandle<()>>,
    latest_snapshot: Option<CorePersistenceSnapshot>,
    notifications: Vec<String>,
    scheduled_timers: Vec<(String, u64)>,
    storage_prepare_url: Option<String>,
    recent_appends: Vec<Envelope>,
    recent_messages: Vec<(String, MessageType)>,
}

pub struct CoreDriver {
    engine: CoreEngine,
    runtime: DriverRuntime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactDeviceSnapshot {
    pub device_id: String,
    pub status: DeviceStatusKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationMemberSnapshot {
    pub user_id: String,
    pub device_id: String,
    pub status: DeviceStatusKind,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PendingMlsArtifacts {
    pub pending_welcome_count: usize,
    pub pending_commit_count: usize,
}

impl CoreDriver {
    pub fn new() -> Result<Self> {
        Self::new_with_storage_base(None)
    }

    pub fn from_snapshot(
        snapshot: CorePersistenceSnapshot,
        base_url: Option<String>,
    ) -> Result<Self> {
        let latest_snapshot = snapshot.clone();
        let (websocket_tx, websocket_rx) = mpsc::unbounded_channel();
        Ok(Self {
            engine: CoreEngine::from_restored_state(snapshot),
            runtime: DriverRuntime {
                client: Client::builder().build().context("build driver reqwest client")?,
                websocket_tx,
                websocket_rx,
                websocket_tasks: BTreeMap::new(),
                latest_snapshot: Some(latest_snapshot),
                notifications: Vec::new(),
                scheduled_timers: Vec::new(),
                storage_prepare_url: base_url
                    .map(|value| format!("{}/v1/storage/prepare-upload", value.trim_end_matches('/'))),
                recent_appends: Vec::new(),
                recent_messages: Vec::new(),
            },
        })
    }

    pub fn new_with_storage_base(base_url: Option<String>) -> Result<Self> {
        let (websocket_tx, websocket_rx) = mpsc::unbounded_channel();
        Ok(Self {
            engine: CoreEngine::new(),
            runtime: DriverRuntime {
                client: Client::builder().build().context("build driver reqwest client")?,
                websocket_tx,
                websocket_rx,
                websocket_tasks: BTreeMap::new(),
                latest_snapshot: None,
                notifications: Vec::new(),
                scheduled_timers: Vec::new(),
                storage_prepare_url: base_url
                    .map(|value| format!("{}/v1/storage/prepare-upload", value.trim_end_matches('/'))),
                recent_appends: Vec::new(),
                recent_messages: Vec::new(),
            },
        })
    }

    pub fn engine(&self) -> &CoreEngine {
        &self.engine
    }

    pub fn latest_snapshot(&self) -> Option<&CorePersistenceSnapshot> {
        self.runtime.latest_snapshot.as_ref()
    }

    pub fn notifications(&self) -> &[String] {
        &self.runtime.notifications
    }

    pub fn scheduled_timers(&self) -> &[(String, u64)] {
        &self.runtime.scheduled_timers
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

    pub fn conversation_recovery_status(&self, conversation_id: &str) -> Option<RecoveryStatus> {
        self.engine
            .conversation_state(conversation_id)
            .map(|state| state.recovery_status)
    }

    pub fn pending_mls_artifacts(&self, conversation_id: &str) -> PendingMlsArtifacts {
        let mut artifacts = PendingMlsArtifacts::default();
        let Some(snapshot) = self.runtime.latest_snapshot.as_ref() else {
            for envelope in &self.runtime.recent_appends {
                if envelope.conversation_id != conversation_id {
                    continue;
                }
                match envelope.message_type {
                    MessageType::MlsWelcome => {
                        artifacts.pending_welcome_count = artifacts.pending_welcome_count.saturating_add(1);
                    }
                    MessageType::MlsCommit => {
                        artifacts.pending_commit_count = artifacts.pending_commit_count.saturating_add(1);
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
                        artifacts.pending_welcome_count = artifacts.pending_welcome_count.saturating_add(1);
                    }
                    MessageType::MlsCommit => {
                        artifacts.pending_commit_count = artifacts.pending_commit_count.saturating_add(1);
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
                    artifacts.pending_welcome_count = artifacts.pending_welcome_count.saturating_add(1);
                }
                MessageType::MlsCommit => {
                    artifacts.pending_commit_count = artifacts.pending_commit_count.saturating_add(1);
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
                    artifacts.pending_welcome_count = artifacts.pending_welcome_count.saturating_add(1);
                }
                MessageType::MlsCommit => {
                    artifacts.pending_commit_count = artifacts.pending_commit_count.saturating_add(1);
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
                    artifacts.pending_welcome_count = artifacts.pending_welcome_count.saturating_add(1);
                }
                MessageType::MlsCommit => {
                    artifacts.pending_commit_count = artifacts.pending_commit_count.saturating_add(1);
                }
                _ => {}
            }
        }
        artifacts
    }

    pub fn clear_recent_transport_activity(&mut self) {
        self.runtime.recent_appends.clear();
        self.runtime.recent_messages.clear();
    }

    pub async fn run_command_until_idle(&mut self, command: CoreCommand) -> Result<CoreOutput> {
        let output = self.engine.handle_command(command)?;
        let output = self.execute_until_idle(output).await?;
        self.record_observed_output(&output);
        Ok(output)
    }

    pub async fn inject_event_until_idle(&mut self, event: CoreEvent) -> Result<CoreOutput> {
        let output = self.engine.handle_event(event)?;
        let output = self.execute_until_idle(output).await?;
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
            let event = match timeout(remaining.min(Duration::from_millis(250)), self.runtime.websocket_rx.recv()).await {
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
        let output = self.engine.handle_event(CoreEvent::WebSocketDisconnected {
            device_id: device_id.to_string(),
            reason: Some("manual close".into()),
        })?;
        let _ = self.execute_until_idle(output).await?;
        Ok(())
    }

    async fn execute_until_idle(&mut self, mut output: CoreOutput) -> Result<CoreOutput> {
        loop {
            let effects = std::mem::take(&mut output.effects);
            if effects.is_empty() {
                break;
            }
            let mut processed_any_event = false;
            for effect in effects {
                let emitted_events = self.execute_effect(effect).await?;
                for event in emitted_events {
                    processed_any_event = true;
                    output = merge_outputs(output, self.engine.handle_event(event.clone()).map_err(|error| anyhow!("event {:?} failed: {}", event, error))?);
                }
            }
            if !processed_any_event {
                break;
            }
        }
        Ok(output)
    }

    async fn execute_effect(&mut self, effect: CoreEffect) -> Result<Vec<CoreEvent>> {
        match effect {
            CoreEffect::ExecuteHttpRequest { request } => self.execute_http_request(request).await,
            CoreEffect::OpenRealtimeConnection { connection } => self.open_realtime(connection.subscription).await,
            CoreEffect::CloseRealtimeConnection { device_id } => {
                if let Some(task) = self.runtime.websocket_tasks.remove(&device_id) {
                    task.abort();
                }
                Ok(Vec::new())
            }
            CoreEffect::FetchIdentityBundle { fetch } => self.fetch_identity_bundle(fetch).await,
            CoreEffect::PrepareBlobUpload { upload } => self.prepare_blob_upload(upload).await,
            CoreEffect::UploadBlob { upload } => self.upload_blob(upload).await,
            CoreEffect::DownloadBlob { download } => self.download_blob(download).await,
            CoreEffect::PersistState { persist } => {
                self.persist_state(persist);
                Ok(Vec::new())
            }
            CoreEffect::ScheduleTimer { timer } => {
                self.runtime.scheduled_timers.push((timer.timer_id, timer.delay_ms));
                Ok(Vec::new())
            }
            CoreEffect::EmitUserNotification { notification } => {
                self.runtime.notifications.push(notification.message);
                Ok(Vec::new())
            }
        }
    }

    async fn execute_http_request(
        &mut self,
        request: tapchat_core::ffi_api::HttpRequestEffect,
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
                let append_request: AppendEnvelopeRequest = serde_json::from_str(body)?;
                self.runtime.recent_appends.push(append_request.envelope);
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

    async fn open_realtime(&mut self, subscription: RealtimeSubscriptionRequest) -> Result<Vec<CoreEvent>> {
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
        let (stream, _) = connect_async(request).await.context("open realtime websocket")?;
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
        self.runtime.websocket_tasks.insert(device_id.clone(), handle);
        Ok(vec![CoreEvent::WebSocketConnected { device_id }])
    }

    async fn fetch_identity_bundle(&self, fetch: FetchIdentityBundleRequest) -> Result<Vec<CoreEvent>> {
        let reference = fetch.reference.ok_or_else(|| anyhow!("identity bundle fetch missing reference"))?;
        match self.runtime.client.get(reference).send().await {
            Ok(response) if response.status().is_success() => {
                let body = response.text().await?;
                let bundle: IdentityBundle = serde_json::from_str(&to_snake_case_json_string(&body)?)?;
                Ok(vec![CoreEvent::IdentityBundleFetched { user_id: fetch.user_id, bundle }])
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

    async fn prepare_blob_upload(&self, upload: PrepareBlobUploadRequest) -> Result<Vec<CoreEvent>> {
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
                Ok(vec![CoreEvent::BlobUploadPrepared { task_id: upload.task_id, result }])
            }
            Ok(response) => Ok(vec![CoreEvent::BlobTransferFailed {
                task_id: upload.task_id,
                retryable: false,
                detail: Some(format!("prepare upload failed with status {}", response.status())),
            }]),
            Err(error) => Ok(vec![CoreEvent::BlobTransferFailed {
                task_id: upload.task_id,
                retryable: true,
                detail: Some(error.to_string()),
            }]),
        }
    }

    async fn upload_blob(&self, upload: BlobUploadRequest) -> Result<Vec<CoreEvent>> {
        let bytes = tokio::fs::read(&upload.source_path).await.context("read upload source")?;
        let mut request = self.runtime.client.put(upload.upload_target.clone());
        for (key, value) in &upload.upload_headers {
            request = request.header(key, value);
        }
        match request.body(bytes).send().await {
            Ok(response) if response.status().is_success() => Ok(vec![CoreEvent::BlobUploaded { task_id: upload.task_id }]),
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
                if let Some(parent) = PathBuf::from(&download.destination_path).parent() {
                    tokio::fs::create_dir_all(parent).await.ok();
                }
                tokio::fs::write(&download.destination_path, &bytes).await?;
                Ok(vec![CoreEvent::BlobDownloaded {
                    task_id: download.task_id,
                    destination: download.destination_path,
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

    fn persist_state(&mut self, persist: PersistStateEffect) {
        if let Some(snapshot) = persist.snapshot {
            self.runtime.latest_snapshot = Some(snapshot);
        }
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
}

fn looks_like_json(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.starts_with('{') || trimmed.starts_with('[')
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
            seq: value.get("seq").and_then(|value| value.as_u64()).ok_or_else(|| anyhow!("missing seq"))?,
        },
        "inbox_record_available" => RealtimeEvent::InboxRecordAvailable {
            seq: value.get("seq").and_then(|value| value.as_u64()).ok_or_else(|| anyhow!("missing seq"))?,
            record: value.get("record").map(|record| serde_json::from_value(record.clone())).transpose()?,
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
    left.state_update.system_statuses_changed.extend(right.state_update.system_statuses_changed);
    left.effects.extend(right.effects);
    if right.view_model.is_some() {
        left.view_model = right.view_model;
    }
    left
}

#[cfg(test)]
mod tests {
    use super::parse_realtime_event;

    #[test]
    fn websocket_payload_maps_to_core_event() {
        let event = parse_realtime_event("device:bob:phone", r#"{"event":"head_updated","seq":7}"#).expect("parse");
        match event {
            tapchat_core::CoreEvent::RealtimeEventReceived { device_id, event } => {
                assert_eq!(device_id, "device:bob:phone");
                assert!(matches!(event, tapchat_core::ffi_api::RealtimeEvent::HeadUpdated { seq: 7 }));
            }
            _ => panic!("unexpected event"),
        }
    }
}






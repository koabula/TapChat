pub mod blob_io;
pub mod media_cache;
pub mod notification;
pub mod persistence;
pub mod realtime;
pub mod timer;
pub mod transport;

use std::sync::Arc;

use anyhow::{Context, Result};
use tapchat_core::external_fetch::{
    fetch_external_json, validate_group_invite_transport_binding, ExternalResourceKind,
};
use tapchat_core::ffi_api::{
    CacheUploadedAttachmentEffect, CoreEvent, DeleteBlobRequest, HttpMethod, HttpRequestEffect,
    PersistStateEffect, ReadAttachmentBytesEffect, UserNotificationEffect,
    WriteDownloadedAttachmentEffect,
};
use tapchat_core::platform_ports::{
    BlobIoPort, NotificationPort, PersistencePort, RealtimePort, SecureStoragePort, TimerPort,
    TransportPort,
};
use tapchat_core::transport_contract::json_case::{
    to_camel_case_json_string, to_snake_case_json_string,
};
use tapchat_core::transport_contract::{
    AppendEnvelopeRequest, AppendGroupEnvelopeRequest, AppendGroupEnvelopeResult,
    AppendGroupTransitionRequest, AppendGroupTransitionResult, BlobDownloadRequest,
    BlobUploadRequest, ClaimGroupJoinRequest, ClaimGroupJoinResult, ClaimGroupLeaveRequest,
    ClaimGroupLeaveResult, CompleteGroupJoinRequest, CompleteGroupJoinResult,
    CreateGroupInviteRequest, CreateGroupInviteResult, DecideGroupJoinRequest,
    DecideGroupJoinResult, FetchAllowlistRequest, FetchGroupInviteRequest, FetchGroupInviteResult,
    FetchGroupOutboxRequest, FetchGroupOutboxResult, FetchIdentityBundleRequest,
    FetchMessageRequestsRequest, FetchWelcomePickupRequest, FetchWelcomePickupResult,
    GetGroupAuthorizationStateRequest, GetGroupAuthorizationStateResult,
    GetGroupJoinRequestStatusRequest, GetGroupJoinRequestStatusResult, GetGroupOutboxHeadRequest,
    GetGroupOutboxHeadResult, GroupRealtimeSubscriptionRequest,
    InitializeGroupAuthorizationRequest, InitializeGroupAuthorizationResult,
    ListGroupInvitesRequest, ListGroupInvitesResult, ListGroupJoinRequestsRequest,
    ListGroupJoinRequestsResult, ListGroupLeaveRequestsRequest, ListGroupLeaveRequestsResult,
    MessageRequestActionRequest, PrepareBlobUploadRequest, PublishSharedStateRequest,
    PutWelcomePickupRequest, PutWelcomePickupResult, RealtimeSubscriptionRequest,
    ReplaceAllowlistRequest, RevokeGroupInviteRequest, RevokeGroupInviteResult,
    SealGroupOutboxRequest, SealGroupOutboxResult, SubmitGroupJoinRequest, SubmitGroupJoinResult,
    SubmitGroupLeaveRequest, SubmitGroupLeaveResult, TransportAuthRequirement,
};
use tauri::{AppHandle, Emitter};
use tokio::sync::RwLock;

use crate::platform::log_sanitize::{redact_id, sanitize_url_for_log};
use crate::platform::persistence::DesktopPersistence;
use crate::platform::profile::ProfileManagerInner;
use crate::platform::realtime::RealtimeManager;
use crate::platform::transport::{build_desktop_http_client, DesktopTransport};
use crate::runtime_auth::RuntimeAuthManager;

/// Desktop-specific implementation of all platform port traits.
/// This is the bridge between CoreEngine effects and actual platform operations.
pub struct DesktopPlatformPorts {
    pub transport: DesktopTransport,
    pub realtime: RealtimeManager,
    pub persistence: DesktopPersistence,
    pub notification: notification::NotificationManager,
    pub timer: timer::TimerManager,
    /// HTTP client for transport operations
    client: reqwest::Client,
    /// AppHandle for emitting progress events
    app_handle: Option<Arc<AppHandle>>,
    runtime_auth: RuntimeAuthManager,
    // Timer uses spawn directly
}

impl DesktopPlatformPorts {
    pub fn new(
        profile_inner: Arc<RwLock<ProfileManagerInner>>,
        runtime_auth: RuntimeAuthManager,
    ) -> Self {
        let client = build_desktop_http_client();
        Self {
            transport: DesktopTransport::new(profile_inner.clone(), client.clone()),
            realtime: RealtimeManager::new(profile_inner.clone()),
            persistence: DesktopPersistence::new(profile_inner),
            notification: notification::NotificationManager::new(),
            timer: timer::TimerManager::new(),
            client,
            app_handle: None,
            runtime_auth,
        }
    }

    async fn inject_runtime_authorization(
        &self,
        headers: &mut std::collections::BTreeMap<String, String>,
        auth: Option<&TransportAuthRequirement>,
        force_refresh: bool,
    ) -> Result<()> {
        let Some(TransportAuthRequirement::DeviceRuntime {
            runtime_id,
            device_id,
        }) = auth
        else {
            return Ok(());
        };
        let profile_manager = crate::platform::profile::ProfileManager::from_inner(
            self.transport.profile_inner.clone(),
        );
        let credential = self
            .runtime_auth
            .ensure(&profile_manager, force_refresh)
            .await?
            .ok_or_else(|| anyhow::anyhow!("runtime_auth_error:enrollment_required"))?;
        if credential.runtime_id != *runtime_id || credential.device_id != *device_id {
            anyhow::bail!("runtime_auth_error:runtime_mismatch");
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        if credential.expires_at <= now {
            anyhow::bail!("runtime_auth_error:runtime_auth_expired");
        }
        headers.insert(
            "Authorization".into(),
            format!("Bearer {}", credential.token),
        );
        Ok(())
    }

    /// Set the app handle for emitting events
    pub fn set_app_handle(&mut self, handle: Arc<AppHandle>) {
        self.app_handle = Some(handle.clone());
        self.realtime.set_app_handle(handle.clone());
        self.notification.set_app_handle(handle);
        if let Some(app_handle) = &self.app_handle {
            self.timer.set_app_handle((**app_handle).clone());
        }
    }

    /// Build contact share URL for sender identification in message requests.
    /// This generates a signed URL that allows recipients to fetch the sender's identity bundle.
    pub(crate) async fn build_contact_share_url(&self) -> Result<Option<String>> {
        let pm = self.transport.profile_inner.read().await;

        // Get active profile
        let Some(profile) = pm.active_profile.as_ref() else {
            log::warn!("No active profile found for contact share URL");
            return Ok(None);
        };

        // Load runtime metadata
        let runtime = match profile.load_runtime_metadata() {
            Ok(r) => r,
            Err(_error) => {
                log::warn!("Failed to load runtime metadata: load_failed");
                return Ok(None);
            }
        };

        // Get base URL
        let base_url = runtime.public_base_url.clone().or(runtime.base_url.clone());

        let Some(base_url) = base_url else {
            log::warn!("No base URL in runtime metadata");
            return Ok(None);
        };

        // Get sharing secret
        let Some(sharing_secret) = runtime.sharing_secret.clone() else {
            log::warn!("No sharing secret in runtime metadata");
            return Ok(None);
        };

        // Get local bundle from persistence
        let snapshot = match profile.load_snapshot() {
            Ok(s) => s,
            Err(_error) => {
                log::warn!("Failed to load snapshot: load_failed");
                return Ok(None);
            }
        };

        let Some(deployment) = snapshot.deployment.as_ref() else {
            log::warn!("No deployment in snapshot");
            return Ok(None);
        };

        let Some(local_bundle) = deployment.local_bundle.as_ref() else {
            log::warn!("No local bundle in deployment");
            return Ok(None);
        };

        // Get bundle_share_id
        let Some(share_id) = local_bundle.bundle_share_id.clone() else {
            log::warn!("No bundle_share_id in local bundle");
            return Ok(None);
        };

        Ok(Some(tapchat_core::contact_share::encode_contact_share_url(
            &base_url,
            &sharing_secret,
            &local_bundle.user_id,
            &share_id,
        )?))
    }

    async fn inbox_base_url(&self) -> Result<String> {
        let pm = self.transport.profile_inner.read().await;
        let profile = pm
            .active_profile
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no active profile found"))?;
        let deployment = profile
            .load_snapshot()
            .context("load active profile snapshot")?
            .deployment
            .ok_or_else(|| anyhow::anyhow!("deployment bundle is missing"))?;
        Ok(deployment.deployment_bundle.inbox_http_endpoint)
    }

    async fn group_outbox_endpoint(&self, group_id: &str) -> Result<String> {
        let pm = self.transport.profile_inner.read().await;
        let profile = pm
            .active_profile
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no active profile found"))?;
        profile
            .load_snapshot()
            .context("load active profile snapshot")?
            .group_states
            .into_iter()
            .find(|state| state.group_id == group_id)
            .map(|state| state.manifest.outbox.endpoint)
            .ok_or_else(|| anyhow::anyhow!("group outbox endpoint is missing"))
    }

    async fn group_outbox_messages_url(
        &self,
        group_id: &str,
        from_seq: u64,
        limit: u64,
    ) -> Result<url::Url> {
        let endpoint = self.group_outbox_endpoint(group_id).await?;
        group_outbox_messages_url_from_endpoint(&endpoint, from_seq, limit)
    }

    async fn group_outbox_sibling_url(&self, group_id: &str, sibling: &str) -> Result<url::Url> {
        let endpoint = self.group_outbox_endpoint(group_id).await?;
        group_outbox_sibling_url_from_endpoint(&endpoint, sibling)
    }
}

fn parse_group_outbox_messages_endpoint(endpoint: &str) -> Result<url::Url> {
    let url = url::Url::parse(endpoint).context("parse group outbox endpoint")?;
    if !url.path().ends_with("/outbox/messages") {
        anyhow::bail!("group outbox endpoint must end with /outbox/messages");
    }
    Ok(url)
}

fn group_outbox_messages_url_from_endpoint(
    endpoint: &str,
    from_seq: u64,
    limit: u64,
) -> Result<url::Url> {
    let mut url = parse_group_outbox_messages_endpoint(endpoint)?;
    url.set_query(None);
    url.set_fragment(None);
    url.query_pairs_mut()
        .append_pair("fromSeq", &from_seq.to_string())
        .append_pair("limit", &limit.to_string());
    Ok(url)
}

fn group_outbox_sibling_url_from_endpoint(endpoint: &str, sibling: &str) -> Result<url::Url> {
    match sibling {
        "head" | "seal" | "transitions" => {}
        _ => anyhow::bail!("unsupported group outbox sibling endpoint: {sibling}"),
    }
    let mut url = parse_group_outbox_messages_endpoint(endpoint)?;
    let base_path = url
        .path()
        .strip_suffix("/outbox/messages")
        .ok_or_else(|| anyhow::anyhow!("group outbox endpoint must end with /outbox/messages"))?;
    url.set_path(&format!("{base_path}/outbox/{sibling}"));
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

fn summarize_share_url(url: Option<&str>) -> String {
    let Some(url) = url else {
        return "none".into();
    };
    sanitize_url_for_log(url)
}

fn summarize_endpoint_url(url: &url::Url) -> String {
    sanitize_url_for_log(url.as_str())
}

// --- TransportPort ---
// Note: TransportPort trait requires `&mut self` but our implementations use `&self`
// We implement by delegating to the platform modules

impl TransportPort for DesktopPlatformPorts {
    async fn execute_http_request(
        &mut self,
        mut request: HttpRequestEffect,
    ) -> Result<Vec<CoreEvent>> {
        // Intercept append envelope requests to inject correct sender_bundle_share_url
        if request.method == HttpMethod::Post && request.url.contains("/messages") {
            log::info!("[TransportPort] Intercepting /messages POST request");
            if let Some(body) = &request.body {
                let is_envelope_v2 = serde_json::from_str::<serde_json::Value>(body)
                    .ok()
                    .and_then(|value| value.get("version")?.as_str().map(str::to_owned))
                    .as_deref()
                    == Some("2");
                if is_envelope_v2 {
                    // V2 carries the exact signed IdentityBundle inline. Any
                    // platform injection would invalidate its protocol binding.
                    log::info!("[TransportPort] Envelope V2 bypasses legacy share-link injection");
                } else {
                    // Try to parse as AppendEnvelopeRequest
                    if let Ok(mut append_request) =
                        serde_json::from_str::<AppendEnvelopeRequest>(body)
                    {
                        log::info!("[TransportPort] Parsed AppendEnvelopeRequest successfully");
                        log::info!(
                            "[TransportPort] sender_bundle_share_url={}",
                            summarize_share_url(append_request.sender_bundle_share_url.as_deref())
                        );

                        // Check if sender_bundle_share_url needs to be replaced
                        // It should be a contact-share URL, not identity_bundle_ref
                        let needs_contact_share_url =
                            append_request.sender_bundle_share_url.is_none()
                                || append_request
                                    .sender_bundle_share_url
                                    .as_ref()
                                    .map(|url| !url.contains("/v1/contact-share/"))
                                    .unwrap_or(true);

                        log::info!(
                            "[TransportPort] needs_contact_share_url: {}",
                            needs_contact_share_url
                        );

                        if needs_contact_share_url {
                            // Generate correct contact share URL from runtime metadata
                            let contact_share_url = match self.build_contact_share_url().await {
                                Ok(url) => url,
                                Err(_) => {
                                    return Ok(vec![CoreEvent::HttpRequestFailed {
                                        request_id: request.request_id.clone(),
                                        failure: tapchat_core::AppErrorV1::from_registered_code(
                                            "contact_share_offline",
                                        ),
                                    }]);
                                }
                            };
                            log::info!(
                                "[TransportPort] generated_contact_share_url={}",
                                summarize_share_url(contact_share_url.as_deref())
                            );

                            if let Some(url) = contact_share_url {
                                log::info!(
                                "[TransportPort] Injecting contact-share URL for outbound request"
                            );
                                append_request.sender_bundle_share_url = Some(url);
                                // Rebuild the request with modified body
                                let modified_body = serde_json::to_string(&append_request)?;
                                request.body = Some(modified_body);
                            } else {
                                log::warn!(
                                "[TransportPort] Failed to generate contact_share_url, sending original request"
                            );
                            }
                        }
                    } else {
                        log::warn!("[TransportPort] Failed to parse body as AppendEnvelopeRequest");
                    }
                }
            }
        }

        let original = request.clone();
        if let Err(error) = self
            .inject_runtime_authorization(&mut request.headers, request.auth.as_ref(), false)
            .await
        {
            return Ok(vec![runtime_auth_http_failure(&request.request_id, &error)]);
        }
        let events = self.transport.execute_http_request(request).await?;
        let runtime_expired = events.iter().any(|event| match event {
            CoreEvent::HttpResponseReceived {
                status,
                body: Some(body),
                ..
            } if *status == 401 || *status == 403 => {
                extract_error_code(body).as_deref() == Some("runtime_auth_expired")
            }
            _ => false,
        });
        if !runtime_expired || original.auth.is_none() {
            return Ok(events);
        }
        let mut retry = original;
        if let Err(error) = self
            .inject_runtime_authorization(&mut retry.headers, retry.auth.as_ref(), true)
            .await
        {
            return Ok(vec![runtime_auth_http_failure(&retry.request_id, &error)]);
        }
        self.transport.execute_http_request(retry).await
    }

    async fn fetch_identity_bundle(
        &mut self,
        fetch: FetchIdentityBundleRequest,
    ) -> Result<Vec<CoreEvent>> {
        let reference = fetch
            .reference
            .as_deref()
            .context("identity bundle fetch missing reference")?;
        match fetch_external_json(reference, ExternalResourceKind::ContactShare).await {
            Ok(body) => {
                let normalized = to_snake_case_json_string(&body)?;
                let bundle = serde_json::from_str(&normalized)?;
                Ok(vec![CoreEvent::IdentityBundleFetched {
                    user_id: fetch.user_id,
                    bundle,
                }])
            }
            Err(error) => Ok(vec![CoreEvent::IdentityBundleFetchFailed {
                user_id: fetch.user_id,
                failure: if error.code() == "external_fetch_timeout" {
                    tapchat_core::AppErrorV1::from_registered_code("request_timeout")
                } else {
                    tapchat_core::AppErrorV1::network_unavailable()
                },
            }]),
        }
    }

    async fn fetch_message_requests(
        &mut self,
        mut fetch: FetchMessageRequestsRequest,
    ) -> Result<Vec<CoreEvent>> {
        let original = fetch.clone();
        self.inject_runtime_authorization(&mut fetch.headers, fetch.auth.as_ref(), false)
            .await?;
        let events = transport::fetch_message_requests(&self.client, fetch).await?;
        if !events_report_runtime_auth_expired(&events) {
            return Ok(events);
        }
        let mut retry = original;
        self.inject_runtime_authorization(&mut retry.headers, retry.auth.as_ref(), true)
            .await?;
        transport::fetch_message_requests(&self.client, retry).await
    }

    async fn act_on_message_request(
        &mut self,
        mut action: MessageRequestActionRequest,
    ) -> Result<Vec<CoreEvent>> {
        let original = action.clone();
        self.inject_runtime_authorization(&mut action.headers, action.auth.as_ref(), false)
            .await?;
        let events = transport::act_on_message_request(&self.client, action).await?;
        if !events_report_runtime_auth_expired(&events) {
            return Ok(events);
        }
        let mut retry = original;
        self.inject_runtime_authorization(&mut retry.headers, retry.auth.as_ref(), true)
            .await?;
        transport::act_on_message_request(&self.client, retry).await
    }

    async fn fetch_allowlist(
        &mut self,
        mut fetch: FetchAllowlistRequest,
    ) -> Result<Vec<CoreEvent>> {
        let original = fetch.clone();
        self.inject_runtime_authorization(&mut fetch.headers, fetch.auth.as_ref(), false)
            .await?;
        let events = transport::fetch_allowlist(&self.client, fetch).await?;
        if !events_report_runtime_auth_expired(&events) {
            return Ok(events);
        }
        let mut retry = original;
        self.inject_runtime_authorization(&mut retry.headers, retry.auth.as_ref(), true)
            .await?;
        transport::fetch_allowlist(&self.client, retry).await
    }

    async fn replace_allowlist(
        &mut self,
        mut update: ReplaceAllowlistRequest,
    ) -> Result<Vec<CoreEvent>> {
        let original = update.clone();
        self.inject_runtime_authorization(&mut update.headers, update.auth.as_ref(), false)
            .await?;
        let events = transport::replace_allowlist(&self.client, update).await?;
        if !events_report_runtime_auth_expired(&events) {
            return Ok(events);
        }
        let mut retry = original;
        self.inject_runtime_authorization(&mut retry.headers, retry.auth.as_ref(), true)
            .await?;
        transport::replace_allowlist(&self.client, retry).await
    }

    async fn publish_shared_state(
        &mut self,
        mut publish: PublishSharedStateRequest,
    ) -> Result<Vec<CoreEvent>> {
        let original = publish.clone();
        self.inject_runtime_authorization(&mut publish.headers, publish.auth.as_ref(), false)
            .await?;
        let events = transport::publish_shared_state(&self.client, publish).await?;
        if !events_report_runtime_auth_expired(&events) {
            return Ok(events);
        }
        let mut retry = original;
        self.inject_runtime_authorization(&mut retry.headers, retry.auth.as_ref(), true)
            .await?;
        transport::publish_shared_state(&self.client, retry).await
    }

    async fn append_group_envelope(
        &mut self,
        append: AppendGroupEnvelopeRequest,
    ) -> Result<Vec<CoreEvent>> {
        let endpoint = self.group_outbox_endpoint(&append.group_id).await?;
        let request = self
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
                        failure: tapchat_core::AppErrorV1::from_http_response(status, &body),
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
            Err(_error) => Ok(vec![CoreEvent::GroupEnvelopeAppendFailed {
                group_id: append.group_id,
                message_id: append.envelope.message_id,
                failure: tapchat_core::AppErrorV1::network_unavailable(),
            }]),
        }
    }

    async fn initialize_group_authorization(
        &mut self,
        mut initialize: InitializeGroupAuthorizationRequest,
    ) -> Result<Vec<CoreEvent>> {
        let already_retried = initialize
            .headers
            .remove("X-Tapchat-Runtime-Retry")
            .is_some();
        let original = initialize.clone();
        self.inject_runtime_authorization(&mut initialize.headers, initialize.auth.as_ref(), false)
            .await?;
        let base = self.inbox_base_url().await?;
        let endpoint = format!(
            "{}/v1/groups/{}/authorization/bootstrap",
            base.trim_end_matches('/'),
            urlencoding::encode(&initialize.group_id)
        );
        let mut request = self
            .client
            .post(endpoint)
            .header("Content-Type", "application/json");
        for (name, value) in &initialize.headers {
            request = request.header(name, value);
        }
        let group_id = initialize.group_id.clone();
        let body = to_camel_case_json_string(&serde_json::to_string(&initialize)?)?;
        let events: Result<Vec<CoreEvent>> = match request.body(body).send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                let body = response.text().await.unwrap_or_default();
                if !(200..300).contains(&status) {
                    return Ok(vec![CoreEvent::GroupAuthorizationInitializeFailed {
                        group_id,
                        failure: tapchat_core::AppErrorV1::from_http_response(status, &body),
                    }]);
                }
                let body = to_snake_case_json_string(&body).unwrap_or(body);
                let result: InitializeGroupAuthorizationResult = serde_json::from_str(&body)?;
                Ok(vec![CoreEvent::GroupAuthorizationInitialized {
                    group_id,
                    roster_version: result.roster_version,
                }])
            }
            Err(_error) => Ok(vec![CoreEvent::GroupAuthorizationInitializeFailed {
                group_id,
                failure: tapchat_core::AppErrorV1::network_unavailable(),
            }]),
        };
        let events = events?;
        if already_retried || !events_report_runtime_auth_expired(&events) {
            return Ok(events);
        }
        let mut retry = original;
        self.inject_runtime_authorization(&mut retry.headers, retry.auth.as_ref(), true)
            .await?;
        retry
            .headers
            .insert("X-Tapchat-Runtime-Retry".into(), "1".into());
        Box::pin(self.initialize_group_authorization(retry)).await
    }

    async fn append_group_transition(
        &mut self,
        append: AppendGroupTransitionRequest,
    ) -> Result<Vec<CoreEvent>> {
        let endpoint = self
            .group_outbox_sibling_url(&append.group_id, "transitions")
            .await?;
        let group_id = append.group_id.clone();
        let transition_id = append.transition_id.clone();
        let response = self
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
            .body(to_camel_case_json_string(&serde_json::to_string(&append)?)?)
            .send()
            .await;
        match response {
            Ok(response) => {
                let status = response.status().as_u16();
                let body = response.text().await.unwrap_or_default();
                if !(200..300).contains(&status) {
                    return Ok(vec![CoreEvent::GroupTransitionAppendFailed {
                        group_id,
                        transition_id,
                        failure: tapchat_core::AppErrorV1::from_http_response(status, &body),
                    }]);
                }
                let body = to_snake_case_json_string(&body).unwrap_or(body);
                let result: AppendGroupTransitionResult = serde_json::from_str(&body)?;
                Ok(vec![CoreEvent::GroupTransitionAppended {
                    group_id,
                    transition_id: result.transition_id,
                    first_seq: result.first_seq,
                    last_seq: result.last_seq,
                    roster_version: result.roster_version,
                    last_commit_message_id: result.last_commit_message_id,
                }])
            }
            Err(_error) => Ok(vec![CoreEvent::GroupTransitionAppendFailed {
                group_id,
                transition_id,
                failure: tapchat_core::AppErrorV1::network_unavailable(),
            }]),
        }
    }

    async fn get_group_authorization_state(
        &mut self,
        get: GetGroupAuthorizationStateRequest,
    ) -> Result<Vec<CoreEvent>> {
        let base = self.inbox_base_url().await?;
        let endpoint = format!(
            "{}/v1/groups/{}/authorization/state",
            base.trim_end_matches('/'),
            urlencoding::encode(&get.group_id)
        );
        let group_id = get.group_id.clone();
        let response = self
            .client
            .get(endpoint)
            .header(
                "Authorization",
                format!("Bearer {}", get.capability.signature),
            )
            .header(
                "X-Tapchat-Group-Capability",
                to_camel_case_json_string(&serde_json::to_string(&get.capability)?)?,
            )
            .send()
            .await;
        match response {
            Ok(response) => {
                let status = response.status().as_u16();
                let body = response.text().await.unwrap_or_default();
                if !(200..300).contains(&status) {
                    return Ok(vec![CoreEvent::GroupAuthorizationStateFetchFailed {
                        group_id,
                        failure: tapchat_core::AppErrorV1::from_http_response(status, &body),
                    }]);
                }
                let body = to_snake_case_json_string(&body).unwrap_or(body);
                let result: GetGroupAuthorizationStateResult = serde_json::from_str(&body)?;
                Ok(vec![CoreEvent::GroupAuthorizationStateFetched {
                    group_id,
                    manifest: result.manifest,
                    manifest_hash: result.manifest_hash,
                    last_transition_id: result.last_transition_id,
                    phase: result.phase,
                    materialized: result.materialized,
                }])
            }
            Err(_error) => Ok(vec![CoreEvent::GroupAuthorizationStateFetchFailed {
                group_id,
                failure: tapchat_core::AppErrorV1::network_unavailable(),
            }]),
        }
    }

    async fn fetch_group_outbox(
        &mut self,
        fetch: FetchGroupOutboxRequest,
    ) -> Result<Vec<CoreEvent>> {
        let url = self
            .group_outbox_messages_url(&fetch.group_id, fetch.from_seq, fetch.limit)
            .await?;
        let endpoint = summarize_endpoint_url(&url);
        let group_ref = redact_id("group", &fetch.group_id);
        log::info!(
            "[TransportPort] fetch_group_outbox start group_id={} from_seq={} limit={} endpoint={}",
            group_ref,
            fetch.from_seq,
            fetch.limit,
            endpoint
        );
        let request = self
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
                    log::warn!(
                        "[TransportPort] fetch_group_outbox failed group_id={} from_seq={} endpoint={} status={}",
                        group_ref,
                        fetch.from_seq,
                        endpoint,
                        status
                    );
                    return Ok(vec![CoreEvent::GroupOutboxFetchFailed {
                        group_id: fetch.group_id,
                        failure: tapchat_core::AppErrorV1::from_http_response(status, &body),
                    }]);
                }
                let body = to_snake_case_json_string(&body).unwrap_or(body);
                let result: FetchGroupOutboxResult = serde_json::from_str(&body)?;
                log::info!(
                    "[TransportPort] fetch_group_outbox accepted group_id={} from_seq={} endpoint={} to_seq={} records={}",
                    group_ref,
                    fetch.from_seq,
                    endpoint,
                    result.to_seq,
                    result.records.len()
                );
                let mut events = Vec::new();
                if result.history_floor_seq > 0 {
                    events.push(CoreEvent::GroupHistoryFloorAdvanced {
                        group_id: fetch.group_id.clone(),
                        history_floor_seq: result.history_floor_seq,
                    });
                }
                events.push(CoreEvent::GroupOutboxFetched {
                    group_id: fetch.group_id,
                    records: result.records,
                    to_seq: result.to_seq,
                });
                Ok(events)
            }
            Err(_error) => {
                log::warn!(
                    "[TransportPort] fetch_group_outbox request failed group_id={} from_seq={} endpoint={} error=request_failed",
                    group_ref,
                    fetch.from_seq,
                    endpoint
                );
                Ok(vec![CoreEvent::GroupOutboxFetchFailed {
                    group_id: fetch.group_id,
                    failure: tapchat_core::AppErrorV1::network_unavailable(),
                }])
            }
        }
    }

    async fn get_group_outbox_head(
        &mut self,
        get: GetGroupOutboxHeadRequest,
    ) -> Result<Vec<CoreEvent>> {
        let url = self.group_outbox_sibling_url(&get.group_id, "head").await?;
        let endpoint = summarize_endpoint_url(&url);
        let group_ref = redact_id("group", &get.group_id);
        log::info!(
            "[TransportPort] get_group_outbox_head start group_id={} endpoint={}",
            group_ref,
            endpoint
        );
        let response = match self
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
            Err(_error) => {
                log::warn!(
                    "[TransportPort] get_group_outbox_head request failed group_id={} endpoint={} error=request_failed",
                    group_ref,
                    endpoint
                );
                return Ok(vec![CoreEvent::GroupOutboxHeadFetchFailed {
                    group_id: get.group_id,
                    failure: tapchat_core::AppErrorV1::network_unavailable(),
                }]);
            }
        };
        let status = response.status().as_u16();
        let body_text = response.text().await.unwrap_or_default();
        if !(200..300).contains(&status) {
            log::warn!(
                "[TransportPort] get_group_outbox_head failed group_id={} endpoint={} status={}",
                group_ref,
                endpoint,
                status
            );
            return Ok(vec![CoreEvent::GroupOutboxHeadFetchFailed {
                group_id: get.group_id,
                failure: tapchat_core::AppErrorV1::from_http_response(status, &body_text),
            }]);
        }
        let body = to_snake_case_json_string(&body_text).unwrap_or(body_text);
        let result: GetGroupOutboxHeadResult = match serde_json::from_str(&body) {
            Ok(result) => result,
            Err(_error) => {
                log::warn!(
                    "[TransportPort] get_group_outbox_head decode failed group_id={} endpoint={} error=decode_failed",
                    group_ref,
                    endpoint
                );
                return Ok(vec![CoreEvent::GroupOutboxHeadFetchFailed {
                    group_id: get.group_id,
                    failure: tapchat_core::AppErrorV1::from_registered_code("unexpected_error")
                        .with_http_status(status),
                }]);
            }
        };
        log::info!(
            "[TransportPort] get_group_outbox_head accepted group_id={} endpoint={} head_seq={}",
            group_ref,
            endpoint,
            result.head_seq
        );
        Ok(vec![CoreEvent::GroupOutboxHeadFetched {
            group_id: get.group_id,
            head_seq: result.head_seq,
            current_roster_version: result.current_roster_version,
            last_commit_message_id: result.last_commit_message_id,
        }])
    }

    async fn put_welcome_pickup(&mut self, put: PutWelcomePickupRequest) -> Result<Vec<CoreEvent>> {
        let group_ref = redact_id("group", &put.descriptor.group_id);
        let device_ref = redact_id("device", &put.descriptor.device_id);
        let endpoint = sanitize_url_for_log(&put.descriptor.endpoint);
        log::info!(
            "[TransportPort] put_welcome_pickup group_id={} device_id={} endpoint={}",
            group_ref,
            device_ref,
            endpoint
        );
        let response = self
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
                    let body = response.text().await.unwrap_or_default();
                    log::warn!(
                        "[TransportPort] put_welcome_pickup failed group_id={} device_id={} status={}",
                        group_ref,
                        device_ref,
                        status
                    );
                    return Ok(vec![CoreEvent::WelcomePickupPutFailed {
                        descriptor: put.descriptor,
                        failure: tapchat_core::AppErrorV1::from_http_response(status, &body),
                    }]);
                }
                let body = to_snake_case_json_string(&response.text().await.unwrap_or_default())?;
                let _result: PutWelcomePickupResult = serde_json::from_str(&body)?;
                log::info!(
                    "[TransportPort] put_welcome_pickup accepted group_id={} device_id={}",
                    group_ref,
                    device_ref
                );
                Ok(vec![CoreEvent::WelcomePickupPut {
                    descriptor: put.descriptor,
                }])
            }
            Err(_error) => Ok(vec![CoreEvent::WelcomePickupPutFailed {
                descriptor: put.descriptor,
                failure: tapchat_core::AppErrorV1::network_unavailable(),
            }]),
        }
    }

    async fn fetch_welcome_pickup(
        &mut self,
        fetch: FetchWelcomePickupRequest,
    ) -> Result<Vec<CoreEvent>> {
        let group_ref = redact_id("group", &fetch.descriptor.group_id);
        let device_ref = redact_id("device", &fetch.descriptor.device_id);
        let endpoint = sanitize_url_for_log(&fetch.descriptor.endpoint);
        log::info!(
            "[TransportPort] fetch_welcome_pickup group_id={} device_id={} endpoint={}",
            group_ref,
            device_ref,
            endpoint
        );
        let response = self
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
                    log::warn!(
                        "[TransportPort] fetch_welcome_pickup failed group_id={} device_id={} status={}",
                        group_ref,
                        device_ref,
                        status
                    );
                    return Ok(vec![CoreEvent::WelcomePickupFetchFailed {
                        descriptor: fetch.descriptor,
                        failure: tapchat_core::AppErrorV1::from_http_response(status, &body),
                    }]);
                }
                let body = to_snake_case_json_string(&body).unwrap_or(body);
                let result: FetchWelcomePickupResult = serde_json::from_str(&body)?;
                log::info!(
                    "[TransportPort] fetch_welcome_pickup accepted group_id={} device_id={} manifest_present={}",
                    group_ref,
                    device_ref,
                    result.manifest.is_some()
                );
                Ok(vec![CoreEvent::WelcomePickupFetched {
                    descriptor: fetch.descriptor,
                    welcome_b64: result.welcome_b64,
                    manifest: result.manifest,
                }])
            }
            Err(_error) => {
                log::warn!(
                    "[TransportPort] fetch_welcome_pickup transport error group_id={} device_id={} error=request_failed",
                    group_ref,
                    device_ref
                );
                Ok(vec![CoreEvent::WelcomePickupFetchFailed {
                    descriptor: fetch.descriptor,
                    failure: tapchat_core::AppErrorV1::network_unavailable(),
                }])
            }
        }
    }

    async fn create_group_invite(
        &mut self,
        create: CreateGroupInviteRequest,
    ) -> Result<Vec<CoreEvent>> {
        let base = self.inbox_base_url().await?;
        let response = self
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
                        failure: tapchat_core::AppErrorV1::from_http_response(status, &body),
                    }]);
                }
                let body = to_snake_case_json_string(&body).unwrap_or(body);
                let result: CreateGroupInviteResult = serde_json::from_str(&body)?;
                Ok(vec![CoreEvent::GroupInviteCreated {
                    invite_url: result.invite_url,
                    invite: result.invite,
                }])
            }
            Err(_error) => Ok(vec![CoreEvent::GroupInviteCreateFailed {
                group_id: create.group_id,
                failure: tapchat_core::AppErrorV1::network_unavailable(),
            }]),
        }
    }

    async fn revoke_group_invite(
        &mut self,
        revoke: RevokeGroupInviteRequest,
    ) -> Result<Vec<CoreEvent>> {
        let base = self.inbox_base_url().await?;
        let response = self
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
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            anyhow::bail!("group invite revoke failed with status {}", status);
        }
        let body = to_snake_case_json_string(&response.text().await.unwrap_or_default())?;
        let result: RevokeGroupInviteResult = serde_json::from_str(&body)?;
        Ok(vec![CoreEvent::GroupInviteRevoked {
            group_id: revoke.group_id,
            invite_id: result.invite_id,
        }])
    }

    async fn list_group_invites(
        &mut self,
        list: ListGroupInvitesRequest,
    ) -> Result<Vec<CoreEvent>> {
        let base = self.inbox_base_url().await?;
        let response = self
            .client
            .get(format!(
                "{}/v1/groups/{}/invites",
                base.trim_end_matches('/'),
                urlencoding::encode(&list.group_id)
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
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();
        if !(200..300).contains(&status) {
            anyhow::bail!("group invite list failed with status {status}: {body}");
        }
        let body = to_snake_case_json_string(&body).unwrap_or(body);
        let result: ListGroupInvitesResult = serde_json::from_str(&body)?;
        Ok(vec![CoreEvent::GroupInvitesListed {
            group_id: list.group_id,
            revision: result.revision,
            invites: result.invites,
        }])
    }

    async fn fetch_group_invite(
        &mut self,
        fetch: FetchGroupInviteRequest,
    ) -> Result<Vec<CoreEvent>> {
        match fetch_external_json(&fetch.invite_url, ExternalResourceKind::GroupInvite).await {
            Ok(body) => {
                let body = to_snake_case_json_string(&body).unwrap_or(body);
                let result: FetchGroupInviteResult = serde_json::from_str(&body)?;
                if let Err(_error) =
                    validate_group_invite_transport_binding(&fetch.invite_url, &result.invite)
                {
                    return Ok(vec![CoreEvent::GroupInviteFetchFailed {
                        invite_url: fetch.invite_url,
                        failure: tapchat_core::AppErrorV1::from_registered_code("invalid_invite"),
                    }]);
                }
                Ok(vec![CoreEvent::GroupInviteFetched {
                    invite_url: fetch.invite_url,
                    invite: result.invite,
                }])
            }
            Err(error) => Ok(vec![CoreEvent::GroupInviteFetchFailed {
                invite_url: fetch.invite_url,
                failure: if error.code() == "external_fetch_timeout" {
                    tapchat_core::AppErrorV1::from_registered_code("request_timeout")
                } else {
                    tapchat_core::AppErrorV1::network_unavailable()
                },
            }]),
        }
    }

    async fn submit_group_join_request(
        &mut self,
        submit: SubmitGroupJoinRequest,
    ) -> Result<Vec<CoreEvent>> {
        let response = self
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
                        failure: tapchat_core::AppErrorV1::from_http_response(status, &body),
                    }]);
                }
                let body = to_snake_case_json_string(&body).unwrap_or(body);
                let result: SubmitGroupJoinResult = serde_json::from_str(&body)?;
                Ok(vec![CoreEvent::GroupJoinRequestSubmitted {
                    request: result.request,
                }])
            }
            Err(_error) => Ok(vec![CoreEvent::GroupJoinRequestSubmitFailed {
                invite_url: submit.invite_token,
                failure: tapchat_core::AppErrorV1::network_unavailable(),
            }]),
        }
    }

    async fn list_group_join_requests(
        &mut self,
        list: ListGroupJoinRequestsRequest,
    ) -> Result<Vec<CoreEvent>> {
        let base = self.inbox_base_url().await?;
        let response = self
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
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            anyhow::bail!("group join list failed with status {}", status);
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
            .client
            .get(&get.endpoint)
            .header(
                "Authorization",
                format!("Bearer {}", get.request_capability),
            )
            .send()
            .await?;
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            anyhow::bail!("group join status failed with status {}", status);
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
        let base = self.inbox_base_url().await?;
        let response = self
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
                        failure: tapchat_core::AppErrorV1::from_http_response(status, &body),
                    }]);
                }
                let body = to_snake_case_json_string(&body).unwrap_or(body);
                let result: DecideGroupJoinResult = serde_json::from_str(&body)?;
                Ok(vec![CoreEvent::GroupJoinDecisionApplied {
                    request: result.request,
                }])
            }
            Err(_error) => Ok(vec![CoreEvent::GroupJoinDecisionFailed {
                group_id: decide.group_id,
                request_id: decide.request_id,
                failure: tapchat_core::AppErrorV1::network_unavailable(),
            }]),
        }
    }

    async fn claim_group_join_request(
        &mut self,
        claim: ClaimGroupJoinRequest,
    ) -> Result<Vec<CoreEvent>> {
        let base = self.inbox_base_url().await?;
        let response = self
            .client
            .post(format!(
                "{}/v1/groups/{}/join-requests/{}/claim",
                base.trim_end_matches('/'),
                urlencoding::encode(&claim.group_id),
                urlencoding::encode(&claim.request_id)
            ))
            .header(
                "Authorization",
                format!("Bearer {}", claim.capability.signature),
            )
            .header("Content-Type", "application/json")
            .body(to_camel_case_json_string(&serde_json::to_string(&claim)?)?)
            .send()
            .await;
        match response {
            Ok(response) => {
                let status = response.status().as_u16();
                let body = response.text().await.unwrap_or_default();
                if !(200..300).contains(&status) {
                    return Ok(vec![CoreEvent::GroupJoinClaimFailed {
                        group_id: claim.group_id,
                        request_id: claim.request_id,
                        failure: tapchat_core::AppErrorV1::from_http_response(status, &body),
                    }]);
                }
                let body = to_snake_case_json_string(&body).unwrap_or(body);
                let result: ClaimGroupJoinResult = serde_json::from_str(&body)?;
                Ok(vec![CoreEvent::GroupJoinClaimed {
                    request: result.request,
                    lease_token: result.lease_token,
                    lease_expires_at: result.lease_expires_at,
                }])
            }
            Err(_error) => Ok(vec![CoreEvent::GroupJoinClaimFailed {
                group_id: claim.group_id,
                request_id: claim.request_id,
                failure: tapchat_core::AppErrorV1::network_unavailable(),
            }]),
        }
    }

    async fn complete_group_join_request(
        &mut self,
        complete: CompleteGroupJoinRequest,
    ) -> Result<Vec<CoreEvent>> {
        let base = self.inbox_base_url().await?;
        let response = self
            .client
            .post(format!(
                "{}/v1/groups/{}/join-requests/{}/complete",
                base.trim_end_matches('/'),
                urlencoding::encode(&complete.group_id),
                urlencoding::encode(&complete.request_id)
            ))
            .header(
                "Authorization",
                format!("Bearer {}", complete.capability.signature),
            )
            .header("Content-Type", "application/json")
            .body(to_camel_case_json_string(&serde_json::to_string(
                &complete,
            )?)?)
            .send()
            .await;
        match response {
            Ok(response) => {
                let status = response.status().as_u16();
                let body = response.text().await.unwrap_or_default();
                if !(200..300).contains(&status) {
                    return Ok(vec![CoreEvent::GroupJoinCompleteFailed {
                        group_id: complete.group_id,
                        request_id: complete.request_id,
                        failure: tapchat_core::AppErrorV1::from_http_response(status, &body),
                    }]);
                }
                let body = to_snake_case_json_string(&body).unwrap_or(body);
                let result: CompleteGroupJoinResult = serde_json::from_str(&body)?;
                Ok(vec![CoreEvent::GroupJoinCompleted {
                    request: result.request,
                }])
            }
            Err(_error) => Ok(vec![CoreEvent::GroupJoinCompleteFailed {
                group_id: complete.group_id,
                request_id: complete.request_id,
                failure: tapchat_core::AppErrorV1::network_unavailable(),
            }]),
        }
    }

    async fn submit_group_leave_request(
        &mut self,
        submit: SubmitGroupLeaveRequest,
    ) -> Result<Vec<CoreEvent>> {
        let base = self.inbox_base_url().await?;
        let response = self
            .client
            .post(format!(
                "{}/v1/groups/{}/leave-requests",
                base.trim_end_matches('/'),
                urlencoding::encode(&submit.group_id)
            ))
            .header(
                "Authorization",
                format!("Bearer {}", submit.capability.signature),
            )
            .header("Content-Type", "application/json")
            .body(to_camel_case_json_string(&serde_json::to_string(&submit)?)?)
            .send()
            .await;
        match response {
            Ok(response) => {
                let status = response.status().as_u16();
                let body = response.text().await.unwrap_or_default();
                if !(200..300).contains(&status) {
                    return Ok(vec![CoreEvent::GroupLeaveRequestSubmitFailed {
                        group_id: submit.group_id,
                        request_id: submit.request.request_id,
                        failure: tapchat_core::AppErrorV1::from_http_response(status, &body),
                    }]);
                }
                let body = to_snake_case_json_string(&body).unwrap_or(body);
                let result: SubmitGroupLeaveResult = serde_json::from_str(&body)?;
                Ok(vec![CoreEvent::GroupLeaveRequestSubmitted {
                    request: result.request,
                }])
            }
            Err(_error) => Ok(vec![CoreEvent::GroupLeaveRequestSubmitFailed {
                group_id: submit.group_id,
                request_id: submit.request.request_id,
                failure: tapchat_core::AppErrorV1::network_unavailable(),
            }]),
        }
    }

    async fn list_group_leave_requests(
        &mut self,
        list: ListGroupLeaveRequestsRequest,
    ) -> Result<Vec<CoreEvent>> {
        let base = self.inbox_base_url().await?;
        let response = self
            .client
            .get(format!(
                "{}/v1/groups/{}/leave-requests",
                base.trim_end_matches('/'),
                urlencoding::encode(&list.group_id)
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
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();
        if !(200..300).contains(&status) {
            anyhow::bail!("group leave list failed with status {status}: {body}");
        }
        let result: ListGroupLeaveRequestsResult =
            serde_json::from_str(&to_snake_case_json_string(&body)?)?;
        Ok(vec![CoreEvent::GroupLeaveRequestsListed {
            group_id: list.group_id,
            requests: result.requests,
        }])
    }

    async fn claim_group_leave_request(
        &mut self,
        claim: ClaimGroupLeaveRequest,
    ) -> Result<Vec<CoreEvent>> {
        let base = self.inbox_base_url().await?;
        let response = self
            .client
            .post(format!(
                "{}/v1/groups/{}/leave-requests/{}/claim",
                base.trim_end_matches('/'),
                urlencoding::encode(&claim.group_id),
                urlencoding::encode(&claim.request_id)
            ))
            .header(
                "Authorization",
                format!("Bearer {}", claim.capability.signature),
            )
            .header("Content-Type", "application/json")
            .body(to_camel_case_json_string(&serde_json::to_string(&claim)?)?)
            .send()
            .await;
        match response {
            Ok(response) => {
                let status = response.status().as_u16();
                let body = response.text().await.unwrap_or_default();
                if !(200..300).contains(&status) {
                    return Ok(vec![CoreEvent::GroupLeaveClaimFailed {
                        group_id: claim.group_id,
                        request_id: claim.request_id,
                        failure: tapchat_core::AppErrorV1::from_http_response(status, &body),
                    }]);
                }
                let result: ClaimGroupLeaveResult =
                    serde_json::from_str(&to_snake_case_json_string(&body).unwrap_or(body))?;
                Ok(vec![CoreEvent::GroupLeaveClaimed {
                    request: result.request,
                    lease_token: result.lease_token,
                    lease_expires_at: result.lease_expires_at,
                }])
            }
            Err(_error) => Ok(vec![CoreEvent::GroupLeaveClaimFailed {
                group_id: claim.group_id,
                request_id: claim.request_id,
                failure: tapchat_core::AppErrorV1::network_unavailable(),
            }]),
        }
    }

    async fn seal_group_outbox(&mut self, seal: SealGroupOutboxRequest) -> Result<Vec<CoreEvent>> {
        let url = self
            .group_outbox_sibling_url(&seal.group_id, "seal")
            .await?;
        let response = match self
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
            Err(_error) => {
                return Ok(vec![CoreEvent::GroupOutboxSealFailed {
                    group_id: seal.group_id,
                    failure: tapchat_core::AppErrorV1::network_unavailable(),
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
}

fn map_seal_group_outbox_response(
    group_id: String,
    status: u16,
    body_text: &str,
) -> Vec<CoreEvent> {
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
            failure: tapchat_core::AppErrorV1::from_http_response(status, body_text),
        }];
    }

    if !(200..300).contains(&status) {
        return vec![CoreEvent::GroupOutboxSealFailed {
            group_id,
            failure: tapchat_core::AppErrorV1::from_http_response(status, body_text),
        }];
    }

    let body = to_snake_case_json_string(body_text).unwrap_or_else(|_| body_text.to_string());
    let result: SealGroupOutboxResult = match serde_json::from_str(&body) {
        Ok(result) => result,
        Err(_error) => {
            return vec![CoreEvent::GroupOutboxSealFailed {
                group_id,
                failure: tapchat_core::AppErrorV1::from_registered_code("unexpected_error")
                    .with_http_status(status),
            }];
        }
    };
    vec![CoreEvent::GroupOutboxSealed {
        group_id,
        sealed_at: result.sealed_at,
        was_already_sealed: result.was_already_sealed,
    }]
}

fn extract_error_code(body: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("code")
                .or_else(|| value.get("error").filter(|error| error.is_string()))
                .or_else(|| value.get("error").and_then(|error| error.get("code")))
                .and_then(|code| code.as_str())
                .map(ToOwned::to_owned)
        })
}

fn blob_prepare_failed_event(task_id: &str, error: &anyhow::Error) -> CoreEvent {
    let detail = error.to_string().to_ascii_lowercase();
    let code = if detail.contains("device_revoked") {
        "device_revoked"
    } else if detail.contains("runtime_mismatch") {
        "runtime_mismatch"
    } else if detail.contains("enrollment_required") {
        "enrollment_required"
    } else if detail.contains("status 400")
        || detail.contains("status 401")
        || detail.contains("status 403")
        || detail.contains("status 404")
        || detail.contains("parse prepare result")
        || detail.contains("convert prepare")
        || detail.contains("no base url")
    {
        "invalid_input"
    } else if detail.contains("runtime_auth_expired") {
        "runtime_auth_expired"
    } else {
        // Network, response-body, rate-limit, conflict and 5xx failures are
        // safe to retry because prepare-upload is idempotent by task id.
        "temporary_unavailable"
    };
    let failure = tapchat_core::AppErrorV1::from_registered_code(code);
    log::warn!(
        "Blob prepare failed: task_id={} code={} retryable={}",
        redact_id("task", task_id),
        code,
        failure.retryable
    );
    CoreEvent::BlobTransferFailed {
        task_id: task_id.to_string(),
        failure,
    }
}

fn runtime_auth_http_failure(request_id: &str, error: &anyhow::Error) -> CoreEvent {
    let detail = error.to_string().to_ascii_lowercase();
    let code = if detail.contains("device_revoked") {
        "device_revoked"
    } else if detail.contains("runtime_mismatch") {
        "runtime_mismatch"
    } else if detail.contains("enrollment_required") {
        "enrollment_required"
    } else {
        "temporary_unavailable"
    };
    CoreEvent::HttpRequestFailed {
        request_id: request_id.to_string(),
        failure: tapchat_core::AppErrorV1::from_registered_code(code),
    }
}

fn events_report_runtime_auth_expired(events: &[CoreEvent]) -> bool {
    events.iter().any(|event| match event {
        CoreEvent::MessageRequestsFetchFailed { failure, .. }
        | CoreEvent::MessageRequestActionFailed { failure, .. }
        | CoreEvent::AllowlistFetchFailed { failure, .. }
        | CoreEvent::AllowlistReplaceFailed { failure, .. }
        | CoreEvent::BlobTransferFailed { failure, .. } => failure.code == "runtime_auth_expired",
        CoreEvent::SharedStatePublishFailed { failure, .. } => {
            failure.code == "runtime_auth_expired"
        }
        CoreEvent::GroupAuthorizationInitializeFailed { failure, .. } => {
            failure.code == "runtime_auth_expired"
        }
        _ => false,
    })
}

fn extract_sealed_at(body: &str) -> Option<u64> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("sealed_at")
                .or_else(|| value.get("sealedAt"))
                .and_then(|sealed_at| sealed_at.as_u64())
        })
}

// --- RealtimePort ---
impl RealtimePort for DesktopPlatformPorts {
    async fn open_realtime(
        &mut self,
        mut subscription: RealtimeSubscriptionRequest,
    ) -> Result<Vec<CoreEvent>> {
        let original = subscription.clone();
        self.inject_runtime_authorization(
            &mut subscription.headers,
            subscription.auth.as_ref(),
            false,
        )
        .await?;
        let events = self.realtime.open_connection(subscription).await?;
        let expired = events.iter().any(|event| {
            matches!(
                event,
                CoreEvent::WebSocketDisconnected { reason: Some(reason), .. }
                    if reason.contains("runtime_auth_expired")
            )
        });
        if !expired {
            return Ok(events);
        }
        let mut retry = original;
        self.inject_runtime_authorization(&mut retry.headers, retry.auth.as_ref(), true)
            .await?;
        self.realtime.open_connection(retry).await
    }

    async fn close_realtime(&mut self, device_id: String) -> Result<Vec<CoreEvent>> {
        self.realtime.close_connection(&device_id).await
    }

    async fn open_group_realtime(
        &mut self,
        subscription: GroupRealtimeSubscriptionRequest,
    ) -> Result<Vec<CoreEvent>> {
        self.realtime.open_group_connection(subscription).await
    }

    async fn close_group_realtime(&mut self, group_id: String) -> Result<Vec<CoreEvent>> {
        self.realtime.close_group_connection(&group_id).await
    }
}

// --- BlobIoPort ---
impl BlobIoPort for DesktopPlatformPorts {
    async fn read_attachment_bytes(
        &mut self,
        read: ReadAttachmentBytesEffect,
    ) -> Result<Vec<CoreEvent>> {
        let staging_dir = self.persistence.transfer_staging_dir().await;

        // Emit progress event if we have app handle
        if let Some(app) = &self.app_handle {
            let _ = app.emit(
                "upload-progress",
                blob_io::UploadProgressEvent::simple(
                    read.task_id.clone(),
                    read.conversation_id.clone(),
                    5,
                    "reading",
                ),
            );
        }

        if let Some(staging_id) = read.attachment_id.strip_prefix("encrypted-staging:") {
            let Some(staging_dir) = staging_dir else {
                return Ok(vec![CoreEvent::BlobTransferFailed {
                    task_id: read.task_id,
                    failure: tapchat_core::AppErrorV1::from_registered_code(
                        "storage_integrity_error",
                    ),
                }]);
            };
            let encrypted = match tokio::fs::read(staging_dir.join(format!("{staging_id}.enc")))
                .await
            {
                Ok(encrypted) => encrypted,
                Err(_) => {
                    return Ok(vec![CoreEvent::BlobTransferFailed {
                        task_id: read.task_id,
                        failure: tapchat_core::AppErrorV1::from_registered_code("blob_not_found"),
                    }]);
                }
            };
            let bytes = {
                let pm = self.transport.profile_inner.read().await;
                let Some(profile) = pm.active_profile.as_ref() else {
                    return Ok(vec![CoreEvent::BlobTransferFailed {
                        task_id: read.task_id,
                        failure: tapchat_core::AppErrorV1::from_registered_code("profile_required"),
                    }]);
                };
                match profile.decrypt_profile_document(
                    &format!("attachment-staging/{staging_id}"),
                    &encrypted,
                ) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        return Ok(vec![CoreEvent::BlobTransferFailed {
                            task_id: read.task_id,
                            failure: tapchat_core::AppErrorV1::from_registered_code(
                                "storage_integrity_error",
                            ),
                        }]);
                    }
                }
            };
            return Ok(vec![CoreEvent::AttachmentBytesLoaded {
                task_id: read.task_id,
                plaintext: bytes,
            }]);
        }
        blob_io::read_attachment_bytes(read, self.persistence.attachment_cache_dir().await).await
    }

    async fn prepare_blob_upload(
        &mut self,
        mut upload: PrepareBlobUploadRequest,
    ) -> Result<Vec<CoreEvent>> {
        let original = upload.clone();
        if let Err(error) = self
            .inject_runtime_authorization(&mut upload.headers, upload.auth.as_ref(), false)
            .await
        {
            return Ok(vec![blob_prepare_failed_event(&upload.task_id, &error)]);
        }
        // Use transport to prepare upload
        let result = match self.transport.prepare_blob_upload(upload.clone()).await {
            Ok(result) => result,
            Err(error) if error.to_string().contains("runtime_auth_expired") => {
                let mut retry = original;
                if let Err(error) = self
                    .inject_runtime_authorization(&mut retry.headers, retry.auth.as_ref(), true)
                    .await
                {
                    return Ok(vec![blob_prepare_failed_event(&upload.task_id, &error)]);
                }
                upload = retry;
                match self.transport.prepare_blob_upload(upload.clone()).await {
                    Ok(result) => result,
                    Err(error) => {
                        return Ok(vec![blob_prepare_failed_event(&upload.task_id, &error)]);
                    }
                }
            }
            Err(error) => return Ok(vec![blob_prepare_failed_event(&upload.task_id, &error)]),
        };

        // Emit progress event
        if let Some(app) = &self.app_handle {
            let _ = app.emit(
                "upload-progress",
                blob_io::UploadProgressEvent::simple(
                    upload.task_id.clone(),
                    upload.conversation_id.clone(),
                    10,
                    "preparing",
                ),
            );
        }

        Ok(vec![CoreEvent::BlobUploadPrepared {
            task_id: upload.task_id,
            result,
        }])
    }

    async fn upload_blob(&mut self, upload: BlobUploadRequest) -> Result<Vec<CoreEvent>> {
        let app_handle = self.app_handle.clone();

        blob_io::upload_blob_with_progress(&self.client, upload, app_handle).await
    }

    async fn download_blob(&mut self, download: BlobDownloadRequest) -> Result<Vec<CoreEvent>> {
        if let Some(TransportAuthRequirement::BlobCapability {
            blob_ref,
            capability,
        }) = download.auth.as_ref()
        {
            let expected = format!("TapChat-Blob {capability}");
            if *blob_ref != download.blob_ref
                || download.download_headers.get("Authorization") != Some(&expected)
            {
                anyhow::bail!("blob capability does not match download request");
            }
        }
        let conversation_id = download.conversation_id.clone();
        let task_id = download.task_id.clone();

        // Emit download progress
        if let Some(app) = &self.app_handle {
            let _ = app.emit(
                "download-progress",
                blob_io::UploadProgressEvent::simple(
                    task_id.clone(),
                    conversation_id.clone(),
                    0,
                    "downloading",
                ),
            );
        }

        let result = blob_io::download_blob(&self.client, download, self.app_handle.clone()).await;

        // A transport response is not necessarily a successful download: the
        // blob adapter reports HTTP failures as BlobTransferFailed events so
        // Core can persist retry state. Reflect that distinction in the UI.
        if let Some(app) = &self.app_handle {
            let completed = result.as_ref().is_ok_and(|events| {
                events
                    .iter()
                    .any(|event| matches!(event, CoreEvent::BlobDownloaded { .. }))
            });
            let _ = app.emit(
                "download-progress",
                blob_io::UploadProgressEvent::simple(
                    task_id,
                    conversation_id,
                    if completed { 100 } else { 0 },
                    if completed { "complete" } else { "failed" },
                ),
            );
        }

        result
    }

    async fn delete_blob(&mut self, delete: DeleteBlobRequest) -> Result<Vec<CoreEvent>> {
        let response = self
            .client
            .delete(&delete.delete_target)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("TapChat-Delete {}", delete.delete_capability),
            )
            .send()
            .await;
        match response {
            Ok(response) if response.status().is_success() || response.status().as_u16() == 404 => {
                Ok(vec![CoreEvent::BlobDeleted {
                    task_id: delete.task_id,
                }])
            }
            Ok(response) => {
                let status = response.status().as_u16();
                let body = response.text().await.unwrap_or_default();
                Ok(vec![CoreEvent::BlobDeleteFailed {
                    task_id: delete.task_id,
                    failure: tapchat_core::AppErrorV1::from_http_response(status, &body),
                }])
            }
            Err(_) => Ok(vec![CoreEvent::BlobDeleteFailed {
                task_id: delete.task_id,
                failure: tapchat_core::AppErrorV1::network_unavailable(),
            }]),
        }
    }

    async fn write_downloaded_attachment(
        &mut self,
        write: WriteDownloadedAttachmentEffect,
    ) -> Result<Vec<CoreEvent>> {
        let dir = self.persistence.attachment_cache_dir().await;
        if let Some(destination) =
            media_cache::EncryptedCacheDestination::parse(&write.destination_id)?
        {
            let dir = dir.ok_or_else(|| anyhow::anyhow!("no attachments directory configured"))?;
            crate::commands::message::ensure_attachment_cache_has_space(&dir)
                .map_err(anyhow::Error::msg)?;
            let encrypted = {
                let pm = self.transport.profile_inner.read().await;
                let profile = pm
                    .active_profile
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("no active profile"))?;
                profile
                    .encrypt_profile_document(
                        &format!("attachment-cache/{}", destination.cache_id()),
                        &write.plaintext,
                    )
                    .context("encrypt attachment cache")?
            };
            // Never join the untrusted opaque id directly. Rebuild the local
            // path from the validated cache digest.
            let path = dir.join(destination.relative_path());
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            let temp = path.with_extension("tmp");
            tokio::fs::write(&temp, encrypted).await?;
            tokio::fs::rename(temp, path).await?;
            return Ok(Vec::new());
        }
        blob_io::write_downloaded_attachment(write, dir).await
    }

    async fn cache_uploaded_attachment(
        &mut self,
        cache: CacheUploadedAttachmentEffect,
    ) -> Result<Vec<CoreEvent>> {
        let Some(staging_id) = cache
            .source_attachment_id
            .strip_prefix("encrypted-staging:")
            .filter(|value| !value.is_empty() && !value.contains('/') && !value.contains('\\'))
        else {
            // A non-desktop adapter may use a path or another opaque handle.
            // Desktop only owns encrypted-staging handles and must never
            // delete an arbitrary source path.
            return Ok(Vec::new());
        };
        let dir = self
            .persistence
            .attachment_cache_dir()
            .await
            .ok_or_else(|| anyhow::anyhow!("no attachments directory configured"))?;
        let cache_id = tapchat_core::attachment_crypto::blob_cache_id(
            &cache.storage_origin,
            &cache.object_ref,
        );
        let destination = media_cache::EncryptedCacheDestination::from_cache_id(&cache_id)?;
        let relative_path = destination.relative_path();
        let encrypted = {
            let pm = self.transport.profile_inner.read().await;
            let profile = pm
                .active_profile
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("no active profile"))?;
            profile
                .encrypt_profile_document(
                    &format!("attachment-cache/{}", destination.cache_id()),
                    &cache.plaintext,
                )
                .context("encrypt uploaded attachment cache")?
        };
        let destination = dir.join(&relative_path);
        crate::commands::message::ensure_attachment_cache_has_space(&dir)
            .map_err(anyhow::Error::msg)?;
        if let Some(parent) = destination.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let temp = destination.with_extension("tmp");
        tokio::fs::write(&temp, encrypted).await?;
        tokio::fs::rename(&temp, &destination).await?;

        // Index the completed cache entry before removing staging. A crash at
        // any earlier point leaves the durable staging copy available for a
        // retry; after this point the encrypted cache is authoritative.
        {
            let pm = self.transport.profile_inner.read().await;
            let profile = pm
                .active_profile
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("no active profile"))?;
            profile.save_attachment_cache_entry(
                &tapchat_core::cli::profile::AttachmentCacheEntry {
                    cache_id: cache_id.clone(),
                    relative_path,
                    mime_type: Some(cache.mime_type),
                    size_bytes: Some(cache.size_bytes),
                    updated_at_ms: crate::ts_ms().min(u64::MAX as u128) as u64,
                },
            )?;
        }
        let staging_dir = self
            .persistence
            .transfer_staging_dir()
            .await
            .ok_or_else(|| anyhow::anyhow!("no transfer staging directory configured"))?;
        let staging_path = staging_dir.join(format!("{staging_id}.enc"));
        match tokio::fs::remove_file(staging_path).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(Vec::new())
    }

    async fn release_staged_attachment(
        &mut self,
        release: tapchat_core::ffi_api::ReleaseStagedAttachmentEffect,
    ) -> Result<Vec<CoreEvent>> {
        let Some(staging_dir) = self.persistence.transfer_staging_dir().await else {
            return Ok(Vec::new());
        };
        for attachment_id in release.attachment_ids {
            let Some(staging_id) = attachment_id
                .strip_prefix("encrypted-staging:")
                .filter(|value| !value.is_empty() && !value.contains('/') && !value.contains('\\'))
            else {
                continue;
            };
            match tokio::fs::remove_file(staging_dir.join(format!("{staging_id}.enc"))).await {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(Vec::new())
    }
}

// --- PersistencePort ---
impl PersistencePort for DesktopPlatformPorts {
    async fn persist_state(&mut self, persist: PersistStateEffect) -> Result<()> {
        self.persistence
            .persist(persist)
            .await
            .context("desktop persistence failed")
    }
}

// --- TimerPort ---
impl TimerPort for DesktopPlatformPorts {
    fn schedule_timer(&mut self, timer_id: String, delay_ms: u64) -> Result<Vec<CoreEvent>> {
        self.timer.schedule_with_handle(timer_id, delay_ms);
        Ok(Vec::new())
    }
}

// --- NotificationPort ---
impl NotificationPort for DesktopPlatformPorts {
    fn emit_user_notification(
        &mut self,
        notification: UserNotificationEffect,
    ) -> Result<Vec<CoreEvent>> {
        if let Err(_error) = self.notification.emit_user_notification(notification) {
            log::error!("Notification error: delivery_failed");
        }
        Ok(Vec::new())
    }
}

// --- SecureStoragePort (skeleton) ---
impl SecureStoragePort for DesktopPlatformPorts {}

#[cfg(test)]
mod tests {
    use super::*;
    use tapchat_core::cli::profile::{
        override_profile_registry_path_for_test, Profile, ProfileInitOptions, ProfileRegistry,
    };

    #[test]
    fn blob_prepare_errors_always_return_a_core_failure_event() {
        let retryable = blob_prepare_failed_event(
            "task:1",
            &anyhow::anyhow!("prepare blob upload: connection reset"),
        );
        assert!(matches!(
            retryable,
            CoreEvent::BlobTransferFailed {
                failure: tapchat_core::AppErrorV1 {
                    retryable: true,
                    ..
                },
                ..
            }
        ));
        let revoked = blob_prepare_failed_event(
            "task:2",
            &anyhow::anyhow!("runtime_auth_error:device_revoked"),
        );
        assert!(matches!(
            revoked,
            CoreEvent::BlobTransferFailed {
                failure: tapchat_core::AppErrorV1 {
                    retryable: false,
                    ..
                },
                ..
            }
        ));
    }

    #[tokio::test]
    async fn encrypted_cache_writer_accepts_canonical_and_legacy_windows_destinations() {
        let temp_dir =
            std::env::temp_dir().join(format!("tapchat-cache-port-test-{}", uuid::Uuid::new_v4()));
        let _registry_override =
            override_profile_registry_path_for_test(temp_dir.join("config").join("profiles.json"));
        let profile = Profile::init_with_options(
            "cache-writer",
            temp_dir.join("profile"),
            ProfileInitOptions {
                passphrase: Some("test-passphrase".into()),
                use_keychain: false,
            },
        )
        .expect("init profile");
        let attachments_dir = profile.metadata().attachments_dir.clone();
        let profile_inner = Arc::new(RwLock::new(ProfileManagerInner {
            registry: ProfileRegistry::default(),
            active_profile: Some(profile),
            locked_profile_path: None,
            unlock_error: None,
            storage_layout: crate::storage_layout::DesktopStorageLayout::system_default()
                .expect("desktop storage layout"),
        }));
        let mut ports =
            DesktopPlatformPorts::new(profile_inner.clone(), RuntimeAuthManager::default());

        let cases = [
            (
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "attachment-cache/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.enc",
                b"preview plaintext".as_slice(),
            ),
            (
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "attachment-cache\\bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.enc",
                b"original plaintext".as_slice(),
            ),
        ];

        for (cache_id, destination_id, plaintext) in cases {
            ports
                .write_downloaded_attachment(WriteDownloadedAttachmentEffect {
                    task_id: format!("download:{cache_id}"),
                    destination_id: destination_id.into(),
                    plaintext: plaintext.to_vec(),
                })
                .await
                .expect("write encrypted cache through desktop port");

            let path = attachments_dir
                .join("objects")
                .join(format!("{cache_id}.enc"));
            let encrypted = std::fs::read(path).expect("read encrypted cache");
            assert!(!encrypted
                .windows(plaintext.len())
                .any(|window| window == plaintext));
            let decrypted = {
                let manager = profile_inner.read().await;
                manager
                    .active_profile
                    .as_ref()
                    .expect("active profile")
                    .decrypt_profile_document(&format!("attachment-cache/{cache_id}"), &encrypted)
                    .expect("decrypt cache")
            };
            assert_eq!(decrypted, plaintext);
        }

        drop(ports);
        drop(profile_inner);
        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn runtime_auth_injection_failure_is_returned_to_core() {
        let temporary = runtime_auth_http_failure(
            "request:1",
            &anyhow::anyhow!("runtime_auth_error:temporary_unavailable"),
        );
        assert!(matches!(
            temporary,
            CoreEvent::HttpRequestFailed {
                failure: tapchat_core::AppErrorV1 {
                    retryable: true,
                    ..
                },
                ..
            }
        ));
        let revoked = runtime_auth_http_failure(
            "request:2",
            &anyhow::anyhow!("runtime_auth_error:device_revoked"),
        );
        assert!(matches!(
            revoked,
            CoreEvent::HttpRequestFailed {
                failure: tapchat_core::AppErrorV1 {
                    retryable: false,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn summarize_share_url_redacts_contact_share_token() {
        let summary = summarize_share_url(Some(
            "https://example.com/v1/contact-share/secret-token-value",
        ));
        assert!(summary.starts_with("https://<host:"));
        assert!(summary.ends_with("/v1/contact-share/<redacted>"));
        assert!(!summary.contains("example.com"));
        assert!(!summary.contains("secret-token-value"));
    }

    #[test]
    fn group_outbox_messages_url_uses_manifest_endpoint_host_and_replaces_query() {
        let url = group_outbox_messages_url_from_endpoint(
            "https://owner.example/v1/groups/group:test/outbox/messages?old=1#fragment",
            7,
            50,
        )
        .expect("messages url");

        assert_eq!(url.host_str(), Some("owner.example"));
        assert_eq!(url.path(), "/v1/groups/group:test/outbox/messages");
        assert_eq!(url.query(), Some("fromSeq=7&limit=50"));
        assert_eq!(url.fragment(), None);
        assert!(!url.as_str().contains("old=1"));
    }

    #[test]
    fn group_outbox_sibling_url_uses_manifest_endpoint_host() {
        let head = group_outbox_sibling_url_from_endpoint(
            "https://owner.example/v1/groups/group:test/outbox/messages?old=1#fragment",
            "head",
        )
        .expect("head url");
        assert_eq!(head.host_str(), Some("owner.example"));
        assert_eq!(head.path(), "/v1/groups/group:test/outbox/head");
        assert_eq!(head.query(), None);
        assert_eq!(head.fragment(), None);

        let seal = group_outbox_sibling_url_from_endpoint(
            "https://owner.example/v1/groups/group:test/outbox/messages",
            "seal",
        )
        .expect("seal url");
        assert_eq!(seal.host_str(), Some("owner.example"));
        assert_eq!(seal.path(), "/v1/groups/group:test/outbox/seal");
    }

    #[test]
    fn group_outbox_endpoint_must_be_messages_endpoint() {
        let error = group_outbox_sibling_url_from_endpoint(
            "https://owner.example/v1/groups/group:test/outbox/head",
            "head",
        )
        .expect_err("invalid outbox endpoint should be rejected");

        assert!(error
            .to_string()
            .contains("group outbox endpoint must end with /outbox/messages"));
    }
}

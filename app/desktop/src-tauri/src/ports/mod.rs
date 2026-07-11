pub mod blob_io;
pub mod notification;
pub mod persistence;
pub mod realtime;
pub mod timer;
pub mod transport;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tapchat_core::ffi_api::{
    CoreEvent, HttpMethod, HttpRequestEffect, PersistStateEffect, ReadAttachmentBytesEffect,
    UserNotificationEffect, WriteDownloadedAttachmentEffect,
};
use tapchat_core::model::CURRENT_MODEL_VERSION;
use tapchat_core::platform_ports::{
    BlobIoPort, NotificationPort, PersistencePort, RealtimePort, SecureStoragePort, TimerPort,
    TransportPort,
};
use tapchat_core::transport_contract::json_case::{
    to_camel_case_json_string, to_snake_case_json_string,
};
use tapchat_core::transport_contract::{
    AppendEnvelopeRequest, AppendGroupEnvelopeRequest, AppendGroupEnvelopeResult,
    AppendGroupTransitionRequest, AppendGroupTransitionResult, AuthorizeBlobDownloadRequest,
    BlobDownloadRequest, BlobUploadRequest, ClaimGroupJoinRequest, ClaimGroupJoinResult,
    ClaimGroupLeaveRequest, ClaimGroupLeaveResult, CompleteGroupJoinRequest,
    CompleteGroupJoinResult, CreateGroupInviteRequest, CreateGroupInviteResult,
    DecideGroupJoinRequest, DecideGroupJoinResult, FetchAllowlistRequest, FetchGroupInviteRequest,
    FetchGroupInviteResult, FetchGroupOutboxRequest, FetchGroupOutboxResult,
    FetchIdentityBundleRequest, FetchMessageRequestsRequest, FetchWelcomePickupRequest,
    FetchWelcomePickupResult, GetGroupAuthorizationStateRequest, GetGroupAuthorizationStateResult,
    GetGroupJoinRequestStatusRequest, GetGroupJoinRequestStatusResult, GetGroupOutboxHeadRequest,
    GetGroupOutboxHeadResult, GroupRealtimeSubscriptionRequest,
    InitializeGroupAuthorizationRequest, InitializeGroupAuthorizationResult,
    ListGroupInvitesRequest, ListGroupInvitesResult, ListGroupJoinRequestsRequest,
    ListGroupJoinRequestsResult, ListGroupLeaveRequestsRequest, ListGroupLeaveRequestsResult,
    MessageRequestActionRequest, PrepareBlobUploadRequest, PublishSharedStateRequest,
    PutWelcomePickupRequest, PutWelcomePickupResult, RealtimeSubscriptionRequest,
    ReplaceAllowlistRequest, RevokeGroupInviteRequest, RevokeGroupInviteResult,
    SealGroupOutboxRequest, SealGroupOutboxResult, SubmitGroupJoinRequest, SubmitGroupJoinResult,
    SubmitGroupLeaveRequest, SubmitGroupLeaveResult,
};
use tauri::{AppHandle, Emitter};
use tokio::sync::RwLock;

use crate::platform::log_sanitize::{redact_id, sanitize_url_for_log};
use crate::platform::persistence::DesktopPersistence;
use crate::platform::profile::ProfileManagerInner;
use crate::platform::realtime::RealtimeManager;
use crate::platform::transport::DesktopTransport;

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
    /// Current conversation ID for upload progress context
    current_conversation_id: Option<String>,
    // Timer uses spawn directly
}

impl DesktopPlatformPorts {
    pub fn new(profile_inner: Arc<RwLock<ProfileManagerInner>>) -> Self {
        Self {
            transport: DesktopTransport::new(profile_inner.clone()),
            realtime: RealtimeManager::new(profile_inner.clone()),
            persistence: DesktopPersistence::new(profile_inner),
            notification: notification::NotificationManager::new(),
            timer: timer::TimerManager::new(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .unwrap_or_else(|error| {
                    log::warn!(
                        "Failed to build timeout-configured desktop HTTP client: {}",
                        error
                    );
                    reqwest::Client::new()
                }),
            app_handle: None,
            current_conversation_id: None,
        }
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

    /// Set the current conversation ID for upload progress context
    pub fn set_conversation_context(&mut self, conversation_id: String) {
        self.current_conversation_id = Some(conversation_id);
    }

    /// Build contact share URL for sender identification in message requests.
    /// This generates a signed URL that allows recipients to fetch the sender's identity bundle.
    async fn build_contact_share_url(&self) -> Result<Option<String>> {
        let pm = self.transport.profile_inner.read().await;

        // Get active profile
        let Some(profile) = pm.active_profile.as_ref() else {
            log::warn!("No active profile found for contact share URL");
            return Ok(None);
        };

        // Load runtime metadata
        let runtime = match profile.load_runtime_metadata() {
            Ok(r) => r,
            Err(e) => {
                log::warn!("Failed to load runtime metadata: {}", e);
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
            Err(e) => {
                log::warn!("Failed to load snapshot: {}", e);
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

        // Build signed token
        let user_id = local_bundle.user_id.clone();
        let token = sign_contact_share_token(&sharing_secret, &user_id, &share_id)?;

        Ok(Some(format!(
            "{}/v1/contact-share/{}",
            base_url.trim_end_matches('/'),
            token
        )))
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
    async fn execute_http_request(&mut self, request: HttpRequestEffect) -> Result<Vec<CoreEvent>> {
        // Intercept append envelope requests to inject correct sender_bundle_share_url
        if request.method == HttpMethod::Post && request.url.contains("/messages") {
            log::info!("[TransportPort] Intercepting /messages POST request");
            if let Some(body) = &request.body {
                // Try to parse as AppendEnvelopeRequest
                if let Ok(mut append_request) = serde_json::from_str::<AppendEnvelopeRequest>(body)
                {
                    log::info!("[TransportPort] Parsed AppendEnvelopeRequest successfully");
                    log::info!(
                        "[TransportPort] sender_bundle_share_url={}",
                        summarize_share_url(append_request.sender_bundle_share_url.as_deref())
                    );

                    // Check if sender_bundle_share_url needs to be replaced
                    // It should be a contact-share URL, not identity_bundle_ref
                    let needs_contact_share_url = append_request.sender_bundle_share_url.is_none()
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
                        let contact_share_url = self.build_contact_share_url().await?;
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
                            let modified_request = HttpRequestEffect {
                                request_id: request.request_id.clone(),
                                method: request.method.clone(),
                                url: request.url.clone(),
                                headers: request.headers.clone(),
                                body: Some(modified_body),
                            };
                            return self.transport.execute_http_request(modified_request).await;
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

        self.transport.execute_http_request(request).await
    }

    async fn fetch_identity_bundle(
        &mut self,
        fetch: FetchIdentityBundleRequest,
    ) -> Result<Vec<CoreEvent>> {
        // The fetch request has user_id which is the share URL
        let bundle = self.transport.fetch_identity_bundle(fetch.clone()).await?;
        Ok(vec![CoreEvent::IdentityBundleFetched {
            user_id: fetch.user_id,
            bundle,
        }])
    }

    async fn fetch_message_requests(
        &mut self,
        fetch: FetchMessageRequestsRequest,
    ) -> Result<Vec<CoreEvent>> {
        transport::fetch_message_requests(&self.client, fetch).await
    }

    async fn act_on_message_request(
        &mut self,
        action: MessageRequestActionRequest,
    ) -> Result<Vec<CoreEvent>> {
        transport::act_on_message_request(&self.client, action).await
    }

    async fn fetch_allowlist(&mut self, fetch: FetchAllowlistRequest) -> Result<Vec<CoreEvent>> {
        transport::fetch_allowlist(&self.client, fetch).await
    }

    async fn replace_allowlist(
        &mut self,
        update: ReplaceAllowlistRequest,
    ) -> Result<Vec<CoreEvent>> {
        transport::replace_allowlist(&self.client, update).await
    }

    async fn publish_shared_state(
        &mut self,
        publish: PublishSharedStateRequest,
    ) -> Result<Vec<CoreEvent>> {
        transport::publish_shared_state(&self.client, publish).await
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
                    let detail = if status == 404 {
                        "Cloudflare runtime does not support group outbox. Upgrade runtime."
                            .to_string()
                    } else {
                        format!("HTTP {status}: {body}")
                    };
                    return Ok(vec![CoreEvent::GroupEnvelopeAppendFailed {
                        group_id: append.group_id,
                        message_id: append.envelope.message_id,
                        retryable: status >= 500,
                        status: Some(status),
                        code: extract_error_code(&body),
                        detail: Some(detail),
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
                status: None,
                code: None,
                detail: Some(error.to_string()),
            }]),
        }
    }

    async fn initialize_group_authorization(
        &mut self,
        initialize: InitializeGroupAuthorizationRequest,
    ) -> Result<Vec<CoreEvent>> {
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
        match request.body(body).send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                let body = response.text().await.unwrap_or_default();
                if !(200..300).contains(&status) {
                    return Ok(vec![CoreEvent::GroupAuthorizationInitializeFailed {
                        group_id,
                        retryable: status >= 500,
                        status: Some(status),
                        code: extract_error_code(&body),
                        detail: Some(format!("HTTP {status}: {body}")),
                    }]);
                }
                let body = to_snake_case_json_string(&body).unwrap_or(body);
                let result: InitializeGroupAuthorizationResult = serde_json::from_str(&body)?;
                Ok(vec![CoreEvent::GroupAuthorizationInitialized {
                    group_id,
                    roster_version: result.roster_version,
                }])
            }
            Err(error) => Ok(vec![CoreEvent::GroupAuthorizationInitializeFailed {
                group_id,
                retryable: true,
                status: None,
                code: None,
                detail: Some(error.to_string()),
            }]),
        }
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
                        retryable: status >= 500,
                        status: Some(status),
                        code: extract_error_code(&body),
                        detail: Some(format!("HTTP {status}: {body}")),
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
            Err(error) => Ok(vec![CoreEvent::GroupTransitionAppendFailed {
                group_id,
                transition_id,
                retryable: true,
                status: None,
                code: None,
                detail: Some(error.to_string()),
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
                        retryable: status >= 500,
                        status: Some(status),
                        code: extract_error_code(&body),
                        detail: Some(format!("HTTP {status}: {body}")),
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
            Err(error) => Ok(vec![CoreEvent::GroupAuthorizationStateFetchFailed {
                group_id,
                retryable: true,
                status: None,
                code: None,
                detail: Some(error.to_string()),
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
                        retryable: status >= 500,
                        status: Some(status),
                        code: extract_error_code(&body),
                        detail: Some(format!("HTTP {status}: {body}")),
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
                Ok(vec![CoreEvent::GroupOutboxFetched {
                    group_id: fetch.group_id,
                    records: result.records,
                    to_seq: result.to_seq,
                }])
            }
            Err(error) => {
                log::warn!(
                    "[TransportPort] fetch_group_outbox request failed group_id={} from_seq={} endpoint={} error={}",
                    group_ref,
                    fetch.from_seq,
                    endpoint,
                    error
                );
                Ok(vec![CoreEvent::GroupOutboxFetchFailed {
                    group_id: fetch.group_id,
                    retryable: true,
                    status: None,
                    code: None,
                    detail: Some(error.to_string()),
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
            Err(error) => {
                log::warn!(
                    "[TransportPort] get_group_outbox_head request failed group_id={} endpoint={} error={}",
                    group_ref,
                    endpoint,
                    error
                );
                return Ok(vec![CoreEvent::GroupOutboxHeadFetchFailed {
                    group_id: get.group_id,
                    retryable: true,
                    status: None,
                    code: None,
                    detail: Some(error.to_string()),
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
                retryable: status >= 500,
                status: Some(status),
                code: extract_error_code(&body_text),
                detail: Some(format!("HTTP {status}: {body_text}")),
            }]);
        }
        let body = to_snake_case_json_string(&body_text).unwrap_or(body_text);
        let result: GetGroupOutboxHeadResult = match serde_json::from_str(&body) {
            Ok(result) => result,
            Err(error) => {
                log::warn!(
                    "[TransportPort] get_group_outbox_head decode failed group_id={} endpoint={} error={}",
                    group_ref,
                    endpoint,
                    error
                );
                return Ok(vec![CoreEvent::GroupOutboxHeadFetchFailed {
                    group_id: get.group_id,
                    retryable: false,
                    status: Some(status),
                    code: None,
                    detail: Some(error.to_string()),
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
                    log::warn!(
                        "[TransportPort] put_welcome_pickup failed group_id={} device_id={} status={}",
                        group_ref,
                        device_ref,
                        status
                    );
                    return Ok(vec![CoreEvent::WelcomePickupPutFailed {
                        descriptor: put.descriptor,
                        retryable: status >= 500,
                        detail: Some(format!("HTTP {status}")),
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
                        retryable: status >= 500,
                        detail: Some(format!("HTTP {status}")),
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
            Err(error) => {
                log::warn!(
                    "[TransportPort] fetch_welcome_pickup transport error group_id={} device_id={} error={}",
                    group_ref,
                    device_ref,
                    error
                );
                Ok(vec![CoreEvent::WelcomePickupFetchFailed {
                    descriptor: fetch.descriptor,
                    retryable: true,
                    detail: Some(error.to_string()),
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
                        retryable: status >= 500,
                        detail: Some(format!("HTTP {status}")),
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
        let response = self.client.get(&fetch.invite_url).send().await;
        match response {
            Ok(response) => {
                let status = response.status().as_u16();
                let body = response.text().await.unwrap_or_default();
                if !(200..300).contains(&status) {
                    return Ok(vec![CoreEvent::GroupInviteFetchFailed {
                        invite_url: fetch.invite_url,
                        retryable: status >= 500,
                        detail: Some(format!("HTTP {status}")),
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
                        detail: Some(format!("HTTP {status}")),
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
                        retryable: status >= 500,
                        detail: Some(format!("HTTP {status}")),
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
                        retryable: status >= 500,
                        status: Some(status),
                        code: extract_error_code(&body),
                        detail: Some(format!("HTTP {status}: {body}")),
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
            Err(error) => Ok(vec![CoreEvent::GroupJoinClaimFailed {
                group_id: claim.group_id,
                request_id: claim.request_id,
                retryable: true,
                status: None,
                code: None,
                detail: Some(error.to_string()),
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
                        retryable: status >= 500,
                        status: Some(status),
                        code: extract_error_code(&body),
                        detail: Some(format!("HTTP {status}: {body}")),
                    }]);
                }
                let body = to_snake_case_json_string(&body).unwrap_or(body);
                let result: CompleteGroupJoinResult = serde_json::from_str(&body)?;
                Ok(vec![CoreEvent::GroupJoinCompleted {
                    request: result.request,
                }])
            }
            Err(error) => Ok(vec![CoreEvent::GroupJoinCompleteFailed {
                group_id: complete.group_id,
                request_id: complete.request_id,
                retryable: true,
                status: None,
                code: None,
                detail: Some(error.to_string()),
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
                        retryable: status >= 500,
                        status: Some(status),
                        code: extract_error_code(&body),
                        detail: Some(format!("HTTP {status}: {body}")),
                    }]);
                }
                let body = to_snake_case_json_string(&body).unwrap_or(body);
                let result: SubmitGroupLeaveResult = serde_json::from_str(&body)?;
                Ok(vec![CoreEvent::GroupLeaveRequestSubmitted {
                    request: result.request,
                }])
            }
            Err(error) => Ok(vec![CoreEvent::GroupLeaveRequestSubmitFailed {
                group_id: submit.group_id,
                request_id: submit.request.request_id,
                retryable: true,
                status: None,
                code: None,
                detail: Some(error.to_string()),
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
                        retryable: status >= 500,
                        status: Some(status),
                        code: extract_error_code(&body),
                        detail: Some(format!("HTTP {status}: {body}")),
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
            Err(error) => Ok(vec![CoreEvent::GroupLeaveClaimFailed {
                group_id: claim.group_id,
                request_id: claim.request_id,
                retryable: true,
                status: None,
                code: None,
                detail: Some(error.to_string()),
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
            retryable: false,
            status: Some(status),
            code,
            detail: Some(format!("HTTP {status}")),
        }];
    }

    if !(200..300).contains(&status) {
        let body = to_snake_case_json_string(body_text).unwrap_or_else(|_| body_text.to_string());
        return vec![CoreEvent::GroupOutboxSealFailed {
            group_id,
            retryable: status >= 500,
            status: Some(status),
            code: extract_error_code(&body),
            detail: Some(format!("HTTP {status}")),
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
        subscription: RealtimeSubscriptionRequest,
    ) -> Result<Vec<CoreEvent>> {
        self.realtime.open_connection(subscription).await
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
        // Read from inbox/outbox attachments dir via persistence
        let dir = self.persistence.attachments_dir().await;

        // Emit progress event if we have app handle
        if let Some(app) = &self.app_handle {
            let _ = app.emit(
                "upload-progress",
                blob_io::UploadProgressEvent {
                    task_id: read.task_id.clone(),
                    conversation_id: self.current_conversation_id.clone().unwrap_or_default(),
                    progress: 5,
                    status: "reading".to_string(),
                },
            );
        }

        blob_io::read_attachment_bytes(read, dir).await
    }

    async fn prepare_blob_upload(
        &mut self,
        upload: PrepareBlobUploadRequest,
    ) -> Result<Vec<CoreEvent>> {
        // Use transport to prepare upload
        let result = self.transport.prepare_blob_upload(upload.clone()).await?;

        // Emit progress event
        if let Some(app) = &self.app_handle {
            let _ = app.emit(
                "upload-progress",
                blob_io::UploadProgressEvent {
                    task_id: upload.task_id.clone(),
                    conversation_id: self.current_conversation_id.clone().unwrap_or_default(),
                    progress: 10,
                    status: "preparing".to_string(),
                },
            );
        }

        Ok(vec![CoreEvent::BlobUploadPrepared {
            task_id: upload.task_id,
            result,
        }])
    }

    async fn upload_blob(&mut self, upload: BlobUploadRequest) -> Result<Vec<CoreEvent>> {
        let conversation_id = self.current_conversation_id.clone().unwrap_or_default();
        let app_handle = self.app_handle.clone();

        blob_io::upload_blob_with_progress(upload, app_handle, conversation_id).await
    }

    async fn authorize_blob_download(
        &mut self,
        authorize: AuthorizeBlobDownloadRequest,
    ) -> Result<Vec<CoreEvent>> {
        let result = self
            .transport
            .authorize_blob_download(authorize.clone())
            .await?;
        Ok(vec![CoreEvent::BlobDownloadAuthorized {
            task_id: authorize.task_id,
            result,
        }])
    }

    async fn download_blob(&mut self, download: BlobDownloadRequest) -> Result<Vec<CoreEvent>> {
        let conversation_id = self.current_conversation_id.clone().unwrap_or_default();
        let task_id = download.task_id.clone();

        // Emit download progress
        if let Some(app) = &self.app_handle {
            let _ = app.emit(
                "download-progress",
                blob_io::UploadProgressEvent {
                    task_id: task_id.clone(),
                    conversation_id: conversation_id.clone(),
                    progress: 50,
                    status: "downloading".to_string(),
                },
            );
        }

        let result = blob_io::download_blob(download).await;

        // Emit complete
        if let Some(app) = &self.app_handle {
            let _ = app.emit(
                "download-progress",
                blob_io::UploadProgressEvent {
                    task_id,
                    conversation_id,
                    progress: 100,
                    status: "complete".to_string(),
                },
            );
        }

        result
    }

    async fn write_downloaded_attachment(
        &mut self,
        write: WriteDownloadedAttachmentEffect,
    ) -> Result<Vec<CoreEvent>> {
        let dir = self.persistence.outbox_attachments_dir().await;
        blob_io::write_downloaded_attachment(write, dir).await
    }
}

// --- PersistencePort ---
impl PersistencePort for DesktopPlatformPorts {
    fn persist_state(&mut self, persist: PersistStateEffect) -> Result<()> {
        // Use tokio runtime to call async persistence
        let persistence = self.persistence.clone();
        tokio::task::block_in_place(|| {
            tauri::async_runtime::handle().block_on(async {
                persistence
                    .persist(persist)
                    .await
                    .context("desktop persistence failed")
            })
        })
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
        if let Err(e) = self.notification.emit_user_notification(notification) {
            log::error!("Notification error: {:?}", e);
        }
        Ok(Vec::new())
    }
}

// --- SecureStoragePort (skeleton) ---
impl SecureStoragePort for DesktopPlatformPorts {}

/// Sign a contact share token using HMAC-SHA256.
/// Format: base64url(payload).base64url(signature)
fn sign_contact_share_token(secret: &str, user_id: &str, share_id: &str) -> Result<String> {
    let payload = serde_json::json!({
        "version": CURRENT_MODEL_VERSION,
        "service": "contact_share",
        "userId": user_id,
        "shareId": share_id,
    });
    let payload_bytes = serde_json::to_vec(&payload)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to initialize HMAC: {}", e))?;
    mac.update(&payload_bytes);
    let signature = mac.finalize().into_bytes();
    Ok(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(payload_bytes),
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

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

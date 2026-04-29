pub mod blob_io;
pub mod notification;
pub mod persistence;
pub mod realtime;
pub mod timer;
pub mod transport;

use std::sync::Arc;

use anyhow::Result;
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
use tapchat_core::transport_contract::{
    AppendEnvelopeRequest, BlobDownloadRequest, BlobUploadRequest, FetchAllowlistRequest,
    FetchIdentityBundleRequest, FetchMessageRequestsRequest, MessageRequestActionRequest,
    PrepareBlobUploadRequest, PublishSharedStateRequest, RealtimeSubscriptionRequest,
    ReplaceAllowlistRequest,
};
use tauri::{AppHandle, Emitter};
use tokio::sync::RwLock;

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
            client: reqwest::Client::new(),
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
}

fn summarize_share_url(url: Option<&str>) -> String {
    let Some(url) = url else {
        return "none".into();
    };
    let Ok(parsed) = url::Url::parse(url) else {
        return "<invalid-url>".into();
    };
    let host = parsed.host_str().unwrap_or_default();
    let path = parsed.path();
    if path.starts_with("/v1/contact-share/") {
        return format!("{host}/v1/contact-share/<redacted>");
    }
    format!("{host}{path}")
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
                            log::warn!("[TransportPort] Failed to generate contact_share_url, sending original request");
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
    fn persist_state(&mut self, persist: PersistStateEffect) {
        // Use tokio runtime to call async persistence
        let persistence = self.persistence.clone();
        tokio::task::block_in_place(|| {
            tauri::async_runtime::handle().block_on(async {
                if let Err(e) = persistence.persist(persist).await {
                    log::error!("Persistence error: {:?}", e);
                }
            });
        });
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
        assert_eq!(summary, "example.com/v1/contact-share/<redacted>");
        assert!(!summary.contains("secret-token-value"));
    }
}

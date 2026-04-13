pub mod transport;
pub mod realtime;
pub mod blob_io;
pub mod persistence;
pub mod timer;
pub mod notification;

use std::sync::Arc;

use anyhow::Result;
use tapchat_core::ffi_api::{
    CoreEvent, HttpRequestEffect, PersistStateEffect, ReadAttachmentBytesEffect,
    UserNotificationEffect, WriteDownloadedAttachmentEffect,
};
use tapchat_core::platform_ports::{
    BlobIoPort, NotificationPort, PersistencePort, RealtimePort, SecureStoragePort, TimerPort,
    TransportPort,
};
use tapchat_core::transport_contract::{
    BlobDownloadRequest, BlobUploadRequest, FetchAllowlistRequest, FetchIdentityBundleRequest,
    FetchMessageRequestsRequest, MessageRequestActionRequest, PrepareBlobUploadRequest,
    PublishSharedStateRequest, RealtimeSubscriptionRequest, ReplaceAllowlistRequest,
};
use tokio::sync::RwLock;

use crate::platform::profile::{ProfileManager, ProfileManagerInner};
use crate::platform::transport::DesktopTransport;
use crate::platform::realtime::RealtimeManager;
use crate::platform::persistence::DesktopPersistence;

/// Desktop-specific implementation of all platform port traits.
/// This is the bridge between CoreEngine effects and actual platform operations.
pub struct DesktopPlatformPorts {
    pub transport: DesktopTransport,
    pub realtime: RealtimeManager,
    pub persistence: DesktopPersistence,
    // Timer and notification use spawn/emit directly
}

impl DesktopPlatformPorts {
    pub fn new(profile_inner: Arc<RwLock<ProfileManagerInner>>) -> Self {
        Self {
            transport: DesktopTransport::new(profile_inner.clone()),
            realtime: RealtimeManager::new(profile_inner.clone()),
            persistence: DesktopPersistence::new(profile_inner),
        }
    }
}

// --- TransportPort ---
// Note: TransportPort trait requires `&mut self` but our implementations use `&self`
// We implement by delegating to the platform modules

impl TransportPort for DesktopPlatformPorts {
    async fn execute_http_request(
        &mut self,
        request: HttpRequestEffect,
    ) -> Result<Vec<CoreEvent>> {
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
        // TODO: Implement message requests fetch via transport
        transport::fetch_message_requests_stub(fetch).await
    }

    async fn act_on_message_request(
        &mut self,
        action: MessageRequestActionRequest,
    ) -> Result<Vec<CoreEvent>> {
        // TODO: Implement message request action via transport
        transport::act_on_message_request_stub(action).await
    }

    async fn fetch_allowlist(
        &mut self,
        fetch: FetchAllowlistRequest,
    ) -> Result<Vec<CoreEvent>> {
        // TODO: Implement allowlist fetch via transport
        transport::fetch_allowlist_stub(fetch).await
    }

    async fn replace_allowlist(
        &mut self,
        update: ReplaceAllowlistRequest,
    ) -> Result<Vec<CoreEvent>> {
        // TODO: Implement allowlist replace via transport
        transport::replace_allowlist_stub(update).await
    }

    async fn publish_shared_state(
        &mut self,
        publish: PublishSharedStateRequest,
    ) -> Result<Vec<CoreEvent>> {
        // TODO: Implement shared state publish via transport
        transport::publish_shared_state_stub(publish).await
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
        let dir = self.persistence.inbox_attachments_dir().await;
        blob_io::read_attachment_bytes(read, dir).await
    }

    async fn prepare_blob_upload(
        &mut self,
        upload: PrepareBlobUploadRequest,
    ) -> Result<Vec<CoreEvent>> {
        // Use transport to prepare upload
        let result = self.transport.prepare_blob_upload(upload.clone()).await?;
        Ok(vec![CoreEvent::BlobUploadPrepared {
            task_id: upload.task_id,
            result,
        }])
    }

    async fn upload_blob(&mut self, upload: BlobUploadRequest) -> Result<Vec<CoreEvent>> {
        blob_io::upload_blob(upload).await
    }

    async fn download_blob(&mut self, download: BlobDownloadRequest) -> Result<Vec<CoreEvent>> {
        blob_io::download_blob(download).await
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
        // Spawn background task that will emit TimerTriggered after delay
        timer::schedule_timer(timer_id, delay_ms);
        Ok(Vec::new())
    }
}

// --- NotificationPort ---
impl NotificationPort for DesktopPlatformPorts {
    fn emit_user_notification(
        &mut self,
        notification: UserNotificationEffect,
    ) -> Result<Vec<CoreEvent>> {
        notification::emit_user_notification(notification);
        Ok(Vec::new())
    }
}

// --- SecureStoragePort (skeleton) ---
impl SecureStoragePort for DesktopPlatformPorts {}
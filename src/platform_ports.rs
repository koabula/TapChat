#![allow(async_fn_in_trait)]

use anyhow::Result;

use crate::ffi_api::{
    CoreEffect, CoreEvent, PersistStateEffect, ReadAttachmentBytesEffect, UserNotificationEffect,
    WriteDownloadedAttachmentEffect,
};
use crate::transport_contract::{
    BlobDownloadRequest, BlobUploadRequest, FetchAllowlistRequest, FetchIdentityBundleRequest,
    FetchMessageRequestsRequest, MessageRequestActionRequest, PrepareBlobUploadRequest,
    PublishSharedStateRequest, RealtimeSubscriptionRequest, ReplaceAllowlistRequest,
};

pub trait TransportPort {
    async fn execute_http_request(
        &mut self,
        request: crate::ffi_api::HttpRequestEffect,
    ) -> Result<Vec<CoreEvent>>;

    async fn fetch_identity_bundle(
        &mut self,
        fetch: FetchIdentityBundleRequest,
    ) -> Result<Vec<CoreEvent>>;

    async fn fetch_message_requests(
        &mut self,
        fetch: FetchMessageRequestsRequest,
    ) -> Result<Vec<CoreEvent>>;

    async fn act_on_message_request(
        &mut self,
        action: MessageRequestActionRequest,
    ) -> Result<Vec<CoreEvent>>;

    async fn fetch_allowlist(&mut self, fetch: FetchAllowlistRequest) -> Result<Vec<CoreEvent>>;

    async fn replace_allowlist(
        &mut self,
        update: ReplaceAllowlistRequest,
    ) -> Result<Vec<CoreEvent>>;

    async fn publish_shared_state(
        &mut self,
        publish: PublishSharedStateRequest,
    ) -> Result<Vec<CoreEvent>>;
}

pub trait RealtimePort {
    async fn open_realtime(
        &mut self,
        subscription: RealtimeSubscriptionRequest,
    ) -> Result<Vec<CoreEvent>>;

    async fn close_realtime(&mut self, device_id: String) -> Result<Vec<CoreEvent>>;
}

pub trait BlobIoPort {
    async fn read_attachment_bytes(
        &mut self,
        read: ReadAttachmentBytesEffect,
    ) -> Result<Vec<CoreEvent>>;

    async fn prepare_blob_upload(
        &mut self,
        upload: PrepareBlobUploadRequest,
    ) -> Result<Vec<CoreEvent>>;

    async fn upload_blob(&mut self, upload: BlobUploadRequest) -> Result<Vec<CoreEvent>>;

    async fn download_blob(&mut self, download: BlobDownloadRequest) -> Result<Vec<CoreEvent>>;

    async fn write_downloaded_attachment(
        &mut self,
        write: WriteDownloadedAttachmentEffect,
    ) -> Result<Vec<CoreEvent>>;
}

pub trait PersistencePort {
    fn persist_state(&mut self, persist: PersistStateEffect);
}

pub trait TimerPort {
    fn schedule_timer(&mut self, timer_id: String, delay_ms: u64) -> Result<Vec<CoreEvent>>;
}

pub trait NotificationPort {
    fn emit_user_notification(
        &mut self,
        notification: UserNotificationEffect,
    ) -> Result<Vec<CoreEvent>>;
}

// Skeleton trait to define the boundary for future platform secure storage work.
pub trait SecureStoragePort {}

pub async fn execute_platform_effect<P>(ports: &mut P, effect: CoreEffect) -> Result<Vec<CoreEvent>>
where
    P: TransportPort + RealtimePort + BlobIoPort + PersistencePort + TimerPort + NotificationPort,
{
    match effect {
        CoreEffect::ExecuteHttpRequest { request } => ports.execute_http_request(request).await,
        CoreEffect::OpenRealtimeConnection { connection } => {
            ports.open_realtime(connection.subscription).await
        }
        CoreEffect::CloseRealtimeConnection { device_id } => ports.close_realtime(device_id).await,
        CoreEffect::FetchIdentityBundle { fetch } => ports.fetch_identity_bundle(fetch).await,
        CoreEffect::FetchMessageRequests { fetch } => ports.fetch_message_requests(fetch).await,
        CoreEffect::ActOnMessageRequest { action } => ports.act_on_message_request(action).await,
        CoreEffect::FetchAllowlist { fetch } => ports.fetch_allowlist(fetch).await,
        CoreEffect::ReplaceAllowlist { update } => ports.replace_allowlist(update).await,
        CoreEffect::PublishSharedState { publish } => ports.publish_shared_state(publish).await,
        CoreEffect::ReadAttachmentBytes { read } => ports.read_attachment_bytes(read).await,
        CoreEffect::PrepareBlobUpload { upload } => ports.prepare_blob_upload(upload).await,
        CoreEffect::UploadBlob { upload } => ports.upload_blob(upload).await,
        CoreEffect::DownloadBlob { download } => ports.download_blob(download).await,
        CoreEffect::WriteDownloadedAttachment { write } => {
            ports.write_downloaded_attachment(write).await
        }
        CoreEffect::PersistState { persist } => {
            ports.persist_state(persist);
            Ok(Vec::new())
        }
        CoreEffect::ScheduleTimer { timer } => ports.schedule_timer(timer.timer_id, timer.delay_ms),
        CoreEffect::EmitUserNotification { notification } => {
            ports.emit_user_notification(notification)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi_api::{HttpMethod, HttpRequestEffect, SystemStatus, TimerEffect};
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct FakePorts {
        calls: Vec<&'static str>,
        timers: Vec<(String, u64)>,
        notifications: Vec<String>,
        persisted: Vec<PersistStateEffect>,
    }

    impl TransportPort for FakePorts {
        async fn execute_http_request(
            &mut self,
            _request: crate::ffi_api::HttpRequestEffect,
        ) -> Result<Vec<CoreEvent>> {
            self.calls.push("execute_http_request");
            Ok(vec![CoreEvent::HttpRequestFailed {
                request_id: "req".into(),
                retryable: true,
                detail: Some("fake".into()),
            }])
        }

        async fn fetch_identity_bundle(
            &mut self,
            _fetch: FetchIdentityBundleRequest,
        ) -> Result<Vec<CoreEvent>> {
            self.calls.push("fetch_identity_bundle");
            Ok(Vec::new())
        }

        async fn fetch_message_requests(
            &mut self,
            _fetch: FetchMessageRequestsRequest,
        ) -> Result<Vec<CoreEvent>> {
            self.calls.push("fetch_message_requests");
            Ok(Vec::new())
        }

        async fn act_on_message_request(
            &mut self,
            _action: MessageRequestActionRequest,
        ) -> Result<Vec<CoreEvent>> {
            self.calls.push("act_on_message_request");
            Ok(Vec::new())
        }

        async fn fetch_allowlist(
            &mut self,
            _fetch: FetchAllowlistRequest,
        ) -> Result<Vec<CoreEvent>> {
            self.calls.push("fetch_allowlist");
            Ok(Vec::new())
        }

        async fn replace_allowlist(
            &mut self,
            _update: ReplaceAllowlistRequest,
        ) -> Result<Vec<CoreEvent>> {
            self.calls.push("replace_allowlist");
            Ok(Vec::new())
        }

        async fn publish_shared_state(
            &mut self,
            _publish: PublishSharedStateRequest,
        ) -> Result<Vec<CoreEvent>> {
            self.calls.push("publish_shared_state");
            Ok(Vec::new())
        }
    }

    impl RealtimePort for FakePorts {
        async fn open_realtime(
            &mut self,
            _subscription: RealtimeSubscriptionRequest,
        ) -> Result<Vec<CoreEvent>> {
            self.calls.push("open_realtime");
            Ok(vec![CoreEvent::WebSocketConnected {
                device_id: "device:test".into(),
            }])
        }

        async fn close_realtime(&mut self, _device_id: String) -> Result<Vec<CoreEvent>> {
            self.calls.push("close_realtime");
            Ok(Vec::new())
        }
    }

    impl BlobIoPort for FakePorts {
        async fn read_attachment_bytes(
            &mut self,
            _read: ReadAttachmentBytesEffect,
        ) -> Result<Vec<CoreEvent>> {
            self.calls.push("read_attachment_bytes");
            Ok(Vec::new())
        }

        async fn prepare_blob_upload(
            &mut self,
            _upload: PrepareBlobUploadRequest,
        ) -> Result<Vec<CoreEvent>> {
            self.calls.push("prepare_blob_upload");
            Ok(Vec::new())
        }

        async fn upload_blob(&mut self, _upload: BlobUploadRequest) -> Result<Vec<CoreEvent>> {
            self.calls.push("upload_blob");
            Ok(Vec::new())
        }

        async fn download_blob(
            &mut self,
            _download: BlobDownloadRequest,
        ) -> Result<Vec<CoreEvent>> {
            self.calls.push("download_blob");
            Ok(Vec::new())
        }

        async fn write_downloaded_attachment(
            &mut self,
            _write: WriteDownloadedAttachmentEffect,
        ) -> Result<Vec<CoreEvent>> {
            self.calls.push("write_downloaded_attachment");
            Ok(Vec::new())
        }
    }

    impl PersistencePort for FakePorts {
        fn persist_state(&mut self, persist: PersistStateEffect) {
            self.calls.push("persist_state");
            self.persisted.push(persist);
        }
    }

    impl TimerPort for FakePorts {
        fn schedule_timer(&mut self, timer_id: String, delay_ms: u64) -> Result<Vec<CoreEvent>> {
            self.calls.push("schedule_timer");
            self.timers.push((timer_id, delay_ms));
            Ok(Vec::new())
        }
    }

    impl NotificationPort for FakePorts {
        fn emit_user_notification(
            &mut self,
            notification: UserNotificationEffect,
        ) -> Result<Vec<CoreEvent>> {
            self.calls.push("emit_user_notification");
            self.notifications.push(notification.message);
            Ok(Vec::new())
        }
    }

    impl SecureStoragePort for FakePorts {}

    #[tokio::test]
    async fn execute_platform_effect_routes_http_and_realtime() {
        let mut ports = FakePorts::default();
        let http_events = execute_platform_effect(
            &mut ports,
            CoreEffect::ExecuteHttpRequest {
                request: HttpRequestEffect {
                    request_id: "req".into(),
                    method: HttpMethod::Get,
                    url: "https://example.com".into(),
                    headers: BTreeMap::new(),
                    body: None,
                },
            },
        )
        .await
        .expect("http effect");
        assert_eq!(ports.calls, vec!["execute_http_request"]);
        assert!(matches!(
            http_events.first(),
            Some(CoreEvent::HttpRequestFailed { .. })
        ));

        let realtime_events = execute_platform_effect(
            &mut ports,
            CoreEffect::OpenRealtimeConnection {
                connection: crate::ffi_api::RealtimeConnectionEffect {
                    subscription: RealtimeSubscriptionRequest {
                        device_id: "device:test".into(),
                        endpoint: "ws://example.com".into(),
                        last_acked_seq: 0,
                        headers: BTreeMap::new(),
                    },
                },
            },
        )
        .await
        .expect("realtime effect");
        assert!(ports.calls.contains(&"open_realtime"));
        assert!(matches!(
            realtime_events.first(),
            Some(CoreEvent::WebSocketConnected { .. })
        ));
    }

    #[tokio::test]
    async fn execute_platform_effect_routes_blob_persistence_timer_and_notification() {
        let mut ports = FakePorts::default();
        execute_platform_effect(
            &mut ports,
            CoreEffect::ReadAttachmentBytes {
                read: ReadAttachmentBytesEffect {
                    task_id: "task".into(),
                    attachment_id: "attachment:1".into(),
                },
            },
        )
        .await
        .expect("blob read effect");
        execute_platform_effect(
            &mut ports,
            CoreEffect::PersistState {
                persist: PersistStateEffect {
                    ops: vec![],
                    snapshot: None,
                },
            },
        )
        .await
        .expect("persist effect");
        execute_platform_effect(
            &mut ports,
            CoreEffect::ScheduleTimer {
                timer: TimerEffect {
                    timer_id: "timer:1".into(),
                    delay_ms: 5,
                },
            },
        )
        .await
        .expect("timer effect");
        execute_platform_effect(
            &mut ports,
            CoreEffect::EmitUserNotification {
                notification: UserNotificationEffect {
                    status: SystemStatus::TemporaryNetworkFailure,
                    message: "hello".into(),
                },
            },
        )
        .await
        .expect("notification effect");

        assert!(ports.calls.contains(&"read_attachment_bytes"));
        assert!(ports.calls.contains(&"persist_state"));
        assert!(ports.calls.contains(&"schedule_timer"));
        assert!(ports.calls.contains(&"emit_user_notification"));
        assert_eq!(ports.timers, vec![("timer:1".into(), 5)]);
        assert_eq!(ports.notifications, vec!["hello".to_string()]);
        assert_eq!(ports.persisted.len(), 1);
    }
}

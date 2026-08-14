#![allow(async_fn_in_trait)]

use std::future::Future;
use std::pin::Pin;

use anyhow::Result;

use crate::ffi_api::{
    CoreEffect, CoreEvent, PersistStateEffect, ReadAttachmentBytesEffect, UserNotificationEffect,
    WriteDownloadedAttachmentEffect,
};
use crate::transport_contract::{
    AppendGroupEnvelopeRequest, AppendGroupTransitionRequest, BlobDownloadRequest,
    BlobUploadRequest, ClaimGroupJoinRequest, ClaimGroupLeaveRequest, CompleteGroupJoinRequest,
    CreateGroupInviteRequest, DecideGroupJoinRequest, FetchAllowlistRequest,
    FetchGroupInviteRequest, FetchGroupOutboxRequest, FetchIdentityBundleRequest,
    FetchMessageRequestsRequest, FetchWelcomePickupRequest, GetGroupAuthorizationStateRequest,
    GetGroupJoinRequestStatusRequest, GetGroupOutboxHeadRequest, GroupRealtimeSubscriptionRequest,
    InitializeGroupAuthorizationRequest, ListGroupInvitesRequest, ListGroupJoinRequestsRequest,
    ListGroupLeaveRequestsRequest, MessageRequestActionRequest, PrepareBlobUploadRequest,
    PublishSharedStateRequest, PutWelcomePickupRequest, RealtimeSubscriptionRequest,
    ReplaceAllowlistRequest, RevokeGroupInviteRequest, SealGroupOutboxRequest,
    SubmitGroupJoinRequest, SubmitGroupLeaveRequest,
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

    async fn append_group_envelope(
        &mut self,
        _append: AppendGroupEnvelopeRequest,
    ) -> Result<Vec<CoreEvent>> {
        anyhow::bail!("group append transport is not implemented by this platform")
    }

    async fn initialize_group_authorization(
        &mut self,
        _initialize: InitializeGroupAuthorizationRequest,
    ) -> Result<Vec<CoreEvent>> {
        anyhow::bail!("group authorization initialization is not implemented by this platform")
    }

    async fn append_group_transition(
        &mut self,
        _append: AppendGroupTransitionRequest,
    ) -> Result<Vec<CoreEvent>> {
        anyhow::bail!("group transition transport is not implemented by this platform")
    }

    async fn get_group_authorization_state(
        &mut self,
        _get: GetGroupAuthorizationStateRequest,
    ) -> Result<Vec<CoreEvent>> {
        anyhow::bail!("group authorization state transport is not implemented by this platform")
    }

    async fn fetch_group_outbox(
        &mut self,
        _fetch: FetchGroupOutboxRequest,
    ) -> Result<Vec<CoreEvent>> {
        anyhow::bail!("group fetch transport is not implemented by this platform")
    }

    async fn get_group_outbox_head(
        &mut self,
        _get: GetGroupOutboxHeadRequest,
    ) -> Result<Vec<CoreEvent>> {
        anyhow::bail!("group head transport is not implemented by this platform")
    }

    async fn fetch_welcome_pickup(
        &mut self,
        _fetch: FetchWelcomePickupRequest,
    ) -> Result<Vec<CoreEvent>> {
        anyhow::bail!("welcome pickup fetch transport is not implemented by this platform")
    }

    async fn put_welcome_pickup(
        &mut self,
        _put: PutWelcomePickupRequest,
    ) -> Result<Vec<CoreEvent>> {
        anyhow::bail!("welcome pickup put transport is not implemented by this platform")
    }

    async fn create_group_invite(
        &mut self,
        _create: CreateGroupInviteRequest,
    ) -> Result<Vec<CoreEvent>> {
        anyhow::bail!("group invite create transport is not implemented by this platform")
    }

    async fn revoke_group_invite(
        &mut self,
        _revoke: RevokeGroupInviteRequest,
    ) -> Result<Vec<CoreEvent>> {
        anyhow::bail!("group invite revoke transport is not implemented by this platform")
    }

    async fn list_group_invites(
        &mut self,
        _list: ListGroupInvitesRequest,
    ) -> Result<Vec<CoreEvent>> {
        anyhow::bail!("group invite list transport is not implemented by this platform")
    }

    async fn fetch_group_invite(
        &mut self,
        _fetch: FetchGroupInviteRequest,
    ) -> Result<Vec<CoreEvent>> {
        anyhow::bail!("group invite fetch transport is not implemented by this platform")
    }

    async fn submit_group_join_request(
        &mut self,
        _submit: SubmitGroupJoinRequest,
    ) -> Result<Vec<CoreEvent>> {
        anyhow::bail!("group join submit transport is not implemented by this platform")
    }

    async fn list_group_join_requests(
        &mut self,
        _list: ListGroupJoinRequestsRequest,
    ) -> Result<Vec<CoreEvent>> {
        anyhow::bail!("group join list transport is not implemented by this platform")
    }

    async fn get_group_join_request_status(
        &mut self,
        _get: GetGroupJoinRequestStatusRequest,
    ) -> Result<Vec<CoreEvent>> {
        anyhow::bail!("group join status transport is not implemented by this platform")
    }

    async fn decide_group_join_request(
        &mut self,
        _decide: DecideGroupJoinRequest,
    ) -> Result<Vec<CoreEvent>> {
        anyhow::bail!("group join decision transport is not implemented by this platform")
    }

    async fn claim_group_join_request(
        &mut self,
        _claim: ClaimGroupJoinRequest,
    ) -> Result<Vec<CoreEvent>> {
        anyhow::bail!("group join claim transport is not implemented by this platform")
    }

    async fn complete_group_join_request(
        &mut self,
        _complete: CompleteGroupJoinRequest,
    ) -> Result<Vec<CoreEvent>> {
        anyhow::bail!("group join completion transport is not implemented by this platform")
    }

    async fn submit_group_leave_request(
        &mut self,
        _submit: SubmitGroupLeaveRequest,
    ) -> Result<Vec<CoreEvent>> {
        anyhow::bail!("group leave submit transport is not implemented by this platform")
    }

    async fn list_group_leave_requests(
        &mut self,
        _list: ListGroupLeaveRequestsRequest,
    ) -> Result<Vec<CoreEvent>> {
        anyhow::bail!("group leave list transport is not implemented by this platform")
    }

    async fn claim_group_leave_request(
        &mut self,
        _claim: ClaimGroupLeaveRequest,
    ) -> Result<Vec<CoreEvent>> {
        anyhow::bail!("group leave claim transport is not implemented by this platform")
    }

    async fn seal_group_outbox(&mut self, _seal: SealGroupOutboxRequest) -> Result<Vec<CoreEvent>> {
        anyhow::bail!("group outbox seal transport is not implemented by this platform")
    }
}

pub trait RealtimePort {
    async fn open_realtime(
        &mut self,
        subscription: RealtimeSubscriptionRequest,
    ) -> Result<Vec<CoreEvent>>;

    async fn close_realtime(&mut self, device_id: String) -> Result<Vec<CoreEvent>>;

    async fn open_group_realtime(
        &mut self,
        _subscription: GroupRealtimeSubscriptionRequest,
    ) -> Result<Vec<CoreEvent>> {
        anyhow::bail!("group realtime is not implemented by this platform")
    }

    async fn close_group_realtime(&mut self, _group_id: String) -> Result<Vec<CoreEvent>> {
        Ok(Vec::new())
    }
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

    async fn cache_uploaded_attachment(
        &mut self,
        _cache: crate::ffi_api::CacheUploadedAttachmentEffect,
    ) -> Result<Vec<CoreEvent>> {
        Ok(Vec::new())
    }
}

pub trait PersistencePort {
    async fn persist_state(&mut self, persist: PersistStateEffect) -> Result<()>;
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

/// Execute one platform effect behind a heap boundary.
///
/// The transport implementations contain several large async state machines.
/// Returning a pinned box keeps their combined state out of every caller's
/// native stack frame, which is especially important at the Tauri IPC boundary
/// on Windows.
pub fn execute_platform_effect<P>(
    ports: &mut P,
    effect: CoreEffect,
) -> Pin<Box<impl Future<Output = Result<Vec<CoreEvent>>> + '_>>
where
    P: TransportPort + RealtimePort + BlobIoPort + PersistencePort + TimerPort + NotificationPort,
{
    Box::pin(async move {
        match effect {
            CoreEffect::ExecuteHttpRequest { request } => ports.execute_http_request(request).await,
            CoreEffect::OpenRealtimeConnection { connection } => {
                ports.open_realtime(connection.subscription).await
            }
            CoreEffect::CloseRealtimeConnection { device_id } => {
                ports.close_realtime(device_id).await
            }
            CoreEffect::FetchIdentityBundle { fetch } => ports.fetch_identity_bundle(fetch).await,
            CoreEffect::FetchMessageRequests { fetch } => ports.fetch_message_requests(fetch).await,
            CoreEffect::ActOnMessageRequest { action } => {
                ports.act_on_message_request(action).await
            }
            CoreEffect::FetchAllowlist { fetch } => ports.fetch_allowlist(fetch).await,
            CoreEffect::ReplaceAllowlist { update } => ports.replace_allowlist(update).await,
            CoreEffect::PublishSharedState { publish } => ports.publish_shared_state(publish).await,
            CoreEffect::OpenGroupRealtimeConnection { subscription } => {
                ports.open_group_realtime(subscription).await
            }
            CoreEffect::CloseGroupRealtimeConnection { group_id } => {
                ports.close_group_realtime(group_id).await
            }
            CoreEffect::AppendGroupEnvelope { append } => ports.append_group_envelope(append).await,
            CoreEffect::AppendGroupTransition { append } => {
                ports.append_group_transition(append).await
            }
            CoreEffect::InitializeGroupAuthorization { initialize } => {
                ports.initialize_group_authorization(initialize).await
            }
            CoreEffect::FetchGroupOutbox { fetch } => ports.fetch_group_outbox(fetch).await,
            CoreEffect::GetGroupOutboxHead { get } => ports.get_group_outbox_head(get).await,
            CoreEffect::GetGroupAuthorizationState { get } => {
                ports.get_group_authorization_state(get).await
            }
            CoreEffect::FetchWelcomePickup { fetch } => ports.fetch_welcome_pickup(fetch).await,
            CoreEffect::PutWelcomePickup { put } => ports.put_welcome_pickup(put).await,
            CoreEffect::CreateGroupInvite { create } => ports.create_group_invite(create).await,
            CoreEffect::RevokeGroupInvite { revoke } => ports.revoke_group_invite(revoke).await,
            CoreEffect::ListGroupInvites { list } => ports.list_group_invites(list).await,
            CoreEffect::FetchGroupInvite { fetch } => ports.fetch_group_invite(fetch).await,
            CoreEffect::SubmitGroupJoinRequest { submit } => {
                ports.submit_group_join_request(submit).await
            }
            CoreEffect::ListGroupJoinRequests { list } => {
                ports.list_group_join_requests(list).await
            }
            CoreEffect::GetGroupJoinRequestStatus { get } => {
                ports.get_group_join_request_status(get).await
            }
            CoreEffect::DecideGroupJoinRequest { decide } => {
                ports.decide_group_join_request(decide).await
            }
            CoreEffect::ClaimGroupJoinRequest { claim } => {
                ports.claim_group_join_request(claim).await
            }
            CoreEffect::CompleteGroupJoinRequest { complete } => {
                ports.complete_group_join_request(complete).await
            }
            CoreEffect::SubmitGroupLeaveRequest { submit } => {
                ports.submit_group_leave_request(submit).await
            }
            CoreEffect::ListGroupLeaveRequests { list } => {
                ports.list_group_leave_requests(list).await
            }
            CoreEffect::ClaimGroupLeaveRequest { claim } => {
                ports.claim_group_leave_request(claim).await
            }
            CoreEffect::SealGroupOutbox { seal } => ports.seal_group_outbox(seal).await,
            CoreEffect::ReadAttachmentBytes { read } => ports.read_attachment_bytes(read).await,
            CoreEffect::PrepareBlobUpload { upload } => ports.prepare_blob_upload(upload).await,
            CoreEffect::UploadBlob { upload } => ports.upload_blob(upload).await,
            CoreEffect::DownloadBlob { download } => ports.download_blob(download).await,
            CoreEffect::WriteDownloadedAttachment { write } => {
                ports.write_downloaded_attachment(write).await
            }
            CoreEffect::CacheUploadedAttachment { cache } => {
                ports.cache_uploaded_attachment(cache).await
            }
            CoreEffect::PersistState { persist } => {
                ports.persist_state(persist).await?;
                Ok(Vec::new())
            }
            CoreEffect::ScheduleTimer { timer } => {
                ports.schedule_timer(timer.timer_id, timer.delay_ms)
            }
            CoreEffect::EmitUserNotification { notification } => {
                ports.emit_user_notification(notification)
            }
        }
    })
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
        fail_persist: bool,
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
        async fn persist_state(&mut self, persist: PersistStateEffect) -> Result<()> {
            self.calls.push("persist_state");
            if self.fail_persist {
                anyhow::bail!("synthetic persist failure");
            }
            self.persisted.push(persist);
            Ok(())
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

    #[test]
    fn execute_platform_effect_future_stays_pointer_sized() {
        let mut ports = FakePorts::default();
        let future = execute_platform_effect(
            &mut ports,
            CoreEffect::ScheduleTimer {
                timer: TimerEffect {
                    timer_id: "stack-regression".into(),
                    delay_ms: 1,
                },
            },
        );

        assert_eq!(
            std::mem::size_of_val(&future),
            std::mem::size_of::<usize>(),
            "platform effect state must remain behind one heap pointer"
        );
    }

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
                    auth: None,
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
                        auth: None,
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
    async fn execute_platform_effect_records_successful_persist() {
        let mut ports = FakePorts::default();
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

        assert_eq!(ports.calls, vec!["persist_state"]);
        assert_eq!(ports.persisted.len(), 1);
    }

    #[tokio::test]
    async fn execute_platform_effect_propagates_persist_error() {
        let mut ports = FakePorts {
            fail_persist: true,
            ..FakePorts::default()
        };
        let result = execute_platform_effect(
            &mut ports,
            CoreEffect::PersistState {
                persist: PersistStateEffect {
                    ops: vec![],
                    snapshot: None,
                },
            },
        )
        .await;

        assert!(result.is_err());
        assert_eq!(ports.calls, vec!["persist_state"]);
        assert!(ports.persisted.is_empty());
    }

    #[tokio::test]
    async fn execute_platform_effect_routes_blob_timer_and_notification() {
        let mut ports = FakePorts::default();
        execute_platform_effect(
            &mut ports,
            CoreEffect::ReadAttachmentBytes {
                read: ReadAttachmentBytesEffect {
                    task_id: "task".into(),
                    conversation_id: "conversation".into(),
                    attachment_id: "attachment:1".into(),
                },
            },
        )
        .await
        .expect("blob read effect");
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
        assert!(ports.calls.contains(&"schedule_timer"));
        assert!(ports.calls.contains(&"emit_user_notification"));
        assert_eq!(ports.timers, vec![("timer:1".into(), 5)]);
        assert_eq!(ports.notifications, vec!["hello".to_string()]);
    }
}

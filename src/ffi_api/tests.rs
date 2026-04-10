#[cfg(test)]
mod tests {
    use crate::attachment_crypto::{
        ATTACHMENT_CIPHER_ALGORITHM, AttachmentCipherMetadata, AttachmentPayloadMetadata,
    };
    use crate::ffi_api::types::{RecoveryContext, RecoveryReason};
    use crate::ffi_api::{
        AttachmentDescriptor, CoreCommand, CoreEffect, CoreEngine, CoreEvent, FfiApiModule,
        RealtimeEvent,
    };
    use crate::identity::IdentityManager;
    use crate::mls_adapter::MlsAdapter;
    use crate::model::{
        CURRENT_MODEL_VERSION, ConversationKind, DeliveryClass, DeploymentBundle,
        DeviceRuntimeAuth, Envelope, IdentityBundle, InboxRecord, InboxRecordState, MessageType,
        SenderProof, StorageBaseInfo, WakeHint,
    };
    use crate::persistence::{CorePersistenceSnapshot, PersistOp};
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    const ALICE_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const BOB_MNEMONIC: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";

    #[test]
    fn module_name_is_stable() {
        assert_eq!(FfiApiModule.name(), "ffi_api");
    }

    #[test]
    fn send_text_message_emits_append_request() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        let output = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id,
                plaintext: "hello".into(),
            })
            .expect("send");
        assert!(output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::ExecuteHttpRequest { request }
                if request.url.contains("/messages")
                    && request.headers.contains_key("X-Tapchat-Capability")
        )));
    }

    #[test]
    fn create_direct_conversation_is_idempotent_for_existing_peer() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        let first_summary = alice
            .mls_summary(&conversation_id)
            .expect("first mls summary")
            .clone();

        let second = alice
            .handle_command(CoreCommand::CreateConversation {
                peer_user_id: bob_bundle.user_id.clone(),
                conversation_kind: ConversationKind::Direct,
            })
            .expect("second create");

        assert!(second.effects.is_empty());
        assert_eq!(alice.state.conversations.len(), 1);
        assert_eq!(
            alice
                .mls_summary(&conversation_id)
                .expect("existing mls summary"),
            &first_summary
        );
        assert_eq!(
            second
                .view_model
                .as_ref()
                .expect("view model")
                .conversations[0]
                .conversation_id,
            conversation_id
        );
    }

    #[test]
    fn realtime_head_updated_triggers_fetch() {
        let mut engine = CoreEngine::new();
        engine
            .handle_command(CoreCommand::ImportDeploymentBundle {
                bundle: sample_deployment(),
            })
            .expect("deployment");
        engine
            .handle_command(CoreCommand::CreateOrLoadIdentity {
                mnemonic: Some(ALICE_MNEMONIC.into()),
                device_name: Some("phone".into()),
            })
            .expect("identity");
        let device_id = engine
            .state
            .local_identity
            .as_ref()
            .unwrap()
            .device_identity
            .device_id
            .clone();
        let output = engine
            .handle_event(CoreEvent::RealtimeEventReceived {
                device_id,
                event: RealtimeEvent::HeadUpdated { seq: 3 },
            })
            .expect("realtime");
        assert!(output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::ExecuteHttpRequest { request } if request.url.contains("fromSeq=1")
        )));
    }

    #[test]
    fn send_attachment_emits_upload_blob_effect() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        let output = alice
            .handle_command(CoreCommand::SendAttachmentMessage {
                conversation_id,
                attachment_descriptor: sample_attachment_descriptor(),
            })
            .expect("attachment");
        assert!(output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::ReadAttachmentBytes { read } if read.attachment_id.ends_with(".bin")
        )));
    }

    #[test]
    fn prepared_blob_upload_and_completion_emit_append_request() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        let upload = alice
            .handle_command(CoreCommand::SendAttachmentMessage {
                conversation_id,
                attachment_descriptor: sample_attachment_descriptor(),
            })
            .expect("attachment");
        let task_id = match upload.effects.iter().find_map(|effect| match effect {
            CoreEffect::ReadAttachmentBytes { read } => Some(read.task_id.clone()),
            _ => None,
        }) {
            Some(task_id) => task_id,
            None => panic!("expected upload task"),
        };
        let prepared = alice
            .handle_event(CoreEvent::AttachmentBytesLoaded {
                task_id: task_id.clone(),
                plaintext_b64: STANDARD.encode([1_u8, 2, 3, 4]),
            })
            .expect("attachment bytes loaded");
        assert!(prepared.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::PrepareBlobUpload { upload }
                if upload.headers.get("Authorization")
                    == Some(&"Bearer device-runtime-token".into())
        )));
        let upload_ready = alice
            .handle_event(CoreEvent::BlobUploadPrepared {
                task_id: task_id.clone(),
                result: crate::transport_contract::PrepareBlobUploadResult {
                    blob_ref: "blob:attachment-1".into(),
                    upload_target: "upload:attachment-1".into(),
                    upload_headers: std::collections::BTreeMap::new(),
                    download_target: Some("blob-download:attachment-1".into()),
                    expires_at: Some(99),
                },
            })
            .expect("blob prepared");
        assert!(upload_ready.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::UploadBlob { upload } if upload.upload_target == "upload:attachment-1"
        )));

        let output = alice
            .handle_event(CoreEvent::BlobUploaded { task_id })
            .expect("blob uploaded");

        assert_eq!(
            alice
                .state
                .pending_outbox
                .iter()
                .find(|item| !item.envelope.storage_refs.is_empty())
                .expect("attachment outbox")
                .envelope
                .storage_refs
                .first()
                .expect("storage ref")
                .object_ref,
            "blob-download:attachment-1"
        );
        assert!(output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::ExecuteHttpRequest { request } if request.url.contains("/messages")
        )));
    }

    #[test]
    fn fetch_response_restores_conversation_and_emits_ack_request() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut engine = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle);
        let device_id = engine
            .state
            .local_identity
            .as_ref()
            .expect("identity")
            .device_identity
            .device_id
            .clone();
        let local_user_id = engine
            .state
            .local_identity
            .as_ref()
            .expect("identity")
            .user_identity
            .user_id
            .clone();
        let peer_user_id = engine
            .state
            .contacts
            .keys()
            .next()
            .expect("contact")
            .clone();
        let peer_device_id = engine
            .state
            .contacts
            .values()
            .next()
            .expect("contact")
            .devices[0]
            .device_id
            .clone();
        let mut conversation_users = [local_user_id.clone(), peer_user_id.clone()];
        conversation_users.sort();
        let expected_conversation_id =
            format!("conv:{}:{}", conversation_users[0], conversation_users[1]);

        let sync = engine
            .handle_command(CoreCommand::SyncInbox {
                device_id: device_id.clone(),
                reason: Some("test".into()),
            })
            .expect("sync");
        let head_request_id = find_http_request_id(&sync, "/head");
        let fetch = engine
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id: head_request_id,
                status: 200,
                body: Some("{\"head_seq\":1}".into()),
            })
            .expect("head response");
        let fetch_request_id = find_http_request_id(&fetch, "/messages?fromSeq=1");

        let output = engine
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id: fetch_request_id,
                status: 200,
                body: Some(
                    serde_json::json!({
                        "to_seq": 1,
                        "records": [sample_control_record(
                            &device_id,
                            1,
                            &local_user_id,
                            &peer_user_id,
                            &peer_device_id,
                        )],
                    })
                    .to_string(),
                ),
            })
            .expect("fetch response");

        assert!(output.state_update.conversations_changed);
        assert!(
            engine
                .state
                .conversations
                .contains_key(&expected_conversation_id)
        );
        assert!(output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::ExecuteHttpRequest { request } if request.url.contains("/ack")
                && request.headers.get("Authorization") == Some(&"Bearer device-runtime-token".into())
        )));
    }

    #[test]
    fn identity_bundle_response_reconciles_membership_and_queues_transport_messages() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());

        let output = alice
            .handle_command(CoreCommand::RefreshIdentityState {
                user_id: bob_bundle.user_id.clone(),
            })
            .expect("refresh");
        assert!(output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::FetchIdentityBundle { fetch } if fetch.user_id == bob_bundle.user_id
        )));

        let updated_bundle = sample_identity_bundle(BOB_MNEMONIC, "laptop");
        let response = alice
            .handle_event(CoreEvent::IdentityBundleFetched {
                user_id: bob_bundle.user_id.clone(),
                bundle: serde_json::from_str(&updated_bundle_json_for_user(
                    &bob_bundle.user_id,
                    updated_bundle,
                ))
                .expect("bundle"),
            })
            .expect("identity bundle response");

        assert!(response.state_update.conversations_changed);
        assert!(response.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::ExecuteHttpRequest { request } if request.url.contains("/messages")
        )));
        assert_eq!(
            alice
                .state
                .conversations
                .get(&conversation_id)
                .expect("conversation")
                .recovery_status,
            crate::conversation::RecoveryStatus::NeedsRecovery
        );
    }

    #[test]
    fn identity_refresh_requires_explicit_identity_bundle_reference() {
        let bundle = sample_identity_bundle_without_identity_ref(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bundle.clone());

        let error = alice
            .handle_command(CoreCommand::RefreshIdentityState {
                user_id: bundle.user_id.clone(),
            })
            .expect_err("missing identity reference should fail");
        assert_eq!(error.code(), "invalid_state");
    }

    #[test]
    fn contact_refresh_does_not_fallback_to_deployment_runtime_reference() {
        let bundle = sample_identity_bundle_without_identity_ref(BOB_MNEMONIC, "phone");
        let mut engine = seeded_engine(ALICE_MNEMONIC, "phone", bundle.clone());

        let error = engine
            .handle_command(CoreCommand::RefreshIdentityState {
                user_id: bundle.user_id.clone(),
            })
            .expect_err("contact refresh should require contact-owned reference");

        assert_eq!(error.code(), "invalid_state");
        assert_eq!(
            error.message(),
            "contact identity bundle reference is missing"
        );
    }

    #[test]
    fn websocket_disconnect_schedules_sync_retry() {
        let mut engine = CoreEngine::new();
        engine
            .handle_command(CoreCommand::ImportDeploymentBundle {
                bundle: sample_deployment(),
            })
            .expect("deployment");
        engine
            .handle_command(CoreCommand::CreateOrLoadIdentity {
                mnemonic: Some(ALICE_MNEMONIC.into()),
                device_name: Some("phone".into()),
            })
            .expect("identity");
        let device_id = engine
            .state
            .local_identity
            .as_ref()
            .expect("identity")
            .device_identity
            .device_id
            .clone();

        let output = engine
            .handle_event(CoreEvent::WebSocketDisconnected {
                device_id: device_id.clone(),
                reason: Some("network".into()),
            })
            .expect("disconnect");

        assert!(output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::ScheduleTimer { timer } if timer.timer_id == format!("sync:{device_id}")
        )));
    }

    #[test]
    fn sync_requests_include_device_runtime_auth_header() {
        let mut engine = CoreEngine::new();
        engine
            .handle_command(CoreCommand::ImportDeploymentBundle {
                bundle: sample_deployment(),
            })
            .expect("deployment");
        engine
            .handle_command(CoreCommand::CreateOrLoadIdentity {
                mnemonic: Some(ALICE_MNEMONIC.into()),
                device_name: Some("phone".into()),
            })
            .expect("identity");
        let device_id = engine
            .state
            .local_identity
            .as_ref()
            .expect("identity")
            .device_identity
            .device_id
            .clone();

        let output = engine
            .handle_command(CoreCommand::SyncInbox {
                device_id,
                reason: Some("test".into()),
            })
            .expect("sync");

        assert!(output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::OpenRealtimeConnection { connection }
                if connection.subscription.headers.get("Authorization")
                    == Some(&"Bearer device-runtime-token".into())
        )));
        assert!(output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::ExecuteHttpRequest { request }
                if request.url.contains("/head")
                    && request.headers.get("Authorization")
                        == Some(&"Bearer device-runtime-token".into())
        )));
    }

    #[test]
    fn prepare_blob_upload_effect_includes_device_runtime_auth_header() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        let output = alice
            .handle_command(CoreCommand::SendAttachmentMessage {
                conversation_id,
                attachment_descriptor: sample_attachment_descriptor(),
            })
            .expect("attachment");

        let task_id = output
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::ReadAttachmentBytes { read } => Some(read.task_id.clone()),
                _ => None,
            })
            .expect("read attachment effect");
        let output = alice
            .handle_event(CoreEvent::AttachmentBytesLoaded {
                task_id,
                plaintext_b64: STANDARD.encode([1_u8, 2, 3, 4]),
            })
            .expect("attachment bytes loaded");
        assert!(output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::PrepareBlobUpload { upload }
                if upload.headers.get("Authorization")
                    == Some(&"Bearer device-runtime-token".into())
        )));
    }

    #[test]
    fn persist_effect_uses_typed_ops_and_snapshot() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        let output = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id,
                plaintext: "hello".into(),
            })
            .expect("send");

        let persist = output.effects.iter().find_map(|effect| match effect {
            CoreEffect::PersistState { persist } => Some(persist),
            _ => None,
        });

        let persist = persist.expect("persist effect");
        assert!(
            persist
                .ops
                .iter()
                .any(|op| matches!(op, PersistOp::SaveOutgoingEnvelope { .. }))
        );
        assert!(persist.snapshot.is_some());
    }

    #[test]
    fn restored_engine_replays_pending_outbox_on_app_started() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        let output = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id,
                plaintext: "hello".into(),
            })
            .expect("send");
        let snapshot = extract_snapshot(&output);

        let mut restored = CoreEngine::from_restored_state(snapshot);
        let resumed = restored
            .handle_event(CoreEvent::AppStarted)
            .expect("app started");

        assert!(resumed.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::ExecuteHttpRequest { request } if request.url.contains("/messages")
        )));
    }

    #[test]
    fn persisted_snapshot_contains_restorable_mls_state() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        let output = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id,
                plaintext: "hello".into(),
            })
            .expect("send");
        let snapshot = extract_snapshot(&output);

        assert!(!snapshot.mls_state_persistence_blocked);
        assert!(
            snapshot
                .mls_states
                .iter()
                .all(|state| state.serialized_group_state.is_some())
        );
    }

    #[test]
    fn append_requires_explicit_accepted_result() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        let output = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id,
                plaintext: "hello".into(),
            })
            .expect("send");
        let request_id = find_http_request_id(&output, "/messages");

        let error = alice
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id,
                status: 200,
                body: Some(r#"{"accepted":false,"seq":0}"#.into()),
            })
            .expect_err("append accepted=false should fail");
        assert_eq!(error.code(), "temporary_failure");
    }

    #[test]
    fn append_message_request_result_emits_policy_notification_and_clears_outbox() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        let output = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id,
                plaintext: "hello".into(),
            })
            .expect("send");
        let request_id = find_http_request_id(&output, "/messages");
        let pending_message_id = alice
            .state
            .pending_outbox
            .last()
            .expect("pending outbox")
            .envelope
            .message_id
            .clone();

        let output = alice
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id,
                status: 200,
                body: Some(
                    r#"{"accepted":true,"seq":0,"delivered_to":"message_request","queued_as_request":true,"request_id":"request:user:bob"}"#.into(),
                ),
            })
            .expect("message request response");

        assert!(
            !alice
                .state
                .pending_outbox
                .iter()
                .any(|item| item.envelope.message_id == pending_message_id)
        );
        assert!(
            output
                .state_update
                .system_statuses_changed
                .contains(&crate::ffi_api::SystemStatus::MessageQueuedForApproval)
        );
        assert!(output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::EmitUserNotification { notification }
            if notification.status == crate::ffi_api::SystemStatus::MessageQueuedForApproval
                && notification.message.contains("queued as a message request")
        )));
        let append_result = output
            .view_model
            .as_ref()
            .and_then(|view| view.append_result.as_ref())
            .expect("append result");
        assert!(append_result.accepted);
        assert_eq!(
            append_result.delivered_to,
            crate::transport_contract::AppendDeliveryDisposition::MessageRequest
        );
        assert_eq!(append_result.request_id.as_deref(), Some("request:user:bob"));
    }

    #[test]
    fn append_rejected_result_emits_policy_notification_and_clears_outbox() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        let output = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id,
                plaintext: "hello".into(),
            })
            .expect("send");
        let request_id = find_http_request_id(&output, "/messages");
        let pending_message_id = alice
            .state
            .pending_outbox
            .last()
            .expect("pending outbox")
            .envelope
            .message_id
            .clone();

        let output = alice
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id,
                status: 200,
                body: Some(r#"{"accepted":true,"seq":0,"delivered_to":"rejected"}"#.into()),
            })
            .expect("rejected response");

        assert!(
            !alice
                .state
                .pending_outbox
                .iter()
                .any(|item| item.envelope.message_id == pending_message_id)
        );
        assert!(
            output
                .state_update
                .system_statuses_changed
                .contains(&crate::ffi_api::SystemStatus::MessageRejectedByPolicy)
        );
        assert!(output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::EmitUserNotification { notification }
            if notification.status == crate::ffi_api::SystemStatus::MessageRejectedByPolicy
                && notification.message.contains("rejected by inbox policy")
        )));
        let append_result = output
            .view_model
            .as_ref()
            .and_then(|view| view.append_result.as_ref())
            .expect("append result");
        assert!(append_result.accepted);
        assert_eq!(
            append_result.delivered_to,
            crate::transport_contract::AppendDeliveryDisposition::Rejected
        );
    }

    #[test]
    fn append_inbox_result_exposes_structured_append_result() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        let output = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id,
                plaintext: "hello".into(),
            })
            .expect("send");
        let request_id = find_http_request_id(&output, "/messages");

        let output = alice
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id,
                status: 200,
                body: Some(r#"{"accepted":true,"seq":3,"delivered_to":"inbox"}"#.into()),
            })
            .expect("inbox response");

        let append_result = output
            .view_model
            .as_ref()
            .and_then(|view| view.append_result.as_ref())
            .expect("append result");
        assert!(append_result.accepted);
        assert_eq!(append_result.seq, Some(3));
        assert_eq!(
            append_result.delivered_to,
            crate::transport_contract::AppendDeliveryDisposition::Inbox
        );
    }

    #[test]
    fn ack_requires_explicit_accepted_result() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut engine = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle);
        let device_id = engine
            .state
            .local_identity
            .as_ref()
            .expect("identity")
            .device_identity
            .device_id
            .clone();
        let local_user_id = engine
            .state
            .local_identity
            .as_ref()
            .expect("identity")
            .user_identity
            .user_id
            .clone();
        let peer_user_id = engine
            .state
            .contacts
            .keys()
            .next()
            .expect("contact")
            .clone();
        let peer_device_id = engine
            .state
            .contacts
            .values()
            .next()
            .expect("contact")
            .devices[0]
            .device_id
            .clone();

        let sync = engine
            .handle_command(CoreCommand::SyncInbox {
                device_id: device_id.clone(),
                reason: Some("test".into()),
            })
            .expect("sync");
        let head_request_id = find_http_request_id(&sync, "/head");
        let fetch = engine
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id: head_request_id,
                status: 200,
                body: Some("{\"head_seq\":1}".into()),
            })
            .expect("head response");
        let fetch_request_id = find_http_request_id(&fetch, "/messages?fromSeq=1");
        let fetched = engine
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id: fetch_request_id,
                status: 200,
                body: Some(
                    serde_json::json!({
                        "to_seq": 1,
                        "records": [sample_control_record(
                            &device_id,
                            1,
                            &local_user_id,
                            &peer_user_id,
                            &peer_device_id,
                        )],
                    })
                    .to_string(),
                ),
            })
            .expect("fetch response");
        let ack_request_id = find_http_request_id(&fetched, "/ack");

        let error = engine
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id: ack_request_id,
                status: 200,
                body: Some(r#"{"accepted":false,"ack_seq":0}"#.into()),
            })
            .expect_err("ack accepted=false should fail");
        assert_eq!(error.code(), "temporary_failure");
    }

    #[test]
    fn restored_engine_replays_pending_ack_and_blob_uploads_on_app_started() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut engine = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut engine, bob_bundle.user_id.clone());
        let upload_output = engine
            .handle_command(CoreCommand::SendAttachmentMessage {
                conversation_id,
                attachment_descriptor: sample_attachment_descriptor(),
            })
            .expect("attachment");
        let mut snapshot = extract_snapshot(&upload_output);
        let device_id = engine
            .state
            .local_identity
            .as_ref()
            .expect("identity")
            .device_identity
            .device_id
            .clone();
        snapshot
            .pending_acks
            .push(crate::persistence::PersistedPendingAck {
                device_id: device_id.clone(),
                ack: crate::model::Ack {
                    device_id: device_id.clone(),
                    ack_seq: 7,
                    acked_message_ids: vec!["msg:ack".into()],
                    acked_at: 7,
                },
                retries: 0,
            });

        let mut restored = CoreEngine::from_restored_state(snapshot);
        let resumed = restored
            .handle_event(CoreEvent::AppStarted)
            .expect("app started");

        assert!(
            resumed
                .effects
                .iter()
                .any(|effect| matches!(effect, CoreEffect::ReadAttachmentBytes { .. }))
        );
        assert!(resumed.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::ExecuteHttpRequest { request } if request.url.contains("/ack")
        )));
    }

    #[test]
    fn prepared_blob_upload_survives_snapshot_restore() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut engine = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut engine, bob_bundle.user_id.clone());
        let upload_output = engine
            .handle_command(CoreCommand::SendAttachmentMessage {
                conversation_id,
                attachment_descriptor: sample_attachment_descriptor(),
            })
            .expect("attachment");
        let task_id = upload_output
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::ReadAttachmentBytes { read } => Some(read.task_id.clone()),
                _ => None,
            })
            .expect("read attachment effect");
        let prepared_output = engine
            .handle_event(CoreEvent::AttachmentBytesLoaded {
                task_id,
                plaintext_b64: STANDARD.encode([1_u8, 2, 3, 4]),
            })
            .expect("attachment bytes loaded");
        let mut snapshot = extract_snapshot(&prepared_output);
        if let Some(crate::persistence::PersistedPendingBlobTransfer::Upload {
            blob_ciphertext_b64,
            payload_metadata,
            metadata_ciphertext,
            prepared_upload,
            ..
        }) = snapshot.pending_blob_transfers.first_mut()
        {
            assert!(blob_ciphertext_b64.is_some());
            assert!(payload_metadata.is_some());
            assert!(metadata_ciphertext.is_some());
            *prepared_upload = Some(crate::transport_contract::PrepareBlobUploadResult {
                blob_ref: "blob:prepared".into(),
                upload_target: "upload:prepared".into(),
                upload_headers: std::collections::BTreeMap::new(),
                download_target: Some("download:prepared".into()),
                expires_at: Some(42),
            });
        } else {
            panic!("missing persisted upload task");
        }

        let mut restored = CoreEngine::from_restored_state(snapshot);
        let resumed = restored
            .handle_event(CoreEvent::AppStarted)
            .expect("app started");

        assert!(resumed.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::UploadBlob { upload } if upload.upload_target == "upload:prepared"
        )));
    }

    #[test]
    fn corrupted_mls_snapshot_marks_only_affected_conversation_for_rebuild() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        let output = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "hello".into(),
            })
            .expect("send");
        let mut snapshot = extract_snapshot(&output);
        snapshot.mls_states[0].serialized_group_state = Some("{broken".into());

        let restored = CoreEngine::from_restored_state(snapshot);

        assert_eq!(
            restored
                .state
                .conversations
                .get(&conversation_id)
                .expect("conversation")
                .conversation
                .state,
            crate::model::ConversationState::NeedsRebuild
        );
        assert_eq!(
            restored
                .state
                .mls_summaries
                .get(&conversation_id)
                .expect("summary")
                .status,
            crate::model::MlsStateStatus::NeedsRebuild
        );
        let recovery = restored
            .recovery_context_snapshot(&conversation_id)
            .expect("recovery context");
        assert_eq!(
            recovery.phase,
            crate::ffi_api::RecoveryPhase::EscalatedToRebuild
        );
        assert_eq!(
            recovery.escalation_reason,
            Some(crate::ffi_api::RecoveryEscalationReason::MlsMarkedUnrecoverable)
        );
    }

    #[test]
    fn inline_realtime_record_and_fetch_do_not_duplicate_ingest() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut engine = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle);
        let device_id = engine
            .state
            .local_identity
            .as_ref()
            .expect("identity")
            .device_identity
            .device_id
            .clone();
        let local_user_id = engine
            .state
            .local_identity
            .as_ref()
            .expect("identity")
            .user_identity
            .user_id
            .clone();
        let peer_user_id = engine
            .state
            .contacts
            .keys()
            .next()
            .expect("contact")
            .clone();
        let peer_device_id = engine
            .state
            .contacts
            .values()
            .next()
            .expect("contact")
            .devices[0]
            .device_id
            .clone();
        let record = sample_control_record(
            &device_id,
            1,
            &local_user_id,
            &peer_user_id,
            &peer_device_id,
        );
        let conversation_id = record.envelope.conversation_id.clone();

        engine
            .handle_event(CoreEvent::RealtimeEventReceived {
                device_id: device_id.clone(),
                event: RealtimeEvent::InboxRecordAvailable {
                    seq: 1,
                    record: Some(record.clone()),
                },
            })
            .expect("inline record");
        engine
            .handle_event(CoreEvent::InboxRecordsFetched {
                device_id,
                records: vec![record],
                to_seq: 1,
            })
            .expect("fetch records");

        assert_eq!(
            engine
                .state
                .conversations
                .get(&conversation_id)
                .expect("conversation")
                .messages
                .len(),
            1
        );
    }

    #[test]
    fn stale_realtime_head_after_fetch_is_noop() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut engine = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle);
        let device_id = engine
            .state
            .local_identity
            .as_ref()
            .expect("identity")
            .device_identity
            .device_id
            .clone();
        let local_user_id = engine
            .state
            .local_identity
            .as_ref()
            .expect("identity")
            .user_identity
            .user_id
            .clone();
        let peer_user_id = engine
            .state
            .contacts
            .keys()
            .next()
            .expect("contact")
            .clone();
        let peer_device_id = engine
            .state
            .contacts
            .values()
            .next()
            .expect("contact")
            .devices[0]
            .device_id
            .clone();

        let record = sample_control_record(
            &device_id,
            1,
            &local_user_id,
            &peer_user_id,
            &peer_device_id,
        );
        let conversation_id = record.envelope.conversation_id.clone();

        engine
            .handle_event(CoreEvent::InboxRecordsFetched {
                device_id: device_id.clone(),
                records: vec![record],
                to_seq: 1,
            })
            .expect("fetch records");

        let stale = engine
            .handle_event(CoreEvent::RealtimeEventReceived {
                device_id: device_id.clone(),
                event: RealtimeEvent::HeadUpdated { seq: 1 },
            })
            .expect("stale realtime");

        assert!(stale.effects.is_empty());
        assert_eq!(
            engine
                .state
                .conversations
                .get(&conversation_id)
                .expect("conversation")
                .messages
                .len(),
            1
        );
        assert_eq!(
            engine
                .sync_checkpoint_snapshot(&device_id)
                .expect("checkpoint")
                .last_acked_seq,
            1
        );
    }

    #[test]
    fn identity_refresh_retries_then_marks_conversation_for_rebuild() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        alice.state.recovery_contexts.insert(
            conversation_id.clone(),
            RecoveryContext {
                conversation_id: conversation_id.clone(),
                reason: RecoveryReason::IdentityChanged,
                phase: crate::ffi_api::RecoveryPhase::WaitingForIdentityRefresh,
                attempt_count: 1,
                identity_refresh_retry_count: 0,
                last_error: None,
                escalation_reason: None,
            },
        );

        for attempt in 0..crate::ffi_api::MAX_TRANSPORT_RETRIES {
            let refresh = alice
                .handle_command(CoreCommand::RefreshIdentityState {
                    user_id: bob_bundle.user_id.clone(),
                })
                .expect("refresh");
            assert!(refresh.effects.iter().any(|effect| matches!(
                effect,
                CoreEffect::FetchIdentityBundle { fetch } if fetch.user_id == bob_bundle.user_id
            )));
            let output = alice
                .handle_event(CoreEvent::IdentityBundleFetchFailed {
                    user_id: bob_bundle.user_id.clone(),
                    retryable: true,
                    detail: Some("network".into()),
                })
                .expect("refresh failure");
            if attempt + 1 < crate::ffi_api::MAX_TRANSPORT_RETRIES {
                assert!(output.effects.iter().any(|effect| matches!(
                    effect,
                    CoreEffect::ScheduleTimer { timer }
                    if timer.timer_id == format!("refresh_identity:{}", bob_bundle.user_id)
                )));
            } else {
                assert!(
                    output
                        .state_update
                        .system_statuses_changed
                        .contains(&crate::ffi_api::SystemStatus::ConversationNeedsRebuild)
                );
            }
        }

        assert_eq!(
            alice
                .state
                .conversations
                .get(&conversation_id)
                .expect("conversation")
                .conversation
                .state,
            crate::model::ConversationState::NeedsRebuild
        );
        let recovery = alice
            .recovery_context_snapshot(&conversation_id)
            .expect("recovery context");
        assert_eq!(
            recovery.phase,
            crate::ffi_api::RecoveryPhase::EscalatedToRebuild
        );
        assert_eq!(
            recovery.escalation_reason,
            Some(crate::ffi_api::RecoveryEscalationReason::IdentityRefreshRetryExhausted)
        );
    }

    #[test]
    fn control_needs_rebuild_record_sets_explicit_rebuild_escalation_reason() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle);
        let device_id = alice
            .state
            .local_identity
            .as_ref()
            .expect("identity")
            .device_identity
            .device_id
            .clone();
        let local_user_id = alice
            .state
            .local_identity
            .as_ref()
            .expect("identity")
            .user_identity
            .user_id
            .clone();
        let peer_user_id = alice.state.contacts.keys().next().expect("contact").clone();
        let peer_device_id = alice
            .state
            .contacts
            .values()
            .next()
            .expect("contact")
            .devices[0]
            .device_id
            .clone();
        let record = sample_control_record_with_type(
            &device_id,
            1,
            &local_user_id,
            &peer_user_id,
            &peer_device_id,
            MessageType::ControlConversationNeedsRebuild,
        );
        let conversation_id = record.envelope.conversation_id.clone();

        alice
            .handle_event(CoreEvent::InboxRecordsFetched {
                device_id,
                records: vec![record],
                to_seq: 1,
            })
            .expect("ingest control rebuild");

        assert_eq!(
            alice
                .state
                .conversations
                .get(&conversation_id)
                .expect("conversation")
                .conversation
                .state,
            crate::model::ConversationState::NeedsRebuild
        );
        let recovery = alice
            .recovery_context_snapshot(&conversation_id)
            .expect("recovery context");
        assert_eq!(
            recovery.phase,
            crate::ffi_api::RecoveryPhase::EscalatedToRebuild
        );
        assert_eq!(
            recovery.escalation_reason,
            Some(crate::ffi_api::RecoveryEscalationReason::ExplicitNeedsRebuildControl)
        );
    }

    #[test]
    fn rebuild_command_sets_recovery_policy_exhausted_escalation_reason() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());

        alice
            .handle_command(CoreCommand::RebuildConversation {
                conversation_id: conversation_id.clone(),
            })
            .expect("rebuild conversation");

        let recovery = alice
            .recovery_context_snapshot(&conversation_id)
            .expect("recovery context");
        assert_eq!(
            recovery.phase,
            crate::ffi_api::RecoveryPhase::EscalatedToRebuild
        );
        assert_eq!(
            recovery.escalation_reason,
            Some(crate::ffi_api::RecoveryEscalationReason::RecoveryPolicyExhausted)
        );
    }

    #[test]
    fn restored_needs_rebuild_preserves_existing_escalation_reason() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());

        let rebuild_output = alice
            .handle_command(CoreCommand::RebuildConversation {
                conversation_id: conversation_id.clone(),
            })
            .expect("rebuild conversation");
        let snapshot = extract_snapshot(&rebuild_output);
        let restored = CoreEngine::from_restored_state(snapshot);

        let recovery = restored
            .recovery_context_snapshot(&conversation_id)
            .expect("restored recovery context");
        assert_eq!(
            recovery.escalation_reason,
            Some(crate::ffi_api::RecoveryEscalationReason::RecoveryPolicyExhausted)
        );
        assert_eq!(
            restored
                .state
                .conversations
                .get(&conversation_id)
                .expect("restored conversation")
                .recovery_status,
            crate::conversation::RecoveryStatus::NeedsRebuild
        );
    }

    #[test]
    fn identity_refresh_failure_below_limit_keeps_needs_recovery() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        alice.state.recovery_contexts.insert(
            conversation_id.clone(),
            RecoveryContext {
                conversation_id: conversation_id.clone(),
                reason: RecoveryReason::IdentityChanged,
                phase: crate::ffi_api::RecoveryPhase::WaitingForIdentityRefresh,
                attempt_count: 1,
                identity_refresh_retry_count: 0,
                last_error: None,
                escalation_reason: None,
            },
        );
        alice
            .state
            .conversations
            .get_mut(&conversation_id)
            .expect("conversation")
            .recovery_status = crate::conversation::RecoveryStatus::NeedsRecovery;

        let output = alice
            .handle_event(CoreEvent::IdentityBundleFetchFailed {
                user_id: bob_bundle.user_id.clone(),
                retryable: true,
                detail: Some("network".into()),
            })
            .expect("refresh failure");

        assert!(output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::ScheduleTimer { timer }
            if timer.timer_id == format!("refresh_identity:{}", bob_bundle.user_id)
        )));
        assert_eq!(
            alice
                .state
                .conversations
                .get(&conversation_id)
                .expect("conversation")
                .conversation
                .state,
            crate::model::ConversationState::Active
        );
        assert_eq!(
            alice
                .recovery_context_snapshot(&conversation_id)
                .expect("context")
                .identity_refresh_retry_count,
            1
        );
    }

    #[test]
    fn late_refresh_identity_timer_is_noop_after_recovery_clears() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        alice.state.recovery_contexts.insert(
            conversation_id.clone(),
            RecoveryContext {
                conversation_id: conversation_id.clone(),
                reason: RecoveryReason::IdentityChanged,
                phase: crate::ffi_api::RecoveryPhase::WaitingForIdentityRefresh,
                attempt_count: 1,
                identity_refresh_retry_count: 1,
                last_error: None,
                escalation_reason: None,
            },
        );
        alice.state.recovery_contexts.remove(&conversation_id);

        let output = alice
            .handle_event(CoreEvent::TimerTriggered {
                timer_id: format!("refresh_identity:{}", bob_bundle.user_id),
            })
            .expect("late timer");
        assert!(output.effects.is_empty());
    }

    #[test]
    fn attachment_download_failure_stops_retrying_at_limit() {
        let mut engine = CoreEngine::new();
        engine
            .handle_command(CoreCommand::ImportDeploymentBundle {
                bundle: sample_deployment(),
            })
            .expect("deployment");
        engine
            .handle_command(CoreCommand::CreateOrLoadIdentity {
                mnemonic: Some(ALICE_MNEMONIC.into()),
                device_name: Some("phone".into()),
            })
            .expect("identity");
        engine.state.conversations.insert(
            "conv:test".into(),
            crate::conversation::LocalConversationState {
                conversation: crate::model::Conversation {
                    conversation_id: "conv:test".into(),
                    kind: ConversationKind::Direct,
                    member_users: vec!["user:alice".into(), "user:bob".into()],
                    member_devices: vec![],
                    state: crate::model::ConversationState::Active,
                    updated_at: 0,
                },
                messages: vec![crate::conversation::StoredMessage {
                    message_id: "msg:download".into(),
                    sender_device_id: "device:sender".into(),
                    recipient_device_id: "device:recipient".into(),
                    message_type: MessageType::MlsApplication,
                    created_at: 0,
                    plaintext: Some(
                        serde_json::to_string(&sample_attachment_payload_metadata())
                            .expect("attachment metadata"),
                    ),
                    storage_refs: vec![],
                    downloaded_blob_b64: None,
                }],
                last_message_type: Some(MessageType::MlsApplication),
                peer_user_id: "user:bob".into(),
                last_known_peer_active_devices: Default::default(),
                recovery_status: crate::conversation::RecoveryStatus::Healthy,
            },
        );
        engine
            .handle_command(CoreCommand::DownloadAttachment {
                conversation_id: "conv:test".into(),
                message_id: "msg:download".into(),
                reference: "cid:download".into(),
                destination: "download.bin".into(),
            })
            .expect("download attachment");

        for attempt in 0..crate::ffi_api::MAX_TRANSPORT_RETRIES {
            let output = engine
                .handle_event(CoreEvent::BlobTransferFailed {
                    task_id: "blob-download:msg:download".into(),
                    retryable: true,
                    detail: Some("download failed".into()),
                })
                .expect("blob failure");
            if attempt + 1 < crate::ffi_api::MAX_TRANSPORT_RETRIES {
                assert!(output.effects.iter().any(|effect| matches!(
                    effect,
                    CoreEffect::ScheduleTimer { timer }
                    if timer.timer_id == "retry_blob_download:blob-download:msg:download"
                )));
                engine
                    .handle_event(CoreEvent::TimerTriggered {
                        timer_id: "retry_blob_download:blob-download:msg:download".into(),
                    })
                    .expect("retry timer");
            } else {
                assert!(
                    !output
                        .effects
                        .iter()
                        .any(|effect| matches!(effect, CoreEffect::ScheduleTimer { .. }))
                );
            }
        }

        assert!(
            !engine
                .state
                .pending_blob_downloads
                .contains_key("blob-download:msg:download")
        );
    }

    #[test]
    fn create_additional_device_identity_keeps_user_and_changes_device() {
        let first = seeded_engine(
            ALICE_MNEMONIC,
            "phone",
            sample_identity_bundle(BOB_MNEMONIC, "phone"),
        );
        let original_user_id = first
            .state
            .local_identity
            .as_ref()
            .expect("identity")
            .user_identity
            .user_id
            .clone();
        let original_device_id = first
            .state
            .local_identity
            .as_ref()
            .expect("identity")
            .device_identity
            .device_id
            .clone();

        let mut engine = CoreEngine::new();
        engine
            .handle_command(CoreCommand::ImportDeploymentBundle {
                bundle: sample_deployment(),
            })
            .expect("deployment");
        engine
            .handle_command(CoreCommand::CreateAdditionalDeviceIdentity {
                mnemonic: Some(ALICE_MNEMONIC.into()),
                device_name: Some("laptop".into()),
            })
            .expect("additional device");

        let identity = engine
            .state
            .local_identity
            .as_ref()
            .expect("local identity");
        assert_eq!(identity.user_identity.user_id, original_user_id);
        assert_ne!(identity.device_identity.device_id, original_device_id);
    }

    #[test]
    fn additional_device_snapshot_round_trip_restores_bootstrap_for_welcome_staging() {
        let bob_phone_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_phone_bundle.clone());
        let conversation_id =
            create_direct_conversation(&mut alice, bob_phone_bundle.user_id.clone());

        let mut laptop = CoreEngine::new();
        laptop
            .handle_command(CoreCommand::ImportDeploymentBundle {
                bundle: sample_deployment(),
            })
            .expect("deployment");
        let create_output = laptop
            .handle_command(CoreCommand::CreateAdditionalDeviceIdentity {
                mnemonic: Some(BOB_MNEMONIC.into()),
                device_name: Some("laptop".into()),
            })
            .expect("additional device");
        let snapshot = extract_snapshot(&create_output);
        let deployment = snapshot
            .deployment
            .as_ref()
            .expect("persisted deployment for additional device");
        assert_eq!(
            deployment
                .local_bundle
                .as_ref()
                .expect("local bundle")
                .devices[0]
                .device_id,
            snapshot
                .local_identity
                .as_ref()
                .expect("local identity")
                .state
                .device_identity
                .device_id
        );
        assert_eq!(
            deployment
                .published_key_package
                .as_ref()
                .expect("published key package")
                .key_package_ref,
            deployment
                .local_bundle
                .as_ref()
                .expect("local bundle")
                .devices[0]
                .keypackage_ref
                .object_ref
        );
        assert!(
            deployment.serialized_mls_bootstrap_state.is_some(),
            "additional device snapshot should persist MLS bootstrap state before welcome"
        );

        let laptop_profile = deployment
            .local_bundle
            .as_ref()
            .expect("local bundle")
            .devices[0]
            .clone();
        let laptop_identity = snapshot
            .local_identity
            .as_ref()
            .expect("local identity")
            .state
            .clone();
        let merged = IdentityManager::export_identity_bundle_with_devices(
            &laptop_identity,
            &sample_deployment(),
            vec![bob_phone_bundle.devices[0].clone(), laptop_profile.clone()],
            None,
        )
        .expect("merged bundle");
        alice
            .handle_command(CoreCommand::ApplyIdentityBundleUpdate { bundle: merged })
            .expect("apply merged bundle");
        let welcome = alice
            .state
            .pending_outbox
            .iter()
            .find(|item| {
                item.envelope.conversation_id == conversation_id
                    && item.envelope.message_type == MessageType::MlsWelcome
                    && item.envelope.recipient_device_id == laptop_profile.device_id
            })
            .map(|item| item.envelope.clone())
            .expect("welcome for laptop");

        let mut restored = CoreEngine::from_restored_state(snapshot);
        let result = restored
            .state
            .mls_adapter
            .as_mut()
            .expect("restored laptop adapter")
            .ingest_message(
                &conversation_id,
                &welcome.sender_device_id,
                MessageType::MlsWelcome,
                welcome
                    .inline_ciphertext
                    .as_deref()
                    .expect("welcome payload"),
            )
            .expect("stage welcome after snapshot restore");
        assert!(matches!(
            result,
            crate::mls_adapter::IngestResult::AppliedWelcome { .. }
        ));
    }

    #[test]
    fn rotate_local_key_package_updates_local_bundle_reference() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut engine = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle);
        let before = engine
            .state
            .local_bundle
            .as_ref()
            .expect("local bundle")
            .devices[0]
            .keypackage_ref
            .object_ref
            .clone();

        engine
            .handle_command(CoreCommand::RotateLocalKeyPackage)
            .expect("rotate key package");

        let after = engine
            .state
            .local_bundle
            .as_ref()
            .expect("local bundle")
            .devices[0]
            .keypackage_ref
            .object_ref
            .clone();
        assert_ne!(before, after);
    }

    #[test]
    fn apply_local_device_status_update_updates_local_bundle_status() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut engine = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle);

        engine
            .handle_command(CoreCommand::ApplyLocalDeviceStatusUpdate {
                status: crate::model::DeviceStatusKind::Revoked,
            })
            .expect("status update");

        assert!(matches!(
            engine
                .state
                .local_bundle
                .as_ref()
                .expect("local bundle")
                .devices[0]
                .status,
            crate::model::DeviceStatusKind::Revoked
        ));
    }

    #[test]
    fn identity_bundle_update_with_new_device_refreshes_contact_devices() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let bob_root = IdentityManager::recover_user_root(BOB_MNEMONIC).expect("bob root");
        let bob_laptop = IdentityManager::create_new_device_for_user(&bob_root, None)
            .expect("bob laptop identity");
        let bob_phone_profile = bob_bundle.devices[0].clone();
        let bob_laptop_package =
            MlsAdapter::generate_key_package(&bob_laptop, 0).expect("laptop package");
        let bob_laptop_profile =
            crate::capability::CapabilityManager::build_device_contact_profile(
                &bob_laptop,
                &sample_deployment(),
                bob_laptop_package.key_package_b64,
                bob_laptop_package.expires_at,
            )
            .expect("laptop profile");
        let merged = IdentityManager::export_identity_bundle_with_devices(
            &bob_laptop,
            &sample_deployment(),
            vec![bob_phone_profile, bob_laptop_profile.clone()],
            None,
        )
        .expect("merged bundle");

        alice
            .handle_command(CoreCommand::ApplyIdentityBundleUpdate {
                bundle: merged.clone(),
            })
            .expect("apply bundle update");

        let updated = alice
            .state
            .contacts
            .get(&merged.user_id)
            .expect("updated contact");
        assert_eq!(updated.devices.len(), 2);
        assert!(
            updated
                .devices
                .iter()
                .any(|device| device.device_id == bob_laptop_profile.device_id)
        );
    }

    #[test]
    fn identity_bundle_update_with_new_device_queues_welcome_and_commit() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());

        let bob_root = IdentityManager::recover_user_root(BOB_MNEMONIC).expect("bob root");
        let bob_laptop = IdentityManager::create_new_device_for_user(&bob_root, None)
            .expect("bob laptop identity");
        let bob_phone_profile = bob_bundle.devices[0].clone();
        let bob_laptop_package =
            MlsAdapter::generate_key_package(&bob_laptop, 0).expect("laptop package");
        let bob_laptop_profile =
            crate::capability::CapabilityManager::build_device_contact_profile(
                &bob_laptop,
                &sample_deployment(),
                bob_laptop_package.key_package_b64,
                bob_laptop_package.expires_at,
            )
            .expect("laptop profile");
        let merged = IdentityManager::export_identity_bundle_with_devices(
            &bob_laptop,
            &sample_deployment(),
            vec![bob_phone_profile, bob_laptop_profile.clone()],
            None,
        )
        .expect("merged bundle");

        alice
            .handle_command(CoreCommand::ApplyIdentityBundleUpdate {
                bundle: merged.clone(),
            })
            .expect("apply bundle update");

        assert!(alice.state.pending_outbox.iter().any(|item| {
            item.envelope.conversation_id == conversation_id
                && item.envelope.message_type == MessageType::MlsWelcome
                && item.envelope.recipient_device_id == bob_laptop_profile.device_id
        }));
        assert!(alice.state.pending_outbox.iter().any(|item| {
            item.envelope.conversation_id == conversation_id
                && item.envelope.message_type == MessageType::MlsCommit
        }));
    }

    #[test]
    fn revoked_device_update_queues_remove_commit_without_welcome() {
        let bob_root = IdentityManager::recover_user_root(BOB_MNEMONIC).expect("bob root");
        let bob_phone = IdentityManager::create_new_device_for_user(&bob_root, None)
            .expect("bob phone identity");
        let bob_laptop = IdentityManager::create_new_device_for_user(&bob_root, None)
            .expect("bob laptop identity");
        let bob_phone_package =
            MlsAdapter::generate_key_package(&bob_phone, 0).expect("phone package");
        let bob_laptop_package =
            MlsAdapter::generate_key_package(&bob_laptop, 0).expect("laptop package");
        let deployment = sample_deployment();
        let mut bob_phone_profile =
            crate::capability::CapabilityManager::build_device_contact_profile(
                &bob_phone,
                &deployment,
                bob_phone_package.key_package_b64,
                bob_phone_package.expires_at,
            )
            .expect("phone profile");
        let bob_laptop_profile =
            crate::capability::CapabilityManager::build_device_contact_profile(
                &bob_laptop,
                &deployment,
                bob_laptop_package.key_package_b64,
                bob_laptop_package.expires_at,
            )
            .expect("laptop profile");
        let active_bundle = IdentityManager::export_identity_bundle_with_devices(
            &bob_laptop,
            &deployment,
            vec![bob_phone_profile.clone(), bob_laptop_profile.clone()],
            None,
        )
        .expect("active bundle");

        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", active_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, active_bundle.user_id.clone());

        bob_phone_profile.status = crate::model::DeviceStatusKind::Revoked;
        let revoked_bundle = IdentityManager::export_identity_bundle_with_devices(
            &bob_laptop,
            &deployment,
            vec![bob_phone_profile.clone(), bob_laptop_profile.clone()],
            None,
        )
        .expect("revoked bundle");
        let pending_before = alice.state.pending_outbox.len();

        alice
            .handle_command(CoreCommand::ApplyIdentityBundleUpdate {
                bundle: revoked_bundle,
            })
            .expect("apply revoked bundle update");

        let new_pending = &alice.state.pending_outbox[pending_before..];
        assert!(!new_pending.iter().any(|item| {
            item.envelope.conversation_id == conversation_id
                && item.envelope.message_type == MessageType::MlsWelcome
        }));
        let remove_commits: Vec<_> = new_pending
            .iter()
            .filter(|item| {
                item.envelope.conversation_id == conversation_id
                    && item.envelope.message_type == MessageType::MlsCommit
            })
            .collect();
        assert!(!remove_commits.is_empty());
        assert!(
            remove_commits
                .iter()
                .all(|item| item.envelope.recipient_device_id == bob_laptop_profile.device_id)
        );
        assert!(
            remove_commits
                .iter()
                .all(|item| item.envelope.recipient_device_id != bob_phone_profile.device_id)
        );
    }

    #[test]
    fn repeated_explicit_reconcile_is_idempotent() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());

        let bob_root = IdentityManager::recover_user_root(BOB_MNEMONIC).expect("bob root");
        let bob_laptop = IdentityManager::create_new_device_for_user(&bob_root, None)
            .expect("bob laptop identity");
        let bob_phone_profile = bob_bundle.devices[0].clone();
        let bob_laptop_package =
            MlsAdapter::generate_key_package(&bob_laptop, 0).expect("laptop package");
        let bob_laptop_profile =
            crate::capability::CapabilityManager::build_device_contact_profile(
                &bob_laptop,
                &sample_deployment(),
                bob_laptop_package.key_package_b64,
                bob_laptop_package.expires_at,
            )
            .expect("laptop profile");
        let merged = IdentityManager::export_identity_bundle_with_devices(
            &bob_laptop,
            &sample_deployment(),
            vec![bob_phone_profile, bob_laptop_profile],
            None,
        )
        .expect("merged bundle");

        alice
            .handle_command(CoreCommand::ApplyIdentityBundleUpdate { bundle: merged })
            .expect("apply bundle update");
        let pending_after_refresh = alice.state.pending_outbox.len();

        alice
            .handle_command(CoreCommand::ReconcileConversationMembership {
                conversation_id: conversation_id.clone(),
            })
            .expect("explicit reconcile should be idempotent");

        assert_eq!(alice.state.pending_outbox.len(), pending_after_refresh);
    }

    #[test]
    fn restored_identity_update_state_keeps_reconcile_idempotent() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());

        let bob_root = IdentityManager::recover_user_root(BOB_MNEMONIC).expect("bob root");
        let bob_laptop = IdentityManager::create_new_device_for_user(&bob_root, None)
            .expect("bob laptop identity");
        let bob_phone_profile = bob_bundle.devices[0].clone();
        let bob_laptop_package =
            MlsAdapter::generate_key_package(&bob_laptop, 0).expect("laptop package");
        let bob_laptop_profile =
            crate::capability::CapabilityManager::build_device_contact_profile(
                &bob_laptop,
                &sample_deployment(),
                bob_laptop_package.key_package_b64,
                bob_laptop_package.expires_at,
            )
            .expect("laptop profile");
        let merged = IdentityManager::export_identity_bundle_with_devices(
            &bob_laptop,
            &sample_deployment(),
            vec![bob_phone_profile, bob_laptop_profile],
            None,
        )
        .expect("merged bundle");

        let refresh_output = alice
            .handle_command(CoreCommand::ApplyIdentityBundleUpdate { bundle: merged })
            .expect("apply bundle update");
        let pending_after_refresh = alice.state.pending_outbox.len();

        let snapshot = extract_snapshot(&refresh_output);
        let mut restored = CoreEngine::from_restored_state(snapshot);
        restored
            .handle_command(CoreCommand::ReconcileConversationMembership {
                conversation_id: conversation_id.clone(),
            })
            .expect("explicit reconcile after restore should remain idempotent");

        assert_eq!(restored.state.pending_outbox.len(), pending_after_refresh);
    }

    #[test]
    fn restored_needs_rebuild_then_reconcile_recreates_mls_artifacts() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());

        let create_output = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "before rebuild".into(),
            })
            .expect("send");
        let mut snapshot = extract_snapshot(&create_output);
        snapshot
            .mls_states
            .first_mut()
            .expect("mls state")
            .serialized_group_state = Some("{broken".into());
        let mut restored = CoreEngine::from_restored_state(snapshot);
        let pending_before = restored.state.pending_outbox.len();

        let output = restored
            .handle_command(CoreCommand::ReconcileConversationMembership {
                conversation_id: conversation_id.clone(),
            })
            .expect("reconcile after rebuild");

        assert!(output.view_model.as_ref().is_some_and(|view| {
            view.messages
                .iter()
                .any(|message| message.message_type == MessageType::MlsCommit)
                && view
                    .messages
                    .iter()
                    .any(|message| message.message_type == MessageType::MlsWelcome)
        }));
        assert!(
            restored.state.pending_outbox[pending_before..]
                .iter()
                .any(|item| {
                    item.envelope.conversation_id == conversation_id
                        && item.envelope.message_type == MessageType::MlsCommit
                })
        );
        assert!(
            restored.state.pending_outbox[pending_before..]
                .iter()
                .any(|item| {
                    item.envelope.conversation_id == conversation_id
                        && item.envelope.message_type == MessageType::MlsWelcome
                })
        );
        assert_eq!(
            restored
                .state
                .conversations
                .get(&conversation_id)
                .expect("conversation")
                .recovery_status,
            crate::conversation::RecoveryStatus::NeedsRecovery
        );
        assert_eq!(
            restored
                .state
                .conversations
                .get(&conversation_id)
                .expect("conversation")
                .conversation
                .state,
            crate::model::ConversationState::Active
        );
    }

    #[test]
    fn reimported_deployment_publishes_local_shared_state_documents() {
        let mut engine = CoreEngine::new();
        engine
            .handle_command(CoreCommand::ImportDeploymentBundle {
                bundle: sample_deployment(),
            })
            .expect("deployment");
        engine
            .handle_command(CoreCommand::CreateOrLoadIdentity {
                mnemonic: Some(ALICE_MNEMONIC.into()),
                device_name: Some("phone".into()),
            })
            .expect("identity");

        let output = engine
            .handle_command(CoreCommand::ImportDeploymentBundle {
                bundle: sample_deployment(),
            })
            .expect("reimport deployment");

        assert_eq!(publish_shared_state_effects(&output).len(), 2);
        assert!(publish_shared_state_effects(&output)
            .iter()
            .any(|publish| publish.document_kind
                == crate::transport_contract::SharedStateDocumentKind::IdentityBundle));
        assert!(publish_shared_state_effects(&output)
            .iter()
            .any(|publish| publish.document_kind
                == crate::transport_contract::SharedStateDocumentKind::DeviceStatus));
    }

    #[test]
    fn updating_local_device_status_publishes_shared_state_documents() {
        let mut engine = CoreEngine::new();
        engine
            .handle_command(CoreCommand::ImportDeploymentBundle {
                bundle: sample_deployment(),
            })
            .expect("deployment");
        engine
            .handle_command(CoreCommand::CreateOrLoadIdentity {
                mnemonic: Some(ALICE_MNEMONIC.into()),
                device_name: Some("phone".into()),
            })
            .expect("identity");
        let device_id = engine
            .state
            .local_identity
            .as_ref()
            .expect("local identity")
            .device_identity
            .device_id
            .clone();

        let output = engine
            .handle_command(CoreCommand::UpdateLocalDeviceStatus {
                target_device_id: device_id,
                status: crate::model::DeviceStatusKind::Revoked,
            })
            .expect("update device status");

        assert_eq!(publish_shared_state_effects(&output).len(), 2);
    }

    #[test]
    fn list_message_requests_emits_fetch_management_effect() {
        let mut engine = CoreEngine::new();
        engine
            .handle_command(CoreCommand::ImportDeploymentBundle {
                bundle: sample_deployment(),
            })
            .expect("deployment");
        engine
            .handle_command(CoreCommand::CreateOrLoadIdentity {
                mnemonic: Some(ALICE_MNEMONIC.into()),
                device_name: Some("phone".into()),
            })
            .expect("identity");

        let output = engine
            .handle_command(CoreCommand::ListMessageRequests)
            .expect("list requests");

        assert!(output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::FetchMessageRequests { fetch }
                if fetch.endpoint.ends_with("/message-requests")
        )));
    }

    #[test]
    fn add_allowlist_user_fetches_then_replaces_allowlist_document() {
        let mut engine = CoreEngine::new();
        engine
            .handle_command(CoreCommand::ImportDeploymentBundle {
                bundle: sample_deployment(),
            })
            .expect("deployment");
        engine
            .handle_command(CoreCommand::CreateOrLoadIdentity {
                mnemonic: Some(ALICE_MNEMONIC.into()),
                device_name: Some("phone".into()),
            })
            .expect("identity");

        let fetch = engine
            .handle_command(CoreCommand::AddAllowlistUser {
                user_id: "user:bob".into(),
            })
            .expect("add allowlist user");
        assert!(fetch.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::FetchAllowlist { fetch } if fetch.endpoint.ends_with("/allowlist")
        )));

        let replaced = engine
            .handle_event(CoreEvent::AllowlistFetched {
                document: crate::transport_contract::AllowlistDocument {
                    allowed_sender_user_ids: vec![],
                    rejected_sender_user_ids: vec!["user:bob".into()],
                },
            })
            .expect("allowlist fetched");

        let replace = replaced
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::ReplaceAllowlist { update } => Some(update),
                _ => None,
            })
            .expect("replace allowlist effect");
        assert_eq!(replace.document.allowed_sender_user_ids, vec!["user:bob"]);
        assert!(replace.document.rejected_sender_user_ids.is_empty());
        assert!(engine.state.pending_allowlist_mutation.is_none());
    }

    #[test]
    fn allowlist_fetch_without_pending_mutation_returns_view_model() {
        let mut engine = CoreEngine::new();
        engine
            .handle_command(CoreCommand::ImportDeploymentBundle {
                bundle: sample_deployment(),
            })
            .expect("deployment");
        engine
            .handle_command(CoreCommand::CreateOrLoadIdentity {
                mnemonic: Some(ALICE_MNEMONIC.into()),
                device_name: Some("phone".into()),
            })
            .expect("identity");

        let output = engine
            .handle_event(CoreEvent::AllowlistFetched {
                document: crate::transport_contract::AllowlistDocument {
                    allowed_sender_user_ids: vec!["user:bob".into()],
                    rejected_sender_user_ids: vec![],
                },
            })
            .expect("allowlist fetched");

        assert_eq!(
            output
                .view_model
                .as_ref()
                .and_then(|view| view.allowlist.as_ref())
                .expect("allowlist view model")
                .allowed_sender_user_ids,
            vec!["user:bob"]
        );
        assert!(output.effects.is_empty());
    }

    fn seeded_engine(mnemonic: &str, device_name: &str, bundle: IdentityBundle) -> CoreEngine {
        let mut engine = CoreEngine::new();
        engine
            .handle_command(CoreCommand::ImportDeploymentBundle {
                bundle: sample_deployment(),
            })
            .expect("deployment");
        engine
            .handle_command(CoreCommand::CreateOrLoadIdentity {
                mnemonic: Some(mnemonic.into()),
                device_name: Some(device_name.into()),
            })
            .expect("identity");
        engine
            .handle_command(CoreCommand::ImportIdentityBundle { bundle })
            .expect("import");
        engine
    }

    fn create_direct_conversation(engine: &mut CoreEngine, peer_user_id: String) -> String {
        engine
            .handle_command(CoreCommand::CreateConversation {
                peer_user_id,
                conversation_kind: ConversationKind::Direct,
            })
            .expect("conversation")
            .view_model
            .unwrap()
            .conversations[0]
            .conversation_id
            .clone()
    }

    fn sample_identity_bundle(mnemonic: &str, device_name: &str) -> IdentityBundle {
        let identity = IdentityManager::create_or_recover(Some(mnemonic), Some(device_name))
            .expect("identity");
        let package = MlsAdapter::generate_key_package(&identity, 0).expect("package");
        IdentityManager::export_identity_bundle(
            &identity,
            &sample_deployment(),
            package.key_package_b64,
            package.expires_at,
        )
        .expect("bundle")
    }

    fn sample_identity_bundle_without_identity_ref(
        mnemonic: &str,
        device_name: &str,
    ) -> IdentityBundle {
        let identity = IdentityManager::create_or_recover(Some(mnemonic), Some(device_name))
            .expect("identity");
        let package = MlsAdapter::generate_key_package(&identity, 0).expect("package");
        let mut deployment = sample_deployment();
        deployment.runtime_config.identity_bundle_ref = None;

        IdentityManager::export_identity_bundle(
            &identity,
            &deployment,
            package.key_package_b64,
            package.expires_at,
        )
        .expect("bundle")
    }

    fn updated_bundle_json_for_user(user_id: &str, mut bundle: IdentityBundle) -> String {
        bundle.user_id = user_id.to_string();
        serde_json::to_string(&bundle).expect("bundle json")
    }

    fn sample_attachment_descriptor() -> AttachmentDescriptor {
        let path = unique_temp_path("attachment");
        std::fs::write(&path, [1_u8, 2, 3, 4]).expect("write attachment temp file");
        AttachmentDescriptor {
            attachment_id: path.to_string_lossy().to_string(),
            mime_type: "application/octet-stream".into(),
            size_bytes: 4,
            file_name: Some("file.bin".into()),
        }
    }

    fn sample_attachment_payload_metadata() -> AttachmentPayloadMetadata {
        AttachmentPayloadMetadata {
            mime_type: "application/octet-stream".into(),
            size_bytes: 4,
            file_name: Some("file.bin".into()),
            encryption: AttachmentCipherMetadata {
                algorithm: ATTACHMENT_CIPHER_ALGORITHM.into(),
                key_b64: STANDARD.encode([1_u8; 32]),
                nonce_b64: STANDARD.encode([2_u8; 12]),
            },
        }
    }

    fn sample_control_record(
        device_id: &str,
        seq: u64,
        local_user_id: &str,
        sender_user_id: &str,
        sender_device_id: &str,
    ) -> InboxRecord {
        sample_control_record_with_type(
            device_id,
            seq,
            local_user_id,
            sender_user_id,
            sender_device_id,
            MessageType::ControlIdentityStateUpdated,
        )
    }

    fn sample_control_record_with_type(
        device_id: &str,
        seq: u64,
        local_user_id: &str,
        sender_user_id: &str,
        sender_device_id: &str,
        message_type: MessageType,
    ) -> InboxRecord {
        let mut users = [local_user_id.to_string(), sender_user_id.to_string()];
        users.sort();
        InboxRecord {
            seq,
            recipient_device_id: device_id.into(),
            message_id: format!("msg:{seq}"),
            received_at: seq,
            expires_at: None,
            state: InboxRecordState::Available,
            envelope: Envelope {
                version: CURRENT_MODEL_VERSION.to_string(),
                message_id: format!("msg:{seq}"),
                conversation_id: format!("conv:{}:{}", users[0], users[1]),
                sender_user_id: sender_user_id.into(),
                sender_device_id: sender_device_id.into(),
                recipient_device_id: device_id.into(),
                created_at: seq,
                message_type,
                inline_ciphertext: Some("cipher".into()),
                storage_refs: vec![],
                delivery_class: DeliveryClass::Normal,
                wake_hint: Some(WakeHint {
                    latest_seq_hint: Some(seq),
                }),
                sender_proof: SenderProof {
                    proof_type: "signature".into(),
                    value: "proof".into(),
                },
            },
        }
    }

    fn find_http_request_id(output: &crate::ffi_api::CoreOutput, needle: &str) -> String {
        output
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::ExecuteHttpRequest { request } if request.url.contains(needle) => {
                    Some(request.request_id.clone())
                }
                _ => None,
            })
            .unwrap_or_else(|| panic!("expected request containing {needle}"))
    }

    fn extract_snapshot(output: &crate::ffi_api::CoreOutput) -> CorePersistenceSnapshot {
        output
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::PersistState { persist } => persist.snapshot.clone(),
                _ => None,
            })
            .expect("persist snapshot")
    }

    fn publish_shared_state_effects(
        output: &crate::ffi_api::CoreOutput,
    ) -> Vec<&crate::transport_contract::PublishSharedStateRequest> {
        output
            .effects
            .iter()
            .filter_map(|effect| match effect {
                CoreEffect::PublishSharedState { publish } => Some(publish),
                _ => None,
            })
            .collect()
    }

    fn sample_deployment() -> DeploymentBundle {
        DeploymentBundle {
            version: CURRENT_MODEL_VERSION.to_string(),
            region: "local".into(),
            inbox_http_endpoint: "https://example.com".into(),
            inbox_websocket_endpoint: "wss://example.com/ws".into(),
            storage_base_info: StorageBaseInfo {
                base_url: Some("https://storage.example.com".into()),
                bucket_hint: None,
            },
            runtime_config: crate::model::RuntimeConfig {
                supported_realtime_kinds: vec![crate::model::RealtimeKind::Websocket],
                identity_bundle_ref: Some(
                    "https://storage.example.com/state/user:alice/identity_bundle.json".into(),
                ),
                device_status_ref: Some(
                    "https://storage.example.com/state/user:alice/device_status.json".into(),
                ),
                keypackage_ref_base: Some("https://storage.example.com/keypackages".into()),
                max_inline_bytes: Some(4096),
                features: vec!["generic_sync".into()],
            },
            device_runtime_auth: Some(DeviceRuntimeAuth {
                scheme: "bearer".into(),
                token: "device-runtime-token".into(),
                expires_at: 999,
                user_id: "user:alice".into(),
                device_id: "device:alice:phone".into(),
                scopes: vec![
                    "inbox_read".into(),
                    "inbox_ack".into(),
                    "inbox_subscribe".into(),
                    "storage_prepare_upload".into(),
                ],
            }),
            expected_user_id: None,
            expected_device_id: None,
        }
    }

    fn unique_temp_path(prefix: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("tapchat-{prefix}-{nanos}.bin"))
    }
}

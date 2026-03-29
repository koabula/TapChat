#[cfg(test)]
mod tests {
    use crate::ffi_api::{
        AttachmentDescriptor, CoreCommand, CoreEffect, CoreEngine, CoreEvent, FfiApiModule,
        RealtimeEvent,
    };
    use crate::ffi_api::types::{RecoveryContext, RecoveryReason};
    use crate::identity::IdentityManager;
    use crate::mls_adapter::MlsAdapter;
    use crate::model::{
        ConversationKind, DeliveryClass, DeploymentBundle, Envelope, IdentityBundle, InboxRecord,
        InboxRecordState, MessageType, SenderProof, StorageBaseInfo, WakeHint,
        CURRENT_MODEL_VERSION,
    };
    use crate::persistence::{CorePersistenceSnapshot, PersistOp};

    const ALICE_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
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
            CoreEffect::ExecuteHttpRequest { request } if request.url.contains("/messages")
        )));
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
        let device_id = engine.state.local_identity.as_ref().unwrap().device_identity.device_id.clone();
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
                attachment_descriptor: AttachmentDescriptor {
                    source: "file.bin".into(),
                    mime_type: "application/octet-stream".into(),
                    size_bytes: 4,
                    file_name: Some("file.bin".into()),
                },
            })
            .expect("attachment");
        assert!(output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::UploadBlob { .. }
        )));
    }

    #[test]
    fn blob_uploaded_emits_append_request() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        let upload = alice
            .handle_command(CoreCommand::SendAttachmentMessage {
                conversation_id,
                attachment_descriptor: AttachmentDescriptor {
                    source: "file.bin".into(),
                    mime_type: "application/octet-stream".into(),
                    size_bytes: 4,
                    file_name: Some("file.bin".into()),
                },
            })
            .expect("attachment");
        let task_id = match upload.effects.iter().find_map(|effect| match effect {
            CoreEffect::UploadBlob { transfer } => Some(transfer.task_id.clone()),
            _ => None,
        }) {
            Some(task_id) => task_id,
            None => panic!("expected upload task"),
        };

        let output = alice
            .handle_event(CoreEvent::BlobUploaded {
                task_id,
                reference: "cid:blob".into(),
                sharing_url: Some("https://storage.example.com/blob".into()),
            })
            .expect("blob uploaded");

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
        let peer_user_id = engine.state.contacts.keys().next().expect("contact").clone();
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
        assert!(engine
            .state
            .conversations
            .contains_key(&expected_conversation_id));
        assert!(output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::ExecuteHttpRequest { request } if request.url.contains("/ack")
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
        let request_id = find_http_request_id(&output, "/identity_bundle.json");

        let updated_bundle = sample_identity_bundle(BOB_MNEMONIC, "laptop");
        let response = alice
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id,
                status: 200,
                body: Some(updated_bundle_json_for_user(&bob_bundle.user_id, updated_bundle)),
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
        assert!(persist
            .ops
            .iter()
            .any(|op| matches!(op, PersistOp::SaveOutgoingEnvelope { .. })));
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
        let peer_user_id = engine.state.contacts.keys().next().expect("contact").clone();
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
    fn identity_refresh_retries_then_marks_conversation_for_rebuild() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        alice.state.recovery_contexts.insert(
            conversation_id.clone(),
            RecoveryContext {
                conversation_id: conversation_id.clone(),
                reason: RecoveryReason::IdentityChanged,
                sync_attempted: true,
                identity_refresh_attempted: true,
                identity_refresh_retry_count: 0,
            },
        );

        for attempt in 0..crate::ffi_api::MAX_TRANSPORT_RETRIES {
            let refresh = alice
                .handle_command(CoreCommand::RefreshIdentityState {
                    user_id: bob_bundle.user_id.clone(),
                })
                .expect("refresh");
            let request_id = find_http_request_id(&refresh, "/identity_bundle.json");
            let output = alice
                .handle_event(CoreEvent::HttpRequestFailed {
                    request_id,
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
                assert!(output.state_update.system_statuses_changed.contains(
                    &crate::ffi_api::SystemStatus::ConversationNeedsRebuild
                ));
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
                assert!(!output.effects.iter().any(|effect| matches!(
                    effect,
                    CoreEffect::ScheduleTimer { .. }
                )));
            }
        }

        assert!(!engine
            .state
            .pending_blob_downloads
            .contains_key("blob-download:msg:download"));
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
        let identity = IdentityManager::create_or_recover(Some(mnemonic), Some(device_name)).expect("identity");
        let package = MlsAdapter::generate_key_package(&identity, 0).expect("package");
        IdentityManager::export_identity_bundle(
            &identity,
            &sample_deployment(),
            package.key_package_b64,
            package.expires_at,
        )
        .expect("bundle")
    }

    fn updated_bundle_json_for_user(user_id: &str, mut bundle: IdentityBundle) -> String {
        bundle.user_id = user_id.to_string();
        serde_json::to_string(&bundle).expect("bundle json")
    }

    fn sample_control_record(
        device_id: &str,
        seq: u64,
        local_user_id: &str,
        sender_user_id: &str,
        sender_device_id: &str,
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
                message_type: MessageType::ControlIdentityStateUpdated,
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
            runtime_config: crate::model::RuntimeConfig::default(),
            expected_user_id: None,
            expected_device_id: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::attachment_crypto::{
        ATTACHMENT_CHUNK_SIZE_BYTES, ATTACHMENT_CIPHER_ALGORITHM, AttachmentCipherMetadata,
        AttachmentPayloadMetadata, CHUNKED_ATTACHMENT_CIPHER_ALGORITHM,
    };
    use crate::conversation::RecoveryStatus;
    use crate::direct_pcs::{
        DIRECT_PCS_COMMIT_INTERVAL, DIRECT_PCS_DEBT_HARD, DirectCommitCertificate,
        DirectPcsHandshake, designated_committer, sign_certificate,
    };
    use crate::ffi_api::groups;
    use crate::ffi_api::types::{MAX_TRANSPORT_RETRIES, RecoveryContext, RecoveryReason};
    use crate::ffi_api::{
        AttachmentDescriptor, CoreCommand, CoreEffect, CoreEngine, CoreEvent, CoreOutput,
        FfiApiModule, PersistenceMutation, PersistenceValue, RealtimeEvent,
    };
    use crate::group_pcs::GROUP_PCS_COMMIT_INTERVAL;
    use crate::identity::IdentityManager;
    use crate::mls_adapter::{IngestResult, MlsAdapter};
    use crate::model::{
        CURRENT_MODEL_VERSION, CapabilityService, ConversationKind, ConversationState,
        DeliveryClass, DeploymentBundle, Envelope, GroupCapability, GroupCapabilityOperation,
        GroupEnvelope, GroupEnvelopeVisibility, GroupInviteDocument, GroupJoinRequest,
        GroupJoinRequestStatus, GroupManifest, GroupMemberStatus, GroupMembershipProof,
        GroupMessageType, GroupOutboxRecord, GroupOutboxRecordState, GroupRole, IdentityBundle,
        InboxRecord, InboxRecordState, MessageType, SenderProof, StorageBaseInfo, WakeHint,
        WelcomePickupDescriptor,
    };
    use crate::persistence::{
        ContactRelationshipStatus, CorePersistenceSnapshot, PersistOp,
        PersistedPendingWelcomePickup,
    };
    use crate::transport_contract::{
        GroupJoinDecision, MessageRequestAction, MessageRequestActionResult,
        SealGroupOutboxRequest, SealGroupOutboxResult, SharedStateDocumentKind,
        TransportAuthRequirement,
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use ed25519_dalek::Signer;
    use std::collections::{BTreeMap, BTreeSet};

    const ALICE_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const BOB_MNEMONIC: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";

    fn test_now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test clock")
            .as_millis() as u64
    }

    fn test_failure(code: &str, retryable: bool, status: Option<u16>) -> crate::AppErrorV1 {
        let mut failure = crate::AppErrorV1::from_registered_code(code);
        failure.retryable = retryable;
        failure.http_status = status;
        failure
    }
    const CAROL_MNEMONIC: &str =
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";
    const DANA_MNEMONIC: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";

    #[test]
    fn module_name_is_stable() {
        assert_eq!(FfiApiModule.name(), "ffi_api");
    }

    #[test]
    fn local_display_name_survives_deployment_import_and_restore() {
        let mut engine = CoreEngine::new();
        engine
            .handle_command(CoreCommand::CreateOrLoadIdentity {
                mnemonic: Some(ALICE_MNEMONIC.into()),
                device_name: Some("phone".into()),
                display_name: Some(" Alice ".into()),
            })
            .expect("identity");
        assert_eq!(engine.local_display_name().as_deref(), Some("Alice"));
        assert!(engine.local_bundle().is_none());

        engine
            .handle_command(CoreCommand::ImportDeploymentBundle {
                bundle: sample_deployment(),
            })
            .expect("deployment");
        assert_eq!(
            engine
                .local_bundle()
                .and_then(|bundle| bundle.display_name.as_deref()),
            Some("Alice")
        );
        let snapshot = engine.refresh_snapshot();
        assert_eq!(snapshot.local_display_name.as_deref(), Some("Alice"));

        let restored = CoreEngine::try_from_restored_state(snapshot).expect("restore snapshot");
        assert_eq!(restored.local_display_name().as_deref(), Some("Alice"));
        assert_eq!(
            restored
                .local_bundle()
                .and_then(|bundle| bundle.display_name.as_deref()),
            Some("Alice")
        );
    }

    #[test]
    fn set_local_display_name_updates_and_clears_persisted_identity_name() {
        let mut engine = local_engine(ALICE_MNEMONIC, "phone");
        let previous_updated_at = engine.local_bundle().expect("bundle").updated_at;

        let output = engine
            .handle_command(CoreCommand::SetLocalDisplayName {
                display_name: Some("Alice Prime".into()),
            })
            .expect("set display name");
        assert!(output.state_update.identity_changed);
        assert_eq!(
            output
                .view_model
                .as_ref()
                .and_then(|view| view.identity.as_ref())
                .and_then(|identity| identity.display_name.as_deref()),
            Some("Alice Prime")
        );
        assert_eq!(engine.local_display_name().as_deref(), Some("Alice Prime"));
        assert_eq!(
            engine
                .local_bundle()
                .and_then(|bundle| bundle.display_name.as_deref()),
            Some("Alice Prime")
        );
        assert!(
            engine.local_bundle().expect("bundle").updated_at > previous_updated_at,
            "display name update should advance bundle updated_at"
        );

        let restored = CoreEngine::try_from_restored_state(engine.refresh_snapshot())
            .expect("restore snapshot");
        assert_eq!(
            restored.local_display_name().as_deref(),
            Some("Alice Prime")
        );

        engine
            .handle_command(CoreCommand::SetLocalDisplayName { display_name: None })
            .expect("clear display name");
        assert_eq!(engine.local_display_name(), None);
        assert_eq!(
            engine
                .local_bundle()
                .and_then(|bundle| bundle.display_name.as_ref()),
            None
        );
    }

    #[test]
    fn rotate_share_link_preserves_local_display_name() {
        let mut engine = local_engine(ALICE_MNEMONIC, "phone");
        engine
            .handle_command(CoreCommand::SetLocalDisplayName {
                display_name: Some("Alice".into()),
            })
            .expect("set display name");

        engine
            .handle_command(CoreCommand::RotateContactShareLink)
            .expect("rotate share link");

        assert_eq!(engine.local_display_name().as_deref(), Some("Alice"));
        assert_eq!(
            engine
                .local_bundle()
                .and_then(|bundle| bundle.display_name.as_deref()),
            Some("Alice")
        );
    }

    #[test]
    fn share_rotation_commits_only_after_server_confirmation_and_survives_failure() {
        let mut engine = local_engine(ALICE_MNEMONIC, "phone");
        let previous_share_id = engine
            .local_bundle()
            .and_then(|bundle| bundle.bundle_share_id.clone())
            .expect("previous share id");
        let output = engine
            .handle_command(CoreCommand::RotateContactShareLink)
            .expect("stage share rotation");
        let publish = output
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::PublishSharedState { publish }
                    if publish.document_kind == SharedStateDocumentKind::IdentityBundle =>
                {
                    Some(publish.clone())
                }
                _ => None,
            })
            .expect("candidate publish effect");
        let candidate: IdentityBundle =
            serde_json::from_str(&publish.body).expect("candidate bundle");
        assert_ne!(candidate.bundle_share_id.as_ref(), Some(&previous_share_id));
        assert_eq!(
            engine
                .local_bundle()
                .and_then(|bundle| bundle.bundle_share_id.as_ref()),
            Some(&previous_share_id)
        );
        assert!(engine.has_pending_share_rotation());

        engine
            .handle_event(CoreEvent::SharedStatePublishFailed {
                operation_id: publish.operation_id.clone(),
                document_kind: SharedStateDocumentKind::IdentityBundle,
                reference: publish.reference.clone(),
                failure: crate::error::AppErrorV1::new(
                    "network_unavailable",
                    crate::error::ErrorDomain::Transport,
                    true,
                ),
                current_bundle: None,
                etag: None,
            })
            .expect("record failed publication");
        let restored = CoreEngine::try_from_restored_state(engine.refresh_snapshot())
            .expect("restore pending publication");
        assert!(restored.has_pending_share_rotation());

        engine
            .handle_event(CoreEvent::SharedStatePublished {
                operation_id: publish.operation_id,
                document_kind: SharedStateDocumentKind::IdentityBundle,
                reference: publish.reference,
                etag: Some("\"candidate\"".into()),
                saved_bundle: Some(candidate.clone()),
            })
            .expect("confirm publication");
        assert!(!engine.has_pending_share_rotation());
        assert_eq!(
            engine
                .local_bundle()
                .and_then(|bundle| bundle.bundle_share_id.as_ref()),
            candidate.bundle_share_id.as_ref()
        );
    }

    #[test]
    fn share_rotation_reconciles_a_lost_put_response_from_authoritative_state() {
        let mut engine = local_engine(ALICE_MNEMONIC, "phone");
        let output = engine
            .handle_command(CoreCommand::RotateContactShareLink)
            .expect("stage share rotation");
        let publish = output
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::PublishSharedState { publish }
                    if publish.document_kind == SharedStateDocumentKind::IdentityBundle =>
                {
                    Some(publish.clone())
                }
                _ => None,
            })
            .expect("candidate publish effect");
        let candidate: IdentityBundle =
            serde_json::from_str(&publish.body).expect("candidate bundle");
        let operation_id = publish.operation_id.clone().expect("operation id");

        let reconciled = engine
            .handle_event(CoreEvent::SharedStatePublishFailed {
                operation_id: Some(operation_id.clone()),
                document_kind: SharedStateDocumentKind::IdentityBundle,
                reference: publish.reference,
                failure: test_failure("identity_bundle_conflict", false, Some(412)),
                current_bundle: Some(candidate.clone()),
                etag: Some("\"committed\"".into()),
            })
            .expect("reconcile committed publication");

        let result = reconciled
            .view_model
            .expect("operation result")
            .operation_results
            .into_iter()
            .find(|result| result.operation_id == operation_id)
            .expect("matching operation result");
        assert_eq!(
            result.status,
            crate::ffi_api::CoreOperationStatus::Confirmed
        );
        assert!(result.failure.is_none());
        assert!(!engine.has_pending_share_rotation());
        assert_eq!(
            engine
                .local_bundle()
                .and_then(|bundle| bundle.bundle_share_id.as_ref()),
            candidate.bundle_share_id.as_ref()
        );
    }

    #[test]
    fn append_request_includes_sender_display_name() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = local_engine(ALICE_MNEMONIC, "phone");
        alice
            .handle_command(CoreCommand::SetLocalDisplayName {
                display_name: Some("Alice".into()),
            })
            .expect("set display name");
        alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: bob_bundle.clone(),
            })
            .expect("import bob");
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id);

        let output = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "hello".into(),
            })
            .expect("send text");

        let append_body = output.effects.iter().find_map(|effect| match effect {
            CoreEffect::ExecuteHttpRequest { request }
                if request.method == crate::ffi_api::HttpMethod::Post =>
            {
                request.body.as_deref()
            }
            _ => None,
        });
        let body = append_body.expect("append request body");
        let request: crate::transport_contract::AppendEnvelopeRequest =
            serde_json::from_str(body).expect("append request json");
        assert_eq!(request.sender_display_name.as_deref(), Some("Alice"));
    }

    #[test]
    fn direct_send_characterization_keeps_snapshot_output_and_effect_order_stable() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = local_engine(ALICE_MNEMONIC, "phone");
        alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: bob_bundle.clone(),
            })
            .expect("import bob");
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id);
        let pending_before_send = alice.state.pending_outbox.len();

        let output = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "characterization".into(),
            })
            .expect("send text");

        assert_eq!(
            output
                .effects
                .iter()
                .map(|effect| match effect {
                    CoreEffect::PersistState { .. } => "persist_state",
                    CoreEffect::ExecuteHttpRequest { .. } => "execute_http_request",
                    _ => "unexpected",
                })
                .collect::<Vec<_>>(),
            vec!["persist_state", "execute_http_request"]
        );
        assert!(output.state_update.messages_changed);
        assert_eq!(
            output
                .view_model
                .as_ref()
                .expect("view model")
                .messages
                .len(),
            1
        );

        let persisted = alice.refresh_snapshot();
        assert_eq!(persisted.pending_outbox.len(), pending_before_send + 1);
        assert_eq!(
            persisted
                .pending_outbox
                .last()
                .expect("new pending envelope")
                .plaintext_cache
                .as_deref(),
            Some("characterization")
        );
        assert_eq!(persisted.pending_outbox.last().expect("pending").retries, 0);
        assert!(
            alice
                .state
                .pending_outbox
                .last()
                .expect("pending")
                .in_flight
        );
        assert_eq!(
            alice.state.pending_outbox.last().expect("pending").retries,
            0
        );

        let restored =
            CoreEngine::try_from_restored_state(persisted).expect("restore persisted send");
        assert_eq!(restored.state.pending_outbox.len(), pending_before_send + 1);
        assert!(
            !restored
                .state
                .pending_outbox
                .last()
                .expect("restored pending")
                .in_flight
        );

        let before_invalid = alice.refresh_snapshot();
        let error = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id,
                plaintext: "   ".into(),
            })
            .expect_err("blank text must fail");
        assert_eq!(error.code(), "invalid_input");
        assert_eq!(alice.refresh_snapshot(), before_invalid);
    }

    #[test]
    fn identity_bundle_verification_accepts_legacy_display_name_signature() {
        let identity = IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone"))
            .expect("identity");
        let deployment = sample_deployment();
        let package =
            MlsAdapter::generate_key_package(&identity, test_now_ms()).expect("key package");
        let mut bundle = IdentityManager::export_identity_bundle(
            &identity,
            &deployment,
            package.key_package_ref,
            package.expires_at,
        )
        .expect("bundle");
        bundle.publication_version = 0;
        bundle.publication_revision = 0;
        bundle.display_name = Some("Alice".into());
        bundle.signature = String::new();
        let signature = identity
            .user_root_signing_key()
            .sign(crate::identity::legacy_identity_bundle_payload(&bundle).as_bytes());
        bundle.signature = crate::identity::encode_hex(&signature.to_bytes());

        IdentityManager::verify_identity_bundle(&bundle).expect("legacy bundle verifies");
    }

    #[test]
    fn group_core_commands_round_trip_json() {
        let commands = vec![
            CoreCommand::CreateGroupConversation {
                title: "Project".into(),
                member_user_ids: vec!["user:bob".into()],
            },
            CoreCommand::SyncGroupOutbox {
                group_id: "group:project".into(),
                reason: Some("manual".into()),
            },
            CoreCommand::SendGroupTextMessage {
                conversation_id: "conv:group:project".into(),
                plaintext: "hello group".into(),
            },
            CoreCommand::InviteToGroup {
                group_id: "group:project".into(),
                invitee_user_ids: vec!["user:eve".into()],
            },
            CoreCommand::LeaveGroup {
                group_id: "group:project".into(),
            },
            CoreCommand::RemoveGroupMember {
                group_id: "group:project".into(),
                target_user_id: "user:eve".into(),
            },
        ];

        for command in commands {
            let json = serde_json::to_string(&command).expect("serialize command");
            assert!(json.contains("group"));
            let decoded: CoreCommand = serde_json::from_str(&json).expect("deserialize command");
            assert_eq!(decoded, command);
        }
    }

    #[test]
    fn shared_group_protocol_fixture_matches_wire_hash_payload_and_role_matrix() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../test-fixtures/group-protocol-v1.json"))
                .expect("group protocol fixture");
        let manifest: GroupManifest =
            serde_json::from_value(fixture["manifest"].clone()).expect("manifest fixture");
        let proof: GroupMembershipProof =
            serde_json::from_value(fixture["membershipProof"].clone())
                .expect("membership proof fixture");

        assert_eq!(
            CoreEngine::manifest_sha256(&manifest).expect("manifest hash"),
            fixture["expected"]["manifestSha256"]
                .as_str()
                .expect("expected hash")
        );
        assert_eq!(
            String::from_utf8(CoreEngine::membership_proof_payload(&proof))
                .expect("membership payload utf8"),
            fixture["expected"]["membershipProofPayload"]
                .as_str()
                .expect("expected payload")
        );
        let encoded = serde_json::to_value(&manifest).expect("manifest json");
        assert!(encoded.get("groupId").is_some());
        assert!(encoded.get("group_id").is_none());

        for (role, key) in [
            (GroupRole::Owner, "owner"),
            (GroupRole::Admin, "admin"),
            (GroupRole::Member, "member"),
        ] {
            let expected: Vec<GroupCapabilityOperation> =
                serde_json::from_value(fixture["roleOperations"][key].clone())
                    .expect("role operations fixture");
            assert_eq!(groups::test_group_capability_operations(role), expected);
        }
    }

    #[test]
    fn retry_pending_welcome_pickups_command_round_trips_json() {
        let command = CoreCommand::RetryPendingWelcomePickups;
        let json = serde_json::to_string(&command).expect("serialize command");
        let decoded: CoreCommand = serde_json::from_str(&json).expect("deserialize command");
        assert_eq!(decoded, command);
    }

    #[test]
    fn retry_pending_welcome_pickups_reissues_staged_fetch() {
        let mut engine = CoreEngine::new();
        let descriptor = WelcomePickupDescriptor {
            group_id: "group:pending".into(),
            device_id: "device:alice:phone".into(),
            endpoint: "https://example.test/welcome".into(),
            capability: "cap".into(),
            expires_at: 999,
            start_seq: None,
            roster_version: None,
            last_commit_message_id: None,
            request_id: None,
        };
        engine.state.pending_welcome_pickups.insert(
            "group:pending::device:alice:phone".into(),
            PersistedPendingWelcomePickup {
                group_id: descriptor.group_id.clone(),
                device_id: descriptor.device_id.clone(),
                descriptor: descriptor.clone(),
                title: Some("Pending".into()),
                inviter_user_id: Some("user:bob".into()),
                retries: 0,
                last_error: None,
            },
        );

        let output = engine
            .handle_command(CoreCommand::RetryPendingWelcomePickups)
            .expect("retry pending welcome pickups");

        assert!(output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::FetchWelcomePickup { fetch } if fetch.descriptor == descriptor
        )));
    }

    #[test]
    fn welcome_pickup_fetch_failure_keeps_pending_for_retry() {
        let mut engine = CoreEngine::new();
        let descriptor = WelcomePickupDescriptor {
            group_id: "group:pending".into(),
            device_id: "device:alice:phone".into(),
            endpoint: "https://example.test/welcome".into(),
            capability: "cap".into(),
            expires_at: 999,
            start_seq: None,
            roster_version: None,
            last_commit_message_id: None,
            request_id: None,
        };
        let key = "group:pending::device:alice:phone".to_string();
        engine.state.pending_welcome_pickups.insert(
            key.clone(),
            PersistedPendingWelcomePickup {
                group_id: descriptor.group_id.clone(),
                device_id: descriptor.device_id.clone(),
                descriptor: descriptor.clone(),
                title: Some("Pending".into()),
                inviter_user_id: Some("user:bob".into()),
                retries: 0,
                last_error: None,
            },
        );

        let output = engine
            .handle_event(CoreEvent::WelcomePickupFetchFailed {
                descriptor,
                failure: test_failure("request_timeout", true, None),
            })
            .expect("welcome pickup failure");

        let pending = engine
            .state
            .pending_welcome_pickups
            .get(&key)
            .expect("pending welcome pickup remains");
        assert_eq!(pending.retries, 1);
        assert_eq!(pending.last_error.as_deref(), Some("request_timeout"));
        assert!(output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::ScheduleTimer { timer }
                if timer.timer_id == format!("retry_welcome_pickup:{key}")
        )));
        assert!(output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::PersistState { persist }
                if persist.ops.iter().any(|op| matches!(
                    op,
                    PersistOp::SavePendingWelcomePickup { group_id, device_id }
                        if group_id == "group:pending" && device_id == "device:alice:phone"
                ))
        )));
    }

    #[test]
    fn core_command_dissolve_group_serializes() {
        // `CoreCommand::DissolveGroup` is the owner-only atomic dissolve
        // primitive defined in PLAN_GROUP Phase 6 (task A.2). The snake_case
        // `type` tag and `group_id` field must round-trip exactly so the
        // Tauri command layer and the CLI produce identical JSON for the
        // same user action.
        let command = CoreCommand::DissolveGroup {
            group_id: "group:project".into(),
        };

        let json = serde_json::to_string(&command).expect("serialize DissolveGroup");
        assert!(
            json.contains("\"type\":\"dissolve_group\""),
            "DissolveGroup must serialise type tag as 'dissolve_group'; got {json}"
        );
        assert!(
            json.contains("\"group_id\":\"group:project\""),
            "DissolveGroup must serialise group_id in snake_case; got {json}"
        );

        let decoded: CoreCommand = serde_json::from_str(&json).expect("deserialize DissolveGroup");
        assert_eq!(decoded, command);
    }

    #[test]
    fn core_event_group_outbox_sealed_variants_serialize() {
        // Both `GroupOutboxSealed` and `GroupOutboxSealFailed` are emitted by
        // the owner driver (`seal_group_outbox`) after A.4's dissolve
        // sequence schedules `CoreEffect::SealGroupOutbox`. Their JSON
        // contract is stable so that C.3's driver and G.4's desktop e2e
        // observe the same bytes on the wire.
        let sealed = CoreEvent::GroupOutboxSealed {
            group_id: "group:project".into(),
            sealed_at: 1_700_000_000_000,
            was_already_sealed: false,
        };
        let sealed_repeat = CoreEvent::GroupOutboxSealed {
            group_id: "group:project".into(),
            sealed_at: 1_700_000_000_500,
            was_already_sealed: true,
        };
        let failed = CoreEvent::GroupOutboxSealFailed {
            group_id: "group:project".into(),
            failure: test_failure("invalid_capability", false, Some(403)),
        };

        let sealed_json = serde_json::to_string(&sealed).expect("serialize sealed");
        assert!(
            sealed_json.contains("\"type\":\"group_outbox_sealed\""),
            "GroupOutboxSealed must tag as group_outbox_sealed; got {sealed_json}"
        );
        // When `was_already_sealed == false` the field should be omitted to
        // keep the wire payload compact and tolerate older decoders.
        assert!(
            !sealed_json.contains("was_already_sealed"),
            "was_already_sealed must be omitted when false; got {sealed_json}"
        );
        let decoded_sealed: CoreEvent =
            serde_json::from_str(&sealed_json).expect("deserialize sealed");
        assert_eq!(decoded_sealed, sealed);

        let repeat_json = serde_json::to_string(&sealed_repeat).expect("serialize repeat");
        assert!(
            repeat_json.contains("\"was_already_sealed\":true"),
            "was_already_sealed must be emitted when true; got {repeat_json}"
        );
        let decoded_repeat: CoreEvent =
            serde_json::from_str(&repeat_json).expect("deserialize repeat");
        assert_eq!(decoded_repeat, sealed_repeat);

        let failed_json = serde_json::to_string(&failed).expect("serialize failed");
        assert!(
            failed_json.contains("\"type\":\"group_outbox_seal_failed\""),
            "GroupOutboxSealFailed must tag as group_outbox_seal_failed; got {failed_json}"
        );
        assert!(
            failed_json.contains("\"retryable\":false"),
            "retryable field must round-trip; got {failed_json}"
        );
        let decoded_failed: CoreEvent =
            serde_json::from_str(&failed_json).expect("deserialize failed");
        assert_eq!(decoded_failed, failed);

        // Ensure `SealGroupOutboxRequest` / `SealGroupOutboxResult` remain
        // accessible from this module so downstream tests can build effect
        // fixtures in subsequent waves (A.4 and beyond).
        let _ = SealGroupOutboxRequest {
            group_id: "group:project".into(),
            capability: crate::model::GroupCapability {
                version: crate::model::CURRENT_MODEL_VERSION.to_string(),
                service: crate::model::CapabilityService::GroupOutbox,
                group_id: "group:project".into(),
                user_id: "user:alice".into(),
                device_id: "device:alice:phone".into(),
                operations: vec![GroupCapabilityOperation::SealGroup],
                role: GroupRole::Owner,
                expires_at: 999,
                signature: "sig".into(),
            },
        };
        let _ = SealGroupOutboxResult {
            sealed_at: 1,
            was_already_sealed: true,
        };
    }

    #[test]
    fn group_membership_workflow_commands_are_implemented() {
        let commands: Vec<CoreCommand> = vec![
            CoreCommand::InviteToGroup {
                group_id: "group:project".into(),
                invitee_user_ids: vec!["user:eve".into()],
            },
            CoreCommand::LeaveGroup {
                group_id: "group:project".into(),
            },
            CoreCommand::RemoveGroupMember {
                group_id: "group:project".into(),
                target_user_id: "user:eve".into(),
            },
            CoreCommand::TransferGroupOwnership {
                group_id: "group:project".into(),
                new_owner_user_id: "user:bob".into(),
            },
        ];

        let mut engine = CoreEngine::new();
        for command in commands {
            let error = engine
                .handle_command(command)
                .expect_err("membership workflow command without setup should fail");
            assert!(
                error.code() != "unsupported",
                "command should be implemented, got unsupported for {error:?}"
            );
        }
    }

    #[test]
    fn group_capability_operations_match_role_matrix() {
        let admin_privileged = vec![
            GroupCapabilityOperation::Read,
            GroupCapabilityOperation::Subscribe,
            GroupCapabilityOperation::AppendApplication,
            GroupCapabilityOperation::AppendControl,
            GroupCapabilityOperation::AppendMembership,
            GroupCapabilityOperation::ManageInvites,
            GroupCapabilityOperation::ApproveJoin,
            GroupCapabilityOperation::RemoveMember,
            GroupCapabilityOperation::UpdateGroupMetadata,
        ];
        // Owners get every admin operation plus `SealGroup`, which per
        // PROTOCOL_GROUP_CN.md §10.4 is owner-exclusive (Cloudflare rejects
        // any seal request signed by a non-owner capability).
        let mut owner_privileged = admin_privileged.clone();
        owner_privileged.push(GroupCapabilityOperation::SealGroup);
        let member = vec![
            GroupCapabilityOperation::Read,
            GroupCapabilityOperation::Subscribe,
            GroupCapabilityOperation::AppendApplication,
            GroupCapabilityOperation::AppendControl,
        ];

        assert_eq!(
            groups::test_group_capability_operations(GroupRole::Owner),
            owner_privileged
        );
        assert_eq!(
            groups::test_group_capability_operations(GroupRole::Admin),
            admin_privileged
        );
        assert_eq!(
            groups::test_group_capability_operations(GroupRole::Member),
            member
        );
    }

    #[test]
    fn create_group_conversation_generates_real_group_effects() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let carol_bundle = sample_identity_bundle(CAROL_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: carol_bundle.clone(),
            })
            .expect("import carol");

        let output = alice
            .handle_command(CoreCommand::CreateGroupConversation {
                title: "Project".into(),
                member_user_ids: vec![bob_bundle.user_id.clone(), carol_bundle.user_id.clone()],
            })
            .expect("create group");
            let output = simulate_pending_key_package_claims(&mut alice, output);

        let summary = output
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .expect("group summary");
        assert_eq!(summary.kind, Some(ConversationKind::Group));
        assert_eq!(summary.title.as_deref(), Some("Project"));
        assert_eq!(
            summary.member_count,
            Some(1),
            "provisional genesis exposes only the owner before transition ACK"
        );
        assert!(
            output
                .effects
                .iter()
                .any(|effect| matches!(effect, CoreEffect::InitializeGroupAuthorization { .. }))
        );
        let transition_output = alice
            .handle_event(CoreEvent::GroupAuthorizationInitialized {
                group_id: summary.group_id.clone().expect("group id"),
                roster_version: 0,
            })
            .expect("bootstrap ack");
        assert!(transition_output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::AppendGroupTransition { append }
                if append.envelopes.iter().any(|envelope|
                    envelope.message_type == crate::model::GroupMessageType::MlsCommit)
        )));
        let owner_operations = transition_output
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::AppendGroupTransition { append } => {
                    Some(append.capability.operations.clone())
                }
                _ => None,
            })
            .expect("group append capability");
        assert_eq!(
            owner_operations,
            vec![
                GroupCapabilityOperation::Read,
                GroupCapabilityOperation::Subscribe,
                GroupCapabilityOperation::AppendApplication,
                GroupCapabilityOperation::AppendControl,
                GroupCapabilityOperation::AppendMembership,
                GroupCapabilityOperation::ManageInvites,
                GroupCapabilityOperation::ApproveJoin,
                GroupCapabilityOperation::RemoveMember,
                GroupCapabilityOperation::UpdateGroupMetadata,
                GroupCapabilityOperation::SealGroup,
            ]
        );
        assert_eq!(
            output
                .effects
                .iter()
                .filter(|effect| matches!(effect, CoreEffect::PutWelcomePickup { .. }))
                .count(),
            0,
            "welcomes must not publish until the atomic transition is acknowledged"
        );
        let transition_ack = acknowledge_pending_group_transition(
            &mut alice,
            &summary.group_id.clone().expect("group id"),
        );
        assert_eq!(
            alice.state.group_states[summary.group_id.as_deref().expect("group id")]
                .manifest
                .members
                .iter()
                .filter(|member| member.status == GroupMemberStatus::Active)
                .count(),
            3
        );
        assert_eq!(
            transition_ack
                .effects
                .iter()
                .filter(|effect| matches!(effect, CoreEffect::PutWelcomePickup { .. }))
                .count(),
            2
        );
        assert_eq!(
            alice
                .state
                .pending_outbox
                .iter()
                .filter(|item| item.envelope.message_type == MessageType::ControlGroupWelcomePickup)
                .count(),
            2
        );
    }

    #[test]
    fn group_creation_fails_closed_without_group_authorization_v2() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        alice
            .state
            .deployment_bundle
            .as_mut()
            .expect("deployment")
            .runtime_config
            .features
            .retain(|feature| feature != "group_authorization_v2");

        let error = alice
            .handle_command(CoreCommand::CreateGroupConversation {
                title: "Blocked".into(),
                member_user_ids: vec![bob_bundle.user_id],
            })
            .expect_err("legacy runtime must not create a group");
        assert_eq!(error.code(), "invalid_state");
        assert!(error.message().contains("group_authorization_v2"));
        assert!(alice.state.group_states.is_empty());
    }

    #[test]
    fn transition_conflict_preserves_intent_for_reconciliation() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let output = alice
            .handle_command(CoreCommand::CreateGroupConversation {
                title: "Conflict".into(),
                member_user_ids: vec![bob_bundle.user_id],
            })
            .expect("create group");
            let output = simulate_pending_key_package_claims(&mut alice, output);
        let group_id = output
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .and_then(|summary| summary.group_id.clone())
            .expect("group id");
        let roster = alice.state.group_states[&group_id].manifest.roster_version;
        alice
            .handle_event(CoreEvent::GroupAuthorizationInitialized {
                group_id: group_id.clone(),
                roster_version: roster,
            })
            .expect("bootstrap ack");
        let transition_id = alice.state.group_states[&group_id]
            .pending_group_transition
            .as_ref()
            .expect("pending transition")
            .transition_id
            .clone();
        alice
            .handle_event(CoreEvent::GroupTransitionAppendFailed {
                group_id: group_id.clone(),
                transition_id,
                failure: test_failure("group_transition_conflict", false, Some(409)),
            })
            .expect("conflict enters reconciliation");
        let state = &alice.state.group_states[&group_id];
        assert_eq!(
            state.consistency_state,
            crate::persistence::GroupConsistencyState::Reconciling
        );
        let pending = state
            .pending_group_transition
            .as_ref()
            .expect("intent must be preserved");
        assert_eq!(
            pending.stage,
            crate::persistence::PendingGroupTransitionStage::ReconcilingAfterConflict
        );
        assert!(matches!(
            pending.intent.operation(),
            Some(crate::model::GroupTransitionOperation::Create)
        ));
    }

    #[test]
    fn leave_request_does_not_mutate_canonical_membership() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let output = alice
            .handle_command(CoreCommand::CreateGroupConversation {
                title: "Leave".into(),
                member_user_ids: vec![bob_bundle.user_id.clone()],
            })
            .expect("create group");
            let output = simulate_pending_key_package_claims(&mut alice, output);
        let group_id = output
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .and_then(|summary| summary.group_id.clone())
            .expect("group id");
        acknowledge_pending_group_transition(&mut alice, &group_id);
        let local_user_id = alice
            .state
            .local_identity
            .as_ref()
            .expect("local identity")
            .user_identity
            .user_id
            .clone();
        let state = alice.state.group_states.get_mut(&group_id).expect("group");
        state.local_role = Some(GroupRole::Member);
        state.manifest.owner_user_id = bob_bundle.user_id;
        for member in &mut state.manifest.members {
            member.role = if member.user_id == local_user_id {
                GroupRole::Member
            } else {
                GroupRole::Owner
            };
        }
        let before = alice.state.group_states[&group_id].manifest.clone();
        let leave = alice
            .handle_command(CoreCommand::LeaveGroup {
                group_id: group_id.clone(),
            })
            .expect("submit leave request");
        assert!(
            leave
                .effects
                .iter()
                .any(|effect| matches!(effect, CoreEffect::SubmitGroupLeaveRequest { .. }))
        );
        assert_eq!(alice.state.group_states[&group_id].manifest, before);
        assert_eq!(
            alice.state.group_states[&group_id].local_role,
            Some(GroupRole::Member)
        );
    }

    #[test]
    fn removed_local_role_cannot_restore_or_send_group_outbox() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let output = alice
            .handle_command(CoreCommand::CreateGroupConversation {
                title: "Project".into(),
                member_user_ids: vec![bob_bundle.user_id.clone()],
            })
            .expect("create group");
            let output = simulate_pending_key_package_claims(&mut alice, output);
        let summary = output
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .expect("group summary");
        let group_id = summary.group_id.clone().expect("group id");
        let conversation_id = summary.conversation_id.clone();
        acknowledge_pending_group_transition(&mut alice, &group_id);

        let group_state = alice
            .state
            .group_states
            .get_mut(&group_id)
            .expect("group state");
        group_state.local_role = None;
        let send_error = alice
            .handle_command(CoreCommand::SendGroupTextMessage {
                conversation_id,
                plaintext: "after removal".into(),
            })
            .expect_err("removed local member cannot send");
        assert_eq!(send_error.code(), "invalid_input");

        let mut snapshot = alice.refresh_snapshot();
        for group_state in &mut snapshot.group_states {
            group_state.local_role = None;
        }
        for item in &mut snapshot.pending_group_outbox {
            item.capability = None;
        }
        let restored = CoreEngine::try_from_restored_state(snapshot).expect("restore snapshot");
        assert!(
            restored.state.pending_group_outbox.is_empty(),
            "pending group sends without a local role must not regain member capability"
        );
    }

    #[test]
    fn capability_expired_resigns_and_retries_group_append() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let created = alice
            .handle_command(CoreCommand::CreateGroupConversation {
                title: "Project".into(),
                member_user_ids: vec![bob_bundle.user_id],
            })
            .expect("create group");
            let created = simulate_pending_key_package_claims(&mut alice, created);
        let summary = created
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .expect("group summary");
        let group_id = summary.group_id.clone().expect("group id");
        let conversation_id = summary.conversation_id.clone();
        acknowledge_pending_group_transition(&mut alice, &group_id);

        let sent = alice
            .handle_command(CoreCommand::SendGroupTextMessage {
                conversation_id,
                plaintext: "retry me".into(),
            })
            .expect("send group text");
        let (message_id, initial_expiry) = sent
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::AppendGroupEnvelope { append } => Some((
                    append.envelope.message_id.clone(),
                    append.capability.expires_at,
                )),
                _ => None,
            })
            .expect("initial group append");
        let failed = alice
            .handle_event(CoreEvent::GroupEnvelopeAppendFailed {
                group_id: group_id.clone(),
                message_id: message_id.clone(),
                failure: test_failure("capability_expired", true, Some(403)),
            })
            .expect("expired capability is retryable");
        assert!(failed.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::ScheduleTimer { timer }
                if timer.timer_id == format!("retry_group_append:{message_id}")
        )));

        let retried = alice
            .handle_event(CoreEvent::TimerTriggered {
                timer_id: format!("retry_group_append:{message_id}"),
            })
            .expect("retry group append");
        assert!(retried.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::AppendGroupEnvelope { append }
                if append.envelope.message_id == message_id
                    && append.capability.expires_at >= initial_expiry
        )));
    }

    #[test]
    fn membership_revoked_clears_every_pending_group_send() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let created = alice
            .handle_command(CoreCommand::CreateGroupConversation {
                title: "Project".into(),
                member_user_ids: vec![bob_bundle.user_id],
            })
            .expect("create group");
            let created = simulate_pending_key_package_claims(&mut alice, created);
        let summary = created
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .expect("group summary");
        let group_id = summary.group_id.clone().expect("group id");
        let conversation_id = summary.conversation_id.clone();
        acknowledge_pending_group_transition(&mut alice, &group_id);
        for plaintext in ["first pending", "second pending"] {
            alice
                .handle_command(CoreCommand::SendGroupTextMessage {
                    conversation_id: conversation_id.clone(),
                    plaintext: plaintext.into(),
                })
                .expect("send group text");
        }
        let pending_ids: Vec<String> = alice
            .state
            .pending_group_outbox
            .iter()
            .filter(|item| item.envelope.group_id == group_id)
            .map(|item| item.envelope.message_id.clone())
            .collect();
        assert_eq!(pending_ids.len(), 2);

        let revoked = alice
            .handle_event(CoreEvent::GroupEnvelopeAppendFailed {
                group_id: group_id.clone(),
                message_id: pending_ids[0].clone(),
                failure: test_failure("group_membership_revoked", false, Some(403)),
            })
            .expect("membership revoked is terminal");

        assert!(
            !alice
                .state
                .pending_group_outbox
                .iter()
                .any(|item| item.envelope.group_id == group_id)
        );
        assert_eq!(alice.state.group_states[&group_id].local_role, None);
        assert_eq!(
            alice.state.conversations[&conversation_id]
                .conversation
                .state,
            crate::model::ConversationState::Closed
        );
        let deleted: BTreeSet<String> = persist_ops(&revoked)
            .into_iter()
            .filter_map(|op| match op {
                PersistOp::DeleteOutgoingGroupEnvelope { message_id } => Some(message_id),
                _ => None,
            })
            .collect();
        assert_eq!(deleted, pending_ids.into_iter().collect());
    }

    #[test]
    fn dissolve_group_requires_owner_role() {
        // Dissolve is owner-only per PROTOCOL_GROUP_CN §10.4 and R12.1.
        // A freshly-joined member trying to dissolve must hit the core's
        // authoritative role check and produce no side-effects.
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let output = alice
            .handle_command(CoreCommand::CreateGroupConversation {
                title: "Project".into(),
                member_user_ids: vec![bob_bundle.user_id.clone()],
            })
            .expect("create group");
            let output = simulate_pending_key_package_claims(&mut alice, output);
        let summary = output
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .expect("group summary");
        let group_id = summary.group_id.clone().expect("group id");
        acknowledge_pending_group_transition(&mut alice, &group_id);

        // Simulate alice losing ownership by demoting her local role to
        // Member — the core's `local_group_role` gate must refuse Dissolve
        // regardless of manifest state on the wire.
        let group_state = alice
            .state
            .group_states
            .get_mut(&group_id)
            .expect("group state");
        group_state.local_role = Some(GroupRole::Member);

        let initial_pending = alice.state.pending_group_outbox.len();
        let initial_seal = alice.state.pending_group_seal.len();

        let error = alice
            .handle_command(CoreCommand::DissolveGroup {
                group_id: group_id.clone(),
            })
            .expect_err("non-owner cannot dissolve");
        assert_eq!(error.code(), "invalid_input");

        // No commit envelope, no seal, no dissolved_at.
        assert_eq!(alice.state.pending_group_outbox.len(), initial_pending);
        assert_eq!(alice.state.pending_group_seal.len(), initial_seal);
        assert!(
            alice
                .state
                .group_states
                .get(&group_id)
                .expect("group still exists")
                .dissolved_at
                .is_none(),
            "a refused dissolve must not set dissolved_at"
        );
    }

    #[test]
    fn dissolve_group_emits_remove_commit_then_dissolved_control_then_seal_effect() {
        // Success path invariant for step (a)+(b)+(c) ordering:
        //   - A single MLS remove_members commit enqueued first.
        //   - A `ControlGroupDissolved` envelope enqueued second, with
        //     `visibility = Visible`.
        //   - No `SealGroupOutbox` effect yet — seal is strictly deferred
        //     until every pending outbox append for this group is
        //     acknowledged (handled by `handle_group_envelope_appended`).
        //   - `pending_group_seal` contains the staged request so the seal
        //     effect will be issued after acks arrive.
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let carol_bundle = sample_identity_bundle(CAROL_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: carol_bundle.clone(),
            })
            .expect("import carol");
        let created = alice
            .handle_command(CoreCommand::CreateGroupConversation {
                title: "Project".into(),
                member_user_ids: vec![bob_bundle.user_id.clone(), carol_bundle.user_id.clone()],
            })
            .expect("create group");
            let created = simulate_pending_key_package_claims(&mut alice, created);
        let group_id = created
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .and_then(|summary| summary.group_id.clone())
            .expect("group id");
        acknowledge_pending_group_transition(&mut alice, &group_id);

        // Drain the initial-create commit from the pending queue so the
        // dissolve flow observes a clean baseline. We do not need the MLS
        // adapter to actually deliver that commit — simply clearing the
        // local staging queue is enough for this unit-level ordering check.
        alice.state.pending_group_outbox.clear();

        let dissolve = alice
            .handle_command(CoreCommand::DissolveGroup {
                group_id: group_id.clone(),
            })
            .expect("dissolve");

        // Inspect the now-pending group outbox items: they must be
        // exactly [remove_commit, control_group_dissolved] in that order.
        let items = &alice.state.pending_group_outbox;
        assert!(
            items.len() >= 2,
            "expected commit + control queued; got {}",
            items.len()
        );
        assert_eq!(
            items[0].envelope.message_type,
            GroupMessageType::MlsCommit,
            "step (a): the MLS remove_members commit must be enqueued first"
        );
        assert_eq!(
            items[1].envelope.message_type,
            GroupMessageType::ControlGroupDissolved,
            "step (b): ControlGroupDissolved must immediately follow the remove commit"
        );
        assert_eq!(
            items[1].envelope.visibility,
            GroupEnvelopeVisibility::Visible,
            "ControlGroupDissolved must be visible (PROTOCOL_GROUP_CN §10.4)"
        );

        // Step (c): seal is staged but not yet emitted as an effect.
        assert!(
            alice.state.pending_group_seal.contains_key(&group_id),
            "the seal request must be staged before its effect is emitted"
        );
        let ops = persist_ops(&dissolve);
        assert!(
            ops.iter().any(|op| matches!(
                op,
                PersistOp::SavePendingGroupSeal { group_id: saved_group_id }
                    if saved_group_id == &group_id
            )),
            "staged seal must be persisted incrementally"
        );
        assert!(
            !dissolve
                .effects
                .iter()
                .any(|effect| matches!(effect, CoreEffect::SealGroupOutbox { .. })),
            "seal effect must not be emitted before commit/control are acknowledged"
        );

        // And step (d): dissolved_at stays None until a GroupOutboxSealed
        // event comes back.
        let group_state = alice
            .state
            .group_states
            .get(&group_id)
            .expect("group still present");
        assert!(
            group_state.dissolved_at.is_none(),
            "dissolved_at must remain None until the seal is acknowledged"
        );
    }

    #[test]
    fn dissolve_group_waits_for_preexisting_pending_outbox_before_seal() {
        // The seal is allowed only after the entire group outbox queue is
        // empty, not merely after the dissolve command's own commit/control
        // messages are acknowledged. This prevents an older pending group
        // append from being stranded behind an irreversible seal.
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let created = alice
            .handle_command(CoreCommand::CreateGroupConversation {
                title: "Project".into(),
                member_user_ids: vec![bob_bundle.user_id.clone()],
            })
            .expect("create group");
            let created = simulate_pending_key_package_claims(&mut alice, created);
        let group_id = created
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .and_then(|summary| summary.group_id.clone())
            .expect("group id");
        acknowledge_pending_group_transition(&mut alice, &group_id);
        alice
            .handle_command(CoreCommand::SendGroupTextMessage {
                conversation_id: alice.state.group_states[&group_id].conversation_id.clone(),
                plaintext: "preexisting".into(),
            })
            .expect("stage preexisting group message");

        let preexisting_pending: Vec<String> = alice
            .state
            .pending_group_outbox
            .iter()
            .filter(|item| item.envelope.group_id == group_id)
            .map(|item| item.envelope.message_id.clone())
            .collect();
        assert!(
            !preexisting_pending.is_empty(),
            "group creation must leave at least one preexisting pending append for this guard"
        );

        alice
            .handle_command(CoreCommand::DissolveGroup {
                group_id: group_id.clone(),
            })
            .expect("dissolve");

        let dissolve_pending: Vec<String> = alice
            .state
            .pending_group_outbox
            .iter()
            .filter(|item| {
                item.envelope.group_id == group_id
                    && !preexisting_pending.contains(&item.envelope.message_id)
            })
            .map(|item| item.envelope.message_id.clone())
            .collect();
        assert!(
            !dissolve_pending.is_empty(),
            "dissolve must stage its own pending commit/control appends"
        );

        for (index, message_id) in dissolve_pending.iter().enumerate() {
            let output = alice
                .handle_event(CoreEvent::GroupEnvelopeAppended {
                    group_id: group_id.clone(),
                    message_id: message_id.clone(),
                    seq: (index as u64) + 10,
                })
                .expect("ack dissolve append");
            assert!(
                !output
                    .effects
                    .iter()
                    .any(|effect| matches!(effect, CoreEffect::SealGroupOutbox { .. })),
                "seal must not be emitted while older group outbox entries remain pending"
            );
        }

        let mut final_output = None;
        for (index, message_id) in preexisting_pending.iter().enumerate() {
            final_output = Some(
                alice
                    .handle_event(CoreEvent::GroupEnvelopeAppended {
                        group_id: group_id.clone(),
                        message_id: message_id.clone(),
                        seq: (index as u64) + 99,
                    })
                    .expect("ack preexisting append"),
            );
        }
        let final_output = final_output.expect("at least one preexisting ack");
        assert!(
            final_output
                .effects
                .iter()
                .any(|effect| matches!(effect, CoreEffect::SealGroupOutbox { .. })),
            "seal must be emitted once the final pending group append is acknowledged"
        );
    }

    #[test]
    fn group_append_ack_persists_local_state_before_seal_effect() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let created = alice
            .handle_command(CoreCommand::CreateGroupConversation {
                title: "Project".into(),
                member_user_ids: vec![bob_bundle.user_id.clone()],
            })
            .expect("create group");
            let created = simulate_pending_key_package_claims(&mut alice, created);
        let group_id = created
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .and_then(|summary| summary.group_id.clone())
            .expect("group id");
        acknowledge_pending_group_transition(&mut alice, &group_id);

        alice.state.pending_group_outbox.clear();
        alice
            .handle_command(CoreCommand::DissolveGroup {
                group_id: group_id.clone(),
            })
            .expect("dissolve");

        let pending_ids: Vec<String> = alice
            .state
            .pending_group_outbox
            .iter()
            .filter(|item| item.envelope.group_id == group_id)
            .map(|item| item.envelope.message_id.clone())
            .collect();
        assert!(
            !pending_ids.is_empty(),
            "dissolve must stage append records before seal"
        );

        let mut last_output = None;
        for (index, message_id) in pending_ids.iter().enumerate() {
            last_output = Some(
                alice
                    .handle_event(CoreEvent::GroupEnvelopeAppended {
                        group_id: group_id.clone(),
                        message_id: message_id.clone(),
                        seq: (index as u64) + 1,
                    })
                    .expect("ack group append"),
            );
        }
        let output = last_output.expect("final append ack");
        let persist_index = first_persist_effect_index(&output).expect("persist effect");
        let seal_index = output
            .effects
            .iter()
            .position(|effect| matches!(effect, CoreEffect::SealGroupOutbox { .. }))
            .expect("seal effect");
        assert!(
            persist_index < seal_index,
            "local cleanup/message persistence must precede seal effect"
        );

        let ops = persist_ops(&output);
        assert!(
            ops.iter()
                .any(|op| matches!(op, PersistOp::DeleteOutgoingGroupEnvelope { .. }))
        );
        assert!(
            ops.iter()
                .any(|op| matches!(op, PersistOp::SaveConversation { .. }))
        );
        assert!(
            !ops.iter()
                .any(|op| matches!(op, PersistOp::DeletePendingGroupSeal { .. })),
            "pending seal must remain durable until seal ack succeeds"
        );
    }

    #[test]
    fn app_started_reissues_persisted_group_seal_after_outbox_drained() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let created = alice
            .handle_command(CoreCommand::CreateGroupConversation {
                title: "Project".into(),
                member_user_ids: vec![bob_bundle.user_id.clone()],
            })
            .expect("create group");
            let created = simulate_pending_key_package_claims(&mut alice, created);
        let group_id = created
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .and_then(|summary| summary.group_id.clone())
            .expect("group id");
        acknowledge_pending_group_transition(&mut alice, &group_id);
        alice.state.pending_group_outbox.clear();
        let local_bundle = alice.local_bundle().expect("local bundle");
        let capability = GroupCapability {
            version: CURRENT_MODEL_VERSION.to_string(),
            service: CapabilityService::GroupOutbox,
            group_id: group_id.clone(),
            user_id: local_bundle.user_id.clone(),
            device_id: local_bundle.devices[0].device_id.clone(),
            operations: vec![GroupCapabilityOperation::SealGroup],
            role: GroupRole::Owner,
            expires_at: 999,
            signature: "sig".into(),
        };
        alice.state.pending_group_seal.insert(
            group_id.clone(),
            SealGroupOutboxRequest {
                group_id: group_id.clone(),
                capability,
            },
        );

        let output = alice
            .handle_event(CoreEvent::AppStarted)
            .expect("app started");

        assert!(output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::SealGroupOutbox { seal } if seal.group_id == group_id
        )));
        assert!(
            !alice.state.pending_group_seal.contains_key(&group_id),
            "seal is consumed in memory to avoid duplicate sends in this process"
        );
    }

    #[test]
    fn dissolve_group_does_not_set_dissolved_at_until_seal_ack() {
        // Even after every pending commit/control is acknowledged AND the
        // SealGroupOutbox effect is emitted, `dissolved_at` must only be
        // set once the `GroupOutboxSealed` event comes back through the
        // engine (strict step-(d) contract).
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let created = alice
            .handle_command(CoreCommand::CreateGroupConversation {
                title: "Project".into(),
                member_user_ids: vec![bob_bundle.user_id.clone()],
            })
            .expect("create group");
            let created = simulate_pending_key_package_claims(&mut alice, created);
        let group_id = created
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .and_then(|summary| summary.group_id.clone())
            .expect("group id");
        acknowledge_pending_group_transition(&mut alice, &group_id);
        alice.state.pending_group_outbox.clear();

        alice
            .handle_command(CoreCommand::DissolveGroup {
                group_id: group_id.clone(),
            })
            .expect("dissolve");

        // Simulate the commit + control envelopes being successfully
        // appended by the transport. The second of these two
        // acknowledgements must trigger the seal effect.
        let pending_ids: Vec<String> = alice
            .state
            .pending_group_outbox
            .iter()
            .map(|item| item.envelope.message_id.clone())
            .collect();
        assert!(
            pending_ids.len() >= 1,
            "dissolve must have staged at least one outbox append"
        );
        let mut seal_effect_observed = false;
        for (index, message_id) in pending_ids.iter().enumerate() {
            let output = alice
                .handle_event(CoreEvent::GroupEnvelopeAppended {
                    group_id: group_id.clone(),
                    message_id: message_id.clone(),
                    seq: (index as u64) + 1,
                })
                .expect("handle group envelope appended");
            if output
                .effects
                .iter()
                .any(|effect| matches!(effect, CoreEffect::SealGroupOutbox { .. }))
            {
                seal_effect_observed = true;
            }
        }
        assert!(
            seal_effect_observed,
            "SealGroupOutbox effect must be emitted after the last pending append is acknowledged"
        );

        // Between the effect being emitted and the ack arriving,
        // `dissolved_at` must still be None.
        assert!(
            alice
                .state
                .group_states
                .get(&group_id)
                .expect("group state")
                .dissolved_at
                .is_none(),
            "dissolved_at must remain None until GroupOutboxSealed is observed"
        );

        // Now inject the success event — the transition must occur.
        let sealed_at = 1_700_000_000_000_u64;
        alice
            .handle_event(CoreEvent::GroupOutboxSealed {
                group_id: group_id.clone(),
                sealed_at,
                was_already_sealed: false,
            })
            .expect("handle sealed");
        assert_eq!(
            alice
                .state
                .group_states
                .get(&group_id)
                .expect("group state")
                .dissolved_at,
            Some(sealed_at),
            "dissolved_at must be set after GroupOutboxSealed arrives"
        );
    }

    #[test]
    fn dissolve_group_propagates_seal_failure_without_marking_dissolved() {
        // A retryable seal failure must re-stage the seal in
        // `pending_group_seal` so the next flush re-emits the effect, and
        // must NOT set `dissolved_at`. A non-retryable failure must clear
        // the staged seal and surface a system-status notification —
        // again, NOT setting `dissolved_at`.
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let created = alice
            .handle_command(CoreCommand::CreateGroupConversation {
                title: "Project".into(),
                member_user_ids: vec![bob_bundle.user_id.clone()],
            })
            .expect("create group");
            let created = simulate_pending_key_package_claims(&mut alice, created);
        let group_id = created
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .and_then(|summary| summary.group_id.clone())
            .expect("group id");
        acknowledge_pending_group_transition(&mut alice, &group_id);
        alice.state.pending_group_outbox.clear();
        alice
            .handle_command(CoreCommand::DissolveGroup {
                group_id: group_id.clone(),
            })
            .expect("dissolve");

        // Simulate a retryable seal failure (network / 5xx). The pending
        // seal entry must be rebuilt so the next flush reissues the effect.
        let retry_output = alice
            .handle_event(CoreEvent::GroupOutboxSealFailed {
                group_id: group_id.clone(),
                failure: test_failure("temporary_unavailable", true, Some(503)),
            })
            .expect("handle retryable seal failure");
        assert!(
            alice.state.pending_group_seal.contains_key(&group_id),
            "a retryable seal failure must re-stage the pending seal"
        );
        assert!(
            alice
                .state
                .group_states
                .get(&group_id)
                .expect("group state")
                .dissolved_at
                .is_none(),
            "a retryable seal failure must NOT mark the group dissolved"
        );
        assert!(
            retry_output
                .state_update
                .system_statuses_changed
                .contains(&crate::ffi_api::SystemStatus::TemporaryNetworkFailure)
        );

        // Simulate a non-retryable seal failure (e.g. 403 unauthorized).
        // The staged seal must be cleared and the user must see a
        // surfaced notification — still no dissolved_at.
        let terminal_output = alice
            .handle_event(CoreEvent::GroupOutboxSealFailed {
                group_id: group_id.clone(),
                failure: test_failure("invalid_capability", false, Some(403)),
            })
            .expect("handle terminal seal failure");
        assert!(
            !alice.state.pending_group_seal.contains_key(&group_id),
            "a non-retryable seal failure must drop the staged seal"
        );
        assert!(
            alice
                .state
                .group_states
                .get(&group_id)
                .expect("group state")
                .dissolved_at
                .is_none(),
            "a non-retryable seal failure must NOT mark the group dissolved"
        );
        assert!(
            terminal_output.effects.iter().any(|effect| matches!(
                effect,
                CoreEffect::EmitUserNotification { notification }
                    if notification.status == crate::ffi_api::SystemStatus::TemporaryNetworkFailure
            )),
            "a non-retryable seal failure must surface a user notification"
        );
    }

    #[test]
    fn group_three_member_text_e2e_with_seq_dedup() {
        let mut alice = harness_user("alice", ALICE_MNEMONIC, "phone");
        let mut bob = harness_user("bob", BOB_MNEMONIC, "phone");
        let mut carol = harness_user("carol", CAROL_MNEMONIC, "phone");
        import_peer_bundles(&mut [&mut alice, &mut bob, &mut carol]);
        let mut harness =
            GroupHarness::with_bundles(&[&alice, &bob, &carol].map(|u| HarnessUser {
                name: u.name,
                bundle: u.bundle.clone(),
                engine: CoreEngine::new(),
            }));

        let (group_id, conversation_id) = harness.create_group(
            &mut alice,
            "Project",
            vec![bob.bundle.user_id.clone(), carol.bundle.user_id.clone()],
        );
        assert_eq!(
            harness.outboxes[&group_id][0].envelope.message_type,
            GroupMessageType::MlsCommit
        );
        assert_eq!(harness.outboxes[&group_id][0].seq, 1);

        harness.import_welcome(&mut bob, &group_id);
        harness.import_welcome(&mut carol, &group_id);
        harness.sync_group(&mut bob, &group_id);
        harness.sync_group(&mut carol, &group_id);

        harness.send_text(&mut alice, &conversation_id, "from alice");
        harness.sync_group(&mut bob, &group_id);
        harness.sync_group(&mut carol, &group_id);
        harness.send_text(&mut bob, &conversation_id, "from bob");
        harness.sync_group(&mut alice, &group_id);
        harness.sync_group(&mut carol, &group_id);
        harness.send_text(&mut carol, &conversation_id, "from carol");
        harness.sync_group(&mut alice, &group_id);
        harness.sync_group(&mut bob, &group_id);

        let expected: BTreeSet<String> = ["from alice", "from bob", "from carol"]
            .into_iter()
            .map(String::from)
            .collect();
        for user in [&alice, &bob, &carol] {
            let texts = group_plaintexts(user, &conversation_id)
                .into_iter()
                .collect::<BTreeSet<_>>();
            assert_eq!(
                texts,
                expected,
                "{} saw wrong plaintexts; outbox={:?}; stored={:?}",
                user.name,
                harness.outboxes[&group_id]
                    .iter()
                    .map(|record| (
                        record.seq,
                        record.message_id.clone(),
                        record.envelope.sender_user_id.clone(),
                        record.envelope.message_type
                    ))
                    .collect::<Vec<_>>(),
                user.engine
                    .state
                    .conversations
                    .get(&conversation_id)
                    .expect("conversation")
                    .messages
                    .iter()
                    .map(|message| (
                        message.message_id.clone(),
                        message.sender_device_id.clone(),
                        message.message_type,
                        message.plaintext.clone()
                    ))
                    .collect::<Vec<_>>()
            );
        }

        let bob_count = group_plaintexts(&bob, &conversation_id).len();
        let carol_count = group_plaintexts(&carol, &conversation_id).len();
        let head = harness.outboxes[&group_id].last().expect("outbox head").seq;
        harness.sync_group(&mut bob, &group_id);
        harness.sync_group(&mut carol, &group_id);
        assert_eq!(group_plaintexts(&bob, &conversation_id).len(), bob_count);
        assert_eq!(
            group_plaintexts(&carol, &conversation_id).len(),
            carol_count
        );
        assert_eq!(group_cursor(&bob, &group_id), head);
        assert_eq!(group_cursor(&carol, &group_id), head);
    }

    #[test]
    fn group_application_message_with_spoofed_envelope_sender_is_dropped() {
        let mut alice = harness_user("alice", ALICE_MNEMONIC, "phone");
        let mut bob = harness_user("bob", BOB_MNEMONIC, "phone");
        let mut carol = harness_user("carol", CAROL_MNEMONIC, "phone");
        import_peer_bundles(&mut [&mut alice, &mut bob, &mut carol]);
        let mut harness =
            GroupHarness::with_bundles(&[&alice, &bob, &carol].map(|u| HarnessUser {
                name: u.name,
                bundle: u.bundle.clone(),
                engine: CoreEngine::new(),
            }));

        let (group_id, conversation_id) = harness.create_group(
            &mut alice,
            "Project",
            vec![bob.bundle.user_id.clone(), carol.bundle.user_id.clone()],
        );
        harness.import_welcome(&mut bob, &group_id);
        harness.import_welcome(&mut carol, &group_id);
        harness.sync_group(&mut bob, &group_id);
        harness.sync_group(&mut carol, &group_id);

        // Alice sends a real, correctly-authenticated MLS application message.
        harness.send_text(&mut alice, &conversation_id, "hi from alice for real");

        // A malicious/compromised Outbox relabels the envelope's sender fields to
        // Carol, without touching the MLS ciphertext (which it cannot forge).
        {
            let record = harness
                .outboxes
                .get_mut(&group_id)
                .expect("group outbox")
                .last_mut()
                .expect("application record");
            assert_eq!(record.envelope.message_type, GroupMessageType::MlsApplication);
            record.envelope.sender_user_id = carol.bundle.user_id.clone();
            record.envelope.sender_device_id = carol.bundle.devices[0].device_id.clone();
        }

        harness.sync_group(&mut bob, &group_id);

        let bob_texts = group_plaintexts(&bob, &conversation_id);
        assert!(
            !bob_texts.iter().any(|text| text == "hi from alice for real"),
            "message with a spoofed envelope sender must not be accepted, even though its MLS ciphertext is genuine: {bob_texts:?}"
        );
        assert!(
            !bob.engine
                .state
                .conversations
                .get(&conversation_id)
                .expect("conversation")
                .messages
                .iter()
                .any(|message| message.sender_user_id.as_deref() == Some(carol.bundle.user_id.as_str())),
            "no message should ever be attributed to carol here"
        );
    }

    #[test]
    fn group_pcs_member_proposal_then_owner_commit_decrypts() {
        let mut alice = harness_user("alice", ALICE_MNEMONIC, "phone");
        let mut bob = harness_user("bob", BOB_MNEMONIC, "phone");
        let mut carol = harness_user("carol", CAROL_MNEMONIC, "phone");
        import_peer_bundles(&mut [&mut alice, &mut bob, &mut carol]);
        let mut harness =
            GroupHarness::with_bundles(&[&alice, &bob, &carol].map(|u| HarnessUser {
                name: u.name,
                bundle: u.bundle.clone(),
                engine: CoreEngine::new(),
            }));

        let (group_id, conversation_id) = harness.create_group(
            &mut alice,
            "PCS Project",
            vec![bob.bundle.user_id.clone(), carol.bundle.user_id.clone()],
        );
        harness.import_welcome(&mut bob, &group_id);
        harness.import_welcome(&mut carol, &group_id);
        harness.sync_group(&mut bob, &group_id);
        harness.sync_group(&mut carol, &group_id);
        let epoch_before = alice.engine.state.group_states[&group_id]
            .manifest
            .mls_epoch_hint;

        for index in 0..GROUP_PCS_COMMIT_INTERVAL {
            harness.send_text(&mut carol, &conversation_id, &format!("pcs-{index}"));
            harness.sync_group(&mut alice, &group_id);
            harness.sync_group(&mut bob, &group_id);
        }

        assert!(
            harness.outboxes[&group_id]
                .iter()
                .any(|record| record.envelope.message_type == GroupMessageType::MlsProposal),
            "member must emit an MLS Update proposal after {GROUP_PCS_COMMIT_INTERVAL} messages"
        );
        assert!(
            harness.outboxes[&group_id].iter().any(|record| {
                record
                    .envelope
                    .membership_proof
                    .as_ref()
                    .is_some_and(|proof| proof.operation == "pcs_update")
            }),
            "owner or admin must commit pcs_update after the proposal"
        );
        harness.sync_group(&mut carol, &group_id);
        harness.sync_group(&mut bob, &group_id);
        let epoch_after = alice.engine.state.group_states[&group_id]
            .manifest
            .mls_epoch_hint;
        assert_eq!(epoch_after, epoch_before + 1);
        assert_eq!(
            bob.engine.state.group_states[&group_id]
                .manifest
                .mls_epoch_hint,
            epoch_after
        );
        assert_eq!(
            carol.engine.state.group_states[&group_id]
                .manifest
                .mls_epoch_hint,
            epoch_after
        );

        harness.send_text(&mut alice, &conversation_id, "after pcs");
        harness.sync_group(&mut bob, &group_id);
        harness.sync_group(&mut carol, &group_id);
        for user in [&alice, &bob, &carol] {
            assert!(
                group_plaintexts(user, &conversation_id)
                    .iter()
                    .any(|text| text == "after pcs"),
                "{} must decrypt post-PCS application traffic",
                user.name
            );
        }
    }

    #[test]
    fn group_pcs_two_admin_commits_conflict_then_converge() {
        let mut alice = harness_user("alice", ALICE_MNEMONIC, "phone");
        let mut bob = harness_user("bob", BOB_MNEMONIC, "phone");
        let mut carol = harness_user("carol", CAROL_MNEMONIC, "phone");
        import_peer_bundles(&mut [&mut alice, &mut bob, &mut carol]);
        let mut harness =
            GroupHarness::with_bundles(&[&alice, &bob, &carol].map(|u| HarnessUser {
                name: u.name,
                bundle: u.bundle.clone(),
                engine: CoreEngine::new(),
            }));

        let (group_id, conversation_id) = harness.create_group(
            &mut alice,
            "PCS Race",
            vec![bob.bundle.user_id.clone(), carol.bundle.user_id.clone()],
        );
        harness.import_welcome(&mut bob, &group_id);
        harness.import_welcome(&mut carol, &group_id);
        harness.sync_group(&mut bob, &group_id);
        harness.sync_group(&mut carol, &group_id);
        let promote = alice
            .engine
            .handle_command(CoreCommand::SetGroupAdmin {
                group_id: group_id.clone(),
                target_user_id: bob.bundle.user_id.clone(),
                is_admin: true,
            })
            .expect("promote bob");
        harness.drain(&mut alice, promote);
        harness.sync_group(&mut bob, &group_id);
        harness.sync_group(&mut carol, &group_id);
        assert_eq!(
            bob.engine.state.group_states[&group_id].local_role,
            Some(GroupRole::Admin)
        );

        alice
            .engine
            .state
            .group_states
            .get_mut(&group_id)
            .expect("alice group")
            .pcs
            .epoch_app_count = GROUP_PCS_COMMIT_INTERVAL;
        bob.engine
            .state
            .group_states
            .get_mut(&group_id)
            .expect("bob group")
            .pcs
            .epoch_app_count = GROUP_PCS_COMMIT_INTERVAL;

        let alice_pcs = alice
            .engine
            .handle_command(CoreCommand::AdvanceGroupPcs {
                group_id: group_id.clone(),
            })
            .expect("alice advance pcs");
        let bob_pcs = bob
            .engine
            .handle_command(CoreCommand::AdvanceGroupPcs {
                group_id: group_id.clone(),
            })
            .expect("bob advance pcs");
        assert!(alice_pcs.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::AppendGroupTransition { append } if append.group_id == group_id
        )));
        assert!(bob_pcs.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::AppendGroupTransition { append } if append.group_id == group_id
        )));
        harness.drain(&mut alice, alice_pcs);
        harness.drain(&mut bob, bob_pcs);
        harness.sync_group(&mut bob, &group_id);
        harness.sync_group(&mut carol, &group_id);
        harness.sync_group(&mut alice, &group_id);

        let alice_epoch = alice.engine.state.group_states[&group_id]
            .manifest
            .mls_epoch_hint;
        assert_eq!(
            bob.engine.state.group_states[&group_id]
                .manifest
                .mls_epoch_hint,
            alice_epoch
        );
        assert_eq!(
            carol.engine.state.group_states[&group_id]
                .manifest
                .mls_epoch_hint,
            alice_epoch
        );
        harness.send_text(&mut alice, &conversation_id, "after race");
        harness.sync_group(&mut bob, &group_id);
        harness.sync_group(&mut carol, &group_id);
        for user in [&alice, &bob, &carol] {
            assert!(
                group_plaintexts(user, &conversation_id)
                    .iter()
                    .any(|text| text == "after race"),
                "{} must decrypt after concurrent pcs_update",
                user.name
            );
        }
    }

    #[test]
    fn group_pcs_batch_sync_keeps_member_update_debt() {
        let mut alice = harness_user("alice", ALICE_MNEMONIC, "phone");
        let mut bob = harness_user("bob", BOB_MNEMONIC, "phone");
        let mut carol = harness_user("carol", CAROL_MNEMONIC, "phone");
        import_peer_bundles(&mut [&mut alice, &mut bob, &mut carol]);
        let mut harness =
            GroupHarness::with_bundles(&[&alice, &bob, &carol].map(|u| HarnessUser {
                name: u.name,
                bundle: u.bundle.clone(),
                engine: CoreEngine::new(),
            }));

        let (group_id, conversation_id) = harness.create_group(
            &mut alice,
            "PCS Batch",
            vec![bob.bundle.user_id.clone(), carol.bundle.user_id.clone()],
        );
        harness.import_welcome(&mut bob, &group_id);
        harness.import_welcome(&mut carol, &group_id);
        harness.sync_group(&mut bob, &group_id);
        harness.sync_group(&mut carol, &group_id);
        let epoch_before = alice.engine.state.group_states[&group_id]
            .manifest
            .mls_epoch_hint;

        for index in 0..GROUP_PCS_COMMIT_INTERVAL {
            harness.send_text(&mut alice, &conversation_id, &format!("owner-{index}"));
        }
        assert!(
            harness.outboxes[&group_id].iter().any(|record| {
                record
                    .envelope
                    .membership_proof
                    .as_ref()
                    .is_some_and(|proof| proof.operation == "pcs_update")
            }),
            "owner must commit pcs_update after {GROUP_PCS_COMMIT_INTERVAL} of their own messages"
        );

        harness.sync_group(&mut bob, &group_id);
        assert!(
            bob.engine.state.group_states[&group_id].pcs.epoch_app_count
                >= GROUP_PCS_COMMIT_INTERVAL,
            "batch sync must not clear member PCS debt when the member leaf did not rotate"
        );
        assert!(
            harness.outboxes[&group_id].iter().any(|record| {
                record.envelope.message_type == GroupMessageType::MlsProposal
                    && record.envelope.sender_device_id == bob.bundle.devices[0].device_id
            }),
            "member must propose a self-update after catching up to a foreign PCS commit"
        );
        assert_eq!(
            bob.engine.state.group_states[&group_id]
                .manifest
                .mls_epoch_hint,
            epoch_before + 1
        );
    }

    #[test]
    fn group_pcs_member_can_send_while_waiting_for_admin_commit() {
        let mut alice = harness_user("alice", ALICE_MNEMONIC, "phone");
        let mut bob = harness_user("bob", BOB_MNEMONIC, "phone");
        let mut carol = harness_user("carol", CAROL_MNEMONIC, "phone");
        import_peer_bundles(&mut [&mut alice, &mut bob, &mut carol]);
        let mut harness =
            GroupHarness::with_bundles(&[&alice, &bob, &carol].map(|u| HarnessUser {
                name: u.name,
                bundle: u.bundle.clone(),
                engine: CoreEngine::new(),
            }));

        let (group_id, conversation_id) = harness.create_group(
            &mut alice,
            "PCS Offline Admin",
            vec![bob.bundle.user_id.clone(), carol.bundle.user_id.clone()],
        );
        harness.import_welcome(&mut bob, &group_id);
        harness.import_welcome(&mut carol, &group_id);
        harness.sync_group(&mut bob, &group_id);
        harness.sync_group(&mut carol, &group_id);

        for index in 0..GROUP_PCS_COMMIT_INTERVAL {
            harness.send_text(&mut carol, &conversation_id, &format!("wait-{index}"));
        }
        assert!(
            harness.outboxes[&group_id]
                .iter()
                .any(|record| record.envelope.message_type == GroupMessageType::MlsProposal),
            "member must emit an MLS Update proposal after {GROUP_PCS_COMMIT_INTERVAL} messages"
        );
        harness.send_text(&mut carol, &conversation_id, "thirty-three");
        harness.sync_group(&mut bob, &group_id);
        harness.send_text(&mut bob, &conversation_id, "bob-after-proposal");
        assert!(
            harness.outboxes[&group_id]
                .iter()
                .any(
                    |record| record.envelope.message_type == GroupMessageType::MlsApplication
                        && record.envelope.inline_ciphertext.as_ref().is_some()
                ),
            "application traffic must continue while the admin is offline"
        );
    }

    #[test]
    fn group_pcs_metadata_update_keeps_pending_proposal() {
        let mut alice = harness_user("alice", ALICE_MNEMONIC, "phone");
        let mut bob = harness_user("bob", BOB_MNEMONIC, "phone");
        let mut carol = harness_user("carol", CAROL_MNEMONIC, "phone");
        import_peer_bundles(&mut [&mut alice, &mut bob, &mut carol]);
        let mut harness =
            GroupHarness::with_bundles(&[&alice, &bob, &carol].map(|u| HarnessUser {
                name: u.name,
                bundle: u.bundle.clone(),
                engine: CoreEngine::new(),
            }));

        let (group_id, conversation_id) = harness.create_group(
            &mut alice,
            "PCS Metadata",
            vec![bob.bundle.user_id.clone(), carol.bundle.user_id.clone()],
        );
        harness.import_welcome(&mut bob, &group_id);
        harness.import_welcome(&mut carol, &group_id);
        harness.sync_group(&mut bob, &group_id);
        harness.sync_group(&mut carol, &group_id);
        let epoch_before = alice.engine.state.group_states[&group_id]
            .manifest
            .mls_epoch_hint;

        let proposal = carol
            .engine
            .state
            .mls_adapter
            .as_mut()
            .expect("carol mls")
            .propose_self_update(&conversation_id)
            .expect("carol propose");
        match alice
            .engine
            .state
            .mls_adapter
            .as_mut()
            .expect("alice mls")
            .ingest_message(
                &conversation_id,
                &carol.bundle.devices[0].device_id,
                MessageType::MlsProposal,
                &proposal.payload_b64,
            )
            .expect("alice ingest proposal")
        {
            crate::mls_adapter::IngestResult::AppliedProposal => {}
            other => panic!("expected AppliedProposal, got {other:?}"),
        }
        assert!(
            alice
                .engine
                .state
                .mls_adapter
                .as_ref()
                .expect("mls")
                .has_pcs_update_proposals(&conversation_id)
                .expect("sidecar before metadata"),
            "member proposal must be cached before metadata ACK"
        );

        let metadata = alice
            .engine
            .handle_command(CoreCommand::UpdateGroupMetadata {
                group_id: group_id.clone(),
                title: Some("PCS Metadata Renamed".into()),
                join_policy: None,
                member_invite_policy: None,
            })
            .expect("update metadata");
        harness.drain(&mut alice, metadata);
        assert_eq!(
            alice.engine.state.group_states[&group_id]
                .manifest
                .mls_epoch_hint,
            epoch_before,
            "metadata update must not advance MLS epoch"
        );
        assert!(
            alice
                .engine
                .state
                .mls_adapter
                .as_ref()
                .expect("mls")
                .has_pcs_update_proposals(&conversation_id)
                .expect("sidecar after ack"),
            "metadata ACK must not drop pending PCS updates"
        );

        let commit = alice
            .engine
            .handle_command(CoreCommand::AdvanceGroupPcs {
                group_id: group_id.clone(),
            })
            .expect("commit cached proposal");
        harness.drain(&mut alice, commit);
        harness.sync_group(&mut carol, &group_id);
        harness.send_text(&mut alice, &conversation_id, "after metadata pcs");
        harness.sync_group(&mut carol, &group_id);
        assert!(
            group_plaintexts(&carol, &conversation_id)
                .iter()
                .any(|text| text == "after metadata pcs"),
            "member must decrypt after PCS commit that followed metadata update"
        );
    }

    #[test]
    fn group_realtime_event_fetches_outbox_and_advances_cursor() {
        let mut alice = harness_user("alice", ALICE_MNEMONIC, "phone");
        let mut bob = harness_user("bob", BOB_MNEMONIC, "phone");
        import_peer_bundles(&mut [&mut alice, &mut bob]);
        let mut harness = GroupHarness::with_bundles(&[&alice, &bob].map(|u| HarnessUser {
            name: u.name,
            bundle: u.bundle.clone(),
            engine: CoreEngine::new(),
        }));

        let (group_id, conversation_id) = harness.create_group(
            &mut alice,
            "Realtime Project",
            vec![bob.bundle.user_id.clone()],
        );
        harness.import_welcome(&mut bob, &group_id);
        let cursor_before_message = group_cursor(&bob, &group_id);

        harness.send_text(&mut alice, &conversation_id, "from realtime owner");
        let head = harness.outboxes[&group_id].last().expect("outbox head").seq;
        assert!(head > cursor_before_message);

        let output = bob
            .engine
            .handle_event(CoreEvent::GroupRealtimeEventReceived {
                group_id: group_id.clone(),
                event: RealtimeEvent::GroupOutboxRecordAvailable {
                    group_id: group_id.clone(),
                    seq: head,
                    record: None,
                },
            })
            .expect("group realtime event");
        assert!(output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::FetchGroupOutbox { fetch }
                if fetch.group_id == group_id
                    && fetch.from_seq == cursor_before_message.saturating_add(1)
        )));
        harness.drain(&mut bob, output);

        assert!(
            group_plaintexts(&bob, &conversation_id)
                .iter()
                .any(|text| text == "from realtime owner")
        );
        assert_eq!(group_cursor(&bob, &group_id), head);

        let caught_up = bob
            .engine
            .handle_event(CoreEvent::GroupRealtimeEventReceived {
                group_id: group_id.clone(),
                event: RealtimeEvent::GroupHeadUpdated {
                    group_id: group_id.clone(),
                    seq: head,
                },
            })
            .expect("caught-up group realtime event");
        assert!(
            !caught_up
                .effects
                .iter()
                .any(|effect| matches!(effect, CoreEffect::FetchGroupOutbox { .. }))
        );
    }

    #[test]
    fn group_attachment_e2e_uses_storage_refs_and_downloads_plaintext() {
        let mut alice = harness_user("alice", ALICE_MNEMONIC, "phone");
        let mut bob = harness_user("bob", BOB_MNEMONIC, "phone");
        let mut carol = harness_user("carol", CAROL_MNEMONIC, "phone");
        import_peer_bundles(&mut [&mut alice, &mut bob, &mut carol]);
        let mut harness =
            GroupHarness::with_bundles(&[&alice, &bob, &carol].map(|u| HarnessUser {
                name: u.name,
                bundle: u.bundle.clone(),
                engine: CoreEngine::new(),
            }));
        let (group_id, conversation_id) = harness.create_group(
            &mut alice,
            "Project",
            vec![bob.bundle.user_id.clone(), carol.bundle.user_id.clone()],
        );
        harness.import_welcome(&mut bob, &group_id);
        harness.import_welcome(&mut carol, &group_id);
        harness.sync_group(&mut bob, &group_id);
        harness.sync_group(&mut carol, &group_id);

        harness.send_attachment(&mut alice, &conversation_id, sample_attachment_descriptor());
        harness.sync_group(&mut bob, &group_id);
        harness.sync_group(&mut carol, &group_id);

        let bob_attachment = group_attachment_message(&bob, &conversation_id);
        let carol_attachment = group_attachment_message(&carol, &conversation_id);
        assert_eq!(bob_attachment.0, carol_attachment.0);
        assert_eq!(bob_attachment.1, carol_attachment.1);
        assert_ne!(bob_attachment.1, "blob-ref:blob-upload");

        harness.download_attachment(
            &mut bob,
            &conversation_id,
            &bob_attachment.0,
            &bob_attachment.1,
            "bob/download/file.bin",
        );
        harness.download_attachment(
            &mut carol,
            &conversation_id,
            &carol_attachment.0,
            &carol_attachment.1,
            "carol/download/file.bin",
        );
        assert_eq!(
            harness.downloaded_attachments["bob/download/file.bin"],
            vec![1, 2, 3, 4]
        );
        assert_eq!(
            harness.downloaded_attachments["carol/download/file.bin"],
            vec![1, 2, 3, 4]
        );
    }

    #[test]
    fn group_attachment_non_member_cannot_sync_or_decrypt() {
        let mut alice = harness_user("alice", ALICE_MNEMONIC, "phone");
        let mut bob = harness_user("bob", BOB_MNEMONIC, "phone");
        let mut carol = harness_user("carol", CAROL_MNEMONIC, "phone");
        let mut dana = harness_user("dana", DANA_MNEMONIC, "phone");
        import_peer_bundles(&mut [&mut alice, &mut bob, &mut carol, &mut dana]);
        let mut harness =
            GroupHarness::with_bundles(&[&alice, &bob, &carol, &dana].map(|u| HarnessUser {
                name: u.name,
                bundle: u.bundle.clone(),
                engine: CoreEngine::new(),
            }));
        let (group_id, conversation_id) = harness.create_group(
            &mut alice,
            "Project",
            vec![bob.bundle.user_id.clone(), carol.bundle.user_id.clone()],
        );
        harness.import_welcome(&mut bob, &group_id);
        harness.import_welcome(&mut carol, &group_id);
        harness.sync_group(&mut bob, &group_id);
        harness.sync_group(&mut carol, &group_id);

        harness.send_attachment(&mut alice, &conversation_id, sample_attachment_descriptor());
        harness.sync_group(&mut bob, &group_id);
        let bob_attachment = group_attachment_message(&bob, &conversation_id);

        let sync_err = dana
            .engine
            .handle_command(CoreCommand::SyncGroupOutbox {
                group_id: group_id.clone(),
                reason: Some("non-member sync".into()),
            })
            .expect_err("non-member must not sync a group without local state");
        assert_eq!(sync_err.code(), "invalid_input");
        assert!(
            !dana.engine.state.group_states.contains_key(&group_id),
            "non-member must not materialize group state by syncing"
        );
        assert!(
            !dana
                .engine
                .state
                .conversations
                .contains_key(&conversation_id),
            "non-member must not materialize the group conversation"
        );
        assert!(
            dana.engine
                .handle_command(CoreCommand::DownloadAttachment {
                    conversation_id,
                    message_id: bob_attachment.0,
                    reference: bob_attachment.1,
                    destination: "dana/download/file.bin".into(),
                })
                .is_err(),
            "non-member must not download/decrypt a group attachment"
        );
    }

    #[test]
    fn group_attachment_removed_member_cannot_decrypt_new_attachment() {
        let mut alice = harness_user("alice", ALICE_MNEMONIC, "phone");
        let mut bob = harness_user("bob", BOB_MNEMONIC, "phone");
        let mut carol = harness_user("carol", CAROL_MNEMONIC, "phone");
        import_peer_bundles(&mut [&mut alice, &mut bob, &mut carol]);
        let mut harness =
            GroupHarness::with_bundles(&[&alice, &bob, &carol].map(|u| HarnessUser {
                name: u.name,
                bundle: u.bundle.clone(),
                engine: CoreEngine::new(),
            }));
        let (group_id, conversation_id) = harness.create_group(
            &mut alice,
            "Project",
            vec![bob.bundle.user_id.clone(), carol.bundle.user_id.clone()],
        );
        harness.import_welcome(&mut bob, &group_id);
        harness.import_welcome(&mut carol, &group_id);
        harness.sync_group(&mut bob, &group_id);
        harness.sync_group(&mut carol, &group_id);

        let remove_output = alice
            .engine
            .handle_command(CoreCommand::RemoveGroupMember {
                group_id: group_id.clone(),
                target_user_id: carol.bundle.user_id.clone(),
            })
            .expect("owner removes carol");
        harness.drain(&mut alice, remove_output);
        harness.sync_group(&mut bob, &group_id);
        harness.send_attachment(&mut alice, &conversation_id, sample_attachment_descriptor());
        harness.sync_group(&mut bob, &group_id);
        let bob_attachment = group_attachment_message(&bob, &conversation_id);
        harness.download_attachment(
            &mut bob,
            &conversation_id,
            &bob_attachment.0,
            &bob_attachment.1,
            "bob/post-remove/file.bin",
        );
        assert_eq!(
            harness.downloaded_attachments["bob/post-remove/file.bin"],
            vec![1, 2, 3, 4]
        );

        let _ = carol
            .engine
            .handle_command(CoreCommand::SyncGroupOutbox {
                group_id: group_id.clone(),
                reason: Some("removed member attachment sync".into()),
            })
            .and_then(|output| Ok(harness.drain(&mut carol, output)));
        let carol_has_post_remove_attachment = carol
            .engine
            .state
            .conversations
            .get(&conversation_id)
            .map(|conversation| {
                conversation.messages.iter().any(|message| {
                    message.message_type == MessageType::MlsApplication
                        && message.message_id == bob_attachment.0
                })
            })
            .unwrap_or_default();
        assert!(
            !carol_has_post_remove_attachment,
            "removed member must not ingest post-remove attachment application messages"
        );
        assert!(
            carol
                .engine
                .handle_command(CoreCommand::DownloadAttachment {
                    conversation_id: conversation_id.clone(),
                    message_id: bob_attachment.0,
                    reference: bob_attachment.1,
                    destination: "carol/post-remove/file.bin".into(),
                })
                .is_err(),
            "removed member must not decrypt a post-remove attachment"
        );
        assert!(
            carol
                .engine
                .handle_command(CoreCommand::SendAttachmentMessage {
                    conversation_id,
                    attachment_descriptor: sample_attachment_descriptor(),
                })
                .is_err(),
            "removed member must not send new group attachments"
        );
    }

    #[test]
    fn group_recovery_restores_state_cursor_and_pending_outbox_on_app_started() {
        let mut alice = harness_user("alice", ALICE_MNEMONIC, "phone");
        let mut bob = harness_user("bob", BOB_MNEMONIC, "phone");
        let mut carol = harness_user("carol", CAROL_MNEMONIC, "phone");
        import_peer_bundles(&mut [&mut alice, &mut bob, &mut carol]);
        let mut harness =
            GroupHarness::with_bundles(&[&alice, &bob, &carol].map(|u| HarnessUser {
                name: u.name,
                bundle: u.bundle.clone(),
                engine: CoreEngine::new(),
            }));
        let (group_id, conversation_id) = harness.create_group(
            &mut alice,
            "Project",
            vec![bob.bundle.user_id.clone(), carol.bundle.user_id.clone()],
        );
        harness.import_welcome(&mut bob, &group_id);
        harness.import_welcome(&mut carol, &group_id);
        harness.sync_group(&mut bob, &group_id);
        let bob_cursor = group_cursor(&bob, &group_id);
        assert!(bob_cursor > 0, "bob cursor should advance after sync");

        let send_output = bob
            .engine
            .handle_command(CoreCommand::SendGroupTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "pending after restart".into(),
            })
            .expect("send pending group text");
        assert!(send_output.effects.iter().any(|effect| {
            matches!(effect, CoreEffect::AppendGroupEnvelope { append } if append.group_id == group_id)
        }));
        let snapshot = bob.engine.refresh_snapshot();
        assert!(
            snapshot
                .pending_group_outbox
                .iter()
                .any(|item| item.group_id == group_id)
        );

        let mut restored = CoreEngine::try_from_restored_state(snapshot).expect("restore snapshot");
        assert!(restored.state.group_states.contains_key(&group_id));
        assert!(restored.state.conversations.contains_key(&conversation_id));
        assert_eq!(group_cursor_engine(&restored, &group_id), bob_cursor);

        let resumed = restored
            .handle_event(CoreEvent::AppStarted)
            .expect("app started");
        assert!(resumed.effects.iter().any(|effect| {
            matches!(effect, CoreEffect::AppendGroupEnvelope { append } if append.group_id == group_id)
        }));
    }

    #[test]
    fn manual_group_outbox_sync_retries_exhausted_pending_appends() {
        let mut alice = harness_user("alice", ALICE_MNEMONIC, "phone");
        let mut bob = harness_user("bob", BOB_MNEMONIC, "phone");
        import_peer_bundles(&mut [&mut alice, &mut bob]);
        let mut harness = GroupHarness::with_bundles(&[&alice, &bob].map(|u| HarnessUser {
            name: u.name,
            bundle: u.bundle.clone(),
            engine: CoreEngine::new(),
        }));
        let (group_id, conversation_id) =
            harness.create_group(&mut alice, "Project", vec![bob.bundle.user_id.clone()]);

        alice
            .engine
            .handle_command(CoreCommand::SendGroupTextMessage {
                conversation_id,
                plaintext: "retry after runtime upgrade".into(),
            })
            .expect("send pending group text");

        for item in &mut alice.engine.state.pending_group_outbox {
            if item.envelope.group_id == group_id {
                item.in_flight = true;
                item.retries = MAX_TRANSPORT_RETRIES;
            }
        }

        let output = alice
            .engine
            .handle_command(CoreCommand::SyncGroupOutbox {
                group_id: group_id.clone(),
                reason: Some("manual_retry".into()),
            })
            .expect("manual retry group outbox");

        assert!(output.effects.iter().any(|effect| {
            matches!(effect, CoreEffect::AppendGroupEnvelope { append } if append.group_id == group_id)
        }));
        assert!(
            alice
                .engine
                .state
                .pending_group_outbox
                .iter()
                .filter(|item| item.envelope.group_id == group_id)
                .all(|item| item.in_flight && item.retries == 0)
        );
    }

    #[test]
    fn apply_group_realtime_plan_opens_only_selected_groups_and_closes_removed_groups() {
        let mut alice = harness_user("alice", ALICE_MNEMONIC, "phone");
        let mut bob = harness_user("bob", BOB_MNEMONIC, "phone");
        import_peer_bundles(&mut [&mut alice, &mut bob]);
        let mut harness = GroupHarness::with_bundles(&[&alice, &bob].map(|u| HarnessUser {
            name: u.name,
            bundle: u.bundle.clone(),
            engine: CoreEngine::new(),
        }));
        let (group_id, _conversation_id) =
            harness.create_group(&mut alice, "Project", vec![bob.bundle.user_id.clone()]);

        let started = alice
            .engine
            .handle_event(CoreEvent::AppStarted)
            .expect("app started");
        assert!(
            !started
                .effects
                .iter()
                .any(|effect| matches!(effect, CoreEffect::OpenGroupRealtimeConnection { .. })),
            "AppStarted must not open every group websocket without a UI plan"
        );

        let planned = alice
            .engine
            .handle_command(CoreCommand::ApplyGroupRealtimePlan {
                websocket_group_ids: vec![group_id.clone()],
            })
            .expect("apply realtime plan");
        assert!(planned.effects.iter().any(|effect| {
            matches!(effect, CoreEffect::OpenGroupRealtimeConnection { subscription }
                if subscription.group_id == group_id)
        }));

        alice
            .engine
            .handle_event(CoreEvent::GroupWebSocketConnected {
                group_id: group_id.clone(),
            })
            .expect("group websocket connected");
        let closed = alice
            .engine
            .handle_command(CoreCommand::ApplyGroupRealtimePlan {
                websocket_group_ids: vec![],
            })
            .expect("clear realtime plan");
        assert!(closed.effects.iter().any(|effect| {
            matches!(effect, CoreEffect::CloseGroupRealtimeConnection { group_id: closed_id }
                if closed_id == &group_id)
        }));
    }

    #[test]
    fn group_websocket_disconnect_schedules_group_sync_fallback() {
        let mut alice = harness_user("alice", ALICE_MNEMONIC, "phone");
        let mut bob = harness_user("bob", BOB_MNEMONIC, "phone");
        import_peer_bundles(&mut [&mut alice, &mut bob]);
        let mut harness = GroupHarness::with_bundles(&[&alice, &bob].map(|u| HarnessUser {
            name: u.name,
            bundle: u.bundle.clone(),
            engine: CoreEngine::new(),
        }));
        let (group_id, _conversation_id) =
            harness.create_group(&mut alice, "Project", vec![bob.bundle.user_id.clone()]);

        let output = alice
            .engine
            .handle_event(CoreEvent::GroupWebSocketDisconnected {
                group_id: group_id.clone(),
                error: Some("network".into()),
            })
            .expect("group websocket disconnected");
        assert!(output.effects.iter().any(|effect| {
            matches!(effect, CoreEffect::ScheduleTimer { timer }
                if timer.timer_id == format!("group_sync:{group_id}"))
        }));
    }

    #[test]
    fn group_recovery_restores_pending_group_seal() {
        let mut alice = harness_user("alice", ALICE_MNEMONIC, "phone");
        let mut bob = harness_user("bob", BOB_MNEMONIC, "phone");
        import_peer_bundles(&mut [&mut alice, &mut bob]);
        let mut harness = GroupHarness::with_bundles(&[&alice, &bob].map(|u| HarnessUser {
            name: u.name,
            bundle: u.bundle.clone(),
            engine: CoreEngine::new(),
        }));
        let (group_id, _conversation_id) =
            harness.create_group(&mut alice, "Project", vec![bob.bundle.user_id.clone()]);
        harness.import_welcome(&mut bob, &group_id);
        harness.sync_group(&mut bob, &group_id);

        let dissolve = alice
            .engine
            .handle_command(CoreCommand::DissolveGroup {
                group_id: group_id.clone(),
            })
            .expect("dissolve");
        assert!(dissolve.effects.iter().any(|effect| {
            matches!(effect, CoreEffect::AppendGroupTransition { append } if append.group_id == group_id)
        }));
        assert!(
            alice
                .engine
                .state
                .pending_group_seal
                .contains_key(&group_id)
        );

        let snapshot = alice.engine.refresh_snapshot();
        assert!(
            snapshot
                .pending_group_seal
                .iter()
                .any(|seal| seal.group_id == group_id)
        );
        let mut restored = CoreEngine::try_from_restored_state(snapshot).expect("restore snapshot");
        assert!(restored.state.pending_group_seal.contains_key(&group_id));
        let resumed = restored
            .handle_event(CoreEvent::AppStarted)
            .expect("app started");
        assert!(
            !resumed
                .effects
                .iter()
                .any(|effect| matches!(effect, CoreEffect::SealGroupOutbox { .. })),
            "seal must not run while restored group outbox entries are still pending"
        );
    }

    #[test]
    fn group_recovery_replays_pending_attachment_download_on_app_started() {
        let mut alice = harness_user("alice", ALICE_MNEMONIC, "phone");
        let mut bob = harness_user("bob", BOB_MNEMONIC, "phone");
        import_peer_bundles(&mut [&mut alice, &mut bob]);
        let mut harness = GroupHarness::with_bundles(&[&alice, &bob].map(|u| HarnessUser {
            name: u.name,
            bundle: u.bundle.clone(),
            engine: CoreEngine::new(),
        }));
        let (group_id, conversation_id) =
            harness.create_group(&mut alice, "Project", vec![bob.bundle.user_id.clone()]);
        harness.import_welcome(&mut bob, &group_id);
        harness.sync_group(&mut bob, &group_id);
        harness.send_attachment(&mut alice, &conversation_id, sample_attachment_descriptor());
        harness.sync_group(&mut bob, &group_id);
        let (message_id, reference) = group_attachment_message(&bob, &conversation_id);

        let download = bob
            .engine
            .handle_command(CoreCommand::DownloadAttachment {
                conversation_id: conversation_id.clone(),
                message_id: message_id.clone(),
                reference: reference.clone(),
                destination: "bob/recovered/file.bin".into(),
            })
            .expect("download attachment");
        assert!(download.effects.iter().any(|effect| {
            matches!(effect, CoreEffect::DownloadBlob { download } if download.blob_ref == reference)
        }));
        let snapshot = bob.engine.refresh_snapshot();
        assert_eq!(snapshot.pending_blob_transfers.len(), 1);

        let mut restored = CoreEngine::try_from_restored_state(snapshot).expect("restore snapshot");
        let resumed = restored
            .handle_event(CoreEvent::AppStarted)
            .expect("app started");
        let download = resumed
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::DownloadBlob { download } => Some(download.clone()),
                _ => None,
            })
            .expect("restored download effect");
        let blob_ciphertext = harness
            .blobs
            .get(&download.blob_ref)
            .cloned()
            .expect("stored group attachment blob");
        let completed = restored
            .handle_event(CoreEvent::BlobDownloaded {
                task_id: download.task_id,
                blob_ciphertext: Some(blob_ciphertext),
            })
            .expect("blob downloaded");
        assert!(completed.effects.iter().any(|effect| {
            matches!(effect, CoreEffect::WriteDownloadedAttachment { write }
                if write.destination_id == "bob/recovered/file.bin")
        }));
    }

    #[test]
    fn group_member_management_remove_e2e() {
        let mut alice = harness_user("alice", ALICE_MNEMONIC, "phone");
        let mut bob = harness_user("bob", BOB_MNEMONIC, "phone");
        let mut carol = harness_user("carol", CAROL_MNEMONIC, "phone");
        import_peer_bundles(&mut [&mut alice, &mut bob, &mut carol]);
        let mut harness =
            GroupHarness::with_bundles(&[&alice, &bob, &carol].map(|u| HarnessUser {
                name: u.name,
                bundle: u.bundle.clone(),
                engine: CoreEngine::new(),
            }));
        let (group_id, conversation_id) = harness.create_group(
            &mut alice,
            "Project",
            vec![bob.bundle.user_id.clone(), carol.bundle.user_id.clone()],
        );
        harness.import_welcome(&mut bob, &group_id);
        harness.import_welcome(&mut carol, &group_id);
        harness.sync_group(&mut bob, &group_id);
        harness.sync_group(&mut carol, &group_id);

        let member_remove_error = bob
            .engine
            .handle_command(CoreCommand::RemoveGroupMember {
                group_id: group_id.clone(),
                target_user_id: carol.bundle.user_id.clone(),
            })
            .expect_err("member remove must fail");
        assert_eq!(member_remove_error.code(), "invalid_input");

        let alice_roster = group_roster_version(&alice, &group_id);
        let carol_roster = group_roster_version(&carol, &group_id);
        harness.append_forged_membership_record(&group_id, &conversation_id, &bob);
        harness.sync_group(&mut alice, &group_id);
        harness.sync_group(&mut carol, &group_id);
        assert_eq!(group_roster_version(&alice, &group_id), alice_roster);
        assert_eq!(group_roster_version(&carol, &group_id), carol_roster);

        let remove_output = alice
            .engine
            .handle_command(CoreCommand::RemoveGroupMember {
                group_id: group_id.clone(),
                target_user_id: carol.bundle.user_id.clone(),
            })
            .expect("owner removes carol");
        assert!(remove_output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::AppendGroupTransition { append }
                if append.envelopes.iter().any(|envelope| envelope.message_type == GroupMessageType::MlsCommit)
                    && append.envelopes.iter().any(|envelope| envelope.message_type == GroupMessageType::ControlGroupMembershipChanged)
        )));
        harness.drain(&mut alice, remove_output);
        harness.sync_group(&mut bob, &group_id);
        harness.send_text(&mut alice, &conversation_id, "after remove from alice");
        harness.sync_group(&mut bob, &group_id);
        harness.send_text(&mut bob, &conversation_id, "after remove from bob");
        harness.sync_group(&mut alice, &group_id);
        assert!(
            group_plaintexts(&bob, &conversation_id)
                .iter()
                .any(|text| text == "after remove from alice")
        );
        assert!(
            group_plaintexts(&alice, &conversation_id)
                .iter()
                .any(|text| text == "after remove from bob")
        );

        let carol_before = group_plaintexts(&carol, &conversation_id);
        let _ = carol
            .engine
            .handle_command(CoreCommand::SyncGroupOutbox {
                group_id: group_id.clone(),
                reason: Some("removed member sync".into()),
            })
            .and_then(|output| Ok(harness.drain(&mut carol, output)));
        assert_eq!(
            group_plaintexts(&carol, &conversation_id),
            carol_before,
            "removed member must not see post-remove plaintext"
        );
        assert!(
            carol
                .engine
                .handle_command(CoreCommand::SendGroupTextMessage {
                    conversation_id: conversation_id.clone(),
                    plaintext: "removed sender".into(),
                })
                .is_err(),
            "removed member must not be able to send"
        );
        assert!(
            carol
                .engine
                .handle_command(CoreCommand::SendAttachmentMessage {
                    conversation_id,
                    attachment_descriptor: sample_attachment_descriptor(),
                })
                .is_err(),
            "removed member must not be able to send attachments"
        );
    }

    #[test]
    fn group_member_management_leave_transfer_and_admin_e2e() {
        let mut alice = harness_user("alice", ALICE_MNEMONIC, "phone");
        let mut bob = harness_user("bob", BOB_MNEMONIC, "phone");
        let mut carol = harness_user("carol", CAROL_MNEMONIC, "phone");
        let mut dana = harness_user("dana", DANA_MNEMONIC, "phone");
        import_peer_bundles(&mut [&mut alice, &mut bob, &mut carol, &mut dana]);
        let mut harness =
            GroupHarness::with_bundles(&[&alice, &bob, &carol, &dana].map(|u| HarnessUser {
                name: u.name,
                bundle: u.bundle.clone(),
                engine: CoreEngine::new(),
            }));
        let (group_id, conversation_id) = harness.create_group(
            &mut alice,
            "Project",
            vec![
                bob.bundle.user_id.clone(),
                carol.bundle.user_id.clone(),
                dana.bundle.user_id.clone(),
            ],
        );
        harness.import_welcome(&mut bob, &group_id);
        harness.import_welcome(&mut carol, &group_id);
        harness.import_welcome(&mut dana, &group_id);
        harness.sync_group(&mut bob, &group_id);
        harness.sync_group(&mut carol, &group_id);
        harness.sync_group(&mut dana, &group_id);

        let bob_leave = bob
            .engine
            .handle_command(CoreCommand::LeaveGroup {
                group_id: group_id.clone(),
            })
            .expect("bob leaves");
        harness.drain(&mut bob, bob_leave);
        assert_eq!(
            bob.engine
                .state
                .group_states
                .get(&group_id)
                .expect("bob group")
                .local_role,
            Some(GroupRole::Member),
            "submitting a leave request must not mutate canonical membership"
        );
        let leave_request_id = harness
            .leave_requests
            .values()
            .find(|request| request.leaver_user_id == bob.bundle.user_id)
            .map(|request| request.request_id.clone())
            .expect("bob leave request");
        harness.list_leave_requests(&mut alice, &group_id);
        harness.approve_leave(&mut alice, &group_id, &leave_request_id);
        harness.sync_group(&mut bob, &group_id);
        let bob_state = bob
            .engine
            .state
            .group_states
            .get(&group_id)
            .expect("bob group");
        assert_eq!(bob_state.local_role, None);
        assert_eq!(
            bob.engine.state.conversations[&conversation_id]
                .conversation
                .state,
            ConversationState::Closed
        );
        assert!(
            bob.engine
                .handle_command(CoreCommand::SendGroupTextMessage {
                    conversation_id: conversation_id.clone(),
                    plaintext: "left member text".into(),
                })
                .is_err(),
            "left member must not send group text"
        );
        assert!(
            bob.engine
                .handle_command(CoreCommand::SendAttachmentMessage {
                    conversation_id: conversation_id.clone(),
                    attachment_descriptor: sample_attachment_descriptor(),
                })
                .is_err(),
            "left member must not send group attachments"
        );
        assert!(
            !alice.engine.state.group_states[&group_id]
                .manifest
                .members
                .iter()
                .any(|member| {
                    member.user_id == bob.bundle.user_id
                        && member.status == GroupMemberStatus::Active
                })
        );

        assert!(
            carol
                .engine
                .handle_command(CoreCommand::SetGroupAdmin {
                    group_id: group_id.clone(),
                    target_user_id: dana.bundle.user_id.clone(),
                    is_admin: true,
                })
                .is_err(),
            "plain member must not appoint admins"
        );
        let promote = alice
            .engine
            .handle_command(CoreCommand::SetGroupAdmin {
                group_id: group_id.clone(),
                target_user_id: carol.bundle.user_id.clone(),
                is_admin: true,
            })
            .expect("owner promotes carol");
        harness.drain(&mut alice, promote);
        harness.sync_group(&mut carol, &group_id);
        assert_eq!(
            carol
                .engine
                .state
                .group_states
                .get(&group_id)
                .expect("carol group")
                .local_role,
            Some(GroupRole::Admin)
        );
        let admin_remove = carol
            .engine
            .handle_command(CoreCommand::RemoveGroupMember {
                group_id: group_id.clone(),
                target_user_id: dana.bundle.user_id.clone(),
            })
            .expect("admin removes dana");
        harness.drain(&mut carol, admin_remove);
        assert!(
            carol
                .engine
                .state
                .group_states
                .get(&group_id)
                .expect("carol group")
                .manifest
                .members
                .iter()
                .any(|member| member.user_id == dana.bundle.user_id
                    && member.status == GroupMemberStatus::Removed)
        );

        let mut owner = harness_user("owner", ALICE_MNEMONIC, "phone");
        let mut successor = harness_user("successor", BOB_MNEMONIC, "phone");
        import_peer_bundles(&mut [&mut owner, &mut successor]);
        let mut transfer_harness =
            GroupHarness::with_bundles(&[&owner, &successor].map(|u| HarnessUser {
                name: u.name,
                bundle: u.bundle.clone(),
                engine: CoreEngine::new(),
            }));
        let (transfer_group_id, transfer_conversation_id) = transfer_harness.create_group(
            &mut owner,
            "Transfer Project",
            vec![successor.bundle.user_id.clone()],
        );
        transfer_harness.import_welcome(&mut successor, &transfer_group_id);
        transfer_harness.sync_group(&mut successor, &transfer_group_id);

        let transfer = owner
            .engine
            .handle_command(CoreCommand::TransferGroupOwnership {
                group_id: transfer_group_id.clone(),
                new_owner_user_id: successor.bundle.user_id.clone(),
            })
            .expect("transfer ownership to successor");
        transfer_harness.drain(&mut owner, transfer);
        transfer_harness.sync_group(&mut successor, &transfer_group_id);
        assert_eq!(
            owner
                .engine
                .state
                .group_states
                .get(&transfer_group_id)
                .expect("owner group")
                .local_role,
            Some(GroupRole::Admin)
        );
        assert_eq!(
            successor
                .engine
                .state
                .group_states
                .get(&transfer_group_id)
                .expect("successor group")
                .local_role,
            Some(GroupRole::Owner)
        );
        assert!(
            owner
                .engine
                .handle_command(CoreCommand::SetGroupAdmin {
                    group_id: transfer_group_id.clone(),
                    target_user_id: successor.bundle.user_id.clone(),
                    is_admin: false,
                })
                .is_err(),
            "former owner must not perform owner-only admin changes"
        );
        let former_owner_leave = owner
            .engine
            .handle_command(CoreCommand::LeaveGroup {
                group_id: transfer_group_id.clone(),
            })
            .expect("former owner can request leave after transfer");
        transfer_harness.drain(&mut owner, former_owner_leave);
        let leave_request_id = transfer_harness
            .leave_requests
            .values()
            .find(|request| request.leaver_user_id == owner.bundle.user_id)
            .map(|request| request.request_id.clone())
            .expect("former owner leave request");
        transfer_harness.list_leave_requests(&mut successor, &transfer_group_id);
        transfer_harness.approve_leave(&mut successor, &transfer_group_id, &leave_request_id);
        transfer_harness.sync_group(&mut owner, &transfer_group_id);
        assert!(
            successor
                .engine
                .handle_command(CoreCommand::DissolveGroup {
                    group_id: transfer_group_id.clone()
                })
                .is_ok(),
            "new owner can perform owner-only dissolve"
        );
        assert!(
            owner
                .engine
                .handle_command(CoreCommand::SendGroupTextMessage {
                    conversation_id: transfer_conversation_id,
                    plaintext: "former owner after leave".into(),
                })
                .is_err(),
            "former owner must not send after leaving"
        );
    }

    #[test]
    fn group_invite_approval_adds_dana_e2e() {
        let mut alice = harness_user("alice", ALICE_MNEMONIC, "phone");
        let mut bob = harness_user("bob", BOB_MNEMONIC, "phone");
        let mut carol = harness_user("carol", CAROL_MNEMONIC, "phone");
        let mut dana = harness_user("dana", DANA_MNEMONIC, "phone");
        import_peer_bundles(&mut [&mut alice, &mut bob, &mut carol, &mut dana]);
        let mut harness =
            GroupHarness::with_bundles(&[&alice, &bob, &carol, &dana].map(|u| HarnessUser {
                name: u.name,
                bundle: u.bundle.clone(),
                engine: CoreEngine::new(),
            }));

        let (group_id, conversation_id) = harness.create_group(
            &mut alice,
            "Project",
            vec![bob.bundle.user_id.clone(), carol.bundle.user_id.clone()],
        );
        harness.import_welcome(&mut bob, &group_id);
        harness.import_welcome(&mut carol, &group_id);
        harness.sync_group(&mut bob, &group_id);
        harness.sync_group(&mut carol, &group_id);

        let invite_url = harness.create_invite(&mut alice, &group_id);
        let request_id = harness.submit_join(&mut dana, &invite_url);
        assert_eq!(
            harness.join_requests[&request_id].status,
            GroupJoinRequestStatus::PendingApproval
        );
        assert!(!harness.join_decisions.contains_key(&request_id));

        harness.list_join_requests(&mut alice, &group_id);
        assert!(
            bob.engine
                .handle_command(CoreCommand::ApproveGroupJoin {
                    group_id: group_id.clone(),
                    request_id: request_id.clone(),
                })
                .is_err(),
            "member must not approve joins"
        );

        harness.approve_join(&mut alice, &group_id, &request_id);
        let decision = harness
            .join_decisions
            .get(&request_id)
            .expect("approval decision");
        assert_eq!(
            decision.request.status,
            GroupJoinRequestStatus::WelcomeAvailable
        );
        assert!(decision.welcome_pickup.is_some());
        assert!(decision.manifest.is_some());
        assert!(decision.start_cursor.is_some());

        harness.fetch_join_status(&mut dana, &group_id, &request_id);
        harness.sync_group(&mut alice, &group_id);
        harness.sync_group(&mut bob, &group_id);
        harness.sync_group(&mut carol, &group_id);
        harness.send_text(&mut dana, &conversation_id, "from dana");
        harness.sync_group(&mut alice, &group_id);
        harness.sync_group(&mut bob, &group_id);
        harness.sync_group(&mut carol, &group_id);
        harness.send_text(&mut alice, &conversation_id, "welcome dana");
        harness.sync_group(&mut dana, &group_id);

        for user in [&alice, &bob, &carol] {
            assert!(
                group_plaintexts(user, &conversation_id)
                    .iter()
                    .any(|text| text == "from dana"),
                "{} did not receive Dana's text",
                user.name
            );
        }
        assert!(
            group_plaintexts(&dana, &conversation_id)
                .iter()
                .any(|text| text == "welcome dana"),
            "Dana did not receive post-approval text"
        );
    }

    #[test]
    fn send_text_message_emits_append_request() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        let output = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "hello".into(),
            })
            .expect("send");
        assert!(output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::ExecuteHttpRequest { request }
                if request.url.contains("/messages")
                    && request.headers.contains_key("X-Tapchat-Capability")
        )));
        let pending = alice
            .state
            .pending_outbox
            .iter()
            .find(|item| item.envelope.message_type == MessageType::MlsApplication)
            .expect("pending application delivery");
        let app_message_id = pending.app_message_id.as_deref().expect("app message id");
        assert!(app_message_id.starts_with(&format!("app:{conversation_id}:")));
        assert!(app_message_id.ends_with(&format!(
            ":{}",
            alice
                .local_identity()
                .expect("local identity")
                .device_identity
                .device_id
        )));
        assert_eq!(pending.plaintext_cache.as_deref(), Some("hello"));
        assert_ne!(pending.envelope.message_id, app_message_id);
        let visible = &output.view_model.as_ref().expect("view model").messages;
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].conversation_id, conversation_id);
        assert_eq!(visible[0].message_id, app_message_id);
        assert_eq!(visible[0].message_type, MessageType::MlsApplication);
    }

    #[test]
    fn non_retryable_append_failure_marks_outbox_delivery_failed() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        let output = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id,
                plaintext: "hello".into(),
            })
            .expect("send");
        let request_id = output
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::ExecuteHttpRequest { request } => Some(request.request_id.clone()),
                _ => None,
            })
            .expect("append request");
        alice
            .handle_event(CoreEvent::HttpRequestFailed {
                request_id,
                failure: test_failure("device_revoked", false, Some(403)),
            })
            .expect("terminal append failure");
        let pending = alice
            .state
            .pending_outbox
            .iter()
            .find(|item| item.envelope.message_type == MessageType::MlsApplication)
            .expect("failed outbox delivery remains visible");
        assert!(!pending.in_flight);
        assert_eq!(pending.retries, crate::ffi_api::MAX_TRANSPORT_RETRIES);
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
    fn create_conversation_reuses_existing_direct_conversation_without_mls() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        alice.state.mls_summaries.remove(&conversation_id);

        let output = alice
            .handle_command(CoreCommand::CreateConversation {
                peer_user_id: bob_bundle.user_id.clone(),
                conversation_kind: ConversationKind::Direct,
            })
            .expect("reuse existing conversation");

        assert_eq!(alice.state.conversations.len(), 1);
        assert_eq!(
            output
                .view_model
                .as_ref()
                .expect("view model")
                .conversations[0]
                .conversation_id,
            conversation_id
        );
        assert_eq!(
            output
                .view_model
                .as_ref()
                .expect("view model")
                .conversations[0]
                .state,
            "needs_recovery"
        );
        assert!(alice.state.recovery_contexts.contains_key(&conversation_id));
        let ops = persist_ops(&output);
        assert!(ops.iter().any(|op| matches!(
            op,
            PersistOp::SaveConversation { conversation_id: saved }
                if saved == &conversation_id
        )));
        assert!(ops.iter().any(|op| matches!(
            op,
            PersistOp::SaveRecoveryContext { conversation_id: saved }
                if saved == &conversation_id
        )));
    }

    #[test]
    fn delete_contact_then_reimport_same_peer_allows_direct_recreate() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        alice
            .state
            .contacts
            .get_mut(&bob_bundle.user_id)
            .expect("bob contact")
            .display_name = Some("Bobby".into());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "pending before delete".into(),
            })
            .expect("queue pending message");
        assert!(!alice.state.pending_outbox.is_empty());

        let delete_output = alice
            .handle_command(CoreCommand::DeleteContact {
                user_id: bob_bundle.user_id.clone(),
            })
            .expect("delete contact");
        assert!(
            delete_output
                .effects
                .iter()
                .any(|effect| matches!(effect, CoreEffect::FetchAllowlist { .. }))
        );
        assert!(!alice.state.contacts.contains_key(&bob_bundle.user_id));
        let archived = alice
            .state
            .conversations
            .get(&conversation_id)
            .expect("conversation retained");
        assert_eq!(
            archived.conversation.state,
            crate::model::ConversationState::Archived
        );
        assert_eq!(
            archived
                .archive_metadata
                .as_ref()
                .and_then(|metadata| metadata.peer_display_name.as_deref()),
            Some("Bobby")
        );
        assert!(archived.messages.iter().any(|message| {
            message.message_type == MessageType::ControlContactRemoved
                && message
                    .plaintext
                    .as_deref()
                    .is_some_and(|text| text.contains("archived"))
        }));
        assert!(!alice.state.mls_summaries.contains_key(&conversation_id));
        assert!(
            alice
                .state
                .pending_outbox
                .iter()
                .all(|item| { item.envelope.message_type == MessageType::ControlContactRemoved })
        );
        let pending_after_delete = alice.state.pending_outbox.len();
        let send_err = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "blocked".into(),
            })
            .expect_err("closed relationship blocks send");
        assert_eq!(send_err.code(), "relationship_closed");
        assert_eq!(alice.state.pending_outbox.len(), pending_after_delete);

        let allowlist_output = alice
            .handle_event(CoreEvent::AllowlistFetched {
                document: crate::transport_contract::AllowlistDocument {
                    allowed_sender_user_ids: vec![bob_bundle.user_id.clone()],
                    rejected_sender_user_ids: vec![],
                },
            })
            .expect("allowlist fetched");
        let replace = allowlist_output
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::ReplaceAllowlist { update } => Some(update),
                _ => None,
            })
            .expect("replace allowlist effect");
        assert!(replace.document.allowed_sender_user_ids.is_empty());
        assert!(replace.document.rejected_sender_user_ids.is_empty());

        let snapshot = alice.refresh_snapshot();
        assert!(
            snapshot
                .conversations
                .iter()
                .any(|conversation| conversation.conversation_id == conversation_id)
        );
        assert!(
            !snapshot
                .contacts
                .iter()
                .any(|contact| contact.user_id == bob_bundle.user_id)
        );
        assert!(
            !snapshot
                .mls_states
                .iter()
                .any(|state| state.conversation_id == conversation_id)
        );
        assert!(
            snapshot
                .pending_outbox
                .iter()
                .all(|item| { item.envelope.message_type == MessageType::ControlContactRemoved })
        );

        let refreshed_bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "laptop");
        alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: refreshed_bob_bundle.clone(),
            })
            .expect("reimport contact");
        assert_eq!(
            alice
                .state
                .contacts
                .get(&refreshed_bob_bundle.user_id)
                .expect("contact")
                .relationship_status,
            ContactRelationshipStatus::Available
        );
        let recreated =
            create_direct_conversation(&mut alice, refreshed_bob_bundle.user_id.clone());
        assert_ne!(recreated, conversation_id);
        assert!(alice.mls_summary(&recreated).is_some());
        assert_eq!(
            alice
                .state
                .conversations
                .get(&conversation_id)
                .expect("archived conversation")
                .conversation
                .state,
            crate::model::ConversationState::Archived
        );
        assert_eq!(
            alice
                .state
                .conversations
                .get(&recreated)
                .expect("conversation")
                .conversation
                .state,
            crate::model::ConversationState::Active
        );
    }

    #[test]
    fn delete_contact_cleans_mls_even_when_conversation_row_is_missing() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        alice.state.conversations.remove(&conversation_id);

        alice
            .handle_command(CoreCommand::DeleteContact {
                user_id: bob_bundle.user_id.clone(),
            })
            .expect("delete contact");
        assert!(!alice.state.contacts.contains_key(&bob_bundle.user_id));
        assert!(!alice.state.mls_summaries.contains_key(&conversation_id));

        let refreshed_bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "laptop");
        alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: refreshed_bob_bundle.clone(),
            })
            .expect("reimport contact");
        let recreated =
            create_direct_conversation(&mut alice, refreshed_bob_bundle.user_id.clone());
        assert_ne!(recreated, conversation_id);
    }

    #[test]
    fn app_started_migrates_legacy_removed_contact_to_archive() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        alice
            .state
            .contacts
            .get_mut(&bob_bundle.user_id)
            .expect("bob contact")
            .relationship_status = ContactRelationshipStatus::RemovedByMe;
        alice
            .state
            .conversations
            .get_mut(&conversation_id)
            .expect("conversation")
            .conversation
            .state = crate::model::ConversationState::Closed;

        let output = alice
            .handle_event(CoreEvent::AppStarted)
            .expect("migrate legacy removed contact");

        assert!(!alice.state.contacts.contains_key(&bob_bundle.user_id));
        let archived = alice
            .state
            .conversations
            .get(&conversation_id)
            .expect("archived conversation");
        assert_eq!(
            archived.conversation.state,
            crate::model::ConversationState::Archived
        );
        assert!(archived.messages.iter().any(|message| {
            message.message_id.ends_with(":system:legacy_archive")
                && message
                    .plaintext
                    .as_deref()
                    .is_some_and(|text| text.contains("archived"))
        }));
        assert!(!alice.state.mls_summaries.contains_key(&conversation_id));
        assert!(
            output
                .effects
                .iter()
                .any(|effect| matches!(effect, CoreEffect::FetchAllowlist { .. }))
        );

        let allowlist_output = alice
            .handle_event(CoreEvent::AllowlistFetched {
                document: crate::transport_contract::AllowlistDocument {
                    allowed_sender_user_ids: vec![bob_bundle.user_id.clone()],
                    rejected_sender_user_ids: vec![bob_bundle.user_id.clone()],
                },
            })
            .expect("legacy allowlist cleanup");
        let replace = allowlist_output
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::ReplaceAllowlist { update } => Some(update),
                _ => None,
            })
            .expect("replace allowlist effect");
        assert!(replace.document.allowed_sender_user_ids.is_empty());
        assert!(replace.document.rejected_sender_user_ids.is_empty());
    }

    #[test]
    fn received_contact_removed_control_closes_relationship_and_blocks_send() {
        let mut alice = local_engine(ALICE_MNEMONIC, "phone");
        let alice_bundle = alice.local_bundle().expect("alice bundle").clone();
        let mut bob = local_engine(BOB_MNEMONIC, "phone");
        let bob_bundle = bob.local_bundle().expect("bob bundle").clone();
        alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: bob_bundle.clone(),
            })
            .expect("alice imports bob");
        bob.handle_command(CoreCommand::ImportIdentityBundle {
            bundle: alice_bundle.clone(),
        })
        .expect("bob imports alice");
        bob.state
            .contacts
            .get_mut(&alice_bundle.user_id)
            .expect("alice contact")
            .display_name = Some("Alice".into());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        assert_eq!(
            create_direct_conversation(&mut bob, alice_bundle.user_id.clone()),
            conversation_id
        );

        alice
            .handle_command(CoreCommand::DeleteContact {
                user_id: bob_bundle.user_id.clone(),
            })
            .expect("alice deletes bob");
        let bob_device_id = bob.local_device_id().expect("bob device").to_string();
        deliver_pending_outbox_to_device(&mut bob, &alice, &bob_device_id);

        assert!(!bob.state.contacts.contains_key(&alice_bundle.user_id));
        let bob_conversation = bob
            .state
            .conversations
            .get(&conversation_id)
            .expect("bob conversation");
        assert_eq!(
            bob_conversation.conversation.state,
            crate::model::ConversationState::Archived
        );
        assert_eq!(
            bob_conversation
                .archive_metadata
                .as_ref()
                .and_then(|metadata| metadata.peer_display_name.as_deref()),
            Some("Alice")
        );
        assert!(bob_conversation.messages.iter().any(|message| {
            message.message_type == MessageType::ControlContactRemoved
                && message
                    .plaintext
                    .as_deref()
                    .is_some_and(|text| text.contains("archived"))
        }));
        assert!(!bob.state.mls_summaries.contains_key(&conversation_id));
        let send_err = bob
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id,
                plaintext: "blocked".into(),
            })
            .expect_err("removed by peer blocks send");
        assert_eq!(send_err.code(), "relationship_closed");
    }

    #[test]
    fn duplicate_contact_removed_after_archive_is_acked_without_contact_bundle() {
        let mut alice = local_engine(ALICE_MNEMONIC, "phone");
        let alice_bundle = alice.local_bundle().expect("alice bundle").clone();
        let mut bob = local_engine(BOB_MNEMONIC, "phone");
        let bob_bundle = bob.local_bundle().expect("bob bundle").clone();
        alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: bob_bundle.clone(),
            })
            .expect("alice imports bob");
        bob.handle_command(CoreCommand::ImportIdentityBundle {
            bundle: alice_bundle.clone(),
        })
        .expect("bob imports alice");
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        assert_eq!(
            create_direct_conversation(&mut bob, alice_bundle.user_id.clone()),
            conversation_id
        );

        alice
            .handle_command(CoreCommand::DeleteContact {
                user_id: bob_bundle.user_id.clone(),
            })
            .expect("alice deletes bob");
        let mut control_envelope = alice
            .state
            .pending_outbox
            .iter()
            .find(|item| item.envelope.message_type == MessageType::ControlContactRemoved)
            .expect("control envelope")
            .envelope
            .clone();
        let bob_device_id = bob.local_device_id().expect("bob device").to_string();
        deliver_pending_outbox_to_device(&mut bob, &alice, &bob_device_id);
        assert!(!bob.state.contacts.contains_key(&alice_bundle.user_id));
        let message_count_before = bob
            .state
            .conversations
            .get(&conversation_id)
            .expect("archived conversation")
            .messages
            .len();
        control_envelope.message_id = format!("{}:duplicate", control_envelope.message_id);

        bob.handle_event(CoreEvent::InboxRecordsFetched {
            device_id: bob_device_id.clone(),
            to_seq: 2,
            records: vec![InboxRecord {
                seq: 2,
                recipient_device_id: bob_device_id.clone(),
                message_id: control_envelope.message_id.clone(),
                received_at: 2,
                expires_at: None,
                state: InboxRecordState::Available,
                envelope: control_envelope,
            }],
        })
        .expect("duplicate control ignored");

        assert_eq!(
            bob.state
                .conversations
                .get(&conversation_id)
                .expect("archived conversation")
                .messages
                .len(),
            message_count_before
        );
        let sync_state = bob
            .state
            .sync_states
            .get(&bob_device_id)
            .expect("sync state");
        assert_eq!(sync_state.checkpoint.last_acked_seq, 2);
        assert!(!sync_state.pending_retry);
    }

    #[test]
    fn pending_outbound_relationship_allows_session_setup_but_blocks_user_messages() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = local_engine(ALICE_MNEMONIC, "phone");
        alice
            .handle_command(CoreCommand::ImportIdentityBundleWithRelationshipStatus {
                bundle: bob_bundle.clone(),
                relationship_status: ContactRelationshipStatus::PendingOutbound,
            })
            .expect("import pending outbound");
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        assert!(alice.state.pending_outbox.iter().any(|item| matches!(
            item.envelope.message_type,
            MessageType::MlsCommit | MessageType::MlsWelcome
        )));

        let pending_count = alice.state.pending_outbox.len();
        let send_err = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id,
                plaintext: "too early".into(),
            })
            .expect_err("pending outbound blocks normal messages");
        assert_eq!(send_err.code(), "relationship_closed");
        assert_eq!(alice.state.pending_outbox.len(), pending_count);
    }

    #[test]
    fn accept_without_promoted_conversation_ids_does_not_send_base_id_control() {
        let mut alice = local_engine(ALICE_MNEMONIC, "phone");
        let bob = local_engine(BOB_MNEMONIC, "phone");
        let bob_bundle = bob.local_bundle().expect("bob bundle").clone();
        alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: bob_bundle.clone(),
            })
            .expect("alice imports bob");
        let mut result = accepted_request_result(&bob_bundle.user_id, "unused");
        result.promoted_conversation_ids.clear();

        alice
            .handle_event(CoreEvent::MessageRequestActionCompleted { result })
            .expect("accept without promoted ids");

        assert!(
            alice
                .state
                .pending_outbox
                .iter()
                .all(|item| item.envelope.message_type != MessageType::ControlContactAccepted),
            "missing promoted ids must not fall back to the legacy base direct conversation id"
        );
        assert!(bob.state.pending_outbox.is_empty());
    }

    #[test]
    fn accept_with_multiple_promoted_direct_conversations_sends_compatibility_controls() {
        let mut alice = local_engine(ALICE_MNEMONIC, "phone");
        let bob = local_engine(BOB_MNEMONIC, "phone");
        let bob_bundle = bob.local_bundle().expect("bob bundle").clone();
        alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: bob_bundle.clone(),
            })
            .expect("alice imports bob");

        let mut result =
            accepted_request_result(&bob_bundle.user_id, "conv:user:alice:user:bob:rel:1");
        result.promoted_count = 2;
        result.promoted_conversation_ids = vec![
            "conv:user:alice:user:bob:rel:1".into(),
            "conv:user:alice:user:bob:rel:2".into(),
        ];
        alice
            .handle_event(CoreEvent::MessageRequestActionCompleted { result })
            .expect("accept with multiple promoted ids");

        let accepted_envelopes = alice
            .state
            .pending_outbox
            .iter()
            .filter(|item| item.envelope.message_type == MessageType::ControlContactAccepted)
            .collect::<Vec<_>>();
        assert_eq!(accepted_envelopes.len(), 2);
        let mut conversation_ids = accepted_envelopes
            .iter()
            .map(|item| {
                let payload_b64 = item
                    .envelope
                    .inline_ciphertext
                    .as_deref()
                    .expect("accepted payload");
                let payload = STANDARD.decode(payload_b64).expect("payload base64");
                let payload: serde_json::Value =
                    serde_json::from_slice(&payload).expect("accepted payload json");
                payload["conversation_id"]
                    .as_str()
                    .expect("conversation id")
                    .to_string()
            })
            .collect::<Vec<_>>();
        conversation_ids.sort();
        assert_eq!(
            conversation_ids,
            vec![
                "conv:user:alice:user:bob:rel:1".to_string(),
                "conv:user:alice:user:bob:rel:2".to_string(),
            ]
        );
    }

    #[test]
    fn create_direct_conversation_prefers_healthy_mls_conversation_for_peer() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let healthy_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        let mut stale = alice
            .state
            .conversations
            .get(&healthy_id)
            .expect("healthy conversation")
            .clone();
        let stale_id = "conv:000-stale-direct".to_string();
        stale.conversation.conversation_id = stale_id.clone();
        stale.conversation.updated_at = stale.conversation.updated_at.saturating_add(10_000);
        stale.recovery_status = RecoveryStatus::NeedsRecovery;
        alice.state.conversations.insert(stale_id, stale);

        let output = alice
            .handle_command(CoreCommand::CreateConversation {
                peer_user_id: bob_bundle.user_id.clone(),
                conversation_kind: ConversationKind::Direct,
            })
            .expect("reuse best direct conversation");

        assert_eq!(
            output
                .view_model
                .as_ref()
                .expect("view model")
                .conversations[0]
                .conversation_id,
            healthy_id
        );
        assert_eq!(
            output
                .view_model
                .as_ref()
                .expect("view model")
                .conversations[0]
                .state,
            "active"
        );
        assert!(output.effects.is_empty());
    }

    #[test]
    fn create_direct_conversation_claims_key_package_before_creating_mls_group() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());

        let output = alice
            .handle_command(CoreCommand::CreateConversation {
                peer_user_id: bob_bundle.user_id.clone(),
                conversation_kind: ConversationKind::Direct,
            })
            .expect("create conversation");

        // Nothing is visible yet: the command only issues the claim request,
        // the MLS group/conversation is not created until the claim resolves.
        assert!(output.view_model.is_none());
        assert!(alice.state.conversations.is_empty());
        assert!(alice.state.mls_summaries.is_empty());
        assert_eq!(output.effects.len(), 1);
        let request = match &output.effects[0] {
            CoreEffect::ExecuteHttpRequest { request } => request.clone(),
            other => panic!("expected a claim request, got {other:?}"),
        };
        assert_eq!(request.method, crate::ffi_api::HttpMethod::Post);
        assert!(request.url.contains("/keypackage-pool/"));
        assert!(request.url.ends_with("/claim"));
        assert!(request.auth.is_none(), "claiming a peer's pool is unauthenticated");

        let claimed_key_package_b64 = bob_bundle.devices[0]
            .keypackage_ref
            .as_ref()
            .expect("bob key package")
            .object_ref
            .clone();
        let body = serde_json::json!({
            "keyPackage": {
                "keyPackageId": "claim-1",
                "keyPackage": claimed_key_package_b64,
                "lifecycleVersion": 1,
                "notBefore": 0,
                "createdAt": 0,
                "expiresAt": 0,
            }
        })
        .to_string();
        let completed = alice
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id: request.request_id.clone(),
                status: 200,
                body: Some(body),
            })
            .expect("claim response completes conversation creation");

        let summary = completed
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .expect("conversation summary");
        assert_eq!(summary.peer_user_id, bob_bundle.user_id);
        assert_eq!(alice.state.conversations.len(), 1);
        assert!(
            alice
                .state
                .mls_summaries
                .contains_key(&summary.conversation_id)
        );
    }

    #[test]
    fn create_direct_conversation_falls_back_to_last_resort_on_pool_empty() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());

        let output = alice
            .handle_command(CoreCommand::CreateConversation {
                peer_user_id: bob_bundle.user_id.clone(),
                conversation_kind: ConversationKind::Direct,
            })
            .expect("create conversation");
        let request_id = first_http_request_id_containing(&output, "/keypackage-pool/");

        let completed = alice
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id,
                status: 404,
                body: Some(r#"{"code":"pool_empty"}"#.into()),
            })
            .expect("pool_empty falls back to the cached last-resort key package");

        let summary = completed
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .expect("conversation summary despite pool_empty");
        assert_eq!(alice.state.conversations.len(), 1);
        assert!(
            alice
                .state
                .mls_summaries
                .contains_key(&summary.conversation_id)
        );
    }

    #[test]
    fn create_direct_conversation_hard_claim_failure_aborts_without_partial_state() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());

        let output = alice
            .handle_command(CoreCommand::CreateConversation {
                peer_user_id: bob_bundle.user_id.clone(),
                conversation_kind: ConversationKind::Direct,
            })
            .expect("create conversation");
        let request_id = first_http_request_id_containing(&output, "/keypackage-pool/");

        let aborted = alice
            .handle_event(CoreEvent::HttpRequestFailed {
                request_id,
                failure: test_failure("network_unreachable", true, None),
            })
            .expect("claim failure surfaces as a notification, not a hard command error");

        assert!(aborted.view_model.is_none(), "no conversation was created");
        assert!(alice.state.conversations.is_empty());
        assert!(alice.state.mls_summaries.is_empty());
        assert_eq!(
            aborted.state_update.system_statuses_changed,
            vec![crate::ffi_api::SystemStatus::TemporaryNetworkFailure]
        );
        assert!(aborted.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::EmitUserNotification { notification }
                if notification.status == crate::ffi_api::SystemStatus::TemporaryNetworkFailure
        )));

        // No leftover pending-creation state: retrying the command starts a
        // clean new claim rather than erroring or getting stuck.
        let retry_output = alice
            .handle_command(CoreCommand::CreateConversation {
                peer_user_id: bob_bundle.user_id.clone(),
                conversation_kind: ConversationKind::Direct,
            })
            .expect("retry after abort");
        assert!(matches!(
            retry_output.effects.first(),
            Some(CoreEffect::ExecuteHttpRequest { .. })
        ));
    }

    #[test]
    fn create_group_conversation_claims_key_packages_sequentially_in_member_order() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let carol_bundle = sample_identity_bundle(CAROL_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: carol_bundle.clone(),
            })
            .expect("import carol");

        let mut ordered_members = vec![
            (bob_bundle.user_id.clone(), bob_bundle.devices[0].clone()),
            (carol_bundle.user_id.clone(), carol_bundle.devices[0].clone()),
        ];
        ordered_members.sort_by(|a, b| a.0.cmp(&b.0));
        let claim_response_for = |device: &crate::model::DeviceContactProfile| {
            serde_json::json!({
                "keyPackage": {
                    "keyPackageId": "claim",
                    "keyPackage": device
                        .keypackage_ref
                        .as_ref()
                        .expect("device key package")
                        .object_ref
                        .clone(),
                    "lifecycleVersion": 1,
                    "notBefore": 0,
                    "createdAt": 0,
                    "expiresAt": 0,
                }
            })
            .to_string()
        };

        let output = alice
            .handle_command(CoreCommand::CreateGroupConversation {
                title: "Project".into(),
                member_user_ids: vec![bob_bundle.user_id.clone(), carol_bundle.user_id.clone()],
            })
            .expect("create group");

        assert!(
            output.view_model.is_none(),
            "no group is visible before every member device's key package is resolved"
        );
        assert!(alice.state.group_states.is_empty());
        assert_eq!(
            output.effects.len(),
            1,
            "claims are strictly sequential: only one in flight at a time"
        );
        let first_request = match &output.effects[0] {
            CoreEffect::ExecuteHttpRequest { request } => request.clone(),
            other => panic!("expected a claim request, got {other:?}"),
        };
        let expected_first_device =
            urlencoding::encode(&ordered_members[0].1.device_id).into_owned();
        assert!(
            first_request.url.contains(&expected_first_device),
            "first claim must target the first member in sorted user_id order: {}",
            first_request.url
        );

        let second_output = alice
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id: first_request.request_id.clone(),
                status: 200,
                body: Some(claim_response_for(&ordered_members[0].1)),
            })
            .expect("first claim resolves");
        assert!(
            second_output.view_model.is_none(),
            "still waiting on the second member's claim"
        );
        assert!(alice.state.group_states.is_empty());
        assert_eq!(second_output.effects.len(), 1);
        let second_request = match &second_output.effects[0] {
            CoreEffect::ExecuteHttpRequest { request } => request.clone(),
            other => panic!("expected the second claim request, got {other:?}"),
        };
        let expected_second_device =
            urlencoding::encode(&ordered_members[1].1.device_id).into_owned();
        assert!(
            second_request.url.contains(&expected_second_device),
            "second claim must target the second member only after the first resolves: {}",
            second_request.url
        );

        let completed = alice
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id: second_request.request_id.clone(),
                status: 200,
                body: Some(claim_response_for(&ordered_members[1].1)),
            })
            .expect("second claim resolves and finalizes group creation");

        let summary = completed
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .expect("group summary after both claims resolve");
        assert_eq!(summary.kind, Some(ConversationKind::Group));
        assert!(
            alice
                .state
                .group_states
                .contains_key(summary.group_id.as_deref().expect("group id"))
        );
    }

    /// Creates a group owned by `alice` with `bob` as its only other member,
    /// resolving the creation's KeyPackage claim and settling the resulting
    /// pending group transition so the group is fully `Ready` for the
    /// caller's own claim-batch test. Returns the group id.
    fn create_ready_two_member_group(alice: &mut CoreEngine, bob_user_id: &str) -> String {
        let output = alice
            .handle_command(CoreCommand::CreateGroupConversation {
                title: "Project".into(),
                member_user_ids: vec![bob_user_id.to_string()],
            })
            .expect("create group");
        let output = simulate_pending_key_package_claims(alice, output);
        let group_id = output
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .expect("group summary")
            .group_id
            .clone()
            .expect("group id");
        acknowledge_pending_group_transition(alice, &group_id);
        group_id
    }

    #[test]
    fn invite_to_group_claims_key_package_before_adding_member() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let carol_bundle = sample_identity_bundle(CAROL_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: carol_bundle.clone(),
            })
            .expect("import carol");
        let group_id = create_ready_two_member_group(&mut alice, &bob_bundle.user_id);

        let output = alice
            .handle_command(CoreCommand::InviteToGroup {
                group_id: group_id.clone(),
                invitee_user_ids: vec![carol_bundle.user_id.clone()],
            })
            .expect("invite carol");

        // Nothing is visible yet: the command only issues the claim
        // request, carol is not added until the claim resolves.
        assert!(output.view_model.is_none());
        assert_eq!(output.effects.len(), 1);
        let request = match &output.effects[0] {
            CoreEffect::ExecuteHttpRequest { request } => request.clone(),
            other => panic!("expected a claim request, got {other:?}"),
        };
        assert_eq!(request.method, crate::ffi_api::HttpMethod::Post);
        assert!(request.url.contains("/keypackage-pool/"));
        assert!(request.url.ends_with("/claim"));
        assert!(
            !alice
                .state
                .group_states
                .get(&group_id)
                .expect("group state")
                .manifest
                .members
                .iter()
                .any(|member| member.user_id == carol_bundle.user_id),
            "carol must not be a member until the claim resolves"
        );
        assert!(
            alice
                .state
                .group_states
                .get(&group_id)
                .expect("group state")
                .pending_group_transition
                .is_none()
        );

        let claimed_key_package_b64 = carol_bundle.devices[0]
            .keypackage_ref
            .as_ref()
            .expect("carol key package")
            .object_ref
            .clone();
        let body = serde_json::json!({
            "keyPackage": {
                "keyPackageId": "claim-carol",
                "keyPackage": claimed_key_package_b64,
                "lifecycleVersion": 1,
                "notBefore": 0,
                "createdAt": 0,
                "expiresAt": 0,
            }
        })
        .to_string();
        alice
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id: request.request_id.clone(),
                status: 200,
                body: Some(body),
            })
            .expect("claim response completes invite");

        // The claim resolving stages the membership transition; the group's
        // canonical manifest only picks it up once the transition is
        // appended (mirroring how group creation itself works).
        assert!(
            alice
                .state
                .group_states
                .get(&group_id)
                .expect("group state")
                .pending_group_transition
                .is_some()
        );
        acknowledge_pending_group_transition(&mut alice, &group_id);
        assert!(
            alice
                .state
                .group_states
                .get(&group_id)
                .expect("group state")
                .manifest
                .members
                .iter()
                .any(|member| member.user_id == carol_bundle.user_id),
            "carol must be a member after the transition is acknowledged"
        );
    }

    #[test]
    fn invite_to_group_falls_back_to_last_resort_on_pool_empty() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let carol_bundle = sample_identity_bundle(CAROL_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: carol_bundle.clone(),
            })
            .expect("import carol");
        let group_id = create_ready_two_member_group(&mut alice, &bob_bundle.user_id);

        let output = alice
            .handle_command(CoreCommand::InviteToGroup {
                group_id: group_id.clone(),
                invitee_user_ids: vec![carol_bundle.user_id.clone()],
            })
            .expect("invite carol");
        let request_id = first_http_request_id_containing(&output, "/keypackage-pool/");

        alice
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id,
                status: 404,
                body: Some(r#"{"code":"pool_empty"}"#.into()),
            })
            .expect("pool_empty falls back to the cached last-resort key package");

        assert!(
            alice
                .state
                .group_states
                .get(&group_id)
                .expect("group state")
                .pending_group_transition
                .is_some(),
            "pool_empty must still stage the invite via the cached last-resort key package"
        );
        acknowledge_pending_group_transition(&mut alice, &group_id);
        assert!(
            alice
                .state
                .group_states
                .get(&group_id)
                .expect("group state")
                .manifest
                .members
                .iter()
                .any(|member| member.user_id == carol_bundle.user_id)
        );
    }

    #[test]
    fn approve_group_join_claims_key_package_before_adding_member() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let dana_bundle = sample_identity_bundle(DANA_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: dana_bundle.clone(),
            })
            .expect("import dana");
        let group_id = create_ready_two_member_group(&mut alice, &bob_bundle.user_id);

        // Fabricate an already-leased, ready-to-approve join request for
        // dana. The invite/submit/decide/lease round trip that produces
        // this state is exercised elsewhere (`group_invite_approval_adds_dana_e2e`);
        // this test isolates just the claim-then-add behavior of the final
        // approval step.
        let request_id = "join:dana:1".to_string();
        let join = GroupJoinRequest {
            version: CURRENT_MODEL_VERSION.to_string(),
            request_id: request_id.clone(),
            group_id: group_id.clone(),
            invite_id: "invite:dana".into(),
            joiner_user_id: dana_bundle.user_id.clone(),
            joiner_device_id: dana_bundle.devices[0].device_id.clone(),
            joiner_contact_share_url: "https://example.com/share/dana".into(),
            requested_at: 0,
            request_capability: "cap".into(),
            signature: "sig".into(),
            status: GroupJoinRequestStatus::WaitingForGroupCommit,
            auto_approve: None,
        };
        alice.state.group_join_requests.insert(
            request_id.clone(),
            crate::persistence::PersistedGroupJoinRequest {
                group_id: group_id.clone(),
                request_id: request_id.clone(),
                request: join,
                join_request_endpoint: None,
                welcome_pickup: None,
                manifest: None,
                start_cursor: None,
                lease_token: Some("lease-token".into()),
                lease_expires_at: Some(u64::MAX),
            },
        );

        let output = alice
            .handle_command(CoreCommand::ApproveGroupJoin {
                group_id: group_id.clone(),
                request_id: request_id.clone(),
            })
            .expect("approve join issues a claim");

        assert!(output.view_model.is_none());
        assert_eq!(output.effects.len(), 1);
        let request = match &output.effects[0] {
            CoreEffect::ExecuteHttpRequest { request } => request.clone(),
            other => panic!("expected a claim request, got {other:?}"),
        };
        assert!(request.url.contains("/keypackage-pool/"));
        assert!(request.url.ends_with("/claim"));
        assert!(
            !alice
                .state
                .group_states
                .get(&group_id)
                .expect("group state")
                .manifest
                .members
                .iter()
                .any(|member| member.user_id == dana_bundle.user_id),
            "dana must not be a member until the claim resolves"
        );
        assert!(
            alice
                .state
                .group_states
                .get(&group_id)
                .expect("group state")
                .pending_group_transition
                .is_none()
        );

        let claimed_key_package_b64 = dana_bundle.devices[0]
            .keypackage_ref
            .as_ref()
            .expect("dana key package")
            .object_ref
            .clone();
        let body = serde_json::json!({
            "keyPackage": {
                "keyPackageId": "claim-dana",
                "keyPackage": claimed_key_package_b64,
                "lifecycleVersion": 1,
                "notBefore": 0,
                "createdAt": 0,
                "expiresAt": 0,
            }
        })
        .to_string();
        alice
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id: request.request_id.clone(),
                status: 200,
                body: Some(body),
            })
            .expect("claim response completes the approval");

        assert!(
            alice
                .state
                .group_states
                .get(&group_id)
                .expect("group state")
                .pending_group_transition
                .is_some(),
            "claim resolving stages the membership transition"
        );
        acknowledge_pending_group_transition(&mut alice, &group_id);
        assert!(
            alice
                .state
                .group_states
                .get(&group_id)
                .expect("group state")
                .manifest
                .members
                .iter()
                .any(|member| member.user_id == dana_bundle.user_id)
        );
    }

    #[test]
    fn add_group_member_device_claims_key_package_from_own_runtime_before_adding_device() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let group_id = create_ready_two_member_group(&mut alice, &bob_bundle.user_id);
        let alice_user_id = alice
            .local_identity()
            .expect("identity")
            .user_identity
            .user_id
            .clone();

        // Register a second device (tablet) in alice's own local bundle,
        // simulating it having been created and merged in via an identity
        // refresh elsewhere.
        let alice_root = IdentityManager::recover_user_root(ALICE_MNEMONIC).expect("alice root");
        let alice_tablet = IdentityManager::create_new_device_for_user(&alice_root, None)
            .expect("alice tablet identity");
        let tablet_package =
            MlsAdapter::generate_key_package(&alice_tablet, test_now_ms()).expect("tablet package");
        let tablet_keypackage_b64 = tablet_package.key_package_b64.clone();
        let tablet_profile = crate::capability::CapabilityManager::build_device_contact_profile(
            &alice_tablet,
            &sample_deployment(),
            tablet_package.key_package_b64,
            tablet_package.expires_at,
        )
        .expect("tablet profile");
        let tablet_device_id = tablet_profile.device_id.clone();
        alice
            .state
            .local_bundle
            .as_mut()
            .expect("local bundle")
            .devices
            .push(tablet_profile);

        let output = alice
            .handle_command(CoreCommand::AddGroupMemberDevice {
                group_id: group_id.clone(),
                user_id: alice_user_id.clone(),
                device_id: tablet_device_id.clone(),
            })
            .expect("add tablet device issues a claim");

        assert!(output.view_model.is_none());
        assert_eq!(output.effects.len(), 1);
        let request = match &output.effects[0] {
            CoreEffect::ExecuteHttpRequest { request } => request.clone(),
            other => panic!("expected a claim request, got {other:?}"),
        };
        assert!(request.url.ends_with("/claim"));
        // This is the one case where a claim targets the LOCAL user's own
        // runtime (the deployment's inbox origin), not a contact lookup —
        // registering an additional device is not a contact operation.
        let own_origin = sample_deployment().inbox_http_endpoint;
        assert!(
            request.url.starts_with(&own_origin),
            "add_group_member_device must claim from the local user's own runtime ({own_origin}), got {}",
            request.url
        );
        assert!(request.auth.is_none(), "claiming a pool is unauthenticated");
        assert!(
            !alice
                .state
                .group_states
                .get(&group_id)
                .expect("group state")
                .manifest
                .member_devices
                .iter()
                .any(|device| device.device_id == tablet_device_id),
            "tablet must not be an MLS member until the claim resolves"
        );

        let body = serde_json::json!({
            "keyPackage": {
                "keyPackageId": "claim-tablet",
                "keyPackage": tablet_keypackage_b64,
                "lifecycleVersion": 1,
                "notBefore": 0,
                "createdAt": 0,
                "expiresAt": 0,
            }
        })
        .to_string();
        alice
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id: request.request_id.clone(),
                status: 200,
                body: Some(body),
            })
            .expect("claim response completes add_group_member_device");

        assert!(
            alice
                .state
                .group_states
                .get(&group_id)
                .expect("group state")
                .pending_group_transition
                .is_some()
        );
        acknowledge_pending_group_transition(&mut alice, &group_id);
        assert!(
            alice
                .state
                .group_states
                .get(&group_id)
                .expect("group state")
                .manifest
                .member_devices
                .iter()
                .any(|device| device.device_id == tablet_device_id)
        );
    }

    #[test]
    fn add_group_member_device_hard_claim_failure_aborts_without_partial_state() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let group_id = create_ready_two_member_group(&mut alice, &bob_bundle.user_id);
        let alice_user_id = alice
            .local_identity()
            .expect("identity")
            .user_identity
            .user_id
            .clone();

        let alice_root = IdentityManager::recover_user_root(ALICE_MNEMONIC).expect("alice root");
        let alice_tablet = IdentityManager::create_new_device_for_user(&alice_root, None)
            .expect("alice tablet identity");
        let tablet_package =
            MlsAdapter::generate_key_package(&alice_tablet, test_now_ms()).expect("tablet package");
        let tablet_profile = crate::capability::CapabilityManager::build_device_contact_profile(
            &alice_tablet,
            &sample_deployment(),
            tablet_package.key_package_b64,
            tablet_package.expires_at,
        )
        .expect("tablet profile");
        let tablet_device_id = tablet_profile.device_id.clone();
        alice
            .state
            .local_bundle
            .as_mut()
            .expect("local bundle")
            .devices
            .push(tablet_profile);

        let output = alice
            .handle_command(CoreCommand::AddGroupMemberDevice {
                group_id: group_id.clone(),
                user_id: alice_user_id.clone(),
                device_id: tablet_device_id.clone(),
            })
            .expect("add tablet device issues a claim");
        let request_id = first_http_request_id_containing(&output, "/keypackage-pool/");

        let aborted = alice
            .handle_event(CoreEvent::HttpRequestFailed {
                request_id,
                failure: test_failure("network_unreachable", true, None),
            })
            .expect("claim failure surfaces as a notification, not a hard command error");

        assert!(aborted.view_model.is_none());
        assert!(
            alice
                .state
                .group_states
                .get(&group_id)
                .expect("group state")
                .pending_group_transition
                .is_none(),
            "no partial group transition was left behind"
        );
        assert!(
            !alice
                .state
                .group_states
                .get(&group_id)
                .expect("group state")
                .manifest
                .member_devices
                .iter()
                .any(|device| device.device_id == tablet_device_id)
        );
        assert_eq!(
            aborted.state_update.system_statuses_changed,
            vec![crate::ffi_api::SystemStatus::TemporaryNetworkFailure]
        );
        assert!(aborted.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::EmitUserNotification { notification }
                if notification.status == crate::ffi_api::SystemStatus::TemporaryNetworkFailure
        )));

        // No leftover pending-claim state: retrying the command starts a
        // clean new claim rather than erroring or getting stuck.
        let retry_output = alice
            .handle_command(CoreCommand::AddGroupMemberDevice {
                group_id: group_id.clone(),
                user_id: alice_user_id,
                device_id: tablet_device_id,
            })
            .expect("retry after abort");
        assert!(matches!(
            retry_output.effects.first(),
            Some(CoreEffect::ExecuteHttpRequest { .. })
        ));
    }

    #[test]
    fn reconcile_membership_rebootstrap_claims_key_package_before_recreating_group() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "before rebuild".into(),
            })
            .expect("send");

        // Force the conversation into a needs-rebuild state (via a
        // persistence round trip, matching how a real MLS-unrecoverable
        // restore marks a conversation) so reconciliation takes the
        // rebootstrap path.
        let mut snapshot = alice.refresh_snapshot();
        snapshot
            .mls_states
            .first_mut()
            .expect("mls state")
            .summary
            .status = crate::model::MlsStateStatus::NeedsRebuild;
        let persisted_conversation = snapshot
            .conversations
            .iter_mut()
            .find(|entry| entry.conversation_id == conversation_id)
            .expect("persisted conversation");
        persisted_conversation.state.conversation.state = ConversationState::NeedsRebuild;
        persisted_conversation.state.recovery_status = RecoveryStatus::NeedsRebuild;
        let mut alice = CoreEngine::try_from_restored_state(snapshot).expect("restore snapshot");

        let output = alice
            .handle_command(CoreCommand::ReconcileConversationMembership {
                conversation_id: conversation_id.clone(),
            })
            .expect("reconcile triggers rebootstrap");

        assert!(output.view_model.is_none());
        assert_eq!(output.effects.len(), 1);
        let request = match &output.effects[0] {
            CoreEffect::ExecuteHttpRequest { request } => request.clone(),
            other => panic!("expected a claim request, got {other:?}"),
        };
        assert!(request.url.ends_with("/claim"));
        assert_eq!(
            alice
                .state
                .conversations
                .get(&conversation_id)
                .expect("conversation")
                .conversation
                .state,
            ConversationState::NeedsRebuild,
            "the conversation is not rebuilt until the claim resolves"
        );

        let claimed_key_package_b64 = bob_bundle.devices[0]
            .keypackage_ref
            .as_ref()
            .expect("bob key package")
            .object_ref
            .clone();
        let body = serde_json::json!({
            "keyPackage": {
                "keyPackageId": "claim-rebootstrap",
                "keyPackage": claimed_key_package_b64,
                "lifecycleVersion": 1,
                "notBefore": 0,
                "createdAt": 0,
                "expiresAt": 0,
            }
        })
        .to_string();
        let completed = alice
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id: request.request_id.clone(),
                status: 200,
                body: Some(body),
            })
            .expect("claim response rebuilds the conversation");

        assert!(completed.view_model.as_ref().is_some_and(|view| {
            view.messages
                .iter()
                .any(|message| message.message_type == MessageType::MlsCommit)
                && view
                    .messages
                    .iter()
                    .any(|message| message.message_type == MessageType::MlsWelcome)
        }));
        assert_eq!(
            alice
                .state
                .conversations
                .get(&conversation_id)
                .expect("conversation")
                .conversation
                .state,
            ConversationState::Active
        );
        assert!(alice.state.mls_summaries.contains_key(&conversation_id));
    }

    #[test]
    fn reconcile_membership_add_devices_claims_key_package_before_adding_member() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());

        let bob_root = IdentityManager::recover_user_root(BOB_MNEMONIC).expect("bob root");
        let bob_laptop = IdentityManager::create_new_device_for_user(&bob_root, None)
            .expect("bob laptop identity");
        let bob_laptop_package =
            MlsAdapter::generate_key_package(&bob_laptop, test_now_ms()).expect("laptop package");
        let laptop_keypackage_b64 = bob_laptop_package.key_package_b64.clone();
        let bob_laptop_profile = crate::capability::CapabilityManager::build_device_contact_profile(
            &bob_laptop,
            &sample_deployment(),
            bob_laptop_package.key_package_b64,
            bob_laptop_package.expires_at,
        )
        .expect("laptop profile");
        let laptop_device_id = bob_laptop_profile.device_id.clone();
        alice
            .state
            .contacts
            .get_mut(&bob_bundle.user_id)
            .expect("bob contact")
            .bundle
            .devices
            .push(bob_laptop_profile);

        let output = alice
            .handle_command(CoreCommand::ReconcileConversationMembership {
                conversation_id: conversation_id.clone(),
            })
            .expect("reconcile claims the new device's key package");

        assert!(
            output.view_model.is_none(),
            "nothing changes until the claim resolves"
        );
        assert_eq!(output.effects.len(), 1);
        let request = match &output.effects[0] {
            CoreEffect::ExecuteHttpRequest { request } => request.clone(),
            other => panic!("expected a claim request, got {other:?}"),
        };
        assert!(request.url.ends_with("/claim"));
        assert!(request.url.contains(&urlencoding::encode(&laptop_device_id).into_owned()));
        assert!(!alice.state.pending_outbox.iter().any(|item| {
            item.envelope.conversation_id == conversation_id
                && item.envelope.recipient_device_id == laptop_device_id
        }));

        let body = serde_json::json!({
            "keyPackage": {
                "keyPackageId": "claim-laptop",
                "keyPackage": laptop_keypackage_b64,
                "lifecycleVersion": 1,
                "notBefore": 0,
                "createdAt": 0,
                "expiresAt": 0,
            }
        })
        .to_string();
        let completed = alice
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id: request.request_id.clone(),
                status: 200,
                body: Some(body),
            })
            .expect("claim response adds the new device");

        assert!(completed.state_update.conversations_changed);
        assert!(alice.state.pending_outbox.iter().any(|item| {
            item.envelope.conversation_id == conversation_id
                && item.envelope.recipient_device_id == laptop_device_id
                && item.envelope.message_type == MessageType::MlsWelcome
        }));
        assert!(alice.state.pending_outbox.iter().any(|item| {
            item.envelope.conversation_id == conversation_id
                && item.envelope.message_type == MessageType::MlsCommit
        }));
    }

    #[test]
    fn credential_maintenance_replenishes_pool_when_below_low_water_mark() {
        let mut engine = local_engine(ALICE_MNEMONIC, "phone");
        let now_ms = engine
            .state
            .published_key_package
            .as_ref()
            .expect("published key package")
            .created_at;

        let output = engine
            .handle_event(CoreEvent::CredentialMaintenanceRequested { now_ms })
            .expect("credential maintenance");
        let count_request_id = first_http_request_id_containing(&output, "/keypackage-pool/");

        let below_low_water = crate::mls_adapter::ONE_TIME_KEY_PACKAGE_POOL_LOW_WATER.saturating_sub(2);
        let replenished = engine
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id: count_request_id,
                status: 200,
                body: Some(format!(r#"{{"count":{below_low_water}}}"#)),
            })
            .expect("pool count below low water triggers a replenish request");

        let replenish_request = replenished
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::ExecuteHttpRequest { request }
                    if request.method == crate::ffi_api::HttpMethod::Put
                        && request.url.contains("/keypackage-pool/") =>
                {
                    Some(request.clone())
                }
                _ => None,
            })
            .expect("replenish request");
        let body: serde_json::Value =
            serde_json::from_str(replenish_request.body.as_deref().expect("replenish body"))
                .expect("replenish body json");
        let key_packages = body["keyPackages"].as_array().expect("keyPackages array");
        assert_eq!(
            key_packages.len(),
            (crate::mls_adapter::ONE_TIME_KEY_PACKAGE_POOL_TARGET - below_low_water) as usize,
            "must request exactly enough key packages to top the pool back up to the target"
        );
    }

    #[test]
    fn direct_shell_without_mls_state_is_recovery_only_and_blocks_send() {
        let mut alice = local_engine(ALICE_MNEMONIC, "phone");
        let alice_bundle = alice.local_bundle().expect("alice bundle").clone();
        let mut bob = local_engine(BOB_MNEMONIC, "phone");
        let bob_bundle = bob.local_bundle().expect("bob bundle").clone();
        alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: bob_bundle.clone(),
            })
            .expect("alice imports bob");
        bob.handle_command(CoreCommand::ImportIdentityBundleWithRelationshipStatus {
            bundle: alice_bundle.clone(),
            relationship_status: ContactRelationshipStatus::PendingOutbound,
        })
        .expect("bob imports alice as pending outbound");
        let conversation_id = create_direct_conversation(&mut bob, alice_bundle.user_id.clone());
        let alice_device_id = alice.local_device_id().expect("alice device").to_string();
        let commit = bob
            .state
            .pending_outbox
            .iter()
            .find(|item| {
                item.envelope.recipient_device_id == alice_device_id
                    && item.envelope.message_type == MessageType::MlsCommit
            })
            .expect("setup commit")
            .envelope
            .clone();

        alice
            .handle_event(CoreEvent::InboxRecordsFetched {
                device_id: alice_device_id.clone(),
                to_seq: 1,
                records: vec![InboxRecord {
                    seq: 1,
                    recipient_device_id: alice_device_id,
                    message_id: commit.message_id.clone(),
                    received_at: 1,
                    expires_at: None,
                    state: InboxRecordState::Available,
                    envelope: commit,
                }],
            })
            .expect("commit pending retry");

        assert!(!alice.state.mls_summaries.contains_key(&conversation_id));
        assert_eq!(
            alice
                .state
                .conversations
                .get(&conversation_id)
                .expect("direct shell")
                .recovery_status,
            RecoveryStatus::NeedsRecovery
        );
        let create_again = alice
            .handle_command(CoreCommand::CreateConversation {
                peer_user_id: bob_bundle.user_id.clone(),
                conversation_kind: ConversationKind::Direct,
            })
            .expect("existing recovery shell is returned");
        assert_eq!(
            create_again
                .view_model
                .as_ref()
                .expect("view model")
                .conversations[0]
                .state,
            "needs_recovery"
        );
        let send_err = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id,
                plaintext: "too early".into(),
            })
            .expect_err("missing mls state blocks send");
        assert_eq!(send_err.code(), "temporary_failure");
    }

    #[test]
    fn pending_retry_clears_after_later_welcome_applies() {
        let mut bob = local_engine(BOB_MNEMONIC, "phone");
        let bob_bundle = bob.local_bundle().expect("bob bundle").clone();
        let bob_device_id = bob.local_device_id().expect("bob device").to_string();
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());

        let commit = alice
            .state
            .pending_outbox
            .iter()
            .find(|item| {
                item.envelope.recipient_device_id == bob_device_id
                    && item.envelope.message_type == MessageType::MlsCommit
            })
            .expect("setup commit")
            .envelope
            .clone();
        let welcome = alice
            .state
            .pending_outbox
            .iter()
            .find(|item| {
                item.envelope.recipient_device_id == bob_device_id
                    && item.envelope.message_type == MessageType::MlsWelcome
            })
            .expect("setup welcome")
            .envelope
            .clone();

        bob.handle_event(CoreEvent::InboxRecordsFetched {
            device_id: bob_device_id.clone(),
            to_seq: 1,
            records: vec![InboxRecord {
                seq: 1,
                recipient_device_id: bob_device_id.clone(),
                message_id: commit.message_id.clone(),
                received_at: 1,
                expires_at: None,
                state: InboxRecordState::Available,
                envelope: commit.clone(),
            }],
        })
        .expect("commit pending retry");
        assert_eq!(
            bob.state
                .conversations
                .get(&conversation_id)
                .expect("direct shell")
                .recovery_status,
            RecoveryStatus::NeedsRecovery
        );
        bob.state
            .sync_states
            .get_mut(&bob_device_id)
            .expect("sync state")
            .pending_records
            .insert(
                1,
                InboxRecord {
                    seq: 1,
                    recipient_device_id: bob_device_id.clone(),
                    message_id: commit.message_id.clone(),
                    received_at: 1,
                    expires_at: None,
                    state: InboxRecordState::Available,
                    envelope: commit,
                },
            );
        {
            let sync_state = bob
                .state
                .sync_states
                .get_mut(&bob_device_id)
                .expect("sync state");
            sync_state.pending_record_seqs.insert(1);
            sync_state.pending_retry = true;
        }
        assert!(
            bob.state
                .sync_states
                .get(&bob_device_id)
                .expect("sync state")
                .pending_records
                .contains_key(&1)
        );

        bob.handle_event(CoreEvent::InboxRecordsFetched {
            device_id: bob_device_id.clone(),
            to_seq: 2,
            records: vec![InboxRecord {
                seq: 2,
                recipient_device_id: bob_device_id.clone(),
                message_id: welcome.message_id.clone(),
                received_at: 2,
                expires_at: None,
                state: InboxRecordState::Available,
                envelope: welcome,
            }],
        })
        .expect("welcome applies");

        assert_eq!(
            bob.state
                .conversations
                .get(&conversation_id)
                .expect("direct conversation")
                .recovery_status,
            RecoveryStatus::Healthy
        );
        assert!(!bob.state.recovery_contexts.contains_key(&conversation_id));
        let sync_state = bob
            .state
            .sync_states
            .get(&bob_device_id)
            .expect("sync state");
        assert!(!sync_state.pending_records.contains_key(&1));
        assert!(!sync_state.pending_record_seqs.contains(&1));
        assert!(!sync_state.pending_retry);
    }

    #[test]
    fn contact_accepted_control_promotes_pending_outbound_to_available() {
        let mut alice = local_engine(ALICE_MNEMONIC, "phone");
        let alice_bundle = alice.local_bundle().expect("alice bundle").clone();
        let mut bob = local_engine(BOB_MNEMONIC, "phone");
        let bob_bundle = bob.local_bundle().expect("bob bundle").clone();
        alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: bob_bundle.clone(),
            })
            .expect("alice imports bob");
        bob.handle_command(CoreCommand::ImportIdentityBundleWithRelationshipStatus {
            bundle: alice_bundle.clone(),
            relationship_status: ContactRelationshipStatus::PendingOutbound,
        })
        .expect("bob imports alice as pending outbound");
        let conversation_id = create_direct_conversation(&mut bob, alice_bundle.user_id.clone());
        let bob_sender_device_id = bob.local_device_id().expect("bob device").to_string();
        let alice_recipient_device_id = alice.local_device_id().expect("alice device").to_string();
        bob.state
            .conversations
            .get_mut(&conversation_id)
            .expect("conversation")
            .messages
            .push(crate::conversation::StoredMessage {
                message_id: "msg:pending-approval".into(),
                app_message_id: Some("app:pending-approval".into()),
                mls_ciphertext_sha256: None,
                sender_user_id: Some(bob_bundle.user_id.clone()),
                sender_device_id: bob_sender_device_id,
                recipient_device_id: alice_recipient_device_id,
                message_type: MessageType::MlsApplication,
                created_at: 1,
                plaintext: Some("hello".into()),
                storage_refs: Vec::new(),
                delivery_state: Some(
                    crate::conversation::StoredMessageDeliveryState::PendingApproval,
                ),
                message_request_id: Some("request:pending".into()),
            });

        let output = alice
            .handle_event(CoreEvent::MessageRequestActionCompleted {
                result: accepted_request_result(&bob_bundle.user_id, &conversation_id),
            })
            .expect("alice accepts bob request");
        assert!(
            output
                .effects
                .iter()
                .any(|effect| matches!(effect, CoreEffect::ExecuteHttpRequest { .. }))
        );

        let bob_device_id = bob.local_device_id().expect("bob device").to_string();
        let accepted_envelope = alice
            .state
            .pending_outbox
            .iter()
            .find(|item| {
                item.envelope.recipient_device_id == bob_device_id
                    && item.envelope.message_type == MessageType::ControlContactAccepted
            })
            .expect("accepted control envelope")
            .envelope
            .clone();
        let payload_b64 = accepted_envelope
            .inline_ciphertext
            .as_deref()
            .expect("accepted payload");
        let payload = STANDARD.decode(payload_b64).expect("payload base64");
        let payload: serde_json::Value =
            serde_json::from_slice(&payload).expect("accepted payload json");
        assert_eq!(payload["conversation_id"], conversation_id);
        assert_eq!(payload["actor_user_id"], alice_bundle.user_id);
        assert_eq!(payload["accepted_user_id"], bob_bundle.user_id);

        deliver_pending_outbox_to_device(&mut bob, &alice, &bob_device_id);

        assert_eq!(
            bob.state
                .contacts
                .get(&alice_bundle.user_id)
                .expect("alice contact")
                .relationship_status,
            ContactRelationshipStatus::Available
        );
        assert_eq!(
            bob.state
                .conversations
                .get(&conversation_id)
                .expect("conversation")
                .messages[0]
                .delivery_state,
            Some(crate::conversation::StoredMessageDeliveryState::Sent)
        );
        assert_eq!(
            bob.state
                .conversations
                .get(&conversation_id)
                .expect("conversation")
                .messages
                .len(),
            1,
            "accepted control must stay protocol-only"
        );
    }

    #[test]
    fn contact_accepted_control_with_invalid_signature_does_not_promote() {
        let mut alice = local_engine(ALICE_MNEMONIC, "phone");
        let alice_bundle = alice.local_bundle().expect("alice bundle").clone();
        let mut bob = local_engine(BOB_MNEMONIC, "phone");
        let bob_bundle = bob.local_bundle().expect("bob bundle").clone();
        alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: bob_bundle.clone(),
            })
            .expect("alice imports bob");
        bob.handle_command(CoreCommand::ImportIdentityBundleWithRelationshipStatus {
            bundle: alice_bundle.clone(),
            relationship_status: ContactRelationshipStatus::PendingOutbound,
        })
        .expect("bob imports alice as pending outbound");
        let conversation_id = create_direct_conversation(&mut bob, alice_bundle.user_id.clone());
        alice
            .handle_event(CoreEvent::MessageRequestActionCompleted {
                result: accepted_request_result(&bob_bundle.user_id, &conversation_id),
            })
            .expect("alice accepts bob request");

        let bob_device_id = bob.local_device_id().expect("bob device").to_string();
        let mut accepted_envelope = alice
            .state
            .pending_outbox
            .iter()
            .find(|item| item.envelope.message_type == MessageType::ControlContactAccepted)
            .expect("accepted control envelope")
            .envelope
            .clone();
        accepted_envelope.sender_proof.value = "00".repeat(64);

        let err = bob
            .handle_event(CoreEvent::InboxRecordsFetched {
                device_id: bob_device_id.clone(),
                to_seq: 1,
                records: vec![InboxRecord {
                    seq: 1,
                    recipient_device_id: bob_device_id,
                    message_id: accepted_envelope.message_id.clone(),
                    received_at: 1,
                    expires_at: None,
                    state: InboxRecordState::Available,
                    envelope: accepted_envelope,
                }],
            })
            .expect_err("invalid accepted control is rejected");
        assert_eq!(err.code(), "invalid_input");
        assert_eq!(
            bob.state
                .contacts
                .get(&alice_bundle.user_id)
                .expect("alice contact")
                .relationship_status,
            ContactRelationshipStatus::PendingOutbound
        );
    }

    #[test]
    fn contact_accepted_control_does_not_revive_deleted_relationship() {
        let mut alice = local_engine(ALICE_MNEMONIC, "phone");
        let alice_bundle = alice.local_bundle().expect("alice bundle").clone();
        let mut bob = local_engine(BOB_MNEMONIC, "phone");
        let bob_bundle = bob.local_bundle().expect("bob bundle").clone();
        alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: bob_bundle.clone(),
            })
            .expect("alice imports bob");
        bob.handle_command(CoreCommand::ImportIdentityBundleWithRelationshipStatus {
            bundle: alice_bundle.clone(),
            relationship_status: ContactRelationshipStatus::PendingOutbound,
        })
        .expect("bob imports alice as pending outbound");
        let conversation_id = create_direct_conversation(&mut bob, alice_bundle.user_id.clone());
        alice
            .handle_event(CoreEvent::MessageRequestActionCompleted {
                result: accepted_request_result(&bob_bundle.user_id, &conversation_id),
            })
            .expect("alice accepts bob request");
        let accepted_envelope = alice
            .state
            .pending_outbox
            .iter()
            .find(|item| item.envelope.message_type == MessageType::ControlContactAccepted)
            .expect("accepted control envelope")
            .envelope
            .clone();

        bob.handle_command(CoreCommand::DeleteContact {
            user_id: alice_bundle.user_id.clone(),
        })
        .expect("bob deletes alice");
        assert!(!bob.state.contacts.contains_key(&alice_bundle.user_id));

        let bob_device_id = bob.local_device_id().expect("bob device").to_string();
        bob.handle_event(CoreEvent::InboxRecordsFetched {
            device_id: bob_device_id.clone(),
            to_seq: 1,
            records: vec![InboxRecord {
                seq: 1,
                recipient_device_id: bob_device_id.clone(),
                message_id: accepted_envelope.message_id.clone(),
                received_at: 1,
                expires_at: None,
                state: InboxRecordState::Available,
                envelope: accepted_envelope,
            }],
        })
        .expect("late accepted control ignored");

        assert!(!bob.state.contacts.contains_key(&alice_bundle.user_id));
        assert_eq!(
            bob.state
                .conversations
                .get(&conversation_id)
                .expect("archived conversation")
                .conversation
                .state,
            ConversationState::Archived
        );
        assert_eq!(
            bob.state
                .sync_states
                .get(&bob_device_id)
                .expect("sync state")
                .checkpoint
                .last_acked_seq,
            1
        );
    }

    #[test]
    fn verified_inbound_mls_application_promotes_pending_outbound_contact() {
        let mut alice = local_engine(ALICE_MNEMONIC, "phone");
        let alice_bundle = alice.local_bundle().expect("alice bundle").clone();
        let mut bob = local_engine(BOB_MNEMONIC, "phone");
        let bob_bundle = bob.local_bundle().expect("bob bundle").clone();
        alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: bob_bundle.clone(),
            })
            .expect("alice imports bob");
        bob.handle_command(CoreCommand::ImportIdentityBundleWithRelationshipStatus {
            bundle: alice_bundle.clone(),
            relationship_status: ContactRelationshipStatus::PendingOutbound,
        })
        .expect("bob imports alice as pending outbound");
        let conversation_id = create_direct_conversation(&mut bob, alice_bundle.user_id.clone());
        let alice_device_id = alice.local_device_id().expect("alice device").to_string();
        deliver_pending_outbox_to_device(&mut alice, &bob, &alice_device_id);

        alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "accepted now".into(),
            })
            .expect("alice sends verified app message");
        let bob_device_id = bob.local_device_id().expect("bob device").to_string();
        deliver_pending_outbox_to_device(&mut bob, &alice, &bob_device_id);

        assert_eq!(
            bob.state
                .contacts
                .get(&alice_bundle.user_id)
                .expect("alice contact")
                .relationship_status,
            ContactRelationshipStatus::Available
        );
    }

    #[test]
    fn closed_relationship_acks_and_ignores_late_mls_application() {
        let mut alice = local_engine(ALICE_MNEMONIC, "phone");
        let alice_bundle = alice.local_bundle().expect("alice bundle").clone();
        let mut bob = local_engine(BOB_MNEMONIC, "phone");
        let bob_bundle = bob.local_bundle().expect("bob bundle").clone();
        alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: bob_bundle.clone(),
            })
            .expect("alice imports bob");
        bob.handle_command(CoreCommand::ImportIdentityBundle {
            bundle: alice_bundle.clone(),
        })
        .expect("bob imports alice");
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        assert_eq!(
            create_direct_conversation(&mut bob, alice_bundle.user_id.clone()),
            conversation_id
        );
        alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "late".into(),
            })
            .expect("queue late message");
        let bob_device_id = bob.local_device_id().expect("bob device").to_string();
        let stale_envelope = alice
            .state
            .pending_outbox
            .iter()
            .find(|item| {
                item.envelope.recipient_device_id == bob_device_id
                    && item.envelope.message_type == MessageType::MlsApplication
            })
            .expect("stale app envelope")
            .envelope
            .clone();

        alice
            .handle_command(CoreCommand::DeleteContact {
                user_id: bob_bundle.user_id.clone(),
            })
            .expect("alice deletes bob");
        deliver_pending_outbox_to_device(&mut bob, &alice, &bob_device_id);
        let message_count_before = bob
            .state
            .conversations
            .get(&conversation_id)
            .expect("conversation")
            .messages
            .len();

        bob.handle_event(CoreEvent::InboxRecordsFetched {
            device_id: bob_device_id.clone(),
            to_seq: 2,
            records: vec![InboxRecord {
                seq: 2,
                recipient_device_id: bob_device_id.clone(),
                message_id: stale_envelope.message_id.clone(),
                received_at: 2,
                expires_at: None,
                state: InboxRecordState::Available,
                envelope: stale_envelope.clone(),
            }],
        })
        .expect("late message ignored");

        let bob_conversation = bob
            .state
            .conversations
            .get(&conversation_id)
            .expect("conversation");
        assert_eq!(bob_conversation.messages.len(), message_count_before);
        assert!(
            !bob_conversation
                .messages
                .iter()
                .any(|message| message.message_id == stale_envelope.message_id)
        );
        assert!(!bob.state.recovery_contexts.contains_key(&conversation_id));
        let sync_state = bob
            .state
            .sync_states
            .get(&bob_device_id)
            .expect("sync state");
        assert_eq!(sync_state.checkpoint.last_acked_seq, 2);
        assert!(!sync_state.pending_retry);
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
                display_name: None,
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
                conversation_id: conversation_id.clone(),
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
                plaintext: vec![1_u8, 2, 3, 4],
            })
            .expect("attachment bytes loaded");
        assert!(prepared.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::PrepareBlobUpload { upload }
                if upload.headers.get("Authorization").is_none()
                    && matches!(upload.auth.as_ref(), Some(TransportAuthRequirement::DeviceRuntime { .. }))
                    && upload.storage_scope.as_deref() == Some("direct")
                    && upload.group_id.is_none()
        )));
        let upload_ready = alice
            .handle_event(CoreEvent::BlobUploadPrepared {
                task_id: task_id.clone(),
                result: crate::transport_contract::PrepareBlobUploadResult {
                    blob_ref: "blob:attachment-1".into(),
                    upload_target: "upload:attachment-1".into(),
                    upload_headers: std::collections::BTreeMap::new(),
                    read_capability: "read-capability".into(),
                    download_target:
                        "https://storage.example.com/v1/storage/blob/blob%3Aattachment-1".into(),
                    upload_expires_at: Some(99),
                    blob_expires_at: Some(999),
                    delete_target: Some(
                        "https://storage.example.com/v1/storage/blob/blob%3Aattachment-1".into(),
                    ),
                    delete_capability: Some("delete-attachment-1".into()),
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
            "blob:attachment-1"
        );
        let outbox_item = alice
            .state
            .pending_outbox
            .iter()
            .find(|item| !item.envelope.storage_refs.is_empty())
            .expect("attachment outbox");
        let message_id = outbox_item.envelope.message_id.clone();
        let logical_message_id = outbox_item
            .app_message_id
            .clone()
            .unwrap_or_else(|| message_id.clone());
        let plaintext_cache = outbox_item
            .plaintext_cache
            .as_deref()
            .expect("attachment metadata cache");
        let metadata: AttachmentPayloadMetadata =
            serde_json::from_str(plaintext_cache).expect("attachment metadata json");
        assert_eq!(metadata.original.mime_type, "application/octet-stream");
        assert_eq!(metadata.file_name.as_deref(), Some("file.bin"));
        assert_eq!(metadata.original.plaintext_size, 4);
        assert_eq!(metadata.original.read_capability, "read-capability");
        assert_eq!(
            metadata.original.storage_origin,
            "https://storage.example.com"
        );

        let download = alice
            .handle_command(CoreCommand::DownloadAttachment {
                conversation_id: conversation_id.clone(),
                message_id: message_id.clone(),
                reference: "blob:attachment-1".into(),
                destination: "cached/file.bin".into(),
            })
            .expect("download attachment from pending outbox metadata");
        assert!(download.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::DownloadBlob { download }
                if download.blob_ref == "blob:attachment-1"
                    && download.download_target == "https://storage.example.com/v1/storage/blob/blob%3Aattachment-1"
                    && matches!(download.auth.as_ref(), Some(TransportAuthRequirement::BlobCapability { capability, .. }) if capability == "read-capability")
        )));
        assert!(output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::ExecuteHttpRequest { request } if request.url.contains("/messages")
        )));

        let request_id = find_http_request_id(&output, "/messages");
        let append_output = alice
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id,
                status: 200,
                body: Some(r#"{"accepted":true,"seq":3,"delivered_to":"inbox"}"#.into()),
            })
            .expect("append inbox response");
        let stored = append_output
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::PersistState { persist } => {
                    persist
                        .mutations
                        .iter()
                        .find_map(|mutation| match mutation {
                            PersistenceMutation::InsertMessage {
                                conversation_id: persisted_conversation_id,
                                message,
                            } if persisted_conversation_id == &conversation_id
                                && (message.message_id == logical_message_id
                                    || message.app_message_id.as_deref()
                                        == Some(logical_message_id.as_str())) =>
                            {
                                Some(message)
                            }
                            _ => None,
                        })
                }
                _ => None,
            })
            .expect("persisted sent attachment mutation");
        let stored_metadata: AttachmentPayloadMetadata = serde_json::from_str(
            stored
                .plaintext
                .as_deref()
                .expect("stored attachment metadata"),
        )
        .expect("stored attachment metadata json");
        assert_eq!(
            stored_metadata.original.encryption.algorithm,
            ATTACHMENT_CIPHER_ALGORITHM
        );
    }

    #[test]
    fn video_original_uses_chunked_cipher_and_download_restores_plaintext() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        let mut descriptor = sample_attachment_descriptor();
        descriptor.mime_type = "video/mp4".into();
        descriptor.file_name = Some("clip.mp4".into());
        let queued = alice
            .handle_command(CoreCommand::SendAttachmentMessage {
                conversation_id: conversation_id.clone(),
                attachment_descriptor: descriptor,
            })
            .expect("queue video");
        let task_id = queued
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::ReadAttachmentBytes { read } => Some(read.task_id.clone()),
                _ => None,
            })
            .expect("read video task");
        let plaintext = vec![1_u8, 2, 3, 4];
        let prepared = alice
            .handle_event(CoreEvent::AttachmentBytesLoaded {
                task_id: task_id.clone(),
                plaintext: plaintext.clone(),
            })
            .expect("encrypt video");
        assert!(prepared.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::PrepareBlobUpload { upload } if upload.size_bytes == 20
        )));
        let upload_ready = alice
            .handle_event(CoreEvent::BlobUploadPrepared {
                task_id: task_id.clone(),
                result: crate::transport_contract::PrepareBlobUploadResult {
                    blob_ref: "blob:video-chunked".into(),
                    upload_target: "upload:video-chunked".into(),
                    upload_headers: std::collections::BTreeMap::new(),
                    read_capability: "read-video".into(),
                    download_target:
                        "https://storage.example.com/v1/storage/blob/blob%3Avideo-chunked".into(),
                    upload_expires_at: Some(99),
                    blob_expires_at: Some(999),
                    delete_target: Some(
                        "https://storage.example.com/v1/storage/blob/blob%3Avideo-chunked".into(),
                    ),
                    delete_capability: Some("delete-video".into()),
                },
            })
            .expect("prepare video");
        let ciphertext = upload_ready
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::UploadBlob { upload } => Some(upload.blob_ciphertext.clone()),
                _ => None,
            })
            .expect("video ciphertext");
        alice
            .handle_event(CoreEvent::BlobUploaded { task_id })
            .expect("publish video");
        let outbox = alice
            .state
            .pending_outbox
            .iter()
            .find(|item| !item.envelope.storage_refs.is_empty())
            .expect("video outbox");
        let envelope_message_id = outbox.envelope.message_id.clone();
        let manifest: AttachmentPayloadMetadata =
            serde_json::from_str(outbox.plaintext_cache.as_deref().expect("video manifest"))
                .expect("decode video manifest");
        assert_eq!(
            manifest.original.encryption.algorithm,
            CHUNKED_ATTACHMENT_CIPHER_ALGORITHM
        );
        assert_eq!(
            manifest.original.encryption.chunk_size_bytes,
            Some(ATTACHMENT_CHUNK_SIZE_BYTES)
        );
        let download = alice
            .handle_command(CoreCommand::DownloadAttachment {
                conversation_id,
                message_id: envelope_message_id,
                reference: "blob:video-chunked".into(),
                destination: "saved/clip.mp4".into(),
            })
            .expect("queue video download");
        let download_task_id = download
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::DownloadBlob { download } => Some(download.task_id.clone()),
                _ => None,
            })
            .expect("video download task");
        let completed = alice
            .handle_event(CoreEvent::BlobDownloaded {
                task_id: download_task_id,
                blob_ciphertext: Some(ciphertext),
            })
            .expect("decrypt video");
        assert!(completed.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::WriteDownloadedAttachment { write } if write.plaintext == plaintext
        )));
    }

    #[test]
    fn image_original_completion_waits_for_preview_without_reupload_loop() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        alice.state.pending_outbox.clear();
        let mut descriptor = sample_attachment_descriptor();
        descriptor.mime_type = "image/png".into();
        descriptor.preview = Some(crate::ffi_api::AttachmentVariantSource {
            attachment_id: "preview:test".into(),
            mime_type: "image/webp".into(),
            size_bytes: 2,
        });
        descriptor.width = Some(32);
        descriptor.height = Some(24);
        let queued = alice
            .handle_command(CoreCommand::SendAttachmentMessage {
                conversation_id,
                attachment_descriptor: descriptor,
            })
            .expect("queue image attachment");
        let logical_message_id = queued
            .view_model
            .as_ref()
            .and_then(|view| view.messages.first())
            .map(|message| message.message_id.clone())
            .expect("logical attachment message id");
        let task_ids = queued
            .effects
            .iter()
            .filter_map(|effect| match effect {
                CoreEffect::ReadAttachmentBytes { read } => Some(read.task_id.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let original_task = task_ids
            .iter()
            .find(|task_id| task_id.ends_with(":original"))
            .cloned()
            .expect("original task");
        let preview_task = task_ids
            .iter()
            .find(|task_id| task_id.ends_with(":preview"))
            .cloned()
            .expect("preview task");

        alice
            .handle_event(CoreEvent::AttachmentBytesLoaded {
                task_id: original_task.clone(),
                plaintext: vec![1, 2, 3, 4],
            })
            .expect("encrypt original");
        alice
            .handle_event(CoreEvent::BlobUploadPrepared {
                task_id: original_task.clone(),
                result: crate::transport_contract::PrepareBlobUploadResult {
                    blob_ref: "blob:image-original".into(),
                    upload_target: "upload:image-original".into(),
                    upload_headers: std::collections::BTreeMap::new(),
                    read_capability: "read-original".into(),
                    download_target:
                        "https://storage.example.com/v1/storage/blob/blob%3Aimage-original".into(),
                    upload_expires_at: Some(99),
                    blob_expires_at: Some(999),
                    delete_target: Some(
                        "https://storage.example.com/v1/storage/blob/blob%3Aimage-original".into(),
                    ),
                    delete_capability: Some("delete-original".into()),
                },
            })
            .expect("prepare original");
        let original_done = alice
            .handle_event(CoreEvent::BlobUploaded {
                task_id: original_task.clone(),
            })
            .expect("complete original");
        assert!(alice.state.pending_outbox.is_empty());
        assert!(
            alice
                .state
                .pending_blob_uploads
                .get(&original_task)
                .is_some_and(|task| task.uploaded)
        );
        assert!(!original_done.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::UploadBlob { upload } if upload.task_id == original_task
        )));

        alice
            .handle_event(CoreEvent::AttachmentBytesLoaded {
                task_id: preview_task.clone(),
                plaintext: vec![9, 8],
            })
            .expect("encrypt preview");
        alice
            .handle_event(CoreEvent::BlobUploadPrepared {
                task_id: preview_task.clone(),
                result: crate::transport_contract::PrepareBlobUploadResult {
                    blob_ref: "blob:image-preview".into(),
                    upload_target: "upload:image-preview".into(),
                    upload_headers: std::collections::BTreeMap::new(),
                    read_capability: "read-preview".into(),
                    download_target:
                        "https://storage.example.com/v1/storage/blob/blob%3Aimage-preview".into(),
                    upload_expires_at: Some(99),
                    blob_expires_at: Some(999),
                    delete_target: Some(
                        "https://storage.example.com/v1/storage/blob/blob%3Aimage-preview".into(),
                    ),
                    delete_capability: Some("delete-preview".into()),
                },
            })
            .expect("prepare preview");
        let completed = alice
            .handle_event(CoreEvent::BlobUploaded {
                task_id: preview_task,
            })
            .expect("complete preview");
        assert_eq!(alice.state.pending_blob_uploads.len(), 0);
        assert_eq!(alice.state.pending_outbox.len(), bob_bundle.devices.len());
        assert!(
            alice.state.pending_outbox.iter().all(|item| {
                item.app_message_id.as_deref() == Some(logical_message_id.as_str())
            })
        );
        assert_eq!(
            completed
                .effects
                .iter()
                .filter(|effect| matches!(effect, CoreEffect::CacheUploadedAttachment { .. }))
                .count(),
            2,
            "original and preview should be promoted into the local cache"
        );
        assert!(completed.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::ExecuteHttpRequest { request } if request.url.contains("/messages")
        )));
    }

    #[test]
    fn direct_attachment_download_after_snapshot_restore_refreshes_short_target() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        let upload = alice
            .handle_command(CoreCommand::SendAttachmentMessage {
                conversation_id: conversation_id.clone(),
                attachment_descriptor: sample_attachment_descriptor(),
            })
            .expect("attachment");
        let task_id = upload
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::ReadAttachmentBytes { read } => Some(read.task_id.clone()),
                _ => None,
            })
            .expect("upload task");
        let prepared = alice
            .handle_event(CoreEvent::AttachmentBytesLoaded {
                task_id: task_id.clone(),
                plaintext: vec![1_u8, 2, 3, 4],
            })
            .expect("attachment bytes loaded");
        assert!(
            prepared
                .effects
                .iter()
                .any(|effect| matches!(effect, CoreEffect::PrepareBlobUpload { .. }))
        );
        let upload_ready = alice
            .handle_event(CoreEvent::BlobUploadPrepared {
                task_id: task_id.clone(),
                result: crate::transport_contract::PrepareBlobUploadResult {
                    blob_ref: "blob:long-idle".into(),
                    upload_target: "upload:long-idle".into(),
                    upload_headers: std::collections::BTreeMap::new(),
                    read_capability: "read-long-idle".into(),
                    download_target: "https://storage.example.com/v1/storage/blob/blob%3Along-idle"
                        .into(),
                    upload_expires_at: Some(15),
                    blob_expires_at: Some(999),
                    delete_target: Some(
                        "https://storage.example.com/v1/storage/blob/blob%3Along-idle".into(),
                    ),
                    delete_capability: Some("delete-long-idle".into()),
                },
            })
            .expect("blob prepared");
        let blob_ciphertext = upload_ready
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::UploadBlob { upload } => Some(upload.blob_ciphertext.clone()),
                _ => None,
            })
            .expect("upload blob ciphertext");
        let appended = alice
            .handle_event(CoreEvent::BlobUploaded { task_id })
            .expect("blob uploaded");
        let request_id = find_http_request_id(&appended, "/messages");
        alice
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id,
                status: 200,
                body: Some(r#"{"accepted":true,"seq":4,"delivered_to":"inbox"}"#.into()),
            })
            .expect("append response");

        let snapshot = alice.refresh_snapshot();
        let persisted_message = snapshot
            .conversations
            .iter()
            .find(|conversation| conversation.conversation_id == conversation_id)
            .and_then(|conversation| {
                conversation
                    .state
                    .messages
                    .iter()
                    .find(|message| !message.storage_refs.is_empty())
            })
            .expect("persisted attachment message");
        let message_id = persisted_message.message_id.clone();
        let stored_ref = persisted_message
            .storage_refs
            .first()
            .expect("attachment ref")
            .object_ref
            .clone();
        assert_eq!(stored_ref, "blob:long-idle");
        assert!(!stored_ref.starts_with("http"));
        let metadata: AttachmentPayloadMetadata = serde_json::from_str(
            persisted_message
                .plaintext
                .as_deref()
                .expect("attachment metadata"),
        )
        .expect("attachment metadata json");
        assert_eq!(metadata.original.read_capability, "read-long-idle");

        let mut restored = CoreEngine::try_from_restored_state(snapshot).expect("restore snapshot");
        let download = restored
            .handle_command(CoreCommand::DownloadAttachment {
                conversation_id,
                message_id,
                reference: stored_ref,
                destination: "long-idle/download.bin".into(),
            })
            .expect("download after long idle restore");
        assert!(download.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::DownloadBlob { download }
                if download.blob_ref == "blob:long-idle"
                    && matches!(download.auth.as_ref(), Some(TransportAuthRequirement::BlobCapability { capability, .. }) if capability == "read-long-idle")
        )));
        let download_task_id = download
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::DownloadBlob { download } => Some(download.task_id.clone()),
                _ => None,
            })
            .expect("pending blob download");
        let completed = restored
            .handle_event(CoreEvent::BlobDownloaded {
                task_id: download_task_id,
                blob_ciphertext: Some(blob_ciphertext),
            })
            .expect("blob downloaded");
        let plaintext = completed
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::WriteDownloadedAttachment { write } => Some(write.plaintext.clone()),
                _ => None,
            })
            .expect("write downloaded attachment");
        assert_eq!(plaintext, vec![1_u8, 2, 3, 4]);
    }

    #[test]
    fn hydrate_message_content_restores_attachment_descriptor_after_stripped_snapshot() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        let appended = complete_direct_attachment_send(&mut alice, &conversation_id);
        let request_id = find_http_request_id(&appended, "/messages");
        alice
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id,
                status: 200,
                body: Some(r#"{"accepted":true,"seq":4,"delivered_to":"inbox"}"#.into()),
            })
            .expect("append response");

        let snapshot = alice.refresh_snapshot();
        let stored_message = snapshot
            .conversations
            .iter()
            .find(|conversation| conversation.conversation_id == conversation_id)
            .and_then(|conversation| {
                conversation
                    .state
                    .messages
                    .iter()
                    .find(|message| message.plaintext.is_some())
            })
            .cloned()
            .expect("persisted attachment message");
        let metadata: AttachmentPayloadMetadata = serde_json::from_str(
            stored_message
                .plaintext
                .as_deref()
                .expect("attachment metadata"),
        )
        .expect("attachment metadata json");

        let mut stripped = snapshot;
        for conversation in &mut stripped.conversations {
            for message in &mut conversation.state.messages {
                message.plaintext = None;
                message.storage_refs.clear();
            }
        }
        for item in &mut stripped.pending_outbox {
            item.plaintext_cache = None;
        }
        for item in &mut stripped.pending_group_outbox {
            item.plaintext_cache = None;
        }

        let mut restored =
            CoreEngine::try_from_restored_state(stripped).expect("restore stripped snapshot");
        let message_id = stored_message.message_id.clone();
        assert!(
            restored
                .resolve_attachment_descriptor(
                    &conversation_id,
                    &message_id,
                    &metadata.original.object_ref,
                )
                .is_err(),
            "stripped restore must hide attachment metadata"
        );
        restored
            .hydrate_message_content(&conversation_id, stored_message)
            .expect("hydrate attachment plaintext");
        let resolved = restored
            .resolve_attachment_descriptor(
                &conversation_id,
                &message_id,
                &metadata.original.object_ref,
            )
            .expect("resolve after hydrate");
        assert_eq!(resolved.object_ref, metadata.original.object_ref);
        assert_eq!(resolved.read_capability, metadata.original.read_capability);
    }

    #[test]
    fn send_attachment_rejects_invalid_descriptor() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());

        let mut descriptor = sample_attachment_descriptor();
        descriptor.size_bytes = 0;
        assert!(
            alice
                .handle_command(CoreCommand::SendAttachmentMessage {
                    conversation_id: conversation_id.clone(),
                    attachment_descriptor: descriptor,
                })
                .is_err()
        );

        let mut descriptor = sample_attachment_descriptor();
        descriptor.file_name = Some("nested/file.bin".into());
        assert!(
            alice
                .handle_command(CoreCommand::SendAttachmentMessage {
                    conversation_id,
                    attachment_descriptor: descriptor,
                })
                .is_err()
        );
    }

    #[test]
    fn terminal_attachment_upload_failure_keeps_failed_message_and_releases_transfer() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        let upload = alice
            .handle_command(CoreCommand::SendAttachmentMessage {
                conversation_id,
                attachment_descriptor: sample_attachment_descriptor(),
            })
            .expect("attachment");
        let task_id = upload
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::ReadAttachmentBytes { read } => Some(read.task_id.clone()),
                _ => None,
            })
            .expect("upload task id");

        let failed = alice
            .handle_event(CoreEvent::BlobTransferFailed {
                task_id: task_id.clone(),
                failure: test_failure("invalid_capability", false, Some(403)),
            })
            .expect("upload failure");

        assert!(!alice.state.pending_blob_uploads.contains_key(&task_id));
        let failed_message = alice
            .state
            .conversations
            .values()
            .flat_map(|conversation| &conversation.messages)
            .find(|message| {
                message.delivery_state
                    == Some(crate::conversation::StoredMessageDeliveryState::Failed)
            })
            .expect("failed message placeholder remains visible");
        assert!(failed_message.plaintext.is_none());
        assert!(failed.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::PersistState { persist }
                if persist.ops.iter().any(|op| matches!(
                    op, PersistOp::DeletePendingBlobTransfer { task_id: deleted }
                        if deleted == &task_id
                ))
        )));
        assert!(failed.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::ReleaseStagedAttachment { release }
                if !release.attachment_ids.is_empty()
        )));
    }

    #[test]
    fn download_attachment_uses_unique_task_ids_for_distinct_destinations() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let bob_user_id = bob_bundle.user_id.clone();
        let mut engine = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle);
        let conversation_id = "conv:test".to_string();
        let mut legacy_metadata = sample_attachment_payload_metadata();
        legacy_metadata.original.storage_origin.clear();
        engine.state.conversations.insert(
            conversation_id.clone(),
            crate::conversation::LocalConversationState {
                conversation: crate::model::Conversation {
                    conversation_id: conversation_id.clone(),
                    kind: ConversationKind::Direct,
                    member_users: vec!["user:alice".into(), bob_user_id.clone()],
                    member_devices: vec![],
                    state: crate::model::ConversationState::Active,
                    updated_at: 0,
                },
                messages: vec![crate::conversation::StoredMessage {
                    message_id: "msg:download".into(),
                    app_message_id: None,
                    mls_ciphertext_sha256: None,
                    sender_user_id: Some(bob_user_id.clone()),
                    sender_device_id: "device:sender".into(),
                    recipient_device_id: "device:recipient".into(),
                    message_type: MessageType::MlsApplication,
                    created_at: 0,
                    plaintext: Some(
                        serde_json::to_string(&legacy_metadata).expect("attachment metadata"),
                    ),
                    storage_refs: vec![],
                    delivery_state: None,
                    message_request_id: None,
                }],
                last_message_type: Some(MessageType::MlsApplication),
                peer_user_id: bob_user_id,
                last_known_peer_active_devices: Default::default(),
                recovery_status: crate::conversation::RecoveryStatus::Healthy,
                archive_metadata: None,
                pcs: Default::default(),
            },
        );

        engine
            .handle_command(CoreCommand::DownloadAttachment {
                conversation_id: conversation_id.clone(),
                message_id: "msg:download".into(),
                reference: "blob:test".into(),
                destination: "cache/a.bin".into(),
            })
            .expect("first download");
        engine
            .handle_command(CoreCommand::DownloadAttachment {
                conversation_id,
                message_id: "msg:download".into(),
                reference: "blob:test".into(),
                destination: "downloads/a.bin".into(),
            })
            .expect("second download");

        let task_ids: Vec<_> = engine
            .state
            .pending_blob_downloads
            .keys()
            .cloned()
            .collect();
        assert_eq!(task_ids.len(), 2);
        assert!(task_ids.iter().all(|task_id| {
            task_id.starts_with("blob-download:msg:download:") && task_id.len() > 32
        }));
        assert_ne!(task_ids[0], task_ids[1]);
        assert!(
            engine.state.pending_blob_downloads.values().all(|task| {
                task.blob_descriptor.storage_origin == "https://storage.example.com"
            })
        );
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
            .bundle
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
                && request.headers.get("Authorization").is_none()
                && matches!(request.auth.as_ref(), Some(TransportAuthRequirement::DeviceRuntime { .. }))
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
        // Bob's device swap (phone -> laptop) is an added + revoked device
        // for the existing direct conversation, which now claims a one-time
        // KeyPackage for the new device before the membership commit is
        // generated.
        let response = simulate_pending_key_package_claims(&mut alice, response);

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
                display_name: None,
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
        let delay =
            scheduled_timer_delay(&output, &format!("sync:{device_id}")).expect("sync retry timer");
        assert!(delay >= 1_000, "retry delay should be nonzero");
    }

    #[test]
    fn retryable_direct_head_failure_backs_off_exponentially() {
        let mut engine = local_engine(ALICE_MNEMONIC, "phone");
        let device_id = engine.local_identity_summary().expect("identity").device_id;

        let sync = engine
            .handle_command(CoreCommand::SyncInbox {
                device_id: device_id.clone(),
                reason: Some("test".into()),
            })
            .expect("sync");
        let first_request_id = first_http_request_id_containing(&sync, "/head");
        let first_failure = engine
            .handle_event(CoreEvent::HttpRequestFailed {
                request_id: first_request_id,
                failure: test_failure("network_unavailable", true, None),
            })
            .expect("first failure");
        let timer_id = format!("sync:{device_id}");
        let first_delay = scheduled_timer_delay(&first_failure, &timer_id).expect("first timer");

        let retry_sync = engine
            .handle_event(CoreEvent::TimerTriggered {
                timer_id: timer_id.clone(),
            })
            .expect("retry sync");
        let second_request_id = first_http_request_id_containing(&retry_sync, "/head");
        let second_failure = engine
            .handle_event(CoreEvent::HttpRequestFailed {
                request_id: second_request_id,
                failure: test_failure("network_unavailable", true, None),
            })
            .expect("second failure");
        let second_delay = scheduled_timer_delay(&second_failure, &timer_id).expect("second timer");

        assert!(first_delay >= 1_000);
        assert!(second_delay >= 2_000);
        assert!(
            second_delay > first_delay,
            "second retry should back off beyond first retry"
        );
    }

    #[test]
    fn successful_direct_head_response_resets_retry_backoff() {
        let mut engine = local_engine(ALICE_MNEMONIC, "phone");
        let device_id = engine.local_identity_summary().expect("identity").device_id;

        let sync = engine
            .handle_command(CoreCommand::SyncInbox {
                device_id: device_id.clone(),
                reason: Some("test".into()),
            })
            .expect("sync");
        let request_id = first_http_request_id_containing(&sync, "/head");
        engine
            .handle_event(CoreEvent::HttpRequestFailed {
                request_id,
                failure: test_failure("network_unavailable", true, None),
            })
            .expect("failure");
        assert_eq!(
            engine
                .sync_state(&device_id)
                .expect("sync state")
                .consecutive_failures,
            1
        );

        let sync = engine
            .handle_command(CoreCommand::SyncInbox {
                device_id: device_id.clone(),
                reason: Some("test".into()),
            })
            .expect("sync after failure");
        let request_id = first_http_request_id_containing(&sync, "/head");
        engine
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id,
                status: 200,
                body: Some("{\"head_seq\":0}".into()),
            })
            .expect("head response");

        assert_eq!(
            engine
                .sync_state(&device_id)
                .expect("sync state")
                .consecutive_failures,
            0
        );
    }

    #[test]
    fn startup_sync_resets_exhausted_direct_pending_transport() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id);
        alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id,
                plaintext: "hello".into(),
            })
            .expect("send");
        let pending = alice
            .state
            .pending_outbox
            .first_mut()
            .expect("pending outbox");
        pending.in_flight = false;
        pending.retries = MAX_TRANSPORT_RETRIES;
        let message_id = pending.envelope.message_id.clone();

        let output = alice
            .handle_event(CoreEvent::AppStarted)
            .expect("startup sync");

        let pending = alice
            .state
            .pending_outbox
            .iter()
            .find(|item| item.envelope.message_id == message_id)
            .expect("pending after startup");
        assert_eq!(pending.retries, 0);
        assert!(
            pending.in_flight,
            "startup should re-flush reset pending message"
        );
        assert!(output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::PersistState { persist }
                if persist.ops.iter().any(|op| matches!(
                    op,
                    PersistOp::SaveOutgoingEnvelope { message_id: persisted }
                        if persisted == &message_id
                ))
        )));
    }

    #[test]
    fn sync_requests_declare_device_runtime_auth_without_bearer_header() {
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
                display_name: None,
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
                if connection.subscription.headers.get("Authorization").is_none()
                    && matches!(
                        connection.subscription.auth.as_ref(),
                        Some(TransportAuthRequirement::DeviceRuntime { runtime_id, device_id: _ })
                            if runtime_id == "runtime:test"
                    )
        )));
        assert!(output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::ExecuteHttpRequest { request }
                if request.url.contains("/head")
                    && request.headers.get("Authorization").is_none()
                    && matches!(
                        request.auth.as_ref(),
                        Some(TransportAuthRequirement::DeviceRuntime { runtime_id, device_id: _ })
                            if runtime_id == "runtime:test"
                    )
        )));
    }

    #[test]
    fn prepare_blob_upload_effect_declares_device_runtime_auth() {
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
                plaintext: vec![1_u8, 2, 3, 4],
            })
            .expect("attachment bytes loaded");
        assert!(output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::PrepareBlobUpload { upload }
                if upload.headers.get("Authorization").is_none()
                    && matches!(
                        upload.auth.as_ref(),
                        Some(TransportAuthRequirement::DeviceRuntime { runtime_id, device_id: _ })
                            if runtime_id == "runtime:test"
                    )
        )));
    }

    #[test]
    fn persist_effect_uses_typed_mutations_without_snapshot() {
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
        assert!(persist.mutations.iter().any(|mutation| matches!(
            mutation,
            PersistenceMutation::Save {
                table: crate::ffi_api::PersistenceTable::PendingOutbox,
                ..
            }
        )));
        assert!(persist.snapshot.is_none());
    }

    #[test]
    fn restored_engine_replays_pending_outbox_on_app_started() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        let _output = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id,
                plaintext: "hello".into(),
            })
            .expect("send");
        let snapshot = alice.refresh_snapshot();

        let mut restored = CoreEngine::try_from_restored_state(snapshot).expect("restore snapshot");
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
        let _output = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id,
                plaintext: "hello".into(),
            })
            .expect("send");
        let snapshot = alice.refresh_snapshot();

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
    fn stale_append_capability_refreshes_contact_and_retries_once() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        let output = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id,
                plaintext: "refresh and retry".into(),
            })
            .expect("send");
        let request_id = find_http_request_id(&output, "/messages");
        let pending_message_id = alice
            .state
            .pending_outbox
            .iter()
            .find(|item| item.plaintext_cache.as_deref() == Some("refresh and retry"))
            .expect("in-flight append")
            .envelope
            .message_id
            .clone();

        let refresh = alice
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id,
                status: 409,
                body: Some(
                    r#"{"version":1,"code":"identity_refresh_required","domain":"identity","retryable":true}"#
                        .into(),
                ),
            })
            .expect("structured refresh response");
        let pending = alice
            .state
            .pending_outbox
            .iter()
            .find(|item| item.envelope.message_id == pending_message_id)
            .expect("message remains pending");
        assert!(!pending.in_flight);
        assert!(pending.identity_refresh_attempted);
        assert!(refresh.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::FetchIdentityBundle { fetch }
                if fetch.user_id == bob_bundle.user_id
        )));

        let refreshed_bob_bundle = bob_bundle.clone();
        let retried = alice
            .handle_event(CoreEvent::IdentityBundleFetched {
                user_id: refreshed_bob_bundle.user_id.clone(),
                bundle: refreshed_bob_bundle,
            })
            .expect("identity refresh applies");
        let retry_request_id = retried
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::ExecuteHttpRequest { request }
                    if request.url.ends_with("/messages") =>
                {
                    Some(request.request_id.clone())
                }
                _ => None,
            })
            .expect("append retried after refresh");

        let failed = alice
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id: retry_request_id,
                status: 409,
                body: Some(
                    r#"{"version":1,"code":"identity_refresh_required","domain":"identity","retryable":true}"#
                        .into(),
                ),
            })
            .expect("second stale response is terminal");
        assert!(
            failed
                .effects
                .iter()
                .all(|effect| !matches!(effect, CoreEffect::FetchIdentityBundle { .. }))
        );
        let pending = alice
            .state
            .pending_outbox
            .iter()
            .find(|item| item.envelope.message_id == pending_message_id)
            .expect("failed message remains visible");
        assert_eq!(pending.retries, MAX_TRANSPORT_RETRIES);
    }

    #[test]
    fn append_message_request_result_emits_policy_notification_and_clears_outbox() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        let output = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
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
                && notification.message.contains("waiting for the contact")
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
        assert_eq!(
            append_result.request_id.as_deref(),
            Some("request:user:bob")
        );
        assert!(output.state_update.contacts_changed);
        assert_eq!(
            alice
                .state
                .contacts
                .get(&bob_bundle.user_id)
                .expect("bob contact")
                .relationship_status,
            ContactRelationshipStatus::PendingOutbound
        );
        let stored = alice
            .state
            .conversations
            .get(&conversation_id)
            .expect("conversation")
            .messages
            .iter()
            .find(|message| message.message_id == pending_message_id)
            .expect("pending approval message remains visible");
        assert_eq!(
            stored.delivery_state,
            Some(crate::conversation::StoredMessageDeliveryState::PendingApproval)
        );
        assert_eq!(
            stored.message_request_id.as_deref(),
            Some("request:user:bob")
        );
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
                && notification.message.contains("did not accept")
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
        assert!(output.state_update.contacts_changed);
        assert_eq!(
            alice
                .state
                .contacts
                .get(&bob_bundle.user_id)
                .expect("bob contact")
                .relationship_status,
            ContactRelationshipStatus::Rejected
        );
    }

    #[test]
    fn append_inbox_result_exposes_structured_append_result() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        alice
            .state
            .contacts
            .get_mut(&bob_bundle.user_id)
            .expect("bob contact")
            .relationship_status = ContactRelationshipStatus::PendingOutbound;
        let output = alice
            .handle_command(CoreCommand::CreateConversation {
                peer_user_id: bob_bundle.user_id.clone(),
                conversation_kind: ConversationKind::Direct,
            })
            .expect("conversation setup");
        let output = simulate_pending_key_package_claims(&mut alice, output);
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
        assert!(output.state_update.contacts_changed);
        assert_eq!(
            alice
                .state
                .contacts
                .get(&bob_bundle.user_id)
                .expect("bob contact")
                .relationship_status,
            ContactRelationshipStatus::Available
        );
    }

    #[test]
    fn append_delivery_persists_delivered_message_after_pending_outbox_removed() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        let output = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "persist me".into(),
            })
            .expect("send");
        let request_id = find_http_request_id(&output, "/messages");
        let pending_message_id = alice
            .state
            .pending_outbox
            .last()
            .expect("pending message")
            .envelope
            .message_id
            .clone();

        let output = alice
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id,
                status: 200,
                body: Some(r#"{"accepted":true,"seq":9,"delivered_to":"inbox"}"#.into()),
            })
            .expect("append response");

        let ops = persist_ops(&output);
        assert!(ops.iter().any(|op| matches!(
            op,
            PersistOp::DeleteOutgoingEnvelope { message_id }
                if message_id == &pending_message_id
        )));
        assert!(ops.iter().any(|op| matches!(
            op,
            PersistOp::SaveConversation { conversation_id: saved }
                if saved == &conversation_id
        )));
        let snapshot = alice.refresh_snapshot();
        assert!(
            !snapshot
                .pending_outbox
                .iter()
                .any(|item| item.message_id == pending_message_id)
        );
        let restored = CoreEngine::try_from_restored_state(snapshot).expect("restore snapshot");
        let conversation = restored
            .conversation_state(&conversation_id)
            .expect("restored conversation");
        let message = conversation
            .messages
            .iter()
            .find(|message| message.message_id == pending_message_id)
            .expect("restored sent message");
        assert_eq!(message.plaintext.as_deref(), Some("persist me"));
    }

    #[test]
    fn import_identity_bundle_with_relationship_status_sets_pending_for_new_contact() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = local_engine(ALICE_MNEMONIC, "phone");

        let output = alice
            .handle_command(CoreCommand::ImportIdentityBundleWithRelationshipStatus {
                bundle: bob_bundle.clone(),
                relationship_status: ContactRelationshipStatus::PendingOutbound,
            })
            .expect("import with explicit relationship");

        assert!(output.state_update.contacts_changed);
        assert_eq!(
            alice
                .state
                .contacts
                .get(&bob_bundle.user_id)
                .expect("bob contact")
                .relationship_status,
            ContactRelationshipStatus::PendingOutbound
        );
    }

    #[test]
    fn import_identity_bundle_with_relationship_status_does_not_downgrade_available() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = local_engine(ALICE_MNEMONIC, "phone");
        alice
            .handle_command(CoreCommand::ImportIdentityBundleWithRelationshipStatus {
                bundle: bob_bundle.clone(),
                relationship_status: ContactRelationshipStatus::Available,
            })
            .expect("available import");

        alice
            .handle_command(CoreCommand::ImportIdentityBundleWithRelationshipStatus {
                bundle: bob_bundle.clone(),
                relationship_status: ContactRelationshipStatus::PendingOutbound,
            })
            .expect("pending import");

        assert_eq!(
            alice
                .state
                .contacts
                .get(&bob_bundle.user_id)
                .expect("bob contact")
                .relationship_status,
            ContactRelationshipStatus::Available
        );
    }

    #[test]
    fn import_identity_bundle_with_relationship_status_can_promote_pending_to_available() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = local_engine(ALICE_MNEMONIC, "phone");
        alice
            .handle_command(CoreCommand::ImportIdentityBundleWithRelationshipStatus {
                bundle: bob_bundle.clone(),
                relationship_status: ContactRelationshipStatus::PendingOutbound,
            })
            .expect("pending import");

        alice
            .handle_command(CoreCommand::ImportIdentityBundleWithRelationshipStatus {
                bundle: bob_bundle.clone(),
                relationship_status: ContactRelationshipStatus::Available,
            })
            .expect("available import");

        assert_eq!(
            alice
                .state
                .contacts
                .get(&bob_bundle.user_id)
                .expect("bob contact")
                .relationship_status,
            ContactRelationshipStatus::Available
        );
    }

    #[test]
    fn set_contact_verified_persists_and_survives_same_key_update() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = local_engine(ALICE_MNEMONIC, "phone");
        alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: bob_bundle.clone(),
            })
            .expect("import");

        let output = alice
            .handle_command(CoreCommand::SetContactVerified {
                user_id: bob_bundle.user_id.clone(),
                verified: true,
            })
            .expect("verify");
        assert!(output.state_update.contacts_changed);
        let contact = alice
            .state
            .contacts
            .get(&bob_bundle.user_id)
            .expect("bob contact");
        assert!(contact.is_verified());
        assert_eq!(
            contact.verified_root_key.as_deref(),
            Some(bob_bundle.user_public_key.as_str())
        );

        alice
            .handle_command(CoreCommand::ApplyIdentityBundleUpdate {
                bundle: bob_bundle.clone(),
            })
            .expect("same-key update");
        assert!(
            alice
                .state
                .contacts
                .get(&bob_bundle.user_id)
                .expect("bob contact")
                .is_verified()
        );

        let snapshot = alice.refresh_snapshot();
        let restored = CoreEngine::try_from_restored_state(snapshot).expect("restore");
        assert!(
            restored
                .state
                .contacts
                .get(&bob_bundle.user_id)
                .expect("restored contact")
                .is_verified()
        );

        alice
            .handle_command(CoreCommand::SetContactVerified {
                user_id: bob_bundle.user_id.clone(),
                verified: false,
            })
            .expect("unverify");
        assert!(
            !alice
                .state
                .contacts
                .get(&bob_bundle.user_id)
                .expect("bob contact")
                .is_verified()
        );
    }

    #[test]
    fn contact_verification_clears_when_root_key_diverges() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = local_engine(ALICE_MNEMONIC, "phone");
        alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: bob_bundle.clone(),
            })
            .expect("import");
        alice
            .handle_command(CoreCommand::SetContactVerified {
                user_id: bob_bundle.user_id.clone(),
                verified: true,
            })
            .expect("verify");

        alice
            .state
            .contacts
            .get_mut(&bob_bundle.user_id)
            .expect("bob contact")
            .verified_root_key =
            Some("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into());

        alice
            .handle_command(CoreCommand::ApplyIdentityBundleUpdate {
                bundle: bob_bundle.clone(),
            })
            .expect("update after key mismatch");
        assert!(
            !alice
                .state
                .contacts
                .get(&bob_bundle.user_id)
                .expect("bob contact")
                .is_verified()
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
            .bundle
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
        let _upload_output = engine
            .handle_command(CoreCommand::SendAttachmentMessage {
                conversation_id,
                attachment_descriptor: sample_attachment_descriptor(),
            })
            .expect("attachment");
        let mut snapshot = engine.refresh_snapshot();
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

        let mut restored = CoreEngine::try_from_restored_state(snapshot).expect("restore snapshot");
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
    fn pending_blob_upload_rereads_opaque_source_after_snapshot_restore() {
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
        let _prepared_output = engine
            .handle_event(CoreEvent::AttachmentBytesLoaded {
                task_id: task_id.clone(),
                plaintext: vec![1_u8, 2, 3, 4],
            })
            .expect("attachment bytes loaded");
        let mut snapshot = engine.refresh_snapshot();
        if let Some(crate::persistence::PersistedPendingBlobTransfer::Upload {
            encrypted_descriptor,
            prepared_upload,
            ..
        }) = snapshot.pending_blob_transfers.first_mut()
        {
            assert!(encrypted_descriptor.is_some());
            *prepared_upload = Some(crate::transport_contract::PrepareBlobUploadResult {
                blob_ref: "blob:prepared".into(),
                upload_target: "upload:prepared".into(),
                upload_headers: std::collections::BTreeMap::new(),
                read_capability: "read-prepared".into(),
                download_target: "https://storage.example.com/v1/storage/blob/blob%3Aprepared"
                    .into(),
                upload_expires_at: Some(42),
                blob_expires_at: Some(999),
                delete_target: Some(
                    "https://storage.example.com/v1/storage/blob/blob%3Aprepared".into(),
                ),
                delete_capability: Some("delete-prepared".into()),
            });
        } else {
            panic!("missing persisted upload task");
        }
        let serialized = serde_json::to_value(&snapshot.pending_blob_transfers)
            .expect("serialize pending blob transfers");
        assert!(
            serialized
                .as_array()
                .and_then(|items| items.first())
                .and_then(|item| item.get("Upload"))
                .and_then(|upload| upload.get("blob_ciphertext"))
                .is_none()
        );

        let mut restored = CoreEngine::try_from_restored_state(snapshot).expect("restore snapshot");
        let resumed = restored
            .handle_event(CoreEvent::AppStarted)
            .expect("app started");

        assert!(resumed.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::ReadAttachmentBytes { read } if read.task_id == task_id
        )));
    }

    #[test]
    fn corrupted_mls_snapshot_fails_restore_closed() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        let _output = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "hello".into(),
            })
            .expect("send");
        let mut snapshot = alice.refresh_snapshot();
        snapshot.mls_states[0].serialized_group_state = Some("{broken".into());

        let error = CoreEngine::try_from_restored_state(snapshot)
            .expect_err("corrupted MLS state must fail closed");
        assert_eq!(error.code(), "restore_failed");
    }

    #[test]
    fn corrupted_closed_mls_snapshot_also_fails_restore_closed() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        let _output = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "hello".into(),
            })
            .expect("send");
        let mut snapshot = alice.refresh_snapshot();
        snapshot
            .conversations
            .iter_mut()
            .find(|conversation| conversation.conversation_id == conversation_id)
            .expect("conversation")
            .state
            .conversation
            .state = crate::model::ConversationState::Archived;
        snapshot.mls_states[0].serialized_group_state = Some("{broken".into());

        let error = CoreEngine::try_from_restored_state(snapshot)
            .expect_err("archived corrupted MLS state must fail closed");
        assert_eq!(error.code(), "restore_failed");
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
            .bundle
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
            .bundle
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
    fn inbox_records_persist_conversation_mls_sync_and_pending_ack() {
        let mut bob = local_engine(BOB_MNEMONIC, "phone");
        let bob_bundle = bob.local_bundle().expect("bob bundle").clone();
        let bob_device_id = bob_bundle.devices[0].device_id.clone();
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "hello after welcome".into(),
            })
            .expect("send application");

        let output = deliver_pending_outbox_to_device(&mut bob, &alice, &bob_device_id);
        let ops = persist_ops(&output);
        assert!(ops.iter().any(|op| matches!(
            op,
            PersistOp::SaveConversation { conversation_id: saved }
                if saved == &conversation_id
        )));
        assert!(ops.iter().any(|op| matches!(
            op,
            PersistOp::SaveMlsState { conversation_id: saved }
                if saved == &conversation_id
        )));
        assert!(ops.iter().any(|op| matches!(
            op,
            PersistOp::SaveSyncState { device_id } if device_id == &bob_device_id
        )));
        assert!(ops.iter().any(|op| matches!(
            op,
            PersistOp::SavePendingAck { device_id } if device_id == &bob_device_id
        )));
        let persist_index = first_persist_effect_index(&output).expect("persist effect");
        let ack_index = output
            .effects
            .iter()
            .position(|effect| {
                matches!(
                    effect,
                    CoreEffect::ExecuteHttpRequest { request } if request.url.contains("/ack")
                )
            })
            .expect("ack request");
        assert!(
            persist_index < ack_index,
            "local state must be persisted before acking inbox records"
        );

        let snapshot = bob.refresh_snapshot();
        assert!(
            snapshot
                .mls_states
                .iter()
                .any(|state| state.conversation_id == conversation_id)
        );
        assert!(
            snapshot
                .sync_states
                .iter()
                .any(|state| state.device_id == bob_device_id)
        );
        assert!(
            snapshot
                .pending_acks
                .iter()
                .any(|ack| ack.device_id == bob_device_id)
        );
        let restored = CoreEngine::try_from_restored_state(snapshot).expect("restore snapshot");
        assert!(restored.mls_summary(&conversation_id).is_some());
        let restored_conversation = restored
            .conversation_state(&conversation_id)
            .expect("restored conversation");
        assert!(
            restored_conversation
                .messages
                .iter()
                .any(|message| { message.plaintext.as_deref() == Some("hello after welcome") })
        );
        assert!(restored.sync_checkpoint_snapshot(&bob_device_id).is_some());
    }

    #[test]
    fn proven_mls_ciphertext_replay_is_acknowledged_without_duplicate_message() {
        let mut bob = local_engine(BOB_MNEMONIC, "phone");
        let bob_bundle = bob.local_bundle().expect("bob bundle").clone();
        let bob_device_id = bob_bundle.devices[0].device_id.clone();
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "stored before replay".into(),
            })
            .expect("send application");

        let mut application_record = pending_application_record(&alice, &bob_device_id);
        deliver_pending_outbox_to_device(&mut bob, &alice, &bob_device_id);
        let persisted =
            serde_json::to_vec(&bob.refresh_snapshot()).expect("serialize bob snapshot");
        let restored = serde_json::from_slice(&persisted).expect("deserialize bob snapshot");
        bob = CoreEngine::try_from_restored_state(restored).expect("restore bob snapshot");
        let state = bob
            .state
            .conversations
            .get_mut(&conversation_id)
            .expect("bob conversation");
        let stored = state
            .messages
            .iter_mut()
            .find(|message| message.plaintext.as_deref() == Some("stored before replay"))
            .expect("stored application");
        assert!(stored.mls_ciphertext_sha256.is_some());
        // Force the transport-id lookup to miss while retaining the durable
        // ciphertext proof, as can happen when a relay duplicates a delivery.
        stored.message_id = "msg:durable-logical-copy".into();
        let sync = bob
            .state
            .sync_states
            .get_mut(&bob_device_id)
            .expect("sync state");
        sync.seen_message_ids.remove(&application_record.message_id);
        let replay_seq = sync.checkpoint.last_fetched_seq + 1;
        application_record.seq = replay_seq;

        bob.handle_event(CoreEvent::InboxRecordsFetched {
            device_id: bob_device_id.clone(),
            records: vec![application_record],
            to_seq: replay_seq,
        })
        .expect("proven replay");

        let sync = bob
            .state
            .sync_states
            .get(&bob_device_id)
            .expect("sync state");
        assert_eq!(sync.checkpoint.last_acked_seq, replay_seq);
        assert!(!sync.pending_record_seqs.contains(&replay_seq));
        assert_eq!(
            bob.state
                .conversations
                .get(&conversation_id)
                .expect("conversation")
                .messages
                .iter()
                .filter(|message| message.plaintext.as_deref() == Some("stored before replay"))
                .count(),
            1
        );
    }

    #[test]
    fn unproven_mls_ciphertext_replay_is_retained_and_never_acked() {
        let mut bob = local_engine(BOB_MNEMONIC, "phone");
        let bob_bundle = bob.local_bundle().expect("bob bundle").clone();
        let bob_device_id = bob_bundle.devices[0].device_id.clone();
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "must not be lost".into(),
            })
            .expect("send application");

        let mut application_record = pending_application_record(&alice, &bob_device_id);
        deliver_pending_outbox_to_device(&mut bob, &alice, &bob_device_id);
        bob.state
            .conversations
            .get_mut(&conversation_id)
            .expect("bob conversation")
            .messages
            .retain(|message| message.plaintext.as_deref() != Some("must not be lost"));
        let sync = bob
            .state
            .sync_states
            .get_mut(&bob_device_id)
            .expect("sync state");
        sync.seen_message_ids.remove(&application_record.message_id);
        let last_acked = sync.checkpoint.last_acked_seq;
        let replay_seq = sync.checkpoint.last_fetched_seq + 1;
        application_record.seq = replay_seq;

        bob.handle_event(CoreEvent::InboxRecordsFetched {
            device_id: bob_device_id.clone(),
            records: vec![application_record],
            to_seq: replay_seq,
        })
        .expect("unproven replay is recoverable");

        let sync = bob
            .state
            .sync_states
            .get(&bob_device_id)
            .expect("sync state");
        assert_eq!(sync.checkpoint.last_acked_seq, last_acked);
        assert!(sync.pending_retry);
        assert!(sync.pending_records.contains_key(&replay_seq));
        assert_eq!(
            bob.state
                .conversations
                .get(&conversation_id)
                .expect("conversation")
                .recovery_status,
            RecoveryStatus::NeedsRecovery
        );
    }

    #[test]
    fn ack_success_deletes_persisted_pending_ack() {
        let mut bob = local_engine(BOB_MNEMONIC, "phone");
        let bob_bundle = bob.local_bundle().expect("bob bundle").clone();
        let bob_device_id = bob_bundle.devices[0].device_id.clone();
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id,
                plaintext: "ack me".into(),
            })
            .expect("send application");
        let fetched = deliver_pending_outbox_to_device(&mut bob, &alice, &bob_device_id);
        let ack_request_id = find_http_request_id(&fetched, "/ack");
        assert!(bob.state.pending_acks.contains_key(&bob_device_id));

        let output = bob
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id: ack_request_id,
                status: 200,
                body: Some(r#"{"accepted":true,"ack_seq":3}"#.into()),
            })
            .expect("ack accepted");

        assert!(!bob.state.pending_acks.contains_key(&bob_device_id));
        let ops = persist_ops(&output);
        assert!(ops.iter().any(|op| matches!(
            op,
            PersistOp::DeletePendingAck { device_id } if device_id == &bob_device_id
        )));
        assert!(ops.iter().any(|op| matches!(
            op,
            PersistOp::SaveSyncState { device_id } if device_id == &bob_device_id
        )));
        let snapshot = bob.refresh_snapshot();
        assert!(
            !snapshot
                .pending_acks
                .iter()
                .any(|ack| ack.device_id == bob_device_id)
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
                restore_failure_reason: None,
                restore_failure_detail: None,
                restore_recoverable: None,
                suggested_action: None,
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
                    failure: test_failure("network_unavailable", true, None),
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
            .bundle
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

        let _rebuild_output = alice
            .handle_command(CoreCommand::RebuildConversation {
                conversation_id: conversation_id.clone(),
            })
            .expect("rebuild conversation");
        let snapshot = alice.refresh_snapshot();
        let restored = CoreEngine::try_from_restored_state(snapshot).expect("restore snapshot");

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
    fn reconcile_success_clears_restore_diagnostics_and_persists_delete() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());

        alice
            .state
            .conversations
            .get_mut(&conversation_id)
            .expect("conversation")
            .recovery_status = RecoveryStatus::NeedsRecovery;
        alice.state.recovery_contexts.insert(
            conversation_id.clone(),
            RecoveryContext {
                conversation_id: conversation_id.clone(),
                reason: RecoveryReason::MissingCommit,
                phase: crate::ffi_api::RecoveryPhase::EscalatedToRebuild,
                attempt_count: 1,
                identity_refresh_retry_count: 0,
                last_error: Some("failed to restore MLS group state: test".into()),
                escalation_reason: Some(
                    crate::ffi_api::RecoveryEscalationReason::MlsMarkedUnrecoverable,
                ),
                restore_failure_reason: Some("invalid_serialized_state".into()),
                restore_failure_detail: Some("synthetic recoverable restore failure".into()),
                restore_recoverable: Some(true),
                suggested_action: Some("reconcile_conversation_membership".into()),
            },
        );
        assert_eq!(alice.recovery_conversations_snapshot().len(), 1);

        let output = alice
            .handle_command(CoreCommand::ReconcileConversationMembership {
                conversation_id: conversation_id.clone(),
            })
            .expect("reconcile membership");

        assert!(alice.recovery_conversations_snapshot().is_empty());
        assert!(!alice.state.recovery_contexts.contains_key(&conversation_id));
        assert_eq!(
            alice
                .state
                .conversations
                .get(&conversation_id)
                .expect("conversation")
                .recovery_status,
            RecoveryStatus::Healthy
        );
        let ops = persist_ops(&output);
        assert!(ops.iter().any(|op| matches!(
            op,
            PersistOp::DeleteRecoveryContext { conversation_id: id } if id == &conversation_id
        )));
        assert!(ops.iter().any(|op| matches!(
            op,
            PersistOp::SaveMlsState { conversation_id: id } if id == &conversation_id
        )));
        let snapshot = alice.refresh_snapshot();
        assert!(
            !snapshot
                .recovery_contexts
                .iter()
                .any(|context| context.conversation_id == conversation_id)
        );

        let send = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "after recovery cleanup".into(),
            })
            .expect("send after cleanup");
        assert!(send.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::ExecuteHttpRequest { request } if request.url.contains("/messages")
        )));
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
                restore_failure_reason: None,
                restore_failure_detail: None,
                restore_recoverable: None,
                suggested_action: None,
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
                failure: test_failure("network_unavailable", true, None),
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
                restore_failure_reason: None,
                restore_failure_detail: None,
                restore_recoverable: None,
                suggested_action: None,
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
                display_name: None,
            })
            .expect("identity");
        let local_identity = engine
            .state
            .local_identity
            .as_ref()
            .expect("local identity");
        let local_user_id = local_identity.user_identity.user_id.clone();
        let local_device_id = local_identity.device_identity.device_id.clone();
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
                    app_message_id: None,
                    mls_ciphertext_sha256: None,
                    sender_user_id: Some(local_user_id),
                    sender_device_id: local_device_id,
                    recipient_device_id: "device:recipient".into(),
                    message_type: MessageType::MlsApplication,
                    created_at: 0,
                    plaintext: Some(
                        serde_json::to_string(&sample_attachment_payload_metadata())
                            .expect("attachment metadata"),
                    ),
                    storage_refs: vec![],
                    delivery_state: None,
                    message_request_id: None,
                }],
                last_message_type: Some(MessageType::MlsApplication),
                peer_user_id: "user:bob".into(),
                last_known_peer_active_devices: Default::default(),
                recovery_status: crate::conversation::RecoveryStatus::Healthy,
                archive_metadata: None,
                pcs: Default::default(),
            },
        );
        engine
            .handle_command(CoreCommand::DownloadAttachment {
                conversation_id: "conv:test".into(),
                message_id: "msg:download".into(),
                reference: "blob:test".into(),
                destination: "download.bin".into(),
            })
            .expect("download attachment");
        let task_id = engine
            .state
            .pending_blob_downloads
            .keys()
            .next()
            .cloned()
            .expect("pending download");
        let retry_timer_id = format!("retry_blob_download:{task_id}");

        for attempt in 0..crate::ffi_api::MAX_TRANSPORT_RETRIES {
            let output = engine
                .handle_event(CoreEvent::BlobTransferFailed {
                    task_id: task_id.clone(),
                    failure: test_failure("network_unavailable", true, None),
                })
                .expect("blob failure");
            if attempt + 1 < crate::ffi_api::MAX_TRANSPORT_RETRIES {
                assert!(output.effects.iter().any(|effect| matches!(
                    effect,
                    CoreEffect::ScheduleTimer { timer }
                    if timer.timer_id == retry_timer_id
                )));
                engine
                    .handle_event(CoreEvent::TimerTriggered {
                        timer_id: retry_timer_id.clone(),
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

        assert!(!engine.state.pending_blob_downloads.contains_key(&task_id));
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
                display_name: None,
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
        let _create_output = laptop
            .handle_command(CoreCommand::CreateAdditionalDeviceIdentity {
                mnemonic: Some(BOB_MNEMONIC.into()),
                device_name: Some("laptop".into()),
                display_name: None,
            })
            .expect("additional device");
        let snapshot = laptop.refresh_snapshot();
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
                .as_ref()
                .expect("key package reference")
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
            None,
        )
        .expect("merged bundle");
        let output = alice
            .handle_command(CoreCommand::ApplyIdentityBundleUpdate { bundle: merged })
            .expect("apply merged bundle");
        simulate_pending_key_package_claims(&mut alice, output);
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

        let mut restored = CoreEngine::try_from_restored_state(snapshot).expect("restore snapshot");
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
    fn manual_key_package_rotation_commits_only_after_publication_confirmation() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut engine = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle);
        let before = engine
            .state
            .local_bundle
            .as_ref()
            .expect("local bundle")
            .devices[0]
            .keypackage_ref
            .as_ref()
            .expect("key package reference")
            .object_ref
            .clone();

        let output = engine
            .handle_command(CoreCommand::RotateLocalKeyPackage)
            .expect("rotate key package");
        let publish = output
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::PublishSharedState { publish }
                    if publish.document_kind == SharedStateDocumentKind::IdentityBundle =>
                {
                    Some(publish.clone())
                }
                _ => None,
            })
            .expect("identity publication");
        let candidate: IdentityBundle =
            serde_json::from_str(&publish.body).expect("candidate bundle");
        let candidate_ref = candidate.devices[0]
            .keypackage_ref
            .as_ref()
            .expect("candidate key package")
            .object_ref
            .clone();
        assert_ne!(before, candidate_ref);
        assert_eq!(local_key_package_ref(&engine), before);

        engine
            .handle_event(CoreEvent::SharedStatePublished {
                operation_id: publish.operation_id,
                document_kind: SharedStateDocumentKind::IdentityBundle,
                reference: publish.reference,
                etag: Some("\"rotated\"".into()),
                saved_bundle: Some(candidate),
            })
            .expect("confirm key package publication");
        let after = engine
            .state
            .local_bundle
            .as_ref()
            .expect("local bundle")
            .devices[0]
            .keypackage_ref
            .as_ref()
            .expect("key package reference")
            .object_ref
            .clone();
        assert_ne!(before, after);
    }

    #[test]
    fn expired_key_package_recovers_after_offline_publication_failure_and_restore() {
        let mut engine = local_engine(ALICE_MNEMONIC, "phone");
        let previous_ref = local_key_package_ref(&engine);
        let expired_at = engine
            .state
            .published_key_package
            .as_ref()
            .expect("published key package")
            .expires_at;
        let output = engine
            .handle_event(CoreEvent::CredentialMaintenanceRequested { now_ms: expired_at })
            .expect("stage expired key package recovery");
        let publish = output
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::PublishSharedState { publish }
                    if publish.document_kind == SharedStateDocumentKind::IdentityBundle =>
                {
                    Some(publish.clone())
                }
                _ => None,
            })
            .expect("identity publication");
        let candidate: IdentityBundle =
            serde_json::from_str(&publish.body).expect("candidate bundle");
        assert_eq!(local_key_package_ref(&engine), previous_ref);

        engine
            .handle_event(CoreEvent::SharedStatePublishFailed {
                operation_id: publish.operation_id.clone(),
                document_kind: SharedStateDocumentKind::IdentityBundle,
                reference: publish.reference.clone(),
                failure: crate::error::AppErrorV1::new(
                    "network_unavailable",
                    crate::error::ErrorDomain::Transport,
                    true,
                ),
                current_bundle: None,
                etag: None,
            })
            .expect("record offline publication failure");
        let mut restored = CoreEngine::try_from_restored_state(engine.refresh_snapshot())
            .expect("restore pending credential publication");
        assert_eq!(local_key_package_ref(&restored), previous_ref);

        let retry = restored
            .handle_event(CoreEvent::CredentialMaintenanceRequested { now_ms: u64::MAX })
            .expect("retry after reconnect");
        let retried = retry.effects.iter().find_map(|effect| match effect {
            CoreEffect::PublishSharedState { publish } => Some(publish),
            _ => None,
        });
        assert_eq!(
            retried.and_then(|publish| publish.operation_id.as_ref()),
            publish.operation_id.as_ref()
        );

        restored
            .handle_event(CoreEvent::SharedStatePublished {
                operation_id: publish.operation_id,
                document_kind: SharedStateDocumentKind::IdentityBundle,
                reference: publish.reference,
                etag: Some("\"recovered\"".into()),
                saved_bundle: Some(candidate),
            })
            .expect("confirm recovered publication");
        assert_ne!(local_key_package_ref(&restored), previous_ref);
        assert!(restored.state.pending_identity_publication.is_none());
    }

    #[test]
    fn restored_legacy_2100_key_package_rotates_on_first_online_maintenance() {
        let engine = local_engine(ALICE_MNEMONIC, "phone");
        let previous_ref = local_key_package_ref(&engine);
        let mut snapshot = engine.refresh_snapshot();
        let deployment = snapshot.deployment.as_mut().expect("deployment snapshot");
        let package = deployment
            .published_key_package
            .as_mut()
            .expect("published key package");
        package.lifecycle_version = 0;
        package.not_before = 0;
        package.created_at = 0;
        package.expires_at = 4_102_444_800_000;
        deployment.key_package_inventory.clear();

        let mut restored = CoreEngine::try_from_restored_state(snapshot)
            .expect("restore legacy key package snapshot");
        let output = restored
            .handle_event(CoreEvent::AppStarted)
            .expect("startup maintenance");
        let candidate = output.effects.iter().find_map(|effect| match effect {
            CoreEffect::PublishSharedState { publish }
                if publish.document_kind == SharedStateDocumentKind::IdentityBundle =>
            {
                serde_json::from_str::<IdentityBundle>(&publish.body).ok()
            }
            _ => None,
        });
        let candidate = candidate.expect("legacy package rotation publication");
        assert_ne!(
            candidate.devices[0]
                .keypackage_ref
                .as_ref()
                .expect("candidate key package")
                .object_ref,
            previous_ref
        );
        assert!(restored.state.pending_identity_publication.is_some());
    }

    #[test]
    fn inbox_append_capability_renews_with_thirty_days_remaining() {
        let mut engine = local_engine(ALICE_MNEMONIC, "phone");
        let now_ms = engine
            .state
            .published_key_package
            .as_ref()
            .expect("published key package")
            .created_at;
        let previous_key_package = local_key_package_ref(&engine);
        let previous_expiry =
            now_ms.saturating_add(crate::capability::INBOX_APPEND_CAPABILITY_RENEWAL_WINDOW_MS);
        engine
            .state
            .local_bundle
            .as_mut()
            .expect("local bundle")
            .devices[0]
            .inbox_append_capability
            .as_mut()
            .expect("inbox capability")
            .expires_at = previous_expiry;

        let output = engine
            .handle_event(CoreEvent::CredentialMaintenanceRequested { now_ms })
            .expect("renew inbox capability");
        let candidate = output
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::PublishSharedState { publish }
                    if publish.document_kind == SharedStateDocumentKind::IdentityBundle =>
                {
                    serde_json::from_str::<IdentityBundle>(&publish.body).ok()
                }
                _ => None,
            })
            .expect("identity publication");
        let candidate_device = &candidate.devices[0];
        assert_eq!(
            candidate_device
                .keypackage_ref
                .as_ref()
                .expect("candidate key package")
                .object_ref,
            previous_key_package
        );
        assert_eq!(
            candidate_device
                .inbox_append_capability
                .as_ref()
                .expect("renewed capability")
                .expires_at,
            now_ms.saturating_add(crate::capability::INBOX_APPEND_CAPABILITY_LIFETIME_MS)
        );
        assert_eq!(
            engine
                .state
                .local_bundle
                .as_ref()
                .expect("confirmed bundle")
                .devices[0]
                .inbox_append_capability
                .as_ref()
                .expect("confirmed capability")
                .expires_at,
            previous_expiry,
            "renewed capability must remain pending until the server confirms it"
        );
    }

    #[test]
    fn direct_welcome_rotates_and_persists_new_key_package() {
        let mut bob = local_engine(BOB_MNEMONIC, "phone");
        let bob_bundle = bob.local_bundle().expect("bob bundle").clone();
        let bob_device_id = bob_bundle.devices[0].device_id.clone();
        let bob_user_id = bob_bundle.user_id.clone();
        let before = local_key_package_ref(&bob);

        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle);
        create_direct_conversation(&mut alice, bob_user_id);
        let output = deliver_pending_outbox_to_device(&mut bob, &alice, &bob_device_id);

        let after = bob
            .state
            .published_key_package
            .as_ref()
            .expect("replacement published key package")
            .key_package_ref
            .clone();
        assert_ne!(
            before, after,
            "welcome import must publish a fresh KeyPackage"
        );

        let snapshot = bob.refresh_snapshot();
        let deployment = snapshot.deployment.expect("persisted deployment");
        assert_eq!(
            deployment
                .published_key_package
                .expect("persisted published key package")
                .key_package_ref,
            after
        );
        let pending = deployment
            .pending_identity_publication
            .expect("welcome rotation publication remains pending");
        assert_eq!(
            pending.candidate_bundle.devices[0]
                .keypackage_ref
                .as_ref()
                .expect("key package reference")
                .object_ref,
            after
        );
        assert_eq!(
            deployment
                .local_bundle
                .expect("persisted confirmed local bundle")
                .devices[0]
                .keypackage_ref
                .as_ref()
                .expect("confirmed key package reference")
                .object_ref,
            before,
            "the advertised package must not switch before server confirmation"
        );
        assert!(
            publish_shared_state_effects(&output)
                .iter()
                .any(|publish| publish.document_kind == SharedStateDocumentKind::IdentityBundle),
            "rotated identity bundle should be republished after welcome"
        );
    }

    #[test]
    fn direct_welcome_via_pool_entry_does_not_rotate_last_resort_key_package() {
        let mut bob = local_engine(BOB_MNEMONIC, "phone");
        let bob_bundle = bob.local_bundle().expect("bob bundle").clone();
        let bob_device_id = bob_bundle.devices[0].device_id.clone();
        let bob_user_id = bob_bundle.user_id.clone();
        let before = local_key_package_ref(&bob);

        // Generate a fresh one-time pool KeyPackage for bob's own device
        // (distinct bytes/init secret from bob's currently-advertised
        // last-resort KeyPackage, but built with bob's own provider/signer
        // so bob can actually process a Welcome built against it) and use
        // it as the simulated claim response instead of the cached
        // last-resort bytes that `create_direct_conversation` would
        // otherwise reuse.
        let pool_entry = bob
            .state
            .mls_adapter
            .as_ref()
            .expect("bob mls adapter")
            .generate_one_time_key_packages(1, test_now_ms())
            .expect("generate pool entry")
            .remove(0);
        assert_ne!(pool_entry.key_package_b64, {
            bob.state
                .published_key_package
                .as_ref()
                .expect("bob last-resort key package")
                .key_package_b64
                .clone()
        });

        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle);
        let output = alice
            .handle_command(CoreCommand::CreateConversation {
                peer_user_id: bob_user_id,
                conversation_kind: ConversationKind::Direct,
            })
            .expect("create conversation");
        let request_id = first_http_request_id_containing(&output, "/keypackage-pool/");
        let body = serde_json::json!({
            "keyPackage": {
                "keyPackageId": "pool-entry-1",
                "keyPackage": pool_entry.key_package_b64,
                "lifecycleVersion": 1,
                "notBefore": 0,
                "createdAt": 0,
                "expiresAt": 0,
            }
        })
        .to_string();
        alice
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id,
                status: 200,
                body: Some(body),
            })
            .expect("pool-entry claim response completes conversation creation");

        let output = deliver_pending_outbox_to_device(&mut bob, &alice, &bob_device_id);

        let after = bob
            .state
            .published_key_package
            .as_ref()
            .expect("last-resort key package must be unchanged")
            .key_package_ref
            .clone();
        assert_eq!(
            before, after,
            "a Welcome built from a claimed one-time pool entry must not rotate the last-resort key package"
        );
        assert!(
            bob.state.pending_identity_publication.is_none(),
            "no rotation means no pending identity republish either"
        );
        assert!(
            !publish_shared_state_effects(&output)
                .iter()
                .any(|publish| publish.document_kind == SharedStateDocumentKind::IdentityBundle),
            "no identity bundle republish should be triggered by a pool-sourced welcome"
        );
    }

    #[test]
    fn delayed_welcome_rebases_an_unconfirmed_share_rotation() {
        let mut bob = local_engine(BOB_MNEMONIC, "phone");
        let confirmed_share_id = bob
            .local_bundle()
            .and_then(|bundle| bundle.bundle_share_id.clone())
            .expect("confirmed share id");
        let bob_bundle = bob.local_bundle().expect("bob bundle").clone();
        let bob_device_id = bob_bundle.devices[0].device_id.clone();
        let bob_user_id = bob_bundle.user_id.clone();

        let staged = bob
            .handle_command(CoreCommand::RotateContactShareLink)
            .expect("stage share rotation");
        let staged_publish = publish_shared_state_effects(&staged)
            .into_iter()
            .find(|publish| publish.document_kind == SharedStateDocumentKind::IdentityBundle)
            .expect("staged identity publication")
            .clone();
        let staged_candidate: IdentityBundle =
            serde_json::from_str(&staged_publish.body).expect("staged bundle");
        let staged_share_id = staged_candidate
            .bundle_share_id
            .clone()
            .expect("rotated share id");

        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle);
        create_direct_conversation(&mut alice, bob_user_id);
        let output = deliver_pending_outbox_to_device(&mut bob, &alice, &bob_device_id);
        let rebased_publish = publish_shared_state_effects(&output)
            .into_iter()
            .find(|publish| publish.document_kind == SharedStateDocumentKind::IdentityBundle)
            .expect("rebased identity publication");
        let rebased_candidate: IdentityBundle =
            serde_json::from_str(&rebased_publish.body).expect("rebased bundle");

        assert_eq!(rebased_publish.operation_id, staged_publish.operation_id);
        assert_eq!(
            rebased_candidate.bundle_share_id.as_deref(),
            Some(staged_share_id.as_str()),
            "the delayed Welcome must preserve the pending share-id change"
        );
        assert_ne!(
            rebased_candidate.devices[0]
                .keypackage_ref
                .as_ref()
                .expect("replacement key package")
                .object_ref,
            staged_candidate.devices[0]
                .keypackage_ref
                .as_ref()
                .expect("staged key package")
                .object_ref
        );
        assert_eq!(
            bob.local_bundle()
                .and_then(|bundle| bundle.bundle_share_id.as_deref()),
            Some(confirmed_share_id.as_str()),
            "the local share link remains confirmed-only until publication succeeds"
        );
    }

    #[test]
    fn group_invite_after_direct_welcome_uses_rotated_key_package() {
        let mut alice = harness_user("alice", ALICE_MNEMONIC, "phone");
        let mut bob = harness_user("bob", BOB_MNEMONIC, "phone");
        import_peer_bundles(&mut [&mut alice, &mut bob]);

        create_direct_conversation(&mut alice.engine, bob.bundle.user_id.clone());
        let bob_device_id = bob.bundle.devices[0].device_id.clone();
        let welcome_output =
            deliver_pending_outbox_to_device(&mut bob.engine, &alice.engine, &bob_device_id);
        let publish = publish_shared_state_effects(&welcome_output)
            .into_iter()
            .find(|publish| publish.document_kind == SharedStateDocumentKind::IdentityBundle)
            .expect("rotated identity publication")
            .clone();
        let saved_bundle: IdentityBundle =
            serde_json::from_str(&publish.body).expect("rotated identity bundle");
        bob.engine
            .handle_event(CoreEvent::SharedStatePublished {
                operation_id: publish.operation_id,
                document_kind: publish.document_kind,
                reference: publish.reference,
                etag: Some("\"direct-welcome\"".into()),
                saved_bundle: Some(saved_bundle),
            })
            .expect("confirm rotated identity publication");
        bob.bundle = bob
            .engine
            .local_bundle()
            .expect("rotated bob bundle")
            .clone();
        alice
            .engine
            .handle_command(CoreCommand::ApplyIdentityBundleUpdate {
                bundle: bob.bundle.clone(),
            })
            .expect("alice refreshes bob identity");

        let mut harness = GroupHarness::with_bundles(&[HarnessUser {
            name: bob.name,
            bundle: bob.bundle.clone(),
            engine: CoreEngine::new(),
        }]);
        let (group_id, _) =
            harness.create_group(&mut alice, "After Direct", vec![bob.bundle.user_id.clone()]);

        harness.import_welcome(&mut bob, &group_id);
        assert!(
            bob.engine.state.group_states.contains_key(&group_id),
            "bob should import the group welcome generated from the rotated KeyPackage"
        );
    }

    #[test]
    fn group_welcome_rotates_key_package_for_subsequent_group_invite() {
        let mut alice = harness_user("alice", ALICE_MNEMONIC, "phone");
        let mut bob = harness_user("bob", BOB_MNEMONIC, "phone");
        import_peer_bundles(&mut [&mut alice, &mut bob]);
        let mut harness = GroupHarness::with_bundles(&[HarnessUser {
            name: bob.name,
            bundle: bob.bundle.clone(),
            engine: CoreEngine::new(),
        }]);

        let before = local_key_package_ref(&bob.engine);
        let (first_group_id, _) =
            harness.create_group(&mut alice, "First", vec![bob.bundle.user_id.clone()]);
        harness.import_welcome(&mut bob, &first_group_id);
        let after_first = local_key_package_ref(&bob.engine);
        assert_ne!(before, after_first);

        alice
            .engine
            .handle_command(CoreCommand::ApplyIdentityBundleUpdate {
                bundle: bob.bundle.clone(),
            })
            .expect("alice refreshes bob identity after first group welcome");
        let (second_group_id, _) =
            harness.create_group(&mut alice, "Second", vec![bob.bundle.user_id.clone()]);
        harness.import_welcome(&mut bob, &second_group_id);

        assert!(
            bob.engine.state.group_states.contains_key(&second_group_id),
            "bob should import a second group welcome after group welcome rotation"
        );
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
            MlsAdapter::generate_key_package(&bob_laptop, test_now_ms()).expect("laptop package");
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
        assert_eq!(updated.bundle.devices.len(), 2);
        assert!(
            updated
                .bundle
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
            MlsAdapter::generate_key_package(&bob_laptop, test_now_ms()).expect("laptop package");
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
            None,
        )
        .expect("merged bundle");

        let output = alice
            .handle_command(CoreCommand::ApplyIdentityBundleUpdate {
                bundle: merged.clone(),
            })
            .expect("apply bundle update");
        simulate_pending_key_package_claims(&mut alice, output);

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
            MlsAdapter::generate_key_package(&bob_phone, test_now_ms()).expect("phone package");
        let bob_laptop_package =
            MlsAdapter::generate_key_package(&bob_laptop, test_now_ms()).expect("laptop package");
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
            MlsAdapter::generate_key_package(&bob_laptop, test_now_ms()).expect("laptop package");
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
            MlsAdapter::generate_key_package(&bob_laptop, test_now_ms()).expect("laptop package");
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
            None,
        )
        .expect("merged bundle");

        let _refresh_output = alice
            .handle_command(CoreCommand::ApplyIdentityBundleUpdate { bundle: merged })
            .expect("apply bundle update");
        let pending_after_refresh = alice.state.pending_outbox.len();

        let snapshot = alice.refresh_snapshot();
        let mut restored = CoreEngine::try_from_restored_state(snapshot).expect("restore snapshot");
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

        let _create_output = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "before rebuild".into(),
            })
            .expect("send");
        let mut snapshot = alice.refresh_snapshot();
        snapshot
            .mls_states
            .first_mut()
            .expect("mls state")
            .summary
            .status = crate::model::MlsStateStatus::NeedsRebuild;
        let persisted_conversation = snapshot
            .conversations
            .iter_mut()
            .find(|entry| entry.conversation_id == conversation_id)
            .expect("persisted conversation");
        persisted_conversation.state.conversation.state =
            crate::model::ConversationState::NeedsRebuild;
        persisted_conversation.state.recovery_status =
            crate::conversation::RecoveryStatus::NeedsRebuild;
        let mut restored = CoreEngine::try_from_restored_state(snapshot).expect("restore snapshot");
        let pending_before = restored.state.pending_outbox.len();

        let output = restored
            .handle_command(CoreCommand::ReconcileConversationMembership {
                conversation_id: conversation_id.clone(),
            })
            .expect("reconcile after rebuild");
        // Rebootstrap now claims a one-time KeyPackage for each peer device
        // before rebuilding the MLS group, rather than reading it straight
        // out of the cached contact bundle.
        let output = simulate_pending_key_package_claims(&mut restored, output);

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
                display_name: None,
            })
            .expect("identity");

        let output = engine
            .handle_command(CoreCommand::ImportDeploymentBundle {
                bundle: sample_deployment(),
            })
            .expect("reimport deployment");

        assert_eq!(publish_shared_state_effects(&output).len(), 2);
        assert!(
            publish_shared_state_effects(&output)
                .iter()
                .any(|publish| publish.document_kind
                    == crate::transport_contract::SharedStateDocumentKind::IdentityBundle)
        );
        assert!(
            publish_shared_state_effects(&output)
                .iter()
                .any(|publish| publish.document_kind
                    == crate::transport_contract::SharedStateDocumentKind::DeviceStatus)
        );
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
                display_name: None,
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
                display_name: None,
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
                display_name: None,
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
                display_name: None,
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

    #[derive(Debug)]
    struct HarnessUser {
        name: &'static str,
        bundle: IdentityBundle,
        engine: CoreEngine,
    }

    #[derive(Debug, Clone)]
    struct JoinDecisionArtifacts {
        request: GroupJoinRequest,
        welcome_pickup: Option<WelcomePickupDescriptor>,
        manifest: Option<crate::model::GroupManifest>,
        start_cursor: Option<crate::model::GroupCursor>,
    }

    #[derive(Debug, Default)]
    struct GroupHarness {
        outboxes: BTreeMap<String, Vec<GroupOutboxRecord>>,
        welcome_pickups: BTreeMap<
            (String, String),
            (
                WelcomePickupDescriptor,
                String,
                Option<crate::model::GroupManifest>,
            ),
        >,
        prepared_blob_downloads: BTreeMap<String, String>,
        blobs: BTreeMap<String, Vec<u8>>,
        downloaded_attachments: BTreeMap<String, Vec<u8>>,
        invites: BTreeMap<String, GroupInviteDocument>,
        invite_urls: BTreeMap<String, String>,
        join_requests: BTreeMap<String, GroupJoinRequest>,
        leave_requests: BTreeMap<String, crate::model::GroupLeaveRequest>,
        join_decisions: BTreeMap<String, JoinDecisionArtifacts>,
        bundles: BTreeMap<String, IdentityBundle>,
        authorization_manifests: BTreeMap<String, crate::model::GroupManifest>,
    }

    impl GroupHarness {
        fn with_bundles(users: &[HarnessUser]) -> Self {
            Self {
                bundles: users
                    .iter()
                    .map(|user| (user.bundle.user_id.clone(), user.bundle.clone()))
                    .collect(),
                ..Self::default()
            }
        }

        fn drain(&mut self, user: &mut HarnessUser, output: CoreOutput) -> CoreOutput {
            let mut aggregate = CoreOutput::default();
            let mut queue: std::collections::VecDeque<_> = output.effects.into();
            aggregate.view_model = output.view_model;
            let mut steps = 0usize;
            while let Some(effect) = queue.pop_front() {
                steps += 1;
                assert!(
                    steps <= 1_000,
                    "group harness effect loop exceeded 1000 steps; next effect: {effect:?}"
                );
                let next = match effect {
                    CoreEffect::AppendGroupEnvelope { append } => {
                        let seq = self
                            .outboxes
                            .entry(append.envelope.group_id.clone())
                            .or_default()
                            .len() as u64
                            + 1;
                        self.outboxes
                            .entry(append.envelope.group_id.clone())
                            .or_default()
                            .push(GroupOutboxRecord {
                                seq,
                                group_id: append.envelope.group_id.clone(),
                                message_id: append.envelope.message_id.clone(),
                                received_at: seq,
                                expires_at: None,
                                state: GroupOutboxRecordState::Available,
                                envelope: append.envelope.clone(),
                            });
                        user.engine
                            .handle_event(CoreEvent::GroupEnvelopeAppended {
                                group_id: append.envelope.group_id,
                                message_id: append.envelope.message_id,
                                seq,
                            })
                            .expect("group envelope appended")
                    }
                    CoreEffect::AppendGroupTransition { append } => {
                        let conflict = self
                            .authorization_manifests
                            .get(&append.group_id)
                            .is_some_and(|manifest| {
                                manifest.roster_version != append.expected_previous_roster_version
                                    || manifest.last_commit_message_id.clone().unwrap_or_default()
                                        != append
                                            .expected_previous_commit_message_id
                                            .clone()
                                            .unwrap_or_default()
                            });
                        if conflict {
                            user.engine
                                .handle_event(CoreEvent::GroupTransitionAppendFailed {
                                    group_id: append.group_id,
                                    transition_id: append.transition_id,
                                    failure: test_failure(
                                        "roster_version_conflict",
                                        false,
                                        Some(409),
                                    ),
                                })
                                .expect("group transition conflict")
                        } else {
                            let outbox = self.outboxes.entry(append.group_id.clone()).or_default();
                            let first_seq = outbox.len() as u64 + 1;
                            for envelope in &append.envelopes {
                                let seq = outbox.len() as u64 + 1;
                                outbox.push(GroupOutboxRecord {
                                    seq,
                                    group_id: append.group_id.clone(),
                                    message_id: envelope.message_id.clone(),
                                    received_at: seq,
                                    expires_at: None,
                                    state: GroupOutboxRecordState::Available,
                                    envelope: envelope.clone(),
                                });
                            }
                            let last_seq = outbox.len() as u64;
                            self.authorization_manifests.insert(
                                append.group_id.clone(),
                                append.authorization_update.manifest.clone(),
                            );
                            user.engine
                                .handle_event(CoreEvent::GroupTransitionAppended {
                                    group_id: append.group_id,
                                    transition_id: append.transition_id,
                                    first_seq,
                                    last_seq,
                                    roster_version: append
                                        .authorization_update
                                        .manifest
                                        .roster_version,
                                    last_commit_message_id: append
                                        .authorization_update
                                        .manifest
                                        .last_commit_message_id,
                                })
                                .expect("group transition appended")
                        }
                    }
                    CoreEffect::GetGroupOutboxHead { get } => {
                        let revoked = self.authorization_manifests.get(&get.group_id).is_some_and(
                            |manifest| {
                                !manifest.members.iter().any(|member| {
                                    member.user_id == get.capability.user_id
                                        && member.status == GroupMemberStatus::Active
                                })
                            },
                        );
                        if revoked {
                            user.engine
                                .handle_event(CoreEvent::GroupOutboxHeadFetchFailed {
                                    group_id: get.group_id,
                                    failure: test_failure(
                                        "group_membership_revoked",
                                        false,
                                        Some(403),
                                    ),
                                })
                                .expect("group membership revoked")
                        } else {
                            let head_seq = self
                                .outboxes
                                .get(&get.group_id)
                                .and_then(|records| records.last())
                                .map(|record| record.seq)
                                .unwrap_or(0);
                            let manifest = self.authorization_manifests.get(&get.group_id);
                            user.engine
                                .handle_event(CoreEvent::GroupOutboxHeadFetched {
                                    group_id: get.group_id,
                                    head_seq,
                                    current_roster_version: manifest
                                        .map(|value| value.roster_version),
                                    last_commit_message_id: manifest
                                        .and_then(|value| value.last_commit_message_id.clone()),
                                })
                                .expect("group outbox head fetched")
                        }
                    }
                    CoreEffect::GetGroupAuthorizationState { get } => {
                        let manifest = self
                            .authorization_manifests
                            .get(&get.group_id)
                            .cloned()
                            .expect("group authorization manifest");
                        let manifest_hash =
                            CoreEngine::manifest_sha256(&manifest).expect("manifest hash");
                        user.engine
                            .handle_event(CoreEvent::GroupAuthorizationStateFetched {
                                group_id: get.group_id,
                                manifest,
                                manifest_hash,
                                last_transition_id: None,
                                phase: crate::transport_contract::GroupAuthorizationPhase::Active,
                                materialized: true,
                            })
                            .expect("group authorization state fetched")
                    }
                    CoreEffect::FetchGroupOutbox { fetch } => {
                        let records = self
                            .outboxes
                            .get(&fetch.group_id)
                            .cloned()
                            .unwrap_or_default()
                            .into_iter()
                            .filter(|record| record.seq >= fetch.from_seq)
                            .take(fetch.limit as usize)
                            .collect::<Vec<_>>();
                        let to_seq = self
                            .outboxes
                            .get(&fetch.group_id)
                            .and_then(|records| records.last())
                            .map(|record| record.seq)
                            .unwrap_or(fetch.from_seq.saturating_sub(1));
                        match user.engine.handle_event(CoreEvent::GroupOutboxFetched {
                            group_id: fetch.group_id,
                            records,
                            to_seq,
                        }) {
                            Ok(output) => output,
                            Err(error) => panic!("group outbox fetched: {error:?}"),
                        }
                    }
                    CoreEffect::PutWelcomePickup { put } => {
                        self.welcome_pickups.insert(
                            (
                                put.descriptor.group_id.clone(),
                                put.descriptor.device_id.clone(),
                            ),
                            (put.descriptor.clone(), put.welcome_b64, put.manifest),
                        );
                        user.engine
                            .handle_event(CoreEvent::WelcomePickupPut {
                                descriptor: put.descriptor,
                            })
                            .expect("welcome pickup put")
                    }
                    CoreEffect::FetchWelcomePickup { fetch } => {
                        let (_, welcome_b64, manifest) = self
                            .welcome_pickups
                            .get(&(
                                fetch.descriptor.group_id.clone(),
                                fetch.descriptor.device_id.clone(),
                            ))
                            .cloned()
                            .expect("stored welcome pickup");
                        user.engine
                            .handle_event(CoreEvent::WelcomePickupFetched {
                                descriptor: fetch.descriptor,
                                welcome_b64,
                                manifest,
                            })
                            .expect("welcome pickup fetched")
                    }
                    CoreEffect::CreateGroupInvite { create } => {
                        let invite_url = format!(
                            "https://example.com/group-invites/{}",
                            create.document.invite_id
                        );
                        self.invites
                            .insert(invite_url.clone(), create.document.clone());
                        self.invite_urls
                            .insert(create.document.invite_id.clone(), invite_url.clone());
                        user.engine
                            .handle_event(CoreEvent::GroupInviteCreated {
                                invite_url,
                                invite: create.document,
                            })
                            .expect("group invite created")
                    }
                    CoreEffect::FetchGroupInvite { fetch } => {
                        let invite = self
                            .invites
                            .get(&fetch.invite_url)
                            .cloned()
                            .expect("stored group invite");
                        user.engine
                            .handle_event(CoreEvent::GroupInviteFetched {
                                invite_url: fetch.invite_url,
                                invite,
                            })
                            .expect("group invite fetched")
                    }
                    CoreEffect::SubmitGroupJoinRequest { submit } => {
                        self.join_requests
                            .insert(submit.request.request_id.clone(), submit.request.clone());
                        user.engine
                            .handle_event(CoreEvent::GroupJoinRequestSubmitted {
                                request: submit.request,
                            })
                            .expect("group join submitted")
                    }
                    CoreEffect::ListGroupJoinRequests { list } => {
                        let requests = self
                            .join_requests
                            .values()
                            .filter(|request| {
                                request.group_id == list.group_id
                                    && matches!(
                                        request.status,
                                        GroupJoinRequestStatus::Pending
                                            | GroupJoinRequestStatus::PendingApproval
                                            | GroupJoinRequestStatus::WaitingForGroupCommit
                                            | GroupJoinRequestStatus::TransitionInProgress
                                    )
                            })
                            .cloned()
                            .collect();
                        user.engine
                            .handle_event(CoreEvent::GroupJoinRequestsListed {
                                group_id: list.group_id,
                                requests,
                            })
                            .expect("group join requests listed")
                    }
                    CoreEffect::GetGroupJoinRequestStatus { get } => {
                        let decision = self
                            .join_decisions
                            .get(&get.request_id)
                            .cloned()
                            .expect("stored group join decision");
                        user.engine
                            .handle_event(CoreEvent::GroupJoinRequestStatusFetched {
                                request: decision.request,
                                welcome_pickup: decision.welcome_pickup,
                                manifest: decision.manifest,
                                start_cursor: decision.start_cursor,
                            })
                            .expect("group join status fetched")
                    }
                    CoreEffect::DecideGroupJoinRequest { decide } => {
                        let mut request = self
                            .join_requests
                            .get(&decide.request_id)
                            .cloned()
                            .expect("stored join request");
                        request.status = match decide.decision {
                            GroupJoinDecision::Approve => {
                                GroupJoinRequestStatus::WaitingForGroupCommit
                            }
                            GroupJoinDecision::Reject => GroupJoinRequestStatus::Rejected,
                        };
                        self.join_requests
                            .insert(request.request_id.clone(), request.clone());
                        let mut start_cursor = decide.start_cursor;
                        if let Some(cursor) = start_cursor.as_mut() {
                            cursor.last_fetched_seq = self
                                .outboxes
                                .get(&decide.group_id)
                                .and_then(|records| records.last())
                                .map(|record| record.seq)
                                .unwrap_or(cursor.last_fetched_seq);
                        }
                        self.join_decisions.insert(
                            request.request_id.clone(),
                            JoinDecisionArtifacts {
                                request: request.clone(),
                                welcome_pickup: decide.welcome_pickup,
                                manifest: decide.manifest,
                                start_cursor,
                            },
                        );
                        user.engine
                            .handle_event(CoreEvent::GroupJoinDecisionApplied { request })
                            .expect("group join decision applied")
                    }
                    CoreEffect::ClaimGroupJoinRequest { claim } => {
                        let mut request = self
                            .join_requests
                            .get(&claim.request_id)
                            .cloned()
                            .expect("stored join request");
                        request.status = GroupJoinRequestStatus::TransitionInProgress;
                        self.join_requests
                            .insert(request.request_id.clone(), request.clone());
                        user.engine
                            .handle_event(CoreEvent::GroupJoinClaimed {
                                request,
                                lease_token: format!("join-lease:{}", claim.request_id),
                                lease_expires_at: u64::MAX,
                            })
                            .expect("group join claimed")
                    }
                    CoreEffect::CompleteGroupJoinRequest { complete } => {
                        let mut request = self
                            .join_requests
                            .get(&complete.request_id)
                            .cloned()
                            .expect("stored join request");
                        request.status = GroupJoinRequestStatus::WelcomeAvailable;
                        self.join_requests
                            .insert(request.request_id.clone(), request.clone());
                        self.join_decisions.insert(
                            request.request_id.clone(),
                            JoinDecisionArtifacts {
                                request: request.clone(),
                                welcome_pickup: Some(complete.welcome_pickup),
                                manifest: Some(complete.manifest),
                                start_cursor: Some(complete.start_cursor),
                            },
                        );
                        user.engine
                            .handle_event(CoreEvent::GroupJoinCompleted { request })
                            .expect("group join completed")
                    }
                    CoreEffect::SubmitGroupLeaveRequest { submit } => {
                        let mut request = submit.request;
                        request.status =
                            crate::model::GroupLeaveRequestStatus::WaitingForGroupCommit;
                        self.leave_requests
                            .insert(request.request_id.clone(), request.clone());
                        user.engine
                            .handle_event(CoreEvent::GroupLeaveRequestSubmitted { request })
                            .expect("group leave submitted")
                    }
                    CoreEffect::ListGroupLeaveRequests { list } => {
                        let requests = self
                            .leave_requests
                            .values()
                            .filter(|request| request.group_id == list.group_id)
                            .cloned()
                            .collect();
                        user.engine
                            .handle_event(CoreEvent::GroupLeaveRequestsListed {
                                group_id: list.group_id,
                                requests,
                            })
                            .expect("group leave requests listed")
                    }
                    CoreEffect::ClaimGroupLeaveRequest { claim } => {
                        let mut request = self
                            .leave_requests
                            .get(&claim.request_id)
                            .cloned()
                            .expect("stored leave request");
                        request.status =
                            crate::model::GroupLeaveRequestStatus::TransitionInProgress;
                        self.leave_requests
                            .insert(request.request_id.clone(), request.clone());
                        user.engine
                            .handle_event(CoreEvent::GroupLeaveClaimed {
                                request,
                                lease_token: format!("leave-lease:{}", claim.request_id),
                                lease_expires_at: u64::MAX,
                            })
                            .expect("group leave claimed")
                    }
                    CoreEffect::FetchIdentityBundle { fetch } => {
                        let bundle = self
                            .bundles
                            .get(&fetch.user_id)
                            .cloned()
                            .expect("known identity bundle");
                        user.engine
                            .handle_event(CoreEvent::IdentityBundleFetched {
                                user_id: fetch.user_id,
                                bundle,
                            })
                            .expect("identity bundle fetched")
                    }
                    CoreEffect::PublishSharedState { publish } => {
                        let saved_bundle =
                            if publish.document_kind == SharedStateDocumentKind::IdentityBundle {
                                let bundle: IdentityBundle = serde_json::from_str(&publish.body)
                                    .expect("published identity bundle");
                                self.bundles.insert(bundle.user_id.clone(), bundle.clone());
                                if bundle.user_id == user.bundle.user_id {
                                    user.bundle = bundle.clone();
                                }
                                Some(bundle)
                            } else {
                                None
                            };
                        user.engine
                            .handle_event(CoreEvent::SharedStatePublished {
                                operation_id: publish.operation_id,
                                document_kind: publish.document_kind,
                                reference: publish.reference,
                                etag: Some("\"group-harness\"".into()),
                                saved_bundle,
                            })
                            .expect("shared state published")
                    }
                    CoreEffect::ReadAttachmentBytes { read } => {
                        let bytes = std::fs::read(&read.attachment_id).expect("attachment bytes");
                        user.engine
                            .handle_event(CoreEvent::AttachmentBytesLoaded {
                                task_id: read.task_id,
                                plaintext: bytes,
                            })
                            .expect("attachment bytes loaded")
                    }
                    CoreEffect::PrepareBlobUpload { upload } => {
                        let scope = if upload.group_id.is_some() {
                            "group"
                        } else {
                            "direct"
                        };
                        assert_eq!(upload.storage_scope.as_deref(), Some(scope));
                        let blob_ref = format!("blob-ref:{}", upload.task_id);
                        let storage_origin = user
                            .bundle
                            .storage_profile
                            .as_ref()
                            .and_then(|profile| profile.base_url.as_deref())
                            .expect("user storage origin");
                        let download_target = format!(
                            "{storage_origin}/v1/storage/blob/{}",
                            urlencoding::encode(&blob_ref)
                        );
                        self.prepared_blob_downloads
                            .insert(blob_ref.clone(), download_target.clone());
                        user.engine
                            .handle_event(CoreEvent::BlobUploadPrepared {
                                task_id: upload.task_id,
                                result: crate::transport_contract::PrepareBlobUploadResult {
                                    blob_ref: blob_ref.clone(),
                                    upload_target: "memory-upload".into(),
                                    upload_headers: BTreeMap::new(),
                                    read_capability: "test-read-capability".into(),
                                    download_target,
                                    upload_expires_at: Some(u64::MAX / 2),
                                    blob_expires_at: Some(u64::MAX / 2),
                                    delete_target: Some(format!(
                                        "{storage_origin}/v1/storage/blob/{}",
                                        urlencoding::encode(&blob_ref)
                                    )),
                                    delete_capability: Some("test-delete-capability".into()),
                                },
                            })
                            .expect("blob upload prepared")
                    }
                    CoreEffect::UploadBlob { upload } => {
                        self.blobs.insert(upload.blob_ref, upload.blob_ciphertext);
                        user.engine
                            .handle_event(CoreEvent::BlobUploaded {
                                task_id: upload.task_id,
                            })
                            .expect("blob uploaded")
                    }
                    CoreEffect::DownloadBlob { download } => {
                        assert_eq!(
                            download.download_target,
                            self.prepared_blob_downloads[&download.blob_ref],
                            "receiver must download from the uploader's runtime"
                        );
                        let blob_ciphertext = self.blobs.get(&download.blob_ref).cloned();
                        user.engine
                            .handle_event(CoreEvent::BlobDownloaded {
                                task_id: download.task_id,
                                blob_ciphertext,
                            })
                            .expect("blob downloaded")
                    }
                    CoreEffect::WriteDownloadedAttachment { write } => {
                        self.downloaded_attachments
                            .insert(write.destination_id, write.plaintext);
                        CoreOutput::default()
                    }
                    CoreEffect::CacheUploadedAttachment { .. } => CoreOutput::default(),
                    CoreEffect::InitializeGroupAuthorization { initialize } => {
                        self.authorization_manifests
                            .insert(initialize.group_id.clone(), initialize.manifest.clone());
                        user.engine
                            .handle_event(CoreEvent::GroupAuthorizationInitialized {
                                group_id: initialize.group_id,
                                roster_version: initialize.manifest.roster_version,
                            })
                            .expect("group authorization initialized")
                    }
                    CoreEffect::ExecuteHttpRequest { request }
                        if request.url.contains("/keypackage-pool/")
                            && request.url.ends_with("/claim") =>
                    {
                        let device_id = request
                            .url
                            .split("/keypackage-pool/")
                            .nth(1)
                            .and_then(|rest| rest.strip_suffix("/claim"))
                            .map(|encoded| {
                                urlencoding::decode(encoded)
                                    .expect("valid device id encoding")
                                    .into_owned()
                            })
                            .expect("claim url must contain a device id");
                        let key_package_b64 = self
                            .bundles
                            .values()
                            .find_map(|bundle| {
                                bundle
                                    .devices
                                    .iter()
                                    .find(|device| device.device_id == device_id)
                                    .and_then(|device| device.keypackage_ref.as_ref())
                                    .map(|keypackage_ref| keypackage_ref.object_ref.clone())
                            })
                            .expect(
                                "group harness must have a cached key package to simulate a claim response",
                            );
                        let body = serde_json::json!({
                            "keyPackage": {
                                "keyPackageId": "test-claim",
                                "keyPackage": key_package_b64,
                                "lifecycleVersion": 1,
                                "notBefore": 0,
                                "createdAt": 0,
                                "expiresAt": 0,
                            }
                        })
                        .to_string();
                        user.engine
                            .handle_event(CoreEvent::HttpResponseReceived {
                                request_id: request.request_id,
                                status: 200,
                                body: Some(body),
                            })
                            .expect("claim response applied")
                    }
                    CoreEffect::PersistState { .. }
                    | CoreEffect::EmitUserNotification { .. }
                    | CoreEffect::ExecuteHttpRequest { .. }
                    | CoreEffect::ScheduleTimer { .. }
                    | CoreEffect::CloseGroupRealtimeConnection { .. } => CoreOutput::default(),
                    other => panic!("unhandled harness effect: {other:?}"),
                };
                if aggregate.view_model.is_none() {
                    aggregate.view_model = next.view_model.clone();
                }
                queue.extend(next.effects);
            }
            aggregate
        }

        fn create_group(
            &mut self,
            owner: &mut HarnessUser,
            title: &str,
            member_user_ids: Vec<String>,
        ) -> (String, String) {
            let output = owner
                .engine
                .handle_command(CoreCommand::CreateGroupConversation {
                    title: title.into(),
                    member_user_ids,
                })
                .expect("create group");
            // `CreateGroupConversation` now claims each target device's
            // one-time KeyPackage sequentially before it can finish; `drain`
            // (which now also simulates `/keypackage-pool/.../claim`
            // responses) must run first so the real view model — carried by
            // whichever response resolves the last outstanding claim — is
            // available, and so every effect that finalize emits also gets
            // drained.
            let drained = self.drain(owner, output);
            let summary = drained
                .view_model
                .as_ref()
                .and_then(|view| view.conversations.first())
                .expect("group summary")
                .clone();
            let group_id = summary.group_id.clone().expect("group id");
            let conversation_id = summary.conversation_id;
            (group_id, conversation_id)
        }

        fn import_welcome(&mut self, user: &mut HarnessUser, group_id: &str) {
            let descriptor = self
                .welcome_pickups
                .iter()
                .find(|((gid, device_id), _)| {
                    gid == group_id && device_id == &user.bundle.devices[0].device_id
                })
                .map(|(_, (descriptor, _, _))| descriptor.clone())
                .expect("welcome descriptor");
            let output = user
                .engine
                .handle_command(CoreCommand::RequestJoinGroup {
                    invite_url: serde_json::to_string(&descriptor).expect("descriptor json"),
                })
                .expect("request welcome import");
            self.drain(user, output);
        }

        fn sync_group(&mut self, user: &mut HarnessUser, group_id: &str) {
            let output = user
                .engine
                .handle_command(CoreCommand::SyncGroupOutbox {
                    group_id: group_id.into(),
                    reason: Some("test".into()),
                })
                .expect("sync group");
            self.drain(user, output);
        }

        fn send_text(&mut self, user: &mut HarnessUser, conversation_id: &str, plaintext: &str) {
            let output = user
                .engine
                .handle_command(CoreCommand::SendGroupTextMessage {
                    conversation_id: conversation_id.into(),
                    plaintext: plaintext.into(),
                })
                .expect("send group text");
            self.drain(user, output);
        }

        fn send_attachment(
            &mut self,
            user: &mut HarnessUser,
            conversation_id: &str,
            descriptor: AttachmentDescriptor,
        ) {
            let output = user
                .engine
                .handle_command(CoreCommand::SendAttachmentMessage {
                    conversation_id: conversation_id.into(),
                    attachment_descriptor: descriptor,
                })
                .expect("send group attachment");
            self.drain(user, output);
        }

        fn download_attachment(
            &mut self,
            user: &mut HarnessUser,
            conversation_id: &str,
            message_id: &str,
            reference: &str,
            destination: &str,
        ) {
            let output = user
                .engine
                .handle_command(CoreCommand::DownloadAttachment {
                    conversation_id: conversation_id.into(),
                    message_id: message_id.into(),
                    reference: reference.into(),
                    destination: destination.into(),
                })
                .expect("download attachment");
            self.drain(user, output);
        }

        fn create_invite(&mut self, user: &mut HarnessUser, group_id: &str) -> String {
            let output = user
                .engine
                .handle_command(CoreCommand::CreateGroupInviteLink {
                    group_id: group_id.into(),
                    expires_at: u64::MAX / 2,
                    max_uses: None,
                })
                .expect("create invite");
            self.drain(user, output);
            self.invites
                .iter()
                .find(|(_, invite)| invite.group_id == group_id)
                .map(|(url, _)| url.clone())
                .expect("invite url")
        }

        fn submit_join(&mut self, user: &mut HarnessUser, invite_url: &str) -> String {
            let output = user
                .engine
                .handle_command(CoreCommand::SubmitGroupJoinRequest {
                    invite_url: invite_url.into(),
                })
                .expect("submit join request");
            self.drain(user, output);
            self.join_requests
                .values()
                .find(|request| request.joiner_user_id == user.bundle.user_id)
                .map(|request| request.request_id.clone())
                .expect("join request id")
        }

        fn list_join_requests(&mut self, user: &mut HarnessUser, group_id: &str) {
            let output = user
                .engine
                .handle_command(CoreCommand::ListGroupJoinRequests {
                    group_id: group_id.into(),
                })
                .expect("list join requests");
            self.drain(user, output);
        }

        fn approve_join(&mut self, user: &mut HarnessUser, group_id: &str, request_id: &str) {
            let output = user
                .engine
                .handle_command(CoreCommand::ApproveGroupJoin {
                    group_id: group_id.into(),
                    request_id: request_id.into(),
                })
                .expect("approve join");
            self.drain(user, output);
        }

        fn list_leave_requests(&mut self, user: &mut HarnessUser, group_id: &str) {
            let output = user
                .engine
                .handle_command(CoreCommand::ListGroupLeaveRequests {
                    group_id: group_id.into(),
                })
                .expect("list leave requests");
            self.drain(user, output);
        }

        fn approve_leave(&mut self, user: &mut HarnessUser, group_id: &str, request_id: &str) {
            let output = user
                .engine
                .handle_command(CoreCommand::ApproveGroupLeave {
                    group_id: group_id.into(),
                    request_id: request_id.into(),
                })
                .expect("approve leave");
            self.drain(user, output);
        }

        fn fetch_join_status(&mut self, user: &mut HarnessUser, group_id: &str, request_id: &str) {
            let request = self
                .join_requests
                .get(request_id)
                .expect("join request")
                .clone();
            let output = user
                .engine
                .handle_event(CoreEvent::GroupJoinRequestStatusFetched {
                    request,
                    welcome_pickup: self
                        .join_decisions
                        .get(request_id)
                        .and_then(|decision| decision.welcome_pickup.clone()),
                    manifest: self
                        .join_decisions
                        .get(request_id)
                        .and_then(|decision| decision.manifest.clone()),
                    start_cursor: self
                        .join_decisions
                        .get(request_id)
                        .and_then(|decision| decision.start_cursor.clone()),
                })
                .expect("fetch join status event");
            self.drain(user, output);
            self.sync_group(user, group_id);
        }

        fn append_forged_membership_record(
            &mut self,
            group_id: &str,
            conversation_id: &str,
            sender: &HarnessUser,
        ) {
            let _ = (group_id, conversation_id, sender);
            // The authoritative FSM v2 Worker rejects forged membership
            // records before assigning a sequence, so the shared outbox is
            // intentionally left unchanged.
        }
    }

    fn harness_user(name: &'static str, mnemonic: &str, device_name: &str) -> HarnessUser {
        let mut engine = CoreEngine::new();
        let mut deployment = sample_deployment();
        deployment.storage_base_info.base_url = Some(format!("https://storage-{name}.example.com"));
        engine
            .handle_command(CoreCommand::ImportDeploymentBundle { bundle: deployment })
            .expect("deployment");
        engine
            .handle_command(CoreCommand::CreateOrLoadIdentity {
                mnemonic: Some(mnemonic.into()),
                device_name: Some(device_name.into()),
                display_name: Some(name.into()),
            })
            .expect("identity");
        let bundle = engine.local_bundle().expect("local bundle").clone();
        HarnessUser {
            name,
            bundle,
            engine,
        }
    }

    fn import_peer_bundles(users: &mut [&mut HarnessUser]) {
        let bundles = users
            .iter()
            .map(|user| user.bundle.clone())
            .collect::<Vec<_>>();
        for user in users {
            for bundle in &bundles {
                if bundle.user_id != user.bundle.user_id {
                    user.engine
                        .handle_command(CoreCommand::ImportIdentityBundle {
                            bundle: bundle.clone(),
                        })
                        .expect("import peer bundle");
                }
            }
        }
    }

    fn group_plaintexts(user: &HarnessUser, conversation_id: &str) -> Vec<String> {
        user.engine
            .state
            .conversations
            .get(conversation_id)
            .expect("conversation")
            .messages
            .iter()
            .filter(|message| message.message_type == MessageType::MlsApplication)
            .filter_map(|message| message.plaintext.clone())
            .collect()
    }

    fn group_attachment_message(user: &HarnessUser, conversation_id: &str) -> (String, String) {
        let message = user
            .engine
            .state
            .conversations
            .get(conversation_id)
            .expect("conversation")
            .messages
            .iter()
            .find(|message| {
                message.message_type == MessageType::MlsApplication
                    && !message.storage_refs.is_empty()
                    && message.plaintext.as_deref().is_some_and(|plaintext| {
                        serde_json::from_str::<AttachmentPayloadMetadata>(plaintext).is_ok()
                    })
            })
            .expect("attachment message");
        (
            message.message_id.clone(),
            message.storage_refs[0].object_ref.clone(),
        )
    }

    fn group_cursor(user: &HarnessUser, group_id: &str) -> u64 {
        user.engine
            .state
            .group_cursors
            .get(group_id)
            .map(|cursor| cursor.last_fetched_seq)
            .unwrap_or_default()
    }

    fn group_cursor_engine(engine: &CoreEngine, group_id: &str) -> u64 {
        engine
            .state
            .group_cursors
            .get(group_id)
            .map(|cursor| cursor.last_fetched_seq)
            .unwrap_or_default()
    }

    fn group_roster_version(user: &HarnessUser, group_id: &str) -> u64 {
        user.engine
            .state
            .group_states
            .get(group_id)
            .expect("group state")
            .manifest
            .roster_version
    }

    fn acknowledge_pending_group_transition(engine: &mut CoreEngine, group_id: &str) -> CoreOutput {
        let pending = engine
            .state
            .group_states
            .get(group_id)
            .and_then(|state| state.pending_group_transition.clone())
            .expect("pending group transition");
        let first_seq = group_cursor_engine(engine, group_id).saturating_add(1);
        let last_seq = first_seq + pending.envelopes.len().saturating_sub(1) as u64;
        let output = engine
            .handle_event(CoreEvent::GroupTransitionAppended {
                group_id: group_id.to_string(),
                transition_id: pending.transition_id,
                first_seq,
                last_seq,
                roster_version: pending.proposed_manifest.roster_version,
                last_commit_message_id: pending.proposed_manifest.last_commit_message_id,
            })
            .expect("acknowledge group transition");
        let welcome_descriptors = output
            .effects
            .iter()
            .filter_map(|effect| match effect {
                CoreEffect::PutWelcomePickup { put } => Some(put.descriptor.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        for descriptor in welcome_descriptors {
            engine
                .handle_event(CoreEvent::WelcomePickupPut { descriptor })
                .expect("acknowledge welcome pickup");
        }
        output
    }

    #[test]
    fn direct_pcs_initial_hash_ignores_forged_commit_before_welcome() {
        assert_direct_pcs_authenticated_initial_hash(true);
    }

    #[test]
    fn direct_pcs_initial_hash_ignores_forged_commit_after_welcome() {
        assert_direct_pcs_authenticated_initial_hash(false);
    }

    fn assert_direct_pcs_authenticated_initial_hash(forged_before_welcome: bool) {
        let mut chat = unjoined_direct_chat();
        let conversation_id = chat.conversation_id.clone();
        let bob_device_id = chat.bob_device_id.clone();
        let commit = first_pending_envelope(&chat.alice, &bob_device_id, MessageType::MlsCommit);
        let welcome = first_pending_envelope(&chat.alice, &bob_device_id, MessageType::MlsWelcome);
        let expected = chat.alice.state.conversations[&conversation_id]
            .pcs
            .last_certified_commit_hash
            .clone()
            .expect("creator initial hash");
        assert_ne!(
            expected,
            crate::direct_pcs::commit_hash_from_b64(commit.inline_ciphertext.as_deref().unwrap())
                .unwrap()
        );

        // Keep a parseable old epoch header, but invalidate the encrypted Commit
        // and its envelope proof. No trusted client signs this payload.
        let mut forged = commit.clone();
        let mut bytes = STANDARD
            .decode(forged.inline_ciphertext.as_deref().unwrap())
            .unwrap();
        *bytes.last_mut().expect("commit bytes") ^= 1;
        forged.inline_ciphertext = Some(STANDARD.encode(bytes));
        forged.message_id = format!("{}:forged", commit.message_id);
        forged.sender_proof.value = "invalid-signature".into();
        assert!(
            MlsAdapter::protocol_message_epoch(forged.inline_ciphertext.as_deref().unwrap())
                .unwrap()
                < conversation_epoch(&chat.alice, &conversation_id)
        );

        if forged_before_welcome {
            deliver_inbox_envelope(&mut chat.bob, &bob_device_id, forged.clone(), 1);
            assert!(
                chat.bob.state.conversations[&conversation_id]
                    .pcs
                    .last_certified_commit_hash
                    .is_none()
            );
            assert!(pending_has_message(
                &chat.bob,
                &bob_device_id,
                &forged.message_id
            ));
        }
        let before_welcome = chat.bob.refresh_snapshot();
        let welcome_output = deliver_inbox_envelope(&mut chat.bob, &bob_device_id, welcome, 2);
        assert_eq!(
            chat.bob.state.conversations[&conversation_id]
                .pcs
                .last_certified_commit_hash
                .as_ref(),
            Some(&expected)
        );
        // Check emitted persistence, not just the in-memory snapshot.
        let persisted = CoreEngine::try_from_restored_state(fold_persist_onto_snapshot(
            before_welcome,
            &welcome_output,
        ))
        .expect("restore persisted initial hash");
        assert_eq!(
            persisted.state.conversations[&conversation_id]
                .pcs
                .last_certified_commit_hash
                .as_ref(),
            Some(&expected)
        );
        if !forged_before_welcome {
            deliver_inbox_envelope(&mut chat.bob, &bob_device_id, forged.clone(), 3);
        }
        assert!(!pending_has_message(
            &chat.bob,
            &bob_device_id,
            &forged.message_id
        ));
        assert_eq!(
            chat.bob.state.conversations[&conversation_id]
                .pcs
                .last_certified_commit_hash
                .as_ref(),
            Some(&expected)
        );
        chat.bob =
            CoreEngine::try_from_restored_state(chat.bob.refresh_snapshot()).expect("restart");

        // Both parties can send before the creating Commit is delivered.
        chat.bob
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "welcome is sufficient".into(),
            })
            .expect("reply without creating Commit");
        let reply = last_pending_application_envelope(&chat.bob, &chat.alice_device_id);
        deliver_inbox_envelope(&mut chat.alice, &chat.alice_device_id, reply, 4);
        assert!(conversation_has_plaintext(
            &chat.alice,
            &conversation_id,
            "welcome is sufficient"
        ));
        chat.alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "authenticated initial chain".into(),
            })
            .expect("creator send");
        let application = last_pending_application_envelope(&chat.alice, &bob_device_id);
        deliver_inbox_envelope(&mut chat.bob, &bob_device_id, application, 5);
        assert!(conversation_has_plaintext(
            &chat.bob,
            &conversation_id,
            "authenticated initial chain"
        ));
        deliver_inbox_envelope(&mut chat.bob, &bob_device_id, commit, 6);
        assert_eq!(
            chat.bob.state.conversations[&conversation_id]
                .pcs
                .last_certified_commit_hash
                .as_ref(),
            Some(&expected)
        );
        let epoch = conversation_epoch(&chat.alice, &conversation_id);
        prime_direct_pcs_count(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        trigger_direct_pcs_from_committer(&mut chat);
        complete_direct_pcs_handshake(&mut chat);
        assert_eq!(conversation_epoch(&chat.alice, &conversation_id), epoch + 1);
        assert_eq!(conversation_epoch(&chat.bob, &conversation_id), epoch + 1);
        assert_eq!(
            chat.alice.state.conversations[&conversation_id]
                .pcs
                .last_certified_commit_hash,
            chat.bob.state.conversations[&conversation_id]
                .pcs
                .last_certified_commit_hash
        );
    }

    #[test]
    fn direct_pcs_handshake_advances_epoch_and_binds_new_hash() {
        let mut chat = paired_direct_chat();
        let genesis_hash = chat
            .alice
            .state
            .conversations
            .get(&chat.conversation_id)
            .expect("alice conversation")
            .pcs
            .last_certified_commit_hash
            .clone()
            .expect("genesis hash");
        let epoch_before = conversation_epoch(&chat.alice, &chat.conversation_id);
        prime_direct_pcs_count(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        trigger_direct_pcs_from_committer(&mut chat);
        complete_direct_pcs_handshake(&mut chat);

        let epoch_after = conversation_epoch(&chat.alice, &chat.conversation_id);
        assert_eq!(epoch_after, epoch_before + 1);
        assert_eq!(
            conversation_epoch(&chat.bob, &chat.conversation_id),
            epoch_after
        );
        let new_hash = chat
            .alice
            .state
            .conversations
            .get(&chat.conversation_id)
            .expect("alice conversation")
            .pcs
            .last_certified_commit_hash
            .clone()
            .expect("certified hash");
        assert_ne!(new_hash, genesis_hash);
        assert_eq!(
            chat.bob
                .state
                .conversations
                .get(&chat.conversation_id)
                .expect("bob conversation")
                .pcs
                .last_certified_commit_hash
                .as_deref(),
            Some(new_hash.as_str())
        );
        assert!(
            chat.alice
                .state
                .conversations
                .get(&chat.conversation_id)
                .expect("alice conversation")
                .pcs
                .handshake
                .is_none()
        );

        chat.alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: chat.conversation_id.clone(),
                plaintext: "after pcs".into(),
            })
            .expect("send after handshake");
        deliver_pending_outbox_to_device(&mut chat.bob, &chat.alice, &chat.bob_device_id);
        assert!(
            chat.bob
                .state
                .conversations
                .get(&chat.conversation_id)
                .expect("bob conversation")
                .messages
                .iter()
                .any(|message| message.plaintext.as_deref() == Some("after pcs"))
        );
    }

    #[test]
    fn direct_pcs_offline_acceptor_does_not_block_send_then_advances() {
        let mut chat = paired_direct_chat();
        let epoch_before = conversation_epoch(&chat.alice, &chat.conversation_id);
        prime_direct_pcs_count(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        trigger_direct_pcs_from_committer(&mut chat);
        let conversation_id = chat.conversation_id.clone();
        for index in 0..3 {
            committer_engine_mut(&mut chat)
                .handle_command(CoreCommand::SendTextMessage {
                    conversation_id: conversation_id.clone(),
                    plaintext: format!("queued-{index}"),
                })
                .expect("send while acceptor is offline");
        }
        assert_eq!(
            conversation_epoch(committer_engine(&chat), &chat.conversation_id),
            epoch_before
        );
        complete_direct_pcs_handshake(&mut chat);
        assert_eq!(
            conversation_epoch(&chat.alice, &chat.conversation_id),
            epoch_before + 1
        );
        assert_eq!(
            conversation_epoch(&chat.bob, &chat.conversation_id),
            epoch_before + 1
        );
    }

    #[test]
    fn direct_pcs_rejects_a_second_commit_in_the_same_epoch() {
        let mut chat = paired_direct_chat();
        prime_direct_pcs_count(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        trigger_direct_pcs_from_committer(&mut chat);
        let alice_is = alice_is_committer(&chat);
        if alice_is {
            deliver_pending_outbox_to_device(&mut chat.bob, &chat.alice, &chat.bob_device_id);
        } else {
            deliver_pending_outbox_to_device(&mut chat.alice, &chat.bob, &chat.alice_device_id);
        }
        let first_commit = committer_engine(&chat)
            .state
            .pending_outbox
            .iter()
            .rev()
            .find(|item| item.envelope.message_type == MessageType::MlsCommit)
            .expect("staged pcs commit")
            .envelope
            .clone();
        let conversation_id = chat.conversation_id.clone();
        let second = committer_engine(&chat)
            .state
            .mls_adapter
            .as_ref()
            .expect("adapter")
            .create_forked_direct_self_update(&conversation_id)
            .expect("second fork commit");
        assert_ne!(
            first_commit.inline_ciphertext.as_deref(),
            Some(second.commit_b64.as_str())
        );
        let mut conflicting = first_commit.clone();
        conflicting.message_id = format!("{}:conflict", conflicting.message_id);
        conflicting.inline_ciphertext = Some(second.commit_b64);
        let acceptor_device_id = acceptor_device_id(&chat).to_string();
        let acceptor = acceptor_engine_mut(&mut chat);
        acceptor
            .handle_event(CoreEvent::InboxRecordsFetched {
                device_id: acceptor_device_id.clone(),
                to_seq: 10_000,
                records: vec![InboxRecord {
                    seq: 10_000,
                    recipient_device_id: acceptor_device_id,
                    message_id: conflicting.message_id.clone(),
                    received_at: 10_000,
                    expires_at: None,
                    state: InboxRecordState::Available,
                    envelope: conflicting,
                }],
            })
            .expect("conflicting commit ingested");
        let acceptor_state = acceptor_engine(&chat)
            .state
            .conversations
            .get(&chat.conversation_id)
            .expect("acceptor conversation");
        assert_eq!(
            acceptor_state.conversation.state,
            ConversationState::NeedsRebuild
        );
        assert_eq!(
            acceptor_state.recovery_status,
            crate::conversation::RecoveryStatus::NeedsRebuild
        );
    }

    #[test]
    fn direct_pcs_hard_debt_marks_degraded_but_still_sends() {
        let mut chat = paired_direct_chat();
        prime_direct_pcs_count(&mut chat, DIRECT_PCS_DEBT_HARD - 1);
        chat.alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: chat.conversation_id.clone(),
                plaintext: "still sending".into(),
            })
            .expect("send at hard debt");
        assert!(
            chat.alice
                .state
                .conversations
                .get(&chat.conversation_id)
                .expect("alice conversation")
                .pcs
                .degraded
        );
        chat.alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: chat.conversation_id.clone(),
                plaintext: "after degraded".into(),
            })
            .expect("send while degraded");
        deliver_pending_outbox_to_device(&mut chat.bob, &chat.alice, &chat.bob_device_id);
        assert!(
            chat.bob
                .state
                .conversations
                .get(&chat.conversation_id)
                .expect("bob conversation")
                .messages
                .iter()
                .any(|message| message.plaintext.as_deref() == Some("after degraded"))
        );
    }

    #[test]
    fn direct_pcs_decrypts_previous_epoch_message_after_merge() {
        let mut chat = paired_direct_chat();
        prime_direct_pcs_count(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        trigger_direct_pcs_from_committer(&mut chat);
        let alice_was_committer = alice_is_committer(&chat);
        complete_direct_pcs_committer_only(&mut chat);
        let conversation_id = chat.conversation_id.clone();
        if alice_was_committer {
            chat.bob
                .handle_command(CoreCommand::SendTextMessage {
                    conversation_id: conversation_id.clone(),
                    plaintext: "late-epoch".into(),
                })
                .expect("bob send on previous epoch");
            deliver_pending_outbox_types(
                &mut chat.alice,
                &chat.bob,
                &chat.alice_device_id,
                &[MessageType::MlsApplication],
            );
            assert!(conversation_has_plaintext(
                &chat.alice,
                &conversation_id,
                "late-epoch"
            ));
            assert_ne!(
                chat.alice
                    .state
                    .conversations
                    .get(&conversation_id)
                    .expect("conversation")
                    .conversation
                    .state,
                ConversationState::NeedsRebuild
            );
        } else {
            chat.alice
                .handle_command(CoreCommand::SendTextMessage {
                    conversation_id: conversation_id.clone(),
                    plaintext: "late-epoch".into(),
                })
                .expect("alice send on previous epoch");
            deliver_pending_outbox_types(
                &mut chat.bob,
                &chat.alice,
                &chat.bob_device_id,
                &[MessageType::MlsApplication],
            );
            assert!(conversation_has_plaintext(
                &chat.bob,
                &conversation_id,
                "late-epoch"
            ));
            assert_ne!(
                chat.bob
                    .state
                    .conversations
                    .get(&conversation_id)
                    .expect("conversation")
                    .conversation
                    .state,
                ConversationState::NeedsRebuild
            );
        }
    }

    #[test]
    fn direct_pcs_restore_still_decrypts_previous_epoch() {
        let mut chat = paired_direct_chat();
        prime_direct_pcs_count(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        trigger_direct_pcs_from_committer(&mut chat);
        complete_direct_pcs_protocol_only(&mut chat);
        chat.alice = CoreEngine::try_from_restored_state(chat.alice.refresh_snapshot())
            .expect("restore alice");
        chat.bob =
            CoreEngine::try_from_restored_state(chat.bob.refresh_snapshot()).expect("restore bob");
        deliver_pending_outbox_types(
            &mut chat.bob,
            &chat.alice,
            &chat.bob_device_id,
            &[MessageType::MlsApplication],
        );
        deliver_pending_outbox_types(
            &mut chat.alice,
            &chat.bob,
            &chat.alice_device_id,
            &[MessageType::MlsApplication],
        );
        assert!(
            conversation_has_plaintext(&chat.alice, &chat.conversation_id, "pcs trigger")
                || conversation_has_plaintext(&chat.bob, &chat.conversation_id, "pcs trigger")
        );
    }

    #[test]
    fn direct_pcs_stale_accept_during_next_handshake_is_idempotent() {
        let mut chat = paired_direct_chat();
        prime_direct_pcs_count(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        trigger_direct_pcs_from_committer(&mut chat);
        complete_direct_pcs_handshake(&mut chat);
        let stale_accept = chat
            .alice
            .state
            .pending_outbox
            .iter()
            .chain(chat.bob.state.pending_outbox.iter())
            .filter(|item| item.envelope.message_type == MessageType::ControlDirectCommitAccept)
            .map(|item| item.envelope.clone())
            .next()
            .expect("previous-round accept");
        prime_direct_pcs_count(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        trigger_direct_pcs_from_committer(&mut chat);
        assert!(
            committer_engine(&chat)
                .state
                .conversations
                .get(&chat.conversation_id)
                .expect("conversation")
                .pcs
                .handshake
                .is_some()
        );
        let committer_device = committer_device_id(&chat);
        let mut stale_accept = stale_accept;
        stale_accept.recipient_device_id = committer_device.clone();
        stale_accept.message_id = format!("{}:replay", stale_accept.message_id);
        committer_engine_mut(&mut chat)
            .handle_event(CoreEvent::InboxRecordsFetched {
                device_id: committer_device.clone(),
                to_seq: 20_000,
                records: vec![InboxRecord {
                    seq: 20_000,
                    recipient_device_id: committer_device,
                    message_id: stale_accept.message_id.clone(),
                    received_at: 20_000,
                    expires_at: None,
                    state: InboxRecordState::Available,
                    envelope: stale_accept,
                }],
            })
            .expect("stale accept replayed");
        let committer_state = committer_engine(&chat)
            .state
            .conversations
            .get(&chat.conversation_id)
            .expect("conversation");
        assert_eq!(
            committer_state.conversation.state,
            ConversationState::Active
        );
        assert!(committer_state.pcs.handshake.is_some());
        let conversation_id = chat.conversation_id.clone();
        committer_engine_mut(&mut chat)
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id,
                plaintext: "still sending".into(),
            })
            .expect("send after stale accept");
    }

    #[test]
    fn direct_pcs_offered_handshake_defers_membership_until_apply() {
        let mut chat = paired_direct_chat();
        let alice_was_committer = alice_is_committer(&chat);
        prime_direct_pcs_count(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        trigger_direct_pcs_from_committer(&mut chat);
        let committer = if alice_was_committer {
            &chat.alice
        } else {
            &chat.bob
        };
        assert!(
            committer
                .state
                .conversations
                .get(&chat.conversation_id)
                .expect("committer conversation")
                .pcs
                .handshake
                .is_some()
        );
        assert!(
            !committer
                .state
                .conversations
                .get(&chat.conversation_id)
                .expect("committer conversation")
                .pcs
                .handshake
                .as_ref()
                .is_some_and(DirectPcsHandshake::is_promised)
        );
        let (peer_mnemonic, peer_user_id) = if alice_was_committer {
            (
                BOB_MNEMONIC,
                chat.bob
                    .state
                    .local_identity
                    .as_ref()
                    .expect("bob identity")
                    .user_identity
                    .user_id
                    .clone(),
            )
        } else {
            (
                ALICE_MNEMONIC,
                chat.alice
                    .state
                    .local_identity
                    .as_ref()
                    .expect("alice identity")
                    .user_identity
                    .user_id
                    .clone(),
            )
        };
        let laptop_id = add_extra_peer_device(
            if alice_was_committer {
                &mut chat.alice
            } else {
                &mut chat.bob
            },
            &peer_user_id,
            peer_mnemonic,
        );
        let committer = if alice_was_committer {
            &chat.alice
        } else {
            &chat.bob
        };
        assert!(
            committer
                .state
                .conversations
                .get(&chat.conversation_id)
                .and_then(|state| state.pcs.handshake.as_ref())
                .is_some()
        );
        let members_before = committer
            .state
            .mls_adapter
            .as_ref()
            .expect("adapter")
            .member_device_ids(&chat.conversation_id)
            .expect("members");
        assert!(!members_before.contains(&laptop_id));
        assert!(!committer.state.pending_outbox.iter().any(|item| {
            item.envelope.message_type == MessageType::MlsWelcome
                && item.envelope.recipient_device_id == laptop_id
        }));
        assert_ne!(
            committer
                .state
                .conversations
                .get(&chat.conversation_id)
                .expect("conversation")
                .conversation
                .state,
            ConversationState::NeedsRebuild
        );
        complete_direct_pcs_protocol_only(&mut chat);
        let committer = if alice_was_committer {
            &chat.alice
        } else {
            &chat.bob
        };
        let members_after = committer
            .state
            .mls_adapter
            .as_ref()
            .expect("adapter")
            .member_device_ids(&chat.conversation_id)
            .expect("members after pcs");
        assert!(members_after.contains(&laptop_id));
    }

    #[test]
    fn direct_pcs_inbox_persist_keeps_final_previous_after_apply_and_app() {
        let mut chat = paired_direct_chat();
        let alice_was_committer = alice_is_committer(&chat);
        prime_direct_pcs_count(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        trigger_direct_pcs_from_committer(&mut chat);
        deliver_committer_commit_to_acceptor(&mut chat);
        let conversation_id = chat.conversation_id.clone();
        let committer_device = if alice_was_committer {
            chat.alice_device_id.clone()
        } else {
            chat.bob_device_id.clone()
        };
        let acceptor = if alice_was_committer {
            &mut chat.bob
        } else {
            &mut chat.alice
        };
        acceptor
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "after-accept".into(),
            })
            .expect("acceptor sends during handshake");
        let accept = first_pending_envelope(
            acceptor,
            &committer_device,
            MessageType::ControlDirectCommitAccept,
        );
        let application = last_pending_application_envelope(acceptor, &committer_device);
        let committer = if alice_was_committer {
            &mut chat.alice
        } else {
            &mut chat.bob
        };
        let pre_snapshot = committer.refresh_snapshot();
        let output = committer
            .handle_event(CoreEvent::InboxRecordsFetched {
                device_id: committer_device.clone(),
                to_seq: 50_001,
                records: vec![
                    InboxRecord {
                        seq: 50_000,
                        recipient_device_id: committer_device.clone(),
                        message_id: accept.message_id.clone(),
                        received_at: 50_000,
                        expires_at: None,
                        state: InboxRecordState::Available,
                        envelope: accept,
                    },
                    InboxRecord {
                        seq: 50_001,
                        recipient_device_id: committer_device.clone(),
                        message_id: application.message_id.clone(),
                        received_at: 50_001,
                        expires_at: None,
                        state: InboxRecordState::Available,
                        envelope: application,
                    },
                ],
            })
            .expect("accept plus application in one batch");
        assert!(
            committer
                .state
                .conversations
                .get(&conversation_id)
                .expect("conversation")
                .pcs
                .handshake
                .is_none()
        );
        assert!(conversation_has_plaintext(
            committer,
            &conversation_id,
            "after-accept"
        ));
        let restored =
            CoreEngine::try_from_restored_state(fold_persist_onto_snapshot(pre_snapshot, &output))
                .expect("restore folded persist");
        assert!(
            restored
                .state
                .conversations
                .get(&conversation_id)
                .expect("restored conversation")
                .pcs
                .handshake
                .is_none()
        );
        assert!(conversation_has_plaintext(
            &restored,
            &conversation_id,
            "after-accept"
        ));
    }

    #[test]
    fn direct_pcs_handshake_stores_commit_not_store_patch() {
        let mut chat = paired_direct_chat();
        prime_direct_pcs_count(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        trigger_direct_pcs_from_committer(&mut chat);
        let conversation_id = chat.conversation_id.clone();
        committer_engine_mut(&mut chat)
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id,
                plaintext: "live after stage".into(),
            })
            .expect("live send after stage");
        let handshake = committer_engine(&chat)
            .state
            .conversations
            .get(&chat.conversation_id)
            .and_then(|state| state.pcs.handshake.clone())
            .expect("handshake");
        assert!(!handshake.commit_b64.is_empty());
        let json = serde_json::to_value(&handshake).expect("handshake json");
        assert!(json.get("patch").is_none());
        let pcs_json = serde_json::to_value(
            &committer_engine(&chat)
                .state
                .conversations
                .get(&chat.conversation_id)
                .expect("conversation")
                .pcs,
        )
        .expect("pcs json");
        assert!(pcs_json.get("previousEpochMls").is_none());
    }

    #[test]
    fn direct_pcs_persisted_live_cannot_rebuild_consumed_next_epoch_keys() {
        let mut chat = paired_direct_chat();
        prime_direct_pcs_count(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        trigger_direct_pcs_from_committer(&mut chat);
        let conversation_id = chat.conversation_id.clone();
        let alice_was_committer = alice_is_committer(&chat);
        let acceptor_device = acceptor_device_id(&chat).to_string();
        let committer_device = committer_device_id(&chat);
        let pcs_commit_b64 = committer_engine(&chat)
            .state
            .conversations
            .get(&conversation_id)
            .and_then(|state| state.pcs.handshake.as_ref())
            .map(|handshake| handshake.commit_b64.clone())
            .expect("pcs commit");
        committer_engine_mut(&mut chat)
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "late-e".into(),
            })
            .expect("late e during handshake");
        let late_e = last_pending_application_envelope(committer_engine(&chat), &acceptor_device);
        complete_direct_pcs_protocol_only(&mut chat);
        {
            let committer = if alice_was_committer {
                &mut chat.alice
            } else {
                &mut chat.bob
            };
            committer
                .handle_command(CoreCommand::SendTextMessage {
                    conversation_id: conversation_id.clone(),
                    plaintext: "next-epoch".into(),
                })
                .expect("e+1 send");
        }
        let next_epoch = last_pending_application_envelope(
            if alice_was_committer {
                &chat.alice
            } else {
                &chat.bob
            },
            &acceptor_device,
        );
        let acceptor = if alice_was_committer {
            &mut chat.bob
        } else {
            &mut chat.alice
        };
        deliver_inbox_envelope(acceptor, &acceptor_device, next_epoch.clone(), 40_000);
        let acceptor = if alice_was_committer {
            &chat.bob
        } else {
            &chat.alice
        };
        assert!(conversation_has_plaintext(
            acceptor,
            &conversation_id,
            "next-epoch"
        ));
        let serialized = acceptor
            .state
            .mls_adapter
            .as_ref()
            .expect("adapter")
            .export_persisted_group_state(&conversation_id)
            .expect("persist live");
        let summary = acceptor
            .state
            .mls_adapter
            .as_ref()
            .expect("adapter")
            .export_group_summary(&conversation_id)
            .expect("summary");
        let restored = MlsAdapter::restore_from_persisted_states(&[(
            conversation_id.clone(),
            summary,
            Some(serialized),
        )])
        .expect("restore live")
        .adapter
        .expect("adapter");
        let mut restored = restored;
        match restored
            .ingest_message(
                &conversation_id,
                &committer_device,
                MessageType::MlsCommit,
                &pcs_commit_b64,
            )
            .expect("replay C")
        {
            IngestResult::IgnoredReplay | IngestResult::PendingRetry => {}
            IngestResult::AppliedCommit { .. } => {
                panic!("persisted live must not re-merge certified commit C")
            }
            other => panic!("unexpected C ingest: {other:?}"),
        }
        match restored
            .ingest_message(
                &conversation_id,
                &committer_device,
                MessageType::MlsApplication,
                next_epoch.inline_ciphertext.as_deref().unwrap_or_default(),
            )
            .expect("replay consumed e+1")
        {
            IngestResult::IgnoredReplay => {}
            IngestResult::AppliedApplication(_) => {
                panic!("consumed e+1 generation must not decrypt from persisted live + C")
            }
            other => panic!("unexpected consumed ingest: {other:?}"),
        }
        match restored
            .ingest_message(
                &conversation_id,
                &committer_device,
                MessageType::MlsApplication,
                late_e.inline_ciphertext.as_deref().unwrap_or_default(),
            )
            .expect("late e")
        {
            IngestResult::AppliedApplication(application) => {
                let plaintext = String::from_utf8(application.plaintext).expect("utf8");
                assert!(plaintext.contains("late-e"));
                assert!(application.from_previous_epoch);
            }
            other => panic!("expected late-e application, got {other:?}"),
        }
    }

    #[test]
    fn direct_pcs_membership_commit_before_certificate_replays_after_apply() {
        let mut chat = paired_direct_chat();
        let alice_was_committer = alice_is_committer(&chat);
        let acceptor_device = acceptor_device_id(&chat).to_string();
        prime_direct_pcs_count(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        trigger_direct_pcs_from_committer(&mut chat);
        let pcs_commit_b64 = committer_engine(&chat)
            .state
            .conversations
            .get(&chat.conversation_id)
            .and_then(|state| state.pcs.handshake.as_ref())
            .map(|handshake| handshake.commit_b64.clone())
            .expect("pcs commit");
        complete_direct_pcs_committer_only(&mut chat);
        assert!(if alice_was_committer {
            chat.bob
                .state
                .conversations
                .get(&chat.conversation_id)
                .and_then(|state| state.pcs.handshake.as_ref())
                .is_some()
        } else {
            chat.alice
                .state
                .conversations
                .get(&chat.conversation_id)
                .and_then(|state| state.pcs.handshake.as_ref())
                .is_some()
        });
        let (peer_mnemonic, peer_user_id) = if alice_was_committer {
            (
                BOB_MNEMONIC,
                chat.bob
                    .state
                    .local_identity
                    .as_ref()
                    .expect("bob identity")
                    .user_identity
                    .user_id
                    .clone(),
            )
        } else {
            (
                ALICE_MNEMONIC,
                chat.alice
                    .state
                    .local_identity
                    .as_ref()
                    .expect("alice identity")
                    .user_identity
                    .user_id
                    .clone(),
            )
        };
        let laptop_id = add_extra_peer_device(
            if alice_was_committer {
                &mut chat.alice
            } else {
                &mut chat.bob
            },
            &peer_user_id,
            peer_mnemonic,
        );
        let membership = if alice_was_committer {
            &chat.alice
        } else {
            &chat.bob
        }
        .state
        .pending_outbox
        .iter()
        .rev()
        .find(|item| {
            item.envelope.recipient_device_id == acceptor_device
                && item.envelope.message_type == MessageType::MlsCommit
                && item.envelope.inline_ciphertext.as_deref() != Some(pcs_commit_b64.as_str())
        })
        .expect("membership commit")
        .envelope
        .clone();
        let complete_cert = first_pending_envelope(
            if alice_was_committer {
                &chat.alice
            } else {
                &chat.bob
            },
            &acceptor_device,
            MessageType::ControlDirectCommitAccept,
        );
        deliver_inbox_envelope(
            if alice_was_committer {
                &mut chat.bob
            } else {
                &mut chat.alice
            },
            &acceptor_device,
            membership.clone(),
            61_000,
        );
        let acceptor = if alice_was_committer {
            &chat.bob
        } else {
            &chat.alice
        };
        assert!(
            acceptor
                .state
                .sync_states
                .get(&acceptor_device)
                .is_some_and(|sync| sync
                    .pending_records
                    .values()
                    .any(|record| record.envelope.message_id == membership.message_id))
        );
        let restored_acceptor = CoreEngine::try_from_restored_state(acceptor.refresh_snapshot())
            .expect("restore acceptor with pending membership");
        if alice_was_committer {
            chat.bob = restored_acceptor;
        } else {
            chat.alice = restored_acceptor;
        }
        let acceptor = if alice_was_committer {
            &chat.bob
        } else {
            &chat.alice
        };
        assert!(
            acceptor
                .state
                .sync_states
                .get(&acceptor_device)
                .is_some_and(|sync| !sync.pending_records.is_empty())
        );
        deliver_inbox_envelope(
            if alice_was_committer {
                &mut chat.bob
            } else {
                &mut chat.alice
            },
            &acceptor_device,
            complete_cert,
            61_001,
        );
        let acceptor = if alice_was_committer {
            &chat.bob
        } else {
            &chat.alice
        };
        let committer = if alice_was_committer {
            &chat.alice
        } else {
            &chat.bob
        };
        assert!(
            acceptor
                .state
                .conversations
                .get(&chat.conversation_id)
                .expect("conversation")
                .pcs
                .handshake
                .is_none()
        );
        let acceptor_members = acceptor
            .state
            .mls_adapter
            .as_ref()
            .expect("adapter")
            .member_device_ids(&chat.conversation_id)
            .expect("acceptor members");
        let committer_members = committer
            .state
            .mls_adapter
            .as_ref()
            .expect("adapter")
            .member_device_ids(&chat.conversation_id)
            .expect("committer members");
        assert!(committer_members.contains(&laptop_id));
        assert!(acceptor_members.contains(&laptop_id));
    }

    #[test]
    fn direct_pcs_late_epoch_decrypt_does_not_drop_pending_next_epoch() {
        let mut chat = paired_direct_chat();
        let alice_was_committer = alice_is_committer(&chat);
        let acceptor_device = acceptor_device_id(&chat).to_string();
        let conversation_id = chat.conversation_id.clone();
        prime_direct_pcs_count(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        trigger_direct_pcs_from_committer(&mut chat);
        committer_engine_mut(&mut chat)
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "late-e".into(),
            })
            .expect("late e during handshake");
        let late_e = last_pending_application_envelope(committer_engine(&chat), &acceptor_device);
        complete_direct_pcs_committer_only(&mut chat);
        {
            let committer = if alice_was_committer {
                &mut chat.alice
            } else {
                &mut chat.bob
            };
            committer
                .handle_command(CoreCommand::SendTextMessage {
                    conversation_id: conversation_id.clone(),
                    plaintext: "next-epoch".into(),
                })
                .expect("e+1 send");
        }
        let next_epoch = last_pending_application_envelope(
            if alice_was_committer {
                &chat.alice
            } else {
                &chat.bob
            },
            &acceptor_device,
        );
        let complete_cert = first_pending_envelope(
            if alice_was_committer {
                &chat.alice
            } else {
                &chat.bob
            },
            &acceptor_device,
            MessageType::ControlDirectCommitAccept,
        );
        deliver_inbox_envelope(
            if alice_was_committer {
                &mut chat.bob
            } else {
                &mut chat.alice
            },
            &acceptor_device,
            next_epoch.clone(),
            70_000,
        );
        assert!(pending_has_message(
            if alice_was_committer {
                &chat.bob
            } else {
                &chat.alice
            },
            &acceptor_device,
            &next_epoch.message_id,
        ));
        deliver_inbox_envelope(
            if alice_was_committer {
                &mut chat.bob
            } else {
                &mut chat.alice
            },
            &acceptor_device,
            late_e,
            70_001,
        );
        let acceptor = if alice_was_committer {
            &chat.bob
        } else {
            &chat.alice
        };
        assert!(conversation_has_plaintext(
            acceptor,
            &conversation_id,
            "late-e"
        ));
        assert!(pending_has_message(
            acceptor,
            &acceptor_device,
            &next_epoch.message_id,
        ));
        let restored = CoreEngine::try_from_restored_state(acceptor.refresh_snapshot())
            .expect("restore acceptor with pending next-epoch");
        if alice_was_committer {
            chat.bob = restored;
        } else {
            chat.alice = restored;
        }
        assert!(pending_has_message(
            if alice_was_committer {
                &chat.bob
            } else {
                &chat.alice
            },
            &acceptor_device,
            &next_epoch.message_id,
        ));
        deliver_inbox_envelope(
            if alice_was_committer {
                &mut chat.bob
            } else {
                &mut chat.alice
            },
            &acceptor_device,
            complete_cert,
            70_002,
        );
        assert!(conversation_has_plaintext(
            if alice_was_committer {
                &chat.bob
            } else {
                &chat.alice
            },
            &conversation_id,
            "next-epoch",
        ));
    }

    #[test]
    fn direct_pcs_late_epoch_decrypt_does_not_drop_pending_membership_commit() {
        let mut chat = paired_direct_chat();
        let alice_was_committer = alice_is_committer(&chat);
        let acceptor_device = acceptor_device_id(&chat).to_string();
        let conversation_id = chat.conversation_id.clone();
        prime_direct_pcs_count(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        trigger_direct_pcs_from_committer(&mut chat);
        committer_engine_mut(&mut chat)
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "late-e".into(),
            })
            .expect("late e during handshake");
        let late_e = last_pending_application_envelope(committer_engine(&chat), &acceptor_device);
        let pcs_commit_b64 = committer_engine(&chat)
            .state
            .conversations
            .get(&conversation_id)
            .and_then(|state| state.pcs.handshake.as_ref())
            .map(|handshake| handshake.commit_b64.clone())
            .expect("pcs commit");
        complete_direct_pcs_committer_only(&mut chat);
        let (peer_mnemonic, peer_user_id) = if alice_was_committer {
            (
                BOB_MNEMONIC,
                chat.bob
                    .state
                    .local_identity
                    .as_ref()
                    .expect("bob identity")
                    .user_identity
                    .user_id
                    .clone(),
            )
        } else {
            (
                ALICE_MNEMONIC,
                chat.alice
                    .state
                    .local_identity
                    .as_ref()
                    .expect("alice identity")
                    .user_identity
                    .user_id
                    .clone(),
            )
        };
        let laptop_id = add_extra_peer_device(
            if alice_was_committer {
                &mut chat.alice
            } else {
                &mut chat.bob
            },
            &peer_user_id,
            peer_mnemonic,
        );
        let membership = if alice_was_committer {
            &chat.alice
        } else {
            &chat.bob
        }
        .state
        .pending_outbox
        .iter()
        .rev()
        .find(|item| {
            item.envelope.recipient_device_id == acceptor_device
                && item.envelope.message_type == MessageType::MlsCommit
                && item.envelope.inline_ciphertext.as_deref() != Some(pcs_commit_b64.as_str())
        })
        .expect("membership commit")
        .envelope
        .clone();
        let complete_cert = first_pending_envelope(
            if alice_was_committer {
                &chat.alice
            } else {
                &chat.bob
            },
            &acceptor_device,
            MessageType::ControlDirectCommitAccept,
        );
        deliver_inbox_envelope(
            if alice_was_committer {
                &mut chat.bob
            } else {
                &mut chat.alice
            },
            &acceptor_device,
            membership.clone(),
            71_000,
        );
        assert!(pending_has_message(
            if alice_was_committer {
                &chat.bob
            } else {
                &chat.alice
            },
            &acceptor_device,
            &membership.message_id,
        ));
        deliver_inbox_envelope(
            if alice_was_committer {
                &mut chat.bob
            } else {
                &mut chat.alice
            },
            &acceptor_device,
            late_e,
            71_001,
        );
        let acceptor = if alice_was_committer {
            &chat.bob
        } else {
            &chat.alice
        };
        assert!(conversation_has_plaintext(
            acceptor,
            &conversation_id,
            "late-e"
        ));
        assert!(pending_has_message(
            acceptor,
            &acceptor_device,
            &membership.message_id,
        ));
        let restored = CoreEngine::try_from_restored_state(acceptor.refresh_snapshot())
            .expect("restore acceptor with pending membership");
        if alice_was_committer {
            chat.bob = restored;
        } else {
            chat.alice = restored;
        }
        deliver_inbox_envelope(
            if alice_was_committer {
                &mut chat.bob
            } else {
                &mut chat.alice
            },
            &acceptor_device,
            complete_cert,
            71_002,
        );
        let acceptor = if alice_was_committer {
            &chat.bob
        } else {
            &chat.alice
        };
        let committer = if alice_was_committer {
            &chat.alice
        } else {
            &chat.bob
        };
        let acceptor_members = acceptor
            .state
            .mls_adapter
            .as_ref()
            .expect("adapter")
            .member_device_ids(&conversation_id)
            .expect("acceptor members");
        let committer_members = committer
            .state
            .mls_adapter
            .as_ref()
            .expect("adapter")
            .member_device_ids(&conversation_id)
            .expect("committer members");
        assert!(committer_members.contains(&laptop_id));
        assert!(acceptor_members.contains(&laptop_id));
    }

    #[test]
    fn direct_pcs_forged_commit_envelope_sender_does_not_rebuild() {
        let mut chat = paired_direct_chat();
        prime_direct_pcs_count(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        trigger_direct_pcs_from_committer(&mut chat);
        let acceptor_device = acceptor_device_id(&chat).to_string();
        let mut forged = first_pending_envelope(
            committer_engine(&chat),
            &acceptor_device,
            MessageType::MlsCommit,
        );
        forged.sender_device_id = "device:forged-sender".into();
        deliver_inbox_envelope(
            acceptor_engine_mut(&mut chat),
            &acceptor_device,
            forged,
            33_000,
        );
        let acceptor_state = acceptor_engine(&chat)
            .state
            .conversations
            .get(&chat.conversation_id)
            .expect("conversation");
        assert_eq!(acceptor_state.conversation.state, ConversationState::Active);
        assert_ne!(
            acceptor_state.conversation.state,
            ConversationState::NeedsRebuild
        );
        assert!(acceptor_state.pcs.handshake.is_none());
    }

    #[test]
    fn direct_pcs_promised_handshake_defers_membership_until_apply() {
        let mut chat = paired_direct_chat();
        let alice_was_committer = alice_is_committer(&chat);
        prime_direct_pcs_count(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        trigger_direct_pcs_from_committer(&mut chat);
        let protocol = [
            MessageType::MlsCommit,
            MessageType::ControlDirectCommitAccept,
        ];
        if alice_was_committer {
            deliver_pending_outbox_types(
                &mut chat.bob,
                &chat.alice,
                &chat.bob_device_id,
                &protocol,
            );
        } else {
            deliver_pending_outbox_types(
                &mut chat.alice,
                &chat.bob,
                &chat.alice_device_id,
                &protocol,
            );
        }
        let acceptor = if alice_was_committer {
            &chat.bob
        } else {
            &chat.alice
        };
        assert!(
            acceptor
                .state
                .conversations
                .get(&chat.conversation_id)
                .and_then(|state| state.pcs.handshake.as_ref())
                .is_some_and(DirectPcsHandshake::is_promised)
        );
        let alice_is_acceptor = !alice_was_committer;
        let (peer_mnemonic, peer_user_id) = if alice_is_acceptor {
            (
                BOB_MNEMONIC,
                chat.bob
                    .state
                    .local_identity
                    .as_ref()
                    .expect("bob identity")
                    .user_identity
                    .user_id
                    .clone(),
            )
        } else {
            (
                ALICE_MNEMONIC,
                chat.alice
                    .state
                    .local_identity
                    .as_ref()
                    .expect("alice identity")
                    .user_identity
                    .user_id
                    .clone(),
            )
        };
        let laptop_id = add_extra_peer_device(
            if alice_was_committer {
                &mut chat.bob
            } else {
                &mut chat.alice
            },
            &peer_user_id,
            peer_mnemonic,
        );
        let acceptor = if alice_was_committer {
            &chat.bob
        } else {
            &chat.alice
        };
        assert!(
            acceptor
                .state
                .conversations
                .get(&chat.conversation_id)
                .and_then(|state| state.pcs.handshake.as_ref())
                .is_some_and(DirectPcsHandshake::is_promised)
        );
        let members_before = acceptor
            .state
            .mls_adapter
            .as_ref()
            .expect("adapter")
            .member_device_ids(&chat.conversation_id)
            .expect("members");
        assert!(!members_before.contains(&laptop_id));
        assert!(!acceptor.state.pending_outbox.iter().any(|item| {
            item.envelope.message_type == MessageType::MlsWelcome
                && item.envelope.recipient_device_id == laptop_id
        }));
        assert_ne!(
            acceptor
                .state
                .conversations
                .get(&chat.conversation_id)
                .expect("conversation")
                .conversation
                .state,
            ConversationState::NeedsRebuild
        );
        complete_direct_pcs_protocol_only(&mut chat);
        let acceptor = if alice_was_committer {
            &chat.bob
        } else {
            &chat.alice
        };
        let members_after = acceptor
            .state
            .mls_adapter
            .as_ref()
            .expect("adapter")
            .member_device_ids(&chat.conversation_id)
            .expect("members after pcs");
        assert!(members_after.contains(&laptop_id));
    }

    #[test]
    fn direct_pcs_previous_consume_survives_restore_without_resurrecting_generation() {
        let mut chat = paired_direct_chat();
        let alice_was_committer = alice_is_committer(&chat);
        prime_direct_pcs_count(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        trigger_direct_pcs_from_committer(&mut chat);
        complete_direct_pcs_committer_only(&mut chat);
        let conversation_id = chat.conversation_id.clone();
        let committer_device = if alice_was_committer {
            chat.alice_device_id.clone()
        } else {
            chat.bob_device_id.clone()
        };
        let acceptor = if alice_was_committer {
            &mut chat.bob
        } else {
            &mut chat.alice
        };
        acceptor
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "old-1".into(),
            })
            .expect("acceptor sends old-1");
        let consumed = last_pending_application_envelope(acceptor, &committer_device);
        acceptor
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "old-2".into(),
            })
            .expect("acceptor sends old-2");
        let unconsumed = last_pending_application_envelope(acceptor, &committer_device);
        let committer = if alice_was_committer {
            &mut chat.alice
        } else {
            &mut chat.bob
        };
        deliver_inbox_envelope(committer, &committer_device, consumed.clone(), 40_000);
        assert_eq!(
            conversation_plaintext_count(committer, &conversation_id, "old-1"),
            1
        );
        if alice_was_committer {
            chat.alice = CoreEngine::try_from_restored_state(chat.alice.refresh_snapshot())
                .expect("restore committer");
        } else {
            chat.bob = CoreEngine::try_from_restored_state(chat.bob.refresh_snapshot())
                .expect("restore committer");
        }
        let committer = if alice_was_committer {
            &mut chat.alice
        } else {
            &mut chat.bob
        };
        deliver_inbox_envelope(committer, &committer_device, consumed, 40_001);
        assert_eq!(
            conversation_plaintext_count(committer, &conversation_id, "old-1"),
            1
        );
        deliver_inbox_envelope(committer, &committer_device, unconsumed, 40_002);
        assert_eq!(
            conversation_plaintext_count(committer, &conversation_id, "old-2"),
            1
        );
    }

    #[test]
    fn direct_pcs_rejects_accept_from_non_session_device() {
        let mut chat = paired_direct_chat();
        prime_direct_pcs_count(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        trigger_direct_pcs_from_committer(&mut chat);
        let carol_bundle = sample_identity_bundle(CAROL_MNEMONIC, "phone");
        chat.alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: carol_bundle.clone(),
            })
            .expect("alice imports carol");
        chat.bob
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: carol_bundle,
            })
            .expect("bob imports carol");
        let carol = IdentityManager::create_or_recover(Some(CAROL_MNEMONIC), Some("phone"))
            .expect("carol identity");
        let handshake = committer_engine(&chat)
            .state
            .conversations
            .get(&chat.conversation_id)
            .and_then(|state| state.pcs.handshake.clone())
            .expect("inflight handshake");
        let epoch_before = conversation_epoch(committer_engine(&chat), &chat.conversation_id);
        let mut cert = DirectCommitCertificate {
            conversation_id: chat.conversation_id.clone(),
            epoch: handshake.epoch,
            parent_commit_hash: handshake.parent_commit_hash.clone(),
            commit_hash: handshake.commit_hash.clone(),
            committer_device_id: handshake.committer_device_id.clone(),
            acceptor_device_id: Some(carol.device_identity.device_id.clone()),
            committer_sig: handshake.committer_sig.clone(),
            acceptor_sig: Some(sign_certificate(
                &carol,
                &chat.conversation_id,
                handshake.epoch,
                &handshake.parent_commit_hash,
                &handshake.commit_hash,
            )),
        };
        if cert.committer_sig.is_none() {
            let committer_identity = committer_engine(&chat)
                .state
                .local_identity
                .clone()
                .expect("committer identity");
            cert.committer_sig = Some(sign_certificate(
                &committer_identity,
                &chat.conversation_id,
                handshake.epoch,
                &handshake.parent_commit_hash,
                &handshake.commit_hash,
            ));
        }
        let payload_b64 = STANDARD.encode(serde_json::to_vec(&cert).expect("cert json"));
        let sender_proof = carol.sign_sender_proof(payload_b64.as_bytes());
        let committer_device = committer_device_id(&chat);
        let envelope = Envelope {
            version: CURRENT_MODEL_VERSION.to_string(),
            message_id: format!("msg:{}:carol-accept", chat.conversation_id),
            conversation_id: chat.conversation_id.clone(),
            sender_user_id: carol.user_identity.user_id.clone(),
            sender_device_id: carol.device_identity.device_id.clone(),
            recipient_device_id: committer_device.clone(),
            created_at: 1,
            message_type: MessageType::ControlDirectCommitAccept,
            inline_ciphertext: Some(payload_b64),
            storage_refs: vec![],
            delivery_class: DeliveryClass::Normal,
            wake_hint: None,
            sender_proof: SenderProof {
                proof_type: "device_signature".into(),
                value: sender_proof,
            },
        };
        committer_engine_mut(&mut chat)
            .handle_event(CoreEvent::InboxRecordsFetched {
                device_id: committer_device.clone(),
                to_seq: 30_000,
                records: vec![InboxRecord {
                    seq: 30_000,
                    recipient_device_id: committer_device,
                    message_id: envelope.message_id.clone(),
                    received_at: 30_000,
                    expires_at: None,
                    state: InboxRecordState::Available,
                    envelope,
                }],
            })
            .expect("non-session accept ingested");
        let committer_state = committer_engine(&chat)
            .state
            .conversations
            .get(&chat.conversation_id)
            .expect("conversation");
        assert!(committer_state.pcs.handshake.is_some());
        assert_eq!(
            conversation_epoch(committer_engine(&chat), &chat.conversation_id),
            epoch_before
        );
        assert_ne!(
            committer_state.conversation.state,
            ConversationState::NeedsRebuild
        );
    }

    #[test]
    fn direct_pcs_unauthenticated_accept_does_not_rebuild() {
        let mut chat = paired_direct_chat();
        prime_direct_pcs_count(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        trigger_direct_pcs_from_committer(&mut chat);
        deliver_committer_commit_to_acceptor(&mut chat);
        let committer_device = committer_device_id(&chat);
        let mut forged = first_pending_envelope(
            acceptor_engine(&chat),
            &committer_device,
            MessageType::ControlDirectCommitAccept,
        );
        forged.sender_proof.value = "00".repeat(64);
        deliver_inbox_envelope(
            committer_engine_mut(&mut chat),
            &committer_device,
            forged,
            31_000,
        );
        let committer_state = committer_engine(&chat)
            .state
            .conversations
            .get(&chat.conversation_id)
            .expect("conversation");
        assert_eq!(
            committer_state.conversation.state,
            ConversationState::Active
        );
        assert_ne!(
            committer_state.conversation.state,
            ConversationState::NeedsRebuild
        );
        assert!(committer_state.pcs.handshake.is_some());
    }

    #[test]
    fn direct_pcs_mismatched_accept_conversation_id_does_not_rebuild() {
        let mut chat = paired_direct_chat();
        prime_direct_pcs_count(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        trigger_direct_pcs_from_committer(&mut chat);
        deliver_committer_commit_to_acceptor(&mut chat);
        let committer_device = committer_device_id(&chat);
        let mut forged = first_pending_envelope(
            acceptor_engine(&chat),
            &committer_device,
            MessageType::ControlDirectCommitAccept,
        );
        let payload = STANDARD
            .decode(forged.inline_ciphertext.as_ref().expect("accept payload"))
            .expect("decode accept");
        let mut cert: DirectCommitCertificate =
            serde_json::from_slice(&payload).expect("accept cert");
        cert.conversation_id = "conv:forged-conversation".into();
        let payload_b64 = STANDARD.encode(serde_json::to_vec(&cert).expect("cert json"));
        let acceptor_identity = acceptor_engine(&chat)
            .state
            .local_identity
            .clone()
            .expect("acceptor identity");
        forged.sender_proof.value = acceptor_identity.sign_sender_proof(payload_b64.as_bytes());
        forged.inline_ciphertext = Some(payload_b64);
        deliver_inbox_envelope(
            committer_engine_mut(&mut chat),
            &committer_device,
            forged,
            32_000,
        );
        let committer_state = committer_engine(&chat)
            .state
            .conversations
            .get(&chat.conversation_id)
            .expect("conversation");
        assert_eq!(
            committer_state.conversation.state,
            ConversationState::Active
        );
        assert_ne!(
            committer_state.conversation.state,
            ConversationState::NeedsRebuild
        );
        assert!(committer_state.pcs.handshake.is_some());
    }

    #[test]
    fn direct_pcs_attachment_send_counts_toward_commit_interval() {
        let mut chat = paired_direct_chat();
        prime_direct_pcs_count(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        let conversation_id = chat.conversation_id.clone();
        complete_direct_attachment_send(committer_engine_mut(&mut chat), &conversation_id);
        assert!(
            committer_engine(&chat)
                .state
                .conversations
                .get(&chat.conversation_id)
                .expect("conversation")
                .pcs
                .handshake
                .is_some()
        );
    }

    #[test]
    fn direct_pcs_attachment_send_persists_before_flush() {
        let mut chat = paired_direct_chat();
        prime_direct_pcs_count(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        let conversation_id = chat.conversation_id.clone();
        let output =
            complete_direct_attachment_send(committer_engine_mut(&mut chat), &conversation_id);
        let ops = persist_ops(&output);
        assert!(ops.iter().any(|op| matches!(
            op,
            PersistOp::SaveConversation { conversation_id: saved }
                if saved == &conversation_id
        )));
        assert!(ops.iter().any(|op| matches!(
            op,
            PersistOp::SaveMlsState { conversation_id: saved }
                if saved == &conversation_id
        )));
        let commit_ids: Vec<String> = committer_engine(&chat)
            .state
            .pending_outbox
            .iter()
            .filter(|item| {
                item.envelope.conversation_id == conversation_id
                    && item.envelope.message_type == MessageType::MlsCommit
            })
            .map(|item| item.envelope.message_id.clone())
            .collect();
        assert!(
            !commit_ids.is_empty(),
            "attachment send should enqueue PCS commit"
        );
        assert!(ops.iter().any(|op| matches!(
            op,
            PersistOp::SaveOutgoingEnvelope { message_id } if commit_ids.contains(message_id)
        )));
        let persist_index = first_persist_effect_index(&output).expect("persist effect");
        let http_index = output
            .effects
            .iter()
            .position(|effect| matches!(effect, CoreEffect::ExecuteHttpRequest { .. }))
            .expect("http flush");
        assert!(
            persist_index < http_index,
            "conversation/mls/outbox persist must precede HTTP flush"
        );
        let restored =
            CoreEngine::try_from_restored_state(committer_engine(&chat).refresh_snapshot())
                .expect("restore after attachment stage");
        assert!(
            restored
                .state
                .conversations
                .get(&conversation_id)
                .expect("restored conversation")
                .pcs
                .handshake
                .is_some()
        );
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
                display_name: None,
            })
            .expect("identity");
        engine
            .handle_command(CoreCommand::ImportIdentityBundle { bundle })
            .expect("import");
        engine
    }

    fn accepted_request_result(
        sender_user_id: &str,
        conversation_id: &str,
    ) -> MessageRequestActionResult {
        MessageRequestActionResult {
            accepted: true,
            request_id: "request:pending".into(),
            sender_user_id: sender_user_id.to_string(),
            promoted_count: 1,
            action: MessageRequestAction::Accept,
            sender_bundle_share_url: None,
            sender_bundle_hash: None,
            sender_display_name: None,
            promoted_conversation_ids: vec![conversation_id.to_string()],
        }
    }

    fn local_engine(mnemonic: &str, device_name: &str) -> CoreEngine {
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
                display_name: None,
            })
            .expect("identity");
        engine
    }

    fn scheduled_timer_delay(output: &CoreOutput, timer_id: &str) -> Option<u64> {
        output.effects.iter().find_map(|effect| match effect {
            CoreEffect::ScheduleTimer { timer } if timer.timer_id == timer_id => {
                Some(timer.delay_ms)
            }
            _ => None,
        })
    }

    fn first_http_request_id_containing(output: &CoreOutput, needle: &str) -> String {
        output
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::ExecuteHttpRequest { request } if request.url.contains(needle) => {
                    Some(request.request_id.clone())
                }
                _ => None,
            })
            .unwrap_or_else(|| panic!("missing HTTP request containing {needle}"))
    }

    /// Resolves every in-flight `ClaimKeyPackage` HTTP effect in `output` by
    /// synthesizing a successful `/v1/keypackage-pool/{deviceId}/claim`
    /// response (claims are strictly sequential, so this loops until none
    /// remain), reusing the target device's cached last-resort KeyPackage
    /// bytes as the "claimed" one-time KeyPackage — realistic enough for
    /// test purposes since the bytes just need to be a validly encoded MLS
    /// KeyPackage. Returns the final output (from whichever call resolved
    /// the last outstanding claim), which carries the real view model.
    fn simulate_pending_key_package_claims(engine: &mut CoreEngine, mut output: CoreOutput) -> CoreOutput {
        loop {
            let claim = output.effects.iter().find_map(|effect| match effect {
                CoreEffect::ExecuteHttpRequest { request }
                    if request.url.contains("/keypackage-pool/") && request.url.ends_with("/claim") =>
                {
                    Some((request.request_id.clone(), request.url.clone()))
                }
                _ => None,
            });
            let Some((request_id, url)) = claim else {
                break;
            };
            let device_id = url
                .split("/keypackage-pool/")
                .nth(1)
                .and_then(|rest| rest.strip_suffix("/claim"))
                .map(|encoded| {
                    urlencoding::decode(encoded)
                        .expect("valid device id encoding")
                        .into_owned()
                })
                .expect("claim url must contain a device id");
            let key_package_b64 = engine
                .state
                .contacts
                .values()
                .find_map(|contact| {
                    contact
                        .bundle
                        .devices
                        .iter()
                        .find(|device| device.device_id == device_id)
                        .and_then(|device| device.keypackage_ref.as_ref())
                        .map(|keypackage_ref| keypackage_ref.object_ref.clone())
                })
                .expect("test harness must have a cached key package to simulate a claim response");
            let body = serde_json::json!({
                "keyPackage": {
                    "keyPackageId": "test-claim",
                    "keyPackage": key_package_b64,
                    "lifecycleVersion": 1,
                    "notBefore": 0,
                    "createdAt": 0,
                    "expiresAt": 0,
                }
            })
            .to_string();
            output = engine
                .handle_event(CoreEvent::HttpResponseReceived {
                    request_id,
                    status: 200,
                    body: Some(body),
                })
                .expect("claim response applied");
        }
        output
    }

    fn create_direct_conversation(engine: &mut CoreEngine, peer_user_id: String) -> String {
        let output = engine
            .handle_command(CoreCommand::CreateConversation {
                peer_user_id,
                conversation_kind: ConversationKind::Direct,
            })
            .expect("conversation");
        simulate_pending_key_package_claims(engine, output)
            .view_model
            .unwrap()
            .conversations[0]
            .conversation_id
            .clone()
    }

    fn local_key_package_ref(engine: &CoreEngine) -> String {
        engine
            .state
            .local_bundle
            .as_ref()
            .expect("local bundle")
            .devices[0]
            .keypackage_ref
            .as_ref()
            .expect("key package reference")
            .object_ref
            .clone()
    }

    fn deliver_pending_outbox_to_device(
        recipient: &mut CoreEngine,
        sender: &CoreEngine,
        device_id: &str,
    ) -> CoreOutput {
        let records = sender
            .state
            .pending_outbox
            .iter()
            .filter(|item| item.envelope.recipient_device_id == device_id)
            .enumerate()
            .map(|(index, item)| InboxRecord {
                seq: index as u64 + 1,
                recipient_device_id: item.envelope.recipient_device_id.clone(),
                message_id: item.envelope.message_id.clone(),
                received_at: index as u64 + 1,
                expires_at: None,
                state: InboxRecordState::Available,
                envelope: item.envelope.clone(),
            })
            .collect::<Vec<_>>();
        assert!(
            !records.is_empty(),
            "sender has no pending records for {device_id}"
        );
        recipient
            .handle_event(CoreEvent::InboxRecordsFetched {
                device_id: device_id.to_string(),
                to_seq: records.len() as u64,
                records,
            })
            .expect("recipient inbox records fetched")
    }

    struct PairedDirectChat {
        alice: CoreEngine,
        bob: CoreEngine,
        conversation_id: String,
        alice_device_id: String,
        bob_device_id: String,
    }

    fn paired_direct_chat() -> PairedDirectChat {
        let mut chat = unjoined_direct_chat();
        deliver_pending_outbox_to_device(&mut chat.bob, &chat.alice, &chat.bob_device_id);
        chat
    }

    fn unjoined_direct_chat() -> PairedDirectChat {
        let mut alice = local_engine(ALICE_MNEMONIC, "phone");
        let alice_bundle = alice.local_bundle().expect("alice bundle").clone();
        let mut bob = local_engine(BOB_MNEMONIC, "phone");
        let bob_bundle = bob.local_bundle().expect("bob bundle").clone();
        alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: bob_bundle.clone(),
            })
            .expect("alice imports bob");
        bob.handle_command(CoreCommand::ImportIdentityBundle {
            bundle: alice_bundle.clone(),
        })
        .expect("bob imports alice");
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        let alice_device_id = alice.local_device_id().expect("alice device").to_string();
        let bob_device_id = bob.local_device_id().expect("bob device").to_string();
        PairedDirectChat {
            alice,
            bob,
            conversation_id,
            alice_device_id,
            bob_device_id,
        }
    }

    fn conversation_epoch(engine: &CoreEngine, conversation_id: &str) -> u64 {
        engine
            .state
            .mls_summaries
            .get(conversation_id)
            .map(|summary| summary.epoch)
            .or_else(|| {
                engine
                    .state
                    .mls_adapter
                    .as_ref()
                    .and_then(|adapter| adapter.export_group_summary(conversation_id).ok())
                    .map(|summary| summary.epoch)
            })
            .expect("conversation epoch")
    }

    fn committer_device_id(chat: &PairedDirectChat) -> String {
        let members = chat
            .alice
            .state
            .mls_adapter
            .as_ref()
            .expect("alice adapter")
            .member_device_ids(&chat.conversation_id)
            .expect("members");
        designated_committer(
            &members,
            conversation_epoch(&chat.alice, &chat.conversation_id),
        )
        .expect("committer")
    }

    fn alice_is_committer(chat: &PairedDirectChat) -> bool {
        committer_device_id(chat) == chat.alice_device_id
    }

    fn committer_engine(chat: &PairedDirectChat) -> &CoreEngine {
        if alice_is_committer(chat) {
            &chat.alice
        } else {
            &chat.bob
        }
    }

    fn committer_engine_mut(chat: &mut PairedDirectChat) -> &mut CoreEngine {
        if alice_is_committer(chat) {
            &mut chat.alice
        } else {
            &mut chat.bob
        }
    }

    fn acceptor_engine(chat: &PairedDirectChat) -> &CoreEngine {
        if alice_is_committer(chat) {
            &chat.bob
        } else {
            &chat.alice
        }
    }

    fn acceptor_engine_mut(chat: &mut PairedDirectChat) -> &mut CoreEngine {
        if alice_is_committer(chat) {
            &mut chat.bob
        } else {
            &mut chat.alice
        }
    }

    fn acceptor_device_id(chat: &PairedDirectChat) -> &str {
        if alice_is_committer(chat) {
            &chat.bob_device_id
        } else {
            &chat.alice_device_id
        }
    }

    fn add_extra_peer_device(
        engine: &mut CoreEngine,
        peer_user_id: &str,
        peer_mnemonic: &str,
    ) -> String {
        let phone_profile = engine
            .state
            .contacts
            .get(peer_user_id)
            .expect("peer contact")
            .bundle
            .devices[0]
            .clone();
        let root = IdentityManager::recover_user_root(peer_mnemonic).expect("peer root");
        let laptop = IdentityManager::create_new_device_for_user(&root, None).expect("laptop");
        let package = MlsAdapter::generate_key_package(&laptop, test_now_ms()).expect("package");
        let laptop_profile = crate::capability::CapabilityManager::build_device_contact_profile(
            &laptop,
            &sample_deployment(),
            package.key_package_b64,
            package.expires_at,
        )
        .expect("laptop profile");
        let device_id = laptop_profile.device_id.clone();
        let merged = IdentityManager::export_identity_bundle_with_devices(
            &laptop,
            &sample_deployment(),
            vec![phone_profile, laptop_profile],
            None,
            None,
        )
        .expect("merged bundle");
        let output = engine
            .handle_command(CoreCommand::ApplyIdentityBundleUpdate { bundle: merged })
            .expect("add extra peer device");
        // Adding a new peer device may now trigger a reconciliation that
        // claims a one-time KeyPackage for it before the membership commit
        // is generated (a no-op when the reconcile takes a fully synchronous
        // path instead, e.g. while a direct PCS handshake is active).
        simulate_pending_key_package_claims(engine, output);
        device_id
    }

    fn prime_direct_pcs_count(chat: &mut PairedDirectChat, count: u32) {
        if let Some(state) = chat
            .alice
            .state
            .conversations
            .get_mut(&chat.conversation_id)
        {
            state.pcs.epoch_app_count = count;
        }
        if let Some(state) = chat.bob.state.conversations.get_mut(&chat.conversation_id) {
            state.pcs.epoch_app_count = count;
        }
    }

    fn trigger_direct_pcs_from_committer(chat: &mut PairedDirectChat) {
        let conversation_id = chat.conversation_id.clone();
        committer_engine_mut(chat)
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id,
                plaintext: "pcs trigger".into(),
            })
            .expect("committer send triggers pcs");
    }

    fn complete_direct_pcs_handshake(chat: &mut PairedDirectChat) {
        let alice_is = alice_is_committer(chat);
        if alice_is {
            deliver_pending_outbox_to_device(&mut chat.bob, &chat.alice, &chat.bob_device_id);
            deliver_pending_outbox_to_device(&mut chat.alice, &chat.bob, &chat.alice_device_id);
            deliver_pending_outbox_to_device(&mut chat.bob, &chat.alice, &chat.bob_device_id);
        } else {
            deliver_pending_outbox_to_device(&mut chat.alice, &chat.bob, &chat.alice_device_id);
            deliver_pending_outbox_to_device(&mut chat.bob, &chat.alice, &chat.bob_device_id);
            deliver_pending_outbox_to_device(&mut chat.alice, &chat.bob, &chat.alice_device_id);
        }
    }

    /// Delivers a pending-outbox record set to `recipient` and, if delivery
    /// produced an output, resolves any `ClaimKeyPackage` HTTP effect it
    /// left in flight (e.g. reconciliation triggered once a deferred PCS
    /// handshake applies now claims a one-time KeyPackage for a newly
    /// active peer device before generating the membership commit). A no-op
    /// when no claim is outstanding.
    fn deliver_and_settle_pending_outbox_types(
        recipient: &mut CoreEngine,
        sender: &CoreEngine,
        device_id: &str,
        types: &[MessageType],
    ) {
        if let Some(output) = deliver_pending_outbox_types(recipient, sender, device_id, types) {
            simulate_pending_key_package_claims(recipient, output);
        }
    }

    fn complete_direct_pcs_protocol_only(chat: &mut PairedDirectChat) {
        let types = [
            MessageType::MlsCommit,
            MessageType::ControlDirectCommitAccept,
        ];
        if alice_is_committer(chat) {
            deliver_and_settle_pending_outbox_types(
                &mut chat.bob,
                &chat.alice,
                &chat.bob_device_id,
                &types,
            );
            deliver_and_settle_pending_outbox_types(
                &mut chat.alice,
                &chat.bob,
                &chat.alice_device_id,
                &types,
            );
            deliver_and_settle_pending_outbox_types(
                &mut chat.bob,
                &chat.alice,
                &chat.bob_device_id,
                &types,
            );
        } else {
            deliver_and_settle_pending_outbox_types(
                &mut chat.alice,
                &chat.bob,
                &chat.alice_device_id,
                &types,
            );
            deliver_and_settle_pending_outbox_types(
                &mut chat.bob,
                &chat.alice,
                &chat.bob_device_id,
                &types,
            );
            deliver_and_settle_pending_outbox_types(
                &mut chat.alice,
                &chat.bob,
                &chat.alice_device_id,
                &types,
            );
        }
    }

    fn complete_direct_pcs_committer_only(chat: &mut PairedDirectChat) {
        let types = [
            MessageType::MlsCommit,
            MessageType::ControlDirectCommitAccept,
        ];
        if alice_is_committer(chat) {
            deliver_and_settle_pending_outbox_types(
                &mut chat.bob,
                &chat.alice,
                &chat.bob_device_id,
                &types,
            );
            deliver_and_settle_pending_outbox_types(
                &mut chat.alice,
                &chat.bob,
                &chat.alice_device_id,
                &types,
            );
        } else {
            deliver_and_settle_pending_outbox_types(
                &mut chat.alice,
                &chat.bob,
                &chat.alice_device_id,
                &types,
            );
            deliver_and_settle_pending_outbox_types(
                &mut chat.bob,
                &chat.alice,
                &chat.bob_device_id,
                &types,
            );
        }
    }

    fn deliver_committer_commit_to_acceptor(chat: &mut PairedDirectChat) {
        let types = [MessageType::MlsCommit];
        if alice_is_committer(chat) {
            deliver_pending_outbox_types(&mut chat.bob, &chat.alice, &chat.bob_device_id, &types);
        } else {
            deliver_pending_outbox_types(&mut chat.alice, &chat.bob, &chat.alice_device_id, &types);
        }
    }

    fn deliver_pending_outbox_types(
        recipient: &mut CoreEngine,
        sender: &CoreEngine,
        device_id: &str,
        types: &[MessageType],
    ) -> Option<CoreOutput> {
        let records = sender
            .state
            .pending_outbox
            .iter()
            .filter(|item| {
                item.envelope.recipient_device_id == device_id
                    && types.contains(&item.envelope.message_type)
            })
            .enumerate()
            .map(|(index, item)| InboxRecord {
                seq: index as u64 + 1,
                recipient_device_id: item.envelope.recipient_device_id.clone(),
                message_id: item.envelope.message_id.clone(),
                received_at: index as u64 + 1,
                expires_at: None,
                state: InboxRecordState::Available,
                envelope: item.envelope.clone(),
            })
            .collect::<Vec<_>>();
        if records.is_empty() {
            return None;
        }
        Some(
            recipient
                .handle_event(CoreEvent::InboxRecordsFetched {
                    device_id: device_id.to_string(),
                    to_seq: records.len() as u64,
                    records,
                })
                .expect("filtered inbox records fetched"),
        )
    }

    fn deliver_inbox_envelope(
        recipient: &mut CoreEngine,
        device_id: &str,
        envelope: Envelope,
        seq: u64,
    ) -> CoreOutput {
        recipient
            .handle_event(CoreEvent::InboxRecordsFetched {
                device_id: device_id.to_string(),
                to_seq: seq,
                records: vec![InboxRecord {
                    seq,
                    recipient_device_id: device_id.to_string(),
                    message_id: envelope.message_id.clone(),
                    received_at: seq,
                    expires_at: None,
                    state: InboxRecordState::Available,
                    envelope,
                }],
            })
            .expect("inbox envelope fetched")
    }

    fn last_pending_application_envelope(sender: &CoreEngine, device_id: &str) -> Envelope {
        sender
            .state
            .pending_outbox
            .iter()
            .rev()
            .find(|item| {
                item.envelope.recipient_device_id == device_id
                    && item.envelope.message_type == MessageType::MlsApplication
            })
            .expect("pending application")
            .envelope
            .clone()
    }

    fn first_pending_envelope(
        sender: &CoreEngine,
        device_id: &str,
        message_type: MessageType,
    ) -> Envelope {
        sender
            .state
            .pending_outbox
            .iter()
            .find(|item| {
                item.envelope.recipient_device_id == device_id
                    && item.envelope.message_type == message_type
            })
            .expect("pending envelope")
            .envelope
            .clone()
    }

    fn conversation_has_plaintext(
        engine: &CoreEngine,
        conversation_id: &str,
        plaintext: &str,
    ) -> bool {
        engine
            .state
            .conversations
            .get(conversation_id)
            .is_some_and(|state| {
                state
                    .messages
                    .iter()
                    .any(|message| message.plaintext.as_deref() == Some(plaintext))
            })
    }

    fn pending_has_message(engine: &CoreEngine, device_id: &str, message_id: &str) -> bool {
        engine.state.sync_states.get(device_id).is_some_and(|sync| {
            sync.pending_records
                .values()
                .any(|record| record.envelope.message_id == message_id)
        })
    }

    fn conversation_plaintext_count(
        engine: &CoreEngine,
        conversation_id: &str,
        plaintext: &str,
    ) -> usize {
        engine
            .state
            .conversations
            .get(conversation_id)
            .map(|state| {
                state
                    .messages
                    .iter()
                    .filter(|message| message.plaintext.as_deref() == Some(plaintext))
                    .count()
            })
            .unwrap_or(0)
    }

    fn complete_direct_attachment_send(
        engine: &mut CoreEngine,
        conversation_id: &str,
    ) -> CoreOutput {
        let upload = engine
            .handle_command(CoreCommand::SendAttachmentMessage {
                conversation_id: conversation_id.to_string(),
                attachment_descriptor: sample_attachment_descriptor(),
            })
            .expect("attachment");
        let task_id = upload
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::ReadAttachmentBytes { read } => Some(read.task_id.clone()),
                _ => None,
            })
            .expect("upload task");
        engine
            .handle_event(CoreEvent::AttachmentBytesLoaded {
                task_id: task_id.clone(),
                plaintext: vec![1_u8, 2, 3, 4],
            })
            .expect("attachment bytes loaded");
        engine
            .handle_event(CoreEvent::BlobUploadPrepared {
                task_id: task_id.clone(),
                result: crate::transport_contract::PrepareBlobUploadResult {
                    blob_ref: "blob:attachment-pcs".into(),
                    upload_target: "upload:attachment-pcs".into(),
                    upload_headers: std::collections::BTreeMap::new(),
                    read_capability: "read-capability".into(),
                    download_target:
                        "https://storage.example.com/v1/storage/blob/blob%3Aattachment-pcs".into(),
                    upload_expires_at: Some(99),
                    blob_expires_at: Some(999),
                    delete_target: Some(
                        "https://storage.example.com/v1/storage/blob/blob%3Aattachment-pcs".into(),
                    ),
                    delete_capability: Some("delete-attachment-pcs".into()),
                },
            })
            .expect("blob prepared");
        engine
            .handle_event(CoreEvent::BlobUploaded { task_id })
            .expect("blob uploaded")
    }

    fn pending_application_record(sender: &CoreEngine, device_id: &str) -> InboxRecord {
        let item = sender
            .state
            .pending_outbox
            .iter()
            .find(|item| {
                item.envelope.recipient_device_id == device_id
                    && item.envelope.message_type == MessageType::MlsApplication
            })
            .expect("pending application delivery");
        InboxRecord {
            seq: 1,
            recipient_device_id: item.envelope.recipient_device_id.clone(),
            message_id: item.envelope.message_id.clone(),
            received_at: 1,
            expires_at: None,
            state: InboxRecordState::Available,
            envelope: item.envelope.clone(),
        }
    }

    fn sample_identity_bundle(mnemonic: &str, device_name: &str) -> IdentityBundle {
        let identity = IdentityManager::create_or_recover(Some(mnemonic), Some(device_name))
            .expect("identity");
        let package = MlsAdapter::generate_key_package(&identity, test_now_ms()).expect("package");
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
        let package = MlsAdapter::generate_key_package(&identity, test_now_ms()).expect("package");
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
            preview: None,
            width: None,
            height: None,
            blur_hash: None,
        }
    }

    fn sample_attachment_payload_metadata() -> AttachmentPayloadMetadata {
        AttachmentPayloadMetadata {
            version: 2,
            attachment_id: "attachment:test".into(),
            kind: crate::attachment_crypto::AttachmentKind::File,
            file_name: Some("file.bin".into()),
            width: None,
            height: None,
            blur_hash: None,
            original: crate::attachment_crypto::EncryptedBlobDescriptor {
                variant: crate::attachment_crypto::AttachmentVariant::Original,
                object_ref: "blob:test".into(),
                storage_origin: "https://storage.example.com".into(),
                read_capability: "read:test".into(),
                mime_type: "application/octet-stream".into(),
                plaintext_size: 4,
                ciphertext_size: 20,
                digest_sha256: crate::attachment_crypto::sha256_hex(&[1_u8, 2, 3, 4]),
                encryption: AttachmentCipherMetadata {
                    algorithm: ATTACHMENT_CIPHER_ALGORITHM.into(),
                    key_b64: STANDARD.encode([1_u8; 32]),
                    nonce_b64: STANDARD.encode([2_u8; 12]),
                    chunk_size_bytes: None,
                },
            },
            preview: None,
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

    fn fold_persist_onto_snapshot(
        mut snapshot: CorePersistenceSnapshot,
        output: &CoreOutput,
    ) -> CorePersistenceSnapshot {
        for effect in &output.effects {
            let CoreEffect::PersistState { persist } = effect else {
                continue;
            };
            for mutation in &persist.mutations {
                match mutation {
                    PersistenceMutation::Save {
                        value: PersistenceValue::ConversationSummary(summary),
                        ..
                    } => {
                        let conversation_id = summary.conversation.conversation_id.clone();
                        let messages = snapshot
                            .conversations
                            .iter()
                            .find(|item| item.conversation_id == conversation_id)
                            .map(|item| item.state.messages.clone())
                            .unwrap_or_default();
                        let mut conversation = summary.conversation.clone();
                        if conversation.state.messages.is_empty() {
                            conversation.state.messages = messages;
                        }
                        if let Some(existing) = snapshot
                            .conversations
                            .iter_mut()
                            .find(|item| item.conversation_id == conversation_id)
                        {
                            *existing = conversation;
                        } else {
                            snapshot.conversations.push(conversation);
                        }
                    }
                    PersistenceMutation::InsertMessage {
                        conversation_id,
                        message,
                    } => {
                        if let Some(existing) = snapshot
                            .conversations
                            .iter_mut()
                            .find(|item| item.conversation_id == *conversation_id)
                        {
                            if let Some(stored) = existing
                                .state
                                .messages
                                .iter_mut()
                                .find(|item| item.message_id == message.message_id)
                            {
                                *stored = message.clone();
                            } else {
                                existing.state.messages.push(message.clone());
                            }
                        }
                    }
                    PersistenceMutation::Save {
                        value: PersistenceValue::MlsState(mls),
                        ..
                    } => {
                        if let Some(existing) = snapshot
                            .mls_states
                            .iter_mut()
                            .find(|item| item.conversation_id == mls.conversation_id)
                        {
                            *existing = mls.clone();
                        } else {
                            snapshot.mls_states.push(mls.clone());
                        }
                    }
                    _ => {}
                }
            }
        }
        snapshot
    }

    fn persist_ops(output: &crate::ffi_api::CoreOutput) -> Vec<PersistOp> {
        output
            .effects
            .iter()
            .flat_map(|effect| match effect {
                CoreEffect::PersistState { persist } => persist.ops.clone(),
                _ => Vec::new(),
            })
            .collect()
    }

    fn first_persist_effect_index(output: &crate::ffi_api::CoreOutput) -> Option<usize> {
        output
            .effects
            .iter()
            .position(|effect| matches!(effect, CoreEffect::PersistState { .. }))
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
            runtime_id: "runtime:test".into(),
            protocol_version: 5,
            worker_build_id: "test-worker-v4".into(),
            registry_schema_version: 2,
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
                keypackage_pool_base: Some("https://storage.example.com/keypackages".into()),
                max_inline_bytes: Some(4096),
                features: vec![
                    "generic_sync".into(),
                    "group_authorization_v2".into(),
                    "group_membership_fsm_v2".into(),
                ],
            },
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

    // ── Phase 8: add/remove group member device ──

    #[test]
    fn group_device_commands_round_trip_json() {
        let commands = vec![
            CoreCommand::AddGroupMemberDevice {
                group_id: "group:project".into(),
                user_id: "user:alice".into(),
                device_id: "device:alice:phone".into(),
            },
            CoreCommand::RemoveGroupMemberDevice {
                group_id: "group:project".into(),
                user_id: "user:alice".into(),
                device_id: "device:alice:phone".into(),
            },
        ];

        for command in commands {
            let json = serde_json::to_string(&command).expect("serialize");
            assert!(json.contains("group_id"));
            let decoded: CoreCommand = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(decoded, command, "round-trip failed for {json}");
        }
    }

    #[test]
    fn add_group_member_device_rejects_current_device() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let output = alice
            .handle_command(CoreCommand::CreateGroupConversation {
                title: "Project".into(),
                member_user_ids: vec![bob_bundle.user_id.clone()],
            })
            .expect("create group");
            let output = simulate_pending_key_package_claims(&mut alice, output);
        let summary = output
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .expect("group summary");
        let group_id = summary.group_id.clone().expect("group id");
        acknowledge_pending_group_transition(&mut alice, &group_id);
        let local_device = alice.local_device_id().expect("local device id");

        let err = alice
            .handle_command(CoreCommand::AddGroupMemberDevice {
                group_id: group_id.clone(),
                user_id: alice
                    .local_identity()
                    .expect("identity")
                    .user_identity
                    .user_id
                    .clone(),
                device_id: local_device.to_string(),
            })
            .expect_err("cannot add current device");
        assert!(
            err.to_string().contains("current device"),
            "expected 'current device' rejection, got: {err}"
        );
    }

    #[test]
    fn add_group_member_device_rejects_wrong_user() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let output = alice
            .handle_command(CoreCommand::CreateGroupConversation {
                title: "Project".into(),
                member_user_ids: vec![bob_bundle.user_id.clone()],
            })
            .expect("create group");
            let output = simulate_pending_key_package_claims(&mut alice, output);
        let group_id = output
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .expect("group summary")
            .group_id
            .clone()
            .expect("group id");
        acknowledge_pending_group_transition(&mut alice, &group_id);

        let err = alice
            .handle_command(CoreCommand::AddGroupMemberDevice {
                group_id,
                user_id: bob_bundle.user_id.clone(),
                device_id: "device:bob:tablet".into(),
            })
            .expect_err("cannot add another user's device");
        assert!(
            err.to_string()
                .contains("only add devices for the local user"),
            "expected local-user-only rejection, got: {err}"
        );
    }

    #[test]
    fn add_group_member_device_rejects_non_existent_group() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle);
        let local_user_id = alice
            .local_identity()
            .expect("identity")
            .user_identity
            .user_id
            .clone();

        let err = alice
            .handle_command(CoreCommand::AddGroupMemberDevice {
                group_id: "group:nonexistent".into(),
                user_id: local_user_id,
                device_id: "device:alice:tablet".into(),
            })
            .expect_err("non-existent group must fail");
        assert!(
            err.to_string().contains("group does not exist"),
            "expected 'group does not exist', got: {err}"
        );
    }

    #[test]
    fn add_group_member_device_rejects_duplicate() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let output = alice
            .handle_command(CoreCommand::CreateGroupConversation {
                title: "Project".into(),
                member_user_ids: vec![bob_bundle.user_id.clone()],
            })
            .expect("create group");
            let output = simulate_pending_key_package_claims(&mut alice, output);
        let group_id = output
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .expect("group summary")
            .group_id
            .clone()
            .expect("group id");
        acknowledge_pending_group_transition(&mut alice, &group_id);
        let local_user_id = alice
            .local_identity()
            .expect("identity")
            .user_identity
            .user_id
            .clone();
        let local_device = alice.local_device_id().expect("local device id");

        // The current device is already in the group (it was the creator).
        let err = alice
            .handle_command(CoreCommand::AddGroupMemberDevice {
                group_id: group_id.clone(),
                user_id: local_user_id.clone(),
                device_id: local_device.to_string(),
            })
            .expect_err("duplicate device must fail");
        assert!(
            err.to_string().contains("current device"),
            "expected duplicate/current-device rejection, got: {err}"
        );
    }

    #[test]
    fn remove_group_member_device_rejects_current_device() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let output = alice
            .handle_command(CoreCommand::CreateGroupConversation {
                title: "Project".into(),
                member_user_ids: vec![bob_bundle.user_id.clone()],
            })
            .expect("create group");
            let output = simulate_pending_key_package_claims(&mut alice, output);
        let group_id = output
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .expect("group summary")
            .group_id
            .clone()
            .expect("group id");
        acknowledge_pending_group_transition(&mut alice, &group_id);
        let local_user_id = alice
            .local_identity()
            .expect("identity")
            .user_identity
            .user_id
            .clone();
        let local_device = alice.local_device_id().expect("local device id");

        let err = alice
            .handle_command(CoreCommand::RemoveGroupMemberDevice {
                group_id,
                user_id: local_user_id,
                device_id: local_device.to_string(),
            })
            .expect_err("cannot remove current device");
        assert!(
            err.to_string().contains("cannot remove the current device"),
            "expected 'cannot remove the current device', got: {err}"
        );
    }

    #[test]
    fn remove_group_member_device_rejects_wrong_user() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let output = alice
            .handle_command(CoreCommand::CreateGroupConversation {
                title: "Project".into(),
                member_user_ids: vec![bob_bundle.user_id.clone()],
            })
            .expect("create group");
            let output = simulate_pending_key_package_claims(&mut alice, output);
        let group_id = output
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .expect("group summary")
            .group_id
            .clone()
            .expect("group id");
        acknowledge_pending_group_transition(&mut alice, &group_id);

        let err = alice
            .handle_command(CoreCommand::RemoveGroupMemberDevice {
                group_id,
                user_id: bob_bundle.user_id.clone(),
                device_id: "device:bob:phone".into(),
            })
            .expect_err("cannot remove another user's device");
        assert!(
            err.to_string()
                .contains("may only remove devices for the local user"),
            "expected local-user-only rejection, got: {err}"
        );
    }

    #[test]
    fn sync_groups_for_new_device_rejects_current_device() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle);
        let local_device = alice.local_device_id().expect("local device id");

        let err = alice
            .handle_command(CoreCommand::SyncGroupsForNewDevice {
                device_id: local_device.to_string(),
            })
            .expect_err("cannot sync for current device");
        assert!(
            err.to_string().contains("current device"),
            "expected current-device rejection, got: {err}"
        );
    }

    #[test]
    fn sync_groups_for_new_device_rejects_unknown_device() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle);

        let err = alice
            .handle_command(CoreCommand::SyncGroupsForNewDevice {
                device_id: "device:unknown:tablet".into(),
            })
            .expect_err("unknown device must fail");
        assert!(
            err.to_string().contains("not an active device"),
            "expected 'not an active device' rejection, got: {err}"
        );
    }

    #[test]
    fn sync_groups_for_new_device_serializes_result() {
        // Verify the SyncGroupsForNewDevice command round-trips and
        // produces a view model with group_sync_results.
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle);
        let local_device = alice.local_device_id().expect("local device id");

        // Sync for current device is rejected (it is already in all groups).
        let err = alice
            .handle_command(CoreCommand::SyncGroupsForNewDevice {
                device_id: local_device.to_string(),
            })
            .expect_err("current device rejected");
        assert!(err.to_string().contains("current device"));

        // JSON serialization round-trip for the command.
        let cmd = CoreCommand::SyncGroupsForNewDevice {
            device_id: "device:alice:tablet".into(),
        };
        let json = serde_json::to_string(&cmd).expect("serialize");
        assert!(json.contains("sync_groups_for_new_device"));
        let decoded: CoreCommand = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, cmd);
    }

    // Security: verify_membership_operation_authority rejection paths.

    fn fake_proof(
        signer_user_id: &str,
        signer_device_id: &str,
        operation: &str,
        previous_roster_version: u64,
        new_roster_version: u64,
        previous_commit_message_id: Option<&str>,
        commit_message_id: &str,
        control_message_id: &str,
        new_manifest_sha256: &str,
        signature: &str,
    ) -> crate::model::GroupMembershipProof {
        crate::model::GroupMembershipProof {
            proof_type: "membership_signature".into(),
            operation: operation.into(),
            signer_user_id: signer_user_id.into(),
            signer_device_id: signer_device_id.into(),
            previous_roster_version,
            new_roster_version,
            previous_commit_message_id: previous_commit_message_id.map(|s| s.into()),
            commit_message_id: commit_message_id.into(),
            control_message_id: control_message_id.into(),
            state_event_message_id: None,
            new_manifest_sha256: new_manifest_sha256.into(),
            signature: signature.into(),
        }
    }

    fn user_id(engine: &CoreEngine) -> String {
        engine
            .local_identity()
            .expect("identity")
            .user_identity
            .user_id
            .clone()
    }

    fn device_id(engine: &CoreEngine) -> String {
        engine.local_device_id().expect("device").to_string()
    }

    #[test]
    fn membership_proof_roster_version_mismatch_is_rejected() {
        let alice_bundle = sample_identity_bundle(ALICE_MNEMONIC, "phone");
        let mut bob = harness_user("bob", BOB_MNEMONIC, "phone");
        bob.engine
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: alice_bundle.clone(),
            })
            .expect("import alice");
        let output = bob
            .engine
            .handle_command(CoreCommand::CreateGroupConversation {
                title: "Project".into(),
                member_user_ids: vec![alice_bundle.user_id.clone()],
            })
            .expect("create group");
            let output = simulate_pending_key_package_claims(&mut bob.engine, output);
        let group_id = output
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .expect("group summary")
            .group_id
            .clone()
            .expect("group id");
        let conversation_id = output
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .expect("group summary")
            .conversation_id
            .clone();
        let mut harness = GroupHarness::default();
        harness.drain(&mut bob, output);
        let roster = engine_state(&bob, &group_id).manifest.roster_version;

        let forged = GroupEnvelope {
            version: crate::model::CURRENT_MODEL_VERSION.to_string(),
            message_id: "forged-roster-skip".into(),
            group_id: group_id.clone(),
            conversation_id: conversation_id.clone(),
            sender_user_id: user_id(&bob.engine),
            sender_device_id: device_id(&bob.engine),
            created_at: 99,
            message_type: GroupMessageType::MlsCommit,
            visibility: GroupEnvelopeVisibility::Protocol,
            inline_ciphertext: Some("Zm9yZ2Vk".into()),
            storage_refs: vec![],
            sender_proof: SenderProof {
                proof_type: "signature".into(),
                value: "forged".into(),
            },
            membership_proof: Some(fake_proof(
                &user_id(&bob.engine),
                &device_id(&bob.engine),
                "invite",
                99,
                100,
                None,
                "forged-roster-skip",
                "forged-roster-ctrl",
                "sha256:forged",
                "forged",
            )),
            transition_id: None,
        };
        harness
            .outboxes
            .entry(group_id.clone())
            .or_default()
            .push(GroupOutboxRecord {
                seq: 99,
                group_id: group_id.clone(),
                message_id: forged.message_id.clone(),
                received_at: 99,
                expires_at: None,
                state: GroupOutboxRecordState::Available,
                envelope: forged,
            });
        let error = bob
            .engine
            .handle_event(CoreEvent::GroupOutboxFetched {
                group_id: group_id.clone(),
                records: vec![
                    harness.outboxes[&group_id]
                        .last()
                        .expect("forged record")
                        .clone(),
                ],
                to_seq: 99,
            })
            .expect_err("non-contiguous forged transition must be rejected");
        assert_eq!(error.code(), "invalid_input");
        let roster_after = engine_state(&bob, &group_id).manifest.roster_version;
        assert_eq!(
            roster_after, roster,
            "roster version must not change when proof with wrong previous version is synced"
        );
    }

    #[test]
    fn membership_proof_missing_on_control_is_rejected() {
        let alice_bundle = sample_identity_bundle(ALICE_MNEMONIC, "phone");
        let mut bob = harness_user("bob", BOB_MNEMONIC, "phone");
        bob.engine
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: alice_bundle.clone(),
            })
            .expect("import alice");
        let output = bob
            .engine
            .handle_command(CoreCommand::CreateGroupConversation {
                title: "Project".into(),
                member_user_ids: vec![alice_bundle.user_id.clone()],
            })
            .expect("create group");
            let output = simulate_pending_key_package_claims(&mut bob.engine, output);
        let group_id = output
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .expect("group summary")
            .group_id
            .clone()
            .expect("group id");
        let conversation_id = output
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .expect("group summary")
            .conversation_id
            .clone();
        let mut harness = GroupHarness::default();
        harness.drain(&mut bob, output);
        let roster_before = engine_state(&bob, &group_id).manifest.roster_version;

        // A ControlGroupMembershipChanged without a membership_proof must
        // be rejected.
        let forged = GroupEnvelope {
            version: crate::model::CURRENT_MODEL_VERSION.to_string(),
            message_id: "forged-no-proof".into(),
            group_id: group_id.clone(),
            conversation_id: conversation_id.clone(),
            sender_user_id: user_id(&bob.engine),
            sender_device_id: device_id(&bob.engine),
            created_at: 99,
            message_type: GroupMessageType::ControlGroupMembershipChanged,
            visibility: GroupEnvelopeVisibility::Protocol,
            inline_ciphertext: Some("Zm9yZ2Vk".into()),
            storage_refs: vec![],
            sender_proof: SenderProof {
                proof_type: "signature".into(),
                value: "forged".into(),
            },
            membership_proof: None,
            transition_id: None,
        };
        harness
            .outboxes
            .entry(group_id.clone())
            .or_default()
            .push(GroupOutboxRecord {
                seq: 99,
                group_id: group_id.clone(),
                message_id: forged.message_id.clone(),
                received_at: 99,
                expires_at: None,
                state: GroupOutboxRecordState::Available,
                envelope: forged,
            });
        let error = bob
            .engine
            .handle_event(CoreEvent::GroupOutboxFetched {
                group_id: group_id.clone(),
                records: vec![
                    harness.outboxes[&group_id]
                        .last()
                        .expect("forged record")
                        .clone(),
                ],
                to_seq: 99,
            })
            .expect_err("control without proof must be rejected");
        assert_eq!(error.code(), "invalid_input");
        let roster_after = engine_state(&bob, &group_id).manifest.roster_version;
        assert_eq!(
            roster_after, roster_before,
            "roster version must not change when control without proof is synced"
        );
    }

    #[test]
    fn membership_proof_commit_message_chain_mismatch_is_rejected() {
        let alice_bundle = sample_identity_bundle(ALICE_MNEMONIC, "phone");
        let mut bob = harness_user("bob", BOB_MNEMONIC, "phone");
        bob.engine
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: alice_bundle.clone(),
            })
            .expect("import alice");
        let output = bob
            .engine
            .handle_command(CoreCommand::CreateGroupConversation {
                title: "Project".into(),
                member_user_ids: vec![alice_bundle.user_id.clone()],
            })
            .expect("create group");
            let output = simulate_pending_key_package_claims(&mut bob.engine, output);
        let group_id = output
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .expect("group summary")
            .group_id
            .clone()
            .expect("group id");
        let conversation_id = output
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .expect("group summary")
            .conversation_id
            .clone();
        let mut harness = GroupHarness::default();
        harness.drain(&mut bob, output);
        let state_before = engine_state(&bob, &group_id).clone();
        let roster = state_before.manifest.roster_version;
        let last_commit = state_before.manifest.last_commit_message_id.clone();

        // Forged proof claims previous_commit_message_id = "nonexistent",
        // which does not match the local manifest.
        let forged = GroupEnvelope {
            version: crate::model::CURRENT_MODEL_VERSION.to_string(),
            message_id: "forged-chain-break".into(),
            group_id: group_id.clone(),
            conversation_id: conversation_id.clone(),
            sender_user_id: user_id(&bob.engine),
            sender_device_id: device_id(&bob.engine),
            created_at: 99,
            message_type: GroupMessageType::MlsCommit,
            visibility: GroupEnvelopeVisibility::Protocol,
            inline_ciphertext: Some("Zm9yZ2Vk".into()),
            storage_refs: vec![],
            sender_proof: SenderProof {
                proof_type: "signature".into(),
                value: "forged".into(),
            },
            membership_proof: Some(fake_proof(
                &user_id(&bob.engine),
                &device_id(&bob.engine),
                "invite",
                roster,
                roster.saturating_add(1),
                Some("nonexistent-commit-id"),
                "forged-chain-break",
                "forged-chain-ctrl",
                "sha256:forged",
                "forged",
            )),
            transition_id: None,
        };
        harness
            .outboxes
            .entry(group_id.clone())
            .or_default()
            .push(GroupOutboxRecord {
                seq: 99,
                group_id: group_id.clone(),
                message_id: forged.message_id.clone(),
                received_at: 99,
                expires_at: None,
                state: GroupOutboxRecordState::Available,
                envelope: forged,
            });
        let error = bob
            .engine
            .handle_event(CoreEvent::GroupOutboxFetched {
                group_id: group_id.clone(),
                records: vec![
                    harness.outboxes[&group_id]
                        .last()
                        .expect("forged record")
                        .clone(),
                ],
                to_seq: 99,
            })
            .expect_err("broken commit chain must be rejected");
        assert_eq!(error.code(), "invalid_input");
        let state_after = engine_state(&bob, &group_id);
        assert_eq!(
            state_after.manifest.roster_version, roster,
            "roster version must not change when proof with broken commit chain is synced"
        );
        assert_eq!(
            state_after.manifest.last_commit_message_id, last_commit,
            "last_commit_message_id must not change"
        );
    }

    fn engine_state<'a>(
        user: &'a HarnessUser,
        group_id: &str,
    ) -> &'a crate::persistence::PersistedGroupState {
        user.engine
            .state
            .group_states
            .get(group_id)
            .expect("group state")
    }
}

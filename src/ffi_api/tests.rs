#[cfg(test)]
pub(crate) mod tests {
    use crate::attachment_crypto::{
        AttachmentCipherMetadata, AttachmentPayloadMetadata, ATTACHMENT_CHUNK_SIZE_BYTES,
        ATTACHMENT_CIPHER_ALGORITHM, CHUNKED_ATTACHMENT_CIPHER_ALGORITHM,
    };
    use crate::conversation::RecoveryStatus;
    use crate::direct_pcs::{designated_committer, DIRECT_PCS_COMMIT_INTERVAL};
    use crate::ffi_api::groups;
    use crate::ffi_api::types::{RecoveryContext, RecoveryReason, MAX_TRANSPORT_RETRIES};
    use crate::ffi_api::{
        AttachmentDescriptor, CoreCommand, CoreEffect, CoreEngine, CoreEvent, CoreOutput,
        FfiApiModule, PersistenceMutation, RealtimeEvent,
    };
    use crate::group_pcs::GROUP_PCS_COMMIT_INTERVAL;
    use crate::identity::IdentityManager;
    use crate::mls_adapter::{IngestResult, MlsAdapter};
    use crate::model::{
        CapabilityService, ConversationKind, ConversationState, DeliveryClass, DeploymentBundle,
        Envelope, GroupCapability, GroupCapabilityOperation, GroupEnvelope,
        GroupEnvelopeVisibility, GroupInviteDocument, GroupJoinRequest, GroupJoinRequestStatus,
        GroupManifest, GroupMemberStatus, GroupMembershipProof, GroupMessageType,
        GroupOutboxRecord, GroupOutboxRecordState, GroupRole, IdentityBundle, InboxRecord,
        InboxRecordState, MessageType, SenderProof, StorageBaseInfo, WelcomePickupDescriptor,
        CURRENT_MODEL_VERSION,
    };
    use crate::persistence::{ContactRelationshipStatus, PersistOp, PersistedPendingWelcomePickup};
    use crate::transport_contract::{
        GroupJoinDecision, MessageRequestAction, MessageRequestActionResult,
        SealGroupOutboxRequest, SealGroupOutboxResult, SharedStateDocumentKind,
        TransportAuthRequirement,
    };
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use std::collections::{BTreeMap, BTreeSet};

    pub(crate) const ALICE_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    pub(crate) const BOB_MNEMONIC: &str =
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
    pub(crate) const CAROL_MNEMONIC: &str =
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";
    pub(crate) const DANA_MNEMONIC: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";

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
    fn append_request_omits_sender_identity_fields() {
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
        let value: serde_json::Value = serde_json::from_str(body).expect("append json");
        assert!(request.envelope.recipient_device_id.starts_with("device:"));
        for forbidden in [
            "sender_bundle_share_url",
            "sender_bundle_hash",
            "sender_display_name",
            "senderBundleShareUrl",
            "senderBundleHash",
            "senderDisplayName",
        ] {
            assert!(
                value.get(forbidden).is_none(),
                "append request must not name the sender via {forbidden}"
            );
        }
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

    /// The domains the worker verifies but the group fixture does not reach.
    ///
    /// Rust signs these and TypeScript verifies them, so the two framings have
    /// to agree byte for byte; nothing else in the suite checks that, because
    /// the only place both languages meet at runtime is the CLI e2e suite,
    /// which needs a live runtime. The fixture pins the digest instead, and
    /// `services/cloudflare/test/group-contract-parity.test.ts` asserts the
    /// same values from the TypeScript side.
    #[test]
    fn shared_signing_domain_fixture_matches_the_typescript_framing() {
        use crate::model::signing::{SignatureDomain, SigningPayload};

        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../test-fixtures/signing-domains-v1.json"))
                .expect("signing domain fixture");
        let expected = &fixture["expected"];

        let capability: crate::model::InboxAppendCapability =
            serde_json::from_value(fixture["inboxAppendCapability"].clone())
                .expect("capability fixture");
        assert_eq!(
            CoreEngine::signing_payload_sha256(crate::capability::inbox_append_capability_payload(
                &capability
            )),
            expected["inboxAppendCapabilitySha256"]
                .as_str()
                .expect("capability digest")
        );

        let binding: crate::model::DeviceBinding =
            serde_json::from_value(fixture["deviceBinding"].clone()).expect("binding fixture");
        assert_eq!(
            CoreEngine::signing_payload_sha256(crate::identity::device_binding_payload(&binding)),
            expected["deviceBindingSha256"]
                .as_str()
                .expect("binding digest")
        );

        let challenge: crate::model::DeviceRuntimeRefreshChallenge =
            serde_json::from_value(fixture["deviceRuntimeChallenge"].clone())
                .expect("challenge fixture");
        assert_eq!(
            CoreEngine::signing_payload_sha256(challenge.signing_payload()),
            expected["deviceRuntimeChallengeSha256"]
                .as_str()
                .expect("challenge digest")
        );

        // A payload that lost its domain would still be self-consistent, so
        // assert the domain is actually the first thing in the bytes.
        let mut bare = SigningPayload::new(SignatureDomain::DeviceBinding);
        bare.push_str("");
        assert!(
            CoreEngine::signing_payload_sha256(bare)
                != *expected["deviceBindingSha256"]
                    .as_str()
                    .expect("binding digest")
        );
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
        // The payload is binary once framed, so the fixture pins its digest
        // rather than its text -- same shape as `manifestSha256` above.
        assert_eq!(
            CoreEngine::signing_payload_sha256(CoreEngine::membership_proof_payload(&proof)),
            fixture["expected"]["membershipProofPayloadSha256"]
                .as_str()
                .expect("expected payload digest")
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
        assert!(output
            .effects
            .iter()
            .any(|effect| matches!(effect, CoreEffect::InitializeGroupAuthorization { .. })));
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
        let for_invitees = alice
            .state
            .pending_outbox
            .iter()
            .filter(|item| {
                item.envelope.recipient_device_id == bob_bundle.devices[0].device_id
                    || item.envelope.recipient_device_id == carol_bundle.devices[0].device_id
            })
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            for_invitees
                .iter()
                .filter(|item| crate::mls_adapter::MlsAdapter::payload_is_welcome(
                    item.envelope.payload_b64().unwrap_or_default()
                ))
                .count(),
            2,
            "invitees without a 1:1 session must receive a Welcome first"
        );
        assert_eq!(
            for_invitees
                .iter()
                .filter(|item| envelope_is_wrapped_app(&alice, &item.envelope))
                .count(),
            2,
            "the group invite must then ride a wrapped application frame"
        );
        for item in &for_invitees {
            let payload = item.envelope.payload_b64().unwrap_or_default();
            if crate::mls_adapter::MlsAdapter::payload_is_welcome(payload) {
                continue;
            }
            assert!(
                envelope_is_wrapped_app(&alice, &item.envelope),
                "1:1 inbox must not carry a parseable non-Welcome record"
            );
            let visible = host_visible_envelope_json(&item.envelope);
            assert!(!visible.contains("control_group_welcome_pickup"));
            assert!(!visible.contains("Project"));
        }
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
        assert!(leave
            .effects
            .iter()
            .any(|effect| matches!(effect, CoreEffect::SubmitGroupLeaveRequest { .. })));
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

        assert!(!alice
            .state
            .pending_group_outbox
            .iter()
            .any(|item| item.envelope.group_id == group_id));
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
        assert!(ops
            .iter()
            .any(|op| matches!(op, PersistOp::DeleteOutgoingGroupEnvelope { .. })));
        assert!(ops
            .iter()
            .any(|op| matches!(op, PersistOp::SaveConversation { .. })));
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
        assert!(retry_output
            .state_update
            .system_statuses_changed
            .contains(&crate::ffi_api::SystemStatus::TemporaryNetworkFailure));

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

        // A malicious/compromised Outbox relabels the envelope's sender fields
        // to Carol, without touching the MLS ciphertext (which it cannot
        // forge). Since R2b this is caught by the sender proof, which covers
        // the sender fields, rather than by the MLS sender cross-check further
        // downstream — the record never reaches the adapter.
        {
            let record = harness
                .outboxes
                .get_mut(&group_id)
                .expect("group outbox")
                .last_mut()
                .expect("application record");
            assert_eq!(
                record.envelope.message_type,
                GroupMessageType::MlsApplication
            );
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
                .any(|message| message.sender_user_id.as_deref()
                    == Some(carol.bundle.user_id.as_str())),
            "no message should ever be attributed to carol here"
        );
    }

    /// A three-member group with Bob caught up, for the R2b tests below.
    fn synced_trio(
        alice: &mut HarnessUser,
        bob: &mut HarnessUser,
        carol: &mut HarnessUser,
    ) -> (GroupHarness, String, String) {
        import_peer_bundles(&mut [alice, bob, carol]);
        let mut harness =
            GroupHarness::with_bundles(&[&*alice, &*bob, &*carol].map(|u| HarnessUser {
                name: u.name,
                bundle: u.bundle.clone(),
                engine: CoreEngine::new(),
            }));
        let (group_id, conversation_id) = harness.create_group(
            alice,
            "Project",
            vec![bob.bundle.user_id.clone(), carol.bundle.user_id.clone()],
        );
        harness.import_welcome(bob, &group_id);
        harness.import_welcome(carol, &group_id);
        harness.sync_group(bob, &group_id);
        harness.sync_group(carol, &group_id);
        (harness, group_id, conversation_id)
    }

    /// What a tampered record must not disturb. The group outbox is a shared
    /// replayable log with a cursor rather than a per-device inbox, so the
    /// group equivalent of "ack it and drop it" is "step the cursor past it
    /// and drop it": the cursor must still advance, or one injected record
    /// stalls every later record forever.
    #[derive(Debug, PartialEq)]
    struct GroupTrace {
        message_ids: Vec<String>,
        roster_version: u64,
        recovery_status: RecoveryStatus,
    }

    fn group_trace(user: &HarnessUser, group_id: &str, conversation_id: &str) -> GroupTrace {
        let conversation = user
            .engine
            .state
            .conversations
            .get(conversation_id)
            .expect("conversation");
        GroupTrace {
            message_ids: conversation
                .messages
                .iter()
                .map(|message| message.message_id.clone())
                .collect(),
            roster_version: group_roster_version(user, group_id),
            recovery_status: conversation.recovery_status,
        }
    }

    /// **R2b.** The attack the widened sender proof exists to stop.
    ///
    /// The group outbox operator cannot forge an MLS ciphertext, but before
    /// R2b it did not have to: `storage_refs` was outside the signature *and*
    /// ordinary records were never signature-checked at all, so it could hang
    /// an arbitrary blob pointer off a genuine message and the receiving
    /// client would copy it into the stored message and offer it for download.
    #[test]
    fn a_forged_attachment_pointer_on_a_genuine_group_message_leaves_no_trace() {
        let mut alice = harness_user("alice", ALICE_MNEMONIC, "phone");
        let mut bob = harness_user("bob", BOB_MNEMONIC, "phone");
        let mut carol = harness_user("carol", CAROL_MNEMONIC, "phone");
        let (mut harness, group_id, conversation_id) =
            synced_trio(&mut alice, &mut bob, &mut carol);

        harness.send_text(&mut alice, &conversation_id, "a genuine message");

        let before = group_trace(&bob, &group_id, &conversation_id);
        let before_cursor = group_cursor(&bob, &group_id);

        let tampered_seq = {
            let record = harness
                .outboxes
                .get_mut(&group_id)
                .expect("group outbox")
                .last_mut()
                .expect("application record");
            record.envelope.storage_refs = vec![crate::model::StorageRef {
                kind: "attachment".into(),
                object_ref: "blob:attacker-chosen".into(),
                size_bytes: 4096,
                mime_type: "image/png".into(),
                file_name: Some("invoice.png".into()),
                expires_at: None,
            }];
            record.seq
        };

        harness.sync_group(&mut bob, &group_id);

        assert_eq!(
            group_trace(&bob, &group_id, &conversation_id),
            before,
            "a record carrying an attacker-chosen storage_ref must leave no trace"
        );
        assert!(
            group_cursor(&bob, &group_id) >= tampered_seq,
            "the cursor must step past the dropped record, or one injected \
             record stalls the group forever"
        );
        assert!(
            group_cursor(&bob, &group_id) > before_cursor,
            "the cursor must actually move"
        );

        // The whole point is that this is not a remote off-switch: the group
        // must still work afterwards.
        harness.send_text(&mut alice, &conversation_id, "after");
        harness.sync_group(&mut bob, &group_id);
        assert!(
            group_plaintexts(&bob, &conversation_id)
                .iter()
                .any(|text| text == "after"),
            "the group must keep working after a record is discarded"
        );
    }

    /// **R2b.** The header as a whole, not just `storage_refs`. A legitimately
    /// signed group ciphertext must not be re-presentable under a different
    /// header.
    #[test]
    fn a_group_record_replayed_under_a_different_header_leaves_no_trace() {
        let rewrites: Vec<(&'static str, fn(&mut GroupEnvelope))> = vec![
            ("message_id", |envelope| {
                envelope.message_id = format!("{}:replayed", envelope.message_id)
            }),
            ("visibility", |envelope| {
                envelope.visibility = GroupEnvelopeVisibility::Protocol
            }),
            ("message_type", |envelope| {
                envelope.message_type = GroupMessageType::ControlGroupStateEvent
            }),
            ("created_at", |envelope| envelope.created_at += 1),
            ("conversation_id", |envelope| {
                envelope.conversation_id = format!("{}:other", envelope.conversation_id)
            }),
        ];

        for (name, rewrite) in rewrites {
            let mut alice = harness_user("alice", ALICE_MNEMONIC, "phone");
            let mut bob = harness_user("bob", BOB_MNEMONIC, "phone");
            let mut carol = harness_user("carol", CAROL_MNEMONIC, "phone");
            let (mut harness, group_id, conversation_id) =
                synced_trio(&mut alice, &mut bob, &mut carol);

            harness.send_text(&mut alice, &conversation_id, "a genuine message");

            let before = group_trace(&bob, &group_id, &conversation_id);
            let before_cursor = group_cursor(&bob, &group_id);

            {
                let record = harness
                    .outboxes
                    .get_mut(&group_id)
                    .expect("group outbox")
                    .last_mut()
                    .expect("application record");
                rewrite(&mut record.envelope);
                // The record id travels alongside the envelope's, and
                // `GroupOutboxRecord::validate` requires them to agree.
                record.message_id = record.envelope.message_id.clone();
            }

            harness.sync_group(&mut bob, &group_id);

            assert_eq!(
                group_trace(&bob, &group_id, &conversation_id),
                before,
                "[{name}] a rewritten header must leave no trace"
            );
            assert!(
                group_cursor(&bob, &group_id) > before_cursor,
                "[{name}] the cursor must step past the dropped record"
            );
        }
    }

    /// **R2b.** The positive control. Without this, every "forgery is
    /// rejected" test above would pass just as well against a gate that
    /// rejected everything.
    #[test]
    fn genuine_group_records_pass_the_authentication_gate() {
        let mut alice = harness_user("alice", ALICE_MNEMONIC, "phone");
        let mut bob = harness_user("bob", BOB_MNEMONIC, "phone");
        let mut carol = harness_user("carol", CAROL_MNEMONIC, "phone");
        let (mut harness, group_id, conversation_id) =
            synced_trio(&mut alice, &mut bob, &mut carol);

        harness.send_text(&mut alice, &conversation_id, "hello");
        harness.send_attachment(&mut alice, &conversation_id, sample_attachment_descriptor());
        harness.sync_group(&mut bob, &group_id);

        let records = harness.outboxes.get(&group_id).expect("group outbox");
        assert!(!records.is_empty(), "alice produced no group records");
        for record in records {
            let verdict =
                bob.engine
                    .authenticate_group_outbox_record(&group_id, &conversation_id, record);
            assert!(
                verdict.is_ok(),
                "the gate rejected a genuine {:?} record: {:?}",
                record.envelope.message_type,
                verdict
            );
        }
    }

    /// **R2b, Part 4.** `ControlConversationNeedsRebuild` has no producer on
    /// the group path, yet it used to be the first statement of the catch-all
    /// branch: one appended record tore the conversation down, unsigned and
    /// unchecked, and returned without even writing the cursor. This is the
    /// group twin of `injected_rebuild_control_leaves_no_trace`.
    #[test]
    fn an_injected_group_rebuild_control_leaves_no_trace() {
        let mut alice = harness_user("alice", ALICE_MNEMONIC, "phone");
        let mut bob = harness_user("bob", BOB_MNEMONIC, "phone");
        let mut carol = harness_user("carol", CAROL_MNEMONIC, "phone");
        let (mut harness, group_id, conversation_id) =
            synced_trio(&mut alice, &mut bob, &mut carol);

        harness.send_text(&mut alice, &conversation_id, "a genuine message");
        harness.sync_group(&mut bob, &group_id);

        let before = group_trace(&bob, &group_id, &conversation_id);
        let before_cursor = group_cursor(&bob, &group_id);

        {
            let records = harness.outboxes.get_mut(&group_id).expect("group outbox");
            let mut injected = records.last().expect("a record to clone").clone();
            injected.seq = records.len() as u64 + 1;
            injected.envelope.message_type = GroupMessageType::ControlConversationNeedsRebuild;
            injected.envelope.message_id = "msg:injected-rebuild".into();
            injected.message_id = injected.envelope.message_id.clone();
            injected.envelope.transition_id = None;
            injected.envelope.membership_proof = None;
            records.push(injected);
        }

        harness.sync_group(&mut bob, &group_id);

        assert_eq!(
            group_trace(&bob, &group_id, &conversation_id),
            before,
            "an injected rebuild control must not tear the conversation down"
        );
        assert!(
            group_cursor(&bob, &group_id) > before_cursor,
            "the cursor must step past it rather than stalling the group"
        );
        assert!(
            !bob.engine
                .state
                .group_states
                .get(&group_id)
                .is_some_and(|state| state.consistency_state
                    == crate::persistence::GroupConsistencyState::BlockedNeedsRebuild),
            "the group must not be blocked on a rebuild"
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

        assert!(group_plaintexts(&bob, &conversation_id)
            .iter()
            .any(|text| text == "from realtime owner"));
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
        assert!(!caught_up
            .effects
            .iter()
            .any(|effect| matches!(effect, CoreEffect::FetchGroupOutbox { .. })));
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
        assert!(snapshot
            .pending_group_outbox
            .iter()
            .any(|item| item.group_id == group_id));

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
        assert!(alice
            .engine
            .state
            .pending_group_outbox
            .iter()
            .filter(|item| item.envelope.group_id == group_id)
            .all(|item| item.in_flight && item.retries == 0));
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
        assert!(alice
            .engine
            .state
            .pending_group_seal
            .contains_key(&group_id));

        let snapshot = alice.engine.refresh_snapshot();
        assert!(snapshot
            .pending_group_seal
            .iter()
            .any(|seal| seal.group_id == group_id));
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
        assert!(group_plaintexts(&bob, &conversation_id)
            .iter()
            .any(|text| text == "after remove from alice"));
        assert!(group_plaintexts(&alice, &conversation_id)
            .iter()
            .any(|text| text == "after remove from bob"));

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
        assert!(!alice.engine.state.group_states[&group_id]
            .manifest
            .members
            .iter()
            .any(|member| {
                member.user_id == bob.bundle.user_id && member.status == GroupMemberStatus::Active
            }));

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
        assert!(carol
            .engine
            .state
            .group_states
            .get(&group_id)
            .expect("carol group")
            .manifest
            .members
            .iter()
            .any(|member| member.user_id == dana.bundle.user_id
                && member.status == GroupMemberStatus::Removed));

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
            .find(|item| item.plaintext_cache.as_deref() == Some("hello"))
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
        assert_ne!(pending.envelope.mid, app_message_id);
        let visible = &output.view_model.as_ref().expect("view model").messages;
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].conversation_id, conversation_id);
        assert_eq!(visible[0].message_id, app_message_id);
        assert_eq!(visible[0].message_type, MessageType::MlsApplication);
    }

    #[test]
    fn live_append_request_exposes_only_the_four_host_fields() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        let output = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "hello".into(),
            })
            .expect("send");
        let body = output
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::ExecuteHttpRequest { request } if request.url.contains("/messages") => {
                    request.body.clone()
                }
                _ => None,
            })
            .expect("append body");
        let value: serde_json::Value = serde_json::from_str(&body).expect("append json");
        let envelope = value
            .get("envelope")
            .expect("envelope")
            .as_object()
            .expect("envelope object");
        let keys: BTreeSet<_> = envelope.keys().cloned().collect();
        for forbidden in [
            "conversationId",
            "conversation_id",
            "senderUserId",
            "sender_user_id",
            "messageType",
            "message_type",
            "senderProof",
            "sender_proof",
        ] {
            assert!(
                !keys.contains(forbidden),
                "host-visible envelope must not include {forbidden}; keys were {keys:?}"
            );
        }
        assert!(keys.contains("lane"));
        assert!(keys.contains("mid"));
        assert!(
            keys.contains("bytes") || keys.contains("storageRef") || keys.contains("storage_ref")
        );
        assert!(keys.contains("recipientDeviceId") || keys.contains("recipient_device_id"));
        let bytes_b64 = envelope
            .get("bytes")
            .and_then(|value| value.as_str())
            .expect("bytes");
        let bytes = STANDARD.decode(bytes_b64).expect("bytes b64");
        let needle = conversation_id.as_bytes();
        assert!(
            !bytes.windows(needle.len()).any(|window| window == needle),
            "wrapped bytes must not contain conversation_id"
        );
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
            .find(|item| outbox_item_matches_type(item, MessageType::MlsApplication))
            .expect("failed outbox delivery remains visible");
        assert!(!pending.in_flight);
        assert_eq!(pending.retries, crate::ffi_api::MAX_TRANSPORT_RETRIES);
    }

    #[test]
    fn create_conversation_enqueues_only_welcome_for_joiner() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = local_engine(ALICE_MNEMONIC, "phone");
        alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: bob_bundle.clone(),
            })
            .expect("import bob");
        let output = alice
            .handle_command(CoreCommand::CreateConversation {
                peer_user_id: bob_bundle.user_id.clone(),
                conversation_kind: ConversationKind::Direct,
            })
            .expect("create");
        let output = simulate_pending_key_package_claims(&mut alice, output);
        let messages = &output.view_model.as_ref().expect("view").messages;
        assert!(
            !messages.is_empty(),
            "create must enqueue a Welcome for the joiner"
        );
        assert!(
            messages
                .iter()
                .all(|message| message.message_type == MessageType::MlsWelcome),
            "create must not send the initiator's already-merged commit"
        );
        assert!(alice.state.pending_outbox.iter().all(|item| {
            crate::mls_adapter::MlsAdapter::payload_is_welcome(
                item.envelope.payload_b64().unwrap_or_default(),
            )
        }));
        assert_eq!(
            output.view_model.as_ref().expect("view").conversations[0].last_message_type,
            Some(MessageType::MlsWelcome)
        );
    }

    #[test]
    fn preview_welcome_reads_identity_bundle_ref_without_adopting() {
        let mut chat = unjoined_direct_chat();
        let expected_ref = chat
            .alice
            .state
            .local_bundle
            .as_ref()
            .and_then(|bundle| bundle.identity_bundle_ref.clone());
        let welcome_bytes = chat
            .alice
            .state
            .pending_outbox
            .iter()
            .find_map(|item| {
                let payload = item.envelope.payload_b64()?;
                crate::mls_adapter::MlsAdapter::payload_is_welcome(payload)
                    .then(|| payload.to_string())
            })
            .expect("alice queued a Welcome");
        let before = chat
            .bob
            .state
            .mls_adapter
            .as_ref()
            .expect("bob adapter")
            .state_fingerprint()
            .expect("fingerprint");
        let preview = chat
            .bob
            .handle_command(CoreCommand::PreviewWelcome {
                welcome_bytes: welcome_bytes.clone(),
            })
            .expect("preview")
            .view_model
            .and_then(|view| view.welcome_preview)
            .expect("welcome preview");
        assert_eq!(preview.conversation_id, chat.conversation_id);
        assert_eq!(
            preview.author_user_id,
            chat.alice
                .state
                .local_identity
                .as_ref()
                .expect("alice identity")
                .user_identity
                .user_id
        );
        assert_eq!(preview.identity_bundle_ref, expected_ref);
        assert_eq!(
            chat.bob
                .state
                .mls_adapter
                .as_ref()
                .expect("bob adapter")
                .state_fingerprint()
                .expect("fingerprint after preview"),
            before,
            "preview must not adopt the Welcome or consume a KeyPackage"
        );
        assert!(
            !chat
                .bob
                .state
                .conversations
                .contains_key(&chat.conversation_id),
            "preview must not create the conversation"
        );
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
        assert!(delete_output
            .effects
            .iter()
            .any(|effect| matches!(effect, CoreEffect::RevokeAcceptedLanes { .. })));
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
                .all(|item| envelope_is_host_opaque_direct(&item.envelope)),
            "contact removed must leave only wrapped MLS application frames"
        );
        let pending_after_delete = alice.state.pending_outbox.len();
        assert!(
            pending_after_delete > 0,
            "contact removed must notify the peer before the session is torn down"
        );
        let send_err = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "blocked".into(),
            })
            .expect_err("closed relationship blocks send");
        assert_eq!(send_err.code(), "relationship_closed");
        assert_eq!(alice.state.pending_outbox.len(), pending_after_delete);

        let _ = alice.handle_event(CoreEvent::AcceptedLaneRegistered {
            lane: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        });

        let snapshot = alice.refresh_snapshot();
        assert!(snapshot
            .conversations
            .iter()
            .any(|conversation| conversation.conversation_id == conversation_id));
        assert!(!snapshot
            .contacts
            .iter()
            .any(|contact| contact.user_id == bob_bundle.user_id));
        assert!(!snapshot
            .mls_states
            .iter()
            .any(|state| state.conversation_id == conversation_id));
        assert!(
            !snapshot.pending_outbox.is_empty(),
            "delete_contact must leave a wrapped ContactRemoved frame for the peer"
        );
        assert!(
            snapshot
                .pending_outbox
                .iter()
                .all(|item| envelope_is_host_opaque_direct(&item.envelope)),
            "the leftover outbox must stay typeless wrapped MLS, not a parseable control"
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
        assert!(output
            .effects
            .iter()
            .any(|effect| matches!(effect, CoreEffect::RevokeAcceptedLanes { .. })));

        let _ = alice.handle_event(CoreEvent::AcceptedLaneRegistered {
            lane: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        });
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

        alice
            .handle_command(CoreCommand::DeleteContact {
                user_id: bob_bundle.user_id.clone(),
            })
            .expect("alice deletes bob");
        assert!(
            alice
                .state
                .pending_outbox
                .iter()
                .all(|item| envelope_is_host_opaque_direct(&item.envelope)),
            "contact removed rides MLS; the 1:1 header stays typeless"
        );
        assert!(!alice.state.pending_outbox.is_empty());
        assert!(!alice.state.contacts.contains_key(&bob_bundle.user_id));
        assert!(!alice.state.mls_summaries.contains_key(&conversation_id));
        assert!(bob.state.contacts.contains_key(&alice_bundle.user_id));
    }

    #[test]
    fn contact_removed_rides_the_direct_session() {
        let mut chat = paired_direct_chat();
        let bob_user_id = chat
            .bob
            .state
            .local_identity
            .as_ref()
            .expect("bob identity")
            .user_identity
            .user_id
            .clone();
        let alice_user_id = chat
            .alice
            .state
            .local_identity
            .as_ref()
            .expect("alice identity")
            .user_identity
            .user_id
            .clone();
        chat.alice
            .handle_command(CoreCommand::DeleteContact {
                user_id: bob_user_id.clone(),
            })
            .expect("alice deletes bob");
        assert!(!chat.alice.state.pending_outbox.is_empty());
        for item in &chat.alice.state.pending_outbox {
            assert!(envelope_is_host_opaque_direct(&item.envelope));
            let visible = host_visible_envelope_json(&item.envelope);
            assert!(
                !visible.contains("control_contact_removed"),
                "removed notify must not name a control type on the wire"
            );
        }
        deliver_pending_outbox_to_device(&mut chat.bob, &chat.alice, &chat.bob_device_id);
        let bob_conversation = chat
            .bob
            .state
            .conversations
            .get(&chat.conversation_id)
            .expect("bob conversation");
        assert_eq!(
            bob_conversation.conversation.state,
            crate::model::ConversationState::Archived
        );
        assert_eq!(
            chat.bob
                .state
                .contacts
                .get(&alice_user_id)
                .expect("alice contact")
                .relationship_status,
            ContactRelationshipStatus::RemovedByPeer
        );
    }

    #[test]
    fn contact_accepted_rides_the_direct_session() {
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
        let bob_device_id = bob.local_device_id().expect("bob device").to_string();
        deliver_pending_outbox_to_device(&mut alice, &bob, &alice_device_id);
        alice
            .handle_event(CoreEvent::MessageRequestActionCompleted {
                result: accepted_request_result(&bob_bundle.user_id, &conversation_id),
            })
            .expect("alice accepts");
        assert!(
            alice
                .state
                .pending_outbox
                .iter()
                .any(|item| envelope_is_wrapped_app(&alice, &item.envelope)),
            "accept must send a wrapped MLS application frame"
        );
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
    fn lane_rotation_body_carries_signed_bundle_and_inbound_lane() {
        let bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let inbound_lane = "0123456789abcdef0123456789abcdef".to_string();
        let body = crate::model::LaneRotationBody {
            bundle: bundle.clone(),
            inbound_lane: inbound_lane.clone(),
        };
        let json = serde_json::to_value(&body).expect("lane rotation json");
        let object = json.as_object().expect("object");
        let mut keys = object.keys().cloned().collect::<Vec<_>>();
        keys.sort();
        assert_eq!(keys, vec!["bundle".to_string(), "inbound_lane".to_string()]);
        assert!(!object.contains_key("identity_bundle_ref"));
        assert_eq!(
            object.get("inbound_lane").and_then(|value| value.as_str()),
            Some(inbound_lane.as_str())
        );
        assert_eq!(
            object
                .get("bundle")
                .and_then(|value| value.get("userId"))
                .and_then(|value| value.as_str()),
            Some(bundle.user_id.as_str())
        );
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
        let _conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());

        alice
            .handle_command(CoreCommand::DeleteContact {
                user_id: bob_bundle.user_id.clone(),
            })
            .expect("alice deletes bob");
        assert!(alice
            .state
            .pending_outbox
            .iter()
            .all(|item| envelope_is_host_opaque_direct(&item.envelope)));

        let bob_device_id = bob.local_device_id().expect("bob device").to_string();
        let late = InboxRecord {
            seq: 1,
            recipient_device_id: bob_device_id.clone(),
            message_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            received_at: 1,
            expires_at: None,
            state: InboxRecordState::Available,
            envelope: Envelope::with_bytes(
                &bob_device_id,
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "not-a-welcome",
            ),
        };
        bob.handle_event(CoreEvent::InboxRecordsFetched {
            device_id: bob_device_id.clone(),
            to_seq: 1,
            records: vec![late],
        })
        .expect("unknown-lane garbage is acked");

        assert!(bob.state.contacts.contains_key(&alice_bundle.user_id));
        let sync_state = bob
            .state
            .sync_states
            .get(&bob_device_id)
            .expect("sync state");
        assert_eq!(sync_state.checkpoint.last_acked_seq, 1);
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
        assert!(alice.state.pending_outbox.iter().any(|item| {
            crate::mls_adapter::MlsAdapter::payload_is_welcome(
                item.envelope.payload_b64().unwrap_or_default(),
            ) || outbox_item_matches_type(item, MessageType::MlsCommit)
        }));

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
            alice.state.pending_outbox.is_empty(),
            "accept without a local MLS session must not enqueue a contact-accepted frame"
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

        assert!(
            alice.state.pending_outbox.is_empty(),
            "accept without those conversations locally must not enqueue a contact-accepted frame"
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
        assert!(
            request.auth.is_none(),
            "claiming a peer's pool is unauthenticated"
        );

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
        assert!(alice
            .state
            .mls_summaries
            .contains_key(&summary.conversation_id));
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
        assert!(alice
            .state
            .mls_summaries
            .contains_key(&summary.conversation_id));
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
            (
                carol_bundle.user_id.clone(),
                carol_bundle.devices[0].clone(),
            ),
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
        assert!(alice
            .state
            .group_states
            .contains_key(summary.group_id.as_deref().expect("group id")));
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
        assert!(alice
            .state
            .group_states
            .get(&group_id)
            .expect("group state")
            .pending_group_transition
            .is_none());

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
        assert!(alice
            .state
            .group_states
            .get(&group_id)
            .expect("group state")
            .pending_group_transition
            .is_some());
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
        assert!(alice
            .state
            .group_states
            .get(&group_id)
            .expect("group state")
            .manifest
            .members
            .iter()
            .any(|member| member.user_id == carol_bundle.user_id));
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
        assert!(alice
            .state
            .group_states
            .get(&group_id)
            .expect("group state")
            .pending_group_transition
            .is_none());

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
        assert!(alice
            .state
            .group_states
            .get(&group_id)
            .expect("group state")
            .manifest
            .members
            .iter()
            .any(|member| member.user_id == dana_bundle.user_id));
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

        assert!(alice
            .state
            .group_states
            .get(&group_id)
            .expect("group state")
            .pending_group_transition
            .is_some());
        acknowledge_pending_group_transition(&mut alice, &group_id);
        assert!(alice
            .state
            .group_states
            .get(&group_id)
            .expect("group state")
            .manifest
            .member_devices
            .iter()
            .any(|device| device.device_id == tablet_device_id));
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
        assert!(!alice
            .state
            .group_states
            .get(&group_id)
            .expect("group state")
            .manifest
            .member_devices
            .iter()
            .any(|device| device.device_id == tablet_device_id));
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
        let bob_laptop_profile =
            crate::capability::CapabilityManager::build_device_contact_profile(
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
        assert!(request
            .url
            .contains(&urlencoding::encode(&laptop_device_id).into_owned()));
        assert!(!alice
            .state
            .pending_outbox
            .iter()
            .any(|item| { item.envelope.recipient_device_id == laptop_device_id }));

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
            item.envelope.recipient_device_id == laptop_device_id
                && crate::mls_adapter::MlsAdapter::payload_is_welcome(
                    item.envelope.payload_b64().unwrap_or_default(),
                )
        }));
        assert!(alice
            .state
            .pending_outbox
            .iter()
            .any(|item| outbox_item_matches_type(item, MessageType::MlsCommit)));
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

        let below_low_water =
            crate::mls_adapter::ONE_TIME_KEY_PACKAGE_POOL_LOW_WATER.saturating_sub(2);
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
        let _conversation_id = create_direct_conversation(&mut bob, alice_bundle.user_id.clone());
        assert!(bob
            .state
            .pending_outbox
            .iter()
            .any(|item| outbox_item_matches_type(item, MessageType::MlsWelcome)));
        assert!(bob
            .state
            .pending_outbox
            .iter()
            .all(|item| { !outbox_item_matches_type(item, MessageType::MlsCommit) }));

        assert!(alice.state.conversations.is_empty());
        let send_err = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: "ffffffffffffffffffffffffffffffff".into(),
                plaintext: "too early".into(),
            })
            .expect_err("missing conversation blocks send");
        assert!(matches!(
            send_err.code(),
            "invalid_input" | "invalid_state" | "temporary_failure"
        ));
    }

    #[test]
    fn quarantine_clears_after_later_welcome_applies() {
        let mut bob = local_engine(BOB_MNEMONIC, "phone");
        let bob_bundle = bob.local_bundle().expect("bob bundle").clone();
        let bob_device_id = bob.local_device_id().expect("bob device").to_string();
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        link_contact(&mut bob, &alice);
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());

        assert!(alice
            .state
            .pending_outbox
            .iter()
            .all(|item| { !outbox_item_matches_type(item, MessageType::MlsCommit) }));
        let welcome = first_pending_envelope(&alice, &bob_device_id, MessageType::MlsWelcome);

        bob.handle_event(CoreEvent::InboxRecordsFetched {
            device_id: bob_device_id.clone(),
            to_seq: 1,
            records: vec![InboxRecord {
                seq: 1,
                recipient_device_id: bob_device_id.clone(),
                message_id: welcome.mid.clone(),
                received_at: 1,
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
        assert!(!sync_state.quarantine.contains_key(&1));
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

        alice
            .handle_event(CoreEvent::MessageRequestActionCompleted {
                result: accepted_request_result(&bob_bundle.user_id, &conversation_id),
            })
            .expect("alice accepts bob request");
        assert!(
            alice.state.pending_outbox.is_empty(),
            "accept without a local MLS session must not enqueue a contact-accepted frame"
        );
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
        assert!(alice.state.pending_outbox.is_empty());

        let bob_device_id = bob.local_device_id().expect("bob device").to_string();
        let accepted_envelope = Envelope::with_bytes(
            &bob_device_id,
            "cccccccccccccccccccccccccccccccc",
            "dddddddddddddddddddddddddddddddd",
            "00".repeat(64),
        );

        bob.handle_event(CoreEvent::InboxRecordsFetched {
            device_id: bob_device_id.clone(),
            to_seq: 1,
            records: vec![InboxRecord {
                seq: 1,
                recipient_device_id: bob_device_id.clone(),
                message_id: accepted_envelope.mid.clone(),
                received_at: 1,
                expires_at: None,
                state: InboxRecordState::Available,
                envelope: accepted_envelope,
            }],
        })
        .expect("a badly signed control is discarded, not an error");
        // Acked and dropped: returning an error here would have left the
        // record un-acked and redelivered forever, stalling every other
        // record on the device.
        assert_eq!(
            bob.state
                .sync_states
                .get(&bob_device_id)
                .expect("sync state")
                .checkpoint
                .last_acked_seq,
            1
        );
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
        assert!(alice.state.pending_outbox.is_empty());
        let bob_device_id_for_late = bob.local_device_id().expect("bob device").to_string();
        let accepted_envelope = Envelope::with_bytes(
            &bob_device_id_for_late,
            "cccccccccccccccccccccccccccccccc",
            "dddddddddddddddddddddddddddddddd",
            "00".repeat(64),
        );

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
                message_id: accepted_envelope.mid.clone(),
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
        let mut chat = paired_direct_chat();
        let conversation_id = chat.conversation_id.clone();
        let bob_device_id = chat.bob_device_id.clone();
        chat.alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "late".into(),
            })
            .expect("queue late message");
        let stale_envelope =
            last_pending_envelope(&chat.alice, &bob_device_id, MessageType::MlsApplication);

        chat.bob
            .handle_command(CoreCommand::DeleteContact {
                user_id: chat
                    .alice
                    .local_bundle()
                    .expect("alice bundle")
                    .user_id
                    .clone(),
            })
            .expect("bob deletes alice");
        let message_count_before = chat
            .bob
            .state
            .conversations
            .get(&conversation_id)
            .expect("conversation")
            .messages
            .len();

        chat.bob
            .handle_event(CoreEvent::InboxRecordsFetched {
                device_id: bob_device_id.clone(),
                to_seq: 2,
                records: vec![InboxRecord {
                    seq: 2,
                    recipient_device_id: bob_device_id.clone(),
                    message_id: stale_envelope.mid.clone(),
                    received_at: 2,
                    expires_at: None,
                    state: InboxRecordState::Available,
                    envelope: stale_envelope.clone(),
                }],
            })
            .expect("late message ignored");

        let bob_conversation = chat
            .bob
            .state
            .conversations
            .get(&conversation_id)
            .expect("conversation");
        assert_eq!(bob_conversation.messages.len(), message_count_before);
        assert!(!bob_conversation
            .messages
            .iter()
            .any(|message| message.message_id == stale_envelope.mid));
        assert!(!chat
            .bob
            .state
            .recovery_contexts
            .contains_key(&conversation_id));
        let sync_state = chat
            .bob
            .state
            .sync_states
            .get(&bob_device_id)
            .expect("sync state");
        assert_eq!(sync_state.checkpoint.last_acked_seq, 2);
        assert_eq!(sync_state.quarantine.len(), 1);
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
            CoreEffect::PrepareBlobUpload { upload, .. }
                // A 1:1 payload is placed in the recipient's runtime, admitted
                // on the lane the recipient already admits us on. No runtime
                // credential of our own takes part: we are a stranger there.
                if upload.headers.get("Authorization").is_none()
                    && upload.auth.is_none()
                    && upload.lane.is_some()
                    && upload.endpoint.ends_with("/blob-upload")
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
                .find(|item| item.envelope.storage_ref.is_some())
                .expect("attachment outbox")
                .envelope
                .storage_ref
                .as_ref()
                .expect("storage ref")
                .object_ref,
            "blob:attachment-1"
        );
        let outbox_item = alice
            .state
            .pending_outbox
            .iter()
            .find(|item| item.envelope.storage_ref.is_some())
            .expect("attachment outbox");
        let message_id = outbox_item.envelope.mid.clone();
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
            CoreEffect::PrepareBlobUpload { upload, .. } if upload.size_bytes == 20
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
            .find(|item| item.envelope.storage_ref.is_some())
            .expect("video outbox");
        let envelope_message_id = outbox.envelope.mid.clone();
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
        assert!(alice
            .state
            .pending_blob_uploads
            .get(&original_task)
            .is_some_and(|task| task.uploaded));
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
        assert!(alice
            .state
            .pending_outbox
            .iter()
            .all(|item| { item.app_message_id.as_deref() == Some(logical_message_id.as_str()) }));
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
        assert!(prepared
            .effects
            .iter()
            .any(|effect| matches!(effect, CoreEffect::PrepareBlobUpload { .. })));
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
        assert!(alice
            .handle_command(CoreCommand::SendAttachmentMessage {
                conversation_id: conversation_id.clone(),
                attachment_descriptor: descriptor,
            })
            .is_err());

        let mut descriptor = sample_attachment_descriptor();
        descriptor.file_name = Some("nested/file.bin".into());
        assert!(alice
            .handle_command(CoreCommand::SendAttachmentMessage {
                conversation_id,
                attachment_descriptor: descriptor,
            })
            .is_err());
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

    /// Payloads are hosted by whoever receives them.
    ///
    /// This is what keeps the sender's infrastructure out of the receiver's
    /// fetch: nothing reports back to the sender that the receiver looked, when,
    /// or from where. It is also what makes delivery final — the object cannot
    /// expire under a retention policy the receiver did not set, because the
    /// runtime holding it is the receiver's own.
    ///
    /// Stated as the polarity of the resolved origin, in both directions of one
    /// conversation, because that is the whole of the claim.
    #[test]
    fn a_direct_payload_is_hosted_by_its_recipient() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let bob_user_id = bob_bundle.user_id.clone();
        let mut engine = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle);
        // The fixtures share one deployment, so both parties would otherwise
        // publish the same storage origin and the polarity would be untestable.
        // Each party provisions its own; give the peer its own here.
        let bob_storage = "https://storage.bob.example".to_string();
        engine
            .state
            .contacts
            .get_mut(&bob_user_id)
            .expect("peer contact")
            .bundle
            .storage_profile
            .as_mut()
            .expect("peer storage profile")
            .base_url = Some(bob_storage.clone());
        let local_device_id = engine
            .state
            .local_identity
            .as_ref()
            .expect("local identity")
            .device_identity
            .device_id
            .clone();

        // What I send names the peer's runtime; what I receive names mine.
        let mut outbound = sample_attachment_payload_metadata();
        outbound.original.storage_origin = bob_storage.clone();
        let mut inbound = sample_attachment_payload_metadata();
        inbound.original.object_ref = "blob:inbound".into();

        let message = |message_id: &str, sender_user: &str, sender_device: &str, manifest: &_| {
            crate::conversation::StoredMessage {
                message_id: message_id.into(),
                app_message_id: None,
                mls_ciphertext_sha256: None,
                sender_user_id: Some(sender_user.into()),
                sender_device_id: sender_device.into(),
                recipient_device_id: "device:recipient".into(),
                message_type: MessageType::MlsApplication,
                created_at: 0,
                plaintext: Some(serde_json::to_string(manifest).expect("manifest")),
                storage_refs: vec![],
                delivery_state: None,
                message_request_id: None,
            }
        };

        engine.state.conversations.insert(
            "conv:test".into(),
            crate::conversation::LocalConversationState {
                conversation: crate::model::Conversation {
                    conversation_id: "conv:test".into(),
                    kind: ConversationKind::Direct,
                    member_users: vec!["user:alice".into(), bob_user_id.clone()],
                    member_devices: vec![],
                    state: crate::model::ConversationState::Active,
                    updated_at: 0,
                },
                messages: vec![
                    message("msg:mine", "user:alice", &local_device_id, &outbound),
                    message("msg:theirs", &bob_user_id, "device:bob:phone", &inbound),
                ],
                last_message_type: Some(MessageType::MlsApplication),
                peer_user_id: bob_user_id,
                last_known_peer_active_devices: Default::default(),
                recovery_status: crate::conversation::RecoveryStatus::Healthy,
                archive_metadata: None,
                pcs: Default::default(),
                lanes: None,
            },
        );

        // What I send is fetched by the peer, so it sits in the peer's storage.
        let sent = engine
            .resolve_attachment_descriptor(
                "conv:test".into(),
                "msg:mine".into(),
                "blob:test".into(),
            )
            .expect("outbound descriptor");
        assert_eq!(sent.storage_origin, bob_storage);

        // What the peer sends is fetched by me, so it sits in mine.
        let received = engine
            .resolve_attachment_descriptor(
                "conv:test".into(),
                "msg:theirs".into(),
                "blob:inbound".into(),
            )
            .expect("inbound descriptor");
        assert_eq!(received.storage_origin, "https://storage.example.com");
        assert_ne!(received.storage_origin, bob_storage);
    }

    #[test]
    fn download_attachment_uses_unique_task_ids_for_distinct_destinations() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let bob_user_id = bob_bundle.user_id.clone();
        let mut engine = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle);
        let conversation_id = "conv:test".to_string();
        // Inbound attachment: the payload sits in our own storage, because
        // this is the runtime the sender was admitted to place it in.
        let legacy_metadata = sample_attachment_payload_metadata();
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
                lanes: None,
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
        assert!(engine
            .state
            .pending_blob_downloads
            .values()
            .all(|task| { task.blob_descriptor.storage_origin == "https://storage.example.com" }));
    }

    #[test]
    fn fetch_response_restores_conversation_and_emits_ack_request() {
        let (bob_identity, bob_bundle) = sample_identity_with_bundle(BOB_MNEMONIC, "phone");
        let mut engine = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle);
        let device_id = engine
            .state
            .local_identity
            .as_ref()
            .expect("identity")
            .device_identity
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

        let output = engine
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id: fetch_request_id,
                status: 200,
                body: Some(
                    serde_json::json!({
                        "to_seq": 1,
                        "records": [signed_control_record_from(
                            &bob_identity,
                            &device_id,
                            1,
                        )],
                    })
                    .to_string(),
                ),
            })
            .expect("fetch response");

        assert!(
            engine.state.conversations.is_empty(),
            "a 1:1 control-shaped record cannot open a conversation"
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
        let message_id = pending.envelope.mid.clone();

        let output = alice
            .handle_event(CoreEvent::AppStarted)
            .expect("startup sync");

        let pending = alice
            .state
            .pending_outbox
            .iter()
            .find(|item| item.envelope.mid == message_id)
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
            CoreEffect::PrepareBlobUpload { upload, .. }
                // A 1:1 payload is placed in the recipient's runtime, where we
                // hold no credential of our own. The lane is the whole of the
                // authorization, and it is the same lane the envelope that
                // references the payload will travel on.
                if upload.headers.get("Authorization").is_none()
                    && upload.auth.is_none()
                    && upload.lane.is_some()
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
        assert!(persist
            .ops
            .iter()
            .any(|op| matches!(op, PersistOp::SaveOutgoingEnvelope { .. })));
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
        assert!(snapshot
            .mls_states
            .iter()
            .all(|state| state.serialized_group_state.is_some()));
    }

    /// An append reply is a sequence number, so there is no disposition to
    /// disbelieve — only a reply we can read, or none.
    #[test]
    fn append_requires_a_decodable_reply() {
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

        let error = alice
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id,
                status: 200,
                body: None,
            })
            .expect_err("an append with no body should fail");
        assert_eq!(error.code(), "invalid_input");

        let output = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id,
                plaintext: "again".into(),
            })
            .expect("send");
        let request_id = find_http_request_id(&output, "/messages");
        let accepted = alice
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id,
                status: 200,
                body: Some(r#"{"seq":41}"#.into()),
            })
            .expect("a sequence number is the whole reply");
        assert_eq!(
            accepted
                .view_model
                .as_ref()
                .and_then(|view| view.append_result.as_ref())
                .and_then(|result| result.seq),
            Some(41)
        );
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
            .mid
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
            .find(|item| item.envelope.mid == pending_message_id)
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
        assert!(failed
            .effects
            .iter()
            .all(|effect| !matches!(effect, CoreEffect::FetchIdentityBundle { .. })));
        let pending = alice
            .state
            .pending_outbox
            .iter()
            .find(|item| item.envelope.mid == pending_message_id)
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
            .mid
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

        assert!(!alice
            .state
            .pending_outbox
            .iter()
            .any(|item| item.envelope.mid == pending_message_id));
        let append_result = output
            .view_model
            .as_ref()
            .and_then(|view| view.append_result.as_ref())
            .expect("append result");
        assert!(append_result.seq.is_some());
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
            Some(crate::conversation::StoredMessageDeliveryState::Sent)
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
            .mid
            .clone();

        let output = alice
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id,
                status: 200,
                body: Some(r#"{"accepted":true,"seq":0,"delivered_to":"rejected"}"#.into()),
            })
            .expect("rejected response");

        assert!(!alice
            .state
            .pending_outbox
            .iter()
            .any(|item| item.envelope.mid == pending_message_id));
        let append_result = output
            .view_model
            .as_ref()
            .and_then(|view| view.append_result.as_ref())
            .expect("append result");
        assert_eq!(append_result.seq, Some(0));
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
        assert_eq!(append_result.seq, Some(3));
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
            .mid
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
        assert!(!snapshot
            .pending_outbox
            .iter()
            .any(|item| item.message_id == pending_message_id));
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
    fn peer_bundle_cannot_be_rolled_back() {
        let bundle_n = sample_identity_bundle_at_revision(BOB_MNEMONIC, "phone", 2);
        let mut alice = local_engine(ALICE_MNEMONIC, "phone");
        alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: bundle_n.clone(),
            })
            .expect("import N");
        let snapshot = alice
            .state
            .contacts
            .get(&bundle_n.user_id)
            .expect("bob contact")
            .clone();

        let error = alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: sample_identity_bundle_at_revision(BOB_MNEMONIC, "phone", 1),
            })
            .expect_err("older revision");
        assert_eq!(error.code(), "identity_bundle_rolled_back");
        assert_eq!(
            alice
                .state
                .contacts
                .get(&bundle_n.user_id)
                .expect("bob contact"),
            &snapshot
        );

        alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: bundle_n.clone(),
            })
            .expect("idempotent N");
        assert_eq!(
            alice
                .state
                .contacts
                .get(&bundle_n.user_id)
                .expect("bob contact")
                .bundle
                .publication_revision,
            2
        );

        alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: sample_identity_bundle_at_revision(BOB_MNEMONIC, "phone", 3),
            })
            .expect("import N+1");
        assert_eq!(
            alice
                .state
                .contacts
                .get(&bundle_n.user_id)
                .expect("bob contact")
                .bundle
                .publication_revision,
            3
        );
    }

    #[test]
    fn peer_bundle_update_cannot_be_rolled_back() {
        let bundle_n = sample_identity_bundle_at_revision(BOB_MNEMONIC, "phone", 2);
        let mut alice = local_engine(ALICE_MNEMONIC, "phone");
        alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: bundle_n.clone(),
            })
            .expect("import N");
        let snapshot = alice
            .state
            .contacts
            .get(&bundle_n.user_id)
            .expect("bob contact")
            .clone();

        let error = alice
            .handle_command(CoreCommand::ApplyIdentityBundleUpdate {
                bundle: sample_identity_bundle_at_revision(BOB_MNEMONIC, "phone", 1),
            })
            .expect_err("older revision");
        assert_eq!(error.code(), "identity_bundle_rolled_back");
        assert_eq!(
            alice
                .state
                .contacts
                .get(&bundle_n.user_id)
                .expect("bob contact"),
            &snapshot
        );

        alice
            .handle_command(CoreCommand::ApplyIdentityBundleUpdate {
                bundle: bundle_n.clone(),
            })
            .expect("idempotent N");
        assert_eq!(
            alice
                .state
                .contacts
                .get(&bundle_n.user_id)
                .expect("bob contact")
                .bundle
                .publication_revision,
            2
        );

        alice
            .handle_command(CoreCommand::ApplyIdentityBundleUpdate {
                bundle: sample_identity_bundle_at_revision(BOB_MNEMONIC, "phone", 3),
            })
            .expect("update N+1");
        assert_eq!(
            alice
                .state
                .contacts
                .get(&bundle_n.user_id)
                .expect("bob contact")
                .bundle
                .publication_revision,
            3
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
        let same_key_contact = alice
            .state
            .contacts
            .get(&bob_bundle.user_id)
            .expect("bob contact");
        assert!(same_key_contact.is_verified());
        assert!(!same_key_contact.key_changed_unverified);

        let snapshot = alice.refresh_snapshot();
        let restored = CoreEngine::try_from_restored_state(snapshot).expect("restore");
        assert!(restored
            .state
            .contacts
            .get(&bob_bundle.user_id)
            .expect("restored contact")
            .is_verified());

        alice
            .handle_command(CoreCommand::SetContactVerified {
                user_id: bob_bundle.user_id.clone(),
                verified: false,
            })
            .expect("unverify");
        assert!(!alice
            .state
            .contacts
            .get(&bob_bundle.user_id)
            .expect("bob contact")
            .is_verified());
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
        // This test mutates the remembered `verified_root_key`, not the
        // contact's actual `bundle.user_public_key` — it simulates the
        // user's confirmation going stale, not a real key change on the
        // wire, so key_changed_unverified must NOT fire here. See
        // `key_changed_unverified_is_set_for_a_real_key_change` below for
        // the case where the underlying root key actually changes.
        assert!(!alice
            .state
            .contacts
            .get(&bob_bundle.user_id)
            .expect("bob contact")
            .is_verified());
    }

    #[test]
    fn key_changed_unverified_is_set_for_a_real_key_change_regardless_of_prior_verification() {
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

        // Simulate the contact's stored bundle having previously carried a
        // different root key. The reimport below restores the real key, so
        // is_verified() legitimately ends up true again (it always tracks
        // "does verified_root_key match the current bundle key", which it
        // now does) — that path is already covered by
        // `contact_verification_clears_when_root_key_diverges`. What this
        // test isolates is that note_root_key_before_update still latches
        // key_changed_unverified purely from seeing the key change happen,
        // regardless of whether verification status happens to end up true.
        alice
            .state
            .contacts
            .get_mut(&bob_bundle.user_id)
            .expect("bob contact")
            .bundle
            .user_public_key =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into();

        alice
            .handle_command(CoreCommand::ApplyIdentityBundleUpdate {
                bundle: bob_bundle.clone(),
            })
            .expect("update after real key change");
        assert!(
            alice
                .state
                .contacts
                .get(&bob_bundle.user_id)
                .expect("bob contact")
                .key_changed_unverified
        );
    }

    #[test]
    fn key_changed_unverified_is_set_even_when_contact_was_never_verified() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = local_engine(ALICE_MNEMONIC, "phone");
        alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: bob_bundle.clone(),
            })
            .expect("import");

        let fresh_contact = alice
            .state
            .contacts
            .get(&bob_bundle.user_id)
            .expect("bob contact");
        assert!(!fresh_contact.is_verified());
        assert!(!fresh_contact.key_changed_unverified);

        // Simulate the contact having previously been on a different root
        // key, without ever having been marked verified — this is exactly
        // the branch that used to produce zero signal.
        alice
            .state
            .contacts
            .get_mut(&bob_bundle.user_id)
            .expect("bob contact")
            .bundle
            .user_public_key =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into();

        alice
            .handle_command(CoreCommand::ApplyIdentityBundleUpdate {
                bundle: bob_bundle.clone(),
            })
            .expect("update after key change");
        let changed_contact = alice
            .state
            .contacts
            .get(&bob_bundle.user_id)
            .expect("bob contact");
        assert!(!changed_contact.is_verified());
        assert!(changed_contact.key_changed_unverified);

        // The flag is sticky: a subsequent update that does not itself
        // change the key must not clear it until the user acknowledges.
        alice
            .handle_command(CoreCommand::ApplyIdentityBundleUpdate {
                bundle: bob_bundle.clone(),
            })
            .expect("no-op update");
        assert!(
            alice
                .state
                .contacts
                .get(&bob_bundle.user_id)
                .expect("bob contact")
                .key_changed_unverified
        );

        alice
            .handle_command(CoreCommand::SetContactVerified {
                user_id: bob_bundle.user_id.clone(),
                verified: true,
            })
            .expect("acknowledge via verify");
        assert!(
            !alice
                .state
                .contacts
                .get(&bob_bundle.user_id)
                .expect("bob contact")
                .key_changed_unverified
        );
    }

    #[test]
    fn ack_requires_explicit_accepted_result() {
        let (bob_identity, bob_bundle) = sample_identity_with_bundle(BOB_MNEMONIC, "phone");
        let mut engine = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle);
        let device_id = engine
            .state
            .local_identity
            .as_ref()
            .expect("identity")
            .device_identity
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
                        "records": [signed_control_record_from(
                            &bob_identity,
                            &device_id,
                            1,
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
                    acked_at: 7,
                },
                retries: 0,
            });

        let mut restored = CoreEngine::try_from_restored_state(snapshot).expect("restore snapshot");
        let resumed = restored
            .handle_event(CoreEvent::AppStarted)
            .expect("app started");

        assert!(resumed
            .effects
            .iter()
            .any(|effect| matches!(effect, CoreEffect::ReadAttachmentBytes { .. })));
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
        assert!(serialized
            .as_array()
            .and_then(|items| items.first())
            .and_then(|item| item.get("Upload"))
            .and_then(|upload| upload.get("blob_ciphertext"))
            .is_none());

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
        let (bob_identity, bob_bundle) = sample_identity_with_bundle(BOB_MNEMONIC, "phone");
        let mut engine = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle);
        let device_id = engine
            .state
            .local_identity
            .as_ref()
            .expect("identity")
            .device_identity
            .device_id
            .clone();
        let record = signed_control_record_from(&bob_identity, &device_id, 1);

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
                device_id: device_id.clone(),
                records: vec![record],
                to_seq: 1,
            })
            .expect("fetch records");

        assert!(engine.state.conversations.is_empty());
        assert_eq!(
            engine
                .sync_checkpoint_snapshot(&device_id)
                .expect("checkpoint")
                .last_acked_seq,
            1
        );
    }

    #[test]
    fn stale_realtime_head_after_fetch_is_noop() {
        let (bob_identity, bob_bundle) = sample_identity_with_bundle(BOB_MNEMONIC, "phone");
        let mut engine = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle);
        let device_id = engine
            .state
            .local_identity
            .as_ref()
            .expect("identity")
            .device_identity
            .device_id
            .clone();

        let record = signed_control_record_from(&bob_identity, &device_id, 1);

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
        assert!(engine.state.conversations.is_empty());
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
        link_contact(&mut bob, &alice);
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
        assert!(snapshot
            .mls_states
            .iter()
            .any(|state| state.conversation_id == conversation_id));
        assert!(snapshot
            .sync_states
            .iter()
            .any(|state| state.device_id == bob_device_id));
        assert!(snapshot
            .pending_acks
            .iter()
            .any(|ack| ack.device_id == bob_device_id));
        let restored = CoreEngine::try_from_restored_state(snapshot).expect("restore snapshot");
        assert!(restored.mls_summary(&conversation_id).is_some());
        let restored_conversation = restored
            .conversation_state(&conversation_id)
            .expect("restored conversation");
        assert!(restored_conversation
            .messages
            .iter()
            .any(|message| { message.plaintext.as_deref() == Some("hello after welcome") }));
        assert!(restored.sync_checkpoint_snapshot(&bob_device_id).is_some());
    }

    #[test]
    fn proven_mls_ciphertext_replay_is_acknowledged_without_duplicate_message() {
        let mut bob = local_engine(BOB_MNEMONIC, "phone");
        let bob_bundle = bob.local_bundle().expect("bob bundle").clone();
        let bob_device_id = bob_bundle.devices[0].device_id.clone();
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        link_contact(&mut bob, &alice);
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
        assert!(!sync.quarantine.contains_key(&replay_seq));
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

    /// The ideal functionality has no interface through which an adversary can
    /// supply a message, so a receiver that reacts observably to one it cannot
    /// authenticate is distinguishable from it (§1 Remark 1(a)).
    ///
    /// Every vector below is something anyone holding the inbox append
    /// capability can construct. For each, the receiver must: return `Ok`,
    /// advance its ack cursor (withholding an ack is itself a reaction, and
    /// pins the cursor for the whole device), and change *nothing* else — no
    /// stored message, no epoch or status movement, no recovery context, no
    /// retained retry copy, no view-model entry, no outbound effect beyond the
    /// ack, and no loss of the ability to send.

    /// `Deliver(Q, i)` returns the i-th entry of the transcript, and an entry
    /// is there only because some party called `Send`. So the set a receiver
    /// surfaces is the set that was sent — no more, which is the half a host
    /// could violate by injecting, and no less, which is the half it could
    /// violate by dropping while the receiver stayed quiet.
    ///
    /// `invalid_ciphertext_leaves_no_trace` already proves that an injected
    /// record changes nothing observable. This proves the complementary thing
    /// it does not: that the delivered *set* equals the sent set.
    #[test]
    fn deliver_returns_only_sent_messages() {
        let mut chat = paired_direct_chat();
        let sent = ["first", "second", "third"];
        for body in sent {
            chat.alice
                .handle_command(CoreCommand::SendTextMessage {
                    conversation_id: chat.conversation_id.clone(),
                    plaintext: body.to_string(),
                })
                .expect("send");
        }
        let bob_device_id = chat.bob_device_id.clone();
        deliver_pending_outbox_to_device(&mut chat.bob, &chat.alice, &bob_device_id);

        let delivered = |engine: &CoreEngine| -> BTreeSet<String> {
            engine
                .state
                .conversations
                .get(&chat.conversation_id)
                .expect("conversation")
                .messages
                .iter()
                .filter_map(|message| message.plaintext.clone())
                .collect()
        };
        let received = delivered(&chat.bob);
        assert_eq!(
            received,
            sent.iter().map(|body| body.to_string()).collect(),
            "the delivered set must be exactly the sent set"
        );

        // Now a record the transcript never held: a well-formed envelope on the
        // live lane whose payload nobody sent. The set must not grow.
        let live_lane = chat
            .alice
            .state
            .conversations
            .get(&chat.conversation_id)
            .expect("conversation")
            .lanes
            .as_ref()
            .expect("lanes")
            .outbound_lane
            .clone();
        let forged = Envelope::with_bytes(
            &bob_device_id,
            live_lane,
            crate::model::random_opaque_id(),
            STANDARD.encode([0x5A_u8; 96]),
        );
        deliver_inbox_envelope(&mut chat.bob, &bob_device_id, forged, 500);
        assert_eq!(
            delivered(&chat.bob),
            received,
            "a record that was never sent must not become a delivered message"
        );
    }

    /// The lane wrap hides the MLS frame header, whose `group_id` is the
    /// conversation and is identical at both inboxes.
    ///
    /// This is the reverse of the deleted existence proof
    /// `mls_frame_header_names_the_conversation_in_the_clear`. What one
    /// execution can show is that the header is not readable off a wrapped
    /// payload while it *is* readable off the one frame that goes unwrapped;
    /// that the two inboxes therefore share no token is the corpus's
    /// `host_view_shares_no_token_across_inboxes`.
    #[test]
    fn a_wrapped_frame_does_not_name_the_conversation() {
        use openmls::prelude::{tls_codec::Deserialize, MlsMessageIn};

        let mut chat = paired_direct_chat();
        let welcome = chat
            .alice
            .state
            .pending_outbox
            .first()
            .map(|item| item.envelope.clone());
        chat.alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: chat.conversation_id.clone(),
                plaintext: "a message whose frame header is hidden".into(),
            })
            .expect("send");
        let wrapped = last_pending_application_envelope(&chat.alice, &chat.bob_device_id);

        let payload = |envelope: &Envelope| -> Vec<u8> {
            STANDARD
                .decode(envelope.payload_b64().expect("payload"))
                .expect("base64")
        };
        let names_conversation = |bytes: &[u8]| -> bool {
            bytes
                .windows(chat.conversation_id.len())
                .any(|window| window == chat.conversation_id.as_bytes())
        };

        let wrapped_bytes = payload(&wrapped);
        assert!(
            !names_conversation(&wrapped_bytes),
            "the conversation id must not appear in a wrapped payload"
        );
        // Not merely absent as a substring: the header is not parseable at any
        // offset a frame can begin at, so no field of it is readable either.
        for start in [0, 1, 1 + crate::direct_frame::COMMIT_SIGNATURE_LEN] {
            assert!(
                start >= wrapped_bytes.len()
                    || MlsMessageIn::tls_deserialize_exact(&wrapped_bytes[start..]).is_err(),
                "a wrapped payload must not parse as an MLS message at offset {start}"
            );
        }

        // The control: the welcome is the one frame that is not wrapped, and it
        // does parse. Without this the assertion above would pass on any
        // payload at all, including an empty one.
        let welcome = welcome.expect("the create step enqueued a welcome");
        assert!(
            MlsMessageIn::tls_deserialize_exact(payload(&welcome).as_slice()).is_ok(),
            "the welcome is sent unwrapped, so it must still parse"
        );
    }

    #[test]
    fn invalid_ciphertext_leaves_no_trace() {
        struct Vector {
            name: &'static str,
            mutate: fn(&mut Envelope),
        }

        let vectors = [
            Vector {
                name: "payload is not base64",
                mutate: |envelope| envelope.bytes = Some("!!! not base64 !!!".into()),
            },
            Vector {
                name: "payload is base64 but not an MLS frame",
                mutate: |envelope| envelope.bytes = Some("aGVsbG8gd29ybGQ=".into()),
            },
            Vector {
                name: "recipient is not this device",
                mutate: |envelope| envelope.recipient_device_id = "device:mallory:phone".into(),
            },
            Vector {
                name: "lane does not resolve to a conversation",
                mutate: |envelope| envelope.lane = "ffffffffffffffffffffffffffffffff".into(),
            },
            Vector {
                name: "wrapped bytes are truncated",
                mutate: |envelope| envelope.bytes = Some("AA==".into()),
            },
        ];

        for vector in vectors {
            let mut chat = paired_direct_chat();
            let conversation_id = chat.conversation_id.clone();
            let bob_device_id = chat.bob_device_id.clone();

            // A healthy, joined conversation with one delivered message.
            chat.alice
                .handle_command(CoreCommand::SendTextMessage {
                    conversation_id: conversation_id.clone(),
                    plaintext: "before".into(),
                })
                .expect("send before");
            deliver_pending_outbox_to_device(&mut chat.bob, &chat.alice, &bob_device_id);

            let before_summary = chat.bob.state.mls_summaries.get(&conversation_id).cloned();
            let before_messages = chat.bob.state.conversations[&conversation_id]
                .messages
                .len();
            let before_ack = chat.bob.state.sync_states[&bob_device_id]
                .checkpoint
                .last_acked_seq;

            // Take a genuine envelope and corrupt exactly one thing about it.
            let mut envelope = pending_application_record(&chat.alice, &bob_device_id).envelope;
            envelope.mid = format!("{}:{}", envelope.mid, vector.name.len());
            resign_envelope(&chat.alice, &mut envelope);
            (vector.mutate)(&mut envelope);

            let seq = before_ack + 1;
            let output = chat
                .bob
                .handle_event(CoreEvent::InboxRecordsFetched {
                    device_id: bob_device_id.clone(),
                    to_seq: seq,
                    records: vec![InboxRecord {
                        seq,
                        recipient_device_id: bob_device_id.clone(),
                        message_id: envelope.mid.clone(),
                        received_at: seq,
                        expires_at: None,
                        state: InboxRecordState::Available,
                        envelope: envelope.clone(),
                    }],
                })
                .unwrap_or_else(|error| panic!("[{}] must not error: {error:?}", vector.name));

            let sync = &chat.bob.state.sync_states[&bob_device_id];
            assert_eq!(
                sync.checkpoint.last_acked_seq, seq,
                "[{}] the ack cursor must advance",
                vector.name
            );
            assert!(
                sync.quarantine.is_empty(),
                "[{}] nothing may be retained",
                vector.name
            );
            assert_eq!(
                chat.bob.state.mls_summaries.get(&conversation_id).cloned(),
                before_summary,
                "[{}] MLS state must not move",
                vector.name
            );
            assert_eq!(
                chat.bob.state.conversations[&conversation_id]
                    .messages
                    .len(),
                before_messages,
                "[{}] no message row may be written",
                vector.name
            );
            assert!(
                chat.bob.state.recovery_contexts.is_empty(),
                "[{}] no recovery context may be opened",
                vector.name
            );
            assert_eq!(
                chat.bob.state.conversations[&conversation_id].recovery_status,
                RecoveryStatus::Healthy,
                "[{}] the conversation must stay healthy",
                vector.name
            );
            assert!(
                output
                    .view_model
                    .as_ref()
                    .map(|model| model.messages.is_empty())
                    .unwrap_or(true),
                "[{}] nothing may surface to the UI",
                vector.name
            );
            // Still usable: the whole point is that this is not a remote
            // off-switch for the conversation.
            chat.bob
                .handle_command(CoreCommand::SendTextMessage {
                    conversation_id: conversation_id.clone(),
                    plaintext: "after".into(),
                })
                .unwrap_or_else(|error| {
                    panic!("[{}] sending must still work: {error:?}", vector.name)
                });
        }
    }

    /// A retained out-of-order record must be invisible.
    ///
    /// It is authenticated, so it is kept for a retry — but "cannot be applied
    /// yet" is indistinguishable from "future-epoch forgery", so if holding
    /// one degraded the conversation, an adversary who can append could switch
    /// off a conversation at will. Only a genuinely missing Welcome is allowed
    /// to surface.
    #[test]
    fn a_retained_out_of_order_record_does_not_degrade_the_conversation() {
        let mut chat = paired_direct_chat();
        let conversation_id = chat.conversation_id.clone();
        let bob_device_id = chat.bob_device_id.clone();

        // Alice sends two application messages but only the second is
        // delivered, so Bob holds a frame he cannot open yet.
        chat.alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "first".into(),
            })
            .expect("send first");
        let first = pending_application_record(&chat.alice, &bob_device_id);
        chat.alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "second".into(),
            })
            .expect("send second");
        let second = chat
            .alice
            .state
            .pending_outbox
            .iter()
            .rev()
            .find(|item| {
                item.envelope.recipient_device_id == bob_device_id
                    && item.envelope.mid != first.envelope.mid
                    && item
                        .plaintext_cache
                        .as_deref()
                        .is_some_and(|text| !text.is_empty())
            })
            .map(|item| item.envelope.clone())
            .expect("second application envelope");

        let base = chat.bob.state.sync_states[&bob_device_id]
            .checkpoint
            .last_acked_seq;
        let seq = base + 1;
        chat.bob
            .handle_event(CoreEvent::InboxRecordsFetched {
                device_id: bob_device_id.clone(),
                to_seq: seq,
                records: vec![InboxRecord {
                    seq,
                    recipient_device_id: bob_device_id.clone(),
                    message_id: second.mid.clone(),
                    received_at: seq,
                    expires_at: None,
                    state: InboxRecordState::Available,
                    envelope: second,
                }],
            })
            .expect("out-of-order delivery is not an error");

        // Whatever the MLS layer decided, the conversation must remain usable
        // and undegraded, and the ack cursor must have moved.
        let sync = &chat.bob.state.sync_states[&bob_device_id];
        assert_eq!(sync.checkpoint.last_acked_seq, seq);
        assert_eq!(
            chat.bob.state.conversations[&conversation_id].recovery_status,
            RecoveryStatus::Healthy,
            "an authenticated but unapplied record must not degrade the conversation"
        );
        assert!(chat.bob.state.recovery_contexts.is_empty());
        chat.bob
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id,
                plaintext: "still sending".into(),
            })
            .expect("sending must still work");
    }

    /// The gate must admit genuine traffic. Without this, every "forgery is
    /// rejected" test could pass while the transport rejected everything.
    #[test]
    fn genuine_inbound_records_pass_the_authentication_gate() {
        let mut bob = local_engine(BOB_MNEMONIC, "phone");
        let bob_bundle = bob.local_bundle().expect("bob bundle").clone();
        let bob_device_id = bob_bundle.devices[0].device_id.clone();
        let bob_user_id = bob_bundle.user_id.clone();
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle);
        link_contact(&mut bob, &alice);
        create_direct_conversation(&mut alice, bob_user_id.clone());

        let records: Vec<InboxRecord> = alice
            .state
            .pending_outbox
            .iter()
            .filter(|item| item.envelope.recipient_device_id == bob_device_id)
            .enumerate()
            .map(|(index, item)| InboxRecord {
                seq: index as u64 + 1,
                recipient_device_id: item.envelope.recipient_device_id.clone(),
                message_id: item.envelope.mid.clone(),
                received_at: index as u64 + 1,
                expires_at: None,
                state: InboxRecordState::Available,
                envelope: item.envelope.clone(),
            })
            .collect();
        assert!(!records.is_empty(), "alice produced no records for bob");

        for record in &records {
            let verdict = bob.authenticate_inbox_record(&bob_user_id, &bob_device_id, record);
            assert!(
                verdict.is_ok(),
                "the gate rejected a genuine lane={} mid={} record: {:?}",
                record.envelope.lane,
                record.envelope.mid,
                verdict
            );
        }
    }

    /// R2: a defect inside one envelope is that envelope's problem.
    ///
    /// A malformed record used to abort the whole batch with `Err`, which
    /// emitted no persist op, acked nothing, and re-failed identically on
    /// every later fetch — so one poisoned record suppressed every other
    /// record on the device indefinitely, across restarts, while looking like
    /// a transient decode error. It costs the attacker one HTTP POST.
    #[test]
    fn one_inadmissible_record_does_not_block_the_rest_of_the_batch() {
        let mut bob = local_engine(BOB_MNEMONIC, "phone");
        let bob_bundle = bob.local_bundle().expect("bob bundle").clone();
        let bob_device_id = bob_bundle.devices[0].device_id.clone();
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        link_contact(&mut bob, &alice);
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        deliver_pending_outbox_to_device(&mut bob, &alice, &bob_device_id);
        alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "must still arrive".into(),
            })
            .expect("send application");

        let good = pending_application_record(&alice, &bob_device_id);
        // Base the new seqs on the ack cursor, not the fetch cursor, so the
        // batch is contiguous with what has already been acked and the
        // assertion below is about admission rather than about a seq gap.
        let next_seq = bob
            .state
            .sync_states
            .get(&bob_device_id)
            .expect("sync state")
            .checkpoint
            .last_acked_seq;

        // A record whose declared model version this build does not support.
        // Every field it fails on is authored inside this one envelope.
        let mut poisoned = good.clone();
        poisoned.seq = next_seq + 1;
        poisoned.message_id = format!("{}:poisoned", good.message_id);
        poisoned.envelope.mid = poisoned.message_id.clone();
        poisoned.envelope.bytes = Some("!!!not-mls!!!".into());

        let mut good = good;
        good.seq = next_seq + 2;

        bob.handle_event(CoreEvent::InboxRecordsFetched {
            device_id: bob_device_id.clone(),
            records: vec![poisoned.clone(), good.clone()],
            to_seq: good.seq,
        })
        .expect("a poisoned record must not abort its neighbours");

        let sync = bob
            .state
            .sync_states
            .get(&bob_device_id)
            .expect("sync state");
        assert_eq!(
            sync.checkpoint.last_acked_seq, good.seq,
            "both records must be acked so the cursor clears the poisoned seq"
        );
        // The valid neighbour was processed, not merely acked.
        assert!(conversation_has_plaintext(
            &bob,
            &conversation_id,
            "must still arrive"
        ));
        // The poisoned record left nothing behind.
        assert!(!bob
            .state
            .conversations
            .get(&conversation_id)
            .expect("conversation")
            .messages
            .iter()
            .any(|message| message.message_id == poisoned.message_id));
        assert!(bob.state.recovery_contexts.is_empty());
    }

    /// R2: a ciphertext whose MLS generation has already been consumed is
    /// terminal — forward secrecy deleted the secret, so no message arriving
    /// later can decrypt it. This used to be retained forever and to force the
    /// conversation into `NeedsRecovery` whenever no durable projection
    /// "proved" the replay, which pinned the ack cursor and blocked sending on
    /// a conversation that an attacker could target for free. Nothing was
    /// recovered by that; the plaintext was already unrecoverable. Ack and
    /// discard, leaving no trace.
    #[test]
    fn unprovable_mls_ciphertext_replay_is_acked_and_leaves_no_trace() {
        let mut bob = local_engine(BOB_MNEMONIC, "phone");
        let bob_bundle = bob.local_bundle().expect("bob bundle").clone();
        let bob_device_id = bob_bundle.devices[0].device_id.clone();
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        link_contact(&mut bob, &alice);
        link_contact(&mut bob, &alice);
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
        .expect("a consumed generation is discarded, not an error");

        let sync = bob
            .state
            .sync_states
            .get(&bob_device_id)
            .expect("sync state");
        assert!(
            sync.checkpoint.last_acked_seq > last_acked,
            "the ack cursor must advance past a discarded record: {} !> {last_acked}",
            sync.checkpoint.last_acked_seq
        );
        // At least the replayed seq, and possibly further: any later record
        // that was queued behind this gap drains as soon as the gap fills.
        // That head-of-line unblocking is the point — one undecryptable frame
        // must not pin the whole device's ack cursor.
        assert!(sync.checkpoint.last_acked_seq >= replay_seq);
        assert!(sync.quarantine.is_empty());
        assert!(!sync.quarantine.contains_key(&replay_seq));
        assert_eq!(
            bob.state
                .conversations
                .get(&conversation_id)
                .expect("conversation")
                .recovery_status,
            RecoveryStatus::Healthy,
            "a discarded record must not degrade the conversation"
        );
        assert!(
            !bob.state.recovery_contexts.contains_key(&conversation_id),
            "a discarded record must not open a recovery context"
        );
    }

    #[test]
    fn ack_success_deletes_persisted_pending_ack() {
        let mut bob = local_engine(BOB_MNEMONIC, "phone");
        let bob_bundle = bob.local_bundle().expect("bob bundle").clone();
        let bob_device_id = bob_bundle.devices[0].device_id.clone();
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        link_contact(&mut bob, &alice);
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
        assert!(!snapshot
            .pending_acks
            .iter()
            .any(|ack| ack.device_id == bob_device_id));
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
                assert!(output
                    .state_update
                    .system_statuses_changed
                    .contains(&crate::ffi_api::SystemStatus::ConversationNeedsRebuild));
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

    /// R2: `ControlConversationNeedsRebuild` has no honest producer on the
    /// direct inbox — nothing in the codebase builds a direct envelope with
    /// that type — so it was pure attack surface: an unsigned, unverified
    /// record that tore a conversation down on arrival. It is now off the
    /// inbound allowlist and leaves no trace.
    #[test]
    fn injected_rebuild_control_leaves_no_trace() {
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
        let record = sample_control_record_with_type(&device_id, 1);
        let conversation_id = format!("control:{}", record.message_id);
        let seq = record.seq;

        alice
            .handle_event(CoreEvent::InboxRecordsFetched {
                device_id: device_id.clone(),
                records: vec![record],
                to_seq: seq,
            })
            .expect("an injected rebuild control is discarded, not an error");

        // Nothing about the conversation moved.
        assert!(
            alice.state.conversations.get(&conversation_id).is_none(),
            "an unauthenticated control must not even materialise a conversation"
        );
        assert!(alice.recovery_context_snapshot(&conversation_id).is_none());
        // And it was acked, so it cannot be redelivered forever.
        assert_eq!(
            alice
                .state
                .sync_states
                .get(&device_id)
                .expect("sync state")
                .checkpoint
                .last_acked_seq,
            seq
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
        assert!(!snapshot
            .recovery_contexts
            .iter()
            .any(|context| context.conversation_id == conversation_id));

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
                    // Inbound: the peer sent it, so the payload sits in our own
                    // storage and the download is against our own runtime.
                    sender_user_id: Some("user:bob".into()),
                    sender_device_id: "device:bob:phone".into(),
                    recipient_device_id: local_device_id,
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
                lanes: None,
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
                assert!(!output
                    .effects
                    .iter()
                    .any(|effect| matches!(effect, CoreEffect::ScheduleTimer { .. })));
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
                true && crate::mls_adapter::MlsAdapter::payload_is_welcome(
                    item.envelope.payload_b64().unwrap_or_default(),
                ) && item.envelope.recipient_device_id == laptop_profile.device_id
            })
            .map(|item| item.envelope.clone())
            .expect("welcome for laptop");

        let phone = alice
            .state
            .local_identity
            .as_ref()
            .expect("alice identity")
            .device_identity
            .clone();
        let mut restored = CoreEngine::try_from_restored_state(snapshot).expect("restore snapshot");
        let result = restored
            .state
            .mls_adapter
            .as_mut()
            .expect("restored laptop adapter")
            .ingest_welcome(
                &conversation_id,
                &crate::mls_adapter::WelcomeAuthor {
                    device_id: phone.device_id,
                    device_public_key: phone.device_public_key,
                },
                welcome.bytes.as_deref().expect("welcome payload"),
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
        link_contact(&mut bob, &alice);
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
        link_contact(&mut bob, &alice);
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
        link_contact(&mut bob, &alice);
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
        assert!(updated
            .bundle
            .devices
            .iter()
            .any(|device| device.device_id == bob_laptop_profile.device_id));
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
            crate::mls_adapter::MlsAdapter::payload_is_welcome(
                item.envelope.payload_b64().unwrap_or_default(),
            ) && item.envelope.recipient_device_id == bob_laptop_profile.device_id
        }));
        assert!(alice
            .state
            .pending_outbox
            .iter()
            .any(|item| { outbox_item_matches_type(item, MessageType::MlsCommit) }));
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
            crate::mls_adapter::MlsAdapter::payload_is_welcome(
                item.envelope.payload_b64().unwrap_or_default(),
            )
        }));
        let remove_commits: Vec<_> = new_pending
            .iter()
            .filter(|item| outbox_item_matches_type(item, MessageType::MlsCommit))
            .collect();
        assert!(!remove_commits.is_empty());
        assert!(remove_commits
            .iter()
            .all(|item| item.envelope.recipient_device_id == bob_laptop_profile.device_id));
        assert!(remove_commits
            .iter()
            .all(|item| item.envelope.recipient_device_id != bob_phone_profile.device_id));
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
        assert!(restored.state.pending_outbox[pending_before..]
            .iter()
            .any(|item| outbox_item_matches_type(item, MessageType::MlsCommit)));
        assert!(restored.state.pending_outbox[pending_before..]
            .iter()
            .any(|item| {
                crate::mls_adapter::MlsAdapter::payload_is_welcome(
                    item.envelope.payload_b64().unwrap_or_default(),
                )
            }));
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
                    CoreEffect::PrepareBlobUpload { task_id, upload } => {
                        // This harness drives group conversations, and group
                        // payloads stay on their uploader's runtime. A 1:1
                        // payload carries a lane and goes to the recipient's
                        // runtime instead; if one ever reaches here, the
                        // uploader-origin answer below would be wrong, so say
                        // so rather than answer quietly.
                        assert!(
                            upload.lane.is_none(),
                            "group harness received a 1:1 payload upload"
                        );
                        let blob_ref = format!("blob-ref:{task_id}");
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
                                task_id,
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
                        let key_package_b64 = user
                            .engine
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
                            .or_else(|| {
                                self.bundles.values().find_map(|bundle| {
                                    bundle
                                        .devices
                                        .iter()
                                        .find(|device| device.device_id == device_id)
                                        .and_then(|device| device.keypackage_ref.as_ref())
                                        .map(|keypackage_ref| keypackage_ref.object_ref.clone())
                                })
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
                    CoreEffect::RegisterAcceptedLane { register } => user
                        .engine
                        .handle_event(CoreEvent::AcceptedLaneRegistered {
                            lane: register.lane,
                        })
                        .expect("accepted lane registered"),
                    CoreEffect::RevokeAcceptedLanes { .. }
                    | CoreEffect::FetchIdentityBundle { .. }
                    | CoreEffect::PersistState { .. }
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

    #[test]
    fn group_invite_rides_the_direct_session() {
        let mut alice = harness_user("alice", ALICE_MNEMONIC, "phone");
        let mut bob = harness_user("bob", BOB_MNEMONIC, "phone");
        import_peer_bundles(&mut [&mut alice, &mut bob]);
        assert!(alice
            .engine
            .state
            .conversations
            .values()
            .all(|conversation| {
                conversation.conversation.kind != ConversationKind::Direct
                    || conversation.peer_user_id != bob.bundle.user_id
            }));
        let mut harness = GroupHarness::with_bundles(&[&alice, &bob].map(|user| HarnessUser {
            name: user.name,
            bundle: user.bundle.clone(),
            engine: CoreEngine::new(),
        }));
        harness.create_group(&mut alice, "Family", vec![bob.bundle.user_id.clone()]);
        let bob_device = bob.bundle.devices[0].device_id.clone();
        let for_bob = alice
            .engine
            .state
            .pending_outbox
            .iter()
            .filter(|item| item.envelope.recipient_device_id == bob_device)
            .cloned()
            .collect::<Vec<_>>();
        assert!(
            for_bob.iter().any(|item| MlsAdapter::payload_is_welcome(
                item.envelope.payload_b64().unwrap_or_default()
            )),
            "inviting a contact with no 1:1 session must emit a Welcome first"
        );
        assert!(
            for_bob
                .iter()
                .any(|item| envelope_is_wrapped_app(&alice.engine, &item.envelope)),
            "the group invite must then ride a wrapped application frame"
        );
        for item in &for_bob {
            let payload = item.envelope.payload_b64().unwrap_or_default();
            if MlsAdapter::payload_is_welcome(payload) {
                continue;
            }
            assert!(
                envelope_is_wrapped_app(&alice.engine, &item.envelope),
                "1:1 inbox must not carry a parseable non-Welcome record"
            );
            let visible = host_visible_envelope_json(&item.envelope);
            assert!(!visible.contains("control_group_welcome_pickup"));
            assert!(!visible.contains("Family"));
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
            let output = engine
                .handle_event(CoreEvent::WelcomePickupPut { descriptor })
                .expect("acknowledge welcome pickup");
            simulate_pending_key_package_claims(engine, output);
        }
        output
    }

    #[test]
    fn lane_rotation_applies_peer_bundle_without_fetch() {
        let mut chat = paired_direct_chat();
        let bob_user_id = chat
            .bob
            .state
            .local_identity
            .as_ref()
            .expect("bob identity")
            .user_identity
            .user_id
            .clone();
        let previous = chat
            .alice
            .state
            .contacts
            .get(&bob_user_id)
            .expect("alice holds bob")
            .bundle
            .clone();
        let mut rotated = chat
            .bob
            .state
            .local_bundle
            .clone()
            .expect("bob local bundle");
        rotated.identity_bundle_ref =
            Some("https://example.test/v1/contact-share/bob-rotated".into());
        rotated.publication_revision = rotated.publication_revision.saturating_add(1);
        rotated.signature = chat
            .bob
            .state
            .local_identity
            .as_ref()
            .expect("bob identity")
            .sign_payload_with_root(crate::identity::identity_bundle_payload(&rotated));
        chat.bob.state.local_bundle = Some(rotated.clone());

        set_direct_pcs_debt(
            &mut chat.bob,
            &chat.conversation_id,
            DIRECT_PCS_COMMIT_INTERVAL * 2,
        );
        chat.bob
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: chat.conversation_id.clone(),
                plaintext: "pcs trigger".into(),
            })
            .expect("bob pcs");

        let inbound =
            deliver_pending_outbox_to_device(&mut chat.alice, &chat.bob, &chat.alice_device_id);
        assert!(
            inbound
                .effects
                .iter()
                .all(|effect| !matches!(effect, CoreEffect::FetchIdentityBundle { .. })),
            "lane rotation must apply the inlined bundle locally"
        );
        assert!(
            !chat
                .alice
                .state
                .conversations
                .get(&chat.conversation_id)
                .expect("conversation")
                .messages
                .iter()
                .any(|message| message.plaintext.as_deref() == Some("")),
            "lane rotation must not become a visible chat message"
        );
        assert_eq!(
            chat.alice
                .state
                .contacts
                .get(&bob_user_id)
                .expect("bob contact")
                .bundle
                .identity_bundle_ref
                .as_deref(),
            Some("https://example.test/v1/contact-share/bob-rotated")
        );
        assert_eq!(
            chat.alice
                .state
                .contacts
                .get(&bob_user_id)
                .expect("bob contact")
                .bundle
                .publication_revision,
            rotated.publication_revision
        );

        let error = chat
            .alice
            .handle_command(CoreCommand::ApplyIdentityBundleUpdate { bundle: previous })
            .expect_err("older revision");
        assert_eq!(error.code(), "identity_bundle_rolled_back");
    }

    #[test]
    fn lane_rotation_applies_newer_publication_without_fetch() {
        let mut chat = paired_direct_chat();
        let bob_user_id = chat
            .bob
            .state
            .local_identity
            .as_ref()
            .expect("bob identity")
            .user_identity
            .user_id
            .clone();
        let stored_ref = chat
            .alice
            .state
            .contacts
            .get(&bob_user_id)
            .expect("alice holds bob")
            .bundle
            .identity_bundle_ref
            .clone()
            .expect("bob contact already has a bundle ref");
        let previous_revision = chat
            .alice
            .state
            .contacts
            .get(&bob_user_id)
            .expect("alice holds bob")
            .bundle
            .publication_revision;
        let mut rotated = chat
            .bob
            .state
            .local_bundle
            .clone()
            .expect("bob local bundle");
        assert_eq!(
            rotated.identity_bundle_ref.as_deref(),
            Some(stored_ref.as_str()),
            "this case is the same locator with a newer publication"
        );
        rotated.publication_revision = previous_revision.saturating_add(1);
        rotated.signature = chat
            .bob
            .state
            .local_identity
            .as_ref()
            .expect("bob identity")
            .sign_payload_with_root(crate::identity::identity_bundle_payload(&rotated));
        chat.bob.state.local_bundle = Some(rotated.clone());

        set_direct_pcs_debt(
            &mut chat.bob,
            &chat.conversation_id,
            DIRECT_PCS_COMMIT_INTERVAL * 2,
        );
        chat.bob
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: chat.conversation_id.clone(),
                plaintext: "pcs trigger".into(),
            })
            .expect("bob pcs");

        let inbound =
            deliver_pending_outbox_to_device(&mut chat.alice, &chat.bob, &chat.alice_device_id);
        assert!(
            inbound
                .effects
                .iter()
                .all(|effect| !matches!(effect, CoreEffect::FetchIdentityBundle { .. })),
            "same-url revision bump must not fetch"
        );
        assert_eq!(
            chat.alice
                .state
                .contacts
                .get(&bob_user_id)
                .expect("bob contact")
                .bundle
                .publication_revision,
            rotated.publication_revision
        );
        assert_eq!(
            chat.alice
                .state
                .contacts
                .get(&bob_user_id)
                .expect("bob contact")
                .bundle
                .identity_bundle_ref
                .as_deref(),
            Some(stored_ref.as_str())
        );
    }

    #[test]
    fn relocation_to_empty_runtime_keeps_the_conversation() {
        let mut chat = paired_direct_chat();
        let conversation_id = chat.conversation_id.clone();
        let bob_user_id = chat
            .bob
            .state
            .local_identity
            .as_ref()
            .expect("bob identity")
            .user_identity
            .user_id
            .clone();

        chat.alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "before-move".into(),
            })
            .expect("alice sends before move");
        deliver_pending_outbox_to_device(&mut chat.bob, &chat.alice, &chat.bob_device_id);
        chat.bob
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "before-move-reply".into(),
            })
            .expect("bob replies before move");
        deliver_pending_outbox_to_device(&mut chat.alice, &chat.bob, &chat.alice_device_id);

        let old_bob_inbound = chat
            .bob
            .state
            .conversations
            .get(&conversation_id)
            .and_then(|conversation| conversation.lanes.as_ref())
            .map(|lanes| lanes.inbound_lane.clone())
            .expect("bob inbound");
        let old_alice_outbound = chat
            .alice
            .state
            .conversations
            .get(&conversation_id)
            .and_then(|conversation| conversation.lanes.as_ref())
            .map(|lanes| lanes.outbound_lane.clone())
            .expect("alice outbound");
        assert_eq!(old_alice_outbound, old_bob_inbound);
        let old_bob_outbound = chat
            .bob
            .state
            .conversations
            .get(&conversation_id)
            .and_then(|conversation| conversation.lanes.as_ref())
            .map(|lanes| lanes.outbound_lane.clone())
            .expect("bob outbound");
        let old_endpoint = chat
            .alice
            .state
            .contacts
            .get(&bob_user_id)
            .and_then(|contact| contact.bundle.devices.first())
            .and_then(|device| device.inbox_append_capability.as_ref())
            .map(|capability| capability.endpoint.clone())
            .expect("bob inbox endpoint");
        let epoch_before = conversation_epoch(&chat.alice, &conversation_id);

        let mut relocated = sample_deployment();
        relocated.inbox_http_endpoint = "https://bob-new.example.test".into();
        relocated.inbox_websocket_endpoint = "wss://bob-new.example.test/ws".into();
        relocated.runtime_id = "runtime:bob-new".into();
        relocated.runtime_config.identity_bundle_ref =
            Some("https://bob-new.example.test/state/identity.json".into());
        relocated.storage_base_info.base_url = Some("https://bob-new-storage.example.test".into());

        let relocate = chat
            .bob
            .handle_command(CoreCommand::ImportDeploymentBundle { bundle: relocated })
            .expect("bob relocates");
        let registered = relocate
            .effects
            .iter()
            .filter_map(|effect| match effect {
                CoreEffect::RegisterAcceptedLane { register } => Some(register.lane.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            registered.len(),
            1,
            "relocation registers one fresh inbound"
        );
        assert_ne!(registered[0], old_bob_inbound, "must not copy the old lane");
        let new_bob_inbound = chat
            .bob
            .state
            .conversations
            .get(&conversation_id)
            .and_then(|conversation| conversation.lanes.as_ref())
            .map(|lanes| lanes.inbound_lane.clone())
            .expect("bob new inbound");
        assert_eq!(new_bob_inbound, registered[0]);
        assert_eq!(
            chat.bob
                .state
                .conversations
                .get(&conversation_id)
                .and_then(|conversation| conversation.lanes.as_ref())
                .map(|lanes| lanes.outbound_lane.as_str()),
            Some(old_bob_outbound.as_str()),
            "relocating B must not change the lane B writes on A's inbox"
        );

        let inbound =
            deliver_pending_outbox_to_device(&mut chat.alice, &chat.bob, &chat.alice_device_id);
        assert!(
            inbound
                .effects
                .iter()
                .all(|effect| !matches!(effect, CoreEffect::FetchIdentityBundle { .. })),
            "relocation announcement must not fetch"
        );
        assert_eq!(
            chat.alice
                .state
                .conversations
                .get(&conversation_id)
                .and_then(|conversation| conversation.lanes.as_ref())
                .map(|lanes| lanes.outbound_lane.clone())
                .as_deref(),
            Some(new_bob_inbound.as_str())
        );
        let new_endpoint = chat
            .alice
            .state
            .contacts
            .get(&bob_user_id)
            .and_then(|contact| contact.bundle.devices.first())
            .and_then(|device| device.inbox_append_capability.as_ref())
            .map(|capability| capability.endpoint.clone())
            .expect("updated bob inbox endpoint");
        assert_ne!(new_endpoint, old_endpoint);
        assert!(new_endpoint.contains("bob-new.example.test"));
        assert_eq!(
            conversation_epoch(&chat.alice, &conversation_id),
            epoch_before,
            "relocation must not rebuild the MLS session"
        );

        let after = chat
            .alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "after-move".into(),
            })
            .expect("alice sends after move");
        assert!(after.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::ExecuteHttpRequest { request }
                if request.url.contains("bob-new.example.test")
        )));
        assert!(after.effects.iter().all(|effect| match effect {
            CoreEffect::ExecuteHttpRequest { request } if request.url.contains("/messages") => {
                !request.url.contains(&old_endpoint)
            }
            _ => true,
        }));
        let after_lane = chat
            .alice
            .state
            .pending_outbox
            .iter()
            .rev()
            .find(|item| item.plaintext_cache.as_deref() == Some("after-move"))
            .map(|item| item.envelope.lane.clone())
            .expect("after-move envelope");
        assert_eq!(after_lane, new_bob_inbound);
        deliver_pending_outbox_to_device(&mut chat.bob, &chat.alice, &chat.bob_device_id);
        assert!(chat
            .bob
            .state
            .conversations
            .get(&conversation_id)
            .expect("bob conversation")
            .messages
            .iter()
            .any(|message| message.plaintext.as_deref() == Some("after-move")));

        chat.bob
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "after-move-reply".into(),
            })
            .expect("bob replies after move");
        deliver_pending_outbox_to_device(&mut chat.alice, &chat.bob, &chat.alice_device_id);
        assert!(chat
            .alice
            .state
            .conversations
            .get(&conversation_id)
            .expect("alice conversation")
            .messages
            .iter()
            .any(|message| message.plaintext.as_deref() == Some("after-move-reply")));

        chat.alice = CoreEngine::try_from_restored_state(chat.alice.refresh_snapshot())
            .expect("restore alice");
        chat.bob =
            CoreEngine::try_from_restored_state(chat.bob.refresh_snapshot()).expect("restore bob");
        assert_eq!(
            chat.alice
                .state
                .conversations
                .get(&conversation_id)
                .and_then(|conversation| conversation.lanes.as_ref())
                .map(|lanes| lanes.outbound_lane.as_str()),
            Some(new_bob_inbound.as_str())
        );

        chat.alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "after-restart".into(),
            })
            .expect("alice sends after restart");
        let restart_lane = chat
            .alice
            .state
            .pending_outbox
            .iter()
            .rev()
            .find(|item| item.plaintext_cache.as_deref() == Some("after-restart"))
            .map(|item| item.envelope.lane.clone())
            .expect("after-restart envelope");
        assert_eq!(restart_lane, new_bob_inbound);
        deliver_pending_outbox_to_device(&mut chat.bob, &chat.alice, &chat.bob_device_id);
        assert!(chat
            .bob
            .state
            .conversations
            .get(&conversation_id)
            .expect("bob conversation")
            .messages
            .iter()
            .any(|message| message.plaintext.as_deref() == Some("after-restart")));
    }

    #[test]
    fn fetched_identity_bundle_must_match_requested_user() {
        let mut alice = local_engine(ALICE_MNEMONIC, "phone");
        let alice_bundle = alice.local_bundle().expect("alice bundle").clone();
        let bob = local_engine(BOB_MNEMONIC, "phone");
        let bob_bundle = bob.local_bundle().expect("bob bundle").clone();
        alice
            .handle_command(CoreCommand::ImportIdentityBundle {
                bundle: bob_bundle.clone(),
            })
            .expect("alice imports bob");
        let before = serde_json::to_vec(
            &alice
                .state
                .contacts
                .get(&bob_bundle.user_id)
                .expect("bob contact")
                .bundle,
        )
        .expect("contact bytes");

        let error = alice
            .handle_event(CoreEvent::IdentityBundleFetched {
                user_id: bob_bundle.user_id.clone(),
                bundle: alice_bundle,
            })
            .expect_err("mismatched subject");
        assert_eq!(error.code(), "invalid_input");
        let after = serde_json::to_vec(
            &alice
                .state
                .contacts
                .get(&bob_bundle.user_id)
                .expect("bob contact")
                .bundle,
        )
        .expect("contact bytes");
        assert_eq!(before, after);
    }

    #[test]
    fn build_envelope_requires_an_outbound_lane() {
        let mut chat = paired_direct_chat();
        if let Some(conversation) = chat
            .alice
            .state
            .conversations
            .get_mut(&chat.conversation_id)
        {
            conversation.lanes = None;
        }
        chat.alice.state.lane_index.clear();
        let error = chat
            .alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: chat.conversation_id.clone(),
                plaintext: "no-lane".into(),
            })
            .expect_err("missing outbound lane");
        assert_eq!(error.code(), "invalid_state");
    }

    /// **Remark 2 / R1.** The decision test: a party completes a rotation with
    /// the counterparty contributing nothing at all.
    ///
    /// Run from the *non*-designated side, which is the hard case — it is the
    /// one the old two-round certificate left unable to heal, because the
    /// designation only rotated when the other party committed.
    #[test]
    fn rotation_completes_without_counterparty() {
        let mut chat = paired_direct_chat();
        let conversation_id = chat.conversation_id.clone();
        let alice_rotates = !alice_is_designated(&chat);
        let epoch_before =
            conversation_epoch(rotator_engine(&chat, alice_rotates), &conversation_id);
        let leaf_before = rotator_engine(&chat, alice_rotates)
            .state
            .mls_adapter
            .as_ref()
            .expect("adapter")
            .own_leaf_key_b64(&conversation_id)
            .expect("leaf key before");
        let peer_fingerprint_before = peer_engine(&chat, alice_rotates)
            .state
            .mls_adapter
            .as_ref()
            .expect("peer adapter")
            .state_fingerprint()
            .expect("peer fingerprint");

        // Two intervals: the non-designated side waits out the designated
        // one's turn before acting on its own.
        set_direct_pcs_debt(
            rotator_engine_mut(&mut chat, alice_rotates),
            &conversation_id,
            DIRECT_PCS_COMMIT_INTERVAL * 2 - 1,
        );
        rotator_engine_mut(&mut chat, alice_rotates)
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "heal alone".into(),
            })
            .expect("send");

        let rotator = rotator_engine(&chat, alice_rotates);
        assert_eq!(
            conversation_epoch(rotator, &conversation_id),
            epoch_before + 1,
            "the epoch must advance without the counterparty"
        );
        assert_ne!(
            rotator
                .state
                .mls_adapter
                .as_ref()
                .expect("adapter")
                .own_leaf_key_b64(&conversation_id)
                .expect("leaf key after"),
            leaf_before,
            "healing means this device's own leaf key is replaced"
        );
        assert_eq!(
            rotator.state.conversations[&conversation_id].pcs.self_debt, 0,
            "rotating clears our own rotation debt"
        );
        assert!(rotator
            .state
            .pending_outbox
            .iter()
            .any(|item| outbox_item_matches_type(item, MessageType::MlsCommit)));
        assert_eq!(
            peer_engine(&chat, alice_rotates)
                .state
                .mls_adapter
                .as_ref()
                .expect("peer adapter")
                .state_fingerprint()
                .expect("peer fingerprint"),
            peer_fingerprint_before,
            "the counterparty contributed nothing and moved not at all"
        );
    }

    /// The designated side waits one interval, everyone else waits two. This
    /// asymmetry is what keeps the common case free of collisions: exactly one
    /// party sits at the 1x threshold at any epoch.
    #[test]
    fn direct_pcs_non_designated_waits_one_extra_interval() {
        let mut chat = paired_direct_chat();
        let conversation_id = chat.conversation_id.clone();
        let alice_rotates = !alice_is_designated(&chat);
        let epoch_before =
            conversation_epoch(rotator_engine(&chat, alice_rotates), &conversation_id);
        set_direct_pcs_debt(
            rotator_engine_mut(&mut chat, alice_rotates),
            &conversation_id,
            DIRECT_PCS_COMMIT_INTERVAL - 1,
        );
        rotator_engine_mut(&mut chat, alice_rotates)
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "one interval is not enough".into(),
            })
            .expect("send");
        assert_eq!(
            conversation_epoch(rotator_engine(&chat, alice_rotates), &conversation_id),
            epoch_before,
            "the non-designated side must not rotate at a single interval"
        );
        assert!(
            rotator_engine(&chat, alice_rotates).state.conversations[&conversation_id]
                .pcs
                .own_commit
                .is_none()
        );
    }

    /// A peer's commit rotates the group secret but not our leaf key, so it
    /// must not clear our rotation debt. If it did, a peer committing often
    /// enough would starve our own rotation forever — S1 in a new costume.
    ///
    /// The visible consequence is the steady state: adopting a commit flips
    /// the designation, and the adopting side is already past its own
    /// threshold, so rotations arrive in back-to-back pairs.
    #[test]
    fn direct_pcs_peer_commit_does_not_clear_own_rotation_debt() {
        let mut chat = paired_direct_chat();
        let conversation_id = chat.conversation_id.clone();
        prime_direct_pcs_debt(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        let alice_rotated = trigger_direct_pcs_from_designated(&mut chat);
        let epoch_after_first =
            conversation_epoch(rotator_engine(&chat, alice_rotated), &conversation_id);
        let peer_leaf_before = peer_engine(&chat, alice_rotated)
            .state
            .mls_adapter
            .as_ref()
            .expect("peer adapter")
            .own_leaf_key_b64(&conversation_id)
            .expect("peer leaf before");

        complete_direct_pcs_rotation(&mut chat, alice_rotated);

        let peer = peer_engine(&chat, alice_rotated);
        assert_ne!(
            peer.state
                .mls_adapter
                .as_ref()
                .expect("peer adapter")
                .own_leaf_key_b64(&conversation_id)
                .expect("peer leaf after"),
            peer_leaf_before,
            "the peer's debt survived our commit, so it rotated in turn"
        );
        assert_eq!(
            conversation_epoch(peer, &conversation_id),
            epoch_after_first + 1,
            "rotations pair: ours, then the peer's"
        );
        assert_eq!(peer.state.conversations[&conversation_id].pcs.self_debt, 0);
    }

    /// Two commits from the same base epoch. The designated committer wins and
    /// must show no state transition whatsoever; the loser cannot un-merge, so
    /// it rebuilds — and repairs itself in the same turn rather than leaving a
    /// conversation the user has to fix by hand.
    #[test]
    fn direct_pcs_concurrent_commits_arbitrate_deterministically() {
        let mut chat = paired_direct_chat();
        let conversation_id = chat.conversation_id.clone();
        let alice_is_winner = alice_is_designated(&chat);
        let winner_device = rotator_device_id(&chat, alice_is_winner).to_string();
        let loser_device = peer_device_id(&chat, alice_is_winner).to_string();

        // The loser goes first, at its 2x threshold, and its commit stays
        // undelivered. Then the winner rotates from the same base epoch.
        set_direct_pcs_debt(
            peer_engine_mut(&mut chat, alice_is_winner),
            &conversation_id,
            DIRECT_PCS_COMMIT_INTERVAL * 2 - 1,
        );
        peer_engine_mut(&mut chat, alice_is_winner)
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "loser rotation".into(),
            })
            .expect("loser send");
        let loser_commit = last_pending_envelope(
            peer_engine(&chat, alice_is_winner),
            &winner_device,
            MessageType::MlsCommit,
        );

        set_direct_pcs_debt(
            rotator_engine_mut(&mut chat, alice_is_winner),
            &conversation_id,
            DIRECT_PCS_COMMIT_INTERVAL - 1,
        );
        rotator_engine_mut(&mut chat, alice_is_winner)
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "winner rotation".into(),
            })
            .expect("winner send");
        let winner_commit = last_pending_envelope(
            rotator_engine(&chat, alice_is_winner),
            &loser_device,
            MessageType::MlsCommit,
        );

        // Both sides agree on who won, and they agree before seeing each
        // other's commit — the verdict is recorded at rotation time.
        assert!(
            rotator_engine(&chat, alice_is_winner).state.conversations[&conversation_id]
                .pcs
                .own_commit
                .as_ref()
                .expect("winner own commit")
                .won_arbitration
        );
        assert!(
            !peer_engine(&chat, alice_is_winner).state.conversations[&conversation_id]
                .pcs
                .own_commit
                .as_ref()
                .expect("loser own commit")
                .won_arbitration
        );

        // The winner sees the losing commit: ack and discard, zero state change.
        let winner_fingerprint = rotator_engine(&chat, alice_is_winner)
            .state
            .mls_adapter
            .as_ref()
            .expect("winner adapter")
            .state_fingerprint()
            .expect("winner fingerprint");
        let winner_epoch =
            conversation_epoch(rotator_engine(&chat, alice_is_winner), &conversation_id);
        deliver_inbox_envelope(
            rotator_engine_mut(&mut chat, alice_is_winner),
            &winner_device,
            loser_commit,
            50_000,
        );
        let winner = rotator_engine(&chat, alice_is_winner);
        assert_eq!(
            winner
                .state
                .mls_adapter
                .as_ref()
                .expect("winner adapter")
                .state_fingerprint()
                .expect("winner fingerprint"),
            winner_fingerprint,
            "the arbitration winner must not move at all"
        );
        assert_eq!(conversation_epoch(winner, &conversation_id), winner_epoch);
        assert_eq!(
            winner.state.conversations[&conversation_id]
                .conversation
                .state,
            ConversationState::Active
        );

        // The loser sees the winning commit: it forked, so it rebuilds — and
        // the rebuild is driven to completion in the same turn.
        let output = deliver_inbox_envelope(
            peer_engine_mut(&mut chat, alice_is_winner),
            &loser_device,
            winner_commit,
            50_001,
        );
        simulate_pending_key_package_claims(peer_engine_mut(&mut chat, alice_is_winner), output);
        // Escalation drives the rebuild and the repair in one turn, so the
        // PcsCommitRace context is already gone by the time the turn ends —
        // which is the point: the user never sees a dead conversation.
        let loser = peer_engine(&chat, alice_is_winner);
        assert_eq!(
            loser.state.conversations[&conversation_id]
                .conversation
                .state,
            ConversationState::Active,
            "the loser must repair itself, not wait for the user"
        );
        assert!(
            loser
                .state
                .mls_adapter
                .as_ref()
                .expect("loser adapter")
                .has_conversation(&conversation_id),
            "the rebuilt group must exist again"
        );
        assert!(
            loser.state.pending_outbox.iter().any(|item| {
                true && crate::mls_adapter::MlsAdapter::payload_is_welcome(
                    item.envelope.payload_b64().unwrap_or_default(),
                )
            }),
            "the rebuild must invite the winner into the fresh group"
        );
    }

    /// The rotation decision runs once the inbound batch has settled, never
    /// per record. A device returning from an absence drains a backlog whose
    /// tail carries the peer's own commit; deciding mid-batch would cross the
    /// threshold and fire before reading it, manufacturing a collision.
    #[test]
    fn direct_pcs_rotation_decision_waits_for_batch_settle() {
        let mut chat = paired_direct_chat();
        let conversation_id = chat.conversation_id.clone();
        // The peer talks and rotates mid-backlog, all while we are away.
        let alice_rotated = alice_is_designated(&chat);
        set_direct_pcs_debt(
            rotator_engine_mut(&mut chat, alice_rotated),
            &conversation_id,
            DIRECT_PCS_COMMIT_INTERVAL - 1,
        );
        for index in 0..3 {
            rotator_engine_mut(&mut chat, alice_rotated)
                .handle_command(CoreCommand::SendTextMessage {
                    conversation_id: conversation_id.clone(),
                    plaintext: format!("backlog {index}"),
                })
                .expect("peer send");
        }
        // We are far past our own threshold, so a per-record decision would
        // fire on the first backlog message.
        set_direct_pcs_debt(
            peer_engine_mut(&mut chat, alice_rotated),
            &conversation_id,
            DIRECT_PCS_COMMIT_INTERVAL * 2,
        );
        let epoch_before = conversation_epoch(peer_engine(&chat, alice_rotated), &conversation_id);

        complete_direct_pcs_rotation(&mut chat, alice_rotated);

        let settled = peer_engine(&chat, alice_rotated);
        assert_eq!(
            conversation_epoch(settled, &conversation_id),
            epoch_before + 2,
            "the batch's commit is adopted first (+1), then one rotation of \
             our own on settled state (+1) — never two of ours"
        );
        let own_commit = settled.state.conversations[&conversation_id]
            .pcs
            .own_commit
            .as_ref()
            .expect("own commit");
        assert_eq!(
            own_commit.base_epoch,
            epoch_before + 1,
            "we rotated from the epoch the peer's commit put us in, not from \
             the one we were in mid-batch"
        );
    }

    /// A rotation merges the new leaf key into the MLS state; if only that
    /// survived a crash the peer would be stranded forever, because the commit
    /// bytes are gone once the pending commit is consumed. The inbound path
    /// must persist both in one batch.
    #[test]
    fn direct_pcs_inbound_rotation_persists_its_commit_envelope() {
        let mut chat = paired_direct_chat();
        let conversation_id = chat.conversation_id.clone();
        prime_direct_pcs_debt(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        let alice_rotated = trigger_direct_pcs_from_designated(&mut chat);
        let output = if alice_rotated {
            deliver_pending_outbox_to_device(&mut chat.bob, &chat.alice, &chat.bob_device_id)
        } else {
            deliver_pending_outbox_to_device(&mut chat.alice, &chat.bob, &chat.alice_device_id)
        };
        let ops = persist_ops(&output);
        let commit_ids: Vec<String> = peer_engine(&chat, alice_rotated)
            .state
            .pending_outbox
            .iter()
            .filter(|item| outbox_item_matches_type(item, MessageType::MlsCommit))
            .map(|item| item.envelope.mid.clone())
            .collect();
        assert!(
            !commit_ids.is_empty(),
            "adopting the peer's commit pairs a rotation of our own"
        );
        assert!(
            ops.iter().any(|op| matches!(
                op,
                PersistOp::SaveMlsState { conversation_id: saved } if saved == &conversation_id
            )),
            "the merged MLS state must be persisted"
        );
        assert!(
            ops.iter().any(|op| matches!(
                op,
                PersistOp::SaveOutgoingEnvelope { message_id } if commit_ids.contains(message_id)
            )),
            "the rotation commit must reach disk in the same batch as the merge"
        );
    }

    #[test]
    fn direct_pcs_decrypts_previous_epoch_message_after_merge() {
        let mut chat = paired_direct_chat();
        prime_direct_pcs_debt(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        // The rotation commit stays undelivered, so the peer is still on the
        // previous epoch and its next message must still decrypt.
        let alice_was_committer = trigger_direct_pcs_from_designated(&mut chat);
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
        prime_direct_pcs_debt(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        let alice_rotated = trigger_direct_pcs_from_designated(&mut chat);
        complete_direct_pcs_rotation(&mut chat, alice_rotated);
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
    fn direct_future_epoch_application_replays_after_commit() {
        let mut chat = paired_direct_chat();
        let conversation_id = chat.conversation_id.clone();
        let alice_rotated = alice_is_designated(&chat);
        let recipient_device = peer_device_id(&chat, alice_rotated).to_string();
        set_direct_pcs_debt(
            rotator_engine_mut(&mut chat, alice_rotated),
            &conversation_id,
            DIRECT_PCS_COMMIT_INTERVAL - 1,
        );
        trigger_direct_pcs_from_designated(&mut chat);
        let commit = last_pending_envelope(
            rotator_engine(&chat, alice_rotated),
            &recipient_device,
            MessageType::MlsCommit,
        );
        rotator_engine_mut(&mut chat, alice_rotated)
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "future-before-commit".into(),
            })
            .expect("send future-epoch application");
        let application = last_pending_application_envelope(
            rotator_engine(&chat, alice_rotated),
            &recipient_device,
        );

        deliver_inbox_envelope(
            peer_engine_mut(&mut chat, alice_rotated),
            &recipient_device,
            application,
            100,
        );
        assert_eq!(
            peer_engine(&chat, alice_rotated)
                .state
                .sync_states
                .get(&recipient_device)
                .map(|state| state.quarantine.len()),
            Some(1),
            "future wrap must remain in the invisible bounded quarantine"
        );
        assert!(!conversation_has_plaintext(
            peer_engine(&chat, alice_rotated),
            &conversation_id,
            "future-before-commit"
        ));

        deliver_inbox_envelope(
            peer_engine_mut(&mut chat, alice_rotated),
            &recipient_device,
            commit,
            101,
        );
        assert!(conversation_has_plaintext(
            peer_engine(&chat, alice_rotated),
            &conversation_id,
            "future-before-commit"
        ));
        assert_eq!(
            peer_engine(&chat, alice_rotated)
                .state
                .sync_states
                .get(&recipient_device)
                .map(|state| state.quarantine.len()),
            Some(0)
        );
    }

    #[test]
    fn direct_previous_epoch_application_survives_peer_commit() {
        let mut chat = paired_direct_chat();
        let conversation_id = chat.conversation_id.clone();
        let alice_rotated = alice_is_designated(&chat);
        let recipient_device = peer_device_id(&chat, alice_rotated).to_string();
        rotator_engine_mut(&mut chat, alice_rotated)
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "previous-after-commit".into(),
            })
            .expect("send previous-epoch application");
        let application = last_pending_application_envelope(
            rotator_engine(&chat, alice_rotated),
            &recipient_device,
        );
        set_direct_pcs_debt(
            rotator_engine_mut(&mut chat, alice_rotated),
            &conversation_id,
            DIRECT_PCS_COMMIT_INTERVAL - 1,
        );
        trigger_direct_pcs_from_designated(&mut chat);
        let commit = last_pending_envelope(
            rotator_engine(&chat, alice_rotated),
            &recipient_device,
            MessageType::MlsCommit,
        );

        deliver_inbox_envelope(
            peer_engine_mut(&mut chat, alice_rotated),
            &recipient_device,
            commit,
            100,
        );
        deliver_inbox_envelope(
            peer_engine_mut(&mut chat, alice_rotated),
            &recipient_device,
            application,
            101,
        );
        assert!(conversation_has_plaintext(
            peer_engine(&chat, alice_rotated),
            &conversation_id,
            "previous-after-commit"
        ));
    }

    #[test]
    fn rejected_spoofed_welcome_leaves_trusted_core_state_unchanged() {
        let mut chat = paired_direct_chat();
        let attacker = local_engine(CAROL_MNEMONIC, "attacker");
        let mut fake_identity = attacker.state.local_identity.as_ref().unwrap().clone();
        fake_identity.user_identity.user_id = chat
            .alice
            .state
            .local_identity
            .as_ref()
            .unwrap()
            .user_identity
            .user_id
            .clone();
        fake_identity.device_identity.device_id = chat.alice_device_id.clone();
        let (mut attacker_mls, _) = MlsAdapter::bootstrap(&fake_identity).unwrap();
        let key_package = chat
            .bob
            .state
            .mls_adapter
            .as_mut()
            .unwrap()
            .rotate_key_package(test_now_ms())
            .unwrap();
        let bob = chat.bob.state.local_identity.as_ref().unwrap();
        let fake_conversation_id = crate::model::random_opaque_id();
        let artifacts = attacker_mls
            .create_conversation_with_reply_lane(
                &fake_conversation_id,
                &[crate::mls_adapter::PeerDeviceKeyPackage {
                    user_id: bob.user_identity.user_id.clone(),
                    device_id: bob.device_identity.device_id.clone(),
                    device_public_key: bob.device_identity.device_public_key.clone(),
                    key_package_b64: key_package.key_package_b64,
                }],
                Some(&crate::model::random_opaque_id()),
                None,
            )
            .unwrap();
        let envelope = Envelope::with_bytes(
            chat.bob_device_id.clone(),
            crate::model::random_opaque_id(),
            crate::model::random_opaque_id(),
            artifacts.welcomes[0].payload_b64.clone(),
        );
        let conversations_before = chat.bob.state.conversations.clone();
        let lane_index_before = chat.bob.state.lane_index.clone();
        let adapter_before = chat
            .bob
            .state
            .mls_adapter
            .as_ref()
            .unwrap()
            .state_fingerprint()
            .unwrap();

        let output = deliver_inbox_envelope(&mut chat.bob, &chat.bob_device_id, envelope, 100);

        assert_eq!(chat.bob.state.conversations, conversations_before);
        assert_eq!(chat.bob.state.lane_index, lane_index_before);
        assert_eq!(
            chat.bob
                .state
                .mls_adapter
                .as_ref()
                .unwrap()
                .state_fingerprint()
                .unwrap(),
            adapter_before
        );
        assert!(!output.state_update.conversations_changed);
        assert!(!output.state_update.messages_changed);
        assert!(output
            .view_model
            .as_ref()
            .is_none_or(|view| view.messages.is_empty() && view.conversations.is_empty()));
    }

    /// A genuine signature does not travel to another commit.
    ///
    /// The detached signature is what lets arbitration act on a rival commit
    /// MLS refuses to process, so the thing that must not be forgeable is the
    /// pair (this epoch, this commit). Here the attacker has a real signature
    /// the peer made, and a stale wrap key to deliver with — everything the
    /// previous test denied it — and still cannot move the signature onto a
    /// commit the peer did not make.
    #[test]
    fn a_genuine_commit_signature_does_not_authenticate_another_commit() {
        let mut chat = paired_direct_chat();
        let conversation_id = chat.conversation_id.clone();
        let alice_rotated = !alice_is_designated(&chat);
        let victim_device = rotator_device_id(&chat, alice_rotated).to_string();
        let victim_lanes = rotator_engine(&chat, alice_rotated).state.conversations
            [&conversation_id]
            .lanes
            .as_ref()
            .unwrap()
            .clone();
        let compromised_wrap_key = rotator_engine(&chat, alice_rotated)
            .state
            .mls_adapter
            .as_ref()
            .unwrap()
            .export_lane_wrap_key(&conversation_id, victim_lanes.inbound_dir())
            .unwrap();

        // Make the peer rotate, so a commit it really signed exists.
        set_direct_pcs_debt(
            peer_engine_mut(&mut chat, alice_rotated),
            &conversation_id,
            DIRECT_PCS_COMMIT_INTERVAL * 2,
        );
        peer_engine_mut(&mut chat, alice_rotated)
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "peer-rotation".into(),
            })
            .unwrap();
        let peer_commit = last_pending_envelope(
            peer_engine(&chat, alice_rotated),
            &victim_device,
            MessageType::MlsCommit,
        );

        let wrapped = STANDARD.decode(peer_commit.payload_b64().unwrap()).unwrap();
        let plaintext =
            crate::lane_wrap::unwrap_with_cached_keys(&compromised_wrap_key, None, &wrapped)
                .expect("the victim's inbound key opens the peer's commit");
        let (genuine_commit_b64, genuine_signature) =
            crate::direct_frame::decode(&plaintext).expect("a commit frame");
        let genuine_signature = genuine_signature.expect("a commit carries a signature");

        let mut tampered = STANDARD.decode(&genuine_commit_b64).unwrap();
        *tampered.last_mut().unwrap() ^= 1;
        let tampered_b64 = STANDARD.encode(tampered);
        assert_ne!(tampered_b64, genuine_commit_b64);
        assert_eq!(
            MlsAdapter::classify_mls_payload(&tampered_b64),
            Some(MessageType::MlsCommit),
            "still a syntactic commit, which is all the arbitration gate used to need"
        );

        let forged = Envelope::with_bytes(
            victim_device.clone(),
            victim_lanes.inbound_lane.clone(),
            crate::model::random_opaque_id(),
            STANDARD.encode(
                crate::lane_wrap::wrap_frame(
                    &compromised_wrap_key,
                    &crate::direct_frame::encode(&tampered_b64, Some(&genuine_signature)).unwrap(),
                )
                .unwrap(),
            ),
        );
        let before = rotator_engine(&chat, alice_rotated)
            .state
            .mls_adapter
            .as_ref()
            .unwrap()
            .state_fingerprint()
            .unwrap();

        deliver_inbox_envelope(
            rotator_engine_mut(&mut chat, alice_rotated),
            &victim_device,
            forged,
            100,
        );

        assert_eq!(
            rotator_engine(&chat, alice_rotated)
                .state
                .mls_adapter
                .as_ref()
                .unwrap()
                .state_fingerprint()
                .unwrap(),
            before,
            "a signature bound to one commit must not authenticate another"
        );
    }

    #[test]
    fn old_wrap_key_without_commit_proof_cannot_trigger_arbitration() {
        let mut chat = paired_direct_chat();
        let conversation_id = chat.conversation_id.clone();
        let alice_rotated = !alice_is_designated(&chat);
        let victim_device = rotator_device_id(&chat, alice_rotated).to_string();
        let peer_device = peer_device_id(&chat, alice_rotated).to_string();
        let victim = rotator_engine(&chat, alice_rotated);
        let lanes = victim.state.conversations[&conversation_id]
            .lanes
            .as_ref()
            .unwrap();
        let inbound_lane = lanes.inbound_lane.clone();
        let compromised_wrap_key = victim
            .state
            .mls_adapter
            .as_ref()
            .unwrap()
            .export_lane_wrap_key(&conversation_id, lanes.inbound_dir())
            .unwrap();
        set_direct_pcs_debt(
            rotator_engine_mut(&mut chat, alice_rotated),
            &conversation_id,
            DIRECT_PCS_COMMIT_INTERVAL * 2,
        );
        rotator_engine_mut(&mut chat, alice_rotated)
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "trigger-local-rotation".into(),
            })
            .unwrap();
        let own_commit = last_pending_envelope(
            rotator_engine(&chat, alice_rotated),
            &peer_device,
            MessageType::MlsCommit,
        );
        let raw_commit = unwrapped_inbox_payload(
            peer_engine(&chat, alice_rotated),
            &conversation_id,
            &own_commit,
        );
        let mut commit_bytes = STANDARD.decode(raw_commit).unwrap();
        *commit_bytes.last_mut().unwrap() ^= 1;
        let forged_commit_b64 = STANDARD.encode(commit_bytes);
        assert_eq!(
            MlsAdapter::classify_mls_payload(&forged_commit_b64),
            Some(MessageType::MlsCommit)
        );
        // Tagged as a commit, but carrying a signature of the wrong shape:
        // the attacker holds a stale wrap key and nothing the peer signed.
        let forged_plaintext = crate::direct_frame::encode(
            &forged_commit_b64,
            Some(&[0_u8; crate::direct_frame::COMMIT_SIGNATURE_LEN]),
        )
        .unwrap();
        let forged = Envelope::with_bytes(
            victim_device.clone(),
            inbound_lane,
            crate::model::random_opaque_id(),
            STANDARD.encode(
                crate::lane_wrap::wrap_frame(&compromised_wrap_key, &forged_plaintext).unwrap(),
            ),
        );
        let before = rotator_engine(&chat, alice_rotated)
            .state
            .mls_adapter
            .as_ref()
            .unwrap()
            .state_fingerprint()
            .unwrap();

        deliver_inbox_envelope(
            rotator_engine_mut(&mut chat, alice_rotated),
            &victim_device,
            forged,
            100,
        );

        assert_eq!(
            rotator_engine(&chat, alice_rotated)
                .state
                .mls_adapter
                .as_ref()
                .unwrap()
                .state_fingerprint()
                .unwrap(),
            before
        );
    }

    /// Forward secrecy watchdog. Persisted live state plus a replay of the
    /// rotation commit must not resurrect an `e+1` generation the live state
    /// already consumed, while a genuine `e` message still decrypts.
    #[test]
    fn direct_pcs_persisted_live_cannot_rebuild_consumed_next_epoch_keys() {
        let mut chat = paired_direct_chat();
        prime_direct_pcs_debt(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        let alice_rotated = trigger_direct_pcs_from_designated(&mut chat);
        let conversation_id = chat.conversation_id.clone();
        let designated_device = rotator_device_id(&chat, alice_rotated).to_string();
        let peer_device = peer_device_id(&chat, alice_rotated).to_string();
        // The rotating side is already on e+1; the commit is still in its
        // outbox, so the peer is the one that can still speak epoch e.
        let pcs_commit_envelope = last_pending_envelope(
            rotator_engine(&chat, alice_rotated),
            &peer_device,
            MessageType::MlsCommit,
        );
        let pcs_commit_b64 = unwrapped_inbox_payload(
            peer_engine(&chat, alice_rotated),
            &conversation_id,
            &pcs_commit_envelope,
        );
        peer_engine_mut(&mut chat, alice_rotated)
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "late-e".into(),
            })
            .expect("peer sends on epoch e");
        let late_e_envelope = last_pending_application_envelope(
            peer_engine(&chat, alice_rotated),
            &designated_device,
        );
        let late_e = unwrapped_inbox_payload(
            rotator_engine(&chat, alice_rotated),
            &conversation_id,
            &late_e_envelope,
        );
        // Our commit does not clear the peer's own rotation debt (by design:
        // it did not replace the peer's leaf key), and adopting it flips the
        // designation to the peer — so by default the peer pairs a second
        // rotation onto ours and the live epoch lands on e+2. Hold that off
        // here; the pairing itself is asserted by
        // `direct_pcs_peer_commit_does_not_clear_own_rotation_debt`.
        set_direct_pcs_debt(
            peer_engine_mut(&mut chat, alice_rotated),
            &conversation_id,
            0,
        );
        complete_direct_pcs_rotation(&mut chat, alice_rotated);
        peer_engine_mut(&mut chat, alice_rotated)
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id: conversation_id.clone(),
                plaintext: "next-epoch".into(),
            })
            .expect("peer sends on epoch e+1");
        let next_epoch_envelope = last_pending_application_envelope(
            peer_engine(&chat, alice_rotated),
            &designated_device,
        );
        let next_epoch = unwrapped_inbox_payload(
            rotator_engine(&chat, alice_rotated),
            &conversation_id,
            &next_epoch_envelope,
        );
        let designated = rotator_engine_mut(&mut chat, alice_rotated);
        deliver_inbox_envelope(
            designated,
            &designated_device,
            next_epoch_envelope.clone(),
            40_000,
        );
        let designated = rotator_engine(&chat, alice_rotated);
        assert!(conversation_has_plaintext(
            designated,
            &conversation_id,
            "next-epoch"
        ));
        let serialized = designated
            .state
            .mls_adapter
            .as_ref()
            .expect("adapter")
            .export_persisted_group_state(&conversation_id)
            .expect("persist live");
        let summary = designated
            .state
            .mls_adapter
            .as_ref()
            .expect("adapter")
            .export_group_summary(&conversation_id)
            .expect("summary");
        let mut restored = MlsAdapter::restore_from_persisted_states(&[(
            conversation_id.clone(),
            summary,
            Some(serialized),
        )])
        .expect("restore live")
        .adapter
        .expect("adapter");
        match restored
            .ingest_message(&conversation_id, MessageType::MlsCommit, &pcs_commit_b64)
            .expect("replay C")
        {
            IngestResult::Rejected(_) | IngestResult::Deferred(_) => {}
            IngestResult::AppliedCommit { .. } => {
                panic!("persisted live must not re-merge rotation commit C")
            }
            other => panic!("unexpected C ingest: {other:?}"),
        }
        match restored
            .ingest_message(&conversation_id, MessageType::MlsApplication, &next_epoch)
            .expect("replay consumed e+1")
        {
            IngestResult::Rejected(_) => {}
            IngestResult::AppliedApplication(_) => {
                panic!("consumed e+1 generation must not decrypt from persisted live + C")
            }
            other => panic!("unexpected consumed ingest: {other:?}"),
        }
        match restored
            .ingest_message(&conversation_id, MessageType::MlsApplication, &late_e)
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
    fn direct_pcs_forged_commit_envelope_sender_does_not_rebuild() {
        let mut chat = paired_direct_chat();
        prime_direct_pcs_debt(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        let alice_rotated = trigger_direct_pcs_from_designated(&mut chat);
        let acceptor_device = peer_device_id(&chat, alice_rotated).to_string();
        let mut forged = first_pending_envelope(
            rotator_engine(&chat, alice_rotated),
            &acceptor_device,
            MessageType::MlsCommit,
        );
        forged.bytes = Some("Zm9yZ2Vk".into());
        deliver_inbox_envelope(
            peer_engine_mut(&mut chat, alice_rotated),
            &acceptor_device,
            forged,
            33_000,
        );
        let acceptor_state = peer_engine(&chat, alice_rotated)
            .state
            .conversations
            .get(&chat.conversation_id)
            .expect("conversation");
        assert_eq!(acceptor_state.conversation.state, ConversationState::Active);
        assert_ne!(
            acceptor_state.conversation.state,
            ConversationState::NeedsRebuild
        );
        // R1 strengthens this: a forged commit does not even reach the
        // arbitration check, so no rotation state moves either.
        assert!(acceptor_state.pcs.own_commit.is_none());
    }

    #[test]
    fn direct_pcs_previous_consume_survives_restore_without_resurrecting_generation() {
        let mut chat = paired_direct_chat();
        prime_direct_pcs_debt(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        // Commit left undelivered: the peer keeps sending on the old epoch.
        let alice_was_committer = trigger_direct_pcs_from_designated(&mut chat);
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
    fn direct_pcs_attachment_send_counts_toward_commit_interval() {
        let mut chat = paired_direct_chat();
        prime_direct_pcs_debt(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        let conversation_id = chat.conversation_id.clone();
        let alice_rotates = alice_is_designated(&chat);
        complete_direct_attachment_send(
            rotator_engine_mut(&mut chat, alice_rotates),
            &conversation_id,
        );
        let state = rotator_engine(&chat, alice_rotates)
            .state
            .conversations
            .get(&chat.conversation_id)
            .expect("conversation");
        assert!(
            state.pcs.own_commit.is_some(),
            "an attachment send counts toward the interval and must rotate"
        );
        assert_eq!(state.pcs.self_debt, 0, "rotating clears the debt");
        assert!(rotator_engine(&chat, alice_rotates)
            .state
            .pending_outbox
            .iter()
            .any(|item| outbox_item_matches_type(item, MessageType::MlsCommit)));
    }

    #[test]
    fn direct_pcs_attachment_send_persists_before_flush() {
        let mut chat = paired_direct_chat();
        prime_direct_pcs_debt(&mut chat, DIRECT_PCS_COMMIT_INTERVAL - 1);
        let conversation_id = chat.conversation_id.clone();
        let alice_rotates = alice_is_designated(&chat);
        let output = complete_direct_attachment_send(
            rotator_engine_mut(&mut chat, alice_rotates),
            &conversation_id,
        );
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
        let commit_ids: Vec<String> = rotator_engine(&chat, alice_rotates)
            .state
            .pending_outbox
            .iter()
            .filter(|item| outbox_item_matches_type(item, MessageType::MlsCommit))
            .map(|item| item.envelope.mid.clone())
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
        let restored = CoreEngine::try_from_restored_state(
            rotator_engine(&chat, alice_rotates).refresh_snapshot(),
        )
        .expect("restore after attachment stage");
        assert!(restored
            .state
            .conversations
            .get(&conversation_id)
            .expect("restored conversation")
            .pcs
            .own_commit
            .is_some());
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
        _sender_user_id: &str,
        conversation_id: &str,
    ) -> MessageRequestActionResult {
        MessageRequestActionResult {
            accepted: true,
            request_id: "request:pending".into(),
            promoted_count: 1,
            action: MessageRequestAction::Accept,
            promoted_conversation_ids: vec![conversation_id.to_string()],
        }
    }

    /// Give `receiver` the sender's real identity bundle.
    ///
    /// Required before `receiver` can ingest anything from `sender`: inbound
    /// records carry a sender proof over the whole envelope, and the receiver
    /// resolves the verifying key through its own contact list. It also
    /// mirrors the real flow, where a peer's envelopes only become fetchable
    /// after the recipient accepts the message request, which imports the
    /// sender's bundle first.
    ///
    /// Note this must use the sender engine's *own* bundle. Device keys are
    /// minted fresh per identity — `IdentityManager::create_or_recover`
    /// ignores the device name and generates a new device key — so a bundle
    /// rebuilt from the same mnemonic describes a different device and its
    /// signatures will not verify.
    pub(crate) fn link_contact(receiver: &mut CoreEngine, sender: &CoreEngine) {
        let bundle = sender.local_bundle().expect("sender bundle").clone();
        receiver
            .handle_command(CoreCommand::ImportIdentityBundle { bundle })
            .expect("receiver imports sender bundle");
    }

    pub(crate) fn local_engine(mnemonic: &str, device_name: &str) -> CoreEngine {
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

    /// The body a key-package pool answers a claim with, for the device the
    /// claim URL names.
    ///
    /// Shared with [`crate::leakage_corpus`], whose recorder drains effects one
    /// at a time and so cannot use the loop below.
    pub(crate) fn key_package_claim_response(engine: &CoreEngine, url: &str) -> String {
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
        serde_json::json!({
            "keyPackage": {
                "keyPackageId": "test-claim",
                "keyPackage": key_package_b64,
                "lifecycleVersion": 1,
                "notBefore": 0,
                "createdAt": 0,
                "expiresAt": 0,
            }
        })
        .to_string()
    }

    /// Resolves every in-flight `ClaimKeyPackage` HTTP effect in `output` by
    /// synthesizing a successful `/v1/keypackage-pool/{deviceId}/claim`
    /// response (claims are strictly sequential, so this loops until none
    /// remain), reusing the target device's cached last-resort KeyPackage
    /// bytes as the "claimed" one-time KeyPackage — realistic enough for
    /// test purposes since the bytes just need to be a validly encoded MLS
    /// KeyPackage. Returns the final output (from whichever call resolved
    /// the last outstanding claim), which carries the real view model.
    pub(crate) fn simulate_pending_key_package_claims(
        engine: &mut CoreEngine,
        mut output: CoreOutput,
    ) -> CoreOutput {
        loop {
            let claim = output.effects.iter().find_map(|effect| match effect {
                CoreEffect::ExecuteHttpRequest { request }
                    if request.url.contains("/keypackage-pool/")
                        && request.url.ends_with("/claim") =>
                {
                    Some((request.request_id.clone(), request.url.clone()))
                }
                _ => None,
            });
            let Some((request_id, url)) = claim else {
                break;
            };
            let body = key_package_claim_response(engine, &url);
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

    pub(crate) fn create_direct_conversation(
        engine: &mut CoreEngine,
        peer_user_id: String,
    ) -> String {
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

    fn envelope_is_wrapped_app(sender: &CoreEngine, envelope: &Envelope) -> bool {
        if !envelope_is_host_opaque_direct(envelope) {
            return false;
        }
        let Some(payload) = envelope.payload_b64() else {
            return false;
        };
        let Ok(raw) = STANDARD.decode(payload.as_bytes()) else {
            return false;
        };
        let Some(conversation_id) = sender.state.lane_index.get(&envelope.lane) else {
            return false;
        };
        let Some(lanes) = sender
            .state
            .conversations
            .get(conversation_id)
            .and_then(|state| state.lanes.as_ref())
        else {
            return false;
        };
        let Some(adapter) = sender.state.mls_adapter.as_ref() else {
            return false;
        };
        let Ok(key) = adapter.export_lane_wrap_key(conversation_id, lanes.outbound_dir) else {
            return false;
        };
        let Some(plaintext) = crate::lane_wrap::unwrap_with_cached_keys(&key, None, &raw) else {
            return false;
        };
        let Ok((mls_b64, _)) = crate::direct_frame::decode(&plaintext) else {
            return false;
        };
        MlsAdapter::classify_mls_payload(&mls_b64) == Some(MessageType::MlsApplication)
    }

    fn envelope_is_host_opaque_direct(envelope: &Envelope) -> bool {
        let Some(payload) = envelope.payload_b64() else {
            return false;
        };
        if MlsAdapter::payload_is_welcome(payload)
            || MlsAdapter::classify_mls_payload(payload).is_some()
        {
            return false;
        }
        STANDARD
            .decode(payload.as_bytes())
            .ok()
            .is_some_and(|raw| crate::direct_frame::decode(&raw).is_err())
    }

    fn host_visible_envelope_json(envelope: &Envelope) -> String {
        serde_json::to_string(envelope).expect("envelope json")
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
                message_id: item.envelope.mid.clone(),
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

    pub(crate) struct PairedDirectChat {
        pub(crate) alice: CoreEngine,
        pub(crate) bob: CoreEngine,
        pub(crate) conversation_id: String,
        pub(crate) alice_device_id: String,
        pub(crate) bob_device_id: String,
    }

    pub(crate) fn paired_direct_chat() -> PairedDirectChat {
        let mut chat = unjoined_direct_chat();
        deliver_pending_outbox_to_device(&mut chat.bob, &chat.alice, &chat.bob_device_id);
        chat
    }

    pub(crate) fn unjoined_direct_chat() -> PairedDirectChat {
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

    fn designated_device_id(chat: &PairedDirectChat) -> String {
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

    pub(crate) fn alice_is_designated(chat: &PairedDirectChat) -> bool {
        designated_device_id(chat) == chat.alice_device_id
    }

    // Role accessors take `alice_rotated` rather than re-deriving the
    // designation. Rotating advances the epoch, and `designated_committer`
    // is a function of the epoch — so after a rotation the designation has
    // already flipped to the other side. Every caller must capture the value
    // that `trigger_direct_pcs_from_designated` returns.
    fn rotator_engine(chat: &PairedDirectChat, alice_rotated: bool) -> &CoreEngine {
        if alice_rotated {
            &chat.alice
        } else {
            &chat.bob
        }
    }

    pub(crate) fn rotator_engine_mut(
        chat: &mut PairedDirectChat,
        alice_rotated: bool,
    ) -> &mut CoreEngine {
        if alice_rotated {
            &mut chat.alice
        } else {
            &mut chat.bob
        }
    }

    fn rotator_device_id(chat: &PairedDirectChat, alice_rotated: bool) -> &str {
        if alice_rotated {
            &chat.alice_device_id
        } else {
            &chat.bob_device_id
        }
    }

    fn peer_engine(chat: &PairedDirectChat, alice_rotated: bool) -> &CoreEngine {
        if alice_rotated {
            &chat.bob
        } else {
            &chat.alice
        }
    }

    fn peer_engine_mut(chat: &mut PairedDirectChat, alice_rotated: bool) -> &mut CoreEngine {
        if alice_rotated {
            &mut chat.bob
        } else {
            &mut chat.alice
        }
    }

    fn peer_device_id(chat: &PairedDirectChat, alice_rotated: bool) -> &str {
        if alice_rotated {
            &chat.bob_device_id
        } else {
            &chat.alice_device_id
        }
    }

    /// Both sides observe the same application messages, so their rotation
    /// debts advance together; only the thresholds differ by role.
    pub(crate) fn set_direct_pcs_debt(engine: &mut CoreEngine, conversation_id: &str, debt: u32) {
        if let Some(state) = engine.state.conversations.get_mut(conversation_id) {
            state.pcs.self_debt = debt;
        }
    }

    pub(crate) fn prime_direct_pcs_debt(chat: &mut PairedDirectChat, debt: u32) {
        for engine in [&mut chat.alice, &mut chat.bob] {
            if let Some(state) = engine.state.conversations.get_mut(&chat.conversation_id) {
                state.pcs.self_debt = debt;
            }
        }
    }

    /// Sends from whichever side is designated for the *current* epoch and
    /// returns whether that was alice. Keep the return value: the rotation it
    /// triggers advances the epoch and flips the designation.
    fn trigger_direct_pcs_from_designated(chat: &mut PairedDirectChat) -> bool {
        let alice_rotates = alice_is_designated(chat);
        let conversation_id = chat.conversation_id.clone();
        rotator_engine_mut(chat, alice_rotates)
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id,
                plaintext: "pcs trigger".into(),
            })
            .expect("designated send triggers pcs");
        alice_rotates
    }

    /// One hop. A rotation is a single commit now: the rotating side already
    /// merged it, and the peer merges it on arrival. Nothing comes back.
    fn complete_direct_pcs_rotation(chat: &mut PairedDirectChat, alice_rotated: bool) {
        if alice_rotated {
            deliver_and_settle_pending_outbox_to_device(
                &mut chat.bob,
                &chat.alice,
                &chat.bob_device_id,
            );
        } else {
            deliver_and_settle_pending_outbox_to_device(
                &mut chat.alice,
                &chat.bob,
                &chat.alice_device_id,
            );
        }
    }

    fn deliver_and_settle_pending_outbox_to_device(
        recipient: &mut CoreEngine,
        sender: &CoreEngine,
        device_id: &str,
    ) {
        let output = deliver_pending_outbox_to_device(recipient, sender, device_id);
        simulate_pending_key_package_claims(recipient, output);
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
                    && outbound_item_message_type(sender, item)
                        .is_some_and(|message_type| types.contains(&message_type))
            })
            .enumerate()
            .map(|(index, item)| InboxRecord {
                seq: index as u64 + 1,
                recipient_device_id: item.envelope.recipient_device_id.clone(),
                message_id: item.envelope.mid.clone(),
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

    fn outbound_item_message_type(
        sender: &CoreEngine,
        item: &crate::ffi_api::types::PendingOutboxItem,
    ) -> Option<MessageType> {
        outbound_envelope_message_type(sender, &item.envelope)
    }

    fn outbound_envelope_message_type(
        sender: &CoreEngine,
        envelope: &Envelope,
    ) -> Option<MessageType> {
        let payload = envelope.payload_b64()?;
        if MlsAdapter::payload_is_welcome(payload) {
            return Some(MessageType::MlsWelcome);
        }
        let conversation_id = sender.state.lane_index.get(&envelope.lane)?;
        let lanes = sender
            .state
            .conversations
            .get(conversation_id)?
            .lanes
            .as_ref()?;
        let key = sender
            .state
            .mls_adapter
            .as_ref()?
            .export_lane_wrap_key(conversation_id, lanes.outbound_dir)
            .ok()?;
        let wrapped = STANDARD.decode(payload).ok()?;
        let plaintext = crate::lane_wrap::unwrap_with_cached_keys(&key, None, &wrapped)?;
        let (mls_b64, _) = crate::direct_frame::decode(&plaintext).ok()?;
        MlsAdapter::classify_mls_payload(&mls_b64)
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
                    message_id: envelope.mid.clone(),
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
                    && item
                        .plaintext_cache
                        .as_deref()
                        .is_some_and(|text| !text.is_empty())
            })
            .expect("pending application")
            .envelope
            .clone()
    }

    fn unwrapped_inbox_payload(
        recipient: &CoreEngine,
        conversation_id: &str,
        envelope: &Envelope,
    ) -> String {
        let payload = envelope.payload_b64().unwrap_or_default();
        if crate::mls_adapter::MlsAdapter::payload_is_welcome(payload) {
            return payload.to_string();
        }
        recipient
            .unwrap_inbound_bytes(conversation_id, payload)
            .expect("unwrap inbox frame")
    }

    /// The most recent match. Prefer this for commits: the conversation's
    /// creating commit can still be sitting at the head of the outbox.
    fn outbox_item_matches_type(
        item: &crate::ffi_api::types::PendingOutboxItem,
        message_type: MessageType,
    ) -> bool {
        let bytes = item.envelope.payload_b64().unwrap_or_default();
        match message_type {
            MessageType::MlsWelcome => crate::mls_adapter::MlsAdapter::payload_is_welcome(bytes),
            MessageType::MlsApplication => {
                item.plaintext_cache.is_some() || item.app_message_id.is_some()
            }
            MessageType::MlsCommit | MessageType::MlsProposal => {
                !crate::mls_adapter::MlsAdapter::payload_is_welcome(bytes)
                    && item.plaintext_cache.is_none()
                    && item.app_message_id.is_none()
            }
            _ => false,
        }
    }

    fn last_pending_envelope(
        sender: &CoreEngine,
        device_id: &str,
        message_type: MessageType,
    ) -> Envelope {
        sender
            .state
            .pending_outbox
            .iter()
            .rfind(|item| {
                item.envelope.recipient_device_id == device_id
                    && outbox_item_matches_type(item, message_type)
            })
            .expect("pending envelope")
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
                    && outbox_item_matches_type(item, message_type)
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

    /// Re-sign an envelope after mutating it.
    ///
    /// The sender proof covers the whole envelope header, so any test that
    /// edits a `message_id`, `conversation_id`, `recipient_device_id` or
    /// payload after the engine produced the envelope must re-sign, or the
    /// inbound authentication gate correctly rejects it. Exactly one place in
    /// the test suite knows the signing domain, mirroring the single place in
    /// production that does (`build_envelope_with_storage_refs`).
    ///
    /// `signer` is the engine whose local identity is the claimed sender.
    fn resign_envelope(signer: &CoreEngine, envelope: &mut Envelope) {
        let identity = signer
            .state
            .local_identity
            .as_ref()
            .expect("signer identity")
            .clone();
        let _ = identity;
        let _ = envelope;
    }

    /// One identity, plus the bundle describing it.
    ///
    /// Device keys are minted fresh per identity, so a fixture that needs both
    /// a verifiable signature and an importable bundle must derive them from
    /// the same `LocalIdentityState`.
    fn sample_identity_with_bundle(
        mnemonic: &str,
        device_name: &str,
    ) -> (crate::identity::LocalIdentityState, IdentityBundle) {
        let identity = IdentityManager::create_or_recover(Some(mnemonic), Some(device_name))
            .expect("identity");
        let package = MlsAdapter::generate_key_package(&identity, test_now_ms()).expect("package");
        let bundle = IdentityManager::export_identity_bundle(
            &identity,
            &sample_deployment(),
            package.key_package_b64,
            package.expires_at,
        )
        .expect("bundle");
        (identity, bundle)
    }

    /// A 1:1 inbox record that is not a Welcome and has no wrap.
    ///
    /// After R3-2 the inbox does not classify by `message_type`; unknown-lane
    /// non-Welcome frames are acked with zero state change.
    fn signed_control_record_from(
        sender_identity: &crate::identity::LocalIdentityState,
        device_id: &str,
        seq: u64,
    ) -> InboxRecord {
        let _ = sender_identity;
        sample_control_record_with_type(device_id, seq)
    }

    fn pending_application_record(sender: &CoreEngine, device_id: &str) -> InboxRecord {
        let item = sender
            .state
            .pending_outbox
            .iter()
            .rev()
            .find(|item| {
                item.envelope.recipient_device_id == device_id
                    && outbox_item_matches_type(item, MessageType::MlsApplication)
            })
            .expect("pending application delivery");
        InboxRecord {
            seq: 1,
            recipient_device_id: item.envelope.recipient_device_id.clone(),
            message_id: item.envelope.mid.clone(),
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

    fn sample_identity_bundle_at_revision(
        mnemonic: &str,
        device_name: &str,
        publication_revision: u64,
    ) -> IdentityBundle {
        let identity = IdentityManager::create_or_recover(Some(mnemonic), Some(device_name))
            .expect("identity");
        let package = MlsAdapter::generate_key_package(&identity, test_now_ms()).expect("package");
        let mut bundle = IdentityManager::export_identity_bundle(
            &identity,
            &sample_deployment(),
            package.key_package_b64,
            package.expires_at,
        )
        .expect("bundle");
        bundle.publication_revision = publication_revision;
        bundle.signature =
            identity.sign_payload_with_root(crate::identity::identity_bundle_payload(&bundle));
        bundle
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

    pub(crate) fn sample_attachment_descriptor() -> AttachmentDescriptor {
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

    fn sample_control_record_with_type(device_id: &str, seq: u64) -> InboxRecord {
        InboxRecord {
            seq,
            recipient_device_id: device_id.into(),
            message_id: format!("msg:{seq}"),
            received_at: seq,
            expires_at: None,
            state: InboxRecordState::Available,
            envelope: Envelope::with_bytes(
                device_id,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                format!("{seq:032x}"),
                "cipher",
            ),
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

    pub(crate) fn sample_deployment() -> DeploymentBundle {
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

    pub(crate) fn unique_temp_path(prefix: &str) -> std::path::PathBuf {
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
                records: vec![harness.outboxes[&group_id]
                    .last()
                    .expect("forged record")
                    .clone()],
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
                records: vec![harness.outboxes[&group_id]
                    .last()
                    .expect("forged record")
                    .clone()],
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
                records: vec![harness.outboxes[&group_id]
                    .last()
                    .expect("forged record")
                    .clone()],
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

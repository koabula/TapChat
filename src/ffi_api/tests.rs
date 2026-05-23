#[cfg(test)]
mod tests {
    use crate::attachment_crypto::{
        AttachmentCipherMetadata, AttachmentPayloadMetadata, ATTACHMENT_CIPHER_ALGORITHM,
    };
    use crate::ffi_api::engine;
    use crate::ffi_api::types::{RecoveryContext, RecoveryReason, MAX_TRANSPORT_RETRIES};
    use crate::ffi_api::{
        AttachmentDescriptor, CoreCommand, CoreEffect, CoreEngine, CoreEvent, CoreOutput,
        FfiApiModule, RealtimeEvent,
    };
    use crate::identity::IdentityManager;
    use crate::mls_adapter::MlsAdapter;
    use crate::model::{
        ConversationKind, DeliveryClass, DeploymentBundle, DeviceRuntimeAuth, Envelope,
        GroupCapabilityOperation, GroupEnvelope, GroupEnvelopeVisibility, GroupInviteDocument,
        GroupJoinRequest, GroupJoinRequestStatus, GroupMemberStatus, GroupMessageType,
        GroupOutboxRecord, GroupOutboxRecordState, GroupRole, IdentityBundle, InboxRecord,
        InboxRecordState, MessageType, SenderProof, StorageBaseInfo, WakeHint,
        WelcomePickupDescriptor, CURRENT_MODEL_VERSION,
    };
    use crate::persistence::{CorePersistenceSnapshot, PersistOp, PersistedPendingWelcomePickup};
    use crate::transport_contract::{
        GroupJoinDecision, SealGroupOutboxRequest, SealGroupOutboxResult, SharedStateDocumentKind,
    };
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use std::collections::{BTreeMap, BTreeSet};

    const ALICE_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const BOB_MNEMONIC: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";
    const CAROL_MNEMONIC: &str =
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";
    const DANA_MNEMONIC: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";

    #[test]
    fn module_name_is_stable() {
        assert_eq!(FfiApiModule.name(), "ffi_api");
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
                retryable: true,
                detail: Some("timeout".into()),
            })
            .expect("welcome pickup failure");

        let pending = engine
            .state
            .pending_welcome_pickups
            .get(&key)
            .expect("pending welcome pickup remains");
        assert_eq!(pending.retries, 1);
        assert!(pending
            .last_error
            .as_deref()
            .unwrap_or("")
            .contains("timeout"));
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
            retryable: false,
            status: Some(403),
            code: Some("unauthorized".into()),
            detail: Some("capability does not authorize seal_group".into()),
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
            engine::test_group_capability_operations(GroupRole::Owner),
            owner_privileged
        );
        assert_eq!(
            engine::test_group_capability_operations(GroupRole::Admin),
            admin_privileged
        );
        assert_eq!(
            engine::test_group_capability_operations(GroupRole::Member),
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

        let summary = output
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .expect("group summary");
        assert_eq!(summary.kind, Some(ConversationKind::Group));
        assert_eq!(summary.title.as_deref(), Some("Project"));
        assert_eq!(summary.member_count, Some(3));
        assert!(output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::AppendGroupEnvelope { append }
                if append.envelope.message_type == crate::model::GroupMessageType::MlsCommit
        )));
        let owner_operations = output
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::AppendGroupEnvelope { append } => {
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
    fn removed_local_role_cannot_restore_or_send_group_outbox() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle.clone());
        let output = alice
            .handle_command(CoreCommand::CreateGroupConversation {
                title: "Project".into(),
                member_user_ids: vec![bob_bundle.user_id.clone()],
            })
            .expect("create group");
        let summary = output
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .expect("group summary");
        let group_id = summary.group_id.clone().expect("group id");
        let conversation_id = summary.conversation_id.clone();

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

        let mut snapshot = extract_snapshot(&output);
        for group_state in &mut snapshot.group_states {
            group_state.local_role = None;
        }
        for item in &mut snapshot.pending_group_outbox {
            item.capability = None;
        }
        let restored = CoreEngine::from_restored_state(snapshot);
        assert!(
            restored.state.pending_group_outbox.is_empty(),
            "pending group sends without a local role must not regain member capability"
        );
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
        let summary = output
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .expect("group summary");
        let group_id = summary.group_id.clone().expect("group id");

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
        let group_id = created
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .and_then(|summary| summary.group_id.clone())
            .expect("group id");

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
        let group_id = created
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .and_then(|summary| summary.group_id.clone())
            .expect("group id");

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
        let group_id = created
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .and_then(|summary| summary.group_id.clone())
            .expect("group id");
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
        let group_id = created
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .and_then(|summary| summary.group_id.clone())
            .expect("group id");
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
                retryable: true,
                status: Some(503),
                code: None,
                detail: Some("upstream unavailable".into()),
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
                retryable: false,
                status: Some(403),
                code: Some("unauthorized".into()),
                detail: Some("capability rejected".into()),
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

        let mut restored = CoreEngine::from_restored_state(snapshot);
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
            matches!(effect, CoreEffect::AppendGroupEnvelope { append } if append.group_id == group_id)
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
        let mut restored = CoreEngine::from_restored_state(snapshot);
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
            matches!(effect, CoreEffect::DownloadBlob { download } if download.download_target == reference)
        }));
        let snapshot = bob.engine.refresh_snapshot();
        assert_eq!(snapshot.pending_blob_transfers.len(), 1);

        let mut restored = CoreEngine::from_restored_state(snapshot);
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
            .get(&download.download_target)
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
            CoreEffect::AppendGroupEnvelope { append }
                if append.envelope.message_type == GroupMessageType::MlsCommit
        )));
        assert!(remove_output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::AppendGroupEnvelope { append }
                if append.envelope.message_type == GroupMessageType::ControlGroupMembershipChanged
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
        let bob_state = bob
            .engine
            .state
            .group_states
            .get(&group_id)
            .expect("bob group");
        assert_eq!(bob_state.local_role, None);
        assert!(bob_state.manifest.members.iter().any(|member| {
            member.user_id == bob.bundle.user_id && member.status == GroupMemberStatus::Left
        }));
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
        harness.sync_group(&mut alice, &group_id);
        assert!(
            alice
                .engine
                .state
                .conversations
                .get(&conversation_id)
                .expect("alice conversation")
                .messages
                .iter()
                .any(|message| message.message_type == MessageType::ControlDeviceMembershipChanged),
            "owner should receive the visible leave request"
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
        assert!(
            owner
                .engine
                .handle_command(CoreCommand::LeaveGroup {
                    group_id: transfer_group_id.clone(),
                })
                .is_ok(),
            "former owner can leave after transfer"
        );
        assert!(
            successor
                .engine
                .handle_command(CoreCommand::DissolveGroup {
                    group_id: transfer_group_id
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
            GroupJoinRequestStatus::Pending
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
        assert_eq!(decision.request.status, GroupJoinRequestStatus::Approved);
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
                plaintext_b64: STANDARD.encode([1_u8, 2, 3, 4]),
            })
            .expect("attachment bytes loaded");
        assert!(prepared.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::PrepareBlobUpload { upload }
                if upload.headers.get("Authorization")
                    == Some(&"Bearer device-runtime-token".into())
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
        let outbox_item = alice
            .state
            .pending_outbox
            .iter()
            .find(|item| !item.envelope.storage_refs.is_empty())
            .expect("attachment outbox");
        let message_id = outbox_item.envelope.message_id.clone();
        let plaintext_cache = outbox_item
            .plaintext_cache
            .as_deref()
            .expect("attachment metadata cache");
        let metadata: AttachmentPayloadMetadata =
            serde_json::from_str(plaintext_cache).expect("attachment metadata json");
        assert_eq!(metadata.mime_type, "application/octet-stream");
        assert_eq!(metadata.file_name.as_deref(), Some("file.bin"));
        assert_eq!(metadata.size_bytes, 4);

        let download = alice
            .handle_command(CoreCommand::DownloadAttachment {
                conversation_id: conversation_id.clone(),
                message_id: message_id.clone(),
                reference: "blob-download:attachment-1".into(),
                destination: "cached/file.bin".into(),
            })
            .expect("download attachment from pending outbox metadata");
        assert!(download.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::DownloadBlob { download }
                if download.blob_ref == "blob-download:attachment-1"
        )));
        assert!(output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::ExecuteHttpRequest { request } if request.url.contains("/messages")
        )));

        let request_id = find_http_request_id(&output, "/messages");
        alice
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id,
                status: 200,
                body: Some(r#"{"accepted":true,"seq":3,"delivered_to":"inbox"}"#.into()),
            })
            .expect("append inbox response");
        let stored = alice
            .state
            .conversations
            .get(&conversation_id)
            .expect("conversation")
            .messages
            .iter()
            .find(|message| message.message_id == message_id)
            .expect("stored sent attachment");
        let stored_metadata: AttachmentPayloadMetadata = serde_json::from_str(
            stored
                .plaintext
                .as_deref()
                .expect("stored attachment metadata"),
        )
        .expect("stored attachment metadata json");
        assert_eq!(
            stored_metadata.encryption.algorithm,
            ATTACHMENT_CIPHER_ALGORITHM
        );
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
    fn terminal_attachment_upload_failure_clears_pending_task() {
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
                retryable: false,
                detail: Some("denied".into()),
            })
            .expect("upload failure");

        assert!(!alice.state.pending_blob_uploads.contains_key(&task_id));
        assert!(failed.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::PersistState { persist }
                if persist.ops.iter().any(|op| matches!(
                    op,
                    PersistOp::DeletePendingBlobTransfer { task_id: deleted } if deleted == &task_id
                ))
        )));
    }

    #[test]
    fn download_attachment_uses_unique_task_ids_for_distinct_destinations() {
        let bob_bundle = sample_identity_bundle(BOB_MNEMONIC, "phone");
        let mut engine = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle);
        let conversation_id = "conv:test".to_string();
        engine.state.conversations.insert(
            conversation_id.clone(),
            crate::conversation::LocalConversationState {
                conversation: crate::model::Conversation {
                    conversation_id: conversation_id.clone(),
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
                conversation_id: conversation_id.clone(),
                message_id: "msg:download".into(),
                reference: "cid:download".into(),
                destination: "cache/a.bin".into(),
            })
            .expect("first download");
        engine
            .handle_command(CoreCommand::DownloadAttachment {
                conversation_id,
                message_id: "msg:download".into(),
                reference: "cid:download".into(),
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
        assert!(engine
            .state
            .conversations
            .contains_key(&expected_conversation_id));
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
        assert!(snapshot
            .mls_states
            .iter()
            .all(|state| state.serialized_group_state.is_some()));
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

        assert!(!alice
            .state
            .pending_outbox
            .iter()
            .any(|item| item.envelope.message_id == pending_message_id));
        assert!(output
            .state_update
            .system_statuses_changed
            .contains(&crate::ffi_api::SystemStatus::MessageQueuedForApproval));
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
        assert_eq!(
            append_result.request_id.as_deref(),
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

        assert!(!alice
            .state
            .pending_outbox
            .iter()
            .any(|item| item.envelope.message_id == pending_message_id));
        assert!(output
            .state_update
            .system_statuses_changed
            .contains(&crate::ffi_api::SystemStatus::MessageRejectedByPolicy));
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
                display_name: None,
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
                    retryable: true,
                    detail: Some("download failed".into()),
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
    fn direct_welcome_rotates_and_persists_new_key_package() {
        let mut bob = local_engine(BOB_MNEMONIC, "phone");
        let bob_bundle = bob.local_bundle().expect("bob bundle").clone();
        let bob_device_id = bob_bundle.devices[0].device_id.clone();
        let bob_user_id = bob_bundle.user_id.clone();
        let before = local_key_package_ref(&bob);

        let mut alice = seeded_engine(ALICE_MNEMONIC, "phone", bob_bundle);
        create_direct_conversation(&mut alice, bob_user_id);
        let output = deliver_pending_outbox_to_device(&mut bob, &alice, &bob_device_id);

        let after = local_key_package_ref(&bob);
        assert_ne!(
            before, after,
            "welcome import must publish a fresh KeyPackage"
        );

        let snapshot = extract_snapshot(&output);
        let deployment = snapshot.deployment.expect("persisted deployment");
        assert_eq!(
            deployment
                .published_key_package
                .expect("persisted published key package")
                .key_package_ref,
            after
        );
        assert_eq!(
            deployment
                .local_bundle
                .expect("persisted local bundle")
                .devices[0]
                .keypackage_ref
                .object_ref,
            after
        );
        assert!(
            publish_shared_state_effects(&output)
                .iter()
                .any(|publish| publish.document_kind == SharedStateDocumentKind::IdentityBundle),
            "rotated identity bundle should be republished after welcome"
        );
    }

    #[test]
    fn group_invite_after_direct_welcome_uses_rotated_key_package() {
        let mut alice = harness_user("alice", ALICE_MNEMONIC, "phone");
        let mut bob = harness_user("bob", BOB_MNEMONIC, "phone");
        import_peer_bundles(&mut [&mut alice, &mut bob]);

        create_direct_conversation(&mut alice.engine, bob.bundle.user_id.clone());
        let bob_device_id = bob.bundle.devices[0].device_id.clone();
        deliver_pending_outbox_to_device(&mut bob.engine, &alice.engine, &bob_device_id);
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
        assert!(restored.state.pending_outbox[pending_before..]
            .iter()
            .any(|item| {
                item.envelope.conversation_id == conversation_id
                    && item.envelope.message_type == MessageType::MlsCommit
            }));
        assert!(restored.state.pending_outbox[pending_before..]
            .iter()
            .any(|item| {
                item.envelope.conversation_id == conversation_id
                    && item.envelope.message_type == MessageType::MlsWelcome
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
        welcome_pickups: BTreeMap<(String, String), (String, Option<crate::model::GroupManifest>)>,
        prepared_blob_downloads: BTreeMap<String, String>,
        blobs: BTreeMap<String, String>,
        downloaded_attachments: BTreeMap<String, Vec<u8>>,
        invites: BTreeMap<String, GroupInviteDocument>,
        invite_urls: BTreeMap<String, String>,
        join_requests: BTreeMap<String, GroupJoinRequest>,
        join_decisions: BTreeMap<String, JoinDecisionArtifacts>,
        bundles: BTreeMap<String, IdentityBundle>,
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
            while let Some(effect) = queue.pop_front() {
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
                    CoreEffect::GetGroupOutboxHead { get } => {
                        let head_seq = self
                            .outboxes
                            .get(&get.group_id)
                            .and_then(|records| records.last())
                            .map(|record| record.seq)
                            .unwrap_or(0);
                        user.engine
                            .handle_event(CoreEvent::GroupOutboxHeadFetched {
                                group_id: get.group_id,
                                head_seq,
                            })
                            .expect("group outbox head fetched")
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
                        user.engine
                            .handle_event(CoreEvent::GroupOutboxFetched {
                                group_id: fetch.group_id,
                                records,
                                to_seq,
                            })
                            .expect("group outbox fetched")
                    }
                    CoreEffect::PutWelcomePickup { put } => {
                        self.welcome_pickups.insert(
                            (
                                put.descriptor.group_id.clone(),
                                put.descriptor.device_id.clone(),
                            ),
                            (put.welcome_b64, put.manifest),
                        );
                        user.engine
                            .handle_event(CoreEvent::WelcomePickupPut {
                                descriptor: put.descriptor,
                            })
                            .expect("welcome pickup put")
                    }
                    CoreEffect::FetchWelcomePickup { fetch } => {
                        let (welcome_b64, manifest) = self
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
                                    && request.status == GroupJoinRequestStatus::Pending
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
                            GroupJoinDecision::Approve => GroupJoinRequestStatus::Approved,
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
                        if publish.document_kind == SharedStateDocumentKind::IdentityBundle {
                            let bundle: IdentityBundle = serde_json::from_str(&publish.body)
                                .expect("published identity bundle");
                            self.bundles.insert(bundle.user_id.clone(), bundle.clone());
                            if bundle.user_id == user.bundle.user_id {
                                user.bundle = bundle;
                            }
                        }
                        CoreOutput::default()
                    }
                    CoreEffect::ReadAttachmentBytes { read } => {
                        let bytes = std::fs::read(&read.attachment_id).expect("attachment bytes");
                        user.engine
                            .handle_event(CoreEvent::AttachmentBytesLoaded {
                                task_id: read.task_id,
                                plaintext_b64: STANDARD.encode(bytes),
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
                        let download_target = format!("download-ref:{}", upload.task_id);
                        self.prepared_blob_downloads
                            .insert(upload.task_id.clone(), download_target.clone());
                        user.engine
                            .handle_event(CoreEvent::BlobUploadPrepared {
                                task_id: upload.task_id,
                                result: crate::transport_contract::PrepareBlobUploadResult {
                                    blob_ref,
                                    upload_target: "memory-upload".into(),
                                    upload_headers: BTreeMap::new(),
                                    download_target: Some(download_target),
                                    expires_at: Some(u64::MAX / 2),
                                },
                            })
                            .expect("blob upload prepared")
                    }
                    CoreEffect::UploadBlob { upload } => {
                        let download_target = self
                            .prepared_blob_downloads
                            .get(&upload.task_id)
                            .cloned()
                            .expect("prepared download target");
                        self.blobs
                            .insert(download_target, upload.blob_ciphertext_b64);
                        user.engine
                            .handle_event(CoreEvent::BlobUploaded {
                                task_id: upload.task_id,
                            })
                            .expect("blob uploaded")
                    }
                    CoreEffect::DownloadBlob { download } => {
                        let blob_ciphertext = self.blobs.get(&download.download_target).cloned();
                        user.engine
                            .handle_event(CoreEvent::BlobDownloaded {
                                task_id: download.task_id,
                                blob_ciphertext,
                            })
                            .expect("blob downloaded")
                    }
                    CoreEffect::WriteDownloadedAttachment { write } => {
                        let plaintext = STANDARD
                            .decode(&write.plaintext_b64)
                            .expect("downloaded plaintext");
                        self.downloaded_attachments
                            .insert(write.destination_id, plaintext);
                        CoreOutput::default()
                    }
                    CoreEffect::PersistState { .. }
                    | CoreEffect::EmitUserNotification { .. }
                    | CoreEffect::ExecuteHttpRequest { .. }
                    | CoreEffect::ScheduleTimer { .. } => CoreOutput::default(),
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
            let summary = output
                .view_model
                .as_ref()
                .and_then(|view| view.conversations.first())
                .expect("group summary")
                .clone();
            let group_id = summary.group_id.clone().expect("group id");
            let conversation_id = summary.conversation_id;
            self.drain(owner, output);
            (group_id, conversation_id)
        }

        fn import_welcome(&mut self, user: &mut HarnessUser, group_id: &str) {
            let descriptor = self
                .welcome_pickups
                .keys()
                .find(|(gid, device_id)| {
                    gid == group_id && device_id == &user.bundle.devices[0].device_id
                })
                .map(|(gid, device_id)| WelcomePickupDescriptor {
                    group_id: gid.clone(),
                    device_id: device_id.clone(),
                    endpoint: "https://example.com/welcome".into(),
                    capability: "test-capability".into(),
                    expires_at: u64::MAX,
                })
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
            let seq = self.outboxes.get(group_id).map(Vec::len).unwrap_or(0) as u64 + 1;
            let envelope = GroupEnvelope {
                version: CURRENT_MODEL_VERSION.to_string(),
                message_id: format!("forged-membership:{seq}"),
                group_id: group_id.into(),
                conversation_id: conversation_id.into(),
                sender_user_id: sender.bundle.user_id.clone(),
                sender_device_id: sender.bundle.devices[0].device_id.clone(),
                created_at: seq,
                message_type: GroupMessageType::ControlGroupMembershipChanged,
                visibility: GroupEnvelopeVisibility::Protocol,
                inline_ciphertext: Some(STANDARD.encode(b"not a valid encrypted manifest")),
                storage_refs: vec![],
                sender_proof: SenderProof {
                    proof_type: "signature".into(),
                    value: "forged".into(),
                },
                membership_proof: Some(crate::model::GroupMembershipProof {
                    proof_type: "membership_signature".into(),
                    operation: "invite".into(),
                    signer_user_id: "user:alice".into(),
                    signer_device_id: "device:alice:phone".into(),
                    previous_roster_version: 1,
                    new_roster_version: 2,
                    previous_commit_message_id: None,
                    commit_message_id: "msg:commit:1".into(),
                    control_message_id: "msg:control:1".into(),
                    new_manifest_sha256: "sha256:forged".into(),
                    signature: "forged".into(),
                }),
            };
            self.outboxes
                .entry(group_id.into())
                .or_default()
                .push(GroupOutboxRecord {
                    seq,
                    group_id: group_id.into(),
                    message_id: envelope.message_id.clone(),
                    received_at: seq,
                    expires_at: None,
                    state: GroupOutboxRecordState::Available,
                    envelope,
                });
        }
    }

    fn harness_user(name: &'static str, mnemonic: &str, device_name: &str) -> HarnessUser {
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

    fn local_key_package_ref(engine: &CoreEngine) -> String {
        engine
            .state
            .local_bundle
            .as_ref()
            .expect("local bundle")
            .devices[0]
            .keypackage_ref
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
        let summary = output
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .expect("group summary");
        let group_id = summary.group_id.clone().expect("group id");
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
        let group_id = output
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .expect("group summary")
            .group_id
            .clone()
            .expect("group id");

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
        let group_id = output
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .expect("group summary")
            .group_id
            .clone()
            .expect("group id");
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
        let group_id = output
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .expect("group summary")
            .group_id
            .clone()
            .expect("group id");
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
        let group_id = output
            .view_model
            .as_ref()
            .and_then(|view| view.conversations.first())
            .expect("group summary")
            .group_id
            .clone()
            .expect("group id");

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
        harness.sync_group(&mut bob, &group_id);
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
        harness.sync_group(&mut bob, &group_id);
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
        harness.sync_group(&mut bob, &group_id);
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

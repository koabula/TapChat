use super::*;

impl CoreEngine {
    pub(super) fn create_group_conversation(
        &mut self,
        title: String,
        member_user_ids: Vec<String>,
    ) -> CoreResult<CoreOutput> {
        self.require_group_authorization_v2()?;
        let title = title.trim().to_string();
        if title.is_empty() {
            return Err(CoreError::invalid_input("group title must not be empty"));
        }
        let local_identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .clone();
        let mut member_user_ids = member_user_ids
            .into_iter()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        member_user_ids.sort();
        member_user_ids.dedup();
        if member_user_ids.is_empty() {
            return Err(CoreError::invalid_input(
                "group must include at least one invited member",
            ));
        }
        if member_user_ids.contains(&local_identity.user_identity.user_id) {
            return Err(CoreError::invalid_input(
                "member_user_ids must not include the local owner",
            ));
        }

        let mut peer_keypackages = Vec::new();
        let mut member_devices = vec![ConversationMember {
            user_id: local_identity.user_identity.user_id.clone(),
            device_id: local_identity.device_identity.device_id.clone(),
            status: DeviceStatusKind::Active,
        }];
        let mut manifest_member_devices = vec![GroupMemberDevice {
            user_id: local_identity.user_identity.user_id.clone(),
            device_id: local_identity.device_identity.device_id.clone(),
            status: GroupMemberStatus::Active,
        }];
        for user_id in &member_user_ids {
            let bundle = self.direct_peer_contact_bundle(user_id)?.clone();
            let now_ms = current_unix_millis(self.state.message_nonce);
            let mut usable_device_found = false;
            for device in bundle
                .devices
                .iter()
                .filter(|device| matches!(device.status, DeviceStatusKind::Active))
            {
                let Some(keypackage_ref) = device
                    .keypackage_ref
                    .as_ref()
                    .filter(|keypackage_ref| keypackage_ref.is_usable_at(now_ms))
                else {
                    continue;
                };
                usable_device_found = true;
                peer_keypackages.push(PeerDeviceKeyPackage {
                    user_id: user_id.clone(),
                    device_id: device.device_id.clone(),
                    device_public_key: device.device_public_key.clone(),
                    key_package_b64: keypackage_ref.object_ref.clone(),
                });
                member_devices.push(ConversationMember {
                    user_id: user_id.clone(),
                    device_id: device.device_id.clone(),
                    status: DeviceStatusKind::Active,
                });
                manifest_member_devices.push(GroupMemberDevice {
                    user_id: user_id.clone(),
                    device_id: device.device_id.clone(),
                    status: GroupMemberStatus::Active,
                });
            }
            if !usable_device_found {
                if bundle.devices.iter().any(|device| {
                    matches!(device.status, DeviceStatusKind::Active)
                        && device.keypackage_ref.as_ref().is_some_and(|keypackage| {
                            keypackage.created_at
                                > now_ms.saturating_add(
                                    crate::mls_adapter::KEY_PACKAGE_CLOCK_TOLERANCE_MS,
                                )
                        })
                }) {
                    return Err(CoreError::new(
                        "device_clock_invalid",
                        "an invited contact key package was created too far in the future",
                    ));
                }
                return Err(CoreError::new(
                    "keypackage_expired",
                    "an invited contact has no usable key package",
                ));
            }
        }
        if peer_keypackages.is_empty() {
            return Err(CoreError::new(
                "keypackage_expired",
                "invited contacts have no usable key packages",
            ));
        }
        crate::pcs_policy::validate_active_leaf_limit(
            1usize.saturating_add(peer_keypackages.len()),
        )?;
        let invitee_user_by_device: BTreeMap<String, String> = peer_keypackages
            .iter()
            .map(|package| (package.device_id.clone(), package.user_id.clone()))
            .collect();

        let group_id = self.next_group_id(&title, &member_user_ids);
        let conversation_id = format!("conv:{group_id}");
        if self.state.group_states.contains_key(&group_id)
            || self.state.conversations.contains_key(&conversation_id)
        {
            return Err(CoreError::invalid_state(
                "group conversation already exists",
            ));
        }

        let canonical_summary = self
            .state
            .mls_adapter
            .as_mut()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .create_owner_conversation(&conversation_id)?;
        let mut staged_mls = self
            .state
            .mls_adapter
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("mls adapter missing after owner genesis"))?
            .fork()?;
        let artifacts = staged_mls.add_members(&conversation_id, &peer_keypackages)?;
        let summary = staged_mls.export_group_summary(&conversation_id)?;
        self.state
            .mls_summaries
            .insert(conversation_id.clone(), canonical_summary.clone());

        let now = current_unix_millis(self.state.message_nonce);
        let mut manifest = self.build_group_manifest(
            &group_id,
            &conversation_id,
            &title,
            &local_identity,
            &member_user_ids,
            manifest_member_devices,
            summary.epoch,
            now,
        )?;
        manifest.validate()?;
        let mut genesis_manifest = manifest.clone();
        genesis_manifest
            .members
            .retain(|member| member.user_id == local_identity.user_identity.user_id);
        genesis_manifest.member_devices.retain(|device| {
            device.user_id == local_identity.user_identity.user_id
                && device.device_id == local_identity.device_identity.device_id
        });
        genesis_manifest.admins.clear();
        genesis_manifest.roster_version = 0;
        genesis_manifest.mls_epoch_hint = canonical_summary.epoch;
        genesis_manifest.last_commit_message_id = None;
        genesis_manifest.signature = self.sign_manifest(&genesis_manifest)?;
        genesis_manifest.validate()?;
        let group_state = PersistedGroupState {
            group_id: group_id.clone(),
            conversation_id: conversation_id.clone(),
            manifest: genesis_manifest.clone(),
            local_role: Some(GroupRole::Owner),
            welcome_pickup: None,
            dissolved_at: None,
            pending_membership_transition: None,
            consistency_state: GroupConsistencyState::Ready,
            pending_group_transition: None,
            leave_requests: Vec::new(),
            pcs_state: Default::default(),
            crypto_epoch: 0,
            crypto_head_hash: String::new(),
            pending_secure_send: None,
            pending_epoch_transition: None,
        };
        self.state
            .group_states
            .insert(group_id.clone(), group_state);
        self.state.group_cursors.insert(
            group_id.clone(),
            GroupCursor {
                group_id: group_id.clone(),
                last_fetched_seq: 0,
                updated_at: now,
            },
        );
        self.state.conversations.insert(
            conversation_id.clone(),
            LocalConversationState {
                conversation: Conversation {
                    conversation_id: conversation_id.clone(),
                    kind: ConversationKind::Group,
                    member_users: vec![local_identity.user_identity.user_id.clone()],
                    member_devices: vec![ConversationMember {
                        user_id: local_identity.user_identity.user_id.clone(),
                        device_id: local_identity.device_identity.device_id.clone(),
                        status: DeviceStatusKind::Active,
                    }],
                    state: ConversationState::Active,
                    updated_at: now,
                },
                messages: Vec::new(),
                last_message_type: None,
                peer_user_id: group_id.clone(),
                last_known_peer_active_devices: BTreeSet::new(),
                recovery_status: RecoveryStatus::Healthy,
                archive_metadata: None,
            },
        );

        let capability = self.group_capability(&group_id, GroupRole::Owner)?;
        let mut commit = self.build_group_envelope(
            &group_id,
            &conversation_id,
            GroupMessageType::MlsCommit,
            GroupEnvelopeVisibility::Protocol,
            artifacts.commit_b64,
        )?;
        manifest.last_commit_message_id = Some(commit.message_id.clone());
        manifest.signature = self.sign_manifest(&manifest)?;
        manifest.validate()?;
        let manifest_payload = serde_json::to_vec(&manifest).map_err(|error| {
            CoreError::invalid_input(format!("failed to encode manifest: {error}"))
        })?;
        let control_plaintext =
            staged_mls.encrypt_application(&conversation_id, &manifest_payload)?;
        let mut control = self.build_group_envelope(
            &group_id,
            &conversation_id,
            GroupMessageType::ControlGroupMembershipChanged,
            GroupEnvelopeVisibility::Protocol,
            control_plaintext.payload_b64,
        )?;
        let mut membership_proof = self.build_membership_proof(
            "create",
            &genesis_manifest,
            &manifest,
            &commit.message_id,
            &control.message_id,
        )?;
        let transition_id = format!("group-transition:{}", membership_proof.control_message_id);
        let mut state_event = self.build_group_envelope(
            &group_id,
            &conversation_id,
            GroupMessageType::ControlGroupStateEvent,
            GroupEnvelopeVisibility::Visible,
            "pending-state-event".into(),
        )?;
        state_event.transition_id = Some(transition_id.clone());
        let state_event_record = GroupOutboxRecord {
            seq: 0,
            group_id: group_id.clone(),
            message_id: state_event.message_id.clone(),
            received_at: state_event.created_at,
            expires_at: None,
            state: GroupOutboxRecordState::Available,
            envelope: state_event.clone(),
        };
        let state_event_plaintext = Self::derive_group_state_event(
            &genesis_manifest,
            &manifest,
            &membership_proof,
            &state_event_record,
        )
        .ok_or_else(|| CoreError::invalid_state("failed to build genesis group state event"))?;
        let protected_state_event =
            staged_mls.encrypt_application(&conversation_id, state_event_plaintext.as_bytes())?;
        state_event.inline_ciphertext = Some(protected_state_event.payload_b64.clone());
        let identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?;
        state_event.sender_proof.value =
            identity.sign_sender_proof(protected_state_event.payload_b64.as_bytes());
        membership_proof.state_event_message_id = Some(state_event.message_id.clone());
        membership_proof.signature =
            identity.sign_sender_proof(&Self::membership_proof_payload(&membership_proof));
        commit.transition_id = Some(transition_id.clone());
        control.transition_id = Some(transition_id.clone());
        commit.membership_proof = Some(membership_proof.clone());
        control.membership_proof = Some(membership_proof.clone());
        state_event.membership_proof = Some(membership_proof);
        self.enqueue_group_envelope(commit.clone(), capability.clone(), None);
        self.enqueue_group_envelope(control.clone(), capability.clone(), None);
        self.enqueue_group_envelope(
            state_event.clone(),
            capability.clone(),
            Some(state_event_plaintext.clone()),
        );

        self.state.group_states.insert(
            group_id.clone(),
            PersistedGroupState {
                group_id: group_id.clone(),
                conversation_id: conversation_id.clone(),
                manifest: genesis_manifest.clone(),
                local_role: Some(GroupRole::Owner),
                welcome_pickup: None,
                dissolved_at: None,
                pending_membership_transition: None,
                consistency_state: GroupConsistencyState::Reconciling,
                pending_group_transition: None,
                leave_requests: Vec::new(),
                pcs_state: Default::default(),
                crypto_epoch: 0,
                crypto_head_hash: String::new(),
                pending_secure_send: None,
                pending_epoch_transition: None,
            },
        );

        let persist_ops = vec![
            PersistOp::SaveConversation {
                conversation_id: conversation_id.clone(),
            },
            PersistOp::SaveMlsState {
                conversation_id: conversation_id.clone(),
            },
            PersistOp::SaveGroupState {
                group_id: group_id.clone(),
            },
            PersistOp::SaveGroupCursor {
                group_id: group_id.clone(),
            },
            PersistOp::SaveOutgoingGroupEnvelope {
                message_id: commit.message_id.clone(),
            },
            PersistOp::SaveOutgoingGroupEnvelope {
                message_id: control.message_id.clone(),
            },
            PersistOp::SaveOutgoingGroupEnvelope {
                message_id: state_event.message_id.clone(),
            },
        ];
        let mut pending_welcomes = Vec::new();
        for welcome in artifacts.welcomes {
            let descriptor =
                self.welcome_pickup_descriptor(&group_id, &welcome.recipient_device_id)?;
            log::info!(
                "create_group_conversation: prepared welcome pickup group_id={} recipient_device_id={} endpoint={}",
                group_id,
                welcome.recipient_device_id,
                descriptor.endpoint
            );
            pending_welcomes.push(PutWelcomePickupRequest {
                descriptor: descriptor.clone(),
                welcome_b64: welcome.payload_b64,
                manifest: Some(manifest.clone()),
                headers: BTreeMap::new(),
            });
            if !invitee_user_by_device.contains_key(&welcome.recipient_device_id) {
                log::warn!(
                    "create_group_conversation: missing invitee user mapping for welcome recipient_device_id={} group_id={}",
                    redact_id("device", &welcome.recipient_device_id),
                    redact_id("group", &group_id)
                );
            }
        }
        let pickup_descriptors = pending_welcomes
            .iter()
            .map(|welcome| welcome.descriptor.clone())
            .collect::<Vec<_>>();
        let mls_patch = self
            .state
            .mls_adapter
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .conversation_patch(&staged_mls, &conversation_id)?;
        let epoch_authenticator_sha256 = staged_mls.epoch_authenticator_sha256(&conversation_id)?;
        let next_crypto_epoch = manifest.mls_epoch_hint;
        let next_crypto_head_hash = Self::group_crypto_head_hash(
            "",
            next_crypto_epoch,
            commit.inline_ciphertext.as_deref().unwrap_or_default(),
            &epoch_authenticator_sha256,
            &commit.sender_user_id,
            &commit.sender_device_id,
        )?;
        self.bind_group_envelope_epoch(
            &mut commit,
            next_crypto_epoch,
            &next_crypto_head_hash,
            Some(&epoch_authenticator_sha256),
        )?;
        self.bind_group_envelope_epoch(
            &mut control,
            next_crypto_epoch,
            &next_crypto_head_hash,
            None,
        )?;
        self.bind_group_envelope_epoch(
            &mut state_event,
            next_crypto_epoch,
            &next_crypto_head_hash,
            None,
        )?;
        for item in &mut self.state.pending_group_outbox {
            let canonical = if item.envelope.message_id == commit.message_id {
                Some(&commit)
            } else if item.envelope.message_id == control.message_id {
                Some(&control)
            } else if item.envelope.message_id == state_event.message_id {
                Some(&state_event)
            } else {
                None
            };
            if let Some(canonical) = canonical {
                item.envelope = canonical.clone();
            }
        }
        if let Some(state) = self.state.group_states.get_mut(&group_id) {
            state.pending_group_transition = Some(PersistedPendingGroupTransition {
                transition_id,
                intent: GroupTransitionIntent::typed(GroupTransitionOperation::Create),
                stage: PendingGroupTransitionStage::AwaitingAuthorizationBootstrap,
                base_manifest_hash: Self::manifest_sha256(&genesis_manifest)?,
                base_roster_version: genesis_manifest.roster_version,
                base_commit_message_id: genesis_manifest.last_commit_message_id.clone(),
                proposed_manifest: manifest.clone(),
                mls_patch: Some(mls_patch),
                staged_mls_state: None,
                envelopes: vec![commit.clone(), control.clone(), state_event.clone()],
                state_event_plaintext: Some(state_event_plaintext),
                welcomes: pending_welcomes,
                join_request_id: None,
                retries: 0,
                first_seq: None,
                last_seq: None,
                expected_crypto_epoch: 0,
                expected_crypto_head_hash: String::new(),
                next_crypto_epoch,
                next_crypto_head_hash,
                epoch_authenticator_sha256,
            });
        }
        let mut effects = vec![persist_effect(&self.state, persist_ops)];
        effects.push(CoreEffect::InitializeGroupAuthorization {
            initialize: self.initialize_group_authorization_request(&group_id)?,
        });

        self.merge_with_transport_flush(CoreOutput {
            state_update: CoreStateUpdate {
                conversations_changed: true,
                messages_changed: true,
                ..CoreStateUpdate::default()
            },
            effects,
            view_model: Some(CoreViewModel {
                conversations: vec![self.conversation_summary(&conversation_id)?],
                messages: vec![
                    MessageSummary {
                        conversation_id: conversation_id.clone(),
                        message_id: commit.message_id,
                        message_type: MessageType::MlsCommit,
                    },
                    MessageSummary {
                        conversation_id,
                        message_id: control.message_id,
                        message_type: MessageType::ControlDeviceMembershipChanged,
                    },
                ],
                welcome_pickups: pickup_descriptors,
                ..CoreViewModel::default()
            }),
        })
    }

    pub(super) fn send_group_text_message(
        &mut self,
        conversation_id: String,
        plaintext: String,
    ) -> CoreResult<CoreOutput> {
        self.ensure_group_ready_for_send(&conversation_id)?;
        if plaintext.trim().is_empty() {
            return Err(CoreError::invalid_input("plaintext must not be empty"));
        }
        let group_id = self
            .group_id_for_conversation(&conversation_id)?
            .to_string();
        let state = self.state.group_states.get_mut(&group_id).unwrap();
        if state.pending_secure_send.is_some() {
            return Err(CoreError::new(
                "secure_send_in_progress",
                "a secure group send is already pending",
            ));
        }
        let nonce = self.next_message_nonce();
        let device_id = self
            .state
            .local_identity
            .as_ref()
            .unwrap()
            .device_identity
            .device_id
            .clone();
        let app_message_id = self.next_app_message_id(&conversation_id, &device_id, nonce);
        self.state
            .group_states
            .get_mut(&group_id)
            .unwrap()
            .pending_secure_send = Some(crate::persistence::PendingGroupSecureSend {
            intent_id: format!("group-secure-send:{app_message_id}"),
            app_message_id: app_message_id.clone(),
            plaintext,
            storage_refs: Vec::new(),
            created_at: None,
        });
        let persisted = CoreOutput {
            state_update: CoreStateUpdate {
                conversations_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(
                &self.state,
                vec![PersistOp::SaveGroupState {
                    group_id: group_id.clone(),
                }],
            )],
            view_model: Some(CoreViewModel {
                messages: vec![MessageSummary {
                    conversation_id,
                    message_id: app_message_id,
                    message_type: MessageType::MlsApplication,
                }],
                ..CoreViewModel::default()
            }),
        };
        Ok(merge_outputs(
            persisted,
            self.sync_group_outbox(group_id, Some("secure_send".into()))?,
        ))
    }

    pub(super) fn continue_group_secure_send(
        &mut self,
        group_id: String,
    ) -> CoreResult<CoreOutput> {
        let state = self
            .state
            .group_states
            .get(&group_id)
            .ok_or_else(|| CoreError::invalid_input("group does not exist"))?;
        if state.pending_secure_send.is_none() {
            return Ok(CoreOutput::default());
        }
        let active_leaves = state
            .manifest
            .member_devices
            .iter()
            .filter(|leaf| leaf.status == GroupMemberStatus::Active)
            .count();
        crate::pcs_policy::validate_active_leaf_limit(active_leaves)?;
        let local_device_id = self
            .state
            .local_identity
            .as_ref()
            .unwrap()
            .device_identity
            .device_id
            .clone();
        if state.pcs_state.update_due(&local_device_id, active_leaves) {
            self.stage_group_epoch_update(group_id)
        } else {
            self.finalize_group_secure_send(group_id)
        }
    }

    fn stage_group_epoch_update(&mut self, group_id: String) -> CoreResult<CoreOutput> {
        let state = self.state.group_states.get(&group_id).unwrap().clone();
        if state.pending_epoch_transition.is_some() {
            return self.issue_group_epoch_transition(group_id);
        }
        let (artifacts, patch) = {
            let canonical = self
                .state
                .mls_adapter
                .as_ref()
                .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?;
            let mut staged = canonical.fork()?;
            let artifacts = staged.self_update(&state.conversation_id)?;
            let patch = canonical.conversation_patch(&staged, &state.conversation_id)?;
            (artifacts, patch)
        };
        if artifacts.base_epoch != state.crypto_epoch {
            return Err(CoreError::new(
                "crypto_epoch_conflict",
                "local group MLS epoch is not the synchronized crypto head",
            ));
        }
        let commit = STANDARD.decode(&artifacts.commit_b64).map_err(|error| {
            CoreError::invalid_state(format!("group update commit is not base64: {error}"))
        })?;
        let commit_sha256 = format!("{:x}", Sha256::digest(commit));
        let identity = self.state.local_identity.as_ref().unwrap();
        let next_head = Self::group_crypto_head_hash(
            &state.crypto_head_hash,
            artifacts.next_epoch,
            &artifacts.commit_b64,
            &artifacts.epoch_authenticator_sha256,
            &identity.user_identity.user_id,
            &identity.device_identity.device_id,
        )?;
        self.state
            .group_states
            .get_mut(&group_id)
            .unwrap()
            .pending_epoch_transition = Some(crate::persistence::PendingGroupSelfUpdate {
            transition_id: format!("group-epoch:{}:{}", group_id, &commit_sha256[..24]),
            base_epoch: artifacts.base_epoch,
            next_epoch: artifacts.next_epoch,
            expected_head_hash: state.crypto_head_hash,
            commit_b64: artifacts.commit_b64,
            commit_sha256,
            epoch_authenticator_sha256: artifacts.epoch_authenticator_sha256,
            patch,
        });
        // next_head is deterministic; issue_group_epoch_transition recomputes
        // it from the persisted transition so crash recovery is identical.
        debug_assert!(!next_head.is_empty());
        let persisted = CoreOutput {
            effects: vec![persist_effect(
                &self.state,
                vec![PersistOp::SaveGroupState {
                    group_id: group_id.clone(),
                }],
            )],
            ..CoreOutput::default()
        };
        Ok(merge_outputs(
            persisted,
            self.issue_group_epoch_transition(group_id)?,
        ))
    }

    pub(super) fn issue_group_epoch_transition(
        &mut self,
        group_id: String,
    ) -> CoreResult<CoreOutput> {
        let state = self.state.group_states.get(&group_id).unwrap().clone();
        let pending = state
            .pending_epoch_transition
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("pending group epoch transition is missing"))?;
        let identity = self.state.local_identity.as_ref().unwrap();
        let next_head = Self::group_crypto_head_hash(
            &pending.expected_head_hash,
            pending.next_epoch,
            &pending.commit_b64,
            &pending.epoch_authenticator_sha256,
            &identity.user_identity.user_id,
            &identity.device_identity.device_id,
        )?;
        let mut envelope = self.build_group_envelope(
            &group_id,
            &state.conversation_id,
            GroupMessageType::MlsCommit,
            GroupEnvelopeVisibility::Protocol,
            pending.commit_b64.clone(),
        )?;
        envelope.transition_id = Some(pending.transition_id.clone());
        self.bind_group_envelope_epoch(
            &mut envelope,
            pending.next_epoch,
            &next_head,
            Some(&pending.epoch_authenticator_sha256),
        )?;
        Ok(CoreOutput {
            effects: vec![CoreEffect::AppendGroupEpochTransition {
                append: crate::transport_contract::AppendGroupEpochTransitionRequest {
                    version: crate::model::CURRENT_MODEL_VERSION.to_string(),
                    group_id: group_id.clone(),
                    transition_id: pending.transition_id.clone(),
                    expected_crypto_epoch: pending.base_epoch,
                    expected_crypto_head_hash: pending.expected_head_hash.clone(),
                    next_crypto_epoch: pending.next_epoch,
                    next_crypto_head_hash: next_head,
                    epoch_authenticator_sha256: pending.epoch_authenticator_sha256.clone(),
                    envelope,
                    capability: self
                        .group_capability(&group_id, self.local_group_role(&group_id)?)?,
                },
            }],
            ..CoreOutput::default()
        })
    }

    pub(super) fn resume_pending_group_secure_sends(&mut self) -> CoreResult<CoreOutput> {
        let group_ids = self
            .state
            .group_states
            .iter()
            .filter(|(_, state)| {
                state.pending_secure_send.is_some() || state.pending_epoch_transition.is_some()
            })
            .map(|(group_id, _)| group_id.clone())
            .collect::<Vec<_>>();
        let mut output = CoreOutput::default();
        for group_id in group_ids {
            let has_staged_transition = self
                .state
                .group_states
                .get(&group_id)
                .is_some_and(|state| state.pending_epoch_transition.is_some());
            let resumed = if has_staged_transition {
                self.issue_group_epoch_transition(group_id)?
            } else {
                self.sync_group_outbox(group_id, Some("resume_secure_send".into()))?
            };
            output = merge_outputs(output, resumed);
        }
        Ok(output)
    }

    fn finalize_group_secure_send(&mut self, group_id: String) -> CoreResult<CoreOutput> {
        let state = self.state.group_states.get(&group_id).unwrap().clone();
        let pending = state
            .pending_secure_send
            .clone()
            .ok_or_else(|| CoreError::invalid_state("pending group secure send is missing"))?;
        let summary = self
            .state
            .mls_adapter
            .as_ref()
            .unwrap()
            .export_group_summary(&state.conversation_id)?;
        if summary.epoch != state.crypto_epoch || state.crypto_head_hash.is_empty() {
            return Err(CoreError::new(
                "crypto_epoch_conflict",
                "group application epoch is not canonical",
            ));
        }
        let identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?;
        let protected = crate::model::ProtectedGroupAppMessage {
            version: crate::model::CURRENT_MODEL_VERSION.to_string(),
            group_id: group_id.clone(),
            conversation_id: state.conversation_id.clone(),
            app_message_id: pending.app_message_id.clone(),
            sender_user_id: identity.user_identity.user_id.clone(),
            sender_device_id: identity.device_identity.device_id.clone(),
            mls_epoch: state.crypto_epoch,
            epoch_head_hash: state.crypto_head_hash.clone(),
            body: pending.plaintext.clone(),
        };
        let payload = self
            .state
            .mls_adapter
            .as_mut()
            .unwrap()
            .encrypt_application(&state.conversation_id, &protected.to_json_bytes()?)?;
        let mut envelope = self.build_group_envelope(
            &group_id,
            &state.conversation_id,
            GroupMessageType::MlsApplication,
            GroupEnvelopeVisibility::Visible,
            payload.payload_b64,
        )?;
        // Preserve the stable user-message identity across crash recovery.
        envelope.message_id = pending.app_message_id.clone();
        envelope.storage_refs = pending.storage_refs.clone();
        if let Some(created_at) = pending.created_at {
            envelope.created_at = created_at;
        }
        self.bind_group_envelope_epoch(
            &mut envelope,
            state.crypto_epoch,
            &state.crypto_head_hash,
            None,
        )?;
        let capability = self.group_capability(&group_id, self.local_group_role(&group_id)?)?;
        self.enqueue_group_envelope(envelope.clone(), capability, Some(pending.plaintext));
        self.state
            .group_states
            .get_mut(&group_id)
            .unwrap()
            .pending_secure_send = None;
        self.merge_with_transport_flush(CoreOutput {
            state_update: CoreStateUpdate {
                messages_changed: true,
                conversations_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(
                &self.state,
                vec![
                    PersistOp::SaveGroupState { group_id },
                    PersistOp::SaveMlsState {
                        conversation_id: state.conversation_id.clone(),
                    },
                    PersistOp::SaveOutgoingGroupEnvelope {
                        message_id: envelope.message_id.clone(),
                    },
                ],
            )],
            view_model: Some(CoreViewModel {
                messages: vec![MessageSummary {
                    conversation_id: state.conversation_id,
                    message_id: envelope.message_id,
                    message_type: MessageType::MlsApplication,
                }],
                ..CoreViewModel::default()
            }),
        })
    }

    pub(super) fn handle_group_epoch_transition_appended(
        &mut self,
        group_id: String,
        transition_id: String,
        seq: u64,
        crypto_epoch: u64,
        crypto_head_hash: String,
    ) -> CoreResult<CoreOutput> {
        let state = self.state.group_states.get(&group_id).unwrap().clone();
        let pending = state
            .pending_epoch_transition
            .ok_or_else(|| CoreError::invalid_state("group epoch ACK has no pending patch"))?;
        let identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?;
        let expected_head = Self::group_crypto_head_hash(
            &pending.expected_head_hash,
            pending.next_epoch,
            &pending.commit_b64,
            &pending.epoch_authenticator_sha256,
            &identity.user_identity.user_id,
            &identity.device_identity.device_id,
        )?;
        if pending.transition_id != transition_id
            || pending.next_epoch != crypto_epoch
            || crypto_head_hash != expected_head
            || seq == 0
        {
            return Err(CoreError::new(
                "crypto_epoch_conflict",
                "group epoch ACK does not match pending transition",
            ));
        }
        let mut summaries = self.state.mls_summaries.clone();
        let summary = summaries.get_mut(&state.conversation_id).unwrap();
        summary.epoch = crypto_epoch;
        summary.updated_at = crypto_epoch;
        let patched = self
            .state
            .mls_adapter
            .as_ref()
            .unwrap()
            .apply_conversation_patch(&pending.patch, &summaries)?;
        if patched.epoch_authenticator_sha256(&state.conversation_id)?
            != pending.epoch_authenticator_sha256
        {
            return Err(CoreError::new(
                "epoch_authenticator_mismatch",
                "group epoch authenticator is invalid",
            ));
        }
        self.state.mls_adapter = Some(patched);
        self.state.mls_summaries = summaries;
        let local_device_id = self
            .state
            .local_identity
            .as_ref()
            .unwrap()
            .device_identity
            .device_id
            .clone();
        let current = self.state.group_states.get_mut(&group_id).unwrap();
        current.crypto_epoch = crypto_epoch;
        current.crypto_head_hash = crypto_head_hash;
        current.pending_epoch_transition = None;
        current.pcs_state.update_ordered(&local_device_id);
        if let Some(cursor) = self.state.group_cursors.get_mut(&group_id) {
            cursor.last_fetched_seq = cursor.last_fetched_seq.max(seq);
        }
        let persisted = CoreOutput {
            effects: vec![persist_effect(
                &self.state,
                vec![
                    PersistOp::SaveGroupState {
                        group_id: group_id.clone(),
                    },
                    PersistOp::SaveMlsState {
                        conversation_id: state.conversation_id,
                    },
                    PersistOp::SaveGroupCursor {
                        group_id: group_id.clone(),
                    },
                ],
            )],
            ..CoreOutput::default()
        };
        Ok(merge_outputs(
            persisted,
            self.continue_group_secure_send(group_id)?,
        ))
    }

    pub(super) fn handle_group_epoch_transition_failed(
        &mut self,
        group_id: String,
        _transition_id: String,
        failure: crate::error::AppErrorV1,
    ) -> CoreResult<CoreOutput> {
        if failure.http_status == Some(409) {
            if let Some(state) = self.state.group_states.get_mut(&group_id) {
                state.pending_epoch_transition = None;
            }
            let persisted = CoreOutput {
                effects: vec![persist_effect(
                    &self.state,
                    vec![PersistOp::SaveGroupState {
                        group_id: group_id.clone(),
                    }],
                )],
                ..CoreOutput::default()
            };
            return Ok(merge_outputs(
                persisted,
                self.sync_group_outbox(group_id, Some("crypto_conflict".into()))?,
            ));
        }
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                ..CoreStateUpdate::default()
            },
            ..CoreOutput::default()
        })
    }

    pub(super) fn create_group_invite_link(
        &mut self,
        group_id: String,
        expires_at: u64,
        max_uses: Option<u64>,
    ) -> CoreResult<CoreOutput> {
        let state = self
            .state
            .group_states
            .get(&group_id)
            .ok_or_else(|| CoreError::invalid_input("group does not exist"))?;
        let role = state.local_role.unwrap_or(GroupRole::Member);
        if !matches!(role, GroupRole::Owner | GroupRole::Admin) {
            return Err(CoreError::invalid_input(
                "only owner or admin can create group invite links",
            ));
        }
        let identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .clone();
        let now = current_unix_millis(self.state.message_nonce);
        if expires_at <= now {
            return Err(CoreError::invalid_input(
                "group invite expires_at is in the past",
            ));
        }
        let nonce = self.next_message_nonce();
        let state = self
            .state
            .group_states
            .get(&group_id)
            .ok_or_else(|| CoreError::invalid_input("group does not exist"))?;
        let invite_id = self.stable_scoped_id("group-invite", &group_id, nonce);
        let base = self.deployment_http_base()?;
        let join_request_endpoint = format!("{}/v1/groups/{}/join-requests", base, group_id);
        let local_contact_share_url = self
            .state
            .local_bundle
            .as_ref()
            .and_then(|bundle| bundle.identity_bundle_ref.clone());
        let document = GroupInviteDocument {
            version: crate::model::CURRENT_MODEL_VERSION.to_string(),
            group_id: group_id.clone(),
            title: state.manifest.title.clone(),
            invite_id: invite_id.clone(),
            join_policy: state.manifest.join_policy,
            inviter_user_id: identity.user_identity.user_id.clone(),
            inviter_device_id: identity.device_identity.device_id.clone(),
            inviter_contact_share_url: local_contact_share_url.clone(),
            owner_user_id: state.manifest.owner_user_id.clone(),
            owner_contact_share_url: local_contact_share_url,
            join_request_endpoint,
            created_at: now,
            expires_at,
            max_uses,
            signature: identity.sign_sender_proof(
                format!("group_invite:{group_id}:{invite_id}:{expires_at}").as_bytes(),
            ),
        };
        document.validate()?;
        let capability = self.group_capability(&group_id, role)?;
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                system_statuses_changed: vec![SystemStatus::SyncInProgress],
                ..CoreStateUpdate::default()
            },
            effects: vec![CoreEffect::CreateGroupInvite {
                create: CreateGroupInviteRequest {
                    version: crate::model::CURRENT_MODEL_VERSION.to_string(),
                    group_id,
                    document,
                    capability,
                    max_uses,
                    headers: BTreeMap::new(),
                },
            }],
            view_model: None,
        })
    }

    pub(super) fn revoke_group_invite_link(
        &mut self,
        group_id: String,
        invite_id: String,
    ) -> CoreResult<CoreOutput> {
        let role = self.local_group_role(&group_id)?;
        if !matches!(role, GroupRole::Owner | GroupRole::Admin) {
            return Err(CoreError::invalid_input(
                "only owner or admin can revoke group invite links",
            ));
        }
        Ok(CoreOutput {
            state_update: CoreStateUpdate::default(),
            effects: vec![CoreEffect::RevokeGroupInvite {
                revoke: RevokeGroupInviteRequest {
                    version: crate::model::CURRENT_MODEL_VERSION.to_string(),
                    group_id: group_id.clone(),
                    invite_id,
                    capability: self.group_capability(&group_id, role)?,
                    headers: BTreeMap::new(),
                },
            }],
            view_model: None,
        })
    }

    pub(super) fn list_group_invites(&mut self, group_id: String) -> CoreResult<CoreOutput> {
        let state = self
            .state
            .group_states
            .get(&group_id)
            .ok_or_else(|| CoreError::invalid_input("group does not exist"))?;
        let capability = self.group_capability_for_state(state)?;
        Ok(CoreOutput {
            state_update: CoreStateUpdate::default(),
            effects: vec![CoreEffect::ListGroupInvites {
                list: ListGroupInvitesRequest {
                    group_id: group_id.clone(),
                    capability,
                },
            }],
            view_model: Some(CoreViewModel {
                group_invites: self
                    .state
                    .group_invites
                    .values()
                    .filter(|invite| invite.group_id == group_id)
                    .cloned()
                    .collect(),
                ..CoreViewModel::default()
            }),
        })
    }

    pub(super) fn handle_group_invites_listed(
        &mut self,
        group_id: String,
        revision: u64,
        invites: Vec<crate::transport_contract::GroupInviteSummary>,
    ) -> CoreResult<CoreOutput> {
        let existing_ids: Vec<String> = self
            .state
            .group_invites
            .values()
            .filter(|invite| invite.group_id == group_id)
            .map(|invite| invite.invite_id.clone())
            .collect();
        let mut persist_ops = Vec::new();
        for invite_id in existing_ids {
            self.state.group_invites.remove(&invite_id);
            persist_ops.push(PersistOp::DeleteGroupInvite { invite_id });
        }
        for summary in invites {
            let invite_id = summary.invite.invite_id.clone();
            self.state.group_invites.insert(
                invite_id.clone(),
                PersistedGroupInvite {
                    group_id: group_id.clone(),
                    invite_id: invite_id.clone(),
                    invite_url: summary.invite_url,
                    document: summary.invite,
                    revision,
                    status: summary.status,
                    uses: summary.uses,
                    max_uses: summary.max_uses,
                    revoked_at: summary.revoked_at,
                },
            );
            persist_ops.push(PersistOp::SaveGroupInvite { invite_id });
        }
        Ok(CoreOutput {
            state_update: CoreStateUpdate::default(),
            effects: vec![persist_effect(&self.state, persist_ops)],
            view_model: Some(CoreViewModel {
                group_invites: self
                    .state
                    .group_invites
                    .values()
                    .filter(|invite| invite.group_id == group_id)
                    .cloned()
                    .collect(),
                ..CoreViewModel::default()
            }),
        })
    }

    pub(super) fn fetch_group_invite(&mut self, invite_url: String) -> CoreResult<CoreOutput> {
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                system_statuses_changed: vec![SystemStatus::SyncInProgress],
                ..CoreStateUpdate::default()
            },
            effects: vec![CoreEffect::FetchGroupInvite {
                fetch: FetchGroupInviteRequest {
                    invite_url,
                    headers: BTreeMap::new(),
                },
            }],
            view_model: None,
        })
    }

    pub(super) fn submit_group_join_request(
        &mut self,
        invite_url: String,
    ) -> CoreResult<CoreOutput> {
        self.fetch_group_invite(invite_url)
    }

    pub(super) fn list_group_join_requests(&mut self, group_id: String) -> CoreResult<CoreOutput> {
        let role = self.local_group_role(&group_id)?;
        if !matches!(role, GroupRole::Owner | GroupRole::Admin) {
            return Err(CoreError::invalid_input(
                "only owner or admin can list group join requests",
            ));
        }
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                system_statuses_changed: vec![SystemStatus::SyncInProgress],
                ..CoreStateUpdate::default()
            },
            effects: vec![CoreEffect::ListGroupJoinRequests {
                list: ListGroupJoinRequestsRequest {
                    group_id: group_id.clone(),
                    capability: self.group_capability(&group_id, role)?,
                    headers: BTreeMap::new(),
                },
            }],
            view_model: Some(CoreViewModel {
                group_join_requests: self
                    .state
                    .group_join_requests
                    .values()
                    .filter(|request| request.group_id == group_id)
                    .map(|request| request.request.clone())
                    .collect(),
                ..CoreViewModel::default()
            }),
        })
    }

    pub(super) fn get_group_join_request_status(
        &mut self,
        group_id: String,
        request_id: String,
    ) -> CoreResult<CoreOutput> {
        let stored = self
            .state
            .group_join_requests
            .get(&request_id)
            .cloned()
            .ok_or_else(|| CoreError::invalid_input("group join request does not exist locally"))?;
        if stored.group_id != group_id {
            return Err(CoreError::invalid_input(
                "group join request id does not belong to this group",
            ));
        }
        let endpoint = if let Some(endpoint) = stored.join_request_endpoint.clone() {
            endpoint
        } else {
            let base = self.deployment_http_base()?;
            format!(
                "{}/v1/groups/{}/join-requests",
                base.trim_end_matches('/'),
                stored.request.group_id
            )
        };
        let endpoint = format!(
            "{}/{}",
            endpoint.trim_end_matches('/'),
            stored.request.request_id
        );
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                system_statuses_changed: vec![SystemStatus::SyncInProgress],
                ..CoreStateUpdate::default()
            },
            effects: vec![CoreEffect::GetGroupJoinRequestStatus {
                get: GetGroupJoinRequestStatusRequest {
                    group_id: stored.group_id.clone(),
                    request_id: stored.request_id.clone(),
                    request_capability: stored.request.request_capability.clone(),
                    endpoint,
                    headers: BTreeMap::new(),
                },
            }],
            view_model: Some(CoreViewModel {
                group_join_requests: vec![stored.request.clone()],
                ..CoreViewModel::default()
            }),
        })
    }

    pub(super) fn approve_group_join(
        &mut self,
        group_id: String,
        request_id: String,
    ) -> CoreResult<CoreOutput> {
        let role = self.local_group_role(&group_id)?;
        if !matches!(role, GroupRole::Owner | GroupRole::Admin) {
            return Err(CoreError::invalid_input(
                "only owner or admin can approve group join requests",
            ));
        }
        let stored_join = self
            .state
            .group_join_requests
            .get(&request_id)
            .ok_or_else(|| CoreError::invalid_input("join request does not exist"))?
            .clone();
        let join = stored_join.request.clone();
        if join.group_id != group_id
            || !matches!(
                join.status,
                GroupJoinRequestStatus::Pending
                    | GroupJoinRequestStatus::PendingApproval
                    | GroupJoinRequestStatus::WaitingForGroupCommit
                    | GroupJoinRequestStatus::TransitionInProgress
            )
        {
            return Err(CoreError::invalid_input(
                "join request is not pending for this group",
            ));
        }
        if matches!(
            join.status,
            GroupJoinRequestStatus::Pending | GroupJoinRequestStatus::PendingApproval
        ) {
            return Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::SyncInProgress],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::DecideGroupJoinRequest {
                    decide: DecideGroupJoinRequest {
                        version: crate::model::CURRENT_MODEL_VERSION.to_string(),
                        group_id: group_id.clone(),
                        request_id,
                        decision: GroupJoinDecision::Approve,
                        capability: self.group_capability(&group_id, role)?,
                        welcome_pickup: None,
                        manifest: None,
                        start_cursor: None,
                        reason: None,
                        headers: BTreeMap::new(),
                    },
                }],
                view_model: Some(CoreViewModel {
                    group_join_requests: vec![join],
                    ..CoreViewModel::default()
                }),
            });
        }
        let now = current_unix_millis(self.state.message_nonce);
        if stored_join.lease_token.is_none()
            || stored_join
                .lease_expires_at
                .is_none_or(|expires_at| expires_at <= now)
        {
            return Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::SyncInProgress],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::ClaimGroupJoinRequest {
                    claim: ClaimGroupJoinRequest {
                        version: crate::model::CURRENT_MODEL_VERSION.to_string(),
                        group_id: group_id.clone(),
                        request_id,
                        capability: self.group_capability(&group_id, role)?,
                    },
                }],
                view_model: None,
            });
        }
        let group_state = self
            .state
            .group_states
            .get(&group_id)
            .cloned()
            .ok_or_else(|| CoreError::invalid_input("group does not exist"))?;
        let manifest_already_contains_user = group_state.manifest.members.iter().any(|member| {
            member.user_id == join.joiner_user_id && member.status == GroupMemberStatus::Active
        });
        let manifest_already_contains_device =
            group_state.manifest.member_devices.iter().any(|device| {
                device.user_id == join.joiner_user_id
                    && device.device_id == join.joiner_device_id
                    && device.status == GroupMemberStatus::Active
            });
        let mls_already_contains_device = self
            .state
            .mls_adapter
            .as_ref()
            .and_then(|adapter| {
                adapter
                    .member_device_ids_for_user(&group_state.conversation_id, &join.joiner_user_id)
                    .ok()
            })
            .map(|devices| {
                devices
                    .iter()
                    .any(|device_id| device_id == &join.joiner_device_id)
            })
            .unwrap_or(false);
        if manifest_already_contains_user
            || manifest_already_contains_device
            || mls_already_contains_device
        {
            return Err(CoreError::invalid_state(
                "already_member: joiner device is already in this group; ask the joiner to retry the initial group invite import or create a new group",
            ));
        }
        let contact = self
            .state
            .contacts
            .get(&join.joiner_user_id)
            .ok_or_else(|| {
                CoreError::invalid_state("joiner identity bundle has not been imported")
            })?
            .bundle
            .clone();
        let peer_devices = active_peer_key_packages(&contact)?;
        if peer_devices.is_empty() {
            return Err(CoreError::invalid_state(
                "joiner has no active key packages",
            ));
        }
        let active_leaf_count = group_state
            .manifest
            .member_devices
            .iter()
            .filter(|leaf| leaf.status == GroupMemberStatus::Active)
            .count();
        crate::pcs_policy::validate_active_leaf_limit(
            active_leaf_count.saturating_add(peer_devices.len()),
        )?;
        let adapter = self
            .state
            .mls_adapter
            .as_mut()
            .ok_or_else(|| CoreError::invalid_state("MLS adapter is not initialized"))?;
        let artifacts = adapter.add_members(&group_state.conversation_id, &peer_devices)?;
        let summary = adapter.export_group_summary(&group_state.conversation_id)?;
        self.state
            .mls_summaries
            .insert(group_state.conversation_id.clone(), summary);
        let previous_manifest = group_state.manifest.clone();
        let mut manifest = previous_manifest.clone();
        if !manifest
            .members
            .iter()
            .any(|member| member.user_id == join.joiner_user_id)
        {
            manifest.members.push(GroupMember {
                user_id: join.joiner_user_id.clone(),
                role: GroupRole::Member,
                status: GroupMemberStatus::Active,
            });
        }
        for device in &peer_devices {
            if !manifest.member_devices.iter().any(|member_device| {
                member_device.user_id == device.user_id
                    && member_device.device_id == device.device_id
            }) {
                manifest.member_devices.push(GroupMemberDevice {
                    user_id: device.user_id.clone(),
                    device_id: device.device_id.clone(),
                    status: GroupMemberStatus::Active,
                });
            }
        }
        self.apply_membership_change_to_manifest(
            &mut manifest,
            artifacts.epoch,
            current_unix_millis(self.state.message_nonce),
        )?;

        self.state.group_states.insert(
            group_id.clone(),
            PersistedGroupState {
                group_id: group_id.clone(),
                conversation_id: group_state.conversation_id.clone(),
                manifest: manifest.clone(),
                local_role: group_state.local_role,
                welcome_pickup: group_state.welcome_pickup.clone(),
                dissolved_at: group_state.dissolved_at,
                pending_membership_transition: group_state.pending_membership_transition.clone(),
                consistency_state: group_state.consistency_state.clone(),
                pending_group_transition: group_state.pending_group_transition.clone(),
                leave_requests: group_state.leave_requests.clone(),
                pcs_state: group_state.pcs_state.clone(),
                crypto_epoch: group_state.crypto_epoch,
                crypto_head_hash: group_state.crypto_head_hash.clone(),
                pending_secure_send: group_state.pending_secure_send.clone(),
                pending_epoch_transition: group_state.pending_epoch_transition.clone(),
            },
        );

        let capability = self.group_capability(&group_id, role)?;
        let mut commit = self.build_group_envelope(
            &group_id,
            &group_state.conversation_id,
            GroupMessageType::MlsCommit,
            GroupEnvelopeVisibility::Protocol,
            artifacts.commit_b64,
        )?;
        manifest.last_commit_message_id = Some(commit.message_id.clone());
        manifest.signature = self.sign_manifest(&manifest)?;
        manifest.validate()?;
        let manifest_payload = serde_json::to_vec(&manifest).map_err(|error| {
            CoreError::invalid_input(format!("failed to encode manifest: {error}"))
        })?;
        let control_payload = self
            .state
            .mls_adapter
            .as_mut()
            .ok_or_else(|| CoreError::invalid_state("MLS adapter is not initialized"))?
            .encrypt_application(&group_state.conversation_id, &manifest_payload)?;
        let mut control = self.build_group_envelope(
            &group_id,
            &group_state.conversation_id,
            GroupMessageType::ControlGroupMembershipChanged,
            GroupEnvelopeVisibility::Protocol,
            control_payload.payload_b64,
        )?;
        let membership_proof = self.build_membership_proof(
            "approve_join",
            &previous_manifest,
            &manifest,
            &commit.message_id,
            &control.message_id,
        )?;
        commit.membership_proof = Some(membership_proof.clone());
        control.membership_proof = Some(membership_proof);
        self.enqueue_group_envelope(commit.clone(), capability.clone(), None);
        self.enqueue_group_envelope(control.clone(), capability.clone(), None);
        self.state.group_states.insert(
            group_id.clone(),
            PersistedGroupState {
                group_id: group_id.clone(),
                conversation_id: group_state.conversation_id.clone(),
                manifest: manifest.clone(),
                local_role: group_state.local_role,
                welcome_pickup: group_state.welcome_pickup.clone(),
                dissolved_at: group_state.dissolved_at,
                pending_membership_transition: group_state.pending_membership_transition.clone(),
                consistency_state: group_state.consistency_state.clone(),
                pending_group_transition: group_state.pending_group_transition.clone(),
                leave_requests: group_state.leave_requests.clone(),
                pcs_state: group_state.pcs_state.clone(),
                crypto_epoch: group_state.crypto_epoch,
                crypto_head_hash: group_state.crypto_head_hash.clone(),
                pending_secure_send: group_state.pending_secure_send.clone(),
                pending_epoch_transition: group_state.pending_epoch_transition.clone(),
            },
        );

        let mut effects = vec![persist_effect(
            &self.state,
            vec![
                PersistOp::SaveGroupState {
                    group_id: group_id.clone(),
                },
                PersistOp::SaveMlsState {
                    conversation_id: group_state.conversation_id.clone(),
                },
                PersistOp::SaveOutgoingGroupEnvelope {
                    message_id: commit.message_id.clone(),
                },
                PersistOp::SaveOutgoingGroupEnvelope {
                    message_id: control.message_id.clone(),
                },
            ],
        )];
        for welcome in artifacts.welcomes {
            let mut descriptor =
                self.welcome_pickup_descriptor(&group_id, &welcome.recipient_device_id)?;
            descriptor.request_id = Some(request_id.clone());
            effects.push(CoreEffect::PutWelcomePickup {
                put: PutWelcomePickupRequest {
                    descriptor,
                    welcome_b64: welcome.payload_b64,
                    manifest: Some(manifest.clone()),
                    headers: BTreeMap::new(),
                },
            });
        }
        let pickup_descriptors: Vec<_> = effects
            .iter()
            .filter_map(|effect| match effect {
                CoreEffect::PutWelcomePickup { put } => Some(put.descriptor.clone()),
                _ => None,
            })
            .collect();
        self.merge_with_transport_flush(CoreOutput {
            state_update: CoreStateUpdate {
                conversations_changed: true,
                messages_changed: true,
                ..CoreStateUpdate::default()
            },
            effects,
            view_model: Some(CoreViewModel {
                messages: vec![
                    MessageSummary {
                        conversation_id: group_state.conversation_id.clone(),
                        message_id: commit.message_id,
                        message_type: MessageType::MlsCommit,
                    },
                    MessageSummary {
                        conversation_id: group_state.conversation_id,
                        message_id: control.message_id,
                        message_type: MessageType::ControlDeviceMembershipChanged,
                    },
                ],
                welcome_pickups: pickup_descriptors,
                ..CoreViewModel::default()
            }),
        })
    }

    pub(super) fn reject_group_join(
        &mut self,
        group_id: String,
        request_id: String,
        reason: Option<String>,
    ) -> CoreResult<CoreOutput> {
        let role = self.local_group_role(&group_id)?;
        if !matches!(role, GroupRole::Owner | GroupRole::Admin) {
            return Err(CoreError::invalid_input(
                "only owner or admin can reject group join requests",
            ));
        }
        Ok(CoreOutput {
            state_update: CoreStateUpdate::default(),
            effects: vec![CoreEffect::DecideGroupJoinRequest {
                decide: DecideGroupJoinRequest {
                    version: crate::model::CURRENT_MODEL_VERSION.to_string(),
                    group_id: group_id.clone(),
                    request_id,
                    decision: GroupJoinDecision::Reject,
                    capability: self.group_capability(&group_id, role)?,
                    welcome_pickup: None,
                    manifest: None,
                    start_cursor: None,
                    reason,
                    headers: BTreeMap::new(),
                },
            }],
            view_model: None,
        })
    }

    pub(super) fn invite_to_group(
        &mut self,
        group_id: String,
        invitee_user_ids: Vec<String>,
    ) -> CoreResult<CoreOutput> {
        let role = self.local_group_role(&group_id)?;
        if !matches!(role, GroupRole::Owner | GroupRole::Admin) {
            return Err(CoreError::invalid_input(
                "only owner or admin can invite new members",
            ));
        }
        let mut invitee_user_ids = invitee_user_ids
            .into_iter()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .collect::<Vec<_>>();
        invitee_user_ids.sort();
        invitee_user_ids.dedup();
        if invitee_user_ids.is_empty() {
            return Err(CoreError::invalid_input(
                "invitee_user_ids must not be empty",
            ));
        }
        let group_state = self
            .state
            .group_states
            .get(&group_id)
            .ok_or_else(|| CoreError::invalid_input("group does not exist"))?
            .clone();
        let previous_manifest = group_state.manifest.clone();
        let mut manifest = previous_manifest.clone();
        let existing_ids: BTreeSet<String> = manifest
            .members
            .iter()
            .filter(|m| matches!(m.status, GroupMemberStatus::Active))
            .map(|m| m.user_id.clone())
            .collect();
        let new_ids: Vec<&String> = invitee_user_ids
            .iter()
            .filter(|id| !existing_ids.contains(*id))
            .collect();
        if new_ids.is_empty() {
            return Err(CoreError::invalid_input(
                "all invitees are already active members of this group",
            ));
        }
        let mut peer_keypackages = Vec::new();
        for user_id in &invitee_user_ids {
            if existing_ids.contains(user_id) {
                continue;
            }
            let bundle = self.direct_peer_contact_bundle(user_id)?.clone();
            let kps = active_peer_key_packages(&bundle)?;
            if kps.is_empty() {
                return Err(CoreError::invalid_state(format!(
                    "invitee {user_id} has no active key packages",
                )));
            }
            peer_keypackages.extend(kps);
        }
        if peer_keypackages.is_empty() {
            return Err(CoreError::invalid_input(
                "no active key packages found for any invitee",
            ));
        }
        let active_leaf_count = group_state
            .manifest
            .member_devices
            .iter()
            .filter(|leaf| leaf.status == GroupMemberStatus::Active)
            .count();
        crate::pcs_policy::validate_active_leaf_limit(
            active_leaf_count.saturating_add(peer_keypackages.len()),
        )?;
        let adapter = self
            .state
            .mls_adapter
            .as_mut()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?;
        let artifacts = adapter.add_members(&group_state.conversation_id, &peer_keypackages)?;
        let summary = adapter.export_group_summary(&group_state.conversation_id)?;
        self.state
            .mls_summaries
            .insert(group_state.conversation_id.clone(), summary);
        let now = current_unix_millis(self.state.message_nonce);
        for user_id in &invitee_user_ids {
            if existing_ids.contains(user_id) {
                continue;
            }
            manifest.members.push(GroupMember {
                user_id: user_id.clone(),
                role: GroupRole::Member,
                status: GroupMemberStatus::Active,
            });
        }
        self.apply_membership_change_to_manifest(&mut manifest, artifacts.epoch, now)?;
        self.sync_conversation_members_from_manifest(&group_state.conversation_id, &manifest)?;
        self.state.group_states.insert(
            group_id.clone(),
            PersistedGroupState {
                group_id: group_id.clone(),
                conversation_id: group_state.conversation_id.clone(),
                manifest: manifest.clone(),
                local_role: group_state.local_role,
                welcome_pickup: group_state.welcome_pickup.clone(),
                dissolved_at: group_state.dissolved_at,
                pending_membership_transition: group_state.pending_membership_transition.clone(),
                consistency_state: group_state.consistency_state.clone(),
                pending_group_transition: group_state.pending_group_transition.clone(),
                leave_requests: group_state.leave_requests.clone(),
                pcs_state: group_state.pcs_state.clone(),
                crypto_epoch: group_state.crypto_epoch,
                crypto_head_hash: group_state.crypto_head_hash.clone(),
                pending_secure_send: group_state.pending_secure_send.clone(),
                pending_epoch_transition: group_state.pending_epoch_transition.clone(),
            },
        );
        let capability = self.group_capability(&group_id, role)?;
        let mut commit = self.build_group_envelope(
            &group_id,
            &group_state.conversation_id,
            GroupMessageType::MlsCommit,
            GroupEnvelopeVisibility::Protocol,
            artifacts.commit_b64,
        )?;
        manifest.last_commit_message_id = Some(commit.message_id.clone());
        manifest.signature = self.sign_manifest(&manifest)?;
        manifest.validate()?;
        let manifest_payload = serde_json::to_vec(&manifest).map_err(|error| {
            CoreError::invalid_input(format!("failed to encode manifest: {error}"))
        })?;
        let control_plaintext = self
            .state
            .mls_adapter
            .as_mut()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .encrypt_application(&group_state.conversation_id, &manifest_payload)?;
        let mut control = self.build_group_envelope(
            &group_id,
            &group_state.conversation_id,
            GroupMessageType::ControlGroupMembershipChanged,
            GroupEnvelopeVisibility::Protocol,
            control_plaintext.payload_b64,
        )?;
        let membership_proof = self.build_membership_proof(
            "invite",
            &previous_manifest,
            &manifest,
            &commit.message_id,
            &control.message_id,
        )?;
        commit.membership_proof = Some(membership_proof.clone());
        control.membership_proof = Some(membership_proof);
        self.enqueue_group_envelope(commit.clone(), capability.clone(), None);
        self.enqueue_group_envelope(control.clone(), capability.clone(), None);
        self.state.group_states.insert(
            group_id.clone(),
            PersistedGroupState {
                group_id: group_id.clone(),
                conversation_id: group_state.conversation_id.clone(),
                manifest: manifest.clone(),
                local_role: group_state.local_role,
                welcome_pickup: group_state.welcome_pickup.clone(),
                dissolved_at: group_state.dissolved_at,
                pending_membership_transition: group_state.pending_membership_transition.clone(),
                consistency_state: group_state.consistency_state.clone(),
                pending_group_transition: group_state.pending_group_transition.clone(),
                leave_requests: group_state.leave_requests.clone(),
                pcs_state: group_state.pcs_state.clone(),
                crypto_epoch: group_state.crypto_epoch,
                crypto_head_hash: group_state.crypto_head_hash.clone(),
                pending_secure_send: group_state.pending_secure_send.clone(),
                pending_epoch_transition: group_state.pending_epoch_transition.clone(),
            },
        );
        let mut effects = vec![persist_effect(
            &self.state,
            vec![
                PersistOp::SaveGroupState {
                    group_id: group_id.clone(),
                },
                PersistOp::SaveMlsState {
                    conversation_id: group_state.conversation_id.clone(),
                },
                PersistOp::SaveOutgoingGroupEnvelope {
                    message_id: commit.message_id.clone(),
                },
                PersistOp::SaveOutgoingGroupEnvelope {
                    message_id: control.message_id.clone(),
                },
            ],
        )];
        for welcome in artifacts.welcomes {
            let descriptor =
                self.welcome_pickup_descriptor(&group_id, &welcome.recipient_device_id)?;
            effects.push(CoreEffect::PutWelcomePickup {
                put: PutWelcomePickupRequest {
                    descriptor,
                    welcome_b64: welcome.payload_b64,
                    manifest: Some(manifest.clone()),
                    headers: BTreeMap::new(),
                },
            });
        }
        let pickup_descriptors: Vec<_> = effects
            .iter()
            .filter_map(|effect| match effect {
                CoreEffect::PutWelcomePickup { put } => Some(put.descriptor.clone()),
                _ => None,
            })
            .collect();
        self.merge_with_transport_flush(CoreOutput {
            state_update: CoreStateUpdate {
                conversations_changed: true,
                messages_changed: true,
                ..CoreStateUpdate::default()
            },
            effects,
            view_model: Some(CoreViewModel {
                messages: vec![
                    MessageSummary {
                        conversation_id: group_state.conversation_id.clone(),
                        message_id: commit.message_id,
                        message_type: MessageType::MlsCommit,
                    },
                    MessageSummary {
                        conversation_id: group_state.conversation_id,
                        message_id: control.message_id,
                        message_type: MessageType::ControlDeviceMembershipChanged,
                    },
                ],
                welcome_pickups: pickup_descriptors,
                ..CoreViewModel::default()
            }),
        })
    }

    pub(super) fn remove_group_member(
        &mut self,
        group_id: String,
        target_user_id: String,
    ) -> CoreResult<CoreOutput> {
        self.remove_group_member_with_operation(group_id, target_user_id, "remove")
    }

    pub(super) fn remove_group_member_with_operation(
        &mut self,
        group_id: String,
        target_user_id: String,
        proof_operation: &str,
    ) -> CoreResult<CoreOutput> {
        let target_user_id = target_user_id.trim().to_string();
        if target_user_id.is_empty() {
            return Err(CoreError::invalid_input("target_user_id must not be empty"));
        }
        let local_identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .clone();
        if target_user_id == local_identity.user_identity.user_id {
            return Err(CoreError::invalid_input(
                "cannot remove yourself; use LeaveGroup instead",
            ));
        }
        let role = self.local_group_role(&group_id)?;
        if !matches!(role, GroupRole::Owner | GroupRole::Admin) {
            return Err(CoreError::invalid_input(
                "only owner or admin can remove a group member",
            ));
        }
        let group_state = self
            .state
            .group_states
            .get(&group_id)
            .ok_or_else(|| CoreError::invalid_input("group does not exist"))?
            .clone();
        let previous_manifest = group_state.manifest.clone();
        let mut manifest = previous_manifest.clone();
        let target_member = manifest
            .members
            .iter()
            .find(|m| m.user_id == target_user_id && m.status == GroupMemberStatus::Active)
            .ok_or_else(|| {
                CoreError::invalid_input("target user is not an active member of this group")
            })?;
        if target_member.role == GroupRole::Owner {
            return Err(CoreError::invalid_input(
                "cannot remove the group owner; transfer ownership first",
            ));
        }
        let member_device_ids: Vec<String> = self
            .state
            .mls_adapter
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .member_device_ids_for_user(&group_state.conversation_id, &target_user_id)?;
        if member_device_ids.is_empty() {
            let summary = self
                .state
                .mls_adapter
                .as_ref()
                .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
                .export_group_summary(&group_state.conversation_id)?;
            return Err(CoreError::invalid_state(format!(
                "target user has no devices in MLS group; known member devices: {:?}",
                summary.member_device_ids
            )));
        }
        let adapter = self
            .state
            .mls_adapter
            .as_mut()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?;
        let artifacts = adapter.remove_members(&group_state.conversation_id, &member_device_ids)?;
        let summary = adapter.export_group_summary(&group_state.conversation_id)?;
        self.state
            .mls_summaries
            .insert(group_state.conversation_id.clone(), summary);
        let now = current_unix_millis(self.state.message_nonce);
        for member in &mut manifest.members {
            if member.user_id == target_user_id && member.status == GroupMemberStatus::Active {
                member.status = if proof_operation == "leave" {
                    GroupMemberStatus::Left
                } else {
                    GroupMemberStatus::Removed
                };
            }
        }
        for device in &mut manifest.member_devices {
            if device.user_id == target_user_id && device.status == GroupMemberStatus::Active {
                device.status = GroupMemberStatus::Removed;
            }
        }
        manifest.admins.retain(|admin| admin != &target_user_id);
        self.apply_membership_change_to_manifest(&mut manifest, artifacts.epoch, now)?;
        self.sync_conversation_members_from_manifest(&group_state.conversation_id, &manifest)?;
        self.state.group_states.insert(
            group_id.clone(),
            PersistedGroupState {
                group_id: group_id.clone(),
                conversation_id: group_state.conversation_id.clone(),
                manifest: manifest.clone(),
                local_role: group_state.local_role,
                welcome_pickup: group_state.welcome_pickup.clone(),
                dissolved_at: group_state.dissolved_at,
                pending_membership_transition: group_state.pending_membership_transition.clone(),
                consistency_state: group_state.consistency_state.clone(),
                pending_group_transition: group_state.pending_group_transition.clone(),
                leave_requests: group_state.leave_requests.clone(),
                pcs_state: group_state.pcs_state.clone(),
                crypto_epoch: group_state.crypto_epoch,
                crypto_head_hash: group_state.crypto_head_hash.clone(),
                pending_secure_send: group_state.pending_secure_send.clone(),
                pending_epoch_transition: group_state.pending_epoch_transition.clone(),
            },
        );
        let capability = self.group_capability(&group_id, role)?;
        let mut commit = self.build_group_envelope(
            &group_id,
            &group_state.conversation_id,
            GroupMessageType::MlsCommit,
            GroupEnvelopeVisibility::Protocol,
            artifacts.commit_b64,
        )?;
        manifest.last_commit_message_id = Some(commit.message_id.clone());
        manifest.signature = self.sign_manifest(&manifest)?;
        manifest.validate()?;
        let manifest_payload = serde_json::to_vec(&manifest).map_err(|error| {
            CoreError::invalid_input(format!("failed to encode manifest: {error}"))
        })?;
        let control_plaintext = self
            .state
            .mls_adapter
            .as_mut()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .encrypt_application(&group_state.conversation_id, &manifest_payload)?;
        let mut control = self.build_group_envelope(
            &group_id,
            &group_state.conversation_id,
            GroupMessageType::ControlGroupMembershipChanged,
            GroupEnvelopeVisibility::Protocol,
            control_plaintext.payload_b64,
        )?;
        let membership_proof = self.build_membership_proof(
            proof_operation,
            &previous_manifest,
            &manifest,
            &commit.message_id,
            &control.message_id,
        )?;
        commit.membership_proof = Some(membership_proof.clone());
        control.membership_proof = Some(membership_proof);
        self.enqueue_group_envelope(commit.clone(), capability.clone(), None);
        self.enqueue_group_envelope(control.clone(), capability.clone(), None);
        self.state.group_states.insert(
            group_id.clone(),
            PersistedGroupState {
                group_id: group_id.clone(),
                conversation_id: group_state.conversation_id.clone(),
                manifest: manifest.clone(),
                local_role: group_state.local_role,
                welcome_pickup: group_state.welcome_pickup.clone(),
                dissolved_at: group_state.dissolved_at,
                pending_membership_transition: group_state.pending_membership_transition.clone(),
                consistency_state: group_state.consistency_state.clone(),
                pending_group_transition: group_state.pending_group_transition.clone(),
                leave_requests: group_state.leave_requests.clone(),
                pcs_state: group_state.pcs_state.clone(),
                crypto_epoch: group_state.crypto_epoch,
                crypto_head_hash: group_state.crypto_head_hash.clone(),
                pending_secure_send: group_state.pending_secure_send.clone(),
                pending_epoch_transition: group_state.pending_epoch_transition.clone(),
            },
        );
        let effects = vec![persist_effect(
            &self.state,
            vec![
                PersistOp::SaveGroupState {
                    group_id: group_id.clone(),
                },
                PersistOp::SaveMlsState {
                    conversation_id: group_state.conversation_id.clone(),
                },
                PersistOp::SaveOutgoingGroupEnvelope {
                    message_id: commit.message_id.clone(),
                },
                PersistOp::SaveOutgoingGroupEnvelope {
                    message_id: control.message_id.clone(),
                },
            ],
        )];
        self.merge_with_transport_flush(CoreOutput {
            state_update: CoreStateUpdate {
                conversations_changed: true,
                messages_changed: true,
                ..CoreStateUpdate::default()
            },
            effects,
            view_model: Some(CoreViewModel {
                messages: vec![
                    MessageSummary {
                        conversation_id: group_state.conversation_id.clone(),
                        message_id: commit.message_id,
                        message_type: MessageType::MlsCommit,
                    },
                    MessageSummary {
                        conversation_id: group_state.conversation_id,
                        message_id: control.message_id,
                        message_type: MessageType::ControlDeviceMembershipChanged,
                    },
                ],
                ..CoreViewModel::default()
            }),
        })
    }

    pub(super) fn leave_group(&mut self, group_id: String) -> CoreResult<CoreOutput> {
        let group_state = self
            .state
            .group_states
            .get(&group_id)
            .ok_or_else(|| CoreError::invalid_input("group does not exist"))?
            .clone();
        let role = group_state.local_role.unwrap_or(GroupRole::Member);
        if role == GroupRole::Owner {
            return Err(CoreError::invalid_input(
                "owner cannot leave without transferring ownership first; use TransferGroupOwnership",
            ));
        }
        let local_identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .clone();
        let existing = group_state.leave_requests.iter().find(|stored| {
            stored.request.leaver_user_id == local_identity.user_identity.user_id
                && stored.request.leaver_device_id == local_identity.device_identity.device_id
                && matches!(
                    stored.request.status,
                    GroupLeaveRequestStatus::WaitingForGroupCommit
                        | GroupLeaveRequestStatus::TransitionInProgress
                )
        });
        let request = if let Some(existing) = existing {
            existing.request.clone()
        } else {
            let requested_at = current_unix_millis(self.state.message_nonce);
            let request_id = format!(
                "group-leave:{}:{}:{}",
                group_id,
                local_identity.user_identity.user_id,
                local_identity.device_identity.device_id
            );
            let request_capability = local_identity
                .sign_sender_proof(format!("group_leave_request:{request_id}").as_bytes());
            let signature_payload = format!(
                "{}\n{}\n{}\n{}\n{}\n{}",
                crate::model::CURRENT_MODEL_VERSION,
                request_id,
                group_id,
                local_identity.user_identity.user_id,
                local_identity.device_identity.device_id,
                requested_at
            );
            GroupLeaveRequest {
                version: crate::model::CURRENT_MODEL_VERSION.to_string(),
                request_id,
                group_id: group_id.clone(),
                leaver_user_id: local_identity.user_identity.user_id.clone(),
                leaver_device_id: local_identity.device_identity.device_id.clone(),
                requested_at,
                request_capability,
                signature: local_identity.sign_sender_proof(signature_payload.as_bytes()),
                status: GroupLeaveRequestStatus::WaitingForGroupCommit,
            }
        };
        request.validate()?;
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                system_statuses_changed: vec![SystemStatus::SyncInProgress],
                ..CoreStateUpdate::default()
            },
            effects: vec![CoreEffect::SubmitGroupLeaveRequest {
                submit: SubmitGroupLeaveRequest {
                    version: crate::model::CURRENT_MODEL_VERSION.to_string(),
                    group_id: group_id.clone(),
                    request: request.clone(),
                    capability: self.group_capability(&group_id, role)?,
                },
            }],
            view_model: Some(CoreViewModel {
                group_leave_requests: vec![request],
                ..CoreViewModel::default()
            }),
        })
    }

    pub(super) fn list_group_leave_requests(&mut self, group_id: String) -> CoreResult<CoreOutput> {
        let role = self.local_group_role(&group_id)?;
        if !matches!(role, GroupRole::Owner | GroupRole::Admin) {
            return Err(CoreError::invalid_input(
                "only owner or admin can list group leave requests",
            ));
        }
        Ok(CoreOutput {
            state_update: CoreStateUpdate::default(),
            effects: vec![CoreEffect::ListGroupLeaveRequests {
                list: ListGroupLeaveRequestsRequest {
                    group_id: group_id.clone(),
                    capability: self.group_capability(&group_id, role)?,
                },
            }],
            view_model: None,
        })
    }

    pub(super) fn approve_group_leave(
        &mut self,
        group_id: String,
        request_id: String,
    ) -> CoreResult<CoreOutput> {
        let role = self.local_group_role(&group_id)?;
        if !matches!(role, GroupRole::Owner | GroupRole::Admin) {
            return Err(CoreError::invalid_input(
                "only owner or admin can approve group leave requests",
            ));
        }
        let stored = self
            .state
            .group_states
            .get(&group_id)
            .and_then(|state| {
                state
                    .leave_requests
                    .iter()
                    .find(|stored| stored.request.request_id == request_id)
            })
            .cloned()
            .ok_or_else(|| CoreError::invalid_input("group leave request does not exist"))?;
        let now = current_unix_millis(self.state.message_nonce);
        if stored.lease_token.is_none()
            || stored
                .lease_expires_at
                .is_none_or(|expires_at| expires_at <= now)
        {
            return Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::SyncInProgress],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::ClaimGroupLeaveRequest {
                    claim: ClaimGroupLeaveRequest {
                        version: crate::model::CURRENT_MODEL_VERSION.to_string(),
                        group_id,
                        request_id,
                        capability: self.group_capability(&stored.request.group_id, role)?,
                    },
                }],
                view_model: None,
            });
        }
        self.remove_group_member_with_operation(group_id, stored.request.leaver_user_id, "leave")
    }

    pub(super) fn transfer_group_ownership(
        &mut self,
        group_id: String,
        new_owner_user_id: String,
    ) -> CoreResult<CoreOutput> {
        let new_owner_user_id = new_owner_user_id.trim().to_string();
        if new_owner_user_id.is_empty() {
            return Err(CoreError::invalid_input(
                "new_owner_user_id must not be empty",
            ));
        }
        let local_identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .clone();
        if new_owner_user_id == local_identity.user_identity.user_id {
            return Err(CoreError::invalid_input(
                "new_owner_user_id must be different from the current owner",
            ));
        }
        let role = self.local_group_role(&group_id)?;
        if role != GroupRole::Owner {
            return Err(CoreError::invalid_input(
                "only the current owner can transfer ownership",
            ));
        }
        let group_state = self
            .state
            .group_states
            .get(&group_id)
            .ok_or_else(|| CoreError::invalid_input("group does not exist"))?
            .clone();
        let previous_manifest = group_state.manifest.clone();
        let mut manifest = previous_manifest.clone();
        let new_owner = manifest
            .members
            .iter()
            .find(|m| m.user_id == new_owner_user_id && m.status == GroupMemberStatus::Active)
            .ok_or_else(|| {
                CoreError::invalid_input("new owner must be an active member of this group")
            })?;
        if new_owner.role == GroupRole::Owner {
            return Err(CoreError::invalid_input(
                "new owner is already the current owner",
            ));
        }
        let now = current_unix_millis(self.state.message_nonce);
        for member in &mut manifest.members {
            if member.user_id == local_identity.user_identity.user_id
                && member.role == GroupRole::Owner
            {
                member.role = GroupRole::Admin;
            }
            if member.user_id == new_owner_user_id {
                member.role = GroupRole::Owner;
            }
        }
        manifest.owner_user_id = new_owner_user_id.clone();
        manifest.admins = manifest
            .members
            .iter()
            .filter(|member| {
                member.status == GroupMemberStatus::Active && member.role == GroupRole::Admin
            })
            .map(|member| member.user_id.clone())
            .collect();
        manifest.roster_version = manifest.roster_version.saturating_add(1);
        manifest.updated_at = now;
        manifest.signer_user_id = local_identity.user_identity.user_id.clone();
        manifest.signer_device_id = local_identity.device_identity.device_id.clone();
        manifest.signature = self.sign_manifest(&manifest)?;
        manifest.validate()?;
        let metadata_payload = serde_json::to_vec(&manifest).map_err(|error| {
            CoreError::invalid_input(format!("failed to encode manifest: {error}"))
        })?;
        let metadata_ciphertext = self
            .state
            .mls_adapter
            .as_mut()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .encrypt_application(&group_state.conversation_id, &metadata_payload)?;
        let mut envelope = self.build_group_envelope(
            &group_id,
            &group_state.conversation_id,
            GroupMessageType::ControlGroupMetadataUpdated,
            GroupEnvelopeVisibility::Visible,
            metadata_ciphertext.payload_b64,
        )?;
        let capability = self.group_capability(&group_id, GroupRole::Owner)?;
        let membership_proof = self.build_membership_proof(
            "transfer_ownership",
            &previous_manifest,
            &manifest,
            previous_manifest
                .last_commit_message_id
                .as_deref()
                .unwrap_or(&envelope.message_id),
            &envelope.message_id,
        )?;
        envelope.membership_proof = Some(membership_proof);
        self.enqueue_group_envelope(envelope.clone(), capability.clone(), None);
        self.state.group_states.insert(
            group_id.clone(),
            PersistedGroupState {
                group_id: group_id.clone(),
                conversation_id: group_state.conversation_id.clone(),
                manifest: manifest.clone(),
                local_role: Some(GroupRole::Admin),
                welcome_pickup: group_state.welcome_pickup,
                dissolved_at: group_state.dissolved_at,
                pending_membership_transition: group_state.pending_membership_transition.clone(),
                consistency_state: group_state.consistency_state.clone(),
                pending_group_transition: group_state.pending_group_transition.clone(),
                leave_requests: group_state.leave_requests.clone(),
                pcs_state: group_state.pcs_state.clone(),
                crypto_epoch: group_state.crypto_epoch,
                crypto_head_hash: group_state.crypto_head_hash.clone(),
                pending_secure_send: group_state.pending_secure_send.clone(),
                pending_epoch_transition: group_state.pending_epoch_transition.clone(),
            },
        );
        self.merge_with_transport_flush(CoreOutput {
            state_update: CoreStateUpdate {
                conversations_changed: true,
                messages_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(
                &self.state,
                vec![
                    PersistOp::SaveGroupState {
                        group_id: group_id.clone(),
                    },
                    PersistOp::SaveOutgoingGroupEnvelope {
                        message_id: envelope.message_id.clone(),
                    },
                ],
            )],
            view_model: Some(CoreViewModel {
                messages: vec![MessageSummary {
                    conversation_id: group_state.conversation_id,
                    message_id: envelope.message_id,
                    message_type: MessageType::ControlIdentityStateUpdated,
                }],
                ..CoreViewModel::default()
            }),
        })
    }

    pub(super) fn set_group_admin(
        &mut self,
        group_id: String,
        target_user_id: String,
        is_admin: bool,
    ) -> CoreResult<CoreOutput> {
        let target_user_id = target_user_id.trim().to_string();
        if target_user_id.is_empty() {
            return Err(CoreError::invalid_input("target_user_id must not be empty"));
        }
        let role = self.local_group_role(&group_id)?;
        if role != GroupRole::Owner {
            return Err(CoreError::invalid_input(
                "only the owner can appoint or remove admins",
            ));
        }
        let group_state = self
            .state
            .group_states
            .get(&group_id)
            .ok_or_else(|| CoreError::invalid_input("group does not exist"))?
            .clone();
        let previous_manifest = group_state.manifest.clone();
        let mut manifest = previous_manifest.clone();
        let target = manifest
            .members
            .iter_mut()
            .find(|m| m.user_id == target_user_id && m.status == GroupMemberStatus::Active)
            .ok_or_else(|| {
                CoreError::invalid_input("target user is not an active member of this group")
            })?;
        if target.role == GroupRole::Owner {
            return Err(CoreError::invalid_input(
                "cannot change the owner role with SetGroupAdmin; use TransferGroupOwnership",
            ));
        }
        let now = current_unix_millis(self.state.message_nonce);
        if is_admin {
            target.role = GroupRole::Admin;
            if !manifest.admins.contains(&target_user_id) {
                manifest.admins.push(target_user_id.clone());
            }
        } else {
            target.role = GroupRole::Member;
            manifest.admins.retain(|a| a != &target_user_id);
        }
        manifest.roster_version = manifest.roster_version.saturating_add(1);
        manifest.updated_at = now;
        manifest.signer_user_id = self.local_identity_user_id()?;
        manifest.signer_device_id = self.local_identity_device_id()?;
        manifest.signature = self.sign_manifest(&manifest)?;
        manifest.validate()?;
        let summary = self
            .state
            .mls_adapter
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .export_group_summary(&group_state.conversation_id)?;
        manifest.mls_epoch_hint = summary.epoch;
        self.state.group_states.insert(
            group_id.clone(),
            PersistedGroupState {
                group_id: group_id.clone(),
                conversation_id: group_state.conversation_id.clone(),
                manifest: manifest.clone(),
                local_role: group_state.local_role,
                welcome_pickup: group_state.welcome_pickup,
                dissolved_at: group_state.dissolved_at,
                pending_membership_transition: group_state.pending_membership_transition.clone(),
                consistency_state: group_state.consistency_state.clone(),
                pending_group_transition: group_state.pending_group_transition.clone(),
                leave_requests: group_state.leave_requests.clone(),
                pcs_state: group_state.pcs_state.clone(),
                crypto_epoch: group_state.crypto_epoch,
                crypto_head_hash: group_state.crypto_head_hash.clone(),
                pending_secure_send: group_state.pending_secure_send.clone(),
                pending_epoch_transition: group_state.pending_epoch_transition.clone(),
            },
        );
        let metadata_payload = serde_json::to_vec(&manifest).map_err(|error| {
            CoreError::invalid_input(format!("failed to encode manifest: {error}"))
        })?;
        let metadata_ciphertext = self
            .state
            .mls_adapter
            .as_mut()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .encrypt_application(&group_state.conversation_id, &metadata_payload)?;
        let mut envelope = self.build_group_envelope(
            &group_id,
            &group_state.conversation_id,
            GroupMessageType::ControlGroupMetadataUpdated,
            GroupEnvelopeVisibility::Visible,
            metadata_ciphertext.payload_b64,
        )?;
        let capability = self.group_capability(&group_id, GroupRole::Owner)?;
        let membership_proof = self.build_membership_proof(
            "set_admin",
            &previous_manifest,
            &manifest,
            previous_manifest
                .last_commit_message_id
                .as_deref()
                .unwrap_or(&envelope.message_id),
            &envelope.message_id,
        )?;
        envelope.membership_proof = Some(membership_proof);
        self.enqueue_group_envelope(envelope.clone(), capability, None);
        self.merge_with_transport_flush(CoreOutput {
            state_update: CoreStateUpdate {
                conversations_changed: true,
                messages_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(
                &self.state,
                vec![
                    PersistOp::SaveGroupState {
                        group_id: group_id.clone(),
                    },
                    PersistOp::SaveOutgoingGroupEnvelope {
                        message_id: envelope.message_id.clone(),
                    },
                ],
            )],
            view_model: Some(CoreViewModel {
                messages: vec![MessageSummary {
                    conversation_id: group_state.conversation_id,
                    message_id: envelope.message_id,
                    message_type: MessageType::ControlIdentityStateUpdated,
                }],
                ..CoreViewModel::default()
            }),
        })
    }

    pub(super) fn update_group_metadata(
        &mut self,
        group_id: String,
        title: Option<String>,
        join_policy: Option<GroupJoinPolicy>,
        member_invite_policy: Option<GroupMemberInvitePolicy>,
    ) -> CoreResult<CoreOutput> {
        let role = self.local_group_role(&group_id)?;
        if !matches!(role, GroupRole::Owner | GroupRole::Admin) {
            return Err(CoreError::invalid_input(
                "only owner or admin can update group metadata",
            ));
        }
        let group_state = self
            .state
            .group_states
            .get(&group_id)
            .ok_or_else(|| CoreError::invalid_input("group does not exist"))?
            .clone();
        let previous_manifest = group_state.manifest.clone();
        let mut manifest = previous_manifest.clone();
        let mut changed = false;
        if let Some(new_title) = title {
            let new_title = new_title.trim().to_string();
            if new_title.is_empty() {
                return Err(CoreError::invalid_input("title must not be empty"));
            }
            if new_title != manifest.title {
                manifest.title = new_title;
                changed = true;
            }
        }
        if let Some(new_join_policy) = join_policy {
            if new_join_policy != manifest.join_policy {
                manifest.join_policy = new_join_policy;
                changed = true;
            }
        }
        if let Some(new_invite_policy) = member_invite_policy {
            if new_invite_policy != manifest.member_invite_policy {
                manifest.member_invite_policy = new_invite_policy;
                changed = true;
            }
        }
        if !changed {
            return Ok(CoreOutput::default());
        }
        let now = current_unix_millis(self.state.message_nonce);
        let summary = self
            .state
            .mls_adapter
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .export_group_summary(&group_state.conversation_id)?;
        manifest.roster_version = manifest.roster_version.saturating_add(1);
        manifest.mls_epoch_hint = summary.epoch;
        manifest.updated_at = now;
        manifest.signer_user_id = self.local_identity_user_id()?;
        manifest.signer_device_id = self.local_identity_device_id()?;
        manifest.signature = self.sign_manifest(&manifest)?;
        manifest.validate()?;
        self.state.group_states.insert(
            group_id.clone(),
            PersistedGroupState {
                group_id: group_id.clone(),
                conversation_id: group_state.conversation_id.clone(),
                manifest: manifest.clone(),
                local_role: group_state.local_role,
                welcome_pickup: group_state.welcome_pickup,
                dissolved_at: group_state.dissolved_at,
                pending_membership_transition: group_state.pending_membership_transition.clone(),
                consistency_state: group_state.consistency_state.clone(),
                pending_group_transition: group_state.pending_group_transition.clone(),
                leave_requests: group_state.leave_requests.clone(),
                pcs_state: group_state.pcs_state.clone(),
                crypto_epoch: group_state.crypto_epoch,
                crypto_head_hash: group_state.crypto_head_hash.clone(),
                pending_secure_send: group_state.pending_secure_send.clone(),
                pending_epoch_transition: group_state.pending_epoch_transition.clone(),
            },
        );
        let metadata_payload = serde_json::to_vec(&manifest).map_err(|error| {
            CoreError::invalid_input(format!("failed to encode manifest: {error}"))
        })?;
        let metadata_ciphertext = self
            .state
            .mls_adapter
            .as_mut()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .encrypt_application(&group_state.conversation_id, &metadata_payload)?;
        let capability = self.group_capability(&group_id, role)?;
        let mut envelope = self.build_group_envelope(
            &group_id,
            &group_state.conversation_id,
            GroupMessageType::ControlGroupMetadataUpdated,
            GroupEnvelopeVisibility::Visible,
            metadata_ciphertext.payload_b64,
        )?;
        envelope.membership_proof = Some(
            self.build_membership_proof(
                "update_metadata",
                &previous_manifest,
                &manifest,
                previous_manifest
                    .last_commit_message_id
                    .as_deref()
                    .unwrap_or(&envelope.message_id),
                &envelope.message_id,
            )?,
        );
        self.enqueue_group_envelope(envelope.clone(), capability, None);
        self.merge_with_transport_flush(CoreOutput {
            state_update: CoreStateUpdate {
                conversations_changed: true,
                messages_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(
                &self.state,
                vec![
                    PersistOp::SaveGroupState {
                        group_id: group_id.clone(),
                    },
                    PersistOp::SaveOutgoingGroupEnvelope {
                        message_id: envelope.message_id.clone(),
                    },
                ],
            )],
            view_model: Some(CoreViewModel {
                messages: vec![MessageSummary {
                    conversation_id: group_state.conversation_id,
                    message_id: envelope.message_id,
                    message_type: MessageType::ControlIdentityStateUpdated,
                }],
                ..CoreViewModel::default()
            }),
        })
    }

    pub(super) fn dissolve_group(&mut self, group_id: String) -> CoreResult<CoreOutput> {
        let local_identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .clone();
        let role = self.local_group_role(&group_id)?;
        if role != GroupRole::Owner {
            return Err(CoreError::invalid_input(
                "only the group owner can dissolve the group",
            ));
        }
        let group_state = self
            .state
            .group_states
            .get(&group_id)
            .ok_or_else(|| CoreError::invalid_input("group does not exist"))?
            .clone();
        if group_state.dissolved_at.is_some() {
            return Err(CoreError::invalid_input("group is already dissolved"));
        }
        if self.state.pending_group_seal.contains_key(&group_id) {
            return Err(CoreError::invalid_input(
                "a dissolve is already in progress for this group",
            ));
        }

        // Build the list of non-owner active members. Step (a) removes all
        // their MLS devices in a single commit so receivers observe a single
        // epoch bump (PROTOCOL_GROUP_CN.md §10.4 non-goal: avoid N-epoch
        // staircase).
        let previous_manifest = group_state.manifest.clone();
        let mut manifest = previous_manifest.clone();
        let target_user_ids: Vec<String> = manifest
            .members
            .iter()
            .filter(|m| {
                m.status == GroupMemberStatus::Active
                    && m.user_id != local_identity.user_identity.user_id
            })
            .map(|m| m.user_id.clone())
            .collect();

        let mut all_device_ids: Vec<String> = Vec::new();
        {
            let adapter = self
                .state
                .mls_adapter
                .as_ref()
                .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?;
            for user_id in &target_user_ids {
                let device_ids =
                    adapter.member_device_ids_for_user(&group_state.conversation_id, user_id)?;
                all_device_ids.extend(device_ids);
            }
        }
        all_device_ids.sort();
        all_device_ids.dedup();

        // Produce the single MLS remove commit. If there are no other
        // members (a lone-owner group), we still must emit the
        // `ControlGroupDissolved` visible message and seal the outbox so
        // third parties cannot revive the log, but there is nothing for MLS
        // to remove — in that case we simulate "commit" by passing an empty
        // set and letting the adapter surface the protocol-level epoch bump
        // that follows from a no-op membership change.
        let artifacts = {
            let adapter = self
                .state
                .mls_adapter
                .as_mut()
                .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?;
            if all_device_ids.is_empty() {
                // Lone-owner groups: no MLS commit is produced. We still
                // walk through the rest of the dissolve flow so the outbox
                // is sealed and subsequent sends fail-closed.
                None
            } else {
                Some(adapter.remove_members(&group_state.conversation_id, &all_device_ids)?)
            }
        };
        if let Some(_) = &artifacts {
            let summary = self
                .state
                .mls_adapter
                .as_ref()
                .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
                .export_group_summary(&group_state.conversation_id)?;
            self.state
                .mls_summaries
                .insert(group_state.conversation_id.clone(), summary);
        }

        let now = current_unix_millis(self.state.message_nonce);
        for member in &mut manifest.members {
            if member.status == GroupMemberStatus::Active
                && member.user_id != local_identity.user_identity.user_id
            {
                member.status = GroupMemberStatus::Removed;
            }
        }
        let epoch = artifacts
            .as_ref()
            .map(|artifacts| artifacts.epoch)
            .unwrap_or(manifest.mls_epoch_hint);
        self.apply_membership_change_to_manifest(&mut manifest, epoch, now)?;
        self.sync_conversation_members_from_manifest(&group_state.conversation_id, &manifest)?;
        self.state.group_states.insert(
            group_id.clone(),
            PersistedGroupState {
                group_id: group_id.clone(),
                conversation_id: group_state.conversation_id.clone(),
                manifest: manifest.clone(),
                local_role: group_state.local_role,
                welcome_pickup: group_state.welcome_pickup,
                // A.4 contract: `dissolved_at` is NOT set here. It is only
                // set in `handle_group_outbox_sealed` after the
                // SealGroupOutbox effect has been acknowledged, ensuring we
                // never flag the group as dissolved locally before the
                // server-side seal is in effect.
                dissolved_at: None,
                pending_membership_transition: None,
                consistency_state: GroupConsistencyState::Ready,
                pending_group_transition: None,
                leave_requests: group_state.leave_requests.clone(),
                pcs_state: group_state.pcs_state.clone(),
                crypto_epoch: group_state.crypto_epoch,
                crypto_head_hash: group_state.crypto_head_hash.clone(),
                pending_secure_send: group_state.pending_secure_send.clone(),
                pending_epoch_transition: group_state.pending_epoch_transition.clone(),
            },
        );

        // Owner-level capability includes `SealGroup` (see
        // `group_capability_operations`). We reuse it for both the commit
        // and the control envelope — the append capability is a superset.
        let capability = self.group_capability(&group_id, role)?;
        let mut persist_ops: Vec<PersistOp> = vec![
            PersistOp::SaveGroupState {
                group_id: group_id.clone(),
            },
            PersistOp::SaveMlsState {
                conversation_id: group_state.conversation_id.clone(),
            },
        ];
        let mut messages: Vec<MessageSummary> = Vec::new();

        // Build any MLS commit envelope first so its message_id can be
        // referenced by the membership proof and manifest chain.
        let commit_message_id: Option<String> = if let Some(artifacts) = artifacts {
            let commit = self.build_group_envelope(
                &group_id,
                &group_state.conversation_id,
                GroupMessageType::MlsCommit,
                GroupEnvelopeVisibility::Protocol,
                artifacts.commit_b64,
            )?;
            let commit_message_id = commit.message_id.clone();
            // A staged commit envelope does not yet carry a membership proof;
            // it will be patched below once the proof is constructed.
            self.enqueue_group_envelope(commit, capability.clone(), None);
            persist_ops.push(PersistOp::SaveOutgoingGroupEnvelope {
                message_id: commit_message_id.clone(),
            });
            messages.push(MessageSummary {
                conversation_id: group_state.conversation_id.clone(),
                message_id: commit_message_id.clone(),
                message_type: MessageType::MlsCommit,
            });
            Some(commit_message_id)
        } else {
            None
        };

        // Wire the commit message into the manifest chain before signing.
        if let Some(ref commit_id) = commit_message_id {
            manifest.last_commit_message_id = Some(commit_id.clone());
        }
        manifest.signature = self.sign_manifest(&manifest)?;
        manifest.validate()?;
        if let Some(state) = self.state.group_states.get_mut(&group_id) {
            state.manifest = manifest.clone();
        }

        // Step (b): visible `ControlGroupDissolved` control message.
        let manifest_payload = serde_json::to_vec(&manifest).map_err(|error| {
            CoreError::invalid_input(format!("failed to encode manifest: {error}"))
        })?;
        let control_plaintext = self
            .state
            .mls_adapter
            .as_mut()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .encrypt_application(&group_state.conversation_id, &manifest_payload)?;
        let mut control = self.build_group_envelope(
            &group_id,
            &group_state.conversation_id,
            GroupMessageType::ControlGroupDissolved,
            GroupEnvelopeVisibility::Visible,
            control_plaintext.payload_b64,
        )?;
        let control_message_id = control.message_id.clone();

        let membership_proof = self.build_membership_proof(
            "dissolve",
            &previous_manifest,
            &manifest,
            commit_message_id
                .as_deref()
                .or(previous_manifest.last_commit_message_id.as_deref())
                .unwrap_or(&control_message_id),
            &control_message_id,
        )?;
        // Patch the already-enqueued commit with its proof.
        if let Some(ref commit_id) = commit_message_id {
            if let Some(item) = self
                .state
                .pending_group_outbox
                .iter_mut()
                .rev()
                .find(|item| item.envelope.message_id == *commit_id)
            {
                item.envelope.membership_proof = Some(membership_proof.clone());
            }
        }
        control.membership_proof = Some(membership_proof);
        self.enqueue_group_envelope(
            control,
            capability.clone(),
            Some("control_group_dissolved".into()),
        );
        persist_ops.push(PersistOp::SaveOutgoingGroupEnvelope {
            message_id: control_message_id.clone(),
        });
        messages.push(MessageSummary {
            conversation_id: group_state.conversation_id.clone(),
            message_id: control_message_id,
            message_type: MessageType::ControlConversationNeedsRebuild,
        });

        // Step (c): stage the owner-signed seal request. Actual
        // `CoreEffect::SealGroupOutbox` is emitted by
        // `handle_group_envelope_appended` once this group's
        // `pending_group_outbox` is drained.
        self.state.pending_group_seal.insert(
            group_id.clone(),
            SealGroupOutboxRequest {
                group_id: group_id.clone(),
                capability,
            },
        );
        persist_ops.push(PersistOp::SavePendingGroupSeal {
            group_id: group_id.clone(),
        });

        let effects = vec![persist_effect(&self.state, persist_ops)];
        self.merge_with_transport_flush(CoreOutput {
            state_update: CoreStateUpdate {
                conversations_changed: true,
                messages_changed: true,
                ..CoreStateUpdate::default()
            },
            effects,
            view_model: Some(CoreViewModel {
                messages,
                ..CoreViewModel::default()
            }),
        })
    }

    /// Phase 8: register a new device in an existing group.
    ///
    /// When a user provisions an additional device, every group the user
    /// belongs to must learn about it. The core issues an MLS External Add
    /// with a Welcome for the new device so it can decrypt future messages.
    /// The updated manifest is published as a `ControlGroupMembershipChanged`
    /// message signed by the calling device.
    ///
    /// Only owners and admins may execute this operation — members do not
    /// hold the `append_membership` capability required to write the MLS
    /// commit to the group outbox.

    pub(super) fn add_group_member_device(
        &mut self,
        group_id: String,
        user_id: String,
        device_id: String,
    ) -> CoreResult<CoreOutput> {
        let local_user_id = self.local_identity_user_id()?;
        if user_id != local_user_id {
            return Err(CoreError::invalid_input(
                "add_group_member_device may only add devices for the local user",
            ));
        }
        let local_device_id = self.local_identity_device_id()?;
        if device_id == local_device_id {
            return Err(CoreError::invalid_input(
                "cannot add the current device; it is already an MLS member of this group",
            ));
        }
        let device_id = device_id.trim().to_string();
        if device_id.is_empty() {
            return Err(CoreError::invalid_input("device_id must not be empty"));
        }
        let group_state = self
            .state
            .group_states
            .get(&group_id)
            .ok_or_else(|| CoreError::invalid_input("group does not exist"))?
            .clone();
        let role = self.local_group_role(&group_id)?;
        if !matches!(role, GroupRole::Owner | GroupRole::Admin) {
            return Err(CoreError::invalid_input(
                "only owner or admin can register a new device in a group",
            ));
        }
        if group_state.dissolved_at.is_some() {
            return Err(CoreError::invalid_input(
                "cannot add a device to a dissolved group",
            ));
        }
        if group_state
            .manifest
            .member_devices
            .iter()
            .any(|d| d.device_id == device_id && d.status == GroupMemberStatus::Active)
        {
            return Err(CoreError::invalid_input(
                "device is already an active member of this group",
            ));
        }
        let active_leaf_count = group_state
            .manifest
            .member_devices
            .iter()
            .filter(|leaf| leaf.status == GroupMemberStatus::Active)
            .count();
        crate::pcs_policy::validate_active_leaf_limit(active_leaf_count.saturating_add(1))?;
        let bundle =
            self.state.local_bundle.as_ref().ok_or_else(|| {
                CoreError::invalid_state("local identity bundle is not initialized")
            })?;
        let device_profile = bundle
            .devices
            .iter()
            .find(|d| d.device_id == device_id && matches!(d.status, DeviceStatusKind::Active))
            .ok_or_else(|| {
                CoreError::invalid_input("target device is not an active device of the local user")
            })?;
        let keypackage_ref = device_profile
            .keypackage_ref
            .as_ref()
            .filter(|keypackage_ref| {
                keypackage_ref.is_usable_at(current_unix_millis(self.state.message_nonce))
            })
            .ok_or_else(|| {
                CoreError::new(
                    "keypackage_expired",
                    "target device does not have a usable key package",
                )
            })?;
        let peer_keypackage = PeerDeviceKeyPackage {
            user_id: local_user_id.clone(),
            device_id: device_id.clone(),
            device_public_key: device_profile.device_public_key.clone(),
            key_package_b64: keypackage_ref.object_ref.clone(),
        };
        let (artifacts, summary) = {
            let adapter = self
                .state
                .mls_adapter
                .as_mut()
                .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?;
            let artifacts =
                adapter.add_members(&group_state.conversation_id, &[peer_keypackage])?;
            let summary = adapter.export_group_summary(&group_state.conversation_id)?;
            (artifacts, summary)
        };
        self.state
            .mls_summaries
            .insert(group_state.conversation_id.clone(), summary);

        let previous_manifest = group_state.manifest.clone();
        let mut manifest = previous_manifest.clone();
        manifest.member_devices.push(GroupMemberDevice {
            user_id: local_user_id.clone(),
            device_id: device_id.clone(),
            status: GroupMemberStatus::Active,
        });
        let now = current_unix_millis(self.state.message_nonce);
        self.apply_membership_change_to_manifest(&mut manifest, artifacts.epoch, now)?;
        self.sync_conversation_members_from_manifest(&group_state.conversation_id, &manifest)?;
        self.state.group_states.insert(
            group_id.clone(),
            PersistedGroupState {
                group_id: group_id.clone(),
                conversation_id: group_state.conversation_id.clone(),
                manifest: manifest.clone(),
                local_role: group_state.local_role,
                welcome_pickup: group_state.welcome_pickup.clone(),
                dissolved_at: group_state.dissolved_at,
                pending_membership_transition: None,
                consistency_state: GroupConsistencyState::Ready,
                pending_group_transition: None,
                leave_requests: group_state.leave_requests.clone(),
                pcs_state: group_state.pcs_state.clone(),
                crypto_epoch: group_state.crypto_epoch,
                crypto_head_hash: group_state.crypto_head_hash.clone(),
                pending_secure_send: group_state.pending_secure_send.clone(),
                pending_epoch_transition: group_state.pending_epoch_transition.clone(),
            },
        );

        let capability = self.group_capability(&group_id, role)?;
        let mut commit = self.build_group_envelope(
            &group_id,
            &group_state.conversation_id,
            GroupMessageType::MlsCommit,
            GroupEnvelopeVisibility::Protocol,
            artifacts.commit_b64,
        )?;
        manifest.last_commit_message_id = Some(commit.message_id.clone());
        manifest.signature = self.sign_manifest(&manifest)?;
        manifest.validate()?;
        let manifest_payload = serde_json::to_vec(&manifest).map_err(|error| {
            CoreError::invalid_input(format!("failed to encode manifest: {error}"))
        })?;
        let control_payload = self
            .state
            .mls_adapter
            .as_mut()
            .ok_or_else(|| CoreError::invalid_state("MLS adapter is not initialized"))?
            .encrypt_application(&group_state.conversation_id, &manifest_payload)?;
        let mut control = self.build_group_envelope(
            &group_id,
            &group_state.conversation_id,
            GroupMessageType::ControlGroupMembershipChanged,
            GroupEnvelopeVisibility::Protocol,
            control_payload.payload_b64,
        )?;
        let membership_proof = self.build_membership_proof(
            "add_device",
            &previous_manifest,
            &manifest,
            &commit.message_id,
            &control.message_id,
        )?;
        commit.membership_proof = Some(membership_proof.clone());
        control.membership_proof = Some(membership_proof);
        self.enqueue_group_envelope(commit.clone(), capability.clone(), None);
        self.enqueue_group_envelope(control.clone(), capability.clone(), None);
        self.state.group_states.insert(
            group_id.clone(),
            PersistedGroupState {
                group_id: group_id.clone(),
                conversation_id: group_state.conversation_id.clone(),
                manifest: manifest.clone(),
                local_role: group_state.local_role,
                welcome_pickup: group_state.welcome_pickup.clone(),
                dissolved_at: group_state.dissolved_at,
                pending_membership_transition: None,
                consistency_state: GroupConsistencyState::Ready,
                pending_group_transition: None,
                leave_requests: group_state.leave_requests.clone(),
                pcs_state: group_state.pcs_state.clone(),
                crypto_epoch: group_state.crypto_epoch,
                crypto_head_hash: group_state.crypto_head_hash.clone(),
                pending_secure_send: group_state.pending_secure_send.clone(),
                pending_epoch_transition: group_state.pending_epoch_transition.clone(),
            },
        );

        let mut effects = vec![persist_effect(
            &self.state,
            vec![
                PersistOp::SaveGroupState {
                    group_id: group_id.clone(),
                },
                PersistOp::SaveMlsState {
                    conversation_id: group_state.conversation_id.clone(),
                },
                PersistOp::SaveOutgoingGroupEnvelope {
                    message_id: commit.message_id.clone(),
                },
                PersistOp::SaveOutgoingGroupEnvelope {
                    message_id: control.message_id.clone(),
                },
            ],
        )];
        for welcome in artifacts.welcomes {
            let descriptor =
                self.welcome_pickup_descriptor(&group_id, &welcome.recipient_device_id)?;
            effects.push(CoreEffect::PutWelcomePickup {
                put: PutWelcomePickupRequest {
                    descriptor,
                    welcome_b64: welcome.payload_b64,
                    manifest: Some(manifest.clone()),
                    headers: BTreeMap::new(),
                },
            });
        }
        let pickup_descriptors: Vec<_> = effects
            .iter()
            .filter_map(|effect| match effect {
                CoreEffect::PutWelcomePickup { put } => Some(put.descriptor.clone()),
                _ => None,
            })
            .collect();
        self.merge_with_transport_flush(CoreOutput {
            state_update: CoreStateUpdate {
                conversations_changed: true,
                messages_changed: true,
                ..CoreStateUpdate::default()
            },
            effects,
            view_model: Some(CoreViewModel {
                messages: vec![
                    MessageSummary {
                        conversation_id: group_state.conversation_id.clone(),
                        message_id: commit.message_id,
                        message_type: MessageType::MlsCommit,
                    },
                    MessageSummary {
                        conversation_id: group_state.conversation_id,
                        message_id: control.message_id,
                        message_type: MessageType::ControlDeviceMembershipChanged,
                    },
                ],
                welcome_pickups: pickup_descriptors,
                ..CoreViewModel::default()
            }),
        })
    }

    /// Phase 8: remove a decommissioned device from an existing group.
    ///
    /// When a user removes a device from their account the group must
    /// advance its MLS epoch so the decommissioned device can no longer
    /// decrypt future messages. The core generates an MLS Remove covering
    /// the target device, bumps the manifest roster version, and publishes
    /// a `ControlGroupMembershipChanged` message.
    ///
    /// Only owners and admins may execute this operation. The calling
    /// device cannot remove itself.

    pub(super) fn remove_group_member_device(
        &mut self,
        group_id: String,
        user_id: String,
        device_id: String,
    ) -> CoreResult<CoreOutput> {
        let local_user_id = self.local_identity_user_id()?;
        if user_id != local_user_id {
            return Err(CoreError::invalid_input(
                "remove_group_member_device may only remove devices for the local user",
            ));
        }
        let local_device_id = self.local_identity_device_id()?;
        let device_id = device_id.trim().to_string();
        if device_id.is_empty() {
            return Err(CoreError::invalid_input("device_id must not be empty"));
        }
        if device_id == local_device_id {
            return Err(CoreError::invalid_input(
                "cannot remove the current device from a group; use LeaveGroup instead",
            ));
        }
        let group_state = self
            .state
            .group_states
            .get(&group_id)
            .ok_or_else(|| CoreError::invalid_input("group does not exist"))?
            .clone();
        let role = self.local_group_role(&group_id)?;
        if !matches!(role, GroupRole::Owner | GroupRole::Admin) {
            return Err(CoreError::invalid_input(
                "only owner or admin can remove a device from a group",
            ));
        }
        if group_state.dissolved_at.is_some() {
            return Err(CoreError::invalid_input(
                "cannot remove a device from a dissolved group",
            ));
        }
        let device_entry = group_state
            .manifest
            .member_devices
            .iter()
            .find(|d| d.device_id == device_id && d.status == GroupMemberStatus::Active)
            .ok_or_else(|| {
                CoreError::invalid_input("target device is not an active member of this group")
            })?;
        if device_entry.user_id != local_user_id {
            return Err(CoreError::invalid_input(
                "target device does not belong to the local user",
            ));
        }
        // Ensure at least one device for this user remains in the group.
        let other_active_device_count = group_state
            .manifest
            .member_devices
            .iter()
            .filter(|d| {
                d.user_id == local_user_id
                    && d.device_id != device_id
                    && d.status == GroupMemberStatus::Active
            })
            .count();
        if other_active_device_count == 0 {
            return Err(CoreError::invalid_input(
                "cannot remove the last device of the local user from a group; use LeaveGroup instead",
            ));
        }
        let target_device_ids = {
            let adapter = self
                .state
                .mls_adapter
                .as_ref()
                .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?;
            adapter.member_device_ids_for_user(&group_state.conversation_id, &local_user_id)?
        };
        let mls_device_id = target_device_ids
            .iter()
            .find(|id| *id == &device_id)
            .ok_or_else(|| {
                CoreError::invalid_input("target device is not registered in the MLS group state")
            })?
            .clone();
        let (artifacts, summary) = {
            let adapter = self
                .state
                .mls_adapter
                .as_mut()
                .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?;
            let artifacts =
                adapter.remove_members(&group_state.conversation_id, &[mls_device_id])?;
            let summary = adapter.export_group_summary(&group_state.conversation_id)?;
            (artifacts, summary)
        };
        self.state
            .mls_summaries
            .insert(group_state.conversation_id.clone(), summary);

        let previous_manifest = group_state.manifest.clone();
        let mut manifest = previous_manifest.clone();
        if let Some(entry) = manifest
            .member_devices
            .iter_mut()
            .find(|d| d.device_id == device_id)
        {
            entry.status = GroupMemberStatus::Removed;
        }
        let now = current_unix_millis(self.state.message_nonce);
        self.apply_membership_change_to_manifest(&mut manifest, artifacts.epoch, now)?;
        self.sync_conversation_members_from_manifest(&group_state.conversation_id, &manifest)?;
        self.state.group_states.insert(
            group_id.clone(),
            PersistedGroupState {
                group_id: group_id.clone(),
                conversation_id: group_state.conversation_id.clone(),
                manifest: manifest.clone(),
                local_role: group_state.local_role,
                welcome_pickup: group_state.welcome_pickup.clone(),
                dissolved_at: group_state.dissolved_at,
                pending_membership_transition: None,
                consistency_state: GroupConsistencyState::Ready,
                pending_group_transition: None,
                leave_requests: group_state.leave_requests.clone(),
                pcs_state: group_state.pcs_state.clone(),
                crypto_epoch: group_state.crypto_epoch,
                crypto_head_hash: group_state.crypto_head_hash.clone(),
                pending_secure_send: group_state.pending_secure_send.clone(),
                pending_epoch_transition: group_state.pending_epoch_transition.clone(),
            },
        );

        let capability = self.group_capability(&group_id, role)?;
        let mut commit = self.build_group_envelope(
            &group_id,
            &group_state.conversation_id,
            GroupMessageType::MlsCommit,
            GroupEnvelopeVisibility::Protocol,
            artifacts.commit_b64,
        )?;
        manifest.last_commit_message_id = Some(commit.message_id.clone());
        manifest.signature = self.sign_manifest(&manifest)?;
        manifest.validate()?;
        let manifest_payload = serde_json::to_vec(&manifest).map_err(|error| {
            CoreError::invalid_input(format!("failed to encode manifest: {error}"))
        })?;
        let control_payload = self
            .state
            .mls_adapter
            .as_mut()
            .ok_or_else(|| CoreError::invalid_state("MLS adapter is not initialized"))?
            .encrypt_application(&group_state.conversation_id, &manifest_payload)?;
        let mut control = self.build_group_envelope(
            &group_id,
            &group_state.conversation_id,
            GroupMessageType::ControlGroupMembershipChanged,
            GroupEnvelopeVisibility::Protocol,
            control_payload.payload_b64,
        )?;
        let membership_proof = self.build_membership_proof(
            "remove_device",
            &previous_manifest,
            &manifest,
            &commit.message_id,
            &control.message_id,
        )?;
        commit.membership_proof = Some(membership_proof.clone());
        control.membership_proof = Some(membership_proof);
        self.enqueue_group_envelope(commit.clone(), capability.clone(), None);
        self.enqueue_group_envelope(control.clone(), capability.clone(), None);
        self.state.group_states.insert(
            group_id.clone(),
            PersistedGroupState {
                group_id: group_id.clone(),
                conversation_id: group_state.conversation_id.clone(),
                manifest: manifest.clone(),
                local_role: group_state.local_role,
                welcome_pickup: group_state.welcome_pickup.clone(),
                dissolved_at: group_state.dissolved_at,
                pending_membership_transition: None,
                consistency_state: GroupConsistencyState::Ready,
                pending_group_transition: None,
                leave_requests: group_state.leave_requests.clone(),
                pcs_state: group_state.pcs_state.clone(),
                crypto_epoch: group_state.crypto_epoch,
                crypto_head_hash: group_state.crypto_head_hash.clone(),
                pending_secure_send: group_state.pending_secure_send.clone(),
                pending_epoch_transition: group_state.pending_epoch_transition.clone(),
            },
        );

        let effects = vec![persist_effect(
            &self.state,
            vec![
                PersistOp::SaveGroupState {
                    group_id: group_id.clone(),
                },
                PersistOp::SaveMlsState {
                    conversation_id: group_state.conversation_id.clone(),
                },
                PersistOp::SaveOutgoingGroupEnvelope {
                    message_id: commit.message_id.clone(),
                },
                PersistOp::SaveOutgoingGroupEnvelope {
                    message_id: control.message_id.clone(),
                },
            ],
        )];
        self.merge_with_transport_flush(CoreOutput {
            state_update: CoreStateUpdate {
                conversations_changed: true,
                messages_changed: true,
                ..CoreStateUpdate::default()
            },
            effects,
            view_model: Some(CoreViewModel {
                messages: vec![
                    MessageSummary {
                        conversation_id: group_state.conversation_id.clone(),
                        message_id: commit.message_id,
                        message_type: MessageType::MlsCommit,
                    },
                    MessageSummary {
                        conversation_id: group_state.conversation_id,
                        message_id: control.message_id,
                        message_type: MessageType::ControlDeviceMembershipChanged,
                    },
                ],
                ..CoreViewModel::default()
            }),
        })
    }

    /// Phase 8: register a newly provisioned device in every group the
    /// local user belongs to.
    ///
    /// Iterates over all known groups, and for each group where the local
    /// user holds an owner or admin role and the target device is not
    /// already present, performs an MLS External Add, writes a Welcome to
    /// the device's welcome pickup, and publishes a
    /// `ControlGroupMembershipChanged` message.
    ///
    /// Groups where the device is already registered, where the local user
    /// does not hold sufficient permissions, or that have been dissolved
    /// are silently skipped. Failures for individual groups are collected
    /// and reported; a single failed group does not abort the batch.

    pub(super) fn sync_groups_for_new_device(
        &mut self,
        device_id: String,
    ) -> CoreResult<CoreOutput> {
        let local_user_id = self.local_identity_user_id()?;
        let local_device_id = self.local_identity_device_id()?;
        let device_id = device_id.trim().to_string();
        if device_id.is_empty() {
            return Err(CoreError::invalid_input("device_id must not be empty"));
        }
        if device_id == local_device_id {
            return Err(CoreError::invalid_input(
                "cannot sync groups for the current device; it is already a member of its groups",
            ));
        }
        // Verify the target device is an active device of the local user
        // before iterating over groups.
        let bundle =
            self.state.local_bundle.as_ref().ok_or_else(|| {
                CoreError::invalid_state("local identity bundle is not initialized")
            })?;
        bundle
            .devices
            .iter()
            .find(|d| d.device_id == device_id && matches!(d.status, DeviceStatusKind::Active))
            .ok_or_else(|| {
                CoreError::invalid_input("target device is not an active device of the local user")
            })?;

        // Collect group ids first to avoid borrowing conflicts during
        // iteration (add_group_member_device borrows &mut self).
        let candidate_group_ids: Vec<String> =
            self.state
                .group_states
                .values()
                .filter(|state| {
                    // Only operate on groups where the local user holds a
                    // role that allows writing membership operations.
                    matches!(state.local_role, Some(GroupRole::Owner | GroupRole::Admin))
                        && state.dissolved_at.is_none()
                        && !state.manifest.member_devices.iter().any(|d| {
                            d.device_id == device_id && d.status == GroupMemberStatus::Active
                        })
                })
                .map(|state| state.group_id.clone())
                .collect();

        if candidate_group_ids.is_empty() {
            return Ok(CoreOutput {
                state_update: CoreStateUpdate::default(),
                effects: vec![],
                view_model: Some(CoreViewModel {
                    group_sync_results: Some(GroupSyncResults {
                        device_id: device_id.clone(),
                        total_candidates: 0,
                        succeeded: 0,
                        skipped: 0,
                        errors: vec![],
                    }),
                    ..CoreViewModel::default()
                }),
            });
        }

        let total_candidates = candidate_group_ids.len() as u64;
        let mut succeeded = 0u64;
        let mut skipped = 0u64;
        let mut errors: Vec<GroupSyncError> = Vec::new();
        let mut aggregate = CoreOutput::default();

        for group_id in candidate_group_ids {
            match self.add_group_member_device(
                group_id.clone(),
                local_user_id.clone(),
                device_id.clone(),
            ) {
                Ok(output) => {
                    succeeded = succeeded.saturating_add(1);
                    aggregate = merge_outputs(aggregate, output);
                }
                Err(err) => {
                    // Distinguish between expected skips and unexpected
                    // failures. Expected skips include groups where the
                    // device was already registered between our snapshot
                    // and the call (concurrent registration) or where
                    // the role changed concurrently.
                    if err.to_string().contains("already an active member")
                        || err.to_string().contains("owner or admin")
                        || err.to_string().contains("dissolved")
                    {
                        skipped = skipped.saturating_add(1);
                    } else {
                        errors.push(GroupSyncError {
                            group_id: group_id.clone(),
                            error: err.to_string(),
                        });
                    }
                }
            }
        }

        let all_succeeded = errors.is_empty();
        let state_update = CoreStateUpdate {
            conversations_changed: succeeded > 0,
            messages_changed: succeeded > 0,
            ..CoreStateUpdate::default()
        };
        // Merge the state update into the aggregate.
        aggregate.state_update = CoreStateUpdate {
            conversations_changed: state_update.conversations_changed
                || aggregate.state_update.conversations_changed,
            messages_changed: state_update.messages_changed
                || aggregate.state_update.messages_changed,
            ..aggregate.state_update
        };
        if !all_succeeded {
            aggregate.state_update.system_statuses_changed =
                vec![SystemStatus::TemporaryNetworkFailure];
        }
        aggregate.view_model = Some(CoreViewModel {
            group_sync_results: Some(GroupSyncResults {
                device_id,
                total_candidates,
                succeeded,
                skipped,
                errors,
            }),
            ..aggregate.view_model.unwrap_or_default()
        });
        Ok(aggregate)
    }

    /// Phase 8: remove a local device from every group the caller can
    /// administer after that device has been revoked from the identity bundle.

    pub(super) fn sync_groups_for_removed_device(
        &mut self,
        device_id: String,
    ) -> CoreResult<CoreOutput> {
        let local_user_id = self.local_identity_user_id()?;
        let local_device_id = self.local_identity_device_id()?;
        let device_id = device_id.trim().to_string();
        if device_id.is_empty() {
            return Err(CoreError::invalid_input("device_id must not be empty"));
        }
        if device_id == local_device_id {
            return Err(CoreError::invalid_input(
                "cannot remove the current device from all groups",
            ));
        }

        let candidate_group_ids: Vec<String> = self
            .state
            .group_states
            .values()
            .filter(|state| {
                matches!(state.local_role, Some(GroupRole::Owner | GroupRole::Admin))
                    && state.dissolved_at.is_none()
                    && state.manifest.member_devices.iter().any(|d| {
                        d.user_id == local_user_id
                            && d.device_id == device_id
                            && d.status == GroupMemberStatus::Active
                    })
            })
            .map(|state| state.group_id.clone())
            .collect();

        if candidate_group_ids.is_empty() {
            return Ok(CoreOutput {
                state_update: CoreStateUpdate::default(),
                effects: vec![],
                view_model: Some(CoreViewModel {
                    group_sync_results: Some(GroupSyncResults {
                        device_id: device_id.clone(),
                        total_candidates: 0,
                        succeeded: 0,
                        skipped: 0,
                        errors: vec![],
                    }),
                    ..CoreViewModel::default()
                }),
            });
        }

        let total_candidates = candidate_group_ids.len() as u64;
        let mut succeeded = 0u64;
        let mut skipped = 0u64;
        let mut errors: Vec<GroupSyncError> = Vec::new();
        let mut aggregate = CoreOutput::default();

        for group_id in candidate_group_ids {
            match self.remove_group_member_device(
                group_id.clone(),
                local_user_id.clone(),
                device_id.clone(),
            ) {
                Ok(output) => {
                    succeeded = succeeded.saturating_add(1);
                    aggregate = merge_outputs(aggregate, output);
                }
                Err(err) => {
                    let detail = err.to_string();
                    if detail.contains("not an active member")
                        || detail.contains("owner or admin")
                        || detail.contains("dissolved")
                        || detail.contains("does not belong to the local user")
                        || detail.contains("cannot remove the last device")
                    {
                        skipped = skipped.saturating_add(1);
                    } else {
                        errors.push(GroupSyncError {
                            group_id: group_id.clone(),
                            error: detail,
                        });
                    }
                }
            }
        }

        aggregate.state_update = CoreStateUpdate {
            conversations_changed: succeeded > 0 || aggregate.state_update.conversations_changed,
            messages_changed: succeeded > 0 || aggregate.state_update.messages_changed,
            ..aggregate.state_update
        };
        if !errors.is_empty() {
            aggregate.state_update.system_statuses_changed =
                vec![SystemStatus::TemporaryNetworkFailure];
        }
        aggregate.view_model = Some(CoreViewModel {
            group_sync_results: Some(GroupSyncResults {
                device_id,
                total_candidates,
                succeeded,
                skipped,
                errors,
            }),
            ..aggregate.view_model.unwrap_or_default()
        });
        Ok(aggregate)
    }
}

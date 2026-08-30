use super::*;

impl CoreEngine {
    pub(super) fn reconcile_conversation_membership(
        &mut self,
        conversation_id: String,
    ) -> CoreResult<CoreOutput> {
        let local_identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?;
        let peer_user_id = self.peer_user_for_conversation(&conversation_id)?;
        let peer_active_device_ids = self.peer_active_device_ids(&peer_user_id)?;
        let reconcile = {
            let conversation_state = self
                .state
                .conversations
                .get(&conversation_id)
                .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?;
            ConversationManager::reconcile_direct_membership(
                Some(conversation_state),
                ReconcileMembershipInput {
                    local_user_id: &local_identity.user_identity.user_id,
                    local_device_id: &local_identity.device_identity.device_id,
                    peer_user_id: &peer_user_id,
                    peer_active_device_ids: &peer_active_device_ids,
                },
            )?
        };
        {
            let conversation_state = self
                .state
                .conversations
                .get_mut(&conversation_id)
                .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?;
            ConversationManager::apply_reconciled_membership(
                conversation_state,
                &reconcile,
                &peer_active_device_ids,
                current_timestamp_hint(self.state.outbox.len()),
            );
        }
        let needs_rebootstrap = {
            let conversation_state = self
                .state
                .conversations
                .get(&conversation_id)
                .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?;
            conversation_state.conversation.state == ConversationState::NeedsRebuild
                || conversation_state.recovery_status == RecoveryStatus::NeedsRebuild
                || self
                    .state
                    .mls_summaries
                    .get(&conversation_id)
                    .map(|summary| summary.status == MlsStateStatus::NeedsRebuild)
                    .unwrap_or(false)
        };

        if !reconcile.changed && !needs_rebootstrap {
            let device_id = self
                .state
                .local_identity
                .as_ref()
                .map(|identity| identity.device_identity.device_id.clone());
            let should_drive_recovery = {
                let has_recovery_context =
                    self.state.recovery_contexts.contains_key(&conversation_id);
                let conversation_needs_recovery = self
                    .state
                    .conversations
                    .get(&conversation_id)
                    .map(|state| state.recovery_status != RecoveryStatus::Healthy)
                    .unwrap_or(false);
                let has_pending_records = device_id
                    .as_deref()
                    .map(|device_id| {
                        self.has_pending_records_for_conversation(device_id, &conversation_id)
                    })
                    .unwrap_or(false);
                has_recovery_context || conversation_needs_recovery || has_pending_records
            };
            let mut output = CoreOutput {
                state_update: CoreStateUpdate {
                    conversations_changed: true,
                    ..CoreStateUpdate::default()
                },
                effects: vec![],
                view_model: Some(CoreViewModel {
                    conversations: vec![self.conversation_summary(&conversation_id)?],
                    ..CoreViewModel::default()
                }),
            };
            if should_drive_recovery {
                if let Some(device_id) = device_id.clone() {
                    output = merge_outputs(output, self.sync_inbox(device_id.clone(), None)?);
                    output =
                        merge_outputs(output, self.replay_pending_records_for_device(device_id)?);
                }
            }
            let still_pending = device_id
                .as_deref()
                .map(|device_id| {
                    self.has_pending_records_for_conversation(device_id, &conversation_id)
                })
                .unwrap_or(false);
            if still_pending {
                self.transition_recovery_phase(&conversation_id, RecoveryPhase::WaitingForSync);
            } else {
                if let Some(adapter) = self.state.mls_adapter.as_mut() {
                    if let Ok(summary) = adapter.attempt_recovery(&conversation_id) {
                        self.state
                            .mls_summaries
                            .insert(conversation_id.clone(), summary);
                    }
                }
                self.clear_recovery_context_as_healthy(&conversation_id);
            }
            output.view_model = Some(CoreViewModel {
                conversations: vec![self.conversation_summary(&conversation_id)?],
                ..output.view_model.unwrap_or_default()
            });
            let recovery_context_op = if self.state.recovery_contexts.contains_key(&conversation_id)
            {
                PersistOp::SaveRecoveryContext {
                    conversation_id: conversation_id.clone(),
                }
            } else {
                PersistOp::DeleteRecoveryContext {
                    conversation_id: conversation_id.clone(),
                }
            };
            output.effects.push(persist_effect(
                &self.state,
                vec![
                    PersistOp::SaveConversation {
                        conversation_id: conversation_id.clone(),
                    },
                    PersistOp::SaveMlsState {
                        conversation_id: conversation_id.clone(),
                    },
                    recovery_context_op,
                ],
            ));
            refresh_persist_effect_snapshots(&mut output, &self.state);
            return self.merge_with_transport_flush(output);
        }

        if needs_rebootstrap {
            let key_packages = self.peer_key_packages(&peer_user_id, &peer_active_device_ids)?;
            let artifacts = self
                .state
                .mls_adapter
                .as_mut()
                .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
                .create_conversation(&conversation_id, &key_packages)?;
            let summary = self
                .state
                .mls_adapter
                .as_ref()
                .ok_or_else(|| CoreError::invalid_state("mls adapter missing after rebuild"))?
                .export_group_summary(&conversation_id)?;
            self.state
                .mls_summaries
                .insert(conversation_id.clone(), summary);
            if let Some(conversation_state) = self.state.conversations.get_mut(&conversation_id) {
                conversation_state.conversation.state = ConversationState::Active;
                conversation_state.recovery_status = RecoveryStatus::NeedsRecovery;
                conversation_state.conversation.member_devices = reconcile.member_devices.clone();
                conversation_state.last_known_peer_active_devices =
                    peer_active_device_ids.iter().cloned().collect();
            }

            let mut generated = self.commit_envelopes_for_artifacts(
                &conversation_id,
                &peer_active_device_ids,
                &artifacts,
            )?;
            generated.extend(self.welcome_envelopes_for_artifacts(&conversation_id, &artifacts)?);
            self.enqueue_envelopes(peer_user_id, generated.clone());
            self.mark_recovery_needed(&conversation_id, RecoveryReason::MembershipChanged);
            return self.merge_with_transport_flush(CoreOutput {
                state_update: CoreStateUpdate {
                    conversations_changed: true,
                    messages_changed: true,
                    contacts_changed: true,
                    system_statuses_changed: vec![SystemStatus::SyncInProgress],
                    ..CoreStateUpdate::default()
                },
                effects: vec![persist_effect(
                    &self.state,
                    vec![
                        PersistOp::SaveConversation {
                            conversation_id: conversation_id.clone(),
                        },
                        PersistOp::SaveMlsState {
                            conversation_id: conversation_id.clone(),
                        },
                    ],
                )],
                view_model: Some(CoreViewModel {
                    conversations: vec![self.conversation_summary(&conversation_id)?],
                    messages: generated
                        .iter()
                        .map(|envelope| MessageSummary {
                            conversation_id: envelope.conversation_id.clone(),
                            message_id: envelope.message_id.clone(),
                            message_type: envelope.message_type,
                        })
                        .collect(),
                    ..CoreViewModel::default()
                }),
            });
        }

        let mut generated = self.build_control_membership_changed_messages(
            &conversation_id,
            &peer_user_id,
            &peer_active_device_ids,
        )?;
        if !reconcile.added_devices.is_empty() {
            let key_packages = self.peer_key_packages(&peer_user_id, &reconcile.added_devices)?;
            let artifacts = self
                .state
                .mls_adapter
                .as_mut()
                .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
                .add_members(&conversation_id, &key_packages)?;
            generated.extend(self.commit_envelopes_for_artifacts(
                &conversation_id,
                &peer_active_device_ids,
                &artifacts,
            )?);
            generated.extend(self.welcome_envelopes_for_artifacts(&conversation_id, &artifacts)?);
        }
        if !reconcile.revoked_devices.is_empty() {
            let artifacts = self
                .state
                .mls_adapter
                .as_mut()
                .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
                .remove_members(&conversation_id, &reconcile.revoked_devices)?;
            generated.extend(self.commit_envelopes_for_remove(
                &conversation_id,
                &peer_active_device_ids,
                &artifacts,
            )?);
        }
        self.enqueue_envelopes(peer_user_id, generated.clone());
        self.mark_recovery_needed(&conversation_id, RecoveryReason::MembershipChanged);
        self.merge_with_transport_flush(CoreOutput {
            state_update: CoreStateUpdate {
                conversations_changed: true,
                messages_changed: true,
                contacts_changed: true,
                system_statuses_changed: vec![SystemStatus::SyncInProgress],
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(
                &self.state,
                vec![
                    PersistOp::SaveConversation {
                        conversation_id: conversation_id.clone(),
                    },
                    PersistOp::SaveMlsState {
                        conversation_id: conversation_id.clone(),
                    },
                ],
            )],
            view_model: Some(CoreViewModel {
                conversations: vec![self.conversation_summary(&conversation_id)?],
                messages: generated
                    .iter()
                    .map(|envelope| MessageSummary {
                        conversation_id: envelope.conversation_id.clone(),
                        message_id: envelope.message_id.clone(),
                        message_type: envelope.message_type,
                    })
                    .collect(),
                ..CoreViewModel::default()
            }),
        })
    }

    pub(super) fn refresh_identity_state(&mut self, user_id: String) -> CoreResult<CoreOutput> {
        for conversation_id in self.affected_conversations_for_peer(&user_id) {
            if let Some(context) = self.state.recovery_contexts.get_mut(&conversation_id) {
                if context.phase == RecoveryPhase::WaitingForIdentityRefresh {
                    context.attempt_count = context.attempt_count.saturating_add(1);
                    context.last_error = None;
                }
            }
        }
        let bundle = self
            .state
            .contacts
            .get(&user_id)
            .ok_or_else(|| CoreError::invalid_input("contact does not exist"))?;
        let reference = bundle.bundle.identity_bundle_ref.clone().ok_or_else(|| {
            CoreError::invalid_state("contact identity bundle reference is missing")
        })?;
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                system_statuses_changed: vec![SystemStatus::IdentityRefreshNeeded],
                ..CoreStateUpdate::default()
            },
            effects: vec![CoreEffect::FetchIdentityBundle {
                fetch: FetchIdentityBundleRequest {
                    user_id,
                    reference: Some(reference),
                },
            }],
            view_model: None,
        })
    }

    pub(super) fn rebuild_conversation(
        &mut self,
        conversation_id: String,
    ) -> CoreResult<CoreOutput> {
        let (member_device_ids, last_message_type, peer_user_id) = {
            let conversation_state = self
                .state
                .conversations
                .get_mut(&conversation_id)
                .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?;
            conversation_state.conversation.state = ConversationState::NeedsRebuild;
            conversation_state.recovery_status = RecoveryStatus::NeedsRebuild;
            (
                conversation_state
                    .conversation
                    .member_devices
                    .iter()
                    .map(|member| member.device_id.clone())
                    .collect::<Vec<_>>(),
                conversation_state.last_message_type,
                conversation_state.peer_user_id.clone(),
            )
        };
        if let Some(adapter) = self.state.mls_adapter.as_mut() {
            adapter.mark_needs_rebuild(&conversation_id);
            adapter.clear_conversation(&conversation_id);
        }
        self.ensure_recovery_context(&conversation_id, RecoveryReason::IdentityChanged);
        self.transition_recovery_phase(&conversation_id, RecoveryPhase::EscalatedToRebuild);
        if let Some(context) = self.state.recovery_contexts.get_mut(&conversation_id) {
            context
                .escalation_reason
                .get_or_insert(RecoveryEscalationReason::RecoveryPolicyExhausted);
        }
        self.state.mls_summaries.insert(
            conversation_id.clone(),
            MlsStateSummary {
                conversation_id: conversation_id.clone(),
                epoch: 0,
                member_device_ids,
                status: MlsStateStatus::NeedsRebuild,
                updated_at: 0,
            },
        );
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                conversations_changed: true,
                system_statuses_changed: vec![SystemStatus::ConversationNeedsRebuild],
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(
                &self.state,
                vec![
                    PersistOp::SaveConversation {
                        conversation_id: conversation_id.clone(),
                    },
                    PersistOp::SaveMlsState {
                        conversation_id: conversation_id.clone(),
                    },
                ],
            )],
            view_model: Some(CoreViewModel {
                conversations: vec![ConversationSummary {
                    conversation_id: conversation_id.clone(),
                    peer_user_id: peer_user_id.clone(),
                    state: "needs_rebuild".into(),
                    kind: Some(ConversationKind::Direct),
                    title: None,
                    display_name: self.contact_archive_display_name(&peer_user_id),
                    group_id: None,
                    member_count: None,
                    group_role: None,
                    group_cursor: None,
                    last_message_preview: None,
                    last_message_type,
                    message_count: None,
                    recovery: self.recovery_snapshot_for_conversation(&conversation_id),
                }],
                ..CoreViewModel::default()
            }),
        })
    }

    pub(super) fn start_foreground_sync(&mut self, reason: &str) -> CoreResult<CoreOutput> {
        let device_id = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .device_identity
            .device_id
            .clone();
        let output = merge_outputs(
            self.maintain_local_credentials(current_unix_millis(self.state.message_nonce))?,
            merge_outputs(
                self.migrate_legacy_removed_relationships()?,
                merge_outputs(
                    self.sync_inbox(device_id, Some(reason.to_string()))?,
                    self.retry_pending_welcome_pickups()?,
                ),
            ),
        );
        let output = merge_outputs(output, self.restore_degraded_output());
        let output = merge_outputs(
            output,
            self.initialize_locally_hosted_group_authorizations(),
        );
        let output = merge_outputs(output, self.resume_pending_group_secure_sends()?);
        self.merge_with_transport_flush(output)
    }

    pub(super) fn ensure_recovery_context(
        &mut self,
        conversation_id: &str,
        reason: RecoveryReason,
    ) -> &mut RecoveryContext {
        self.state
            .recovery_contexts
            .entry(conversation_id.to_string())
            .and_modify(|context| {
                context.reason = reason;
                if matches!(
                    context.phase,
                    RecoveryPhase::EscalatedToRebuild | RecoveryPhase::WaitingForExplicitReconcile
                ) {
                    return;
                }
                if matches!(reason, RecoveryReason::MissingCommit)
                    && matches!(context.phase, RecoveryPhase::WaitingForSync)
                {
                    context.phase = RecoveryPhase::WaitingForPendingReplay;
                }
            })
            .or_insert(RecoveryContext {
                conversation_id: conversation_id.to_string(),
                reason,
                phase: RecoveryPhase::WaitingForSync,
                attempt_count: 0,
                identity_refresh_retry_count: 0,
                last_error: None,
                escalation_reason: None,
                restore_failure_reason: None,
                restore_failure_detail: None,
                restore_recoverable: None,
                suggested_action: None,
            })
    }

    pub(super) fn mark_recovery_needed(&mut self, conversation_id: &str, reason: RecoveryReason) {
        let context = self.ensure_recovery_context(conversation_id, reason);
        if matches!(reason, RecoveryReason::MissingCommit)
            && matches!(context.phase, RecoveryPhase::WaitingForSync)
        {
            context.phase = RecoveryPhase::WaitingForPendingReplay;
        }
        if let Some(state) = self.state.conversations.get_mut(conversation_id) {
            state.recovery_status = RecoveryStatus::NeedsRecovery;
        }
        if let Some(adapter) = self.state.mls_adapter.as_mut() {
            adapter.mark_recovery_needed(conversation_id);
        }
    }

    pub(super) fn transition_recovery_phase(
        &mut self,
        conversation_id: &str,
        next_phase: RecoveryPhase,
    ) {
        if let Some(context) = self.state.recovery_contexts.get_mut(conversation_id) {
            if context.phase != next_phase {
                context.phase = next_phase;
                context.attempt_count = context.attempt_count.saturating_add(1);
            }
        }
    }

    pub(super) fn clear_recovery_context_as_healthy(&mut self, conversation_id: &str) {
        self.state.recovery_contexts.remove(conversation_id);
        if let Some(state) = self.state.conversations.get_mut(conversation_id) {
            if state.conversation.state != ConversationState::NeedsRebuild {
                state.recovery_status = RecoveryStatus::Healthy;
            }
        }
    }

    pub(super) fn escalate_conversation_to_rebuild(
        &mut self,
        conversation_id: &str,
        escalation_reason: RecoveryEscalationReason,
        message: impl Into<String>,
    ) -> CoreResult<CoreOutput> {
        let message = message.into();
        if let Some(context) = self.state.recovery_contexts.get_mut(conversation_id) {
            context.phase = RecoveryPhase::EscalatedToRebuild;
            context.escalation_reason = Some(escalation_reason);
            context.last_error = Some(message.clone());
        } else {
            self.state.recovery_contexts.insert(
                conversation_id.to_string(),
                RecoveryContext {
                    conversation_id: conversation_id.to_string(),
                    reason: RecoveryReason::IdentityChanged,
                    phase: RecoveryPhase::EscalatedToRebuild,
                    attempt_count: 0,
                    identity_refresh_retry_count: MAX_TRANSPORT_RETRIES,
                    last_error: Some(message.clone()),
                    escalation_reason: Some(escalation_reason),
                    restore_failure_reason: None,
                    restore_failure_detail: None,
                    restore_recoverable: None,
                    suggested_action: None,
                },
            );
        }
        self.rebuild_conversation(conversation_id.to_string())
    }

    pub(super) fn recovery_snapshot_for_conversation(
        &self,
        conversation_id: &str,
    ) -> Option<RecoveryDiagnostics> {
        let conversation = self.state.conversations.get(conversation_id)?;
        if conversation.recovery_status == RecoveryStatus::Healthy {
            return None;
        }
        let context = self.state.recovery_contexts.get(conversation_id);
        let local_device_id = self.local_device_id()?;
        let sync_state = self.state.sync_states.get(local_device_id);
        Some(RecoveryDiagnostics {
            conversation_id: conversation_id.to_string(),
            recovery_status: conversation.recovery_status,
            reason: context
                .map(|value| value.reason)
                .unwrap_or(RecoveryReason::MembershipChanged),
            phase: context
                .map(|value| value.phase)
                .unwrap_or(RecoveryPhase::EscalatedToRebuild),
            attempt_count: context.map(|value| value.attempt_count).unwrap_or(0),
            identity_refresh_retry_count: context
                .map(|value| value.identity_refresh_retry_count)
                .unwrap_or(0),
            pending_record_count: sync_state
                .map(|value| value.pending_records.len())
                .unwrap_or(0),
            pending_record_seqs: sync_state
                .map(|value| value.pending_record_seqs.iter().copied().collect())
                .unwrap_or_default(),
            last_fetched_seq: sync_state
                .map(|value| value.checkpoint.last_fetched_seq)
                .unwrap_or(0),
            last_acked_seq: sync_state
                .map(|value| value.checkpoint.last_acked_seq)
                .unwrap_or(0),
            mls_status: self
                .state
                .mls_summaries
                .get(conversation_id)
                .map(|value| value.status),
            escalation_reason: context.and_then(|value| value.escalation_reason),
            last_error: context.and_then(|value| value.last_error.clone()),
            recoverable: recovery_recoverable(
                conversation.conversation.state,
                context.and_then(|value| value.restore_recoverable),
            ),
            suggested_action: suggested_recovery_action(
                conversation.recovery_status,
                conversation.conversation.state,
                context.and_then(|value| value.suggested_action.clone()),
            ),
            restore_failure_reason: context.and_then(|value| value.restore_failure_reason.clone()),
            restore_failure_detail: context.and_then(|value| value.restore_failure_detail.clone()),
        })
    }

    pub(super) fn process_pending_recovery_batch(
        &mut self,
        device_id: &str,
        conversations: BTreeSet<String>,
        allow_pending_replay: bool,
    ) -> CoreResult<CoreOutput> {
        if conversations.is_empty() {
            return Ok(CoreOutput::default());
        }

        let pending_retry = self
            .state
            .sync_states
            .get(device_id)
            .map(|state| state.pending_retry)
            .unwrap_or(false);

        if pending_retry && allow_pending_replay {
            return self.replay_pending_records_for_device(device_id.to_string());
        }

        let next_phase = if pending_retry {
            RecoveryPhase::WaitingForPendingReplay
        } else {
            RecoveryPhase::WaitingForIdentityRefresh
        };
        for conversation_id in conversations {
            if self.state.conversations.contains_key(&conversation_id) {
                self.transition_recovery_phase(&conversation_id, next_phase);
            }
        }
        Ok(CoreOutput::default())
    }

    pub(super) fn ensure_local_conversation_for_record(
        &mut self,
        device_id: &str,
        local_user_id: &str,
        record: &InboxRecord,
    ) {
        self.state
            .conversations
            .entry(record.envelope.conversation_id.clone())
            .or_insert_with(|| LocalConversationState {
                conversation: crate::model::Conversation {
                    conversation_id: record.envelope.conversation_id.clone(),
                    kind: ConversationKind::Direct,
                    member_users: vec![
                        record.envelope.sender_user_id.clone(),
                        local_user_id.to_string(),
                    ],
                    member_devices: vec![
                        crate::model::ConversationMember {
                            user_id: record.envelope.sender_user_id.clone(),
                            device_id: record.envelope.sender_device_id.clone(),
                            status: crate::model::DeviceStatusKind::Active,
                        },
                        crate::model::ConversationMember {
                            user_id: local_user_id.to_string(),
                            device_id: device_id.to_string(),
                            status: crate::model::DeviceStatusKind::Active,
                        },
                    ],
                    state: ConversationState::Active,
                    updated_at: record.envelope.created_at,
                },
                messages: Vec::new(),
                last_message_type: None,
                peer_user_id: record.envelope.sender_user_id.clone(),
                last_known_peer_active_devices: BTreeSet::from([record
                    .envelope
                    .sender_device_id
                    .clone()]),
                recovery_status: RecoveryStatus::Healthy,
                archive_metadata: None,
            });
    }

    pub(super) fn has_pending_records_for_conversation(
        &self,
        device_id: &str,
        conversation_id: &str,
    ) -> bool {
        self.state
            .sync_states
            .get(device_id)
            .map(|sync_state| {
                sync_state
                    .pending_records
                    .values()
                    .any(|record| record.envelope.conversation_id == conversation_id)
            })
            .unwrap_or(false)
    }

    pub(super) fn ack_pending_records_for_conversation_up_to(
        &mut self,
        device_id: &str,
        conversation_id: &str,
        up_to_seq: u64,
        contiguous_ack: &mut u64,
        deferred_ackable_seqs: &mut BTreeSet<u64>,
    ) {
        let Some(sync_state) = self.state.sync_states.get_mut(device_id) else {
            return;
        };
        let pending_seqs: Vec<u64> = sync_state
            .pending_records
            .iter()
            .filter_map(|(seq, record)| {
                if *seq <= up_to_seq && record.envelope.conversation_id == conversation_id {
                    Some(*seq)
                } else {
                    None
                }
            })
            .collect();
        for seq in pending_seqs {
            log::warn!(
                "handle_inbox_records: clearing pending retry seq {} for conversation {} after later MLS record applied",
                seq,
                redact_id("conversation", conversation_id)
            );
            SyncEngine::clear_pending_retry(sync_state, seq);
            advance_contiguous_ack(contiguous_ack, deferred_ackable_seqs, seq);
        }
    }

    pub(super) fn recovery_reason_for_record(&self, conversation_id: &str) -> RecoveryReason {
        if self.state.mls_summaries.contains_key(conversation_id) {
            RecoveryReason::MissingCommit
        } else {
            RecoveryReason::MissingWelcome
        }
    }

    pub(super) fn handle_identity_refresh_failure(
        &mut self,
        user_id: &str,
        message: String,
    ) -> CoreResult<CoreOutput> {
        let affected_conversations = self.affected_conversations_for_peer(user_id);
        let mut should_retry = false;
        let mut retry_attempt = 1_u32;
        for conversation_id in &affected_conversations {
            if let Some(context) = self.state.recovery_contexts.get_mut(conversation_id) {
                if context.identity_refresh_retry_count < MAX_TRANSPORT_RETRIES {
                    context.identity_refresh_retry_count =
                        context.identity_refresh_retry_count.saturating_add(1);
                }
                retry_attempt = retry_attempt.max(u32::from(context.identity_refresh_retry_count));
                context.phase = RecoveryPhase::WaitingForIdentityRefresh;
                context.last_error = Some(message.clone());
                if context.identity_refresh_retry_count < MAX_TRANSPORT_RETRIES {
                    should_retry = true;
                }
            }
        }
        if should_retry {
            let timer_id = format!("refresh_identity:{user_id}");
            Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    contacts_changed: true,
                    system_statuses_changed: vec![SystemStatus::IdentityRefreshNeeded],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::ScheduleTimer {
                    timer: TimerEffect {
                        delay_ms: retry_delay_ms(&timer_id, retry_attempt),
                        timer_id,
                    },
                }],
                view_model: None,
            })
        } else {
            let mut output = CoreOutput::default();
            for conversation_id in affected_conversations {
                output = merge_outputs(
                    output,
                    self.escalate_conversation_to_rebuild(
                        &conversation_id,
                        RecoveryEscalationReason::IdentityRefreshRetryExhausted,
                        message.clone(),
                    )?,
                );
            }
            Ok(output)
        }
    }
}

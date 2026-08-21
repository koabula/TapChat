use super::*;

impl CoreEngine {
    pub(super) fn sync_group_outbox(
        &mut self,
        group_id: String,
        reason: Option<String>,
    ) -> CoreResult<CoreOutput> {
        let state = self
            .state
            .group_states
            .get(&group_id)
            .ok_or_else(|| CoreError::invalid_input("group does not exist"))?
            .clone();
        if state.consistency_state == GroupConsistencyState::BlockedNeedsRebuild {
            return Ok(CoreOutput::default());
        }
        let should_retry_pending = reason.as_deref().is_some_and(|reason| {
            matches!(
                reason,
                "runtime_upgraded" | "manual_retry" | "retry_pending"
            )
        });
        let retry_reset_message_ids = if should_retry_pending {
            self.reset_pending_group_outbox_for_retry(&group_id)
        } else {
            Vec::new()
        };
        if self.state.pending_sync_group_head.contains(&group_id) {
            return Ok(CoreOutput::default());
        }
        // Check head first so we only fetch when there is a real gap.
        // This avoids a wasteful fetch round-trip when the cursor is already
        // caught up — each group on every AppForegrounded / AppStarted fires
        // sync_group_outbox, and without the pre-check each one would issue
        // an HTTP fetch regardless of whether new records exist.
        self.state.pending_sync_group_head.insert(group_id.clone());
        let sync_output = CoreOutput {
            state_update: CoreStateUpdate {
                checkpoints_changed: true,
                system_statuses_changed: vec![SystemStatus::SyncInProgress],
                ..CoreStateUpdate::default()
            },
            effects: vec![CoreEffect::GetGroupOutboxHead {
                get: GetGroupOutboxHeadRequest {
                    group_id,
                    capability: self.group_capability_for_state(&state)?,
                },
            }],
            view_model: None,
        };
        if retry_reset_message_ids.is_empty() {
            return Ok(sync_output);
        }
        let persist_retry_reset = persist_effect(
            &self.state,
            retry_reset_message_ids
                .into_iter()
                .map(|message_id| PersistOp::SaveOutgoingGroupEnvelope { message_id })
                .collect(),
        );
        let retry_output = merge_outputs(
            CoreOutput {
                state_update: CoreStateUpdate {
                    checkpoints_changed: true,
                    messages_changed: true,
                    system_statuses_changed: vec![SystemStatus::SyncInProgress],
                    ..CoreStateUpdate::default()
                },
                effects: vec![persist_retry_reset],
                view_model: None,
            },
            self.flush_pending_transport()?,
        );
        Ok(merge_outputs(retry_output, sync_output))
    }

    pub(super) fn request_join_group(&mut self, invite_url: String) -> CoreResult<CoreOutput> {
        let descriptor_json = invite_url
            .strip_prefix("tapchat://welcome-pickup/")
            .map(|value| {
                let bytes = STANDARD.decode(value).map_err(|error| {
                    CoreError::invalid_input(format!(
                        "welcome pickup invite payload is not valid base64: {error}"
                    ))
                })?;
                String::from_utf8(bytes).map_err(|error| {
                    CoreError::invalid_input(format!(
                        "welcome pickup invite payload is not valid UTF-8: {error}"
                    ))
                })
            })
            .transpose()?
            .unwrap_or(invite_url);
        let descriptor: WelcomePickupDescriptor =
            serde_json::from_str(&descriptor_json).map_err(|error| {
                CoreError::invalid_input(format!(
                    "phase 2 request_join_group expects a welcome pickup descriptor JSON: {error}"
                ))
            })?;
        descriptor.validate()?;
        self.stage_welcome_pickup(descriptor.group_id.clone(), descriptor, None, None, true)
    }

    pub(super) fn stage_welcome_pickup(
        &mut self,
        group_id: String,
        descriptor: WelcomePickupDescriptor,
        title: Option<String>,
        inviter_user_id: Option<String>,
        reset_error: bool,
    ) -> CoreResult<CoreOutput> {
        descriptor.validate()?;
        if self.state.group_states.contains_key(&group_id) {
            self.state
                .pending_welcome_pickups
                .remove(&pending_welcome_pickup_key(
                    &group_id,
                    &descriptor.device_id,
                ));
            return Ok(CoreOutput::default());
        }
        let key = pending_welcome_pickup_key(&group_id, &descriptor.device_id);
        let mut pending = self
            .state
            .pending_welcome_pickups
            .get(&key)
            .cloned()
            .unwrap_or(PersistedPendingWelcomePickup {
                group_id: group_id.clone(),
                device_id: descriptor.device_id.clone(),
                descriptor: descriptor.clone(),
                title: title.clone(),
                inviter_user_id: inviter_user_id.clone(),
                retries: 0,
                last_error: None,
            });
        pending.group_id = group_id.clone();
        pending.device_id = descriptor.device_id.clone();
        pending.descriptor = descriptor.clone();
        if pending.title.is_none() {
            pending.title = title;
        }
        if pending.inviter_user_id.is_none() {
            pending.inviter_user_id = inviter_user_id;
        }
        if reset_error {
            pending.last_error = None;
        }
        self.state.pending_welcome_pickups.insert(key, pending);
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                system_statuses_changed: vec![SystemStatus::SyncInProgress],
                ..CoreStateUpdate::default()
            },
            effects: vec![
                persist_effect(
                    &self.state,
                    vec![PersistOp::SavePendingWelcomePickup {
                        group_id: group_id.clone(),
                        device_id: descriptor.device_id.clone(),
                    }],
                ),
                CoreEffect::FetchWelcomePickup {
                    fetch: FetchWelcomePickupRequest {
                        descriptor,
                        headers: BTreeMap::new(),
                    },
                },
            ],
            view_model: None,
        })
    }

    pub(super) fn retry_pending_welcome_pickups(&mut self) -> CoreResult<CoreOutput> {
        let pending: Vec<PersistedPendingWelcomePickup> = self
            .state
            .pending_welcome_pickups
            .values()
            .filter(|pickup| !self.state.group_states.contains_key(&pickup.group_id))
            .cloned()
            .collect();
        if pending.is_empty() {
            return Ok(CoreOutput::default());
        }
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                system_statuses_changed: vec![SystemStatus::SyncInProgress],
                ..CoreStateUpdate::default()
            },
            effects: pending
                .into_iter()
                .map(|pickup| CoreEffect::FetchWelcomePickup {
                    fetch: FetchWelcomePickupRequest {
                        descriptor: pickup.descriptor,
                        headers: BTreeMap::new(),
                    },
                })
                .collect(),
            view_model: None,
        })
    }

    pub(super) fn handle_welcome_pickup_put(
        &mut self,
        descriptor: WelcomePickupDescriptor,
    ) -> CoreResult<CoreOutput> {
        let group_state = self.state.group_states.get(&descriptor.group_id).cloned();
        let mut completed_join = None;
        let mut persist_ops = vec![PersistOp::SaveGroupState {
            group_id: descriptor.group_id.clone(),
        }];
        if let Some(state) = self.state.group_states.get_mut(&descriptor.group_id) {
            if let Some(pending) = state.pending_group_transition.as_mut() {
                pending
                    .welcomes
                    .retain(|welcome| welcome.descriptor.device_id != descriptor.device_id);
                if pending.stage == PendingGroupTransitionStage::AcceptedPublishingWelcomes
                    && pending.welcomes.is_empty()
                {
                    completed_join = pending.join_request_id.clone().map(|request_id| {
                        (
                            request_id,
                            pending.transition_id.clone(),
                            pending.proposed_manifest.clone(),
                            pending.last_seq.unwrap_or(0),
                        )
                    });
                    state.pending_group_transition = None;
                }
            }
        }
        if let Some(group_state) = group_state {
            if let Some(recipient_user_id) = group_state
                .manifest
                .member_devices
                .iter()
                .find(|device| device.device_id == descriptor.device_id)
                .map(|device| device.user_id.clone())
            {
                let local_user_id = self.local_identity_user_id()?;
                if recipient_user_id != local_user_id
                    && self.state.contacts.contains_key(&recipient_user_id)
                {
                    let direct_conversation_id = self
                        .active_direct_conversation_for_peer(&recipient_user_id)
                        .map(|(conversation_id, _)| conversation_id)
                        .ok_or_else(|| {
                            CoreError::new(
                                "protocol_upgrade_required",
                                "group Welcome delivery requires an accepted V2 Direct relationship",
                            )
                        })?;
                    let relationship_id =
                        self.direct_relationship_id_for_conversation(&direct_conversation_id)?;
                    let invite = GroupWelcomePickupControl {
                        version: crate::model::CURRENT_MODEL_VERSION.to_string(),
                        group_id: group_state.group_id.clone(),
                        conversation_id: group_state.conversation_id.clone(),
                        title: group_state.manifest.title.clone(),
                        inviter_user_id: local_user_id,
                        welcome_pickup_descriptor: descriptor.clone(),
                    };
                    let payload = serde_json::to_vec(&invite).map_err(|error| {
                        CoreError::invalid_input(format!(
                            "failed to encode group welcome pickup control: {error}"
                        ))
                    })?;
                    let envelope = self.build_envelope_v2(
                        &relationship_id,
                        &recipient_user_id,
                        &descriptor.device_id,
                        MessageType::ControlGroupWelcomePickup,
                        STANDARD.encode(payload),
                        None,
                    )?;
                    persist_ops.push(PersistOp::SaveOutgoingEnvelope {
                        message_id: envelope.message_id.clone(),
                    });
                    self.enqueue_envelopes_v2(recipient_user_id, vec![envelope]);
                }
            }
        }
        let mut output = CoreOutput {
            state_update: CoreStateUpdate {
                checkpoints_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(&self.state, persist_ops)],
            view_model: Some(CoreViewModel {
                welcome_pickups: vec![descriptor.clone()],
                ..CoreViewModel::default()
            }),
        };
        if let Some((request_id, transition_id, manifest, start_seq)) = completed_join {
            let state = self
                .state
                .group_states
                .get(&descriptor.group_id)
                .ok_or_else(|| CoreError::invalid_input("group does not exist"))?;
            let lease_token = self
                .state
                .group_join_requests
                .get(&request_id)
                .and_then(|stored| stored.lease_token.clone())
                .ok_or_else(|| {
                    CoreError::invalid_state("group join completion is missing its lease")
                })?;
            output.effects.push(CoreEffect::CompleteGroupJoinRequest {
                complete: CompleteGroupJoinRequest {
                    version: crate::model::CURRENT_MODEL_VERSION.to_string(),
                    group_id: descriptor.group_id.clone(),
                    request_id,
                    capability: self.group_capability_for_state(state)?,
                    lease_token,
                    transition_id,
                    welcome_pickup: descriptor.clone(),
                    manifest,
                    start_cursor: GroupCursor {
                        group_id: descriptor.group_id.clone(),
                        last_fetched_seq: start_seq,
                        updated_at: current_unix_millis(self.state.message_nonce),
                    },
                },
            });
        }
        self.merge_with_transport_flush(output)
    }

    pub(super) fn initialize_locally_hosted_group_authorizations(&self) -> CoreOutput {
        let Some(deployment) = self.state.deployment_bundle.as_ref() else {
            return CoreOutput::default();
        };
        if !deployment
            .runtime_config
            .features
            .iter()
            .any(|feature| feature == "group_authorization_v2")
        {
            return CoreOutput::default();
        }
        let Some(local_user_id) = self
            .state
            .local_identity
            .as_ref()
            .map(|identity| identity.user_identity.user_id.as_str())
        else {
            return CoreOutput::default();
        };
        let local_base = deployment.inbox_http_endpoint.trim_end_matches('/');
        let mut effects = Vec::new();
        for (group_id, state) in &self.state.group_states {
            if state.local_role != Some(GroupRole::Owner)
                || state.manifest.owner_user_id != local_user_id
                || !state.manifest.outbox.endpoint.starts_with(local_base)
            {
                continue;
            }
            match self.initialize_group_authorization_request(group_id) {
                Ok(initialize) => {
                    effects.push(CoreEffect::InitializeGroupAuthorization { initialize })
                }
                Err(error) => log::warn!(
                    "skipping group authorization migration for {}: {}",
                    redact_id("group", group_id),
                    error.code()
                ),
            }
        }
        CoreOutput {
            state_update: CoreStateUpdate::default(),
            effects,
            view_model: None,
        }
    }

    pub(super) fn restore_degraded_output(&self) -> CoreOutput {
        let conversation_ids: Vec<String> = self
            .state
            .conversations
            .keys()
            .filter(|conversation_id| {
                self.recovery_snapshot_for_conversation(conversation_id)
                    .is_some_and(|recovery| is_degraded_restore_diagnostic(&recovery))
            })
            .cloned()
            .collect();
        let conversations: Vec<ConversationSummary> = conversation_ids
            .iter()
            .filter_map(|conversation_id| self.conversation_summary(conversation_id).ok())
            .collect();
        if conversations.is_empty() {
            return CoreOutput::default();
        }
        let message = if conversations.len() == 1 {
            "A secure conversation needs recovery before it can send new messages.".to_string()
        } else {
            format!(
                "{} secure conversations need recovery before they can send new messages.",
                conversations.len()
            )
        };
        let persist_ops = conversation_ids
            .into_iter()
            .flat_map(|conversation_id| {
                [
                    PersistOp::SaveConversation {
                        conversation_id: conversation_id.clone(),
                    },
                    PersistOp::SaveMlsState {
                        conversation_id: conversation_id.clone(),
                    },
                    PersistOp::SaveRecoveryContext { conversation_id },
                ]
            })
            .collect();
        CoreOutput {
            state_update: CoreStateUpdate {
                conversations_changed: true,
                system_statuses_changed: vec![SystemStatus::ConversationNeedsRebuild],
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(&self.state, persist_ops)],
            view_model: Some(CoreViewModel {
                conversations,
                banners: vec![SystemBanner {
                    status: SystemStatus::ConversationNeedsRebuild,
                    message,
                }],
                ..CoreViewModel::default()
            }),
        }
    }

    pub(super) fn apply_group_realtime_plan(
        &mut self,
        websocket_group_ids: Vec<String>,
    ) -> CoreResult<CoreOutput> {
        let desired: BTreeSet<String> = websocket_group_ids.into_iter().collect();
        let mut effects = Vec::new();
        let existing: Vec<String> = self.state.group_realtime_sessions.keys().cloned().collect();
        for group_id in existing {
            if desired.contains(&group_id) {
                continue;
            }
            if let Some(session) = self.state.group_realtime_sessions.get_mut(&group_id) {
                session.connected = false;
                session.needs_reconnect = false;
            }
            effects.push(CoreEffect::CloseGroupRealtimeConnection { group_id });
        }

        for group_id in desired {
            let group_state = match self.state.group_states.get(&group_id) {
                Some(state) => state.clone(),
                None => continue,
            };
            let subscribe_endpoint = match &group_state.manifest.outbox.subscribe_endpoint {
                Some(endpoint) => endpoint.clone(),
                None => continue,
            };
            let last_seq = self
                .state
                .group_cursors
                .get(&group_id)
                .map(|cursor| cursor.last_fetched_seq)
                .unwrap_or(0);
            let local_role = group_state
                .local_role
                .unwrap_or(crate::model::GroupRole::Member);
            let capability = self.group_capability(&group_id, local_role)?;
            self.state
                .group_realtime_sessions
                .entry(group_id.clone())
                .or_insert_with(|| GroupRealtimeSessionState {
                    connected: false,
                    last_known_seq: last_seq,
                    needs_reconnect: false,
                    reconnect_failures: 0,
                });
            effects.push(CoreEffect::OpenGroupRealtimeConnection {
                subscription: crate::transport_contract::GroupRealtimeSubscriptionRequest {
                    group_id,
                    endpoint: subscribe_endpoint,
                    last_seq,
                    capability,
                    headers: BTreeMap::new(),
                },
            });
        }
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                checkpoints_changed: true,
                ..CoreStateUpdate::default()
            },
            effects,
            view_model: None,
        })
    }

    pub(super) fn handle_websocket_connected(
        &mut self,
        device_id: String,
    ) -> CoreResult<CoreOutput> {
        let last_known_seq = {
            let session = self
                .state
                .realtime_sessions
                .entry(device_id.clone())
                .or_default();
            session.connected = true;
            session.needs_reconnect = false;
            session.reconnect_failures = 0;
            session.last_known_seq
        };

        let sync_state = self
            .state
            .sync_states
            .entry(device_id.clone())
            .or_insert_with(|| SyncEngine::new_device_state(&device_id));
        SyncEngine::clear_sync_failures(sync_state);
        if last_known_seq > 0 {
            SyncEngine::register_head(sync_state, last_known_seq);
        }

        let mut output = CoreOutput {
            state_update: CoreStateUpdate {
                checkpoints_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![],
            view_model: None,
        };
        if let Some(decision) = SyncEngine::next_fetch(sync_state) {
            output = merge_outputs(output, self.issue_fetch(device_id, decision)?);
        }
        Ok(output)
    }

    pub(super) fn handle_websocket_disconnected(
        &mut self,
        device_id: String,
    ) -> CoreResult<CoreOutput> {
        let session = self
            .state
            .realtime_sessions
            .entry(device_id.clone())
            .or_default();
        session.connected = false;
        session.needs_reconnect = true;
        session.reconnect_failures = session.reconnect_failures.saturating_add(1);
        let timer = self.sync_retry_timer(&device_id);
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                checkpoints_changed: true,
                system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                ..CoreStateUpdate::default()
            },
            effects: vec![CoreEffect::ScheduleTimer { timer }],
            view_model: None,
        })
    }

    pub(super) fn handle_group_websocket_connected(
        &mut self,
        group_id: String,
    ) -> CoreResult<CoreOutput> {
        let session = self
            .state
            .group_realtime_sessions
            .entry(group_id)
            .or_default();
        session.connected = true;
        session.needs_reconnect = false;
        session.reconnect_failures = 0;
        Ok(CoreOutput::default())
    }

    pub(super) fn handle_group_websocket_disconnected(
        &mut self,
        group_id: String,
        error: Option<String>,
    ) -> CoreResult<CoreOutput> {
        let session = self
            .state
            .group_realtime_sessions
            .entry(group_id.clone())
            .or_default();
        session.connected = false;
        session.needs_reconnect = true;
        session.reconnect_failures = session.reconnect_failures.saturating_add(1);
        let timer_id = format!("group_sync:{group_id}");
        let delay_ms = retry_delay_ms(&timer_id, session.reconnect_failures);
        let notification = error.and_then(|detail| {
            if detail.contains("404") {
                Some(CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect {
                        status: SystemStatus::TemporaryNetworkFailure,
                        message:
                            "Cloudflare runtime does not support group outbox. Upgrade runtime."
                                .into(),
                    },
                })
            } else {
                None
            }
        });
        let mut effects = vec![CoreEffect::ScheduleTimer {
            timer: TimerEffect { timer_id, delay_ms },
        }];
        if let Some(notification) = notification {
            effects.push(notification);
        }
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                checkpoints_changed: true,
                system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                ..CoreStateUpdate::default()
            },
            effects,
            view_model: None,
        })
    }

    pub(super) fn group_sync_retry_timer(&mut self, group_id: &str) -> TimerEffect {
        let session = self
            .state
            .group_realtime_sessions
            .entry(group_id.to_string())
            .or_default();
        session.reconnect_failures = session.reconnect_failures.saturating_add(1);
        let timer_id = format!("group_sync:{group_id}");
        TimerEffect {
            delay_ms: retry_delay_ms(&timer_id, session.reconnect_failures),
            timer_id,
        }
    }

    pub(super) fn handle_group_sync_failed(
        &mut self,
        group_id: String,
        retryable: bool,
        status: Option<u16>,
        code: Option<String>,
        detail: Option<String>,
    ) -> CoreResult<CoreOutput> {
        if status == Some(403) && code.as_deref() == Some("group_membership_revoked") {
            let revoked_message_ids: Vec<String> = self
                .state
                .pending_group_outbox
                .iter()
                .filter(|item| item.envelope.group_id == group_id)
                .map(|item| item.envelope.message_id.clone())
                .collect();
            self.state
                .pending_group_outbox
                .retain(|item| item.envelope.group_id != group_id);
            let removed_pending_seal = self.state.pending_group_seal.remove(&group_id).is_some();
            let mut persist_ops = revoked_message_ids
                .into_iter()
                .map(|message_id| PersistOp::DeleteOutgoingGroupEnvelope { message_id })
                .collect::<Vec<_>>();
            if removed_pending_seal {
                persist_ops.push(PersistOp::DeletePendingGroupSeal {
                    group_id: group_id.clone(),
                });
            }
            if let Some(state) = self.state.group_states.get_mut(&group_id) {
                state.local_role = None;
                state.consistency_state = GroupConsistencyState::BlockedNeedsRebuild;
                state.pending_membership_transition = None;
                state.pending_group_transition = None;
                persist_ops.push(PersistOp::SaveGroupState {
                    group_id: group_id.clone(),
                });
                if let Some(conversation) = self.state.conversations.get_mut(&state.conversation_id)
                {
                    conversation.conversation.state = ConversationState::Closed;
                    persist_ops.push(PersistOp::SaveConversation {
                        conversation_id: state.conversation_id.clone(),
                    });
                }
            }
            self.state.pending_sync_group_head.remove(&group_id);
            self.state.group_sync_target_head.remove(&group_id);
            return Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    conversations_changed: true,
                    system_statuses_changed: vec![SystemStatus::GroupMembershipRevoked],
                    ..CoreStateUpdate::default()
                },
                effects: vec![
                    persist_effect(&self.state, persist_ops),
                    CoreEffect::CloseGroupRealtimeConnection {
                        group_id: group_id.clone(),
                    },
                    CoreEffect::EmitUserNotification {
                        notification: UserNotificationEffect {
                            status: SystemStatus::GroupMembershipRevoked,
                            message: format!("you are no longer a member of group {group_id}"),
                        },
                    },
                ],
                view_model: None,
            });
        }
        if status == Some(403) && code.as_deref() == Some("invalid_capability") {
            let mut persist_ops = Vec::new();
            if let Some(state) = self.state.group_states.get_mut(&group_id) {
                state.local_role = None;
                persist_ops.push(PersistOp::SaveGroupState {
                    group_id: group_id.clone(),
                });
                if let Some(conversation) = self.state.conversations.get_mut(&state.conversation_id)
                {
                    conversation.conversation.state = ConversationState::NeedsRebuild;
                    conversation.recovery_status = RecoveryStatus::NeedsRebuild;
                    persist_ops.push(PersistOp::SaveConversation {
                        conversation_id: state.conversation_id.clone(),
                    });
                }
            }
            return Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    conversations_changed: true,
                    system_statuses_changed: vec![SystemStatus::ConversationNeedsRebuild],
                    ..CoreStateUpdate::default()
                },
                effects: vec![persist_effect(&self.state, persist_ops)],
                view_model: None,
            });
        }
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                ..CoreStateUpdate::default()
            },
            effects: if retryable {
                vec![CoreEffect::ScheduleTimer {
                    timer: self.group_sync_retry_timer(&group_id),
                }]
            } else {
                vec![CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect {
                        status: SystemStatus::TemporaryNetworkFailure,
                        message: detail
                            .map(|detail| format!("group outbox sync failed: {detail}"))
                            .unwrap_or_else(|| format!("group outbox sync failed for {group_id}")),
                    },
                }]
            },
            view_model: None,
        })
    }

    pub(super) fn handle_group_realtime_event(
        &mut self,
        group_id: String,
        event: RealtimeEvent,
    ) -> CoreResult<CoreOutput> {
        if self.state.group_states.get(&group_id).is_some_and(|state| {
            state.consistency_state == GroupConsistencyState::BlockedNeedsRebuild
        }) {
            return Ok(CoreOutput::default());
        }
        match event {
            RealtimeEvent::GroupHeadUpdated {
                group_id: event_group_id,
                seq,
            } => {
                if event_group_id != group_id {
                    return Ok(CoreOutput::default());
                }
                self.state
                    .group_realtime_sessions
                    .entry(group_id.clone())
                    .or_default()
                    .last_known_seq = seq;
                let needs_backfill = self
                    .state
                    .group_cursors
                    .get(&group_id)
                    .map(|cursor| seq > cursor.last_fetched_seq)
                    .unwrap_or(true);
                if needs_backfill {
                    let group_state = self
                        .state
                        .group_states
                        .get(&group_id)
                        .ok_or_else(|| CoreError::invalid_input("group does not exist"))?
                        .clone();
                    let capability = self.group_capability(
                        &group_id,
                        group_state
                            .local_role
                            .unwrap_or(crate::model::GroupRole::Member),
                    )?;
                    let from_seq = self
                        .state
                        .group_cursors
                        .get(&group_id)
                        .map(|cursor| cursor.last_fetched_seq.saturating_add(1))
                        .unwrap_or(1);
                    let fetch = crate::transport_contract::FetchGroupOutboxRequest {
                        group_id: group_id.clone(),
                        from_seq,
                        limit: GROUP_OUTBOX_FETCH_LIMIT,
                        capability,
                    };
                    Ok(CoreOutput {
                        state_update: CoreStateUpdate {
                            checkpoints_changed: true,
                            ..CoreStateUpdate::default()
                        },
                        effects: vec![CoreEffect::FetchGroupOutbox { fetch }],
                        view_model: None,
                    })
                } else {
                    Ok(CoreOutput::default())
                }
            }
            RealtimeEvent::GroupOutboxRecordAvailable {
                group_id: event_group_id,
                seq,
                record,
            } => {
                if event_group_id != group_id {
                    return Ok(CoreOutput::default());
                }
                self.state
                    .group_realtime_sessions
                    .entry(group_id.clone())
                    .or_default()
                    .last_known_seq = seq;
                // A realtime notification may contain only one record from an
                // atomic transition bundle.  Never ingest it directly; use it
                // solely as a head hint and fetch from the durable cursor.
                let _ = record;
                {
                    let needs_backfill = self
                        .state
                        .group_cursors
                        .get(&group_id)
                        .map(|cursor| seq > cursor.last_fetched_seq)
                        .unwrap_or(true);
                    if needs_backfill {
                        let group_state = self
                            .state
                            .group_states
                            .get(&group_id)
                            .ok_or_else(|| CoreError::invalid_input("group does not exist"))?
                            .clone();
                        let capability = self.group_capability(
                            &group_id,
                            group_state
                                .local_role
                                .unwrap_or(crate::model::GroupRole::Member),
                        )?;
                        let from_seq = self
                            .state
                            .group_cursors
                            .get(&group_id)
                            .map(|cursor| cursor.last_fetched_seq.saturating_add(1))
                            .unwrap_or(1);
                        let fetch = crate::transport_contract::FetchGroupOutboxRequest {
                            group_id: group_id.clone(),
                            from_seq,
                            limit: GROUP_OUTBOX_FETCH_LIMIT,
                            capability,
                        };
                        Ok(CoreOutput {
                            state_update: CoreStateUpdate {
                                checkpoints_changed: true,
                                ..CoreStateUpdate::default()
                            },
                            effects: vec![CoreEffect::FetchGroupOutbox { fetch }],
                            view_model: None,
                        })
                    } else {
                        Ok(CoreOutput::default())
                    }
                }
            }
            RealtimeEvent::GroupInvitesChanged {
                group_id: event_group_id,
                revision: _,
            } if event_group_id == group_id => self.list_group_invites(group_id),
            RealtimeEvent::GroupAutoJoinAvailable {
                group_id: event_group_id,
                request_id: _,
            }
            | RealtimeEvent::GroupJoinRequestAvailable {
                group_id: event_group_id,
                request_id: _,
            } if event_group_id == group_id => self.list_group_join_requests(group_id),
            RealtimeEvent::GroupLeaveRequestAvailable {
                group_id: event_group_id,
                request_id: _,
            } if event_group_id == group_id => self.list_group_leave_requests(group_id),
            _ => Ok(CoreOutput::default()),
        }
    }

    pub(super) fn handle_group_outbox_head_fetched(
        &mut self,
        group_id: String,
        head_seq: u64,
        current_roster_version: Option<u64>,
        last_commit_message_id: Option<String>,
    ) -> CoreResult<CoreOutput> {
        if self.state.group_states.get(&group_id).is_some_and(|state| {
            state.consistency_state == GroupConsistencyState::BlockedNeedsRebuild
        }) {
            self.state.pending_sync_group_head.remove(&group_id);
            self.state.group_sync_target_head.remove(&group_id);
            return Ok(CoreOutput::default());
        }
        if let Some(session) = self.state.group_realtime_sessions.get_mut(&group_id) {
            session.reconnect_failures = 0;
        }
        if let Some(remote_roster) = current_roster_version {
            let local = self
                .state
                .group_states
                .get(&group_id)
                .ok_or_else(|| CoreError::invalid_input("group does not exist"))?;
            if local.manifest.roster_version != remote_roster
                || local.manifest.last_commit_message_id != last_commit_message_id
            {
                let capability = self.group_capability_for_state(local)?;
                if let Some(state) = self.state.group_states.get_mut(&group_id) {
                    state.consistency_state = GroupConsistencyState::Reconciling;
                }
                self.state
                    .group_sync_target_head
                    .insert(group_id.clone(), head_seq);
                self.state.pending_sync_group_head.remove(&group_id);
                return Ok(CoreOutput {
                    state_update: CoreStateUpdate {
                        checkpoints_changed: true,
                        ..CoreStateUpdate::default()
                    },
                    effects: vec![CoreEffect::GetGroupAuthorizationState {
                        get: GetGroupAuthorizationStateRequest {
                            group_id,
                            capability,
                        },
                    }],
                    view_model: None,
                });
            }
            if let Some(state) = self.state.group_states.get_mut(&group_id) {
                if state.consistency_state == GroupConsistencyState::Reconciling {
                    state.consistency_state = GroupConsistencyState::Ready;
                }
            }
        }
        // If this head request was issued by sync_group_outbox (not by the
        // welcome-pickup join fast-forward path), fetch the actual records
        // rather than skipping ahead.
        if self.state.pending_sync_group_head.remove(&group_id) {
            log::info!(
                "handle_group_outbox_head_fetched: sync head group_id={} head_seq={}",
                group_id,
                head_seq
            );
            let cursor = self
                .state
                .group_cursors
                .get(&group_id)
                .cloned()
                .unwrap_or(GroupCursor {
                    group_id: group_id.clone(),
                    last_fetched_seq: 0,
                    updated_at: 0,
                });
            let from_seq = cursor.last_fetched_seq.saturating_add(1).max(1);
            if head_seq < from_seq {
                // Already caught up — nothing to fetch.
                log::info!(
                    "handle_group_outbox_head_fetched: already caught up group_id={} head_seq={} cursor={}",
                    group_id,
                    head_seq,
                    cursor.last_fetched_seq
                );
                return Ok(CoreOutput {
                    state_update: CoreStateUpdate {
                        checkpoints_changed: true,
                        ..CoreStateUpdate::default()
                    },
                    effects: vec![],
                    view_model: None,
                });
            }
            // Store the target head so the fetch loop in
            // handle_group_outbox_records knows when it has caught up.
            self.state
                .group_sync_target_head
                .insert(group_id.clone(), head_seq);
            let state = self
                .state
                .group_states
                .get(&group_id)
                .ok_or_else(|| CoreError::invalid_input("group does not exist"))?
                .clone();
            let limit = GROUP_OUTBOX_FETCH_LIMIT;
            Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    checkpoints_changed: true,
                    system_statuses_changed: vec![SystemStatus::SyncInProgress],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::FetchGroupOutbox {
                    fetch: FetchGroupOutboxRequest {
                        group_id,
                        from_seq,
                        limit,
                        capability: self.group_capability_for_state(&state)?,
                    },
                }],
                view_model: None,
            })
        } else {
            Ok(CoreOutput::default())
        }
    }

    pub(super) fn handle_group_authorization_state_fetched(
        &mut self,
        group_id: String,
        manifest: GroupManifest,
        manifest_hash: String,
        _last_transition_id: Option<String>,
        phase: crate::transport_contract::GroupAuthorizationPhase,
        materialized: bool,
    ) -> CoreResult<CoreOutput> {
        if self.state.group_states.get(&group_id).is_some_and(|state| {
            state.consistency_state == GroupConsistencyState::BlockedNeedsRebuild
        }) {
            return Ok(CoreOutput::default());
        }
        manifest.validate()?;
        self.verify_manifest_signature(&manifest)?;
        if phase == crate::transport_contract::GroupAuthorizationPhase::Active && !materialized {
            return self.block_group_needs_rebuild(
                &group_id,
                "active authorization state is not materialized",
            );
        }
        if Self::manifest_sha256(&manifest)? != manifest_hash {
            return Err(CoreError::invalid_input(
                "group authorization manifest hash does not match the response",
            ));
        }
        let local = self
            .state
            .group_states
            .get(&group_id)
            .ok_or_else(|| CoreError::invalid_input("group does not exist"))?
            .clone();
        let local_hash = Self::manifest_sha256(&local.manifest)?;
        let local_epoch = self
            .state
            .mls_summaries
            .get(&local.conversation_id)
            .map(|summary| summary.epoch)
            .unwrap_or(0);

        if local_hash == manifest_hash && local_epoch == manifest.mls_epoch_hint {
            if let Some(state) = self.state.group_states.get_mut(&group_id) {
                state.consistency_state = GroupConsistencyState::Ready;
            }
            if self.state.group_states.get(&group_id).is_some_and(|state| {
                state
                    .pending_group_transition
                    .as_ref()
                    .is_some_and(|pending| {
                        pending.stage == PendingGroupTransitionStage::ReconcilingAfterConflict
                    })
            }) {
                return self.resume_group_transition_after_reconciliation(group_id);
            }
            return Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    checkpoints_changed: true,
                    ..CoreStateUpdate::default()
                },
                effects: vec![persist_effect(
                    &self.state,
                    vec![PersistOp::SaveGroupState {
                        group_id: group_id.clone(),
                    }],
                )],
                view_model: None,
            });
        }

        if manifest.roster_version < local.manifest.roster_version
            || (manifest.roster_version == local.manifest.roster_version
                && local_hash != manifest_hash)
            || manifest.mls_epoch_hint < local_epoch
        {
            return self.block_group_needs_rebuild(
                &group_id,
                "authoritative group state conflicts with the local manifest or MLS epoch",
            );
        }

        let from_seq = self
            .state
            .group_cursors
            .get(&group_id)
            .map(|cursor| cursor.last_fetched_seq.saturating_add(1).max(1))
            .unwrap_or(1);
        let capability = self.group_capability_for_state(&local)?;
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                checkpoints_changed: true,
                system_statuses_changed: vec![SystemStatus::SyncInProgress],
                ..CoreStateUpdate::default()
            },
            effects: vec![CoreEffect::FetchGroupOutbox {
                fetch: FetchGroupOutboxRequest {
                    group_id,
                    from_seq,
                    limit: GROUP_OUTBOX_FETCH_LIMIT,
                    capability,
                },
            }],
            view_model: None,
        })
    }

    pub(super) fn group_transition_target_achieved(
        operation: &GroupTransitionOperation,
        manifest: &GroupManifest,
    ) -> bool {
        match operation {
            GroupTransitionOperation::Create => manifest.roster_version >= 1,
            GroupTransitionOperation::InviteMembers { user_ids } => {
                user_ids.iter().all(|user_id| {
                    manifest.members.iter().any(|member| {
                        member.user_id == *user_id && member.status == GroupMemberStatus::Active
                    })
                })
            }
            GroupTransitionOperation::ApproveJoin {
                user_id, device_id, ..
            } => {
                manifest.members.iter().any(|member| {
                    member.user_id == *user_id && member.status == GroupMemberStatus::Active
                }) && manifest.member_devices.iter().any(|device| {
                    device.user_id == *user_id
                        && device.device_id == *device_id
                        && device.status == GroupMemberStatus::Active
                })
            }
            GroupTransitionOperation::ApproveLeave { user_id, .. }
            | GroupTransitionOperation::RemoveMember { user_id } => {
                !manifest.members.iter().any(|member| {
                    member.user_id == *user_id && member.status == GroupMemberStatus::Active
                })
            }
            GroupTransitionOperation::TransferOwnership { user_id } => {
                manifest.owner_user_id == *user_id
            }
            GroupTransitionOperation::SetAdmin { user_id, is_admin } => manifest
                .members
                .iter()
                .find(|member| member.user_id == *user_id)
                .is_some_and(|member| (member.role == GroupRole::Admin) == *is_admin),
            GroupTransitionOperation::UpdateMetadata => false,
            GroupTransitionOperation::Dissolve => false,
            GroupTransitionOperation::AddDevice { user_id, device_id } => {
                manifest.member_devices.iter().any(|device| {
                    device.user_id == *user_id
                        && device.device_id == *device_id
                        && device.status == GroupMemberStatus::Active
                })
            }
            GroupTransitionOperation::RemoveDevice { user_id, device_id } => {
                !manifest.member_devices.iter().any(|device| {
                    device.user_id == *user_id
                        && device.device_id == *device_id
                        && device.status == GroupMemberStatus::Active
                })
            }
        }
    }

    pub(super) fn command_for_group_transition_intent(
        group_id: &str,
        operation: &GroupTransitionOperation,
        proposed: &GroupManifest,
    ) -> Option<CoreCommand> {
        Some(match operation {
            GroupTransitionOperation::Create => return None,
            GroupTransitionOperation::InviteMembers { user_ids } => CoreCommand::InviteToGroup {
                group_id: group_id.to_string(),
                invitee_user_ids: user_ids.clone(),
            },
            GroupTransitionOperation::ApproveJoin { request_id, .. } => {
                CoreCommand::ApproveGroupJoin {
                    group_id: group_id.to_string(),
                    request_id: request_id.clone(),
                }
            }
            GroupTransitionOperation::ApproveLeave { request_id, .. } => {
                CoreCommand::ApproveGroupLeave {
                    group_id: group_id.to_string(),
                    request_id: request_id.clone(),
                }
            }
            GroupTransitionOperation::RemoveMember { user_id } => CoreCommand::RemoveGroupMember {
                group_id: group_id.to_string(),
                target_user_id: user_id.clone(),
            },
            GroupTransitionOperation::TransferOwnership { user_id } => {
                CoreCommand::TransferGroupOwnership {
                    group_id: group_id.to_string(),
                    new_owner_user_id: user_id.clone(),
                }
            }
            GroupTransitionOperation::SetAdmin { user_id, is_admin } => {
                CoreCommand::SetGroupAdmin {
                    group_id: group_id.to_string(),
                    target_user_id: user_id.clone(),
                    is_admin: *is_admin,
                }
            }
            GroupTransitionOperation::UpdateMetadata => CoreCommand::UpdateGroupMetadata {
                group_id: group_id.to_string(),
                title: Some(proposed.title.clone()),
                join_policy: Some(proposed.join_policy),
                member_invite_policy: Some(proposed.member_invite_policy),
            },
            GroupTransitionOperation::Dissolve => CoreCommand::DissolveGroup {
                group_id: group_id.to_string(),
            },
            GroupTransitionOperation::AddDevice { user_id, device_id } => {
                CoreCommand::AddGroupMemberDevice {
                    group_id: group_id.to_string(),
                    user_id: user_id.clone(),
                    device_id: device_id.clone(),
                }
            }
            GroupTransitionOperation::RemoveDevice { user_id, device_id } => {
                CoreCommand::RemoveGroupMemberDevice {
                    group_id: group_id.to_string(),
                    user_id: user_id.clone(),
                    device_id: device_id.clone(),
                }
            }
        })
    }

    pub(super) fn resume_group_transition_after_reconciliation(
        &mut self,
        group_id: String,
    ) -> CoreResult<CoreOutput> {
        let state = self
            .state
            .group_states
            .get(&group_id)
            .cloned()
            .ok_or_else(|| CoreError::invalid_input("group does not exist"))?;
        let Some(pending) = state.pending_group_transition.clone().filter(|pending| {
            pending.stage == PendingGroupTransitionStage::ReconcilingAfterConflict
        }) else {
            return Ok(CoreOutput::default());
        };
        let Some(operation) = pending.intent.operation().cloned() else {
            return self.block_group_needs_rebuild(
                &group_id,
                "legacy transition intent cannot be reconstructed safely",
            );
        };
        if Self::group_transition_target_achieved(&operation, &state.manifest) {
            if let Some(state) = self.state.group_states.get_mut(&group_id) {
                state.pending_group_transition = None;
                state.consistency_state = GroupConsistencyState::Ready;
            }
            return Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    checkpoints_changed: true,
                    ..CoreStateUpdate::default()
                },
                effects: vec![persist_effect(
                    &self.state,
                    vec![PersistOp::SaveGroupState {
                        group_id: group_id.clone(),
                    }],
                )],
                view_model: None,
            });
        }
        let already_rebuilt = matches!(
            pending.intent,
            GroupTransitionIntent::Typed {
                conflict_rebuild_attempted: true,
                ..
            }
        );
        if already_rebuilt {
            if let Some(state) = self.state.group_states.get_mut(&group_id) {
                state.pending_group_transition = None;
                state.consistency_state = GroupConsistencyState::Ready;
            }
            return Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    checkpoints_changed: true,
                    ..CoreStateUpdate::default()
                },
                effects: vec![
                    persist_effect(
                        &self.state,
                        vec![PersistOp::SaveGroupState {
                            group_id: group_id.clone(),
                        }],
                    ),
                    CoreEffect::EmitUserNotification {
                        notification: UserNotificationEffect {
                            status: SystemStatus::TemporaryNetworkFailure,
                            message: format!(
                                "group {group_id} changed concurrently; retry the operation manually"
                            ),
                        },
                    },
                ],
                view_model: None,
            });
        }
        let Some(command) = Self::command_for_group_transition_intent(
            &group_id,
            &operation,
            &pending.proposed_manifest,
        ) else {
            return self.block_group_needs_rebuild(
                &group_id,
                "create transition conflict cannot be rebuilt safely",
            );
        };
        if let Some(state) = self.state.group_states.get_mut(&group_id) {
            state.pending_group_transition = None;
            state.consistency_state = GroupConsistencyState::Ready;
        }
        let mut output = match self.handle_command(command) {
            Ok(output) => output,
            Err(error) => {
                return Ok(CoreOutput {
                    state_update: CoreStateUpdate {
                        checkpoints_changed: true,
                        ..CoreStateUpdate::default()
                    },
                    effects: vec![
                        persist_effect(
                            &self.state,
                            vec![PersistOp::SaveGroupState {
                                group_id: group_id.clone(),
                            }],
                        ),
                        CoreEffect::EmitUserNotification {
                            notification: UserNotificationEffect {
                                status: SystemStatus::TemporaryNetworkFailure,
                                message: format!(
                                    "group operation was cancelled after reconciliation: {error}"
                                ),
                            },
                        },
                    ],
                    view_model: None,
                });
            }
        };
        if let Some(rebuilt) = self
            .state
            .group_states
            .get_mut(&group_id)
            .and_then(|state| state.pending_group_transition.as_mut())
        {
            if let GroupTransitionIntent::Typed {
                conflict_rebuild_attempted,
                ..
            } = &mut rebuilt.intent
            {
                *conflict_rebuild_attempted = true;
            }
        }
        output.effects.push(persist_effect(
            &self.state,
            vec![PersistOp::SaveGroupState {
                group_id: group_id.clone(),
            }],
        ));
        Ok(output)
    }

    pub(super) fn handle_group_authorization_initialized(
        &mut self,
        group_id: String,
        roster_version: u64,
    ) -> CoreResult<CoreOutput> {
        let state = self
            .state
            .group_states
            .get_mut(&group_id)
            .ok_or_else(|| CoreError::invalid_input("group does not exist"))?;
        if state.manifest.roster_version != roster_version {
            return self.block_group_needs_rebuild(
                &group_id,
                "authorization bootstrap ACK does not match the provisional manifest",
            );
        }
        let Some(pending) = state.pending_group_transition.as_mut() else {
            return Ok(CoreOutput::default());
        };
        if pending.stage != PendingGroupTransitionStage::AwaitingAuthorizationBootstrap {
            return Ok(CoreOutput::default());
        }
        pending.stage = PendingGroupTransitionStage::Prepared;
        let persist = persist_effect(
            &self.state,
            vec![PersistOp::SaveGroupState {
                group_id: group_id.clone(),
            }],
        );
        Ok(merge_outputs(
            CoreOutput {
                state_update: CoreStateUpdate {
                    checkpoints_changed: true,
                    ..CoreStateUpdate::default()
                },
                effects: vec![persist],
                view_model: None,
            },
            self.flush_group_outbox()?,
        ))
    }

    pub(super) fn block_group_needs_rebuild(
        &mut self,
        group_id: &str,
        reason: &str,
    ) -> CoreResult<CoreOutput> {
        let mut persist_ops = Vec::new();
        if let Some(state) = self.state.group_states.get_mut(group_id) {
            state.consistency_state = GroupConsistencyState::BlockedNeedsRebuild;
            state.pending_group_transition = None;
            persist_ops.push(PersistOp::SaveGroupState {
                group_id: group_id.to_string(),
            });
            if let Some(conversation) = self.state.conversations.get_mut(&state.conversation_id) {
                conversation.conversation.state = ConversationState::NeedsRebuild;
                conversation.recovery_status = RecoveryStatus::NeedsRebuild;
                persist_ops.push(PersistOp::SaveConversation {
                    conversation_id: state.conversation_id.clone(),
                });
            }
        }
        self.state.pending_sync_group_head.remove(group_id);
        self.state.group_sync_target_head.remove(group_id);
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                conversations_changed: true,
                checkpoints_changed: true,
                system_statuses_changed: vec![SystemStatus::ConversationNeedsRebuild],
                ..CoreStateUpdate::default()
            },
            effects: vec![
                persist_effect(&self.state, persist_ops),
                CoreEffect::CloseGroupRealtimeConnection {
                    group_id: group_id.to_string(),
                },
                CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect {
                        status: SystemStatus::ConversationNeedsRebuild,
                        message: format!("group {group_id} was blocked: {reason}"),
                    },
                },
            ],
            view_model: None,
        })
    }

    pub(super) fn handle_group_history_floor(
        &mut self,
        group_id: &str,
        history_floor_seq: u64,
    ) -> CoreResult<CoreOutput> {
        let current = self
            .state
            .group_cursors
            .get(group_id)
            .map(|cursor| cursor.last_fetched_seq)
            .unwrap_or(0);
        if history_floor_seq <= current {
            return Ok(CoreOutput::default());
        }
        self.block_group_needs_rebuild(
            group_id,
            &format!(
                "remote history before sequence {history_floor_seq} expired before this device synchronized"
            ),
        )
    }

    pub(super) fn handle_group_outbox_records(
        &mut self,
        group_id: String,
        mut records: Vec<GroupOutboxRecord>,
        to_seq: u64,
    ) -> CoreResult<CoreOutput> {
        if self.state.group_states.get(&group_id).is_some_and(|state| {
            state.consistency_state == GroupConsistencyState::BlockedNeedsRebuild
        }) {
            return Ok(CoreOutput::default());
        }
        let group_state = self
            .state
            .group_states
            .get(&group_id)
            .ok_or_else(|| CoreError::invalid_input("group does not exist"))?
            .clone();
        let conversation_id = group_state.conversation_id.clone();
        records.sort_by_key(|record| record.seq);
        let initial_cursor = self
            .state
            .group_cursors
            .get(&group_id)
            .map(|cursor| cursor.last_fetched_seq)
            .unwrap_or(0);
        records.retain(|record| record.seq > initial_cursor);
        let mut expected_seq = initial_cursor.saturating_add(1).max(1);
        for record in &records {
            record.validate()?;
            if record.seq != expected_seq {
                return Err(CoreError::invalid_input(
                    "group outbox records must be contiguous from the local cursor",
                ));
            }
            expected_seq = expected_seq.saturating_add(1);
        }
        if records.last().is_some_and(|record| record.seq > to_seq) {
            return Err(CoreError::invalid_input(
                "group outbox to_seq must cover every returned record",
            ));
        }
        let record_count = records.len();
        let mut messages = Vec::new();
        let mut last_terminal_seq = initial_cursor;
        let mut stopped_on_retryable_gap = false;
        let mut record_iter = records.into_iter().peekable();
        while let Some(record) = record_iter.next() {
            if let Some(transition_id) = record.envelope.transition_id.clone() {
                if record.envelope.membership_proof.is_some() {
                    let mut bundle = vec![record];
                    while record_iter.peek().is_some_and(|next| {
                        next.envelope.transition_id.as_deref() == Some(transition_id.as_str())
                    }) {
                        if let Some(next) = record_iter.next() {
                            bundle.push(next);
                        }
                    }
                    let bundle_last_seq = bundle.last().map(|item| item.seq).unwrap_or(0);
                    match self.apply_inbound_group_transition_bundle(&group_id, &bundle)? {
                        Some(mut applied) => {
                            messages.append(&mut applied);
                            last_terminal_seq = bundle_last_seq;
                        }
                        None => {
                            stopped_on_retryable_gap = true;
                            break;
                        }
                    }
                    continue;
                }
            }
            let record_seq = record.seq;
            if record.group_id != group_id || record.envelope.conversation_id != conversation_id {
                return Err(CoreError::invalid_input(
                    "group outbox record does not match local group",
                ));
            }
            if self
                .state
                .conversations
                .get(&conversation_id)
                .map(|state| {
                    state
                        .messages
                        .iter()
                        .any(|message| message.message_id == record.message_id)
                })
                .unwrap_or(false)
            {
                last_terminal_seq = record_seq;
                continue;
            }
            let group_state = self
                .state
                .group_states
                .get(&group_id)
                .ok_or_else(|| CoreError::invalid_input("group does not exist"))?
                .clone();
            let is_membership_operation = matches!(
                record.envelope.message_type,
                GroupMessageType::MlsCommit
                    | GroupMessageType::ControlGroupMembershipChanged
                    | GroupMessageType::ControlGroupMetadataUpdated
                    | GroupMessageType::ControlGroupDissolved
            );
            let membership_proof = if is_membership_operation {
                match self
                    .verify_membership_operation_authority(&record.envelope, &group_state.manifest)
                {
                    Ok(proof) => Some(proof),
                    Err(err) => {
                        log::warn!(
                            "rejected membership operation from {} ({}) in group {}: {}",
                            redact_id("user", &record.envelope.sender_user_id),
                            redact_id("device", &record.envelope.sender_device_id),
                            redact_id("group", &group_id),
                            err.code()
                        );
                        let signer_is_privileged =
                            group_state.manifest.members.iter().any(|member| {
                                member.user_id == record.envelope.sender_user_id
                                    && member.status == GroupMemberStatus::Active
                                    && matches!(member.role, GroupRole::Owner | GroupRole::Admin)
                            });
                        if signer_is_privileged {
                            self.mark_recovery_needed(
                                &conversation_id,
                                RecoveryReason::MissingCommit,
                            );
                        }
                        stopped_on_retryable_gap = true;
                        break;
                    }
                }
            } else {
                None
            };
            let mut message_type = group_message_type_to_direct(record.envelope.message_type);
            if membership_proof.as_ref().is_some_and(|proof| {
                group_state.manifest.roster_version == proof.new_roster_version
                    && group_state.manifest.last_commit_message_id.as_ref()
                        == Some(&proof.commit_message_id)
                    && matches!(
                        record.envelope.message_type,
                        GroupMessageType::MlsCommit
                            | GroupMessageType::ControlGroupMembershipChanged
                            | GroupMessageType::ControlGroupMetadataUpdated
                            | GroupMessageType::ControlGroupDissolved
                    )
            }) {
                self.store_group_record_message(&conversation_id, &record, message_type, None)?;
                messages.push(MessageSummary {
                    conversation_id: conversation_id.clone(),
                    message_id: record.message_id,
                    message_type,
                });
                last_terminal_seq = record_seq;
                continue;
            }
            if matches!(
                record.envelope.message_type,
                GroupMessageType::MlsApplication | GroupMessageType::MlsCommit
            ) {
                if group_state.local_role.is_none()
                    && record.envelope.message_type == GroupMessageType::MlsApplication
                {
                    self.mark_recovery_needed(&conversation_id, RecoveryReason::MembershipChanged);
                    stopped_on_retryable_gap = true;
                    break;
                }
                let binding_bundles =
                    self.identity_bundles_for_group_manifest(&group_state.manifest)?;
                let result = match self
                    .state
                    .mls_adapter
                    .as_mut()
                    .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
                    .ingest_protocol_message_with_device_bindings(
                        &conversation_id,
                        &record.envelope.sender_device_id,
                        message_type,
                        record
                            .envelope
                            .inline_ciphertext
                            .as_deref()
                            .unwrap_or_default(),
                        &binding_bundles,
                    ) {
                    Ok(result) => result,
                    Err(error)
                        if record.envelope.message_type == GroupMessageType::MlsCommit
                            && membership_proof.is_some() =>
                    {
                        log::warn!(
                            "failed to ingest membership commit {} for group {}: {}",
                            redact_id("msg", &record.envelope.message_id),
                            redact_id("group", &group_id),
                            error.code()
                        );
                        self.mark_recovery_needed(&conversation_id, RecoveryReason::MissingCommit);
                        stopped_on_retryable_gap = true;
                        break;
                    }
                    Err(error) => return Err(error),
                };
                match result {
                    IngestResult::AppliedApplication(application) => self
                        .store_group_record_message(
                            &conversation_id,
                            &record,
                            message_type,
                            String::from_utf8(application.plaintext).ok(),
                        )?,
                    IngestResult::AppliedCommit { .. } => {
                        if let Some(proof) = membership_proof.clone() {
                            let mut state = self
                                .state
                                .group_states
                                .get(&group_id)
                                .ok_or_else(|| CoreError::invalid_input("group does not exist"))?
                                .clone();
                            state.pending_membership_transition =
                                Some(PersistedPendingGroupMembershipTransition {
                                    group_id: group_id.clone(),
                                    conversation_id: conversation_id.clone(),
                                    commit_message_id: record.envelope.message_id.clone(),
                                    control_message_id: proof.control_message_id.clone(),
                                    proof,
                                });
                            self.state.group_states.insert(group_id.clone(), state);
                        }
                        self.store_group_record_message(
                            &conversation_id,
                            &record,
                            message_type,
                            None,
                        )?
                    }
                    IngestResult::PendingRetry => {
                        self.mark_recovery_needed(&conversation_id, RecoveryReason::MissingCommit);
                        stopped_on_retryable_gap = true;
                        break;
                    }
                    IngestResult::IgnoredReplay => {
                        log::warn!(
                            "sync_group_outbox: ignoring replay/duplicate MLS record {} for group {}",
                            redact_id("msg", &record.envelope.message_id),
                            redact_id("group", &group_id)
                        );
                        last_terminal_seq = record_seq;
                        continue;
                    }
                    IngestResult::NeedsRebuild => {
                        return self.escalate_conversation_to_rebuild(
                            &conversation_id,
                            RecoveryEscalationReason::MlsMarkedUnrecoverable,
                            "group MLS marked conversation unrecoverable",
                        );
                    }
                    IngestResult::AppliedWelcome { .. } => {}
                }
                if let Ok(summary) = self
                    .state
                    .mls_adapter
                    .as_ref()
                    .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
                    .export_group_summary(&conversation_id)
                {
                    if let Ok(local_device_id) = self.local_identity_device_id() {
                        if !summary
                            .member_device_ids
                            .iter()
                            .any(|device_id| device_id == &local_device_id)
                        {
                            if let Some(state) = self.state.group_states.get_mut(&group_id) {
                                state.local_role = None;
                                state.pending_membership_transition = None;
                            }
                        }
                    }
                    self.state
                        .mls_summaries
                        .insert(conversation_id.clone(), summary);
                }
            } else {
                if record.envelope.message_type == GroupMessageType::ControlConversationNeedsRebuild
                {
                    return self.escalate_conversation_to_rebuild(
                        &conversation_id,
                        RecoveryEscalationReason::ExplicitNeedsRebuildControl,
                        "group outbox received control_conversation_needs_rebuild",
                    );
                }
                let is_manifest_control = matches!(
                    record.envelope.message_type,
                    GroupMessageType::ControlGroupMembershipChanged
                        | GroupMessageType::ControlGroupMetadataUpdated
                        | GroupMessageType::ControlGroupDissolved
                );
                let mut plaintext = None;
                if is_manifest_control
                    && !self.try_apply_control_manifest_update(
                        &conversation_id,
                        &group_id,
                        &record,
                        &group_state,
                    )
                {
                    stopped_on_retryable_gap = true;
                    break;
                }
                if is_manifest_control {
                    if let (Some(updated), Some(proof)) = (
                        self.state.group_states.get(&group_id),
                        record.envelope.membership_proof.as_ref(),
                    ) {
                        plaintext = Self::derive_group_state_event(
                            &group_state.manifest,
                            &updated.manifest,
                            proof,
                            &record,
                        );
                        message_type = MessageType::ControlGroupStateEvent;
                    }
                }
                self.store_group_record_message(
                    &conversation_id,
                    &record,
                    message_type,
                    plaintext,
                )?;
            }
            messages.push(MessageSummary {
                conversation_id: conversation_id.clone(),
                message_id: record.message_id,
                message_type,
            });
            last_terminal_seq = record_seq;
        }
        let now = current_unix_millis(self.state.message_nonce);
        self.state.group_cursors.insert(
            group_id.clone(),
            GroupCursor {
                group_id: group_id.clone(),
                last_fetched_seq: last_terminal_seq,
                updated_at: now,
            },
        );
        log::info!(
            "handle_group_outbox_records: applied group_id={} records={} messages={} cursor={}",
            group_id,
            record_count,
            messages.len(),
            last_terminal_seq
        );
        let target_head = self.state.group_sync_target_head.get(&group_id).copied();
        let mut output = CoreOutput {
            state_update: CoreStateUpdate {
                conversations_changed: !messages.is_empty(),
                messages_changed: !messages.is_empty(),
                checkpoints_changed: true,
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
                    PersistOp::SaveGroupState {
                        group_id: group_id.clone(),
                    },
                    PersistOp::SaveGroupCursor {
                        group_id: group_id.clone(),
                    },
                ],
            )],
            view_model: Some(CoreViewModel {
                conversations: vec![self.conversation_summary(&conversation_id)?],
                messages,
                ..CoreViewModel::default()
            }),
        };
        // Continue fetching if we haven't caught up to the target head.
        if stopped_on_retryable_gap {
            if let Some(state) = self.state.group_states.get_mut(&group_id) {
                state.consistency_state = GroupConsistencyState::Reconciling;
            }
            let state = self
                .state
                .group_states
                .get(&group_id)
                .ok_or_else(|| CoreError::invalid_input("group does not exist"))?
                .clone();
            output.effects.push(CoreEffect::GetGroupAuthorizationState {
                get: GetGroupAuthorizationStateRequest {
                    group_id: group_id.clone(),
                    capability: self.group_capability_for_state(&state)?,
                },
            });
        } else if let Some(head_seq) = target_head {
            if last_terminal_seq < head_seq {
                let state = self
                    .state
                    .group_states
                    .get(&group_id)
                    .ok_or_else(|| CoreError::invalid_input("group does not exist"))?
                    .clone();
                let next_fetch = CoreEffect::FetchGroupOutbox {
                    fetch: FetchGroupOutboxRequest {
                        group_id,
                        from_seq: last_terminal_seq.saturating_add(1),
                        limit: GROUP_OUTBOX_FETCH_LIMIT,
                        capability: self.group_capability_for_state(&state)?,
                    },
                };
                output.effects.push(next_fetch);
            } else {
                self.state.group_sync_target_head.remove(&group_id);
                if self.state.group_states.get(&group_id).is_some_and(|state| {
                    state
                        .pending_group_transition
                        .as_ref()
                        .is_some_and(|pending| {
                            pending.stage == PendingGroupTransitionStage::ReconcilingAfterConflict
                        })
                }) {
                    output = merge_outputs(
                        output,
                        self.resume_group_transition_after_reconciliation(group_id.clone())?,
                    );
                }
            }
        }
        self.merge_with_transport_flush(output)
    }

    pub(super) fn apply_inbound_group_transition_bundle(
        &mut self,
        group_id: &str,
        bundle: &[GroupOutboxRecord],
    ) -> CoreResult<Option<Vec<MessageSummary>>> {
        let current = self
            .state
            .group_states
            .get(group_id)
            .cloned()
            .ok_or_else(|| CoreError::invalid_input("group does not exist"))?;
        if current.consistency_state == GroupConsistencyState::BlockedNeedsRebuild {
            return Ok(None);
        }
        let first = bundle
            .first()
            .ok_or_else(|| CoreError::invalid_input("transition bundle must not be empty"))?;
        let transition_id = first.envelope.transition_id.as_deref().ok_or_else(|| {
            CoreError::invalid_input("transition bundle is missing transition_id")
        })?;
        let proof = first
            .envelope
            .membership_proof
            .as_ref()
            .ok_or_else(|| CoreError::invalid_input("transition bundle is missing proof"))?
            .clone();
        if bundle.iter().any(|record| {
            record.envelope.transition_id.as_deref() != Some(transition_id)
                || record.envelope.membership_proof.as_ref() != Some(&proof)
                || record.envelope.group_id != group_id
                || record.envelope.conversation_id != current.conversation_id
                || record.envelope.sender_user_id != proof.signer_user_id
                || record.envelope.sender_device_id != proof.signer_device_id
        }) {
            return Err(CoreError::invalid_input(
                "transition bundle records do not share identity, proof, and transition_id",
            ));
        }
        let commit = bundle
            .iter()
            .find(|record| record.message_id == proof.commit_message_id);
        let control = bundle
            .iter()
            .find(|record| record.message_id == proof.control_message_id)
            .ok_or_else(|| CoreError::invalid_input("transition bundle is missing control"))?;
        let state_event_id = proof.state_event_message_id.as_deref().ok_or_else(|| {
            CoreError::invalid_input("transition proof is missing state_event_message_id")
        })?;
        let state_event = bundle
            .iter()
            .find(|record| record.message_id == state_event_id)
            .ok_or_else(|| CoreError::invalid_input("transition bundle is missing state event"))?;
        let commit_is_new =
            proof.previous_commit_message_id.as_ref() != Some(&proof.commit_message_id);
        if commit_is_new != commit.is_some()
            || control.envelope.message_type == GroupMessageType::ControlGroupStateEvent
            || state_event.envelope.message_type != GroupMessageType::ControlGroupStateEvent
            || bundle.len() != if commit_is_new { 3 } else { 2 }
        {
            return Err(CoreError::invalid_input(
                "transition bundle has an invalid commit/control/event shape",
            ));
        }
        self.verify_membership_operation_authority(&control.envelope, &current.manifest)?;
        if let Some(commit) = commit {
            self.verify_membership_operation_authority(&commit.envelope, &current.manifest)?;
        }
        for record in bundle {
            let ciphertext = record
                .envelope
                .inline_ciphertext
                .as_deref()
                .ok_or_else(|| CoreError::invalid_input("transition record has no ciphertext"))?;
            self.verify_device_signature(
                &record.envelope.sender_user_id,
                &record.envelope.sender_device_id,
                ciphertext.as_bytes(),
                &record.envelope.sender_proof.value,
            )?;
        }

        let mut staged_mls = self
            .state
            .mls_adapter
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .fork()?;
        if let Some(commit) = commit {
            match staged_mls.ingest_message(
                &current.conversation_id,
                &commit.envelope.sender_device_id,
                MessageType::MlsCommit,
                commit
                    .envelope
                    .inline_ciphertext
                    .as_deref()
                    .unwrap_or_default(),
            )? {
                IngestResult::AppliedCommit { .. } | IngestResult::IgnoredReplay => {}
                IngestResult::PendingRetry => return Ok(None),
                IngestResult::NeedsRebuild => {
                    return Err(CoreError::invalid_state(
                        "transition commit marked MLS state unrecoverable",
                    ))
                }
                _ => {
                    return Err(CoreError::invalid_input(
                        "transition commit did not produce an MLS commit",
                    ))
                }
            }
        }
        let manifest_plaintext = match staged_mls.ingest_message(
            &current.conversation_id,
            &control.envelope.sender_device_id,
            MessageType::MlsApplication,
            control
                .envelope
                .inline_ciphertext
                .as_deref()
                .unwrap_or_default(),
        )? {
            IngestResult::AppliedApplication(application) => application.plaintext,
            IngestResult::PendingRetry => return Ok(None),
            _ => {
                return Err(CoreError::invalid_input(
                    "transition control did not decrypt as an application message",
                ))
            }
        };
        let updated: GroupManifest =
            serde_json::from_slice(&manifest_plaintext).map_err(|error| {
                CoreError::invalid_input(format!("transition manifest is invalid JSON: {error}"))
            })?;
        updated.validate()?;
        self.verify_manifest_signature(&updated)?;
        if updated.group_id != group_id
            || updated.conversation_id != current.conversation_id
            || Self::manifest_sha256(&updated)? != proof.new_manifest_sha256
            || updated.roster_version != proof.new_roster_version
            || updated.last_commit_message_id.as_ref() != Some(&proof.commit_message_id)
            || !Self::validate_manifest_transition_for_operation(
                &current.manifest,
                &updated,
                &proof,
            )
        {
            return Err(CoreError::invalid_input(
                "transition manifest does not match its proof and previous state",
            ));
        }
        let state_event_plaintext = match staged_mls.ingest_message(
            &current.conversation_id,
            &state_event.envelope.sender_device_id,
            MessageType::MlsApplication,
            state_event
                .envelope
                .inline_ciphertext
                .as_deref()
                .unwrap_or_default(),
        )? {
            IngestResult::AppliedApplication(application) => application.plaintext,
            IngestResult::PendingRetry => return Ok(None),
            _ => {
                return Err(CoreError::invalid_input(
                    "transition state event did not decrypt as an application message",
                ))
            }
        };
        let event: GroupStateEvent =
            serde_json::from_slice(&state_event_plaintext).map_err(|error| {
                CoreError::invalid_input(format!("transition state event is invalid JSON: {error}"))
            })?;
        let expected_json =
            Self::derive_group_state_event(&current.manifest, &updated, &proof, state_event)
                .ok_or_else(|| CoreError::invalid_state("failed to derive expected state event"))?;
        let expected: GroupStateEvent = serde_json::from_str(&expected_json).map_err(|error| {
            CoreError::invalid_state(format!("failed to parse expected state event: {error}"))
        })?;
        if event != expected || event.transition_id != transition_id {
            return Err(CoreError::invalid_input(
                "transition state event does not match the verified manifest diff",
            ));
        }

        let updated_bundles = self.identity_bundles_for_group_manifest(&updated)?;
        staged_mls
            .validate_group_member_device_bindings(&current.conversation_id, &updated_bundles)?;

        let summary = staged_mls.export_group_summary(&current.conversation_id)?;
        if summary.epoch != updated.mls_epoch_hint {
            return Err(CoreError::invalid_input(
                "transition MLS epoch does not match manifest",
            ));
        }
        self.state.mls_adapter = Some(staged_mls);
        self.state
            .mls_summaries
            .insert(current.conversation_id.clone(), summary);
        let local_user_id = self.local_identity_user_id()?;
        let local_role = updated
            .members
            .iter()
            .find(|member| {
                member.user_id == local_user_id && member.status == GroupMemberStatus::Active
            })
            .map(|member| member.role);
        if let Some(state) = self.state.group_states.get_mut(group_id) {
            state.manifest = updated.clone();
            state.local_role = local_role;
            state.pending_membership_transition = None;
            state.consistency_state = if proof.operation == "dissolve" {
                GroupConsistencyState::Dissolved
            } else {
                GroupConsistencyState::Ready
            };
        }
        self.sync_conversation_members_from_manifest(&current.conversation_id, &updated)?;
        let mut messages = Vec::new();
        for record in bundle {
            let (message_type, plaintext) = if record.message_id == state_event.message_id {
                (
                    MessageType::ControlGroupStateEvent,
                    String::from_utf8(state_event_plaintext.clone()).ok(),
                )
            } else {
                (
                    group_message_type_to_direct(record.envelope.message_type),
                    None,
                )
            };
            if !self
                .state
                .conversations
                .get(&current.conversation_id)
                .is_some_and(|conversation| {
                    conversation
                        .messages
                        .iter()
                        .any(|message| message.message_id == record.message_id)
                })
            {
                self.store_group_record_message(
                    &current.conversation_id,
                    record,
                    message_type,
                    plaintext,
                )?;
            }
            messages.push(MessageSummary {
                conversation_id: current.conversation_id.clone(),
                message_id: record.message_id.clone(),
                message_type,
            });
        }
        Ok(Some(messages))
    }

    pub(super) fn derive_group_state_event(
        previous: &GroupManifest,
        updated: &GroupManifest,
        proof: &GroupMembershipProof,
        record: &GroupOutboxRecord,
    ) -> Option<String> {
        let active = |manifest: &GroupManifest| {
            manifest
                .members
                .iter()
                .filter(|member| member.status == GroupMemberStatus::Active)
                .map(|member| (member.user_id.clone(), member.role))
                .collect::<BTreeMap<_, _>>()
        };
        let before = active(previous);
        let after = active(updated);
        let joined = after
            .keys()
            .filter(|user_id| !before.contains_key(*user_id))
            .cloned()
            .collect::<Vec<_>>();
        let removed = before
            .keys()
            .filter(|user_id| !after.contains_key(*user_id))
            .cloned()
            .collect::<Vec<_>>();
        let role_change = before.iter().find_map(|(user_id, old_role)| {
            after
                .get(user_id)
                .filter(|new_role| *new_role != old_role)
                .map(|new_role| (user_id.clone(), *old_role, *new_role))
        });
        let (kind, subject_user_ids, old_role, new_role) = if proof.operation == "dissolve" {
            (GroupStateEventKind::GroupDissolved, Vec::new(), None, None)
        } else if previous.owner_user_id != updated.owner_user_id {
            (
                GroupStateEventKind::OwnershipTransferred,
                vec![updated.owner_user_id.clone()],
                Some(GroupRole::Member),
                Some(GroupRole::Owner),
            )
        } else if let Some((user_id, old_role, new_role)) = role_change {
            (
                GroupStateEventKind::RoleChanged,
                vec![user_id],
                Some(old_role),
                Some(new_role),
            )
        } else if !joined.is_empty() {
            (GroupStateEventKind::MemberJoined, joined, None, None)
        } else if !removed.is_empty() {
            let kind = if proof.operation == "leave" {
                GroupStateEventKind::MemberLeft
            } else {
                GroupStateEventKind::MemberRemoved
            };
            (kind, removed, None, None)
        } else {
            (
                GroupStateEventKind::GroupMetadataChanged,
                Vec::new(),
                None,
                None,
            )
        };
        serde_json::to_string(&GroupStateEvent {
            version: crate::model::CURRENT_MODEL_VERSION.to_string(),
            event_id: record.message_id.clone(),
            transition_id: record
                .envelope
                .transition_id
                .clone()
                .unwrap_or_else(|| format!("group-transition:{}", proof.control_message_id)),
            kind,
            actor_user_id: proof.signer_user_id.clone(),
            subject_user_ids,
            old_role,
            new_role,
            roster_version: updated.roster_version,
            manifest_hash: proof.new_manifest_sha256.clone(),
            occurred_at: record.envelope.created_at,
        })
        .ok()
    }

    pub(super) fn transition_intent_from_staged_state(
        &self,
        previous: &GroupManifest,
        updated: &GroupManifest,
        proof: &GroupMembershipProof,
        join_request_id: Option<&str>,
    ) -> CoreResult<GroupTransitionIntent> {
        let active_users = |manifest: &GroupManifest| {
            manifest
                .members
                .iter()
                .filter(|member| member.status == GroupMemberStatus::Active)
                .map(|member| member.user_id.clone())
                .collect::<BTreeSet<_>>()
        };
        let before_users = active_users(previous);
        let after_users = active_users(updated);
        let added_users = after_users
            .difference(&before_users)
            .cloned()
            .collect::<Vec<_>>();
        let removed_users = before_users
            .difference(&after_users)
            .cloned()
            .collect::<Vec<_>>();
        let added_device = updated.member_devices.iter().find(|device| {
            device.status == GroupMemberStatus::Active
                && !previous.member_devices.iter().any(|old| {
                    old.user_id == device.user_id
                        && old.device_id == device.device_id
                        && old.status == GroupMemberStatus::Active
                })
        });
        let removed_device = previous.member_devices.iter().find(|device| {
            device.status == GroupMemberStatus::Active
                && !updated.member_devices.iter().any(|new| {
                    new.user_id == device.user_id
                        && new.device_id == device.device_id
                        && new.status == GroupMemberStatus::Active
                })
        });
        let operation = match proof.operation.as_str() {
            "create" => GroupTransitionOperation::Create,
            "invite" => GroupTransitionOperation::InviteMembers {
                user_ids: added_users,
            },
            "approve_join" => {
                let request_id = join_request_id.ok_or_else(|| {
                    CoreError::invalid_state("approve_join transition is missing request_id")
                })?;
                let request = self
                    .state
                    .group_join_requests
                    .get(request_id)
                    .ok_or_else(|| CoreError::invalid_state("join request does not exist"))?;
                GroupTransitionOperation::ApproveJoin {
                    request_id: request_id.to_string(),
                    user_id: request.request.joiner_user_id.clone(),
                    device_id: request.request.joiner_device_id.clone(),
                }
            }
            "leave" => {
                let request_id = join_request_id.ok_or_else(|| {
                    CoreError::invalid_state("leave transition is missing request_id")
                })?;
                let request = self
                    .state
                    .group_states
                    .get(&previous.group_id)
                    .and_then(|state| {
                        state
                            .leave_requests
                            .iter()
                            .find(|stored| stored.request.request_id == request_id)
                    })
                    .ok_or_else(|| CoreError::invalid_state("leave request does not exist"))?;
                let user_id = request.request.leaver_user_id.clone();
                let device_id = request.request.leaver_device_id.clone();
                GroupTransitionOperation::ApproveLeave {
                    request_id: request_id.to_string(),
                    user_id,
                    device_id,
                }
            }
            "remove" => GroupTransitionOperation::RemoveMember {
                user_id: removed_users.first().cloned().ok_or_else(|| {
                    CoreError::invalid_state("remove transition removed no active member")
                })?,
            },
            "transfer_ownership" => GroupTransitionOperation::TransferOwnership {
                user_id: updated.owner_user_id.clone(),
            },
            "set_admin" => {
                let (user_id, is_admin) = updated
                    .members
                    .iter()
                    .find_map(|member| {
                        previous
                            .members
                            .iter()
                            .find(|old| old.user_id == member.user_id)
                            .filter(|old| old.role != member.role)
                            .map(|_| (member.user_id.clone(), member.role == GroupRole::Admin))
                    })
                    .ok_or_else(|| CoreError::invalid_state("set_admin changed no role"))?;
                GroupTransitionOperation::SetAdmin { user_id, is_admin }
            }
            "update_metadata" => GroupTransitionOperation::UpdateMetadata,
            "dissolve" => GroupTransitionOperation::Dissolve,
            "add_device" => {
                let device = added_device.ok_or_else(|| {
                    CoreError::invalid_state("add_device transition added no active device")
                })?;
                GroupTransitionOperation::AddDevice {
                    user_id: device.user_id.clone(),
                    device_id: device.device_id.clone(),
                }
            }
            "remove_device" => {
                let device = removed_device.ok_or_else(|| {
                    CoreError::invalid_state("remove_device transition removed no active device")
                })?;
                GroupTransitionOperation::RemoveDevice {
                    user_id: device.user_id.clone(),
                    device_id: device.device_id.clone(),
                }
            }
            operation => {
                return Err(CoreError::invalid_state(format!(
                    "unsupported group transition operation {operation}"
                )))
            }
        };
        let request_binding = match (&operation, join_request_id) {
            (GroupTransitionOperation::ApproveJoin { .. }, Some(request_id)) => self
                .state
                .group_join_requests
                .get(request_id)
                .and_then(|request| {
                    request.lease_token.as_ref().map(|lease_token| {
                        GroupTransitionRequestBinding::Join {
                            request_id: request.request_id.clone(),
                            lease_token: lease_token.clone(),
                        }
                    })
                }),
            (GroupTransitionOperation::ApproveLeave { .. }, Some(request_id)) => self
                .state
                .group_states
                .get(&previous.group_id)
                .and_then(|state| {
                    state
                        .leave_requests
                        .iter()
                        .find(|stored| stored.request.request_id == request_id)
                })
                .and_then(|stored| {
                    stored.lease_token.as_ref().map(|lease_token| {
                        GroupTransitionRequestBinding::Leave {
                            request_id: stored.request.request_id.clone(),
                            lease_token: lease_token.clone(),
                        }
                    })
                }),
            _ => None,
        };
        Ok(GroupTransitionIntent::Typed {
            operation,
            request_binding,
            conflict_rebuild_attempted: false,
        })
    }

    pub(super) fn store_group_record_message(
        &mut self,
        conversation_id: &str,
        record: &GroupOutboxRecord,
        message_type: MessageType,
        plaintext: Option<String>,
    ) -> CoreResult<()> {
        let state = self
            .state
            .conversations
            .get_mut(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?;
        state.messages.push(crate::conversation::StoredMessage {
            message_id: record.message_id.clone(),
            app_message_id: None,
            mls_ciphertext_sha256: None,
            sender_user_id: Some(record.envelope.sender_user_id.clone()),
            sender_device_id: record.envelope.sender_device_id.clone(),
            recipient_device_id: String::new(),
            message_type,
            created_at: record.envelope.created_at,
            plaintext,
            storage_refs: record.envelope.storage_refs.clone(),
            delivery_state: None,
            message_request_id: None,
        });
        state.last_message_type = Some(message_type);
        state.conversation.updated_at = record.envelope.created_at;
        Ok(())
    }

    pub(super) fn handle_group_transition_appended(
        &mut self,
        group_id: String,
        transition_id: String,
        first_seq: u64,
        last_seq: u64,
        roster_version: u64,
        last_commit_message_id: Option<String>,
    ) -> CoreResult<CoreOutput> {
        let group_state = self
            .state
            .group_states
            .get(&group_id)
            .ok_or_else(|| CoreError::invalid_input("group does not exist"))?
            .clone();
        let pending = group_state
            .pending_group_transition
            .clone()
            .ok_or_else(|| {
                CoreError::invalid_state("group transition ACK has no pending transition")
            })?;
        if pending.transition_id != transition_id
            || pending.proposed_manifest.roster_version != roster_version
            || pending.proposed_manifest.last_commit_message_id != last_commit_message_id
            || first_seq == 0
            || last_seq < first_seq
            || last_seq.saturating_sub(first_seq).saturating_add(1)
                != pending.envelopes.len() as u64
            || group_state.manifest.roster_version != pending.base_roster_version
            || group_state.manifest.last_commit_message_id != pending.base_commit_message_id
            || Self::manifest_sha256(&group_state.manifest)? != pending.base_manifest_hash
        {
            if let Some(state) = self.state.group_states.get_mut(&group_id) {
                state.consistency_state = GroupConsistencyState::Reconciling;
            }
            return self.sync_group_outbox(group_id, Some("stale_transition_ack".into()));
        }

        let mut summaries = self.state.mls_summaries.clone();
        summaries.insert(
            group_state.conversation_id.clone(),
            MlsStateSummary {
                conversation_id: group_state.conversation_id.clone(),
                epoch: pending.proposed_manifest.mls_epoch_hint,
                member_device_ids: pending
                    .proposed_manifest
                    .member_devices
                    .iter()
                    .filter(|device| device.status == GroupMemberStatus::Active)
                    .map(|device| device.device_id.clone())
                    .collect(),
                status: MlsStateStatus::Active,
                updated_at: current_unix_millis(self.state.message_nonce),
            },
        );
        let Some(patch) = pending.mls_patch.as_ref() else {
            // A legacy full-adapter snapshot cannot be promoted safely because
            // it may overwrite unrelated conversations that advanced while the
            // transition was in flight.
            if let Some(state) = self.state.group_states.get_mut(&group_id) {
                state.consistency_state = GroupConsistencyState::Reconciling;
            }
            return self.sync_group_outbox(group_id, Some("legacy_transition_ack".into()));
        };
        let patched_adapter = self
            .state
            .mls_adapter
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .apply_conversation_patch(patch, &summaries);
        let patched_adapter = match patched_adapter {
            Ok(adapter) => adapter,
            Err(_) => {
                if let Some(state) = self.state.group_states.get_mut(&group_id) {
                    state.consistency_state = GroupConsistencyState::Reconciling;
                }
                return self.sync_group_outbox(group_id, Some("mls_patch_conflict".into()));
            }
        };
        self.state.mls_adapter = Some(patched_adapter);
        self.state.mls_summaries = summaries;
        let local_user_id = self.local_identity_user_id()?;
        let local_role = pending
            .proposed_manifest
            .members
            .iter()
            .find(|member| {
                member.user_id == local_user_id && member.status == GroupMemberStatus::Active
            })
            .map(|member| member.role);
        if let Some(state) = self.state.group_states.get_mut(&group_id) {
            state.manifest = pending.proposed_manifest.clone();
            state.local_role = local_role;
            state.consistency_state = if state.dissolved_at.is_some() {
                GroupConsistencyState::Dissolved
            } else {
                GroupConsistencyState::Ready
            };
            if let Some(staged) = state.pending_group_transition.as_mut() {
                staged.stage = PendingGroupTransitionStage::AcceptedPublishingWelcomes;
                staged.first_seq = Some(first_seq);
                staged.last_seq = Some(last_seq);
            }
            if state
                .pending_group_transition
                .as_ref()
                .is_some_and(|pending| pending.welcomes.is_empty())
            {
                state.pending_group_transition = None;
            }
        }
        self.sync_conversation_members_from_manifest(
            &group_state.conversation_id,
            &pending.proposed_manifest,
        )?;
        self.state.group_cursors.insert(
            group_id.clone(),
            GroupCursor {
                group_id: group_id.clone(),
                last_fetched_seq: last_seq,
                updated_at: current_unix_millis(self.state.message_nonce),
            },
        );
        let mut system_message = None;
        if let Some(envelope) = pending
            .envelopes
            .iter()
            .find(|envelope| envelope.message_type == GroupMessageType::ControlGroupStateEvent)
        {
            let record = GroupOutboxRecord {
                seq: last_seq,
                group_id: group_id.clone(),
                message_id: envelope.message_id.clone(),
                received_at: current_unix_millis(self.state.message_nonce),
                expires_at: None,
                state: GroupOutboxRecordState::Available,
                envelope: envelope.clone(),
            };
            self.store_group_record_message(
                &group_state.conversation_id,
                &record,
                MessageType::ControlGroupStateEvent,
                pending.state_event_plaintext.clone(),
            )?;
            system_message = Some(MessageSummary {
                conversation_id: group_state.conversation_id.clone(),
                message_id: envelope.message_id.clone(),
                message_type: MessageType::ControlGroupStateEvent,
            });
        }
        let transition_message_ids: BTreeSet<_> = pending
            .envelopes
            .iter()
            .map(|envelope| envelope.message_id.as_str())
            .collect();
        self.state
            .pending_group_outbox
            .retain(|item| !transition_message_ids.contains(item.envelope.message_id.as_str()));

        let mut effects = Vec::new();
        for mut welcome in pending.welcomes {
            welcome.descriptor.start_seq = Some(last_seq);
            welcome.descriptor.roster_version = Some(roster_version);
            welcome.descriptor.last_commit_message_id = last_commit_message_id.clone();
            effects.push(CoreEffect::PutWelcomePickup { put: welcome });
        }
        // Atomic membership transitions bypass the legacy per-envelope ACK
        // handler. A dissolve still stages its seal there, so dispatch it
        // here once the acknowledged bundle has drained every pending record.
        let seal = if !self
            .state
            .pending_group_outbox
            .iter()
            .any(|item| item.envelope.group_id == group_id)
        {
            self.state.pending_group_seal.remove(&group_id)
        } else {
            None
        };
        let mut persist_ops = vec![
            PersistOp::SaveGroupState {
                group_id: group_id.clone(),
            },
            PersistOp::SaveGroupCursor {
                group_id: group_id.clone(),
            },
            PersistOp::SaveConversation {
                conversation_id: group_state.conversation_id.clone(),
            },
            PersistOp::SaveMlsState {
                conversation_id: group_state.conversation_id.clone(),
            },
        ];
        if seal.is_some() {
            persist_ops.push(PersistOp::DeletePendingGroupSeal {
                group_id: group_id.clone(),
            });
        }
        effects.insert(0, persist_effect(&self.state, persist_ops));
        if let Some(seal) = seal {
            effects.push(CoreEffect::SealGroupOutbox { seal });
        }
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                conversations_changed: true,
                messages_changed: system_message.is_some(),
                checkpoints_changed: true,
                ..CoreStateUpdate::default()
            },
            effects,
            view_model: system_message.map(|message| CoreViewModel {
                messages: vec![message],
                ..CoreViewModel::default()
            }),
        })
    }

    pub(super) fn handle_group_transition_failed(
        &mut self,
        group_id: String,
        transition_id: String,
        retryable: bool,
        status: Option<u16>,
        code: Option<String>,
        detail: Option<String>,
    ) -> CoreResult<CoreOutput> {
        if status == Some(403) && code.as_deref() == Some("group_membership_revoked") {
            return self.handle_group_sync_failed(group_id, false, status, code, detail);
        }
        let message_ids: BTreeSet<String> = self
            .state
            .group_states
            .get(&group_id)
            .and_then(|state| state.pending_group_transition.as_ref())
            .filter(|pending| pending.transition_id == transition_id)
            .map(|pending| {
                pending
                    .envelopes
                    .iter()
                    .map(|envelope| envelope.message_id.clone())
                    .collect()
            })
            .unwrap_or_default();
        for item in &mut self.state.pending_group_outbox {
            if message_ids.contains(&item.envelope.message_id) {
                item.in_flight = false;
                item.retries = item.retries.saturating_add(1);
            }
        }
        if status == Some(409)
            && matches!(
                code.as_deref(),
                Some("roster_version_conflict") | Some("group_transition_conflict")
            )
        {
            self.state
                .pending_group_outbox
                .retain(|item| !message_ids.contains(&item.envelope.message_id));
            if let Some(state) = self.state.group_states.get_mut(&group_id) {
                if let Some(pending) = state.pending_group_transition.as_mut() {
                    if pending.transition_id == transition_id {
                        pending.stage = PendingGroupTransitionStage::ReconcilingAfterConflict;
                        pending.mls_patch = None;
                        pending.staged_mls_state = None;
                        pending.envelopes.clear();
                        pending.welcomes.clear();
                        pending.first_seq = None;
                        pending.last_seq = None;
                    }
                }
                state.consistency_state = GroupConsistencyState::Reconciling;
            }
            let persist = persist_effect(
                &self.state,
                vec![PersistOp::SaveGroupState {
                    group_id: group_id.clone(),
                }],
            );
            return Ok(merge_outputs(
                CoreOutput {
                    state_update: CoreStateUpdate {
                        checkpoints_changed: true,
                        system_statuses_changed: vec![SystemStatus::SyncInProgress],
                        ..CoreStateUpdate::default()
                    },
                    effects: vec![persist],
                    view_model: None,
                },
                self.sync_group_outbox(group_id, Some("transition_conflict".into()))?,
            ));
        }
        if retryable {
            return Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::ScheduleTimer {
                    timer: TimerEffect {
                        timer_id: format!("retry_group_transition:{transition_id}"),
                        delay_ms: retry_delay_ms(&transition_id, 1),
                    },
                }],
                view_model: None,
            });
        }
        self.block_group_needs_rebuild(
            &group_id,
            detail
                .as_deref()
                .or(code.as_deref())
                .unwrap_or("group transition was rejected"),
        )
    }

    pub(super) fn handle_group_envelope_appended(
        &mut self,
        group_id: String,
        message_id: String,
        seq: u64,
    ) -> CoreResult<CoreOutput> {
        let pending_item = self
            .state
            .pending_group_outbox
            .iter()
            .find(|item| item.envelope.message_id == message_id)
            .cloned();
        self.state
            .pending_group_outbox
            .retain(|item| item.envelope.message_id != message_id);
        let mut messages = Vec::new();
        let mut touched_conversation_id: Option<String> = None;
        let mut touched_group_state = false;
        if let Some(item) = pending_item {
            let group_state = self
                .state
                .group_states
                .get(&group_id)
                .ok_or_else(|| CoreError::invalid_input("group does not exist"))?
                .clone();
            let conversation_id = group_state.conversation_id.clone();
            let already_stored = self
                .state
                .conversations
                .get(&conversation_id)
                .map(|state| {
                    state
                        .messages
                        .iter()
                        .any(|message| message.message_id == message_id)
                })
                .unwrap_or(false);
            if !already_stored {
                let message_type = group_message_type_to_direct(item.envelope.message_type);
                let record = GroupOutboxRecord {
                    seq,
                    group_id: group_id.clone(),
                    message_id: message_id.clone(),
                    received_at: current_unix_millis(self.state.message_nonce),
                    expires_at: None,
                    state: GroupOutboxRecordState::Available,
                    envelope: item.envelope,
                };
                self.store_group_record_message(
                    &conversation_id,
                    &record,
                    message_type,
                    item.plaintext_cache,
                )?;
                touched_conversation_id = Some(conversation_id.clone());
                messages.push(MessageSummary {
                    conversation_id,
                    message_id: message_id.clone(),
                    message_type,
                });
                // When the sender's own control message is acknowledged by
                // the server, the membership transition is complete — the
                // manifest update has been durably published. Clear any
                // pending transition so subsequent sends are unblocked.
                if matches!(
                    record.envelope.message_type,
                    GroupMessageType::ControlGroupMembershipChanged
                        | GroupMessageType::ControlGroupMetadataUpdated
                        | GroupMessageType::ControlGroupDissolved
                ) && group_state.pending_membership_transition.is_some()
                {
                    if let Some(state) = self.state.group_states.get_mut(&group_id) {
                        state.pending_membership_transition = None;
                        touched_group_state = true;
                    }
                }
            }
        }

        // Step (c) of `DissolveGroup`: emit the SealGroupOutbox effect only
        // after every pending commit/control for this group has been
        // acknowledged. This guarantees the seal is applied strictly after
        // the MLS remove_commit and `control_group_dissolved` are already
        // durable on the outbox, preserving the four-step atomic contract
        // (design.md Dissolve-group decision).
        let ready_to_seal = self.state.pending_group_seal.contains_key(&group_id)
            && !self
                .state
                .pending_group_outbox
                .iter()
                .any(|item| item.envelope.group_id == group_id);
        let mut seal_effect: Option<CoreEffect> = None;
        if ready_to_seal {
            if let Some(request) = self.state.pending_group_seal.remove(&group_id) {
                seal_effect = Some(CoreEffect::SealGroupOutbox { seal: request });
            }
        }

        let mut persist_ops = vec![PersistOp::DeleteOutgoingGroupEnvelope { message_id }];
        if let Some(conversation_id) = touched_conversation_id {
            persist_ops.push(PersistOp::SaveConversation { conversation_id });
        }
        if touched_group_state {
            persist_ops.push(PersistOp::SaveGroupState {
                group_id: group_id.clone(),
            });
        }

        let mut effects = vec![persist_effect(&self.state, persist_ops)];
        if let Some(effect) = seal_effect {
            effects.push(effect);
        }
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                checkpoints_changed: true,
                conversations_changed: !messages.is_empty(),
                messages_changed: !messages.is_empty(),
                ..CoreStateUpdate::default()
            },
            effects,
            view_model: Some(CoreViewModel {
                messages,
                ..CoreViewModel::default()
            }),
        })
    }

    pub(super) fn handle_group_append_failed(
        &mut self,
        group_id: String,
        message_id: String,
        retryable: bool,
        status: Option<u16>,
        code: Option<String>,
        detail: Option<String>,
    ) -> CoreResult<CoreOutput> {
        if status == Some(403) && code.as_deref() == Some("group_membership_revoked") {
            return self.handle_group_sync_failed(group_id, false, status, code, detail);
        }
        if let Some(item) = self
            .state
            .pending_group_outbox
            .iter_mut()
            .find(|item| item.envelope.message_id == message_id)
        {
            item.in_flight = false;
            item.retries = item.retries.saturating_add(1);
            if retryable && item.retries < MAX_TRANSPORT_RETRIES {
                let timer_id = format!("retry_group_append:{message_id}");
                return Ok(CoreOutput {
                    state_update: CoreStateUpdate {
                        system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                        ..CoreStateUpdate::default()
                    },
                    effects: vec![CoreEffect::ScheduleTimer {
                        timer: TimerEffect {
                            delay_ms: retry_delay_ms(&timer_id, u32::from(item.retries)),
                            timer_id,
                        },
                    }],
                    view_model: None,
                });
            }
        }
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                ..CoreStateUpdate::default()
            },
            effects: vec![CoreEffect::EmitUserNotification {
                notification: UserNotificationEffect {
                    status: SystemStatus::TemporaryNetworkFailure,
                    message: detail
                        .map(|detail| format!("group append failed: {detail}"))
                        .unwrap_or_else(|| {
                            format!("group append failed for {group_id}/{message_id}")
                        }),
                },
            }],
            view_model: None,
        })
    }

    /// Owner-only atomic dissolve of a group.
    ///
    /// Implements the four-step sequence locked in by the `design.md`
    /// Dissolve-group decision (B-full):
    ///   (a) Issue a single MLS `remove_members` commit covering every
    ///       other active member's devices in one epoch bump.
    ///   (b) Append a `ControlGroupDissolved` envelope
    ///       (`visibility = Visible`) carrying the post-dissolve manifest
    ///       so that remaining clients render a single "group dissolved"
    ///       banner instead of N membership-changed banners.
    ///   (c) Stage a `SealGroupOutbox` request in `pending_group_seal`.
    ///       The actual `CoreEffect::SealGroupOutbox` is emitted only
    ///       after both (a) and (b) have been acknowledged by the
    ///       transport (see `handle_group_envelope_appended`) so that the
    ///       seal cannot precede the commit/control messages on the wire.
    ///   (d) On `CoreEvent::GroupOutboxSealed` the engine flips
    ///       `group_state.dissolved_at = Some(sealed_at)` and transitions
    ///       the conversation state to `ConversationState::Dissolved`
    ///       (see `handle_group_outbox_sealed`).
    ///
    /// `dissolved_at` is deliberately *not* set in this method — only step
    /// (d) is allowed to mark the group dissolved, guaranteeing we never
    /// fail-closed locally on a dissolve whose seal never reached the
    /// server.

    /// Handle `CoreEvent::GroupOutboxSealed` — step (d) of `DissolveGroup`.
    ///
    /// The local group becomes dissolved only after the server acknowledges
    /// the seal. An already-sealed response is therefore also successful.
    pub(super) fn handle_group_outbox_sealed(
        &mut self,
        group_id: String,
        sealed_at: u64,
        was_already_sealed: bool,
    ) -> CoreResult<CoreOutput> {
        // Observability signal only (see design.md).
        let _ = was_already_sealed;
        // Drop any lingering pending seal entry — whether or not the seal
        // effect was issued (it may have been a retry pending a
        // `GroupOutboxSealFailed` earlier), the terminal state is now
        // "sealed on the server", so no further seal effects are needed.
        self.state.pending_group_seal.remove(&group_id);
        let mut persist_ops = vec![PersistOp::DeletePendingGroupSeal {
            group_id: group_id.clone(),
        }];

        let group_state = match self.state.group_states.get(&group_id) {
            Some(state) => state.clone(),
            None => {
                // The group could have been removed locally since the effect
                // was issued (e.g. profile reset). Nothing to transition.
                return Ok(CoreOutput {
                    state_update: CoreStateUpdate::default(),
                    effects: vec![persist_effect(&self.state, persist_ops)],
                    view_model: None,
                });
            }
        };
        let conversation_id = group_state.conversation_id.clone();

        // Set the dissolved marker only now — after the server acknowledged.
        let mut updated_group_state = group_state.clone();
        let transitioned = updated_group_state.dissolved_at.is_none();
        if transitioned {
            updated_group_state.dissolved_at = Some(sealed_at);
            self.state
                .group_states
                .insert(group_id.clone(), updated_group_state);
            persist_ops.push(PersistOp::SaveGroupState {
                group_id: group_id.clone(),
            });
        }

        // Transition the conversation to `Dissolved` so existing rendering
        // paths treat the log as read-only archive. We avoid overwriting a
        // `NeedsRebuild` state because that signals an unresolvable MLS
        // fault which must not be masked by dissolve.
        if let Some(state) = self.state.conversations.get_mut(&conversation_id) {
            if state.conversation.state != ConversationState::NeedsRebuild
                && state.conversation.state != ConversationState::Dissolved
            {
                state.conversation.state = ConversationState::Dissolved;
                state.conversation.updated_at = sealed_at;
                persist_ops.push(PersistOp::SaveConversation {
                    conversation_id: conversation_id.clone(),
                });
            }
        }

        let effects = if persist_ops.is_empty() {
            Vec::new()
        } else {
            vec![persist_effect(&self.state, persist_ops)]
        };
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                conversations_changed: transitioned,
                ..CoreStateUpdate::default()
            },
            effects,
            view_model: None,
        })
    }

    /// Handle `CoreEvent::GroupOutboxSealFailed`.
    ///
    /// Retryable failures (network errors, 5xx) re-stage the pending seal so
    /// the next `flush_pending_transport` cycle can re-emit the effect. A
    /// retryable seal failure does NOT set `dissolved_at` — the group
    /// remains locally open until the server confirms the seal (step (d)
    /// contract).
    ///
    /// Non-retryable failures surface as a temporary-network-failure
    /// notification so the UI can re-present the dissolve dialog to the
    /// owner. We keep the manifest change (removed members) intact: once
    /// the MLS commit has reached the outbox, those members cannot send
    /// again anyway. The owner's retry will re-mint the seal capability
    /// and try again.

    pub(super) fn handle_group_outbox_seal_failed(
        &mut self,
        group_id: String,
        retryable: bool,
        status: Option<u16>,
        code: Option<String>,
        detail: Option<String>,
    ) -> CoreResult<CoreOutput> {
        let _ = (status, code.clone());
        if retryable {
            // The pending seal entry was consumed when the effect was
            // dispatched. For retry we need to rebuild it. The owner's
            // current role + capability is still valid because their
            // removal was to members, not to self.
            let role = match self.local_group_role(&group_id) {
                Ok(role) => role,
                Err(_) => {
                    // Group no longer known locally — abort retry.
                    return Ok(CoreOutput::default());
                }
            };
            if role == GroupRole::Owner {
                match self.group_capability(&group_id, role) {
                    Ok(capability) => {
                        self.state.pending_group_seal.insert(
                            group_id.clone(),
                            SealGroupOutboxRequest {
                                group_id: group_id.clone(),
                                capability,
                            },
                        );
                        let persist = persist_effect(
                            &self.state,
                            vec![PersistOp::SavePendingGroupSeal {
                                group_id: group_id.clone(),
                            }],
                        );
                        let timer_id = format!("retry_group_seal:{group_id}");
                        return Ok(CoreOutput {
                            state_update: CoreStateUpdate {
                                system_statuses_changed: vec![
                                    SystemStatus::TemporaryNetworkFailure,
                                ],
                                ..CoreStateUpdate::default()
                            },
                            effects: vec![
                                persist,
                                CoreEffect::ScheduleTimer {
                                    timer: TimerEffect {
                                        delay_ms: retry_delay_ms(&timer_id, 1),
                                        timer_id,
                                    },
                                },
                            ],
                            view_model: None,
                        });
                    }
                    Err(_) => {
                        // Can't rebuild capability (unlikely); fall through
                        // to surfacing a notification.
                    }
                }
            }
            return Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: Vec::new(),
                view_model: None,
            });
        }

        // Non-retryable: clear pending state and surface the failure.
        self.state.pending_group_seal.remove(&group_id);
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                ..CoreStateUpdate::default()
            },
            effects: vec![
                persist_effect(
                    &self.state,
                    vec![PersistOp::DeletePendingGroupSeal {
                        group_id: group_id.clone(),
                    }],
                ),
                CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect {
                        status: SystemStatus::TemporaryNetworkFailure,
                        message: detail.unwrap_or_else(|| {
                            format!("failed to seal dissolved group {group_id}")
                        }),
                    },
                },
            ],
            view_model: None,
        })
    }

    pub(super) fn handle_welcome_pickup_fetch_failed(
        &mut self,
        descriptor: WelcomePickupDescriptor,
        failure: crate::error::AppErrorV1,
    ) -> CoreResult<CoreOutput> {
        let key = pending_welcome_pickup_key(&descriptor.group_id, &descriptor.device_id);
        let diagnostic_code = failure.code.clone();
        let message =
            "TapChat couldn't fetch the group welcome. It will retry when connected.".to_string();
        let mut effects = Vec::new();
        let mut persist_ops = Vec::new();

        if let Some(pending) = self.state.pending_welcome_pickups.get_mut(&key) {
            pending.retries = pending.retries.saturating_add(1);
            pending.last_error = Some(diagnostic_code);
            persist_ops.push(PersistOp::SavePendingWelcomePickup {
                group_id: descriptor.group_id.clone(),
                device_id: descriptor.device_id.clone(),
            });
            if failure.retryable && pending.retries < MAX_TRANSPORT_RETRIES {
                let timer_id = format!("{WELCOME_PICKUP_RETRY_TIMER_PREFIX}{key}");
                effects.push(CoreEffect::ScheduleTimer {
                    timer: TimerEffect {
                        delay_ms: retry_delay_ms(&timer_id, u32::from(pending.retries)),
                        timer_id,
                    },
                });
            }
        }
        if !persist_ops.is_empty() {
            effects.insert(0, persist_effect(&self.state, persist_ops));
        }
        effects.push(CoreEffect::EmitUserNotification {
            notification: UserNotificationEffect {
                status: SystemStatus::TemporaryNetworkFailure,
                message,
            },
        });

        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                ..CoreStateUpdate::default()
            },
            effects,
            view_model: None,
        })
    }

    pub(super) fn handle_welcome_pickup_fetched(
        &mut self,
        descriptor: WelcomePickupDescriptor,
        welcome_b64: String,
        manifest: Option<GroupManifest>,
    ) -> CoreResult<CoreOutput> {
        let claim_id = descriptor.claim_id.as_ref().ok_or_else(|| {
            CoreError::new(
                "protocol_upgrade_required",
                "group Welcome pickup is missing its V2 KeyPackage claim ID",
            )
        })?;
        let declared_digest = descriptor.welcome_digest.as_ref().ok_or_else(|| {
            CoreError::new(
                "protocol_upgrade_required",
                "group Welcome pickup is missing its signed Welcome digest",
            )
        })?;
        let actual_digest = STANDARD.encode(Sha256::digest(welcome_b64.as_bytes()));
        if &actual_digest != declared_digest {
            return Err(CoreError::invalid_input(
                "group Welcome ciphertext does not match its signed pickup descriptor",
            ));
        }
        if let Some(existing) = self
            .state
            .group_states
            .get(&descriptor.group_id)
            .and_then(|state| state.welcome_pickup.as_ref())
        {
            if existing.claim_id.as_ref() == Some(claim_id) {
                if existing.welcome_digest.as_ref() == Some(declared_digest) {
                    self.state
                        .pending_welcome_pickups
                        .remove(&pending_welcome_pickup_key(
                            &descriptor.group_id,
                            &descriptor.device_id,
                        ));
                    return Ok(CoreOutput {
                        effects: vec![persist_effect(
                            &self.state,
                            vec![PersistOp::DeletePendingWelcomePickup {
                                group_id: descriptor.group_id.clone(),
                                device_id: descriptor.device_id.clone(),
                            }],
                        )],
                        ..CoreOutput::default()
                    });
                }
                return Err(CoreError::invalid_input(
                    "a consumed group KeyPackage claim was reused with a different Welcome",
                ));
            }
        }
        log::info!(
            "handle_welcome_pickup_fetched: applying welcome pickup group_id={} device_id={}",
            descriptor.group_id,
            descriptor.device_id
        );
        let mut imported_shell: Option<(String, String)> = None;
        if !self.state.group_states.contains_key(&descriptor.group_id) {
            let manifest = manifest.ok_or_else(|| {
                CoreError::invalid_input("welcome pickup result is missing group manifest")
            })?;
            manifest.validate()?;
            self.verify_manifest_signature(&manifest)?;
            let start_seq = descriptor
                .start_seq
                .ok_or_else(|| CoreError::invalid_input("fsm_v2 welcome is missing startSeq"))?;
            let roster_version = descriptor.roster_version.ok_or_else(|| {
                CoreError::invalid_input("fsm_v2 welcome is missing rosterVersion")
            })?;
            let last_commit_message_id =
                descriptor.last_commit_message_id.as_ref().ok_or_else(|| {
                    CoreError::invalid_input("fsm_v2 welcome is missing lastCommitMessageId")
                })?;
            if manifest.group_id != descriptor.group_id
                || roster_version != manifest.roster_version
                || manifest.last_commit_message_id.as_ref() != Some(last_commit_message_id)
                || start_seq == 0
            {
                return Err(CoreError::invalid_input(
                    "welcome cursor metadata does not match the imported manifest",
                ));
            }
            let local_identity = self
                .state
                .local_identity
                .as_ref()
                .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?;
            let local_role = manifest
                .members
                .iter()
                .find(|member| {
                    member.user_id == local_identity.user_identity.user_id
                        && member.status == GroupMemberStatus::Active
                })
                .map(|member| member.role);
            if local_role.is_none() {
                return Err(CoreError::invalid_input(
                    "local user is not an active member of the group manifest",
                ));
            }
            let imported_group_id = manifest.group_id.clone();
            let imported_conversation_id = manifest.conversation_id.clone();
            self.state.conversations.insert(
                manifest.conversation_id.clone(),
                LocalConversationState {
                    conversation: Conversation {
                        conversation_id: manifest.conversation_id.clone(),
                        kind: ConversationKind::Group,
                        member_users: manifest
                            .members
                            .iter()
                            .map(|member| member.user_id.clone())
                            .collect(),
                        member_devices: vec![ConversationMember {
                            user_id: local_identity.user_identity.user_id.clone(),
                            device_id: local_identity.device_identity.device_id.clone(),
                            status: DeviceStatusKind::Active,
                        }],
                        state: ConversationState::Active,
                        updated_at: manifest.updated_at,
                    },
                    messages: Vec::new(),
                    last_message_type: None,
                    peer_user_id: manifest.group_id.clone(),
                    last_known_peer_active_devices: BTreeSet::new(),
                    recovery_status: RecoveryStatus::Healthy,
                    archive_metadata: None,
                },
            );
            self.state.group_cursors.insert(
                manifest.group_id.clone(),
                GroupCursor {
                    group_id: manifest.group_id.clone(),
                    last_fetched_seq: self
                        .state
                        .group_join_requests
                        .values()
                        .find(|join| {
                            join.group_id == manifest.group_id
                                && join.welcome_pickup.as_ref().is_some_and(|pickup| {
                                    pickup.group_id == descriptor.group_id
                                        && pickup.device_id == descriptor.device_id
                                })
                        })
                        .and_then(|join| join.start_cursor.as_ref())
                        .map(|cursor| cursor.last_fetched_seq)
                        .unwrap_or(0),
                    updated_at: manifest.updated_at,
                },
            );
            self.state.group_states.insert(
                manifest.group_id.clone(),
                PersistedGroupState {
                    group_id: manifest.group_id.clone(),
                    conversation_id: manifest.conversation_id.clone(),
                    manifest,
                    local_role,
                    welcome_pickup: Some(descriptor.clone()),
                    dissolved_at: None,
                    pending_membership_transition: None,
                    consistency_state: GroupConsistencyState::Ready,
                    pending_group_transition: None,
                    leave_requests: Vec::new(),
                },
            );
            imported_shell = Some((imported_group_id, imported_conversation_id));
            log::info!(
                "handle_welcome_pickup_fetched: imported group shell group_id={} conversation_id={} local_role={:?}",
                descriptor.group_id,
                self.state
                    .group_states
                    .get(&descriptor.group_id)
                    .map(|state| state.conversation_id.as_str())
                    .unwrap_or("<missing>"),
                local_role
            );
        }
        let group_state = self
            .state
            .group_states
            .get(&descriptor.group_id)
            .ok_or_else(|| CoreError::invalid_input("group state does not exist for welcome"))?
            .clone();
        let mut staged_mls = self
            .state
            .mls_adapter
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .fork()?;
        let binding_bundles = self.identity_bundles_for_group_manifest(&group_state.manifest)?;
        let result = staged_mls.ingest_welcome_with_device_bindings(
            &group_state.conversation_id,
            &welcome_b64,
            &binding_bundles,
        );
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                if let Some((group_id, conversation_id)) = imported_shell {
                    self.state.group_states.remove(&group_id);
                    self.state.group_cursors.remove(&group_id);
                    self.state.conversations.remove(&conversation_id);
                }
                let message = format!(
                    "failed to import group welcome for {}: {}. The welcome may target an expired device key package; ask the inviter to refresh the contact and invite again.",
                    descriptor.group_id, error
                );
                log::warn!(
                    "handle_welcome_pickup_fetched: welcome import failed group_id={} device_id={} error={}",
                    redact_id("group", &descriptor.group_id),
                    redact_id("device", &descriptor.device_id),
                    error.code()
                );
                return Ok(CoreOutput {
                    state_update: CoreStateUpdate {
                        conversations_changed: true,
                        system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                        ..CoreStateUpdate::default()
                    },
                    effects: vec![CoreEffect::EmitUserNotification {
                        notification: UserNotificationEffect {
                            status: SystemStatus::TemporaryNetworkFailure,
                            message,
                        },
                    }],
                    view_model: None,
                });
            }
        };
        if !matches!(result, IngestResult::AppliedWelcome { .. }) {
            if let Some((group_id, conversation_id)) = imported_shell {
                self.state.group_states.remove(&group_id);
                self.state.group_cursors.remove(&group_id);
                self.state.conversations.remove(&conversation_id);
            }
            return Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    conversations_changed: true,
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect {
                        status: SystemStatus::TemporaryNetworkFailure,
                        message: format!(
                            "failed to import group welcome for {}: welcome pickup did not apply",
                            descriptor.group_id
                        ),
                    },
                }],
                view_model: None,
            });
        }
        let summary = staged_mls.export_group_summary(&group_state.conversation_id)?;
        if summary.epoch != group_state.manifest.mls_epoch_hint {
            if let Some((group_id, conversation_id)) = imported_shell {
                self.state.group_states.remove(&group_id);
                self.state.group_cursors.remove(&group_id);
                self.state.conversations.remove(&conversation_id);
            }
            return Err(CoreError::invalid_input(
                "welcome MLS epoch does not match the imported manifest",
            ));
        }
        self.state.mls_adapter = Some(staged_mls);
        self.state
            .mls_summaries
            .insert(group_state.conversation_id.clone(), summary);
        if descriptor
            .roster_version
            .is_some_and(|version| version != group_state.manifest.roster_version)
            || descriptor.last_commit_message_id.is_some()
                && descriptor.last_commit_message_id != group_state.manifest.last_commit_message_id
        {
            return self.block_group_needs_rebuild(
                &group_state.group_id,
                "welcome cursor metadata does not match the imported manifest",
            );
        }
        if let Some(state) = self.state.group_states.get_mut(&group_state.group_id) {
            state.consistency_state = GroupConsistencyState::Ready;
        }
        let start_seq = descriptor.start_seq.unwrap_or_else(|| {
            self.state
                .group_cursors
                .get(&group_state.group_id)
                .map(|cursor| cursor.last_fetched_seq)
                .unwrap_or(0)
        });
        self.state.group_cursors.insert(
            group_state.group_id.clone(),
            GroupCursor {
                group_id: group_state.group_id.clone(),
                last_fetched_seq: start_seq,
                updated_at: current_unix_millis(self.state.message_nonce),
            },
        );
        let post_welcome_effects = self.rotate_local_key_package_after_welcome()?;
        log::info!(
            "handle_welcome_pickup_fetched: group imported group_id={} conversation_id={} epoch_ready=true",
            group_state.group_id,
            group_state.conversation_id
        );
        let pending_key = pending_welcome_pickup_key(&descriptor.group_id, &descriptor.device_id);
        let had_pending = self
            .state
            .pending_welcome_pickups
            .remove(&pending_key)
            .is_some();
        let mut effects = vec![persist_effect(
            &self.state,
            vec![
                PersistOp::SaveConversation {
                    conversation_id: group_state.conversation_id.clone(),
                },
                PersistOp::SaveMlsState {
                    conversation_id: group_state.conversation_id.clone(),
                },
                PersistOp::SaveGroupState {
                    group_id: group_state.group_id.clone(),
                },
                PersistOp::SaveGroupCursor {
                    group_id: group_state.group_id.clone(),
                },
            ],
        )];
        if had_pending {
            effects.insert(
                0,
                persist_effect(
                    &self.state,
                    vec![PersistOp::DeletePendingWelcomePickup {
                        group_id: descriptor.group_id.clone(),
                        device_id: descriptor.device_id.clone(),
                    }],
                ),
            );
        }
        effects.extend(post_welcome_effects);
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                conversations_changed: true,
                contacts_changed: true,
                ..CoreStateUpdate::default()
            },
            effects,
            view_model: Some(CoreViewModel {
                conversations: vec![self.conversation_summary(&group_state.conversation_id)?],
                ..CoreViewModel::default()
            }),
        })
    }

    pub(super) fn replay_pending_records_for_device(
        &mut self,
        device_id: String,
    ) -> CoreResult<CoreOutput> {
        let records: Vec<InboxRecord> = {
            let Some(sync_state) = self.state.sync_states.get(&device_id) else {
                return Ok(CoreOutput::default());
            };
            if sync_state.pending_records.is_empty() {
                return Ok(CoreOutput::default());
            }
            sync_state.pending_records.values().cloned().collect()
        };
        let to_seq = records.iter().map(|record| record.seq).max().unwrap_or(0);
        let output = self.handle_inbox_records_internal(
            device_id.clone(),
            records,
            to_seq,
            false,
            InboxRecordSource::PendingReplay,
        )?;
        let pending_retry = self
            .state
            .sync_states
            .get(&device_id)
            .map(|state| state.pending_retry)
            .unwrap_or(false);
        let next_phase = if pending_retry {
            RecoveryPhase::WaitingForPendingReplay
        } else {
            RecoveryPhase::WaitingForIdentityRefresh
        };
        let recovery_ids: Vec<String> = self.state.recovery_contexts.keys().cloned().collect();
        for conversation_id in recovery_ids {
            if self.state.conversations.contains_key(&conversation_id) {
                self.transition_recovery_phase(&conversation_id, next_phase);
            }
        }
        Ok(output)
    }
}

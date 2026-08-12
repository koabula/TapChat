use super::*;

impl CoreEngine {
    pub(super) fn send_attachment_message(
        &mut self,
        conversation_id: String,
        attachment_descriptor: AttachmentDescriptor,
    ) -> CoreResult<CoreOutput> {
        validate_attachment_descriptor(&attachment_descriptor)?;
        let is_group = self
            .state
            .conversations
            .get(&conversation_id)
            .map(|c| c.conversation.kind == ConversationKind::Group)
            .unwrap_or(false);
        if is_group {
            self.ensure_group_ready_for_send(&conversation_id)?;
        } else {
            self.ensure_conversation_ready_for_send(&conversation_id)?;
        }
        let message_nonce = self.next_message_nonce();
        let message_id = self.next_message_id(
            &conversation_id,
            if is_group {
                "group-attachment"
            } else {
                "attachment"
            },
            message_nonce,
        );
        let group_id = if is_group {
            Some(
                self.group_id_for_conversation(&conversation_id)?
                    .to_string(),
            )
        } else {
            None
        };
        let task_id = format!("blob-upload:{message_id}");
        self.state.pending_blob_uploads.insert(
            task_id.clone(),
            PendingBlobUpload {
                task_id: task_id.clone(),
                conversation_id: conversation_id.clone(),
                group_id,
                descriptor: attachment_descriptor.clone(),
                blob_ciphertext_b64: None,
                payload_metadata: None,
                message_id: message_id.clone(),
                metadata_ciphertext: None,
                prepared_upload: None,
                retries: 0,
                in_flight: false,
            },
        );
        self.merge_with_transport_flush(CoreOutput {
            state_update: CoreStateUpdate {
                messages_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(
                &self.state,
                vec![PersistOp::SavePendingBlobTransfer {
                    task_id: task_id.clone(),
                }],
            )],
            view_model: Some(CoreViewModel {
                messages: vec![MessageSummary {
                    conversation_id,
                    message_id,
                    message_type: MessageType::MlsApplication,
                }],
                ..CoreViewModel::default()
            }),
        })
    }

    pub(super) fn download_attachment(
        &mut self,
        conversation_id: String,
        message_id: String,
        reference: String,
        destination: String,
    ) -> CoreResult<CoreOutput> {
        let payload_metadata =
            self.attachment_payload_metadata_json(&conversation_id, &message_id)?;
        let payload_metadata: AttachmentPayloadMetadata = serde_json::from_str(&payload_metadata)
            .map_err(|error| {
            CoreError::invalid_input(format!(
                "failed to decode attachment payload metadata: {error}"
            ))
        })?;
        let task_id = attachment_download_task_id(&message_id, &reference, &destination);
        self.state.pending_blob_downloads.insert(
            task_id.clone(),
            PendingBlobDownload {
                task_id: task_id.clone(),
                conversation_id,
                message_id,
                reference,
                destination_id: destination,
                payload_metadata,
                authorized_download: None,
                retries: 0,
                in_flight: false,
            },
        );
        Ok(merge_outputs(
            CoreOutput {
                state_update: CoreStateUpdate {
                    messages_changed: true,
                    ..CoreStateUpdate::default()
                },
                effects: vec![persist_effect(
                    &self.state,
                    vec![PersistOp::SavePendingBlobTransfer { task_id }],
                )],
                view_model: None,
            },
            self.flush_pending_transport()?,
        ))
    }

    pub(super) fn attachment_payload_metadata_json(
        &self,
        conversation_id: &str,
        message_id: &str,
    ) -> CoreResult<String> {
        self.state
            .conversations
            .get(conversation_id)
            .and_then(|state| {
                state
                    .messages
                    .iter()
                    .find(|message| message.message_id == message_id)
            })
            .and_then(|message| message.plaintext.as_deref())
            .or_else(|| {
                self.state
                    .pending_outbox
                    .iter()
                    .find(|item| {
                        item.envelope.conversation_id == conversation_id
                            && item.envelope.message_id == message_id
                    })
                    .and_then(|item| item.plaintext_cache.as_deref())
            })
            .or_else(|| {
                self.state
                    .pending_group_outbox
                    .iter()
                    .find(|item| {
                        item.envelope.conversation_id == conversation_id
                            && item.envelope.message_id == message_id
                    })
                    .and_then(|item| item.plaintext_cache.as_deref())
            })
            .ok_or_else(|| CoreError::invalid_input("attachment metadata is missing"))
            .map(str::to_string)
    }

    pub(super) fn sync_inbox(
        &mut self,
        device_id: String,
        reason: Option<String>,
    ) -> CoreResult<CoreOutput> {
        if device_id.trim().is_empty() {
            return Err(CoreError::invalid_input("device_id must not be empty"));
        }

        // Check if deployment_bundle exists - if not, skip sync gracefully
        let deployment = match self.state.deployment_bundle.as_ref() {
            Some(d) => d,
            None => {
                // No deployment configured - return empty output without error
                // This happens when profile hasn't been deployed to Cloudflare yet
                return Ok(CoreOutput::default());
            }
        };

        let inbox_websocket_endpoint = deployment.inbox_websocket_endpoint.clone();
        let inbox_http_endpoint = deployment.inbox_http_endpoint.clone();
        let auth = self.device_runtime_auth_requirement()?;
        let retry_reset_ops = if Self::should_reset_pending_direct_transport(reason.as_deref()) {
            self.reset_pending_direct_transport_for_retry(&device_id)
        } else {
            Vec::new()
        };
        let sync_state = self
            .state
            .sync_states
            .entry(device_id.clone())
            .or_insert_with(|| SyncEngine::new_device_state(&device_id));
        let last_acked_seq = sync_state.checkpoint.last_acked_seq;
        for context in self.state.recovery_contexts.values_mut() {
            if context.phase == RecoveryPhase::WaitingForSync {
                context.phase = RecoveryPhase::WaitingForPendingReplay;
                context.attempt_count = context.attempt_count.saturating_add(1);
            }
        }
        self.state
            .realtime_sessions
            .entry(device_id.clone())
            .or_default();
        let request_id = self.next_request_id(&format!("get_head:{device_id}"));
        self.state.pending_requests.insert(
            request_id.clone(),
            PendingRequest::GetHead {
                device_id: device_id.clone(),
            },
        );
        let sync_output = CoreOutput {
            state_update: CoreStateUpdate {
                checkpoints_changed: true,
                system_statuses_changed: vec![SystemStatus::SyncInProgress],
                ..CoreStateUpdate::default()
            },
            effects: vec![
                CoreEffect::OpenRealtimeConnection {
                    connection: RealtimeConnectionEffect {
                        subscription: RealtimeSubscriptionRequest {
                            device_id: device_id.clone(),
                            endpoint: inbox_websocket_endpoint,
                            last_acked_seq,
                            headers: BTreeMap::new(),
                            auth: Some(auth.clone()),
                        },
                    },
                },
                CoreEffect::ExecuteHttpRequest {
                    request: HttpRequestEffect {
                        request_id,
                        method: HttpMethod::Get,
                        url: format!(
                            "{}/v1/inbox/{}/head",
                            inbox_http_endpoint.trim_end_matches('/'),
                            device_id
                        ),
                        headers: BTreeMap::new(),
                        auth: Some(auth.clone()),
                        body: None,
                    },
                },
                CoreEffect::PersistState {
                    persist: PersistStateEffect {
                        ops: vec![PersistOp::SaveSyncState {
                            device_id: device_id.clone(),
                        }],
                        snapshot: Some(build_persistence_snapshot(&self.state)),
                    },
                },
            ],
            view_model: None,
        };
        if retry_reset_ops.is_empty() {
            return Ok(sync_output);
        }
        let retry_output = merge_outputs(
            CoreOutput {
                state_update: CoreStateUpdate {
                    checkpoints_changed: true,
                    messages_changed: true,
                    system_statuses_changed: vec![SystemStatus::SyncInProgress],
                    ..CoreStateUpdate::default()
                },
                effects: vec![persist_effect(&self.state, retry_reset_ops)],
                view_model: None,
            },
            self.flush_pending_transport()?,
        );
        Ok(merge_outputs(retry_output, sync_output))
    }

    pub(super) fn next_request_id(&mut self, prefix: &str) -> String {
        self.state.request_nonce = self.state.request_nonce.saturating_add(1);
        format!("{prefix}:{}", self.state.request_nonce)
    }

    pub(super) fn next_message_nonce(&mut self) -> u64 {
        self.state.message_nonce = self.state.message_nonce.saturating_add(1);
        self.state.message_nonce
    }

    pub(super) fn device_runtime_auth_requirement(&self) -> CoreResult<TransportAuthRequirement> {
        let deployment = self
            .state
            .deployment_bundle
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("deployment bundle is not initialized"))?;
        Ok(TransportAuthRequirement::DeviceRuntime {
            runtime_id: deployment.runtime_id.clone(),
            device_id: self.local_device_id_required()?,
        })
    }

    pub(super) fn local_device_id_required(&self) -> CoreResult<String> {
        self.state
            .local_identity
            .as_ref()
            .map(|identity| identity.device_identity.device_id.clone())
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))
    }

    pub(super) fn inbox_management_endpoint(&self, suffix: &str) -> CoreResult<String> {
        let deployment = self
            .state
            .deployment_bundle
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("deployment bundle is not initialized"))?;
        let device_id = self.local_device_id_required()?;
        Ok(format!(
            "{}/v1/inbox/{}/{}",
            deployment.inbox_http_endpoint.trim_end_matches('/'),
            urlencoding::encode(&device_id),
            suffix.trim_start_matches('/')
        ))
    }

    pub(super) fn local_device_status_document(&self) -> CoreResult<DeviceStatusDocument> {
        let bundle = self
            .state
            .local_bundle
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity bundle is unavailable"))?;
        Ok(DeviceStatusDocument {
            version: crate::model::CURRENT_MODEL_VERSION.to_string(),
            user_id: bundle.user_id.clone(),
            updated_at: bundle.updated_at,
            devices: bundle
                .devices
                .iter()
                .map(|device| DeviceStatusRecord {
                    version: crate::model::CURRENT_MODEL_VERSION.to_string(),
                    user_id: bundle.user_id.clone(),
                    device_id: device.device_id.clone(),
                    status: device.status,
                    updated_at: bundle.updated_at,
                })
                .collect(),
        })
    }

    pub(super) fn local_shared_state_publish_effects(&self) -> CoreResult<Vec<CoreEffect>> {
        let mut effects = Vec::new();
        let Some(bundle) = self.state.local_bundle.as_ref() else {
            return Ok(effects);
        };
        let auth = self.device_runtime_auth_requirement()?;
        if let Some(reference) = bundle.identity_bundle_ref.clone() {
            effects.push(CoreEffect::PublishSharedState {
                publish: PublishSharedStateRequest {
                    reference,
                    document_kind: SharedStateDocumentKind::IdentityBundle,
                    body: serde_json::to_string(bundle).map_err(|error| {
                        CoreError::invalid_input(format!(
                            "failed to encode local identity bundle: {error}"
                        ))
                    })?,
                    headers: BTreeMap::new(),
                    auth: Some(auth.clone()),
                },
            });
        }
        if let Some(reference) = bundle.device_status_ref.clone() {
            let document = self.local_device_status_document()?;
            effects.push(CoreEffect::PublishSharedState {
                publish: PublishSharedStateRequest {
                    reference,
                    document_kind: SharedStateDocumentKind::DeviceStatus,
                    body: serde_json::to_string(&document).map_err(|error| {
                        CoreError::invalid_input(format!(
                            "failed to encode local device status document: {error}"
                        ))
                    })?,
                    headers: BTreeMap::new(),
                    auth: Some(auth),
                },
            });
        }
        Ok(effects)
    }

    pub(super) fn list_message_requests(&mut self) -> CoreResult<CoreOutput> {
        Ok(CoreOutput {
            state_update: CoreStateUpdate::default(),
            effects: vec![CoreEffect::FetchMessageRequests {
                fetch: FetchMessageRequestsRequest {
                    device_id: self.local_device_id_required()?,
                    endpoint: self.inbox_management_endpoint("message-requests")?,
                    headers: BTreeMap::new(),
                    auth: Some(self.device_runtime_auth_requirement()?),
                },
            }],
            view_model: None,
        })
    }

    pub(super) fn act_on_message_request(
        &mut self,
        request_id: String,
        action: MessageRequestAction,
    ) -> CoreResult<CoreOutput> {
        Ok(CoreOutput {
            state_update: CoreStateUpdate::default(),
            effects: vec![CoreEffect::ActOnMessageRequest {
                action: MessageRequestActionRequest {
                    device_id: self.local_device_id_required()?,
                    request_id,
                    action,
                    endpoint: self.inbox_management_endpoint("message-requests")?,
                    headers: BTreeMap::new(),
                    auth: Some(self.device_runtime_auth_requirement()?),
                },
            }],
            view_model: None,
        })
    }

    pub(super) fn list_allowlist(&mut self) -> CoreResult<CoreOutput> {
        let device_id = self.local_device_id_required()?;
        Ok(CoreOutput {
            state_update: CoreStateUpdate::default(),
            effects: vec![CoreEffect::FetchAllowlist {
                fetch: FetchAllowlistRequest {
                    device_id,
                    endpoint: self.inbox_management_endpoint("allowlist")?,
                    headers: BTreeMap::new(),
                    auth: Some(self.device_runtime_auth_requirement()?),
                },
            }],
            view_model: None,
        })
    }

    pub(super) fn add_allowlist_user(&mut self, user_id: String) -> CoreResult<CoreOutput> {
        let device_id = self.local_device_id_required()?;
        self.state.pending_allowlist_mutation = Some(PendingAllowlistMutation::Add {
            user_id: user_id.clone(),
        });
        Ok(CoreOutput {
            state_update: CoreStateUpdate::default(),
            effects: vec![CoreEffect::FetchAllowlist {
                fetch: FetchAllowlistRequest {
                    device_id,
                    endpoint: self.inbox_management_endpoint("allowlist")?,
                    headers: BTreeMap::new(),
                    auth: Some(self.device_runtime_auth_requirement()?),
                },
            }],
            view_model: None,
        })
    }

    pub(super) fn remove_allowlist_user(&mut self, user_id: String) -> CoreResult<CoreOutput> {
        self.remove_allowlist_users(vec![user_id])
    }

    pub(super) fn remove_allowlist_users(
        &mut self,
        mut user_ids: Vec<String>,
    ) -> CoreResult<CoreOutput> {
        user_ids.sort();
        user_ids.dedup();
        if user_ids.is_empty() {
            return Ok(CoreOutput::default());
        }
        let device_id = self.local_device_id_required()?;
        self.state.pending_allowlist_mutation = if user_ids.len() == 1 {
            Some(PendingAllowlistMutation::Remove {
                user_id: user_ids.remove(0),
            })
        } else {
            Some(PendingAllowlistMutation::RemoveMany { user_ids })
        };
        Ok(CoreOutput {
            state_update: CoreStateUpdate::default(),
            effects: vec![CoreEffect::FetchAllowlist {
                fetch: FetchAllowlistRequest {
                    device_id,
                    endpoint: self.inbox_management_endpoint("allowlist")?,
                    headers: BTreeMap::new(),
                    auth: Some(self.device_runtime_auth_requirement()?),
                },
            }],
            view_model: None,
        })
    }

    pub(super) fn handle_realtime_event(
        &mut self,
        device_id: String,
        event: RealtimeEvent,
    ) -> CoreResult<CoreOutput> {
        match event {
            RealtimeEvent::HeadUpdated { seq } => {
                let sync_state = self
                    .state
                    .sync_states
                    .entry(device_id.clone())
                    .or_insert_with(|| SyncEngine::new_device_state(&device_id));
                SyncEngine::register_head(sync_state, seq);
                self.state
                    .realtime_sessions
                    .entry(device_id.clone())
                    .or_default()
                    .last_known_seq = seq;
                if let Some(decision) = SyncEngine::next_fetch(sync_state) {
                    self.issue_fetch(device_id, decision)
                } else {
                    Ok(CoreOutput::default())
                }
            }
            RealtimeEvent::InboxRecordAvailable { seq, record } => {
                if let Some(record) = record {
                    if record.seq != seq {
                        let sync_state = self
                            .state
                            .sync_states
                            .entry(device_id.clone())
                            .or_insert_with(|| SyncEngine::new_device_state(&device_id));
                        SyncEngine::register_head(sync_state, seq.max(record.seq));
                        if let Some(decision) = SyncEngine::next_fetch(sync_state) {
                            return self.issue_fetch(device_id, decision);
                        }
                    }
                    let sync_state = self
                        .state
                        .sync_states
                        .entry(device_id.clone())
                        .or_insert_with(|| SyncEngine::new_device_state(&device_id));
                    SyncEngine::register_head(sync_state, seq);
                    self.handle_inbox_records(device_id, vec![record], seq)
                } else {
                    let sync_state = self
                        .state
                        .sync_states
                        .entry(device_id.clone())
                        .or_insert_with(|| SyncEngine::new_device_state(&device_id));
                    SyncEngine::register_head(sync_state, seq);
                    if let Some(decision) = SyncEngine::next_fetch(sync_state) {
                        self.issue_fetch(device_id, decision)
                    } else {
                        Ok(CoreOutput::default())
                    }
                }
            }
            RealtimeEvent::MessageRequestChanged { .. } => self.list_message_requests(),
            _ => Ok(CoreOutput::default()),
        }
    }

    pub(super) fn handle_timer(&mut self, timer_id: String) -> CoreResult<CoreOutput> {
        if let Some(device_id) = timer_id.strip_prefix("sync:") {
            return self.sync_inbox(device_id.to_string(), None);
        }
        if let Some(group_id) = timer_id.strip_prefix("group_sync:") {
            return self.sync_group_outbox(group_id.to_string(), None);
        }
        if let Some(user_id) = timer_id.strip_prefix("refresh_identity:") {
            let has_pending_recovery = self
                .affected_conversations_for_peer(user_id)
                .into_iter()
                .any(|conversation_id| {
                    self.state
                        .recovery_contexts
                        .get(&conversation_id)
                        .map(|context| context.phase == RecoveryPhase::WaitingForIdentityRefresh)
                        .unwrap_or(false)
                });
            if !has_pending_recovery {
                return Ok(CoreOutput::default());
            }
            return self.refresh_identity_state(user_id.to_string());
        }
        if let Some(message_id) = timer_id.strip_prefix("retry_append:") {
            if let Some(item) = self
                .state
                .pending_outbox
                .iter_mut()
                .find(|item| item.envelope.message_id == message_id)
            {
                item.in_flight = false;
            }
            return self.flush_pending_transport();
        }
        if let Some(message_id) = timer_id.strip_prefix("retry_group_append:") {
            if let Some(item) = self
                .state
                .pending_group_outbox
                .iter_mut()
                .find(|item| item.envelope.message_id == message_id)
            {
                item.in_flight = false;
            }
            return self.flush_pending_transport();
        }
        if let Some(transition_id) = timer_id.strip_prefix("retry_group_transition:") {
            for item in &mut self.state.pending_group_outbox {
                if item
                    .envelope
                    .membership_proof
                    .as_ref()
                    .is_some_and(|proof| {
                        format!("group-transition:{}", proof.control_message_id) == transition_id
                    })
                {
                    item.in_flight = false;
                }
            }
            return self.flush_pending_transport();
        }
        if let Some(device_id) = timer_id.strip_prefix("retry_ack:") {
            if let Some(ack) = self.state.pending_acks.get_mut(device_id) {
                ack.in_flight = false;
            }
            return self.flush_pending_transport();
        }
        if let Some(task_id) = timer_id.strip_prefix("retry_blob_upload:") {
            if let Some(task) = self.state.pending_blob_uploads.get_mut(task_id) {
                task.in_flight = false;
            }
            return self.flush_pending_transport();
        }
        if let Some(task_id) = timer_id.strip_prefix("retry_blob_download:") {
            if let Some(task) = self.state.pending_blob_downloads.get_mut(task_id) {
                task.in_flight = false;
            }
            return self.flush_pending_transport();
        }
        if let Some(key) = timer_id.strip_prefix(WELCOME_PICKUP_RETRY_TIMER_PREFIX) {
            if let Some(pending) = self.state.pending_welcome_pickups.get(key).cloned() {
                if self.state.group_states.contains_key(&pending.group_id)
                    || pending.retries >= MAX_TRANSPORT_RETRIES
                {
                    return Ok(CoreOutput::default());
                }
                return Ok(CoreOutput {
                    state_update: CoreStateUpdate {
                        system_statuses_changed: vec![SystemStatus::SyncInProgress],
                        ..CoreStateUpdate::default()
                    },
                    effects: vec![CoreEffect::FetchWelcomePickup {
                        fetch: FetchWelcomePickupRequest {
                            descriptor: pending.descriptor,
                            headers: BTreeMap::new(),
                        },
                    }],
                    view_model: None,
                });
            }
        }
        Ok(CoreOutput::default())
    }

    pub(super) fn merge_with_transport_flush(
        &mut self,
        output: CoreOutput,
    ) -> CoreResult<CoreOutput> {
        Ok(merge_outputs(output, self.flush_pending_transport()?))
    }

    pub(super) fn flush_pending_transport(&mut self) -> CoreResult<CoreOutput> {
        let mut output = CoreOutput::default();
        output = merge_outputs(output, self.flush_outbox()?);
        output = merge_outputs(output, self.flush_group_outbox()?);
        output = merge_outputs(output, self.flush_group_seals()?);
        output = merge_outputs(output, self.flush_pending_acks()?);
        output = merge_outputs(output, self.flush_blob_uploads()?);
        output = merge_outputs(output, self.flush_blob_downloads()?);
        Ok(output)
    }

    pub(super) fn flush_outbox(&mut self) -> CoreResult<CoreOutput> {
        let mut effects = Vec::new();
        for index in 0..self.state.pending_outbox.len() {
            if self.state.pending_outbox[index].in_flight
                || self.state.pending_outbox[index].retries >= MAX_TRANSPORT_RETRIES
            {
                continue;
            }
            let item = self.state.pending_outbox[index].clone();
            let request = self.build_append_request(&item)?;
            self.state.pending_outbox[index].in_flight = true;
            effects.push(CoreEffect::ExecuteHttpRequest { request });
        }
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                messages_changed: !effects.is_empty(),
                ..CoreStateUpdate::default()
            },
            effects,
            view_model: None,
        })
    }

    pub(super) fn flush_group_outbox(&mut self) -> CoreResult<CoreOutput> {
        if self.require_group_authorization_v2().is_err() {
            return Ok(CoreOutput::default());
        }
        let mut effects = Vec::new();
        let mut bundled_message_ids = BTreeSet::new();

        let proofs: Vec<GroupMembershipProof> = self
            .state
            .pending_group_outbox
            .iter()
            .filter(|item| !item.in_flight && item.retries < MAX_TRANSPORT_RETRIES)
            .filter_map(|item| item.envelope.membership_proof.clone())
            .fold(
                BTreeMap::<String, GroupMembershipProof>::new(),
                |mut proofs, proof| {
                    proofs
                        .entry(proof.control_message_id.clone())
                        .or_insert(proof);
                    proofs
                },
            )
            .into_values()
            .collect();

        for proof in proofs {
            let mut indexes = Vec::new();
            for (index, item) in self.state.pending_group_outbox.iter().enumerate() {
                if item.in_flight || item.retries >= MAX_TRANSPORT_RETRIES {
                    continue;
                }
                if item.envelope.membership_proof.as_ref() == Some(&proof)
                    && (item.envelope.message_id == proof.commit_message_id
                        || item.envelope.message_id == proof.control_message_id
                        || proof.state_event_message_id.as_ref() == Some(&item.envelope.message_id))
                {
                    indexes.push(index);
                }
            }
            let has_control = indexes.iter().any(|index| {
                self.state.pending_group_outbox[*index].envelope.message_id
                    == proof.control_message_id
            });
            let commit_is_new =
                proof.previous_commit_message_id.as_ref() != Some(&proof.commit_message_id);
            let has_commit = indexes.iter().any(|index| {
                self.state.pending_group_outbox[*index].envelope.message_id
                    == proof.commit_message_id
            });
            if !has_control || (commit_is_new && !has_commit) {
                continue;
            }
            let group_id = self.state.pending_group_outbox[indexes[0]]
                .envelope
                .group_id
                .clone();
            let transition_id = format!("group-transition:{}", proof.control_message_id);
            let group_state = self
                .state
                .group_states
                .get(&group_id)
                .ok_or_else(|| CoreError::invalid_input("group does not exist"))?
                .clone();
            if group_state.consistency_state == GroupConsistencyState::BlockedNeedsRebuild {
                continue;
            }
            let Some(pending_transition) = group_state
                .pending_group_transition
                .as_ref()
                .filter(|pending| pending.transition_id == transition_id)
            else {
                // Membership envelopes without a persisted semantic intent are
                // legacy partial transitions.  They must be reconciled, never
                // replayed one record at a time.
                if let Some(state) = self.state.group_states.get_mut(&group_id) {
                    state.consistency_state = GroupConsistencyState::Reconciling;
                }
                continue;
            };
            let Some(operation) = pending_transition.intent.operation().cloned() else {
                if let Some(state) = self.state.group_states.get_mut(&group_id) {
                    state.consistency_state = GroupConsistencyState::Reconciling;
                }
                continue;
            };
            if matches!(
                pending_transition.stage,
                PendingGroupTransitionStage::AwaitingAuthorizationBootstrap
                    | PendingGroupTransitionStage::ReconcilingAfterConflict
            ) {
                continue;
            }
            let request_binding = pending_transition.intent.request_binding().cloned();
            let role = group_state.local_role.unwrap_or(GroupRole::Member);
            let mut envelopes = Vec::new();
            for index in &indexes {
                let item = &mut self.state.pending_group_outbox[*index];
                item.in_flight = true;
                let mut envelope = item.envelope.clone();
                envelope.transition_id = Some(transition_id.clone());
                bundled_message_ids.insert(envelope.message_id.clone());
                envelopes.push(envelope);
            }
            if let Some(state) = self.state.group_states.get_mut(&group_id) {
                if let Some(pending) = state.pending_group_transition.as_mut() {
                    if pending.transition_id == transition_id {
                        pending.stage = PendingGroupTransitionStage::Submitting;
                    }
                }
            }
            envelopes.sort_by_key(|envelope| {
                if envelope.message_id == proof.commit_message_id {
                    0
                } else {
                    1
                }
            });
            effects.push(CoreEffect::AppendGroupTransition {
                append: AppendGroupTransitionRequest {
                    version: crate::model::CURRENT_MODEL_VERSION.to_string(),
                    group_id: group_id.clone(),
                    transition_id,
                    operation,
                    request_binding,
                    expected_previous_roster_version: proof.previous_roster_version,
                    expected_previous_commit_message_id: proof.previous_commit_message_id.clone(),
                    envelopes,
                    authorization_update: self.group_authorization_update(&group_id)?,
                    capability: self.group_capability(&group_id, role)?,
                },
            });
        }

        for index in 0..self.state.pending_group_outbox.len() {
            if self.state.pending_group_outbox[index].in_flight
                || self.state.pending_group_outbox[index].retries >= MAX_TRANSPORT_RETRIES
                || bundled_message_ids
                    .contains(&self.state.pending_group_outbox[index].envelope.message_id)
            {
                continue;
            }
            let item = self.state.pending_group_outbox[index].clone();
            if item.envelope.membership_proof.is_some() {
                continue;
            }
            // The server derives the effective role from its authorization manifest.
            // Keep the queued role only as a signing hint for operations such as a
            // self-leave, where local state is intentionally deactivated before the
            // request is dispatched; the queued signature itself is never reused.
            let role = self.local_group_role(&item.envelope.group_id)?;
            let fresh_capability = self.group_capability(&item.envelope.group_id, role)?;
            let authorization_update = item
                .envelope
                .membership_proof
                .as_ref()
                .map(|_| self.group_authorization_update(&item.envelope.group_id))
                .transpose()?;
            self.state.pending_group_outbox[index].in_flight = true;
            let carries_membership_transition = item
                .envelope
                .membership_proof
                .as_ref()
                .is_some_and(|proof| {
                    proof.commit_message_id == item.envelope.message_id
                        || (proof.control_message_id == item.envelope.message_id
                            && proof.previous_commit_message_id.as_ref()
                                == Some(&proof.commit_message_id))
                });
            let expected_previous_roster_version = carries_membership_transition
                .then(|| {
                    item.envelope
                        .membership_proof
                        .as_ref()
                        .map(|proof| proof.previous_roster_version)
                })
                .flatten();
            let expected_previous_commit_message_id = carries_membership_transition
                .then(|| {
                    item.envelope
                        .membership_proof
                        .as_ref()
                        .and_then(|proof| proof.previous_commit_message_id.clone())
                })
                .flatten();
            effects.push(CoreEffect::AppendGroupEnvelope {
                append: AppendGroupEnvelopeRequest {
                    version: crate::model::CURRENT_MODEL_VERSION.to_string(),
                    group_id: item.envelope.group_id.clone(),
                    envelope: item.envelope,
                    capability: fresh_capability,
                    authorization_update,
                    expected_previous_roster_version,
                    expected_previous_commit_message_id,
                },
            });
        }
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                messages_changed: !effects.is_empty(),
                ..CoreStateUpdate::default()
            },
            effects,
            view_model: None,
        })
    }

    pub(super) fn flush_group_seals(&mut self) -> CoreResult<CoreOutput> {
        let group_ids: Vec<String> = self.state.pending_group_seal.keys().cloned().collect();
        let mut effects = Vec::new();
        for group_id in group_ids {
            if self
                .state
                .pending_group_outbox
                .iter()
                .any(|item| item.envelope.group_id == group_id)
            {
                continue;
            }
            if let Some(request) = self.state.pending_group_seal.remove(&group_id) {
                effects.push(CoreEffect::SealGroupOutbox { seal: request });
            }
        }
        Ok(CoreOutput {
            state_update: CoreStateUpdate::default(),
            effects,
            view_model: None,
        })
    }

    pub(super) fn reset_pending_group_outbox_for_retry(&mut self, group_id: &str) -> Vec<String> {
        let mut reset_message_ids = Vec::new();
        for item in &mut self.state.pending_group_outbox {
            if item.envelope.group_id == group_id {
                item.in_flight = false;
                item.retries = 0;
                reset_message_ids.push(item.envelope.message_id.clone());
            }
        }
        reset_message_ids
    }

    pub(super) fn reset_pending_direct_transport_for_retry(
        &mut self,
        device_id: &str,
    ) -> Vec<PersistOp> {
        let mut persist_ops = Vec::new();
        for item in &mut self.state.pending_outbox {
            if !item.in_flight && item.retries >= MAX_TRANSPORT_RETRIES {
                item.retries = 0;
                persist_ops.push(PersistOp::SaveOutgoingEnvelope {
                    message_id: item.envelope.message_id.clone(),
                });
            }
        }
        if let Some(ack) = self.state.pending_acks.get_mut(device_id) {
            if !ack.in_flight && ack.retries >= MAX_TRANSPORT_RETRIES {
                ack.retries = 0;
                persist_ops.push(PersistOp::SavePendingAck {
                    device_id: device_id.to_string(),
                });
            }
        }
        for task in self.state.pending_blob_uploads.values_mut() {
            if !task.in_flight && task.retries >= MAX_TRANSPORT_RETRIES {
                task.retries = 0;
                persist_ops.push(PersistOp::SavePendingBlobTransfer {
                    task_id: task.task_id.clone(),
                });
            }
        }
        for task in self.state.pending_blob_downloads.values_mut() {
            if !task.in_flight && task.retries >= MAX_TRANSPORT_RETRIES {
                task.retries = 0;
                task.authorized_download = None;
                persist_ops.push(PersistOp::SavePendingBlobTransfer {
                    task_id: task.task_id.clone(),
                });
            }
        }
        persist_ops
    }

    pub(super) fn should_reset_pending_direct_transport(reason: Option<&str>) -> bool {
        reason.is_some_and(|reason| {
            matches!(
                reason,
                "startup"
                    | "manual"
                    | "manual_retry"
                    | "network_recovered"
                    | "runtime_upgraded"
                    | "retry_pending"
            )
        })
    }

    pub(super) fn flush_pending_acks(&mut self) -> CoreResult<CoreOutput> {
        let keys: Vec<String> = self.state.pending_acks.keys().cloned().collect();
        let mut effects = Vec::new();
        for device_id in keys {
            let Some(pending) = self.state.pending_acks.get(&device_id).cloned() else {
                continue;
            };
            if pending.in_flight || pending.retries >= MAX_TRANSPORT_RETRIES {
                continue;
            }
            let request = self.build_ack_request(&pending.ack)?;
            if let Some(entry) = self.state.pending_acks.get_mut(&device_id) {
                entry.in_flight = true;
            }
            effects.push(CoreEffect::ExecuteHttpRequest { request });
        }
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                checkpoints_changed: !effects.is_empty(),
                ..CoreStateUpdate::default()
            },
            effects,
            view_model: None,
        })
    }

    pub(super) fn flush_blob_uploads(&mut self) -> CoreResult<CoreOutput> {
        let auth = self.device_runtime_auth_requirement()?;
        let keys: Vec<String> = self.state.pending_blob_uploads.keys().cloned().collect();
        let mut effects = Vec::new();
        for task_id in keys {
            let Some(task) = self.state.pending_blob_uploads.get(&task_id).cloned() else {
                continue;
            };
            if task.in_flight || task.retries >= MAX_TRANSPORT_RETRIES {
                continue;
            }
            if task.blob_ciphertext_b64.is_none() {
                effects.push(CoreEffect::ReadAttachmentBytes {
                    read: ReadAttachmentBytesEffect {
                        task_id: task.task_id.clone(),
                        attachment_id: task.descriptor.attachment_id.clone(),
                    },
                });
            } else if let Some(prepared) = &task.prepared_upload {
                effects.push(CoreEffect::UploadBlob {
                    upload: BlobUploadRequest {
                        task_id: task.task_id.clone(),
                        blob_ciphertext_b64: task.blob_ciphertext_b64.clone().unwrap_or_default(),
                        upload_target: prepared.upload_target.clone(),
                        upload_headers: prepared.upload_headers.clone(),
                        blob_ref: prepared.blob_ref.clone(),
                    },
                });
            } else {
                let size_bytes = task
                    .blob_ciphertext_b64
                    .as_ref()
                    .and_then(|value| STANDARD.decode(value).ok())
                    .map(|bytes| bytes.len() as u64)
                    .unwrap_or(task.descriptor.size_bytes);
                effects.push(CoreEffect::PrepareBlobUpload {
                    upload: PrepareBlobUploadRequest {
                        task_id: task.task_id.clone(),
                        conversation_id: task.conversation_id.clone(),
                        group_id: task.group_id.clone(),
                        storage_scope: Some(if task.group_id.is_some() {
                            "group".into()
                        } else {
                            "direct".into()
                        }),
                        message_id: task.message_id.clone(),
                        mime_type: task.descriptor.mime_type.clone(),
                        size_bytes,
                        file_name: task.descriptor.file_name.clone(),
                        headers: BTreeMap::new(),
                        auth: Some(auth.clone()),
                    },
                });
            }
            if let Some(entry) = self.state.pending_blob_uploads.get_mut(&task_id) {
                entry.in_flight = true;
            }
        }
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                messages_changed: !effects.is_empty(),
                ..CoreStateUpdate::default()
            },
            effects,
            view_model: None,
        })
    }

    pub(super) fn flush_blob_downloads(&mut self) -> CoreResult<CoreOutput> {
        let keys: Vec<String> = self.state.pending_blob_downloads.keys().cloned().collect();
        let mut effects = Vec::new();
        for task_id in keys {
            let Some(task) = self.state.pending_blob_downloads.get(&task_id).cloned() else {
                continue;
            };
            if task.in_flight || task.retries >= MAX_TRANSPORT_RETRIES {
                continue;
            }
            if let Some(authorized) = task.authorized_download.clone() {
                effects.push(CoreEffect::DownloadBlob {
                    download: BlobDownloadRequest {
                        task_id: task.task_id.clone(),
                        blob_ref: authorized.blob_ref,
                        download_target: authorized.download_target,
                        download_headers: authorized.download_headers,
                    },
                });
            } else if let Some(grant) = task.payload_metadata.download_grant.clone() {
                effects.push(CoreEffect::AuthorizeBlobDownload {
                    authorize: AuthorizeBlobDownloadRequest {
                        task_id: task.task_id.clone(),
                        blob_ref: task.reference.clone(),
                        grant,
                    },
                });
            } else {
                effects.push(CoreEffect::DownloadBlob {
                    download: BlobDownloadRequest {
                        task_id: task.task_id.clone(),
                        blob_ref: task.reference.clone(),
                        download_target: task.reference.clone(),
                        download_headers: BTreeMap::new(),
                    },
                });
            }
            if let Some(entry) = self.state.pending_blob_downloads.get_mut(&task_id) {
                entry.in_flight = true;
            }
        }
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                messages_changed: !effects.is_empty(),
                ..CoreStateUpdate::default()
            },
            effects,
            view_model: None,
        })
    }

    pub(super) fn build_append_request(
        &mut self,
        item: &PendingOutboxItem,
    ) -> CoreResult<HttpRequestEffect> {
        let device_profile = self
            .direct_peer_contact_bundle(&item.peer_user_id)?
            .devices
            .iter()
            .find(|device| device.device_id == item.envelope.recipient_device_id)
            .ok_or_else(|| CoreError::invalid_input("recipient device profile is missing"))?
            .clone();
        let request_id = self.next_request_id(&format!("append:{}", item.envelope.message_id));
        self.state.pending_requests.insert(
            request_id.clone(),
            PendingRequest::AppendEnvelope {
                message_id: item.envelope.message_id.clone(),
                peer_user_id: item.peer_user_id.clone(),
            },
        );
        let sender_bundle_share_url = self
            .state
            .local_bundle
            .as_ref()
            .and_then(|bundle| bundle.identity_bundle_ref.clone());
        let body = AppendEnvelopeRequest {
            version: crate::model::CURRENT_MODEL_VERSION.to_string(),
            recipient_device_id: item.envelope.recipient_device_id.clone(),
            envelope: item.envelope.clone(),
            sender_bundle_share_url,
            sender_bundle_hash: None,
            sender_display_name: self.local_display_name(),
        };
        let mut headers = BTreeMap::new();
        headers.insert(
            "Authorization".into(),
            format!(
                "Bearer {}",
                device_profile.inbox_append_capability.signature
            ),
        );
        headers.insert(
            "X-Tapchat-Capability".into(),
            serde_json::to_string(&device_profile.inbox_append_capability).map_err(|error| {
                CoreError::invalid_input(format!("failed to encode append capability: {error}"))
            })?,
        );
        headers.insert("Content-Type".into(), "application/json".into());
        Ok(HttpRequestEffect {
            request_id,
            method: HttpMethod::Post,
            url: device_profile.inbox_append_capability.endpoint.clone(),
            headers,
            auth: None,
            body: Some(serde_json::to_string(&body).map_err(|error| {
                CoreError::invalid_input(format!("failed to encode append request: {error}"))
            })?),
        })
    }

    pub(super) fn build_ack_request(&mut self, ack: &Ack) -> CoreResult<HttpRequestEffect> {
        let deployment = self
            .state
            .deployment_bundle
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("deployment bundle is not initialized"))?;
        let inbox_http_endpoint = deployment.inbox_http_endpoint.clone();
        let request_id = self.next_request_id(&format!("ack:{}", ack.device_id));
        self.state.pending_requests.insert(
            request_id.clone(),
            PendingRequest::Ack {
                device_id: ack.device_id.clone(),
                ack_seq: ack.ack_seq,
            },
        );
        let auth = self.device_runtime_auth_requirement()?;
        let mut headers = BTreeMap::new();
        headers.insert("Content-Type".into(), "application/json".into());
        let request = AckRequest { ack: ack.clone() };
        Ok(HttpRequestEffect {
            request_id,
            method: HttpMethod::Post,
            url: format!(
                "{}/v1/inbox/{}/ack",
                inbox_http_endpoint.trim_end_matches('/'),
                ack.device_id
            ),
            headers,
            auth: Some(auth),
            body: Some(serde_json::to_string(&request).map_err(|error| {
                CoreError::invalid_input(format!("failed to encode ack request: {error}"))
            })?),
        })
    }

    pub(super) fn issue_fetch(
        &mut self,
        device_id: String,
        decision: SyncDecision,
    ) -> CoreResult<CoreOutput> {
        let deployment = self
            .state
            .deployment_bundle
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("deployment bundle is not initialized"))?;
        let inbox_http_endpoint = deployment.inbox_http_endpoint.clone();
        let auth = self.device_runtime_auth_requirement()?;
        let limit = decision
            .to_seq
            .saturating_sub(decision.from_seq)
            .saturating_add(1)
            .max(1);
        let request_id = self.next_request_id(&format!("fetch:{device_id}"));
        self.state.pending_requests.insert(
            request_id.clone(),
            PendingRequest::FetchMessages {
                device_id: device_id.clone(),
                from_seq: decision.from_seq,
                limit,
            },
        );
        let fetch = FetchMessagesRequest {
            device_id: device_id.clone(),
            from_seq: decision.from_seq,
            limit,
        };
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                checkpoints_changed: true,
                system_statuses_changed: vec![SystemStatus::SyncInProgress],
                ..CoreStateUpdate::default()
            },
            effects: vec![CoreEffect::ExecuteHttpRequest {
                request: HttpRequestEffect {
                    request_id,
                    method: HttpMethod::Get,
                    url: format!(
                        "{}/v1/inbox/{}/messages?fromSeq={}&limit={}",
                        inbox_http_endpoint.trim_end_matches('/'),
                        fetch.device_id,
                        fetch.from_seq,
                        fetch.limit
                    ),
                    headers: BTreeMap::new(),
                    auth: Some(auth),
                    body: None,
                },
            }],
            view_model: None,
        })
    }

    pub(super) fn handle_http_response(
        &mut self,
        request_id: String,
        status: u16,
        body: Option<String>,
    ) -> CoreResult<CoreOutput> {
        let request = self
            .state
            .pending_requests
            .remove(&request_id)
            .ok_or_else(|| CoreError::invalid_input("unknown request_id"))?;
        if !(200..300).contains(&status) {
            return self.handle_unsuccessful_request(request, status, body);
        }
        match request {
            PendingRequest::GetHead { device_id } => {
                let head: GetHeadResult = serde_json::from_str(
                    body.as_deref().unwrap_or("{\"head_seq\":0}"),
                )
                .map_err(|error| {
                    CoreError::invalid_input(format!("failed to decode head response: {error}"))
                })?;
                let sync_state = self
                    .state
                    .sync_states
                    .entry(device_id.clone())
                    .or_insert_with(|| SyncEngine::new_device_state(&device_id));
                SyncEngine::register_head(sync_state, head.head_seq);
                if let Some(decision) = SyncEngine::next_fetch(sync_state) {
                    self.issue_fetch(device_id, decision)
                } else {
                    Ok(CoreOutput::default())
                }
            }
            PendingRequest::FetchMessages { device_id, .. } => {
                let response: FetchMessagesResult = serde_json::from_str(
                    body.as_deref().unwrap_or("{\"to_seq\":0,\"records\":[]}"),
                )
                .map_err(|error| {
                    CoreError::invalid_input(format!("failed to decode fetch response: {error}"))
                })?;
                self.handle_inbox_records(device_id, response.records, response.to_seq)
            }
            PendingRequest::AppendEnvelope {
                message_id,
                peer_user_id,
            } => {
                let result: AppendEnvelopeResult = serde_json::from_str(
                    body.as_deref().unwrap_or("{\"accepted\":false,\"seq\":0}"),
                )
                .map_err(|error| {
                    CoreError::invalid_input(format!("failed to decode append response: {error}"))
                })?;
                if !result.accepted {
                    return Err(CoreError::temporary_failure(
                        "append response was not accepted",
                    ));
                }
                let append_delivery = self.handle_append_delivery_result(&message_id, &result);
                self.state
                    .pending_outbox
                    .retain(|item| item.envelope.message_id != message_id);
                let mut persist_ops = vec![PersistOp::DeleteOutgoingEnvelope {
                    message_id: message_id.clone(),
                }];
                if let Some(conversation_id) = append_delivery.saved_conversation_id {
                    persist_ops.push(PersistOp::SaveConversation { conversation_id });
                }
                if self.state.contacts.contains_key(&peer_user_id) {
                    persist_ops.push(PersistOp::SaveContact {
                        user_id: peer_user_id,
                    });
                }
                Ok(merge_outputs(
                    merge_outputs(
                        append_delivery.output,
                        CoreOutput {
                            state_update: CoreStateUpdate::default(),
                            effects: vec![persist_effect(&self.state, persist_ops)],
                            view_model: None,
                        },
                    ),
                    self.flush_pending_transport()?,
                ))
            }
            PendingRequest::Ack { device_id, .. } => {
                let result: AckResult = serde_json::from_str(
                    body.as_deref()
                        .unwrap_or("{\"accepted\":false,\"ack_seq\":0}"),
                )
                .map_err(|error| {
                    CoreError::invalid_input(format!("failed to decode ack response: {error}"))
                })?;
                if !result.accepted {
                    return Err(CoreError::temporary_failure(
                        "ack response was not accepted",
                    ));
                }
                self.state.pending_acks.remove(&device_id);
                Ok(merge_outputs(
                    CoreOutput {
                        state_update: CoreStateUpdate {
                            checkpoints_changed: true,
                            ..CoreStateUpdate::default()
                        },
                        effects: vec![persist_effect(
                            &self.state,
                            vec![
                                PersistOp::DeletePendingAck {
                                    device_id: device_id.clone(),
                                },
                                PersistOp::SaveSyncState {
                                    device_id: device_id.clone(),
                                },
                            ],
                        )],
                        view_model: None,
                    },
                    self.flush_pending_transport()?,
                ))
            }
            PendingRequest::AppendGroupEnvelope {
                group_id,
                message_id,
            } => {
                let body_str = body.as_deref().unwrap_or("");
                // Detect server-side optimistic-concurrency rejection. When
                // the server returns HTTP 409 roster_version_conflict another
                // writer already advanced the membership chain. The local
                // manifest has been updated by the concurrent commit, so the
                // stale envelope (with its old membership proof) is removed
                // and the caller must re-invoke the high-level command to
                // rebuild the proof from the current manifest state.
                if let Ok(error_obj) = serde_json::from_str::<serde_json::Value>(body_str) {
                    if error_obj
                        .get("error")
                        .and_then(|v| v.as_str())
                        .is_some_and(|code| code == "roster_version_conflict")
                    {
                        self.state
                            .pending_group_outbox
                            .retain(|item| item.envelope.message_id != message_id);
                        return Ok(merge_outputs(
                            CoreOutput {
                                state_update: CoreStateUpdate {
                                    system_statuses_changed: vec![
                                        SystemStatus::TemporaryNetworkFailure,
                                    ],
                                    ..CoreStateUpdate::default()
                                },
                                effects: vec![CoreEffect::EmitUserNotification {
                                    notification: UserNotificationEffect {
                                        status: SystemStatus::TemporaryNetworkFailure,
                                        message: format!(
                                            "group membership operation for {} conflicted; sync and retry",
                                            group_id
                                        ),
                                    },
                                }],
                                view_model: None,
                            },
                            self.sync_group_outbox(group_id.clone(), None)?,
                        ));
                    }
                }
                let result: AppendGroupEnvelopeResult =
                    serde_json::from_str(body_str).map_err(|error| {
                        CoreError::invalid_input(format!(
                            "failed to decode group append response: {error}"
                        ))
                    })?;
                if !result.accepted {
                    return Err(CoreError::temporary_failure(
                        "group append response was not accepted",
                    ));
                }
                self.handle_group_envelope_appended(group_id, message_id, result.seq)
            }
            PendingRequest::FetchGroupOutbox { group_id, .. } => {
                let response: FetchGroupOutboxResult = serde_json::from_str(
                    body.as_deref().unwrap_or("{\"to_seq\":0,\"records\":[]}"),
                )
                .map_err(|error| {
                    CoreError::invalid_input(format!(
                        "failed to decode group fetch response: {error}"
                    ))
                })?;
                self.handle_group_outbox_records(group_id, response.records, response.to_seq)
            }
            PendingRequest::PutWelcomePickup { .. } => {
                let result: PutWelcomePickupResult =
                    serde_json::from_str(body.as_deref().unwrap_or("{\"accepted\":false}"))
                        .map_err(|error| {
                            CoreError::invalid_input(format!(
                                "failed to decode welcome pickup put response: {error}"
                            ))
                        })?;
                if !result.accepted {
                    return Err(CoreError::temporary_failure(
                        "welcome pickup put response was not accepted",
                    ));
                }
                Ok(CoreOutput::default())
            }
            PendingRequest::FetchWelcomePickup {
                group_id: _,
                device_id: _,
            } => {
                let result: FetchWelcomePickupResult =
                    serde_json::from_str(body.as_deref().unwrap_or("{\"welcome_b64\":\"\"}"))
                        .map_err(|error| {
                            CoreError::invalid_input(format!(
                                "failed to decode welcome pickup response: {error}"
                            ))
                        })?;
                Err(CoreError::invalid_state(format!(
                    "welcome pickup HTTP response cannot be applied without descriptor: {}",
                    result.welcome_b64.len()
                )))
            }
            PendingRequest::CreateGroupInvite {
                group_id,
                invite_id,
            } => Err(CoreError::invalid_state(format!(
                "group invite HTTP response cannot be applied without typed transport event: {group_id}/{invite_id}"
            ))),
            PendingRequest::SubmitGroupJoinRequest {
                group_id,
                request_id,
                ..
            } => Err(CoreError::invalid_state(format!(
                "group join HTTP response cannot be applied without typed transport event: {group_id}/{request_id}"
            ))),
            PendingRequest::DecideGroupJoinRequest {
                group_id,
                request_id,
            } => Err(CoreError::invalid_state(format!(
                "group join decision HTTP response cannot be applied without typed transport event: {group_id}/{request_id}"
            ))),
        }
    }

    pub(super) fn sync_retry_timer(&mut self, device_id: &str) -> TimerEffect {
        let sync_state = self
            .state
            .sync_states
            .entry(device_id.to_string())
            .or_insert_with(|| SyncEngine::new_device_state(device_id));
        let attempt = SyncEngine::note_sync_failure(sync_state);
        let timer_id = format!("sync:{device_id}");
        TimerEffect {
            delay_ms: retry_delay_ms(&timer_id, attempt),
            timer_id,
        }
    }

    pub(super) fn handle_http_failure(
        &mut self,
        request_id: String,
        retryable: bool,
        detail: Option<String>,
    ) -> CoreResult<CoreOutput> {
        let request = self
            .state
            .pending_requests
            .remove(&request_id)
            .ok_or_else(|| CoreError::invalid_input("unknown request_id"))?;
        match request {
            PendingRequest::AppendEnvelope { message_id, .. } => {
                if let Some(item) = self
                    .state
                    .pending_outbox
                    .iter_mut()
                    .find(|item| item.envelope.message_id == message_id)
                {
                    item.in_flight = false;
                    item.retries = item.retries.saturating_add(1);
                    if retryable && item.retries < MAX_TRANSPORT_RETRIES {
                        let timer_id = format!("retry_append:{message_id}");
                        return Ok(CoreOutput {
                            state_update: CoreStateUpdate {
                                system_statuses_changed: vec![
                                    SystemStatus::TemporaryNetworkFailure,
                                ],
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
                            message: detail.unwrap_or_else(|| {
                                format!("append request failed for {message_id}")
                            }),
                        },
                    }],
                    view_model: None,
                })
            }
            PendingRequest::Ack { device_id, .. } => {
                if let Some(ack) = self.state.pending_acks.get_mut(&device_id) {
                    ack.in_flight = false;
                    ack.retries = ack.retries.saturating_add(1);
                    if retryable && ack.retries < MAX_TRANSPORT_RETRIES {
                        let timer_id = format!("retry_ack:{device_id}");
                        return Ok(CoreOutput {
                            state_update: CoreStateUpdate {
                                system_statuses_changed: vec![
                                    SystemStatus::TemporaryNetworkFailure,
                                ],
                                ..CoreStateUpdate::default()
                            },
                            effects: vec![CoreEffect::ScheduleTimer {
                                timer: TimerEffect {
                                    delay_ms: retry_delay_ms(&timer_id, u32::from(ack.retries)),
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
                                .unwrap_or_else(|| format!("ack request failed for {device_id}")),
                        },
                    }],
                    view_model: None,
                })
            }
            PendingRequest::GetHead { device_id }
            | PendingRequest::FetchMessages { device_id, .. } => Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: if retryable {
                    vec![CoreEffect::ScheduleTimer {
                        timer: self.sync_retry_timer(&device_id),
                    }]
                } else {
                    vec![CoreEffect::EmitUserNotification {
                        notification: UserNotificationEffect {
                            status: SystemStatus::TemporaryNetworkFailure,
                            message: detail
                                .unwrap_or_else(|| format!("sync request failed for {device_id}")),
                        },
                    }]
                },
                view_model: None,
            }),
            PendingRequest::AppendGroupEnvelope {
                group_id,
                message_id,
            } => {
                self.handle_group_append_failed(group_id, message_id, retryable, None, None, detail)
            }
            PendingRequest::FetchGroupOutbox { group_id, .. } => Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect {
                        status: SystemStatus::TemporaryNetworkFailure,
                        message: detail
                            .unwrap_or_else(|| format!("group outbox fetch failed for {group_id}")),
                    },
                }],
                view_model: None,
            }),
            PendingRequest::PutWelcomePickup {
                group_id,
                device_id,
            }
            | PendingRequest::FetchWelcomePickup {
                group_id,
                device_id,
            } => Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect {
                        status: SystemStatus::TemporaryNetworkFailure,
                        message: detail.unwrap_or_else(|| {
                            format!("welcome pickup request failed for {group_id}/{device_id}")
                        }),
                    },
                }],
                view_model: None,
            }),
            PendingRequest::CreateGroupInvite {
                group_id,
                invite_id,
            } => Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect {
                        status: SystemStatus::TemporaryNetworkFailure,
                        message: detail.unwrap_or_else(|| {
                            format!("group invite create failed for {group_id}/{invite_id}")
                        }),
                    },
                }],
                view_model: None,
            }),
            PendingRequest::SubmitGroupJoinRequest {
                group_id,
                request_id,
                ..
            }
            | PendingRequest::DecideGroupJoinRequest {
                group_id,
                request_id,
            } => Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect {
                        status: SystemStatus::TemporaryNetworkFailure,
                        message: detail.unwrap_or_else(|| {
                            format!("group join request failed for {group_id}/{request_id}")
                        }),
                    },
                }],
                view_model: None,
            }),
        }
    }

    pub(super) fn handle_blob_upload_prepared(
        &mut self,
        task_id: String,
        result: PrepareBlobUploadResult,
    ) -> CoreResult<CoreOutput> {
        let (conversation_id, payload_metadata) = {
            let task = self
                .state
                .pending_blob_uploads
                .get(&task_id)
                .ok_or_else(|| CoreError::invalid_input("unknown blob upload task"))?;
            (task.conversation_id.clone(), task.payload_metadata.clone())
        };
        let mut payload_metadata = payload_metadata;
        let mut metadata_ciphertext = None;
        if let Some(download_grant) = result.download_grant.clone() {
            if let Some(mut metadata) = payload_metadata.take() {
                metadata.download_grant = Some(download_grant);
                let metadata_json = serde_json::to_string(&metadata).map_err(|error| {
                    CoreError::invalid_input(format!(
                        "failed to encode attachment payload metadata: {error}"
                    ))
                })?;
                let ciphertext = self
                    .state
                    .mls_adapter
                    .as_mut()
                    .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
                    .encrypt_application(&conversation_id, metadata_json.as_bytes())?
                    .payload_b64;
                payload_metadata = Some(metadata);
                metadata_ciphertext = Some(ciphertext);
            }
        }

        let task = self
            .state
            .pending_blob_uploads
            .get_mut(&task_id)
            .ok_or_else(|| CoreError::invalid_input("unknown blob upload task"))?;
        if let Some(metadata) = payload_metadata {
            task.payload_metadata = Some(metadata);
        }
        if let Some(ciphertext) = metadata_ciphertext {
            task.metadata_ciphertext = Some(ciphertext);
        }
        task.prepared_upload = Some(result);
        task.in_flight = false;
        Ok(merge_outputs(
            CoreOutput {
                state_update: CoreStateUpdate::default(),
                effects: vec![persist_effect(
                    &self.state,
                    vec![PersistOp::SavePendingBlobTransfer {
                        task_id: task_id.clone(),
                    }],
                )],
                view_model: None,
            },
            self.flush_pending_transport()?,
        ))
    }

    pub(super) fn handle_blob_download_authorized(
        &mut self,
        task_id: String,
        result: AuthorizeBlobDownloadResult,
    ) -> CoreResult<CoreOutput> {
        let task = self
            .state
            .pending_blob_downloads
            .get_mut(&task_id)
            .ok_or_else(|| CoreError::invalid_input("unknown blob download task"))?;
        if result.blob_ref != task.reference {
            return Err(CoreError::invalid_input(
                "authorized blob_ref does not match pending download reference",
            ));
        }
        task.authorized_download = Some(result);
        task.in_flight = false;
        self.flush_pending_transport()
    }

    pub(super) fn handle_blob_uploaded(&mut self, task_id: String) -> CoreResult<CoreOutput> {
        let task = self
            .state
            .pending_blob_uploads
            .remove(&task_id)
            .ok_or_else(|| CoreError::invalid_input("unknown blob upload task"))?;
        let prepared = task.prepared_upload.ok_or_else(|| {
            CoreError::invalid_state("blob upload completed before upload target was prepared")
        })?;
        let payload_metadata = task.payload_metadata.clone().ok_or_else(|| {
            CoreError::invalid_state("blob upload completed before payload metadata was prepared")
        })?;
        let final_ref = if payload_metadata.download_grant.is_some() {
            prepared.blob_ref.clone()
        } else {
            prepared.download_target.clone().ok_or_else(|| {
                CoreError::invalid_state("blob upload result is missing download grant")
            })?
        };
        let payload_metadata_json = serde_json::to_string(&payload_metadata).map_err(|error| {
            CoreError::invalid_input(format!(
                "failed to encode attachment payload metadata: {error}"
            ))
        })?;
        let metadata_ciphertext = task.metadata_ciphertext.clone().ok_or_else(|| {
            CoreError::invalid_state(
                "blob upload completed before metadata ciphertext was prepared",
            )
        })?;
        let storage_ref = StorageRef {
            kind: "attachment".into(),
            object_ref: final_ref.clone(),
            size_bytes: task
                .blob_ciphertext_b64
                .as_ref()
                .and_then(|value| STANDARD.decode(value).ok())
                .map(|bytes| bytes.len() as u64)
                .or(Some(payload_metadata.size_bytes))
                .unwrap_or(task.descriptor.size_bytes),
            mime_type: payload_metadata.mime_type.clone(),
            file_name: payload_metadata
                .file_name
                .clone()
                .or_else(|| task.descriptor.file_name.clone()),
            expires_at: payload_metadata
                .download_grant
                .as_ref()
                .map(|grant| grant.expires_at)
                .or(prepared.expires_at),
        };
        if let Some(group_id) = task.group_id {
            let conversation_id = task.conversation_id.clone();
            self.ensure_group_ready_for_send(&conversation_id)?;
            let capability = self.group_capability(&group_id, self.local_group_role(&group_id)?)?;
            let mut envelope = self.build_group_envelope(
                &group_id,
                &conversation_id,
                GroupMessageType::MlsApplication,
                GroupEnvelopeVisibility::Visible,
                metadata_ciphertext,
            )?;
            envelope.storage_refs.push(storage_ref);
            self.enqueue_group_envelope(envelope.clone(), capability, Some(payload_metadata_json));
            Ok(merge_outputs(
                CoreOutput {
                    state_update: CoreStateUpdate::default(),
                    effects: vec![persist_effect(
                        &self.state,
                        vec![
                            PersistOp::DeletePendingBlobTransfer { task_id },
                            PersistOp::SaveOutgoingGroupEnvelope {
                                message_id: envelope.message_id,
                            },
                        ],
                    )],
                    view_model: None,
                },
                self.flush_pending_transport()?,
            ))
        } else {
            let peer_user_id = self.peer_user_for_conversation(&task.conversation_id)?;
            let recipients = self.recipient_device_ids(&task.conversation_id)?;
            let mut envelopes = Vec::new();
            for recipient in recipients {
                let mut envelope = self.build_envelope(
                    &task.conversation_id,
                    &recipient,
                    MessageType::MlsApplication,
                    metadata_ciphertext.clone(),
                )?;
                envelope.storage_refs.push(storage_ref.clone());
                envelopes.push(envelope);
            }
            self.enqueue_envelopes_with_plaintext(
                peer_user_id,
                envelopes,
                payload_metadata_json,
                None,
            );
            Ok(merge_outputs(
                CoreOutput {
                    state_update: CoreStateUpdate::default(),
                    effects: vec![persist_effect(
                        &self.state,
                        vec![PersistOp::DeletePendingBlobTransfer { task_id }],
                    )],
                    view_model: None,
                },
                self.flush_pending_transport()?,
            ))
        }
    }

    pub(super) fn handle_attachment_bytes_loaded(
        &mut self,
        task_id: String,
        plaintext_b64: String,
    ) -> CoreResult<CoreOutput> {
        let plaintext = STANDARD.decode(&plaintext_b64).map_err(|error| {
            CoreError::invalid_input(format!(
                "attachment plaintext bytes were not valid base64: {error}"
            ))
        })?;
        let (conversation_id, mime_type, size_bytes, file_name) = {
            let task = self
                .state
                .pending_blob_uploads
                .get(&task_id)
                .ok_or_else(|| CoreError::invalid_input("pending blob upload task not found"))?;
            (
                task.conversation_id.clone(),
                task.descriptor.mime_type.clone(),
                task.descriptor.size_bytes,
                task.descriptor.file_name.clone(),
            )
        };
        if plaintext.len() as u64 != size_bytes {
            return Err(CoreError::invalid_input(
                "attachment plaintext size did not match descriptor size",
            ));
        }
        let encrypted = encrypt_blob(&plaintext)?;
        let payload_metadata = AttachmentPayloadMetadata {
            mime_type,
            size_bytes,
            file_name,
            encryption: encrypted.metadata,
            download_grant: None,
        };
        let metadata_json = serde_json::to_string(&payload_metadata).map_err(|error| {
            CoreError::invalid_input(format!(
                "failed to encode attachment payload metadata: {error}"
            ))
        })?;
        let metadata_ciphertext = self
            .state
            .mls_adapter
            .as_mut()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .encrypt_application(&conversation_id, metadata_json.as_bytes())?
            .payload_b64;
        let task = self
            .state
            .pending_blob_uploads
            .get_mut(&task_id)
            .ok_or_else(|| CoreError::invalid_input("pending blob upload task not found"))?;
        task.blob_ciphertext_b64 = Some(STANDARD.encode(encrypted.ciphertext));
        task.payload_metadata = Some(payload_metadata);
        task.metadata_ciphertext = Some(metadata_ciphertext);
        task.in_flight = false;
        Ok(merge_outputs(
            CoreOutput {
                state_update: CoreStateUpdate::default(),
                effects: vec![persist_effect(
                    &self.state,
                    vec![PersistOp::SavePendingBlobTransfer {
                        task_id: task_id.clone(),
                    }],
                )],
                view_model: None,
            },
            self.flush_pending_transport()?,
        ))
    }

    pub(super) fn handle_blob_downloaded(
        &mut self,
        task_id: String,
        blob_ciphertext: Option<String>,
    ) -> CoreResult<CoreOutput> {
        let mut effects = Vec::new();
        if let Some(task) = self.state.pending_blob_downloads.remove(&task_id) {
            if let Some(blob_ciphertext) = blob_ciphertext {
                let ciphertext = STANDARD.decode(&blob_ciphertext).map_err(|error| {
                    CoreError::invalid_input(format!(
                        "downloaded blob ciphertext was not valid base64: {error}"
                    ))
                })?;
                let plaintext = decrypt_blob(&ciphertext, &task.payload_metadata.encryption)?;
                effects.push(CoreEffect::WriteDownloadedAttachment {
                    write: WriteDownloadedAttachmentEffect {
                        task_id: task.task_id.clone(),
                        destination_id: task.destination_id.clone(),
                        plaintext_b64: STANDARD.encode(&plaintext),
                    },
                });
                if let Some(state) = self.state.conversations.get_mut(&task.conversation_id) {
                    if let Some(message) = state
                        .messages
                        .iter_mut()
                        .find(|message| message.message_id == task.message_id)
                    {
                        message.downloaded_blob_b64 = Some(blob_ciphertext);
                    }
                }
            }
        }
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                messages_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: {
                let mut effects = effects;
                effects.push(persist_effect(
                    &self.state,
                    vec![PersistOp::DeletePendingBlobTransfer { task_id }],
                ));
                effects
            },
            view_model: None,
        })
    }

    pub(super) fn handle_blob_transfer_failed(
        &mut self,
        task_id: String,
        retryable: bool,
        detail: Option<String>,
    ) -> CoreResult<CoreOutput> {
        if let Some(task) = self.state.pending_blob_uploads.get_mut(&task_id) {
            task.in_flight = false;
            task.retries = task.retries.saturating_add(1);
            if retryable && task.retries < MAX_TRANSPORT_RETRIES {
                let timer_id = format!("retry_blob_upload:{task_id}");
                return Ok(CoreOutput {
                    state_update: CoreStateUpdate {
                        system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                        ..CoreStateUpdate::default()
                    },
                    effects: vec![CoreEffect::ScheduleTimer {
                        timer: TimerEffect {
                            delay_ms: retry_delay_ms(&timer_id, u32::from(task.retries)),
                            timer_id,
                        },
                    }],
                    view_model: None,
                });
            }
            self.state.pending_blob_uploads.remove(&task_id);
            return Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::AttachmentUploadFailed],
                    ..CoreStateUpdate::default()
                },
                effects: vec![
                    CoreEffect::EmitUserNotification {
                        notification: UserNotificationEffect {
                            status: SystemStatus::AttachmentUploadFailed,
                            message: detail.unwrap_or_else(|| "attachment upload failed".into()),
                        },
                    },
                    persist_effect(
                        &self.state,
                        vec![PersistOp::DeletePendingBlobTransfer {
                            task_id: task_id.clone(),
                        }],
                    ),
                ],
                view_model: None,
            });
        }
        if let Some(task) = self.state.pending_blob_downloads.get_mut(&task_id) {
            task.in_flight = false;
            task.authorized_download = None;
            task.retries = task.retries.saturating_add(1);
            if retryable && task.retries < MAX_TRANSPORT_RETRIES {
                let timer_id = format!("retry_blob_download:{task_id}");
                return Ok(CoreOutput {
                    state_update: CoreStateUpdate {
                        system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                        ..CoreStateUpdate::default()
                    },
                    effects: vec![CoreEffect::ScheduleTimer {
                        timer: TimerEffect {
                            delay_ms: retry_delay_ms(&timer_id, u32::from(task.retries)),
                            timer_id,
                        },
                    }],
                    view_model: None,
                });
            }
            log::warn!("attachment download failed");
            self.state.pending_blob_downloads.remove(&task_id);
            return Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: vec![
                    CoreEffect::EmitUserNotification {
                        notification: UserNotificationEffect {
                            status: SystemStatus::TemporaryNetworkFailure,
                            message: "attachment download failed".into(),
                        },
                    },
                    persist_effect(
                        &self.state,
                        vec![PersistOp::DeletePendingBlobTransfer {
                            task_id: task_id.clone(),
                        }],
                    ),
                ],
                view_model: None,
            });
        }
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                ..CoreStateUpdate::default()
            },
            effects: vec![],
            view_model: None,
        })
    }

    pub(super) fn handle_inbox_records(
        &mut self,
        device_id: String,
        records: Vec<InboxRecord>,
        to_seq: u64,
    ) -> CoreResult<CoreOutput> {
        self.handle_inbox_records_internal(
            device_id,
            records,
            to_seq,
            true,
            InboxRecordSource::Fetch,
        )
    }

    pub(super) fn handle_inbox_records_internal(
        &mut self,
        device_id: String,
        records: Vec<InboxRecord>,
        to_seq: u64,
        allow_pending_replay: bool,
        source: InboxRecordSource,
    ) -> CoreResult<CoreOutput> {
        // Validate the complete transport batch before touching conversation,
        // MLS, seen-message, or checkpoint state. A malformed batch must be
        // safely retryable and must never consume a delivery.
        let mut previous_seq = None;
        let mut batch_message_ids = BTreeSet::new();
        for record in &records {
            record.validate()?;
            if record.recipient_device_id != device_id {
                return Err(CoreError::invalid_input(
                    "fetched inbox record recipient_device_id does not match target device",
                ));
            }
            if previous_seq.is_some_and(|seq| record.seq <= seq) {
                return Err(CoreError::invalid_input(
                    "fetched inbox records must have strictly increasing seq values",
                ));
            }
            if !batch_message_ids.insert(record.message_id.clone()) {
                return Err(CoreError::invalid_input(
                    "fetched inbox records must not repeat message_id",
                ));
            }
            previous_seq = Some(record.seq);
        }
        if previous_seq.is_some_and(|seq| seq > to_seq) {
            return Err(CoreError::invalid_input(
                "fetched inbox to_seq must cover every returned record",
            ));
        }

        let mut pending_recovery_conversations = BTreeSet::new();
        let mut touched_conversation_ids = BTreeSet::new();
        let mut touched_mls_conversation_ids = BTreeSet::new();
        let mut touched_recovery_context_ids = BTreeSet::new();
        let touched_sync_device_ids = BTreeSet::from([device_id.clone()]);
        let mut touched_pending_ack_device_ids = BTreeSet::new();
        let mut fresh_records = match source {
            InboxRecordSource::Fetch => self
                .state
                .sync_states
                .get(&device_id)
                .map(|sync_state| SyncEngine::select_fresh(sync_state, &records))
                .unwrap_or(records),
            InboxRecordSource::PendingReplay => records,
        };
        fresh_records.sort_by_key(|record| record.seq);
        let mut processed_records = Vec::new();
        let mut output = CoreOutput {
            state_update: CoreStateUpdate {
                checkpoints_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![],
            view_model: Some(CoreViewModel::default()),
        };
        let local_user_id = self
            .state
            .local_identity
            .as_ref()
            .map(|identity| identity.user_identity.user_id.clone())
            .unwrap_or_else(|| "user:local".into());
        let mut contiguous_ack = self
            .state
            .sync_states
            .get(&device_id)
            .map(|state| state.checkpoint.last_acked_seq)
            .unwrap_or(0);
        let mut deferred_ackable_seqs = BTreeSet::new();
        for record in fresh_records {
            if record.envelope.message_type == MessageType::ControlContactRemoved {
                if self.should_ignore_idempotent_contact_removed_record(&local_user_id, &record) {
                    log::info!(
                        "handle_inbox_records: acking and ignoring idempotent ControlContactRemoved for archived relationship conversation_id={} sender_user_id={} message_id={}",
                        record.envelope.conversation_id,
                        record.envelope.sender_user_id,
                        record.message_id
                    );
                    {
                        let sync_state = self
                            .state
                            .sync_states
                            .entry(device_id.clone())
                            .or_insert_with(|| SyncEngine::new_device_state(&device_id));
                        SyncEngine::clear_pending_retry(sync_state, record.seq);
                    }
                    advance_contiguous_ack(
                        &mut contiguous_ack,
                        &mut deferred_ackable_seqs,
                        record.seq,
                    );
                    processed_records.push(record);
                    continue;
                }
                output = merge_outputs(
                    output,
                    self.handle_contact_removed_record(&local_user_id, &device_id, &record)?,
                );
                {
                    let sync_state = self
                        .state
                        .sync_states
                        .entry(device_id.clone())
                        .or_insert_with(|| SyncEngine::new_device_state(&device_id));
                    SyncEngine::clear_pending_retry(sync_state, record.seq);
                }
                advance_contiguous_ack(&mut contiguous_ack, &mut deferred_ackable_seqs, record.seq);
                processed_records.push(record);
                continue;
            }
            if record.envelope.message_type == MessageType::ControlContactAccepted {
                output = merge_outputs(
                    output,
                    self.handle_contact_accepted_record(&local_user_id, &record)?,
                );
                {
                    let sync_state = self
                        .state
                        .sync_states
                        .entry(device_id.clone())
                        .or_insert_with(|| SyncEngine::new_device_state(&device_id));
                    SyncEngine::clear_pending_retry(sync_state, record.seq);
                }
                advance_contiguous_ack(&mut contiguous_ack, &mut deferred_ackable_seqs, record.seq);
                processed_records.push(record);
                continue;
            }
            if self.should_ignore_closed_relationship_record(&local_user_id, &record) {
                log::info!(
                    "handle_inbox_records: acking and ignoring {:?} for closed relationship conversation_id={} sender_user_id={} message_id={}",
                    record.envelope.message_type,
                    record.envelope.conversation_id,
                    record.envelope.sender_user_id,
                    record.message_id
                );
                {
                    let sync_state = self
                        .state
                        .sync_states
                        .entry(device_id.clone())
                        .or_insert_with(|| SyncEngine::new_device_state(&device_id));
                    SyncEngine::clear_pending_retry(sync_state, record.seq);
                }
                advance_contiguous_ack(&mut contiguous_ack, &mut deferred_ackable_seqs, record.seq);
                processed_records.push(record);
                continue;
            }
            self.ensure_local_conversation_for_record(&device_id, &local_user_id, &record);
            let conversation_id = record.envelope.conversation_id.clone();
            touched_conversation_ids.insert(conversation_id.clone());
            if record.envelope.message_type == MessageType::MlsApplication {
                let duplicate_delivery = self
                    .state
                    .conversations
                    .get(&conversation_id)
                    .is_some_and(|state| {
                        state
                            .messages
                            .iter()
                            .any(|message| message.message_id == record.message_id)
                    });
                let mut ackable = duplicate_delivery;
                if !duplicate_delivery {
                    match self
                        .state
                        .mls_adapter
                        .as_mut()
                        .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
                        .ingest_message(
                            &conversation_id,
                            &record.envelope.sender_device_id,
                            record.envelope.message_type,
                            record
                                .envelope
                                .inline_ciphertext
                                .as_deref()
                                .unwrap_or_default(),
                        )? {
                        IngestResult::AppliedApplication(application) => {
                            log::info!(
                                "handle_inbox_records: AppliedApplication for message {}, plaintext len={}",
                                redact_id("msg", &record.message_id),
                                application.plaintext.len()
                            );
                            match self.evaluate_direct_application_plaintext(
                                &record,
                                &local_user_id,
                                &device_id,
                                application,
                            ) {
                                ApplicationPlaintextDecision::Accepted {
                                    plaintext,
                                    app_message_id,
                                } => {
                                    if self.store_accepted_application_message(
                                        &record,
                                        plaintext,
                                        app_message_id,
                                    )? {
                                        output.state_update.messages_changed = true;
                                        output.state_update.conversations_changed = true;
                                        output
                                            .view_model
                                            .get_or_insert_with(CoreViewModel::default)
                                            .messages
                                            .push(MessageSummary {
                                                conversation_id: conversation_id.clone(),
                                                message_id: record.message_id.clone(),
                                                message_type: record.envelope.message_type,
                                            });
                                    }
                                    if self.direct_relationship_open_for_record(
                                        &record.envelope.sender_user_id,
                                        &conversation_id,
                                    ) {
                                        output = merge_outputs(
                                            output,
                                            self.promote_pending_outbound_contact(
                                                &record.envelope.sender_user_id,
                                                "verified_inbound_mls_application",
                                            )?,
                                        );
                                    }
                                }
                                ApplicationPlaintextDecision::DuplicateAppMessage {
                                    app_message_id,
                                } => {
                                    log::info!(
                                        "handle_inbox_records: acking duplicate protected app message {} for delivery {}",
                                        redact_id("app", &app_message_id),
                                        redact_id("msg", &record.message_id)
                                    );
                                }
                                ApplicationPlaintextDecision::RejectedProtocol { reason } => {
                                    log::warn!(
                                        "handle_inbox_records: rejecting MLS application delivery {} after open: {}",
                                        redact_id("msg", &record.message_id),
                                        reason
                                    );
                                }
                            }
                            if let Ok(summary) = self
                                .state
                                .mls_adapter
                                .as_ref()
                                .ok_or_else(|| {
                                    CoreError::invalid_state("mls adapter is not initialized")
                                })?
                                .export_group_summary(&conversation_id)
                            {
                                self.state
                                    .mls_summaries
                                    .insert(conversation_id.clone(), summary);
                            }
                            self.ack_pending_records_for_conversation_up_to(
                                &device_id,
                                &conversation_id,
                                record.seq,
                                &mut contiguous_ack,
                                &mut deferred_ackable_seqs,
                            );
                            touched_mls_conversation_ids.insert(conversation_id.clone());
                            touched_recovery_context_ids.insert(conversation_id.clone());
                            self.clear_recovery_context_as_healthy(&conversation_id);
                            ackable = true;
                        }
                        IngestResult::AppliedCommit { epoch } => {
                            log::info!(
                                "handle_inbox_records: unexpected AppliedCommit for application message {} in conversation {}, epoch={}",
                                record.message_id,
                                conversation_id,
                                epoch
                            );
                            if let Ok(summary) = self
                                .state
                                .mls_adapter
                                .as_ref()
                                .ok_or_else(|| {
                                    CoreError::invalid_state("mls adapter is not initialized")
                                })?
                                .export_group_summary(&conversation_id)
                            {
                                self.state
                                    .mls_summaries
                                    .insert(conversation_id.clone(), summary);
                            }
                            self.ack_pending_records_for_conversation_up_to(
                                &device_id,
                                &conversation_id,
                                record.seq,
                                &mut contiguous_ack,
                                &mut deferred_ackable_seqs,
                            );
                            touched_mls_conversation_ids.insert(conversation_id.clone());
                            touched_recovery_context_ids.insert(conversation_id.clone());
                            self.clear_recovery_context_as_healthy(&conversation_id);
                            ackable = true;
                        }
                        IngestResult::AppliedWelcome { epoch } => {
                            log::info!(
                                "handle_inbox_records: unexpected AppliedWelcome for application message {} in conversation {}, epoch={}",
                                record.message_id,
                                conversation_id,
                                epoch
                            );
                            if let Ok(summary) = self
                                .state
                                .mls_adapter
                                .as_ref()
                                .ok_or_else(|| {
                                    CoreError::invalid_state("mls adapter is not initialized")
                                })?
                                .export_group_summary(&conversation_id)
                            {
                                self.state
                                    .mls_summaries
                                    .insert(conversation_id.clone(), summary);
                            }
                            self.ack_pending_records_for_conversation_up_to(
                                &device_id,
                                &conversation_id,
                                record.seq,
                                &mut contiguous_ack,
                                &mut deferred_ackable_seqs,
                            );
                            touched_mls_conversation_ids.insert(conversation_id.clone());
                            touched_recovery_context_ids.insert(conversation_id.clone());
                            self.clear_recovery_context_as_healthy(&conversation_id);
                            output
                                .effects
                                .extend(self.rotate_local_key_package_after_welcome()?);
                            output.state_update.contacts_changed = true;
                            ackable = true;
                        }
                        IngestResult::IgnoredReplay => {
                            log::warn!(
                                "handle_inbox_records: IgnoredReplay for message {} in conversation {}",
                                redact_id("msg", &record.message_id),
                                redact_id("conversation", &conversation_id)
                            );
                            ackable = true;
                        }
                        IngestResult::PendingRetry => {
                            log::warn!(
                                "handle_inbox_records: PendingRetry for message {} in conversation {}",
                                redact_id("msg", &record.message_id),
                                redact_id("conversation", &conversation_id)
                            );
                            let reason = self.recovery_reason_for_record(&conversation_id);
                            {
                                let sync_state = self
                                    .state
                                    .sync_states
                                    .entry(device_id.clone())
                                    .or_insert_with(|| SyncEngine::new_device_state(&device_id));
                                SyncEngine::store_pending_record(sync_state, &record);
                            }
                            self.mark_recovery_needed(&conversation_id, reason);
                            self.transition_recovery_phase(
                                &conversation_id,
                                RecoveryPhase::WaitingForPendingReplay,
                            );
                            touched_recovery_context_ids.insert(conversation_id.clone());
                            pending_recovery_conversations.insert(conversation_id.clone());
                        }
                        IngestResult::NeedsRebuild => {
                            log::warn!(
                                "handle_inbox_records: NeedsRebuild for message {} in conversation {}",
                                redact_id("msg", &record.message_id),
                                redact_id("conversation", &conversation_id)
                            );
                            output = merge_outputs(
                                output,
                                self.escalate_conversation_to_rebuild(
                                    &conversation_id,
                                    RecoveryEscalationReason::MlsMarkedUnrecoverable,
                                    "MLS marked conversation unrecoverable",
                                )?,
                            );
                            touched_recovery_context_ids.insert(conversation_id.clone());
                        }
                    }
                }
                if ackable {
                    {
                        let sync_state = self
                            .state
                            .sync_states
                            .entry(device_id.clone())
                            .or_insert_with(|| SyncEngine::new_device_state(&device_id));
                        SyncEngine::clear_pending_retry(sync_state, record.seq);
                    }
                    advance_contiguous_ack(
                        &mut contiguous_ack,
                        &mut deferred_ackable_seqs,
                        record.seq,
                    );
                }
                processed_records.push(record);
                continue;
            }
            let apply_effect = {
                let conversation_state = self
                    .state
                    .conversations
                    .get_mut(&conversation_id)
                    .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?;
                ConversationManager::apply_incoming_envelope(conversation_state, &record.envelope)?
            };

            output.state_update.messages_changed = true;
            output.state_update.conversations_changed = true;
            output
                .view_model
                .get_or_insert_with(CoreViewModel::default)
                .messages
                .push(MessageSummary {
                    conversation_id: conversation_id.clone(),
                    message_id: record.message_id.clone(),
                    message_type: record.envelope.message_type,
                });

            let mut ackable = apply_effect.duplicate_message;
            if !apply_effect.duplicate_message {
                match record.envelope.message_type {
                    MessageType::MlsApplication
                    | MessageType::MlsCommit
                    | MessageType::MlsWelcome => {
                        match self
                            .state
                            .mls_adapter
                            .as_mut()
                            .ok_or_else(|| {
                                CoreError::invalid_state("mls adapter is not initialized")
                            })?
                            .ingest_message(
                                &conversation_id,
                                &record.envelope.sender_device_id,
                                record.envelope.message_type,
                                record
                                    .envelope
                                    .inline_ciphertext
                                    .as_deref()
                                    .unwrap_or_default(),
                            )? {
                            IngestResult::AppliedApplication(application) => {
                                log::info!(
                                    "handle_inbox_records: AppliedApplication for message {}, plaintext len={}",
                                    redact_id("msg", &record.message_id),
                                    application.plaintext.len()
                                );
                                if let Some(state) =
                                    self.state.conversations.get_mut(&conversation_id)
                                {
                                    if let Some(message) = state
                                        .messages
                                        .iter_mut()
                                        .find(|message| message.message_id == record.message_id)
                                    {
                                        message.plaintext =
                                            String::from_utf8(application.plaintext).ok();
                                        log::info!(
                                            "handle_inbox_records: stored plaintext for message {}",
                                            redact_id("msg", &record.message_id)
                                        );
                                    } else {
                                        log::warn!(
                                            "handle_inbox_records: Could not find message {} in conversation {} to set plaintext",
                                            redact_id("msg", &record.message_id),
                                            redact_id("conversation", &conversation_id)
                                        );
                                    }
                                } else {
                                    log::warn!(
                                        "handle_inbox_records: Conversation {} not found for message {}",
                                        redact_id("conversation", &conversation_id),
                                        redact_id("msg", &record.message_id)
                                    );
                                }
                                if let Ok(summary) = self
                                    .state
                                    .mls_adapter
                                    .as_ref()
                                    .ok_or_else(|| {
                                        CoreError::invalid_state("mls adapter is not initialized")
                                    })?
                                    .export_group_summary(&conversation_id)
                                {
                                    self.state
                                        .mls_summaries
                                        .insert(conversation_id.clone(), summary);
                                }
                                self.ack_pending_records_for_conversation_up_to(
                                    &device_id,
                                    &conversation_id,
                                    record.seq,
                                    &mut contiguous_ack,
                                    &mut deferred_ackable_seqs,
                                );
                                touched_mls_conversation_ids.insert(conversation_id.clone());
                                touched_recovery_context_ids.insert(conversation_id.clone());
                                self.clear_recovery_context_as_healthy(&conversation_id);
                                if self.direct_relationship_open_for_record(
                                    &record.envelope.sender_user_id,
                                    &conversation_id,
                                ) {
                                    output = merge_outputs(
                                        output,
                                        self.promote_pending_outbound_contact(
                                            &record.envelope.sender_user_id,
                                            "verified_inbound_mls_application",
                                        )?,
                                    );
                                }
                                ackable = true;
                            }
                            IngestResult::AppliedCommit { epoch } => {
                                log::info!(
                                    "handle_inbox_records: AppliedCommit for message {} in conversation {}, epoch={}",
                                    record.message_id,
                                    conversation_id,
                                    epoch
                                );
                                if let Ok(summary) = self
                                    .state
                                    .mls_adapter
                                    .as_ref()
                                    .ok_or_else(|| {
                                        CoreError::invalid_state("mls adapter is not initialized")
                                    })?
                                    .export_group_summary(&conversation_id)
                                {
                                    self.state
                                        .mls_summaries
                                        .insert(conversation_id.clone(), summary);
                                }
                                self.ack_pending_records_for_conversation_up_to(
                                    &device_id,
                                    &conversation_id,
                                    record.seq,
                                    &mut contiguous_ack,
                                    &mut deferred_ackable_seqs,
                                );
                                touched_mls_conversation_ids.insert(conversation_id.clone());
                                touched_recovery_context_ids.insert(conversation_id.clone());
                                self.clear_recovery_context_as_healthy(&conversation_id);
                                if self.direct_relationship_open_for_record(
                                    &record.envelope.sender_user_id,
                                    &conversation_id,
                                ) {
                                    output = merge_outputs(
                                        output,
                                        self.promote_pending_outbound_contact(
                                            &record.envelope.sender_user_id,
                                            "verified_inbound_mls_commit",
                                        )?,
                                    );
                                }
                                ackable = true;
                            }
                            IngestResult::AppliedWelcome { epoch } => {
                                log::info!(
                                    "handle_inbox_records: AppliedWelcome for message {} in conversation {}, epoch={}",
                                    record.message_id,
                                    conversation_id,
                                    epoch
                                );
                                if let Ok(summary) = self
                                    .state
                                    .mls_adapter
                                    .as_ref()
                                    .ok_or_else(|| {
                                        CoreError::invalid_state("mls adapter is not initialized")
                                    })?
                                    .export_group_summary(&conversation_id)
                                {
                                    self.state
                                        .mls_summaries
                                        .insert(conversation_id.clone(), summary);
                                }
                                self.ack_pending_records_for_conversation_up_to(
                                    &device_id,
                                    &conversation_id,
                                    record.seq,
                                    &mut contiguous_ack,
                                    &mut deferred_ackable_seqs,
                                );
                                touched_mls_conversation_ids.insert(conversation_id.clone());
                                touched_recovery_context_ids.insert(conversation_id.clone());
                                self.clear_recovery_context_as_healthy(&conversation_id);
                                output
                                    .effects
                                    .extend(self.rotate_local_key_package_after_welcome()?);
                                output.state_update.contacts_changed = true;
                                if self.direct_relationship_open_for_record(
                                    &record.envelope.sender_user_id,
                                    &conversation_id,
                                ) {
                                    output = merge_outputs(
                                        output,
                                        self.promote_pending_outbound_contact(
                                            &record.envelope.sender_user_id,
                                            "verified_inbound_mls_welcome",
                                        )?,
                                    );
                                }
                                ackable = true;
                            }
                            IngestResult::IgnoredReplay => {
                                log::warn!(
                                    "handle_inbox_records: IgnoredReplay for message {} in conversation {}",
                                    redact_id("msg", &record.message_id),
                                    redact_id("conversation", &conversation_id)
                                );
                                ackable = true;
                            }
                            IngestResult::PendingRetry => {
                                log::warn!(
                                    "handle_inbox_records: PendingRetry for message {} in conversation {}",
                                    redact_id("msg", &record.message_id),
                                    redact_id("conversation", &conversation_id)
                                );
                                let reason = self.recovery_reason_for_record(&conversation_id);
                                {
                                    let sync_state = self
                                        .state
                                        .sync_states
                                        .entry(device_id.clone())
                                        .or_insert_with(|| {
                                            SyncEngine::new_device_state(&device_id)
                                        });
                                    SyncEngine::store_pending_record(sync_state, &record);
                                }
                                self.mark_recovery_needed(&conversation_id, reason);
                                self.transition_recovery_phase(
                                    &conversation_id,
                                    RecoveryPhase::WaitingForPendingReplay,
                                );
                                touched_recovery_context_ids.insert(conversation_id.clone());
                                pending_recovery_conversations.insert(conversation_id.clone());
                            }
                            IngestResult::NeedsRebuild => {
                                log::warn!(
                                    "handle_inbox_records: NeedsRebuild for message {} in conversation {}",
                                    redact_id("msg", &record.message_id),
                                    redact_id("conversation", &conversation_id)
                                );
                                output = merge_outputs(
                                    output,
                                    self.escalate_conversation_to_rebuild(
                                        &conversation_id,
                                        RecoveryEscalationReason::MlsMarkedUnrecoverable,
                                        "MLS marked conversation unrecoverable",
                                    )?,
                                );
                                touched_recovery_context_ids.insert(conversation_id.clone());
                            }
                        }
                    }
                    _ => {
                        ackable = true;
                        if record.envelope.message_type == MessageType::ControlGroupWelcomePickup {
                            log::info!(
                                "handle_inbox_records: received group welcome control message_id={} conversation_id={}",
                                record.message_id,
                                conversation_id
                            );
                            let payload_b64 = record
                                .envelope
                                .inline_ciphertext
                                .as_deref()
                                .ok_or_else(|| {
                                    CoreError::invalid_input(
                                        "group welcome pickup control is missing payload",
                                    )
                                })?;
                            let payload = STANDARD.decode(payload_b64).map_err(|error| {
                                CoreError::invalid_input(format!(
                                    "failed to decode group welcome pickup control: {error}"
                                ))
                            })?;
                            let invite: GroupWelcomePickupControl =
                                serde_json::from_slice(&payload).map_err(|error| {
                                    CoreError::invalid_input(format!(
                                        "failed to parse group welcome pickup control: {error}"
                                    ))
                                })?;
                            invite.welcome_pickup_descriptor.validate()?;
                            if let Some(state) = self.state.conversations.get_mut(&conversation_id)
                            {
                                if let Some(message) = state
                                    .messages
                                    .iter_mut()
                                    .find(|message| message.message_id == record.message_id)
                                {
                                    message.plaintext =
                                        Some(format!("Group invite: {}", invite.title));
                                }
                            }
                            if !self.state.group_states.contains_key(&invite.group_id) {
                                log::info!(
                                    "handle_inbox_records: fetching welcome pickup group_id={} device_id={} endpoint={}",
                                    invite.group_id,
                                    invite.welcome_pickup_descriptor.device_id,
                                    invite.welcome_pickup_descriptor.endpoint
                                );
                                output = merge_outputs(
                                    output,
                                    self.stage_welcome_pickup(
                                        invite.group_id.clone(),
                                        invite.welcome_pickup_descriptor,
                                        Some(invite.title),
                                        Some(invite.inviter_user_id),
                                        true,
                                    )?,
                                );
                            } else {
                                log::info!(
                                    "handle_inbox_records: group welcome control ignored because group already exists group_id={}",
                                    invite.group_id
                                );
                            }
                        }
                        if apply_effect.identity_refresh_needed {
                            let peer_user_id = self.peer_user_for_conversation(&conversation_id)?;
                            output =
                                merge_outputs(output, self.refresh_identity_state(peer_user_id)?);
                        }
                        if apply_effect.membership_refresh_needed {
                            touched_recovery_context_ids.insert(conversation_id.clone());
                            output = merge_outputs(
                                output,
                                self.reconcile_conversation_membership(conversation_id.clone())?,
                            );
                        }
                        if apply_effect.needs_rebuild {
                            output = merge_outputs(
                                output,
                                self.escalate_conversation_to_rebuild(
                                    &conversation_id,
                                    RecoveryEscalationReason::ExplicitNeedsRebuildControl,
                                    "conversation received explicit rebuild control message",
                                )?,
                            );
                            touched_recovery_context_ids.insert(conversation_id.clone());
                        }
                    }
                }
            }

            if ackable {
                {
                    let sync_state = self
                        .state
                        .sync_states
                        .entry(device_id.clone())
                        .or_insert_with(|| SyncEngine::new_device_state(&device_id));
                    SyncEngine::clear_pending_retry(sync_state, record.seq);
                }
                advance_contiguous_ack(&mut contiguous_ack, &mut deferred_ackable_seqs, record.seq);
            }
            processed_records.push(record);
        }

        {
            let sync_state = self
                .state
                .sync_states
                .entry(device_id.clone())
                .or_insert_with(|| SyncEngine::new_device_state(&device_id));
            for record in &processed_records {
                SyncEngine::commit_fetched_record(sync_state, record);
            }
            SyncEngine::clear_sync_failures(sync_state);
        }
        let ack = {
            let sync_state = self
                .state
                .sync_states
                .entry(device_id.clone())
                .or_insert_with(|| SyncEngine::new_device_state(&device_id));
            SyncEngine::ack_up_to(sync_state, contiguous_ack)
        };
        if ack.ack_seq > 0 {
            self.state.pending_acks.insert(
                ack.device_id.clone(),
                PendingAckState {
                    ack,
                    retries: 0,
                    in_flight: false,
                },
            );
            touched_pending_ack_device_ids.insert(device_id.clone());
        }
        let pending_recovery_conversations_for_persist = pending_recovery_conversations.clone();
        output = merge_outputs(
            output,
            self.process_pending_recovery_batch(
                &device_id,
                pending_recovery_conversations,
                allow_pending_replay,
            )?,
        );
        for conversation_id in pending_recovery_conversations_for_persist {
            touched_conversation_ids.insert(conversation_id.clone());
            touched_recovery_context_ids.insert(conversation_id);
        }
        let mut persist_ops = Vec::new();
        persist_ops.extend(
            touched_conversation_ids
                .into_iter()
                .map(|conversation_id| PersistOp::SaveConversation { conversation_id }),
        );
        persist_ops.extend(
            touched_mls_conversation_ids
                .into_iter()
                .map(|conversation_id| PersistOp::SaveMlsState { conversation_id }),
        );
        persist_ops.extend(
            touched_sync_device_ids
                .into_iter()
                .map(|device_id| PersistOp::SaveSyncState { device_id }),
        );
        persist_ops.extend(
            touched_pending_ack_device_ids
                .into_iter()
                .map(|device_id| PersistOp::SavePendingAck { device_id }),
        );
        persist_ops.extend(
            touched_recovery_context_ids
                .into_iter()
                .map(|conversation_id| {
                    if self.state.recovery_contexts.contains_key(&conversation_id) {
                        PersistOp::SaveRecoveryContext { conversation_id }
                    } else {
                        PersistOp::DeleteRecoveryContext { conversation_id }
                    }
                }),
        );
        if !persist_ops.is_empty() {
            output = merge_outputs(
                CoreOutput {
                    state_update: CoreStateUpdate::default(),
                    effects: vec![persist_effect(&self.state, persist_ops)],
                    view_model: None,
                },
                output,
            );
        }
        self.merge_with_transport_flush(output)
    }

    pub(super) fn handle_unsuccessful_request(
        &mut self,
        request: PendingRequest,
        status: u16,
        body: Option<String>,
    ) -> CoreResult<CoreOutput> {
        match request {
            PendingRequest::AppendEnvelope { message_id, .. } => {
                if status >= 500 {
                    if let Some(item) = self
                        .state
                        .pending_outbox
                        .iter_mut()
                        .find(|item| item.envelope.message_id == message_id)
                    {
                        item.in_flight = false;
                        item.retries = item.retries.saturating_add(1);
                        if item.retries < MAX_TRANSPORT_RETRIES {
                            let timer_id = format!("retry_append:{message_id}");
                            return Ok(CoreOutput {
                                state_update: CoreStateUpdate {
                                    system_statuses_changed: vec![
                                        SystemStatus::TemporaryNetworkFailure,
                                    ],
                                    ..CoreStateUpdate::default()
                                },
                                effects: vec![CoreEffect::ScheduleTimer {
                                    timer: TimerEffect {
                                        delay_ms: retry_delay_ms(
                                            &timer_id,
                                            u32::from(item.retries),
                                        ),
                                        timer_id,
                                    },
                                }],
                                view_model: None,
                            });
                        }
                    }
                } else {
                    self.state
                        .pending_outbox
                        .retain(|item| item.envelope.message_id != message_id);
                }
                Ok(CoreOutput {
                    state_update: CoreStateUpdate {
                        system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                        ..CoreStateUpdate::default()
                    },
                    effects: vec![CoreEffect::EmitUserNotification {
                        notification: UserNotificationEffect {
                            status: SystemStatus::TemporaryNetworkFailure,
                            message: body.unwrap_or_else(|| {
                                format!("append request returned status {status}")
                            }),
                        },
                    }],
                    view_model: None,
                })
            }
            PendingRequest::Ack { device_id, .. } => {
                if status >= 500 {
                    if let Some(ack) = self.state.pending_acks.get_mut(&device_id) {
                        ack.in_flight = false;
                        ack.retries = ack.retries.saturating_add(1);
                        if ack.retries < MAX_TRANSPORT_RETRIES {
                            let timer_id = format!("retry_ack:{device_id}");
                            return Ok(CoreOutput {
                                state_update: CoreStateUpdate {
                                    system_statuses_changed: vec![
                                        SystemStatus::TemporaryNetworkFailure,
                                    ],
                                    ..CoreStateUpdate::default()
                                },
                                effects: vec![CoreEffect::ScheduleTimer {
                                    timer: TimerEffect {
                                        delay_ms: retry_delay_ms(
                                            &timer_id,
                                            u32::from(ack.retries),
                                        ),
                                        timer_id,
                                    },
                                }],
                                view_model: None,
                            });
                        }
                    }
                } else {
                    self.state.pending_acks.remove(&device_id);
                }
                Ok(CoreOutput {
                    state_update: CoreStateUpdate {
                        system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                        ..CoreStateUpdate::default()
                    },
                    effects: vec![CoreEffect::EmitUserNotification {
                        notification: UserNotificationEffect {
                            status: SystemStatus::TemporaryNetworkFailure,
                            message: body
                                .unwrap_or_else(|| format!("ack request returned status {status}")),
                        },
                    }],
                    view_model: None,
                })
            }
            PendingRequest::GetHead { device_id } => Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::ScheduleTimer {
                    timer: self.sync_retry_timer(&device_id),
                }],
                view_model: None,
            }),
            PendingRequest::FetchMessages { device_id, .. } => Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::ScheduleTimer {
                    timer: self.sync_retry_timer(&device_id),
                }],
                view_model: None,
            }),
            PendingRequest::AppendGroupEnvelope {
                group_id,
                message_id,
            } => {
                let code = body.as_deref().and_then(|value| {
                    serde_json::from_str::<serde_json::Value>(value)
                        .ok()
                        .and_then(|json| json.get("error")?.as_str().map(str::to_owned))
                });
                self.handle_group_append_failed(
                    group_id,
                    message_id,
                    status >= 500,
                    Some(status),
                    code,
                    body.or_else(|| Some(format!("group append returned status {status}"))),
                )
            }
            PendingRequest::FetchGroupOutbox { group_id, .. } => Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect {
                        status: SystemStatus::TemporaryNetworkFailure,
                        message: body
                            .map(|body| format!("group outbox fetch failed: {body}"))
                            .unwrap_or_else(|| {
                                format!("group fetch returned status {status} for {group_id}")
                            }),
                    },
                }],
                view_model: None,
            }),
            PendingRequest::PutWelcomePickup {
                group_id,
                device_id,
            }
            | PendingRequest::FetchWelcomePickup {
                group_id,
                device_id,
            } => Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect {
                        status: SystemStatus::TemporaryNetworkFailure,
                        message: body
                            .map(|body| {
                                format!("welcome pickup transfer failed: {body}")
                            })
                            .unwrap_or_else(|| {
                                format!(
                                    "welcome pickup returned status {status} for {group_id}/{device_id}"
                                )
                            }),
                    },
                }],
                view_model: None,
            }),
            PendingRequest::CreateGroupInvite {
                group_id,
                invite_id,
            } => Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect {
                        status: SystemStatus::TemporaryNetworkFailure,
                        message: body.unwrap_or_else(|| {
                            format!(
                                "group invite returned status {status} for {group_id}/{invite_id}"
                            )
                        }),
                    },
                }],
                view_model: None,
            }),
            PendingRequest::SubmitGroupJoinRequest {
                group_id,
                request_id,
                ..
            }
            | PendingRequest::DecideGroupJoinRequest {
                group_id,
                request_id,
            } => Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect {
                        status: SystemStatus::TemporaryNetworkFailure,
                        message: body.unwrap_or_else(|| {
                            format!(
                                "group join returned status {status} for {group_id}/{request_id}"
                            )
                        }),
                    },
                }],
                view_model: None,
            }),
        }
    }

    pub(super) fn handle_append_delivery_result(
        &mut self,
        message_id: &str,
        result: &AppendEnvelopeResult,
    ) -> AppendDeliveryOutput {
        // Find the pending outbox item to get plaintext and conversation info
        let pending_item = self
            .state
            .pending_outbox
            .iter()
            .find(|item| item.envelope.message_id == message_id);

        let peer_user_id = pending_item
            .map(|item| item.peer_user_id.clone())
            .unwrap_or_else(|| "peer".into());

        let plaintext_cache = pending_item.and_then(|item| item.plaintext_cache.clone());
        let app_message_id = pending_item.and_then(|item| item.app_message_id.clone());

        let envelope = pending_item.map(|item| item.envelope.clone());

        let append_result = AppendResultSummary {
            accepted: result.accepted,
            delivered_to: result.delivered_to.clone(),
            queued_as_request: result.queued_as_request,
            request_id: result.request_id.clone(),
            seq: Some(result.seq),
        };
        let protocol_only_contact_control = envelope.as_ref().is_some_and(|env| {
            matches!(
                env.message_type,
                MessageType::ControlContactRemoved | MessageType::ControlContactAccepted
            )
        });
        let current_relationship_removed = self
            .state
            .contacts
            .get(&peer_user_id)
            .is_some_and(|contact| Self::relationship_is_removed(&contact.relationship_status));
        let contact_changed = if protocol_only_contact_control || current_relationship_removed {
            false
        } else {
            let relationship_status = match result.delivered_to {
                AppendDeliveryDisposition::Inbox => ContactRelationshipStatus::Available,
                AppendDeliveryDisposition::MessageRequest => {
                    ContactRelationshipStatus::PendingOutbound
                }
                AppendDeliveryDisposition::Rejected => ContactRelationshipStatus::Rejected,
            };
            self.set_contact_relationship_status(&peer_user_id, relationship_status)
        };
        let contacts = if contact_changed {
            self.contact_summaries()
        } else {
            Vec::new()
        };

        let mut saved_conversation_id = None;

        // When message is delivered to inbox, store it in conversation.messages
        // This ensures the message is preserved even after pending_outbox is cleared
        let messages_changed = if result.delivered_to == AppendDeliveryDisposition::Inbox {
            if let Some(env) = &envelope {
                if protocol_only_contact_control {
                    return AppendDeliveryOutput {
                        output: CoreOutput {
                            state_update: CoreStateUpdate {
                                contacts_changed: contact_changed,
                                ..CoreStateUpdate::default()
                            },
                            effects: vec![],
                            view_model: Some(CoreViewModel {
                                append_result: Some(append_result),
                                contacts,
                                ..CoreViewModel::default()
                            }),
                        },
                        saved_conversation_id: None,
                    };
                }
                let conversation_id = env.conversation_id.clone();
                if let Some(conv) = self.state.conversations.get_mut(&conversation_id) {
                    // Check if message already exists (avoid duplicates)
                    let duplicate = conv.messages.iter().any(|m| {
                        m.message_id == message_id
                            || app_message_id
                                .as_deref()
                                .is_some_and(|app_id| m.app_message_id.as_deref() == Some(app_id))
                    });
                    if !duplicate {
                        conv.messages.push(crate::conversation::StoredMessage {
                            message_id: message_id.to_string(),
                            app_message_id: app_message_id.clone(),
                            sender_user_id: Some(env.sender_user_id.clone()),
                            sender_device_id: env.sender_device_id.clone(),
                            recipient_device_id: env.recipient_device_id.clone(),
                            message_type: env.message_type,
                            created_at: env.created_at,
                            plaintext: plaintext_cache.clone(),
                            storage_refs: env.storage_refs.clone(),
                            downloaded_blob_b64: None,
                        });
                        conv.last_message_type = Some(env.message_type);
                        log::info!(
                            "handle_append_delivery_result: stored message {} in conversation {} with plaintext={}",
                            redact_id("msg", message_id),
                            redact_id("conversation", &conversation_id),
                            plaintext_cache.is_some()
                        );
                        saved_conversation_id = Some(conversation_id);
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        let (status, message, banner) = match result.delivered_to {
            AppendDeliveryDisposition::Inbox => {
                return AppendDeliveryOutput {
                    output: CoreOutput {
                        state_update: CoreStateUpdate {
                            messages_changed,
                            conversations_changed: messages_changed,
                            contacts_changed: contact_changed,
                            ..CoreStateUpdate::default()
                        },
                        effects: vec![],
                        view_model: Some(CoreViewModel {
                            append_result: Some(append_result),
                            contacts,
                            ..CoreViewModel::default()
                        }),
                    },
                    saved_conversation_id,
                };
            }
            AppendDeliveryDisposition::MessageRequest => (
                SystemStatus::MessageQueuedForApproval,
                format!("message {message_id} for {peer_user_id} is queued as a message request"),
                "message queued for recipient approval".to_string(),
            ),
            AppendDeliveryDisposition::Rejected => (
                SystemStatus::MessageRejectedByPolicy,
                format!("message {message_id} for {peer_user_id} was rejected by inbox policy"),
                "message rejected by recipient policy".to_string(),
            ),
        };
        AppendDeliveryOutput {
            output: CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![status],
                    contacts_changed: contact_changed,
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect { status, message },
                }],
                view_model: Some(CoreViewModel {
                    append_result: Some(append_result),
                    contacts,
                    banners: vec![SystemBanner {
                        status,
                        message: banner,
                    }],
                    ..CoreViewModel::default()
                }),
            },
            saved_conversation_id,
        }
    }

    pub(super) fn message_requests_output(&self, requests: Vec<MessageRequestItem>) -> CoreOutput {
        CoreOutput {
            state_update: CoreStateUpdate::default(),
            effects: vec![],
            view_model: Some(CoreViewModel {
                message_requests: requests,
                ..CoreViewModel::default()
            }),
        }
    }

    pub(super) fn contact_accepted_notification_output(
        &mut self,
        result: &MessageRequestActionResult,
    ) -> CoreResult<CoreOutput> {
        if !result.accepted || result.action != MessageRequestAction::Accept {
            return Ok(CoreOutput::default());
        }
        if result.sender_user_id.trim().is_empty() {
            log::warn!(
                "message request accept completed without sender_user_id; skipping contact accepted control"
            );
            return Ok(CoreOutput::default());
        }
        let Some(contact) = self.state.contacts.get(&result.sender_user_id) else {
            log::warn!(
                "message request accept completed for {} but sender contact is missing; skipping contact accepted control",
                redact_id("user", &result.sender_user_id)
            );
            return Ok(CoreOutput::default());
        };
        if Self::relationship_is_removed(&contact.relationship_status) {
            log::info!(
                "message request accept completed for {} but sender contact is removed; skipping contact accepted control",
                redact_id("user", &result.sender_user_id)
            );
            return Ok(CoreOutput::default());
        }

        let created_at = current_unix_millis(self.next_message_nonce());
        let envelopes = self.build_contact_accepted_envelopes(
            &result.sender_user_id,
            &result.request_id,
            &result.promoted_conversation_ids,
            created_at,
        )?;
        if envelopes.is_empty() {
            log::warn!(
                "message request accept completed for {} but no active peer devices were available for contact accepted control",
                redact_id("user", &result.sender_user_id)
            );
            return Ok(CoreOutput::default());
        }
        let message_ids = envelopes
            .iter()
            .map(|envelope| envelope.message_id.clone())
            .collect::<Vec<_>>();
        self.enqueue_envelopes(result.sender_user_id.clone(), envelopes);
        let mut output = CoreOutput {
            state_update: CoreStateUpdate::default(),
            effects: vec![persist_effect(
                &self.state,
                message_ids
                    .into_iter()
                    .map(|message_id| PersistOp::SaveOutgoingEnvelope { message_id })
                    .collect(),
            )],
            view_model: None,
        };
        output = merge_outputs(output, self.flush_pending_transport()?);
        Ok(output)
    }

    pub(super) fn message_request_action_output(
        &mut self,
        result: MessageRequestActionResult,
    ) -> CoreResult<CoreOutput> {
        let message = match result.action {
            MessageRequestAction::Accept => {
                format!("accepted message request {}", result.request_id)
            }
            MessageRequestAction::Reject => {
                format!("rejected message request {}", result.request_id)
            }
        };
        let mut output = CoreOutput {
            state_update: CoreStateUpdate::default(),
            effects: vec![CoreEffect::EmitUserNotification {
                notification: UserNotificationEffect {
                    status: SystemStatus::SyncInProgress,
                    message: message.clone(),
                },
            }],
            view_model: Some(CoreViewModel {
                message_request_action: Some(MessageRequestActionSummary {
                    accepted: result.accepted,
                    request_id: result.request_id.clone(),
                    sender_user_id: result.sender_user_id.clone(),
                    promoted_count: result.promoted_count,
                    action: result.action,
                }),
                banners: vec![SystemBanner {
                    status: SystemStatus::SyncInProgress,
                    message,
                }],
                ..CoreViewModel::default()
            }),
        };
        if result.accepted && result.action == MessageRequestAction::Accept {
            output = merge_outputs(output, self.contact_accepted_notification_output(&result)?);
            let device_id = self.local_device_id_required()?;
            return Ok(merge_outputs(output, self.sync_inbox(device_id, None)?));
        }
        Ok(output)
    }

    pub(super) fn allowlist_output(
        &self,
        document: AllowlistDocument,
        _updated: bool,
    ) -> CoreOutput {
        CoreOutput {
            state_update: CoreStateUpdate::default(),
            effects: vec![],
            view_model: Some(CoreViewModel {
                allowlist: Some(document),
                banners: Vec::new(),
                ..CoreViewModel::default()
            }),
        }
    }

    pub(super) fn handle_allowlist_fetched(
        &mut self,
        mut document: AllowlistDocument,
    ) -> CoreResult<CoreOutput> {
        let Some(mutation) = self.state.pending_allowlist_mutation.take() else {
            return Ok(self.allowlist_output(document, false));
        };
        match mutation {
            PendingAllowlistMutation::Add { user_id } => {
                if !document
                    .allowed_sender_user_ids
                    .iter()
                    .any(|existing| existing == &user_id)
                {
                    document.allowed_sender_user_ids.push(user_id.clone());
                    document.allowed_sender_user_ids.sort();
                    document.allowed_sender_user_ids.dedup();
                }
                document
                    .rejected_sender_user_ids
                    .retain(|existing| existing != &user_id);
            }
            PendingAllowlistMutation::Remove { user_id } => {
                document
                    .allowed_sender_user_ids
                    .retain(|existing| existing != &user_id);
                document
                    .rejected_sender_user_ids
                    .retain(|existing| existing != &user_id);
            }
            PendingAllowlistMutation::RemoveMany { user_ids } => {
                let user_ids = user_ids.into_iter().collect::<BTreeSet<_>>();
                document
                    .allowed_sender_user_ids
                    .retain(|existing| !user_ids.contains(existing));
                document
                    .rejected_sender_user_ids
                    .retain(|existing| !user_ids.contains(existing));
            }
        }
        Ok(CoreOutput {
            state_update: CoreStateUpdate::default(),
            effects: vec![CoreEffect::ReplaceAllowlist {
                update: ReplaceAllowlistRequest {
                    device_id: self.local_device_id_required()?,
                    endpoint: self.inbox_management_endpoint("allowlist")?,
                    headers: BTreeMap::new(),
                    auth: Some(self.device_runtime_auth_requirement()?),
                    document,
                },
            }],
            view_model: None,
        })
    }
}

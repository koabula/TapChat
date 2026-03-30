use std::collections::{BTreeMap, BTreeSet};

use crate::conversation::{
    ConversationManager, LocalConversationState, ReconcileMembershipInput, RecoveryStatus,
};
use crate::error::{CoreError, CoreResult};
use crate::ffi_api::types::*;
use crate::identity::IdentityManager;
use crate::mls_adapter::{
    CreateConversationArtifacts, IngestResult, MlsAdapter, PeerDeviceKeyPackage,
    RemoveMembersArtifacts,
};
use crate::model::{
    Ack, ConversationKind, ConversationState, DeliveryClass, Envelope, IdentityBundle,
    InboxRecord, MessageType, MlsStateStatus, MlsStateSummary, SenderProof, StorageRef, Validate,
};
use crate::persistence::{
    CorePersistenceSnapshot, PersistOp, PersistedContact, PersistedConversation,
    PersistedDeployment, PersistedLocalIdentity, PersistedMlsState, PersistedOutgoingEnvelope,
    PersistedPendingAck, PersistedPendingBlobTransfer, PersistedRealtimeSession,
    PersistedRecoveryContext, PersistedRecoveryReason, PersistedSyncState,
};
use crate::sync_engine::{SyncDecision, SyncEngine};
use crate::transport_contract::{
    AckRequest, AckResult, AppendEnvelopeRequest, AppendEnvelopeResult, BlobDownloadRequest,
    BlobUploadRequest,
    FetchIdentityBundleRequest, FetchMessagesRequest, FetchMessagesResult, GetHeadResult,
    PrepareBlobUploadRequest, PrepareBlobUploadResult, RealtimeSubscriptionRequest,
};

#[derive(Debug, Default)]
pub struct CoreEngine {
    pub(crate) state: CoreState,
}

impl CoreEngine {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(dead_code)]
    pub(crate) fn from_restored_state(snapshot: CorePersistenceSnapshot) -> Self {
        let restored_mls = MlsAdapter::restore_from_persisted_states(
            &snapshot
                .mls_states
                .iter()
                .map(|state| {
                    (
                        state.conversation_id.clone(),
                        state.summary.clone(),
                        state.serialized_group_state.clone(),
                    )
                })
                .collect::<Vec<_>>(),
        )
        .unwrap_or_default();
        let mut contacts = BTreeMap::new();
        for contact in snapshot.contacts {
            contacts.insert(contact.user_id, contact.bundle);
        }

        let mut conversations = BTreeMap::new();
        for conversation in snapshot.conversations {
            conversations.insert(conversation.conversation_id, conversation.state);
        }

        let mut sync_states = BTreeMap::new();
        for sync_state in snapshot.sync_states {
            sync_states.insert(sync_state.device_id, sync_state.state);
        }

        let mls_summaries = restored_mls.summaries;

        let pending_outbox: Vec<PendingOutboxItem> = snapshot
            .pending_outbox
            .into_iter()
            .map(|item| PendingOutboxItem {
                envelope: item.envelope,
                peer_user_id: item.peer_user_id,
                retries: item.retries,
                in_flight: false,
            })
            .collect();
        let outbox = pending_outbox
            .iter()
            .map(|item| item.envelope.clone())
            .collect::<Vec<_>>();

        let pending_acks = snapshot
            .pending_acks
            .into_iter()
            .map(|ack| {
                (
                    ack.device_id.clone(),
                    PendingAckState {
                        ack: ack.ack,
                        retries: ack.retries,
                        in_flight: false,
                    },
                )
            })
            .collect();

        let mut pending_blob_uploads = BTreeMap::new();
        let mut pending_blob_downloads = BTreeMap::new();
        for transfer in snapshot.pending_blob_transfers {
            match transfer {
                PersistedPendingBlobTransfer::Upload {
                    task_id,
                    conversation_id,
                    message_id,
                    source,
                    mime_type,
                    size_bytes,
                    file_name,
                    metadata_ciphertext,
                    prepared_upload,
                    retries,
                } => {
                    pending_blob_uploads.insert(
                        task_id.clone(),
                        PendingBlobUpload {
                            task_id,
                            conversation_id,
                            descriptor: AttachmentDescriptor {
                                source,
                                mime_type,
                                size_bytes,
                                file_name,
                            },
                            message_id,
                            metadata_ciphertext,
                            prepared_upload,
                            retries,
                            in_flight: false,
                        },
                    );
                }
                PersistedPendingBlobTransfer::Download {
                    task_id,
                    conversation_id,
                    message_id,
                    reference,
                    destination,
                    retries,
                } => {
                    pending_blob_downloads.insert(
                        task_id.clone(),
                        PendingBlobDownload {
                            task_id,
                            conversation_id,
                            message_id,
                            reference,
                            destination,
                            retries,
                            in_flight: false,
                        },
                    );
                }
            }
        }

        let realtime_sessions = snapshot
            .realtime_sessions
            .into_iter()
            .map(|session| {
                (
                    session.device_id.clone(),
                    RealtimeSessionState {
                        connected: false,
                        last_known_seq: session.last_known_seq,
                        needs_reconnect: session.needs_reconnect,
                    },
                )
            })
            .collect();

        let recovery_contexts = snapshot
            .recovery_contexts
            .into_iter()
            .map(|context| {
                (
                    context.conversation_id.clone(),
                    RecoveryContext {
                        conversation_id: context.conversation_id,
                        reason: match context.reason {
                            PersistedRecoveryReason::MissingCommit => RecoveryReason::MissingCommit,
                            PersistedRecoveryReason::MissingWelcome => {
                                RecoveryReason::MissingWelcome
                            }
                            PersistedRecoveryReason::MembershipChanged => {
                                RecoveryReason::MembershipChanged
                            }
                            PersistedRecoveryReason::IdentityChanged => {
                                RecoveryReason::IdentityChanged
                            }
                        },
                        sync_attempted: context.sync_attempted,
                        identity_refresh_attempted: context.identity_refresh_attempted,
                        identity_refresh_retry_count: context.identity_refresh_retry_count,
                    },
                )
            })
            .collect();

        let local_identity = snapshot.local_identity.map(|identity| identity.state);
        let mut engine = Self {
            state: CoreState {
                local_identity,
                local_bundle: snapshot
                    .deployment
                    .as_ref()
                    .and_then(|deployment| deployment.local_bundle.clone()),
                deployment_bundle: snapshot
                    .deployment
                    .as_ref()
                    .map(|deployment| deployment.deployment_bundle.clone()),
                contacts,
                conversations,
                sync_states,
                outbox,
                pending_outbox,
                pending_acks,
                pending_blob_uploads,
                pending_blob_downloads,
                realtime_sessions,
                mls_adapter: restored_mls.adapter,
                mls_summaries,
                published_key_package: snapshot
                    .deployment
                    .and_then(|deployment| deployment.published_key_package),
                pending_requests: BTreeMap::new(),
                recovery_contexts,
            },
        };

        if engine.state.mls_adapter.is_none() {
            if let Some(identity) = engine.state.local_identity.as_ref() {
                if let Ok((adapter, published_key_package)) = MlsAdapter::bootstrap(identity) {
                    engine.state.mls_adapter = Some(adapter);
                    if engine.state.published_key_package.is_none() {
                        engine.state.published_key_package = Some(published_key_package);
                    }
                }
            }
        }

        for conversation_id in restored_mls.failed_conversation_ids {
            if let Some(conversation) = engine.state.conversations.get_mut(&conversation_id) {
                conversation.conversation.state = ConversationState::NeedsRebuild;
                conversation.recovery_status = RecoveryStatus::NeedsRebuild;
            }
            if let Some(summary) = engine.state.mls_summaries.get_mut(&conversation_id) {
                summary.status = MlsStateStatus::NeedsRebuild;
                summary.updated_at = 0;
            }
            engine.state.recovery_contexts.remove(&conversation_id);
        }

        engine
    }

    pub fn handle_command(&mut self, command: CoreCommand) -> CoreResult<CoreOutput> {
        match command {
            CoreCommand::CreateOrLoadIdentity { mnemonic, device_name } => {
                self.create_or_load_identity(mnemonic, device_name)
            }
            CoreCommand::ImportDeploymentBundle { bundle } => self.import_deployment_bundle(bundle),
            CoreCommand::ImportIdentityBundle { bundle } => self.import_identity_bundle(bundle),
            CoreCommand::ApplyIdentityBundleUpdate { bundle } => self.apply_identity_bundle_update(bundle),
            CoreCommand::CreateConversation { peer_user_id, conversation_kind } => {
                self.create_conversation(peer_user_id, conversation_kind)
            }
            CoreCommand::ReconcileConversationMembership { conversation_id } => {
                self.reconcile_conversation_membership(conversation_id)
            }
            CoreCommand::SendTextMessage { conversation_id, plaintext } => {
                self.send_text_message(conversation_id, plaintext)
            }
            CoreCommand::SendAttachmentMessage { conversation_id, attachment_descriptor } => {
                self.send_attachment_message(conversation_id, attachment_descriptor)
            }
            CoreCommand::DownloadAttachment {
                conversation_id,
                message_id,
                reference,
                destination,
            } => self.download_attachment(conversation_id, message_id, reference, destination),
            CoreCommand::SyncInbox { device_id, .. } => self.sync_inbox(device_id),
            CoreCommand::RefreshIdentityState { user_id } => self.refresh_identity_state(user_id),
            CoreCommand::RebuildConversation { conversation_id } => {
                self.rebuild_conversation(conversation_id)
            }
        }
    }

    pub fn handle_event(&mut self, event: CoreEvent) -> CoreResult<CoreOutput> {
        match event {
            CoreEvent::AppStarted | CoreEvent::AppForegrounded => self.start_foreground_sync(),
            CoreEvent::WebSocketConnected { device_id } => self.handle_websocket_connected(device_id),
            CoreEvent::WebSocketDisconnected { device_id, .. } => {
                self.handle_websocket_disconnected(device_id)
            }
            CoreEvent::RealtimeEventReceived { device_id, event } => {
                self.handle_realtime_event(device_id, event)
            }
            CoreEvent::WakeupReceived { device_id, .. } => self.sync_inbox(device_id),
            CoreEvent::InboxRecordsFetched { device_id, records, to_seq } => {
                self.handle_inbox_records(device_id, records, to_seq)
            }
            CoreEvent::HttpResponseReceived { request_id, status, body } => {
                self.handle_http_response(request_id, status, body)
            }
            CoreEvent::HttpRequestFailed { request_id, retryable, detail } => {
                self.handle_http_failure(request_id, retryable, detail)
            }
            CoreEvent::IdentityBundleFetched { user_id: _, bundle } => {
                self.apply_identity_bundle_update(bundle)
            }
            CoreEvent::IdentityBundleFetchFailed {
                user_id,
                retryable,
                detail,
            } => self.handle_identity_refresh_failure(
                &user_id,
                detail.unwrap_or_else(|| {
                    if retryable {
                        format!("identity refresh request failed for {user_id}")
                    } else {
                        format!("identity refresh failed for {user_id}")
                    }
                }),
            ),
            CoreEvent::BlobUploadPrepared { task_id, result } => {
                self.handle_blob_upload_prepared(task_id, result)
            }
            CoreEvent::BlobUploaded { task_id } => {
                self.handle_blob_uploaded(task_id)
            }
            CoreEvent::BlobDownloaded { task_id, destination, blob_ciphertext: _ } => {
                self.handle_blob_downloaded(task_id, destination)
            }
            CoreEvent::BlobTransferFailed { task_id, retryable, detail } => {
                self.handle_blob_transfer_failed(task_id, retryable, detail)
            }
            CoreEvent::TimerTriggered { timer_id } => self.handle_timer(timer_id),
            CoreEvent::UserConfirmedRebuild { conversation_id } => {
                self.rebuild_conversation(conversation_id)
            }
        }
    }

    fn import_deployment_bundle(
        &mut self,
        bundle: crate::model::DeploymentBundle,
    ) -> CoreResult<CoreOutput> {
        bundle.validate()?;
        self.state.deployment_bundle = Some(bundle);
        self.refresh_local_bundle()?;
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: self.state.local_bundle.is_some(),
                checkpoints_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(
                &self.state,
                vec![PersistOp::SaveDeployment, PersistOp::SaveLocalIdentity],
            )],
            view_model: None,
        })
    }

    fn import_identity_bundle(&mut self, bundle: IdentityBundle) -> CoreResult<CoreOutput> {
        IdentityManager::verify_identity_bundle(&bundle)?;
        let user_id = bundle.user_id.clone();
        self.state.contacts.insert(user_id.clone(), bundle);
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(
                &self.state,
                vec![PersistOp::SaveContact { user_id }],
            )],
            view_model: None,
        })
    }

    fn apply_identity_bundle_update(&mut self, bundle: IdentityBundle) -> CoreResult<CoreOutput> {
        IdentityManager::verify_identity_bundle(&bundle)?;
        let user_id = bundle.user_id.clone();
        let affected_conversations = self.affected_conversations_for_peer(&user_id);
        self.state.contacts.insert(user_id.clone(), bundle);

        let mut output = CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(
                &self.state,
                vec![PersistOp::SaveContact { user_id: user_id.clone() }],
            )],
            view_model: None,
        };
        for conversation_id in affected_conversations {
            self.mark_recovery_needed(&conversation_id, RecoveryReason::IdentityChanged);
            output = merge_outputs(output, self.reconcile_conversation_membership(conversation_id)?);
        }
        if let Some(device_id) = self
            .state
            .local_identity
            .as_ref()
            .map(|identity| identity.device_identity.device_id.clone())
        {
            output = merge_outputs(output, self.replay_pending_records_for_device(device_id)?);
        }
        self.merge_with_transport_flush(output)
    }

    fn create_or_load_identity(
        &mut self,
        mnemonic: Option<String>,
        device_name: Option<String>,
    ) -> CoreResult<CoreOutput> {
        let identity = if let Some(existing) = self.state.local_identity.clone() {
            if let Some(provided_mnemonic) = mnemonic.as_deref() {
                let recovered = IdentityManager::recover_user_root(provided_mnemonic)?;
                if recovered.user_identity.user_id != existing.user_identity.user_id {
                    return Err(CoreError::invalid_input(
                        "provided mnemonic does not match persisted local identity",
                    ));
                }
            }
            existing
        } else {
            IdentityManager::create_or_recover(mnemonic.as_deref(), device_name.as_deref())?
        };
        let (adapter, package) = crate::mls_adapter::MlsAdapter::bootstrap(&identity)?;
        let user_id = identity.user_identity.user_id.clone();
        let device_id = identity.device_identity.device_id.clone();
        self.state.local_identity = Some(identity);
        self.state.mls_adapter = Some(adapter);
        self.state.published_key_package = Some(package);
        self.state
            .sync_states
            .insert(device_id.clone(), SyncEngine::new_device_state(&device_id));
        self.refresh_local_bundle()?;
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                checkpoints_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(
                &self.state,
                vec![PersistOp::SaveLocalIdentity, PersistOp::SaveDeployment],
            )],
            view_model: Some(CoreViewModel {
                contacts: vec![ContactSummary {
                    user_id,
                    device_count: 1,
                }],
                banners: vec![SystemBanner {
                    status: SystemStatus::IdentityRefreshNeeded,
                    message: format!("local identity ready for {device_id}"),
                }],
                ..CoreViewModel::default()
            }),
        })
    }

    fn create_conversation(
        &mut self,
        peer_user_id: String,
        conversation_kind: ConversationKind,
    ) -> CoreResult<CoreOutput> {
        if conversation_kind != ConversationKind::Direct {
            return Err(CoreError::unsupported("phase 5 only supports direct conversations"));
        }
        let local_identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?;
        let contact_bundle = self
            .state
            .contacts
            .get(&peer_user_id)
            .ok_or_else(|| CoreError::invalid_input("peer identity bundle has not been imported"))?;
        let peer_device_ids: Vec<String> = contact_bundle
            .devices
            .iter()
            .filter(|d| matches!(d.status, crate::model::DeviceStatusKind::Active))
            .map(|d| d.device_id.clone())
            .collect();
        let local_conversation = ConversationManager::create_direct_conversation(
            &local_identity.user_identity.user_id,
            &local_identity.device_identity.device_id,
            &peer_user_id,
            &peer_device_ids,
        )?;
        let conversation_id = local_conversation.conversation.conversation_id.clone();
        let peer_keypackages: Vec<PeerDeviceKeyPackage> = contact_bundle
            .devices
            .iter()
            .filter(|d| matches!(d.status, crate::model::DeviceStatusKind::Active))
            .map(|device| PeerDeviceKeyPackage {
                user_id: peer_user_id.clone(),
                device_id: device.device_id.clone(),
                device_public_key: device.device_public_key.clone(),
                key_package_b64: device.keypackage_ref.object_ref.clone(),
            })
            .collect();
        let artifacts = self
            .state
            .mls_adapter
            .as_mut()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .create_conversation(&conversation_id, &peer_keypackages)?;
        let summary = self
            .state
            .mls_adapter
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("mls adapter missing after create"))?
            .export_group_summary(&conversation_id)?;
        self.state.mls_summaries.insert(conversation_id.clone(), summary);
        self.state.conversations.insert(conversation_id.clone(), local_conversation);

        let mut generated = Vec::new();
        for device_id in &peer_device_ids {
            generated.push(self.build_envelope(
                &conversation_id,
                device_id,
                MessageType::MlsCommit,
                artifacts.commit_b64.clone(),
            )?);
        }
        for welcome in &artifacts.welcomes {
            generated.push(self.build_envelope(
                &conversation_id,
                &welcome.recipient_device_id,
                MessageType::MlsWelcome,
                welcome.payload_b64.clone(),
            )?);
        }
        self.enqueue_envelopes(peer_user_id, generated.clone());
        self.merge_with_transport_flush(CoreOutput {
            state_update: CoreStateUpdate {
                conversations_changed: true,
                messages_changed: true,
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
                    conversation_id,
                    state: "active".into(),
                    last_message_type: Some(MessageType::MlsCommit),
                }],
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

    fn send_text_message(&mut self, conversation_id: String, plaintext: String) -> CoreResult<CoreOutput> {
        self.ensure_conversation_ready_for_send(&conversation_id)?;
        if plaintext.trim().is_empty() {
            return Err(CoreError::invalid_input("plaintext must not be empty"));
        }
        let payload = self
            .state
            .mls_adapter
            .as_mut()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .encrypt_application(&conversation_id, plaintext.as_bytes())?;
        let peer_user_id = self.peer_user_for_conversation(&conversation_id)?;
        let recipient_device_ids = self.recipient_device_ids(&conversation_id)?;
        let envelopes = recipient_device_ids
            .iter()
            .map(|device_id| {
                self.build_envelope(
                    &conversation_id,
                    device_id,
                    MessageType::MlsApplication,
                    payload.payload_b64.clone(),
                )
            })
            .collect::<CoreResult<Vec<_>>>()?;
        self.enqueue_envelopes(peer_user_id, envelopes.clone());
        self.merge_with_transport_flush(CoreOutput {
            state_update: CoreStateUpdate {
                messages_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(
                &self.state,
                vec![
                    PersistOp::SaveMlsState {
                        conversation_id: conversation_id.clone(),
                    },
                    PersistOp::SaveOutgoingEnvelope {
                        message_id: envelopes
                            .first()
                            .map(|envelope| envelope.message_id.clone())
                            .unwrap_or_default(),
                    },
                ],
            )],
            view_model: Some(CoreViewModel {
                messages: envelopes
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

    fn send_attachment_message(
        &mut self,
        conversation_id: String,
        attachment_descriptor: AttachmentDescriptor,
    ) -> CoreResult<CoreOutput> {
        self.ensure_conversation_ready_for_send(&conversation_id)?;
        let message_id = self.next_message_id(&conversation_id, "attachment");
        let metadata_json = serde_json::to_string(&attachment_descriptor).map_err(|error| {
            CoreError::invalid_input(format!("failed to encode attachment descriptor: {error}"))
        })?;
        let metadata_ciphertext = self
            .state
            .mls_adapter
            .as_mut()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .encrypt_application(&conversation_id, metadata_json.as_bytes())?
            .payload_b64;
        let task_id = format!("blob-upload:{message_id}");
        self.state.pending_blob_uploads.insert(
            task_id.clone(),
            PendingBlobUpload {
                task_id: task_id.clone(),
                conversation_id: conversation_id.clone(),
                descriptor: attachment_descriptor.clone(),
                message_id: message_id.clone(),
                metadata_ciphertext,
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

    fn download_attachment(
        &mut self,
        conversation_id: String,
        message_id: String,
        reference: String,
        destination: String,
    ) -> CoreResult<CoreOutput> {
        self.state.pending_blob_downloads.insert(
            format!("blob-download:{message_id}"),
            PendingBlobDownload {
                task_id: format!("blob-download:{message_id}"),
                conversation_id,
                message_id,
                reference,
                destination,
                retries: 0,
                in_flight: false,
            },
        );
        self.flush_pending_transport()
    }

    fn reconcile_conversation_membership(&mut self, conversation_id: String) -> CoreResult<CoreOutput> {
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

        if !reconcile.changed {
            if let Some(adapter) = self.state.mls_adapter.as_mut() {
                if let Ok(summary) = adapter.attempt_recovery(&conversation_id) {
                    self.state.mls_summaries.insert(conversation_id.clone(), summary);
                }
            }
            self.state.recovery_contexts.remove(&conversation_id);
            let mut output = CoreOutput {
                state_update: CoreStateUpdate {
                    conversations_changed: true,
                    ..CoreStateUpdate::default()
                },
                effects: vec![persist_effect(
                    &self.state,
                    vec![PersistOp::SaveConversation {
                        conversation_id: conversation_id.clone(),
                    }],
                )],
                view_model: Some(CoreViewModel {
                    conversations: vec![self.conversation_summary(&conversation_id)?],
                    ..CoreViewModel::default()
                }),
            };
            if let Some(device_id) = self
                .state
                .local_identity
                .as_ref()
                .map(|identity| identity.device_identity.device_id.clone())
            {
                output = merge_outputs(output, self.replay_pending_records_for_device(device_id)?);
            }
            return self.merge_with_transport_flush(output);
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
            generated.extend(self.welcome_envelopes_for_artifacts(
                &conversation_id,
                &artifacts,
            )?);
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

    fn sync_inbox(&mut self, device_id: String) -> CoreResult<CoreOutput> {
        if device_id.trim().is_empty() {
            return Err(CoreError::invalid_input("device_id must not be empty"));
        }
        let deployment = self
            .state
            .deployment_bundle
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("deployment bundle is not initialized"))?;
        let sync_state = self
            .state
            .sync_states
            .entry(device_id.clone())
            .or_insert_with(|| SyncEngine::new_device_state(&device_id));
        self.state.realtime_sessions.entry(device_id.clone()).or_default();
        let request_id = format!("get_head:{device_id}:{}", self.state.pending_requests.len() + 1);
        self.state.pending_requests.insert(
            request_id.clone(),
            PendingRequest::GetHead {
                device_id: device_id.clone(),
            },
        );
        Ok(CoreOutput {
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
                            endpoint: deployment.inbox_websocket_endpoint.clone(),
                            last_acked_seq: sync_state.checkpoint.last_acked_seq,
                            headers: self.device_runtime_headers()?,
                        },
                    },
                },
                CoreEffect::ExecuteHttpRequest {
                    request: HttpRequestEffect {
                        request_id,
                        method: HttpMethod::Get,
                        url: format!(
                            "{}/v1/inbox/{}/head",
                            deployment.inbox_http_endpoint.trim_end_matches('/'),
                            device_id
                        ),
                        headers: self.device_runtime_headers()?,
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
        })
    }

    fn device_runtime_headers(&self) -> CoreResult<BTreeMap<String, String>> {
        let deployment = self
            .state
            .deployment_bundle
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("deployment bundle is not initialized"))?;
        let auth = deployment.device_runtime_auth.as_ref().ok_or_else(|| {
            CoreError::invalid_state("device runtime auth is not initialized")
        })?;
        if auth.scheme != "bearer" {
            return Err(CoreError::invalid_state(
                "unsupported device runtime auth scheme",
            ));
        }
        let mut headers = BTreeMap::new();
        headers.insert("Authorization".into(), format!("Bearer {}", auth.token));
        Ok(headers)
    }

    fn refresh_identity_state(&mut self, user_id: String) -> CoreResult<CoreOutput> {
        let bundle = self
            .state
            .contacts
            .get(&user_id)
            .ok_or_else(|| CoreError::invalid_input("contact does not exist"))?;
        let reference = bundle
            .identity_bundle_ref
            .clone()
            .ok_or_else(|| {
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

    fn rebuild_conversation(&mut self, conversation_id: String) -> CoreResult<CoreOutput> {
        let (member_device_ids, last_message_type) = {
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
            )
        };
        if let Some(adapter) = self.state.mls_adapter.as_mut() {
            adapter.mark_needs_rebuild(&conversation_id);
            adapter.clear_conversation(&conversation_id);
        }
        self.state.recovery_contexts.remove(&conversation_id);
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
                    conversation_id,
                    state: "needs_rebuild".into(),
                    last_message_type,
                }],
                ..CoreViewModel::default()
            }),
        })
    }

    fn start_foreground_sync(&mut self) -> CoreResult<CoreOutput> {
        let device_id = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .device_identity
            .device_id
            .clone();
        let output = self.sync_inbox(device_id)?;
        self.merge_with_transport_flush(output)
    }

    fn handle_websocket_connected(&mut self, device_id: String) -> CoreResult<CoreOutput> {
        let last_known_seq = {
            let session = self.state.realtime_sessions.entry(device_id.clone()).or_default();
            session.connected = true;
            session.needs_reconnect = false;
            session.last_known_seq
        };

        let sync_state = self
            .state
            .sync_states
            .entry(device_id.clone())
            .or_insert_with(|| SyncEngine::new_device_state(&device_id));
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

    fn handle_websocket_disconnected(&mut self, device_id: String) -> CoreResult<CoreOutput> {
        let session = self.state.realtime_sessions.entry(device_id.clone()).or_default();
        session.connected = false;
        session.needs_reconnect = true;
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                checkpoints_changed: true,
                system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                ..CoreStateUpdate::default()
            },
            effects: vec![CoreEffect::ScheduleTimer {
                timer: TimerEffect {
                    timer_id: format!("sync:{device_id}"),
                    delay_ms: 0,
                },
            }],
            view_model: None,
        })
    }

    fn handle_realtime_event(&mut self, device_id: String, event: RealtimeEvent) -> CoreResult<CoreOutput> {
        match event {
            RealtimeEvent::HeadUpdated { seq } => {
                let sync_state = self
                    .state
                    .sync_states
                    .entry(device_id.clone())
                    .or_insert_with(|| SyncEngine::new_device_state(&device_id));
                SyncEngine::register_head(sync_state, seq);
                self.state.realtime_sessions.entry(device_id.clone()).or_default().last_known_seq = seq;
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
        }
    }

    fn handle_timer(&mut self, timer_id: String) -> CoreResult<CoreOutput> {
        if let Some(device_id) = timer_id.strip_prefix("sync:") {
            return self.sync_inbox(device_id.to_string());
        }
        if let Some(user_id) = timer_id.strip_prefix("refresh_identity:") {
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
        Ok(CoreOutput::default())
    }

    fn refresh_local_bundle(&mut self) -> CoreResult<()> {
        let Some(local_identity) = self.state.local_identity.as_ref() else {
            return Ok(());
        };
        let Some(deployment) = self.state.deployment_bundle.as_ref() else {
            self.state.local_bundle = None;
            return Ok(());
        };
        let package = self
            .state
            .published_key_package
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("published key package missing"))?;
        self.state.local_bundle = Some(IdentityManager::export_identity_bundle(
            local_identity,
            deployment,
            package.key_package_ref.clone(),
            package.expires_at,
        )?);
        Ok(())
    }

    fn affected_conversations_for_peer(&self, peer_user_id: &str) -> Vec<String> {
        self.state
            .conversations
            .iter()
            .filter_map(|(conversation_id, state)| {
                if state.peer_user_id == peer_user_id {
                    Some(conversation_id.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    fn peer_active_device_ids(&self, peer_user_id: &str) -> CoreResult<Vec<String>> {
        let bundle = self
            .state
            .contacts
            .get(peer_user_id)
            .ok_or_else(|| CoreError::invalid_input("peer identity bundle has not been imported"))?;
        let devices: Vec<String> = bundle
            .devices
            .iter()
            .filter(|device| matches!(device.status, crate::model::DeviceStatusKind::Active))
            .map(|device| device.device_id.clone())
            .collect();
        if devices.is_empty() {
            return Err(CoreError::invalid_input(
                "peer identity bundle does not contain any active devices",
            ));
        }
        Ok(devices)
    }

    fn peer_key_packages(
        &self,
        peer_user_id: &str,
        device_ids: &[String],
    ) -> CoreResult<Vec<PeerDeviceKeyPackage>> {
        let wanted: BTreeSet<String> = device_ids.iter().cloned().collect();
        let bundle = self
            .state
            .contacts
            .get(peer_user_id)
            .ok_or_else(|| CoreError::invalid_input("peer identity bundle has not been imported"))?;
        Ok(bundle
            .devices
            .iter()
            .filter(|device| wanted.contains(&device.device_id))
            .map(|device| PeerDeviceKeyPackage {
                user_id: peer_user_id.to_string(),
                device_id: device.device_id.clone(),
                device_public_key: device.device_public_key.clone(),
                key_package_b64: device.keypackage_ref.object_ref.clone(),
            })
            .collect())
    }

    fn peer_user_for_conversation(&self, conversation_id: &str) -> CoreResult<String> {
        self.state
            .conversations
            .get(conversation_id)
            .map(|state| state.peer_user_id.clone())
            .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))
    }

    fn recipient_device_ids(&self, conversation_id: &str) -> CoreResult<Vec<String>> {
        let local_user_id = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .user_identity
            .user_id
            .clone();
        Ok(self
            .state
            .conversations
            .get(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?
            .conversation
            .member_devices
            .iter()
            .filter(|member| member.user_id != local_user_id)
            .map(|member| member.device_id.clone())
            .collect())
    }

    fn enqueue_envelopes(&mut self, peer_user_id: String, envelopes: Vec<Envelope>) {
        for envelope in envelopes {
            self.state.outbox.push(envelope.clone());
            self.state.pending_outbox.push(PendingOutboxItem {
                envelope,
                peer_user_id: peer_user_id.clone(),
                retries: 0,
                in_flight: false,
            });
        }
    }

    fn ensure_conversation_ready_for_send(&self, conversation_id: &str) -> CoreResult<()> {
        if conversation_id.trim().is_empty() {
            return Err(CoreError::invalid_input("conversation_id must not be empty"));
        }
        let conversation = self
            .state
            .conversations
            .get(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?;
        if conversation.conversation.state == ConversationState::NeedsRebuild {
            return Err(CoreError::invalid_state(
                "conversation needs rebuild before sending new messages",
            ));
        }
        if conversation.recovery_status != RecoveryStatus::Healthy {
            return Err(CoreError::temporary_failure(
                "conversation membership is still recovering",
            ));
        }
        Ok(())
    }

    fn mark_recovery_needed(&mut self, conversation_id: &str, reason: RecoveryReason) {
        self.state
            .recovery_contexts
            .entry(conversation_id.to_string())
            .and_modify(|context| context.reason = reason)
            .or_insert(RecoveryContext {
                conversation_id: conversation_id.to_string(),
                reason,
                sync_attempted: false,
                identity_refresh_attempted: false,
                identity_refresh_retry_count: 0,
            });
        if let Some(state) = self.state.conversations.get_mut(conversation_id) {
            state.recovery_status = RecoveryStatus::NeedsRecovery;
        }
        if let Some(adapter) = self.state.mls_adapter.as_mut() {
            adapter.mark_recovery_needed(conversation_id);
        }
    }

    fn build_envelope(
        &self,
        conversation_id: &str,
        recipient_device_id: &str,
        message_type: MessageType,
        payload_b64: String,
    ) -> CoreResult<Envelope> {
        let identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?;
        Ok(Envelope {
            version: crate::model::CURRENT_MODEL_VERSION.to_string(),
            message_id: self.next_message_id(conversation_id, recipient_device_id),
            conversation_id: conversation_id.to_string(),
            sender_user_id: identity.user_identity.user_id.clone(),
            sender_device_id: identity.device_identity.device_id.clone(),
            recipient_device_id: recipient_device_id.to_string(),
            created_at: (self.state.outbox.len() + self.state.pending_outbox.len() + 1) as u64,
            message_type,
            inline_ciphertext: Some(payload_b64.clone()),
            storage_refs: vec![],
            delivery_class: DeliveryClass::Normal,
            wake_hint: None,
            sender_proof: SenderProof {
                proof_type: "device_signature".into(),
                value: identity.sign_sender_proof(payload_b64.as_bytes()),
            },
        })
    }

    fn conversation_summary(&self, conversation_id: &str) -> CoreResult<ConversationSummary> {
        let conversation = self
            .state
            .conversations
            .get(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?;
        Ok(ConversationSummary {
            conversation_id: conversation_id.to_string(),
            state: match conversation.recovery_status {
                RecoveryStatus::Healthy => "active".into(),
                RecoveryStatus::NeedsRecovery => "needs_recovery".into(),
                RecoveryStatus::NeedsRebuild => "needs_rebuild".into(),
            },
            last_message_type: conversation.last_message_type,
        })
    }

    fn build_control_membership_changed_messages(
        &self,
        conversation_id: &str,
        peer_user_id: &str,
        peer_active_device_ids: &[String],
    ) -> CoreResult<Vec<Envelope>> {
        let payload = format!(
            "membership_changed:{}:{}:{}",
            conversation_id,
            peer_user_id,
            peer_active_device_ids.len()
        );
        peer_active_device_ids
            .iter()
            .map(|device_id| {
                self.build_envelope(
                    conversation_id,
                    device_id,
                    MessageType::ControlDeviceMembershipChanged,
                    payload.clone(),
                )
            })
            .collect()
    }

    fn commit_envelopes_for_artifacts(
        &self,
        conversation_id: &str,
        peer_active_device_ids: &[String],
        artifacts: &CreateConversationArtifacts,
    ) -> CoreResult<Vec<Envelope>> {
        peer_active_device_ids
            .iter()
            .map(|device_id| {
                self.build_envelope(
                    conversation_id,
                    device_id,
                    MessageType::MlsCommit,
                    artifacts.commit_b64.clone(),
                )
            })
            .collect()
    }

    fn welcome_envelopes_for_artifacts(
        &self,
        conversation_id: &str,
        artifacts: &CreateConversationArtifacts,
    ) -> CoreResult<Vec<Envelope>> {
        artifacts
            .welcomes
            .iter()
            .map(|welcome| {
                self.build_envelope(
                    conversation_id,
                    &welcome.recipient_device_id,
                    MessageType::MlsWelcome,
                    welcome.payload_b64.clone(),
                )
            })
            .collect()
    }

    fn commit_envelopes_for_remove(
        &self,
        conversation_id: &str,
        peer_active_device_ids: &[String],
        artifacts: &RemoveMembersArtifacts,
    ) -> CoreResult<Vec<Envelope>> {
        peer_active_device_ids
            .iter()
            .map(|device_id| {
                self.build_envelope(
                    conversation_id,
                    device_id,
                    MessageType::MlsCommit,
                    artifacts.commit_b64.clone(),
                )
            })
            .collect()
    }

    fn next_message_id(&self, conversation_id: &str, suffix: &str) -> String {
        format!(
            "msg:{}:{}:{}",
            conversation_id,
            self.state.outbox.len() + self.state.pending_outbox.len() + 1,
            suffix
        )
    }

    fn merge_with_transport_flush(&mut self, output: CoreOutput) -> CoreResult<CoreOutput> {
        Ok(merge_outputs(output, self.flush_pending_transport()?))
    }

    fn flush_pending_transport(&mut self) -> CoreResult<CoreOutput> {
        let mut output = CoreOutput::default();
        output = merge_outputs(output, self.flush_outbox()?);
        output = merge_outputs(output, self.flush_pending_acks()?);
        output = merge_outputs(output, self.flush_blob_uploads()?);
        output = merge_outputs(output, self.flush_blob_downloads()?);
        Ok(output)
    }

    fn flush_outbox(&mut self) -> CoreResult<CoreOutput> {
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

    fn flush_pending_acks(&mut self) -> CoreResult<CoreOutput> {
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

    fn flush_blob_uploads(&mut self) -> CoreResult<CoreOutput> {
        let keys: Vec<String> = self.state.pending_blob_uploads.keys().cloned().collect();
        let mut effects = Vec::new();
        for task_id in keys {
            let Some(task) = self.state.pending_blob_uploads.get(&task_id).cloned() else {
                continue;
            };
            if task.in_flight || task.retries >= MAX_TRANSPORT_RETRIES {
                continue;
            }
            if let Some(prepared) = &task.prepared_upload {
                effects.push(CoreEffect::UploadBlob {
                    upload: BlobUploadRequest {
                        task_id: task.task_id.clone(),
                        source_path: task.descriptor.source.clone(),
                        upload_target: prepared.upload_target.clone(),
                        upload_headers: prepared.upload_headers.clone(),
                        blob_ref: prepared.blob_ref.clone(),
                    },
                });
            } else {
                effects.push(CoreEffect::PrepareBlobUpload {
                    upload: PrepareBlobUploadRequest {
                        task_id: task.task_id.clone(),
                        conversation_id: task.conversation_id.clone(),
                        message_id: task.message_id.clone(),
                        mime_type: task.descriptor.mime_type.clone(),
                        size_bytes: task.descriptor.size_bytes,
                        file_name: task.descriptor.file_name.clone(),
                        headers: self.device_runtime_headers()?,
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

    fn flush_blob_downloads(&mut self) -> CoreResult<CoreOutput> {
        let keys: Vec<String> = self.state.pending_blob_downloads.keys().cloned().collect();
        let mut effects = Vec::new();
        for task_id in keys {
            let Some(task) = self.state.pending_blob_downloads.get(&task_id).cloned() else {
                continue;
            };
            if task.in_flight || task.retries >= MAX_TRANSPORT_RETRIES {
                continue;
            }
            effects.push(CoreEffect::DownloadBlob {
                download: BlobDownloadRequest {
                    task_id: task.task_id.clone(),
                    blob_ref: task.reference.clone(),
                    download_target: task.reference.clone(),
                    destination_path: task.destination.clone(),
                    download_headers: BTreeMap::new(),
                },
            });
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

    fn build_append_request(&mut self, item: &PendingOutboxItem) -> CoreResult<HttpRequestEffect> {
        let bundle = self
            .state
            .contacts
            .get(&item.peer_user_id)
            .ok_or_else(|| CoreError::invalid_input("peer identity bundle has not been imported"))?;
        let device_profile = bundle
            .devices
            .iter()
            .find(|device| device.device_id == item.envelope.recipient_device_id)
            .ok_or_else(|| CoreError::invalid_input("recipient device profile is missing"))?;
        let request_id = format!("append:{}:{}", item.envelope.message_id, self.state.pending_requests.len() + 1);
        self.state.pending_requests.insert(
            request_id.clone(),
            PendingRequest::AppendEnvelope {
                message_id: item.envelope.message_id.clone(),
                peer_user_id: item.peer_user_id.clone(),
            },
        );
        let body = AppendEnvelopeRequest {
            version: crate::model::CURRENT_MODEL_VERSION.to_string(),
            recipient_device_id: item.envelope.recipient_device_id.clone(),
            envelope: item.envelope.clone(),
        };
        let mut headers = BTreeMap::new();
        headers.insert(
            "Authorization".into(),
            format!("Bearer {}", device_profile.inbox_append_capability.signature),
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
            body: Some(serde_json::to_string(&body).map_err(|error| {
                CoreError::invalid_input(format!("failed to encode append request: {error}"))
            })?),
        })
    }

    fn build_ack_request(&mut self, ack: &Ack) -> CoreResult<HttpRequestEffect> {
        let deployment = self
            .state
            .deployment_bundle
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("deployment bundle is not initialized"))?;
        let request_id = format!("ack:{}:{}", ack.device_id, self.state.pending_requests.len() + 1);
        self.state.pending_requests.insert(
            request_id.clone(),
            PendingRequest::Ack {
                device_id: ack.device_id.clone(),
                ack_seq: ack.ack_seq,
            },
        );
        let mut headers = self.device_runtime_headers()?;
        headers.insert("Content-Type".into(), "application/json".into());
        let request = AckRequest { ack: ack.clone() };
        Ok(HttpRequestEffect {
            request_id,
            method: HttpMethod::Post,
            url: format!(
                "{}/v1/inbox/{}/ack",
                deployment.inbox_http_endpoint.trim_end_matches('/'),
                ack.device_id
            ),
            headers,
            body: Some(serde_json::to_string(&request).map_err(|error| {
                CoreError::invalid_input(format!("failed to encode ack request: {error}"))
            })?),
        })
    }

    fn issue_fetch(&mut self, device_id: String, decision: SyncDecision) -> CoreResult<CoreOutput> {
        let deployment = self
            .state
            .deployment_bundle
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("deployment bundle is not initialized"))?;
        let limit = decision.to_seq.saturating_sub(decision.from_seq).saturating_add(1).max(1);
        let request_id = format!("fetch:{device_id}:{}", self.state.pending_requests.len() + 1);
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
                        deployment.inbox_http_endpoint.trim_end_matches('/'),
                        fetch.device_id,
                        fetch.from_seq,
                        fetch.limit
                    ),
                    headers: self.device_runtime_headers()?,
                    body: None,
                },
            }],
            view_model: None,
        })
    }

    fn handle_http_response(
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
                let head: GetHeadResult = serde_json::from_str(body.as_deref().unwrap_or("{\"head_seq\":0}"))
                    .map_err(|error| CoreError::invalid_input(format!("failed to decode head response: {error}")))?;
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
                let response: FetchMessagesResult = serde_json::from_str(body.as_deref().unwrap_or("{\"to_seq\":0,\"records\":[]}"))
                    .map_err(|error| CoreError::invalid_input(format!("failed to decode fetch response: {error}")))?;
                self.handle_inbox_records(device_id, response.records, response.to_seq)
            }
            PendingRequest::AppendEnvelope { message_id, .. } => {
                let result: AppendEnvelopeResult =
                    serde_json::from_str(body.as_deref().unwrap_or("{\"accepted\":false,\"seq\":0}"))
                        .map_err(|error| {
                            CoreError::invalid_input(format!(
                                "failed to decode append response: {error}"
                            ))
                        })?;
                if !result.accepted {
                    return Err(CoreError::temporary_failure(
                        "append response was not accepted",
                    ));
                }
                self.state
                    .pending_outbox
                    .retain(|item| item.envelope.message_id != message_id);
                self.flush_pending_transport()
            }
            PendingRequest::Ack { device_id, .. } => {
                let result: AckResult =
                    serde_json::from_str(body.as_deref().unwrap_or("{\"accepted\":false,\"ack_seq\":0}"))
                        .map_err(|error| {
                            CoreError::invalid_input(format!(
                                "failed to decode ack response: {error}"
                            ))
                        })?;
                if !result.accepted {
                    return Err(CoreError::temporary_failure(
                        "ack response was not accepted",
                    ));
                }
                self.state.pending_acks.remove(&device_id);
                self.flush_pending_transport()
            }
        }
    }

    fn handle_http_failure(
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
                        return Ok(CoreOutput {
                            state_update: CoreStateUpdate {
                                system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                                ..CoreStateUpdate::default()
                            },
                            effects: vec![CoreEffect::ScheduleTimer {
                                timer: TimerEffect {
                                    timer_id: format!("retry_append:{message_id}"),
                                    delay_ms: 0,
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
                        return Ok(CoreOutput {
                            state_update: CoreStateUpdate {
                                system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                                ..CoreStateUpdate::default()
                            },
                            effects: vec![CoreEffect::ScheduleTimer {
                                timer: TimerEffect {
                                    timer_id: format!("retry_ack:{device_id}"),
                                    delay_ms: 0,
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
                                format!("ack request failed for {device_id}")
                            }),
                        },
                    }],
                    view_model: None,
                })
            }
            PendingRequest::GetHead { device_id } | PendingRequest::FetchMessages { device_id, .. } => {
                Ok(CoreOutput {
                    state_update: CoreStateUpdate {
                        system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                        ..CoreStateUpdate::default()
                    },
                    effects: if retryable {
                        vec![CoreEffect::ScheduleTimer {
                            timer: TimerEffect {
                                timer_id: format!("sync:{device_id}"),
                                delay_ms: 0,
                            },
                        }]
                    } else {
                        vec![CoreEffect::EmitUserNotification {
                            notification: UserNotificationEffect {
                                status: SystemStatus::TemporaryNetworkFailure,
                                message: detail.unwrap_or_else(|| {
                                    format!("sync request failed for {device_id}")
                                }),
                            },
                        }]
                    },
                    view_model: None,
                })
            }
        }
    }

    fn handle_blob_upload_prepared(
        &mut self,
        task_id: String,
        result: PrepareBlobUploadResult,
    ) -> CoreResult<CoreOutput> {
        let task = self
            .state
            .pending_blob_uploads
            .get_mut(&task_id)
            .ok_or_else(|| CoreError::invalid_input("unknown blob upload task"))?;
        task.prepared_upload = Some(result);
        task.in_flight = false;
        self.flush_pending_transport()
    }

    fn handle_blob_uploaded(&mut self, task_id: String) -> CoreResult<CoreOutput> {
        let task = self
            .state
            .pending_blob_uploads
            .remove(&task_id)
            .ok_or_else(|| CoreError::invalid_input("unknown blob upload task"))?;
        let peer_user_id = self.peer_user_for_conversation(&task.conversation_id)?;
        let recipients = self.recipient_device_ids(&task.conversation_id)?;
        let prepared = task.prepared_upload.ok_or_else(|| {
            CoreError::invalid_state("blob upload completed before upload target was prepared")
        })?;
        let final_ref = prepared
            .download_target
            .clone()
            .unwrap_or(prepared.blob_ref.clone());
        let mut envelopes = Vec::new();
        for recipient in recipients {
            let mut envelope = self.build_envelope(
                &task.conversation_id,
                &recipient,
                MessageType::MlsApplication,
                task.metadata_ciphertext.clone(),
            )?;
            envelope.storage_refs.push(StorageRef {
                kind: "attachment".into(),
                object_ref: final_ref.clone(),
                size_bytes: task.descriptor.size_bytes,
                mime_type: task.descriptor.mime_type.clone(),
                expires_at: prepared.expires_at,
            });
            envelopes.push(envelope);
        }
        self.enqueue_envelopes(peer_user_id, envelopes);
        self.flush_pending_transport()
    }

    fn handle_blob_downloaded(
        &mut self,
        task_id: String,
        _destination: String,
    ) -> CoreResult<CoreOutput> {
        self.state.pending_blob_downloads.remove(&task_id);
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                messages_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![],
            view_model: None,
        })
    }

    fn handle_blob_transfer_failed(
        &mut self,
        task_id: String,
        retryable: bool,
        detail: Option<String>,
    ) -> CoreResult<CoreOutput> {
        if let Some(task) = self.state.pending_blob_uploads.get_mut(&task_id) {
            task.in_flight = false;
            task.retries = task.retries.saturating_add(1);
            if retryable && task.retries < MAX_TRANSPORT_RETRIES {
                return Ok(CoreOutput {
                    state_update: CoreStateUpdate {
                        system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                        ..CoreStateUpdate::default()
                    },
                    effects: vec![CoreEffect::ScheduleTimer {
                        timer: TimerEffect {
                            timer_id: format!("retry_blob_upload:{task_id}"),
                            delay_ms: 0,
                        },
                    }],
                    view_model: None,
                });
            }
            return Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::AttachmentUploadFailed],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect {
                        status: SystemStatus::AttachmentUploadFailed,
                        message: detail.unwrap_or_else(|| "attachment upload failed".into()),
                    },
                }],
                view_model: None,
            });
        }
        if let Some(task) = self.state.pending_blob_downloads.get_mut(&task_id) {
            task.in_flight = false;
            task.retries = task.retries.saturating_add(1);
            if retryable && task.retries < MAX_TRANSPORT_RETRIES {
                return Ok(CoreOutput {
                    state_update: CoreStateUpdate {
                        messages_changed: true,
                        system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                        ..CoreStateUpdate::default()
                    },
                    effects: vec![CoreEffect::ScheduleTimer {
                        timer: TimerEffect {
                            timer_id: format!("retry_blob_download:{task_id}"),
                            delay_ms: 0,
                        },
                    }],
                    view_model: None,
                });
            }
        }
        self.state.pending_blob_downloads.remove(&task_id);
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                ..CoreStateUpdate::default()
            },
            effects: vec![],
            view_model: None,
        })
    }

    fn handle_inbox_records(
        &mut self,
        device_id: String,
        records: Vec<InboxRecord>,
        to_seq: u64,
    ) -> CoreResult<CoreOutput> {
        let mut fresh_records = {
            let sync_state = self
                .state
                .sync_states
                .entry(device_id.clone())
                .or_insert_with(|| SyncEngine::new_device_state(&device_id));
            SyncEngine::register_fetch(sync_state, &records, to_seq)
        };
        fresh_records.sort_by_key(|record| record.seq);
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
        for record in fresh_records {
            record.validate()?;
            if record.recipient_device_id != device_id {
                return Err(CoreError::invalid_input(
                    "fetched inbox record recipient_device_id does not match target device",
                ));
            }
            self.ensure_local_conversation_for_record(&device_id, &local_user_id, &record);
            let conversation_id = record.envelope.conversation_id.clone();
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
                    MessageType::MlsApplication | MessageType::MlsCommit | MessageType::MlsWelcome => {
                        match self
                            .state
                            .mls_adapter
                            .as_mut()
                            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
                            .ingest_message(
                                &conversation_id,
                                &record.envelope.sender_device_id,
                                record.envelope.message_type,
                                record.envelope.inline_ciphertext.as_deref().unwrap_or_default(),
                            )? {
                            IngestResult::AppliedApplication(_) | IngestResult::AppliedCommit { .. }
                            | IngestResult::AppliedWelcome { .. } => {
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
                                self.state.recovery_contexts.remove(&conversation_id);
                                if let Some(state) =
                                    self.state.conversations.get_mut(&conversation_id)
                                {
                                    if state.conversation.state != ConversationState::NeedsRebuild {
                                        state.recovery_status = RecoveryStatus::Healthy;
                                    }
                                }
                                ackable = true;
                            }
                            IngestResult::PendingRetry => {
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
                                output = merge_outputs(
                                    output,
                                    self.advance_recovery(&conversation_id)?,
                                );
                            }
                            IngestResult::NeedsRebuild => {
                                output = merge_outputs(
                                    output,
                                    self.rebuild_conversation(conversation_id.clone())?,
                                );
                            }
                        }
                    }
                    _ => {
                        ackable = true;
                        if apply_effect.identity_refresh_needed {
                            let peer_user_id = self.peer_user_for_conversation(&conversation_id)?;
                            output =
                                merge_outputs(output, self.refresh_identity_state(peer_user_id)?);
                        }
                        if apply_effect.membership_refresh_needed {
                            output = merge_outputs(
                                output,
                                self.reconcile_conversation_membership(conversation_id.clone())?,
                            );
                        }
                        if apply_effect.needs_rebuild {
                            output = merge_outputs(
                                output,
                                self.rebuild_conversation(conversation_id.clone())?,
                            );
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
                contiguous_ack = record.seq.max(contiguous_ack);
            }
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
        }
        self.merge_with_transport_flush(output)
    }

    fn ensure_local_conversation_for_record(
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
                last_known_peer_active_devices: BTreeSet::from([record.envelope.sender_device_id.clone()]),
                recovery_status: RecoveryStatus::Healthy,
            });
    }

    fn recovery_reason_for_record(&self, conversation_id: &str) -> RecoveryReason {
        if self.state.mls_summaries.contains_key(conversation_id) {
            RecoveryReason::MissingCommit
        } else {
            RecoveryReason::MissingWelcome
        }
    }

    fn advance_recovery(&mut self, conversation_id: &str) -> CoreResult<CoreOutput> {
        enum RecoveryAction {
            Sync,
            RefreshIdentity,
            Rebuild,
        }

        let Some(action) = ({
            let Some(context) = self.state.recovery_contexts.get_mut(conversation_id) else {
                return Ok(CoreOutput::default());
            };
            if !context.sync_attempted {
                context.sync_attempted = true;
                Some(RecoveryAction::Sync)
            } else if matches!(
                context.reason,
                RecoveryReason::MissingWelcome
                    | RecoveryReason::MembershipChanged
                    | RecoveryReason::IdentityChanged
            ) && !context.identity_refresh_attempted
            {
                context.identity_refresh_attempted = true;
                Some(RecoveryAction::RefreshIdentity)
            } else {
                Some(RecoveryAction::Rebuild)
            }
        }) else {
            return Ok(CoreOutput::default());
        };

        match action {
            RecoveryAction::Sync => {
                let device_id = self
                .state
                .local_identity
                .as_ref()
                .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
                .device_identity
                .device_id
                .clone();
                self.sync_inbox(device_id)
            }
            RecoveryAction::RefreshIdentity => {
                let user_id = self.peer_user_for_conversation(conversation_id)?;
                self.refresh_identity_state(user_id)
            }
            RecoveryAction::Rebuild => self.rebuild_conversation(conversation_id.to_string()),
        }
    }

    fn handle_unsuccessful_request(
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
                            return Ok(CoreOutput {
                                state_update: CoreStateUpdate {
                                    system_statuses_changed: vec![
                                        SystemStatus::TemporaryNetworkFailure,
                                    ],
                                    ..CoreStateUpdate::default()
                                },
                                effects: vec![CoreEffect::ScheduleTimer {
                                    timer: TimerEffect {
                                        timer_id: format!("retry_append:{message_id}"),
                                        delay_ms: 0,
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
                            return Ok(CoreOutput {
                                state_update: CoreStateUpdate {
                                    system_statuses_changed: vec![
                                        SystemStatus::TemporaryNetworkFailure,
                                    ],
                                    ..CoreStateUpdate::default()
                                },
                                effects: vec![CoreEffect::ScheduleTimer {
                                    timer: TimerEffect {
                                        timer_id: format!("retry_ack:{device_id}"),
                                        delay_ms: 0,
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
                            message: body.unwrap_or_else(|| {
                                format!("ack request returned status {status}")
                            }),
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
                    timer: TimerEffect {
                        timer_id: format!("sync:{device_id}"),
                        delay_ms: 0,
                    },
                }],
                view_model: None,
            }),
            PendingRequest::FetchMessages { device_id, .. } => Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::ScheduleTimer {
                    timer: TimerEffect {
                        timer_id: format!("sync:{device_id}"),
                        delay_ms: 0,
                    },
                }],
                view_model: None,
            }),
        }
    }

    fn rebuild_affected_conversations_for_peer(
        &mut self,
        peer_user_id: &str,
        message: String,
    ) -> CoreResult<CoreOutput> {
        let mut output = CoreOutput {
            state_update: CoreStateUpdate {
                conversations_changed: true,
                system_statuses_changed: vec![SystemStatus::ConversationNeedsRebuild],
                ..CoreStateUpdate::default()
            },
            effects: vec![CoreEffect::EmitUserNotification {
                notification: UserNotificationEffect {
                    status: SystemStatus::ConversationNeedsRebuild,
                    message,
                },
            }],
            view_model: None,
        };
        for conversation_id in self.affected_conversations_for_peer(peer_user_id) {
            output = merge_outputs(output, self.rebuild_conversation(conversation_id)?);
        }
        Ok(output)
    }

    fn handle_identity_refresh_failure(
        &mut self,
        user_id: &str,
        message: String,
    ) -> CoreResult<CoreOutput> {
        let affected_conversations = self.affected_conversations_for_peer(user_id);
        let mut should_retry = false;
        for conversation_id in &affected_conversations {
            if let Some(context) = self.state.recovery_contexts.get_mut(conversation_id) {
                context.identity_refresh_attempted = true;
                context.identity_refresh_retry_count =
                    context.identity_refresh_retry_count.saturating_add(1);
                if context.identity_refresh_retry_count < MAX_TRANSPORT_RETRIES {
                    should_retry = true;
                }
            }
        }
        if should_retry {
            Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    contacts_changed: true,
                    system_statuses_changed: vec![SystemStatus::IdentityRefreshNeeded],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::ScheduleTimer {
                    timer: TimerEffect {
                        timer_id: format!("refresh_identity:{user_id}"),
                        delay_ms: 0,
                    },
                }],
                view_model: None,
            })
        } else {
            self.rebuild_affected_conversations_for_peer(user_id, message)
        }
    }

    fn replay_pending_records_for_device(&mut self, device_id: String) -> CoreResult<CoreOutput> {
        let records = {
            let Some(sync_state) = self.state.sync_states.get_mut(&device_id) else {
                return Ok(CoreOutput::default());
            };
            if sync_state.pending_records.is_empty() {
                return Ok(CoreOutput::default());
            }
            let records: Vec<InboxRecord> = sync_state.pending_records.values().cloned().collect();
            for record in &records {
                sync_state.seen_message_ids.remove(&record.message_id);
            }
            records
        };
        let to_seq = records.iter().map(|record| record.seq).max().unwrap_or(0);
        self.handle_inbox_records(device_id, records, to_seq)
    }
}

fn current_timestamp_hint(outbox_len: usize) -> u64 {
    outbox_len as u64 + 1
}

fn persist_effect(state: &CoreState, ops: Vec<PersistOp>) -> CoreEffect {
    let mut unique = BTreeSet::new();
    unique.extend(ops);
    CoreEffect::PersistState {
        persist: PersistStateEffect {
            ops: unique.into_iter().collect(),
            snapshot: Some(build_persistence_snapshot(state)),
        },
    }
}

fn build_persistence_snapshot(state: &CoreState) -> CorePersistenceSnapshot {
    let persisted_mls_states: Vec<PersistedMlsState> = state
        .mls_summaries
        .iter()
        .map(|(conversation_id, summary)| PersistedMlsState {
            conversation_id: conversation_id.clone(),
            summary: summary.clone(),
            serialized_group_state: state
                .mls_adapter
                .as_ref()
                .and_then(|adapter| adapter.export_persisted_group_state(conversation_id).ok()),
        })
        .collect();
    let mls_state_persistence_blocked = !persisted_mls_states.is_empty()
        && persisted_mls_states
            .iter()
            .any(|state| state.serialized_group_state.is_none());

    CorePersistenceSnapshot {
        local_identity: state
            .local_identity
            .clone()
            .map(|identity| PersistedLocalIdentity { state: identity }),
        deployment: state.deployment_bundle.clone().map(|deployment_bundle| PersistedDeployment {
            deployment_bundle,
            local_bundle: state.local_bundle.clone(),
            published_key_package: state.published_key_package.clone(),
        }),
        contacts: state
            .contacts
            .iter()
            .map(|(user_id, bundle)| PersistedContact {
                user_id: user_id.clone(),
                bundle: bundle.clone(),
            })
            .collect(),
        conversations: state
            .conversations
            .iter()
            .map(|(conversation_id, conversation)| PersistedConversation {
                conversation_id: conversation_id.clone(),
                state: conversation.clone(),
            })
            .collect(),
        sync_states: state
            .sync_states
            .iter()
            .map(|(device_id, sync_state)| PersistedSyncState {
                device_id: device_id.clone(),
                state: sync_state.clone(),
            })
            .collect(),
        mls_states: persisted_mls_states,
        pending_outbox: state
            .pending_outbox
            .iter()
            .map(|item| PersistedOutgoingEnvelope {
                message_id: item.envelope.message_id.clone(),
                envelope: item.envelope.clone(),
                peer_user_id: item.peer_user_id.clone(),
                retries: item.retries,
            })
            .collect(),
        pending_acks: state
            .pending_acks
            .iter()
            .map(|(device_id, pending)| PersistedPendingAck {
                device_id: device_id.clone(),
                ack: pending.ack.clone(),
                retries: pending.retries,
            })
            .collect(),
        pending_blob_transfers: state
            .pending_blob_uploads
            .values()
            .map(|task| PersistedPendingBlobTransfer::Upload {
                task_id: task.task_id.clone(),
                conversation_id: task.conversation_id.clone(),
                message_id: task.message_id.clone(),
                source: task.descriptor.source.clone(),
                mime_type: task.descriptor.mime_type.clone(),
                size_bytes: task.descriptor.size_bytes,
                file_name: task.descriptor.file_name.clone(),
                metadata_ciphertext: task.metadata_ciphertext.clone(),
                prepared_upload: task.prepared_upload.clone(),
                retries: task.retries,
            })
            .chain(
                state
                    .pending_blob_downloads
                    .values()
                    .map(|task| PersistedPendingBlobTransfer::Download {
                        task_id: task.task_id.clone(),
                        conversation_id: task.conversation_id.clone(),
                        message_id: task.message_id.clone(),
                        reference: task.reference.clone(),
                        destination: task.destination.clone(),
                        retries: task.retries,
                    }),
            )
            .collect(),
        recovery_contexts: state
            .recovery_contexts
            .iter()
            .map(|(conversation_id, context)| PersistedRecoveryContext {
                conversation_id: conversation_id.clone(),
                reason: match context.reason {
                    RecoveryReason::MissingCommit => PersistedRecoveryReason::MissingCommit,
                    RecoveryReason::MissingWelcome => PersistedRecoveryReason::MissingWelcome,
                    RecoveryReason::MembershipChanged => {
                        PersistedRecoveryReason::MembershipChanged
                    }
                    RecoveryReason::IdentityChanged => PersistedRecoveryReason::IdentityChanged,
                },
                sync_attempted: context.sync_attempted,
                identity_refresh_attempted: context.identity_refresh_attempted,
                identity_refresh_retry_count: context.identity_refresh_retry_count,
            })
            .collect(),
        realtime_sessions: state
            .realtime_sessions
            .iter()
            .map(|(device_id, session)| PersistedRealtimeSession {
                device_id: device_id.clone(),
                last_known_seq: session.last_known_seq,
                needs_reconnect: session.needs_reconnect,
            })
            .collect(),
        mls_state_persistence_blocked,
    }
}

fn merge_outputs(mut base: CoreOutput, mut next: CoreOutput) -> CoreOutput {
    base.state_update.conversations_changed |= next.state_update.conversations_changed;
    base.state_update.messages_changed |= next.state_update.messages_changed;
    base.state_update.contacts_changed |= next.state_update.contacts_changed;
    base.state_update.checkpoints_changed |= next.state_update.checkpoints_changed;
    base.state_update
        .system_statuses_changed
        .append(&mut next.state_update.system_statuses_changed);
    base.effects.append(&mut next.effects);
    match (&mut base.view_model, next.view_model.take()) {
        (Some(base_view), Some(mut next_view)) => {
            base_view.conversations.append(&mut next_view.conversations);
            base_view.messages.append(&mut next_view.messages);
            base_view.contacts.append(&mut next_view.contacts);
            base_view.banners.append(&mut next_view.banners);
        }
        (None, Some(next_view)) => base.view_model = Some(next_view),
        _ => {}
    }
    base
}

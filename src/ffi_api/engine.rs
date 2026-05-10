use std::collections::{BTreeMap, BTreeSet};

use crate::attachment_crypto::{decrypt_blob, encrypt_blob, AttachmentPayloadMetadata};
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
    Ack, CapabilityService, Conversation, ConversationKind, ConversationMember, ConversationState,
    DeliveryClass, DeviceStatusKind, Envelope, GroupCapability, GroupCapabilityOperation,
    GroupCursor, GroupEnvelope, GroupEnvelopeVisibility, GroupInviteDocument, GroupJoinPolicy,
    GroupJoinRequest, GroupJoinRequestStatus, GroupManifest, GroupMember, GroupMemberInvitePolicy,
    GroupMemberStatus, GroupMessageType, GroupOutboxDescriptor, GroupOutboxRecord,
    GroupOutboxRecordState, GroupRole, IdentityBundle, InboxRecord, MessageType, MlsStateStatus,
    MlsStateSummary, SenderProof, StorageRef, Validate, WelcomePickupDescriptor,
};
use crate::persistence::{
    CorePersistenceSnapshot, PersistOp, PersistedContact, PersistedConversation,
    PersistedDeployment, PersistedGroupCursor, PersistedGroupInvite, PersistedGroupJoinRequest,
    PersistedGroupState, PersistedLocalIdentity, PersistedMlsState, PersistedOutgoingEnvelope,
    PersistedOutgoingGroupEnvelope, PersistedPendingAck, PersistedPendingBlobTransfer,
    PersistedRealtimeSession, PersistedRecoveryContext, PersistedRecoveryEscalationReason,
    PersistedRecoveryPhase, PersistedRecoveryReason, PersistedSyncState,
};
use crate::sync_engine::{SyncDecision, SyncEngine};
use crate::transport_contract::{
    AckRequest, AckResult, AllowlistDocument, AppendDeliveryDisposition, AppendEnvelopeRequest,
    AppendEnvelopeResult, AppendGroupEnvelopeRequest, AppendGroupEnvelopeResult,
    BlobDownloadRequest, BlobUploadRequest, CreateGroupInviteRequest, DecideGroupJoinRequest,
    DeviceStatusDocument, DeviceStatusRecord, FetchAllowlistRequest, FetchGroupInviteRequest,
    FetchGroupOutboxRequest, FetchGroupOutboxResult, FetchIdentityBundleRequest,
    FetchMessageRequestsRequest, FetchMessagesRequest, FetchMessagesResult,
    FetchWelcomePickupRequest, FetchWelcomePickupResult, GetGroupJoinRequestStatusRequest,
    GetGroupOutboxHeadRequest, GetHeadResult, GroupJoinDecision,
    ListGroupJoinRequestsRequest, MessageRequestAction, MessageRequestActionRequest,
    MessageRequestActionResult, MessageRequestItem, PrepareBlobUploadRequest,
    PrepareBlobUploadResult, PublishSharedStateRequest, PutWelcomePickupRequest,
    PutWelcomePickupResult, RealtimeSubscriptionRequest, ReplaceAllowlistRequest,
    RevokeGroupInviteRequest, SealGroupOutboxRequest, SharedStateDocumentKind, SubmitGroupJoinRequest,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::Signer;
use log;
use sha2::{Digest, Sha256};

const MAX_ATTACHMENT_BYTES: u64 = 25 * 1024 * 1024;
const MAX_ATTACHMENT_MIME_TYPE_LEN: usize = 255;
const MAX_ATTACHMENT_FILE_NAME_LEN: usize = 255;

#[derive(Debug, Default)]
pub struct CoreEngine {
    pub(crate) state: CoreState,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RecoveryContextSnapshot {
    pub reason: RecoveryReason,
    pub phase: RecoveryPhase,
    pub attempt_count: u8,
    pub identity_refresh_retry_count: u8,
    pub last_error: Option<String>,
    pub escalation_reason: Option<RecoveryEscalationReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SyncCheckpointSnapshot {
    pub last_fetched_seq: u64,
    pub last_acked_seq: u64,
    pub pending_retry: bool,
    pub pending_record_seqs: Vec<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct RealtimeSessionSnapshot {
    pub last_known_seq: u64,
    pub needs_reconnect: bool,
}

fn validate_attachment_descriptor(descriptor: &AttachmentDescriptor) -> CoreResult<()> {
    if descriptor.attachment_id.trim().is_empty() {
        return Err(CoreError::invalid_input("attachment id is required"));
    }
    if descriptor.mime_type.trim().is_empty()
        || descriptor.mime_type.len() > MAX_ATTACHMENT_MIME_TYPE_LEN
        || descriptor.mime_type.contains('\r')
        || descriptor.mime_type.contains('\n')
    {
        return Err(CoreError::invalid_input("attachment mime type is invalid"));
    }
    if descriptor.size_bytes == 0 || descriptor.size_bytes > MAX_ATTACHMENT_BYTES {
        return Err(CoreError::invalid_input(
            "attachment size is outside supported limits",
        ));
    }
    if let Some(file_name) = &descriptor.file_name {
        if file_name.trim().is_empty()
            || file_name.len() > MAX_ATTACHMENT_FILE_NAME_LEN
            || file_name.contains('/')
            || file_name.contains('\\')
            || file_name.contains('\0')
            || file_name.contains('\r')
            || file_name.contains('\n')
        {
            return Err(CoreError::invalid_input("attachment file name is invalid"));
        }
    }
    Ok(())
}

impl CoreEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn local_bundle(&self) -> Option<&IdentityBundle> {
        self.state.local_bundle.as_ref()
    }

    pub fn local_identity(&self) -> Option<&crate::identity::LocalIdentityState> {
        self.state.local_identity.as_ref()
    }

    pub fn local_display_name(&self) -> Option<String> {
        self.state
            .local_display_name
            .clone()
            .or_else(|| self.state.local_bundle.as_ref()?.display_name.clone())
    }

    pub fn contact_bundle(&self, user_id: &str) -> Option<&IdentityBundle> {
        self.state.contacts.get(user_id).map(|c| &c.bundle)
    }

    pub fn contact_display_name(&self, user_id: &str) -> Option<&str> {
        self.state
            .contacts
            .get(user_id)
            .and_then(|c| c.display_name.as_deref().or(c.original_name.as_deref()))
    }

    pub fn conversation_state(&self, conversation_id: &str) -> Option<&LocalConversationState> {
        self.state.conversations.get(conversation_id)
    }

    pub fn mls_summary(&self, conversation_id: &str) -> Option<&MlsStateSummary> {
        self.state.mls_summaries.get(conversation_id)
    }

    pub fn sync_state(&self, device_id: &str) -> Option<&crate::sync_engine::DeviceSyncState> {
        self.state.sync_states.get(device_id)
    }

    pub fn recovery_context_snapshot(
        &self,
        conversation_id: &str,
    ) -> Option<RecoveryContextSnapshot> {
        self.state
            .recovery_contexts
            .get(conversation_id)
            .map(|context| RecoveryContextSnapshot {
                reason: context.reason,
                phase: context.phase,
                attempt_count: context.attempt_count,
                identity_refresh_retry_count: context.identity_refresh_retry_count,
                last_error: context.last_error.clone(),
                escalation_reason: context.escalation_reason,
            })
    }

    pub fn recovery_conversations_snapshot(&self) -> Vec<RecoveryDiagnostics> {
        self.state
            .conversations
            .keys()
            .filter_map(|conversation_id| self.recovery_snapshot_for_conversation(conversation_id))
            .collect()
    }

    pub fn sync_checkpoint_snapshot(&self, device_id: &str) -> Option<SyncCheckpointSnapshot> {
        self.state
            .sync_states
            .get(device_id)
            .map(|state| SyncCheckpointSnapshot {
                last_fetched_seq: state.checkpoint.last_fetched_seq,
                last_acked_seq: state.checkpoint.last_acked_seq,
                pending_retry: state.pending_retry,
                pending_record_seqs: state.pending_record_seqs.iter().copied().collect(),
            })
    }

    pub fn realtime_session_snapshot(&self, device_id: &str) -> Option<RealtimeSessionSnapshot> {
        self.state
            .realtime_sessions
            .get(device_id)
            .map(|session| RealtimeSessionSnapshot {
                last_known_seq: session.last_known_seq,
                needs_reconnect: session.needs_reconnect,
            })
    }

    pub fn clear_realtime_reconnect(&mut self, device_id: &str) {
        if let Some(session) = self.state.realtime_sessions.get_mut(device_id) {
            session.connected = false;
            session.needs_reconnect = false;
        }
    }

    pub fn refresh_snapshot(&self) -> CorePersistenceSnapshot {
        build_persistence_snapshot(&self.state)
    }

    pub fn local_device_id(&self) -> Option<&str> {
        self.state
            .local_identity
            .as_ref()
            .map(|identity| identity.device_identity.device_id.as_str())
    }

    pub fn from_restored_state(snapshot: CorePersistenceSnapshot) -> Self {
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
            contacts.insert(
                contact.user_id.clone(),
                PersistedContact {
                    user_id: contact.user_id,
                    bundle: contact.bundle,
                    display_name: contact.display_name,
                    original_name: contact.original_name,
                    added_at: contact.added_at,
                },
            );
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
                plaintext_cache: item.plaintext_cache,
            })
            .collect();
        let outbox = pending_outbox
            .iter()
            .map(|item| item.envelope.clone())
            .collect::<Vec<_>>();
        let group_states = snapshot
            .group_states
            .into_iter()
            .map(|state| (state.group_id.clone(), state))
            .collect::<BTreeMap<_, _>>();
        let group_cursors = snapshot
            .group_cursors
            .into_iter()
            .map(|cursor| (cursor.group_id.clone(), cursor.cursor))
            .collect::<BTreeMap<_, _>>();
        let pending_group_outbox = snapshot
            .pending_group_outbox
            .into_iter()
            .filter_map(|item| {
                let capability = item.capability.or_else(|| {
                    group_states.get(&item.group_id).and_then(|state| {
                        state
                            .local_role
                            .map(|role| group_capability_for_manifest(&state.manifest, role))
                    })
                })?;
                Some(PendingGroupOutboxItem {
                    envelope: item.envelope,
                    capability,
                    retries: item.retries,
                    in_flight: false,
                    plaintext_cache: item.plaintext_cache,
                })
            })
            .collect::<Vec<_>>();
        let group_invites = snapshot
            .group_invites
            .into_iter()
            .map(|invite| (invite.invite_id.clone(), invite))
            .collect::<BTreeMap<_, _>>();
        let group_join_requests = snapshot
            .group_join_requests
            .into_iter()
            .map(|request| (request.request_id.clone(), request))
            .collect::<BTreeMap<_, _>>();
        let pending_group_join_approvals = snapshot
            .pending_group_join_approvals
            .into_iter()
            .map(|approval| (approval.request_id.clone(), approval))
            .collect::<BTreeMap<_, _>>();

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
                    group_id,
                    message_id,
                    attachment_id,
                    blob_ciphertext_b64,
                    payload_metadata,
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
                            group_id,
                            descriptor: AttachmentDescriptor {
                                attachment_id,
                                mime_type,
                                size_bytes,
                                file_name,
                            },
                            blob_ciphertext_b64,
                            payload_metadata,
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
                    destination_id,
                    payload_metadata,
                    retries,
                } => {
                    pending_blob_downloads.insert(
                        task_id.clone(),
                        PendingBlobDownload {
                            task_id,
                            conversation_id,
                            message_id,
                            reference,
                            destination_id,
                            payload_metadata,
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
                        phase: match context.phase {
                            PersistedRecoveryPhase::WaitingForSync => RecoveryPhase::WaitingForSync,
                            PersistedRecoveryPhase::WaitingForPendingReplay => {
                                RecoveryPhase::WaitingForPendingReplay
                            }
                            PersistedRecoveryPhase::WaitingForIdentityRefresh => {
                                RecoveryPhase::WaitingForIdentityRefresh
                            }
                            PersistedRecoveryPhase::WaitingForExplicitReconcile => {
                                RecoveryPhase::WaitingForExplicitReconcile
                            }
                            PersistedRecoveryPhase::EscalatedToRebuild => {
                                RecoveryPhase::EscalatedToRebuild
                            }
                        },
                        attempt_count: context.attempt_count,
                        identity_refresh_retry_count: context.identity_refresh_retry_count,
                        last_error: context.last_error,
                        escalation_reason: context.escalation_reason.map(|reason| match reason {
                            PersistedRecoveryEscalationReason::MlsMarkedUnrecoverable => {
                                RecoveryEscalationReason::MlsMarkedUnrecoverable
                            }
                            PersistedRecoveryEscalationReason::IdentityRefreshRetryExhausted => {
                                RecoveryEscalationReason::IdentityRefreshRetryExhausted
                            }
                            PersistedRecoveryEscalationReason::ExplicitNeedsRebuildControl => {
                                RecoveryEscalationReason::ExplicitNeedsRebuildControl
                            }
                            PersistedRecoveryEscalationReason::RecoveryPolicyExhausted => {
                                RecoveryEscalationReason::RecoveryPolicyExhausted
                            }
                        }),
                    },
                )
            })
            .collect();

        let local_identity = snapshot.local_identity.map(|identity| identity.state);
        let persisted_deployment = snapshot.deployment.clone();
        let local_display_name = persisted_deployment
            .as_ref()
            .and_then(|deployment| deployment.local_bundle.as_ref())
            .and_then(|bundle| bundle.display_name.clone());
        let mut engine = Self {
            state: CoreState {
                local_identity,
                local_bundle: persisted_deployment
                    .as_ref()
                    .and_then(|deployment| deployment.local_bundle.clone()),
                deployment_bundle: persisted_deployment
                    .as_ref()
                    .map(|deployment| deployment.deployment_bundle.clone()),
                contacts,
                conversations,
                sync_states,
                outbox,
                pending_outbox,
                group_states,
                group_cursors,
                pending_group_outbox,
                group_invites,
                group_join_requests,
                pending_group_join_approvals,
                pending_group_seal: BTreeMap::new(),
                pending_acks,
                pending_blob_uploads,
                pending_blob_downloads,
                realtime_sessions,
                mls_adapter: restored_mls.adapter,
                mls_summaries,
                published_key_package: persisted_deployment
                    .and_then(|deployment| deployment.published_key_package),
                pending_requests: BTreeMap::new(),
                request_nonce: 0,
                message_nonce: snapshot.message_nonce,
                recovery_contexts,
                pending_allowlist_mutation: None,
                local_display_name,
            },
        };

        if engine.state.mls_adapter.is_none() {
            if let Some(serialized_state) = snapshot
                .deployment
                .as_ref()
                .and_then(|deployment| deployment.serialized_mls_bootstrap_state.clone())
            {
                if let Ok(adapter) = MlsAdapter::restore_from_bootstrap_state(&serialized_state) {
                    engine.state.mls_adapter = Some(adapter);
                }
            }
        }

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
            engine.state.recovery_contexts.insert(
                conversation_id.clone(),
                RecoveryContext {
                    conversation_id,
                    reason: RecoveryReason::MissingCommit,
                    phase: RecoveryPhase::EscalatedToRebuild,
                    attempt_count: 0,
                    identity_refresh_retry_count: MAX_TRANSPORT_RETRIES,
                    last_error: Some("failed to restore MLS group state".into()),
                    escalation_reason: Some(RecoveryEscalationReason::MlsMarkedUnrecoverable),
                },
            );
        }

        engine
    }

    pub fn handle_command(&mut self, command: CoreCommand) -> CoreResult<CoreOutput> {
        match command {
            CoreCommand::CreateOrLoadIdentity {
                mnemonic,
                device_name,
                display_name,
            } => self.create_or_load_identity(mnemonic, device_name, display_name),
            CoreCommand::ImportDeploymentBundle { bundle } => self.import_deployment_bundle(bundle),
            CoreCommand::ImportIdentityBundle { bundle } => self.import_identity_bundle(bundle),
            CoreCommand::ApplyIdentityBundleUpdate { bundle } => {
                self.apply_identity_bundle_update(bundle)
            }
            CoreCommand::CreateConversation {
                peer_user_id,
                conversation_kind,
            } => self.create_conversation(peer_user_id, conversation_kind),
            CoreCommand::CreateGroupConversation {
                title,
                member_user_ids,
            } => self.create_group_conversation(title, member_user_ids),
            CoreCommand::SyncGroupOutbox { group_id, .. } => self.sync_group_outbox(group_id),
            CoreCommand::SendGroupTextMessage {
                conversation_id,
                plaintext,
            } => self.send_group_text_message(conversation_id, plaintext),
            CoreCommand::CreateGroupInviteLink {
                group_id,
                expires_at,
                max_uses,
            } => self.create_group_invite_link(group_id, expires_at, max_uses),
            CoreCommand::RevokeGroupInviteLink {
                group_id,
                invite_id,
            } => self.revoke_group_invite_link(group_id, invite_id),
            CoreCommand::FetchGroupInvite { invite_url } => self.fetch_group_invite(invite_url),
            CoreCommand::SubmitGroupJoinRequest { invite_url } => {
                self.submit_group_join_request(invite_url)
            }
            CoreCommand::ListGroupJoinRequests { group_id } => {
                self.list_group_join_requests(group_id)
            }
            CoreCommand::GetGroupJoinRequestStatus {
                group_id,
                request_id,
            } => self.get_group_join_request_status(group_id, request_id),
            CoreCommand::ApproveGroupJoin {
                group_id,
                request_id,
            } => self.approve_group_join(group_id, request_id),
            CoreCommand::RejectGroupJoin {
                group_id,
                request_id,
                reason,
            } => self.reject_group_join(group_id, request_id, reason),
            CoreCommand::InviteToGroup {
                group_id,
                invitee_user_ids,
            } => self.invite_to_group(group_id, invitee_user_ids),
            CoreCommand::LeaveGroup { group_id } => self.leave_group(group_id),
            CoreCommand::RemoveGroupMember {
                group_id,
                target_user_id,
            } => self.remove_group_member(group_id, target_user_id),
            CoreCommand::TransferGroupOwnership {
                group_id,
                new_owner_user_id,
            } => self.transfer_group_ownership(group_id, new_owner_user_id),
            CoreCommand::SetGroupAdmin {
                group_id,
                target_user_id,
                is_admin,
            } => self.set_group_admin(group_id, target_user_id, is_admin),
            CoreCommand::UpdateGroupMetadata {
                group_id,
                title,
                join_policy,
                member_invite_policy,
            } => self.update_group_metadata(group_id, title, join_policy, member_invite_policy),
            CoreCommand::RequestJoinGroup { invite_url } => self.request_join_group(invite_url),
            CoreCommand::ReconcileConversationMembership { conversation_id } => {
                self.reconcile_conversation_membership(conversation_id)
            }
            CoreCommand::SendTextMessage {
                conversation_id,
                plaintext,
            } => self.send_text_message(conversation_id, plaintext),
            CoreCommand::SendAttachmentMessage {
                conversation_id,
                attachment_descriptor,
            } => self.send_attachment_message(conversation_id, attachment_descriptor),
            CoreCommand::DownloadAttachment {
                conversation_id,
                message_id,
                reference,
                destination,
            } => self.download_attachment(conversation_id, message_id, reference, destination),
            CoreCommand::SyncInbox { device_id, .. } => self.sync_inbox(device_id),
            CoreCommand::RefreshIdentityState { user_id } => self.refresh_identity_state(user_id),
            CoreCommand::ListMessageRequests => self.list_message_requests(),
            CoreCommand::ActOnMessageRequest { request_id, action } => {
                self.act_on_message_request(request_id, action)
            }
            CoreCommand::ListAllowlist => self.list_allowlist(),
            CoreCommand::AddAllowlistUser { user_id } => self.add_allowlist_user(user_id),
            CoreCommand::RemoveAllowlistUser { user_id } => self.remove_allowlist_user(user_id),
            CoreCommand::CreateAdditionalDeviceIdentity {
                mnemonic,
                device_name,
            } => self.create_additional_device_identity(mnemonic, device_name),
            CoreCommand::RotateLocalKeyPackage => self.rotate_local_key_package(),
            CoreCommand::ApplyLocalDeviceStatusUpdate { status } => {
                self.apply_local_device_status_update(status)
            }
            CoreCommand::UpdateLocalDeviceStatus {
                target_device_id,
                status,
            } => self.update_local_device_status(target_device_id, status),
            CoreCommand::RotateContactShareLink => self.rotate_contact_share_link(),
            CoreCommand::RebuildConversation { conversation_id } => {
                self.rebuild_conversation(conversation_id)
            }
            CoreCommand::SetLocalDisplayName { display_name } => {
                self.set_local_display_name(display_name)
            }
            CoreCommand::SetContactDisplayName {
                user_id,
                display_name,
            } => self.set_contact_display_name(user_id, display_name),
            CoreCommand::DeleteContact { user_id } => self.delete_contact(user_id),
            CoreCommand::DissolveGroup { group_id } => self.dissolve_group(group_id),
        }
    }

    pub fn handle_event(&mut self, event: CoreEvent) -> CoreResult<CoreOutput> {
        match event {
            CoreEvent::AppStarted | CoreEvent::AppForegrounded => self.start_foreground_sync(),
            CoreEvent::WebSocketConnected { device_id } => {
                self.handle_websocket_connected(device_id)
            }
            CoreEvent::WebSocketDisconnected { device_id, .. } => {
                self.handle_websocket_disconnected(device_id)
            }
            CoreEvent::RealtimeEventReceived { device_id, event } => {
                self.handle_realtime_event(device_id, event)
            }
            CoreEvent::WakeupReceived { device_id, .. } => self.sync_inbox(device_id),
            CoreEvent::InboxRecordsFetched {
                device_id,
                records,
                to_seq,
            } => self.handle_inbox_records(device_id, records, to_seq),
            CoreEvent::HttpResponseReceived {
                request_id,
                status,
                body,
            } => self.handle_http_response(request_id, status, body),
            CoreEvent::HttpRequestFailed {
                request_id,
                retryable,
                detail,
            } => self.handle_http_failure(request_id, retryable, detail),
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
            CoreEvent::MessageRequestsFetched { requests } => {
                Ok(self.message_requests_output(requests))
            }
            CoreEvent::MessageRequestsFetchFailed {
                retryable: _,
                detail,
            } => Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect {
                        status: SystemStatus::TemporaryNetworkFailure,
                        message: detail.unwrap_or_else(|| "message request query failed".into()),
                    },
                }],
                view_model: None,
            }),
            CoreEvent::MessageRequestActionCompleted { result } => {
                Ok(self.message_request_action_output(result))
            }
            CoreEvent::MessageRequestActionFailed {
                request_id,
                action,
                retryable: _,
                detail,
            } => Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect {
                        status: SystemStatus::TemporaryNetworkFailure,
                        message: detail.unwrap_or_else(|| {
                            format!("message request {:?} failed for {}", action, request_id)
                        }),
                    },
                }],
                view_model: None,
            }),
            CoreEvent::AllowlistFetched { document } => self.handle_allowlist_fetched(document),
            CoreEvent::AllowlistFetchFailed {
                retryable: _,
                detail,
            } => Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect {
                        status: SystemStatus::TemporaryNetworkFailure,
                        message: detail.unwrap_or_else(|| "allowlist query failed".into()),
                    },
                }],
                view_model: None,
            }),
            CoreEvent::AllowlistReplaced { document } => Ok(self.allowlist_output(document, true)),
            CoreEvent::AllowlistReplaceFailed {
                retryable: _,
                detail,
            } => Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect {
                        status: SystemStatus::TemporaryNetworkFailure,
                        message: detail.unwrap_or_else(|| "allowlist update failed".into()),
                    },
                }],
                view_model: None,
            }),
            CoreEvent::SharedStatePublished { .. } => Ok(CoreOutput::default()),
            CoreEvent::SharedStatePublishFailed {
                document_kind,
                reference: _,
                retryable: _,
                detail,
            } => Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect {
                        status: SystemStatus::TemporaryNetworkFailure,
                        message: detail.unwrap_or_else(|| {
                            format!("shared state publish failed for {:?}", document_kind)
                        }),
                    },
                }],
                view_model: None,
            }),
            CoreEvent::AttachmentBytesLoaded {
                task_id,
                plaintext_b64,
            } => self.handle_attachment_bytes_loaded(task_id, plaintext_b64),
            CoreEvent::BlobUploadPrepared { task_id, result } => {
                self.handle_blob_upload_prepared(task_id, result)
            }
            CoreEvent::BlobUploaded { task_id } => self.handle_blob_uploaded(task_id),
            CoreEvent::BlobDownloaded {
                task_id,
                blob_ciphertext,
            } => self.handle_blob_downloaded(task_id, blob_ciphertext),
            CoreEvent::BlobTransferFailed {
                task_id,
                retryable,
                detail,
            } => self.handle_blob_transfer_failed(task_id, retryable, detail),
            CoreEvent::TimerTriggered { timer_id } => self.handle_timer(timer_id),
            CoreEvent::UserConfirmedRebuild { conversation_id } => {
                self.rebuild_conversation(conversation_id)
            }
            CoreEvent::GroupOutboxFetched {
                group_id,
                records,
                to_seq,
            } => self.handle_group_outbox_records(group_id, records, to_seq),
            CoreEvent::GroupOutboxFetchFailed {
                group_id,
                retryable: _,
                detail,
            } => Ok(CoreOutput {
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
            CoreEvent::GroupOutboxHeadFetched { group_id, head_seq } => {
                self.handle_group_outbox_head_fetched(group_id, head_seq)
            }
            CoreEvent::GroupOutboxHeadFetchFailed {
                group_id: _,
                retryable: _,
                detail: _,
            } => Ok(CoreOutput::default()),
            CoreEvent::GroupEnvelopeAppended {
                group_id,
                message_id,
                seq,
            } => self.handle_group_envelope_appended(group_id, message_id, seq),
            CoreEvent::GroupEnvelopeAppendFailed {
                group_id,
                message_id,
                retryable,
                detail,
            } => self.handle_group_append_failed(group_id, message_id, retryable, detail),
            CoreEvent::WelcomePickupFetched {
                descriptor,
                welcome_b64,
                manifest,
            } => self.handle_welcome_pickup_fetched(descriptor, welcome_b64, manifest),
            CoreEvent::WelcomePickupFetchFailed {
                descriptor,
                retryable: _,
                detail,
            } => Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect {
                        status: SystemStatus::TemporaryNetworkFailure,
                        message: detail.unwrap_or_else(|| {
                            format!("welcome pickup fetch failed for {}", descriptor.device_id)
                        }),
                    },
                }],
                view_model: None,
            }),
            CoreEvent::WelcomePickupPut { .. } => Ok(CoreOutput::default()),
            CoreEvent::WelcomePickupPutFailed {
                descriptor,
                retryable: _,
                detail,
            } => Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect {
                        status: SystemStatus::TemporaryNetworkFailure,
                        message: detail.unwrap_or_else(|| {
                            format!("welcome pickup put failed for {}", descriptor.device_id)
                        }),
                    },
                }],
                view_model: None,
            }),
            CoreEvent::GroupInviteCreated { invite_url, invite } => {
                self.state.group_invites.insert(
                    invite.invite_id.clone(),
                    PersistedGroupInvite {
                        group_id: invite.group_id.clone(),
                        invite_id: invite.invite_id.clone(),
                        invite_url: invite_url.clone(),
                        document: invite.clone(),
                    },
                );
                Ok(CoreOutput {
                    state_update: CoreStateUpdate::default(),
                    effects: vec![persist_effect(
                        &self.state,
                        vec![PersistOp::SaveGroupInvite {
                            invite_id: invite.invite_id.clone(),
                        }],
                    )],
                    view_model: Some(CoreViewModel {
                        group_invites: self.state.group_invites.values().cloned().collect(),
                        ..CoreViewModel::default()
                    }),
                })
            }
            CoreEvent::GroupInviteFetched { invite_url, invite } => {
                let local = self
                    .state
                    .local_identity
                    .as_ref()
                    .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
                    .clone();
                let joiner_user_id = local.user_identity.user_id.clone();
                let joiner_device_id = local.device_identity.device_id.clone();
                let contact_share = self
                    .state
                    .local_bundle
                    .as_ref()
                    .and_then(|bundle| bundle.identity_bundle_ref.clone())
                    .ok_or_else(|| {
                        CoreError::invalid_state(
                            "local contact-share URL is required for group join",
                        )
                    })?;
                let nonce = self.next_message_nonce();
                let request_id = self.stable_scoped_id("group-join", &invite.invite_id, nonce);
                let requested_at = current_unix_millis(self.state.message_nonce);
                let request_capability = local.sign_sender_proof(
                    format!(
                        "group_join_request_capability:{}:{request_id}",
                        invite.group_id
                    )
                    .as_bytes(),
                );
                let request = GroupJoinRequest {
                    version: crate::model::CURRENT_MODEL_VERSION.to_string(),
                    request_id: request_id.clone(),
                    group_id: invite.group_id.clone(),
                    invite_id: invite.invite_id.clone(),
                    joiner_user_id,
                    joiner_device_id,
                    joiner_contact_share_url: contact_share,
                    requested_at,
                    request_capability,
                    signature: local.sign_sender_proof(
                        format!("group_join_request:{}:{request_id}", invite.group_id).as_bytes(),
                    ),
                    status: GroupJoinRequestStatus::Pending,
                    auto_approve: None,
                };
                request.validate()?;
                self.state.group_join_requests.insert(
                    request_id.clone(),
                    PersistedGroupJoinRequest {
                        group_id: invite.group_id.clone(),
                        request_id: request_id.clone(),
                        request: request.clone(),
                        welcome_pickup: None,
                        manifest: None,
                        start_cursor: None,
                    },
                );
                let invite_token = invite_url
                    .rsplit('/')
                    .next()
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| CoreError::invalid_input("invite URL does not contain token"))?
                    .to_string();
                Ok(CoreOutput {
                    state_update: CoreStateUpdate {
                        system_statuses_changed: vec![SystemStatus::SyncInProgress],
                        ..CoreStateUpdate::default()
                    },
                    effects: vec![
                        persist_effect(
                            &self.state,
                            vec![PersistOp::SaveGroupJoinRequest {
                                request_id: request_id.clone(),
                            }],
                        ),
                        CoreEffect::SubmitGroupJoinRequest {
                            submit: SubmitGroupJoinRequest {
                                version: crate::model::CURRENT_MODEL_VERSION.to_string(),
                                invite_token,
                                request: request.clone(),
                                headers: BTreeMap::new(),
                            },
                        },
                    ],
                    view_model: Some(CoreViewModel {
                        group_join_requests: vec![request],
                        ..CoreViewModel::default()
                    }),
                })
            }
            CoreEvent::GroupJoinRequestSubmitted { request } => {
                self.state.group_join_requests.insert(
                    request.request_id.clone(),
                    PersistedGroupJoinRequest {
                        group_id: request.group_id.clone(),
                        request_id: request.request_id.clone(),
                        request: request.clone(),
                        welcome_pickup: None,
                        manifest: None,
                        start_cursor: None,
                    },
                );
                Ok(CoreOutput {
                    state_update: CoreStateUpdate::default(),
                    effects: vec![persist_effect(
                        &self.state,
                        vec![PersistOp::SaveGroupJoinRequest {
                            request_id: request.request_id.clone(),
                        }],
                    )],
                    view_model: Some(CoreViewModel {
                        group_join_requests: vec![request],
                        ..CoreViewModel::default()
                    }),
                })
            }
            CoreEvent::GroupJoinRequestsListed { group_id, requests } => {
                let mut effects = Vec::new();
                for request in &requests {
                    self.state.group_join_requests.insert(
                        request.request_id.clone(),
                        PersistedGroupJoinRequest {
                            group_id: request.group_id.clone(),
                            request_id: request.request_id.clone(),
                            request: request.clone(),
                            welcome_pickup: None,
                            manifest: None,
                            start_cursor: None,
                        },
                    );
                    effects.push(CoreEffect::FetchIdentityBundle {
                        fetch: FetchIdentityBundleRequest {
                            user_id: request.joiner_user_id.clone(),
                            reference: Some(request.joiner_contact_share_url.clone()),
                        },
                    });
                }
                effects.push(persist_effect(
                    &self.state,
                    requests
                        .iter()
                        .map(|request| PersistOp::SaveGroupJoinRequest {
                            request_id: request.request_id.clone(),
                        })
                        .collect(),
                ));
                Ok(CoreOutput {
                    state_update: CoreStateUpdate {
                        system_statuses_changed: vec![SystemStatus::SyncInProgress],
                        ..CoreStateUpdate::default()
                    },
                    effects,
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
            CoreEvent::GroupJoinRequestStatusFetched {
                request,
                welcome_pickup,
                manifest,
                start_cursor,
            } => {
                self.state.group_join_requests.insert(
                    request.request_id.clone(),
                    PersistedGroupJoinRequest {
                        group_id: request.group_id.clone(),
                        request_id: request.request_id.clone(),
                        request: request.clone(),
                        welcome_pickup: welcome_pickup.clone(),
                        manifest,
                        start_cursor,
                    },
                );
                let mut effects = vec![persist_effect(
                    &self.state,
                    vec![PersistOp::SaveGroupJoinRequest {
                        request_id: request.request_id.clone(),
                    }],
                )];
                if let Some(descriptor) = welcome_pickup {
                    effects.push(CoreEffect::FetchWelcomePickup {
                        fetch: FetchWelcomePickupRequest {
                            descriptor,
                            headers: BTreeMap::new(),
                        },
                    });
                }
                Ok(CoreOutput {
                    state_update: CoreStateUpdate {
                        system_statuses_changed: vec![SystemStatus::SyncInProgress],
                        ..CoreStateUpdate::default()
                    },
                    effects,
                    view_model: Some(CoreViewModel {
                        group_join_requests: vec![request],
                        ..CoreViewModel::default()
                    }),
                })
            }
            CoreEvent::GroupInviteCreateFailed { detail, .. }
            | CoreEvent::GroupInviteFetchFailed { detail, .. }
            | CoreEvent::GroupJoinRequestSubmitFailed { detail, .. }
            | CoreEvent::GroupJoinDecisionFailed { detail, .. } => Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect {
                        status: SystemStatus::TemporaryNetworkFailure,
                        message: detail
                            .unwrap_or_else(|| "group invite/join request failed".into()),
                    },
                }],
                view_model: None,
            }),
            CoreEvent::GroupInviteRevoked {
                group_id: _,
                invite_id,
            } => {
                self.state.group_invites.remove(&invite_id);
                Ok(CoreOutput {
                    state_update: CoreStateUpdate::default(),
                    effects: vec![persist_effect(
                        &self.state,
                        vec![PersistOp::DeleteGroupInvite { invite_id }],
                    )],
                    view_model: None,
                })
            }
            CoreEvent::GroupJoinDecisionApplied { request } => Ok(CoreOutput {
                state_update: CoreStateUpdate::default(),
                effects: vec![CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect {
                        status: SystemStatus::SyncInProgress,
                        message: format!("group join request {} decided", request.request_id),
                    },
                }],
                view_model: Some(CoreViewModel {
                    group_join_requests: vec![request],
                    ..CoreViewModel::default()
                }),
            }),
            CoreEvent::GroupOutboxSealed {
                group_id,
                sealed_at,
                was_already_sealed,
            } => self.handle_group_outbox_sealed(group_id, sealed_at, was_already_sealed),
            CoreEvent::GroupOutboxSealFailed {
                group_id,
                retryable,
                status,
                code,
                detail,
            } => self.handle_group_outbox_seal_failed(group_id, retryable, status, code, detail),
        }
    }

    fn import_deployment_bundle(
        &mut self,
        bundle: crate::model::DeploymentBundle,
    ) -> CoreResult<CoreOutput> {
        bundle.validate()?;
        self.state.deployment_bundle = Some(bundle);
        self.refresh_local_bundle()?;
        let mut output = CoreOutput {
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
        };
        output
            .effects
            .extend(self.local_shared_state_publish_effects()?);
        Ok(output)
    }

    fn import_identity_bundle(&mut self, bundle: IdentityBundle) -> CoreResult<CoreOutput> {
        IdentityManager::verify_identity_bundle(&bundle)?;
        let user_id = bundle.user_id.clone();
        let original_name = bundle.display_name.clone();
        let now = current_timestamp_hint(self.state.outbox.len());

        // Check if contact already exists to preserve user's display_name
        let existing_display_name = self
            .state
            .contacts
            .get(&user_id)
            .and_then(|c| c.display_name.clone());

        let persisted_contact = PersistedContact {
            user_id: user_id.clone(),
            bundle,
            display_name: existing_display_name,
            original_name,
            added_at: now,
        };

        self.state
            .contacts
            .insert(user_id.clone(), persisted_contact);
        let mut output = CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(
                &self.state,
                vec![PersistOp::SaveContact {
                    user_id: user_id.clone(),
                }],
            )],
            view_model: None,
        };
        if self.state.deployment_bundle.is_some() {
            output = merge_outputs(output, self.add_allowlist_user(user_id)?);
        }
        Ok(output)
    }

    fn apply_identity_bundle_update(&mut self, bundle: IdentityBundle) -> CoreResult<CoreOutput> {
        IdentityManager::verify_identity_bundle(&bundle)?;
        let user_id = bundle.user_id.clone();
        let affected_conversations = self.affected_conversations_for_peer(&user_id);

        // Preserve existing display_name, update original_name if bundle has display_name
        let existing = self.state.contacts.get(&user_id);
        let display_name = existing.and_then(|c| c.display_name.clone());
        let original_name = bundle
            .display_name
            .clone()
            .or(existing.and_then(|c| c.original_name.clone()));
        let added_at = existing
            .map(|c| c.added_at)
            .unwrap_or_else(|| current_timestamp_hint(self.state.outbox.len()));

        let persisted_contact = PersistedContact {
            user_id: user_id.clone(),
            bundle,
            display_name,
            original_name,
            added_at,
        };

        self.state
            .contacts
            .insert(user_id.clone(), persisted_contact);

        let mut output = CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(
                &self.state,
                vec![PersistOp::SaveContact {
                    user_id: user_id.clone(),
                }],
            )],
            view_model: None,
        };
        for conversation_id in affected_conversations {
            self.mark_recovery_needed(&conversation_id, RecoveryReason::IdentityChanged);
            self.transition_recovery_phase(
                &conversation_id,
                RecoveryPhase::WaitingForExplicitReconcile,
            );
            output = merge_outputs(
                output,
                self.reconcile_conversation_membership(conversation_id)?,
            );
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
        display_name: Option<String>,
    ) -> CoreResult<CoreOutput> {
        // Validate display_name if provided
        if let Some(ref name) = display_name {
            crate::model::validate_display_name(name)?;
        }

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
        self.state.local_display_name = display_name.clone();
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
                    display_name,
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

    fn create_additional_device_identity(
        &mut self,
        mnemonic: Option<String>,
        device_name: Option<String>,
    ) -> CoreResult<CoreOutput> {
        let mnemonic = mnemonic.ok_or_else(|| {
            CoreError::invalid_input("mnemonic is required to create an additional device")
        })?;
        let recovered = IdentityManager::recover_user_root(&mnemonic)?;
        if let Some(existing) = self.state.local_identity.as_ref() {
            if existing.user_identity.user_id != recovered.user_identity.user_id {
                return Err(CoreError::invalid_input(
                    "provided mnemonic does not match persisted local identity",
                ));
            }
        }
        let _ = device_name;
        let identity = IdentityManager::create_new_device_for_user(&recovered, None)?;
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
                    display_name: None,
                    device_count: 1,
                }],
                banners: vec![SystemBanner {
                    status: SystemStatus::IdentityRefreshNeeded,
                    message: format!("additional local device ready for {device_id}"),
                }],
                ..CoreViewModel::default()
            }),
        })
    }

    fn rotate_local_key_package(&mut self) -> CoreResult<CoreOutput> {
        let package = self
            .state
            .mls_adapter
            .as_mut()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .rotate_key_package(0)?;
        self.state.published_key_package = Some(package);
        self.refresh_local_bundle()?;
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(&self.state, vec![PersistOp::SaveDeployment])],
            view_model: None,
        })
    }

    fn apply_local_device_status_update(
        &mut self,
        status: crate::model::DeviceStatusKind,
    ) -> CoreResult<CoreOutput> {
        let device_id = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .device_identity
            .device_id
            .clone();
        self.update_local_device_status(device_id, status)
    }

    fn update_local_device_status(
        &mut self,
        target_device_id: String,
        status: crate::model::DeviceStatusKind,
    ) -> CoreResult<CoreOutput> {
        let local_device_id = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .device_identity
            .device_id
            .clone();
        let updated_at = if target_device_id == local_device_id {
            let identity = self
                .state
                .local_identity
                .as_mut()
                .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?;
            identity.device_status.status = status;
            identity.device_status.updated_at = identity.device_status.updated_at.saturating_add(1);
            identity.device_status.updated_at
        } else {
            let local_bundle =
                self.state.local_bundle.as_mut().ok_or_else(|| {
                    CoreError::invalid_state("local identity bundle is unavailable")
                })?;
            let device = local_bundle
                .devices
                .iter_mut()
                .find(|device| device.device_id == target_device_id)
                .ok_or_else(|| {
                    CoreError::invalid_input(
                        "target device is not present in local identity bundle",
                    )
                })?;
            device.status = status;
            local_bundle.updated_at = local_bundle.updated_at.saturating_add(1);
            local_bundle.updated_at
        };
        self.refresh_local_bundle_with_updated_at(updated_at)?;
        let mut output = CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(
                &self.state,
                vec![PersistOp::SaveLocalIdentity, PersistOp::SaveDeployment],
            )],
            view_model: None,
        };
        output
            .effects
            .extend(self.local_shared_state_publish_effects()?);
        Ok(output)
    }

    fn create_conversation(
        &mut self,
        peer_user_id: String,
        conversation_kind: ConversationKind,
    ) -> CoreResult<CoreOutput> {
        if conversation_kind != ConversationKind::Direct {
            return Err(CoreError::unsupported(
                "phase 5 only supports direct conversations",
            ));
        }
        let local_identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?;
        let contact_bundle = self.direct_peer_contact_bundle(&peer_user_id)?.clone();
        let peer_device_ids: Vec<String> = contact_bundle
            .devices
            .iter()
            .filter(|d| matches!(d.status, crate::model::DeviceStatusKind::Active))
            .map(|d| d.device_id.clone())
            .collect();
        if peer_device_ids.is_empty() {
            return Err(CoreError::invalid_input(
                "peer identity bundle does not contain any active devices",
            ));
        }
        let local_conversation = ConversationManager::create_direct_conversation(
            &local_identity.user_identity.user_id,
            &local_identity.device_identity.device_id,
            &peer_user_id,
            &peer_device_ids,
        )?;
        let conversation_id = local_conversation.conversation.conversation_id.clone();
        if let Some(existing) = self.state.conversations.get(&conversation_id) {
            let recovery = self.recovery_snapshot_for_conversation(&conversation_id);
            let existing_last_message_type = existing.last_message_type;
            if !self.state.mls_summaries.contains_key(&conversation_id) {
                return Err(CoreError::invalid_state(format!(
                    "conversation {conversation_id} already exists but the MLS state is incomplete"
                )));
            }
            return Ok(CoreOutput {
                state_update: CoreStateUpdate::default(),
                effects: Vec::new(),
                view_model: Some(CoreViewModel {
                    conversations: vec![ConversationSummary {
                        conversation_id,
                        peer_user_id: peer_user_id.clone(),
                        state: format!("{:?}", existing.conversation.state).to_lowercase(),
                        kind: Some(ConversationKind::Direct),
                        title: None,
                        group_id: None,
                        member_count: None,
                        group_role: None,
                        group_cursor: None,
                        last_message_preview: None,
                        last_message_type: existing_last_message_type,
                        message_count: None,
                        recovery,
                    }],
                    ..CoreViewModel::default()
                }),
            });
        }
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
        self.state
            .mls_summaries
            .insert(conversation_id.clone(), summary);
        self.state
            .conversations
            .insert(conversation_id.clone(), local_conversation);

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
        self.enqueue_envelopes(peer_user_id.clone(), generated.clone());
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
                    peer_user_id,
                    state: "active".into(),
                    kind: Some(ConversationKind::Direct),
                    title: None,
                    group_id: None,
                    member_count: None,
                    group_role: None,
                    group_cursor: None,
                    last_message_preview: None,
                    last_message_type: Some(MessageType::MlsCommit),
                    message_count: None,
                    recovery: None,
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

    fn send_text_message(
        &mut self,
        conversation_id: String,
        plaintext: String,
    ) -> CoreResult<CoreOutput> {
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
        // Cache plaintext for display until message is synced
        self.enqueue_envelopes_with_plaintext(peer_user_id, envelopes.clone(), plaintext.clone());
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

    fn create_group_conversation(
        &mut self,
        title: String,
        member_user_ids: Vec<String>,
    ) -> CoreResult<CoreOutput> {
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
        for user_id in &member_user_ids {
            let bundle = self.direct_peer_contact_bundle(user_id)?.clone();
            for device in bundle
                .devices
                .iter()
                .filter(|device| matches!(device.status, DeviceStatusKind::Active))
            {
                peer_keypackages.push(PeerDeviceKeyPackage {
                    user_id: user_id.clone(),
                    device_id: device.device_id.clone(),
                    device_public_key: device.device_public_key.clone(),
                    key_package_b64: device.keypackage_ref.object_ref.clone(),
                });
                member_devices.push(ConversationMember {
                    user_id: user_id.clone(),
                    device_id: device.device_id.clone(),
                    status: DeviceStatusKind::Active,
                });
            }
        }
        if peer_keypackages.is_empty() {
            return Err(CoreError::invalid_input(
                "group must include at least one active invited device",
            ));
        }

        let group_id = self.next_group_id(&title, &member_user_ids);
        let conversation_id = format!("conv:{group_id}");
        if self.state.group_states.contains_key(&group_id)
            || self.state.conversations.contains_key(&conversation_id)
        {
            return Err(CoreError::invalid_state(
                "group conversation already exists",
            ));
        }

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
        self.state
            .mls_summaries
            .insert(conversation_id.clone(), summary.clone());

        let now = current_unix_millis(self.state.message_nonce);
        let manifest = self.build_group_manifest(
            &group_id,
            &conversation_id,
            &title,
            &local_identity,
            &member_user_ids,
            summary.epoch,
            now,
        )?;
        manifest.validate()?;
        let group_state = PersistedGroupState {
            group_id: group_id.clone(),
            conversation_id: conversation_id.clone(),
            manifest: manifest.clone(),
            local_role: Some(GroupRole::Owner),
            welcome_pickup: None,
            dissolved_at: None,
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
                    member_users: {
                        let mut users = member_user_ids.clone();
                        users.push(local_identity.user_identity.user_id.clone());
                        users.sort();
                        users.dedup();
                        users
                    },
                    member_devices,
                    state: ConversationState::Active,
                    updated_at: now,
                },
                messages: Vec::new(),
                last_message_type: None,
                peer_user_id: group_id.clone(),
                last_known_peer_active_devices: BTreeSet::new(),
                recovery_status: RecoveryStatus::Healthy,
            },
        );

        let capability = self.group_capability(&group_id, GroupRole::Owner)?;
        let commit_envelope = self.build_group_envelope(
            &group_id,
            &conversation_id,
            GroupMessageType::MlsCommit,
            GroupEnvelopeVisibility::Protocol,
            artifacts.commit_b64,
        )?;
        self.enqueue_group_envelope(commit_envelope.clone(), capability, None);

        let mut effects = vec![persist_effect(
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
                PersistOp::SaveOutgoingGroupEnvelope {
                    message_id: commit_envelope.message_id.clone(),
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
                conversations: vec![self.conversation_summary(&conversation_id)?],
                messages: vec![MessageSummary {
                    conversation_id,
                    message_id: commit_envelope.message_id,
                    message_type: MessageType::MlsCommit,
                }],
                welcome_pickups: pickup_descriptors,
                ..CoreViewModel::default()
            }),
        })
    }

    fn send_group_text_message(
        &mut self,
        conversation_id: String,
        plaintext: String,
    ) -> CoreResult<CoreOutput> {
        self.ensure_group_ready_for_send(&conversation_id)?;
        if plaintext.trim().is_empty() {
            return Err(CoreError::invalid_input("plaintext must not be empty"));
        }
        let payload = self
            .state
            .mls_adapter
            .as_mut()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .encrypt_application(&conversation_id, plaintext.as_bytes())?;
        let group_id = self
            .group_id_for_conversation(&conversation_id)?
            .to_string();
        let envelope = self.build_group_envelope(
            &group_id,
            &conversation_id,
            GroupMessageType::MlsApplication,
            GroupEnvelopeVisibility::Visible,
            payload.payload_b64,
        )?;
        let capability = self.group_capability(&group_id, self.local_group_role(&group_id)?)?;
        self.enqueue_group_envelope(envelope.clone(), capability, Some(plaintext));
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
                    PersistOp::SaveOutgoingGroupEnvelope {
                        message_id: envelope.message_id.clone(),
                    },
                ],
            )],
            view_model: Some(CoreViewModel {
                messages: vec![MessageSummary {
                    conversation_id,
                    message_id: envelope.message_id,
                    message_type: MessageType::MlsApplication,
                }],
                ..CoreViewModel::default()
            }),
        })
    }

    fn sync_group_outbox(&mut self, group_id: String) -> CoreResult<CoreOutput> {
        let state = self
            .state
            .group_states
            .get(&group_id)
            .ok_or_else(|| CoreError::invalid_input("group does not exist"))?
            .clone();
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
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                checkpoints_changed: true,
                system_statuses_changed: vec![SystemStatus::SyncInProgress],
                ..CoreStateUpdate::default()
            },
            effects: vec![CoreEffect::FetchGroupOutbox {
                fetch: FetchGroupOutboxRequest {
                    group_id,
                    from_seq: cursor.last_fetched_seq.saturating_add(1).max(1),
                    limit: 100,
                    capability: self.group_capability_for_state(&state)?,
                },
            }],
            view_model: None,
        })
    }

    fn request_join_group(&mut self, invite_url: String) -> CoreResult<CoreOutput> {
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
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                system_statuses_changed: vec![SystemStatus::SyncInProgress],
                ..CoreStateUpdate::default()
            },
            effects: vec![CoreEffect::FetchWelcomePickup {
                fetch: FetchWelcomePickupRequest {
                    descriptor,
                    headers: BTreeMap::new(),
                },
            }],
            view_model: None,
        })
    }

    fn create_group_invite_link(
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

    fn revoke_group_invite_link(
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

    fn fetch_group_invite(&mut self, invite_url: String) -> CoreResult<CoreOutput> {
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

    fn submit_group_join_request(&mut self, invite_url: String) -> CoreResult<CoreOutput> {
        self.fetch_group_invite(invite_url)
    }

    fn list_group_join_requests(&mut self, group_id: String) -> CoreResult<CoreOutput> {
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

    fn get_group_join_request_status(
        &mut self,
        group_id: String,
        request_id: String,
    ) -> CoreResult<CoreOutput> {
        let stored = self
            .state
            .group_join_requests
            .get(&request_id)
            .cloned()
            .ok_or_else(|| {
                CoreError::invalid_input("group join request does not exist locally")
            })?;
        if stored.group_id != group_id {
            return Err(CoreError::invalid_input(
                "group join request id does not belong to this group",
            ));
        }
        let base = self.deployment_http_base()?;
        let endpoint = format!(
            "{}/v1/groups/{}/join-requests/{}",
            base.trim_end_matches('/'),
            stored.request.group_id,
            stored.request.request_id,
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

    fn approve_group_join(
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
        let join = self
            .state
            .group_join_requests
            .get(&request_id)
            .ok_or_else(|| CoreError::invalid_input("join request does not exist"))?
            .request
            .clone();
        if join.group_id != group_id || join.status != GroupJoinRequestStatus::Pending {
            return Err(CoreError::invalid_input(
                "join request is not pending for this group",
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
        let group_state = self
            .state
            .group_states
            .get(&group_id)
            .cloned()
            .ok_or_else(|| CoreError::invalid_input("group does not exist"))?;
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
        let mut manifest = group_state.manifest.clone();
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
                welcome_pickup: group_state.welcome_pickup,
                dissolved_at: group_state.dissolved_at,
            },
        );

        let capability = self.group_capability(&group_id, role)?;
        let membership_proof =
            self.build_membership_proof(&group_id, manifest.roster_version, "approve_join")?;
        let mut commit = self.build_group_envelope(
            &group_id,
            &group_state.conversation_id,
            GroupMessageType::MlsCommit,
            GroupEnvelopeVisibility::Protocol,
            artifacts.commit_b64,
        )?;
        commit.membership_proof = Some(membership_proof.clone());
        self.enqueue_group_envelope(commit.clone(), capability.clone(), None);
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
        control.membership_proof = Some(membership_proof);
        self.enqueue_group_envelope(control.clone(), capability.clone(), None);

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
        let mut first_welcome = None;
        for welcome in artifacts.welcomes {
            let descriptor =
                self.welcome_pickup_descriptor(&group_id, &welcome.recipient_device_id)?;
            first_welcome.get_or_insert_with(|| descriptor.clone());
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
        let start_cursor = GroupCursor {
            group_id: group_id.clone(),
            last_fetched_seq: 0,
            updated_at: current_unix_millis(self.state.message_nonce),
        };
        effects.push(CoreEffect::DecideGroupJoinRequest {
            decide: DecideGroupJoinRequest {
                version: crate::model::CURRENT_MODEL_VERSION.to_string(),
                group_id: group_id.clone(),
                request_id,
                decision: GroupJoinDecision::Approve,
                capability,
                welcome_pickup: first_welcome,
                manifest: Some(manifest),
                start_cursor: Some(start_cursor),
                reason: None,
                headers: BTreeMap::new(),
            },
        });
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

    fn reject_group_join(
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

    fn invite_to_group(
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
        let mut manifest = group_state.manifest.clone();
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
                welcome_pickup: group_state.welcome_pickup,
                dissolved_at: group_state.dissolved_at,
            },
        );
        let capability = self.group_capability(&group_id, role)?;
        let membership_proof =
            self.build_membership_proof(&group_id, manifest.roster_version, "invite")?;
        let mut commit = self.build_group_envelope(
            &group_id,
            &group_state.conversation_id,
            GroupMessageType::MlsCommit,
            GroupEnvelopeVisibility::Protocol,
            artifacts.commit_b64,
        )?;
        commit.membership_proof = Some(membership_proof.clone());
        self.enqueue_group_envelope(commit.clone(), capability.clone(), None);
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
        control.membership_proof = Some(membership_proof);
        self.enqueue_group_envelope(control.clone(), capability.clone(), None);
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

    fn remove_group_member(
        &mut self,
        group_id: String,
        target_user_id: String,
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
        let mut manifest = group_state.manifest.clone();
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
                member.status = GroupMemberStatus::Removed;
            }
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
                welcome_pickup: group_state.welcome_pickup,
                dissolved_at: group_state.dissolved_at,
            },
        );
        let capability = self.group_capability(&group_id, role)?;
        let membership_proof =
            self.build_membership_proof(&group_id, manifest.roster_version, "remove")?;
        let mut commit = self.build_group_envelope(
            &group_id,
            &group_state.conversation_id,
            GroupMessageType::MlsCommit,
            GroupEnvelopeVisibility::Protocol,
            artifacts.commit_b64,
        )?;
        commit.membership_proof = Some(membership_proof.clone());
        self.enqueue_group_envelope(commit.clone(), capability.clone(), None);
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
        control.membership_proof = Some(membership_proof);
        self.enqueue_group_envelope(control.clone(), capability.clone(), None);
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

    fn leave_group(&mut self, group_id: String) -> CoreResult<CoreOutput> {
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
        let conversation_id = group_state.conversation_id.clone();
        let leave_payload = serde_json::to_vec(&serde_json::json!({
            "group_id": group_id,
            "leaving_user_id": local_identity.user_identity.user_id,
            "leaving_device_id": local_identity.device_identity.device_id,
            "left_at": current_unix_millis(self.state.message_nonce),
        }))
        .map_err(|error| {
            CoreError::invalid_input(format!("failed to encode leave payload: {error}"))
        })?;
        let leave_b64 = STANDARD.encode(&leave_payload);
        let capability = self.group_capability(&group_id, role)?;
        let envelope = self.build_group_envelope(
            &group_id,
            &conversation_id,
            GroupMessageType::ControlGroupLeaveRequested,
            GroupEnvelopeVisibility::Visible,
            leave_b64,
        )?;
        self.enqueue_group_envelope(envelope.clone(), capability, None);
        if let Some(conversation) = self.state.conversations.get_mut(&conversation_id) {
            conversation.conversation.state = ConversationState::NeedsRebuild;
            conversation.recovery_status = RecoveryStatus::NeedsRebuild;
        }
        let mut manifest = group_state.manifest.clone();
        for member in &mut manifest.members {
            if member.user_id == local_identity.user_identity.user_id {
                member.status = GroupMemberStatus::Left;
            }
        }
        let now = current_unix_millis(self.state.message_nonce);
        manifest.roster_version = manifest.roster_version.saturating_add(1);
        manifest.updated_at = now;
        manifest.signer_user_id = local_identity.user_identity.user_id.clone();
        manifest.signer_device_id = local_identity.device_identity.device_id.clone();
        manifest.signature = self.sign_manifest(&manifest)?;
        manifest.validate()?;
        self.state.group_states.insert(
            group_id.clone(),
            PersistedGroupState {
                group_id: group_id.clone(),
                conversation_id: conversation_id.clone(),
                manifest,
                local_role: None,
                welcome_pickup: group_state.welcome_pickup,
                dissolved_at: group_state.dissolved_at,
            },
        );
        self.merge_with_transport_flush(CoreOutput {
            state_update: CoreStateUpdate {
                conversations_changed: true,
                messages_changed: true,
                system_statuses_changed: vec![SystemStatus::ConversationNeedsRebuild],
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
                    conversation_id,
                    message_id: envelope.message_id,
                    message_type: MessageType::ControlDeviceMembershipChanged,
                }],
                ..CoreViewModel::default()
            }),
        })
    }

    fn transfer_group_ownership(
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
        let mut manifest = group_state.manifest.clone();
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
        if !manifest.admins.iter().any(|a| a == &new_owner_user_id) {
            manifest
                .admins
                .retain(|a| a != &local_identity.user_identity.user_id);
        }
        manifest.roster_version = manifest.roster_version.saturating_add(1);
        manifest.updated_at = now;
        manifest.signer_user_id = local_identity.user_identity.user_id.clone();
        manifest.signer_device_id = local_identity.device_identity.device_id.clone();
        manifest.signature = self.sign_manifest(&manifest)?;
        manifest.validate()?;
        let metadata_payload = serde_json::to_vec(&manifest).map_err(|error| {
            CoreError::invalid_input(format!("failed to encode manifest: {error}"))
        })?;
        let metadata_b64 = STANDARD.encode(&metadata_payload);
        let capability = self.group_capability(&group_id, GroupRole::Owner)?;
        let membership_proof =
            self.build_membership_proof(&group_id, manifest.roster_version, "transfer_ownership")?;
        let mut envelope = self.build_group_envelope(
            &group_id,
            &group_state.conversation_id,
            GroupMessageType::ControlGroupMetadataUpdated,
            GroupEnvelopeVisibility::Visible,
            metadata_b64,
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

    fn set_group_admin(
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
        let mut manifest = group_state.manifest.clone();
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
            },
        );
        let metadata_payload = serde_json::to_vec(&manifest).map_err(|error| {
            CoreError::invalid_input(format!("failed to encode manifest: {error}"))
        })?;
        let metadata_b64 = STANDARD.encode(&metadata_payload);
        let capability = self.group_capability(&group_id, GroupRole::Owner)?;
        let membership_proof =
            self.build_membership_proof(&group_id, manifest.roster_version, "set_admin")?;
        let mut envelope = self.build_group_envelope(
            &group_id,
            &group_state.conversation_id,
            GroupMessageType::ControlGroupMetadataUpdated,
            GroupEnvelopeVisibility::Visible,
            metadata_b64,
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

    fn update_group_metadata(
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
        let mut manifest = group_state.manifest.clone();
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
            },
        );
        let metadata_payload = serde_json::to_vec(&manifest).map_err(|error| {
            CoreError::invalid_input(format!("failed to encode manifest: {error}"))
        })?;
        let metadata_b64 = STANDARD.encode(&metadata_payload);
        let capability = self.group_capability(&group_id, role)?;
        let membership_proof = if matches!(role, GroupRole::Owner | GroupRole::Admin) {
            Some(self.build_membership_proof(
                &group_id,
                manifest.roster_version,
                "update_metadata",
            )?)
        } else {
            None
        };
        let mut envelope = self.build_group_envelope(
            &group_id,
            &group_state.conversation_id,
            GroupMessageType::ControlGroupMetadataUpdated,
            GroupEnvelopeVisibility::Visible,
            metadata_b64,
        )?;
        if let Some(proof) = membership_proof {
            envelope.membership_proof = Some(proof);
        }
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

    fn send_attachment_message(
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

    fn download_attachment(
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

    fn attachment_payload_metadata_json(
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

    fn reconcile_conversation_membership(
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
            if let Some(adapter) = self.state.mls_adapter.as_mut() {
                if let Ok(summary) = adapter.attempt_recovery(&conversation_id) {
                    self.state
                        .mls_summaries
                        .insert(conversation_id.clone(), summary);
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

    fn sync_inbox(&mut self, device_id: String) -> CoreResult<CoreOutput> {
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
        let headers = self.device_runtime_headers()?;
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
                            endpoint: inbox_websocket_endpoint,
                            last_acked_seq,
                            headers: headers.clone(),
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
                        headers: headers.clone(),
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

    fn next_request_id(&mut self, prefix: &str) -> String {
        self.state.request_nonce = self.state.request_nonce.saturating_add(1);
        format!("{prefix}:{}", self.state.request_nonce)
    }
    fn next_message_nonce(&mut self) -> u64 {
        self.state.message_nonce = self.state.message_nonce.saturating_add(1);
        self.state.message_nonce
    }
    fn device_runtime_headers(&self) -> CoreResult<BTreeMap<String, String>> {
        let deployment = self
            .state
            .deployment_bundle
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("deployment bundle is not initialized"))?;
        let auth = deployment
            .device_runtime_auth
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("device runtime auth is not initialized"))?;
        if auth.scheme != "bearer" {
            return Err(CoreError::invalid_state(
                "unsupported device runtime auth scheme",
            ));
        }
        let mut headers = BTreeMap::new();
        headers.insert("Authorization".into(), format!("Bearer {}", auth.token));
        Ok(headers)
    }

    fn local_device_id_required(&self) -> CoreResult<String> {
        self.state
            .local_identity
            .as_ref()
            .map(|identity| identity.device_identity.device_id.clone())
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))
    }

    fn inbox_management_endpoint(&self, suffix: &str) -> CoreResult<String> {
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

    fn local_device_status_document(&self) -> CoreResult<DeviceStatusDocument> {
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

    fn local_shared_state_publish_effects(&self) -> CoreResult<Vec<CoreEffect>> {
        let mut effects = Vec::new();
        let Some(bundle) = self.state.local_bundle.as_ref() else {
            return Ok(effects);
        };
        let headers = self.device_runtime_headers()?;
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
                    headers: headers.clone(),
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
                    headers,
                },
            });
        }
        Ok(effects)
    }

    fn list_message_requests(&mut self) -> CoreResult<CoreOutput> {
        Ok(CoreOutput {
            state_update: CoreStateUpdate::default(),
            effects: vec![CoreEffect::FetchMessageRequests {
                fetch: FetchMessageRequestsRequest {
                    device_id: self.local_device_id_required()?,
                    endpoint: self.inbox_management_endpoint("message-requests")?,
                    headers: self.device_runtime_headers()?,
                },
            }],
            view_model: None,
        })
    }

    fn act_on_message_request(
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
                    headers: self.device_runtime_headers()?,
                },
            }],
            view_model: None,
        })
    }

    fn list_allowlist(&mut self) -> CoreResult<CoreOutput> {
        let device_id = self.local_device_id_required()?;
        Ok(CoreOutput {
            state_update: CoreStateUpdate::default(),
            effects: vec![CoreEffect::FetchAllowlist {
                fetch: FetchAllowlistRequest {
                    device_id,
                    endpoint: self.inbox_management_endpoint("allowlist")?,
                    headers: self.device_runtime_headers()?,
                },
            }],
            view_model: None,
        })
    }

    fn add_allowlist_user(&mut self, user_id: String) -> CoreResult<CoreOutput> {
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
                    headers: self.device_runtime_headers()?,
                },
            }],
            view_model: None,
        })
    }

    fn remove_allowlist_user(&mut self, user_id: String) -> CoreResult<CoreOutput> {
        let device_id = self.local_device_id_required()?;
        self.state.pending_allowlist_mutation = Some(PendingAllowlistMutation::Remove {
            user_id: user_id.clone(),
        });
        Ok(CoreOutput {
            state_update: CoreStateUpdate::default(),
            effects: vec![CoreEffect::FetchAllowlist {
                fetch: FetchAllowlistRequest {
                    device_id,
                    endpoint: self.inbox_management_endpoint("allowlist")?,
                    headers: self.device_runtime_headers()?,
                },
            }],
            view_model: None,
        })
    }

    fn refresh_identity_state(&mut self, user_id: String) -> CoreResult<CoreOutput> {
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

    fn rebuild_conversation(&mut self, conversation_id: String) -> CoreResult<CoreOutput> {
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
                    peer_user_id,
                    state: "needs_rebuild".into(),
                    kind: Some(ConversationKind::Direct),
                    title: None,
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
            let session = self
                .state
                .realtime_sessions
                .entry(device_id.clone())
                .or_default();
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
        let session = self
            .state
            .realtime_sessions
            .entry(device_id.clone())
            .or_default();
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

    fn handle_realtime_event(
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
        }
    }

    fn handle_timer(&mut self, timer_id: String) -> CoreResult<CoreOutput> {
        if let Some(device_id) = timer_id.strip_prefix("sync:") {
            return self.sync_inbox(device_id.to_string());
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
        let updated_at = self
            .state
            .local_bundle
            .as_ref()
            .map(|bundle| bundle.updated_at)
            .unwrap_or_else(|| {
                self.state
                    .local_identity
                    .as_ref()
                    .map(|identity| identity.device_status.updated_at)
                    .unwrap_or_default()
            });
        self.refresh_local_bundle_with_updated_at(updated_at)
    }

    fn refresh_local_bundle_with_updated_at(&mut self, updated_at: u64) -> CoreResult<()> {
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
        let mut signing_identity = local_identity.clone();
        signing_identity.device_status.updated_at = updated_at;
        let mut devices = self
            .state
            .local_bundle
            .as_ref()
            .map(|bundle| {
                bundle
                    .devices
                    .iter()
                    .filter(|device| device.device_id != local_identity.device_identity.device_id)
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let bundle_share_id = self
            .state
            .local_bundle
            .as_ref()
            .and_then(|bundle| bundle.bundle_share_id.clone());
        devices.push(
            crate::capability::CapabilityManager::build_device_contact_profile(
                &signing_identity,
                deployment,
                package.key_package_ref.clone(),
                package.expires_at,
            )?,
        );
        devices.sort_by(|left, right| left.device_id.cmp(&right.device_id));
        let bundle = IdentityManager::export_identity_bundle_with_devices(
            &signing_identity,
            deployment,
            devices,
            bundle_share_id,
        )?;
        self.state.local_bundle = Some(bundle);
        Ok(())
    }

    fn rotate_contact_share_link(&mut self) -> CoreResult<CoreOutput> {
        let updated_at = self
            .state
            .local_bundle
            .as_ref()
            .map(|bundle| bundle.updated_at.saturating_add(1))
            .unwrap_or_else(|| {
                self.state
                    .local_identity
                    .as_ref()
                    .map(|identity| identity.device_status.updated_at.saturating_add(1))
                    .unwrap_or(1)
            });
        self.refresh_local_bundle_with_share_id(updated_at, None)?;
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(&self.state, vec![PersistOp::SaveDeployment])],
            view_model: Some(CoreViewModel {
                banners: vec![SystemBanner {
                    status: SystemStatus::SyncInProgress,
                    message: "contact link rotated".into(),
                }],
                ..CoreViewModel::default()
            }),
        })
    }

    fn refresh_local_bundle_with_share_id(
        &mut self,
        updated_at: u64,
        bundle_share_id: Option<String>,
    ) -> CoreResult<()> {
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
        let mut signing_identity = local_identity.clone();
        signing_identity.device_status.updated_at = updated_at;
        let mut devices = self
            .state
            .local_bundle
            .as_ref()
            .map(|bundle| {
                bundle
                    .devices
                    .iter()
                    .filter(|device| device.device_id != local_identity.device_identity.device_id)
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        devices.push(
            crate::capability::CapabilityManager::build_device_contact_profile(
                &signing_identity,
                deployment,
                package.key_package_ref.clone(),
                package.expires_at,
            )?,
        );
        devices.sort_by(|left, right| left.device_id.cmp(&right.device_id));
        let bundle = IdentityManager::export_identity_bundle_with_devices(
            &signing_identity,
            deployment,
            devices,
            bundle_share_id,
        )?;
        self.state.local_bundle = Some(bundle);
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
        let bundle = self.direct_peer_contact_bundle(peer_user_id)?;
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
        let bundle = self.direct_peer_contact_bundle(peer_user_id)?;
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

    fn direct_peer_contact_bundle(&self, peer_user_id: &str) -> CoreResult<&IdentityBundle> {
        let bundle = self
            .state
            .contacts
            .get(peer_user_id)
            .ok_or_else(|| CoreError::invalid_input("peer contact is missing"))?;
        if bundle.bundle.identity_bundle_ref.is_none() {
            return Err(CoreError::invalid_input(
                "peer identity bundle reference is missing",
            ));
        }
        if !bundle
            .bundle
            .devices
            .iter()
            .any(|device| matches!(device.status, crate::model::DeviceStatusKind::Active))
        {
            return Err(CoreError::invalid_input(
                "peer identity bundle does not contain any active devices",
            ));
        }
        Ok(&bundle.bundle)
    }

    fn enqueue_envelopes(&mut self, peer_user_id: String, envelopes: Vec<Envelope>) {
        for envelope in envelopes {
            self.state.outbox.push(envelope.clone());
            self.state.pending_outbox.push(PendingOutboxItem {
                envelope,
                peer_user_id: peer_user_id.clone(),
                retries: 0,
                in_flight: false,
                plaintext_cache: None,
            });
        }
    }

    /// Enqueue envelopes with plaintext cache for sent messages
    fn enqueue_envelopes_with_plaintext(
        &mut self,
        peer_user_id: String,
        envelopes: Vec<Envelope>,
        plaintext: String,
    ) {
        for envelope in envelopes {
            self.state.outbox.push(envelope.clone());
            self.state.pending_outbox.push(PendingOutboxItem {
                envelope,
                peer_user_id: peer_user_id.clone(),
                retries: 0,
                in_flight: false,
                plaintext_cache: Some(plaintext.clone()),
            });
        }
    }

    fn ensure_conversation_ready_for_send(&mut self, conversation_id: &str) -> CoreResult<()> {
        if conversation_id.trim().is_empty() {
            return Err(CoreError::invalid_input(
                "conversation_id must not be empty",
            ));
        }
        // Get conversation state info first (immutable borrow)
        let (conv_state, recovery_status, peer_user_id) = {
            let conversation = self
                .state
                .conversations
                .get(conversation_id)
                .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?;
            (
                conversation.conversation.state,
                conversation.recovery_status,
                conversation.peer_user_id.clone(),
            )
        };

        if conv_state == ConversationState::NeedsRebuild {
            return Err(CoreError::invalid_state(
                "conversation needs rebuild before sending new messages",
            ));
        }

        // Check if conversation is still recovering
        if recovery_status == RecoveryStatus::NeedsRecovery {
            // The authoritative signal is the active recovery context: if a
            // context still exists, recovery has not converged and we must
            // fail-closed so the sender does not overclaim delivery.
            //
            // `mls_summaries` staying `Active` is *not* sufficient evidence
            // that recovery completed -- e.g. after a peer device change the
            // MLS group may still be cryptographically valid for the old
            // roster while a new commit is being prepared. Trusting the MLS
            // status alone here caused the sender to accept new messages
            // during recovery and regress the "fail-closed during recovery"
            // guarantee.
            if self.state.recovery_contexts.contains_key(conversation_id) {
                return Err(CoreError::temporary_failure(
                    "conversation membership is still recovering",
                ));
            }
            // No active recovery context left: recovery completed in a prior
            // step but the conversation's recovery_status field was never
            // cleared. Treat the conversation as healthy going forward.
            if let Some(state) = self.state.conversations.get_mut(conversation_id) {
                state.recovery_status = RecoveryStatus::Healthy;
            }
        }
        self.direct_peer_contact_bundle(&peer_user_id)?;
        Ok(())
    }

    fn ensure_recovery_context(
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
            })
    }

    fn mark_recovery_needed(&mut self, conversation_id: &str, reason: RecoveryReason) {
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

    fn transition_recovery_phase(&mut self, conversation_id: &str, next_phase: RecoveryPhase) {
        if let Some(context) = self.state.recovery_contexts.get_mut(conversation_id) {
            if context.phase != next_phase {
                context.phase = next_phase;
                context.attempt_count = context.attempt_count.saturating_add(1);
            }
        }
    }

    fn clear_recovery_context_as_healthy(&mut self, conversation_id: &str) {
        self.state.recovery_contexts.remove(conversation_id);
        if let Some(state) = self.state.conversations.get_mut(conversation_id) {
            if state.conversation.state != ConversationState::NeedsRebuild {
                state.recovery_status = RecoveryStatus::Healthy;
            }
        }
    }

    fn escalate_conversation_to_rebuild(
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
                },
            );
        }
        self.rebuild_conversation(conversation_id.to_string())
    }

    fn build_envelope(
        &mut self,
        conversation_id: &str,
        recipient_device_id: &str,
        message_type: MessageType,
        payload_b64: String,
    ) -> CoreResult<Envelope> {
        let identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .clone();
        let sender_user_id = identity.user_identity.user_id.clone();
        let sender_device_id = identity.device_identity.device_id.clone();
        let sender_proof = identity.sign_sender_proof(payload_b64.as_bytes());
        let message_nonce = self.next_message_nonce();
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(message_nonce);
        Ok(Envelope {
            version: crate::model::CURRENT_MODEL_VERSION.to_string(),
            message_id: self.next_message_id(conversation_id, recipient_device_id, message_nonce),
            conversation_id: conversation_id.to_string(),
            sender_user_id,
            sender_device_id,
            recipient_device_id: recipient_device_id.to_string(),
            created_at,
            message_type,
            inline_ciphertext: Some(payload_b64.clone()),
            storage_refs: vec![],
            delivery_class: DeliveryClass::Normal,
            wake_hint: None,
            sender_proof: SenderProof {
                proof_type: "device_signature".into(),
                value: sender_proof,
            },
        })
    }

    fn build_group_manifest(
        &self,
        group_id: &str,
        conversation_id: &str,
        title: &str,
        identity: &crate::identity::LocalIdentityState,
        member_user_ids: &[String],
        epoch: u64,
        now: u64,
    ) -> CoreResult<GroupManifest> {
        let mut members = vec![GroupMember {
            user_id: identity.user_identity.user_id.clone(),
            role: GroupRole::Owner,
            status: GroupMemberStatus::Active,
        }];
        members.extend(member_user_ids.iter().cloned().map(|user_id| GroupMember {
            user_id,
            role: GroupRole::Member,
            status: GroupMemberStatus::Active,
        }));
        let outbox = GroupOutboxDescriptor {
            endpoint: self.group_outbox_messages_endpoint(group_id)?,
            subscribe_endpoint: None,
        };
        let signature_payload = format!(
            "group_manifest:{group_id}:{conversation_id}:{title}:{}:{epoch}:{now}",
            identity.user_identity.user_id
        );
        Ok(GroupManifest {
            version: crate::model::CURRENT_MODEL_VERSION.to_string(),
            group_id: group_id.to_string(),
            conversation_id: conversation_id.to_string(),
            title: title.to_string(),
            owner_user_id: identity.user_identity.user_id.clone(),
            admins: Vec::new(),
            members,
            join_policy: GroupJoinPolicy::Closed,
            member_invite_policy: GroupMemberInvitePolicy::OwnerAdminOnly,
            roster_version: 1,
            mls_epoch_hint: epoch,
            last_commit_message_id: None,
            outbox,
            updated_at: now,
            signer_user_id: identity.user_identity.user_id.clone(),
            signer_device_id: identity.device_identity.device_id.clone(),
            signature: identity.sign_sender_proof(signature_payload.as_bytes()),
        })
    }

    fn build_group_envelope(
        &mut self,
        group_id: &str,
        conversation_id: &str,
        message_type: GroupMessageType,
        visibility: GroupEnvelopeVisibility,
        payload_b64: String,
    ) -> CoreResult<GroupEnvelope> {
        let identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .clone();
        let message_nonce = self.next_message_nonce();
        let created_at = current_unix_millis(message_nonce);
        let sender_proof = identity.sign_sender_proof(payload_b64.as_bytes());
        let message_id = format!(
            "msg:{conversation_id}:{}:{message_nonce}:group",
            identity.device_identity.device_id
        );
        Ok(GroupEnvelope {
            version: crate::model::CURRENT_MODEL_VERSION.to_string(),
            message_id,
            group_id: group_id.to_string(),
            conversation_id: conversation_id.to_string(),
            sender_user_id: identity.user_identity.user_id.clone(),
            sender_device_id: identity.device_identity.device_id.clone(),
            created_at,
            message_type,
            visibility,
            inline_ciphertext: Some(payload_b64),
            storage_refs: Vec::new(),
            sender_proof: SenderProof {
                proof_type: "device_signature".into(),
                value: sender_proof,
            },
            membership_proof: None,
        })
    }

    fn enqueue_group_envelope(
        &mut self,
        envelope: GroupEnvelope,
        capability: GroupCapability,
        plaintext: Option<String>,
    ) {
        self.state
            .pending_group_outbox
            .push(PendingGroupOutboxItem {
                envelope,
                capability,
                retries: 0,
                in_flight: false,
                plaintext_cache: plaintext,
            });
    }

    fn group_outbox_messages_endpoint(&self, group_id: &str) -> CoreResult<String> {
        let deployment = self
            .state
            .deployment_bundle
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("deployment bundle is not initialized"))?;
        Ok(format!(
            "{}/v1/groups/{}/outbox/messages",
            deployment.inbox_http_endpoint.trim_end_matches('/'),
            group_id
        ))
    }

    fn deployment_http_base(&self) -> CoreResult<String> {
        let deployment = self
            .state
            .deployment_bundle
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("deployment bundle is not initialized"))?;
        Ok(deployment
            .inbox_http_endpoint
            .trim_end_matches('/')
            .to_string())
    }

    fn stable_scoped_id(&self, prefix: &str, scope: &str, nonce: u64) -> String {
        let local_user_id = self
            .state
            .local_identity
            .as_ref()
            .map(|identity| identity.user_identity.user_id.as_str())
            .unwrap_or("user:local");
        let mut hasher = Sha256::new();
        hasher.update(prefix.as_bytes());
        hasher.update(b":");
        hasher.update(scope.as_bytes());
        hasher.update(b":");
        hasher.update(local_user_id.as_bytes());
        hasher.update(b":");
        hasher.update(nonce.to_le_bytes());
        format!("{prefix}:{}", hex_lower(&hasher.finalize()[..16]))
    }

    fn sign_manifest(&self, manifest: &GroupManifest) -> CoreResult<String> {
        let identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .clone();
        Ok(identity.sign_sender_proof(
            format!(
                "group_manifest:{}:{}:{}:{}",
                manifest.group_id,
                manifest.conversation_id,
                manifest.roster_version,
                manifest.updated_at
            )
            .as_bytes(),
        ))
    }

    fn local_identity_user_id(&self) -> CoreResult<String> {
        Ok(self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .user_identity
            .user_id
            .clone())
    }

    fn local_identity_device_id(&self) -> CoreResult<String> {
        Ok(self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .device_identity
            .device_id
            .clone())
    }

    fn build_membership_proof(
        &self,
        group_id: &str,
        roster_version: u64,
        operation: &str,
    ) -> CoreResult<SenderProof> {
        let identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?;
        Ok(SenderProof {
            proof_type: "membership_signature".into(),
            value: identity.sign_sender_proof(
                format!("membership_proof:{group_id}:{roster_version}:{operation}").as_bytes(),
            ),
        })
    }

    fn apply_membership_change_to_manifest(
        &self,
        manifest: &mut GroupManifest,
        epoch: u64,
        now: u64,
    ) -> CoreResult<()> {
        let identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .clone();
        manifest.roster_version = manifest.roster_version.saturating_add(1);
        manifest.mls_epoch_hint = epoch;
        manifest.updated_at = now;
        manifest.signer_user_id = identity.user_identity.user_id.clone();
        manifest.signer_device_id = identity.device_identity.device_id.clone();
        manifest.signature = self.sign_manifest(manifest)?;
        manifest.validate()
    }

    fn sync_conversation_members_from_manifest(
        &mut self,
        conversation_id: &str,
        manifest: &GroupManifest,
    ) -> CoreResult<()> {
        let local_identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?;
        let conversation = self
            .state
            .conversations
            .get_mut(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?;
        let mut member_users: Vec<String> = manifest
            .members
            .iter()
            .filter(|m| matches!(m.status, GroupMemberStatus::Active))
            .map(|m| m.user_id.clone())
            .collect();
        member_users.sort();
        member_users.dedup();
        conversation.conversation.member_users = member_users;
        let mut member_devices = vec![ConversationMember {
            user_id: local_identity.user_identity.user_id.clone(),
            device_id: local_identity.device_identity.device_id.clone(),
            status: DeviceStatusKind::Active,
        }];
        if let Ok(summary) = self
            .state
            .mls_adapter
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .export_group_summary(conversation_id)
        {
            for device_id in &summary.member_device_ids {
                if device_id != &local_identity.device_identity.device_id {
                    member_devices.push(ConversationMember {
                        user_id: String::new(),
                        device_id: device_id.clone(),
                        status: DeviceStatusKind::Active,
                    });
                }
            }
        }
        conversation.conversation.member_devices = member_devices;
        conversation.conversation.updated_at = manifest.updated_at;
        Ok(())
    }

    fn verify_membership_operation_authority(
        &self,
        envelope: &GroupEnvelope,
        manifest: &GroupManifest,
    ) -> CoreResult<()> {
        let sender_role = manifest
            .members
            .iter()
            .find(|m| {
                m.user_id == envelope.sender_user_id
                    && matches!(m.status, GroupMemberStatus::Active)
            })
            .map(|m| m.role);
        match sender_role {
            Some(GroupRole::Owner | GroupRole::Admin) => {}
            Some(GroupRole::Member) | None => {
                return Err(CoreError::invalid_input(
                    "sender is not an active owner or admin; membership operation rejected",
                ));
            }
        }
        let proof = envelope.membership_proof.as_ref().ok_or_else(|| {
            CoreError::invalid_input("membership operation requires membership_proof")
        })?;
        if proof.proof_type != "membership_signature" {
            return Err(CoreError::invalid_input(
                "membership_proof type must be membership_signature",
            ));
        }
        if proof.value.trim().is_empty() {
            return Err(CoreError::invalid_input(
                "membership_proof value must not be empty",
            ));
        }
        Ok(())
    }

    fn try_apply_control_manifest_update(
        &mut self,
        conversation_id: &str,
        group_id: &str,
        record: &GroupOutboxRecord,
        current_state: &PersistedGroupState,
    ) -> bool {
        if !matches!(
            record.envelope.message_type,
            GroupMessageType::ControlGroupMembershipChanged
                | GroupMessageType::ControlGroupMetadataUpdated
        ) {
            return false;
        }
        let Some(ciphertext) = &record.envelope.inline_ciphertext else {
            return false;
        };
        let mls = match self.state.mls_adapter.as_mut() {
            Some(adapter) => adapter,
            None => return false,
        };
        let result = match mls.ingest_message(
            conversation_id,
            &record.envelope.sender_device_id,
            MessageType::MlsApplication,
            ciphertext,
        ) {
            Ok(result) => result,
            Err(_) => return false,
        };
        let plaintext = match result {
            IngestResult::AppliedApplication(app) => app.plaintext,
            _ => return false,
        };
        let updated = match serde_json::from_slice::<GroupManifest>(&plaintext) {
            Ok(manifest) => manifest,
            Err(_) => return false,
        };
        if updated.group_id != group_id {
            return false;
        }
        if updated.roster_version <= current_state.manifest.roster_version {
            log::warn!(
                "rejected stale manifest update for group {group_id}: new roster_version {} is not newer than current {}",
                updated.roster_version,
                current_state.manifest.roster_version
            );
            return false;
        }
        if let Err(err) = updated.validate() {
            log::warn!("rejected invalid manifest update for group {group_id}: {err}");
            return false;
        }
        if !Self::validate_manifest_transition(&current_state.manifest, &updated) {
            log::warn!(
                "rejected invalid manifest transition for group {group_id} at roster_version {} -> {}",
                current_state.manifest.roster_version,
                updated.roster_version
            );
            return false;
        }
        let local_user_id = self
            .state
            .local_identity
            .as_ref()
            .map(|id| id.user_identity.user_id.clone());
        let updated_local_role = local_user_id.as_ref().and_then(|uid| {
            updated
                .members
                .iter()
                .find(|m| &m.user_id == uid && m.status == GroupMemberStatus::Active)
                .map(|m| m.role)
        });
        self.state.group_states.insert(
            group_id.to_string(),
            PersistedGroupState {
                group_id: group_id.to_string(),
                conversation_id: conversation_id.to_string(),
                manifest: updated.clone(),
                local_role: updated_local_role,
                welcome_pickup: current_state.welcome_pickup.clone(),
                dissolved_at: current_state.dissolved_at,
            },
        );
        let _ = self.sync_conversation_members_from_manifest(conversation_id, &updated);
        true
    }

    fn validate_manifest_transition(old: &GroupManifest, new: &GroupManifest) -> bool {
        if old.group_id != new.group_id || old.conversation_id != new.conversation_id {
            return false;
        }
        if new.roster_version != old.roster_version.saturating_add(1) {
            return false;
        }
        if new.mls_epoch_hint < old.mls_epoch_hint {
            return false;
        }
        let signer_role = old
            .members
            .iter()
            .find(|member| {
                member.user_id == new.signer_user_id && member.status == GroupMemberStatus::Active
            })
            .map(|member| member.role);
        if !matches!(signer_role, Some(GroupRole::Owner | GroupRole::Admin)) {
            return false;
        }
        let active_count = |m: &GroupManifest| {
            m.members
                .iter()
                .filter(|m| m.status == GroupMemberStatus::Active)
                .count()
        };
        let active_owner_count = |m: &GroupManifest| {
            m.members
                .iter()
                .filter(|m| m.role == GroupRole::Owner && m.status == GroupMemberStatus::Active)
                .count()
        };
        if active_owner_count(new) != 1 {
            return false;
        }
        if new.owner_user_id
            != new
                .members
                .iter()
                .find(|m| m.role == GroupRole::Owner && m.status == GroupMemberStatus::Active)
                .map(|m| m.user_id.as_str())
                .unwrap_or("")
        {
            return false;
        }
        if active_count(new) == 0 {
            return false;
        }
        true
    }

    fn welcome_pickup_descriptor(
        &self,
        group_id: &str,
        device_id: &str,
    ) -> CoreResult<WelcomePickupDescriptor> {
        let deployment = self
            .state
            .deployment_bundle
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("deployment bundle is not initialized"))?;
        let identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?;
        let expires_at = current_unix_millis(self.state.message_nonce) + 24 * 60 * 60 * 1000;
        let endpoint = format!(
            "{}/v1/groups/{}/welcome-pickup/{}",
            deployment.inbox_http_endpoint.trim_end_matches('/'),
            group_id,
            device_id
        );
        let capability = identity.sign_sender_proof(
            format!("welcome_pickup:{group_id}:{device_id}:{expires_at}").as_bytes(),
        );
        Ok(WelcomePickupDescriptor {
            group_id: group_id.to_string(),
            device_id: device_id.to_string(),
            endpoint,
            capability,
            expires_at,
        })
    }

    fn group_capability(&self, group_id: &str, role: GroupRole) -> CoreResult<GroupCapability> {
        let identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?;
        let expires_at = current_unix_millis(self.state.message_nonce) + 24 * 60 * 60 * 1000;
        let operations = group_capability_operations(role);
        let signature = identity.sign_sender_proof(
            format!(
                "group_capability:{group_id}:{}:{}:{expires_at}",
                identity.user_identity.user_id, identity.device_identity.device_id
            )
            .as_bytes(),
        );
        Ok(GroupCapability {
            version: crate::model::CURRENT_MODEL_VERSION.to_string(),
            service: CapabilityService::GroupOutbox,
            group_id: group_id.to_string(),
            user_id: identity.user_identity.user_id.clone(),
            device_id: identity.device_identity.device_id.clone(),
            operations,
            role,
            expires_at,
            signature,
        })
    }

    fn group_capability_for_state(
        &self,
        state: &PersistedGroupState,
    ) -> CoreResult<GroupCapability> {
        let role = state
            .local_role
            .ok_or_else(|| CoreError::invalid_input("local group role is missing"))?;
        self.group_capability(&state.group_id, role)
    }

    fn local_group_role(&self, group_id: &str) -> CoreResult<GroupRole> {
        self.state
            .group_states
            .get(group_id)
            .and_then(|state| state.local_role)
            .ok_or_else(|| CoreError::invalid_input("local group role is missing"))
    }

    fn group_id_for_conversation(&self, conversation_id: &str) -> CoreResult<&str> {
        self.state
            .group_states
            .values()
            .find(|state| state.conversation_id == conversation_id)
            .map(|state| state.group_id.as_str())
            .ok_or_else(|| CoreError::invalid_input("group conversation does not exist"))
    }

    fn ensure_group_ready_for_send(&self, conversation_id: &str) -> CoreResult<()> {
        let conversation = self
            .state
            .conversations
            .get(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?;
        if conversation.conversation.kind != ConversationKind::Group {
            return Err(CoreError::invalid_input("conversation is not a group"));
        }
        if conversation.conversation.state == ConversationState::Dissolved {
            return Err(CoreError::invalid_input("group is dissolved"));
        }
        if conversation.conversation.state == ConversationState::NeedsRebuild
            || conversation.recovery_status != RecoveryStatus::Healthy
        {
            return Err(CoreError::temporary_failure(
                "group conversation is not ready for sending",
            ));
        }
        let summary = self
            .state
            .mls_summaries
            .get(conversation_id)
            .ok_or_else(|| CoreError::invalid_state("group MLS state is missing"))?;
        if summary.status != MlsStateStatus::Active {
            return Err(CoreError::temporary_failure(
                "group MLS state is not active",
            ));
        }
        let local_identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?;
        let group_state = self
            .state
            .group_states
            .values()
            .find(|state| state.conversation_id == conversation_id)
            .ok_or_else(|| CoreError::invalid_input("group conversation does not exist"))?;
        // A.5: dissolved groups fail-closed locally before any transport
        // layer gets involved — even if `ConversationState` has not yet been
        // flipped to Dissolved (the transition happens on
        // `CoreEvent::GroupOutboxSealed`, so between the initial
        // `DissolveGroup` command and the seal ack there is a brief window
        // where `dissolved_at.is_some()` but conversation state is still
        // Active).
        if group_state.dissolved_at.is_some() {
            return Err(CoreError::invalid_input("group is dissolved"));
        }
        let Some(local_role) = group_state.local_role else {
            return Err(CoreError::invalid_input("local group member is not active"));
        };
        let local_is_active = group_state.manifest.members.iter().any(|member| {
            member.user_id == local_identity.user_identity.user_id
                && member.role == local_role
                && member.status == GroupMemberStatus::Active
        });
        if !local_is_active {
            return Err(CoreError::invalid_input("local group member is not active"));
        }
        Ok(())
    }

    fn next_group_id(&mut self, title: &str, members: &[String]) -> String {
        let nonce = self.next_message_nonce();
        let local_user_id = self
            .state
            .local_identity
            .as_ref()
            .map(|identity| identity.user_identity.user_id.as_str())
            .unwrap_or("user:local");
        let mut hasher = Sha256::new();
        hasher.update(local_user_id.as_bytes());
        hasher.update(title.as_bytes());
        for member in members {
            hasher.update(member.as_bytes());
        }
        hasher.update(nonce.to_be_bytes());
        let digest = hasher.finalize();
        format!("group:{}", hex_prefix(&digest, 16))
    }

    fn conversation_summary(&self, conversation_id: &str) -> CoreResult<ConversationSummary> {
        let conversation = self
            .state
            .conversations
            .get(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?;
        if conversation.conversation.kind == ConversationKind::Group {
            let group_state = self
                .state
                .group_states
                .values()
                .find(|state| state.conversation_id == conversation_id);
            return Ok(ConversationSummary {
                conversation_id: conversation_id.to_string(),
                peer_user_id: conversation.peer_user_id.clone(),
                state: match conversation.recovery_status {
                    RecoveryStatus::Healthy => "active".into(),
                    RecoveryStatus::NeedsRecovery => "needs_recovery".into(),
                    RecoveryStatus::NeedsRebuild => "needs_rebuild".into(),
                },
                kind: Some(ConversationKind::Group),
                title: group_state.map(|state| state.manifest.title.clone()),
                group_id: group_state.map(|state| state.group_id.clone()),
                member_count: group_state.map(|state| {
                    state
                        .manifest
                        .members
                        .iter()
                        .filter(|member| member.status == GroupMemberStatus::Active)
                        .count()
                }),
                group_role: group_state.and_then(|state| state.local_role),
                group_cursor: group_state
                    .and_then(|state| self.state.group_cursors.get(&state.group_id).cloned()),
                last_message_preview: None,
                last_message_type: conversation.last_message_type,
                message_count: Some(conversation.messages.len()),
                recovery: self.recovery_snapshot_for_conversation(conversation_id),
            });
        }
        Ok(ConversationSummary {
            conversation_id: conversation_id.to_string(),
            peer_user_id: conversation.peer_user_id.clone(),
            state: match conversation.recovery_status {
                RecoveryStatus::Healthy => "active".into(),
                RecoveryStatus::NeedsRecovery => "needs_recovery".into(),
                RecoveryStatus::NeedsRebuild => "needs_rebuild".into(),
            },
            kind: Some(ConversationKind::Direct),
            title: None,
            group_id: None,
            member_count: None,
            group_role: None,
            group_cursor: None,
            last_message_preview: None,
            last_message_type: conversation.last_message_type,
            message_count: None,
            recovery: self.recovery_snapshot_for_conversation(conversation_id),
        })
    }

    fn set_local_display_name(&mut self, display_name: Option<String>) -> CoreResult<CoreOutput> {
        // Validate display_name if provided
        if let Some(ref name) = display_name {
            crate::model::validate_display_name(name)?;
        }

        self.state.local_display_name = display_name.clone();

        // Re-generate and sign the identity bundle with new display_name
        let publish_effects = if self.state.local_identity.is_some()
            && self.state.deployment_bundle.is_some()
        {
            // Build devices list from existing bundle
            let devices: Vec<crate::model::DeviceContactProfile> = self
                .state
                .local_bundle
                .as_ref()
                .map(|b| b.devices.clone())
                .unwrap_or_default();

            // Get existing bundle_share_id
            let bundle_share_id = self
                .state
                .local_bundle
                .as_ref()
                .and_then(|b| b.bundle_share_id.clone());

            // Re-export identity bundle with new display_name
            let local_identity = self.state.local_identity.as_ref().unwrap();
            let deployment = self.state.deployment_bundle.as_ref().unwrap();

            let encoded_user_id =
                urlencoding::encode(&local_identity.user_identity.user_id).into_owned();
            let unsigned = crate::model::IdentityBundle {
                version: crate::model::CURRENT_MODEL_VERSION.to_string(),
                user_id: local_identity.user_identity.user_id.clone(),
                user_public_key: local_identity.user_identity.user_public_key.clone(),
                devices,
                bundle_share_id: Some(
                    bundle_share_id.unwrap_or_else(|| crate::identity::generate_bundle_share_id()),
                ),
                identity_bundle_ref: deployment
                    .runtime_config
                    .identity_bundle_ref
                    .clone()
                    .map(|reference| reference.replace("{userId}", &encoded_user_id)),
                device_status_ref: deployment
                    .runtime_config
                    .device_status_ref
                    .clone()
                    .map(|reference| reference.replace("{userId}", &encoded_user_id)),
                storage_profile: Some(crate::model::StorageProfile {
                    base_url: deployment.storage_base_info.base_url.clone(),
                    profile_ref: None,
                }),
                display_name: display_name.clone(),
                updated_at: local_identity.device_status.updated_at,
                signature: String::new(),
            };

            // Sign the bundle
            let signature = local_identity
                .user_root_signing_key()
                .sign(crate::identity::identity_bundle_payload(&unsigned).as_bytes());
            let signed_bundle = crate::model::IdentityBundle {
                signature: crate::identity::encode_hex(&signature.to_bytes()),
                ..unsigned
            };

            // Update the local bundle
            self.state.local_bundle = Some(signed_bundle.clone());

            // Generate publish effects
            self.local_shared_state_publish_effects()?
        } else {
            // Just update the bundle display_name if we can't re-sign
            if let Some(ref mut bundle) = self.state.local_bundle {
                bundle.display_name = display_name.clone();
            }
            vec![]
        };

        let persist_effect = persist_effect(&self.state, vec![PersistOp::SaveDeployment]);

        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: {
                let mut effects = publish_effects;
                effects.push(persist_effect);
                effects
            },
            view_model: Some(CoreViewModel {
                contacts: vec![ContactSummary {
                    user_id: self
                        .state
                        .local_identity
                        .as_ref()
                        .map(|i| i.user_identity.user_id.clone())
                        .unwrap_or_default(),
                    display_name,
                    device_count: 1,
                }],
                ..CoreViewModel::default()
            }),
        })
    }

    fn set_contact_display_name(
        &mut self,
        user_id: String,
        display_name: Option<String>,
    ) -> CoreResult<CoreOutput> {
        // Validate display_name if provided
        if let Some(ref name) = display_name {
            crate::model::validate_display_name(name)?;
        }

        // Check if contact exists
        if !self.state.contacts.contains_key(&user_id) {
            return Err(CoreError::invalid_input("contact does not exist"));
        }

        // Update display_name
        if let Some(contact) = self.state.contacts.get_mut(&user_id) {
            contact.display_name = display_name.clone();
        }

        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(
                &self.state,
                vec![PersistOp::SaveContact { user_id }],
            )],
            view_model: Some(CoreViewModel {
                contacts: self
                    .state
                    .contacts
                    .iter()
                    .map(|(uid, c)| ContactSummary {
                        user_id: uid.clone(),
                        display_name: c.display_name.clone().or(c.original_name.clone()),
                        device_count: c.bundle.devices.len(),
                    })
                    .collect(),
                ..CoreViewModel::default()
            }),
        })
    }

    fn delete_contact(&mut self, user_id: String) -> CoreResult<CoreOutput> {
        // Check if contact exists
        if !self.state.contacts.contains_key(&user_id) {
            return Err(CoreError::invalid_input("contact does not exist"));
        }

        // Remove contact from state
        self.state.contacts.remove(&user_id);

        // Remove any conversations with this peer
        let conversation_ids_to_remove: Vec<String> = self
            .state
            .conversations
            .iter()
            .filter(|(_, conv)| conv.peer_user_id == user_id)
            .map(|(id, _)| id.clone())
            .collect();

        // Collect persistence operations
        let mut persist_ops: Vec<PersistOp> = vec![PersistOp::DeleteContact {
            user_id: user_id.clone(),
        }];

        for conv_id in &conversation_ids_to_remove {
            // Remove from state
            self.state.conversations.remove(conv_id);
            self.state.mls_summaries.remove(conv_id);
            self.state.recovery_contexts.remove(conv_id);

            // Remove MLS group from adapter
            if let Some(ref mut mls_adapter) = self.state.mls_adapter {
                mls_adapter.delete_group(conv_id)?;
            }

            // Add persistence operations
            persist_ops.push(PersistOp::DeleteConversation {
                conversation_id: conv_id.clone(),
            });
            persist_ops.push(PersistOp::DeleteMlsState {
                conversation_id: conv_id.clone(),
            });
            persist_ops.push(PersistOp::DeleteRecoveryContext {
                conversation_id: conv_id.clone(),
            });
        }

        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                conversations_changed: !conversation_ids_to_remove.is_empty(),
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(&self.state, persist_ops)],
            view_model: Some(CoreViewModel {
                contacts: self
                    .state
                    .contacts
                    .iter()
                    .map(|(uid, c)| ContactSummary {
                        user_id: uid.clone(),
                        display_name: c.display_name.clone().or(c.original_name.clone()),
                        device_count: c.bundle.devices.len(),
                    })
                    .collect(),
                ..CoreViewModel::default()
            }),
        })
    }

    fn recovery_snapshot_for_conversation(
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
        })
    }

    fn build_control_membership_changed_messages(
        &mut self,
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
        &mut self,
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
        &mut self,
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
        &mut self,
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

    fn next_message_id(&self, conversation_id: &str, suffix: &str, message_nonce: u64) -> String {
        format!("msg:{conversation_id}:{message_nonce}:{suffix}")
    }

    fn merge_with_transport_flush(&mut self, output: CoreOutput) -> CoreResult<CoreOutput> {
        Ok(merge_outputs(output, self.flush_pending_transport()?))
    }

    fn flush_pending_transport(&mut self) -> CoreResult<CoreOutput> {
        let mut output = CoreOutput::default();
        output = merge_outputs(output, self.flush_outbox()?);
        output = merge_outputs(output, self.flush_group_outbox()?);
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

    fn flush_group_outbox(&mut self) -> CoreResult<CoreOutput> {
        let mut effects = Vec::new();
        for index in 0..self.state.pending_group_outbox.len() {
            if self.state.pending_group_outbox[index].in_flight
                || self.state.pending_group_outbox[index].retries >= MAX_TRANSPORT_RETRIES
            {
                continue;
            }
            let item = self.state.pending_group_outbox[index].clone();
            self.state.pending_group_outbox[index].in_flight = true;
            effects.push(CoreEffect::AppendGroupEnvelope {
                append: AppendGroupEnvelopeRequest {
                    version: crate::model::CURRENT_MODEL_VERSION.to_string(),
                    group_id: item.envelope.group_id.clone(),
                    envelope: item.envelope,
                    capability: item.capability,
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
        let headers = self.device_runtime_headers()?;
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
                        headers: headers.clone(),
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
            sender_display_name: None,
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
        let inbox_http_endpoint = deployment.inbox_http_endpoint.clone();
        let request_id = self.next_request_id(&format!("ack:{}", ack.device_id));
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
                inbox_http_endpoint.trim_end_matches('/'),
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
        let inbox_http_endpoint = deployment.inbox_http_endpoint.clone();
        let headers = self.device_runtime_headers()?;
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
                    headers: headers.clone(),
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
            PendingRequest::AppendEnvelope { message_id, .. } => {
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
                let request_output = self.handle_append_delivery_result(&message_id, &result);
                self.state
                    .pending_outbox
                    .retain(|item| item.envelope.message_id != message_id);
                Ok(merge_outputs(
                    request_output,
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
                self.flush_pending_transport()
            }
            PendingRequest::AppendGroupEnvelope {
                group_id,
                message_id,
            } => {
                let result: AppendGroupEnvelopeResult = serde_json::from_str(
                    body.as_deref().unwrap_or("{\"accepted\":false,\"seq\":0}"),
                )
                .map_err(|error| {
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
                        timer: TimerEffect {
                            timer_id: format!("sync:{device_id}"),
                            delay_ms: 0,
                        },
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
            } => self.handle_group_append_failed(group_id, message_id, retryable, detail),
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

    fn handle_blob_uploaded(&mut self, task_id: String) -> CoreResult<CoreOutput> {
        let task = self
            .state
            .pending_blob_uploads
            .remove(&task_id)
            .ok_or_else(|| CoreError::invalid_input("unknown blob upload task"))?;
        let prepared = task.prepared_upload.ok_or_else(|| {
            CoreError::invalid_state("blob upload completed before upload target was prepared")
        })?;
        let final_ref = prepared.download_target.clone().ok_or_else(|| {
            CoreError::invalid_state("blob upload result is missing download target")
        })?;
        let payload_metadata = task.payload_metadata.clone().ok_or_else(|| {
            CoreError::invalid_state("blob upload completed before payload metadata was prepared")
        })?;
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
            expires_at: prepared.expires_at,
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
            self.enqueue_envelopes_with_plaintext(peer_user_id, envelopes, payload_metadata_json);
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

    fn handle_attachment_bytes_loaded(
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

    fn handle_blob_downloaded(
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
            task.retries = task.retries.saturating_add(1);
            if retryable && task.retries < MAX_TRANSPORT_RETRIES {
                return Ok(CoreOutput {
                    state_update: CoreStateUpdate {
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
            if let Some(detail) = detail {
                log::warn!("attachment download failed: {detail}");
            } else {
                log::warn!("attachment download failed");
            }
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

    fn handle_inbox_records(
        &mut self,
        device_id: String,
        records: Vec<InboxRecord>,
        to_seq: u64,
    ) -> CoreResult<CoreOutput> {
        self.handle_inbox_records_internal(device_id, records, to_seq, true)
    }

    fn handle_inbox_records_internal(
        &mut self,
        device_id: String,
        records: Vec<InboxRecord>,
        to_seq: u64,
        allow_pending_replay: bool,
    ) -> CoreResult<CoreOutput> {
        let mut pending_recovery_conversations = BTreeSet::new();
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
                                    record.message_id,
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
                                            "handle_inbox_records: Set plaintext for message {} to {:?}",
                                            record.message_id,
                                            message.plaintext.as_deref().map(|s| if s.len() > 50 {
                                                &s[..50]
                                            } else {
                                                s
                                            })
                                        );
                                    } else {
                                        log::warn!(
                                            "handle_inbox_records: Could not find message {} in conversation {} to set plaintext",
                                            record.message_id,
                                            conversation_id
                                        );
                                    }
                                } else {
                                    log::warn!(
                                        "handle_inbox_records: Conversation {} not found for message {}",
                                        conversation_id,
                                        record.message_id
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
                                self.clear_recovery_context_as_healthy(&conversation_id);
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
                                self.clear_recovery_context_as_healthy(&conversation_id);
                                ackable = true;
                            }
                            IngestResult::AppliedWelcome { epoch } => {
                                log::info!(
                                    "handle_inbox_records: AppliedWelcome for message {} in conversation {}, epoch={}",
                                    record.message_id,
                                    conversation_id,
                                    epoch
                                );
                                self.clear_pending_records_for_conversation(
                                    &device_id,
                                    &conversation_id,
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
                                self.clear_recovery_context_as_healthy(&conversation_id);
                                ackable = true;
                            }
                            IngestResult::PendingRetry => {
                                log::warn!(
                                    "handle_inbox_records: PendingRetry for message {} in conversation {}",
                                    record.message_id,
                                    conversation_id
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
                                pending_recovery_conversations.insert(conversation_id.clone());
                            }
                            IngestResult::NeedsRebuild => {
                                log::warn!(
                                    "handle_inbox_records: NeedsRebuild for message {} in conversation {}",
                                    record.message_id,
                                    conversation_id
                                );
                                output = merge_outputs(
                                    output,
                                    self.escalate_conversation_to_rebuild(
                                        &conversation_id,
                                        RecoveryEscalationReason::MlsMarkedUnrecoverable,
                                        "MLS marked conversation unrecoverable",
                                    )?,
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
                                self.escalate_conversation_to_rebuild(
                                    &conversation_id,
                                    RecoveryEscalationReason::ExplicitNeedsRebuildControl,
                                    "conversation received explicit rebuild control message",
                                )?,
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
        output = merge_outputs(
            output,
            self.process_pending_recovery_batch(
                &device_id,
                pending_recovery_conversations,
                allow_pending_replay,
            )?,
        );
        self.merge_with_transport_flush(output)
    }

    fn process_pending_recovery_batch(
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
                last_known_peer_active_devices: BTreeSet::from([record
                    .envelope
                    .sender_device_id
                    .clone()]),
                recovery_status: RecoveryStatus::Healthy,
            });
    }

    fn clear_pending_records_for_conversation(&mut self, device_id: &str, conversation_id: &str) {
        let Some(sync_state) = self.state.sync_states.get_mut(device_id) else {
            return;
        };
        let pending_seqs: Vec<u64> = sync_state
            .pending_records
            .iter()
            .filter_map(|(seq, record)| {
                (record.envelope.conversation_id == conversation_id).then_some(*seq)
            })
            .collect();
        for seq in pending_seqs {
            SyncEngine::clear_pending_retry(sync_state, seq);
        }
    }

    fn recovery_reason_for_record(&self, conversation_id: &str) -> RecoveryReason {
        if self.state.mls_summaries.contains_key(conversation_id) {
            RecoveryReason::MissingCommit
        } else {
            RecoveryReason::MissingWelcome
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
            PendingRequest::AppendGroupEnvelope {
                group_id,
                message_id,
            } => self.handle_group_append_failed(
                group_id,
                message_id,
                status >= 500,
                body.or_else(|| Some(format!("group append returned status {status}"))),
            ),
            PendingRequest::FetchGroupOutbox { group_id, .. } => Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect {
                        status: SystemStatus::TemporaryNetworkFailure,
                        message: body.unwrap_or_else(|| {
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
                        message: body.unwrap_or_else(|| {
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

    fn handle_append_delivery_result(
        &mut self,
        message_id: &str,
        result: &AppendEnvelopeResult,
    ) -> CoreOutput {
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

        let envelope = pending_item.map(|item| item.envelope.clone());

        let append_result = AppendResultSummary {
            accepted: result.accepted,
            delivered_to: result.delivered_to.clone(),
            queued_as_request: result.queued_as_request,
            request_id: result.request_id.clone(),
            seq: Some(result.seq),
        };

        // When message is delivered to inbox, store it in conversation.messages
        // This ensures the message is preserved even after pending_outbox is cleared
        let messages_changed = if result.delivered_to == AppendDeliveryDisposition::Inbox {
            if let Some(env) = &envelope {
                let conversation_id = env.conversation_id.clone();
                if let Some(conv) = self.state.conversations.get_mut(&conversation_id) {
                    // Check if message already exists (avoid duplicates)
                    if !conv.messages.iter().any(|m| m.message_id == message_id) {
                        conv.messages.push(crate::conversation::StoredMessage {
                            message_id: message_id.to_string(),
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
                            message_id,
                            conversation_id,
                            plaintext_cache.is_some()
                        );
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
                return CoreOutput {
                    state_update: CoreStateUpdate {
                        messages_changed,
                        conversations_changed: messages_changed,
                        ..CoreStateUpdate::default()
                    },
                    effects: vec![],
                    view_model: Some(CoreViewModel {
                        append_result: Some(append_result),
                        ..CoreViewModel::default()
                    }),
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
        CoreOutput {
            state_update: CoreStateUpdate {
                system_statuses_changed: vec![status],
                ..CoreStateUpdate::default()
            },
            effects: vec![CoreEffect::EmitUserNotification {
                notification: UserNotificationEffect { status, message },
            }],
            view_model: Some(CoreViewModel {
                append_result: Some(append_result),
                banners: vec![SystemBanner {
                    status,
                    message: banner,
                }],
                ..CoreViewModel::default()
            }),
        }
    }

    fn message_requests_output(&self, requests: Vec<MessageRequestItem>) -> CoreOutput {
        CoreOutput {
            state_update: CoreStateUpdate::default(),
            effects: vec![],
            view_model: Some(CoreViewModel {
                message_requests: requests,
                ..CoreViewModel::default()
            }),
        }
    }

    fn message_request_action_output(&self, result: MessageRequestActionResult) -> CoreOutput {
        let message = match result.action {
            MessageRequestAction::Accept => {
                format!("accepted message request {}", result.request_id)
            }
            MessageRequestAction::Reject => {
                format!("rejected message request {}", result.request_id)
            }
        };
        CoreOutput {
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
                    request_id: result.request_id,
                    sender_user_id: result.sender_user_id,
                    promoted_count: result.promoted_count,
                    action: result.action,
                }),
                banners: vec![SystemBanner {
                    status: SystemStatus::SyncInProgress,
                    message,
                }],
                ..CoreViewModel::default()
            }),
        }
    }

    fn allowlist_output(&self, document: AllowlistDocument, updated: bool) -> CoreOutput {
        let message = if updated {
            "allowlist updated"
        } else {
            "allowlist loaded"
        };
        CoreOutput {
            state_update: CoreStateUpdate::default(),
            effects: vec![],
            view_model: Some(CoreViewModel {
                allowlist: Some(document),
                banners: if updated {
                    vec![SystemBanner {
                        status: SystemStatus::SyncInProgress,
                        message: message.into(),
                    }]
                } else {
                    Vec::new()
                },
                ..CoreViewModel::default()
            }),
        }
    }

    fn handle_allowlist_fetched(
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
            }
        }
        Ok(CoreOutput {
            state_update: CoreStateUpdate::default(),
            effects: vec![CoreEffect::ReplaceAllowlist {
                update: ReplaceAllowlistRequest {
                    device_id: self.local_device_id_required()?,
                    endpoint: self.inbox_management_endpoint("allowlist")?,
                    headers: self.device_runtime_headers()?,
                    document,
                },
            }],
            view_model: None,
        })
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
                if context.identity_refresh_retry_count < MAX_TRANSPORT_RETRIES {
                    context.identity_refresh_retry_count =
                        context.identity_refresh_retry_count.saturating_add(1);
                }
                context.phase = RecoveryPhase::WaitingForIdentityRefresh;
                context.last_error = Some(message.clone());
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

    fn handle_group_outbox_head_fetched(
        &mut self,
        group_id: String,
        head_seq: u64,
    ) -> CoreResult<CoreOutput> {
        // This event is emitted after a successful welcome pickup so that the
        // fresh joiner skips every outbox record produced before she was
        // added: those records belong to MLS epochs she cannot decrypt and
        // would otherwise trip the sync engine into a false recovery loop.
        // The head is advisory -- only advance the cursor, never roll it
        // back, so concurrent fetches that already progressed past `head`
        // keep their progress.
        let Some(cursor) = self.state.group_cursors.get_mut(&group_id) else {
            return Ok(CoreOutput::default());
        };
        if head_seq <= cursor.last_fetched_seq {
            return Ok(CoreOutput::default());
        }
        cursor.last_fetched_seq = head_seq;
        cursor.updated_at = current_unix_millis(self.state.message_nonce);
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                checkpoints_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(
                &self.state,
                vec![PersistOp::SaveGroupCursor {
                    group_id: group_id.clone(),
                }],
            )],
            view_model: None,
        })
    }

    fn handle_group_outbox_records(
        &mut self,
        group_id: String,
        mut records: Vec<GroupOutboxRecord>,
        to_seq: u64,
    ) -> CoreResult<CoreOutput> {
        let group_state = self
            .state
            .group_states
            .get(&group_id)
            .ok_or_else(|| CoreError::invalid_input("group does not exist"))?
            .clone();
        let conversation_id = group_state.conversation_id.clone();
        records.sort_by_key(|record| record.seq);
        let mut messages = Vec::new();
        for record in records {
            record.validate()?;
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
                continue;
            }
            let is_membership_operation = matches!(
                record.envelope.message_type,
                GroupMessageType::MlsCommit
                    | GroupMessageType::ControlGroupMembershipChanged
                    | GroupMessageType::ControlGroupMetadataUpdated
            );
            if is_membership_operation {
                if let Err(err) = self
                    .verify_membership_operation_authority(&record.envelope, &group_state.manifest)
                {
                    log::warn!(
                        "rejected membership operation from {} ({}) in group {}: {err}",
                        record.envelope.sender_user_id,
                        record.envelope.sender_device_id,
                        group_id
                    );
                    continue;
                }
            }
            let message_type = group_message_type_to_direct(record.envelope.message_type);
            if matches!(
                record.envelope.message_type,
                GroupMessageType::MlsApplication | GroupMessageType::MlsCommit
            ) {
                if group_state.local_role.is_none()
                    && record.envelope.message_type == GroupMessageType::MlsApplication
                {
                    self.mark_recovery_needed(&conversation_id, RecoveryReason::MembershipChanged);
                    continue;
                }
                let result = self
                    .state
                    .mls_adapter
                    .as_mut()
                    .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
                    .ingest_message(
                        &conversation_id,
                        &record.envelope.sender_device_id,
                        message_type,
                        record
                            .envelope
                            .inline_ciphertext
                            .as_deref()
                            .unwrap_or_default(),
                    )?;
                match result {
                    IngestResult::AppliedApplication(application) => self
                        .store_group_record_message(
                            &conversation_id,
                            &record,
                            message_type,
                            String::from_utf8(application.plaintext).ok(),
                        )?,
                    IngestResult::AppliedCommit { .. } => self.store_group_record_message(
                        &conversation_id,
                        &record,
                        message_type,
                        None,
                    )?,
                    IngestResult::PendingRetry => {
                        self.mark_recovery_needed(&conversation_id, RecoveryReason::MissingCommit);
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
                    self.state
                        .mls_summaries
                        .insert(conversation_id.clone(), summary);
                }
            } else {
                let is_manifest_control = matches!(
                    record.envelope.message_type,
                    GroupMessageType::ControlGroupMembershipChanged
                        | GroupMessageType::ControlGroupMetadataUpdated
                );
                if is_manifest_control
                    && !self.try_apply_control_manifest_update(
                        &conversation_id,
                        &group_id,
                        &record,
                        &group_state,
                    )
                {
                    continue;
                }
                self.store_group_record_message(&conversation_id, &record, message_type, None)?;
            }
            messages.push(MessageSummary {
                conversation_id: conversation_id.clone(),
                message_id: record.message_id,
                message_type,
            });
        }
        let now = current_unix_millis(self.state.message_nonce);
        self.state.group_cursors.insert(
            group_id.clone(),
            GroupCursor {
                group_id: group_id.clone(),
                last_fetched_seq: to_seq,
                updated_at: now,
            },
        );
        self.merge_with_transport_flush(CoreOutput {
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
                    PersistOp::SaveGroupCursor { group_id },
                ],
            )],
            view_model: Some(CoreViewModel {
                conversations: vec![self.conversation_summary(&conversation_id)?],
                messages,
                ..CoreViewModel::default()
            }),
        })
    }

    fn store_group_record_message(
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
            sender_device_id: record.envelope.sender_device_id.clone(),
            recipient_device_id: String::new(),
            message_type,
            created_at: record.envelope.created_at,
            plaintext,
            storage_refs: record.envelope.storage_refs.clone(),
            downloaded_blob_b64: None,
        });
        state.last_message_type = Some(message_type);
        state.conversation.updated_at = record.envelope.created_at;
        Ok(())
    }

    fn handle_group_envelope_appended(
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
        if let Some(item) = pending_item {
            let group_state = self
                .state
                .group_states
                .get(&group_id)
                .ok_or_else(|| CoreError::invalid_input("group does not exist"))?
                .clone();
            let already_stored = self
                .state
                .conversations
                .get(&group_state.conversation_id)
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
                    &group_state.conversation_id,
                    &record,
                    message_type,
                    item.plaintext_cache,
                )?;
                messages.push(MessageSummary {
                    conversation_id: group_state.conversation_id,
                    message_id: message_id.clone(),
                    message_type,
                });
            }
        }

        // Step (c) of `DissolveGroup`: emit the SealGroupOutbox effect only
        // after every pending commit/control for this group has been
        // acknowledged. This guarantees the seal is applied strictly after
        // the MLS remove_commit and `control_group_dissolved` are already
        // durable on the outbox, preserving the four-step atomic contract
        // (design.md Dissolve-group decision).
        let ready_to_seal = self
            .state
            .pending_group_seal
            .contains_key(&group_id)
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

        let mut effects = vec![persist_effect(
            &self.state,
            vec![PersistOp::DeleteOutgoingGroupEnvelope { message_id }],
        )];
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

    fn handle_group_append_failed(
        &mut self,
        group_id: String,
        message_id: String,
        retryable: bool,
        detail: Option<String>,
    ) -> CoreResult<CoreOutput> {
        if let Some(item) = self
            .state
            .pending_group_outbox
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
                            timer_id: format!("retry_group_append:{message_id}"),
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
    fn dissolve_group(&mut self, group_id: String) -> CoreResult<CoreOutput> {
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
            return Err(CoreError::invalid_input(
                "group is already dissolved",
            ));
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
        let mut manifest = group_state.manifest.clone();
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
            },
        );

        // Owner-level capability includes `SealGroup` (see
        // `group_capability_operations`). We reuse it for both the commit
        // and the control envelope — the append capability is a superset.
        let capability = self.group_capability(&group_id, role)?;
        let membership_proof =
            self.build_membership_proof(&group_id, manifest.roster_version, "dissolve")?;
        let mut persist_ops: Vec<PersistOp> = vec![
            PersistOp::SaveGroupState {
                group_id: group_id.clone(),
            },
            PersistOp::SaveMlsState {
                conversation_id: group_state.conversation_id.clone(),
            },
        ];
        let mut messages: Vec<MessageSummary> = Vec::new();
        if let Some(artifacts) = artifacts {
            let mut commit = self.build_group_envelope(
                &group_id,
                &group_state.conversation_id,
                GroupMessageType::MlsCommit,
                GroupEnvelopeVisibility::Protocol,
                artifacts.commit_b64,
            )?;
            commit.membership_proof = Some(membership_proof.clone());
            let commit_message_id = commit.message_id.clone();
            self.enqueue_group_envelope(commit, capability.clone(), None);
            persist_ops.push(PersistOp::SaveOutgoingGroupEnvelope {
                message_id: commit_message_id.clone(),
            });
            messages.push(MessageSummary {
                conversation_id: group_state.conversation_id.clone(),
                message_id: commit_message_id,
                message_type: MessageType::MlsCommit,
            });
        }

        // Step (b): visible `ControlGroupDissolved` control message. The
        // payload is the final (all-removed) manifest so every receiving
        // client can render a single "group dissolved" banner by reading
        // `message_type = control_group_dissolved` and showing a localized
        // string (the Desktop UI locks the text to
        // "This group has been dissolved by the owner." per R3.6).
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
        control.membership_proof = Some(membership_proof);
        let control_message_id = control.message_id.clone();
        self.enqueue_group_envelope(control, capability.clone(), None);
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

    /// Handle `CoreEvent::GroupOutboxSealed` — step (d) of `DissolveGroup`.
    ///
    /// When the Cloudflare outbox acknowledges the seal request, transition
    /// the local group state to dissolved (`dissolved_at` +
    /// `ConversationState::Dissolved`). This is the *only* place that may
    /// set `dissolved_at` — every other code path that inspects
    /// `dissolved_at` relies on it being set strictly after the server has
    /// acknowledged the seal.
    ///
    /// A `was_already_sealed = true` variant (HTTP 409) is treated as
    /// success: the terminal state is identical whether we observed the
    /// transition or the server had seen it before.
    fn handle_group_outbox_sealed(
        &mut self,
        group_id: String,
        sealed_at: u64,
        was_already_sealed: bool,
    ) -> CoreResult<CoreOutput> {
        let _ = was_already_sealed; // Observability signal only (see design.md).
        // Drop any lingering pending seal entry — whether or not the seal
        // effect was issued (it may have been a retry pending a
        // `GroupOutboxSealFailed` earlier), the terminal state is now
        // "sealed on the server", so no further seal effects are needed.
        self.state.pending_group_seal.remove(&group_id);

        let group_state = match self.state.group_states.get(&group_id) {
            Some(state) => state.clone(),
            None => {
                // The group could have been removed locally since the effect
                // was issued (e.g. profile reset). Nothing to transition.
                return Ok(CoreOutput {
                    state_update: CoreStateUpdate::default(),
                    effects: vec![],
                    view_model: None,
                });
            }
        };
        let conversation_id = group_state.conversation_id.clone();

        let mut persist_ops: Vec<PersistOp> = Vec::new();
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
    fn handle_group_outbox_seal_failed(
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
                effects: vec![CoreEffect::ScheduleTimer {
                    timer: TimerEffect {
                        timer_id: format!("retry_group_seal:{group_id}"),
                        delay_ms: 0,
                    },
                }],
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
            effects: vec![CoreEffect::EmitUserNotification {
                notification: UserNotificationEffect {
                    status: SystemStatus::TemporaryNetworkFailure,
                    message: detail.unwrap_or_else(|| {
                        format!("failed to seal dissolved group {group_id}")
                    }),
                },
            }],
            view_model: None,
        })
    }

    fn handle_welcome_pickup_fetched(
        &mut self,
        descriptor: WelcomePickupDescriptor,
        welcome_b64: String,
        manifest: Option<GroupManifest>,
    ) -> CoreResult<CoreOutput> {
        if !self.state.group_states.contains_key(&descriptor.group_id) {
            let manifest = manifest.ok_or_else(|| {
                CoreError::invalid_input("welcome pickup result is missing group manifest")
            })?;
            manifest.validate()?;
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
                },
            );
        }
        let group_state = self
            .state
            .group_states
            .get(&descriptor.group_id)
            .ok_or_else(|| CoreError::invalid_input("group state does not exist for welcome"))?
            .clone();
        let result = self
            .state
            .mls_adapter
            .as_mut()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .ingest_message(
                &group_state.conversation_id,
                &group_state.manifest.signer_device_id,
                MessageType::MlsWelcome,
                &welcome_b64,
            )?;
        if !matches!(result, IngestResult::AppliedWelcome { .. }) {
            return Err(CoreError::invalid_state("welcome pickup did not apply"));
        }
        let summary = self
            .state
            .mls_adapter
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .export_group_summary(&group_state.conversation_id)?;
        self.state
            .mls_summaries
            .insert(group_state.conversation_id.clone(), summary);
        // The welcome established a cryptographically valid group state at
        // the MLS epoch where the approver added this device. Any outbox
        // records that predate that epoch cannot be decrypted by us and
        // would otherwise trip MLS's `process_message` into returning
        // `PendingRetry`, which would incorrectly flip our recovery status
        // to `NeedsRecovery`. We proactively advance the group cursor to
        // the current server head so future syncs only consider records
        // emitted after we joined; the head lookup is issued as an effect
        // so the driver can perform the real HTTP call.
        let head_request = CoreEffect::GetGroupOutboxHead {
            get: GetGroupOutboxHeadRequest {
                group_id: group_state.group_id.clone(),
                capability: self.group_capability_for_state(&group_state)?,
            },
        };
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                conversations_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![
                persist_effect(
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
                ),
                head_request,
            ],
            view_model: Some(CoreViewModel {
                conversations: vec![self.conversation_summary(&group_state.conversation_id)?],
                ..CoreViewModel::default()
            }),
        })
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
        let output =
            self.handle_inbox_records_internal(device_id.clone(), records, to_seq, false)?;
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

fn current_timestamp_hint(outbox_len: usize) -> u64 {
    outbox_len as u64 + 1
}

fn current_unix_millis(fallback: u64) -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(fallback)
}

fn hex_prefix(bytes: &[u8], len: usize) -> String {
    bytes
        .iter()
        .flat_map(|byte| {
            let hi = byte >> 4;
            let lo = byte & 0x0f;
            [hex_nibble(hi), hex_nibble(lo)]
        })
        .take(len)
        .collect()
}

fn hex_nibble(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        _ => (b'a' + (value - 10)) as char,
    }
}

fn group_capability_for_manifest(manifest: &GroupManifest, role: GroupRole) -> GroupCapability {
    GroupCapability {
        version: crate::model::CURRENT_MODEL_VERSION.to_string(),
        service: CapabilityService::GroupOutbox,
        group_id: manifest.group_id.clone(),
        user_id: manifest.signer_user_id.clone(),
        device_id: manifest.signer_device_id.clone(),
        operations: group_capability_operations(role),
        role,
        expires_at: current_unix_millis(0) + 60 * 60 * 1000,
        signature: manifest.signature.clone(),
    }
}

fn group_capability_operations(role: GroupRole) -> Vec<GroupCapabilityOperation> {
    match role {
        GroupRole::Owner => vec![
            GroupCapabilityOperation::Read,
            GroupCapabilityOperation::Subscribe,
            GroupCapabilityOperation::AppendApplication,
            GroupCapabilityOperation::AppendControl,
            GroupCapabilityOperation::AppendMembership,
            GroupCapabilityOperation::ManageInvites,
            GroupCapabilityOperation::ApproveJoin,
            GroupCapabilityOperation::RemoveMember,
            GroupCapabilityOperation::UpdateGroupMetadata,
            // Only the owner may seal the outbox (PROTOCOL_GROUP_CN.md §10.4).
            GroupCapabilityOperation::SealGroup,
        ],
        GroupRole::Admin => vec![
            GroupCapabilityOperation::Read,
            GroupCapabilityOperation::Subscribe,
            GroupCapabilityOperation::AppendApplication,
            GroupCapabilityOperation::AppendControl,
            GroupCapabilityOperation::AppendMembership,
            GroupCapabilityOperation::ManageInvites,
            GroupCapabilityOperation::ApproveJoin,
            GroupCapabilityOperation::RemoveMember,
            GroupCapabilityOperation::UpdateGroupMetadata,
        ],
        GroupRole::Member => vec![
            GroupCapabilityOperation::Read,
            GroupCapabilityOperation::Subscribe,
            GroupCapabilityOperation::AppendApplication,
            GroupCapabilityOperation::AppendControl,
        ],
    }
}

#[cfg(test)]
pub(crate) fn test_group_capability_operations(role: GroupRole) -> Vec<GroupCapabilityOperation> {
    group_capability_operations(role)
}

fn group_message_type_to_direct(message_type: GroupMessageType) -> MessageType {
    match message_type {
        GroupMessageType::MlsApplication => MessageType::MlsApplication,
        GroupMessageType::MlsCommit => MessageType::MlsCommit,
        GroupMessageType::ControlConversationNeedsRebuild => {
            MessageType::ControlConversationNeedsRebuild
        }
        GroupMessageType::ControlGroupMembershipChanged
        | GroupMessageType::ControlGroupJoinRequested
        | GroupMessageType::ControlGroupJoinApproved
        | GroupMessageType::ControlGroupJoinRejected
        | GroupMessageType::ControlGroupLeaveRequested
        | GroupMessageType::ControlGroupDissolved => {
            // Dissolve is a terminal membership-change event; fold it into the
            // existing membership-changed bucket here so direct-chat message
            // type derivation stays a pure model projection. The
            // dissolve-specific behaviour (owner-only, seal outbox, etc.)
            // lives in the engine path added by later A.2-A.6 tasks.
            MessageType::ControlDeviceMembershipChanged
        }
        GroupMessageType::ControlGroupMetadataUpdated => MessageType::ControlIdentityStateUpdated,
    }
}

fn active_peer_key_packages(bundle: &IdentityBundle) -> CoreResult<Vec<PeerDeviceKeyPackage>> {
    Ok(bundle
        .devices
        .iter()
        .filter(|device| matches!(device.status, DeviceStatusKind::Active))
        .map(|device| PeerDeviceKeyPackage {
            user_id: bundle.user_id.clone(),
            device_id: device.device_id.clone(),
            device_public_key: device.device_public_key.clone(),
            key_package_b64: device.keypackage_ref.object_ref.clone(),
        })
        .collect())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
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
        message_nonce: state.message_nonce,
        local_identity: state
            .local_identity
            .clone()
            .map(|identity| PersistedLocalIdentity { state: identity }),
        deployment: state
            .deployment_bundle
            .clone()
            .map(|deployment_bundle| PersistedDeployment {
                deployment_bundle,
                local_bundle: state.local_bundle.clone(),
                published_key_package: state.published_key_package.clone(),
                serialized_mls_bootstrap_state: if state.mls_summaries.is_empty() {
                    state
                        .mls_adapter
                        .as_ref()
                        .and_then(|adapter| adapter.export_bootstrap_state().ok())
                } else {
                    None
                },
            }),
        contacts: state
            .contacts
            .iter()
            .map(|(_user_id, contact)| contact.clone())
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
                plaintext_cache: item.plaintext_cache.clone(),
            })
            .collect(),
        group_states: state.group_states.values().cloned().collect(),
        group_cursors: state
            .group_cursors
            .iter()
            .map(|(group_id, cursor)| PersistedGroupCursor {
                group_id: group_id.clone(),
                cursor: cursor.clone(),
            })
            .collect(),
        pending_group_outbox: state
            .pending_group_outbox
            .iter()
            .map(|item| PersistedOutgoingGroupEnvelope {
                message_id: item.envelope.message_id.clone(),
                group_id: item.envelope.group_id.clone(),
                envelope: item.envelope.clone(),
                capability: Some(item.capability.clone()),
                retries: item.retries,
                plaintext_cache: item.plaintext_cache.clone(),
            })
            .collect(),
        group_invites: state.group_invites.values().cloned().collect(),
        group_join_requests: state.group_join_requests.values().cloned().collect(),
        pending_group_join_approvals: state
            .pending_group_join_approvals
            .values()
            .cloned()
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
                group_id: task.group_id.clone(),
                message_id: task.message_id.clone(),
                attachment_id: task.descriptor.attachment_id.clone(),
                blob_ciphertext_b64: task.blob_ciphertext_b64.clone(),
                payload_metadata: task.payload_metadata.clone(),
                mime_type: task.descriptor.mime_type.clone(),
                size_bytes: task.descriptor.size_bytes,
                file_name: task.descriptor.file_name.clone(),
                metadata_ciphertext: task.metadata_ciphertext.clone(),
                prepared_upload: task.prepared_upload.clone(),
                retries: task.retries,
            })
            .chain(state.pending_blob_downloads.values().map(|task| {
                PersistedPendingBlobTransfer::Download {
                    task_id: task.task_id.clone(),
                    conversation_id: task.conversation_id.clone(),
                    message_id: task.message_id.clone(),
                    reference: task.reference.clone(),
                    destination_id: task.destination_id.clone(),
                    payload_metadata: task.payload_metadata.clone(),
                    retries: task.retries,
                }
            }))
            .collect(),
        recovery_contexts: state
            .recovery_contexts
            .iter()
            .map(|(conversation_id, context)| PersistedRecoveryContext {
                conversation_id: conversation_id.clone(),
                reason: match context.reason {
                    RecoveryReason::MissingCommit => PersistedRecoveryReason::MissingCommit,
                    RecoveryReason::MissingWelcome => PersistedRecoveryReason::MissingWelcome,
                    RecoveryReason::MembershipChanged => PersistedRecoveryReason::MembershipChanged,
                    RecoveryReason::IdentityChanged => PersistedRecoveryReason::IdentityChanged,
                },
                phase: match context.phase {
                    RecoveryPhase::WaitingForSync => PersistedRecoveryPhase::WaitingForSync,
                    RecoveryPhase::WaitingForPendingReplay => {
                        PersistedRecoveryPhase::WaitingForPendingReplay
                    }
                    RecoveryPhase::WaitingForIdentityRefresh => {
                        PersistedRecoveryPhase::WaitingForIdentityRefresh
                    }
                    RecoveryPhase::WaitingForExplicitReconcile => {
                        PersistedRecoveryPhase::WaitingForExplicitReconcile
                    }
                    RecoveryPhase::EscalatedToRebuild => PersistedRecoveryPhase::EscalatedToRebuild,
                },
                attempt_count: context.attempt_count,
                identity_refresh_retry_count: context.identity_refresh_retry_count,
                last_error: context.last_error.clone(),
                escalation_reason: context.escalation_reason.map(|reason| match reason {
                    RecoveryEscalationReason::MlsMarkedUnrecoverable => {
                        PersistedRecoveryEscalationReason::MlsMarkedUnrecoverable
                    }
                    RecoveryEscalationReason::IdentityRefreshRetryExhausted => {
                        PersistedRecoveryEscalationReason::IdentityRefreshRetryExhausted
                    }
                    RecoveryEscalationReason::ExplicitNeedsRebuildControl => {
                        PersistedRecoveryEscalationReason::ExplicitNeedsRebuildControl
                    }
                    RecoveryEscalationReason::RecoveryPolicyExhausted => {
                        PersistedRecoveryEscalationReason::RecoveryPolicyExhausted
                    }
                }),
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

fn attachment_download_task_id(message_id: &str, reference: &str, destination: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(reference.as_bytes());
    hasher.update([0]);
    hasher.update(destination.as_bytes());
    let digest = hasher.finalize();
    let hash: String = format!("{digest:x}").chars().take(12).collect();
    format!("blob-download:{message_id}:{hash}")
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
            base_view
                .message_requests
                .append(&mut next_view.message_requests);
            if next_view.allowlist.is_some() {
                base_view.allowlist = next_view.allowlist.take();
            }
            if next_view.message_request_action.is_some() {
                base_view.message_request_action = next_view.message_request_action.take();
            }
            if next_view.append_result.is_some() {
                base_view.append_result = next_view.append_result.take();
            }
        }
        (None, Some(next_view)) => base.view_model = Some(next_view),
        _ => {}
    }
    base
}

mod direct;
mod group_commands;
mod group_fsm;
mod group_sync;
mod recovery;
mod transport;

use std::collections::{BTreeMap, BTreeSet};

use super::attachments::{attachment_download_task_id, validate_attachment_descriptor};
use super::groups::{
    active_peer_key_packages, group_capability_operations, group_message_type_to_direct,
};
use super::recovery::{
    is_degraded_restore_diagnostic, recovery_recoverable, suggested_recovery_action,
};
use super::sync::{
    pending_welcome_pickup_key, retry_delay_ms, GROUP_OUTBOX_FETCH_LIMIT,
    WELCOME_PICKUP_RETRY_TIMER_PREFIX,
};
use crate::attachment_crypto::{
    decrypt_blob, decrypt_chunked_blob, encrypt_blob, encrypt_chunked_blob, AttachmentKind,
    AttachmentManifestV2, AttachmentPayloadMetadata, AttachmentVariant, EncryptedBlobDescriptor,
    CHUNKED_ATTACHMENT_CIPHER_ALGORITHM,
};
use crate::conversation::{
    direct_conversation_id, ConversationArchiveMetadata, ConversationManager,
    LocalConversationState, ReconcileMembershipInput, RecoveryStatus, StoredMessage,
};
use crate::direct_pcs::{
    commit_hash_from_b64, designated_committer, sign_certificate, DirectCommitCertificate,
    DirectPcsHandshake, DirectPcsRole,
};
use crate::error::{CoreError, CoreResult};
use crate::ffi_api::types::*;
use crate::identity::{parse_signature, parse_verifying_key, IdentityManager};
use crate::log_sanitize::redact_id;
use crate::mls_adapter::{
    CreateConversationArtifacts, DecryptedApplicationMessage, DirectCommitClass, IngestResult,
    MlsAdapter, PeerDeviceKeyPackage, RemoveMembersArtifacts,
};
use crate::model::{
    Ack, CapabilityService, Conversation, ConversationKind, ConversationMember, ConversationState,
    DeliveryClass, DeviceStatusKind, Envelope, GroupCapability, GroupCursor, GroupEnvelope,
    GroupEnvelopeVisibility, GroupInviteDocument, GroupJoinPolicy, GroupJoinRequest,
    GroupJoinRequestStatus, GroupLeaveRequest, GroupLeaveRequestStatus, GroupManifest, GroupMember,
    GroupMemberDevice, GroupMemberInvitePolicy, GroupMemberStatus, GroupMembershipProof,
    GroupMessageType, GroupOutboxDescriptor, GroupOutboxRecord, GroupOutboxRecordState, GroupRole,
    GroupStateEvent, GroupStateEventKind, GroupTransitionOperation, GroupTransitionRequestBinding,
    IdentityBundle, InboxRecord, MessageType, MlsStateStatus, MlsStateSummary, ProtectedAppMessage,
    ProtectedPayloadKind, SenderProof, StorageRef, Validate, WelcomePickupDescriptor,
};
use crate::persistence::{
    ContactRelationshipStatus, CorePersistenceSnapshot, GroupConsistencyState,
    GroupTransitionIntent, PendingGroupTransitionStage, PersistOp, PersistedContact,
    PersistedConversation, PersistedDeployment, PersistedGroupCursor, PersistedGroupInvite,
    PersistedGroupJoinRequest, PersistedGroupLeaveRequest, PersistedGroupRealtimeSession,
    PersistedGroupState, PersistedLocalIdentity, PersistedMlsState, PersistedOutgoingEnvelope,
    PersistedOutgoingGroupEnvelope, PersistedPendingAck, PersistedPendingBlobTransfer,
    PersistedPendingGroupMembershipTransition, PersistedPendingGroupTransition,
    PersistedPendingWelcomePickup, PersistedRealtimeSession, PersistedRecoveryContext,
    PersistedRecoveryEscalationReason, PersistedRecoveryPhase, PersistedRecoveryReason,
    PersistedSyncState,
};
use crate::sync_engine::{SyncDecision, SyncEngine};
use crate::transport_contract::{
    AckRequest, AckResult, AllowlistDocument, AppendDeliveryDisposition, AppendEnvelopeRequest,
    AppendEnvelopeResult, AppendGroupEnvelopeRequest, AppendGroupEnvelopeResult,
    AppendGroupTransitionRequest, BlobDownloadRequest, BlobUploadRequest, ClaimGroupJoinRequest,
    ClaimGroupLeaveRequest, CompleteGroupJoinRequest, CreateGroupInviteRequest,
    DecideGroupJoinRequest, DeviceStatusDocument, DeviceStatusRecord, FetchAllowlistRequest,
    FetchGroupInviteRequest, FetchGroupOutboxRequest, FetchGroupOutboxResult,
    FetchIdentityBundleRequest, FetchMessageRequestsRequest, FetchMessagesRequest,
    FetchMessagesResult, FetchWelcomePickupRequest, FetchWelcomePickupResult,
    GetGroupAuthorizationStateRequest, GetGroupJoinRequestStatusRequest, GetGroupOutboxHeadRequest,
    GetHeadResult, GroupAuthorizationUpdate, GroupJoinDecision,
    InitializeGroupAuthorizationRequest, ListGroupInvitesRequest, ListGroupJoinRequestsRequest,
    ListGroupLeaveRequestsRequest, MessageRequestAction, MessageRequestActionRequest,
    MessageRequestActionResult, MessageRequestItem, PrepareBlobUploadRequest,
    PrepareBlobUploadResult, PublishSharedStateRequest, PutWelcomePickupRequest,
    PutWelcomePickupResult, RealtimeSubscriptionRequest, ReplaceAllowlistRequest,
    RevokeGroupInviteRequest, SealGroupOutboxRequest, SharedStateDocumentKind,
    SubmitGroupJoinRequest, SubmitGroupLeaveRequest, TransportAuthRequirement,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::Verifier;
use log;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Default)]
pub struct CoreEngine {
    pub(crate) state: CoreState,
}

#[derive(Debug, Default)]
struct AppendDeliveryOutput {
    output: CoreOutput,
    saved_conversation_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InboxRecordSource {
    Fetch,
    PendingReplay,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RecoveryContextSnapshot {
    pub reason: RecoveryReason,
    pub phase: RecoveryPhase,
    pub attempt_count: u8,
    pub identity_refresh_retry_count: u8,
    pub last_error: Option<String>,
    pub escalation_reason: Option<RecoveryEscalationReason>,
    pub restore_failure_reason: Option<String>,
    pub restore_failure_detail: Option<String>,
    pub restore_recoverable: Option<bool>,
    pub suggested_action: Option<String>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupWelcomePickupControl {
    version: String,
    #[serde(alias = "group_id")]
    group_id: String,
    #[serde(alias = "conversation_id")]
    conversation_id: String,
    title: String,
    #[serde(alias = "inviter_user_id")]
    inviter_user_id: String,
    #[serde(alias = "welcome_pickup_descriptor")]
    welcome_pickup_descriptor: WelcomePickupDescriptor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ContactRemovedControl {
    version: String,
    #[serde(alias = "conversation_id")]
    conversation_id: String,
    #[serde(alias = "actor_user_id")]
    actor_user_id: String,
    #[serde(alias = "removed_user_id")]
    removed_user_id: String,
    #[serde(alias = "created_at")]
    created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ContactAcceptedControl {
    version: String,
    #[serde(alias = "conversation_id")]
    conversation_id: String,
    #[serde(alias = "actor_user_id")]
    actor_user_id: String,
    #[serde(alias = "accepted_user_id")]
    accepted_user_id: String,
    #[serde(alias = "request_id")]
    request_id: String,
    #[serde(alias = "created_at")]
    created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedMlsSenderIdentity {
    user_id: String,
    device_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ApplicationPlaintextDecision {
    Accepted {
        plaintext: String,
        app_message_id: Option<String>,
    },
    DuplicateAppMessage {
        app_message_id: String,
    },
    RejectedProtocol {
        reason: String,
    },
}

impl CoreEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn local_bundle(&self) -> Option<&IdentityBundle> {
        self.state.local_bundle.as_ref()
    }

    pub fn has_pending_share_rotation(&self) -> bool {
        self.state
            .pending_identity_publication
            .as_ref()
            .is_some_and(|pending| pending.reason == "share_link_rotation")
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

    pub fn local_identity_summary(&self) -> Option<LocalIdentitySummary> {
        let identity = self.state.local_identity.as_ref()?;
        Some(LocalIdentitySummary {
            user_id: identity.user_identity.user_id.clone(),
            device_id: identity.device_identity.device_id.clone(),
            display_name: self.local_display_name(),
        })
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
                restore_failure_reason: context.restore_failure_reason.clone(),
                restore_failure_detail: context.restore_failure_detail.clone(),
                restore_recoverable: context.restore_recoverable,
                suggested_action: context.suggested_action.clone(),
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

    pub fn try_from_restored_state(snapshot: CorePersistenceSnapshot) -> CoreResult<Self> {
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
        )?;
        if !restored_mls.failures.is_empty() {
            return Err(CoreError::restore_failed(
                "persisted MLS state failed integrity validation",
            ));
        }
        let mut contacts = BTreeMap::new();
        for contact in snapshot.contacts {
            contacts.insert(
                contact.user_id.clone(),
                PersistedContact {
                    user_id: contact.user_id,
                    bundle: contact.bundle,
                    display_name: contact.display_name,
                    original_name: contact.original_name,
                    relationship_status: contact.relationship_status,
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
                app_message_id: item.app_message_id,
                plaintext_cache: item.plaintext_cache,
                identity_refresh_attempted: item.identity_refresh_attempted,
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
                group_states.get(&item.group_id)?.local_role?;
                Some(PendingGroupOutboxItem {
                    envelope: item.envelope,
                    retries: item.retries,
                    in_flight: false,
                    plaintext_cache: item.plaintext_cache,
                })
            })
            .collect::<Vec<_>>();
        let pending_group_seal = snapshot
            .pending_group_seal
            .into_iter()
            .map(|seal| (seal.group_id.clone(), seal))
            .collect::<BTreeMap<_, _>>();
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
        let mut pending_blob_deletions = BTreeMap::new();
        for transfer in snapshot.pending_blob_transfers {
            match transfer {
                PersistedPendingBlobTransfer::Upload {
                    task_id,
                    conversation_id,
                    group_id,
                    message_id,
                    created_at,
                    descriptor,
                    source,
                    variant,
                    encrypted_descriptor,
                    prepared_upload,
                    uploaded,
                    retries,
                } => {
                    pending_blob_uploads.insert(
                        task_id.clone(),
                        PendingBlobUpload {
                            task_id,
                            conversation_id,
                            group_id,
                            descriptor,
                            source,
                            variant,
                            blob_ciphertext: None,
                            encrypted_descriptor: uploaded
                                .then_some(encrypted_descriptor)
                                .flatten(),
                            message_id,
                            created_at,
                            prepared_upload: uploaded.then_some(prepared_upload).flatten(),
                            uploaded,
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
                    blob_descriptor,
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
                            blob_descriptor,
                            retries,
                            in_flight: false,
                        },
                    );
                }
                PersistedPendingBlobTransfer::Delete {
                    task_id,
                    blob_ref,
                    delete_target,
                    delete_capability,
                    retries,
                } => {
                    pending_blob_deletions.insert(
                        task_id.clone(),
                        PendingBlobDeletion {
                            task_id,
                            blob_ref,
                            delete_target,
                            delete_capability,
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
                        reconnect_failures: 0,
                    },
                )
            })
            .collect();

        let group_realtime_sessions = snapshot
            .group_realtime_sessions
            .into_iter()
            .map(|session| {
                (
                    session.group_id.clone(),
                    GroupRealtimeSessionState {
                        connected: false,
                        last_known_seq: session.last_known_seq,
                        needs_reconnect: session.needs_reconnect,
                        reconnect_failures: 0,
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
                        restore_failure_reason: context.restore_failure_reason,
                        restore_failure_detail: context.restore_failure_detail,
                        restore_recoverable: context.restore_recoverable,
                        suggested_action: context.suggested_action,
                    },
                )
            })
            .collect();

        let local_identity = snapshot.local_identity.map(|identity| identity.state);
        let persisted_deployment = snapshot.deployment.clone();
        let local_display_name = snapshot.local_display_name.clone().or_else(|| {
            persisted_deployment
                .as_ref()
                .and_then(|deployment| deployment.local_bundle.as_ref())
                .and_then(|bundle| bundle.display_name.clone())
        });
        let pending_welcome_pickups = snapshot
            .pending_welcome_pickups
            .iter()
            .cloned()
            .map(|pickup| {
                (
                    pending_welcome_pickup_key(&pickup.group_id, &pickup.device_id),
                    pickup,
                )
            })
            .collect();
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
                pending_welcome_pickups,
                pending_group_seal,
                pending_acks,
                pending_blob_uploads,
                pending_blob_downloads,
                pending_blob_deletions,
                realtime_sessions,
                group_realtime_sessions,
                mls_adapter: restored_mls.adapter,
                mls_summaries,
                published_key_package: persisted_deployment
                    .as_ref()
                    .and_then(|deployment| deployment.published_key_package.clone()),
                key_package_inventory: persisted_deployment
                    .as_ref()
                    .map(|deployment| {
                        if deployment.key_package_inventory.is_empty() {
                            deployment
                                .published_key_package
                                .iter()
                                .cloned()
                                .collect::<Vec<_>>()
                        } else {
                            deployment.key_package_inventory.clone()
                        }
                    })
                    .unwrap_or_default(),
                pending_identity_publication: persisted_deployment
                    .as_ref()
                    .and_then(|deployment| deployment.pending_identity_publication.clone()),
                pending_requests: BTreeMap::new(),
                request_nonce: 0,
                message_nonce: snapshot.message_nonce,
                recovery_contexts,
                pending_allowlist_mutation: None,
                local_display_name,
                pending_sync_group_head: BTreeSet::new(),
                group_sync_target_head: BTreeMap::new(),
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

        for failure in restored_mls.failures {
            let conversation_id = failure.conversation_id.clone();
            if let Some(conversation) = engine.state.conversations.get_mut(&conversation_id) {
                if matches!(
                    conversation.conversation.state,
                    ConversationState::Closed | ConversationState::Archived
                ) {
                    engine.state.mls_summaries.remove(&conversation_id);
                    continue;
                }
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
                    last_error: Some(match failure.detail.as_ref() {
                        Some(detail) => {
                            format!("failed to restore MLS group state: {detail}")
                        }
                        None => "failed to restore MLS group state".into(),
                    }),
                    escalation_reason: Some(RecoveryEscalationReason::MlsMarkedUnrecoverable),
                    restore_failure_reason: Some(failure.reason),
                    restore_failure_detail: failure.detail,
                    restore_recoverable: Some(failure.recoverable),
                    suggested_action: Some(failure.suggested_action),
                },
            );
        }

        Ok(engine)
    }

    pub fn handle_command(&mut self, command: CoreCommand) -> CoreResult<CoreOutput> {
        let staged_join_request_id = match &command {
            CoreCommand::ApproveGroupJoin { request_id, .. }
            | CoreCommand::ApproveGroupLeave { request_id, .. } => Some(request_id.clone()),
            _ => None,
        };
        let stage_group_transition = matches!(
            &command,
            CoreCommand::ApproveGroupJoin { .. }
                | CoreCommand::InviteToGroup { .. }
                | CoreCommand::ApproveGroupLeave { .. }
                | CoreCommand::RemoveGroupMember { .. }
                | CoreCommand::TransferGroupOwnership { .. }
                | CoreCommand::SetGroupAdmin { .. }
                | CoreCommand::UpdateGroupMetadata { .. }
                | CoreCommand::DissolveGroup { .. }
                | CoreCommand::AddGroupMemberDevice { .. }
                | CoreCommand::RemoveGroupMemberDevice { .. }
                | CoreCommand::SyncGroupsForNewDevice { .. }
                | CoreCommand::SyncGroupsForRemovedDevice { .. }
        );
        let requires_membership_fsm_v2 = stage_group_transition
            || matches!(
                &command,
                CoreCommand::CreateGroupConversation { .. }
                    | CoreCommand::CreateGroupInviteLink { .. }
                    | CoreCommand::RevokeGroupInviteLink { .. }
                    | CoreCommand::LeaveGroup { .. }
                    | CoreCommand::RejectGroupJoin { .. }
            );
        if requires_membership_fsm_v2 {
            self.require_group_membership_fsm_v2()?;
        }
        let transition_group_id = match &command {
            CoreCommand::ApproveGroupJoin { group_id, .. }
            | CoreCommand::InviteToGroup { group_id, .. }
            | CoreCommand::LeaveGroup { group_id }
            | CoreCommand::ApproveGroupLeave { group_id, .. }
            | CoreCommand::RemoveGroupMember { group_id, .. }
            | CoreCommand::TransferGroupOwnership { group_id, .. }
            | CoreCommand::SetGroupAdmin { group_id, .. }
            | CoreCommand::UpdateGroupMetadata { group_id, .. }
            | CoreCommand::DissolveGroup { group_id }
            | CoreCommand::AddGroupMemberDevice { group_id, .. }
            | CoreCommand::RemoveGroupMemberDevice { group_id, .. } => Some(group_id.as_str()),
            _ => None,
        };
        if let Some(group_id) = transition_group_id {
            self.ensure_group_state_operation_ready(group_id)?;
        }
        let staging_context = if stage_group_transition {
            let canonical_mls = self.state.mls_adapter.take();
            let staged_mls = canonical_mls.as_ref().map(MlsAdapter::fork).transpose()?;
            self.state.mls_adapter = staged_mls;
            Some((
                canonical_mls,
                self.state.group_states.clone(),
                self.state.conversations.clone(),
                self.state.mls_summaries.clone(),
                self.state.pending_group_outbox.len(),
            ))
        } else {
            None
        };

        let result = match command {
            CoreCommand::CreateOrLoadIdentity {
                mnemonic,
                device_name,
                display_name,
            } => self.create_or_load_identity(mnemonic, device_name, display_name),
            CoreCommand::ImportDeploymentBundle { bundle } => self.import_deployment_bundle(bundle),
            CoreCommand::ImportIdentityBundle { bundle } => self.import_identity_bundle(bundle),
            CoreCommand::ImportIdentityBundleWithRelationshipStatus {
                bundle,
                relationship_status,
            } => self.import_identity_bundle_with_relationship_status(bundle, relationship_status),
            CoreCommand::ApplyIdentityBundleUpdate { bundle } => {
                self.apply_identity_bundle_update(bundle)
            }
            CoreCommand::CreateConversation {
                peer_user_id,
                conversation_kind,
            } => {
                let now_ms = current_unix_millis(self.state.message_nonce);
                let maintenance = if self.local_credential_maintenance_due(now_ms) {
                    self.maintain_local_credentials(now_ms)?
                } else {
                    CoreOutput::default()
                };
                let created = self.create_conversation(peer_user_id, conversation_kind)?;
                Ok(merge_outputs(maintenance, created))
            }
            CoreCommand::CreateGroupConversation {
                title,
                member_user_ids,
            } => {
                let now_ms = current_unix_millis(self.state.message_nonce);
                let maintenance = if self.local_credential_maintenance_due(now_ms) {
                    self.maintain_local_credentials(now_ms)?
                } else {
                    CoreOutput::default()
                };
                let created = self.create_group_conversation(title, member_user_ids)?;
                Ok(merge_outputs(maintenance, created))
            }
            CoreCommand::SyncGroupOutbox { group_id, reason } => {
                self.sync_group_outbox(group_id, reason)
            }
            CoreCommand::ApplyGroupRealtimePlan {
                websocket_group_ids,
            } => self.apply_group_realtime_plan(websocket_group_ids),
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
            CoreCommand::ListGroupInvites { group_id } => self.list_group_invites(group_id),
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
            CoreCommand::RetryPendingWelcomePickups => self.retry_pending_welcome_pickups(),
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
            CoreCommand::ListGroupLeaveRequests { group_id } => {
                self.list_group_leave_requests(group_id)
            }
            CoreCommand::ApproveGroupLeave {
                group_id,
                request_id,
            } => self.approve_group_leave(group_id, request_id),
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
            CoreCommand::SyncInbox { device_id, reason } => self.sync_inbox(device_id, reason),
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
                display_name,
            } => self.create_additional_device_identity(mnemonic, device_name, display_name),
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
            CoreCommand::AddGroupMemberDevice {
                group_id,
                user_id,
                device_id,
            } => self.add_group_member_device(group_id, user_id, device_id),
            CoreCommand::RemoveGroupMemberDevice {
                group_id,
                user_id,
                device_id,
            } => self.remove_group_member_device(group_id, user_id, device_id),
            CoreCommand::SyncGroupsForNewDevice { device_id } => {
                self.sync_groups_for_new_device(device_id)
            }
            CoreCommand::SyncGroupsForRemovedDevice { device_id } => {
                self.sync_groups_for_removed_device(device_id)
            }
        };

        let Some((
            canonical_mls,
            canonical_groups,
            canonical_conversations,
            canonical_summaries,
            pending_start,
        )) = staging_context
        else {
            return result;
        };
        let mut output = match result {
            Ok(output) => output,
            Err(error) => {
                self.state.mls_adapter = canonical_mls;
                self.state.group_states = canonical_groups;
                self.state.conversations = canonical_conversations;
                self.state.mls_summaries = canonical_summaries;
                self.state.pending_group_outbox.truncate(pending_start);
                return Err(error);
            }
        };
        let staged_items: Vec<_> = self.state.pending_group_outbox[pending_start..].to_vec();
        let Some(mut proof) = staged_items
            .iter()
            .find_map(|item| item.envelope.membership_proof.clone())
        else {
            self.state.mls_adapter = canonical_mls;
            self.state.group_states = canonical_groups;
            self.state.conversations = canonical_conversations;
            self.state.mls_summaries = canonical_summaries;
            self.state.pending_group_outbox.truncate(pending_start);
            return Ok(output);
        };
        let group_id = staged_items
            .iter()
            .find(|item| item.envelope.membership_proof.as_ref() == Some(&proof))
            .map(|item| item.envelope.group_id.clone())
            .ok_or_else(|| CoreError::invalid_state("staged group transition has no group"))?;
        let proposed = self
            .state
            .group_states
            .get(&group_id)
            .ok_or_else(|| CoreError::invalid_state("staged group transition lost proposed state"))?
            .clone();
        let base_manifest = canonical_groups
            .get(&group_id)
            .ok_or_else(|| CoreError::invalid_state("canonical group state is missing"))?
            .manifest
            .clone();
        let transition_id = format!("group-transition:{}", proof.control_message_id);
        let mut event_envelope = self.build_group_envelope(
            &group_id,
            &proposed.conversation_id,
            GroupMessageType::ControlGroupStateEvent,
            GroupEnvelopeVisibility::Visible,
            "pending-state-event".into(),
        )?;
        event_envelope.transition_id = Some(transition_id.clone());
        let event_record = GroupOutboxRecord {
            seq: 0,
            group_id: group_id.clone(),
            message_id: event_envelope.message_id.clone(),
            received_at: event_envelope.created_at,
            expires_at: None,
            state: GroupOutboxRecordState::Available,
            envelope: event_envelope.clone(),
        };
        let event_plaintext = Self::derive_group_state_event(
            &base_manifest,
            &proposed.manifest,
            &proof,
            &event_record,
        )
        .ok_or_else(|| CoreError::invalid_state("failed to derive group state event"))?;
        let encrypted_event = self
            .state
            .mls_adapter
            .as_mut()
            .ok_or_else(|| CoreError::invalid_state("staged MLS adapter is missing"))?
            .encrypt_application(&proposed.conversation_id, event_plaintext.as_bytes())?;
        event_envelope.inline_ciphertext = Some(encrypted_event.payload_b64.clone());
        let identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?;
        event_envelope.sender_proof.value =
            identity.sign_sender_proof(encrypted_event.payload_b64.as_bytes());
        proof.state_event_message_id = Some(event_envelope.message_id.clone());
        proof.signature = identity.sign_sender_proof(&Self::membership_proof_payload(&proof));
        proof.validate()?;
        for item in &mut self.state.pending_group_outbox[pending_start..] {
            if item.envelope.membership_proof.is_some() {
                item.envelope.membership_proof = Some(proof.clone());
                item.envelope.transition_id = Some(transition_id.clone());
            }
        }
        event_envelope.membership_proof = Some(proof.clone());
        let capability = self.group_capability_for_state(&proposed)?;
        self.enqueue_group_envelope(event_envelope, capability, Some(event_plaintext));
        let new_items: Vec<_> = self.state.pending_group_outbox[pending_start..].to_vec();
        let welcomes: Vec<PutWelcomePickupRequest> = output
            .effects
            .iter()
            .filter_map(|effect| match effect {
                CoreEffect::PutWelcomePickup { put } => Some(put.clone()),
                _ => None,
            })
            .collect();
        let join_request_id = staged_join_request_id.or_else(|| {
            output.effects.iter().find_map(|effect| match effect {
                CoreEffect::DecideGroupJoinRequest { decide }
                    if decide.decision == GroupJoinDecision::Approve =>
                {
                    Some(decide.request_id.clone())
                }
                _ => None,
            })
        });
        let intent = self.transition_intent_from_staged_state(
            &base_manifest,
            &proposed.manifest,
            &proof,
            join_request_id.as_deref(),
        )?;
        let mls_patch = canonical_mls
            .as_ref()
            .zip(self.state.mls_adapter.as_ref())
            .map(|(canonical, staged)| {
                canonical.conversation_patch(staged, &proposed.conversation_id)
            })
            .transpose()?
            .ok_or_else(|| CoreError::invalid_state("staged MLS adapter is missing"))?;
        self.state.mls_adapter = canonical_mls;
        self.state.group_states = canonical_groups;
        self.state.conversations = canonical_conversations;
        self.state.mls_summaries = canonical_summaries;
        let base = self
            .state
            .group_states
            .get(&group_id)
            .ok_or_else(|| CoreError::invalid_state("canonical group state is missing"))?
            .clone();
        if let Some(state) = self.state.group_states.get_mut(&group_id) {
            state.pending_group_transition = Some(PersistedPendingGroupTransition {
                transition_id: transition_id.clone(),
                intent,
                stage: PendingGroupTransitionStage::Prepared,
                base_manifest_hash: Self::manifest_sha256(&base.manifest)?,
                base_roster_version: proof.previous_roster_version,
                base_commit_message_id: proof.previous_commit_message_id.clone(),
                proposed_manifest: proposed.manifest,
                mls_patch: Some(mls_patch),
                staged_mls_state: None,
                envelopes: new_items
                    .iter()
                    .filter(|item| item.envelope.membership_proof.as_ref() == Some(&proof))
                    .map(|item| item.envelope.clone())
                    .collect(),
                state_event_plaintext: new_items
                    .iter()
                    .find(|item| {
                        item.envelope.message_type == GroupMessageType::ControlGroupStateEvent
                    })
                    .and_then(|item| item.plaintext_cache.clone()),
                welcomes,
                join_request_id,
                retries: 0,
                first_seq: None,
                last_seq: None,
            });
        }
        output.effects.retain(|effect| {
            !matches!(
                effect,
                CoreEffect::PutWelcomePickup { .. }
                    | CoreEffect::AppendGroupEnvelope { .. }
                    | CoreEffect::AppendGroupTransition { .. }
                    | CoreEffect::DecideGroupJoinRequest { .. }
            )
        });
        output.view_model = None;
        let snapshot = build_persistence_snapshot(&self.state);
        for effect in &mut output.effects {
            if let CoreEffect::PersistState { persist } = effect {
                persist.mutations = persistence_mutations(&snapshot, &persist.ops);
                persist.snapshot = None;
            }
        }
        output = merge_outputs(output, self.flush_group_outbox()?);
        Ok(output)
    }

    pub fn handle_event(&mut self, event: CoreEvent) -> CoreResult<CoreOutput> {
        match event {
            CoreEvent::AppStarted => self.start_foreground_sync("startup"),
            CoreEvent::AppForegrounded => self.start_foreground_sync("foreground"),
            CoreEvent::CredentialMaintenanceRequested { now_ms } => {
                self.maintain_local_credentials(now_ms)
            }
            CoreEvent::WebSocketConnected { device_id } => {
                self.handle_websocket_connected(device_id)
            }
            CoreEvent::WebSocketDisconnected { device_id, .. } => {
                self.handle_websocket_disconnected(device_id)
            }
            CoreEvent::RealtimeEventReceived { device_id, event } => {
                self.handle_realtime_event(device_id, event)
            }
            CoreEvent::GroupWebSocketConnected { group_id } => {
                self.handle_group_websocket_connected(group_id)
            }
            CoreEvent::GroupWebSocketDisconnected { group_id, error } => {
                self.handle_group_websocket_disconnected(group_id, error)
            }
            CoreEvent::GroupRealtimeEventReceived { group_id, event } => {
                self.handle_group_realtime_event(group_id, event)
            }
            CoreEvent::WakeupReceived { device_id, .. } => {
                self.sync_inbox(device_id, Some("wakeup".into()))
            }
            CoreEvent::InboxRecordsFetched {
                device_id,
                records,
                to_seq,
            } => self.handle_inbox_records(device_id, records, to_seq),
            CoreEvent::InboxHistoryFloorAdvanced {
                device_id,
                history_floor_seq,
            } => self.handle_inbox_history_floor(device_id, history_floor_seq),
            CoreEvent::HttpResponseReceived {
                request_id,
                status,
                body,
            } => self.handle_http_response(request_id, status, body),
            CoreEvent::HttpRequestFailed {
                request_id,
                failure,
            } => self.handle_http_failure(request_id, failure),
            CoreEvent::IdentityBundleFetched { user_id: _, bundle } => {
                self.apply_identity_bundle_update(bundle)
            }
            CoreEvent::IdentityBundleFetchFailed {
                user_id,
                failure: _,
            } => self.handle_identity_refresh_failure(&user_id, "Identity refresh failed.".into()),
            CoreEvent::MessageRequestsFetched { requests } => {
                Ok(self.message_requests_output(requests))
            }
            CoreEvent::MessageRequestsFetchFailed { failure: _ } => Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect {
                        status: SystemStatus::TemporaryNetworkFailure,
                        message: "TapChat couldn't refresh message requests. Try again.".into(),
                    },
                }],
                view_model: None,
            }),
            CoreEvent::MessageRequestActionCompleted { result } => {
                self.message_request_action_output(result)
            }
            CoreEvent::MessageRequestActionFailed {
                request_id,
                action,
                failure: _,
            } => Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect {
                        status: SystemStatus::TemporaryNetworkFailure,
                        message: format!("TapChat couldn't complete the {action:?} action for message request {request_id}."),
                    },
                }],
                view_model: None,
            }),
            CoreEvent::AllowlistFetched { document } => self.handle_allowlist_fetched(document),
            CoreEvent::AllowlistFetchFailed { failure: _ } => Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect {
                        status: SystemStatus::TemporaryNetworkFailure,
                        message: "TapChat couldn't refresh the allowlist. Try again.".into(),
                    },
                }],
                view_model: None,
            }),
            CoreEvent::AllowlistReplaced { document } => Ok(self.allowlist_output(document, true)),
            CoreEvent::AllowlistReplaceFailed { failure: _ } => Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect {
                        status: SystemStatus::TemporaryNetworkFailure,
                        message: "TapChat couldn't update the allowlist. Try again.".into(),
                    },
                }],
                view_model: None,
            }),
            CoreEvent::SharedStatePublished {
                operation_id,
                document_kind: _,
                reference: _,
                etag,
                saved_bundle,
            } => {
                let publication_revision = saved_bundle
                    .as_ref()
                    .map(|bundle| bundle.publication_revision);
                let Some(operation_id) = operation_id else {
                    return Ok(CoreOutput::default());
                };
                let mut effects = Vec::new();
                if let Some(pending) = self.state.pending_identity_publication.clone() {
                    if pending.operation_id == operation_id {
                        let confirmed = saved_bundle.as_ref().is_some_and(|saved| {
                            saved.publication_revision
                                == pending.candidate_bundle.publication_revision
                                && saved.bundle_share_id == pending.candidate_bundle.bundle_share_id
                                && saved.signature == pending.candidate_bundle.signature
                        });
                        if !confirmed {
                            if let Some(current) = self.state.pending_identity_publication.as_mut()
                            {
                                current.stage = crate::persistence::PendingIdentityPublicationStage::AwaitingVerification;
                                current.expected_etag = etag.clone();
                            }
                            effects
                                .push(persist_effect(&self.state, vec![PersistOp::SaveDeployment]));
                            return Ok(CoreOutput {
                                effects,
                                view_model: Some(CoreViewModel {
                                    operation_results: vec![CoreOperationResult {
                                        operation_id,
                                        status: CoreOperationStatus::Failed,
                                        etag,
                                        publication_revision,
                                        failure: Some(
                                            CoreError::new(
                                                "contact_share_rotation_unverified",
                                                "server response did not confirm the candidate identity bundle",
                                            )
                                            .to_app_error(),
                                        ),
                                    }],
                                    ..CoreViewModel::default()
                                }),
                                ..CoreOutput::default()
                            });
                        }
                        self.state.local_bundle = Some(pending.candidate_bundle);
                        self.state.pending_identity_publication = None;
                        effects.push(persist_effect(&self.state, vec![PersistOp::SaveDeployment]));
                    }
                }
                Ok(CoreOutput {
                    effects,
                    view_model: Some(CoreViewModel {
                        operation_results: vec![CoreOperationResult {
                            operation_id,
                            status: CoreOperationStatus::Confirmed,
                            etag,
                            publication_revision,
                            failure: None,
                        }],
                        ..CoreViewModel::default()
                    }),
                    ..CoreOutput::default()
                })
            }
            CoreEvent::SharedStatePublishFailed {
                operation_id,
                document_kind: _,
                reference: _,
                failure,
                current_bundle,
                etag,
            } => {
                if failure.code == "identity_bundle_conflict" {
                    if let (Some(operation_id), Some(remote), Some(etag), Some(pending)) = (
                        operation_id.as_ref(),
                        current_bundle.as_ref(),
                        etag.as_ref(),
                        self.state.pending_identity_publication.clone(),
                    ) {
                        if pending.operation_id == *operation_id {
                            if remote.publication_revision
                                == pending.candidate_bundle.publication_revision
                                && remote.bundle_share_id
                                    == pending.candidate_bundle.bundle_share_id
                                && remote.signature == pending.candidate_bundle.signature
                            {
                                self.state.local_bundle = Some(remote.clone());
                                self.state.pending_identity_publication = None;
                                return Ok(CoreOutput {
                                    effects: vec![persist_effect(
                                        &self.state,
                                        vec![PersistOp::SaveDeployment],
                                    )],
                                    view_model: Some(CoreViewModel {
                                        operation_results: vec![CoreOperationResult {
                                            operation_id: operation_id.clone(),
                                            status: CoreOperationStatus::Confirmed,
                                            etag: Some(etag.clone()),
                                            publication_revision: Some(remote.publication_revision),
                                            failure: None,
                                        }],
                                        ..CoreViewModel::default()
                                    }),
                                    ..CoreOutput::default()
                                });
                            }
                            if pending.attempt_count < 3 {
                                let rebased = (|| -> CoreResult<IdentityBundle> {
                                    IdentityManager::verify_identity_bundle(remote)?;
                                    let local_identity =
                                        self.state.local_identity.as_ref().ok_or_else(|| {
                                            CoreError::invalid_state(
                                                "local identity is unavailable",
                                            )
                                        })?;
                                    let deployment =
                                        self.state.deployment_bundle.as_ref().ok_or_else(|| {
                                            CoreError::invalid_state("deployment is unavailable")
                                        })?;
                                    let local_device_id = &local_identity.device_identity.device_id;
                                    let local_profile = pending
                                        .candidate_bundle
                                        .devices
                                        .iter()
                                        .find(|device| &device.device_id == local_device_id)
                                        .cloned()
                                        .ok_or_else(|| {
                                            CoreError::invalid_state(
                                                "candidate local device is unavailable",
                                            )
                                        })?;
                                    let now_ms = current_unix_millis(self.state.message_nonce);
                                    let mut devices = remote
                                        .devices
                                        .iter()
                                        .filter(|device| &device.device_id != local_device_id)
                                        .cloned()
                                        .collect::<Vec<_>>();
                                    for device in &mut devices {
                                        if device.keypackage_ref.as_ref().is_some_and(
                                            |keypackage| !keypackage.is_usable_at(now_ms),
                                        ) {
                                            device.keypackage_ref = None;
                                        }
                                        if device.inbox_append_capability.as_ref().is_some_and(
                                            |capability| capability.expires_at <= now_ms,
                                        ) {
                                            device.inbox_append_capability = None;
                                        }
                                    }
                                    devices.push(local_profile);
                                    devices.sort_by(|left, right| {
                                        left.device_id.cmp(&right.device_id)
                                    });
                                    let mut signing_identity = local_identity.clone();
                                    signing_identity.device_status.updated_at = remote
                                        .publication_revision
                                        .max(pending.candidate_bundle.publication_revision)
                                        .saturating_add(1);
                                    IdentityManager::export_identity_bundle_with_devices(
                                        &signing_identity,
                                        deployment,
                                        devices,
                                        pending.candidate_bundle.bundle_share_id.clone(),
                                        self.state.local_display_name.clone(),
                                    )
                                })();
                                if let Ok(candidate_bundle) = rebased {
                                    let mut rebased_pending = pending;
                                    rebased_pending.candidate_bundle = candidate_bundle.clone();
                                    rebased_pending.expected_etag = Some(etag.clone());
                                    rebased_pending.attempt_count =
                                        rebased_pending.attempt_count.saturating_add(1);
                                    rebased_pending.stage = crate::persistence::PendingIdentityPublicationStage::AwaitingPublish;
                                    self.state.pending_identity_publication = Some(rebased_pending);
                                    return Ok(CoreOutput {
                                        effects: vec![
                                            persist_effect(
                                                &self.state,
                                                vec![PersistOp::SaveDeployment],
                                            ),
                                            self.identity_bundle_publish_effect(
                                                &candidate_bundle,
                                                operation_id.clone(),
                                                Some(etag),
                                            )?,
                                        ],
                                        ..CoreOutput::default()
                                    });
                                }
                            }
                        }
                    }
                }
                let is_share_rotation = operation_id
                    .as_deref()
                    .is_some_and(|id| id.starts_with("contact_share_rotation:"));
                let message = if is_share_rotation && failure.code == "contact_share_offline" {
                    "Connect to your TapChat service before rotating the share link."
                } else if is_share_rotation {
                    "TapChat couldn't verify whether the link was rotated. Reconnect to check which link is active."
                } else {
                    "TapChat couldn't publish your secure contact information. It will retry when connected."
                };
                let mut operation_results = Vec::new();
                let mut effects = Vec::new();
                if let Some(operation_id) = operation_id {
                    if let Some(pending) = self.state.pending_identity_publication.as_mut() {
                        if pending.operation_id == operation_id {
                            pending.attempt_count = pending.attempt_count.saturating_add(1);
                            pending.stage = crate::persistence::PendingIdentityPublicationStage::AwaitingPublish;
                            let retry_delay =
                                30_000_u64.saturating_mul(1_u64 << pending.attempt_count.min(7));
                            pending.next_retry_at = current_unix_millis(self.state.message_nonce)
                                .saturating_add(retry_delay.min(24 * 60 * 60 * 1000));
                            effects
                                .push(persist_effect(&self.state, vec![PersistOp::SaveDeployment]));
                            effects.push(CoreEffect::ScheduleTimer {
                                timer: TimerEffect {
                                    timer_id: "credential_maintenance".into(),
                                    delay_ms: retry_delay.min(24 * 60 * 60 * 1000),
                                },
                            });
                        }
                    }
                    operation_results.push(CoreOperationResult {
                        operation_id,
                        status: CoreOperationStatus::Failed,
                        etag: None,
                        publication_revision: None,
                        failure: Some(failure),
                    });
                }
                Ok(CoreOutput {
                    state_update: CoreStateUpdate {
                        system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                        ..CoreStateUpdate::default()
                    },
                    effects: {
                        effects.push(CoreEffect::EmitUserNotification {
                            notification: UserNotificationEffect {
                                status: SystemStatus::TemporaryNetworkFailure,
                                message: message.into(),
                            },
                        });
                        effects
                    },
                    view_model: Some(CoreViewModel {
                        operation_results,
                        ..CoreViewModel::default()
                    }),
                })
            }
            CoreEvent::AttachmentBytesLoaded { task_id, plaintext } => {
                self.handle_attachment_bytes_loaded(task_id, plaintext)
            }
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
                failure,
            } => self.handle_blob_transfer_failed(task_id, failure.retryable, None),
            CoreEvent::BlobDeleted { task_id } => self.handle_blob_deleted(task_id),
            CoreEvent::BlobDeleteFailed { task_id, failure } => {
                self.handle_blob_delete_failed(task_id, failure.retryable)
            }
            CoreEvent::TimerTriggered { timer_id } => self.handle_timer(timer_id),
            CoreEvent::UserConfirmedRebuild { conversation_id } => {
                self.rebuild_conversation(conversation_id)
            }
            CoreEvent::GroupOutboxFetched {
                group_id,
                records,
                to_seq,
            } => self.handle_group_outbox_records(group_id, records, to_seq),
            CoreEvent::GroupHistoryFloorAdvanced {
                group_id,
                history_floor_seq,
            } => self.handle_group_history_floor(&group_id, history_floor_seq),
            CoreEvent::GroupOutboxFetchFailed {
                group_id,
                failure,
            } => self.handle_group_sync_failed(
                group_id,
                failure.retryable,
                failure.http_status,
                Some(failure.code),
                None,
            ),
            CoreEvent::GroupOutboxHeadFetched {
                group_id,
                head_seq,
                current_roster_version,
                last_commit_message_id,
            } => self.handle_group_outbox_head_fetched(
                group_id,
                head_seq,
                current_roster_version,
                last_commit_message_id,
            ),
            CoreEvent::GroupOutboxHeadFetchFailed {
                group_id,
                failure,
            } => self.handle_group_sync_failed(
                group_id,
                failure.retryable,
                failure.http_status,
                Some(failure.code),
                None,
            ),
            CoreEvent::GroupEnvelopeAppended {
                group_id,
                message_id,
                seq,
            } => self.handle_group_envelope_appended(group_id, message_id, seq),
            CoreEvent::GroupEnvelopeAppendFailed {
                group_id,
                message_id,
                failure,
            } => self.handle_group_append_failed(
                group_id,
                message_id,
                failure.retryable,
                failure.http_status,
                Some(failure.code),
                None,
            ),
            CoreEvent::GroupTransitionAppended {
                group_id,
                transition_id,
                first_seq,
                last_seq,
                roster_version,
                last_commit_message_id,
            } => self.handle_group_transition_appended(
                group_id,
                transition_id,
                first_seq,
                last_seq,
                roster_version,
                last_commit_message_id,
            ),
            CoreEvent::GroupTransitionAppendFailed {
                group_id,
                transition_id,
                failure,
            } => self.handle_group_transition_failed(
                group_id,
                transition_id,
                failure.retryable,
                failure.http_status,
                Some(failure.code),
                None,
            ),
            CoreEvent::GroupAuthorizationStateFetched {
                group_id,
                manifest,
                manifest_hash,
                last_transition_id,
                phase,
                materialized,
            } => self.handle_group_authorization_state_fetched(
                group_id,
                manifest,
                manifest_hash,
                last_transition_id,
                phase,
                materialized,
            ),
            CoreEvent::GroupAuthorizationStateFetchFailed {
                group_id,
                failure,
            } => self.handle_group_sync_failed(
                group_id,
                failure.retryable,
                failure.http_status,
                Some(failure.code),
                None,
            ),
            CoreEvent::GroupAuthorizationInitialized {
                group_id,
                roster_version,
            } => self.handle_group_authorization_initialized(group_id, roster_version),
            CoreEvent::GroupAuthorizationInitializeFailed {
                group_id,
                failure,
            } => {
                log::warn!(
                    "group authorization initialization failed: group_id={} retryable={} status={:?} code={}",
                    redact_id("group", &group_id),
                    failure.retryable,
                    failure.http_status,
                    failure.code
                );
                Ok(CoreOutput {
                    state_update: CoreStateUpdate {
                        system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                        ..CoreStateUpdate::default()
                    },
                    effects: vec![CoreEffect::EmitUserNotification {
                        notification: UserNotificationEffect {
                            status: SystemStatus::TemporaryNetworkFailure,
                            message: "TapChat couldn't initialize group authorization. Try again.".into(),
                        },
                    }],
                    view_model: None,
                })
            }
            CoreEvent::WelcomePickupFetched {
                descriptor,
                welcome_b64,
                manifest,
            } => self.handle_welcome_pickup_fetched(descriptor, welcome_b64, manifest),
            CoreEvent::WelcomePickupFetchFailed {
                descriptor,
                failure,
            } => self.handle_welcome_pickup_fetch_failed(descriptor, failure),
            CoreEvent::WelcomePickupPut { descriptor } => {
                self.handle_welcome_pickup_put(descriptor)
            }
            CoreEvent::WelcomePickupPutFailed {
                descriptor,
                failure: _,
            } => Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect {
                        status: SystemStatus::TemporaryNetworkFailure,
                        message: format!(
                            "TapChat couldn't publish the group welcome for device {}.",
                            descriptor.device_id
                        ),
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
                        revision: 0,
                        status: crate::transport_contract::GroupInviteStatus::Active,
                        uses: 0,
                        max_uses: None,
                        revoked_at: None,
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
            CoreEvent::GroupInviteFetched {
                invite_url: _,
                invite,
            } => {
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
                    status: if invite.join_policy == GroupJoinPolicy::OpenByInvite {
                        GroupJoinRequestStatus::WaitingForGroupCommit
                    } else {
                        GroupJoinRequestStatus::PendingApproval
                    },
                    auto_approve: Some(invite.join_policy == GroupJoinPolicy::OpenByInvite),
                };
                request.validate()?;
                self.state.group_join_requests.insert(
                    request_id.clone(),
                    PersistedGroupJoinRequest {
                        group_id: invite.group_id.clone(),
                        request_id: request_id.clone(),
                        request: request.clone(),
                        join_request_endpoint: Some(invite.join_request_endpoint.clone()),
                        welcome_pickup: None,
                        manifest: None,
                        start_cursor: None,
                        lease_token: None,
                        lease_expires_at: None,
                    },
                );
                let invite_token = invite.signature.clone();
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
                                join_request_endpoint: invite.join_request_endpoint.clone(),
                                request: request.clone(),
                                headers: BTreeMap::new(),
                            },
                        },
                    ],
                    view_model: Some(CoreViewModel {
                        group_join_requests: vec![request.clone()],
                        ..CoreViewModel::default()
                    }),
                })
            }
            CoreEvent::GroupJoinRequestSubmitted { request } => {
                let join_request_endpoint = self
                    .state
                    .group_join_requests
                    .get(&request.request_id)
                    .and_then(|stored| stored.join_request_endpoint.clone());
                self.state.group_join_requests.insert(
                    request.request_id.clone(),
                    PersistedGroupJoinRequest {
                        group_id: request.group_id.clone(),
                        request_id: request.request_id.clone(),
                        request: request.clone(),
                        join_request_endpoint,
                        welcome_pickup: None,
                        manifest: None,
                        start_cursor: None,
                        lease_token: None,
                        lease_expires_at: None,
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
                    let previous = self.state.group_join_requests.get(&request.request_id);
                    self.state.group_join_requests.insert(
                        request.request_id.clone(),
                        PersistedGroupJoinRequest {
                            group_id: request.group_id.clone(),
                            request_id: request.request_id.clone(),
                            request: request.clone(),
                            join_request_endpoint: previous
                                .and_then(|stored| stored.join_request_endpoint.clone()),
                            welcome_pickup: None,
                            manifest: None,
                            start_cursor: None,
                            lease_token: previous.and_then(|stored| stored.lease_token.clone()),
                            lease_expires_at: previous.and_then(|stored| stored.lease_expires_at),
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
                let previous = self.state.group_join_requests.get(&request.request_id);
                self.state.group_join_requests.insert(
                    request.request_id.clone(),
                    PersistedGroupJoinRequest {
                        group_id: request.group_id.clone(),
                        request_id: request.request_id.clone(),
                        request: request.clone(),
                        join_request_endpoint: previous
                            .and_then(|stored| stored.join_request_endpoint.clone()),
                        welcome_pickup: welcome_pickup.clone(),
                        manifest,
                        start_cursor,
                        lease_token: previous.and_then(|stored| stored.lease_token.clone()),
                        lease_expires_at: previous.and_then(|stored| stored.lease_expires_at),
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
            CoreEvent::GroupInviteCreateFailed { failure: _, .. }
            | CoreEvent::GroupInviteFetchFailed { failure: _, .. }
            | CoreEvent::GroupJoinRequestSubmitFailed { failure: _, .. }
            | CoreEvent::GroupJoinDecisionFailed { failure: _, .. } => Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect {
                        status: SystemStatus::TemporaryNetworkFailure,
                        message: "TapChat couldn't complete the group invite or join request. Try again.".into(),
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
            CoreEvent::GroupInvitesListed {
                group_id,
                revision,
                invites,
            } => self.handle_group_invites_listed(group_id, revision, invites),
            CoreEvent::GroupJoinDecisionApplied { request } => {
                let previous = self
                    .state
                    .group_join_requests
                    .get(&request.request_id)
                    .cloned();
                self.state.group_join_requests.insert(
                    request.request_id.clone(),
                    PersistedGroupJoinRequest {
                        group_id: request.group_id.clone(),
                        request_id: request.request_id.clone(),
                        request: request.clone(),
                        join_request_endpoint: previous
                            .as_ref()
                            .and_then(|stored| stored.join_request_endpoint.clone()),
                        welcome_pickup: previous
                            .as_ref()
                            .and_then(|stored| stored.welcome_pickup.clone()),
                        manifest: previous.as_ref().and_then(|stored| stored.manifest.clone()),
                        start_cursor: previous
                            .as_ref()
                            .and_then(|stored| stored.start_cursor.clone()),
                        lease_token: previous
                            .as_ref()
                            .and_then(|stored| stored.lease_token.clone()),
                        lease_expires_at: previous
                            .as_ref()
                            .and_then(|stored| stored.lease_expires_at),
                    },
                );
                let output = CoreOutput {
                    state_update: CoreStateUpdate {
                        conversations_changed: true,
                        ..CoreStateUpdate::default()
                    },
                    effects: vec![
                        persist_effect(
                            &self.state,
                            vec![PersistOp::SaveGroupJoinRequest {
                                request_id: request.request_id.clone(),
                            }],
                        ),
                        CoreEffect::EmitUserNotification {
                            notification: UserNotificationEffect {
                                status: SystemStatus::SyncInProgress,
                                message: format!(
                                    "group join request {} decided",
                                    request.request_id
                                ),
                            },
                        },
                    ],
                    view_model: Some(CoreViewModel {
                        group_join_requests: vec![request.clone()],
                        ..CoreViewModel::default()
                    }),
                };
                if request.status == GroupJoinRequestStatus::WaitingForGroupCommit {
                    let continuation = self.handle_command(CoreCommand::ApproveGroupJoin {
                        group_id: request.group_id,
                        request_id: request.request_id,
                    })?;
                    Ok(merge_outputs(output, continuation))
                } else {
                    Ok(output)
                }
            }
            CoreEvent::GroupJoinClaimed {
                request,
                lease_token,
                lease_expires_at,
            } => {
                let stored = self
                    .state
                    .group_join_requests
                    .get_mut(&request.request_id)
                    .ok_or_else(|| {
                        CoreError::invalid_input("claimed join request does not exist locally")
                    })?;
                stored.request = request.clone();
                stored.lease_token = Some(lease_token);
                stored.lease_expires_at = Some(lease_expires_at);
                let persist = persist_effect(
                    &self.state,
                    vec![PersistOp::SaveGroupJoinRequest {
                        request_id: request.request_id.clone(),
                    }],
                );
                let transition = self.handle_command(CoreCommand::ApproveGroupJoin {
                    group_id: request.group_id,
                    request_id: request.request_id,
                })?;
                Ok(merge_outputs(
                    CoreOutput {
                        state_update: CoreStateUpdate::default(),
                        effects: vec![persist],
                        view_model: None,
                    },
                    transition,
                ))
            }
            CoreEvent::GroupJoinCompleted { request } => {
                if let Some(stored) = self.state.group_join_requests.get_mut(&request.request_id) {
                    stored.request = request.clone();
                    stored.lease_token = None;
                    stored.lease_expires_at = None;
                }
                Ok(CoreOutput {
                    state_update: CoreStateUpdate {
                        conversations_changed: true,
                        ..CoreStateUpdate::default()
                    },
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
            CoreEvent::GroupJoinClaimFailed {
                group_id,
                request_id,
                failure,
            } => {
                Ok(CoreOutput {
                    state_update: CoreStateUpdate {
                        system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                        ..CoreStateUpdate::default()
                    },
                    effects: if failure.retryable {
                        vec![CoreEffect::ScheduleTimer {
                            timer: TimerEffect {
                                timer_id: format!("group_join_claim:{group_id}:{request_id}"),
                                delay_ms: 5_000,
                            },
                        }]
                    } else {
                        vec![CoreEffect::EmitUserNotification {
                            notification: UserNotificationEffect {
                                status: SystemStatus::TemporaryNetworkFailure,
                                message: "TapChat couldn't claim this group join request.".into(),
                            },
                        }]
                    },
                    view_model: None,
                })
            }
            CoreEvent::GroupJoinCompleteFailed {
                group_id,
                request_id,
                failure,
            } => Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: if failure.retryable {
                    vec![CoreEffect::ScheduleTimer {
                        timer: TimerEffect {
                            timer_id: format!("group_join_complete:{group_id}:{request_id}"),
                            delay_ms: 5_000,
                        },
                    }]
                } else {
                    vec![CoreEffect::EmitUserNotification {
                        notification: UserNotificationEffect {
                            status: SystemStatus::TemporaryNetworkFailure,
                            message: "TapChat couldn't complete this group join request.".into(),
                        },
                    }]
                },
                view_model: None,
            }),
            CoreEvent::GroupLeaveRequestSubmitted { request } => {
                let state = self
                    .state
                    .group_states
                    .get_mut(&request.group_id)
                    .ok_or_else(|| CoreError::invalid_input("group does not exist"))?;
                state
                    .leave_requests
                    .retain(|stored| stored.request.request_id != request.request_id);
                state.leave_requests.push(PersistedGroupLeaveRequest {
                    request: request.clone(),
                    lease_token: None,
                    lease_expires_at: None,
                });
                Ok(CoreOutput {
                    state_update: CoreStateUpdate {
                        conversations_changed: true,
                        ..CoreStateUpdate::default()
                    },
                    effects: vec![persist_effect(
                        &self.state,
                        vec![PersistOp::SaveGroupState {
                            group_id: request.group_id.clone(),
                        }],
                    )],
                    view_model: Some(CoreViewModel {
                        group_leave_requests: vec![request],
                        ..CoreViewModel::default()
                    }),
                })
            }
            CoreEvent::GroupLeaveRequestsListed { group_id, requests } => {
                let state = self
                    .state
                    .group_states
                    .get_mut(&group_id)
                    .ok_or_else(|| CoreError::invalid_input("group does not exist"))?;
                let old = std::mem::take(&mut state.leave_requests);
                state.leave_requests = requests
                    .iter()
                    .cloned()
                    .map(|request| {
                        let prior = old
                            .iter()
                            .find(|stored| stored.request.request_id == request.request_id);
                        PersistedGroupLeaveRequest {
                            request,
                            lease_token: prior.and_then(|stored| stored.lease_token.clone()),
                            lease_expires_at: prior.and_then(|stored| stored.lease_expires_at),
                        }
                    })
                    .collect();
                Ok(CoreOutput {
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
                        group_leave_requests: requests,
                        ..CoreViewModel::default()
                    }),
                })
            }
            CoreEvent::GroupLeaveClaimed {
                request,
                lease_token,
                lease_expires_at,
            } => {
                let state = self
                    .state
                    .group_states
                    .get_mut(&request.group_id)
                    .ok_or_else(|| CoreError::invalid_input("group does not exist"))?;
                let stored = state
                    .leave_requests
                    .iter_mut()
                    .find(|stored| stored.request.request_id == request.request_id)
                    .ok_or_else(|| {
                        CoreError::invalid_input("claimed leave request does not exist locally")
                    })?;
                stored.request = request.clone();
                stored.lease_token = Some(lease_token);
                stored.lease_expires_at = Some(lease_expires_at);
                let persist = persist_effect(
                    &self.state,
                    vec![PersistOp::SaveGroupState {
                        group_id: request.group_id.clone(),
                    }],
                );
                let transition = self.handle_command(CoreCommand::ApproveGroupLeave {
                    group_id: request.group_id,
                    request_id: request.request_id,
                })?;
                Ok(merge_outputs(
                    CoreOutput {
                        state_update: CoreStateUpdate::default(),
                        effects: vec![persist],
                        view_model: None,
                    },
                    transition,
                ))
            }
            CoreEvent::GroupLeaveRequestSubmitFailed {
                group_id,
                request_id,
                failure,
            }
            | CoreEvent::GroupLeaveClaimFailed {
                group_id,
                request_id,
                failure,
            } => Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: if failure.retryable {
                    vec![CoreEffect::ScheduleTimer {
                        timer: TimerEffect {
                            timer_id: format!("group_leave:{group_id}:{request_id}"),
                            delay_ms: 5_000,
                        },
                    }]
                } else {
                    vec![CoreEffect::EmitUserNotification {
                        notification: UserNotificationEffect {
                            status: SystemStatus::TemporaryNetworkFailure,
                            message: "TapChat couldn't complete the group leave operation.".into(),
                        },
                    }]
                },
                view_model: None,
            }),
            CoreEvent::GroupOutboxSealed {
                group_id,
                sealed_at,
                was_already_sealed,
            } => self.handle_group_outbox_sealed(group_id, sealed_at, was_already_sealed),
            CoreEvent::GroupOutboxSealFailed {
                group_id,
                failure,
            } => self.handle_group_outbox_seal_failed(
                group_id,
                failure.retryable,
                failure.http_status,
                Some(failure.code),
                None,
            ),
        }
    }
}

fn current_timestamp_hint(outbox_len: usize) -> u64 {
    outbox_len as u64 + 1
}

pub(super) fn advance_contiguous_ack(
    contiguous_ack: &mut u64,
    deferred_ackable_seqs: &mut BTreeSet<u64>,
    seq: u64,
) {
    if seq <= *contiguous_ack {
        return;
    }
    deferred_ackable_seqs.insert(seq);
    while deferred_ackable_seqs.remove(&(*contiguous_ack).saturating_add(1)) {
        *contiguous_ack = (*contiguous_ack).saturating_add(1);
    }
}

fn normalize_display_name(display_name: Option<String>) -> CoreResult<Option<String>> {
    let Some(display_name) = display_name else {
        return Ok(None);
    };
    let trimmed = display_name.trim().to_string();
    if trimmed.is_empty() {
        return Ok(None);
    }
    crate::model::validate_display_name(&trimmed)?;
    Ok(Some(trimmed))
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

fn group_capability_signing_payload(capability: &GroupCapability) -> String {
    let mut operations = capability
        .operations
        .iter()
        .map(|operation| match operation {
            crate::model::GroupCapabilityOperation::Read => "read",
            crate::model::GroupCapabilityOperation::Subscribe => "subscribe",
            crate::model::GroupCapabilityOperation::AppendApplication => "append_application",
            crate::model::GroupCapabilityOperation::AppendControl => "append_control",
            crate::model::GroupCapabilityOperation::AppendMembership => "append_membership",
            crate::model::GroupCapabilityOperation::ManageInvites => "manage_invites",
            crate::model::GroupCapabilityOperation::ApproveJoin => "approve_join",
            crate::model::GroupCapabilityOperation::RemoveMember => "remove_member",
            crate::model::GroupCapabilityOperation::UpdateGroupMetadata => "update_group_metadata",
            crate::model::GroupCapabilityOperation::SealGroup => "seal_group",
        })
        .collect::<Vec<_>>();
    operations.sort_unstable();
    let role = match capability.role {
        GroupRole::Owner => "owner",
        GroupRole::Admin => "admin",
        GroupRole::Member => "member",
    };
    format!(
        "tapchat.group_capability.v2\nversion={}\nservice=group_outbox\ngroup_id={}\nuser_id={}\ndevice_id={}\nrole={}\noperations={}\nexpires_at={}",
        capability.version,
        capability.group_id,
        capability.user_id,
        capability.device_id,
        role,
        operations.join(","),
        capability.expires_at
    )
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
    let ops = unique.into_iter().collect::<Vec<_>>();
    let snapshot = build_persistence_snapshot(state);
    CoreEffect::PersistState {
        persist: PersistenceBatch {
            mutations: persistence_mutations(&snapshot, &ops),
            ops,
            snapshot: None,
        },
    }
}

fn refresh_persist_effect_snapshots(output: &mut CoreOutput, state: &CoreState) {
    let snapshot = build_persistence_snapshot(state);
    for effect in &mut output.effects {
        if let CoreEffect::PersistState { persist } = effect {
            persist.mutations = persistence_mutations(&snapshot, &persist.ops);
            persist.snapshot = None;
        }
    }
}

fn persistence_mutations(
    snapshot: &CorePersistenceSnapshot,
    ops: &[PersistOp],
) -> Vec<PersistenceMutation> {
    fn positioned<T: Clone, F: Fn(&T) -> String>(
        values: &[T],
        key: &str,
        key_fn: F,
    ) -> Option<(usize, T)> {
        values
            .iter()
            .enumerate()
            .find(|(_, value)| key_fn(value) == key)
            .map(|(position, value)| (position, value.clone()))
    }
    fn save_or_delete(
        mutations: &mut Vec<PersistenceMutation>,
        table: PersistenceTable,
        key: String,
        value: Option<(usize, PersistenceValue)>,
    ) {
        match value {
            Some((position, value)) => mutations.push(PersistenceMutation::Save {
                table,
                key,
                position,
                value,
            }),
            None => mutations.push(PersistenceMutation::Delete { table, key }),
        }
    }

    fn save_conversation_mutations(
        mutations: &mut Vec<PersistenceMutation>,
        snapshot: &CorePersistenceSnapshot,
        conversation_id: &str,
    ) {
        let Some((position, conversation)) =
            positioned(&snapshot.conversations, conversation_id, |value| {
                value.conversation_id.clone()
            })
        else {
            mutations.push(PersistenceMutation::Delete {
                table: PersistenceTable::Conversations,
                key: conversation_id.to_string(),
            });
            return;
        };

        let message_count = conversation.state.messages.len() as u64;
        let last_visible_message = conversation
            .state
            .messages
            .iter()
            .rev()
            .find(|message| message.plaintext.is_some() || !message.storage_refs.is_empty())
            .cloned();
        let mut summary = conversation.clone();
        summary.state.messages.clear();
        mutations.push(PersistenceMutation::Save {
            table: PersistenceTable::Conversations,
            key: conversation_id.to_string(),
            position,
            value: PersistenceValue::ConversationSummary(PersistedConversationSummary {
                conversation: summary,
                message_count,
                last_visible_message,
            }),
        });

        // A conversation save may be generated from a compact bootstrap index
        // containing years of message IDs. Keep every batch bounded to the
        // mutable tail plus non-terminal delivery rows.
        const MUTABLE_MESSAGE_TAIL: usize = 16;
        let tail_start = conversation
            .state
            .messages
            .len()
            .saturating_sub(MUTABLE_MESSAGE_TAIL);
        let mut selected = BTreeSet::new();
        for message in conversation.state.messages.iter().skip(tail_start).chain(
            conversation.state.messages.iter().filter(|message| {
                matches!(
                    message.delivery_state,
                    Some(
                        crate::conversation::StoredMessageDeliveryState::Sending
                            | crate::conversation::StoredMessageDeliveryState::PendingApproval
                            | crate::conversation::StoredMessageDeliveryState::Failed
                    )
                )
            }),
        ) {
            if !selected.insert(message.message_id.clone()) {
                continue;
            }
            mutations.push(PersistenceMutation::InsertMessage {
                conversation_id: conversation_id.to_string(),
                message: message.clone(),
            });
            mutations.push(PersistenceMutation::UpdateMessageDelivery {
                conversation_id: conversation_id.to_string(),
                message_id: message.message_id.clone(),
                delivery_state: message.delivery_state,
                message_request_id: message.message_request_id.clone(),
            });

            let is_attachment = message.message_id.ends_with(":attachment")
                || message
                    .storage_refs
                    .iter()
                    .any(|reference| reference.kind.starts_with("attachment_"))
                || message.plaintext.as_deref().is_some_and(|plaintext| {
                    serde_json::from_str::<AttachmentManifestV2>(plaintext).is_ok()
                });
            if is_attachment {
                let attachment_state = match message.delivery_state {
                    Some(crate::conversation::StoredMessageDeliveryState::Failed) => {
                        PersistedMessageAttachmentState::Failed
                    }
                    _ if message.plaintext.is_some() || !message.storage_refs.is_empty() => {
                        PersistedMessageAttachmentState::Published
                    }
                    _ => PersistedMessageAttachmentState::Sending,
                };
                mutations.push(PersistenceMutation::UpdateAttachmentState {
                    conversation_id: conversation_id.to_string(),
                    message_id: message.message_id.clone(),
                    attachment_state,
                    plaintext: message.plaintext.clone(),
                    storage_refs: message.storage_refs.clone(),
                });
            }
        }
    }

    let mut mutations = vec![PersistenceMutation::SaveMetadata {
        message_nonce: snapshot.message_nonce,
        local_display_name: snapshot.local_display_name.clone(),
        mls_state_persistence_blocked: snapshot.mls_state_persistence_blocked,
    }];
    for op in ops {
        match op {
            PersistOp::SaveLocalIdentity => save_or_delete(
                &mut mutations,
                PersistenceTable::Identity,
                "local".into(),
                snapshot
                    .local_identity
                    .clone()
                    .map(|value| (0, PersistenceValue::LocalIdentity(value))),
            ),
            PersistOp::SaveDeployment => save_or_delete(
                &mut mutations,
                PersistenceTable::Deployment,
                "active".into(),
                snapshot
                    .deployment
                    .clone()
                    .map(|value| (0, PersistenceValue::Deployment(value))),
            ),
            PersistOp::SaveContact { user_id } => save_or_delete(
                &mut mutations,
                PersistenceTable::Contacts,
                user_id.clone(),
                positioned(&snapshot.contacts, user_id, |value| value.user_id.clone())
                    .map(|(position, value)| (position, PersistenceValue::Contact(value))),
            ),
            PersistOp::DeleteContact { user_id } => mutations.push(PersistenceMutation::Delete {
                table: PersistenceTable::Contacts,
                key: user_id.clone(),
            }),
            PersistOp::SaveConversation { conversation_id } => {
                save_conversation_mutations(&mut mutations, snapshot, conversation_id)
            }
            PersistOp::DeleteConversation { conversation_id } => {
                mutations.push(PersistenceMutation::Delete {
                    table: PersistenceTable::Conversations,
                    key: conversation_id.clone(),
                })
            }
            PersistOp::SaveSyncState { device_id } => save_or_delete(
                &mut mutations,
                PersistenceTable::SyncCheckpoints,
                device_id.clone(),
                positioned(&snapshot.sync_states, device_id, |value| {
                    value.device_id.clone()
                })
                .map(|(position, value)| (position, PersistenceValue::SyncState(value))),
            ),
            PersistOp::DeleteSyncState { device_id } => {
                mutations.push(PersistenceMutation::Delete {
                    table: PersistenceTable::SyncCheckpoints,
                    key: device_id.clone(),
                })
            }
            PersistOp::SaveMlsState { conversation_id } => save_or_delete(
                &mut mutations,
                PersistenceTable::MlsStates,
                conversation_id.clone(),
                positioned(&snapshot.mls_states, conversation_id, |value| {
                    value.conversation_id.clone()
                })
                .map(|(position, value)| (position, PersistenceValue::MlsState(value))),
            ),
            PersistOp::DeleteMlsState { conversation_id } => {
                mutations.push(PersistenceMutation::Delete {
                    table: PersistenceTable::MlsStates,
                    key: conversation_id.clone(),
                })
            }
            PersistOp::SaveOutgoingEnvelope { message_id } => save_or_delete(
                &mut mutations,
                PersistenceTable::PendingOutbox,
                message_id.clone(),
                positioned(&snapshot.pending_outbox, message_id, |value| {
                    value.message_id.clone()
                })
                .map(|(position, value)| (position, PersistenceValue::OutgoingEnvelope(value))),
            ),
            PersistOp::DeleteOutgoingEnvelope { message_id } => {
                mutations.push(PersistenceMutation::Delete {
                    table: PersistenceTable::PendingOutbox,
                    key: message_id.clone(),
                })
            }
            PersistOp::SaveGroupState { group_id } => save_or_delete(
                &mut mutations,
                PersistenceTable::GroupStates,
                group_id.clone(),
                positioned(&snapshot.group_states, group_id, |value| {
                    value.group_id.clone()
                })
                .map(|(position, value)| (position, PersistenceValue::GroupState(value))),
            ),
            PersistOp::DeleteGroupState { group_id } => {
                mutations.push(PersistenceMutation::Delete {
                    table: PersistenceTable::GroupStates,
                    key: group_id.clone(),
                })
            }
            PersistOp::SaveGroupCursor { group_id } => save_or_delete(
                &mut mutations,
                PersistenceTable::GroupCursors,
                group_id.clone(),
                positioned(&snapshot.group_cursors, group_id, |value| {
                    value.group_id.clone()
                })
                .map(|(position, value)| (position, PersistenceValue::GroupCursor(value))),
            ),
            PersistOp::DeleteGroupCursor { group_id } => {
                mutations.push(PersistenceMutation::Delete {
                    table: PersistenceTable::GroupCursors,
                    key: group_id.clone(),
                })
            }
            PersistOp::SaveOutgoingGroupEnvelope { message_id } => save_or_delete(
                &mut mutations,
                PersistenceTable::PendingGroupOutbox,
                message_id.clone(),
                positioned(&snapshot.pending_group_outbox, message_id, |value| {
                    value.message_id.clone()
                })
                .map(|(position, value)| {
                    (position, PersistenceValue::OutgoingGroupEnvelope(value))
                }),
            ),
            PersistOp::DeleteOutgoingGroupEnvelope { message_id } => {
                mutations.push(PersistenceMutation::Delete {
                    table: PersistenceTable::PendingGroupOutbox,
                    key: message_id.clone(),
                })
            }
            PersistOp::SavePendingGroupSeal { group_id } => save_or_delete(
                &mut mutations,
                PersistenceTable::PendingGroupSeal,
                group_id.clone(),
                positioned(&snapshot.pending_group_seal, group_id, |value| {
                    value.group_id.clone()
                })
                .map(|(position, value)| (position, PersistenceValue::PendingGroupSeal(value))),
            ),
            PersistOp::DeletePendingGroupSeal { group_id } => {
                mutations.push(PersistenceMutation::Delete {
                    table: PersistenceTable::PendingGroupSeal,
                    key: group_id.clone(),
                })
            }
            PersistOp::SaveGroupInvite { invite_id } => save_or_delete(
                &mut mutations,
                PersistenceTable::GroupInvites,
                invite_id.clone(),
                positioned(&snapshot.group_invites, invite_id, |value| {
                    value.invite_id.clone()
                })
                .map(|(position, value)| (position, PersistenceValue::GroupInvite(value))),
            ),
            PersistOp::DeleteGroupInvite { invite_id } => {
                mutations.push(PersistenceMutation::Delete {
                    table: PersistenceTable::GroupInvites,
                    key: invite_id.clone(),
                })
            }
            PersistOp::SaveGroupJoinRequest { request_id } => save_or_delete(
                &mut mutations,
                PersistenceTable::GroupJoinRequests,
                request_id.clone(),
                positioned(&snapshot.group_join_requests, request_id, |value| {
                    value.request_id.clone()
                })
                .map(|(position, value)| (position, PersistenceValue::GroupJoinRequest(value))),
            ),
            PersistOp::DeleteGroupJoinRequest { request_id } => {
                mutations.push(PersistenceMutation::Delete {
                    table: PersistenceTable::GroupJoinRequests,
                    key: request_id.clone(),
                })
            }
            PersistOp::SavePendingGroupJoinApproval { request_id } => save_or_delete(
                &mut mutations,
                PersistenceTable::PendingGroupJoinApprovals,
                request_id.clone(),
                positioned(
                    &snapshot.pending_group_join_approvals,
                    request_id,
                    |value| value.request_id.clone(),
                )
                .map(|(position, value)| {
                    (position, PersistenceValue::PendingGroupJoinApproval(value))
                }),
            ),
            PersistOp::DeletePendingGroupJoinApproval { request_id } => {
                mutations.push(PersistenceMutation::Delete {
                    table: PersistenceTable::PendingGroupJoinApprovals,
                    key: request_id.clone(),
                })
            }
            PersistOp::SavePendingWelcomePickup {
                group_id,
                device_id,
            } => {
                let key = format!("{group_id}::{device_id}");
                save_or_delete(
                    &mut mutations,
                    PersistenceTable::PendingWelcomePickups,
                    key.clone(),
                    positioned(&snapshot.pending_welcome_pickups, &key, |value| {
                        format!("{}::{}", value.group_id, value.device_id)
                    })
                    .map(|(position, value)| {
                        (position, PersistenceValue::PendingWelcomePickup(value))
                    }),
                );
            }
            PersistOp::DeletePendingWelcomePickup {
                group_id,
                device_id,
            } => mutations.push(PersistenceMutation::Delete {
                table: PersistenceTable::PendingWelcomePickups,
                key: format!("{group_id}::{device_id}"),
            }),
            PersistOp::SavePendingAck { device_id } => save_or_delete(
                &mut mutations,
                PersistenceTable::PendingAcks,
                device_id.clone(),
                positioned(&snapshot.pending_acks, device_id, |value| {
                    value.device_id.clone()
                })
                .map(|(position, value)| (position, PersistenceValue::PendingAck(value))),
            ),
            PersistOp::DeletePendingAck { device_id } => {
                mutations.push(PersistenceMutation::Delete {
                    table: PersistenceTable::PendingAcks,
                    key: device_id.clone(),
                })
            }
            PersistOp::SavePendingBlobTransfer { task_id } => save_or_delete(
                &mut mutations,
                PersistenceTable::PendingBlobTransfers,
                task_id.clone(),
                positioned(
                    &snapshot.pending_blob_transfers,
                    task_id,
                    |value| match value {
                        PersistedPendingBlobTransfer::Upload { task_id, .. }
                        | PersistedPendingBlobTransfer::Download { task_id, .. }
                        | PersistedPendingBlobTransfer::Delete { task_id, .. } => task_id.clone(),
                    },
                )
                .map(|(position, value)| (position, PersistenceValue::PendingBlobTransfer(value))),
            ),
            PersistOp::DeletePendingBlobTransfer { task_id } => {
                mutations.push(PersistenceMutation::Delete {
                    table: PersistenceTable::PendingBlobTransfers,
                    key: task_id.clone(),
                })
            }
            PersistOp::SaveRecoveryContext { conversation_id } => save_or_delete(
                &mut mutations,
                PersistenceTable::RecoveryContexts,
                conversation_id.clone(),
                positioned(&snapshot.recovery_contexts, conversation_id, |value| {
                    value.conversation_id.clone()
                })
                .map(|(position, value)| (position, PersistenceValue::RecoveryContext(value))),
            ),
            PersistOp::DeleteRecoveryContext { conversation_id } => {
                mutations.push(PersistenceMutation::Delete {
                    table: PersistenceTable::RecoveryContexts,
                    key: conversation_id.clone(),
                })
            }
            PersistOp::SaveRealtimeSession { device_id } => save_or_delete(
                &mut mutations,
                PersistenceTable::RealtimeSessions,
                device_id.clone(),
                positioned(&snapshot.realtime_sessions, device_id, |value| {
                    value.device_id.clone()
                })
                .map(|(position, value)| (position, PersistenceValue::RealtimeSession(value))),
            ),
            PersistOp::DeleteRealtimeSession { device_id } => {
                mutations.push(PersistenceMutation::Delete {
                    table: PersistenceTable::RealtimeSessions,
                    key: device_id.clone(),
                })
            }
        }
    }
    mutations
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
        local_display_name: state.local_display_name.clone(),
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
                key_package_inventory: state.key_package_inventory.clone(),
                pending_identity_publication: state.pending_identity_publication.clone(),
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
                app_message_id: item.app_message_id.clone(),
                plaintext_cache: item.plaintext_cache.clone(),
                identity_refresh_attempted: item.identity_refresh_attempted,
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
                capability: None,
                retries: item.retries,
                plaintext_cache: item.plaintext_cache.clone(),
            })
            .collect(),
        pending_group_seal: state.pending_group_seal.values().cloned().collect(),
        group_invites: state.group_invites.values().cloned().collect(),
        group_join_requests: state.group_join_requests.values().cloned().collect(),
        pending_group_join_approvals: state
            .pending_group_join_approvals
            .values()
            .cloned()
            .collect(),
        pending_welcome_pickups: state.pending_welcome_pickups.values().cloned().collect(),
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
                created_at: task.created_at,
                descriptor: task.descriptor.clone(),
                source: task.source.clone(),
                variant: task.variant,
                encrypted_descriptor: task.encrypted_descriptor.clone(),
                prepared_upload: task.prepared_upload.clone(),
                uploaded: task.uploaded,
                retries: task.retries,
            })
            .chain(state.pending_blob_downloads.values().map(|task| {
                PersistedPendingBlobTransfer::Download {
                    task_id: task.task_id.clone(),
                    conversation_id: task.conversation_id.clone(),
                    message_id: task.message_id.clone(),
                    reference: task.reference.clone(),
                    destination_id: task.destination_id.clone(),
                    blob_descriptor: task.blob_descriptor.clone(),
                    retries: task.retries,
                }
            }))
            .chain(state.pending_blob_deletions.values().map(|task| {
                PersistedPendingBlobTransfer::Delete {
                    task_id: task.task_id.clone(),
                    blob_ref: task.blob_ref.clone(),
                    delete_target: task.delete_target.clone(),
                    delete_capability: task.delete_capability.clone(),
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
                restore_failure_reason: context.restore_failure_reason.clone(),
                restore_failure_detail: context.restore_failure_detail.clone(),
                restore_recoverable: context.restore_recoverable,
                suggested_action: context.suggested_action.clone(),
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
        group_realtime_sessions: state
            .group_realtime_sessions
            .iter()
            .map(|(group_id, session)| PersistedGroupRealtimeSession {
                group_id: group_id.clone(),
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
    base.state_update.identity_changed |= next.state_update.identity_changed;
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
            if next_view.identity.is_some() {
                base_view.identity = next_view.identity.take();
            }
            base_view.banners.append(&mut next_view.banners);
            base_view
                .message_requests
                .append(&mut next_view.message_requests);
            base_view
                .operation_results
                .append(&mut next_view.operation_results);
            if next_view.allowlist.is_some() {
                base_view.allowlist = next_view.allowlist.take();
            }
            if next_view.message_request_action.is_some() {
                base_view.message_request_action = next_view.message_request_action.take();
            }
            if next_view.append_result.is_some() {
                base_view.append_result = next_view.append_result.take();
            }
            if next_view.group_sync_results.is_some() {
                base_view.group_sync_results = next_view.group_sync_results.take();
            }
            base_view.group_invites.append(&mut next_view.group_invites);
            base_view
                .group_join_requests
                .append(&mut next_view.group_join_requests);
            base_view
                .group_leave_requests
                .append(&mut next_view.group_leave_requests);
            base_view
                .welcome_pickups
                .append(&mut next_view.welcome_pickups);
        }
        (None, Some(next_view)) => base.view_model = Some(next_view),
        _ => {}
    }
    base
}

#[cfg(test)]
mod protected_application_message_tests {
    use super::{ApplicationPlaintextDecision, CoreEngine};
    use crate::conversation::{LocalConversationState, RecoveryStatus, StoredMessage};
    use crate::mls_adapter::DecryptedApplicationMessage;
    use crate::model::{
        Conversation, ConversationKind, ConversationMember, ConversationState, DeliveryClass,
        DeviceStatusKind, Envelope, InboxRecord, InboxRecordState, MessageType,
        ProtectedAppMessage, SenderProof, CURRENT_MODEL_VERSION,
    };

    fn sender_identity(user_id: &str, device_id: &str) -> String {
        format!("{user_id}|{device_id}|pk|sig")
    }

    fn sample_record() -> InboxRecord {
        InboxRecord {
            seq: 1,
            recipient_device_id: "device:bob:phone".into(),
            message_id: "msg:conv:alice:bob:1:device:bob:phone".into(),
            received_at: 1,
            expires_at: None,
            state: InboxRecordState::Available,
            envelope: Envelope {
                version: CURRENT_MODEL_VERSION.to_string(),
                message_id: "msg:conv:alice:bob:1:device:bob:phone".into(),
                conversation_id: "conv:alice:bob".into(),
                sender_user_id: "user:alice".into(),
                sender_device_id: "device:alice:phone".into(),
                recipient_device_id: "device:bob:phone".into(),
                created_at: 1,
                message_type: MessageType::MlsApplication,
                inline_ciphertext: Some("cipher".into()),
                storage_refs: Vec::new(),
                delivery_class: DeliveryClass::Normal,
                wake_hint: None,
                sender_proof: SenderProof {
                    proof_type: "signature".into(),
                    value: "proof".into(),
                },
            },
        }
    }

    #[test]
    fn invalid_inbox_batch_does_not_commit_seen_or_checkpoint_state() {
        let mut engine = CoreEngine::default();
        let mut record = sample_record();
        record.recipient_device_id = "device:mallory:phone".into();
        record.envelope.recipient_device_id = "device:mallory:phone".into();

        let error = engine
            .handle_inbox_records("device:bob:phone".into(), vec![record], 1)
            .expect_err("recipient mismatch must fail before registration");

        assert_eq!(error.code(), "invalid_input");
        assert!(engine.state.sync_states.is_empty());
    }

    #[test]
    fn non_monotonic_inbox_batch_does_not_commit_seen_or_checkpoint_state() {
        let mut engine = CoreEngine::default();
        let mut second = sample_record();
        second.seq = 2;
        second.message_id = "msg:conv:alice:bob:2:device:bob:phone".into();
        second.envelope.message_id = second.message_id.clone();
        let first = sample_record();

        let error = engine
            .handle_inbox_records("device:bob:phone".into(), vec![second, first], 2)
            .expect_err("non-monotonic batch must fail before registration");

        assert_eq!(error.code(), "invalid_input");
        assert!(engine.state.sync_states.is_empty());
    }

    fn protected_plaintext(audience: Vec<String>) -> Vec<u8> {
        ProtectedAppMessage::new_text(
            "app:conv:alice:bob:1:device:alice:phone".into(),
            "conv:alice:bob".into(),
            "user:alice".into(),
            "device:alice:phone".into(),
            "user:bob".into(),
            audience,
            "hello protected".into(),
            "sha256:genesis".into(),
        )
        .expect("protected message")
        .to_json_bytes()
        .expect("protected bytes")
    }

    fn decrypted(
        plaintext: Vec<u8>,
        user_id: &str,
        device_id: &str,
    ) -> DecryptedApplicationMessage {
        DecryptedApplicationMessage {
            plaintext,
            sender_identity: sender_identity(user_id, device_id),
            from_previous_epoch: false,
        }
    }

    #[test]
    fn protected_wrapper_accepts_body_and_app_message_id() {
        let engine = CoreEngine::default();
        let record = sample_record();
        let decision = engine.evaluate_direct_application_plaintext(
            &record,
            "user:bob",
            "device:bob:phone",
            decrypted(
                protected_plaintext(vec!["device:bob:phone".into()]),
                "user:alice",
                "device:alice:phone",
            ),
        );

        match decision {
            ApplicationPlaintextDecision::Accepted {
                plaintext,
                app_message_id,
            } => {
                assert_eq!(plaintext, "hello protected");
                assert_eq!(
                    app_message_id.as_deref(),
                    Some("app:conv:alice:bob:1:device:alice:phone")
                );
            }
            other => panic!("expected accepted wrapper, got {other:?}"),
        }
    }

    #[test]
    fn protected_wrapper_rejects_context_mismatch() {
        let engine = CoreEngine::default();
        let record = sample_record();
        let sender_mismatch = engine.evaluate_direct_application_plaintext(
            &record,
            "user:bob",
            "device:bob:phone",
            decrypted(
                protected_plaintext(vec!["device:bob:phone".into()]),
                "user:alice",
                "device:alice:laptop",
            ),
        );
        assert!(matches!(
            sender_mismatch,
            ApplicationPlaintextDecision::RejectedProtocol { .. }
        ));

        let audience_miss = engine.evaluate_direct_application_plaintext(
            &record,
            "user:bob",
            "device:bob:phone",
            decrypted(
                protected_plaintext(vec!["device:bob:laptop".into()]),
                "user:alice",
                "device:alice:phone",
            ),
        );
        assert!(matches!(
            audience_miss,
            ApplicationPlaintextDecision::RejectedProtocol { .. }
        ));
    }

    #[test]
    fn duplicate_app_message_id_is_not_accepted_again() {
        let mut engine = CoreEngine::default();
        engine.state.conversations.insert(
            "conv:alice:bob".into(),
            LocalConversationState {
                conversation: Conversation {
                    conversation_id: "conv:alice:bob".into(),
                    kind: ConversationKind::Direct,
                    member_users: vec!["user:alice".into(), "user:bob".into()],
                    member_devices: vec![
                        ConversationMember {
                            user_id: "user:alice".into(),
                            device_id: "device:alice:phone".into(),
                            status: DeviceStatusKind::Active,
                        },
                        ConversationMember {
                            user_id: "user:bob".into(),
                            device_id: "device:bob:phone".into(),
                            status: DeviceStatusKind::Active,
                        },
                    ],
                    state: ConversationState::Active,
                    updated_at: 1,
                },
                messages: vec![StoredMessage {
                    message_id: "msg:existing".into(),
                    app_message_id: Some("app:conv:alice:bob:1:device:alice:phone".into()),
                    mls_ciphertext_sha256: None,
                    sender_user_id: Some("user:alice".into()),
                    sender_device_id: "device:alice:phone".into(),
                    recipient_device_id: "device:bob:phone".into(),
                    message_type: MessageType::MlsApplication,
                    created_at: 1,
                    plaintext: Some("hello protected".into()),
                    storage_refs: Vec::new(),
                    delivery_state: None,
                    message_request_id: None,
                }],
                last_message_type: Some(MessageType::MlsApplication),
                peer_user_id: "user:alice".into(),
                last_known_peer_active_devices: Default::default(),
                recovery_status: RecoveryStatus::Healthy,
                archive_metadata: None,
                pcs: Default::default(),
            },
        );

        let decision = engine.evaluate_direct_application_plaintext(
            &sample_record(),
            "user:bob",
            "device:bob:phone",
            decrypted(
                protected_plaintext(vec!["device:bob:phone".into()]),
                "user:alice",
                "device:alice:phone",
            ),
        );
        assert!(matches!(
            decision,
            ApplicationPlaintextDecision::DuplicateAppMessage { .. }
        ));
    }

    #[test]
    fn legacy_plaintext_is_accepted_but_malformed_wrapper_is_rejected() {
        let engine = CoreEngine::default();
        let record = sample_record();
        let legacy = engine.evaluate_direct_application_plaintext(
            &record,
            "user:bob",
            "device:bob:phone",
            decrypted(b"legacy hello".to_vec(), "user:alice", "device:alice:phone"),
        );
        assert!(matches!(
            legacy,
            ApplicationPlaintextDecision::Accepted {
                app_message_id: None,
                ..
            }
        ));

        let malformed = serde_json::json!({
            "version": CURRENT_MODEL_VERSION,
            "payload_kind": "text",
            "body": "do not show"
        });
        let malformed = engine.evaluate_direct_application_plaintext(
            &record,
            "user:bob",
            "device:bob:phone",
            decrypted(
                malformed.to_string().into_bytes(),
                "user:alice",
                "device:alice:phone",
            ),
        );
        assert!(matches!(
            malformed,
            ApplicationPlaintextDecision::RejectedProtocol { .. }
        ));
    }
}

#[cfg(test)]
mod group_membership_security_tests {
    use super::{advance_contiguous_ack, CoreEngine};
    use crate::ffi_api::CoreCommand;
    use crate::model::{
        DeploymentBundle, GroupEnvelope, GroupEnvelopeVisibility, GroupJoinPolicy, GroupManifest,
        GroupMember, GroupMemberDevice, GroupMemberInvitePolicy, GroupMemberStatus,
        GroupMembershipProof, GroupMessageType, GroupOutboxDescriptor, GroupRole, RuntimeConfig,
        SenderProof, StorageBaseInfo, Validate, WelcomePickupDescriptor, CURRENT_MODEL_VERSION,
    };
    use std::collections::BTreeSet;

    fn membership_fsm_deployment() -> DeploymentBundle {
        DeploymentBundle {
            version: CURRENT_MODEL_VERSION.to_string(),
            runtime_id: "runtime:test".into(),
            protocol_version: 5,
            worker_build_id: "test-worker-v4".into(),
            registry_schema_version: 2,
            region: "test".into(),
            inbox_http_endpoint: "https://example.test".into(),
            inbox_websocket_endpoint: "wss://example.test/ws".into(),
            storage_base_info: StorageBaseInfo {
                base_url: Some("https://storage.example.test".into()),
                bucket_hint: None,
            },
            runtime_config: RuntimeConfig {
                supported_realtime_kinds: vec![],
                identity_bundle_ref: None,
                device_status_ref: None,
                keypackage_ref_base: None,
                max_inline_bytes: Some(4096),
                features: vec!["group_membership_fsm_v2".into()],
            },
            expected_user_id: None,
            expected_device_id: None,
        }
    }

    #[test]
    fn contiguous_ack_does_not_advance_past_pending_gap() {
        let mut ack = 6;
        let mut deferred = BTreeSet::new();

        advance_contiguous_ack(&mut ack, &mut deferred, 8);

        assert_eq!(ack, 6);
        assert!(deferred.contains(&8));
    }

    #[test]
    fn contiguous_ack_advances_after_gap_becomes_ackable() {
        let mut ack = 6;
        let mut deferred = BTreeSet::new();

        advance_contiguous_ack(&mut ack, &mut deferred, 8);
        advance_contiguous_ack(&mut ack, &mut deferred, 7);

        assert_eq!(ack, 8);
        assert!(deferred.is_empty());
    }

    fn base_manifest() -> GroupManifest {
        GroupManifest {
            version: CURRENT_MODEL_VERSION.to_string(),
            group_id: "group:security".into(),
            conversation_id: "conv:security".into(),
            title: "Security".into(),
            owner_user_id: "user:owner".into(),
            admins: vec!["user:admin".into()],
            members: vec![
                GroupMember {
                    user_id: "user:owner".into(),
                    role: GroupRole::Owner,
                    status: GroupMemberStatus::Active,
                },
                GroupMember {
                    user_id: "user:admin".into(),
                    role: GroupRole::Admin,
                    status: GroupMemberStatus::Active,
                },
                GroupMember {
                    user_id: "user:member".into(),
                    role: GroupRole::Member,
                    status: GroupMemberStatus::Active,
                },
            ],
            member_devices: vec![
                GroupMemberDevice {
                    user_id: "user:owner".into(),
                    device_id: "device:owner:desktop".into(),
                    status: GroupMemberStatus::Active,
                },
                GroupMemberDevice {
                    user_id: "user:admin".into(),
                    device_id: "device:admin:desktop".into(),
                    status: GroupMemberStatus::Active,
                },
                GroupMemberDevice {
                    user_id: "user:member".into(),
                    device_id: "device:member:desktop".into(),
                    status: GroupMemberStatus::Active,
                },
            ],
            join_policy: GroupJoinPolicy::ApprovalRequired,
            member_invite_policy: GroupMemberInvitePolicy::OwnerAdminOnly,
            roster_version: 4,
            mls_epoch_hint: 9,
            last_commit_message_id: Some("msg:commit:old".into()),
            outbox: GroupOutboxDescriptor {
                endpoint: "https://example.test/groups/security/outbox".into(),
                subscribe_endpoint: None,
            },
            updated_at: 100,
            signer_user_id: "user:owner".into(),
            signer_device_id: "device:owner:desktop".into(),
            signature: "manifest-sig".into(),
        }
    }

    fn next_manifest(signer_user_id: &str, signer_device_id: &str) -> GroupManifest {
        let mut manifest = base_manifest();
        manifest.roster_version += 1;
        manifest.mls_epoch_hint += 1;
        manifest.updated_at += 1;
        manifest.signer_user_id = signer_user_id.into();
        manifest.signer_device_id = signer_device_id.into();
        manifest.last_commit_message_id = Some("msg:commit:new".into());
        manifest
    }

    fn proof() -> GroupMembershipProof {
        GroupMembershipProof {
            proof_type: "membership_signature".into(),
            operation: "remove_device".into(),
            signer_user_id: "user:admin".into(),
            signer_device_id: "device:admin:desktop".into(),
            previous_roster_version: 4,
            new_roster_version: 5,
            previous_commit_message_id: Some("msg:commit:old".into()),
            commit_message_id: "msg:commit:new".into(),
            control_message_id: "msg:control:new".into(),
            state_event_message_id: None,
            new_manifest_sha256: "sha256:manifest".into(),
            signature: "proof-sig".into(),
        }
    }

    fn envelope(message_type: GroupMessageType, message_id: &str) -> GroupEnvelope {
        GroupEnvelope {
            version: CURRENT_MODEL_VERSION.to_string(),
            message_id: message_id.into(),
            group_id: "group:security".into(),
            conversation_id: "conv:security".into(),
            sender_user_id: "user:admin".into(),
            sender_device_id: "device:admin:desktop".into(),
            created_at: 101,
            message_type,
            visibility: GroupEnvelopeVisibility::Visible,
            inline_ciphertext: None,
            storage_refs: vec![],
            sender_proof: SenderProof {
                proof_type: "signature".into(),
                value: "sender-sig".into(),
            },
            membership_proof: Some(proof()),
            transition_id: None,
        }
    }

    #[test]
    fn group_membership_manifest_transition_rejects_member_signer() {
        let old = base_manifest();
        let new = next_manifest("user:member", "device:member:desktop");

        assert!(!CoreEngine::validate_manifest_transition(&old, &new));
    }

    #[test]
    fn group_membership_manifest_transition_rejects_signer_device_absent_from_manifest() {
        let old = base_manifest();
        let new = next_manifest("user:admin", "device:admin:unlisted");

        assert!(!CoreEngine::validate_manifest_transition(&old, &new));
    }

    #[test]
    fn group_membership_manifest_transition_rejects_roster_rollback_or_skip() {
        let old = base_manifest();
        let mut rollback = next_manifest("user:admin", "device:admin:desktop");
        rollback.roster_version = old.roster_version;
        assert!(!CoreEngine::validate_manifest_transition(&old, &rollback));

        let mut skip = next_manifest("user:admin", "device:admin:desktop");
        skip.roster_version = old.roster_version + 2;
        assert!(!CoreEngine::validate_manifest_transition(&old, &skip));
    }

    #[test]
    fn group_membership_manifest_transition_rejects_invalid_owner_shape() {
        let old = base_manifest();
        let mut two_owners = next_manifest("user:owner", "device:owner:desktop");
        two_owners.members[1].role = GroupRole::Owner;
        assert!(!CoreEngine::validate_manifest_transition(&old, &two_owners));

        let mut owner_id_mismatch = next_manifest("user:owner", "device:owner:desktop");
        owner_id_mismatch.owner_user_id = "user:admin".into();
        assert!(!CoreEngine::validate_manifest_transition(
            &old,
            &owner_id_mismatch
        ));
    }

    #[test]
    fn group_membership_proof_rejects_roster_skip() {
        let mut stale = proof();
        stale.new_roster_version = stale.previous_roster_version + 2;

        assert!(stale.validate().is_err());
    }

    #[test]
    fn group_membership_proof_binds_mls_commit_message_id() {
        let commit = envelope(GroupMessageType::MlsCommit, "msg:commit:other");
        let proof = commit.membership_proof.as_ref().expect("test proof");

        assert!(CoreEngine::verify_membership_proof_message_binding(&commit, proof).is_err());
    }

    #[test]
    fn group_membership_proof_binds_all_control_message_ids() {
        for message_type in [
            GroupMessageType::ControlGroupMembershipChanged,
            GroupMessageType::ControlGroupMetadataUpdated,
            GroupMessageType::ControlGroupDissolved,
        ] {
            let control = envelope(message_type, "msg:control:other");
            let proof = control.membership_proof.as_ref().expect("test proof");
            assert!(CoreEngine::verify_membership_proof_message_binding(&control, proof).is_err());
        }
    }

    #[test]
    fn group_membership_operation_rejects_delta_that_does_not_match_proof_operation() {
        let old = base_manifest();
        let mut new = next_manifest("user:admin", "device:admin:desktop");
        new.member_devices.push(GroupMemberDevice {
            user_id: "user:admin".into(),
            device_id: "device:admin:tablet".into(),
            status: GroupMemberStatus::Active,
        });
        let mut proof = proof();
        proof.operation = "update_metadata".into();
        proof.signer_user_id = new.signer_user_id.clone();
        proof.signer_device_id = new.signer_device_id.clone();
        proof.previous_roster_version = old.roster_version;
        proof.new_roster_version = new.roster_version;
        proof.previous_commit_message_id = old.last_commit_message_id.clone();
        proof.commit_message_id = new.last_commit_message_id.clone().expect("commit id");

        assert!(!CoreEngine::validate_manifest_transition_for_operation(
            &old, &new, &proof
        ));
    }

    #[test]
    fn group_membership_operation_accepts_single_device_addition() {
        let old = base_manifest();
        let mut new = next_manifest("user:admin", "device:admin:desktop");
        new.member_devices.push(GroupMemberDevice {
            user_id: "user:member".into(),
            device_id: "device:member:tablet".into(),
            status: GroupMemberStatus::Active,
        });
        let mut proof = proof();
        proof.operation = "add_device".into();
        proof.signer_user_id = new.signer_user_id.clone();
        proof.signer_device_id = new.signer_device_id.clone();
        proof.previous_roster_version = old.roster_version;
        proof.new_roster_version = new.roster_version;
        proof.previous_commit_message_id = old.last_commit_message_id.clone();
        proof.commit_message_id = new.last_commit_message_id.clone().expect("commit id");

        assert!(CoreEngine::validate_manifest_transition_for_operation(
            &old, &new, &proof
        ));
    }

    #[test]
    fn group_membership_operation_metadata_keeps_commit_chain_unchanged() {
        let old = base_manifest();
        let mut new = old.clone();
        new.title = "Security Updated".into();
        new.roster_version = old.roster_version + 1;
        new.mls_epoch_hint = old.mls_epoch_hint;
        new.updated_at = old.updated_at + 1;
        new.signer_user_id = "user:admin".into();
        new.signer_device_id = "device:admin:desktop".into();
        new.signature = "manifest-sig-updated".into();
        let mut proof = proof();
        proof.operation = "update_metadata".into();
        proof.signer_user_id = new.signer_user_id.clone();
        proof.signer_device_id = new.signer_device_id.clone();
        proof.previous_roster_version = old.roster_version;
        proof.new_roster_version = new.roster_version;
        proof.previous_commit_message_id = old.last_commit_message_id.clone();
        proof.commit_message_id = old.last_commit_message_id.clone().expect("commit id");

        assert!(CoreEngine::validate_manifest_transition_for_operation(
            &old, &new, &proof
        ));

        let mut forged = new.clone();
        forged.last_commit_message_id = Some("msg:commit:forged".into());
        assert!(!CoreEngine::validate_manifest_transition_for_operation(
            &old, &forged, &proof
        ));
    }

    #[test]
    fn welcome_pickup_rejects_manifest_with_invalid_signature_before_importing_shell() {
        let mut engine = CoreEngine::new();
        engine
            .handle_command(CoreCommand::CreateOrLoadIdentity {
                mnemonic: None,
                device_name: Some("desktop".into()),
                display_name: None,
            })
            .expect("create identity");
        let user_id = engine.local_identity_user_id().expect("local user");
        let device_id = engine.local_identity_device_id().expect("local device");
        let manifest = GroupManifest {
            version: CURRENT_MODEL_VERSION.to_string(),
            group_id: "group:welcome-invalid-signature".into(),
            conversation_id: "conv:welcome-invalid-signature".into(),
            title: "Invalid Signature".into(),
            owner_user_id: user_id.clone(),
            admins: vec![],
            members: vec![GroupMember {
                user_id: user_id.clone(),
                role: GroupRole::Owner,
                status: GroupMemberStatus::Active,
            }],
            member_devices: vec![GroupMemberDevice {
                user_id: user_id.clone(),
                device_id: device_id.clone(),
                status: GroupMemberStatus::Active,
            }],
            join_policy: GroupJoinPolicy::ApprovalRequired,
            member_invite_policy: GroupMemberInvitePolicy::OwnerAdminOnly,
            roster_version: 1,
            mls_epoch_hint: 1,
            last_commit_message_id: Some("msg:welcome:commit".into()),
            outbox: GroupOutboxDescriptor {
                endpoint: "https://example.test/groups/welcome-invalid-signature/outbox".into(),
                subscribe_endpoint: None,
            },
            updated_at: 1,
            signer_user_id: user_id,
            signer_device_id: device_id.clone(),
            signature: "00".repeat(64),
        };
        let descriptor = WelcomePickupDescriptor {
            group_id: manifest.group_id.clone(),
            device_id,
            endpoint: "https://example.test/welcome".into(),
            capability: "capability".into(),
            expires_at: 999,
            start_seq: None,
            roster_version: None,
            last_commit_message_id: None,
            request_id: None,
        };

        let error = engine
            .handle_welcome_pickup_fetched(descriptor, "Zm9yZ2Vk".into(), Some(manifest))
            .expect_err("invalid manifest signature must be rejected");

        assert!(!error.to_string().is_empty());
        assert!(!engine
            .state
            .group_states
            .contains_key("group:welcome-invalid-signature"));
    }

    #[test]
    fn sync_groups_for_removed_device_rejects_current_device() {
        let mut engine = CoreEngine::new();
        engine
            .handle_command(CoreCommand::ImportDeploymentBundle {
                bundle: membership_fsm_deployment(),
            })
            .expect("deployment");
        engine
            .handle_command(CoreCommand::CreateOrLoadIdentity {
                mnemonic: None,
                device_name: Some("desktop".into()),
                display_name: None,
            })
            .expect("create identity");
        let current_device_id = engine
            .local_identity()
            .expect("identity")
            .device_identity
            .device_id
            .clone();

        let error = engine
            .handle_command(CoreCommand::SyncGroupsForRemovedDevice {
                device_id: current_device_id,
            })
            .expect_err("current device must be rejected");

        assert!(error.to_string().contains("current device"));
    }

    #[test]
    fn sync_groups_for_removed_device_reports_empty_batch() {
        let mut engine = CoreEngine::new();
        engine
            .handle_command(CoreCommand::ImportDeploymentBundle {
                bundle: membership_fsm_deployment(),
            })
            .expect("deployment");
        engine
            .handle_command(CoreCommand::CreateOrLoadIdentity {
                mnemonic: None,
                device_name: Some("desktop".into()),
                display_name: None,
            })
            .expect("create identity");

        let output = engine
            .handle_command(CoreCommand::SyncGroupsForRemovedDevice {
                device_id: "device:alice:old-phone".into(),
            })
            .expect("empty batch succeeds");
        let results = output
            .view_model
            .and_then(|view_model| view_model.group_sync_results)
            .expect("group sync results");

        assert_eq!(results.total_candidates, 0);
        assert_eq!(results.succeeded, 0);
        assert_eq!(results.skipped, 0);
        assert!(results.errors.is_empty());
    }
}

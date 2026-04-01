use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::attachment_crypto::AttachmentPayloadMetadata;
use crate::conversation::LocalConversationState;
use crate::identity::LocalIdentityState;
use crate::mls_adapter::PublishedKeyPackage;
use crate::model::{Ack, DeploymentBundle, Envelope, IdentityBundle, MlsStateSummary};
use crate::sync_engine::DeviceSyncState;
use crate::transport_contract::PrepareBlobUploadResult;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedLocalIdentity {
    pub state: LocalIdentityState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedDeployment {
    pub deployment_bundle: DeploymentBundle,
    pub local_bundle: Option<IdentityBundle>,
    pub published_key_package: Option<PublishedKeyPackage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedContact {
    pub user_id: String,
    pub bundle: IdentityBundle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedConversation {
    pub conversation_id: String,
    pub state: LocalConversationState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedSyncState {
    pub device_id: String,
    pub state: DeviceSyncState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedMlsState {
    pub conversation_id: String,
    pub summary: MlsStateSummary,
    pub serialized_group_state: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedOutgoingEnvelope {
    pub message_id: String,
    pub envelope: Envelope,
    pub peer_user_id: String,
    pub retries: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedPendingAck {
    pub device_id: String,
    pub ack: Ack,
    pub retries: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PersistedPendingBlobTransfer {
    Upload {
        task_id: String,
        conversation_id: String,
        message_id: String,
        source: String,
        encrypted_source_path: String,
        payload_metadata: AttachmentPayloadMetadata,
        mime_type: String,
        size_bytes: u64,
        file_name: Option<String>,
        metadata_ciphertext: String,
        prepared_upload: Option<PrepareBlobUploadResult>,
        retries: u8,
    },
    Download {
        task_id: String,
        conversation_id: String,
        message_id: String,
        reference: String,
        destination: String,
        payload_metadata: AttachmentPayloadMetadata,
        retries: u8,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistedRecoveryReason {
    MissingCommit,
    MissingWelcome,
    MembershipChanged,
    IdentityChanged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedRecoveryContext {
    pub conversation_id: String,
    pub reason: PersistedRecoveryReason,
    pub sync_attempted: bool,
    pub identity_refresh_attempted: bool,
    pub identity_refresh_retry_count: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedRealtimeSession {
    pub device_id: String,
    pub last_known_seq: u64,
    pub needs_reconnect: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CorePersistenceSnapshot {
    #[serde(default)]
    pub message_nonce: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_identity: Option<PersistedLocalIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment: Option<PersistedDeployment>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contacts: Vec<PersistedContact>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conversations: Vec<PersistedConversation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sync_states: Vec<PersistedSyncState>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mls_states: Vec<PersistedMlsState>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_outbox: Vec<PersistedOutgoingEnvelope>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_acks: Vec<PersistedPendingAck>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_blob_transfers: Vec<PersistedPendingBlobTransfer>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recovery_contexts: Vec<PersistedRecoveryContext>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub realtime_sessions: Vec<PersistedRealtimeSession>,
    #[serde(default)]
    pub mls_state_persistence_blocked: bool,
}

pub const SNAPSHOT_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SnapshotFileEnvelope {
    format_version: u32,
    snapshot: CorePersistenceSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PersistOp {
    SaveLocalIdentity,
    SaveDeployment,
    SaveContact { user_id: String },
    DeleteContact { user_id: String },
    SaveConversation { conversation_id: String },
    DeleteConversation { conversation_id: String },
    SaveSyncState { device_id: String },
    DeleteSyncState { device_id: String },
    SaveMlsState { conversation_id: String },
    DeleteMlsState { conversation_id: String },
    SaveOutgoingEnvelope { message_id: String },
    DeleteOutgoingEnvelope { message_id: String },
    SavePendingAck { device_id: String },
    DeletePendingAck { device_id: String },
    SavePendingBlobTransfer { task_id: String },
    DeletePendingBlobTransfer { task_id: String },
    SaveRecoveryContext { conversation_id: String },
    DeleteRecoveryContext { conversation_id: String },
    SaveRealtimeSession { device_id: String },
    DeleteRealtimeSession { device_id: String },
}

pub trait IdentityRepository {
    fn save_local_identity(&mut self, identity: PersistedLocalIdentity);
    fn load_local_identity(&self) -> Option<PersistedLocalIdentity>;
    fn save_deployment(&mut self, deployment: PersistedDeployment);
    fn load_deployment(&self) -> Option<PersistedDeployment>;
    fn save_contact(&mut self, contact: PersistedContact);
    fn delete_contact(&mut self, user_id: &str);
    fn load_contacts(&self) -> Vec<PersistedContact>;
}

pub trait ConversationRepository {
    fn save_conversation(&mut self, conversation: PersistedConversation);
    fn delete_conversation(&mut self, conversation_id: &str);
    fn load_conversations(&self) -> Vec<PersistedConversation>;
}

pub trait InboxCheckpointRepository {
    fn save_sync_state(&mut self, sync_state: PersistedSyncState);
    fn delete_sync_state(&mut self, device_id: &str);
    fn load_sync_states(&self) -> Vec<PersistedSyncState>;
}

pub trait MlsStateRepository {
    fn save_mls_state(&mut self, mls_state: PersistedMlsState);
    fn delete_mls_state(&mut self, conversation_id: &str);
    fn load_mls_states(&self) -> Vec<PersistedMlsState>;
}

pub trait OutgoingQueueRepository {
    fn save_outgoing_envelope(&mut self, envelope: PersistedOutgoingEnvelope);
    fn delete_outgoing_envelope(&mut self, message_id: &str);
    fn load_outgoing_envelopes(&self) -> Vec<PersistedOutgoingEnvelope>;
    fn save_pending_ack(&mut self, ack: PersistedPendingAck);
    fn delete_pending_ack(&mut self, device_id: &str);
    fn load_pending_acks(&self) -> Vec<PersistedPendingAck>;
    fn save_pending_blob_transfer(&mut self, transfer: PersistedPendingBlobTransfer);
    fn delete_pending_blob_transfer(&mut self, task_id: &str);
    fn load_pending_blob_transfers(&self) -> Vec<PersistedPendingBlobTransfer>;
}

pub trait SystemStateRepository {
    fn save_recovery_context(&mut self, context: PersistedRecoveryContext);
    fn delete_recovery_context(&mut self, conversation_id: &str);
    fn load_recovery_contexts(&self) -> Vec<PersistedRecoveryContext>;
    fn save_realtime_session(&mut self, session: PersistedRealtimeSession);
    fn delete_realtime_session(&mut self, device_id: &str);
    fn load_realtime_sessions(&self) -> Vec<PersistedRealtimeSession>;
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct InMemoryPersistence {
    message_nonce: u64,
    local_identity: Option<PersistedLocalIdentity>,
    deployment: Option<PersistedDeployment>,
    contacts: BTreeMap<String, PersistedContact>,
    conversations: BTreeMap<String, PersistedConversation>,
    sync_states: BTreeMap<String, PersistedSyncState>,
    mls_states: BTreeMap<String, PersistedMlsState>,
    pending_outbox: BTreeMap<String, PersistedOutgoingEnvelope>,
    pending_acks: BTreeMap<String, PersistedPendingAck>,
    pending_blob_transfers: BTreeMap<String, PersistedPendingBlobTransfer>,
    recovery_contexts: BTreeMap<String, PersistedRecoveryContext>,
    realtime_sessions: BTreeMap<String, PersistedRealtimeSession>,
}

impl InMemoryPersistence {
    pub fn save_snapshot(&mut self, snapshot: &CorePersistenceSnapshot) {
        self.message_nonce = snapshot.message_nonce;
        self.local_identity = snapshot.local_identity.clone();
        self.deployment = snapshot.deployment.clone();
        self.contacts = snapshot
            .contacts
            .iter()
            .cloned()
            .map(|contact| (contact.user_id.clone(), contact))
            .collect();
        self.conversations = snapshot
            .conversations
            .iter()
            .cloned()
            .map(|conversation| (conversation.conversation_id.clone(), conversation))
            .collect();
        self.sync_states = snapshot
            .sync_states
            .iter()
            .cloned()
            .map(|sync_state| (sync_state.device_id.clone(), sync_state))
            .collect();
        self.mls_states = snapshot
            .mls_states
            .iter()
            .cloned()
            .map(|state| (state.conversation_id.clone(), state))
            .collect();
        self.pending_outbox = snapshot
            .pending_outbox
            .iter()
            .cloned()
            .map(|item| (item.message_id.clone(), item))
            .collect();
        self.pending_acks = snapshot
            .pending_acks
            .iter()
            .cloned()
            .map(|ack| (ack.device_id.clone(), ack))
            .collect();
        self.pending_blob_transfers = snapshot
            .pending_blob_transfers
            .iter()
            .cloned()
            .map(|transfer| {
                let key = match &transfer {
                    PersistedPendingBlobTransfer::Upload { task_id, .. }
                    | PersistedPendingBlobTransfer::Download { task_id, .. } => task_id.clone(),
                };
                (key, transfer)
            })
            .collect();
        self.recovery_contexts = snapshot
            .recovery_contexts
            .iter()
            .cloned()
            .map(|context| (context.conversation_id.clone(), context))
            .collect();
        self.realtime_sessions = snapshot
            .realtime_sessions
            .iter()
            .cloned()
            .map(|session| (session.device_id.clone(), session))
            .collect();
    }

    pub fn load_snapshot(&self) -> CorePersistenceSnapshot {
        CorePersistenceSnapshot {
            message_nonce: self.message_nonce,
            local_identity: self.local_identity.clone(),
            deployment: self.deployment.clone(),
            contacts: self.contacts.values().cloned().collect(),
            conversations: self.conversations.values().cloned().collect(),
            sync_states: self.sync_states.values().cloned().collect(),
            mls_states: self.mls_states.values().cloned().collect(),
            pending_outbox: self.pending_outbox.values().cloned().collect(),
            pending_acks: self.pending_acks.values().cloned().collect(),
            pending_blob_transfers: self.pending_blob_transfers.values().cloned().collect(),
            recovery_contexts: self.recovery_contexts.values().cloned().collect(),
            realtime_sessions: self.realtime_sessions.values().cloned().collect(),
            mls_state_persistence_blocked: self
                .mls_states
                .values()
                .any(|state| state.serialized_group_state.is_none()),
        }
    }
}

impl IdentityRepository for InMemoryPersistence {
    fn save_local_identity(&mut self, identity: PersistedLocalIdentity) {
        self.local_identity = Some(identity);
    }

    fn load_local_identity(&self) -> Option<PersistedLocalIdentity> {
        self.local_identity.clone()
    }

    fn save_deployment(&mut self, deployment: PersistedDeployment) {
        self.deployment = Some(deployment);
    }

    fn load_deployment(&self) -> Option<PersistedDeployment> {
        self.deployment.clone()
    }

    fn save_contact(&mut self, contact: PersistedContact) {
        self.contacts.insert(contact.user_id.clone(), contact);
    }

    fn delete_contact(&mut self, user_id: &str) {
        self.contacts.remove(user_id);
    }

    fn load_contacts(&self) -> Vec<PersistedContact> {
        self.contacts.values().cloned().collect()
    }
}

impl ConversationRepository for InMemoryPersistence {
    fn save_conversation(&mut self, conversation: PersistedConversation) {
        self.conversations
            .insert(conversation.conversation_id.clone(), conversation);
    }

    fn delete_conversation(&mut self, conversation_id: &str) {
        self.conversations.remove(conversation_id);
    }

    fn load_conversations(&self) -> Vec<PersistedConversation> {
        self.conversations.values().cloned().collect()
    }
}

impl InboxCheckpointRepository for InMemoryPersistence {
    fn save_sync_state(&mut self, sync_state: PersistedSyncState) {
        self.sync_states
            .insert(sync_state.device_id.clone(), sync_state);
    }

    fn delete_sync_state(&mut self, device_id: &str) {
        self.sync_states.remove(device_id);
    }

    fn load_sync_states(&self) -> Vec<PersistedSyncState> {
        self.sync_states.values().cloned().collect()
    }
}

impl MlsStateRepository for InMemoryPersistence {
    fn save_mls_state(&mut self, mls_state: PersistedMlsState) {
        self.mls_states
            .insert(mls_state.conversation_id.clone(), mls_state);
    }

    fn delete_mls_state(&mut self, conversation_id: &str) {
        self.mls_states.remove(conversation_id);
    }

    fn load_mls_states(&self) -> Vec<PersistedMlsState> {
        self.mls_states.values().cloned().collect()
    }
}

impl OutgoingQueueRepository for InMemoryPersistence {
    fn save_outgoing_envelope(&mut self, envelope: PersistedOutgoingEnvelope) {
        self.pending_outbox
            .insert(envelope.message_id.clone(), envelope);
    }

    fn delete_outgoing_envelope(&mut self, message_id: &str) {
        self.pending_outbox.remove(message_id);
    }

    fn load_outgoing_envelopes(&self) -> Vec<PersistedOutgoingEnvelope> {
        self.pending_outbox.values().cloned().collect()
    }

    fn save_pending_ack(&mut self, ack: PersistedPendingAck) {
        self.pending_acks.insert(ack.device_id.clone(), ack);
    }

    fn delete_pending_ack(&mut self, device_id: &str) {
        self.pending_acks.remove(device_id);
    }

    fn load_pending_acks(&self) -> Vec<PersistedPendingAck> {
        self.pending_acks.values().cloned().collect()
    }

    fn save_pending_blob_transfer(&mut self, transfer: PersistedPendingBlobTransfer) {
        let key = match &transfer {
            PersistedPendingBlobTransfer::Upload { task_id, .. }
            | PersistedPendingBlobTransfer::Download { task_id, .. } => task_id.clone(),
        };
        self.pending_blob_transfers.insert(key, transfer);
    }

    fn delete_pending_blob_transfer(&mut self, task_id: &str) {
        self.pending_blob_transfers.remove(task_id);
    }

    fn load_pending_blob_transfers(&self) -> Vec<PersistedPendingBlobTransfer> {
        self.pending_blob_transfers.values().cloned().collect()
    }
}

impl SystemStateRepository for InMemoryPersistence {
    fn save_recovery_context(&mut self, context: PersistedRecoveryContext) {
        self.recovery_contexts
            .insert(context.conversation_id.clone(), context);
    }

    fn delete_recovery_context(&mut self, conversation_id: &str) {
        self.recovery_contexts.remove(conversation_id);
    }

    fn load_recovery_contexts(&self) -> Vec<PersistedRecoveryContext> {
        self.recovery_contexts.values().cloned().collect()
    }

    fn save_realtime_session(&mut self, session: PersistedRealtimeSession) {
        self.realtime_sessions
            .insert(session.device_id.clone(), session);
    }

    fn delete_realtime_session(&mut self, device_id: &str) {
        self.realtime_sessions.remove(device_id);
    }

    fn load_realtime_sessions(&self) -> Vec<PersistedRealtimeSession> {
        self.realtime_sessions.values().cloned().collect()
    }
}

pub fn save_snapshot(path: &Path, snapshot: &CorePersistenceSnapshot) -> crate::CoreResult<()> {
    let payload = SnapshotFileEnvelope {
        format_version: SNAPSHOT_FORMAT_VERSION,
        snapshot: snapshot.clone(),
    };
    let serialized = serde_json::to_vec_pretty(&payload).map_err(|error| {
        crate::CoreError::invalid_state(format!("failed to serialize persistence snapshot: {error}"))
    })?;

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("tapchat.snapshot.json");
    let temp_path = path.with_file_name(format!("{file_name}.tmp"));

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            crate::CoreError::invalid_state(format!(
                "failed to create persistence snapshot directory: {error}"
            ))
        })?;
    }

    fs::write(&temp_path, serialized).map_err(|error| {
        crate::CoreError::invalid_state(format!("failed to write persistence snapshot: {error}"))
    })?;

    if path.exists() {
        fs::remove_file(path).map_err(|error| {
            crate::CoreError::invalid_state(format!(
                "failed to replace existing persistence snapshot: {error}"
            ))
        })?;
    }

    fs::rename(&temp_path, path).map_err(|error| {
        crate::CoreError::invalid_state(format!("failed to finalize persistence snapshot: {error}"))
    })?;
    Ok(())
}

pub fn load_snapshot(path: &Path) -> crate::CoreResult<Option<CorePersistenceSnapshot>> {
    if !path.exists() {
        return Ok(None);
    }

    let bytes = fs::read(path).map_err(|error| {
        crate::CoreError::invalid_state(format!("failed to read persistence snapshot: {error}"))
    })?;
    let envelope: SnapshotFileEnvelope = serde_json::from_slice(&bytes).map_err(|error| {
        crate::CoreError::invalid_input(format!("failed to decode persistence snapshot: {error}"))
    })?;

    if envelope.format_version != SNAPSHOT_FORMAT_VERSION {
        return Err(crate::CoreError::unsupported(format!(
            "unsupported persistence snapshot format version {}",
            envelope.format_version
        )));
    }

    Ok(Some(envelope.snapshot))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use crate::conversation::{ConversationManager, RecoveryStatus};
    use crate::identity::IdentityManager;
    use crate::model::{
        ConversationState, DeliveryClass, DeviceStatusKind, Envelope, MessageType, SenderProof,
        WakeHint, CURRENT_MODEL_VERSION,
    };

    const ALICE_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn in_memory_repository_round_trips_snapshot() {
        let identity =
            IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone"))
                .expect("identity");
        let conversation = ConversationManager::create_direct_conversation(
            &identity.user_identity.user_id,
            &identity.device_identity.device_id,
            "user:bob",
            &["device:bob:phone".into()],
        )
        .expect("conversation");
        let snapshot = CorePersistenceSnapshot {
            message_nonce: 7,
            local_identity: Some(PersistedLocalIdentity {
                state: identity.clone(),
            }),
            contacts: vec![PersistedContact {
                user_id: "user:bob".into(),
                bundle: IdentityBundle {
                    version: CURRENT_MODEL_VERSION.to_string(),
                    user_id: "user:bob".into(),
                    user_public_key: "pub".into(),
                    devices: vec![],
                    identity_bundle_ref: Some("ref:identity-bob".into()),
                    device_status_ref: None,
                    storage_profile: None,
                    updated_at: 0,
                    signature: "sig".into(),
                },
            }],
            conversations: vec![PersistedConversation {
                conversation_id: conversation.conversation.conversation_id.clone(),
                state: conversation,
            }],
            sync_states: vec![PersistedSyncState {
                device_id: identity.device_identity.device_id.clone(),
                state: DeviceSyncState {
                    checkpoint: crate::model::SyncCheckpoint {
                        device_id: identity.device_identity.device_id.clone(),
                        last_fetched_seq: 1,
                        last_acked_seq: 1,
                        updated_at: 1,
                    },
                    seen_message_ids: Default::default(),
                    pending_records: BTreeMap::new(),
                    pending_record_seqs: Default::default(),
                    pending_retry: false,
                    last_head_seq: 1,
                },
            }],
            pending_outbox: vec![PersistedOutgoingEnvelope {
                message_id: "msg:1".into(),
                envelope: Envelope {
                    version: CURRENT_MODEL_VERSION.to_string(),
                    message_id: "msg:1".into(),
                    conversation_id: "conv:one".into(),
                    sender_user_id: identity.user_identity.user_id.clone(),
                    sender_device_id: identity.device_identity.device_id.clone(),
                    recipient_device_id: "device:bob:phone".into(),
                    created_at: 1,
                    message_type: MessageType::MlsApplication,
                    inline_ciphertext: Some("cipher".into()),
                    storage_refs: vec![],
                    delivery_class: DeliveryClass::Normal,
                    wake_hint: Some(WakeHint {
                        latest_seq_hint: Some(1),
                    }),
                    sender_proof: SenderProof {
                        proof_type: "signature".into(),
                        value: "proof".into(),
                    },
                },
                peer_user_id: "user:bob".into(),
                retries: 0,
            }],
            pending_acks: vec![PersistedPendingAck {
                device_id: identity.device_identity.device_id.clone(),
                ack: Ack {
                    device_id: identity.device_identity.device_id.clone(),
                    ack_seq: 1,
                    acked_message_ids: vec![],
                    acked_at: 1,
                },
                retries: 0,
            }],
            pending_blob_transfers: vec![PersistedPendingBlobTransfer::Download {
                task_id: "blob:1".into(),
                conversation_id: "conv:one".into(),
                message_id: "msg:1".into(),
                reference: "cid:1".into(),
                destination: "download.bin".into(),
                payload_metadata: AttachmentPayloadMetadata {
                    mime_type: "application/octet-stream".into(),
                    size_bytes: 8,
                    file_name: Some("download.bin".into()),
                    encryption: crate::attachment_crypto::AttachmentCipherMetadata {
                        algorithm: crate::attachment_crypto::ATTACHMENT_CIPHER_ALGORITHM.into(),
                        key_b64: base64::engine::general_purpose::STANDARD
                            .encode([7_u8; 32]),
                        nonce_b64: base64::engine::general_purpose::STANDARD
                            .encode([9_u8; 12]),
                    },
                },
                retries: 1,
            }],
            recovery_contexts: vec![PersistedRecoveryContext {
                conversation_id: "conv:one".into(),
                reason: PersistedRecoveryReason::MissingCommit,
                sync_attempted: true,
                identity_refresh_attempted: false,
                identity_refresh_retry_count: 1,
            }],
            realtime_sessions: vec![PersistedRealtimeSession {
                device_id: identity.device_identity.device_id.clone(),
                last_known_seq: 3,
                needs_reconnect: true,
            }],
            mls_states: vec![PersistedMlsState {
                conversation_id: "conv:one".into(),
                summary: MlsStateSummary {
                    conversation_id: "conv:one".into(),
                    epoch: 1,
                    member_device_ids: vec![
                        identity.device_identity.device_id.clone(),
                        "device:bob:phone".into(),
                    ],
                    status: crate::model::MlsStateStatus::NeedsRecovery,
                    updated_at: 1,
                },
                serialized_group_state: None,
            }],
            deployment: None,
            mls_state_persistence_blocked: true,
        };

        let mut repo = InMemoryPersistence::default();
        repo.save_snapshot(&snapshot);
        let loaded = repo.load_snapshot();

        assert_eq!(loaded.local_identity, snapshot.local_identity);
        assert_eq!(loaded.pending_outbox.len(), 1);
        assert_eq!(loaded.pending_blob_transfers.len(), 1);
        assert!(loaded.mls_state_persistence_blocked);
    }

    #[test]
    fn persisted_types_capture_recovery_and_conversation_state() {
        let identity =
            IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone"))
                .expect("identity");
        let mut conversation = ConversationManager::create_direct_conversation(
            &identity.user_identity.user_id,
            &identity.device_identity.device_id,
            "user:bob",
            &["device:bob:phone".into()],
        )
        .expect("conversation");
        conversation.recovery_status = RecoveryStatus::NeedsRecovery;
        conversation.conversation.state = ConversationState::Active;
        conversation.conversation.member_devices.push(crate::model::ConversationMember {
            user_id: "user:bob".into(),
            device_id: "device:bob:laptop".into(),
            status: DeviceStatusKind::Revoked,
        });

        let persisted = PersistedConversation {
            conversation_id: conversation.conversation.conversation_id.clone(),
            state: conversation.clone(),
        };

        assert_eq!(persisted.state.recovery_status, RecoveryStatus::NeedsRecovery);
        assert_eq!(persisted.state.messages.len(), 0);
    }

    #[test]
    fn snapshot_file_round_trips() {
        let path = unique_snapshot_path("roundtrip");
        let snapshot = CorePersistenceSnapshot {
            message_nonce: 11,
            local_identity: None,
            deployment: Some(PersistedDeployment {
                deployment_bundle: DeploymentBundle {
                    version: CURRENT_MODEL_VERSION.to_string(),
                    region: "local".into(),
                    inbox_http_endpoint: "https://example.com".into(),
                    inbox_websocket_endpoint: "wss://example.com/ws".into(),
                    storage_base_info: crate::model::StorageBaseInfo {
                        base_url: Some("https://storage.example.com".into()),
                        bucket_hint: None,
                    },
                    runtime_config: crate::model::RuntimeConfig {
                        supported_realtime_kinds: vec![crate::model::RealtimeKind::Websocket],
                        identity_bundle_ref: Some("ref:identity-local".into()),
                        device_status_ref: Some("ref:device-status-local".into()),
                        keypackage_ref_base: Some("ref:keypackages-local".into()),
                        max_inline_bytes: Some(4096),
                        features: vec!["generic_sync".into()],
                    },
                    device_runtime_auth: Some(crate::model::DeviceRuntimeAuth {
                        scheme: "bearer".into(),
                        token: "device-runtime-token".into(),
                        expires_at: 999,
                        user_id: "user:alice".into(),
                        device_id: "device:alice:phone".into(),
                        scopes: vec!["inbox_read".into(), "inbox_ack".into()],
                    }),
                    expected_user_id: Some("user:alice".into()),
                    expected_device_id: Some("device:alice:phone".into()),
                },
                local_bundle: Some(IdentityBundle {
                    version: CURRENT_MODEL_VERSION.to_string(),
                    user_id: "user:alice".into(),
                    user_public_key: "pub".into(),
                    devices: vec![sample_contact_device("user:alice", "device:alice:phone")],
                    identity_bundle_ref: Some("ref:identity-local".into()),
                    device_status_ref: Some("ref:device-status-local".into()),
                    storage_profile: Some(crate::model::StorageProfile {
                        base_url: Some("https://storage.example.com".into()),
                        profile_ref: None,
                    }),
                    updated_at: 0,
                    signature: "sig".into(),
                }),
                published_key_package: None,
            }),
            contacts: vec![PersistedContact {
                user_id: "user:bob".into(),
                bundle: IdentityBundle {
                    version: CURRENT_MODEL_VERSION.to_string(),
                    user_id: "user:bob".into(),
                    user_public_key: "pub-bob".into(),
                    devices: vec![sample_contact_device("user:bob", "device:bob:phone")],
                    identity_bundle_ref: Some("ref:identity-bob".into()),
                    device_status_ref: Some("ref:device-status-bob".into()),
                    storage_profile: Some(crate::model::StorageProfile {
                        base_url: Some("https://storage.example.com".into()),
                        profile_ref: None,
                    }),
                    updated_at: 1,
                    signature: "sig-bob".into(),
                },
            }],
            conversations: vec![],
            sync_states: vec![],
            mls_states: vec![],
            pending_outbox: vec![],
            pending_acks: vec![],
            pending_blob_transfers: vec![],
            recovery_contexts: vec![],
            realtime_sessions: vec![],
            mls_state_persistence_blocked: false,
        };

        save_snapshot(&path, &snapshot).expect("save snapshot");
        let loaded = load_snapshot(&path).expect("load snapshot").expect("snapshot");
        assert_eq!(loaded, snapshot);
        assert_eq!(
            loaded
                .deployment
                .as_ref()
                .and_then(|deployment| {
                    deployment
                        .deployment_bundle
                        .runtime_config
                        .identity_bundle_ref
                        .as_deref()
                }),
            Some("ref:identity-local")
        );
        assert_eq!(
            loaded.contacts[0].bundle.identity_bundle_ref.as_deref(),
            Some("ref:identity-bob")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn snapshot_file_rejects_invalid_json() {
        let path = unique_snapshot_path("invalid-json");
        fs::write(&path, b"{not json").expect("write invalid json");

        let error = load_snapshot(&path).expect_err("invalid json should fail");
        assert_eq!(error.code(), "invalid_input");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn snapshot_file_rejects_unsupported_version() {
        let path = unique_snapshot_path("bad-version");
        fs::write(
            &path,
            serde_json::json!({
                "format_version": SNAPSHOT_FORMAT_VERSION + 1,
                "snapshot": CorePersistenceSnapshot::default(),
            })
            .to_string(),
        )
        .expect("write invalid version");

        let error = load_snapshot(&path).expect_err("unsupported version should fail");
        assert_eq!(error.code(), "unsupported");

        let _ = fs::remove_file(path);
    }

    fn unique_snapshot_path(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("tapchat-{name}-{nanos}.json"))
    }

    fn sample_contact_device(user_id: &str, device_id: &str) -> crate::model::DeviceContactProfile {
        crate::model::DeviceContactProfile {
            version: CURRENT_MODEL_VERSION.to_string(),
            device_id: device_id.into(),
            device_public_key: format!("pub:{device_id}"),
            binding: crate::model::DeviceBinding {
                version: CURRENT_MODEL_VERSION.to_string(),
                user_id: user_id.into(),
                device_id: device_id.into(),
                device_public_key: format!("pub:{device_id}"),
                created_at: 0,
                signature: "binding-sig".into(),
            },
            status: DeviceStatusKind::Active,
            inbox_append_capability: crate::model::InboxAppendCapability {
                version: CURRENT_MODEL_VERSION.to_string(),
                service: crate::model::CapabilityService::Inbox,
                user_id: user_id.into(),
                target_device_id: device_id.into(),
                endpoint: "https://example.com/inbox".into(),
                operations: vec![crate::model::CapabilityOperation::Append],
                conversation_scope: vec![],
                expires_at: 999,
                constraints: None,
                signature: "cap-sig".into(),
            },
            keypackage_ref: crate::model::KeyPackageRef {
                version: CURRENT_MODEL_VERSION.to_string(),
                user_id: user_id.into(),
                device_id: device_id.into(),
                object_ref: format!("ref:keypackage:{device_id}"),
                expires_at: 999,
            },
        }
    }
}


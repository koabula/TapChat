use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::attachment_crypto::AttachmentPayloadMetadata;
use crate::conversation::LocalConversationState;
use crate::conversation::RecoveryStatus;
use crate::identity::LocalIdentityState;
use crate::mls_adapter::{MlsAdapter, PublishedKeyPackage};
use crate::model::{
    Ack, ConversationKind, DeploymentBundle, Envelope, IdentityBundle, InboxRecord, MessageType,
    MlsStateStatus, MlsStateSummary,
};
use crate::persistence::{CorePersistenceSnapshot, PersistOp};
use crate::sync_engine::DeviceSyncState;
use crate::transport_contract::{
    BlobDownloadRequest, BlobUploadRequest, FetchIdentityBundleRequest, PrepareBlobUploadRequest,
    PrepareBlobUploadResult, RealtimeSubscriptionRequest,
};

pub const MAX_TRANSPORT_RETRIES: u8 = 3;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FfiApiModule;
impl FfiApiModule {
    pub fn name(&self) -> &'static str {
        "ffi_api"
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CoreCommand {
    CreateOrLoadIdentity {
        mnemonic: Option<String>,
        device_name: Option<String>,
    },
    ImportDeploymentBundle {
        bundle: DeploymentBundle,
    },
    ImportIdentityBundle {
        bundle: IdentityBundle,
    },
    ApplyIdentityBundleUpdate {
        bundle: IdentityBundle,
    },
    CreateConversation {
        peer_user_id: String,
        conversation_kind: ConversationKind,
    },
    ReconcileConversationMembership {
        conversation_id: String,
    },
    SendTextMessage {
        conversation_id: String,
        plaintext: String,
    },
    SendAttachmentMessage {
        conversation_id: String,
        attachment_descriptor: AttachmentDescriptor,
    },
    DownloadAttachment {
        conversation_id: String,
        message_id: String,
        reference: String,
        destination: String,
    },
    SyncInbox {
        device_id: String,
        reason: Option<String>,
    },
    RefreshIdentityState {
        user_id: String,
    },
    CreateAdditionalDeviceIdentity {
        mnemonic: Option<String>,
        device_name: Option<String>,
    },
    RotateLocalKeyPackage,
    ApplyLocalDeviceStatusUpdate {
        status: crate::model::DeviceStatusKind,
    },
    UpdateLocalDeviceStatus {
        target_device_id: String,
        status: crate::model::DeviceStatusKind,
    },
    RebuildConversation {
        conversation_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CoreEvent {
    AppStarted,
    AppForegrounded,
    WebSocketConnected {
        device_id: String,
    },
    WebSocketDisconnected {
        device_id: String,
        reason: Option<String>,
    },
    RealtimeEventReceived {
        device_id: String,
        event: RealtimeEvent,
    },
    WakeupReceived {
        device_id: String,
        latest_seq_hint: Option<u64>,
    },
    InboxRecordsFetched {
        device_id: String,
        records: Vec<InboxRecord>,
        to_seq: u64,
    },
    HttpResponseReceived {
        request_id: String,
        status: u16,
        body: Option<String>,
    },
    HttpRequestFailed {
        request_id: String,
        retryable: bool,
        detail: Option<String>,
    },
    IdentityBundleFetched {
        user_id: String,
        bundle: IdentityBundle,
    },
    IdentityBundleFetchFailed {
        user_id: String,
        retryable: bool,
        detail: Option<String>,
    },
    AttachmentBytesLoaded {
        task_id: String,
        plaintext_b64: String,
    },
    BlobUploadPrepared {
        task_id: String,
        result: PrepareBlobUploadResult,
    },
    BlobUploaded {
        task_id: String,
    },
    BlobDownloaded {
        task_id: String,
        blob_ciphertext: Option<String>,
    },
    BlobTransferFailed {
        task_id: String,
        retryable: bool,
        detail: Option<String>,
    },
    TimerTriggered {
        timer_id: String,
    },
    UserConfirmedRebuild {
        conversation_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RealtimeEvent {
    HeadUpdated {
        seq: u64,
    },
    InboxRecordAvailable {
        seq: u64,
        record: Option<InboxRecord>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentDescriptor {
    pub attachment_id: String,
    pub mime_type: String,
    pub size_bytes: u64,
    pub file_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadAttachmentBytesEffect {
    pub task_id: String,
    pub attachment_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteDownloadedAttachmentEffect {
    pub task_id: String,
    pub destination_id: String,
    pub plaintext_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequestEffect {
    pub request_id: String,
    pub method: HttpMethod,
    pub url: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealtimeConnectionEffect {
    pub subscription: RealtimeSubscriptionRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistStateEffect {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ops: Vec<PersistOp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<CorePersistenceSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimerEffect {
    pub timer_id: String,
    pub delay_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserNotificationEffect {
    pub status: SystemStatus,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CoreEffect {
    ExecuteHttpRequest {
        request: HttpRequestEffect,
    },
    OpenRealtimeConnection {
        connection: RealtimeConnectionEffect,
    },
    CloseRealtimeConnection {
        device_id: String,
    },
    FetchIdentityBundle {
        fetch: FetchIdentityBundleRequest,
    },
    ReadAttachmentBytes {
        read: ReadAttachmentBytesEffect,
    },
    PrepareBlobUpload {
        upload: PrepareBlobUploadRequest,
    },
    UploadBlob {
        upload: BlobUploadRequest,
    },
    DownloadBlob {
        download: BlobDownloadRequest,
    },
    WriteDownloadedAttachment {
        write: WriteDownloadedAttachmentEffect,
    },
    PersistState {
        persist: PersistStateEffect,
    },
    ScheduleTimer {
        timer: TimerEffect,
    },
    EmitUserNotification {
        notification: UserNotificationEffect,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemStatus {
    SyncInProgress,
    IdentityRefreshNeeded,
    ConversationNeedsRebuild,
    AttachmentUploadFailed,
    TemporaryNetworkFailure,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CoreStateUpdate {
    #[serde(default)]
    pub conversations_changed: bool,
    #[serde(default)]
    pub messages_changed: bool,
    #[serde(default)]
    pub contacts_changed: bool,
    #[serde(default)]
    pub checkpoints_changed: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub system_statuses_changed: Vec<SystemStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationSummary {
    pub conversation_id: String,
    pub state: String,
    pub last_message_type: Option<MessageType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<RecoveryDiagnostics>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageSummary {
    pub conversation_id: String,
    pub message_id: String,
    pub message_type: MessageType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactSummary {
    pub user_id: String,
    pub device_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemBanner {
    pub status: SystemStatus,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CoreViewModel {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conversations: Vec<ConversationSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub messages: Vec<MessageSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contacts: Vec<ContactSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub banners: Vec<SystemBanner>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CoreOutput {
    #[serde(default)]
    pub state_update: CoreStateUpdate,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effects: Vec<CoreEffect>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view_model: Option<CoreViewModel>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PendingOutboxItem {
    pub(crate) envelope: Envelope,
    pub(crate) peer_user_id: String,
    pub(crate) retries: u8,
    pub(crate) in_flight: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PendingAckState {
    pub(crate) ack: Ack,
    pub(crate) retries: u8,
    pub(crate) in_flight: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PendingBlobUpload {
    pub(crate) task_id: String,
    pub(crate) conversation_id: String,
    pub(crate) descriptor: AttachmentDescriptor,
    pub(crate) blob_ciphertext_b64: Option<String>,
    pub(crate) payload_metadata: Option<AttachmentPayloadMetadata>,
    pub(crate) message_id: String,
    pub(crate) metadata_ciphertext: Option<String>,
    pub(crate) prepared_upload: Option<PrepareBlobUploadResult>,
    pub(crate) retries: u8,
    pub(crate) in_flight: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PendingBlobDownload {
    pub(crate) task_id: String,
    pub(crate) conversation_id: String,
    pub(crate) message_id: String,
    pub(crate) reference: String,
    pub(crate) destination_id: String,
    pub(crate) payload_metadata: AttachmentPayloadMetadata,
    pub(crate) retries: u8,
    pub(crate) in_flight: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RealtimeSessionState {
    pub(crate) connected: bool,
    pub(crate) last_known_seq: u64,
    pub(crate) needs_reconnect: bool,
}

#[derive(Debug)]
pub(crate) struct CoreState {
    pub(crate) local_identity: Option<LocalIdentityState>,
    pub(crate) local_bundle: Option<IdentityBundle>,
    pub(crate) deployment_bundle: Option<DeploymentBundle>,
    pub(crate) contacts: BTreeMap<String, IdentityBundle>,
    pub(crate) conversations: BTreeMap<String, LocalConversationState>,
    pub(crate) sync_states: BTreeMap<String, DeviceSyncState>,
    pub(crate) outbox: Vec<Envelope>,
    pub(crate) pending_outbox: Vec<PendingOutboxItem>,
    pub(crate) pending_acks: BTreeMap<String, PendingAckState>,
    pub(crate) pending_blob_uploads: BTreeMap<String, PendingBlobUpload>,
    pub(crate) pending_blob_downloads: BTreeMap<String, PendingBlobDownload>,
    pub(crate) realtime_sessions: BTreeMap<String, RealtimeSessionState>,
    pub(crate) mls_adapter: Option<MlsAdapter>,
    pub(crate) mls_summaries: BTreeMap<String, MlsStateSummary>,
    pub(crate) published_key_package: Option<PublishedKeyPackage>,
    pub(crate) pending_requests: BTreeMap<String, PendingRequest>,
    pub(crate) request_nonce: u64,
    pub(crate) message_nonce: u64,
    pub(crate) recovery_contexts: BTreeMap<String, RecoveryContext>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PendingRequest {
    GetHead {
        device_id: String,
    },
    FetchMessages {
        device_id: String,
        from_seq: u64,
        limit: u64,
    },
    AppendEnvelope {
        message_id: String,
        peer_user_id: String,
    },
    Ack {
        device_id: String,
        ack_seq: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryReason {
    MissingCommit,
    MissingWelcome,
    MembershipChanged,
    IdentityChanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryPhase {
    WaitingForSync,
    WaitingForPendingReplay,
    WaitingForIdentityRefresh,
    WaitingForExplicitReconcile,
    EscalatedToRebuild,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryEscalationReason {
    MlsMarkedUnrecoverable,
    IdentityRefreshRetryExhausted,
    ExplicitNeedsRebuildControl,
    RecoveryPolicyExhausted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RecoveryContext {
    pub(crate) conversation_id: String,
    pub(crate) reason: RecoveryReason,
    pub(crate) phase: RecoveryPhase,
    pub(crate) attempt_count: u8,
    pub(crate) identity_refresh_retry_count: u8,
    pub(crate) last_error: Option<String>,
    pub(crate) escalation_reason: Option<RecoveryEscalationReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryDiagnostics {
    pub conversation_id: String,
    pub recovery_status: RecoveryStatus,
    pub reason: RecoveryReason,
    pub phase: RecoveryPhase,
    pub attempt_count: u8,
    pub identity_refresh_retry_count: u8,
    pub pending_record_count: usize,
    pub pending_record_seqs: Vec<u64>,
    pub last_fetched_seq: u64,
    pub last_acked_seq: u64,
    pub mls_status: Option<MlsStateStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escalation_reason: Option<RecoveryEscalationReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

impl Default for CoreState {
    fn default() -> Self {
        Self {
            local_identity: None,
            local_bundle: None,
            deployment_bundle: None,
            contacts: BTreeMap::new(),
            conversations: BTreeMap::new(),
            sync_states: BTreeMap::new(),
            outbox: Vec::new(),
            pending_outbox: Vec::new(),
            pending_acks: BTreeMap::new(),
            pending_blob_uploads: BTreeMap::new(),
            pending_blob_downloads: BTreeMap::new(),
            realtime_sessions: BTreeMap::new(),
            mls_adapter: None,
            mls_summaries: BTreeMap::new(),
            published_key_package: None,
            pending_requests: BTreeMap::new(),
            request_nonce: 0,
            message_nonce: 0,
            recovery_contexts: BTreeMap::new(),
        }
    }
}

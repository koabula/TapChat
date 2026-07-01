use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::attachment_crypto::AttachmentPayloadMetadata;
use crate::conversation::LocalConversationState;
use crate::conversation::RecoveryStatus;
use crate::identity::LocalIdentityState;
use crate::mls_adapter::{MlsAdapter, PublishedKeyPackage};
use crate::model::{
    Ack, ConversationKind, DeploymentBundle, Envelope, GroupCursor, GroupEnvelope,
    GroupInviteDocument, GroupJoinRequest, GroupRole, IdentityBundle, InboxRecord, MessageType,
    MlsStateStatus, MlsStateSummary, WelcomePickupDescriptor,
};
use crate::persistence::{
    ContactRelationshipStatus, CorePersistenceSnapshot, PersistOp, PersistedContact,
    PersistedGroupInvite, PersistedGroupJoinRequest, PersistedPendingGroupJoinApproval,
    PersistedPendingWelcomePickup,
};
use crate::sync_engine::DeviceSyncState;
use crate::transport_contract::{
    AllowlistDocument, AppendDeliveryDisposition, AppendGroupEnvelopeRequest,
    AuthorizeBlobDownloadRequest, AuthorizeBlobDownloadResult, BlobDownloadRequest,
    BlobUploadRequest, CreateGroupInviteRequest, DecideGroupJoinRequest, FetchAllowlistRequest,
    FetchGroupInviteRequest, FetchGroupOutboxRequest, FetchIdentityBundleRequest,
    FetchMessageRequestsRequest, FetchWelcomePickupRequest, GetGroupJoinRequestStatusRequest,
    GetGroupOutboxHeadRequest, GroupRealtimeSubscriptionRequest, ListGroupJoinRequestsRequest,
    MessageRequestAction, MessageRequestActionRequest, MessageRequestActionResult,
    MessageRequestItem, MessageRequestRealtimeChange, PrepareBlobUploadRequest,
    PrepareBlobUploadResult, PublishSharedStateRequest, PutWelcomePickupRequest,
    RealtimeSubscriptionRequest, ReplaceAllowlistRequest, RevokeGroupInviteRequest,
    SealGroupOutboxRequest, SharedStateDocumentKind, SubmitGroupJoinRequest,
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
        display_name: Option<String>,
    },
    ImportDeploymentBundle {
        bundle: DeploymentBundle,
    },
    ImportIdentityBundle {
        bundle: IdentityBundle,
    },
    ImportIdentityBundleWithRelationshipStatus {
        bundle: IdentityBundle,
        relationship_status: ContactRelationshipStatus,
    },
    ApplyIdentityBundleUpdate {
        bundle: IdentityBundle,
    },
    CreateConversation {
        peer_user_id: String,
        conversation_kind: ConversationKind,
    },
    CreateGroupConversation {
        title: String,
        member_user_ids: Vec<String>,
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
    SyncGroupOutbox {
        group_id: String,
        reason: Option<String>,
    },
    ApplyGroupRealtimePlan {
        websocket_group_ids: Vec<String>,
    },
    SendGroupTextMessage {
        conversation_id: String,
        plaintext: String,
    },
    InviteToGroup {
        group_id: String,
        invitee_user_ids: Vec<String>,
    },
    AddGroupMemberDevice {
        group_id: String,
        user_id: String,
        device_id: String,
    },
    CreateGroupInviteLink {
        group_id: String,
        expires_at: u64,
        max_uses: Option<u64>,
    },
    RevokeGroupInviteLink {
        group_id: String,
        invite_id: String,
    },
    FetchGroupInvite {
        invite_url: String,
    },
    SubmitGroupJoinRequest {
        invite_url: String,
    },
    ListGroupJoinRequests {
        group_id: String,
    },
    GetGroupJoinRequestStatus {
        group_id: String,
        request_id: String,
    },
    RequestJoinGroup {
        invite_url: String,
    },
    RetryPendingWelcomePickups,
    ApproveGroupJoin {
        group_id: String,
        request_id: String,
    },
    RejectGroupJoin {
        group_id: String,
        request_id: String,
        reason: Option<String>,
    },
    LeaveGroup {
        group_id: String,
    },
    RemoveGroupMember {
        group_id: String,
        target_user_id: String,
    },
    RemoveGroupMemberDevice {
        group_id: String,
        user_id: String,
        device_id: String,
    },
    /// Phase 8: register a newly provisioned device in every group the
    /// local user belongs to. For each group where the caller holds an
    /// owner or admin role and the target device is not already present,
    /// the core issues an MLS External Add with a Welcome so the new
    /// device can decrypt future messages.
    SyncGroupsForNewDevice {
        device_id: String,
    },
    /// Phase 8: remove a revoked local device from every group the local
    /// user administers. Mirrors `SyncGroupsForNewDevice` but issues MLS
    /// removes for currently active group membership entries.
    SyncGroupsForRemovedDevice {
        device_id: String,
    },
    TransferGroupOwnership {
        group_id: String,
        new_owner_user_id: String,
    },
    SetGroupAdmin {
        group_id: String,
        target_user_id: String,
        is_admin: bool,
    },
    UpdateGroupMetadata {
        group_id: String,
        title: Option<String>,
        join_policy: Option<crate::model::GroupJoinPolicy>,
        member_invite_policy: Option<crate::model::GroupMemberInvitePolicy>,
    },
    DissolveGroup {
        group_id: String,
    },
    RefreshIdentityState {
        user_id: String,
    },
    ListMessageRequests,
    ActOnMessageRequest {
        request_id: String,
        action: MessageRequestAction,
    },
    ListAllowlist,
    AddAllowlistUser {
        user_id: String,
    },
    RemoveAllowlistUser {
        user_id: String,
    },
    CreateAdditionalDeviceIdentity {
        mnemonic: Option<String>,
        device_name: Option<String>,
        display_name: Option<String>,
    },
    RotateLocalKeyPackage,
    ApplyLocalDeviceStatusUpdate {
        status: crate::model::DeviceStatusKind,
    },
    UpdateLocalDeviceStatus {
        target_device_id: String,
        status: crate::model::DeviceStatusKind,
    },
    RotateContactShareLink,
    RebuildConversation {
        conversation_id: String,
    },
    SetLocalDisplayName {
        display_name: Option<String>,
    },
    SetContactDisplayName {
        user_id: String,
        display_name: Option<String>,
    },
    DeleteContact {
        user_id: String,
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
    MessageRequestsFetched {
        requests: Vec<MessageRequestItem>,
    },
    MessageRequestsFetchFailed {
        retryable: bool,
        detail: Option<String>,
    },
    MessageRequestActionCompleted {
        result: MessageRequestActionResult,
    },
    MessageRequestActionFailed {
        request_id: String,
        action: MessageRequestAction,
        retryable: bool,
        detail: Option<String>,
    },
    AllowlistFetched {
        document: AllowlistDocument,
    },
    AllowlistFetchFailed {
        retryable: bool,
        detail: Option<String>,
    },
    AllowlistReplaced {
        document: AllowlistDocument,
    },
    AllowlistReplaceFailed {
        retryable: bool,
        detail: Option<String>,
    },
    SharedStatePublished {
        document_kind: SharedStateDocumentKind,
        reference: String,
    },
    SharedStatePublishFailed {
        document_kind: SharedStateDocumentKind,
        reference: String,
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
    BlobDownloadAuthorized {
        task_id: String,
        result: AuthorizeBlobDownloadResult,
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
    GroupOutboxFetched {
        group_id: String,
        records: Vec<crate::model::GroupOutboxRecord>,
        to_seq: u64,
    },
    GroupOutboxFetchFailed {
        group_id: String,
        retryable: bool,
        detail: Option<String>,
    },
    GroupOutboxHeadFetched {
        group_id: String,
        head_seq: u64,
    },
    GroupOutboxHeadFetchFailed {
        group_id: String,
        retryable: bool,
        detail: Option<String>,
    },
    GroupEnvelopeAppended {
        group_id: String,
        message_id: String,
        seq: u64,
    },
    GroupEnvelopeAppendFailed {
        group_id: String,
        message_id: String,
        retryable: bool,
        detail: Option<String>,
    },
    GroupOutboxSealed {
        group_id: String,
        sealed_at: u64,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        was_already_sealed: bool,
    },
    GroupOutboxSealFailed {
        group_id: String,
        retryable: bool,
        status: Option<u16>,
        code: Option<String>,
        detail: Option<String>,
    },
    WelcomePickupFetched {
        descriptor: crate::model::WelcomePickupDescriptor,
        welcome_b64: String,
        manifest: Option<crate::model::GroupManifest>,
    },
    WelcomePickupFetchFailed {
        descriptor: crate::model::WelcomePickupDescriptor,
        retryable: bool,
        detail: Option<String>,
    },
    WelcomePickupPut {
        descriptor: crate::model::WelcomePickupDescriptor,
    },
    WelcomePickupPutFailed {
        descriptor: crate::model::WelcomePickupDescriptor,
        retryable: bool,
        detail: Option<String>,
    },
    GroupInviteCreated {
        invite_url: String,
        invite: GroupInviteDocument,
    },
    GroupInviteCreateFailed {
        group_id: String,
        retryable: bool,
        detail: Option<String>,
    },
    GroupInviteFetched {
        invite_url: String,
        invite: GroupInviteDocument,
    },
    GroupInviteFetchFailed {
        invite_url: String,
        retryable: bool,
        detail: Option<String>,
    },
    GroupInviteRevoked {
        group_id: String,
        invite_id: String,
    },
    GroupJoinRequestSubmitted {
        request: GroupJoinRequest,
    },
    GroupJoinRequestSubmitFailed {
        invite_url: String,
        retryable: bool,
        detail: Option<String>,
    },
    GroupJoinRequestsListed {
        group_id: String,
        requests: Vec<GroupJoinRequest>,
    },
    GroupJoinRequestStatusFetched {
        request: GroupJoinRequest,
        welcome_pickup: Option<WelcomePickupDescriptor>,
        manifest: Option<crate::model::GroupManifest>,
        start_cursor: Option<GroupCursor>,
    },
    GroupJoinDecisionApplied {
        request: GroupJoinRequest,
    },
    GroupJoinDecisionFailed {
        group_id: String,
        request_id: String,
        retryable: bool,
        detail: Option<String>,
    },
    GroupWebSocketConnected {
        group_id: String,
    },
    GroupWebSocketDisconnected {
        group_id: String,
        error: Option<String>,
    },
    GroupRealtimeEventReceived {
        group_id: String,
        event: RealtimeEvent,
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
    MessageRequestChanged {
        sender_user_id: String,
        request_id: String,
        change: MessageRequestRealtimeChange,
    },
    GroupHeadUpdated {
        group_id: String,
        seq: u64,
    },
    GroupOutboxRecordAvailable {
        group_id: String,
        seq: u64,
        record: Option<crate::model::GroupOutboxRecord>,
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
    // Platform-defined attachment handle. It may be a path-like string in the CLI,
    // but core treats it as an opaque identifier owned by BlobIoPort.
    pub attachment_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteDownloadedAttachmentEffect {
    pub task_id: String,
    // Platform-defined destination handle. The CLI currently resolves it to a file path,
    // but core only promises an opaque identifier for BlobIoPort to interpret.
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
    OpenGroupRealtimeConnection {
        subscription: GroupRealtimeSubscriptionRequest,
    },
    CloseGroupRealtimeConnection {
        group_id: String,
    },
    CloseRealtimeConnection {
        device_id: String,
    },
    AppendGroupEnvelope {
        append: AppendGroupEnvelopeRequest,
    },
    FetchGroupOutbox {
        fetch: FetchGroupOutboxRequest,
    },
    GetGroupOutboxHead {
        get: GetGroupOutboxHeadRequest,
    },
    SealGroupOutbox {
        seal: SealGroupOutboxRequest,
    },
    FetchWelcomePickup {
        fetch: FetchWelcomePickupRequest,
    },
    PutWelcomePickup {
        put: PutWelcomePickupRequest,
    },
    CreateGroupInvite {
        create: CreateGroupInviteRequest,
    },
    RevokeGroupInvite {
        revoke: RevokeGroupInviteRequest,
    },
    FetchGroupInvite {
        fetch: FetchGroupInviteRequest,
    },
    SubmitGroupJoinRequest {
        submit: SubmitGroupJoinRequest,
    },
    ListGroupJoinRequests {
        list: ListGroupJoinRequestsRequest,
    },
    GetGroupJoinRequestStatus {
        get: GetGroupJoinRequestStatusRequest,
    },
    DecideGroupJoinRequest {
        decide: DecideGroupJoinRequest,
    },
    FetchIdentityBundle {
        fetch: FetchIdentityBundleRequest,
    },
    FetchMessageRequests {
        fetch: FetchMessageRequestsRequest,
    },
    ActOnMessageRequest {
        action: MessageRequestActionRequest,
    },
    FetchAllowlist {
        fetch: FetchAllowlistRequest,
    },
    ReplaceAllowlist {
        update: ReplaceAllowlistRequest,
    },
    PublishSharedState {
        publish: PublishSharedStateRequest,
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
    AuthorizeBlobDownload {
        authorize: AuthorizeBlobDownloadRequest,
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
    MessageQueuedForApproval,
    MessageRejectedByPolicy,
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
    pub identity_changed: bool,
    #[serde(default)]
    pub checkpoints_changed: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub system_statuses_changed: Vec<SystemStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationSummary {
    pub conversation_id: String,
    pub peer_user_id: String,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<ConversationKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_role: Option<GroupRole>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_cursor: Option<GroupCursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_message_preview: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_message_type: Option<MessageType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_count: Option<usize>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub device_count: usize,
    #[serde(default)]
    pub relationship_status: ContactRelationshipStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalIdentitySummary {
    pub user_id: String,
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemBanner {
    pub status: SystemStatus,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageRequestActionSummary {
    pub accepted: bool,
    pub request_id: String,
    pub sender_user_id: String,
    pub promoted_count: u64,
    pub action: MessageRequestAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppendResultSummary {
    pub accepted: bool,
    pub delivered_to: AppendDeliveryDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued_as_request: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
}

/// Result of a single failed group operation within a batch sync.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupSyncError {
    pub group_id: String,
    pub error: String,
}

/// Summary produced by group device batch sync commands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupSyncResults {
    pub device_id: String,
    pub total_candidates: u64,
    pub succeeded: u64,
    pub skipped: u64,
    pub errors: Vec<GroupSyncError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CoreViewModel {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conversations: Vec<ConversationSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub messages: Vec<MessageSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contacts: Vec<ContactSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<LocalIdentitySummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub banners: Vec<SystemBanner>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub message_requests: Vec<MessageRequestItem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowlist: Option<AllowlistDocument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_request_action: Option<MessageRequestActionSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub append_result: Option<AppendResultSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub group_invites: Vec<PersistedGroupInvite>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub group_join_requests: Vec<GroupJoinRequest>,
    /// Welcome pickup descriptors produced by the most recent command.
    ///
    /// Populated when the owner/admin creates a group or approves a join
    /// request; the invitee(s) need these descriptors out-of-band to fetch
    /// the MLS welcome from the server. The descriptors are intentionally
    /// scoped to a single `(group_id, device_id)` pair and capabilities are
    /// short-lived.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub welcome_pickups: Vec<crate::model::WelcomePickupDescriptor>,
    /// Result summary for `SyncGroupsForNewDevice` batch operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_sync_results: Option<GroupSyncResults>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) plaintext_cache: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PendingGroupOutboxItem {
    pub(crate) envelope: GroupEnvelope,
    pub(crate) capability: crate::model::GroupCapability,
    pub(crate) retries: u8,
    pub(crate) in_flight: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) plaintext_cache: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) group_id: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) authorized_download: Option<AuthorizeBlobDownloadResult>,
    pub(crate) retries: u8,
    pub(crate) in_flight: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RealtimeSessionState {
    pub(crate) connected: bool,
    pub(crate) last_known_seq: u64,
    pub(crate) needs_reconnect: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GroupRealtimeSessionState {
    pub(crate) connected: bool,
    pub(crate) last_known_seq: u64,
    pub(crate) needs_reconnect: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum PendingAllowlistMutation {
    Add { user_id: String },
    Remove { user_id: String },
    RemoveMany { user_ids: Vec<String> },
}

#[derive(Debug)]
pub(crate) struct CoreState {
    pub(crate) local_identity: Option<LocalIdentityState>,
    pub(crate) local_bundle: Option<IdentityBundle>,
    pub(crate) deployment_bundle: Option<DeploymentBundle>,
    pub(crate) contacts: BTreeMap<String, PersistedContact>,
    pub(crate) conversations: BTreeMap<String, LocalConversationState>,
    pub(crate) sync_states: BTreeMap<String, DeviceSyncState>,
    pub(crate) outbox: Vec<Envelope>,
    pub(crate) pending_outbox: Vec<PendingOutboxItem>,
    pub(crate) group_states: BTreeMap<String, crate::persistence::PersistedGroupState>,
    pub(crate) group_cursors: BTreeMap<String, GroupCursor>,
    pub(crate) pending_group_outbox: Vec<PendingGroupOutboxItem>,
    pub(crate) group_invites: BTreeMap<String, PersistedGroupInvite>,
    pub(crate) group_join_requests: BTreeMap<String, PersistedGroupJoinRequest>,
    pub(crate) pending_group_join_approvals: BTreeMap<String, PersistedPendingGroupJoinApproval>,
    pub(crate) pending_welcome_pickups: BTreeMap<String, PersistedPendingWelcomePickup>,
    /// In-memory staging for owner-signed `SealGroupOutbox` requests.
    ///
    /// Keyed by `group_id`. An entry is inserted when
    /// `dissolve_group` finishes step (a)+(b) (MLS remove_members commit
    /// and `control_group_dissolved` control message enqueued). The entry
    /// is consumed into a real `CoreEffect::SealGroupOutbox` by
    /// `handle_group_envelope_appended` once every pending_group_outbox
    /// entry belonging to that group has been acknowledged — i.e. step (c)
    /// only runs after steps (a)+(b) succeed, in line with the four-step
    /// atomic contract in `design.md` (Dissolve-group decision section).
    ///
    /// Not persisted: if the process dies between the commit and the seal
    /// the owner's next `DissolveGroup` call re-enqueues the pending seal.
    /// The MLS commit itself is persisted via `pending_group_outbox` and is
    /// replayed normally on startup.
    pub(crate) pending_group_seal:
        BTreeMap<String, crate::transport_contract::SealGroupOutboxRequest>,
    pub(crate) pending_acks: BTreeMap<String, PendingAckState>,
    pub(crate) pending_blob_uploads: BTreeMap<String, PendingBlobUpload>,
    pub(crate) pending_blob_downloads: BTreeMap<String, PendingBlobDownload>,
    pub(crate) realtime_sessions: BTreeMap<String, RealtimeSessionState>,
    pub(crate) group_realtime_sessions: BTreeMap<String, GroupRealtimeSessionState>,
    pub(crate) mls_adapter: Option<MlsAdapter>,
    pub(crate) mls_summaries: BTreeMap<String, MlsStateSummary>,
    pub(crate) published_key_package: Option<PublishedKeyPackage>,
    pub(crate) pending_requests: BTreeMap<String, PendingRequest>,
    pub(crate) request_nonce: u64,
    pub(crate) message_nonce: u64,
    pub(crate) recovery_contexts: BTreeMap<String, RecoveryContext>,
    pub(crate) pending_allowlist_mutation: Option<PendingAllowlistMutation>,
    pub(crate) local_display_name: Option<String>,
    /// Set of group_ids that are waiting for a head response to trigger a sync fetch.
    /// When the head response arrives, handle_group_outbox_head_fetched checks this set
    /// to decide whether to fetch records (sync path) or skip ahead (welcome pickup path).
    pub(crate) pending_sync_group_head: BTreeSet<String>,
    /// The target head_seq for an in-progress group sync fetch loop.
    /// When handle_group_outbox_records finishes a batch with to_seq < target_head_seq,
    /// it continues fetching from to_seq+1 until caught up.
    pub(crate) group_sync_target_head: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
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
    AppendGroupEnvelope {
        group_id: String,
        message_id: String,
    },
    FetchGroupOutbox {
        group_id: String,
        from_seq: u64,
        limit: u64,
    },
    PutWelcomePickup {
        group_id: String,
        device_id: String,
    },
    FetchWelcomePickup {
        group_id: String,
        device_id: String,
    },
    CreateGroupInvite {
        group_id: String,
        invite_id: String,
    },
    SubmitGroupJoinRequest {
        group_id: String,
        request_id: String,
        invite_url: String,
    },
    DecideGroupJoinRequest {
        group_id: String,
        request_id: String,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) restore_failure_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) restore_failure_detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) restore_recoverable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) suggested_action: Option<String>,
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
    #[serde(default)]
    pub recoverable: bool,
    #[serde(default)]
    pub suggested_action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restore_failure_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restore_failure_detail: Option<String>,
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
            group_states: BTreeMap::new(),
            group_cursors: BTreeMap::new(),
            pending_group_outbox: Vec::new(),
            group_invites: BTreeMap::new(),
            group_join_requests: BTreeMap::new(),
            pending_group_join_approvals: BTreeMap::new(),
            pending_welcome_pickups: BTreeMap::new(),
            pending_group_seal: BTreeMap::new(),
            pending_acks: BTreeMap::new(),
            pending_blob_uploads: BTreeMap::new(),
            pending_blob_downloads: BTreeMap::new(),
            realtime_sessions: BTreeMap::new(),
            group_realtime_sessions: BTreeMap::new(),
            mls_adapter: None,
            mls_summaries: BTreeMap::new(),
            published_key_package: None,
            pending_requests: BTreeMap::new(),
            request_nonce: 0,
            message_nonce: 0,
            recovery_contexts: BTreeMap::new(),
            pending_allowlist_mutation: None,
            local_display_name: None,
            pending_sync_group_head: BTreeSet::new(),
            group_sync_target_head: BTreeMap::new(),
        }
    }
}

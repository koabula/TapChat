export const CURRENT_MODEL_VERSION = "0.1";

export interface SenderProof {
  type: string;
  value: string;
}

export interface StorageRef {
  kind: string;
  ref: string;
  sizeBytes: number;
  mimeType: string;
  fileName?: string;
  expiresAt?: number;
}

export interface WakeHint {
  latestSeqHint?: number;
}

export interface CapabilityConstraints {
  maxBytes?: number;
  maxOpsPerMinute?: number;
  maxOpsPerHour?: number;
}

export type MessageType =
  | "mls_application"
  | "mls_commit"
  | "mls_welcome"
  | "control_device_membership_changed"
  | "control_identity_state_updated"
  | "control_conversation_needs_rebuild";

export interface Envelope {
  version: string;
  messageId: string;
  conversationId: string;
  senderUserId: string;
  senderDeviceId: string;
  recipientDeviceId: string;
  createdAt: number;
  messageType: MessageType;
  inlineCiphertext?: string;
  storageRefs?: StorageRef[];
  deliveryClass: "normal";
  wakeHint?: WakeHint;
  senderProof: SenderProof;
}

export interface InboxRecord {
  seq: number;
  recipientDeviceId: string;
  messageId: string;
  receivedAt: number;
  expiresAt?: number;
  state: "available";
  envelope: Envelope;
}

export type GroupRole = "owner" | "admin" | "member";
export type GroupMemberStatus = "active" | "pending" | "removed" | "left";
export type GroupJoinPolicy = "closed" | "approval_required" | "open_by_invite";
export type GroupMemberInvitePolicy = "owner_admin_only" | "request_owner_approval";

export interface GroupMember {
  userId: string;
  role: GroupRole;
  status: GroupMemberStatus;
}

export interface GroupOutboxDescriptor {
  endpoint: string;
  subscribeEndpoint?: string;
}

export interface GroupManifest {
  version: string;
  groupId: string;
  conversationId: string;
  title: string;
  ownerUserId: string;
  admins: string[];
  members: GroupMember[];
  joinPolicy: GroupJoinPolicy;
  memberInvitePolicy: GroupMemberInvitePolicy;
  rosterVersion: number;
  mlsEpochHint: number;
  lastCommitMessageId?: string;
  outbox: GroupOutboxDescriptor;
  updatedAt: number;
  signerUserId: string;
  signerDeviceId: string;
  signature: string;
}

export type GroupCapabilityOperation =
  | "read"
  | "subscribe"
  | "append_application"
  | "append_control"
  | "append_membership"
  | "manage_invites"
  | "approve_join"
  | "remove_member"
  | "update_group_metadata";

export interface GroupCapability {
  version: string;
  service: "group_outbox";
  groupId: string;
  userId: string;
  deviceId: string;
  operations: GroupCapabilityOperation[];
  role: GroupRole;
  expiresAt: number;
  signature: string;
}

export type GroupMessageType =
  | "mls_application"
  | "mls_commit"
  | "control_group_membership_changed"
  | "control_group_metadata_updated"
  | "control_group_join_requested"
  | "control_group_join_approved"
  | "control_group_join_rejected"
  | "control_group_leave_requested"
  | "control_conversation_needs_rebuild";

export type GroupEnvelopeVisibility = "visible" | "protocol";

export interface GroupEnvelope {
  version: string;
  messageId: string;
  groupId: string;
  conversationId: string;
  senderUserId: string;
  senderDeviceId: string;
  createdAt: number;
  messageType: GroupMessageType;
  visibility: GroupEnvelopeVisibility;
  inlineCiphertext?: string;
  storageRefs?: StorageRef[];
  senderProof: SenderProof;
  membershipProof?: SenderProof;
}

export interface GroupOutboxRecord {
  seq: number;
  groupId: string;
  messageId: string;
  receivedAt: number;
  expiresAt?: number;
  state: "available";
  envelope: GroupEnvelope;
}

export interface GroupCursor {
  groupId: string;
  lastFetchedSeq: number;
  updatedAt: number;
}

export interface WelcomePickupDescriptor {
  groupId: string;
  deviceId: string;
  endpoint: string;
  capability: string;
  expiresAt: number;
}

export interface AppendGroupEnvelopeRequest {
  version: string;
  groupId: string;
  envelope: GroupEnvelope;
  capability: GroupCapability;
}

export interface AppendGroupEnvelopeResult {
  accepted: boolean;
  seq: number;
}

export interface FetchGroupOutboxRequest {
  groupId: string;
  fromSeq: number;
  limit: number;
  capability: GroupCapability;
}

export interface FetchGroupOutboxResult {
  toSeq: number;
  records: GroupOutboxRecord[];
}

export interface GetGroupOutboxHeadResult {
  headSeq: number;
}

export interface GetGroupOutboxHeadRequest {
  groupId: string;
  capability: GroupCapability;
}

export interface GroupRealtimeSubscriptionRequest {
  groupId: string;
  endpoint: string;
  lastSeq: number;
  capability: GroupCapability;
  headers?: Record<string, string>;
}

export interface FetchWelcomePickupRequest {
  descriptor: WelcomePickupDescriptor;
  headers?: Record<string, string>;
}

export interface FetchWelcomePickupResult {
  welcomeB64: string;
  manifest?: GroupManifest;
}

export interface PutWelcomePickupRequest {
  descriptor: WelcomePickupDescriptor;
  welcomeB64: string;
  manifest?: GroupManifest;
  headers?: Record<string, string>;
}

export interface PutWelcomePickupResult {
  accepted: boolean;
}

export type GroupInviteService = "group_invite";

export interface GroupInviteTokenPayload {
  version: string;
  service: GroupInviteService;
  groupId: string;
  inviteId: string;
  inviterUserId: string;
  inviterDeviceId: string;
  joinPolicy: GroupJoinPolicy;
  expiresAt: number;
  maxUses?: number;
}

export interface GroupInviteDocument {
  version: string;
  groupId: string;
  title: string;
  inviteId: string;
  joinPolicy: GroupJoinPolicy;
  inviterUserId: string;
  inviterDeviceId: string;
  inviterContactShareUrl?: string;
  ownerUserId: string;
  ownerContactShareUrl?: string;
  joinRequestEndpoint: string;
  createdAt: number;
  expiresAt: number;
  maxUses?: number;
  signature: string;
}

export type GroupJoinRequestStatus = "pending" | "approved" | "rejected" | "expired" | "revoked";

export interface GroupJoinRequest {
  version: string;
  requestId: string;
  groupId: string;
  inviteId: string;
  joinerUserId: string;
  joinerDeviceId: string;
  joinerContactShareUrl: string;
  requestedAt: number;
  requestCapability: string;
  signature: string;
  status: GroupJoinRequestStatus;
  autoApprove?: boolean;
}

export interface CreateGroupInviteRequest {
  version: string;
  groupId: string;
  document: GroupInviteDocument;
  capability: GroupCapability;
  maxUses?: number;
}

export interface CreateGroupInviteResult {
  inviteUrl: string;
  invite: GroupInviteDocument;
}

export interface RevokeGroupInviteRequest {
  version: string;
  groupId: string;
  inviteId: string;
  capability: GroupCapability;
}

export interface RevokeGroupInviteResult {
  accepted: boolean;
  inviteId: string;
}

export interface FetchGroupInviteResult {
  invite: GroupInviteDocument;
}

export interface SubmitGroupJoinRequest {
  version: string;
  inviteToken: string;
  request: GroupJoinRequest;
}

export interface SubmitGroupJoinResult {
  accepted: boolean;
  request: GroupJoinRequest;
  autoApprove?: boolean;
}

export interface ListGroupJoinRequestsResult {
  requests: GroupJoinRequest[];
}

export interface GetGroupJoinRequestStatusResult {
  request: GroupJoinRequest;
  welcomePickup?: WelcomePickupDescriptor;
  manifest?: GroupManifest;
  startCursor?: GroupCursor;
}

export type GroupJoinDecision = "approve" | "reject";

export interface DecideGroupJoinRequest {
  version: string;
  groupId: string;
  requestId: string;
  decision: GroupJoinDecision;
  capability: GroupCapability;
  welcomePickup?: WelcomePickupDescriptor;
  manifest?: GroupManifest;
  startCursor?: GroupCursor;
  reason?: string;
}

export interface DecideGroupJoinResult {
  accepted: boolean;
  request: GroupJoinRequest;
}

export interface Ack {
  deviceId: string;
  ackSeq: number;
  ackedMessageIds?: string[];
  ackedAt: number;
}

export interface AppendEnvelopeRequest {
  version: string;
  recipientDeviceId: string;
  envelope: Envelope;
  senderBundleShareUrl?: string;
  senderBundleHash?: string;
  senderDisplayName?: string;
}

export interface AppendEnvelopeResult {
  accepted: boolean;
  seq: number;
  deliveredTo: "inbox" | "message_request" | "rejected";
  queuedAsRequest?: boolean;
  requestId?: string;
}

export interface FetchMessagesRequest {
  deviceId: string;
  fromSeq: number;
  limit: number;
}

export interface FetchMessagesResult {
  toSeq: number;
  records: InboxRecord[];
}

export interface AckRequest {
  ack: Ack;
}

export interface AckResult {
  accepted: boolean;
  ackSeq: number;
}

export interface GetHeadResult {
  headSeq: number;
}

export interface PrepareBlobUploadRequest {
  taskId: string;
  conversationId: string;
  groupId?: string;
  storageScope?: "direct" | "group";
  messageId: string;
  mimeType: string;
  sizeBytes: number;
  fileName?: string;
}

export interface PrepareBlobUploadResult {
  blobRef: string;
  uploadTarget: string;
  uploadHeaders: Record<string, string>;
  downloadTarget?: string;
  expiresAt?: number;
}

export interface StorageBaseInfo {
  baseUrl?: string;
  bucketHint?: string;
}

export interface DeviceRuntimeAuth {
  scheme: "bearer";
  token: string;
  expiresAt: number;
  userId: string;
  deviceId: string;
  scopes: DeviceRuntimeScope[];
}

export type DeviceRuntimeScope =
  | "inbox_read"
  | "inbox_ack"
  | "inbox_subscribe"
  | "inbox_manage"
  | "storage_prepare_upload"
  | "shared_state_write"
  | "keypackage_write";

export interface RuntimeConfig {
  supportedRealtimeKinds: Array<"websocket" | "server_sent_events" | "polling">;
  identityBundleRef?: string;
  deviceStatusRef?: string;
  keypackageRefBase?: string;
  maxInlineBytes?: number;
  features: string[];
}

export interface DeploymentBundle {
  version: string;
  region: string;
  inboxHttpEndpoint: string;
  inboxWebsocketEndpoint: string;
  storageBaseInfo: StorageBaseInfo;
  runtimeConfig: RuntimeConfig;
  deviceRuntimeAuth?: DeviceRuntimeAuth;
  expectedUserId?: string;
  expectedDeviceId?: string;
}

export interface InboxAppendCapability {
  version: string;
  service: "inbox";
  userId: string;
  targetDeviceId: string;
  endpoint: string;
  operations: string[];
  conversationScope?: string[];
  expiresAt: number;
  constraints?: CapabilityConstraints;
  signature: string;
}

export interface DeviceBinding {
  version: string;
  userId: string;
  deviceId: string;
  devicePublicKey: string;
  createdAt: number;
  signature: string;
}

export type DeviceStatusKind = "active" | "revoked";

export interface KeyPackageRef {
  version: string;
  userId: string;
  deviceId: string;
  ref: string;
  expiresAt: number;
}

export interface DeviceContactProfile {
  version: string;
  deviceId: string;
  devicePublicKey: string;
  binding: DeviceBinding;
  status: DeviceStatusKind;
  inboxAppendCapability: InboxAppendCapability;
  keypackageRef: KeyPackageRef;
}

export interface StorageProfile {
  baseUrl?: string;
  profileRef?: string;
}

export interface IdentityBundle {
  version: string;
  userId: string;
  userPublicKey: string;
  devices: DeviceContactProfile[];
  bundleShareId?: string;
  identityBundleRef?: string;
  deviceStatusRef?: string;
  storageProfile?: StorageProfile;
  updatedAt: number;
  signature: string;
}

export interface DeviceStatusRecord {
  version: string;
  userId: string;
  deviceId: string;
  status: DeviceStatusKind;
  updatedAt: number;
}

export interface DeviceListEntry {
  deviceId: string;
  status: DeviceStatusKind;
}

export interface DeviceListDocument {
  version: string;
  userId: string;
  updatedAt: number;
  devices: DeviceListEntry[];
}

export interface DeviceStatusDocument {
  version: string;
  userId: string;
  updatedAt: number;
  devices: DeviceStatusRecord[];
}

export interface KeyPackageRefEntry {
  keyPackageId: string;
  ref: string;
  expiresAt: number;
  createdAt: number;
}

export interface KeyPackageRefsDocument {
  version: string;
  userId: string;
  deviceId: string;
  updatedAt: number;
  refs: KeyPackageRefEntry[];
}

export interface SharedStateWriteToken {
  version: string;
  service: "shared_state";
  userId: string;
  objectKinds: Array<"identity_bundle" | "device_status">;
  expiresAt: number;
}

export interface KeyPackageWriteToken {
  version: string;
  service: "keypackages";
  userId: string;
  deviceId: string;
  keyPackageId?: string;
  expiresAt: number;
}

export interface BootstrapDeviceRequest {
  version: string;
  userId: string;
  deviceId: string;
}

export interface BootstrapToken {
  version: string;
  service: "bootstrap";
  userId: string;
  deviceId: string;
  operations: Array<"issue_device_bundle">;
  expiresAt: number;
}

export interface DeviceRuntimeToken {
  version: string;
  service: "device_runtime";
  userId: string;
  deviceId: string;
  scopes: DeviceRuntimeScope[];
  expiresAt: number;
}

export interface RealtimeEvent {
  event: "head_updated" | "inbox_record_available" | "message_request_changed";
  deviceId: string;
  seq?: number;
  record?: InboxRecord;
  senderUserId?: string;
  requestId?: string;
  change?: "queued" | "accepted" | "rejected";
}

export interface AllowlistDocument {
  version: string;
  deviceId: string;
  updatedAt: number;
  allowedSenderUserIds: string[];
  rejectedSenderUserIds: string[];
}

export interface MessageRequestItem {
  requestId: string;
  recipientDeviceId: string;
  senderUserId: string;
  senderBundleShareUrl?: string;
  senderBundleHash?: string;
  senderDisplayName?: string;
  firstSeenAt: number;
  lastSeenAt: number;
  messageCount: number;
  lastMessageId: string;
  lastConversationId: string;
}

export interface MessageRequestListResult {
  requests: MessageRequestItem[];
}

export interface MessageRequestActionResult {
  accepted: boolean;
  requestId: string;
  senderUserId: string;
  senderBundleShareUrl?: string;
  senderBundleHash?: string;
  senderDisplayName?: string;
  promotedCount?: number;
}



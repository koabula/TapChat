// Types matching Rust backend

// Core output
export interface CoreOutput {
  state_update: CoreStateUpdate;
  effects: CoreEffect[];
  view_model?: CoreViewModel;
}

export interface CoreStateUpdate {
  conversations_changed: boolean;
  messages_changed: boolean;
  contacts_changed: boolean;
  checkpoints_changed: boolean;
  system_statuses_changed: SystemStatus[];
}

export interface CoreViewModel {
  conversations: ConversationSummary[];
  messages: MessageSummary[];
  contacts: ContactSummary[];
  banners: SystemBanner[];
  message_requests: MessageRequestItem[];
  allowlist?: AllowlistDocument;
}

// Identity - matches backend IdentityInfo struct
export interface IdentityInfo {
  user_id: string;
  device_id: string;
  mnemonic: string;
  display_name?: string;
}

// Profiles - matches backend ProfileSummary struct
export interface ProfileSummary {
  name: string;
  path: string;
  is_active: boolean;
  user_id: string | null;
  device_id: string | null;
  runtime_bound: boolean | null;
}

// Conversations
export interface ConversationSummary {
  conversation_id: string;
  peer_user_id: string;
  state: string;
  kind?: "direct" | "group";
  title?: string | null;
  group_id?: string | null;
  member_count?: number | null;
  group_role?: GroupRole | null;
  group_cursor?: GroupCursor | null;
  last_message_preview?: string | null;
  last_message_type?: string;
  message_count?: number;
  recovery?: RecoveryDiagnostics;
}

export interface MessageSummary {
  conversation_id: string;
  message_id: string;
  message_type: string;
}

// Storage reference for attachments - matches Rust StorageRef
export interface StorageRef {
  kind: string;
  ref: string;        // object_ref in Rust, renamed for JSON compatibility
  size_bytes: number;
  mime_type: string;
  file_name?: string; // original file name
  expires_at?: number;
}

export type GroupRole = "owner" | "admin" | "member";
export type GroupMemberStatus = "active" | "pending" | "removed" | "left";
export type GroupJoinPolicy = "closed" | "approval_required" | "open_by_invite";
export type GroupMemberInvitePolicy = "owner_admin_only" | "request_owner_approval";

export interface GroupMember {
  user_id: string;
  role: GroupRole;
  status: GroupMemberStatus;
}

export interface GroupOutboxDescriptor {
  endpoint: string;
  subscribe_endpoint?: string;
}

export interface GroupManifest {
  version: string;
  group_id: string;
  conversation_id: string;
  title: string;
  owner_user_id: string;
  admins: string[];
  members: GroupMember[];
  join_policy: GroupJoinPolicy;
  member_invite_policy: GroupMemberInvitePolicy;
  roster_version: number;
  mls_epoch_hint: number;
  last_commit_message_id?: string;
  outbox: GroupOutboxDescriptor;
  updated_at: number;
  signer_user_id: string;
  signer_device_id: string;
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
  | "update_group_metadata"
  | "seal_group";

export interface GroupCapability {
  version: string;
  service: "group_outbox";
  group_id: string;
  user_id: string;
  device_id: string;
  operations: GroupCapabilityOperation[];
  role: GroupRole;
  expires_at: number;
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
  | "control_group_dissolved"
  | "control_conversation_needs_rebuild";

export type GroupEnvelopeVisibility = "visible" | "protocol";

export interface GroupEnvelope {
  version: string;
  message_id: string;
  group_id: string;
  conversation_id: string;
  sender_user_id: string;
  sender_device_id: string;
  created_at: number;
  message_type: GroupMessageType;
  visibility: GroupEnvelopeVisibility;
  inline_ciphertext?: string;
  storage_refs?: StorageRef[];
  sender_proof: SenderProof;
  membership_proof?: SenderProof;
}

export interface GroupOutboxRecord {
  seq: number;
  group_id: string;
  message_id: string;
  received_at: number;
  expires_at?: number;
  state: "available";
  envelope: GroupEnvelope;
}

export interface GroupCursor {
  group_id: string;
  last_fetched_seq: number;
  updated_at: number;
}

export interface WelcomePickupDescriptor {
  group_id: string;
  device_id: string;
  endpoint: string;
  capability: string;
  expires_at: number;
}

export interface GroupCommandResultSummary {
  group_id?: string;
  conversation_id?: string;
  accepted: boolean;
  status: "unsupported" | "pending" | "accepted";
}

export interface SenderProof {
  type: string;
  value: string;
}

// Messages - matches backend get_messages response
export interface Message {
  message_id: string;
  sender_device_id: string;
  recipient_device_id: string;
  message_type: string; // "sent" | "received" | "control"
  created_at: number;
  plaintext: string | null;
  has_attachment: boolean;
  storage_refs?: StorageRef[]; // attachment references with full metadata
}

// Contacts - matches backend ContactSummary
export interface ContactSummary {
  user_id: string;
  device_count: number;
  display_name?: string | null;
}

// Message Requests
export interface MessageRequestItem {
  request_id: string;
  recipient_device_id: string;
  sender_user_id: string;
  sender_bundle_share_url?: string;
  sender_bundle_hash?: string;
  sender_display_name?: string;
  first_seen_at: number;
  last_seen_at: number;
  message_count: number;
  last_message_id: string;
  last_conversation_id: string;
  request_kind?: "direct" | "group_invite";
  group_id?: string;
  group_title?: string;
}

// Message Request Action Output (matches Rust MessageRequestActionOutput)
export interface MessageRequestActionOutput {
  accepted: boolean;
  request_id: string;
  sender_user_id: string;
  action: string;
  contact_available: boolean;
  conversation_available: boolean;
  auto_created_conversation: boolean;
  conversation_id?: string;
}

// Allowlist
export interface AllowlistDocument {
  allowed_sender_user_ids: string[];
  rejected_sender_user_ids: string[];
}

// System status
export type SystemStatus =
  | "sync_in_progress"
  | "identity_refresh_needed"
  | "conversation_needs_rebuild"
  | "attachment_upload_failed"
  | "temporary_network_failure"
  | "message_queued_for_approval"
  | "message_rejected_by_policy";

export interface SystemBanner {
  status: SystemStatus;
  message: string;
}

// Recovery
export interface RecoveryDiagnostics {
  conversation_id: string;
  recovery_status: string;
  reason: RecoveryReason;
  phase: RecoveryPhase;
  attempt_count: number;
  identity_refresh_retry_count: number;
  pending_record_count: number;
  pending_record_seqs: number[];
  last_fetched_seq: number;
  last_acked_seq: number;
  mls_status?: string;
  escalation_reason?: RecoveryEscalationReason;
  last_error?: string;
}

export type RecoveryReason =
  | "missing_commit"
  | "missing_welcome"
  | "membership_changed"
  | "identity_changed";

export type RecoveryPhase =
  | "waiting_for_sync"
  | "waiting_for_pending_replay"
  | "waiting_for_identity_refresh"
  | "waiting_for_explicit_reconcile"
  | "escalated_to_rebuild";

export type RecoveryEscalationReason =
  | "mls_marked_unrecoverable"
  | "identity_refresh_retry_exhausted"
  | "explicit_needs_rebuild_control"
  | "recovery_policy_exhausted";

// Cloudflare
export interface PreflightResult {
  wrangler_installed: boolean;
  wrangler_logged_in: boolean;
  ready: boolean;
  error?: string;
}

export interface CloudflareProgressEvent {
  phase: string;
  message: string;
  progress: number;
  progress_percent?: number;
}

export interface CloudflareStatus {
  bound: boolean;
  endpoint?: string | null;
  features: string[];
  supports_group_outbox: boolean;
  supports_welcome_pickup: boolean;
  needs_upgrade: boolean;
  last_error?: string | null;
}

// Session
export interface SessionStatus {
  state: string;
  device_id?: string;
  ws_connected: boolean;
}

// Realtime WebSocket event payload
export interface RealtimeEventPayload {
  device_id: string;
  event_type:
    | "connected"
    | "disconnected"
    | "head_updated"
    | "inbox_record_available"
    | "message_request_changed"
    | "error"
    | "group_connected"
    | "group_disconnected"
    | "group_head_updated"
    | "group_outbox_record_available"
    | "group_join_request_available"
    | "group_error";
  data?: string;
}

// Core events (for Tauri event listening)
export interface CoreUpdateEvent {
  state_update: CoreStateUpdate;
  effects: unknown[];
  view_model?: CoreViewModel;
}

// Core effects (for debugging, not typically used in frontend)
export type CoreEffect =
  | { type: "execute_http_request"; request: HttpRequestEffect }
  | { type: "open_realtime_connection"; connection: RealtimeConnectionEffect }
  | { type: "open_group_realtime_connection"; subscription: GroupRealtimeSubscriptionRequest }
  | { type: "close_realtime_connection"; device_id: string }
  | { type: "append_group_envelope"; append: AppendGroupEnvelopeRequest }
  | { type: "fetch_group_outbox"; fetch: FetchGroupOutboxRequest }
  | { type: "get_group_outbox_head"; get: GetGroupOutboxHeadRequest }
  | { type: "seal_group_outbox"; seal: SealGroupOutboxRequest }
  | { type: "fetch_welcome_pickup"; fetch: FetchWelcomePickupRequest }
  | { type: "put_welcome_pickup"; put: PutWelcomePickupRequest }
  | { type: "fetch_identity_bundle"; fetch: FetchIdentityBundleRequest }
  | { type: "fetch_message_requests"; fetch: FetchMessageRequestsRequest }
  | { type: "act_on_message_request"; action: MessageRequestActionRequest }
  | { type: "fetch_allowlist"; fetch: FetchAllowlistRequest }
  | { type: "replace_allowlist"; update: ReplaceAllowlistRequest }
  | { type: "publish_shared_state"; publish: PublishSharedStateRequest }
  | { type: "read_attachment_bytes"; read: ReadAttachmentBytesEffect }
  | { type: "prepare_blob_upload"; upload: PrepareBlobUploadRequest }
  | { type: "upload_blob"; upload: BlobUploadRequest }
  | { type: "download_blob"; download: BlobDownloadRequest }
  | { type: "write_downloaded_attachment"; write: WriteDownloadedAttachmentEffect }
  | { type: "persist_state"; persist: PersistStateEffect }
  | { type: "schedule_timer"; timer: TimerEffect }
  | { type: "emit_user_notification"; notification: UserNotificationEffect };

// Effect detail types (minimal, for reference)
interface HttpRequestEffect {
  request_id: string;
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
}

interface RealtimeConnectionEffect {
  subscription: RealtimeSubscriptionRequest;
}

interface RealtimeSubscriptionRequest {
  device_id: string;
  endpoint: string;
  last_acked_seq: number;
  headers: Record<string, string>;
}

interface GroupRealtimeSubscriptionRequest {
  group_id: string;
  endpoint: string;
  last_seq: number;
  capability: GroupCapability;
  headers: Record<string, string>;
}

interface AppendGroupEnvelopeRequest {
  version: string;
  group_id: string;
  envelope: GroupEnvelope;
  capability: GroupCapability;
}

interface FetchGroupOutboxRequest {
  group_id: string;
  from_seq: number;
  limit: number;
  capability: GroupCapability;
}

interface GetGroupOutboxHeadRequest {
  group_id: string;
  capability: GroupCapability;
}

export interface SealGroupOutboxRequest {
  group_id: string;
  capability: GroupCapability;
}

interface FetchWelcomePickupRequest {
  descriptor: WelcomePickupDescriptor;
  headers: Record<string, string>;
}

interface PutWelcomePickupRequest {
  descriptor: WelcomePickupDescriptor;
  welcome_b64: string;
  manifest?: GroupManifest | null;
  headers: Record<string, string>;
}

interface FetchIdentityBundleRequest {
  user_id: string;
  reference?: string;
}

interface FetchMessageRequestsRequest {
  device_id: string;
  endpoint: string;
  headers: Record<string, string>;
}

interface MessageRequestActionRequest {
  device_id: string;
  request_id: string;
  action: "accept" | "reject";
  endpoint: string;
  headers: Record<string, string>;
}

interface FetchAllowlistRequest {
  device_id: string;
  endpoint: string;
  headers: Record<string, string>;
}

interface ReplaceAllowlistRequest {
  device_id: string;
  endpoint: string;
  headers: Record<string, string>;
  document: AllowlistDocument;
}

interface PublishSharedStateRequest {
  reference: string;
  document_kind: "identity_bundle" | "device_status";
  body: string;
  headers: Record<string, string>;
}

interface ReadAttachmentBytesEffect {
  task_id: string;
  attachment_id: string;
}

interface PrepareBlobUploadRequest {
  task_id: string;
  conversation_id: string;
  message_id: string;
  mime_type: string;
  size_bytes: number;
  file_name?: string;
  headers: Record<string, string>;
}

interface BlobUploadRequest {
  task_id: string;
  blob_ciphertext_b64: string;
  upload_target: string;
  upload_headers: Record<string, string>;
  blob_ref: string;
}

interface BlobDownloadRequest {
  task_id: string;
  blob_ref: string;
  download_target: string;
  download_headers: Record<string, string>;
}

interface WriteDownloadedAttachmentEffect {
  task_id: string;
  destination_id: string;
  plaintext_b64: string;
}

interface PersistStateEffect {
  ops: unknown[];
  snapshot?: unknown;
}

interface TimerEffect {
  timer_id: string;
  delay_ms: number;
}

interface UserNotificationEffect {
  status: SystemStatus;
  message: string;
}

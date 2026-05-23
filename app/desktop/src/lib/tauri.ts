import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type {
  CoreOutput,
  IdentityInfo,
  ConversationSummary,
  ContactSummary,
  Message,
  PreflightResult,
  CloudflareStatus,
  SessionStatus,
  CoreUpdateEvent,
  CloudflareProgressEvent,
  ProfileSummary,
} from "./types";

// Re-export Tauri primitives
export { invoke, listen };

// Typed wrappers for common operations

// Identity
export async function createOrLoadIdentity(
  mnemonic?: string,
  deviceName?: string
): Promise<CoreOutput> {
  return invoke("create_or_load_identity", { mnemonic, deviceName });
}

export async function getIdentityInfo(): Promise<IdentityInfo | null> {
  return invoke("get_identity_info");
}

export async function getShareLink(): Promise<string | null> {
  return invoke("get_share_link");
}

export async function rotateShareLink(): Promise<void> {
  return invoke("rotate_share_link");
}

export async function setLocalDisplayName(displayName: string | null): Promise<void> {
  return invoke("set_local_display_name", { displayName });
}

// Profiles
export async function listProfiles(): Promise<ProfileSummary[]> {
  return invoke("list_profiles");
}

export async function activateProfile(path: string): Promise<void> {
  return invoke("activate_profile", { path });
}

export async function deleteProfile(path: string): Promise<void> {
  return invoke("delete_profile", { path });
}

export async function startNewProfileOnboarding(): Promise<void> {
  return invoke("start_new_profile_onboarding");
}

export async function initOnboardingProfile(profileName: string): Promise<ProfileSummary> {
  return invoke("init_onboarding_profile", { profileName });
}

// Conversations
export async function listConversations(): Promise<ConversationSummary[]> {
  return invoke("list_conversations");
}

export async function createConversation(peerUserId: string): Promise<CoreOutput> {
  return invoke("create_conversation", { peerUserId });
}

export async function getMessages(conversationId: string): Promise<Message[]> {
  return invoke("get_messages", { conversationId });
}

// Messages
export async function sendText(
  conversationId: string,
  plaintext: string
): Promise<CoreOutput> {
  return invoke("send_text", { conversationId, plaintext });
}

export async function sendAttachment(
  conversationId: string,
  filePath: string,
  mimeType: string,
  sizeBytes: number,
  fileName?: string
): Promise<CoreOutput> {
  return invoke("send_attachment", {
    conversationId,
    filePath,
    mimeType,
    sizeBytes,
    fileName,
  });
}

export async function downloadAttachment(
  conversationId: string,
  messageId: string,
  reference: string,
  destination: string
): Promise<CoreOutput> {
  return invoke("download_attachment", {
    conversationId,
    messageId,
    reference,
    destination,
  });
}

// Contacts
export async function importContactByLink(shareLink: string): Promise<void> {
  return invoke("import_contact_by_link", { shareLink });
}

export async function listContacts(): Promise<ContactSummary[]> {
  return invoke("list_contacts");
}

export async function refreshContact(userId: string): Promise<void> {
  return invoke("refresh_contact", { userId });
}

export async function deleteContact(userId: string): Promise<CoreOutput> {
  return invoke("delete_contact", { userId });
}

// Message Requests
export async function listMessageRequests(): Promise<CoreOutput> {
  return invoke("list_message_requests");
}

export async function actOnMessageRequest(
  requestId: string,
  action: "accept" | "reject"
): Promise<CoreOutput> {
  return invoke("act_on_message_request", { requestId, action });
}

// Allowlist
export async function getAllowlist(): Promise<CoreOutput> {
  return invoke("get_allowlist");
}

export async function addToAllowlist(userId: string): Promise<CoreOutput> {
  return invoke("add_to_allowlist", { userId });
}

export async function removeFromAllowlist(userId: string): Promise<CoreOutput> {
  return invoke("remove_from_allowlist", { userId });
}

// Cloudflare
export async function cloudflarePreflight(): Promise<PreflightResult> {
  return invoke("cloudflare_preflight");
}

export interface CloudflareLoginResult {
  success: boolean;
  account_id: string | null;
  account_name: string | null;
  error: string | null;
}

export async function cloudflareLogin(): Promise<CloudflareLoginResult> {
  return invoke("cloudflare_login");
}

export interface CloudflareDeployResult {
  success: boolean;
  worker_name: string;
  worker_url: string;
  error: string | null;
}

export async function cloudflareDeploy(): Promise<CloudflareDeployResult> {
  return invoke("cloudflare_deploy");
}

export async function cloudflareStatus(): Promise<CloudflareStatus> {
  return invoke("cloudflare_status");
}

export const getCloudflareStatus = cloudflareStatus;
export const deployCloudflare = cloudflareDeploy;

// Session
export async function startRealtimeSession(): Promise<void> {
  return invoke("start_realtime_session");
}

export async function stopRealtimeSession(): Promise<void> {
  return invoke("stop_realtime_session");
}

export async function syncNow(): Promise<CoreOutput> {
  return invoke("sync_now");
}

export async function getSessionStatus(): Promise<SessionStatus> {
  return invoke("get_session_status");
}

// Event listeners
export function onCoreUpdate(
  callback: (event: CoreUpdateEvent) => void
): Promise<() => void> {
  return listen<CoreUpdateEvent>("core-update", (e) => callback(e.payload));
}

export function onCloudflareProgress(
  callback: (event: CloudflareProgressEvent) => void
): Promise<() => void> {
  return listen<CloudflareProgressEvent>("cloudflare-progress", (e) =>
    callback(e.payload)
  );
}

export function onSessionStatus(
  callback: (event: SessionStatus) => void
): Promise<() => void> {
  return listen<SessionStatus>("session-status", (e) => callback(e.payload));
}

// Attachment settings
export interface AttachmentSettings {
  auto_download_media: boolean;
  always_ask_save_path: boolean;
}

export async function getAttachmentSettings(): Promise<AttachmentSettings> {
  return invoke("get_attachment_settings");
}

export async function setAttachmentSettings(settings: AttachmentSettings): Promise<void> {
  return invoke("set_attachment_settings", { settings });
}

export async function getAttachmentCacheDir(): Promise<string> {
  return invoke("get_attachment_cache_dir");
}

export type GroupSyncMode = "auto" | "polling" | "manual";

export interface GroupSyncSettings {
  mode: GroupSyncMode;
  max_websocket_groups: number;
  poll_interval_minutes: number;
  important_group_ids: string[];
}

export async function getGroupSyncSettings(): Promise<GroupSyncSettings> {
  return invoke("get_group_sync_settings");
}

export async function setGroupSyncSettings(
  settings: GroupSyncSettings,
): Promise<GroupSyncSettings> {
  return invoke("set_group_sync_settings", { settings });
}

// Debug mode for performance timing tests
export async function setDebugMode(enabled: boolean): Promise<void> {
  return invoke("set_debug_mode", { enabled });
}

export async function getDebugMode(): Promise<boolean> {
  return invoke("get_debug_mode");
}

// ---------------------------------------------------------------------------
// Groups (Phase 6 — PLAN_GROUP)
//
// Thin invoke wrappers over the `commands::group::*` Tauri handlers
// defined in `app/desktop/src-tauri/src/commands/group.rs`. Every
// wrapper mirrors the underlying Tauri command 1:1 and deliberately
// preserves snake_case on nested fields so the wire shape matches the
// Rust side (see app/desktop/src-tauri/src/commands/group.rs:GroupSnapshotView etc).
// ---------------------------------------------------------------------------

import type {
  GroupCursor,
  GroupJoinPolicy,
  GroupMemberStatus,
  GroupMemberInvitePolicy,
  GroupManifest,
  GroupRole,
  StorageRef,
  WelcomePickupDescriptor,
} from "./types";

export interface GroupConversationSummary {
  group_id: string;
  conversation_id: string;
  title: string;
  owner_user_id: string;
  member_count: number;
  local_role: GroupRole | null;
  conversation_state: "active" | "needs_rebuild" | "dissolved" | string;
  dissolved_at: number | null;
  last_message_preview: string | null;
  message_count: number;
}

export interface WelcomePickupShareable extends WelcomePickupDescriptor {
  /** `tapchat://welcome-pickup/<base64(descriptor json)>` */
  url: string;
}

export interface GroupInviteView {
  group_id: string;
  invite_id: string;
  invite_url: string;
  join_policy: GroupJoinPolicy;
  expires_at: number;
  max_uses: number | null;
  inviter_user_id: string;
  created_at: number;
}

export interface GroupJoinRequestView {
  request_id: string;
  group_id: string;
  joiner_user_id: string;
  joiner_device_id: string;
  requested_at: number;
  status: "pending" | "approved" | "rejected" | string;
  invite_id: string;
}

export interface GroupSnapshotView {
  group_id: string;
  conversation_id: string;
  manifest: GroupManifest;
  local_role: GroupRole | null;
  cursor: GroupCursor | null;
  invites: GroupInviteView[];
  join_requests: GroupJoinRequestView[];
  pending_outbox_count: number;
  dissolved_at: number | null;
  conversation_state: "active" | "needs_rebuild" | "dissolved" | string;
}

/**
 * A single row the chat view renders. The variant is discriminated on
 * the `kind` field so React components can switch behaviour directly.
 */
export type GroupMessageView =
  | {
      kind: "bubble";
      message_id: string;
      sender_device_id: string;
      created_at: number;
      plaintext: string | null;
      has_attachment: boolean;
      storage_refs: StorageRef[];
      raw_message_type: string;
    }
  | {
      kind: "system_banner";
      message_id: string;
      created_at: number;
      text: string;
      raw_message_type: string;
    };

export interface CreateGroupConversationResult {
  group_id: string;
  conversation_id: string;
  title: string;
  member_count: number;
  local_role: GroupRole | null;
  welcome_pickups: WelcomePickupShareable[];
  pending_group_outbox: number;
}

export interface SendGroupTextResult {
  message_id: string;
  conversation_id: string;
  sender_user_id: string;
  sender_device_id: string;
  plaintext: string;
  created_at: number;
  pending_group_outbox: number;
}

export interface SyncGroupOutboxResult {
  group_id: string;
  cursor: GroupCursor | null;
  dissolved_at: number | null;
}

export interface InviteToGroupResult {
  group_id: string;
  welcome_pickups: WelcomePickupShareable[];
}

export interface CreateGroupInviteLinkResult {
  group_id: string;
  invite_id: string;
  invite_url: string;
  expires_at: number;
  max_uses: number | null;
  join_policy: GroupJoinPolicy;
}

export interface RevokeGroupInviteLinkResult {
  group_id: string;
  invite_id: string;
}

export interface SubmitGroupJoinRequestResult {
  request_id: string;
  group_id: string;
  status: "pending" | "approved" | "rejected" | string;
}

export interface GroupJoinStatusView {
  group_id: string;
  request_id: string;
  status: "pending" | "approved" | "rejected" | string;
  group_imported: boolean;
  welcome_pickup: WelcomePickupShareable | null;
}

export interface ApproveGroupJoinResult {
  group_id: string;
  request_id: string;
  status: "approved" | "already_member" | "failed" | string;
  welcome_pickups: WelcomePickupShareable[];
}

export interface ProcessGroupJoinRequestsResult {
  group_id: string;
  processed: number;
  approved: number;
  already_member: number;
  failed: number;
}

export interface UpdateGroupMetadataResult {
  group_id: string;
  title: string | null;
  join_policy: GroupJoinPolicy | null;
  member_invite_policy: GroupMemberInvitePolicy | null;
  roster_version: number | null;
}

export interface DissolveGroupResult {
  group_id: string;
  conversation_id: string | null;
  dissolved_at: number | null;
  conversation_state: "active" | "needs_rebuild" | "dissolved" | string;
  pending_group_outbox: number;
}

type WireObject = Record<string, unknown>;

function pick<T>(value: WireObject, snake: string, camel: string): T {
  return (value[snake] ?? value[camel]) as T;
}

export function normalizeGroupManifest(manifest: unknown): GroupManifest {
  const wire = manifest as WireObject;
  return {
    ...wire,
    group_id: pick<string>(wire, "group_id", "groupId"),
    conversation_id: pick<string>(wire, "conversation_id", "conversationId"),
    owner_user_id: pick<string>(wire, "owner_user_id", "ownerUserId"),
    admins: (wire.admins ?? []) as string[],
    members: ((wire.members ?? []) as WireObject[]).map((member) => ({
      ...member,
      user_id: pick<string>(member, "user_id", "userId"),
      role: member.role as GroupRole,
      status: member.status as GroupMemberStatus,
    })),
    join_policy: pick<GroupJoinPolicy>(wire, "join_policy", "joinPolicy"),
    member_invite_policy: pick<GroupMemberInvitePolicy>(
      wire,
      "member_invite_policy",
      "memberInvitePolicy",
    ),
    roster_version: pick<number>(wire, "roster_version", "rosterVersion"),
    mls_epoch_hint: pick<number>(wire, "mls_epoch_hint", "mlsEpochHint"),
    last_commit_message_id:
      (wire.last_commit_message_id ?? wire.lastCommitMessageId) as string | undefined,
    outbox: wire.outbox as GroupManifest["outbox"],
    updated_at: pick<number>(wire, "updated_at", "updatedAt"),
    signer_user_id: pick<string>(wire, "signer_user_id", "signerUserId"),
    signer_device_id: pick<string>(wire, "signer_device_id", "signerDeviceId"),
    signature: wire.signature as string,
    version: wire.version as string,
    title: wire.title as string,
  };
}

function normalizeGroupCursor(cursor: unknown): GroupCursor | null {
  if (!cursor) return null;
  const wire = cursor as WireObject;
  return {
    ...wire,
    group_id: pick<string>(wire, "group_id", "groupId"),
    last_fetched_seq: pick<number>(wire, "last_fetched_seq", "lastFetchedSeq"),
    updated_at: pick<number>(wire, "updated_at", "updatedAt"),
  } as GroupCursor;
}

export function normalizeGroupInvite(invite: unknown): GroupInviteView {
  const wire = invite as WireObject;
  return {
    group_id: pick<string>(wire, "group_id", "groupId"),
    invite_id: pick<string>(wire, "invite_id", "inviteId"),
    invite_url: pick<string>(wire, "invite_url", "inviteUrl"),
    join_policy: pick<GroupJoinPolicy>(wire, "join_policy", "joinPolicy"),
    expires_at: pick<number>(wire, "expires_at", "expiresAt"),
    max_uses: (wire.max_uses ?? wire.maxUses ?? null) as number | null,
    inviter_user_id: pick<string>(wire, "inviter_user_id", "inviterUserId"),
    created_at: pick<number>(wire, "created_at", "createdAt"),
  };
}

export function normalizeGroupJoinRequest(request: unknown): GroupJoinRequestView {
  const wire = request as WireObject;
  return {
    request_id: pick<string>(wire, "request_id", "requestId"),
    group_id: pick<string>(wire, "group_id", "groupId"),
    joiner_user_id: pick<string>(wire, "joiner_user_id", "joinerUserId"),
    joiner_device_id: pick<string>(wire, "joiner_device_id", "joinerDeviceId"),
    requested_at: pick<number>(wire, "requested_at", "requestedAt"),
    status: wire.status as GroupJoinRequestView["status"],
    invite_id: pick<string>(wire, "invite_id", "inviteId"),
  };
}

export function normalizeGroupSnapshot(snapshot: unknown): GroupSnapshotView {
  const wire = snapshot as WireObject;
  return {
    group_id: pick<string>(wire, "group_id", "groupId"),
    conversation_id: pick<string>(wire, "conversation_id", "conversationId"),
    manifest: normalizeGroupManifest(wire.manifest),
    local_role: (wire.local_role ?? wire.localRole ?? null) as GroupRole | null,
    cursor: normalizeGroupCursor(wire.cursor),
    invites: ((wire.invites ?? []) as unknown[]).map(normalizeGroupInvite),
    join_requests: ((wire.join_requests ?? wire.joinRequests ?? []) as unknown[]).map(
      normalizeGroupJoinRequest,
    ),
    pending_outbox_count: pick<number>(
      wire,
      "pending_outbox_count",
      "pendingOutboxCount",
    ),
    dissolved_at: (wire.dissolved_at ?? wire.dissolvedAt ?? null) as number | null,
    conversation_state: pick<GroupSnapshotView["conversation_state"]>(
      wire,
      "conversation_state",
      "conversationState",
    ),
  };
}

// Read-only projections ------------------------------------------------------

export async function listGroupConversations(): Promise<GroupConversationSummary[]> {
  return invoke("list_group_conversations");
}

export async function getGroupSnapshot(groupId: string): Promise<GroupSnapshotView> {
  return normalizeGroupSnapshot(await invoke("get_group_snapshot", { groupId }));
}

export async function getGroupMessages(
  conversationId: string,
): Promise<GroupMessageView[]> {
  return invoke("get_group_messages", { conversationId });
}

// Core write paths -----------------------------------------------------------

export async function createGroupConversation(
  title: string,
  memberUserIds: string[],
): Promise<CreateGroupConversationResult> {
  return invoke("create_group_conversation", { title, memberUserIds });
}

export async function sendGroupTextMessage(
  conversationId: string,
  plaintext: string,
): Promise<SendGroupTextResult> {
  return invoke("send_group_text_message", { conversationId, plaintext });
}

export async function syncGroupOutbox(
  groupId: string,
  reason?: string,
): Promise<SyncGroupOutboxResult> {
  return invoke("sync_group_outbox", { groupId, reason });
}

export async function applyGroupRealtimePlan(
  websocketGroupIds: string[],
): Promise<void> {
  return invoke("apply_group_realtime_plan", { websocketGroupIds });
}

// Invite lifecycle -----------------------------------------------------------

export async function inviteToGroup(
  groupId: string,
  inviteeUserIds: string[],
): Promise<InviteToGroupResult> {
  return invoke("invite_to_group", { groupId, inviteeUserIds });
}

export async function createGroupInviteLink(
  groupId: string,
  expiresAt: number,
  maxUses?: number,
): Promise<CreateGroupInviteLinkResult> {
  return invoke("create_group_invite_link", { groupId, expiresAt, maxUses });
}

export async function revokeGroupInviteLink(
  groupId: string,
  inviteId: string,
): Promise<RevokeGroupInviteLinkResult> {
  return invoke("revoke_group_invite_link", { groupId, inviteId });
}

export async function listGroupInvites(groupId: string): Promise<GroupInviteView[]> {
  const rows = await invoke<unknown[]>("list_group_invites", { groupId });
  return rows.map(normalizeGroupInvite);
}

// Join flow ------------------------------------------------------------------

export async function submitGroupJoinRequest(
  inviteUrl: string,
): Promise<SubmitGroupJoinRequestResult> {
  return invoke("submit_group_join_request", { inviteUrl });
}

export async function listGroupJoinRequests(
  groupId: string,
): Promise<GroupJoinRequestView[]> {
  const rows = await invoke<unknown[]>("list_group_join_requests", { groupId });
  return rows.map(normalizeGroupJoinRequest);
}

export async function getGroupJoinRequestStatus(
  groupId: string,
  requestId: string,
): Promise<GroupJoinStatusView> {
  return invoke("get_group_join_request_status", { groupId, requestId });
}

export async function approveGroupJoin(
  groupId: string,
  requestId: string,
): Promise<ApproveGroupJoinResult> {
  return invoke("approve_group_join", { groupId, requestId });
}

export async function processGroupJoinRequests(
  groupId: string,
): Promise<ProcessGroupJoinRequestsResult> {
  return invoke("process_group_join_requests", { groupId });
}

export async function retryPendingWelcomePickups(): Promise<void> {
  return invoke("retry_pending_welcome_pickups");
}

export async function rejectGroupJoin(
  groupId: string,
  requestId: string,
  reason?: string,
): Promise<void> {
  return invoke("reject_group_join", { groupId, requestId, reason });
}

// Membership + metadata ------------------------------------------------------

export async function leaveGroup(groupId: string): Promise<void> {
  return invoke("leave_group", { groupId });
}

export async function removeGroupMember(
  groupId: string,
  targetUserId: string,
): Promise<void> {
  return invoke("remove_group_member", { groupId, targetUserId });
}

export async function transferGroupOwnership(
  groupId: string,
  newOwnerUserId: string,
): Promise<void> {
  return invoke("transfer_group_ownership", { groupId, newOwnerUserId });
}

export async function setGroupAdmin(
  groupId: string,
  targetUserId: string,
  isAdmin: boolean,
): Promise<void> {
  return invoke("set_group_admin", { groupId, targetUserId, isAdmin });
}

export async function updateGroupMetadata(
  groupId: string,
  updates: {
    title?: string;
    joinPolicy?: GroupJoinPolicy;
    memberInvitePolicy?: GroupMemberInvitePolicy;
  },
): Promise<UpdateGroupMetadataResult> {
  return invoke("update_group_metadata", { groupId, ...updates });
}

// Dissolve -------------------------------------------------------------------

export async function dissolveGroup(groupId: string): Promise<DissolveGroupResult> {
  return invoke("dissolve_group", { groupId });
}

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

export async function cloudflareLogin(): Promise<boolean> {
  return invoke("cloudflare_login");
}

export async function cloudflareDeploy(): Promise<void> {
  return invoke("cloudflare_deploy");
}

export async function cloudflareStatus(): Promise<CloudflareStatus> {
  return invoke("cloudflare_status");
}

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
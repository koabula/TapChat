import { invoke } from "@tauri-apps/api/core";
import type {
  CloudflareActionResultView,
  AllowlistView,
  AppBootstrapView,
  AttachmentPreviewView,
  CloudflarePreflightView,
  CloudflareDeployOverrides,
  CloudflareRuntimeDetailsView,
  CloudflareWizardStatusView,
  ContactDetailView,
  ContactListItem,
  ContactShareLinkView,
  ConversationDetailView,
  BackgroundDownloadTicketView,
  BatchSendAttachmentResultView,
  DownloadAttachmentResultView,
  DirectShellView,
  IdentitySummaryView,
  MessageRequestActionView,
  MessageRequestItemView,
  ProfileSummary,
  ProvisionProgressView,
  RuntimeStatusView,
  SendAttachmentResultView,
  SendMessageResultView,
  SyncStatusView,
} from "./types";

export function appBootstrap() {
  return invoke<AppBootstrapView>("app_bootstrap");
}

export function syncWindowVisibility() {
  return invoke<string>("sync_window_visibility");
}

export function profileList() {
  return invoke<ProfileSummary[]>("profile_list");
}

export function profileActivate(profileIdOrPath: string) {
  return invoke<AppBootstrapView>("profile_activate", { profileIdOrPath });
}

export function profileCreate(name: string, root: string) {
  return invoke<ProfileSummary>("profile_create", { name, root });
}

export function profileOpenOrImport(rootDir: string) {
  return invoke<ProfileSummary>("profile_open_or_import", { rootDir });
}

export function profileRevealInShell(profilePath: string) {
  return invoke<boolean>("profile_reveal_in_shell", { profilePath });
}

export function showOnboardingWindow() {
  return invoke<string>("show_onboarding_window");
}

export function completeOnboardingHandoff(profilePath?: string | null) {
  return invoke<AppBootstrapView>("complete_onboarding_handoff", { profilePath });
}

export function desktopDebugLog(
  scope: string,
  message: string,
  windowLabel?: string | null,
  profilePath?: string | null,
) {
  return invoke<boolean>("desktop_debug_log", {
    scope,
    message,
    windowLabel,
    profilePath,
  });
}

export function identityCreate(profilePath: string, deviceName: string) {
  return invoke<IdentitySummaryView>("identity_create", { profilePath, deviceName });
}

export function identityRecover(profilePath: string, deviceName: string, mnemonic: string) {
  return invoke<IdentitySummaryView>("identity_recover", {
    profilePath,
    deviceName,
    mnemonic,
  });
}

export function deploymentImport(profilePath: string, bundleJsonOrPath: string) {
  return invoke<RuntimeStatusView>("deployment_import", {
    profilePath,
    bundleJsonOrPath,
  });
}

export function cloudflareProvisionAuto(profilePath: string) {
  return invoke<ProvisionProgressView>("cloudflare_provision_auto", { profilePath });
}

export function cloudflarePreflight(profilePath: string) {
  return invoke<CloudflarePreflightView>("cloudflare_preflight", { profilePath });
}

export function cloudflareProvisionCustom(
  profilePath: string,
  overrides: CloudflareDeployOverrides,
) {
  return invoke<ProvisionProgressView>("cloudflare_provision_custom", {
    profilePath,
    overrides,
  });
}

export function cloudflareStatus(profilePath: string) {
  return invoke<RuntimeStatusView>("cloudflare_status", { profilePath });
}

export function cloudflareRuntimeDetails(profilePath: string) {
  return invoke<CloudflareRuntimeDetailsView>("cloudflare_runtime_details", { profilePath });
}

export function cloudflareRedeploy(profilePath: string) {
  return invoke<CloudflareActionResultView>("cloudflare_redeploy", { profilePath });
}

export function cloudflareRotateSecrets(profilePath: string) {
  return invoke<CloudflareActionResultView>("cloudflare_rotate_secrets", { profilePath });
}

export function cloudflareDetach(profilePath: string) {
  return invoke<CloudflareActionResultView>("cloudflare_detach", { profilePath });
}

export function cloudflareSetupWizardStart(
  profilePath: string,
  mode: "auto" | "custom",
  overrides?: CloudflareDeployOverrides | null,
) {
  return invoke<CloudflareWizardStatusView>("cloudflare_setup_wizard_start", {
    profilePath,
    mode,
    overrides,
  });
}

export function cloudflareSetupWizardStatus(profilePath: string) {
  return invoke<CloudflareWizardStatusView>("cloudflare_setup_wizard_status", { profilePath });
}

export function cloudflareSetupWizardCancel(profilePath: string) {
  return invoke<CloudflareWizardStatusView>("cloudflare_setup_wizard_cancel", { profilePath });
}

export function contactList(profilePath: string) {
  return invoke<ContactListItem[]>("contact_list", { profilePath });
}

export function contactImportIdentity(profilePath: string, bundleJsonOrPath: string) {
  return invoke<ContactDetailView>("contact_import_identity", {
    profilePath,
    bundleJsonOrPath,
  });
}

export function contactImportShareLink(profilePath: string, url: string) {
  return invoke<ContactDetailView>("contact_import_share_link", {
    profilePath,
    url,
  });
}

export function contactShareLinkGet(profilePath: string) {
  return invoke<ContactShareLinkView>("contact_share_link_get", { profilePath });
}

export function contactShareLinkRotate(profilePath: string) {
  return invoke<ContactShareLinkView>("contact_share_link_rotate", { profilePath });
}

export function contactShow(profilePath: string, userId: string) {
  return invoke<ContactDetailView>("contact_show", { profilePath, userId });
}

export function messageRequestsList(profilePath: string) {
  return invoke<MessageRequestItemView[]>("message_requests_list", { profilePath });
}

export function messageRequestAccept(profilePath: string, requestId: string) {
  return invoke<MessageRequestActionView>("message_request_accept", { profilePath, requestId });
}

export function messageRequestReject(profilePath: string, requestId: string) {
  return invoke<MessageRequestActionView>("message_request_reject", { profilePath, requestId });
}

export function allowlistGet(profilePath: string) {
  return invoke<AllowlistView>("allowlist_get", { profilePath });
}

export function allowlistAdd(profilePath: string, userId: string) {
  return invoke<AllowlistView>("allowlist_add", { profilePath, userId });
}

export function allowlistRemove(profilePath: string, userId: string) {
  return invoke<AllowlistView>("allowlist_remove", { profilePath, userId });
}

export function contactRefresh(profilePath: string, userId: string) {
  return invoke<ContactDetailView>("contact_refresh", { profilePath, userId });
}

export function conversationCreateDirect(profilePath: string, peerUserId: string) {
  return invoke<ConversationDetailView>("conversation_create_direct", { profilePath, peerUserId });
}

export function conversationReconcile(profilePath: string, conversationId: string) {
  return invoke<ConversationDetailView>("conversation_reconcile", { profilePath, conversationId });
}

export function conversationRebuild(profilePath: string, conversationId: string) {
  return invoke<ConversationDetailView>("conversation_rebuild", { profilePath, conversationId });
}

export function messageSendText(profilePath: string, conversationId: string, text: string) {
  return invoke<SendMessageResultView>("message_send_text", {
    profilePath,
    conversationId,
    text,
  });
}

export function messageSendAttachment(profilePath: string, conversationId: string, filePath: string) {
  return invoke<SendAttachmentResultView>("message_send_attachment", {
    profilePath,
    conversationId,
    filePath,
  });
}

export function messageSendAttachments(profilePath: string, conversationId: string, filePaths: string[]) {
  return invoke<BatchSendAttachmentResultView>("message_send_attachments", {
    profilePath,
    conversationId,
    filePaths,
  });
}

export function messageDownloadAttachment(
  profilePath: string,
  conversationId: string,
  messageId: string,
  reference: string,
  destination?: string | null,
) {
  return invoke<DownloadAttachmentResultView>("message_download_attachment", {
    profilePath,
    conversationId,
    messageId,
    reference,
    destination,
  });
}

export function messageDownloadAttachmentBackground(
  profilePath: string,
  conversationId: string,
  messageId: string,
  reference: string,
  destination?: string | null,
) {
  return invoke<BackgroundDownloadTicketView>("message_download_attachment_background", {
    profilePath,
    conversationId,
    messageId,
    reference,
    destination,
  });
}

export function attachmentOpenLocal(profilePath: string, messageId: string) {
  return invoke<boolean>("attachment_open_local", {
    profilePath,
    messageId,
  });
}

export function attachmentPreviewSource(profilePath: string, messageId: string, reference?: string | null) {
  return invoke<AttachmentPreviewView>("attachment_preview_source", {
    profilePath,
    messageId,
    reference,
  });
}

export function syncOnce(profilePath: string) {
  return invoke<SyncStatusView>("sync_once", { profilePath });
}

export function syncForeground(profilePath: string) {
  return invoke<SyncStatusView>("sync_foreground", { profilePath });
}

export function syncRealtimeConnect(profilePath: string) {
  return invoke("sync_realtime_connect", { profilePath });
}

export function syncRealtimeClose(profilePath: string) {
  return invoke("sync_realtime_close", { profilePath });
}

export function directShell(
  profilePath: string,
  selectedConversationId?: string | null,
  selectedContactUserId?: string | null,
) {
  return invoke<DirectShellView>("direct_shell", {
    profilePath,
    selectedConversationId,
    selectedContactUserId,
  });
}

export function attachmentTransfers(profilePath: string, conversationId?: string | null) {
  return invoke("attachment_transfers", {
    profilePath,
    conversationId,
  });
}

export function attachmentTransferHistory(profilePath: string, conversationId?: string | null) {
  return invoke("attachment_transfer_history", {
    profilePath,
    conversationId,
  });
}

export function appSetBackgroundMode(profilePath: string, enabled: boolean) {
  return invoke<boolean>("app_set_background_mode", { profilePath, enabled });
}

export function appBackgroundMode(profilePath: string) {
  return invoke<boolean>("app_background_mode", { profilePath });
}

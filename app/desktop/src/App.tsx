import { useEffect, useMemo, useState } from "react";
import { open, save } from "@tauri-apps/plugin-dialog";
import { convertFileSrc } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import {
  allowlistAdd,
  allowlistGet,
  allowlistRemove,
  appBackgroundMode,
  appSetBackgroundMode,
  appBootstrap,
  attachmentOpenLocal,
  attachmentPreviewSource,
  cloudflareProvisionAuto,
  cloudflareProvisionCustom,
  cloudflareStatus,
  contactImportIdentity,
  contactRefresh,
  conversationCreateDirect,
  conversationRebuild,
  conversationReconcile,
  deploymentImport,
  directShell,
  identityCreate,
  identityRecover,
  messageRequestAccept,
  messageRequestReject,
  messageRequestsList,
  messageDownloadAttachmentBackground,
  messageSendAttachments,
  messageSendText,
  profileActivate,
  profileCreate,
  syncForeground,
  syncOnce,
  syncRealtimeClose,
  syncRealtimeConnect,
} from "./lib/commands";
import type {
  AllowlistView,
  AppBootstrapView,
  AttachmentPreviewView,
  BatchSendAttachmentResultView,
  CloudflareDeployOverrides,
  DirectShellView,
  MessageRequestItemView,
  ProfileSummary,
  SendMessageResultView,
} from "./lib/types";

type ViewState = {
  bootstrap: AppBootstrapView | null;
  shell: DirectShellView | null;
  loading: boolean;
  error: string | null;
  success: string | null;
  selectedContactUserId: string | null;
  selectedConversationId: string | null;
  lastSend: SendMessageResultView | null;
  lastAttachmentSend: BatchSendAttachmentResultView | null;
  messageRequests: MessageRequestItemView[];
  allowlist: AllowlistView | null;
};

const emptyOverrides: CloudflareDeployOverrides = {
  worker_name: "",
  public_base_url: "",
  deployment_region: "",
  max_inline_bytes: "",
  retention_days: "",
  rate_limit_per_minute: "",
  rate_limit_per_hour: "",
  bucket_name: "",
  preview_bucket_name: "",
};

export default function App() {
  const [state, setState] = useState<ViewState>({
    bootstrap: null,
    shell: null,
    loading: true,
    error: null,
    success: null,
    selectedContactUserId: null,
    selectedConversationId: null,
    lastSend: null,
    lastAttachmentSend: null,
    messageRequests: [],
    allowlist: null,
  });
  const [createName, setCreateName] = useState("alice");
  const [createRoot, setCreateRoot] = useState("");
  const [deviceName, setDeviceName] = useState("phone");
  const [mnemonic, setMnemonic] = useState("");
  const [customProvision, setCustomProvision] = useState(false);
  const [overrides, setOverrides] = useState<CloudflareDeployOverrides>(emptyOverrides);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [composerText, setComposerText] = useState("");
  const [selectedAttachmentPaths, setSelectedAttachmentPaths] = useState<string[]>([]);
  const [downloadingMessageId, setDownloadingMessageId] = useState<string | null>(null);
  const [preview, setPreview] = useState<AttachmentPreviewView | null>(null);
  const [dropActive, setDropActive] = useState(false);
  const [backgroundEnabled, setBackgroundEnabled] = useState(true);
  const [allowlistDraft, setAllowlistDraft] = useState("");

  useEffect(() => {
    void refreshBootstrap();
  }, []);

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let unlistenBackground: (() => void) | undefined;
    let unlistenDrop: (() => void) | undefined;
    void listen<string>("tapchat://direct-shell-dirty", (event) => {
      if (event.payload && event.payload === state.bootstrap?.active_profile?.path) {
        void refreshDirectShell();
      }
    }).then((dispose) => {
      unlisten = dispose;
    });
    void listen("tapchat://background-download-complete", () => {
      void refreshDirectShell();
    }).then((dispose) => {
      unlistenBackground = dispose;
    });
    void getCurrentWindow().onDragDropEvent((event) => {
      if (event.payload.type === "enter" || event.payload.type === "over") {
        setDropActive(true);
        return;
      }
      if (event.payload.type === "leave") {
        setDropActive(false);
        return;
      }
      if (event.payload.type === "drop") {
        setDropActive(false);
        const droppedPaths = event.payload.paths;
        setSelectedAttachmentPaths((current) => dedupePaths([...current, ...droppedPaths]));
      }
    }).then((dispose) => {
      unlistenDrop = dispose;
    });
    return () => {
      unlisten?.();
      unlistenBackground?.();
      unlistenDrop?.();
    };
  }, [state.bootstrap?.active_profile?.path, state.selectedContactUserId, state.selectedConversationId]);

  useEffect(() => {
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!profilePath || state.bootstrap?.onboarding.step !== "complete") {
      return;
    }
    void syncForeground(profilePath)
      .then(() => syncRealtimeConnect(profilePath))
      .then(() => appBackgroundMode(profilePath))
      .then((enabled) => setBackgroundEnabled(enabled))
      .then(() => refreshDirectShell())
      .catch((error) => {
        setState((current) => ({ ...current, error: formatError(error), loading: false }));
      });
    return () => {
      void syncRealtimeClose(profilePath);
    };
  }, [state.bootstrap?.active_profile?.path, state.bootstrap?.onboarding.step]);

  useEffect(() => {
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!profilePath || state.bootstrap?.onboarding.step !== "complete") {
      return;
    }
    void refreshDirectShell(profilePath);
  }, [state.bootstrap?.active_profile?.path, state.bootstrap?.onboarding.step, state.selectedConversationId, state.selectedContactUserId]);

  async function refreshBootstrap(message?: string) {
    setState((current) => ({ ...current, loading: true, error: null, success: message ?? current.success }));
    try {
      const bootstrap = await appBootstrap();
      setState((current) => ({
        ...current,
        bootstrap,
        loading: false,
        error: null,
        success: message ?? current.success,
        shell: bootstrap.onboarding.step === "complete" ? current.shell : null,
      }));
      if (!createRoot && bootstrap.active_profile?.path) {
        setCreateRoot(bootstrap.active_profile.path);
      }
      if (bootstrap.onboarding.step === "complete") {
        await refreshDirectShell(bootstrap.active_profile?.path ?? null);
      }
    } catch (error) {
      setState((current) => ({
        ...current,
        bootstrap: null,
        shell: null,
        loading: false,
        error: formatError(error),
        success: null,
      }));
    }
  }

  async function refreshDirectShell(explicitProfilePath?: string | null) {
    const profilePath = explicitProfilePath ?? state.bootstrap?.active_profile?.path ?? null;
    if (!profilePath) {
      return;
    }
    const shell = await directShell(
      profilePath,
      state.selectedConversationId,
      state.selectedContactUserId,
    );
    setState((current) => ({
      ...current,
      shell,
      loading: false,
    }));
    await refreshPolicyState(profilePath);
  }

  async function refreshPolicyState(explicitProfilePath?: string | null) {
    const profilePath = explicitProfilePath ?? state.bootstrap?.active_profile?.path ?? null;
    if (!profilePath) {
      return;
    }
    const [messageRequests, allowlist] = await Promise.all([
      messageRequestsList(profilePath),
      allowlistGet(profilePath),
    ]);
    setState((current) => ({
      ...current,
      messageRequests,
      allowlist,
    }));
  }

  async function runTask(task: () => Promise<void>) {
    setState((current) => ({ ...current, loading: true, error: null, success: null }));
    try {
      await task();
    } catch (error) {
      setState((current) => ({
        ...current,
        loading: false,
        error: formatError(error),
        success: null,
      }));
    }
  }

  async function chooseProfileRoot() {
    const selected = await open({
      directory: true,
      multiple: false,
      title: "Choose a folder for the TapChat profile",
    });
    if (typeof selected === "string") {
      setCreateRoot(selected);
    }
  }

  async function chooseDeploymentBundle() {
    const selected = await open({
      multiple: false,
      directory: false,
      filters: [{ name: "JSON", extensions: ["json"] }],
      title: "Choose a deployment bundle",
    });
    const profilePath = state.bootstrap?.active_profile?.path;
    if (typeof selected === "string" && profilePath) {
      await runTask(async () => {
        await deploymentImport(profilePath, selected);
        await refreshBootstrap("Deployment bundle imported.");
      });
    }
  }

  async function chooseIdentityBundle() {
    const selected = await open({
      multiple: false,
      directory: false,
      filters: [{ name: "JSON", extensions: ["json"] }],
      title: "Choose a contact identity bundle",
    });
    const profilePath = state.bootstrap?.active_profile?.path;
    if (typeof selected === "string" && profilePath) {
      await runTask(async () => {
        const contact = await contactImportIdentity(profilePath, selected);
        setState((current) => ({ ...current, selectedContactUserId: contact.user_id }));
        await refreshDirectShell(profilePath);
        setState((current) => ({ ...current, success: `Imported ${contact.user_id}.` }));
      });
    }
  }

  async function chooseAttachmentFile() {
    const selected = await open({
      multiple: true,
      directory: false,
      title: "Choose files to send",
    });
    if (typeof selected === "string") {
      setSelectedAttachmentPaths((current) => dedupePaths([...current, selected]));
    } else if (Array.isArray(selected)) {
      setSelectedAttachmentPaths((current) => dedupePaths([...current, ...selected]));
    }
  }

  async function handleCreateProfile() {
    await runTask(async () => {
      const profile = await profileCreate(createName, createRoot);
      await profileActivate(profile.path);
      await refreshBootstrap(`Profile ${profile.name} created.`);
    });
  }

  async function handleActivateProfile(profile: ProfileSummary) {
    const previous = state.bootstrap?.active_profile?.path;
    await runTask(async () => {
      if (previous) {
        await syncRealtimeClose(previous);
      }
      await profileActivate(profile.path);
      setState((current) => ({
        ...current,
        selectedContactUserId: null,
        selectedConversationId: null,
        lastSend: null,
        lastAttachmentSend: null,
        messageRequests: [],
        allowlist: null,
      }));
      setSelectedAttachmentPaths([]);
      setPreview(null);
      await refreshBootstrap(`Switched to ${profile.name}.`);
    });
  }

  async function handleIdentityCreate() {
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!profilePath) {
      return;
    }
    await runTask(async () => {
      const identity = await identityCreate(profilePath, deviceName);
      setMnemonic(identity.mnemonic);
      await refreshBootstrap("Identity created.");
    });
  }

  async function handleIdentityRecover() {
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!profilePath) {
      return;
    }
    await runTask(async () => {
      await identityRecover(profilePath, deviceName, mnemonic);
      await refreshBootstrap("Identity recovered.");
    });
  }

  async function handleProvisionAuto() {
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!profilePath) {
      return;
    }
    await runTask(async () => {
      await cloudflareProvisionAuto(profilePath);
      await refreshBootstrap("Cloudflare runtime provisioned.");
    });
  }

  async function handleProvisionCustom() {
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!profilePath) {
      return;
    }
    await runTask(async () => {
      await cloudflareProvisionCustom(profilePath, normalizeOverrides(overrides));
      await refreshBootstrap("Custom Cloudflare runtime provisioned.");
    });
  }

  async function handleRefreshRuntimeStatus() {
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!profilePath) {
      return;
    }
    await runTask(async () => {
      await cloudflareStatus(profilePath);
      await refreshBootstrap("Runtime status refreshed.");
    });
  }

  async function handleRefreshContact(userId: string) {
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!profilePath) {
      return;
    }
    await runTask(async () => {
      await contactRefresh(profilePath, userId);
      await refreshDirectShell(profilePath);
      setState((current) => ({ ...current, success: `Refreshed ${userId}.` }));
    });
  }

  async function handleCreateDirectConversation() {
    const profilePath = state.bootstrap?.active_profile?.path;
    const peerUserId = state.selectedContactUserId;
    if (!profilePath || !peerUserId) {
      return;
    }
    await runTask(async () => {
      const conversation = await conversationCreateDirect(profilePath, peerUserId);
      setState((current) => ({
        ...current,
        selectedConversationId: conversation.conversation_id,
      }));
      setSelectedAttachmentPaths([]);
      await refreshDirectShell(profilePath);
      setState((current) => ({ ...current, success: `Created conversation with ${peerUserId}.` }));
    });
  }

  async function handleSendMessage() {
    const profilePath = state.bootstrap?.active_profile?.path;
    const conversationId = state.selectedConversationId;
    if (!profilePath || !conversationId || !composerText.trim()) {
      return;
    }
    await runTask(async () => {
      const result = await messageSendText(profilePath, conversationId, composerText.trim());
      setComposerText("");
      setState((current) => ({ ...current, lastSend: result }));
      await refreshDirectShell(profilePath);
      if (result.append_result?.queued_as_request) {
        setState((current) => ({
          ...current,
          success: "Message queued as a request.",
        }));
      } else {
        setState((current) => ({
          ...current,
          success: "Message sent.",
        }));
      }
    });
  }

  async function handleSendAttachments() {
    const profilePath = state.bootstrap?.active_profile?.path;
    const conversationId = state.selectedConversationId;
    if (!profilePath || !conversationId || selectedAttachmentPaths.length === 0) {
      return;
    }
    await runTask(async () => {
      const result = await messageSendAttachments(profilePath, conversationId, selectedAttachmentPaths);
      setSelectedAttachmentPaths([]);
      setState((current) => ({ ...current, lastAttachmentSend: result }));
      await refreshDirectShell(profilePath);
      if (result.results.some((item) => item.append_result?.queued_as_request)) {
        setState((current) => ({ ...current, success: "One or more attachments were queued as requests." }));
      } else {
        setState((current) => ({ ...current, success: `Queued ${result.queued_count} attachment messages.` }));
      }
    });
  }

  async function handleDownloadAttachment(messageId: string, reference: string) {
    const profilePath = state.bootstrap?.active_profile?.path;
    const conversationId = state.selectedConversationId;
    if (!profilePath || !conversationId) {
      return;
    }
    const selected = await save({
      title: "Save attachment",
      defaultPath: `${messageId}.bin`,
    });
    if (!selected || Array.isArray(selected)) {
      return;
    }
    await runTask(async () => {
      setDownloadingMessageId(messageId);
      await messageDownloadAttachmentBackground(profilePath, conversationId, messageId, reference, selected);
      await refreshDirectShell(profilePath);
      setState((current) => ({ ...current, success: "Attachment download started in background." }));
      setDownloadingMessageId(null);
    });
    setDownloadingMessageId(null);
  }

  async function handleOpenAttachment(messageId: string) {
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!profilePath) {
      return;
    }
    await runTask(async () => {
      await attachmentOpenLocal(profilePath, messageId);
      await refreshDirectShell(profilePath);
      setState((current) => ({ ...current, success: "Attachment opened." }));
    });
  }

  async function handlePreviewAttachment(messageId: string, reference: string) {
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!profilePath) {
      return;
    }
    await runTask(async () => {
      const nextPreview = await attachmentPreviewSource(profilePath, messageId, reference);
      setPreview(nextPreview);
      setState((current) => ({ ...current, loading: false, error: null }));
    });
  }

  async function handleManualSync() {
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!profilePath) {
      return;
    }
    await runTask(async () => {
      await syncOnce(profilePath);
      await refreshDirectShell(profilePath);
      setState((current) => ({ ...current, success: "Sync complete." }));
    });
  }

  async function handleMessageRequest(requestId: string, action: "accept" | "reject") {
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!profilePath) {
      return;
    }
    await runTask(async () => {
      const result = action === "accept"
        ? await messageRequestAccept(profilePath, requestId)
        : await messageRequestReject(profilePath, requestId);
      await refreshDirectShell(profilePath);
      setState((current) => ({
        ...current,
        success: `${action === "accept" ? "Accepted" : "Rejected"} request from ${result.sender_user_id}.`,
      }));
    });
  }

  async function handleAllowlistAdd() {
    const profilePath = state.bootstrap?.active_profile?.path;
    const nextUserId = allowlistDraft.trim();
    if (!profilePath || !nextUserId) {
      return;
    }
    await runTask(async () => {
      const next = await allowlistAdd(profilePath, nextUserId);
      setAllowlistDraft("");
      setState((current) => ({
        ...current,
        allowlist: next,
        success: `Added ${nextUserId} to allowlist.`,
      }));
      await refreshDirectShell(profilePath);
    });
  }

  async function handleAllowlistRemove(userId: string) {
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!profilePath) {
      return;
    }
    await runTask(async () => {
      const next = await allowlistRemove(profilePath, userId);
      setState((current) => ({
        ...current,
        allowlist: next,
        success: `Removed ${userId} from allowlist.`,
      }));
      await refreshDirectShell(profilePath);
    });
  }

  async function handleConversationRepair(action: "reconcile" | "rebuild") {
    const profilePath = state.bootstrap?.active_profile?.path;
    const conversationId = state.selectedConversationId;
    if (!profilePath || !conversationId) {
      return;
    }
    await runTask(async () => {
      if (action === "reconcile") {
        await conversationReconcile(profilePath, conversationId);
      } else {
        await conversationRebuild(profilePath, conversationId);
      }
      await refreshDirectShell(profilePath);
      setState((current) => ({
        ...current,
        success: `${action === "reconcile" ? "Reconciled" : "Rebuilt"} conversation state.`,
      }));
    });
  }

  const bootstrap = state.bootstrap;
  const activeProfile = bootstrap?.active_profile ?? null;
  const step = bootstrap?.onboarding.step ?? "welcome";
  const activeConversation = state.shell?.selected_conversation ?? null;
  const selectedContact = state.shell?.selected_contact ?? null;
  const selectedConversationId = state.selectedConversationId;
  const selectedContactUserId = state.selectedContactUserId;

  const statusLabel = useMemo(() => {
    if (!state.shell?.realtime) {
      return "disconnected";
    }
    if (state.shell.realtime.connected) {
      return "connected";
    }
    if (state.shell.realtime.needs_reconnect) {
      return "reconnecting";
    }
    return "disconnected";
  }, [state.shell?.realtime]);

  const composerStatus = state.lastAttachmentSend?.latest_notification
    ?? state.lastSend?.latest_notification
    ?? "Attachments are queued as separate messages. Drag files into the conversation or choose multiple files.";

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-block">
          <div className="brand-mark">T</div>
          <div>
            <div className="brand-title">TapChat</div>
            <div className="brand-subtitle">Desktop direct shell</div>
          </div>
        </div>

        <section className="sidebar-section">
          <div className="section-label">Profiles</div>
          <div className="profile-list">
            {bootstrap?.profiles.map((profile) => (
              <button
                key={profile.path}
                className={profile.is_active ? "profile-pill active" : "profile-pill"}
                onClick={() => void handleActivateProfile(profile)}
              >
                <span>{profile.name}</span>
                <small>{profile.user_id ?? "No identity"}</small>
              </button>
            ))}
          </div>
        </section>

        {step === "complete" && state.shell ? (
          <>
            <section className="sidebar-section">
              <div className="section-label">Contacts</div>
              <button className="ghost-button full-width" onClick={() => void chooseIdentityBundle()}>
                Import identity bundle
              </button>
              <div className="profile-list">
                {state.shell.contacts.map((contact) => (
                  <button
                    key={contact.user_id}
                    className={selectedContactUserId === contact.user_id ? "profile-pill active" : "profile-pill"}
                    onClick={() =>
                      {
                        setSelectedAttachmentPaths([]);
                        setPreview(null);
                        setState((current) => ({
                          ...current,
                          selectedContactUserId: contact.user_id,
                          selectedConversationId: current.shell?.conversations.find(
                            (row) => row.peer_user_id === contact.user_id,
                          )?.conversation_id ?? null,
                        }));
                      }
                    }
                  >
                    <span>{contact.user_id}</span>
                    <small>{contact.device_count} devices</small>
                  </button>
                ))}
              </div>
            </section>

            <section className="sidebar-section">
              <div className="section-label">Conversations</div>
              <div className="profile-list">
                {state.shell.conversations.map((conversation) => (
                  <button
                    key={conversation.conversation_id}
                    className={selectedConversationId === conversation.conversation_id ? "profile-pill active" : "profile-pill"}
                    onClick={() =>
                      {
                        setSelectedAttachmentPaths([]);
                        setPreview(null);
                        setState((current) => ({
                          ...current,
                          selectedConversationId: conversation.conversation_id,
                          selectedContactUserId: conversation.peer_user_id,
                        }));
                      }
                    }
                  >
                    <span>{conversation.peer_user_id}</span>
                    <small>{conversation.last_message_preview ?? "No messages yet"}</small>
                  </button>
                ))}
              </div>
            </section>
          </>
        ) : (
          <section className="sidebar-section sidebar-status">
            <div className="section-label">Status</div>
            <div className="status-chip">
              <span>Onboarding</span>
              <strong>{step}</strong>
            </div>
          </section>
        )}
      </aside>

      <main className="main-panel">
        <header className="topbar">
          <div>
            <div className="eyebrow">Signal-inspired desktop flow</div>
            <h1>{activeProfile ? activeProfile.name : "Welcome to TapChat"}</h1>
          </div>
          <div className="topbar-actions">
            <button className="ghost-button" onClick={() => setSettingsOpen((value) => !value)}>
              {settingsOpen ? "Close settings" : "Open settings"}
            </button>
          </div>
        </header>

        {state.error && <Banner tone="error" message={state.error} />}
        {state.success && <Banner tone="success" message={state.success} />}

        {step !== "complete" ? (
          <OnboardingPane
            state={state}
            createName={createName}
            setCreateName={setCreateName}
            createRoot={createRoot}
            setCreateRoot={setCreateRoot}
            chooseProfileRoot={chooseProfileRoot}
            handleCreateProfile={handleCreateProfile}
            deviceName={deviceName}
            setDeviceName={setDeviceName}
            mnemonic={mnemonic}
            setMnemonic={setMnemonic}
            handleIdentityCreate={handleIdentityCreate}
            handleIdentityRecover={handleIdentityRecover}
            customProvision={customProvision}
            setCustomProvision={setCustomProvision}
            overrides={overrides}
            setOverrides={setOverrides}
            handleProvisionAuto={handleProvisionAuto}
            handleProvisionCustom={handleProvisionCustom}
            chooseDeploymentBundle={chooseDeploymentBundle}
          />
        ) : (
          <div className="content-grid direct-layout">
            <section className="hero-card conversation-shell">
              <div className="card-header">
                <div>
                  <span className="eyebrow">Sync and realtime</span>
                  <h3>Direct conversation shell</h3>
                </div>
                <div className="button-row">
                  <span className="status-chip inline">{statusLabel}</span>
                  <button className="ghost-button" disabled={state.loading} onClick={() => void handleManualSync()}>
                    Sync now
                  </button>
                </div>
              </div>

              {!activeConversation && selectedContact ? (
                <div className="empty-state">
                  <h3>{selectedContact.user_id}</h3>
                  <p>Identity imported. Create a direct conversation to start messaging.</p>
                  <div className="button-row">
                    <button className="primary-button" disabled={state.loading} onClick={() => void handleCreateDirectConversation()}>
                      Create direct conversation
                    </button>
                    <button className="ghost-button" disabled={state.loading} onClick={() => void handleRefreshContact(selectedContact.user_id)}>
                      Refresh contact
                    </button>
                  </div>
                </div>
              ) : !activeConversation ? (
                <div className="empty-state">
                  <h3>No conversation selected</h3>
                  <p>Import a contact identity on the left, then create or open a direct conversation.</p>
                </div>
              ) : (
                <>
                  <div className="conversation-header">
                    <div>
                      <h3>{activeConversation.peer_user_id}</h3>
                      <p>{activeConversation.recovery_status}</p>
                    </div>
                    <div className="button-row">
                      <button className="ghost-button" disabled={state.loading} onClick={() => void handleConversationRepair("reconcile")}>
                        Reconcile
                      </button>
                      <button className="ghost-button" disabled={state.loading} onClick={() => void handleConversationRepair("rebuild")}>
                        Rebuild
                      </button>
                      <span className="status-chip inline">{activeConversation.conversation_state}</span>
                    </div>
                  </div>
                  <div className={dropActive ? "message-list drop-active" : "message-list"}>
                    {state.shell?.messages.map((message) => (
                      <div
                        key={message.message_id}
                        className={message.direction === "outgoing" ? "message-bubble outgoing" : "message-bubble incoming"}
                      >
                        <div className="message-meta">
                          <span>{message.sender_user_id ?? "unknown"}</span>
                          <small>{message.created_at ?? ""}</small>
                        </div>
                        <div>{message.plaintext ?? `[${message.message_type}]`}</div>
                        {message.has_attachment && (
                          <div className="attachment-card">
                            {message.primary_attachment_previewable && message.primary_attachment_local_path && (
                              <button
                                className="attachment-preview-button"
                                disabled={state.loading || message.attachment_refs.length === 0}
                                onClick={() => void handlePreviewAttachment(message.message_id, message.attachment_refs[0].ref)}
                              >
                                <img
                                  src={convertFileSrc(message.primary_attachment_local_path)}
                                  alt={message.primary_attachment_display_name ?? "attachment"}
                                  className="attachment-preview-image"
                                />
                              </button>
                            )}
                            <div className="attachment-meta">
                              <strong>{message.primary_attachment_display_name ?? message.attachment_refs[0]?.mime_type ?? "attachment"}</strong>
                              <small>{message.attachment_refs[0]?.size_bytes ?? 0} bytes</small>
                            </div>
                            <div className="button-row">
                              <span className="composer-status">
                                {message.downloaded_attachment_available
                                  ? message.primary_attachment_previewable
                                    ? "Saved locally. Preview or open it."
                                    : "Saved locally. Open or re-download it."
                                  : message.attachment_refs[0]?.mime_type?.startsWith("image/")
                                  ? "Download to preview."
                                  : "Attachment available for download."}
                              </span>
                              {message.downloaded_attachment_available && (
                                <button
                                  className="ghost-button"
                                  disabled={state.loading}
                                  onClick={() => void handleOpenAttachment(message.message_id)}
                                >
                                  Open
                                </button>
                              )}
                              <button
                                className="ghost-button"
                                disabled={state.loading || downloadingMessageId === message.message_id || message.attachment_refs.length === 0}
                                onClick={() => void handleDownloadAttachment(message.message_id, message.attachment_refs[0].ref)}
                              >
                                {downloadingMessageId === message.message_id
                                  ? "Downloading..."
                                  : message.downloaded_attachment_available
                                  ? "Re-download"
                                  : "Download"}
                              </button>
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                    {dropActive && (
                      <div className="drop-overlay">
                        <strong>Drop files to queue attachments</strong>
                        <small>Files will be sent as separate attachment messages.</small>
                      </div>
                    )}
                  </div>
                  <div className="composer">
                    <div className="button-row">
                      <button className="ghost-button" disabled={state.loading} onClick={() => void chooseAttachmentFile()}>
                        Attach files
                      </button>
                      {selectedAttachmentPaths.length > 0 && (
                        <AttachmentDraftQueue
                          paths={selectedAttachmentPaths}
                          onRemove={(path) => setSelectedAttachmentPaths((current) => current.filter((item) => item !== path))}
                        />
                      )}
                    </div>
                    <textarea
                      rows={3}
                      value={composerText}
                      placeholder="Type a message"
                      onChange={(event) => setComposerText(event.target.value)}
                    />
                    <div className="button-row">
                      <div className="composer-status">
                        {state.lastAttachmentSend?.results.some((item) => item.append_result?.queued_as_request)
                          ? "One or more attachments were queued as requests."
                          : state.lastSend?.append_result?.queued_as_request
                          ? "Last message was queued as a request."
                          : composerStatus}
                      </div>
                      {selectedAttachmentPaths.length > 0 && (
                        <button
                          className="ghost-button"
                          disabled={state.loading}
                          onClick={() => void handleSendAttachments()}
                        >
                          Send attachments
                        </button>
                      )}
                      <button
                        className="primary-button"
                        disabled={state.loading || !composerText.trim()}
                        onClick={() => void handleSendMessage()}
                      >
                        Send
                      </button>
                    </div>
                  </div>
                </>
              )}
            </section>
          </div>
        )}
      </main>

      <aside className={settingsOpen ? "settings-drawer open" : "settings-drawer"}>
        <div className="settings-header">
          <div>
            <span className="eyebrow">Settings</span>
            <h3>Profile and runtime</h3>
          </div>
        </div>

        {activeProfile && (
          <div className="settings-stack">
            <InfoCard title="Active profile" rows={[
              ["Name", activeProfile.name],
              ["Path", activeProfile.path],
              ["User", activeProfile.user_id ?? "Pending"],
              ["Device", activeProfile.device_id ?? "Pending"],
            ]} />
            <InfoCard title="Runtime" rows={[
              ["Mode", bootstrap?.runtime?.mode ?? "Not bound"],
              ["Bound", bootstrap?.runtime?.deployment_bound ? "Yes" : "No"],
              ["Base URL", bootstrap?.runtime?.public_base_url ?? "Pending"],
              ["Worker", bootstrap?.runtime?.worker_name ?? "Pending"],
            ]} />
            {step === "complete" && state.shell && (
              <>
                <InfoCard title="Sync" rows={[
                  ["Device", state.shell.sync.device_id ?? "Pending"],
                  ["Fetched", String(state.shell.sync.checkpoint?.last_fetched_seq ?? 0)],
                  ["Acked", String(state.shell.sync.checkpoint?.last_acked_seq ?? 0)],
                  ["Realtime", statusLabel],
                  ["Background downloads", backgroundEnabled ? "Enabled" : "Disabled"],
                ]} />
                {activeConversation && (
                  <InfoCard title="Diagnostics" rows={[
                    ["Conversation", activeConversation.conversation_id],
                    ["Recovery", activeConversation.recovery_status],
                    ["MLS", activeConversation.mls_status ?? "Pending"],
                    ["Reason", activeConversation.recovery?.reason ?? "None"],
                    ["Phase", activeConversation.recovery?.phase ?? "None"],
                    ["Attempts", String(activeConversation.recovery?.attempt_count ?? 0)],
                    ["Refresh retries", String(activeConversation.recovery?.identity_refresh_retry_count ?? 0)],
                    ["Last error", activeConversation.recovery?.last_error ?? "None"],
                  ]} />
                )}
                {state.shell.sync.recovery_conversations.length > 0 && (
                  <InfoCard title="Recovery queue" rows={state.shell.sync.recovery_conversations.map((item) => [
                    item.conversation_id,
                    `${item.recovery_status} · ${item.phase} · ${item.reason}`,
                  ])} />
                )}
                {selectedContact && (
                  <InfoCard title="Selected contact" rows={[
                    ["User", selectedContact.user_id],
                    ["Devices", String(selectedContact.devices.length)],
                    ["Bundle ref", selectedContact.identity_bundle_ref ?? "Pending"],
                  ]} />
                )}
                <div className="info-card">
                  <div className="info-card-title">Message requests</div>
                  <div className="info-card-rows">
                    {state.messageRequests.length === 0 ? (
                      <div className="info-row">
                        <span>Requests</span>
                        <strong>None</strong>
                      </div>
                    ) : (
                      state.messageRequests.map((request) => (
                        <div className="info-row" key={request.request_id}>
                          <span>{request.sender_user_id}</span>
                          <div className="button-row">
                            <small>{request.message_count} msg</small>
                            <button className="ghost-button" disabled={state.loading} onClick={() => void handleMessageRequest(request.request_id, "accept")}>
                              Accept
                            </button>
                            <button className="ghost-button" disabled={state.loading} onClick={() => void handleMessageRequest(request.request_id, "reject")}>
                              Reject
                            </button>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
                <div className="info-card">
                  <div className="info-card-title">Allowlist</div>
                  <div className="info-card-rows">
                    <div className="inline-field">
                      <input
                        placeholder="user_id"
                        value={allowlistDraft}
                        onChange={(event) => setAllowlistDraft(event.target.value)}
                      />
                      <button className="ghost-button" disabled={state.loading || !allowlistDraft.trim()} onClick={() => void handleAllowlistAdd()}>
                        Add
                      </button>
                    </div>
                    {(state.allowlist?.allowed_sender_user_ids ?? []).length === 0 ? (
                      <div className="info-row">
                        <span>Allowed</span>
                        <strong>Empty</strong>
                      </div>
                    ) : (
                      state.allowlist?.allowed_sender_user_ids.map((userId) => (
                        <div className="info-row" key={userId}>
                          <span>{userId}</span>
                          <button className="ghost-button" disabled={state.loading} onClick={() => void handleAllowlistRemove(userId)}>
                            Remove
                          </button>
                        </div>
                      ))
                    )}
                    {(state.allowlist?.rejected_sender_user_ids ?? []).length > 0 && (
                      <InfoCard
                        title="Rejected senders"
                        rows={(state.allowlist?.rejected_sender_user_ids ?? []).map((userId) => [userId, "Rejected"])}
                      />
                    )}
                  </div>
                </div>
                {state.shell.attachment_transfers.length > 0 && (
                  <InfoCard title="Transfers" rows={state.shell.attachment_transfers.map((transfer, index) => [
                    `${transfer.task_kind} ${index + 1}`,
                    `${transfer.file_name ?? transfer.message_id ?? transfer.state} · ${transfer.state}`,
                  ])} />
                )}
              </>
            )}
            {step === "complete" && (
              <button
                className="ghost-button full-width"
                disabled={state.loading || !activeProfile}
                onClick={() => {
                  if (!activeProfile) {
                    return;
                  }
                  void runTask(async () => {
                    const enabled = await appSetBackgroundMode(activeProfile.path, !backgroundEnabled);
                    setBackgroundEnabled(enabled);
                    setState((current) => ({
                      ...current,
                      success: enabled
                        ? "Background downloads enabled. Closing the window will keep TapChat in the tray."
                        : "Background downloads disabled for this profile.",
                    }));
                  });
                }}
              >
                {backgroundEnabled ? "Disable background downloads" : "Enable background downloads"}
              </button>
            )}
            <button className="ghost-button full-width" disabled={state.loading} onClick={() => void handleRefreshRuntimeStatus()}>
              Refresh runtime status
            </button>
          </div>
        )}
      </aside>
      {preview?.kind === "image" && preview.local_path && (
        <ImagePreviewModal
          title={preview.display_name}
          src={convertFileSrc(preview.local_path)}
          onClose={() => setPreview(null)}
        />
      )}
    </div>
  );
}

function OnboardingPane(props: {
  state: ViewState;
  createName: string;
  setCreateName: (value: string) => void;
  createRoot: string;
  setCreateRoot: (value: string) => void;
  chooseProfileRoot: () => Promise<void>;
  handleCreateProfile: () => Promise<void>;
  deviceName: string;
  setDeviceName: (value: string) => void;
  mnemonic: string;
  setMnemonic: (value: string) => void;
  handleIdentityCreate: () => Promise<void>;
  handleIdentityRecover: () => Promise<void>;
  customProvision: boolean;
  setCustomProvision: (value: boolean | ((value: boolean) => boolean)) => void;
  overrides: CloudflareDeployOverrides;
  setOverrides: React.Dispatch<React.SetStateAction<CloudflareDeployOverrides>>;
  handleProvisionAuto: () => Promise<void>;
  handleProvisionCustom: () => Promise<void>;
  chooseDeploymentBundle: () => Promise<void>;
}) {
  const { state } = props;
  const bootstrap = state.bootstrap;
  const activeProfile = bootstrap?.active_profile ?? null;

  return (
    <div className="content-grid">
      <section className="hero-card">
        <div className="hero-copy">
          <span className="eyebrow">Current flow</span>
          <h2>Direct conversations start here</h2>
          <p>Create a profile, establish identity, bind Cloudflare runtime, then move into contacts and direct conversations.</p>
        </div>
      </section>

      {!bootstrap?.onboarding.has_profiles && (
        <section className="card">
          <div className="card-header"><h3>Create your first profile</h3></div>
          <div className="form-grid">
            <label><span>Profile name</span><input value={props.createName} onChange={(event) => props.setCreateName(event.target.value)} /></label>
            <label>
              <span>Profile directory</span>
              <div className="inline-field">
                <input value={props.createRoot} onChange={(event) => props.setCreateRoot(event.target.value)} />
                <button className="ghost-button" onClick={() => void props.chooseProfileRoot()}>Browse</button>
              </div>
            </label>
          </div>
          <button className="primary-button" disabled={state.loading || !props.createName.trim() || !props.createRoot.trim()} onClick={() => void props.handleCreateProfile()}>
            Create profile
          </button>
        </section>
      )}

      {bootstrap?.onboarding.has_profiles && !bootstrap.onboarding.has_identity && activeProfile && (
        <section className="card">
          <div className="card-header"><h3>Create or recover device identity</h3></div>
          <div className="form-grid">
            <label><span>Device name</span><input value={props.deviceName} onChange={(event) => props.setDeviceName(event.target.value)} /></label>
            <label><span>Mnemonic</span><textarea rows={4} value={props.mnemonic} onChange={(event) => props.setMnemonic(event.target.value)} /></label>
          </div>
          <div className="button-row">
            <button className="primary-button" disabled={state.loading || !props.deviceName.trim()} onClick={() => void props.handleIdentityCreate()}>Create identity</button>
            <button className="ghost-button" disabled={state.loading || !props.deviceName.trim() || !props.mnemonic.trim()} onClick={() => void props.handleIdentityRecover()}>Recover identity</button>
          </div>
        </section>
      )}

      {bootstrap?.onboarding.has_identity && !bootstrap.onboarding.has_runtime_binding && activeProfile && (
        <section className="card">
          <div className="card-header">
            <h3>Bind Cloudflare runtime</h3>
            <button className="ghost-button" onClick={() => props.setCustomProvision((value) => !value)}>
              {props.customProvision ? "Use auto provision" : "Customize provision"}
            </button>
          </div>
          {!props.customProvision ? (
            <div className="button-row">
              <button className="primary-button" disabled={state.loading} onClick={() => void props.handleProvisionAuto()}>Provision Cloudflare</button>
              <button className="ghost-button" disabled={state.loading} onClick={() => void props.chooseDeploymentBundle()}>Import deployment bundle</button>
            </div>
          ) : (
            <>
              <div className="form-grid two-columns">
                {Object.entries(props.overrides).map(([key, value]) => (
                  <label key={key}>
                    <span>{key.replace(/_/g, " ")}</span>
                    <input value={value ?? ""} onChange={(event) => props.setOverrides((current) => ({ ...current, [key]: event.target.value }))} />
                  </label>
                ))}
              </div>
              <div className="button-row">
                <button className="primary-button" disabled={state.loading} onClick={() => void props.handleProvisionCustom()}>Provision with overrides</button>
                <button className="ghost-button" disabled={state.loading} onClick={() => void props.chooseDeploymentBundle()}>Import deployment bundle</button>
              </div>
            </>
          )}
        </section>
      )}
    </div>
  );
}

function Banner({ tone, message }: { tone: "error" | "success"; message: string }) {
  return <div className={tone === "error" ? "banner error" : "banner success"}>{message}</div>;
}

function InfoCard({ title, rows }: { title: string; rows: Array<[string, string]> }) {
  return (
    <div className="info-card">
      <div className="info-card-title">{title}</div>
      <div className="info-card-rows">
        {rows.map(([label, value]) => (
          <div className="info-row" key={label}>
            <span>{label}</span>
            <strong>{value}</strong>
          </div>
        ))}
      </div>
    </div>
  );
}

function AttachmentDraftQueue({
  paths,
  onRemove,
}: {
  paths: string[];
  onRemove: (path: string) => void;
}) {
  return (
    <div className="attachment-draft-queue">
      {paths.map((path) => (
        <span className="status-chip inline attachment-draft-item" key={path}>
          {fileNameFromPath(path)}
          <button className="draft-remove-button" onClick={() => onRemove(path)}>
            x
          </button>
        </span>
      ))}
    </div>
  );
}

function ImagePreviewModal({
  title,
  src,
  onClose,
}: {
  title: string;
  src: string;
  onClose: () => void;
}) {
  return (
    <div className="preview-modal-backdrop" onClick={onClose}>
      <div className="preview-modal" onClick={(event) => event.stopPropagation()}>
        <div className="card-header">
          <div>
            <span className="eyebrow">Image preview</span>
            <h3>{title}</h3>
          </div>
          <button className="ghost-button" onClick={onClose}>Close</button>
        </div>
        <img className="preview-modal-image" src={src} alt={title} />
      </div>
    </div>
  );
}

function normalizeOverrides(overrides: CloudflareDeployOverrides) {
  const next = { ...overrides };
  for (const [key, value] of Object.entries(next)) {
    if (!value || !value.trim()) {
      delete (next as Record<string, string | null | undefined>)[key];
    }
  }
  return next;
}

function formatError(error: unknown) {
  if (typeof error === "string") {
    return error;
  }
  if (error && typeof error === "object" && "toString" in error) {
    return String(error);
  }
  return "Unknown error";
}

function dedupePaths(paths: string[]) {
  return Array.from(new Set(paths));
}

function fileNameFromPath(path: string) {
  const segments = path.split(/[/\\]/);
  return segments[segments.length - 1] ?? path;
}

import { useEffect, useRef, useState } from "react";
import { convertFileSrc } from "@tauri-apps/api/core";
import type { DesktopController } from "./types";
import ImagePreviewModal from "../components/shared/ImagePreviewModal";
import GlobalRail from "../components/shell/GlobalRail";
import ChatsPane from "../components/navigation/ChatsPane";
import ContactsPane from "../components/navigation/ContactsPane";
import RequestsPane from "../components/navigation/RequestsPane";
import ConversationView from "../components/conversation/ConversationView";
import RuntimeDrawer from "../components/drawers/RuntimeDrawer";
import PolicyDrawer from "../components/drawers/PolicyDrawer";
import DiagnosticsDrawer from "../components/drawers/DiagnosticsDrawer";
import InfoCard from "../components/shared/InfoCard";
import ContactQrModal from "../components/shared/ContactQrModal";
import ToastHost, { type ToastItem } from "../components/shared/ToastHost";

export default function MainApp({ controller }: { controller: DesktopController }) {
  const { state, bootstrap, activeProfile, step } = controller;
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const nextToastId = useRef(1);
  const lastSuccessRef = useRef<string | null>(null);
  const lastErrorRef = useRef<string | null>(null);
  const activeConversation =
    controller.activeSection === "chats" ? controller.activeConversation ?? null : null;
  const selectedContact = controller.selectedContact ?? null;
  const conversationSubtitleParts = [controller.statusLabel];

  if (activeConversation?.recovery_status && activeConversation.recovery_status.toLowerCase() !== "healthy") {
    conversationSubtitleParts.push(activeConversation.recovery_status);
  }
  if (activeConversation?.conversation_state) {
    conversationSubtitleParts.push(activeConversation.conversation_state);
  }

  const headerTitle =
    step === "complete" ? activeConversation?.peer_user_id ?? selectedContact?.user_id ?? "Chats" : "TapChat";
  const headerSubtitle =
    step !== "complete"
      ? "Finish setup in the onboarding window to unlock chats."
      : activeConversation
        ? conversationSubtitleParts.filter(Boolean).join(" · ")
        : selectedContact
          ? "Ready to create a direct conversation."
          : controller.transportStatusMessage;

  useEffect(() => {
    if (!state.success) {
      lastSuccessRef.current = null;
      return;
    }
    const successMessage = state.success;
    if (lastSuccessRef.current === successMessage) {
      return;
    }
    lastSuccessRef.current = successMessage;
    const id = nextToastId.current++;
    setToasts((current) => [...current, { id, tone: "success", message: successMessage }]);
    const timeout = window.setTimeout(() => {
      setToasts((current) => current.filter((toast) => toast.id !== id));
    }, 3200);
    return () => window.clearTimeout(timeout);
  }, [state.success]);

  useEffect(() => {
    if (!state.error) {
      lastErrorRef.current = null;
      return;
    }
    const errorMessage = state.error;
    if (lastErrorRef.current === errorMessage) {
      return;
    }
    lastErrorRef.current = errorMessage;
    const id = nextToastId.current++;
    setToasts((current) => [...current, { id, tone: "error", message: errorMessage }]);
    const timeout = window.setTimeout(() => {
      setToasts((current) => current.filter((toast) => toast.id !== id));
    }, 5200);
    return () => window.clearTimeout(timeout);
  }, [state.error]);

  return (
    <div className="app-shell">
      <GlobalRail
        activeSection={controller.activeSection}
        setActiveSection={controller.setActiveSection}
        drawerMode={controller.drawerMode}
        setDrawerMode={controller.setDrawerMode}
        activeProfile={activeProfile}
        profileSwitcherOpen={controller.profileSwitcherOpen}
        setProfileSwitcherOpen={controller.setProfileSwitcherOpen}
        onOpenExistingProfile={controller.chooseExistingProfileDirectory}
        onCreateProfile={controller.handleShowCreateProfile}
        onRevealCurrentProfileDirectory={controller.handleRevealCurrentProfileDirectory}
        loading={state.loading}
        theme={controller.theme}
        onToggleTheme={() => controller.setTheme((current) => (current === "dark" ? "light" : "dark"))}
      />

      <aside className="navigation-pane">
        <div className="nav-header">
          <div>
            <span className="eyebrow">TapChat Desktop</span>
            <h2>{controller.navigationTitle}</h2>
          </div>
        </div>

        {step === "complete" ? (
          <>
            <div className="nav-search">
              <input
                readOnly
                value=""
                placeholder={
                  controller.activeSection === "chats"
                    ? "Search or open a conversation"
                    : controller.activeSection === "contacts"
                      ? "Browse contacts"
                      : "Review pending requests"
                }
              />
            </div>
            <div className="nav-list">
              {controller.activeSection === "chats" && (
                <ChatsPane
                  conversations={state.shell?.conversations ?? []}
                  selectedConversationId={controller.selectedConversationId}
                  onSelect={(conversation) =>
                    controller.selectConversation(conversation.conversation_id, conversation.peer_user_id)
                  }
                />
              )}
              {controller.activeSection === "contacts" && (
                <ContactsPane
                  contacts={state.shell?.contacts ?? []}
                  selectedContactUserId={controller.selectedContactUserId}
                  onSelect={(contact) =>
                    controller.selectContact(
                      contact.user_id,
                      state.shell?.conversations.find((row) => row.peer_user_id === contact.user_id)?.conversation_id ??
                        null,
                    )
                  }
                />
              )}
              {controller.activeSection === "requests" && (
                <RequestsPane
                  requests={state.messageRequests}
                  loading={state.loading}
                  onAction={controller.handleMessageRequest}
                />
              )}
            </div>
          </>
        ) : (
          <div className="nav-list onboarding-nav">
            <div className="pane-empty-state">
              <strong>Setup in progress</strong>
              <small>
                Finish the remaining setup steps in the onboarding window. Chats, contacts, and requests will unlock
                automatically.
              </small>
            </div>
          </div>
        )}
      </aside>

      <main className="conversation-pane">
        <div className="chat-header">
          <div className="chat-header-copy">
            <span className="eyebrow">Direct messaging</span>
            <h1>{headerTitle}</h1>
            <small>{headerSubtitle}</small>
          </div>
          <div className="chat-header-actions">
            {step === "complete" && (
              <button className="ghost-button compact-button" disabled={state.loading} onClick={() => void controller.handleManualSync()}>
                Sync now
              </button>
            )}
            {activeConversation && (
              <>
                <button
                  className="ghost-button compact-button subtle-button"
                  disabled={state.loading}
                  onClick={() => void controller.handleConversationRepair("reconcile")}
                >
                  Reconcile
                </button>
                <button
                  className="ghost-button compact-button subtle-button"
                  disabled={state.loading}
                  onClick={() => void controller.handleConversationRepair("rebuild")}
                >
                  Rebuild
                </button>
              </>
            )}
            <span className="status-chip inline">{step === "complete" ? controller.statusLabel : "setup in progress"}</span>
          </div>
        </div>

        <div className="conversation-content">
          <ConversationView
            loading={state.loading}
            step={step}
            activeSection={controller.activeSection}
            activeConversation={activeConversation}
            selectedContact={selectedContact}
            shell={state.shell}
            contactShareLink={controller.contactShareLink}
            contactLinkDraft={controller.contactLinkDraft}
            setContactLinkDraft={controller.setContactLinkDraft}
            selectedAttachmentPaths={controller.selectedAttachmentPaths}
            setSelectedAttachmentPaths={controller.setSelectedAttachmentPaths}
            downloadingMessageId={controller.downloadingMessageId}
            dropActive={controller.dropActive}
            composerText={controller.composerText}
            setComposerText={controller.setComposerText}
            composerStatus={controller.composerStatus}
            onCreateDirectConversation={controller.handleCreateDirectConversation}
            onRefreshContact={controller.handleRefreshContact}
            onCopyContactLink={controller.handleCopyContactLink}
            onRotateContactLink={controller.handleRotateContactLink}
            onShowQr={() => controller.setShowContactQr(true)}
            onImportLink={controller.handleImportContactLink}
            onImportBundle={controller.chooseIdentityBundle}
            onPreviewAttachment={controller.handlePreviewAttachment}
            onOpenAttachment={controller.handleOpenAttachment}
            onDownloadAttachment={controller.handleDownloadAttachment}
            onChooseAttachmentFile={controller.chooseAttachmentFile}
            onSendAttachments={controller.handleSendAttachments}
            onSendMessage={controller.handleSendMessage}
          />
        </div>

        <aside className={controller.drawerMode === "closed" ? "drawer-panel" : "drawer-panel open"}>
          <div className="drawer-header">
            <div>
              <span className="eyebrow">
                {controller.drawerMode === "runtime"
                  ? "Runtime"
                  : controller.drawerMode === "policy"
                    ? "Policy"
                    : "Diagnostics"}
              </span>
              <h3>
                {controller.drawerMode === "runtime"
                  ? "Deployment"
                  : controller.drawerMode === "policy"
                    ? "Allowlist and requests"
                    : "Sync and recovery"}
              </h3>
            </div>
            <button className="ghost-button compact-button" onClick={() => controller.setDrawerMode("closed")}>
              Close
            </button>
          </div>
          <div className="drawer-body">
            {activeProfile && (
              <InfoCard
                title="Active profile"
                rows={[
                  ["Name", activeProfile.name],
                  ["Path", activeProfile.path],
                  ["User", activeProfile.user_id ?? "Pending"],
                  ["Device", activeProfile.device_id ?? "Pending"],
                ]}
              />
            )}
            {controller.drawerMode === "runtime" && (
              <RuntimeDrawer
                bootstrap={bootstrap}
                activeProfilePath={activeProfile?.path ?? null}
                runtimeDetails={controller.runtimeDetails}
                preflight={controller.preflight}
                cloudflareWizard={controller.cloudflareWizard}
                customWizardOpen={controller.customWizardOpen}
                setCustomWizardOpen={controller.setCustomWizardOpen}
                overrides={controller.overrides}
                setOverrides={controller.setOverrides}
                loading={state.loading}
                wizardRunning={controller.wizardRunning}
                onStartWizard={controller.handleStartCloudflareWizard}
                onCancelWizard={controller.handleCancelCloudflareWizard}
                onImportBundle={controller.chooseDeploymentBundle}
                onRefreshStatus={controller.handleRefreshRuntimeStatus}
                onRedeploy={controller.handleCloudflareRedeploy}
                onRotateSecrets={controller.handleCloudflareRotateSecrets}
                onDetach={controller.handleCloudflareDetach}
                pendingAction={controller.pendingAction}
              />
            )}
            {controller.drawerMode === "policy" && (
              <PolicyDrawer
                requests={state.messageRequests}
                allowlist={state.allowlist}
                allowlistDraft={controller.allowlistDraft}
                setAllowlistDraft={controller.setAllowlistDraft}
                loading={state.loading}
                onMessageRequest={controller.handleMessageRequest}
                onAllowlistAdd={controller.handleAllowlistAdd}
                onAllowlistRemove={controller.handleAllowlistRemove}
              />
            )}
            {controller.drawerMode === "diagnostics" && state.shell && (
              <DiagnosticsDrawer
                shell={state.shell}
                statusLabel={controller.statusLabel}
                backgroundEnabled={controller.backgroundEnabled}
                activeConversation={activeConversation}
                selectedContact={selectedContact}
                recoveryRows={controller.recoveryRows}
                transferRows={controller.transferRows}
                loading={state.loading}
                onToggleBackground={controller.toggleBackgroundMode}
              />
            )}
          </div>
        </aside>
      </main>

      {controller.showContactQr && controller.contactShareLink?.url && (
        <ContactQrModal
          title="Share your contact link"
          value={controller.contactShareLink.url}
          onClose={() => controller.setShowContactQr(false)}
        />
      )}
      {controller.preview?.kind === "image" && controller.preview.local_path && (
        <ImagePreviewModal
          title={controller.preview.display_name}
          src={convertFileSrc(controller.preview.local_path)}
          onClose={() => controller.setPreview(null)}
        />
      )}
      <ToastHost
        toasts={toasts}
        onDismiss={(id) => setToasts((current) => current.filter((toast) => toast.id !== id))}
      />
    </div>
  );
}

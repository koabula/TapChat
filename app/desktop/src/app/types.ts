import type { Dispatch, SetStateAction } from "react";
import type {
  AllowlistView,
  AppBootstrapView,
  AttachmentPreviewView,
  BatchSendAttachmentResultView,
  CloudflareDeployOverrides,
  CloudflarePreflightView,
  CloudflareRuntimeDetailsView,
  CloudflareWizardStatusView,
  ContactShareLinkView,
  DirectShellView,
  MessageRequestItemView,
  ProfileSummary,
  SendMessageResultView,
} from "../lib/types";

export type ViewState = {
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
  cloudflarePreflight: CloudflarePreflightView | null;
  cloudflareRuntime: CloudflareRuntimeDetailsView | null;
  cloudflareWizard: CloudflareWizardStatusView | null;
};

export type ActiveSection = "chats" | "contacts" | "requests";
export type DrawerMode = "closed" | "runtime" | "policy" | "diagnostics";
export type OnboardingViewStep = "choose_profile" | "identity" | "runtime" | "complete";
export type ConnectionHealth = "ready" | "connecting" | "connected" | "reconnecting" | "degraded" | "disconnected";

export type DesktopController = {
  isOnboardingWindow: boolean;
  state: ViewState;
  createName: string;
  setCreateName: (value: string) => void;
  createRoot: string;
  setCreateRoot: (value: string) => void;
  deviceName: string;
  setDeviceName: (value: string) => void;
  mnemonic: string;
  setMnemonic: (value: string) => void;
  overrides: CloudflareDeployOverrides;
  setOverrides: Dispatch<SetStateAction<CloudflareDeployOverrides>>;
  activeSection: ActiveSection;
  setActiveSection: Dispatch<SetStateAction<ActiveSection>>;
  drawerMode: DrawerMode;
  setDrawerMode: Dispatch<SetStateAction<DrawerMode>>;
  profileSwitcherOpen: boolean;
  setProfileSwitcherOpen: Dispatch<SetStateAction<boolean>>;
  composerText: string;
  setComposerText: Dispatch<SetStateAction<string>>;
  selectedAttachmentPaths: string[];
  setSelectedAttachmentPaths: Dispatch<SetStateAction<string[]>>;
  downloadingMessageId: string | null;
  preview: AttachmentPreviewView | null;
  setPreview: Dispatch<SetStateAction<AttachmentPreviewView | null>>;
  dropActive: boolean;
  backgroundEnabled: boolean;
  allowlistDraft: string;
  setAllowlistDraft: Dispatch<SetStateAction<string>>;
  customWizardOpen: boolean;
  setCustomWizardOpen: Dispatch<SetStateAction<boolean>>;
  pendingAction: string | null;
  contactLinkDraft: string;
  setContactLinkDraft: Dispatch<SetStateAction<string>>;
  contactShareLink: ContactShareLinkView | null;
  showContactQr: boolean;
  setShowContactQr: Dispatch<SetStateAction<boolean>>;
  theme: "light" | "dark";
  setTheme: Dispatch<SetStateAction<"light" | "dark">>;
  bootstrap: AppBootstrapView | null;
  activeProfile: ProfileSummary | null;
  step: string;
  onboardingViewStep: OnboardingViewStep;
  canGoBackInOnboarding: boolean;
  activeConversation: DirectShellView["selected_conversation"] | null;
  selectedContact: DirectShellView["selected_contact"] | null;
  selectedConversationId: string | null;
  selectedContactUserId: string | null;
  runtimeDetails: CloudflareRuntimeDetailsView | null;
  preflight: CloudflarePreflightView | null;
  cloudflareWizard: CloudflareWizardStatusView | null;
  connectionHealth: ConnectionHealth;
  reconnectAttempt: number;
  lastTransportError: string | null;
  statusLabel: string;
  transportStatusMessage: string;
  composerStatus: string;
  navigationTitle: string;
  canOperateRuntime: boolean;
  recoveryRows: DirectShellView["sync"]["recovery_conversations"];
  transferRows: DirectShellView["attachment_transfers"];
  wizardRunning: boolean;
  chooseProfileRoot: () => Promise<void>;
  chooseExistingProfileDirectory: () => Promise<void>;
  chooseDeploymentBundle: () => Promise<void>;
  chooseIdentityBundle: () => Promise<void>;
  handleCopyContactLink: () => Promise<void>;
  handleRotateContactLink: () => Promise<void>;
  handleImportContactLink: () => Promise<void>;
  chooseAttachmentFile: () => Promise<void>;
  handleCreateProfile: () => Promise<void>;
  handleShowCreateProfile: () => Promise<void>;
  handleActivateProfile: (profile: ProfileSummary) => Promise<void>;
  handleRevealCurrentProfileDirectory: () => Promise<void>;
  handleOnboardingBack: () => void;
  handleIdentityCreate: () => Promise<void>;
  handleIdentityRecover: () => Promise<void>;
  handleStartCloudflareWizard: (mode: "auto" | "custom") => Promise<void>;
  handleCancelCloudflareWizard: () => Promise<void>;
  handleRefreshRuntimeStatus: () => Promise<void>;
  handleCloudflareRedeploy: () => Promise<void>;
  handleCloudflareRotateSecrets: () => Promise<void>;
  handleCloudflareDetach: () => Promise<void>;
  handleRefreshContact: (userId: string) => Promise<void>;
  handleCreateDirectConversation: () => Promise<void>;
  handleSendMessage: () => Promise<void>;
  handleSendAttachments: () => Promise<void>;
  handleDownloadAttachment: (messageId: string, reference: string) => Promise<void>;
  handleOpenAttachment: (messageId: string) => Promise<void>;
  handlePreviewAttachment: (messageId: string, reference: string) => Promise<void>;
  handleManualSync: () => Promise<void>;
  handleMessageRequest: (requestId: string, action: "accept" | "reject") => Promise<void>;
  handleAllowlistAdd: () => Promise<void>;
  handleAllowlistRemove: (userId: string) => Promise<void>;
  handleConversationRepair: (action: "reconcile" | "rebuild") => Promise<void>;
  selectConversation: (conversationId: string, peerUserId: string) => void;
  selectContact: (userId: string, conversationId: string | null) => void;
  toggleBackgroundMode: () => Promise<void>;
};

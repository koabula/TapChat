import { useEffect, useMemo, useRef, useState } from "react";
import { open, save } from "@tauri-apps/plugin-dialog";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import {
  allowlistAdd,
  allowlistGet,
  allowlistRemove,
  appBackgroundMode,
  appBootstrap,
  appSetBackgroundMode,
  attachmentOpenLocal,
  attachmentPreviewSource,
  completeOnboardingHandoff,
  cloudflareDetach,
  cloudflarePreflight,
  cloudflareRedeploy,
  cloudflareRotateSecrets,
  cloudflareRuntimeDetails,
  cloudflareSetupWizardCancel,
  cloudflareSetupWizardStart,
  cloudflareSetupWizardStatus,
  cloudflareStatus,
  contactImportIdentity,
  contactImportShareLink,
  contactRefresh,
  contactShareLinkGet,
  contactShareLinkRotate,
  conversationCreateDirect,
  conversationRebuild,
  conversationReconcile,
  desktopDebugLog,
  deploymentImport,
  directShell,
  identityCreate,
  identityRecover,
  messageDownloadAttachmentBackground,
  messageRequestAccept,
  messageRequestReject,
  messageRequestsList,
  messageSendAttachments,
  messageSendText,
  profileActivate,
  profileCreate,
  profileRevealInShell,
  profileOpenOrImport,
  showOnboardingWindow,
  syncOnce,
  syncRealtimeClose,
  syncRealtimeConnect,
  syncWindowVisibility,
} from "../lib/commands";
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
import { dedupePaths, formatError, normalizeOverrides } from "./formatters";
import type { ActiveSection, ConnectionHealth, DesktopController, DrawerMode, OnboardingViewStep, ViewState } from "./types";
import { useTheme } from "./useTheme";

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

function waitForNextFrame() {
  return new Promise<void>((resolve) => {
    window.requestAnimationFrame(() => resolve());
  });
}

export function useDesktopController(windowLabel: string): DesktopController {
  const isOnboardingWindow = windowLabel === "onboarding";
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
    cloudflarePreflight: null,
    cloudflareRuntime: null,
    cloudflareWizard: null,
  });
  const [createName, setCreateName] = useState("alice");
  const [createRoot, setCreateRoot] = useState("");
  const [deviceName, setDeviceName] = useState("phone");
  const [mnemonic, setMnemonic] = useState("");
  const [mnemonicBackupPending, setMnemonicBackupPending] = useState(false);
  const [overrides, setOverrides] = useState<CloudflareDeployOverrides>(emptyOverrides);
  const [activeSection, setActiveSection] = useState<ActiveSection>("chats");
  const [drawerMode, setDrawerMode] = useState<DrawerMode>("closed");
  const [profileSwitcherOpen, setProfileSwitcherOpen] = useState(false);
  const [composerText, setComposerText] = useState("");
  const [selectedAttachmentPaths, setSelectedAttachmentPaths] = useState<string[]>([]);
  const [downloadingMessageId, setDownloadingMessageId] = useState<string | null>(null);
  const [preview, setPreview] = useState<AttachmentPreviewView | null>(null);
  const [dropActive, setDropActive] = useState(false);
  const [backgroundEnabled, setBackgroundEnabled] = useState(true);
  const [allowlistDraft, setAllowlistDraft] = useState("");
  const [customWizardOpen, setCustomWizardOpen] = useState(false);
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  const [onboardingStepOverride, setOnboardingStepOverride] = useState<OnboardingViewStep | null>(null);
  const [contactLinkDraft, setContactLinkDraft] = useState("");
  const [contactShareLink, setContactShareLink] = useState<ContactShareLinkView | null>(null);
  const [showContactQr, setShowContactQr] = useState(false);
  const [connectionHealth, setConnectionHealth] = useState<ConnectionHealth>("disconnected");
  const [reconnectAttempt, setReconnectAttempt] = useState(0);
  const [lastTransportError, setLastTransportError] = useState<string | null>(null);
  const [postOnboardingHandoffPending, setPostOnboardingHandoffPending] = useState(false);
  const { theme, setTheme } = useTheme();
  const reconnectTimerRef = useRef<number | null>(null);
  const transportConnectRef = useRef<{
    token: number;
    profilePath: string | null;
    promise: Promise<void> | null;
    pendingShellRefresh: boolean;
    pendingPolicyRefresh: boolean;
    pendingMessageRequestsRefresh: boolean;
  }>({
    token: 0,
    profilePath: null,
    promise: null,
    pendingShellRefresh: false,
    pendingPolicyRefresh: false,
    pendingMessageRequestsRefresh: false,
  });
  const selectionRef = useRef<{
    selectedConversationId: string | null;
    selectedContactUserId: string | null;
  }>({
    selectedConversationId: null,
    selectedContactUserId: null,
  });
  const onboardingHandoffRef = useRef(false);
  const transportStaleError = "__tapchat_transport_startup_stale__";

  function traceDesktop(
    scope: string,
    message: string,
    profilePath?: string | null,
  ) {
    void desktopDebugLog(scope, message, windowLabel, profilePath ?? state.bootstrap?.active_profile?.path ?? null)
      .catch(() => null);
  }

  function isTransportStartupActive(profilePath?: string | null) {
    if (!profilePath) {
      return false;
    }
    return (
      transportConnectRef.current.promise !== null &&
      transportConnectRef.current.profilePath === profilePath
    );
  }

  function markPendingTransportRefresh(
    profilePath: string,
    kind: "shell" | "policy" | "messageRequests",
  ) {
    if (!isTransportStartupActive(profilePath)) {
      return;
    }
    if (kind === "shell") {
      transportConnectRef.current.pendingShellRefresh = true;
      return;
    }
    if (kind === "policy") {
      transportConnectRef.current.pendingPolicyRefresh = true;
      return;
    }
    transportConnectRef.current.pendingMessageRequestsRefresh = true;
  }

  function isStaleTransportConnect(error: unknown) {
    return error instanceof Error && error.message === transportStaleError;
  }

  useEffect(() => {
    void refreshBootstrap();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (isOnboardingWindow) {
      return;
    }
    let unlistenDirty: (() => void) | undefined;
    let unlistenMessageRequests: (() => void) | undefined;
    let unlistenBackground: (() => void) | undefined;
    let unlistenDrop: (() => void) | undefined;
    let unlistenBootstrap: (() => void) | undefined;

    void listen<string>("tapchat://direct-shell-dirty", (event) => {
      if (event.payload && event.payload === state.bootstrap?.active_profile?.path) {
        if (isTransportStartupActive(event.payload)) {
          markPendingTransportRefresh(event.payload, "shell");
          return;
        }
        void refreshDirectShell(undefined, undefined, undefined, false);
      }
    }).then((dispose) => {
      unlistenDirty = dispose;
    });

    void listen<string>("tapchat://message-requests-dirty", (event) => {
      if (event.payload && event.payload === state.bootstrap?.active_profile?.path) {
        if (isTransportStartupActive(event.payload)) {
          markPendingTransportRefresh(event.payload, "messageRequests");
          return;
        }
        void refreshMessageRequestsState(event.payload);
      }
    }).then((dispose) => {
      unlistenMessageRequests = dispose;
    });

    void listen("tapchat://background-download-complete", () => {
      if (isTransportStartupActive(state.bootstrap?.active_profile?.path)) {
        const profilePath = state.bootstrap?.active_profile?.path;
        if (profilePath) {
          markPendingTransportRefresh(profilePath, "shell");
        }
        return;
      }
      void refreshDirectShell();
    }).then((dispose) => {
      unlistenBackground = dispose;
    });

    void listen<AppBootstrapView>("tapchat://bootstrap-dirty", () => {
      void refreshBootstrap();
    }).then((dispose) => {
      unlistenBootstrap = dispose;
    });

    void getCurrentWindow().onDragDropEvent((event) => {
      const { payload } = event;
      if (payload.type === "enter" || payload.type === "over") {
        setDropActive(true);
        return;
      }
      if (payload.type === "leave") {
        setDropActive(false);
        return;
      }
      if (payload.type === "drop") {
        setDropActive(false);
        setSelectedAttachmentPaths((current) => dedupePaths([...current, ...payload.paths]));
      }
    }).then((dispose) => {
      unlistenDrop = dispose;
    });

    return () => {
      unlistenDirty?.();
      unlistenMessageRequests?.();
      unlistenBackground?.();
      unlistenDrop?.();
      unlistenBootstrap?.();
    };
  }, [isOnboardingWindow, state.bootstrap?.active_profile?.path]);

  useEffect(() => {
    return () => {
      if (reconnectTimerRef.current !== null) {
        window.clearTimeout(reconnectTimerRef.current);
      }
    };
  }, []);

  useEffect(() => {
    if (activeSection === "chats") {
      return;
    }
    selectionRef.current = {
      ...selectionRef.current,
      selectedConversationId: null,
    };
    setSelectedAttachmentPaths([]);
    setPreview(null);
    setState((current) => (
      current.selectedConversationId === null
        ? current
        : { ...current, selectedConversationId: null }
    ));
  }, [activeSection]);

  useEffect(() => {
    if (!isOnboardingWindow) {
      return;
    }
    let unlistenWizard: (() => void) | undefined;
    void listen("tapchat://cloudflare-wizard", (event) => {
      const payload = event.payload as CloudflareWizardStatusView | null;
      if (!payload) {
        return;
      }
      setState((current) => ({ ...current, cloudflareWizard: payload }));
      if (payload.state === "completed") {
        traceDesktop("wizard", "received completed event", state.bootstrap?.active_profile?.path ?? null);
        void performOnboardingHandoff();
      }
    }).then((dispose) => {
      unlistenWizard = dispose;
    });
    return () => {
      unlistenWizard?.();
    };
  }, [isOnboardingWindow, state.bootstrap?.active_profile?.path]);

  useEffect(() => {
    if (isOnboardingWindow) {
      return;
    }
    const profilePath = state.bootstrap?.active_profile?.path;
    if (onboardingHandoffRef.current || postOnboardingHandoffPending) {
      return;
    }
    if (!profilePath || state.bootstrap?.onboarding.step !== "complete") {
      setConnectionHealth("disconnected");
      return;
    }
    void connectTransport(profilePath, "connecting");
    return () => {
      if (reconnectTimerRef.current !== null) {
        window.clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
      void syncRealtimeClose(profilePath);
    };
  }, [
    isOnboardingWindow,
    postOnboardingHandoffPending,
    state.bootstrap?.active_profile?.path,
    state.bootstrap?.onboarding.step,
  ]);

  useEffect(() => {
    function handleEscape(event: KeyboardEvent) {
      if (event.key !== "Escape") {
        return;
      }
      setDrawerMode("closed");
      setProfileSwitcherOpen(false);
    }

    window.addEventListener("keydown", handleEscape);
    return () => window.removeEventListener("keydown", handleEscape);
  }, []);

  useEffect(() => {
    if (isOnboardingWindow) {
      return;
    }
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!profilePath || state.bootstrap?.onboarding.step !== "complete") {
      return;
    }
    void refreshDirectShell(profilePath);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOnboardingWindow, state.bootstrap?.active_profile?.path, state.bootstrap?.onboarding.step, state.selectedConversationId, state.selectedContactUserId]);

  useEffect(() => {
    if (!isOnboardingWindow) {
      return;
    }
    const profilePath = state.bootstrap?.active_profile?.path;
    const wizard = state.cloudflareWizard;
    if (!profilePath || !wizard) {
      return;
    }
    if (wizard.state === "completed" || wizard.state === "failed" || wizard.state === "idle") {
      return;
    }
    const timer = window.setTimeout(() => {
      void cloudflareSetupWizardStatus(profilePath)
          .then((status) => {
            setState((current) => ({ ...current, cloudflareWizard: status }));
            if (status.state === "completed") {
              traceDesktop("wizard", "poll observed completed state", profilePath);
              void performOnboardingHandoff();
            }
          })
        .catch((error) => {
          setState((current) => ({ ...current, cloudflareWizard: null, error: formatError(error) }));
        });
    }, 1000);
    return () => window.clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOnboardingWindow, state.bootstrap?.active_profile?.path, state.cloudflareWizard]);

  useEffect(() => {
    if (isOnboardingWindow) {
      return;
    }
    const profilePath = state.bootstrap?.active_profile?.path;
    const onboardingComplete = state.bootstrap?.onboarding.step === "complete";
    const runtimeBound = !!state.cloudflareRuntime?.deployment_bound;
    if (!profilePath || !onboardingComplete) {
      setConnectionHealth("disconnected");
      setReconnectAttempt(0);
      setLastTransportError(null);
      return;
    }
    if (!runtimeBound) {
      setConnectionHealth("ready");
      setReconnectAttempt(0);
      return;
    }
    if (state.shell?.realtime?.connected) {
      setConnectionHealth("connected");
      setReconnectAttempt(0);
      setLastTransportError(null);
      if (reconnectTimerRef.current !== null) {
        window.clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
      return;
    }
    if (state.shell?.realtime?.needs_reconnect && reconnectTimerRef.current === null) {
      const nextAttempt = reconnectAttempt + 1;
      const delay = [1000, 3000, 5000, 10000][Math.min(nextAttempt - 1, 3)];
      setConnectionHealth(nextAttempt >= 4 ? "degraded" : "reconnecting");
      reconnectTimerRef.current = window.setTimeout(() => {
        reconnectTimerRef.current = null;
        setReconnectAttempt(nextAttempt);
        void connectTransport(profilePath, nextAttempt >= 4 ? "degraded" : "reconnecting");
      }, delay);
      return;
    }
    if (!state.shell?.realtime) {
      setConnectionHealth(runtimeBound ? "ready" : "disconnected");
    }
  }, [
    isOnboardingWindow,
    reconnectAttempt,
    state.bootstrap?.active_profile?.path,
    state.bootstrap?.onboarding.step,
    state.cloudflareRuntime?.deployment_bound,
    state.shell?.realtime,
  ]);

  async function refreshBootstrap(message?: string) {
    setState((current) => ({ ...current, loading: true, error: null, success: message ?? current.success }));
    try {
      const bootstrap = await appBootstrap();
      if (bootstrap.onboarding.step !== "complete") {
        selectionRef.current = {
          selectedConversationId: null,
          selectedContactUserId: null,
        };
      }
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
      if (!bootstrap.onboarding.has_identity || bootstrap.onboarding.step === "complete") {
        setMnemonicBackupPending(false);
      }
      setPostOnboardingHandoffPending(false);
      setOnboardingStepOverride(null);
      await syncWindowVisibility().catch(() => null);
      if (bootstrap.onboarding.step === "complete" && !isOnboardingWindow) {
        await refreshDirectShell(bootstrap.active_profile?.path ?? null);
      }
      if (bootstrap.active_profile?.path) {
        await refreshCloudflareState(bootstrap.active_profile.path);
        await refreshContactShareLink(bootstrap.active_profile.path);
      } else {
        setContactShareLink(null);
      }
    } catch (error) {
      setState((current) => ({
        ...current,
        bootstrap: null,
        shell: null,
        cloudflarePreflight: null,
        cloudflareRuntime: null,
        cloudflareWizard: null,
        loading: false,
        error: formatError(error),
        success: null,
      }));
    }
  }

  async function performOnboardingHandoff() {
    if (!isOnboardingWindow) {
      traceDesktop("handoff", "ignored handoff request outside onboarding window");
      return;
    }
    if (onboardingHandoffRef.current) {
      traceDesktop("handoff", "ignored duplicate handoff request while one is already running");
      return;
    }
    setPostOnboardingHandoffPending(true);
    onboardingHandoffRef.current = true;
    try {
      const profilePath = state.bootstrap?.active_profile?.path ?? null;
      traceDesktop("handoff", "starting onboarding handoff", profilePath);
      await completeOnboardingHandoff(profilePath);
      const bootstrap = await appBootstrap();
      selectionRef.current = {
        selectedConversationId: null,
        selectedContactUserId: null,
      };
      setState((current) => ({
        ...current,
        bootstrap,
        loading: false,
        error: null,
        success: "Cloudflare transport is ready. Next, add a contact to start chatting.",
        shell: bootstrap.onboarding.step === "complete" ? current.shell : null,
      }));
      if (!createRoot && bootstrap.active_profile?.path) {
        setCreateRoot(bootstrap.active_profile.path);
      }
      setOnboardingStepOverride(null);
      const activeProfilePath = bootstrap.active_profile?.path ?? null;
      if (!activeProfilePath || bootstrap.onboarding.step !== "complete") {
        throw new Error("Onboarding handoff did not produce an active completed profile.");
      }
      await refreshCloudflareState(activeProfilePath);
      await refreshContactShareLink(activeProfilePath);
      traceDesktop("handoff", "completed onboarding handoff", activeProfilePath);
    } catch (error) {
      traceDesktop(
        "handoff",
        `handoff failed: ${formatError(error)}`,
        state.bootstrap?.active_profile?.path ?? null,
      );
      setState((current) => ({
        ...current,
        loading: false,
        error: `Onboarding handoff failed: ${formatError(error)}`,
      }));
    } finally {
      onboardingHandoffRef.current = false;
      setPostOnboardingHandoffPending(false);
    }
  }

  async function continueTransportWarmup(profilePath: string, token: number) {
    const isCurrentToken = () => transportConnectRef.current.token === token;
    traceDesktop("connectTransport", "starting background warmup", profilePath);
    try {
      const latestShell = await refreshDirectShell(profilePath, undefined, undefined, false);
      if (!isCurrentToken()) {
        return;
      }
      await refreshPolicyState(profilePath, { suppressTransientErrors: true });
      if (!isCurrentToken()) {
        return;
      }
      setConnectionHealth(latestShell?.realtime?.connected ? "connected" : "ready");
      setLastTransportError(null);
      traceDesktop("connectTransport", "background warmup completed", profilePath);
    } catch (error) {
      if (!isCurrentToken() || isStaleTransportConnect(error)) {
        return;
      }
      const formatted = formatError(error);
      setLastTransportError(formatted);
      setState((current) => ({ ...current, error: formatted, loading: false }));
      traceDesktop("connectTransport", `background warmup failed: ${formatted}`, profilePath);
    }
  }

  async function connectTransport(profilePath: string, health: ConnectionHealth) {
    if (isOnboardingWindow) {
      traceDesktop("connectTransport", "ignored connect request from onboarding window", profilePath);
      return;
    }
    const existing = transportConnectRef.current;
    if (existing.promise && existing.profilePath === profilePath) {
      setConnectionHealth(health);
      return existing.promise;
    }

    const token = existing.token + 1;
    const isCurrent = () =>
      transportConnectRef.current.token === token &&
      transportConnectRef.current.profilePath === profilePath;
    const assertCurrent = () => {
      if (!isCurrent()) {
        throw new Error(transportStaleError);
      }
    };

    const promise = (async () => {
      setConnectionHealth(health);
      setLastTransportError(null);
      let shouldWarmup = false;
      traceDesktop("connectTransport", `starting connect with health=${health}`, profilePath);
      try {
        await syncRealtimeClose(profilePath).catch(() => false);
        assertCurrent();
        await refreshDirectShell(profilePath, undefined, undefined, false, { allowDuringTransportStartup: true });
        assertCurrent();
        await syncRealtimeConnect(profilePath);
        assertCurrent();
        const enabled = await appBackgroundMode(profilePath);
        assertCurrent();
        setBackgroundEnabled(enabled);
        const latestShell = await refreshDirectShell(
          profilePath,
          undefined,
          undefined,
          false,
          { allowDuringTransportStartup: true },
        );
        assertCurrent();
        setConnectionHealth(latestShell?.realtime?.connected ? "connected" : "ready");
        setLastTransportError(null);
        shouldWarmup = true;
        traceDesktop(
          "connectTransport",
          `initial connect completed with health=${latestShell?.realtime?.connected ? "connected" : "ready"}`,
          profilePath,
        );
      } catch (error) {
        if (isStaleTransportConnect(error)) {
          return;
        }
        const formatted = formatError(error);
        setLastTransportError(formatted);
        setConnectionHealth((current) => (current === "degraded" ? "degraded" : "disconnected"));
        setState((current) => ({ ...current, error: formatted, loading: false }));
        traceDesktop("connectTransport", `connect failed: ${formatted}`, profilePath);
      } finally {
        if (!isCurrent()) {
          return;
        }
        const pendingShellRefresh = transportConnectRef.current.pendingShellRefresh;
        const pendingPolicyRefresh = transportConnectRef.current.pendingPolicyRefresh;
        const pendingMessageRequestsRefresh = transportConnectRef.current.pendingMessageRequestsRefresh;
        transportConnectRef.current = {
          token,
          profilePath: null,
          promise: null,
          pendingShellRefresh: false,
          pendingPolicyRefresh: false,
          pendingMessageRequestsRefresh: false,
        };
        if (pendingShellRefresh) {
          await refreshDirectShell(profilePath, undefined, undefined, false).catch(() => null);
        }
        if (pendingMessageRequestsRefresh) {
          await refreshMessageRequestsState(profilePath).catch(() => null);
        }
        if (pendingPolicyRefresh) {
          await refreshPolicyState(profilePath, { suppressTransientErrors: true }).catch(() => null);
        }
        if (shouldWarmup && transportConnectRef.current.token === token) {
          void continueTransportWarmup(profilePath, token);
        }
      }
    })();

    transportConnectRef.current = {
      token,
      profilePath,
      promise,
      pendingShellRefresh: false,
      pendingPolicyRefresh: false,
      pendingMessageRequestsRefresh: false,
    };
    return promise;
  }

  async function refreshDirectShell(
    explicitProfilePath?: string | null,
    explicitConversationId?: string | null,
    explicitContactUserId?: string | null,
    refreshPolicy = true,
    options?: { allowDuringTransportStartup?: boolean },
  ) {
    const profilePath = explicitProfilePath ?? state.bootstrap?.active_profile?.path ?? null;
    if (!profilePath) {
      return null;
    }
    if (!options?.allowDuringTransportStartup && isTransportStartupActive(profilePath)) {
      markPendingTransportRefresh(profilePath, "shell");
      return state.shell;
    }
    const selectedConversationId =
      explicitConversationId !== undefined
        ? explicitConversationId
        : selectionRef.current.selectedConversationId;
    const selectedContactUserId =
      explicitContactUserId !== undefined
        ? explicitContactUserId
        : selectionRef.current.selectedContactUserId;
    let shell = await directShell(profilePath, selectedConversationId, selectedContactUserId);
    if (
      selectedConversationId &&
      !shell.selected_conversation &&
      shell.conversations.some((conversation) => conversation.conversation_id === selectedConversationId)
    ) {
      shell = await directShell(profilePath, selectedConversationId, selectedContactUserId);
    }
    setState((current) => ({ ...current, shell, loading: false }));
    if (refreshPolicy && state.bootstrap?.onboarding.step === "complete") {
      await refreshPolicyState(profilePath, {
        suppressTransientErrors: true,
        allowDuringTransportStartup: options?.allowDuringTransportStartup,
      });
    }
    return shell;
  }

  async function refreshCloudflareState(explicitProfilePath?: string | null) {
    const profilePath = explicitProfilePath ?? state.bootstrap?.active_profile?.path ?? null;
    if (!profilePath) {
      return;
    }
    const [preflight, runtime] = await Promise.all([
      cloudflarePreflight(profilePath),
      cloudflareRuntimeDetails(profilePath),
    ]);
    const wizard = await cloudflareSetupWizardStatus(profilePath).catch(() => null);
    setState((current) => ({ ...current, cloudflarePreflight: preflight, cloudflareRuntime: runtime, cloudflareWizard: wizard }));
  }

  async function refreshContactShareLink(explicitProfilePath?: string | null) {
    const profilePath = explicitProfilePath ?? state.bootstrap?.active_profile?.path ?? null;
    if (!profilePath) {
      setContactShareLink(null);
      return;
    }
    const link = await contactShareLinkGet(profilePath).catch(() => null);
    setContactShareLink(link);
  }

  function shouldSuppressPolicyError(message: string) {
    return (
      message.includes("message requests were not returned by core") ||
      message.includes("allowlist document was not returned by core")
    );
  }

  async function refreshPolicyState(
    explicitProfilePath?: string | null,
    options?: { suppressTransientErrors?: boolean; allowDuringTransportStartup?: boolean },
  ) {
    const profilePath = explicitProfilePath ?? state.bootstrap?.active_profile?.path ?? null;
    const onboardingComplete = state.bootstrap?.onboarding.step === "complete";
    if (!profilePath || !onboardingComplete) {
      return;
    }
    if (!options?.allowDuringTransportStartup && isTransportStartupActive(profilePath)) {
      markPendingTransportRefresh(profilePath, "policy");
      return;
    }
    const [messageRequestsResult, allowlistResult] = await Promise.allSettled([
      messageRequestsList(profilePath),
      allowlistGet(profilePath),
    ]);
    const nextState: Partial<ViewState> = {};
    let transientError: string | null = null;
    if (messageRequestsResult.status === "fulfilled") {
      nextState.messageRequests = messageRequestsResult.value;
    } else {
      transientError = formatError(messageRequestsResult.reason);
    }
    if (allowlistResult.status === "fulfilled") {
      nextState.allowlist = allowlistResult.value;
    } else if (!transientError) {
      transientError = formatError(allowlistResult.reason);
    }
    setState((current) => ({ ...current, ...nextState }));
    if (
      transientError &&
      !(options?.suppressTransientErrors && shouldSuppressPolicyError(transientError)) &&
      !onboardingHandoffRef.current
    ) {
      setState((current) => ({ ...current, error: transientError }));
    }
  }

  async function refreshMessageRequestsState(
    explicitProfilePath?: string | null,
    options?: { allowDuringTransportStartup?: boolean },
  ) {
    const profilePath = explicitProfilePath ?? state.bootstrap?.active_profile?.path ?? null;
    const onboardingComplete = state.bootstrap?.onboarding.step === "complete";
    if (!profilePath || !onboardingComplete) {
      return;
    }
    if (!options?.allowDuringTransportStartup && isTransportStartupActive(profilePath)) {
      markPendingTransportRefresh(profilePath, "messageRequests");
      return;
    }
    try {
      const messageRequests = await messageRequestsList(profilePath);
      setState((current) => ({ ...current, messageRequests }));
    } catch (error) {
      const formatted = formatError(error);
      if (!shouldSuppressPolicyError(formatted)) {
        throw error;
      }
    }
  }

  async function runTask(task: () => Promise<void>) {
    setState((current) => ({ ...current, loading: true, error: null, success: null }));
    try {
      await task();
    } catch (error) {
      setState((current) => ({ ...current, loading: false, error: formatError(error), success: null }));
    }
  }

  async function runLocalTask(task: () => Promise<void>) {
    try {
      await task();
    } catch (error) {
      setState((current) => ({ ...current, error: formatError(error), success: null }));
    }
  }

  async function runCloudflareTask(action: string, task: () => Promise<void>) {
    setPendingAction(action);
    setState((current) => ({ ...current, error: null, success: null }));
    try {
      await task();
    } catch (error) {
      setState((current) => ({ ...current, error: formatError(error), success: null }));
    } finally {
      setPendingAction(null);
    }
  }

  async function chooseProfileRoot() {
    const selected = await open({ directory: true, multiple: false, title: "Choose a folder for the TapChat profile" });
    if (typeof selected === "string") {
      setCreateRoot(selected);
    }
  }

  async function chooseExistingProfileDirectory() {
    const selected = await open({ directory: true, multiple: false, title: "Open an existing TapChat profile directory" });
    if (typeof selected !== "string") {
      return;
    }
    await runTask(async () => {
      const profile = await profileOpenOrImport(selected);
      await profileActivate(profile.path);
      selectionRef.current = {
        selectedConversationId: null,
        selectedContactUserId: null,
      };
      setProfileSwitcherOpen(false);
      setActiveSection("chats");
      setSelectedAttachmentPaths([]);
      setPreview(null);
      setOnboardingStepOverride(null);
      setState((current) => ({
        ...current,
        selectedContactUserId: null,
        selectedConversationId: null,
        lastSend: null,
        lastAttachmentSend: null,
      }));
      await refreshBootstrap("Profile imported.");
    });
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
      await runCloudflareTask("bundle_import", async () => {
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
        setActiveSection("contacts");
        selectionRef.current = {
          selectedConversationId: null,
          selectedContactUserId: contact.user_id,
        };
        setState((current) => ({ ...current, selectedConversationId: null, selectedContactUserId: contact.user_id }));
        await refreshDirectShell(profilePath, null, contact.user_id);
        setState((current) => ({ ...current, success: "Contact imported. Select them to start a direct conversation." }));
      });
    }
  }

  async function handleStartCloudflareWizard(mode: "auto" | "custom") {
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!profilePath) return;
    await runCloudflareTask(mode === "custom" ? "wizard_custom" : "wizard_auto", async () => {
      const status = await cloudflareSetupWizardStart(
        profilePath,
        mode,
        mode === "custom" ? normalizeOverrides(overrides) : null,
      );
      setState((current) => ({ ...current, cloudflareWizard: status, loading: false }));
    });
  }

  async function handleCancelCloudflareWizard() {
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!profilePath) return;
    await runCloudflareTask("wizard_cancel", async () => {
      const status = await cloudflareSetupWizardCancel(profilePath);
      setState((current) => ({ ...current, cloudflareWizard: status, loading: false }));
    });
  }

  async function chooseAttachmentFile() {
    const selected = await open({ multiple: true, directory: false, title: "Choose files to send" });
    if (typeof selected === "string") {
      setSelectedAttachmentPaths((current) => dedupePaths([...current, selected]));
    } else if (Array.isArray(selected)) {
      setSelectedAttachmentPaths((current) => dedupePaths([...current, ...selected]));
    }
  }

  async function handleImportContactLink() {
    const profilePath = state.bootstrap?.active_profile?.path;
    const url = contactLinkDraft.trim();
    if (!profilePath || !url) return;
    await runTask(async () => {
      const contact = await contactImportShareLink(profilePath, url);
      setContactLinkDraft("");
      setActiveSection("contacts");
      selectionRef.current = {
        selectedConversationId: null,
        selectedContactUserId: contact.user_id,
      };
      setState((current) => ({ ...current, selectedConversationId: null, selectedContactUserId: contact.user_id }));
      await refreshDirectShell(profilePath, null, contact.user_id);
      setState((current) => ({ ...current, success: "Contact imported. Select them to start a direct conversation." }));
    });
  }

  async function handleCopyContactLink() {
    if (!contactShareLink?.url) {
      return;
    }
    await runLocalTask(async () => {
      await navigator.clipboard.writeText(contactShareLink.url);
      setState((current) => ({ ...current, success: "Contact link copied." }));
    });
  }

  async function handleRotateContactLink() {
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!profilePath) return;
    await runTask(async () => {
      const link = await contactShareLinkRotate(profilePath);
      setContactShareLink(link);
      setState((current) => ({ ...current, success: "Contact link rotated." }));
    });
  }

  async function handleCreateProfile() {
    await runTask(async () => {
      const profile = await profileCreate(createName, createRoot);
      await profileActivate(profile.path);
      setProfileSwitcherOpen(false);
      setActiveSection("chats");
      setOnboardingStepOverride(null);
      await refreshBootstrap(`Profile ${profile.name} created.`);
    });
  }

  async function handleShowCreateProfile() {
    setProfileSwitcherOpen(false);
    setActiveSection("chats");
    setDrawerMode("closed");
    setSelectedAttachmentPaths([]);
    setPreview(null);
    setShowContactQr(false);
    setState((current) => ({
      ...current,
      selectedContactUserId: null,
      selectedConversationId: null,
      lastSend: null,
      lastAttachmentSend: null,
      error: null,
      success: null,
    }));
    selectionRef.current = {
      selectedConversationId: null,
      selectedContactUserId: null,
    };
    setMnemonicBackupPending(false);
    setOnboardingStepOverride("choose_profile");
    await showOnboardingWindow();
  }

  async function handleRevealCurrentProfileDirectory() {
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!profilePath) return;
    await runLocalTask(async () => {
      await profileRevealInShell(profilePath);
      setProfileSwitcherOpen(false);
      setState((current) => ({ ...current, success: "Opened the current profile directory." }));
    });
  }

  async function handleActivateProfile(profile: ProfileSummary) {
    const previous = state.bootstrap?.active_profile?.path;
    await runTask(async () => {
      if (previous) {
        await syncRealtimeClose(previous);
      }
      setDrawerMode("closed");
      setProfileSwitcherOpen(false);
      setActiveSection("chats");
      await profileActivate(profile.path);
      selectionRef.current = {
        selectedConversationId: null,
        selectedContactUserId: null,
      };
      setState((current) => ({
        ...current,
        selectedContactUserId: null,
        selectedConversationId: null,
        lastSend: null,
        lastAttachmentSend: null,
        messageRequests: [],
        allowlist: null,
        cloudflarePreflight: null,
        cloudflareRuntime: null,
        cloudflareWizard: null,
      }));
      setOnboardingStepOverride(null);
      setMnemonicBackupPending(false);
      setSelectedAttachmentPaths([]);
      setPreview(null);
      setShowContactQr(false);
      if (reconnectTimerRef.current !== null) {
        window.clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
      setReconnectAttempt(0);
      setLastTransportError(null);
      setConnectionHealth("disconnected");
      await refreshBootstrap(`Switched to ${profile.name}.`);
    });
  }

  async function handleIdentityCreate() {
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!profilePath) return;
    await runTask(async () => {
      await waitForNextFrame();
      const identity = await identityCreate(profilePath, deviceName);
      setMnemonic(identity.mnemonic);
      setMnemonicBackupPending(true);
      await refreshBootstrap("Identity created.");
      setOnboardingStepOverride("mnemonic_backup");
    });
  }

  async function handleIdentityRecover() {
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!profilePath) return;
    await runTask(async () => {
      await waitForNextFrame();
      await identityRecover(profilePath, deviceName, mnemonic);
      setMnemonicBackupPending(false);
      setOnboardingStepOverride(null);
      await refreshBootstrap("Identity recovered.");
    });
  }

  function handleConfirmMnemonicBackup() {
    setMnemonicBackupPending(false);
    setOnboardingStepOverride(null);
    setState((current) => ({ ...current, success: "Recovery phrase backup confirmed." }));
  }

  function handleOnboardingBack() {
    const bootstrap = state.bootstrap?.onboarding;
    if (!bootstrap) {
      return;
    }
    if (wizardRunning) {
      return;
    }
    if (onboardingViewStep === "mnemonic_backup") {
      setOnboardingStepOverride("identity");
      return;
    }
    if (bootstrap.has_identity && !bootstrap.has_runtime_binding) {
      setOnboardingStepOverride("identity");
      return;
    }
    if (bootstrap.has_profiles && !bootstrap.has_identity) {
      setOnboardingStepOverride("choose_profile");
    }
  }

  async function handleRefreshRuntimeStatus() {
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!profilePath) return;
    await runCloudflareTask("runtime_refresh", async () => {
      await cloudflareStatus(profilePath);
      await refreshCloudflareState(profilePath);
      setState((current) => ({ ...current, success: "Runtime status refreshed." }));
    });
  }

  async function handleCloudflareRedeploy() {
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!profilePath) return;
    await runCloudflareTask("runtime_redeploy", async () => {
      const result = await cloudflareRedeploy(profilePath);
      await refreshBootstrap(result.banner.message);
    });
  }

  async function handleCloudflareRotateSecrets() {
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!profilePath) return;
    if (!window.confirm("Rotate Cloudflare secrets and re-bootstrap the current device? This will not delete cloud resources.")) return;
    await runCloudflareTask("runtime_rotate", async () => {
      const result = await cloudflareRotateSecrets(profilePath);
      await refreshBootstrap(result.banner.message);
    });
  }

  async function handleCloudflareDetach() {
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!profilePath) return;
    if (!window.confirm("Detach this profile from the Cloudflare runtime? This only unbinds the profile and does not delete cloud resources.")) return;
    await runCloudflareTask("runtime_detach", async () => {
      const result = await cloudflareDetach(profilePath);
      await refreshBootstrap(result.banner.message);
    });
  }

  async function handleRefreshContact(userId: string) {
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!profilePath) return;
    await runTask(async () => {
      await contactRefresh(profilePath, userId);
      await refreshDirectShell(profilePath);
      setState((current) => ({ ...current, success: `Refreshed ${userId}.` }));
    });
  }

  async function handleCreateDirectConversation() {
    const profilePath = state.bootstrap?.active_profile?.path;
    const peerUserId = state.selectedContactUserId;
    if (!profilePath || !peerUserId) return;
    await runTask(async () => {
      const conversation = await conversationCreateDirect(profilePath, peerUserId);
      setActiveSection("chats");
      selectionRef.current = {
        selectedConversationId: conversation.conversation_id,
        selectedContactUserId: peerUserId,
      };
      setState((current) => ({ ...current, selectedConversationId: conversation.conversation_id }));
      setSelectedAttachmentPaths([]);
      await refreshDirectShell(profilePath, conversation.conversation_id, peerUserId);
      setState((current) => ({ ...current, success: `Created conversation with ${peerUserId}.` }));
    });
  }

  async function handleSendMessage() {
    const profilePath = state.bootstrap?.active_profile?.path;
    const conversationId = state.selectedConversationId;
    if (!profilePath || !conversationId || !composerText.trim()) return;
    await runTask(async () => {
      const result = await messageSendText(profilePath, conversationId, composerText.trim());
      setComposerText("");
      setState((current) => ({ ...current, lastSend: result }));
      await refreshDirectShell(profilePath);
      setState((current) => ({ ...current, success: result.append_result?.queued_as_request ? "Message queued as a request." : "Message sent." }));
    });
  }

  async function handleSendAttachments() {
    const profilePath = state.bootstrap?.active_profile?.path;
    const conversationId = state.selectedConversationId;
    if (!profilePath || !conversationId || selectedAttachmentPaths.length === 0) return;
    await runTask(async () => {
      const result = await messageSendAttachments(profilePath, conversationId, selectedAttachmentPaths);
      setSelectedAttachmentPaths([]);
      setState((current) => ({ ...current, lastAttachmentSend: result }));
      await refreshDirectShell(profilePath);
      setState((current) => ({
        ...current,
        success: result.results.some((item) => item.append_result?.queued_as_request)
          ? "One or more attachments were queued as requests."
          : `Queued ${result.queued_count} attachment messages.`,
      }));
    });
  }

  async function handleDownloadAttachment(messageId: string, reference: string) {
    const profilePath = state.bootstrap?.active_profile?.path;
    const conversationId = state.selectedConversationId;
    if (!profilePath || !conversationId) return;
    const selected = await save({ title: "Save attachment", defaultPath: `${messageId}.bin` });
    if (!selected || Array.isArray(selected)) return;
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
    if (!profilePath) return;
    await runTask(async () => {
      await attachmentOpenLocal(profilePath, messageId);
      await refreshDirectShell(profilePath);
      setState((current) => ({ ...current, success: "Attachment opened." }));
    });
  }

  async function handlePreviewAttachment(messageId: string, reference: string) {
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!profilePath) return;
    await runTask(async () => {
      const nextPreview = await attachmentPreviewSource(profilePath, messageId, reference);
      setPreview(nextPreview);
      setState((current) => ({ ...current, loading: false, error: null }));
    });
  }

  async function handleManualSync() {
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!profilePath) return;
    await runTask(async () => {
      await syncOnce(profilePath);
      setReconnectAttempt(0);
      await refreshDirectShell(profilePath);
      setState((current) => ({ ...current, success: "Sync complete." }));
    });
  }

  async function handleMessageRequest(requestId: string, action: "accept" | "reject") {
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!profilePath) return;
    await runTask(async () => {
      const result = action === "accept"
        ? await messageRequestAccept(profilePath, requestId)
        : await messageRequestReject(profilePath, requestId);
      await refreshMessageRequestsState(profilePath);
      if (action === "accept") {
        const selectedConversationId = result.conversation_id ?? null;
        const selectedContactUserId = result.sender_user_id;
        selectionRef.current = {
          selectedConversationId,
          selectedContactUserId,
        };
        setActiveSection("chats");
        setState((current) => ({
          ...current,
          selectedConversationId,
          selectedContactUserId,
        }));
        await refreshDirectShell(
          profilePath,
          selectedConversationId ?? undefined,
          selectedContactUserId,
          false,
        );
        setState((current) => ({
          ...current,
          selectedConversationId,
          selectedContactUserId,
          success: result.auto_created_conversation
            ? "Request accepted. Direct conversation created."
            : "Request accepted. Direct conversation ready.",
        }));
        return;
      }

      await refreshDirectShell(profilePath, undefined, undefined, false);
      setActiveSection("requests");
      setState((current) => ({
        ...current,
        success: `Rejected request from ${result.sender_user_id}.`,
      }));
    });
  }

  async function handleAllowlistAdd() {
    const profilePath = state.bootstrap?.active_profile?.path;
    const nextUserId = allowlistDraft.trim();
    if (!profilePath || !nextUserId) return;
    await runTask(async () => {
      const next = await allowlistAdd(profilePath, nextUserId);
      setAllowlistDraft("");
      setState((current) => ({ ...current, allowlist: next, success: `Added ${nextUserId} to allowlist.` }));
      await refreshDirectShell(profilePath);
    });
  }

  async function handleAllowlistRemove(userId: string) {
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!profilePath) return;
    await runTask(async () => {
      const next = await allowlistRemove(profilePath, userId);
      setState((current) => ({ ...current, allowlist: next, success: `Removed ${userId} from allowlist.` }));
      await refreshDirectShell(profilePath);
    });
  }

  async function handleConversationRepair(action: "reconcile" | "rebuild") {
    const profilePath = state.bootstrap?.active_profile?.path;
    const conversationId = state.selectedConversationId;
    if (!profilePath || !conversationId) return;
    await runTask(async () => {
      if (action === "reconcile") {
        await conversationReconcile(profilePath, conversationId);
      } else {
        await conversationRebuild(profilePath, conversationId);
      }
      await refreshDirectShell(profilePath);
      setState((current) => ({ ...current, success: `${action === "reconcile" ? "Reconciled" : "Rebuilt"} conversation state.` }));
    });
  }

  function selectConversation(conversationId: string, peerUserId: string) {
    setSelectedAttachmentPaths([]);
    setPreview(null);
    const nextConversationId = conversationId;
    const nextContactUserId = peerUserId;
    selectionRef.current = {
      selectedConversationId: nextConversationId,
      selectedContactUserId: nextContactUserId,
    };
    setState((current) => ({
      ...current,
      selectedConversationId: nextConversationId,
      selectedContactUserId: nextContactUserId,
    }));
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!isOnboardingWindow && state.bootstrap?.onboarding.step === "complete" && profilePath) {
      void refreshDirectShell(profilePath, nextConversationId, nextContactUserId);
    }
  }

  function selectContact(userId: string, conversationId: string | null) {
    setSelectedAttachmentPaths([]);
    setPreview(null);
    const nextConversationId = conversationId;
    const nextContactUserId = userId;
    selectionRef.current = {
      selectedConversationId: nextConversationId,
      selectedContactUserId: nextContactUserId,
    };
    setState((current) => ({
      ...current,
      selectedContactUserId: nextContactUserId,
      selectedConversationId: nextConversationId,
    }));
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!isOnboardingWindow && state.bootstrap?.onboarding.step === "complete" && profilePath) {
      void refreshDirectShell(profilePath, nextConversationId, nextContactUserId);
    }
  }

  async function toggleBackgroundMode() {
    const profilePath = state.bootstrap?.active_profile?.path;
    if (!profilePath) return;
    await runTask(async () => {
      const enabled = await appSetBackgroundMode(profilePath, !backgroundEnabled);
      setBackgroundEnabled(enabled);
      setState((current) => ({
        ...current,
        loading: false,
        success: enabled
          ? "Background downloads enabled. Closing the window will keep TapChat in the tray."
          : "Background downloads disabled for this profile.",
      }));
    });
  }

  const bootstrap = state.bootstrap;
  const activeProfile = bootstrap?.active_profile ?? null;
  const step = bootstrap?.onboarding.step ?? "welcome";
  const effectiveStep = postOnboardingHandoffPending && step !== "complete" ? "complete" : step;
  const actualOnboardingViewStep: OnboardingViewStep = !bootstrap?.onboarding.has_profiles || !activeProfile
    ? "choose_profile"
    : !bootstrap.onboarding.has_identity
      ? "identity"
      : !bootstrap.onboarding.has_runtime_binding
        ? "runtime"
        : "complete";
  const onboardingViewStep: OnboardingViewStep = actualOnboardingViewStep === "complete"
    ? "complete"
    : onboardingStepOverride === "choose_profile"
      ? "choose_profile"
      : onboardingStepOverride === "identity" && (actualOnboardingViewStep === "identity" || actualOnboardingViewStep === "runtime")
        ? "identity"
        : mnemonicBackupPending && actualOnboardingViewStep === "runtime"
          ? "mnemonic_backup"
        : onboardingStepOverride === "runtime" && actualOnboardingViewStep === "runtime"
          ? "runtime"
          : actualOnboardingViewStep;
  const activeConversation = state.shell?.selected_conversation ?? null;
  const selectedContact = state.shell?.selected_contact ?? null;
  const selectedConversationId = state.selectedConversationId;
  const selectedContactUserId = state.selectedContactUserId;
  const runtimeDetails = state.cloudflareRuntime;
  const preflight = state.cloudflarePreflight;
  const cloudflareWizard = state.cloudflareWizard;

  const statusLabel = useMemo(() => connectionHealth, [connectionHealth]);
  const transportStatusMessage = useMemo(() => {
    if (effectiveStep !== "complete") {
      return "Finish onboarding to enable transport.";
    }
    if (!runtimeDetails?.deployment_bound) {
      return "Transport is ready locally, but no Cloudflare runtime is bound.";
    }
    switch (connectionHealth) {
      case "connecting":
        return "Connecting to Cloudflare transport...";
      case "connected":
        return "Cloudflare transport is connected.";
      case "reconnecting":
        return "Realtime disconnected. TapChat is retrying automatically.";
      case "degraded":
        return "Realtime is unavailable. Sync now still works while TapChat keeps retrying.";
      case "ready":
        return "Runtime is bound. Open chats or run Sync now to refresh state.";
      default:
        return lastTransportError ?? "Cloudflare transport is currently unavailable.";
    }
  }, [connectionHealth, effectiveStep, lastTransportError, runtimeDetails?.deployment_bound]);

  const composerStatus = state.lastAttachmentSend?.latest_notification
    ?? state.lastSend?.latest_notification
    ?? "Attachments are queued as separate messages. Drag files into the conversation or choose multiple files.";
  const navigationTitle = activeSection === "chats" ? "Chats" : activeSection === "contacts" ? "Contacts" : "Requests";
  const canOperateRuntime = step === "complete" && !!activeProfile;
  const recoveryRows = state.shell?.sync.recovery_conversations ?? [];
  const transferRows = state.shell?.attachment_transfers ?? [];
  const wizardRunning = !!cloudflareWizard && !["idle", "completed", "failed"].includes(cloudflareWizard.state);
  const canGoBackInOnboarding = onboardingViewStep === "identity"
    || onboardingViewStep === "mnemonic_backup"
    || (onboardingViewStep === "runtime" && !wizardRunning);

  return {
    isOnboardingWindow,
    state,
    createName,
    setCreateName,
    createRoot,
    setCreateRoot,
    deviceName,
    setDeviceName,
    mnemonic,
    setMnemonic,
    handleConfirmMnemonicBackup,
    overrides,
    setOverrides,
    activeSection,
    setActiveSection,
    drawerMode,
    setDrawerMode,
    profileSwitcherOpen,
    setProfileSwitcherOpen,
    composerText,
    setComposerText,
    selectedAttachmentPaths,
    setSelectedAttachmentPaths,
    downloadingMessageId,
    preview,
    setPreview,
    dropActive,
    backgroundEnabled,
    allowlistDraft,
    setAllowlistDraft,
    customWizardOpen,
    setCustomWizardOpen,
    pendingAction,
    contactLinkDraft,
    setContactLinkDraft,
    contactShareLink,
    showContactQr,
    setShowContactQr,
    theme,
    setTheme,
    bootstrap,
    activeProfile,
    step: effectiveStep,
    onboardingViewStep,
    canGoBackInOnboarding,
    activeConversation,
    selectedContact,
    selectedConversationId,
    selectedContactUserId,
    runtimeDetails,
    preflight,
    cloudflareWizard,
    connectionHealth,
    reconnectAttempt,
    lastTransportError,
    statusLabel,
    transportStatusMessage,
    composerStatus,
    navigationTitle,
    canOperateRuntime,
    recoveryRows,
    transferRows,
    wizardRunning,
    chooseProfileRoot,
    chooseExistingProfileDirectory,
    chooseDeploymentBundle,
    chooseIdentityBundle,
    handleCopyContactLink,
    handleRotateContactLink,
    handleImportContactLink,
    chooseAttachmentFile,
    handleCreateProfile,
    handleShowCreateProfile,
    handleActivateProfile,
    handleRevealCurrentProfileDirectory,
    handleOnboardingBack,
    handleIdentityCreate,
    handleIdentityRecover,
    handleStartCloudflareWizard,
    handleCancelCloudflareWizard,
    handleRefreshRuntimeStatus,
    handleCloudflareRedeploy,
    handleCloudflareRotateSecrets,
    handleCloudflareDetach,
    handleRefreshContact,
    handleCreateDirectConversation,
    handleSendMessage,
    handleSendAttachments,
    handleDownloadAttachment,
    handleOpenAttachment,
    handlePreviewAttachment,
    handleManualSync,
    handleMessageRequest,
    handleAllowlistAdd,
    handleAllowlistRemove,
    handleConversationRepair,
    selectConversation,
    selectContact,
    toggleBackgroundMode,
  };
}

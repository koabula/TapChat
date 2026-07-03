import { useEffect, useRef, useState } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";

import Welcome from "./pages/onboarding/Welcome";
import Identity from "./pages/onboarding/Identity";
import BackupMnemonic from "./pages/onboarding/BackupMnemonic";
import CloudflareSetup from "./pages/onboarding/CloudflareSetup";
import Complete from "./pages/onboarding/Complete";

import AppShell from "./pages/shell/AppShell";
import ChatView from "./pages/chat/ChatView";
import GroupsPage from "./pages/groups/GroupsPage";

import ContactList from "./pages/contacts/ContactList";
import ContactDetail from "./pages/contacts/ContactDetail";

import MessageRequests from "./pages/requests/MessageRequests";

import Settings from "./pages/settings/Settings";

import SystemBanner from "./components/SystemBanner";

import { useSessionStore } from "./store/session";
import {
  filterMessageRequestsForSession,
  useMessageRequestsStore,
} from "./store/requests";
import { useCoreUpdate } from "./hooks/useCoreUpdate";
import { useGroupSyncScheduler } from "./hooks/useGroupSyncScheduler";
import { useGlobalShortcuts } from "./hooks/useKeyboardShortcuts";
import { useNotifications } from "./hooks/useNotifications";
import { waitForNonBootstrappingSessionStatus } from "./lib/sessionStartup";
import {
  directRealtimeEventHandledByRustCore,
  shouldFrontendInvokeSyncForRealtimeEvent,
} from "./lib/realtimeEventPolicy";
import {
  lockedProfileRetryDisabled,
  lockedProfileRetryPayload,
  lockedProfileView,
} from "./lib/lockedProfile";
import { useThemeStore } from "./store/theme";

import type { ProfileSummary, SessionStatus, RealtimeEventPayload } from "./lib/types";
import type { MessageRequestItem } from "./store/requests";

function summarizeSessionStatus(status: SessionStatus): string {
  return `state=${status.state} ws_connected=${status.ws_connected} device_id=${status.device_id ?? "none"} lock_reason=${status.lock_reason ?? "none"} error=${status.error ?? "none"}`;
}

function summarizeRealtimeEvent(event: RealtimeEventPayload): string {
  return `type=${event.event_type} device_id=${event.device_id}`;
}

function isRuntimeAuthError(detail: string | undefined | null): boolean {
  const value = (detail ?? "").toLowerCase();
  return (
    value.includes("403") ||
    value.includes("forbidden") ||
    value.includes("capability_expired") ||
    value.includes("invalid_capability") ||
    value.includes("device runtime")
  );
}

/**
 * Inner app component that has Router context.
 * Hooks that use useNavigate() must be called here, inside BrowserRouter.
 */
function AppInner({ startupError }: { startupError: string | null }) {
  const { sessionState, unlockError, lockReason } = useSessionStore();
  const [unlockPassphrase, setUnlockPassphrase] = useState("");
  const [unlocking, setUnlocking] = useState(false);
  const [unlockSubmitError, setUnlockSubmitError] = useState<string | null>(null);
  const [profiles, setProfiles] = useState<ProfileSummary[]>([]);
  const [loadingProfiles, setLoadingProfiles] = useState(false);

  // Connect to core-update events
  useCoreUpdate();
  useGroupSyncScheduler();

  // Register global keyboard shortcuts (only when active - requires Router context)
  useGlobalShortcuts();

  // Handle OS native notifications
  useNotifications();

  // Route based on session state
  if (sessionState === "bootstrapping") {
    return (
      <div className="flex h-full min-h-0 bg-base">
        <div className="sidebar flex w-72 flex-col border-r border-default">
          <div className="flex items-center p-3 border-b border-default">
            <h1 className="font-semibold text-primary-color">TapChat</h1>
          </div>
          <div className="p-3 text-sm text-muted-color">Starting session...</div>
        </div>
        <div className="flex min-h-0 flex-1 items-center justify-center bg-base">
          <div className="text-center">
            <div className="text-primary-color font-medium">TapChat</div>
            <div className="mt-2 text-sm text-muted-color">
              {startupError ?? "Preparing your workspace"}
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (sessionState === "locked") {
    const lockedView = lockedProfileView(lockReason);

    const handleRetry = async () => {
      setUnlocking(true);
      setUnlockSubmitError(null);
      try {
        await invoke(
          "retry_locked_profile_startup",
          lockedProfileRetryPayload(lockReason, unlockPassphrase),
        );
        const status = await waitForNonBootstrappingSessionStatus(() =>
          invoke<SessionStatus>("get_session_status"),
        );
        const session = useSessionStore.getState();
        session.setSessionState(status.state);
        session.setUnlockError(status.error ?? null);
        session.setLockReason(status.lock_reason ?? null);
        session.setWsConnected(status.ws_connected);
        session.setDeviceId(status.device_id ?? null);
      } catch (err) {
        setUnlockSubmitError(String(err));
      } finally {
        setUnlocking(false);
      }
    };
    const handleShowProfiles = async () => {
      setLoadingProfiles(true);
      setUnlockSubmitError(null);
      try {
        setProfiles(await invoke<ProfileSummary[]>("list_profiles"));
      } catch (err) {
        setUnlockSubmitError(String(err));
      } finally {
        setLoadingProfiles(false);
      }
    };
    const handleActivateProfile = async (profile: ProfileSummary) => {
      setUnlocking(true);
      setUnlockSubmitError(null);
      try {
        await invoke("activate_profile", {
          path: profile.path,
          passphrase: unlockPassphrase || null,
        });
      } catch (err) {
        setUnlockSubmitError(String(err));
      } finally {
        setUnlocking(false);
      }
    };
    const handleOnboarding = async () => {
      setUnlockSubmitError(null);
      try {
        await invoke("start_new_profile_onboarding");
      } catch (err) {
        setUnlockSubmitError(String(err));
      }
    };

    return (
      <div className="flex h-full min-h-0 items-center justify-center bg-base p-8">
        <div className="w-full max-w-md space-y-4">
          <div>
            <h1 className="text-xl font-semibold text-primary-color">{lockedView.reasonLabel}</h1>
            <p className="mt-2 text-sm text-secondary-color">
              {unlockError ?? "TapChat could not unlock the active profile."}
            </p>
          </div>
          {lockedView.needsPassphrase && (
            <input
              className="input"
              type="password"
              placeholder="Profile passphrase"
              value={unlockPassphrase}
              onChange={(event) => setUnlockPassphrase(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter" && unlockPassphrase && !unlocking) {
                  void handleRetry();
                }
              }}
            />
          )}
          {unlockSubmitError && (
            <div className="status-error text-sm">{unlockSubmitError}</div>
          )}
          <div className="grid grid-cols-2 gap-2">
            <button
              className="btn btn-primary"
              disabled={lockedProfileRetryDisabled(lockReason, unlockPassphrase, unlocking)}
              onClick={handleRetry}
            >
              {unlocking ? "Retrying..." : lockedView.primaryActionLabel}
            </button>
            <button className="btn" disabled={loadingProfiles} onClick={handleShowProfiles}>
              {loadingProfiles ? "Loading..." : "Switch Profile"}
            </button>
            <button className="btn" onClick={handleOnboarding}>New Profile</button>
            <button className="btn" onClick={handleOnboarding}>Recover</button>
          </div>
          {profiles.length > 0 && (
            <div className="space-y-2 border-t border-default pt-3">
              {profiles.map((profile) => (
                <button
                  key={profile.path}
                  className="btn w-full justify-start"
                  disabled={unlocking}
                  onClick={() => void handleActivateProfile(profile)}
                >
                  {profile.name}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    );
  }

  const isOnboarding = sessionState.startsWith("onboarding") || sessionState === "uninitialized";
  const onboardingDefaultRoute =
    sessionState === "onboarding:cloudflaresetup"
      ? "/onboarding/cloudflare"
      : sessionState === "onboarding:backupmnemonic"
        ? "/onboarding/backup"
        : sessionState === "onboarding:createidentity" || sessionState === "onboarding:recoveridentity"
          ? "/onboarding/identity"
          : "/onboarding";

  return (
    <>
      {/* System banners for sync status and errors */}
      {!isOnboarding && <SystemBanner />}

      <Routes>
        {/* Onboarding routes - accessible only when not active */}
        {isOnboarding && (
          <>
            <Route path="/onboarding" element={<Welcome />} />
            <Route path="/onboarding/identity" element={<Identity />} />
            <Route path="/onboarding/backup" element={<BackupMnemonic />} />
            <Route path="/onboarding/cloudflare" element={<CloudflareSetup />} />
            <Route path="/onboarding/complete" element={<Complete />} />
            <Route path="*" element={<Navigate to={onboardingDefaultRoute} replace />} />
          </>
        )}

        {/* Main app routes - accessible only when active */}
        {!isOnboarding && (
          <>
            <Route path="/" element={<AppShell />}>
              <Route index element={<ChatView />} />
              <Route path="chat/:id" element={<ChatView />} />
              <Route path="groups" element={<GroupsPage />} />
              <Route path="contacts" element={<ContactList />} />
              <Route path="contacts/:id" element={<ContactDetail />} />
              <Route path="requests" element={<MessageRequests />} />
              <Route path="settings" element={<Settings />} />
              <Route path="settings/devices" element={<Settings initialSection="devices" />} />
              <Route path="settings/runtime" element={<Settings initialSection="runtime" />} />
            </Route>
            <Route path="*" element={<Navigate to="/" replace />} />
          </>
        )}
      </Routes>
    </>
  );
}

function App() {
  const { setSessionState, setWsConnected, setDeviceId, setUnlockError, setLockReason } = useSessionStore();
  const hydrateTheme = useThemeStore((s) => s.hydrateTheme);
  const handleSystemThemeChanged = useThemeStore((s) => s.handleSystemThemeChanged);
  const setRequests = useMessageRequestsStore((s) => s.setRequests);
  const [statusResolved, setStatusResolved] = useState(false);
  const [startupError, setStartupError] = useState<string | null>(null);
  const isProfileSwitchingRef = useRef(false);

  useEffect(() => {
    hydrateTheme();
    if (typeof window.matchMedia !== "function") {
      return;
    }

    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const listener = () => handleSystemThemeChanged();
    media.addEventListener("change", listener);
    return () => media.removeEventListener("change", listener);
  }, [hydrateTheme, handleSystemThemeChanged]);

  // Subscribe to Tauri events on mount (these don't need Router context)
  useEffect(() => {
    const mountedAt = performance.now();

    const refreshMessageRequests = async () => {
      const before = useSessionStore.getState();
      const result = await invoke<{ view_model?: { message_requests?: MessageRequestItem[] } }>("list_message_requests");
      const after = useSessionStore.getState();
      if (before.deviceId !== after.deviceId || before.userId !== after.userId) {
        console.debug("[App] discarded message request refresh after session changed");
        return;
      }
      if (result.view_model?.message_requests) {
        const filtered = filterMessageRequestsForSession(
          result.view_model.message_requests,
          after.deviceId,
          after.userId,
        );
        setRequests(filtered);
        console.debug(`[App] message requests refreshed count=${filtered.length}`);
      }
    };

    // Subscribe to session-status events
    const unlistenSessionStatus = listen<SessionStatus>("session-status", (event) => {
      console.debug(`[App] session-status ${summarizeSessionStatus(event.payload)}`);
      setSessionState(event.payload.state);
      setUnlockError(event.payload.error ?? null);
      setLockReason(event.payload.lock_reason ?? null);
      setWsConnected(event.payload.ws_connected);
      setDeviceId(event.payload.device_id ?? null);
    });

    // Subscribe to profile switch events to track state
    const unlistenProfileSwitchStart = listen<void>("profile-switch-start", () => {
      console.debug("[App] profile-switch-start");
      isProfileSwitchingRef.current = true;
      setWsConnected(false);
      setRequests([]);
    });

    const unlistenProfileSwitchComplete = listen<void>("profile-switch-complete", () => {
      console.debug("[App] profile-switch-complete");
      isProfileSwitchingRef.current = false;
    });

    // Subscribe to realtime WebSocket events
    const unlistenRealtime = listen<RealtimeEventPayload>("realtime-event", (event) => {
      console.debug(`[App] realtime-event ${summarizeRealtimeEvent(event.payload)}`);
      const { event_type } = event.payload;

      switch (event_type) {
        case "connected":
          setWsConnected(true);
          break;
        case "disconnected":
          setWsConnected(false);
          if (shouldFrontendInvokeSyncForRealtimeEvent(event_type)) {
            console.warn("[App] unexpected frontend sync policy for disconnected event");
          }
          if (isProfileSwitchingRef.current) {
            console.debug("[App] websocket disconnected during profile switch");
          }
          break;
        case "error":
          setWsConnected(false);
          if (shouldFrontendInvokeSyncForRealtimeEvent(event_type)) {
            console.warn("[App] unexpected frontend sync policy for websocket error event");
          }
          console.warn(`[App] websocket error ${event.payload.device_id}: ${event.payload.data ?? "unknown"}`);
          if (isRuntimeAuthError(event.payload.data)) {
            console.warn("[App] websocket auth error detected; waiting for explicit refresh instead of auto-retrying");
          }
          break;
        case "message_request_changed":
          if (
            useSessionStore.getState().deviceId &&
            event.payload.device_id !== useSessionStore.getState().deviceId
          ) {
            console.debug(
              `[App] ignored stale message_request_changed for device_id=${event.payload.device_id}`,
            );
            break;
          }
          // Refresh message requests from backend
          refreshMessageRequests()
            .catch((err) => {
              console.error(`[App] failed to refresh message requests: ${String(err)}`);
            });
          break;
        case "inbox_record_available":
        case "head_updated":
          if (directRealtimeEventHandledByRustCore(event_type)) {
            console.debug(`[App] ${event_type} handled by Rust core`);
          }
          break;
      }
    });

    // Subscribe to websocket connection events (legacy)
    const unlistenWsConnect = listen<{ device_id: string }>("websocket-connected", (event) => {
      console.debug(`[App] websocket-connected device_id=${event.payload.device_id}`);
      setWsConnected(true);
    });

    const unlistenWsDisconnect = listen<{ device_id: string; reason?: string }>("websocket-disconnected", (event) => {
      console.debug(`[App] websocket-disconnected device_id=${event.payload.device_id} reason=${event.payload.reason ?? "none"}`);
      setWsConnected(false);
    });

    // Fetch initial session status
    setStartupError(null);
    waitForNonBootstrappingSessionStatus(() => invoke<SessionStatus>("get_session_status"))
      .then((status) => {
        const elapsedMs = Math.round(performance.now() - mountedAt);
        console.debug(
          `[App] get_session_status resolved in ${elapsedMs}ms ${summarizeSessionStatus(status)}`,
        );
        console.debug(`[App] initial session-status ${summarizeSessionStatus(status)}`);
        setSessionState(status.state);
        setUnlockError(status.error ?? null);
        setLockReason(status.lock_reason ?? null);
        setWsConnected(status.ws_connected);
        setDeviceId(status.device_id ?? null);
        setStatusResolved(true);
      })
      .catch((err) => {
        console.error(`[App] failed to get session status: ${String(err)}`);
        setStartupError(String(err));
        setSessionState("bootstrapping");
        setStatusResolved(true);
      });

    return () => {
      unlistenSessionStatus.then((fn) => fn());
      unlistenProfileSwitchStart.then((fn) => fn());
      unlistenProfileSwitchComplete.then((fn) => fn());
      unlistenRealtime.then((fn) => fn());
      unlistenWsConnect.then((fn) => fn());
      unlistenWsDisconnect.then((fn) => fn());
    };
  }, [setSessionState, setWsConnected, setRequests, setDeviceId, setUnlockError, setLockReason]);

  return (
    <BrowserRouter>
      <AppInner key={statusResolved ? "resolved" : "bootstrapping"} startupError={startupError} />
    </BrowserRouter>
  );
}

export default App;

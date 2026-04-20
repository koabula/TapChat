import { useEffect, useRef, useState } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";

import Welcome from "./pages/onboarding/Welcome";
import Identity from "./pages/onboarding/Identity";
import BackupMnemonic from "./pages/onboarding/BackupMnemonic";
import CloudflareSetup from "./pages/onboarding/CloudflareSetup";
import Complete from "./pages/onboarding/Complete";

import ChatLayout from "./pages/chat/ChatLayout";
import ChatView from "./pages/chat/ChatView";

import ContactList from "./pages/contacts/ContactList";
import ContactDetail from "./pages/contacts/ContactDetail";

import MessageRequests from "./pages/requests/MessageRequests";

import Settings from "./pages/settings/Settings";
import Devices from "./pages/settings/Devices";
import Runtime from "./pages/settings/Runtime";

import SystemBanner from "./components/SystemBanner";
import { UpdateNotification } from "./hooks/useAutoUpdate";

import { useSessionStore } from "./store/session";
import { useMessageRequestsStore } from "./store/requests";
import { useCoreUpdate } from "./hooks/useCoreUpdate";
import { useGlobalShortcuts } from "./hooks/useKeyboardShortcuts";
import { useNotifications } from "./hooks/useNotifications";

import type { SessionStatus, RealtimeEventPayload } from "./lib/types";
import type { MessageRequestItem } from "./store/requests";

function summarizeSessionStatus(status: SessionStatus): string {
  return `state=${status.state} ws_connected=${status.ws_connected} device_id=${status.device_id ?? "none"}`;
}

function summarizeRealtimeEvent(event: RealtimeEventPayload): string {
  return `type=${event.event_type} device_id=${event.device_id}`;
}

function isBenignMessageRequestSyncError(error: unknown): boolean {
  const message = String(error);
  return (
    message.includes("unknown request_id") ||
    message.includes("message request not found") ||
    message.includes("not_found")
  );
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
function AppInner() {
  const { sessionState } = useSessionStore();

  // Connect to core-update events
  useCoreUpdate();

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
              Preparing your workspace
            </div>
          </div>
        </div>
      </div>
    );
  }

  const isOnboarding = sessionState.startsWith("onboarding") || sessionState === "uninitialized";

  return (
    <>
      {/* System banners for sync status and errors */}
      {!isOnboarding && <SystemBanner />}

      {/* Update notification */}
      {!isOnboarding && <UpdateNotification />}

      <Routes>
        {/* Onboarding routes - accessible only when not active */}
        {isOnboarding && (
          <>
            <Route path="/onboarding" element={<Welcome />} />
            <Route path="/onboarding/identity" element={<Identity />} />
            <Route path="/onboarding/backup" element={<BackupMnemonic />} />
            <Route path="/onboarding/cloudflare" element={<CloudflareSetup />} />
            <Route path="/onboarding/complete" element={<Complete />} />
            <Route path="*" element={<Navigate to="/onboarding" replace />} />
          </>
        )}

        {/* Main app routes - accessible only when active */}
        {!isOnboarding && (
          <>
            <Route path="/" element={<ChatLayout />}>
              <Route index element={<ChatView />} />
              <Route path="chat/:id" element={<ChatView />} />
            </Route>
            <Route path="/contacts" element={<ContactList />} />
            <Route path="/contacts/:id" element={<ContactDetail />} />
            <Route path="/requests" element={<MessageRequests />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/settings/devices" element={<Devices />} />
            <Route path="/settings/runtime" element={<Runtime />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </>
        )}
      </Routes>
    </>
  );
}

function App() {
  const { setSessionState, setWsConnected, setDeviceId, setSyncInFlight } = useSessionStore();
  const setRequests = useMessageRequestsStore((s) => s.setRequests);
  const [statusResolved, setStatusResolved] = useState(false);
  const isProfileSwitchingRef = useRef(false);
  const syncInFlightRef = useRef(false);
  const syncPendingRef = useRef(false);

  // Subscribe to Tauri events on mount (these don't need Router context)
  useEffect(() => {
    const mountedAt = performance.now();

    const refreshMessageRequests = async () => {
      const result = await invoke<{ view_model?: { message_requests?: MessageRequestItem[] } }>("list_message_requests");
      if (result.view_model?.message_requests) {
        setRequests(result.view_model.message_requests);
        console.debug(`[App] message requests refreshed count=${result.view_model.message_requests.length}`);
      }
    };

    const scheduleSync = () => {
      if (isProfileSwitchingRef.current) {
        console.debug("[App] skipping sync during profile switch");
        return;
      }

      if (syncInFlightRef.current) {
        syncPendingRef.current = true;
        console.debug("[App] sync already in flight; marked trailing sync");
        return;
      }

      syncInFlightRef.current = true;
      setSyncInFlight(true);

      const runSync = async () => {
        try {
          await invoke("sync_now");
          console.debug("[App] sync completed");
        } catch (err) {
          if (isBenignMessageRequestSyncError(err)) {
            console.warn(`[App] benign sync race ignored: ${String(err)}`);
            try {
              await refreshMessageRequests();
            } catch (refreshErr) {
              console.warn(`[App] message request refresh after benign sync race failed: ${String(refreshErr)}`);
            }
          } else {
            console.error(`[App] sync failed: ${String(err)}`);
          }
        } finally {
          if (syncPendingRef.current) {
            syncPendingRef.current = false;
            console.debug("[App] running trailing sync");
            void runSync();
            return;
          }
          syncInFlightRef.current = false;
          setSyncInFlight(false);
        }
      };

      void runSync();
    };

    // Subscribe to session-status events
    const unlistenSessionStatus = listen<SessionStatus>("session-status", (event) => {
      console.debug(`[App] session-status ${summarizeSessionStatus(event.payload)}`);
      setSessionState(event.payload.state);
      setWsConnected(event.payload.ws_connected);
      if (event.payload.device_id) {
        setDeviceId(event.payload.device_id);
      }
    });

    // Subscribe to profile switch events to track state
    const unlistenProfileSwitchStart = listen<void>("profile-switch-start", () => {
      console.debug("[App] profile-switch-start");
      isProfileSwitchingRef.current = true;
      setWsConnected(false);
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
          // Only attempt reconnect if not in profile switch mode
          if (!isProfileSwitchingRef.current) {
            console.debug("[App] websocket disconnected; scheduling reconnect");
            // Schedule a reconnect attempt after a short delay
            setTimeout(() => {
              if (!isProfileSwitchingRef.current) {
                scheduleSync();
              }
            }, 2000);
          } else {
            console.debug("[App] websocket disconnected during profile switch");
          }
          break;
        case "error":
          setWsConnected(false);
          console.warn(`[App] websocket error ${event.payload.device_id}: ${event.payload.data ?? "unknown"}`);
          // Avoid tight reconnect loops when runtime auth is invalid or expired.
          if (!isProfileSwitchingRef.current && !isRuntimeAuthError(event.payload.data)) {
            setTimeout(() => {
              if (!isProfileSwitchingRef.current) {
                scheduleSync();
              }
            }, 3000);
          } else if (isRuntimeAuthError(event.payload.data)) {
            console.warn("[App] websocket auth error detected; waiting for explicit refresh instead of auto-retrying");
          }
          break;
        case "message_request_changed":
          // Refresh message requests from backend
          refreshMessageRequests()
            .catch((err) => {
              console.error(`[App] failed to refresh message requests: ${String(err)}`);
            });
          break;
        case "inbox_record_available":
          scheduleSync();
          break;
        case "head_updated":
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
    invoke<SessionStatus>("get_session_status")
      .then((status) => {
        const elapsedMs = Math.round(performance.now() - mountedAt);
        console.debug(
          `[App] get_session_status resolved in ${elapsedMs}ms ${summarizeSessionStatus(status)}`,
        );
        console.debug(`[App] initial session-status ${summarizeSessionStatus(status)}`);
        setSessionState(status.state);
        setWsConnected(status.ws_connected);
        if (status.device_id) {
          setDeviceId(status.device_id);
        }
        setStatusResolved(true);
      })
      .catch((err) => {
        console.error(`[App] failed to get session status: ${String(err)}`);
        setSessionState("uninitialized");
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
  }, [setSessionState, setWsConnected, setRequests, setDeviceId, setSyncInFlight]);

  return (
    <BrowserRouter>
      <AppInner key={statusResolved ? "resolved" : "bootstrapping"} />
    </BrowserRouter>
  );
}

export default App;

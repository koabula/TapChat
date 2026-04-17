import { useEffect, useState } from "react";
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
  const { setSessionState, setWsConnected, setDeviceId } = useSessionStore();
  const setRequests = useMessageRequestsStore((s) => s.setRequests);
  const [loading, setLoading] = useState(true);

  // Subscribe to Tauri events on mount (these don't need Router context)
  useEffect(() => {
    // Subscribe to session-status events
    const unlistenSessionStatus = listen<SessionStatus>("session-status", (event) => {
      console.log("[App] session-status:", event.payload);
      setSessionState(event.payload.state);
      setWsConnected(event.payload.ws_connected);
      if (event.payload.device_id) {
        setDeviceId(event.payload.device_id);
      }
    });

    // Subscribe to realtime WebSocket events
    const unlistenRealtime = listen<RealtimeEventPayload>("realtime-event", (event) => {
      console.log("[App] realtime-event:", event.payload);
      const { event_type } = event.payload;

      switch (event_type) {
        case "connected":
          setWsConnected(true);
          break;
        case "disconnected":
          setWsConnected(false);
          // Trigger reconnection via sync
          console.log("[App] WebSocket disconnected, triggering sync for reconnection...");
          invoke("sync_now").catch((err) => {
            console.error("[App] Failed to trigger sync for reconnection:", err);
          });
          break;
        case "message_request_changed":
          // Refresh message requests from backend
          invoke<{ view_model?: { message_requests?: MessageRequestItem[] } }>("list_message_requests")
            .then((result) => {
              if (result.view_model?.message_requests) {
                setRequests(result.view_model.message_requests);
              }
            })
            .catch((err) => {
              console.error("[App] Failed to refresh message requests:", err);
            });
          break;
        case "head_updated":
        case "inbox_record_available":
          // These events indicate new messages - trigger sync to fetch them
          console.log("[App] Realtime event received, triggering sync...");
          invoke("sync_now").catch((err) => {
            console.error("[App] Failed to sync:", err);
          });
          break;
      }
    });

    // Subscribe to websocket connection events (legacy)
    const unlistenWsConnect = listen<{ device_id: string }>("websocket-connected", (event) => {
      console.log("[App] WebSocket connected:", event.payload);
      setWsConnected(true);
    });

    const unlistenWsDisconnect = listen<{ device_id: string; reason?: string }>("websocket-disconnected", (event) => {
      console.log("[App] WebSocket disconnected:", event.payload);
      setWsConnected(false);
    });

    // Fetch initial session status
    invoke<SessionStatus>("get_session_status")
      .then((status) => {
        setSessionState(status.state);
        setWsConnected(status.ws_connected);
        setLoading(false);
      })
      .catch((err) => {
        console.error("[App] Failed to get session status:", err);
        setLoading(false);
      });

    return () => {
      unlistenSessionStatus.then((fn) => fn());
      unlistenRealtime.then((fn) => fn());
      unlistenWsConnect.then((fn) => fn());
      unlistenWsDisconnect.then((fn) => fn());
    };
  }, [setSessionState, setWsConnected, setRequests]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen bg-base">
        <div className="text-muted-color">Loading...</div>
      </div>
    );
  }

  return (
    <BrowserRouter>
      <AppInner />
    </BrowserRouter>
  );
}

export default App;
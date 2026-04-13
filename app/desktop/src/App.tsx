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

import { useSessionStore } from "./store/session";
import { useCoreUpdate } from "./hooks/useCoreUpdate";

import type { SessionStatus } from "./lib/types";

function App() {
  const { sessionState, setSessionState, setWsConnected } = useSessionStore();
  const [loading, setLoading] = useState(true);

  // Connect to core-update events
  useCoreUpdate();

  // Subscribe to Tauri events on mount
  useEffect(() => {
    // Subscribe to session-status events
    const unlistenSessionStatus = listen<SessionStatus>("session-status", (event) => {
      console.log("[App] session-status:", event.payload);
      setSessionState(event.payload.state);
      setWsConnected(event.payload.ws_connected);
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
    };
  }, [setSessionState, setWsConnected]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen bg-base">
        <div className="text-muted-color">Loading...</div>
      </div>
    );
  }

  // Route based on session state
  const isOnboarding = sessionState.startsWith("onboarding") || sessionState === "uninitialized";

  return (
    <BrowserRouter>
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
            <Route path="*" element={<Navigate to="/" replace />} />
          </>
        )}
      </Routes>
    </BrowserRouter>
  );
}

export default App;
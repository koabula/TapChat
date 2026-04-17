import { useState, useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";

interface BannerData {
  status: "sync_in_progress" | "identity_refresh_needed" | "conversation_needs_rebuild" | "attachment_upload_failed" | "temporary_network_failure" | "message_queued_for_approval" | "message_rejected_by_policy";
  message: string;
}

interface CoreUpdateEvent {
  state_update: {
    system_statuses_changed: BannerData[];
  };
}

interface RealtimeEventPayload {
  device_id: string;
  event_type: string;
  data?: string;
}

const statusIcons: Record<BannerData["status"], string> = {
  sync_in_progress: "⏳",
  identity_refresh_needed: "🔐",
  conversation_needs_rebuild: "🔧",
  attachment_upload_failed: "📎",
  temporary_network_failure: "📶",
  message_queued_for_approval: "📬",
  message_rejected_by_policy: "🚫",
};

const statusColors: Record<BannerData["status"], string> = {
  sync_in_progress: "bg-frost.3 text-polar.1",
  identity_refresh_needed: "bg-aurora.orange text-polar.1",
  conversation_needs_rebuild: "bg-aurora.yellow text-polar.1",
  attachment_upload_failed: "bg-aurora.red text-polar.1",
  temporary_network_failure: "bg-aurora.red text-polar.1",
  message_queued_for_approval: "bg-frost.2 text-polar.1",
  message_rejected_by_policy: "bg-aurora.red text-polar.1",
};

/**
 * System banner component for displaying sync status, errors, and warnings.
 * Appears at the top of the main chat layout when there are system statuses.
 */
export default function SystemBanner() {
  const [banners, setBanners] = useState<BannerData[]>([]);
  const [dismissed, setDismissed] = useState<Set<string>>(new Set());

  useEffect(() => {
    // Listen for core-update events to show/hide banners
    const unlisten = listen<CoreUpdateEvent>("core-update", (event) => {
      const { state_update } = event.payload;
      if (state_update.system_statuses_changed && state_update.system_statuses_changed.length > 0) {
        // Add new banners, filter out dismissed ones
        const newBanners = state_update.system_statuses_changed.filter(
          (b) => !dismissed.has(b.status)
        );
        setBanners(newBanners);
      } else {
        // Clear banners if no statuses
        setBanners([]);
      }
    });

    return () => {
      unlisten.then((fn) => fn());
    };
  }, [dismissed]);

  const handleDismiss = (status: BannerData["status"]) => {
    setDismissed((prev) => new Set([...prev, status]));
    setBanners((prev) => prev.filter((b) => b.status !== status));
  };

  if (banners.length === 0) {
    return null;
  }

  return (
    <div className="fixed top-0 left-0 right-0 z-50 flex flex-col gap-1 p-2">
      {banners.map((banner) => (
        <div
          key={banner.status}
          className={`flex items-center justify-between px-3 py-2 rounded-lg shadow-lg ${statusColors[banner.status]}`}
        >
          <div className="flex items-center gap-2">
            <span className="text-lg">{statusIcons[banner.status]}</span>
            <span className="text-sm font-medium">{banner.message}</span>
          </div>
          <button
            className="text-sm px-2 hover:opacity-70"
            onClick={() => handleDismiss(banner.status)}
          >
            ✕
          </button>
        </div>
      ))}
    </div>
  );
}

/**
 * Network status indicator for the sidebar.
 * Shows connection state without being intrusive.
 * Listen to realtime-event for accurate status.
 * Handles profile switch gracefully without showing disconnect during switch.
 */
export function NetworkIndicator() {
  const [connected, setConnected] = useState<boolean | null>(null); // null = unknown
  const [syncing, setSyncing] = useState(false);
  const [isProfileSwitching, setIsProfileSwitching] = useState(false);
  const [lastDisconnectTime, setLastDisconnectTime] = useState<number | null>(null);

  useEffect(() => {
    // Listen to profile-switch events to track when we're switching profiles
    const unlistenProfileSwitchStart = listen<void>("profile-switch-start", () => {
      console.log("[NetworkIndicator] profile-switch-start");
      setIsProfileSwitching(true);
      setConnected(null); // Reset to unknown during switch
      setLastDisconnectTime(null);
    });

    const unlistenProfileSwitchComplete = listen<void>("profile-switch-complete", () => {
      console.log("[NetworkIndicator] profile-switch-complete");
      setIsProfileSwitching(false);
      setLastDisconnectTime(null);
    });

    // Listen to realtime-event for connection status
    const unlistenRealtime = listen<RealtimeEventPayload>("realtime-event", (event) => {
      const { event_type } = event.payload;
      console.log("[NetworkIndicator] realtime-event:", event_type);

      // Skip handling during profile switch
      if (isProfileSwitching) {
        console.log("[NetworkIndicator] skipping event during profile switch");
        return;
      }

      switch (event_type) {
        case "connected":
          setConnected(true);
          setLastDisconnectTime(null);
          break;
        case "disconnected":
          setConnected(false);
          setLastDisconnectTime(Date.now());
          break;
        case "error":
          setConnected(false);
          setLastDisconnectTime(Date.now());
          break;
      }
    });

    // Listen for sync status
    const unlistenSync = listen<CoreUpdateEvent>("core-update", (event) => {
      const { state_update } = event.payload;
      const hasSyncStatus = state_update.system_statuses_changed?.some(
        (s) => s.status === "sync_in_progress"
      );
      setSyncing(hasSyncStatus);
    });

    // Check initial connection status
    invoke<{ ws_connected: boolean }>("get_session_status")
      .then((status) => {
        if (!isProfileSwitching) {
          setConnected(status.ws_connected);
        }
      })
      .catch((err) => {
        console.error("[NetworkIndicator] Failed to get session status:", err);
      });

    return () => {
      unlistenProfileSwitchStart.then((fn) => fn());
      unlistenProfileSwitchComplete.then((fn) => fn());
      unlistenRealtime.then((fn) => fn());
      unlistenSync.then((fn) => fn());
    };
  }, [isProfileSwitching]);

  // Check if we've been disconnected for more than 5 seconds (not just brief flicker)
  const isLongDisconnect = lastDisconnectTime !== null &&
    (Date.now() - lastDisconnectTime) > 5000;

  const handleReconnect = async () => {
    console.log("[NetworkIndicator] Manual reconnect triggered");
    setSyncing(true);
    try {
      await invoke("sync_now");
    } catch (err) {
      console.error("[NetworkIndicator] Reconnect failed:", err);
    }
    // Sync status will be updated via core-update event
  };

  return (
    <div className="flex items-center gap-1 px-2 py-1 text-xs">
      {syncing ? (
        <>
          <span className="w-2 h-2 rounded-full bg-frost.3 animate-pulse" />
          <span className="text-muted-color">Syncing...</span>
        </>
      ) : connected === true ? (
        <>
          <span className="w-2 h-2 rounded-full status-success" />
          <span className="text-muted-color">Connected</span>
        </>
      ) : connected === false ? (
        <>
          <span className={`w-2 h-2 rounded-full ${isLongDisconnect ? "status-error" : "bg-frost.3"} animate-pulse`} />
          {isLongDisconnect ? (
            <button
              className="text-error hover:underline"
              onClick={handleReconnect}
              title="Click to reconnect"
            >
              Offline (Reconnect)
            </button>
          ) : (
            <span className="text-muted-color">Reconnecting...</span>
          )}
        </>
      ) : (
        <>
          <span className="w-2 h-2 rounded-full bg-muted-color" />
          <span className="text-muted-color">
            {isProfileSwitching ? "Switching..." : "Checking..."}
          </span>
        </>
      )}
    </div>
  );
}
import { useState, useEffect } from "react";
import { listen } from "@tauri-apps/api/event";

interface BannerData {
  status: "sync_in_progress" | "identity_refresh_needed" | "conversation_needs_rebuild" | "attachment_upload_failed" | "temporary_network_failure" | "message_queued_for_approval" | "message_rejected_by_policy";
  message: string;
}

interface CoreUpdateEvent {
  state_update: {
    system_statuses_changed: BannerData[];
  };
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
 */
export function NetworkIndicator() {
  const [connected, setConnected] = useState(true);
  const [syncing, setSyncing] = useState(false);

  useEffect(() => {
    const unlistenConnect = listen<{ device_id: string }>("websocket-connected", () => {
      setConnected(true);
    });

    const unlistenDisconnect = listen<{ device_id: string; reason?: string }>("websocket-disconnected", () => {
      setConnected(false);
    });

    const unlistenSync = listen<CoreUpdateEvent>("core-update", (event) => {
      const { state_update } = event.payload;
      const hasSyncStatus = state_update.system_statuses_changed?.some(
        (s) => s.status === "sync_in_progress"
      );
      setSyncing(hasSyncStatus);
    });

    return () => {
      unlistenConnect.then((fn) => fn());
      unlistenDisconnect.then((fn) => fn());
      unlistenSync.then((fn) => fn());
    };
  }, []);

  return (
    <div className="flex items-center gap-1 px-2 py-1 text-xs">
      {syncing ? (
        <>
          <span className="w-2 h-2 rounded-full bg-frost.3 animate-pulse" />
          <span className="text-muted-color">Syncing...</span>
        </>
      ) : connected ? (
        <>
          <span className="w-2 h-2 rounded-full status-success" />
          <span className="text-muted-color">Connected</span>
        </>
      ) : (
        <>
          <span className="w-2 h-2 rounded-full status-error" />
          <span className="text-muted-color">Offline</span>
        </>
      )}
    </div>
  );
}
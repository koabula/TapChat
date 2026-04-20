import { useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";

import type {
  CoreUpdateEvent,
  RealtimeEventPayload,
  SystemBanner as SystemBannerItem,
} from "@/lib/types";
import { useSessionStore } from "@/store/session";

const statusIcons: Record<SystemBannerItem["status"], string> = {
  sync_in_progress: "?",
  identity_refresh_needed: "??",
  conversation_needs_rebuild: "??",
  attachment_upload_failed: "??",
  temporary_network_failure: "??",
  message_queued_for_approval: "??",
  message_rejected_by_policy: "??",
};

const statusColors: Record<SystemBannerItem["status"], string> = {
  sync_in_progress: "bg-frost.3 text-polar.1",
  identity_refresh_needed: "bg-aurora.orange text-polar.1",
  conversation_needs_rebuild: "bg-aurora.yellow text-polar.1",
  attachment_upload_failed: "bg-aurora.red text-polar.1",
  temporary_network_failure: "bg-aurora.red text-polar.1",
  message_queued_for_approval: "bg-frost.2 text-polar.1",
  message_rejected_by_policy: "bg-aurora.red text-polar.1",
};

function bannerKey(banner: SystemBannerItem): string {
  return `${banner.status}:${banner.message}`;
}

function visibleBanners(banners: SystemBannerItem[] | undefined): SystemBannerItem[] {
  return (banners ?? []).filter((banner) => banner.message.trim().length > 0);
}

/**
 * System banner component for displaying sync status, errors, and warnings.
 * Appears at the top of the main chat layout when there are user-visible banners.
 */
export default function SystemBanner() {
  const [banners, setBanners] = useState<SystemBannerItem[]>([]);
  const [dismissed, setDismissed] = useState<Set<string>>(new Set());

  useEffect(() => {
    const unlisten = listen<CoreUpdateEvent>("core-update", (event) => {
      const nextBanners = visibleBanners(event.payload.view_model?.banners).filter(
        (banner) => !dismissed.has(bannerKey(banner)),
      );
      setBanners(nextBanners);
    });

    return () => {
      unlisten.then((fn) => fn());
    };
  }, [dismissed]);

  const handleDismiss = (banner: SystemBannerItem) => {
    const key = bannerKey(banner);
    setDismissed((prev) => new Set([...prev, key]));
    setBanners((prev) => prev.filter((item) => bannerKey(item) !== key));
  };

  if (banners.length === 0) {
    return null;
  }

  return (
    <div className="fixed top-0 left-0 right-0 z-50 flex flex-col gap-1 p-2">
      {banners.map((banner) => (
        <div
          key={bannerKey(banner)}
          className={`flex items-center justify-between px-3 py-2 rounded-lg shadow-lg ${statusColors[banner.status]}`}
        >
          <div className="flex items-center gap-2">
            <span className="text-lg">{statusIcons[banner.status]}</span>
            <span className="text-sm font-medium">{banner.message}</span>
          </div>
          <button
            className="text-sm px-2 hover:opacity-70"
            onClick={() => handleDismiss(banner)}
          >
            ?
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
  const [connected, setConnected] = useState<boolean | null>(null);
  const [isProfileSwitching, setIsProfileSwitching] = useState(false);
  const [lastDisconnectTime, setLastDisconnectTime] = useState<number | null>(null);
  const isProfileSwitchingRef = useRef(false);
  const syncing = useSessionStore((state) => state.syncInFlight);

  useEffect(() => {
    const unlistenProfileSwitchStart = listen<void>("profile-switch-start", () => {
      console.debug("[NetworkIndicator] profile-switch-start");
      isProfileSwitchingRef.current = true;
      setIsProfileSwitching(true);
      setConnected(null);
      setLastDisconnectTime(null);
    });

    const unlistenProfileSwitchComplete = listen<void>("profile-switch-complete", () => {
      console.debug("[NetworkIndicator] profile-switch-complete");
      isProfileSwitchingRef.current = false;
      setIsProfileSwitching(false);
      setLastDisconnectTime(null);
    });

    const unlistenRealtime = listen<RealtimeEventPayload>("realtime-event", (event) => {
      const { event_type } = event.payload;
      console.debug(`[NetworkIndicator] realtime-event type=${event_type}`);

      if (isProfileSwitchingRef.current) {
        return;
      }

      switch (event_type) {
        case "connected":
          setConnected(true);
          setLastDisconnectTime(null);
          break;
        case "disconnected":
        case "error":
          setConnected(false);
          setLastDisconnectTime(Date.now());
          break;
      }
    });

    invoke<{ ws_connected: boolean }>("get_session_status")
      .then((status) => {
        if (!isProfileSwitchingRef.current) {
          setConnected(status.ws_connected);
          if (!status.ws_connected) {
            setLastDisconnectTime(Date.now());
          }
        }
      })
      .catch((err) => {
        console.error(`[NetworkIndicator] failed to get session status: ${String(err)}`);
      });

    return () => {
      unlistenProfileSwitchStart.then((fn) => fn());
      unlistenProfileSwitchComplete.then((fn) => fn());
      unlistenRealtime.then((fn) => fn());
    };
  }, []);

  const isLongDisconnect =
    lastDisconnectTime !== null && (Date.now() - lastDisconnectTime) > 5000;

  const handleReconnect = async () => {
    console.debug("[NetworkIndicator] manual reconnect triggered");
    try {
      await invoke("sync_now");
    } catch (err) {
      console.error(`[NetworkIndicator] reconnect failed: ${String(err)}`);
    }
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
          <span
            className={`w-2 h-2 rounded-full ${isLongDisconnect ? "status-error" : "bg-frost.3"} animate-pulse`}
          />
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

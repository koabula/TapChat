import { presentError } from "@/lib/errors";
import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { listen } from "@tauri-apps/api/event";
import { invokeApp as invoke } from "@/lib/tauri";
import { useNavigate } from "react-router";
import {
  RefreshCw,
  AlertTriangle,
  AlertCircle,
  FileWarning,
  WifiOff,
  Clock,
  ShieldX,
  X,
} from "lucide-react";

import type {
  CloudflareStatus,
  CoreUpdateEvent,
  RealtimeEventPayload,
  SystemBanner as SystemBannerItem,
} from "@/lib/types";
import { runtimeBannerForStatus } from "@/lib/runtimeBanner";
import { useSessionStore } from "@/store/session";

const statusIcons: Record<SystemBannerItem["status"], ReactNode> = {
  sync_in_progress: <RefreshCw size={18} className="animate-spin" />,
  identity_refresh_needed: <AlertTriangle size={18} />,
  conversation_needs_rebuild: <AlertCircle size={18} />,
  attachment_upload_failed: <FileWarning size={18} />,
  attachment_download_failed: <FileWarning size={18} />,
  temporary_network_failure: <WifiOff size={18} />,
  message_queued_for_approval: <Clock size={18} />,
  message_rejected_by_policy: <ShieldX size={18} />,
};

const statusTones: Record<SystemBannerItem["status"], "warning" | "error" | "info"> = {
  sync_in_progress: "info",
  identity_refresh_needed: "warning",
  conversation_needs_rebuild: "warning",
  attachment_upload_failed: "error",
  attachment_download_failed: "error",
  temporary_network_failure: "error",
  message_queued_for_approval: "info",
  message_rejected_by_policy: "error",
};

function bannerKey(banner: SystemBannerItem): string {
  return `${banner.status}:${banner.message}`;
}

function visibleBanners(banners: SystemBannerItem[] | undefined): SystemBannerItem[] {
  return (banners ?? []).filter((banner) => banner.message.trim().length > 0);
}

function toneClass(tone: "warning" | "error" | "info"): string {
  if (tone === "error") return "status-error";
  if (tone === "warning") return "status-warning";
  return "text-muted-color";
}

/**
 * System toasts for sync status, errors, and runtime issues that need user action.
 * Anchored to the bottom-right so they never overlay the app chrome.
 */
export default function SystemBanner() {
  const navigate = useNavigate();
  const [banners, setBanners] = useState<SystemBannerItem[]>([]);
  const [runtimeStatus, setRuntimeStatus] = useState<CloudflareStatus | null>(null);
  const [dismissed, setDismissed] = useState<Set<string>>(new Set());
  const [runtimeDismissed, setRuntimeDismissed] = useState(false);

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

  useEffect(() => {
    const refreshRuntime = () => {
      invoke<CloudflareStatus>("cloudflare_status")
        .then((status) => {
          setRuntimeStatus(status);
          setRuntimeDismissed(false);
        })
        .catch((err) => {
          console.debug(`[SystemBanner] cloudflare_status failed: ${presentError(err).message}`);
        });
    };
    refreshRuntime();
    const unlisten = listen<CloudflareStatus>("runtime-status-changed", (event) => {
      setRuntimeStatus(event.payload);
      setRuntimeDismissed(false);
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

  const handleDismiss = (banner: SystemBannerItem) => {
    const key = bannerKey(banner);
    setDismissed((prev) => new Set([...prev, key]));
    setBanners((prev) => prev.filter((item) => bannerKey(item) !== key));
  };

  const runtimeBanner = runtimeDismissed ? null : runtimeBannerForStatus(runtimeStatus);

  if (banners.length === 0 && !runtimeBanner) {
    return null;
  }

  return (
    <div className="pointer-events-none fixed bottom-20 right-4 z-50 flex w-80 max-w-[calc(100vw-2rem)] flex-col gap-2">
      {runtimeBanner && (
        <div className="toast toast-card pointer-events-auto flex items-start gap-2 px-3 py-2">
          <span className={`mt-0.5 shrink-0 ${toneClass(runtimeBanner.tone)}`}>
            <AlertTriangle size={18} />
          </span>
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium text-primary-color">{runtimeBanner.message}</p>
            {runtimeBanner.actionLabel && (
              <button
                className="mt-1 text-xs font-medium text-secondary-color hover:text-primary-color"
                onClick={() => navigate("/settings/runtime")}
              >
                {runtimeBanner.actionLabel}
              </button>
            )}
          </div>
          <button
            className="shrink-0 text-muted-color hover:text-primary-color"
            onClick={() => setRuntimeDismissed(true)}
            aria-label="Dismiss"
          >
            <X size={16} />
          </button>
        </div>
      )}
      {banners.map((banner) => (
        <div
          key={bannerKey(banner)}
          className="toast toast-card pointer-events-auto flex items-start gap-2 px-3 py-2"
        >
          <span className={`mt-0.5 shrink-0 ${toneClass(statusTones[banner.status])}`}>
            {statusIcons[banner.status]}
          </span>
          <p className="min-w-0 flex-1 text-sm font-medium text-primary-color">{banner.message}</p>
          <button
            className="shrink-0 text-muted-color hover:text-primary-color"
            onClick={() => handleDismiss(banner)}
            aria-label="Dismiss"
          >
            <X size={16} />
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
        console.error(`[NetworkIndicator] failed to get session status: ${presentError(err).message}`);
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
      console.error(`[NetworkIndicator] reconnect failed: ${presentError(err).message}`);
    }
  };

  return (
    <div className="flex items-center gap-1 px-2 py-1 text-xs">
      {syncing ? (
        <>
          <span className="w-2 h-2 rounded-full bg-frost-3 animate-pulse" />
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
            className={`w-2 h-2 rounded-full ${isLongDisconnect ? "status-error" : "bg-frost-3"} animate-pulse`}
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

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

const statusColors: Record<SystemBannerItem["status"], string> = {
  sync_in_progress: "bg-frost.3 text-polar.1",
  identity_refresh_needed: "bg-aurora.orange text-polar.1",
  conversation_needs_rebuild: "bg-aurora.yellow text-polar.1",
  attachment_upload_failed: "bg-aurora.red text-polar.1",
  attachment_download_failed: "bg-aurora.red text-polar.1",
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
  const navigate = useNavigate();
  const [banners, setBanners] = useState<SystemBannerItem[]>([]);
  const [runtimeStatus, setRuntimeStatus] = useState<CloudflareStatus | null>(null);
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

  useEffect(() => {
    const refreshRuntime = () => {
      invoke<CloudflareStatus>("cloudflare_status")
        .then(setRuntimeStatus)
        .catch((err) => {
          console.debug(`[SystemBanner] cloudflare_status failed: ${presentError(err).message}`);
        });
    };
    refreshRuntime();
    const unlisten = listen<CloudflareStatus>("runtime-status-changed", (event) => {
      setRuntimeStatus(event.payload);
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

  const runtimeBanner = runtimeBannerForStatus(runtimeStatus);

  if (banners.length === 0 && !runtimeBanner) {
    return null;
  }

  return (
    <div className="fixed top-0 left-0 right-0 z-50 flex flex-col gap-1 p-2">
      {runtimeBanner && (
        <div className="flex items-center justify-between rounded-lg bg-aurora.orange px-3 py-2 text-polar.1 shadow-lg">
          <div className="flex items-center gap-2">
            <AlertTriangle size={18} />
            <span className="text-sm font-medium">{runtimeBanner.message}</span>
          </div>
          <div className="flex items-center gap-2">
            {runtimeBanner.actionLabel && (
              <button
                className="rounded bg-polar.1/20 px-2 py-1 text-xs font-medium hover:bg-polar.1/30"
                onClick={() => navigate("/settings/runtime")}
              >
                {runtimeBanner.actionLabel}
              </button>
            )}
          </div>
        </div>
      )}
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
            <X size={16} />
          </button>
        </div>
      ))}
    </div>
  );
}

function runtimeBannerForStatus(status: CloudflareStatus | null): {
  message: string;
  actionLabel?: string;
} | null {
  if (!status || status.state === "ready" || status.state === "refreshing" || status.state === "degraded") {
    return null;
  }
  switch (status.state) {
    case "missing":
      return {
        message: "Cloudflare runtime is not deployed.",
        actionLabel: "Deploy",
      };
    case "incomplete":
    case "writeback_incomplete":
      return {
        message: status.details || "Cloudflare runtime setup is incomplete.",
        actionLabel: "Repair",
      };
    case "outdated":
      return {
        message: "Cloudflare runtime needs an upgrade.",
        actionLabel: "Upgrade",
      };
    case "unreachable":
      return {
        message: status.last_error || "Cloudflare runtime is unreachable.",
        actionLabel: "Redeploy",
      };
    case "auth_expired":
    case "offline_expired":
      return {
        message: "Cloudflare runtime authorization needs refresh.",
        actionLabel: "Refresh",
      };
    case "upgrade_required":
      return {
        message: "Cloudflare runtime needs a one-time upgrade.",
        actionLabel: "Upgrade",
      };
    case "enrollment_required":
      return {
        message: "This device must enroll with the Cloudflare runtime.",
        actionLabel: "Open",
      };
    case "device_revoked":
      return {
        message: "This device was revoked. Restore your identity or create a new device.",
      };
    default:
      return {
        message: status.details || status.last_error || "Cloudflare runtime needs attention.",
        actionLabel: "Open",
      };
  }
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

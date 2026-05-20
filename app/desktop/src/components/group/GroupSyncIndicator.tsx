import { groupSyncLamp, type GroupSyncStatus } from "@/store/groupSync";

interface GroupSyncIndicatorProps {
  status?: GroupSyncStatus;
  compact?: boolean;
}

function labelFor(status: GroupSyncStatus | undefined): string {
  if (!status) return "Group sync idle";
  if (status.expectedWebsocket && status.connected) return "Live via WebSocket";
  if (status.expectedWebsocket && !status.connected) {
    return status.lastError
      ? `Realtime disconnected: ${status.lastError}`
      : "Realtime disconnected, polling fallback active";
  }
  if (status.mode === "polling") {
    return status.lastSyncedAt
      ? `Polling active, last synced ${new Date(status.lastSyncedAt).toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
        })}`
      : "Polling active";
  }
  return "Manual sync only";
}

export default function GroupSyncIndicator({ status, compact = false }: GroupSyncIndicatorProps) {
  const lamp = groupSyncLamp(status);
  const cls =
    lamp === "websocket_live"
      ? "bg-green-500 animate-pulse"
      : lamp === "polling_ok"
        ? "bg-green-500"
        : lamp === "websocket_error"
          ? "bg-red-500 animate-pulse"
          : "bg-surface-elevated";

  return (
    <span
      className={`inline-flex items-center ${compact ? "" : "gap-1.5 text-xs text-muted-color"}`}
      title={labelFor(status)}
      aria-label={labelFor(status)}
    >
      <span className={`h-2 w-2 rounded-full ${cls}`} />
      {!compact && <span>{status?.mode === "websocket" ? "Live" : status?.mode ?? "Idle"}</span>}
    </span>
  );
}

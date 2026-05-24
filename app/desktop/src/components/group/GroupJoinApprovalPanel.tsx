import { useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { writeText as clipboardWriteText } from "@tauri-apps/plugin-clipboard-manager";
import { AlertCircle, Check, X, Copy, UserCheck, UserX } from "lucide-react";

import {
  approveGroupJoin,
  getGroupSnapshot,
  listGroupJoinRequests,
  rejectGroupJoin,
  type GroupJoinRequestView,
  type WelcomePickupShareable,
} from "@/lib/tauri";
import type { RealtimeEventPayload } from "@/lib/types";
import { useGroupsStore } from "@/store/groups";
import { useContactsStore } from "@/store/contacts";
import { useSessionStore } from "@/store/session";
import { buildGroupNameResolver } from "@/lib/groupDisplayNames";

interface GroupJoinApprovalPanelProps {
  open: boolean;
  groupId: string;
  onClose: () => void;
}

/**
 * Owner/admin approval queue for pending join requests.
 *
 * Requirements (R9):
 *   - Only renders for `owner` / `admin` roles (cosmetic gate — the
 *     core rejects non-privileged list/approve/reject calls).
 *   - Lists every pending request from `snapshot.group_join_requests`.
 *   - Approve path surfaces the `welcome_pickups` the inviter must
 *     hand out-of-band to the joiner's devices (the core writes them
 *     to the welcome-pickup queue, but they are still surfaced here
 *     in case the inviter needs to re-share a URL).
 *   - Reject lets the admin optionally type a reason; the core
 *     forwards it to the joiner if the transport supports it.
 */
export default function GroupJoinApprovalPanel({
  open,
  groupId,
  onClose,
}: GroupJoinApprovalPanelProps) {
  const snapshot = useGroupsStore((s) => s.snapshots[groupId] ?? null);
  const setSnapshot = useGroupsStore((s) => s.setSnapshot);
  const contacts = useContactsStore((s) => s.contacts);
  const localUserId = useSessionStore((s) => s.userId);
  const localDisplayName = useSessionStore((s) => s.displayName);

  const [requests, setRequests] = useState<GroupJoinRequestView[]>([]);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [approvedPickups, setApprovedPickups] = useState<WelcomePickupShareable[]>([]);
  const [rejectReason, setRejectReason] = useState<Record<string, string>>({});

  useEffect(() => {
    if (open) {
      setApprovedPickups([]);
      setError(null);
      setRejectReason({});
      void refresh();
    }
  }, [open, groupId]);

  useEffect(() => {
    if (!open) return;
    const unlisten = listen<RealtimeEventPayload>("realtime-event", (event) => {
      const payload = event.payload;
      if (
        payload.event_type === "group_join_request_available" &&
        payload.device_id === groupId
      ) {
        void refresh();
      }
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, [open, groupId]);

  const refresh = async () => {
    setLoading(true);
    try {
      const rows = await listGroupJoinRequests(groupId);
      setRequests(rows.filter((row) => row.status === "pending"));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  const handleApprove = async (request: GroupJoinRequestView) => {
    setBusy(`approve:${request.request_id}`);
    setError(null);
    try {
      const result = await approveGroupJoin(groupId, request.request_id);
      if (result.status === "already_member") {
        setError(
          "该设备已经在群成员列表中，请让对方重试初始群邀请导入或重建新群。",
        );
        await refresh();
        return;
      }
      setApprovedPickups(result.welcome_pickups);
      await refresh();
      try {
        const fresh = await getGroupSnapshot(groupId);
        setSnapshot(fresh);
      } catch {
        // Non-fatal — core-update will refresh soon.
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  const handleReject = async (request: GroupJoinRequestView) => {
    setBusy(`reject:${request.request_id}`);
    setError(null);
    try {
      const reason = rejectReason[request.request_id]?.trim() || undefined;
      await rejectGroupJoin(groupId, request.request_id, reason);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  const handleCopyPickup = async (url: string) => {
    try {
      await clipboardWriteText(url);
    } catch {
      // Best-effort; fallback is not critical here because the pickup
      // is also stored server-side in the welcome-pickup queue.
    }
  };

  if (!open) return null;

  const localRole = snapshot?.local_role ?? null;
  const privileged = localRole === "owner" || localRole === "admin";
  const resolveGroupName = buildGroupNameResolver({
    manifest: snapshot?.manifest ?? null,
    contacts,
    localUserId,
    localDisplayName,
  });

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="join-approval-title"
    >
      <div className="bg-surface rounded-lg shadow-xl w-full max-w-2xl max-h-[85vh] flex flex-col overflow-hidden">
        <header className="flex items-center justify-between p-4 border-b border-default">
          <div className="flex items-center gap-2">
            <UserCheck size={20} className="text-primary-color" />
            <h2
              id="join-approval-title"
              className="text-lg font-semibold text-primary-color"
            >
              Pending join requests
            </h2>
          </div>
          <button className="btn btn-ghost px-2" onClick={onClose} aria-label="Close panel">
            <X size={18} />
          </button>
        </header>

        <div className="flex-1 min-h-0 overflow-y-auto p-4 space-y-3">
          {!privileged && (
            <div className="p-3 rounded-lg bg-yellow-500/10 text-sm text-yellow-500">
              Only owners and admins can approve or reject join requests.
            </div>
          )}

          {loading && (
            <div className="text-center py-4 text-muted-color text-sm">Loading…</div>
          )}

          {!loading && requests.length === 0 && privileged && (
            <div className="text-center py-4 text-muted-color text-sm">
              No pending requests.
            </div>
          )}

          {privileged &&
            requests.map((request) => (
              <div
                key={request.request_id}
                className="p-3 rounded-lg border border-subtle bg-base"
              >
                <div className="flex items-start justify-between gap-2 mb-2">
                  <div className="min-w-0">
                    <div className="text-primary-color font-medium truncate">
                      {resolveGroupName({
                        userId: request.joiner_user_id,
                        deviceId: request.joiner_device_id,
                      })}
                    </div>
                    <div className="text-xs text-muted-color truncate">
                      Device {request.joiner_device_id} · {new Date(request.requested_at).toLocaleString()}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      className="btn btn-primary text-xs"
                      onClick={() => void handleApprove(request)}
                      disabled={busy !== null}
                    >
                      {busy === `approve:${request.request_id}` ? (
                        "Approving…"
                      ) : (
                        <>
                          <Check size={14} /> Approve
                        </>
                      )}
                    </button>
                    <button
                      className="btn btn-danger text-xs"
                      onClick={() => void handleReject(request)}
                      disabled={busy !== null}
                    >
                      {busy === `reject:${request.request_id}` ? (
                        "Rejecting…"
                      ) : (
                        <>
                          <UserX size={14} /> Reject
                        </>
                      )}
                    </button>
                  </div>
                </div>
                <input
                  className="input text-xs"
                  placeholder="Reason (optional, sent with reject)"
                  value={rejectReason[request.request_id] ?? ""}
                  onChange={(e) =>
                    setRejectReason((prev) => ({
                      ...prev,
                      [request.request_id]: e.target.value,
                    }))
                  }
                  disabled={busy !== null}
                />
              </div>
            ))}

          {approvedPickups.length > 0 && (
            <section className="p-3 rounded-lg border border-subtle bg-base">
              <div className="text-sm font-medium text-primary-color mb-2">
                Welcome pickups issued
              </div>
              <p className="text-xs text-muted-color mb-2">
                The core stores these on the welcome-pickup queue so the
                joiner's devices can import the group. Hand them out if
                the joiner asks for a fresh link.
              </p>
              <ul className="space-y-1">
                {approvedPickups.map((pickup) => (
                  <li
                    key={pickup.capability}
                    className="flex items-center gap-2"
                  >
                    <input
                      readOnly
                      className="input text-xs font-mono flex-1"
                      value={pickup.url}
                      onClick={(e) => e.currentTarget.select()}
                    />
                    <button
                      className="btn btn-secondary text-xs"
                      onClick={() => void handleCopyPickup(pickup.url)}
                    >
                      <Copy size={14} /> Copy
                    </button>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {error && (
            <div
              role="alert"
              className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10 text-sm text-red-500"
            >
              <AlertCircle size={16} className="shrink-0 mt-0.5" />
              <div className="break-words">{error}</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

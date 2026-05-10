import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router";
import { X, Link2, AlertCircle, Loader } from "lucide-react";

import {
  getGroupJoinRequestStatus,
  submitGroupJoinRequest,
  type SubmitGroupJoinRequestResult,
} from "@/lib/tauri";
import { useConversationsStore } from "@/store/conversations";

interface GroupJoinByLinkDialogProps {
  open: boolean;
  onClose: () => void;
}

/**
 * Paste-an-invite-URL dialog for new joiners.
 *
 * Flow (requirements R8):
 *   1. User pastes either a `https://.../v1/group-invite/<token>` URL
 *      (owner/admin invite link) or a `tapchat://welcome-pickup/<b64>`
 *      URL (direct welcome pickup). The Tauri command dispatches the
 *      right `CoreCommand` based on the prefix.
 *   2. For welcome-pickup URLs the core imports the group immediately
 *      and returns `status === "approved"`; the UI navigates to the
 *      new conversation.
 *   3. For invite-link URLs the core persists a pending join request
 *      and returns `status === "pending"`. The UI then polls
 *      `getGroupJoinRequestStatus` every 3 seconds until the status
 *      flips to `approved` (then navigates to the group chat) or
 *      `rejected` (surfaces the rejection and stops polling).
 *
 * On dialog close the polling interval is cleared so the hook does
 * not leak timers. The interval is also rebound to a fresh value
 * whenever the user submits a new URL.
 */
export default function GroupJoinByLinkDialog({
  open,
  onClose,
}: GroupJoinByLinkDialogProps) {
  const navigate = useNavigate();
  const conversations = useConversationsStore((s) => s.conversations);

  const [inviteUrl, setInviteUrl] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [pending, setPending] = useState<SubmitGroupJoinRequestResult | null>(null);
  const [status, setStatus] = useState<
    "idle" | "pending" | "approved" | "rejected" | "error"
  >("idle");
  const [error, setError] = useState<string | null>(null);

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const stopPolling = () => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  };

  useEffect(() => {
    if (!open) {
      stopPolling();
      setInviteUrl("");
      setSubmitting(false);
      setPending(null);
      setStatus("idle");
      setError(null);
    }
    return () => stopPolling();
  }, [open]);

  const handleSubmit = async () => {
    const trimmed = inviteUrl.trim();
    if (!trimmed) {
      setError("Paste an invite URL first.");
      return;
    }
    setSubmitting(true);
    setError(null);
    stopPolling();

    try {
      const result = await submitGroupJoinRequest(trimmed);
      setPending(result);
      if (result.status === "approved") {
        setStatus("approved");
        handleApproved(result.group_id);
        return;
      }
      setStatus("pending");
      startPolling(result.group_id, result.request_id);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setStatus("error");
    } finally {
      setSubmitting(false);
    }
  };

  const startPolling = (groupId: string, requestId: string) => {
    stopPolling();
    pollRef.current = setInterval(() => {
      void tick(groupId, requestId);
    }, 3000);
    // Also fire one immediate check so the UI does not appear stuck
    // for the first 3 seconds after submission.
    void tick(groupId, requestId);
  };

  const tick = async (groupId: string, requestId: string) => {
    try {
      const view = await getGroupJoinRequestStatus(groupId, requestId);
      if (view.status === "approved" && view.group_imported) {
        setStatus("approved");
        stopPolling();
        handleApproved(groupId);
      } else if (view.status === "rejected") {
        setStatus("rejected");
        stopPolling();
      } else {
        setStatus("pending");
      }
    } catch (err) {
      // Transient errors are non-fatal; log and keep polling.
      console.debug(
        `[GroupJoinByLinkDialog] status poll error: ${String(err)}`,
      );
    }
  };

  const handleApproved = (groupId: string) => {
    // The core-update fan-out may take a beat to materialise the new
    // conversation; fall back to a small retry loop.
    const targetId = resolveConversationId(groupId);
    if (targetId) {
      navigate(`/chat/${targetId}`);
      onClose();
    } else {
      // Keep the dialog open with an "Open group" CTA and let the
      // user click once the store settles.
      setStatus("approved");
    }
  };

  const resolveConversationId = (groupId: string): string | null => {
    const match = conversations.find((conv) => conv.group_id === groupId);
    return match?.conversation_id ?? null;
  };

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="join-by-link-title"
    >
      <div className="bg-surface rounded-lg shadow-xl w-full max-w-lg max-h-[85vh] flex flex-col overflow-hidden">
        <header className="flex items-center justify-between p-4 border-b border-default">
          <div className="flex items-center gap-2">
            <Link2 size={20} className="text-primary-color" />
            <h2
              id="join-by-link-title"
              className="text-lg font-semibold text-primary-color"
            >
              Join a group
            </h2>
          </div>
          <button className="btn btn-ghost px-2" onClick={onClose} aria-label="Close dialog">
            <X size={18} />
          </button>
        </header>

        <div className="p-4 space-y-3">
          <label className="block">
            <span className="text-sm text-secondary-color">
              Paste an invite link or welcome pickup URL
            </span>
            <textarea
              className="input mt-1 font-mono text-xs"
              rows={3}
              placeholder="https://.../v1/group-invite/... or tapchat://welcome-pickup/..."
              value={inviteUrl}
              onChange={(e) => setInviteUrl(e.target.value)}
              disabled={submitting || status === "pending"}
            />
          </label>

          {status === "pending" && (
            <div className="flex items-center gap-2 p-3 rounded-lg bg-surface-elevated text-sm text-secondary-color">
              <Loader size={14} className="animate-spin" />
              <span>
                Waiting for approval… you can close this dialog and
                check back later. The request remains pending
                server-side.
              </span>
            </div>
          )}

          {status === "approved" && pending && (
            <div className="flex items-center justify-between gap-2 p-3 rounded-lg bg-green-500/10 text-sm text-green-500">
              <span>Joined! Opening group…</span>
              {resolveConversationId(pending.group_id) && (
                <button
                  className="btn btn-secondary text-xs"
                  onClick={() => {
                    const id = resolveConversationId(pending.group_id);
                    if (id) {
                      navigate(`/chat/${id}`);
                      onClose();
                    }
                  }}
                >
                  Open group
                </button>
              )}
            </div>
          )}

          {status === "rejected" && (
            <div
              role="alert"
              className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10 text-sm text-red-500"
            >
              <AlertCircle size={16} className="shrink-0 mt-0.5" />
              <div>Your join request was rejected.</div>
            </div>
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

        <footer className="p-4 border-t border-default flex items-center justify-end gap-2">
          <button className="btn btn-ghost" onClick={onClose} disabled={submitting}>
            Close
          </button>
          <button
            className="btn btn-primary"
            onClick={handleSubmit}
            disabled={submitting || status === "pending"}
          >
            {submitting ? "Submitting..." : "Submit join request"}
          </button>
        </footer>
      </div>
    </div>
  );
}

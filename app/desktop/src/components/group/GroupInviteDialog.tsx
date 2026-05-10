import { useEffect, useRef, useState } from "react";
import { writeText as clipboardWriteText } from "@tauri-apps/plugin-clipboard-manager";
import { Copy, Check, X, AlertCircle, Link2, Trash2 } from "lucide-react";

import {
  createGroupInviteLink,
  listGroupInvites,
  revokeGroupInviteLink,
  type GroupInviteView,
} from "@/lib/tauri";

interface GroupInviteDialogProps {
  open: boolean;
  groupId: string;
  onClose: () => void;
}

/**
 * Owner/admin-facing dialog for managing group invite links.
 *
 * Requirements (R7):
 *   - Create new invite with an `hoursValid` input + optional `maxUses`.
 *   - List every invite the core has persisted for this group (unexpired).
 *   - Copy invite URL via the Tauri `clipboard-manager` plugin
 *     (NOT `navigator.clipboard`) with a select-the-text fallback if
 *     the plugin rejects (R7.5 / R7.6 / R7.7).
 *   - Revoke an existing invite.
 *
 * Server-side authority (R14.3): the core and Cloudflare both reject
 * invite-create calls from unauthorised roles. This dialog is only
 * rendered for owner/admin, but that gating is cosmetic — the dialog
 * will surface the server's error if it is somehow opened in a
 * privileged-looking-but-not-actually state.
 */
export default function GroupInviteDialog({
  open,
  groupId,
  onClose,
}: GroupInviteDialogProps) {
  const [hoursValid, setHoursValid] = useState(24);
  const [maxUses, setMaxUses] = useState<string>("");
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copyError, setCopyError] = useState<string | null>(null);
  const [invites, setInvites] = useState<GroupInviteView[]>([]);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  // Fallback selection target when the Tauri clipboard rejects the
  // write (R7.6): we still keep the focus on the url text and select
  // its contents so the user can Ctrl+C manually.
  const urlInputRefs = useRef<Map<string, HTMLInputElement>>(new Map());

  useEffect(() => {
    if (open) {
      setError(null);
      setCopyError(null);
      setCopiedId(null);
      setHoursValid(24);
      setMaxUses("");
      void refreshInvites();
    }
  }, [open]);

  const refreshInvites = async () => {
    try {
      const rows = await listGroupInvites(groupId);
      setInvites(rows);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleCreate = async () => {
    if (hoursValid <= 0) {
      setError("Hours valid must be greater than zero.");
      return;
    }
    const parsedMaxUses =
      maxUses.trim() === "" ? undefined : Number.parseInt(maxUses.trim(), 10);
    if (
      parsedMaxUses !== undefined &&
      (Number.isNaN(parsedMaxUses) || parsedMaxUses <= 0)
    ) {
      setError("Max uses must be a positive integer when supplied.");
      return;
    }
    setCreating(true);
    setError(null);
    try {
      const expiresAt = Date.now() + hoursValid * 3600_000;
      await createGroupInviteLink(groupId, expiresAt, parsedMaxUses);
      await refreshInvites();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setCreating(false);
    }
  };

  const handleCopy = async (invite: GroupInviteView) => {
    setCopyError(null);
    try {
      await clipboardWriteText(invite.invite_url);
      setCopiedId(invite.invite_id);
      setTimeout(() => {
        setCopiedId((current) => (current === invite.invite_id ? null : current));
      }, 2000);
    } catch (err) {
      setCopyError(err instanceof Error ? err.message : String(err));
      // Fallback: select the URL text so Ctrl+C still works.
      const input = urlInputRefs.current.get(invite.invite_id);
      if (input) {
        input.select();
        input.focus();
      }
    }
  };

  const handleRevoke = async (invite: GroupInviteView) => {
    const confirm = window.confirm(
      `Revoke invite ${invite.invite_id}? Anyone who hasn't used it yet will be rejected.`,
    );
    if (!confirm) return;
    setError(null);
    try {
      await revokeGroupInviteLink(groupId, invite.invite_id);
      await refreshInvites();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="invite-dialog-title"
    >
      <div className="bg-surface rounded-lg shadow-xl w-full max-w-xl max-h-[85vh] flex flex-col overflow-hidden">
        <header className="flex items-center justify-between p-4 border-b border-default">
          <div className="flex items-center gap-2">
            <Link2 size={20} className="text-primary-color" />
            <h2 id="invite-dialog-title" className="text-lg font-semibold text-primary-color">
              Invite links
            </h2>
          </div>
          <button className="btn btn-ghost px-2" onClick={onClose} aria-label="Close dialog">
            <X size={18} />
          </button>
        </header>

        <div className="flex-1 min-h-0 overflow-y-auto">
          {/* Create form */}
          <section className="p-4 border-b border-default space-y-3">
            <h3 className="text-sm font-medium text-primary-color">Create invite</h3>
            <div className="grid grid-cols-2 gap-3">
              <label className="block">
                <span className="text-xs text-secondary-color">Hours valid</span>
                <input
                  type="number"
                  min={1}
                  step={1}
                  className="input mt-1"
                  value={hoursValid}
                  onChange={(e) => setHoursValid(Number.parseInt(e.target.value || "0", 10))}
                  disabled={creating}
                />
              </label>
              <label className="block">
                <span className="text-xs text-secondary-color">Max uses (optional)</span>
                <input
                  type="number"
                  min={1}
                  step={1}
                  className="input mt-1"
                  value={maxUses}
                  onChange={(e) => setMaxUses(e.target.value)}
                  placeholder="Unlimited"
                  disabled={creating}
                />
              </label>
            </div>
            <button
              className="btn btn-primary"
              onClick={handleCreate}
              disabled={creating}
            >
              {creating ? "Creating..." : "Create invite"}
            </button>
          </section>

          {/* Invite list */}
          <section className="p-4">
            <h3 className="text-sm font-medium text-primary-color mb-2">Active invites</h3>
            {invites.length === 0 ? (
              <div className="text-center py-4 text-muted-color text-sm">
                No invites yet.
              </div>
            ) : (
              <ul className="space-y-2">
                {invites.map((invite) => (
                  <li
                    key={invite.invite_id}
                    className="p-3 rounded-lg border border-subtle bg-base"
                  >
                    <div className="flex items-center justify-between gap-2 mb-2">
                      <div className="text-xs text-muted-color">
                        {invite.join_policy} · expires {formatExpiresAt(invite.expires_at)}
                        {invite.max_uses !== null && ` · ${invite.max_uses} uses`}
                      </div>
                      <button
                        className="btn btn-ghost px-2 text-red-500"
                        onClick={() => void handleRevoke(invite)}
                        aria-label={`Revoke invite ${invite.invite_id}`}
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                    <div className="flex items-center gap-2">
                      <input
                        ref={(el) => {
                          if (el) urlInputRefs.current.set(invite.invite_id, el);
                          else urlInputRefs.current.delete(invite.invite_id);
                        }}
                        readOnly
                        className="input flex-1 text-xs font-mono"
                        value={invite.invite_url}
                        onClick={(e) => e.currentTarget.select()}
                      />
                      <button
                        className="btn btn-secondary text-xs"
                        onClick={() => void handleCopy(invite)}
                      >
                        {copiedId === invite.invite_id ? (
                          <>
                            <Check size={14} /> Copied
                          </>
                        ) : (
                          <>
                            <Copy size={14} /> Copy
                          </>
                        )}
                      </button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </section>

          {error && (
            <div
              role="alert"
              className="m-4 flex items-start gap-2 p-3 rounded-lg bg-red-500/10 text-sm text-red-500"
            >
              <AlertCircle size={16} className="shrink-0 mt-0.5" />
              <div className="break-words">{error}</div>
            </div>
          )}
          {copyError && (
            <div
              role="alert"
              className="m-4 flex items-start gap-2 p-3 rounded-lg bg-yellow-500/10 text-sm text-yellow-500"
            >
              <AlertCircle size={16} className="shrink-0 mt-0.5" />
              <div className="break-words">
                Failed to copy — press Ctrl+C with the link selected. ({copyError})
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function formatExpiresAt(timestamp: number): string {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return "unknown";
  return date.toLocaleString();
}

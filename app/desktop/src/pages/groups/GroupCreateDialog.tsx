import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { writeText as clipboardWriteText } from "@tauri-apps/plugin-clipboard-manager";
import { Users, Copy, Check, X, AlertCircle } from "lucide-react";

import { useContactsStore } from "@/store/contacts";
import {
  cloudflareDeploy,
  cloudflareLogin,
  cloudflarePreflight,
  cloudflareStatus,
  createGroupConversation,
  type CreateGroupConversationResult,
  type WelcomePickupShareable,
} from "@/lib/tauri";

interface GroupCreateDialogProps {
  open: boolean;
  onClose: () => void;
}

/**
 * Modal dialog for creating a new MLS group conversation.
 *
 * Flow (requirements R1.1–R1.6):
 *   1. User picks ≥1 contact and enters a non-empty title.
 *   2. On submit, the dialog calls `createGroupConversation(title, ids)`.
 *   3. On success the Rust core returns the new conversation_id plus a
 *      list of `welcome_pickups`, one per invitee device. Each pickup
 *      carries a `tapchat://welcome-pickup/<b64>` URL the inviter can
 *      hand out-of-band. We surface these URLs for copying via the
 *      Tauri clipboard plugin (NOT `navigator.clipboard`, per R6.4),
 *      with a fallback that selects the text on copy failure.
 *   4. The dialog navigates to `/chat/{conversation_id}` once the
 *      inviter confirms they've copied all pickup links.
 *
 * The dialog is intentionally blocking on the welcome-pickup step: if
 * the user closes the dialog before copying the pickups, the invitees
 * will never receive the welcome (the pickup URL is never re-surfaced
 * elsewhere in the UI today).
 */
export default function GroupCreateDialog({ open, onClose }: GroupCreateDialogProps) {
  const navigate = useNavigate();
  const { contacts } = useContactsStore();

  const [title, setTitle] = useState("");
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<CreateGroupConversationResult | null>(null);
  const [copiedUrl, setCopiedUrl] = useState<string | null>(null);
  const [copyError, setCopyError] = useState<string | null>(null);
  const [runtimeUpgradeRequired, setRuntimeUpgradeRequired] = useState(false);
  const [runtimeBusy, setRuntimeBusy] = useState(false);
  const availableContacts = useMemo(
    () =>
      contacts.filter(
        (contact) => (contact.relationship_status ?? "available") === "available",
      ),
    [contacts],
  );

  // Reset the modal each time it opens so stale state does not leak
  // across invocations.
  useEffect(() => {
    if (open) {
      setTitle("");
      setSelectedIds(new Set());
      setSubmitting(false);
      setError(null);
      setCreated(null);
      setCopiedUrl(null);
      setCopyError(null);
      setRuntimeUpgradeRequired(false);
      setRuntimeBusy(false);
    }
  }, [open]);

  const canSubmit = useMemo(() => {
    return title.trim().length > 0 && selectedIds.size > 0 && !submitting;
  }, [title, selectedIds, submitting]);

  const toggleContact = (userId: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(userId)) {
        next.delete(userId);
      } else {
        next.add(userId);
      }
      return next;
    });
  };

  const handleSubmit = async () => {
    if (!canSubmit) return;
    setSubmitting(true);
    setError(null);
    try {
      const availableContactIds = new Set(
        availableContacts.map((contact) => contact.user_id),
      );
      const inviteeIds = Array.from(selectedIds).filter((userId) =>
        availableContactIds.has(userId),
      );
      const result = await createGroupConversation(
        title.trim(),
        inviteeIds,
      );
      setCreated(result);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes("runtime_missing_group_outbox")) {
        setRuntimeUpgradeRequired(true);
        setError("Cloudflare runtime needs an upgrade before group creation.");
      } else {
        setError(message);
      }
    } finally {
      setSubmitting(false);
    }
  };

  const handleRuntimeUpgrade = async () => {
    setRuntimeBusy(true);
    setError(null);
    try {
      const preflight = await cloudflarePreflight();
      if (!preflight.ready) {
        const login = await cloudflareLogin();
        if (!login.success) {
          setError(login.error || "Cloudflare login failed.");
          return;
        }
      }
      const deployed = await cloudflareDeploy();
      if (!deployed.success) {
        setError(deployed.error || "Cloudflare runtime upgrade failed.");
        return;
      }
      const status = await cloudflareStatus();
      if (status.needs_upgrade) {
        setError(status.last_error || "Cloudflare runtime still needs an upgrade.");
        return;
      }
      setRuntimeUpgradeRequired(false);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setRuntimeBusy(false);
    }
  };

  const handleCopy = async (url: string) => {
    try {
      await clipboardWriteText(url);
      setCopiedUrl(url);
      setCopyError(null);
      // Reset the "copied" indicator after a short delay.
      setTimeout(() => {
        setCopiedUrl((current) => (current === url ? null : current));
      }, 2000);
    } catch (err) {
      setCopyError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleDone = () => {
    if (!created) return;
    navigate(`/chat/${created.conversation_id}`);
    onClose();
  };

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="group-create-title"
    >
      <div className="bg-surface rounded-lg shadow-xl w-full max-w-lg max-h-[85vh] flex flex-col overflow-hidden">
        <header className="flex items-center justify-between p-4 border-b border-default">
          <div className="flex items-center gap-2">
            <Users size={20} className="text-primary-color" />
            <h2 id="group-create-title" className="text-lg font-semibold text-primary-color">
              {created ? "Group created" : "New group"}
            </h2>
          </div>
          <button
            className="btn btn-ghost px-2"
            onClick={onClose}
            aria-label="Close dialog"
          >
            <X size={18} />
          </button>
        </header>

        {created ? (
          <WelcomePickupSharing
            result={created}
            onCopy={handleCopy}
            copiedUrl={copiedUrl}
            copyError={copyError}
            onDone={handleDone}
          />
        ) : (
          <div className="flex-1 min-h-0 flex flex-col overflow-hidden">
            <div className="p-4 space-y-4 flex-1 overflow-y-auto">
              <label className="block">
                <span className="text-secondary-color text-sm">Group title</span>
                <input
                  className="input mt-1"
                  placeholder="e.g. Project Room"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  maxLength={120}
                  autoFocus
                />
              </label>

              <div>
                <div className="flex items-center justify-between text-sm text-secondary-color mb-2">
                  <span>Invite contacts</span>
                  <span className="text-xs text-muted-color">
                    {selectedIds.size} selected
                  </span>
                </div>
                {availableContacts.length === 0 ? (
                  <div className="text-center py-6 text-muted-color text-sm">
                    Add contacts first to create a group.
                  </div>
                ) : (
                  <ul className="space-y-1 max-h-64 overflow-y-auto">
                    {availableContacts.map((contact) => {
                      const checked = selectedIds.has(contact.user_id);
                      return (
                        <li key={contact.user_id}>
                          <label className="flex items-center gap-3 p-2 rounded-lg cursor-pointer hover:bg-surface-elevated">
                            <input
                              type="checkbox"
                              checked={checked}
                              onChange={() => toggleContact(contact.user_id)}
                            />
                            <div className="flex-1 min-w-0">
                              <div className="text-primary-color truncate">
                                {contact.display_name || contact.user_id}
                              </div>
                              <div className="text-xs text-muted-color truncate">
                                {contact.user_id}
                              </div>
                            </div>
                          </label>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </div>

              {error && (
                <div
                  role="alert"
                  className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10 text-sm text-red-500"
                >
                  <AlertCircle size={16} className="shrink-0 mt-0.5" />
                  <div className="break-words">
                    <div>{error}</div>
                    {runtimeUpgradeRequired && (
                      <button
                        className="btn btn-primary mt-3"
                        onClick={handleRuntimeUpgrade}
                        disabled={runtimeBusy}
                      >
                        {runtimeBusy ? "Upgrading..." : "Upgrade Cloudflare runtime"}
                      </button>
                    )}
                  </div>
                </div>
              )}
            </div>

            <footer className="p-4 border-t border-default flex items-center justify-end gap-2">
              <button className="btn btn-ghost" onClick={onClose} disabled={submitting}>
                Cancel
              </button>
              <button
                className="btn btn-primary"
                onClick={handleSubmit}
                disabled={!canSubmit}
              >
                {submitting ? "Creating..." : "Create group"}
              </button>
            </footer>
          </div>
        )}
      </div>
    </div>
  );
}

interface WelcomePickupSharingProps {
  result: CreateGroupConversationResult;
  onCopy: (url: string) => void;
  copiedUrl: string | null;
  copyError: string | null;
  onDone: () => void;
}

function WelcomePickupSharing({
  result,
  onCopy,
  copiedUrl,
  copyError,
  onDone,
}: WelcomePickupSharingProps) {
  return (
    <div className="flex-1 min-h-0 flex flex-col overflow-hidden">
      <div className="p-4 space-y-3 flex-1 overflow-y-auto">
        <p className="text-primary-color text-sm font-medium">
          Group created. Existing contacts will receive an encrypted group
          welcome through your direct chat and import it automatically.
        </p>
        <p className="text-secondary-color text-sm">
          If a contact does not see the group after syncing, share the
          matching device welcome fallback URL. It is device-specific and
          different from a reusable invite link.
        </p>
        {result.welcome_pickups.length === 0 ? (
          <div className="text-center py-6 text-muted-color text-sm">
            No welcome pickups were produced. The group was created; if
            invitees cannot join, re-invite them from the member drawer.
          </div>
        ) : (
          <ul className="space-y-2">
            {result.welcome_pickups.map((pickup) => (
              <PickupRow
                key={pickup.capability}
                pickup={pickup}
                onCopy={onCopy}
                copied={copiedUrl === pickup.url}
              />
            ))}
          </ul>
        )}
        {copyError && (
          <div
            role="alert"
            className="flex items-start gap-2 p-3 rounded-lg bg-yellow-500/10 text-sm text-yellow-500"
          >
            <AlertCircle size={16} className="shrink-0 mt-0.5" />
            <div className="break-words">
              Failed to copy — press Ctrl+C with the link selected. ({copyError})
            </div>
          </div>
        )}
      </div>
      <footer className="p-4 border-t border-default flex items-center justify-end gap-2">
        <button className="btn btn-primary" onClick={onDone}>
          Open group
        </button>
      </footer>
    </div>
  );
}

interface PickupRowProps {
  pickup: WelcomePickupShareable;
  onCopy: (url: string) => void;
  copied: boolean;
}

function PickupRow({ pickup, onCopy, copied }: PickupRowProps) {
  return (
    <li className="p-2 rounded-lg border border-subtle bg-base">
      <div className="flex items-center justify-between gap-2">
        <div className="flex-1 min-w-0">
          <div className="text-xs text-muted-color truncate">
            Device {pickup.device_id}
          </div>
          <div className="text-sm text-primary-color font-mono truncate">
            {pickup.url}
          </div>
        </div>
        <button
          className="btn btn-secondary text-xs"
          onClick={() => onCopy(pickup.url)}
          aria-label={`Copy pickup URL for ${pickup.device_id}`}
        >
          {copied ? (
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
  );
}

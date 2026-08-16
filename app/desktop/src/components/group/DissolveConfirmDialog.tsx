import { presentError } from "@/lib/errors";
import { useEffect, useState } from "react";
import { AlertTriangle, X } from "lucide-react";

import { dissolveGroup } from "@/lib/tauri";

interface DissolveConfirmDialogProps {
  open: boolean;
  groupId: string;
  groupTitle: string;
  onClose: () => void;
  onDissolved: () => void;
}

/**
 * "Type-to-confirm" dialog guarding the owner-only dissolve action.
 *
 * The dissolve primitive is irreversible (PLAN_GROUP §10.4 — once the
 * Cloudflare outbox is sealed it cannot be unsealed). To prevent
 * misclicks we require the owner to retype the group's title before
 * enabling the destructive button. This matches the Wave C CLI
 * confirmation prompt (`group dissolve --yes`) in spirit: the UI never
 * skips the confirmation even in one-click automation flows.
 */
export default function DissolveConfirmDialog({
  open,
  groupId,
  groupTitle,
  onClose,
  onDissolved,
}: DissolveConfirmDialogProps) {
  const [typedTitle, setTypedTitle] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setTypedTitle("");
      setSubmitting(false);
      setError(null);
    }
  }, [open]);

  const canSubmit =
    typedTitle.trim() === groupTitle.trim() && typedTitle.length > 0 && !submitting;

  const handleSubmit = async () => {
    if (!canSubmit) return;
    setSubmitting(true);
    setError(null);
    try {
      await dissolveGroup(groupId);
      onDissolved();
    } catch (err) {
      setError(presentError(err).message);
      setSubmitting(false);
    }
  };

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="dissolve-confirm-title"
    >
      <div className="bg-surface rounded-lg shadow-xl w-full max-w-md overflow-hidden">
        <header className="flex items-start justify-between p-4 border-b border-default">
          <div className="flex items-start gap-2">
            <AlertTriangle className="text-red-500 shrink-0" size={22} />
            <div>
              <h2
                id="dissolve-confirm-title"
                className="text-lg font-semibold text-primary-color"
              >
                Dissolve "{groupTitle}"?
              </h2>
              <p className="text-sm text-secondary-color mt-1">
                This will remove every other member, append a visible
                "group dissolved" system message, and permanently seal
                the group's outbox. It cannot be undone.
              </p>
            </div>
          </div>
          <button
            className="btn btn-ghost px-2 shrink-0"
            onClick={onClose}
            disabled={submitting}
            aria-label="Close dialog"
          >
            <X size={18} />
          </button>
        </header>

        <div className="p-4 space-y-3">
          <label className="block">
            <span className="text-sm text-secondary-color">
              Type the group title to confirm
            </span>
            <input
              className="input mt-1"
              placeholder={groupTitle}
              value={typedTitle}
              onChange={(e) => setTypedTitle(e.target.value)}
              disabled={submitting}
              autoFocus
            />
          </label>

          {error && (
            <div
              role="alert"
              className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10 text-sm text-red-500"
            >
              <AlertTriangle size={16} className="shrink-0 mt-0.5" />
              <div className="break-words">{error}</div>
            </div>
          )}
        </div>

        <footer className="p-4 border-t border-default flex items-center justify-end gap-2">
          <button className="btn btn-ghost" onClick={onClose} disabled={submitting}>
            Cancel
          </button>
          <button
            className="btn btn-danger"
            onClick={handleSubmit}
            disabled={!canSubmit}
          >
            {submitting ? "Dissolving..." : "Dissolve group"}
          </button>
        </footer>
      </div>
    </div>
  );
}

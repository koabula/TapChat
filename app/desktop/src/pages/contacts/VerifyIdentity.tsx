import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router";

import { presentError } from "@/lib/errors";
import {
  getSafetyNumber,
  listContacts,
  setContactVerified,
  type SafetyNumberView,
} from "@/lib/tauri";
import { useContactsStore } from "@/store/contacts";

function normalizeDigits(value: string): string {
  return value.replace(/\D/g, "");
}

export default function VerifyIdentity() {
  const navigate = useNavigate();
  const { id: userId } = useParams();
  const { contacts, updateContact, setContacts } = useContactsStore();
  const [safetyNumber, setSafetyNumber] = useState<SafetyNumberView | null>(null);
  const [pasteValue, setPasteValue] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const contact = contacts.find((item) => item.user_id === userId);
  const displayName = contact?.display_name || userId || "Contact";

  useEffect(() => {
    if (!userId) return;
    let cancelled = false;
    getSafetyNumber(userId)
      .then((result) => {
        if (!cancelled) setSafetyNumber(result);
      })
      .catch((err) => {
        if (!cancelled) setError(presentError(err).message);
      });
    return () => {
      cancelled = true;
    };
  }, [userId]);

  const pasteStatus = useMemo(() => {
    const pasted = normalizeDigits(pasteValue);
    if (!safetyNumber || pasted.length === 0) return null;
    return pasted === safetyNumber.digits ? "match" : "mismatch";
  }, [pasteValue, safetyNumber]);

  const handleSetVerified = async (verified: boolean) => {
    if (!userId) return;
    setSaving(true);
    setError(null);
    try {
      await setContactVerified(userId, verified);
      updateContact(userId, { verified, key_changed_unverified: false });
      const contacts = await listContacts();
      setContacts(
        contacts.map((item) => ({
          user_id: item.user_id,
          display_name: item.display_name ?? null,
          device_count: item.device_count,
          last_refresh: null,
          relationship_status: item.relationship_status ?? "available",
          verified: Boolean(item.verified),
          key_changed_unverified: Boolean(item.key_changed_unverified),
        })),
      );
      const next = await getSafetyNumber(userId);
      setSafetyNumber(next);
    } catch (err) {
      setError(presentError(err).message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="flex h-full min-h-0 overflow-hidden bg-base">
      <div className="flex-1 flex min-h-0 flex-col">
        <header className="flex items-center p-3 border-b border-default">
          <button className="btn btn-ghost px-2" onClick={() => navigate(-1)}>
            ←
          </button>
          <h1 className="font-semibold text-primary-color ml-2">Safety number</h1>
        </header>

        <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain p-6">
          <p className="text-muted-color text-sm text-center mb-4">
            Compare these numbers on both devices.
          </p>

          {safetyNumber && (
            <div className="card mx-auto max-w-md space-y-4">
              <img
                alt=""
                className="mx-auto h-48 w-48 rounded bg-white p-2"
                src={`data:image/svg+xml;utf8,${encodeURIComponent(safetyNumber.qr_svg)}`}
              />
              <div className="grid grid-cols-4 gap-2 font-mono text-center text-primary-color tracking-wider">
                {safetyNumber.groups.map((group, index) => (
                  <span key={`${index}-${group}`}>{group}</span>
                ))}
              </div>
            </div>
          )}

          <div className="mx-auto mt-4 max-w-md space-y-3">
            <input
              className="input w-full font-mono"
              placeholder="Paste their number"
              value={pasteValue}
              onChange={(event) => setPasteValue(event.target.value)}
            />
            {pasteStatus === "match" && (
              <p className="text-sm status-success">Match</p>
            )}
            {pasteStatus === "mismatch" && (
              <p className="text-sm status-error">Does not match</p>
            )}

            {safetyNumber?.verified ? (
              <button
                className="btn btn-ghost w-full"
                disabled={saving}
                onClick={() => handleSetVerified(false)}
              >
                {saving ? "Saving..." : "Remove verification"}
              </button>
            ) : (
              <button
                className="btn btn-primary w-full"
                disabled={saving || !safetyNumber}
                onClick={() => handleSetVerified(true)}
              >
                {saving ? "Saving..." : "Mark as verified"}
              </button>
            )}

            {error && <p className="text-sm status-error">{error}</p>}
            <p className="text-muted-color text-xs text-center">{displayName}</p>
          </div>
        </div>
      </div>
    </div>
  );
}

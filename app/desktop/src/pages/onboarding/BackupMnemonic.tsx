import { useCallback, useEffect, useState } from "react";
import { useNavigate, useLocation } from "react-router";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { clearClipboardIfUnchanged } from "../../lib/clipboardSecurity";

interface LocationState {
  mnemonic: string;
}

export default function BackupMnemonic() {
  const navigate = useNavigate();
  const location = useLocation();
  const state = location.state as LocationState | null;

  const mnemonic = state?.mnemonic || "";
  const [confirmed, setConfirmed] = useState(false);
  const [copyConfirmed, setCopyConfirmed] = useState(false);
  const [copiedUntil, setCopiedUntil] = useState<number | null>(null);
  const [secondsUntilClear, setSecondsUntilClear] = useState(0);
  const [clipboardWarning, setClipboardWarning] = useState<string | null>(null);

  const words = mnemonic.split(" ");

  const clearMnemonicIfUnchanged = useCallback(async () => {
    try {
      await clearClipboardIfUnchanged(mnemonic);
    } catch {
      setClipboardWarning("TapChat could not clear the clipboard. Copy something else before leaving your device unattended.");
    }
  }, [mnemonic]);

  useEffect(() => {
    if (!copiedUntil) {
      return;
    }
    const tick = () => {
      const remaining = Math.max(0, Math.ceil((copiedUntil - Date.now()) / 1000));
      setSecondsUntilClear(remaining);
      if (remaining === 0) {
        setCopiedUntil(null);
        void clearMnemonicIfUnchanged();
      }
    };
    tick();
    const timer = window.setInterval(tick, 1_000);
    return () => window.clearInterval(timer);
  }, [clearMnemonicIfUnchanged, copiedUntil]);

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    void getCurrentWindow().onCloseRequested(async () => {
      await clearMnemonicIfUnchanged();
    }).then((dispose) => {
      unlisten = dispose;
    }).catch(() => {
      // Route cleanup below remains the best-effort fallback.
    });
    return () => {
      unlisten?.();
      void clearMnemonicIfUnchanged();
    };
  }, [clearMnemonicIfUnchanged]);

  useEffect(() => {
    if (!mnemonic) {
      navigate("/onboarding", { replace: true });
    }
  }, [mnemonic, navigate]);

  const handleCopy = async () => {
    if (!copyConfirmed) {
      const accepted = window.confirm(
        "Your recovery phrase will be visible to every application that can read the system clipboard. TapChat will clear it after 30 seconds if it has not been replaced. Continue?"
      );
      if (!accepted) {
        return;
      }
      setCopyConfirmed(true);
    }
    try {
      await writeText(mnemonic);
      setClipboardWarning(null);
      setCopiedUntil(Date.now() + 30_000);
      setSecondsUntilClear(30);
    } catch {
      setClipboardWarning("TapChat could not copy the recovery phrase. Please write it down manually.");
    }
  };

  const handleContinue = async () => {
    if (confirmed) {
      await clearMnemonicIfUnchanged();
      navigate("/onboarding/cloudflare");
    }
  };

  // If no mnemonic (e.g., direct navigation), redirect to start
  if (!mnemonic) {
    return null;
  }

  return (
    <div className="flex flex-col h-screen bg-base p-8">
      {/* Header */}
      <div className="flex items-center mb-8">
        <button
          className="btn btn-ghost px-2"
          onClick={() => { void clearMnemonicIfUnchanged().then(() => navigate("/onboarding/identity")); }}
        >
          ← Back
        </button>
        <span className="ml-auto text-muted-color">Step 3 of 5</span>
      </div>

      {/* Content */}
      <div className="flex flex-col items-center justify-center flex-1">
        <h2 className="text-xl font-semibold text-primary-color mb-2">
          Save Your Recovery Phrase
        </h2>

        <p className="status-warning text-center mb-6 max-w-md">
          Write these words down and store them safely.<br />
          This is the ONLY way to recover your identity.
        </p>

        {/* Mnemonic display */}
        <div className="card mb-4 max-w-sm w-full">
          <div className="grid grid-cols-3 gap-2">
            {words.map((word, i) => (
              <div key={i} className="flex items-center gap-1">
                <span className="text-muted-color text-sm">{i + 1}.</span>
                <span className="text-primary-color">{word}</span>
              </div>
            ))}
          </div>
        </div>

        <button
          className="btn btn-ghost mb-4"
          onClick={handleCopy}
        >
          {copiedUntil ? `Copied · clears in ${secondsUntilClear}s` : "Copy to Clipboard"}
        </button>

        <p className="text-xs text-muted-color text-center mb-4 max-w-sm">
          Clipboard history and other applications may retain copied recovery phrases. Prefer writing it down.
        </p>
        {clipboardWarning && (
          <p className="status-warning text-sm text-center mb-4 max-w-sm" role="alert">
            {clipboardWarning}
          </p>
        )}

        {/* Confirmation checkbox */}
        <label className="flex items-center gap-2 mb-6 cursor-pointer">
          <input
            type="checkbox"
            checked={confirmed}
            onChange={(e) => setConfirmed(e.target.checked)}
            className="w-5 h-5 rounded border-default bg-surface-elevated accent-primary"
          />
          <span className="text-secondary-color">
            I have saved my recovery phrase
          </span>
        </label>

        <button
          className="btn btn-primary w-full max-w-xs"
          onClick={handleContinue}
          disabled={!confirmed}
        >
          Continue
        </button>
      </div>
    </div>
  );
}

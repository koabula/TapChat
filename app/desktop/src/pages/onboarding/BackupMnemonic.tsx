import { useState } from "react";
import { useNavigate, useLocation } from "react-router";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";

interface LocationState {
  mnemonic: string;
}

export default function BackupMnemonic() {
  const navigate = useNavigate();
  const location = useLocation();
  const state = location.state as LocationState | null;

  const mnemonic = state?.mnemonic || "";
  const [confirmed, setConfirmed] = useState(false);
  const [copied, setCopied] = useState(false);

  const words = mnemonic.split(" ");

  const handleCopy = async () => {
    try {
      await writeText(mnemonic);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error(`[BackupMnemonic] Failed to copy mnemonic: ${String(err)}`);
    }
  };

  const handleContinue = () => {
    if (confirmed) {
      navigate("/onboarding/cloudflare");
    }
  };

  // If no mnemonic (e.g., direct navigation), redirect to start
  if (!mnemonic) {
    navigate("/onboarding");
    return null;
  }

  return (
    <div className="flex flex-col h-screen bg-base p-8">
      {/* Header */}
      <div className="flex items-center mb-8">
        <button
          className="btn btn-ghost px-2"
          onClick={() => navigate("/onboarding/identity")}
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
          {copied ? "Copied!" : "Copy to Clipboard"}
        </button>

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

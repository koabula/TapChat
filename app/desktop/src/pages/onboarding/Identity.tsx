import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router";
import { invoke } from "@tauri-apps/api/core";

interface CreateIdentityResult {
  user_id: string;
  device_id: string;
  mnemonic: string | null;
}

export default function Identity() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const isRecover = searchParams.get("mode") === "recover";

  const [deviceName, setDeviceName] = useState("My Laptop");
  const [mnemonic, setMnemonic] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async () => {
    setLoading(true);
    setError(null);

    try {
      const result = await invoke<CreateIdentityResult>("create_or_load_identity", {
        mnemonic: isRecover ? mnemonic : null,
        deviceName,
      });

      // Store mnemonic for backup step (only for new identity creation)
      if (!isRecover && result.mnemonic) {
        // Pass mnemonic to next step via state
        navigate("/onboarding/backup", { state: { mnemonic: result.mnemonic } });
      } else {
        // Skip backup for recovery
        navigate("/onboarding/cloudflare");
      }
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-screen bg-base p-8">
      {/* Header */}
      <div className="flex items-center mb-8">
        <button
          className="btn btn-ghost px-2"
          onClick={() => navigate("/onboarding")}
        >
          ← Back
        </button>
        <span className="ml-auto text-muted-color">Step 2 of 5</span>
      </div>

      {/* Content */}
      <div className="flex flex-col items-center justify-center flex-1">
        <h2 className="text-xl font-semibold text-primary-color mb-2">
          {isRecover ? "Recover Your Identity" : "Name Your Device"}
        </h2>

        {!isRecover && (
          <p className="text-secondary-color text-center mb-6 max-w-md">
            This name helps you identify this device when managing multiple devices.
          </p>
        )}

        {isRecover && (
          <p className="text-secondary-color text-center mb-4 max-w-md">
            Enter your 12-word recovery phrase:
          </p>
        )}

        <div className="w-full max-w-sm space-y-4">
          {isRecover && (
            <textarea
              className="input min-h-[100px] resize-none"
              placeholder="word1 word2 word3 word4 ..."
              value={mnemonic}
              onChange={(e) => setMnemonic(e.target.value)}
            />
          )}

          <div>
            <label className="text-sm text-muted-color mb-1 block">Device name</label>
            <input
              className="input"
              placeholder="My Laptop"
              value={deviceName}
              onChange={(e) => setDeviceName(e.target.value)}
            />
          </div>

          {error && (
            <div className="status-error text-sm">{error}</div>
          )}

          <button
            className="btn btn-primary w-full"
            onClick={handleSubmit}
            disabled={loading || (isRecover && !mnemonic.trim())}
          >
            {loading ? "Loading..." : isRecover ? "Recover" : "Continue"}
          </button>
        </div>
      </div>
    </div>
  );
}
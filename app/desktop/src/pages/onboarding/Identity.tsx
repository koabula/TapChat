import { presentError } from "@/lib/errors";
import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router";
import { invokeApp as invoke } from "@/lib/tauri";
import { evaluatePassphraseStrength } from "@/lib/passphraseStrength";

interface ProfileSummary {
  name: string;
  path: string;
  is_active: boolean;
  user_id?: string;
  device_id?: string;
}

interface CreateIdentityResult {
  user_id: string;
  device_id: string;
  mnemonic: string | null;
}

type ProfileProtectionMode =
  | "keychain_and_passphrase"
  | "keychain_only"
  | "passphrase_only";

export default function Identity() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const isRecover = searchParams.get("mode") === "recover";

  const [profileName, setProfileName] = useState("default");
  const [protectionMode, setProtectionMode] =
    useState<ProfileProtectionMode>("keychain_and_passphrase");
  const [profilePassphrase, setProfilePassphrase] = useState("");
  const [confirmProfilePassphrase, setConfirmProfilePassphrase] = useState("");
  const [weakPassphraseAccepted, setWeakPassphraseAccepted] = useState(false);
  const [displayName, setDisplayName] = useState("");
  const [deviceName, setDeviceName] = useState("My Laptop");
  const [mnemonic, setMnemonic] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [step, setStep] = useState<"profile" | "identity">("profile");
  const passphraseStrength = evaluatePassphraseStrength(profilePassphrase, profileName);
  const trimmedPassphrase = profilePassphrase.trim();
  const trimmedConfirmPassphrase = confirmProfilePassphrase.trim();
  const hasAnyPassphraseInput = Boolean(trimmedPassphrase || trimmedConfirmPassphrase);
  const requiresPassphrase = protectionMode !== "keychain_only";
  const passphrasesMatch = !hasAnyPassphraseInput || trimmedPassphrase === trimmedConfirmPassphrase;
  const mustConfirmWeakPassphrase =
    Boolean(trimmedPassphrase) && passphraseStrength.requiresConfirmation;
  const canContinueProfile =
    !loading &&
    Boolean(profileName.trim()) &&
    (!requiresPassphrase || Boolean(trimmedPassphrase)) &&
    passphrasesMatch &&
    (!mustConfirmWeakPassphrase || weakPassphraseAccepted);
  const passphraseStrengthWidth =
    passphraseStrength.level === "empty" ? 0 : Math.max(passphraseStrength.score, 1) * 25;

  const handleInitProfile = async () => {
    setLoading(true);
    setError(null);

    try {
      if (hasAnyPassphraseInput) {
        if (trimmedPassphrase !== trimmedConfirmPassphrase) {
          setError("Profile passphrases do not match.");
          return;
        }
        if (mustConfirmWeakPassphrase && !weakPassphraseAccepted) {
          setError("Please confirm that you understand this passphrase is weak.");
          return;
        }
      }
      console.debug(`[OnboardingIdentity] Initializing profile profileName=${profileName}`);

      // Initialize profile first
      const result = await invoke<ProfileSummary>("init_onboarding_profile", {
        profileName,
        passphrase: requiresPassphrase ? trimmedPassphrase || null : null,
        protectionMode,
      });

      console.debug(
        `[OnboardingIdentity] Profile initialized name=${result.name} active=${result.is_active}`,
      );

      // Move to identity step
      setStep("identity");
    } catch (err) {
      console.error(`[OnboardingIdentity] Failed to create profile: ${presentError(err).message}`);
      // Handle different error formats
      const errorMsg = typeof err === 'string' ? err :
        (err instanceof Error ? err.message :
          JSON.stringify(err));
      setError(errorMsg);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmitIdentity = async () => {
    setLoading(true);
    setError(null);

    try {
      const result = await invoke<CreateIdentityResult>("create_or_load_identity", {
        mnemonic: isRecover ? mnemonic : null,
        deviceName,
        displayName: displayName.trim() || null,
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
      setError(presentError(err).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex h-screen min-h-0 flex-col overflow-hidden bg-base p-8">
      {/* Header */}
      <div className="mb-4 flex shrink-0 items-center">
        <button
          className="btn btn-ghost px-2"
          onClick={() => step === "identity" ? setStep("profile") : navigate("/onboarding")}
        >
          ← Back
        </button>
        <span className="ml-auto text-muted-color">Step 2 of 5</span>
      </div>

      {/* Content */}
      <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain">
        <div
          className={`flex min-h-full flex-col items-center px-2 py-4 ${
            step === "identity" ? "justify-center" : ""
          }`}
        >
        {step === "profile" && (
          <>
            <h2 className="text-xl font-semibold text-primary-color mb-2">
              {isRecover ? "Create a Profile for Recovery" : "Create Your Profile"}
            </h2>
            <p className="text-secondary-color text-center mb-6 max-w-md">
              Your profile stores encrypted messages and contacts locally. Choose how its local
              encryption key is protected.
            </p>

            <div className="w-full max-w-sm space-y-3 pb-4">
              <div>
                <label className="text-sm text-muted-color mb-1 block">Profile name</label>
                <input
                  className="input"
                  placeholder="default"
                  value={profileName}
                  onChange={(e) => {
                    setProfileName(e.target.value);
                    setWeakPassphraseAccepted(false);
                  }}
                />
              </div>

              <fieldset className="space-y-2">
                <legend className="text-sm text-muted-color mb-1">Protection</legend>
                <ProtectionOption
                  checked={protectionMode === "keychain_and_passphrase"}
                  title="System keychain + passphrase"
                  description="Recommended. The passphrase is a backup if the keychain is unavailable."
                  onChange={() => setProtectionMode("keychain_and_passphrase")}
                />
                <ProtectionOption
                  checked={protectionMode === "passphrase_only"}
                  title="Passphrase only"
                  description="Enter the passphrase after each app restart."
                  onChange={() => setProtectionMode("passphrase_only")}
                />
                <ProtectionOption
                  checked={protectionMode === "keychain_only"}
                  title="System keychain only"
                  description="Convenient, but losing the keychain entry may make local data unrecoverable."
                  onChange={() => {
                    setProtectionMode("keychain_only");
                    setProfilePassphrase("");
                    setConfirmProfilePassphrase("");
                    setWeakPassphraseAccepted(false);
                  }}
                />
              </fieldset>

              {requiresPassphrase && <div>
                <label className="text-sm text-muted-color mb-1 block">Profile passphrase</label>
                <input
                  className="input"
                  placeholder="Required"
                  type="password"
                  value={profilePassphrase}
                  onChange={(e) => {
                    setProfilePassphrase(e.target.value);
                    setWeakPassphraseAccepted(false);
                  }}
                />
                <div className="mt-2 space-y-1">
                  <div className="h-1.5 rounded-full bg-surface-elevated overflow-hidden">
                    <div
                      className={`h-full transition-medium ${strengthBarClass(passphraseStrength.level)}`}
                      style={{ width: `${passphraseStrengthWidth}%` }}
                    />
                  </div>
                  <p className={`text-xs ${strengthTextClass(passphraseStrength.level)}`}>
                    {passphraseStrength.label}: {passphraseStrength.message}
                  </p>
                </div>
              </div>}

              {requiresPassphrase && <div>
                <label className="text-sm text-muted-color mb-1 block">Confirm passphrase</label>
                <input
                  className="input"
                  placeholder="Required"
                  type="password"
                  value={confirmProfilePassphrase}
                  onChange={(e) => setConfirmProfilePassphrase(e.target.value)}
                />
                {!passphrasesMatch && (
                  <p className="status-error text-xs mt-1">Profile passphrases do not match.</p>
                )}
              </div>}

              {mustConfirmWeakPassphrase && (
                <label className="flex items-start gap-2 text-sm text-secondary-color">
                  <input
                    className="mt-1 accent-primary"
                    type="checkbox"
                    checked={weakPassphraseAccepted}
                    onChange={(e) => setWeakPassphraseAccepted(e.target.checked)}
                  />
                  <span>I understand this is a weak passphrase and want to use it anyway.</span>
                </label>
              )}

              {error && (
                <div className="status-error text-sm">{error}</div>
              )}

              <button
                className="btn btn-primary w-full"
                onClick={handleInitProfile}
                disabled={!canContinueProfile}
              >
                {loading ? "Creating..." : "Continue"}
              </button>
            </div>
          </>
        )}

        {step === "identity" && (
          <>
            <h2 className="text-xl font-semibold text-primary-color mb-2">
              {isRecover ? "Recover Your Identity" : "Name Your Identity"}
            </h2>

            {!isRecover && (
              <p className="text-secondary-color text-center mb-6 max-w-md">
                Choose the public name contacts will see, then name this device for your own device list.
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
                <label className="text-sm text-muted-color mb-1 block">
                  Display name (optional)
                </label>
                <input
                  className="input"
                  value={displayName}
                  maxLength={64}
                  onChange={(e) => setDisplayName(e.target.value)}
                />
              </div>

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
                onClick={handleSubmitIdentity}
                disabled={loading || (isRecover && !mnemonic.trim())}
              >
                {loading ? "Loading..." : isRecover ? "Recover" : "Continue"}
              </button>
            </div>
          </>
        )}
        </div>
      </div>
    </div>
  );
}

function ProtectionOption({
  checked,
  title,
  description,
  onChange,
}: {
  checked: boolean;
  title: string;
  description: string;
  onChange: () => void;
}) {
  return (
    <label className="flex cursor-pointer items-start gap-2.5 rounded-lg border border-default px-3 py-2">
      <input
        className="mt-1 accent-primary"
        type="radio"
        name="profile-protection"
        checked={checked}
        onChange={onChange}
      />
      <span>
        <span className="block text-sm font-medium text-primary-color">{title}</span>
        <span className="block text-xs text-muted-color mt-1">{description}</span>
      </span>
    </label>
  );
}

function strengthBarClass(level: ReturnType<typeof evaluatePassphraseStrength>["level"]): string {
  switch (level) {
    case "empty":
      return "bg-surface-elevated";
    case "very_weak":
    case "weak":
      return "bg-[var(--error)]";
    case "fair":
      return "bg-[var(--warning)]";
    case "strong":
      return "bg-[var(--success)]";
  }
}

function strengthTextClass(level: ReturnType<typeof evaluatePassphraseStrength>["level"]): string {
  switch (level) {
    case "very_weak":
    case "weak":
      return "status-error";
    case "fair":
      return "status-warning";
    case "empty":
    case "strong":
      return "text-muted-color";
  }
}

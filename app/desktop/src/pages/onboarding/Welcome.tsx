import { presentError } from "@/lib/errors";
import { invokeApp as invoke } from "@/lib/tauri";
import type { ProfileSummary } from "@/lib/types";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router";

export default function Welcome() {
  const navigate = useNavigate();
  const [profiles, setProfiles] = useState<ProfileSummary[]>([]);
  const [busyPath, setBusyPath] = useState<string | null>(null);
  const [passphrasePath, setPassphrasePath] = useState<string | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    invoke<ProfileSummary[]>("list_profiles")
      .then((items) => {
        if (!cancelled) {
          setProfiles(
            items.filter(
              (profile) =>
                profile.user_id && profile.device_id && profile.runtime_bound !== false,
            ),
          );
        }
      })
      .catch((reason) => {
        if (!cancelled) setError(presentError(reason).message);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const beginIdentity = async (mode: "create" | "recover") => {
    setError(null);
    try {
      await invoke("set_onboarding_step", {
        step: mode === "recover" ? "recover_identity" : "create_identity",
      });
      navigate(mode === "recover" ? "/onboarding/identity?mode=recover" : "/onboarding/identity");
    } catch (reason) {
      setError(presentError(reason).message);
    }
  };

  const activateProfile = async (profile: ProfileSummary) => {
    setBusyPath(profile.path);
    setError(null);
    try {
      await invoke("activate_profile", {
        path: profile.path,
        passphrase: passphrasePath === profile.path ? passphrase || null : null,
      });
    } catch (reason) {
      const presented = presentError(reason);
      setError(presented.message);
      if (
        presented.error.code === "profile_passphrase_required" ||
        presented.error.code === "auth_failed"
      ) {
        setPassphrasePath(profile.path);
      }
    } finally {
      setBusyPath(null);
    }
  };

  return (
    <div className="flex h-screen flex-col items-center justify-center bg-base p-8">
      <div className="mb-6 flex h-16 w-16 items-center justify-center rounded-full bg-primary">
        <span className="text-2xl font-bold text-white">T</span>
      </div>

      <h1 className="mb-2 text-3xl font-semibold text-primary-color">TapChat</h1>
      <p className="mb-8 text-center text-secondary-color">
        Private. Decentralized.
        <br />
        Yours.
      </p>

      <div className="flex w-full max-w-sm flex-col gap-4">
        <button className="btn btn-primary w-full" onClick={() => void beginIdentity("create")}>
          Create New Identity
        </button>
        <button className="btn btn-secondary w-full" onClick={() => void beginIdentity("recover")}>
          Recover Identity on This Device
        </button>

        {profiles.length > 0 ? (
          <div className="mt-2 space-y-2 border-t border-default pt-4">
            <p className="text-center text-sm text-muted-color">Or use an existing profile</p>
            {profiles.map((profile) => (
              <div key={profile.path} className="rounded-lg border border-default p-3">
                <button
                  className="w-full text-left"
                  disabled={busyPath !== null}
                  onClick={() => void activateProfile(profile)}
                >
                  <span className="block font-medium text-primary-color">{profile.name}</span>
                  <span className="block text-xs text-muted-color">
                    {profileReference(profile)} · {profile.runtime_bound ? "Connected" : "Ready to unlock"}
                  </span>
                </button>
                {passphrasePath === profile.path ? (
                  <div className="mt-3 flex gap-2">
                    <input
                      className="input min-w-0 flex-1"
                      type="password"
                      autoFocus
                      placeholder="Profile passphrase"
                      value={passphrase}
                      onChange={(event) => setPassphrase(event.target.value)}
                      onKeyDown={(event) => {
                        if (event.key === "Enter" && passphrase && busyPath === null) {
                          void activateProfile(profile);
                        }
                      }}
                    />
                    <button
                      className="btn btn-primary"
                      disabled={!passphrase || busyPath !== null}
                      onClick={() => void activateProfile(profile)}
                    >
                      Open
                    </button>
                  </div>
                ) : null}
              </div>
            ))}
          </div>
        ) : null}

        {error ? (
          <div className="status-error text-sm" role="alert">
            {error}
          </div>
        ) : null}
      </div>
    </div>
  );
}

function profileReference(profile: ProfileSummary): string {
  const component = profile.path.split(/[\\/]/).at(-1) ?? profile.path;
  const user = profile.user_id ? shortId(profile.user_id) : "Unknown identity";
  const device = profile.device_id ? shortId(profile.device_id) : "Unknown device";
  return `${user} · ${device} · Profile …${component.slice(-8)}`;
}

function shortId(value: string): string {
  return value.length > 8 ? `…${value.slice(-8)}` : value;
}

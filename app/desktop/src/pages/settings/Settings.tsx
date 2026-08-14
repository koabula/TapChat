import { useEffect, useMemo, useState } from "react";
import type { ComponentType } from "react";
import { invoke } from "@tauri-apps/api/core";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { listen } from "@tauri-apps/api/event";
import { relaunch } from "@tauri-apps/plugin-process";
import {
  Check,
  ChevronDown,
  ChevronRight,
  Code2,
  Download,
  ExternalLink,
  HardDrive,
  Palette,
  Paperclip,
  RefreshCw,
  Server,
  UserRound,
  X,
} from "lucide-react";

import { useManualUpdate } from "@/hooks/useAutoUpdate";
import { clearClipboardIfUnchanged } from "@/lib/clipboardSecurity";
import { THEME_OPTIONS, type ResolvedTheme } from "@/lib/theme";
import { useThemeStore } from "@/store/theme";
import Devices from "./Devices";
import Runtime from "./Runtime";

import {
  getIdentityInfo,
  getShareLink,
  rotateShareLink,
  setLocalDisplayName,
  listProfiles,
  selectProfileForRestart,
  deleteProfile,
  startNewProfileOnboarding,
  addToAllowlist,
  removeFromAllowlist,
  getAllowlist,
  setDebugMode,
  getDebugMode,
  getAppMetadata,
  beginRecoveryPhraseReveal,
  completeRecoveryPhraseReveal,
} from "@/lib/tauri";
import type {
  AppMetadata,
  IdentityInfo,
  ProfileSummary,
  RecoveryPhraseRevealChallenge,
} from "@/lib/types";

export type SettingsSection =
  | "account"
  | "appearance"
  | "devices"
  | "runtime"
  | "attachments"
  | "developer";

interface SettingsProps {
  initialSection?: SettingsSection;
}

interface SettingsNavItem {
  id: SettingsSection;
  label: string;
  description: string;
  Icon: ComponentType<{ size?: number; className?: string }>;
}

const DEVELOPER_MODE_SESSION_KEY = "tapchat:developerMode";
const DEVELOPER_MODE_CLICK_TARGET = 5;

function readSessionDeveloperMode(): boolean {
  if (typeof window === "undefined") return false;
  try {
    return window.sessionStorage.getItem(DEVELOPER_MODE_SESSION_KEY) === "true";
  } catch {
    return false;
  }
}

function writeSessionDeveloperMode(enabled: boolean) {
  try {
    if (enabled) {
      window.sessionStorage.setItem(DEVELOPER_MODE_SESSION_KEY, "true");
    } else {
      window.sessionStorage.removeItem(DEVELOPER_MODE_SESSION_KEY);
    }
  } catch {
    // Developer mode is a convenience toggle; sessionStorage failure is non-fatal.
  }
}

export default function Settings({ initialSection = "account" }: SettingsProps) {
  const [activeSection, setActiveSection] = useState<SettingsSection>(initialSection);
  const [identity, setIdentity] = useState<IdentityInfo | null>(null);
  const [appMetadata, setAppMetadata] = useState<AppMetadata | null>(null);
  const [profiles, setProfiles] = useState<ProfileSummary[]>([]);
  const [recoveryChallenge, setRecoveryChallenge] =
    useState<RecoveryPhraseRevealChallenge | null>(null);
  const [recoveryPassphrase, setRecoveryPassphrase] = useState("");
  const [recoveryConfirmed, setRecoveryConfirmed] = useState(false);
  const [recoveryPhrase, setRecoveryPhrase] = useState<string | null>(null);
  const [recoveryError, setRecoveryError] = useState<string | null>(null);
  const [recoveryLoading, setRecoveryLoading] = useState(false);
  const [recoveryPhraseCopied, setRecoveryPhraseCopied] = useState(false);
  const [newAllowlistUser, setNewAllowlistUser] = useState("");
  const [allowlist, setAllowlist] = useState<string[]>([]);
  const [debugMode, setDebugModeState] = useState(false);
  const [developerMode, setDeveloperMode] = useState(readSessionDeveloperMode);
  const [developerClickCount, setDeveloperClickCount] = useState(0);
  const [showAboutDetails, setShowAboutDetails] = useState(false);
  const [copied, setCopied] = useState(false);
  const [switchingProfile, setSwitchingProfile] = useState<string | null>(null);
  const update = useManualUpdate();

  const [editingDisplayName, setEditingDisplayName] = useState(false);
  const [displayNameInput, setDisplayNameInput] = useState("");
  const [savingDisplayName, setSavingDisplayName] = useState(false);
  const [showCreateConfirm, setShowCreateConfirm] = useState(false);
  const [startingOnboarding, setStartingOnboarding] = useState(false);
  const [deletingProfile, setDeletingProfile] = useState<string | null>(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState<{ path: string; name: string } | null>(null);

  const themePreference = useThemeStore((s) => s.preference);
  const resolvedTheme = useThemeStore((s) => s.resolvedTheme);
  const setThemePreference = useThemeStore((s) => s.setThemePreference);

  useEffect(() => {
    setActiveSection(initialSection);
    setRecoveryChallenge(null);
    setRecoveryPassphrase("");
    setRecoveryConfirmed(false);
    setRecoveryPhrase(null);
    setRecoveryError(null);
    setRecoveryLoading(false);
    setRecoveryPhraseCopied(false);
  }, [initialSection]);

  useEffect(() => {
    void loadIdentity();
    void loadAppMetadata();
    void loadProfiles();

    const unlistenEngineReloaded = listen<void>("engine-reloaded", () => {
      console.debug("[Settings] Engine reloaded, refreshing settings data");
      void loadIdentity();
      void loadProfiles();
      if (readSessionDeveloperMode()) {
        void loadAllowlist();
        void loadDebugMode();
      }
    });

    return () => {
      unlistenEngineReloaded.then((fn) => fn());
    };
  }, []);

  useEffect(() => {
    if (!developerMode) {
      if (activeSection === "developer") {
        setActiveSection("account");
      }
      return;
    }
    void loadAllowlist();
    void loadDebugMode();
  }, [activeSection, developerMode]);

  useEffect(() => {
    if (!recoveryPhrase) return;
    const hide = () => closeRecoveryPhraseDialog();
    const timeoutId = window.setTimeout(hide, 60_000);
    window.addEventListener("blur", hide);
    return () => {
      window.clearTimeout(timeoutId);
      window.removeEventListener("blur", hide);
    };
  }, [recoveryPhrase]);

  const navItems = useMemo<SettingsNavItem[]>(() => {
    const items: SettingsNavItem[] = [
      { id: "account", label: "Account", description: "Identity and profiles", Icon: UserRound },
      { id: "appearance", label: "Appearance", description: "Themes and color", Icon: Palette },
      { id: "devices", label: "Devices", description: "Local device state", Icon: HardDrive },
      { id: "runtime", label: "Runtime", description: "Cloudflare inbox/storage", Icon: Server },
      { id: "attachments", label: "Attachments", description: "Media and downloads", Icon: Paperclip },
    ];
    if (developerMode) {
      items.push({ id: "developer", label: "Developer", description: "Diagnostics and testing", Icon: Code2 });
    }
    return items;
  }, [developerMode]);

  const activeItem = navItems.find((item) => item.id === activeSection) ?? navItems[0];
  const followsSystemTheme = themePreference === "system";
  const updateProgressPercent = Math.round(update.progress);
  const remainingDeveloperClicks = DEVELOPER_MODE_CLICK_TARGET - developerClickCount;

  const loadIdentity = async () => {
    try {
      const result = await getIdentityInfo();
      setIdentity(result);
      setDisplayNameInput(result?.display_name || "");
    } catch (err) {
      console.error(`[Settings] Failed to get identity: ${String(err)}`);
    }
  };

  const loadAppMetadata = async () => {
    try {
      setAppMetadata(await getAppMetadata());
    } catch (err) {
      console.error(`[Settings] Failed to get app metadata: ${String(err)}`);
    }
  };

  const loadProfiles = async () => {
    try {
      setProfiles(await listProfiles());
    } catch (err) {
      console.error(`[Settings] Failed to load profiles: ${String(err)}`);
    }
  };

  const loadAllowlist = async () => {
    try {
      const result = await getAllowlist();
      if (result.view_model?.allowlist) {
        setAllowlist(result.view_model.allowlist.allowed_sender_user_ids || []);
      }
    } catch (err) {
      console.error(`[Settings] Failed to load allowlist: ${String(err)}`);
    }
  };

  const loadDebugMode = async () => {
    try {
      setDebugModeState(await getDebugMode());
    } catch {
      // debug mode toggle is best-effort
    }
  };

  const handleToggleDebugMode = async () => {
    const next = !debugMode;
    setDebugModeState(next);
    try {
      await setDebugMode(next);
    } catch {
      setDebugModeState(!next);
    }
  };

  const handleVersionClick = () => {
    if (developerMode) return;
    setDeveloperClickCount((current) => {
      const next = current + 1;
      if (next >= DEVELOPER_MODE_CLICK_TARGET) {
        setDeveloperMode(true);
        writeSessionDeveloperMode(true);
        return 0;
      }
      return next;
    });
  };

  const handleDisableDeveloperMode = async () => {
    setDeveloperMode(false);
    writeSessionDeveloperMode(false);
    setDeveloperClickCount(0);
    if (debugMode) {
      setDebugModeState(false);
      try {
        await setDebugMode(false);
      } catch {
        // Best-effort cleanup.
      }
    }
  };

  const handleCopyShareLink = async () => {
    try {
      const link = await getShareLink();
      if (link) {
        await writeText(link);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      }
    } catch (err) {
      console.error(`[Settings] Failed to copy share link: ${String(err)}`);
    }
  };

  const handleRotateLink = async () => {
    try {
      await rotateShareLink();
      alert("Share link rotated. Share the new link with your contacts.");
    } catch (err) {
      console.error(`[Settings] Failed to rotate share link: ${String(err)}`);
      alert(String(err));
    }
  };

  const closeRecoveryPhraseDialog = () => {
    setRecoveryChallenge(null);
    setRecoveryPassphrase("");
    setRecoveryConfirmed(false);
    setRecoveryPhrase(null);
    setRecoveryError(null);
    setRecoveryLoading(false);
    setRecoveryPhraseCopied(false);
  };

  const handleBeginRecoveryPhraseReveal = async () => {
    setRecoveryLoading(true);
    setRecoveryError(null);
    try {
      setRecoveryChallenge(await beginRecoveryPhraseReveal());
    } catch {
      setRecoveryError("Recovery phrase access is unavailable while this profile is locked.");
    } finally {
      setRecoveryLoading(false);
    }
  };

  const handleCompleteRecoveryPhraseReveal = async () => {
    if (!recoveryChallenge) return;
    setRecoveryLoading(true);
    setRecoveryError(null);
    try {
      const result = await completeRecoveryPhraseReveal(
        recoveryChallenge.challenge_id,
        recoveryChallenge.auth_mode === "passphrase" ? recoveryPassphrase : null,
        recoveryChallenge.auth_mode === "confirmation_only" && recoveryConfirmed,
      );
      setRecoveryPassphrase("");
      setRecoveryPhrase(result.mnemonic);
    } catch (error) {
      setRecoveryChallenge(null);
      setRecoveryPassphrase("");
      setRecoveryConfirmed(false);
      setRecoveryError(
        String(error).includes("auth_failed")
          ? "The profile passphrase is incorrect. Start again to retry."
          : "The sensitive-action challenge expired. Start again to retry.",
      );
    } finally {
      setRecoveryLoading(false);
    }
  };

  const handleCopyRecoveryPhrase = async () => {
    if (!recoveryPhrase) return;
    await writeText(recoveryPhrase);
    setRecoveryPhraseCopied(true);
    window.setTimeout(() => setRecoveryPhraseCopied(false), 2_000);
    window.setTimeout(() => {
      void clearClipboardIfUnchanged(recoveryPhrase);
    }, 60_000);
  };

  const handleAddAllowlist = async () => {
    if (!newAllowlistUser.trim()) return;
    try {
      await addToAllowlist(newAllowlistUser);
      setNewAllowlistUser("");
      void loadAllowlist();
    } catch (err) {
      console.error(`[Settings] Failed to add allowlist entry: ${String(err)}`);
    }
  };

  const handleRemoveAllowlist = async (userId: string) => {
    try {
      await removeFromAllowlist(userId);
      void loadAllowlist();
    } catch (err) {
      console.error(`[Settings] Failed to remove allowlist entry: ${String(err)}`);
    }
  };

  const handleSaveDisplayName = async () => {
    setSavingDisplayName(true);
    try {
      const nameToSave = displayNameInput.trim() || null;
      const output = await setLocalDisplayName(nameToSave);
      const identityUpdate = output.view_model?.identity;
      if (identityUpdate) {
        setIdentity((current) =>
          current
            ? {
                ...current,
                user_id: identityUpdate.user_id,
                device_id: identityUpdate.device_id,
                display_name: identityUpdate.display_name ?? null,
              }
            : current,
        );
        setDisplayNameInput(identityUpdate.display_name ?? "");
      }
      setEditingDisplayName(false);
      void loadIdentity();
    } catch (err) {
      console.error(`[Settings] Failed to save display name: ${String(err)}`);
      alert(String(err));
    } finally {
      setSavingDisplayName(false);
    }
  };

  const handleSwitchProfile = async (path: string) => {
    setSwitchingProfile(path);
    try {
      try {
        await selectProfileForRestart(path);
      } catch (err) {
        const errorMsg = String(err);
        if (!errorMsg.toLowerCase().includes("passphrase")) {
          throw err;
        }
        const passphrase = window.prompt("Enter the profile passphrase");
        if (!passphrase) {
          throw err;
        }
        await selectProfileForRestart(path, passphrase);
      }
      await relaunch();
    } catch (err) {
      console.error(`[Settings] Profile switch error: ${String(err)}`);
      const errorMsg = String(err);
      if (errorMsg !== "") {
        if (errorMsg.toLowerCase().includes("restart") || errorMsg.toLowerCase().includes("relaunch")) {
          alert(`Profile selected. Please restart TapChat manually to finish switching.\n\n${errorMsg}`);
        } else {
          alert(errorMsg);
        }
      }
    } finally {
      void loadProfiles();
      setSwitchingProfile(null);
    }
  };

  const handleStartNewProfileOnboarding = async () => {
    setStartingOnboarding(true);
    try {
      await startNewProfileOnboarding();
      setShowCreateConfirm(false);
    } catch (err) {
      console.error(`[Settings] Failed to start onboarding: ${String(err)}`);
      alert(String(err));
    } finally {
      setStartingOnboarding(false);
    }
  };

  const handleDeleteProfile = (path: string, name: string) => {
    setShowDeleteConfirm({ path, name });
  };

  const confirmDeleteProfile = async () => {
    if (!showDeleteConfirm) return;
    const { path } = showDeleteConfirm;
    setDeletingProfile(path);
    setShowDeleteConfirm(null);
    try {
      await deleteProfile(path);
      void loadProfiles();
    } catch (err) {
      console.error(`[Settings] Failed to delete profile: ${String(err)}`);
      alert(String(err));
    } finally {
      setDeletingProfile(null);
    }
  };

  const selectTheme = (theme: ResolvedTheme) => {
    setThemePreference(theme);
  };

  const toggleFollowSystemTheme = () => {
    setThemePreference(followsSystemTheme ? resolvedTheme : "system");
  };

  return (
    <div className="flex h-full min-h-0 overflow-hidden bg-base">
      <aside className="w-56 shrink-0 border-r border-subtle bg-surface">
        <div className="border-b border-subtle px-4 py-4">
          <h1 className="font-semibold text-primary-color">Settings</h1>
          <p className="mt-1 text-xs text-muted-color">TapChat preferences</p>
        </div>
        <nav className="space-y-1 p-2">
          {navItems.map((item) => {
            const selected = activeSection === item.id;
            return (
              <button
                key={item.id}
                className={`flex w-full items-center gap-3 rounded-md px-3 py-2 text-left transition-colors ${
                  selected
                    ? "bg-primary/10 text-primary-color"
                    : "text-secondary-color hover:bg-surface-elevated hover:text-primary-color"
                }`}
                onClick={() => {
                  closeRecoveryPhraseDialog();
                  setActiveSection(item.id);
                }}
              >
                <item.Icon size={17} />
                <span className="min-w-0">
                  <span className="block truncate text-sm font-medium">{item.label}</span>
                  <span className="block truncate text-[11px] text-muted-color">
                    {item.description}
                  </span>
                </span>
              </button>
            );
          })}
        </nav>
      </aside>

      <main className="min-w-0 flex-1 overflow-y-auto overscroll-contain">
        <div className="mx-auto w-full max-w-3xl px-6 py-5">
          <div className="mb-5">
            <h2 className="text-xl font-semibold text-primary-color">{activeItem.label}</h2>
            <p className="mt-1 text-sm text-muted-color">{activeItem.description}</p>
          </div>
          {activeSection === "account" && renderAccountPanel()}
          {activeSection === "appearance" && renderAppearancePanel()}
          {activeSection === "devices" && <Devices embedded />}
          {activeSection === "runtime" && <Runtime embedded />}
          {activeSection === "attachments" && <AttachmentsSettings />}
          {activeSection === "developer" && developerMode && renderDeveloperPanel()}
        </div>
      </main>
    </div>
  );

  function renderAppearancePanel() {
    return (
      <section className="card space-y-4">
        <label className="flex cursor-pointer items-center justify-between gap-4">
          <div className="min-w-0">
            <span className="text-primary-color">Follow system</span>
            <p className="mt-0.5 text-xs text-muted-color">
              Uses Nord Light or Nord Dark based on your OS appearance.
            </p>
          </div>
          <button
            className={`h-6 w-11 flex-shrink-0 rounded-full transition-colors ${
              followsSystemTheme ? "bg-primary" : "bg-surface-elevated"
            }`}
            role="switch"
            aria-checked={followsSystemTheme}
            onClick={toggleFollowSystemTheme}
          >
            <span
              className={`block h-5 w-5 rounded-full bg-white transition-transform ${
                followsSystemTheme ? "translate-x-5" : "translate-x-1"
              }`}
            />
          </button>
        </label>

        <div className="grid gap-2 sm:grid-cols-2">
          {THEME_OPTIONS.map((theme) => {
            const selected = themePreference === theme.id;
            const activeViaSystem = followsSystemTheme && resolvedTheme === theme.id;
            return (
              <button
                key={theme.id}
                className={`rounded-lg border p-3 text-left transition-colors ${
                  selected
                    ? "border-primary bg-primary/10"
                    : activeViaSystem
                      ? "border-default bg-surface-elevated"
                      : "border-subtle hover:border-default hover:bg-surface-elevated"
                }`}
                onClick={() => selectTheme(theme.id)}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="font-medium text-primary-color">{theme.label}</div>
                    <div className="mt-0.5 text-xs text-muted-color">
                      {theme.description}
                    </div>
                  </div>
                  {(selected || activeViaSystem) && (
                    <span
                      className={`mt-0.5 inline-flex h-5 w-5 items-center justify-center rounded-full ${
                        selected ? "bg-primary" : "bg-surface text-muted-color"
                      }`}
                      style={selected ? { color: "var(--bubble-sent-text)" } : undefined}
                      title={selected ? "Selected" : "Active from system"}
                    >
                      <Check size={13} />
                    </span>
                  )}
                </div>
                <div className="mt-3 flex items-center gap-1">
                  <span
                    className="h-5 flex-1 rounded border border-subtle"
                    style={{ backgroundColor: theme.preview.base }}
                  />
                  <span
                    className="h-5 flex-1 rounded border border-subtle"
                    style={{ backgroundColor: theme.preview.surface }}
                  />
                  <span
                    className="h-5 flex-1 rounded border border-subtle"
                    style={{ backgroundColor: theme.preview.accent }}
                  />
                </div>
              </button>
            );
          })}
        </div>
      </section>
    );
  }

  function renderAccountPanel() {
    return (
      <div className="space-y-4">
        <section className="card space-y-3">
          <div className="flex items-center justify-between gap-3">
            <div>
              <h3 className="font-medium text-primary-color">Identity</h3>
              <p className="text-xs text-muted-color">Local name and share link</p>
            </div>
            <button className="btn btn-secondary text-sm" onClick={handleCopyShareLink}>
              {copied ? "Copied!" : "Copy Share Link"}
            </button>
          </div>

          <div>
            <label className="mb-1 block text-xs text-muted-color">Display name</label>
            {editingDisplayName ? (
              <div className="flex items-center gap-2">
                <input
                  className="input flex-1"
                  value={displayNameInput}
                  onChange={(event) => setDisplayNameInput(event.target.value)}
                  placeholder="Display name"
                  maxLength={64}
                />
                <button
                  className="btn btn-primary"
                  onClick={handleSaveDisplayName}
                  disabled={savingDisplayName}
                >
                  {savingDisplayName ? "Saving..." : "Save"}
                </button>
                <button
                  className="btn btn-ghost"
                  onClick={() => {
                    setEditingDisplayName(false);
                    setDisplayNameInput(identity?.display_name || "");
                  }}
                >
                  Cancel
                </button>
              </div>
            ) : (
              <div className="flex items-center justify-between gap-3">
                <span className="text-primary-color">
                  {identity?.display_name || "No display name"}
                </span>
                <button className="btn btn-ghost text-sm" onClick={() => setEditingDisplayName(true)}>
                  Edit
                </button>
              </div>
            )}
          </div>

          <InfoRow label="User ID" value={identity?.user_id ?? "Loading..."} />
          <InfoRow label="Device ID" value={identity?.device_id ?? "Loading..."} />
          <div className="flex gap-2">
            <button className="btn btn-ghost" onClick={handleRotateLink}>
              Rotate Link
            </button>
          </div>
        </section>

        <section className="card space-y-2">
          <div className="flex items-center justify-between gap-3">
            <div>
              <h3 className="font-medium text-primary-color">Profiles</h3>
              <p className="text-xs text-muted-color">Switch or create local profiles</p>
            </div>
          </div>

          {profiles.length === 0 && (
            <p className="text-sm text-muted-color">No profiles found. Create a profile during onboarding.</p>
          )}

          {profiles.map((profile) => (
            <div
              key={profile.path}
              className={`flex items-center justify-between rounded-md p-2 ${
                profile.is_active ? "bg-surface-elevated" : ""
              }`}
            >
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span
                    className={`h-2 w-2 rounded-full ${
                      profile.is_active ? "status-success" : "bg-surface-elevated"
                    }`}
                  />
                  <span className="font-medium text-primary-color">{profile.name}</span>
                  {profile.runtime_bound && (
                    <span className="text-xs status-success">Connected</span>
                  )}
                </div>
                {profile.user_id && (
                  <div className="truncate text-xs text-muted-color">
                    {profile.user_id.slice(0, 16)}...
                  </div>
                )}
              </div>
              <div className="flex items-center gap-1">
                {profile.is_active ? (
                  <span className="text-xs text-muted-color">Active</span>
                ) : (
                  <>
                    <button
                      className="btn btn-ghost text-sm"
                      onClick={() => void handleSwitchProfile(profile.path)}
                      disabled={switchingProfile === profile.path}
                    >
                      {switchingProfile === profile.path ? "Restarting..." : "Switch"}
                    </button>
                    <button
                      className="btn btn-ghost text-xs status-error"
                      onClick={() => handleDeleteProfile(profile.path, profile.name)}
                      disabled={deletingProfile === profile.path}
                    >
                      {deletingProfile === profile.path ? "..." : <X size={14} />}
                    </button>
                  </>
                )}
              </div>
            </div>
          ))}

          {showDeleteConfirm && (
            <div className="rounded-md border border-subtle bg-error/10 p-3">
              <p className="mb-2 status-error">Delete profile "{showDeleteConfirm.name}"?</p>
              <p className="mb-3 text-sm text-muted-color">
                This action cannot be undone. All data in this profile will be permanently deleted.
              </p>
              <div className="flex items-center gap-2">
                <button
                  className="btn btn-ghost status-error"
                  onClick={() => void confirmDeleteProfile()}
                  disabled={deletingProfile === showDeleteConfirm.path}
                >
                  {deletingProfile === showDeleteConfirm.path ? "Deleting..." : "Yes, Delete"}
                </button>
                <button
                  className="btn btn-ghost"
                  onClick={() => setShowDeleteConfirm(null)}
                  disabled={deletingProfile !== null}
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          {showCreateConfirm ? (
            <div className="rounded-md border border-subtle bg-surface-elevated p-3">
              <p className="mb-3 text-primary-color">
                Create a new profile? You will be guided through the setup process.
              </p>
              <div className="flex items-center gap-2">
                <button
                  className="btn btn-primary"
                  onClick={() => void handleStartNewProfileOnboarding()}
                  disabled={startingOnboarding}
                >
                  {startingOnboarding ? "Starting..." : "Yes, Start Setup"}
                </button>
                <button className="btn btn-ghost" onClick={() => setShowCreateConfirm(false)}>
                  Cancel
                </button>
              </div>
            </div>
          ) : (
            <button className="btn btn-secondary w-full" onClick={() => setShowCreateConfirm(true)}>
              Create New Profile
            </button>
          )}
        </section>

        <section className="card">
          <h3 className="mb-3 font-medium text-primary-color">Recovery Phrase</h3>
          <p className="mb-3 text-sm text-muted-color">
            Viewing this secret requires an explicit sensitive action. It is never returned by
            normal identity queries.
          </p>
          <button
            className="btn btn-secondary w-full"
            onClick={() => void handleBeginRecoveryPhraseReveal()}
            disabled={!identity || recoveryLoading}
          >
            {recoveryLoading ? "Preparing..." : "Show Recovery Phrase"}
          </button>
          {recoveryError && !recoveryChallenge && (
            <p role="alert" className="status-error mt-2 text-sm">
              {recoveryError}
            </p>
          )}
        </section>

        {(recoveryChallenge || recoveryPhrase) && (
          <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
            role="dialog"
            aria-modal="true"
            aria-labelledby="recovery-phrase-dialog-title"
          >
            <div className="w-full max-w-lg rounded-lg border border-default bg-surface p-5 shadow-xl">
              <div className="mb-4 flex items-center justify-between gap-3">
                <h3 id="recovery-phrase-dialog-title" className="font-semibold text-primary-color">
                  Recovery Phrase
                </h3>
                <button
                  className="btn btn-ghost px-2"
                  onClick={closeRecoveryPhraseDialog}
                  aria-label="Close recovery phrase dialog"
                >
                  <X size={18} />
                </button>
              </div>

              {!recoveryPhrase && recoveryChallenge?.auth_mode === "passphrase" && (
                <label className="block">
                  <span className="mb-1 block text-sm text-secondary-color">
                    Enter the active profile passphrase
                  </span>
                  <input
                    className="input w-full"
                    type="password"
                    autoComplete="current-password"
                    value={recoveryPassphrase}
                    onChange={(event) => setRecoveryPassphrase(event.target.value)}
                    autoFocus
                  />
                </label>
              )}

              {!recoveryPhrase && recoveryChallenge?.auth_mode === "confirmation_only" && (
                <div className="space-y-3">
                  <p className="status-warning text-sm">
                    This profile has no passphrase. This confirmation is not Windows Hello,
                    Touch ID, or other system-level re-authentication. Anyone controlling this
                    unlocked app session may be able to reveal the phrase.
                  </p>
                  <label className="flex items-start gap-2 text-sm text-secondary-color">
                    <input
                      type="checkbox"
                      checked={recoveryConfirmed}
                      onChange={(event) => setRecoveryConfirmed(event.target.checked)}
                    />
                    <span>I understand the risk and want to reveal the recovery phrase.</span>
                  </label>
                </div>
              )}

              {recoveryError && (
                <p role="alert" className="status-error mt-3 text-sm">
                  {recoveryError}
                </p>
              )}

              {recoveryPhrase ? (
                <div className="space-y-4">
                  <p className="status-warning text-sm">
                    Keep this secret. It will be hidden after 60 seconds or when the window loses
                    focus.
                  </p>
                  <div className="grid grid-cols-3 gap-2 rounded bg-surface-elevated p-3">
                    {recoveryPhrase.split(" ").map((word, index) => (
                      <div key={index} className="flex items-center gap-1">
                        <span className="text-xs text-muted-color">{index + 1}.</span>
                        <span className="text-sm text-primary-color">{word}</span>
                      </div>
                    ))}
                  </div>
                  <div className="flex gap-2">
                    <button
                      className="btn btn-secondary flex-1"
                      onClick={() => void handleCopyRecoveryPhrase()}
                    >
                      {recoveryPhraseCopied ? "Copied" : "Copy for 60 seconds"}
                    </button>
                    <button className="btn btn-primary flex-1" onClick={closeRecoveryPhraseDialog}>
                      Hide now
                    </button>
                  </div>
                </div>
              ) : (
                <div className="mt-4 flex justify-end gap-2">
                  <button className="btn btn-ghost" onClick={closeRecoveryPhraseDialog}>
                    Cancel
                  </button>
                  <button
                    className="btn btn-primary"
                    onClick={() => void handleCompleteRecoveryPhraseReveal()}
                    disabled={
                      recoveryLoading ||
                      (recoveryChallenge?.auth_mode === "passphrase"
                        ? !recoveryPassphrase
                        : !recoveryConfirmed)
                    }
                  >
                    {recoveryLoading ? "Verifying..." : "Reveal"}
                  </button>
                </div>
              )}
            </div>
          </div>
        )}

        {renderAboutCard()}
      </div>
    );
  }

  function renderAboutCard() {
    return (
      <section className="card space-y-3">
        <div className="flex items-center justify-between gap-3">
          <button className="min-w-0 flex-1 text-left" onClick={handleVersionClick}>
            <span className="mb-1 block text-xs text-muted-color">Version</span>
            <span className="text-primary-color">
              {appMetadata?.app_version ?? "Loading..."}
            </span>
            {appMetadata?.git_tag && (
              <span className="ml-2 text-xs text-muted-color">{appMetadata.git_tag}</span>
            )}
          </button>
          <button
            className="btn btn-ghost flex-shrink-0 text-sm"
            onClick={() => setShowAboutDetails((value) => !value)}
            aria-expanded={showAboutDetails}
          >
            {showAboutDetails ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            Details
          </button>
        </div>

        {!developerMode && developerClickCount >= 3 && (
          <p className="text-xs text-muted-color">
            {remainingDeveloperClicks} more tap{remainingDeveloperClicks === 1 ? "" : "s"} to enable developer mode.
          </p>
        )}

        {showAboutDetails && (
          <div className="space-y-3 border-t border-subtle pt-3">
            <div className="grid gap-3 sm:grid-cols-2">
              <InfoRow label="Core" value={appMetadata?.core_version ?? "Unknown"} />
              <InfoRow label="Protocol" value={appMetadata?.protocol_version ?? "Unknown"} />
              <InfoRow label="Commit" value={appMetadata?.git_sha ?? "Unknown"} />
              <InfoRow
                label="Updates"
                value={appMetadata ? (appMetadata.update_endpoint_configured ? "Configured" : "Unavailable") : "Loading..."}
              />
            </div>

            {appMetadata && !appMetadata.update_endpoint_configured && (
              <p className="status-warning text-xs">This build does not include an update endpoint.</p>
            )}

            <div className="space-y-2 border-t border-subtle pt-3">
              <div className="flex flex-wrap items-center gap-2">
                <button
                  className="btn btn-secondary"
                  onClick={() => void update.checkForUpdates()}
                  disabled={update.checking || update.downloading || appMetadata?.update_endpoint_configured === false}
                >
                  <RefreshCw size={14} />
                  {update.checking ? "Checking..." : "Check for Updates"}
                </button>
                {update.updateAvailable && update.update && (
                  <button
                    className="btn btn-primary"
                    onClick={() => void update.downloadAndInstall()}
                    disabled={update.downloading || update.downloaded}
                  >
                    <Download size={14} />
                    {update.downloading ? "Installing..." : "Install"}
                  </button>
                )}
                {update.manualUpdateAvailable && update.manualRelease && (
                  <button className="btn btn-primary" onClick={() => void update.openManualRelease()}>
                    <ExternalLink size={14} />
                    Open Release
                  </button>
                )}
              </div>

              {update.checked &&
                !update.checking &&
                !update.updateAvailable &&
                !update.manualUpdateAvailable &&
                !update.error &&
                !update.warning && (
                  <p className="status-success text-sm">TapChat is up to date.</p>
                )}
              {update.updateAvailable && update.update && (
                <p className="text-sm text-secondary-color">Version {update.update.version} is available.</p>
              )}
              {update.manualUpdateAvailable && update.manualRelease && (
                <p className="text-sm text-secondary-color">
                  Version {update.manualRelease.version} is available on GitHub.
                </p>
              )}
              {update.downloading && (
                <div>
                  <p className="mb-1 text-xs text-muted-color">
                    Downloading: {updateProgressPercent} percent
                  </p>
                  <div className="h-2 w-full rounded bg-surface-elevated">
                    <div className="h-2 rounded bg-primary" style={{ width: `${updateProgressPercent}%` }} />
                  </div>
                </div>
              )}
              {update.downloaded && <p className="status-success text-sm">Update installed. Restarting...</p>}
              {update.warning && <p className="status-warning text-sm">{update.warning}</p>}
              {update.error && <p className="status-error text-sm">{update.error}</p>}
            </div>
          </div>
        )}
      </section>
    );
  }

  function renderDeveloperPanel() {
    return (
      <section className="card space-y-5">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Code2 size={18} className="text-muted-color" />
            <span className="text-primary-color">Developer Mode</span>
            <span className="status-success text-xs">Enabled</span>
          </div>
          <button className="btn btn-ghost text-sm" onClick={() => void handleDisableDeveloperMode()}>
            Disable
          </button>
        </div>

        <div className="space-y-2 border-t border-subtle pt-4">
          <h3 className="font-medium text-primary-color">Allowlist</h3>
          {allowlist.length === 0 && (
            <p className="text-sm text-muted-color">
              No users in allowlist. Add users to automatically accept their messages.
            </p>
          )}

          {allowlist.map((userId) => (
            <div key={userId} className="flex items-center justify-between">
              <span className="truncate text-primary-color">{userId.slice(0, 20)}...</span>
              <button className="btn btn-ghost text-xs status-error" onClick={() => handleRemoveAllowlist(userId)}>
                <X size={14} />
              </button>
            </div>
          ))}

          <div className="flex items-center gap-2 pt-2">
            <input
              className="input flex-1"
              placeholder="User ID"
              value={newAllowlistUser}
              onChange={(event) => setNewAllowlistUser(event.target.value)}
            />
            <button className="btn btn-primary" onClick={handleAddAllowlist} disabled={!newAllowlistUser.trim()}>
              Add
            </button>
          </div>
        </div>

        <div className="border-t border-subtle pt-4">
          <h3 className="mb-3 font-medium text-primary-color">Performance Testing</h3>
          <label className="flex cursor-pointer items-center justify-between">
            <div className="flex-1">
              <span className="text-primary-color">Debug Mode</span>
              <p className="mt-0.5 text-xs text-muted-color">
                Emits [TIMETEST] tagged log entries for measuring latency, recovery, and deploy timing.
              </p>
            </div>
            <button
              className={`ml-3 h-6 w-11 flex-shrink-0 rounded-full transition-colors ${
                debugMode ? "bg-primary" : "bg-surface-elevated"
              }`}
              onClick={handleToggleDebugMode}
            >
              <span
                className={`block h-5 w-5 rounded-full bg-white transition-transform ${
                  debugMode ? "translate-x-5" : "translate-x-1"
                }`}
              />
            </button>
          </label>
        </div>

        <div className="border-t border-subtle pt-4">
          <h3 className="mb-3 font-medium status-error">Danger Zone</h3>
          <button
            className="btn btn-ghost w-full cursor-not-allowed status-error opacity-50"
            disabled
            title="Feature not yet implemented"
          >
            Delete Identity (Not Yet Implemented)
          </button>
          <p className="mt-2 text-center text-xs text-muted-color">
            This feature will be available in a future update.
          </p>
        </div>
      </section>
    );
  }
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <label className="mb-1 block text-xs text-muted-color">{label}</label>
      <span className="block truncate text-sm text-primary-color" title={value}>
        {value}
      </span>
    </div>
  );
}

function AttachmentsSettings() {
  const [settings, setLocalSettings] = useState<{ prefetch_previews: boolean; always_ask_save_path: boolean } | null>(null);
  const [cacheDir, setCacheDir] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    void loadSettings();
    void loadCacheDir();
  }, []);

  const loadSettings = async () => {
    try {
      const s = await invoke<{ prefetch_previews: boolean; always_ask_save_path: boolean }>("get_attachment_settings");
      setLocalSettings(s);
    } catch (err) {
      console.error("[Settings] Failed to load attachment settings:", err);
    }
  };

  const loadCacheDir = async () => {
    try {
      setCacheDir(await invoke<string>("get_attachment_cache_dir"));
    } catch {
      // not critical
    }
  };

  const togglePreviewPrefetch = async () => {
    if (!settings) return;
    const next = { ...settings, prefetch_previews: !settings.prefetch_previews };
    setLocalSettings(next);
    setSaving(true);
    try {
      await invoke("set_attachment_settings", { settings: next });
    } catch (err) {
      console.error("[Settings] Failed to save attachment settings:", err);
      setLocalSettings(settings);
    } finally {
      setSaving(false);
    }
  };

  const toggleAlwaysAsk = async () => {
    if (!settings) return;
    const next = { ...settings, always_ask_save_path: !settings.always_ask_save_path };
    setLocalSettings(next);
    setSaving(true);
    try {
      await invoke("set_attachment_settings", { settings: next });
    } catch (err) {
      console.error("[Settings] Failed to save attachment settings:", err);
      setLocalSettings(settings);
    } finally {
      setSaving(false);
    }
  };

  if (!settings) {
    return (
      <div className="card">
        <span className="text-sm text-muted-color">Loading...</span>
      </div>
    );
  }

  return (
    <div className="card space-y-4">
      <label className="flex cursor-pointer items-center justify-between">
        <div className="flex-1">
          <span className="text-primary-color">Prefetch image previews</span>
          <p className="mt-0.5 text-xs text-muted-color">
            Privately cache small screen previews from accepted chats. Originals are always loaded on demand.
          </p>
        </div>
        <button
          className={`ml-3 h-6 w-11 flex-shrink-0 rounded-full transition-colors ${
            settings.prefetch_previews ? "bg-primary" : "bg-surface-elevated"
          }`}
          onClick={togglePreviewPrefetch}
          disabled={saving}
          aria-label="Prefetch image previews"
        >
          <span
            className={`block h-5 w-5 rounded-full bg-white transition-transform ${
              settings.prefetch_previews ? "translate-x-5" : "translate-x-1"
            }`}
          />
        </button>
      </label>

      <label className="flex cursor-pointer items-center justify-between">
        <div className="flex-1">
          <span className="text-primary-color">Always ask save path</span>
          <p className="mt-0.5 text-xs text-muted-color">
            When enabled, you will be asked where to save each downloaded file.
          </p>
        </div>
        <button
          className={`ml-3 h-6 w-11 flex-shrink-0 rounded-full transition-colors ${
            settings.always_ask_save_path ? "bg-primary" : "bg-surface-elevated"
          }`}
          onClick={toggleAlwaysAsk}
          disabled={saving}
        >
          <span
            className={`block h-5 w-5 rounded-full bg-white transition-transform ${
              settings.always_ask_save_path ? "translate-x-5" : "translate-x-1"
            }`}
          />
        </button>
      </label>

      {cacheDir && (
        <div className="border-t border-subtle pt-3">
          <label className="mb-1 block text-xs text-muted-color">Cache directory</label>
          <span className="block truncate text-sm text-primary-color">{cacheDir}</span>
        </div>
      )}
    </div>
  );
}

import { useState, useEffect } from "react";
import { useNavigate } from "react-router";
import { invoke } from "@tauri-apps/api/core";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { listen } from "@tauri-apps/api/event";
import { Monitor, X } from "lucide-react";

import {
  getIdentityInfo,
  getShareLink,
  rotateShareLink,
  setLocalDisplayName,
  listProfiles,
  activateProfile,
  deleteProfile,
  startNewProfileOnboarding,
  cloudflareStatus,
  addToAllowlist,
  removeFromAllowlist,
  getAllowlist,
  setDebugMode,
  getDebugMode,
} from "@/lib/tauri";
import type { IdentityInfo, ProfileSummary, CloudflareStatus } from "@/lib/types";

export default function Settings() {
  const navigate = useNavigate();
  const [identity, setIdentity] = useState<IdentityInfo | null>(null);
  const [runtimeStatus, setRuntimeStatus] = useState<CloudflareStatus | null>(null);
  const [profiles, setProfiles] = useState<ProfileSummary[]>([]);
  const [showMnemonic, setShowMnemonic] = useState(false);
  const [newAllowlistUser, setNewAllowlistUser] = useState("");
  const [allowlist, setAllowlist] = useState<string[]>([]);
  const [darkMode, setDarkMode] = useState(false);
  const [debugMode, setDebugModeState] = useState(false);
  const [copied, setCopied] = useState(false);
  const [switchingProfile, setSwitchingProfile] = useState<string | null>(null);

  // Display name editing state
  const [editingDisplayName, setEditingDisplayName] = useState(false);
  const [displayNameInput, setDisplayNameInput] = useState("");
  const [savingDisplayName, setSavingDisplayName] = useState(false);

  // New profile creation state - just show confirmation dialog
  const [showCreateConfirm, setShowCreateConfirm] = useState(false);
  const [startingOnboarding, setStartingOnboarding] = useState(false);

  // Delete profile state
  const [deletingProfile, setDeletingProfile] = useState<string | null>(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState<{ path: string; name: string } | null>(null);

  useEffect(() => {
    loadIdentity();
    loadRuntimeStatus();
    loadAllowlist();
    loadProfiles();
    loadDebugMode();

    // Check system preference for dark mode
    const isDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    setDarkMode(isDark);

    // Listen for engine-reloaded event (profile switch) to reload all data
    const unlistenEngineReloaded = listen<void>("engine-reloaded", () => {
      console.debug("[Settings] Engine reloaded, refreshing settings data");
      loadIdentity();
      loadRuntimeStatus();
      loadAllowlist();
      loadProfiles();
    });

    return () => {
      unlistenEngineReloaded.then((fn) => fn());
    };
  }, []);

  const loadIdentity = async () => {
    try {
      const result = await getIdentityInfo();
      setIdentity(result);
      setDisplayNameInput(result?.display_name || "");
    } catch (err) {
      console.error(`[Settings] Failed to get identity: ${String(err)}`);
    }
  };

  const loadRuntimeStatus = async () => {
    try {
      const result = await cloudflareStatus();
      setRuntimeStatus(result);
    } catch (err) {
      console.error(`[Settings] Failed to get runtime status: ${String(err)}`);
    }
  };

  const loadProfiles = async () => {
    try {
      const result = await listProfiles();
      setProfiles(result);
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
      const result = await getDebugMode();
      setDebugModeState(result);
    } catch {
      // debug mode toggle is best-effort
    }
  };

  // Toggle debug mode for [TIMETEST] instrumentation
  const handleToggleDebugMode = async () => {
    const next = !debugMode;
    setDebugModeState(next);
    try {
      await setDebugMode(next);
    } catch {
      setDebugModeState(!next); // revert
    }
  };

  // Toggle dark mode
  const toggleDarkMode = () => {
    setDarkMode(!darkMode);
    document.documentElement.classList.toggle("dark", !darkMode);
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

  const handleAddAllowlist = async () => {
    if (!newAllowlistUser.trim()) return;
    try {
      await addToAllowlist(newAllowlistUser);
      setNewAllowlistUser("");
      loadAllowlist();
    } catch (err) {
      console.error(`[Settings] Failed to add allowlist entry: ${String(err)}`);
    }
  };

  const handleRemoveAllowlist = async (userId: string) => {
    try {
      await removeFromAllowlist(userId);
      loadAllowlist();
    } catch (err) {
      console.error(`[Settings] Failed to remove allowlist entry: ${String(err)}`);
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

  const handleSaveDisplayName = async () => {
    setSavingDisplayName(true);
    try {
      const nameToSave = displayNameInput.trim() || null;
      await setLocalDisplayName(nameToSave);
      setEditingDisplayName(false);
      loadIdentity();
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
      await activateProfile(path);
      // Do NOT reload data here - wait for engine-reloaded event
      // which will trigger useCoreUpdate to fetch new data
      // The profile-switch-complete event signals that the switch is done
    } catch (err) {
      console.error(`[Settings] Profile switch error: ${String(err)}`);
      // Don't show popup for transient errors like websocket connect
      const errorMsg = String(err);
      if (!errorMsg.includes("websocket") && !errorMsg.includes("connect") && errorMsg !== "") {
        alert(errorMsg);
      }
    } finally {
      // Just update the profiles list and clear switching state
      // Identity/runtime/allowlist data will be refreshed via engine-reloaded event
      loadProfiles();
      setSwitchingProfile(null);
    }
  };

  const handleStartNewProfileOnboarding = async () => {
    setStartingOnboarding(true);
    try {
      // Start onboarding - does NOT create profile yet, will be created during onboarding
      await startNewProfileOnboarding();
      setShowCreateConfirm(false);
      // The backend will emit session-status event which triggers frontend navigation
    } catch (err) {
      console.error(`[Settings] Failed to start onboarding: ${String(err)}`);
      alert(String(err));
    } finally {
      setStartingOnboarding(false);
    }
  };

  const handleDeleteProfile = async (path: string, name: string) => {
    // Show confirmation dialog
    setShowDeleteConfirm({ path, name });
  };

  const confirmDeleteProfile = async () => {
    if (!showDeleteConfirm) return;
    const { path } = showDeleteConfirm;
    setDeletingProfile(path);
    setShowDeleteConfirm(null);
    try {
      await deleteProfile(path);
      loadProfiles();
    } catch (err) {
      console.error(`[Settings] Failed to delete profile: ${String(err)}`);
      alert(String(err));
    } finally {
      setDeletingProfile(null);
    }
  };

  return (
    <div className="flex h-full min-h-0 overflow-hidden bg-base">
      <div className="mx-auto flex min-h-0 max-w-2xl flex-1 flex-col">
        {/* Header */}
        <header className="flex items-center p-3 border-b border-default">
          <button
            className="btn btn-ghost px-2"
            onClick={() => navigate("/")}
          >
            ←
          </button>
          <h1 className="font-semibold text-primary-color ml-2">Settings</h1>
        </header>

        {/* Content */}
        <div className="flex-1 overflow-y-auto overscroll-contain p-4">
          {/* Appearance section */}
          <section className="mb-6">
            <h2 className="text-lg font-medium text-primary-color mb-3">Appearance</h2>

            <div className="card">
              <label className="flex items-center justify-between cursor-pointer">
                <span className="text-primary-color">Dark Mode</span>
                <button
                  className={`w-12 h-6 rounded-full transition-colors ${
                    darkMode ? "bg-primary" : "bg-surface-elevated"
                  }`}
                  onClick={toggleDarkMode}
                >
                  <span
                    className={`block w-5 h-5 rounded-full bg-white transition-transform ${
                      darkMode ? "translate-x-6" : "translate-x-1"
                    }`}
                  />
                </button>
              </label>
            </div>
          </section>

          {/* Profiles section */}
          <section className="mb-6">
            <h2 className="text-lg font-medium text-primary-color mb-3">Profiles</h2>

            <div className="card space-y-2">
              {profiles.length === 0 && (
                <p className="text-muted-color text-sm">
                  No profiles found. Create a profile during onboarding.
                </p>
              )}

              {profiles.map((profile) => (
                <div
                  key={profile.path}
                  className={`flex items-center justify-between p-2 rounded ${
                    profile.is_active ? "bg-surface-elevated" : ""
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <span className={`w-2 h-2 rounded-full ${
                      profile.is_active ? "status-success" : "bg-surface-elevated"
                    }`} />
                    <div>
                      <span className="text-primary-color font-medium">{profile.name}</span>
                      {profile.user_id && (
                        <span className="text-muted-color text-xs ml-2">
                          ({profile.user_id.slice(0, 8)}...)
                        </span>
                      )}
                      {profile.runtime_bound && (
                        <span className="status-success text-xs ml-1">Connected</span>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-1">
                    {profile.is_active ? (
                      <span className="text-xs text-muted-color">(Active)</span>
                    ) : (
                      <>
                        <button
                          className="btn btn-ghost text-sm"
                          onClick={() => handleSwitchProfile(profile.path)}
                          disabled={switchingProfile === profile.path}
                        >
                          {switchingProfile === profile.path ? "Switching..." : "Switch"}
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

              {/* Delete confirmation dialog */}
              {showDeleteConfirm && (
                <div className="card mt-2 pt-2 border-t border-default">
                  <p className="status-error mb-3">
                    Delete profile "{showDeleteConfirm.name}"?
                  </p>
                  <p className="text-muted-color text-sm mb-3">
                    This action cannot be undone. All data in this profile will be permanently deleted.
                  </p>
                  <div className="flex items-center gap-2">
                    <button
                      className="btn btn-ghost status-error"
                      onClick={confirmDeleteProfile}
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

              {/* Create new profile - confirmation dialog */}
              {showCreateConfirm ? (
                <div className="card mt-2 pt-2 border-t border-default">
                  <p className="text-primary-color mb-3">
                    Create a new profile? You will be guided through the setup process.
                  </p>
                  <div className="flex items-center gap-2">
                    <button
                      className="btn btn-primary"
                      onClick={handleStartNewProfileOnboarding}
                      disabled={startingOnboarding}
                    >
                      {startingOnboarding ? "Starting..." : "Yes, Start Setup"}
                    </button>
                    <button
                      className="btn btn-ghost"
                      onClick={() => setShowCreateConfirm(false)}
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              ) : (
                <button
                  className="btn btn-secondary w-full mt-2"
                  onClick={() => setShowCreateConfirm(true)}
                >
                  + Create New Profile
                </button>
              )}
            </div>
          </section>

          {/* Profile section - User info */}
          <section className="mb-6">
            <h2 className="text-lg font-medium text-primary-color mb-3">Account</h2>

            <div className="card space-y-3">
              {/* Display Name */}
              <div>
                <label className="text-muted-color text-xs block mb-1">Display Name</label>
                {editingDisplayName ? (
                  <div className="flex items-center gap-2">
                    <input
                      className="input flex-1"
                      value={displayNameInput}
                      onChange={(e) => setDisplayNameInput(e.target.value)}
                      placeholder="Enter your display name"
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
                  <div className="flex items-center gap-2">
                    <span className="text-primary-color">
                      {identity?.display_name || "Not set"}
                    </span>
                    <button
                      className="btn btn-ghost text-sm"
                      onClick={() => setEditingDisplayName(true)}
                    >
                      Edit
                    </button>
                  </div>
                )}
              </div>

              <div>
                <label className="text-muted-color text-xs block mb-1">User ID</label>
                <span className="text-primary-color truncate">
                  {identity?.user_id || "Not set"}
                </span>
              </div>
              <div>
                <label className="text-muted-color text-xs block mb-1">Device</label>
                <span className="text-primary-color">
                  {identity?.device_id?.slice(0, 16) || "Not set"}...
                </span>
              </div>
              <div className="flex items-center gap-2 mt-2">
                <button className="btn btn-secondary" onClick={handleCopyShareLink}>
                  {copied ? "Copied!" : "Copy Share Link"}
                </button>
                <button className="btn btn-ghost" onClick={handleRotateLink}>
                  Rotate Link
                </button>
              </div>
            </div>
          </section>

          {/* Devices section */}
          <section className="mb-6">
            <h2 className="text-lg font-medium text-primary-color mb-3">Devices</h2>

            <div className="card">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <Monitor size={20} className="text-muted-color" />
                  <span className="text-primary-color">This Device</span>
                  <span className="status-success text-xs">Active</span>
                </div>
                <button
                  className="btn btn-ghost text-sm"
                  onClick={() => navigate("/settings/devices")}
                >
                  Manage →
                </button>
              </div>
              <button
                className="btn btn-secondary w-full"
                onClick={() => navigate("/settings/devices")}
              >
                Manage Devices
              </button>
            </div>
          </section>

          {/* Allowlist section */}
          <section className="mb-6">
            <h2 className="text-lg font-medium text-primary-color mb-3">Allowlist</h2>

            <div className="card space-y-2">
              {allowlist.length === 0 && (
                <p className="text-muted-color text-sm">
                  No users in allowlist. Add users to automatically accept their messages.
                </p>
              )}

              {allowlist.map((userId) => (
                <div key={userId} className="flex items-center justify-between">
                  <span className="text-primary-color truncate">{userId.slice(0, 20)}...</span>
                  <button
                    className="btn btn-ghost text-xs status-error"
                    onClick={() => handleRemoveAllowlist(userId)}
                  >
                    <X size={14} />
                  </button>
                </div>
              ))}

              {/* Add new */}
              <div className="flex items-center gap-2 mt-2 pt-2 border-t border-default">
                <input
                  className="input flex-1"
                  placeholder="User ID"
                  value={newAllowlistUser}
                  onChange={(e) => setNewAllowlistUser(e.target.value)}
                />
                <button
                  className="btn btn-primary"
                  onClick={handleAddAllowlist}
                  disabled={!newAllowlistUser.trim()}
                >
                  Add
                </button>
              </div>
            </div>
          </section>

          {/* Infrastructure section */}
          <section className="mb-6">
            <h2 className="text-lg font-medium text-primary-color mb-3">Infrastructure</h2>

            <div className="card space-y-2">
              <div className="flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full ${runtimeStatus?.bound ? "status-success" : "status-error"}`} />
                <span className="text-primary-color">
                  {runtimeStatus?.bound ? "Connected" : "Not Deployed"}
                </span>
              </div>

              {runtimeStatus?.endpoint && (
                <div>
                  <label className="text-muted-color text-xs block mb-1">Endpoint</label>
                  <span className="text-primary-color text-sm truncate">{runtimeStatus.endpoint}</span>
                </div>
              )}

              <button
                className="btn btn-secondary w-full mt-2"
                onClick={() => navigate("/settings/runtime")}
              >
                Manage Runtime
              </button>
            </div>
          </section>

          {/* Attachments section */}
          <section className="mb-6">
            <h2 className="text-lg font-medium text-primary-color mb-3">Attachments</h2>
            <AttachmentsSettings />
          </section>

          {/* Recovery section */}
          <section className="mb-6">
            <h2 className="text-lg font-medium text-primary-color mb-3">Recovery Phrase</h2>

            <div className="card">
              {showMnemonic ? (
                <div className="space-y-2">
                  <p className="status-warning text-sm">Keep this secret! Never share it.</p>
                  <div className="grid grid-cols-3 gap-1 bg-surface-elevated p-2 rounded">
                    {identity?.mnemonic?.split(" ").map((word, i) => (
                      <div key={i} className="flex items-center gap-1">
                        <span className="text-muted-color text-xs">{i + 1}.</span>
                        <span className="text-primary-color text-sm">{word}</span>
                      </div>
                    ))}
                  </div>
                  <button
                    className="btn btn-ghost w-full"
                    onClick={() => setShowMnemonic(false)}
                  >
                    Hide
                  </button>
                </div>
              ) : (
                <button
                  className="btn btn-secondary w-full"
                  onClick={() => setShowMnemonic(true)}
                >
                  Show Recovery Phrase
                </button>
              )}
            </div>
          </section>

          {/* Performance Testing — Debug Mode */}
          <section className="mb-6">
            <h2 className="text-lg font-medium text-primary-color mb-3">Performance Testing</h2>

            <div className="card">
              <label className="flex items-center justify-between cursor-pointer">
                <div className="flex-1">
                  <span className="text-primary-color">Debug Mode</span>
                  <p className="text-muted-color text-xs mt-0.5">
                    When enabled, [TIMETEST] tagged log entries are emitted for measuring end-to-end latency, recovery, and deploy timing. Log entries are prefixed with "[TIMETEST]" for easy filtering.
                  </p>
                </div>
                <button
                  className={`w-11 h-6 rounded-full transition-colors flex-shrink-0 ml-3 ${
                    debugMode ? "bg-primary" : "bg-surface-elevated"
                  }`}
                  onClick={handleToggleDebugMode}
                >
                  <span
                    className={`block w-5 h-5 rounded-full bg-white transition-transform ${
                      debugMode ? "translate-x-5" : "translate-x-1"
                    }`}
                  />
                </button>
              </label>
            </div>
          </section>

          {/* Danger zone */}
          <section className="mb-6">
            <h2 className="text-lg font-medium status-error mb-3">Danger Zone</h2>

            <div className="card">
              <button
                className="btn btn-ghost w-full status-error opacity-50 cursor-not-allowed"
                disabled
                title="Feature not yet implemented"
              >
                Delete Identity (Not Yet Implemented)
              </button>
              <p className="text-muted-color text-xs mt-2 text-center">
                This feature will be available in a future update
              </p>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}

/** Inline component for attachment settings, co-located with Settings page. */
function AttachmentsSettings() {
  const [settings, setLocalSettings] = useState<{ auto_download_media: boolean; always_ask_save_path: boolean } | null>(null);
  const [cacheDir, setCacheDir] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    loadSettings();
    loadCacheDir();
  }, []);

  const loadSettings = async () => {
    try {
      const s = await invoke<{ auto_download_media: boolean; always_ask_save_path: boolean }>("get_attachment_settings");
      setLocalSettings(s);
    } catch (err) {
      console.error("[Settings] Failed to load attachment settings:", err);
    }
  };

  const loadCacheDir = async () => {
    try {
      const dir = await invoke<string>("get_attachment_cache_dir");
      setCacheDir(dir);
    } catch {
      // not critical
    }
  };

  const toggleAutoDownload = async () => {
    if (!settings) return;
    const next = { ...settings, auto_download_media: !settings.auto_download_media };
    setLocalSettings(next);
    setSaving(true);
    try {
      await invoke("set_attachment_settings", { settings: next });
    } catch (err) {
      console.error("[Settings] Failed to save attachment settings:", err);
      setLocalSettings(settings); // revert
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
      setLocalSettings(settings); // revert
    } finally {
      setSaving(false);
    }
  };

  if (!settings) {
    return <div className="card"><span className="text-muted-color text-sm">Loading...</span></div>;
  }

  return (
    <div className="card space-y-4">
      {/* Auto-download toggle */}
      <label className="flex items-center justify-between cursor-pointer">
        <div className="flex-1">
          <span className="text-primary-color">Auto-download media</span>
          <p className="text-muted-color text-xs mt-0.5">
            Automatically download image, audio, and video attachments (≤10 MB) from trusted contacts
          </p>
        </div>
        <button
          className={`w-11 h-6 rounded-full transition-colors flex-shrink-0 ml-3 ${
            settings.auto_download_media ? "bg-primary" : "bg-surface-elevated"
          }`}
          onClick={toggleAutoDownload}
          disabled={saving}
        >
          <span
            className={`block w-5 h-5 rounded-full bg-white transition-transform ${
              settings.auto_download_media ? "translate-x-5" : "translate-x-1"
            }`}
          />
        </button>
      </label>

      {/* Always ask save path toggle */}
      <label className="flex items-center justify-between cursor-pointer">
        <div className="flex-1">
          <span className="text-primary-color">Always ask save path</span>
          <p className="text-muted-color text-xs mt-0.5">
            When enabled, you will be asked where to save each downloaded file
          </p>
        </div>
        <button
          className={`w-11 h-6 rounded-full transition-colors flex-shrink-0 ml-3 ${
            settings.always_ask_save_path ? "bg-primary" : "bg-surface-elevated"
          }`}
          onClick={toggleAlwaysAsk}
          disabled={saving}
        >
          <span
            className={`block w-5 h-5 rounded-full bg-white transition-transform ${
              settings.always_ask_save_path ? "translate-x-5" : "translate-x-1"
            }`}
          />
        </button>
      </label>

      {/* Cache directory (read-only) */}
      {cacheDir && (
        <div className="pt-3 border-t border-subtle">
          <label className="text-muted-color text-xs block mb-1">Cache directory</label>
          <span className="text-primary-color text-sm truncate block">{cacheDir}</span>
        </div>
      )}
    </div>
  );
}

import { useState, useEffect } from "react";
import { useNavigate } from "react-router";
import { invoke } from "@tauri-apps/api/core";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";

interface IdentityInfo {
  user_id: string;
  device_id: string;
  mnemonic: string;
}

interface RuntimeStatus {
  bound: boolean;
  endpoint: string | null;
}

export default function Settings() {
  const navigate = useNavigate();
  const [identity, setIdentity] = useState<IdentityInfo | null>(null);
  const [runtimeStatus, setRuntimeStatus] = useState<RuntimeStatus | null>(null);
  const [showMnemonic, setShowMnemonic] = useState(false);
  const [newAllowlistUser, setNewAllowlistUser] = useState("");
  const [allowlist, setAllowlist] = useState<string[]>([]);
  const [darkMode, setDarkMode] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    invoke<IdentityInfo | null>("get_identity_info")
      .then(setIdentity)
      .catch((err) => console.error("Failed to get identity:", err));

    invoke<RuntimeStatus>("cloudflare_status")
      .then(setRuntimeStatus)
      .catch((err) => console.error("Failed to get runtime status:", err));

    // Load allowlist
    loadAllowlist();

    // Check system preference for dark mode
    const isDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    setDarkMode(isDark);
  }, []);

  const loadAllowlist = async () => {
    try {
      const result = await invoke<{ allowlist?: { allowed_sender_user_ids: string[] } }>("get_allowlist");
      setAllowlist(result.allowlist?.allowed_sender_user_ids || []);
    } catch (err) {
      console.error("Failed to load allowlist:", err);
    }
  };

  // Toggle dark mode
  const toggleDarkMode = () => {
    setDarkMode(!darkMode);
    document.documentElement.classList.toggle("dark", !darkMode);
  };

  const handleCopyShareLink = async () => {
    try {
      const link = await invoke<string | null>("get_share_link");
      if (link) {
        await writeText(link);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      }
    } catch (err) {
      console.error("Failed to copy:", err);
    }
  };

  const handleAddAllowlist = async () => {
    if (!newAllowlistUser.trim()) return;
    try {
      await invoke("add_to_allowlist", { userId: newAllowlistUser });
      setNewAllowlistUser("");
      loadAllowlist();
    } catch (err) {
      console.error("Failed to add to allowlist:", err);
    }
  };

  const handleRemoveAllowlist = async (userId: string) => {
    try {
      await invoke("remove_from_allowlist", { userId });
      loadAllowlist();
    } catch (err) {
      console.error("Failed to remove from allowlist:", err);
    }
  };

  const handleRotateLink = async () => {
    try {
      await invoke("rotate_share_link");
      alert("Share link rotated. Share the new link with your contacts.");
    } catch (err) {
      console.error("Failed to rotate link:", err);
      alert(String(err));
    }
  };

  return (
    <div className="flex h-screen bg-base">
      <div className="flex-1 flex flex-col max-w-2xl mx-auto">
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
        <div className="flex-1 overflow-y-auto p-4">
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

          {/* Profile section */}
          <section className="mb-6">
            <h2 className="text-lg font-medium text-primary-color mb-3">Profile</h2>

            <div className="card space-y-2">
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
                  <span className="text-lg">💻</span>
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
                    ✕
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

          {/* Danger zone */}
          <section className="mb-6">
            <h2 className="text-lg font-medium status-error mb-3">Danger Zone</h2>

            <div className="card">
              <button className="btn btn-ghost w-full status-error">
                Delete Identity
              </button>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
import { useState, useEffect } from "react";
import { useNavigate } from "react-router";
import { invoke } from "@tauri-apps/api/core";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";

interface IdentityInfo {
  user_id: string;
  device_id: string;
  mnemonic: string;
}

export default function Settings() {
  const navigate = useNavigate();
  const [identity, setIdentity] = useState<IdentityInfo | null>(null);
  const [showMnemonic, setShowMnemonic] = useState(false);
  const [newAllowlistUser, setNewAllowlistUser] = useState("");
  const [darkMode, setDarkMode] = useState(false);

  useEffect(() => {
    invoke<IdentityInfo | null>("get_identity_info")
      .then(setIdentity)
      .catch((err) => console.error("Failed to get identity:", err));

    // Check system preference for dark mode
    const isDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    setDarkMode(isDark);
  }, []);

  // Toggle dark mode
  const toggleDarkMode = () => {
    setDarkMode(!darkMode);
    document.documentElement.classList.toggle("dark", !darkMode);
  };

  const handleCopyShareLink = async () => {
    // TODO: Get actual share link from backend
    const link = "https://tapchat.link/s/placeholder";
    try {
      await writeText(link);
    } catch (err) {
      console.error("Failed to copy:", err);
    }
  };

  const handleAddAllowlist = async () => {
    if (!newAllowlistUser.trim()) return;
    try {
      await invoke("add_to_allowlist", { userId: newAllowlistUser });
      setNewAllowlistUser("");
    } catch (err) {
      console.error("Failed to add to allowlist:", err);
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
                  {identity?.device_id || "Not set"} (this device)
                </span>
              </div>
              <div className="flex items-center gap-2">
                <button className="btn btn-ghost" onClick={handleCopyShareLink}>Copy Share Link</button>
                <button className="btn btn-ghost">Rotate Link</button>
              </div>
            </div>
          </section>

          {/* Devices section */}
          <section className="mb-6">
            <h2 className="text-lg font-medium text-primary-color mb-3">Devices</h2>

            <div className="card space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-primary-color">💻 {identity?.device_id || "This device"}</span>
                <span className="status-success text-xs">Active</span>
              </div>
              <button className="btn btn-secondary w-full mt-2">+ Add Device</button>
            </div>
          </section>

          {/* Allowlist section */}
          <section className="mb-6">
            <h2 className="text-lg font-medium text-primary-color mb-3">Allowlist</h2>

            <div className="card space-y-2">
              {/* Placeholder allowlist */}
              <div className="flex items-center justify-between">
                <span className="text-primary-color truncate">user:alice</span>
                <button className="btn btn-ghost text-xs">✕</button>
              </div>

              {/* Add new */}
              <div className="flex items-center gap-2 mt-2">
                <input
                  className="input flex-1"
                  placeholder="user_id"
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
                <span className="w-2 h-2 rounded-full status-success" />
                <span className="text-primary-color">Connected</span>
              </div>
              <div>
                <label className="text-muted-color text-xs block mb-1">Worker</label>
                <span className="text-primary-color">tapchat-abc123</span>
              </div>
              <div>
                <label className="text-muted-color text-xs block mb-1">Endpoint</label>
                <span className="text-primary-color truncate">https://tapchat-abc123.workers.dev</span>
              </div>

              <div className="flex gap-2 mt-2">
                <button className="btn btn-secondary">Redeploy</button>
                <button className="btn btn-secondary">Rotate Secrets</button>
              </div>
              <button className="btn btn-ghost w-full status-error">Detach Runtime</button>
            </div>
          </section>

          {/* Recovery section */}
          <section className="mb-6">
            <h2 className="text-lg font-medium text-primary-color mb-3">Recovery Phrase</h2>

            <div className="card">
              {showMnemonic ? (
                <div className="space-y-2">
                  <p className="status-warning text-sm">Keep this secret!</p>
                  <code className="text-primary-color">{identity?.mnemonic || "..."}</code>
                  <button
                    className="btn btn-ghost"
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
        </div>
      </div>
    </div>
  );
}
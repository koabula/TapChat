import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useNavigate } from "react-router";

interface RuntimeStatus {
  bound: boolean;
  endpoint: string | null;
}

interface DeployProgress {
  phase: string;
  message: string;
  complete: boolean;
}

interface PreflightResult {
  wrangler_installed: boolean;
  wrangler_logged_in: boolean;
  ready: boolean;
  error: string | null;
}

export default function Runtime() {
  const navigate = useNavigate();
  const [status, setStatus] = useState<RuntimeStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [deploying, setDeploying] = useState(false);
  const [progress, setProgress] = useState<DeployProgress | null>(null);
  const [preflight, setPreflight] = useState<PreflightResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadStatus();

    // Listen for deploy progress
    const unlisten = listen<DeployProgress>("cloudflare-progress", (event) => {
      setProgress(event.payload);
      if (event.payload.complete) {
        setDeploying(false);
        loadStatus();
      }
    });

    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

  const loadStatus = async () => {
    setLoading(true);
    try {
      const result = await invoke<RuntimeStatus>("cloudflare_status");
      setStatus(result);
    } catch (err) {
      console.error("Failed to load runtime status:", err);
    } finally {
      setLoading(false);
    }
  };

  const checkPreflight = async () => {
    try {
      const result = await invoke<PreflightResult>("cloudflare_preflight");
      setPreflight(result);
    } catch (err) {
      console.error("Preflight check failed:", err);
      setError(String(err));
    }
  };

  const handleLogin = async () => {
    setError(null);
    try {
      const success = await invoke<boolean>("cloudflare_login");
      if (success) {
        checkPreflight();
      } else {
        setError("Login failed");
      }
    } catch (err) {
      setError(String(err));
    }
  };

  const handleDeploy = async () => {
    setError(null);
    setDeploying(true);
    try {
      await invoke("cloudflare_deploy");
    } catch (err) {
      setError(String(err));
      setDeploying(false);
    }
  };

  const handleRedeploy = async () => {
    setError(null);
    setDeploying(true);
    checkPreflight();
  };

  return (
    <div className="flex flex-col h-screen bg-base">
      {/* Header */}
      <header className="flex items-center p-3 border-b border-default">
        <button className="btn btn-ghost px-2" onClick={() => navigate("/settings")}>
          ← Back
        </button>
        <h1 className="ml-2 text-lg font-medium text-primary-color">Runtime Management</h1>
      </header>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4">
        {loading && (
          <div className="text-center text-muted-color">Loading...</div>
        )}

        {!loading && (
          <>
            {/* Current status */}
            <div className="card mb-4">
              <h2 className="text-sm font-medium text-muted-color mb-3">Current Runtime</h2>

              <div className="flex items-center gap-3 mb-3">
                <span className={`w-3 h-3 rounded-full ${status?.bound ? "status-success" : "status-error"}`} />
                <span className="text-primary-color">
                  {status?.bound ? "Deployed and Active" : "Not Deployed"}
                </span>
              </div>

              {status?.endpoint && (
                <div className="space-y-1">
                  <div className="flex justify-between">
                    <span className="text-secondary-color">Endpoint</span>
                    <span className="text-primary-color text-sm truncate max-w-[200px]">
                      {status.endpoint}
                    </span>
                  </div>
                </div>
              )}

              {!status?.bound && (
                <p className="text-muted-color text-sm mt-2">
                  Deploy your personal inbox server to Cloudflare to start messaging.
                </p>
              )}
            </div>

            {/* Deploy progress */}
            {deploying && progress && (
              <div className="card mb-4">
                <h2 className="text-sm font-medium text-muted-color mb-2">Deployment Progress</h2>
                <div className="flex items-center gap-2 mb-2">
                  <span className={`w-2 h-2 rounded-full ${progress.complete ? "status-success" : "status-warning animate-pulse"}`} />
                  <span className="text-primary-color">{progress.message}</span>
                </div>
                <div className="text-muted-color text-xs">
                  Phase: {progress.phase}
                </div>
              </div>
            )}

            {/* Error display */}
            {error && (
              <div className="card status-error mb-4">
                <span className="text-sm">{error}</span>
              </div>
            )}

            {/* Deploy controls */}
            {!status?.bound && !deploying && (
              <>
                {!preflight && (
                  <button className="btn btn-primary w-full" onClick={checkPreflight}>
                    Check Prerequisites
                  </button>
                )}

                {preflight && (
                  <div className="card mb-4">
                    <h2 className="text-sm font-medium text-muted-color mb-2">Prerequisites</h2>

                    <div className="space-y-2 mb-4">
                      <div className="flex items-center gap-2">
                        <span className={preflight.wrangler_installed ? "status-success" : "status-error"}>
                          {preflight.wrangler_installed ? "✓" : "✗"}
                        </span>
                        <span className="text-primary-color">Wrangler CLI installed</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className={preflight.wrangler_logged_in ? "status-success" : "text-muted-color"}>
                          {preflight.wrangler_logged_in ? "✓" : "○"}
                        </span>
                        <span className="text-primary-color">Cloudflare account authorized</span>
                      </div>
                    </div>

                    {!preflight.wrangler_installed && (
                      <a
                        href="https://developers.cloudflare.com/workers/wrangler/install/"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="btn btn-secondary w-full text-center block mb-2"
                      >
                        Install Wrangler Guide
                      </a>
                    )}

                    {preflight.wrangler_installed && !preflight.wrangler_logged_in && (
                      <button className="btn btn-primary w-full mb-2" onClick={handleLogin}>
                        Log in to Cloudflare
                      </button>
                    )}

                    {preflight.ready && (
                      <button className="btn btn-primary w-full" onClick={handleDeploy}>
                        Deploy Runtime
                      </button>
                    )}
                  </div>
                )}
              </>
            )}

            {/* Redeploy option for existing deployment */}
            {status?.bound && !deploying && (
              <button className="btn btn-secondary w-full" onClick={handleRedeploy}>
                Update / Redeploy
              </button>
            )}

            {/* Info section */}
            <div className="card mt-4">
              <h2 className="text-sm font-medium text-muted-color mb-2">About Runtime</h2>
              <p className="text-secondary-color text-sm">
                Your runtime is a personal inbox server deployed to Cloudflare Workers.
                It stores and delivers your encrypted messages. All data is encrypted
                end-to-end - Cloudflare cannot read your messages.
              </p>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
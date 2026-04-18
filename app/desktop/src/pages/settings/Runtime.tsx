import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useNavigate } from "react-router";

interface RuntimeStatus {
  bound: boolean;
  endpoint: string | null;
}

interface AccountInfo {
  account_id: string;
  account_name: string;
  email?: string;
}

interface PreflightResult {
  authenticated: boolean;
  token_stored: boolean;
  embedded_available: boolean;
  ready: boolean;
  error: string | null;
  account: AccountInfo | null;
}

interface DeployProgress {
  phase: string;
  message: string;
  progress_percent: number;
}

interface DeployResult {
  success: boolean;
  worker_name: string;
  worker_url: string;
  error: string | null;
}

const PHASE_LABELS: Record<string, string> = {
  Preflight: "Checking prerequisites...",
  CreatingBuckets: "Creating storage buckets...",
  UploadingWorker: "Uploading Worker script...",
  WritingSecrets: "Writing authentication secrets...",
  ConfiguringBindings: "Configuring bindings...",
  VerifyingDeployment: "Verifying deployment...",
  Complete: "Complete!",
  Failed: "Failed",
};

export default function Runtime() {
  const navigate = useNavigate();
  const [status, setStatus] = useState<RuntimeStatus | null>(null);
  const [preflight, setPreflight] = useState<PreflightResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [deploying, setDeploying] = useState(false);
  const [progress, setProgress] = useState<DeployProgress | null>(null);
  const [deployResult, setDeployResult] = useState<DeployResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadStatus();
    checkPreflight();

    // Listen for deploy progress
    const unlisten = listen<DeployProgress>("cloudflare-progress", (event) => {
      setProgress(event.payload);
      if (event.payload.phase === "Complete" || event.payload.phase === "Failed") {
        setDeploying(false);
        if (event.payload.phase === "Complete") {
          loadStatus();
        }
      }
    });

    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

  const loadStatus = async () => {
    try {
      const result = await invoke<RuntimeStatus>("cloudflare_status");
      setStatus(result);
    } catch (err) {
      console.error(`[RuntimeSettings] Failed to load runtime status: ${String(err)}`);
    } finally {
      setLoading(false);
    }
  };

  const checkPreflight = async () => {
    try {
      const result = await invoke<PreflightResult>("cloudflare_preflight");
      setPreflight(result);
    } catch (err) {
      console.error(`[RuntimeSettings] Preflight check failed: ${String(err)}`);
      setError(String(err));
    }
  };

  const handleLogin = async () => {
    setError(null);
    try {
      const result = await invoke<{ success: boolean; error?: string }>("cloudflare_login");
      if (result.success) {
        await checkPreflight();
      } else {
        setError(result.error || "Login failed");
      }
    } catch (err) {
      setError(String(err));
    }
  };

  const handleDeploy = async () => {
    setError(null);
    setDeploying(true);
    setProgress(null);
    setDeployResult(null);
    try {
      const result = await invoke<DeployResult>("cloudflare_deploy");
      setDeployResult(result);
      if (!result.success) {
        setError(result.error || "Deployment failed");
      }
    } catch (err) {
      setError(String(err));
      setDeploying(false);
    }
  };

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden bg-base">
      {/* Header */}
      <header className="flex items-center p-3 border-b border-default animate-fade-in-down">
        <button className="btn btn-ghost px-2 transition-fast" onClick={() => navigate("/settings")}>
          ← Back
        </button>
        <h1 className="ml-2 text-lg font-medium text-primary-color">Runtime Management</h1>
      </header>

      {/* Content */}
      <div className="flex-1 overflow-y-auto overscroll-contain p-4">
        {loading && (
          <div className="text-center text-muted-color animate-pulse">Loading...</div>
        )}

        {!loading && (
          <>
            {/* Current status */}
            <div className="card mb-4 animate-fade-in-up">
              <h2 className="text-sm font-medium text-muted-color mb-3">Current Runtime</h2>

              <div className="flex items-center gap-3 mb-3">
                <span className={`w-3 h-3 rounded-full animate-scale-in ${status?.bound ? "bg-frost.1" : "bg-surface-elevated"}`} />
                <span className="text-primary-color font-medium">
                  {status?.bound ? "Deployed and Active" : "Not Deployed"}
                </span>
              </div>

              {status?.endpoint && (
                <div className="bg-surface-elevated rounded px-3 py-2">
                  <span className="text-xs text-muted-color">Endpoint</span>
                  <span className="text-primary-color text-sm block truncate">
                    {status.endpoint}
                  </span>
                </div>
              )}

              {!status?.bound && (
                <p className="text-muted-color text-sm mt-3">
                  Deploy your personal inbox server to Cloudflare to start messaging.
                </p>
              )}
            </div>

            {/* Deploy progress */}
            {deploying && progress && (
              <div className="card mb-4 animate-fade-in-up">
                <h2 className="text-sm font-medium text-muted-color mb-3">Deployment Progress</h2>

                <div className="flex items-center gap-3 mb-3">
                  <span className={`w-6 h-6 rounded-full flex items-center justify-center text-sm ${
                    progress.phase === "Complete" ? "bg-frost.1 text-white" :
                    progress.phase === "Failed" ? "bg-error text-white" :
                    "bg-primary animate-pulse text-white"
                  }`}>
                    {progress.phase === "Complete" ? "✓" :
                     progress.phase === "Failed" ? "✗" : "⏳"}
                  </span>
                  <span className="text-primary-color">
                    {PHASE_LABELS[progress.phase] || progress.message}
                  </span>
                </div>

                {/* Progress bar */}
                <div className="w-full bg-surface-elevated rounded-full h-2 mb-2">
                  <div
                    className={`rounded-full h-2 transition-all ${
                      progress.phase === "Failed" ? "bg-error" :
                      progress.phase === "Complete" ? "bg-frost.1" : "bg-primary"
                    }`}
                    style={{ width: `${progress.progress_percent}%` }}
                  />
                </div>

                <p className="text-xs text-muted-color">{progress.message}</p>
              </div>
            )}

            {/* Deploy result */}
            {deployResult && !deploying && (
              <div className="card mb-4 animate-fade-in-up">
                <h2 className="text-sm font-medium text-muted-color mb-2">Deployment Result</h2>

                {deployResult.success ? (
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <span className="w-5 h-5 rounded-full bg-frost.1 text-white flex items-center justify-center text-sm">✓</span>
                      <span className="text-primary-color font-medium">Successfully deployed</span>
                    </div>
                    <div className="text-sm text-muted-color">
                      <span className="text-secondary-color">Worker:</span> {deployResult.worker_name}
                    </div>
                    <div className="text-sm text-muted-color">
                      <span className="text-secondary-color">URL:</span> {deployResult.worker_url}
                    </div>
                  </div>
                ) : (
                  <div className="text-error">{deployResult.error}</div>
                )}
              </div>
            )}

            {/* Error display */}
            {error && (
              <div className="card mb-4 animate-fade-in-up bg-error/10">
                <span className="text-error text-sm">{error}</span>
              </div>
            )}

            {/* Deploy controls */}
            {!status?.bound && !deploying && !deployResult && preflight && (
              <div className="card mb-4 animate-fade-in-up">
                <h2 className="text-sm font-medium text-muted-color mb-3">Prerequisites</h2>

                <div className="space-y-3 mb-4">
                  {/* Embedded runtime */}
                  <div className="flex items-center gap-3">
                    <span className={`w-5 h-5 rounded-full flex items-center justify-center text-sm ${preflight.embedded_available ? "bg-frost.1 text-white" : "bg-surface-elevated text-muted-color"}`}>
                      {preflight.embedded_available ? "✓" : "○"}
                    </span>
                    <span className="text-primary-color">Embedded runtime</span>
                  </div>

                  {/* Authentication */}
                  <div className="flex items-center gap-3">
                    <span className={`w-5 h-5 rounded-full flex items-center justify-center text-sm ${preflight.authenticated ? "bg-frost.1 text-white" : "bg-surface-elevated text-muted-color"}`}>
                      {preflight.authenticated ? "✓" : "○"}
                    </span>
                    <div className="flex-1">
                      <span className="text-primary-color">Cloudflare connected</span>
                      {preflight.account && (
                        <span className="text-xs text-muted-color block">{preflight.account.account_name}</span>
                      )}
                    </div>
                  </div>
                </div>

                {/* Login button */}
                {preflight.embedded_available && !preflight.authenticated && (
                  <button className="btn btn-primary w-full transition-fast" onClick={handleLogin}>
                    Connect Cloudflare
                  </button>
                )}

                {/* Deploy button */}
                {preflight.ready && (
                  <button className="btn btn-primary w-full transition-fast animate-scale-in" onClick={handleDeploy}>
                    Deploy Runtime
                  </button>
                )}

                {/* Reinstall prompt */}
                {!preflight.embedded_available && (
                  <p className="text-muted-color text-sm text-center">
                    Embedded runtime not found. Please reinstall TapChat.
                  </p>
                )}
              </div>
            )}

            {/* Redeploy option */}
            {status?.bound && !deploying && (
              <button className="btn btn-secondary w-full transition-fast" onClick={handleDeploy}>
                Update / Redeploy
              </button>
            )}

            {/* Info section */}
            <div className="card mt-4 animate-fade-in-up" style={{ animationDelay: "200ms" }}>
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

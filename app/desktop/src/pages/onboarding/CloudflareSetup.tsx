import { useState, useEffect } from "react";
import { useNavigate } from "react-router";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

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

interface LoginResult {
  success: boolean;
  account_id: string | null;
  account_name: string | null;
  error: string | null;
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

export default function CloudflareSetup() {
  const navigate = useNavigate();

  const [preflight, setPreflight] = useState<PreflightResult | null>(null);
  const [loginInProgress, setLoginInProgress] = useState(false);
  const [deploying, setDeploying] = useState(false);
  const [progress, setProgress] = useState<DeployProgress | null>(null);
  const [deployResult, setDeployResult] = useState<DeployResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Check preflight on mount
  useEffect(() => {
    checkPreflight();

    // Listen for progress events
    const unlistenProgress = listen<DeployProgress>("cloudflare-progress", (event) => {
      setProgress(event.payload);
    });

    return () => {
      unlistenProgress.then((fn) => fn());
    };
  }, []);

  const checkPreflight = async () => {
    setError(null);
    try {
      const result = await invoke<PreflightResult>("cloudflare_preflight");
      setPreflight(result);
      if (result.error) {
        setError(result.error);
      }
    } catch (err) {
      setError(String(err));
    }
  };

  const handleLogin = async () => {
    setError(null);
    setLoginInProgress(true);
    try {
      const result = await invoke<LoginResult>("cloudflare_login");
      if (result.success) {
        // Re-check preflight after successful login
        await checkPreflight();
      } else {
        setError(result.error || "Login failed. Please try again.");
      }
    } catch (err) {
      setError(String(err));
    } finally {
      setLoginInProgress(false);
    }
  };

  const handleDeploy = async () => {
    setError(null);
    setDeploying(true);
    setProgress(null);
    setDeployResult(null);
    try {
      const result = await invoke<DeployResult>("cloudflare_deploy");
      if (result.success) {
        setDeployResult(result);
      } else {
        setError(result.error || "Deployment failed.");
        setDeploying(false);
      }
    } catch (err) {
      setError(String(err));
      setDeploying(false);
    }
  };

  const handleContinue = () => {
    navigate("/onboarding/complete");
  };

  const handleSkip = () => {
    navigate("/onboarding/complete");
  };

  return (
    <div className="flex flex-col h-screen bg-base p-8 animate-fade-in">
      {/* Header */}
      <div className="flex items-center mb-8 animate-fade-in-down">
        <button
          className="btn btn-ghost px-2 transition-fast"
          onClick={() => navigate("/onboarding/backup")}
        >
          ← Back
        </button>
        <span className="ml-auto text-muted-color">Step 4 of 5</span>
      </div>

      {/* Content */}
      <div className="flex flex-col items-center justify-center flex-1">
        <h2 className="text-xl font-semibold text-primary-color mb-2 animate-fade-in-up">
          Deploy Your Infrastructure
        </h2>

        <p className="text-secondary-color text-center mb-6 max-w-md animate-fade-in-up" style={{ animationDelay: "100ms" }}>
          TapChat deploys your personal inbox to Cloudflare's global network.
          No account required - just click Connect.
        </p>

        {/* Status panel */}
        <div className="card mb-4 max-w-sm w-full animate-fade-in-up" style={{ animationDelay: "200ms" }}>
          {!preflight && !deploying && (
            <div className="text-muted-color animate-pulse">Checking prerequisites...</div>
          )}

          {preflight && !deploying && !deployResult && (
            <div className="space-y-3">
              {/* Embedded runtime */}
              <div className="flex items-center gap-3">
                <span className={`w-6 h-6 rounded-full flex items-center justify-center text-sm ${preflight.embedded_available ? "bg-frost.1 text-white" : "bg-surface-elevated text-muted-color"}`}>
                  {preflight.embedded_available ? "✓" : "○"}
                </span>
                <div className="flex-1">
                  <span className="text-primary-color">Embedded runtime</span>
                  {!preflight.embedded_available && (
                    <span className="text-xs text-muted-color block">Reinstall TapChat to fix</span>
                  )}
                </div>
              </div>

              {/* Authentication */}
              <div className="flex items-center gap-3">
                <span className={`w-6 h-6 rounded-full flex items-center justify-center text-sm ${preflight.authenticated ? "bg-frost.1 text-white" : "bg-surface-elevated text-muted-color"}`}>
                  {preflight.authenticated ? "✓" : "○"}
                </span>
                <div className="flex-1">
                  <span className="text-primary-color">Cloudflare connected</span>
                  {preflight.account && (
                    <span className="text-xs text-muted-color block">{preflight.account.account_name}</span>
                  )}
                </div>
              </div>

              {/* Error message */}
              {error && (
                <div className="text-sm bg-error/10 text-error rounded px-3 py-2 mt-2">
                  {error}
                </div>
              )}
            </div>
          )}

          {/* Deployment progress */}
          {deploying && progress && (
            <div className="space-y-3 animate-fade-in">
              {/* Phase indicator */}
              <div className="flex items-center gap-3">
                <span className={`w-6 h-6 rounded-full flex items-center justify-center text-sm ${
                  progress.phase === "Complete" ? "bg-frost.1 text-white" :
                  progress.phase === "Failed" ? "bg-error text-white" :
                  "bg-primary animate-pulse text-white"
                }`}>
                  {progress.phase === "Complete" ? "✓" :
                   progress.phase === "Failed" ? "✗" : "⏳"}
                </span>
                <div className="flex-1">
                  <span className="text-primary-color">
                    {PHASE_LABELS[progress.phase] || progress.message}
                  </span>
                </div>
              </div>

              {/* Progress bar */}
              <div className="w-full bg-surface-elevated rounded-full h-2 progress-bar">
                <div
                  className={`rounded-full h-2 transition-all ${
                    progress.phase === "Failed" ? "bg-error" :
                    progress.phase === "Complete" ? "bg-frost.1" : "bg-primary"
                  }`}
                  style={{ width: `${progress.progress_percent}%` }}
                />
              </div>

              {/* Phase message */}
              <p className="text-xs text-muted-color">{progress.message}</p>
            </div>
          )}

          {/* Deploy success */}
          {deployResult && (
            <div className="space-y-3 animate-fade-in">
              <div className="flex items-center gap-3">
                <span className="w-6 h-6 rounded-full bg-frost.1 text-white flex items-center justify-center text-sm">
                  ✓
                </span>
                <span className="text-primary-color font-medium">Infrastructure deployed!</span>
              </div>

              <div className="text-sm text-muted-color space-y-1">
                <p><span className="text-secondary-color">Worker:</span> {deployResult.worker_name}</p>
                <p><span className="text-secondary-color">URL:</span> {deployResult.worker_url}</p>
              </div>
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="space-y-2 w-full max-w-xs animate-fade-in-up" style={{ animationDelay: "300ms" }}>
          {/* Not embedded - show reinstall message */}
          {!preflight?.embedded_available && !deploying && (
            <div className="text-center text-muted-color text-sm mb-4">
              Embedded runtime not found.<br />
              Please reinstall TapChat.
            </div>
          )}

          {/* Need login */}
          {preflight?.embedded_available && !preflight?.authenticated && !deploying && (
            <button
              className="btn btn-primary w-full transition-fast"
              onClick={handleLogin}
              disabled={loginInProgress}
            >
              {loginInProgress ? "Connecting..." : "Connect Cloudflare"}
            </button>
          )}

          {/* Ready to deploy */}
          {preflight?.ready && !deploying && !deployResult && (
            <button
              className="btn btn-primary w-full transition-fast animate-scale-in"
              onClick={handleDeploy}
            >
              Deploy Infrastructure
            </button>
          )}

          {/* Deployment complete - continue */}
          {deployResult && (
            <button
              className="btn btn-primary w-full transition-fast animate-scale-in"
              onClick={handleContinue}
            >
              Continue
            </button>
          )}

          {/* Skip option */}
          {!deploying && !deployResult && (
            <button
              className="btn btn-ghost w-full transition-fast"
              onClick={handleSkip}
            >
              Skip for now
            </button>
          )}
        </div>

        {/* Help link */}
        <p className="text-muted-color text-sm mt-6 animate-fade-in" style={{ animationDelay: "400ms" }}>
          Need help? <a href="https://developers.cloudflare.com/workers/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Cloudflare Workers Guide</a>
        </p>
      </div>
    </div>
  );
}
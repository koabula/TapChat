import { useState, useEffect } from "react";
import { useNavigate } from "react-router";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

interface PreflightResult {
  wrangler_installed: boolean;
  wrangler_logged_in: boolean;
  ready: boolean;
  error: string | null;
}

interface CloudflareProgress {
  phase: string;
  message: string;
  progress: number;
}

export default function CloudflareSetup() {
  const navigate = useNavigate();

  const [preflight, setPreflight] = useState<PreflightResult | null>(null);
  const [deploying, setDeploying] = useState(false);
  const [progress, setProgress] = useState<CloudflareProgress | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Check preflight on mount
  useEffect(() => {
    invoke<PreflightResult>("cloudflare_preflight")
      .then(setPreflight)
      .catch((err) => setError(String(err)));

    // Listen for progress events
    const unlisten = listen<CloudflareProgress>("cloudflare-progress", (event) => {
      setProgress(event.payload);
    });

    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

  const handleLogin = async () => {
    setError(null);
    try {
      const success = await invoke<boolean>("cloudflare_login");
      if (success) {
        // Re-check preflight
        const result = await invoke<PreflightResult>("cloudflare_preflight");
        setPreflight(result);
      } else {
        setError("Login failed. Please try again.");
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
      navigate("/onboarding/complete");
    } catch (err) {
      setError(String(err));
      setDeploying(false);
    }
  };

  const handleSkip = () => {
    navigate("/onboarding/complete");
  };

  return (
    <div className="flex flex-col h-screen bg-base p-8">
      {/* Header */}
      <div className="flex items-center mb-8">
        <button
          className="btn btn-ghost px-2"
          onClick={() => navigate("/onboarding/backup")}
        >
          ← Back
        </button>
        <span className="ml-auto text-muted-color">Step 4 of 5</span>
      </div>

      {/* Content */}
      <div className="flex flex-col items-center justify-center flex-1">
        <h2 className="text-xl font-semibold text-primary-color mb-2">
          Deploy Your Infrastructure
        </h2>

        <p className="text-secondary-color text-center mb-6 max-w-md">
          TapChat needs to deploy your personal inbox and storage server to Cloudflare Workers.
        </p>

        {/* Status panel */}
        <div className="card mb-4 max-w-sm w-full">
          {!preflight && <div className="text-muted-color">Checking prerequisites...</div>}

          {preflight && (
            <div className="space-y-2">
              {/* Wrangler installed */}
              <div className="flex items-center gap-2">
                <span className={preflight.wrangler_installed ? "status-success" : "status-error"}>
                  {preflight.wrangler_installed ? "✓" : "✗"}
                </span>
                <span className="text-primary-color">Wrangler CLI installed</span>
              </div>

              {/* Wrangler logged in */}
              <div className="flex items-center gap-2">
                <span className={preflight.wrangler_logged_in ? "status-success" : "text-muted-color"}>
                  {preflight.wrangler_logged_in ? "✓" : "○"}
                </span>
                <span className="text-primary-color">Cloudflare account authorized</span>
              </div>

              {/* Deploy progress */}
              {deploying && progress && (
                <>
                  <div className="flex items-center gap-2">
                    <span className="status-warning animate-pulse">⏳</span>
                    <span className="text-primary-color">{progress.message}</span>
                  </div>
                  <div className="w-full bg-surface rounded-full h-2 mt-2">
                    <div
                      className="bg-primary rounded-full h-2 transition-all"
                      style={{ width: `${progress.progress}%` }}
                    />
                  </div>
                </>
              )}

              {/* Error */}
              {error && (
                <div className="status-error text-sm mt-2">{error}</div>
              )}
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="space-y-2 w-full max-w-xs">
          {!preflight?.wrangler_installed && (
            <a
              href="https://developers.cloudflare.com/workers/wrangler/install/"
              target="_blank"
              rel="noopener noreferrer"
              className="btn btn-secondary w-full text-center block"
            >
              Install Wrangler Guide
            </a>
          )}

          {preflight?.wrangler_installed && !preflight?.wrangler_logged_in && (
            <button
              className="btn btn-primary w-full"
              onClick={handleLogin}
              disabled={deploying}
            >
              Log in to Cloudflare
            </button>
          )}

          {preflight?.ready && !deploying && (
            <button
              className="btn btn-primary w-full"
              onClick={handleDeploy}
            >
              Deploy Infrastructure
            </button>
          )}

          <button
            className="btn btn-ghost w-full"
            onClick={handleSkip}
            disabled={deploying}
          >
            Skip for now
          </button>
        </div>

        <p className="text-muted-color text-sm mt-4">
          Need help? <a href="#" className="text-primary hover:underline">Cloudflare Setup Guide</a>
        </p>
      </div>
    </div>
  );
}
import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { ArrowLeft, Check, Circle, Cloud, Database, Loader, Server, X } from "lucide-react";

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

type StepState = "idle" | "current" | "complete" | "error";

const PHASE_LABELS: Record<string, string> = {
  Preflight: "Checking prerequisites",
  CreatingBuckets: "Creating storage buckets",
  UploadingWorker: "Uploading inbox worker",
  WritingSecrets: "Writing private runtime secrets",
  ConfiguringBindings: "Connecting inbox and storage",
  VerifyingDeployment: "Verifying deployment",
  Complete: "Deployment complete",
  Failed: "Deployment failed",
};

export default function CloudflareSetup() {
  const navigate = useNavigate();
  const [preflight, setPreflight] = useState<PreflightResult | null>(null);
  const [loginInProgress, setLoginInProgress] = useState(false);
  const [deploying, setDeploying] = useState(false);
  const [progress, setProgress] = useState<DeployProgress | null>(null);
  const [deployResult, setDeployResult] = useState<DeployResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void checkPreflight();

    const unlistenProgress = listen<DeployProgress>("cloudflare-progress", (event) => {
      setProgress(event.payload);
    });

    return () => {
      unlistenProgress.then((fn) => fn());
    };
  }, []);

  const steps = useMemo(
    () => [
      {
        label: "Runtime ready",
        detail: preflight?.embedded_available
          ? "Embedded deploy runtime is available."
          : "Checking local runtime package.",
        Icon: Server,
        state: preflight == null
          ? "current"
          : preflight.embedded_available
            ? "complete"
            : "error",
      },
      {
        label: "Cloudflare connected",
        detail: preflight?.account?.account_name || "Authorize TapChat to deploy your inbox.",
        Icon: Cloud,
        state: preflight?.authenticated
          ? "complete"
          : preflight?.embedded_available
            ? "current"
            : "idle",
      },
      {
        label: "Deploy inbox/storage",
        detail: progress?.phase && progress.phase !== "VerifyingDeployment"
          ? PHASE_LABELS[progress.phase] || progress.message
          : "Create your personal inbox and attachment storage.",
        Icon: Database,
        state: deployResult?.success
          ? "complete"
          : progress?.phase === "Failed"
            ? "error"
            : deploying
              ? "current"
              : preflight?.ready
                ? "current"
                : "idle",
      },
      {
        label: "Verify deployment",
        detail: deployResult?.success
          ? deployResult.worker_url
          : progress?.phase === "VerifyingDeployment"
            ? progress.message
            : "Confirm your inbox endpoint is reachable.",
        Icon: Check,
        state: deployResult?.success
          ? "complete"
          : progress?.phase === "VerifyingDeployment"
            ? "current"
            : progress?.phase === "Failed"
              ? "error"
              : "idle",
      },
    ] satisfies Array<{ label: string; detail: string; Icon: typeof Server; state: StepState }>,
    [deployResult?.success, deployResult?.worker_url, deploying, preflight, progress],
  );

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
      setDeployResult(result);
      if (!result.success) {
        setError(result.error || "Deployment failed.");
      }
    } catch (err) {
      setError(String(err));
    } finally {
      setDeploying(false);
    }
  };

  const handleContinue = () => {
    navigate("/onboarding/complete");
  };

  const handleSkip = () => {
    navigate("/onboarding/complete");
  };

  const progressPercent = deployResult?.success
    ? 100
    : progress?.progress_percent ?? (preflight?.ready ? 20 : preflight?.authenticated ? 10 : 0);

  return (
    <div className="flex h-screen flex-col bg-base p-8">
      <div className="flex items-center">
        <button className="btn btn-ghost px-2" onClick={() => navigate("/onboarding/backup")}>
          <ArrowLeft size={16} />
          Back
        </button>
        <span className="ml-auto text-sm text-muted-color">Step 4 of 5</span>
      </div>

      <main className="flex min-h-0 flex-1 items-center justify-center">
        <div className="grid w-full max-w-4xl gap-8 lg:grid-cols-[1fr_22rem]">
          <section className="flex flex-col justify-center">
            <div className="mb-6">
              <h1 className="text-2xl font-semibold text-primary-color">
                Deploy your personal inbox
              </h1>
              <p className="mt-3 max-w-xl text-sm leading-6 text-secondary-color">
                TapChat can deploy a private inbox worker and attachment storage to
                your Cloudflare account. Messages stay end-to-end encrypted; the
                runtime only stores and forwards encrypted records.
              </p>
            </div>

            <div className="space-y-3">
              {steps.map((step) => (
                <StepRow key={step.label} {...step} />
              ))}
            </div>

            {error && (
              <div className="mt-4 rounded-md border border-error/30 bg-error/10 px-3 py-2 text-sm text-error">
                {error}
              </div>
            )}
          </section>

          <aside className="rounded-lg border border-subtle bg-surface p-4">
            <div className="mb-4 flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-md bg-surface-elevated text-muted-color">
                <Database size={20} />
              </div>
              <div>
                <h2 className="font-medium text-primary-color">Inbox/storage</h2>
                <p className="text-xs text-muted-color">Profile-local transport</p>
              </div>
            </div>

            <div className="mb-4 h-2 rounded-full bg-surface-elevated">
              <div
                className="h-2 rounded-full bg-primary transition-all"
                style={{ width: `${progressPercent}%` }}
              />
            </div>

            {deployResult?.success ? (
              <div className="space-y-2 text-sm">
                <p className="status-success font-medium">Infrastructure deployed.</p>
                <InfoLine label="Worker" value={deployResult.worker_name} />
                <InfoLine label="URL" value={deployResult.worker_url} />
              </div>
            ) : (
              <div className="space-y-2 text-sm text-secondary-color">
                <InfoLine
                  label="Runtime"
                  value={preflight?.embedded_available ? "Ready" : "Checking"}
                />
                <InfoLine
                  label="Cloudflare"
                  value={preflight?.authenticated ? "Connected" : "Not connected"}
                />
                <InfoLine
                  label="Status"
                  value={progress?.phase ? PHASE_LABELS[progress.phase] || progress.message : "Not deployed"}
                />
              </div>
            )}

            <div className="mt-5 space-y-2">
              {preflight?.embedded_available && !preflight.authenticated && !deploying && !deployResult && (
                <button
                  className="btn btn-primary w-full"
                  onClick={handleLogin}
                  disabled={loginInProgress}
                >
                  {loginInProgress ? "Connecting..." : "Connect Cloudflare"}
                </button>
              )}

              {preflight?.ready && !deploying && !deployResult && (
                <button className="btn btn-primary w-full" onClick={handleDeploy}>
                  Deploy Inbox/Storage
                </button>
              )}

              {deploying && (
                <button className="btn btn-primary w-full" disabled>
                  <Loader size={16} className="animate-spin" />
                  Deploying...
                </button>
              )}

              {deployResult?.success && (
                <button className="btn btn-primary w-full" onClick={handleContinue}>
                  Continue
                </button>
              )}

              {!deploying && !deployResult && (
                <button className="btn btn-ghost w-full" onClick={handleSkip}>
                  Skip for now
                </button>
              )}
            </div>
          </aside>
        </div>
      </main>
    </div>
  );
}

function StepRow({
  label,
  detail,
  Icon,
  state,
}: {
  label: string;
  detail: string;
  Icon: typeof Server;
  state: StepState;
}) {
  return (
    <div className="flex items-start gap-3 rounded-lg border border-subtle bg-surface px-3 py-3">
      <div className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-surface-elevated text-muted-color">
        <Icon size={17} />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center justify-between gap-3">
          <h2 className="font-medium text-primary-color">{label}</h2>
          <StepStatus state={state} />
        </div>
        <p className="mt-1 truncate text-sm text-muted-color">{detail}</p>
      </div>
    </div>
  );
}

function StepStatus({ state }: { state: StepState }) {
  if (state === "complete") {
    return <Check size={16} className="status-success" />;
  }
  if (state === "error") {
    return <X size={16} className="status-error" />;
  }
  if (state === "current") {
    return <Loader size={16} className="animate-spin text-primary" />;
  }
  return <Circle size={16} className="text-muted-color" />;
}

function InfoLine({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span className="block text-xs text-muted-color">{label}</span>
      <span className="block truncate text-primary-color" title={value}>
        {value}
      </span>
    </div>
  );
}

import type { Dispatch, SetStateAction } from "react";
import type {
  CloudflareDeployOverrides,
  CloudflarePreflightView,
  CloudflareWizardStatusView,
} from "../../lib/types";
import { wizardPrimaryCopy, wizardSecondaryCopy } from "../../app/formatters";
import { cloudflareActionLabel } from "../../app/formatters";

export default function CloudflareSetupStep({
  preflight,
  wizard,
  overrides,
  setOverrides,
  customOpen,
  setCustomOpen,
  onBack,
  canGoBack,
  onStart,
  onCancel,
  onRefreshStatus,
  onImportBundle,
  disabled,
  pendingAction,
}: {
  preflight: CloudflarePreflightView | null;
  wizard: CloudflareWizardStatusView | null;
  overrides: CloudflareDeployOverrides;
  setOverrides: Dispatch<SetStateAction<CloudflareDeployOverrides>>;
  customOpen: boolean;
  setCustomOpen: Dispatch<SetStateAction<boolean>>;
  onBack: () => void;
  canGoBack: boolean;
  onStart: (mode: "auto" | "custom") => Promise<void>;
  onCancel: () => Promise<void>;
  onRefreshStatus: () => Promise<void>;
  onImportBundle: () => Promise<void>;
  disabled: boolean;
  pendingAction: string | null;
}) {
  const wizardRunning = !!wizard && !["idle", "completed", "failed"].includes(wizard.state);
  const canOperate = !disabled && !wizardRunning;
  const failed = wizard?.state === "failed";
  return (
    <section className="onboarding-step">
      <div className="onboarding-step-header">
        <div className="onboarding-step-actions">
          <button className="ghost-button compact-button" disabled={!canGoBack || wizardRunning || disabled || pendingAction === "wizard_cancel"} onClick={onBack}>
            Back
          </button>
        </div>
        <span className="eyebrow">Step 3</span>
        <h2>Set up Cloudflare transport</h2>
        <p>{wizardPrimaryCopy(wizard)}</p>
        <small className="muted">{wizardSecondaryCopy(wizard)}</small>
      </div>

      <div className={failed ? "wizard-status-card failed" : "wizard-status-card"}>
        <div className="wizard-status-row"><span>Current state</span><strong>{wizard?.state ?? "idle"}</strong></div>
        <div className="wizard-status-row"><span>Workspace</span><strong>{preflight?.workspace_root_found ? "Found" : "Missing"}</strong></div>
        <div className="wizard-status-row"><span>Wrangler</span><strong>{preflight?.wrangler_available ? "Available" : "Missing"}</strong></div>
        <div className="wizard-status-row"><span>Identity</span><strong>{preflight?.identity_ready ? "Ready" : "Missing"}</strong></div>
        {failed && wizard?.diagnostic_bootstrap_url && (
          <div className="wizard-status-row"><span>Bootstrap URL</span><strong>{wizard.diagnostic_bootstrap_url}</strong></div>
        )}
        {failed && wizard?.diagnostic_deploy_url && (
          <div className="wizard-status-row"><span>Deploy URL</span><strong>{wizard.diagnostic_deploy_url}</strong></div>
        )}
        {failed && wizard?.diagnostic_runtime_url && (
          <div className="wizard-status-row"><span>Runtime URL</span><strong>{wizard.diagnostic_runtime_url}</strong></div>
        )}
        {failed && wizard?.last_error_detail && <small className="muted">{wizard.last_error_detail}</small>}
      </div>

      <div className="button-row">
        <button
          className="primary-button"
          disabled={!canOperate || !preflight?.identity_ready || !preflight?.workspace_root_found || !preflight?.wrangler_available || !!pendingAction}
          onClick={() => void onStart("auto")}
        >
          {cloudflareActionLabel(pendingAction, "wizard_auto", failed ? "Try again" : "Set up Cloudflare automatically", "Setting up Cloudflare...")}
        </button>
        {wizardRunning && (
          <button className="ghost-button" disabled={disabled || pendingAction === "wizard_cancel"} onClick={() => void onCancel()}>
            {cloudflareActionLabel(pendingAction, "wizard_cancel", "Cancel", "Cancelling...")}
          </button>
        )}
        {failed && (
          <button className="ghost-button" disabled={disabled || !!pendingAction} onClick={() => void onRefreshStatus()}>
            {cloudflareActionLabel(pendingAction, "runtime_refresh", "Refresh status", "Refreshing...")}
          </button>
        )}
      </div>

      <details className="onboarding-advanced" open={customOpen}>
        <summary onClick={(event) => {
          event.preventDefault();
          setCustomOpen((value) => !value);
        }}
        >
          {customOpen ? "Hide advanced options" : "Show advanced options"}
        </summary>
        <div className="onboarding-advanced-body">
          <div className="button-row">
            <button className="ghost-button" disabled={disabled || !!pendingAction} onClick={() => void onImportBundle()}>
              {cloudflareActionLabel(pendingAction, "bundle_import", "Import deployment bundle", "Importing...")}
            </button>
          </div>
          <div className="onboarding-form-grid two-columns">
            {Object.entries(overrides).map(([key, value]) => (
              <label key={key}>
                <span>{key.replace(/_/g, " ")}</span>
                <input value={value ?? ""} onChange={(event) => setOverrides((current) => ({ ...current, [key]: event.target.value }))} />
              </label>
            ))}
          </div>
          <div className="button-row">
            <button
              className="ghost-button"
              disabled={!canOperate || !preflight?.identity_ready || !preflight?.workspace_root_found || !preflight?.wrangler_available || !!pendingAction}
              onClick={() => void onStart("custom")}
            >
              {cloudflareActionLabel(pendingAction, "wizard_custom", "Use custom options", "Starting custom setup...")}
            </button>
          </div>
        </div>
      </details>
    </section>
  );
}

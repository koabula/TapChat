import type { Dispatch, SetStateAction } from "react";
import type {
  AppBootstrapView,
  CloudflareDeployOverrides,
  CloudflarePreflightView,
  CloudflareRuntimeDetailsView,
  CloudflareWizardStatusView,
} from "../../lib/types";
import InfoCard from "../shared/InfoCard";
import { cloudflareActionLabel } from "../../app/formatters";

export default function RuntimeDrawer({
  bootstrap,
  activeProfilePath,
  runtimeDetails,
  preflight,
  cloudflareWizard,
  customWizardOpen,
  setCustomWizardOpen,
  overrides,
  setOverrides,
  loading,
  wizardRunning,
  onStartWizard,
  onCancelWizard,
  onImportBundle,
  onRefreshStatus,
  onRedeploy,
  onRotateSecrets,
  onDetach,
  pendingAction,
}: {
  bootstrap: AppBootstrapView | null;
  activeProfilePath: string | null;
  runtimeDetails: CloudflareRuntimeDetailsView | null;
  preflight: CloudflarePreflightView | null;
  cloudflareWizard: CloudflareWizardStatusView | null;
  customWizardOpen: boolean;
  setCustomWizardOpen: Dispatch<SetStateAction<boolean>>;
  overrides: CloudflareDeployOverrides;
  setOverrides: Dispatch<SetStateAction<CloudflareDeployOverrides>>;
  loading: boolean;
  wizardRunning: boolean;
  onStartWizard: (mode: "auto" | "custom") => Promise<void>;
  onCancelWizard: () => Promise<void>;
  onImportBundle: () => Promise<void>;
  onRefreshStatus: () => Promise<void>;
  onRedeploy: () => Promise<void>;
  onRotateSecrets: () => Promise<void>;
  onDetach: () => Promise<void>;
  pendingAction: string | null;
}) {
  const disableCloudflareActions = !!pendingAction || wizardRunning;
  return (
    <>
      <InfoCard title="Runtime binding" rows={[
        ["Mode", runtimeDetails?.mode ?? bootstrap?.runtime?.mode ?? "none"],
        ["Bound", runtimeDetails?.deployment_bound ? "Yes" : "No"],
        ["Base URL", runtimeDetails?.public_base_url ?? bootstrap?.runtime?.public_base_url ?? "Pending"],
        ["Worker", runtimeDetails?.worker_name ?? bootstrap?.runtime?.worker_name ?? "Pending"],
        ["Status", runtimeDetails?.deployment_bound ? "Bound" : "Missing"],
      ]} />
      <InfoCard title="Setup status" rows={[
        ["State", cloudflareWizard?.state ?? "idle"],
        ["Message", cloudflareWizard?.message ?? "Ready to set up Cloudflare transport."],
        ["Blocking", cloudflareWizard?.blocking_error ?? preflight?.blocking_error ?? "None"],
      ]} />
      <InfoCard title="Deployment details" rows={[
        ["Deploy URL", runtimeDetails?.deploy_url ?? "Missing"],
        ["Region", runtimeDetails?.deployment_region ?? "Missing"],
        ["Bucket", runtimeDetails?.bucket_name ?? "Missing"],
        ["Preview bucket", runtimeDetails?.preview_bucket_name ?? "Missing"],
        ["Bundle path", runtimeDetails?.deployment_bundle_path ?? "Missing"],
        ["Last deployed", runtimeDetails?.provisioned_at ?? "Missing"],
        ["Bootstrap secret", runtimeDetails?.bootstrap_secret_present ? "Present" : "Missing"],
        ["Sharing secret", runtimeDetails?.sharing_secret_present ? "Present" : "Missing"],
      ]} />
      <InfoCard title="Preflight" rows={[
        ["Workspace", preflight?.workspace_root_found ? "Found" : "Missing"],
        ["Service root", preflight?.service_root ?? "Missing"],
        ["Wrangler", preflight?.wrangler_available ? "Available" : "Missing"],
        ["Wrangler login", preflight?.wrangler_logged_in ? "Ready" : "Missing"],
        ["Identity", preflight?.identity_ready ? "Ready" : "Missing"],
        ["Bundle", preflight?.deployment_bundle_present ? "Present" : "Missing"],
        ["Blocking", preflight?.blocking_error ?? "None"],
      ]} />
      <div className="button-row">
        <button className="ghost-button" disabled={loading || disableCloudflareActions || !preflight?.identity_ready || !preflight?.workspace_root_found || !preflight?.wrangler_available} onClick={() => void onStartWizard("auto")}>{cloudflareActionLabel(pendingAction, "wizard_auto", "Set up Cloudflare automatically", "Setting up Cloudflare...")}</button>
        {wizardRunning && <button className="ghost-button" disabled={loading || pendingAction === "wizard_cancel"} onClick={() => void onCancelWizard()}>{cloudflareActionLabel(pendingAction, "wizard_cancel", "Cancel setup", "Cancelling...")}</button>}
        <button className="ghost-button" disabled={loading || disableCloudflareActions} onClick={() => void onImportBundle()}>{cloudflareActionLabel(pendingAction, "bundle_import", "Import deployment bundle", "Importing...")}</button>
        <button className="ghost-button" disabled={loading || !!pendingAction} onClick={() => setCustomWizardOpen((current) => !current)}>{customWizardOpen ? "Hide custom options" : "Use custom options"}</button>
        <button className="ghost-button" disabled={loading || disableCloudflareActions} onClick={() => void onRefreshStatus()}>{cloudflareActionLabel(pendingAction, "runtime_refresh", "Refresh status", "Refreshing...")}</button>
        <button className="ghost-button" disabled={loading || disableCloudflareActions || !runtimeDetails?.deployment_bound || !activeProfilePath} onClick={() => void onRedeploy()}>{cloudflareActionLabel(pendingAction, "runtime_redeploy", "Redeploy", "Redeploying...")}</button>
        <button className="ghost-button" disabled={loading || disableCloudflareActions || !runtimeDetails?.deployment_bound || !activeProfilePath} onClick={() => void onRotateSecrets()}>{cloudflareActionLabel(pendingAction, "runtime_rotate", "Rotate secrets", "Rotating...")}</button>
        <button className="ghost-button" disabled={loading || disableCloudflareActions || !runtimeDetails?.deployment_bound || !activeProfilePath} onClick={() => void onDetach()}>{cloudflareActionLabel(pendingAction, "runtime_detach", "Detach", "Detaching...")}</button>
      </div>
      {customWizardOpen && (
        <>
          <div className="form-grid two-columns">
            {Object.entries(overrides).map(([key, value]) => (
              <label key={key}>
                <span>{key.replace(/_/g, " ")}</span>
                <input value={value ?? ""} onChange={(event) => setOverrides((current) => ({ ...current, [key]: event.target.value }))} />
              </label>
            ))}
          </div>
          <div className="button-row">
            <button className="primary-button" disabled={loading || disableCloudflareActions || !preflight?.identity_ready || !preflight?.workspace_root_found || !preflight?.wrangler_available} onClick={() => void onStartWizard("custom")}>
              {cloudflareActionLabel(pendingAction, "wizard_custom", "Start custom setup", "Starting custom setup...")}
            </button>
          </div>
        </>
      )}
    </>
  );
}

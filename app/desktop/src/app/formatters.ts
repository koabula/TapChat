import type { CloudflareDeployOverrides, CloudflareWizardStatusView } from "../lib/types";

export function normalizeOverrides(overrides: CloudflareDeployOverrides) {
  const next = { ...overrides };
  for (const [key, value] of Object.entries(next)) {
    if (!value || !value.trim()) {
      delete (next as Record<string, string | null | undefined>)[key];
    }
  }
  return next;
}

export function formatError(error: unknown) {
  const raw = typeof error === "string"
    ? error
    : error && typeof error === "object" && "toString" in error
      ? String(error)
      : "Unknown error";
  const lower = raw.toLowerCase();
  if (lower.includes("not_a_profile_directory") || lower.includes("profile.json not found")) {
    return "This folder is not a TapChat profile. Choose a folder that already contains profile.json.";
  }
  if (lower.includes("wrangler_missing") || lower.includes("wrangler is not available")) {
    return "Wrangler is not available in the Cloudflare service workspace. Run npm install in services/cloudflare first.";
  }
  if (lower.includes("wrangler_not_logged_in")) {
    return "Cloudflare authorization is required. TapChat will open the Wrangler login flow in your browser.";
  }
  if (lower.includes("workspace_not_found") || lower.includes("workspace root") || lower.includes("service root")) {
    return "The Cloudflare service workspace could not be found from this checkout.";
  }
  if (lower.includes("identity_not_ready") || lower.includes("local identity is not initialized")) {
    return "Create or recover this profile identity before setting up transport.";
  }
  if (lower.includes("runtime_not_bound")) {
    return "This profile is not currently bound to a Cloudflare deployment.";
  }
  if (lower.includes("runtime_not_ready_in_time") || lower.includes("did not become ready in time")) {
    return "Cloudflare deployed, but the runtime did not become reachable in time. Wait a moment and try Refresh status or Redeploy.";
  }
  if (lower.includes("bootstrap_failed") || lower.includes("bootstrap failed")) {
    return "Cloudflare deployed, but device bootstrap failed.";
  }
  if (lower.includes("bundle_import_failed") || lower.includes("import deployment bundle")) {
    return "Deployment succeeded, but TapChat could not import the deployment bundle.";
  }
  if (lower.includes("deploy_failed") || lower.includes("cloudflare deploy script failed")) {
    return "Cloudflare deployment failed before runtime setup completed.";
  }
  return raw;
}

export function dedupePaths(paths: string[]) {
  return Array.from(new Set(paths));
}

export function fileNameFromPath(path: string) {
  const segments = path.split(/[/\\]/);
  return segments[segments.length - 1] ?? path;
}

export function wizardPrimaryCopy(status: CloudflareWizardStatusView | null) {
  switch (status?.state) {
    case "waiting_for_login":
      return "Browser authorization required";
    case "deploying":
      return "Deploying Cloudflare transport";
    case "bootstrapping":
      return "Bootstrapping this device";
    case "importing_bundle":
      return "Importing deployment bundle";
    case "completed":
      return "Cloudflare transport is ready.";
    case "failed":
      return formatError(status.last_error_detail ?? status.blocking_error ?? status.message);
    default:
      return "Set up Cloudflare automatically";
  }
}

export function wizardSecondaryCopy(status: CloudflareWizardStatusView | null) {
  switch (status?.state) {
    case "waiting_for_login":
      return "Your browser should already be open. Finish Cloudflare authorization and TapChat will continue deployment automatically.";
    case "deploying":
      return "TapChat is deploying the inbox and storage runtime.";
    case "bootstrapping":
      return "Cloudflare is ready. TapChat is now bootstrapping the active device.";
    case "importing_bundle":
      return "The deployment bundle is being imported into this profile.";
    case "completed":
      return "Cloudflare transport is ready.";
    case "failed":
      return status.message;
    default:
      return "TapChat will guide you through Wrangler login, deployment, bootstrap, and bundle import.";
  }
}

export function cloudflareActionLabel(
  pendingAction: string | null,
  action: string,
  idleLabel: string,
  loadingLabel: string,
) {
  return pendingAction === action ? loadingLabel : idleLabel;
}

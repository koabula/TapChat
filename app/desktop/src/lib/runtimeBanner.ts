import type { CloudflareStatus } from "./types";

export type RuntimeBannerTone = "warning" | "error";

export interface RuntimeBanner {
  message: string;
  actionLabel?: string;
  tone: RuntimeBannerTone;
}

export function runtimeBannerForStatus(status: CloudflareStatus | null): RuntimeBanner | null {
  if (!status) {
    return null;
  }
  switch (status.state) {
    case "ready":
    case "refreshing":
    case "degraded":
    case "offline_expired":
    case "auth_expired":
      return null;
    case "missing":
      return {
        message: "Cloudflare runtime is not deployed.",
        actionLabel: "Deploy",
        tone: "warning",
      };
    case "incomplete":
    case "writeback_incomplete":
      return {
        message: status.details || "Cloudflare runtime setup is incomplete.",
        actionLabel: "Repair",
        tone: "warning",
      };
    case "outdated":
      return {
        message: "Cloudflare runtime needs an upgrade.",
        actionLabel: "Upgrade",
        tone: "warning",
      };
    case "unreachable":
      return {
        message: status.last_error || "Cloudflare runtime is unreachable.",
        actionLabel: "Redeploy",
        tone: "error",
      };
    case "upgrade_required":
      return {
        message: "Cloudflare runtime needs a one-time upgrade.",
        actionLabel: "Upgrade",
        tone: "warning",
      };
    case "enrollment_required":
      return {
        message: "This device must enroll with the Cloudflare runtime.",
        actionLabel: "Open",
        tone: "warning",
      };
    case "device_revoked":
      return {
        message: "This device was revoked. Restore your identity or create a new device.",
        tone: "error",
      };
    default:
      return {
        message: status.details || status.last_error || "Cloudflare runtime needs attention.",
        actionLabel: "Open",
        tone: "warning",
      };
  }
}

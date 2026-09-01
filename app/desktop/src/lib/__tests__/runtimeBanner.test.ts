import { describe, expect, it } from "vitest";

import { runtimeBannerForStatus } from "../runtimeBanner";
import type { CloudflareStatus } from "../types";

function status(state: string, extras: Partial<CloudflareStatus> = {}): CloudflareStatus {
  return {
    bound: true,
    features: [],
    supports_group_outbox: true,
    supports_welcome_pickup: true,
    needs_upgrade: false,
    state,
    ...extras,
  };
}

describe("runtimeBannerForStatus", () => {
  it("does not toast for automatic credential refresh states", () => {
    for (const state of ["ready", "refreshing", "degraded", "offline_expired", "auth_expired"]) {
      expect(runtimeBannerForStatus(status(state))).toBeNull();
    }
    expect(runtimeBannerForStatus(null)).toBeNull();
  });

  it("toasts when the device was revoked", () => {
    const banner = runtimeBannerForStatus(status("device_revoked"));
    expect(banner).toEqual({
      message: "This device was revoked. Restore your identity or create a new device.",
      tone: "error",
    });
  });

  it("toasts user-actionable runtime setup failures", () => {
    expect(runtimeBannerForStatus(status("missing"))?.actionLabel).toBe("Deploy");
    expect(runtimeBannerForStatus(status("incomplete"))?.actionLabel).toBe("Repair");
    expect(runtimeBannerForStatus(status("upgrade_required"))?.actionLabel).toBe("Upgrade");
  });
});

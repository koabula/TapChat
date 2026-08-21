import { describe, expect, it } from "vitest";

import { AppInvokeError, normalizeAppError, presentError } from "../errors";

describe("structured application errors", () => {
  it("presents every security-sensitive key package error with fixed English copy", () => {
    expect(presentError({ version: 1, code: "keypackage_expired", domain: "mls", retryable: true }).message)
      .toBe("This contact needs to open TapChat before a secure conversation can be started.");
    expect(presentError({ version: 1, code: "device_clock_invalid", domain: "security", retryable: false }).message)
      .toBe("Your device date and time appear to be incorrect. Correct them and try again.");
  });

  it("does not expose raw strings from native or HTTP failures", () => {
    const raw = "C:\\Users\\alice\\profile.json token=secret HTTP 500";
    expect(presentError(raw).message).toBe("Something went wrong. Try again.");
    expect(JSON.stringify(normalizeAppError(raw))).not.toContain("secret");
  });

  it("preserves safe recovery metadata", () => {
    const error = normalizeAppError({
      version: 1,
      code: "upgrade_required",
      domain: "runtime",
      retryable: false,
      action: "upgrade_runtime",
      correlationId: "safe-id",
    });
    expect(error.action).toBe("upgrade_runtime");
    expect(error.correlationId).toBe("safe-id");
    expect(presentError(error).message).toBe("Update TapChat and your Cloudflare runtime to continue.");
  });

  it("presents Cloudflare deployment failures without exposing provider details", () => {
    const permission = presentError({
      version: 1,
      code: "cloudflare_permission_denied",
      domain: "runtime",
      retryable: false,
    });
    expect(permission.message).toBe(
      "Reconnect Cloudflare and allow TapChat to manage Workers and R2 storage.",
    );

    const incomplete = presentError({
      version: 1,
      code: "cloudflare_setup_incomplete",
      domain: "runtime",
      retryable: true,
    });
    expect(incomplete.message).toBe(
      "The Worker may already be deployed, but this device did not finish setup. Retry to resume.",
    );
  });

  it("preserves structured errors after the invoke boundary wraps them", () => {
    const wrapped = new AppInvokeError({
      version: 1,
      code: "cloudflare_storage_setup_failed",
      domain: "runtime",
      retryable: true,
    });

    expect(presentError(wrapped).message).toBe(
      "TapChat could not prepare its Cloudflare R2 storage. Try again.",
    );
  });

  it("normalizes domain and recovery action from the registry", () => {
    const error = normalizeAppError({
      version: 1,
      code: "keypackage_expired",
      domain: "raw-server-domain",
      retryable: false,
      action: "show_raw_details",
      correlationId: "token value must not escape",
      httpStatus: 999,
    });
    expect(error.domain).toBe("mls");
    expect(error.action).toBe("refresh_identity");
    expect(error.correlationId).toBeUndefined();
    expect(error.httpStatus).toBeUndefined();
  });

  it("rejects non-v1 structured errors", () => {
    expect(normalizeAppError({
      version: 2,
      code: "upgrade_required",
      domain: "runtime",
      retryable: false,
    }).code).toBe("unexpected_error");
  });
});

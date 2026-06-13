import { describe, expect, it, vi } from "vitest";

import { waitForNonBootstrappingSessionStatus } from "../sessionStartup";
import type { SessionStatus } from "../types";

function status(state: string): SessionStatus {
  return {
    state,
    device_id: state === "active" ? "device:test" : undefined,
    ws_connected: false,
  };
}

describe("waitForNonBootstrappingSessionStatus", () => {
  it("retries bootstrapping status until the backend reports a final state", async () => {
    let now = 0;
    const fetchStatus = vi
      .fn<() => Promise<SessionStatus>>()
      .mockResolvedValueOnce(status("bootstrapping"))
      .mockResolvedValueOnce(status("bootstrapping"))
      .mockResolvedValueOnce(status("active"));
    const sleep = vi.fn(async (delayMs: number) => {
      now += delayMs;
    });

    const result = await waitForNonBootstrappingSessionStatus(fetchStatus, {
      retryDelayMs: 10,
      timeoutMs: 100,
      now: () => now,
      sleep,
    });

    expect(result.state).toBe("active");
    expect(fetchStatus).toHaveBeenCalledTimes(3);
    expect(sleep).toHaveBeenCalledTimes(2);
  });

  it("fails with a diagnostic error instead of waiting forever", async () => {
    let now = 0;
    const fetchStatus = vi
      .fn<() => Promise<SessionStatus>>()
      .mockResolvedValue(status("bootstrapping"));
    const sleep = vi.fn(async (delayMs: number) => {
      now += delayMs;
    });

    await expect(
      waitForNonBootstrappingSessionStatus(fetchStatus, {
        retryDelayMs: 10,
        timeoutMs: 20,
        now: () => now,
        sleep,
      }),
    ).rejects.toThrow("still preparing your workspace");
  });
});

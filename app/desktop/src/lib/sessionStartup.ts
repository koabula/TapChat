import type { SessionStatus } from "./types";

export const SESSION_STATUS_RETRY_DELAY_MS = 250;
export const SESSION_STATUS_BOOTSTRAP_TIMEOUT_MS = 20_000;

export interface WaitForSessionStatusOptions {
  retryDelayMs?: number;
  timeoutMs?: number;
  now?: () => number;
  sleep?: (delayMs: number) => Promise<void>;
}

export async function waitForNonBootstrappingSessionStatus(
  fetchStatus: () => Promise<SessionStatus>,
  options: WaitForSessionStatusOptions = {},
): Promise<SessionStatus> {
  const retryDelayMs = options.retryDelayMs ?? SESSION_STATUS_RETRY_DELAY_MS;
  const timeoutMs = options.timeoutMs ?? SESSION_STATUS_BOOTSTRAP_TIMEOUT_MS;
  const now = options.now ?? (() => Date.now());
  const sleep =
    options.sleep ??
    ((delayMs: number) =>
      new Promise<void>((resolve) => {
        setTimeout(resolve, delayMs);
      }));

  const startedAt = now();
  let status = await fetchStatus();

  while (status.state === "bootstrapping") {
    if (now() - startedAt >= timeoutMs) {
      throw new Error(
        "TapChat is still preparing your workspace. Please restart the app or check the TapChat logs.",
      );
    }
    await sleep(retryDelayMs);
    status = await fetchStatus();
  }

  return status;
}

import type { DeviceRuntimeRefreshChallenge } from "../types/contracts";

export function deviceRuntimeSigningPayload(challenge: DeviceRuntimeRefreshChallenge): string {
  return [
    "tapchat.device_runtime_auth.v2",
    `purpose=${challenge.purpose}`,
    `runtime_id=${challenge.runtimeId}`,
    `user_id=${challenge.userId}`,
    `device_id=${challenge.deviceId}`,
    `nonce=${challenge.nonce}`,
    `expires_at=${challenge.expiresAt}`
  ].join("\n");
}

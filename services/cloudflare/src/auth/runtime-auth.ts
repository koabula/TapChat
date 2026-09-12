import type { DeviceRuntimeRefreshChallenge } from "../types/contracts";
import { SIGNATURE_DOMAIN, signingPayload } from "./signing-payload";

/**
 * The domain used to be the first line of this string; it now comes from
 * `SIGNATURE_DOMAIN`, so exactly one place names it. Mirrors
 * `DeviceRuntimeRefreshChallenge::signing_payload` in `src/model/mod.rs`.
 */
export function deviceRuntimeSigningPayload(challenge: DeviceRuntimeRefreshChallenge) {
  const body = [
    `purpose=${challenge.purpose}`,
    `runtime_id=${challenge.runtimeId}`,
    `user_id=${challenge.userId}`,
    `device_id=${challenge.deviceId}`,
    `nonce=${challenge.nonce}`,
    `expires_at=${challenge.expiresAt}`
  ].join("\n");
  return signingPayload(SIGNATURE_DOMAIN.deviceRuntimeAuth).pushStr(body).bytes();
}

import type { DurableObject as CloudflareDurableObject } from "cloudflare:workers";

import {
  HttpError,
  verifyDeviceBinding,
  verifyEd25519,
  verifyIdentityBundle
} from "../auth/capability";
import { CONTROL_JSON_MAX_BYTES, readJsonLimited } from "../auth/runtime-security";
import { deviceRuntimeSigningPayload } from "../auth/runtime-auth";
import {
  CURRENT_MODEL_VERSION,
  type DeviceContactProfile,
  type DeviceRegistryRecord,
  type DeviceRuntimeEnrollmentProof,
  type DeviceRuntimeRefreshChallenge,
  type DeviceRuntimeRefreshProof,
  type DeviceRuntimeToken,
  type IdentityBundle
} from "../types/contracts";
import type { Env } from "../types/env";

const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const CHALLENGE_PREFIX = "challenge:";
const DEVICE_PREFIX = "device:";
const MAX_ACTIVE_CHALLENGES = 8;

const DurableObjectBase: typeof CloudflareDurableObject<Env> =
  (globalThis as { DurableObject?: typeof CloudflareDurableObject<Env> }).DurableObject ??
  (class {
    constructor(_state: DurableObjectState, _env: Env) {}
  } as unknown as typeof CloudflareDurableObject<Env>);

function jsonResponse(body: unknown, status = 200): Response {
  return Response.json(body, { status });
}

function runtimeConfig(env: Env): { runtimeId: string; userId: string; userPublicKey: string } {
  const runtimeId = env.RUNTIME_ID?.trim();
  const userId = env.OWNER_USER_ID?.trim();
  const userPublicKey = env.OWNER_USER_PUBLIC_KEY?.trim();
  if (!runtimeId || !userId || !userPublicKey) {
    throw new HttpError(503, "runtime_misconfigured", "runtime owner identity is not configured");
  }
  return { runtimeId, userId, userPublicKey };
}

function challengeKey(nonce: string): string {
  return `${CHALLENGE_PREFIX}${nonce}`;
}

function deviceKey(deviceId: string): string {
  return `${DEVICE_PREFIX}${deviceId}`;
}

function randomNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function bindingHash(device: DeviceContactProfile): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(JSON.stringify(device.binding))
  );
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function assertChallengeScope(
  challenge: DeviceRuntimeRefreshChallenge,
  purpose: DeviceRuntimeRefreshChallenge["purpose"],
  config: ReturnType<typeof runtimeConfig>,
  now: number
): void {
  if (
    challenge.version !== CURRENT_MODEL_VERSION ||
    challenge.purpose !== purpose ||
    challenge.runtimeId !== config.runtimeId ||
    challenge.userId !== config.userId ||
    !challenge.deviceId ||
    !challenge.nonce ||
    challenge.expiresAt <= now
  ) {
    throw new HttpError(403, "runtime_auth_invalid", "runtime authorization challenge is invalid or expired");
  }
}

function sameChallenge(
  stored: DeviceRuntimeRefreshChallenge,
  submitted: DeviceRuntimeRefreshChallenge
): boolean {
  return stored.version === submitted.version
    && stored.purpose === submitted.purpose
    && stored.runtimeId === submitted.runtimeId
    && stored.userId === submitted.userId
    && stored.deviceId === submitted.deviceId
    && stored.nonce === submitted.nonce
    && stored.expiresAt === submitted.expiresAt;
}

export class DeviceRegistryDurableObject extends DurableObjectBase {
  private readonly stateRef: DurableObjectState;
  private readonly envRef: Env;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.stateRef = state;
    this.envRef = env;
  }

  async fetch(request: Request): Promise<Response> {
    try {
      const url = new URL(request.url);
      const now = Date.now();
      if (request.method === "GET" && url.pathname.endsWith("/ready")) {
        return await this.ready();
      }
      if (request.method === "POST" && url.pathname.endsWith("/challenge")) {
        return await this.issueChallenge(request, now);
      }
      if (request.method === "POST" && url.pathname.endsWith("/enroll")) {
        return await this.enroll(request, now);
      }
      if (request.method === "POST" && url.pathname.endsWith("/refresh")) {
        return await this.refresh(request, now);
      }
      if (request.method === "POST" && url.pathname.endsWith("/authorize")) {
        return await this.authorize(request);
      }
      if (request.method === "POST" && url.pathname.endsWith("/sync")) {
        return await this.syncIdentityBundle(request, now);
      }
      return jsonResponse({ error: "not_found" }, 404);
    } catch (error) {
      if (error instanceof HttpError) {
        return jsonResponse({ error: error.code, message: error.message }, error.status);
      }
      return jsonResponse({ error: "temporary_unavailable", message: "device registry request failed" }, 500);
    }
  }

  private async ready(): Promise<Response> {
    const config = runtimeConfig(this.envRef);
    // Touch storage so this endpoint only succeeds once the namespace, class,
    // and backing storage are all available at the serving location.
    await this.stateRef.storage.get("__runtime_registry_ready__");
    return jsonResponse({ ready: true, runtimeId: config.runtimeId });
  }

  private async issueChallenge(request: Request, now: number): Promise<Response> {
    const config = runtimeConfig(this.envRef);
    const body = await readJsonLimited<{
      purpose?: DeviceRuntimeRefreshChallenge["purpose"];
      userId?: string;
      deviceId?: string;
    }>(request, CONTROL_JSON_MAX_BYTES);
    if (
      (body.purpose !== "enroll" && body.purpose !== "refresh") ||
      body.userId !== config.userId ||
      !body.deviceId
    ) {
      throw new HttpError(400, "runtime_auth_invalid", "runtime authorization challenge scope is invalid");
    }
    if (body.purpose === "refresh") {
      const record = await this.stateRef.storage.get<DeviceRegistryRecord>(deviceKey(body.deviceId));
      if (!record) throw new HttpError(403, "enrollment_required", "device is not registered");
      if (record.status !== "active") throw new HttpError(403, "device_revoked", "device is revoked");
    }
    const existing = await this.stateRef.storage.list<DeviceRuntimeRefreshChallenge>({ prefix: CHALLENGE_PREFIX });
    const expired = Array.from(existing.entries())
      .filter(([, challenge]) => challenge.expiresAt <= now)
      .map(([key]) => key);
    if (expired.length) await this.stateRef.storage.delete(expired);
    if (existing.size - expired.length >= MAX_ACTIVE_CHALLENGES) {
      throw new HttpError(429, "rate_limited", "too many active runtime authorization challenges");
    }
    const challenge: DeviceRuntimeRefreshChallenge = {
      version: CURRENT_MODEL_VERSION,
      purpose: body.purpose,
      runtimeId: config.runtimeId,
      userId: config.userId,
      deviceId: body.deviceId,
      nonce: randomNonce(),
      expiresAt: now + CHALLENGE_TTL_MS
    };
    await this.stateRef.storage.put(challengeKey(challenge.nonce), challenge);
    return jsonResponse(challenge);
  }

  private async consumeChallenge(
    challenge: DeviceRuntimeRefreshChallenge,
    purpose: DeviceRuntimeRefreshChallenge["purpose"],
    now: number
  ): Promise<void> {
    const config = runtimeConfig(this.envRef);
    assertChallengeScope(challenge, purpose, config, now);
    const key = challengeKey(challenge.nonce);
    const consumed = await this.stateRef.storage.transaction(async (transaction) => {
      const stored = await transaction.get<DeviceRuntimeRefreshChallenge>(key);
      if (!stored || !sameChallenge(stored, challenge)) return false;
      await transaction.delete(key);
      return true;
    });
    if (!consumed) {
      throw new HttpError(403, "challenge_replayed", "runtime authorization challenge was already consumed");
    }
  }

  private async enroll(request: Request, now: number): Promise<Response> {
    const config = runtimeConfig(this.envRef);
    const proof = await readJsonLimited<DeviceRuntimeEnrollmentProof>(request, CONTROL_JSON_MAX_BYTES);
    const { challenge, device } = proof;
    assertChallengeScope(challenge, "enroll", config, now);
    if (
      !device ||
      device.status !== "active" ||
      device.deviceId !== challenge.deviceId ||
      device.devicePublicKey !== device.binding.devicePublicKey ||
      device.binding.userId !== config.userId ||
      device.binding.deviceId !== device.deviceId ||
      !verifyDeviceBinding(config.userPublicKey, device.binding) ||
      !verifyEd25519(device.devicePublicKey, proof.signature, deviceRuntimeSigningPayload(challenge))
    ) {
      throw new HttpError(403, "runtime_auth_invalid", "device enrollment proof is invalid");
    }
    const key = deviceKey(device.deviceId);
    const hash = await bindingHash(device);
    const existing = await this.stateRef.storage.get<DeviceRegistryRecord>(key);
    if (existing?.status === "revoked") {
      throw new HttpError(403, "device_revoked", "revoked devices cannot be re-enrolled");
    }
    if (existing && (existing.devicePublicKey !== device.devicePublicKey || existing.bindingHash !== hash)) {
      throw new HttpError(403, "runtime_auth_invalid", "registered device identity does not match");
    }
    await this.consumeChallenge(challenge, "enroll", now);
    const record: DeviceRegistryRecord = existing ?? {
      version: CURRENT_MODEL_VERSION,
      runtimeId: config.runtimeId,
      userId: config.userId,
      deviceId: device.deviceId,
      devicePublicKey: device.devicePublicKey,
      bindingHash: hash,
      status: "active",
      registrationVersion: 1,
      createdAt: now,
      updatedAt: now
    };
    await this.stateRef.storage.put(key, { ...record, updatedAt: now });
    return jsonResponse({ registrationVersion: record.registrationVersion });
  }

  private async refresh(request: Request, now: number): Promise<Response> {
    const proof = await readJsonLimited<DeviceRuntimeRefreshProof>(request, CONTROL_JSON_MAX_BYTES);
    const config = runtimeConfig(this.envRef);
    assertChallengeScope(proof.challenge, "refresh", config, now);
    const record = await this.stateRef.storage.get<DeviceRegistryRecord>(deviceKey(proof.challenge.deviceId));
    if (!record) throw new HttpError(403, "enrollment_required", "device is not registered");
    if (record.status !== "active") throw new HttpError(403, "device_revoked", "device is revoked");
    if (!verifyEd25519(record.devicePublicKey, proof.signature, deviceRuntimeSigningPayload(proof.challenge))) {
      throw new HttpError(403, "runtime_auth_invalid", "runtime authorization proof is invalid");
    }
    await this.consumeChallenge(proof.challenge, "refresh", now);
    return jsonResponse({ registrationVersion: record.registrationVersion });
  }

  private async authorize(request: Request): Promise<Response> {
    const token = await readJsonLimited<DeviceRuntimeToken>(request, CONTROL_JSON_MAX_BYTES);
    const config = runtimeConfig(this.envRef);
    if (token.runtimeId !== config.runtimeId || token.userId !== config.userId) {
      throw new HttpError(403, "runtime_mismatch", "runtime token audience does not match this runtime");
    }
    const record = await this.stateRef.storage.get<DeviceRegistryRecord>(deviceKey(token.deviceId));
    if (!record) throw new HttpError(403, "enrollment_required", "device is not registered");
    if (record.status !== "active") throw new HttpError(403, "device_revoked", "device is revoked");
    if (record.registrationVersion !== token.registrationVersion) {
      throw new HttpError(403, "runtime_auth_invalid", "runtime token registration is stale");
    }
    return jsonResponse({ active: true });
  }

  private async syncIdentityBundle(request: Request, now: number): Promise<Response> {
    const bundle = await readJsonLimited<IdentityBundle>(request, CONTROL_JSON_MAX_BYTES);
    const config = runtimeConfig(this.envRef);
    if (
      bundle.userId !== config.userId ||
      bundle.userPublicKey !== config.userPublicKey ||
      !verifyIdentityBundle(bundle)
    ) {
      throw new HttpError(403, "runtime_auth_invalid", "identity bundle does not match runtime owner");
    }
    const changes: Array<{ key: string; record: DeviceRegistryRecord }> = [];
    for (const device of bundle.devices) {
      if (
        device.binding.userId !== config.userId ||
        device.binding.deviceId !== device.deviceId ||
        device.binding.devicePublicKey !== device.devicePublicKey ||
        !verifyDeviceBinding(config.userPublicKey, device.binding)
      ) {
        throw new HttpError(403, "runtime_auth_invalid", "identity bundle contains an invalid device binding");
      }
      const key = deviceKey(device.deviceId);
      const hash = await bindingHash(device);
      const existing = await this.stateRef.storage.get<DeviceRegistryRecord>(key);
      if (existing && (existing.devicePublicKey !== device.devicePublicKey || existing.bindingHash !== hash)) {
        throw new HttpError(403, "runtime_auth_invalid", "identity bundle attempts to replace a registered device key");
      }
      if (existing?.status === "revoked" && device.status === "active") {
        throw new HttpError(403, "device_revoked", "identity bundle attempts to reactivate a revoked device");
      }
      const status = existing?.status === "revoked" || device.status === "revoked" ? "revoked" : "active";
      changes.push({
        key,
        record: {
          version: CURRENT_MODEL_VERSION,
          runtimeId: config.runtimeId,
          userId: config.userId,
          deviceId: device.deviceId,
          devicePublicKey: device.devicePublicKey,
          bindingHash: hash,
          status,
          registrationVersion:
            existing && existing.status !== status
              ? existing.registrationVersion + 1
              : existing?.registrationVersion ?? 1,
          createdAt: existing?.createdAt ?? now,
          updatedAt: now
        }
      });
    }
    await this.stateRef.storage.transaction(async (transaction) => {
      for (const change of changes) await transaction.put(change.key, change.record);
    });
    return jsonResponse({ synchronized: changes.length });
  }
}

export function registryStub(env: Env): DurableObjectStub {
  const runtimeId = runtimeConfig(env).runtimeId;
  return env.DEVICE_REGISTRY.get(env.DEVICE_REGISTRY.idFromName(runtimeId));
}

export async function assertRegisteredRuntimeToken(env: Env, token: DeviceRuntimeToken): Promise<void> {
  const response = await registryStub(env).fetch(
    new Request("https://device-registry.internal/v2/device-registry/authorize", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(token)
    })
  );
  if (!response.ok) {
    const body: { error?: string; message?: string } = await response
      .json<{ error?: string; message?: string }>()
      .catch(() => ({}));
    throw new HttpError(response.status, body.error ?? "runtime_auth_invalid", body.message ?? "device registry rejected token");
  }
}

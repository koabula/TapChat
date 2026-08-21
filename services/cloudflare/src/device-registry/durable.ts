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
import { appErrorBody } from "../errors";

const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const CHALLENGE_PREFIX = "challenge:";
const DEVICE_PREFIX = "device:";
const IDENTITY_BUNDLE_KEY = "identity_bundle:v2";
const MAX_ACTIVE_CHALLENGES = 8;
const KEY_PACKAGE_LIFETIME_MS = 84 * 24 * 60 * 60 * 1000;
const KEY_PACKAGE_NOT_BEFORE_SKEW_MS = 60 * 60 * 1000;
const KEY_PACKAGE_MIN_REMAINING_MS = 7 * 24 * 60 * 60 * 1000;
const CLOCK_TOLERANCE_MS = 5 * 60 * 1000;
const INBOX_CAPABILITY_MAX_LIFETIME_MS = 365 * 24 * 60 * 60 * 1000;

interface StoredIdentityBundle {
  bundle: IdentityBundle;
  etag: string;
}

const DurableObjectBase: typeof CloudflareDurableObject<Env> =
  (globalThis as { DurableObject?: typeof CloudflareDurableObject<Env> }).DurableObject ??
  (class {
    constructor(_state: DurableObjectState, _env: Env) {}
  } as unknown as typeof CloudflareDurableObject<Env>);

function jsonResponse(body: unknown, status = 200): Response {
  return Response.json(body, { status });
}

function errorResponse(status: number, code: string): Response {
  return jsonResponse(appErrorBody(status, code, crypto.randomUUID()), status);
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

async function identityBundleEtag(bundle: IdentityBundle): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(JSON.stringify(bundle))
  );
  const value = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `"${value}"`;
}

function validateIdentityBundleLifecycle(bundle: IdentityBundle, writerDeviceId: string, now: number): void {
  if (bundle.publicationVersion !== 1 || !Number.isSafeInteger(bundle.publicationRevision) || bundle.publicationRevision! < 1) {
    throw new HttpError(426, "upgrade_required", "identity bundle publication protocol is not supported");
  }
  const writer = bundle.devices.find((device) => device.deviceId === writerDeviceId);
  if (!writer || writer.status !== "active") {
    throw new HttpError(403, "device_revoked", "publishing device is not active in the identity bundle");
  }
  for (const device of bundle.devices) {
    const keyPackage = device.keypackageRef;
    if (keyPackage) {
      if (keyPackage.createdAt! > now + CLOCK_TOLERANCE_MS || keyPackage.notBefore! > now + CLOCK_TOLERANCE_MS) {
        throw new HttpError(422, "device_clock_invalid", "key package timestamps are too far in the future");
      }
      const validMetadata = keyPackage.lifecycleVersion === 1
        && Number.isSafeInteger(keyPackage.notBefore)
        && Number.isSafeInteger(keyPackage.createdAt)
        && Number.isSafeInteger(keyPackage.expiresAt)
        && keyPackage.userId === bundle.userId
        && keyPackage.deviceId === device.deviceId
        && keyPackage.expiresAt - keyPackage.createdAt! === KEY_PACKAGE_LIFETIME_MS
        && keyPackage.notBefore === Math.max(0, keyPackage.createdAt! - KEY_PACKAGE_NOT_BEFORE_SKEW_MS);
      if (!validMetadata) {
        throw new HttpError(422, "keypackage_lifetime_invalid", "key package lifecycle metadata is invalid");
      }
      if (keyPackage.expiresAt <= now - CLOCK_TOLERANCE_MS) {
        throw new HttpError(422, "keypackage_expired", "key package is expired");
      }
    }
    const capability = device.inboxAppendCapability;
    if (capability) {
      if (
        capability.userId !== bundle.userId ||
        capability.targetDeviceId !== device.deviceId ||
        capability.expiresAt <= now - CLOCK_TOLERANCE_MS ||
        capability.expiresAt > now + INBOX_CAPABILITY_MAX_LIFETIME_MS + CLOCK_TOLERANCE_MS
      ) {
        throw new HttpError(422, "capability_expired", "inbox append capability lifecycle is invalid");
      }
    }
  }
  if (!writer.keypackageRef || writer.keypackageRef.expiresAt < now + KEY_PACKAGE_MIN_REMAINING_MS) {
    throw new HttpError(422, "keypackage_expired", "publishing device key package has insufficient remaining lifetime");
  }
  if (!writer.inboxAppendCapability || writer.inboxAppendCapability.expiresAt <= now) {
    throw new HttpError(422, "capability_expired", "publishing device inbox append capability is expired");
  }
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
      if (request.method === "GET" && url.pathname.endsWith("/identity-bundle")) {
        return await this.getIdentityBundle();
      }
      if (request.method === "POST" && url.pathname.endsWith("/identity-bundle/migrate")) {
        return await this.migrateIdentityBundle(request, now);
      }
      return errorResponse(404, "not_found");
    } catch (error) {
      if (error instanceof HttpError) {
        return errorResponse(error.status, error.code);
      }
      return errorResponse(500, "temporary_unavailable");
    }
  }

  private async ready(): Promise<Response> {
    const config = runtimeConfig(this.envRef);
    // Touch storage so this endpoint only succeeds once the namespace, class,
    // and backing storage are all available at the serving location.
    await this.stateRef.storage.get("__runtime_registry_ready__");
    return jsonResponse({
      ready: true,
      runtimeId: config.runtimeId,
      protocolVersion: 5,
      workerBuildId: this.envRef.WORKER_BUILD_ID?.trim() || "tapchat-worker-v5-unknown",
      registrySchemaVersion: 2
    });
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
    const body = await readJsonLimited<{
      bundle?: IdentityBundle;
      expectedEtag?: string;
      writerDeviceId?: string;
    }>(request, CONTROL_JSON_MAX_BYTES);
    const bundle = body.bundle;
    if (!bundle || !body.writerDeviceId) {
      throw new HttpError(426, "upgrade_required", "structured identity publication is required");
    }
    const config = runtimeConfig(this.envRef);
    validateIdentityBundleLifecycle(bundle, body.writerDeviceId, now);
    if (
      bundle.userId !== config.userId ||
      bundle.userPublicKey !== config.userPublicKey ||
      !verifyIdentityBundle(bundle)
    ) {
      throw new HttpError(403, "runtime_auth_invalid", "identity bundle does not match runtime owner");
    }
    const preparedDevices: Array<{ device: DeviceContactProfile; key: string; hash: string }> = [];
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
      preparedDevices.push({ device, key, hash });
    }
    const etag = await identityBundleEtag(bundle);
    await this.stateRef.storage.transaction(async (transaction) => {
      const stored = await transaction.get<StoredIdentityBundle>(IDENTITY_BUNDLE_KEY);
      if (stored) {
        if (!body.expectedEtag || body.expectedEtag !== stored.etag) {
          throw new HttpError(412, "identity_bundle_conflict", "identity bundle ETag does not match");
        }
        if ((bundle.publicationRevision ?? 0) <= (stored.bundle.publicationRevision ?? 0)) {
          throw new HttpError(412, "identity_bundle_conflict", "identity bundle revision is not newer");
        }
      } else if (body.expectedEtag && body.expectedEtag !== "*") {
        throw new HttpError(412, "identity_bundle_conflict", "identity bundle does not exist at the expected ETag");
      }
      for (const prepared of preparedDevices) {
        const existing = await transaction.get<DeviceRegistryRecord>(prepared.key);
        if (existing && (existing.devicePublicKey !== prepared.device.devicePublicKey || existing.bindingHash !== prepared.hash)) {
          throw new HttpError(403, "runtime_auth_invalid", "identity bundle attempts to replace a registered device key");
        }
        if (existing?.status === "revoked" && prepared.device.status === "active") {
          throw new HttpError(403, "device_revoked", "identity bundle attempts to reactivate a revoked device");
        }
        const status = existing?.status === "revoked" || prepared.device.status === "revoked" ? "revoked" : "active";
        await transaction.put(prepared.key, {
          version: CURRENT_MODEL_VERSION,
          runtimeId: config.runtimeId,
          userId: config.userId,
          deviceId: prepared.device.deviceId,
          devicePublicKey: prepared.device.devicePublicKey,
          bindingHash: prepared.hash,
          status,
          registrationVersion:
            existing && existing.status !== status
              ? existing.registrationVersion + 1
              : existing?.registrationVersion ?? 1,
          createdAt: existing?.createdAt ?? now,
          updatedAt: now
        } satisfies DeviceRegistryRecord);
      }
      await transaction.put(IDENTITY_BUNDLE_KEY, { bundle, etag } satisfies StoredIdentityBundle);
    });
    const response = jsonResponse(bundle);
    response.headers.set("etag", etag);
    return response;
  }

  private async getIdentityBundle(): Promise<Response> {
    const stored = await this.stateRef.storage.get<StoredIdentityBundle>(IDENTITY_BUNDLE_KEY);
    if (!stored) return errorResponse(404, "not_found");
    const response = jsonResponse(stored.bundle);
    response.headers.set("etag", stored.etag);
    return response;
  }

  private async migrateIdentityBundle(request: Request, now: number): Promise<Response> {
    const body = await readJsonLimited<{ bundle?: IdentityBundle }>(request, CONTROL_JSON_MAX_BYTES);
    const bundle = body.bundle;
    const config = runtimeConfig(this.envRef);
    if (
      !bundle ||
      bundle.userId !== config.userId ||
      bundle.userPublicKey !== config.userPublicKey ||
      !verifyIdentityBundle(bundle)
    ) {
      throw new HttpError(403, "runtime_auth_invalid", "legacy identity bundle is invalid");
    }
    const preparedDevices: Array<{ device: DeviceContactProfile; key: string; hash: string }> = [];
    for (const device of bundle.devices) {
      if (
        device.binding.userId !== config.userId ||
        device.binding.deviceId !== device.deviceId ||
        device.binding.devicePublicKey !== device.devicePublicKey ||
        !verifyDeviceBinding(config.userPublicKey, device.binding)
      ) {
        throw new HttpError(403, "runtime_auth_invalid", "legacy identity bundle contains an invalid device binding");
      }
      preparedDevices.push({
        device,
        key: deviceKey(device.deviceId),
        hash: await bindingHash(device)
      });
    }
    const etag = await identityBundleEtag(bundle);
    const stored = await this.stateRef.storage.transaction(async (transaction) => {
      const existingBundle = await transaction.get<StoredIdentityBundle>(IDENTITY_BUNDLE_KEY);
      if (existingBundle) return existingBundle;
      for (const prepared of preparedDevices) {
        const existing = await transaction.get<DeviceRegistryRecord>(prepared.key);
        if (
          existing &&
          (existing.devicePublicKey !== prepared.device.devicePublicKey || existing.bindingHash !== prepared.hash)
        ) {
          throw new HttpError(403, "runtime_auth_invalid", "legacy identity bundle conflicts with a registered device");
        }
        if (!existing) {
          await transaction.put(prepared.key, {
            version: CURRENT_MODEL_VERSION,
            runtimeId: config.runtimeId,
            userId: config.userId,
            deviceId: prepared.device.deviceId,
            devicePublicKey: prepared.device.devicePublicKey,
            bindingHash: prepared.hash,
            status: prepared.device.status,
            registrationVersion: 1,
            createdAt: now,
            updatedAt: now
          } satisfies DeviceRegistryRecord);
        }
      }
      const migrated = { bundle, etag } satisfies StoredIdentityBundle;
      await transaction.put(IDENTITY_BUNDLE_KEY, migrated);
      return migrated;
    });
    const response = jsonResponse(stored.bundle);
    response.headers.set("etag", stored.etag);
    return response;
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
    const body: { code?: string } = await response
      .json<{ code?: string }>()
      .catch(() => ({}));
    const code = body.code ?? "runtime_auth_invalid";
    throw new HttpError(response.status, code, code);
  }
}

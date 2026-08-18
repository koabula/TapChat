import {
  HttpError,
  APPEND_AUTH_CONTEXT_HEADER,
  validateAnyDeviceRuntimeAuthorization,
  validateAppendAuthorization,
  validateDeviceRuntimeAuthorizationForDevice,
  validateKeyPackageWriteAuthorization,
  validateSharedStateWriteAuthorization,
  validateWelcomePickupAuthorization
} from "../auth/capability";
import {
  CONTROL_JSON_MAX_BYTES,
  DEFAULT_MESSAGE_REQUEST_MAX_BODY_BYTES,
  readJsonLimited,
  readRequestTextLimited,
  requireDeviceRuntimeSecrets,
  requireSharingSecret
} from "../auth/runtime-security";
import { signSharingPayload, verifySharingPayload } from "../storage/sharing";
import { SharedStateService } from "../storage/shared-state";
import { StorageService } from "../storage/service";
import { WelcomePickupService } from "../welcome-pickup/service";
import {
  CURRENT_MODEL_VERSION,
  type AllowlistDocument,
  type AppendGroupEnvelopeRequest,
  type AppendEnvelopeRequest,
  type DeploymentBundle,
  type DeviceRuntimeAuth,
  type DeviceRuntimeEnrollmentProof,
  type DeviceRuntimeRefreshProof,
  type DeviceRuntimeScope,
  type DeviceRuntimeToken,
  type DeviceStatusDocument,
  type GroupInviteTokenPayload,
  type IdentityBundle,
  type KeyPackageRefsDocument,
  type PrepareBlobUploadRequest,
  type PutWelcomePickupRequest,
  type WelcomePickupDescriptor
} from "../types/contracts";
import { appErrorBody } from "../errors";
import type { Env } from "../types/env";
import { assertRegisteredRuntimeToken, registryStub } from "../device-registry/durable";

function versionedBody(body: unknown): unknown {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return body;
  }
  const record = body as Record<string, unknown>;
  if (record.version !== undefined) {
    return body;
  }
  return {
    version: CURRENT_MODEL_VERSION,
    ...record
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(versionedBody(body)), {
    status,
    headers: {
      "content-type": "application/json"
    }
  });
}

function structuredErrorResponse(
  request: Request,
  status: number,
  code: string,
  retryable?: boolean
): Response {
  const correlationId = request.headers.get("cf-ray") ?? crypto.randomUUID();
  return jsonResponse(appErrorBody(status, code, correlationId, retryable), status);
}

function forwardRequestWithBody(request: Request, body: string): Request {
  return new Request(request.url, {
    method: request.method,
    headers: new Headers(request.headers),
    body
  });
}

class R2JsonBlobStore {
  private readonly bucket: Env["TAPCHAT_STORAGE"];

  constructor(bucket: Env["TAPCHAT_STORAGE"]) {
    this.bucket = bucket;
  }

  async putJson<T>(key: string, value: T): Promise<void> {
    await this.bucket.put(key, JSON.stringify(value));
  }

  async getJson<T>(key: string): Promise<T | null> {
    const object = await this.bucket.get(key);
    if (!object) {
      return null;
    }
    return await object.json<T>();
  }

  async putBytes(key: string, value: ArrayBuffer | Uint8Array, metadata?: Record<string, string>): Promise<void> {
    await this.bucket.put(key, value, metadata ? { customMetadata: metadata } : undefined);
  }

  async getBytes(key: string): Promise<ArrayBuffer | null> {
    const object = await this.bucket.get(key);
    if (!object) {
      return null;
    }
    return object.arrayBuffer();
  }

  async getBytesMetadata(key: string): Promise<{ bytes: ArrayBuffer; customMetadata: Record<string, string> } | null> {
    const object = await this.bucket.get(key);
    if (!object) return null;
    return {
      bytes: await object.arrayBuffer(),
      customMetadata: object.customMetadata ?? {}
    };
  }

  async putStream(
    key: string,
    value: ReadableStream,
    metadata?: Record<string, string>,
  ): Promise<{ size: number }> {
    const object = await this.bucket.put(
      key,
      value,
      metadata ? { customMetadata: metadata } : undefined,
    );
    return { size: object.size };
  }

  async headBytes(key: string): Promise<{
    size: number;
    customMetadata: Record<string, string>;
    httpEtag?: string;
  } | null> {
    const object = await this.bucket.head(key);
    if (!object) return null;
    return {
      size: object.size,
      customMetadata: object.customMetadata ?? {},
      ...(object.httpEtag ? { httpEtag: object.httpEtag } : {}),
    };
  }

  async getStream(
    key: string,
    range?: { offset: number; length: number },
  ): Promise<{
    body: ReadableStream;
    size: number;
    customMetadata: Record<string, string>;
    httpEtag?: string;
  } | null> {
    const object = await this.bucket.get(key, range ? { range } : undefined);
    if (!object) return null;
    return {
      body: object.body,
      size: object.size,
      customMetadata: object.customMetadata ?? {},
      ...(object.httpEtag ? { httpEtag: object.httpEtag } : {}),
    };
  }

  async delete(key: string): Promise<void> {
    await this.bucket.delete(key);
  }
}

function baseUrl(request: Request, env: Env): string {
  return env.PUBLIC_BASE_URL?.trim().replace(/\/+$/, "") ?? new URL(request.url).origin;
}

function sharedStateSecret(env: Env): string {
  return requireSharingSecret(env);
}

function deviceRuntimeSecrets(env: Env) {
  return requireDeviceRuntimeSecrets(env);
}

function messageRequestBodyLimit(env: Env): number {
  const configured = Number(env.MESSAGE_REQUEST_MAX_BODY_BYTES ?? DEFAULT_MESSAGE_REQUEST_MAX_BODY_BYTES);
  return Number.isSafeInteger(configured) && configured > 0
    ? configured
    : DEFAULT_MESSAGE_REQUEST_MAX_BODY_BYTES;
}

function runtimeScopes(): DeviceRuntimeAuth["scopes"] {
  return [
    "inbox_read",
    "inbox_ack",
    "inbox_subscribe",
    "inbox_manage",
    "group_authorization_bootstrap",
    "storage_prepare_upload",
    "shared_state_write",
    "keypackage_write"
  ];
}

function runtimeIdentity(env: Env): { runtimeId: string; userId: string; userPublicKey: string } {
  const runtimeId = env.RUNTIME_ID?.trim();
  const userId = env.OWNER_USER_ID?.trim();
  const userPublicKey = env.OWNER_USER_PUBLIC_KEY?.trim();
  if (!runtimeId || !userId || !userPublicKey) {
    throw new HttpError(503, "runtime_misconfigured", "runtime owner identity is not configured");
  }
  return { runtimeId, userId, userPublicKey };
}

async function authoritativeIdentityBundle(
  env: Env,
  sharedState: SharedStateService
): Promise<IdentityBundle | null> {
  const { userId } = runtimeIdentity(env);
  const registry = registryStub(env);
  const authoritative = await registry.fetch(
    new Request("https://device-registry.internal/v2/device-registry/identity-bundle")
  );
  if (authoritative.ok) {
    return await authoritative.json<IdentityBundle>();
  }
  if (authoritative.status !== 404) {
    const error = await authoritative
      .json<{ code?: string }>()
      .catch((): { code?: string } => ({}));
    throw new HttpError(
      authoritative.status,
      error.code ?? "temporary_unavailable",
      "authoritative identity lookup failed"
    );
  }

  const legacyBundle = await sharedState.getIdentityBundle(userId);
  if (!legacyBundle) return null;
  const migrated = await registry.fetch(
    new Request("https://device-registry.internal/v2/device-registry/identity-bundle/migrate", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ bundle: legacyBundle })
    })
  );
  if (!migrated.ok) {
    const error = await migrated
      .json<{ code?: string }>()
      .catch((): { code?: string } => ({}));
    throw new HttpError(
      migrated.status,
      error.code ?? "temporary_unavailable",
      "legacy identity migration failed"
    );
  }
  return await migrated.json<IdentityBundle>();
}

async function issueDeviceRuntimeAuth(
  env: Env,
  userId: string,
  deviceId: string,
  registrationVersion: number,
  now: number
): Promise<DeviceRuntimeAuth> {
  const { runtimeId } = runtimeIdentity(env);
  const expiresAt = now + 24 * 60 * 60 * 1000;
  const scopes = runtimeScopes();
  const signingKey = deviceRuntimeSecrets(env).current;
  const token = await signSharingPayload(signingKey.secret, {
    version: CURRENT_MODEL_VERSION,
    service: "device_runtime",
    runtimeId,
    userId,
    deviceId,
    scopes,
    issuedAt: now,
    expiresAt,
    registrationVersion,
    ...(signingKey.keyId ? { keyId: signingKey.keyId } : {})
  });
  return {
    scheme: "bearer",
    token,
    issuedAt: now,
    expiresAt,
    runtimeId,
    userId,
    deviceId,
    scopes,
    registrationVersion,
    keyId: signingKey.keyId
  };
}

function publicDeploymentBundle(request: Request, env: Env): DeploymentBundle {
  const { runtimeId } = runtimeIdentity(env);
  return {
    version: CURRENT_MODEL_VERSION,
    runtimeId,
    protocolVersion: 5,
    workerBuildId: env.WORKER_BUILD_ID?.trim() || "tapchat-worker-v5-unknown",
    registrySchemaVersion: 2,
    region: env.DEPLOYMENT_REGION ?? "local",
    inboxHttpEndpoint: baseUrl(request, env),
    inboxWebsocketEndpoint: `${baseUrl(request, env).replace(/^http/i, "ws")}/v1/inbox/{deviceId}/subscribe`,
    storageBaseInfo: {
      baseUrl: baseUrl(request, env),
      bucketHint: "tapchat-storage"
    },
    runtimeConfig: {
      supportedRealtimeKinds: ["websocket"],
      identityBundleRef: `${baseUrl(request, env)}/v1/shared-state/{userId}/identity-bundle`,
      deviceStatusRef: `${baseUrl(request, env)}/v1/shared-state/{userId}/device-status`,
      keypackageRefBase: `${baseUrl(request, env)}/v1/shared-state/keypackages`,
      maxInlineBytes: Number(env.MAX_INLINE_BYTES ?? "4096"),
      features: [
        "generic_sync",
        "attachment_v2",
        "message_requests",
        "allowlist",
        "rate_limit",
        "group_outbox_mvp",
        "welcome_pickup_mvp",
        "short_group_invite",
        "group_member_subscribe",
        "group_authorization_v2",
        "group_membership_fsm_v2",
        "runtime_secret_rotation_v1",
        "device_runtime_refresh_v2",
        "device_registry_v1",
        "keypackage_lifecycle_v1",
        "identity_bundle_cas_v1",
        "structured_errors_v1"
      ]
    }
  };
}

async function validateRegisteredRuntimeAuthorization(
  request: Request,
  env: Env,
  scope: DeviceRuntimeScope,
  now: number
): Promise<DeviceRuntimeToken> {
  const token = await validateAnyDeviceRuntimeAuthorization(request, deviceRuntimeSecrets(env), scope, now);
  if (token.runtimeId !== runtimeIdentity(env).runtimeId) {
    throw new HttpError(403, "runtime_mismatch", "runtime token audience does not match this runtime");
  }
  await assertRegisteredRuntimeToken(env, token);
  return token;
}

async function validateRegisteredRuntimeAuthorizationForDevice(
  request: Request,
  env: Env,
  deviceId: string,
  scope: DeviceRuntimeScope,
  now: number
): Promise<DeviceRuntimeToken> {
  const token = await validateDeviceRuntimeAuthorizationForDevice(
    request,
    deviceRuntimeSecrets(env),
    deviceId,
    scope,
    now
  );
  if (token.runtimeId !== runtimeIdentity(env).runtimeId) {
    throw new HttpError(403, "runtime_mismatch", "runtime token audience does not match this runtime");
  }
  await assertRegisteredRuntimeToken(env, token);
  return token;
}

async function authorizeSharedStateWrite(
  request: Request,
  env: Env,
  userId: string,
  objectKind: "identity_bundle" | "device_status",
  now: number
): Promise<DeviceRuntimeToken> {
  try {
    const auth = await validateRegisteredRuntimeAuthorization(request, env, "shared_state_write", now);
    if (auth.userId !== userId) {
      throw new HttpError(403, "invalid_capability", "device runtime token scope does not match request path");
    }
    return auth;
  } catch (error) {
    if (
      !(error instanceof HttpError) ||
      error.code === "runtime_auth_expired" ||
      error.code === "device_revoked" ||
      error.code === "runtime_mismatch" ||
      error.code === "enrollment_required"
    ) {
      throw error;
    }
  }
  await validateSharedStateWriteAuthorization(request, sharedStateSecret(env), userId, "", objectKind, now);
  throw new HttpError(426, "upgrade_required", "device runtime authorization is required for shared-state writes");
}

export async function handleRequest(request: Request, env: Env): Promise<Response> {
  try {
    const url = new URL(request.url);
    const sharingSecret = sharedStateSecret(env);
    const runtimeSecret = deviceRuntimeSecrets(env).current.secret;
    if (env.DEVICE_RUNTIME_SECRET?.trim() && runtimeSecret === sharingSecret) {
      throw new HttpError(503, "runtime_misconfigured", "device runtime secret must use an independent value");
    }
    const store = new StorageService(
      new R2JsonBlobStore(env.TAPCHAT_STORAGE),
      baseUrl(request, env),
      sharingSecret,
      Number(env.RETENTION_DAYS ?? "30")
    );
    const sharedState = new SharedStateService(new R2JsonBlobStore(env.TAPCHAT_STORAGE), baseUrl(request, env));
    const welcomePickup = new WelcomePickupService(new R2JsonBlobStore(env.TAPCHAT_STORAGE));
    const now = Date.now();

    if (request.method === "GET" && url.pathname === "/v1/deployment-bundle") {
      return jsonResponse(publicDeploymentBundle(request, env));
    }

    if (request.method === "GET" && url.pathname === "/v2/runtime/ready") {
      try {
        return await registryStub(env).fetch(
          new Request("https://device-registry.internal/v2/device-registry/ready")
        );
      } catch {
        return structuredErrorResponse(request, 503, "temporary_unavailable", true);
      }
    }

    const contactShareMatch = url.pathname.match(/^\/v1\/contact-share\/([^/]+)$/);
    if (contactShareMatch && request.method === "GET") {
      type ContactSharePayload = {
        version?: string;
        service?: string;
        userId?: string;
        shareId?: string;
        expiresAt?: number;
      };
      const token = decodeURIComponent(contactShareMatch[1]);
      const payload = await verifySharingPayload<ContactSharePayload>(sharedStateSecret(env), token, now);
      if (payload.service !== "contact_share" || !payload.userId || !payload.shareId) {
        throw new HttpError(403, "invalid_capability", "invalid contact share token");
      }
      const bundle = await authoritativeIdentityBundle(env, sharedState);
      if (
        !bundle ||
        bundle.userId !== payload.userId ||
        bundle.bundleShareId !== payload.shareId
      ) {
        throw new HttpError(404, "contact_share_revoked", "contact share not found");
      }
      return jsonResponse(bundle);
    }

    if (request.method === "POST" && url.pathname === "/v2/runtime-auth/challenge") {
      const bodyText = await readRequestTextLimited(request, CONTROL_JSON_MAX_BYTES);
      const body = JSON.parse(bodyText) as { purpose?: "enroll" | "refresh"; userId?: string; deviceId?: string };
      if ((body.purpose !== "enroll" && body.purpose !== "refresh") || !body.userId || !body.deviceId) {
        throw new HttpError(400, "runtime_auth_invalid", "purpose, userId and deviceId are required");
      }
      try {
        return await registryStub(env).fetch(new Request("https://device-registry.internal/v2/device-registry/challenge", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: bodyText
        }));
      } catch {
        return structuredErrorResponse(request, 503, "temporary_unavailable", true);
      }
    }

    if (request.method === "POST" && url.pathname === "/v2/runtime-auth/enroll") {
      const bodyText = await readRequestTextLimited(request, CONTROL_JSON_MAX_BYTES);
      const proof = JSON.parse(bodyText) as DeviceRuntimeEnrollmentProof;
      const deviceId = proof.challenge?.deviceId;
      const userId = proof.challenge?.userId;
      if (!deviceId || !userId) {
        throw new HttpError(400, "runtime_auth_invalid", "enrollment proof scope is required");
      }
      const verified = await registryStub(env).fetch(new Request("https://device-registry.internal/v2/device-registry/enroll", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: bodyText
      }));
      if (!verified.ok) return verified;
      const result = await verified.json<{ registrationVersion: number }>();
      return jsonResponse({ runtimeCredential: await issueDeviceRuntimeAuth(env, userId, deviceId, result.registrationVersion, now) });
    }

    if (request.method === "POST" && url.pathname === "/v2/runtime-auth/refresh") {
      const bodyText = await readRequestTextLimited(request, CONTROL_JSON_MAX_BYTES);
      const proof = JSON.parse(bodyText) as DeviceRuntimeRefreshProof;
      const deviceId = proof.challenge?.deviceId;
      const userId = proof.challenge?.userId;
      if (!deviceId || !userId) {
        throw new HttpError(400, "runtime_auth_invalid", "refresh proof scope is required");
      }
      const verified = await registryStub(env).fetch(new Request("https://device-registry.internal/v2/device-registry/refresh", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: bodyText
      }));
      if (!verified.ok) return verified;
      const result = await verified.json<{ registrationVersion: number }>();
      return jsonResponse({ runtimeCredential: await issueDeviceRuntimeAuth(env, userId, deviceId, result.registrationVersion, now) });
    }

    const inboxMatch = url.pathname.match(/^\/v1\/inbox\/([^/]+)\/(messages|ack|head|subscribe|allowlist|message-requests(?:\/[^/]+\/(?:accept|reject))?)$/);
    if (inboxMatch) {
      const deviceId = decodeURIComponent(inboxMatch[1]);
      const operation = inboxMatch[2];
      const objectId = env.INBOX.idFromName(deviceId);
      const stub = env.INBOX.get(objectId);

      if (request.method === "POST" && operation === "messages") {
        const bodyText = await readRequestTextLimited(request, messageRequestBodyLimit(env));
        const body = JSON.parse(bodyText) as AppendEnvelopeRequest;
        const appendAuth = await validateAppendAuthorization(
          request,
          deviceId,
          body,
          now,
          () => authoritativeIdentityBundle(env, sharedState)
        );
        const forwarded = forwardRequestWithBody(request, bodyText);
        forwarded.headers.set(APPEND_AUTH_CONTEXT_HEADER, appendAuth.mode);
        return await stub.fetch(forwarded);
      } else if (request.method === "GET" && (operation === "messages" || operation === "head")) {
        await validateRegisteredRuntimeAuthorizationForDevice(request, env, deviceId, "inbox_read", now);
      } else if (request.method === "POST" && operation === "ack") {
        await validateRegisteredRuntimeAuthorizationForDevice(request, env, deviceId, "inbox_ack", now);
      } else if (operation === "subscribe") {
        await validateRegisteredRuntimeAuthorizationForDevice(request, env, deviceId, "inbox_subscribe", now);
      } else if (
        operation === "allowlist" ||
        operation === "message-requests" ||
        operation.startsWith("message-requests/")
      ) {
        await validateRegisteredRuntimeAuthorizationForDevice(request, env, deviceId, "inbox_manage", now);
      }

      if (request.method !== "GET" && request.method !== "HEAD") {
        const bodyText = await readRequestTextLimited(request, CONTROL_JSON_MAX_BYTES);
        return await stub.fetch(forwardRequestWithBody(request, bodyText));
      }
      return await stub.fetch(request);
    }

    const groupOutboxMatch = url.pathname.match(/^\/v1\/groups\/([^/]+)\/outbox\/(messages|transitions|head|seal|subscribe)$/);
    if (groupOutboxMatch) {
      const groupId = decodeURIComponent(groupOutboxMatch[1]);
      const operation = groupOutboxMatch[2];
      const objectId = env.GROUP_OUTBOX.idFromName(groupId);
      const stub = env.GROUP_OUTBOX.get(objectId);

      if (request.method === "POST" && (operation === "messages" || operation === "transitions")) {
        const bodyText = await readRequestTextLimited(request, messageRequestBodyLimit(env));
        return await stub.fetch(forwardRequestWithBody(request, bodyText));
      }

      if (request.method !== "GET" && request.method !== "HEAD") {
        const bodyText = await readRequestTextLimited(request, CONTROL_JSON_MAX_BYTES);
        return await stub.fetch(forwardRequestWithBody(request, bodyText));
      }
      return await stub.fetch(request);
    }

    const groupAuthorizationMatch = url.pathname.match(/^\/v1\/groups\/([^/]+)\/authorization\/bootstrap$/);
    if (groupAuthorizationMatch && request.method === "POST") {
      const groupId = decodeURIComponent(groupAuthorizationMatch[1]);
      const objectId = env.GROUP_OUTBOX.idFromName(groupId);
      const bodyText = await readRequestTextLimited(request, CONTROL_JSON_MAX_BYTES);
      return await env.GROUP_OUTBOX.get(objectId).fetch(forwardRequestWithBody(request, bodyText));
    }

    const groupAuthorizationStateMatch = url.pathname.match(/^\/v1\/groups\/([^/]+)\/authorization\/state$/);
    if (groupAuthorizationStateMatch && request.method === "GET") {
      const groupId = decodeURIComponent(groupAuthorizationStateMatch[1]);
      const objectId = env.GROUP_OUTBOX.idFromName(groupId);
      return env.GROUP_OUTBOX.get(objectId).fetch(request);
    }

    const shortPublicInviteMatch = url.pathname.match(/^\/v1\/group-invite\/([^/]+)\/([^/]+)$/);
    if (shortPublicInviteMatch && request.method === "GET") {
      const groupId = decodeURIComponent(shortPublicInviteMatch[1]);
      const objectId = env.GROUP_OUTBOX.idFromName(groupId);
      return env.GROUP_OUTBOX.get(objectId).fetch(request);
    }

    const publicInviteMatch = url.pathname.match(/^\/v1\/group-invite\/([^/]+)$/);
    if (publicInviteMatch && request.method === "GET") {
      let payload: GroupInviteTokenPayload;
      try {
        payload = await verifySharingPayload<GroupInviteTokenPayload>(
          sharedStateSecret(env),
          decodeURIComponent(publicInviteMatch[1]),
          now
        );
      } catch (error) {
        const message = error instanceof Error ? error.message : "invalid group invite token";
        throw new HttpError(message.includes("expired") ? 403 : 403, message.includes("expired") ? "capability_expired" : "invalid_capability", message);
      }
      if (payload.service !== "group_invite" || !payload.groupId || !payload.inviteId) {
        throw new HttpError(403, "invalid_capability", "group invite token is malformed");
      }
      const objectId = env.GROUP_OUTBOX.idFromName(payload.groupId);
      return env.GROUP_OUTBOX.get(objectId).fetch(request);
    }

    const groupInviteMatch = url.pathname.match(/^\/v1\/groups\/([^/]+)\/invites(?:\/([^/]+)\/revoke)?$/);
    if (groupInviteMatch && (request.method === "POST" || (request.method === "GET" && !groupInviteMatch[2]))) {
      const groupId = decodeURIComponent(groupInviteMatch[1]);
      const objectId = env.GROUP_OUTBOX.idFromName(groupId);
      if (request.method === "POST") {
        const bodyText = await readRequestTextLimited(request, CONTROL_JSON_MAX_BYTES);
        return await env.GROUP_OUTBOX.get(objectId).fetch(forwardRequestWithBody(request, bodyText));
      }
      return env.GROUP_OUTBOX.get(objectId).fetch(request);
    }

    const joinCollectionMatch = url.pathname.match(/^\/v1\/groups\/([^/]+)\/join-requests$/);
    if (joinCollectionMatch) {
      const groupId = decodeURIComponent(joinCollectionMatch[1]);
      if (request.method === "POST") {
        const token = request.headers.get("Authorization")?.replace(/^Bearer\s+/i, "").trim();
        if (!token) {
          throw new HttpError(401, "invalid_capability", "missing group invite bearer token");
        }
        let payload: GroupInviteTokenPayload;
        try {
          payload = await verifySharingPayload<GroupInviteTokenPayload>(sharedStateSecret(env), token, now);
        } catch (error) {
          const message = error instanceof Error ? error.message : "invalid group invite token";
          throw new HttpError(
            message.includes("expired") ? 403 : 403,
            message.includes("expired") ? "capability_expired" : "invalid_capability",
            message
          );
        }
        if (payload.service !== "group_invite" || payload.groupId !== groupId) {
          throw new HttpError(403, "invalid_capability", "group invite token scope does not match request");
        }
      }
      const objectId = env.GROUP_OUTBOX.idFromName(groupId);
      if (request.method === "POST") {
        const bodyText = await readRequestTextLimited(request, CONTROL_JSON_MAX_BYTES);
        return await env.GROUP_OUTBOX.get(objectId).fetch(forwardRequestWithBody(request, bodyText));
      }
      return await env.GROUP_OUTBOX.get(objectId).fetch(request);
    }

    const joinDecisionMatch = url.pathname.match(/^\/v1\/groups\/([^/]+)\/join-requests\/([^/]+)\/decision$/);
    if (joinDecisionMatch && request.method === "POST") {
      const groupId = decodeURIComponent(joinDecisionMatch[1]);
      const bodyText = await readRequestTextLimited(request, CONTROL_JSON_MAX_BYTES);
      const objectId = env.GROUP_OUTBOX.idFromName(groupId);
      return await env.GROUP_OUTBOX.get(objectId).fetch(forwardRequestWithBody(request, bodyText));
    }

    const joinLeaseMatch = url.pathname.match(/^\/v1\/groups\/([^/]+)\/join-requests\/([^/]+)\/(claim|complete)$/);
    if (joinLeaseMatch && request.method === "POST") {
      const groupId = decodeURIComponent(joinLeaseMatch[1]);
      const bodyText = await readRequestTextLimited(request, CONTROL_JSON_MAX_BYTES);
      const objectId = env.GROUP_OUTBOX.idFromName(groupId);
      return await env.GROUP_OUTBOX.get(objectId).fetch(forwardRequestWithBody(request, bodyText));
    }

    const joinStatusMatch = url.pathname.match(/^\/v1\/groups\/([^/]+)\/join-requests\/([^/]+)$/);
    if (joinStatusMatch && request.method === "GET") {
      const groupId = decodeURIComponent(joinStatusMatch[1]);
      const objectId = env.GROUP_OUTBOX.idFromName(groupId);
      return env.GROUP_OUTBOX.get(objectId).fetch(request);
    }

    const leaveRequestMatch = url.pathname.match(/^\/v1\/groups\/([^/]+)\/leave-requests(?:\/([^/]+)\/claim)?$/);
    if (leaveRequestMatch && (request.method === "GET" || request.method === "POST")) {
      const groupId = decodeURIComponent(leaveRequestMatch[1]);
      const objectId = env.GROUP_OUTBOX.idFromName(groupId);
      if (request.method === "POST") {
        const bodyText = await readRequestTextLimited(request, CONTROL_JSON_MAX_BYTES);
        return await env.GROUP_OUTBOX.get(objectId).fetch(forwardRequestWithBody(request, bodyText));
      }
      return env.GROUP_OUTBOX.get(objectId).fetch(request);
    }

    const welcomePickupMatch = url.pathname.match(/^\/v1\/groups\/([^/]+)\/welcome-pickup\/([^/]+)$/);
    if (welcomePickupMatch) {
      const groupId = decodeURIComponent(welcomePickupMatch[1]);
      const deviceId = decodeURIComponent(welcomePickupMatch[2]);
      if (request.method === "PUT") {
        const body = await readJsonLimited<PutWelcomePickupRequest>(request, messageRequestBodyLimit(env));
        validateWelcomePickupAuthorization(request, groupId, deviceId, body.descriptor, now);
        if (body.descriptor.requestId) {
          const authorized = await env.GROUP_OUTBOX.get(env.GROUP_OUTBOX.idFromName(groupId)).fetch(
            new Request(`${url.origin}/v1/groups/${encodeURIComponent(groupId)}/internal/welcome-authorize`, {
              method: "POST",
              headers: { "Content-Type": "application/json", "X-Tapchat-Internal-Secret": sharingSecret },
              body: JSON.stringify({ deviceId, requestId: body.descriptor.requestId, capability: body.descriptor.capability })
            })
          );
          if (!authorized.ok) throw new HttpError(409, "group_transition_invalid", "welcome upload is not authorized by a committed join transition");
        }
        return jsonResponse(await welcomePickup.put(body, now));
      }
      if (request.method === "GET") {
        const encoded = request.headers.get("X-Tapchat-Welcome-Pickup");
        if (!encoded) {
          throw new HttpError(401, "invalid_capability", "missing X-Tapchat-Welcome-Pickup header");
        }
        let descriptor: WelcomePickupDescriptor;
        try {
          descriptor = JSON.parse(encoded) as WelcomePickupDescriptor;
        } catch {
          throw new HttpError(400, "invalid_capability", "X-Tapchat-Welcome-Pickup is not valid JSON");
        }
        validateWelcomePickupAuthorization(request, groupId, deviceId, descriptor, now);
        const result = await welcomePickup.fetch(descriptor, now);
        if (descriptor.requestId) {
          const objectId = env.GROUP_OUTBOX.idFromName(groupId);
          const marked = await env.GROUP_OUTBOX.get(objectId).fetch(
            new Request(`${url.origin}/v1/groups/${encodeURIComponent(groupId)}/internal/welcome-claimed`, {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                "X-Tapchat-Internal-Secret": sharingSecret
              },
              body: JSON.stringify({ deviceId, requestId: descriptor.requestId, capability: descriptor.capability })
            })
          );
          if (!marked.ok) {
            throw new HttpError(500, "temporary_unavailable", "failed to finalize joined group state");
          }
        }
        return jsonResponse(result);
      }
    }

    const identityBundleMatch = url.pathname.match(/^\/v1\/shared-state\/([^/]+)\/identity-bundle$/);
    if (identityBundleMatch) {
      const userId = decodeURIComponent(identityBundleMatch[1]);
      if (request.method === "GET") {
        const authoritative = await registryStub(env).fetch(
          new Request("https://device-registry.internal/v2/device-registry/identity-bundle")
        );
        if (authoritative.ok) return authoritative;
        if (authoritative.status !== 404) return authoritative;
        const legacyBundle = await sharedState.getIdentityBundle(userId);
        if (!legacyBundle) throw new HttpError(404, "not_found", "identity bundle not found");
        return registryStub(env).fetch(
          new Request("https://device-registry.internal/v2/device-registry/identity-bundle/migrate", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ bundle: legacyBundle })
          })
        );
      }
      if (request.method === "PUT") {
        const authorization = await authorizeSharedStateWrite(request, env, userId, "identity_bundle", now);
        const body = await readJsonLimited<IdentityBundle>(request, CONTROL_JSON_MAX_BYTES);
        const synchronized = await registryStub(env).fetch(new Request("https://device-registry.internal/v2/device-registry/sync", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            bundle: body,
            expectedEtag: request.headers.get("If-Match") ?? undefined,
            writerDeviceId: authorization.deviceId
          })
        }));
        if (!synchronized.ok) return synchronized;
        const saved = await synchronized.clone().json<IdentityBundle>();
        await sharedState.putIdentityBundle(userId, saved).catch(() => undefined);
        return synchronized;
      }
    }

    const deviceStatusMatch = url.pathname.match(/^\/v1\/shared-state\/([^/]+)\/device-status$/);
    if (deviceStatusMatch) {
      const userId = decodeURIComponent(deviceStatusMatch[1]);
      if (request.method === "GET") {
        const document = await sharedState.getDeviceStatus(userId);
        if (!document) {
          return structuredErrorResponse(request, 404, "not_found", false);
        }
        return jsonResponse(document);
      }
      if (request.method === "PUT") {
        await authorizeSharedStateWrite(request, env, userId, "device_status", now);
        const body = await readJsonLimited<DeviceStatusDocument>(request, CONTROL_JSON_MAX_BYTES);
        await sharedState.putDeviceStatus(userId, body);
        const saved = await sharedState.getDeviceStatus(userId);
        return jsonResponse(saved);
      }
    }

    const deviceListMatch = url.pathname.match(/^\/v1\/shared-state\/([^/]+)\/device-list$/);
    if (deviceListMatch && request.method === "GET") {
      const userId = decodeURIComponent(deviceListMatch[1]);
      const document = await sharedState.getDeviceList(userId);
      if (!document) {
        return structuredErrorResponse(request, 404, "not_found", false);
      }
      return jsonResponse(document);
    }

    const keyPackageRefsMatch = url.pathname.match(/^\/v1\/shared-state\/keypackages\/([^/]+)\/([^/]+)$/);
    if (keyPackageRefsMatch) {
      const userId = decodeURIComponent(keyPackageRefsMatch[1]);
      const deviceId = decodeURIComponent(keyPackageRefsMatch[2]);
      if (request.method === "GET") {
        const document = await sharedState.getKeyPackageRefs(userId, deviceId);
        if (!document) {
          return structuredErrorResponse(request, 404, "not_found", false);
        }
        return jsonResponse(document);
      }
      if (request.method === "PUT") {
        const authorization = await validateKeyPackageWriteAuthorization(
          request,
          deviceRuntimeSecrets(env),
          userId,
          deviceId,
          undefined,
          now,
          sharedStateSecret(env)
        );
        if (authorization.service === "device_runtime") await assertRegisteredRuntimeToken(env, authorization);
        const body = await readJsonLimited<KeyPackageRefsDocument>(request, CONTROL_JSON_MAX_BYTES);
        await sharedState.putKeyPackageRefs(userId, deviceId, body);
        const saved = await sharedState.getKeyPackageRefs(userId, deviceId);
        return jsonResponse(saved);
      }
    }

    const keyPackageObjectMatch = url.pathname.match(/^\/v1\/shared-state\/keypackages\/([^/]+)\/([^/]+)\/([^/]+)$/);
    if (keyPackageObjectMatch) {
      const userId = decodeURIComponent(keyPackageObjectMatch[1]);
      const deviceId = decodeURIComponent(keyPackageObjectMatch[2]);
      const keyPackageId = decodeURIComponent(keyPackageObjectMatch[3]);
      if (request.method === "GET") {
        const payload = await sharedState.getKeyPackageObject(userId, deviceId, keyPackageId);
        if (!payload) {
          return structuredErrorResponse(request, 404, "not_found", false);
        }
        return new Response(payload, {
          status: 200,
          headers: {
            "content-type": "application/octet-stream"
          }
        });
      }
      if (request.method === "PUT") {
        const authorization = await validateKeyPackageWriteAuthorization(
          request,
          deviceRuntimeSecrets(env),
          userId,
          deviceId,
          keyPackageId,
          now,
          sharedStateSecret(env)
        );
        if (authorization.service === "device_runtime") await assertRegisteredRuntimeToken(env, authorization);
        await sharedState.putKeyPackageObject(userId, deviceId, keyPackageId, await request.arrayBuffer());
        return new Response(null, { status: 204 });
      }
    }

    if (request.method === "POST" && url.pathname === "/v1/storage/prepare-upload") {
      const auth = await validateRegisteredRuntimeAuthorization(request, env, "storage_prepare_upload", now);
      const body = await readJsonLimited<PrepareBlobUploadRequest>(request, CONTROL_JSON_MAX_BYTES);
      const result = await store.prepareUpload(body, { userId: auth.userId, deviceId: auth.deviceId }, now);
      return jsonResponse(result);
    }

    const uploadMatch = url.pathname.match(/^\/v1\/storage\/upload\/(.+)$/);
    if (request.method === "PUT" && uploadMatch) {
      const blobKey = decodeURIComponent(uploadMatch[1]);
      const token = url.searchParams.get("token");
      if (!token) {
        throw new HttpError(401, "invalid_capability", "missing upload token");
      }
      const contentLengthHeader = request.headers.get("Content-Length");
      const contentLength = contentLengthHeader && /^\d+$/.test(contentLengthHeader)
        ? Number(contentLengthHeader)
        : Number.NaN;
      if (!Number.isSafeInteger(contentLength) || contentLength <= 0 || !request.body) {
        throw new HttpError(400, "invalid_input", "valid Content-Length and upload body are required");
      }
      await store.uploadBlob(blobKey, token, request.body, contentLength, now);
      return new Response(null, { status: 204 });
    }

    const blobMatch = url.pathname.match(/^\/v1\/storage\/blob\/(.+)$/);
    if ((request.method === "GET" || request.method === "HEAD") && blobMatch) {
      const blobKey = decodeURIComponent(blobMatch[1]);
      const header = request.headers.get("Authorization")?.trim();
      if (!header?.startsWith("TapChat-Blob ")) {
        throw new HttpError(401, "invalid_capability", "missing blob capability");
      }
      const capability = header.slice("TapChat-Blob ".length).trim();
      const payload = await store.fetchBlob(
        blobKey,
        capability,
        request.headers.get("Range") ?? undefined,
        request.method === "GET",
        now,
      );
      const headers = new Headers({
        "content-type": "application/octet-stream",
        "accept-ranges": "bytes",
        "content-length": String(payload.contentLength),
      });
      if (payload.httpEtag) headers.set("etag", payload.httpEtag);
      if (payload.range) {
        headers.set(
          "content-range",
          `bytes ${payload.range.offset}-${payload.range.offset + payload.range.length - 1}/${payload.size}`,
        );
      }
      return new Response(payload.body, {
        status: payload.range ? 206 : 200,
        headers,
      });
    }
    if (request.method === "DELETE" && blobMatch) {
      const blobKey = decodeURIComponent(blobMatch[1]);
      const header = request.headers.get("Authorization")?.trim();
      if (!header?.startsWith("TapChat-Delete ")) {
        throw new HttpError(401, "invalid_capability", "missing blob delete capability");
      }
      await store.deleteBlob(blobKey, header.slice("TapChat-Delete ".length).trim());
      return new Response(null, { status: 204 });
    }

    return structuredErrorResponse(request, 404, "not_found", false);
  } catch (error) {
    if (error instanceof HttpError) {
      const response = structuredErrorResponse(request, error.status, error.code);
      if (error.status === 416 && typeof error.details?.totalSize === "number") {
        response.headers.set("accept-ranges", "bytes");
        response.headers.set("content-range", `bytes */${error.details.totalSize}`);
      }
      return response;
    }
    return structuredErrorResponse(request, 500, "temporary_unavailable", true);
  }
}

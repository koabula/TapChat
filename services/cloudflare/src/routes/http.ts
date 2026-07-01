import {
  HttpError,
  APPEND_AUTH_CONTEXT_HEADER,
  APPEND_AUTH_REASON_HEADER,
  readGroupCapabilityHeader,
  validateAnyDeviceRuntimeAuthorization,
  validateAppendAuthorization,
  validateBootstrapAuthorization,
  validateDeviceRuntimeAuthorizationForDevice,
  validateGroupAppendAuthorization,
  validateGroupOperationAuthorization,
  validateGroupReadAuthorization,
  validateKeyPackageWriteAuthorization,
  validateSharedStateWriteAuthorization,
  validateWelcomePickupAuthorization
} from "../auth/capability";
import { signSharingPayload, verifySharingPayload } from "../storage/sharing";
import { SharedStateService } from "../storage/shared-state";
import { StorageService } from "../storage/service";
import { WelcomePickupService } from "../welcome-pickup/service";
import {
  CURRENT_MODEL_VERSION,
  type AllowlistDocument,
  type AppendGroupEnvelopeRequest,
  type AppendEnvelopeRequest,
  type AuthorizeBlobDownloadRequest,
  type BootstrapDeviceRequest,
  type DeploymentBundle,
  type DeviceRuntimeAuth,
  type DeviceStatusDocument,
  type GroupCapability,
  type GroupInviteTokenPayload,
  type IdentityBundle,
  type KeyPackageRefsDocument,
  type PrepareBlobUploadRequest,
  type PutWelcomePickupRequest,
  type WelcomePickupDescriptor
} from "../types/contracts";
import type { Env } from "../types/runtime";

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
    await this.bucket.put(key, value, metadata ? { httpMetadata: metadata } : undefined);
  }

  async getBytes(key: string): Promise<ArrayBuffer | null> {
    const object = await this.bucket.get(key);
    if (!object) {
      return null;
    }
    return object.arrayBuffer();
  }

  async delete(key: string): Promise<void> {
    await this.bucket.delete(key);
  }
}

function baseUrl(request: Request, env: Env): string {
  return env.PUBLIC_BASE_URL?.trim().replace(/\/+$/, "") ?? new URL(request.url).origin;
}

function sharedStateSecret(env: Env): string {
  return env.SHARING_TOKEN_SECRET ?? "replace-me";
}

function downloadGrantTtlDays(env: Env): number {
  const raw = env.ATTACHMENT_DOWNLOAD_GRANT_TTL_DAYS?.trim();
  if (!raw) {
    return 365;
  }
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? parsed : 365;
}

function bootstrapSecret(env: Env): string {
  return env.BOOTSTRAP_TOKEN_SECRET ?? env.SHARING_TOKEN_SECRET ?? "replace-me";
}

function runtimeScopes(): DeviceRuntimeAuth["scopes"] {
  return [
    "inbox_read",
    "inbox_ack",
    "inbox_subscribe",
    "inbox_manage",
    "storage_prepare_upload",
    "shared_state_write",
    "keypackage_write"
  ];
}

async function issueDeviceRuntimeAuth(env: Env, userId: string, deviceId: string, now: number): Promise<DeviceRuntimeAuth> {
  const expiresAt = now + 24 * 60 * 60 * 1000;
  const scopes = runtimeScopes();
  const token = await signSharingPayload(sharedStateSecret(env), {
    version: CURRENT_MODEL_VERSION,
    service: "device_runtime",
    userId,
    deviceId,
    scopes,
    expiresAt
  });
  return {
    scheme: "bearer",
    token,
    expiresAt,
    userId,
    deviceId,
    scopes
  };
}

function publicDeploymentBundle(request: Request, env: Env): DeploymentBundle {
  return {
    version: CURRENT_MODEL_VERSION,
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
        "attachment_v1",
        "message_requests",
        "allowlist",
        "rate_limit",
        "group_outbox_mvp",
        "welcome_pickup_mvp",
        "short_group_invite",
        "group_member_subscribe"
      ]
    }
  };
}

async function authorizeSharedStateWrite(
  request: Request,
  env: Env,
  userId: string,
  objectKind: "identity_bundle" | "device_status",
  now: number
): Promise<void> {
  try {
    const auth = await validateAnyDeviceRuntimeAuthorization(request, sharedStateSecret(env), "shared_state_write", now);
    if (auth.userId !== userId) {
      throw new HttpError(403, "invalid_capability", "device runtime token scope does not match request path");
    }
    return;
  } catch (error) {
    if (!(error instanceof HttpError) || error.code === "capability_expired") {
      throw error;
    }
  }
  await validateSharedStateWriteAuthorization(request, sharedStateSecret(env), userId, "", objectKind, now);
}

export async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const store = new StorageService(
    new R2JsonBlobStore(env.TAPCHAT_STORAGE),
    baseUrl(request, env),
    sharedStateSecret(env),
    downloadGrantTtlDays(env)
  );
  const sharedState = new SharedStateService(new R2JsonBlobStore(env.TAPCHAT_STORAGE), baseUrl(request, env));
  const welcomePickup = new WelcomePickupService(new R2JsonBlobStore(env.TAPCHAT_STORAGE));
  const now = Date.now();

  try {
    if (request.method === "GET" && url.pathname === "/v1/deployment-bundle") {
      return jsonResponse(publicDeploymentBundle(request, env));
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
      const bundle = await sharedState.getIdentityBundle(payload.userId);
      if (!bundle || bundle.bundleShareId !== payload.shareId) {
        return jsonResponse({ error: "not_found", message: "contact share not found" }, 404);
      }
      return jsonResponse(bundle);
    }

    if (request.method === "POST" && url.pathname === "/v1/bootstrap/device") {
      const body = (await request.json()) as BootstrapDeviceRequest;
      if (body.version !== CURRENT_MODEL_VERSION) {
        throw new HttpError(400, "unsupported_version", "bootstrap request version is not supported");
      }
      await validateBootstrapAuthorization(request, bootstrapSecret(env), body.userId, body.deviceId, now);
      const bundle: DeploymentBundle = {
        ...publicDeploymentBundle(request, env),
        deviceRuntimeAuth: await issueDeviceRuntimeAuth(env, body.userId, body.deviceId, now),
        expectedUserId: body.userId,
        expectedDeviceId: body.deviceId
      };
      return jsonResponse(bundle);
    }

    const inboxMatch = url.pathname.match(/^\/v1\/inbox\/([^/]+)\/(messages|ack|head|subscribe|allowlist|message-requests(?:\/[^/]+\/(?:accept|reject))?)$/);
    if (inboxMatch) {
      const deviceId = decodeURIComponent(inboxMatch[1]);
      const operation = inboxMatch[2];
      const objectId = env.INBOX.idFromName(deviceId);
      const stub = env.INBOX.get(objectId);

      if (request.method === "POST" && operation === "messages") {
        const bodyText = await request.text();
        const body = JSON.parse(bodyText) as AppendEnvelopeRequest;
        const appendAuth = await validateAppendAuthorization(request, deviceId, body, now, sharedState);
        const forwarded = forwardRequestWithBody(request, bodyText);
        forwarded.headers.set(APPEND_AUTH_CONTEXT_HEADER, appendAuth.mode);
        if (appendAuth.reason) {
          forwarded.headers.set(APPEND_AUTH_REASON_HEADER, appendAuth.reason);
        }
        return await stub.fetch(forwarded);
      } else if (request.method === "GET" && (operation === "messages" || operation === "head")) {
        await validateDeviceRuntimeAuthorizationForDevice(request, sharedStateSecret(env), deviceId, "inbox_read", now);
      } else if (request.method === "POST" && operation === "ack") {
        await validateDeviceRuntimeAuthorizationForDevice(request, sharedStateSecret(env), deviceId, "inbox_ack", now);
      } else if (operation === "subscribe") {
        await validateDeviceRuntimeAuthorizationForDevice(request, sharedStateSecret(env), deviceId, "inbox_subscribe", now);
      } else if (
        operation === "allowlist" ||
        operation === "message-requests" ||
        operation.startsWith("message-requests/")
      ) {
        await validateDeviceRuntimeAuthorizationForDevice(request, sharedStateSecret(env), deviceId, "inbox_manage", now);
      }

      return stub.fetch(request);
    }

    const groupOutboxMatch = url.pathname.match(/^\/v1\/groups\/([^/]+)\/outbox\/(messages|head|seal|subscribe)$/);
    if (groupOutboxMatch) {
      const groupId = decodeURIComponent(groupOutboxMatch[1]);
      const operation = groupOutboxMatch[2];
      const objectId = env.GROUP_OUTBOX.idFromName(groupId);
      const stub = env.GROUP_OUTBOX.get(objectId);

      if (request.method === "POST" && operation === "messages") {
        const bodyText = await request.text();
        const body = JSON.parse(bodyText) as AppendGroupEnvelopeRequest;
        validateGroupAppendAuthorization(request, groupId, body, now);
        return await stub.fetch(forwardRequestWithBody(request, bodyText));
      } else if (request.method === "POST" && operation === "seal") {
        // Owner-only seal capability check happens twice: once at the
        // worker boundary (here) to fail fast before we wake up the
        // durable object, and once inside the durable object so that
        // the storage-side invariant is never bypassed.
        validateGroupOperationAuthorization(
          request,
          groupId,
          readGroupCapabilityHeader(request),
          now,
          "seal_group",
          ["owner"]
        );
      } else if (request.method === "GET" && (operation === "messages" || operation === "head")) {
        validateGroupReadAuthorization(request, groupId, readGroupCapabilityHeader(request), now);
      } else if (operation === "subscribe") {
        validateGroupOperationAuthorization(
          request,
          groupId,
          readGroupCapabilityHeader(request),
          now,
          "subscribe",
          ["owner", "admin", "member"]
        );
      }

      return stub.fetch(request);
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
    if (groupInviteMatch && request.method === "POST") {
      const groupId = decodeURIComponent(groupInviteMatch[1]);
      const bodyText = await request.text();
      const body = JSON.parse(bodyText) as { capability?: GroupCapability };
      validateGroupOperationAuthorization(request, groupId, body.capability as GroupCapability, now, "manage_invites");
      const objectId = env.GROUP_OUTBOX.idFromName(groupId);
      return await env.GROUP_OUTBOX.get(objectId).fetch(forwardRequestWithBody(request, bodyText));
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
      } else if (request.method === "GET") {
        validateGroupOperationAuthorization(request, groupId, readGroupCapabilityHeader(request), now, "approve_join");
      }
      const objectId = env.GROUP_OUTBOX.idFromName(groupId);
      return env.GROUP_OUTBOX.get(objectId).fetch(request);
    }

    const joinDecisionMatch = url.pathname.match(/^\/v1\/groups\/([^/]+)\/join-requests\/([^/]+)\/decision$/);
    if (joinDecisionMatch && request.method === "POST") {
      const groupId = decodeURIComponent(joinDecisionMatch[1]);
      const bodyText = await request.text();
      const body = JSON.parse(bodyText) as { capability?: GroupCapability };
      validateGroupOperationAuthorization(request, groupId, body.capability as GroupCapability, now, "approve_join");
      const objectId = env.GROUP_OUTBOX.idFromName(groupId);
      return await env.GROUP_OUTBOX.get(objectId).fetch(forwardRequestWithBody(request, bodyText));
    }

    const joinStatusMatch = url.pathname.match(/^\/v1\/groups\/([^/]+)\/join-requests\/([^/]+)$/);
    if (joinStatusMatch && request.method === "GET") {
      const groupId = decodeURIComponent(joinStatusMatch[1]);
      const objectId = env.GROUP_OUTBOX.idFromName(groupId);
      return env.GROUP_OUTBOX.get(objectId).fetch(request);
    }

    const welcomePickupMatch = url.pathname.match(/^\/v1\/groups\/([^/]+)\/welcome-pickup\/([^/]+)$/);
    if (welcomePickupMatch) {
      const groupId = decodeURIComponent(welcomePickupMatch[1]);
      const deviceId = decodeURIComponent(welcomePickupMatch[2]);
      if (request.method === "PUT") {
        const body = (await request.json()) as PutWelcomePickupRequest;
        validateWelcomePickupAuthorization(request, groupId, deviceId, body.descriptor, now);
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
        return jsonResponse(await welcomePickup.fetch(descriptor, now));
      }
    }

    const identityBundleMatch = url.pathname.match(/^\/v1\/shared-state\/([^/]+)\/identity-bundle$/);
    if (identityBundleMatch) {
      const userId = decodeURIComponent(identityBundleMatch[1]);
      if (request.method === "GET") {
        const bundle = await sharedState.getIdentityBundle(userId);
        if (!bundle) {
          return jsonResponse({ error: "not_found", message: "identity bundle not found" }, 404);
        }
        return jsonResponse(bundle);
      }
      if (request.method === "PUT") {
        await authorizeSharedStateWrite(request, env, userId, "identity_bundle", now);
        const body = (await request.json()) as IdentityBundle;
        await sharedState.putIdentityBundle(userId, body);
        const saved = await sharedState.getIdentityBundle(userId);
        return jsonResponse(saved);
      }
    }

    const deviceStatusMatch = url.pathname.match(/^\/v1\/shared-state\/([^/]+)\/device-status$/);
    if (deviceStatusMatch) {
      const userId = decodeURIComponent(deviceStatusMatch[1]);
      if (request.method === "GET") {
        const document = await sharedState.getDeviceStatus(userId);
        if (!document) {
          return jsonResponse({ error: "not_found", message: "device status not found" }, 404);
        }
        return jsonResponse(document);
      }
      if (request.method === "PUT") {
        await authorizeSharedStateWrite(request, env, userId, "device_status", now);
        const body = (await request.json()) as DeviceStatusDocument;
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
        return jsonResponse({ error: "not_found", message: "device list not found" }, 404);
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
          return jsonResponse({ error: "not_found", message: "keypackage refs not found" }, 404);
        }
        return jsonResponse(document);
      }
      if (request.method === "PUT") {
        await validateKeyPackageWriteAuthorization(request, sharedStateSecret(env), userId, deviceId, undefined, now);
        const body = (await request.json()) as KeyPackageRefsDocument;
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
          return jsonResponse({ error: "not_found", message: "keypackage not found" }, 404);
        }
        return new Response(payload, {
          status: 200,
          headers: {
            "content-type": "application/octet-stream"
          }
        });
      }
      if (request.method === "PUT") {
        await validateKeyPackageWriteAuthorization(request, sharedStateSecret(env), userId, deviceId, keyPackageId, now);
        await sharedState.putKeyPackageObject(userId, deviceId, keyPackageId, await request.arrayBuffer());
        return new Response(null, { status: 204 });
      }
    }

    if (request.method === "POST" && url.pathname === "/v1/storage/prepare-upload") {
      const auth = await validateAnyDeviceRuntimeAuthorization(request, sharedStateSecret(env), "storage_prepare_upload", now);
      const body = (await request.json()) as PrepareBlobUploadRequest;
      const result = await store.prepareUpload(body, { userId: auth.userId, deviceId: auth.deviceId }, now);
      return jsonResponse(result);
    }

    if (request.method === "POST" && url.pathname === "/v1/storage/authorize-download") {
      const header = request.headers.get("Authorization")?.trim();
      if (!header?.startsWith("Bearer ")) {
        throw new HttpError(401, "invalid_capability", "missing download refresh grant");
      }
      const token = header.slice("Bearer ".length).trim();
      if (!token) {
        throw new HttpError(401, "invalid_capability", "download refresh grant must not be empty");
      }
      const body = (await request.json()) as AuthorizeBlobDownloadRequest;
      if (body.version !== CURRENT_MODEL_VERSION) {
        throw new HttpError(400, "unsupported_version", "authorize download version is not supported");
      }
      return jsonResponse(await store.authorizeDownload(body.blobRef, token, now));
    }

    const uploadMatch = url.pathname.match(/^\/v1\/storage\/upload\/(.+)$/);
    if (request.method === "PUT" && uploadMatch) {
      const blobKey = decodeURIComponent(uploadMatch[1]);
      const token = url.searchParams.get("token");
      if (!token) {
        throw new HttpError(401, "invalid_capability", "missing upload token");
      }
      const contentType = request.headers.get("content-type") ?? "application/octet-stream";
      await store.uploadBlob(blobKey, token, await request.arrayBuffer(), { "content-type": contentType }, now);
      return new Response(null, { status: 204 });
    }

    const blobMatch = url.pathname.match(/^\/v1\/storage\/blob\/(.+)$/);
    if (request.method === "GET" && blobMatch) {
      const blobKey = decodeURIComponent(blobMatch[1]);
      const token = url.searchParams.get("token");
      if (!token) {
        throw new HttpError(401, "invalid_capability", "missing download token");
      }
      const payload = await store.fetchBlob(blobKey, token, now);
      return new Response(payload, {
        status: 200,
        headers: {
          "content-type": "application/octet-stream"
        }
      });
    }

    return jsonResponse({ error: "not_found", message: "route not found" }, 404);
  } catch (error) {
    if (error instanceof HttpError) {
      return jsonResponse({ error: error.code, message: error.message }, error.status);
    }
    const runtimeError = error as { message?: string };
    const message = runtimeError.message ?? "internal error";
    return jsonResponse({ error: "temporary_unavailable", message }, 500);
  }
}

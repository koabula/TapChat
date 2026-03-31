var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/types/contracts.ts
var CURRENT_MODEL_VERSION = "0.1";

// src/storage/sharing.ts
var encoder = new TextEncoder();
function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
__name(toBase64Url, "toBase64Url");
function fromBase64Url(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  const binary = atob(padded);
  const output = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    output[i] = binary.charCodeAt(i);
  }
  return output;
}
__name(fromBase64Url, "fromBase64Url");
async function importSecret(secret) {
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}
__name(importSecret, "importSecret");
async function signSharingPayload(secret, payload) {
  const encodedPayload = encoder.encode(JSON.stringify(payload));
  const key = await importSecret(secret);
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, encodedPayload));
  return `${toBase64Url(encodedPayload)}.${toBase64Url(signature)}`;
}
__name(signSharingPayload, "signSharingPayload");
async function verifySharingPayload(secret, token, now) {
  const [payloadPart, signaturePart] = token.split(".");
  if (!payloadPart || !signaturePart) {
    throw new Error("invalid sharing token");
  }
  const payloadBytes = fromBase64Url(payloadPart);
  const signatureBytes = fromBase64Url(signaturePart);
  const key = await importSecret(secret);
  const payloadBuffer = payloadBytes.buffer.slice(
    payloadBytes.byteOffset,
    payloadBytes.byteOffset + payloadBytes.byteLength
  );
  const signatureBuffer = signatureBytes.buffer.slice(
    signatureBytes.byteOffset,
    signatureBytes.byteOffset + signatureBytes.byteLength
  );
  const valid = await crypto.subtle.verify("HMAC", key, signatureBuffer, payloadBuffer);
  if (!valid) {
    throw new Error("invalid sharing token");
  }
  const payload = JSON.parse(new TextDecoder().decode(payloadBytes));
  if (payload.expiresAt !== void 0 && payload.expiresAt <= now) {
    throw new Error("sharing token expired");
  }
  return payload;
}
__name(verifySharingPayload, "verifySharingPayload");

// src/auth/capability.ts
var HttpError = class extends Error {
  static {
    __name(this, "HttpError");
  }
  status;
  code;
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
};
function getBearerToken(request) {
  const header = request.headers.get("Authorization")?.trim();
  if (!header) {
    throw new HttpError(401, "invalid_capability", "missing Authorization header");
  }
  if (!header.startsWith("Bearer ")) {
    throw new HttpError(401, "invalid_capability", "Authorization header must use Bearer token");
  }
  const token = header.slice("Bearer ".length).trim();
  if (!token) {
    throw new HttpError(401, "invalid_capability", "Bearer token must not be empty");
  }
  return token;
}
__name(getBearerToken, "getBearerToken");
function validateAppendAuthorization(request, deviceId, body, now) {
  const signature = getBearerToken(request);
  const capabilityHeader = request.headers.get("X-Tapchat-Capability");
  if (!capabilityHeader) {
    throw new HttpError(401, "invalid_capability", "missing X-Tapchat-Capability header");
  }
  let capability;
  try {
    capability = JSON.parse(capabilityHeader);
  } catch {
    throw new HttpError(400, "invalid_capability", "X-Tapchat-Capability is not valid JSON");
  }
  if (body.version !== CURRENT_MODEL_VERSION || capability.version !== CURRENT_MODEL_VERSION) {
    throw new HttpError(400, "unsupported_version", "append capability version is not supported");
  }
  if (capability.signature !== signature) {
    throw new HttpError(403, "invalid_capability", "capability signature does not match bearer token");
  }
  if (capability.service !== "inbox") {
    throw new HttpError(403, "invalid_capability", "capability service must be inbox");
  }
  if (!capability.operations.includes("append")) {
    throw new HttpError(403, "invalid_capability", "capability does not grant append");
  }
  if (capability.targetDeviceId !== deviceId) {
    throw new HttpError(403, "invalid_capability", "capability target device does not match request path");
  }
  const requestUrl = new URL(request.url);
  if (capability.endpoint !== `${requestUrl.origin}${requestUrl.pathname}`) {
    throw new HttpError(403, "invalid_capability", "capability endpoint does not match request path");
  }
  if (capability.expiresAt <= now) {
    throw new HttpError(403, "capability_expired", "append capability is expired");
  }
  if (body.recipientDeviceId !== deviceId || body.envelope.recipientDeviceId !== deviceId) {
    throw new HttpError(403, "invalid_capability", "recipient device does not match target inbox");
  }
  if (capability.conversationScope?.length && !capability.conversationScope.includes(body.envelope.conversationId)) {
    throw new HttpError(403, "invalid_capability", "conversation is outside capability scope");
  }
  const size = new TextEncoder().encode(JSON.stringify(body.envelope)).byteLength;
  if (capability.constraints?.maxBytes !== void 0 && size > capability.constraints.maxBytes) {
    throw new HttpError(413, "payload_too_large", "envelope exceeds capability size limit");
  }
}
__name(validateAppendAuthorization, "validateAppendAuthorization");
async function verifySignedToken(secret, request, now) {
  const token = getBearerToken(request);
  try {
    return await verifySharingPayload(secret, token, now);
  } catch (error) {
    const message = error instanceof Error ? error.message : "invalid signed token";
    if (message.includes("expired")) {
      throw new HttpError(403, "capability_expired", message);
    }
    throw new HttpError(403, "invalid_capability", message);
  }
}
__name(verifySignedToken, "verifySignedToken");
async function verifyDeviceRuntimeToken(request, secret, now) {
  const token = await verifySignedToken(secret, request, now);
  if (token.version !== CURRENT_MODEL_VERSION) {
    throw new HttpError(400, "unsupported_version", "device runtime token version is not supported");
  }
  if (token.service !== "device_runtime") {
    throw new HttpError(403, "invalid_capability", "token service must be device_runtime");
  }
  if (!token.userId || !token.deviceId || !token.scopes.length) {
    throw new HttpError(403, "invalid_capability", "device runtime token is malformed");
  }
  return token;
}
__name(verifyDeviceRuntimeToken, "verifyDeviceRuntimeToken");
async function validateBootstrapAuthorization(request, secret, userId, deviceId, now) {
  const token = await verifySignedToken(secret, request, now);
  if (token.version !== CURRENT_MODEL_VERSION) {
    throw new HttpError(400, "unsupported_version", "bootstrap token version is not supported");
  }
  if (token.service !== "bootstrap") {
    throw new HttpError(403, "invalid_capability", "token service must be bootstrap");
  }
  if (token.userId !== userId || token.deviceId !== deviceId) {
    throw new HttpError(403, "invalid_capability", "bootstrap token scope does not match request");
  }
  if (!token.operations.includes("issue_device_bundle")) {
    throw new HttpError(403, "invalid_capability", "bootstrap token does not grant device bundle issuance");
  }
  return token;
}
__name(validateBootstrapAuthorization, "validateBootstrapAuthorization");
async function validateAnyDeviceRuntimeAuthorization(request, secret, scope, now) {
  const token = await verifyDeviceRuntimeToken(request, secret, now);
  if (!token.scopes.includes(scope)) {
    throw new HttpError(403, "invalid_capability", `device runtime token does not grant ${scope}`);
  }
  return token;
}
__name(validateAnyDeviceRuntimeAuthorization, "validateAnyDeviceRuntimeAuthorization");
async function validateDeviceRuntimeAuthorization(request, secret, userId, deviceId, scope, now) {
  const token = await validateAnyDeviceRuntimeAuthorization(request, secret, scope, now);
  if (token.userId !== userId || token.deviceId !== deviceId) {
    throw new HttpError(403, "invalid_capability", "device runtime token scope does not match request path");
  }
  return token;
}
__name(validateDeviceRuntimeAuthorization, "validateDeviceRuntimeAuthorization");
async function validateDeviceRuntimeAuthorizationForDevice(request, secret, deviceId, scope, now) {
  const token = await validateAnyDeviceRuntimeAuthorization(request, secret, scope, now);
  if (token.deviceId !== deviceId) {
    throw new HttpError(403, "invalid_capability", "device runtime token scope does not match request path");
  }
  return token;
}
__name(validateDeviceRuntimeAuthorizationForDevice, "validateDeviceRuntimeAuthorizationForDevice");
async function validateSharedStateWriteAuthorization(request, secret, userId, deviceId, objectKind, now) {
  try {
    return await validateDeviceRuntimeAuthorization(request, secret, userId, deviceId, "shared_state_write", now);
  } catch (error) {
    if (!(error instanceof HttpError) || error.code === "capability_expired") {
      throw error;
    }
  }
  const token = await verifySignedToken(secret, request, now);
  if (token.version !== CURRENT_MODEL_VERSION) {
    throw new HttpError(400, "unsupported_version", "shared-state token version is not supported");
  }
  if (token.service !== "shared_state") {
    throw new HttpError(403, "invalid_capability", "token service must be shared_state");
  }
  if (token.userId !== userId) {
    throw new HttpError(403, "invalid_capability", "token userId does not match request path");
  }
  if (!token.objectKinds.includes(objectKind)) {
    throw new HttpError(403, "invalid_capability", "token does not grant this shared-state object kind");
  }
  return token;
}
__name(validateSharedStateWriteAuthorization, "validateSharedStateWriteAuthorization");
async function validateKeyPackageWriteAuthorization(request, secret, userId, deviceId, keyPackageId, now) {
  try {
    return await validateDeviceRuntimeAuthorization(request, secret, userId, deviceId, "keypackage_write", now);
  } catch (error) {
    if (!(error instanceof HttpError) || error.code === "capability_expired") {
      throw error;
    }
  }
  const token = await verifySignedToken(secret, request, now);
  if (token.version !== CURRENT_MODEL_VERSION) {
    throw new HttpError(400, "unsupported_version", "keypackage token version is not supported");
  }
  if (token.service !== "keypackages") {
    throw new HttpError(403, "invalid_capability", "token service must be keypackages");
  }
  if (token.userId !== userId || token.deviceId !== deviceId) {
    throw new HttpError(403, "invalid_capability", "token scope does not match request path");
  }
  if (token.keyPackageId && token.keyPackageId !== keyPackageId) {
    throw new HttpError(403, "invalid_capability", "token keyPackageId does not match request path");
  }
  return token;
}
__name(validateKeyPackageWriteAuthorization, "validateKeyPackageWriteAuthorization");

// src/inbox/service.ts
var META_KEY = "meta";
var IDEMPOTENCY_PREFIX = "idempotency:";
var RECORD_PREFIX = "record:";
var InboxService = class {
  static {
    __name(this, "InboxService");
  }
  deviceId;
  state;
  spillStore;
  sessions;
  defaults;
  constructor(deviceId, state, spillStore, sessions, defaults) {
    this.deviceId = deviceId;
    this.state = state;
    this.spillStore = spillStore;
    this.sessions = sessions;
    this.defaults = defaults;
  }
  async appendEnvelope(input, now) {
    this.validateAppendRequest(input);
    const meta = await this.getMeta();
    const existingSeq = await this.state.get(`${IDEMPOTENCY_PREFIX}${input.envelope.messageId}`);
    if (existingSeq !== void 0) {
      return { accepted: true, seq: existingSeq };
    }
    const seq = meta.headSeq + 1;
    const expiresAt = now + meta.retentionDays * 24 * 60 * 60 * 1e3;
    const record = {
      seq,
      recipientDeviceId: this.deviceId,
      messageId: input.envelope.messageId,
      receivedAt: now,
      expiresAt,
      state: "available",
      envelope: input.envelope
    };
    const serialized = JSON.stringify(record);
    const storageKey = `${RECORD_PREFIX}${seq}`;
    if (new TextEncoder().encode(serialized).byteLength <= meta.maxInlineBytes && input.envelope.inlineCiphertext) {
      const inlineIndex = {
        seq,
        messageId: record.messageId,
        recipientDeviceId: record.recipientDeviceId,
        receivedAt: record.receivedAt,
        expiresAt,
        state: record.state,
        inlineRecord: record
      };
      await this.state.put(storageKey, inlineIndex);
    } else {
      const payloadRef = `inbox-payload/${this.deviceId}/${seq}.json`;
      await this.spillStore.putJson(payloadRef, record);
      const indexed = {
        seq,
        messageId: record.messageId,
        recipientDeviceId: record.recipientDeviceId,
        receivedAt: record.receivedAt,
        expiresAt,
        state: record.state,
        payloadRef
      };
      await this.state.put(storageKey, indexed);
    }
    await this.state.put(`${IDEMPOTENCY_PREFIX}${record.messageId}`, seq);
    await this.state.put(META_KEY, { ...meta, headSeq: seq });
    await this.state.setAlarm(expiresAt);
    this.publish({
      event: "head_updated",
      deviceId: this.deviceId,
      seq
    });
    this.publish({
      event: "inbox_record_available",
      deviceId: this.deviceId,
      seq,
      record
    });
    return { accepted: true, seq };
  }
  async fetchMessages(input) {
    if (input.deviceId !== this.deviceId) {
      throw new HttpError(400, "invalid_input", "device_id does not match inbox route");
    }
    if (input.limit <= 0) {
      throw new HttpError(400, "invalid_input", "limit must be greater than zero");
    }
    const meta = await this.getMeta();
    const records = [];
    const upper = Math.min(meta.headSeq, input.fromSeq + input.limit - 1);
    for (let seq = input.fromSeq; seq <= upper; seq += 1) {
      const index = await this.state.get(`${RECORD_PREFIX}${seq}`);
      if (!index) {
        continue;
      }
      if (index.inlineRecord) {
        records.push(index.inlineRecord);
        continue;
      }
      if (!index.payloadRef) {
        throw new HttpError(500, "temporary_unavailable", "record payload reference is missing");
      }
      const record = await this.spillStore.getJson(index.payloadRef);
      if (!record) {
        throw new HttpError(500, "temporary_unavailable", "record payload is missing");
      }
      records.push(record);
    }
    return {
      toSeq: records.length > 0 ? records[records.length - 1].seq : meta.headSeq,
      records
    };
  }
  async ack(input) {
    if (input.ack.deviceId !== this.deviceId) {
      throw new HttpError(400, "invalid_input", "ack device_id does not match inbox route");
    }
    const meta = await this.getMeta();
    const ackSeq = Math.max(meta.ackedSeq, input.ack.ackSeq);
    await this.state.put(META_KEY, { ...meta, ackedSeq: ackSeq });
    await this.state.setAlarm(Date.now());
    return { accepted: true, ackSeq };
  }
  async getHead() {
    const meta = await this.getMeta();
    return { headSeq: meta.headSeq };
  }
  async cleanExpiredRecords(now) {
    const meta = await this.getMeta();
    for (let seq = 1; seq <= meta.ackedSeq; seq += 1) {
      const key = `${RECORD_PREFIX}${seq}`;
      const index = await this.state.get(key);
      if (!index || index.expiresAt === void 0 || index.expiresAt > now) {
        continue;
      }
      if (index.payloadRef) {
        await this.spillStore.delete(index.payloadRef);
      }
      await this.state.delete(key);
      await this.state.delete(`${IDEMPOTENCY_PREFIX}${index.messageId}`);
    }
  }
  async getMeta() {
    return await this.state.get(META_KEY) ?? this.defaults;
  }
  publish(event) {
    const payload = JSON.stringify(event);
    for (const session of this.sessions) {
      session.send(payload);
    }
  }
  validateAppendRequest(input) {
    if (input.recipientDeviceId !== this.deviceId) {
      throw new HttpError(400, "invalid_input", "recipient_device_id does not match inbox route");
    }
    if (input.envelope.recipientDeviceId !== this.deviceId) {
      throw new HttpError(400, "invalid_input", "envelope recipient_device_id does not match inbox route");
    }
    if (!input.envelope.messageId || !input.envelope.conversationId || !input.envelope.senderUserId) {
      throw new HttpError(400, "invalid_input", "append request is missing required envelope fields");
    }
    const hasInline = Boolean(input.envelope.inlineCiphertext);
    const hasStorageRefs = (input.envelope.storageRefs?.length ?? 0) > 0;
    if (!hasInline && !hasStorageRefs) {
      throw new HttpError(400, "invalid_input", "envelope must include inline_ciphertext or storage_refs");
    }
  }
};

// src/inbox/durable.ts
var DurableObjectStorageAdapter = class {
  static {
    __name(this, "DurableObjectStorageAdapter");
  }
  storage;
  constructor(storage) {
    this.storage = storage;
  }
  async get(key) {
    return await this.storage.get(key) ?? void 0;
  }
  async put(key, value) {
    await this.storage.put(key, value);
  }
  async delete(key) {
    await this.storage.delete(key);
  }
  async setAlarm(epochMillis) {
    await this.storage.setAlarm(epochMillis);
  }
};
var R2JsonBlobStore = class {
  static {
    __name(this, "R2JsonBlobStore");
  }
  bucket;
  constructor(bucket) {
    this.bucket = bucket;
  }
  async putJson(key, value) {
    await this.bucket.put(key, JSON.stringify(value));
  }
  async getJson(key) {
    const object = await this.bucket.get(key);
    if (!object) {
      return null;
    }
    return await object.json();
  }
  async putBytes(key, value) {
    await this.bucket.put(key, value);
  }
  async getBytes(key) {
    const object = await this.bucket.get(key);
    if (!object) {
      return null;
    }
    return object.arrayBuffer();
  }
  async delete(key) {
    await this.bucket.delete(key);
  }
};
function versionedBody(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return body;
  }
  const record = body;
  if (record.version !== void 0) {
    return body;
  }
  return {
    version: "0.1",
    ...record
  };
}
__name(versionedBody, "versionedBody");
function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(versionedBody(body)), {
    status,
    headers: {
      "content-type": "application/json"
    }
  });
}
__name(jsonResponse, "jsonResponse");
var DurableObjectBase = globalThis.DurableObject ?? class {
  constructor(_state, _env) {
  }
};
async function handleInboxDurableRequest(request, deps) {
  const now = deps.now ?? Date.now();
  const url = new URL(request.url);
  const service = new InboxService(deps.deviceId, deps.state, deps.spillStore, deps.sessions, {
    headSeq: 0,
    ackedSeq: 0,
    retentionDays: deps.retentionDays,
    maxInlineBytes: deps.maxInlineBytes
  });
  try {
    if (url.pathname.endsWith("/subscribe")) {
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
        throw new HttpError(400, "invalid_input", "subscribe requires websocket upgrade");
      }
      if (!deps.onUpgrade) {
        throw new HttpError(500, "temporary_unavailable", "websocket upgrade handler is unavailable");
      }
      return deps.onUpgrade();
    }
    if (url.pathname.endsWith("/messages") && request.method === "POST") {
      const body = await request.json();
      const result = await service.appendEnvelope(body, now);
      return jsonResponse({ accepted: result.accepted, seq: result.seq });
    }
    if (url.pathname.endsWith("/messages") && request.method === "GET") {
      const fromSeq = Number(url.searchParams.get("fromSeq") ?? "1");
      const limit = Number(url.searchParams.get("limit") ?? "100");
      const result = await service.fetchMessages({
        deviceId: deps.deviceId,
        fromSeq,
        limit
      });
      return jsonResponse({
        toSeq: result.toSeq,
        records: result.records
      });
    }
    if (url.pathname.endsWith("/ack") && request.method === "POST") {
      const body = await request.json();
      const result = await service.ack(body);
      return jsonResponse({
        accepted: result.accepted,
        ackSeq: result.ackSeq
      });
    }
    if (url.pathname.endsWith("/head") && request.method === "GET") {
      const result = await service.getHead();
      return jsonResponse(result);
    }
    return jsonResponse({ error: "not_found" }, 404);
  } catch (error) {
    if (error instanceof HttpError) {
      return jsonResponse({ error: error.code, message: error.message }, error.status);
    }
    const runtimeError = error;
    const message = runtimeError.message ?? "internal error";
    return jsonResponse({ error: "temporary_unavailable", message }, 500);
  }
}
__name(handleInboxDurableRequest, "handleInboxDurableRequest");
var InboxDurableObject = class extends DurableObjectBase {
  static {
    __name(this, "InboxDurableObject");
  }
  sessions = /* @__PURE__ */ new Map();
  stateRef;
  envRef;
  constructor(state, env) {
    super(state, env);
    this.stateRef = state;
    this.envRef = env;
  }
  async fetch(request) {
    const url = new URL(request.url);
    const match = url.pathname.match(/\/v1\/inbox\/([^/]+)\//);
    const deviceId = decodeURIComponent(match?.[1] ?? "");
    return handleInboxDurableRequest(request, {
      deviceId,
      state: new DurableObjectStorageAdapter(this.stateRef.storage),
      spillStore: new R2JsonBlobStore(this.envRef.TAPCHAT_STORAGE),
      sessions: Array.from(this.sessions.values()).map(
        (socket) => ({
          send(payload) {
            socket.send(payload);
          }
        })
      ),
      maxInlineBytes: Number(this.envRef.MAX_INLINE_BYTES ?? "4096"),
      retentionDays: Number(this.envRef.RETENTION_DAYS ?? "30"),
      onUpgrade: /* @__PURE__ */ __name(() => {
        const pair = new WebSocketPair();
        const client = pair[0];
        const server = pair[1];
        server.accept();
        const sessionId = crypto.randomUUID();
        this.sessions.set(sessionId, server);
        server.addEventListener("close", () => {
          this.sessions.delete(sessionId);
        });
        return new Response(null, {
          status: 101,
          webSocket: client
        });
      }, "onUpgrade")
    });
  }
  async alarm() {
    const service = new InboxService(
      "",
      new DurableObjectStorageAdapter(this.stateRef.storage),
      new R2JsonBlobStore(this.envRef.TAPCHAT_STORAGE),
      [],
      {
        headSeq: 0,
        ackedSeq: 0,
        retentionDays: Number(this.envRef.RETENTION_DAYS ?? "30"),
        maxInlineBytes: Number(this.envRef.MAX_INLINE_BYTES ?? "4096")
      }
    );
    await service.cleanExpiredRecords(Date.now());
  }
};

// src/storage/shared-state.ts
function sanitizeSegment(value) {
  return value.replace(/[^a-zA-Z0-9:_-]/g, "_");
}
__name(sanitizeSegment, "sanitizeSegment");
var SharedStateService = class {
  static {
    __name(this, "SharedStateService");
  }
  store;
  baseUrl;
  constructor(store, baseUrl2) {
    this.store = store;
    this.baseUrl = baseUrl2;
  }
  identityBundleKey(userId) {
    return `shared-state/${sanitizeSegment(userId)}/identity_bundle.json`;
  }
  deviceListKey(userId) {
    return `shared-state/${sanitizeSegment(userId)}/device_list.json`;
  }
  deviceStatusKey(userId) {
    return `shared-state/${sanitizeSegment(userId)}/device_status.json`;
  }
  keyPackageRefsKey(userId, deviceId) {
    return `keypackages/${sanitizeSegment(userId)}/${sanitizeSegment(deviceId)}/refs.json`;
  }
  keyPackageObjectKey(userId, deviceId, keyPackageId) {
    return `keypackages/${sanitizeSegment(userId)}/${sanitizeSegment(deviceId)}/${sanitizeSegment(keyPackageId)}.bin`;
  }
  identityBundleUrl(userId) {
    return `${this.baseUrl}/v1/shared-state/${encodeURIComponent(userId)}/identity-bundle`;
  }
  deviceStatusUrl(userId) {
    return `${this.baseUrl}/v1/shared-state/${encodeURIComponent(userId)}/device-status`;
  }
  keyPackageRefsUrl(userId, deviceId) {
    return `${this.baseUrl}/v1/shared-state/keypackages/${encodeURIComponent(userId)}/${encodeURIComponent(deviceId)}`;
  }
  keyPackageObjectUrl(userId, deviceId, keyPackageId) {
    return `${this.baseUrl}/v1/shared-state/keypackages/${encodeURIComponent(userId)}/${encodeURIComponent(deviceId)}/${encodeURIComponent(keyPackageId)}`;
  }
  async getIdentityBundle(userId) {
    return this.store.getJson(this.identityBundleKey(userId));
  }
  async putIdentityBundle(userId, bundle) {
    if (bundle.userId !== userId) {
      throw new HttpError(400, "invalid_input", "identity bundle userId does not match request path");
    }
    const normalized = {
      ...bundle,
      identityBundleRef: this.identityBundleUrl(userId),
      deviceStatusRef: bundle.deviceStatusRef ?? this.deviceStatusUrl(userId),
      devices: bundle.devices.map((device) => ({
        ...device,
        keypackageRef: {
          ...device.keypackageRef,
          userId,
          deviceId: device.deviceId,
          ref: device.keypackageRef.ref
        }
      }))
    };
    await this.store.putJson(this.identityBundleKey(userId), normalized);
    await this.store.putJson(this.deviceListKey(userId), this.buildDeviceListDocument(normalized));
  }
  async getDeviceList(userId) {
    return this.store.getJson(this.deviceListKey(userId));
  }
  async getDeviceStatus(userId) {
    return this.store.getJson(this.deviceStatusKey(userId));
  }
  async putDeviceStatus(userId, document) {
    if (document.userId !== userId) {
      throw new HttpError(400, "invalid_input", "device status userId does not match request path");
    }
    for (const device of document.devices) {
      if (device.userId !== userId) {
        throw new HttpError(400, "invalid_input", "device status entry userId does not match request path");
      }
    }
    await this.store.putJson(this.deviceStatusKey(userId), document);
  }
  async getKeyPackageRefs(userId, deviceId) {
    return this.store.getJson(this.keyPackageRefsKey(userId, deviceId));
  }
  async putKeyPackageRefs(userId, deviceId, document) {
    if (document.userId !== userId || document.deviceId !== deviceId) {
      throw new HttpError(400, "invalid_input", "keypackage refs scope does not match request path");
    }
    for (const entry of document.refs) {
      if (!entry.ref || !entry.ref.startsWith(this.keyPackageRefsUrl(userId, deviceId))) {
        throw new HttpError(400, "invalid_input", "keypackage ref must be a concrete object URL");
      }
    }
    await this.store.putJson(this.keyPackageRefsKey(userId, deviceId), document);
  }
  async putKeyPackageObject(userId, deviceId, keyPackageId, body) {
    await this.store.putBytes(this.keyPackageObjectKey(userId, deviceId, keyPackageId), body, {
      "content-type": "application/octet-stream"
    });
  }
  async getKeyPackageObject(userId, deviceId, keyPackageId) {
    return this.store.getBytes(this.keyPackageObjectKey(userId, deviceId, keyPackageId));
  }
  buildDeviceListDocument(bundle) {
    return {
      version: bundle.version,
      userId: bundle.userId,
      updatedAt: bundle.updatedAt,
      devices: bundle.devices.map((device) => ({
        deviceId: device.deviceId,
        status: device.status
      }))
    };
  }
};

// src/storage/service.ts
function sanitizeSegment2(value) {
  return value.replace(/[^a-zA-Z0-9:_-]/g, "_");
}
__name(sanitizeSegment2, "sanitizeSegment");
var StorageService = class {
  static {
    __name(this, "StorageService");
  }
  store;
  baseUrl;
  secret;
  constructor(store, baseUrl2, secret) {
    this.store = store;
    this.baseUrl = baseUrl2;
    this.secret = secret;
  }
  async prepareUpload(input, owner, now) {
    if (!input.taskId || !input.conversationId || !input.messageId || !input.mimeType || input.sizeBytes <= 0) {
      throw new HttpError(400, "invalid_input", "prepare upload request is missing required fields");
    }
    const blobKey = [
      "blob",
      sanitizeSegment2(owner.userId),
      sanitizeSegment2(owner.deviceId),
      sanitizeSegment2(input.conversationId),
      `${sanitizeSegment2(input.messageId)}-${sanitizeSegment2(input.taskId)}`
    ].join("/");
    const expiresAt = now + 15 * 60 * 1e3;
    const uploadToken = await signSharingPayload(this.secret, {
      action: "upload",
      blobKey,
      expiresAt
    });
    const downloadToken = await signSharingPayload(this.secret, {
      action: "download",
      blobKey,
      expiresAt
    });
    return {
      blobRef: blobKey,
      uploadTarget: `${this.baseUrl}/v1/storage/upload/${encodeURIComponent(blobKey)}?token=${encodeURIComponent(uploadToken)}`,
      uploadHeaders: {
        "content-type": input.mimeType
      },
      downloadTarget: `${this.baseUrl}/v1/storage/blob/${encodeURIComponent(blobKey)}?token=${encodeURIComponent(downloadToken)}`,
      expiresAt
    };
  }
  async uploadBlob(blobKey, token, body, metadata, now) {
    const payload = await this.verifyToken(token, now);
    if (payload.action !== "upload" || payload.blobKey !== blobKey) {
      throw new HttpError(403, "invalid_capability", "upload token is not valid for this blob");
    }
    await this.store.putBytes(blobKey, body, metadata);
  }
  async fetchBlob(blobKey, token, now) {
    const payload = await this.verifyToken(token, now);
    if (payload.action !== "download" || payload.blobKey !== blobKey) {
      throw new HttpError(403, "invalid_capability", "download token is not valid for this blob");
    }
    const object = await this.store.getBytes(blobKey);
    if (!object) {
      throw new HttpError(404, "blob_not_found", "blob does not exist");
    }
    return object;
  }
  async putJson(key, value) {
    await this.store.putJson(key, value);
  }
  async getJson(key) {
    return this.store.getJson(key);
  }
  async delete(key) {
    await this.store.delete(key);
  }
  async verifyToken(token, now) {
    try {
      return await verifySharingPayload(this.secret, token, now);
    } catch (error) {
      const message = error instanceof Error ? error.message : "invalid sharing token";
      if (message.includes("expired")) {
        throw new HttpError(403, "capability_expired", message);
      }
      throw new HttpError(403, "invalid_capability", message);
    }
  }
};

// src/routes/http.ts
function versionedBody2(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return body;
  }
  const record = body;
  if (record.version !== void 0) {
    return body;
  }
  return {
    version: CURRENT_MODEL_VERSION,
    ...record
  };
}
__name(versionedBody2, "versionedBody");
function jsonResponse2(body, status = 200) {
  return new Response(JSON.stringify(versionedBody2(body)), {
    status,
    headers: {
      "content-type": "application/json"
    }
  });
}
__name(jsonResponse2, "jsonResponse");
var R2JsonBlobStore2 = class {
  static {
    __name(this, "R2JsonBlobStore");
  }
  bucket;
  constructor(bucket) {
    this.bucket = bucket;
  }
  async putJson(key, value) {
    await this.bucket.put(key, JSON.stringify(value));
  }
  async getJson(key) {
    const object = await this.bucket.get(key);
    if (!object) {
      return null;
    }
    return await object.json();
  }
  async putBytes(key, value, metadata) {
    await this.bucket.put(key, value, metadata ? { httpMetadata: metadata } : void 0);
  }
  async getBytes(key) {
    const object = await this.bucket.get(key);
    if (!object) {
      return null;
    }
    return object.arrayBuffer();
  }
  async delete(key) {
    await this.bucket.delete(key);
  }
};
function baseUrl(request, env) {
  return env.PUBLIC_BASE_URL?.trim().replace(/\/+$/, "") ?? new URL(request.url).origin;
}
__name(baseUrl, "baseUrl");
function sharedStateSecret(env) {
  return env.SHARING_TOKEN_SECRET ?? "replace-me";
}
__name(sharedStateSecret, "sharedStateSecret");
function bootstrapSecret(env) {
  return env.BOOTSTRAP_TOKEN_SECRET ?? env.SHARING_TOKEN_SECRET ?? "replace-me";
}
__name(bootstrapSecret, "bootstrapSecret");
function runtimeScopes() {
  return [
    "inbox_read",
    "inbox_ack",
    "inbox_subscribe",
    "storage_prepare_upload",
    "shared_state_write",
    "keypackage_write"
  ];
}
__name(runtimeScopes, "runtimeScopes");
async function issueDeviceRuntimeAuth(env, userId, deviceId, now) {
  const expiresAt = now + 24 * 60 * 60 * 1e3;
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
__name(issueDeviceRuntimeAuth, "issueDeviceRuntimeAuth");
function publicDeploymentBundle(request, env) {
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
      features: ["generic_sync", "attachment_v1"]
    }
  };
}
__name(publicDeploymentBundle, "publicDeploymentBundle");
async function authorizeSharedStateWrite(request, env, userId, objectKind, now) {
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
__name(authorizeSharedStateWrite, "authorizeSharedStateWrite");
async function handleRequest(request, env) {
  const url = new URL(request.url);
  const store = new StorageService(
    new R2JsonBlobStore2(env.TAPCHAT_STORAGE),
    baseUrl(request, env),
    sharedStateSecret(env)
  );
  const sharedState = new SharedStateService(new R2JsonBlobStore2(env.TAPCHAT_STORAGE), baseUrl(request, env));
  const now = Date.now();
  try {
    if (request.method === "GET" && url.pathname === "/v1/deployment-bundle") {
      return jsonResponse2(publicDeploymentBundle(request, env));
    }
    if (request.method === "POST" && url.pathname === "/v1/bootstrap/device") {
      const body = await request.json();
      if (body.version !== CURRENT_MODEL_VERSION) {
        throw new HttpError(400, "unsupported_version", "bootstrap request version is not supported");
      }
      await validateBootstrapAuthorization(request, bootstrapSecret(env), body.userId, body.deviceId, now);
      const bundle = {
        ...publicDeploymentBundle(request, env),
        deviceRuntimeAuth: await issueDeviceRuntimeAuth(env, body.userId, body.deviceId, now),
        expectedUserId: body.userId,
        expectedDeviceId: body.deviceId
      };
      return jsonResponse2(bundle);
    }
    const inboxMatch = url.pathname.match(/^\/v1\/inbox\/([^/]+)\/(messages|ack|head|subscribe)$/);
    if (inboxMatch) {
      const deviceId = decodeURIComponent(inboxMatch[1]);
      const operation = inboxMatch[2];
      const objectId = env.INBOX.idFromName(deviceId);
      const stub = env.INBOX.get(objectId);
      if (request.method === "POST" && operation === "messages") {
        const body = await request.clone().json();
        validateAppendAuthorization(request, deviceId, body, now);
      } else if (request.method === "GET" && (operation === "messages" || operation === "head")) {
        await validateDeviceRuntimeAuthorizationForDevice(request, sharedStateSecret(env), deviceId, "inbox_read", now);
      } else if (request.method === "POST" && operation === "ack") {
        await validateDeviceRuntimeAuthorizationForDevice(request, sharedStateSecret(env), deviceId, "inbox_ack", now);
      } else if (operation === "subscribe") {
        await validateDeviceRuntimeAuthorizationForDevice(request, sharedStateSecret(env), deviceId, "inbox_subscribe", now);
      }
      return stub.fetch(request);
    }
    const identityBundleMatch = url.pathname.match(/^\/v1\/shared-state\/([^/]+)\/identity-bundle$/);
    if (identityBundleMatch) {
      const userId = decodeURIComponent(identityBundleMatch[1]);
      if (request.method === "GET") {
        const bundle = await sharedState.getIdentityBundle(userId);
        if (!bundle) {
          return jsonResponse2({ error: "not_found", message: "identity bundle not found" }, 404);
        }
        return jsonResponse2(bundle);
      }
      if (request.method === "PUT") {
        await authorizeSharedStateWrite(request, env, userId, "identity_bundle", now);
        const body = await request.json();
        await sharedState.putIdentityBundle(userId, body);
        const saved = await sharedState.getIdentityBundle(userId);
        return jsonResponse2(saved);
      }
    }
    const deviceStatusMatch = url.pathname.match(/^\/v1\/shared-state\/([^/]+)\/device-status$/);
    if (deviceStatusMatch) {
      const userId = decodeURIComponent(deviceStatusMatch[1]);
      if (request.method === "GET") {
        const document = await sharedState.getDeviceStatus(userId);
        if (!document) {
          return jsonResponse2({ error: "not_found", message: "device status not found" }, 404);
        }
        return jsonResponse2(document);
      }
      if (request.method === "PUT") {
        await authorizeSharedStateWrite(request, env, userId, "device_status", now);
        const body = await request.json();
        await sharedState.putDeviceStatus(userId, body);
        const saved = await sharedState.getDeviceStatus(userId);
        return jsonResponse2(saved);
      }
    }
    const deviceListMatch = url.pathname.match(/^\/v1\/shared-state\/([^/]+)\/device-list$/);
    if (deviceListMatch && request.method === "GET") {
      const userId = decodeURIComponent(deviceListMatch[1]);
      const document = await sharedState.getDeviceList(userId);
      if (!document) {
        return jsonResponse2({ error: "not_found", message: "device list not found" }, 404);
      }
      return jsonResponse2(document);
    }
    const keyPackageRefsMatch = url.pathname.match(/^\/v1\/shared-state\/keypackages\/([^/]+)\/([^/]+)$/);
    if (keyPackageRefsMatch) {
      const userId = decodeURIComponent(keyPackageRefsMatch[1]);
      const deviceId = decodeURIComponent(keyPackageRefsMatch[2]);
      if (request.method === "GET") {
        const document = await sharedState.getKeyPackageRefs(userId, deviceId);
        if (!document) {
          return jsonResponse2({ error: "not_found", message: "keypackage refs not found" }, 404);
        }
        return jsonResponse2(document);
      }
      if (request.method === "PUT") {
        await validateKeyPackageWriteAuthorization(request, sharedStateSecret(env), userId, deviceId, void 0, now);
        const body = await request.json();
        await sharedState.putKeyPackageRefs(userId, deviceId, body);
        const saved = await sharedState.getKeyPackageRefs(userId, deviceId);
        return jsonResponse2(saved);
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
          return jsonResponse2({ error: "not_found", message: "keypackage not found" }, 404);
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
      const body = await request.json();
      const result = await store.prepareUpload(body, { userId: auth.userId, deviceId: auth.deviceId }, now);
      return jsonResponse2(result);
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
    return jsonResponse2({ error: "not_found", message: "route not found" }, 404);
  } catch (error) {
    if (error instanceof HttpError) {
      return jsonResponse2({ error: error.code, message: error.message }, error.status);
    }
    const runtimeError = error;
    const message = runtimeError.message ?? "internal error";
    return jsonResponse2({ error: "temporary_unavailable", message }, 500);
  }
}
__name(handleRequest, "handleRequest");

// src/index.ts
var src_default = {
  async fetch(request, env) {
    return handleRequest(request, env);
  }
};

// node_modules/wrangler/templates/middleware/middleware-ensure-req-body-drained.ts
var drainBody = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } finally {
    try {
      if (request.body !== null && !request.bodyUsed) {
        const reader = request.body.getReader();
        while (!(await reader.read()).done) {
        }
      }
    } catch (e) {
      console.error("Failed to drain the unused request body.", e);
    }
  }
}, "drainBody");
var middleware_ensure_req_body_drained_default = drainBody;

// node_modules/wrangler/templates/middleware/middleware-miniflare3-json-error.ts
function reduceError(e) {
  return {
    name: e?.name,
    message: e?.message ?? String(e),
    stack: e?.stack,
    cause: e?.cause === void 0 ? void 0 : reduceError(e.cause)
  };
}
__name(reduceError, "reduceError");
var jsonError = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } catch (e) {
    const error = reduceError(e);
    return Response.json(error, {
      status: 500,
      headers: { "MF-Experimental-Error-Stack": "true" }
    });
  }
}, "jsonError");
var middleware_miniflare3_json_error_default = jsonError;

// .wrangler/tmp/bundle-Y4iBux/middleware-insertion-facade.js
var __INTERNAL_WRANGLER_MIDDLEWARE__ = [
  middleware_ensure_req_body_drained_default,
  middleware_miniflare3_json_error_default
];
var middleware_insertion_facade_default = src_default;

// node_modules/wrangler/templates/middleware/common.ts
var __facade_middleware__ = [];
function __facade_register__(...args) {
  __facade_middleware__.push(...args.flat());
}
__name(__facade_register__, "__facade_register__");
function __facade_invokeChain__(request, env, ctx, dispatch, middlewareChain) {
  const [head, ...tail] = middlewareChain;
  const middlewareCtx = {
    dispatch,
    next(newRequest, newEnv) {
      return __facade_invokeChain__(newRequest, newEnv, ctx, dispatch, tail);
    }
  };
  return head(request, env, ctx, middlewareCtx);
}
__name(__facade_invokeChain__, "__facade_invokeChain__");
function __facade_invoke__(request, env, ctx, dispatch, finalMiddleware) {
  return __facade_invokeChain__(request, env, ctx, dispatch, [
    ...__facade_middleware__,
    finalMiddleware
  ]);
}
__name(__facade_invoke__, "__facade_invoke__");

// .wrangler/tmp/bundle-Y4iBux/middleware-loader.entry.ts
var __Facade_ScheduledController__ = class ___Facade_ScheduledController__ {
  constructor(scheduledTime, cron, noRetry) {
    this.scheduledTime = scheduledTime;
    this.cron = cron;
    this.#noRetry = noRetry;
  }
  static {
    __name(this, "__Facade_ScheduledController__");
  }
  #noRetry;
  noRetry() {
    if (!(this instanceof ___Facade_ScheduledController__)) {
      throw new TypeError("Illegal invocation");
    }
    this.#noRetry();
  }
};
function wrapExportedHandler(worker) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return worker;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  const fetchDispatcher = /* @__PURE__ */ __name(function(request, env, ctx) {
    if (worker.fetch === void 0) {
      throw new Error("Handler does not export a fetch() function.");
    }
    return worker.fetch(request, env, ctx);
  }, "fetchDispatcher");
  return {
    ...worker,
    fetch(request, env, ctx) {
      const dispatcher = /* @__PURE__ */ __name(function(type, init) {
        if (type === "scheduled" && worker.scheduled !== void 0) {
          const controller = new __Facade_ScheduledController__(
            Date.now(),
            init.cron ?? "",
            () => {
            }
          );
          return worker.scheduled(controller, env, ctx);
        }
      }, "dispatcher");
      return __facade_invoke__(request, env, ctx, dispatcher, fetchDispatcher);
    }
  };
}
__name(wrapExportedHandler, "wrapExportedHandler");
function wrapWorkerEntrypoint(klass) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return klass;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  return class extends klass {
    #fetchDispatcher = /* @__PURE__ */ __name((request, env, ctx) => {
      this.env = env;
      this.ctx = ctx;
      if (super.fetch === void 0) {
        throw new Error("Entrypoint class does not define a fetch() function.");
      }
      return super.fetch(request);
    }, "#fetchDispatcher");
    #dispatcher = /* @__PURE__ */ __name((type, init) => {
      if (type === "scheduled" && super.scheduled !== void 0) {
        const controller = new __Facade_ScheduledController__(
          Date.now(),
          init.cron ?? "",
          () => {
          }
        );
        return super.scheduled(controller);
      }
    }, "#dispatcher");
    fetch(request) {
      return __facade_invoke__(
        request,
        this.env,
        this.ctx,
        this.#dispatcher,
        this.#fetchDispatcher
      );
    }
  };
}
__name(wrapWorkerEntrypoint, "wrapWorkerEntrypoint");
var WRAPPED_ENTRY;
if (typeof middleware_insertion_facade_default === "object") {
  WRAPPED_ENTRY = wrapExportedHandler(middleware_insertion_facade_default);
} else if (typeof middleware_insertion_facade_default === "function") {
  WRAPPED_ENTRY = wrapWorkerEntrypoint(middleware_insertion_facade_default);
}
var middleware_loader_entry_default = WRAPPED_ENTRY;
export {
  InboxDurableObject,
  __INTERNAL_WRANGLER_MIDDLEWARE__,
  middleware_loader_entry_default as default
};
//# sourceMappingURL=index.js.map

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
async function importSecret(secret) {
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}
async function signSharingPayload(secret, payload) {
  const encodedPayload = encoder.encode(JSON.stringify(payload));
  const key = await importSecret(secret);
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, encodedPayload));
  return `${toBase64Url(encodedPayload)}.${toBase64Url(signature)}`;
}
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

// src/auth/capability.ts
var HttpError = class extends Error {
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
async function validateAnyDeviceRuntimeAuthorization(request, secret, scope, now) {
  const token = await verifyDeviceRuntimeToken(request, secret, now);
  if (!token.scopes.includes(scope)) {
    throw new HttpError(403, "invalid_capability", `device runtime token does not grant ${scope}`);
  }
  return token;
}
async function validateDeviceRuntimeAuthorization(request, secret, userId, deviceId, scope, now) {
  const token = await validateAnyDeviceRuntimeAuthorization(request, secret, scope, now);
  if (token.userId !== userId || token.deviceId !== deviceId) {
    throw new HttpError(403, "invalid_capability", "device runtime token scope does not match request path");
  }
  return token;
}
async function validateDeviceRuntimeAuthorizationForDevice(request, secret, deviceId, scope, now) {
  const token = await validateAnyDeviceRuntimeAuthorization(request, secret, scope, now);
  if (token.deviceId !== deviceId) {
    throw new HttpError(403, "invalid_capability", "device runtime token scope does not match request path");
  }
  return token;
}
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

// src/inbox/service.ts
var META_KEY = "meta";
var IDEMPOTENCY_PREFIX = "idempotency:";
var RECORD_PREFIX = "record:";
var InboxService = class {
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
function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(versionedBody(body)), {
    status,
    headers: {
      "content-type": "application/json"
    }
  });
}
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
var InboxDurableObject = class extends DurableObjectBase {
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
      onUpgrade: () => {
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
      }
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
var SharedStateService = class {
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
var StorageService = class {
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
function jsonResponse2(body, status = 200) {
  return new Response(JSON.stringify(versionedBody2(body)), {
    status,
    headers: {
      "content-type": "application/json"
    }
  });
}
var R2JsonBlobStore2 = class {
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
function sharedStateSecret(env) {
  return env.SHARING_TOKEN_SECRET ?? "replace-me";
}
function bootstrapSecret(env) {
  return env.BOOTSTRAP_TOKEN_SECRET ?? env.SHARING_TOKEN_SECRET ?? "replace-me";
}
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

// src/index.ts
var index_default = {
  async fetch(request, env) {
    return handleRequest(request, env);
  }
};
export {
  InboxDurableObject,
  index_default as default
};
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsiLi4vc3JjL3R5cGVzL2NvbnRyYWN0cy50cyIsICIuLi9zcmMvc3RvcmFnZS9zaGFyaW5nLnRzIiwgIi4uL3NyYy9hdXRoL2NhcGFiaWxpdHkudHMiLCAiLi4vc3JjL2luYm94L3NlcnZpY2UudHMiLCAiLi4vc3JjL2luYm94L2R1cmFibGUudHMiLCAiLi4vc3JjL3N0b3JhZ2Uvc2hhcmVkLXN0YXRlLnRzIiwgIi4uL3NyYy9zdG9yYWdlL3NlcnZpY2UudHMiLCAiLi4vc3JjL3JvdXRlcy9odHRwLnRzIiwgIi4uL3NyYy9pbmRleC50cyJdLAogICJzb3VyY2VzQ29udGVudCI6IFsiZXhwb3J0IGNvbnN0IENVUlJFTlRfTU9ERUxfVkVSU0lPTiA9IFwiMC4xXCI7XG5cbmV4cG9ydCBpbnRlcmZhY2UgU2VuZGVyUHJvb2Yge1xuICB0eXBlOiBzdHJpbmc7XG4gIHZhbHVlOiBzdHJpbmc7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgU3RvcmFnZVJlZiB7XG4gIGtpbmQ6IHN0cmluZztcbiAgcmVmOiBzdHJpbmc7XG4gIHNpemVCeXRlczogbnVtYmVyO1xuICBtaW1lVHlwZTogc3RyaW5nO1xuICBleHBpcmVzQXQ/OiBudW1iZXI7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgV2FrZUhpbnQge1xuICBsYXRlc3RTZXFIaW50PzogbnVtYmVyO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIENhcGFiaWxpdHlDb25zdHJhaW50cyB7XG4gIG1heEJ5dGVzPzogbnVtYmVyO1xuICBtYXhPcHNQZXJNaW51dGU/OiBudW1iZXI7XG59XG5cbmV4cG9ydCB0eXBlIE1lc3NhZ2VUeXBlID1cbiAgfCBcIm1sc19hcHBsaWNhdGlvblwiXG4gIHwgXCJtbHNfY29tbWl0XCJcbiAgfCBcIm1sc193ZWxjb21lXCJcbiAgfCBcImNvbnRyb2xfZGV2aWNlX21lbWJlcnNoaXBfY2hhbmdlZFwiXG4gIHwgXCJjb250cm9sX2lkZW50aXR5X3N0YXRlX3VwZGF0ZWRcIlxuICB8IFwiY29udHJvbF9jb252ZXJzYXRpb25fbmVlZHNfcmVidWlsZFwiO1xuXG5leHBvcnQgaW50ZXJmYWNlIEVudmVsb3BlIHtcbiAgdmVyc2lvbjogc3RyaW5nO1xuICBtZXNzYWdlSWQ6IHN0cmluZztcbiAgY29udmVyc2F0aW9uSWQ6IHN0cmluZztcbiAgc2VuZGVyVXNlcklkOiBzdHJpbmc7XG4gIHNlbmRlckRldmljZUlkOiBzdHJpbmc7XG4gIHJlY2lwaWVudERldmljZUlkOiBzdHJpbmc7XG4gIGNyZWF0ZWRBdDogbnVtYmVyO1xuICBtZXNzYWdlVHlwZTogTWVzc2FnZVR5cGU7XG4gIGlubGluZUNpcGhlcnRleHQ/OiBzdHJpbmc7XG4gIHN0b3JhZ2VSZWZzPzogU3RvcmFnZVJlZltdO1xuICBkZWxpdmVyeUNsYXNzOiBcIm5vcm1hbFwiO1xuICB3YWtlSGludD86IFdha2VIaW50O1xuICBzZW5kZXJQcm9vZjogU2VuZGVyUHJvb2Y7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgSW5ib3hSZWNvcmQge1xuICBzZXE6IG51bWJlcjtcbiAgcmVjaXBpZW50RGV2aWNlSWQ6IHN0cmluZztcbiAgbWVzc2FnZUlkOiBzdHJpbmc7XG4gIHJlY2VpdmVkQXQ6IG51bWJlcjtcbiAgZXhwaXJlc0F0PzogbnVtYmVyO1xuICBzdGF0ZTogXCJhdmFpbGFibGVcIjtcbiAgZW52ZWxvcGU6IEVudmVsb3BlO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEFjayB7XG4gIGRldmljZUlkOiBzdHJpbmc7XG4gIGFja1NlcTogbnVtYmVyO1xuICBhY2tlZE1lc3NhZ2VJZHM/OiBzdHJpbmdbXTtcbiAgYWNrZWRBdDogbnVtYmVyO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEFwcGVuZEVudmVsb3BlUmVxdWVzdCB7XG4gIHZlcnNpb246IHN0cmluZztcbiAgcmVjaXBpZW50RGV2aWNlSWQ6IHN0cmluZztcbiAgZW52ZWxvcGU6IEVudmVsb3BlO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEFwcGVuZEVudmVsb3BlUmVzdWx0IHtcbiAgYWNjZXB0ZWQ6IGJvb2xlYW47XG4gIHNlcTogbnVtYmVyO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEZldGNoTWVzc2FnZXNSZXF1ZXN0IHtcbiAgZGV2aWNlSWQ6IHN0cmluZztcbiAgZnJvbVNlcTogbnVtYmVyO1xuICBsaW1pdDogbnVtYmVyO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEZldGNoTWVzc2FnZXNSZXN1bHQge1xuICB0b1NlcTogbnVtYmVyO1xuICByZWNvcmRzOiBJbmJveFJlY29yZFtdO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEFja1JlcXVlc3Qge1xuICBhY2s6IEFjaztcbn1cblxuZXhwb3J0IGludGVyZmFjZSBBY2tSZXN1bHQge1xuICBhY2NlcHRlZDogYm9vbGVhbjtcbiAgYWNrU2VxOiBudW1iZXI7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgR2V0SGVhZFJlc3VsdCB7XG4gIGhlYWRTZXE6IG51bWJlcjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBQcmVwYXJlQmxvYlVwbG9hZFJlcXVlc3Qge1xuICB0YXNrSWQ6IHN0cmluZztcbiAgY29udmVyc2F0aW9uSWQ6IHN0cmluZztcbiAgbWVzc2FnZUlkOiBzdHJpbmc7XG4gIG1pbWVUeXBlOiBzdHJpbmc7XG4gIHNpemVCeXRlczogbnVtYmVyO1xuICBmaWxlTmFtZT86IHN0cmluZztcbn1cblxuZXhwb3J0IGludGVyZmFjZSBQcmVwYXJlQmxvYlVwbG9hZFJlc3VsdCB7XG4gIGJsb2JSZWY6IHN0cmluZztcbiAgdXBsb2FkVGFyZ2V0OiBzdHJpbmc7XG4gIHVwbG9hZEhlYWRlcnM6IFJlY29yZDxzdHJpbmcsIHN0cmluZz47XG4gIGRvd25sb2FkVGFyZ2V0Pzogc3RyaW5nO1xuICBleHBpcmVzQXQ/OiBudW1iZXI7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgU3RvcmFnZUJhc2VJbmZvIHtcbiAgYmFzZVVybD86IHN0cmluZztcbiAgYnVja2V0SGludD86IHN0cmluZztcbn1cblxuZXhwb3J0IGludGVyZmFjZSBEZXZpY2VSdW50aW1lQXV0aCB7XG4gIHNjaGVtZTogXCJiZWFyZXJcIjtcbiAgdG9rZW46IHN0cmluZztcbiAgZXhwaXJlc0F0OiBudW1iZXI7XG4gIHVzZXJJZDogc3RyaW5nO1xuICBkZXZpY2VJZDogc3RyaW5nO1xuICBzY29wZXM6IERldmljZVJ1bnRpbWVTY29wZVtdO1xufVxuXG5leHBvcnQgdHlwZSBEZXZpY2VSdW50aW1lU2NvcGUgPVxuICB8IFwiaW5ib3hfcmVhZFwiXG4gIHwgXCJpbmJveF9hY2tcIlxuICB8IFwiaW5ib3hfc3Vic2NyaWJlXCJcbiAgfCBcInN0b3JhZ2VfcHJlcGFyZV91cGxvYWRcIlxuICB8IFwic2hhcmVkX3N0YXRlX3dyaXRlXCJcbiAgfCBcImtleXBhY2thZ2Vfd3JpdGVcIjtcblxuZXhwb3J0IGludGVyZmFjZSBSdW50aW1lQ29uZmlnIHtcbiAgc3VwcG9ydGVkUmVhbHRpbWVLaW5kczogQXJyYXk8XCJ3ZWJzb2NrZXRcIiB8IFwic2VydmVyX3NlbnRfZXZlbnRzXCIgfCBcInBvbGxpbmdcIj47XG4gIGlkZW50aXR5QnVuZGxlUmVmPzogc3RyaW5nO1xuICBkZXZpY2VTdGF0dXNSZWY/OiBzdHJpbmc7XG4gIGtleXBhY2thZ2VSZWZCYXNlPzogc3RyaW5nO1xuICBtYXhJbmxpbmVCeXRlcz86IG51bWJlcjtcbiAgZmVhdHVyZXM6IHN0cmluZ1tdO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIERlcGxveW1lbnRCdW5kbGUge1xuICB2ZXJzaW9uOiBzdHJpbmc7XG4gIHJlZ2lvbjogc3RyaW5nO1xuICBpbmJveEh0dHBFbmRwb2ludDogc3RyaW5nO1xuICBpbmJveFdlYnNvY2tldEVuZHBvaW50OiBzdHJpbmc7XG4gIHN0b3JhZ2VCYXNlSW5mbzogU3RvcmFnZUJhc2VJbmZvO1xuICBydW50aW1lQ29uZmlnOiBSdW50aW1lQ29uZmlnO1xuICBkZXZpY2VSdW50aW1lQXV0aD86IERldmljZVJ1bnRpbWVBdXRoO1xuICBleHBlY3RlZFVzZXJJZD86IHN0cmluZztcbiAgZXhwZWN0ZWREZXZpY2VJZD86IHN0cmluZztcbn1cblxuZXhwb3J0IGludGVyZmFjZSBJbmJveEFwcGVuZENhcGFiaWxpdHkge1xuICB2ZXJzaW9uOiBzdHJpbmc7XG4gIHNlcnZpY2U6IFwiaW5ib3hcIjtcbiAgdXNlcklkOiBzdHJpbmc7XG4gIHRhcmdldERldmljZUlkOiBzdHJpbmc7XG4gIGVuZHBvaW50OiBzdHJpbmc7XG4gIG9wZXJhdGlvbnM6IHN0cmluZ1tdO1xuICBjb252ZXJzYXRpb25TY29wZT86IHN0cmluZ1tdO1xuICBleHBpcmVzQXQ6IG51bWJlcjtcbiAgY29uc3RyYWludHM/OiBDYXBhYmlsaXR5Q29uc3RyYWludHM7XG4gIHNpZ25hdHVyZTogc3RyaW5nO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIERldmljZUJpbmRpbmcge1xuICB2ZXJzaW9uOiBzdHJpbmc7XG4gIHVzZXJJZDogc3RyaW5nO1xuICBkZXZpY2VJZDogc3RyaW5nO1xuICBkZXZpY2VQdWJsaWNLZXk6IHN0cmluZztcbiAgY3JlYXRlZEF0OiBudW1iZXI7XG4gIHNpZ25hdHVyZTogc3RyaW5nO1xufVxuXG5leHBvcnQgdHlwZSBEZXZpY2VTdGF0dXNLaW5kID0gXCJhY3RpdmVcIiB8IFwicmV2b2tlZFwiO1xuXG5leHBvcnQgaW50ZXJmYWNlIEtleVBhY2thZ2VSZWYge1xuICB2ZXJzaW9uOiBzdHJpbmc7XG4gIHVzZXJJZDogc3RyaW5nO1xuICBkZXZpY2VJZDogc3RyaW5nO1xuICByZWY6IHN0cmluZztcbiAgZXhwaXJlc0F0OiBudW1iZXI7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgRGV2aWNlQ29udGFjdFByb2ZpbGUge1xuICB2ZXJzaW9uOiBzdHJpbmc7XG4gIGRldmljZUlkOiBzdHJpbmc7XG4gIGRldmljZVB1YmxpY0tleTogc3RyaW5nO1xuICBiaW5kaW5nOiBEZXZpY2VCaW5kaW5nO1xuICBzdGF0dXM6IERldmljZVN0YXR1c0tpbmQ7XG4gIGluYm94QXBwZW5kQ2FwYWJpbGl0eTogSW5ib3hBcHBlbmRDYXBhYmlsaXR5O1xuICBrZXlwYWNrYWdlUmVmOiBLZXlQYWNrYWdlUmVmO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIFN0b3JhZ2VQcm9maWxlIHtcbiAgYmFzZVVybD86IHN0cmluZztcbiAgcHJvZmlsZVJlZj86IHN0cmluZztcbn1cblxuZXhwb3J0IGludGVyZmFjZSBJZGVudGl0eUJ1bmRsZSB7XG4gIHZlcnNpb246IHN0cmluZztcbiAgdXNlcklkOiBzdHJpbmc7XG4gIHVzZXJQdWJsaWNLZXk6IHN0cmluZztcbiAgZGV2aWNlczogRGV2aWNlQ29udGFjdFByb2ZpbGVbXTtcbiAgaWRlbnRpdHlCdW5kbGVSZWY/OiBzdHJpbmc7XG4gIGRldmljZVN0YXR1c1JlZj86IHN0cmluZztcbiAgc3RvcmFnZVByb2ZpbGU/OiBTdG9yYWdlUHJvZmlsZTtcbiAgdXBkYXRlZEF0OiBudW1iZXI7XG4gIHNpZ25hdHVyZTogc3RyaW5nO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIERldmljZVN0YXR1c1JlY29yZCB7XG4gIHZlcnNpb246IHN0cmluZztcbiAgdXNlcklkOiBzdHJpbmc7XG4gIGRldmljZUlkOiBzdHJpbmc7XG4gIHN0YXR1czogRGV2aWNlU3RhdHVzS2luZDtcbiAgdXBkYXRlZEF0OiBudW1iZXI7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgRGV2aWNlTGlzdEVudHJ5IHtcbiAgZGV2aWNlSWQ6IHN0cmluZztcbiAgc3RhdHVzOiBEZXZpY2VTdGF0dXNLaW5kO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIERldmljZUxpc3REb2N1bWVudCB7XG4gIHZlcnNpb246IHN0cmluZztcbiAgdXNlcklkOiBzdHJpbmc7XG4gIHVwZGF0ZWRBdDogbnVtYmVyO1xuICBkZXZpY2VzOiBEZXZpY2VMaXN0RW50cnlbXTtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBEZXZpY2VTdGF0dXNEb2N1bWVudCB7XG4gIHZlcnNpb246IHN0cmluZztcbiAgdXNlcklkOiBzdHJpbmc7XG4gIHVwZGF0ZWRBdDogbnVtYmVyO1xuICBkZXZpY2VzOiBEZXZpY2VTdGF0dXNSZWNvcmRbXTtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBLZXlQYWNrYWdlUmVmRW50cnkge1xuICBrZXlQYWNrYWdlSWQ6IHN0cmluZztcbiAgcmVmOiBzdHJpbmc7XG4gIGV4cGlyZXNBdDogbnVtYmVyO1xuICBjcmVhdGVkQXQ6IG51bWJlcjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBLZXlQYWNrYWdlUmVmc0RvY3VtZW50IHtcbiAgdmVyc2lvbjogc3RyaW5nO1xuICB1c2VySWQ6IHN0cmluZztcbiAgZGV2aWNlSWQ6IHN0cmluZztcbiAgdXBkYXRlZEF0OiBudW1iZXI7XG4gIHJlZnM6IEtleVBhY2thZ2VSZWZFbnRyeVtdO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIFNoYXJlZFN0YXRlV3JpdGVUb2tlbiB7XG4gIHZlcnNpb246IHN0cmluZztcbiAgc2VydmljZTogXCJzaGFyZWRfc3RhdGVcIjtcbiAgdXNlcklkOiBzdHJpbmc7XG4gIG9iamVjdEtpbmRzOiBBcnJheTxcImlkZW50aXR5X2J1bmRsZVwiIHwgXCJkZXZpY2Vfc3RhdHVzXCI+O1xuICBleHBpcmVzQXQ6IG51bWJlcjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBLZXlQYWNrYWdlV3JpdGVUb2tlbiB7XG4gIHZlcnNpb246IHN0cmluZztcbiAgc2VydmljZTogXCJrZXlwYWNrYWdlc1wiO1xuICB1c2VySWQ6IHN0cmluZztcbiAgZGV2aWNlSWQ6IHN0cmluZztcbiAga2V5UGFja2FnZUlkPzogc3RyaW5nO1xuICBleHBpcmVzQXQ6IG51bWJlcjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBCb290c3RyYXBEZXZpY2VSZXF1ZXN0IHtcbiAgdmVyc2lvbjogc3RyaW5nO1xuICB1c2VySWQ6IHN0cmluZztcbiAgZGV2aWNlSWQ6IHN0cmluZztcbn1cblxuZXhwb3J0IGludGVyZmFjZSBCb290c3RyYXBUb2tlbiB7XG4gIHZlcnNpb246IHN0cmluZztcbiAgc2VydmljZTogXCJib290c3RyYXBcIjtcbiAgdXNlcklkOiBzdHJpbmc7XG4gIGRldmljZUlkOiBzdHJpbmc7XG4gIG9wZXJhdGlvbnM6IEFycmF5PFwiaXNzdWVfZGV2aWNlX2J1bmRsZVwiPjtcbiAgZXhwaXJlc0F0OiBudW1iZXI7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgRGV2aWNlUnVudGltZVRva2VuIHtcbiAgdmVyc2lvbjogc3RyaW5nO1xuICBzZXJ2aWNlOiBcImRldmljZV9ydW50aW1lXCI7XG4gIHVzZXJJZDogc3RyaW5nO1xuICBkZXZpY2VJZDogc3RyaW5nO1xuICBzY29wZXM6IERldmljZVJ1bnRpbWVTY29wZVtdO1xuICBleHBpcmVzQXQ6IG51bWJlcjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBSZWFsdGltZUV2ZW50IHtcbiAgZXZlbnQ6IFwiaGVhZF91cGRhdGVkXCIgfCBcImluYm94X3JlY29yZF9hdmFpbGFibGVcIjtcbiAgZGV2aWNlSWQ6IHN0cmluZztcbiAgc2VxOiBudW1iZXI7XG4gIHJlY29yZD86IEluYm94UmVjb3JkO1xufVxyXG4iLCAiY29uc3QgZW5jb2RlciA9IG5ldyBUZXh0RW5jb2RlcigpO1xuXG5mdW5jdGlvbiB0b0Jhc2U2NFVybChieXRlczogVWludDhBcnJheSk6IHN0cmluZyB7XG4gIGxldCBiaW5hcnkgPSBcIlwiO1xuICBmb3IgKGNvbnN0IGJ5dGUgb2YgYnl0ZXMpIHtcbiAgICBiaW5hcnkgKz0gU3RyaW5nLmZyb21DaGFyQ29kZShieXRlKTtcbiAgfVxuICByZXR1cm4gYnRvYShiaW5hcnkpLnJlcGxhY2UoL1xcKy9nLCBcIi1cIikucmVwbGFjZSgvXFwvL2csIFwiX1wiKS5yZXBsYWNlKC89KyQvZywgXCJcIik7XG59XG5cbmZ1bmN0aW9uIGZyb21CYXNlNjRVcmwodmFsdWU6IHN0cmluZyk6IFVpbnQ4QXJyYXkge1xuICBjb25zdCBub3JtYWxpemVkID0gdmFsdWUucmVwbGFjZSgvLS9nLCBcIitcIikucmVwbGFjZSgvXy9nLCBcIi9cIik7XG4gIGNvbnN0IHBhZGRlZCA9IG5vcm1hbGl6ZWQgKyBcIj1cIi5yZXBlYXQoKDQgLSAobm9ybWFsaXplZC5sZW5ndGggJSA0KSkgJSA0KTtcbiAgY29uc3QgYmluYXJ5ID0gYXRvYihwYWRkZWQpO1xuICBjb25zdCBvdXRwdXQgPSBuZXcgVWludDhBcnJheShiaW5hcnkubGVuZ3RoKTtcbiAgZm9yIChsZXQgaSA9IDA7IGkgPCBiaW5hcnkubGVuZ3RoOyBpICs9IDEpIHtcbiAgICBvdXRwdXRbaV0gPSBiaW5hcnkuY2hhckNvZGVBdChpKTtcbiAgfVxuICByZXR1cm4gb3V0cHV0O1xufVxuXG5hc3luYyBmdW5jdGlvbiBpbXBvcnRTZWNyZXQoc2VjcmV0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT4ge1xuICByZXR1cm4gY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoXG4gICAgXCJyYXdcIixcbiAgICBlbmNvZGVyLmVuY29kZShzZWNyZXQpLFxuICAgIHsgbmFtZTogXCJITUFDXCIsIGhhc2g6IFwiU0hBLTI1NlwiIH0sXG4gICAgZmFsc2UsXG4gICAgW1wic2lnblwiLCBcInZlcmlmeVwiXVxuICApO1xufVxuXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gc2lnblNoYXJpbmdQYXlsb2FkKHNlY3JldDogc3RyaW5nLCBwYXlsb2FkOiBSZWNvcmQ8c3RyaW5nLCB1bmtub3duPik6IFByb21pc2U8c3RyaW5nPiB7XG4gIGNvbnN0IGVuY29kZWRQYXlsb2FkID0gZW5jb2Rlci5lbmNvZGUoSlNPTi5zdHJpbmdpZnkocGF5bG9hZCkpO1xuICBjb25zdCBrZXkgPSBhd2FpdCBpbXBvcnRTZWNyZXQoc2VjcmV0KTtcbiAgY29uc3Qgc2lnbmF0dXJlID0gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5zaWduKFwiSE1BQ1wiLCBrZXksIGVuY29kZWRQYXlsb2FkKSk7XG4gIHJldHVybiBgJHt0b0Jhc2U2NFVybChlbmNvZGVkUGF5bG9hZCl9LiR7dG9CYXNlNjRVcmwoc2lnbmF0dXJlKX1gO1xufVxuXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gdmVyaWZ5U2hhcmluZ1BheWxvYWQ8VD4oc2VjcmV0OiBzdHJpbmcsIHRva2VuOiBzdHJpbmcsIG5vdzogbnVtYmVyKTogUHJvbWlzZTxUPiB7XG4gIGNvbnN0IFtwYXlsb2FkUGFydCwgc2lnbmF0dXJlUGFydF0gPSB0b2tlbi5zcGxpdChcIi5cIik7XG4gIGlmICghcGF5bG9hZFBhcnQgfHwgIXNpZ25hdHVyZVBhcnQpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoXCJpbnZhbGlkIHNoYXJpbmcgdG9rZW5cIik7XG4gIH1cblxuICBjb25zdCBwYXlsb2FkQnl0ZXMgPSBmcm9tQmFzZTY0VXJsKHBheWxvYWRQYXJ0KTtcbiAgY29uc3Qgc2lnbmF0dXJlQnl0ZXMgPSBmcm9tQmFzZTY0VXJsKHNpZ25hdHVyZVBhcnQpO1xuICBjb25zdCBrZXkgPSBhd2FpdCBpbXBvcnRTZWNyZXQoc2VjcmV0KTtcbiAgY29uc3QgcGF5bG9hZEJ1ZmZlciA9IHBheWxvYWRCeXRlcy5idWZmZXIuc2xpY2UoXG4gICAgcGF5bG9hZEJ5dGVzLmJ5dGVPZmZzZXQsXG4gICAgcGF5bG9hZEJ5dGVzLmJ5dGVPZmZzZXQgKyBwYXlsb2FkQnl0ZXMuYnl0ZUxlbmd0aFxuICApIGFzIEFycmF5QnVmZmVyO1xuICBjb25zdCBzaWduYXR1cmVCdWZmZXIgPSBzaWduYXR1cmVCeXRlcy5idWZmZXIuc2xpY2UoXG4gICAgc2lnbmF0dXJlQnl0ZXMuYnl0ZU9mZnNldCxcbiAgICBzaWduYXR1cmVCeXRlcy5ieXRlT2Zmc2V0ICsgc2lnbmF0dXJlQnl0ZXMuYnl0ZUxlbmd0aFxuICApIGFzIEFycmF5QnVmZmVyO1xuICBjb25zdCB2YWxpZCA9IGF3YWl0IGNyeXB0by5zdWJ0bGUudmVyaWZ5KFwiSE1BQ1wiLCBrZXksIHNpZ25hdHVyZUJ1ZmZlciwgcGF5bG9hZEJ1ZmZlcik7XG4gIGlmICghdmFsaWQpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoXCJpbnZhbGlkIHNoYXJpbmcgdG9rZW5cIik7XG4gIH1cblxuICBjb25zdCBwYXlsb2FkID0gSlNPTi5wYXJzZShuZXcgVGV4dERlY29kZXIoKS5kZWNvZGUocGF5bG9hZEJ5dGVzKSkgYXMgVCAmIHsgZXhwaXJlc0F0PzogbnVtYmVyIH07XG4gIGlmIChwYXlsb2FkLmV4cGlyZXNBdCAhPT0gdW5kZWZpbmVkICYmIHBheWxvYWQuZXhwaXJlc0F0IDw9IG5vdykge1xuICAgIHRocm93IG5ldyBFcnJvcihcInNoYXJpbmcgdG9rZW4gZXhwaXJlZFwiKTtcbiAgfVxuICByZXR1cm4gcGF5bG9hZDtcbn1cclxuIiwgImltcG9ydCB0eXBlIHtcbiAgQXBwZW5kRW52ZWxvcGVSZXF1ZXN0LFxuICBCb290c3RyYXBUb2tlbixcbiAgRGV2aWNlUnVudGltZVNjb3BlLFxuICBEZXZpY2VSdW50aW1lVG9rZW4sXG4gIEluYm94QXBwZW5kQ2FwYWJpbGl0eSxcbiAgS2V5UGFja2FnZVdyaXRlVG9rZW4sXG4gIFNoYXJlZFN0YXRlV3JpdGVUb2tlblxufSBmcm9tIFwiLi4vdHlwZXMvY29udHJhY3RzXCI7XG5pbXBvcnQgeyBDVVJSRU5UX01PREVMX1ZFUlNJT04gfSBmcm9tIFwiLi4vdHlwZXMvY29udHJhY3RzXCI7XG5pbXBvcnQgeyB2ZXJpZnlTaGFyaW5nUGF5bG9hZCB9IGZyb20gXCIuLi9zdG9yYWdlL3NoYXJpbmdcIjtcblxuZXhwb3J0IGNsYXNzIEh0dHBFcnJvciBleHRlbmRzIEVycm9yIHtcbiAgcmVhZG9ubHkgc3RhdHVzOiBudW1iZXI7XG4gIHJlYWRvbmx5IGNvZGU6IHN0cmluZztcblxuICBjb25zdHJ1Y3RvcihzdGF0dXM6IG51bWJlciwgY29kZTogc3RyaW5nLCBtZXNzYWdlOiBzdHJpbmcpIHtcbiAgICBzdXBlcihtZXNzYWdlKTtcbiAgICB0aGlzLnN0YXR1cyA9IHN0YXR1cztcbiAgICB0aGlzLmNvZGUgPSBjb2RlO1xuICB9XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBnZXRCZWFyZXJUb2tlbihyZXF1ZXN0OiBSZXF1ZXN0KTogc3RyaW5nIHtcbiAgY29uc3QgaGVhZGVyID0gcmVxdWVzdC5oZWFkZXJzLmdldChcIkF1dGhvcml6YXRpb25cIik/LnRyaW0oKTtcbiAgaWYgKCFoZWFkZXIpIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMSwgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJtaXNzaW5nIEF1dGhvcml6YXRpb24gaGVhZGVyXCIpO1xuICB9XG4gIGlmICghaGVhZGVyLnN0YXJ0c1dpdGgoXCJCZWFyZXIgXCIpKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDEsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwiQXV0aG9yaXphdGlvbiBoZWFkZXIgbXVzdCB1c2UgQmVhcmVyIHRva2VuXCIpO1xuICB9XG4gIGNvbnN0IHRva2VuID0gaGVhZGVyLnNsaWNlKFwiQmVhcmVyIFwiLmxlbmd0aCkudHJpbSgpO1xuICBpZiAoIXRva2VuKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDEsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwiQmVhcmVyIHRva2VuIG11c3Qgbm90IGJlIGVtcHR5XCIpO1xuICB9XG4gIHJldHVybiB0b2tlbjtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIHZhbGlkYXRlQXBwZW5kQXV0aG9yaXphdGlvbihcbiAgcmVxdWVzdDogUmVxdWVzdCxcbiAgZGV2aWNlSWQ6IHN0cmluZyxcbiAgYm9keTogQXBwZW5kRW52ZWxvcGVSZXF1ZXN0LFxuICBub3c6IG51bWJlclxuKTogdm9pZCB7XG4gIGNvbnN0IHNpZ25hdHVyZSA9IGdldEJlYXJlclRva2VuKHJlcXVlc3QpO1xuICBjb25zdCBjYXBhYmlsaXR5SGVhZGVyID0gcmVxdWVzdC5oZWFkZXJzLmdldChcIlgtVGFwY2hhdC1DYXBhYmlsaXR5XCIpO1xuICBpZiAoIWNhcGFiaWxpdHlIZWFkZXIpIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMSwgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJtaXNzaW5nIFgtVGFwY2hhdC1DYXBhYmlsaXR5IGhlYWRlclwiKTtcbiAgfVxuXG4gIGxldCBjYXBhYmlsaXR5OiBJbmJveEFwcGVuZENhcGFiaWxpdHk7XG4gIHRyeSB7XG4gICAgY2FwYWJpbGl0eSA9IEpTT04ucGFyc2UoY2FwYWJpbGl0eUhlYWRlcikgYXMgSW5ib3hBcHBlbmRDYXBhYmlsaXR5O1xuICB9IGNhdGNoIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMCwgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJYLVRhcGNoYXQtQ2FwYWJpbGl0eSBpcyBub3QgdmFsaWQgSlNPTlwiKTtcbiAgfVxuXG4gIGlmIChib2R5LnZlcnNpb24gIT09IENVUlJFTlRfTU9ERUxfVkVSU0lPTiB8fCBjYXBhYmlsaXR5LnZlcnNpb24gIT09IENVUlJFTlRfTU9ERUxfVkVSU0lPTikge1xuICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAwLCBcInVuc3VwcG9ydGVkX3ZlcnNpb25cIiwgXCJhcHBlbmQgY2FwYWJpbGl0eSB2ZXJzaW9uIGlzIG5vdCBzdXBwb3J0ZWRcIik7XG4gIH1cbiAgaWYgKGNhcGFiaWxpdHkuc2lnbmF0dXJlICE9PSBzaWduYXR1cmUpIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMywgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJjYXBhYmlsaXR5IHNpZ25hdHVyZSBkb2VzIG5vdCBtYXRjaCBiZWFyZXIgdG9rZW5cIik7XG4gIH1cbiAgaWYgKGNhcGFiaWxpdHkuc2VydmljZSAhPT0gXCJpbmJveFwiKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwiY2FwYWJpbGl0eSBzZXJ2aWNlIG11c3QgYmUgaW5ib3hcIik7XG4gIH1cbiAgaWYgKCFjYXBhYmlsaXR5Lm9wZXJhdGlvbnMuaW5jbHVkZXMoXCJhcHBlbmRcIikpIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMywgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJjYXBhYmlsaXR5IGRvZXMgbm90IGdyYW50IGFwcGVuZFwiKTtcbiAgfVxuICBpZiAoY2FwYWJpbGl0eS50YXJnZXREZXZpY2VJZCAhPT0gZGV2aWNlSWQpIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMywgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJjYXBhYmlsaXR5IHRhcmdldCBkZXZpY2UgZG9lcyBub3QgbWF0Y2ggcmVxdWVzdCBwYXRoXCIpO1xuICB9XG4gIGNvbnN0IHJlcXVlc3RVcmwgPSBuZXcgVVJMKHJlcXVlc3QudXJsKTtcbiAgaWYgKGNhcGFiaWxpdHkuZW5kcG9pbnQgIT09IGAke3JlcXVlc3RVcmwub3JpZ2lufSR7cmVxdWVzdFVybC5wYXRobmFtZX1gKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwiY2FwYWJpbGl0eSBlbmRwb2ludCBkb2VzIG5vdCBtYXRjaCByZXF1ZXN0IHBhdGhcIik7XG4gIH1cbiAgaWYgKGNhcGFiaWxpdHkuZXhwaXJlc0F0IDw9IG5vdykge1xuICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAzLCBcImNhcGFiaWxpdHlfZXhwaXJlZFwiLCBcImFwcGVuZCBjYXBhYmlsaXR5IGlzIGV4cGlyZWRcIik7XG4gIH1cbiAgaWYgKGJvZHkucmVjaXBpZW50RGV2aWNlSWQgIT09IGRldmljZUlkIHx8IGJvZHkuZW52ZWxvcGUucmVjaXBpZW50RGV2aWNlSWQgIT09IGRldmljZUlkKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwicmVjaXBpZW50IGRldmljZSBkb2VzIG5vdCBtYXRjaCB0YXJnZXQgaW5ib3hcIik7XG4gIH1cbiAgaWYgKGNhcGFiaWxpdHkuY29udmVyc2F0aW9uU2NvcGU/Lmxlbmd0aCAmJiAhY2FwYWJpbGl0eS5jb252ZXJzYXRpb25TY29wZS5pbmNsdWRlcyhib2R5LmVudmVsb3BlLmNvbnZlcnNhdGlvbklkKSkge1xuICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAzLCBcImludmFsaWRfY2FwYWJpbGl0eVwiLCBcImNvbnZlcnNhdGlvbiBpcyBvdXRzaWRlIGNhcGFiaWxpdHkgc2NvcGVcIik7XG4gIH1cbiAgY29uc3Qgc2l6ZSA9IG5ldyBUZXh0RW5jb2RlcigpLmVuY29kZShKU09OLnN0cmluZ2lmeShib2R5LmVudmVsb3BlKSkuYnl0ZUxlbmd0aDtcbiAgaWYgKGNhcGFiaWxpdHkuY29uc3RyYWludHM/Lm1heEJ5dGVzICE9PSB1bmRlZmluZWQgJiYgc2l6ZSA+IGNhcGFiaWxpdHkuY29uc3RyYWludHMubWF4Qnl0ZXMpIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQxMywgXCJwYXlsb2FkX3Rvb19sYXJnZVwiLCBcImVudmVsb3BlIGV4Y2VlZHMgY2FwYWJpbGl0eSBzaXplIGxpbWl0XCIpO1xuICB9XG59XG5cbmFzeW5jIGZ1bmN0aW9uIHZlcmlmeVNpZ25lZFRva2VuPFQ+KHNlY3JldDogc3RyaW5nLCByZXF1ZXN0OiBSZXF1ZXN0LCBub3c6IG51bWJlcik6IFByb21pc2U8VD4ge1xuICBjb25zdCB0b2tlbiA9IGdldEJlYXJlclRva2VuKHJlcXVlc3QpO1xuICB0cnkge1xuICAgIHJldHVybiBhd2FpdCB2ZXJpZnlTaGFyaW5nUGF5bG9hZDxUPihzZWNyZXQsIHRva2VuLCBub3cpO1xuICB9IGNhdGNoIChlcnJvcikge1xuICAgIGNvbnN0IG1lc3NhZ2UgPSBlcnJvciBpbnN0YW5jZW9mIEVycm9yID8gZXJyb3IubWVzc2FnZSA6IFwiaW52YWxpZCBzaWduZWQgdG9rZW5cIjtcbiAgICBpZiAobWVzc2FnZS5pbmNsdWRlcyhcImV4cGlyZWRcIikpIHtcbiAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAzLCBcImNhcGFiaWxpdHlfZXhwaXJlZFwiLCBtZXNzYWdlKTtcbiAgICB9XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIG1lc3NhZ2UpO1xuICB9XG59XG5cbmFzeW5jIGZ1bmN0aW9uIHZlcmlmeURldmljZVJ1bnRpbWVUb2tlbihyZXF1ZXN0OiBSZXF1ZXN0LCBzZWNyZXQ6IHN0cmluZywgbm93OiBudW1iZXIpOiBQcm9taXNlPERldmljZVJ1bnRpbWVUb2tlbj4ge1xuICBjb25zdCB0b2tlbiA9IGF3YWl0IHZlcmlmeVNpZ25lZFRva2VuPERldmljZVJ1bnRpbWVUb2tlbj4oc2VjcmV0LCByZXF1ZXN0LCBub3cpO1xuICBpZiAodG9rZW4udmVyc2lvbiAhPT0gQ1VSUkVOVF9NT0RFTF9WRVJTSU9OKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDAsIFwidW5zdXBwb3J0ZWRfdmVyc2lvblwiLCBcImRldmljZSBydW50aW1lIHRva2VuIHZlcnNpb24gaXMgbm90IHN1cHBvcnRlZFwiKTtcbiAgfVxuICBpZiAodG9rZW4uc2VydmljZSAhPT0gXCJkZXZpY2VfcnVudGltZVwiKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwidG9rZW4gc2VydmljZSBtdXN0IGJlIGRldmljZV9ydW50aW1lXCIpO1xuICB9XG4gIGlmICghdG9rZW4udXNlcklkIHx8ICF0b2tlbi5kZXZpY2VJZCB8fCAhdG9rZW4uc2NvcGVzLmxlbmd0aCkge1xuICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAzLCBcImludmFsaWRfY2FwYWJpbGl0eVwiLCBcImRldmljZSBydW50aW1lIHRva2VuIGlzIG1hbGZvcm1lZFwiKTtcbiAgfVxuICByZXR1cm4gdG9rZW47XG59XG5cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiB2YWxpZGF0ZUJvb3RzdHJhcEF1dGhvcml6YXRpb24oXG4gIHJlcXVlc3Q6IFJlcXVlc3QsXG4gIHNlY3JldDogc3RyaW5nLFxuICB1c2VySWQ6IHN0cmluZyxcbiAgZGV2aWNlSWQ6IHN0cmluZyxcbiAgbm93OiBudW1iZXJcbik6IFByb21pc2U8Qm9vdHN0cmFwVG9rZW4+IHtcbiAgY29uc3QgdG9rZW4gPSBhd2FpdCB2ZXJpZnlTaWduZWRUb2tlbjxCb290c3RyYXBUb2tlbj4oc2VjcmV0LCByZXF1ZXN0LCBub3cpO1xuICBpZiAodG9rZW4udmVyc2lvbiAhPT0gQ1VSUkVOVF9NT0RFTF9WRVJTSU9OKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDAsIFwidW5zdXBwb3J0ZWRfdmVyc2lvblwiLCBcImJvb3RzdHJhcCB0b2tlbiB2ZXJzaW9uIGlzIG5vdCBzdXBwb3J0ZWRcIik7XG4gIH1cbiAgaWYgKHRva2VuLnNlcnZpY2UgIT09IFwiYm9vdHN0cmFwXCIpIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMywgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJ0b2tlbiBzZXJ2aWNlIG11c3QgYmUgYm9vdHN0cmFwXCIpO1xuICB9XG4gIGlmICh0b2tlbi51c2VySWQgIT09IHVzZXJJZCB8fCB0b2tlbi5kZXZpY2VJZCAhPT0gZGV2aWNlSWQpIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMywgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJib290c3RyYXAgdG9rZW4gc2NvcGUgZG9lcyBub3QgbWF0Y2ggcmVxdWVzdFwiKTtcbiAgfVxuICBpZiAoIXRva2VuLm9wZXJhdGlvbnMuaW5jbHVkZXMoXCJpc3N1ZV9kZXZpY2VfYnVuZGxlXCIpKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwiYm9vdHN0cmFwIHRva2VuIGRvZXMgbm90IGdyYW50IGRldmljZSBidW5kbGUgaXNzdWFuY2VcIik7XG4gIH1cbiAgcmV0dXJuIHRva2VuO1xufVxuXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gdmFsaWRhdGVBbnlEZXZpY2VSdW50aW1lQXV0aG9yaXphdGlvbihcbiAgcmVxdWVzdDogUmVxdWVzdCxcbiAgc2VjcmV0OiBzdHJpbmcsXG4gIHNjb3BlOiBEZXZpY2VSdW50aW1lU2NvcGUsXG4gIG5vdzogbnVtYmVyXG4pOiBQcm9taXNlPERldmljZVJ1bnRpbWVUb2tlbj4ge1xuICBjb25zdCB0b2tlbiA9IGF3YWl0IHZlcmlmeURldmljZVJ1bnRpbWVUb2tlbihyZXF1ZXN0LCBzZWNyZXQsIG5vdyk7XG4gIGlmICghdG9rZW4uc2NvcGVzLmluY2x1ZGVzKHNjb3BlKSkge1xuICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAzLCBcImludmFsaWRfY2FwYWJpbGl0eVwiLCBgZGV2aWNlIHJ1bnRpbWUgdG9rZW4gZG9lcyBub3QgZ3JhbnQgJHtzY29wZX1gKTtcbiAgfVxuICByZXR1cm4gdG9rZW47XG59XG5cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiB2YWxpZGF0ZURldmljZVJ1bnRpbWVBdXRob3JpemF0aW9uKFxuICByZXF1ZXN0OiBSZXF1ZXN0LFxuICBzZWNyZXQ6IHN0cmluZyxcbiAgdXNlcklkOiBzdHJpbmcsXG4gIGRldmljZUlkOiBzdHJpbmcsXG4gIHNjb3BlOiBEZXZpY2VSdW50aW1lU2NvcGUsXG4gIG5vdzogbnVtYmVyXG4pOiBQcm9taXNlPERldmljZVJ1bnRpbWVUb2tlbj4ge1xuICBjb25zdCB0b2tlbiA9IGF3YWl0IHZhbGlkYXRlQW55RGV2aWNlUnVudGltZUF1dGhvcml6YXRpb24ocmVxdWVzdCwgc2VjcmV0LCBzY29wZSwgbm93KTtcbiAgaWYgKHRva2VuLnVzZXJJZCAhPT0gdXNlcklkIHx8IHRva2VuLmRldmljZUlkICE9PSBkZXZpY2VJZCkge1xuICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAzLCBcImludmFsaWRfY2FwYWJpbGl0eVwiLCBcImRldmljZSBydW50aW1lIHRva2VuIHNjb3BlIGRvZXMgbm90IG1hdGNoIHJlcXVlc3QgcGF0aFwiKTtcbiAgfVxuICByZXR1cm4gdG9rZW47XG59XG5cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiB2YWxpZGF0ZURldmljZVJ1bnRpbWVBdXRob3JpemF0aW9uRm9yRGV2aWNlKFxuICByZXF1ZXN0OiBSZXF1ZXN0LFxuICBzZWNyZXQ6IHN0cmluZyxcbiAgZGV2aWNlSWQ6IHN0cmluZyxcbiAgc2NvcGU6IERldmljZVJ1bnRpbWVTY29wZSxcbiAgbm93OiBudW1iZXJcbik6IFByb21pc2U8RGV2aWNlUnVudGltZVRva2VuPiB7XG4gIGNvbnN0IHRva2VuID0gYXdhaXQgdmFsaWRhdGVBbnlEZXZpY2VSdW50aW1lQXV0aG9yaXphdGlvbihyZXF1ZXN0LCBzZWNyZXQsIHNjb3BlLCBub3cpO1xuICBpZiAodG9rZW4uZGV2aWNlSWQgIT09IGRldmljZUlkKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwiZGV2aWNlIHJ1bnRpbWUgdG9rZW4gc2NvcGUgZG9lcyBub3QgbWF0Y2ggcmVxdWVzdCBwYXRoXCIpO1xuICB9XG4gIHJldHVybiB0b2tlbjtcbn1cblxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHZhbGlkYXRlU2hhcmVkU3RhdGVXcml0ZUF1dGhvcml6YXRpb24oXG4gIHJlcXVlc3Q6IFJlcXVlc3QsXG4gIHNlY3JldDogc3RyaW5nLFxuICB1c2VySWQ6IHN0cmluZyxcbiAgZGV2aWNlSWQ6IHN0cmluZyxcbiAgb2JqZWN0S2luZDogXCJpZGVudGl0eV9idW5kbGVcIiB8IFwiZGV2aWNlX3N0YXR1c1wiLFxuICBub3c6IG51bWJlclxuKTogUHJvbWlzZTxTaGFyZWRTdGF0ZVdyaXRlVG9rZW4gfCBEZXZpY2VSdW50aW1lVG9rZW4+IHtcbiAgdHJ5IHtcbiAgICByZXR1cm4gYXdhaXQgdmFsaWRhdGVEZXZpY2VSdW50aW1lQXV0aG9yaXphdGlvbihyZXF1ZXN0LCBzZWNyZXQsIHVzZXJJZCwgZGV2aWNlSWQsIFwic2hhcmVkX3N0YXRlX3dyaXRlXCIsIG5vdyk7XG4gIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgaWYgKCEoZXJyb3IgaW5zdGFuY2VvZiBIdHRwRXJyb3IpIHx8IGVycm9yLmNvZGUgPT09IFwiY2FwYWJpbGl0eV9leHBpcmVkXCIpIHtcbiAgICAgIHRocm93IGVycm9yO1xuICAgIH1cbiAgfVxuXG4gIGNvbnN0IHRva2VuID0gYXdhaXQgdmVyaWZ5U2lnbmVkVG9rZW48U2hhcmVkU3RhdGVXcml0ZVRva2VuPihzZWNyZXQsIHJlcXVlc3QsIG5vdyk7XG4gIGlmICh0b2tlbi52ZXJzaW9uICE9PSBDVVJSRU5UX01PREVMX1ZFUlNJT04pIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMCwgXCJ1bnN1cHBvcnRlZF92ZXJzaW9uXCIsIFwic2hhcmVkLXN0YXRlIHRva2VuIHZlcnNpb24gaXMgbm90IHN1cHBvcnRlZFwiKTtcbiAgfVxuICBpZiAodG9rZW4uc2VydmljZSAhPT0gXCJzaGFyZWRfc3RhdGVcIikge1xuICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAzLCBcImludmFsaWRfY2FwYWJpbGl0eVwiLCBcInRva2VuIHNlcnZpY2UgbXVzdCBiZSBzaGFyZWRfc3RhdGVcIik7XG4gIH1cbiAgaWYgKHRva2VuLnVzZXJJZCAhPT0gdXNlcklkKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwidG9rZW4gdXNlcklkIGRvZXMgbm90IG1hdGNoIHJlcXVlc3QgcGF0aFwiKTtcbiAgfVxuICBpZiAoIXRva2VuLm9iamVjdEtpbmRzLmluY2x1ZGVzKG9iamVjdEtpbmQpKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwidG9rZW4gZG9lcyBub3QgZ3JhbnQgdGhpcyBzaGFyZWQtc3RhdGUgb2JqZWN0IGtpbmRcIik7XG4gIH1cbiAgcmV0dXJuIHRva2VuO1xufVxuXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gdmFsaWRhdGVLZXlQYWNrYWdlV3JpdGVBdXRob3JpemF0aW9uKFxuICByZXF1ZXN0OiBSZXF1ZXN0LFxuICBzZWNyZXQ6IHN0cmluZyxcbiAgdXNlcklkOiBzdHJpbmcsXG4gIGRldmljZUlkOiBzdHJpbmcsXG4gIGtleVBhY2thZ2VJZDogc3RyaW5nIHwgdW5kZWZpbmVkLFxuICBub3c6IG51bWJlclxuKTogUHJvbWlzZTxLZXlQYWNrYWdlV3JpdGVUb2tlbiB8IERldmljZVJ1bnRpbWVUb2tlbj4ge1xuICB0cnkge1xuICAgIHJldHVybiBhd2FpdCB2YWxpZGF0ZURldmljZVJ1bnRpbWVBdXRob3JpemF0aW9uKHJlcXVlc3QsIHNlY3JldCwgdXNlcklkLCBkZXZpY2VJZCwgXCJrZXlwYWNrYWdlX3dyaXRlXCIsIG5vdyk7XG4gIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgaWYgKCEoZXJyb3IgaW5zdGFuY2VvZiBIdHRwRXJyb3IpIHx8IGVycm9yLmNvZGUgPT09IFwiY2FwYWJpbGl0eV9leHBpcmVkXCIpIHtcbiAgICAgIHRocm93IGVycm9yO1xuICAgIH1cbiAgfVxuXG4gIGNvbnN0IHRva2VuID0gYXdhaXQgdmVyaWZ5U2lnbmVkVG9rZW48S2V5UGFja2FnZVdyaXRlVG9rZW4+KHNlY3JldCwgcmVxdWVzdCwgbm93KTtcbiAgaWYgKHRva2VuLnZlcnNpb24gIT09IENVUlJFTlRfTU9ERUxfVkVSU0lPTikge1xuICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAwLCBcInVuc3VwcG9ydGVkX3ZlcnNpb25cIiwgXCJrZXlwYWNrYWdlIHRva2VuIHZlcnNpb24gaXMgbm90IHN1cHBvcnRlZFwiKTtcbiAgfVxuICBpZiAodG9rZW4uc2VydmljZSAhPT0gXCJrZXlwYWNrYWdlc1wiKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwidG9rZW4gc2VydmljZSBtdXN0IGJlIGtleXBhY2thZ2VzXCIpO1xuICB9XG4gIGlmICh0b2tlbi51c2VySWQgIT09IHVzZXJJZCB8fCB0b2tlbi5kZXZpY2VJZCAhPT0gZGV2aWNlSWQpIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMywgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJ0b2tlbiBzY29wZSBkb2VzIG5vdCBtYXRjaCByZXF1ZXN0IHBhdGhcIik7XG4gIH1cbiAgaWYgKHRva2VuLmtleVBhY2thZ2VJZCAmJiB0b2tlbi5rZXlQYWNrYWdlSWQgIT09IGtleVBhY2thZ2VJZCkge1xuICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAzLCBcImludmFsaWRfY2FwYWJpbGl0eVwiLCBcInRva2VuIGtleVBhY2thZ2VJZCBkb2VzIG5vdCBtYXRjaCByZXF1ZXN0IHBhdGhcIik7XG4gIH1cbiAgcmV0dXJuIHRva2VuO1xufVxyXG4iLCAiaW1wb3J0IHsgSHR0cEVycm9yIH0gZnJvbSBcIi4uL2F1dGgvY2FwYWJpbGl0eVwiO1xuaW1wb3J0IHR5cGUge1xuICBBY2tSZXF1ZXN0LFxuICBBY2tSZXN1bHQsXG4gIEFwcGVuZEVudmVsb3BlUmVxdWVzdCxcbiAgQXBwZW5kRW52ZWxvcGVSZXN1bHQsXG4gIEZldGNoTWVzc2FnZXNSZXF1ZXN0LFxuICBGZXRjaE1lc3NhZ2VzUmVzdWx0LFxuICBJbmJveFJlY29yZCxcbiAgUmVhbHRpbWVFdmVudFxufSBmcm9tIFwiLi4vdHlwZXMvY29udHJhY3RzXCI7XG5pbXBvcnQgdHlwZSB7IER1cmFibGVPYmplY3RTdG9yYWdlTGlrZSwgSnNvbkJsb2JTdG9yZSwgU2Vzc2lvblNpbmsgfSBmcm9tIFwiLi4vdHlwZXMvcnVudGltZVwiO1xuXG5pbnRlcmZhY2UgSW5ib3hNZXRhIHtcbiAgaGVhZFNlcTogbnVtYmVyO1xuICBhY2tlZFNlcTogbnVtYmVyO1xuICByZXRlbnRpb25EYXlzOiBudW1iZXI7XG4gIG1heElubGluZUJ5dGVzOiBudW1iZXI7XG59XG5cbmludGVyZmFjZSBTdG9yZWRSZWNvcmRJbmRleCB7XG4gIHNlcTogbnVtYmVyO1xuICBtZXNzYWdlSWQ6IHN0cmluZztcbiAgcmVjaXBpZW50RGV2aWNlSWQ6IHN0cmluZztcbiAgcmVjZWl2ZWRBdDogbnVtYmVyO1xuICBleHBpcmVzQXQ/OiBudW1iZXI7XG4gIHN0YXRlOiBcImF2YWlsYWJsZVwiO1xuICBpbmxpbmVSZWNvcmQ/OiBJbmJveFJlY29yZDtcbiAgcGF5bG9hZFJlZj86IHN0cmluZztcbn1cblxuY29uc3QgTUVUQV9LRVkgPSBcIm1ldGFcIjtcbmNvbnN0IElERU1QT1RFTkNZX1BSRUZJWCA9IFwiaWRlbXBvdGVuY3k6XCI7XG5jb25zdCBSRUNPUkRfUFJFRklYID0gXCJyZWNvcmQ6XCI7XG5cbmV4cG9ydCBjbGFzcyBJbmJveFNlcnZpY2Uge1xuICBwcml2YXRlIHJlYWRvbmx5IGRldmljZUlkOiBzdHJpbmc7XG4gIHByaXZhdGUgcmVhZG9ubHkgc3RhdGU6IER1cmFibGVPYmplY3RTdG9yYWdlTGlrZTtcbiAgcHJpdmF0ZSByZWFkb25seSBzcGlsbFN0b3JlOiBKc29uQmxvYlN0b3JlO1xuICBwcml2YXRlIHJlYWRvbmx5IHNlc3Npb25zOiBTZXNzaW9uU2lua1tdO1xuICBwcml2YXRlIHJlYWRvbmx5IGRlZmF1bHRzOiBJbmJveE1ldGE7XG5cbiAgY29uc3RydWN0b3IoXG4gICAgZGV2aWNlSWQ6IHN0cmluZyxcbiAgICBzdGF0ZTogRHVyYWJsZU9iamVjdFN0b3JhZ2VMaWtlLFxuICAgIHNwaWxsU3RvcmU6IEpzb25CbG9iU3RvcmUsXG4gICAgc2Vzc2lvbnM6IFNlc3Npb25TaW5rW10sXG4gICAgZGVmYXVsdHM6IEluYm94TWV0YVxuICApIHtcbiAgICB0aGlzLmRldmljZUlkID0gZGV2aWNlSWQ7XG4gICAgdGhpcy5zdGF0ZSA9IHN0YXRlO1xuICAgIHRoaXMuc3BpbGxTdG9yZSA9IHNwaWxsU3RvcmU7XG4gICAgdGhpcy5zZXNzaW9ucyA9IHNlc3Npb25zO1xuICAgIHRoaXMuZGVmYXVsdHMgPSBkZWZhdWx0cztcbiAgfVxuXG4gIGFzeW5jIGFwcGVuZEVudmVsb3BlKGlucHV0OiBBcHBlbmRFbnZlbG9wZVJlcXVlc3QsIG5vdzogbnVtYmVyKTogUHJvbWlzZTxBcHBlbmRFbnZlbG9wZVJlc3VsdD4ge1xuICAgIHRoaXMudmFsaWRhdGVBcHBlbmRSZXF1ZXN0KGlucHV0KTtcbiAgICBjb25zdCBtZXRhID0gYXdhaXQgdGhpcy5nZXRNZXRhKCk7XG4gICAgY29uc3QgZXhpc3RpbmdTZXEgPSBhd2FpdCB0aGlzLnN0YXRlLmdldDxudW1iZXI+KGAke0lERU1QT1RFTkNZX1BSRUZJWH0ke2lucHV0LmVudmVsb3BlLm1lc3NhZ2VJZH1gKTtcbiAgICBpZiAoZXhpc3RpbmdTZXEgIT09IHVuZGVmaW5lZCkge1xuICAgICAgcmV0dXJuIHsgYWNjZXB0ZWQ6IHRydWUsIHNlcTogZXhpc3RpbmdTZXEgfTtcbiAgICB9XG5cbiAgICBjb25zdCBzZXEgPSBtZXRhLmhlYWRTZXEgKyAxO1xuICAgIGNvbnN0IGV4cGlyZXNBdCA9IG5vdyArIG1ldGEucmV0ZW50aW9uRGF5cyAqIDI0ICogNjAgKiA2MCAqIDEwMDA7XG4gICAgY29uc3QgcmVjb3JkOiBJbmJveFJlY29yZCA9IHtcbiAgICAgIHNlcSxcbiAgICAgIHJlY2lwaWVudERldmljZUlkOiB0aGlzLmRldmljZUlkLFxuICAgICAgbWVzc2FnZUlkOiBpbnB1dC5lbnZlbG9wZS5tZXNzYWdlSWQsXG4gICAgICByZWNlaXZlZEF0OiBub3csXG4gICAgICBleHBpcmVzQXQsXG4gICAgICBzdGF0ZTogXCJhdmFpbGFibGVcIixcbiAgICAgIGVudmVsb3BlOiBpbnB1dC5lbnZlbG9wZVxuICAgIH07XG4gICAgY29uc3Qgc2VyaWFsaXplZCA9IEpTT04uc3RyaW5naWZ5KHJlY29yZCk7XG4gICAgY29uc3Qgc3RvcmFnZUtleSA9IGAke1JFQ09SRF9QUkVGSVh9JHtzZXF9YDtcblxuICAgIGlmIChuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUoc2VyaWFsaXplZCkuYnl0ZUxlbmd0aCA8PSBtZXRhLm1heElubGluZUJ5dGVzICYmIGlucHV0LmVudmVsb3BlLmlubGluZUNpcGhlcnRleHQpIHtcbiAgICAgIGNvbnN0IGlubGluZUluZGV4OiBTdG9yZWRSZWNvcmRJbmRleCA9IHtcbiAgICAgICAgc2VxLFxuICAgICAgICBtZXNzYWdlSWQ6IHJlY29yZC5tZXNzYWdlSWQsXG4gICAgICAgIHJlY2lwaWVudERldmljZUlkOiByZWNvcmQucmVjaXBpZW50RGV2aWNlSWQsXG4gICAgICAgIHJlY2VpdmVkQXQ6IHJlY29yZC5yZWNlaXZlZEF0LFxuICAgICAgICBleHBpcmVzQXQsXG4gICAgICAgIHN0YXRlOiByZWNvcmQuc3RhdGUsXG4gICAgICAgIGlubGluZVJlY29yZDogcmVjb3JkXG4gICAgICB9O1xuICAgICAgYXdhaXQgdGhpcy5zdGF0ZS5wdXQoc3RvcmFnZUtleSwgaW5saW5lSW5kZXgpO1xuICAgIH0gZWxzZSB7XG4gICAgICBjb25zdCBwYXlsb2FkUmVmID0gYGluYm94LXBheWxvYWQvJHt0aGlzLmRldmljZUlkfS8ke3NlcX0uanNvbmA7XG4gICAgICBhd2FpdCB0aGlzLnNwaWxsU3RvcmUucHV0SnNvbihwYXlsb2FkUmVmLCByZWNvcmQpO1xuICAgICAgY29uc3QgaW5kZXhlZDogU3RvcmVkUmVjb3JkSW5kZXggPSB7XG4gICAgICAgIHNlcSxcbiAgICAgICAgbWVzc2FnZUlkOiByZWNvcmQubWVzc2FnZUlkLFxuICAgICAgICByZWNpcGllbnREZXZpY2VJZDogcmVjb3JkLnJlY2lwaWVudERldmljZUlkLFxuICAgICAgICByZWNlaXZlZEF0OiByZWNvcmQucmVjZWl2ZWRBdCxcbiAgICAgICAgZXhwaXJlc0F0LFxuICAgICAgICBzdGF0ZTogcmVjb3JkLnN0YXRlLFxuICAgICAgICBwYXlsb2FkUmVmXG4gICAgICB9O1xuICAgICAgYXdhaXQgdGhpcy5zdGF0ZS5wdXQoc3RvcmFnZUtleSwgaW5kZXhlZCk7XG4gICAgfVxuXG4gICAgYXdhaXQgdGhpcy5zdGF0ZS5wdXQoYCR7SURFTVBPVEVOQ1lfUFJFRklYfSR7cmVjb3JkLm1lc3NhZ2VJZH1gLCBzZXEpO1xuICAgIGF3YWl0IHRoaXMuc3RhdGUucHV0KE1FVEFfS0VZLCB7IC4uLm1ldGEsIGhlYWRTZXE6IHNlcSB9KTtcbiAgICBhd2FpdCB0aGlzLnN0YXRlLnNldEFsYXJtKGV4cGlyZXNBdCk7XG5cbiAgICB0aGlzLnB1Ymxpc2goe1xuICAgICAgZXZlbnQ6IFwiaGVhZF91cGRhdGVkXCIsXG4gICAgICBkZXZpY2VJZDogdGhpcy5kZXZpY2VJZCxcbiAgICAgIHNlcVxuICAgIH0pO1xuICAgIHRoaXMucHVibGlzaCh7XG4gICAgICBldmVudDogXCJpbmJveF9yZWNvcmRfYXZhaWxhYmxlXCIsXG4gICAgICBkZXZpY2VJZDogdGhpcy5kZXZpY2VJZCxcbiAgICAgIHNlcSxcbiAgICAgIHJlY29yZFxuICAgIH0pO1xuXG4gICAgcmV0dXJuIHsgYWNjZXB0ZWQ6IHRydWUsIHNlcSB9O1xuICB9XG5cbiAgYXN5bmMgZmV0Y2hNZXNzYWdlcyhpbnB1dDogRmV0Y2hNZXNzYWdlc1JlcXVlc3QpOiBQcm9taXNlPEZldGNoTWVzc2FnZXNSZXN1bHQ+IHtcbiAgICBpZiAoaW5wdXQuZGV2aWNlSWQgIT09IHRoaXMuZGV2aWNlSWQpIHtcbiAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAwLCBcImludmFsaWRfaW5wdXRcIiwgXCJkZXZpY2VfaWQgZG9lcyBub3QgbWF0Y2ggaW5ib3ggcm91dGVcIik7XG4gICAgfVxuICAgIGlmIChpbnB1dC5saW1pdCA8PSAwKSB7XG4gICAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMCwgXCJpbnZhbGlkX2lucHV0XCIsIFwibGltaXQgbXVzdCBiZSBncmVhdGVyIHRoYW4gemVyb1wiKTtcbiAgICB9XG5cbiAgICBjb25zdCBtZXRhID0gYXdhaXQgdGhpcy5nZXRNZXRhKCk7XG4gICAgY29uc3QgcmVjb3JkczogSW5ib3hSZWNvcmRbXSA9IFtdO1xuICAgIGNvbnN0IHVwcGVyID0gTWF0aC5taW4obWV0YS5oZWFkU2VxLCBpbnB1dC5mcm9tU2VxICsgaW5wdXQubGltaXQgLSAxKTtcbiAgICBmb3IgKGxldCBzZXEgPSBpbnB1dC5mcm9tU2VxOyBzZXEgPD0gdXBwZXI7IHNlcSArPSAxKSB7XG4gICAgICBjb25zdCBpbmRleCA9IGF3YWl0IHRoaXMuc3RhdGUuZ2V0PFN0b3JlZFJlY29yZEluZGV4PihgJHtSRUNPUkRfUFJFRklYfSR7c2VxfWApO1xuICAgICAgaWYgKCFpbmRleCkge1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cbiAgICAgIGlmIChpbmRleC5pbmxpbmVSZWNvcmQpIHtcbiAgICAgICAgcmVjb3Jkcy5wdXNoKGluZGV4LmlubGluZVJlY29yZCk7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuICAgICAgaWYgKCFpbmRleC5wYXlsb2FkUmVmKSB7XG4gICAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNTAwLCBcInRlbXBvcmFyeV91bmF2YWlsYWJsZVwiLCBcInJlY29yZCBwYXlsb2FkIHJlZmVyZW5jZSBpcyBtaXNzaW5nXCIpO1xuICAgICAgfVxuICAgICAgY29uc3QgcmVjb3JkID0gYXdhaXQgdGhpcy5zcGlsbFN0b3JlLmdldEpzb248SW5ib3hSZWNvcmQ+KGluZGV4LnBheWxvYWRSZWYpO1xuICAgICAgaWYgKCFyZWNvcmQpIHtcbiAgICAgICAgdGhyb3cgbmV3IEh0dHBFcnJvcig1MDAsIFwidGVtcG9yYXJ5X3VuYXZhaWxhYmxlXCIsIFwicmVjb3JkIHBheWxvYWQgaXMgbWlzc2luZ1wiKTtcbiAgICAgIH1cbiAgICAgIHJlY29yZHMucHVzaChyZWNvcmQpO1xuICAgIH1cbiAgICByZXR1cm4ge1xuICAgICAgdG9TZXE6IHJlY29yZHMubGVuZ3RoID4gMCA/IHJlY29yZHNbcmVjb3Jkcy5sZW5ndGggLSAxXS5zZXEgOiBtZXRhLmhlYWRTZXEsXG4gICAgICByZWNvcmRzXG4gICAgfTtcbiAgfVxuXG4gIGFzeW5jIGFjayhpbnB1dDogQWNrUmVxdWVzdCk6IFByb21pc2U8QWNrUmVzdWx0PiB7XG4gICAgaWYgKGlucHV0LmFjay5kZXZpY2VJZCAhPT0gdGhpcy5kZXZpY2VJZCkge1xuICAgICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDAsIFwiaW52YWxpZF9pbnB1dFwiLCBcImFjayBkZXZpY2VfaWQgZG9lcyBub3QgbWF0Y2ggaW5ib3ggcm91dGVcIik7XG4gICAgfVxuICAgIGNvbnN0IG1ldGEgPSBhd2FpdCB0aGlzLmdldE1ldGEoKTtcbiAgICBjb25zdCBhY2tTZXEgPSBNYXRoLm1heChtZXRhLmFja2VkU2VxLCBpbnB1dC5hY2suYWNrU2VxKTtcbiAgICBhd2FpdCB0aGlzLnN0YXRlLnB1dChNRVRBX0tFWSwgeyAuLi5tZXRhLCBhY2tlZFNlcTogYWNrU2VxIH0pO1xuICAgIGF3YWl0IHRoaXMuc3RhdGUuc2V0QWxhcm0oRGF0ZS5ub3coKSk7XG4gICAgcmV0dXJuIHsgYWNjZXB0ZWQ6IHRydWUsIGFja1NlcSB9O1xuICB9XG5cbiAgYXN5bmMgZ2V0SGVhZCgpOiBQcm9taXNlPHsgaGVhZFNlcTogbnVtYmVyIH0+IHtcbiAgICBjb25zdCBtZXRhID0gYXdhaXQgdGhpcy5nZXRNZXRhKCk7XG4gICAgcmV0dXJuIHsgaGVhZFNlcTogbWV0YS5oZWFkU2VxIH07XG4gIH1cblxuICBhc3luYyBjbGVhbkV4cGlyZWRSZWNvcmRzKG5vdzogbnVtYmVyKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgbWV0YSA9IGF3YWl0IHRoaXMuZ2V0TWV0YSgpO1xuICAgIGZvciAobGV0IHNlcSA9IDE7IHNlcSA8PSBtZXRhLmFja2VkU2VxOyBzZXEgKz0gMSkge1xuICAgICAgY29uc3Qga2V5ID0gYCR7UkVDT1JEX1BSRUZJWH0ke3NlcX1gO1xuICAgICAgY29uc3QgaW5kZXggPSBhd2FpdCB0aGlzLnN0YXRlLmdldDxTdG9yZWRSZWNvcmRJbmRleD4oa2V5KTtcbiAgICAgIGlmICghaW5kZXggfHwgaW5kZXguZXhwaXJlc0F0ID09PSB1bmRlZmluZWQgfHwgaW5kZXguZXhwaXJlc0F0ID4gbm93KSB7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuICAgICAgaWYgKGluZGV4LnBheWxvYWRSZWYpIHtcbiAgICAgICAgYXdhaXQgdGhpcy5zcGlsbFN0b3JlLmRlbGV0ZShpbmRleC5wYXlsb2FkUmVmKTtcbiAgICAgIH1cbiAgICAgIGF3YWl0IHRoaXMuc3RhdGUuZGVsZXRlKGtleSk7XG4gICAgICBhd2FpdCB0aGlzLnN0YXRlLmRlbGV0ZShgJHtJREVNUE9URU5DWV9QUkVGSVh9JHtpbmRleC5tZXNzYWdlSWR9YCk7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBhc3luYyBnZXRNZXRhKCk6IFByb21pc2U8SW5ib3hNZXRhPiB7XG4gICAgcmV0dXJuIChhd2FpdCB0aGlzLnN0YXRlLmdldDxJbmJveE1ldGE+KE1FVEFfS0VZKSkgPz8gdGhpcy5kZWZhdWx0cztcbiAgfVxuXG4gIHByaXZhdGUgcHVibGlzaChldmVudDogUmVhbHRpbWVFdmVudCk6IHZvaWQge1xuICAgIGNvbnN0IHBheWxvYWQgPSBKU09OLnN0cmluZ2lmeShldmVudCk7XG4gICAgZm9yIChjb25zdCBzZXNzaW9uIG9mIHRoaXMuc2Vzc2lvbnMpIHtcbiAgICAgIHNlc3Npb24uc2VuZChwYXlsb2FkKTtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIHZhbGlkYXRlQXBwZW5kUmVxdWVzdChpbnB1dDogQXBwZW5kRW52ZWxvcGVSZXF1ZXN0KTogdm9pZCB7XG4gICAgaWYgKGlucHV0LnJlY2lwaWVudERldmljZUlkICE9PSB0aGlzLmRldmljZUlkKSB7XG4gICAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMCwgXCJpbnZhbGlkX2lucHV0XCIsIFwicmVjaXBpZW50X2RldmljZV9pZCBkb2VzIG5vdCBtYXRjaCBpbmJveCByb3V0ZVwiKTtcbiAgICB9XG4gICAgaWYgKGlucHV0LmVudmVsb3BlLnJlY2lwaWVudERldmljZUlkICE9PSB0aGlzLmRldmljZUlkKSB7XG4gICAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMCwgXCJpbnZhbGlkX2lucHV0XCIsIFwiZW52ZWxvcGUgcmVjaXBpZW50X2RldmljZV9pZCBkb2VzIG5vdCBtYXRjaCBpbmJveCByb3V0ZVwiKTtcbiAgICB9XG4gICAgaWYgKCFpbnB1dC5lbnZlbG9wZS5tZXNzYWdlSWQgfHwgIWlucHV0LmVudmVsb3BlLmNvbnZlcnNhdGlvbklkIHx8ICFpbnB1dC5lbnZlbG9wZS5zZW5kZXJVc2VySWQpIHtcbiAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAwLCBcImludmFsaWRfaW5wdXRcIiwgXCJhcHBlbmQgcmVxdWVzdCBpcyBtaXNzaW5nIHJlcXVpcmVkIGVudmVsb3BlIGZpZWxkc1wiKTtcbiAgICB9XG4gICAgY29uc3QgaGFzSW5saW5lID0gQm9vbGVhbihpbnB1dC5lbnZlbG9wZS5pbmxpbmVDaXBoZXJ0ZXh0KTtcbiAgICBjb25zdCBoYXNTdG9yYWdlUmVmcyA9IChpbnB1dC5lbnZlbG9wZS5zdG9yYWdlUmVmcz8ubGVuZ3RoID8/IDApID4gMDtcbiAgICBpZiAoIWhhc0lubGluZSAmJiAhaGFzU3RvcmFnZVJlZnMpIHtcbiAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAwLCBcImludmFsaWRfaW5wdXRcIiwgXCJlbnZlbG9wZSBtdXN0IGluY2x1ZGUgaW5saW5lX2NpcGhlcnRleHQgb3Igc3RvcmFnZV9yZWZzXCIpO1xuICAgIH1cbiAgfVxufVxyXG4iLCAiaW1wb3J0IHsgSHR0cEVycm9yIH0gZnJvbSBcIi4uL2F1dGgvY2FwYWJpbGl0eVwiO1xuaW1wb3J0IHsgSW5ib3hTZXJ2aWNlIH0gZnJvbSBcIi4vc2VydmljZVwiO1xuaW1wb3J0IHR5cGUgeyBBY2tSZXF1ZXN0LCBBcHBlbmRFbnZlbG9wZVJlcXVlc3QsIEZldGNoTWVzc2FnZXNSZXF1ZXN0IH0gZnJvbSBcIi4uL3R5cGVzL2NvbnRyYWN0c1wiO1xuaW1wb3J0IHR5cGUgeyBEdXJhYmxlT2JqZWN0U3RvcmFnZUxpa2UsIEVudiwgSnNvbkJsb2JTdG9yZSwgU2Vzc2lvblNpbmsgfSBmcm9tIFwiLi4vdHlwZXMvcnVudGltZVwiO1xuXG5jbGFzcyBEdXJhYmxlT2JqZWN0U3RvcmFnZUFkYXB0ZXIgaW1wbGVtZW50cyBEdXJhYmxlT2JqZWN0U3RvcmFnZUxpa2Uge1xuICBwcml2YXRlIHJlYWRvbmx5IHN0b3JhZ2U6IER1cmFibGVPYmplY3RTdGF0ZVtcInN0b3JhZ2VcIl07XG5cbiAgY29uc3RydWN0b3Ioc3RvcmFnZTogRHVyYWJsZU9iamVjdFN0YXRlW1wic3RvcmFnZVwiXSkge1xuICAgIHRoaXMuc3RvcmFnZSA9IHN0b3JhZ2U7XG4gIH1cblxuICBhc3luYyBnZXQ8VD4oa2V5OiBzdHJpbmcpOiBQcm9taXNlPFQgfCB1bmRlZmluZWQ+IHtcbiAgICByZXR1cm4gKGF3YWl0IHRoaXMuc3RvcmFnZS5nZXQ8VD4oa2V5KSkgPz8gdW5kZWZpbmVkO1xuICB9XG5cbiAgYXN5bmMgcHV0PFQ+KGtleTogc3RyaW5nLCB2YWx1ZTogVCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGF3YWl0IHRoaXMuc3RvcmFnZS5wdXQoa2V5LCB2YWx1ZSk7XG4gIH1cblxuICBhc3luYyBkZWxldGUoa2V5OiBzdHJpbmcpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLnN0b3JhZ2UuZGVsZXRlKGtleSk7XG4gIH1cblxuICBhc3luYyBzZXRBbGFybShlcG9jaE1pbGxpczogbnVtYmVyKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgYXdhaXQgdGhpcy5zdG9yYWdlLnNldEFsYXJtKGVwb2NoTWlsbGlzKTtcbiAgfVxufVxuXG5jbGFzcyBSMkpzb25CbG9iU3RvcmUgaW1wbGVtZW50cyBKc29uQmxvYlN0b3JlIHtcbiAgcHJpdmF0ZSByZWFkb25seSBidWNrZXQ6IEVudltcIlRBUENIQVRfU1RPUkFHRVwiXTtcblxuICBjb25zdHJ1Y3RvcihidWNrZXQ6IEVudltcIlRBUENIQVRfU1RPUkFHRVwiXSkge1xuICAgIHRoaXMuYnVja2V0ID0gYnVja2V0O1xuICB9XG5cbiAgYXN5bmMgcHV0SnNvbjxUPihrZXk6IHN0cmluZywgdmFsdWU6IFQpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLmJ1Y2tldC5wdXQoa2V5LCBKU09OLnN0cmluZ2lmeSh2YWx1ZSkpO1xuICB9XG5cbiAgYXN5bmMgZ2V0SnNvbjxUPihrZXk6IHN0cmluZyk6IFByb21pc2U8VCB8IG51bGw+IHtcbiAgICBjb25zdCBvYmplY3QgPSBhd2FpdCB0aGlzLmJ1Y2tldC5nZXQoa2V5KTtcbiAgICBpZiAoIW9iamVjdCkge1xuICAgICAgcmV0dXJuIG51bGw7XG4gICAgfVxuICAgIHJldHVybiBhd2FpdCBvYmplY3QuanNvbjxUPigpO1xuICB9XG5cbiAgYXN5bmMgcHV0Qnl0ZXMoa2V5OiBzdHJpbmcsIHZhbHVlOiBBcnJheUJ1ZmZlciB8IFVpbnQ4QXJyYXkpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLmJ1Y2tldC5wdXQoa2V5LCB2YWx1ZSk7XG4gIH1cblxuICBhc3luYyBnZXRCeXRlcyhrZXk6IHN0cmluZyk6IFByb21pc2U8QXJyYXlCdWZmZXIgfCBudWxsPiB7XG4gICAgY29uc3Qgb2JqZWN0ID0gYXdhaXQgdGhpcy5idWNrZXQuZ2V0KGtleSk7XG4gICAgaWYgKCFvYmplY3QpIHtcbiAgICAgIHJldHVybiBudWxsO1xuICAgIH1cbiAgICByZXR1cm4gb2JqZWN0LmFycmF5QnVmZmVyKCk7XG4gIH1cblxuICBhc3luYyBkZWxldGUoa2V5OiBzdHJpbmcpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLmJ1Y2tldC5kZWxldGUoa2V5KTtcbiAgfVxufVxuXG5mdW5jdGlvbiB2ZXJzaW9uZWRCb2R5KGJvZHk6IHVua25vd24pOiB1bmtub3duIHtcbiAgaWYgKCFib2R5IHx8IHR5cGVvZiBib2R5ICE9PSBcIm9iamVjdFwiIHx8IEFycmF5LmlzQXJyYXkoYm9keSkpIHtcbiAgICByZXR1cm4gYm9keTtcbiAgfVxuICBjb25zdCByZWNvcmQgPSBib2R5IGFzIFJlY29yZDxzdHJpbmcsIHVua25vd24+O1xuICBpZiAocmVjb3JkLnZlcnNpb24gIT09IHVuZGVmaW5lZCkge1xuICAgIHJldHVybiBib2R5O1xuICB9XG4gIHJldHVybiB7XG4gICAgdmVyc2lvbjogXCIwLjFcIixcbiAgICAuLi5yZWNvcmRcbiAgfTtcbn1cblxuZnVuY3Rpb24ganNvblJlc3BvbnNlKGJvZHk6IHVua25vd24sIHN0YXR1cyA9IDIwMCk6IFJlc3BvbnNlIHtcbiAgcmV0dXJuIG5ldyBSZXNwb25zZShKU09OLnN0cmluZ2lmeSh2ZXJzaW9uZWRCb2R5KGJvZHkpKSwge1xuICAgIHN0YXR1cyxcbiAgICBoZWFkZXJzOiB7XG4gICAgICBcImNvbnRlbnQtdHlwZVwiOiBcImFwcGxpY2F0aW9uL2pzb25cIlxuICAgIH1cbiAgfSk7XG59XG5cbmNvbnN0IER1cmFibGVPYmplY3RCYXNlOiB0eXBlb2YgRHVyYWJsZU9iamVjdCA9XG4gIChnbG9iYWxUaGlzIGFzIHsgRHVyYWJsZU9iamVjdD86IHR5cGVvZiBEdXJhYmxlT2JqZWN0IH0pLkR1cmFibGVPYmplY3QgPz9cbiAgKGNsYXNzIHtcbiAgICBjb25zdHJ1Y3Rvcihfc3RhdGU6IER1cmFibGVPYmplY3RTdGF0ZSwgX2VudjogRW52KSB7fVxuICB9IGFzIHVua25vd24gYXMgdHlwZW9mIER1cmFibGVPYmplY3QpO1xuXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gaGFuZGxlSW5ib3hEdXJhYmxlUmVxdWVzdChcbiAgcmVxdWVzdDogUmVxdWVzdCxcbiAgZGVwczoge1xuICAgIGRldmljZUlkOiBzdHJpbmc7XG4gICAgc3RhdGU6IER1cmFibGVPYmplY3RTdG9yYWdlTGlrZTtcbiAgICBzcGlsbFN0b3JlOiBKc29uQmxvYlN0b3JlO1xuICAgIHNlc3Npb25zOiBTZXNzaW9uU2lua1tdO1xuICAgIG1heElubGluZUJ5dGVzOiBudW1iZXI7XG4gICAgcmV0ZW50aW9uRGF5czogbnVtYmVyO1xuICAgIG9uVXBncmFkZT86ICgpID0+IFJlc3BvbnNlO1xuICAgIG5vdz86IG51bWJlcjtcbiAgfVxuKTogUHJvbWlzZTxSZXNwb25zZT4ge1xuICBjb25zdCBub3cgPSBkZXBzLm5vdyA/PyBEYXRlLm5vdygpO1xuICBjb25zdCB1cmwgPSBuZXcgVVJMKHJlcXVlc3QudXJsKTtcbiAgY29uc3Qgc2VydmljZSA9IG5ldyBJbmJveFNlcnZpY2UoZGVwcy5kZXZpY2VJZCwgZGVwcy5zdGF0ZSwgZGVwcy5zcGlsbFN0b3JlLCBkZXBzLnNlc3Npb25zLCB7XG4gICAgaGVhZFNlcTogMCxcbiAgICBhY2tlZFNlcTogMCxcbiAgICByZXRlbnRpb25EYXlzOiBkZXBzLnJldGVudGlvbkRheXMsXG4gICAgbWF4SW5saW5lQnl0ZXM6IGRlcHMubWF4SW5saW5lQnl0ZXNcbiAgfSk7XG5cbiAgdHJ5IHtcbiAgICBpZiAodXJsLnBhdGhuYW1lLmVuZHNXaXRoKFwiL3N1YnNjcmliZVwiKSkge1xuICAgICAgaWYgKHJlcXVlc3QuaGVhZGVycy5nZXQoXCJVcGdyYWRlXCIpPy50b0xvd2VyQ2FzZSgpICE9PSBcIndlYnNvY2tldFwiKSB7XG4gICAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAwLCBcImludmFsaWRfaW5wdXRcIiwgXCJzdWJzY3JpYmUgcmVxdWlyZXMgd2Vic29ja2V0IHVwZ3JhZGVcIik7XG4gICAgICB9XG4gICAgICBpZiAoIWRlcHMub25VcGdyYWRlKSB7XG4gICAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNTAwLCBcInRlbXBvcmFyeV91bmF2YWlsYWJsZVwiLCBcIndlYnNvY2tldCB1cGdyYWRlIGhhbmRsZXIgaXMgdW5hdmFpbGFibGVcIik7XG4gICAgICB9XG4gICAgICByZXR1cm4gZGVwcy5vblVwZ3JhZGUoKTtcbiAgICB9XG5cbiAgICBpZiAodXJsLnBhdGhuYW1lLmVuZHNXaXRoKFwiL21lc3NhZ2VzXCIpICYmIHJlcXVlc3QubWV0aG9kID09PSBcIlBPU1RcIikge1xuICAgICAgY29uc3QgYm9keSA9IChhd2FpdCByZXF1ZXN0Lmpzb24oKSkgYXMgQXBwZW5kRW52ZWxvcGVSZXF1ZXN0O1xuICAgICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgc2VydmljZS5hcHBlbmRFbnZlbG9wZShib2R5LCBub3cpO1xuICAgICAgcmV0dXJuIGpzb25SZXNwb25zZSh7IGFjY2VwdGVkOiByZXN1bHQuYWNjZXB0ZWQsIHNlcTogcmVzdWx0LnNlcSB9KTtcbiAgICB9XG5cbiAgICBpZiAodXJsLnBhdGhuYW1lLmVuZHNXaXRoKFwiL21lc3NhZ2VzXCIpICYmIHJlcXVlc3QubWV0aG9kID09PSBcIkdFVFwiKSB7XG4gICAgICBjb25zdCBmcm9tU2VxID0gTnVtYmVyKHVybC5zZWFyY2hQYXJhbXMuZ2V0KFwiZnJvbVNlcVwiKSA/PyBcIjFcIik7XG4gICAgICBjb25zdCBsaW1pdCA9IE51bWJlcih1cmwuc2VhcmNoUGFyYW1zLmdldChcImxpbWl0XCIpID8/IFwiMTAwXCIpO1xuICAgICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgc2VydmljZS5mZXRjaE1lc3NhZ2VzKHtcbiAgICAgICAgZGV2aWNlSWQ6IGRlcHMuZGV2aWNlSWQsXG4gICAgICAgIGZyb21TZXEsXG4gICAgICAgIGxpbWl0XG4gICAgICB9IGFzIEZldGNoTWVzc2FnZXNSZXF1ZXN0KTtcbiAgICAgIHJldHVybiBqc29uUmVzcG9uc2Uoe1xuICAgICAgICB0b1NlcTogcmVzdWx0LnRvU2VxLFxuICAgICAgICByZWNvcmRzOiByZXN1bHQucmVjb3Jkc1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgaWYgKHVybC5wYXRobmFtZS5lbmRzV2l0aChcIi9hY2tcIikgJiYgcmVxdWVzdC5tZXRob2QgPT09IFwiUE9TVFwiKSB7XG4gICAgICBjb25zdCBib2R5ID0gKGF3YWl0IHJlcXVlc3QuanNvbigpKSBhcyBBY2tSZXF1ZXN0O1xuICAgICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgc2VydmljZS5hY2soYm9keSk7XG4gICAgICByZXR1cm4ganNvblJlc3BvbnNlKHtcbiAgICAgICAgYWNjZXB0ZWQ6IHJlc3VsdC5hY2NlcHRlZCxcbiAgICAgICAgYWNrU2VxOiByZXN1bHQuYWNrU2VxXG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBpZiAodXJsLnBhdGhuYW1lLmVuZHNXaXRoKFwiL2hlYWRcIikgJiYgcmVxdWVzdC5tZXRob2QgPT09IFwiR0VUXCIpIHtcbiAgICAgIGNvbnN0IHJlc3VsdCA9IGF3YWl0IHNlcnZpY2UuZ2V0SGVhZCgpO1xuICAgICAgcmV0dXJuIGpzb25SZXNwb25zZShyZXN1bHQpO1xuICAgIH1cblxuICAgIHJldHVybiBqc29uUmVzcG9uc2UoeyBlcnJvcjogXCJub3RfZm91bmRcIiB9LCA0MDQpO1xuICB9IGNhdGNoIChlcnJvcikge1xuICAgIGlmIChlcnJvciBpbnN0YW5jZW9mIEh0dHBFcnJvcikge1xuICAgICAgcmV0dXJuIGpzb25SZXNwb25zZSh7IGVycm9yOiBlcnJvci5jb2RlLCBtZXNzYWdlOiBlcnJvci5tZXNzYWdlIH0sIGVycm9yLnN0YXR1cyk7XG4gICAgfVxuICAgIGNvbnN0IHJ1bnRpbWVFcnJvciA9IGVycm9yIGFzIHsgbWVzc2FnZT86IHN0cmluZyB9O1xuICAgIGNvbnN0IG1lc3NhZ2UgPSBydW50aW1lRXJyb3IubWVzc2FnZSA/PyBcImludGVybmFsIGVycm9yXCI7XG4gICAgcmV0dXJuIGpzb25SZXNwb25zZSh7IGVycm9yOiBcInRlbXBvcmFyeV91bmF2YWlsYWJsZVwiLCBtZXNzYWdlIH0sIDUwMCk7XG4gIH1cbn1cblxuZXhwb3J0IGNsYXNzIEluYm94RHVyYWJsZU9iamVjdCBleHRlbmRzIER1cmFibGVPYmplY3RCYXNlIHtcbiAgcHJpdmF0ZSByZWFkb25seSBzZXNzaW9ucyA9IG5ldyBNYXA8c3RyaW5nLCBXZWJTb2NrZXQ+KCk7XG4gIHByaXZhdGUgcmVhZG9ubHkgc3RhdGVSZWY6IER1cmFibGVPYmplY3RTdGF0ZTtcbiAgcHJpdmF0ZSByZWFkb25seSBlbnZSZWY6IEVudjtcblxuICBjb25zdHJ1Y3RvcihzdGF0ZTogRHVyYWJsZU9iamVjdFN0YXRlLCBlbnY6IEVudikge1xuICAgIHN1cGVyKHN0YXRlLCBlbnYpO1xuICAgIHRoaXMuc3RhdGVSZWYgPSBzdGF0ZTtcbiAgICB0aGlzLmVudlJlZiA9IGVudjtcbiAgfVxuXG4gIGFzeW5jIGZldGNoKHJlcXVlc3Q6IFJlcXVlc3QpOiBQcm9taXNlPFJlc3BvbnNlPiB7XG4gICAgY29uc3QgdXJsID0gbmV3IFVSTChyZXF1ZXN0LnVybCk7XG4gICAgY29uc3QgbWF0Y2ggPSB1cmwucGF0aG5hbWUubWF0Y2goL1xcL3YxXFwvaW5ib3hcXC8oW14vXSspXFwvLyk7XG4gICAgY29uc3QgZGV2aWNlSWQgPSBkZWNvZGVVUklDb21wb25lbnQobWF0Y2g/LlsxXSA/PyBcIlwiKTtcblxuICAgIHJldHVybiBoYW5kbGVJbmJveER1cmFibGVSZXF1ZXN0KHJlcXVlc3QsIHtcbiAgICAgIGRldmljZUlkLFxuICAgICAgc3RhdGU6IG5ldyBEdXJhYmxlT2JqZWN0U3RvcmFnZUFkYXB0ZXIodGhpcy5zdGF0ZVJlZi5zdG9yYWdlKSxcbiAgICAgIHNwaWxsU3RvcmU6IG5ldyBSMkpzb25CbG9iU3RvcmUodGhpcy5lbnZSZWYuVEFQQ0hBVF9TVE9SQUdFKSxcbiAgICAgIHNlc3Npb25zOiBBcnJheS5mcm9tKHRoaXMuc2Vzc2lvbnMudmFsdWVzKCkpLm1hcChcbiAgICAgICAgKHNvY2tldCkgPT5cbiAgICAgICAgICAoe1xuICAgICAgICAgICAgc2VuZChwYXlsb2FkOiBzdHJpbmcpOiB2b2lkIHtcbiAgICAgICAgICAgICAgc29ja2V0LnNlbmQocGF5bG9hZCk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfSkgc2F0aXNmaWVzIFNlc3Npb25TaW5rXG4gICAgICApLFxuICAgICAgbWF4SW5saW5lQnl0ZXM6IE51bWJlcih0aGlzLmVudlJlZi5NQVhfSU5MSU5FX0JZVEVTID8/IFwiNDA5NlwiKSxcbiAgICAgIHJldGVudGlvbkRheXM6IE51bWJlcih0aGlzLmVudlJlZi5SRVRFTlRJT05fREFZUyA/PyBcIjMwXCIpLFxuICAgICAgb25VcGdyYWRlOiAoKSA9PiB7XG4gICAgICAgIGNvbnN0IHBhaXIgPSBuZXcgV2ViU29ja2V0UGFpcigpO1xuICAgICAgICBjb25zdCBjbGllbnQgPSBwYWlyWzBdO1xuICAgICAgICBjb25zdCBzZXJ2ZXIgPSBwYWlyWzFdO1xuICAgICAgICBzZXJ2ZXIuYWNjZXB0KCk7XG4gICAgICAgIGNvbnN0IHNlc3Npb25JZCA9IGNyeXB0by5yYW5kb21VVUlEKCk7XG4gICAgICAgIHRoaXMuc2Vzc2lvbnMuc2V0KHNlc3Npb25JZCwgc2VydmVyKTtcbiAgICAgICAgc2VydmVyLmFkZEV2ZW50TGlzdGVuZXIoXCJjbG9zZVwiLCAoKSA9PiB7XG4gICAgICAgICAgdGhpcy5zZXNzaW9ucy5kZWxldGUoc2Vzc2lvbklkKTtcbiAgICAgICAgfSk7XG4gICAgICAgIHJldHVybiBuZXcgUmVzcG9uc2UobnVsbCwge1xuICAgICAgICAgIHN0YXR1czogMTAxLFxuICAgICAgICAgIHdlYlNvY2tldDogY2xpZW50XG4gICAgICAgIH0gYXMgUmVzcG9uc2VJbml0ICYgeyB3ZWJTb2NrZXQ6IFdlYlNvY2tldCB9KTtcbiAgICAgIH1cbiAgICB9KTtcbiAgfVxuXG4gIGFzeW5jIGFsYXJtKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IHNlcnZpY2UgPSBuZXcgSW5ib3hTZXJ2aWNlKFxuICAgICAgXCJcIixcbiAgICAgIG5ldyBEdXJhYmxlT2JqZWN0U3RvcmFnZUFkYXB0ZXIodGhpcy5zdGF0ZVJlZi5zdG9yYWdlKSxcbiAgICAgIG5ldyBSMkpzb25CbG9iU3RvcmUodGhpcy5lbnZSZWYuVEFQQ0hBVF9TVE9SQUdFKSxcbiAgICAgIFtdLFxuICAgICAge1xuICAgICAgICBoZWFkU2VxOiAwLFxuICAgICAgICBhY2tlZFNlcTogMCxcbiAgICAgICAgcmV0ZW50aW9uRGF5czogTnVtYmVyKHRoaXMuZW52UmVmLlJFVEVOVElPTl9EQVlTID8/IFwiMzBcIiksXG4gICAgICAgIG1heElubGluZUJ5dGVzOiBOdW1iZXIodGhpcy5lbnZSZWYuTUFYX0lOTElORV9CWVRFUyA/PyBcIjQwOTZcIilcbiAgICAgIH1cbiAgICApO1xuICAgIGF3YWl0IHNlcnZpY2UuY2xlYW5FeHBpcmVkUmVjb3JkcyhEYXRlLm5vdygpKTtcbiAgfVxufVxyXG4iLCAiaW1wb3J0IHsgSHR0cEVycm9yIH0gZnJvbSBcIi4uL2F1dGgvY2FwYWJpbGl0eVwiO1xuaW1wb3J0IHR5cGUge1xuICBEZXZpY2VMaXN0RG9jdW1lbnQsXG4gIERldmljZVN0YXR1c0RvY3VtZW50LFxuICBJZGVudGl0eUJ1bmRsZSxcbiAgS2V5UGFja2FnZVJlZnNEb2N1bWVudFxufSBmcm9tIFwiLi4vdHlwZXMvY29udHJhY3RzXCI7XG5pbXBvcnQgdHlwZSB7IEpzb25CbG9iU3RvcmUgfSBmcm9tIFwiLi4vdHlwZXMvcnVudGltZVwiO1xuXG5mdW5jdGlvbiBzYW5pdGl6ZVNlZ21lbnQodmFsdWU6IHN0cmluZyk6IHN0cmluZyB7XG4gIHJldHVybiB2YWx1ZS5yZXBsYWNlKC9bXmEtekEtWjAtOTpfLV0vZywgXCJfXCIpO1xufVxuXG5leHBvcnQgY2xhc3MgU2hhcmVkU3RhdGVTZXJ2aWNlIHtcbiAgcHJpdmF0ZSByZWFkb25seSBzdG9yZTogSnNvbkJsb2JTdG9yZTtcbiAgcHJpdmF0ZSByZWFkb25seSBiYXNlVXJsOiBzdHJpbmc7XG5cbiAgY29uc3RydWN0b3Ioc3RvcmU6IEpzb25CbG9iU3RvcmUsIGJhc2VVcmw6IHN0cmluZykge1xuICAgIHRoaXMuc3RvcmUgPSBzdG9yZTtcbiAgICB0aGlzLmJhc2VVcmwgPSBiYXNlVXJsO1xuICB9XG5cbiAgaWRlbnRpdHlCdW5kbGVLZXkodXNlcklkOiBzdHJpbmcpOiBzdHJpbmcge1xuICAgIHJldHVybiBgc2hhcmVkLXN0YXRlLyR7c2FuaXRpemVTZWdtZW50KHVzZXJJZCl9L2lkZW50aXR5X2J1bmRsZS5qc29uYDtcbiAgfVxuXG4gIGRldmljZUxpc3RLZXkodXNlcklkOiBzdHJpbmcpOiBzdHJpbmcge1xuICAgIHJldHVybiBgc2hhcmVkLXN0YXRlLyR7c2FuaXRpemVTZWdtZW50KHVzZXJJZCl9L2RldmljZV9saXN0Lmpzb25gO1xuICB9XG5cbiAgZGV2aWNlU3RhdHVzS2V5KHVzZXJJZDogc3RyaW5nKTogc3RyaW5nIHtcbiAgICByZXR1cm4gYHNoYXJlZC1zdGF0ZS8ke3Nhbml0aXplU2VnbWVudCh1c2VySWQpfS9kZXZpY2Vfc3RhdHVzLmpzb25gO1xuICB9XG5cbiAga2V5UGFja2FnZVJlZnNLZXkodXNlcklkOiBzdHJpbmcsIGRldmljZUlkOiBzdHJpbmcpOiBzdHJpbmcge1xuICAgIHJldHVybiBga2V5cGFja2FnZXMvJHtzYW5pdGl6ZVNlZ21lbnQodXNlcklkKX0vJHtzYW5pdGl6ZVNlZ21lbnQoZGV2aWNlSWQpfS9yZWZzLmpzb25gO1xuICB9XG5cbiAga2V5UGFja2FnZU9iamVjdEtleSh1c2VySWQ6IHN0cmluZywgZGV2aWNlSWQ6IHN0cmluZywga2V5UGFja2FnZUlkOiBzdHJpbmcpOiBzdHJpbmcge1xuICAgIHJldHVybiBga2V5cGFja2FnZXMvJHtzYW5pdGl6ZVNlZ21lbnQodXNlcklkKX0vJHtzYW5pdGl6ZVNlZ21lbnQoZGV2aWNlSWQpfS8ke3Nhbml0aXplU2VnbWVudChrZXlQYWNrYWdlSWQpfS5iaW5gO1xuICB9XG5cbiAgaWRlbnRpdHlCdW5kbGVVcmwodXNlcklkOiBzdHJpbmcpOiBzdHJpbmcge1xuICAgIHJldHVybiBgJHt0aGlzLmJhc2VVcmx9L3YxL3NoYXJlZC1zdGF0ZS8ke2VuY29kZVVSSUNvbXBvbmVudCh1c2VySWQpfS9pZGVudGl0eS1idW5kbGVgO1xuICB9XG5cbiAgZGV2aWNlU3RhdHVzVXJsKHVzZXJJZDogc3RyaW5nKTogc3RyaW5nIHtcbiAgICByZXR1cm4gYCR7dGhpcy5iYXNlVXJsfS92MS9zaGFyZWQtc3RhdGUvJHtlbmNvZGVVUklDb21wb25lbnQodXNlcklkKX0vZGV2aWNlLXN0YXR1c2A7XG4gIH1cblxuICBrZXlQYWNrYWdlUmVmc1VybCh1c2VySWQ6IHN0cmluZywgZGV2aWNlSWQ6IHN0cmluZyk6IHN0cmluZyB7XG4gICAgcmV0dXJuIGAke3RoaXMuYmFzZVVybH0vdjEvc2hhcmVkLXN0YXRlL2tleXBhY2thZ2VzLyR7ZW5jb2RlVVJJQ29tcG9uZW50KHVzZXJJZCl9LyR7ZW5jb2RlVVJJQ29tcG9uZW50KGRldmljZUlkKX1gO1xuICB9XG5cbiAga2V5UGFja2FnZU9iamVjdFVybCh1c2VySWQ6IHN0cmluZywgZGV2aWNlSWQ6IHN0cmluZywga2V5UGFja2FnZUlkOiBzdHJpbmcpOiBzdHJpbmcge1xuICAgIHJldHVybiBgJHt0aGlzLmJhc2VVcmx9L3YxL3NoYXJlZC1zdGF0ZS9rZXlwYWNrYWdlcy8ke2VuY29kZVVSSUNvbXBvbmVudCh1c2VySWQpfS8ke2VuY29kZVVSSUNvbXBvbmVudChkZXZpY2VJZCl9LyR7ZW5jb2RlVVJJQ29tcG9uZW50KGtleVBhY2thZ2VJZCl9YDtcbiAgfVxuXG4gIGFzeW5jIGdldElkZW50aXR5QnVuZGxlKHVzZXJJZDogc3RyaW5nKTogUHJvbWlzZTxJZGVudGl0eUJ1bmRsZSB8IG51bGw+IHtcbiAgICByZXR1cm4gdGhpcy5zdG9yZS5nZXRKc29uPElkZW50aXR5QnVuZGxlPih0aGlzLmlkZW50aXR5QnVuZGxlS2V5KHVzZXJJZCkpO1xuICB9XG5cbiAgYXN5bmMgcHV0SWRlbnRpdHlCdW5kbGUodXNlcklkOiBzdHJpbmcsIGJ1bmRsZTogSWRlbnRpdHlCdW5kbGUpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBpZiAoYnVuZGxlLnVzZXJJZCAhPT0gdXNlcklkKSB7XG4gICAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMCwgXCJpbnZhbGlkX2lucHV0XCIsIFwiaWRlbnRpdHkgYnVuZGxlIHVzZXJJZCBkb2VzIG5vdCBtYXRjaCByZXF1ZXN0IHBhdGhcIik7XG4gICAgfVxuICAgIGNvbnN0IG5vcm1hbGl6ZWQ6IElkZW50aXR5QnVuZGxlID0ge1xuICAgICAgLi4uYnVuZGxlLFxuICAgICAgaWRlbnRpdHlCdW5kbGVSZWY6IHRoaXMuaWRlbnRpdHlCdW5kbGVVcmwodXNlcklkKSxcbiAgICAgIGRldmljZVN0YXR1c1JlZjogYnVuZGxlLmRldmljZVN0YXR1c1JlZiA/PyB0aGlzLmRldmljZVN0YXR1c1VybCh1c2VySWQpLFxuICAgICAgZGV2aWNlczogYnVuZGxlLmRldmljZXMubWFwKChkZXZpY2UpID0+ICh7XG4gICAgICAgIC4uLmRldmljZSxcbiAgICAgICAga2V5cGFja2FnZVJlZjoge1xuICAgICAgICAgIC4uLmRldmljZS5rZXlwYWNrYWdlUmVmLFxuICAgICAgICAgIHVzZXJJZCxcbiAgICAgICAgICBkZXZpY2VJZDogZGV2aWNlLmRldmljZUlkLFxuICAgICAgICAgIHJlZjogZGV2aWNlLmtleXBhY2thZ2VSZWYucmVmXG4gICAgICAgIH1cbiAgICAgIH0pKVxuICAgIH07XG4gICAgYXdhaXQgdGhpcy5zdG9yZS5wdXRKc29uKHRoaXMuaWRlbnRpdHlCdW5kbGVLZXkodXNlcklkKSwgbm9ybWFsaXplZCk7XG4gICAgYXdhaXQgdGhpcy5zdG9yZS5wdXRKc29uKHRoaXMuZGV2aWNlTGlzdEtleSh1c2VySWQpLCB0aGlzLmJ1aWxkRGV2aWNlTGlzdERvY3VtZW50KG5vcm1hbGl6ZWQpKTtcbiAgfVxuXG4gIGFzeW5jIGdldERldmljZUxpc3QodXNlcklkOiBzdHJpbmcpOiBQcm9taXNlPERldmljZUxpc3REb2N1bWVudCB8IG51bGw+IHtcbiAgICByZXR1cm4gdGhpcy5zdG9yZS5nZXRKc29uPERldmljZUxpc3REb2N1bWVudD4odGhpcy5kZXZpY2VMaXN0S2V5KHVzZXJJZCkpO1xuICB9XG5cbiAgYXN5bmMgZ2V0RGV2aWNlU3RhdHVzKHVzZXJJZDogc3RyaW5nKTogUHJvbWlzZTxEZXZpY2VTdGF0dXNEb2N1bWVudCB8IG51bGw+IHtcbiAgICByZXR1cm4gdGhpcy5zdG9yZS5nZXRKc29uPERldmljZVN0YXR1c0RvY3VtZW50Pih0aGlzLmRldmljZVN0YXR1c0tleSh1c2VySWQpKTtcbiAgfVxuXG4gIGFzeW5jIHB1dERldmljZVN0YXR1cyh1c2VySWQ6IHN0cmluZywgZG9jdW1lbnQ6IERldmljZVN0YXR1c0RvY3VtZW50KTogUHJvbWlzZTx2b2lkPiB7XG4gICAgaWYgKGRvY3VtZW50LnVzZXJJZCAhPT0gdXNlcklkKSB7XG4gICAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMCwgXCJpbnZhbGlkX2lucHV0XCIsIFwiZGV2aWNlIHN0YXR1cyB1c2VySWQgZG9lcyBub3QgbWF0Y2ggcmVxdWVzdCBwYXRoXCIpO1xuICAgIH1cbiAgICBmb3IgKGNvbnN0IGRldmljZSBvZiBkb2N1bWVudC5kZXZpY2VzKSB7XG4gICAgICBpZiAoZGV2aWNlLnVzZXJJZCAhPT0gdXNlcklkKSB7XG4gICAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAwLCBcImludmFsaWRfaW5wdXRcIiwgXCJkZXZpY2Ugc3RhdHVzIGVudHJ5IHVzZXJJZCBkb2VzIG5vdCBtYXRjaCByZXF1ZXN0IHBhdGhcIik7XG4gICAgICB9XG4gICAgfVxuICAgIGF3YWl0IHRoaXMuc3RvcmUucHV0SnNvbih0aGlzLmRldmljZVN0YXR1c0tleSh1c2VySWQpLCBkb2N1bWVudCk7XG4gIH1cblxuICBhc3luYyBnZXRLZXlQYWNrYWdlUmVmcyh1c2VySWQ6IHN0cmluZywgZGV2aWNlSWQ6IHN0cmluZyk6IFByb21pc2U8S2V5UGFja2FnZVJlZnNEb2N1bWVudCB8IG51bGw+IHtcbiAgICByZXR1cm4gdGhpcy5zdG9yZS5nZXRKc29uPEtleVBhY2thZ2VSZWZzRG9jdW1lbnQ+KHRoaXMua2V5UGFja2FnZVJlZnNLZXkodXNlcklkLCBkZXZpY2VJZCkpO1xuICB9XG5cbiAgYXN5bmMgcHV0S2V5UGFja2FnZVJlZnModXNlcklkOiBzdHJpbmcsIGRldmljZUlkOiBzdHJpbmcsIGRvY3VtZW50OiBLZXlQYWNrYWdlUmVmc0RvY3VtZW50KTogUHJvbWlzZTx2b2lkPiB7XG4gICAgaWYgKGRvY3VtZW50LnVzZXJJZCAhPT0gdXNlcklkIHx8IGRvY3VtZW50LmRldmljZUlkICE9PSBkZXZpY2VJZCkge1xuICAgICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDAsIFwiaW52YWxpZF9pbnB1dFwiLCBcImtleXBhY2thZ2UgcmVmcyBzY29wZSBkb2VzIG5vdCBtYXRjaCByZXF1ZXN0IHBhdGhcIik7XG4gICAgfVxuICAgIGZvciAoY29uc3QgZW50cnkgb2YgZG9jdW1lbnQucmVmcykge1xuICAgICAgaWYgKCFlbnRyeS5yZWYgfHwgIWVudHJ5LnJlZi5zdGFydHNXaXRoKHRoaXMua2V5UGFja2FnZVJlZnNVcmwodXNlcklkLCBkZXZpY2VJZCkpKSB7XG4gICAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAwLCBcImludmFsaWRfaW5wdXRcIiwgXCJrZXlwYWNrYWdlIHJlZiBtdXN0IGJlIGEgY29uY3JldGUgb2JqZWN0IFVSTFwiKTtcbiAgICAgIH1cbiAgICB9XG4gICAgYXdhaXQgdGhpcy5zdG9yZS5wdXRKc29uKHRoaXMua2V5UGFja2FnZVJlZnNLZXkodXNlcklkLCBkZXZpY2VJZCksIGRvY3VtZW50KTtcbiAgfVxuXG4gIGFzeW5jIHB1dEtleVBhY2thZ2VPYmplY3QodXNlcklkOiBzdHJpbmcsIGRldmljZUlkOiBzdHJpbmcsIGtleVBhY2thZ2VJZDogc3RyaW5nLCBib2R5OiBBcnJheUJ1ZmZlcik6IFByb21pc2U8dm9pZD4ge1xuICAgIGF3YWl0IHRoaXMuc3RvcmUucHV0Qnl0ZXModGhpcy5rZXlQYWNrYWdlT2JqZWN0S2V5KHVzZXJJZCwgZGV2aWNlSWQsIGtleVBhY2thZ2VJZCksIGJvZHksIHtcbiAgICAgIFwiY29udGVudC10eXBlXCI6IFwiYXBwbGljYXRpb24vb2N0ZXQtc3RyZWFtXCJcbiAgICB9KTtcbiAgfVxuXG4gIGFzeW5jIGdldEtleVBhY2thZ2VPYmplY3QodXNlcklkOiBzdHJpbmcsIGRldmljZUlkOiBzdHJpbmcsIGtleVBhY2thZ2VJZDogc3RyaW5nKTogUHJvbWlzZTxBcnJheUJ1ZmZlciB8IG51bGw+IHtcbiAgICByZXR1cm4gdGhpcy5zdG9yZS5nZXRCeXRlcyh0aGlzLmtleVBhY2thZ2VPYmplY3RLZXkodXNlcklkLCBkZXZpY2VJZCwga2V5UGFja2FnZUlkKSk7XG4gIH1cblxuICBwcml2YXRlIGJ1aWxkRGV2aWNlTGlzdERvY3VtZW50KGJ1bmRsZTogSWRlbnRpdHlCdW5kbGUpOiBEZXZpY2VMaXN0RG9jdW1lbnQge1xuICAgIHJldHVybiB7XG4gICAgICB2ZXJzaW9uOiBidW5kbGUudmVyc2lvbixcbiAgICAgIHVzZXJJZDogYnVuZGxlLnVzZXJJZCxcbiAgICAgIHVwZGF0ZWRBdDogYnVuZGxlLnVwZGF0ZWRBdCxcbiAgICAgIGRldmljZXM6IGJ1bmRsZS5kZXZpY2VzLm1hcCgoZGV2aWNlKSA9PiAoe1xuICAgICAgICBkZXZpY2VJZDogZGV2aWNlLmRldmljZUlkLFxuICAgICAgICBzdGF0dXM6IGRldmljZS5zdGF0dXNcbiAgICAgIH0pKVxuICAgIH07XG4gIH1cbn0iLCAiaW1wb3J0IHR5cGUgeyBQcmVwYXJlQmxvYlVwbG9hZFJlcXVlc3QsIFByZXBhcmVCbG9iVXBsb2FkUmVzdWx0IH0gZnJvbSBcIi4uL3R5cGVzL2NvbnRyYWN0c1wiO1xuaW1wb3J0IHR5cGUgeyBKc29uQmxvYlN0b3JlIH0gZnJvbSBcIi4uL3R5cGVzL3J1bnRpbWVcIjtcbmltcG9ydCB7IEh0dHBFcnJvciB9IGZyb20gXCIuLi9hdXRoL2NhcGFiaWxpdHlcIjtcbmltcG9ydCB7IHNpZ25TaGFyaW5nUGF5bG9hZCwgdmVyaWZ5U2hhcmluZ1BheWxvYWQgfSBmcm9tIFwiLi9zaGFyaW5nXCI7XG5cbmZ1bmN0aW9uIHNhbml0aXplU2VnbWVudCh2YWx1ZTogc3RyaW5nKTogc3RyaW5nIHtcbiAgcmV0dXJuIHZhbHVlLnJlcGxhY2UoL1teYS16QS1aMC05Ol8tXS9nLCBcIl9cIik7XG59XG5cbmV4cG9ydCBjbGFzcyBTdG9yYWdlU2VydmljZSB7XG4gIHByaXZhdGUgcmVhZG9ubHkgc3RvcmU6IEpzb25CbG9iU3RvcmU7XG4gIHByaXZhdGUgcmVhZG9ubHkgYmFzZVVybDogc3RyaW5nO1xuICBwcml2YXRlIHJlYWRvbmx5IHNlY3JldDogc3RyaW5nO1xuXG4gIGNvbnN0cnVjdG9yKHN0b3JlOiBKc29uQmxvYlN0b3JlLCBiYXNlVXJsOiBzdHJpbmcsIHNlY3JldDogc3RyaW5nKSB7XG4gICAgdGhpcy5zdG9yZSA9IHN0b3JlO1xuICAgIHRoaXMuYmFzZVVybCA9IGJhc2VVcmw7XG4gICAgdGhpcy5zZWNyZXQgPSBzZWNyZXQ7XG4gIH1cblxuICBhc3luYyBwcmVwYXJlVXBsb2FkKFxuICAgIGlucHV0OiBQcmVwYXJlQmxvYlVwbG9hZFJlcXVlc3QsXG4gICAgb3duZXI6IHsgdXNlcklkOiBzdHJpbmc7IGRldmljZUlkOiBzdHJpbmcgfSxcbiAgICBub3c6IG51bWJlclxuICApOiBQcm9taXNlPFByZXBhcmVCbG9iVXBsb2FkUmVzdWx0PiB7XG4gICAgaWYgKCFpbnB1dC50YXNrSWQgfHwgIWlucHV0LmNvbnZlcnNhdGlvbklkIHx8ICFpbnB1dC5tZXNzYWdlSWQgfHwgIWlucHV0Lm1pbWVUeXBlIHx8IGlucHV0LnNpemVCeXRlcyA8PSAwKSB7XG4gICAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMCwgXCJpbnZhbGlkX2lucHV0XCIsIFwicHJlcGFyZSB1cGxvYWQgcmVxdWVzdCBpcyBtaXNzaW5nIHJlcXVpcmVkIGZpZWxkc1wiKTtcbiAgICB9XG4gICAgY29uc3QgYmxvYktleSA9IFtcbiAgICAgIFwiYmxvYlwiLFxuICAgICAgc2FuaXRpemVTZWdtZW50KG93bmVyLnVzZXJJZCksXG4gICAgICBzYW5pdGl6ZVNlZ21lbnQob3duZXIuZGV2aWNlSWQpLFxuICAgICAgc2FuaXRpemVTZWdtZW50KGlucHV0LmNvbnZlcnNhdGlvbklkKSxcbiAgICAgIGAke3Nhbml0aXplU2VnbWVudChpbnB1dC5tZXNzYWdlSWQpfS0ke3Nhbml0aXplU2VnbWVudChpbnB1dC50YXNrSWQpfWBcbiAgICBdLmpvaW4oXCIvXCIpO1xuICAgIGNvbnN0IGV4cGlyZXNBdCA9IG5vdyArIDE1ICogNjAgKiAxMDAwO1xuICAgIGNvbnN0IHVwbG9hZFRva2VuID0gYXdhaXQgc2lnblNoYXJpbmdQYXlsb2FkKHRoaXMuc2VjcmV0LCB7XG4gICAgICBhY3Rpb246IFwidXBsb2FkXCIsXG4gICAgICBibG9iS2V5LFxuICAgICAgZXhwaXJlc0F0XG4gICAgfSk7XG4gICAgY29uc3QgZG93bmxvYWRUb2tlbiA9IGF3YWl0IHNpZ25TaGFyaW5nUGF5bG9hZCh0aGlzLnNlY3JldCwge1xuICAgICAgYWN0aW9uOiBcImRvd25sb2FkXCIsXG4gICAgICBibG9iS2V5LFxuICAgICAgZXhwaXJlc0F0XG4gICAgfSk7XG5cbiAgICByZXR1cm4ge1xuICAgICAgYmxvYlJlZjogYmxvYktleSxcbiAgICAgIHVwbG9hZFRhcmdldDogYCR7dGhpcy5iYXNlVXJsfS92MS9zdG9yYWdlL3VwbG9hZC8ke2VuY29kZVVSSUNvbXBvbmVudChibG9iS2V5KX0/dG9rZW49JHtlbmNvZGVVUklDb21wb25lbnQodXBsb2FkVG9rZW4pfWAsXG4gICAgICB1cGxvYWRIZWFkZXJzOiB7XG4gICAgICAgIFwiY29udGVudC10eXBlXCI6IGlucHV0Lm1pbWVUeXBlXG4gICAgICB9LFxuICAgICAgZG93bmxvYWRUYXJnZXQ6IGAke3RoaXMuYmFzZVVybH0vdjEvc3RvcmFnZS9ibG9iLyR7ZW5jb2RlVVJJQ29tcG9uZW50KGJsb2JLZXkpfT90b2tlbj0ke2VuY29kZVVSSUNvbXBvbmVudChkb3dubG9hZFRva2VuKX1gLFxuICAgICAgZXhwaXJlc0F0XG4gICAgfTtcbiAgfVxuXG4gIGFzeW5jIHVwbG9hZEJsb2IoYmxvYktleTogc3RyaW5nLCB0b2tlbjogc3RyaW5nLCBib2R5OiBBcnJheUJ1ZmZlciwgbWV0YWRhdGE6IFJlY29yZDxzdHJpbmcsIHN0cmluZz4sIG5vdzogbnVtYmVyKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgcGF5bG9hZCA9IGF3YWl0IHRoaXMudmVyaWZ5VG9rZW48eyBhY3Rpb246IHN0cmluZzsgYmxvYktleTogc3RyaW5nIH0+KHRva2VuLCBub3cpO1xuICAgIGlmIChwYXlsb2FkLmFjdGlvbiAhPT0gXCJ1cGxvYWRcIiB8fCBwYXlsb2FkLmJsb2JLZXkgIT09IGJsb2JLZXkpIHtcbiAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAzLCBcImludmFsaWRfY2FwYWJpbGl0eVwiLCBcInVwbG9hZCB0b2tlbiBpcyBub3QgdmFsaWQgZm9yIHRoaXMgYmxvYlwiKTtcbiAgICB9XG4gICAgYXdhaXQgdGhpcy5zdG9yZS5wdXRCeXRlcyhibG9iS2V5LCBib2R5LCBtZXRhZGF0YSk7XG4gIH1cblxuICBhc3luYyBmZXRjaEJsb2IoYmxvYktleTogc3RyaW5nLCB0b2tlbjogc3RyaW5nLCBub3c6IG51bWJlcik6IFByb21pc2U8QXJyYXlCdWZmZXI+IHtcbiAgICBjb25zdCBwYXlsb2FkID0gYXdhaXQgdGhpcy52ZXJpZnlUb2tlbjx7IGFjdGlvbjogc3RyaW5nOyBibG9iS2V5OiBzdHJpbmcgfT4odG9rZW4sIG5vdyk7XG4gICAgaWYgKHBheWxvYWQuYWN0aW9uICE9PSBcImRvd25sb2FkXCIgfHwgcGF5bG9hZC5ibG9iS2V5ICE9PSBibG9iS2V5KSB7XG4gICAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMywgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJkb3dubG9hZCB0b2tlbiBpcyBub3QgdmFsaWQgZm9yIHRoaXMgYmxvYlwiKTtcbiAgICB9XG4gICAgY29uc3Qgb2JqZWN0ID0gYXdhaXQgdGhpcy5zdG9yZS5nZXRCeXRlcyhibG9iS2V5KTtcbiAgICBpZiAoIW9iamVjdCkge1xuICAgICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDQsIFwiYmxvYl9ub3RfZm91bmRcIiwgXCJibG9iIGRvZXMgbm90IGV4aXN0XCIpO1xuICAgIH1cbiAgICByZXR1cm4gb2JqZWN0O1xuICB9XG5cbiAgYXN5bmMgcHV0SnNvbjxUPihrZXk6IHN0cmluZywgdmFsdWU6IFQpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLnN0b3JlLnB1dEpzb24oa2V5LCB2YWx1ZSk7XG4gIH1cblxuICBhc3luYyBnZXRKc29uPFQ+KGtleTogc3RyaW5nKTogUHJvbWlzZTxUIHwgbnVsbD4ge1xuICAgIHJldHVybiB0aGlzLnN0b3JlLmdldEpzb248VD4oa2V5KTtcbiAgfVxuXG4gIGFzeW5jIGRlbGV0ZShrZXk6IHN0cmluZyk6IFByb21pc2U8dm9pZD4ge1xuICAgIGF3YWl0IHRoaXMuc3RvcmUuZGVsZXRlKGtleSk7XG4gIH1cblxuICBwcml2YXRlIGFzeW5jIHZlcmlmeVRva2VuPFQ+KHRva2VuOiBzdHJpbmcsIG5vdzogbnVtYmVyKTogUHJvbWlzZTxUPiB7XG4gICAgdHJ5IHtcbiAgICAgIHJldHVybiBhd2FpdCB2ZXJpZnlTaGFyaW5nUGF5bG9hZDxUPih0aGlzLnNlY3JldCwgdG9rZW4sIG5vdyk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGNvbnN0IG1lc3NhZ2UgPSBlcnJvciBpbnN0YW5jZW9mIEVycm9yID8gZXJyb3IubWVzc2FnZSA6IFwiaW52YWxpZCBzaGFyaW5nIHRva2VuXCI7XG4gICAgICBpZiAobWVzc2FnZS5pbmNsdWRlcyhcImV4cGlyZWRcIikpIHtcbiAgICAgICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiY2FwYWJpbGl0eV9leHBpcmVkXCIsIG1lc3NhZ2UpO1xuICAgICAgfVxuICAgICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIG1lc3NhZ2UpO1xuICAgIH1cbiAgfVxufVxyXG4iLCAiaW1wb3J0IHtcbiAgSHR0cEVycm9yLFxuICB2YWxpZGF0ZUFueURldmljZVJ1bnRpbWVBdXRob3JpemF0aW9uLFxuICB2YWxpZGF0ZUFwcGVuZEF1dGhvcml6YXRpb24sXG4gIHZhbGlkYXRlQm9vdHN0cmFwQXV0aG9yaXphdGlvbixcbiAgdmFsaWRhdGVEZXZpY2VSdW50aW1lQXV0aG9yaXphdGlvbkZvckRldmljZSxcbiAgdmFsaWRhdGVLZXlQYWNrYWdlV3JpdGVBdXRob3JpemF0aW9uLFxuICB2YWxpZGF0ZVNoYXJlZFN0YXRlV3JpdGVBdXRob3JpemF0aW9uXG59IGZyb20gXCIuLi9hdXRoL2NhcGFiaWxpdHlcIjtcbmltcG9ydCB7IHNpZ25TaGFyaW5nUGF5bG9hZCB9IGZyb20gXCIuLi9zdG9yYWdlL3NoYXJpbmdcIjtcbmltcG9ydCB7IFNoYXJlZFN0YXRlU2VydmljZSB9IGZyb20gXCIuLi9zdG9yYWdlL3NoYXJlZC1zdGF0ZVwiO1xuaW1wb3J0IHsgU3RvcmFnZVNlcnZpY2UgfSBmcm9tIFwiLi4vc3RvcmFnZS9zZXJ2aWNlXCI7XG5pbXBvcnQge1xuICBDVVJSRU5UX01PREVMX1ZFUlNJT04sXG4gIHR5cGUgQXBwZW5kRW52ZWxvcGVSZXF1ZXN0LFxuICB0eXBlIEJvb3RzdHJhcERldmljZVJlcXVlc3QsXG4gIHR5cGUgRGVwbG95bWVudEJ1bmRsZSxcbiAgdHlwZSBEZXZpY2VSdW50aW1lQXV0aCxcbiAgdHlwZSBEZXZpY2VTdGF0dXNEb2N1bWVudCxcbiAgdHlwZSBJZGVudGl0eUJ1bmRsZSxcbiAgdHlwZSBLZXlQYWNrYWdlUmVmc0RvY3VtZW50LFxuICB0eXBlIFByZXBhcmVCbG9iVXBsb2FkUmVxdWVzdFxufSBmcm9tIFwiLi4vdHlwZXMvY29udHJhY3RzXCI7XG5pbXBvcnQgdHlwZSB7IEVudiB9IGZyb20gXCIuLi90eXBlcy9ydW50aW1lXCI7XG5cbmZ1bmN0aW9uIHZlcnNpb25lZEJvZHkoYm9keTogdW5rbm93bik6IHVua25vd24ge1xuICBpZiAoIWJvZHkgfHwgdHlwZW9mIGJvZHkgIT09IFwib2JqZWN0XCIgfHwgQXJyYXkuaXNBcnJheShib2R5KSkge1xuICAgIHJldHVybiBib2R5O1xuICB9XG4gIGNvbnN0IHJlY29yZCA9IGJvZHkgYXMgUmVjb3JkPHN0cmluZywgdW5rbm93bj47XG4gIGlmIChyZWNvcmQudmVyc2lvbiAhPT0gdW5kZWZpbmVkKSB7XG4gICAgcmV0dXJuIGJvZHk7XG4gIH1cbiAgcmV0dXJuIHtcbiAgICB2ZXJzaW9uOiBDVVJSRU5UX01PREVMX1ZFUlNJT04sXG4gICAgLi4ucmVjb3JkXG4gIH07XG59XG5cbmZ1bmN0aW9uIGpzb25SZXNwb25zZShib2R5OiB1bmtub3duLCBzdGF0dXMgPSAyMDApOiBSZXNwb25zZSB7XG4gIHJldHVybiBuZXcgUmVzcG9uc2UoSlNPTi5zdHJpbmdpZnkodmVyc2lvbmVkQm9keShib2R5KSksIHtcbiAgICBzdGF0dXMsXG4gICAgaGVhZGVyczoge1xuICAgICAgXCJjb250ZW50LXR5cGVcIjogXCJhcHBsaWNhdGlvbi9qc29uXCJcbiAgICB9XG4gIH0pO1xufVxuXG5jbGFzcyBSMkpzb25CbG9iU3RvcmUge1xuICBwcml2YXRlIHJlYWRvbmx5IGJ1Y2tldDogRW52W1wiVEFQQ0hBVF9TVE9SQUdFXCJdO1xuXG4gIGNvbnN0cnVjdG9yKGJ1Y2tldDogRW52W1wiVEFQQ0hBVF9TVE9SQUdFXCJdKSB7XG4gICAgdGhpcy5idWNrZXQgPSBidWNrZXQ7XG4gIH1cblxuICBhc3luYyBwdXRKc29uPFQ+KGtleTogc3RyaW5nLCB2YWx1ZTogVCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGF3YWl0IHRoaXMuYnVja2V0LnB1dChrZXksIEpTT04uc3RyaW5naWZ5KHZhbHVlKSk7XG4gIH1cblxuICBhc3luYyBnZXRKc29uPFQ+KGtleTogc3RyaW5nKTogUHJvbWlzZTxUIHwgbnVsbD4ge1xuICAgIGNvbnN0IG9iamVjdCA9IGF3YWl0IHRoaXMuYnVja2V0LmdldChrZXkpO1xuICAgIGlmICghb2JqZWN0KSB7XG4gICAgICByZXR1cm4gbnVsbDtcbiAgICB9XG4gICAgcmV0dXJuIGF3YWl0IG9iamVjdC5qc29uPFQ+KCk7XG4gIH1cblxuICBhc3luYyBwdXRCeXRlcyhrZXk6IHN0cmluZywgdmFsdWU6IEFycmF5QnVmZmVyIHwgVWludDhBcnJheSwgbWV0YWRhdGE/OiBSZWNvcmQ8c3RyaW5nLCBzdHJpbmc+KTogUHJvbWlzZTx2b2lkPiB7XG4gICAgYXdhaXQgdGhpcy5idWNrZXQucHV0KGtleSwgdmFsdWUsIG1ldGFkYXRhID8geyBodHRwTWV0YWRhdGE6IG1ldGFkYXRhIH0gOiB1bmRlZmluZWQpO1xuICB9XG5cbiAgYXN5bmMgZ2V0Qnl0ZXMoa2V5OiBzdHJpbmcpOiBQcm9taXNlPEFycmF5QnVmZmVyIHwgbnVsbD4ge1xuICAgIGNvbnN0IG9iamVjdCA9IGF3YWl0IHRoaXMuYnVja2V0LmdldChrZXkpO1xuICAgIGlmICghb2JqZWN0KSB7XG4gICAgICByZXR1cm4gbnVsbDtcbiAgICB9XG4gICAgcmV0dXJuIG9iamVjdC5hcnJheUJ1ZmZlcigpO1xuICB9XG5cbiAgYXN5bmMgZGVsZXRlKGtleTogc3RyaW5nKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgYXdhaXQgdGhpcy5idWNrZXQuZGVsZXRlKGtleSk7XG4gIH1cbn1cblxuZnVuY3Rpb24gYmFzZVVybChyZXF1ZXN0OiBSZXF1ZXN0LCBlbnY6IEVudik6IHN0cmluZyB7XG4gIHJldHVybiBlbnYuUFVCTElDX0JBU0VfVVJMPy50cmltKCkucmVwbGFjZSgvXFwvKyQvLCBcIlwiKSA/PyBuZXcgVVJMKHJlcXVlc3QudXJsKS5vcmlnaW47XG59XG5cbmZ1bmN0aW9uIHNoYXJlZFN0YXRlU2VjcmV0KGVudjogRW52KTogc3RyaW5nIHtcbiAgcmV0dXJuIGVudi5TSEFSSU5HX1RPS0VOX1NFQ1JFVCA/PyBcInJlcGxhY2UtbWVcIjtcbn1cblxuZnVuY3Rpb24gYm9vdHN0cmFwU2VjcmV0KGVudjogRW52KTogc3RyaW5nIHtcbiAgcmV0dXJuIGVudi5CT09UU1RSQVBfVE9LRU5fU0VDUkVUID8/IGVudi5TSEFSSU5HX1RPS0VOX1NFQ1JFVCA/PyBcInJlcGxhY2UtbWVcIjtcbn1cblxuZnVuY3Rpb24gcnVudGltZVNjb3BlcygpOiBEZXZpY2VSdW50aW1lQXV0aFtcInNjb3Blc1wiXSB7XG4gIHJldHVybiBbXG4gICAgXCJpbmJveF9yZWFkXCIsXG4gICAgXCJpbmJveF9hY2tcIixcbiAgICBcImluYm94X3N1YnNjcmliZVwiLFxuICAgIFwic3RvcmFnZV9wcmVwYXJlX3VwbG9hZFwiLFxuICAgIFwic2hhcmVkX3N0YXRlX3dyaXRlXCIsXG4gICAgXCJrZXlwYWNrYWdlX3dyaXRlXCJcbiAgXTtcbn1cblxuYXN5bmMgZnVuY3Rpb24gaXNzdWVEZXZpY2VSdW50aW1lQXV0aChlbnY6IEVudiwgdXNlcklkOiBzdHJpbmcsIGRldmljZUlkOiBzdHJpbmcsIG5vdzogbnVtYmVyKTogUHJvbWlzZTxEZXZpY2VSdW50aW1lQXV0aD4ge1xuICBjb25zdCBleHBpcmVzQXQgPSBub3cgKyAyNCAqIDYwICogNjAgKiAxMDAwO1xuICBjb25zdCBzY29wZXMgPSBydW50aW1lU2NvcGVzKCk7XG4gIGNvbnN0IHRva2VuID0gYXdhaXQgc2lnblNoYXJpbmdQYXlsb2FkKHNoYXJlZFN0YXRlU2VjcmV0KGVudiksIHtcbiAgICB2ZXJzaW9uOiBDVVJSRU5UX01PREVMX1ZFUlNJT04sXG4gICAgc2VydmljZTogXCJkZXZpY2VfcnVudGltZVwiLFxuICAgIHVzZXJJZCxcbiAgICBkZXZpY2VJZCxcbiAgICBzY29wZXMsXG4gICAgZXhwaXJlc0F0XG4gIH0pO1xuICByZXR1cm4ge1xuICAgIHNjaGVtZTogXCJiZWFyZXJcIixcbiAgICB0b2tlbixcbiAgICBleHBpcmVzQXQsXG4gICAgdXNlcklkLFxuICAgIGRldmljZUlkLFxuICAgIHNjb3Blc1xuICB9O1xufVxuXG5mdW5jdGlvbiBwdWJsaWNEZXBsb3ltZW50QnVuZGxlKHJlcXVlc3Q6IFJlcXVlc3QsIGVudjogRW52KTogRGVwbG95bWVudEJ1bmRsZSB7XG4gIHJldHVybiB7XG4gICAgdmVyc2lvbjogQ1VSUkVOVF9NT0RFTF9WRVJTSU9OLFxuICAgIHJlZ2lvbjogZW52LkRFUExPWU1FTlRfUkVHSU9OID8/IFwibG9jYWxcIixcbiAgICBpbmJveEh0dHBFbmRwb2ludDogYmFzZVVybChyZXF1ZXN0LCBlbnYpLFxuICAgIGluYm94V2Vic29ja2V0RW5kcG9pbnQ6IGAke2Jhc2VVcmwocmVxdWVzdCwgZW52KS5yZXBsYWNlKC9eaHR0cC9pLCBcIndzXCIpfS92MS9pbmJveC97ZGV2aWNlSWR9L3N1YnNjcmliZWAsXG4gICAgc3RvcmFnZUJhc2VJbmZvOiB7XG4gICAgICBiYXNlVXJsOiBiYXNlVXJsKHJlcXVlc3QsIGVudiksXG4gICAgICBidWNrZXRIaW50OiBcInRhcGNoYXQtc3RvcmFnZVwiXG4gICAgfSxcbiAgICBydW50aW1lQ29uZmlnOiB7XG4gICAgICBzdXBwb3J0ZWRSZWFsdGltZUtpbmRzOiBbXCJ3ZWJzb2NrZXRcIl0sXG4gICAgICBpZGVudGl0eUJ1bmRsZVJlZjogYCR7YmFzZVVybChyZXF1ZXN0LCBlbnYpfS92MS9zaGFyZWQtc3RhdGUve3VzZXJJZH0vaWRlbnRpdHktYnVuZGxlYCxcbiAgICAgIGRldmljZVN0YXR1c1JlZjogYCR7YmFzZVVybChyZXF1ZXN0LCBlbnYpfS92MS9zaGFyZWQtc3RhdGUve3VzZXJJZH0vZGV2aWNlLXN0YXR1c2AsXG4gICAgICBrZXlwYWNrYWdlUmVmQmFzZTogYCR7YmFzZVVybChyZXF1ZXN0LCBlbnYpfS92MS9zaGFyZWQtc3RhdGUva2V5cGFja2FnZXNgLFxuICAgICAgbWF4SW5saW5lQnl0ZXM6IE51bWJlcihlbnYuTUFYX0lOTElORV9CWVRFUyA/PyBcIjQwOTZcIiksXG4gICAgICBmZWF0dXJlczogW1wiZ2VuZXJpY19zeW5jXCIsIFwiYXR0YWNobWVudF92MVwiXVxuICAgIH1cbiAgfTtcbn1cblxuYXN5bmMgZnVuY3Rpb24gYXV0aG9yaXplU2hhcmVkU3RhdGVXcml0ZShcbiAgcmVxdWVzdDogUmVxdWVzdCxcbiAgZW52OiBFbnYsXG4gIHVzZXJJZDogc3RyaW5nLFxuICBvYmplY3RLaW5kOiBcImlkZW50aXR5X2J1bmRsZVwiIHwgXCJkZXZpY2Vfc3RhdHVzXCIsXG4gIG5vdzogbnVtYmVyXG4pOiBQcm9taXNlPHZvaWQ+IHtcbiAgdHJ5IHtcbiAgICBjb25zdCBhdXRoID0gYXdhaXQgdmFsaWRhdGVBbnlEZXZpY2VSdW50aW1lQXV0aG9yaXphdGlvbihyZXF1ZXN0LCBzaGFyZWRTdGF0ZVNlY3JldChlbnYpLCBcInNoYXJlZF9zdGF0ZV93cml0ZVwiLCBub3cpO1xuICAgIGlmIChhdXRoLnVzZXJJZCAhPT0gdXNlcklkKSB7XG4gICAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMywgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJkZXZpY2UgcnVudGltZSB0b2tlbiBzY29wZSBkb2VzIG5vdCBtYXRjaCByZXF1ZXN0IHBhdGhcIik7XG4gICAgfVxuICAgIHJldHVybjtcbiAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICBpZiAoIShlcnJvciBpbnN0YW5jZW9mIEh0dHBFcnJvcikgfHwgZXJyb3IuY29kZSA9PT0gXCJjYXBhYmlsaXR5X2V4cGlyZWRcIikge1xuICAgICAgdGhyb3cgZXJyb3I7XG4gICAgfVxuICB9XG4gIGF3YWl0IHZhbGlkYXRlU2hhcmVkU3RhdGVXcml0ZUF1dGhvcml6YXRpb24ocmVxdWVzdCwgc2hhcmVkU3RhdGVTZWNyZXQoZW52KSwgdXNlcklkLCBcIlwiLCBvYmplY3RLaW5kLCBub3cpO1xufVxuXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gaGFuZGxlUmVxdWVzdChyZXF1ZXN0OiBSZXF1ZXN0LCBlbnY6IEVudik6IFByb21pc2U8UmVzcG9uc2U+IHtcbiAgY29uc3QgdXJsID0gbmV3IFVSTChyZXF1ZXN0LnVybCk7XG4gIGNvbnN0IHN0b3JlID0gbmV3IFN0b3JhZ2VTZXJ2aWNlKFxuICAgIG5ldyBSMkpzb25CbG9iU3RvcmUoZW52LlRBUENIQVRfU1RPUkFHRSksXG4gICAgYmFzZVVybChyZXF1ZXN0LCBlbnYpLFxuICAgIHNoYXJlZFN0YXRlU2VjcmV0KGVudilcbiAgKTtcbiAgY29uc3Qgc2hhcmVkU3RhdGUgPSBuZXcgU2hhcmVkU3RhdGVTZXJ2aWNlKG5ldyBSMkpzb25CbG9iU3RvcmUoZW52LlRBUENIQVRfU1RPUkFHRSksIGJhc2VVcmwocmVxdWVzdCwgZW52KSk7XG4gIGNvbnN0IG5vdyA9IERhdGUubm93KCk7XG5cbiAgdHJ5IHtcbiAgICBpZiAocmVxdWVzdC5tZXRob2QgPT09IFwiR0VUXCIgJiYgdXJsLnBhdGhuYW1lID09PSBcIi92MS9kZXBsb3ltZW50LWJ1bmRsZVwiKSB7XG4gICAgICByZXR1cm4ganNvblJlc3BvbnNlKHB1YmxpY0RlcGxveW1lbnRCdW5kbGUocmVxdWVzdCwgZW52KSk7XG4gICAgfVxuXG4gICAgaWYgKHJlcXVlc3QubWV0aG9kID09PSBcIlBPU1RcIiAmJiB1cmwucGF0aG5hbWUgPT09IFwiL3YxL2Jvb3RzdHJhcC9kZXZpY2VcIikge1xuICAgICAgY29uc3QgYm9keSA9IChhd2FpdCByZXF1ZXN0Lmpzb24oKSkgYXMgQm9vdHN0cmFwRGV2aWNlUmVxdWVzdDtcbiAgICAgIGlmIChib2R5LnZlcnNpb24gIT09IENVUlJFTlRfTU9ERUxfVkVSU0lPTikge1xuICAgICAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMCwgXCJ1bnN1cHBvcnRlZF92ZXJzaW9uXCIsIFwiYm9vdHN0cmFwIHJlcXVlc3QgdmVyc2lvbiBpcyBub3Qgc3VwcG9ydGVkXCIpO1xuICAgICAgfVxuICAgICAgYXdhaXQgdmFsaWRhdGVCb290c3RyYXBBdXRob3JpemF0aW9uKHJlcXVlc3QsIGJvb3RzdHJhcFNlY3JldChlbnYpLCBib2R5LnVzZXJJZCwgYm9keS5kZXZpY2VJZCwgbm93KTtcbiAgICAgIGNvbnN0IGJ1bmRsZTogRGVwbG95bWVudEJ1bmRsZSA9IHtcbiAgICAgICAgLi4ucHVibGljRGVwbG95bWVudEJ1bmRsZShyZXF1ZXN0LCBlbnYpLFxuICAgICAgICBkZXZpY2VSdW50aW1lQXV0aDogYXdhaXQgaXNzdWVEZXZpY2VSdW50aW1lQXV0aChlbnYsIGJvZHkudXNlcklkLCBib2R5LmRldmljZUlkLCBub3cpLFxuICAgICAgICBleHBlY3RlZFVzZXJJZDogYm9keS51c2VySWQsXG4gICAgICAgIGV4cGVjdGVkRGV2aWNlSWQ6IGJvZHkuZGV2aWNlSWRcbiAgICAgIH07XG4gICAgICByZXR1cm4ganNvblJlc3BvbnNlKGJ1bmRsZSk7XG4gICAgfVxuXG4gICAgY29uc3QgaW5ib3hNYXRjaCA9IHVybC5wYXRobmFtZS5tYXRjaCgvXlxcL3YxXFwvaW5ib3hcXC8oW14vXSspXFwvKG1lc3NhZ2VzfGFja3xoZWFkfHN1YnNjcmliZSkkLyk7XG4gICAgaWYgKGluYm94TWF0Y2gpIHtcbiAgICAgIGNvbnN0IGRldmljZUlkID0gZGVjb2RlVVJJQ29tcG9uZW50KGluYm94TWF0Y2hbMV0pO1xuICAgICAgY29uc3Qgb3BlcmF0aW9uID0gaW5ib3hNYXRjaFsyXTtcbiAgICAgIGNvbnN0IG9iamVjdElkID0gZW52LklOQk9YLmlkRnJvbU5hbWUoZGV2aWNlSWQpO1xuICAgICAgY29uc3Qgc3R1YiA9IGVudi5JTkJPWC5nZXQob2JqZWN0SWQpO1xuXG4gICAgICBpZiAocmVxdWVzdC5tZXRob2QgPT09IFwiUE9TVFwiICYmIG9wZXJhdGlvbiA9PT0gXCJtZXNzYWdlc1wiKSB7XG4gICAgICAgIGNvbnN0IGJvZHkgPSAoYXdhaXQgcmVxdWVzdC5jbG9uZSgpLmpzb24oKSkgYXMgQXBwZW5kRW52ZWxvcGVSZXF1ZXN0O1xuICAgICAgICB2YWxpZGF0ZUFwcGVuZEF1dGhvcml6YXRpb24ocmVxdWVzdCwgZGV2aWNlSWQsIGJvZHksIG5vdyk7XG4gICAgICB9IGVsc2UgaWYgKHJlcXVlc3QubWV0aG9kID09PSBcIkdFVFwiICYmIChvcGVyYXRpb24gPT09IFwibWVzc2FnZXNcIiB8fCBvcGVyYXRpb24gPT09IFwiaGVhZFwiKSkge1xuICAgICAgICBhd2FpdCB2YWxpZGF0ZURldmljZVJ1bnRpbWVBdXRob3JpemF0aW9uRm9yRGV2aWNlKHJlcXVlc3QsIHNoYXJlZFN0YXRlU2VjcmV0KGVudiksIGRldmljZUlkLCBcImluYm94X3JlYWRcIiwgbm93KTtcbiAgICAgIH0gZWxzZSBpZiAocmVxdWVzdC5tZXRob2QgPT09IFwiUE9TVFwiICYmIG9wZXJhdGlvbiA9PT0gXCJhY2tcIikge1xuICAgICAgICBhd2FpdCB2YWxpZGF0ZURldmljZVJ1bnRpbWVBdXRob3JpemF0aW9uRm9yRGV2aWNlKHJlcXVlc3QsIHNoYXJlZFN0YXRlU2VjcmV0KGVudiksIGRldmljZUlkLCBcImluYm94X2Fja1wiLCBub3cpO1xuICAgICAgfSBlbHNlIGlmIChvcGVyYXRpb24gPT09IFwic3Vic2NyaWJlXCIpIHtcbiAgICAgICAgYXdhaXQgdmFsaWRhdGVEZXZpY2VSdW50aW1lQXV0aG9yaXphdGlvbkZvckRldmljZShyZXF1ZXN0LCBzaGFyZWRTdGF0ZVNlY3JldChlbnYpLCBkZXZpY2VJZCwgXCJpbmJveF9zdWJzY3JpYmVcIiwgbm93KTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIHN0dWIuZmV0Y2gocmVxdWVzdCk7XG4gICAgfVxuXG4gICAgY29uc3QgaWRlbnRpdHlCdW5kbGVNYXRjaCA9IHVybC5wYXRobmFtZS5tYXRjaCgvXlxcL3YxXFwvc2hhcmVkLXN0YXRlXFwvKFteL10rKVxcL2lkZW50aXR5LWJ1bmRsZSQvKTtcbiAgICBpZiAoaWRlbnRpdHlCdW5kbGVNYXRjaCkge1xuICAgICAgY29uc3QgdXNlcklkID0gZGVjb2RlVVJJQ29tcG9uZW50KGlkZW50aXR5QnVuZGxlTWF0Y2hbMV0pO1xuICAgICAgaWYgKHJlcXVlc3QubWV0aG9kID09PSBcIkdFVFwiKSB7XG4gICAgICAgIGNvbnN0IGJ1bmRsZSA9IGF3YWl0IHNoYXJlZFN0YXRlLmdldElkZW50aXR5QnVuZGxlKHVzZXJJZCk7XG4gICAgICAgIGlmICghYnVuZGxlKSB7XG4gICAgICAgICAgcmV0dXJuIGpzb25SZXNwb25zZSh7IGVycm9yOiBcIm5vdF9mb3VuZFwiLCBtZXNzYWdlOiBcImlkZW50aXR5IGJ1bmRsZSBub3QgZm91bmRcIiB9LCA0MDQpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBqc29uUmVzcG9uc2UoYnVuZGxlKTtcbiAgICAgIH1cbiAgICAgIGlmIChyZXF1ZXN0Lm1ldGhvZCA9PT0gXCJQVVRcIikge1xuICAgICAgICBhd2FpdCBhdXRob3JpemVTaGFyZWRTdGF0ZVdyaXRlKHJlcXVlc3QsIGVudiwgdXNlcklkLCBcImlkZW50aXR5X2J1bmRsZVwiLCBub3cpO1xuICAgICAgICBjb25zdCBib2R5ID0gKGF3YWl0IHJlcXVlc3QuanNvbigpKSBhcyBJZGVudGl0eUJ1bmRsZTtcbiAgICAgICAgYXdhaXQgc2hhcmVkU3RhdGUucHV0SWRlbnRpdHlCdW5kbGUodXNlcklkLCBib2R5KTtcbiAgICAgICAgY29uc3Qgc2F2ZWQgPSBhd2FpdCBzaGFyZWRTdGF0ZS5nZXRJZGVudGl0eUJ1bmRsZSh1c2VySWQpO1xuICAgICAgICByZXR1cm4ganNvblJlc3BvbnNlKHNhdmVkKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBjb25zdCBkZXZpY2VTdGF0dXNNYXRjaCA9IHVybC5wYXRobmFtZS5tYXRjaCgvXlxcL3YxXFwvc2hhcmVkLXN0YXRlXFwvKFteL10rKVxcL2RldmljZS1zdGF0dXMkLyk7XG4gICAgaWYgKGRldmljZVN0YXR1c01hdGNoKSB7XG4gICAgICBjb25zdCB1c2VySWQgPSBkZWNvZGVVUklDb21wb25lbnQoZGV2aWNlU3RhdHVzTWF0Y2hbMV0pO1xuICAgICAgaWYgKHJlcXVlc3QubWV0aG9kID09PSBcIkdFVFwiKSB7XG4gICAgICAgIGNvbnN0IGRvY3VtZW50ID0gYXdhaXQgc2hhcmVkU3RhdGUuZ2V0RGV2aWNlU3RhdHVzKHVzZXJJZCk7XG4gICAgICAgIGlmICghZG9jdW1lbnQpIHtcbiAgICAgICAgICByZXR1cm4ganNvblJlc3BvbnNlKHsgZXJyb3I6IFwibm90X2ZvdW5kXCIsIG1lc3NhZ2U6IFwiZGV2aWNlIHN0YXR1cyBub3QgZm91bmRcIiB9LCA0MDQpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBqc29uUmVzcG9uc2UoZG9jdW1lbnQpO1xuICAgICAgfVxuICAgICAgaWYgKHJlcXVlc3QubWV0aG9kID09PSBcIlBVVFwiKSB7XG4gICAgICAgIGF3YWl0IGF1dGhvcml6ZVNoYXJlZFN0YXRlV3JpdGUocmVxdWVzdCwgZW52LCB1c2VySWQsIFwiZGV2aWNlX3N0YXR1c1wiLCBub3cpO1xuICAgICAgICBjb25zdCBib2R5ID0gKGF3YWl0IHJlcXVlc3QuanNvbigpKSBhcyBEZXZpY2VTdGF0dXNEb2N1bWVudDtcbiAgICAgICAgYXdhaXQgc2hhcmVkU3RhdGUucHV0RGV2aWNlU3RhdHVzKHVzZXJJZCwgYm9keSk7XG4gICAgICAgIGNvbnN0IHNhdmVkID0gYXdhaXQgc2hhcmVkU3RhdGUuZ2V0RGV2aWNlU3RhdHVzKHVzZXJJZCk7XG4gICAgICAgIHJldHVybiBqc29uUmVzcG9uc2Uoc2F2ZWQpO1xuICAgICAgfVxuICAgIH1cblxuICAgIGNvbnN0IGRldmljZUxpc3RNYXRjaCA9IHVybC5wYXRobmFtZS5tYXRjaCgvXlxcL3YxXFwvc2hhcmVkLXN0YXRlXFwvKFteL10rKVxcL2RldmljZS1saXN0JC8pO1xuICAgIGlmIChkZXZpY2VMaXN0TWF0Y2ggJiYgcmVxdWVzdC5tZXRob2QgPT09IFwiR0VUXCIpIHtcbiAgICAgIGNvbnN0IHVzZXJJZCA9IGRlY29kZVVSSUNvbXBvbmVudChkZXZpY2VMaXN0TWF0Y2hbMV0pO1xuICAgICAgY29uc3QgZG9jdW1lbnQgPSBhd2FpdCBzaGFyZWRTdGF0ZS5nZXREZXZpY2VMaXN0KHVzZXJJZCk7XG4gICAgICBpZiAoIWRvY3VtZW50KSB7XG4gICAgICAgIHJldHVybiBqc29uUmVzcG9uc2UoeyBlcnJvcjogXCJub3RfZm91bmRcIiwgbWVzc2FnZTogXCJkZXZpY2UgbGlzdCBub3QgZm91bmRcIiB9LCA0MDQpO1xuICAgICAgfVxuICAgICAgcmV0dXJuIGpzb25SZXNwb25zZShkb2N1bWVudCk7XG4gICAgfVxuXG4gICAgY29uc3Qga2V5UGFja2FnZVJlZnNNYXRjaCA9IHVybC5wYXRobmFtZS5tYXRjaCgvXlxcL3YxXFwvc2hhcmVkLXN0YXRlXFwva2V5cGFja2FnZXNcXC8oW14vXSspXFwvKFteL10rKSQvKTtcbiAgICBpZiAoa2V5UGFja2FnZVJlZnNNYXRjaCkge1xuICAgICAgY29uc3QgdXNlcklkID0gZGVjb2RlVVJJQ29tcG9uZW50KGtleVBhY2thZ2VSZWZzTWF0Y2hbMV0pO1xuICAgICAgY29uc3QgZGV2aWNlSWQgPSBkZWNvZGVVUklDb21wb25lbnQoa2V5UGFja2FnZVJlZnNNYXRjaFsyXSk7XG4gICAgICBpZiAocmVxdWVzdC5tZXRob2QgPT09IFwiR0VUXCIpIHtcbiAgICAgICAgY29uc3QgZG9jdW1lbnQgPSBhd2FpdCBzaGFyZWRTdGF0ZS5nZXRLZXlQYWNrYWdlUmVmcyh1c2VySWQsIGRldmljZUlkKTtcbiAgICAgICAgaWYgKCFkb2N1bWVudCkge1xuICAgICAgICAgIHJldHVybiBqc29uUmVzcG9uc2UoeyBlcnJvcjogXCJub3RfZm91bmRcIiwgbWVzc2FnZTogXCJrZXlwYWNrYWdlIHJlZnMgbm90IGZvdW5kXCIgfSwgNDA0KTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4ganNvblJlc3BvbnNlKGRvY3VtZW50KTtcbiAgICAgIH1cbiAgICAgIGlmIChyZXF1ZXN0Lm1ldGhvZCA9PT0gXCJQVVRcIikge1xuICAgICAgICBhd2FpdCB2YWxpZGF0ZUtleVBhY2thZ2VXcml0ZUF1dGhvcml6YXRpb24ocmVxdWVzdCwgc2hhcmVkU3RhdGVTZWNyZXQoZW52KSwgdXNlcklkLCBkZXZpY2VJZCwgdW5kZWZpbmVkLCBub3cpO1xuICAgICAgICBjb25zdCBib2R5ID0gKGF3YWl0IHJlcXVlc3QuanNvbigpKSBhcyBLZXlQYWNrYWdlUmVmc0RvY3VtZW50O1xuICAgICAgICBhd2FpdCBzaGFyZWRTdGF0ZS5wdXRLZXlQYWNrYWdlUmVmcyh1c2VySWQsIGRldmljZUlkLCBib2R5KTtcbiAgICAgICAgY29uc3Qgc2F2ZWQgPSBhd2FpdCBzaGFyZWRTdGF0ZS5nZXRLZXlQYWNrYWdlUmVmcyh1c2VySWQsIGRldmljZUlkKTtcbiAgICAgICAgcmV0dXJuIGpzb25SZXNwb25zZShzYXZlZCk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgY29uc3Qga2V5UGFja2FnZU9iamVjdE1hdGNoID0gdXJsLnBhdGhuYW1lLm1hdGNoKC9eXFwvdjFcXC9zaGFyZWQtc3RhdGVcXC9rZXlwYWNrYWdlc1xcLyhbXi9dKylcXC8oW14vXSspXFwvKFteL10rKSQvKTtcbiAgICBpZiAoa2V5UGFja2FnZU9iamVjdE1hdGNoKSB7XG4gICAgICBjb25zdCB1c2VySWQgPSBkZWNvZGVVUklDb21wb25lbnQoa2V5UGFja2FnZU9iamVjdE1hdGNoWzFdKTtcbiAgICAgIGNvbnN0IGRldmljZUlkID0gZGVjb2RlVVJJQ29tcG9uZW50KGtleVBhY2thZ2VPYmplY3RNYXRjaFsyXSk7XG4gICAgICBjb25zdCBrZXlQYWNrYWdlSWQgPSBkZWNvZGVVUklDb21wb25lbnQoa2V5UGFja2FnZU9iamVjdE1hdGNoWzNdKTtcbiAgICAgIGlmIChyZXF1ZXN0Lm1ldGhvZCA9PT0gXCJHRVRcIikge1xuICAgICAgICBjb25zdCBwYXlsb2FkID0gYXdhaXQgc2hhcmVkU3RhdGUuZ2V0S2V5UGFja2FnZU9iamVjdCh1c2VySWQsIGRldmljZUlkLCBrZXlQYWNrYWdlSWQpO1xuICAgICAgICBpZiAoIXBheWxvYWQpIHtcbiAgICAgICAgICByZXR1cm4ganNvblJlc3BvbnNlKHsgZXJyb3I6IFwibm90X2ZvdW5kXCIsIG1lc3NhZ2U6IFwia2V5cGFja2FnZSBub3QgZm91bmRcIiB9LCA0MDQpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBuZXcgUmVzcG9uc2UocGF5bG9hZCwge1xuICAgICAgICAgIHN0YXR1czogMjAwLFxuICAgICAgICAgIGhlYWRlcnM6IHtcbiAgICAgICAgICAgIFwiY29udGVudC10eXBlXCI6IFwiYXBwbGljYXRpb24vb2N0ZXQtc3RyZWFtXCJcbiAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgfVxuICAgICAgaWYgKHJlcXVlc3QubWV0aG9kID09PSBcIlBVVFwiKSB7XG4gICAgICAgIGF3YWl0IHZhbGlkYXRlS2V5UGFja2FnZVdyaXRlQXV0aG9yaXphdGlvbihyZXF1ZXN0LCBzaGFyZWRTdGF0ZVNlY3JldChlbnYpLCB1c2VySWQsIGRldmljZUlkLCBrZXlQYWNrYWdlSWQsIG5vdyk7XG4gICAgICAgIGF3YWl0IHNoYXJlZFN0YXRlLnB1dEtleVBhY2thZ2VPYmplY3QodXNlcklkLCBkZXZpY2VJZCwga2V5UGFja2FnZUlkLCBhd2FpdCByZXF1ZXN0LmFycmF5QnVmZmVyKCkpO1xuICAgICAgICByZXR1cm4gbmV3IFJlc3BvbnNlKG51bGwsIHsgc3RhdHVzOiAyMDQgfSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgaWYgKHJlcXVlc3QubWV0aG9kID09PSBcIlBPU1RcIiAmJiB1cmwucGF0aG5hbWUgPT09IFwiL3YxL3N0b3JhZ2UvcHJlcGFyZS11cGxvYWRcIikge1xuICAgICAgY29uc3QgYXV0aCA9IGF3YWl0IHZhbGlkYXRlQW55RGV2aWNlUnVudGltZUF1dGhvcml6YXRpb24ocmVxdWVzdCwgc2hhcmVkU3RhdGVTZWNyZXQoZW52KSwgXCJzdG9yYWdlX3ByZXBhcmVfdXBsb2FkXCIsIG5vdyk7XG4gICAgICBjb25zdCBib2R5ID0gKGF3YWl0IHJlcXVlc3QuanNvbigpKSBhcyBQcmVwYXJlQmxvYlVwbG9hZFJlcXVlc3Q7XG4gICAgICBjb25zdCByZXN1bHQgPSBhd2FpdCBzdG9yZS5wcmVwYXJlVXBsb2FkKGJvZHksIHsgdXNlcklkOiBhdXRoLnVzZXJJZCwgZGV2aWNlSWQ6IGF1dGguZGV2aWNlSWQgfSwgbm93KTtcbiAgICAgIHJldHVybiBqc29uUmVzcG9uc2UocmVzdWx0KTtcbiAgICB9XG5cbiAgICBjb25zdCB1cGxvYWRNYXRjaCA9IHVybC5wYXRobmFtZS5tYXRjaCgvXlxcL3YxXFwvc3RvcmFnZVxcL3VwbG9hZFxcLyguKykkLyk7XG4gICAgaWYgKHJlcXVlc3QubWV0aG9kID09PSBcIlBVVFwiICYmIHVwbG9hZE1hdGNoKSB7XG4gICAgICBjb25zdCBibG9iS2V5ID0gZGVjb2RlVVJJQ29tcG9uZW50KHVwbG9hZE1hdGNoWzFdKTtcbiAgICAgIGNvbnN0IHRva2VuID0gdXJsLnNlYXJjaFBhcmFtcy5nZXQoXCJ0b2tlblwiKTtcbiAgICAgIGlmICghdG9rZW4pIHtcbiAgICAgICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDEsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwibWlzc2luZyB1cGxvYWQgdG9rZW5cIik7XG4gICAgICB9XG4gICAgICBjb25zdCBjb250ZW50VHlwZSA9IHJlcXVlc3QuaGVhZGVycy5nZXQoXCJjb250ZW50LXR5cGVcIikgPz8gXCJhcHBsaWNhdGlvbi9vY3RldC1zdHJlYW1cIjtcbiAgICAgIGF3YWl0IHN0b3JlLnVwbG9hZEJsb2IoYmxvYktleSwgdG9rZW4sIGF3YWl0IHJlcXVlc3QuYXJyYXlCdWZmZXIoKSwgeyBcImNvbnRlbnQtdHlwZVwiOiBjb250ZW50VHlwZSB9LCBub3cpO1xuICAgICAgcmV0dXJuIG5ldyBSZXNwb25zZShudWxsLCB7IHN0YXR1czogMjA0IH0pO1xuICAgIH1cblxuICAgIGNvbnN0IGJsb2JNYXRjaCA9IHVybC5wYXRobmFtZS5tYXRjaCgvXlxcL3YxXFwvc3RvcmFnZVxcL2Jsb2JcXC8oLispJC8pO1xuICAgIGlmIChyZXF1ZXN0Lm1ldGhvZCA9PT0gXCJHRVRcIiAmJiBibG9iTWF0Y2gpIHtcbiAgICAgIGNvbnN0IGJsb2JLZXkgPSBkZWNvZGVVUklDb21wb25lbnQoYmxvYk1hdGNoWzFdKTtcbiAgICAgIGNvbnN0IHRva2VuID0gdXJsLnNlYXJjaFBhcmFtcy5nZXQoXCJ0b2tlblwiKTtcbiAgICAgIGlmICghdG9rZW4pIHtcbiAgICAgICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDEsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwibWlzc2luZyBkb3dubG9hZCB0b2tlblwiKTtcbiAgICAgIH1cbiAgICAgIGNvbnN0IHBheWxvYWQgPSBhd2FpdCBzdG9yZS5mZXRjaEJsb2IoYmxvYktleSwgdG9rZW4sIG5vdyk7XG4gICAgICByZXR1cm4gbmV3IFJlc3BvbnNlKHBheWxvYWQsIHtcbiAgICAgICAgc3RhdHVzOiAyMDAsXG4gICAgICAgIGhlYWRlcnM6IHtcbiAgICAgICAgICBcImNvbnRlbnQtdHlwZVwiOiBcImFwcGxpY2F0aW9uL29jdGV0LXN0cmVhbVwiXG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHJldHVybiBqc29uUmVzcG9uc2UoeyBlcnJvcjogXCJub3RfZm91bmRcIiwgbWVzc2FnZTogXCJyb3V0ZSBub3QgZm91bmRcIiB9LCA0MDQpO1xuICB9IGNhdGNoIChlcnJvcikge1xuICAgIGlmIChlcnJvciBpbnN0YW5jZW9mIEh0dHBFcnJvcikge1xuICAgICAgcmV0dXJuIGpzb25SZXNwb25zZSh7IGVycm9yOiBlcnJvci5jb2RlLCBtZXNzYWdlOiBlcnJvci5tZXNzYWdlIH0sIGVycm9yLnN0YXR1cyk7XG4gICAgfVxuICAgIGNvbnN0IHJ1bnRpbWVFcnJvciA9IGVycm9yIGFzIHsgbWVzc2FnZT86IHN0cmluZyB9O1xuICAgIGNvbnN0IG1lc3NhZ2UgPSBydW50aW1lRXJyb3IubWVzc2FnZSA/PyBcImludGVybmFsIGVycm9yXCI7XG4gICAgcmV0dXJuIGpzb25SZXNwb25zZSh7IGVycm9yOiBcInRlbXBvcmFyeV91bmF2YWlsYWJsZVwiLCBtZXNzYWdlIH0sIDUwMCk7XG4gIH1cbn1cclxuIiwgImltcG9ydCB7IEluYm94RHVyYWJsZU9iamVjdCB9IGZyb20gXCIuL2luYm94L2R1cmFibGVcIjtcbmltcG9ydCB7IGhhbmRsZVJlcXVlc3QgfSBmcm9tIFwiLi9yb3V0ZXMvaHR0cFwiO1xuaW1wb3J0IHR5cGUgeyBFbnYgfSBmcm9tIFwiLi90eXBlcy9ydW50aW1lXCI7XG5cbmV4cG9ydCB7IEluYm94RHVyYWJsZU9iamVjdCB9O1xuXG5leHBvcnQgZGVmYXVsdCB7XG4gIGFzeW5jIGZldGNoKHJlcXVlc3Q6IFJlcXVlc3QsIGVudjogRW52KTogUHJvbWlzZTxSZXNwb25zZT4ge1xuICAgIHJldHVybiBoYW5kbGVSZXF1ZXN0KHJlcXVlc3QsIGVudik7XG4gIH1cbn07XHJcbiJdLAogICJtYXBwaW5ncyI6ICI7QUFBTyxJQUFNLHdCQUF3Qjs7O0FDQXJDLElBQU0sVUFBVSxJQUFJLFlBQVk7QUFFaEMsU0FBUyxZQUFZLE9BQTJCO0FBQzlDLE1BQUksU0FBUztBQUNiLGFBQVcsUUFBUSxPQUFPO0FBQ3hCLGNBQVUsT0FBTyxhQUFhLElBQUk7QUFBQSxFQUNwQztBQUNBLFNBQU8sS0FBSyxNQUFNLEVBQUUsUUFBUSxPQUFPLEdBQUcsRUFBRSxRQUFRLE9BQU8sR0FBRyxFQUFFLFFB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LE9BQU8sR0FBRztBQUN6RCxhQUFPLElBQUksU0FBUyxTQUFTO0FBQUEsUUFDM0IsUUFBUTtBQUFBLFFBQ1IsU0FBUztBQUFBLFVBQ1AsZ0JBQWdCO0FBQUEsUUFDbEI7QUFBQSxNQUNGLENBQUM7QUFBQSxJQUNIO0FBRUEsV0FBT0EsY0FBYSxFQUFFLE9BQU8sYUFBYSxTQUFTLGtCQUFrQixHQUFHLEdBQUc7QUFBQSxFQUM3RSxTQUFTLE9BQU87QUFDZCxRQUFJLGlCQUFpQixXQUFXO0FBQzlCLGFBQU9BLGNBQWEsRUFBRSxPQUFPLE1BQU0sTUFBTSxTQUFTLE1BQU0sUUFBUSxHQUFHLE1BQU0sTUFBTTtBQUFBLElBQ2pGO0FBQ0EsVUFBTSxlQUFlO0FBQ3JCLFVBQU0sVUFBVSxhQUFhLFdBQVc7QUFDeEMsV0FBT0EsY0FBYSxFQUFFLE9BQU8seUJBQXlCLFFBQVEsR0FBRyxHQUFHO0FBQUEsRUFDdEU7QUFDRjs7O0FDL1ZBLElBQU8sZ0JBQVE7QUFBQSxFQUNiLE1BQU0sTUFBTSxTQUFrQixLQUE2QjtBQUN6RCxXQUFPLGNBQWMsU0FBUyxHQUFHO0FBQUEsRUFDbkM7QUFDRjsiLAogICJuYW1lcyI6IFsiYmFzZVVybCIsICJzYW5pdGl6ZVNlZ21lbnQiLCAiYmFzZVVybCIsICJ2ZXJzaW9uZWRCb2R5IiwgImpzb25SZXNwb25zZSIsICJSMkpzb25CbG9iU3RvcmUiXQp9Cg==

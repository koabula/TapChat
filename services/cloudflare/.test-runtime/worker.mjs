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
        (session) => ({
          send(payload) {
            session.send(payload);
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
        const session = new ManagedSession(server);
        this.sessions.set(sessionId, session);
        queueMicrotask(() => {
          session.markReady();
        });
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
var ManagedSession = class {
  socket;
  ready = false;
  queuedPayloads = [];
  constructor(socket) {
    this.socket = socket;
  }
  send(payload) {
    if (!this.ready) {
      this.queuedPayloads.push(payload);
      return;
    }
    this.dispatch(payload);
  }
  markReady() {
    if (this.ready) {
      return;
    }
    this.ready = true;
    while (this.queuedPayloads.length > 0) {
      const payload = this.queuedPayloads.shift();
      if (payload === void 0) {
        break;
      }
      this.dispatch(payload);
    }
  }
  dispatch(payload) {
    setTimeout(() => {
      this.socket.send(payload);
    }, 0);
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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsiLi4vc3JjL3R5cGVzL2NvbnRyYWN0cy50cyIsICIuLi9zcmMvc3RvcmFnZS9zaGFyaW5nLnRzIiwgIi4uL3NyYy9hdXRoL2NhcGFiaWxpdHkudHMiLCAiLi4vc3JjL2luYm94L3NlcnZpY2UudHMiLCAiLi4vc3JjL2luYm94L2R1cmFibGUudHMiLCAiLi4vc3JjL3N0b3JhZ2Uvc2hhcmVkLXN0YXRlLnRzIiwgIi4uL3NyYy9zdG9yYWdlL3NlcnZpY2UudHMiLCAiLi4vc3JjL3JvdXRlcy9odHRwLnRzIiwgIi4uL3NyYy9pbmRleC50cyJdLAogICJzb3VyY2VzQ29udGVudCI6IFsiZXhwb3J0IGNvbnN0IENVUlJFTlRfTU9ERUxfVkVSU0lPTiA9IFwiMC4xXCI7XG5cbmV4cG9ydCBpbnRlcmZhY2UgU2VuZGVyUHJvb2Yge1xuICB0eXBlOiBzdHJpbmc7XG4gIHZhbHVlOiBzdHJpbmc7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgU3RvcmFnZVJlZiB7XG4gIGtpbmQ6IHN0cmluZztcbiAgcmVmOiBzdHJpbmc7XG4gIHNpemVCeXRlczogbnVtYmVyO1xuICBtaW1lVHlwZTogc3RyaW5nO1xuICBleHBpcmVzQXQ/OiBudW1iZXI7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgV2FrZUhpbnQge1xuICBsYXRlc3RTZXFIaW50PzogbnVtYmVyO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIENhcGFiaWxpdHlDb25zdHJhaW50cyB7XG4gIG1heEJ5dGVzPzogbnVtYmVyO1xuICBtYXhPcHNQZXJNaW51dGU/OiBudW1iZXI7XG59XG5cbmV4cG9ydCB0eXBlIE1lc3NhZ2VUeXBlID1cbiAgfCBcIm1sc19hcHBsaWNhdGlvblwiXG4gIHwgXCJtbHNfY29tbWl0XCJcbiAgfCBcIm1sc193ZWxjb21lXCJcbiAgfCBcImNvbnRyb2xfZGV2aWNlX21lbWJlcnNoaXBfY2hhbmdlZFwiXG4gIHwgXCJjb250cm9sX2lkZW50aXR5X3N0YXRlX3VwZGF0ZWRcIlxuICB8IFwiY29udHJvbF9jb252ZXJzYXRpb25fbmVlZHNfcmVidWlsZFwiO1xuXG5leHBvcnQgaW50ZXJmYWNlIEVudmVsb3BlIHtcbiAgdmVyc2lvbjogc3RyaW5nO1xuICBtZXNzYWdlSWQ6IHN0cmluZztcbiAgY29udmVyc2F0aW9uSWQ6IHN0cmluZztcbiAgc2VuZGVyVXNlcklkOiBzdHJpbmc7XG4gIHNlbmRlckRldmljZUlkOiBzdHJpbmc7XG4gIHJlY2lwaWVudERldmljZUlkOiBzdHJpbmc7XG4gIGNyZWF0ZWRBdDogbnVtYmVyO1xuICBtZXNzYWdlVHlwZTogTWVzc2FnZVR5cGU7XG4gIGlubGluZUNpcGhlcnRleHQ/OiBzdHJpbmc7XG4gIHN0b3JhZ2VSZWZzPzogU3RvcmFnZVJlZltdO1xuICBkZWxpdmVyeUNsYXNzOiBcIm5vcm1hbFwiO1xuICB3YWtlSGludD86IFdha2VIaW50O1xuICBzZW5kZXJQcm9vZjogU2VuZGVyUHJvb2Y7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgSW5ib3hSZWNvcmQge1xuICBzZXE6IG51bWJlcjtcbiAgcmVjaXBpZW50RGV2aWNlSWQ6IHN0cmluZztcbiAgbWVzc2FnZUlkOiBzdHJpbmc7XG4gIHJlY2VpdmVkQXQ6IG51bWJlcjtcbiAgZXhwaXJlc0F0PzogbnVtYmVyO1xuICBzdGF0ZTogXCJhdmFpbGFibGVcIjtcbiAgZW52ZWxvcGU6IEVudmVsb3BlO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEFjayB7XG4gIGRldmljZUlkOiBzdHJpbmc7XG4gIGFja1NlcTogbnVtYmVyO1xuICBhY2tlZE1lc3NhZ2VJZHM/OiBzdHJpbmdbXTtcbiAgYWNrZWRBdDogbnVtYmVyO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEFwcGVuZEVudmVsb3BlUmVxdWVzdCB7XG4gIHZlcnNpb246IHN0cmluZztcbiAgcmVjaXBpZW50RGV2aWNlSWQ6IHN0cmluZztcbiAgZW52ZWxvcGU6IEVudmVsb3BlO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEFwcGVuZEVudmVsb3BlUmVzdWx0IHtcbiAgYWNjZXB0ZWQ6IGJvb2xlYW47XG4gIHNlcTogbnVtYmVyO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEZldGNoTWVzc2FnZXNSZXF1ZXN0IHtcbiAgZGV2aWNlSWQ6IHN0cmluZztcbiAgZnJvbVNlcTogbnVtYmVyO1xuICBsaW1pdDogbnVtYmVyO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEZldGNoTWVzc2FnZXNSZXN1bHQge1xuICB0b1NlcTogbnVtYmVyO1xuICByZWNvcmRzOiBJbmJveFJlY29yZFtdO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEFja1JlcXVlc3Qge1xuICBhY2s6IEFjaztcbn1cblxuZXhwb3J0IGludGVyZmFjZSBBY2tSZXN1bHQge1xuICBhY2NlcHRlZDogYm9vbGVhbjtcbiAgYWNrU2VxOiBudW1iZXI7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgR2V0SGVhZFJlc3VsdCB7XG4gIGhlYWRTZXE6IG51bWJlcjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBQcmVwYXJlQmxvYlVwbG9hZFJlcXVlc3Qge1xuICB0YXNrSWQ6IHN0cmluZztcbiAgY29udmVyc2F0aW9uSWQ6IHN0cmluZztcbiAgbWVzc2FnZUlkOiBzdHJpbmc7XG4gIG1pbWVUeXBlOiBzdHJpbmc7XG4gIHNpemVCeXRlczogbnVtYmVyO1xuICBmaWxlTmFtZT86IHN0cmluZztcbn1cblxuZXhwb3J0IGludGVyZmFjZSBQcmVwYXJlQmxvYlVwbG9hZFJlc3VsdCB7XG4gIGJsb2JSZWY6IHN0cmluZztcbiAgdXBsb2FkVGFyZ2V0OiBzdHJpbmc7XG4gIHVwbG9hZEhlYWRlcnM6IFJlY29yZDxzdHJpbmcsIHN0cmluZz47XG4gIGRvd25sb2FkVGFyZ2V0Pzogc3RyaW5nO1xuICBleHBpcmVzQXQ/OiBudW1iZXI7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgU3RvcmFnZUJhc2VJbmZvIHtcbiAgYmFzZVVybD86IHN0cmluZztcbiAgYnVja2V0SGludD86IHN0cmluZztcbn1cblxuZXhwb3J0IGludGVyZmFjZSBEZXZpY2VSdW50aW1lQXV0aCB7XG4gIHNjaGVtZTogXCJiZWFyZXJcIjtcbiAgdG9rZW46IHN0cmluZztcbiAgZXhwaXJlc0F0OiBudW1iZXI7XG4gIHVzZXJJZDogc3RyaW5nO1xuICBkZXZpY2VJZDogc3RyaW5nO1xuICBzY29wZXM6IERldmljZVJ1bnRpbWVTY29wZVtdO1xufVxuXG5leHBvcnQgdHlwZSBEZXZpY2VSdW50aW1lU2NvcGUgPVxuICB8IFwiaW5ib3hfcmVhZFwiXG4gIHwgXCJpbmJveF9hY2tcIlxuICB8IFwiaW5ib3hfc3Vic2NyaWJlXCJcbiAgfCBcInN0b3JhZ2VfcHJlcGFyZV91cGxvYWRcIlxuICB8IFwic2hhcmVkX3N0YXRlX3dyaXRlXCJcbiAgfCBcImtleXBhY2thZ2Vfd3JpdGVcIjtcblxuZXhwb3J0IGludGVyZmFjZSBSdW50aW1lQ29uZmlnIHtcbiAgc3VwcG9ydGVkUmVhbHRpbWVLaW5kczogQXJyYXk8XCJ3ZWJzb2NrZXRcIiB8IFwic2VydmVyX3NlbnRfZXZlbnRzXCIgfCBcInBvbGxpbmdcIj47XG4gIGlkZW50aXR5QnVuZGxlUmVmPzogc3RyaW5nO1xuICBkZXZpY2VTdGF0dXNSZWY/OiBzdHJpbmc7XG4gIGtleXBhY2thZ2VSZWZCYXNlPzogc3RyaW5nO1xuICBtYXhJbmxpbmVCeXRlcz86IG51bWJlcjtcbiAgZmVhdHVyZXM6IHN0cmluZ1tdO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIERlcGxveW1lbnRCdW5kbGUge1xuICB2ZXJzaW9uOiBzdHJpbmc7XG4gIHJlZ2lvbjogc3RyaW5nO1xuICBpbmJveEh0dHBFbmRwb2ludDogc3RyaW5nO1xuICBpbmJveFdlYnNvY2tldEVuZHBvaW50OiBzdHJpbmc7XG4gIHN0b3JhZ2VCYXNlSW5mbzogU3RvcmFnZUJhc2VJbmZvO1xuICBydW50aW1lQ29uZmlnOiBSdW50aW1lQ29uZmlnO1xuICBkZXZpY2VSdW50aW1lQXV0aD86IERldmljZVJ1bnRpbWVBdXRoO1xuICBleHBlY3RlZFVzZXJJZD86IHN0cmluZztcbiAgZXhwZWN0ZWREZXZpY2VJZD86IHN0cmluZztcbn1cblxuZXhwb3J0IGludGVyZmFjZSBJbmJveEFwcGVuZENhcGFiaWxpdHkge1xuICB2ZXJzaW9uOiBzdHJpbmc7XG4gIHNlcnZpY2U6IFwiaW5ib3hcIjtcbiAgdXNlcklkOiBzdHJpbmc7XG4gIHRhcmdldERldmljZUlkOiBzdHJpbmc7XG4gIGVuZHBvaW50OiBzdHJpbmc7XG4gIG9wZXJhdGlvbnM6IHN0cmluZ1tdO1xuICBjb252ZXJzYXRpb25TY29wZT86IHN0cmluZ1tdO1xuICBleHBpcmVzQXQ6IG51bWJlcjtcbiAgY29uc3RyYWludHM/OiBDYXBhYmlsaXR5Q29uc3RyYWludHM7XG4gIHNpZ25hdHVyZTogc3RyaW5nO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIERldmljZUJpbmRpbmcge1xuICB2ZXJzaW9uOiBzdHJpbmc7XG4gIHVzZXJJZDogc3RyaW5nO1xuICBkZXZpY2VJZDogc3RyaW5nO1xuICBkZXZpY2VQdWJsaWNLZXk6IHN0cmluZztcbiAgY3JlYXRlZEF0OiBudW1iZXI7XG4gIHNpZ25hdHVyZTogc3RyaW5nO1xufVxuXG5leHBvcnQgdHlwZSBEZXZpY2VTdGF0dXNLaW5kID0gXCJhY3RpdmVcIiB8IFwicmV2b2tlZFwiO1xuXG5leHBvcnQgaW50ZXJmYWNlIEtleVBhY2thZ2VSZWYge1xuICB2ZXJzaW9uOiBzdHJpbmc7XG4gIHVzZXJJZDogc3RyaW5nO1xuICBkZXZpY2VJZDogc3RyaW5nO1xuICByZWY6IHN0cmluZztcbiAgZXhwaXJlc0F0OiBudW1iZXI7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgRGV2aWNlQ29udGFjdFByb2ZpbGUge1xuICB2ZXJzaW9uOiBzdHJpbmc7XG4gIGRldmljZUlkOiBzdHJpbmc7XG4gIGRldmljZVB1YmxpY0tleTogc3RyaW5nO1xuICBiaW5kaW5nOiBEZXZpY2VCaW5kaW5nO1xuICBzdGF0dXM6IERldmljZVN0YXR1c0tpbmQ7XG4gIGluYm94QXBwZW5kQ2FwYWJpbGl0eTogSW5ib3hBcHBlbmRDYXBhYmlsaXR5O1xuICBrZXlwYWNrYWdlUmVmOiBLZXlQYWNrYWdlUmVmO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIFN0b3JhZ2VQcm9maWxlIHtcbiAgYmFzZVVybD86IHN0cmluZztcbiAgcHJvZmlsZVJlZj86IHN0cmluZztcbn1cblxuZXhwb3J0IGludGVyZmFjZSBJZGVudGl0eUJ1bmRsZSB7XG4gIHZlcnNpb246IHN0cmluZztcbiAgdXNlcklkOiBzdHJpbmc7XG4gIHVzZXJQdWJsaWNLZXk6IHN0cmluZztcbiAgZGV2aWNlczogRGV2aWNlQ29udGFjdFByb2ZpbGVbXTtcbiAgaWRlbnRpdHlCdW5kbGVSZWY/OiBzdHJpbmc7XG4gIGRldmljZVN0YXR1c1JlZj86IHN0cmluZztcbiAgc3RvcmFnZVByb2ZpbGU/OiBTdG9yYWdlUHJvZmlsZTtcbiAgdXBkYXRlZEF0OiBudW1iZXI7XG4gIHNpZ25hdHVyZTogc3RyaW5nO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIERldmljZVN0YXR1c1JlY29yZCB7XG4gIHZlcnNpb246IHN0cmluZztcbiAgdXNlcklkOiBzdHJpbmc7XG4gIGRldmljZUlkOiBzdHJpbmc7XG4gIHN0YXR1czogRGV2aWNlU3RhdHVzS2luZDtcbiAgdXBkYXRlZEF0OiBudW1iZXI7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgRGV2aWNlTGlzdEVudHJ5IHtcbiAgZGV2aWNlSWQ6IHN0cmluZztcbiAgc3RhdHVzOiBEZXZpY2VTdGF0dXNLaW5kO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIERldmljZUxpc3REb2N1bWVudCB7XG4gIHZlcnNpb246IHN0cmluZztcbiAgdXNlcklkOiBzdHJpbmc7XG4gIHVwZGF0ZWRBdDogbnVtYmVyO1xuICBkZXZpY2VzOiBEZXZpY2VMaXN0RW50cnlbXTtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBEZXZpY2VTdGF0dXNEb2N1bWVudCB7XG4gIHZlcnNpb246IHN0cmluZztcbiAgdXNlcklkOiBzdHJpbmc7XG4gIHVwZGF0ZWRBdDogbnVtYmVyO1xuICBkZXZpY2VzOiBEZXZpY2VTdGF0dXNSZWNvcmRbXTtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBLZXlQYWNrYWdlUmVmRW50cnkge1xuICBrZXlQYWNrYWdlSWQ6IHN0cmluZztcbiAgcmVmOiBzdHJpbmc7XG4gIGV4cGlyZXNBdDogbnVtYmVyO1xuICBjcmVhdGVkQXQ6IG51bWJlcjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBLZXlQYWNrYWdlUmVmc0RvY3VtZW50IHtcbiAgdmVyc2lvbjogc3RyaW5nO1xuICB1c2VySWQ6IHN0cmluZztcbiAgZGV2aWNlSWQ6IHN0cmluZztcbiAgdXBkYXRlZEF0OiBudW1iZXI7XG4gIHJlZnM6IEtleVBhY2thZ2VSZWZFbnRyeVtdO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIFNoYXJlZFN0YXRlV3JpdGVUb2tlbiB7XG4gIHZlcnNpb246IHN0cmluZztcbiAgc2VydmljZTogXCJzaGFyZWRfc3RhdGVcIjtcbiAgdXNlcklkOiBzdHJpbmc7XG4gIG9iamVjdEtpbmRzOiBBcnJheTxcImlkZW50aXR5X2J1bmRsZVwiIHwgXCJkZXZpY2Vfc3RhdHVzXCI+O1xuICBleHBpcmVzQXQ6IG51bWJlcjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBLZXlQYWNrYWdlV3JpdGVUb2tlbiB7XG4gIHZlcnNpb246IHN0cmluZztcbiAgc2VydmljZTogXCJrZXlwYWNrYWdlc1wiO1xuICB1c2VySWQ6IHN0cmluZztcbiAgZGV2aWNlSWQ6IHN0cmluZztcbiAga2V5UGFja2FnZUlkPzogc3RyaW5nO1xuICBleHBpcmVzQXQ6IG51bWJlcjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBCb290c3RyYXBEZXZpY2VSZXF1ZXN0IHtcbiAgdmVyc2lvbjogc3RyaW5nO1xuICB1c2VySWQ6IHN0cmluZztcbiAgZGV2aWNlSWQ6IHN0cmluZztcbn1cblxuZXhwb3J0IGludGVyZmFjZSBCb290c3RyYXBUb2tlbiB7XG4gIHZlcnNpb246IHN0cmluZztcbiAgc2VydmljZTogXCJib290c3RyYXBcIjtcbiAgdXNlcklkOiBzdHJpbmc7XG4gIGRldmljZUlkOiBzdHJpbmc7XG4gIG9wZXJhdGlvbnM6IEFycmF5PFwiaXNzdWVfZGV2aWNlX2J1bmRsZVwiPjtcbiAgZXhwaXJlc0F0OiBudW1iZXI7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgRGV2aWNlUnVudGltZVRva2VuIHtcbiAgdmVyc2lvbjogc3RyaW5nO1xuICBzZXJ2aWNlOiBcImRldmljZV9ydW50aW1lXCI7XG4gIHVzZXJJZDogc3RyaW5nO1xuICBkZXZpY2VJZDogc3RyaW5nO1xuICBzY29wZXM6IERldmljZVJ1bnRpbWVTY29wZVtdO1xuICBleHBpcmVzQXQ6IG51bWJlcjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBSZWFsdGltZUV2ZW50IHtcbiAgZXZlbnQ6IFwiaGVhZF91cGRhdGVkXCIgfCBcImluYm94X3JlY29yZF9hdmFpbGFibGVcIjtcbiAgZGV2aWNlSWQ6IHN0cmluZztcbiAgc2VxOiBudW1iZXI7XG4gIHJlY29yZD86IEluYm94UmVjb3JkO1xufVxyXG4iLCAiY29uc3QgZW5jb2RlciA9IG5ldyBUZXh0RW5jb2RlcigpO1xuXG5mdW5jdGlvbiB0b0Jhc2U2NFVybChieXRlczogVWludDhBcnJheSk6IHN0cmluZyB7XG4gIGxldCBiaW5hcnkgPSBcIlwiO1xuICBmb3IgKGNvbnN0IGJ5dGUgb2YgYnl0ZXMpIHtcbiAgICBiaW5hcnkgKz0gU3RyaW5nLmZyb21DaGFyQ29kZShieXRlKTtcbiAgfVxuICByZXR1cm4gYnRvYShiaW5hcnkpLnJlcGxhY2UoL1xcKy9nLCBcIi1cIikucmVwbGFjZSgvXFwvL2csIFwiX1wiKS5yZXBsYWNlKC89KyQvZywgXCJcIik7XG59XG5cbmZ1bmN0aW9uIGZyb21CYXNlNjRVcmwodmFsdWU6IHN0cmluZyk6IFVpbnQ4QXJyYXkge1xuICBjb25zdCBub3JtYWxpemVkID0gdmFsdWUucmVwbGFjZSgvLS9nLCBcIitcIikucmVwbGFjZSgvXy9nLCBcIi9cIik7XG4gIGNvbnN0IHBhZGRlZCA9IG5vcm1hbGl6ZWQgKyBcIj1cIi5yZXBlYXQoKDQgLSAobm9ybWFsaXplZC5sZW5ndGggJSA0KSkgJSA0KTtcbiAgY29uc3QgYmluYXJ5ID0gYXRvYihwYWRkZWQpO1xuICBjb25zdCBvdXRwdXQgPSBuZXcgVWludDhBcnJheShiaW5hcnkubGVuZ3RoKTtcbiAgZm9yIChsZXQgaSA9IDA7IGkgPCBiaW5hcnkubGVuZ3RoOyBpICs9IDEpIHtcbiAgICBvdXRwdXRbaV0gPSBiaW5hcnkuY2hhckNvZGVBdChpKTtcbiAgfVxuICByZXR1cm4gb3V0cHV0O1xufVxuXG5hc3luYyBmdW5jdGlvbiBpbXBvcnRTZWNyZXQoc2VjcmV0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT4ge1xuICByZXR1cm4gY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoXG4gICAgXCJyYXdcIixcbiAgICBlbmNvZGVyLmVuY29kZShzZWNyZXQpLFxuICAgIHsgbmFtZTogXCJITUFDXCIsIGhhc2g6IFwiU0hBLTI1NlwiIH0sXG4gICAgZmFsc2UsXG4gICAgW1wic2lnblwiLCBcInZlcmlmeVwiXVxuICApO1xufVxuXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gc2lnblNoYXJpbmdQYXlsb2FkKHNlY3JldDogc3RyaW5nLCBwYXlsb2FkOiBSZWNvcmQ8c3RyaW5nLCB1bmtub3duPik6IFByb21pc2U8c3RyaW5nPiB7XG4gIGNvbnN0IGVuY29kZWRQYXlsb2FkID0gZW5jb2Rlci5lbmNvZGUoSlNPTi5zdHJpbmdpZnkocGF5bG9hZCkpO1xuICBjb25zdCBrZXkgPSBhd2FpdCBpbXBvcnRTZWNyZXQoc2VjcmV0KTtcbiAgY29uc3Qgc2lnbmF0dXJlID0gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5zaWduKFwiSE1BQ1wiLCBrZXksIGVuY29kZWRQYXlsb2FkKSk7XG4gIHJldHVybiBgJHt0b0Jhc2U2NFVybChlbmNvZGVkUGF5bG9hZCl9LiR7dG9CYXNlNjRVcmwoc2lnbmF0dXJlKX1gO1xufVxuXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gdmVyaWZ5U2hhcmluZ1BheWxvYWQ8VD4oc2VjcmV0OiBzdHJpbmcsIHRva2VuOiBzdHJpbmcsIG5vdzogbnVtYmVyKTogUHJvbWlzZTxUPiB7XG4gIGNvbnN0IFtwYXlsb2FkUGFydCwgc2lnbmF0dXJlUGFydF0gPSB0b2tlbi5zcGxpdChcIi5cIik7XG4gIGlmICghcGF5bG9hZFBhcnQgfHwgIXNpZ25hdHVyZVBhcnQpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoXCJpbnZhbGlkIHNoYXJpbmcgdG9rZW5cIik7XG4gIH1cblxuICBjb25zdCBwYXlsb2FkQnl0ZXMgPSBmcm9tQmFzZTY0VXJsKHBheWxvYWRQYXJ0KTtcbiAgY29uc3Qgc2lnbmF0dXJlQnl0ZXMgPSBmcm9tQmFzZTY0VXJsKHNpZ25hdHVyZVBhcnQpO1xuICBjb25zdCBrZXkgPSBhd2FpdCBpbXBvcnRTZWNyZXQoc2VjcmV0KTtcbiAgY29uc3QgcGF5bG9hZEJ1ZmZlciA9IHBheWxvYWRCeXRlcy5idWZmZXIuc2xpY2UoXG4gICAgcGF5bG9hZEJ5dGVzLmJ5dGVPZmZzZXQsXG4gICAgcGF5bG9hZEJ5dGVzLmJ5dGVPZmZzZXQgKyBwYXlsb2FkQnl0ZXMuYnl0ZUxlbmd0aFxuICApIGFzIEFycmF5QnVmZmVyO1xuICBjb25zdCBzaWduYXR1cmVCdWZmZXIgPSBzaWduYXR1cmVCeXRlcy5idWZmZXIuc2xpY2UoXG4gICAgc2lnbmF0dXJlQnl0ZXMuYnl0ZU9mZnNldCxcbiAgICBzaWduYXR1cmVCeXRlcy5ieXRlT2Zmc2V0ICsgc2lnbmF0dXJlQnl0ZXMuYnl0ZUxlbmd0aFxuICApIGFzIEFycmF5QnVmZmVyO1xuICBjb25zdCB2YWxpZCA9IGF3YWl0IGNyeXB0by5zdWJ0bGUudmVyaWZ5KFwiSE1BQ1wiLCBrZXksIHNpZ25hdHVyZUJ1ZmZlciwgcGF5bG9hZEJ1ZmZlcik7XG4gIGlmICghdmFsaWQpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoXCJpbnZhbGlkIHNoYXJpbmcgdG9rZW5cIik7XG4gIH1cblxuICBjb25zdCBwYXlsb2FkID0gSlNPTi5wYXJzZShuZXcgVGV4dERlY29kZXIoKS5kZWNvZGUocGF5bG9hZEJ5dGVzKSkgYXMgVCAmIHsgZXhwaXJlc0F0PzogbnVtYmVyIH07XG4gIGlmIChwYXlsb2FkLmV4cGlyZXNBdCAhPT0gdW5kZWZpbmVkICYmIHBheWxvYWQuZXhwaXJlc0F0IDw9IG5vdykge1xuICAgIHRocm93IG5ldyBFcnJvcihcInNoYXJpbmcgdG9rZW4gZXhwaXJlZFwiKTtcbiAgfVxuICByZXR1cm4gcGF5bG9hZDtcbn1cclxuIiwgImltcG9ydCB0eXBlIHtcbiAgQXBwZW5kRW52ZWxvcGVSZXF1ZXN0LFxuICBCb290c3RyYXBUb2tlbixcbiAgRGV2aWNlUnVudGltZVNjb3BlLFxuICBEZXZpY2VSdW50aW1lVG9rZW4sXG4gIEluYm94QXBwZW5kQ2FwYWJpbGl0eSxcbiAgS2V5UGFja2FnZVdyaXRlVG9rZW4sXG4gIFNoYXJlZFN0YXRlV3JpdGVUb2tlblxufSBmcm9tIFwiLi4vdHlwZXMvY29udHJhY3RzXCI7XG5pbXBvcnQgeyBDVVJSRU5UX01PREVMX1ZFUlNJT04gfSBmcm9tIFwiLi4vdHlwZXMvY29udHJhY3RzXCI7XG5pbXBvcnQgeyB2ZXJpZnlTaGFyaW5nUGF5bG9hZCB9IGZyb20gXCIuLi9zdG9yYWdlL3NoYXJpbmdcIjtcblxuZXhwb3J0IGNsYXNzIEh0dHBFcnJvciBleHRlbmRzIEVycm9yIHtcbiAgcmVhZG9ubHkgc3RhdHVzOiBudW1iZXI7XG4gIHJlYWRvbmx5IGNvZGU6IHN0cmluZztcblxuICBjb25zdHJ1Y3RvcihzdGF0dXM6IG51bWJlciwgY29kZTogc3RyaW5nLCBtZXNzYWdlOiBzdHJpbmcpIHtcbiAgICBzdXBlcihtZXNzYWdlKTtcbiAgICB0aGlzLnN0YXR1cyA9IHN0YXR1cztcbiAgICB0aGlzLmNvZGUgPSBjb2RlO1xuICB9XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBnZXRCZWFyZXJUb2tlbihyZXF1ZXN0OiBSZXF1ZXN0KTogc3RyaW5nIHtcbiAgY29uc3QgaGVhZGVyID0gcmVxdWVzdC5oZWFkZXJzLmdldChcIkF1dGhvcml6YXRpb25cIik/LnRyaW0oKTtcbiAgaWYgKCFoZWFkZXIpIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMSwgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJtaXNzaW5nIEF1dGhvcml6YXRpb24gaGVhZGVyXCIpO1xuICB9XG4gIGlmICghaGVhZGVyLnN0YXJ0c1dpdGgoXCJCZWFyZXIgXCIpKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDEsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwiQXV0aG9yaXphdGlvbiBoZWFkZXIgbXVzdCB1c2UgQmVhcmVyIHRva2VuXCIpO1xuICB9XG4gIGNvbnN0IHRva2VuID0gaGVhZGVyLnNsaWNlKFwiQmVhcmVyIFwiLmxlbmd0aCkudHJpbSgpO1xuICBpZiAoIXRva2VuKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDEsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwiQmVhcmVyIHRva2VuIG11c3Qgbm90IGJlIGVtcHR5XCIpO1xuICB9XG4gIHJldHVybiB0b2tlbjtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIHZhbGlkYXRlQXBwZW5kQXV0aG9yaXphdGlvbihcbiAgcmVxdWVzdDogUmVxdWVzdCxcbiAgZGV2aWNlSWQ6IHN0cmluZyxcbiAgYm9keTogQXBwZW5kRW52ZWxvcGVSZXF1ZXN0LFxuICBub3c6IG51bWJlclxuKTogdm9pZCB7XG4gIGNvbnN0IHNpZ25hdHVyZSA9IGdldEJlYXJlclRva2VuKHJlcXVlc3QpO1xuICBjb25zdCBjYXBhYmlsaXR5SGVhZGVyID0gcmVxdWVzdC5oZWFkZXJzLmdldChcIlgtVGFwY2hhdC1DYXBhYmlsaXR5XCIpO1xuICBpZiAoIWNhcGFiaWxpdHlIZWFkZXIpIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMSwgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJtaXNzaW5nIFgtVGFwY2hhdC1DYXBhYmlsaXR5IGhlYWRlclwiKTtcbiAgfVxuXG4gIGxldCBjYXBhYmlsaXR5OiBJbmJveEFwcGVuZENhcGFiaWxpdHk7XG4gIHRyeSB7XG4gICAgY2FwYWJpbGl0eSA9IEpTT04ucGFyc2UoY2FwYWJpbGl0eUhlYWRlcikgYXMgSW5ib3hBcHBlbmRDYXBhYmlsaXR5O1xuICB9IGNhdGNoIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMCwgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJYLVRhcGNoYXQtQ2FwYWJpbGl0eSBpcyBub3QgdmFsaWQgSlNPTlwiKTtcbiAgfVxuXG4gIGlmIChib2R5LnZlcnNpb24gIT09IENVUlJFTlRfTU9ERUxfVkVSU0lPTiB8fCBjYXBhYmlsaXR5LnZlcnNpb24gIT09IENVUlJFTlRfTU9ERUxfVkVSU0lPTikge1xuICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAwLCBcInVuc3VwcG9ydGVkX3ZlcnNpb25cIiwgXCJhcHBlbmQgY2FwYWJpbGl0eSB2ZXJzaW9uIGlzIG5vdCBzdXBwb3J0ZWRcIik7XG4gIH1cbiAgaWYgKGNhcGFiaWxpdHkuc2lnbmF0dXJlICE9PSBzaWduYXR1cmUpIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMywgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJjYXBhYmlsaXR5IHNpZ25hdHVyZSBkb2VzIG5vdCBtYXRjaCBiZWFyZXIgdG9rZW5cIik7XG4gIH1cbiAgaWYgKGNhcGFiaWxpdHkuc2VydmljZSAhPT0gXCJpbmJveFwiKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwiY2FwYWJpbGl0eSBzZXJ2aWNlIG11c3QgYmUgaW5ib3hcIik7XG4gIH1cbiAgaWYgKCFjYXBhYmlsaXR5Lm9wZXJhdGlvbnMuaW5jbHVkZXMoXCJhcHBlbmRcIikpIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMywgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJjYXBhYmlsaXR5IGRvZXMgbm90IGdyYW50IGFwcGVuZFwiKTtcbiAgfVxuICBpZiAoY2FwYWJpbGl0eS50YXJnZXREZXZpY2VJZCAhPT0gZGV2aWNlSWQpIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMywgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJjYXBhYmlsaXR5IHRhcmdldCBkZXZpY2UgZG9lcyBub3QgbWF0Y2ggcmVxdWVzdCBwYXRoXCIpO1xuICB9XG4gIGNvbnN0IHJlcXVlc3RVcmwgPSBuZXcgVVJMKHJlcXVlc3QudXJsKTtcbiAgaWYgKGNhcGFiaWxpdHkuZW5kcG9pbnQgIT09IGAke3JlcXVlc3RVcmwub3JpZ2lufSR7cmVxdWVzdFVybC5wYXRobmFtZX1gKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwiY2FwYWJpbGl0eSBlbmRwb2ludCBkb2VzIG5vdCBtYXRjaCByZXF1ZXN0IHBhdGhcIik7XG4gIH1cbiAgaWYgKGNhcGFiaWxpdHkuZXhwaXJlc0F0IDw9IG5vdykge1xuICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAzLCBcImNhcGFiaWxpdHlfZXhwaXJlZFwiLCBcImFwcGVuZCBjYXBhYmlsaXR5IGlzIGV4cGlyZWRcIik7XG4gIH1cbiAgaWYgKGJvZHkucmVjaXBpZW50RGV2aWNlSWQgIT09IGRldmljZUlkIHx8IGJvZHkuZW52ZWxvcGUucmVjaXBpZW50RGV2aWNlSWQgIT09IGRldmljZUlkKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwicmVjaXBpZW50IGRldmljZSBkb2VzIG5vdCBtYXRjaCB0YXJnZXQgaW5ib3hcIik7XG4gIH1cbiAgaWYgKGNhcGFiaWxpdHkuY29udmVyc2F0aW9uU2NvcGU/Lmxlbmd0aCAmJiAhY2FwYWJpbGl0eS5jb252ZXJzYXRpb25TY29wZS5pbmNsdWRlcyhib2R5LmVudmVsb3BlLmNvbnZlcnNhdGlvbklkKSkge1xuICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAzLCBcImludmFsaWRfY2FwYWJpbGl0eVwiLCBcImNvbnZlcnNhdGlvbiBpcyBvdXRzaWRlIGNhcGFiaWxpdHkgc2NvcGVcIik7XG4gIH1cbiAgY29uc3Qgc2l6ZSA9IG5ldyBUZXh0RW5jb2RlcigpLmVuY29kZShKU09OLnN0cmluZ2lmeShib2R5LmVudmVsb3BlKSkuYnl0ZUxlbmd0aDtcbiAgaWYgKGNhcGFiaWxpdHkuY29uc3RyYWludHM/Lm1heEJ5dGVzICE9PSB1bmRlZmluZWQgJiYgc2l6ZSA+IGNhcGFiaWxpdHkuY29uc3RyYWludHMubWF4Qnl0ZXMpIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQxMywgXCJwYXlsb2FkX3Rvb19sYXJnZVwiLCBcImVudmVsb3BlIGV4Y2VlZHMgY2FwYWJpbGl0eSBzaXplIGxpbWl0XCIpO1xuICB9XG59XG5cbmFzeW5jIGZ1bmN0aW9uIHZlcmlmeVNpZ25lZFRva2VuPFQ+KHNlY3JldDogc3RyaW5nLCByZXF1ZXN0OiBSZXF1ZXN0LCBub3c6IG51bWJlcik6IFByb21pc2U8VD4ge1xuICBjb25zdCB0b2tlbiA9IGdldEJlYXJlclRva2VuKHJlcXVlc3QpO1xuICB0cnkge1xuICAgIHJldHVybiBhd2FpdCB2ZXJpZnlTaGFyaW5nUGF5bG9hZDxUPihzZWNyZXQsIHRva2VuLCBub3cpO1xuICB9IGNhdGNoIChlcnJvcikge1xuICAgIGNvbnN0IG1lc3NhZ2UgPSBlcnJvciBpbnN0YW5jZW9mIEVycm9yID8gZXJyb3IubWVzc2FnZSA6IFwiaW52YWxpZCBzaWduZWQgdG9rZW5cIjtcbiAgICBpZiAobWVzc2FnZS5pbmNsdWRlcyhcImV4cGlyZWRcIikpIHtcbiAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAzLCBcImNhcGFiaWxpdHlfZXhwaXJlZFwiLCBtZXNzYWdlKTtcbiAgICB9XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIG1lc3NhZ2UpO1xuICB9XG59XG5cbmFzeW5jIGZ1bmN0aW9uIHZlcmlmeURldmljZVJ1bnRpbWVUb2tlbihyZXF1ZXN0OiBSZXF1ZXN0LCBzZWNyZXQ6IHN0cmluZywgbm93OiBudW1iZXIpOiBQcm9taXNlPERldmljZVJ1bnRpbWVUb2tlbj4ge1xuICBjb25zdCB0b2tlbiA9IGF3YWl0IHZlcmlmeVNpZ25lZFRva2VuPERldmljZVJ1bnRpbWVUb2tlbj4oc2VjcmV0LCByZXF1ZXN0LCBub3cpO1xuICBpZiAodG9rZW4udmVyc2lvbiAhPT0gQ1VSUkVOVF9NT0RFTF9WRVJTSU9OKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDAsIFwidW5zdXBwb3J0ZWRfdmVyc2lvblwiLCBcImRldmljZSBydW50aW1lIHRva2VuIHZlcnNpb24gaXMgbm90IHN1cHBvcnRlZFwiKTtcbiAgfVxuICBpZiAodG9rZW4uc2VydmljZSAhPT0gXCJkZXZpY2VfcnVudGltZVwiKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwidG9rZW4gc2VydmljZSBtdXN0IGJlIGRldmljZV9ydW50aW1lXCIpO1xuICB9XG4gIGlmICghdG9rZW4udXNlcklkIHx8ICF0b2tlbi5kZXZpY2VJZCB8fCAhdG9rZW4uc2NvcGVzLmxlbmd0aCkge1xuICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAzLCBcImludmFsaWRfY2FwYWJpbGl0eVwiLCBcImRldmljZSBydW50aW1lIHRva2VuIGlzIG1hbGZvcm1lZFwiKTtcbiAgfVxuICByZXR1cm4gdG9rZW47XG59XG5cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiB2YWxpZGF0ZUJvb3RzdHJhcEF1dGhvcml6YXRpb24oXG4gIHJlcXVlc3Q6IFJlcXVlc3QsXG4gIHNlY3JldDogc3RyaW5nLFxuICB1c2VySWQ6IHN0cmluZyxcbiAgZGV2aWNlSWQ6IHN0cmluZyxcbiAgbm93OiBudW1iZXJcbik6IFByb21pc2U8Qm9vdHN0cmFwVG9rZW4+IHtcbiAgY29uc3QgdG9rZW4gPSBhd2FpdCB2ZXJpZnlTaWduZWRUb2tlbjxCb290c3RyYXBUb2tlbj4oc2VjcmV0LCByZXF1ZXN0LCBub3cpO1xuICBpZiAodG9rZW4udmVyc2lvbiAhPT0gQ1VSUkVOVF9NT0RFTF9WRVJTSU9OKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDAsIFwidW5zdXBwb3J0ZWRfdmVyc2lvblwiLCBcImJvb3RzdHJhcCB0b2tlbiB2ZXJzaW9uIGlzIG5vdCBzdXBwb3J0ZWRcIik7XG4gIH1cbiAgaWYgKHRva2VuLnNlcnZpY2UgIT09IFwiYm9vdHN0cmFwXCIpIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMywgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJ0b2tlbiBzZXJ2aWNlIG11c3QgYmUgYm9vdHN0cmFwXCIpO1xuICB9XG4gIGlmICh0b2tlbi51c2VySWQgIT09IHVzZXJJZCB8fCB0b2tlbi5kZXZpY2VJZCAhPT0gZGV2aWNlSWQpIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMywgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJib290c3RyYXAgdG9rZW4gc2NvcGUgZG9lcyBub3QgbWF0Y2ggcmVxdWVzdFwiKTtcbiAgfVxuICBpZiAoIXRva2VuLm9wZXJhdGlvbnMuaW5jbHVkZXMoXCJpc3N1ZV9kZXZpY2VfYnVuZGxlXCIpKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwiYm9vdHN0cmFwIHRva2VuIGRvZXMgbm90IGdyYW50IGRldmljZSBidW5kbGUgaXNzdWFuY2VcIik7XG4gIH1cbiAgcmV0dXJuIHRva2VuO1xufVxuXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gdmFsaWRhdGVBbnlEZXZpY2VSdW50aW1lQXV0aG9yaXphdGlvbihcbiAgcmVxdWVzdDogUmVxdWVzdCxcbiAgc2VjcmV0OiBzdHJpbmcsXG4gIHNjb3BlOiBEZXZpY2VSdW50aW1lU2NvcGUsXG4gIG5vdzogbnVtYmVyXG4pOiBQcm9taXNlPERldmljZVJ1bnRpbWVUb2tlbj4ge1xuICBjb25zdCB0b2tlbiA9IGF3YWl0IHZlcmlmeURldmljZVJ1bnRpbWVUb2tlbihyZXF1ZXN0LCBzZWNyZXQsIG5vdyk7XG4gIGlmICghdG9rZW4uc2NvcGVzLmluY2x1ZGVzKHNjb3BlKSkge1xuICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAzLCBcImludmFsaWRfY2FwYWJpbGl0eVwiLCBgZGV2aWNlIHJ1bnRpbWUgdG9rZW4gZG9lcyBub3QgZ3JhbnQgJHtzY29wZX1gKTtcbiAgfVxuICByZXR1cm4gdG9rZW47XG59XG5cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiB2YWxpZGF0ZURldmljZVJ1bnRpbWVBdXRob3JpemF0aW9uKFxuICByZXF1ZXN0OiBSZXF1ZXN0LFxuICBzZWNyZXQ6IHN0cmluZyxcbiAgdXNlcklkOiBzdHJpbmcsXG4gIGRldmljZUlkOiBzdHJpbmcsXG4gIHNjb3BlOiBEZXZpY2VSdW50aW1lU2NvcGUsXG4gIG5vdzogbnVtYmVyXG4pOiBQcm9taXNlPERldmljZVJ1bnRpbWVUb2tlbj4ge1xuICBjb25zdCB0b2tlbiA9IGF3YWl0IHZhbGlkYXRlQW55RGV2aWNlUnVudGltZUF1dGhvcml6YXRpb24ocmVxdWVzdCwgc2VjcmV0LCBzY29wZSwgbm93KTtcbiAgaWYgKHRva2VuLnVzZXJJZCAhPT0gdXNlcklkIHx8IHRva2VuLmRldmljZUlkICE9PSBkZXZpY2VJZCkge1xuICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAzLCBcImludmFsaWRfY2FwYWJpbGl0eVwiLCBcImRldmljZSBydW50aW1lIHRva2VuIHNjb3BlIGRvZXMgbm90IG1hdGNoIHJlcXVlc3QgcGF0aFwiKTtcbiAgfVxuICByZXR1cm4gdG9rZW47XG59XG5cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiB2YWxpZGF0ZURldmljZVJ1bnRpbWVBdXRob3JpemF0aW9uRm9yRGV2aWNlKFxuICByZXF1ZXN0OiBSZXF1ZXN0LFxuICBzZWNyZXQ6IHN0cmluZyxcbiAgZGV2aWNlSWQ6IHN0cmluZyxcbiAgc2NvcGU6IERldmljZVJ1bnRpbWVTY29wZSxcbiAgbm93OiBudW1iZXJcbik6IFByb21pc2U8RGV2aWNlUnVudGltZVRva2VuPiB7XG4gIGNvbnN0IHRva2VuID0gYXdhaXQgdmFsaWRhdGVBbnlEZXZpY2VSdW50aW1lQXV0aG9yaXphdGlvbihyZXF1ZXN0LCBzZWNyZXQsIHNjb3BlLCBub3cpO1xuICBpZiAodG9rZW4uZGV2aWNlSWQgIT09IGRldmljZUlkKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwiZGV2aWNlIHJ1bnRpbWUgdG9rZW4gc2NvcGUgZG9lcyBub3QgbWF0Y2ggcmVxdWVzdCBwYXRoXCIpO1xuICB9XG4gIHJldHVybiB0b2tlbjtcbn1cblxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHZhbGlkYXRlU2hhcmVkU3RhdGVXcml0ZUF1dGhvcml6YXRpb24oXG4gIHJlcXVlc3Q6IFJlcXVlc3QsXG4gIHNlY3JldDogc3RyaW5nLFxuICB1c2VySWQ6IHN0cmluZyxcbiAgZGV2aWNlSWQ6IHN0cmluZyxcbiAgb2JqZWN0S2luZDogXCJpZGVudGl0eV9idW5kbGVcIiB8IFwiZGV2aWNlX3N0YXR1c1wiLFxuICBub3c6IG51bWJlclxuKTogUHJvbWlzZTxTaGFyZWRTdGF0ZVdyaXRlVG9rZW4gfCBEZXZpY2VSdW50aW1lVG9rZW4+IHtcbiAgdHJ5IHtcbiAgICByZXR1cm4gYXdhaXQgdmFsaWRhdGVEZXZpY2VSdW50aW1lQXV0aG9yaXphdGlvbihyZXF1ZXN0LCBzZWNyZXQsIHVzZXJJZCwgZGV2aWNlSWQsIFwic2hhcmVkX3N0YXRlX3dyaXRlXCIsIG5vdyk7XG4gIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgaWYgKCEoZXJyb3IgaW5zdGFuY2VvZiBIdHRwRXJyb3IpIHx8IGVycm9yLmNvZGUgPT09IFwiY2FwYWJpbGl0eV9leHBpcmVkXCIpIHtcbiAgICAgIHRocm93IGVycm9yO1xuICAgIH1cbiAgfVxuXG4gIGNvbnN0IHRva2VuID0gYXdhaXQgdmVyaWZ5U2lnbmVkVG9rZW48U2hhcmVkU3RhdGVXcml0ZVRva2VuPihzZWNyZXQsIHJlcXVlc3QsIG5vdyk7XG4gIGlmICh0b2tlbi52ZXJzaW9uICE9PSBDVVJSRU5UX01PREVMX1ZFUlNJT04pIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMCwgXCJ1bnN1cHBvcnRlZF92ZXJzaW9uXCIsIFwic2hhcmVkLXN0YXRlIHRva2VuIHZlcnNpb24gaXMgbm90IHN1cHBvcnRlZFwiKTtcbiAgfVxuICBpZiAodG9rZW4uc2VydmljZSAhPT0gXCJzaGFyZWRfc3RhdGVcIikge1xuICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAzLCBcImludmFsaWRfY2FwYWJpbGl0eVwiLCBcInRva2VuIHNlcnZpY2UgbXVzdCBiZSBzaGFyZWRfc3RhdGVcIik7XG4gIH1cbiAgaWYgKHRva2VuLnVzZXJJZCAhPT0gdXNlcklkKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwidG9rZW4gdXNlcklkIGRvZXMgbm90IG1hdGNoIHJlcXVlc3QgcGF0aFwiKTtcbiAgfVxuICBpZiAoIXRva2VuLm9iamVjdEtpbmRzLmluY2x1ZGVzKG9iamVjdEtpbmQpKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwidG9rZW4gZG9lcyBub3QgZ3JhbnQgdGhpcyBzaGFyZWQtc3RhdGUgb2JqZWN0IGtpbmRcIik7XG4gIH1cbiAgcmV0dXJuIHRva2VuO1xufVxuXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gdmFsaWRhdGVLZXlQYWNrYWdlV3JpdGVBdXRob3JpemF0aW9uKFxuICByZXF1ZXN0OiBSZXF1ZXN0LFxuICBzZWNyZXQ6IHN0cmluZyxcbiAgdXNlcklkOiBzdHJpbmcsXG4gIGRldmljZUlkOiBzdHJpbmcsXG4gIGtleVBhY2thZ2VJZDogc3RyaW5nIHwgdW5kZWZpbmVkLFxuICBub3c6IG51bWJlclxuKTogUHJvbWlzZTxLZXlQYWNrYWdlV3JpdGVUb2tlbiB8IERldmljZVJ1bnRpbWVUb2tlbj4ge1xuICB0cnkge1xuICAgIHJldHVybiBhd2FpdCB2YWxpZGF0ZURldmljZVJ1bnRpbWVBdXRob3JpemF0aW9uKHJlcXVlc3QsIHNlY3JldCwgdXNlcklkLCBkZXZpY2VJZCwgXCJrZXlwYWNrYWdlX3dyaXRlXCIsIG5vdyk7XG4gIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgaWYgKCEoZXJyb3IgaW5zdGFuY2VvZiBIdHRwRXJyb3IpIHx8IGVycm9yLmNvZGUgPT09IFwiY2FwYWJpbGl0eV9leHBpcmVkXCIpIHtcbiAgICAgIHRocm93IGVycm9yO1xuICAgIH1cbiAgfVxuXG4gIGNvbnN0IHRva2VuID0gYXdhaXQgdmVyaWZ5U2lnbmVkVG9rZW48S2V5UGFja2FnZVdyaXRlVG9rZW4+KHNlY3JldCwgcmVxdWVzdCwgbm93KTtcbiAgaWYgKHRva2VuLnZlcnNpb24gIT09IENVUlJFTlRfTU9ERUxfVkVSU0lPTikge1xuICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAwLCBcInVuc3VwcG9ydGVkX3ZlcnNpb25cIiwgXCJrZXlwYWNrYWdlIHRva2VuIHZlcnNpb24gaXMgbm90IHN1cHBvcnRlZFwiKTtcbiAgfVxuICBpZiAodG9rZW4uc2VydmljZSAhPT0gXCJrZXlwYWNrYWdlc1wiKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwidG9rZW4gc2VydmljZSBtdXN0IGJlIGtleXBhY2thZ2VzXCIpO1xuICB9XG4gIGlmICh0b2tlbi51c2VySWQgIT09IHVzZXJJZCB8fCB0b2tlbi5kZXZpY2VJZCAhPT0gZGV2aWNlSWQpIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMywgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJ0b2tlbiBzY29wZSBkb2VzIG5vdCBtYXRjaCByZXF1ZXN0IHBhdGhcIik7XG4gIH1cbiAgaWYgKHRva2VuLmtleVBhY2thZ2VJZCAmJiB0b2tlbi5rZXlQYWNrYWdlSWQgIT09IGtleVBhY2thZ2VJZCkge1xuICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAzLCBcImludmFsaWRfY2FwYWJpbGl0eVwiLCBcInRva2VuIGtleVBhY2thZ2VJZCBkb2VzIG5vdCBtYXRjaCByZXF1ZXN0IHBhdGhcIik7XG4gIH1cbiAgcmV0dXJuIHRva2VuO1xufVxyXG4iLCAiaW1wb3J0IHsgSHR0cEVycm9yIH0gZnJvbSBcIi4uL2F1dGgvY2FwYWJpbGl0eVwiO1xuaW1wb3J0IHR5cGUge1xuICBBY2tSZXF1ZXN0LFxuICBBY2tSZXN1bHQsXG4gIEFwcGVuZEVudmVsb3BlUmVxdWVzdCxcbiAgQXBwZW5kRW52ZWxvcGVSZXN1bHQsXG4gIEZldGNoTWVzc2FnZXNSZXF1ZXN0LFxuICBGZXRjaE1lc3NhZ2VzUmVzdWx0LFxuICBJbmJveFJlY29yZCxcbiAgUmVhbHRpbWVFdmVudFxufSBmcm9tIFwiLi4vdHlwZXMvY29udHJhY3RzXCI7XG5pbXBvcnQgdHlwZSB7IER1cmFibGVPYmplY3RTdG9yYWdlTGlrZSwgSnNvbkJsb2JTdG9yZSwgU2Vzc2lvblNpbmsgfSBmcm9tIFwiLi4vdHlwZXMvcnVudGltZVwiO1xuXG5pbnRlcmZhY2UgSW5ib3hNZXRhIHtcbiAgaGVhZFNlcTogbnVtYmVyO1xuICBhY2tlZFNlcTogbnVtYmVyO1xuICByZXRlbnRpb25EYXlzOiBudW1iZXI7XG4gIG1heElubGluZUJ5dGVzOiBudW1iZXI7XG59XG5cbmludGVyZmFjZSBTdG9yZWRSZWNvcmRJbmRleCB7XG4gIHNlcTogbnVtYmVyO1xuICBtZXNzYWdlSWQ6IHN0cmluZztcbiAgcmVjaXBpZW50RGV2aWNlSWQ6IHN0cmluZztcbiAgcmVjZWl2ZWRBdDogbnVtYmVyO1xuICBleHBpcmVzQXQ/OiBudW1iZXI7XG4gIHN0YXRlOiBcImF2YWlsYWJsZVwiO1xuICBpbmxpbmVSZWNvcmQ/OiBJbmJveFJlY29yZDtcbiAgcGF5bG9hZFJlZj86IHN0cmluZztcbn1cblxuY29uc3QgTUVUQV9LRVkgPSBcIm1ldGFcIjtcbmNvbnN0IElERU1QT1RFTkNZX1BSRUZJWCA9IFwiaWRlbXBvdGVuY3k6XCI7XG5jb25zdCBSRUNPUkRfUFJFRklYID0gXCJyZWNvcmQ6XCI7XG5cbmV4cG9ydCBjbGFzcyBJbmJveFNlcnZpY2Uge1xuICBwcml2YXRlIHJlYWRvbmx5IGRldmljZUlkOiBzdHJpbmc7XG4gIHByaXZhdGUgcmVhZG9ubHkgc3RhdGU6IER1cmFibGVPYmplY3RTdG9yYWdlTGlrZTtcbiAgcHJpdmF0ZSByZWFkb25seSBzcGlsbFN0b3JlOiBKc29uQmxvYlN0b3JlO1xuICBwcml2YXRlIHJlYWRvbmx5IHNlc3Npb25zOiBTZXNzaW9uU2lua1tdO1xuICBwcml2YXRlIHJlYWRvbmx5IGRlZmF1bHRzOiBJbmJveE1ldGE7XG5cbiAgY29uc3RydWN0b3IoXG4gICAgZGV2aWNlSWQ6IHN0cmluZyxcbiAgICBzdGF0ZTogRHVyYWJsZU9iamVjdFN0b3JhZ2VMaWtlLFxuICAgIHNwaWxsU3RvcmU6IEpzb25CbG9iU3RvcmUsXG4gICAgc2Vzc2lvbnM6IFNlc3Npb25TaW5rW10sXG4gICAgZGVmYXVsdHM6IEluYm94TWV0YVxuICApIHtcbiAgICB0aGlzLmRldmljZUlkID0gZGV2aWNlSWQ7XG4gICAgdGhpcy5zdGF0ZSA9IHN0YXRlO1xuICAgIHRoaXMuc3BpbGxTdG9yZSA9IHNwaWxsU3RvcmU7XG4gICAgdGhpcy5zZXNzaW9ucyA9IHNlc3Npb25zO1xuICAgIHRoaXMuZGVmYXVsdHMgPSBkZWZhdWx0cztcbiAgfVxuXG4gIGFzeW5jIGFwcGVuZEVudmVsb3BlKGlucHV0OiBBcHBlbmRFbnZlbG9wZVJlcXVlc3QsIG5vdzogbnVtYmVyKTogUHJvbWlzZTxBcHBlbmRFbnZlbG9wZVJlc3VsdD4ge1xuICAgIHRoaXMudmFsaWRhdGVBcHBlbmRSZXF1ZXN0KGlucHV0KTtcbiAgICBjb25zdCBtZXRhID0gYXdhaXQgdGhpcy5nZXRNZXRhKCk7XG4gICAgY29uc3QgZXhpc3RpbmdTZXEgPSBhd2FpdCB0aGlzLnN0YXRlLmdldDxudW1iZXI+KGAke0lERU1QT1RFTkNZX1BSRUZJWH0ke2lucHV0LmVudmVsb3BlLm1lc3NhZ2VJZH1gKTtcbiAgICBpZiAoZXhpc3RpbmdTZXEgIT09IHVuZGVmaW5lZCkge1xuICAgICAgcmV0dXJuIHsgYWNjZXB0ZWQ6IHRydWUsIHNlcTogZXhpc3RpbmdTZXEgfTtcbiAgICB9XG5cbiAgICBjb25zdCBzZXEgPSBtZXRhLmhlYWRTZXEgKyAxO1xuICAgIGNvbnN0IGV4cGlyZXNBdCA9IG5vdyArIG1ldGEucmV0ZW50aW9uRGF5cyAqIDI0ICogNjAgKiA2MCAqIDEwMDA7XG4gICAgY29uc3QgcmVjb3JkOiBJbmJveFJlY29yZCA9IHtcbiAgICAgIHNlcSxcbiAgICAgIHJlY2lwaWVudERldmljZUlkOiB0aGlzLmRldmljZUlkLFxuICAgICAgbWVzc2FnZUlkOiBpbnB1dC5lbnZlbG9wZS5tZXNzYWdlSWQsXG4gICAgICByZWNlaXZlZEF0OiBub3csXG4gICAgICBleHBpcmVzQXQsXG4gICAgICBzdGF0ZTogXCJhdmFpbGFibGVcIixcbiAgICAgIGVudmVsb3BlOiBpbnB1dC5lbnZlbG9wZVxuICAgIH07XG4gICAgY29uc3Qgc2VyaWFsaXplZCA9IEpTT04uc3RyaW5naWZ5KHJlY29yZCk7XG4gICAgY29uc3Qgc3RvcmFnZUtleSA9IGAke1JFQ09SRF9QUkVGSVh9JHtzZXF9YDtcblxuICAgIGlmIChuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUoc2VyaWFsaXplZCkuYnl0ZUxlbmd0aCA8PSBtZXRhLm1heElubGluZUJ5dGVzICYmIGlucHV0LmVudmVsb3BlLmlubGluZUNpcGhlcnRleHQpIHtcbiAgICAgIGNvbnN0IGlubGluZUluZGV4OiBTdG9yZWRSZWNvcmRJbmRleCA9IHtcbiAgICAgICAgc2VxLFxuICAgICAgICBtZXNzYWdlSWQ6IHJlY29yZC5tZXNzYWdlSWQsXG4gICAgICAgIHJlY2lwaWVudERldmljZUlkOiByZWNvcmQucmVjaXBpZW50RGV2aWNlSWQsXG4gICAgICAgIHJlY2VpdmVkQXQ6IHJlY29yZC5yZWNlaXZlZEF0LFxuICAgICAgICBleHBpcmVzQXQsXG4gICAgICAgIHN0YXRlOiByZWNvcmQuc3RhdGUsXG4gICAgICAgIGlubGluZVJlY29yZDogcmVjb3JkXG4gICAgICB9O1xuICAgICAgYXdhaXQgdGhpcy5zdGF0ZS5wdXQoc3RvcmFnZUtleSwgaW5saW5lSW5kZXgpO1xuICAgIH0gZWxzZSB7XG4gICAgICBjb25zdCBwYXlsb2FkUmVmID0gYGluYm94LXBheWxvYWQvJHt0aGlzLmRldmljZUlkfS8ke3NlcX0uanNvbmA7XG4gICAgICBhd2FpdCB0aGlzLnNwaWxsU3RvcmUucHV0SnNvbihwYXlsb2FkUmVmLCByZWNvcmQpO1xuICAgICAgY29uc3QgaW5kZXhlZDogU3RvcmVkUmVjb3JkSW5kZXggPSB7XG4gICAgICAgIHNlcSxcbiAgICAgICAgbWVzc2FnZUlkOiByZWNvcmQubWVzc2FnZUlkLFxuICAgICAgICByZWNpcGllbnREZXZpY2VJZDogcmVjb3JkLnJlY2lwaWVudERldmljZUlkLFxuICAgICAgICByZWNlaXZlZEF0OiByZWNvcmQucmVjZWl2ZWRBdCxcbiAgICAgICAgZXhwaXJlc0F0LFxuICAgICAgICBzdGF0ZTogcmVjb3JkLnN0YXRlLFxuICAgICAgICBwYXlsb2FkUmVmXG4gICAgICB9O1xuICAgICAgYXdhaXQgdGhpcy5zdGF0ZS5wdXQoc3RvcmFnZUtleSwgaW5kZXhlZCk7XG4gICAgfVxuXG4gICAgYXdhaXQgdGhpcy5zdGF0ZS5wdXQoYCR7SURFTVBPVEVOQ1lfUFJFRklYfSR7cmVjb3JkLm1lc3NhZ2VJZH1gLCBzZXEpO1xuICAgIGF3YWl0IHRoaXMuc3RhdGUucHV0KE1FVEFfS0VZLCB7IC4uLm1ldGEsIGhlYWRTZXE6IHNlcSB9KTtcbiAgICBhd2FpdCB0aGlzLnN0YXRlLnNldEFsYXJtKGV4cGlyZXNBdCk7XG5cbiAgICB0aGlzLnB1Ymxpc2goe1xuICAgICAgZXZlbnQ6IFwiaGVhZF91cGRhdGVkXCIsXG4gICAgICBkZXZpY2VJZDogdGhpcy5kZXZpY2VJZCxcbiAgICAgIHNlcVxuICAgIH0pO1xuICAgIHRoaXMucHVibGlzaCh7XG4gICAgICBldmVudDogXCJpbmJveF9yZWNvcmRfYXZhaWxhYmxlXCIsXG4gICAgICBkZXZpY2VJZDogdGhpcy5kZXZpY2VJZCxcbiAgICAgIHNlcSxcbiAgICAgIHJlY29yZFxuICAgIH0pO1xuXG4gICAgcmV0dXJuIHsgYWNjZXB0ZWQ6IHRydWUsIHNlcSB9O1xuICB9XG5cbiAgYXN5bmMgZmV0Y2hNZXNzYWdlcyhpbnB1dDogRmV0Y2hNZXNzYWdlc1JlcXVlc3QpOiBQcm9taXNlPEZldGNoTWVzc2FnZXNSZXN1bHQ+IHtcbiAgICBpZiAoaW5wdXQuZGV2aWNlSWQgIT09IHRoaXMuZGV2aWNlSWQpIHtcbiAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAwLCBcImludmFsaWRfaW5wdXRcIiwgXCJkZXZpY2VfaWQgZG9lcyBub3QgbWF0Y2ggaW5ib3ggcm91dGVcIik7XG4gICAgfVxuICAgIGlmIChpbnB1dC5saW1pdCA8PSAwKSB7XG4gICAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMCwgXCJpbnZhbGlkX2lucHV0XCIsIFwibGltaXQgbXVzdCBiZSBncmVhdGVyIHRoYW4gemVyb1wiKTtcbiAgICB9XG5cbiAgICBjb25zdCBtZXRhID0gYXdhaXQgdGhpcy5nZXRNZXRhKCk7XG4gICAgY29uc3QgcmVjb3JkczogSW5ib3hSZWNvcmRbXSA9IFtdO1xuICAgIGNvbnN0IHVwcGVyID0gTWF0aC5taW4obWV0YS5oZWFkU2VxLCBpbnB1dC5mcm9tU2VxICsgaW5wdXQubGltaXQgLSAxKTtcbiAgICBmb3IgKGxldCBzZXEgPSBpbnB1dC5mcm9tU2VxOyBzZXEgPD0gdXBwZXI7IHNlcSArPSAxKSB7XG4gICAgICBjb25zdCBpbmRleCA9IGF3YWl0IHRoaXMuc3RhdGUuZ2V0PFN0b3JlZFJlY29yZEluZGV4PihgJHtSRUNPUkRfUFJFRklYfSR7c2VxfWApO1xuICAgICAgaWYgKCFpbmRleCkge1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cbiAgICAgIGlmIChpbmRleC5pbmxpbmVSZWNvcmQpIHtcbiAgICAgICAgcmVjb3Jkcy5wdXNoKGluZGV4LmlubGluZVJlY29yZCk7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuICAgICAgaWYgKCFpbmRleC5wYXlsb2FkUmVmKSB7XG4gICAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNTAwLCBcInRlbXBvcmFyeV91bmF2YWlsYWJsZVwiLCBcInJlY29yZCBwYXlsb2FkIHJlZmVyZW5jZSBpcyBtaXNzaW5nXCIpO1xuICAgICAgfVxuICAgICAgY29uc3QgcmVjb3JkID0gYXdhaXQgdGhpcy5zcGlsbFN0b3JlLmdldEpzb248SW5ib3hSZWNvcmQ+KGluZGV4LnBheWxvYWRSZWYpO1xuICAgICAgaWYgKCFyZWNvcmQpIHtcbiAgICAgICAgdGhyb3cgbmV3IEh0dHBFcnJvcig1MDAsIFwidGVtcG9yYXJ5X3VuYXZhaWxhYmxlXCIsIFwicmVjb3JkIHBheWxvYWQgaXMgbWlzc2luZ1wiKTtcbiAgICAgIH1cbiAgICAgIHJlY29yZHMucHVzaChyZWNvcmQpO1xuICAgIH1cbiAgICByZXR1cm4ge1xuICAgICAgdG9TZXE6IHJlY29yZHMubGVuZ3RoID4gMCA/IHJlY29yZHNbcmVjb3Jkcy5sZW5ndGggLSAxXS5zZXEgOiBtZXRhLmhlYWRTZXEsXG4gICAgICByZWNvcmRzXG4gICAgfTtcbiAgfVxuXG4gIGFzeW5jIGFjayhpbnB1dDogQWNrUmVxdWVzdCk6IFByb21pc2U8QWNrUmVzdWx0PiB7XG4gICAgaWYgKGlucHV0LmFjay5kZXZpY2VJZCAhPT0gdGhpcy5kZXZpY2VJZCkge1xuICAgICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDAsIFwiaW52YWxpZF9pbnB1dFwiLCBcImFjayBkZXZpY2VfaWQgZG9lcyBub3QgbWF0Y2ggaW5ib3ggcm91dGVcIik7XG4gICAgfVxuICAgIGNvbnN0IG1ldGEgPSBhd2FpdCB0aGlzLmdldE1ldGEoKTtcbiAgICBjb25zdCBhY2tTZXEgPSBNYXRoLm1heChtZXRhLmFja2VkU2VxLCBpbnB1dC5hY2suYWNrU2VxKTtcbiAgICBhd2FpdCB0aGlzLnN0YXRlLnB1dChNRVRBX0tFWSwgeyAuLi5tZXRhLCBhY2tlZFNlcTogYWNrU2VxIH0pO1xuICAgIGF3YWl0IHRoaXMuc3RhdGUuc2V0QWxhcm0oRGF0ZS5ub3coKSk7XG4gICAgcmV0dXJuIHsgYWNjZXB0ZWQ6IHRydWUsIGFja1NlcSB9O1xuICB9XG5cbiAgYXN5bmMgZ2V0SGVhZCgpOiBQcm9taXNlPHsgaGVhZFNlcTogbnVtYmVyIH0+IHtcbiAgICBjb25zdCBtZXRhID0gYXdhaXQgdGhpcy5nZXRNZXRhKCk7XG4gICAgcmV0dXJuIHsgaGVhZFNlcTogbWV0YS5oZWFkU2VxIH07XG4gIH1cblxuICBhc3luYyBjbGVhbkV4cGlyZWRSZWNvcmRzKG5vdzogbnVtYmVyKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgbWV0YSA9IGF3YWl0IHRoaXMuZ2V0TWV0YSgpO1xuICAgIGZvciAobGV0IHNlcSA9IDE7IHNlcSA8PSBtZXRhLmFja2VkU2VxOyBzZXEgKz0gMSkge1xuICAgICAgY29uc3Qga2V5ID0gYCR7UkVDT1JEX1BSRUZJWH0ke3NlcX1gO1xuICAgICAgY29uc3QgaW5kZXggPSBhd2FpdCB0aGlzLnN0YXRlLmdldDxTdG9yZWRSZWNvcmRJbmRleD4oa2V5KTtcbiAgICAgIGlmICghaW5kZXggfHwgaW5kZXguZXhwaXJlc0F0ID09PSB1bmRlZmluZWQgfHwgaW5kZXguZXhwaXJlc0F0ID4gbm93KSB7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuICAgICAgaWYgKGluZGV4LnBheWxvYWRSZWYpIHtcbiAgICAgICAgYXdhaXQgdGhpcy5zcGlsbFN0b3JlLmRlbGV0ZShpbmRleC5wYXlsb2FkUmVmKTtcbiAgICAgIH1cbiAgICAgIGF3YWl0IHRoaXMuc3RhdGUuZGVsZXRlKGtleSk7XG4gICAgICBhd2FpdCB0aGlzLnN0YXRlLmRlbGV0ZShgJHtJREVNUE9URU5DWV9QUkVGSVh9JHtpbmRleC5tZXNzYWdlSWR9YCk7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBhc3luYyBnZXRNZXRhKCk6IFByb21pc2U8SW5ib3hNZXRhPiB7XG4gICAgcmV0dXJuIChhd2FpdCB0aGlzLnN0YXRlLmdldDxJbmJveE1ldGE+KE1FVEFfS0VZKSkgPz8gdGhpcy5kZWZhdWx0cztcbiAgfVxuXG4gIHByaXZhdGUgcHVibGlzaChldmVudDogUmVhbHRpbWVFdmVudCk6IHZvaWQge1xuICAgIGNvbnN0IHBheWxvYWQgPSBKU09OLnN0cmluZ2lmeShldmVudCk7XG4gICAgZm9yIChjb25zdCBzZXNzaW9uIG9mIHRoaXMuc2Vzc2lvbnMpIHtcbiAgICAgIHNlc3Npb24uc2VuZChwYXlsb2FkKTtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIHZhbGlkYXRlQXBwZW5kUmVxdWVzdChpbnB1dDogQXBwZW5kRW52ZWxvcGVSZXF1ZXN0KTogdm9pZCB7XG4gICAgaWYgKGlucHV0LnJlY2lwaWVudERldmljZUlkICE9PSB0aGlzLmRldmljZUlkKSB7XG4gICAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMCwgXCJpbnZhbGlkX2lucHV0XCIsIFwicmVjaXBpZW50X2RldmljZV9pZCBkb2VzIG5vdCBtYXRjaCBpbmJveCByb3V0ZVwiKTtcbiAgICB9XG4gICAgaWYgKGlucHV0LmVudmVsb3BlLnJlY2lwaWVudERldmljZUlkICE9PSB0aGlzLmRldmljZUlkKSB7XG4gICAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMCwgXCJpbnZhbGlkX2lucHV0XCIsIFwiZW52ZWxvcGUgcmVjaXBpZW50X2RldmljZV9pZCBkb2VzIG5vdCBtYXRjaCBpbmJveCByb3V0ZVwiKTtcbiAgICB9XG4gICAgaWYgKCFpbnB1dC5lbnZlbG9wZS5tZXNzYWdlSWQgfHwgIWlucHV0LmVudmVsb3BlLmNvbnZlcnNhdGlvbklkIHx8ICFpbnB1dC5lbnZlbG9wZS5zZW5kZXJVc2VySWQpIHtcbiAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAwLCBcImludmFsaWRfaW5wdXRcIiwgXCJhcHBlbmQgcmVxdWVzdCBpcyBtaXNzaW5nIHJlcXVpcmVkIGVudmVsb3BlIGZpZWxkc1wiKTtcbiAgICB9XG4gICAgY29uc3QgaGFzSW5saW5lID0gQm9vbGVhbihpbnB1dC5lbnZlbG9wZS5pbmxpbmVDaXBoZXJ0ZXh0KTtcbiAgICBjb25zdCBoYXNTdG9yYWdlUmVmcyA9IChpbnB1dC5lbnZlbG9wZS5zdG9yYWdlUmVmcz8ubGVuZ3RoID8/IDApID4gMDtcbiAgICBpZiAoIWhhc0lubGluZSAmJiAhaGFzU3RvcmFnZVJlZnMpIHtcbiAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAwLCBcImludmFsaWRfaW5wdXRcIiwgXCJlbnZlbG9wZSBtdXN0IGluY2x1ZGUgaW5saW5lX2NpcGhlcnRleHQgb3Igc3RvcmFnZV9yZWZzXCIpO1xuICAgIH1cbiAgfVxufVxyXG4iLCAiaW1wb3J0IHsgSHR0cEVycm9yIH0gZnJvbSBcIi4uL2F1dGgvY2FwYWJpbGl0eVwiO1xuaW1wb3J0IHsgSW5ib3hTZXJ2aWNlIH0gZnJvbSBcIi4vc2VydmljZVwiO1xuaW1wb3J0IHR5cGUgeyBBY2tSZXF1ZXN0LCBBcHBlbmRFbnZlbG9wZVJlcXVlc3QsIEZldGNoTWVzc2FnZXNSZXF1ZXN0IH0gZnJvbSBcIi4uL3R5cGVzL2NvbnRyYWN0c1wiO1xuaW1wb3J0IHR5cGUgeyBEdXJhYmxlT2JqZWN0U3RvcmFnZUxpa2UsIEVudiwgSnNvbkJsb2JTdG9yZSwgU2Vzc2lvblNpbmsgfSBmcm9tIFwiLi4vdHlwZXMvcnVudGltZVwiO1xuXG5jbGFzcyBEdXJhYmxlT2JqZWN0U3RvcmFnZUFkYXB0ZXIgaW1wbGVtZW50cyBEdXJhYmxlT2JqZWN0U3RvcmFnZUxpa2Uge1xuICBwcml2YXRlIHJlYWRvbmx5IHN0b3JhZ2U6IER1cmFibGVPYmplY3RTdGF0ZVtcInN0b3JhZ2VcIl07XG5cbiAgY29uc3RydWN0b3Ioc3RvcmFnZTogRHVyYWJsZU9iamVjdFN0YXRlW1wic3RvcmFnZVwiXSkge1xuICAgIHRoaXMuc3RvcmFnZSA9IHN0b3JhZ2U7XG4gIH1cblxuICBhc3luYyBnZXQ8VD4oa2V5OiBzdHJpbmcpOiBQcm9taXNlPFQgfCB1bmRlZmluZWQ+IHtcbiAgICByZXR1cm4gKGF3YWl0IHRoaXMuc3RvcmFnZS5nZXQ8VD4oa2V5KSkgPz8gdW5kZWZpbmVkO1xuICB9XG5cbiAgYXN5bmMgcHV0PFQ+KGtleTogc3RyaW5nLCB2YWx1ZTogVCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGF3YWl0IHRoaXMuc3RvcmFnZS5wdXQoa2V5LCB2YWx1ZSk7XG4gIH1cblxuICBhc3luYyBkZWxldGUoa2V5OiBzdHJpbmcpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLnN0b3JhZ2UuZGVsZXRlKGtleSk7XG4gIH1cblxuICBhc3luYyBzZXRBbGFybShlcG9jaE1pbGxpczogbnVtYmVyKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgYXdhaXQgdGhpcy5zdG9yYWdlLnNldEFsYXJtKGVwb2NoTWlsbGlzKTtcbiAgfVxufVxuXG5jbGFzcyBSMkpzb25CbG9iU3RvcmUgaW1wbGVtZW50cyBKc29uQmxvYlN0b3JlIHtcbiAgcHJpdmF0ZSByZWFkb25seSBidWNrZXQ6IEVudltcIlRBUENIQVRfU1RPUkFHRVwiXTtcblxuICBjb25zdHJ1Y3RvcihidWNrZXQ6IEVudltcIlRBUENIQVRfU1RPUkFHRVwiXSkge1xuICAgIHRoaXMuYnVja2V0ID0gYnVja2V0O1xuICB9XG5cbiAgYXN5bmMgcHV0SnNvbjxUPihrZXk6IHN0cmluZywgdmFsdWU6IFQpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLmJ1Y2tldC5wdXQoa2V5LCBKU09OLnN0cmluZ2lmeSh2YWx1ZSkpO1xuICB9XG5cbiAgYXN5bmMgZ2V0SnNvbjxUPihrZXk6IHN0cmluZyk6IFByb21pc2U8VCB8IG51bGw+IHtcbiAgICBjb25zdCBvYmplY3QgPSBhd2FpdCB0aGlzLmJ1Y2tldC5nZXQoa2V5KTtcbiAgICBpZiAoIW9iamVjdCkge1xuICAgICAgcmV0dXJuIG51bGw7XG4gICAgfVxuICAgIHJldHVybiBhd2FpdCBvYmplY3QuanNvbjxUPigpO1xuICB9XG5cbiAgYXN5bmMgcHV0Qnl0ZXMoa2V5OiBzdHJpbmcsIHZhbHVlOiBBcnJheUJ1ZmZlciB8IFVpbnQ4QXJyYXkpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLmJ1Y2tldC5wdXQoa2V5LCB2YWx1ZSk7XG4gIH1cblxuICBhc3luYyBnZXRCeXRlcyhrZXk6IHN0cmluZyk6IFByb21pc2U8QXJyYXlCdWZmZXIgfCBudWxsPiB7XG4gICAgY29uc3Qgb2JqZWN0ID0gYXdhaXQgdGhpcy5idWNrZXQuZ2V0KGtleSk7XG4gICAgaWYgKCFvYmplY3QpIHtcbiAgICAgIHJldHVybiBudWxsO1xuICAgIH1cbiAgICByZXR1cm4gb2JqZWN0LmFycmF5QnVmZmVyKCk7XG4gIH1cblxuICBhc3luYyBkZWxldGUoa2V5OiBzdHJpbmcpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLmJ1Y2tldC5kZWxldGUoa2V5KTtcbiAgfVxufVxuXG5mdW5jdGlvbiB2ZXJzaW9uZWRCb2R5KGJvZHk6IHVua25vd24pOiB1bmtub3duIHtcbiAgaWYgKCFib2R5IHx8IHR5cGVvZiBib2R5ICE9PSBcIm9iamVjdFwiIHx8IEFycmF5LmlzQXJyYXkoYm9keSkpIHtcbiAgICByZXR1cm4gYm9keTtcbiAgfVxuICBjb25zdCByZWNvcmQgPSBib2R5IGFzIFJlY29yZDxzdHJpbmcsIHVua25vd24+O1xuICBpZiAocmVjb3JkLnZlcnNpb24gIT09IHVuZGVmaW5lZCkge1xuICAgIHJldHVybiBib2R5O1xuICB9XG4gIHJldHVybiB7XG4gICAgdmVyc2lvbjogXCIwLjFcIixcbiAgICAuLi5yZWNvcmRcbiAgfTtcbn1cblxuZnVuY3Rpb24ganNvblJlc3BvbnNlKGJvZHk6IHVua25vd24sIHN0YXR1cyA9IDIwMCk6IFJlc3BvbnNlIHtcbiAgcmV0dXJuIG5ldyBSZXNwb25zZShKU09OLnN0cmluZ2lmeSh2ZXJzaW9uZWRCb2R5KGJvZHkpKSwge1xuICAgIHN0YXR1cyxcbiAgICBoZWFkZXJzOiB7XG4gICAgICBcImNvbnRlbnQtdHlwZVwiOiBcImFwcGxpY2F0aW9uL2pzb25cIlxuICAgIH1cbiAgfSk7XG59XG5cbmNvbnN0IER1cmFibGVPYmplY3RCYXNlOiB0eXBlb2YgRHVyYWJsZU9iamVjdCA9XG4gIChnbG9iYWxUaGlzIGFzIHsgRHVyYWJsZU9iamVjdD86IHR5cGVvZiBEdXJhYmxlT2JqZWN0IH0pLkR1cmFibGVPYmplY3QgPz9cbiAgKGNsYXNzIHtcbiAgICBjb25zdHJ1Y3Rvcihfc3RhdGU6IER1cmFibGVPYmplY3RTdGF0ZSwgX2VudjogRW52KSB7fVxuICB9IGFzIHVua25vd24gYXMgdHlwZW9mIER1cmFibGVPYmplY3QpO1xuXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gaGFuZGxlSW5ib3hEdXJhYmxlUmVxdWVzdChcbiAgcmVxdWVzdDogUmVxdWVzdCxcbiAgZGVwczoge1xuICAgIGRldmljZUlkOiBzdHJpbmc7XG4gICAgc3RhdGU6IER1cmFibGVPYmplY3RTdG9yYWdlTGlrZTtcbiAgICBzcGlsbFN0b3JlOiBKc29uQmxvYlN0b3JlO1xuICAgIHNlc3Npb25zOiBTZXNzaW9uU2lua1tdO1xuICAgIG1heElubGluZUJ5dGVzOiBudW1iZXI7XG4gICAgcmV0ZW50aW9uRGF5czogbnVtYmVyO1xuICAgIG9uVXBncmFkZT86ICgpID0+IFJlc3BvbnNlO1xuICAgIG5vdz86IG51bWJlcjtcbiAgfVxuKTogUHJvbWlzZTxSZXNwb25zZT4ge1xuICBjb25zdCBub3cgPSBkZXBzLm5vdyA/PyBEYXRlLm5vdygpO1xuICBjb25zdCB1cmwgPSBuZXcgVVJMKHJlcXVlc3QudXJsKTtcbiAgY29uc3Qgc2VydmljZSA9IG5ldyBJbmJveFNlcnZpY2UoZGVwcy5kZXZpY2VJZCwgZGVwcy5zdGF0ZSwgZGVwcy5zcGlsbFN0b3JlLCBkZXBzLnNlc3Npb25zLCB7XG4gICAgaGVhZFNlcTogMCxcbiAgICBhY2tlZFNlcTogMCxcbiAgICByZXRlbnRpb25EYXlzOiBkZXBzLnJldGVudGlvbkRheXMsXG4gICAgbWF4SW5saW5lQnl0ZXM6IGRlcHMubWF4SW5saW5lQnl0ZXNcbiAgfSk7XG5cbiAgdHJ5IHtcbiAgICBpZiAodXJsLnBhdGhuYW1lLmVuZHNXaXRoKFwiL3N1YnNjcmliZVwiKSkge1xuICAgICAgaWYgKHJlcXVlc3QuaGVhZGVycy5nZXQoXCJVcGdyYWRlXCIpPy50b0xvd2VyQ2FzZSgpICE9PSBcIndlYnNvY2tldFwiKSB7XG4gICAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAwLCBcImludmFsaWRfaW5wdXRcIiwgXCJzdWJzY3JpYmUgcmVxdWlyZXMgd2Vic29ja2V0IHVwZ3JhZGVcIik7XG4gICAgICB9XG4gICAgICBpZiAoIWRlcHMub25VcGdyYWRlKSB7XG4gICAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNTAwLCBcInRlbXBvcmFyeV91bmF2YWlsYWJsZVwiLCBcIndlYnNvY2tldCB1cGdyYWRlIGhhbmRsZXIgaXMgdW5hdmFpbGFibGVcIik7XG4gICAgICB9XG4gICAgICByZXR1cm4gZGVwcy5vblVwZ3JhZGUoKTtcbiAgICB9XG5cbiAgICBpZiAodXJsLnBhdGhuYW1lLmVuZHNXaXRoKFwiL21lc3NhZ2VzXCIpICYmIHJlcXVlc3QubWV0aG9kID09PSBcIlBPU1RcIikge1xuICAgICAgY29uc3QgYm9keSA9IChhd2FpdCByZXF1ZXN0Lmpzb24oKSkgYXMgQXBwZW5kRW52ZWxvcGVSZXF1ZXN0O1xuICAgICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgc2VydmljZS5hcHBlbmRFbnZlbG9wZShib2R5LCBub3cpO1xuICAgICAgcmV0dXJuIGpzb25SZXNwb25zZSh7IGFjY2VwdGVkOiByZXN1bHQuYWNjZXB0ZWQsIHNlcTogcmVzdWx0LnNlcSB9KTtcbiAgICB9XG5cbiAgICBpZiAodXJsLnBhdGhuYW1lLmVuZHNXaXRoKFwiL21lc3NhZ2VzXCIpICYmIHJlcXVlc3QubWV0aG9kID09PSBcIkdFVFwiKSB7XG4gICAgICBjb25zdCBmcm9tU2VxID0gTnVtYmVyKHVybC5zZWFyY2hQYXJhbXMuZ2V0KFwiZnJvbVNlcVwiKSA/PyBcIjFcIik7XG4gICAgICBjb25zdCBsaW1pdCA9IE51bWJlcih1cmwuc2VhcmNoUGFyYW1zLmdldChcImxpbWl0XCIpID8/IFwiMTAwXCIpO1xuICAgICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgc2VydmljZS5mZXRjaE1lc3NhZ2VzKHtcbiAgICAgICAgZGV2aWNlSWQ6IGRlcHMuZGV2aWNlSWQsXG4gICAgICAgIGZyb21TZXEsXG4gICAgICAgIGxpbWl0XG4gICAgICB9IGFzIEZldGNoTWVzc2FnZXNSZXF1ZXN0KTtcbiAgICAgIHJldHVybiBqc29uUmVzcG9uc2Uoe1xuICAgICAgICB0b1NlcTogcmVzdWx0LnRvU2VxLFxuICAgICAgICByZWNvcmRzOiByZXN1bHQucmVjb3Jkc1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgaWYgKHVybC5wYXRobmFtZS5lbmRzV2l0aChcIi9hY2tcIikgJiYgcmVxdWVzdC5tZXRob2QgPT09IFwiUE9TVFwiKSB7XG4gICAgICBjb25zdCBib2R5ID0gKGF3YWl0IHJlcXVlc3QuanNvbigpKSBhcyBBY2tSZXF1ZXN0O1xuICAgICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgc2VydmljZS5hY2soYm9keSk7XG4gICAgICByZXR1cm4ganNvblJlc3BvbnNlKHtcbiAgICAgICAgYWNjZXB0ZWQ6IHJlc3VsdC5hY2NlcHRlZCxcbiAgICAgICAgYWNrU2VxOiByZXN1bHQuYWNrU2VxXG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBpZiAodXJsLnBhdGhuYW1lLmVuZHNXaXRoKFwiL2hlYWRcIikgJiYgcmVxdWVzdC5tZXRob2QgPT09IFwiR0VUXCIpIHtcbiAgICAgIGNvbnN0IHJlc3VsdCA9IGF3YWl0IHNlcnZpY2UuZ2V0SGVhZCgpO1xuICAgICAgcmV0dXJuIGpzb25SZXNwb25zZShyZXN1bHQpO1xuICAgIH1cblxuICAgIHJldHVybiBqc29uUmVzcG9uc2UoeyBlcnJvcjogXCJub3RfZm91bmRcIiB9LCA0MDQpO1xuICB9IGNhdGNoIChlcnJvcikge1xuICAgIGlmIChlcnJvciBpbnN0YW5jZW9mIEh0dHBFcnJvcikge1xuICAgICAgcmV0dXJuIGpzb25SZXNwb25zZSh7IGVycm9yOiBlcnJvci5jb2RlLCBtZXNzYWdlOiBlcnJvci5tZXNzYWdlIH0sIGVycm9yLnN0YXR1cyk7XG4gICAgfVxuICAgIGNvbnN0IHJ1bnRpbWVFcnJvciA9IGVycm9yIGFzIHsgbWVzc2FnZT86IHN0cmluZyB9O1xuICAgIGNvbnN0IG1lc3NhZ2UgPSBydW50aW1lRXJyb3IubWVzc2FnZSA/PyBcImludGVybmFsIGVycm9yXCI7XG4gICAgcmV0dXJuIGpzb25SZXNwb25zZSh7IGVycm9yOiBcInRlbXBvcmFyeV91bmF2YWlsYWJsZVwiLCBtZXNzYWdlIH0sIDUwMCk7XG4gIH1cbn1cblxuZXhwb3J0IGNsYXNzIEluYm94RHVyYWJsZU9iamVjdCBleHRlbmRzIER1cmFibGVPYmplY3RCYXNlIHtcbiAgcHJpdmF0ZSByZWFkb25seSBzZXNzaW9ucyA9IG5ldyBNYXA8c3RyaW5nLCBNYW5hZ2VkU2Vzc2lvbj4oKTtcbiAgcHJpdmF0ZSByZWFkb25seSBzdGF0ZVJlZjogRHVyYWJsZU9iamVjdFN0YXRlO1xuICBwcml2YXRlIHJlYWRvbmx5IGVudlJlZjogRW52O1xuXG4gIGNvbnN0cnVjdG9yKHN0YXRlOiBEdXJhYmxlT2JqZWN0U3RhdGUsIGVudjogRW52KSB7XG4gICAgc3VwZXIoc3RhdGUsIGVudik7XG4gICAgdGhpcy5zdGF0ZVJlZiA9IHN0YXRlO1xuICAgIHRoaXMuZW52UmVmID0gZW52O1xuICB9XG5cbiAgYXN5bmMgZmV0Y2gocmVxdWVzdDogUmVxdWVzdCk6IFByb21pc2U8UmVzcG9uc2U+IHtcbiAgICBjb25zdCB1cmwgPSBuZXcgVVJMKHJlcXVlc3QudXJsKTtcbiAgICBjb25zdCBtYXRjaCA9IHVybC5wYXRobmFtZS5tYXRjaCgvXFwvdjFcXC9pbmJveFxcLyhbXi9dKylcXC8vKTtcbiAgICBjb25zdCBkZXZpY2VJZCA9IGRlY29kZVVSSUNvbXBvbmVudChtYXRjaD8uWzFdID8/IFwiXCIpO1xuXG4gICAgcmV0dXJuIGhhbmRsZUluYm94RHVyYWJsZVJlcXVlc3QocmVxdWVzdCwge1xuICAgICAgZGV2aWNlSWQsXG4gICAgICBzdGF0ZTogbmV3IER1cmFibGVPYmplY3RTdG9yYWdlQWRhcHRlcih0aGlzLnN0YXRlUmVmLnN0b3JhZ2UpLFxuICAgICAgc3BpbGxTdG9yZTogbmV3IFIySnNvbkJsb2JTdG9yZSh0aGlzLmVudlJlZi5UQVBDSEFUX1NUT1JBR0UpLFxuICAgICAgc2Vzc2lvbnM6IEFycmF5LmZyb20odGhpcy5zZXNzaW9ucy52YWx1ZXMoKSkubWFwKFxuICAgICAgICAoc2Vzc2lvbikgPT5cbiAgICAgICAgICAoe1xuICAgICAgICAgICAgc2VuZChwYXlsb2FkOiBzdHJpbmcpOiB2b2lkIHtcbiAgICAgICAgICAgICAgc2Vzc2lvbi5zZW5kKHBheWxvYWQpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH0pIHNhdGlzZmllcyBTZXNzaW9uU2lua1xuICAgICAgKSxcbiAgICAgIG1heElubGluZUJ5dGVzOiBOdW1iZXIodGhpcy5lbnZSZWYuTUFYX0lOTElORV9CWVRFUyA/PyBcIjQwOTZcIiksXG4gICAgICByZXRlbnRpb25EYXlzOiBOdW1iZXIodGhpcy5lbnZSZWYuUkVURU5USU9OX0RBWVMgPz8gXCIzMFwiKSxcbiAgICAgIG9uVXBncmFkZTogKCkgPT4ge1xuICAgICAgICBjb25zdCBwYWlyID0gbmV3IFdlYlNvY2tldFBhaXIoKTtcbiAgICAgICAgY29uc3QgY2xpZW50ID0gcGFpclswXTtcbiAgICAgICAgY29uc3Qgc2VydmVyID0gcGFpclsxXTtcbiAgICAgICAgc2VydmVyLmFjY2VwdCgpO1xuICAgICAgICBjb25zdCBzZXNzaW9uSWQgPSBjcnlwdG8ucmFuZG9tVVVJRCgpO1xuICAgICAgICBjb25zdCBzZXNzaW9uID0gbmV3IE1hbmFnZWRTZXNzaW9uKHNlcnZlcik7XG4gICAgICAgIHRoaXMuc2Vzc2lvbnMuc2V0KHNlc3Npb25JZCwgc2Vzc2lvbik7XG4gICAgICAgIHF1ZXVlTWljcm90YXNrKCgpID0+IHtcbiAgICAgICAgICBzZXNzaW9uLm1hcmtSZWFkeSgpO1xuICAgICAgICB9KTtcbiAgICAgICAgc2VydmVyLmFkZEV2ZW50TGlzdGVuZXIoXCJjbG9zZVwiLCAoKSA9PiB7XG4gICAgICAgICAgdGhpcy5zZXNzaW9ucy5kZWxldGUoc2Vzc2lvbklkKTtcbiAgICAgICAgfSk7XG4gICAgICAgIHJldHVybiBuZXcgUmVzcG9uc2UobnVsbCwge1xuICAgICAgICAgIHN0YXR1czogMTAxLFxuICAgICAgICAgIHdlYlNvY2tldDogY2xpZW50XG4gICAgICAgIH0gYXMgUmVzcG9uc2VJbml0ICYgeyB3ZWJTb2NrZXQ6IFdlYlNvY2tldCB9KTtcbiAgICAgIH1cbiAgICB9KTtcbiAgfVxuXG4gIGFzeW5jIGFsYXJtKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IHNlcnZpY2UgPSBuZXcgSW5ib3hTZXJ2aWNlKFxuICAgICAgXCJcIixcbiAgICAgIG5ldyBEdXJhYmxlT2JqZWN0U3RvcmFnZUFkYXB0ZXIodGhpcy5zdGF0ZVJlZi5zdG9yYWdlKSxcbiAgICAgIG5ldyBSMkpzb25CbG9iU3RvcmUodGhpcy5lbnZSZWYuVEFQQ0hBVF9TVE9SQUdFKSxcbiAgICAgIFtdLFxuICAgICAge1xuICAgICAgICBoZWFkU2VxOiAwLFxuICAgICAgICBhY2tlZFNlcTogMCxcbiAgICAgICAgcmV0ZW50aW9uRGF5czogTnVtYmVyKHRoaXMuZW52UmVmLlJFVEVOVElPTl9EQVlTID8/IFwiMzBcIiksXG4gICAgICAgIG1heElubGluZUJ5dGVzOiBOdW1iZXIodGhpcy5lbnZSZWYuTUFYX0lOTElORV9CWVRFUyA/PyBcIjQwOTZcIilcbiAgICAgIH1cbiAgICApO1xuICAgIGF3YWl0IHNlcnZpY2UuY2xlYW5FeHBpcmVkUmVjb3JkcyhEYXRlLm5vdygpKTtcbiAgfVxufVxuXG5jbGFzcyBNYW5hZ2VkU2Vzc2lvbiB7XG4gIHByaXZhdGUgcmVhZG9ubHkgc29ja2V0OiBXZWJTb2NrZXQ7XG4gIHByaXZhdGUgcmVhZHkgPSBmYWxzZTtcbiAgcHJpdmF0ZSByZWFkb25seSBxdWV1ZWRQYXlsb2Fkczogc3RyaW5nW10gPSBbXTtcblxuICBjb25zdHJ1Y3Rvcihzb2NrZXQ6IFdlYlNvY2tldCkge1xuICAgIHRoaXMuc29ja2V0ID0gc29ja2V0O1xuICB9XG5cbiAgc2VuZChwYXlsb2FkOiBzdHJpbmcpOiB2b2lkIHtcbiAgICBpZiAoIXRoaXMucmVhZHkpIHtcbiAgICAgIHRoaXMucXVldWVkUGF5bG9hZHMucHVzaChwYXlsb2FkKTtcbiAgICAgIHJldHVybjtcbiAgICB9XG4gICAgdGhpcy5kaXNwYXRjaChwYXlsb2FkKTtcbiAgfVxuXG4gIG1hcmtSZWFkeSgpOiB2b2lkIHtcbiAgICBpZiAodGhpcy5yZWFkeSkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICB0aGlzLnJlYWR5ID0gdHJ1ZTtcbiAgICB3aGlsZSAodGhpcy5xdWV1ZWRQYXlsb2Fkcy5sZW5ndGggPiAwKSB7XG4gICAgICBjb25zdCBwYXlsb2FkID0gdGhpcy5xdWV1ZWRQYXlsb2Fkcy5zaGlmdCgpO1xuICAgICAgaWYgKHBheWxvYWQgPT09IHVuZGVmaW5lZCkge1xuICAgICAgICBicmVhaztcbiAgICAgIH1cbiAgICAgIHRoaXMuZGlzcGF0Y2gocGF5bG9hZCk7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBkaXNwYXRjaChwYXlsb2FkOiBzdHJpbmcpOiB2b2lkIHtcbiAgICAvLyBEZWxpdmVyIG9uIHRoZSBuZXh0IHRhc2sgdHVybiBzbyBiYWNrLXRvLWJhY2sgcHVibGlzaCBldmVudHMgYXJlIG5vdCBsb3N0XG4gICAgLy8gYnkgdGhlIE1pbmlmbGFyZSB0ZXN0IGNsaWVudCB3aGlsZSBpdCBzd2FwcyBtZXNzYWdlIGxpc3RlbmVycy5cbiAgICBzZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgIHRoaXMuc29ja2V0LnNlbmQocGF5bG9hZCk7XG4gICAgfSwgMCk7XG4gIH1cbn1cclxuIiwgImltcG9ydCB7IEh0dHBFcnJvciB9IGZyb20gXCIuLi9hdXRoL2NhcGFiaWxpdHlcIjtcbmltcG9ydCB0eXBlIHtcbiAgRGV2aWNlTGlzdERvY3VtZW50LFxuICBEZXZpY2VTdGF0dXNEb2N1bWVudCxcbiAgSWRlbnRpdHlCdW5kbGUsXG4gIEtleVBhY2thZ2VSZWZzRG9jdW1lbnRcbn0gZnJvbSBcIi4uL3R5cGVzL2NvbnRyYWN0c1wiO1xuaW1wb3J0IHR5cGUgeyBKc29uQmxvYlN0b3JlIH0gZnJvbSBcIi4uL3R5cGVzL3J1bnRpbWVcIjtcblxuZnVuY3Rpb24gc2FuaXRpemVTZWdtZW50KHZhbHVlOiBzdHJpbmcpOiBzdHJpbmcge1xuICByZXR1cm4gdmFsdWUucmVwbGFjZSgvW15hLXpBLVowLTk6Xy1dL2csIFwiX1wiKTtcbn1cblxuZXhwb3J0IGNsYXNzIFNoYXJlZFN0YXRlU2VydmljZSB7XG4gIHByaXZhdGUgcmVhZG9ubHkgc3RvcmU6IEpzb25CbG9iU3RvcmU7XG4gIHByaXZhdGUgcmVhZG9ubHkgYmFzZVVybDogc3RyaW5nO1xuXG4gIGNvbnN0cnVjdG9yKHN0b3JlOiBKc29uQmxvYlN0b3JlLCBiYXNlVXJsOiBzdHJpbmcpIHtcbiAgICB0aGlzLnN0b3JlID0gc3RvcmU7XG4gICAgdGhpcy5iYXNlVXJsID0gYmFzZVVybDtcbiAgfVxuXG4gIGlkZW50aXR5QnVuZGxlS2V5KHVzZXJJZDogc3RyaW5nKTogc3RyaW5nIHtcbiAgICByZXR1cm4gYHNoYXJlZC1zdGF0ZS8ke3Nhbml0aXplU2VnbWVudCh1c2VySWQpfS9pZGVudGl0eV9idW5kbGUuanNvbmA7XG4gIH1cblxuICBkZXZpY2VMaXN0S2V5KHVzZXJJZDogc3RyaW5nKTogc3RyaW5nIHtcbiAgICByZXR1cm4gYHNoYXJlZC1zdGF0ZS8ke3Nhbml0aXplU2VnbWVudCh1c2VySWQpfS9kZXZpY2VfbGlzdC5qc29uYDtcbiAgfVxuXG4gIGRldmljZVN0YXR1c0tleSh1c2VySWQ6IHN0cmluZyk6IHN0cmluZyB7XG4gICAgcmV0dXJuIGBzaGFyZWQtc3RhdGUvJHtzYW5pdGl6ZVNlZ21lbnQodXNlcklkKX0vZGV2aWNlX3N0YXR1cy5qc29uYDtcbiAgfVxuXG4gIGtleVBhY2thZ2VSZWZzS2V5KHVzZXJJZDogc3RyaW5nLCBkZXZpY2VJZDogc3RyaW5nKTogc3RyaW5nIHtcbiAgICByZXR1cm4gYGtleXBhY2thZ2VzLyR7c2FuaXRpemVTZWdtZW50KHVzZXJJZCl9LyR7c2FuaXRpemVTZWdtZW50KGRldmljZUlkKX0vcmVmcy5qc29uYDtcbiAgfVxuXG4gIGtleVBhY2thZ2VPYmplY3RLZXkodXNlcklkOiBzdHJpbmcsIGRldmljZUlkOiBzdHJpbmcsIGtleVBhY2thZ2VJZDogc3RyaW5nKTogc3RyaW5nIHtcbiAgICByZXR1cm4gYGtleXBhY2thZ2VzLyR7c2FuaXRpemVTZWdtZW50KHVzZXJJZCl9LyR7c2FuaXRpemVTZWdtZW50KGRldmljZUlkKX0vJHtzYW5pdGl6ZVNlZ21lbnQoa2V5UGFja2FnZUlkKX0uYmluYDtcbiAgfVxuXG4gIGlkZW50aXR5QnVuZGxlVXJsKHVzZXJJZDogc3RyaW5nKTogc3RyaW5nIHtcbiAgICByZXR1cm4gYCR7dGhpcy5iYXNlVXJsfS92MS9zaGFyZWQtc3RhdGUvJHtlbmNvZGVVUklDb21wb25lbnQodXNlcklkKX0vaWRlbnRpdHktYnVuZGxlYDtcbiAgfVxuXG4gIGRldmljZVN0YXR1c1VybCh1c2VySWQ6IHN0cmluZyk6IHN0cmluZyB7XG4gICAgcmV0dXJuIGAke3RoaXMuYmFzZVVybH0vdjEvc2hhcmVkLXN0YXRlLyR7ZW5jb2RlVVJJQ29tcG9uZW50KHVzZXJJZCl9L2RldmljZS1zdGF0dXNgO1xuICB9XG5cbiAga2V5UGFja2FnZVJlZnNVcmwodXNlcklkOiBzdHJpbmcsIGRldmljZUlkOiBzdHJpbmcpOiBzdHJpbmcge1xuICAgIHJldHVybiBgJHt0aGlzLmJhc2VVcmx9L3YxL3NoYXJlZC1zdGF0ZS9rZXlwYWNrYWdlcy8ke2VuY29kZVVSSUNvbXBvbmVudCh1c2VySWQpfS8ke2VuY29kZVVSSUNvbXBvbmVudChkZXZpY2VJZCl9YDtcbiAgfVxuXG4gIGtleVBhY2thZ2VPYmplY3RVcmwodXNlcklkOiBzdHJpbmcsIGRldmljZUlkOiBzdHJpbmcsIGtleVBhY2thZ2VJZDogc3RyaW5nKTogc3RyaW5nIHtcbiAgICByZXR1cm4gYCR7dGhpcy5iYXNlVXJsfS92MS9zaGFyZWQtc3RhdGUva2V5cGFja2FnZXMvJHtlbmNvZGVVUklDb21wb25lbnQodXNlcklkKX0vJHtlbmNvZGVVUklDb21wb25lbnQoZGV2aWNlSWQpfS8ke2VuY29kZVVSSUNvbXBvbmVudChrZXlQYWNrYWdlSWQpfWA7XG4gIH1cblxuICBhc3luYyBnZXRJZGVudGl0eUJ1bmRsZSh1c2VySWQ6IHN0cmluZyk6IFByb21pc2U8SWRlbnRpdHlCdW5kbGUgfCBudWxsPiB7XG4gICAgcmV0dXJuIHRoaXMuc3RvcmUuZ2V0SnNvbjxJZGVudGl0eUJ1bmRsZT4odGhpcy5pZGVudGl0eUJ1bmRsZUtleSh1c2VySWQpKTtcbiAgfVxuXG4gIGFzeW5jIHB1dElkZW50aXR5QnVuZGxlKHVzZXJJZDogc3RyaW5nLCBidW5kbGU6IElkZW50aXR5QnVuZGxlKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgaWYgKGJ1bmRsZS51c2VySWQgIT09IHVzZXJJZCkge1xuICAgICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDAsIFwiaW52YWxpZF9pbnB1dFwiLCBcImlkZW50aXR5IGJ1bmRsZSB1c2VySWQgZG9lcyBub3QgbWF0Y2ggcmVxdWVzdCBwYXRoXCIpO1xuICAgIH1cbiAgICBjb25zdCBub3JtYWxpemVkOiBJZGVudGl0eUJ1bmRsZSA9IHtcbiAgICAgIC4uLmJ1bmRsZSxcbiAgICAgIGlkZW50aXR5QnVuZGxlUmVmOiB0aGlzLmlkZW50aXR5QnVuZGxlVXJsKHVzZXJJZCksXG4gICAgICBkZXZpY2VTdGF0dXNSZWY6IGJ1bmRsZS5kZXZpY2VTdGF0dXNSZWYgPz8gdGhpcy5kZXZpY2VTdGF0dXNVcmwodXNlcklkKSxcbiAgICAgIGRldmljZXM6IGJ1bmRsZS5kZXZpY2VzLm1hcCgoZGV2aWNlKSA9PiAoe1xuICAgICAgICAuLi5kZXZpY2UsXG4gICAgICAgIGtleXBhY2thZ2VSZWY6IHtcbiAgICAgICAgICAuLi5kZXZpY2Uua2V5cGFja2FnZVJlZixcbiAgICAgICAgICB1c2VySWQsXG4gICAgICAgICAgZGV2aWNlSWQ6IGRldmljZS5kZXZpY2VJZCxcbiAgICAgICAgICByZWY6IGRldmljZS5rZXlwYWNrYWdlUmVmLnJlZlxuICAgICAgICB9XG4gICAgICB9KSlcbiAgICB9O1xuICAgIGF3YWl0IHRoaXMuc3RvcmUucHV0SnNvbih0aGlzLmlkZW50aXR5QnVuZGxlS2V5KHVzZXJJZCksIG5vcm1hbGl6ZWQpO1xuICAgIGF3YWl0IHRoaXMuc3RvcmUucHV0SnNvbih0aGlzLmRldmljZUxpc3RLZXkodXNlcklkKSwgdGhpcy5idWlsZERldmljZUxpc3REb2N1bWVudChub3JtYWxpemVkKSk7XG4gIH1cblxuICBhc3luYyBnZXREZXZpY2VMaXN0KHVzZXJJZDogc3RyaW5nKTogUHJvbWlzZTxEZXZpY2VMaXN0RG9jdW1lbnQgfCBudWxsPiB7XG4gICAgcmV0dXJuIHRoaXMuc3RvcmUuZ2V0SnNvbjxEZXZpY2VMaXN0RG9jdW1lbnQ+KHRoaXMuZGV2aWNlTGlzdEtleSh1c2VySWQpKTtcbiAgfVxuXG4gIGFzeW5jIGdldERldmljZVN0YXR1cyh1c2VySWQ6IHN0cmluZyk6IFByb21pc2U8RGV2aWNlU3RhdHVzRG9jdW1lbnQgfCBudWxsPiB7XG4gICAgcmV0dXJuIHRoaXMuc3RvcmUuZ2V0SnNvbjxEZXZpY2VTdGF0dXNEb2N1bWVudD4odGhpcy5kZXZpY2VTdGF0dXNLZXkodXNlcklkKSk7XG4gIH1cblxuICBhc3luYyBwdXREZXZpY2VTdGF0dXModXNlcklkOiBzdHJpbmcsIGRvY3VtZW50OiBEZXZpY2VTdGF0dXNEb2N1bWVudCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGlmIChkb2N1bWVudC51c2VySWQgIT09IHVzZXJJZCkge1xuICAgICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDAsIFwiaW52YWxpZF9pbnB1dFwiLCBcImRldmljZSBzdGF0dXMgdXNlcklkIGRvZXMgbm90IG1hdGNoIHJlcXVlc3QgcGF0aFwiKTtcbiAgICB9XG4gICAgZm9yIChjb25zdCBkZXZpY2Ugb2YgZG9jdW1lbnQuZGV2aWNlcykge1xuICAgICAgaWYgKGRldmljZS51c2VySWQgIT09IHVzZXJJZCkge1xuICAgICAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMCwgXCJpbnZhbGlkX2lucHV0XCIsIFwiZGV2aWNlIHN0YXR1cyBlbnRyeSB1c2VySWQgZG9lcyBub3QgbWF0Y2ggcmVxdWVzdCBwYXRoXCIpO1xuICAgICAgfVxuICAgIH1cbiAgICBhd2FpdCB0aGlzLnN0b3JlLnB1dEpzb24odGhpcy5kZXZpY2VTdGF0dXNLZXkodXNlcklkKSwgZG9jdW1lbnQpO1xuICB9XG5cbiAgYXN5bmMgZ2V0S2V5UGFja2FnZVJlZnModXNlcklkOiBzdHJpbmcsIGRldmljZUlkOiBzdHJpbmcpOiBQcm9taXNlPEtleVBhY2thZ2VSZWZzRG9jdW1lbnQgfCBudWxsPiB7XG4gICAgcmV0dXJuIHRoaXMuc3RvcmUuZ2V0SnNvbjxLZXlQYWNrYWdlUmVmc0RvY3VtZW50Pih0aGlzLmtleVBhY2thZ2VSZWZzS2V5KHVzZXJJZCwgZGV2aWNlSWQpKTtcbiAgfVxuXG4gIGFzeW5jIHB1dEtleVBhY2thZ2VSZWZzKHVzZXJJZDogc3RyaW5nLCBkZXZpY2VJZDogc3RyaW5nLCBkb2N1bWVudDogS2V5UGFja2FnZVJlZnNEb2N1bWVudCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGlmIChkb2N1bWVudC51c2VySWQgIT09IHVzZXJJZCB8fCBkb2N1bWVudC5kZXZpY2VJZCAhPT0gZGV2aWNlSWQpIHtcbiAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAwLCBcImludmFsaWRfaW5wdXRcIiwgXCJrZXlwYWNrYWdlIHJlZnMgc2NvcGUgZG9lcyBub3QgbWF0Y2ggcmVxdWVzdCBwYXRoXCIpO1xuICAgIH1cbiAgICBmb3IgKGNvbnN0IGVudHJ5IG9mIGRvY3VtZW50LnJlZnMpIHtcbiAgICAgIGlmICghZW50cnkucmVmIHx8ICFlbnRyeS5yZWYuc3RhcnRzV2l0aCh0aGlzLmtleVBhY2thZ2VSZWZzVXJsKHVzZXJJZCwgZGV2aWNlSWQpKSkge1xuICAgICAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMCwgXCJpbnZhbGlkX2lucHV0XCIsIFwia2V5cGFja2FnZSByZWYgbXVzdCBiZSBhIGNvbmNyZXRlIG9iamVjdCBVUkxcIik7XG4gICAgICB9XG4gICAgfVxuICAgIGF3YWl0IHRoaXMuc3RvcmUucHV0SnNvbih0aGlzLmtleVBhY2thZ2VSZWZzS2V5KHVzZXJJZCwgZGV2aWNlSWQpLCBkb2N1bWVudCk7XG4gIH1cblxuICBhc3luYyBwdXRLZXlQYWNrYWdlT2JqZWN0KHVzZXJJZDogc3RyaW5nLCBkZXZpY2VJZDogc3RyaW5nLCBrZXlQYWNrYWdlSWQ6IHN0cmluZywgYm9keTogQXJyYXlCdWZmZXIpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLnN0b3JlLnB1dEJ5dGVzKHRoaXMua2V5UGFja2FnZU9iamVjdEtleSh1c2VySWQsIGRldmljZUlkLCBrZXlQYWNrYWdlSWQpLCBib2R5LCB7XG4gICAgICBcImNvbnRlbnQtdHlwZVwiOiBcImFwcGxpY2F0aW9uL29jdGV0LXN0cmVhbVwiXG4gICAgfSk7XG4gIH1cblxuICBhc3luYyBnZXRLZXlQYWNrYWdlT2JqZWN0KHVzZXJJZDogc3RyaW5nLCBkZXZpY2VJZDogc3RyaW5nLCBrZXlQYWNrYWdlSWQ6IHN0cmluZyk6IFByb21pc2U8QXJyYXlCdWZmZXIgfCBudWxsPiB7XG4gICAgcmV0dXJuIHRoaXMuc3RvcmUuZ2V0Qnl0ZXModGhpcy5rZXlQYWNrYWdlT2JqZWN0S2V5KHVzZXJJZCwgZGV2aWNlSWQsIGtleVBhY2thZ2VJZCkpO1xuICB9XG5cbiAgcHJpdmF0ZSBidWlsZERldmljZUxpc3REb2N1bWVudChidW5kbGU6IElkZW50aXR5QnVuZGxlKTogRGV2aWNlTGlzdERvY3VtZW50IHtcbiAgICByZXR1cm4ge1xuICAgICAgdmVyc2lvbjogYnVuZGxlLnZlcnNpb24sXG4gICAgICB1c2VySWQ6IGJ1bmRsZS51c2VySWQsXG4gICAgICB1cGRhdGVkQXQ6IGJ1bmRsZS51cGRhdGVkQXQsXG4gICAgICBkZXZpY2VzOiBidW5kbGUuZGV2aWNlcy5tYXAoKGRldmljZSkgPT4gKHtcbiAgICAgICAgZGV2aWNlSWQ6IGRldmljZS5kZXZpY2VJZCxcbiAgICAgICAgc3RhdHVzOiBkZXZpY2Uuc3RhdHVzXG4gICAgICB9KSlcbiAgICB9O1xuICB9XG59IiwgImltcG9ydCB0eXBlIHsgUHJlcGFyZUJsb2JVcGxvYWRSZXF1ZXN0LCBQcmVwYXJlQmxvYlVwbG9hZFJlc3VsdCB9IGZyb20gXCIuLi90eXBlcy9jb250cmFjdHNcIjtcbmltcG9ydCB0eXBlIHsgSnNvbkJsb2JTdG9yZSB9IGZyb20gXCIuLi90eXBlcy9ydW50aW1lXCI7XG5pbXBvcnQgeyBIdHRwRXJyb3IgfSBmcm9tIFwiLi4vYXV0aC9jYXBhYmlsaXR5XCI7XG5pbXBvcnQgeyBzaWduU2hhcmluZ1BheWxvYWQsIHZlcmlmeVNoYXJpbmdQYXlsb2FkIH0gZnJvbSBcIi4vc2hhcmluZ1wiO1xuXG5mdW5jdGlvbiBzYW5pdGl6ZVNlZ21lbnQodmFsdWU6IHN0cmluZyk6IHN0cmluZyB7XG4gIHJldHVybiB2YWx1ZS5yZXBsYWNlKC9bXmEtekEtWjAtOTpfLV0vZywgXCJfXCIpO1xufVxuXG5leHBvcnQgY2xhc3MgU3RvcmFnZVNlcnZpY2Uge1xuICBwcml2YXRlIHJlYWRvbmx5IHN0b3JlOiBKc29uQmxvYlN0b3JlO1xuICBwcml2YXRlIHJlYWRvbmx5IGJhc2VVcmw6IHN0cmluZztcbiAgcHJpdmF0ZSByZWFkb25seSBzZWNyZXQ6IHN0cmluZztcblxuICBjb25zdHJ1Y3RvcihzdG9yZTogSnNvbkJsb2JTdG9yZSwgYmFzZVVybDogc3RyaW5nLCBzZWNyZXQ6IHN0cmluZykge1xuICAgIHRoaXMuc3RvcmUgPSBzdG9yZTtcbiAgICB0aGlzLmJhc2VVcmwgPSBiYXNlVXJsO1xuICAgIHRoaXMuc2VjcmV0ID0gc2VjcmV0O1xuICB9XG5cbiAgYXN5bmMgcHJlcGFyZVVwbG9hZChcbiAgICBpbnB1dDogUHJlcGFyZUJsb2JVcGxvYWRSZXF1ZXN0LFxuICAgIG93bmVyOiB7IHVzZXJJZDogc3RyaW5nOyBkZXZpY2VJZDogc3RyaW5nIH0sXG4gICAgbm93OiBudW1iZXJcbiAgKTogUHJvbWlzZTxQcmVwYXJlQmxvYlVwbG9hZFJlc3VsdD4ge1xuICAgIGlmICghaW5wdXQudGFza0lkIHx8ICFpbnB1dC5jb252ZXJzYXRpb25JZCB8fCAhaW5wdXQubWVzc2FnZUlkIHx8ICFpbnB1dC5taW1lVHlwZSB8fCBpbnB1dC5zaXplQnl0ZXMgPD0gMCkge1xuICAgICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDAsIFwiaW52YWxpZF9pbnB1dFwiLCBcInByZXBhcmUgdXBsb2FkIHJlcXVlc3QgaXMgbWlzc2luZyByZXF1aXJlZCBmaWVsZHNcIik7XG4gICAgfVxuICAgIGNvbnN0IGJsb2JLZXkgPSBbXG4gICAgICBcImJsb2JcIixcbiAgICAgIHNhbml0aXplU2VnbWVudChvd25lci51c2VySWQpLFxuICAgICAgc2FuaXRpemVTZWdtZW50KG93bmVyLmRldmljZUlkKSxcbiAgICAgIHNhbml0aXplU2VnbWVudChpbnB1dC5jb252ZXJzYXRpb25JZCksXG4gICAgICBgJHtzYW5pdGl6ZVNlZ21lbnQoaW5wdXQubWVzc2FnZUlkKX0tJHtzYW5pdGl6ZVNlZ21lbnQoaW5wdXQudGFza0lkKX1gXG4gICAgXS5qb2luKFwiL1wiKTtcbiAgICBjb25zdCBleHBpcmVzQXQgPSBub3cgKyAxNSAqIDYwICogMTAwMDtcbiAgICBjb25zdCB1cGxvYWRUb2tlbiA9IGF3YWl0IHNpZ25TaGFyaW5nUGF5bG9hZCh0aGlzLnNlY3JldCwge1xuICAgICAgYWN0aW9uOiBcInVwbG9hZFwiLFxuICAgICAgYmxvYktleSxcbiAgICAgIGV4cGlyZXNBdFxuICAgIH0pO1xuICAgIGNvbnN0IGRvd25sb2FkVG9rZW4gPSBhd2FpdCBzaWduU2hhcmluZ1BheWxvYWQodGhpcy5zZWNyZXQsIHtcbiAgICAgIGFjdGlvbjogXCJkb3dubG9hZFwiLFxuICAgICAgYmxvYktleSxcbiAgICAgIGV4cGlyZXNBdFxuICAgIH0pO1xuXG4gICAgcmV0dXJuIHtcbiAgICAgIGJsb2JSZWY6IGJsb2JLZXksXG4gICAgICB1cGxvYWRUYXJnZXQ6IGAke3RoaXMuYmFzZVVybH0vdjEvc3RvcmFnZS91cGxvYWQvJHtlbmNvZGVVUklDb21wb25lbnQoYmxvYktleSl9P3Rva2VuPSR7ZW5jb2RlVVJJQ29tcG9uZW50KHVwbG9hZFRva2VuKX1gLFxuICAgICAgdXBsb2FkSGVhZGVyczoge1xuICAgICAgICBcImNvbnRlbnQtdHlwZVwiOiBpbnB1dC5taW1lVHlwZVxuICAgICAgfSxcbiAgICAgIGRvd25sb2FkVGFyZ2V0OiBgJHt0aGlzLmJhc2VVcmx9L3YxL3N0b3JhZ2UvYmxvYi8ke2VuY29kZVVSSUNvbXBvbmVudChibG9iS2V5KX0/dG9rZW49JHtlbmNvZGVVUklDb21wb25lbnQoZG93bmxvYWRUb2tlbil9YCxcbiAgICAgIGV4cGlyZXNBdFxuICAgIH07XG4gIH1cblxuICBhc3luYyB1cGxvYWRCbG9iKGJsb2JLZXk6IHN0cmluZywgdG9rZW46IHN0cmluZywgYm9keTogQXJyYXlCdWZmZXIsIG1ldGFkYXRhOiBSZWNvcmQ8c3RyaW5nLCBzdHJpbmc+LCBub3c6IG51bWJlcik6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IHBheWxvYWQgPSBhd2FpdCB0aGlzLnZlcmlmeVRva2VuPHsgYWN0aW9uOiBzdHJpbmc7IGJsb2JLZXk6IHN0cmluZyB9Pih0b2tlbiwgbm93KTtcbiAgICBpZiAocGF5bG9hZC5hY3Rpb24gIT09IFwidXBsb2FkXCIgfHwgcGF5bG9hZC5ibG9iS2V5ICE9PSBibG9iS2V5KSB7XG4gICAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMywgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJ1cGxvYWQgdG9rZW4gaXMgbm90IHZhbGlkIGZvciB0aGlzIGJsb2JcIik7XG4gICAgfVxuICAgIGF3YWl0IHRoaXMuc3RvcmUucHV0Qnl0ZXMoYmxvYktleSwgYm9keSwgbWV0YWRhdGEpO1xuICB9XG5cbiAgYXN5bmMgZmV0Y2hCbG9iKGJsb2JLZXk6IHN0cmluZywgdG9rZW46IHN0cmluZywgbm93OiBudW1iZXIpOiBQcm9taXNlPEFycmF5QnVmZmVyPiB7XG4gICAgY29uc3QgcGF5bG9hZCA9IGF3YWl0IHRoaXMudmVyaWZ5VG9rZW48eyBhY3Rpb246IHN0cmluZzsgYmxvYktleTogc3RyaW5nIH0+KHRva2VuLCBub3cpO1xuICAgIGlmIChwYXlsb2FkLmFjdGlvbiAhPT0gXCJkb3dubG9hZFwiIHx8IHBheWxvYWQuYmxvYktleSAhPT0gYmxvYktleSkge1xuICAgICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwiZG93bmxvYWQgdG9rZW4gaXMgbm90IHZhbGlkIGZvciB0aGlzIGJsb2JcIik7XG4gICAgfVxuICAgIGNvbnN0IG9iamVjdCA9IGF3YWl0IHRoaXMuc3RvcmUuZ2V0Qnl0ZXMoYmxvYktleSk7XG4gICAgaWYgKCFvYmplY3QpIHtcbiAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDA0LCBcImJsb2Jfbm90X2ZvdW5kXCIsIFwiYmxvYiBkb2VzIG5vdCBleGlzdFwiKTtcbiAgICB9XG4gICAgcmV0dXJuIG9iamVjdDtcbiAgfVxuXG4gIGFzeW5jIHB1dEpzb248VD4oa2V5OiBzdHJpbmcsIHZhbHVlOiBUKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgYXdhaXQgdGhpcy5zdG9yZS5wdXRKc29uKGtleSwgdmFsdWUpO1xuICB9XG5cbiAgYXN5bmMgZ2V0SnNvbjxUPihrZXk6IHN0cmluZyk6IFByb21pc2U8VCB8IG51bGw+IHtcbiAgICByZXR1cm4gdGhpcy5zdG9yZS5nZXRKc29uPFQ+KGtleSk7XG4gIH1cblxuICBhc3luYyBkZWxldGUoa2V5OiBzdHJpbmcpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLnN0b3JlLmRlbGV0ZShrZXkpO1xuICB9XG5cbiAgcHJpdmF0ZSBhc3luYyB2ZXJpZnlUb2tlbjxUPih0b2tlbjogc3RyaW5nLCBub3c6IG51bWJlcik6IFByb21pc2U8VD4ge1xuICAgIHRyeSB7XG4gICAgICByZXR1cm4gYXdhaXQgdmVyaWZ5U2hhcmluZ1BheWxvYWQ8VD4odGhpcy5zZWNyZXQsIHRva2VuLCBub3cpO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBjb25zdCBtZXNzYWdlID0gZXJyb3IgaW5zdGFuY2VvZiBFcnJvciA/IGVycm9yLm1lc3NhZ2UgOiBcImludmFsaWQgc2hhcmluZyB0b2tlblwiO1xuICAgICAgaWYgKG1lc3NhZ2UuaW5jbHVkZXMoXCJleHBpcmVkXCIpKSB7XG4gICAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAzLCBcImNhcGFiaWxpdHlfZXhwaXJlZFwiLCBtZXNzYWdlKTtcbiAgICAgIH1cbiAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAzLCBcImludmFsaWRfY2FwYWJpbGl0eVwiLCBtZXNzYWdlKTtcbiAgICB9XG4gIH1cbn1cclxuIiwgImltcG9ydCB7XG4gIEh0dHBFcnJvcixcbiAgdmFsaWRhdGVBbnlEZXZpY2VSdW50aW1lQXV0aG9yaXphdGlvbixcbiAgdmFsaWRhdGVBcHBlbmRBdXRob3JpemF0aW9uLFxuICB2YWxpZGF0ZUJvb3RzdHJhcEF1dGhvcml6YXRpb24sXG4gIHZhbGlkYXRlRGV2aWNlUnVudGltZUF1dGhvcml6YXRpb25Gb3JEZXZpY2UsXG4gIHZhbGlkYXRlS2V5UGFja2FnZVdyaXRlQXV0aG9yaXphdGlvbixcbiAgdmFsaWRhdGVTaGFyZWRTdGF0ZVdyaXRlQXV0aG9yaXphdGlvblxufSBmcm9tIFwiLi4vYXV0aC9jYXBhYmlsaXR5XCI7XG5pbXBvcnQgeyBzaWduU2hhcmluZ1BheWxvYWQgfSBmcm9tIFwiLi4vc3RvcmFnZS9zaGFyaW5nXCI7XG5pbXBvcnQgeyBTaGFyZWRTdGF0ZVNlcnZpY2UgfSBmcm9tIFwiLi4vc3RvcmFnZS9zaGFyZWQtc3RhdGVcIjtcbmltcG9ydCB7IFN0b3JhZ2VTZXJ2aWNlIH0gZnJvbSBcIi4uL3N0b3JhZ2Uvc2VydmljZVwiO1xuaW1wb3J0IHtcbiAgQ1VSUkVOVF9NT0RFTF9WRVJTSU9OLFxuICB0eXBlIEFwcGVuZEVudmVsb3BlUmVxdWVzdCxcbiAgdHlwZSBCb290c3RyYXBEZXZpY2VSZXF1ZXN0LFxuICB0eXBlIERlcGxveW1lbnRCdW5kbGUsXG4gIHR5cGUgRGV2aWNlUnVudGltZUF1dGgsXG4gIHR5cGUgRGV2aWNlU3RhdHVzRG9jdW1lbnQsXG4gIHR5cGUgSWRlbnRpdHlCdW5kbGUsXG4gIHR5cGUgS2V5UGFja2FnZVJlZnNEb2N1bWVudCxcbiAgdHlwZSBQcmVwYXJlQmxvYlVwbG9hZFJlcXVlc3Rcbn0gZnJvbSBcIi4uL3R5cGVzL2NvbnRyYWN0c1wiO1xuaW1wb3J0IHR5cGUgeyBFbnYgfSBmcm9tIFwiLi4vdHlwZXMvcnVudGltZVwiO1xuXG5mdW5jdGlvbiB2ZXJzaW9uZWRCb2R5KGJvZHk6IHVua25vd24pOiB1bmtub3duIHtcbiAgaWYgKCFib2R5IHx8IHR5cGVvZiBib2R5ICE9PSBcIm9iamVjdFwiIHx8IEFycmF5LmlzQXJyYXkoYm9keSkpIHtcbiAgICByZXR1cm4gYm9keTtcbiAgfVxuICBjb25zdCByZWNvcmQgPSBib2R5IGFzIFJlY29yZDxzdHJpbmcsIHVua25vd24+O1xuICBpZiAocmVjb3JkLnZlcnNpb24gIT09IHVuZGVmaW5lZCkge1xuICAgIHJldHVybiBib2R5O1xuICB9XG4gIHJldHVybiB7XG4gICAgdmVyc2lvbjogQ1VSUkVOVF9NT0RFTF9WRVJTSU9OLFxuICAgIC4uLnJlY29yZFxuICB9O1xufVxuXG5mdW5jdGlvbiBqc29uUmVzcG9uc2UoYm9keTogdW5rbm93biwgc3RhdHVzID0gMjAwKTogUmVzcG9uc2Uge1xuICByZXR1cm4gbmV3IFJlc3BvbnNlKEpTT04uc3RyaW5naWZ5KHZlcnNpb25lZEJvZHkoYm9keSkpLCB7XG4gICAgc3RhdHVzLFxuICAgIGhlYWRlcnM6IHtcbiAgICAgIFwiY29udGVudC10eXBlXCI6IFwiYXBwbGljYXRpb24vanNvblwiXG4gICAgfVxuICB9KTtcbn1cblxuY2xhc3MgUjJKc29uQmxvYlN0b3JlIHtcbiAgcHJpdmF0ZSByZWFkb25seSBidWNrZXQ6IEVudltcIlRBUENIQVRfU1RPUkFHRVwiXTtcblxuICBjb25zdHJ1Y3RvcihidWNrZXQ6IEVudltcIlRBUENIQVRfU1RPUkFHRVwiXSkge1xuICAgIHRoaXMuYnVja2V0ID0gYnVja2V0O1xuICB9XG5cbiAgYXN5bmMgcHV0SnNvbjxUPihrZXk6IHN0cmluZywgdmFsdWU6IFQpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLmJ1Y2tldC5wdXQoa2V5LCBKU09OLnN0cmluZ2lmeSh2YWx1ZSkpO1xuICB9XG5cbiAgYXN5bmMgZ2V0SnNvbjxUPihrZXk6IHN0cmluZyk6IFByb21pc2U8VCB8IG51bGw+IHtcbiAgICBjb25zdCBvYmplY3QgPSBhd2FpdCB0aGlzLmJ1Y2tldC5nZXQoa2V5KTtcbiAgICBpZiAoIW9iamVjdCkge1xuICAgICAgcmV0dXJuIG51bGw7XG4gICAgfVxuICAgIHJldHVybiBhd2FpdCBvYmplY3QuanNvbjxUPigpO1xuICB9XG5cbiAgYXN5bmMgcHV0Qnl0ZXMoa2V5OiBzdHJpbmcsIHZhbHVlOiBBcnJheUJ1ZmZlciB8IFVpbnQ4QXJyYXksIG1ldGFkYXRhPzogUmVjb3JkPHN0cmluZywgc3RyaW5nPik6IFByb21pc2U8dm9pZD4ge1xuICAgIGF3YWl0IHRoaXMuYnVja2V0LnB1dChrZXksIHZhbHVlLCBtZXRhZGF0YSA/IHsgaHR0cE1ldGFkYXRhOiBtZXRhZGF0YSB9IDogdW5kZWZpbmVkKTtcbiAgfVxuXG4gIGFzeW5jIGdldEJ5dGVzKGtleTogc3RyaW5nKTogUHJvbWlzZTxBcnJheUJ1ZmZlciB8IG51bGw+IHtcbiAgICBjb25zdCBvYmplY3QgPSBhd2FpdCB0aGlzLmJ1Y2tldC5nZXQoa2V5KTtcbiAgICBpZiAoIW9iamVjdCkge1xuICAgICAgcmV0dXJuIG51bGw7XG4gICAgfVxuICAgIHJldHVybiBvYmplY3QuYXJyYXlCdWZmZXIoKTtcbiAgfVxuXG4gIGFzeW5jIGRlbGV0ZShrZXk6IHN0cmluZyk6IFByb21pc2U8dm9pZD4ge1xuICAgIGF3YWl0IHRoaXMuYnVja2V0LmRlbGV0ZShrZXkpO1xuICB9XG59XG5cbmZ1bmN0aW9uIGJhc2VVcmwocmVxdWVzdDogUmVxdWVzdCwgZW52OiBFbnYpOiBzdHJpbmcge1xuICByZXR1cm4gZW52LlBVQkxJQ19CQVNFX1VSTD8udHJpbSgpLnJlcGxhY2UoL1xcLyskLywgXCJcIikgPz8gbmV3IFVSTChyZXF1ZXN0LnVybCkub3JpZ2luO1xufVxuXG5mdW5jdGlvbiBzaGFyZWRTdGF0ZVNlY3JldChlbnY6IEVudik6IHN0cmluZyB7XG4gIHJldHVybiBlbnYuU0hBUklOR19UT0tFTl9TRUNSRVQgPz8gXCJyZXBsYWNlLW1lXCI7XG59XG5cbmZ1bmN0aW9uIGJvb3RzdHJhcFNlY3JldChlbnY6IEVudik6IHN0cmluZyB7XG4gIHJldHVybiBlbnYuQk9PVFNUUkFQX1RPS0VOX1NFQ1JFVCA/PyBlbnYuU0hBUklOR19UT0tFTl9TRUNSRVQgPz8gXCJyZXBsYWNlLW1lXCI7XG59XG5cbmZ1bmN0aW9uIHJ1bnRpbWVTY29wZXMoKTogRGV2aWNlUnVudGltZUF1dGhbXCJzY29wZXNcIl0ge1xuICByZXR1cm4gW1xuICAgIFwiaW5ib3hfcmVhZFwiLFxuICAgIFwiaW5ib3hfYWNrXCIsXG4gICAgXCJpbmJveF9zdWJzY3JpYmVcIixcbiAgICBcInN0b3JhZ2VfcHJlcGFyZV91cGxvYWRcIixcbiAgICBcInNoYXJlZF9zdGF0ZV93cml0ZVwiLFxuICAgIFwia2V5cGFja2FnZV93cml0ZVwiXG4gIF07XG59XG5cbmFzeW5jIGZ1bmN0aW9uIGlzc3VlRGV2aWNlUnVudGltZUF1dGgoZW52OiBFbnYsIHVzZXJJZDogc3RyaW5nLCBkZXZpY2VJZDogc3RyaW5nLCBub3c6IG51bWJlcik6IFByb21pc2U8RGV2aWNlUnVudGltZUF1dGg+IHtcbiAgY29uc3QgZXhwaXJlc0F0ID0gbm93ICsgMjQgKiA2MCAqIDYwICogMTAwMDtcbiAgY29uc3Qgc2NvcGVzID0gcnVudGltZVNjb3BlcygpO1xuICBjb25zdCB0b2tlbiA9IGF3YWl0IHNpZ25TaGFyaW5nUGF5bG9hZChzaGFyZWRTdGF0ZVNlY3JldChlbnYpLCB7XG4gICAgdmVyc2lvbjogQ1VSUkVOVF9NT0RFTF9WRVJTSU9OLFxuICAgIHNlcnZpY2U6IFwiZGV2aWNlX3J1bnRpbWVcIixcbiAgICB1c2VySWQsXG4gICAgZGV2aWNlSWQsXG4gICAgc2NvcGVzLFxuICAgIGV4cGlyZXNBdFxuICB9KTtcbiAgcmV0dXJuIHtcbiAgICBzY2hlbWU6IFwiYmVhcmVyXCIsXG4gICAgdG9rZW4sXG4gICAgZXhwaXJlc0F0LFxuICAgIHVzZXJJZCxcbiAgICBkZXZpY2VJZCxcbiAgICBzY29wZXNcbiAgfTtcbn1cblxuZnVuY3Rpb24gcHVibGljRGVwbG95bWVudEJ1bmRsZShyZXF1ZXN0OiBSZXF1ZXN0LCBlbnY6IEVudik6IERlcGxveW1lbnRCdW5kbGUge1xuICByZXR1cm4ge1xuICAgIHZlcnNpb246IENVUlJFTlRfTU9ERUxfVkVSU0lPTixcbiAgICByZWdpb246IGVudi5ERVBMT1lNRU5UX1JFR0lPTiA/PyBcImxvY2FsXCIsXG4gICAgaW5ib3hIdHRwRW5kcG9pbnQ6IGJhc2VVcmwocmVxdWVzdCwgZW52KSxcbiAgICBpbmJveFdlYnNvY2tldEVuZHBvaW50OiBgJHtiYXNlVXJsKHJlcXVlc3QsIGVudikucmVwbGFjZSgvXmh0dHAvaSwgXCJ3c1wiKX0vdjEvaW5ib3gve2RldmljZUlkfS9zdWJzY3JpYmVgLFxuICAgIHN0b3JhZ2VCYXNlSW5mbzoge1xuICAgICAgYmFzZVVybDogYmFzZVVybChyZXF1ZXN0LCBlbnYpLFxuICAgICAgYnVja2V0SGludDogXCJ0YXBjaGF0LXN0b3JhZ2VcIlxuICAgIH0sXG4gICAgcnVudGltZUNvbmZpZzoge1xuICAgICAgc3VwcG9ydGVkUmVhbHRpbWVLaW5kczogW1wid2Vic29ja2V0XCJdLFxuICAgICAgaWRlbnRpdHlCdW5kbGVSZWY6IGAke2Jhc2VVcmwocmVxdWVzdCwgZW52KX0vdjEvc2hhcmVkLXN0YXRlL3t1c2VySWR9L2lkZW50aXR5LWJ1bmRsZWAsXG4gICAgICBkZXZpY2VTdGF0dXNSZWY6IGAke2Jhc2VVcmwocmVxdWVzdCwgZW52KX0vdjEvc2hhcmVkLXN0YXRlL3t1c2VySWR9L2RldmljZS1zdGF0dXNgLFxuICAgICAga2V5cGFja2FnZVJlZkJhc2U6IGAke2Jhc2VVcmwocmVxdWVzdCwgZW52KX0vdjEvc2hhcmVkLXN0YXRlL2tleXBhY2thZ2VzYCxcbiAgICAgIG1heElubGluZUJ5dGVzOiBOdW1iZXIoZW52Lk1BWF9JTkxJTkVfQllURVMgPz8gXCI0MDk2XCIpLFxuICAgICAgZmVhdHVyZXM6IFtcImdlbmVyaWNfc3luY1wiLCBcImF0dGFjaG1lbnRfdjFcIl1cbiAgICB9XG4gIH07XG59XG5cbmFzeW5jIGZ1bmN0aW9uIGF1dGhvcml6ZVNoYXJlZFN0YXRlV3JpdGUoXG4gIHJlcXVlc3Q6IFJlcXVlc3QsXG4gIGVudjogRW52LFxuICB1c2VySWQ6IHN0cmluZyxcbiAgb2JqZWN0S2luZDogXCJpZGVudGl0eV9idW5kbGVcIiB8IFwiZGV2aWNlX3N0YXR1c1wiLFxuICBub3c6IG51bWJlclxuKTogUHJvbWlzZTx2b2lkPiB7XG4gIHRyeSB7XG4gICAgY29uc3QgYXV0aCA9IGF3YWl0IHZhbGlkYXRlQW55RGV2aWNlUnVudGltZUF1dGhvcml6YXRpb24ocmVxdWVzdCwgc2hhcmVkU3RhdGVTZWNyZXQoZW52KSwgXCJzaGFyZWRfc3RhdGVfd3JpdGVcIiwgbm93KTtcbiAgICBpZiAoYXV0aC51c2VySWQgIT09IHVzZXJJZCkge1xuICAgICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwiZGV2aWNlIHJ1bnRpbWUgdG9rZW4gc2NvcGUgZG9lcyBub3QgbWF0Y2ggcmVxdWVzdCBwYXRoXCIpO1xuICAgIH1cbiAgICByZXR1cm47XG4gIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgaWYgKCEoZXJyb3IgaW5zdGFuY2VvZiBIdHRwRXJyb3IpIHx8IGVycm9yLmNvZGUgPT09IFwiY2FwYWJpbGl0eV9leHBpcmVkXCIpIHtcbiAgICAgIHRocm93IGVycm9yO1xuICAgIH1cbiAgfVxuICBhd2FpdCB2YWxpZGF0ZVNoYXJlZFN0YXRlV3JpdGVBdXRob3JpemF0aW9uKHJlcXVlc3QsIHNoYXJlZFN0YXRlU2VjcmV0KGVudiksIHVzZXJJZCwgXCJcIiwgb2JqZWN0S2luZCwgbm93KTtcbn1cblxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGhhbmRsZVJlcXVlc3QocmVxdWVzdDogUmVxdWVzdCwgZW52OiBFbnYpOiBQcm9taXNlPFJlc3BvbnNlPiB7XG4gIGNvbnN0IHVybCA9IG5ldyBVUkwocmVxdWVzdC51cmwpO1xuICBjb25zdCBzdG9yZSA9IG5ldyBTdG9yYWdlU2VydmljZShcbiAgICBuZXcgUjJKc29uQmxvYlN0b3JlKGVudi5UQVBDSEFUX1NUT1JBR0UpLFxuICAgIGJhc2VVcmwocmVxdWVzdCwgZW52KSxcbiAgICBzaGFyZWRTdGF0ZVNlY3JldChlbnYpXG4gICk7XG4gIGNvbnN0IHNoYXJlZFN0YXRlID0gbmV3IFNoYXJlZFN0YXRlU2VydmljZShuZXcgUjJKc29uQmxvYlN0b3JlKGVudi5UQVBDSEFUX1NUT1JBR0UpLCBiYXNlVXJsKHJlcXVlc3QsIGVudikpO1xuICBjb25zdCBub3cgPSBEYXRlLm5vdygpO1xuXG4gIHRyeSB7XG4gICAgaWYgKHJlcXVlc3QubWV0aG9kID09PSBcIkdFVFwiICYmIHVybC5wYXRobmFtZSA9PT0gXCIvdjEvZGVwbG95bWVudC1idW5kbGVcIikge1xuICAgICAgcmV0dXJuIGpzb25SZXNwb25zZShwdWJsaWNEZXBsb3ltZW50QnVuZGxlKHJlcXVlc3QsIGVudikpO1xuICAgIH1cblxuICAgIGlmIChyZXF1ZXN0Lm1ldGhvZCA9PT0gXCJQT1NUXCIgJiYgdXJsLnBhdGhuYW1lID09PSBcIi92MS9ib290c3RyYXAvZGV2aWNlXCIpIHtcbiAgICAgIGNvbnN0IGJvZHkgPSAoYXdhaXQgcmVxdWVzdC5qc29uKCkpIGFzIEJvb3RzdHJhcERldmljZVJlcXVlc3Q7XG4gICAgICBpZiAoYm9keS52ZXJzaW9uICE9PSBDVVJSRU5UX01PREVMX1ZFUlNJT04pIHtcbiAgICAgICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDAsIFwidW5zdXBwb3J0ZWRfdmVyc2lvblwiLCBcImJvb3RzdHJhcCByZXF1ZXN0IHZlcnNpb24gaXMgbm90IHN1cHBvcnRlZFwiKTtcbiAgICAgIH1cbiAgICAgIGF3YWl0IHZhbGlkYXRlQm9vdHN0cmFwQXV0aG9yaXphdGlvbihyZXF1ZXN0LCBib290c3RyYXBTZWNyZXQoZW52KSwgYm9keS51c2VySWQsIGJvZHkuZGV2aWNlSWQsIG5vdyk7XG4gICAgICBjb25zdCBidW5kbGU6IERlcGxveW1lbnRCdW5kbGUgPSB7XG4gICAgICAgIC4uLnB1YmxpY0RlcGxveW1lbnRCdW5kbGUocmVxdWVzdCwgZW52KSxcbiAgICAgICAgZGV2aWNlUnVudGltZUF1dGg6IGF3YWl0IGlzc3VlRGV2aWNlUnVudGltZUF1dGgoZW52LCBib2R5LnVzZXJJZCwgYm9keS5kZXZpY2VJZCwgbm93KSxcbiAgICAgICAgZXhwZWN0ZWRVc2VySWQ6IGJvZHkudXNlcklkLFxuICAgICAgICBleHBlY3RlZERldmljZUlkOiBib2R5LmRldmljZUlkXG4gICAgICB9O1xuICAgICAgcmV0dXJuIGpzb25SZXNwb25zZShidW5kbGUpO1xuICAgIH1cblxuICAgIGNvbnN0IGluYm94TWF0Y2ggPSB1cmwucGF0aG5hbWUubWF0Y2goL15cXC92MVxcL2luYm94XFwvKFteL10rKVxcLyhtZXNzYWdlc3xhY2t8aGVhZHxzdWJzY3JpYmUpJC8pO1xuICAgIGlmIChpbmJveE1hdGNoKSB7XG4gICAgICBjb25zdCBkZXZpY2VJZCA9IGRlY29kZVVSSUNvbXBvbmVudChpbmJveE1hdGNoWzFdKTtcbiAgICAgIGNvbnN0IG9wZXJhdGlvbiA9IGluYm94TWF0Y2hbMl07XG4gICAgICBjb25zdCBvYmplY3RJZCA9IGVudi5JTkJPWC5pZEZyb21OYW1lKGRldmljZUlkKTtcbiAgICAgIGNvbnN0IHN0dWIgPSBlbnYuSU5CT1guZ2V0KG9iamVjdElkKTtcblxuICAgICAgaWYgKHJlcXVlc3QubWV0aG9kID09PSBcIlBPU1RcIiAmJiBvcGVyYXRpb24gPT09IFwibWVzc2FnZXNcIikge1xuICAgICAgICBjb25zdCBib2R5ID0gKGF3YWl0IHJlcXVlc3QuY2xvbmUoKS5qc29uKCkpIGFzIEFwcGVuZEVudmVsb3BlUmVxdWVzdDtcbiAgICAgICAgdmFsaWRhdGVBcHBlbmRBdXRob3JpemF0aW9uKHJlcXVlc3QsIGRldmljZUlkLCBib2R5LCBub3cpO1xuICAgICAgfSBlbHNlIGlmIChyZXF1ZXN0Lm1ldGhvZCA9PT0gXCJHRVRcIiAmJiAob3BlcmF0aW9uID09PSBcIm1lc3NhZ2VzXCIgfHwgb3BlcmF0aW9uID09PSBcImhlYWRcIikpIHtcbiAgICAgICAgYXdhaXQgdmFsaWRhdGVEZXZpY2VSdW50aW1lQXV0aG9yaXphdGlvbkZvckRldmljZShyZXF1ZXN0LCBzaGFyZWRTdGF0ZVNlY3JldChlbnYpLCBkZXZpY2VJZCwgXCJpbmJveF9yZWFkXCIsIG5vdyk7XG4gICAgICB9IGVsc2UgaWYgKHJlcXVlc3QubWV0aG9kID09PSBcIlBPU1RcIiAmJiBvcGVyYXRpb24gPT09IFwiYWNrXCIpIHtcbiAgICAgICAgYXdhaXQgdmFsaWRhdGVEZXZpY2VSdW50aW1lQXV0aG9yaXphdGlvbkZvckRldmljZShyZXF1ZXN0LCBzaGFyZWRTdGF0ZVNlY3JldChlbnYpLCBkZXZpY2VJZCwgXCJpbmJveF9hY2tcIiwgbm93KTtcbiAgICAgIH0gZWxzZSBpZiAob3BlcmF0aW9uID09PSBcInN1YnNjcmliZVwiKSB7XG4gICAgICAgIGF3YWl0IHZhbGlkYXRlRGV2aWNlUnVudGltZUF1dGhvcml6YXRpb25Gb3JEZXZpY2UocmVxdWVzdCwgc2hhcmVkU3RhdGVTZWNyZXQoZW52KSwgZGV2aWNlSWQsIFwiaW5ib3hfc3Vic2NyaWJlXCIsIG5vdyk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBzdHViLmZldGNoKHJlcXVlc3QpO1xuICAgIH1cblxuICAgIGNvbnN0IGlkZW50aXR5QnVuZGxlTWF0Y2ggPSB1cmwucGF0aG5hbWUubWF0Y2goL15cXC92MVxcL3NoYXJlZC1zdGF0ZVxcLyhbXi9dKylcXC9pZGVudGl0eS1idW5kbGUkLyk7XG4gICAgaWYgKGlkZW50aXR5QnVuZGxlTWF0Y2gpIHtcbiAgICAgIGNvbnN0IHVzZXJJZCA9IGRlY29kZVVSSUNvbXBvbmVudChpZGVudGl0eUJ1bmRsZU1hdGNoWzFdKTtcbiAgICAgIGlmIChyZXF1ZXN0Lm1ldGhvZCA9PT0gXCJHRVRcIikge1xuICAgICAgICBjb25zdCBidW5kbGUgPSBhd2FpdCBzaGFyZWRTdGF0ZS5nZXRJZGVudGl0eUJ1bmRsZSh1c2VySWQpO1xuICAgICAgICBpZiAoIWJ1bmRsZSkge1xuICAgICAgICAgIHJldHVybiBqc29uUmVzcG9uc2UoeyBlcnJvcjogXCJub3RfZm91bmRcIiwgbWVzc2FnZTogXCJpZGVudGl0eSBidW5kbGUgbm90IGZvdW5kXCIgfSwgNDA0KTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4ganNvblJlc3BvbnNlKGJ1bmRsZSk7XG4gICAgICB9XG4gICAgICBpZiAocmVxdWVzdC5tZXRob2QgPT09IFwiUFVUXCIpIHtcbiAgICAgICAgYXdhaXQgYXV0aG9yaXplU2hhcmVkU3RhdGVXcml0ZShyZXF1ZXN0LCBlbnYsIHVzZXJJZCwgXCJpZGVudGl0eV9idW5kbGVcIiwgbm93KTtcbiAgICAgICAgY29uc3QgYm9keSA9IChhd2FpdCByZXF1ZXN0Lmpzb24oKSkgYXMgSWRlbnRpdHlCdW5kbGU7XG4gICAgICAgIGF3YWl0IHNoYXJlZFN0YXRlLnB1dElkZW50aXR5QnVuZGxlKHVzZXJJZCwgYm9keSk7XG4gICAgICAgIGNvbnN0IHNhdmVkID0gYXdhaXQgc2hhcmVkU3RhdGUuZ2V0SWRlbnRpdHlCdW5kbGUodXNlcklkKTtcbiAgICAgICAgcmV0dXJuIGpzb25SZXNwb25zZShzYXZlZCk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgY29uc3QgZGV2aWNlU3RhdHVzTWF0Y2ggPSB1cmwucGF0aG5hbWUubWF0Y2goL15cXC92MVxcL3NoYXJlZC1zdGF0ZVxcLyhbXi9dKylcXC9kZXZpY2Utc3RhdHVzJC8pO1xuICAgIGlmIChkZXZpY2VTdGF0dXNNYXRjaCkge1xuICAgICAgY29uc3QgdXNlcklkID0gZGVjb2RlVVJJQ29tcG9uZW50KGRldmljZVN0YXR1c01hdGNoWzFdKTtcbiAgICAgIGlmIChyZXF1ZXN0Lm1ldGhvZCA9PT0gXCJHRVRcIikge1xuICAgICAgICBjb25zdCBkb2N1bWVudCA9IGF3YWl0IHNoYXJlZFN0YXRlLmdldERldmljZVN0YXR1cyh1c2VySWQpO1xuICAgICAgICBpZiAoIWRvY3VtZW50KSB7XG4gICAgICAgICAgcmV0dXJuIGpzb25SZXNwb25zZSh7IGVycm9yOiBcIm5vdF9mb3VuZFwiLCBtZXNzYWdlOiBcImRldmljZSBzdGF0dXMgbm90IGZvdW5kXCIgfSwgNDA0KTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4ganNvblJlc3BvbnNlKGRvY3VtZW50KTtcbiAgICAgIH1cbiAgICAgIGlmIChyZXF1ZXN0Lm1ldGhvZCA9PT0gXCJQVVRcIikge1xuICAgICAgICBhd2FpdCBhdXRob3JpemVTaGFyZWRTdGF0ZVdyaXRlKHJlcXVlc3QsIGVudiwgdXNlcklkLCBcImRldmljZV9zdGF0dXNcIiwgbm93KTtcbiAgICAgICAgY29uc3QgYm9keSA9IChhd2FpdCByZXF1ZXN0Lmpzb24oKSkgYXMgRGV2aWNlU3RhdHVzRG9jdW1lbnQ7XG4gICAgICAgIGF3YWl0IHNoYXJlZFN0YXRlLnB1dERldmljZVN0YXR1cyh1c2VySWQsIGJvZHkpO1xuICAgICAgICBjb25zdCBzYXZlZCA9IGF3YWl0IHNoYXJlZFN0YXRlLmdldERldmljZVN0YXR1cyh1c2VySWQpO1xuICAgICAgICByZXR1cm4ganNvblJlc3BvbnNlKHNhdmVkKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBjb25zdCBkZXZpY2VMaXN0TWF0Y2ggPSB1cmwucGF0aG5hbWUubWF0Y2goL15cXC92MVxcL3NoYXJlZC1zdGF0ZVxcLyhbXi9dKylcXC9kZXZpY2UtbGlzdCQvKTtcbiAgICBpZiAoZGV2aWNlTGlzdE1hdGNoICYmIHJlcXVlc3QubWV0aG9kID09PSBcIkdFVFwiKSB7XG4gICAgICBjb25zdCB1c2VySWQgPSBkZWNvZGVVUklDb21wb25lbnQoZGV2aWNlTGlzdE1hdGNoWzFdKTtcbiAgICAgIGNvbnN0IGRvY3VtZW50ID0gYXdhaXQgc2hhcmVkU3RhdGUuZ2V0RGV2aWNlTGlzdCh1c2VySWQpO1xuICAgICAgaWYgKCFkb2N1bWVudCkge1xuICAgICAgICByZXR1cm4ganNvblJlc3BvbnNlKHsgZXJyb3I6IFwibm90X2ZvdW5kXCIsIG1lc3NhZ2U6IFwiZGV2aWNlIGxpc3Qgbm90IGZvdW5kXCIgfSwgNDA0KTtcbiAgICAgIH1cbiAgICAgIHJldHVybiBqc29uUmVzcG9uc2UoZG9jdW1lbnQpO1xuICAgIH1cblxuICAgIGNvbnN0IGtleVBhY2thZ2VSZWZzTWF0Y2ggPSB1cmwucGF0aG5hbWUubWF0Y2goL15cXC92MVxcL3NoYXJlZC1zdGF0ZVxcL2tleXBhY2thZ2VzXFwvKFteL10rKVxcLyhbXi9dKykkLyk7XG4gICAgaWYgKGtleVBhY2thZ2VSZWZzTWF0Y2gpIHtcbiAgICAgIGNvbnN0IHVzZXJJZCA9IGRlY29kZVVSSUNvbXBvbmVudChrZXlQYWNrYWdlUmVmc01hdGNoWzFdKTtcbiAgICAgIGNvbnN0IGRldmljZUlkID0gZGVjb2RlVVJJQ29tcG9uZW50KGtleVBhY2thZ2VSZWZzTWF0Y2hbMl0pO1xuICAgICAgaWYgKHJlcXVlc3QubWV0aG9kID09PSBcIkdFVFwiKSB7XG4gICAgICAgIGNvbnN0IGRvY3VtZW50ID0gYXdhaXQgc2hhcmVkU3RhdGUuZ2V0S2V5UGFja2FnZVJlZnModXNlcklkLCBkZXZpY2VJZCk7XG4gICAgICAgIGlmICghZG9jdW1lbnQpIHtcbiAgICAgICAgICByZXR1cm4ganNvblJlc3BvbnNlKHsgZXJyb3I6IFwibm90X2ZvdW5kXCIsIG1lc3NhZ2U6IFwia2V5cGFja2FnZSByZWZzIG5vdCBmb3VuZFwiIH0sIDQwNCk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIGpzb25SZXNwb25zZShkb2N1bWVudCk7XG4gICAgICB9XG4gICAgICBpZiAocmVxdWVzdC5tZXRob2QgPT09IFwiUFVUXCIpIHtcbiAgICAgICAgYXdhaXQgdmFsaWRhdGVLZXlQYWNrYWdlV3JpdGVBdXRob3JpemF0aW9uKHJlcXVlc3QsIHNoYXJlZFN0YXRlU2VjcmV0KGVudiksIHVzZXJJZCwgZGV2aWNlSWQsIHVuZGVmaW5lZCwgbm93KTtcbiAgICAgICAgY29uc3QgYm9keSA9IChhd2FpdCByZXF1ZXN0Lmpzb24oKSkgYXMgS2V5UGFja2FnZVJlZnNEb2N1bWVudDtcbiAgICAgICAgYXdhaXQgc2hhcmVkU3RhdGUucHV0S2V5UGFja2FnZVJlZnModXNlcklkLCBkZXZpY2VJZCwgYm9keSk7XG4gICAgICAgIGNvbnN0IHNhdmVkID0gYXdhaXQgc2hhcmVkU3RhdGUuZ2V0S2V5UGFja2FnZVJlZnModXNlcklkLCBkZXZpY2VJZCk7XG4gICAgICAgIHJldHVybiBqc29uUmVzcG9uc2Uoc2F2ZWQpO1xuICAgICAgfVxuICAgIH1cblxuICAgIGNvbnN0IGtleVBhY2thZ2VPYmplY3RNYXRjaCA9IHVybC5wYXRobmFtZS5tYXRjaCgvXlxcL3YxXFwvc2hhcmVkLXN0YXRlXFwva2V5cGFja2FnZXNcXC8oW14vXSspXFwvKFteL10rKVxcLyhbXi9dKykkLyk7XG4gICAgaWYgKGtleVBhY2thZ2VPYmplY3RNYXRjaCkge1xuICAgICAgY29uc3QgdXNlcklkID0gZGVjb2RlVVJJQ29tcG9uZW50KGtleVBhY2thZ2VPYmplY3RNYXRjaFsxXSk7XG4gICAgICBjb25zdCBkZXZpY2VJZCA9IGRlY29kZVVSSUNvbXBvbmVudChrZXlQYWNrYWdlT2JqZWN0TWF0Y2hbMl0pO1xuICAgICAgY29uc3Qga2V5UGFja2FnZUlkID0gZGVjb2RlVVJJQ29tcG9uZW50KGtleVBhY2thZ2VPYmplY3RNYXRjaFszXSk7XG4gICAgICBpZiAocmVxdWVzdC5tZXRob2QgPT09IFwiR0VUXCIpIHtcbiAgICAgICAgY29uc3QgcGF5bG9hZCA9IGF3YWl0IHNoYXJlZFN0YXRlLmdldEtleVBhY2thZ2VPYmplY3QodXNlcklkLCBkZXZpY2VJZCwga2V5UGFja2FnZUlkKTtcbiAgICAgICAgaWYgKCFwYXlsb2FkKSB7XG4gICAgICAgICAgcmV0dXJuIGpzb25SZXNwb25zZSh7IGVycm9yOiBcIm5vdF9mb3VuZFwiLCBtZXNzYWdlOiBcImtleXBhY2thZ2Ugbm90IGZvdW5kXCIgfSwgNDA0KTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gbmV3IFJlc3BvbnNlKHBheWxvYWQsIHtcbiAgICAgICAgICBzdGF0dXM6IDIwMCxcbiAgICAgICAgICBoZWFkZXJzOiB7XG4gICAgICAgICAgICBcImNvbnRlbnQtdHlwZVwiOiBcImFwcGxpY2F0aW9uL29jdGV0LXN0cmVhbVwiXG4gICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICAgIGlmIChyZXF1ZXN0Lm1ldGhvZCA9PT0gXCJQVVRcIikge1xuICAgICAgICBhd2FpdCB2YWxpZGF0ZUtleVBhY2thZ2VXcml0ZUF1dGhvcml6YXRpb24ocmVxdWVzdCwgc2hhcmVkU3RhdGVTZWNyZXQoZW52KSwgdXNlcklkLCBkZXZpY2VJZCwga2V5UGFja2FnZUlkLCBub3cpO1xuICAgICAgICBhd2FpdCBzaGFyZWRTdGF0ZS5wdXRLZXlQYWNrYWdlT2JqZWN0KHVzZXJJZCwgZGV2aWNlSWQsIGtleVBhY2thZ2VJZCwgYXdhaXQgcmVxdWVzdC5hcnJheUJ1ZmZlcigpKTtcbiAgICAgICAgcmV0dXJuIG5ldyBSZXNwb25zZShudWxsLCB7IHN0YXR1czogMjA0IH0pO1xuICAgICAgfVxuICAgIH1cblxuICAgIGlmIChyZXF1ZXN0Lm1ldGhvZCA9PT0gXCJQT1NUXCIgJiYgdXJsLnBhdGhuYW1lID09PSBcIi92MS9zdG9yYWdlL3ByZXBhcmUtdXBsb2FkXCIpIHtcbiAgICAgIGNvbnN0IGF1dGggPSBhd2FpdCB2YWxpZGF0ZUFueURldmljZVJ1bnRpbWVBdXRob3JpemF0aW9uKHJlcXVlc3QsIHNoYXJlZFN0YXRlU2VjcmV0KGVudiksIFwic3RvcmFnZV9wcmVwYXJlX3VwbG9hZFwiLCBub3cpO1xuICAgICAgY29uc3QgYm9keSA9IChhd2FpdCByZXF1ZXN0Lmpzb24oKSkgYXMgUHJlcGFyZUJsb2JVcGxvYWRSZXF1ZXN0O1xuICAgICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgc3RvcmUucHJlcGFyZVVwbG9hZChib2R5LCB7IHVzZXJJZDogYXV0aC51c2VySWQsIGRldmljZUlkOiBhdXRoLmRldmljZUlkIH0sIG5vdyk7XG4gICAgICByZXR1cm4ganNvblJlc3BvbnNlKHJlc3VsdCk7XG4gICAgfVxuXG4gICAgY29uc3QgdXBsb2FkTWF0Y2ggPSB1cmwucGF0aG5hbWUubWF0Y2goL15cXC92MVxcL3N0b3JhZ2VcXC91cGxvYWRcXC8oLispJC8pO1xuICAgIGlmIChyZXF1ZXN0Lm1ldGhvZCA9PT0gXCJQVVRcIiAmJiB1cGxvYWRNYXRjaCkge1xuICAgICAgY29uc3QgYmxvYktleSA9IGRlY29kZVVSSUNvbXBvbmVudCh1cGxvYWRNYXRjaFsxXSk7XG4gICAgICBjb25zdCB0b2tlbiA9IHVybC5zZWFyY2hQYXJhbXMuZ2V0KFwidG9rZW5cIik7XG4gICAgICBpZiAoIXRva2VuKSB7XG4gICAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAxLCBcImludmFsaWRfY2FwYWJpbGl0eVwiLCBcIm1pc3NpbmcgdXBsb2FkIHRva2VuXCIpO1xuICAgICAgfVxuICAgICAgY29uc3QgY29udGVudFR5cGUgPSByZXF1ZXN0LmhlYWRlcnMuZ2V0KFwiY29udGVudC10eXBlXCIpID8/IFwiYXBwbGljYXRpb24vb2N0ZXQtc3RyZWFtXCI7XG4gICAgICBhd2FpdCBzdG9yZS51cGxvYWRCbG9iKGJsb2JLZXksIHRva2VuLCBhd2FpdCByZXF1ZXN0LmFycmF5QnVmZmVyKCksIHsgXCJjb250ZW50LXR5cGVcIjogY29udGVudFR5cGUgfSwgbm93KTtcbiAgICAgIHJldHVybiBuZXcgUmVzcG9uc2UobnVsbCwgeyBzdGF0dXM6IDIwNCB9KTtcbiAgICB9XG5cbiAgICBjb25zdCBibG9iTWF0Y2ggPSB1cmwucGF0aG5hbWUubWF0Y2goL15cXC92MVxcL3N0b3JhZ2VcXC9ibG9iXFwvKC4rKSQvKTtcbiAgICBpZiAocmVxdWVzdC5tZXRob2QgPT09IFwiR0VUXCIgJiYgYmxvYk1hdGNoKSB7XG4gICAgICBjb25zdCBibG9iS2V5ID0gZGVjb2RlVVJJQ29tcG9uZW50KGJsb2JNYXRjaFsxXSk7XG4gICAgICBjb25zdCB0b2tlbiA9IHVybC5zZWFyY2hQYXJhbXMuZ2V0KFwidG9rZW5cIik7XG4gICAgICBpZiAoIXRva2VuKSB7XG4gICAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAxLCBcImludmFsaWRfY2FwYWJpbGl0eVwiLCBcIm1pc3NpbmcgZG93bmxvYWQgdG9rZW5cIik7XG4gICAgICB9XG4gICAgICBjb25zdCBwYXlsb2FkID0gYXdhaXQgc3RvcmUuZmV0Y2hCbG9iKGJsb2JLZXksIHRva2VuLCBub3cpO1xuICAgICAgcmV0dXJuIG5ldyBSZXNwb25zZShwYXlsb2FkLCB7XG4gICAgICAgIHN0YXR1czogMjAwLFxuICAgICAgICBoZWFkZXJzOiB7XG4gICAgICAgICAgXCJjb250ZW50LXR5cGVcIjogXCJhcHBsaWNhdGlvbi9vY3RldC1zdHJlYW1cIlxuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICByZXR1cm4ganNvblJlc3BvbnNlKHsgZXJyb3I6IFwibm90X2ZvdW5kXCIsIG1lc3NhZ2U6IFwicm91dGUgbm90IGZvdW5kXCIgfSwgNDA0KTtcbiAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICBpZiAoZXJyb3IgaW5zdGFuY2VvZiBIdHRwRXJyb3IpIHtcbiAgICAgIHJldHVybiBqc29uUmVzcG9uc2UoeyBlcnJvcjogZXJyb3IuY29kZSwgbWVzc2FnZTogZXJyb3IubWVzc2FnZSB9LCBlcnJvci5zdGF0dXMpO1xuICAgIH1cbiAgICBjb25zdCBydW50aW1lRXJyb3IgPSBlcnJvciBhcyB7IG1lc3NhZ2U/OiBzdHJpbmcgfTtcbiAgICBjb25zdCBtZXNzYWdlID0gcnVudGltZUVycm9yLm1lc3NhZ2UgPz8gXCJpbnRlcm5hbCBlcnJvclwiO1xuICAgIHJldHVybiBqc29uUmVzcG9uc2UoeyBlcnJvcjogXCJ0ZW1wb3JhcnlfdW5hdmFpbGFibGVcIiwgbWVzc2FnZSB9LCA1MDApO1xuICB9XG59XHJcbiIsICJpbXBvcnQgeyBJbmJveER1cmFibGVPYmplY3QgfSBmcm9tIFwiLi9pbmJveC9kdXJhYmxlXCI7XG5pbXBvcnQgeyBoYW5kbGVSZXF1ZXN0IH0gZnJvbSBcIi4vcm91dGVzL2h0dHBcIjtcbmltcG9ydCB0eXBlIHsgRW52IH0gZnJvbSBcIi4vdHlwZXMvcnVudGltZVwiO1xuXG5leHBvcnQgeyBJbmJveER1cmFibGVPYmplY3QgfTtcblxuZXhwb3J0IGRlZmF1bHQge1xuICBhc3luYyBmZXRjaChyZXF1ZXN0OiBSZXF1ZXN0LCBlbnY6IEVudik6IFByb21pc2U8UmVzcG9uc2U+IHtcbiAgICByZXR1cm4gaGFuZGxlUmVxdWVzdChyZXF1ZXN0LCBlbnYpO1xuICB9XG59O1xyXG4iXSwKICAibWFwcGluZ3MiOiAiO0FBQU8sSUFBTSx3QkFBd0I7OztBQ0FyQyxJ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QUEsTUFDRixDQUFDO0FBQUEsSUFDSDtBQUVBLFdBQU9BLGNBQWEsRUFBRSxPQUFPLGFBQWEsU0FBUyxrQkFBa0IsR0FBRyxHQUFHO0FBQUEsRUFDN0UsU0FBUyxPQUFPO0FBQ2QsUUFBSSxpQkFBaUIsV0FBVztBQUM5QixhQUFPQSxjQUFhLEVBQUUsT0FBTyxNQUFNLE1BQU0sU0FBUyxNQUFNLFFBQVEsR0FBRyxNQUFNLE1BQU07QUFBQSxJQUNqRjtBQUNBLFVBQU0sZUFBZTtBQUNyQixVQUFNLFVBQVUsYUFBYSxXQUFXO0FBQ3hDLFdBQU9BLGNBQWEsRUFBRSxPQUFPLHlCQUF5QixRQUFRLEdBQUcsR0FBRztBQUFBLEVBQ3RFO0FBQ0Y7OztBQy9WQSxJQUFPLGdCQUFRO0FBQUEsRUFDYixNQUFNLE1BQU0sU0FBa0IsS0FBNkI7QUFDekQsV0FBTyxjQUFjLFNBQVMsR0FBRztBQUFBLEVBQ25DO0FBQ0Y7IiwKICAibmFtZXMiOiBbImJhc2VVcmwiLCAic2FuaXRpemVTZWdtZW50IiwgImJhc2VVcmwiLCAidmVyc2lvbmVkQm9keSIsICJqc29uUmVzcG9uc2UiLCAiUjJKc29uQmxvYlN0b3JlIl0KfQo=

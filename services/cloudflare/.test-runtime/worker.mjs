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
var APPEND_RESULT_PREFIX = "append-result:";
var RECORD_PREFIX = "record:";
var ALLOWLIST_KEY = "allowlist";
var MESSAGE_REQUEST_PREFIX = "message-request:";
var RATE_LIMIT_PREFIX = "rate-limit:";
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
    const existingResult = await this.state.get(`${APPEND_RESULT_PREFIX}${input.envelope.messageId}`);
    if (existingResult) {
      return existingResult;
    }
    await this.enforceRateLimit(input.envelope.senderUserId, now);
    const allowlist = await this.getAllowlist(now);
    if (allowlist.rejectedSenderUserIds.includes(input.envelope.senderUserId)) {
      const rejected = {
        accepted: true,
        seq: 0,
        deliveredTo: "rejected",
        queuedAsRequest: false
      };
      await this.state.put(`${APPEND_RESULT_PREFIX}${input.envelope.messageId}`, rejected);
      return rejected;
    }
    if (allowlist.allowedSenderUserIds.includes(input.envelope.senderUserId)) {
      const delivered = await this.deliverEnvelope(input, now);
      await this.state.put(`${APPEND_RESULT_PREFIX}${input.envelope.messageId}`, delivered);
      return delivered;
    }
    const request = await this.queueMessageRequest(input, now);
    await this.state.put(`${APPEND_RESULT_PREFIX}${input.envelope.messageId}`, request);
    return request;
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
        continue;
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
    if (input.ack.ackSeq < meta.ackedSeq) {
      throw new HttpError(409, "invalid_ack", "ack_seq must not move backwards");
    }
    const ackSeq = Math.max(meta.ackedSeq, input.ack.ackSeq);
    await this.state.put(META_KEY, { ...meta, ackedSeq: ackSeq });
    await this.state.setAlarm(Date.now());
    return { accepted: true, ackSeq };
  }
  async getHead() {
    const meta = await this.getMeta();
    return { headSeq: meta.headSeq };
  }
  async getAllowlist(now = Date.now()) {
    return await this.state.get(ALLOWLIST_KEY) ?? {
      version: "0.1",
      deviceId: this.deviceId,
      updatedAt: now,
      allowedSenderUserIds: [],
      rejectedSenderUserIds: []
    };
  }
  async replaceAllowlist(allowedSenderUserIds, rejectedSenderUserIds, now) {
    const document = {
      version: "0.1",
      deviceId: this.deviceId,
      updatedAt: now,
      allowedSenderUserIds: Array.from(new Set(allowedSenderUserIds)).sort(),
      rejectedSenderUserIds: Array.from(new Set(rejectedSenderUserIds.filter((userId) => !allowedSenderUserIds.includes(userId)))).sort()
    };
    await this.state.put(ALLOWLIST_KEY, document);
    return document;
  }
  async listMessageRequests() {
    const requests = await this.state.get(this.messageRequestIndexKey());
    if (!requests?.length) {
      return [];
    }
    const items = [];
    for (const senderUserId of requests) {
      const entry = await this.state.get(this.messageRequestKey(senderUserId));
      if (!entry) {
        continue;
      }
      items.push(this.toMessageRequestItem(entry));
    }
    items.sort((left, right) => left.firstSeenAt - right.firstSeenAt || left.senderUserId.localeCompare(right.senderUserId));
    return items;
  }
  async acceptMessageRequest(requestId, now) {
    const entry = await this.findMessageRequest(requestId);
    if (!entry) {
      throw new HttpError(404, "not_found", "message request not found");
    }
    const allowlist = await this.getAllowlist(now);
    await this.replaceAllowlist(
      [...allowlist.allowedSenderUserIds, entry.senderUserId],
      allowlist.rejectedSenderUserIds.filter((userId) => userId !== entry.senderUserId),
      now
    );
    let promotedCount = 0;
    for (const request of entry.pendingRequests) {
      const delivered = await this.deliverEnvelope(request, now);
      await this.state.put(`${APPEND_RESULT_PREFIX}${request.envelope.messageId}`, delivered);
      promotedCount += delivered.seq === void 0 ? 0 : 1;
    }
    await this.deleteMessageRequest(entry.senderUserId);
    return {
      accepted: true,
      requestId: entry.requestId,
      senderUserId: entry.senderUserId,
      promotedCount
    };
  }
  async rejectMessageRequest(requestId, now) {
    const entry = await this.findMessageRequest(requestId);
    if (!entry) {
      throw new HttpError(404, "not_found", "message request not found");
    }
    const allowlist = await this.getAllowlist(now);
    await this.replaceAllowlist(
      allowlist.allowedSenderUserIds.filter((userId) => userId !== entry.senderUserId),
      [...allowlist.rejectedSenderUserIds, entry.senderUserId],
      now
    );
    await this.deleteMessageRequest(entry.senderUserId);
    return {
      accepted: true,
      requestId: entry.requestId,
      senderUserId: entry.senderUserId,
      promotedCount: 0
    };
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
  async deliverEnvelope(input, now) {
    const meta = await this.getMeta();
    const existingSeq = await this.state.get(`${IDEMPOTENCY_PREFIX}${input.envelope.messageId}`);
    if (existingSeq !== void 0) {
      return { accepted: true, seq: existingSeq, deliveredTo: "inbox" };
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
    return { accepted: true, seq, deliveredTo: "inbox" };
  }
  async queueMessageRequest(input, now) {
    const senderUserId = input.envelope.senderUserId;
    const key = this.messageRequestKey(senderUserId);
    const requestId = this.requestIdForSender(senderUserId);
    const existing = await this.state.get(key);
    const entry = existing ?? {
      requestId,
      recipientDeviceId: this.deviceId,
      senderUserId,
      firstSeenAt: now,
      lastSeenAt: now,
      messageCount: 0,
      lastMessageId: input.envelope.messageId,
      lastConversationId: input.envelope.conversationId,
      pendingRequests: []
    };
    entry.lastSeenAt = now;
    entry.messageCount += 1;
    entry.lastMessageId = input.envelope.messageId;
    entry.lastConversationId = input.envelope.conversationId;
    entry.pendingRequests.push(input);
    await this.state.put(key, entry);
    await this.addMessageRequestIndex(senderUserId);
    return {
      accepted: true,
      seq: 0,
      deliveredTo: "message_request",
      queuedAsRequest: true,
      requestId
    };
  }
  async enforceRateLimit(senderUserId, now) {
    const meta = await this.getMeta();
    const minuteLimit = meta.rateLimitPerMinute;
    const hourLimit = meta.rateLimitPerHour;
    if (minuteLimit <= 0 && hourLimit <= 0) {
      return;
    }
    const key = `${RATE_LIMIT_PREFIX}${senderUserId}`;
    const minuteWindowStart = Math.floor(now / 6e4) * 6e4;
    const hourWindowStart = Math.floor(now / 36e5) * 36e5;
    const state = await this.state.get(key) ?? {
      minuteWindowStart,
      minuteCount: 0,
      hourWindowStart,
      hourCount: 0
    };
    if (state.minuteWindowStart !== minuteWindowStart) {
      state.minuteWindowStart = minuteWindowStart;
      state.minuteCount = 0;
    }
    if (state.hourWindowStart !== hourWindowStart) {
      state.hourWindowStart = hourWindowStart;
      state.hourCount = 0;
    }
    if (minuteLimit > 0 && state.minuteCount >= minuteLimit) {
      throw new HttpError(429, "rate_limited", "append rate limit exceeded for minute window");
    }
    if (hourLimit > 0 && state.hourCount >= hourLimit) {
      throw new HttpError(429, "rate_limited", "append rate limit exceeded for hour window");
    }
    state.minuteCount += 1;
    state.hourCount += 1;
    await this.state.put(key, state);
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
  requestIdForSender(senderUserId) {
    return `request:${senderUserId}`;
  }
  messageRequestKey(senderUserId) {
    return `${MESSAGE_REQUEST_PREFIX}${senderUserId}`;
  }
  messageRequestIndexKey() {
    return `${MESSAGE_REQUEST_PREFIX}index`;
  }
  async addMessageRequestIndex(senderUserId) {
    const index = await this.state.get(this.messageRequestIndexKey()) ?? [];
    if (!index.includes(senderUserId)) {
      index.push(senderUserId);
      index.sort();
      await this.state.put(this.messageRequestIndexKey(), index);
    }
  }
  async deleteMessageRequest(senderUserId) {
    await this.state.delete(this.messageRequestKey(senderUserId));
    const index = await this.state.get(this.messageRequestIndexKey()) ?? [];
    await this.state.put(
      this.messageRequestIndexKey(),
      index.filter((entry) => entry !== senderUserId)
    );
  }
  async findMessageRequest(requestId) {
    const requests = await this.listMessageRequests();
    const match = requests.find((request) => request.requestId === requestId);
    if (!match) {
      return null;
    }
    return await this.state.get(this.messageRequestKey(match.senderUserId)) ?? null;
  }
  toMessageRequestItem(entry) {
    return {
      requestId: entry.requestId,
      recipientDeviceId: entry.recipientDeviceId,
      senderUserId: entry.senderUserId,
      firstSeenAt: entry.firstSeenAt,
      lastSeenAt: entry.lastSeenAt,
      messageCount: entry.messageCount,
      lastMessageId: entry.lastMessageId,
      lastConversationId: entry.lastConversationId
    };
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
    maxInlineBytes: deps.maxInlineBytes,
    rateLimitPerMinute: deps.rateLimitPerMinute,
    rateLimitPerHour: deps.rateLimitPerHour
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
    if (url.pathname.endsWith("/message-requests") && request.method === "GET") {
      return jsonResponse({ requests: await service.listMessageRequests() });
    }
    const requestActionMatch = url.pathname.match(/\/message-requests\/([^/]+)\/(accept|reject)$/);
    if (requestActionMatch && request.method === "POST") {
      const requestId = decodeURIComponent(requestActionMatch[1]);
      const action = requestActionMatch[2];
      const result = action === "accept" ? await service.acceptMessageRequest(requestId, now) : await service.rejectMessageRequest(requestId, now);
      return jsonResponse(result);
    }
    if (url.pathname.endsWith("/allowlist") && request.method === "GET") {
      return jsonResponse(await service.getAllowlist(now));
    }
    if (url.pathname.endsWith("/allowlist") && request.method === "PUT") {
      const body = await request.json();
      const result = await service.replaceAllowlist(
        body.allowedSenderUserIds ?? [],
        body.rejectedSenderUserIds ?? [],
        now
      );
      return jsonResponse(result);
    }
    if (url.pathname.endsWith("/messages") && request.method === "POST") {
      const body = await request.json();
      const result = await service.appendEnvelope(body, now);
      return jsonResponse(result);
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
      rateLimitPerMinute: Number(this.envRef.RATE_LIMIT_PER_MINUTE ?? "60"),
      rateLimitPerHour: Number(this.envRef.RATE_LIMIT_PER_HOUR ?? "600"),
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
        maxInlineBytes: Number(this.envRef.MAX_INLINE_BYTES ?? "4096"),
        rateLimitPerMinute: Number(this.envRef.RATE_LIMIT_PER_MINUTE ?? "60"),
        rateLimitPerHour: Number(this.envRef.RATE_LIMIT_PER_HOUR ?? "600")
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
    "inbox_manage",
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
      features: ["generic_sync", "attachment_v1", "message_requests", "allowlist", "rate_limit"]
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
    const inboxMatch = url.pathname.match(/^\/v1\/inbox\/([^/]+)\/(messages|ack|head|subscribe|allowlist|message-requests(?:\/[^/]+\/(?:accept|reject))?)$/);
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
      } else if (operation === "allowlist" || operation === "message-requests" || operation.startsWith("message-requests/")) {
        await validateDeviceRuntimeAuthorizationForDevice(request, sharedStateSecret(env), deviceId, "inbox_manage", now);
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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsiLi4vc3JjL3R5cGVzL2NvbnRyYWN0cy50cyIsICIuLi9zcmMvc3RvcmFnZS9zaGFyaW5nLnRzIiwgIi4uL3NyYy9hdXRoL2NhcGFiaWxpdHkudHMiLCAiLi4vc3JjL2luYm94L3NlcnZpY2UudHMiLCAiLi4vc3JjL2luYm94L2R1cmFibGUudHMiLCAiLi4vc3JjL3N0b3JhZ2Uvc2hhcmVkLXN0YXRlLnRzIiwgIi4uL3NyYy9zdG9yYWdlL3NlcnZpY2UudHMiLCAiLi4vc3JjL3JvdXRlcy9odHRwLnRzIiwgIi4uL3NyYy9pbmRleC50cyJdLAogICJzb3VyY2VzQ29udGVudCI6IFsiZXhwb3J0IGNvbnN0IENVUlJFTlRfTU9ERUxfVkVSU0lPTiA9IFwiMC4xXCI7XG5cbmV4cG9ydCBpbnRlcmZhY2UgU2VuZGVyUHJvb2Yge1xuICB0eXBlOiBzdHJpbmc7XG4gIHZhbHVlOiBzdHJpbmc7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgU3RvcmFnZVJlZiB7XG4gIGtpbmQ6IHN0cmluZztcbiAgcmVmOiBzdHJpbmc7XG4gIHNpemVCeXRlczogbnVtYmVyO1xuICBtaW1lVHlwZTogc3RyaW5nO1xuICBleHBpcmVzQXQ/OiBudW1iZXI7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgV2FrZUhpbnQge1xuICBsYXRlc3RTZXFIaW50PzogbnVtYmVyO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIENhcGFiaWxpdHlDb25zdHJhaW50cyB7XG4gIG1heEJ5dGVzPzogbnVtYmVyO1xuICBtYXhPcHNQZXJNaW51dGU/OiBudW1iZXI7XG4gIG1heE9wc1BlckhvdXI/OiBudW1iZXI7XG59XG5cbmV4cG9ydCB0eXBlIE1lc3NhZ2VUeXBlID1cbiAgfCBcIm1sc19hcHBsaWNhdGlvblwiXG4gIHwgXCJtbHNfY29tbWl0XCJcbiAgfCBcIm1sc193ZWxjb21lXCJcbiAgfCBcImNvbnRyb2xfZGV2aWNlX21lbWJlcnNoaXBfY2hhbmdlZFwiXG4gIHwgXCJjb250cm9sX2lkZW50aXR5X3N0YXRlX3VwZGF0ZWRcIlxuICB8IFwiY29udHJvbF9jb252ZXJzYXRpb25fbmVlZHNfcmVidWlsZFwiO1xuXG5leHBvcnQgaW50ZXJmYWNlIEVudmVsb3BlIHtcbiAgdmVyc2lvbjogc3RyaW5nO1xuICBtZXNzYWdlSWQ6IHN0cmluZztcbiAgY29udmVyc2F0aW9uSWQ6IHN0cmluZztcbiAgc2VuZGVyVXNlcklkOiBzdHJpbmc7XG4gIHNlbmRlckRldmljZUlkOiBzdHJpbmc7XG4gIHJlY2lwaWVudERldmljZUlkOiBzdHJpbmc7XG4gIGNyZWF0ZWRBdDogbnVtYmVyO1xuICBtZXNzYWdlVHlwZTogTWVzc2FnZVR5cGU7XG4gIGlubGluZUNpcGhlcnRleHQ/OiBzdHJpbmc7XG4gIHN0b3JhZ2VSZWZzPzogU3RvcmFnZVJlZltdO1xuICBkZWxpdmVyeUNsYXNzOiBcIm5vcm1hbFwiO1xuICB3YWtlSGludD86IFdha2VIaW50O1xuICBzZW5kZXJQcm9vZjogU2VuZGVyUHJvb2Y7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgSW5ib3hSZWNvcmQge1xuICBzZXE6IG51bWJlcjtcbiAgcmVjaXBpZW50RGV2aWNlSWQ6IHN0cmluZztcbiAgbWVzc2FnZUlkOiBzdHJpbmc7XG4gIHJlY2VpdmVkQXQ6IG51bWJlcjtcbiAgZXhwaXJlc0F0PzogbnVtYmVyO1xuICBzdGF0ZTogXCJhdmFpbGFibGVcIjtcbiAgZW52ZWxvcGU6IEVudmVsb3BlO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEFjayB7XG4gIGRldmljZUlkOiBzdHJpbmc7XG4gIGFja1NlcTogbnVtYmVyO1xuICBhY2tlZE1lc3NhZ2VJZHM/OiBzdHJpbmdbXTtcbiAgYWNrZWRBdDogbnVtYmVyO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEFwcGVuZEVudmVsb3BlUmVxdWVzdCB7XG4gIHZlcnNpb246IHN0cmluZztcbiAgcmVjaXBpZW50RGV2aWNlSWQ6IHN0cmluZztcbiAgZW52ZWxvcGU6IEVudmVsb3BlO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEFwcGVuZEVudmVsb3BlUmVzdWx0IHtcbiAgYWNjZXB0ZWQ6IGJvb2xlYW47XG4gIHNlcTogbnVtYmVyO1xuICBkZWxpdmVyZWRUbzogXCJpbmJveFwiIHwgXCJtZXNzYWdlX3JlcXVlc3RcIiB8IFwicmVqZWN0ZWRcIjtcbiAgcXVldWVkQXNSZXF1ZXN0PzogYm9vbGVhbjtcbiAgcmVxdWVzdElkPzogc3RyaW5nO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEZldGNoTWVzc2FnZXNSZXF1ZXN0IHtcbiAgZGV2aWNlSWQ6IHN0cmluZztcbiAgZnJvbVNlcTogbnVtYmVyO1xuICBsaW1pdDogbnVtYmVyO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEZldGNoTWVzc2FnZXNSZXN1bHQge1xuICB0b1NlcTogbnVtYmVyO1xuICByZWNvcmRzOiBJbmJveFJlY29yZFtdO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEFja1JlcXVlc3Qge1xuICBhY2s6IEFjaztcbn1cblxuZXhwb3J0IGludGVyZmFjZSBBY2tSZXN1bHQge1xuICBhY2NlcHRlZDogYm9vbGVhbjtcbiAgYWNrU2VxOiBudW1iZXI7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgR2V0SGVhZFJlc3VsdCB7XG4gIGhlYWRTZXE6IG51bWJlcjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBQcmVwYXJlQmxvYlVwbG9hZFJlcXVlc3Qge1xuICB0YXNrSWQ6IHN0cmluZztcbiAgY29udmVyc2F0aW9uSWQ6IHN0cmluZztcbiAgbWVzc2FnZUlkOiBzdHJpbmc7XG4gIG1pbWVUeXBlOiBzdHJpbmc7XG4gIHNpemVCeXRlczogbnVtYmVyO1xuICBmaWxlTmFtZT86IHN0cmluZztcbn1cblxuZXhwb3J0IGludGVyZmFjZSBQcmVwYXJlQmxvYlVwbG9hZFJlc3VsdCB7XG4gIGJsb2JSZWY6IHN0cmluZztcbiAgdXBsb2FkVGFyZ2V0OiBzdHJpbmc7XG4gIHVwbG9hZEhlYWRlcnM6IFJlY29yZDxzdHJpbmcsIHN0cmluZz47XG4gIGRvd25sb2FkVGFyZ2V0Pzogc3RyaW5nO1xuICBleHBpcmVzQXQ/OiBudW1iZXI7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgU3RvcmFnZUJhc2VJbmZvIHtcbiAgYmFzZVVybD86IHN0cmluZztcbiAgYnVja2V0SGludD86IHN0cmluZztcbn1cblxuZXhwb3J0IGludGVyZmFjZSBEZXZpY2VSdW50aW1lQXV0aCB7XG4gIHNjaGVtZTogXCJiZWFyZXJcIjtcbiAgdG9rZW46IHN0cmluZztcbiAgZXhwaXJlc0F0OiBudW1iZXI7XG4gIHVzZXJJZDogc3RyaW5nO1xuICBkZXZpY2VJZDogc3RyaW5nO1xuICBzY29wZXM6IERldmljZVJ1bnRpbWVTY29wZVtdO1xufVxuXG5leHBvcnQgdHlwZSBEZXZpY2VSdW50aW1lU2NvcGUgPVxuICB8IFwiaW5ib3hfcmVhZFwiXG4gIHwgXCJpbmJveF9hY2tcIlxuICB8IFwiaW5ib3hfc3Vic2NyaWJlXCJcbiAgfCBcImluYm94X21hbmFnZVwiXG4gIHwgXCJzdG9yYWdlX3ByZXBhcmVfdXBsb2FkXCJcbiAgfCBcInNoYXJlZF9zdGF0ZV93cml0ZVwiXG4gIHwgXCJrZXlwYWNrYWdlX3dyaXRlXCI7XG5cbmV4cG9ydCBpbnRlcmZhY2UgUnVudGltZUNvbmZpZyB7XG4gIHN1cHBvcnRlZFJlYWx0aW1lS2luZHM6IEFycmF5PFwid2Vic29ja2V0XCIgfCBcInNlcnZlcl9zZW50X2V2ZW50c1wiIHwgXCJwb2xsaW5nXCI+O1xuICBpZGVudGl0eUJ1bmRsZVJlZj86IHN0cmluZztcbiAgZGV2aWNlU3RhdHVzUmVmPzogc3RyaW5nO1xuICBrZXlwYWNrYWdlUmVmQmFzZT86IHN0cmluZztcbiAgbWF4SW5saW5lQnl0ZXM/OiBudW1iZXI7XG4gIGZlYXR1cmVzOiBzdHJpbmdbXTtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBEZXBsb3ltZW50QnVuZGxlIHtcbiAgdmVyc2lvbjogc3RyaW5nO1xuICByZWdpb246IHN0cmluZztcbiAgaW5ib3hIdHRwRW5kcG9pbnQ6IHN0cmluZztcbiAgaW5ib3hXZWJzb2NrZXRFbmRwb2ludDogc3RyaW5nO1xuICBzdG9yYWdlQmFzZUluZm86IFN0b3JhZ2VCYXNlSW5mbztcbiAgcnVudGltZUNvbmZpZzogUnVudGltZUNvbmZpZztcbiAgZGV2aWNlUnVudGltZUF1dGg/OiBEZXZpY2VSdW50aW1lQXV0aDtcbiAgZXhwZWN0ZWRVc2VySWQ/OiBzdHJpbmc7XG4gIGV4cGVjdGVkRGV2aWNlSWQ/OiBzdHJpbmc7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgSW5ib3hBcHBlbmRDYXBhYmlsaXR5IHtcbiAgdmVyc2lvbjogc3RyaW5nO1xuICBzZXJ2aWNlOiBcImluYm94XCI7XG4gIHVzZXJJZDogc3RyaW5nO1xuICB0YXJnZXREZXZpY2VJZDogc3RyaW5nO1xuICBlbmRwb2ludDogc3RyaW5nO1xuICBvcGVyYXRpb25zOiBzdHJpbmdbXTtcbiAgY29udmVyc2F0aW9uU2NvcGU/OiBzdHJpbmdbXTtcbiAgZXhwaXJlc0F0OiBudW1iZXI7XG4gIGNvbnN0cmFpbnRzPzogQ2FwYWJpbGl0eUNvbnN0cmFpbnRzO1xuICBzaWduYXR1cmU6IHN0cmluZztcbn1cblxuZXhwb3J0IGludGVyZmFjZSBEZXZpY2VCaW5kaW5nIHtcbiAgdmVyc2lvbjogc3RyaW5nO1xuICB1c2VySWQ6IHN0cmluZztcbiAgZGV2aWNlSWQ6IHN0cmluZztcbiAgZGV2aWNlUHVibGljS2V5OiBzdHJpbmc7XG4gIGNyZWF0ZWRBdDogbnVtYmVyO1xuICBzaWduYXR1cmU6IHN0cmluZztcbn1cblxuZXhwb3J0IHR5cGUgRGV2aWNlU3RhdHVzS2luZCA9IFwiYWN0aXZlXCIgfCBcInJldm9rZWRcIjtcblxuZXhwb3J0IGludGVyZmFjZSBLZXlQYWNrYWdlUmVmIHtcbiAgdmVyc2lvbjogc3RyaW5nO1xuICB1c2VySWQ6IHN0cmluZztcbiAgZGV2aWNlSWQ6IHN0cmluZztcbiAgcmVmOiBzdHJpbmc7XG4gIGV4cGlyZXNBdDogbnVtYmVyO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIERldmljZUNvbnRhY3RQcm9maWxlIHtcbiAgdmVyc2lvbjogc3RyaW5nO1xuICBkZXZpY2VJZDogc3RyaW5nO1xuICBkZXZpY2VQdWJsaWNLZXk6IHN0cmluZztcbiAgYmluZGluZzogRGV2aWNlQmluZGluZztcbiAgc3RhdHVzOiBEZXZpY2VTdGF0dXNLaW5kO1xuICBpbmJveEFwcGVuZENhcGFiaWxpdHk6IEluYm94QXBwZW5kQ2FwYWJpbGl0eTtcbiAga2V5cGFja2FnZVJlZjogS2V5UGFja2FnZVJlZjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBTdG9yYWdlUHJvZmlsZSB7XG4gIGJhc2VVcmw/OiBzdHJpbmc7XG4gIHByb2ZpbGVSZWY/OiBzdHJpbmc7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgSWRlbnRpdHlCdW5kbGUge1xuICB2ZXJzaW9uOiBzdHJpbmc7XG4gIHVzZXJJZDogc3RyaW5nO1xuICB1c2VyUHVibGljS2V5OiBzdHJpbmc7XG4gIGRldmljZXM6IERldmljZUNvbnRhY3RQcm9maWxlW107XG4gIGlkZW50aXR5QnVuZGxlUmVmPzogc3RyaW5nO1xuICBkZXZpY2VTdGF0dXNSZWY/OiBzdHJpbmc7XG4gIHN0b3JhZ2VQcm9maWxlPzogU3RvcmFnZVByb2ZpbGU7XG4gIHVwZGF0ZWRBdDogbnVtYmVyO1xuICBzaWduYXR1cmU6IHN0cmluZztcbn1cblxuZXhwb3J0IGludGVyZmFjZSBEZXZpY2VTdGF0dXNSZWNvcmQge1xuICB2ZXJzaW9uOiBzdHJpbmc7XG4gIHVzZXJJZDogc3RyaW5nO1xuICBkZXZpY2VJZDogc3RyaW5nO1xuICBzdGF0dXM6IERldmljZVN0YXR1c0tpbmQ7XG4gIHVwZGF0ZWRBdDogbnVtYmVyO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIERldmljZUxpc3RFbnRyeSB7XG4gIGRldmljZUlkOiBzdHJpbmc7XG4gIHN0YXR1czogRGV2aWNlU3RhdHVzS2luZDtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBEZXZpY2VMaXN0RG9jdW1lbnQge1xuICB2ZXJzaW9uOiBzdHJpbmc7XG4gIHVzZXJJZDogc3RyaW5nO1xuICB1cGRhdGVkQXQ6IG51bWJlcjtcbiAgZGV2aWNlczogRGV2aWNlTGlzdEVudHJ5W107XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgRGV2aWNlU3RhdHVzRG9jdW1lbnQge1xuICB2ZXJzaW9uOiBzdHJpbmc7XG4gIHVzZXJJZDogc3RyaW5nO1xuICB1cGRhdGVkQXQ6IG51bWJlcjtcbiAgZGV2aWNlczogRGV2aWNlU3RhdHVzUmVjb3JkW107XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgS2V5UGFja2FnZVJlZkVudHJ5IHtcbiAga2V5UGFja2FnZUlkOiBzdHJpbmc7XG4gIHJlZjogc3RyaW5nO1xuICBleHBpcmVzQXQ6IG51bWJlcjtcbiAgY3JlYXRlZEF0OiBudW1iZXI7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgS2V5UGFja2FnZVJlZnNEb2N1bWVudCB7XG4gIHZlcnNpb246IHN0cmluZztcbiAgdXNlcklkOiBzdHJpbmc7XG4gIGRldmljZUlkOiBzdHJpbmc7XG4gIHVwZGF0ZWRBdDogbnVtYmVyO1xuICByZWZzOiBLZXlQYWNrYWdlUmVmRW50cnlbXTtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBTaGFyZWRTdGF0ZVdyaXRlVG9rZW4ge1xuICB2ZXJzaW9uOiBzdHJpbmc7XG4gIHNlcnZpY2U6IFwic2hhcmVkX3N0YXRlXCI7XG4gIHVzZXJJZDogc3RyaW5nO1xuICBvYmplY3RLaW5kczogQXJyYXk8XCJpZGVudGl0eV9idW5kbGVcIiB8IFwiZGV2aWNlX3N0YXR1c1wiPjtcbiAgZXhwaXJlc0F0OiBudW1iZXI7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgS2V5UGFja2FnZVdyaXRlVG9rZW4ge1xuICB2ZXJzaW9uOiBzdHJpbmc7XG4gIHNlcnZpY2U6IFwia2V5cGFja2FnZXNcIjtcbiAgdXNlcklkOiBzdHJpbmc7XG4gIGRldmljZUlkOiBzdHJpbmc7XG4gIGtleVBhY2thZ2VJZD86IHN0cmluZztcbiAgZXhwaXJlc0F0OiBudW1iZXI7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQm9vdHN0cmFwRGV2aWNlUmVxdWVzdCB7XG4gIHZlcnNpb246IHN0cmluZztcbiAgdXNlcklkOiBzdHJpbmc7XG4gIGRldmljZUlkOiBzdHJpbmc7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQm9vdHN0cmFwVG9rZW4ge1xuICB2ZXJzaW9uOiBzdHJpbmc7XG4gIHNlcnZpY2U6IFwiYm9vdHN0cmFwXCI7XG4gIHVzZXJJZDogc3RyaW5nO1xuICBkZXZpY2VJZDogc3RyaW5nO1xuICBvcGVyYXRpb25zOiBBcnJheTxcImlzc3VlX2RldmljZV9idW5kbGVcIj47XG4gIGV4cGlyZXNBdDogbnVtYmVyO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIERldmljZVJ1bnRpbWVUb2tlbiB7XG4gIHZlcnNpb246IHN0cmluZztcbiAgc2VydmljZTogXCJkZXZpY2VfcnVudGltZVwiO1xuICB1c2VySWQ6IHN0cmluZztcbiAgZGV2aWNlSWQ6IHN0cmluZztcbiAgc2NvcGVzOiBEZXZpY2VSdW50aW1lU2NvcGVbXTtcbiAgZXhwaXJlc0F0OiBudW1iZXI7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgUmVhbHRpbWVFdmVudCB7XG4gIGV2ZW50OiBcImhlYWRfdXBkYXRlZFwiIHwgXCJpbmJveF9yZWNvcmRfYXZhaWxhYmxlXCI7XG4gIGRldmljZUlkOiBzdHJpbmc7XG4gIHNlcTogbnVtYmVyO1xuICByZWNvcmQ/OiBJbmJveFJlY29yZDtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBBbGxvd2xpc3REb2N1bWVudCB7XG4gIHZlcnNpb246IHN0cmluZztcbiAgZGV2aWNlSWQ6IHN0cmluZztcbiAgdXBkYXRlZEF0OiBudW1iZXI7XG4gIGFsbG93ZWRTZW5kZXJVc2VySWRzOiBzdHJpbmdbXTtcbiAgcmVqZWN0ZWRTZW5kZXJVc2VySWRzOiBzdHJpbmdbXTtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBNZXNzYWdlUmVxdWVzdEl0ZW0ge1xuICByZXF1ZXN0SWQ6IHN0cmluZztcbiAgcmVjaXBpZW50RGV2aWNlSWQ6IHN0cmluZztcbiAgc2VuZGVyVXNlcklkOiBzdHJpbmc7XG4gIGZpcnN0U2VlbkF0OiBudW1iZXI7XG4gIGxhc3RTZWVuQXQ6IG51bWJlcjtcbiAgbWVzc2FnZUNvdW50OiBudW1iZXI7XG4gIGxhc3RNZXNzYWdlSWQ6IHN0cmluZztcbiAgbGFzdENvbnZlcnNhdGlvbklkOiBzdHJpbmc7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgTWVzc2FnZVJlcXVlc3RMaXN0UmVzdWx0IHtcbiAgcmVxdWVzdHM6IE1lc3NhZ2VSZXF1ZXN0SXRlbVtdO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIE1lc3NhZ2VSZXF1ZXN0QWN0aW9uUmVzdWx0IHtcbiAgYWNjZXB0ZWQ6IGJvb2xlYW47XG4gIHJlcXVlc3RJZDogc3RyaW5nO1xuICBzZW5kZXJVc2VySWQ6IHN0cmluZztcbiAgcHJvbW90ZWRDb3VudD86IG51bWJlcjtcbn1cclxuXHJcbiIsICJjb25zdCBlbmNvZGVyID0gbmV3IFRleHRFbmNvZGVyKCk7XG5cbmZ1bmN0aW9uIHRvQmFzZTY0VXJsKGJ5dGVzOiBVaW50OEFycmF5KTogc3RyaW5nIHtcbiAgbGV0IGJpbmFyeSA9IFwiXCI7XG4gIGZvciAoY29uc3QgYnl0ZSBvZiBieXRlcykge1xuICAgIGJpbmFyeSArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKGJ5dGUpO1xuICB9XG4gIHJldHVybiBidG9hKGJpbmFyeSkucmVwbGFjZSgvXFwrL2csIFwiLVwiKS5yZXBsYWNlKC9cXC8vZywgXCJfXCIpLnJlcGxhY2UoLz0rJC9nLCBcIlwiKTtcbn1cblxuZnVuY3Rpb24gZnJvbUJhc2U2NFVybCh2YWx1ZTogc3RyaW5nKTogVWludDhBcnJheSB7XG4gIGNvbnN0IG5vcm1hbGl6ZWQgPSB2YWx1ZS5yZXBsYWNlKC8tL2csIFwiK1wiKS5yZXBsYWNlKC9fL2csIFwiL1wiKTtcbiAgY29uc3QgcGFkZGVkID0gbm9ybWFsaXplZCArIFwiPVwiLnJlcGVhdCgoNCAtIChub3JtYWxpemVkLmxlbmd0aCAlIDQpKSAlIDQpO1xuICBjb25zdCBiaW5hcnkgPSBhdG9iKHBhZGRlZCk7XG4gIGNvbnN0IG91dHB1dCA9IG5ldyBVaW50OEFycmF5KGJpbmFyeS5sZW5ndGgpO1xuICBmb3IgKGxldCBpID0gMDsgaSA8IGJpbmFyeS5sZW5ndGg7IGkgKz0gMSkge1xuICAgIG91dHB1dFtpXSA9IGJpbmFyeS5jaGFyQ29kZUF0KGkpO1xuICB9XG4gIHJldHVybiBvdXRwdXQ7XG59XG5cbmFzeW5jIGZ1bmN0aW9uIGltcG9ydFNlY3JldChzZWNyZXQ6IHN0cmluZyk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gIHJldHVybiBjcnlwdG8uc3VidGxlLmltcG9ydEtleShcbiAgICBcInJhd1wiLFxuICAgIGVuY29kZXIuZW5jb2RlKHNlY3JldCksXG4gICAgeyBuYW1lOiBcIkhNQUNcIiwgaGFzaDogXCJTSEEtMjU2XCIgfSxcbiAgICBmYWxzZSxcbiAgICBbXCJzaWduXCIsIFwidmVyaWZ5XCJdXG4gICk7XG59XG5cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzaWduU2hhcmluZ1BheWxvYWQoc2VjcmV0OiBzdHJpbmcsIHBheWxvYWQ6IFJlY29yZDxzdHJpbmcsIHVua25vd24+KTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgY29uc3QgZW5jb2RlZFBheWxvYWQgPSBlbmNvZGVyLmVuY29kZShKU09OLnN0cmluZ2lmeShwYXlsb2FkKSk7XG4gIGNvbnN0IGtleSA9IGF3YWl0IGltcG9ydFNlY3JldChzZWNyZXQpO1xuICBjb25zdCBzaWduYXR1cmUgPSBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLnNpZ24oXCJITUFDXCIsIGtleSwgZW5jb2RlZFBheWxvYWQpKTtcbiAgcmV0dXJuIGAke3RvQmFzZTY0VXJsKGVuY29kZWRQYXlsb2FkKX0uJHt0b0Jhc2U2NFVybChzaWduYXR1cmUpfWA7XG59XG5cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiB2ZXJpZnlTaGFyaW5nUGF5bG9hZDxUPihzZWNyZXQ6IHN0cmluZywgdG9rZW46IHN0cmluZywgbm93OiBudW1iZXIpOiBQcm9taXNlPFQ+IHtcbiAgY29uc3QgW3BheWxvYWRQYXJ0LCBzaWduYXR1cmVQYXJ0XSA9IHRva2VuLnNwbGl0KFwiLlwiKTtcbiAgaWYgKCFwYXlsb2FkUGFydCB8fCAhc2lnbmF0dXJlUGFydCkge1xuICAgIHRocm93IG5ldyBFcnJvcihcImludmFsaWQgc2hhcmluZyB0b2tlblwiKTtcbiAgfVxuXG4gIGNvbnN0IHBheWxvYWRCeXRlcyA9IGZyb21CYXNlNjRVcmwocGF5bG9hZFBhcnQpO1xuICBjb25zdCBzaWduYXR1cmVCeXRlcyA9IGZyb21CYXNlNjRVcmwoc2lnbmF0dXJlUGFydCk7XG4gIGNvbnN0IGtleSA9IGF3YWl0IGltcG9ydFNlY3JldChzZWNyZXQpO1xuICBjb25zdCBwYXlsb2FkQnVmZmVyID0gcGF5bG9hZEJ5dGVzLmJ1ZmZlci5zbGljZShcbiAgICBwYXlsb2FkQnl0ZXMuYnl0ZU9mZnNldCxcbiAgICBwYXlsb2FkQnl0ZXMuYnl0ZU9mZnNldCArIHBheWxvYWRCeXRlcy5ieXRlTGVuZ3RoXG4gICkgYXMgQXJyYXlCdWZmZXI7XG4gIGNvbnN0IHNpZ25hdHVyZUJ1ZmZlciA9IHNpZ25hdHVyZUJ5dGVzLmJ1ZmZlci5zbGljZShcbiAgICBzaWduYXR1cmVCeXRlcy5ieXRlT2Zmc2V0LFxuICAgIHNpZ25hdHVyZUJ5dGVzLmJ5dGVPZmZzZXQgKyBzaWduYXR1cmVCeXRlcy5ieXRlTGVuZ3RoXG4gICkgYXMgQXJyYXlCdWZmZXI7XG4gIGNvbnN0IHZhbGlkID0gYXdhaXQgY3J5cHRvLnN1YnRsZS52ZXJpZnkoXCJITUFDXCIsIGtleSwgc2lnbmF0dXJlQnVmZmVyLCBwYXlsb2FkQnVmZmVyKTtcbiAgaWYgKCF2YWxpZCkge1xuICAgIHRocm93IG5ldyBFcnJvcihcImludmFsaWQgc2hhcmluZyB0b2tlblwiKTtcbiAgfVxuXG4gIGNvbnN0IHBheWxvYWQgPSBKU09OLnBhcnNlKG5ldyBUZXh0RGVjb2RlcigpLmRlY29kZShwYXlsb2FkQnl0ZXMpKSBhcyBUICYgeyBleHBpcmVzQXQ/OiBudW1iZXIgfTtcbiAgaWYgKHBheWxvYWQuZXhwaXJlc0F0ICE9PSB1bmRlZmluZWQgJiYgcGF5bG9hZC5leHBpcmVzQXQgPD0gbm93KSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKFwic2hhcmluZyB0b2tlbiBleHBpcmVkXCIpO1xuICB9XG4gIHJldHVybiBwYXlsb2FkO1xufVxyXG4iLCAiaW1wb3J0IHR5cGUge1xuICBBcHBlbmRFbnZlbG9wZVJlcXVlc3QsXG4gIEJvb3RzdHJhcFRva2VuLFxuICBEZXZpY2VSdW50aW1lU2NvcGUsXG4gIERldmljZVJ1bnRpbWVUb2tlbixcbiAgSW5ib3hBcHBlbmRDYXBhYmlsaXR5LFxuICBLZXlQYWNrYWdlV3JpdGVUb2tlbixcbiAgU2hhcmVkU3RhdGVXcml0ZVRva2VuXG59IGZyb20gXCIuLi90eXBlcy9jb250cmFjdHNcIjtcbmltcG9ydCB7IENVUlJFTlRfTU9ERUxfVkVSU0lPTiB9IGZyb20gXCIuLi90eXBlcy9jb250cmFjdHNcIjtcbmltcG9ydCB7IHZlcmlmeVNoYXJpbmdQYXlsb2FkIH0gZnJvbSBcIi4uL3N0b3JhZ2Uvc2hhcmluZ1wiO1xuXG5leHBvcnQgY2xhc3MgSHR0cEVycm9yIGV4dGVuZHMgRXJyb3Ige1xuICByZWFkb25seSBzdGF0dXM6IG51bWJlcjtcbiAgcmVhZG9ubHkgY29kZTogc3RyaW5nO1xuXG4gIGNvbnN0cnVjdG9yKHN0YXR1czogbnVtYmVyLCBjb2RlOiBzdHJpbmcsIG1lc3NhZ2U6IHN0cmluZykge1xuICAgIHN1cGVyKG1lc3NhZ2UpO1xuICAgIHRoaXMuc3RhdHVzID0gc3RhdHVzO1xuICAgIHRoaXMuY29kZSA9IGNvZGU7XG4gIH1cbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGdldEJlYXJlclRva2VuKHJlcXVlc3Q6IFJlcXVlc3QpOiBzdHJpbmcge1xuICBjb25zdCBoZWFkZXIgPSByZXF1ZXN0LmhlYWRlcnMuZ2V0KFwiQXV0aG9yaXphdGlvblwiKT8udHJpbSgpO1xuICBpZiAoIWhlYWRlcikge1xuICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAxLCBcImludmFsaWRfY2FwYWJpbGl0eVwiLCBcIm1pc3NpbmcgQXV0aG9yaXphdGlvbiBoZWFkZXJcIik7XG4gIH1cbiAgaWYgKCFoZWFkZXIuc3RhcnRzV2l0aChcIkJlYXJlciBcIikpIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMSwgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJBdXRob3JpemF0aW9uIGhlYWRlciBtdXN0IHVzZSBCZWFyZXIgdG9rZW5cIik7XG4gIH1cbiAgY29uc3QgdG9rZW4gPSBoZWFkZXIuc2xpY2UoXCJCZWFyZXIgXCIubGVuZ3RoKS50cmltKCk7XG4gIGlmICghdG9rZW4pIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMSwgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJCZWFyZXIgdG9rZW4gbXVzdCBub3QgYmUgZW1wdHlcIik7XG4gIH1cbiAgcmV0dXJuIHRva2VuO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gdmFsaWRhdGVBcHBlbmRBdXRob3JpemF0aW9uKFxuICByZXF1ZXN0OiBSZXF1ZXN0LFxuICBkZXZpY2VJZDogc3RyaW5nLFxuICBib2R5OiBBcHBlbmRFbnZlbG9wZVJlcXVlc3QsXG4gIG5vdzogbnVtYmVyXG4pOiB2b2lkIHtcbiAgY29uc3Qgc2lnbmF0dXJlID0gZ2V0QmVhcmVyVG9rZW4ocmVxdWVzdCk7XG4gIGNvbnN0IGNhcGFiaWxpdHlIZWFkZXIgPSByZXF1ZXN0LmhlYWRlcnMuZ2V0KFwiWC1UYXBjaGF0LUNhcGFiaWxpdHlcIik7XG4gIGlmICghY2FwYWJpbGl0eUhlYWRlcikge1xuICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAxLCBcImludmFsaWRfY2FwYWJpbGl0eVwiLCBcIm1pc3NpbmcgWC1UYXBjaGF0LUNhcGFiaWxpdHkgaGVhZGVyXCIpO1xuICB9XG5cbiAgbGV0IGNhcGFiaWxpdHk6IEluYm94QXBwZW5kQ2FwYWJpbGl0eTtcbiAgdHJ5IHtcbiAgICBjYXBhYmlsaXR5ID0gSlNPTi5wYXJzZShjYXBhYmlsaXR5SGVhZGVyKSBhcyBJbmJveEFwcGVuZENhcGFiaWxpdHk7XG4gIH0gY2F0Y2gge1xuICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAwLCBcImludmFsaWRfY2FwYWJpbGl0eVwiLCBcIlgtVGFwY2hhdC1DYXBhYmlsaXR5IGlzIG5vdCB2YWxpZCBKU09OXCIpO1xuICB9XG5cbiAgaWYgKGJvZHkudmVyc2lvbiAhPT0gQ1VSUkVOVF9NT0RFTF9WRVJTSU9OIHx8IGNhcGFiaWxpdHkudmVyc2lvbiAhPT0gQ1VSUkVOVF9NT0RFTF9WRVJTSU9OKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDAsIFwidW5zdXBwb3J0ZWRfdmVyc2lvblwiLCBcImFwcGVuZCBjYXBhYmlsaXR5IHZlcnNpb24gaXMgbm90IHN1cHBvcnRlZFwiKTtcbiAgfVxuICBpZiAoY2FwYWJpbGl0eS5zaWduYXR1cmUgIT09IHNpZ25hdHVyZSkge1xuICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAzLCBcImludmFsaWRfY2FwYWJpbGl0eVwiLCBcImNhcGFiaWxpdHkgc2lnbmF0dXJlIGRvZXMgbm90IG1hdGNoIGJlYXJlciB0b2tlblwiKTtcbiAgfVxuICBpZiAoY2FwYWJpbGl0eS5zZXJ2aWNlICE9PSBcImluYm94XCIpIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMywgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJjYXBhYmlsaXR5IHNlcnZpY2UgbXVzdCBiZSBpbmJveFwiKTtcbiAgfVxuICBpZiAoIWNhcGFiaWxpdHkub3BlcmF0aW9ucy5pbmNsdWRlcyhcImFwcGVuZFwiKSkge1xuICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAzLCBcImludmFsaWRfY2FwYWJpbGl0eVwiLCBcImNhcGFiaWxpdHkgZG9lcyBub3QgZ3JhbnQgYXBwZW5kXCIpO1xuICB9XG4gIGlmIChjYXBhYmlsaXR5LnRhcmdldERldmljZUlkICE9PSBkZXZpY2VJZCkge1xuICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAzLCBcImludmFsaWRfY2FwYWJpbGl0eVwiLCBcImNhcGFiaWxpdHkgdGFyZ2V0IGRldmljZSBkb2VzIG5vdCBtYXRjaCByZXF1ZXN0IHBhdGhcIik7XG4gIH1cbiAgY29uc3QgcmVxdWVzdFVybCA9IG5ldyBVUkwocmVxdWVzdC51cmwpO1xuICBpZiAoY2FwYWJpbGl0eS5lbmRwb2ludCAhPT0gYCR7cmVxdWVzdFVybC5vcmlnaW59JHtyZXF1ZXN0VXJsLnBhdGhuYW1lfWApIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMywgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJjYXBhYmlsaXR5IGVuZHBvaW50IGRvZXMgbm90IG1hdGNoIHJlcXVlc3QgcGF0aFwiKTtcbiAgfVxuICBpZiAoY2FwYWJpbGl0eS5leHBpcmVzQXQgPD0gbm93KSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiY2FwYWJpbGl0eV9leHBpcmVkXCIsIFwiYXBwZW5kIGNhcGFiaWxpdHkgaXMgZXhwaXJlZFwiKTtcbiAgfVxuICBpZiAoYm9keS5yZWNpcGllbnREZXZpY2VJZCAhPT0gZGV2aWNlSWQgfHwgYm9keS5lbnZlbG9wZS5yZWNpcGllbnREZXZpY2VJZCAhPT0gZGV2aWNlSWQpIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMywgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJyZWNpcGllbnQgZGV2aWNlIGRvZXMgbm90IG1hdGNoIHRhcmdldCBpbmJveFwiKTtcbiAgfVxuICBpZiAoY2FwYWJpbGl0eS5jb252ZXJzYXRpb25TY29wZT8ubGVuZ3RoICYmICFjYXBhYmlsaXR5LmNvbnZlcnNhdGlvblNjb3BlLmluY2x1ZGVzKGJvZHkuZW52ZWxvcGUuY29udmVyc2F0aW9uSWQpKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwiY29udmVyc2F0aW9uIGlzIG91dHNpZGUgY2FwYWJpbGl0eSBzY29wZVwiKTtcbiAgfVxuICBjb25zdCBzaXplID0gbmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKEpTT04uc3RyaW5naWZ5KGJvZHkuZW52ZWxvcGUpKS5ieXRlTGVuZ3RoO1xuICBpZiAoY2FwYWJpbGl0eS5jb25zdHJhaW50cz8ubWF4Qnl0ZXMgIT09IHVuZGVmaW5lZCAmJiBzaXplID4gY2FwYWJpbGl0eS5jb25zdHJhaW50cy5tYXhCeXRlcykge1xuICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDEzLCBcInBheWxvYWRfdG9vX2xhcmdlXCIsIFwiZW52ZWxvcGUgZXhjZWVkcyBjYXBhYmlsaXR5IHNpemUgbGltaXRcIik7XG4gIH1cbn1cblxuYXN5bmMgZnVuY3Rpb24gdmVyaWZ5U2lnbmVkVG9rZW48VD4oc2VjcmV0OiBzdHJpbmcsIHJlcXVlc3Q6IFJlcXVlc3QsIG5vdzogbnVtYmVyKTogUHJvbWlzZTxUPiB7XG4gIGNvbnN0IHRva2VuID0gZ2V0QmVhcmVyVG9rZW4ocmVxdWVzdCk7XG4gIHRyeSB7XG4gICAgcmV0dXJuIGF3YWl0IHZlcmlmeVNoYXJpbmdQYXlsb2FkPFQ+KHNlY3JldCwgdG9rZW4sIG5vdyk7XG4gIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgY29uc3QgbWVzc2FnZSA9IGVycm9yIGluc3RhbmNlb2YgRXJyb3IgPyBlcnJvci5tZXNzYWdlIDogXCJpbnZhbGlkIHNpZ25lZCB0b2tlblwiO1xuICAgIGlmIChtZXNzYWdlLmluY2x1ZGVzKFwiZXhwaXJlZFwiKSkge1xuICAgICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiY2FwYWJpbGl0eV9leHBpcmVkXCIsIG1lc3NhZ2UpO1xuICAgIH1cbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMywgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgbWVzc2FnZSk7XG4gIH1cbn1cblxuYXN5bmMgZnVuY3Rpb24gdmVyaWZ5RGV2aWNlUnVudGltZVRva2VuKHJlcXVlc3Q6IFJlcXVlc3QsIHNlY3JldDogc3RyaW5nLCBub3c6IG51bWJlcik6IFByb21pc2U8RGV2aWNlUnVudGltZVRva2VuPiB7XG4gIGNvbnN0IHRva2VuID0gYXdhaXQgdmVyaWZ5U2lnbmVkVG9rZW48RGV2aWNlUnVudGltZVRva2VuPihzZWNyZXQsIHJlcXVlc3QsIG5vdyk7XG4gIGlmICh0b2tlbi52ZXJzaW9uICE9PSBDVVJSRU5UX01PREVMX1ZFUlNJT04pIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMCwgXCJ1bnN1cHBvcnRlZF92ZXJzaW9uXCIsIFwiZGV2aWNlIHJ1bnRpbWUgdG9rZW4gdmVyc2lvbiBpcyBub3Qgc3VwcG9ydGVkXCIpO1xuICB9XG4gIGlmICh0b2tlbi5zZXJ2aWNlICE9PSBcImRldmljZV9ydW50aW1lXCIpIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMywgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJ0b2tlbiBzZXJ2aWNlIG11c3QgYmUgZGV2aWNlX3J1bnRpbWVcIik7XG4gIH1cbiAgaWYgKCF0b2tlbi51c2VySWQgfHwgIXRva2VuLmRldmljZUlkIHx8ICF0b2tlbi5zY29wZXMubGVuZ3RoKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwiZGV2aWNlIHJ1bnRpbWUgdG9rZW4gaXMgbWFsZm9ybWVkXCIpO1xuICB9XG4gIHJldHVybiB0b2tlbjtcbn1cblxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHZhbGlkYXRlQm9vdHN0cmFwQXV0aG9yaXphdGlvbihcbiAgcmVxdWVzdDogUmVxdWVzdCxcbiAgc2VjcmV0OiBzdHJpbmcsXG4gIHVzZXJJZDogc3RyaW5nLFxuICBkZXZpY2VJZDogc3RyaW5nLFxuICBub3c6IG51bWJlclxuKTogUHJvbWlzZTxCb290c3RyYXBUb2tlbj4ge1xuICBjb25zdCB0b2tlbiA9IGF3YWl0IHZlcmlmeVNpZ25lZFRva2VuPEJvb3RzdHJhcFRva2VuPihzZWNyZXQsIHJlcXVlc3QsIG5vdyk7XG4gIGlmICh0b2tlbi52ZXJzaW9uICE9PSBDVVJSRU5UX01PREVMX1ZFUlNJT04pIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMCwgXCJ1bnN1cHBvcnRlZF92ZXJzaW9uXCIsIFwiYm9vdHN0cmFwIHRva2VuIHZlcnNpb24gaXMgbm90IHN1cHBvcnRlZFwiKTtcbiAgfVxuICBpZiAodG9rZW4uc2VydmljZSAhPT0gXCJib290c3RyYXBcIikge1xuICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAzLCBcImludmFsaWRfY2FwYWJpbGl0eVwiLCBcInRva2VuIHNlcnZpY2UgbXVzdCBiZSBib290c3RyYXBcIik7XG4gIH1cbiAgaWYgKHRva2VuLnVzZXJJZCAhPT0gdXNlcklkIHx8IHRva2VuLmRldmljZUlkICE9PSBkZXZpY2VJZCkge1xuICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAzLCBcImludmFsaWRfY2FwYWJpbGl0eVwiLCBcImJvb3RzdHJhcCB0b2tlbiBzY29wZSBkb2VzIG5vdCBtYXRjaCByZXF1ZXN0XCIpO1xuICB9XG4gIGlmICghdG9rZW4ub3BlcmF0aW9ucy5pbmNsdWRlcyhcImlzc3VlX2RldmljZV9idW5kbGVcIikpIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMywgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJib290c3RyYXAgdG9rZW4gZG9lcyBub3QgZ3JhbnQgZGV2aWNlIGJ1bmRsZSBpc3N1YW5jZVwiKTtcbiAgfVxuICByZXR1cm4gdG9rZW47XG59XG5cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiB2YWxpZGF0ZUFueURldmljZVJ1bnRpbWVBdXRob3JpemF0aW9uKFxuICByZXF1ZXN0OiBSZXF1ZXN0LFxuICBzZWNyZXQ6IHN0cmluZyxcbiAgc2NvcGU6IERldmljZVJ1bnRpbWVTY29wZSxcbiAgbm93OiBudW1iZXJcbik6IFByb21pc2U8RGV2aWNlUnVudGltZVRva2VuPiB7XG4gIGNvbnN0IHRva2VuID0gYXdhaXQgdmVyaWZ5RGV2aWNlUnVudGltZVRva2VuKHJlcXVlc3QsIHNlY3JldCwgbm93KTtcbiAgaWYgKCF0b2tlbi5zY29wZXMuaW5jbHVkZXMoc2NvcGUpKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIGBkZXZpY2UgcnVudGltZSB0b2tlbiBkb2VzIG5vdCBncmFudCAke3Njb3BlfWApO1xuICB9XG4gIHJldHVybiB0b2tlbjtcbn1cblxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHZhbGlkYXRlRGV2aWNlUnVudGltZUF1dGhvcml6YXRpb24oXG4gIHJlcXVlc3Q6IFJlcXVlc3QsXG4gIHNlY3JldDogc3RyaW5nLFxuICB1c2VySWQ6IHN0cmluZyxcbiAgZGV2aWNlSWQ6IHN0cmluZyxcbiAgc2NvcGU6IERldmljZVJ1bnRpbWVTY29wZSxcbiAgbm93OiBudW1iZXJcbik6IFByb21pc2U8RGV2aWNlUnVudGltZVRva2VuPiB7XG4gIGNvbnN0IHRva2VuID0gYXdhaXQgdmFsaWRhdGVBbnlEZXZpY2VSdW50aW1lQXV0aG9yaXphdGlvbihyZXF1ZXN0LCBzZWNyZXQsIHNjb3BlLCBub3cpO1xuICBpZiAodG9rZW4udXNlcklkICE9PSB1c2VySWQgfHwgdG9rZW4uZGV2aWNlSWQgIT09IGRldmljZUlkKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwiZGV2aWNlIHJ1bnRpbWUgdG9rZW4gc2NvcGUgZG9lcyBub3QgbWF0Y2ggcmVxdWVzdCBwYXRoXCIpO1xuICB9XG4gIHJldHVybiB0b2tlbjtcbn1cblxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHZhbGlkYXRlRGV2aWNlUnVudGltZUF1dGhvcml6YXRpb25Gb3JEZXZpY2UoXG4gIHJlcXVlc3Q6IFJlcXVlc3QsXG4gIHNlY3JldDogc3RyaW5nLFxuICBkZXZpY2VJZDogc3RyaW5nLFxuICBzY29wZTogRGV2aWNlUnVudGltZVNjb3BlLFxuICBub3c6IG51bWJlclxuKTogUHJvbWlzZTxEZXZpY2VSdW50aW1lVG9rZW4+IHtcbiAgY29uc3QgdG9rZW4gPSBhd2FpdCB2YWxpZGF0ZUFueURldmljZVJ1bnRpbWVBdXRob3JpemF0aW9uKHJlcXVlc3QsIHNlY3JldCwgc2NvcGUsIG5vdyk7XG4gIGlmICh0b2tlbi5kZXZpY2VJZCAhPT0gZGV2aWNlSWQpIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMywgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJkZXZpY2UgcnVudGltZSB0b2tlbiBzY29wZSBkb2VzIG5vdCBtYXRjaCByZXF1ZXN0IHBhdGhcIik7XG4gIH1cbiAgcmV0dXJuIHRva2VuO1xufVxuXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gdmFsaWRhdGVTaGFyZWRTdGF0ZVdyaXRlQXV0aG9yaXphdGlvbihcbiAgcmVxdWVzdDogUmVxdWVzdCxcbiAgc2VjcmV0OiBzdHJpbmcsXG4gIHVzZXJJZDogc3RyaW5nLFxuICBkZXZpY2VJZDogc3RyaW5nLFxuICBvYmplY3RLaW5kOiBcImlkZW50aXR5X2J1bmRsZVwiIHwgXCJkZXZpY2Vfc3RhdHVzXCIsXG4gIG5vdzogbnVtYmVyXG4pOiBQcm9taXNlPFNoYXJlZFN0YXRlV3JpdGVUb2tlbiB8IERldmljZVJ1bnRpbWVUb2tlbj4ge1xuICB0cnkge1xuICAgIHJldHVybiBhd2FpdCB2YWxpZGF0ZURldmljZVJ1bnRpbWVBdXRob3JpemF0aW9uKHJlcXVlc3QsIHNlY3JldCwgdXNlcklkLCBkZXZpY2VJZCwgXCJzaGFyZWRfc3RhdGVfd3JpdGVcIiwgbm93KTtcbiAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICBpZiAoIShlcnJvciBpbnN0YW5jZW9mIEh0dHBFcnJvcikgfHwgZXJyb3IuY29kZSA9PT0gXCJjYXBhYmlsaXR5X2V4cGlyZWRcIikge1xuICAgICAgdGhyb3cgZXJyb3I7XG4gICAgfVxuICB9XG5cbiAgY29uc3QgdG9rZW4gPSBhd2FpdCB2ZXJpZnlTaWduZWRUb2tlbjxTaGFyZWRTdGF0ZVdyaXRlVG9rZW4+KHNlY3JldCwgcmVxdWVzdCwgbm93KTtcbiAgaWYgKHRva2VuLnZlcnNpb24gIT09IENVUlJFTlRfTU9ERUxfVkVSU0lPTikge1xuICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAwLCBcInVuc3VwcG9ydGVkX3ZlcnNpb25cIiwgXCJzaGFyZWQtc3RhdGUgdG9rZW4gdmVyc2lvbiBpcyBub3Qgc3VwcG9ydGVkXCIpO1xuICB9XG4gIGlmICh0b2tlbi5zZXJ2aWNlICE9PSBcInNoYXJlZF9zdGF0ZVwiKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwidG9rZW4gc2VydmljZSBtdXN0IGJlIHNoYXJlZF9zdGF0ZVwiKTtcbiAgfVxuICBpZiAodG9rZW4udXNlcklkICE9PSB1c2VySWQpIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMywgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJ0b2tlbiB1c2VySWQgZG9lcyBub3QgbWF0Y2ggcmVxdWVzdCBwYXRoXCIpO1xuICB9XG4gIGlmICghdG9rZW4ub2JqZWN0S2luZHMuaW5jbHVkZXMob2JqZWN0S2luZCkpIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMywgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJ0b2tlbiBkb2VzIG5vdCBncmFudCB0aGlzIHNoYXJlZC1zdGF0ZSBvYmplY3Qga2luZFwiKTtcbiAgfVxuICByZXR1cm4gdG9rZW47XG59XG5cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiB2YWxpZGF0ZUtleVBhY2thZ2VXcml0ZUF1dGhvcml6YXRpb24oXG4gIHJlcXVlc3Q6IFJlcXVlc3QsXG4gIHNlY3JldDogc3RyaW5nLFxuICB1c2VySWQ6IHN0cmluZyxcbiAgZGV2aWNlSWQ6IHN0cmluZyxcbiAga2V5UGFja2FnZUlkOiBzdHJpbmcgfCB1bmRlZmluZWQsXG4gIG5vdzogbnVtYmVyXG4pOiBQcm9taXNlPEtleVBhY2thZ2VXcml0ZVRva2VuIHwgRGV2aWNlUnVudGltZVRva2VuPiB7XG4gIHRyeSB7XG4gICAgcmV0dXJuIGF3YWl0IHZhbGlkYXRlRGV2aWNlUnVudGltZUF1dGhvcml6YXRpb24ocmVxdWVzdCwgc2VjcmV0LCB1c2VySWQsIGRldmljZUlkLCBcImtleXBhY2thZ2Vfd3JpdGVcIiwgbm93KTtcbiAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICBpZiAoIShlcnJvciBpbnN0YW5jZW9mIEh0dHBFcnJvcikgfHwgZXJyb3IuY29kZSA9PT0gXCJjYXBhYmlsaXR5X2V4cGlyZWRcIikge1xuICAgICAgdGhyb3cgZXJyb3I7XG4gICAgfVxuICB9XG5cbiAgY29uc3QgdG9rZW4gPSBhd2FpdCB2ZXJpZnlTaWduZWRUb2tlbjxLZXlQYWNrYWdlV3JpdGVUb2tlbj4oc2VjcmV0LCByZXF1ZXN0LCBub3cpO1xuICBpZiAodG9rZW4udmVyc2lvbiAhPT0gQ1VSUkVOVF9NT0RFTF9WRVJTSU9OKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDAsIFwidW5zdXBwb3J0ZWRfdmVyc2lvblwiLCBcImtleXBhY2thZ2UgdG9rZW4gdmVyc2lvbiBpcyBub3Qgc3VwcG9ydGVkXCIpO1xuICB9XG4gIGlmICh0b2tlbi5zZXJ2aWNlICE9PSBcImtleXBhY2thZ2VzXCIpIHtcbiAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMywgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJ0b2tlbiBzZXJ2aWNlIG11c3QgYmUga2V5cGFja2FnZXNcIik7XG4gIH1cbiAgaWYgKHRva2VuLnVzZXJJZCAhPT0gdXNlcklkIHx8IHRva2VuLmRldmljZUlkICE9PSBkZXZpY2VJZCkge1xuICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAzLCBcImludmFsaWRfY2FwYWJpbGl0eVwiLCBcInRva2VuIHNjb3BlIGRvZXMgbm90IG1hdGNoIHJlcXVlc3QgcGF0aFwiKTtcbiAgfVxuICBpZiAodG9rZW4ua2V5UGFja2FnZUlkICYmIHRva2VuLmtleVBhY2thZ2VJZCAhPT0ga2V5UGFja2FnZUlkKSB7XG4gICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwidG9rZW4ga2V5UGFja2FnZUlkIGRvZXMgbm90IG1hdGNoIHJlcXVlc3QgcGF0aFwiKTtcbiAgfVxuICByZXR1cm4gdG9rZW47XG59XHJcbiIsICJpbXBvcnQgeyBIdHRwRXJyb3IgfSBmcm9tIFwiLi4vYXV0aC9jYXBhYmlsaXR5XCI7XG5pbXBvcnQgdHlwZSB7XG4gIEFja1JlcXVlc3QsXG4gIEFja1Jlc3VsdCxcbiAgQWxsb3dsaXN0RG9jdW1lbnQsXG4gIEFwcGVuZEVudmVsb3BlUmVxdWVzdCxcbiAgQXBwZW5kRW52ZWxvcGVSZXN1bHQsXG4gIEZldGNoTWVzc2FnZXNSZXF1ZXN0LFxuICBGZXRjaE1lc3NhZ2VzUmVzdWx0LFxuICBJbmJveFJlY29yZCxcbiAgTWVzc2FnZVJlcXVlc3RBY3Rpb25SZXN1bHQsXG4gIE1lc3NhZ2VSZXF1ZXN0SXRlbSxcbiAgUmVhbHRpbWVFdmVudFxufSBmcm9tIFwiLi4vdHlwZXMvY29udHJhY3RzXCI7XG5pbXBvcnQgdHlwZSB7IER1cmFibGVPYmplY3RTdG9yYWdlTGlrZSwgSnNvbkJsb2JTdG9yZSwgU2Vzc2lvblNpbmsgfSBmcm9tIFwiLi4vdHlwZXMvcnVudGltZVwiO1xuXG5pbnRlcmZhY2UgSW5ib3hNZXRhIHtcbiAgaGVhZFNlcTogbnVtYmVyO1xuICBhY2tlZFNlcTogbnVtYmVyO1xuICByZXRlbnRpb25EYXlzOiBudW1iZXI7XG4gIG1heElubGluZUJ5dGVzOiBudW1iZXI7XG4gIHJhdGVMaW1pdFBlck1pbnV0ZTogbnVtYmVyO1xuICByYXRlTGltaXRQZXJIb3VyOiBudW1iZXI7XG59XG5cbmludGVyZmFjZSBTdG9yZWRSZWNvcmRJbmRleCB7XG4gIHNlcTogbnVtYmVyO1xuICBtZXNzYWdlSWQ6IHN0cmluZztcbiAgcmVjaXBpZW50RGV2aWNlSWQ6IHN0cmluZztcbiAgcmVjZWl2ZWRBdDogbnVtYmVyO1xuICBleHBpcmVzQXQ/OiBudW1iZXI7XG4gIHN0YXRlOiBcImF2YWlsYWJsZVwiO1xuICBpbmxpbmVSZWNvcmQ/OiBJbmJveFJlY29yZDtcbiAgcGF5bG9hZFJlZj86IHN0cmluZztcbn1cblxuaW50ZXJmYWNlIE1lc3NhZ2VSZXF1ZXN0RW50cnkge1xuICByZXF1ZXN0SWQ6IHN0cmluZztcbiAgcmVjaXBpZW50RGV2aWNlSWQ6IHN0cmluZztcbiAgc2VuZGVyVXNlcklkOiBzdHJpbmc7XG4gIGZpcnN0U2VlbkF0OiBudW1iZXI7XG4gIGxhc3RTZWVuQXQ6IG51bWJlcjtcbiAgbWVzc2FnZUNvdW50OiBudW1iZXI7XG4gIGxhc3RNZXNzYWdlSWQ6IHN0cmluZztcbiAgbGFzdENvbnZlcnNhdGlvbklkOiBzdHJpbmc7XG4gIHBlbmRpbmdSZXF1ZXN0czogQXBwZW5kRW52ZWxvcGVSZXF1ZXN0W107XG59XG5cbmludGVyZmFjZSBSYXRlTGltaXRTdGF0ZSB7XG4gIG1pbnV0ZVdpbmRvd1N0YXJ0OiBudW1iZXI7XG4gIG1pbnV0ZUNvdW50OiBudW1iZXI7XG4gIGhvdXJXaW5kb3dTdGFydDogbnVtYmVyO1xuICBob3VyQ291bnQ6IG51bWJlcjtcbn1cblxuY29uc3QgTUVUQV9LRVkgPSBcIm1ldGFcIjtcbmNvbnN0IElERU1QT1RFTkNZX1BSRUZJWCA9IFwiaWRlbXBvdGVuY3k6XCI7XG5jb25zdCBBUFBFTkRfUkVTVUxUX1BSRUZJWCA9IFwiYXBwZW5kLXJlc3VsdDpcIjtcbmNvbnN0IFJFQ09SRF9QUkVGSVggPSBcInJlY29yZDpcIjtcbmNvbnN0IEFMTE9XTElTVF9LRVkgPSBcImFsbG93bGlzdFwiO1xuY29uc3QgTUVTU0FHRV9SRVFVRVNUX1BSRUZJWCA9IFwibWVzc2FnZS1yZXF1ZXN0OlwiO1xuY29uc3QgUkFURV9MSU1JVF9QUkVGSVggPSBcInJhdGUtbGltaXQ6XCI7XG5cbmV4cG9ydCBjbGFzcyBJbmJveFNlcnZpY2Uge1xuICBwcml2YXRlIHJlYWRvbmx5IGRldmljZUlkOiBzdHJpbmc7XG4gIHByaXZhdGUgcmVhZG9ubHkgc3RhdGU6IER1cmFibGVPYmplY3RTdG9yYWdlTGlrZTtcbiAgcHJpdmF0ZSByZWFkb25seSBzcGlsbFN0b3JlOiBKc29uQmxvYlN0b3JlO1xuICBwcml2YXRlIHJlYWRvbmx5IHNlc3Npb25zOiBTZXNzaW9uU2lua1tdO1xuICBwcml2YXRlIHJlYWRvbmx5IGRlZmF1bHRzOiBJbmJveE1ldGE7XG5cbiAgY29uc3RydWN0b3IoXG4gICAgZGV2aWNlSWQ6IHN0cmluZyxcbiAgICBzdGF0ZTogRHVyYWJsZU9iamVjdFN0b3JhZ2VMaWtlLFxuICAgIHNwaWxsU3RvcmU6IEpzb25CbG9iU3RvcmUsXG4gICAgc2Vzc2lvbnM6IFNlc3Npb25TaW5rW10sXG4gICAgZGVmYXVsdHM6IEluYm94TWV0YVxuICApIHtcbiAgICB0aGlzLmRldmljZUlkID0gZGV2aWNlSWQ7XG4gICAgdGhpcy5zdGF0ZSA9IHN0YXRlO1xuICAgIHRoaXMuc3BpbGxTdG9yZSA9IHNwaWxsU3RvcmU7XG4gICAgdGhpcy5zZXNzaW9ucyA9IHNlc3Npb25zO1xuICAgIHRoaXMuZGVmYXVsdHMgPSBkZWZhdWx0cztcbiAgfVxuXG4gIGFzeW5jIGFwcGVuZEVudmVsb3BlKGlucHV0OiBBcHBlbmRFbnZlbG9wZVJlcXVlc3QsIG5vdzogbnVtYmVyKTogUHJvbWlzZTxBcHBlbmRFbnZlbG9wZVJlc3VsdD4ge1xuICAgIHRoaXMudmFsaWRhdGVBcHBlbmRSZXF1ZXN0KGlucHV0KTtcblxuICAgIGNvbnN0IGV4aXN0aW5nUmVzdWx0ID0gYXdhaXQgdGhpcy5zdGF0ZS5nZXQ8QXBwZW5kRW52ZWxvcGVSZXN1bHQ+KGAke0FQUEVORF9SRVNVTFRfUFJFRklYfSR7aW5wdXQuZW52ZWxvcGUubWVzc2FnZUlkfWApO1xuICAgIGlmIChleGlzdGluZ1Jlc3VsdCkge1xuICAgICAgcmV0dXJuIGV4aXN0aW5nUmVzdWx0O1xuICAgIH1cblxuICAgIGF3YWl0IHRoaXMuZW5mb3JjZVJhdGVMaW1pdChpbnB1dC5lbnZlbG9wZS5zZW5kZXJVc2VySWQsIG5vdyk7XG5cbiAgICBjb25zdCBhbGxvd2xpc3QgPSBhd2FpdCB0aGlzLmdldEFsbG93bGlzdChub3cpO1xuICAgIGlmIChhbGxvd2xpc3QucmVqZWN0ZWRTZW5kZXJVc2VySWRzLmluY2x1ZGVzKGlucHV0LmVudmVsb3BlLnNlbmRlclVzZXJJZCkpIHtcbiAgICAgIGNvbnN0IHJlamVjdGVkOiBBcHBlbmRFbnZlbG9wZVJlc3VsdCA9IHtcclxuICAgICAgICBhY2NlcHRlZDogdHJ1ZSxcclxuICAgICAgICBzZXE6IDAsXHJcbiAgICAgICAgZGVsaXZlcmVkVG86IFwicmVqZWN0ZWRcIixcclxuICAgICAgICBxdWV1ZWRBc1JlcXVlc3Q6IGZhbHNlXHJcbiAgICAgIH07XG4gICAgICBhd2FpdCB0aGlzLnN0YXRlLnB1dChgJHtBUFBFTkRfUkVTVUxUX1BSRUZJWH0ke2lucHV0LmVudmVsb3BlLm1lc3NhZ2VJZH1gLCByZWplY3RlZCk7XG4gICAgICByZXR1cm4gcmVqZWN0ZWQ7XG4gICAgfVxuXG4gICAgaWYgKGFsbG93bGlzdC5hbGxvd2VkU2VuZGVyVXNlcklkcy5pbmNsdWRlcyhpbnB1dC5lbnZlbG9wZS5zZW5kZXJVc2VySWQpKSB7XG4gICAgICBjb25zdCBkZWxpdmVyZWQgPSBhd2FpdCB0aGlzLmRlbGl2ZXJFbnZlbG9wZShpbnB1dCwgbm93KTtcbiAgICAgIGF3YWl0IHRoaXMuc3RhdGUucHV0KGAke0FQUEVORF9SRVNVTFRfUFJFRklYfSR7aW5wdXQuZW52ZWxvcGUubWVzc2FnZUlkfWAsIGRlbGl2ZXJlZCk7XG4gICAgICByZXR1cm4gZGVsaXZlcmVkO1xuICAgIH1cblxuICAgIGNvbnN0IHJlcXVlc3QgPSBhd2FpdCB0aGlzLnF1ZXVlTWVzc2FnZVJlcXVlc3QoaW5wdXQsIG5vdyk7XG4gICAgYXdhaXQgdGhpcy5zdGF0ZS5wdXQoYCR7QVBQRU5EX1JFU1VMVF9QUkVGSVh9JHtpbnB1dC5lbnZlbG9wZS5tZXNzYWdlSWR9YCwgcmVxdWVzdCk7XG4gICAgcmV0dXJuIHJlcXVlc3Q7XG4gIH1cblxuICBhc3luYyBmZXRjaE1lc3NhZ2VzKGlucHV0OiBGZXRjaE1lc3NhZ2VzUmVxdWVzdCk6IFByb21pc2U8RmV0Y2hNZXNzYWdlc1Jlc3VsdD4ge1xuICAgIGlmIChpbnB1dC5kZXZpY2VJZCAhPT0gdGhpcy5kZXZpY2VJZCkge1xuICAgICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDAsIFwiaW52YWxpZF9pbnB1dFwiLCBcImRldmljZV9pZCBkb2VzIG5vdCBtYXRjaCBpbmJveCByb3V0ZVwiKTtcbiAgICB9XG4gICAgaWYgKGlucHV0LmxpbWl0IDw9IDApIHtcbiAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAwLCBcImludmFsaWRfaW5wdXRcIiwgXCJsaW1pdCBtdXN0IGJlIGdyZWF0ZXIgdGhhbiB6ZXJvXCIpO1xuICAgIH1cblxuICAgIGNvbnN0IG1ldGEgPSBhd2FpdCB0aGlzLmdldE1ldGEoKTtcbiAgICBjb25zdCByZWNvcmRzOiBJbmJveFJlY29yZFtdID0gW107XG4gICAgY29uc3QgdXBwZXIgPSBNYXRoLm1pbihtZXRhLmhlYWRTZXEsIGlucHV0LmZyb21TZXEgKyBpbnB1dC5saW1pdCAtIDEpO1xuICAgIGZvciAobGV0IHNlcSA9IGlucHV0LmZyb21TZXE7IHNlcSA8PSB1cHBlcjsgc2VxICs9IDEpIHtcbiAgICAgIGNvbnN0IGluZGV4ID0gYXdhaXQgdGhpcy5zdGF0ZS5nZXQ8U3RvcmVkUmVjb3JkSW5kZXg+KGAke1JFQ09SRF9QUkVGSVh9JHtzZXF9YCk7XG4gICAgICBpZiAoIWluZGV4KSB7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuICAgICAgaWYgKGluZGV4LmlubGluZVJlY29yZCkge1xuICAgICAgICByZWNvcmRzLnB1c2goaW5kZXguaW5saW5lUmVjb3JkKTtcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG4gICAgICBpZiAoIWluZGV4LnBheWxvYWRSZWYpIHtcbiAgICAgICAgdGhyb3cgbmV3IEh0dHBFcnJvcig1MDAsIFwidGVtcG9yYXJ5X3VuYXZhaWxhYmxlXCIsIFwicmVjb3JkIHBheWxvYWQgcmVmZXJlbmNlIGlzIG1pc3NpbmdcIik7XG4gICAgICB9XG4gICAgICBjb25zdCByZWNvcmQgPSBhd2FpdCB0aGlzLnNwaWxsU3RvcmUuZ2V0SnNvbjxJbmJveFJlY29yZD4oaW5kZXgucGF5bG9hZFJlZik7XG4gICAgICBpZiAoIXJlY29yZCkge1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cbiAgICAgIHJlY29yZHMucHVzaChyZWNvcmQpO1xuICAgIH1cbiAgICByZXR1cm4ge1xuICAgICAgdG9TZXE6IHJlY29yZHMubGVuZ3RoID4gMCA/IHJlY29yZHNbcmVjb3Jkcy5sZW5ndGggLSAxXS5zZXEgOiBtZXRhLmhlYWRTZXEsXG4gICAgICByZWNvcmRzXG4gICAgfTtcbiAgfVxuXG4gIGFzeW5jIGFjayhpbnB1dDogQWNrUmVxdWVzdCk6IFByb21pc2U8QWNrUmVzdWx0PiB7XG4gICAgaWYgKGlucHV0LmFjay5kZXZpY2VJZCAhPT0gdGhpcy5kZXZpY2VJZCkge1xuICAgICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDAsIFwiaW52YWxpZF9pbnB1dFwiLCBcImFjayBkZXZpY2VfaWQgZG9lcyBub3QgbWF0Y2ggaW5ib3ggcm91dGVcIik7XG4gICAgfVxuICAgIGNvbnN0IG1ldGEgPSBhd2FpdCB0aGlzLmdldE1ldGEoKTtcbiAgICBpZiAoaW5wdXQuYWNrLmFja1NlcSA8IG1ldGEuYWNrZWRTZXEpIHtcbiAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDA5LCBcImludmFsaWRfYWNrXCIsIFwiYWNrX3NlcSBtdXN0IG5vdCBtb3ZlIGJhY2t3YXJkc1wiKTtcbiAgICB9XG4gICAgY29uc3QgYWNrU2VxID0gTWF0aC5tYXgobWV0YS5hY2tlZFNlcSwgaW5wdXQuYWNrLmFja1NlcSk7XG4gICAgYXdhaXQgdGhpcy5zdGF0ZS5wdXQoTUVUQV9LRVksIHsgLi4ubWV0YSwgYWNrZWRTZXE6IGFja1NlcSB9KTtcbiAgICBhd2FpdCB0aGlzLnN0YXRlLnNldEFsYXJtKERhdGUubm93KCkpO1xuICAgIHJldHVybiB7IGFjY2VwdGVkOiB0cnVlLCBhY2tTZXEgfTtcbiAgfVxuXG4gIGFzeW5jIGdldEhlYWQoKTogUHJvbWlzZTx7IGhlYWRTZXE6IG51bWJlciB9PiB7XG4gICAgY29uc3QgbWV0YSA9IGF3YWl0IHRoaXMuZ2V0TWV0YSgpO1xuICAgIHJldHVybiB7IGhlYWRTZXE6IG1ldGEuaGVhZFNlcSB9O1xuICB9XG5cbiAgYXN5bmMgZ2V0QWxsb3dsaXN0KG5vdyA9IERhdGUubm93KCkpOiBQcm9taXNlPEFsbG93bGlzdERvY3VtZW50PiB7XG4gICAgcmV0dXJuIChhd2FpdCB0aGlzLnN0YXRlLmdldDxBbGxvd2xpc3REb2N1bWVudD4oQUxMT1dMSVNUX0tFWSkpID8/IHtcbiAgICAgIHZlcnNpb246IFwiMC4xXCIsXG4gICAgICBkZXZpY2VJZDogdGhpcy5kZXZpY2VJZCxcbiAgICAgIHVwZGF0ZWRBdDogbm93LFxuICAgICAgYWxsb3dlZFNlbmRlclVzZXJJZHM6IFtdLFxuICAgICAgcmVqZWN0ZWRTZW5kZXJVc2VySWRzOiBbXVxuICAgIH07XG4gIH1cblxuICBhc3luYyByZXBsYWNlQWxsb3dsaXN0KGFsbG93ZWRTZW5kZXJVc2VySWRzOiBzdHJpbmdbXSwgcmVqZWN0ZWRTZW5kZXJVc2VySWRzOiBzdHJpbmdbXSwgbm93OiBudW1iZXIpOiBQcm9taXNlPEFsbG93bGlzdERvY3VtZW50PiB7XG4gICAgY29uc3QgZG9jdW1lbnQ6IEFsbG93bGlzdERvY3VtZW50ID0ge1xuICAgICAgdmVyc2lvbjogXCIwLjFcIixcbiAgICAgIGRldmljZUlkOiB0aGlzLmRldmljZUlkLFxuICAgICAgdXBkYXRlZEF0OiBub3csXG4gICAgICBhbGxvd2VkU2VuZGVyVXNlcklkczogQXJyYXkuZnJvbShuZXcgU2V0KGFsbG93ZWRTZW5kZXJVc2VySWRzKSkuc29ydCgpLFxuICAgICAgcmVqZWN0ZWRTZW5kZXJVc2VySWRzOiBBcnJheS5mcm9tKG5ldyBTZXQocmVqZWN0ZWRTZW5kZXJVc2VySWRzLmZpbHRlcigodXNlcklkKSA9PiAhYWxsb3dlZFNlbmRlclVzZXJJZHMuaW5jbHVkZXModXNlcklkKSkpKS5zb3J0KClcbiAgICB9O1xuICAgIGF3YWl0IHRoaXMuc3RhdGUucHV0KEFMTE9XTElTVF9LRVksIGRvY3VtZW50KTtcbiAgICByZXR1cm4gZG9jdW1lbnQ7XG4gIH1cblxuICBhc3luYyBsaXN0TWVzc2FnZVJlcXVlc3RzKCk6IFByb21pc2U8TWVzc2FnZVJlcXVlc3RJdGVtW10+IHtcbiAgICBjb25zdCByZXF1ZXN0cyA9IGF3YWl0IHRoaXMuc3RhdGUuZ2V0PHN0cmluZ1tdPih0aGlzLm1lc3NhZ2VSZXF1ZXN0SW5kZXhLZXkoKSk7XG4gICAgaWYgKCFyZXF1ZXN0cz8ubGVuZ3RoKSB7XG4gICAgICByZXR1cm4gW107XG4gICAgfVxuICAgIGNvbnN0IGl0ZW1zOiBNZXNzYWdlUmVxdWVzdEl0ZW1bXSA9IFtdO1xuICAgIGZvciAoY29uc3Qgc2VuZGVyVXNlcklkIG9mIHJlcXVlc3RzKSB7XG4gICAgICBjb25zdCBlbnRyeSA9IGF3YWl0IHRoaXMuc3RhdGUuZ2V0PE1lc3NhZ2VSZXF1ZXN0RW50cnk+KHRoaXMubWVzc2FnZVJlcXVlc3RLZXkoc2VuZGVyVXNlcklkKSk7XG4gICAgICBpZiAoIWVudHJ5KSB7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuICAgICAgaXRlbXMucHVzaCh0aGlzLnRvTWVzc2FnZVJlcXVlc3RJdGVtKGVudHJ5KSk7XG4gICAgfVxuICAgIGl0ZW1zLnNvcnQoKGxlZnQsIHJpZ2h0KSA9PiBsZWZ0LmZpcnN0U2VlbkF0IC0gcmlnaHQuZmlyc3RTZWVuQXQgfHwgbGVmdC5zZW5kZXJVc2VySWQubG9jYWxlQ29tcGFyZShyaWdodC5zZW5kZXJVc2VySWQpKTtcbiAgICByZXR1cm4gaXRlbXM7XG4gIH1cblxuICBhc3luYyBhY2NlcHRNZXNzYWdlUmVxdWVzdChyZXF1ZXN0SWQ6IHN0cmluZywgbm93OiBudW1iZXIpOiBQcm9taXNlPE1lc3NhZ2VSZXF1ZXN0QWN0aW9uUmVzdWx0PiB7XG4gICAgY29uc3QgZW50cnkgPSBhd2FpdCB0aGlzLmZpbmRNZXNzYWdlUmVxdWVzdChyZXF1ZXN0SWQpO1xuICAgIGlmICghZW50cnkpIHtcbiAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDA0LCBcIm5vdF9mb3VuZFwiLCBcIm1lc3NhZ2UgcmVxdWVzdCBub3QgZm91bmRcIik7XG4gICAgfVxuICAgIGNvbnN0IGFsbG93bGlzdCA9IGF3YWl0IHRoaXMuZ2V0QWxsb3dsaXN0KG5vdyk7XG4gICAgYXdhaXQgdGhpcy5yZXBsYWNlQWxsb3dsaXN0KFxuICAgICAgWy4uLmFsbG93bGlzdC5hbGxvd2VkU2VuZGVyVXNlcklkcywgZW50cnkuc2VuZGVyVXNlcklkXSxcbiAgICAgIGFsbG93bGlzdC5yZWplY3RlZFNlbmRlclVzZXJJZHMuZmlsdGVyKCh1c2VySWQpID0+IHVzZXJJZCAhPT0gZW50cnkuc2VuZGVyVXNlcklkKSxcbiAgICAgIG5vd1xuICAgICk7XG5cbiAgICBsZXQgcHJvbW90ZWRDb3VudCA9IDA7XG4gICAgZm9yIChjb25zdCByZXF1ZXN0IG9mIGVudHJ5LnBlbmRpbmdSZXF1ZXN0cykge1xuICAgICAgY29uc3QgZGVsaXZlcmVkID0gYXdhaXQgdGhpcy5kZWxpdmVyRW52ZWxvcGUocmVxdWVzdCwgbm93KTtcbiAgICAgIGF3YWl0IHRoaXMuc3RhdGUucHV0KGAke0FQUEVORF9SRVNVTFRfUFJFRklYfSR7cmVxdWVzdC5lbnZlbG9wZS5tZXNzYWdlSWR9YCwgZGVsaXZlcmVkKTtcbiAgICAgIHByb21vdGVkQ291bnQgKz0gZGVsaXZlcmVkLnNlcSA9PT0gdW5kZWZpbmVkID8gMCA6IDE7XG4gICAgfVxuICAgIGF3YWl0IHRoaXMuZGVsZXRlTWVzc2FnZVJlcXVlc3QoZW50cnkuc2VuZGVyVXNlcklkKTtcbiAgICByZXR1cm4ge1xuICAgICAgYWNjZXB0ZWQ6IHRydWUsXG4gICAgICByZXF1ZXN0SWQ6IGVudHJ5LnJlcXVlc3RJZCxcbiAgICAgIHNlbmRlclVzZXJJZDogZW50cnkuc2VuZGVyVXNlcklkLFxuICAgICAgcHJvbW90ZWRDb3VudFxuICAgIH07XG4gIH1cblxuICBhc3luYyByZWplY3RNZXNzYWdlUmVxdWVzdChyZXF1ZXN0SWQ6IHN0cmluZywgbm93OiBudW1iZXIpOiBQcm9taXNlPE1lc3NhZ2VSZXF1ZXN0QWN0aW9uUmVzdWx0PiB7XG4gICAgY29uc3QgZW50cnkgPSBhd2FpdCB0aGlzLmZpbmRNZXNzYWdlUmVxdWVzdChyZXF1ZXN0SWQpO1xuICAgIGlmICghZW50cnkpIHtcbiAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDA0LCBcIm5vdF9mb3VuZFwiLCBcIm1lc3NhZ2UgcmVxdWVzdCBub3QgZm91bmRcIik7XG4gICAgfVxuICAgIGNvbnN0IGFsbG93bGlzdCA9IGF3YWl0IHRoaXMuZ2V0QWxsb3dsaXN0KG5vdyk7XG4gICAgYXdhaXQgdGhpcy5yZXBsYWNlQWxsb3dsaXN0KFxuICAgICAgYWxsb3dsaXN0LmFsbG93ZWRTZW5kZXJVc2VySWRzLmZpbHRlcigodXNlcklkKSA9PiB1c2VySWQgIT09IGVudHJ5LnNlbmRlclVzZXJJZCksXG4gICAgICBbLi4uYWxsb3dsaXN0LnJlamVjdGVkU2VuZGVyVXNlcklkcywgZW50cnkuc2VuZGVyVXNlcklkXSxcbiAgICAgIG5vd1xuICAgICk7XG4gICAgYXdhaXQgdGhpcy5kZWxldGVNZXNzYWdlUmVxdWVzdChlbnRyeS5zZW5kZXJVc2VySWQpO1xuICAgIHJldHVybiB7XG4gICAgICBhY2NlcHRlZDogdHJ1ZSxcbiAgICAgIHJlcXVlc3RJZDogZW50cnkucmVxdWVzdElkLFxuICAgICAgc2VuZGVyVXNlcklkOiBlbnRyeS5zZW5kZXJVc2VySWQsXG4gICAgICBwcm9tb3RlZENvdW50OiAwXG4gICAgfTtcbiAgfVxuXG4gIGFzeW5jIGNsZWFuRXhwaXJlZFJlY29yZHMobm93OiBudW1iZXIpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBjb25zdCBtZXRhID0gYXdhaXQgdGhpcy5nZXRNZXRhKCk7XG4gICAgZm9yIChsZXQgc2VxID0gMTsgc2VxIDw9IG1ldGEuYWNrZWRTZXE7IHNlcSArPSAxKSB7XG4gICAgICBjb25zdCBrZXkgPSBgJHtSRUNPUkRfUFJFRklYfSR7c2VxfWA7XG4gICAgICBjb25zdCBpbmRleCA9IGF3YWl0IHRoaXMuc3RhdGUuZ2V0PFN0b3JlZFJlY29yZEluZGV4PihrZXkpO1xuICAgICAgaWYgKCFpbmRleCB8fCBpbmRleC5leHBpcmVzQXQgPT09IHVuZGVmaW5lZCB8fCBpbmRleC5leHBpcmVzQXQgPiBub3cpIHtcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG4gICAgICBpZiAoaW5kZXgucGF5bG9hZFJlZikge1xuICAgICAgICBhd2FpdCB0aGlzLnNwaWxsU3RvcmUuZGVsZXRlKGluZGV4LnBheWxvYWRSZWYpO1xuICAgICAgfVxuICAgICAgYXdhaXQgdGhpcy5zdGF0ZS5kZWxldGUoa2V5KTtcbiAgICAgIGF3YWl0IHRoaXMuc3RhdGUuZGVsZXRlKGAke0lERU1QT1RFTkNZX1BSRUZJWH0ke2luZGV4Lm1lc3NhZ2VJZH1gKTtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIGFzeW5jIGdldE1ldGEoKTogUHJvbWlzZTxJbmJveE1ldGE+IHtcbiAgICByZXR1cm4gKGF3YWl0IHRoaXMuc3RhdGUuZ2V0PEluYm94TWV0YT4oTUVUQV9LRVkpKSA/PyB0aGlzLmRlZmF1bHRzO1xuICB9XG5cbiAgcHJpdmF0ZSBhc3luYyBkZWxpdmVyRW52ZWxvcGUoaW5wdXQ6IEFwcGVuZEVudmVsb3BlUmVxdWVzdCwgbm93OiBudW1iZXIpOiBQcm9taXNlPEFwcGVuZEVudmVsb3BlUmVzdWx0PiB7XG4gICAgY29uc3QgbWV0YSA9IGF3YWl0IHRoaXMuZ2V0TWV0YSgpO1xuICAgIGNvbnN0IGV4aXN0aW5nU2VxID0gYXdhaXQgdGhpcy5zdGF0ZS5nZXQ8bnVtYmVyPihgJHtJREVNUE9URU5DWV9QUkVGSVh9JHtpbnB1dC5lbnZlbG9wZS5tZXNzYWdlSWR9YCk7XG4gICAgaWYgKGV4aXN0aW5nU2VxICE9PSB1bmRlZmluZWQpIHtcbiAgICAgIHJldHVybiB7IGFjY2VwdGVkOiB0cnVlLCBzZXE6IGV4aXN0aW5nU2VxLCBkZWxpdmVyZWRUbzogXCJpbmJveFwiIH07XG4gICAgfVxuXG4gICAgY29uc3Qgc2VxID0gbWV0YS5oZWFkU2VxICsgMTtcbiAgICBjb25zdCBleHBpcmVzQXQgPSBub3cgKyBtZXRhLnJldGVudGlvbkRheXMgKiAyNCAqIDYwICogNjAgKiAxMDAwO1xuICAgIGNvbnN0IHJlY29yZDogSW5ib3hSZWNvcmQgPSB7XG4gICAgICBzZXEsXG4gICAgICByZWNpcGllbnREZXZpY2VJZDogdGhpcy5kZXZpY2VJZCxcbiAgICAgIG1lc3NhZ2VJZDogaW5wdXQuZW52ZWxvcGUubWVzc2FnZUlkLFxuICAgICAgcmVjZWl2ZWRBdDogbm93LFxuICAgICAgZXhwaXJlc0F0LFxuICAgICAgc3RhdGU6IFwiYXZhaWxhYmxlXCIsXG4gICAgICBlbnZlbG9wZTogaW5wdXQuZW52ZWxvcGVcbiAgICB9O1xuICAgIGNvbnN0IHNlcmlhbGl6ZWQgPSBKU09OLnN0cmluZ2lmeShyZWNvcmQpO1xuICAgIGNvbnN0IHN0b3JhZ2VLZXkgPSBgJHtSRUNPUkRfUFJFRklYfSR7c2VxfWA7XG5cbiAgICBpZiAobmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKHNlcmlhbGl6ZWQpLmJ5dGVMZW5ndGggPD0gbWV0YS5tYXhJbmxpbmVCeXRlcyAmJiBpbnB1dC5lbnZlbG9wZS5pbmxpbmVDaXBoZXJ0ZXh0KSB7XG4gICAgICBjb25zdCBpbmxpbmVJbmRleDogU3RvcmVkUmVjb3JkSW5kZXggPSB7XG4gICAgICAgIHNlcSxcbiAgICAgICAgbWVzc2FnZUlkOiByZWNvcmQubWVzc2FnZUlkLFxuICAgICAgICByZWNpcGllbnREZXZpY2VJZDogcmVjb3JkLnJlY2lwaWVudERldmljZUlkLFxuICAgICAgICByZWNlaXZlZEF0OiByZWNvcmQucmVjZWl2ZWRBdCxcbiAgICAgICAgZXhwaXJlc0F0LFxuICAgICAgICBzdGF0ZTogcmVjb3JkLnN0YXRlLFxuICAgICAgICBpbmxpbmVSZWNvcmQ6IHJlY29yZFxuICAgICAgfTtcbiAgICAgIGF3YWl0IHRoaXMuc3RhdGUucHV0KHN0b3JhZ2VLZXksIGlubGluZUluZGV4KTtcbiAgICB9IGVsc2Uge1xuICAgICAgY29uc3QgcGF5bG9hZFJlZiA9IGBpbmJveC1wYXlsb2FkLyR7dGhpcy5kZXZpY2VJZH0vJHtzZXF9Lmpzb25gO1xuICAgICAgYXdhaXQgdGhpcy5zcGlsbFN0b3JlLnB1dEpzb24ocGF5bG9hZFJlZiwgcmVjb3JkKTtcbiAgICAgIGNvbnN0IGluZGV4ZWQ6IFN0b3JlZFJlY29yZEluZGV4ID0ge1xuICAgICAgICBzZXEsXG4gICAgICAgIG1lc3NhZ2VJZDogcmVjb3JkLm1lc3NhZ2VJZCxcbiAgICAgICAgcmVjaXBpZW50RGV2aWNlSWQ6IHJlY29yZC5yZWNpcGllbnREZXZpY2VJZCxcbiAgICAgICAgcmVjZWl2ZWRBdDogcmVjb3JkLnJlY2VpdmVkQXQsXG4gICAgICAgIGV4cGlyZXNBdCxcbiAgICAgICAgc3RhdGU6IHJlY29yZC5zdGF0ZSxcbiAgICAgICAgcGF5bG9hZFJlZlxuICAgICAgfTtcbiAgICAgIGF3YWl0IHRoaXMuc3RhdGUucHV0KHN0b3JhZ2VLZXksIGluZGV4ZWQpO1xuICAgIH1cblxuICAgIGF3YWl0IHRoaXMuc3RhdGUucHV0KGAke0lERU1QT1RFTkNZX1BSRUZJWH0ke3JlY29yZC5tZXNzYWdlSWR9YCwgc2VxKTtcbiAgICBhd2FpdCB0aGlzLnN0YXRlLnB1dChNRVRBX0tFWSwgeyAuLi5tZXRhLCBoZWFkU2VxOiBzZXEgfSk7XG4gICAgYXdhaXQgdGhpcy5zdGF0ZS5zZXRBbGFybShleHBpcmVzQXQpO1xuXG4gICAgdGhpcy5wdWJsaXNoKHtcbiAgICAgIGV2ZW50OiBcImhlYWRfdXBkYXRlZFwiLFxuICAgICAgZGV2aWNlSWQ6IHRoaXMuZGV2aWNlSWQsXG4gICAgICBzZXFcbiAgICB9KTtcbiAgICB0aGlzLnB1Ymxpc2goe1xuICAgICAgZXZlbnQ6IFwiaW5ib3hfcmVjb3JkX2F2YWlsYWJsZVwiLFxuICAgICAgZGV2aWNlSWQ6IHRoaXMuZGV2aWNlSWQsXG4gICAgICBzZXEsXG4gICAgICByZWNvcmRcbiAgICB9KTtcblxuICAgIHJldHVybiB7IGFjY2VwdGVkOiB0cnVlLCBzZXEsIGRlbGl2ZXJlZFRvOiBcImluYm94XCIgfTtcbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgcXVldWVNZXNzYWdlUmVxdWVzdChpbnB1dDogQXBwZW5kRW52ZWxvcGVSZXF1ZXN0LCBub3c6IG51bWJlcik6IFByb21pc2U8QXBwZW5kRW52ZWxvcGVSZXN1bHQ+IHtcbiAgICBjb25zdCBzZW5kZXJVc2VySWQgPSBpbnB1dC5lbnZlbG9wZS5zZW5kZXJVc2VySWQ7XG4gICAgY29uc3Qga2V5ID0gdGhpcy5tZXNzYWdlUmVxdWVzdEtleShzZW5kZXJVc2VySWQpO1xuICAgIGNvbnN0IHJlcXVlc3RJZCA9IHRoaXMucmVxdWVzdElkRm9yU2VuZGVyKHNlbmRlclVzZXJJZCk7XG4gICAgY29uc3QgZXhpc3RpbmcgPSBhd2FpdCB0aGlzLnN0YXRlLmdldDxNZXNzYWdlUmVxdWVzdEVudHJ5PihrZXkpO1xuICAgIGNvbnN0IGVudHJ5OiBNZXNzYWdlUmVxdWVzdEVudHJ5ID0gZXhpc3RpbmcgPz8ge1xuICAgICAgcmVxdWVzdElkLFxuICAgICAgcmVjaXBpZW50RGV2aWNlSWQ6IHRoaXMuZGV2aWNlSWQsXG4gICAgICBzZW5kZXJVc2VySWQsXG4gICAgICBmaXJzdFNlZW5BdDogbm93LFxuICAgICAgbGFzdFNlZW5BdDogbm93LFxuICAgICAgbWVzc2FnZUNvdW50OiAwLFxuICAgICAgbGFzdE1lc3NhZ2VJZDogaW5wdXQuZW52ZWxvcGUubWVzc2FnZUlkLFxuICAgICAgbGFzdENvbnZlcnNhdGlvbklkOiBpbnB1dC5lbnZlbG9wZS5jb252ZXJzYXRpb25JZCxcbiAgICAgIHBlbmRpbmdSZXF1ZXN0czogW11cbiAgICB9O1xuICAgIGVudHJ5Lmxhc3RTZWVuQXQgPSBub3c7XG4gICAgZW50cnkubWVzc2FnZUNvdW50ICs9IDE7XG4gICAgZW50cnkubGFzdE1lc3NhZ2VJZCA9IGlucHV0LmVudmVsb3BlLm1lc3NhZ2VJZDtcbiAgICBlbnRyeS5sYXN0Q29udmVyc2F0aW9uSWQgPSBpbnB1dC5lbnZlbG9wZS5jb252ZXJzYXRpb25JZDtcbiAgICBlbnRyeS5wZW5kaW5nUmVxdWVzdHMucHVzaChpbnB1dCk7XG4gICAgYXdhaXQgdGhpcy5zdGF0ZS5wdXQoa2V5LCBlbnRyeSk7XG4gICAgYXdhaXQgdGhpcy5hZGRNZXNzYWdlUmVxdWVzdEluZGV4KHNlbmRlclVzZXJJZCk7XG4gICAgcmV0dXJuIHtcclxuICAgICAgYWNjZXB0ZWQ6IHRydWUsXHJcbiAgICAgIHNlcTogMCxcclxuICAgICAgZGVsaXZlcmVkVG86IFwibWVzc2FnZV9yZXF1ZXN0XCIsXHJcbiAgICAgIHF1ZXVlZEFzUmVxdWVzdDogdHJ1ZSxcclxuICAgICAgcmVxdWVzdElkXHJcbiAgICB9O1xuICB9XG5cbiAgcHJpdmF0ZSBhc3luYyBlbmZvcmNlUmF0ZUxpbWl0KHNlbmRlclVzZXJJZDogc3RyaW5nLCBub3c6IG51bWJlcik6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IG1ldGEgPSBhd2FpdCB0aGlzLmdldE1ldGEoKTtcbiAgICBjb25zdCBtaW51dGVMaW1pdCA9IG1ldGEucmF0ZUxpbWl0UGVyTWludXRlO1xuICAgIGNvbnN0IGhvdXJMaW1pdCA9IG1ldGEucmF0ZUxpbWl0UGVySG91cjtcbiAgICBpZiAobWludXRlTGltaXQgPD0gMCAmJiBob3VyTGltaXQgPD0gMCkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGNvbnN0IGtleSA9IGAke1JBVEVfTElNSVRfUFJFRklYfSR7c2VuZGVyVXNlcklkfWA7XG4gICAgY29uc3QgbWludXRlV2luZG93U3RhcnQgPSBNYXRoLmZsb29yKG5vdyAvIDYwXzAwMCkgKiA2MF8wMDA7XG4gICAgY29uc3QgaG91cldpbmRvd1N0YXJ0ID0gTWF0aC5mbG9vcihub3cgLyAzXzYwMF8wMDApICogM182MDBfMDAwO1xuICAgIGNvbnN0IHN0YXRlID0gKGF3YWl0IHRoaXMuc3RhdGUuZ2V0PFJhdGVMaW1pdFN0YXRlPihrZXkpKSA/PyB7XG4gICAgICBtaW51dGVXaW5kb3dTdGFydCxcbiAgICAgIG1pbnV0ZUNvdW50OiAwLFxuICAgICAgaG91cldpbmRvd1N0YXJ0LFxuICAgICAgaG91ckNvdW50OiAwXG4gICAgfTtcblxuICAgIGlmIChzdGF0ZS5taW51dGVXaW5kb3dTdGFydCAhPT0gbWludXRlV2luZG93U3RhcnQpIHtcbiAgICAgIHN0YXRlLm1pbnV0ZVdpbmRvd1N0YXJ0ID0gbWludXRlV2luZG93U3RhcnQ7XG4gICAgICBzdGF0ZS5taW51dGVDb3VudCA9IDA7XG4gICAgfVxuICAgIGlmIChzdGF0ZS5ob3VyV2luZG93U3RhcnQgIT09IGhvdXJXaW5kb3dTdGFydCkge1xuICAgICAgc3RhdGUuaG91cldpbmRvd1N0YXJ0ID0gaG91cldpbmRvd1N0YXJ0O1xuICAgICAgc3RhdGUuaG91ckNvdW50ID0gMDtcbiAgICB9XG4gICAgaWYgKG1pbnV0ZUxpbWl0ID4gMCAmJiBzdGF0ZS5taW51dGVDb3VudCA+PSBtaW51dGVMaW1pdCkge1xuICAgICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MjksIFwicmF0ZV9saW1pdGVkXCIsIFwiYXBwZW5kIHJhdGUgbGltaXQgZXhjZWVkZWQgZm9yIG1pbnV0ZSB3aW5kb3dcIik7XG4gICAgfVxuICAgIGlmIChob3VyTGltaXQgPiAwICYmIHN0YXRlLmhvdXJDb3VudCA+PSBob3VyTGltaXQpIHtcbiAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDI5LCBcInJhdGVfbGltaXRlZFwiLCBcImFwcGVuZCByYXRlIGxpbWl0IGV4Y2VlZGVkIGZvciBob3VyIHdpbmRvd1wiKTtcbiAgICB9XG5cbiAgICBzdGF0ZS5taW51dGVDb3VudCArPSAxO1xuICAgIHN0YXRlLmhvdXJDb3VudCArPSAxO1xuICAgIGF3YWl0IHRoaXMuc3RhdGUucHV0KGtleSwgc3RhdGUpO1xuICB9XG5cbiAgcHJpdmF0ZSBwdWJsaXNoKGV2ZW50OiBSZWFsdGltZUV2ZW50KTogdm9pZCB7XG4gICAgY29uc3QgcGF5bG9hZCA9IEpTT04uc3RyaW5naWZ5KGV2ZW50KTtcbiAgICBmb3IgKGNvbnN0IHNlc3Npb24gb2YgdGhpcy5zZXNzaW9ucykge1xuICAgICAgc2Vzc2lvbi5zZW5kKHBheWxvYWQpO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgdmFsaWRhdGVBcHBlbmRSZXF1ZXN0KGlucHV0OiBBcHBlbmRFbnZlbG9wZVJlcXVlc3QpOiB2b2lkIHtcbiAgICBpZiAoaW5wdXQucmVjaXBpZW50RGV2aWNlSWQgIT09IHRoaXMuZGV2aWNlSWQpIHtcbiAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAwLCBcImludmFsaWRfaW5wdXRcIiwgXCJyZWNpcGllbnRfZGV2aWNlX2lkIGRvZXMgbm90IG1hdGNoIGluYm94IHJvdXRlXCIpO1xuICAgIH1cbiAgICBpZiAoaW5wdXQuZW52ZWxvcGUucmVjaXBpZW50RGV2aWNlSWQgIT09IHRoaXMuZGV2aWNlSWQpIHtcbiAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAwLCBcImludmFsaWRfaW5wdXRcIiwgXCJlbnZlbG9wZSByZWNpcGllbnRfZGV2aWNlX2lkIGRvZXMgbm90IG1hdGNoIGluYm94IHJvdXRlXCIpO1xuICAgIH1cbiAgICBpZiAoIWlucHV0LmVudmVsb3BlLm1lc3NhZ2VJZCB8fCAhaW5wdXQuZW52ZWxvcGUuY29udmVyc2F0aW9uSWQgfHwgIWlucHV0LmVudmVsb3BlLnNlbmRlclVzZXJJZCkge1xuICAgICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDAsIFwiaW52YWxpZF9pbnB1dFwiLCBcImFwcGVuZCByZXF1ZXN0IGlzIG1pc3NpbmcgcmVxdWlyZWQgZW52ZWxvcGUgZmllbGRzXCIpO1xuICAgIH1cbiAgICBjb25zdCBoYXNJbmxpbmUgPSBCb29sZWFuKGlucHV0LmVudmVsb3BlLmlubGluZUNpcGhlcnRleHQpO1xuICAgIGNvbnN0IGhhc1N0b3JhZ2VSZWZzID0gKGlucHV0LmVudmVsb3BlLnN0b3JhZ2VSZWZzPy5sZW5ndGggPz8gMCkgPiAwO1xuICAgIGlmICghaGFzSW5saW5lICYmICFoYXNTdG9yYWdlUmVmcykge1xuICAgICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDAsIFwiaW52YWxpZF9pbnB1dFwiLCBcImVudmVsb3BlIG11c3QgaW5jbHVkZSBpbmxpbmVfY2lwaGVydGV4dCBvciBzdG9yYWdlX3JlZnNcIik7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSByZXF1ZXN0SWRGb3JTZW5kZXIoc2VuZGVyVXNlcklkOiBzdHJpbmcpOiBzdHJpbmcge1xuICAgIHJldHVybiBgcmVxdWVzdDoke3NlbmRlclVzZXJJZH1gO1xuICB9XG5cbiAgcHJpdmF0ZSBtZXNzYWdlUmVxdWVzdEtleShzZW5kZXJVc2VySWQ6IHN0cmluZyk6IHN0cmluZyB7XG4gICAgcmV0dXJuIGAke01FU1NBR0VfUkVRVUVTVF9QUkVGSVh9JHtzZW5kZXJVc2VySWR9YDtcbiAgfVxuXG4gIHByaXZhdGUgbWVzc2FnZVJlcXVlc3RJbmRleEtleSgpOiBzdHJpbmcge1xuICAgIHJldHVybiBgJHtNRVNTQUdFX1JFUVVFU1RfUFJFRklYfWluZGV4YDtcbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgYWRkTWVzc2FnZVJlcXVlc3RJbmRleChzZW5kZXJVc2VySWQ6IHN0cmluZyk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IGluZGV4ID0gKGF3YWl0IHRoaXMuc3RhdGUuZ2V0PHN0cmluZ1tdPih0aGlzLm1lc3NhZ2VSZXF1ZXN0SW5kZXhLZXkoKSkpID8/IFtdO1xuICAgIGlmICghaW5kZXguaW5jbHVkZXMoc2VuZGVyVXNlcklkKSkge1xuICAgICAgaW5kZXgucHVzaChzZW5kZXJVc2VySWQpO1xuICAgICAgaW5kZXguc29ydCgpO1xuICAgICAgYXdhaXQgdGhpcy5zdGF0ZS5wdXQodGhpcy5tZXNzYWdlUmVxdWVzdEluZGV4S2V5KCksIGluZGV4KTtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIGFzeW5jIGRlbGV0ZU1lc3NhZ2VSZXF1ZXN0KHNlbmRlclVzZXJJZDogc3RyaW5nKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgYXdhaXQgdGhpcy5zdGF0ZS5kZWxldGUodGhpcy5tZXNzYWdlUmVxdWVzdEtleShzZW5kZXJVc2VySWQpKTtcbiAgICBjb25zdCBpbmRleCA9IChhd2FpdCB0aGlzLnN0YXRlLmdldDxzdHJpbmdbXT4odGhpcy5tZXNzYWdlUmVxdWVzdEluZGV4S2V5KCkpKSA/PyBbXTtcbiAgICBhd2FpdCB0aGlzLnN0YXRlLnB1dChcbiAgICAgIHRoaXMubWVzc2FnZVJlcXVlc3RJbmRleEtleSgpLFxuICAgICAgaW5kZXguZmlsdGVyKChlbnRyeSkgPT4gZW50cnkgIT09IHNlbmRlclVzZXJJZClcbiAgICApO1xuICB9XG5cbiAgcHJpdmF0ZSBhc3luYyBmaW5kTWVzc2FnZVJlcXVlc3QocmVxdWVzdElkOiBzdHJpbmcpOiBQcm9taXNlPE1lc3NhZ2VSZXF1ZXN0RW50cnkgfCBudWxsPiB7XG4gICAgY29uc3QgcmVxdWVzdHMgPSBhd2FpdCB0aGlzLmxpc3RNZXNzYWdlUmVxdWVzdHMoKTtcbiAgICBjb25zdCBtYXRjaCA9IHJlcXVlc3RzLmZpbmQoKHJlcXVlc3QpID0+IHJlcXVlc3QucmVxdWVzdElkID09PSByZXF1ZXN0SWQpO1xuICAgIGlmICghbWF0Y2gpIHtcbiAgICAgIHJldHVybiBudWxsO1xuICAgIH1cbiAgICByZXR1cm4gKGF3YWl0IHRoaXMuc3RhdGUuZ2V0PE1lc3NhZ2VSZXF1ZXN0RW50cnk+KHRoaXMubWVzc2FnZVJlcXVlc3RLZXkobWF0Y2guc2VuZGVyVXNlcklkKSkpID8/IG51bGw7XG4gIH1cblxuICBwcml2YXRlIHRvTWVzc2FnZVJlcXVlc3RJdGVtKGVudHJ5OiBNZXNzYWdlUmVxdWVzdEVudHJ5KTogTWVzc2FnZVJlcXVlc3RJdGVtIHtcbiAgICByZXR1cm4ge1xuICAgICAgcmVxdWVzdElkOiBlbnRyeS5yZXF1ZXN0SWQsXG4gICAgICByZWNpcGllbnREZXZpY2VJZDogZW50cnkucmVjaXBpZW50RGV2aWNlSWQsXG4gICAgICBzZW5kZXJVc2VySWQ6IGVudHJ5LnNlbmRlclVzZXJJZCxcbiAgICAgIGZpcnN0U2VlbkF0OiBlbnRyeS5maXJzdFNlZW5BdCxcbiAgICAgIGxhc3RTZWVuQXQ6IGVudHJ5Lmxhc3RTZWVuQXQsXG4gICAgICBtZXNzYWdlQ291bnQ6IGVudHJ5Lm1lc3NhZ2VDb3VudCxcbiAgICAgIGxhc3RNZXNzYWdlSWQ6IGVudHJ5Lmxhc3RNZXNzYWdlSWQsXG4gICAgICBsYXN0Q29udmVyc2F0aW9uSWQ6IGVudHJ5Lmxhc3RDb252ZXJzYXRpb25JZFxuICAgIH07XG4gIH1cbn1cclxuXHJcblxyXG5cclxuXHJcblxyXG4iLCAiaW1wb3J0IHsgSHR0cEVycm9yIH0gZnJvbSBcIi4uL2F1dGgvY2FwYWJpbGl0eVwiO1xuaW1wb3J0IHsgSW5ib3hTZXJ2aWNlIH0gZnJvbSBcIi4vc2VydmljZVwiO1xuaW1wb3J0IHR5cGUge1xuICBBY2tSZXF1ZXN0LFxuICBBbGxvd2xpc3REb2N1bWVudCxcbiAgQXBwZW5kRW52ZWxvcGVSZXF1ZXN0LFxuICBGZXRjaE1lc3NhZ2VzUmVxdWVzdFxufSBmcm9tIFwiLi4vdHlwZXMvY29udHJhY3RzXCI7XG5pbXBvcnQgdHlwZSB7IER1cmFibGVPYmplY3RTdG9yYWdlTGlrZSwgRW52LCBKc29uQmxvYlN0b3JlLCBTZXNzaW9uU2luayB9IGZyb20gXCIuLi90eXBlcy9ydW50aW1lXCI7XG5cbmNsYXNzIER1cmFibGVPYmplY3RTdG9yYWdlQWRhcHRlciBpbXBsZW1lbnRzIER1cmFibGVPYmplY3RTdG9yYWdlTGlrZSB7XG4gIHByaXZhdGUgcmVhZG9ubHkgc3RvcmFnZTogRHVyYWJsZU9iamVjdFN0YXRlW1wic3RvcmFnZVwiXTtcblxuICBjb25zdHJ1Y3RvcihzdG9yYWdlOiBEdXJhYmxlT2JqZWN0U3RhdGVbXCJzdG9yYWdlXCJdKSB7XG4gICAgdGhpcy5zdG9yYWdlID0gc3RvcmFnZTtcbiAgfVxuXG4gIGFzeW5jIGdldDxUPihrZXk6IHN0cmluZyk6IFByb21pc2U8VCB8IHVuZGVmaW5lZD4ge1xuICAgIHJldHVybiAoYXdhaXQgdGhpcy5zdG9yYWdlLmdldDxUPihrZXkpKSA/PyB1bmRlZmluZWQ7XG4gIH1cblxuICBhc3luYyBwdXQ8VD4oa2V5OiBzdHJpbmcsIHZhbHVlOiBUKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgYXdhaXQgdGhpcy5zdG9yYWdlLnB1dChrZXksIHZhbHVlKTtcbiAgfVxuXG4gIGFzeW5jIGRlbGV0ZShrZXk6IHN0cmluZyk6IFByb21pc2U8dm9pZD4ge1xuICAgIGF3YWl0IHRoaXMuc3RvcmFnZS5kZWxldGUoa2V5KTtcbiAgfVxuXG4gIGFzeW5jIHNldEFsYXJtKGVwb2NoTWlsbGlzOiBudW1iZXIpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLnN0b3JhZ2Uuc2V0QWxhcm0oZXBvY2hNaWxsaXMpO1xuICB9XG59XG5cbmNsYXNzIFIySnNvbkJsb2JTdG9yZSBpbXBsZW1lbnRzIEpzb25CbG9iU3RvcmUge1xuICBwcml2YXRlIHJlYWRvbmx5IGJ1Y2tldDogRW52W1wiVEFQQ0hBVF9TVE9SQUdFXCJdO1xuXG4gIGNvbnN0cnVjdG9yKGJ1Y2tldDogRW52W1wiVEFQQ0hBVF9TVE9SQUdFXCJdKSB7XG4gICAgdGhpcy5idWNrZXQgPSBidWNrZXQ7XG4gIH1cblxuICBhc3luYyBwdXRKc29uPFQ+KGtleTogc3RyaW5nLCB2YWx1ZTogVCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGF3YWl0IHRoaXMuYnVja2V0LnB1dChrZXksIEpTT04uc3RyaW5naWZ5KHZhbHVlKSk7XG4gIH1cblxuICBhc3luYyBnZXRKc29uPFQ+KGtleTogc3RyaW5nKTogUHJvbWlzZTxUIHwgbnVsbD4ge1xuICAgIGNvbnN0IG9iamVjdCA9IGF3YWl0IHRoaXMuYnVja2V0LmdldChrZXkpO1xuICAgIGlmICghb2JqZWN0KSB7XG4gICAgICByZXR1cm4gbnVsbDtcbiAgICB9XG4gICAgcmV0dXJuIGF3YWl0IG9iamVjdC5qc29uPFQ+KCk7XG4gIH1cblxuICBhc3luYyBwdXRCeXRlcyhrZXk6IHN0cmluZywgdmFsdWU6IEFycmF5QnVmZmVyIHwgVWludDhBcnJheSk6IFByb21pc2U8dm9pZD4ge1xuICAgIGF3YWl0IHRoaXMuYnVja2V0LnB1dChrZXksIHZhbHVlKTtcbiAgfVxuXG4gIGFzeW5jIGdldEJ5dGVzKGtleTogc3RyaW5nKTogUHJvbWlzZTxBcnJheUJ1ZmZlciB8IG51bGw+IHtcbiAgICBjb25zdCBvYmplY3QgPSBhd2FpdCB0aGlzLmJ1Y2tldC5nZXQoa2V5KTtcbiAgICBpZiAoIW9iamVjdCkge1xuICAgICAgcmV0dXJuIG51bGw7XG4gICAgfVxuICAgIHJldHVybiBvYmplY3QuYXJyYXlCdWZmZXIoKTtcbiAgfVxuXG4gIGFzeW5jIGRlbGV0ZShrZXk6IHN0cmluZyk6IFByb21pc2U8dm9pZD4ge1xuICAgIGF3YWl0IHRoaXMuYnVja2V0LmRlbGV0ZShrZXkpO1xuICB9XG59XG5cbmZ1bmN0aW9uIHZlcnNpb25lZEJvZHkoYm9keTogdW5rbm93bik6IHVua25vd24ge1xuICBpZiAoIWJvZHkgfHwgdHlwZW9mIGJvZHkgIT09IFwib2JqZWN0XCIgfHwgQXJyYXkuaXNBcnJheShib2R5KSkge1xuICAgIHJldHVybiBib2R5O1xuICB9XG4gIGNvbnN0IHJlY29yZCA9IGJvZHkgYXMgUmVjb3JkPHN0cmluZywgdW5rbm93bj47XG4gIGlmIChyZWNvcmQudmVyc2lvbiAhPT0gdW5kZWZpbmVkKSB7XG4gICAgcmV0dXJuIGJvZHk7XG4gIH1cbiAgcmV0dXJuIHtcbiAgICB2ZXJzaW9uOiBcIjAuMVwiLFxuICAgIC4uLnJlY29yZFxuICB9O1xufVxuXG5mdW5jdGlvbiBqc29uUmVzcG9uc2UoYm9keTogdW5rbm93biwgc3RhdHVzID0gMjAwKTogUmVzcG9uc2Uge1xuICByZXR1cm4gbmV3IFJlc3BvbnNlKEpTT04uc3RyaW5naWZ5KHZlcnNpb25lZEJvZHkoYm9keSkpLCB7XG4gICAgc3RhdHVzLFxuICAgIGhlYWRlcnM6IHtcbiAgICAgIFwiY29udGVudC10eXBlXCI6IFwiYXBwbGljYXRpb24vanNvblwiXG4gICAgfVxuICB9KTtcbn1cblxuY29uc3QgRHVyYWJsZU9iamVjdEJhc2U6IHR5cGVvZiBEdXJhYmxlT2JqZWN0ID1cbiAgKGdsb2JhbFRoaXMgYXMgeyBEdXJhYmxlT2JqZWN0PzogdHlwZW9mIER1cmFibGVPYmplY3QgfSkuRHVyYWJsZU9iamVjdCA/P1xuICAoY2xhc3Mge1xuICAgIGNvbnN0cnVjdG9yKF9zdGF0ZTogRHVyYWJsZU9iamVjdFN0YXRlLCBfZW52OiBFbnYpIHt9XG4gIH0gYXMgdW5rbm93biBhcyB0eXBlb2YgRHVyYWJsZU9iamVjdCk7XG5cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBoYW5kbGVJbmJveER1cmFibGVSZXF1ZXN0KFxuICByZXF1ZXN0OiBSZXF1ZXN0LFxuICBkZXBzOiB7XG4gICAgZGV2aWNlSWQ6IHN0cmluZztcbiAgICBzdGF0ZTogRHVyYWJsZU9iamVjdFN0b3JhZ2VMaWtlO1xuICAgIHNwaWxsU3RvcmU6IEpzb25CbG9iU3RvcmU7XG4gICAgc2Vzc2lvbnM6IFNlc3Npb25TaW5rW107XG4gICAgbWF4SW5saW5lQnl0ZXM6IG51bWJlcjtcbiAgICByZXRlbnRpb25EYXlzOiBudW1iZXI7XG4gICAgcmF0ZUxpbWl0UGVyTWludXRlOiBudW1iZXI7XG4gICAgcmF0ZUxpbWl0UGVySG91cjogbnVtYmVyO1xuICAgIG9uVXBncmFkZT86ICgpID0+IFJlc3BvbnNlO1xuICAgIG5vdz86IG51bWJlcjtcbiAgfVxuKTogUHJvbWlzZTxSZXNwb25zZT4ge1xuICBjb25zdCBub3cgPSBkZXBzLm5vdyA/PyBEYXRlLm5vdygpO1xuICBjb25zdCB1cmwgPSBuZXcgVVJMKHJlcXVlc3QudXJsKTtcbiAgY29uc3Qgc2VydmljZSA9IG5ldyBJbmJveFNlcnZpY2UoZGVwcy5kZXZpY2VJZCwgZGVwcy5zdGF0ZSwgZGVwcy5zcGlsbFN0b3JlLCBkZXBzLnNlc3Npb25zLCB7XG4gICAgaGVhZFNlcTogMCxcbiAgICBhY2tlZFNlcTogMCxcbiAgICByZXRlbnRpb25EYXlzOiBkZXBzLnJldGVudGlvbkRheXMsXG4gICAgbWF4SW5saW5lQnl0ZXM6IGRlcHMubWF4SW5saW5lQnl0ZXMsXG4gICAgcmF0ZUxpbWl0UGVyTWludXRlOiBkZXBzLnJhdGVMaW1pdFBlck1pbnV0ZSxcbiAgICByYXRlTGltaXRQZXJIb3VyOiBkZXBzLnJhdGVMaW1pdFBlckhvdXJcbiAgfSk7XG5cbiAgdHJ5IHtcbiAgICBpZiAodXJsLnBhdGhuYW1lLmVuZHNXaXRoKFwiL3N1YnNjcmliZVwiKSkge1xuICAgICAgaWYgKHJlcXVlc3QuaGVhZGVycy5nZXQoXCJVcGdyYWRlXCIpPy50b0xvd2VyQ2FzZSgpICE9PSBcIndlYnNvY2tldFwiKSB7XG4gICAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAwLCBcImludmFsaWRfaW5wdXRcIiwgXCJzdWJzY3JpYmUgcmVxdWlyZXMgd2Vic29ja2V0IHVwZ3JhZGVcIik7XG4gICAgICB9XG4gICAgICBpZiAoIWRlcHMub25VcGdyYWRlKSB7XG4gICAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNTAwLCBcInRlbXBvcmFyeV91bmF2YWlsYWJsZVwiLCBcIndlYnNvY2tldCB1cGdyYWRlIGhhbmRsZXIgaXMgdW5hdmFpbGFibGVcIik7XG4gICAgICB9XG4gICAgICByZXR1cm4gZGVwcy5vblVwZ3JhZGUoKTtcbiAgICB9XG5cbiAgICBpZiAodXJsLnBhdGhuYW1lLmVuZHNXaXRoKFwiL21lc3NhZ2UtcmVxdWVzdHNcIikgJiYgcmVxdWVzdC5tZXRob2QgPT09IFwiR0VUXCIpIHtcbiAgICAgIHJldHVybiBqc29uUmVzcG9uc2UoeyByZXF1ZXN0czogYXdhaXQgc2VydmljZS5saXN0TWVzc2FnZVJlcXVlc3RzKCkgfSk7XG4gICAgfVxuXG4gICAgY29uc3QgcmVxdWVzdEFjdGlvbk1hdGNoID0gdXJsLnBhdGhuYW1lLm1hdGNoKC9cXC9tZXNzYWdlLXJlcXVlc3RzXFwvKFteL10rKVxcLyhhY2NlcHR8cmVqZWN0KSQvKTtcbiAgICBpZiAocmVxdWVzdEFjdGlvbk1hdGNoICYmIHJlcXVlc3QubWV0aG9kID09PSBcIlBPU1RcIikge1xuICAgICAgY29uc3QgcmVxdWVzdElkID0gZGVjb2RlVVJJQ29tcG9uZW50KHJlcXVlc3RBY3Rpb25NYXRjaFsxXSk7XG4gICAgICBjb25zdCBhY3Rpb24gPSByZXF1ZXN0QWN0aW9uTWF0Y2hbMl07XG4gICAgICBjb25zdCByZXN1bHQgPSBhY3Rpb24gPT09IFwiYWNjZXB0XCJcbiAgICAgICAgPyBhd2FpdCBzZXJ2aWNlLmFjY2VwdE1lc3NhZ2VSZXF1ZXN0KHJlcXVlc3RJZCwgbm93KVxuICAgICAgICA6IGF3YWl0IHNlcnZpY2UucmVqZWN0TWVzc2FnZVJlcXVlc3QocmVxdWVzdElkLCBub3cpO1xuICAgICAgcmV0dXJuIGpzb25SZXNwb25zZShyZXN1bHQpO1xuICAgIH1cblxuICAgIGlmICh1cmwucGF0aG5hbWUuZW5kc1dpdGgoXCIvYWxsb3dsaXN0XCIpICYmIHJlcXVlc3QubWV0aG9kID09PSBcIkdFVFwiKSB7XG4gICAgICByZXR1cm4ganNvblJlc3BvbnNlKGF3YWl0IHNlcnZpY2UuZ2V0QWxsb3dsaXN0KG5vdykpO1xuICAgIH1cblxuICAgIGlmICh1cmwucGF0aG5hbWUuZW5kc1dpdGgoXCIvYWxsb3dsaXN0XCIpICYmIHJlcXVlc3QubWV0aG9kID09PSBcIlBVVFwiKSB7XG4gICAgICBjb25zdCBib2R5ID0gKGF3YWl0IHJlcXVlc3QuanNvbigpKSBhcyBQYXJ0aWFsPEFsbG93bGlzdERvY3VtZW50PjtcbiAgICAgIGNvbnN0IHJlc3VsdCA9IGF3YWl0IHNlcnZpY2UucmVwbGFjZUFsbG93bGlzdChcbiAgICAgICAgYm9keS5hbGxvd2VkU2VuZGVyVXNlcklkcyA/PyBbXSxcbiAgICAgICAgYm9keS5yZWplY3RlZFNlbmRlclVzZXJJZHMgPz8gW10sXG4gICAgICAgIG5vd1xuICAgICAgKTtcbiAgICAgIHJldHVybiBqc29uUmVzcG9uc2UocmVzdWx0KTtcbiAgICB9XG5cbiAgICBpZiAodXJsLnBhdGhuYW1lLmVuZHNXaXRoKFwiL21lc3NhZ2VzXCIpICYmIHJlcXVlc3QubWV0aG9kID09PSBcIlBPU1RcIikge1xuICAgICAgY29uc3QgYm9keSA9IChhd2FpdCByZXF1ZXN0Lmpzb24oKSkgYXMgQXBwZW5kRW52ZWxvcGVSZXF1ZXN0O1xuICAgICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgc2VydmljZS5hcHBlbmRFbnZlbG9wZShib2R5LCBub3cpO1xuICAgICAgcmV0dXJuIGpzb25SZXNwb25zZShyZXN1bHQpO1xuICAgIH1cblxuICAgIGlmICh1cmwucGF0aG5hbWUuZW5kc1dpdGgoXCIvbWVzc2FnZXNcIikgJiYgcmVxdWVzdC5tZXRob2QgPT09IFwiR0VUXCIpIHtcbiAgICAgIGNvbnN0IGZyb21TZXEgPSBOdW1iZXIodXJsLnNlYXJjaFBhcmFtcy5nZXQoXCJmcm9tU2VxXCIpID8/IFwiMVwiKTtcbiAgICAgIGNvbnN0IGxpbWl0ID0gTnVtYmVyKHVybC5zZWFyY2hQYXJhbXMuZ2V0KFwibGltaXRcIikgPz8gXCIxMDBcIik7XG4gICAgICBjb25zdCByZXN1bHQgPSBhd2FpdCBzZXJ2aWNlLmZldGNoTWVzc2FnZXMoe1xuICAgICAgICBkZXZpY2VJZDogZGVwcy5kZXZpY2VJZCxcbiAgICAgICAgZnJvbVNlcSxcbiAgICAgICAgbGltaXRcbiAgICAgIH0gYXMgRmV0Y2hNZXNzYWdlc1JlcXVlc3QpO1xuICAgICAgcmV0dXJuIGpzb25SZXNwb25zZSh7XG4gICAgICAgIHRvU2VxOiByZXN1bHQudG9TZXEsXG4gICAgICAgIHJlY29yZHM6IHJlc3VsdC5yZWNvcmRzXG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBpZiAodXJsLnBhdGhuYW1lLmVuZHNXaXRoKFwiL2Fja1wiKSAmJiByZXF1ZXN0Lm1ldGhvZCA9PT0gXCJQT1NUXCIpIHtcbiAgICAgIGNvbnN0IGJvZHkgPSAoYXdhaXQgcmVxdWVzdC5qc29uKCkpIGFzIEFja1JlcXVlc3Q7XG4gICAgICBjb25zdCByZXN1bHQgPSBhd2FpdCBzZXJ2aWNlLmFjayhib2R5KTtcbiAgICAgIHJldHVybiBqc29uUmVzcG9uc2Uoe1xuICAgICAgICBhY2NlcHRlZDogcmVzdWx0LmFjY2VwdGVkLFxuICAgICAgICBhY2tTZXE6IHJlc3VsdC5hY2tTZXFcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGlmICh1cmwucGF0aG5hbWUuZW5kc1dpdGgoXCIvaGVhZFwiKSAmJiByZXF1ZXN0Lm1ldGhvZCA9PT0gXCJHRVRcIikge1xuICAgICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgc2VydmljZS5nZXRIZWFkKCk7XG4gICAgICByZXR1cm4ganNvblJlc3BvbnNlKHJlc3VsdCk7XG4gICAgfVxuXG4gICAgcmV0dXJuIGpzb25SZXNwb25zZSh7IGVycm9yOiBcIm5vdF9mb3VuZFwiIH0sIDQwNCk7XG4gIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgaWYgKGVycm9yIGluc3RhbmNlb2YgSHR0cEVycm9yKSB7XG4gICAgICByZXR1cm4ganNvblJlc3BvbnNlKHsgZXJyb3I6IGVycm9yLmNvZGUsIG1lc3NhZ2U6IGVycm9yLm1lc3NhZ2UgfSwgZXJyb3Iuc3RhdHVzKTtcbiAgICB9XG4gICAgY29uc3QgcnVudGltZUVycm9yID0gZXJyb3IgYXMgeyBtZXNzYWdlPzogc3RyaW5nIH07XG4gICAgY29uc3QgbWVzc2FnZSA9IHJ1bnRpbWVFcnJvci5tZXNzYWdlID8/IFwiaW50ZXJuYWwgZXJyb3JcIjtcbiAgICByZXR1cm4ganNvblJlc3BvbnNlKHsgZXJyb3I6IFwidGVtcG9yYXJ5X3VuYXZhaWxhYmxlXCIsIG1lc3NhZ2UgfSwgNTAwKTtcbiAgfVxufVxuXG5leHBvcnQgY2xhc3MgSW5ib3hEdXJhYmxlT2JqZWN0IGV4dGVuZHMgRHVyYWJsZU9iamVjdEJhc2Uge1xuICBwcml2YXRlIHJlYWRvbmx5IHNlc3Npb25zID0gbmV3IE1hcDxzdHJpbmcsIE1hbmFnZWRTZXNzaW9uPigpO1xuICBwcml2YXRlIHJlYWRvbmx5IHN0YXRlUmVmOiBEdXJhYmxlT2JqZWN0U3RhdGU7XG4gIHByaXZhdGUgcmVhZG9ubHkgZW52UmVmOiBFbnY7XG5cbiAgY29uc3RydWN0b3Ioc3RhdGU6IER1cmFibGVPYmplY3RTdGF0ZSwgZW52OiBFbnYpIHtcbiAgICBzdXBlcihzdGF0ZSwgZW52KTtcbiAgICB0aGlzLnN0YXRlUmVmID0gc3RhdGU7XG4gICAgdGhpcy5lbnZSZWYgPSBlbnY7XG4gIH1cblxuICBhc3luYyBmZXRjaChyZXF1ZXN0OiBSZXF1ZXN0KTogUHJvbWlzZTxSZXNwb25zZT4ge1xuICAgIGNvbnN0IHVybCA9IG5ldyBVUkwocmVxdWVzdC51cmwpO1xuICAgIGNvbnN0IG1hdGNoID0gdXJsLnBhdGhuYW1lLm1hdGNoKC9cXC92MVxcL2luYm94XFwvKFteL10rKVxcLy8pO1xuICAgIGNvbnN0IGRldmljZUlkID0gZGVjb2RlVVJJQ29tcG9uZW50KG1hdGNoPy5bMV0gPz8gXCJcIik7XG5cbiAgICByZXR1cm4gaGFuZGxlSW5ib3hEdXJhYmxlUmVxdWVzdChyZXF1ZXN0LCB7XG4gICAgICBkZXZpY2VJZCxcbiAgICAgIHN0YXRlOiBuZXcgRHVyYWJsZU9iamVjdFN0b3JhZ2VBZGFwdGVyKHRoaXMuc3RhdGVSZWYuc3RvcmFnZSksXG4gICAgICBzcGlsbFN0b3JlOiBuZXcgUjJKc29uQmxvYlN0b3JlKHRoaXMuZW52UmVmLlRBUENIQVRfU1RPUkFHRSksXG4gICAgICBzZXNzaW9uczogQXJyYXkuZnJvbSh0aGlzLnNlc3Npb25zLnZhbHVlcygpKS5tYXAoXG4gICAgICAgIChzZXNzaW9uKSA9PlxuICAgICAgICAgICh7XG4gICAgICAgICAgICBzZW5kKHBheWxvYWQ6IHN0cmluZyk6IHZvaWQge1xuICAgICAgICAgICAgICBzZXNzaW9uLnNlbmQocGF5bG9hZCk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfSkgc2F0aXNmaWVzIFNlc3Npb25TaW5rXG4gICAgICApLFxuICAgICAgbWF4SW5saW5lQnl0ZXM6IE51bWJlcih0aGlzLmVudlJlZi5NQVhfSU5MSU5FX0JZVEVTID8/IFwiNDA5NlwiKSxcbiAgICAgIHJldGVudGlvbkRheXM6IE51bWJlcih0aGlzLmVudlJlZi5SRVRFTlRJT05fREFZUyA/PyBcIjMwXCIpLFxuICAgICAgcmF0ZUxpbWl0UGVyTWludXRlOiBOdW1iZXIodGhpcy5lbnZSZWYuUkFURV9MSU1JVF9QRVJfTUlOVVRFID8/IFwiNjBcIiksXG4gICAgICByYXRlTGltaXRQZXJIb3VyOiBOdW1iZXIodGhpcy5lbnZSZWYuUkFURV9MSU1JVF9QRVJfSE9VUiA/PyBcIjYwMFwiKSxcbiAgICAgIG9uVXBncmFkZTogKCkgPT4ge1xuICAgICAgICBjb25zdCBwYWlyID0gbmV3IFdlYlNvY2tldFBhaXIoKTtcbiAgICAgICAgY29uc3QgY2xpZW50ID0gcGFpclswXTtcbiAgICAgICAgY29uc3Qgc2VydmVyID0gcGFpclsxXTtcbiAgICAgICAgc2VydmVyLmFjY2VwdCgpO1xuICAgICAgICBjb25zdCBzZXNzaW9uSWQgPSBjcnlwdG8ucmFuZG9tVVVJRCgpO1xuICAgICAgICBjb25zdCBzZXNzaW9uID0gbmV3IE1hbmFnZWRTZXNzaW9uKHNlcnZlcik7XG4gICAgICAgIHRoaXMuc2Vzc2lvbnMuc2V0KHNlc3Npb25JZCwgc2Vzc2lvbik7XG4gICAgICAgIHF1ZXVlTWljcm90YXNrKCgpID0+IHtcbiAgICAgICAgICBzZXNzaW9uLm1hcmtSZWFkeSgpO1xuICAgICAgICB9KTtcbiAgICAgICAgc2VydmVyLmFkZEV2ZW50TGlzdGVuZXIoXCJjbG9zZVwiLCAoKSA9PiB7XG4gICAgICAgICAgdGhpcy5zZXNzaW9ucy5kZWxldGUoc2Vzc2lvbklkKTtcbiAgICAgICAgfSk7XG4gICAgICAgIHJldHVybiBuZXcgUmVzcG9uc2UobnVsbCwge1xuICAgICAgICAgIHN0YXR1czogMTAxLFxuICAgICAgICAgIHdlYlNvY2tldDogY2xpZW50XG4gICAgICAgIH0gYXMgUmVzcG9uc2VJbml0ICYgeyB3ZWJTb2NrZXQ6IFdlYlNvY2tldCB9KTtcbiAgICAgIH1cbiAgICB9KTtcbiAgfVxuXG4gIGFzeW5jIGFsYXJtKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IHNlcnZpY2UgPSBuZXcgSW5ib3hTZXJ2aWNlKFxuICAgICAgXCJcIixcbiAgICAgIG5ldyBEdXJhYmxlT2JqZWN0U3RvcmFnZUFkYXB0ZXIodGhpcy5zdGF0ZVJlZi5zdG9yYWdlKSxcbiAgICAgIG5ldyBSMkpzb25CbG9iU3RvcmUodGhpcy5lbnZSZWYuVEFQQ0hBVF9TVE9SQUdFKSxcbiAgICAgIFtdLFxuICAgICAge1xuICAgICAgICBoZWFkU2VxOiAwLFxuICAgICAgICBhY2tlZFNlcTogMCxcbiAgICAgICAgcmV0ZW50aW9uRGF5czogTnVtYmVyKHRoaXMuZW52UmVmLlJFVEVOVElPTl9EQVlTID8/IFwiMzBcIiksXG4gICAgICAgIG1heElubGluZUJ5dGVzOiBOdW1iZXIodGhpcy5lbnZSZWYuTUFYX0lOTElORV9CWVRFUyA/PyBcIjQwOTZcIiksXG4gICAgICAgIHJhdGVMaW1pdFBlck1pbnV0ZTogTnVtYmVyKHRoaXMuZW52UmVmLlJBVEVfTElNSVRfUEVSX01JTlVURSA/PyBcIjYwXCIpLFxuICAgICAgICByYXRlTGltaXRQZXJIb3VyOiBOdW1iZXIodGhpcy5lbnZSZWYuUkFURV9MSU1JVF9QRVJfSE9VUiA/PyBcIjYwMFwiKVxuICAgICAgfVxuICAgICk7XG4gICAgYXdhaXQgc2VydmljZS5jbGVhbkV4cGlyZWRSZWNvcmRzKERhdGUubm93KCkpO1xuICB9XG59XG5cbmNsYXNzIE1hbmFnZWRTZXNzaW9uIHtcbiAgcHJpdmF0ZSByZWFkb25seSBzb2NrZXQ6IFdlYlNvY2tldDtcbiAgcHJpdmF0ZSByZWFkeSA9IGZhbHNlO1xuICBwcml2YXRlIHJlYWRvbmx5IHF1ZXVlZFBheWxvYWRzOiBzdHJpbmdbXSA9IFtdO1xuXG4gIGNvbnN0cnVjdG9yKHNvY2tldDogV2ViU29ja2V0KSB7XG4gICAgdGhpcy5zb2NrZXQgPSBzb2NrZXQ7XG4gIH1cblxuICBzZW5kKHBheWxvYWQ6IHN0cmluZyk6IHZvaWQge1xuICAgIGlmICghdGhpcy5yZWFkeSkge1xuICAgICAgdGhpcy5xdWV1ZWRQYXlsb2Fkcy5wdXNoKHBheWxvYWQpO1xuICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICB0aGlzLmRpc3BhdGNoKHBheWxvYWQpO1xuICB9XG5cbiAgbWFya1JlYWR5KCk6IHZvaWQge1xuICAgIGlmICh0aGlzLnJlYWR5KSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuICAgIHRoaXMucmVhZHkgPSB0cnVlO1xuICAgIHdoaWxlICh0aGlzLnF1ZXVlZFBheWxvYWRzLmxlbmd0aCA+IDApIHtcbiAgICAgIGNvbnN0IHBheWxvYWQgPSB0aGlzLnF1ZXVlZFBheWxvYWRzLnNoaWZ0KCk7XG4gICAgICBpZiAocGF5bG9hZCA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIGJyZWFrO1xuICAgICAgfVxuICAgICAgdGhpcy5kaXNwYXRjaChwYXlsb2FkKTtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIGRpc3BhdGNoKHBheWxvYWQ6IHN0cmluZyk6IHZvaWQge1xuICAgIHNldFRpbWVvdXQoKCkgPT4ge1xuICAgICAgdGhpcy5zb2NrZXQuc2VuZChwYXlsb2FkKTtcbiAgICB9LCAwKTtcbiAgfVxufVxyXG4iLCAiaW1wb3J0IHsgSHR0cEVycm9yIH0gZnJvbSBcIi4uL2F1dGgvY2FwYWJpbGl0eVwiO1xuaW1wb3J0IHR5cGUge1xuICBEZXZpY2VMaXN0RG9jdW1lbnQsXG4gIERldmljZVN0YXR1c0RvY3VtZW50LFxuICBJZGVudGl0eUJ1bmRsZSxcbiAgS2V5UGFja2FnZVJlZnNEb2N1bWVudFxufSBmcm9tIFwiLi4vdHlwZXMvY29udHJhY3RzXCI7XG5pbXBvcnQgdHlwZSB7IEpzb25CbG9iU3RvcmUgfSBmcm9tIFwiLi4vdHlwZXMvcnVudGltZVwiO1xuXG5mdW5jdGlvbiBzYW5pdGl6ZVNlZ21lbnQodmFsdWU6IHN0cmluZyk6IHN0cmluZyB7XG4gIHJldHVybiB2YWx1ZS5yZXBsYWNlKC9bXmEtekEtWjAtOTpfLV0vZywgXCJfXCIpO1xufVxuXG5leHBvcnQgY2xhc3MgU2hhcmVkU3RhdGVTZXJ2aWNlIHtcbiAgcHJpdmF0ZSByZWFkb25seSBzdG9yZTogSnNvbkJsb2JTdG9yZTtcbiAgcHJpdmF0ZSByZWFkb25seSBiYXNlVXJsOiBzdHJpbmc7XG5cbiAgY29uc3RydWN0b3Ioc3RvcmU6IEpzb25CbG9iU3RvcmUsIGJhc2VVcmw6IHN0cmluZykge1xuICAgIHRoaXMuc3RvcmUgPSBzdG9yZTtcbiAgICB0aGlzLmJhc2VVcmwgPSBiYXNlVXJsO1xuICB9XG5cbiAgaWRlbnRpdHlCdW5kbGVLZXkodXNlcklkOiBzdHJpbmcpOiBzdHJpbmcge1xuICAgIHJldHVybiBgc2hhcmVkLXN0YXRlLyR7c2FuaXRpemVTZWdtZW50KHVzZXJJZCl9L2lkZW50aXR5X2J1bmRsZS5qc29uYDtcbiAgfVxuXG4gIGRldmljZUxpc3RLZXkodXNlcklkOiBzdHJpbmcpOiBzdHJpbmcge1xuICAgIHJldHVybiBgc2hhcmVkLXN0YXRlLyR7c2FuaXRpemVTZWdtZW50KHVzZXJJZCl9L2RldmljZV9saXN0Lmpzb25gO1xuICB9XG5cbiAgZGV2aWNlU3RhdHVzS2V5KHVzZXJJZDogc3RyaW5nKTogc3RyaW5nIHtcbiAgICByZXR1cm4gYHNoYXJlZC1zdGF0ZS8ke3Nhbml0aXplU2VnbWVudCh1c2VySWQpfS9kZXZpY2Vfc3RhdHVzLmpzb25gO1xuICB9XG5cbiAga2V5UGFja2FnZVJlZnNLZXkodXNlcklkOiBzdHJpbmcsIGRldmljZUlkOiBzdHJpbmcpOiBzdHJpbmcge1xuICAgIHJldHVybiBga2V5cGFja2FnZXMvJHtzYW5pdGl6ZVNlZ21lbnQodXNlcklkKX0vJHtzYW5pdGl6ZVNlZ21lbnQoZGV2aWNlSWQpfS9yZWZzLmpzb25gO1xuICB9XG5cbiAga2V5UGFja2FnZU9iamVjdEtleSh1c2VySWQ6IHN0cmluZywgZGV2aWNlSWQ6IHN0cmluZywga2V5UGFja2FnZUlkOiBzdHJpbmcpOiBzdHJpbmcge1xuICAgIHJldHVybiBga2V5cGFja2FnZXMvJHtzYW5pdGl6ZVNlZ21lbnQodXNlcklkKX0vJHtzYW5pdGl6ZVNlZ21lbnQoZGV2aWNlSWQpfS8ke3Nhbml0aXplU2VnbWVudChrZXlQYWNrYWdlSWQpfS5iaW5gO1xuICB9XG5cbiAgaWRlbnRpdHlCdW5kbGVVcmwodXNlcklkOiBzdHJpbmcpOiBzdHJpbmcge1xuICAgIHJldHVybiBgJHt0aGlzLmJhc2VVcmx9L3YxL3NoYXJlZC1zdGF0ZS8ke2VuY29kZVVSSUNvbXBvbmVudCh1c2VySWQpfS9pZGVudGl0eS1idW5kbGVgO1xuICB9XG5cbiAgZGV2aWNlU3RhdHVzVXJsKHVzZXJJZDogc3RyaW5nKTogc3RyaW5nIHtcbiAgICByZXR1cm4gYCR7dGhpcy5iYXNlVXJsfS92MS9zaGFyZWQtc3RhdGUvJHtlbmNvZGVVUklDb21wb25lbnQodXNlcklkKX0vZGV2aWNlLXN0YXR1c2A7XG4gIH1cblxuICBrZXlQYWNrYWdlUmVmc1VybCh1c2VySWQ6IHN0cmluZywgZGV2aWNlSWQ6IHN0cmluZyk6IHN0cmluZyB7XG4gICAgcmV0dXJuIGAke3RoaXMuYmFzZVVybH0vdjEvc2hhcmVkLXN0YXRlL2tleXBhY2thZ2VzLyR7ZW5jb2RlVVJJQ29tcG9uZW50KHVzZXJJZCl9LyR7ZW5jb2RlVVJJQ29tcG9uZW50KGRldmljZUlkKX1gO1xuICB9XG5cbiAga2V5UGFja2FnZU9iamVjdFVybCh1c2VySWQ6IHN0cmluZywgZGV2aWNlSWQ6IHN0cmluZywga2V5UGFja2FnZUlkOiBzdHJpbmcpOiBzdHJpbmcge1xuICAgIHJldHVybiBgJHt0aGlzLmJhc2VVcmx9L3YxL3NoYXJlZC1zdGF0ZS9rZXlwYWNrYWdlcy8ke2VuY29kZVVSSUNvbXBvbmVudCh1c2VySWQpfS8ke2VuY29kZVVSSUNvbXBvbmVudChkZXZpY2VJZCl9LyR7ZW5jb2RlVVJJQ29tcG9uZW50KGtleVBhY2thZ2VJZCl9YDtcbiAgfVxuXG4gIGFzeW5jIGdldElkZW50aXR5QnVuZGxlKHVzZXJJZDogc3RyaW5nKTogUHJvbWlzZTxJZGVudGl0eUJ1bmRsZSB8IG51bGw+IHtcbiAgICByZXR1cm4gdGhpcy5zdG9yZS5nZXRKc29uPElkZW50aXR5QnVuZGxlPih0aGlzLmlkZW50aXR5QnVuZGxlS2V5KHVzZXJJZCkpO1xuICB9XG5cbiAgYXN5bmMgcHV0SWRlbnRpdHlCdW5kbGUodXNlcklkOiBzdHJpbmcsIGJ1bmRsZTogSWRlbnRpdHlCdW5kbGUpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBpZiAoYnVuZGxlLnVzZXJJZCAhPT0gdXNlcklkKSB7XG4gICAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMCwgXCJpbnZhbGlkX2lucHV0XCIsIFwiaWRlbnRpdHkgYnVuZGxlIHVzZXJJZCBkb2VzIG5vdCBtYXRjaCByZXF1ZXN0IHBhdGhcIik7XG4gICAgfVxuICAgIGNvbnN0IG5vcm1hbGl6ZWQ6IElkZW50aXR5QnVuZGxlID0ge1xuICAgICAgLi4uYnVuZGxlLFxuICAgICAgaWRlbnRpdHlCdW5kbGVSZWY6IHRoaXMuaWRlbnRpdHlCdW5kbGVVcmwodXNlcklkKSxcbiAgICAgIGRldmljZVN0YXR1c1JlZjogYnVuZGxlLmRldmljZVN0YXR1c1JlZiA/PyB0aGlzLmRldmljZVN0YXR1c1VybCh1c2VySWQpLFxuICAgICAgZGV2aWNlczogYnVuZGxlLmRldmljZXMubWFwKChkZXZpY2UpID0+ICh7XG4gICAgICAgIC4uLmRldmljZSxcbiAgICAgICAga2V5cGFja2FnZVJlZjoge1xuICAgICAgICAgIC4uLmRldmljZS5rZXlwYWNrYWdlUmVmLFxuICAgICAgICAgIHVzZXJJZCxcbiAgICAgICAgICBkZXZpY2VJZDogZGV2aWNlLmRldmljZUlkLFxuICAgICAgICAgIHJlZjogZGV2aWNlLmtleXBhY2thZ2VSZWYucmVmXG4gICAgICAgIH1cbiAgICAgIH0pKVxuICAgIH07XG4gICAgYXdhaXQgdGhpcy5zdG9yZS5wdXRKc29uKHRoaXMuaWRlbnRpdHlCdW5kbGVLZXkodXNlcklkKSwgbm9ybWFsaXplZCk7XG4gICAgYXdhaXQgdGhpcy5zdG9yZS5wdXRKc29uKHRoaXMuZGV2aWNlTGlzdEtleSh1c2VySWQpLCB0aGlzLmJ1aWxkRGV2aWNlTGlzdERvY3VtZW50KG5vcm1hbGl6ZWQpKTtcbiAgfVxuXG4gIGFzeW5jIGdldERldmljZUxpc3QodXNlcklkOiBzdHJpbmcpOiBQcm9taXNlPERldmljZUxpc3REb2N1bWVudCB8IG51bGw+IHtcbiAgICByZXR1cm4gdGhpcy5zdG9yZS5nZXRKc29uPERldmljZUxpc3REb2N1bWVudD4odGhpcy5kZXZpY2VMaXN0S2V5KHVzZXJJZCkpO1xuICB9XG5cbiAgYXN5bmMgZ2V0RGV2aWNlU3RhdHVzKHVzZXJJZDogc3RyaW5nKTogUHJvbWlzZTxEZXZpY2VTdGF0dXNEb2N1bWVudCB8IG51bGw+IHtcbiAgICByZXR1cm4gdGhpcy5zdG9yZS5nZXRKc29uPERldmljZVN0YXR1c0RvY3VtZW50Pih0aGlzLmRldmljZVN0YXR1c0tleSh1c2VySWQpKTtcbiAgfVxuXG4gIGFzeW5jIHB1dERldmljZVN0YXR1cyh1c2VySWQ6IHN0cmluZywgZG9jdW1lbnQ6IERldmljZVN0YXR1c0RvY3VtZW50KTogUHJvbWlzZTx2b2lkPiB7XG4gICAgaWYgKGRvY3VtZW50LnVzZXJJZCAhPT0gdXNlcklkKSB7XG4gICAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMCwgXCJpbnZhbGlkX2lucHV0XCIsIFwiZGV2aWNlIHN0YXR1cyB1c2VySWQgZG9lcyBub3QgbWF0Y2ggcmVxdWVzdCBwYXRoXCIpO1xuICAgIH1cbiAgICBmb3IgKGNvbnN0IGRldmljZSBvZiBkb2N1bWVudC5kZXZpY2VzKSB7XG4gICAgICBpZiAoZGV2aWNlLnVzZXJJZCAhPT0gdXNlcklkKSB7XG4gICAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAwLCBcImludmFsaWRfaW5wdXRcIiwgXCJkZXZpY2Ugc3RhdHVzIGVudHJ5IHVzZXJJZCBkb2VzIG5vdCBtYXRjaCByZXF1ZXN0IHBhdGhcIik7XG4gICAgICB9XG4gICAgfVxuICAgIGF3YWl0IHRoaXMuc3RvcmUucHV0SnNvbih0aGlzLmRldmljZVN0YXR1c0tleSh1c2VySWQpLCBkb2N1bWVudCk7XG4gIH1cblxuICBhc3luYyBnZXRLZXlQYWNrYWdlUmVmcyh1c2VySWQ6IHN0cmluZywgZGV2aWNlSWQ6IHN0cmluZyk6IFByb21pc2U8S2V5UGFja2FnZVJlZnNEb2N1bWVudCB8IG51bGw+IHtcbiAgICByZXR1cm4gdGhpcy5zdG9yZS5nZXRKc29uPEtleVBhY2thZ2VSZWZzRG9jdW1lbnQ+KHRoaXMua2V5UGFja2FnZVJlZnNLZXkodXNlcklkLCBkZXZpY2VJZCkpO1xuICB9XG5cbiAgYXN5bmMgcHV0S2V5UGFja2FnZVJlZnModXNlcklkOiBzdHJpbmcsIGRldmljZUlkOiBzdHJpbmcsIGRvY3VtZW50OiBLZXlQYWNrYWdlUmVmc0RvY3VtZW50KTogUHJvbWlzZTx2b2lkPiB7XG4gICAgaWYgKGRvY3VtZW50LnVzZXJJZCAhPT0gdXNlcklkIHx8IGRvY3VtZW50LmRldmljZUlkICE9PSBkZXZpY2VJZCkge1xuICAgICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDAsIFwiaW52YWxpZF9pbnB1dFwiLCBcImtleXBhY2thZ2UgcmVmcyBzY29wZSBkb2VzIG5vdCBtYXRjaCByZXF1ZXN0IHBhdGhcIik7XG4gICAgfVxuICAgIGZvciAoY29uc3QgZW50cnkgb2YgZG9jdW1lbnQucmVmcykge1xuICAgICAgaWYgKCFlbnRyeS5yZWYgfHwgIWVudHJ5LnJlZi5zdGFydHNXaXRoKHRoaXMua2V5UGFja2FnZVJlZnNVcmwodXNlcklkLCBkZXZpY2VJZCkpKSB7XG4gICAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAwLCBcImludmFsaWRfaW5wdXRcIiwgXCJrZXlwYWNrYWdlIHJlZiBtdXN0IGJlIGEgY29uY3JldGUgb2JqZWN0IFVSTFwiKTtcbiAgICAgIH1cbiAgICB9XG4gICAgYXdhaXQgdGhpcy5zdG9yZS5wdXRKc29uKHRoaXMua2V5UGFja2FnZVJlZnNLZXkodXNlcklkLCBkZXZpY2VJZCksIGRvY3VtZW50KTtcbiAgfVxuXG4gIGFzeW5jIHB1dEtleVBhY2thZ2VPYmplY3QodXNlcklkOiBzdHJpbmcsIGRldmljZUlkOiBzdHJpbmcsIGtleVBhY2thZ2VJZDogc3RyaW5nLCBib2R5OiBBcnJheUJ1ZmZlcik6IFByb21pc2U8dm9pZD4ge1xuICAgIGF3YWl0IHRoaXMuc3RvcmUucHV0Qnl0ZXModGhpcy5rZXlQYWNrYWdlT2JqZWN0S2V5KHVzZXJJZCwgZGV2aWNlSWQsIGtleVBhY2thZ2VJZCksIGJvZHksIHtcbiAgICAgIFwiY29udGVudC10eXBlXCI6IFwiYXBwbGljYXRpb24vb2N0ZXQtc3RyZWFtXCJcbiAgICB9KTtcbiAgfVxuXG4gIGFzeW5jIGdldEtleVBhY2thZ2VPYmplY3QodXNlcklkOiBzdHJpbmcsIGRldmljZUlkOiBzdHJpbmcsIGtleVBhY2thZ2VJZDogc3RyaW5nKTogUHJvbWlzZTxBcnJheUJ1ZmZlciB8IG51bGw+IHtcbiAgICByZXR1cm4gdGhpcy5zdG9yZS5nZXRCeXRlcyh0aGlzLmtleVBhY2thZ2VPYmplY3RLZXkodXNlcklkLCBkZXZpY2VJZCwga2V5UGFja2FnZUlkKSk7XG4gIH1cblxuICBwcml2YXRlIGJ1aWxkRGV2aWNlTGlzdERvY3VtZW50KGJ1bmRsZTogSWRlbnRpdHlCdW5kbGUpOiBEZXZpY2VMaXN0RG9jdW1lbnQge1xuICAgIHJldHVybiB7XG4gICAgICB2ZXJzaW9uOiBidW5kbGUudmVyc2lvbixcbiAgICAgIHVzZXJJZDogYnVuZGxlLnVzZXJJZCxcbiAgICAgIHVwZGF0ZWRBdDogYnVuZGxlLnVwZGF0ZWRBdCxcbiAgICAgIGRldmljZXM6IGJ1bmRsZS5kZXZpY2VzLm1hcCgoZGV2aWNlKSA9PiAoe1xuICAgICAgICBkZXZpY2VJZDogZGV2aWNlLmRldmljZUlkLFxuICAgICAgICBzdGF0dXM6IGRldmljZS5zdGF0dXNcbiAgICAgIH0pKVxuICAgIH07XG4gIH1cbn0iLCAiaW1wb3J0IHR5cGUgeyBQcmVwYXJlQmxvYlVwbG9hZFJlcXVlc3QsIFByZXBhcmVCbG9iVXBsb2FkUmVzdWx0IH0gZnJvbSBcIi4uL3R5cGVzL2NvbnRyYWN0c1wiO1xuaW1wb3J0IHR5cGUgeyBKc29uQmxvYlN0b3JlIH0gZnJvbSBcIi4uL3R5cGVzL3J1bnRpbWVcIjtcbmltcG9ydCB7IEh0dHBFcnJvciB9IGZyb20gXCIuLi9hdXRoL2NhcGFiaWxpdHlcIjtcbmltcG9ydCB7IHNpZ25TaGFyaW5nUGF5bG9hZCwgdmVyaWZ5U2hhcmluZ1BheWxvYWQgfSBmcm9tIFwiLi9zaGFyaW5nXCI7XG5cbmZ1bmN0aW9uIHNhbml0aXplU2VnbWVudCh2YWx1ZTogc3RyaW5nKTogc3RyaW5nIHtcbiAgcmV0dXJuIHZhbHVlLnJlcGxhY2UoL1teYS16QS1aMC05Ol8tXS9nLCBcIl9cIik7XG59XG5cbmV4cG9ydCBjbGFzcyBTdG9yYWdlU2VydmljZSB7XG4gIHByaXZhdGUgcmVhZG9ubHkgc3RvcmU6IEpzb25CbG9iU3RvcmU7XG4gIHByaXZhdGUgcmVhZG9ubHkgYmFzZVVybDogc3RyaW5nO1xuICBwcml2YXRlIHJlYWRvbmx5IHNlY3JldDogc3RyaW5nO1xuXG4gIGNvbnN0cnVjdG9yKHN0b3JlOiBKc29uQmxvYlN0b3JlLCBiYXNlVXJsOiBzdHJpbmcsIHNlY3JldDogc3RyaW5nKSB7XG4gICAgdGhpcy5zdG9yZSA9IHN0b3JlO1xuICAgIHRoaXMuYmFzZVVybCA9IGJhc2VVcmw7XG4gICAgdGhpcy5zZWNyZXQgPSBzZWNyZXQ7XG4gIH1cblxuICBhc3luYyBwcmVwYXJlVXBsb2FkKFxuICAgIGlucHV0OiBQcmVwYXJlQmxvYlVwbG9hZFJlcXVlc3QsXG4gICAgb3duZXI6IHsgdXNlcklkOiBzdHJpbmc7IGRldmljZUlkOiBzdHJpbmcgfSxcbiAgICBub3c6IG51bWJlclxuICApOiBQcm9taXNlPFByZXBhcmVCbG9iVXBsb2FkUmVzdWx0PiB7XG4gICAgaWYgKCFpbnB1dC50YXNrSWQgfHwgIWlucHV0LmNvbnZlcnNhdGlvbklkIHx8ICFpbnB1dC5tZXNzYWdlSWQgfHwgIWlucHV0Lm1pbWVUeXBlIHx8IGlucHV0LnNpemVCeXRlcyA8PSAwKSB7XG4gICAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMCwgXCJpbnZhbGlkX2lucHV0XCIsIFwicHJlcGFyZSB1cGxvYWQgcmVxdWVzdCBpcyBtaXNzaW5nIHJlcXVpcmVkIGZpZWxkc1wiKTtcbiAgICB9XG4gICAgY29uc3QgYmxvYktleSA9IFtcbiAgICAgIFwiYmxvYlwiLFxuICAgICAgc2FuaXRpemVTZWdtZW50KG93bmVyLnVzZXJJZCksXG4gICAgICBzYW5pdGl6ZVNlZ21lbnQob3duZXIuZGV2aWNlSWQpLFxuICAgICAgc2FuaXRpemVTZWdtZW50KGlucHV0LmNvbnZlcnNhdGlvbklkKSxcbiAgICAgIGAke3Nhbml0aXplU2VnbWVudChpbnB1dC5tZXNzYWdlSWQpfS0ke3Nhbml0aXplU2VnbWVudChpbnB1dC50YXNrSWQpfWBcbiAgICBdLmpvaW4oXCIvXCIpO1xuICAgIGNvbnN0IGV4cGlyZXNBdCA9IG5vdyArIDE1ICogNjAgKiAxMDAwO1xuICAgIGNvbnN0IHVwbG9hZFRva2VuID0gYXdhaXQgc2lnblNoYXJpbmdQYXlsb2FkKHRoaXMuc2VjcmV0LCB7XG4gICAgICBhY3Rpb246IFwidXBsb2FkXCIsXG4gICAgICBibG9iS2V5LFxuICAgICAgZXhwaXJlc0F0XG4gICAgfSk7XG4gICAgY29uc3QgZG93bmxvYWRUb2tlbiA9IGF3YWl0IHNpZ25TaGFyaW5nUGF5bG9hZCh0aGlzLnNlY3JldCwge1xuICAgICAgYWN0aW9uOiBcImRvd25sb2FkXCIsXG4gICAgICBibG9iS2V5LFxuICAgICAgZXhwaXJlc0F0XG4gICAgfSk7XG5cbiAgICByZXR1cm4ge1xuICAgICAgYmxvYlJlZjogYmxvYktleSxcbiAgICAgIHVwbG9hZFRhcmdldDogYCR7dGhpcy5iYXNlVXJsfS92MS9zdG9yYWdlL3VwbG9hZC8ke2VuY29kZVVSSUNvbXBvbmVudChibG9iS2V5KX0/dG9rZW49JHtlbmNvZGVVUklDb21wb25lbnQodXBsb2FkVG9rZW4pfWAsXG4gICAgICB1cGxvYWRIZWFkZXJzOiB7XG4gICAgICAgIFwiY29udGVudC10eXBlXCI6IGlucHV0Lm1pbWVUeXBlXG4gICAgICB9LFxuICAgICAgZG93bmxvYWRUYXJnZXQ6IGAke3RoaXMuYmFzZVVybH0vdjEvc3RvcmFnZS9ibG9iLyR7ZW5jb2RlVVJJQ29tcG9uZW50KGJsb2JLZXkpfT90b2tlbj0ke2VuY29kZVVSSUNvbXBvbmVudChkb3dubG9hZFRva2VuKX1gLFxuICAgICAgZXhwaXJlc0F0XG4gICAgfTtcbiAgfVxuXG4gIGFzeW5jIHVwbG9hZEJsb2IoYmxvYktleTogc3RyaW5nLCB0b2tlbjogc3RyaW5nLCBib2R5OiBBcnJheUJ1ZmZlciwgbWV0YWRhdGE6IFJlY29yZDxzdHJpbmcsIHN0cmluZz4sIG5vdzogbnVtYmVyKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgcGF5bG9hZCA9IGF3YWl0IHRoaXMudmVyaWZ5VG9rZW48eyBhY3Rpb246IHN0cmluZzsgYmxvYktleTogc3RyaW5nIH0+KHRva2VuLCBub3cpO1xuICAgIGlmIChwYXlsb2FkLmFjdGlvbiAhPT0gXCJ1cGxvYWRcIiB8fCBwYXlsb2FkLmJsb2JLZXkgIT09IGJsb2JLZXkpIHtcbiAgICAgIHRocm93IG5ldyBIdHRwRXJyb3IoNDAzLCBcImludmFsaWRfY2FwYWJpbGl0eVwiLCBcInVwbG9hZCB0b2tlbiBpcyBub3QgdmFsaWQgZm9yIHRoaXMgYmxvYlwiKTtcbiAgICB9XG4gICAgYXdhaXQgdGhpcy5zdG9yZS5wdXRCeXRlcyhibG9iS2V5LCBib2R5LCBtZXRhZGF0YSk7XG4gIH1cblxuICBhc3luYyBmZXRjaEJsb2IoYmxvYktleTogc3RyaW5nLCB0b2tlbjogc3RyaW5nLCBub3c6IG51bWJlcik6IFByb21pc2U8QXJyYXlCdWZmZXI+IHtcbiAgICBjb25zdCBwYXlsb2FkID0gYXdhaXQgdGhpcy52ZXJpZnlUb2tlbjx7IGFjdGlvbjogc3RyaW5nOyBibG9iS2V5OiBzdHJpbmcgfT4odG9rZW4sIG5vdyk7XG4gICAgaWYgKHBheWxvYWQuYWN0aW9uICE9PSBcImRvd25sb2FkXCIgfHwgcGF5bG9hZC5ibG9iS2V5ICE9PSBibG9iS2V5KSB7XG4gICAgICB0aHJvdyBuZXcgSHR0cEVycm9yKDQwMywgXCJpbnZhbGlkX2NhcGFiaWxpdHlcIiwgXCJkb3dubG9hZCB0b2tlbiBpcyBub3QgdmFsaWQgZm9yIHRoaXMgYmxvYlwiKTtcbiAgICB9XG4gICAgY29uc3Qgb2JqZWN0ID0gYXdhaXQgdGhpcy5zdG9yZS5nZXRCeXRlcyhibG9iS2V5KTtcbiAgICBpZiAoIW9iamVjdCkge1xuICAgICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDQsIFwiYmxvYl9ub3RfZm91bmRcIiwgXCJibG9iIGRvZXMgbm90IGV4aXN0XCIpO1xuICAgIH1cbiAgICByZXR1cm4gb2JqZWN0O1xuICB9XG5cbiAgYXN5bmMgcHV0SnNvbjxUPihrZXk6IHN0cmluZywgdmFsdWU6IFQpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLnN0b3JlLnB1dEpzb24oa2V5LCB2YWx1ZSk7XG4gIH1cblxuICBhc3luYyBnZXRKc29uPFQ+KGtleTogc3RyaW5nKTogUHJvbWlzZTxUIHwgbnVsbD4ge1xuICAgIHJldHVybiB0aGlzLnN0b3JlLmdldEpzb248VD4oa2V5KTtcbiAgfVxuXG4gIGFzeW5jIGRlbGV0ZShrZXk6IHN0cmluZyk6IFByb21pc2U8dm9pZD4ge1xuICAgIGF3YWl0IHRoaXMuc3RvcmUuZGVsZXRlKGtleSk7XG4gIH1cblxuICBwcml2YXRlIGFzeW5jIHZlcmlmeVRva2VuPFQ+KHRva2VuOiBzdHJpbmcsIG5vdzogbnVtYmVyKTogUHJvbWlzZTxUPiB7XG4gICAgdHJ5IHtcbiAgICAgIHJldHVybiBhd2FpdCB2ZXJpZnlTaGFyaW5nUGF5bG9hZDxUPih0aGlzLnNlY3JldCwgdG9rZW4sIG5vdyk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGNvbnN0IG1lc3NhZ2UgPSBlcnJvciBpbnN0YW5jZW9mIEVycm9yID8gZXJyb3IubWVzc2FnZSA6IFwiaW52YWxpZCBzaGFyaW5nIHRva2VuXCI7XG4gICAgICBpZiAobWVzc2FnZS5pbmNsdWRlcyhcImV4cGlyZWRcIikpIHtcbiAgICAgICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiY2FwYWJpbGl0eV9leHBpcmVkXCIsIG1lc3NhZ2UpO1xuICAgICAgfVxuICAgICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIG1lc3NhZ2UpO1xuICAgIH1cbiAgfVxufVxyXG4iLCAiaW1wb3J0IHtcbiAgSHR0cEVycm9yLFxuICB2YWxpZGF0ZUFueURldmljZVJ1bnRpbWVBdXRob3JpemF0aW9uLFxuICB2YWxpZGF0ZUFwcGVuZEF1dGhvcml6YXRpb24sXG4gIHZhbGlkYXRlQm9vdHN0cmFwQXV0aG9yaXphdGlvbixcbiAgdmFsaWRhdGVEZXZpY2VSdW50aW1lQXV0aG9yaXphdGlvbkZvckRldmljZSxcbiAgdmFsaWRhdGVLZXlQYWNrYWdlV3JpdGVBdXRob3JpemF0aW9uLFxuICB2YWxpZGF0ZVNoYXJlZFN0YXRlV3JpdGVBdXRob3JpemF0aW9uXG59IGZyb20gXCIuLi9hdXRoL2NhcGFiaWxpdHlcIjtcbmltcG9ydCB7IHNpZ25TaGFyaW5nUGF5bG9hZCB9IGZyb20gXCIuLi9zdG9yYWdlL3NoYXJpbmdcIjtcbmltcG9ydCB7IFNoYXJlZFN0YXRlU2VydmljZSB9IGZyb20gXCIuLi9zdG9yYWdlL3NoYXJlZC1zdGF0ZVwiO1xuaW1wb3J0IHsgU3RvcmFnZVNlcnZpY2UgfSBmcm9tIFwiLi4vc3RvcmFnZS9zZXJ2aWNlXCI7XG5pbXBvcnQge1xuICBDVVJSRU5UX01PREVMX1ZFUlNJT04sXG4gIHR5cGUgQWxsb3dsaXN0RG9jdW1lbnQsXG4gIHR5cGUgQXBwZW5kRW52ZWxvcGVSZXF1ZXN0LFxuICB0eXBlIEJvb3RzdHJhcERldmljZVJlcXVlc3QsXG4gIHR5cGUgRGVwbG95bWVudEJ1bmRsZSxcbiAgdHlwZSBEZXZpY2VSdW50aW1lQXV0aCxcbiAgdHlwZSBEZXZpY2VTdGF0dXNEb2N1bWVudCxcbiAgdHlwZSBJZGVudGl0eUJ1bmRsZSxcbiAgdHlwZSBLZXlQYWNrYWdlUmVmc0RvY3VtZW50LFxuICB0eXBlIFByZXBhcmVCbG9iVXBsb2FkUmVxdWVzdFxufSBmcm9tIFwiLi4vdHlwZXMvY29udHJhY3RzXCI7XG5pbXBvcnQgdHlwZSB7IEVudiB9IGZyb20gXCIuLi90eXBlcy9ydW50aW1lXCI7XG5cbmZ1bmN0aW9uIHZlcnNpb25lZEJvZHkoYm9keTogdW5rbm93bik6IHVua25vd24ge1xuICBpZiAoIWJvZHkgfHwgdHlwZW9mIGJvZHkgIT09IFwib2JqZWN0XCIgfHwgQXJyYXkuaXNBcnJheShib2R5KSkge1xuICAgIHJldHVybiBib2R5O1xuICB9XG4gIGNvbnN0IHJlY29yZCA9IGJvZHkgYXMgUmVjb3JkPHN0cmluZywgdW5rbm93bj47XG4gIGlmIChyZWNvcmQudmVyc2lvbiAhPT0gdW5kZWZpbmVkKSB7XG4gICAgcmV0dXJuIGJvZHk7XG4gIH1cbiAgcmV0dXJuIHtcbiAgICB2ZXJzaW9uOiBDVVJSRU5UX01PREVMX1ZFUlNJT04sXG4gICAgLi4ucmVjb3JkXG4gIH07XG59XG5cbmZ1bmN0aW9uIGpzb25SZXNwb25zZShib2R5OiB1bmtub3duLCBzdGF0dXMgPSAyMDApOiBSZXNwb25zZSB7XG4gIHJldHVybiBuZXcgUmVzcG9uc2UoSlNPTi5zdHJpbmdpZnkodmVyc2lvbmVkQm9keShib2R5KSksIHtcbiAgICBzdGF0dXMsXG4gICAgaGVhZGVyczoge1xuICAgICAgXCJjb250ZW50LXR5cGVcIjogXCJhcHBsaWNhdGlvbi9qc29uXCJcbiAgICB9XG4gIH0pO1xufVxuXG5jbGFzcyBSMkpzb25CbG9iU3RvcmUge1xuICBwcml2YXRlIHJlYWRvbmx5IGJ1Y2tldDogRW52W1wiVEFQQ0hBVF9TVE9SQUdFXCJdO1xuXG4gIGNvbnN0cnVjdG9yKGJ1Y2tldDogRW52W1wiVEFQQ0hBVF9TVE9SQUdFXCJdKSB7XG4gICAgdGhpcy5idWNrZXQgPSBidWNrZXQ7XG4gIH1cblxuICBhc3luYyBwdXRKc29uPFQ+KGtleTogc3RyaW5nLCB2YWx1ZTogVCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGF3YWl0IHRoaXMuYnVja2V0LnB1dChrZXksIEpTT04uc3RyaW5naWZ5KHZhbHVlKSk7XG4gIH1cblxuICBhc3luYyBnZXRKc29uPFQ+KGtleTogc3RyaW5nKTogUHJvbWlzZTxUIHwgbnVsbD4ge1xuICAgIGNvbnN0IG9iamVjdCA9IGF3YWl0IHRoaXMuYnVja2V0LmdldChrZXkpO1xuICAgIGlmICghb2JqZWN0KSB7XG4gICAgICByZXR1cm4gbnVsbDtcbiAgICB9XG4gICAgcmV0dXJuIGF3YWl0IG9iamVjdC5qc29uPFQ+KCk7XG4gIH1cblxuICBhc3luYyBwdXRCeXRlcyhrZXk6IHN0cmluZywgdmFsdWU6IEFycmF5QnVmZmVyIHwgVWludDhBcnJheSwgbWV0YWRhdGE/OiBSZWNvcmQ8c3RyaW5nLCBzdHJpbmc+KTogUHJvbWlzZTx2b2lkPiB7XG4gICAgYXdhaXQgdGhpcy5idWNrZXQucHV0KGtleSwgdmFsdWUsIG1ldGFkYXRhID8geyBodHRwTWV0YWRhdGE6IG1ldGFkYXRhIH0gOiB1bmRlZmluZWQpO1xuICB9XG5cbiAgYXN5bmMgZ2V0Qnl0ZXMoa2V5OiBzdHJpbmcpOiBQcm9taXNlPEFycmF5QnVmZmVyIHwgbnVsbD4ge1xuICAgIGNvbnN0IG9iamVjdCA9IGF3YWl0IHRoaXMuYnVja2V0LmdldChrZXkpO1xuICAgIGlmICghb2JqZWN0KSB7XG4gICAgICByZXR1cm4gbnVsbDtcbiAgICB9XG4gICAgcmV0dXJuIG9iamVjdC5hcnJheUJ1ZmZlcigpO1xuICB9XG5cbiAgYXN5bmMgZGVsZXRlKGtleTogc3RyaW5nKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgYXdhaXQgdGhpcy5idWNrZXQuZGVsZXRlKGtleSk7XG4gIH1cbn1cblxuZnVuY3Rpb24gYmFzZVVybChyZXF1ZXN0OiBSZXF1ZXN0LCBlbnY6IEVudik6IHN0cmluZyB7XG4gIHJldHVybiBlbnYuUFVCTElDX0JBU0VfVVJMPy50cmltKCkucmVwbGFjZSgvXFwvKyQvLCBcIlwiKSA/PyBuZXcgVVJMKHJlcXVlc3QudXJsKS5vcmlnaW47XG59XG5cbmZ1bmN0aW9uIHNoYXJlZFN0YXRlU2VjcmV0KGVudjogRW52KTogc3RyaW5nIHtcbiAgcmV0dXJuIGVudi5TSEFSSU5HX1RPS0VOX1NFQ1JFVCA/PyBcInJlcGxhY2UtbWVcIjtcbn1cblxuZnVuY3Rpb24gYm9vdHN0cmFwU2VjcmV0KGVudjogRW52KTogc3RyaW5nIHtcbiAgcmV0dXJuIGVudi5CT09UU1RSQVBfVE9LRU5fU0VDUkVUID8/IGVudi5TSEFSSU5HX1RPS0VOX1NFQ1JFVCA/PyBcInJlcGxhY2UtbWVcIjtcbn1cblxuZnVuY3Rpb24gcnVudGltZVNjb3BlcygpOiBEZXZpY2VSdW50aW1lQXV0aFtcInNjb3Blc1wiXSB7XG4gIHJldHVybiBbXG4gICAgXCJpbmJveF9yZWFkXCIsXG4gICAgXCJpbmJveF9hY2tcIixcbiAgICBcImluYm94X3N1YnNjcmliZVwiLFxuICAgIFwiaW5ib3hfbWFuYWdlXCIsXG4gICAgXCJzdG9yYWdlX3ByZXBhcmVfdXBsb2FkXCIsXG4gICAgXCJzaGFyZWRfc3RhdGVfd3JpdGVcIixcbiAgICBcImtleXBhY2thZ2Vfd3JpdGVcIlxuICBdO1xufVxuXG5hc3luYyBmdW5jdGlvbiBpc3N1ZURldmljZVJ1bnRpbWVBdXRoKGVudjogRW52LCB1c2VySWQ6IHN0cmluZywgZGV2aWNlSWQ6IHN0cmluZywgbm93OiBudW1iZXIpOiBQcm9taXNlPERldmljZVJ1bnRpbWVBdXRoPiB7XG4gIGNvbnN0IGV4cGlyZXNBdCA9IG5vdyArIDI0ICogNjAgKiA2MCAqIDEwMDA7XG4gIGNvbnN0IHNjb3BlcyA9IHJ1bnRpbWVTY29wZXMoKTtcbiAgY29uc3QgdG9rZW4gPSBhd2FpdCBzaWduU2hhcmluZ1BheWxvYWQoc2hhcmVkU3RhdGVTZWNyZXQoZW52KSwge1xuICAgIHZlcnNpb246IENVUlJFTlRfTU9ERUxfVkVSU0lPTixcbiAgICBzZXJ2aWNlOiBcImRldmljZV9ydW50aW1lXCIsXG4gICAgdXNlcklkLFxuICAgIGRldmljZUlkLFxuICAgIHNjb3BlcyxcbiAgICBleHBpcmVzQXRcbiAgfSk7XG4gIHJldHVybiB7XG4gICAgc2NoZW1lOiBcImJlYXJlclwiLFxuICAgIHRva2VuLFxuICAgIGV4cGlyZXNBdCxcbiAgICB1c2VySWQsXG4gICAgZGV2aWNlSWQsXG4gICAgc2NvcGVzXG4gIH07XG59XG5cbmZ1bmN0aW9uIHB1YmxpY0RlcGxveW1lbnRCdW5kbGUocmVxdWVzdDogUmVxdWVzdCwgZW52OiBFbnYpOiBEZXBsb3ltZW50QnVuZGxlIHtcbiAgcmV0dXJuIHtcbiAgICB2ZXJzaW9uOiBDVVJSRU5UX01PREVMX1ZFUlNJT04sXG4gICAgcmVnaW9uOiBlbnYuREVQTE9ZTUVOVF9SRUdJT04gPz8gXCJsb2NhbFwiLFxuICAgIGluYm94SHR0cEVuZHBvaW50OiBiYXNlVXJsKHJlcXVlc3QsIGVudiksXG4gICAgaW5ib3hXZWJzb2NrZXRFbmRwb2ludDogYCR7YmFzZVVybChyZXF1ZXN0LCBlbnYpLnJlcGxhY2UoL15odHRwL2ksIFwid3NcIil9L3YxL2luYm94L3tkZXZpY2VJZH0vc3Vic2NyaWJlYCxcbiAgICBzdG9yYWdlQmFzZUluZm86IHtcbiAgICAgIGJhc2VVcmw6IGJhc2VVcmwocmVxdWVzdCwgZW52KSxcbiAgICAgIGJ1Y2tldEhpbnQ6IFwidGFwY2hhdC1zdG9yYWdlXCJcbiAgICB9LFxuICAgIHJ1bnRpbWVDb25maWc6IHtcbiAgICAgIHN1cHBvcnRlZFJlYWx0aW1lS2luZHM6IFtcIndlYnNvY2tldFwiXSxcbiAgICAgIGlkZW50aXR5QnVuZGxlUmVmOiBgJHtiYXNlVXJsKHJlcXVlc3QsIGVudil9L3YxL3NoYXJlZC1zdGF0ZS97dXNlcklkfS9pZGVudGl0eS1idW5kbGVgLFxuICAgICAgZGV2aWNlU3RhdHVzUmVmOiBgJHtiYXNlVXJsKHJlcXVlc3QsIGVudil9L3YxL3NoYXJlZC1zdGF0ZS97dXNlcklkfS9kZXZpY2Utc3RhdHVzYCxcbiAgICAgIGtleXBhY2thZ2VSZWZCYXNlOiBgJHtiYXNlVXJsKHJlcXVlc3QsIGVudil9L3YxL3NoYXJlZC1zdGF0ZS9rZXlwYWNrYWdlc2AsXG4gICAgICBtYXhJbmxpbmVCeXRlczogTnVtYmVyKGVudi5NQVhfSU5MSU5FX0JZVEVTID8/IFwiNDA5NlwiKSxcbiAgICAgIGZlYXR1cmVzOiBbXCJnZW5lcmljX3N5bmNcIiwgXCJhdHRhY2htZW50X3YxXCIsIFwibWVzc2FnZV9yZXF1ZXN0c1wiLCBcImFsbG93bGlzdFwiLCBcInJhdGVfbGltaXRcIl1cbiAgICB9XG4gIH07XG59XG5cbmFzeW5jIGZ1bmN0aW9uIGF1dGhvcml6ZVNoYXJlZFN0YXRlV3JpdGUoXG4gIHJlcXVlc3Q6IFJlcXVlc3QsXG4gIGVudjogRW52LFxuICB1c2VySWQ6IHN0cmluZyxcbiAgb2JqZWN0S2luZDogXCJpZGVudGl0eV9idW5kbGVcIiB8IFwiZGV2aWNlX3N0YXR1c1wiLFxuICBub3c6IG51bWJlclxuKTogUHJvbWlzZTx2b2lkPiB7XG4gIHRyeSB7XG4gICAgY29uc3QgYXV0aCA9IGF3YWl0IHZhbGlkYXRlQW55RGV2aWNlUnVudGltZUF1dGhvcml6YXRpb24ocmVxdWVzdCwgc2hhcmVkU3RhdGVTZWNyZXQoZW52KSwgXCJzaGFyZWRfc3RhdGVfd3JpdGVcIiwgbm93KTtcbiAgICBpZiAoYXV0aC51c2VySWQgIT09IHVzZXJJZCkge1xuICAgICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDMsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwiZGV2aWNlIHJ1bnRpbWUgdG9rZW4gc2NvcGUgZG9lcyBub3QgbWF0Y2ggcmVxdWVzdCBwYXRoXCIpO1xuICAgIH1cbiAgICByZXR1cm47XG4gIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgaWYgKCEoZXJyb3IgaW5zdGFuY2VvZiBIdHRwRXJyb3IpIHx8IGVycm9yLmNvZGUgPT09IFwiY2FwYWJpbGl0eV9leHBpcmVkXCIpIHtcbiAgICAgIHRocm93IGVycm9yO1xuICAgIH1cbiAgfVxuICBhd2FpdCB2YWxpZGF0ZVNoYXJlZFN0YXRlV3JpdGVBdXRob3JpemF0aW9uKHJlcXVlc3QsIHNoYXJlZFN0YXRlU2VjcmV0KGVudiksIHVzZXJJZCwgXCJcIiwgb2JqZWN0S2luZCwgbm93KTtcbn1cblxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGhhbmRsZVJlcXVlc3QocmVxdWVzdDogUmVxdWVzdCwgZW52OiBFbnYpOiBQcm9taXNlPFJlc3BvbnNlPiB7XG4gIGNvbnN0IHVybCA9IG5ldyBVUkwocmVxdWVzdC51cmwpO1xuICBjb25zdCBzdG9yZSA9IG5ldyBTdG9yYWdlU2VydmljZShcbiAgICBuZXcgUjJKc29uQmxvYlN0b3JlKGVudi5UQVBDSEFUX1NUT1JBR0UpLFxuICAgIGJhc2VVcmwocmVxdWVzdCwgZW52KSxcbiAgICBzaGFyZWRTdGF0ZVNlY3JldChlbnYpXG4gICk7XG4gIGNvbnN0IHNoYXJlZFN0YXRlID0gbmV3IFNoYXJlZFN0YXRlU2VydmljZShuZXcgUjJKc29uQmxvYlN0b3JlKGVudi5UQVBDSEFUX1NUT1JBR0UpLCBiYXNlVXJsKHJlcXVlc3QsIGVudikpO1xuICBjb25zdCBub3cgPSBEYXRlLm5vdygpO1xuXG4gIHRyeSB7XG4gICAgaWYgKHJlcXVlc3QubWV0aG9kID09PSBcIkdFVFwiICYmIHVybC5wYXRobmFtZSA9PT0gXCIvdjEvZGVwbG95bWVudC1idW5kbGVcIikge1xuICAgICAgcmV0dXJuIGpzb25SZXNwb25zZShwdWJsaWNEZXBsb3ltZW50QnVuZGxlKHJlcXVlc3QsIGVudikpO1xuICAgIH1cblxuICAgIGlmIChyZXF1ZXN0Lm1ldGhvZCA9PT0gXCJQT1NUXCIgJiYgdXJsLnBhdGhuYW1lID09PSBcIi92MS9ib290c3RyYXAvZGV2aWNlXCIpIHtcbiAgICAgIGNvbnN0IGJvZHkgPSAoYXdhaXQgcmVxdWVzdC5qc29uKCkpIGFzIEJvb3RzdHJhcERldmljZVJlcXVlc3Q7XG4gICAgICBpZiAoYm9keS52ZXJzaW9uICE9PSBDVVJSRU5UX01PREVMX1ZFUlNJT04pIHtcbiAgICAgICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDAsIFwidW5zdXBwb3J0ZWRfdmVyc2lvblwiLCBcImJvb3RzdHJhcCByZXF1ZXN0IHZlcnNpb24gaXMgbm90IHN1cHBvcnRlZFwiKTtcbiAgICAgIH1cbiAgICAgIGF3YWl0IHZhbGlkYXRlQm9vdHN0cmFwQXV0aG9yaXphdGlvbihyZXF1ZXN0LCBib290c3RyYXBTZWNyZXQoZW52KSwgYm9keS51c2VySWQsIGJvZHkuZGV2aWNlSWQsIG5vdyk7XG4gICAgICBjb25zdCBidW5kbGU6IERlcGxveW1lbnRCdW5kbGUgPSB7XG4gICAgICAgIC4uLnB1YmxpY0RlcGxveW1lbnRCdW5kbGUocmVxdWVzdCwgZW52KSxcbiAgICAgICAgZGV2aWNlUnVudGltZUF1dGg6IGF3YWl0IGlzc3VlRGV2aWNlUnVudGltZUF1dGgoZW52LCBib2R5LnVzZXJJZCwgYm9keS5kZXZpY2VJZCwgbm93KSxcbiAgICAgICAgZXhwZWN0ZWRVc2VySWQ6IGJvZHkudXNlcklkLFxuICAgICAgICBleHBlY3RlZERldmljZUlkOiBib2R5LmRldmljZUlkXG4gICAgICB9O1xuICAgICAgcmV0dXJuIGpzb25SZXNwb25zZShidW5kbGUpO1xuICAgIH1cblxuICAgIGNvbnN0IGluYm94TWF0Y2ggPSB1cmwucGF0aG5hbWUubWF0Y2goL15cXC92MVxcL2luYm94XFwvKFteL10rKVxcLyhtZXNzYWdlc3xhY2t8aGVhZHxzdWJzY3JpYmV8YWxsb3dsaXN0fG1lc3NhZ2UtcmVxdWVzdHMoPzpcXC9bXi9dK1xcLyg/OmFjY2VwdHxyZWplY3QpKT8pJC8pO1xuICAgIGlmIChpbmJveE1hdGNoKSB7XG4gICAgICBjb25zdCBkZXZpY2VJZCA9IGRlY29kZVVSSUNvbXBvbmVudChpbmJveE1hdGNoWzFdKTtcbiAgICAgIGNvbnN0IG9wZXJhdGlvbiA9IGluYm94TWF0Y2hbMl07XG4gICAgICBjb25zdCBvYmplY3RJZCA9IGVudi5JTkJPWC5pZEZyb21OYW1lKGRldmljZUlkKTtcbiAgICAgIGNvbnN0IHN0dWIgPSBlbnYuSU5CT1guZ2V0KG9iamVjdElkKTtcblxuICAgICAgaWYgKHJlcXVlc3QubWV0aG9kID09PSBcIlBPU1RcIiAmJiBvcGVyYXRpb24gPT09IFwibWVzc2FnZXNcIikge1xuICAgICAgICBjb25zdCBib2R5ID0gKGF3YWl0IHJlcXVlc3QuY2xvbmUoKS5qc29uKCkpIGFzIEFwcGVuZEVudmVsb3BlUmVxdWVzdDtcbiAgICAgICAgdmFsaWRhdGVBcHBlbmRBdXRob3JpemF0aW9uKHJlcXVlc3QsIGRldmljZUlkLCBib2R5LCBub3cpO1xuICAgICAgfSBlbHNlIGlmIChyZXF1ZXN0Lm1ldGhvZCA9PT0gXCJHRVRcIiAmJiAob3BlcmF0aW9uID09PSBcIm1lc3NhZ2VzXCIgfHwgb3BlcmF0aW9uID09PSBcImhlYWRcIikpIHtcbiAgICAgICAgYXdhaXQgdmFsaWRhdGVEZXZpY2VSdW50aW1lQXV0aG9yaXphdGlvbkZvckRldmljZShyZXF1ZXN0LCBzaGFyZWRTdGF0ZVNlY3JldChlbnYpLCBkZXZpY2VJZCwgXCJpbmJveF9yZWFkXCIsIG5vdyk7XG4gICAgICB9IGVsc2UgaWYgKHJlcXVlc3QubWV0aG9kID09PSBcIlBPU1RcIiAmJiBvcGVyYXRpb24gPT09IFwiYWNrXCIpIHtcbiAgICAgICAgYXdhaXQgdmFsaWRhdGVEZXZpY2VSdW50aW1lQXV0aG9yaXphdGlvbkZvckRldmljZShyZXF1ZXN0LCBzaGFyZWRTdGF0ZVNlY3JldChlbnYpLCBkZXZpY2VJZCwgXCJpbmJveF9hY2tcIiwgbm93KTtcbiAgICAgIH0gZWxzZSBpZiAob3BlcmF0aW9uID09PSBcInN1YnNjcmliZVwiKSB7XG4gICAgICAgIGF3YWl0IHZhbGlkYXRlRGV2aWNlUnVudGltZUF1dGhvcml6YXRpb25Gb3JEZXZpY2UocmVxdWVzdCwgc2hhcmVkU3RhdGVTZWNyZXQoZW52KSwgZGV2aWNlSWQsIFwiaW5ib3hfc3Vic2NyaWJlXCIsIG5vdyk7XG4gICAgICB9IGVsc2UgaWYgKFxuICAgICAgICBvcGVyYXRpb24gPT09IFwiYWxsb3dsaXN0XCIgfHxcbiAgICAgICAgb3BlcmF0aW9uID09PSBcIm1lc3NhZ2UtcmVxdWVzdHNcIiB8fFxuICAgICAgICBvcGVyYXRpb24uc3RhcnRzV2l0aChcIm1lc3NhZ2UtcmVxdWVzdHMvXCIpXG4gICAgICApIHtcbiAgICAgICAgYXdhaXQgdmFsaWRhdGVEZXZpY2VSdW50aW1lQXV0aG9yaXphdGlvbkZvckRldmljZShyZXF1ZXN0LCBzaGFyZWRTdGF0ZVNlY3JldChlbnYpLCBkZXZpY2VJZCwgXCJpbmJveF9tYW5hZ2VcIiwgbm93KTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIHN0dWIuZmV0Y2gocmVxdWVzdCk7XG4gICAgfVxuXG4gICAgY29uc3QgaWRlbnRpdHlCdW5kbGVNYXRjaCA9IHVybC5wYXRobmFtZS5tYXRjaCgvXlxcL3YxXFwvc2hhcmVkLXN0YXRlXFwvKFteL10rKVxcL2lkZW50aXR5LWJ1bmRsZSQvKTtcbiAgICBpZiAoaWRlbnRpdHlCdW5kbGVNYXRjaCkge1xuICAgICAgY29uc3QgdXNlcklkID0gZGVjb2RlVVJJQ29tcG9uZW50KGlkZW50aXR5QnVuZGxlTWF0Y2hbMV0pO1xuICAgICAgaWYgKHJlcXVlc3QubWV0aG9kID09PSBcIkdFVFwiKSB7XG4gICAgICAgIGNvbnN0IGJ1bmRsZSA9IGF3YWl0IHNoYXJlZFN0YXRlLmdldElkZW50aXR5QnVuZGxlKHVzZXJJZCk7XG4gICAgICAgIGlmICghYnVuZGxlKSB7XG4gICAgICAgICAgcmV0dXJuIGpzb25SZXNwb25zZSh7IGVycm9yOiBcIm5vdF9mb3VuZFwiLCBtZXNzYWdlOiBcImlkZW50aXR5IGJ1bmRsZSBub3QgZm91bmRcIiB9LCA0MDQpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBqc29uUmVzcG9uc2UoYnVuZGxlKTtcbiAgICAgIH1cbiAgICAgIGlmIChyZXF1ZXN0Lm1ldGhvZCA9PT0gXCJQVVRcIikge1xuICAgICAgICBhd2FpdCBhdXRob3JpemVTaGFyZWRTdGF0ZVdyaXRlKHJlcXVlc3QsIGVudiwgdXNlcklkLCBcImlkZW50aXR5X2J1bmRsZVwiLCBub3cpO1xuICAgICAgICBjb25zdCBib2R5ID0gKGF3YWl0IHJlcXVlc3QuanNvbigpKSBhcyBJZGVudGl0eUJ1bmRsZTtcbiAgICAgICAgYXdhaXQgc2hhcmVkU3RhdGUucHV0SWRlbnRpdHlCdW5kbGUodXNlcklkLCBib2R5KTtcbiAgICAgICAgY29uc3Qgc2F2ZWQgPSBhd2FpdCBzaGFyZWRTdGF0ZS5nZXRJZGVudGl0eUJ1bmRsZSh1c2VySWQpO1xuICAgICAgICByZXR1cm4ganNvblJlc3BvbnNlKHNhdmVkKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBjb25zdCBkZXZpY2VTdGF0dXNNYXRjaCA9IHVybC5wYXRobmFtZS5tYXRjaCgvXlxcL3YxXFwvc2hhcmVkLXN0YXRlXFwvKFteL10rKVxcL2RldmljZS1zdGF0dXMkLyk7XG4gICAgaWYgKGRldmljZVN0YXR1c01hdGNoKSB7XG4gICAgICBjb25zdCB1c2VySWQgPSBkZWNvZGVVUklDb21wb25lbnQoZGV2aWNlU3RhdHVzTWF0Y2hbMV0pO1xuICAgICAgaWYgKHJlcXVlc3QubWV0aG9kID09PSBcIkdFVFwiKSB7XG4gICAgICAgIGNvbnN0IGRvY3VtZW50ID0gYXdhaXQgc2hhcmVkU3RhdGUuZ2V0RGV2aWNlU3RhdHVzKHVzZXJJZCk7XG4gICAgICAgIGlmICghZG9jdW1lbnQpIHtcbiAgICAgICAgICByZXR1cm4ganNvblJlc3BvbnNlKHsgZXJyb3I6IFwibm90X2ZvdW5kXCIsIG1lc3NhZ2U6IFwiZGV2aWNlIHN0YXR1cyBub3QgZm91bmRcIiB9LCA0MDQpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBqc29uUmVzcG9uc2UoZG9jdW1lbnQpO1xuICAgICAgfVxuICAgICAgaWYgKHJlcXVlc3QubWV0aG9kID09PSBcIlBVVFwiKSB7XG4gICAgICAgIGF3YWl0IGF1dGhvcml6ZVNoYXJlZFN0YXRlV3JpdGUocmVxdWVzdCwgZW52LCB1c2VySWQsIFwiZGV2aWNlX3N0YXR1c1wiLCBub3cpO1xuICAgICAgICBjb25zdCBib2R5ID0gKGF3YWl0IHJlcXVlc3QuanNvbigpKSBhcyBEZXZpY2VTdGF0dXNEb2N1bWVudDtcbiAgICAgICAgYXdhaXQgc2hhcmVkU3RhdGUucHV0RGV2aWNlU3RhdHVzKHVzZXJJZCwgYm9keSk7XG4gICAgICAgIGNvbnN0IHNhdmVkID0gYXdhaXQgc2hhcmVkU3RhdGUuZ2V0RGV2aWNlU3RhdHVzKHVzZXJJZCk7XG4gICAgICAgIHJldHVybiBqc29uUmVzcG9uc2Uoc2F2ZWQpO1xuICAgICAgfVxuICAgIH1cblxuICAgIGNvbnN0IGRldmljZUxpc3RNYXRjaCA9IHVybC5wYXRobmFtZS5tYXRjaCgvXlxcL3YxXFwvc2hhcmVkLXN0YXRlXFwvKFteL10rKVxcL2RldmljZS1saXN0JC8pO1xuICAgIGlmIChkZXZpY2VMaXN0TWF0Y2ggJiYgcmVxdWVzdC5tZXRob2QgPT09IFwiR0VUXCIpIHtcbiAgICAgIGNvbnN0IHVzZXJJZCA9IGRlY29kZVVSSUNvbXBvbmVudChkZXZpY2VMaXN0TWF0Y2hbMV0pO1xuICAgICAgY29uc3QgZG9jdW1lbnQgPSBhd2FpdCBzaGFyZWRTdGF0ZS5nZXREZXZpY2VMaXN0KHVzZXJJZCk7XG4gICAgICBpZiAoIWRvY3VtZW50KSB7XG4gICAgICAgIHJldHVybiBqc29uUmVzcG9uc2UoeyBlcnJvcjogXCJub3RfZm91bmRcIiwgbWVzc2FnZTogXCJkZXZpY2UgbGlzdCBub3QgZm91bmRcIiB9LCA0MDQpO1xuICAgICAgfVxuICAgICAgcmV0dXJuIGpzb25SZXNwb25zZShkb2N1bWVudCk7XG4gICAgfVxuXG4gICAgY29uc3Qga2V5UGFja2FnZVJlZnNNYXRjaCA9IHVybC5wYXRobmFtZS5tYXRjaCgvXlxcL3YxXFwvc2hhcmVkLXN0YXRlXFwva2V5cGFja2FnZXNcXC8oW14vXSspXFwvKFteL10rKSQvKTtcbiAgICBpZiAoa2V5UGFja2FnZVJlZnNNYXRjaCkge1xuICAgICAgY29uc3QgdXNlcklkID0gZGVjb2RlVVJJQ29tcG9uZW50KGtleVBhY2thZ2VSZWZzTWF0Y2hbMV0pO1xuICAgICAgY29uc3QgZGV2aWNlSWQgPSBkZWNvZGVVUklDb21wb25lbnQoa2V5UGFja2FnZVJlZnNNYXRjaFsyXSk7XG4gICAgICBpZiAocmVxdWVzdC5tZXRob2QgPT09IFwiR0VUXCIpIHtcbiAgICAgICAgY29uc3QgZG9jdW1lbnQgPSBhd2FpdCBzaGFyZWRTdGF0ZS5nZXRLZXlQYWNrYWdlUmVmcyh1c2VySWQsIGRldmljZUlkKTtcbiAgICAgICAgaWYgKCFkb2N1bWVudCkge1xuICAgICAgICAgIHJldHVybiBqc29uUmVzcG9uc2UoeyBlcnJvcjogXCJub3RfZm91bmRcIiwgbWVzc2FnZTogXCJrZXlwYWNrYWdlIHJlZnMgbm90IGZvdW5kXCIgfSwgNDA0KTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4ganNvblJlc3BvbnNlKGRvY3VtZW50KTtcbiAgICAgIH1cbiAgICAgIGlmIChyZXF1ZXN0Lm1ldGhvZCA9PT0gXCJQVVRcIikge1xuICAgICAgICBhd2FpdCB2YWxpZGF0ZUtleVBhY2thZ2VXcml0ZUF1dGhvcml6YXRpb24ocmVxdWVzdCwgc2hhcmVkU3RhdGVTZWNyZXQoZW52KSwgdXNlcklkLCBkZXZpY2VJZCwgdW5kZWZpbmVkLCBub3cpO1xuICAgICAgICBjb25zdCBib2R5ID0gKGF3YWl0IHJlcXVlc3QuanNvbigpKSBhcyBLZXlQYWNrYWdlUmVmc0RvY3VtZW50O1xuICAgICAgICBhd2FpdCBzaGFyZWRTdGF0ZS5wdXRLZXlQYWNrYWdlUmVmcyh1c2VySWQsIGRldmljZUlkLCBib2R5KTtcbiAgICAgICAgY29uc3Qgc2F2ZWQgPSBhd2FpdCBzaGFyZWRTdGF0ZS5nZXRLZXlQYWNrYWdlUmVmcyh1c2VySWQsIGRldmljZUlkKTtcbiAgICAgICAgcmV0dXJuIGpzb25SZXNwb25zZShzYXZlZCk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgY29uc3Qga2V5UGFja2FnZU9iamVjdE1hdGNoID0gdXJsLnBhdGhuYW1lLm1hdGNoKC9eXFwvdjFcXC9zaGFyZWQtc3RhdGVcXC9rZXlwYWNrYWdlc1xcLyhbXi9dKylcXC8oW14vXSspXFwvKFteL10rKSQvKTtcbiAgICBpZiAoa2V5UGFja2FnZU9iamVjdE1hdGNoKSB7XG4gICAgICBjb25zdCB1c2VySWQgPSBkZWNvZGVVUklDb21wb25lbnQoa2V5UGFja2FnZU9iamVjdE1hdGNoWzFdKTtcbiAgICAgIGNvbnN0IGRldmljZUlkID0gZGVjb2RlVVJJQ29tcG9uZW50KGtleVBhY2thZ2VPYmplY3RNYXRjaFsyXSk7XG4gICAgICBjb25zdCBrZXlQYWNrYWdlSWQgPSBkZWNvZGVVUklDb21wb25lbnQoa2V5UGFja2FnZU9iamVjdE1hdGNoWzNdKTtcbiAgICAgIGlmIChyZXF1ZXN0Lm1ldGhvZCA9PT0gXCJHRVRcIikge1xuICAgICAgICBjb25zdCBwYXlsb2FkID0gYXdhaXQgc2hhcmVkU3RhdGUuZ2V0S2V5UGFja2FnZU9iamVjdCh1c2VySWQsIGRldmljZUlkLCBrZXlQYWNrYWdlSWQpO1xuICAgICAgICBpZiAoIXBheWxvYWQpIHtcbiAgICAgICAgICByZXR1cm4ganNvblJlc3BvbnNlKHsgZXJyb3I6IFwibm90X2ZvdW5kXCIsIG1lc3NhZ2U6IFwia2V5cGFja2FnZSBub3QgZm91bmRcIiB9LCA0MDQpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBuZXcgUmVzcG9uc2UocGF5bG9hZCwge1xuICAgICAgICAgIHN0YXR1czogMjAwLFxuICAgICAgICAgIGhlYWRlcnM6IHtcbiAgICAgICAgICAgIFwiY29udGVudC10eXBlXCI6IFwiYXBwbGljYXRpb24vb2N0ZXQtc3RyZWFtXCJcbiAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgfVxuICAgICAgaWYgKHJlcXVlc3QubWV0aG9kID09PSBcIlBVVFwiKSB7XG4gICAgICAgIGF3YWl0IHZhbGlkYXRlS2V5UGFja2FnZVdyaXRlQXV0aG9yaXphdGlvbihyZXF1ZXN0LCBzaGFyZWRTdGF0ZVNlY3JldChlbnYpLCB1c2VySWQsIGRldmljZUlkLCBrZXlQYWNrYWdlSWQsIG5vdyk7XG4gICAgICAgIGF3YWl0IHNoYXJlZFN0YXRlLnB1dEtleVBhY2thZ2VPYmplY3QodXNlcklkLCBkZXZpY2VJZCwga2V5UGFja2FnZUlkLCBhd2FpdCByZXF1ZXN0LmFycmF5QnVmZmVyKCkpO1xuICAgICAgICByZXR1cm4gbmV3IFJlc3BvbnNlKG51bGwsIHsgc3RhdHVzOiAyMDQgfSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgaWYgKHJlcXVlc3QubWV0aG9kID09PSBcIlBPU1RcIiAmJiB1cmwucGF0aG5hbWUgPT09IFwiL3YxL3N0b3JhZ2UvcHJlcGFyZS11cGxvYWRcIikge1xuICAgICAgY29uc3QgYXV0aCA9IGF3YWl0IHZhbGlkYXRlQW55RGV2aWNlUnVudGltZUF1dGhvcml6YXRpb24ocmVxdWVzdCwgc2hhcmVkU3RhdGVTZWNyZXQoZW52KSwgXCJzdG9yYWdlX3ByZXBhcmVfdXBsb2FkXCIsIG5vdyk7XG4gICAgICBjb25zdCBib2R5ID0gKGF3YWl0IHJlcXVlc3QuanNvbigpKSBhcyBQcmVwYXJlQmxvYlVwbG9hZFJlcXVlc3Q7XG4gICAgICBjb25zdCByZXN1bHQgPSBhd2FpdCBzdG9yZS5wcmVwYXJlVXBsb2FkKGJvZHksIHsgdXNlcklkOiBhdXRoLnVzZXJJZCwgZGV2aWNlSWQ6IGF1dGguZGV2aWNlSWQgfSwgbm93KTtcbiAgICAgIHJldHVybiBqc29uUmVzcG9uc2UocmVzdWx0KTtcbiAgICB9XG5cbiAgICBjb25zdCB1cGxvYWRNYXRjaCA9IHVybC5wYXRobmFtZS5tYXRjaCgvXlxcL3YxXFwvc3RvcmFnZVxcL3VwbG9hZFxcLyguKykkLyk7XG4gICAgaWYgKHJlcXVlc3QubWV0aG9kID09PSBcIlBVVFwiICYmIHVwbG9hZE1hdGNoKSB7XG4gICAgICBjb25zdCBibG9iS2V5ID0gZGVjb2RlVVJJQ29tcG9uZW50KHVwbG9hZE1hdGNoWzFdKTtcbiAgICAgIGNvbnN0IHRva2VuID0gdXJsLnNlYXJjaFBhcmFtcy5nZXQoXCJ0b2tlblwiKTtcbiAgICAgIGlmICghdG9rZW4pIHtcbiAgICAgICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDEsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwibWlzc2luZyB1cGxvYWQgdG9rZW5cIik7XG4gICAgICB9XG4gICAgICBjb25zdCBjb250ZW50VHlwZSA9IHJlcXVlc3QuaGVhZGVycy5nZXQoXCJjb250ZW50LXR5cGVcIikgPz8gXCJhcHBsaWNhdGlvbi9vY3RldC1zdHJlYW1cIjtcbiAgICAgIGF3YWl0IHN0b3JlLnVwbG9hZEJsb2IoYmxvYktleSwgdG9rZW4sIGF3YWl0IHJlcXVlc3QuYXJyYXlCdWZmZXIoKSwgeyBcImNvbnRlbnQtdHlwZVwiOiBjb250ZW50VHlwZSB9LCBub3cpO1xuICAgICAgcmV0dXJuIG5ldyBSZXNwb25zZShudWxsLCB7IHN0YXR1czogMjA0IH0pO1xuICAgIH1cblxuICAgIGNvbnN0IGJsb2JNYXRjaCA9IHVybC5wYXRobmFtZS5tYXRjaCgvXlxcL3YxXFwvc3RvcmFnZVxcL2Jsb2JcXC8oLispJC8pO1xuICAgIGlmIChyZXF1ZXN0Lm1ldGhvZCA9PT0gXCJHRVRcIiAmJiBibG9iTWF0Y2gpIHtcbiAgICAgIGNvbnN0IGJsb2JLZXkgPSBkZWNvZGVVUklDb21wb25lbnQoYmxvYk1hdGNoWzFdKTtcbiAgICAgIGNvbnN0IHRva2VuID0gdXJsLnNlYXJjaFBhcmFtcy5nZXQoXCJ0b2tlblwiKTtcbiAgICAgIGlmICghdG9rZW4pIHtcbiAgICAgICAgdGhyb3cgbmV3IEh0dHBFcnJvcig0MDEsIFwiaW52YWxpZF9jYXBhYmlsaXR5XCIsIFwibWlzc2luZyBkb3dubG9hZCB0b2tlblwiKTtcbiAgICAgIH1cbiAgICAgIGNvbnN0IHBheWxvYWQgPSBhd2FpdCBzdG9yZS5mZXRjaEJsb2IoYmxvYktleSwgdG9rZW4sIG5vdyk7XG4gICAgICByZXR1cm4gbmV3IFJlc3BvbnNlKHBheWxvYWQsIHtcbiAgICAgICAgc3RhdHVzOiAyMDAsXG4gICAgICAgIGhlYWRlcnM6IHtcbiAgICAgICAgICBcImNvbnRlbnQtdHlwZVwiOiBcImFwcGxpY2F0aW9uL29jdGV0LXN0cmVhbVwiXG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHJldHVybiBqc29uUmVzcG9uc2UoeyBlcnJvcjogXCJub3RfZm91bmRcIiwgbWVzc2FnZTogXCJyb3V0ZSBub3QgZm91bmRcIiB9LCA0MDQpO1xuICB9IGNhdGNoIChlcnJvcikge1xuICAgIGlmIChlcnJvciBpbnN0YW5jZW9mIEh0dHBFcnJvcikge1xuICAgICAgcmV0dXJuIGpzb25SZXNwb25zZSh7IGVycm9yOiBlcnJvci5jb2RlLCBtZXNzYWdlOiBlcnJvci5tZXNzYWdlIH0sIGVycm9yLnN0YXR1cyk7XG4gICAgfVxuICAgIGNvbnN0IHJ1bnRpbWVFcnJvciA9IGVycm9yIGFzIHsgbWVzc2FnZT86IHN0cmluZyB9O1xuICAgIGNvbnN0IG1lc3NhZ2UgPSBydW50aW1lRXJyb3IubWVzc2FnZSA/PyBcImludGVybmFsIGVycm9yXCI7XG4gICAgcmV0dXJuIGpzb25SZXNwb25zZSh7IGVycm9yOiBcInRlbXBvcmFyeV91bmF2YWlsYWJsZVwiLCBtZXNzYWdlIH0sIDUwMCk7XG4gIH1cbn1cclxuIiwgImltcG9ydCB7IEluYm94RHVyYWJsZU9iamVjdCB9IGZyb20gXCIuL2luYm94L2R1cmFibGVcIjtcbmltcG9ydCB7IGhhbmRsZVJlcXVlc3QgfSBmcm9tIFwiLi9yb3V0ZXMvaHR0cFwiO1xuaW1wb3J0IHR5cGUgeyBFbnYgfSBmcm9tIFwiLi90eXBlcy9ydW50aW1lXCI7XG5cbmV4cG9ydCB7IEluYm94RHVyYWJsZU9iamVjdCB9O1xuXG5leHBvcnQgZGVmYXVsdCB7XG4gIGFzeW5jIGZldGNoKHJlcXVlc3Q6IFJlcXVlc3QsIGVudjogRW52KTogUHJvbWlzZTxSZXNwb25zZT4ge1xuICAgIHJl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UUFBSSxRQUFRLFdBQVcsU0FBUyxXQUFXO0FBQ3pDLFlBQU0sVUFBVSxtQkFBbUIsVUFBVSxDQUFDLENBQUM7QUFDL0MsWUFBTSxRQUFRLElBQUksYUFBYSxJQUFJLE9BQU87QUFDMUMsVUFBSSxDQUFDLE9BQU87QUFDVixjQUFNLElBQUksVUFBVSxLQUFLLHNCQUFzQix3QkFBd0I7QUFBQSxNQUN6RTtBQUNBLFlBQU0sVUFBVSxNQUFNLE1BQU0sVUFBVSxTQUFTLE9BQU8sR0FBRztBQUN6RCxhQUFPLElBQUksU0FBUyxTQUFTO0FBQUEsUUFDM0IsUUFBUTtBQUFBLFFBQ1IsU0FBUztBQUFBLFVBQ1AsZ0JBQWdCO0FBQUEsUUFDbEI7QUFBQSxNQUNGLENBQUM7QUFBQSxJQUNIO0FBRUEsV0FBT0EsY0FBYSxFQUFFLE9BQU8sYUFBYSxTQUFTLGtCQUFrQixHQUFHLEdBQUc7QUFBQSxFQUM3RSxTQUFTLE9BQU87QUFDZCxRQUFJLGlCQUFpQixXQUFXO0FBQzlCLGFBQU9BLGNBQWEsRUFBRSxPQUFPLE1BQU0sTUFBTSxTQUFTLE1BQU0sUUFBUSxHQUFHLE1BQU0sTUFBTTtBQUFBLElBQ2pGO0FBQ0EsVUFBTSxlQUFlO0FBQ3JCLFVBQU0sVUFBVSxhQUFhLFdBQVc7QUFDeEMsV0FBT0EsY0FBYSxFQUFFLE9BQU8seUJBQXlCLFFBQVEsR0FBRyxHQUFHO0FBQUEsRUFDdEU7QUFDRjs7O0FDdldBLElBQU8sZ0JBQVE7QUFBQSxFQUNiLE1BQU0sTUFBTSxTQUFrQixLQUE2QjtBQUN6RCxXQUFPLGNBQWMsU0FBUyxHQUFHO0FBQUEsRUFDbkM7QUFDRjsiLAogICJuYW1lcyI6IFsiYmFzZVVybCIsICJzYW5pdGl6ZVNlZ21lbnQiLCAiYmFzZVVybCIsICJ2ZXJzaW9uZWRCb2R5IiwgImpzb25SZXNwb25zZSIsICJSMkpzb25CbG9iU3RvcmUiXQp9Cg==

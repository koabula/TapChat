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
function readGroupCapabilityHeader(request) {
  const capabilityHeader = request.headers.get("X-Tapchat-Group-Capability");
  if (!capabilityHeader) {
    throw new HttpError(401, "invalid_capability", "missing X-Tapchat-Group-Capability header");
  }
  try {
    return JSON.parse(capabilityHeader);
  } catch {
    throw new HttpError(400, "invalid_capability", "X-Tapchat-Group-Capability is not valid JSON");
  }
}
function validateGroupReadAuthorization(request, groupId, capability, now) {
  if (!capability) {
    throw new HttpError(401, "invalid_capability", "missing group capability");
  }
  validateGroupCapabilityBase(request, groupId, capability, now);
  if (!capability.operations.includes("read")) {
    throw new HttpError(403, "invalid_capability", "group capability does not grant read");
  }
}
function validateGroupOperationAuthorization(request, groupId, capability, now, operation, allowedRoles = ["owner", "admin"]) {
  validateGroupCapabilityBase(request, groupId, capability, now);
  if (!capability.operations.includes(operation)) {
    throw new HttpError(403, "invalid_capability", `group capability does not grant ${operation}`);
  }
  if (!allowedRoles.includes(capability.role)) {
    throw new HttpError(403, "invalid_capability", `group role cannot use ${operation}`);
  }
}
function validateGroupAppendAuthorization(request, groupId, body, now) {
  const capability = body.capability;
  if (!capability) {
    throw new HttpError(401, "invalid_capability", "missing group capability");
  }
  validateGroupCapabilityBase(request, groupId, capability, now);
  if (body.groupId !== groupId || body.envelope.groupId !== groupId) {
    throw new HttpError(403, "invalid_capability", "group capability scope does not match request group");
  }
  for (const required of requiredGroupAppendOperations(body.envelope.messageType)) {
    if (!capability.operations.includes(required)) {
      throw new HttpError(403, "invalid_capability", `group capability does not grant ${required}`);
    }
  }
  for (const role of allowedGroupAppendRoles(body.envelope.messageType)) {
    if (capability.role === role) {
      return;
    }
  }
  throw new HttpError(403, "invalid_capability", `group role cannot append ${body.envelope.messageType}`);
}
function validateWelcomePickupAuthorization(request, groupId, deviceId, descriptor, now) {
  const token = getBearerToken(request);
  if (descriptor.groupId !== groupId || descriptor.deviceId !== deviceId) {
    throw new HttpError(403, "invalid_capability", "welcome pickup descriptor scope does not match request path");
  }
  const requestUrl = new URL(request.url);
  if (descriptor.endpoint !== `${requestUrl.origin}${requestUrl.pathname}`) {
    throw new HttpError(403, "invalid_capability", "welcome pickup endpoint does not match request path");
  }
  if (descriptor.expiresAt <= now) {
    throw new HttpError(403, "capability_expired", "welcome pickup capability is expired");
  }
  if (descriptor.capability !== token) {
    throw new HttpError(403, "invalid_capability", "welcome pickup capability does not match bearer token");
  }
}
function validateGroupCapabilityBase(request, groupId, capability, now) {
  const signature = getBearerToken(request);
  if (capability.version !== CURRENT_MODEL_VERSION) {
    throw new HttpError(400, "unsupported_version", "group capability version is not supported");
  }
  if (capability.signature !== signature) {
    throw new HttpError(403, "invalid_capability", "group capability signature does not match bearer token");
  }
  if (capability.service !== "group_outbox") {
    throw new HttpError(403, "invalid_capability", "group capability service must be group_outbox");
  }
  if (capability.groupId !== groupId) {
    throw new HttpError(403, "invalid_capability", "group capability groupId does not match request path");
  }
  if (capability.expiresAt <= now) {
    throw new HttpError(403, "capability_expired", "group capability is expired");
  }
}
function requiredGroupAppendOperations(messageType) {
  switch (messageType) {
    case "mls_application":
      return ["append_application"];
    case "mls_commit":
    case "control_group_membership_changed":
      return ["append_membership"];
    case "control_group_metadata_updated":
      return ["update_group_metadata"];
    case "control_group_join_approved":
    case "control_group_join_rejected":
      return ["approve_join"];
    case "control_group_leave_requested":
    case "control_group_join_requested":
    case "control_conversation_needs_rebuild":
      return ["append_control"];
    default:
      return ["append_control"];
  }
}
function allowedGroupAppendRoles(messageType) {
  switch (messageType) {
    case "mls_commit":
    case "control_group_membership_changed":
    case "control_group_metadata_updated":
    case "control_group_join_approved":
    case "control_group_join_rejected":
      return ["owner", "admin"];
    default:
      return ["owner", "admin", "member"];
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

// src/group-outbox/service.ts
var META_KEY = "meta";
var IDEMPOTENCY_PREFIX = "idempotency:";
var RECORD_PREFIX = "record:";
var INVITE_PREFIX = "invite:";
var JOIN_REQUEST_PREFIX = "join-request:";
var GroupOutboxService = class {
  groupId;
  state;
  spillStore;
  defaults;
  sessions;
  constructor(groupId, state, spillStore, defaults, sessions = []) {
    this.groupId = groupId;
    this.state = state;
    this.spillStore = spillStore;
    this.defaults = defaults;
    this.sessions = sessions;
  }
  async appendEnvelope(input, now) {
    await this.rejectIfSealed();
    this.validateAppendRequest(input);
    const existingSeq = await this.state.get(`${IDEMPOTENCY_PREFIX}${input.envelope.messageId}`);
    if (existingSeq !== void 0) {
      return { accepted: true, seq: existingSeq };
    }
    const meta = await this.getMeta();
    if (input.expectedPreviousRosterVersion !== void 0) {
      const storedRosterVersion = meta.currentRosterVersion ?? 0;
      if (input.expectedPreviousRosterVersion !== storedRosterVersion) {
        throw new HttpError(
          409,
          "roster_version_conflict",
          `expected previous roster version ${input.expectedPreviousRosterVersion} but current is ${storedRosterVersion}`
        );
      }
    }
    if (input.expectedPreviousCommitMessageId !== void 0) {
      const storedCommitMessageId = meta.lastCommitMessageId ?? "";
      if (input.expectedPreviousCommitMessageId !== storedCommitMessageId) {
        throw new HttpError(
          409,
          "roster_version_conflict",
          `expected previous commit message id does not match current`
        );
      }
    }
    const seq = meta.headSeq + 1;
    const expiresAt = now + meta.retentionDays * 24 * 60 * 60 * 1e3;
    const record = {
      seq,
      groupId: this.groupId,
      messageId: input.envelope.messageId,
      receivedAt: now,
      expiresAt,
      state: "available",
      envelope: input.envelope
    };
    const serialized = JSON.stringify(record);
    const storageKey = `${RECORD_PREFIX}${seq}`;
    if (new TextEncoder().encode(serialized).byteLength <= meta.maxInlineBytes && input.envelope.inlineCiphertext) {
      await this.state.put(storageKey, {
        seq,
        groupId: record.groupId,
        messageId: record.messageId,
        receivedAt: record.receivedAt,
        expiresAt,
        state: record.state,
        inlineRecord: record
      });
    } else {
      const payloadRef = `group-outbox-payload/${this.groupId}/${seq}.json`;
      await this.spillStore.putJson(payloadRef, record);
      await this.state.put(storageKey, {
        seq,
        groupId: record.groupId,
        messageId: record.messageId,
        receivedAt: record.receivedAt,
        expiresAt,
        state: record.state,
        payloadRef
      });
    }
    let nextMeta = { ...meta, headSeq: seq };
    const proof = input.envelope.membershipProof;
    if (proof && proof.type === "membership_signature") {
      if (typeof proof.newRosterVersion === "number") {
        nextMeta.currentRosterVersion = proof.newRosterVersion;
      }
      if (typeof proof.commitMessageId === "string" && proof.commitMessageId.length > 0) {
        nextMeta.lastCommitMessageId = proof.commitMessageId;
      }
    }
    await this.state.put(`${IDEMPOTENCY_PREFIX}${record.messageId}`, seq);
    await this.state.put(META_KEY, nextMeta);
    await this.state.setAlarm(expiresAt);
    this.publish({ event: "group_head_updated", groupId: this.groupId, seq });
    this.publish({ event: "group_outbox_record_available", groupId: this.groupId, seq, record });
    return { accepted: true, seq };
  }
  async fetchOutbox(input) {
    if (input.groupId !== this.groupId) {
      throw new HttpError(400, "invalid_input", "group_id does not match group outbox route");
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
        throw new HttpError(500, "temporary_unavailable", "group record payload reference is missing");
      }
      const record = await this.spillStore.getJson(index.payloadRef);
      if (record) {
        records.push(record);
      }
    }
    return {
      toSeq: records.length > 0 ? records[records.length - 1].seq : meta.headSeq,
      records
    };
  }
  async getHead() {
    const meta = await this.getMeta();
    return {
      headSeq: meta.headSeq,
      currentRosterVersion: meta.currentRosterVersion,
      lastCommitMessageId: meta.lastCommitMessageId
    };
  }
  async createInvite(input, inviteUrl, token, now) {
    if (input.groupId !== this.groupId || input.document.groupId !== this.groupId) {
      throw new HttpError(400, "invalid_input", "group_id does not match group invite route");
    }
    await this.rejectIfSealed();
    this.validateInviteDocument(input.document, now);
    const key = `${INVITE_PREFIX}${input.document.inviteId}`;
    const existing = await this.state.get(key);
    if (existing) {
      if (existing.document.signature !== input.document.signature) {
        throw new HttpError(409, "conflict", "invite id already exists with a different document");
      }
      return { inviteUrl: existing.inviteUrl, invite: existing.document };
    }
    const stored = {
      inviteUrl,
      token,
      document: { ...input.document, signature: token },
      uses: 0,
      maxUses: input.maxUses ?? input.document.maxUses
    };
    await this.state.put(key, stored);
    await this.state.setAlarm(input.document.expiresAt);
    return { inviteUrl, invite: stored.document };
  }
  async fetchInvite(payload, now) {
    if (payload.groupId !== this.groupId) {
      throw new HttpError(400, "invalid_input", "invite token group does not match route");
    }
    const stored = await this.loadUsableInvite(payload.inviteId, now);
    if (stored.token !== stored.document.signature) {
      throw new HttpError(403, "invalid_capability", "invite signature is invalid");
    }
    return { invite: stored.document };
  }
  async fetchInviteById(inviteId, now) {
    const stored = await this.loadUsableInvite(inviteId, now);
    if (stored.token !== stored.document.signature) {
      throw new HttpError(403, "invalid_capability", "invite signature is invalid");
    }
    return { invite: stored.document };
  }
  async revokeInvite(input, now) {
    if (input.groupId !== this.groupId) {
      throw new HttpError(400, "invalid_input", "group_id does not match group invite route");
    }
    await this.rejectIfSealed();
    const key = `${INVITE_PREFIX}${input.inviteId}`;
    const stored = await this.state.get(key);
    if (!stored) {
      throw new HttpError(404, "not_found", "invite not found");
    }
    await this.state.put(key, { ...stored, revokedAt: now });
    return { accepted: true, inviteId: input.inviteId };
  }
  async submitJoinRequest(input, payload, now) {
    if (payload.groupId !== this.groupId || input.request.groupId !== this.groupId) {
      throw new HttpError(400, "invalid_input", "join request group does not match route");
    }
    await this.rejectIfSealed();
    if (payload.inviteId !== input.request.inviteId) {
      throw new HttpError(403, "invalid_capability", "join request invite does not match bearer token");
    }
    const invite = await this.loadUsableInvite(payload.inviteId, now);
    if (invite.document.joinPolicy === "closed") {
      throw new HttpError(403, "invalid_invite", "invite does not allow link join requests");
    }
    this.validateJoinRequest(input.request, now);
    const key = `${JOIN_REQUEST_PREFIX}${input.request.requestId}`;
    const existing = await this.state.get(key);
    if (existing) {
      if (JSON.stringify(existing.request) !== JSON.stringify(input.request)) {
        throw new HttpError(409, "conflict", "join request id already exists with different content");
      }
      return {
        accepted: true,
        request: existing.request,
        autoApprove: existing.request.autoApprove
      };
    }
    const request = {
      ...input.request,
      status: "pending",
      autoApprove: invite.document.joinPolicy === "open_by_invite"
    };
    await this.state.put(key, { request });
    await this.state.put(`${INVITE_PREFIX}${payload.inviteId}`, {
      ...invite,
      uses: invite.uses + 1
    });
    this.publish({
      event: "group_join_request_available",
      groupId: this.groupId,
      requestId: request.requestId
    });
    return { accepted: true, request, autoApprove: request.autoApprove };
  }
  async listJoinRequests() {
    const result = await this.state.list({ prefix: JOIN_REQUEST_PREFIX });
    const requests = Array.from(result.values()).map((stored) => stored.request).filter((request) => request.groupId === this.groupId && request.status === "pending").sort((a, b) => a.requestedAt - b.requestedAt || a.requestId.localeCompare(b.requestId));
    return { requests };
  }
  async getJoinRequestStatus(requestId, requestCapability) {
    const stored = await this.state.get(`${JOIN_REQUEST_PREFIX}${requestId}`);
    if (!stored || stored.request.groupId !== this.groupId) {
      throw new HttpError(404, "not_found", "join request not found");
    }
    if (stored.request.requestCapability !== requestCapability) {
      throw new HttpError(403, "invalid_capability", "join request capability does not match bearer token");
    }
    if (stored.request.status !== "approved") {
      return { request: stored.request };
    }
    return {
      request: stored.request,
      welcomePickup: stored.welcomePickup,
      manifest: stored.manifest,
      startCursor: stored.startCursor
    };
  }
  async decideJoinRequest(input) {
    if (input.groupId !== this.groupId) {
      throw new HttpError(400, "invalid_input", "group_id does not match group join route");
    }
    await this.rejectIfSealed();
    const key = `${JOIN_REQUEST_PREFIX}${input.requestId}`;
    const stored = await this.state.get(key);
    if (!stored || stored.request.groupId !== this.groupId) {
      throw new HttpError(404, "not_found", "join request not found");
    }
    if (stored.request.status !== "pending") {
      throw new HttpError(409, "conflict", "join request is already terminal");
    }
    if (input.decision === "approve" && (!input.welcomePickup || !input.manifest || !input.startCursor)) {
      throw new HttpError(400, "invalid_input", "approved join request requires welcome pickup, manifest, and start cursor");
    }
    if (input.decision === "reject" && (input.welcomePickup || input.manifest || input.startCursor)) {
      throw new HttpError(400, "invalid_input", "rejected join request must not include welcome pickup, manifest, or start cursor");
    }
    const request = {
      ...stored.request,
      status: input.decision === "approve" ? "approved" : "rejected"
    };
    const updated = {
      request,
      welcomePickup: input.decision === "approve" ? input.welcomePickup : void 0,
      manifest: input.decision === "approve" ? input.manifest : void 0,
      startCursor: input.decision === "approve" ? input.startCursor : void 0,
      reason: input.decision === "reject" ? input.reason : void 0
    };
    await this.state.put(key, updated);
    return { accepted: true, request };
  }
  async getMeta() {
    return await this.state.get(META_KEY) ?? this.defaults;
  }
  /**
   * Idempotent seal of the group outbox. The very first caller flips
   * `sealed = true` and records `sealedAt = now`; subsequent callers are
   * rejected with HTTP 409 `already_sealed` regardless of their
   * capability (PROTOCOL_GROUP_CN.md §10.4 — seals are irreversible).
   *
   * Callers must already have authenticated owner-signed
   * `seal_group` capability at the transport layer; this method only
   * enforces the storage-side invariant.
   */
  async sealOutbox(now) {
    const meta = await this.getMeta();
    if (meta.sealed === true) {
      throw new HttpError(409, "already_sealed", "group outbox is already sealed");
    }
    const nextMeta = { ...meta, sealed: true, sealedAt: now };
    await this.state.put(META_KEY, nextMeta);
    return { sealed: true, sealedAt: now, wasAlreadySealed: false };
  }
  async getSealStatus() {
    const meta = await this.getMeta();
    return { sealed: meta.sealed === true, sealedAt: meta.sealedAt ?? 0 };
  }
  /**
   * Reject any append-type flow on a sealed outbox with the canonical
   * `403 group_sealed` response. Reads (fetch / head / subscribe-replay)
   * are explicitly allowed to continue, so only write paths call this.
   */
  async rejectIfSealed() {
    const meta = await this.getMeta();
    if (meta.sealed === true) {
      throw new HttpError(403, "group_sealed", "group outbox is sealed and cannot accept new writes");
    }
  }
  validateAppendRequest(input) {
    if (input.groupId !== this.groupId || input.envelope.groupId !== this.groupId) {
      throw new HttpError(400, "invalid_input", "group_id does not match group outbox route");
    }
    this.validateEnvelope(input.envelope);
  }
  async loadUsableInvite(inviteId, now) {
    const stored = await this.state.get(`${INVITE_PREFIX}${inviteId}`);
    if (!stored || stored.document.groupId !== this.groupId) {
      throw new HttpError(404, "not_found", "invite not found");
    }
    if (stored.revokedAt !== void 0) {
      throw new HttpError(403, "invalid_invite", "invite is revoked");
    }
    if (stored.document.expiresAt <= now) {
      throw new HttpError(403, "capability_expired", "invite is expired");
    }
    if (stored.maxUses !== void 0 && stored.uses >= stored.maxUses) {
      throw new HttpError(403, "invalid_invite", "invite max uses exceeded");
    }
    return stored;
  }
  validateInviteDocument(document, now) {
    if (!document.groupId || !document.inviteId || !document.title || !document.inviterUserId || !document.inviterDeviceId || !document.ownerUserId || !document.joinRequestEndpoint || !document.signature) {
      throw new HttpError(400, "invalid_input", "invite document is missing required fields");
    }
    if (document.expiresAt <= now) {
      throw new HttpError(400, "invalid_input", "invite must not already be expired");
    }
  }
  validateJoinRequest(request, now) {
    if (!request.requestId || !request.groupId || !request.inviteId || !request.joinerUserId || !request.joinerDeviceId || !request.joinerContactShareUrl || !request.requestCapability || !request.signature) {
      throw new HttpError(400, "invalid_input", "join request is missing required fields");
    }
    if (request.requestedAt > now + 5 * 60 * 1e3) {
      throw new HttpError(400, "invalid_input", "join request timestamp is too far in the future");
    }
  }
  validateEnvelope(envelope) {
    if (!envelope.messageId || !envelope.groupId || !envelope.conversationId || !envelope.senderUserId || !envelope.senderDeviceId) {
      throw new HttpError(400, "invalid_input", "group envelope is missing required fields");
    }
    if (!envelope.senderProof?.type || !envelope.senderProof.value) {
      throw new HttpError(400, "invalid_input", "group envelope sender proof is required");
    }
    const hasInline = Boolean(envelope.inlineCiphertext);
    const hasStorageRefs = (envelope.storageRefs?.length ?? 0) > 0;
    if (!hasInline && !hasStorageRefs) {
      throw new HttpError(400, "invalid_input", "group envelope must include inline_ciphertext or storage_refs");
    }
  }
  publish(event) {
    const payload = JSON.stringify(event);
    for (const session of this.sessions) {
      session.send(payload);
    }
  }
};

// src/group-outbox/durable.ts
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
  async list(options) {
    return this.storage.list(options);
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
async function handleGroupOutboxDurableRequest(request, deps) {
  const now = deps.now ?? Date.now();
  const url = new URL(request.url);
  const service = new GroupOutboxService(deps.groupId, deps.state, deps.spillStore, {
    headSeq: 0,
    retentionDays: deps.retentionDays,
    maxInlineBytes: deps.maxInlineBytes
  }, deps.sessions);
  try {
    if (url.pathname.endsWith("/subscribe") && deps.onUpgrade) {
      validateGroupOperationAuthorization(
        request,
        deps.groupId,
        readGroupCapabilityHeader(request),
        now,
        "subscribe",
        ["owner", "admin", "member"]
      );
      return deps.onUpgrade();
    }
    if (url.pathname.endsWith("/messages") && request.method === "POST") {
      const body = await request.json();
      return jsonResponse(await service.appendEnvelope(body, now));
    }
    if (url.pathname.endsWith("/messages") && request.method === "GET") {
      const fromSeq = Number(url.searchParams.get("fromSeq") ?? "1");
      const limit = Number(url.searchParams.get("limit") ?? "100");
      const capability = JSON.parse(request.headers.get("X-Tapchat-Group-Capability") ?? "{}");
      return jsonResponse(await service.fetchOutbox({
        groupId: deps.groupId,
        fromSeq,
        limit,
        capability
      }));
    }
    if (url.pathname.endsWith("/head") && request.method === "GET") {
      return jsonResponse(await service.getHead());
    }
    if (url.pathname.endsWith("/outbox/seal") && request.method === "POST") {
      const capability = readGroupCapabilityHeader(request);
      validateGroupOperationAuthorization(request, deps.groupId, capability, now, "seal_group", [
        "owner"
      ]);
      return jsonResponse(await service.sealOutbox(now));
    }
    if (url.pathname.match(/\/v1\/groups\/[^/]+\/invites$/) && request.method === "POST") {
      const body = await request.json();
      const token = await signSharingPayload(deps.sharingSecret, {
        version: body.document.version,
        service: "group_invite",
        groupId: deps.groupId,
        inviteId: body.document.inviteId,
        inviterUserId: body.document.inviterUserId,
        inviterDeviceId: body.document.inviterDeviceId,
        joinPolicy: body.document.joinPolicy,
        expiresAt: body.document.expiresAt,
        maxUses: body.maxUses ?? body.document.maxUses
      });
      return jsonResponse(
        await service.createInvite(
          body,
          `${url.origin}/v1/group-invite/${encodeURIComponent(deps.groupId)}/${encodeURIComponent(body.document.inviteId)}`,
          token,
          now
        )
      );
    }
    const shortInviteFetchMatch = url.pathname.match(/\/v1\/group-invite\/([^/]+)\/([^/]+)$/);
    if (shortInviteFetchMatch && request.method === "GET") {
      const routeGroupId = decodeURIComponent(shortInviteFetchMatch[1]);
      if (routeGroupId !== deps.groupId) {
        throw new HttpError(400, "invalid_input", "group invite route does not match durable object");
      }
      return jsonResponse(await service.fetchInviteById(decodeURIComponent(shortInviteFetchMatch[2]), now));
    }
    const inviteFetchMatch = url.pathname.match(/\/v1\/group-invite\/([^/]+)$/);
    if (inviteFetchMatch && request.method === "GET") {
      const payload = await verifyInviteToken(deps.sharingSecret, decodeURIComponent(inviteFetchMatch[1]), now);
      return jsonResponse(await service.fetchInvite(payload, now));
    }
    const revokeMatch = url.pathname.match(/\/v1\/groups\/[^/]+\/invites\/([^/]+)\/revoke$/);
    if (revokeMatch && request.method === "POST") {
      const body = await request.json();
      return jsonResponse(
        await service.revokeInvite(
          {
            version: body.version,
            groupId: deps.groupId,
            inviteId: decodeURIComponent(revokeMatch[1]),
            capability: body.capability
          },
          now
        )
      );
    }
    const joinCollectionMatch = url.pathname.match(/\/v1\/groups\/[^/]+\/join-requests$/);
    if (joinCollectionMatch && request.method === "POST") {
      const token = getBearerToken(request);
      const payload = await verifyInviteToken(deps.sharingSecret, token, now);
      const body = await request.json();
      return jsonResponse(await service.submitJoinRequest({ ...body, inviteToken: token }, payload, now));
    }
    if (joinCollectionMatch && request.method === "GET") {
      return jsonResponse(await service.listJoinRequests());
    }
    const joinStatusMatch = url.pathname.match(/\/v1\/groups\/[^/]+\/join-requests\/([^/]+)$/);
    if (joinStatusMatch && request.method === "GET") {
      return jsonResponse(await service.getJoinRequestStatus(decodeURIComponent(joinStatusMatch[1]), getBearerToken(request)));
    }
    const decisionMatch = url.pathname.match(/\/v1\/groups\/[^/]+\/join-requests\/([^/]+)\/decision$/);
    if (decisionMatch && request.method === "POST") {
      const body = await request.json();
      return jsonResponse(
        await service.decideJoinRequest({
          ...body,
          groupId: deps.groupId,
          requestId: decodeURIComponent(decisionMatch[1])
        })
      );
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
async function verifyInviteToken(secret, token, now) {
  try {
    const payload = await verifySharingPayload(secret, token, now);
    if (payload.version !== "0.1" || payload.service !== "group_invite" || !payload.groupId || !payload.inviteId) {
      throw new Error("malformed group invite token");
    }
    return payload;
  } catch (error) {
    const message = error instanceof Error ? error.message : "invalid group invite token";
    if (message.includes("expired")) {
      throw new HttpError(403, "capability_expired", message);
    }
    throw new HttpError(403, "invalid_capability", message);
  }
}
async function groupIdFromGroupOutboxRequestUrl(url, sharingSecret, now) {
  const groupMatch = url.pathname.match(/\/v1\/groups\/([^/]+)\//);
  let groupId = decodeURIComponent(groupMatch?.[1] ?? "");
  if (!groupId) {
    const shortInviteMatch = url.pathname.match(/\/v1\/group-invite\/([^/]+)\/([^/]+)$/);
    if (shortInviteMatch) {
      groupId = decodeURIComponent(shortInviteMatch[1]);
    }
  }
  if (!groupId) {
    const inviteMatch = url.pathname.match(/\/v1\/group-invite\/([^/]+)$/);
    if (inviteMatch) {
      const payload = await verifyInviteToken(
        sharingSecret,
        decodeURIComponent(inviteMatch[1]),
        now
      );
      groupId = payload.groupId;
    }
  }
  return groupId;
}
var GroupOutboxDurableObject = class extends DurableObjectBase {
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
    const sharingSecret = this.envRef.SHARING_TOKEN_SECRET ?? "replace-me";
    const groupId = await groupIdFromGroupOutboxRequestUrl(url, sharingSecret, Date.now());
    return handleGroupOutboxDurableRequest(request, {
      groupId,
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
      sharingSecret: this.envRef.SHARING_TOKEN_SECRET ?? "replace-me",
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
  // Cloudflare's runtime requires any durable object that calls `setAlarm()`
  // to expose a matching `alarm()` handler. We currently rely on alarms as a
  // best-effort cleanup hook for expired invites and old outbox records; the
  // service itself is responsible for deleting stale entries at read/write
  // time, so the alarm body is intentionally a no-op for now.
  async alarm() {
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

// src/inbox/service.ts
var META_KEY2 = "meta";
var IDEMPOTENCY_PREFIX2 = "idempotency:";
var APPEND_RESULT_PREFIX = "append-result:";
var RECORD_PREFIX2 = "record:";
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
      const index = await this.state.get(`${RECORD_PREFIX2}${seq}`);
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
    await this.state.put(META_KEY2, { ...meta, ackedSeq: ackSeq });
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
    const requestsToPromote = this.messageRequestsToPromote(entry);
    const promotedMessageIds = new Set(
      requestsToPromote.map((request) => request.envelope.messageId)
    );
    for (const request of entry.pendingRequests) {
      if (promotedMessageIds.has(request.envelope.messageId)) {
        continue;
      }
      await this.state.put(
        `${APPEND_RESULT_PREFIX}${request.envelope.messageId}`,
        this.supersededMessageRequestResult()
      );
    }
    let promotedCount = 0;
    const promotedConversationIds = /* @__PURE__ */ new Set();
    for (const request of requestsToPromote) {
      const delivered = await this.deliverEnvelope(request, now);
      await this.state.put(`${APPEND_RESULT_PREFIX}${request.envelope.messageId}`, delivered);
      if (delivered.deliveredTo === "inbox") {
        promotedCount += 1;
        promotedConversationIds.add(request.envelope.conversationId);
      }
    }
    await this.deleteMessageRequest(entry.senderUserId, "accepted");
    return {
      accepted: true,
      requestId: entry.requestId,
      senderUserId: entry.senderUserId,
      senderBundleShareUrl: entry.senderBundleShareUrl,
      senderBundleHash: entry.senderBundleHash,
      senderDisplayName: entry.senderDisplayName,
      promotedCount,
      promotedConversationIds: [...promotedConversationIds].sort()
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
    await this.deleteMessageRequest(entry.senderUserId, "rejected");
    return {
      accepted: true,
      requestId: entry.requestId,
      senderUserId: entry.senderUserId,
      senderBundleShareUrl: entry.senderBundleShareUrl,
      senderBundleHash: entry.senderBundleHash,
      senderDisplayName: entry.senderDisplayName,
      promotedCount: 0,
      promotedConversationIds: []
    };
  }
  async cleanExpiredRecords(now) {
    const meta = await this.getMeta();
    for (let seq = 1; seq <= meta.ackedSeq; seq += 1) {
      const key = `${RECORD_PREFIX2}${seq}`;
      const index = await this.state.get(key);
      if (!index || index.expiresAt === void 0 || index.expiresAt > now) {
        continue;
      }
      if (index.payloadRef) {
        await this.spillStore.delete(index.payloadRef);
      }
      await this.state.delete(key);
      await this.state.delete(`${IDEMPOTENCY_PREFIX2}${index.messageId}`);
    }
  }
  async getMeta() {
    return await this.state.get(META_KEY2) ?? this.defaults;
  }
  async deliverEnvelope(input, now) {
    const meta = await this.getMeta();
    const existingSeq = await this.state.get(`${IDEMPOTENCY_PREFIX2}${input.envelope.messageId}`);
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
    const storageKey = `${RECORD_PREFIX2}${seq}`;
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
    await this.state.put(`${IDEMPOTENCY_PREFIX2}${record.messageId}`, seq);
    await this.state.put(META_KEY2, { ...meta, headSeq: seq });
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
      senderBundleShareUrl: input.senderBundleShareUrl,
      senderBundleHash: input.senderBundleHash,
      senderDisplayName: input.senderDisplayName,
      firstSeenAt: now,
      lastSeenAt: now,
      messageCount: 0,
      lastMessageId: input.envelope.messageId,
      lastConversationId: input.envelope.conversationId,
      pendingRequests: []
    };
    entry.senderBundleShareUrl ??= input.senderBundleShareUrl;
    entry.senderBundleHash ??= input.senderBundleHash;
    entry.senderDisplayName ??= input.senderDisplayName;
    entry.lastSeenAt = now;
    entry.messageCount += 1;
    entry.lastMessageId = input.envelope.messageId;
    entry.lastConversationId = input.envelope.conversationId;
    entry.pendingRequests.push(input);
    await this.state.put(key, entry);
    await this.addMessageRequestIndex(senderUserId);
    this.publish({
      event: "message_request_changed",
      deviceId: this.deviceId,
      senderUserId,
      requestId,
      change: "queued"
    });
    return {
      accepted: true,
      seq: 0,
      deliveredTo: "message_request",
      queuedAsRequest: true,
      requestId
    };
  }
  messageRequestsToPromote(entry) {
    if (this.groupInviteMetadata(entry)) {
      return entry.pendingRequests;
    }
    const latestConversationId = entry.lastConversationId || entry.pendingRequests[entry.pendingRequests.length - 1]?.envelope.conversationId;
    if (!latestConversationId) {
      return [];
    }
    return entry.pendingRequests.filter(
      (request) => request.envelope.conversationId === latestConversationId
    );
  }
  supersededMessageRequestResult() {
    return {
      accepted: true,
      seq: 0,
      deliveredTo: "rejected",
      queuedAsRequest: false
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
  async deleteMessageRequest(senderUserId, change) {
    const existing = await this.state.get(this.messageRequestKey(senderUserId));
    await this.state.delete(this.messageRequestKey(senderUserId));
    const index = await this.state.get(this.messageRequestIndexKey()) ?? [];
    await this.state.put(
      this.messageRequestIndexKey(),
      index.filter((entry) => entry !== senderUserId)
    );
    if (existing) {
      this.publish({
        event: "message_request_changed",
        deviceId: this.deviceId,
        senderUserId,
        requestId: existing.requestId,
        change
      });
    }
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
    const groupInvite = this.groupInviteMetadata(entry);
    return {
      requestId: entry.requestId,
      recipientDeviceId: entry.recipientDeviceId,
      senderUserId: entry.senderUserId,
      senderBundleShareUrl: entry.senderBundleShareUrl,
      senderBundleHash: entry.senderBundleHash,
      senderDisplayName: entry.senderDisplayName,
      firstSeenAt: entry.firstSeenAt,
      lastSeenAt: entry.lastSeenAt,
      messageCount: entry.messageCount,
      lastMessageId: entry.lastMessageId,
      lastConversationId: entry.lastConversationId,
      requestKind: groupInvite ? "group_invite" : "direct",
      groupId: groupInvite?.groupId,
      groupTitle: groupInvite?.title
    };
  }
  groupInviteMetadata(entry) {
    for (let index = entry.pendingRequests.length - 1; index >= 0; index -= 1) {
      const request = entry.pendingRequests[index];
      if (request.envelope.messageType !== "control_group_welcome_pickup") {
        continue;
      }
      const encoded = request.envelope.inlineCiphertext;
      if (!encoded) {
        return null;
      }
      try {
        const payload = JSON.parse(atob(encoded));
        if (payload.groupId && payload.title) {
          return payload;
        }
      } catch {
        return null;
      }
    }
    return null;
  }
};

// src/inbox/durable.ts
var DurableObjectStorageAdapter2 = class {
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
  async list(options) {
    return this.storage.list(options);
  }
  async setAlarm(epochMillis) {
    await this.storage.setAlarm(epochMillis);
  }
};
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
function versionedBody2(body) {
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
function jsonResponse2(body, status = 200) {
  return new Response(JSON.stringify(versionedBody2(body)), {
    status,
    headers: {
      "content-type": "application/json"
    }
  });
}
var DurableObjectBase2 = globalThis.DurableObject ?? class {
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
      return jsonResponse2({ requests: await service.listMessageRequests() });
    }
    const requestActionMatch = url.pathname.match(/\/message-requests\/([^/]+)\/(accept|reject)$/);
    if (requestActionMatch && request.method === "POST") {
      const requestId = decodeURIComponent(requestActionMatch[1]);
      const action = requestActionMatch[2];
      const result = action === "accept" ? await service.acceptMessageRequest(requestId, now) : await service.rejectMessageRequest(requestId, now);
      return jsonResponse2(result);
    }
    if (url.pathname.endsWith("/allowlist") && request.method === "GET") {
      return jsonResponse2(await service.getAllowlist(now));
    }
    if (url.pathname.endsWith("/allowlist") && request.method === "PUT") {
      const body = await request.json();
      const result = await service.replaceAllowlist(
        body.allowedSenderUserIds ?? [],
        body.rejectedSenderUserIds ?? [],
        now
      );
      return jsonResponse2(result);
    }
    if (url.pathname.endsWith("/messages") && request.method === "POST") {
      const body = await request.json();
      const result = await service.appendEnvelope(body, now);
      return jsonResponse2(result);
    }
    if (url.pathname.endsWith("/messages") && request.method === "GET") {
      const fromSeq = Number(url.searchParams.get("fromSeq") ?? "1");
      const limit = Number(url.searchParams.get("limit") ?? "100");
      const result = await service.fetchMessages({
        deviceId: deps.deviceId,
        fromSeq,
        limit
      });
      return jsonResponse2({
        toSeq: result.toSeq,
        records: result.records
      });
    }
    if (url.pathname.endsWith("/ack") && request.method === "POST") {
      const body = await request.json();
      const result = await service.ack(body);
      return jsonResponse2({
        accepted: result.accepted,
        ackSeq: result.ackSeq
      });
    }
    if (url.pathname.endsWith("/head") && request.method === "GET") {
      const result = await service.getHead();
      return jsonResponse2(result);
    }
    return jsonResponse2({ error: "not_found" }, 404);
  } catch (error) {
    if (error instanceof HttpError) {
      return jsonResponse2({ error: error.code, message: error.message }, error.status);
    }
    const runtimeError = error;
    const message = runtimeError.message ?? "internal error";
    return jsonResponse2({ error: "temporary_unavailable", message }, 500);
  }
}
var InboxDurableObject = class extends DurableObjectBase2 {
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
      state: new DurableObjectStorageAdapter2(this.stateRef.storage),
      spillStore: new R2JsonBlobStore2(this.envRef.TAPCHAT_STORAGE),
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
        const session = new ManagedSession2(server);
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
      new DurableObjectStorageAdapter2(this.stateRef.storage),
      new R2JsonBlobStore2(this.envRef.TAPCHAT_STORAGE),
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
var ManagedSession2 = class {
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
var MAX_BLOB_BYTES = 25 * 1024 * 1024;
var MAX_MIME_TYPE_LENGTH = 255;
var MAX_FILE_NAME_BYTES = 255;
function sanitizeSegment2(value) {
  return value.replace(/[^a-zA-Z0-9:_-]/g, "_");
}
function requireNonEmpty(value, field) {
  if (!value || value.trim().length === 0) {
    throw new HttpError(400, "invalid_input", `${field} is required`);
  }
  return value;
}
function validateMimeType(mimeType) {
  if (mimeType.trim().length === 0 || mimeType.length > MAX_MIME_TYPE_LENGTH || /[\r\n]/.test(mimeType)) {
    throw new HttpError(400, "invalid_input", "mime type is invalid");
  }
}
function validateFileName(fileName) {
  if (fileName === void 0) {
    return;
  }
  if (fileName.trim().length === 0 || fileName.length > MAX_FILE_NAME_BYTES || /[\/\\\0\r\n]/.test(fileName)) {
    throw new HttpError(400, "invalid_input", "file name is invalid");
  }
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
    const taskId = requireNonEmpty(input.taskId, "taskId");
    const conversationId = requireNonEmpty(input.conversationId, "conversationId");
    const messageId = requireNonEmpty(input.messageId, "messageId");
    validateMimeType(input.mimeType);
    validateFileName(input.fileName);
    if (!Number.isSafeInteger(input.sizeBytes) || input.sizeBytes <= 0 || input.sizeBytes > MAX_BLOB_BYTES) {
      throw new HttpError(400, "invalid_input", "sizeBytes is outside supported limits");
    }
    const storageScope = input.storageScope ?? (input.groupId ? "group" : "direct");
    if (storageScope !== "direct" && storageScope !== "group") {
      throw new HttpError(400, "invalid_input", "storageScope is invalid");
    }
    if (storageScope === "group" && (!input.groupId || input.groupId.trim().length === 0)) {
      throw new HttpError(400, "invalid_input", "groupId is required for group storage");
    }
    const blobKey = [
      "blob",
      sanitizeSegment2(owner.userId),
      sanitizeSegment2(owner.deviceId),
      storageScope,
      storageScope === "group" ? sanitizeSegment2(input.groupId) : "direct",
      sanitizeSegment2(conversationId),
      `${sanitizeSegment2(messageId)}-${sanitizeSegment2(taskId)}`
    ].join("/");
    const expiresAt = now + 15 * 60 * 1e3;
    const uploadToken = await signSharingPayload(this.secret, {
      action: "upload",
      blobKey,
      sizeBytes: input.sizeBytes,
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
    if (!Number.isSafeInteger(payload.sizeBytes) || body.byteLength !== payload.sizeBytes) {
      throw new HttpError(400, "invalid_input", "upload body size does not match prepared size");
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

// src/welcome-pickup/service.ts
function pickupKey(groupId, deviceId) {
  return `welcome-pickup/${groupId}/${deviceId}.json`;
}
var WelcomePickupService = class {
  store;
  constructor(store) {
    this.store = store;
  }
  async put(request, now) {
    this.validateDescriptor(request.descriptor, now);
    if (!request.welcomeB64?.trim()) {
      throw new HttpError(400, "invalid_input", "welcome_b64 must not be empty");
    }
    await this.store.putJson(pickupKey(request.descriptor.groupId, request.descriptor.deviceId), {
      descriptor: request.descriptor,
      welcomeB64: request.welcomeB64,
      manifest: request.manifest,
      storedAt: now
    });
    return { accepted: true };
  }
  async fetch(descriptor, now) {
    this.validateDescriptor(descriptor, now);
    const stored = await this.store.getJson(pickupKey(descriptor.groupId, descriptor.deviceId));
    if (!stored) {
      throw new HttpError(404, "not_found", "welcome pickup not found");
    }
    if (stored.descriptor.capability !== descriptor.capability) {
      throw new HttpError(403, "invalid_capability", "welcome pickup capability does not match stored descriptor");
    }
    if (stored.descriptor.expiresAt <= now) {
      await this.store.delete(pickupKey(descriptor.groupId, descriptor.deviceId));
      throw new HttpError(403, "capability_expired", "welcome pickup capability is expired");
    }
    return { welcomeB64: stored.welcomeB64, manifest: stored.manifest };
  }
  validateDescriptor(descriptor, now) {
    if (!descriptor.groupId || !descriptor.deviceId || !descriptor.endpoint || !descriptor.capability) {
      throw new HttpError(400, "invalid_input", "welcome pickup descriptor is missing required fields");
    }
    if (descriptor.expiresAt <= now) {
      throw new HttpError(403, "capability_expired", "welcome pickup capability is expired");
    }
  }
};

// src/routes/http.ts
function versionedBody3(body) {
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
function jsonResponse3(body, status = 200) {
  return new Response(JSON.stringify(versionedBody3(body)), {
    status,
    headers: {
      "content-type": "application/json"
    }
  });
}
function forwardRequestWithBody(request, body) {
  return new Request(request.url, {
    method: request.method,
    headers: new Headers(request.headers),
    body
  });
}
var R2JsonBlobStore3 = class {
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
    new R2JsonBlobStore3(env.TAPCHAT_STORAGE),
    baseUrl(request, env),
    sharedStateSecret(env)
  );
  const sharedState = new SharedStateService(new R2JsonBlobStore3(env.TAPCHAT_STORAGE), baseUrl(request, env));
  const welcomePickup = new WelcomePickupService(new R2JsonBlobStore3(env.TAPCHAT_STORAGE));
  const now = Date.now();
  try {
    if (request.method === "GET" && url.pathname === "/v1/deployment-bundle") {
      return jsonResponse3(publicDeploymentBundle(request, env));
    }
    const contactShareMatch = url.pathname.match(/^\/v1\/contact-share\/([^/]+)$/);
    if (contactShareMatch && request.method === "GET") {
      const token = decodeURIComponent(contactShareMatch[1]);
      const payload = await verifySharingPayload(sharedStateSecret(env), token, now);
      if (payload.service !== "contact_share" || !payload.userId || !payload.shareId) {
        throw new HttpError(403, "invalid_capability", "invalid contact share token");
      }
      const bundle = await sharedState.getIdentityBundle(payload.userId);
      if (!bundle || bundle.bundleShareId !== payload.shareId) {
        return jsonResponse3({ error: "not_found", message: "contact share not found" }, 404);
      }
      return jsonResponse3(bundle);
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
      return jsonResponse3(bundle);
    }
    const inboxMatch = url.pathname.match(/^\/v1\/inbox\/([^/]+)\/(messages|ack|head|subscribe|allowlist|message-requests(?:\/[^/]+\/(?:accept|reject))?)$/);
    if (inboxMatch) {
      const deviceId = decodeURIComponent(inboxMatch[1]);
      const operation = inboxMatch[2];
      const objectId = env.INBOX.idFromName(deviceId);
      const stub = env.INBOX.get(objectId);
      if (request.method === "POST" && operation === "messages") {
        const bodyText = await request.text();
        const body = JSON.parse(bodyText);
        validateAppendAuthorization(request, deviceId, body, now);
        return await stub.fetch(forwardRequestWithBody(request, bodyText));
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
    const groupOutboxMatch = url.pathname.match(/^\/v1\/groups\/([^/]+)\/outbox\/(messages|head|seal|subscribe)$/);
    if (groupOutboxMatch) {
      const groupId = decodeURIComponent(groupOutboxMatch[1]);
      const operation = groupOutboxMatch[2];
      const objectId = env.GROUP_OUTBOX.idFromName(groupId);
      const stub = env.GROUP_OUTBOX.get(objectId);
      if (request.method === "POST" && operation === "messages") {
        const bodyText = await request.text();
        const body = JSON.parse(bodyText);
        validateGroupAppendAuthorization(request, groupId, body, now);
        return await stub.fetch(forwardRequestWithBody(request, bodyText));
      } else if (request.method === "POST" && operation === "seal") {
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
      let payload;
      try {
        payload = await verifySharingPayload(
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
      const body = JSON.parse(bodyText);
      validateGroupOperationAuthorization(request, groupId, body.capability, now, "manage_invites");
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
        let payload;
        try {
          payload = await verifySharingPayload(sharedStateSecret(env), token, now);
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
      const body = JSON.parse(bodyText);
      validateGroupOperationAuthorization(request, groupId, body.capability, now, "approve_join");
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
        const body = await request.json();
        validateWelcomePickupAuthorization(request, groupId, deviceId, body.descriptor, now);
        return jsonResponse3(await welcomePickup.put(body, now));
      }
      if (request.method === "GET") {
        const encoded = request.headers.get("X-Tapchat-Welcome-Pickup");
        if (!encoded) {
          throw new HttpError(401, "invalid_capability", "missing X-Tapchat-Welcome-Pickup header");
        }
        let descriptor;
        try {
          descriptor = JSON.parse(encoded);
        } catch {
          throw new HttpError(400, "invalid_capability", "X-Tapchat-Welcome-Pickup is not valid JSON");
        }
        validateWelcomePickupAuthorization(request, groupId, deviceId, descriptor, now);
        return jsonResponse3(await welcomePickup.fetch(descriptor, now));
      }
    }
    const identityBundleMatch = url.pathname.match(/^\/v1\/shared-state\/([^/]+)\/identity-bundle$/);
    if (identityBundleMatch) {
      const userId = decodeURIComponent(identityBundleMatch[1]);
      if (request.method === "GET") {
        const bundle = await sharedState.getIdentityBundle(userId);
        if (!bundle) {
          return jsonResponse3({ error: "not_found", message: "identity bundle not found" }, 404);
        }
        return jsonResponse3(bundle);
      }
      if (request.method === "PUT") {
        await authorizeSharedStateWrite(request, env, userId, "identity_bundle", now);
        const body = await request.json();
        await sharedState.putIdentityBundle(userId, body);
        const saved = await sharedState.getIdentityBundle(userId);
        return jsonResponse3(saved);
      }
    }
    const deviceStatusMatch = url.pathname.match(/^\/v1\/shared-state\/([^/]+)\/device-status$/);
    if (deviceStatusMatch) {
      const userId = decodeURIComponent(deviceStatusMatch[1]);
      if (request.method === "GET") {
        const document = await sharedState.getDeviceStatus(userId);
        if (!document) {
          return jsonResponse3({ error: "not_found", message: "device status not found" }, 404);
        }
        return jsonResponse3(document);
      }
      if (request.method === "PUT") {
        await authorizeSharedStateWrite(request, env, userId, "device_status", now);
        const body = await request.json();
        await sharedState.putDeviceStatus(userId, body);
        const saved = await sharedState.getDeviceStatus(userId);
        return jsonResponse3(saved);
      }
    }
    const deviceListMatch = url.pathname.match(/^\/v1\/shared-state\/([^/]+)\/device-list$/);
    if (deviceListMatch && request.method === "GET") {
      const userId = decodeURIComponent(deviceListMatch[1]);
      const document = await sharedState.getDeviceList(userId);
      if (!document) {
        return jsonResponse3({ error: "not_found", message: "device list not found" }, 404);
      }
      return jsonResponse3(document);
    }
    const keyPackageRefsMatch = url.pathname.match(/^\/v1\/shared-state\/keypackages\/([^/]+)\/([^/]+)$/);
    if (keyPackageRefsMatch) {
      const userId = decodeURIComponent(keyPackageRefsMatch[1]);
      const deviceId = decodeURIComponent(keyPackageRefsMatch[2]);
      if (request.method === "GET") {
        const document = await sharedState.getKeyPackageRefs(userId, deviceId);
        if (!document) {
          return jsonResponse3({ error: "not_found", message: "keypackage refs not found" }, 404);
        }
        return jsonResponse3(document);
      }
      if (request.method === "PUT") {
        await validateKeyPackageWriteAuthorization(request, sharedStateSecret(env), userId, deviceId, void 0, now);
        const body = await request.json();
        await sharedState.putKeyPackageRefs(userId, deviceId, body);
        const saved = await sharedState.getKeyPackageRefs(userId, deviceId);
        return jsonResponse3(saved);
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
          return jsonResponse3({ error: "not_found", message: "keypackage not found" }, 404);
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
      return jsonResponse3(result);
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
    return jsonResponse3({ error: "not_found", message: "route not found" }, 404);
  } catch (error) {
    if (error instanceof HttpError) {
      return jsonResponse3({ error: error.code, message: error.message }, error.status);
    }
    const runtimeError = error;
    const message = runtimeError.message ?? "internal error";
    return jsonResponse3({ error: "temporary_unavailable", message }, 500);
  }
}

// src/index.ts
var index_default = {
  async fetch(request, env) {
    return handleRequest(request, env);
  }
};
export {
  GroupOutboxDurableObject,
  InboxDurableObject,
  index_default as default
};

import { ed25519 } from "@noble/curves/ed25519";
import type {
  AppendEnvelopeRequest,
  AppendGroupEnvelopeRequest,
  DeviceBinding,
  DeviceContactProfile,
  DeviceRuntimeScope,
  DeviceRuntimeToken,
  GroupCapability,
  GroupCapabilityOperation,
  GroupManifest,
  GroupMembershipProof,
  GroupMessageType,
  IdentityBundle,
  InboxAppendCapability,
  KeyPackageWriteToken,
  SharedStateWriteToken,
  WelcomePickupDescriptor
} from "../types/contracts";
import { CURRENT_MODEL_VERSION } from "../types/contracts";
import { verifySharingPayload } from "../storage/sharing";
import type { SharedStateService } from "../storage/shared-state";
import type { RotatingSecretSet } from "./runtime-security";

export class HttpError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details?: Record<string, unknown>;

  constructor(status: number, code: string, message: string, details?: Record<string, unknown>) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export function getBearerToken(request: Request): string {
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

export interface AppendAuthContext {
  mode: "verified" | "legacy_unverified";
  reason?: string;
}

export async function validateAppendAuthorization(
  request: Request,
  deviceId: string,
  body: AppendEnvelopeRequest,
  now: number,
  sharedState: SharedStateService
): Promise<AppendAuthContext> {
  if (body.version !== CURRENT_MODEL_VERSION) {
    throw new HttpError(400, "unsupported_version", "append request version is not supported");
  }
  if (body.recipientDeviceId !== deviceId || body.envelope.recipientDeviceId !== deviceId) {
    throw new HttpError(403, "invalid_capability", "recipient device does not match target inbox");
  }

  const authorization = request.headers.get("Authorization")?.trim();
  const capabilityHeader = request.headers.get("X-Tapchat-Capability");
  if (!authorization || !capabilityHeader) {
    return { mode: "legacy_unverified", reason: "missing_append_grant" };
  }
  if (!authorization.startsWith("Bearer ")) {
    return { mode: "legacy_unverified", reason: "invalid_bearer" };
  }
  const signature = authorization.slice("Bearer ".length).trim();
  if (!signature) {
    return { mode: "legacy_unverified", reason: "invalid_bearer" };
  }

  let capability: InboxAppendCapability;
  try {
    capability = JSON.parse(capabilityHeader) as InboxAppendCapability;
  } catch {
    throw new HttpError(400, "invalid_capability", "X-Tapchat-Capability is not valid JSON");
  }

  if (capability.version !== CURRENT_MODEL_VERSION) {
    throw new HttpError(400, "unsupported_version", "append capability version is not supported");
  }
  if (capability.signature !== signature) {
    return { mode: "legacy_unverified", reason: "bearer_mismatch" };
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
    return { mode: "legacy_unverified", reason: "capability_expired" };
  }
  if (capability.conversationScope?.length && !capability.conversationScope.includes(body.envelope.conversationId)) {
    throw new HttpError(403, "invalid_capability", "conversation is outside capability scope");
  }
  const size = new TextEncoder().encode(JSON.stringify(body.envelope)).byteLength;
  if (capability.constraints?.maxBytes !== undefined && size > capability.constraints.maxBytes) {
    throw new HttpError(413, "payload_too_large", "envelope exceeds capability size limit");
  }
  const bundle = await sharedState.getIdentityBundle(capability.userId);
  if (!bundle) {
    return { mode: "legacy_unverified", reason: "identity_bundle_missing" };
  }
  if (!verifyIdentityBundle(bundle)) {
    return { mode: "legacy_unverified", reason: "identity_bundle_invalid" };
  }
  if (bundle.userId !== capability.userId) {
    return { mode: "legacy_unverified", reason: "identity_bundle_scope_mismatch" };
  }
  const device = bundle.devices.find((item) => item.deviceId === capability.targetDeviceId);
  if (!device) {
    return { mode: "legacy_unverified", reason: "device_missing" };
  }
  if (device.status !== "active") {
    return { mode: "legacy_unverified", reason: "device_not_active" };
  }
  if (
    device.deviceId !== capability.targetDeviceId ||
    device.binding.userId !== bundle.userId ||
    device.binding.deviceId !== device.deviceId ||
    device.binding.devicePublicKey !== device.devicePublicKey ||
    device.inboxAppendCapability.signature !== capability.signature
  ) {
    return { mode: "legacy_unverified", reason: "device_binding_mismatch" };
  }
  if (!verifyDeviceBinding(bundle.userPublicKey, device.binding)) {
    return { mode: "legacy_unverified", reason: "device_binding_invalid" };
  }
  if (!verifyInboxAppendCapability(capability, device.devicePublicKey)) {
    return { mode: "legacy_unverified", reason: "capability_signature_invalid" };
  }
  return { mode: "verified" };
}

export const APPEND_AUTH_CONTEXT_HEADER = "X-Tapchat-Append-Auth";
export const APPEND_AUTH_REASON_HEADER = "X-Tapchat-Append-Auth-Reason";

function capabilityPayload(capability: InboxAppendCapability): string {
  const constraints = capability.constraints
    ? `${capability.constraints.maxBytes ?? ""}:${capability.constraints.maxOpsPerMinute ?? ""}`
    : "";
  return [
    capability.version,
    rustCapabilityServiceDebug(capability.service),
    capability.userId,
    capability.targetDeviceId,
    capability.endpoint,
    rustCapabilityOperationsDebug(capability.operations),
    (capability.conversationScope ?? []).join(","),
    String(capability.expiresAt),
    constraints
  ].join("|");
}

function rustCapabilityServiceDebug(service: InboxAppendCapability["service"]): string {
  return service === "inbox" ? "Inbox" : service;
}

function rustCapabilityOperationsDebug(operations: string[]): string {
  return `[${operations.map((operation) => (operation === "append" ? "Append" : operation)).join(", ")}]`;
}

function bindingPayload(binding: DeviceBinding): string {
  return `${CURRENT_MODEL_VERSION}:${binding.userId}:${binding.deviceId}:${binding.devicePublicKey}:${binding.createdAt}`;
}

function identityBundlePayload(bundle: IdentityBundle, includeDisplayName: boolean): string {
  const parts = [bundle.version, bundle.userId, bundle.userPublicKey];
  if (includeDisplayName) {
    parts.push(bundle.displayName ?? "");
  }
  parts.push(
    String(bundle.updatedAt),
    bundle.bundleShareId ?? "",
    bundle.identityBundleRef ?? "",
    bundle.deviceStatusRef ?? "",
    bundle.storageProfile?.baseUrl ?? "",
    bundle.storageProfile?.profileRef ?? ""
  );
  for (const device of bundle.devices) {
    parts.push(device.deviceId);
    parts.push(device.devicePublicKey);
    parts.push(device.binding.signature);
    parts.push(device.inboxAppendCapability.signature);
    parts.push(keyPackageRefValue(device));
    parts.push(String(device.keypackageRef.expiresAt));
  }
  return parts.join("|");
}

function keyPackageRefValue(device: DeviceContactProfile): string {
  const keypackage = device.keypackageRef as DeviceContactProfile["keypackageRef"] & { objectRef?: string };
  return keypackage.ref ?? keypackage.objectRef ?? "";
}

export function verifyIdentityBundle(bundle: IdentityBundle): boolean {
  if (bundle.version !== CURRENT_MODEL_VERSION) {
    return false;
  }
  return (
    verifyEd25519(bundle.userPublicKey, bundle.signature, identityBundlePayload(bundle, true)) ||
    verifyEd25519(bundle.userPublicKey, bundle.signature, identityBundlePayload(bundle, false))
  );
}

export function verifyDeviceBinding(userPublicKey: string, binding: DeviceBinding): boolean {
  if (binding.version !== CURRENT_MODEL_VERSION) {
    return false;
  }
  return verifyEd25519(userPublicKey, binding.signature, bindingPayload(binding));
}

function verifyInboxAppendCapability(capability: InboxAppendCapability, devicePublicKey: string): boolean {
  return verifyEd25519(devicePublicKey, capability.signature, capabilityPayload(capability));
}

export function verifyEd25519(publicKeyHex: string, signatureHex: string, payload: string | Uint8Array): boolean {
  try {
    const encoded = typeof payload === "string" ? new TextEncoder().encode(payload) : payload;
    return ed25519.verify(hexToBytes(signatureHex), encoded, hexToBytes(publicKeyHex));
  } catch {
    return false;
  }
}

export function groupCapabilitySigningPayload(capability: GroupCapability): string {
  const operations = Array.from(new Set(capability.operations)).sort().join(",");
  return [
    "tapchat.group_capability.v2",
    `version=${capability.version}`,
    `service=${capability.service}`,
    `group_id=${capability.groupId}`,
    `user_id=${capability.userId}`,
    `device_id=${capability.deviceId}`,
    `role=${capability.role}`,
    `operations=${operations}`,
    `expires_at=${capability.expiresAt}`
  ].join("\n");
}

function unsignedGroupManifest(manifest: GroupManifest): Record<string, unknown> {
  return {
    version: manifest.version,
    groupId: manifest.groupId,
    conversationId: manifest.conversationId,
    title: manifest.title,
    ownerUserId: manifest.ownerUserId,
    admins: manifest.admins,
    members: manifest.members.map((member) => ({
      userId: member.userId,
      role: member.role,
      status: member.status
    })),
    ...(manifest.memberDevices?.length
      ? {
          memberDevices: manifest.memberDevices.map((device) => ({
            userId: device.userId,
            deviceId: device.deviceId,
            status: device.status
          }))
        }
      : {}),
    joinPolicy: manifest.joinPolicy,
    memberInvitePolicy: manifest.memberInvitePolicy,
    rosterVersion: manifest.rosterVersion,
    mlsEpochHint: manifest.mlsEpochHint,
    ...(manifest.lastCommitMessageId ? { lastCommitMessageId: manifest.lastCommitMessageId } : {}),
    outbox: {
      endpoint: manifest.outbox.endpoint,
      ...(manifest.outbox.subscribeEndpoint
        ? { subscribeEndpoint: manifest.outbox.subscribeEndpoint }
        : {})
    },
    updatedAt: manifest.updatedAt,
    signerUserId: manifest.signerUserId,
    signerDeviceId: manifest.signerDeviceId,
    signature: ""
  };
}

export function groupManifestSigningPayload(manifest: GroupManifest): Uint8Array {
  const prefix = new TextEncoder().encode("tapchat.group_manifest.v1\n");
  const body = new TextEncoder().encode(JSON.stringify(unsignedGroupManifest(manifest)));
  const payload = new Uint8Array(prefix.length + body.length);
  payload.set(prefix);
  payload.set(body, prefix.length);
  return payload;
}

export function groupMembershipProofSigningPayload(proof: GroupMembershipProof): string {
  const fields = [
    "tapchat.group.membership.v1",
    `proof_type=${proof.type}`,
    `operation=${proof.operation}`,
    `signer_user_id=${proof.signerUserId}`,
    `signer_device_id=${proof.signerDeviceId}`,
    `previous_roster_version=${proof.previousRosterVersion}`,
    `new_roster_version=${proof.newRosterVersion}`,
    `previous_commit_message_id=${proof.previousCommitMessageId ?? ""}`,
    `commit_message_id=${proof.commitMessageId}`,
    `control_message_id=${proof.controlMessageId}`,
    `new_manifest_sha256=${proof.newManifestSha256}`
  ];
  if (proof.stateEventMessageId) {
    fields.push(`state_event_message_id=${proof.stateEventMessageId}`);
  }
  return fields.join("\n");
}

export async function groupManifestSha256(manifest: GroupManifest): Promise<string> {
  const body = new TextEncoder().encode(JSON.stringify(unsignedGroupManifest(manifest)));
  const digest = await crypto.subtle.digest("SHA-256", body);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(input: string): Uint8Array {
  const value = input.trim();
  if (value.length % 2 !== 0) {
    throw new Error("hex input must have even length");
  }
  if (!/^[0-9a-fA-F]*$/.test(value)) {
    throw new Error("invalid hex input");
  }
  const output = new Uint8Array(value.length / 2);
  for (let index = 0; index < value.length; index += 2) {
    const byte = Number.parseInt(value.slice(index, index + 2), 16);
    if (!Number.isFinite(byte)) {
      throw new Error("invalid hex input");
    }
    output[index / 2] = byte;
  }
  return output;
}

export function readGroupCapabilityHeader(request: Request): GroupCapability {
  const capabilityHeader = request.headers.get("X-Tapchat-Group-Capability");
  if (!capabilityHeader) {
    throw new HttpError(401, "invalid_capability", "missing X-Tapchat-Group-Capability header");
  }
  try {
    return JSON.parse(capabilityHeader) as GroupCapability;
  } catch {
    throw new HttpError(400, "invalid_capability", "X-Tapchat-Group-Capability is not valid JSON");
  }
}

export function validateGroupReadAuthorization(
  request: Request,
  groupId: string,
  capability: GroupCapability,
  now: number
): void {
  if (!capability) {
    throw new HttpError(401, "invalid_capability", "missing group capability");
  }
  validateGroupCapabilityBase(request, groupId, capability, now);
  if (!capability.operations.includes("read")) {
    throw new HttpError(403, "invalid_capability", "group capability does not grant read");
  }
}

export function validateGroupOperationAuthorization(
  request: Request,
  groupId: string,
  capability: GroupCapability,
  now: number,
  operation: GroupCapabilityOperation,
  allowedRoles: Array<GroupCapability["role"]> = ["owner", "admin"]
): void {
  validateGroupCapabilityBase(request, groupId, capability, now);
  if (!capability.operations.includes(operation)) {
    throw new HttpError(403, "invalid_capability", `group capability does not grant ${operation}`);
  }
  if (!allowedRoles.includes(capability.role)) {
    throw new HttpError(403, "invalid_capability", `group role cannot use ${operation}`);
  }
}

export function validateGroupAppendAuthorization(
  request: Request,
  groupId: string,
  body: AppendGroupEnvelopeRequest,
  now: number
): void {
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

export function validateWelcomePickupAuthorization(
  request: Request,
  groupId: string,
  deviceId: string,
  descriptor: WelcomePickupDescriptor,
  now: number
): void {
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

function validateGroupCapabilityBase(
  request: Request,
  groupId: string,
  capability: GroupCapability,
  now: number
): void {
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

export function requiredGroupAppendOperations(messageType: GroupMessageType): GroupCapabilityOperation[] {
  switch (messageType) {
    case "mls_application":
      return ["append_application"];
    case "mls_commit":
    case "control_group_membership_changed":
    case "control_group_state_event":
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

export function allowedGroupAppendRoles(messageType: GroupMessageType): Array<GroupCapability["role"]> {
  switch (messageType) {
    case "mls_commit":
    case "control_group_membership_changed":
    case "control_group_state_event":
    case "control_group_metadata_updated":
    case "control_group_join_approved":
    case "control_group_join_rejected":
      return ["owner", "admin"];
    default:
      return ["owner", "admin", "member"];
  }
}

function tokenKeyId(token: string): string | undefined {
  try {
    const payloadPart = token.split(".")[0];
    if (!payloadPart) return undefined;
    const normalized = payloadPart.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
    const payload = JSON.parse(atob(padded)) as { keyId?: unknown };
    return typeof payload.keyId === "string" && payload.keyId.trim() ? payload.keyId : undefined;
  } catch {
    return undefined;
  }
}

async function verifySignedToken<T>(secrets: string | RotatingSecretSet, request: Request, now: number): Promise<T> {
  const token = getBearerToken(request);
  const candidates = typeof secrets === "string"
    ? [secrets]
    : (() => {
        const keyId = tokenKeyId(token);
        if (keyId) {
          if (keyId === secrets.current.keyId) return [secrets.current.secret];
          if (
            secrets.previous?.keyId === keyId &&
            secrets.graceUntilMs !== undefined &&
            now < secrets.graceUntilMs
          ) return [secrets.previous.secret];
          return [];
        }
        return secrets.allowUnkeyedCurrent ? [secrets.current.secret] : [];
      })();
  let lastMessage = "invalid signed token";
  for (const secret of candidates) {
    try {
      return await verifySharingPayload<T>(secret, token, now);
    } catch (error) {
      lastMessage = error instanceof Error ? error.message : lastMessage;
    }
  }
  if (lastMessage.includes("expired")) {
    throw new HttpError(403, "capability_expired", lastMessage);
  }
  throw new HttpError(403, "invalid_capability", lastMessage);
}

async function verifyDeviceRuntimeToken(request: Request, secrets: string | RotatingSecretSet, now: number): Promise<DeviceRuntimeToken> {
  let token: DeviceRuntimeToken;
  try {
    token = await verifySignedToken<DeviceRuntimeToken>(secrets, request, now);
  } catch (error) {
    if (error instanceof HttpError && error.code === "capability_expired") {
      throw new HttpError(403, "runtime_auth_expired", "device runtime token is expired");
    }
    throw new HttpError(403, "runtime_auth_invalid", "device runtime token is invalid");
  }
  if (token.version !== CURRENT_MODEL_VERSION) {
    throw new HttpError(400, "unsupported_version", "device runtime token version is not supported");
  }
  if (token.service !== "device_runtime") {
    throw new HttpError(403, "runtime_auth_invalid", "token service must be device_runtime");
  }
  if (
    !token.runtimeId ||
    !token.userId ||
    !token.deviceId ||
    !token.scopes.length ||
    !Number.isSafeInteger(token.issuedAt) ||
    !Number.isSafeInteger(token.registrationVersion) ||
    token.registrationVersion < 1
  ) {
    throw new HttpError(403, "runtime_auth_invalid", "device runtime token is malformed");
  }
  return token;
}

export async function validateAnyDeviceRuntimeAuthorization(
  request: Request,
  secret: string | RotatingSecretSet,
  scope: DeviceRuntimeScope,
  now: number
): Promise<DeviceRuntimeToken> {
  const token = await verifyDeviceRuntimeToken(request, secret, now);
  if (!token.scopes.includes(scope)) {
    throw new HttpError(403, "runtime_auth_invalid", `device runtime token does not grant ${scope}`);
  }
  return token;
}

export async function validateDeviceRuntimeAuthorization(
  request: Request,
  secret: string | RotatingSecretSet,
  userId: string,
  deviceId: string,
  scope: DeviceRuntimeScope,
  now: number
): Promise<DeviceRuntimeToken> {
  const token = await validateAnyDeviceRuntimeAuthorization(request, secret, scope, now);
  if (token.userId !== userId || token.deviceId !== deviceId) {
    throw new HttpError(403, "runtime_auth_invalid", "device runtime token scope does not match request path");
  }
  return token;
}

export async function validateDeviceRuntimeAuthorizationForDevice(
  request: Request,
  secret: string | RotatingSecretSet,
  deviceId: string,
  scope: DeviceRuntimeScope,
  now: number
): Promise<DeviceRuntimeToken> {
  const token = await validateAnyDeviceRuntimeAuthorization(request, secret, scope, now);
  if (token.deviceId !== deviceId) {
    throw new HttpError(403, "runtime_auth_invalid", "device runtime token scope does not match request path");
  }
  return token;
}

export async function validateSharedStateWriteAuthorization(
  request: Request,
  secret: string,
  userId: string,
  deviceId: string,
  objectKind: "identity_bundle" | "device_status",
  now: number
): Promise<SharedStateWriteToken | DeviceRuntimeToken> {
  try {
    return await validateDeviceRuntimeAuthorization(request, secret, userId, deviceId, "shared_state_write", now);
  } catch (error) {
    if (!(error instanceof HttpError) || error.code === "runtime_auth_expired") {
      throw error;
    }
  }

  const token = await verifySignedToken<SharedStateWriteToken>(secret, request, now);
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

export async function validateKeyPackageWriteAuthorization(
  request: Request,
  secret: string | RotatingSecretSet,
  userId: string,
  deviceId: string,
  keyPackageId: string | undefined,
  now: number,
  legacySecret?: string
): Promise<KeyPackageWriteToken | DeviceRuntimeToken> {
  try {
    return await validateDeviceRuntimeAuthorization(request, secret, userId, deviceId, "keypackage_write", now);
  } catch (error) {
    if (!(error instanceof HttpError) || error.code === "runtime_auth_expired") {
      throw error;
    }
  }

  const token = await verifySignedToken<KeyPackageWriteToken>(legacySecret ?? secret, request, now);
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

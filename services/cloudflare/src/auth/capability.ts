import type {
  AppendEnvelopeRequest,
  AppendGroupEnvelopeRequest,
  BootstrapToken,
  DeviceRuntimeScope,
  DeviceRuntimeToken,
  GroupCapability,
  GroupCapabilityOperation,
  GroupMessageType,
  InboxAppendCapability,
  KeyPackageWriteToken,
  SharedStateWriteToken
} from "../types/contracts";
import { CURRENT_MODEL_VERSION } from "../types/contracts";
import { verifySharingPayload } from "../storage/sharing";

export class HttpError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
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

export function validateAppendAuthorization(
  request: Request,
  deviceId: string,
  body: AppendEnvelopeRequest,
  now: number
): void {
  const signature = getBearerToken(request);
  const capabilityHeader = request.headers.get("X-Tapchat-Capability");
  if (!capabilityHeader) {
    throw new HttpError(401, "invalid_capability", "missing X-Tapchat-Capability header");
  }

  let capability: InboxAppendCapability;
  try {
    capability = JSON.parse(capabilityHeader) as InboxAppendCapability;
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
  if (capability.constraints?.maxBytes !== undefined && size > capability.constraints.maxBytes) {
    throw new HttpError(413, "payload_too_large", "envelope exceeds capability size limit");
  }
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
  validateGroupCapabilityBase(request, groupId, capability, now);
  if (!capability.operations.includes("read")) {
    throw new HttpError(403, "invalid_capability", "group capability does not grant read");
  }
}

export function validateGroupAppendAuthorization(
  request: Request,
  groupId: string,
  body: AppendGroupEnvelopeRequest,
  now: number
): void {
  const capability = body.capability;
  validateGroupCapabilityBase(request, groupId, capability, now);
  if (body.groupId !== groupId || body.envelope.groupId !== groupId) {
    throw new HttpError(403, "invalid_capability", "group capability scope does not match request group");
  }

  const required = requiredGroupAppendOperation(body.envelope.messageType);
  if (!capability.operations.includes(required)) {
    throw new HttpError(403, "invalid_capability", `group capability does not grant ${required}`);
  }
  if (required === "append_membership" && capability.role === "member") {
    throw new HttpError(403, "invalid_capability", "member role cannot append membership control messages");
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

function requiredGroupAppendOperation(messageType: GroupMessageType): GroupCapabilityOperation {
  if (messageType === "mls_application") {
    return "append_application";
  }
  if (isMembershipControlMessage(messageType)) {
    return "append_membership";
  }
  return "append_control";
}

function isMembershipControlMessage(messageType: GroupMessageType): boolean {
  return (
    messageType === "control_group_membership_changed" ||
    messageType === "control_group_join_requested" ||
    messageType === "control_group_join_approved" ||
    messageType === "control_group_join_rejected" ||
    messageType === "control_group_leave_requested"
  );
}

async function verifySignedToken<T>(secret: string, request: Request, now: number): Promise<T> {
  const token = getBearerToken(request);
  try {
    return await verifySharingPayload<T>(secret, token, now);
  } catch (error) {
    const message = error instanceof Error ? error.message : "invalid signed token";
    if (message.includes("expired")) {
      throw new HttpError(403, "capability_expired", message);
    }
    throw new HttpError(403, "invalid_capability", message);
  }
}

async function verifyDeviceRuntimeToken(request: Request, secret: string, now: number): Promise<DeviceRuntimeToken> {
  const token = await verifySignedToken<DeviceRuntimeToken>(secret, request, now);
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

export async function validateBootstrapAuthorization(
  request: Request,
  secret: string,
  userId: string,
  deviceId: string,
  now: number
): Promise<BootstrapToken> {
  const token = await verifySignedToken<BootstrapToken>(secret, request, now);
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

export async function validateAnyDeviceRuntimeAuthorization(
  request: Request,
  secret: string,
  scope: DeviceRuntimeScope,
  now: number
): Promise<DeviceRuntimeToken> {
  const token = await verifyDeviceRuntimeToken(request, secret, now);
  if (!token.scopes.includes(scope)) {
    throw new HttpError(403, "invalid_capability", `device runtime token does not grant ${scope}`);
  }
  return token;
}

export async function validateDeviceRuntimeAuthorization(
  request: Request,
  secret: string,
  userId: string,
  deviceId: string,
  scope: DeviceRuntimeScope,
  now: number
): Promise<DeviceRuntimeToken> {
  const token = await validateAnyDeviceRuntimeAuthorization(request, secret, scope, now);
  if (token.userId !== userId || token.deviceId !== deviceId) {
    throw new HttpError(403, "invalid_capability", "device runtime token scope does not match request path");
  }
  return token;
}

export async function validateDeviceRuntimeAuthorizationForDevice(
  request: Request,
  secret: string,
  deviceId: string,
  scope: DeviceRuntimeScope,
  now: number
): Promise<DeviceRuntimeToken> {
  const token = await validateAnyDeviceRuntimeAuthorization(request, secret, scope, now);
  if (token.deviceId !== deviceId) {
    throw new HttpError(403, "invalid_capability", "device runtime token scope does not match request path");
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
    if (!(error instanceof HttpError) || error.code === "capability_expired") {
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
  secret: string,
  userId: string,
  deviceId: string,
  keyPackageId: string | undefined,
  now: number
): Promise<KeyPackageWriteToken | DeviceRuntimeToken> {
  try {
    return await validateDeviceRuntimeAuthorization(request, secret, userId, deviceId, "keypackage_write", now);
  } catch (error) {
    if (!(error instanceof HttpError) || error.code === "capability_expired") {
      throw error;
    }
  }

  const token = await verifySignedToken<KeyPackageWriteToken>(secret, request, now);
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

import {
  groupCapabilitySigningPayload,
  groupManifestSha256,
  groupManifestSigningPayload,
  groupMembershipProofSigningPayload,
  HttpError,
  verifyDeviceBinding,
  verifyEd25519,
  verifyIdentityBundle
} from "../auth/capability";
import { CURRENT_MODEL_VERSION } from "../types/contracts";
import type {
  DeviceRuntimeToken,
  GroupAuthorizationUpdate,
  GroupCapability,
  GroupCapabilityOperation,
  GroupManifest,
  GroupMember,
  GroupMembershipProof,
  GroupTransitionOperation,
  GroupRole,
  IdentityBundle,
  InitializeGroupAuthorizationRequest,
  InitializeGroupAuthorizationResult,
  GetGroupAuthorizationStateResult
} from "../types/contracts";
import type { DurableObjectStorageLike } from "../types/runtime";

export const GROUP_AUTHORIZATION_KEY = "group-authorization:v2";
const MAX_CAPABILITY_TTL_MS = 24 * 60 * 60 * 1000 + 5 * 60 * 1000;

export interface AuthorizedGroupDevice {
  userId: string;
  deviceId: string;
  publicKey: string;
  status: "active" | "revoked";
}

export interface GroupAuthorizationState {
  version: "2";
  manifest: GroupManifest;
  devices: Record<string, AuthorizedGroupDevice>;
  initializedAt: number;
  updatedAt: number;
  lastTransitionProof?: GroupMembershipProof;
  lastTransitionId?: string;
  phase: "provisioning" | "active";
}

const ROLE_OPERATIONS: Record<GroupRole, ReadonlySet<GroupCapabilityOperation>> = {
  owner: new Set([
    "read",
    "subscribe",
    "append_application",
    "append_control",
    "append_membership",
    "manage_invites",
    "approve_join",
    "remove_member",
    "update_group_metadata",
    "seal_group"
  ]),
  admin: new Set([
    "read",
    "subscribe",
    "append_application",
    "append_control",
    "append_membership",
    "manage_invites",
    "approve_join",
    "remove_member",
    "update_group_metadata"
  ]),
  member: new Set(["read", "subscribe", "append_application", "append_control"])
};

function deviceKey(userId: string, deviceId: string): string {
  return `${userId}\u0000${deviceId}`;
}

function activeMember(manifest: GroupManifest, userId: string): GroupMember | undefined {
  return manifest.members.find((member) => member.userId === userId && member.status === "active");
}

function canonicalJson(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(canonicalJson);
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, item]) => [key, canonicalJson(item)])
    );
  }
  return value;
}

function sameJson(left: unknown, right: unknown): boolean {
  return JSON.stringify(canonicalJson(left)) === JSON.stringify(canonicalJson(right));
}

function validateManifestShape(manifest: GroupManifest, groupId: string): void {
  if (manifest.version !== CURRENT_MODEL_VERSION) {
    throw new HttpError(400, "unsupported_version", "group manifest version is not supported");
  }
  if (manifest.groupId !== groupId || !manifest.conversationId || !manifest.signature) {
    throw new HttpError(400, "group_transition_invalid", "group manifest scope or signature is invalid");
  }
  if (!Number.isSafeInteger(manifest.rosterVersion) || manifest.rosterVersion < 0) {
    throw new HttpError(400, "group_transition_invalid", "group manifest rosterVersion is invalid");
  }
  const activeOwners = manifest.members.filter(
    (member) => member.status === "active" && member.role === "owner"
  );
  if (activeOwners.length !== 1 || activeOwners[0].userId !== manifest.ownerUserId) {
    throw new HttpError(409, "group_transition_invalid", "group manifest must contain exactly one active owner");
  }
  const memberIds = new Set<string>();
  for (const member of manifest.members) {
    if (!member.userId || memberIds.has(member.userId)) {
      throw new HttpError(409, "group_transition_invalid", "group manifest contains duplicate or empty members");
    }
    memberIds.add(member.userId);
  }
  const activeAdminIds = manifest.members
    .filter((member) => member.status === "active" && member.role === "admin")
    .map((member) => member.userId)
    .sort();
  if (!sameJson(Array.from(new Set(manifest.admins)).sort(), activeAdminIds)) {
    throw new HttpError(409, "group_transition_invalid", "group manifest admin index does not match active member roles");
  }
  if (manifest.rosterVersion === 0) {
    const ownerOnly = manifest.members.length === 1 &&
      manifest.members[0].userId === manifest.ownerUserId &&
      manifest.members[0].role === "owner" &&
      manifest.members[0].status === "active";
    if (!ownerOnly || manifest.admins.length !== 0 || manifest.mlsEpochHint !== 0 || manifest.lastCommitMessageId) {
      throw new HttpError(409, "group_transition_invalid", "provisional group manifest must be owner-only at roster 0 and MLS epoch 0");
    }
  }
  const memberDeviceIds = new Set<string>();
  for (const device of manifest.memberDevices ?? []) {
    if (!memberIds.has(device.userId) || !device.deviceId || memberDeviceIds.has(device.deviceId)) {
      throw new HttpError(409, "group_transition_invalid", "group manifest contains an invalid member device");
    }
    memberDeviceIds.add(device.deviceId);
  }
  let endpoint: URL;
  try {
    endpoint = new URL(manifest.outbox.endpoint);
  } catch {
    throw new HttpError(409, "group_transition_invalid", "group outbox endpoint is invalid");
  }
  const match = endpoint.pathname.match(/^\/v1\/groups\/([^/]+)\/outbox\/messages$/);
  if (!match || decodeURIComponent(match[1]) !== groupId) {
    throw new HttpError(409, "group_transition_invalid", "group outbox endpoint does not match groupId");
  }
}

function mergeVerifiedDevices(
  existing: Record<string, AuthorizedGroupDevice>,
  bundles: IdentityBundle[]
): Record<string, AuthorizedGroupDevice> {
  const devices = { ...existing };
  for (const bundle of bundles) {
    if (!verifyIdentityBundle(bundle)) {
      throw new HttpError(403, "invalid_capability", `identity bundle is invalid for ${bundle.userId}`);
    }
    for (const device of bundle.devices) {
      if (
        device.binding.userId !== bundle.userId ||
        device.binding.deviceId !== device.deviceId ||
        device.binding.devicePublicKey !== device.devicePublicKey ||
        !verifyDeviceBinding(bundle.userPublicKey, device.binding)
      ) {
        throw new HttpError(403, "invalid_capability", `device binding is invalid for ${device.deviceId}`);
      }
      devices[deviceKey(bundle.userId, device.deviceId)] = {
        userId: bundle.userId,
        deviceId: device.deviceId,
        publicKey: device.devicePublicKey,
        status: device.status
      };
    }
  }
  return devices;
}

function validateManifestDevices(
  manifest: GroupManifest,
  devices: Record<string, AuthorizedGroupDevice>
): void {
  for (const memberDevice of manifest.memberDevices ?? []) {
    if (memberDevice.status !== "active") {
      continue;
    }
    const device = devices[deviceKey(memberDevice.userId, memberDevice.deviceId)];
    if (!device || device.status !== "active" || device.userId !== memberDevice.userId) {
      throw new HttpError(
        409,
        "group_transition_invalid",
        `active manifest device has no verified identity binding: ${memberDevice.deviceId}`
      );
    }
  }
}

function verifyManifestSignature(
  manifest: GroupManifest,
  devices: Record<string, AuthorizedGroupDevice>
): void {
  const signer = devices[deviceKey(manifest.signerUserId, manifest.signerDeviceId)];
  const signerMember = activeMember(manifest, manifest.signerUserId);
  const signerDevice = (manifest.memberDevices ?? []).find(
    (device) =>
      device.userId === manifest.signerUserId &&
      device.deviceId === manifest.signerDeviceId &&
      device.status === "active"
  );
  if (
    !signer ||
    signer.status !== "active" ||
    !signerDevice ||
    !signerMember ||
    !["owner", "admin"].includes(signerMember.role) ||
    !verifyEd25519(signer.publicKey, manifest.signature, groupManifestSigningPayload(manifest))
  ) {
    throw new HttpError(403, "invalid_capability", "group manifest signature is invalid");
  }
}

function verifyMembershipProof(
  proof: GroupMembershipProof,
  oldState: GroupAuthorizationState,
  nextManifest: GroupManifest
): void {
  const signer = oldState.devices[deviceKey(proof.signerUserId, proof.signerDeviceId)];
  const signerMember = activeMember(oldState.manifest, proof.signerUserId);
  if (
    proof.type !== "membership_signature" ||
    !signer ||
    signer.status !== "active" ||
    !signerMember ||
    !["owner", "admin"].includes(signerMember.role) ||
    !verifyEd25519(signer.publicKey, proof.signature, groupMembershipProofSigningPayload(proof))
  ) {
    throw new HttpError(403, "invalid_capability", "group membership proof signature is invalid");
  }
  if (
    proof.previousRosterVersion !== oldState.manifest.rosterVersion ||
    proof.newRosterVersion !== nextManifest.rosterVersion
  ) {
    throw new HttpError(409, "group_transition_invalid", "group membership proof roster chain is invalid");
  }
  if ((proof.previousCommitMessageId ?? "") !== (oldState.manifest.lastCommitMessageId ?? "")) {
    throw new HttpError(409, "group_transition_invalid", "group membership proof commit chain is invalid");
  }
  if (["create", "transfer_ownership", "set_admin", "dissolve"].includes(proof.operation) && signerMember.role !== "owner") {
    throw new HttpError(403, "invalid_capability", `${proof.operation} requires the current group owner`);
  }
}

function verifyIdempotentMembershipProof(
  proof: GroupMembershipProof,
  current: GroupAuthorizationState,
  manifestHash: string
): void {
  if (current.lastTransitionProof && sameJson(current.lastTransitionProof, proof)) {
    return;
  }
  const signer = current.devices[deviceKey(proof.signerUserId, proof.signerDeviceId)];
  const signerMember = activeMember(current.manifest, proof.signerUserId);
  if (
    proof.type !== "membership_signature" ||
    !signer ||
    signer.status !== "active" ||
    !signerMember ||
    !["owner", "admin"].includes(signerMember.role) ||
    !verifyEd25519(signer.publicKey, proof.signature, groupMembershipProofSigningPayload(proof))
  ) {
    throw new HttpError(403, "invalid_capability", "group membership proof signature is invalid");
  }
  if (proof.newRosterVersion !== current.manifest.rosterVersion || proof.newManifestSha256 !== manifestHash) {
    throw new HttpError(409, "group_transition_invalid", "idempotent group transition does not match current manifest");
  }
  if (["transfer_ownership", "set_admin", "dissolve"].includes(proof.operation) && signerMember.role !== "owner") {
    throw new HttpError(403, "invalid_capability", `${proof.operation} requires the current group owner`);
  }
}

function manifestTransitionMatches(
  oldManifest: GroupManifest,
  nextManifest: GroupManifest,
  applyAllowedChanges: (expected: GroupManifest) => void
): boolean {
  const expected: GroupManifest = JSON.parse(JSON.stringify(oldManifest)) as GroupManifest;
  expected.rosterVersion = nextManifest.rosterVersion;
  expected.mlsEpochHint = nextManifest.mlsEpochHint;
  expected.updatedAt = nextManifest.updatedAt;
  expected.signerUserId = nextManifest.signerUserId;
  expected.signerDeviceId = nextManifest.signerDeviceId;
  expected.signature = nextManifest.signature;
  applyAllowedChanges(expected);
  return sameJson(expected, nextManifest);
}

function membershipAdditionsAreWellFormed(oldManifest: GroupManifest, nextManifest: GroupManifest): boolean {
  if (nextManifest.members.length <= oldManifest.members.length) {
    return false;
  }
  const oldMembers = new Map(oldManifest.members.map((member) => [member.userId, member]));
  let added = 0;
  for (const member of nextManifest.members) {
    const oldMember = oldMembers.get(member.userId);
    if (oldMember) {
      if (!sameJson(oldMember, member)) {
        return false;
      }
    } else if (member.role === "member" && member.status === "active") {
      added += 1;
    } else {
      return false;
    }
  }
  return added > 0;
}

function genesisTransitionIsWellFormed(oldManifest: GroupManifest, nextManifest: GroupManifest): boolean {
  const oldMembers = new Map(oldManifest.members.map((member) => [member.userId, member]));
  for (const member of nextManifest.members) {
    const old = oldMembers.get(member.userId);
    if (old ? !sameJson(old, member) : member.role !== "member" || member.status !== "active") return false;
  }
  if (oldManifest.members.some((member) => !nextManifest.members.some((next) => sameJson(member, next)))) return false;
  const oldDevices = oldManifest.memberDevices ?? [];
  const nextDevices = nextManifest.memberDevices ?? [];
  if (oldDevices.some((device) => !nextDevices.some((next) => sameJson(device, next)))) return false;
  return nextDevices.every((device) =>
    oldDevices.some((old) => sameJson(old, device)) ||
    (device.status === "active" && nextManifest.members.some((member) => member.userId === device.userId && member.status === "active"))
  );
}

function membershipDeviceAdditionsAreWellFormed(
  oldManifest: GroupManifest,
  nextManifest: GroupManifest,
  addedUserIds: ReadonlySet<string>
): boolean {
  const oldDevices = oldManifest.memberDevices ?? [];
  const nextDevices = nextManifest.memberDevices ?? [];
  if (oldDevices.some((device) => !nextDevices.some((next) => sameJson(device, next)))) return false;
  return nextDevices.every((device) =>
    oldDevices.some((old) => sameJson(old, device)) ||
    (addedUserIds.has(device.userId) && device.status === "active")
  );
}

function memberRemovalIsWellFormed(oldManifest: GroupManifest, nextManifest: GroupManifest, nextStatus: "removed" | "left"): boolean {
  if (oldManifest.members.length !== nextManifest.members.length) {
    return false;
  }
  let removals = 0;
  for (const oldMember of oldManifest.members) {
    const nextMember = nextManifest.members.find((member) => member.userId === oldMember.userId);
    if (!nextMember) {
      return false;
    }
    if (sameJson(oldMember, nextMember)) {
      continue;
    }
    if (
      oldMember.role === nextMember.role &&
      oldMember.status === "active" &&
      nextMember.status === nextStatus &&
      oldMember.role !== "owner"
    ) {
      removals += 1;
      continue;
    }
    return false;
  }
  return removals === 1;
}

function deviceAdditionIsWellFormed(oldManifest: GroupManifest, nextManifest: GroupManifest): boolean {
  const oldDevices = oldManifest.memberDevices ?? [];
  const nextDevices = nextManifest.memberDevices ?? [];
  if (!sameJson(oldManifest.members, nextManifest.members) || nextDevices.length !== oldDevices.length + 1) {
    return false;
  }
  let added = 0;
  for (const device of nextDevices) {
    if (oldDevices.some((oldDevice) => sameJson(oldDevice, device))) {
      continue;
    }
    if (
      device.status !== "active" ||
      !oldManifest.members.some((member) => member.userId === device.userId && member.status === "active")
    ) {
      return false;
    }
    added += 1;
  }
  return added === 1;
}

function deviceRemovalIsWellFormed(oldManifest: GroupManifest, nextManifest: GroupManifest): boolean {
  const oldDevices = oldManifest.memberDevices ?? [];
  const nextDevices = nextManifest.memberDevices ?? [];
  if (!sameJson(oldManifest.members, nextManifest.members) || oldDevices.length !== nextDevices.length) {
    return false;
  }
  let removals = 0;
  for (const oldDevice of oldDevices) {
    const nextDevice = nextDevices.find((device) => device.deviceId === oldDevice.deviceId);
    if (!nextDevice) {
      return false;
    }
    if (sameJson(oldDevice, nextDevice)) {
      continue;
    }
    if (
      oldDevice.userId === nextDevice.userId &&
      oldDevice.status === "active" &&
      nextDevice.status === "removed" &&
      oldDevice.userId !== oldManifest.ownerUserId
    ) {
      removals += 1;
      continue;
    }
    return false;
  }
  return removals === 1;
}

function memberDevicesForRemovalAreWellFormed(
  oldManifest: GroupManifest,
  nextManifest: GroupManifest,
  userId: string
): boolean {
  const oldDevices = oldManifest.memberDevices ?? [];
  const nextDevices = nextManifest.memberDevices ?? [];
  if (oldDevices.length !== nextDevices.length) return false;
  for (const oldDevice of oldDevices) {
    const nextDevice = nextDevices.find((device) =>
      device.userId === oldDevice.userId && device.deviceId === oldDevice.deviceId
    );
    if (!nextDevice) return false;
    if (oldDevice.userId !== userId) {
      if (!sameJson(oldDevice, nextDevice)) return false;
    } else if (oldDevice.status === "active" && nextDevice.status !== "removed") {
      return false;
    }
  }
  return true;
}

function adminUpdateIsWellFormed(oldManifest: GroupManifest, nextManifest: GroupManifest): boolean {
  if (oldManifest.members.length !== nextManifest.members.length) {
    return false;
  }
  let roleChanges = 0;
  for (const oldMember of oldManifest.members) {
    const nextMember = nextManifest.members.find((member) => member.userId === oldMember.userId);
    if (!nextMember) {
      return false;
    }
    if (sameJson(oldMember, nextMember)) {
      continue;
    }
    if (
      oldMember.status === "active" &&
      nextMember.status === "active" &&
      oldMember.role !== "owner" &&
      ((oldMember.role === "member" && nextMember.role === "admin") ||
        (oldMember.role === "admin" && nextMember.role === "member"))
    ) {
      roleChanges += 1;
      continue;
    }
    return false;
  }
  return roleChanges === 1;
}

function ownershipTransferIsWellFormed(oldManifest: GroupManifest, nextManifest: GroupManifest): boolean {
  if (oldManifest.ownerUserId === nextManifest.ownerUserId || oldManifest.members.length !== nextManifest.members.length) {
    return false;
  }
  let oldOwnerChanged = false;
  let newOwnerChanged = false;
  for (const oldMember of oldManifest.members) {
    const nextMember = nextManifest.members.find((member) => member.userId === oldMember.userId);
    if (!nextMember) {
      return false;
    }
    if (sameJson(oldMember, nextMember)) {
      continue;
    }
    if (
      oldMember.userId === oldManifest.ownerUserId &&
      oldMember.role === "owner" &&
      nextMember.role === "admin" &&
      oldMember.status === "active" &&
      nextMember.status === "active"
    ) {
      oldOwnerChanged = true;
      continue;
    }
    if (
      oldMember.userId === nextManifest.ownerUserId &&
      oldMember.role !== "owner" &&
      nextMember.role === "owner" &&
      oldMember.status === "active" &&
      nextMember.status === "active"
    ) {
      newOwnerChanged = true;
      continue;
    }
    return false;
  }
  return oldOwnerChanged && newOwnerChanged;
}

function dissolveTransitionIsWellFormed(oldManifest: GroupManifest, nextManifest: GroupManifest): boolean {
  if (oldManifest.members.length !== nextManifest.members.length) {
    return false;
  }
  let removedCount = 0;
  for (const oldMember of oldManifest.members) {
    const nextMember = nextManifest.members.find((member) => member.userId === oldMember.userId);
    if (!nextMember) {
      return false;
    }
    if (oldMember.userId === oldManifest.ownerUserId) {
      if (!sameJson(oldMember, nextMember)) {
        return false;
      }
      continue;
    }
    if (oldMember.status === "active" && nextMember.status === "removed" && oldMember.role === nextMember.role) {
      removedCount += 1;
      continue;
    }
    if (!sameJson(oldMember, nextMember)) {
      return false;
    }
  }
  return removedCount > 0 || oldManifest.members.length === 1;
}

function validateTransitionShape(
  oldManifest: GroupManifest,
  nextManifest: GroupManifest,
  proof: GroupMembershipProof,
  operation: GroupTransitionOperation
): void {
  if (
    oldManifest.groupId !== nextManifest.groupId ||
    oldManifest.conversationId !== nextManifest.conversationId ||
    !sameJson(oldManifest.outbox, nextManifest.outbox) ||
    nextManifest.rosterVersion !== oldManifest.rosterVersion + 1
  ) {
    throw new HttpError(409, "group_transition_invalid", "group manifest transition is not contiguous");
  }
  if (proof.signerUserId !== nextManifest.signerUserId || proof.signerDeviceId !== nextManifest.signerDeviceId) {
    throw new HttpError(409, "group_transition_invalid", "group transition signer does not match the manifest signer");
  }
  const commitChanged = proof.commitMessageId !== (proof.previousCommitMessageId ?? "");
  if ((nextManifest.lastCommitMessageId ?? "") !== proof.commitMessageId ||
      nextManifest.mlsEpochHint !== oldManifest.mlsEpochHint + (commitChanged ? 1 : 0)) {
    throw new HttpError(409, "group_transition_invalid", "group transition MLS epoch or commit is not contiguous");
  }

  if (proof.operation !== groupTransitionProofOperation(operation)) {
    throw new HttpError(409, "group_transition_invalid", "group transition operation does not match membership proof");
  }
  let valid = false;
  switch (operation.type) {
    case "create":
      valid = oldManifest.rosterVersion === 0 && oldManifest.mlsEpochHint === 0 &&
        oldManifest.ownerUserId === nextManifest.ownerUserId &&
        genesisTransitionIsWellFormed(oldManifest, nextManifest) &&
        manifestTransitionMatches(oldManifest, nextManifest, (expected) => {
          expected.members = nextManifest.members;
          expected.memberDevices = nextManifest.memberDevices;
          expected.lastCommitMessageId = nextManifest.lastCommitMessageId;
        });
      break;
    case "invite_members": {
      const oldIds = new Set(oldManifest.members.map((member) => member.userId));
      const addedIds = nextManifest.members.filter((member) => !oldIds.has(member.userId)).map((member) => member.userId).sort();
      valid = membershipAdditionsAreWellFormed(oldManifest, nextManifest) &&
        sameJson([...new Set(operation.userIds)].sort(), addedIds) &&
        membershipDeviceAdditionsAreWellFormed(oldManifest, nextManifest, new Set(addedIds)) &&
        manifestTransitionMatches(oldManifest, nextManifest, (expected) => {
          expected.members = nextManifest.members;
          expected.memberDevices = nextManifest.memberDevices;
          expected.lastCommitMessageId = nextManifest.lastCommitMessageId;
        });
      break;
    }
    case "approve_join": {
      const oldUser = oldManifest.members.find((member) => member.userId === operation.userId);
      const nextUser = nextManifest.members.find((member) => member.userId === operation.userId);
      const addedUsers = nextManifest.members.filter((member) => !oldManifest.members.some((old) => old.userId === member.userId));
      const nextDevice = (nextManifest.memberDevices ?? []).find((device) => device.userId === operation.userId && device.deviceId === operation.deviceId && device.status === "active");
      valid = !oldUser && addedUsers.length === 1 && addedUsers[0].userId === operation.userId && nextUser?.role === "member" && nextUser.status === "active" && Boolean(nextDevice) &&
        membershipAdditionsAreWellFormed(oldManifest, nextManifest) &&
        membershipDeviceAdditionsAreWellFormed(oldManifest, nextManifest, new Set([operation.userId])) &&
        manifestTransitionMatches(oldManifest, nextManifest, (expected) => {
          expected.members = nextManifest.members;
          expected.memberDevices = nextManifest.memberDevices;
          expected.lastCommitMessageId = nextManifest.lastCommitMessageId;
        });
      break;
    }
    case "approve_leave":
    case "remove_member": {
      const targetUserId = operation.userId;
      const oldTarget = oldManifest.members.find((member) => member.userId === targetUserId);
      const nextTarget = nextManifest.members.find((member) => member.userId === targetUserId);
      const expectedStatus = operation.type === "approve_leave" ? "left" : "removed";
      valid = memberRemovalIsWellFormed(oldManifest, nextManifest, expectedStatus) &&
        Boolean(oldTarget && nextTarget && oldTarget.status === "active" && nextTarget.status === expectedStatus) &&
        memberDevicesForRemovalAreWellFormed(oldManifest, nextManifest, targetUserId) &&
        manifestTransitionMatches(oldManifest, nextManifest, (expected) => {
          expected.members = nextManifest.members;
          expected.memberDevices = nextManifest.memberDevices;
          expected.admins = nextManifest.admins;
          expected.lastCommitMessageId = nextManifest.lastCommitMessageId;
        });
      break;
    }
    case "add_device":
      valid = deviceAdditionIsWellFormed(oldManifest, nextManifest) &&
        (nextManifest.memberDevices ?? []).some((device) => device.userId === operation.userId && device.deviceId === operation.deviceId && device.status === "active") &&
        manifestTransitionMatches(oldManifest, nextManifest, (expected) => {
          expected.memberDevices = nextManifest.memberDevices;
          expected.lastCommitMessageId = nextManifest.lastCommitMessageId;
        });
      break;
    case "remove_device":
      valid = deviceRemovalIsWellFormed(oldManifest, nextManifest) &&
        (nextManifest.memberDevices ?? []).some((device) => device.userId === operation.userId && device.deviceId === operation.deviceId && device.status === "removed") &&
        manifestTransitionMatches(oldManifest, nextManifest, (expected) => {
          expected.memberDevices = nextManifest.memberDevices;
          expected.lastCommitMessageId = nextManifest.lastCommitMessageId;
        });
      break;
    case "update_metadata":
      valid = (
        oldManifest.title !== nextManifest.title ||
        oldManifest.joinPolicy !== nextManifest.joinPolicy ||
        oldManifest.memberInvitePolicy !== nextManifest.memberInvitePolicy
      ) && manifestTransitionMatches(oldManifest, nextManifest, (expected) => {
        expected.title = nextManifest.title;
        expected.joinPolicy = nextManifest.joinPolicy;
        expected.memberInvitePolicy = nextManifest.memberInvitePolicy;
      });
      break;
    case "set_admin":
      valid = adminUpdateIsWellFormed(oldManifest, nextManifest) &&
        nextManifest.members.some((member) => member.userId === operation.userId && member.status === "active" && member.role === (operation.isAdmin ? "admin" : "member")) &&
        manifestTransitionMatches(oldManifest, nextManifest, (expected) => {
          expected.members = nextManifest.members;
          expected.admins = nextManifest.admins;
        });
      break;
    case "transfer_ownership":
      valid = ownershipTransferIsWellFormed(oldManifest, nextManifest) &&
        nextManifest.ownerUserId === operation.userId &&
        manifestTransitionMatches(oldManifest, nextManifest, (expected) => {
          expected.ownerUserId = nextManifest.ownerUserId;
          expected.members = nextManifest.members;
          expected.admins = nextManifest.admins;
        });
      break;
    case "dissolve":
      valid = dissolveTransitionIsWellFormed(oldManifest, nextManifest) &&
        manifestTransitionMatches(oldManifest, nextManifest, (expected) => {
          expected.members = nextManifest.members;
          expected.lastCommitMessageId = nextManifest.lastCommitMessageId;
        });
      break;
    case "pcs_update":
      valid = commitChanged &&
        manifestTransitionMatches(oldManifest, nextManifest, (expected) => {
          expected.lastCommitMessageId = nextManifest.lastCommitMessageId;
        });
      break;
  }
  if (!valid) {
    throw new HttpError(409, "group_transition_invalid", `manifest changes do not match ${operation.type}`);
  }
}

export function groupTransitionProofOperation(operation: GroupTransitionOperation): string {
  switch (operation.type) {
    case "invite_members":
      return "invite";
    case "approve_leave":
      return "leave";
    case "remove_member":
      return "remove";
    case "pcs_update":
      return "pcs_update";
    default:
      return operation.type;
  }
}

export class GroupAuthorizationService {
  constructor(
    private readonly groupId: string,
    private readonly storage: DurableObjectStorageLike
  ) {}

  async getState(): Promise<GroupAuthorizationState | undefined> {
    return this.storage.get<GroupAuthorizationState>(GROUP_AUTHORIZATION_KEY);
  }

  async getPublicState(): Promise<GetGroupAuthorizationStateResult> {
    const state = await this.getState();
    if (!state) {
      throw new HttpError(428, "group_authorization_uninitialized", "group authorization has not been initialized");
    }
    return {
      manifest: state.manifest,
      manifestHash: await groupManifestSha256(state.manifest),
      lastTransitionId: state.lastTransitionId,
      phase: state.phase ?? (state.manifest.rosterVersion === 0 ? "provisioning" : "active"),
      materialized: (state.phase ?? (state.manifest.rosterVersion === 0 ? "provisioning" : "active")) === "active"
    };
  }

  async initialize(
    input: InitializeGroupAuthorizationRequest,
    runtimeToken: DeviceRuntimeToken,
    now: number
  ): Promise<InitializeGroupAuthorizationResult> {
    if (input.version !== CURRENT_MODEL_VERSION || input.groupId !== this.groupId) {
      throw new HttpError(400, "unsupported_version", "group authorization bootstrap scope is invalid");
    }
    validateManifestShape(input.manifest, this.groupId);
    if (runtimeToken.userId !== input.manifest.ownerUserId) {
      throw new HttpError(403, "invalid_capability", "only the transport owner's active group owner can bootstrap authorization");
    }

    const existing = await this.getState();
    if (existing) {
      if (!sameJson(existing.manifest, input.manifest)) {
        throw new HttpError(409, "group_authorization_conflict", "group authorization is already initialized with a different manifest");
      }
      return {
        initialized: true,
        alreadyInitialized: true,
        rosterVersion: existing.manifest.rosterVersion,
        lastCommitMessageId: existing.manifest.lastCommitMessageId
      };
    }

    const devices = mergeVerifiedDevices({}, input.identityBundles);
    validateManifestDevices(input.manifest, devices);
    verifyManifestSignature(input.manifest, devices);
    const state: GroupAuthorizationState = {
      version: "2",
      manifest: input.manifest,
      devices,
      initializedAt: now,
      updatedAt: now,
      phase: input.manifest.rosterVersion === 0 ? "provisioning" : "active"
    };
    await this.storage.put(GROUP_AUTHORIZATION_KEY, state);
    return {
      initialized: true,
      alreadyInitialized: false,
      rosterVersion: input.manifest.rosterVersion,
      lastCommitMessageId: input.manifest.lastCommitMessageId
    };
  }

  async authorize(
    request: Request,
    capability: GroupCapability,
    operation: GroupCapabilityOperation,
    allowedRoles: GroupRole[],
    now: number,
    allowInactiveMember = false,
    allowProvisioning = false
  ): Promise<{ state: GroupAuthorizationState; role: GroupRole }> {
    const state = await this.getState();
    if (!state) {
      throw new HttpError(428, "group_authorization_uninitialized", "group authorization has not been initialized");
    }
    const phase = state.phase ?? (state.manifest.rosterVersion === 0 ? "provisioning" : "active");
    if (phase === "provisioning" && !allowProvisioning) {
      throw new HttpError(428, "group_membership_uninitialized", "group membership has not completed its genesis transition");
    }
    const authorization = request.headers.get("Authorization")?.trim();
    const bearer = authorization?.startsWith("Bearer ") ? authorization.slice("Bearer ".length).trim() : "";
    if (
      capability.version !== CURRENT_MODEL_VERSION ||
      capability.service !== "group_outbox" ||
      capability.groupId !== this.groupId ||
      !bearer ||
      bearer !== capability.signature ||
      !Number.isSafeInteger(capability.expiresAt) ||
      capability.expiresAt <= now ||
      capability.expiresAt - now > MAX_CAPABILITY_TTL_MS ||
      !capability.operations.includes(operation)
    ) {
      throw new HttpError(403, "invalid_capability", "group capability is invalid or expired");
    }

    const device = state.devices[deviceKey(capability.userId, capability.deviceId)];
    const knownMember = state.manifest.members.find((item) => item.userId === capability.userId);
    const knownManifestDevice = (state.manifest.memberDevices ?? []).find(
      (item) => item.userId === capability.userId && item.deviceId === capability.deviceId
    );
    const hasValidDeviceSignature = Boolean(
      device &&
      device.status === "active" &&
      verifyEd25519(device.publicKey, capability.signature, groupCapabilitySigningPayload(capability))
    );
    if (
      hasValidDeviceSignature &&
      (knownMember?.status !== "active" || knownManifestDevice?.status !== "active")
    ) {
      throw new HttpError(403, "group_membership_revoked", "group membership has been revoked");
    }
    const member = allowInactiveMember
      ? knownMember
      : activeMember(state.manifest, capability.userId);
    const manifestDevice = knownManifestDevice?.status === "active" ? knownManifestDevice : undefined;
    if (
      !device ||
      device.status !== "active" ||
      !manifestDevice ||
      !member ||
      !hasValidDeviceSignature
    ) {
      throw new HttpError(403, "invalid_capability", "group capability device signature or membership is invalid");
    }
    if (!allowedRoles.includes(member.role) || !ROLE_OPERATIONS[member.role].has(operation)) {
      throw new HttpError(403, "invalid_capability", `current group role cannot use ${operation}`);
    }
    return { state, role: member.role };
  }

  async prepareUpdate(
    current: GroupAuthorizationState,
    update: GroupAuthorizationUpdate | undefined,
    proof: GroupMembershipProof | undefined,
    now: number,
    operation?: GroupTransitionOperation
  ): Promise<GroupAuthorizationState | undefined> {
    if (!proof && !update) {
      return undefined;
    }
    if (!proof || !update) {
      throw new HttpError(409, "group_transition_invalid", "membership proof and authorizationUpdate must be supplied together");
    }
    validateManifestShape(update.manifest, this.groupId);

    const devices = mergeVerifiedDevices(current.devices, update.identityBundles);
    validateManifestDevices(update.manifest, devices);
    const manifestHash = await groupManifestSha256(update.manifest);
    if (manifestHash !== proof.newManifestSha256) {
      throw new HttpError(409, "group_transition_invalid", "group manifest hash does not match membership proof");
    }
    verifyManifestSignature(update.manifest, devices);

    if (current.manifest.signature === update.manifest.signature) {
      verifyIdempotentMembershipProof(proof, { ...current, devices }, manifestHash);
      return {
        ...current,
        devices,
        lastTransitionProof: proof,
        updatedAt: now
      };
    }
    verifyMembershipProof(proof, current, update.manifest);
    if (!operation) {
      throw new HttpError(409, "group_transition_invalid", "atomic membership transition operation is required");
    }
    validateTransitionShape(current.manifest, update.manifest, proof, operation);
    return {
      ...current,
      manifest: update.manifest,
      devices,
      lastTransitionProof: proof,
      updatedAt: now,
      phase: current.phase === "provisioning" && operation.type === "create" ? "active" : (current.phase ?? "active")
    };
  }

  async commitPreparedUpdate(state: GroupAuthorizationState | undefined): Promise<void> {
    if (state) {
      await this.storage.put(GROUP_AUTHORIZATION_KEY, state);
    }
  }
}

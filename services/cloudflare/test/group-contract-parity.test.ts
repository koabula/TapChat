import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  groupManifestSha256,
  groupManifestSigningPayload,
  groupMembershipProofSigningPayload
} from "../src/auth/capability";
import type {
  GroupCapability,
  GroupCapabilityOperation,
  GroupManifest,
  GroupMembershipProof,
  GroupMessageType,
  GroupStateEventKind,
  GroupTransitionOperation,
  SealGroupOutboxRequest,
  SealGroupOutboxResult
} from "../src/types/contracts";

const fixture = JSON.parse(
  readFileSync(new URL("../../../test-fixtures/group-protocol-v1.json", import.meta.url), "utf8")
) as {
  manifest: GroupManifest;
  capability: GroupCapability;
  membershipProof: GroupMembershipProof;
  expected: { manifestSha256: string; membershipProofPayload: string };
  roleOperations: Record<"owner" | "admin" | "member", GroupCapabilityOperation[]>;
  groupMessageTypes: GroupMessageType[];
  groupTransitionOperations: GroupTransitionOperation["type"][];
  groupStateEventKinds: GroupStateEventKind[];
};

test("shared group fixture keeps manifest hash and membership proof payload stable", async () => {
  assert.equal(await groupManifestSha256(fixture.manifest), fixture.expected.manifestSha256);
  assert.equal(
    groupMembershipProofSigningPayload(fixture.membershipProof),
    fixture.expected.membershipProofPayload
  );
  const signingPayload = new TextDecoder().decode(groupManifestSigningPayload(fixture.manifest));
  assert.ok(signingPayload.startsWith("tapchat.group_manifest.v1\n{"));
  assert.ok(signingPayload.includes('"groupId":"group:fixture"'));
  assert.ok(!signingPayload.includes("fixture-signature"));
  assert.ok(!JSON.stringify(fixture.manifest).includes("group_id"));
});

test("shared role-operation matrix remains least-privilege ordered", () => {
  assert.deepEqual(fixture.capability.operations, fixture.roleOperations.owner);
  assert.ok(!fixture.roleOperations.admin.includes("seal_group"));
  assert.deepEqual(fixture.roleOperations.member, [
    "read",
    "subscribe",
    "append_application",
    "append_control"
  ]);
});

test("group contract includes dissolve message and seal capability", () => {
  const dissolved: GroupMessageType = "control_group_dissolved";
  const seal: GroupCapabilityOperation = "seal_group";

  assert.equal(dissolved, "control_group_dissolved");
  assert.equal(seal, "seal_group");
});

test("seal group outbox contract keeps Cloudflare HTTP camelCase", () => {
  const capability: GroupCapability = {
    version: "0.1",
    service: "group_outbox",
    groupId: "group:project",
    userId: "user:alice",
    deviceId: "device:alice:laptop",
    operations: ["read", "append_membership", "seal_group"],
    role: "owner",
    expiresAt: 1_775_004_800_000,
    signature: "cap-sig"
  };
  const request: SealGroupOutboxRequest = {
    groupId: "group:project",
    capability
  };
  const result: SealGroupOutboxResult = {
    sealed: true,
    sealedAt: 1_775_004_800_000,
    wasAlreadySealed: false
  };

  assert.deepEqual(Object.keys(request), ["groupId", "capability"]);
  assert.equal(request.capability.operations.at(-1), "seal_group");
  assert.equal(result.sealedAt, 1_775_004_800_000);
});

function groupTransitionProofOperation(operation: GroupTransitionOperation): string {
  switch (operation.type) {
    case "create":
    case "approve_join":
    case "transfer_ownership":
    case "set_admin":
    case "update_metadata":
    case "dissolve":
    case "add_device":
    case "remove_device":
    case "pcs_update":
      return operation.type;
    case "invite_members":
      return "invite";
    case "approve_leave":
      return "leave";
    case "remove_member":
      return "remove";
  }
}

function groupMessageTypeIsKnown(messageType: GroupMessageType): boolean {
  switch (messageType) {
    case "mls_application":
    case "mls_commit":
    case "mls_proposal":
    case "control_group_membership_changed":
    case "control_group_metadata_updated":
    case "control_group_join_requested":
    case "control_group_join_approved":
    case "control_group_join_rejected":
    case "control_group_leave_requested":
    case "control_group_dissolved":
    case "control_group_state_event":
    case "control_conversation_needs_rebuild":
      return true;
  }
}

function groupStateEventKindIsKnown(kind: GroupStateEventKind): boolean {
  switch (kind) {
    case "member_joined":
    case "member_left":
    case "member_removed":
    case "role_changed":
    case "ownership_transferred":
    case "group_metadata_changed":
    case "group_dissolved":
    case "mls_epoch_advanced":
      return true;
  }
}

test("group PCS contract variants stay exhaustive with shared fixture lists", () => {
  assert.equal(groupTransitionProofOperation({ type: "pcs_update" }), "pcs_update");
  assert.equal(groupMessageTypeIsKnown("mls_proposal"), true);
  assert.equal(groupStateEventKindIsKnown("mls_epoch_advanced"), true);
  assert.ok(fixture.groupMessageTypes.includes("mls_proposal"));
  assert.ok(fixture.groupTransitionOperations.includes("pcs_update"));
  assert.ok(fixture.groupStateEventKinds.includes("mls_epoch_advanced"));
  for (const messageType of fixture.groupMessageTypes) {
    assert.equal(groupMessageTypeIsKnown(messageType), true, messageType);
  }
  for (const kind of fixture.groupStateEventKinds) {
    assert.equal(groupStateEventKindIsKnown(kind), true, kind);
  }
  for (const operationType of fixture.groupTransitionOperations) {
    const operation = { type: operationType } as GroupTransitionOperation;
    assert.ok(groupTransitionProofOperation(operation).length > 0, operationType);
  }
});

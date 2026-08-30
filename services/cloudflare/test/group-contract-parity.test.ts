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

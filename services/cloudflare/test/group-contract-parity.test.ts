import test from "node:test";
import assert from "node:assert/strict";
import type {
  GroupCapability,
  GroupCapabilityOperation,
  GroupMessageType,
  SealGroupOutboxRequest,
  SealGroupOutboxResult
} from "../src/types/contracts";

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

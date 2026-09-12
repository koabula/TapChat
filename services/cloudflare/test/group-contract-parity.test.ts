import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  bindingPayload,
  capabilityPayload,
  groupManifestSha256,
  groupManifestSigningPayload,
  groupMembershipProofSigningPayload
} from "../src/auth/capability";
import { deviceRuntimeSigningPayload } from "../src/auth/runtime-auth";
import type {
  CapabilityOperation,
  CapabilityService,
  DeviceBinding,
  DeviceRuntimeRefreshChallenge,
  GroupCapability,
  GroupCapabilityOperation,
  GroupManifest,
  GroupMembershipProof,
  GroupMessageType,
  GroupStateEventKind,
  GroupTransitionOperation,
  InboxAppendCapability,
  SealGroupOutboxRequest,
  SealGroupOutboxResult
} from "../src/types/contracts";

async function sha256Hex(payload: Uint8Array<ArrayBuffer>): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", payload);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

const fixture = JSON.parse(
  readFileSync(new URL("../../../test-fixtures/group-protocol-v1.json", import.meta.url), "utf8")
) as {
  manifest: GroupManifest;
  capability: GroupCapability;
  membershipProof: GroupMembershipProof;
  expected: { manifestSha256: string; membershipProofPayloadSha256: string };
  roleOperations: Record<"owner" | "admin" | "member", GroupCapabilityOperation[]>;
  groupMessageTypes: GroupMessageType[];
  groupTransitionOperations: GroupTransitionOperation["type"][];
  groupStateEventKinds: GroupStateEventKind[];
};

test("shared group fixture keeps manifest hash and membership proof payload stable", async () => {
  assert.equal(await groupManifestSha256(fixture.manifest), fixture.expected.manifestSha256);
  // The payload is binary once framed, so the fixture pins its digest. The
  // Rust side computes the same digest from the same fixture: that is what
  // keeps the two implementations of the framing in step.
  assert.equal(
    await sha256Hex(groupMembershipProofSigningPayload(fixture.membershipProof)),
    fixture.expected.membershipProofPayloadSha256
  );

  const signingPayload = groupManifestSigningPayload(fixture.manifest);
  // Domain first, length-prefixed: four zero-ish bytes of u32 length, then the
  // domain, then the u32-prefixed body. A payload that still began with the
  // bare domain text would fail here.
  const domain = "tapchat.group_manifest.v1";
  assert.deepEqual(
    Array.from(signingPayload.subarray(0, 4)),
    [0, 0, 0, domain.length],
    "manifest payload must open with the u32 length of its domain"
  );
  assert.equal(new TextDecoder().decode(signingPayload.subarray(4, 4 + domain.length)), domain);
  const body = new TextDecoder().decode(signingPayload.subarray(4 + domain.length + 4));
  assert.ok(body.startsWith("{"));
  assert.ok(body.includes('"groupId":"group:fixture"'));
  assert.ok(!body.includes("fixture-signature"));
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

/**
 * The domains the worker verifies but the group fixture does not reach.
 *
 * Rust signs these and this worker verifies them, so the two framings have to
 * agree byte for byte. The only place both languages meet at runtime is the
 * CLI e2e suite, which needs a live runtime, so the digest is pinned here and
 * asserted again from Rust in `shared_signing_domain_fixture_matches_the_
 * typescript_framing`.
 */
const signingFixture = JSON.parse(
  readFileSync(new URL("../../../test-fixtures/signing-domains-v1.json", import.meta.url), "utf8")
) as {
  inboxAppendCapability: InboxAppendCapability;
  deviceBinding: DeviceBinding;
  deviceRuntimeChallenge: DeviceRuntimeRefreshChallenge;
  expected: {
    inboxAppendCapabilitySha256: string;
    deviceBindingSha256: string;
    deviceRuntimeChallengeSha256: string;
  };
};

test("shared signing-domain fixture matches the Rust framing", async () => {
  assert.equal(
    await sha256Hex(capabilityPayload(signingFixture.inboxAppendCapability)),
    signingFixture.expected.inboxAppendCapabilitySha256
  );
  assert.equal(
    await sha256Hex(bindingPayload(signingFixture.deviceBinding)),
    signingFixture.expected.deviceBindingSha256
  );
  assert.equal(
    await sha256Hex(deviceRuntimeSigningPayload(signingFixture.deviceRuntimeChallenge)),
    signingFixture.expected.deviceRuntimeChallengeSha256
  );
});

/**
 * The capability arrives from an attacker-controlled header via `JSON.parse`,
 * so the type union is a claim about producers, not a runtime guarantee. The
 * payload builder has to reject what the union excludes: the previous encoding
 * mapped both "append" and "Append" onto the same signed bytes while the grant
 * check treated them differently.
 */
test("capability payload rejects wire values outside the closed set", () => {
  const capability = { ...signingFixture.inboxAppendCapability };
  assert.throws(() =>
    capabilityPayload({ ...capability, operations: ["Append" as CapabilityOperation] })
  );
  assert.throws(() =>
    capabilityPayload({ ...capability, service: "Inbox" as CapabilityService })
  );
  // The control: the real wire names still build.
  assert.ok(capabilityPayload(capability).length > 0);
});

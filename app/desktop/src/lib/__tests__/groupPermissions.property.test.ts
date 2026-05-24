import { describe, test } from "vitest";
import fc from "fast-check";

import { canPerform, type GroupAction, type GroupGateContext } from "../groupPermissions";
import type {
  GroupJoinPolicy,
  GroupManifest,
  GroupMember,
  GroupMemberInvitePolicy,
  GroupMemberStatus,
  GroupRole,
} from "../types";

// ---------------------------------------------------------------------------
// Reference oracle — hand-written truth table for every action × context
// combination per `doc/PROTOCOL_GROUP_CN.md §5.1` (plus the §10.4 dissolve
// rule). The test suite checks that the `canPerform` implementation matches
// the oracle on every sampled input. We deliberately keep the oracle
// structurally distinct from the implementation so a bug in one does not
// propagate to the other.
// ---------------------------------------------------------------------------

type OracleContext = Required<Pick<GroupGateContext, "manifest" | "localUserId" | "localRole">> & {
  dissolvedAt: number | null;
  target: GroupMember | null;
};

function oracle(action: GroupAction, ctx: OracleContext): boolean {
  const { manifest, localRole, localUserId, dissolvedAt, target } = ctx;

  if (dissolvedAt !== null) return false;

  const localMember = manifest.members.find((m) => m.user_id === localUserId);
  if (!localRole || localMember?.status !== "active") return false;

  const role = localRole;

  switch (action) {
    case "send_message":
      return true;

    case "leave":
      if (role === "owner") {
        return manifest.members.some(
          (m) =>
            m.role === "owner" &&
            m.status === "active" &&
            m.user_id !== localUserId,
        );
      }
      return true;

    case "create_invite":
      if (role === "owner" || role === "admin") return true;
      return manifest.member_invite_policy === "request_owner_approval";

    case "list_join_requests":
    case "approve_join":
      return role === "owner" || role === "admin";

    case "update_metadata":
      return role === "owner" || role === "admin";

    case "set_admin":
      if (role !== "owner") return false;
      if (!target) return false;
      if (target.user_id === localUserId) return false;
      if (target.role === "owner") return false;
      return target.status === "active";

    case "transfer_ownership":
      if (role !== "owner") return false;
      if (!target) return false;
      if (target.user_id === localUserId) return false;
      return target.status === "active";

    case "remove_member":
      if (role !== "owner" && role !== "admin") return false;
      if (!target) return false;
      if (target.user_id === localUserId) return false;
      if (target.role === "owner") return false;
      if (role === "admin" && target.role === "admin") return false;
      return target.status === "active";

    case "dissolve":
      return role === "owner";
  }
}

// ---------------------------------------------------------------------------
// Generators.
//
// - `arbAction`: uniform over every `GroupAction` variant.
// - `arbManifest`: well-formed manifest with 1–8 members, each having a
//    role ∈ {owner, admin, member} and a status ∈ {active, pending,
//    removed, left}. We deliberately allow malformed cases (e.g. zero or
//    multiple owners) because the UI gate must still behave safely on
//    any manifest it might observe mid-rebuild.
// - `arbLocalRole`: the locally-computed role can disagree with the
//    manifest (the manifest might have been edited by a concurrent
//    admin); the oracle and the implementation must both treat
//    `localRole` as authoritative for the "is local active" question
//    and the manifest as authoritative for "what status is the local
//    user recorded as".
// ---------------------------------------------------------------------------

const ACTIONS: GroupAction[] = [
  "send_message",
  "create_invite",
  "list_join_requests",
  "approve_join",
  "remove_member",
  "update_metadata",
  "set_admin",
  "transfer_ownership",
  "leave",
  "dissolve",
];
const ROLES: GroupRole[] = ["owner", "admin", "member"];
const STATUSES: GroupMemberStatus[] = ["active", "pending", "removed", "left"];
const JOIN_POLICIES: GroupJoinPolicy[] = ["closed", "approval_required", "open_by_invite"];
const MEMBER_INVITE_POLICIES: GroupMemberInvitePolicy[] = [
  "owner_admin_only",
  "request_owner_approval",
];

const arbRole: fc.Arbitrary<GroupRole> = fc.constantFrom(...ROLES);
const arbStatus: fc.Arbitrary<GroupMemberStatus> = fc.constantFrom(...STATUSES);
const arbJoinPolicy: fc.Arbitrary<GroupJoinPolicy> = fc.constantFrom(...JOIN_POLICIES);
const arbMemberInvitePolicy: fc.Arbitrary<GroupMemberInvitePolicy> = fc.constantFrom(
  ...MEMBER_INVITE_POLICIES,
);
const arbAction: fc.Arbitrary<GroupAction> = fc.constantFrom(...ACTIONS);

const arbMember = (userId: string): fc.Arbitrary<GroupMember> =>
  fc.record({
    user_id: fc.constant(userId),
    role: arbRole,
    status: arbStatus,
  });

const arbManifestFromIds = (userIds: string[]): fc.Arbitrary<GroupManifest> =>
  fc
    .tuple(
      fc.array(
        fc.nat().map((n) => `device:${n}`),
        { minLength: 0, maxLength: 2 },
      ),
      arbJoinPolicy,
      arbMemberInvitePolicy,
      // members: one arbMember per id, in the order we supplied the ids
      fc.tuple(...userIds.map((id) => arbMember(id))),
    )
    .map(([admins, joinPolicy, memberInvitePolicy, members]) => {
      const manifest: GroupManifest = {
        version: "0.1",
        group_id: "group:test",
        conversation_id: "conv:group:test",
        title: "Test Group",
        owner_user_id: members[0]?.user_id ?? userIds[0] ?? "user:unknown",
        admins,
        members: [...members],
        member_devices: [],
        join_policy: joinPolicy,
        member_invite_policy: memberInvitePolicy,
        roster_version: 1,
        mls_epoch_hint: 0,
        outbox: {
          endpoint: "https://example.com/v1/groups/group%3Atest/outbox",
        },
        updated_at: 0,
        signer_user_id: members[0]?.user_id ?? userIds[0] ?? "user:unknown",
        signer_device_id: "device:owner",
        signature: "sig",
      };
      return manifest;
    });

const arbContext: fc.Arbitrary<OracleContext> = fc
  .integer({ min: 1, max: 8 })
  .chain((memberCount) => {
    const userIds = Array.from({ length: memberCount }, (_, i) => `user:${i}`);
    return fc
      .tuple(
        arbManifestFromIds(userIds),
        fc.integer({ min: 0, max: memberCount - 1 }),
        fc.option(arbRole, { freq: 3 }),
        fc.option(fc.integer({ min: 1, max: 1_700_000_000_000 }), { freq: 3 }),
        fc.option(fc.integer({ min: 0, max: memberCount - 1 }), { freq: 2 }),
      )
      .map(([manifest, localIdx, roleOpt, dissolvedOpt, targetIdx]) => {
        const localUserId = userIds[localIdx];
        const target =
          targetIdx === null
            ? null
            : (manifest.members[targetIdx] ?? null);
        return {
          manifest,
          localUserId,
          localRole: roleOpt,
          dissolvedAt: dissolvedOpt,
          target,
        };
      });
  });

function toGateContext(ctx: OracleContext): GroupGateContext {
  return {
    manifest: ctx.manifest,
    localUserId: ctx.localUserId,
    localRole: ctx.localRole,
    dissolvedAt: ctx.dissolvedAt,
    target: ctx.target ?? undefined,
  };
}

// ---------------------------------------------------------------------------
// Properties.
// ---------------------------------------------------------------------------

describe("groupPermissions.canPerform", () => {
  test("matches the hand-written oracle on every sampled input", () => {
    fc.assert(
      fc.property(arbAction, arbContext, (action, ctx) => {
        const expected = oracle(action, ctx);
        const actual = canPerform(action, toGateContext(ctx));
        if (expected !== actual) {
          throw new Error(
            `Oracle mismatch for action=${action}: expected ${expected}, got ${actual}. ctx=${JSON.stringify(
              ctx,
              null,
              2,
            )}`,
          );
        }
        return true;
      }),
      { numRuns: 2000 },
    );
  });

  test("dissolved groups reject every write action", () => {
    fc.assert(
      fc.property(arbAction, arbContext, (action, baseCtx) => {
        const ctx: OracleContext = { ...baseCtx, dissolvedAt: 1_700_000_000_000 };
        return canPerform(action, toGateContext(ctx)) === false;
      }),
      { numRuns: 500 },
    );
  });

  test("dissolved owner view is read-only for every concrete UI action", () => {
    const owner: GroupMember = {
      user_id: "user:alice",
      role: "owner",
      status: "active",
    };
    const member: GroupMember = {
      user_id: "user:bob",
      role: "member",
      status: "active",
    };
    const manifest: GroupManifest = {
      version: "0.1",
      group_id: "group:project",
      conversation_id: "conv:group:project",
      title: "Project",
      owner_user_id: owner.user_id,
      admins: [],
      members: [owner, member],
      member_devices: [],
      join_policy: "approval_required",
      member_invite_policy: "request_owner_approval",
      roster_version: 1,
      mls_epoch_hint: 0,
      outbox: {
        endpoint: "https://example.com/v1/groups/group%3Aproject/outbox",
      },
      updated_at: 1,
      signer_user_id: owner.user_id,
      signer_device_id: "device:alice:phone",
      signature: "sig",
    };

    for (const action of ACTIONS) {
      const allowed = canPerform(action, {
        manifest,
        localRole: "owner",
        localUserId: owner.user_id,
        dissolvedAt: 1_700_000_000_000,
        target: member,
      });
      if (allowed) {
        throw new Error(`dissolved group must render ${action} as read-only`);
      }
    }
  });

  test("non-active local members reject every action", () => {
    fc.assert(
      fc.property(arbAction, arbContext, fc.constantFrom("pending", "removed", "left" as GroupMemberStatus), (action, baseCtx, badStatus) => {
        // Force the local member's status to something non-active.
        const manifest: GroupManifest = {
          ...baseCtx.manifest,
          members: baseCtx.manifest.members.map((member) =>
            member.user_id === baseCtx.localUserId
              ? { ...member, status: badStatus }
              : member,
          ),
        };
        return (
          canPerform(action, toGateContext({ ...baseCtx, manifest, dissolvedAt: null })) === false
        );
      }),
      { numRuns: 500 },
    );
  });

  test("dissolve is owner-only", () => {
    fc.assert(
      fc.property(arbContext, (ctx) => {
        const allowed = canPerform("dissolve", toGateContext({ ...ctx, dissolvedAt: null }));
        if (ctx.localRole !== "owner") return allowed === false;
        // Owner case: implementation must also ensure local member is
        // active. The oracle handles that already; just check
        // implementation matches.
        const expected = oracle("dissolve", { ...ctx, dissolvedAt: null });
        return allowed === expected;
      }),
      { numRuns: 1000 },
    );
  });
});

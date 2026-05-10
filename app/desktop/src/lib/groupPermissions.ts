/**
 * UI-side cosmetic role gating for group actions.
 *
 * **This module is non-authoritative.** The TapChat protocol relies on
 * three independent layers for authoritative permission enforcement
 * (`doc/PROTOCOL_GROUP_CN.md §5.2`):
 *
 *   1. Rust core (`engine::local_group_role` + per-command role checks).
 *   2. Cloudflare group outbox (`GroupCapability.operations` + role).
 *   3. Receiver-side manifest signer validation on each member-changing
 *      commit.
 *
 * `canPerform()` duplicates a conservative view of those rules so the
 * React UI can hide / disable controls the core would otherwise
 * reject. Removing the UI gate does NOT grant any capability — the
 * core and server will still refuse unauthorised operations. The
 * desktop e2e and the fast-check property test in
 * `__tests__/groupPermissions.property.test.ts` pin this function to
 * the §5.1 matrix.
 */

import type {
  GroupManifest,
  GroupMember,
  GroupMemberInvitePolicy,
  GroupMemberStatus,
  GroupRole,
} from "./types";

/**
 * Every action the group UI can attempt to render. The names match
 * the button labels in `components/group/*` one-to-one so it's easy
 * to trace a rendered control back to the rule that gated it.
 */
export type GroupAction =
  | "send_message"
  | "create_invite"
  | "list_join_requests"
  | "approve_join"
  | "remove_member"
  | "update_metadata"
  | "set_admin"
  | "transfer_ownership"
  | "leave"
  | "dissolve";

/**
 * Additional signals the gate needs that are not covered by the
 * standard `GroupManifest` fields — specifically the
 * owner-side-only `dissolvedAt` marker, which is stored on
 * `PersistedGroupState` on the Rust side.
 */
export interface GroupGateContext {
  manifest: GroupManifest;
  /**
   * `null` when the local device is not a member of the group
   * (welcome pickup failed or local membership revoked). Mirrors
   * `PersistedGroupState.local_role`.
   */
  localRole: GroupRole | null;
  localUserId: string;
  /**
   * When set, the group has been dissolved by the owner and the
   * server outbox is sealed. Every write action must be gated off.
   */
  dissolvedAt?: number | null;
  /** The target of the action (required for actions on another member). */
  target?: GroupMember;
}

/**
 * Pure, synchronous permission gate. Returns `true` only when the
 * UI is confident the core will accept the corresponding action.
 *
 * This is intentionally conservative: if any rule is ambiguous, it
 * returns `false`. Users who need an action disabled for non-UI
 * reasons can still hit the core directly; the core will produce a
 * clear error that the UI then surfaces via the dialog's error
 * banner.
 */
export function canPerform(action: GroupAction, ctx: GroupGateContext): boolean {
  const { manifest, localRole, localUserId, dissolvedAt, target } = ctx;

  // Gate 0: dissolved groups are read-only. Only the already-"dissolved"
  // informational surfaces remain visible; every write action is off.
  if (dissolvedAt != null) {
    return false;
  }

  // Gate 1: removed / left members cannot do anything either. This
  // also covers the case where the local device has not imported its
  // welcome yet (`localRole === null` / `status !== "active"`).
  const localMember = findLocalMember(manifest.members, localUserId);
  const localStatus = statusOf(localMember);
  if (localRole == null || localStatus !== "active") {
    return false;
  }

  switch (action) {
    case "send_message":
      // Every active member may send. The composer `ensure_group_ready_for_send`
      // check on the core is the final gate.
      return true;

    case "leave":
      // Any active non-owner may leave. Owners must transfer first
      // (§5.1 "transfer ownership"). If the manifest still lists the
      // local user as `owner`, they cannot leave yet.
      if (localRole === "owner") {
        // Owners can leave only after transferring ownership. Since
        // this function is synchronous we look at the manifest: if
        // there is another owner-role member we consider the local
        // user able to leave (the second owner has already been
        // installed by a successful transfer).
        return manifest.members.some(
          (member) =>
            member.role === "owner" &&
            member.status === "active" &&
            member.user_id !== localUserId,
        );
      }
      return true;

    case "create_invite":
      // Owner / admin may always create invites. Members may only
      // create invites when the manifest declares
      // `request_owner_approval` — these invites still go through
      // admin review (R14.3 conservative choice).
      if (localRole === "owner" || localRole === "admin") {
        return true;
      }
      return isOpenMemberInvitePolicy(manifest.member_invite_policy);

    case "list_join_requests":
    case "approve_join":
      // Join requests are owner/admin only — the core rejects member
      // calls to `ListGroupJoinRequests` / `ApproveGroupJoin`.
      return localRole === "owner" || localRole === "admin";

    case "update_metadata":
      // Owner + admin may edit metadata (title / join_policy /
      // member_invite_policy). The granular per-field gating between
      // owner and admin is a core concern; the UI exposes the full
      // form for both roles.
      return localRole === "owner" || localRole === "admin";

    case "set_admin":
      // Only the owner may add or revoke admin roles.
      if (localRole !== "owner") return false;
      if (!target) return false;
      // Cannot toggle admin on self or on the owner.
      if (target.user_id === localUserId) return false;
      if (target.role === "owner") return false;
      return target.status === "active";

    case "transfer_ownership":
      // Owner-only; target must be an active member other than self.
      if (localRole !== "owner") return false;
      if (!target) return false;
      if (target.user_id === localUserId) return false;
      return target.status === "active";

    case "remove_member":
      if (localRole !== "owner" && localRole !== "admin") return false;
      if (!target) return false;
      if (target.user_id === localUserId) return false;
      if (target.role === "owner") return false; // §5.1 owner cannot be removed
      // Admins may only remove plain members (§5.1: admins cannot
      // remove other admins; that's owner-only). Owners may remove
      // admins and members alike.
      if (localRole === "admin" && target.role === "admin") return false;
      return target.status === "active";

    case "dissolve":
      // Irreversible, owner-only (§10.4).
      return localRole === "owner";

    default: {
      // Exhaustiveness guard: TypeScript will error if a new
      // `GroupAction` variant is added without a case here.
      const _exhaustive: never = action;
      return _exhaustive;
    }
  }
}

function findLocalMember(
  members: GroupMember[],
  localUserId: string,
): GroupMember | undefined {
  return members.find((member) => member.user_id === localUserId);
}

function statusOf(member: GroupMember | undefined): GroupMemberStatus | "missing" {
  return member?.status ?? "missing";
}

function isOpenMemberInvitePolicy(policy: GroupMemberInvitePolicy): boolean {
  // `request_owner_approval` lets members submit an invite link that
  // still requires admin approval. `owner_admin_only` blocks them.
  return policy === "request_owner_approval";
}

import { presentError } from "@/lib/errors";
import { useEffect, useMemo, useState } from "react";
import {
  X,
  Crown,
  Shield,
  UserMinus,
  UserCog,
  LogOut,
  ArrowRight,
  Zap,
  AlertCircle,
  Link2,
  UserCheck,
  Settings as SettingsIcon,
} from "lucide-react";

import { useGroupsStore } from "@/store/groups";
import { useContactsStore } from "@/store/contacts";
import { useSessionStore } from "@/store/session";
import {
  approveGroupLeave,
  getGroupSnapshot,
  leaveGroup,
  removeGroupMember,
  setGroupAdmin,
  transferGroupOwnership,
} from "@/lib/tauri";
import type { GroupMember, GroupRole } from "@/lib/types";
import { canPerform } from "@/lib/groupPermissions";
import { buildGroupNameResolver } from "@/lib/groupDisplayNames";
import DissolveConfirmDialog from "./DissolveConfirmDialog";
import GroupInviteDialog from "./GroupInviteDialog";
import GroupJoinApprovalPanel from "./GroupJoinApprovalPanel";
import GroupSettingsPanel from "./GroupSettingsPanel";

interface GroupMemberDrawerProps {
  open: boolean;
  groupId: string;
  localUserId: string;
  onClose: () => void;
}

/**
 * Right-side drawer that surfaces the group's roster and the
 * role-gated actions each UI role can perform.
 *
 * Authoritative role gating lives in the core and Cloudflare; this
 * component's gating is cosmetic (R14) — hiding / disabling actions
 * we know the core will reject, so the user does not hit avoidable
 * errors. Every failed command surfaces as an inline banner with the
 * core's error text (R10.6 / R18.3).
 */
export default function GroupMemberDrawer({
  open,
  groupId,
  localUserId,
  onClose,
}: GroupMemberDrawerProps) {
  const snapshot = useGroupsStore((s) => s.snapshots[groupId] ?? null);
  const setSnapshot = useGroupsStore((s) => s.setSnapshot);
  const contacts = useContactsStore((s) => s.contacts);
  const localDisplayName = useSessionStore((s) => s.displayName);

  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dissolveOpen, setDissolveOpen] = useState(false);
  const [inviteOpen, setInviteOpen] = useState(false);
  const [approvalOpen, setApprovalOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);

  useEffect(() => {
    if (!open) {
      setBusy(null);
      setError(null);
      setDissolveOpen(false);
      setInviteOpen(false);
      setApprovalOpen(false);
      setSettingsOpen(false);
    }
  }, [open]);

  // Refresh the snapshot when the drawer opens so the roster is fresh
  // even if core-update has not yet fanned out.
  useEffect(() => {
    if (open && groupId) {
      getGroupSnapshot(groupId)
        .then(setSnapshot)
        .catch((err) => {
          console.debug(
            `[GroupMemberDrawer] getGroupSnapshot(${groupId}) failed: ${presentError(err).message}`,
          );
        });
    }
  }, [open, groupId, setSnapshot]);

  const localRole = snapshot?.local_role ?? null;
  const isOwner = localRole === "owner";
  const dissolved = snapshot?.dissolved_at != null;
  const governanceReady =
    snapshot?.consistency_state === "ready" &&
    snapshot.pending_transition_stage === null &&
    !dissolved;

  const members = useMemo(() => snapshot?.manifest.members ?? [], [snapshot]);
  const resolveGroupName = useMemo(
    () =>
      buildGroupNameResolver({
        manifest: snapshot?.manifest ?? null,
        contacts,
        localUserId,
        localDisplayName,
      }),
    [contacts, localDisplayName, localUserId, snapshot?.manifest],
  );
  const activeMembers = useMemo(
    () => members.filter((m) => m.status === "active"),
    [members],
  );
  const canLeave = useMemo(() => {
    if (!snapshot || !governanceReady) return false;
    return canPerform("leave", {
      manifest: snapshot.manifest,
      localRole,
      localUserId,
      dissolvedAt: snapshot.dissolved_at ?? null,
    });
  }, [snapshot, localRole, localUserId, governanceReady]);

  const canDissolve = useMemo(() => {
    return snapshot != null && localRole === "owner" && governanceReady;
  }, [snapshot, localRole, governanceReady]);

  useEffect(() => {
    if (!governanceReady) {
      setInviteOpen(false);
      setApprovalOpen(false);
      setSettingsOpen(false);
      setDissolveOpen(false);
    }
  }, [governanceReady]);

  const runCommand = async (
    id: string,
    command: () => Promise<unknown>,
    options: { refreshOnSuccess?: boolean } = {},
  ): Promise<boolean> => {
    const { refreshOnSuccess = true } = options;
    setBusy(id);
    setError(null);
    try {
      await command();
      if (refreshOnSuccess) {
        const fresh = await getGroupSnapshot(groupId);
        setSnapshot(fresh);
      }
      return true;
    } catch (err) {
      setError(presentError(err).message);
      return false;
    } finally {
      setBusy(null);
    }
  };

  const handleRemove = (member: GroupMember) =>
    runCommand(`remove:${member.user_id}`, () => removeGroupMember(groupId, member.user_id));

  const handleToggleAdmin = (member: GroupMember) =>
    runCommand(`admin:${member.user_id}`, () =>
      setGroupAdmin(groupId, member.user_id, member.role !== "admin"),
    );

  const handleTransfer = (member: GroupMember) => {
    const memberName = resolveGroupName({ userId: member.user_id });
    const confirm = window.confirm(
      `Transfer ownership to ${memberName}? You will become an admin. This cannot be undone from this dialog.`,
    );
    if (!confirm) return;
    void runCommand(`transfer:${member.user_id}`, () =>
      transferGroupOwnership(groupId, member.user_id),
    );
  };

  const handleLeave = () => {
    const confirm = window.confirm(
      "Request to leave this group? An owner or admin must complete the encrypted membership update.",
    );
    if (!confirm) return;
    void runCommand("leave", () => leaveGroup(groupId));
  };

  const handleApproveLeave = (requestId: string) =>
    runCommand(`approve-leave:${requestId}`, () => approveGroupLeave(groupId, requestId));

  const pendingJoinCount = snapshot?.join_requests.filter(
    (request) => request.status === "pending_approval",
  ).length ?? 0;
  const pendingLeaveRequests = snapshot?.leave_requests.filter(
    (request) =>
      request.status === "waiting_for_group_commit" ||
      request.status === "transition_in_progress",
  ) ?? [];
  const localLeaveRequest = pendingLeaveRequests.find(
    (request) => request.leaver_user_id === localUserId,
  );

  if (!open) return null;

  return (
    <aside
      className="fixed right-0 top-0 bottom-0 z-40 w-full max-w-sm bg-surface border-l border-default shadow-xl flex flex-col overflow-hidden"
      role="dialog"
      aria-modal="true"
      aria-labelledby="member-drawer-title"
    >
      <header className="flex items-center justify-between p-4 border-b border-default">
        <div>
          <h2 id="member-drawer-title" className="font-semibold text-primary-color">
            {snapshot?.manifest.title || "Group"}
          </h2>
          <div className="text-xs text-muted-color">
            {activeMembers.length} member{activeMembers.length === 1 ? "" : "s"}
            {dissolved && <span className="ml-2 text-red-500">Dissolved</span>}
          </div>
        </div>
        <button className="btn btn-ghost px-2" onClick={onClose} aria-label="Close drawer">
          <X size={18} />
        </button>
      </header>

      {/* Action row — cosmetic gating: only shows buttons the user's
          role can actually use. The authoritative check still lives
          in the core/cloudflare (R14). */}
      {(isOwner || snapshot?.local_role === "admin") && !dissolved && (
        <nav className="flex items-center gap-2 p-2 border-b border-default">
          <button
            className="btn btn-ghost text-xs flex-1"
            onClick={() => setInviteOpen(true)}
            disabled={!governanceReady}
            title="Manage invite links"
          >
            <Link2 size={14} /> Invites
          </button>
          <button
            className="btn btn-ghost text-xs flex-1 relative"
            onClick={() => setApprovalOpen(true)}
            disabled={!governanceReady}
            title="Review join requests"
          >
            <UserCheck size={14} /> Requests
            {pendingJoinCount > 0 && (
              <span className="absolute -top-1 -right-1 badge badge-primary text-[10px]">
                {pendingJoinCount}
              </span>
            )}
          </button>
          <button
            className="btn btn-ghost text-xs flex-1"
            onClick={() => setSettingsOpen(true)}
            disabled={!governanceReady}
            title="Group settings"
          >
            <SettingsIcon size={14} /> Settings
          </button>
        </nav>
      )}

      <div className="flex-1 overflow-y-auto">
        {snapshot && !governanceReady && (
          <div
            className={`m-3 flex items-start gap-2 rounded-lg p-3 text-sm ${
              snapshot.consistency_state === "blocked_needs_rebuild"
                ? "bg-red-500/10 text-red-500"
                : "bg-yellow-500/10 text-yellow-500"
            }`}
            role="status"
          >
            <AlertCircle size={16} className="mt-0.5 shrink-0" />
            <div>
              {snapshot.consistency_state === "blocked_needs_rebuild"
                ? "This group's encrypted membership state cannot be verified. Governance is disabled until you explicitly rebuild the group."
                : snapshot.pending_transition_stage === "awaiting_authorization_bootstrap"
                  ? "This group is still being securely created. Membership controls will unlock after authorization is initialized."
                  : snapshot.pending_transition_stage
                    ? "A membership change is in progress. Wait for it to finish before starting another change."
                    : "The group is reconciling its authoritative membership state. Membership controls are temporarily read-only."}
            </div>
          </div>
        )}
        {!snapshot ? (
          <div className="text-center py-8 text-muted-color text-sm">Loading group...</div>
        ) : (
          <MemberList
            members={members}
            localUserId={localUserId}
            localRole={localRole}
            dissolved={dissolved}
            governanceReady={governanceReady}
            busy={busy}
            onRemove={handleRemove}
            onToggleAdmin={handleToggleAdmin}
            onTransfer={handleTransfer}
            resolveName={resolveGroupName}
          />
        )}

        {(isOwner || localRole === "admin") && pendingLeaveRequests.length > 0 && (
          <section className="m-3 rounded-lg border border-subtle p-3" aria-label="Leave requests">
            <h3 className="text-sm font-semibold text-primary-color">Leave requests</h3>
            <div className="mt-2 space-y-2">
              {pendingLeaveRequests.map((request) => (
                <div key={request.request_id} className="flex items-center justify-between gap-3">
                  <div className="min-w-0 text-sm">
                    <div className="truncate text-primary-color">
                      {resolveGroupName({ userId: request.leaver_user_id })}
                    </div>
                    <div className="text-xs text-muted-color">
                      {request.status === "transition_in_progress"
                        ? "Encrypted membership update in progress"
                        : "Waiting for confirmation"}
                    </div>
                  </div>
                  {request.status === "waiting_for_group_commit" && (
                    <button
                      className="btn btn-secondary text-xs shrink-0"
                      onClick={() => void handleApproveLeave(request.request_id)}
                      disabled={!governanceReady || busy !== null}
                    >
                      Confirm exit
                    </button>
                  )}
                </div>
              ))}
            </div>
          </section>
        )}

        {error && (
          <div
            role="alert"
            className="m-3 flex items-start gap-2 p-3 rounded-lg bg-red-500/10 text-sm text-red-500"
          >
            <AlertCircle size={16} className="shrink-0 mt-0.5" />
            <div className="break-words">{error}</div>
          </div>
        )}
      </div>

      <footer className="p-3 border-t border-default space-y-2">
        {localLeaveRequest && !isOwner && (
          <div className="rounded-lg bg-yellow-500/10 p-3 text-xs text-yellow-600" role="status">
            {localLeaveRequest.status === "transition_in_progress"
              ? "Your encrypted membership update is in progress."
              : "Waiting for an owner or admin to complete the encrypted membership update."}
          </div>
        )}
        {!isOwner && (
          <button
            className="btn btn-ghost w-full justify-start text-sm"
            onClick={handleLeave}
            disabled={!canLeave || busy !== null || localLeaveRequest != null}
            title={
              !canLeave
                ? dissolved
                  ? "You are no longer a member of this group."
                  : "Wait for the current group membership state to become ready."
                : undefined
            }
          >
            <LogOut size={16} /> Leave group
          </button>
        )}
        {isOwner && canDissolve && (
          <button
            className="btn btn-danger w-full justify-start text-sm"
            onClick={() => setDissolveOpen(true)}
            disabled={busy !== null}
          >
            <Zap size={16} /> Dissolve group
          </button>
        )}
      </footer>

      {snapshot && (
        <DissolveConfirmDialog
          open={dissolveOpen}
          groupId={groupId}
          groupTitle={snapshot.manifest.title}
          onClose={() => setDissolveOpen(false)}
          onDissolved={async () => {
            setDissolveOpen(false);
            // Refresh the snapshot to reflect dissolved_at (may still be
            // null until the seal ack arrives; core-update will update
            // it once the seal event lands).
            try {
              const fresh = await getGroupSnapshot(groupId);
              setSnapshot(fresh);
            } catch {
              // Non-fatal; core-update will refresh shortly.
            }
          }}
        />
      )}

      <GroupInviteDialog
        open={inviteOpen}
        groupId={groupId}
        onClose={() => setInviteOpen(false)}
      />
      <GroupJoinApprovalPanel
        open={approvalOpen}
        groupId={groupId}
        onClose={() => setApprovalOpen(false)}
      />
      <GroupSettingsPanel
        open={settingsOpen}
        groupId={groupId}
        onClose={() => setSettingsOpen(false)}
      />
    </aside>
  );
}

interface MemberListProps {
  members: GroupMember[];
  localUserId: string;
  localRole: GroupRole | null;
  dissolved: boolean;
  governanceReady: boolean;
  busy: string | null;
  onRemove: (member: GroupMember) => void;
  onToggleAdmin: (member: GroupMember) => void;
  onTransfer: (member: GroupMember) => void;
  resolveName: (input: { userId?: string | null; deviceId?: string | null }) => string;
}

function MemberList({
  members,
  localUserId,
  localRole,
  dissolved,
  governanceReady,
  busy,
  onRemove,
  onToggleAdmin,
  onTransfer,
  resolveName,
}: MemberListProps) {
  const sorted = [...members].sort((a, b) => {
    // Owner → admin → member; within a role sort by user_id.
    const rank = (role: GroupRole) =>
      role === "owner" ? 0 : role === "admin" ? 1 : 2;
    if (rank(a.role) !== rank(b.role)) {
      return rank(a.role) - rank(b.role);
    }
    return a.user_id.localeCompare(b.user_id);
  });

  // Stable manifest projection for the `canPerform` calls below. We
  // derive it once per render instead of re-constructing for every
  // row.
  const manifestForGate = useMemo(() => {
    // `canPerform` only reads the `members` and `member_invite_policy`
    // fields on this code path, so we build a minimal projection.
    return {
      version: "0.1",
      group_id: "",
      conversation_id: "",
      title: "",
      owner_user_id: "",
      admins: [],
      members,
      member_devices: [],
      join_policy: "closed",
      member_invite_policy: "owner_admin_only",
      roster_version: 0,
      mls_epoch_hint: 0,
      outbox: { endpoint: "" },
      updated_at: 0,
      signer_user_id: "",
      signer_device_id: "",
      signature: "",
    } as const;
  }, [members]);

  return (
    <ul className="p-3 space-y-2">
      {sorted.map((member) => {
        const isSelf = member.user_id === localUserId;
        const memberBusy =
          busy?.startsWith("remove:") && busy.endsWith(member.user_id)
            ? "Removing..."
            : busy?.startsWith("admin:") && busy.endsWith(member.user_id)
              ? "Updating role..."
              : busy?.startsWith("transfer:") && busy.endsWith(member.user_id)
                ? "Transferring..."
                : null;

        // Authoritative gate: canPerform covers every rule from
        // §5.1 plus dissolved / removed / left cases, matched by
        // the fast-check property test on §5.1.
        const gateCtx = {
          manifest: manifestForGate as unknown as import("@/lib/types").GroupManifest,
          localRole,
          localUserId,
          dissolvedAt: dissolved ? Date.now() : null,
          target: member,
        };
        const canRemove = governanceReady && canPerform("remove_member", gateCtx);
        const canToggleAdmin = governanceReady && canPerform("set_admin", gateCtx);
        const canTransfer = governanceReady && canPerform("transfer_ownership", gateCtx);
        const memberName = resolveName({ userId: member.user_id });

        return (
          <li
            key={member.user_id}
            className={`p-3 rounded-lg border border-subtle ${
              member.status === "active" ? "bg-base" : "bg-surface-elevated opacity-60"
            }`}
          >
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <div className="flex items-center gap-1 text-primary-color font-medium truncate">
                  {member.role === "owner" && (
                    <Crown size={14} className="text-amber-500" aria-label="Owner" />
                  )}
                  {member.role === "admin" && (
                    <Shield size={14} className="text-sky-500" aria-label="Admin" />
                  )}
                  <span className="truncate" title={member.user_id}>{memberName}</span>
                  {isSelf && <span className="text-xs text-muted-color">(you)</span>}
                </div>
                <div className="text-xs text-muted-color uppercase tracking-wide">
                  {member.role} · {member.status}
                </div>
              </div>
            </div>

            {memberBusy && (
              <div className="mt-2 text-xs text-muted-color">{memberBusy}</div>
            )}

            {member.status === "active" && (canRemove || canToggleAdmin || canTransfer) && (
              <div className="mt-2 flex flex-wrap gap-2">
                {canToggleAdmin && (
                  <button
                    className="btn btn-secondary text-xs"
                    onClick={() => onToggleAdmin(member)}
                    disabled={busy !== null}
                  >
                    <UserCog size={14} />
                    {member.role === "admin" ? "Demote admin" : "Make admin"}
                  </button>
                )}
                {canTransfer && (
                  <button
                    className="btn btn-secondary text-xs"
                    onClick={() => onTransfer(member)}
                    disabled={busy !== null}
                  >
                    <ArrowRight size={14} /> Transfer ownership
                  </button>
                )}
                {canRemove && (
                  <button
                    className="btn btn-danger text-xs"
                    onClick={() => onRemove(member)}
                    disabled={busy !== null}
                  >
                    <UserMinus size={14} /> Remove
                  </button>
                )}
              </div>
            )}
          </li>
        );
      })}
    </ul>
  );
}

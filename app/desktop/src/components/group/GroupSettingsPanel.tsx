import { useEffect, useMemo, useState } from "react";
import { X, Settings as SettingsIcon, AlertCircle } from "lucide-react";

import {
  getGroupSnapshot,
  updateGroupMetadata,
  type UpdateGroupMetadataResult,
} from "@/lib/tauri";
import type { GroupJoinPolicy, GroupMemberInvitePolicy } from "@/lib/types";
import { useGroupsStore } from "@/store/groups";

interface GroupSettingsPanelProps {
  open: boolean;
  groupId: string;
  onClose: () => void;
}

const JOIN_POLICIES: Array<{ value: GroupJoinPolicy; label: string; description: string }> = [
  {
    value: "closed",
    label: "Closed",
    description: "Owners/admins add members manually. Invite links are rejected.",
  },
  {
    value: "approval_required",
    label: "Approval required",
    description: "Invite links may submit join requests that owners/admins review.",
  },
  {
    value: "open_by_invite",
    label: "Open by invite",
    description:
      "Valid invite links auto-approve. Owners/admins must still be online to generate the MLS commit.",
  },
];

const MEMBER_INVITE_POLICIES: Array<{
  value: GroupMemberInvitePolicy;
  label: string;
  description: string;
}> = [
  {
    value: "owner_admin_only",
    label: "Owner / admin only",
    description: "Only owners and admins may create invite links.",
  },
  {
    value: "request_owner_approval",
    label: "Members may request",
    description:
      "Members may create invite links that still require owner/admin approval for each join request.",
  },
];

/**
 * Group settings editor (R11). Lets owner/admins update the title,
 * join policy, and member-invite policy. Save rolls back the form on
 * core rejection and surfaces the error verbatim.
 */
export default function GroupSettingsPanel({
  open,
  groupId,
  onClose,
}: GroupSettingsPanelProps) {
  const snapshot = useGroupsStore((s) => s.snapshots[groupId] ?? null);
  const setSnapshot = useGroupsStore((s) => s.setSnapshot);

  const [title, setTitle] = useState("");
  const [joinPolicy, setJoinPolicy] = useState<GroupJoinPolicy>("closed");
  const [memberInvitePolicy, setMemberInvitePolicy] =
    useState<GroupMemberInvitePolicy>("owner_admin_only");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [savedAt, setSavedAt] = useState<number | null>(null);

  const manifest = snapshot?.manifest ?? null;
  const localRole = snapshot?.local_role ?? null;
  const isOwner = localRole === "owner";
  const isAdmin = localRole === "admin";
  const privileged = isOwner || isAdmin;

  useEffect(() => {
    if (!open) return;
    if (manifest) {
      setTitle(manifest.title);
      setJoinPolicy(manifest.join_policy);
      setMemberInvitePolicy(manifest.member_invite_policy);
    }
    setError(null);
    setSavedAt(null);
  }, [open, manifest]);

  const dirty = useMemo(() => {
    if (!manifest) return false;
    return (
      title !== manifest.title ||
      joinPolicy !== manifest.join_policy ||
      memberInvitePolicy !== manifest.member_invite_policy
    );
  }, [manifest, title, joinPolicy, memberInvitePolicy]);

  const handleSave = async () => {
    if (!manifest) return;
    const trimmedTitle = title.trim();
    if (!trimmedTitle) {
      setError("Title must not be empty.");
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      const updates: {
        title?: string;
        joinPolicy?: GroupJoinPolicy;
        memberInvitePolicy?: GroupMemberInvitePolicy;
      } = {};
      if (trimmedTitle !== manifest.title) updates.title = trimmedTitle;
      if (joinPolicy !== manifest.join_policy) updates.joinPolicy = joinPolicy;
      if (memberInvitePolicy !== manifest.member_invite_policy) {
        updates.memberInvitePolicy = memberInvitePolicy;
      }
      const result: UpdateGroupMetadataResult = await updateGroupMetadata(
        groupId,
        updates,
      );
      setSavedAt(Date.now());
      // Refresh the snapshot so the UI reflects the authoritative
      // manifest (core may have bumped roster_version etc).
      const fresh = await getGroupSnapshot(groupId);
      setSnapshot(fresh);
      // If the core echoed empty strings / nulls (e.g. admin-only
      // fields rejected), reflect that in the form as a rollback.
      if (result.title !== null) setTitle(result.title);
    } catch (err) {
      // Roll back the form to the manifest values so the user knows
      // the change did not stick (R11.4).
      setTitle(manifest.title);
      setJoinPolicy(manifest.join_policy);
      setMemberInvitePolicy(manifest.member_invite_policy);
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  };

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="group-settings-title"
    >
      <div className="bg-surface rounded-lg shadow-xl w-full max-w-lg max-h-[85vh] flex flex-col overflow-hidden">
        <header className="flex items-center justify-between p-4 border-b border-default">
          <div className="flex items-center gap-2">
            <SettingsIcon size={20} className="text-primary-color" />
            <h2
              id="group-settings-title"
              className="text-lg font-semibold text-primary-color"
            >
              Group settings
            </h2>
          </div>
          <button className="btn btn-ghost px-2" onClick={onClose} aria-label="Close panel">
            <X size={18} />
          </button>
        </header>

        <div className="flex-1 min-h-0 overflow-y-auto p-4 space-y-4">
          {!manifest ? (
            <div className="text-center py-6 text-muted-color text-sm">
              Loading group settings…
            </div>
          ) : (
            <>
              {!privileged && (
                <div className="p-3 rounded-lg bg-yellow-500/10 text-sm text-yellow-500">
                  Only owners and admins can edit group settings.
                </div>
              )}
              <label className="block">
                <span className="text-sm text-secondary-color">Title</span>
                <input
                  className="input mt-1"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  disabled={!privileged || submitting}
                  maxLength={120}
                />
              </label>

              <fieldset className="space-y-2">
                <legend className="text-sm text-secondary-color">Join policy</legend>
                {JOIN_POLICIES.map((policy) => (
                  <label
                    key={policy.value}
                    className={`flex items-start gap-2 p-2 rounded-lg border ${
                      joinPolicy === policy.value
                        ? "border-primary bg-primary/10"
                        : "border-subtle bg-base"
                    } ${!privileged || submitting ? "opacity-60" : "cursor-pointer"}`}
                  >
                    <input
                      type="radio"
                      name="join_policy"
                      className="mt-1"
                      checked={joinPolicy === policy.value}
                      onChange={() => setJoinPolicy(policy.value)}
                      disabled={!privileged || submitting}
                    />
                    <div>
                      <div className="text-primary-color text-sm">{policy.label}</div>
                      <div className="text-xs text-muted-color">{policy.description}</div>
                    </div>
                  </label>
                ))}
              </fieldset>

              <fieldset className="space-y-2">
                <legend className="text-sm text-secondary-color">
                  Member invite policy
                </legend>
                {MEMBER_INVITE_POLICIES.map((policy) => (
                  <label
                    key={policy.value}
                    className={`flex items-start gap-2 p-2 rounded-lg border ${
                      memberInvitePolicy === policy.value
                        ? "border-primary bg-primary/10"
                        : "border-subtle bg-base"
                    } ${!privileged || submitting ? "opacity-60" : "cursor-pointer"}`}
                  >
                    <input
                      type="radio"
                      name="member_invite_policy"
                      className="mt-1"
                      checked={memberInvitePolicy === policy.value}
                      onChange={() => setMemberInvitePolicy(policy.value)}
                      disabled={!privileged || submitting}
                    />
                    <div>
                      <div className="text-primary-color text-sm">{policy.label}</div>
                      <div className="text-xs text-muted-color">{policy.description}</div>
                    </div>
                  </label>
                ))}
              </fieldset>

              {savedAt && !error && (
                <div className="text-xs text-green-500">Saved.</div>
              )}

              {error && (
                <div
                  role="alert"
                  className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10 text-sm text-red-500"
                >
                  <AlertCircle size={16} className="shrink-0 mt-0.5" />
                  <div className="break-words">{error}</div>
                </div>
              )}
            </>
          )}
        </div>

        <footer className="p-4 border-t border-default flex items-center justify-end gap-2">
          <button className="btn btn-ghost" onClick={onClose} disabled={submitting}>
            Close
          </button>
          <button
            className="btn btn-primary"
            onClick={handleSave}
            disabled={!privileged || !dirty || submitting}
          >
            {submitting ? "Saving..." : "Save changes"}
          </button>
        </footer>
      </div>
    </div>
  );
}

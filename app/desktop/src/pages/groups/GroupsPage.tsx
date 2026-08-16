import { presentError } from "@/lib/errors";
import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router";
import {
  AlertCircle,
  Link2,
  Loader,
  MessageCircle,
  RefreshCw,
  Settings,
  Shield,
  Star,
  UsersRound,
  Zap,
} from "lucide-react";

import GroupJoinByLinkDialog from "@/components/group/GroupJoinByLinkDialog";
import GroupMemberDrawer from "@/components/group/GroupMemberDrawer";
import DissolveConfirmDialog from "@/components/group/DissolveConfirmDialog";
import GroupSyncIndicator from "@/components/group/GroupSyncIndicator";
import GroupCreateDialog from "@/pages/groups/GroupCreateDialog";
import {
  getGroupSnapshot,
  listGroupConversations,
  setGroupSyncSettings,
  type GroupConversationSummary,
  type GroupSnapshotView,
} from "@/lib/tauri";
import { useConversationsStore } from "@/store/conversations";
import { useGroupsStore } from "@/store/groups";
import { useGroupSyncStore } from "@/store/groupSync";
import { useSessionStore } from "@/store/session";

export default function GroupsPage() {
  const navigate = useNavigate();
  const localUserId = useSessionStore((s) => s.userId) ?? "";
  const mergeGroupConversationSnapshot = useConversationsStore(
    (s) => s.mergeGroupConversationSnapshot,
  );
  const setGroupSnapshot = useGroupsStore((s) => s.setSnapshot);
  const snapshots = useGroupsStore((s) => s.snapshots);
  const syncSettings = useGroupSyncStore((s) => s.settings);
  const setSyncSettings = useGroupSyncStore((s) => s.setSettings);
  const syncStatuses = useGroupSyncStore((s) => s.statuses);

  const [groups, setGroups] = useState<GroupConversationSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [joinOpen, setJoinOpen] = useState(false);
  const [memberDrawerGroupId, setMemberDrawerGroupId] = useState<string | null>(null);
  const [dissolveGroup, setDissolveGroup] = useState<GroupSnapshotView | null>(null);
  const [savingSyncSettings, setSavingSyncSettings] = useState(false);

  const sortedGroups = useMemo(
    () =>
      [...groups].sort((a, b) => {
        if ((a.dissolved_at == null) !== (b.dissolved_at == null)) {
          return a.dissolved_at == null ? -1 : 1;
        }
        return a.title.localeCompare(b.title);
      }),
    [groups],
  );

  useEffect(() => {
    void refreshGroups({ initial: true });
  }, []);

  const refreshGroups = async (options: { initial?: boolean } = {}) => {
    if (options.initial) {
      setLoading(true);
    } else {
      setRefreshing(true);
    }
    setError(null);
    try {
      const summaries = await listGroupConversations();
      setGroups(summaries);
      mergeGroupConversationSnapshot(summaries);
      await Promise.all(
        summaries.map(async (summary) => {
          try {
            const snapshot = await getGroupSnapshot(summary.group_id);
            setGroupSnapshot(snapshot);
          } catch (err) {
            console.debug(
              `[GroupsPage] getGroupSnapshot(${summary.group_id}) failed: ${presentError(err).message}`,
            );
          }
        }),
      );
    } catch (err) {
      setError(presentError(err).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const openChat = (conversationId: string) => {
    navigate(`/chat/${conversationId}`);
  };

  const openMembers = async (groupId: string) => {
    try {
      const snapshot = await getGroupSnapshot(groupId);
      setGroupSnapshot(snapshot);
    } catch (err) {
      console.debug(`[GroupsPage] preloading snapshot failed: ${presentError(err).message}`);
    }
    setMemberDrawerGroupId(groupId);
  };

  const openDissolve = async (groupId: string) => {
    try {
      const snapshot = await getGroupSnapshot(groupId);
      setGroupSnapshot(snapshot);
      setDissolveGroup(snapshot);
    } catch (err) {
      setError(presentError(err).message);
    }
  };

  const updateSyncSettings = async (patch: Partial<typeof syncSettings>) => {
    const next = { ...syncSettings, ...patch };
    setSyncSettings(next);
    setSavingSyncSettings(true);
    try {
      const saved = await setGroupSyncSettings(next);
      setSyncSettings(saved);
    } catch (err) {
      setError(presentError(err).message);
      setSyncSettings(syncSettings);
    } finally {
      setSavingSyncSettings(false);
    }
  };

  const toggleImportant = (groupId: string) => {
    const important = new Set(syncSettings.important_group_ids);
    if (important.has(groupId)) {
      important.delete(groupId);
    } else {
      important.add(groupId);
    }
    void updateSyncSettings({ important_group_ids: Array.from(important) });
  };

  return (
    <div className="flex-1 min-h-0 overflow-y-auto bg-base">
      <header className="border-b border-default bg-surface p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="text-xl font-semibold text-primary-color">Groups</h1>
            <p className="text-sm text-muted-color">Encrypted group conversations</p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              className="btn btn-secondary"
              onClick={() => void refreshGroups()}
              disabled={refreshing}
            >
              {refreshing ? <Loader size={16} className="animate-spin" /> : <RefreshCw size={16} />}
              Refresh
            </button>
            <button className="btn btn-secondary" onClick={() => setJoinOpen(true)}>
              <Link2 size={16} />
              Join by link
            </button>
            <button className="btn btn-primary" onClick={() => setCreateOpen(true)}>
              <UsersRound size={16} />
              New group
            </button>
          </div>
        </div>
      </header>

      <main className="p-4">
        {error && (
          <div
            role="alert"
            className="mb-4 flex items-start gap-2 rounded-lg bg-red-500/10 p-3 text-sm text-red-500"
          >
            <AlertCircle size={16} className="mt-0.5 shrink-0" />
            <div className="break-words">{error}</div>
          </div>
        )}

        <section className="mb-4 rounded-lg border border-default bg-surface p-4">
          <div className="flex flex-wrap items-end gap-3">
            <label className="flex min-w-40 flex-col gap-1 text-xs text-muted-color">
              Sync mode
              <select
                className="rounded-md border border-default bg-base px-2 py-1 text-sm text-primary-color"
                value={syncSettings.mode}
                disabled={savingSyncSettings}
                onChange={(event) =>
                  void updateSyncSettings({
                    mode: event.target.value as typeof syncSettings.mode,
                  })
                }
              >
                <option value="auto">Auto</option>
                <option value="polling">Polling</option>
                <option value="manual">Manual</option>
              </select>
            </label>
            <label className="flex w-36 flex-col gap-1 text-xs text-muted-color">
              Max live groups
              <input
                className="rounded-md border border-default bg-base px-2 py-1 text-sm text-primary-color"
                type="number"
                min={0}
                max={50}
                value={syncSettings.max_websocket_groups}
                disabled={savingSyncSettings || syncSettings.mode !== "auto"}
                onChange={(event) =>
                  void updateSyncSettings({
                    max_websocket_groups: Number(event.target.value),
                  })
                }
              />
            </label>
            <label className="flex w-36 flex-col gap-1 text-xs text-muted-color">
              Poll minutes
              <input
                className="rounded-md border border-default bg-base px-2 py-1 text-sm text-primary-color"
                type="number"
                min={1}
                max={1440}
                value={syncSettings.poll_interval_minutes}
                disabled={savingSyncSettings || syncSettings.mode === "manual"}
                onChange={(event) =>
                  void updateSyncSettings({
                    poll_interval_minutes: Number(event.target.value),
                  })
                }
              />
            </label>
            <span className="text-xs text-muted-color">
              {savingSyncSettings ? "Saving..." : "Profile-local group sync settings"}
            </span>
          </div>
        </section>

        {loading ? (
          <div className="flex items-center justify-center py-16 text-muted-color">
            <Loader size={24} className="animate-spin" />
          </div>
        ) : sortedGroups.length === 0 ? (
          <div className="py-16 text-center text-muted-color">
            <UsersRound size={32} className="mx-auto mb-3" />
            <p className="mb-1">No groups yet</p>
          </div>
        ) : (
          <div className="grid gap-3">
            {sortedGroups.map((group) => {
              const snapshot = snapshots[group.group_id];
              const localRole = snapshot?.local_role ?? group.local_role;
              const dissolved = group.dissolved_at != null || snapshot?.dissolved_at != null;
              const consistencyState = snapshot?.consistency_state ?? "reconciling";
              const transitionStage = snapshot?.pending_transition_stage ?? null;
              const governanceReady =
                consistencyState === "ready" && transitionStage === null && !dissolved;
              const pending = snapshot?.pending_outbox_count ?? 0;
              const pendingJoinRequests =
                snapshot?.join_requests.filter(
                  (request) => request.status === "pending_approval",
                )
                  .length ?? 0;
              const activeMembers =
                snapshot?.manifest.members.filter((member) => member.status === "active")
                  .length ?? group.member_count;
              const isOwner = localRole === "owner";
              const canLeave = localRole != null && localRole !== "owner" && !dissolved;
              const important = syncSettings.important_group_ids.includes(group.group_id);

              return (
                <section
                  key={group.group_id}
                  className="rounded-lg border border-default bg-surface p-4"
                >
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <h2 className="truncate text-base font-semibold text-primary-color">
                          {group.title || "Untitled group"}
                        </h2>
                        {localRole && (
                          <span className="badge text-[10px] uppercase tracking-wide">
                            {localRole}
                          </span>
                        )}
                        {dissolved && (
                          <span className="badge bg-red-500/10 text-[10px] uppercase text-red-500">
                            dissolved
                          </span>
                        )}
                        {!dissolved && consistencyState === "blocked_needs_rebuild" && (
                          <span className="badge bg-red-500/10 text-[10px] uppercase text-red-500">
                            rebuild required
                          </span>
                        )}
                        {!dissolved && consistencyState === "reconciling" && (
                          <span className="badge bg-yellow-500/10 text-[10px] uppercase text-yellow-500">
                            reconciling
                          </span>
                        )}
                        {!dissolved && transitionStage && (
                          <span className="badge bg-sky-500/10 text-[10px] uppercase text-sky-500">
                            {transitionStage.replaceAll("_", " ")}
                          </span>
                        )}
                        {pendingJoinRequests > 0 && (
                          <span className="badge bg-yellow-500/10 text-[10px] uppercase text-yellow-500">
                            {pendingJoinRequests} join request
                            {pendingJoinRequests === 1 ? "" : "s"}
                          </span>
                        )}
                        {!dissolved && (
                          <GroupSyncIndicator status={syncStatuses[group.group_id]} />
                        )}
                      </div>
                      <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-color">
                        <span>{activeMembers} members</span>
                        <span>state: {group.conversation_state}</span>
                        <span>cursor: {snapshot?.cursor?.last_fetched_seq ?? 0}</span>
                        {pending > 0 && <span>pending outbox: {pending}</span>}
                        <span>membership: {consistencyState.replaceAll("_", " ")}</span>
                      </div>
                      <div className="mt-1 truncate font-mono text-xs text-muted-color">
                        {group.group_id}
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center justify-end gap-2">
                      <button
                        className={`btn btn-secondary text-xs ${important ? "status-warning" : ""}`}
                        onClick={() => toggleImportant(group.group_id)}
                        disabled={savingSyncSettings}
                        title={important ? "Important group" : "Prioritize realtime"}
                      >
                        <Star size={14} fill={important ? "currentColor" : "none"} />
                        Important
                      </button>
                      <button
                        className="btn btn-secondary text-xs"
                        onClick={() => openChat(group.conversation_id)}
                      >
                        <MessageCircle size={14} />
                        Open
                      </button>
                      <button
                        className="btn btn-secondary text-xs"
                        onClick={() => void openMembers(group.group_id)}
                      >
                        <Settings size={14} />
                        Manage
                      </button>
                      {isOwner && !dissolved && (
                        <button
                          className="btn btn-danger text-xs"
                          onClick={() => void openDissolve(group.group_id)}
                          disabled={!governanceReady}
                          title={
                            governanceReady
                              ? undefined
                              : "Membership controls are read-only until the group is ready."
                          }
                        >
                          <Zap size={14} />
                          Dissolve
                        </button>
                      )}
                    </div>
                  </div>

                  {isOwner && !dissolved && activeMembers > 1 && (
                    <div className="mt-3 flex items-start gap-2 rounded-lg bg-surface-elevated p-3 text-xs text-secondary-color">
                      <Shield size={14} className="mt-0.5 shrink-0" />
                      <span>
                        Owners cannot leave directly. Transfer ownership from Manage,
                        then leave, or dissolve the group.
                      </span>
                    </div>
                  )}
                  {canLeave && (
                    <div className="mt-3 text-xs text-secondary-color">
                      Open Manage to leave this group or review member details.
                    </div>
                  )}
                  {!dissolved && consistencyState === "blocked_needs_rebuild" && (
                    <div className="mt-3 flex items-start gap-2 rounded-lg bg-red-500/10 p-3 text-xs text-red-500">
                      <AlertCircle size={14} className="mt-0.5 shrink-0" />
                      <span>
                        This group's encrypted membership state could not be verified. Messaging history remains visible, but membership changes are blocked until the group is rebuilt.
                      </span>
                    </div>
                  )}
                </section>
              );
            })}
          </div>
        )}
      </main>

      <GroupCreateDialog
        open={createOpen}
        onClose={() => {
          setCreateOpen(false);
          void refreshGroups();
        }}
      />
      <GroupJoinByLinkDialog
        open={joinOpen}
        onClose={() => {
          setJoinOpen(false);
          void refreshGroups();
        }}
      />
      {memberDrawerGroupId && (
        <GroupMemberDrawer
          open={memberDrawerGroupId != null}
          groupId={memberDrawerGroupId}
          localUserId={localUserId}
          onClose={() => {
            setMemberDrawerGroupId(null);
            void refreshGroups();
          }}
        />
      )}
      {dissolveGroup && (
        <DissolveConfirmDialog
          open={dissolveGroup != null}
          groupId={dissolveGroup.group_id}
          groupTitle={dissolveGroup.manifest.title}
          onClose={() => setDissolveGroup(null)}
          onDissolved={() => {
            setDissolveGroup(null);
            void refreshGroups();
          }}
        />
      )}
    </div>
  );
}

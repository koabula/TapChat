import { create } from "zustand";
import type { GroupSnapshotView } from "../lib/tauri";

/**
 * Derived store for group-specific UI state.
 *
 * Key invariant (requirements R19.1 / R19.3): this store is **derived**,
 * never authoritative. All mutations flow through Tauri commands (which
 * go through `drive_core_with_handle` on the Rust side); the UI
 * subsequently reads a fresh `GroupSnapshotView` via
 * `getGroupSnapshot(groupId)` and writes it here through
 * [`setSnapshot`]. The store never invents or edits roster / capability
 * fields locally.
 *
 * Paired with [`useCoreUpdate`], which owns the refresh cadence:
 *   - After every `core-update` carrying `conversations_changed`, for
 *     each visible group conversation the hook invokes
 *     `getGroupSnapshot` and calls [`setSnapshot`].
 *   - Groups that disappear from the view-model are evicted via
 *     [`removeSnapshot`].
 *   - On `engine-reloaded` (profile switch) the hook calls [`clear`].
 */
interface GroupsState {
  /** Keyed by `group_id`. */
  snapshots: Record<string, GroupSnapshotView>;
  /** The group the chat view is currently displaying, if any. */
  activeGroupId: string | null;
  /** Replace or insert a snapshot for a single group. */
  setSnapshot: (snapshot: GroupSnapshotView) => void;
  /** Remove a snapshot (e.g. after the group disappears from the view-model). */
  removeSnapshot: (groupId: string) => void;
  /** Mark which group the chat view is rendering. */
  setActiveGroupId: (groupId: string | null) => void;
  /** Wipe everything (profile switch, logout, etc). */
  clear: () => void;
}

export const useGroupsStore = create<GroupsState>((set) => ({
  snapshots: {},
  activeGroupId: null,
  setSnapshot: (snapshot) =>
    set((state) => ({
      snapshots: {
        ...state.snapshots,
        [snapshot.group_id]: snapshot,
      },
    })),
  removeSnapshot: (groupId) =>
    set((state) => {
      if (!(groupId in state.snapshots)) {
        return state;
      }
      const next = { ...state.snapshots };
      delete next[groupId];
      return { snapshots: next };
    }),
  setActiveGroupId: (groupId) => set({ activeGroupId: groupId }),
  clear: () => set({ snapshots: {}, activeGroupId: null }),
}));

/** Convenience selector: the active group's snapshot, if any. */
export function selectActiveGroupSnapshot(state: GroupsState): GroupSnapshotView | null {
  if (!state.activeGroupId) return null;
  return state.snapshots[state.activeGroupId] ?? null;
}

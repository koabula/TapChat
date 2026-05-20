import { create } from "zustand";
import type { GroupSyncSettings } from "@/lib/tauri";

export type GroupSyncLamp = "websocket_live" | "polling_ok" | "websocket_error" | "idle";

export interface GroupSyncStatus {
  mode: "websocket" | "polling" | "manual";
  expectedWebsocket: boolean;
  connected: boolean;
  lastSyncedAt: number | null;
  lastError: string | null;
}

interface GroupSyncState {
  settings: GroupSyncSettings;
  loaded: boolean;
  recentGroupIds: string[];
  websocketGroupIds: string[];
  statuses: Record<string, GroupSyncStatus>;
  setSettings: (settings: GroupSyncSettings) => void;
  setLoaded: (loaded: boolean) => void;
  markGroupOpened: (groupId: string) => void;
  setWebsocketPlan: (groupIds: string[]) => void;
  markConnected: (groupId: string) => void;
  markDisconnected: (groupId: string, error?: string | null) => void;
  markSynced: (groupId: string) => void;
  markSyncFailed: (groupId: string, error: string) => void;
  setStatusMode: (
    groupId: string,
    mode: "websocket" | "polling" | "manual",
    expectedWebsocket: boolean,
  ) => void;
  clear: () => void;
}

export const DEFAULT_GROUP_SYNC_SETTINGS: GroupSyncSettings = {
  mode: "auto",
  max_websocket_groups: 5,
  poll_interval_minutes: 5,
  important_group_ids: [],
};

function defaultStatus(): GroupSyncStatus {
  return {
    mode: "manual",
    expectedWebsocket: false,
    connected: false,
    lastSyncedAt: null,
    lastError: null,
  };
}

export const useGroupSyncStore = create<GroupSyncState>((set) => ({
  settings: DEFAULT_GROUP_SYNC_SETTINGS,
  loaded: false,
  recentGroupIds: [],
  websocketGroupIds: [],
  statuses: {},
  setSettings: (settings) => set({ settings }),
  setLoaded: (loaded) => set({ loaded }),
  markGroupOpened: (groupId) =>
    set((state) => ({
      recentGroupIds: [groupId, ...state.recentGroupIds.filter((id) => id !== groupId)].slice(0, 50),
    })),
  setWebsocketPlan: (groupIds) =>
    set((state) => {
      const planned = new Set(groupIds);
      const statuses = { ...state.statuses };
      for (const groupId of groupIds) {
        statuses[groupId] = {
          ...defaultStatus(),
          ...statuses[groupId],
          mode: "websocket",
          expectedWebsocket: true,
        };
      }
      for (const [groupId, status] of Object.entries(statuses)) {
        if (status.expectedWebsocket && !planned.has(groupId)) {
          statuses[groupId] = {
            ...status,
            expectedWebsocket: false,
            connected: false,
          };
        }
      }
      return { websocketGroupIds: groupIds, statuses };
    }),
  markConnected: (groupId) =>
    set((state) => ({
      statuses: {
        ...state.statuses,
        [groupId]: {
          ...defaultStatus(),
          ...state.statuses[groupId],
          mode: "websocket",
          expectedWebsocket: true,
          connected: true,
          lastError: null,
        },
      },
    })),
  markDisconnected: (groupId, error = null) =>
    set((state) => ({
      statuses: {
        ...state.statuses,
        [groupId]: {
          ...defaultStatus(),
          ...state.statuses[groupId],
          connected: false,
          lastError: error,
        },
      },
    })),
  markSynced: (groupId) =>
    set((state) => ({
      statuses: {
        ...state.statuses,
        [groupId]: {
          ...defaultStatus(),
          ...state.statuses[groupId],
          lastSyncedAt: Date.now(),
          lastError: null,
        },
      },
    })),
  markSyncFailed: (groupId, error) =>
    set((state) => ({
      statuses: {
        ...state.statuses,
        [groupId]: {
          ...defaultStatus(),
          ...state.statuses[groupId],
          lastError: error,
        },
      },
    })),
  setStatusMode: (groupId, mode, expectedWebsocket) =>
    set((state) => ({
      statuses: {
        ...state.statuses,
        [groupId]: {
          ...defaultStatus(),
          ...state.statuses[groupId],
          mode,
          expectedWebsocket,
          connected: expectedWebsocket ? state.statuses[groupId]?.connected ?? false : false,
        },
      },
    })),
  clear: () =>
    set({
      settings: DEFAULT_GROUP_SYNC_SETTINGS,
      loaded: false,
      recentGroupIds: [],
      websocketGroupIds: [],
      statuses: {},
    }),
}));

export function groupSyncLamp(status: GroupSyncStatus | undefined): GroupSyncLamp {
  if (!status) return "idle";
  if (status.expectedWebsocket) {
    return status.connected ? "websocket_live" : "websocket_error";
  }
  if (status.mode === "polling" && status.lastSyncedAt != null && !status.lastError) {
    return "polling_ok";
  }
  return "idle";
}

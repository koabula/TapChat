import type { GroupSyncSettings } from "./tauri";

export interface GroupPlanInput {
  groupIds: string[];
  currentGroupId: string | null;
  recentGroupIds: string[];
  settings: GroupSyncSettings;
}

export function chooseWebsocketGroups(input: GroupPlanInput): string[] {
  if (input.settings.mode !== "auto" || input.settings.max_websocket_groups <= 0) {
    return [];
  }

  const available = new Set(input.groupIds);
  const selected: string[] = [];
  const take = (groupId: string | null | undefined) => {
    if (!groupId || !available.has(groupId) || selected.includes(groupId)) return;
    if (selected.length >= input.settings.max_websocket_groups) return;
    selected.push(groupId);
  };

  take(input.currentGroupId);
  input.settings.important_group_ids.forEach(take);
  input.recentGroupIds.forEach(take);

  return selected;
}

export function pollingInitialDelayMs(groupId: string, intervalMs: number): number {
  if (intervalMs <= 0) return 0;
  let hash = 2166136261;
  for (let index = 0; index < groupId.length; index += 1) {
    hash ^= groupId.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0) % intervalMs;
}

export function shouldPollGroup(
  groupId: string,
  websocketGroupIds: string[],
  settings: GroupSyncSettings,
): boolean {
  if (settings.mode === "manual") return false;
  if (settings.mode === "polling") return true;
  return !websocketGroupIds.includes(groupId);
}

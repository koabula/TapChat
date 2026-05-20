import { useEffect, useMemo, useRef } from "react";
import { listen } from "@tauri-apps/api/event";

import {
  applyGroupRealtimePlan,
  getGroupSyncSettings,
  syncGroupOutbox,
} from "@/lib/tauri";
import {
  chooseWebsocketGroups,
  pollingInitialDelayMs,
  shouldPollGroup,
} from "@/lib/groupSyncPlanner";
import { useConversationsStore } from "@/store/conversations";
import { useGroupsStore } from "@/store/groups";
import {
  DEFAULT_GROUP_SYNC_SETTINGS,
  useGroupSyncStore,
} from "@/store/groupSync";
import { useSessionStore } from "@/store/session";
import type { RealtimeEventPayload } from "@/lib/types";

export function useGroupSyncScheduler() {
  const sessionState = useSessionStore((s) => s.sessionState);
  const conversations = useConversationsStore((s) => s.conversations);
  const activeGroupId = useGroupsStore((s) => s.activeGroupId);
  const settings = useGroupSyncStore((s) => s.settings);
  const loaded = useGroupSyncStore((s) => s.loaded);
  const recentGroupIds = useGroupSyncStore((s) => s.recentGroupIds);
  const setSettings = useGroupSyncStore((s) => s.setSettings);
  const setLoaded = useGroupSyncStore((s) => s.setLoaded);
  const setWebsocketPlan = useGroupSyncStore((s) => s.setWebsocketPlan);
  const setStatusMode = useGroupSyncStore((s) => s.setStatusMode);
  const markConnected = useGroupSyncStore((s) => s.markConnected);
  const markDisconnected = useGroupSyncStore((s) => s.markDisconnected);
  const markSynced = useGroupSyncStore((s) => s.markSynced);
  const markSyncFailed = useGroupSyncStore((s) => s.markSyncFailed);
  const clear = useGroupSyncStore((s) => s.clear);
  const timersRef = useRef<ReturnType<typeof setTimeout>[]>([]);

  const groupIds = useMemo(
    () =>
      conversations
        .filter((conversation) => conversation.kind === "group" && conversation.group_id)
        .map((conversation) => conversation.group_id!)
        .sort(),
    [conversations],
  );

  const websocketGroupIds = useMemo(
    () =>
      chooseWebsocketGroups({
        groupIds,
        currentGroupId: activeGroupId,
        recentGroupIds,
        settings,
      }),
    [activeGroupId, groupIds, recentGroupIds, settings],
  );

  useEffect(() => {
    if (sessionState !== "active") {
      clear();
      return;
    }
    let cancelled = false;
    getGroupSyncSettings()
      .then((next) => {
        if (!cancelled) {
          setSettings(next);
          setLoaded(true);
        }
      })
      .catch((err) => {
        console.warn(`[GroupSync] failed to load settings: ${String(err)}`);
        if (!cancelled) {
          setSettings(DEFAULT_GROUP_SYNC_SETTINGS);
          setLoaded(true);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [clear, sessionState, setLoaded, setSettings]);

  useEffect(() => {
    if (sessionState !== "active" || !loaded) return;
    setWebsocketPlan(websocketGroupIds);
    applyGroupRealtimePlan(websocketGroupIds).catch((err) => {
      console.warn(`[GroupSync] failed to apply realtime plan: ${String(err)}`);
    });
  }, [loaded, sessionState, setWebsocketPlan, websocketGroupIds]);

  useEffect(() => {
    if (sessionState !== "active" || !loaded) return;
    const websocketSet = new Set(websocketGroupIds);
    for (const groupId of groupIds) {
      const poll = shouldPollGroup(groupId, websocketGroupIds, settings);
      setStatusMode(
        groupId,
        websocketSet.has(groupId) ? "websocket" : poll ? "polling" : "manual",
        websocketSet.has(groupId),
      );
    }
  }, [groupIds, loaded, sessionState, setStatusMode, settings, websocketGroupIds]);

  useEffect(() => {
    for (const timer of timersRef.current) clearTimeout(timer);
    timersRef.current = [];
    if (sessionState !== "active" || !loaded) return;

    const intervalMs = settings.poll_interval_minutes * 60_000;
    for (const groupId of groupIds) {
      const expectedWebsocket = websocketGroupIds.includes(groupId);
      if (!shouldPollGroup(groupId, websocketGroupIds, settings) && !expectedWebsocket) {
        continue;
      }
      const run = async () => {
        if (
          expectedWebsocket &&
          useGroupSyncStore.getState().statuses[groupId]?.connected === true
        ) {
          const next = setTimeout(run, intervalMs);
          timersRef.current.push(next);
          return;
        }
        try {
          await syncGroupOutbox(groupId, "poll");
          markSynced(groupId);
        } catch (err) {
          markSyncFailed(groupId, String(err));
        }
        const next = setTimeout(run, intervalMs);
        timersRef.current.push(next);
      };
      const first = setTimeout(run, pollingInitialDelayMs(groupId, intervalMs));
      timersRef.current.push(first);
    }

    return () => {
      for (const timer of timersRef.current) clearTimeout(timer);
      timersRef.current = [];
    };
  }, [
    groupIds,
    loaded,
    markSyncFailed,
    markSynced,
    sessionState,
    settings,
    websocketGroupIds,
  ]);

  useEffect(() => {
    const unlisten = listen<RealtimeEventPayload>("realtime-event", (event) => {
      const payload = event.payload;
      if (!payload.event_type.startsWith("group_")) return;
      if (payload.event_type === "group_connected") {
        markConnected(payload.device_id);
      } else if (payload.event_type === "group_disconnected") {
        markDisconnected(payload.device_id);
        syncGroupOutbox(payload.device_id, "realtime_disconnected")
          .then(() => markSynced(payload.device_id))
          .catch((err) => markSyncFailed(payload.device_id, String(err)));
      } else if (payload.event_type === "group_error") {
        markDisconnected(payload.device_id, payload.data ?? "group websocket error");
        syncGroupOutbox(payload.device_id, "realtime_error")
          .then(() => markSynced(payload.device_id))
          .catch((err) => markSyncFailed(payload.device_id, String(err)));
      } else if (
        payload.event_type === "group_head_updated" ||
        payload.event_type === "group_outbox_record_available" ||
        payload.event_type === "group_join_request_available"
      ) {
        syncGroupOutbox(payload.device_id, "realtime")
          .then(() => markSynced(payload.device_id))
          .catch((err) => markSyncFailed(payload.device_id, String(err)));
      }
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, [markConnected, markDisconnected, markSyncFailed, markSynced]);

  useEffect(() => {
    const unlisten = listen<void>("engine-reloaded", () => {
      setLoaded(false);
      getGroupSyncSettings()
        .then((next) => {
          setSettings(next);
          setLoaded(true);
        })
        .catch((err) => {
          console.warn(`[GroupSync] failed to reload settings: ${String(err)}`);
          setSettings(DEFAULT_GROUP_SYNC_SETTINGS);
          setLoaded(true);
        });
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, [setLoaded, setSettings]);
}

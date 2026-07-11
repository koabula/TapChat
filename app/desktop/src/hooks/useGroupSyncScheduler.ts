import { useEffect, useMemo, useRef } from "react";
import { listen } from "@tauri-apps/api/event";

import {
  applyGroupRealtimePlan,
  getGroupSnapshot,
  getGroupSyncSettings,
  processGroupJoinRequests,
  setGroupSyncSettings,
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
  const localUserId = useSessionStore((s) => s.userId);
  const conversations = useConversationsStore((s) => s.conversations);
  const activeGroupId = useGroupsStore((s) => s.activeGroupId);
  const snapshots = useGroupsStore((s) => s.snapshots);
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
  const setGroupSnapshot = useGroupsStore((s) => s.setSnapshot);
  const timersRef = useRef<ReturnType<typeof setTimeout>[]>([]);
  const oneShotSyncedRef = useRef<Set<string>>(new Set());
  const inFlightRef = useRef<Set<string>>(new Set());
  const foregroundSyncedAtRef = useRef(0);

  const groupIds = useMemo(
    () =>
      conversations
        .filter((conversation) => conversation.kind === "group" && conversation.group_id)
        .map((conversation) => conversation.group_id!)
        .sort(),
    [conversations],
  );
  const validGroupIds = useMemo(
    () =>
      groupIds.filter((groupId) => {
        const conversation = conversations.find((item) => item.group_id === groupId);
        if (conversation?.dissolved_at != null || conversation?.state === "dissolved") {
          return false;
        }
        const snapshot = snapshots[groupId];
        if (!snapshot || !localUserId) return true;
        return snapshot.manifest.members.some(
          (member) =>
            member.user_id === localUserId &&
            member.status !== "removed" &&
            member.status !== "left",
        );
      }),
    [conversations, groupIds, localUserId, snapshots],
  );
  const activityGroupIds = useMemo(
    () =>
      conversations
        .filter((conversation) => conversation.kind === "group" && conversation.group_id)
        .filter((conversation) => conversation.has_unread || conversation.message_count > 0)
        .sort((a, b) => {
          if (a.has_unread !== b.has_unread) return a.has_unread ? -1 : 1;
          return b.message_count - a.message_count;
        })
        .map((conversation) => conversation.group_id!)
        .filter((groupId) => validGroupIds.includes(groupId)),
    [conversations, validGroupIds],
  );

  const websocketGroupIds = useMemo(
    () =>
      chooseWebsocketGroups({
        groupIds: validGroupIds,
        currentGroupId: activeGroupId,
        recentGroupIds,
        activeGroupIds: activityGroupIds,
        settings,
      }),
    [activeGroupId, activityGroupIds, recentGroupIds, settings, validGroupIds],
  );

  useEffect(() => {
    if (sessionState !== "active") {
      oneShotSyncedRef.current.clear();
      inFlightRef.current.clear();
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
    const settingsRecent = settings.recent_group_ids ?? [];
    const same =
      settingsRecent.length === recentGroupIds.length &&
      settingsRecent.every((groupId, index) => groupId === recentGroupIds[index]);
    if (same) return;
    const next = {
      ...settings,
      recent_group_ids: recentGroupIds,
    };
    setGroupSyncSettings(next)
      .then(setSettings)
      .catch((err) => {
        console.warn(`[GroupSync] failed to persist recent groups: ${String(err)}`);
      });
  }, [loaded, recentGroupIds, sessionState, setSettings, settings]);

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
    for (const groupId of validGroupIds) {
      const poll = shouldPollGroup(groupId, websocketGroupIds, settings);
      setStatusMode(
        groupId,
        websocketSet.has(groupId) ? "websocket" : poll ? "polling" : "manual",
        websocketSet.has(groupId),
      );
    }
  }, [loaded, sessionState, setStatusMode, settings, validGroupIds, websocketGroupIds]);

  useEffect(() => {
    if (sessionState !== "active" || !loaded || validGroupIds.length === 0) return;
    const pending = validGroupIds.filter((groupId) => !oneShotSyncedRef.current.has(groupId));
    if (pending.length === 0) return;

    let cancelled = false;
    const runOneShot = async (reason: "startup" | "foreground", groupIdsToSync: string[]) => {
      const queue = [...groupIdsToSync];
      const workers = Array.from({ length: Math.min(3, queue.length) }, async () => {
        while (!cancelled) {
          const groupId = queue.shift();
          if (!groupId) return;
          if (inFlightRef.current.has(groupId)) continue;
          inFlightRef.current.add(groupId);
          try {
            await syncGroupOutbox(groupId, reason);
            markSynced(groupId);
          } catch (err) {
            markSyncFailed(groupId, String(err));
          } finally {
            inFlightRef.current.delete(groupId);
            oneShotSyncedRef.current.add(groupId);
          }
        }
      });
      await Promise.all(workers);
    };

    void runOneShot("startup", pending);
    return () => {
      cancelled = true;
    };
  }, [loaded, markSyncFailed, markSynced, sessionState, validGroupIds]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const onFocus = () => {
      if (useSessionStore.getState().sessionState !== "active") return;
      if (!useGroupSyncStore.getState().loaded) return;
      const now = Date.now();
      if (now - foregroundSyncedAtRef.current < 30_000) return;
      foregroundSyncedAtRef.current = now;
      const groupIdsToSync = validGroupIds.filter((groupId) => !inFlightRef.current.has(groupId));
      if (groupIdsToSync.length === 0) return;
      const queue = [...groupIdsToSync];
      const run = async () => {
        while (queue.length > 0) {
          const groupId = queue.shift();
          if (!groupId || inFlightRef.current.has(groupId)) continue;
          inFlightRef.current.add(groupId);
          try {
            await syncGroupOutbox(groupId, "foreground");
            markSynced(groupId);
          } catch (err) {
            markSyncFailed(groupId, String(err));
          } finally {
            inFlightRef.current.delete(groupId);
          }
        }
      };
      void Promise.all(Array.from({ length: Math.min(3, queue.length) }, run));
    };
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, [markSyncFailed, markSynced, validGroupIds]);

  useEffect(() => {
    for (const timer of timersRef.current) clearTimeout(timer);
    timersRef.current = [];
    if (sessionState !== "active" || !loaded) return;

    const intervalMs = settings.poll_interval_minutes * 60_000;
    for (const groupId of validGroupIds) {
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
    loaded,
    markSyncFailed,
    markSynced,
    sessionState,
    settings,
    validGroupIds,
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
      } else if (payload.event_type === "group_error") {
        markDisconnected(payload.device_id, payload.data ?? "group websocket error");
      } else if (payload.event_type === "group_join_request_available") {
        // RealtimeManager already delivered this to Core, which refreshes the
        // authoritative approval queue. Do not start a second list/sync path.
      } else if (payload.event_type === "group_auto_join_available") {
        // Open invites are advanced by whichever admin device wins the DO
        // lease. Core handles claim conflicts and idempotent retries.
        processGroupJoinRequests(payload.device_id)
          .then(() => getGroupSnapshot(payload.device_id))
          .then((snapshot) => {
            setGroupSnapshot(snapshot);
            markSynced(payload.device_id);
          })
          .catch((err) => markSyncFailed(payload.device_id, String(err)));
      } else if (payload.event_type === "group_invites_changed") {
        // Core owns the authority refresh. An open invite dialog refreshes its
        // projection after that event; no parallel scheduler request is needed.
      } else if (payload.event_type === "group_leave_request_available") {
        // Core refreshes the shared leave-request queue. The explicit approval
        // surface consumes the resulting snapshot when available.
      } else if (
        payload.event_type === "group_head_updated" ||
        payload.event_type === "group_outbox_record_available"
      ) {
        // RealtimeManager maps these events directly into Rust Core. Core owns
        // the per-group in-flight fetch guard; firing a second frontend sync
        // here races the authoritative cursor and can split transition bundles.
      }
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, [
    markConnected,
    markDisconnected,
    markSyncFailed,
    markSynced,
    setGroupSnapshot,
  ]);

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

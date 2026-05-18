import { useEffect, useRef } from "react";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";

import { useConversationsStore } from "../store/conversations";
import { useContactsStore } from "../store/contacts";
import { useSessionStore } from "../store/session";
import { useMessageRequestsStore } from "../store/requests";
import { useGroupsStore } from "../store/groups";
import {
  getGroupSnapshot,
  listGroupConversations,
  type GroupConversationSummary,
} from "../lib/tauri";

import type {
  CoreUpdateEvent,
  ConversationSummary,
  ContactSummary,
  MessageRequestItem,
} from "../lib/types";

function mapContacts(contacts: ContactSummary[]) {
  return contacts.map((contact) => ({
    user_id: contact.user_id,
    display_name: contact.display_name ?? null,
    device_count: contact.device_count,
    last_refresh: null,
  }));
}

async function fetchConversationSnapshot(): Promise<ConversationSummary[]> {
  return invoke<ConversationSummary[]>("list_conversations");
}

/**
 * Hook that listens to core-update events and dispatches them to the appropriate stores.
 * Also fetches initial data on mount when the session is active.
 *
 * Handles profile switching by clearing stores and reloading data on engine-reloaded event.
 */
export function useCoreUpdate() {
  const setConversations = useConversationsStore((s) => s.setConversations);
  const mergeConversationSnapshot = useConversationsStore(
    (s) => s.mergeConversationSnapshot,
  );
  const mergeGroupConversationSnapshot = useConversationsStore(
    (s) => s.mergeGroupConversationSnapshot,
  );
  const setContacts = useContactsStore((s) => s.setContacts);
  const sessionState = useSessionStore((s) => s.sessionState);
  const setDeviceId = useSessionStore((s) => s.setDeviceId);
  const setRequests = useMessageRequestsStore((s) => s.setRequests);
  const setGroupSnapshot = useGroupsStore((s) => s.setSnapshot);
  const removeGroupSnapshot = useGroupsStore((s) => s.removeSnapshot);
  const clearGroups = useGroupsStore((s) => s.clear);
  const latestConversationRequestIdRef = useRef(0);
  const latestAppliedConversationRequestIdRef = useRef(0);
  /**
   * Debounce group-snapshot refreshes: back-to-back core-update events
   * that touch the same group (e.g. a commit + its ack) should coalesce
   * into a single `getGroupSnapshot` fetch within a short window.
   * Tracks the in-flight debounce timers keyed by group_id.
   */
  const groupRefreshTimersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(
    new Map(),
  );

  const applyConversationSnapshot = (
    requestId: number,
    conversations: ConversationSummary[],
    contacts: Array<{ user_id: string; display_name: string | null }>,
    markUnread: boolean,
    replace: boolean,
  ) => {
    if (requestId < latestAppliedConversationRequestIdRef.current) {
      return;
    }
    latestAppliedConversationRequestIdRef.current = requestId;
    mergeConversationSnapshot(conversations, contacts, { markUnread, replace });
  };

  const refreshConversationsFromBackend = async (
    contacts: Array<{ user_id: string; display_name: string | null }>,
    markUnread: boolean,
  ) => {
    const requestId = ++latestConversationRequestIdRef.current;
    const conversations = await fetchConversationSnapshot();
    if (requestId < latestConversationRequestIdRef.current) {
      return;
    }
    applyConversationSnapshot(requestId, conversations, contacts, markUnread, true);
  };

  /**
   * Fan out a single group-snapshot refresh with short debounce.
   *
   * The Rust core may emit multiple back-to-back `core-update` events
   * for the same group (MLS commit, control envelope, seal ack, etc).
   * Debouncing lets the UI coalesce these into a single
   * `getGroupSnapshot` fetch per burst while still guaranteeing the
   * snapshot is fresh once the burst ends.
   *
   * Requirements R2.4 / R5.2 / R19.2.
   */
  const scheduleGroupSnapshotRefresh = (groupId: string) => {
    const timers = groupRefreshTimersRef.current;
    const existing = timers.get(groupId);
    if (existing) {
      clearTimeout(existing);
    }
    const handle = setTimeout(() => {
      timers.delete(groupId);
      getGroupSnapshot(groupId)
        .then((snapshot) => {
          setGroupSnapshot(snapshot);
        })
        .catch((err) => {
          // Non-fatal — the snapshot will be refreshed on the next
          // core-update or foreground fetch.
          console.debug(
            `[useCoreUpdate] getGroupSnapshot(${groupId}) failed: ${String(err)}`,
          );
        });
    }, 250);
    timers.set(groupId, handle);
  };

  /**
   * Pull the freshly-flattened group conversation list from the Tauri
   * layer and fan out per-group snapshot refreshes. Groups that have
   * vanished from the list (e.g. after a profile switch) are evicted
   * from the store.
   */
  const refreshGroupsFromBackend = async () => {
    let summaries: GroupConversationSummary[];
    try {
      summaries = await listGroupConversations();
    } catch (err) {
      console.debug(
        `[useCoreUpdate] listGroupConversations failed: ${String(err)}`,
      );
      return;
    }
    mergeGroupConversationSnapshot(summaries);
    const visible = new Set(summaries.map((summary) => summary.group_id));
    for (const summary of summaries) {
      scheduleGroupSnapshotRefresh(summary.group_id);
    }
    const known = Object.keys(useGroupsStore.getState().snapshots);
    for (const groupId of known) {
      if (!visible.has(groupId)) {
        removeGroupSnapshot(groupId);
        const pending = groupRefreshTimersRef.current.get(groupId);
        if (pending) {
          clearTimeout(pending);
          groupRefreshTimersRef.current.delete(groupId);
        }
      }
    }
  };

  const fetchAndSetData = async () => {
    try {
      console.debug("[useCoreUpdate] fetching initial data");

      const contacts = await invoke<ContactSummary[]>("list_contacts");
      console.debug(`[useCoreUpdate] loaded contacts=${contacts.length}`);

      const mappedContacts = mapContacts(contacts);
      setContacts(mappedContacts);

      const conversations = await fetchConversationSnapshot();
      console.debug(`[useCoreUpdate] loaded conversations=${conversations.length}`);
      const requestId = ++latestConversationRequestIdRef.current;
      applyConversationSnapshot(requestId, conversations, mappedContacts, false, true);

      // Fan out group-specific snapshot refreshes. Keeps groups in
      // sync on every session start without requiring the ChatView
      // component to refetch on mount.
      await refreshGroupsFromBackend();

      const requestsResult = await invoke<{
        view_model?: { message_requests?: MessageRequestItem[] };
      }>("list_message_requests");
      if (requestsResult.view_model?.message_requests) {
        setRequests(requestsResult.view_model.message_requests);
        console.debug(
          `[useCoreUpdate] loaded message_requests=${requestsResult.view_model.message_requests.length}`,
        );
      }

      try {
        const identity = await invoke<{ device_id?: string } | null>("get_identity_info");
        if (identity?.device_id) {
          setDeviceId(identity.device_id);
        }
      } catch (err) {
        console.error(`[useCoreUpdate] failed to get identity info: ${String(err)}`);
      }
    } catch (err) {
      console.error(`[useCoreUpdate] failed to fetch data: ${String(err)}`);
    }
  };

  const clearStores = () => {
    console.debug("[useCoreUpdate] clearing stores");
    setConversations([], { replace: true });
    setContacts([]);
    clearGroups();
    useConversationsStore.getState().setActiveConversation(null);
    // Clear any in-flight group-snapshot refreshes so a lingering
    // fetch from the previous profile does not race a fresh store.
    for (const timer of groupRefreshTimersRef.current.values()) {
      clearTimeout(timer);
    }
    groupRefreshTimersRef.current.clear();
  };

  useEffect(() => {
    if (sessionState === "active") {
      void fetchAndSetData();
    }

    const unlistenCoreUpdate = listen<CoreUpdateEvent>("core-update", (event) => {
      const { state_update, view_model } = event.payload;

      console.debug(
        `[useCoreUpdate] core-update conversations_changed=${state_update.conversations_changed} contacts_changed=${state_update.contacts_changed} messages_changed=${state_update.messages_changed} has_view_model=${Boolean(view_model)}`,
      );

      let nextContacts = useContactsStore.getState().contacts;

      if (state_update.contacts_changed && view_model?.contacts) {
        nextContacts = mapContacts(view_model.contacts);
        setContacts(nextContacts);
      }

      if (state_update.conversations_changed || state_update.messages_changed) {
        if (view_model?.conversations) {
          const requestId = ++latestConversationRequestIdRef.current;
          applyConversationSnapshot(
            requestId,
            view_model.conversations,
            nextContacts,
            state_update.messages_changed,
            false,
          );
        } else {
          void refreshConversationsFromBackend(
            nextContacts,
            state_update.messages_changed,
          ).catch((err) => {
            console.error(
              `[useCoreUpdate] failed to refresh conversations from backend: ${String(err)}`,
            );
          });
        }
        // Keep group snapshots in lock-step with the conversation list.
        // Every conversation change that could touch a group (membership
        // commit, new join, metadata update, dissolve) goes through
        // this branch, so we always re-fetch the flat group list and
        // fan out per-group snapshot refreshes.
        void refreshGroupsFromBackend().catch((err) => {
          console.debug(
            `[useCoreUpdate] failed to refresh groups from backend: ${String(err)}`,
          );
        });
      } else if (state_update.contacts_changed) {
        setConversations(useConversationsStore.getState().conversations, {
          markUnread: false,
          replace: true,
        });
      }

      if (view_model?.banners && view_model.banners.length > 0) {
        for (const banner of view_model.banners) {
          console.warn("[useCoreUpdate] System banner:", banner.status, banner.message);
        }
      }

      if (view_model?.message_requests) {
        setRequests(view_model.message_requests);
        console.debug(
          `[useCoreUpdate] message_requests=${view_model.message_requests.length}`,
        );
      }
    });

    const unlistenEngineReloaded = listen<void>("engine-reloaded", () => {
      console.debug("[useCoreUpdate] engine reloaded");
      clearStores();
      void fetchAndSetData();
    });

    return () => {
      unlistenCoreUpdate.then((fn) => fn());
      unlistenEngineReloaded.then((fn) => fn());
    };
  }, [
    mergeConversationSnapshot,
    mergeGroupConversationSnapshot,
    setConversations,
    setContacts,
    setDeviceId,
    setRequests,
    setGroupSnapshot,
    removeGroupSnapshot,
    clearGroups,
    sessionState,
  ]);
}

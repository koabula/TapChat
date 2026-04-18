import { useEffect, useRef } from "react";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";

import { useConversationsStore } from "../store/conversations";
import { useContactsStore } from "../store/contacts";
import { useSessionStore } from "../store/session";
import { useMessageRequestsStore } from "../store/requests";

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
  const setContacts = useContactsStore((s) => s.setContacts);
  const sessionState = useSessionStore((s) => s.sessionState);
  const setDeviceId = useSessionStore((s) => s.setDeviceId);
  const setRequests = useMessageRequestsStore((s) => s.setRequests);
  const latestConversationRequestIdRef = useRef(0);
  const latestAppliedConversationRequestIdRef = useRef(0);

  const applyConversationSnapshot = (
    requestId: number,
    conversations: ConversationSummary[],
    contacts: Array<{ user_id: string; display_name: string | null }>,
    markUnread: boolean,
  ) => {
    if (requestId < latestAppliedConversationRequestIdRef.current) {
      return;
    }
    latestAppliedConversationRequestIdRef.current = requestId;
    mergeConversationSnapshot(conversations, contacts, { markUnread });
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
    applyConversationSnapshot(requestId, conversations, contacts, markUnread);
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
      applyConversationSnapshot(requestId, conversations, mappedContacts, false);

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
    setConversations([]);
    setContacts([]);
    useConversationsStore.getState().setActiveConversation(null);
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
      } else if (state_update.contacts_changed) {
        setConversations(useConversationsStore.getState().conversations, {
          markUnread: false,
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
    setConversations,
    setContacts,
    setDeviceId,
    setRequests,
    sessionState,
  ]);
}

import { useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
import { useConversationsStore } from "../store/conversations";
import { useContactsStore } from "../store/contacts";
import { useSessionStore } from "../store/session";
import { useMessageRequestsStore } from "../store/requests";
import type { CoreUpdateEvent, ConversationSummary, ContactSummary, MessageRequestItem } from "../lib/types";
import type { Conversation } from "../store/conversations";

function mapContacts(contacts: ContactSummary[]) {
  return contacts.map((contact) => ({
    user_id: contact.user_id,
    display_name: contact.display_name ?? null,
    device_count: contact.device_count,
    last_refresh: null,
  }));
}

function displayMessagePreview(conversation: ConversationSummary): string {
  const preview = conversation.last_message_preview?.trim();
  if (preview) {
    return preview;
  }
  return conversation.peer_user_id;
}

function buildConversations(
  conversations: ConversationSummary[],
  contacts: Array<{ user_id: string; display_name: string | null }>,
  previous: Conversation[],
  activeConversationId: string | null,
  markUnread: boolean,
): Conversation[] {
  const previousById = new Map(previous.map((conversation) => [conversation.conversation_id, conversation]));
  const displayNameByUserId = new Map(contacts.map((contact) => [contact.user_id, contact.display_name]));

  return conversations.map((conversation) => {
    const prior = previousById.get(conversation.conversation_id);
    const displayName = displayNameByUserId.get(conversation.peer_user_id) ?? null;
    const messageCount = conversation.message_count ?? prior?.message_count ?? 0;
    const hasNewMessages = prior !== undefined && messageCount > prior.message_count;
    const shouldMarkUnread =
      markUnread &&
      hasNewMessages &&
      conversation.conversation_id !== activeConversationId;

    return {
      conversation_id: conversation.conversation_id,
      peer_user_id: conversation.peer_user_id,
      state: conversation.state,
      display_name: displayName,
      last_message: displayMessagePreview(conversation),
      last_message_time: prior?.last_message_time ?? null,
      message_count: messageCount,
      unread_count: shouldMarkUnread ? 1 : prior?.unread_count ?? 0,
      has_unread:
        conversation.conversation_id === activeConversationId
          ? false
          : shouldMarkUnread || prior?.has_unread || false,
    };
  });
}

function refreshConversationDisplayNames(
  conversations: Conversation[],
  contacts: Array<{ user_id: string; display_name: string | null }>,
): Conversation[] {
  const displayNameByUserId = new Map(contacts.map((contact) => [contact.user_id, contact.display_name]));
  return conversations.map((conversation) => ({
    ...conversation,
    display_name: displayNameByUserId.get(conversation.peer_user_id) ?? null,
  }));
}

/**
 * Hook that listens to core-update events and dispatches them to the appropriate stores.
 * Also fetches initial data on mount when the session is active.
 *
 * Handles profile switching by clearing stores and reloading data on engine-reloaded event.
 */
export function useCoreUpdate() {
  const setConversations = useConversationsStore((s) => s.setConversations);
  const setContacts = useContactsStore((s) => s.setContacts);
  const sessionState = useSessionStore((s) => s.sessionState);
  const setDeviceId = useSessionStore((s) => s.setDeviceId);
  const setRequests = useMessageRequestsStore((s) => s.setRequests);

  // Function to fetch and set all data
  const fetchAndSetData = async () => {
    try {
      console.debug("[useCoreUpdate] fetching initial data");

      // Fetch contacts
      const contacts = await invoke<ContactSummary[]>("list_contacts");
      console.debug(`[useCoreUpdate] loaded contacts=${contacts.length}`);

      const mappedContacts = mapContacts(contacts);
      setContacts(mappedContacts);

      // Fetch conversations
      const conversations = await invoke<ConversationSummary[]>("list_conversations");
      console.debug(`[useCoreUpdate] loaded conversations=${conversations.length}`);
      const mappedConversations = buildConversations(
        conversations,
        mappedContacts,
        [],
        useConversationsStore.getState().activeConversationId,
        false,
      );
      setConversations(mappedConversations);

      // Fetch message requests
      const requestsResult = await invoke<{ view_model?: { message_requests?: MessageRequestItem[] } }>("list_message_requests");
      if (requestsResult.view_model?.message_requests) {
        setRequests(requestsResult.view_model.message_requests);
        console.debug(`[useCoreUpdate] loaded message_requests=${requestsResult.view_model.message_requests.length}`);
      }

      // Fetch identity info to get device_id
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

  // Clear all stores
  const clearStores = () => {
    console.debug("[useCoreUpdate] clearing stores");
    setConversations([]);
    setContacts([]);
    useConversationsStore.getState().setActiveConversation(null);
  };

  useEffect(() => {
    // Fetch initial data if session is active
    if (sessionState === "active") {
      fetchAndSetData();
    }

    // Listen for core-update events
    const unlistenCoreUpdate = listen<CoreUpdateEvent>("core-update", (event) => {
      const { state_update, view_model } = event.payload;

      console.debug(
        `[useCoreUpdate] core-update conversations_changed=${state_update.conversations_changed} contacts_changed=${state_update.contacts_changed} messages_changed=${state_update.messages_changed} has_view_model=${Boolean(view_model)}`
      );

      if (!view_model) return;

      // Update conversations if changed
      const previousConversations = useConversationsStore.getState().conversations;
      const activeConversationId = useConversationsStore.getState().activeConversationId;
      let nextContacts = useContactsStore.getState().contacts;

      // Update contacts if changed
      if (state_update.contacts_changed && view_model.contacts) {
        nextContacts = mapContacts(view_model.contacts);
        setContacts(nextContacts);
      }

      if (view_model.conversations && (state_update.conversations_changed || state_update.messages_changed)) {
        const conversations = buildConversations(
          view_model.conversations,
          nextContacts,
          previousConversations,
          activeConversationId,
          state_update.messages_changed,
        );
        setConversations(conversations);
      } else if (state_update.contacts_changed) {
        setConversations(refreshConversationDisplayNames(previousConversations, nextContacts));
      }

      // Process banners for system status notifications
      if (view_model.banners && view_model.banners.length > 0) {
        for (const banner of view_model.banners) {
          console.warn("[useCoreUpdate] System banner:", banner.status, banner.message);
        }
      }

      // Process message requests
      if (view_model.message_requests) {
        setRequests(view_model.message_requests);
        console.debug(`[useCoreUpdate] message_requests=${view_model.message_requests.length}`);
      }
    });

    // Listen for engine-reloaded event (profile switch)
    const unlistenEngineReloaded = listen<void>("engine-reloaded", () => {
      console.debug("[useCoreUpdate] engine reloaded");
      // Clear stores first to remove old profile's data
      clearStores();
      // Then fetch new profile's data
      fetchAndSetData();
    });

    return () => {
      unlistenCoreUpdate.then((fn) => fn());
      unlistenEngineReloaded.then((fn) => fn());
    };
  }, [setConversations, setContacts, setDeviceId, setRequests, sessionState]);
}

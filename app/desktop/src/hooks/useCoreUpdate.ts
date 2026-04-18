import { useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
import { useConversationsStore } from "../store/conversations";
import { useContactsStore } from "../store/contacts";
import { useSessionStore } from "../store/session";
import { useMessageRequestsStore } from "../store/requests";
import type { CoreUpdateEvent, ConversationSummary, ContactSummary, MessageRequestItem } from "../lib/types";

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

      // Fetch conversations
      const conversations = await invoke<ConversationSummary[]>("list_conversations");
      console.debug(`[useCoreUpdate] loaded conversations=${conversations.length}`);

      const mappedConversations = conversations.map((c) => ({
        conversation_id: c.conversation_id,
        peer_user_id: c.peer_user_id,
        state: c.state,
        last_message: c.last_message_type ? formatMessageType(c.last_message_type) : null,
        last_message_time: null,
        unread_count: 0,
      }));
      setConversations(mappedConversations);

      // Fetch contacts
      const contacts = await invoke<ContactSummary[]>("list_contacts");
      console.debug(`[useCoreUpdate] loaded contacts=${contacts.length}`);

      const mappedContacts = contacts.map((c) => ({
        user_id: c.user_id,
        display_name: null,
        device_count: c.device_count,
        last_refresh: null,
      }));
      setContacts(mappedContacts);

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
      if (state_update.conversations_changed && view_model.conversations) {
        const conversations = view_model.conversations.map((c) => ({
          conversation_id: c.conversation_id,
          peer_user_id: c.peer_user_id,
          state: c.state,
          last_message: c.last_message_type ? formatMessageType(c.last_message_type) : null,
          last_message_time: null,
          unread_count: 0,
        }));
        setConversations(conversations);
      }

      // Update contacts if changed
      if (state_update.contacts_changed && view_model.contacts) {
        const contacts = view_model.contacts.map((c) => ({
          user_id: c.user_id,
          display_name: null,
          device_count: c.device_count,
          last_refresh: null,
        }));
        setContacts(contacts);
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

function formatMessageType(type: string): string {
  switch (type) {
    case "text":
      return "Message";
    case "attachment":
      return "Attachment";
    case "control":
      return "Control message";
    default:
      return type;
  }
}

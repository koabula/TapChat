import { useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
import { useConversationsStore } from "../store/conversations";
import { useContactsStore } from "../store/contacts";
import { useSessionStore } from "../store/session";
import type { CoreUpdateEvent, ConversationSummary, ContactSummary } from "../lib/types";

/**
 * Hook that listens to core-update events and dispatches them to the appropriate stores.
 * Also fetches initial data on mount when the session is active.
 */
export function useCoreUpdate() {
  const setConversations = useConversationsStore((s) => s.setConversations);
  const setContacts = useContactsStore((s) => s.setContacts);
  const sessionState = useSessionStore((s) => s.sessionState);

  useEffect(() => {
    // Fetch initial data if session is active
    if (sessionState === "active") {
      fetchInitialData();
    }

    async function fetchInitialData() {
      try {
        console.log("[useCoreUpdate] Fetching initial data...");

        // Fetch conversations
        const conversations = await invoke<ConversationSummary[]>("list_conversations");
        console.log("[useCoreUpdate] Loaded conversations:", conversations.length);

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
        console.log("[useCoreUpdate] Loaded contacts:", contacts.length);

        const mappedContacts = contacts.map((c) => ({
          user_id: c.user_id,
          display_name: null,
          device_count: c.device_count,
          last_refresh: null,
        }));
        setContacts(mappedContacts);
      } catch (err) {
        console.error("[useCoreUpdate] Failed to fetch initial data:", err);
      }
    }

    // Listen for core-update events
    const unlisten = listen<CoreUpdateEvent>("core-update", (event) => {
      const { state_update, view_model } = event.payload;

      // Log for debugging
      console.log("[useCoreUpdate] Received core-update:", {
        state_update,
        view_model,
      });

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
        // Could dispatch to a separate message requests store
        console.log("[useCoreUpdate] Message requests:", view_model.message_requests.length);
      }
    });

    return () => {
      unlisten.then((fn) => fn());
    };
  }, [setConversations, setContacts, sessionState]);
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
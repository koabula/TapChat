import { useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import { useConversationsStore } from "../store/conversations";
import { useContactsStore } from "../store/contacts";
import { useSessionStore } from "../store/session";
import type { CoreUpdateEvent } from "../lib/types";

/**
 * Hook that listens to core-update events and dispatches them to the appropriate stores.
 */
export function useCoreUpdate() {
  const setConversations = useConversationsStore((s) => s.setConversations);
  const setContacts = useContactsStore((s) => s.setContacts);
  const setUserId = useSessionStore((s) => s.setUserId);

  useEffect(() => {
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
          peer_user_id: "", // We need to fetch this separately or add to view model
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
  }, [setConversations, setContacts, setUserId]);
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
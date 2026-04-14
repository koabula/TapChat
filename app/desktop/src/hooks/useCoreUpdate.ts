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
 *
 * Handles profile switching by clearing stores and reloading data on engine-reloaded event.
 */
export function useCoreUpdate() {
  const setConversations = useConversationsStore((s) => s.setConversations);
  const setContacts = useContactsStore((s) => s.setContacts);
  const sessionState = useSessionStore((s) => s.sessionState);
  const setDeviceId = useSessionStore((s) => s.setDeviceId);

  // Function to fetch and set all data
  const fetchAndSetData = async () => {
    try {
      console.log("[useCoreUpdate] Fetching data...");

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

      // Fetch identity info to get device_id
      try {
        const identity = await invoke<{ device_id?: string } | null>("get_identity_info");
        if (identity?.device_id) {
          setDeviceId(identity.device_id);
        }
      } catch (err) {
        console.error("[useCoreUpdate] Failed to get identity info:", err);
      }
    } catch (err) {
      console.error("[useCoreUpdate] Failed to fetch data:", err);
    }
  };

  // Clear all stores
  const clearStores = () => {
    console.log("[useCoreUpdate] Clearing stores...");
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

    // Listen for engine-reloaded event (profile switch)
    const unlistenEngineReloaded = listen<void>("engine-reloaded", () => {
      console.log("[useCoreUpdate] Engine reloaded (profile switched)");
      // Clear stores first to remove old profile's data
      clearStores();
      // Then fetch new profile's data
      fetchAndSetData();
    });

    return () => {
      unlistenCoreUpdate.then((fn) => fn());
      unlistenEngineReloaded.then((fn) => fn());
    };
  }, [setConversations, setContacts, setDeviceId, sessionState]);
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
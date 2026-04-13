import { useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";

interface NotificationPayload {
  status: string;
  message: string;
}

interface MessageReceivedPayload {
  conversation_id: string;
  sender_user_id: string;
  sender_display_name?: string;
  message_preview?: string;
}

/**
 * Hook to handle OS native notifications.
 * Listens for notification events from the backend and displays them.
 */
export function useNotifications() {
  useEffect(() => {
    // Listen for user notification events from core
    const unlistenNotification = listen<NotificationPayload>("user-notification", async (event) => {
      const { status, message } = event.payload;

      // Determine notification type based on status
      const title = getNotificationTitle(status);

      // Request permission if not already granted
      let permissionGranted = await invoke<boolean>("check_notification_permission");

      if (!permissionGranted) {
        permissionGranted = await invoke<boolean>("request_notification_permission");
      }

      if (permissionGranted) {
        await invoke("show_notification", {
          title,
          body: message,
        });
      }
    });

    // Listen for new message events (for message notifications)
    const unlistenMessage = listen<MessageReceivedPayload>("message-received", async (event) => {
      const { sender_display_name, message_preview } = event.payload;

      // Check if app is in focus - if so, don't notify
      const focused = document.hasFocus();
      if (focused) return;

      let permissionGranted = await invoke<boolean>("check_notification_permission");

      if (!permissionGranted) {
        permissionGranted = await invoke<boolean>("request_notification_permission");
      }

      if (permissionGranted) {
        await invoke("show_notification", {
          title: sender_display_name || "New Message",
          body: message_preview || "You have a new message",
        });
      }
    });

    return () => {
      unlistenNotification.then((fn) => fn());
      unlistenMessage.then((fn) => fn());
    };
  }, []);
}

function getNotificationTitle(status: string): string {
  switch (status) {
    case "sync_in_progress":
      return "Syncing";
    case "identity_refresh_needed":
      return "Identity Update Required";
    case "conversation_needs_rebuild":
      return "Conversation Recovery Needed";
    case "attachment_upload_failed":
      return "Upload Failed";
    case "temporary_network_failure":
      return "Network Issue";
    case "message_queued_for_approval":
      return "Message Queued";
    case "message_rejected_by_policy":
      return "Message Rejected";
    default:
      return "TapChat";
  }
}

/**
 * Check and request notification permissions on startup.
 */
export async function ensureNotificationPermission(): Promise<boolean> {
  try {
    let granted = await invoke<boolean>("check_notification_permission");
    if (!granted) {
      granted = await invoke<boolean>("request_notification_permission");
    }
    return granted;
  } catch (err) {
    console.error("Failed to check notification permission:", err);
    return false;
  }
}
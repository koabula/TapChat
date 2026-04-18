import { useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

/**
 * Desktop notifications are emitted directly by the Tauri notification port.
 * Keep this hook as the shared lifecycle point for future desktop-only logic.
 */
export function useNotifications() {
  useEffect(() => {
    return () => undefined;
  }, []);
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
    console.error(`[Notifications] Failed to check notification permission: ${String(err)}`);
    return false;
  }
}

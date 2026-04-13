use tapchat_core::ffi_api::UserNotificationEffect;

/// Emit a user notification using the Tauri notification plugin.
pub fn emit_user_notification(notification: UserNotificationEffect) {
    // Use tauri_plugin_notification for OS-level notifications
    // The notification plugin is initialized in lib.rs

    // The notification has status and message fields
    let title = format_status_title(&notification.status);
    let body = &notification.message;

    emit_notification(&title, body);
}

fn format_status_title(status: &tapchat_core::ffi_api::SystemStatus) -> String {
    use tapchat_core::ffi_api::SystemStatus;
    match status {
        SystemStatus::TemporaryNetworkFailure => "Network Error".to_string(),
        SystemStatus::AttachmentUploadFailed => "Upload Failed".to_string(),
        SystemStatus::SyncInProgress => "Sync".to_string(),
        SystemStatus::IdentityRefreshNeeded => "Identity".to_string(),
        SystemStatus::ConversationNeedsRebuild => "Conversation".to_string(),
        SystemStatus::MessageQueuedForApproval => "Pending".to_string(),
        SystemStatus::MessageRejectedByPolicy => "Blocked".to_string(),
    }
}

fn emit_notification(title: &str, body: &str) {
    // Note: Tauri notification requires app handle context
    // In production, we'd pass the handle through NotificationManager pattern
    // For now, log the notification
    log::info!("Notification: {} - {}", title, body);

    // TODO: Use tauri_plugin_notification::NotificationBuilder
    // Example:
    // Notification::new(app_handle)
    //     .title(title)
    //     .body(body)
    //     .show()
}

/// Notification manager that holds app handle for proper OS notifications.
pub struct NotificationManager {
    // Store reference to emit notifications with app handle
}

impl NotificationManager {
    pub fn new() -> Self {
        Self {}
    }

    /// Show notification using Tauri plugin with app handle.
    pub fn show_notification(
        &self,
        app: &tauri::AppHandle,
        title: &str,
        body: &str,
    ) -> anyhow::Result<()> {
        use tauri_plugin_notification::NotificationExt;

        app.notification()
            .builder()
            .title(title)
            .body(body)
            .show()?;

        Ok(())
    }

    /// Show notification with custom icon.
    pub fn show_notification_with_icon(
        &self,
        app: &tauri::AppHandle,
        title: &str,
        body: &str,
        icon_path: &str,
    ) -> anyhow::Result<()> {
        use tauri_plugin_notification::NotificationExt;

        app.notification()
            .builder()
            .title(title)
            .body(body)
            .icon(icon_path)
            .show()?;

        Ok(())
    }
}

impl Default for NotificationManager {
    fn default() -> Self {
        Self::new()
    }
}
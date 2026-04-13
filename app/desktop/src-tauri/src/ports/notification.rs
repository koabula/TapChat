use std::sync::Arc;
use tauri::AppHandle;

use tapchat_core::ffi_api::UserNotificationEffect;

/// Notification manager that holds app handle for proper OS notifications.
pub struct NotificationManager {
    app_handle: Option<Arc<AppHandle>>,
}

impl NotificationManager {
    pub fn new() -> Self {
        Self { app_handle: None }
    }

    /// Set the app handle for emitting notifications.
    pub fn set_app_handle(&mut self, handle: Arc<AppHandle>) {
        self.app_handle = Some(handle);
    }

    /// Emit a user notification using the Tauri notification plugin.
    pub fn emit_user_notification(&self, notification: UserNotificationEffect) -> anyhow::Result<()> {
        let title = format_status_title(&notification.status);
        let body = &notification.message;

        self.show_notification(&title, body)
    }

    /// Show notification using Tauri plugin with app handle.
    pub fn show_notification(&self, title: &str, body: &str) -> anyhow::Result<()> {
        if let Some(app) = &self.app_handle {
            use tauri_plugin_notification::NotificationExt;

            app.notification()
                .builder()
                .title(title)
                .body(body)
                .show()?;
        } else {
            // Fallback to logging if no app handle
            log::info!("Notification (no handle): {} - {}", title, body);
        }

        Ok(())
    }

    /// Show notification with custom icon.
    pub fn show_notification_with_icon(&self, title: &str, body: &str, icon_path: &str) -> anyhow::Result<()> {
        if let Some(app) = &self.app_handle {
            use tauri_plugin_notification::NotificationExt;

            app.notification()
                .builder()
                .title(title)
                .body(body)
                .icon(icon_path)
                .show()?;
        } else {
            log::info!("Notification (no handle): {} - {}", title, body);
        }

        Ok(())
    }
}

impl Default for NotificationManager {
    fn default() -> Self {
        Self::new()
    }
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
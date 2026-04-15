use std::io::Write;

use tauri::Manager;
use tauri_plugin_shell::ShellExt;
use tauri_plugin_notification::NotificationExt;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

#[tauri::command]
#[allow(deprecated)] // TODO: migrate to tauri-plugin-opener
pub fn open_file(
    app: tauri::AppHandle,
    path: String,
) -> Result<(), String> {
    let shell = app.shell();

    shell
        .open(&path, None)
        .map_err(|e| e.to_string())?;

    Ok(())
}

#[tauri::command]
pub fn check_notification_permission(
    app: tauri::AppHandle,
) -> Result<bool, String> {
    let notification = app.notification();
    let state = notification
        .permission_state()
        .map_err(|e| e.to_string())?;
    Ok(state == tauri_plugin_notification::PermissionState::Granted)
}

#[tauri::command]
pub fn request_notification_permission(
    app: tauri::AppHandle,
) -> Result<bool, String> {
    let notification = app.notification();
    let state = notification
        .request_permission()
        .map_err(|e| e.to_string())?;
    Ok(state == tauri_plugin_notification::PermissionState::Granted)
}

#[tauri::command]
pub fn show_notification(
    app: tauri::AppHandle,
    title: String,
    body: String,
) -> Result<(), String> {
    let notification = app.notification();
    notification
        .builder()
        .title(title)
        .body(body)
        .show()
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Write a base64-encoded file to a temporary location.
/// Used for handling drag-drop from browser context where we can't get file paths.
#[tauri::command]
pub fn write_temp_file(
    app: tauri::AppHandle,
    file_name: String,
    content_base64: String,
) -> Result<String, String> {
    // Get temp directory
    let temp_dir = app.path().temp_dir()
        .map_err(|e| e.to_string())?;

    // Create tapchat temp subdir
    let tapchat_temp = temp_dir.join("tapchat");
    std::fs::create_dir_all(&tapchat_temp)
        .map_err(|e| e.to_string())?;

    // Generate unique filename
    let unique_name = format!("{}-{}",
        chrono::Utc::now().format("%Y%m%d%H%M%S"),
        sanitize_filename(&file_name)
    );
    let file_path = tapchat_temp.join(&unique_name);

    // Decode base64 and write
    let bytes = BASE64.decode(&content_base64)
        .map_err(|e| e.to_string())?;

    let mut file = std::fs::File::create(&file_path)
        .map_err(|e| e.to_string())?;
    file.write_all(&bytes)
        .map_err(|e| e.to_string())?;

    Ok(file_path.to_string_lossy().to_string())
}

fn sanitize_filename(name: &str) -> String {
    // Remove potentially dangerous characters
    name.chars()
        .filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
        .take(50) // Limit length
        .collect()
}
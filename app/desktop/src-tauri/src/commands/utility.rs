use std::io::Write;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::Serialize;
use tauri::Manager;
use tauri_plugin_notification::NotificationExt;
use tauri_plugin_shell::ShellExt;

/// File metadata for attachment preview
#[derive(Debug, Serialize)]
pub struct FileMetadata {
    pub size: u64,
    pub mime_type: String,
}

/// Get file metadata (size and mime type from extension).
#[tauri::command]
pub fn get_file_metadata(path: String) -> Result<FileMetadata, String> {
    let metadata =
        std::fs::metadata(&path).map_err(|e| format!("Failed to read file metadata: {}", e))?;

    let size = metadata.len();

    // Infer mime type from extension
    let mime_type = infer_mime_type(&path);

    Ok(FileMetadata { size, mime_type })
}

fn infer_mime_type(path: &str) -> String {
    let ext = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase());

    match ext.as_deref() {
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("png") => "image/png",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("bmp") => "image/bmp",
        Some("svg") => "image/svg+xml",
        Some("pdf") => "application/pdf",
        Some("doc") => "application/msword",
        Some("docx") => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        Some("xls") => "application/vnd.ms-excel",
        Some("xlsx") => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        Some("ppt") => "application/vnd.ms-powerpoint",
        Some("pptx") => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        Some("mp3") => "audio/mpeg",
        Some("wav") => "audio/wav",
        Some("ogg") => "audio/ogg",
        Some("mp4") => "video/mp4",
        Some("webm") => "video/webm",
        Some("mov") => "video/quicktime",
        Some("avi") => "video/x-msvideo",
        Some("zip") => "application/zip",
        Some("tar") => "application/x-tar",
        Some("gz") => "application/gzip",
        Some("rar") => "application/vnd.rar",
        Some("7z") => "application/x-7z-compressed",
        Some("txt") => "text/plain",
        Some("html") | Some("htm") => "text/html",
        Some("css") => "text/css",
        Some("js") => "application/javascript",
        Some("json") => "application/json",
        Some("xml") => "application/xml",
        Some("csv") => "text/csv",
        _ => "application/octet-stream",
    }
    .to_string()
}

#[tauri::command]
#[allow(deprecated)] // TODO: migrate to tauri-plugin-opener
pub fn open_file(app: tauri::AppHandle, path: String) -> Result<(), String> {
    let shell = app.shell();

    shell.open(&path, None).map_err(|e| e.to_string())?;

    Ok(())
}

#[tauri::command]
pub fn path_exists(path: String) -> bool {
    std::path::Path::new(&path).exists()
}

#[tauri::command]
pub fn check_notification_permission(app: tauri::AppHandle) -> Result<bool, String> {
    let notification = app.notification();
    let state = notification.permission_state().map_err(|e| e.to_string())?;
    Ok(state == tauri_plugin_notification::PermissionState::Granted)
}

#[tauri::command]
pub fn request_notification_permission(app: tauri::AppHandle) -> Result<bool, String> {
    let notification = app.notification();
    let state = notification
        .request_permission()
        .map_err(|e| e.to_string())?;
    Ok(state == tauri_plugin_notification::PermissionState::Granted)
}

#[tauri::command]
pub fn show_notification(app: tauri::AppHandle, title: String, body: String) -> Result<(), String> {
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
    let temp_dir = app.path().temp_dir().map_err(|e| e.to_string())?;

    // Create tapchat temp subdir
    let tapchat_temp = temp_dir.join("tapchat");
    std::fs::create_dir_all(&tapchat_temp).map_err(|e| e.to_string())?;

    // Generate unique filename
    let unique_name = format!(
        "{}-{}",
        chrono::Utc::now().format("%Y%m%d%H%M%S"),
        sanitize_filename(&file_name)
    );
    let file_path = tapchat_temp.join(&unique_name);

    // Decode base64 and write
    let bytes = BASE64.decode(&content_base64).map_err(|e| e.to_string())?;

    let mut file = std::fs::File::create(&file_path).map_err(|e| e.to_string())?;
    file.write_all(&bytes).map_err(|e| e.to_string())?;

    Ok(file_path.to_string_lossy().to_string())
}

/// Toggle debug mode for performance timing tests.
/// When enabled, [TIMETEST] tagged log entries are emitted at key instrumentation points.
#[tauri::command]
pub fn set_debug_mode(enabled: bool) {
    let was_enabled = crate::DEBUG_MODE.swap(enabled, std::sync::atomic::Ordering::Relaxed);
    if was_enabled != enabled {
        log::info!(
            "[TIMETEST] Debug mode {}",
            if enabled { "enabled" } else { "disabled" }
        );
    }
}

/// Get current debug mode state.
#[tauri::command]
pub fn get_debug_mode() -> bool {
    crate::DEBUG_MODE.load(std::sync::atomic::Ordering::Relaxed)
}

fn sanitize_filename(name: &str) -> String {
    // Remove potentially dangerous characters
    name.chars()
        .filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
        .take(50) // Limit length
        .collect()
}

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

#[derive(Debug, Serialize)]
pub struct AppMetadata {
    pub app_version: &'static str,
    pub core_version: &'static str,
    pub protocol_version: &'static str,
    pub git_sha: Option<&'static str>,
    pub git_tag: Option<&'static str>,
    pub update_endpoint_configured: bool,
}

/// Get build and protocol metadata for the Settings About panel.
#[tauri::command]
pub fn get_app_metadata() -> AppMetadata {
    let git_sha = option_env!("TAPCHAT_GIT_SHA").filter(|value| !value.is_empty());
    let git_tag = option_env!("TAPCHAT_GIT_TAG").filter(|value| !value.is_empty());
    let update_endpoint_configured =
        option_env!("TAPCHAT_UPDATER_ENDPOINT_CONFIGURED") == Some("true");

    AppMetadata {
        app_version: env!("CARGO_PKG_VERSION"),
        core_version: tapchat_core::CORE_VERSION,
        protocol_version: tapchat_core::model::CURRENT_MODEL_VERSION,
        git_sha,
        git_tag,
        update_endpoint_configured,
    }
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

#[tauri::command]
#[allow(deprecated)]
pub async fn open_containing_folder(app: tauri::AppHandle, path: String) -> Result<(), String> {
    let file = std::path::PathBuf::from(path);
    if !file.is_absolute() || !file.is_file() {
        return Err("Saved attachment path must be an existing absolute file".into());
    }
    if !app
        .state::<crate::state::AppState>()
        .saved_attachment_paths
        .read()
        .await
        .contains(&file)
    {
        return Err("Attachment was not saved during this app session".into());
    }
    let parent = file
        .parent()
        .filter(|parent| parent.is_dir())
        .ok_or_else(|| "Saved attachment folder is unavailable".to_string())?;
    app.shell()
        .open(parent.to_string_lossy().as_ref(), None)
        .map_err(|error| error.to_string())
}

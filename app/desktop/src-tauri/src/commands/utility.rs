use tauri_plugin_shell::ShellExt;
use tauri_plugin_notification::NotificationExt;

#[tauri::command]
pub fn open_file(
    app: tauri::AppHandle,
    path: String,
) -> Result<(), String> {
    let shell = app.shell();

    // Use the shell plugin to open the file with the system's default application
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

    // Check if notification permission is granted
    // PermissionState::Granted = allowed
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

    // Request permission - on desktop this typically returns true
    // On macOS, this may prompt the user
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
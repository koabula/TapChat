use tapchat_core::{CoreCommand, CoreOutput};
use tapchat_core::transport_contract::MessageRequestAction;

use crate::lifecycle::{CoreInput, drive_core_with_handle};

#[tauri::command]
pub async fn list_message_requests(
    app: tauri::AppHandle,
) -> Result<CoreOutput, String> {
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::ListMessageRequests),
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn act_on_message_request(
    app: tauri::AppHandle,
    request_id: String,
    action: String,
) -> Result<CoreOutput, String> {
    let action = match action.as_str() {
        "accept" => MessageRequestAction::Accept,
        "reject" => MessageRequestAction::Reject,
        _ => return Err("Invalid action: must be 'accept' or 'reject'".into()),
    };
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::ActOnMessageRequest { request_id, action }),
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_allowlist(
    app: tauri::AppHandle,
) -> Result<CoreOutput, String> {
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::ListAllowlist),
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn add_to_allowlist(
    app: tauri::AppHandle,
    user_id: String,
) -> Result<CoreOutput, String> {
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::AddAllowlistUser { user_id }),
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn remove_from_allowlist(
    app: tauri::AppHandle,
    user_id: String,
) -> Result<CoreOutput, String> {
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::RemoveAllowlistUser { user_id }),
    )
    .await
    .map_err(|e| e.to_string())
}

use tauri::State;
use base64::Engine;

use tapchat_core::{CoreCommand, CoreOutput};
use tapchat_core::ffi_api::AttachmentDescriptor;

use crate::lifecycle::{CoreInput, drive_core_with_handle};
use crate::state::AppState;

#[tauri::command]
pub async fn send_text(
    app: tauri::AppHandle,
    conversation_id: String,
    plaintext: String,
) -> Result<CoreOutput, String> {
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::SendTextMessage {
            conversation_id,
            plaintext,
        }),
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn send_attachment(
    app: tauri::AppHandle,
    conversation_id: String,
    file_path: String,
    mime_type: String,
    size_bytes: u64,
    file_name: Option<String>,
) -> Result<CoreOutput, String> {
    let descriptor = AttachmentDescriptor {
        attachment_id: file_path,
        mime_type,
        size_bytes,
        file_name,
    };
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::SendAttachmentMessage {
            conversation_id,
            attachment_descriptor: descriptor,
        }),
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn download_attachment(
    app: tauri::AppHandle,
    conversation_id: String,
    message_id: String,
    reference: String,
    destination: String,
) -> Result<CoreOutput, String> {
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::DownloadAttachment {
            conversation_id,
            message_id,
            reference,
            destination,
        }),
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_attachment_preview(
    app: tauri::AppHandle,
    conversation_id: String,
    message_id: String,
    reference: String,
) -> Result<Option<String>, String> {
    // For now, return a placeholder - actual implementation would:
    // 1. Check if attachment is an image
    // 2. Load from blob storage
    // 3. Resize to thumbnail size
    // 4. Return as base64

    // TODO: Implement actual preview loading via BlobIoPort
    // This requires the attachment to be downloaded first or cached

    // Placeholder: return None to show fallback icon
    Ok(None)
}

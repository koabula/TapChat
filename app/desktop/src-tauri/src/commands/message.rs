use tauri::{AppHandle, Manager, State};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use tapchat_core::{CoreCommand, CoreOutput};
use tapchat_core::ffi_api::AttachmentDescriptor;

use crate::lifecycle::{CoreInput, drive_core_with_handle};
use crate::state::AppState;

/// Result of sending a message, including plaintext for local display
#[derive(Debug, Clone, serde::Serialize)]
pub struct SendMessageResult {
    pub message_id: String,
    pub conversation_id: String,
    pub sender_device_id: String,
    pub plaintext: String,
    pub created_at: u64,
}

#[tauri::command]
pub async fn send_text(
    app: tauri::AppHandle,
    conversation_id: String,
    plaintext: String,
) -> Result<SendMessageResult, String> {
    let output = drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::SendTextMessage {
            conversation_id: conversation_id.clone(),
            plaintext: plaintext.clone(),
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    // Extract message_id from output
    let message_id = output
        .view_model
        .and_then(|vm| vm.messages.first().map(|m| m.message_id.clone()))
        .unwrap_or_default();

    // Get device_id for sender identification
    let state = app.state::<AppState>();
    let inner = state.inner.read().await;
    let snapshot = inner.engine.refresh_snapshot();
    let sender_device_id = snapshot.local_identity
        .as_ref()
        .map(|li| li.state.device_identity.device_id.clone())
        .unwrap_or_default();

    Ok(SendMessageResult {
        message_id,
        conversation_id,
        sender_device_id,
        plaintext,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
    })
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

/// Generate a thumbnail/preview for an image attachment.
/// Returns base64-encoded image data suitable for inline display.
#[tauri::command]
pub async fn get_attachment_preview(
    app: tauri::AppHandle,
    _conversation_id: String,
    _message_id: String,
    reference: String,
) -> Result<Option<String>, String> {
    let state = app.state::<AppState>();
    let inner = state.inner.read().await;

    // Get the attachments directory from persistence
    let attachments_dir = inner.ports.persistence.inbox_attachments_dir().await;

    // The reference is the attachment ID
    let file_path = attachments_dir
        .as_ref()
        .map(|dir| dir.join(&reference));

    drop(inner);

    // Check if directory and file exist
    let file_path = match file_path {
        Some(path) if path.exists() => path,
        _ => return Ok(None),
    };

    // Load and resize image
    generate_thumbnail(&file_path).await
        .map_err(|e| format!("Failed to generate thumbnail: {}", e))
}

/// Generate a thumbnail from an image file.
/// Returns base64-encoded JPEG data.
async fn generate_thumbnail(path: &std::path::Path) -> anyhow::Result<Option<String>> {
    use image::ImageReader;

    // Try to load the image
    let img = match ImageReader::open(path)?.decode() {
        Ok(img) => img,
        Err(_) => return Ok(None), // Not a valid image
    };

    // Resize to max 200x200 while maintaining aspect ratio
    let thumbnail = img.resize(
        200,
        200,
        image::imageops::FilterType::Lanczos3,
    );

    // Convert to JPEG and encode as base64
    let mut buffer = std::io::Cursor::new(Vec::new());
    thumbnail.write_to(&mut buffer, image::ImageFormat::Jpeg)?;

    let encoded = BASE64.encode(buffer.into_inner());
    Ok(Some(encoded))
}
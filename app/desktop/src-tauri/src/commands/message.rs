use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use sha2::{Digest, Sha256};
use tauri::Manager;

use tapchat_core::attachment_crypto::{decrypt_blob, AttachmentPayloadMetadata};
use tapchat_core::ffi_api::AttachmentDescriptor;
use tapchat_core::{CoreCommand, CoreOutput};

use crate::lifecycle::{drive_core_with_handle, CoreInput};
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
    let sender_device_id = snapshot
        .local_identity
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
    .map_err(|e| normalize_attachment_error(&e.to_string()))
}

#[tauri::command]
pub async fn download_attachment_to_default_path(
    app: tauri::AppHandle,
    conversation_id: String,
    message_id: String,
    reference: String,
    file_name: Option<String>,
    mime_type: Option<String>,
) -> Result<String, String> {
    ensure_attachment_metadata(&app, &conversation_id, &message_id).await?;

    let attachments_dir = {
        let state = app.state::<AppState>();
        let inner = state.inner.read().await;
        inner.ports.persistence.attachments_dir().await
    }
    .ok_or_else(|| "no attachments directory configured".to_string())?;

    std::fs::create_dir_all(&attachments_dir)
        .map_err(|e| format!("failed to create attachments directory: {e}"))?;

    let destination = unique_download_path(
        &attachments_dir,
        file_name.as_deref(),
        mime_type.as_deref(),
        &reference,
    );

    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::DownloadAttachment {
            conversation_id,
            message_id,
            reference,
            destination: destination.to_string_lossy().to_string(),
        }),
    )
    .await
    .map_err(|e| normalize_attachment_error(&e.to_string()))?;

    if destination.exists() {
        Ok(destination.to_string_lossy().to_string())
    } else {
        Err("Attachment link expired".to_string())
    }
}

/// Download an attachment into the profile-local attachment cache.
///
/// The storage reference is normally a remote URL, so it must not be used as a
/// filesystem path. This command maps it to a deterministic local cache id.
#[tauri::command]
pub async fn cache_attachment(
    app: tauri::AppHandle,
    conversation_id: String,
    message_id: String,
    reference: String,
    _file_name: Option<String>,
) -> Result<String, String> {
    let cache = ensure_attachment_cached(&app, conversation_id, message_id, reference).await?;
    Ok(cache.to_string_lossy().to_string())
}

/// Generate a thumbnail/preview for an image attachment.
/// Returns base64-encoded image data suitable for inline display.
/// If the file is not cached locally, downloads it from Storage first.
#[tauri::command]
pub async fn get_attachment_preview(
    app: tauri::AppHandle,
    conversation_id: String,
    message_id: String,
    reference: String,
) -> Result<Option<String>, String> {
    let file_path = ensure_attachment_cached(&app, conversation_id, message_id, reference).await?;

    let thumbnail = generate_thumbnail(&file_path)
        .await
        .map_err(|e| {
            log::warn!(
                "get_attachment_preview: thumbnail generation failed for {}: {}",
                file_path.display(),
                e
            );
            format!("Failed to generate thumbnail: {}", e)
        })?;
    if thumbnail.is_some() {
        log::debug!(
            "get_attachment_preview: thumbnail generated for {}",
            file_path.display()
        );
    }
    Ok(thumbnail)
}

async fn ensure_attachment_cached(
    app: &tauri::AppHandle,
    conversation_id: String,
    message_id: String,
    reference: String,
) -> Result<std::path::PathBuf, String> {
    let attachments_dir = {
        let state = app.state::<AppState>();
        let inner = state.inner.read().await;
        inner.ports.persistence.attachments_dir().await
    }
    .ok_or_else(|| "no attachments directory configured".to_string())?;

    let (relative_path, file_path) = resolve_attachment_cache_path(&attachments_dir, &reference);
    if file_path.exists() {
        log::debug!("cache_attachment: cache hit at {}", file_path.display());
        return Ok(file_path);
    }

    if let Some((metadata, downloaded_blob_b64)) =
        attachment_metadata_and_downloaded_blob(app, &conversation_id, &message_id).await?
    {
        if materialize_cached_attachment_from_snapshot(&metadata, &downloaded_blob_b64, &file_path)?
        {
            log::info!(
                "cache_attachment: materialized cache from snapshot at {}",
                file_path.display()
            );
            return Ok(file_path);
        }
    }

    drive_core_with_handle(
        app,
        CoreInput::Command(CoreCommand::DownloadAttachment {
            conversation_id,
            message_id,
            reference,
            destination: relative_path.to_string_lossy().to_string(),
        }),
    )
    .await
    .map_err(|e| normalize_attachment_error(&e.to_string()))?;

    if file_path.exists() {
        log::info!(
            "cache_attachment: downloaded attachment to {}",
            file_path.display()
        );
        Ok(file_path)
    } else {
        Err("Attachment link expired".to_string())
    }
}

fn resolve_attachment_cache_path(
    attachments_dir: &std::path::Path,
    reference: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let relative_path = cache_relative_path(reference);
    let file_path = attachments_dir.join(&relative_path);
    (relative_path, file_path)
}

fn cache_relative_path(reference: &str) -> std::path::PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(reference.as_bytes());
    let digest = hasher.finalize();
    std::path::PathBuf::from("attachment-cache").join(format!("{digest:x}"))
}

async fn attachment_metadata_and_downloaded_blob(
    app: &tauri::AppHandle,
    conversation_id: &str,
    message_id: &str,
) -> Result<Option<(AttachmentPayloadMetadata, String)>, String> {
    let state = app.state::<AppState>();
    let inner = state.inner.read().await;
    let snapshot = inner.engine.refresh_snapshot();

    let message = snapshot
        .conversations
        .iter()
        .find(|conversation| conversation.conversation_id == conversation_id)
        .and_then(|conversation| {
            conversation
                .state
                .messages
                .iter()
                .find(|message| message.message_id == message_id)
        });
    let metadata = message
        .and_then(|message| message.plaintext.as_deref())
        .and_then(|plaintext| serde_json::from_str::<AttachmentPayloadMetadata>(plaintext).ok())
        .or_else(|| {
            snapshot
                .pending_outbox
                .iter()
                .find(|item| {
                    item.envelope.conversation_id == conversation_id
                        && item.envelope.message_id == message_id
                })
                .and_then(|item| item.plaintext_cache.as_deref())
                .and_then(|plaintext| {
                    serde_json::from_str::<AttachmentPayloadMetadata>(plaintext).ok()
                })
        });

    let Some(metadata) = metadata else {
        log::debug!("cache_attachment: metadata missing for message {message_id}");
        return Err("Attachment metadata missing".to_string());
    };

    Ok(message
        .and_then(|message| message.downloaded_blob_b64.clone())
        .map(|downloaded_blob_b64| (metadata, downloaded_blob_b64)))
}

fn materialize_cached_attachment_from_snapshot(
    metadata: &AttachmentPayloadMetadata,
    downloaded_blob_b64: &str,
    file_path: &std::path::Path,
) -> Result<bool, String> {
    if downloaded_blob_b64.is_empty() {
        return Ok(false);
    }
    let ciphertext = BASE64
        .decode(downloaded_blob_b64)
        .map_err(|_| "Attachment cache is corrupt".to_string())?;
    let plaintext = decrypt_blob(&ciphertext, &metadata.encryption)
        .map_err(|e| normalize_attachment_error(&e.to_string()))?;
    if let Some(parent) = file_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create attachment cache directory: {e}"))?;
    }
    std::fs::write(file_path, plaintext)
        .map_err(|e| format!("failed to write attachment cache: {e}"))?;
    Ok(true)
}

async fn ensure_attachment_metadata(
    app: &tauri::AppHandle,
    conversation_id: &str,
    message_id: &str,
) -> Result<(), String> {
    let state = app.state::<AppState>();
    let inner = state.inner.read().await;
    let snapshot = inner.engine.refresh_snapshot();
    let has_metadata = snapshot
        .conversations
        .iter()
        .find(|conversation| conversation.conversation_id == conversation_id)
        .and_then(|conversation| {
            conversation
                .state
                .messages
                .iter()
                .find(|message| message.message_id == message_id)
        })
        .and_then(|message| message.plaintext.as_deref())
        .is_some_and(is_attachment_metadata)
        || snapshot
            .pending_outbox
            .iter()
            .find(|item| {
                item.envelope.conversation_id == conversation_id
                    && item.envelope.message_id == message_id
            })
            .and_then(|item| item.plaintext_cache.as_deref())
            .is_some_and(is_attachment_metadata);

    if has_metadata {
        Ok(())
    } else {
        Err("Attachment metadata missing".to_string())
    }
}

fn is_attachment_metadata(plaintext: &str) -> bool {
    serde_json::from_str::<AttachmentPayloadMetadata>(plaintext).is_ok()
}

fn normalize_attachment_error(error: &str) -> String {
    let normalized = error.to_ascii_lowercase();
    if normalized.contains("capability_expired")
        || normalized.contains("sharing token expired")
        || normalized.contains("http 403")
        || normalized.contains("link may have expired")
    {
        "Attachment link expired".to_string()
    } else if normalized.contains("metadata is missing")
        || normalized.contains("attachment metadata missing")
    {
        "Attachment metadata missing".to_string()
    } else {
        error.to_string()
    }
}

fn unique_download_path(
    attachments_dir: &std::path::Path,
    file_name: Option<&str>,
    mime_type: Option<&str>,
    reference: &str,
) -> std::path::PathBuf {
    let fallback_name = format!(
        "attachment{}",
        extension_from_mime(mime_type.unwrap_or_default())
    );
    let safe_name = sanitize_file_name(file_name.unwrap_or(&fallback_name));
    let candidate = attachments_dir.join(&safe_name);
    if !candidate.exists() {
        return candidate;
    }

    let short_hash = short_reference_hash(reference);
    let path = std::path::Path::new(&safe_name);
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("attachment");
    let extension = path.extension().and_then(|value| value.to_str());
    let hashed_name = match extension {
        Some(extension) if !extension.is_empty() => format!("{stem}-{short_hash}.{extension}"),
        _ => format!("{stem}-{short_hash}"),
    };
    attachments_dir.join(hashed_name)
}

fn short_reference_hash(reference: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(reference.as_bytes());
    let digest = hasher.finalize();
    format!("{digest:x}").chars().take(8).collect()
}

fn sanitize_file_name(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .map(|ch| match ch {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            ch if ch.is_control() => '_',
            ch => ch,
        })
        .collect();
    let trimmed = sanitized.trim().trim_matches('.');
    if trimmed.is_empty() {
        "attachment".to_string()
    } else {
        trimmed.chars().take(120).collect()
    }
}

fn extension_from_mime(mime_type: &str) -> &'static str {
    match mime_type {
        "image/jpeg" => ".jpg",
        "image/png" => ".png",
        "image/gif" => ".gif",
        "image/webp" => ".webp",
        "audio/mpeg" => ".mp3",
        "audio/wav" => ".wav",
        "video/mp4" => ".mp4",
        "application/pdf" => ".pdf",
        "text/plain" => ".txt",
        _ => "",
    }
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
    let thumbnail = img.resize(200, 200, image::imageops::FilterType::Lanczos3);

    // Convert to JPEG and encode as base64
    let mut buffer = std::io::Cursor::new(Vec::new());
    thumbnail.write_to(&mut buffer, image::ImageFormat::Jpeg)?;

    let encoded = BASE64.encode(buffer.into_inner());
    Ok(Some(encoded))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tapchat_core::attachment_crypto::encrypt_blob;

    #[test]
    fn cache_attachment_materializes_from_downloaded_blob_without_network() {
        let plaintext = b"cached attachment plaintext";
        let encrypted = encrypt_blob(plaintext).expect("encrypt attachment");
        let metadata = AttachmentPayloadMetadata {
            mime_type: "image/png".to_string(),
            size_bytes: plaintext.len() as u64,
            file_name: Some("image.png".to_string()),
            encryption: encrypted.metadata,
        };
        let downloaded_blob_b64 = BASE64.encode(encrypted.ciphertext);
        let temp_dir = std::env::temp_dir().join(format!(
            "tapchat-cache-test-{}",
            uuid::Uuid::new_v4()
        ));
        let file_path = temp_dir.join("attachment-cache").join("cached");

        let materialized = materialize_cached_attachment_from_snapshot(
            &metadata,
            &downloaded_blob_b64,
            &file_path,
        )
        .expect("materialize cache");

        assert!(materialized);
        assert_eq!(std::fs::read(&file_path).expect("read cache"), plaintext);
        let _ = std::fs::remove_dir_all(temp_dir);
    }
}

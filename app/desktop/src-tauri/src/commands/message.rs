use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use sha2::{Digest, Sha256};
use tauri::Manager;

use tapchat_core::attachment_crypto::{decrypt_blob, AttachmentPayloadMetadata};
use tapchat_core::ffi_api::AttachmentDescriptor;
use tapchat_core::{CoreCommand, CoreOutput};

const ATTACHMENT_CACHE_TTL_SECS: u64 = 30 * 24 * 60 * 60;
const ATTACHMENT_CACHE_MAX_BYTES: u64 = 512 * 1024 * 1024;

#[cfg(any(test, feature = "test-support"))]
use crate::lifecycle::drive_core_without_handle;
use crate::lifecycle::{
    drive_core_persist_then_defer_transport, drive_core_with_handle, CoreInput,
};
use crate::platform::log_sanitize::redact_id;
use crate::state::AppState;
use crate::timetest;

/// Result of sending a message, including plaintext for local display
#[derive(Debug, Clone, serde::Serialize)]
pub struct SendMessageResult {
    pub message_id: String,
    pub conversation_id: String,
    pub sender_device_id: String,
    pub plaintext: String,
    pub created_at: u64,
    pub delivery_state: String,
}

fn normalize_direct_send_error(error: &str) -> String {
    if error.contains("peer contact is missing") {
        return "Peer identity is missing for this chat. Accept the message request again or re-add the contact before sending.".into();
    }
    error.to_string()
}

#[tauri::command]
pub async fn send_text(
    app: tauri::AppHandle,
    conversation_id: String,
    plaintext: String,
) -> Result<SendMessageResult, String> {
    let send_start = std::time::Instant::now();
    let abs_start = crate::ts_ms();
    timetest!(
        "send_begin conversation_id={} len={} ts={}",
        conversation_id,
        plaintext.len(),
        abs_start
    );

    let output = drive_core_persist_then_defer_transport(
        &app,
        CoreInput::Command(CoreCommand::SendTextMessage {
            conversation_id: conversation_id.clone(),
            plaintext: plaintext.clone(),
        }),
    )
    .await
    .map_err(|e| normalize_direct_send_error(&e.to_string()))?;

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

    let elapsed_ms = send_start.elapsed().as_millis();
    timetest!(
        "send_done msg_id={} elapsed_ms={} ts={}",
        message_id,
        elapsed_ms,
        abs_start + elapsed_ms as u128
    );

    Ok(SendMessageResult {
        message_id,
        conversation_id,
        sender_device_id,
        plaintext,
        created_at: crate::ts_ms().min(u64::MAX as u128) as u64,
        delivery_state: "sending".into(),
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
    .map_err(|e| normalize_direct_send_error(&e.to_string()))
}

#[cfg(any(test, feature = "test-support"))]
pub async fn send_attachment_impl(
    state: &AppState,
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
    drive_core_without_handle(
        state,
        CoreInput::Command(CoreCommand::SendAttachmentMessage {
            conversation_id,
            attachment_descriptor: descriptor,
        }),
    )
    .await
    .map_err(|e| normalize_direct_send_error(&e.to_string()))
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

#[cfg(any(test, feature = "test-support"))]
pub async fn download_attachment_impl(
    state: &AppState,
    conversation_id: String,
    message_id: String,
    reference: String,
    destination: String,
) -> Result<CoreOutput, String> {
    drive_core_without_handle(
        state,
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
    let cached_original =
        ensure_attachment_cached(&app, conversation_id, message_id, reference).await?;
    let downloads = app
        .path()
        .download_dir()
        .map_err(|error| format!("failed to locate Downloads directory: {error}"))?;
    std::fs::create_dir_all(&downloads)
        .map_err(|error| format!("failed to create Downloads directory: {error}"))?;
    let requested_name = file_name.unwrap_or_else(|| {
        format!(
            "attachment{}",
            extension_from_mime(mime_type.as_deref().unwrap_or_default())
        )
    });
    let destination = unique_download_destination(&downloads, &requested_name);
    tokio::fs::copy(&cached_original, &destination)
        .await
        .map_err(|error| format!("failed to save attachment to Downloads: {error}"))?;
    Ok(destination.to_string_lossy().to_string())
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

    let thumbnail = generate_thumbnail(&file_path).await.map_err(|e| {
        log::warn!(
            "get_attachment_preview: thumbnail generation failed for {}: generation_failed",
            redact_id("attachment", &file_path.to_string_lossy())
        );
        format!("Failed to generate thumbnail: {}", e)
    })?;
    if thumbnail.is_some() {
        log::debug!(
            "get_attachment_preview: thumbnail generated for {}",
            redact_id("attachment", &file_path.to_string_lossy())
        );
    }
    Ok(thumbnail)
}

#[tauri::command]
pub async fn clear_attachment_cache(app: tauri::AppHandle) -> Result<(), String> {
    let attachments_dir = {
        let state = app.state::<AppState>();
        let persistence = {
            let ports = state.ports.lock().await;
            ports.persistence.clone()
        };
        persistence.attachments_dir().await
    }
    .ok_or_else(|| "no attachments directory configured".to_string())?;

    let cache_dir = attachments_dir.join("attachment-cache");
    if cache_dir.exists() {
        std::fs::remove_dir_all(&cache_dir)
            .map_err(|e| format!("failed to clear attachment cache: {e}"))?;
    }
    let preview_root = preview_temp_root(&attachments_dir);
    if preview_root.exists() {
        std::fs::remove_dir_all(&preview_root)
            .map_err(|e| format!("failed to clear attachment previews: {e}"))?;
    }

    let state = app.state::<AppState>();
    let inner = state.inner.read().await;
    let pm = inner.profile_manager.inner.read().await;
    if let Some(profile) = pm.active_profile.as_ref() {
        profile
            .clear_attachment_cache_entries()
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

async fn ensure_attachment_cached(
    app: &tauri::AppHandle,
    conversation_id: String,
    message_id: String,
    reference: String,
) -> Result<std::path::PathBuf, String> {
    let attachments_dir = {
        let state = app.state::<AppState>();
        let persistence = {
            let ports = state.ports.lock().await;
            ports.persistence.clone()
        };
        persistence.attachments_dir().await
    }
    .ok_or_else(|| "no attachments directory configured".to_string())?;

    cleanup_temp_attachment_previews(&attachments_dir);
    cleanup_encrypted_attachment_cache(app, &attachments_dir).await?;

    let cache_id = attachment_cache_id(&reference);
    let (relative_path, encrypted_path) =
        resolve_encrypted_attachment_cache_path(&attachments_dir, &cache_id);
    if encrypted_path.exists() {
        log::debug!(
            "cache_attachment: encrypted cache hit at {}",
            encrypted_path.display()
        );
        return materialize_preview_from_encrypted_cache(
            app,
            &attachments_dir,
            &cache_id,
            &encrypted_path,
            &conversation_id,
            &message_id,
        )
        .await;
    }

    if let Some((metadata, downloaded_blob_b64)) =
        attachment_metadata_and_downloaded_blob(app, &conversation_id, &message_id).await?
    {
        if materialize_encrypted_cache_from_snapshot(
            app,
            &metadata,
            &downloaded_blob_b64,
            &cache_id,
            &encrypted_path,
        )
        .await?
        {
            log::info!(
                "cache_attachment: materialized encrypted cache from snapshot at {}",
                encrypted_path.display()
            );
            return materialize_preview_from_encrypted_cache(
                app,
                &attachments_dir,
                &cache_id,
                &encrypted_path,
                &conversation_id,
                &message_id,
            )
            .await;
        }
    }

    drive_core_with_handle(
        app,
        CoreInput::Command(CoreCommand::DownloadAttachment {
            conversation_id: conversation_id.clone(),
            message_id: message_id.clone(),
            reference,
            destination: relative_path.to_string_lossy().to_string(),
        }),
    )
    .await
    .map_err(|e| normalize_attachment_error(&e.to_string()))?;

    let Some((metadata, downloaded_blob_b64)) =
        attachment_metadata_and_downloaded_blob(app, &conversation_id, &message_id).await?
    else {
        return Err("Attachment link expired".to_string());
    };
    if !materialize_encrypted_cache_from_snapshot(
        app,
        &metadata,
        &downloaded_blob_b64,
        &cache_id,
        &encrypted_path,
    )
    .await?
    {
        return Err("Attachment link expired".to_string());
    }
    log::info!(
        "cache_attachment: downloaded attachment to encrypted cache {}",
        encrypted_path.display()
    );
    materialize_preview_from_encrypted_cache(
        app,
        &attachments_dir,
        &cache_id,
        &encrypted_path,
        &conversation_id,
        &message_id,
    )
    .await
}

fn resolve_encrypted_attachment_cache_path(
    attachments_dir: &std::path::Path,
    cache_id: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let relative_path = encrypted_cache_relative_path(cache_id);
    let file_path = attachments_dir.join(&relative_path);
    (relative_path, file_path)
}

fn attachment_cache_id(reference: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(reference.as_bytes());
    let digest = hasher.finalize();
    format!("{digest:x}")
}

fn encrypted_cache_relative_path(cache_id: &str) -> std::path::PathBuf {
    std::path::PathBuf::from("attachment-cache").join(format!("{cache_id}.enc"))
}

async fn attachment_metadata_and_downloaded_blob(
    app: &tauri::AppHandle,
    conversation_id: &str,
    message_id: &str,
) -> Result<Option<(AttachmentPayloadMetadata, String)>, String> {
    let Some(metadata) =
        attachment_metadata_from_snapshot(app, conversation_id, message_id).await?
    else {
        log::debug!("cache_attachment: metadata missing for message {message_id}");
        return Err("Attachment metadata missing".to_string());
    };

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

    Ok(message
        .and_then(|message| message.downloaded_blob_b64.clone())
        .map(|downloaded_blob_b64| (metadata, downloaded_blob_b64)))
}

async fn attachment_metadata_from_snapshot(
    app: &tauri::AppHandle,
    conversation_id: &str,
    message_id: &str,
) -> Result<Option<AttachmentPayloadMetadata>, String> {
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
    Ok(metadata)
}

async fn materialize_encrypted_cache_from_snapshot(
    app: &tauri::AppHandle,
    metadata: &AttachmentPayloadMetadata,
    downloaded_blob_b64: &str,
    cache_id: &str,
    encrypted_path: &std::path::Path,
) -> Result<bool, String> {
    if downloaded_blob_b64.is_empty() {
        return Ok(false);
    }
    let ciphertext = BASE64
        .decode(downloaded_blob_b64)
        .map_err(|_| "Attachment cache is corrupt".to_string())?;
    let plaintext = decrypt_blob(&ciphertext, &metadata.encryption)
        .map_err(|e| normalize_attachment_error(&e.to_string()))?;
    let encrypted = encrypt_attachment_cache_bytes(app, cache_id, &plaintext).await?;
    if let Some(parent) = encrypted_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create attachment cache directory: {e}"))?;
    }
    write_atomic_sync(encrypted_path, &encrypted)
        .map_err(|e| format!("failed to write attachment cache: {e}"))?;
    remember_attachment_cache_entry(app, cache_id, encrypted_path, metadata).await?;
    Ok(true)
}

async fn materialize_preview_from_encrypted_cache(
    app: &tauri::AppHandle,
    attachments_dir: &std::path::Path,
    cache_id: &str,
    encrypted_path: &std::path::Path,
    conversation_id: &str,
    message_id: &str,
) -> Result<std::path::PathBuf, String> {
    let metadata = attachment_metadata_from_snapshot(app, conversation_id, message_id)
        .await?
        .ok_or_else(|| "Attachment metadata missing".to_string())?;
    let encrypted = std::fs::read(encrypted_path)
        .map_err(|e| format!("failed to read attachment cache: {e}"))?;
    let plaintext = decrypt_attachment_cache_bytes(app, cache_id, &encrypted).await?;
    let preview_path = preview_temp_path(attachments_dir, cache_id, &metadata);
    if let Some(parent) = preview_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create attachment preview directory: {e}"))?;
    }
    write_atomic_sync(&preview_path, &plaintext)
        .map_err(|e| format!("failed to write attachment preview: {e}"))?;
    Ok(preview_path)
}

async fn encrypt_attachment_cache_bytes(
    app: &tauri::AppHandle,
    cache_id: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let state = app.state::<AppState>();
    let inner = state.inner.read().await;
    let pm = inner.profile_manager.inner.read().await;
    let profile = pm
        .active_profile
        .as_ref()
        .ok_or_else(|| "No active profile".to_string())?;
    profile
        .encrypt_profile_document(&attachment_cache_document_kind(cache_id), plaintext)
        .map_err(|e| e.to_string())
}

async fn decrypt_attachment_cache_bytes(
    app: &tauri::AppHandle,
    cache_id: &str,
    encrypted: &[u8],
) -> Result<Vec<u8>, String> {
    let state = app.state::<AppState>();
    let inner = state.inner.read().await;
    let pm = inner.profile_manager.inner.read().await;
    let profile = pm
        .active_profile
        .as_ref()
        .ok_or_else(|| "No active profile".to_string())?;
    profile
        .decrypt_profile_document(&attachment_cache_document_kind(cache_id), encrypted)
        .map_err(|e| e.to_string())
}

async fn remember_attachment_cache_entry(
    app: &tauri::AppHandle,
    cache_id: &str,
    encrypted_path: &std::path::Path,
    metadata: &AttachmentPayloadMetadata,
) -> Result<(), String> {
    let state = app.state::<AppState>();
    let inner = state.inner.read().await;
    let pm = inner.profile_manager.inner.read().await;
    let profile = pm
        .active_profile
        .as_ref()
        .ok_or_else(|| "No active profile".to_string())?;
    profile
        .save_attachment_cache_entry(&tapchat_core::cli::profile::AttachmentCacheEntry {
            cache_id: cache_id.to_string(),
            relative_path: encrypted_cache_relative_path(cache_id),
            mime_type: Some(metadata.mime_type.clone()),
            size_bytes: Some(metadata.size_bytes),
            updated_at_ms: now_ms(),
        })
        .map_err(|e| e.to_string())?;
    if !encrypted_path.exists() {
        return Err("Attachment cache write did not complete".to_string());
    }
    Ok(())
}

fn attachment_cache_document_kind(cache_id: &str) -> String {
    format!("attachment-cache/{cache_id}")
}

fn preview_temp_path(
    attachments_dir: &std::path::Path,
    cache_id: &str,
    metadata: &AttachmentPayloadMetadata,
) -> std::path::PathBuf {
    preview_temp_root(attachments_dir).join(format!(
        "{}{}",
        cache_id,
        extension_from_mime(&metadata.mime_type)
    ))
}

fn preview_temp_root(attachments_dir: &std::path::Path) -> std::path::PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(attachments_dir.to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    let namespace = format!("{digest:x}").chars().take(16).collect::<String>();
    std::env::temp_dir()
        .join("tapchat")
        .join("attachment-previews")
        .join(namespace)
}

fn cleanup_temp_attachment_previews(attachments_dir: &std::path::Path) {
    const PREVIEW_TTL_SECS: u64 = 6 * 60 * 60;
    let root = preview_temp_root(attachments_dir);
    let Ok(entries) = std::fs::read_dir(&root) else {
        return;
    };
    let now = std::time::SystemTime::now();
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        let Ok(modified) = metadata.modified() else {
            continue;
        };
        if now
            .duration_since(modified)
            .map(|age| age.as_secs() > PREVIEW_TTL_SECS)
            .unwrap_or(false)
        {
            let _ = std::fs::remove_file(path);
        }
    }
}

async fn cleanup_encrypted_attachment_cache(
    app: &tauri::AppHandle,
    attachments_dir: &std::path::Path,
) -> Result<(), String> {
    let state = app.state::<AppState>();
    let inner = state.inner.read().await;
    let pm = inner.profile_manager.inner.read().await;
    let Some(profile) = pm.active_profile.as_ref() else {
        return Ok(());
    };
    let mut entries = profile
        .load_attachment_cache_entries()
        .map_err(|e| e.to_string())?;
    let now = now_ms();
    let ttl_ms = ATTACHMENT_CACHE_TTL_SECS.saturating_mul(1000);

    entries.retain(|entry| {
        if !is_safe_relative_path(&entry.relative_path) {
            let _ = profile.delete_attachment_cache_entry(&entry.cache_id);
            return false;
        }
        let path = attachments_dir.join(&entry.relative_path);
        let expired = now.saturating_sub(entry.updated_at_ms) > ttl_ms;
        if expired || !path.exists() {
            let _ = std::fs::remove_file(path);
            let _ = profile.delete_attachment_cache_entry(&entry.cache_id);
            return false;
        }
        true
    });

    entries.sort_by(|left, right| right.updated_at_ms.cmp(&left.updated_at_ms));
    let mut total = 0_u64;
    for entry in entries {
        total = total.saturating_add(entry.size_bytes.unwrap_or_default());
        if total <= ATTACHMENT_CACHE_MAX_BYTES {
            continue;
        }
        if is_safe_relative_path(&entry.relative_path) {
            let _ = std::fs::remove_file(attachments_dir.join(&entry.relative_path));
        }
        let _ = profile.delete_attachment_cache_entry(&entry.cache_id);
    }
    Ok(())
}

fn is_safe_relative_path(path: &std::path::Path) -> bool {
    !path.components().any(|component| {
        matches!(
            component,
            std::path::Component::Prefix(_)
                | std::path::Component::RootDir
                | std::path::Component::ParentDir
        )
    })
}

fn write_atomic_sync(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(tmp, path)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
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

    // This derivative is only used in the compact chat grid. Full-screen
    // viewing and saving use the original cached attachment.
    let thumbnail = img.resize(512, 512, image::imageops::FilterType::Lanczos3);

    // Convert to JPEG and encode as base64
    let mut buffer = std::io::Cursor::new(Vec::new());
    thumbnail.write_to(&mut buffer, image::ImageFormat::Jpeg)?;

    let encoded = BASE64.encode(buffer.into_inner());
    Ok(Some(encoded))
}

fn unique_download_destination(
    directory: &std::path::Path,
    requested_name: &str,
) -> std::path::PathBuf {
    let base_name = std::path::Path::new(requested_name)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("attachment");
    let sanitized = base_name
        .chars()
        .map(|character| {
            if character.is_control()
                || matches!(
                    character,
                    '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
                )
            {
                '_'
            } else {
                character
            }
        })
        .collect::<String>();
    let sanitized = sanitized.trim().trim_matches('.');
    let sanitized = if sanitized.is_empty() {
        "attachment"
    } else {
        sanitized
    };
    let initial = directory.join(sanitized);
    if !initial.exists() {
        return initial;
    }
    let path = std::path::Path::new(sanitized);
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("attachment");
    let extension = path.extension().and_then(|value| value.to_str());
    for suffix in 1_u32..10_000 {
        let candidate = match extension {
            Some(extension) => directory.join(format!("{stem} ({suffix}).{extension}")),
            None => directory.join(format!("{stem} ({suffix})")),
        };
        if !candidate.exists() {
            return candidate;
        }
    }
    directory.join(format!("{stem}-{}", uuid::Uuid::new_v4()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tapchat_core::attachment_crypto::encrypt_blob;
    use tapchat_core::cli::profile::{
        override_profile_registry_path_for_test, Profile, ProfileInitOptions,
    };

    #[test]
    fn download_destination_is_sanitized_and_never_overwrites() {
        let temp_dir =
            std::env::temp_dir().join(format!("tapchat-download-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).expect("create download test directory");
        let first = unique_download_destination(&temp_dir, "../photo:original.png");
        assert_eq!(first, temp_dir.join("photo_original.png"));
        std::fs::write(&first, b"existing").expect("write existing download");
        let second = unique_download_destination(&temp_dir, "photo:original.png");
        assert_eq!(second, temp_dir.join("photo_original (1).png"));
        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn encrypted_attachment_cache_round_trips_without_plaintext_at_rest() {
        let plaintext = b"cached attachment plaintext";
        let encrypted = encrypt_blob(plaintext).expect("encrypt attachment");
        let metadata = AttachmentPayloadMetadata {
            mime_type: "image/png".to_string(),
            size_bytes: plaintext.len() as u64,
            file_name: Some("image.png".to_string()),
            encryption: encrypted.metadata,
            download_grant: None,
        };
        let downloaded_blob_b64 = BASE64.encode(encrypted.ciphertext);
        let temp_dir =
            std::env::temp_dir().join(format!("tapchat-cache-test-{}", uuid::Uuid::new_v4()));
        let _registry_override =
            override_profile_registry_path_for_test(temp_dir.join("config").join("profiles.json"));
        let profile = Profile::init_with_options(
            "alice",
            temp_dir.join("profile"),
            ProfileInitOptions {
                passphrase: Some("test-passphrase".into()),
                use_keychain: false,
            },
        )
        .expect("init profile");
        let cache_id = "cache-test";
        let blob_ciphertext = BASE64
            .decode(downloaded_blob_b64)
            .expect("decode downloaded blob");
        let decrypted = decrypt_blob(&blob_ciphertext, &metadata.encryption).expect("decrypt blob");
        let encrypted_cache = profile
            .encrypt_profile_document(&attachment_cache_document_kind(cache_id), &decrypted)
            .expect("encrypt cache");
        let cache_path = temp_dir.join("attachment-cache").join("cached.enc");
        write_atomic_sync(&cache_path, &encrypted_cache).expect("write encrypted cache");

        let bytes = std::fs::read(&cache_path).expect("read cache");
        assert!(!bytes
            .windows(plaintext.len())
            .any(|window| window == plaintext));
        let round_trip = profile
            .decrypt_profile_document(&attachment_cache_document_kind(cache_id), &bytes)
            .expect("decrypt cache");
        assert_eq!(round_trip, plaintext);
        let _ = std::fs::remove_dir_all(temp_dir);
    }
}

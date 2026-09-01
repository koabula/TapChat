use futures_util::StreamExt;
use rand::Rng;
use sha2::{Digest, Sha256};
use tauri::{Emitter, Manager};
#[cfg(feature = "gui")]
use tauri_plugin_clipboard_manager::ClipboardExt;
#[cfg(feature = "gui")]
use tauri_plugin_dialog::DialogExt;
use tokio::io::AsyncWriteExt;

use tapchat_core::attachment_crypto::{
    AttachmentPayloadMetadata, CHUNKED_ATTACHMENT_CIPHER_ALGORITHM, EncryptedBlobDescriptor,
};
use tapchat_core::ffi_api::{AttachmentDescriptor, AttachmentVariantSource, SystemStatus};
use tapchat_core::{CoreCommand, CoreOutput};

const ATTACHMENT_CACHE_TTL_SECS: u64 = 30 * 24 * 60 * 60;
const ATTACHMENT_CACHE_MAX_BYTES: u64 = 512 * 1024 * 1024;
const ATTACHMENT_CACHE_GLOBAL_MAX_BYTES: u64 = 1024 * 1024 * 1024;
const ATTACHMENT_CACHE_MIN_FREE_BYTES: u64 = 1024 * 1024 * 1024;
const ATTACHMENT_MAX_BYTES: u64 = 25 * 1024 * 1024;
const IMAGE_PREVIEW_INITIAL_EDGE: u32 = 1280;
const IMAGE_PREVIEW_MIN_EDGE: u32 = 512;
const IMAGE_PREVIEW_INITIAL_QUALITY: f32 = 75.0;
const IMAGE_PREVIEW_MIN_QUALITY: f32 = 45.0;
const IMAGE_PREVIEW_MAX_BYTES: usize = 192 * 1024;

use super::conversation::MessageDeliveryState;
#[cfg(any(test, feature = "test-support"))]
use crate::lifecycle::drive_core_without_handle;
use crate::lifecycle::{
    CoreInput, drive_core_persist_then_defer_transport, drive_core_with_handle,
};
use crate::ports::media_cache::EncryptedCacheDestination;
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
    pub delivery_state: MessageDeliveryState,
}

struct PreparedImageAttachment {
    relative_path: String,
    size_bytes: u64,
    width: u32,
    height: u32,
    blur_hash: Option<String>,
    preview_bytes: std::sync::Arc<Vec<u8>>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StagedAttachmentOutput {
    pub handle: String,
    pub name: String,
    pub size: u64,
    pub mime_type: String,
    pub preview_url: Option<String>,
}

async fn stage_attachment_bytes(app: &tauri::AppHandle, bytes: &[u8]) -> Result<String, String> {
    let staging_id = uuid::Uuid::new_v4().to_string();
    let state = app.state::<AppState>();
    let (staging_dir, encrypted) = {
        let inner = state.inner.read().await;
        let pm = inner.profile_manager.inner.read().await;
        let profile = pm
            .active_profile
            .as_ref()
            .ok_or_else(|| "No active profile".to_string())?;
        let encrypted = profile
            .encrypt_profile_document(&format!("attachment-staging/{staging_id}"), &bytes)
            .map_err(|error| error.to_string())?;
        (
            profile.storage_paths().transfer_staging_dir.clone(),
            encrypted,
        )
    };
    let path = staging_dir.join(format!("{staging_id}.enc"));
    write_atomic_sync(&path, &encrypted)
        .map_err(|error| format!("failed to stage encrypted attachment: {error}"))?;
    Ok(format!("encrypted-staging:{staging_id}"))
}

async fn prepare_image_attachment(
    app: &tauri::AppHandle,
    source_bytes: std::sync::Arc<Vec<u8>>,
    mime_type: &str,
) -> Result<Option<PreparedImageAttachment>, String> {
    if !mime_type.starts_with("image/") {
        return Ok(None);
    }
    let state = app.state::<AppState>();
    let _decode_permit = state
        .media_decode_limit
        .acquire()
        .await
        .map_err(|_| "media manager stopped".to_string())?;
    let generated = tokio::task::spawn_blocking(move || generate_image_preview(&source_bytes))
        .await
        .map_err(|error| format!("image preview task failed: {error}"))??;
    let Some((preview, width, height, blur_hash)) = generated else {
        return Ok(None);
    };
    let staging_id = uuid::Uuid::new_v4().to_string();
    let (staging_dir, encrypted) = {
        let inner = state.inner.read().await;
        let pm = inner.profile_manager.inner.read().await;
        let profile = pm
            .active_profile
            .as_ref()
            .ok_or_else(|| "No active profile".to_string())?;
        let encrypted = profile
            .encrypt_profile_document(&format!("attachment-staging/{staging_id}"), &preview)
            .map_err(|error| error.to_string())?;
        (
            profile.storage_paths().transfer_staging_dir.clone(),
            encrypted,
        )
    };
    let path = staging_dir.join(format!("{staging_id}.enc"));
    write_atomic_sync(&path, &encrypted)
        .map_err(|error| format!("failed to stage encrypted image preview: {error}"))?;
    Ok(Some(PreparedImageAttachment {
        relative_path: format!("encrypted-staging:{staging_id}"),
        size_bytes: preview.len() as u64,
        width,
        height,
        blur_hash: Some(blur_hash),
        preview_bytes: std::sync::Arc::new(preview),
    }))
}

fn generate_image_preview(source: &[u8]) -> Result<Option<(Vec<u8>, u32, u32, String)>, String> {
    use image::GenericImageView;

    let image = match image::load_from_memory(source) {
        Ok(image) => image,
        Err(_) => return Ok(None),
    };
    let (original_width, original_height) = image.dimensions();
    let mut max_edge = IMAGE_PREVIEW_INITIAL_EDGE;
    let mut quality = IMAGE_PREVIEW_INITIAL_QUALITY;
    loop {
        let preview = image.resize(max_edge, max_edge, image::imageops::FilterType::Lanczos3);
        let rgba = preview.to_rgba8();
        let blur_hash = blurhash::encode(4, 3, rgba.width(), rgba.height(), rgba.as_raw())
            .map_err(|error| format!("failed to encode blurhash: {error}"))?;
        let encoded = webp::Encoder::from_rgba(rgba.as_raw(), rgba.width(), rgba.height())
            .encode(quality)
            .to_vec();
        if encoded.len() <= IMAGE_PREVIEW_MAX_BYTES {
            return Ok(Some((encoded, original_width, original_height, blur_hash)));
        }
        if quality > IMAGE_PREVIEW_MIN_QUALITY {
            quality -= 10.0;
        } else if max_edge > IMAGE_PREVIEW_MIN_EDGE {
            max_edge = ((max_edge as f32) * 0.8)
                .round()
                .max(IMAGE_PREVIEW_MIN_EDGE as f32) as u32;
            quality = IMAGE_PREVIEW_INITIAL_QUALITY;
        } else {
            return Ok(None);
        }
    }
}

fn normalize_direct_send_error(error: &str) -> String {
    if error.contains("peer contact is missing") {
        return "Peer identity is missing for this chat. Accept the message request again or re-add the contact before sending.".into();
    }
    error.to_string()
}

fn attachment_mime_type(file_name: &str) -> String {
    match std::path::Path::new(file_name)
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("png") => "image/png",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("pdf") => "application/pdf",
        Some("mp3") => "audio/mpeg",
        Some("mp4") => "video/mp4",
        Some("txt") => "text/plain",
        Some("zip") => "application/zip",
        _ => "application/octet-stream",
    }
    .into()
}

async fn validate_attachment_file_metadata(path: &std::path::Path) -> Result<(), String> {
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|error| format!("failed to inspect attachment: {error}"))?;
    if !metadata.is_file() {
        return Err("Attachment is not a regular file".into());
    }
    match metadata.len() {
        0 => Err("Attachment is empty".into()),
        size if size > ATTACHMENT_MAX_BYTES => Err("Attachment exceeds the 25 MiB limit".into()),
        _ => Ok(()),
    }
}

fn media_url(handle: &str) -> String {
    #[cfg(target_os = "windows")]
    return format!("http://tapchat-media.localhost/{handle}");
    #[cfg(not(target_os = "windows"))]
    return format!("tapchat-media://localhost/{handle}");
}

async fn register_staged_attachment(
    app: &tauri::AppHandle,
    bytes: Vec<u8>,
    file_name: String,
    mime_type: String,
) -> Result<StagedAttachmentOutput, String> {
    if bytes.is_empty() {
        return Err("Attachment is empty".into());
    }
    if bytes.len() as u64 > ATTACHMENT_MAX_BYTES {
        return Err("Attachment exceeds the 25 MiB limit".into());
    }
    cleanup_orphaned_staging(app).await;
    let state = app.state::<AppState>();
    let profile_path = state.inner.read().await.profile_path.clone();
    let profile_generation = state
        .profile_generation
        .load(std::sync::atomic::Ordering::SeqCst);
    let source_bytes = std::sync::Arc::new(bytes);
    let size_bytes = source_bytes.len() as u64;
    let prepared = prepare_image_attachment(app, source_bytes.clone(), &mime_type).await?;
    let original_source = stage_attachment_bytes(app, &source_bytes).await?;
    let descriptor = AttachmentDescriptor {
        attachment_id: original_source,
        mime_type: mime_type.clone(),
        size_bytes,
        file_name: Some(file_name.clone()),
        preview: prepared.as_ref().map(|prepared| AttachmentVariantSource {
            attachment_id: prepared.relative_path.clone(),
            mime_type: "image/webp".into(),
            size_bytes: prepared.size_bytes,
        }),
        width: prepared.as_ref().map(|prepared| prepared.width),
        height: prepared.as_ref().map(|prepared| prepared.height),
        blur_hash: prepared
            .as_ref()
            .and_then(|prepared| prepared.blur_hash.clone()),
    };
    let preview_handle = prepared.as_ref().map(|prepared| {
        let handle = uuid::Uuid::new_v4().to_string();
        (handle, prepared.preview_bytes.clone())
    });
    if let Some((handle, preview_bytes)) = &preview_handle {
        state.media_handles.write().await.insert(
            handle.clone(),
            crate::state::MediaHandle {
                source: crate::state::MediaHandleSource::InMemory {
                    bytes: preview_bytes.clone(),
                },
                mime_type: "image/webp".into(),
                profile_path: profile_path.clone(),
                profile_generation,
                expires_at_ms: now_ms().saturating_add(10 * 60 * 1000),
            },
        );
    }
    let handle = uuid::Uuid::new_v4().to_string();
    state.staged_attachments.lock().await.insert(
        handle.clone(),
        crate::state::StagedAttachment {
            descriptor,
            profile_path,
            profile_generation,
            preview_handle: preview_handle.as_ref().map(|(handle, _)| handle.clone()),
        },
    );
    Ok(StagedAttachmentOutput {
        handle,
        name: file_name,
        size: size_bytes,
        mime_type,
        preview_url: preview_handle.map(|(handle, _)| media_url(&handle)),
    })
}

#[tauri::command]
pub async fn stage_attachment(
    app: tauri::AppHandle,
    file_path: String,
) -> crate::errors::DesktopResult<StagedAttachmentOutput> {
    let path = std::path::PathBuf::from(&file_path);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("attachment")
        .to_string();
    let mime_type = attachment_mime_type(&file_name);
    validate_attachment_file_metadata(&path).await?;
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|error| format!("failed to read attachment: {error}"))?;
    Ok(register_staged_attachment(&app, bytes, file_name, mime_type).await?)
}

#[tauri::command]
#[cfg(feature = "gui")]
pub async fn stage_attachments_from_dialog(
    app: tauri::AppHandle,
) -> crate::errors::DesktopResult<Vec<StagedAttachmentOutput>> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_title("Select files to attach")
        .pick_files(move |paths| {
            let _ = sender.send(paths);
        });
    let paths = receiver
        .await
        .map_err(|_| "Attachment dialog closed unexpectedly".to_string())?
        .unwrap_or_default();
    let mut staged = Vec::with_capacity(paths.len());
    for path in paths {
        let path = path
            .into_path()
            .map_err(|_| "Selected attachment is not a local file".to_string())?;
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("attachment")
            .to_string();
        let mime_type = attachment_mime_type(&file_name);
        validate_attachment_file_metadata(&path).await?;
        let bytes = tokio::fs::read(&path)
            .await
            .map_err(|error| format!("failed to read attachment: {error}"))?;
        staged.push(register_staged_attachment(&app, bytes, file_name, mime_type).await?);
    }
    Ok(staged)
}

#[tauri::command]
#[cfg(feature = "gui")]
pub async fn stage_clipboard_image(
    app: tauri::AppHandle,
) -> crate::errors::DesktopResult<StagedAttachmentOutput> {
    let clipboard_app = app.clone();
    let bytes = tokio::task::spawn_blocking(move || {
        let image = clipboard_app
            .clipboard()
            .read_image()
            .map_err(|error| format!("Clipboard image is unavailable: {error}"))?;
        let rgba = image.rgba().to_vec();
        let buffer = image::RgbaImage::from_raw(image.width(), image.height(), rgba)
            .ok_or_else(|| "Clipboard image dimensions are invalid".to_string())?;
        let mut encoded = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgba8(buffer)
            .write_to(&mut encoded, image::ImageFormat::Png)
            .map_err(|error| format!("Failed to encode clipboard image: {error}"))?;
        Ok::<_, String>(encoded.into_inner())
    })
    .await
    .map_err(|error| format!("Clipboard image task failed: {error}"))??;
    let file_name = format!("clipboard-image-{}.png", now_ms());
    Ok(register_staged_attachment(&app, bytes, file_name, "image/png".into()).await?)
}

#[tauri::command]
pub async fn release_staged_attachment(
    state: tauri::State<'_, AppState>,
    handle: String,
) -> crate::errors::DesktopResult<()> {
    if let Some(staged) = state.staged_attachments.lock().await.remove(&handle) {
        if let Some(preview_handle) = staged.preview_handle {
            state.media_handles.write().await.remove(&preview_handle);
        }
        let staging_dir = {
            let inner = state.inner.read().await;
            let pm = inner.profile_manager.inner.read().await;
            pm.active_profile.as_ref().and_then(|profile| {
                (Some(profile.root().to_path_buf()) == staged.profile_path)
                    .then(|| profile.storage_paths().transfer_staging_dir.clone())
            })
        };
        if let Some(staging_dir) = staging_dir {
            remove_encrypted_staging_source(&staging_dir, &staged.descriptor.attachment_id).await?;
            if let Some(preview) = staged.descriptor.preview.as_ref() {
                remove_encrypted_staging_source(&staging_dir, &preview.attachment_id).await?;
            }
        }
    }
    Ok(())
}

async fn remove_encrypted_staging_source(
    staging_dir: &std::path::Path,
    attachment_id: &str,
) -> Result<(), String> {
    let Some(staging_id) = attachment_id
        .strip_prefix("encrypted-staging:")
        .filter(|value| !value.is_empty() && !value.contains('/') && !value.contains('\\'))
    else {
        return Ok(());
    };
    let path = staging_dir.join(format!("{staging_id}.enc"));
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("failed to remove staged attachment: {error}")),
    }
}

async fn cleanup_orphaned_staging(app: &tauri::AppHandle) {
    const ORPHAN_GRACE_SECS: u64 = 24 * 60 * 60;
    let state = app.state::<AppState>();
    let mut live_ids = std::collections::BTreeSet::new();
    {
        let staged = state.staged_attachments.lock().await;
        for attachment in staged.values() {
            for source in std::iter::once(attachment.descriptor.attachment_id.as_str()).chain(
                attachment
                    .descriptor
                    .preview
                    .as_ref()
                    .map(|preview| preview.attachment_id.as_str()),
            ) {
                if let Some(id) = source.strip_prefix("encrypted-staging:") {
                    live_ids.insert(id.to_string());
                }
            }
        }
    }
    let staging_dir = {
        let inner = state.inner.read().await;
        for transfer in inner.engine.refresh_snapshot().pending_blob_transfers {
            if let tapchat_core::persistence::PersistedPendingBlobTransfer::Upload {
                source, ..
            } = transfer
            {
                if let Some(id) = source.attachment_id.strip_prefix("encrypted-staging:") {
                    live_ids.insert(id.to_string());
                }
            }
        }
        let pm = inner.profile_manager.inner.read().await;
        pm.active_profile
            .as_ref()
            .map(|profile| profile.storage_paths().transfer_staging_dir.clone())
    };
    let Some(staging_dir) = staging_dir else {
        return;
    };
    let Ok(mut entries) = tokio::fs::read_dir(staging_dir).await else {
        return;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        let Some(staging_id) = path
            .file_stem()
            .and_then(|value| value.to_str())
            .filter(|_| path.extension().and_then(|value| value.to_str()) == Some("enc"))
        else {
            continue;
        };
        if live_ids.contains(staging_id) {
            continue;
        }
        let old_enough = entry
            .metadata()
            .await
            .ok()
            .and_then(|metadata| metadata.modified().ok())
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age.as_secs() >= ORPHAN_GRACE_SECS);
        if old_enough {
            let _ = tokio::fs::remove_file(path).await;
        }
    }
}

#[tauri::command]
pub async fn send_text(
    app: tauri::AppHandle,
    conversation_id: String,
    plaintext: String,
) -> crate::errors::DesktopResult<SendMessageResult> {
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
        .ok_or_else(|| "Core did not return a logical message identity".to_string())?;

    // Get device_id for sender identification
    let state = app.state::<AppState>();
    let inner = state.inner.read().await;
    let snapshot = inner.engine.refresh_snapshot();
    let sender_device_id = snapshot
        .local_identity
        .as_ref()
        .map(|li| li.state.device_identity.device_id.clone())
        .unwrap_or_default();
    let created_at = snapshot
        .pending_outbox
        .iter()
        .find(|item| item.app_message_id.as_deref() == Some(&message_id))
        .map(|item| item.envelope.created_at)
        .or_else(|| {
            snapshot
                .conversations
                .iter()
                .find(|conversation| conversation.conversation_id == conversation_id)
                .and_then(|conversation| {
                    conversation
                        .state
                        .messages
                        .iter()
                        .find(|message| message.app_message_id.as_deref() == Some(&message_id))
                        .map(|message| message.created_at)
                })
        })
        // The deferred transport worker can finish a message-request delivery
        // before this read acquires the state lock. In that case the durable
        // pending row has already been consumed, so retain the command-start
        // timestamp; identity reconciliation still uses the Core message id.
        .unwrap_or_else(|| abs_start.min(u64::MAX as u128) as u64);

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
        created_at,
        delivery_state: MessageDeliveryState::Sending,
    })
}

#[tauri::command]
pub async fn send_attachment(
    app: tauri::AppHandle,
    conversation_id: String,
    attachment_handle: String,
) -> crate::errors::DesktopResult<CoreOutput> {
    let state = app.state::<AppState>();
    let staged = state
        .staged_attachments
        .lock()
        .await
        .get(&attachment_handle)
        .cloned()
        .ok_or_else(|| "Attachment staging handle is invalid or expired".to_string())?;
    let current_profile = state.inner.read().await.profile_path.clone();
    let current_generation = state
        .profile_generation
        .load(std::sync::atomic::Ordering::SeqCst);
    if staged.profile_path != current_profile || staged.profile_generation != current_generation {
        return Err("Attachment belongs to a different profile".into());
    }
    let output = drive_core_persist_then_defer_transport(
        &app,
        CoreInput::Command(CoreCommand::SendAttachmentMessage {
            conversation_id,
            attachment_descriptor: staged.descriptor,
        }),
    )
    .await
    .map_err(|e| normalize_direct_send_error(&e.to_string()))?;
    state
        .staged_attachments
        .lock()
        .await
        .remove(&attachment_handle);
    if let Some(preview_handle) = staged.preview_handle {
        state.media_handles.write().await.remove(&preview_handle);
    }
    Ok(output)
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
        preview: None,
        width: None,
        height: None,
        blur_hash: None,
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
) -> crate::errors::DesktopResult<CoreOutput> {
    ensure_attachment_metadata(&app, &conversation_id, &message_id).await?;
    let destination_path = std::path::PathBuf::from(&destination);
    if !destination_path.is_absolute() {
        return Err("Attachment save destination must be an absolute path".into());
    }
    let reference =
        resolve_attachment_reference(&app, &conversation_id, &message_id, &reference).await?;
    let descriptor =
        attachment_descriptor_for_reference(&app, &conversation_id, &message_id, &reference)
            .await?;
    if descriptor.encryption.algorithm == CHUNKED_ATTACHMENT_CIPHER_ALGORITHM {
        let crypto_message_id =
            attachment_crypto_message_id(&app, &conversation_id, &message_id).await?;
        save_chunked_attachment_to_path(
            &app,
            &conversation_id,
            &crypto_message_id,
            &descriptor,
            &destination_path,
        )
        .await?;
        remember_saved_attachment_path(&app, destination_path).await;
        return Ok(CoreOutput::default());
    }
    let output = drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::DownloadAttachment {
            conversation_id,
            message_id,
            reference,
            destination,
        }),
    )
    .await
    .map_err(|e| normalize_attachment_error(&e.to_string()))?;
    if let Some(error) = attachment_download_failure(&output) {
        return Err(normalize_attachment_error(&error).into());
    }
    if destination_path.is_file() {
        remember_saved_attachment_path(&app, destination_path).await;
    }
    Ok(output)
}

#[cfg(any(test, feature = "test-support"))]
pub async fn download_attachment_impl(
    state: &AppState,
    conversation_id: String,
    message_id: String,
    reference: String,
    destination: String,
) -> Result<CoreOutput, String> {
    let output = drive_core_without_handle(
        state,
        CoreInput::Command(CoreCommand::DownloadAttachment {
            conversation_id,
            message_id,
            reference,
            destination,
        }),
    )
    .await
    .map_err(|e| normalize_attachment_error(&e.to_string()))?;
    if let Some(error) = attachment_download_failure(&output) {
        return Err(normalize_attachment_error(&error));
    }
    Ok(output)
}

#[tauri::command]
pub async fn download_attachment_to_default_path(
    app: tauri::AppHandle,
    conversation_id: String,
    message_id: String,
    reference: String,
    file_name: Option<String>,
    mime_type: Option<String>,
) -> crate::errors::DesktopResult<String> {
    ensure_attachment_metadata(&app, &conversation_id, &message_id).await?;
    let requested_variant = if reference == "preview" {
        "preview"
    } else {
        "original"
    };
    let descriptor =
        attachment_variant_from_snapshot(&app, &conversation_id, &message_id, requested_variant)
            .await?;
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
    if descriptor.encryption.algorithm == CHUNKED_ATTACHMENT_CIPHER_ALGORITHM {
        let crypto_message_id =
            attachment_crypto_message_id(&app, &conversation_id, &message_id).await?;
        save_chunked_attachment_to_path(
            &app,
            &conversation_id,
            &crypto_message_id,
            &descriptor,
            &destination,
        )
        .await?;
    } else {
        let plaintext =
            load_media_variant_bytes(&app, &conversation_id, &message_id, &descriptor).await?;
        write_atomic_sync(&destination, &plaintext)
            .map_err(|error| format!("failed to save attachment to Downloads: {error}"))?;
    }
    remember_saved_attachment_path(&app, destination.clone()).await;
    Ok(destination.to_string_lossy().to_string())
}

async fn remember_saved_attachment_path(app: &tauri::AppHandle, path: std::path::PathBuf) {
    app.state::<AppState>()
        .saved_attachment_paths
        .write()
        .await
        .insert(path);
}

async fn attachment_descriptor_for_reference(
    app: &tauri::AppHandle,
    conversation_id: &str,
    message_id: &str,
    reference: &str,
) -> Result<EncryptedBlobDescriptor, String> {
    let manifest = attachment_metadata_from_snapshot(app, conversation_id, message_id)
        .await?
        .ok_or_else(|| "Attachment metadata missing".to_string())?;
    let variant = if manifest.original.object_ref == reference {
        "original"
    } else if manifest
        .preview
        .as_ref()
        .is_some_and(|preview| preview.object_ref == reference)
    {
        "preview"
    } else {
        return Err("Attachment reference is not present in manifest".into());
    };
    attachment_variant_from_snapshot(app, conversation_id, message_id, variant).await
}

async fn attachment_crypto_message_id(
    app: &tauri::AppHandle,
    conversation_id: &str,
    message_id: &str,
) -> Result<String, String> {
    attachment_metadata_from_snapshot(app, conversation_id, message_id)
        .await?
        .map(|manifest| manifest.attachment_id)
        .ok_or_else(|| "Attachment metadata missing".to_string())
}

async fn resolve_attachment_reference(
    app: &tauri::AppHandle,
    conversation_id: &str,
    message_id: &str,
    reference: &str,
) -> Result<String, String> {
    if matches!(reference, "original" | "preview") {
        return Ok(
            attachment_variant_from_snapshot(app, conversation_id, message_id, reference)
                .await?
                .object_ref,
        );
    }
    Ok(reference.to_string())
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct OpenMediaResult {
    pub handle: String,
    pub url: String,
    pub expires_at: u64,
    pub served_variant: String,
    pub cached: bool,
    pub streaming: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AttachmentMediaState {
    pub preview_state: String,
    pub original_state: String,
    pub cached_bytes: u64,
    pub total_bytes: u64,
}

#[derive(Clone)]
struct PreviewPrefetchCandidate {
    conversation_id: String,
    message_id: String,
    created_at: u64,
}

fn conversation_allows_preview_prefetch(state: tapchat_core::model::ConversationState) -> bool {
    state == tapchat_core::model::ConversationState::Active
}

fn retain_recent_preview_candidates(
    mut candidates: Vec<PreviewPrefetchCandidate>,
) -> Vec<PreviewPrefetchCandidate> {
    candidates.sort_by(|left, right| right.created_at.cmp(&left.created_at));
    candidates.truncate(20);
    candidates
}

pub(crate) fn schedule_preview_prefetch(app: &tauri::AppHandle) {
    let state = app.state::<AppState>();
    if state
        .preview_prefetch_running
        .swap(true, std::sync::atomic::Ordering::SeqCst)
    {
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let state = app.state::<AppState>();
        let generation = state
            .profile_generation
            .load(std::sync::atomic::Ordering::SeqCst);
        if !matches!(
            state.inner.read().await.session,
            crate::state::SessionState::Active { .. }
        ) || !super::attachment_settings::preview_prefetch_enabled(&state).await
        {
            state
                .preview_prefetch_running
                .store(false, std::sync::atomic::Ordering::SeqCst);
            return;
        }
        let initial_delay = rand::thread_rng().gen_range(5_000_u64..=20_000);
        tokio::time::sleep(std::time::Duration::from_millis(initial_delay)).await;
        if state
            .profile_generation
            .load(std::sync::atomic::Ordering::SeqCst)
            != generation
            || !matches!(
                state.inner.read().await.session,
                crate::state::SessionState::Active { .. }
            )
            || !super::attachment_settings::preview_prefetch_enabled(&state).await
        {
            state
                .preview_prefetch_running
                .store(false, std::sync::atomic::Ordering::SeqCst);
            return;
        }
        let mut candidates = {
            let inner = state.inner.read().await;
            let snapshot = inner.engine.refresh_snapshot();
            snapshot
                .conversations
                .iter()
                .filter(|conversation| {
                    conversation_allows_preview_prefetch(conversation.state.conversation.state)
                })
                .flat_map(|conversation| {
                    conversation.state.messages.iter().filter_map(|message| {
                        let manifest = message.plaintext.as_deref().and_then(|plaintext| {
                            serde_json::from_str::<AttachmentPayloadMetadata>(plaintext).ok()
                        })?;
                        manifest.preview.as_ref()?;
                        Some(PreviewPrefetchCandidate {
                            conversation_id: conversation.conversation_id.clone(),
                            message_id: manifest.attachment_id,
                            created_at: message.created_at,
                        })
                    })
                })
                .collect::<Vec<_>>()
        };
        candidates = retain_recent_preview_candidates(candidates);
        let jobs = candidates.into_iter().map(|candidate| {
            let app = app.clone();
            async move {
                let state = app.state::<AppState>();
                if state
                    .profile_generation
                    .load(std::sync::atomic::Ordering::SeqCst)
                    != generation
                    || !super::attachment_settings::preview_prefetch_enabled(&state).await
                {
                    return;
                }
                let Ok(descriptor) = attachment_variant_from_snapshot(
                    &app,
                    &candidate.conversation_id,
                    &candidate.message_id,
                    "preview",
                )
                .await
                else {
                    return;
                };
                if complete_attachment_cache_exists(&app, &descriptor)
                    .await
                    .unwrap_or(false)
                {
                    return;
                }
                let jitter = rand::thread_rng().gen_range(250_u64..=750);
                tokio::time::sleep(std::time::Duration::from_millis(jitter)).await;
                if state
                    .profile_generation
                    .load(std::sync::atomic::Ordering::SeqCst)
                    != generation
                    || !super::attachment_settings::preview_prefetch_enabled(&state).await
                {
                    return;
                }
                let key = format!("{}:preview", descriptor.object_ref);
                let gate = {
                    let mut inflight = state.media_inflight.lock().await;
                    inflight
                        .entry(key.clone())
                        .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
                        .clone()
                };
                let _single_flight = gate.lock().await;
                if !complete_attachment_cache_exists(&app, &descriptor)
                    .await
                    .unwrap_or(false)
                {
                    let _ = load_media_variant_bytes(
                        &app,
                        &candidate.conversation_id,
                        &candidate.message_id,
                        &descriptor,
                    )
                    .await;
                }
                state.media_inflight.lock().await.remove(&key);
            }
        });
        let _: Vec<()> = futures_util::stream::iter(jobs)
            .buffer_unordered(2)
            .collect()
            .await;
        state
            .preview_prefetch_running
            .store(false, std::sync::atomic::Ordering::SeqCst);
    });
}

#[tauri::command]
pub async fn get_attachment_media_state(
    app: tauri::AppHandle,
    conversation_id: String,
    message_id: String,
) -> crate::errors::DesktopResult<AttachmentMediaState> {
    ensure_attachment_metadata(&app, &conversation_id, &message_id).await?;
    let manifest = attachment_metadata_from_snapshot(&app, &conversation_id, &message_id)
        .await?
        .ok_or_else(|| "Attachment metadata missing".to_string())?;
    let preview_state = match &manifest.preview {
        None => "unavailable",
        Some(preview) if complete_attachment_cache_exists(&app, preview).await? => "cached",
        Some(_) => "remote",
    }
    .to_string();
    let total_bytes = manifest.original.plaintext_size;
    let (original_state, cached_bytes) =
        if complete_attachment_cache_exists(&app, &manifest.original).await? {
            ("cached", total_bytes)
        } else if manifest.original.encryption.algorithm == CHUNKED_ATTACHMENT_CIPHER_ALGORITHM {
            let cached = chunked_cached_plaintext_bytes(&app, &manifest.original).await?;
            (
                if cached == total_bytes {
                    "cached"
                } else if cached > 0 {
                    "partial"
                } else {
                    "remote"
                },
                cached,
            )
        } else {
            ("remote", 0)
        };
    Ok(AttachmentMediaState {
        preview_state,
        original_state: original_state.to_string(),
        cached_bytes,
        total_bytes,
    })
}

/// Resolve an attachment variant entirely in Rust and expose it through a
/// short-lived opaque protocol handle. Neither object capabilities nor local
/// paths cross into the WebView.
#[tauri::command]
pub async fn open_media(
    app: tauri::AppHandle,
    conversation_id: String,
    message_id: String,
    variant: String,
) -> crate::errors::DesktopResult<OpenMediaResult> {
    ensure_attachment_metadata(&app, &conversation_id, &message_id).await?;
    let descriptor =
        attachment_variant_from_snapshot(&app, &conversation_id, &message_id, &variant).await;
    let pending_source = if descriptor.is_err() {
        pending_attachment_variant_source(&app, &conversation_id, &message_id, &variant).await?
    } else {
        None
    };
    if descriptor.is_err() && pending_source.is_none() {
        return Err(descriptor
            .err()
            .unwrap_or_else(|| "Attachment metadata missing".to_string())
            .into());
    }
    let state = app.state::<AppState>();
    let profile_before = state.inner.read().await.profile_path.clone();
    let generation_before = state
        .profile_generation
        .load(std::sync::atomic::Ordering::SeqCst);
    let key = descriptor
        .as_ref()
        .map(|descriptor| format!("{}:{}", descriptor.object_ref, variant))
        .unwrap_or_else(|_| format!("pending:{message_id}:{variant}"));
    let gate = {
        let mut inflight = state.media_inflight.lock().await;
        inflight
            .entry(key.clone())
            .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };
    let single_flight = gate.lock().await;
    let (source, mime_type, cached, streaming) = match descriptor {
        Ok(descriptor) => {
            let mime_type = descriptor.mime_type.clone();
            let was_cached = complete_attachment_cache_exists(&app, &descriptor).await?;
            if descriptor.encryption.algorithm == CHUNKED_ATTACHMENT_CIPHER_ALGORITHM && !was_cached
            {
                tapchat_core::attachment_crypto::validate_chunked_ciphertext_size(
                    &descriptor.encryption,
                    descriptor.plaintext_size,
                    descriptor.ciphertext_size,
                )
                .map_err(|error| normalize_attachment_error(&error.to_string()))?;
                let crypto_message_id =
                    attachment_crypto_message_id(&app, &conversation_id, &message_id).await?;
                let chunks_cached = chunked_cached_plaintext_bytes(&app, &descriptor).await?
                    == descriptor.plaintext_size;
                (
                    crate::state::MediaHandleSource::ChunkedVideo {
                        conversation_id: conversation_id.clone(),
                        message_id: crypto_message_id,
                        descriptor,
                    },
                    mime_type,
                    chunks_cached,
                    true,
                )
            } else {
                let bytes =
                    load_media_variant_bytes(&app, &conversation_id, &message_id, &descriptor)
                        .await?;
                (
                    crate::state::MediaHandleSource::InMemory {
                        bytes: std::sync::Arc::new(bytes),
                    },
                    mime_type,
                    was_cached,
                    false,
                )
            }
        }
        Err(_) => {
            let source = pending_source
                .ok_or_else(|| "Attachment local staging data is unavailable".to_string())?;
            let mime_type = source.mime_type.clone();
            let bytes = load_pending_attachment_bytes(&app, &source).await?;
            (
                crate::state::MediaHandleSource::InMemory {
                    bytes: std::sync::Arc::new(bytes),
                },
                mime_type,
                true,
                false,
            )
        }
    };
    if state.inner.read().await.profile_path != profile_before
        || state
            .profile_generation
            .load(std::sync::atomic::Ordering::SeqCst)
            != generation_before
    {
        return Err("Profile changed while loading media".into());
    }
    drop(single_flight);
    state.media_inflight.lock().await.remove(&key);
    let handle = uuid::Uuid::new_v4().to_string();
    let expires_at = now_ms().saturating_add(10 * 60 * 1000);
    state.media_handles.write().await.insert(
        handle.clone(),
        crate::state::MediaHandle {
            source,
            mime_type,
            profile_path: profile_before,
            profile_generation: generation_before,
            expires_at_ms: expires_at,
        },
    );
    let url = media_url(&handle);
    Ok(OpenMediaResult {
        handle,
        url,
        expires_at,
        served_variant: variant,
        cached,
        streaming,
    })
}

async fn pending_attachment_variant_source(
    app: &tauri::AppHandle,
    conversation_id: &str,
    message_id: &str,
    variant: &str,
) -> Result<Option<tapchat_core::ffi_api::AttachmentVariantSource>, String> {
    let requested = match variant {
        "original" => tapchat_core::attachment_crypto::AttachmentVariant::Original,
        "preview" => tapchat_core::attachment_crypto::AttachmentVariant::Preview,
        _ => return Err("Unsupported attachment variant".into()),
    };
    let state = app.state::<AppState>();
    let inner = state.inner.read().await;
    let snapshot = inner.engine.refresh_snapshot();
    Ok(snapshot
        .pending_blob_transfers
        .iter()
        .find_map(|transfer| match transfer {
            tapchat_core::persistence::PersistedPendingBlobTransfer::Upload {
                conversation_id: pending_conversation_id,
                message_id: pending_message_id,
                source,
                variant,
                ..
            } if pending_conversation_id == conversation_id
                && pending_message_id == message_id
                && *variant == requested =>
            {
                Some(source.clone())
            }
            _ => None,
        }))
}

async fn load_pending_attachment_bytes(
    app: &tauri::AppHandle,
    source: &tapchat_core::ffi_api::AttachmentVariantSource,
) -> Result<Vec<u8>, String> {
    let staging_id = source
        .attachment_id
        .strip_prefix("encrypted-staging:")
        .filter(|value| !value.is_empty() && !value.contains('/') && !value.contains('\\'))
        .ok_or_else(|| "Attachment local staging handle is invalid".to_string())?;
    let state = app.state::<AppState>();
    let staging_dir = {
        let inner = state.inner.read().await;
        let pm = inner.profile_manager.inner.read().await;
        pm.active_profile
            .as_ref()
            .map(|profile| profile.storage_paths().transfer_staging_dir.clone())
    }
    .ok_or_else(|| "No active profile".to_string())?;
    let encrypted_path = staging_dir.join(format!("{staging_id}.enc"));
    let encrypted = tokio::fs::read(&encrypted_path)
        .await
        .map_err(|_| "Attachment local staging data is unavailable".to_string())?;
    let plaintext = {
        let inner = state.inner.read().await;
        let pm = inner.profile_manager.inner.read().await;
        let profile = pm
            .active_profile
            .as_ref()
            .ok_or_else(|| "No active profile".to_string())?;
        profile
            .decrypt_profile_document(&format!("attachment-staging/{staging_id}"), &encrypted)
            .map_err(|_| "Attachment local staging data could not be decrypted".to_string())?
    };
    if plaintext.len() as u64 != source.size_bytes {
        return Err("Attachment local staging data failed integrity validation".into());
    }
    Ok(plaintext)
}

#[tauri::command]
pub async fn release_media(
    state: tauri::State<'_, AppState>,
    handle: String,
) -> crate::errors::DesktopResult<()> {
    state.media_handles.write().await.remove(&handle);
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PlaintextHttpRange {
    start: u64,
    end_exclusive: u64,
}

fn parse_single_http_range(
    header: Option<&str>,
    total_size: u64,
) -> Result<Option<PlaintextHttpRange>, ()> {
    let Some(header) = header else {
        return Ok(None);
    };
    let value = header.strip_prefix("bytes=").ok_or(())?;
    if value.contains(',') || total_size == 0 {
        return Err(());
    }
    let (start, end) = value.split_once('-').ok_or(())?;
    if start.is_empty() {
        let suffix = end.parse::<u64>().map_err(|_| ())?;
        if suffix == 0 {
            return Err(());
        }
        return Ok(Some(PlaintextHttpRange {
            start: total_size.saturating_sub(suffix.min(total_size)),
            end_exclusive: total_size,
        }));
    }
    let start = start.parse::<u64>().map_err(|_| ())?;
    if start >= total_size {
        return Err(());
    }
    let end_exclusive = if end.is_empty() {
        total_size
    } else {
        end.parse::<u64>()
            .map_err(|_| ())?
            .saturating_add(1)
            .min(total_size)
    };
    if start >= end_exclusive {
        return Err(());
    }
    Ok(Some(PlaintextHttpRange {
        start,
        end_exclusive,
    }))
}

fn media_http_response(
    status: http::StatusCode,
    mime_type: &str,
    body: Vec<u8>,
    total_size: u64,
    range: Option<PlaintextHttpRange>,
) -> http::Response<Vec<u8>> {
    let mut builder = http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, mime_type)
        .header(http::header::CACHE_CONTROL, "no-store")
        .header(http::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .header(http::header::ACCEPT_RANGES, "bytes")
        .header(http::header::CONTENT_LENGTH, body.len().to_string());
    if let Some(range) = range {
        builder = builder.header(
            http::header::CONTENT_RANGE,
            format!(
                "bytes {}-{}/{}",
                range.start,
                range.end_exclusive - 1,
                total_size
            ),
        );
    }
    builder
        .body(body)
        .unwrap_or_else(|_| http::Response::new(Vec::new()))
}

fn media_range_not_satisfiable(total_size: u64) -> http::Response<Vec<u8>> {
    http::Response::builder()
        .status(http::StatusCode::RANGE_NOT_SATISFIABLE)
        .header(http::header::CACHE_CONTROL, "no-store")
        .header(http::header::ACCEPT_RANGES, "bytes")
        .header(http::header::CONTENT_RANGE, format!("bytes */{total_size}"))
        .body(Vec::new())
        .unwrap_or_else(|_| http::Response::new(Vec::new()))
}

pub(crate) async fn media_protocol_response(
    app: &tauri::AppHandle,
    handle: &str,
    range_header: Option<&str>,
) -> http::Response<Vec<u8>> {
    let state = app.state::<AppState>();
    let profile_path = state.inner.read().await.profile_path.clone();
    let profile_generation = state
        .profile_generation
        .load(std::sync::atomic::Ordering::SeqCst);
    let media = state.media_handles.read().await.get(handle).cloned();
    let Some(media) = media.filter(|media| {
        media.expires_at_ms > now_ms()
            && media.profile_path == profile_path
            && media.profile_generation == profile_generation
    }) else {
        return http::Response::builder()
            .status(http::StatusCode::NOT_FOUND)
            .header(http::header::CACHE_CONTROL, "no-store")
            .body(Vec::new())
            .unwrap_or_else(|_| http::Response::new(Vec::new()));
    };
    let total_size = match &media.source {
        crate::state::MediaHandleSource::InMemory { bytes } => bytes.len() as u64,
        crate::state::MediaHandleSource::ChunkedVideo { descriptor, .. } => {
            descriptor.plaintext_size
        }
    };
    let range = match parse_single_http_range(range_header, total_size) {
        Ok(range) => range,
        Err(()) => return media_range_not_satisfiable(total_size),
    };
    let selected = range.unwrap_or(PlaintextHttpRange {
        start: 0,
        end_exclusive: total_size,
    });
    let body = match &media.source {
        crate::state::MediaHandleSource::InMemory { bytes } => {
            bytes[selected.start as usize..selected.end_exclusive as usize].to_vec()
        }
        crate::state::MediaHandleSource::ChunkedVideo {
            conversation_id,
            message_id,
            descriptor,
        } => match load_chunked_plaintext_range(
            app,
            conversation_id,
            message_id,
            descriptor,
            selected.start,
            selected.end_exclusive,
        )
        .await
        {
            Ok(body) => body,
            Err(error) => {
                log::warn!(
                    target: "tapchat_attachment",
                    "attachment range failed error_class={}",
                    attachment_error_class(&error)
                );
                return http::Response::builder()
                    .status(http::StatusCode::INTERNAL_SERVER_ERROR)
                    .header(http::header::CACHE_CONTROL, "no-store")
                    .body(Vec::new())
                    .unwrap_or_else(|_| http::Response::new(Vec::new()));
            }
        },
    };
    let status = if range.is_some() {
        http::StatusCode::PARTIAL_CONTENT
    } else {
        http::StatusCode::OK
    };
    media_http_response(status, &media.mime_type, body, total_size, range)
}

async fn attachment_variant_from_snapshot(
    app: &tauri::AppHandle,
    conversation_id: &str,
    message_id: &str,
    variant: &str,
) -> Result<tapchat_core::attachment_crypto::EncryptedBlobDescriptor, String> {
    let manifest = attachment_metadata_from_snapshot(app, conversation_id, message_id)
        .await?
        .ok_or_else(|| "Attachment metadata missing".to_string())?;
    let descriptor = match variant {
        "original" => Ok(manifest.original),
        "preview" => manifest
            .preview
            .ok_or_else(|| "Attachment preview is unavailable".to_string()),
        _ => Err("Unsupported attachment variant".into()),
    }?;
    let resolved = {
        let state = app.state::<AppState>();
        let inner = state.inner.read().await;
        inner.engine.resolve_attachment_descriptor(
            conversation_id,
            message_id,
            &descriptor.object_ref,
        )
    };
    match resolved {
        Ok(descriptor) => Ok(descriptor),
        Err(_error)
            if pending_attachment_variant_source(app, conversation_id, message_id, variant)
                .await?
                .is_some() =>
        {
            Ok(descriptor)
        }
        Err(error) => Err(normalize_attachment_error(&error.to_string())),
    }
}

async fn load_media_variant_bytes(
    app: &tauri::AppHandle,
    conversation_id: &str,
    message_id: &str,
    descriptor: &tapchat_core::attachment_crypto::EncryptedBlobDescriptor,
) -> Result<Vec<u8>, String> {
    let state = app.state::<AppState>();
    let profile_before = state.inner.read().await.profile_path.clone();
    let generation_before = state
        .profile_generation
        .load(std::sync::atomic::Ordering::SeqCst);
    let attachments_dir = {
        let ports = state.ports.lock().await;
        ports.persistence.attachment_cache_dir().await
    }
    .ok_or_else(|| "no attachments directory configured".to_string())?;
    cleanup_encrypted_attachment_cache(app, &attachments_dir).await?;
    ensure_attachment_cache_has_space(&attachments_dir)?;
    let cache_id = attachment_cache_id(descriptor);
    let cache_destination = EncryptedCacheDestination::from_cache_id(&cache_id)
        .map_err(|_| "invalid encrypted media cache destination".to_string())?;
    let relative_path = cache_destination.relative_path();
    let encrypted_path = attachments_dir.join(&relative_path);
    if !encrypted_path.exists() {
        let _permit = state
            .media_network_limit
            .acquire()
            .await
            .map_err(|_| "media manager stopped".to_string())?;
        let output = drive_core_with_handle(
            app,
            CoreInput::Command(CoreCommand::DownloadAttachment {
                conversation_id: conversation_id.to_string(),
                message_id: message_id.to_string(),
                reference: descriptor.object_ref.clone(),
                // This is a platform contract id, not an OS path. Keep it
                // canonical across Windows and Unix.
                destination: cache_destination.destination_id(),
            }),
        )
        .await
        .map_err(|error| {
            let error = error.to_string();
            log::warn!(
                target: "tapchat_attachment",
                "attachment_transfer phase=download_failed variant={} error_class={}",
                descriptor.variant.as_str(),
                attachment_error_class(&error)
            );
            normalize_attachment_error(&error)
        })?;
        if let Some(error) = attachment_download_failure(&output) {
            return Err(normalize_attachment_error(&error));
        }
    }
    if state.inner.read().await.profile_path != profile_before
        || state
            .profile_generation
            .load(std::sync::atomic::Ordering::SeqCst)
            != generation_before
    {
        return Err("Profile changed while loading media".into());
    }
    let encrypted = tokio::fs::read(&encrypted_path)
        .await
        .map_err(|error| format!("failed to read encrypted media cache: {error}"))?;
    let plaintext = decrypt_attachment_cache_bytes(app, &cache_id, &encrypted).await?;
    if plaintext.len() as u64 != descriptor.plaintext_size
        || tapchat_core::attachment_crypto::sha256_hex(&plaintext) != descriptor.digest_sha256
    {
        return Err("Attachment integrity verification failed".into());
    }
    remember_attachment_cache_entry(app, &cache_id, descriptor, encrypted.len() as u64).await?;
    Ok(plaintext)
}

#[tauri::command]
pub async fn clear_attachment_cache(app: tauri::AppHandle) -> crate::errors::DesktopResult<()> {
    let attachments_dir = {
        let state = app.state::<AppState>();
        let persistence = {
            let ports = state.ports.lock().await;
            ports.persistence.clone()
        };
        persistence.attachment_cache_dir().await
    }
    .ok_or_else(|| "no attachments directory configured".to_string())?;

    if attachments_dir.exists() {
        std::fs::remove_dir_all(&attachments_dir)
            .map_err(|e| format!("failed to clear attachment cache: {e}"))?;
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

fn attachment_cache_id(
    descriptor: &tapchat_core::attachment_crypto::EncryptedBlobDescriptor,
) -> String {
    tapchat_core::attachment_crypto::blob_cache_id(
        &descriptor.storage_origin,
        &descriptor.object_ref,
    )
}

async fn attachment_cache_dir(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    let state = app.state::<AppState>();
    let directory = {
        let ports = state.ports.lock().await;
        ports.persistence.attachment_cache_dir().await
    }
    .ok_or_else(|| "no attachments directory configured".to_string())?;
    Ok(directory)
}

async fn complete_attachment_cache_exists(
    app: &tauri::AppHandle,
    descriptor: &EncryptedBlobDescriptor,
) -> Result<bool, String> {
    let attachments_dir = attachment_cache_dir(app).await?;
    let destination = EncryptedCacheDestination::from_cache_id(&attachment_cache_id(descriptor))
        .map_err(|_| "invalid encrypted media cache destination".to_string())?;
    Ok(attachments_dir.join(destination.relative_path()).is_file())
}

fn chunk_cache_relative_path(
    descriptor: &EncryptedBlobDescriptor,
    index: u32,
) -> std::path::PathBuf {
    std::path::PathBuf::from("chunks")
        .join(attachment_cache_id(descriptor))
        .join(format!("{index}.chunk"))
}

fn chunk_cache_entry_id(descriptor: &EncryptedBlobDescriptor, index: u32) -> String {
    tapchat_core::attachment_crypto::sha256_hex(
        format!("{}\0{index}", attachment_cache_id(descriptor)).as_bytes(),
    )
}

async fn chunked_cached_plaintext_bytes(
    app: &tauri::AppHandle,
    descriptor: &EncryptedBlobDescriptor,
) -> Result<u64, String> {
    let attachments_dir = attachment_cache_dir(app).await?;
    let chunk_size = descriptor
        .encryption
        .chunk_size_bytes
        .ok_or_else(|| "Chunked attachment is missing its chunk size".to_string())?;
    let count = tapchat_core::attachment_crypto::attachment_chunk_count(
        descriptor.plaintext_size,
        chunk_size,
    )
    .map_err(|error| error.to_string())?;
    let mut cached = 0_u64;
    for index in 0..count {
        let range = tapchat_core::attachment_crypto::attachment_chunk_ciphertext_range(
            &descriptor.encryption,
            descriptor.plaintext_size,
            index,
        )
        .map_err(|error| error.to_string())?;
        let path = attachments_dir.join(chunk_cache_relative_path(descriptor, index));
        if path
            .metadata()
            .is_ok_and(|metadata| metadata.len() == range.end_exclusive - range.start)
        {
            cached = cached.saturating_add(
                range.end_exclusive
                    - range.start
                    - tapchat_core::attachment_crypto::ATTACHMENT_GCM_TAG_BYTES,
            );
        }
    }
    Ok(cached)
}

#[derive(Debug, Clone, serde::Serialize)]
struct AttachmentTransferProgressEvent {
    conversation_id: String,
    message_id: String,
    transferred_bytes: u64,
    total_bytes: u64,
    percent: u32,
    variant: String,
    status: String,
}

async fn remember_chunk_cache_entry(
    app: &tauri::AppHandle,
    descriptor: &EncryptedBlobDescriptor,
    index: u32,
    size: u64,
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
            cache_id: chunk_cache_entry_id(descriptor, index),
            relative_path: chunk_cache_relative_path(descriptor, index),
            mime_type: Some("application/octet-stream".into()),
            size_bytes: Some(size),
            updated_at_ms: now_ms(),
        })
        .map_err(|error| error.to_string())
}

async fn write_ciphertext_chunk(
    app: &tauri::AppHandle,
    descriptor: &EncryptedBlobDescriptor,
    index: u32,
    bytes: &[u8],
) -> Result<(), String> {
    let attachments_dir = attachment_cache_dir(app).await?;
    ensure_attachment_cache_has_space(&attachments_dir)?;
    let path = attachments_dir.join(chunk_cache_relative_path(descriptor, index));
    write_atomic_sync(&path, bytes)
        .map_err(|error| format!("failed to cache encrypted video chunk: {error}"))?;
    remember_chunk_cache_entry(app, descriptor, index, bytes.len() as u64).await
}

async fn cache_complete_ciphertext_blob(
    app: &tauri::AppHandle,
    descriptor: &EncryptedBlobDescriptor,
    bytes: &[u8],
) -> Result<(), String> {
    if bytes.len() as u64 != descriptor.ciphertext_size {
        return Err("Storage returned an invalid attachment size".into());
    }
    let count = tapchat_core::attachment_crypto::attachment_chunk_count(
        descriptor.plaintext_size,
        descriptor
            .encryption
            .chunk_size_bytes
            .ok_or_else(|| "Chunked attachment is missing its chunk size".to_string())?,
    )
    .map_err(|error| error.to_string())?;
    for index in 0..count {
        let range = tapchat_core::attachment_crypto::attachment_chunk_ciphertext_range(
            &descriptor.encryption,
            descriptor.plaintext_size,
            index,
        )
        .map_err(|error| error.to_string())?;
        write_ciphertext_chunk(
            app,
            descriptor,
            index,
            &bytes[range.start as usize..range.end_exclusive as usize],
        )
        .await?;
    }
    Ok(())
}

async fn load_ciphertext_chunk(
    app: &tauri::AppHandle,
    conversation_id: &str,
    message_id: &str,
    descriptor: &EncryptedBlobDescriptor,
    index: u32,
) -> Result<Vec<u8>, String> {
    let range = tapchat_core::attachment_crypto::attachment_chunk_ciphertext_range(
        &descriptor.encryption,
        descriptor.plaintext_size,
        index,
    )
    .map_err(|error| normalize_attachment_error(&error.to_string()))?;
    let expected_len = range.end_exclusive - range.start;
    let attachments_dir = attachment_cache_dir(app).await?;
    let path = attachments_dir.join(chunk_cache_relative_path(descriptor, index));
    if let Ok(bytes) = tokio::fs::read(&path).await {
        if bytes.len() as u64 == expected_len {
            remember_chunk_cache_entry(app, descriptor, index, expected_len).await?;
            return Ok(bytes);
        }
    }

    let state = app.state::<AppState>();
    let inflight_key = format!("chunk:{}:{index}", attachment_cache_id(descriptor));
    let gate = {
        let mut inflight = state.media_inflight.lock().await;
        inflight
            .entry(inflight_key.clone())
            .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };
    let _single_flight = gate.lock().await;
    if let Ok(bytes) = tokio::fs::read(&path).await {
        if bytes.len() as u64 == expected_len {
            return Ok(bytes);
        }
    }

    let generation = state
        .profile_generation
        .load(std::sync::atomic::Ordering::SeqCst);
    let _permit = state
        .media_network_limit
        .acquire()
        .await
        .map_err(|_| "media manager stopped".to_string())?;
    let target = format!(
        "{}/v1/storage/blob/{}",
        descriptor.storage_origin.trim_end_matches('/'),
        urlencoding::encode(&descriptor.object_ref)
    );
    let response = crate::platform::transport::build_desktop_http_client()
        .get(target)
        .header(
            reqwest::header::AUTHORIZATION,
            format!("TapChat-Blob {}", descriptor.read_capability),
        )
        .header(
            reqwest::header::RANGE,
            format!("bytes={}-{}", range.start, range.end_exclusive - 1),
        )
        .send()
        .await
        .map_err(|error| {
            normalize_attachment_error(&format!("Attachment download failed: {error}"))
        })?;
    let status = response.status();
    if status != reqwest::StatusCode::PARTIAL_CONTENT && status != reqwest::StatusCode::OK {
        return Err(normalize_attachment_error(&format!(
            "Attachment download failed with HTTP {}",
            status.as_u16()
        )));
    }
    if response
        .content_length()
        .is_some_and(|length| length > descriptor.ciphertext_size)
    {
        return Err("Storage returned an oversized attachment".into());
    }
    let mut received = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(next) = stream.next().await {
        let bytes = next.map_err(|error| format!("failed to read attachment stream: {error}"))?;
        received.extend_from_slice(&bytes);
        if received.len() as u64 > descriptor.ciphertext_size {
            return Err("Storage returned an oversized attachment".into());
        }
        let transferred = received.len() as u64;
        let total = if status == reqwest::StatusCode::PARTIAL_CONTENT {
            expected_len
        } else {
            descriptor.ciphertext_size
        };
        let _ = app.emit(
            "download-progress",
            AttachmentTransferProgressEvent {
                conversation_id: conversation_id.to_string(),
                message_id: message_id.to_string(),
                transferred_bytes: transferred.min(total),
                total_bytes: total,
                percent: ((transferred.min(total) * 100) / total.max(1)) as u32,
                variant: descriptor.variant.as_str().into(),
                status: "downloading".into(),
            },
        );
    }
    if state
        .profile_generation
        .load(std::sync::atomic::Ordering::SeqCst)
        != generation
    {
        return Err("Profile changed while loading media".into());
    }
    let chunk = if status == reqwest::StatusCode::PARTIAL_CONTENT {
        if received.len() as u64 != expected_len {
            return Err("Storage returned an incomplete attachment range".into());
        }
        write_ciphertext_chunk(app, descriptor, index, &received).await?;
        received
    } else {
        // Older storage Workers ignored Range. Accept a bounded full response,
        // split it locally once, and keep the deployment order backwards compatible.
        cache_complete_ciphertext_blob(app, descriptor, &received).await?;
        received[range.start as usize..range.end_exclusive as usize].to_vec()
    };
    state.media_inflight.lock().await.remove(&inflight_key);
    Ok(chunk)
}

async fn load_chunked_plaintext_range(
    app: &tauri::AppHandle,
    conversation_id: &str,
    message_id: &str,
    descriptor: &EncryptedBlobDescriptor,
    start: u64,
    end_exclusive: u64,
) -> Result<Vec<u8>, String> {
    let span = tapchat_core::attachment_crypto::plaintext_range_to_chunk_span(
        &descriptor.encryption,
        descriptor.plaintext_size,
        start,
        end_exclusive,
    )
    .map_err(|error| normalize_attachment_error(&error.to_string()))?;
    let chunk_size = descriptor.encryption.chunk_size_bytes.unwrap_or_default() as u64;
    let mut output = Vec::with_capacity((end_exclusive - start) as usize);
    for index in span.first_chunk..=span.last_chunk {
        let ciphertext =
            load_ciphertext_chunk(app, conversation_id, message_id, descriptor, index).await?;
        let plaintext = tapchat_core::attachment_crypto::decrypt_attachment_chunk(
            &ciphertext,
            &descriptor.encryption,
            message_id,
            descriptor.variant,
            descriptor.plaintext_size,
            index,
        )
        .map_err(|error| normalize_attachment_error(&error.to_string()))?;
        let chunk_start = index as u64 * chunk_size;
        let local_start = start.saturating_sub(chunk_start) as usize;
        let local_end =
            (end_exclusive.min(chunk_start + plaintext.len() as u64) - chunk_start) as usize;
        output.extend_from_slice(&plaintext[local_start..local_end]);
    }
    Ok(output)
}

async fn save_chunked_attachment_to_path(
    app: &tauri::AppHandle,
    conversation_id: &str,
    message_id: &str,
    descriptor: &EncryptedBlobDescriptor,
    destination: &std::path::Path,
) -> Result<(), String> {
    tapchat_core::attachment_crypto::validate_chunked_ciphertext_size(
        &descriptor.encryption,
        descriptor.plaintext_size,
        descriptor.ciphertext_size,
    )
    .map_err(|error| normalize_attachment_error(&error.to_string()))?;
    let parent = destination
        .parent()
        .ok_or_else(|| "Attachment save destination has no parent directory".to_string())?;
    tokio::fs::create_dir_all(parent)
        .await
        .map_err(|error| format!("failed to create attachment destination: {error}"))?;
    let temporary = parent.join(format!(".tapchat-{}.tmp", uuid::Uuid::new_v4()));
    let result = async {
        let mut file = tokio::fs::File::create(&temporary)
            .await
            .map_err(|error| format!("failed to create attachment temp file: {error}"))?;
        let chunk_size = descriptor
            .encryption
            .chunk_size_bytes
            .ok_or_else(|| "Chunked attachment is missing its chunk size".to_string())?;
        let count = tapchat_core::attachment_crypto::attachment_chunk_count(
            descriptor.plaintext_size,
            chunk_size,
        )
        .map_err(|error| error.to_string())?;
        let mut digest = Sha256::new();
        let mut written = 0_u64;
        for index in 0..count {
            let ciphertext =
                load_ciphertext_chunk(app, conversation_id, message_id, descriptor, index).await?;
            let plaintext = tapchat_core::attachment_crypto::decrypt_attachment_chunk(
                &ciphertext,
                &descriptor.encryption,
                message_id,
                descriptor.variant,
                descriptor.plaintext_size,
                index,
            )
            .map_err(|error| normalize_attachment_error(&error.to_string()))?;
            file.write_all(&plaintext)
                .await
                .map_err(|error| format!("failed to write attachment temp file: {error}"))?;
            digest.update(&plaintext);
            written = written.saturating_add(plaintext.len() as u64);
            let _ = app.emit(
                "download-progress",
                AttachmentTransferProgressEvent {
                    conversation_id: conversation_id.to_string(),
                    message_id: message_id.to_string(),
                    transferred_bytes: written,
                    total_bytes: descriptor.plaintext_size,
                    percent: ((written * 100) / descriptor.plaintext_size.max(1)) as u32,
                    variant: descriptor.variant.as_str().into(),
                    status: "saving".into(),
                },
            );
        }
        file.flush()
            .await
            .map_err(|error| format!("failed to flush attachment temp file: {error}"))?;
        file.sync_all()
            .await
            .map_err(|error| format!("failed to sync attachment temp file: {error}"))?;
        drop(file);
        let actual_digest = digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if written != descriptor.plaintext_size || actual_digest != descriptor.digest_sha256 {
            return Err("Attachment integrity verification failed".into());
        }
        tokio::fs::rename(&temporary, destination)
            .await
            .map_err(|error| format!("failed to finalize attachment save: {error}"))?;
        let _ = app.emit(
            "download-progress",
            AttachmentTransferProgressEvent {
                conversation_id: conversation_id.to_string(),
                message_id: message_id.to_string(),
                transferred_bytes: descriptor.plaintext_size,
                total_bytes: descriptor.plaintext_size,
                percent: 100,
                variant: descriptor.variant.as_str().into(),
                status: "complete".into(),
            },
        );
        Ok(())
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(&temporary).await;
    }
    result
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
            conversation.state.messages.iter().find(|message| {
                message.message_id == message_id
                    || message.app_message_id.as_deref() == Some(message_id)
            })
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
                        && (item.envelope.message_id == message_id
                            || item.app_message_id.as_deref() == Some(message_id))
                })
                .and_then(|item| item.plaintext_cache.as_deref())
                .and_then(|plaintext| {
                    serde_json::from_str::<AttachmentPayloadMetadata>(plaintext).ok()
                })
        });
    Ok(metadata)
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
    descriptor: &tapchat_core::attachment_crypto::EncryptedBlobDescriptor,
    encrypted_size: u64,
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
            relative_path: EncryptedCacheDestination::from_cache_id(cache_id)
                .map_err(|error| error.to_string())?
                .relative_path(),
            mime_type: Some(descriptor.mime_type.clone()),
            size_bytes: Some(encrypted_size),
            updated_at_ms: now_ms(),
        })
        .map_err(|error| error.to_string())
}

fn attachment_cache_document_kind(cache_id: &str) -> String {
    format!("attachment-cache/{cache_id}")
}

async fn cleanup_encrypted_attachment_cache(
    app: &tauri::AppHandle,
    attachments_dir: &std::path::Path,
) -> Result<(), String> {
    let state = app.state::<AppState>();
    let protected_cache_ids: std::collections::HashSet<String> = state
        .media_handles
        .read()
        .await
        .values()
        .filter_map(|handle| match &handle.source {
            crate::state::MediaHandleSource::ChunkedVideo { descriptor, .. } => {
                Some(attachment_cache_id(descriptor))
            }
            crate::state::MediaHandleSource::InMemory { .. } => None,
        })
        .collect();
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
    let global_cache_root = pm.storage_layout.attachments_cache_root.clone();

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
    let mut indexed_paths = std::collections::HashSet::new();
    for entry in &entries {
        total = total.saturating_add(entry.size_bytes.unwrap_or_default());
        let is_leased = protected_cache_ids
            .iter()
            .any(|cache_id| entry.relative_path.to_string_lossy().contains(cache_id));
        if total <= ATTACHMENT_CACHE_MAX_BYTES || is_leased {
            indexed_paths.insert(entry.relative_path.clone());
            continue;
        }
        if is_safe_relative_path(&entry.relative_path) {
            let _ = std::fs::remove_file(attachments_dir.join(&entry.relative_path));
        }
        let _ = profile.delete_attachment_cache_entry(&entry.cache_id);
    }

    // Reconcile the other direction: files without an index are cache
    // orphans. Keep a 24-hour crash-recovery grace period, while stale temp
    // files can be removed after one hour.
    for file in collect_cache_files(attachments_dir) {
        let Ok(relative) = file.strip_prefix(attachments_dir) else {
            continue;
        };
        if indexed_paths.contains(relative) {
            continue;
        }
        let age = std::fs::metadata(&file)
            .ok()
            .and_then(|metadata| metadata.modified().ok())
            .and_then(|modified| modified.elapsed().ok())
            .map(|age| age.as_secs())
            .unwrap_or_default();
        let is_temp = file.extension().and_then(|value| value.to_str()) == Some("tmp");
        let grace = if is_temp { 60 * 60 } else { 24 * 60 * 60 };
        if age >= grace
            && !protected_cache_ids
                .iter()
                .any(|cache_id| relative.to_string_lossy().contains(cache_id))
        {
            let _ = std::fs::remove_file(file);
        }
    }
    remove_empty_cache_dirs(attachments_dir);

    // Enforce the cross-profile cap using file modification time as the LRU
    // fallback. Other profiles reconcile their DB index on next activation.
    let mut global_files = collect_cache_files(&global_cache_root)
        .into_iter()
        .filter_map(|path| {
            let metadata = std::fs::metadata(&path).ok()?;
            let modified = metadata
                .modified()
                .ok()?
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            Some((modified, metadata.len(), path))
        })
        .collect::<Vec<_>>();
    let mut global_total = global_files
        .iter()
        .fold(0_u64, |sum, (_, size, _)| sum.saturating_add(*size));
    global_files.sort_by_key(|(modified, _, _)| *modified);
    for (_, size, path) in global_files {
        if global_total <= ATTACHMENT_CACHE_GLOBAL_MAX_BYTES {
            break;
        }
        if protected_cache_ids
            .iter()
            .any(|cache_id| path.to_string_lossy().contains(cache_id))
        {
            continue;
        }
        if std::fs::remove_file(&path).is_ok() {
            global_total = global_total.saturating_sub(size);
            if let Ok(relative) = path.strip_prefix(attachments_dir) {
                if let Some(entry) = entries.iter().find(|entry| entry.relative_path == relative) {
                    let _ = profile.delete_attachment_cache_entry(&entry.cache_id);
                }
            }
        }
    }
    remove_empty_cache_dirs(&global_cache_root);
    Ok(())
}

fn collect_cache_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return files;
    };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_file() {
            files.push(entry.path());
        } else if file_type.is_dir() {
            files.extend(collect_cache_files(&entry.path()));
        }
    }
    files
}

fn remove_empty_cache_dirs(root: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            remove_empty_cache_dirs(&entry.path());
            let _ = std::fs::remove_dir(entry.path());
        }
    }
}

pub(crate) fn ensure_attachment_cache_has_space(
    cache_root: &std::path::Path,
) -> Result<(), String> {
    std::fs::create_dir_all(cache_root)
        .map_err(|error| format!("failed to create attachment cache: {error}"))?;
    let free = fs2::available_space(cache_root)
        .map_err(|error| format!("failed to inspect free disk space: {error}"))?;
    if free < ATTACHMENT_CACHE_MIN_FREE_BYTES {
        return Err("Attachment cache is disabled because less than 1 GiB is available".into());
    }
    Ok(())
}

pub(crate) async fn run_attachment_maintenance(app: &tauri::AppHandle) -> Result<(), String> {
    cleanup_orphaned_staging(app).await;
    if let Ok(cache_dir) = attachment_cache_dir(app).await {
        cleanup_encrypted_attachment_cache(app, &cache_dir).await?;
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
    {
        let inner = state.inner.read().await;
        if snapshot_has_attachment_metadata(
            &inner.engine.refresh_snapshot(),
            conversation_id,
            message_id,
        ) {
            return Ok(());
        }
    }

    let stored = {
        let inner = state.inner.read().await;
        let pm = inner.profile_manager.inner.read().await;
        let profile = pm
            .active_profile
            .as_ref()
            .ok_or_else(|| "No active profile".to_string())?;
        profile
            .get_message(conversation_id, message_id)
            .map_err(|error| error.to_string())?
    };
    let Some(stored) = stored else {
        return Err("Attachment metadata missing".to_string());
    };
    if !stored
        .plaintext
        .as_deref()
        .is_some_and(is_attachment_metadata)
    {
        return Err("Attachment metadata missing".to_string());
    }

    let mut inner = state.inner.write().await;
    if snapshot_has_attachment_metadata(
        &inner.engine.refresh_snapshot(),
        conversation_id,
        message_id,
    ) {
        return Ok(());
    }
    inner
        .engine
        .hydrate_message_content(conversation_id, stored)
        .map_err(|error| normalize_attachment_error(&error.to_string()))?;
    Ok(())
}

fn snapshot_has_attachment_metadata(
    snapshot: &tapchat_core::persistence::CorePersistenceSnapshot,
    conversation_id: &str,
    message_id: &str,
) -> bool {
    snapshot
        .conversations
        .iter()
        .find(|conversation| conversation.conversation_id == conversation_id)
        .and_then(|conversation| {
            conversation.state.messages.iter().find(|message| {
                message.message_id == message_id
                    || message.app_message_id.as_deref() == Some(message_id)
            })
        })
        .and_then(|message| message.plaintext.as_deref())
        .is_some_and(is_attachment_metadata)
        || snapshot
            .pending_outbox
            .iter()
            .find(|item| {
                item.envelope.conversation_id == conversation_id
                    && (item.envelope.message_id == message_id
                        || item.app_message_id.as_deref() == Some(message_id))
            })
            .and_then(|item| item.plaintext_cache.as_deref())
            .is_some_and(is_attachment_metadata)
}

fn is_attachment_metadata(plaintext: &str) -> bool {
    serde_json::from_str::<AttachmentPayloadMetadata>(plaintext).is_ok()
}

fn attachment_download_failure(output: &CoreOutput) -> Option<String> {
    output.effects.iter().rev().find_map(|effect| match effect {
        tapchat_core::CoreEffect::EmitUserNotification { notification }
            if notification.status == SystemStatus::AttachmentDownloadFailed =>
        {
            Some(notification.message.clone())
        }
        _ => None,
    })
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
    } else if normalized.contains("blob_not_found") {
        "Attachment is unavailable in the sender's storage (blob_not_found)".to_string()
    } else if normalized.contains("invalid_capability") {
        "Attachment access was rejected (invalid_capability)".to_string()
    } else if normalized.contains("encrypted cache destination")
        || normalized.contains("encrypted media cache")
    {
        "Attachment cache is unavailable. Try again.".to_string()
    } else {
        error.to_string()
    }
}

fn attachment_error_class(error: &str) -> &'static str {
    let normalized = error.to_ascii_lowercase();
    if normalized.contains("encrypted cache destination")
        || normalized.contains("encrypted media cache")
    {
        "cache_destination"
    } else if normalized.contains("blob_not_found") {
        "blob_not_found"
    } else if normalized.contains("capability") || normalized.contains("http 403") {
        "authorization"
    } else if normalized.contains("integrity") || normalized.contains("decrypt") {
        "integrity"
    } else {
        "platform"
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
    use tapchat_core::cli::profile::{
        Profile, ProfileInitOptions, override_profile_registry_path_for_test,
    };

    #[test]
    fn terminal_blob_failure_is_returned_instead_of_becoming_a_cache_path_error() {
        let output = CoreOutput {
            effects: vec![tapchat_core::CoreEffect::EmitUserNotification {
                notification: tapchat_core::ffi_api::UserNotificationEffect {
                    status: SystemStatus::AttachmentDownloadFailed,
                    message: "blob_download:blob_not_found".into(),
                },
            }],
            ..CoreOutput::default()
        };
        let failure = attachment_download_failure(&output).expect("download failure");
        assert_eq!(
            normalize_attachment_error(&failure),
            "Attachment is unavailable in the sender's storage (blob_not_found)"
        );
    }

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
        let encrypted_cache = profile
            .encrypt_profile_document(&attachment_cache_document_kind(cache_id), plaintext)
            .expect("encrypt cache");
        let cache_path = temp_dir.join("attachment-cache").join("cached.enc");
        write_atomic_sync(&cache_path, &encrypted_cache).expect("write encrypted cache");

        let bytes = std::fs::read(&cache_path).expect("read cache");
        assert!(
            !bytes
                .windows(plaintext.len())
                .any(|window| window == plaintext)
        );
        let round_trip = profile
            .decrypt_profile_document(&attachment_cache_document_kind(cache_id), &bytes)
            .expect("decrypt cache");
        assert_eq!(round_trip, plaintext);
        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn image_preview_is_bounded_webp_and_original_is_untouched() {
        let temp_dir =
            std::env::temp_dir().join(format!("tapchat-preview-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).expect("create preview test directory");
        let original_path = temp_dir.join("original.png");
        let original =
            image::DynamicImage::ImageRgba8(image::RgbaImage::from_fn(1600, 1000, |x, y| {
                image::Rgba([(x % 251) as u8, (y % 241) as u8, ((x + y) % 239) as u8, 255])
            }));
        original.save(&original_path).expect("save original image");
        let before = std::fs::read(&original_path).expect("read original before preview");
        let (preview, width, height, blur_hash) = generate_image_preview(&before)
            .expect("generate preview")
            .expect("preview available");
        let after = std::fs::read(&original_path).expect("read original after preview");
        assert_eq!(before, after);
        assert_eq!((width, height), (1600, 1000));
        assert!(preview.len() <= IMAGE_PREVIEW_MAX_BYTES);
        assert_eq!(&preview[..4], b"RIFF");
        let decoded = image::load_from_memory(&preview).expect("decode preview");
        assert!(decoded.width().max(decoded.height()) <= IMAGE_PREVIEW_INITIAL_EDGE);
        assert!(decoded.width().max(decoded.height()) >= IMAGE_PREVIEW_MIN_EDGE);
        assert!(!blur_hash.is_empty());
        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn single_http_ranges_cover_closed_open_and_suffix_forms() {
        assert_eq!(parse_single_http_range(None, 100), Ok(None));
        assert_eq!(
            parse_single_http_range(Some("bytes=0-0"), 100),
            Ok(Some(PlaintextHttpRange {
                start: 0,
                end_exclusive: 1,
            }))
        );
        assert_eq!(
            parse_single_http_range(Some("bytes=50-"), 100),
            Ok(Some(PlaintextHttpRange {
                start: 50,
                end_exclusive: 100,
            }))
        );
        assert_eq!(
            parse_single_http_range(Some("bytes=-12"), 100),
            Ok(Some(PlaintextHttpRange {
                start: 88,
                end_exclusive: 100,
            }))
        );
        assert!(parse_single_http_range(Some("bytes=0-1,4-5"), 100).is_err());
        assert!(parse_single_http_range(Some("bytes=100-"), 100).is_err());
        assert!(parse_single_http_range(Some("items=0-1"), 100).is_err());
    }

    #[test]
    fn partial_media_response_has_plaintext_range_headers() {
        let range = PlaintextHttpRange {
            start: 10,
            end_exclusive: 20,
        };
        let response = media_http_response(
            http::StatusCode::PARTIAL_CONTENT,
            "video/mp4",
            vec![0_u8; 10],
            100,
            Some(range),
        );
        assert_eq!(response.status(), http::StatusCode::PARTIAL_CONTENT);
        assert_eq!(response.headers()[http::header::CONTENT_LENGTH], "10");
        assert_eq!(
            response.headers()[http::header::CONTENT_RANGE],
            "bytes 10-19/100"
        );
        assert_eq!(response.headers()[http::header::ACCEPT_RANGES], "bytes");
    }

    #[test]
    fn preview_prefetch_accepts_only_active_conversations_and_caps_recent_items() {
        assert!(conversation_allows_preview_prefetch(
            tapchat_core::model::ConversationState::Active
        ));
        assert!(!conversation_allows_preview_prefetch(
            tapchat_core::model::ConversationState::Archived
        ));
        assert!(!conversation_allows_preview_prefetch(
            tapchat_core::model::ConversationState::Closed
        ));
        let candidates = (0..25)
            .map(|index| PreviewPrefetchCandidate {
                conversation_id: "conversation:accepted".into(),
                message_id: format!("message:{index}"),
                created_at: index,
            })
            .collect();
        let selected = retain_recent_preview_candidates(candidates);
        assert_eq!(selected.len(), 20);
        assert_eq!(selected.first().map(|item| item.created_at), Some(24));
        assert_eq!(selected.last().map(|item| item.created_at), Some(5));
    }
}

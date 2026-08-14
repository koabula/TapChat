use tauri::Manager;
#[cfg(feature = "gui")]
use tauri_plugin_clipboard_manager::ClipboardExt;
#[cfg(feature = "gui")]
use tauri_plugin_dialog::DialogExt;

use tapchat_core::attachment_crypto::AttachmentPayloadMetadata;
use tapchat_core::ffi_api::{AttachmentDescriptor, AttachmentVariantSource, SystemStatus};
use tapchat_core::{CoreCommand, CoreOutput};

const ATTACHMENT_CACHE_TTL_SECS: u64 = 30 * 24 * 60 * 60;
const ATTACHMENT_CACHE_MAX_BYTES: u64 = 512 * 1024 * 1024;

use super::conversation::MessageDeliveryState;
#[cfg(any(test, feature = "test-support"))]
use crate::lifecycle::drive_core_without_handle;
use crate::lifecycle::{
    drive_core_persist_then_defer_transport, drive_core_with_handle, CoreInput,
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
    preview_bytes: Vec<u8>,
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
    let (attachments_dir, encrypted) = {
        let inner = state.inner.read().await;
        let pm = inner.profile_manager.inner.read().await;
        let profile = pm
            .active_profile
            .as_ref()
            .ok_or_else(|| "No active profile".to_string())?;
        let encrypted = profile
            .encrypt_profile_document(&format!("attachment-staging/{staging_id}"), &bytes)
            .map_err(|error| error.to_string())?;
        (profile.metadata().attachments_dir.clone(), encrypted)
    };
    let path = attachments_dir
        .join("attachment-staging")
        .join(format!("{staging_id}.enc"));
    write_atomic_sync(&path, &encrypted)
        .map_err(|error| format!("failed to stage encrypted attachment: {error}"))?;
    Ok(format!("encrypted-staging:{staging_id}"))
}

async fn prepare_image_attachment(
    app: &tauri::AppHandle,
    source_bytes: Vec<u8>,
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
    let relative = std::path::PathBuf::from("attachment-staging").join(format!("{staging_id}.enc"));
    let (attachments_dir, encrypted) = {
        let inner = state.inner.read().await;
        let pm = inner.profile_manager.inner.read().await;
        let profile = pm
            .active_profile
            .as_ref()
            .ok_or_else(|| "No active profile".to_string())?;
        let encrypted = profile
            .encrypt_profile_document(&format!("attachment-staging/{staging_id}"), &preview)
            .map_err(|error| error.to_string())?;
        (profile.metadata().attachments_dir.clone(), encrypted)
    };
    let path = attachments_dir.join(&relative);
    write_atomic_sync(&path, &encrypted)
        .map_err(|error| format!("failed to stage encrypted image preview: {error}"))?;
    Ok(Some(PreparedImageAttachment {
        relative_path: format!("encrypted-staging:{staging_id}"),
        size_bytes: preview.len() as u64,
        width,
        height,
        blur_hash: Some(blur_hash),
        preview_bytes: preview,
    }))
}

fn generate_image_preview(source: &[u8]) -> Result<Option<(Vec<u8>, u32, u32, String)>, String> {
    use image::GenericImageView;

    let image = match image::load_from_memory(source) {
        Ok(image) => image,
        Err(_) => return Ok(None),
    };
    let (original_width, original_height) = image.dimensions();
    let mut max_edge = 512_u32;
    let mut quality = 75.0_f32;
    loop {
        let preview = image.resize(max_edge, max_edge, image::imageops::FilterType::Lanczos3);
        let rgba = preview.to_rgba8();
        let blur_hash = blurhash::encode(4, 3, rgba.width(), rgba.height(), rgba.as_raw())
            .map_err(|error| format!("failed to encode blurhash: {error}"))?;
        let encoded = webp::Encoder::from_rgba(rgba.as_raw(), rgba.width(), rgba.height())
            .encode(quality)
            .to_vec();
        if encoded.len() <= 128 * 1024 || max_edge <= 160 {
            if encoded.len() > 128 * 1024 {
                return Ok(None);
            }
            return Ok(Some((encoded, original_width, original_height, blur_hash)));
        }
        if quality > 45.0 {
            quality -= 10.0;
        } else {
            max_edge = ((max_edge as f32) * 0.8).round().max(160.0) as u32;
            quality = 75.0;
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
    cleanup_orphaned_staging(app).await;
    let state = app.state::<AppState>();
    let profile_path = state.inner.read().await.profile_path.clone();
    let profile_generation = state
        .profile_generation
        .load(std::sync::atomic::Ordering::SeqCst);
    let size_bytes = bytes.len() as u64;
    let prepared = prepare_image_attachment(app, bytes.clone(), &mime_type).await?;
    let original_source = stage_attachment_bytes(app, &bytes).await?;
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
                bytes: std::sync::Arc::new(preview_bytes.clone()),
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
) -> Result<StagedAttachmentOutput, String> {
    let path = std::path::PathBuf::from(&file_path);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("attachment")
        .to_string();
    let mime_type = attachment_mime_type(&file_name);
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|error| format!("failed to read attachment: {error}"))?;
    register_staged_attachment(&app, bytes, file_name, mime_type).await
}

#[tauri::command]
#[cfg(feature = "gui")]
pub async fn stage_attachments_from_dialog(
    app: tauri::AppHandle,
) -> Result<Vec<StagedAttachmentOutput>, String> {
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
) -> Result<StagedAttachmentOutput, String> {
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
    register_staged_attachment(&app, bytes, file_name, "image/png".into()).await
}

#[tauri::command]
pub async fn release_staged_attachment(
    state: tauri::State<'_, AppState>,
    handle: String,
) -> Result<(), String> {
    if let Some(staged) = state.staged_attachments.lock().await.remove(&handle) {
        if let Some(preview_handle) = staged.preview_handle {
            state.media_handles.write().await.remove(&preview_handle);
        }
        let attachments_dir = {
            let inner = state.inner.read().await;
            let pm = inner.profile_manager.inner.read().await;
            pm.active_profile.as_ref().and_then(|profile| {
                (Some(profile.root().to_path_buf()) == staged.profile_path)
                    .then(|| profile.metadata().attachments_dir.clone())
            })
        };
        if let Some(attachments_dir) = attachments_dir {
            remove_encrypted_staging_source(&attachments_dir, &staged.descriptor.attachment_id)
                .await?;
            if let Some(preview) = staged.descriptor.preview.as_ref() {
                remove_encrypted_staging_source(&attachments_dir, &preview.attachment_id).await?;
            }
        }
    }
    Ok(())
}

async fn remove_encrypted_staging_source(
    attachments_dir: &std::path::Path,
    attachment_id: &str,
) -> Result<(), String> {
    let Some(staging_id) = attachment_id
        .strip_prefix("encrypted-staging:")
        .filter(|value| !value.is_empty() && !value.contains('/') && !value.contains('\\'))
    else {
        return Ok(());
    };
    let path = attachments_dir
        .join("attachment-staging")
        .join(format!("{staging_id}.enc"));
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
    let attachments_dir = {
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
            .map(|profile| profile.metadata().attachments_dir.clone())
    };
    let Some(staging_dir) = attachments_dir.map(|dir| dir.join("attachment-staging")) else {
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
) -> Result<CoreOutput, String> {
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
) -> Result<CoreOutput, String> {
    let reference =
        resolve_attachment_reference(&app, &conversation_id, &message_id, &reference).await?;
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
        return Err(normalize_attachment_error(&error));
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
) -> Result<String, String> {
    ensure_attachment_metadata(&app, &conversation_id, &message_id).await?;
    let requested_variant = if reference == "preview" {
        "preview"
    } else {
        "original"
    };
    let descriptor =
        attachment_variant_from_snapshot(&app, &conversation_id, &message_id, requested_variant)
            .await?;
    let plaintext =
        load_media_variant_bytes(&app, &conversation_id, &message_id, &descriptor).await?;
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
    write_atomic_sync(&destination, &plaintext)
        .map_err(|error| format!("failed to save attachment to Downloads: {error}"))?;
    Ok(destination.to_string_lossy().to_string())
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
) -> Result<OpenMediaResult, String> {
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
            .unwrap_or_else(|| "Attachment metadata missing".to_string()));
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
    let (bytes, mime_type) = match descriptor {
        Ok(descriptor) => {
            let mime_type = descriptor.mime_type.clone();
            let bytes =
                load_media_variant_bytes(&app, &conversation_id, &message_id, &descriptor).await?;
            (bytes, mime_type)
        }
        Err(_) => {
            let source = pending_source
                .ok_or_else(|| "Attachment local staging data is unavailable".to_string())?;
            let mime_type = source.mime_type.clone();
            let bytes = load_pending_attachment_bytes(&app, &source).await?;
            (bytes, mime_type)
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
            bytes: std::sync::Arc::new(bytes),
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
    let attachments_dir = {
        let inner = state.inner.read().await;
        let pm = inner.profile_manager.inner.read().await;
        pm.active_profile
            .as_ref()
            .map(|profile| profile.metadata().attachments_dir.clone())
    }
    .ok_or_else(|| "No active profile".to_string())?;
    let encrypted_path = attachments_dir
        .join("attachment-staging")
        .join(format!("{staging_id}.enc"));
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
) -> Result<(), String> {
    state.media_handles.write().await.remove(&handle);
    Ok(())
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
    match variant {
        "original" => Ok(manifest.original),
        "preview" => manifest
            .preview
            .ok_or_else(|| "Attachment preview is unavailable".to_string()),
        _ => Err("Unsupported attachment variant".into()),
    }
}

async fn load_media_variant_bytes(
    app: &tauri::AppHandle,
    conversation_id: &str,
    message_id: &str,
    descriptor: &tapchat_core::attachment_crypto::EncryptedBlobDescriptor,
) -> Result<Vec<u8>, String> {
    let state = app.state::<AppState>();
    let attachments_dir = {
        let ports = state.ports.lock().await;
        ports.persistence.attachments_dir().await
    }
    .ok_or_else(|| "no attachments directory configured".to_string())?;
    cleanup_encrypted_attachment_cache(app, &attachments_dir).await?;
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
        override_profile_registry_path_for_test, Profile, ProfileInitOptions,
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
        assert!(!bytes
            .windows(plaintext.len())
            .any(|window| window == plaintext));
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
            image::DynamicImage::ImageRgba8(image::RgbaImage::from_fn(960, 640, |x, y| {
                image::Rgba([(x % 251) as u8, (y % 241) as u8, ((x + y) % 239) as u8, 255])
            }));
        original.save(&original_path).expect("save original image");
        let before = std::fs::read(&original_path).expect("read original before preview");
        let (preview, width, height, blur_hash) = generate_image_preview(&before)
            .expect("generate preview")
            .expect("preview available");
        let after = std::fs::read(&original_path).expect("read original after preview");
        assert_eq!(before, after);
        assert_eq!((width, height), (960, 640));
        assert!(preview.len() <= 128 * 1024);
        assert_eq!(&preview[..4], b"RIFF");
        assert!(!blur_hash.is_empty());
        let _ = std::fs::remove_dir_all(temp_dir);
    }
}

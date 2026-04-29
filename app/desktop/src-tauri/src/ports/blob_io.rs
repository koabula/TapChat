use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use tauri::{AppHandle, Emitter};
use tokio::fs;

use tapchat_core::ffi_api::{
    CoreEvent, ReadAttachmentBytesEffect, WriteDownloadedAttachmentEffect,
};
use tapchat_core::transport_contract::{BlobDownloadRequest, BlobUploadRequest};

/// Progress event payload sent to frontend during uploads
#[derive(Debug, Clone, serde::Serialize)]
pub struct UploadProgressEvent {
    pub task_id: String,
    pub conversation_id: String,
    pub progress: u32,  // 0-100 percentage
    pub status: String, // "reading", "encrypting", "uploading", "complete", "failed"
}

/// Read attachment bytes from disk and return base64-encoded content.
pub async fn read_attachment_bytes(
    read: ReadAttachmentBytesEffect,
    attachments_dir: Option<PathBuf>,
) -> Result<Vec<CoreEvent>> {
    let dir = attachments_dir.context("no attachments directory configured")?;
    let file_path = dir.join(&read.attachment_id);

    match fs::read(&file_path).await {
        Ok(bytes) => {
            let encoded = BASE64.encode(&bytes);
            Ok(vec![CoreEvent::AttachmentBytesLoaded {
                task_id: read.task_id,
                plaintext_b64: encoded,
            }])
        }
        Err(e) => {
            log::error!("Failed to read attachment {}: {:?}", read.attachment_id, e);
            Ok(vec![CoreEvent::BlobTransferFailed {
                task_id: read.task_id,
                retryable: false,
                detail: Some(e.to_string()),
            }])
        }
    }
}

/// Upload blob to remote storage with progress tracking.
pub async fn upload_blob_with_progress(
    upload: BlobUploadRequest,
    app: Option<Arc<AppHandle>>,
    conversation_id: String,
) -> Result<Vec<CoreEvent>> {
    let client = reqwest::Client::new();
    let task_id = upload.task_id.clone();

    // Emit progress: starting upload
    if let Some(app_ref) = &app {
        let _ = app_ref.emit(
            "upload-progress",
            UploadProgressEvent {
                task_id: task_id.clone(),
                conversation_id: conversation_id.clone(),
                progress: 0,
                status: "uploading".to_string(),
            },
        );
    }

    // Decode base64 content
    let bytes = BASE64
        .decode(&upload.blob_ciphertext_b64)
        .context("decode base64 blob content")?;

    let mut request = client.put(&upload.upload_target);

    for (key, value) in &upload.upload_headers {
        request = request.header(key, value);
    }

    // Use body with progress tracking
    // Note: reqwest doesn't have built-in progress, so we chunk it manually
    // For now, emit progress at start and completion
    if let Some(app_ref) = &app {
        let _ = app_ref.emit(
            "upload-progress",
            UploadProgressEvent {
                task_id: task_id.clone(),
                conversation_id: conversation_id.clone(),
                progress: 10,
                status: "uploading".to_string(),
            },
        );
    }

    request = request.body(bytes);

    match request.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            if status >= 200 && status < 300 {
                // Emit progress: complete
                if let Some(app_ref) = &app {
                    let _ = app_ref.emit(
                        "upload-progress",
                        UploadProgressEvent {
                            task_id: task_id.clone(),
                            conversation_id: conversation_id.clone(),
                            progress: 100,
                            status: "complete".to_string(),
                        },
                    );
                }
                Ok(vec![CoreEvent::BlobUploaded {
                    task_id: upload.task_id,
                }])
            } else {
                let error_body = response.text().await.unwrap_or_default();
                log::error!("Blob upload failed: {} - {}", status, error_body);

                // Emit progress: failed
                if let Some(app_ref) = &app {
                    let _ = app_ref.emit(
                        "upload-progress",
                        UploadProgressEvent {
                            task_id: task_id.clone(),
                            conversation_id: conversation_id.clone(),
                            progress: 0,
                            status: "failed".to_string(),
                        },
                    );
                }

                Ok(vec![CoreEvent::BlobTransferFailed {
                    task_id: upload.task_id,
                    retryable: false,
                    detail: Some(format!("HTTP {}: {}", status, error_body)),
                }])
            }
        }
        Err(e) => {
            log::error!("Blob upload error: {:?}", e);
            let retryable = e.is_timeout() || e.is_connect();

            // Emit progress: failed
            if let Some(app_ref) = &app {
                let _ = app_ref.emit(
                    "upload-progress",
                    UploadProgressEvent {
                        task_id: task_id.clone(),
                        conversation_id,
                        progress: 0,
                        status: "failed".to_string(),
                    },
                );
            }

            Ok(vec![CoreEvent::BlobTransferFailed {
                task_id: upload.task_id,
                retryable,
                detail: Some(e.to_string()),
            }])
        }
    }
}

/// Upload blob without progress tracking (for cases where app handle isn't available).
#[allow(dead_code)]
pub async fn upload_blob(upload: BlobUploadRequest) -> Result<Vec<CoreEvent>> {
    upload_blob_with_progress(upload, None, String::new()).await
}

/// Download blob from remote storage (GET from download URL).
pub async fn download_blob(download: BlobDownloadRequest) -> Result<Vec<CoreEvent>> {
    let client = reqwest::Client::new();

    let mut request = client.get(&download.download_target);

    for (key, value) in &download.download_headers {
        request = request.header(key, value);
    }

    match request.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            if status >= 200 && status < 300 {
                let bytes = response.bytes().await.context("read blob response")?;
                let encoded = BASE64.encode(&bytes);
                Ok(vec![CoreEvent::BlobDownloaded {
                    task_id: download.task_id,
                    blob_ciphertext: Some(encoded),
                }])
            } else {
                let error_body = response.text().await.unwrap_or_default();
                if status == 403 && error_body.contains("capability_expired") {
                    log::warn!("Blob download link expired: {} - {}", status, error_body);
                } else {
                    log::error!("Blob download failed: {} - {}", status, error_body);
                }
                Ok(vec![CoreEvent::BlobTransferFailed {
                    task_id: download.task_id,
                    retryable: false,
                    detail: Some(format!("HTTP {}: {}", status, error_body)),
                }])
            }
        }
        Err(e) => {
            log::error!("Blob download error: {:?}", e);
            let retryable = e.is_timeout() || e.is_connect();
            Ok(vec![CoreEvent::BlobTransferFailed {
                task_id: download.task_id,
                retryable,
                detail: Some(e.to_string()),
            }])
        }
    }
}

/// Write downloaded attachment bytes to disk.
pub async fn write_downloaded_attachment(
    write: WriteDownloadedAttachmentEffect,
    attachments_dir: Option<PathBuf>,
) -> Result<Vec<CoreEvent>> {
    let dir = attachments_dir.context("no attachments directory configured")?;

    // Ensure directory exists
    fs::create_dir_all(&dir)
        .await
        .context("create attachments dir")?;

    // Decode base64 content
    let bytes = BASE64
        .decode(&write.plaintext_b64)
        .context("decode base64 attachment content")?;

    // Use destination_id as an opaque platform destination. Absolute paths are
    // user-selected save paths; relative ids are written under attachments_dir.
    let file_path = dir.join(&write.destination_id);
    if let Some(parent) = file_path.parent() {
        fs::create_dir_all(parent)
            .await
            .context("create attachment destination parent")?;
    }

    // Write atomically using temp file
    let tmp_path = file_path.with_extension("tmp");
    fs::write(&tmp_path, &bytes)
        .await
        .context("write attachment temp file")?;
    fs::rename(&tmp_path, &file_path)
        .await
        .context("rename attachment file")?;

    // Return a successful result - the destination_id is opaque, so we just confirm success
    // Core doesn't have a specific "AttachmentWritten" event, we'll use BlobTransferFailed with success
    // Actually, let's return an empty vec since this is a completion side-effect
    Ok(Vec::new())
}

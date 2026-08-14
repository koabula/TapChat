use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::Deserialize;
use tauri::{AppHandle, Emitter};
use tokio::fs;

use tapchat_core::ffi_api::{
    CoreEvent, ReadAttachmentBytesEffect, WriteDownloadedAttachmentEffect,
};
use tapchat_core::transport_contract::{BlobDownloadRequest, BlobUploadRequest};

use crate::platform::log_sanitize::redact_id;

/// Progress event payload sent to frontend during uploads
#[derive(Debug, Clone, serde::Serialize)]
pub struct UploadProgressEvent {
    pub task_id: String,
    pub conversation_id: String,
    pub progress: u32,  // 0-100 percentage
    pub status: String, // "reading", "encrypting", "uploading", "complete", "failed"
}

/// Read attachment bytes from the platform-owned attachment handle.
pub async fn read_attachment_bytes(
    read: ReadAttachmentBytesEffect,
    attachments_dir: Option<PathBuf>,
) -> Result<Vec<CoreEvent>> {
    let dir = attachments_dir.context("no attachments directory configured")?;
    let file_path = dir.join(&read.attachment_id);

    match fs::read(&file_path).await {
        Ok(bytes) => Ok(vec![CoreEvent::AttachmentBytesLoaded {
            task_id: read.task_id,
            plaintext: bytes,
        }]),
        Err(e) => {
            log::error!(
                "Failed to read attachment {}: read_failed",
                redact_id("attachment", &read.attachment_id)
            );
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
    client: &reqwest::Client,
    upload: BlobUploadRequest,
    app: Option<Arc<AppHandle>>,
) -> Result<Vec<CoreEvent>> {
    let task_id = upload.task_id.clone();
    let conversation_id = upload.conversation_id.clone();

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

    request = request.body(upload.blob_ciphertext);

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
                let body = response.text().await.unwrap_or_default();
                let code = serde_json::from_str::<BlobErrorResponse>(&body)
                    .ok()
                    .and_then(|value| value.error);
                let retryable = upload_status_is_retryable(status)
                    || code.as_deref() == Some("capability_expired");
                log::error!(
                    "Blob upload failed: status={} code={} task_id={} retryable={}",
                    status,
                    code.as_deref().unwrap_or("http_error"),
                    redact_id("task", &upload.task_id),
                    retryable
                );

                // Emit progress: failed
                if let Some(app_ref) = &app {
                    let _ = app_ref.emit(
                        "upload-progress",
                        UploadProgressEvent {
                            task_id: task_id.clone(),
                            conversation_id: conversation_id.clone(),
                            progress: 0,
                            status: if retryable { "retrying" } else { "failed" }.to_string(),
                        },
                    );
                }

                Ok(vec![CoreEvent::BlobTransferFailed {
                    task_id: upload.task_id,
                    retryable,
                    detail: Some(match code {
                        Some(code) => format!("blob_upload:{code}"),
                        None => format!("blob_upload:http_{status}"),
                    }),
                }])
            }
        }
        Err(e) => {
            let error_class = request_error_class(&e);
            let retryable = request_error_is_retryable(&e);
            log::error!(
                "Blob upload error: task_id={} error_class={} retryable={}",
                redact_id("task", &upload.task_id),
                error_class,
                retryable
            );

            // Emit progress: failed
            if let Some(app_ref) = &app {
                let _ = app_ref.emit(
                    "upload-progress",
                    UploadProgressEvent {
                        task_id: task_id.clone(),
                        conversation_id,
                        progress: 0,
                        status: if retryable { "retrying" } else { "failed" }.to_string(),
                    },
                );
            }

            Ok(vec![CoreEvent::BlobTransferFailed {
                task_id: upload.task_id,
                retryable,
                detail: Some(format!("blob_upload:{error_class}")),
            }])
        }
    }
}

/// Upload blob without progress tracking (for cases where app handle isn't available).
#[allow(dead_code)]
pub async fn upload_blob(upload: BlobUploadRequest) -> Result<Vec<CoreEvent>> {
    let client = crate::platform::transport::build_desktop_http_client();
    upload_blob_with_progress(&client, upload, None).await
}

/// Download blob from remote storage (GET from download URL).
pub async fn download_blob(
    client: &reqwest::Client,
    download: BlobDownloadRequest,
) -> Result<Vec<CoreEvent>> {
    let mut request = client.get(&download.download_target);

    for (key, value) in &download.download_headers {
        request = request.header(key, value);
    }

    match request.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            if status >= 200 && status < 300 {
                let bytes = response.bytes().await.context("read blob response")?;
                Ok(vec![CoreEvent::BlobDownloaded {
                    task_id: download.task_id,
                    blob_ciphertext: Some(bytes.to_vec()),
                }])
            } else {
                let error_body = response.text().await.unwrap_or_default();
                let code = serde_json::from_str::<BlobErrorResponse>(&error_body)
                    .ok()
                    .and_then(|value| value.error);
                let retryable = upload_status_is_retryable(status);
                log::error!(
                    "Blob download failed: status={} code={} task_id={} retryable={}",
                    status,
                    code.as_deref().unwrap_or("http_error"),
                    redact_id("task", &download.task_id),
                    retryable
                );
                Ok(vec![CoreEvent::BlobTransferFailed {
                    task_id: download.task_id,
                    retryable,
                    detail: Some(match code {
                        Some(code) => format!("blob_download:{code}"),
                        None => format!("blob_download:http_{status}"),
                    }),
                }])
            }
        }
        Err(e) => {
            let error_class = request_error_class(&e);
            let retryable = request_error_is_retryable(&e);
            log::error!(
                "Blob download error: task_id={} error_class={} retryable={}",
                redact_id("task", &download.task_id),
                error_class,
                retryable
            );
            Ok(vec![CoreEvent::BlobTransferFailed {
                task_id: download.task_id,
                retryable,
                detail: Some(format!("blob_download:{error_class}")),
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

    // Use destination_id as an opaque platform destination. Absolute paths are
    // user-selected save paths; relative ids are written under attachments_dir.
    match super::media_cache::EncryptedCacheDestination::parse(&write.destination_id) {
        Ok(Some(_)) => {
            anyhow::bail!("encrypted cache destination must be handled by DesktopPlatformPorts")
        }
        Err(_) => anyhow::bail!("invalid encrypted cache destination"),
        Ok(None) => {}
    }
    let file_path = dir.join(&write.destination_id);
    if let Some(parent) = file_path.parent() {
        fs::create_dir_all(parent)
            .await
            .context("create attachment destination parent")?;
    }

    // Write atomically using temp file
    let tmp_path = file_path.with_extension("tmp");
    fs::write(&tmp_path, &write.plaintext)
        .await
        .context("write attachment temp file")?;
    fs::rename(&tmp_path, &file_path)
        .await
        .context("rename attachment file")?;

    Ok(Vec::new())
}

#[derive(Debug, Deserialize)]
struct BlobErrorResponse {
    error: Option<String>,
}

fn request_error_class(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else if error.is_body() {
        "body"
    } else if error.is_redirect() {
        "redirect"
    } else if error.is_builder() {
        "builder"
    } else if error.is_request() {
        "request"
    } else {
        "transport"
    }
}

fn request_error_is_retryable(error: &reqwest::Error) -> bool {
    !error.is_builder() && !error.is_redirect()
}

fn upload_status_is_retryable(status: u16) -> bool {
    matches!(status, 408 | 409 | 425 | 429 | 500..=599)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CACHE_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[tokio::test]
    async fn generic_writer_never_writes_encrypted_cache_destinations_as_plaintext() {
        for destination_id in [
            format!("attachment-cache/{CACHE_ID}.enc"),
            format!("attachment-cache\\{CACHE_ID}.enc"),
            "attachment-cache/../outside.enc".to_string(),
        ] {
            let temp_dir = std::env::temp_dir().join(format!(
                "tapchat-generic-cache-guard-{}",
                uuid::Uuid::new_v4()
            ));
            let error = write_downloaded_attachment(
                WriteDownloadedAttachmentEffect {
                    task_id: "download:test".into(),
                    destination_id,
                    plaintext: b"must never reach disk".to_vec(),
                },
                Some(temp_dir.clone()),
            )
            .await
            .expect_err("encrypted cache destination must be refused");
            assert!(error.to_string().contains("encrypted cache destination"));
            assert_eq!(
                std::fs::read_dir(&temp_dir)
                    .expect("cache guard directory")
                    .count(),
                0
            );
            let _ = std::fs::remove_dir_all(temp_dir);
        }
    }
}

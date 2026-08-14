use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use futures_util::StreamExt;
use serde::Deserialize;
use tauri::{AppHandle, Emitter};
use tokio::fs;

use tapchat_core::ffi_api::{
    CoreEvent, ReadAttachmentBytesEffect, WriteDownloadedAttachmentEffect,
};
use tapchat_core::transport_contract::{BlobDownloadRequest, BlobUploadRequest};

use crate::platform::log_sanitize::redact_id;

const MAX_ATTACHMENT_CIPHERTEXT_BYTES: u64 = 25 * 1024 * 1024 + 1024;

/// Progress event payload sent to frontend during uploads
#[derive(Debug, Clone, serde::Serialize)]
pub struct UploadProgressEvent {
    pub task_id: String,
    pub conversation_id: String,
    pub transferred_bytes: u64,
    pub total_bytes: u64,
    pub percent: u32,
    /// Kept during the UI migration; it is always identical to `percent`.
    pub progress: u32,
    pub variant: String,
    pub status: String,
}

impl UploadProgressEvent {
    pub fn simple(
        task_id: String,
        conversation_id: String,
        percent: u32,
        status: impl Into<String>,
    ) -> Self {
        Self {
            variant: transfer_variant(&task_id),
            task_id,
            conversation_id,
            transferred_bytes: 0,
            total_bytes: 0,
            percent,
            progress: percent,
            status: status.into(),
        }
    }
}

fn transfer_variant(task_id: &str) -> String {
    if task_id.ends_with(":preview") {
        "preview"
    } else {
        "original"
    }
    .into()
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
            UploadProgressEvent::simple(task_id.clone(), conversation_id.clone(), 0, "uploading"),
        );
    }

    let mut request = client.put(&upload.upload_target);

    for (key, value) in &upload.upload_headers {
        request = request.header(key, value);
    }

    let total_bytes = upload.blob_ciphertext.len() as u64;
    let variant = transfer_variant(&task_id);
    let stream_task_id = task_id.clone();
    let stream_conversation_id = conversation_id.clone();
    let upload_stream = futures_util::stream::unfold(
        (upload.blob_ciphertext, 0_usize, app.clone()),
        move |(bytes, offset, app)| {
            let task_id = stream_task_id.clone();
            let conversation_id = stream_conversation_id.clone();
            let variant = variant.clone();
            async move {
                if offset >= bytes.len() {
                    return None;
                }
                let end = (offset + 64 * 1024).min(bytes.len());
                let chunk = bytes[offset..end].to_vec();
                if let Some(app_ref) = &app {
                    let transferred = end as u64;
                    let percent = ((transferred * 100) / total_bytes.max(1)) as u32;
                    let _ = app_ref.emit(
                        "upload-progress",
                        UploadProgressEvent {
                            task_id,
                            conversation_id,
                            transferred_bytes: transferred,
                            total_bytes,
                            percent,
                            progress: percent,
                            variant,
                            status: "uploading".into(),
                        },
                    );
                }
                Some((Ok::<Vec<u8>, std::io::Error>(chunk), (bytes, end, app)))
            }
        },
    );
    request = request
        .header(reqwest::header::CONTENT_LENGTH, total_bytes)
        .body(reqwest::Body::wrap_stream(upload_stream));

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
                            transferred_bytes: total_bytes,
                            total_bytes,
                            percent: 100,
                            progress: 100,
                            variant: transfer_variant(&task_id),
                            status: "complete".into(),
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
                        UploadProgressEvent::simple(
                            task_id.clone(),
                            conversation_id.clone(),
                            0,
                            if retryable { "retrying" } else { "failed" },
                        ),
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
                    UploadProgressEvent::simple(
                        task_id.clone(),
                        conversation_id,
                        0,
                        if retryable { "retrying" } else { "failed" },
                    ),
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
    app: Option<Arc<AppHandle>>,
) -> Result<Vec<CoreEvent>> {
    let mut request = client.get(&download.download_target);

    for (key, value) in &download.download_headers {
        request = request.header(key, value);
    }

    match request.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            if status >= 200 && status < 300 {
                let total_bytes = response.content_length().unwrap_or_default();
                if total_bytes > MAX_ATTACHMENT_CIPHERTEXT_BYTES {
                    return Ok(vec![CoreEvent::BlobTransferFailed {
                        task_id: download.task_id,
                        retryable: false,
                        detail: Some("blob_download:oversized".into()),
                    }]);
                }
                let mut transferred_bytes = 0_u64;
                let mut bytes = Vec::with_capacity(total_bytes as usize);
                let mut stream = response.bytes_stream();
                while let Some(next) = stream.next().await {
                    let chunk = next.context("read blob response")?;
                    transferred_bytes = transferred_bytes.saturating_add(chunk.len() as u64);
                    if transferred_bytes > MAX_ATTACHMENT_CIPHERTEXT_BYTES {
                        return Ok(vec![CoreEvent::BlobTransferFailed {
                            task_id: download.task_id,
                            retryable: false,
                            detail: Some("blob_download:oversized".into()),
                        }]);
                    }
                    bytes.extend_from_slice(&chunk);
                    if let Some(app_ref) = &app {
                        let percent = if total_bytes == 0 {
                            0
                        } else {
                            ((transferred_bytes.min(total_bytes) * 100) / total_bytes) as u32
                        };
                        let _ = app_ref.emit(
                            "download-progress",
                            UploadProgressEvent {
                                task_id: download.task_id.clone(),
                                conversation_id: download.conversation_id.clone(),
                                transferred_bytes,
                                total_bytes,
                                percent,
                                progress: percent,
                                variant: transfer_variant(&download.task_id),
                                status: "downloading".into(),
                            },
                        );
                    }
                }
                Ok(vec![CoreEvent::BlobDownloaded {
                    task_id: download.task_id,
                    blob_ciphertext: Some(bytes),
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

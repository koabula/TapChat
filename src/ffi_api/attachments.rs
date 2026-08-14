use sha2::{Digest, Sha256};

use crate::error::{CoreError, CoreResult};
use crate::ffi_api::types::AttachmentDescriptor;

const MAX_ATTACHMENT_BYTES: u64 = 25 * 1024 * 1024;
const MAX_ATTACHMENT_MIME_TYPE_LEN: usize = 255;
const MAX_ATTACHMENT_FILE_NAME_LEN: usize = 255;

pub(super) fn validate_attachment_descriptor(descriptor: &AttachmentDescriptor) -> CoreResult<()> {
    if descriptor.attachment_id.trim().is_empty() {
        return Err(CoreError::invalid_input("attachment id is required"));
    }
    if descriptor.mime_type.trim().is_empty()
        || descriptor.mime_type.len() > MAX_ATTACHMENT_MIME_TYPE_LEN
        || descriptor.mime_type.contains('\r')
        || descriptor.mime_type.contains('\n')
    {
        return Err(CoreError::invalid_input("attachment mime type is invalid"));
    }
    if descriptor.size_bytes == 0 || descriptor.size_bytes > MAX_ATTACHMENT_BYTES {
        return Err(CoreError::invalid_input(
            "attachment size is outside supported limits",
        ));
    }
    if let Some(file_name) = &descriptor.file_name {
        if file_name.trim().is_empty()
            || file_name.len() > MAX_ATTACHMENT_FILE_NAME_LEN
            || file_name.contains('/')
            || file_name.contains('\\')
            || file_name.contains('\0')
            || file_name.contains('\r')
            || file_name.contains('\n')
        {
            return Err(CoreError::invalid_input("attachment file name is invalid"));
        }
    }
    if let Some(preview) = &descriptor.preview {
        if preview.attachment_id.trim().is_empty()
            || preview.mime_type != "image/webp"
            || preview.size_bytes == 0
            || preview.size_bytes > 128 * 1024
        {
            return Err(CoreError::invalid_input(
                "attachment preview descriptor is invalid",
            ));
        }
        if descriptor.width.is_none() || descriptor.height.is_none() {
            return Err(CoreError::invalid_input(
                "image dimensions are required when a preview is present",
            ));
        }
    }
    Ok(())
}

pub(super) fn attachment_download_task_id(
    message_id: &str,
    reference: &str,
    destination: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(reference.as_bytes());
    hasher.update([0]);
    hasher.update(destination.as_bytes());
    let digest = hasher.finalize();
    let hash: String = format!("{digest:x}").chars().take(12).collect();
    format!("blob-download:{message_id}:{hash}")
}

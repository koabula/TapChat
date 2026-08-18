use tapchat_core::conversation::StoredMessage;
use tapchat_core::model::MessageType;

pub(super) fn summarize_plaintext(plaintext: Option<&str>) -> String {
    match plaintext {
        Some(value) => format!("has_plaintext=true plaintext_len={}", value.len()),
        None => "has_plaintext=false plaintext_len=0".into(),
    }
}

/// Generate a preview string for the last message in a conversation.
/// Returns None if there are no messages or the last message has no plaintext.
pub(super) fn generate_last_message_preview(messages: &[StoredMessage]) -> Option<String> {
    // Find the last application message (not protocol messages like Welcome/Commit)
    let last_app_message = messages
        .iter()
        .rev()
        .find(|msg| matches!(msg.message_type, MessageType::MlsApplication));

    last_app_message.and_then(|msg| msg.plaintext.as_deref().map(visible_plaintext_preview))
}

pub(super) fn visible_plaintext_preview(plaintext: &str) -> String {
    if let Ok(manifest) =
        serde_json::from_str::<tapchat_core::attachment_crypto::AttachmentManifestV2>(plaintext)
    {
        return match manifest.kind {
            tapchat_core::attachment_crypto::AttachmentKind::Image => "Photo".into(),
            tapchat_core::attachment_crypto::AttachmentKind::Video => "Video".into(),
            tapchat_core::attachment_crypto::AttachmentKind::Audio => "Audio".into(),
            tapchat_core::attachment_crypto::AttachmentKind::File => manifest
                .file_name
                .filter(|name| !name.trim().is_empty())
                .map(|name| format!("File · {name}"))
                .unwrap_or_else(|| "File".into()),
        };
    }
    let mut characters = plaintext.chars();
    let preview = characters.by_ref().take(50).collect::<String>();
    if characters.next().is_some() {
        format!("{preview}...")
    } else {
        preview
    }
}

#[cfg(test)]
mod tests {
    use super::visible_plaintext_preview;
    use tapchat_core::attachment_crypto::{
        encrypt_blob, sha256_hex, AttachmentKind, AttachmentManifestV2, AttachmentVariant,
        EncryptedBlobDescriptor,
    };

    #[test]
    fn attachment_manifest_is_projected_to_a_human_preview() {
        let plaintext = b"image";
        let encrypted = encrypt_blob(plaintext).expect("encrypt");
        let manifest = AttachmentManifestV2 {
            version: 2,
            attachment_id: "msg:photo".into(),
            kind: AttachmentKind::Image,
            file_name: Some("secret-name.png".into()),
            width: Some(100),
            height: Some(80),
            blur_hash: None,
            original: EncryptedBlobDescriptor {
                variant: AttachmentVariant::Original,
                object_ref: "blob:photo".into(),
                storage_origin: "https://storage.example.com".into(),
                read_capability: "read".into(),
                mime_type: "image/png".into(),
                plaintext_size: plaintext.len() as u64,
                ciphertext_size: encrypted.ciphertext.len() as u64,
                digest_sha256: sha256_hex(plaintext),
                encryption: encrypted.metadata,
            },
            preview: None,
        };
        let json = serde_json::to_string(&manifest).expect("manifest json");
        assert_eq!(visible_plaintext_preview(&json), "Photo");
        assert!(!visible_plaintext_preview(&json).contains("attachment_id"));
    }

    #[test]
    fn unicode_preview_truncates_on_character_boundaries() {
        let plaintext = "图".repeat(51);
        assert_eq!(
            visible_plaintext_preview(&plaintext),
            format!("{}...", "图".repeat(50))
        );
    }
}

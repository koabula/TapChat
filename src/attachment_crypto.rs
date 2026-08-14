use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};
use sha2::{Digest, Sha256};

pub const ATTACHMENT_CIPHER_ALGORITHM: &str = "aes_256_gcm";
const ATTACHMENT_KEY_LEN: usize = 32;
const ATTACHMENT_NONCE_LEN: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentCipherMetadata {
    pub algorithm: String,
    pub key_b64: String,
    pub nonce_b64: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentKind {
    Image,
    Video,
    Audio,
    File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentVariant {
    Original,
    Preview,
}

impl AttachmentVariant {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Original => "original",
            Self::Preview => "preview",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedBlobDescriptor {
    pub variant: AttachmentVariant,
    pub object_ref: String,
    /// Stable origin of the user-provisioned storage runtime that owns the
    /// object. Older manifests omit this field; the receiver then derives it
    /// from the sender's signed identity bundle instead of its local runtime.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub storage_origin: String,
    pub read_capability: String,
    pub mime_type: String,
    pub plaintext_size: u64,
    pub ciphertext_size: u64,
    pub digest_sha256: String,
    pub encryption: AttachmentCipherMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentManifestV2 {
    pub version: u32,
    pub attachment_id: String,
    pub kind: AttachmentKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blur_hash: Option<String>,
    pub original: EncryptedBlobDescriptor,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<EncryptedBlobDescriptor>,
}

pub type AttachmentPayloadMetadata = AttachmentManifestV2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedAttachment {
    pub ciphertext: Vec<u8>,
    pub metadata: AttachmentCipherMetadata,
}

pub fn encrypt_blob(plaintext: &[u8]) -> CoreResult<EncryptedAttachment> {
    let mut key = [0_u8; ATTACHMENT_KEY_LEN];
    let mut nonce = [0_u8; ATTACHMENT_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut key);
    rand::thread_rng().fill_bytes(&mut nonce);

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|error| {
        CoreError::invalid_state(format!("failed to initialize attachment cipher: {error}"))
    })?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| CoreError::invalid_state("failed to encrypt attachment blob"))?;

    Ok(EncryptedAttachment {
        ciphertext,
        metadata: AttachmentCipherMetadata {
            algorithm: ATTACHMENT_CIPHER_ALGORITHM.into(),
            key_b64: STANDARD.encode(key),
            nonce_b64: STANDARD.encode(nonce),
        },
    })
}

pub fn decrypt_blob(ciphertext: &[u8], metadata: &AttachmentCipherMetadata) -> CoreResult<Vec<u8>> {
    if metadata.algorithm != ATTACHMENT_CIPHER_ALGORITHM {
        return Err(CoreError::invalid_input(format!(
            "unsupported attachment cipher algorithm {}",
            metadata.algorithm
        )));
    }
    let key = STANDARD
        .decode(&metadata.key_b64)
        .map_err(|_| CoreError::invalid_input("attachment key must be valid base64"))?;
    let nonce = STANDARD
        .decode(&metadata.nonce_b64)
        .map_err(|_| CoreError::invalid_input("attachment nonce must be valid base64"))?;
    if key.len() != ATTACHMENT_KEY_LEN {
        return Err(CoreError::invalid_input(
            "attachment key has invalid length",
        ));
    }
    if nonce.len() != ATTACHMENT_NONCE_LEN {
        return Err(CoreError::invalid_input(
            "attachment nonce has invalid length",
        ));
    }
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|error| {
        CoreError::invalid_state(format!("failed to initialize attachment cipher: {error}"))
    })?;
    cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext)
        .map_err(|_| CoreError::invalid_input("failed to decrypt attachment blob"))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn blob_cache_id(storage_origin: &str, object_ref: &str) -> String {
    let mut locator = Vec::with_capacity(storage_origin.len() + object_ref.len() + 1);
    locator.extend_from_slice(storage_origin.as_bytes());
    locator.push(0);
    locator.extend_from_slice(object_ref.as_bytes());
    sha256_hex(&locator)
}

#[cfg(test)]
mod tests {
    use super::{
        decrypt_blob, encrypt_blob, sha256_hex, AttachmentKind, AttachmentManifestV2,
        AttachmentVariant, EncryptedBlobDescriptor,
    };

    #[test]
    fn blob_encryption_round_trip_restores_plaintext() {
        let plaintext = b"attachment-bytes";
        let encrypted = encrypt_blob(plaintext).expect("encrypt");
        assert_ne!(encrypted.ciphertext, plaintext);
        let decrypted = decrypt_blob(&encrypted.ciphertext, &encrypted.metadata).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn original_and_preview_use_independent_cipher_parameters() {
        let original = encrypt_blob(b"original image bytes").expect("encrypt original");
        let preview = encrypt_blob(b"preview bytes").expect("encrypt preview");
        assert_ne!(original.metadata.key_b64, preview.metadata.key_b64);
        assert_ne!(original.metadata.nonce_b64, preview.metadata.nonce_b64);
        assert_ne!(original.ciphertext, preview.ciphertext);
    }

    #[test]
    fn manifest_v2_round_trip_keeps_blob_scoped_capability() {
        let encrypted = encrypt_blob(b"original").expect("encrypt");
        let manifest = AttachmentManifestV2 {
            version: 2,
            attachment_id: "attachment:test".into(),
            kind: AttachmentKind::Image,
            file_name: Some("photo.png".into()),
            width: Some(640),
            height: Some(480),
            blur_hash: Some("LEHV6nWB2yk8pyo0adR*.7kCMdnj".into()),
            original: EncryptedBlobDescriptor {
                variant: AttachmentVariant::Original,
                object_ref: "blobs/original/test".into(),
                storage_origin: "https://storage.example".into(),
                read_capability: "opaque-capability".into(),
                mime_type: "image/png".into(),
                plaintext_size: 8,
                ciphertext_size: encrypted.ciphertext.len() as u64,
                digest_sha256: sha256_hex(b"original"),
                encryption: encrypted.metadata,
            },
            preview: None,
        };
        let encoded = serde_json::to_string(&manifest).expect("encode manifest");
        let decoded: AttachmentManifestV2 =
            serde_json::from_str(&encoded).expect("decode manifest");
        assert_eq!(decoded, manifest);
        assert!(!encoded.contains("original image bytes"));
    }

    #[test]
    fn media_cache_identity_binds_storage_origin_and_object_reference() {
        assert_ne!(
            super::blob_cache_id("https://alice.example", "blobs/original/1"),
            super::blob_cache_id("https://bob.example", "blobs/original/1")
        );
        assert_ne!(
            super::blob_cache_id("https://alice.example", "blobs/original/1"),
            super::blob_cache_id("https://alice.example", "blobs/original/2")
        );
    }
}

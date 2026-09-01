use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};
use sha2::{Digest, Sha256};

pub const ATTACHMENT_CIPHER_ALGORITHM: &str = "aes_256_gcm";
pub const CHUNKED_ATTACHMENT_CIPHER_ALGORITHM: &str = "aes_256_gcm_chunked_v1";
pub const ATTACHMENT_CHUNK_SIZE_BYTES: u32 = 512 * 1024;
pub const ATTACHMENT_GCM_TAG_BYTES: u64 = 16;
const ATTACHMENT_KEY_LEN: usize = 32;
const ATTACHMENT_NONCE_LEN: usize = 12;
const ATTACHMENT_CHUNK_NONCE_PREFIX_LEN: usize = 8;
const ATTACHMENT_CHUNK_AAD_LABEL: &[u8] = b"tapchat-attachment-chunk-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentCipherMetadata {
    pub algorithm: String,
    pub key_b64: String,
    pub nonce_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_size_bytes: Option<u32>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachmentByteRange {
    pub start: u64,
    pub end_exclusive: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachmentChunkSpan {
    pub first_chunk: u32,
    pub last_chunk: u32,
    pub ciphertext: AttachmentByteRange,
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
            chunk_size_bytes: None,
        },
    })
}

pub fn decrypt_blob(ciphertext: &[u8], metadata: &AttachmentCipherMetadata) -> CoreResult<Vec<u8>> {
    if metadata.algorithm != ATTACHMENT_CIPHER_ALGORITHM {
        return Err(CoreError::invalid_input(format!(
            "attachment requires a newer TapChat version: unsupported cipher algorithm {}",
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

pub fn encrypt_chunked_blob(
    plaintext: &[u8],
    message_id: &str,
    variant: AttachmentVariant,
) -> CoreResult<EncryptedAttachment> {
    if plaintext.is_empty() {
        return Err(CoreError::invalid_input(
            "chunked attachment plaintext must not be empty",
        ));
    }
    let mut key = [0_u8; ATTACHMENT_KEY_LEN];
    let mut nonce_prefix = [0_u8; ATTACHMENT_CHUNK_NONCE_PREFIX_LEN];
    rand::thread_rng().fill_bytes(&mut key);
    rand::thread_rng().fill_bytes(&mut nonce_prefix);
    let metadata = AttachmentCipherMetadata {
        algorithm: CHUNKED_ATTACHMENT_CIPHER_ALGORITHM.into(),
        key_b64: STANDARD.encode(key),
        nonce_b64: STANDARD.encode(nonce_prefix),
        chunk_size_bytes: Some(ATTACHMENT_CHUNK_SIZE_BYTES),
    };
    let total_plaintext_size = plaintext.len() as u64;
    let mut ciphertext = Vec::with_capacity(chunked_ciphertext_size(
        total_plaintext_size,
        ATTACHMENT_CHUNK_SIZE_BYTES,
    )? as usize);
    for (index, chunk) in plaintext
        .chunks(ATTACHMENT_CHUNK_SIZE_BYTES as usize)
        .enumerate()
    {
        ciphertext.extend_from_slice(&encrypt_attachment_chunk(
            chunk,
            &metadata,
            message_id,
            variant,
            total_plaintext_size,
            index as u32,
        )?);
    }
    Ok(EncryptedAttachment {
        ciphertext,
        metadata,
    })
}

pub fn decrypt_chunked_blob(
    ciphertext: &[u8],
    metadata: &AttachmentCipherMetadata,
    message_id: &str,
    variant: AttachmentVariant,
    total_plaintext_size: u64,
) -> CoreResult<Vec<u8>> {
    validate_chunked_ciphertext_size(metadata, total_plaintext_size, ciphertext.len() as u64)?;
    let chunk_size = chunk_size(metadata)?;
    let mut plaintext = Vec::with_capacity(total_plaintext_size as usize);
    for index in 0..attachment_chunk_count(total_plaintext_size, chunk_size)? {
        let range = attachment_chunk_ciphertext_range(metadata, total_plaintext_size, index)?;
        plaintext.extend_from_slice(&decrypt_attachment_chunk(
            &ciphertext[range.start as usize..range.end_exclusive as usize],
            metadata,
            message_id,
            variant,
            total_plaintext_size,
            index,
        )?);
    }
    Ok(plaintext)
}

pub fn encrypt_attachment_chunk(
    plaintext: &[u8],
    metadata: &AttachmentCipherMetadata,
    message_id: &str,
    variant: AttachmentVariant,
    total_plaintext_size: u64,
    chunk_index: u32,
) -> CoreResult<Vec<u8>> {
    let (cipher, nonce_prefix, chunk_size) = chunk_cipher(metadata)?;
    let expected_len =
        attachment_chunk_plaintext_len(total_plaintext_size, chunk_size, chunk_index)?;
    if plaintext.len() as u64 != expected_len {
        return Err(CoreError::invalid_input(
            "attachment chunk plaintext length is invalid",
        ));
    }
    let nonce = attachment_chunk_nonce(&nonce_prefix, chunk_index);
    let aad = attachment_chunk_aad(
        message_id,
        variant,
        total_plaintext_size,
        chunk_index,
        expected_len as u32,
    )?;
    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CoreError::invalid_state("failed to encrypt attachment chunk"))
}

pub fn decrypt_attachment_chunk(
    ciphertext: &[u8],
    metadata: &AttachmentCipherMetadata,
    message_id: &str,
    variant: AttachmentVariant,
    total_plaintext_size: u64,
    chunk_index: u32,
) -> CoreResult<Vec<u8>> {
    let (cipher, nonce_prefix, chunk_size) = chunk_cipher(metadata)?;
    let plaintext_len =
        attachment_chunk_plaintext_len(total_plaintext_size, chunk_size, chunk_index)?;
    if ciphertext.len() as u64 != plaintext_len + ATTACHMENT_GCM_TAG_BYTES {
        return Err(CoreError::invalid_input(
            "attachment chunk ciphertext length is invalid",
        ));
    }
    let nonce = attachment_chunk_nonce(&nonce_prefix, chunk_index);
    let aad = attachment_chunk_aad(
        message_id,
        variant,
        total_plaintext_size,
        chunk_index,
        plaintext_len as u32,
    )?;
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CoreError::invalid_input("failed to authenticate attachment chunk"))
}

pub fn attachment_chunk_count(total_plaintext_size: u64, chunk_size: u32) -> CoreResult<u32> {
    if total_plaintext_size == 0 || chunk_size == 0 {
        return Err(CoreError::invalid_input(
            "chunked attachment size is invalid",
        ));
    }
    let count = total_plaintext_size
        .checked_add(chunk_size as u64 - 1)
        .ok_or_else(|| CoreError::invalid_input("chunked attachment size overflow"))?
        / chunk_size as u64;
    u32::try_from(count)
        .map_err(|_| CoreError::invalid_input("chunked attachment has too many chunks"))
}

pub fn chunked_ciphertext_size(total_plaintext_size: u64, chunk_size: u32) -> CoreResult<u64> {
    let count = attachment_chunk_count(total_plaintext_size, chunk_size)? as u64;
    total_plaintext_size
        .checked_add(count * ATTACHMENT_GCM_TAG_BYTES)
        .ok_or_else(|| CoreError::invalid_input("chunked attachment size overflow"))
}

pub fn validate_chunked_ciphertext_size(
    metadata: &AttachmentCipherMetadata,
    total_plaintext_size: u64,
    ciphertext_size: u64,
) -> CoreResult<()> {
    let expected = chunked_ciphertext_size(total_plaintext_size, chunk_size(metadata)?)?;
    if ciphertext_size != expected {
        return Err(CoreError::invalid_input(
            "chunked attachment ciphertext size is invalid",
        ));
    }
    Ok(())
}

pub fn attachment_chunk_ciphertext_range(
    metadata: &AttachmentCipherMetadata,
    total_plaintext_size: u64,
    chunk_index: u32,
) -> CoreResult<AttachmentByteRange> {
    let chunk_size = chunk_size(metadata)?;
    let plaintext_len =
        attachment_chunk_plaintext_len(total_plaintext_size, chunk_size, chunk_index)?;
    let stride = chunk_size as u64 + ATTACHMENT_GCM_TAG_BYTES;
    let start = (chunk_index as u64)
        .checked_mul(stride)
        .ok_or_else(|| CoreError::invalid_input("attachment chunk offset overflow"))?;
    Ok(AttachmentByteRange {
        start,
        end_exclusive: start + plaintext_len + ATTACHMENT_GCM_TAG_BYTES,
    })
}

pub fn plaintext_range_to_chunk_span(
    metadata: &AttachmentCipherMetadata,
    total_plaintext_size: u64,
    start: u64,
    end_exclusive: u64,
) -> CoreResult<AttachmentChunkSpan> {
    if start >= end_exclusive || end_exclusive > total_plaintext_size {
        return Err(CoreError::invalid_input(
            "attachment plaintext range is invalid",
        ));
    }
    let chunk_size = chunk_size(metadata)? as u64;
    let first_chunk = (start / chunk_size) as u32;
    let last_chunk = ((end_exclusive - 1) / chunk_size) as u32;
    let first_range =
        attachment_chunk_ciphertext_range(metadata, total_plaintext_size, first_chunk)?;
    let last_range = attachment_chunk_ciphertext_range(metadata, total_plaintext_size, last_chunk)?;
    Ok(AttachmentChunkSpan {
        first_chunk,
        last_chunk,
        ciphertext: AttachmentByteRange {
            start: first_range.start,
            end_exclusive: last_range.end_exclusive,
        },
    })
}

fn chunk_size(metadata: &AttachmentCipherMetadata) -> CoreResult<u32> {
    if metadata.algorithm != CHUNKED_ATTACHMENT_CIPHER_ALGORITHM {
        return Err(CoreError::invalid_input(format!(
            "attachment requires a newer TapChat version: unsupported cipher algorithm {}",
            metadata.algorithm
        )));
    }
    match metadata.chunk_size_bytes {
        Some(ATTACHMENT_CHUNK_SIZE_BYTES) => Ok(ATTACHMENT_CHUNK_SIZE_BYTES),
        _ => Err(CoreError::invalid_input(
            "chunked attachment has an unsupported chunk size",
        )),
    }
}

fn attachment_chunk_plaintext_len(
    total_plaintext_size: u64,
    chunk_size: u32,
    chunk_index: u32,
) -> CoreResult<u64> {
    let count = attachment_chunk_count(total_plaintext_size, chunk_size)?;
    if chunk_index >= count {
        return Err(CoreError::invalid_input(
            "attachment chunk index is out of bounds",
        ));
    }
    let start = chunk_index as u64 * chunk_size as u64;
    Ok((total_plaintext_size - start).min(chunk_size as u64))
}

fn chunk_cipher(metadata: &AttachmentCipherMetadata) -> CoreResult<(Aes256Gcm, Vec<u8>, u32)> {
    let chunk_size = chunk_size(metadata)?;
    let key = STANDARD
        .decode(&metadata.key_b64)
        .map_err(|_| CoreError::invalid_input("attachment key must be valid base64"))?;
    let nonce_prefix = STANDARD
        .decode(&metadata.nonce_b64)
        .map_err(|_| CoreError::invalid_input("attachment nonce must be valid base64"))?;
    if key.len() != ATTACHMENT_KEY_LEN {
        return Err(CoreError::invalid_input(
            "attachment key has invalid length",
        ));
    }
    if nonce_prefix.len() != ATTACHMENT_CHUNK_NONCE_PREFIX_LEN {
        return Err(CoreError::invalid_input(
            "attachment nonce prefix has invalid length",
        ));
    }
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|error| {
        CoreError::invalid_state(format!("failed to initialize attachment cipher: {error}"))
    })?;
    Ok((cipher, nonce_prefix, chunk_size))
}

fn attachment_chunk_nonce(prefix: &[u8], chunk_index: u32) -> [u8; ATTACHMENT_NONCE_LEN] {
    let mut nonce = [0_u8; ATTACHMENT_NONCE_LEN];
    nonce[..ATTACHMENT_CHUNK_NONCE_PREFIX_LEN].copy_from_slice(prefix);
    nonce[ATTACHMENT_CHUNK_NONCE_PREFIX_LEN..].copy_from_slice(&chunk_index.to_be_bytes());
    nonce
}

fn attachment_chunk_aad(
    message_id: &str,
    variant: AttachmentVariant,
    total_plaintext_size: u64,
    chunk_index: u32,
    chunk_plaintext_size: u32,
) -> CoreResult<Vec<u8>> {
    let message_len = u32::try_from(message_id.len())
        .map_err(|_| CoreError::invalid_input("attachment message id is too long"))?;
    let mut aad = Vec::with_capacity(ATTACHMENT_CHUNK_AAD_LABEL.len() + message_id.len() + 21);
    aad.extend_from_slice(ATTACHMENT_CHUNK_AAD_LABEL);
    aad.extend_from_slice(&message_len.to_be_bytes());
    aad.extend_from_slice(message_id.as_bytes());
    aad.push(match variant {
        AttachmentVariant::Original => 0,
        AttachmentVariant::Preview => 1,
    });
    aad.extend_from_slice(&total_plaintext_size.to_be_bytes());
    aad.extend_from_slice(&chunk_index.to_be_bytes());
    aad.extend_from_slice(&chunk_plaintext_size.to_be_bytes());
    Ok(aad)
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
        ATTACHMENT_CHUNK_SIZE_BYTES, AttachmentKind, AttachmentManifestV2, AttachmentVariant,
        EncryptedBlobDescriptor, attachment_chunk_ciphertext_range, attachment_chunk_count,
        attachment_chunk_nonce, decrypt_attachment_chunk, decrypt_blob, decrypt_chunked_blob,
        encrypt_blob, encrypt_chunked_blob, plaintext_range_to_chunk_span, sha256_hex,
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

    #[test]
    fn chunked_encryption_round_trips_boundaries_and_near_attachment_limit() {
        for size in [
            1_usize,
            ATTACHMENT_CHUNK_SIZE_BYTES as usize,
            ATTACHMENT_CHUNK_SIZE_BYTES as usize + 1,
            ATTACHMENT_CHUNK_SIZE_BYTES as usize * 2 - 1,
            25 * 1024 * 1024 - 1,
        ] {
            let plaintext = (0..size)
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>();
            let encrypted = encrypt_chunked_blob(
                &plaintext,
                "message:chunked-round-trip",
                AttachmentVariant::Original,
            )
            .expect("encrypt chunked");
            let decrypted = decrypt_chunked_blob(
                &encrypted.ciphertext,
                &encrypted.metadata,
                "message:chunked-round-trip",
                AttachmentVariant::Original,
                plaintext.len() as u64,
            )
            .expect("decrypt chunked");
            assert_eq!(decrypted, plaintext);
        }
    }

    #[test]
    fn plaintext_ranges_map_to_complete_ciphertext_chunks() {
        let plaintext = vec![7_u8; ATTACHMENT_CHUNK_SIZE_BYTES as usize * 2 + 9];
        let encrypted =
            encrypt_chunked_blob(&plaintext, "message:range", AttachmentVariant::Original)
                .expect("encrypt");
        let one_byte =
            plaintext_range_to_chunk_span(&encrypted.metadata, plaintext.len() as u64, 0, 1)
                .expect("one byte range");
        assert_eq!((one_byte.first_chunk, one_byte.last_chunk), (0, 0));

        let boundary = plaintext_range_to_chunk_span(
            &encrypted.metadata,
            plaintext.len() as u64,
            ATTACHMENT_CHUNK_SIZE_BYTES as u64 - 1,
            ATTACHMENT_CHUNK_SIZE_BYTES as u64 + 1,
        )
        .expect("cross-boundary range");
        assert_eq!((boundary.first_chunk, boundary.last_chunk), (0, 1));

        let last = plaintext_range_to_chunk_span(
            &encrypted.metadata,
            plaintext.len() as u64,
            plaintext.len() as u64 - 1,
            plaintext.len() as u64,
        )
        .expect("last byte range");
        assert_eq!((last.first_chunk, last.last_chunk), (2, 2));
        assert_eq!(
            boundary.ciphertext.start,
            attachment_chunk_ciphertext_range(&encrypted.metadata, plaintext.len() as u64, 0)
                .expect("first chunk")
                .start
        );
    }

    #[test]
    fn chunk_authentication_binds_message_variant_and_index() {
        let plaintext = vec![3_u8; ATTACHMENT_CHUNK_SIZE_BYTES as usize * 2];
        let encrypted =
            encrypt_chunked_blob(&plaintext, "message:bound", AttachmentVariant::Original)
                .expect("encrypt");
        let range =
            attachment_chunk_ciphertext_range(&encrypted.metadata, plaintext.len() as u64, 0)
                .expect("range");
        let chunk = &encrypted.ciphertext[range.start as usize..range.end_exclusive as usize];
        assert!(
            decrypt_attachment_chunk(
                chunk,
                &encrypted.metadata,
                "message:other",
                AttachmentVariant::Original,
                plaintext.len() as u64,
                0,
            )
            .is_err()
        );
        assert!(
            decrypt_attachment_chunk(
                chunk,
                &encrypted.metadata,
                "message:bound",
                AttachmentVariant::Preview,
                plaintext.len() as u64,
                0,
            )
            .is_err()
        );
        assert!(
            decrypt_attachment_chunk(
                chunk,
                &encrypted.metadata,
                "message:bound",
                AttachmentVariant::Original,
                plaintext.len() as u64,
                1,
            )
            .is_err()
        );
    }

    #[test]
    fn chunk_nonces_are_unique_for_each_index() {
        let prefix = [8_u8; 8];
        let count = attachment_chunk_count(25 * 1024 * 1024, ATTACHMENT_CHUNK_SIZE_BYTES)
            .expect("chunk count");
        let mut nonces = std::collections::BTreeSet::new();
        for index in 0..count {
            assert!(nonces.insert(attachment_chunk_nonce(&prefix, index)));
        }
    }

    #[test]
    fn manifest_v2_accepts_legacy_cipher_metadata_without_chunk_size() {
        let legacy = r#"{
          "version":2,
          "attachment_id":"attachment:legacy",
          "kind":"file",
          "original":{
            "variant":"original",
            "object_ref":"blob:legacy",
            "read_capability":"cap",
            "mime_type":"application/octet-stream",
            "plaintext_size":1,
            "ciphertext_size":17,
            "digest_sha256":"00",
            "encryption":{"algorithm":"aes_256_gcm","key_b64":"key","nonce_b64":"nonce"}
          }
        }"#;
        let decoded: AttachmentManifestV2 = serde_json::from_str(legacy).expect("legacy manifest");
        assert_eq!(decoded.original.encryption.chunk_size_bytes, None);
        let encoded = serde_json::to_string(&decoded).expect("encode legacy manifest");
        assert!(!encoded.contains("chunk_size_bytes"));
    }
}

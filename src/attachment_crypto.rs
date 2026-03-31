use std::env;
use std::fs;
use std::path::PathBuf;

use aes_gcm::{Aes256Gcm, Nonce, aead::{Aead, KeyInit}};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};

pub const ATTACHMENT_CIPHER_ALGORITHM: &str = "aes_256_gcm";
const ATTACHMENT_KEY_LEN: usize = 32;
const ATTACHMENT_NONCE_LEN: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentCipherMetadata {
    pub algorithm: String,
    pub key_b64: String,
    pub nonce_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentPayloadMetadata {
    pub mime_type: String,
    pub size_bytes: u64,
    pub file_name: Option<String>,
    pub encryption: AttachmentCipherMetadata,
}

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

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|error| CoreError::invalid_state(format!("failed to initialize attachment cipher: {error}")))?;
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
        return Err(CoreError::invalid_input("attachment key has invalid length"));
    }
    if nonce.len() != ATTACHMENT_NONCE_LEN {
        return Err(CoreError::invalid_input("attachment nonce has invalid length"));
    }
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|error| CoreError::invalid_state(format!("failed to initialize attachment cipher: {error}")))?;
    cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext)
        .map_err(|_| CoreError::invalid_input("failed to decrypt attachment blob"))
}

pub fn write_ciphertext_temp(task_id: &str, ciphertext: &[u8]) -> CoreResult<String> {
    let mut path: PathBuf = env::temp_dir();
    let sanitized_task_id: String = task_id
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => ch,
            _ => '_',
        })
        .collect();
    path.push(format!("tapchat-{sanitized_task_id}.blob"));
    fs::write(&path, ciphertext)
        .map_err(|error| CoreError::invalid_state(format!("failed to persist encrypted attachment blob: {error}")))?;
    Ok(path.to_string_lossy().to_string())
}

#[cfg(test)]
mod tests {
    use super::{decrypt_blob, encrypt_blob};

    #[test]
    fn blob_encryption_round_trip_restores_plaintext() {
        let plaintext = b"attachment-bytes";
        let encrypted = encrypt_blob(plaintext).expect("encrypt");
        assert_ne!(encrypted.ciphertext, plaintext);
        let decrypted = decrypt_blob(&encrypted.ciphertext, &encrypted.metadata).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }
}

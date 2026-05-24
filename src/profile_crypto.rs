use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{CoreError, CoreResult};

pub const PROFILE_ENCRYPTION_VERSION: u32 = 1;
pub const SNAPSHOT_FILE_NAME: &str = "snapshot.enc";
pub const LEGACY_SNAPSHOT_FILE_NAME: &str = "snapshot.json";
pub const SNAPSHOT_ALGORITHM: &str = "xchacha20poly1305";
pub const SNAPSHOT_KDF: &str = "hkdf-sha256";
pub const WRAP_ALGORITHM: &str = "xchacha20poly1305";
pub const OS_KEYCHAIN_SERVICE: &str = "TapChat Profile Keys";
pub const PDEK_LEN: usize = 32;
pub const WRAP_KEY_LEN: usize = 32;
const XNONCE_LEN: usize = 24;
const SNAPSHOT_KDF_INFO: &[u8] = b"tapchat/profile/snapshot/v1";
const APP_ID: &str = "tapchat";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileEncryptionMetadata {
    pub version: u32,
    pub snapshot_file: String,
    pub snapshot_algorithm: String,
    pub snapshot_kdf: String,
    pub wrap_algorithm: String,
    #[serde(default)]
    pub wrappers: Vec<ProfileKeyWrapperMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileKeyWrapperMetadata {
    pub id: String,
    pub kind: ProfileKeyWrapperKind,
    pub nonce_b64: String,
    pub wrapped_pdek_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keychain_service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keychain_account: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub salt_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argon2id: Option<Argon2idParamsMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileKeyWrapperKind {
    OsKeychain,
    PassphraseArgon2id,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2idParamsMetadata {
    pub memory_cost_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
    pub output_len: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedSnapshotEnvelope {
    pub version: u32,
    pub algorithm: String,
    pub kdf: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

pub fn default_encryption_metadata(
    wrappers: Vec<ProfileKeyWrapperMetadata>,
) -> ProfileEncryptionMetadata {
    ProfileEncryptionMetadata {
        version: PROFILE_ENCRYPTION_VERSION,
        snapshot_file: SNAPSHOT_FILE_NAME.into(),
        snapshot_algorithm: SNAPSHOT_ALGORITHM.into(),
        snapshot_kdf: SNAPSHOT_KDF.into(),
        wrap_algorithm: WRAP_ALGORITHM.into(),
        wrappers,
    }
}

pub fn generate_pdek() -> Zeroizing<[u8; PDEK_LEN]> {
    let mut pdek = Zeroizing::new([0_u8; PDEK_LEN]);
    rand::thread_rng().fill_bytes(&mut *pdek);
    pdek
}

pub fn generate_wrap_key() -> Zeroizing<[u8; WRAP_KEY_LEN]> {
    let mut key = Zeroizing::new([0_u8; WRAP_KEY_LEN]);
    rand::thread_rng().fill_bytes(&mut *key);
    key
}

pub fn generate_keychain_account(profile_id: &str, wrapper_id: &str) -> String {
    format!("{profile_id}:{wrapper_id}")
}

pub fn build_os_keychain_wrapper(
    profile_id: &str,
    wrapper_id: &str,
    os_kek: &[u8],
    pdek: &[u8],
) -> CoreResult<ProfileKeyWrapperMetadata> {
    let wrapped = wrap_pdek(profile_id, wrapper_id, "os_keychain", os_kek, pdek)?;
    Ok(ProfileKeyWrapperMetadata {
        id: wrapper_id.into(),
        kind: ProfileKeyWrapperKind::OsKeychain,
        nonce_b64: wrapped.nonce_b64,
        wrapped_pdek_b64: wrapped.ciphertext_b64,
        keychain_service: Some(OS_KEYCHAIN_SERVICE.into()),
        keychain_account: Some(generate_keychain_account(profile_id, wrapper_id)),
        salt_b64: None,
        argon2id: None,
    })
}

pub fn build_passphrase_wrapper(
    profile_id: &str,
    wrapper_id: &str,
    passphrase: &str,
    pdek: &[u8],
) -> CoreResult<ProfileKeyWrapperMetadata> {
    let mut salt = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let params = default_argon2id_params();
    let key = derive_passphrase_kek(passphrase, &salt, &params)?;
    let wrapped = wrap_pdek(profile_id, wrapper_id, "passphrase_argon2id", &*key, pdek)?;
    Ok(ProfileKeyWrapperMetadata {
        id: wrapper_id.into(),
        kind: ProfileKeyWrapperKind::PassphraseArgon2id,
        nonce_b64: wrapped.nonce_b64,
        wrapped_pdek_b64: wrapped.ciphertext_b64,
        keychain_service: None,
        keychain_account: None,
        salt_b64: Some(STANDARD.encode(salt)),
        argon2id: Some(params),
    })
}

pub fn unwrap_with_key(
    profile_id: &str,
    wrapper: &ProfileKeyWrapperMetadata,
    key: &[u8],
) -> CoreResult<Zeroizing<[u8; PDEK_LEN]>> {
    let kind = wrapper_kind_label(&wrapper.kind);
    let aad = wrapper_aad(profile_id, &wrapper.id, kind);
    let plaintext = decrypt_aead(key, &wrapper.nonce_b64, &wrapper.wrapped_pdek_b64, aad)?;
    if plaintext.len() != PDEK_LEN {
        return Err(CoreError::invalid_input("wrapped PDEK has invalid length"));
    }
    let mut pdek = Zeroizing::new([0_u8; PDEK_LEN]);
    pdek.copy_from_slice(&plaintext);
    Ok(pdek)
}

pub fn unwrap_with_passphrase(
    profile_id: &str,
    wrapper: &ProfileKeyWrapperMetadata,
    passphrase: &str,
) -> CoreResult<Zeroizing<[u8; PDEK_LEN]>> {
    let salt = wrapper
        .salt_b64
        .as_deref()
        .ok_or_else(|| CoreError::invalid_input("passphrase wrapper is missing salt"))?;
    let salt = STANDARD
        .decode(salt)
        .map_err(|_| CoreError::invalid_input("passphrase wrapper salt must be base64"))?;
    let params = wrapper
        .argon2id
        .as_ref()
        .ok_or_else(|| CoreError::invalid_input("passphrase wrapper is missing argon2 params"))?;
    let key = derive_passphrase_kek(passphrase, &salt, params)?;
    unwrap_with_key(profile_id, wrapper, &*key)
}

pub fn encrypt_snapshot(profile_id: &str, pdek: &[u8], plaintext: &[u8]) -> CoreResult<Vec<u8>> {
    let key = derive_snapshot_key(profile_id, pdek)?;
    let encrypted = encrypt_aead(&*key, plaintext, snapshot_aad(profile_id))?;
    let envelope = EncryptedSnapshotEnvelope {
        version: PROFILE_ENCRYPTION_VERSION,
        algorithm: SNAPSHOT_ALGORITHM.into(),
        kdf: SNAPSHOT_KDF.into(),
        nonce_b64: encrypted.nonce_b64,
        ciphertext_b64: encrypted.ciphertext_b64,
    };
    serde_json::to_vec_pretty(&envelope).map_err(|error| {
        CoreError::invalid_state(format!("failed to serialize encrypted snapshot: {error}"))
    })
}

pub fn decrypt_snapshot(profile_id: &str, pdek: &[u8], bytes: &[u8]) -> CoreResult<Vec<u8>> {
    let envelope: EncryptedSnapshotEnvelope = serde_json::from_slice(bytes).map_err(|error| {
        CoreError::invalid_input(format!("failed to decode encrypted snapshot: {error}"))
    })?;
    if envelope.version != PROFILE_ENCRYPTION_VERSION {
        return Err(CoreError::unsupported(format!(
            "unsupported encrypted snapshot version {}",
            envelope.version
        )));
    }
    if envelope.algorithm != SNAPSHOT_ALGORITHM {
        return Err(CoreError::unsupported(format!(
            "unsupported encrypted snapshot algorithm {}",
            envelope.algorithm
        )));
    }
    if envelope.kdf != SNAPSHOT_KDF {
        return Err(CoreError::unsupported(format!(
            "unsupported encrypted snapshot kdf {}",
            envelope.kdf
        )));
    }
    let key = derive_snapshot_key(profile_id, pdek)?;
    decrypt_aead(
        &*key,
        &envelope.nonce_b64,
        &envelope.ciphertext_b64,
        snapshot_aad(profile_id),
    )
}

pub fn validate_encryption_metadata(metadata: &ProfileEncryptionMetadata) -> CoreResult<()> {
    if metadata.version != PROFILE_ENCRYPTION_VERSION {
        return Err(CoreError::unsupported(format!(
            "unsupported profile encryption version {}",
            metadata.version
        )));
    }
    if metadata.snapshot_algorithm != SNAPSHOT_ALGORITHM {
        return Err(CoreError::unsupported(format!(
            "unsupported snapshot algorithm {}",
            metadata.snapshot_algorithm
        )));
    }
    if metadata.snapshot_kdf != SNAPSHOT_KDF {
        return Err(CoreError::unsupported(format!(
            "unsupported snapshot kdf {}",
            metadata.snapshot_kdf
        )));
    }
    if metadata.wrap_algorithm != WRAP_ALGORITHM {
        return Err(CoreError::unsupported(format!(
            "unsupported wrap algorithm {}",
            metadata.wrap_algorithm
        )));
    }
    if metadata.wrappers.is_empty() {
        return Err(CoreError::invalid_input(
            "profile encryption metadata has no key wrappers",
        ));
    }
    Ok(())
}

fn default_argon2id_params() -> Argon2idParamsMetadata {
    Argon2idParamsMetadata {
        memory_cost_kib: 64 * 1024,
        time_cost: 3,
        parallelism: 1,
        output_len: WRAP_KEY_LEN as u32,
    }
}

fn derive_passphrase_kek(
    passphrase: &str,
    salt: &[u8],
    params: &Argon2idParamsMetadata,
) -> CoreResult<Zeroizing<[u8; WRAP_KEY_LEN]>> {
    if params.output_len != WRAP_KEY_LEN as u32 {
        return Err(CoreError::unsupported(format!(
            "unsupported argon2 output length {}",
            params.output_len
        )));
    }
    let params = Params::new(
        params.memory_cost_kib,
        params.time_cost,
        params.parallelism,
        Some(WRAP_KEY_LEN),
    )
    .map_err(|error| CoreError::invalid_input(format!("invalid argon2 params: {error}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0_u8; WRAP_KEY_LEN]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut *key)
        .map_err(|error| {
            CoreError::invalid_input(format!("failed to derive passphrase key: {error}"))
        })?;
    Ok(key)
}

fn derive_snapshot_key(profile_id: &str, pdek: &[u8]) -> CoreResult<Zeroizing<[u8; WRAP_KEY_LEN]>> {
    let hk = Hkdf::<Sha256>::new(Some(profile_id.as_bytes()), pdek);
    let mut key = Zeroizing::new([0_u8; WRAP_KEY_LEN]);
    hk.expand(SNAPSHOT_KDF_INFO, &mut *key)
        .map_err(|_| CoreError::invalid_state("failed to derive snapshot key"))?;
    Ok(key)
}

struct AeadBlob {
    nonce_b64: String,
    ciphertext_b64: String,
}

fn wrap_pdek(
    profile_id: &str,
    wrapper_id: &str,
    kind: &str,
    key: &[u8],
    pdek: &[u8],
) -> CoreResult<AeadBlob> {
    encrypt_aead(key, pdek, wrapper_aad(profile_id, wrapper_id, kind))
}

fn encrypt_aead(key: &[u8], plaintext: &[u8], aad: Vec<u8>) -> CoreResult<AeadBlob> {
    if key.len() != WRAP_KEY_LEN {
        return Err(CoreError::invalid_input("AEAD key has invalid length"));
    }
    let mut nonce = [0_u8; XNONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|error| {
        CoreError::invalid_state(format!("failed to initialize cipher: {error}"))
    })?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CoreError::invalid_state("failed to encrypt profile payload"))?;
    Ok(AeadBlob {
        nonce_b64: STANDARD.encode(nonce),
        ciphertext_b64: STANDARD.encode(ciphertext),
    })
}

fn decrypt_aead(
    key: &[u8],
    nonce_b64: &str,
    ciphertext_b64: &str,
    aad: Vec<u8>,
) -> CoreResult<Vec<u8>> {
    if key.len() != WRAP_KEY_LEN {
        return Err(CoreError::invalid_input("AEAD key has invalid length"));
    }
    let nonce = STANDARD
        .decode(nonce_b64)
        .map_err(|_| CoreError::invalid_input("profile nonce must be base64"))?;
    if nonce.len() != XNONCE_LEN {
        return Err(CoreError::invalid_input("profile nonce has invalid length"));
    }
    let ciphertext = STANDARD
        .decode(ciphertext_b64)
        .map_err(|_| CoreError::invalid_input("profile ciphertext must be base64"))?;
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|error| {
        CoreError::invalid_state(format!("failed to initialize cipher: {error}"))
    })?;
    cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CoreError::invalid_input("failed to decrypt profile payload"))
}

fn snapshot_aad(profile_id: &str) -> Vec<u8> {
    format!("{APP_ID}|{profile_id}|snapshot|v{PROFILE_ENCRYPTION_VERSION}").into_bytes()
}

fn wrapper_aad(profile_id: &str, wrapper_id: &str, kind: &str) -> Vec<u8> {
    format!("{APP_ID}|{profile_id}|{wrapper_id}|{kind}|pdek-wrap|v{PROFILE_ENCRYPTION_VERSION}")
        .into_bytes()
}

fn wrapper_kind_label(kind: &ProfileKeyWrapperKind) -> &'static str {
    match kind {
        ProfileKeyWrapperKind::OsKeychain => "os_keychain",
        ProfileKeyWrapperKind::PassphraseArgon2id => "passphrase_argon2id",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passphrase_wrapper_round_trips_pdek_and_rejects_wrong_passphrase() {
        let profile_id = "profile:test";
        let pdek = generate_pdek();
        let wrapper = build_passphrase_wrapper(profile_id, "wrapper:test", "correct horse", &*pdek)
            .expect("build wrapper");

        let unwrapped =
            unwrap_with_passphrase(profile_id, &wrapper, "correct horse").expect("unwrap");
        assert_eq!(&*unwrapped, &*pdek);

        let error =
            unwrap_with_passphrase(profile_id, &wrapper, "wrong").expect_err("wrong passphrase");
        assert_eq!(error.code(), "invalid_input");
    }

    #[test]
    fn snapshot_encryption_round_trips_and_hides_plaintext() {
        let profile_id = "profile:test";
        let pdek = generate_pdek();
        let plaintext = br#"{"secret":"visible-marker"}"#;

        let encrypted = encrypt_snapshot(profile_id, &*pdek, plaintext).expect("encrypt");
        assert!(!encrypted
            .windows("visible-marker".len())
            .any(|window| window == b"visible-marker"));

        let decrypted = decrypt_snapshot(profile_id, &*pdek, &encrypted).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrapper_aad_binds_profile_id() {
        let pdek = generate_pdek();
        let os_kek = generate_wrap_key();
        let wrapper =
            build_os_keychain_wrapper("profile:a", "wrapper:a", &*os_kek, &*pdek).expect("wrap");

        let error = unwrap_with_key("profile:b", &wrapper, &*os_kek).expect_err("aad mismatch");
        assert_eq!(error.code(), "invalid_input");
    }
}

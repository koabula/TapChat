//! Epoch-and-direction wrap around MLS frames so the host never sees
//! RFC 9420 PrivateMessage headers.
//!
//! `K(e, dir) = Exporter_e("tapchat.lane-wrap.v1", dir)`. The adapter
//! exports only the current epoch; the previous key is kept on the
//! conversation sidecar to match `max_past_epochs(1)`.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;

use crate::error::{CoreError, CoreResult};

pub const LANE_WRAP_LABEL: &str = "tapchat.lane-wrap.v1";
pub const WRAP_DIR_C1: u8 = 0x00;
pub const WRAP_DIR_C2: u8 = 0x01;
pub const WRAP_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

pub fn wrap_frame(key: &[u8; WRAP_KEY_LEN], frame: &[u8]) -> CoreResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), frame)
        .map_err(|_| CoreError::invalid_state("lane wrap encrypt failed"))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn unwrap_frame(key: &[u8; WRAP_KEY_LEN], wrapped: &[u8]) -> Option<Vec<u8>> {
    if wrapped.len() <= NONCE_LEN {
        return None;
    }
    let (nonce_bytes, ciphertext) = wrapped.split_at(NONCE_LEN);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .ok()
}

pub fn unwrap_with_cached_keys(
    current: &[u8; WRAP_KEY_LEN],
    previous: Option<&[u8; WRAP_KEY_LEN]>,
    wrapped: &[u8],
) -> Option<Vec<u8>> {
    unwrap_frame(current, wrapped).or_else(|| previous.and_then(|key| unwrap_frame(key, wrapped)))
}

pub fn key_from_exporter(bytes: &[u8]) -> CoreResult<[u8; WRAP_KEY_LEN]> {
    bytes
        .try_into()
        .map_err(|_| CoreError::invalid_state("lane wrap exporter returned the wrong length"))
}

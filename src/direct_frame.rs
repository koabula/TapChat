use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{CoreError, CoreResult};

/// The plaintext protected by the epoch-derived lane wrap for every direct
/// MLS protocol frame.  A single mandatory shape keeps old bare-MLS frames
/// from being accepted accidentally after the authentication boundary moved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectWrappedFrame {
    pub mls_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_proof: Option<DirectCommitProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectCommitProof {
    pub sender_user_id: String,
    pub sender_device_id: String,
    pub base_epoch: u64,
    pub signature: String,
}

/// A commit whose detached proof has been checked against both the local
/// identity graph and the matching MLS member leaf key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthenticatedDirectCommit {
    pub base_epoch: u64,
    pub commit_hash: String,
}

pub(crate) fn encode(frame: &DirectWrappedFrame) -> CoreResult<Vec<u8>> {
    serde_json::to_vec(frame)
        .map_err(|error| CoreError::invalid_input(format!("direct frame encode failed: {error}")))
}

pub(crate) fn decode(bytes: &[u8]) -> CoreResult<DirectWrappedFrame> {
    serde_json::from_slice(bytes)
        .map_err(|error| CoreError::invalid_input(format!("direct frame decode failed: {error}")))
}

pub(crate) fn commit_sha256(payload_b64: &str) -> CoreResult<[u8; 32]> {
    let bytes = STANDARD
        .decode(payload_b64.trim())
        .map_err(|_| CoreError::invalid_input("invalid base64 MLS commit payload"))?;
    Ok(Sha256::digest(bytes).into())
}

pub(crate) fn commit_hash(digest: &[u8; 32]) -> String {
    format!("sha256:{}", hex(digest))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

//! The plaintext protected by the epoch-derived lane wrap on the 1:1 path.
//!
//! A tag, and then the MLS message:
//!
//! ```text
//! 0x00 || MLS bytes                    every frame but a commit
//! 0x01 || signature(64) || MLS bytes   a commit
//! ```
//!
//! This replaces a JSON object carrying the same two things. That object held
//! the MLS message as base64, so every frame paid a third of its own size to
//! make room for a field only a commit ever uses; the message now goes in as
//! bytes, and the envelope base64s the wrapped result once on the way out.
//!
//! The tag is not a proof of anything. It distinguishes the two shapes, and a
//! byte string that was never a frame — a bare MLS message, say — will parse
//! into bytes that do not classify as an MLS message, which is where the
//! caller refuses it.
//!
//! # Why a commit carries a signature at all
//!
//! Rotation is unilateral: a party commits a self-update whenever it likes,
//! merging it in the same step, because healing that waits on the counterparty
//! is not healing. So both parties can commit against the same epoch, and one
//! of them has to lose. The loser tears its session down and rebuilds.
//!
//! By the time the rival commit arrives, the local group has already moved to
//! the next epoch, and MLS will not process a handshake message for a
//! superseded epoch — the check is against the current group context and it
//! runs before decryption, so the retained past-epoch secrets do not help.
//! Nothing inside the group can say who sent the rival commit, or that anyone
//! did. Arbitration therefore acts on evidence MLS cannot authenticate, and
//! without a signature a stale wrap key would be enough to force a rebuild at
//! will: the frame need not be a valid commit, only a syntactic one at the
//! right epoch.
//!
//! The alternative — keeping a pre-rotation snapshot of the group so the rival
//! can be validated at its own epoch — retains the leaf private key the
//! rotation exists to destroy, for exactly as long as the race window. That
//! trades a security parameter for frame overhead.
//!
//! # What the signature does not carry
//!
//! No names. The signed payload still binds the author's user and device, so a
//! proof made for one device cannot be lifted onto another's commit, but none
//! of it travels: a two-party conversation has one counterparty, the recipient
//! already holds its device keys, and the arbitration verdict is a function of
//! the epoch and the commit's own hash. The epoch and hash are likewise read
//! back off the frame rather than sent beside it.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use sha2::{Digest, Sha256};

use crate::error::{CoreError, CoreResult};

/// Ed25519, so a fixed width and no length prefix.
pub(crate) const COMMIT_SIGNATURE_LEN: usize = 64;

const TAG_PLAIN: u8 = 0x00;
const TAG_COMMIT: u8 = 0x01;

/// A commit whose detached signature has been checked against both the local
/// identity graph and the matching MLS member leaf key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthenticatedDirectCommit {
    pub base_epoch: u64,
    pub commit_hash: String,
}

pub(crate) fn encode(
    mls_b64: &str,
    commit_signature: Option<&[u8; COMMIT_SIGNATURE_LEN]>,
) -> CoreResult<Vec<u8>> {
    // The MLS message goes in as bytes. It is base64 everywhere else in the
    // engine, and carrying it that way here would have cost a third of every
    // frame for nothing: the wrap takes bytes and the envelope base64s the
    // result once, on the way out.
    let mls = STANDARD
        .decode(mls_b64.trim())
        .map_err(|_| CoreError::invalid_input("invalid base64 MLS payload"))?;
    let mut out = Vec::with_capacity(1 + COMMIT_SIGNATURE_LEN + mls.len());
    match commit_signature {
        None => out.push(TAG_PLAIN),
        Some(signature) => {
            out.push(TAG_COMMIT);
            out.extend_from_slice(signature);
        }
    }
    out.extend_from_slice(&mls);
    Ok(out)
}

/// The MLS payload and, for a commit, the signature that came with it.
///
/// Total and failing closed: an empty plaintext, an unknown tag, or a commit
/// shorter than its own signature is a rejection rather than a partial parse.
pub(crate) fn decode(bytes: &[u8]) -> CoreResult<(String, Option<[u8; COMMIT_SIGNATURE_LEN]>)> {
    let invalid = || CoreError::invalid_input("direct frame is malformed");
    let (&tag, rest) = bytes.split_first().ok_or_else(invalid)?;
    match tag {
        TAG_PLAIN => Ok((STANDARD.encode(rest), None)),
        TAG_COMMIT => {
            if rest.len() < COMMIT_SIGNATURE_LEN {
                return Err(invalid());
            }
            let (signature, mls) = rest.split_at(COMMIT_SIGNATURE_LEN);
            let mut fixed = [0_u8; COMMIT_SIGNATURE_LEN];
            fixed.copy_from_slice(signature);
            Ok((STANDARD.encode(mls), Some(fixed)))
        }
        _ => Err(invalid()),
    }
}

/// The signing API speaks hex; the frame carries the bytes.
pub(crate) fn signature_from_hex(signature_hex: &str) -> CoreResult<[u8; COMMIT_SIGNATURE_LEN]> {
    let bytes = signature_hex.as_bytes();
    if bytes.len() != COMMIT_SIGNATURE_LEN * 2 {
        return Err(CoreError::invalid_input("commit signature is not 64 bytes"));
    }
    let mut out = [0_u8; COMMIT_SIGNATURE_LEN];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        let digit = |byte: u8| match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(CoreError::invalid_input("commit signature is not hex")),
        };
        out[index] = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Ok(out)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_frame_round_trips_without_a_signature() {
        let (mls, signature) = decode(&encode("bWxz", None).expect("encode")).expect("decode");
        assert_eq!(mls, "bWxz");
        assert_eq!(signature, None);
    }

    #[test]
    fn a_commit_frame_round_trips_its_signature() {
        let signature = [7_u8; COMMIT_SIGNATURE_LEN];
        let (mls, decoded) =
            decode(&encode("bWxz", Some(&signature)).expect("encode")).expect("decode");
        assert_eq!(mls, "bWxz");
        assert_eq!(decoded, Some(signature));
    }

    #[test]
    fn a_malformed_frame_is_refused_rather_than_partially_parsed() {
        assert!(decode(&[]).is_err(), "empty");
        assert!(decode(&[0x02, 1, 2, 3]).is_err(), "unknown tag");
        assert!(
            decode(&[TAG_COMMIT; COMMIT_SIGNATURE_LEN]).is_err(),
            "commit shorter than its own signature"
        );
    }

    #[test]
    fn a_commit_signature_survives_only_as_the_bytes_that_were_signed() {
        let signature = [0xAB_u8; COMMIT_SIGNATURE_LEN];
        let frame = encode("bWxzIG1lc3NhZ2U=", Some(&signature)).expect("encode");
        // Tag, signature, message: nothing between them to disagree about.
        assert_eq!(frame[0], TAG_COMMIT);
        assert_eq!(&frame[1..=COMMIT_SIGNATURE_LEN], &signature);
        assert_eq!(
            frame.len(),
            1 + COMMIT_SIGNATURE_LEN + STANDARD.decode("bWxzIG1lc3NhZ2U=").unwrap().len()
        );
    }
}

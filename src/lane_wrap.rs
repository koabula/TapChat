//! Epoch-and-direction wrap around MLS frames so the host never sees
//! RFC 9420 PrivateMessage headers, and cannot tell 1:1 record kinds apart by
//! their length.
//!
//! `K(e, dir) = Exporter_e("tapchat.lane-wrap.v1", dir)` for every frame but
//! a commit, `K_c(e, dir) = Exporter_e("tapchat.commit-wrap.v1", dir)` for a
//! commit. The adapter exports only the current epoch; the previous epoch's
//! keys are kept on the conversation sidecar to match `max_past_epochs(1)`.
//!
//! On the wire:
//!
//! ```text
//! nonce(12) || ChaCha20-Poly1305(K, frame || 0x80 || 0x00*)
//! ```
//!
//! The zeros run until the whole output, nonce and 16-byte tag included, is
//! the smallest positive multiple of [`WRAP_BLOCK`]. A frame of up to
//! [`MAX_ONE_BLOCK_FRAME`] bytes therefore travels as exactly one block,
//! whatever kind of record it is, so a short message, a rotation commit, a
//! rebuild Welcome and `ContactAccepted` cannot be told apart by length. A
//! longer frame shows the host its block count and nothing finer. The `0x80`
//! marks where the frame ends, because a `direct_frame` runs to the end of its
//! plaintext and may itself end in zero bytes. A wrapped payload of any other
//! length is refused unopened.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;

use crate::error::{CoreError, CoreResult};

pub const LANE_WRAP_LABEL: &str = "tapchat.lane-wrap.v1";
/// Commits travel under a key of their own, `K_c(e, dir)`. A receiver keeps
/// the one for each peer commit it merged (`direct_fork`); drawn from the same
/// exporter as the frame key, it would open every frame of that epoch.
pub const COMMIT_WRAP_LABEL: &str = "tapchat.commit-wrap.v1";
pub const WRAP_DIR_C1: u8 = 0x00;
pub const WRAP_DIR_C2: u8 = 0x01;
pub const WRAP_KEY_LEN: usize = 32;
/// Every wrapped frame is a whole number of these bytes, nonce and tag
/// included.
///
/// Must not exceed the inbox's `MAX_INLINE_BYTES` (4096 by default, see
/// `services/cloudflare/src/inbox/durable.ts`): the inbox keeps a record
/// inline only up to that many decoded bytes, so a larger block would spill
/// every record to R2.
pub const WRAP_BLOCK: usize = 4096;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// Ends the frame inside the padded plaintext; only zeros may follow it.
const PAD_MARKER: u8 = 0x80;
/// The bytes a wrap adds to a frame before padding: nonce, tag and marker.
const WRAP_OVERHEAD: usize = NONCE_LEN + TAG_LEN + 1;
/// The longest frame that still travels as a single block.
pub const MAX_ONE_BLOCK_FRAME: usize = WRAP_BLOCK - WRAP_OVERHEAD;

const _: () = assert!(WRAP_BLOCK > WRAP_OVERHEAD);

pub fn wrap_frame(key: &[u8; WRAP_KEY_LEN], frame: &[u8]) -> CoreResult<Vec<u8>> {
    let too_long = || CoreError::invalid_input("lane wrap frame is too long to pad");
    let blocks = frame
        .len()
        .checked_add(WRAP_OVERHEAD)
        .and_then(|unpadded| unpadded.checked_add(WRAP_BLOCK - 1))
        .map(|rounded_up| rounded_up / WRAP_BLOCK)
        .ok_or_else(too_long)?;
    let total = blocks.checked_mul(WRAP_BLOCK).ok_or_else(too_long)?;
    // `total >= WRAP_BLOCK > NONCE_LEN + TAG_LEN`, so this cannot underflow.
    let padded_len = total - NONCE_LEN - TAG_LEN;
    let mut plaintext = Vec::with_capacity(padded_len);
    plaintext.extend_from_slice(frame);
    plaintext.push(PAD_MARKER);
    plaintext.resize(padded_len, 0);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_slice())
        .map_err(|_| CoreError::invalid_state("lane wrap encrypt failed"))?;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    debug_assert_eq!(out.len(), total);
    Ok(out)
}

pub fn unwrap_frame(key: &[u8; WRAP_KEY_LEN], wrapped: &[u8]) -> Option<Vec<u8>> {
    // Every wrap is a whole number of blocks, so any other length was not made
    // by `wrap_frame` and is refused without decrypting.
    if wrapped.len() < WRAP_BLOCK || wrapped.len() % WRAP_BLOCK != 0 {
        return None;
    }
    let (nonce_bytes, ciphertext) = wrapped.split_at(NONCE_LEN);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    // Authenticate first and only then look at the padding. The padding of a
    // plaintext that failed authentication is never examined, so whether and
    // how the padding check fails tells a forger nothing: there is no padding
    // oracle. Keep this order.
    let mut plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .ok()?;
    let marker = plaintext.iter().rposition(|byte| *byte != 0)?;
    if plaintext[marker] != PAD_MARKER {
        return None;
    }
    plaintext.truncate(marker);
    Some(plaintext)
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

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; WRAP_KEY_LEN] = [0x42; WRAP_KEY_LEN];
    const B: usize = WRAP_BLOCK;

    /// A frame that ends in the two byte values the unpadding looks for, the
    /// marker and then zeros, so that unpadding which ate into the frame
    /// would fail the round trip.
    fn frame(len: usize) -> Vec<u8> {
        let mut frame: Vec<u8> = (0..len).map(|index| (index % 251) as u8 + 1).collect();
        let tail = [PAD_MARKER, 0x00, 0x00];
        let from = len.saturating_sub(tail.len());
        frame[from..].copy_from_slice(&tail[..len - from]);
        frame
    }

    /// `nonce || ChaCha20-Poly1305(KEY, plaintext)` with no padding applied:
    /// how a forger holding the key, or an older wrap, would build a payload.
    fn seal(plaintext: &[u8]) -> Vec<u8> {
        let nonce = [7_u8; NONCE_LEN];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&KEY));
        let sealed = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .expect("seal");
        [nonce.as_slice(), sealed.as_slice()].concat()
    }

    /// The plaintext length that makes a sealed payload exactly `blocks`
    /// blocks long.
    fn sealed_plaintext_len(blocks: usize) -> usize {
        blocks * B - NONCE_LEN - TAG_LEN
    }

    #[test]
    fn a_frame_survives_the_wrap_at_every_block_boundary() {
        for len in [0, 1, B - 29, B - 28, 2 * B - 29, 2 * B - 28, 100_000] {
            let frame = frame(len);
            let wrapped = wrap_frame(&KEY, &frame).expect("wrap");
            assert_eq!(
                unwrap_frame(&KEY, &wrapped).as_deref(),
                Some(frame.as_slice()),
                "a frame of {len} bytes"
            );
        }
    }

    #[test]
    fn the_wrap_is_the_fewest_whole_blocks_that_hold_the_frame() {
        assert_eq!(MAX_ONE_BLOCK_FRAME, B - 29);
        for len in [0, 1, 2, 64, 1000, B - 30, B - 29] {
            assert_eq!(
                wrap_frame(&KEY, &frame(len)).expect("wrap").len(),
                B,
                "a frame of {len} bytes fits one block"
            );
        }
        for (len, blocks) in [(B - 28, 2), (2 * B - 29, 2), (100_000, 25)] {
            assert_eq!(
                wrap_frame(&KEY, &frame(len)).expect("wrap").len(),
                blocks * B,
                "a frame of {len} bytes"
            );
        }
        for len in (0..3 * B).step_by(97) {
            let wrapped = wrap_frame(&KEY, &frame(len)).expect("wrap");
            assert_eq!(wrapped.len() % B, 0, "a frame of {len} bytes");
            assert!(
                wrapped.len() >= len + 29 && wrapped.len() - B < len + 29,
                "a frame of {len} bytes took {} bytes",
                wrapped.len()
            );
        }
    }

    #[test]
    fn a_length_that_is_not_a_whole_number_of_blocks_is_refused() {
        let wrapped = wrap_frame(&KEY, b"frame").expect("wrap");
        let mut longer = wrapped.clone();
        longer.push(0);
        assert_eq!(unwrap_frame(&KEY, &longer), None, "one byte over a block");

        let two_blocks = wrap_frame(&KEY, &frame(B)).expect("wrap");
        assert_eq!(two_blocks.len(), 2 * B);
        assert_eq!(
            unwrap_frame(&KEY, &two_blocks[..2 * B - 1]),
            None,
            "one byte short of two blocks"
        );
        // Authentic under the key and correctly padded, but a length between
        // blocks: refused on its length alone.
        let mut plaintext = b"frame".to_vec();
        plaintext.push(PAD_MARKER);
        plaintext.resize(B + 6, 0);
        let between = seal(&plaintext);
        assert_eq!(between.len(), B + 34);
        assert_eq!(unwrap_frame(&KEY, &between), None);
    }

    #[test]
    fn a_length_shorter_than_one_block_is_refused() {
        let wrapped = wrap_frame(&KEY, b"frame").expect("wrap");
        for len in [0, 1, NONCE_LEN, NONCE_LEN + TAG_LEN, 29, B / 2, B - 1] {
            assert_eq!(unwrap_frame(&KEY, &wrapped[..len]), None, "{len} bytes");
        }
        // An unpadded wrap, the layout before padding, opens under the key and
        // is still refused.
        let unpadded = seal(b"frame");
        assert!(unpadded.len() < B);
        assert_eq!(unwrap_frame(&KEY, &unpadded), None);
    }

    #[test]
    fn a_hand_padded_plaintext_opens_so_the_refusals_below_are_not_vacuous() {
        let mut plaintext = b"frame".to_vec();
        plaintext.push(PAD_MARKER);
        plaintext.resize(sealed_plaintext_len(1), 0);
        assert_eq!(
            unwrap_frame(&KEY, &seal(&plaintext)).as_deref(),
            Some(b"frame".as_slice())
        );
    }

    #[test]
    fn an_authentic_plaintext_without_the_marker_is_refused() {
        // Ends in a byte that is neither zero nor the marker.
        let mut no_marker = vec![0x01_u8; sealed_plaintext_len(1)];
        assert_eq!(unwrap_frame(&KEY, &seal(&no_marker)), None, "no padding");
        // Zero padding after something other than the marker.
        no_marker[100] = 0x7f;
        no_marker[101..].fill(0);
        assert_eq!(unwrap_frame(&KEY, &seal(&no_marker)), None, "not 0x80");
        // Two blocks, so the check is not confined to the first.
        let two = vec![0x01_u8; sealed_plaintext_len(2)];
        assert_eq!(unwrap_frame(&KEY, &seal(&two)), None, "two blocks");
    }

    #[test]
    fn an_authentic_all_zero_plaintext_is_refused() {
        for blocks in [1, 2] {
            let zeros = vec![0_u8; sealed_plaintext_len(blocks)];
            assert_eq!(unwrap_frame(&KEY, &seal(&zeros)), None, "{blocks} blocks");
        }
    }

    #[test]
    fn a_tampered_or_misaddressed_wrap_is_refused() {
        let wrapped = wrap_frame(&KEY, b"frame").expect("wrap");
        assert!(unwrap_frame(&KEY, &wrapped).is_some());
        // Nonce, the frame, the padding, the tag.
        for at in [0, NONCE_LEN, NONCE_LEN + 5, B / 2, B - 1] {
            let mut tampered = wrapped.clone();
            tampered[at] ^= 0x01;
            assert_eq!(unwrap_frame(&KEY, &tampered), None, "bit flipped at {at}");
        }
        let other = [0x43; WRAP_KEY_LEN];
        assert_eq!(unwrap_frame(&other, &wrapped), None, "wrong key");
        assert_eq!(
            unwrap_with_cached_keys(&other, Some(&KEY), &wrapped).as_deref(),
            Some(b"frame".as_slice()),
            "the previous epoch's key still opens it"
        );
    }
}

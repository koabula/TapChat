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
//!
//! That padding sits outside MLS, so whoever holds a wrap key sees, under it,
//! each MLS message's exact length. An application message is therefore
//! padded inside MLS as well, before it is encrypted
//! ([`pad_application_plaintext`]), to a length that leaves the frame exactly
//! a whole number of blocks: the wrap's own padding then adds only the few
//! bytes the MLS overhead fell short of its bound, and under the wrap key the
//! frame shows the block count and nothing finer. Commits and Welcomes are not
//! padded this way.

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

/// The longest MLS group id [`APPLICATION_RESERVE`] makes room for. A 1:1
/// group id is the conversation id, 32 hex characters (`random_opaque_id`).
/// A conversation can send only once it has lanes, and it gets them only when
/// created under such an id or by joining a Welcome, which `inspect_welcome`
/// refuses unless the group id has that shape. An older `conv:{user}:{user}`
/// conversation (80 bytes) has no lanes, so none of its frames is ever sent.
pub const MAX_DIRECT_GROUP_ID_LEN: usize = 64;

/// The most an MLS application message can add to its plaintext, under the
/// one ciphersuite in use (`DEFAULT_CIPHERSUITE`: AES-128-GCM, Ed25519), with
/// every variable-length prefix at its largest (RFC 9420 §6, §6.3). Outside
/// the content's encryption: the MLSMessage version and wire format (4), the
/// group id with a 2-byte prefix, the epoch (8), the content type (1), an
/// empty authenticated data (1), and the encrypted sender data with its
/// prefix (1 + leaf index, generation and reuse guard 12 + tag).
const MLS_HEADER_MAX: usize = 4 + 2 + MAX_DIRECT_GROUP_ID_LEN + 8 + 1 + 1 + 1 + 12 + TAG_LEN;
/// Inside it: the ciphertext's prefix and the application data's prefix (4
/// each at their largest), the Ed25519 signature with its prefix (2 + 64: a
/// 1-byte prefix covers lengths 0 to 63 only) and the tag. There is no
/// padding there: OpenMLS's `padding_size` stays 0.
const MLS_CONTENT_MAX: usize = 4 + 4 + 2 + 64 + TAG_LEN;
const MLS_APPLICATION_OVERHEAD: usize = MLS_HEADER_MAX + MLS_CONTENT_MAX;

/// The `direct_frame` tag of a frame that is not a commit.
const PLAIN_FRAME_TAG_LEN: usize = 1;

/// The constant C: every 1:1 application plaintext handed to MLS is padded to
/// `WRAP_BLOCK * k - APPLICATION_RESERVE` bytes for the smallest whole `k >= 1`
/// that holds it, by [`pad_application_plaintext`]. The reserve covers the
/// largest MLS overhead, the frame tag and the wrap's own overhead, so the
/// wrapped frame then fills exactly `k` blocks and its length shows `k` and
/// nothing else, even to a holder of the wrap key.
pub const APPLICATION_RESERVE: usize =
    MLS_APPLICATION_OVERHEAD + PLAIN_FRAME_TAG_LEN + WRAP_OVERHEAD;

/// The longest application plaintext, before padding, that still travels as
/// a single block: one block less the reserve and the padding marker.
pub const MAX_ONE_BLOCK_APPLICATION: usize = WRAP_BLOCK - APPLICATION_RESERVE - 1;

const _: () = assert!(WRAP_BLOCK > APPLICATION_RESERVE + 1);

/// Pad a 1:1 application plaintext to `WRAP_BLOCK * k - APPLICATION_RESERVE`
/// bytes, the smallest such length above it: the plaintext, the marker `0x80`,
/// then zeros. The same for every application kind, so a message, a lane
/// notice and `ContactAccepted` of one block count are one length.
pub fn pad_application_plaintext(plaintext: &[u8]) -> CoreResult<Vec<u8>> {
    let too_long = || CoreError::invalid_input("application plaintext is too long to pad");
    let blocks = plaintext
        .len()
        .checked_add(1 + APPLICATION_RESERVE)
        .and_then(|unpadded| unpadded.checked_add(WRAP_BLOCK - 1))
        .map(|rounded_up| rounded_up / WRAP_BLOCK)
        .ok_or_else(too_long)?;
    // `blocks >= 1` and `WRAP_BLOCK > APPLICATION_RESERVE`, so no underflow.
    let total = blocks.checked_mul(WRAP_BLOCK).ok_or_else(too_long)?;
    let padded_len = total - APPLICATION_RESERVE;
    let mut padded = Vec::with_capacity(padded_len);
    padded.extend_from_slice(plaintext);
    padded.push(PAD_MARKER);
    padded.resize(padded_len, 0);
    Ok(padded)
}

/// Undo [`pad_application_plaintext`]. `None` for any length it does not
/// produce, or a plaintext whose last nonzero byte is not the marker. Called
/// only on what MLS has already authenticated.
pub fn strip_application_padding(padded: &[u8]) -> Option<&[u8]> {
    if padded.len() < WRAP_BLOCK - APPLICATION_RESERVE
        || (padded.len() + APPLICATION_RESERVE) % WRAP_BLOCK != 0
    {
        return None;
    }
    let marker = padded.iter().rposition(|byte| *byte != 0)?;
    (padded[marker] == PAD_MARKER).then(|| &padded[..marker])
}

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

    // ---- Application padding inside MLS ------------------------------------

    const C: usize = APPLICATION_RESERVE;

    #[test]
    fn the_reserve_is_the_sum_of_its_parts() {
        assert_eq!(MLS_APPLICATION_OVERHEAD, 199);
        assert_eq!(C, 229);
        assert_eq!(MAX_ONE_BLOCK_APPLICATION, B - 230);
    }

    #[test]
    fn every_padded_plaintext_is_a_whole_number_of_blocks_less_the_reserve() {
        let mut lens: Vec<usize> = (0..5 * B).step_by(61).collect();
        for k in 1..=5 {
            // Either side of the last length that still fits k blocks.
            lens.extend([k * B - C - 2, k * B - C - 1, k * B - C]);
        }
        lens.extend([62, 63, 64, 16_382, 16_383, 16_384, 16_385, 100_000]);
        for len in lens {
            let padded = pad_application_plaintext(&frame(len)).expect("pad");
            let k = (len + 1 + C).div_ceil(B);
            assert_eq!(padded.len(), k * B - C, "a plaintext of {len} bytes");
            assert_eq!(
                strip_application_padding(&padded),
                Some(frame(len).as_slice()),
                "a plaintext of {len} bytes"
            );
        }
        let one = MAX_ONE_BLOCK_APPLICATION;
        assert_eq!(pad_application_plaintext(b"").unwrap().len(), B - C);
        assert_eq!(pad_application_plaintext(&frame(one)).unwrap().len(), B - C);
        let spilled = pad_application_plaintext(&frame(one + 1)).unwrap();
        assert_eq!(spilled.len(), 2 * B - C);
    }

    #[test]
    fn only_a_padded_plaintext_strips() {
        let padded = pad_application_plaintext(b"{}").expect("pad");
        assert_eq!(strip_application_padding(&padded), Some(b"{}".as_slice()));
        assert_eq!(strip_application_padding(b"{}"), None, "unpadded");
        assert_eq!(strip_application_padding(&padded[1..]), None, "one short");
        let mut longer = padded.clone();
        longer.push(0);
        assert_eq!(strip_application_padding(&longer), None, "one over");
        let zeros = vec![0_u8; B - C];
        assert_eq!(strip_application_padding(&zeros), None, "all zeros");
        let mut no_marker = zeros.clone();
        no_marker[10] = 0x7f;
        assert_eq!(strip_application_padding(&no_marker), None, "no marker");
        let mut two = vec![0x01_u8; 2 * B - C];
        two[B] = PAD_MARKER;
        two[B + 1..].fill(0);
        assert_eq!(strip_application_padding(&two).map(<[u8]>::len), Some(B));
    }

    mod through_mls {
        use super::*;

        use crate::identity::IdentityManager;
        use crate::mls_adapter::{IngestResult, MlsAdapter, PeerDeviceKeyPackage, WelcomeAuthor};
        use crate::model::{MessageType, ProtectedAppMessage, ProtectedPayloadKind};

        use base64::{engine::general_purpose::STANDARD, Engine as _};

        /// Alice and Bob in a 1:1 group whose id is `conversation_id`.
        fn pair(conversation_id: &str) -> (MlsAdapter, MlsAdapter) {
            let alice = IdentityManager::create_or_recover(None, None).unwrap();
            let bob = IdentityManager::create_or_recover(None, None).unwrap();
            let (mut alice_adapter, _) = MlsAdapter::bootstrap(&alice).expect("alice adapter");
            let (mut bob_adapter, bob_package) = MlsAdapter::bootstrap(&bob).expect("bob adapter");
            let artifacts = alice_adapter
                .create_conversation(
                    conversation_id,
                    &[PeerDeviceKeyPackage {
                        user_id: bob.user_identity.user_id.clone(),
                        device_id: bob.device_identity.device_id.clone(),
                        device_public_key: bob.device_identity.device_public_key.clone(),
                        key_package_b64: bob_package.key_package_b64,
                    }],
                )
                .expect("create conversation");
            bob_adapter
                .ingest_welcome(
                    conversation_id,
                    &WelcomeAuthor {
                        device_id: alice.device_identity.device_id.clone(),
                        device_public_key: alice.device_identity.device_public_key.clone(),
                    },
                    &artifacts.welcomes[0].payload_b64,
                )
                .expect("welcome");
            let _ = bob_adapter
                .ingest_message(
                    conversation_id,
                    MessageType::MlsCommit,
                    &artifacts.commit_b64,
                )
                .expect("genesis commit");
            (alice_adapter, bob_adapter)
        }

        /// What the 1:1 send path puts on the wire for an unpadded plaintext,
        /// and the MLS message inside it.
        fn send(
            alice: &mut MlsAdapter,
            conversation_id: &str,
            plaintext: &[u8],
        ) -> (Vec<u8>, String) {
            let padded = pad_application_plaintext(plaintext).expect("pad");
            let mls = alice
                .encrypt_application(conversation_id, &padded)
                .expect("encrypt")
                .payload_b64;
            let frame = crate::direct_frame::encode(&mls, None).expect("frame");
            let key = alice
                .export_lane_wrap_key(conversation_id, WRAP_DIR_C1)
                .expect("wrap key");
            (wrap_frame(&key, &frame).expect("wrap"), mls)
        }

        /// A group id as long as the reserve allows, and the production shape.
        fn conversation_ids() -> [String; 2] {
            [
                "g".repeat(MAX_DIRECT_GROUP_ID_LEN),
                crate::model::random_opaque_id(),
            ]
        }

        #[test]
        fn a_padded_plaintext_never_spills_into_another_block() {
            for conversation_id in conversation_ids() {
                let (mut alice, _bob) = pair(&conversation_id);
                // The longest plaintext each k holds, over a range of k and
                // a k past the 4-byte length prefixes.
                let mut lens: Vec<usize> = (1..=8).map(|k| k * B - C - 1).collect();
                lens.push(64 * B - C - 1);
                // Either side of where MLS's length prefixes grow: 63/64 bytes
                // and 16383/16384 bytes, for the application data and for the
                // ciphertext around it.
                for edge in [64_usize, 16_384] {
                    for delta in 0..=200 {
                        lens.push(edge.saturating_sub(delta));
                        lens.push(edge + delta);
                    }
                }
                lens.extend([0, 1, MAX_ONE_BLOCK_APPLICATION]);
                lens.push(MAX_ONE_BLOCK_APPLICATION + 1);
                lens.sort_unstable();
                lens.dedup();
                for len in lens {
                    let (wrapped, mls) = send(&mut alice, &conversation_id, &frame(len));
                    let k = (len + 1 + C).div_ceil(B);
                    assert_eq!(
                        wrapped.len(),
                        k * B,
                        "a plaintext of {len} bytes, group id of {} bytes",
                        conversation_id.len()
                    );
                    let mls_len = STANDARD.decode(&mls).expect("mls").len();
                    let overhead = mls_len - (k * B - C);
                    assert!(
                        overhead <= MLS_APPLICATION_OVERHEAD,
                        "MLS added {overhead} bytes to {len}"
                    );
                    // At the largest group id and with both 4-byte prefixes,
                    // the bound is met exactly: the test checks the bound,
                    // not the slack a shorter group id leaves.
                    if conversation_id.len() == MAX_DIRECT_GROUP_ID_LEN && k * B - C >= 16_384 {
                        assert_eq!(overhead, MLS_APPLICATION_OVERHEAD, "at {len} bytes");
                    }
                }
            }
        }

        #[test]
        fn the_smallest_message_is_one_block() {
            let conversation_id = crate::model::random_opaque_id();
            let (mut alice, _bob) = pair(&conversation_id);
            assert_eq!(send(&mut alice, &conversation_id, b"").0.len(), B);
            assert_eq!(send(&mut alice, &conversation_id, b"x").0.len(), B);
        }

        #[test]
        fn pad_encrypt_wrap_unwrap_decrypt_strip_returns_the_message() {
            for conversation_id in conversation_ids() {
                let (mut alice, mut bob) = pair(&conversation_id);
                let one = MAX_ONE_BLOCK_APPLICATION;
                for len in [0, 1, 300, one, one + 1, 3 * B] {
                    let message = frame(len);
                    let (wrapped, _) = send(&mut alice, &conversation_id, &message);
                    let key = bob
                        .export_lane_wrap_key(&conversation_id, WRAP_DIR_C1)
                        .expect("wrap key");
                    let opened = unwrap_frame(&key, &wrapped).expect("unwrap");
                    let (mls, signature) = crate::direct_frame::decode(&opened).expect("frame");
                    assert_eq!(signature, None);
                    let application = match bob
                        .ingest_message(&conversation_id, MessageType::MlsApplication, &mls)
                        .expect("decrypt")
                    {
                        IngestResult::AppliedApplication(application) => application,
                        other => panic!("expected an application, got {other:?}"),
                    };
                    let padded_len = (len + 1 + C).div_ceil(B) * B - C;
                    assert_eq!(application.plaintext.len(), padded_len);
                    assert_eq!(
                        strip_application_padding(&application.plaintext),
                        Some(message.as_slice()),
                        "a message of {len} bytes"
                    );
                }
            }
        }

        /// The protected payload of `kind` as the send path serializes it.
        /// Built unchecked: a real lane notice carries a signed identity
        /// bundle, and only its length matters here.
        fn protected(kind: ProtectedPayloadKind, body: String) -> Vec<u8> {
            let conversation_id = crate::model::random_opaque_id();
            let mut message = ProtectedAppMessage::new_text(
                format!("app:{conversation_id}:1:device:alice"),
                conversation_id,
                "user:alice".into(),
                "device:alice".into(),
                "user:bob".into(),
                vec!["device:bob".into()],
                "placeholder".into(),
                1_700_000_000_000,
            )
            .expect("protected");
            message.payload_kind = kind;
            message.body = body;
            serde_json::to_vec(&message).expect("json")
        }

        #[test]
        fn kinds_of_one_block_count_give_frames_of_one_length() {
            let text = protected(ProtectedPayloadKind::Text, "hi".into());
            let accepted = protected(ProtectedPayloadKind::ContactAccepted, "{}".into());
            let rotation = protected(
                ProtectedPayloadKind::LaneRotation,
                format!(
                    r#"{{"bundle":{{"devices":["{}"]}},"inbound_lane":"{}"}}"#,
                    "d".repeat(1500),
                    crate::model::random_opaque_id()
                ),
            );
            let conversation_id = crate::model::random_opaque_id();
            let (mut alice, _bob) = pair(&conversation_id);
            let lengths: Vec<(usize, usize)> = [&text, &accepted, &rotation]
                .iter()
                .map(|plaintext| {
                    assert!(plaintext.len() <= MAX_ONE_BLOCK_APPLICATION);
                    let padded = pad_application_plaintext(plaintext).expect("pad").len();
                    let sent = send(&mut alice, &conversation_id, plaintext).0.len();
                    (padded, sent)
                })
                .collect();
            assert_eq!(lengths, vec![(B - C, B); 3]);
        }
    }
}

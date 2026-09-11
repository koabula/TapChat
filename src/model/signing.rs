//! Canonical signing domain for envelope sender proofs.
//!
//! An envelope's `sender_proof` used to be an Ed25519 signature over the
//! base64 `inline_ciphertext` alone. That authenticated the payload but not
//! where it was going or what it claimed to be, so a legitimately signed
//! payload could be re-appended under a different `conversation_id`,
//! `message_id` or `message_type` and would still verify. This module defines
//! the bytes that are signed instead: a domain-separated, length-prefixed
//! encoding of the whole envelope header plus a hash of the payload.
//!
//! Two properties matter.
//!
//! **Injectivity.** Every variable-length field is preceded by its byte
//! length, so no field value can imitate a field boundary and no two distinct
//! envelopes produce the same bytes. This is the structural fix for the class
//! of bug that delimiter-joined signing domains have: with a `|` separator and
//! no escaping, a value containing `|` can shift the frame and forge a
//! different envelope's payload.
//!
//! **Stability across languages.** Field encodings are explicit rather than
//! derived from serde, so the Cloudflare worker can reproduce these bytes
//! exactly. A TypeScript port needs `DataView.setBigUint64` for the 64-bit
//! fields (`size_bytes` is attacker-supplied and a JS `number` silently loses
//! precision past 2^53), `TextEncoder` for UTF-8, and a SHA-256 over the
//! base64 payload text exactly as it appears on the wire.

use sha2::{Digest, Sha256};

use super::{DeliveryClass, Envelope, MessageType, StorageRef};

/// Domain separator. Signed as field zero, itself length-prefixed, so these
/// bytes cannot collide with any other payload signed by the same device key.
pub const ENVELOPE_SENDER_PROOF_DOMAIN: &str = "tapchat.envelope.sender_proof.v2";

/// A length-prefixed byte writer.
///
/// Public so other signing domains can adopt the same framing instead of
/// re-inventing a delimiter scheme.
#[derive(Debug, Default)]
pub struct SigningPayload {
    bytes: Vec<u8>,
}

impl SigningPayload {
    pub fn new(domain: &str) -> Self {
        let mut payload = Self { bytes: Vec::new() };
        payload.push_str(domain);
        payload
    }

    /// A length-prefixed string. `u32` big-endian length, then UTF-8 bytes.
    pub fn push_str(&mut self, value: &str) {
        self.push_bytes(value.as_bytes());
    }

    /// A length-prefixed byte string.
    pub fn push_bytes(&mut self, value: &[u8]) {
        self.bytes
            .extend_from_slice(&(value.len() as u32).to_be_bytes());
        self.bytes.extend_from_slice(value);
    }

    /// A fixed-width 64-bit integer. No length prefix: the width is implicit.
    pub fn push_u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// A fixed-width 32-bit count.
    pub fn push_u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// An optional string, with an explicit presence byte so that `None` and
    /// `Some("")` never encode identically.
    pub fn push_optional_str(&mut self, value: Option<&str>) {
        match value {
            Some(value) => {
                self.bytes.push(1);
                self.push_str(value);
            }
            None => self.bytes.push(0),
        }
    }

    /// An optional 64-bit integer, with an explicit presence byte.
    pub fn push_optional_u64(&mut self, value: Option<u64>) {
        match value {
            Some(value) => {
                self.bytes.push(1);
                self.push_u64(value);
            }
            None => self.bytes.push(0),
        }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl MessageType {
    /// The stable wire name used in signing domains and on the wire.
    ///
    /// An exhaustive match on purpose: adding a variant is a compile error
    /// here rather than a silent change to what every signature covers. Never
    /// use `{:?}` or a serde round-trip for this — `Debug` output is not a
    /// stable format and a `rename_all` attribute can be changed from a
    /// distance.
    pub fn wire_name(&self) -> &'static str {
        match self {
            MessageType::MlsApplication => "mls_application",
            MessageType::MlsCommit => "mls_commit",
            MessageType::MlsProposal => "mls_proposal",
            MessageType::MlsWelcome => "mls_welcome",
            MessageType::ControlDeviceMembershipChanged => "control_device_membership_changed",
            MessageType::ControlIdentityStateUpdated => "control_identity_state_updated",
            MessageType::ControlConversationNeedsRebuild => "control_conversation_needs_rebuild",
            MessageType::ControlContactRemoved => "control_contact_removed",
            MessageType::ControlContactAccepted => "control_contact_accepted",
            MessageType::ControlGroupWelcomePickup => "control_group_welcome_pickup",
            MessageType::ControlGroupStateEvent => "control_group_state_event",
        }
    }
}

impl DeliveryClass {
    pub fn wire_name(&self) -> &'static str {
        match self {
            DeliveryClass::Normal => "normal",
        }
    }
}

fn push_storage_ref(payload: &mut SigningPayload, reference: &StorageRef) {
    payload.push_str(&reference.kind);
    payload.push_str(&reference.object_ref);
    payload.push_u64(reference.size_bytes);
    payload.push_str(&reference.mime_type);
    payload.push_optional_str(reference.file_name.as_deref());
    payload.push_optional_u64(reference.expires_at);
}

/// The exact bytes an envelope's `sender_proof` signs.
///
/// Covers every field of the envelope except `sender_proof` itself. The
/// payload is included as a SHA-256 of the base64 text rather than inline, so
/// the signing input stays a fixed couple of hundred bytes even for a large
/// Welcome or attachment manifest, and so no base64 alphabet or padding
/// ambiguity can arise in a cross-language reimplementation.
///
/// `storage_refs` are signed in transmission order, not sorted: the order is
/// semantically live, since it is copied verbatim into the stored message.
pub fn envelope_sender_proof_payload(envelope: &Envelope) -> Vec<u8> {
    let mut payload = SigningPayload::new(ENVELOPE_SENDER_PROOF_DOMAIN);
    payload.push_str(&envelope.version);
    payload.push_str(&envelope.message_id);
    payload.push_str(&envelope.conversation_id);
    payload.push_str(&envelope.sender_user_id);
    payload.push_str(&envelope.sender_device_id);
    payload.push_str(&envelope.recipient_device_id);
    payload.push_u64(envelope.created_at);
    payload.push_str(envelope.message_type.wire_name());
    payload.push_str(envelope.delivery_class.wire_name());
    match envelope.inline_ciphertext.as_deref() {
        Some(ciphertext) => {
            payload.push_u32(1);
            payload.push_bytes(&Sha256::digest(ciphertext.as_bytes()));
        }
        None => payload.push_u32(0),
    }
    payload.push_u32(envelope.storage_refs.len() as u32);
    for reference in &envelope.storage_refs {
        push_storage_ref(&mut payload, reference);
    }
    payload.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{SenderProof, StorageRef, CURRENT_MODEL_VERSION};

    /// A named field mutation, for the coverage test below.
    type Mutation = (&'static str, Box<dyn Fn(&mut Envelope)>);

    /// SHA-256 of the golden envelope's signing payload. Computed from this
    /// implementation; a TypeScript port must reproduce it byte for byte.
    const GOLDEN_ENVELOPE_DIGEST: &str =
        "4e50c2c241007efcd8a027f988345a6ab227524a87a4b9227a897667b5f12d6e";

    fn envelope() -> Envelope {
        Envelope {
            version: CURRENT_MODEL_VERSION.to_string(),
            message_id: "msg:1".into(),
            conversation_id: "conv:alice:bob".into(),
            sender_user_id: "user:alice".into(),
            sender_device_id: "device:alice:phone".into(),
            recipient_device_id: "device:bob:phone".into(),
            created_at: 1_700_000_000_000,
            message_type: MessageType::MlsApplication,
            inline_ciphertext: Some("Y2lwaGVy".into()),
            storage_refs: Vec::new(),
            delivery_class: DeliveryClass::Normal,
            sender_proof: SenderProof {
                proof_type: "device_signature".into(),
                value: "unsigned".into(),
            },
        }
    }

    /// Every signed field must actually change the bytes. Without this, a
    /// field could silently drop out of the domain during a refactor and the
    /// signature would stop covering it.
    #[test]
    fn every_field_is_covered() {
        let base = envelope_sender_proof_payload(&envelope());

        let mutations: Vec<Mutation> = vec![
            (
                "version",
                Box::new(|e: &mut Envelope| e.version = "0.2".into()),
            ),
            (
                "message_id",
                Box::new(|e: &mut Envelope| e.message_id = "msg:2".into()),
            ),
            (
                "conversation_id",
                Box::new(|e: &mut Envelope| e.conversation_id = "conv:alice:mallory".into()),
            ),
            (
                "sender_user_id",
                Box::new(|e: &mut Envelope| e.sender_user_id = "user:mallory".into()),
            ),
            (
                "sender_device_id",
                Box::new(|e: &mut Envelope| e.sender_device_id = "device:mallory:phone".into()),
            ),
            (
                "recipient_device_id",
                Box::new(|e: &mut Envelope| e.recipient_device_id = "device:carol:phone".into()),
            ),
            ("created_at", Box::new(|e: &mut Envelope| e.created_at += 1)),
            (
                "message_type",
                Box::new(|e: &mut Envelope| {
                    e.message_type = MessageType::ControlConversationNeedsRebuild
                }),
            ),
            (
                "inline_ciphertext",
                Box::new(|e: &mut Envelope| e.inline_ciphertext = Some("b3RoZXI=".into())),
            ),
            (
                "inline_ciphertext absence",
                Box::new(|e: &mut Envelope| e.inline_ciphertext = None),
            ),
            (
                "storage_refs",
                Box::new(|e: &mut Envelope| {
                    e.storage_refs = vec![StorageRef {
                        kind: "attachment".into(),
                        object_ref: "blob:1".into(),
                        size_bytes: 10,
                        mime_type: "image/png".into(),
                        file_name: None,
                        expires_at: None,
                    }]
                }),
            ),
        ];

        for (field, mutate) in mutations {
            let mut mutated = envelope();
            mutate(&mut mutated);
            assert_ne!(
                envelope_sender_proof_payload(&mutated),
                base,
                "{field} is not covered by the signing domain"
            );
        }
    }

    /// `sender_proof` must not sign itself.
    #[test]
    fn sender_proof_is_not_part_of_its_own_domain() {
        let base = envelope_sender_proof_payload(&envelope());
        let mut other = envelope();
        other.sender_proof.value = "something else".into();
        assert_eq!(envelope_sender_proof_payload(&other), base);
    }

    /// The bug that delimiter-joined domains have: two different envelopes
    /// whose fields concatenate to the same string under a `|` separator must
    /// not collide here.
    #[test]
    fn field_boundaries_cannot_be_shifted() {
        let mut left = envelope();
        left.conversation_id = "conv:a".into();
        left.sender_user_id = "b|user:c".into();

        let mut right = envelope();
        right.conversation_id = "conv:a|b".into();
        right.sender_user_id = "user:c".into();

        assert_ne!(
            envelope_sender_proof_payload(&left),
            envelope_sender_proof_payload(&right)
        );
    }

    /// An empty payload and an absent payload are different envelopes.
    #[test]
    fn absent_and_empty_payload_differ() {
        let mut empty = envelope();
        empty.inline_ciphertext = Some(String::new());
        let mut absent = envelope();
        absent.inline_ciphertext = None;
        assert_ne!(
            envelope_sender_proof_payload(&empty),
            envelope_sender_proof_payload(&absent)
        );
    }

    /// Pins the byte layout, so a change that would silently invalidate every
    /// peer's signatures has to be deliberate. Also the vector a TypeScript
    /// port checks itself against.
    #[test]
    fn golden_vector_is_stable() {
        let mut envelope = envelope();
        envelope.storage_refs = vec![
            StorageRef {
                kind: "attachment".into(),
                object_ref: "blob:1".into(),
                size_bytes: 4096,
                mime_type: "image/png".into(),
                file_name: Some("cat.png".into()),
                expires_at: Some(1_700_000_100_000),
            },
            StorageRef {
                kind: "attachment".into(),
                object_ref: "blob:2".into(),
                size_bytes: 0,
                mime_type: "application/octet-stream".into(),
                file_name: None,
                expires_at: None,
            },
        ];
        let digest = Sha256::digest(envelope_sender_proof_payload(&envelope));
        assert_eq!(
            format!("{digest:x}"),
            GOLDEN_ENVELOPE_DIGEST,
            "the envelope signing domain changed; update every implementation \
             of it (Rust and TypeScript) before changing this vector"
        );
    }
}

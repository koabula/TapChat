//! The signing domain registry, and the framing every signature uses.
//!
//! A signature binds a key to a byte string. If the domain is not inside
//! those bytes the domain does not exist, and any two protocols that can
//! produce the same bytes are the same protocol. This project has one
//! signing key per device that signs both MLS handshake messages (under
//! RFC 9420 `SignWithLabel`) and a dozen TapChat payloads, so that is not an
//! abstract concern: the two were kept apart only by the accident that MLS
//! starts with a TLS length prefix and the TapChat payloads started with
//! ASCII. Nothing maintained that property and no test asserted it.
//!
//! So the domain is not something a call site remembers to prepend. A
//! [`SigningPayload`] cannot be constructed without a [`SignatureDomain`],
//! and `LocalIdentityState::sign_payload` accepts nothing else. A signature
//! without a domain has no type that can express it.
//!
//! Three properties matter.
//!
//! **Domain separation.** Every payload begins with its domain, itself
//! length-prefixed, so no domain can be a prefix of another and no payload
//! can imitate one from a different domain. Every signature this module
//! produces begins with a zero byte (the high byte of a `u32` length under
//! 256), while an MLS `SignContent` begins with the varint length of a label
//! that is never empty — the mutual exclusion is now structural.
//!
//! **Injectivity.** Every variable-length field is preceded by its byte
//! length, so no field value can imitate a field boundary and no two distinct
//! messages produce the same bytes. This is the structural fix for the class
//! of bug that delimiter-joined signing domains have: with a `|` separator and
//! no escaping, a value containing `|` can shift the frame and forge a
//! different message's payload. Not every domain's body is injective yet —
//! the ones still carrying a delimiter-joined body are noted at their call
//! sites — but every domain is at least separated from every other.
//!
//! **Stability across languages.** Field encodings are explicit rather than
//! derived from serde, so the Cloudflare worker can reproduce these bytes
//! exactly. A TypeScript port needs `DataView.setBigUint64` for the 64-bit
//! fields (`size_bytes` is attacker-supplied and a JS `number` silently loses
//! precision past 2^53), `TextEncoder` for UTF-8, and a SHA-256 over the
//! base64 payload text exactly as it appears on the wire. The port lives in
//! `services/cloudflare/src/auth/signing-payload.ts`.

use sha2::{Digest, Sha256};

use super::{
    GroupEnvelope, GroupEnvelopeVisibility, GroupMessageType, MessageType, StorageRef,
};

/// Every payload this project signs, outside MLS.
///
/// MLS signs under RFC 9420 `SignWithLabel` and is therefore not listed here;
/// that is the one signing path the device key takes without going through
/// [`SigningPayload`], and it is documented at its single call site in
/// `mls_adapter`.
///
/// The string form is an exhaustive match on purpose: a new payload cannot be
/// added without naming its domain, the same way a new `MessageType` cannot be
/// added without naming its wire form. Never derive these from `Debug` or a
/// serde round-trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureDomain {
    // Signed by the device key.
    GroupEnvelopeSenderProof,
    GroupManifest,
    GroupMembershipProof,
    GroupCapability,
    InboxAppendCapability,
    DeviceRuntimeAuth,
    WelcomePickupToken,
    GroupInviteToken,
    GroupJoinRequestToken,
    GroupJoinRequestSignature,
    GroupLeaveRequestToken,
    GroupLeaveRequestSignature,
    // Signed by the user root key.
    DeviceBinding,
    IdentityBundle,
}

impl SignatureDomain {
    /// The stable domain string. Version suffixes are historical and are kept
    /// verbatim where they already existed; they are not parsed anywhere and
    /// carry no negotiation.
    pub fn as_str(&self) -> &'static str {
        match self {
            SignatureDomain::GroupEnvelopeSenderProof => "tapchat.group_envelope.sender_proof.v1",
            SignatureDomain::GroupManifest => "tapchat.group_manifest.v1",
            SignatureDomain::GroupMembershipProof => "tapchat.group.membership.v1",
            SignatureDomain::GroupCapability => "tapchat.group_capability.v2",
            SignatureDomain::InboxAppendCapability => "tapchat.inbox_append_capability.v1",
            SignatureDomain::DeviceRuntimeAuth => "tapchat.device_runtime_auth.v2",
            SignatureDomain::WelcomePickupToken => "tapchat.welcome_pickup.v1",
            SignatureDomain::GroupInviteToken => "tapchat.group_invite.v1",
            SignatureDomain::GroupJoinRequestToken => "tapchat.group_join_request_capability.v1",
            SignatureDomain::GroupJoinRequestSignature => "tapchat.group_join_request.v1",
            SignatureDomain::GroupLeaveRequestToken => "tapchat.group_leave_request_capability.v1",
            SignatureDomain::GroupLeaveRequestSignature => "tapchat.group_leave_request.v1",
            SignatureDomain::DeviceBinding => "tapchat.device_binding.v1",
            SignatureDomain::IdentityBundle => "tapchat.identity_bundle.v1",
        }
    }

    /// Every variant, for the distinctness test. An exhaustive slice rather
    /// than a derived iterator so that a new variant left out of it fails the
    /// test that guards the whole scheme.
    #[cfg(test)]
    pub(crate) const ALL: &'static [SignatureDomain] = &[
        SignatureDomain::GroupEnvelopeSenderProof,
        SignatureDomain::GroupManifest,
        SignatureDomain::GroupMembershipProof,
        SignatureDomain::GroupCapability,
        SignatureDomain::InboxAppendCapability,
        SignatureDomain::DeviceRuntimeAuth,
        SignatureDomain::WelcomePickupToken,
        SignatureDomain::GroupInviteToken,
        SignatureDomain::GroupJoinRequestToken,
        SignatureDomain::GroupJoinRequestSignature,
        SignatureDomain::GroupLeaveRequestToken,
        SignatureDomain::GroupLeaveRequestSignature,
        SignatureDomain::DeviceBinding,
        SignatureDomain::IdentityBundle,
    ];
}

/// A length-prefixed byte writer, always opened with a domain.
///
/// There is deliberately no `Default` and no public way to read the bytes
/// back: the only thing that can be done with a finished payload is hand it
/// to a signer or a verifier in `identity`. That is what keeps "signed
/// without a domain" unrepresentable rather than merely discouraged.
#[derive(Debug)]
pub struct SigningPayload {
    bytes: Vec<u8>,
}

impl SigningPayload {
    pub fn new(domain: SignatureDomain) -> Self {
        let mut payload = Self { bytes: Vec::new() };
        payload.push_str(domain.as_str());
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

    /// Crate-visible on purpose: `identity` is the only module that signs or
    /// verifies, and widening this back to `pub` would re-open the path that
    /// lets a caller sign bytes it assembled itself.
    pub(crate) fn into_bytes(self) -> Vec<u8> {
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

impl GroupMessageType {
    /// The stable wire name used in signing domains and on the wire.
    ///
    /// Exhaustive for the same reason as [`MessageType::wire_name`]: adding a
    /// variant must be a compile error here rather than a silent change to
    /// what every group signature covers.
    pub fn wire_name(&self) -> &'static str {
        match self {
            GroupMessageType::MlsApplication => "mls_application",
            GroupMessageType::MlsCommit => "mls_commit",
            GroupMessageType::MlsProposal => "mls_proposal",
            GroupMessageType::ControlGroupMembershipChanged => "control_group_membership_changed",
            GroupMessageType::ControlGroupMetadataUpdated => "control_group_metadata_updated",
            GroupMessageType::ControlGroupJoinRequested => "control_group_join_requested",
            GroupMessageType::ControlGroupJoinApproved => "control_group_join_approved",
            GroupMessageType::ControlGroupJoinRejected => "control_group_join_rejected",
            GroupMessageType::ControlGroupLeaveRequested => "control_group_leave_requested",
            GroupMessageType::ControlGroupDissolved => "control_group_dissolved",
            GroupMessageType::ControlGroupStateEvent => "control_group_state_event",
            GroupMessageType::ControlConversationNeedsRebuild => {
                "control_conversation_needs_rebuild"
            }
        }
    }
}

impl GroupEnvelopeVisibility {
    pub fn wire_name(&self) -> &'static str {
        match self {
            GroupEnvelopeVisibility::Visible => "visible",
            GroupEnvelopeVisibility::Protocol => "protocol",
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

/// The finished bytes, for tests that assert two payloads differ. Not a way
/// to sign: `LocalIdentityState` is still the only thing that can do that.
#[cfg(test)]
pub fn signing_payload_bytes_for_test(payload: SigningPayload) -> Vec<u8> {
    payload.into_bytes()
}

/// The exact bytes a group envelope's `sender_proof` signs.
///
/// The same shape as [`envelope_sender_proof_payload`], for the same reason:
/// signing the ciphertext alone let a legitimately signed group ciphertext be
/// re-appended under a different `message_id`, `message_type`, `visibility` or
/// `storage_refs` and still verify. `storage_refs` was the sharpest of those —
/// it is copied verbatim into the stored message and drives the attachment
/// download, so the group outbox operator could hang an arbitrary blob pointer
/// off a genuine message.
///
/// Three fields are deliberately outside the signature. The test for whether a
/// field belongs here is whether anything else already authenticates it, not
/// whether covering it would be convenient:
///
/// * `sender_proof` — itself.
/// * `membership_proof` — carries its own signature under
///   [`SignatureDomain::GroupMembershipProof`], and
///   `verify_membership_proof_message_binding` binds it to this envelope's
///   `message_id`. Already authenticated. Stripping it does not forge
///   anything: the record degrades into one that needs a proof and is
///   refused.
/// * `transition_id` — a derivation of `membership_proof.control_message_id`,
///   not an independent fact, and it is assigned at flush time. The bundle
///   path separately requires every record of a bundle to carry the same
///   proof and re-checks the commit/control/event shape.
pub fn group_envelope_sender_proof_payload(envelope: &GroupEnvelope) -> SigningPayload {
    let mut payload = SigningPayload::new(SignatureDomain::GroupEnvelopeSenderProof);
    payload.push_str(&envelope.version);
    payload.push_str(&envelope.group_id);
    payload.push_str(&envelope.message_id);
    payload.push_str(&envelope.conversation_id);
    payload.push_str(&envelope.sender_user_id);
    payload.push_str(&envelope.sender_device_id);
    payload.push_u64(envelope.created_at);
    payload.push_str(envelope.message_type.wire_name());
    payload.push_str(envelope.visibility.wire_name());
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
    payload
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{SenderProof, StorageRef, CURRENT_MODEL_VERSION};

    /// The group counterpart of a named field mutation.
    type GroupMutation = (&'static str, Box<dyn Fn(&mut GroupEnvelope)>);

    /// SHA-256 of the golden group envelope's signing payload.
    const GOLDEN_GROUP_ENVELOPE_DIGEST: &str =
        "6563a355dec4d7081f6d1a9f26dba49ccae18ee945308ee6843aa2738cd13bcf";

    /// The whole scheme rests on domains being distinguishable, and nothing
    /// else checks it. Pairwise distinctness is not enough on its own: because
    /// the domain is length-prefixed a prefix relation cannot actually cause a
    /// collision, but a domain that is a prefix of another is a sign someone
    /// versioned by appending, so reject it too.
    #[test]
    fn every_signature_domain_is_distinct() {
        for (index, left) in SignatureDomain::ALL.iter().enumerate() {
            for right in &SignatureDomain::ALL[index + 1..] {
                assert_ne!(
                    left.as_str(),
                    right.as_str(),
                    "{left:?} and {right:?} share a domain string"
                );
                assert!(
                    !right.as_str().starts_with(left.as_str())
                        && !left.as_str().starts_with(right.as_str()),
                    "{left:?} and {right:?} are prefixes of one another"
                );
            }
        }
    }

    fn group_envelope() -> GroupEnvelope {
        GroupEnvelope {
            version: CURRENT_MODEL_VERSION.to_string(),
            message_id: "msg:1:group".into(),
            group_id: "group:project".into(),
            conversation_id: "conv:group:project".into(),
            sender_user_id: "user:alice".into(),
            sender_device_id: "device:alice:phone".into(),
            created_at: 1_700_000_000_000,
            message_type: GroupMessageType::MlsApplication,
            visibility: GroupEnvelopeVisibility::Visible,
            inline_ciphertext: Some("Y2lwaGVy".into()),
            storage_refs: Vec::new(),
            sender_proof: SenderProof {
                proof_type: "device_signature".into(),
                value: "unsigned".into(),
            },
            membership_proof: None,
            transition_id: None,
        }
    }

    /// The group twin of [`every_field_is_covered`]. `storage_refs` is the
    /// entry that matters most: it is copied verbatim into the stored message
    /// and drives the attachment download, so a group outbox operator that
    /// could edit it could point a genuine message at a blob of its choosing.
    #[test]
    fn group_every_field_is_covered() {
        let base = group_envelope_sender_proof_payload(&group_envelope()).into_bytes();

        let mutations: Vec<GroupMutation> = vec![
            (
                "version",
                Box::new(|e: &mut GroupEnvelope| e.version = "0.2".into()),
            ),
            (
                "group_id",
                Box::new(|e: &mut GroupEnvelope| e.group_id = "group:other".into()),
            ),
            (
                "message_id",
                Box::new(|e: &mut GroupEnvelope| e.message_id = "msg:2:group".into()),
            ),
            (
                "conversation_id",
                Box::new(|e: &mut GroupEnvelope| e.conversation_id = "conv:group:other".into()),
            ),
            (
                "sender_user_id",
                Box::new(|e: &mut GroupEnvelope| e.sender_user_id = "user:mallory".into()),
            ),
            (
                "sender_device_id",
                Box::new(|e: &mut GroupEnvelope| {
                    e.sender_device_id = "device:mallory:phone".into()
                }),
            ),
            (
                "created_at",
                Box::new(|e: &mut GroupEnvelope| e.created_at += 1),
            ),
            (
                "message_type",
                Box::new(|e: &mut GroupEnvelope| {
                    e.message_type = GroupMessageType::ControlGroupStateEvent
                }),
            ),
            (
                "visibility",
                Box::new(|e: &mut GroupEnvelope| e.visibility = GroupEnvelopeVisibility::Protocol),
            ),
            (
                "inline_ciphertext",
                Box::new(|e: &mut GroupEnvelope| e.inline_ciphertext = Some("b3RoZXI=".into())),
            ),
            (
                "inline_ciphertext absence",
                Box::new(|e: &mut GroupEnvelope| e.inline_ciphertext = None),
            ),
            (
                "storage_refs",
                Box::new(|e: &mut GroupEnvelope| {
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
            let mut mutated = group_envelope();
            mutate(&mut mutated);
            assert_ne!(
                group_envelope_sender_proof_payload(&mutated).into_bytes(),
                base,
                "{field} is not covered by the group signing domain"
            );
        }
    }

    /// The three fields deliberately left out. This is an assertion about a
    /// decision, not an oversight: each is authenticated elsewhere, and the
    /// doc comment on `group_envelope_sender_proof_payload` says why. If one
    /// of them ever needs covering, this test is the thing that has to change
    /// first.
    #[test]
    fn group_sender_proof_covers_neither_itself_nor_the_separately_signed_fields() {
        let base = group_envelope_sender_proof_payload(&group_envelope()).into_bytes();

        let mut resigned = group_envelope();
        resigned.sender_proof.value = "something else".into();
        assert_eq!(
            group_envelope_sender_proof_payload(&resigned).into_bytes(),
            base,
            "sender_proof must not sign itself"
        );

        let mut retagged = group_envelope();
        retagged.transition_id = Some("group-transition:msg:control".into());
        assert_eq!(
            group_envelope_sender_proof_payload(&retagged).into_bytes(),
            base,
            "transition_id is derived from the membership proof, not signed"
        );
    }

    /// The delimiter-shifting bug, on the group domain.
    #[test]
    fn group_field_boundaries_cannot_be_shifted() {
        let mut left = group_envelope();
        left.conversation_id = "conv:a".into();
        left.sender_user_id = "b|user:c".into();

        let mut right = group_envelope();
        right.conversation_id = "conv:a|b".into();
        right.sender_user_id = "user:c".into();

        assert_ne!(
            group_envelope_sender_proof_payload(&left).into_bytes(),
            group_envelope_sender_proof_payload(&right).into_bytes()
        );
    }

    /// Pins the byte layout.
    #[test]
    fn group_golden_vector_is_stable() {
        let mut envelope = group_envelope();
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
        let digest = Sha256::digest(group_envelope_sender_proof_payload(&envelope).into_bytes());
        assert_eq!(
            format!("{digest:x}"),
            GOLDEN_GROUP_ENVELOPE_DIGEST,
            "the group envelope signing domain changed; update every \
             implementation of it before changing this vector"
        );
    }
}

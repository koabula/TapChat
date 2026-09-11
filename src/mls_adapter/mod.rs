use std::collections::{BTreeMap, BTreeSet};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use openmls::framing::errors::{MessageDecryptionError, SecretTreeError};
use openmls::prelude::{tls_codec::Deserialize, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::{MemoryStorageError, OpenMlsRustCrypto};
use serde::{Deserialize as SerdeDeserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{CoreError, CoreResult};
use crate::identity::LocalIdentityState;
use crate::log_sanitize::redact_id;
use crate::model::{MessageType, MlsStateStatus, MlsStateSummary};

pub const DEFAULT_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
pub const KEY_PACKAGE_LIFECYCLE_VERSION: u16 = 1;
pub const KEY_PACKAGE_LIFETIME_MS: u64 = 84 * 24 * 60 * 60 * 1000;
pub const KEY_PACKAGE_CLOCK_SKEW_MS: u64 = 60 * 60 * 1000;
pub const KEY_PACKAGE_CLOCK_TOLERANCE_MS: u64 = 5 * 60 * 1000;
pub const KEY_PACKAGE_ROTATION_WINDOW_MS: u64 = 14 * 24 * 60 * 60 * 1000;
pub const KEY_PACKAGE_ROTATION_JITTER_MAX_MS: u64 = 24 * 60 * 60 * 1000;
/// Target size of the one-time KeyPackage pool each device keeps replenished
/// on its own runtime, so that starting a new session consumes a KeyPackage
/// that is never handed out to a second contact.
pub const ONE_TIME_KEY_PACKAGE_POOL_TARGET: u32 = 20;
/// Once the remaining pool count (as reported by the runtime) drops below
/// this, the maintenance timer tops the pool back up to the target size.
pub const ONE_TIME_KEY_PACKAGE_POOL_LOW_WATER: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, SerdeDeserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PublishedKeyPackageState {
    #[default]
    Advertised,
    Consumed,
    Retired,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MlsAdapterModule;

impl MlsAdapterModule {
    pub fn name(&self) -> &'static str {
        "mls_adapter"
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, SerdeDeserialize)]
pub struct PublishedKeyPackage {
    pub key_package_ref: String,
    pub key_package_b64: String,
    #[serde(default)]
    pub lifecycle_version: u16,
    #[serde(default)]
    pub not_before: u64,
    #[serde(default)]
    pub created_at: u64,
    pub expires_at: u64,
    #[serde(default)]
    pub state: PublishedKeyPackageState,
    pub credential_identity: String,
}

impl PublishedKeyPackage {
    pub fn is_legacy(&self) -> bool {
        self.lifecycle_version != KEY_PACKAGE_LIFECYCLE_VERSION
            || self.not_before == 0
            || self.created_at == 0
            || self.expires_at.saturating_sub(self.created_at) != KEY_PACKAGE_LIFETIME_MS
    }

    pub fn is_expired_at(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at
    }

    pub fn should_rotate_at(&self, now_ms: u64, device_id: &str) -> bool {
        if self.is_legacy() || self.is_expired_at(now_ms) {
            return true;
        }
        let threshold = KEY_PACKAGE_ROTATION_WINDOW_MS
            .saturating_add(key_package_rotation_jitter_ms(device_id));
        now_ms >= self.expires_at.saturating_sub(threshold)
    }
}

pub fn key_package_rotation_jitter_ms(device_id: &str) -> u64 {
    let digest = Sha256::digest(device_id.as_bytes());
    let sample = u64::from_be_bytes(digest[..8].try_into().expect("sha256 prefix"));
    sample % (KEY_PACKAGE_ROTATION_JITTER_MAX_MS + 1)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerDeviceKeyPackage {
    pub user_id: String,
    pub device_id: String,
    pub device_public_key: String,
    pub key_package_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WelcomeEnvelope {
    pub recipient_device_id: String,
    pub payload_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateConversationArtifacts {
    pub commit_b64: String,
    pub welcomes: Vec<WelcomeEnvelope>,
    pub member_device_ids: Vec<String>,
    pub epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoveMembersArtifacts {
    pub commit_b64: String,
    pub removed_device_ids: Vec<String>,
    pub member_device_ids: Vec<String>,
    pub epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundMlsMessage {
    pub payload_b64: String,
    pub epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedApplicationMessage {
    pub plaintext: Vec<u8>,
    pub sender_identity: String,
    pub from_previous_epoch: bool,
}

/// Why a frame can never be applied.
///
/// Terminal: no future local state makes these bytes valid. The disposition is
/// always ack-and-discard, so the reason is telemetry only and must never
/// drive a state transition — with the single, documented exception of
/// [`RejectReason::LocalGroupUnusable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// Undecodable, or structurally impossible for its claimed type.
    Malformed,
    /// A cryptographic check failed: signature, membership tag, confirmation
    /// tag, or the AEAD tag. This is the forgery signal.
    Forged,
    /// The sender is not permitted to send this content.
    Unauthorized,
    /// This exact generation was already consumed, or it is our own message
    /// echoed back to us by the delivery service.
    Replay,
    /// The secrets needed are gone for forward secrecy and never come back.
    SecretsGone,
    /// The local group can no longer process anything — we were evicted, or
    /// our own key material for the update path is missing. This condition is
    /// pre-existing and local: it holds for every frame, not just this one, so
    /// acting on it is not a reaction to adversary input. It is the only
    /// reason a disposition site may escalate to a rebuild.
    LocalGroupUnusable,
    /// An openmls `LibraryError` or an unreachable state. Should never happen;
    /// acked and discarded rather than allowed to stall sync, with loud logs.
    Internal,
}

/// Why a frame cannot be authenticated *yet*.
///
/// Non-terminal: a future local state transition may make these bytes valid.
/// A future-epoch forgery and a legitimate out-of-order frame are
/// bit-identical in every observable respect, so this verdict is
/// indistinguishable from a forgery by construction. It must therefore be
/// quarantined *invisibly* and *boundedly* — never surfaced, never allowed to
/// grow without limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeferReason {
    /// We hold the group but are behind it: a future epoch, a future
    /// generation, or a commit referencing a proposal we have not seen.
    OutOfOrder,
    /// We hold no MLS group for this conversation at all. Only the disposition
    /// site can tell whether that is a genuine missing Welcome, so the adapter
    /// reports the fact and leaves the judgement to the caller.
    NoLocalGroup,
}

/// The two non-applied outcomes.
///
/// Shared by every classifier so the reason vocabulary cannot drift between
/// the message path and the commit path — the duplication it replaces had
/// already drifted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Rejected(RejectReason),
    Deferred(DeferReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestResult {
    AppliedApplication(DecryptedApplicationMessage),
    AppliedCommit { epoch: u64 },
    AppliedWelcome { epoch: u64 },
    AppliedProposal,
    Rejected(RejectReason),
    Deferred(DeferReason),
}

impl From<Verdict> for IngestResult {
    fn from(verdict: Verdict) -> Self {
        match verdict {
            Verdict::Rejected(reason) => IngestResult::Rejected(reason),
            Verdict::Deferred(reason) => IngestResult::Deferred(reason),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectSelfUpdate {
    pub commit_b64: String,
    pub commit_hash: String,
    pub base_epoch: u64,
}

#[derive(Debug)]
struct LocalMlsState {
    group: MlsGroup,
    member_device_ids: BTreeSet<String>,
    status: MlsStateStatus,
    pcs_updates: Vec<QueuedProposal>,
    pcs_update_epoch: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, SerdeDeserialize)]
struct PcsUpdateSidecar {
    #[serde(default)]
    epoch: u64,
    #[serde(default)]
    proposals: Vec<QueuedProposal>,
}

fn local_mls_state(
    group: MlsGroup,
    member_device_ids: BTreeSet<String>,
    status: MlsStateStatus,
) -> LocalMlsState {
    let pcs_update_epoch = group.epoch().as_u64();
    LocalMlsState {
        group,
        member_device_ids,
        status,
        pcs_updates: Vec::new(),
        pcs_update_epoch,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, SerdeDeserialize)]
struct SerializableStore {
    values: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, SerdeDeserialize)]
struct PersistedGroupState {
    credential_identity: String,
    local_device_id: String,
    signer: SignatureKeyPair,
    credential_with_key: CredentialWithKey,
    storage: SerializableStore,
    #[serde(default)]
    pcs_update_sidecar: BTreeMap<String, PcsUpdateSidecar>,
}

/// A compare-and-swap delta for the OpenMLS provider entries changed while a
/// single conversation is staged on a fork.  Keeping the delta, rather than a
/// serialized copy of the whole adapter, prevents a later transition ACK from
/// rolling back unrelated conversations that advanced while the request was
/// in flight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct MlsConversationPatch {
    pub conversation_id: String,
    pub base_state_sha256: String,
    pub staged_state_sha256: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub base_hashes: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub staged_values: BTreeMap<String, Option<String>>,
}

/// A complete, comparable snapshot of everything an `MlsAdapter` exposes.
///
/// Built by [`MlsAdapter::state_fingerprint`]. Two adapters with equal
/// fingerprints are indistinguishable to every caller: same provider store,
/// same conversations, same epochs, same rosters, same statuses, same PCS
/// sidecars.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlsStateFingerprint {
    pub provider_state_sha256: String,
    pub conversations: BTreeMap<String, MlsStateSummary>,
    /// Per conversation, the PCS sidecar's `(epoch, pending update count)`.
    /// The sidecar lives only in memory, so the provider hash does not cover
    /// it and a fingerprint comparison would otherwise miss `push_pcs_update`.
    pub pcs_sidecars: BTreeMap<String, (u64, usize)>,
}

#[derive(Debug, Default)]
pub struct RestoreMlsStateResult {
    pub adapter: Option<MlsAdapter>,
    pub summaries: BTreeMap<String, MlsStateSummary>,
    pub failed_conversation_ids: Vec<String>,
    pub failures: Vec<RestoreMlsFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreMlsFailure {
    pub conversation_id: String,
    pub reason: String,
    pub detail: Option<String>,
    pub recoverable: bool,
    pub suggested_action: String,
}

impl RestoreMlsFailure {
    fn new(
        conversation_id: impl Into<String>,
        reason: impl Into<String>,
        detail: Option<String>,
    ) -> Self {
        Self {
            conversation_id: conversation_id.into(),
            reason: reason.into(),
            detail,
            recoverable: true,
            suggested_action: "reconcile_conversation_membership".into(),
        }
    }
}

fn record_restore_failure(
    failed_conversation_ids: &mut Vec<String>,
    failures: &mut Vec<RestoreMlsFailure>,
    failure: RestoreMlsFailure,
) {
    if !failed_conversation_ids.contains(&failure.conversation_id) {
        failed_conversation_ids.push(failure.conversation_id.clone());
    }
    failures.push(failure);
}

/// Classify an OpenMLS `process_message` failure into an ingest disposition.
///
/// Two rules govern this table.
///
/// **`Err` means *our* fault, never theirs.** Anything a peer or an adversary
/// can cause by choosing bytes is a return value, because an `Err` here
/// propagates out of the whole inbox batch, emits no persist op, acks nothing,
/// and re-fails identically on every later fetch — a permanent, restart-
/// surviving sync stall that costs the attacker one HTTP POST. So the only
/// `Err` is `StorageError`. Note `LibraryError` is *not* eligible: it is
/// reachable from attacker bytes through `ValidationError::LibraryError`,
/// `MessageDecryptionError::LibraryError` and `SecretTreeError::LibraryError`,
/// so it is classified as terminal-and-discarded with loud telemetry instead.
///
/// **When in doubt, retry rather than discard.** Misclassifying a terminal
/// failure as retryable costs one buffer slot. Misclassifying an out-of-order
/// frame as terminal silently loses a real message.
///
/// This replaces a `format!("{error:?}")` substring match that was wrong in
/// both directions: it tested for `GenerationOutOfBound`, which openmls 0.8.1
/// never constructs, and it missed `TooDistantInThePast`,
/// `StageCommitError::OwnCommit` and `CannotDecryptOwnMessage` — three routine
/// conditions (the delivery service echoing our own traffic back at us) that
/// consequently drove the conversation into recovery and stalled the ack
/// cursor. Matching on the real types also means an openmls upgrade that adds
/// a variant fails the build instead of silently landing in a catch-all.
fn classify_process_error(error: ProcessMessageError<MemoryStorageError>) -> CoreResult<Verdict> {
    use ProcessMessageError as P;
    Ok(match error {
        // The only local fault.
        P::StorageError(error) => {
            return Err(CoreError::invalid_state(format!(
                "MLS provider storage failed while processing a message: {error:?}"
            )))
        }
        P::LibraryError(error) => {
            log::error!("openmls reported a library error while processing a message: {error:?}");
            Verdict::Rejected(RejectReason::Internal)
        }
        P::IncompatibleWireFormat => Verdict::Rejected(RejectReason::Malformed),
        P::UnauthorizedExternalApplicationMessage
        | P::UnauthorizedExternalCommitMessage
        | P::UnsupportedProposalType => Verdict::Rejected(RejectReason::Unauthorized),
        P::GroupStateError(error) => classify_group_state_error(error),
        P::InvalidCommit(error) => classify_stage_commit_error(error),
        P::ValidationError(error) => classify_validation_error(error),
    })
}

fn classify_group_state_error(error: MlsGroupStateError) -> Verdict {
    use MlsGroupStateError as G;
    match error {
        // We were removed from the group by a commit we already merged. This
        // is a pre-existing local condition — true for every frame, not caused
        // by this one — so acting on it is not a reaction to attacker input.
        G::UseAfterEviction => Verdict::Rejected(RejectReason::LocalGroupUnusable),
        // Only the create/commit APIs produce these; reaching one here means a
        // library invariant broke.
        G::PendingProposal | G::PendingCommit | G::NoPendingCommit | G::PendingProposalNotFound => {
            log::error!("unexpected MLS group state error while processing a message: {error:?}");
            Verdict::Rejected(RejectReason::Internal)
        }
        G::LibraryError(error) => {
            log::error!("openmls library error in group state: {error:?}");
            Verdict::Rejected(RejectReason::Internal)
        }
    }
}

fn classify_stage_commit_error(error: StageCommitError) -> Verdict {
    use StageCommitError as S;
    match error {
        // A commit-by-reference can arrive before the proposal it references.
        S::MissingProposal => Verdict::Deferred(DeferReason::OutOfOrder),
        // Unreachable in practice: our own pre-gate rejects `epoch < live` and
        // `epoch > live` fails earlier during decryption. Retryable by the
        // when-in-doubt rule.
        S::EpochMismatch => Verdict::Deferred(DeferReason::OutOfOrder),
        // The delivery service echoed our own commit back at us. Nothing to
        // apply, and it never becomes applicable.
        S::OwnCommit => Verdict::Rejected(RejectReason::Replay),
        // Our own key material for the update path is gone. Only reachable
        // after the commit authenticated, so escalating is safe.
        S::OwnKeyNotFound | S::MissingDecryptionKey => {
            Verdict::Rejected(RejectReason::LocalGroupUnusable)
        }
        // Everything else is a commit that either failed authentication or is
        // semantically invalid. No future local state makes it valid.
        S::ConfirmationTagMissing
        | S::ConfirmationTagMismatch
        | S::PathLeafNodeVerificationFailure => Verdict::Rejected(RejectReason::Forged),
        S::SenderTypeExternal | S::SenderTypeNewMemberProposal => {
            Verdict::Rejected(RejectReason::Unauthorized)
        }
        S::LibraryError(_)
        | S::WrongPlaintextContentType
        | S::RequiredPathNotFound
        | S::AttemptedSelfRemoval
        | S::InconsistentSenderIndex
        | S::TooManyNewMembers
        | S::ProposalValidationError(_)
        | S::PskError(_)
        | S::ExternalCommitValidation(_)
        | S::UpdatePathError(_)
        | S::VerifiedUpdatePathError(_)
        | S::GroupContextExtensionsProposalValidationError(_)
        | S::LeafNodeValidation(_)
        | S::DuplicatePskId(_) => Verdict::Rejected(RejectReason::Malformed),
        // `AppDataUpdateValidationError` and `ApplyAppDataUpdateError` exist
        // only under openmls' `extensions-draft-08` feature, which is off.
        // If it is ever enabled this match stops compiling, which is the
        // intended way to be told about it.
    }
}

fn classify_validation_error(error: ValidationError) -> Verdict {
    use ValidationError as V;
    match error {
        // The core of the problem R2 solves: our pre-gate already rejected
        // `epoch < live`, so this is a handshake message for an epoch we have
        // not reached yet. A legitimate commit that overtook its predecessor
        // and a future-epoch forgery are bit-identical in every observable
        // respect, so both are retried — bounded, and invisibly.
        V::WrongEpoch => Verdict::Deferred(DeferReason::OutOfOrder),
        // The sender's leaf may be populated by a commit we have not processed.
        V::UnknownMember => Verdict::Deferred(DeferReason::OutOfOrder),
        // `max_past_epochs(1)` already deleted that epoch's secrets. Retrying
        // cannot help: nothing arriving later restores deleted key material.
        V::NoPastEpochData => Verdict::Rejected(RejectReason::SecretsGone),
        // The delivery service echoed our own application message back, and
        // the deletion schedule removed our own sender keys. Never decryptable.
        V::CannotDecryptOwnMessage => Verdict::Rejected(RejectReason::Replay),
        V::UnableToDecrypt(error) => classify_decryption_error(error),
        V::LibraryError(error) => {
            log::error!("openmls library error during validation: {error:?}");
            Verdict::Rejected(RejectReason::Internal)
        }
        V::InvalidSignature
        | V::InvalidMembershipTag
        | V::InvalidLeafNodeSignature
        | V::MissingMembershipTag
        | V::MissingConfirmationTag => Verdict::Rejected(RejectReason::Forged),
        V::NonMemberApplicationMessage
        | V::UnauthorizedExternalSender
        | V::NoExternalSendersExtension => Verdict::Rejected(RejectReason::Unauthorized),
        // Structurally impossible frames.
        V::WrongGroupId
        | V::NotACommit
        | V::NotAnExternalAddProposal
        | V::NoPath
        | V::UnencryptedApplicationMessage
        | V::WrongWireFormat
        | V::KeyPackageVerifyError(_)
        | V::UpdatePathError(_)
        | V::InvalidLeafNodeSourceType
        | V::InvalidSenderType
        | V::CommitterIncludedOwnUpdate
        | V::InvalidAddProposalCiphersuite
        | V::ExternalCommitValidation(_)
        | V::InvalidExtension(_) => Verdict::Rejected(RejectReason::Malformed),
    }
}

fn classify_decryption_error(error: MessageDecryptionError) -> Verdict {
    use MessageDecryptionError as D;
    match error {
        D::SecretTreeError(error) => classify_secret_tree_error(error),
        // Right epoch, right generation window, wrong key. The AEAD tag *is*
        // the authentication, so this is the forgery signal.
        D::AeadError => Verdict::Rejected(RejectReason::Forged),
        // Declared but never constructed in openmls 0.8.1; listed so the
        // match stays exhaustive.
        D::GenerationOutOfBound => Verdict::Rejected(RejectReason::SecretsGone),
        D::WrongWireFormat | D::MalformedContent => Verdict::Rejected(RejectReason::Malformed),
        D::LibraryError(error) => {
            log::error!("openmls library error during decryption: {error:?}");
            Verdict::Rejected(RejectReason::Internal)
        }
    }
}

fn classify_secret_tree_error(error: SecretTreeError) -> Verdict {
    use SecretTreeError as T;
    match error {
        // Generation beyond the forward window. Tempting to treat as a
        // forgery, since an attacker sets a huge generation for free — but it
        // is genuinely repairable: once the intervening frames ratchet us
        // forward this generation falls inside the window and decrypts. A real
        // frame after a long burst is indistinguishable from the forgery, so
        // discarding would silently drop real messages. Retry, bounded.
        T::TooDistantInTheFuture => Verdict::Deferred(DeferReason::OutOfOrder),
        // The secret was deleted immediately after use: canonical replay.
        T::SecretReuseError => Verdict::Rejected(RejectReason::Replay),
        // Outside the out-of-order tolerance, or already consumed. Gone for
        // forward secrecy. Previously classified as retryable, which made this
        // the cheapest way to stall a client permanently.
        T::TooDistantInThePast | T::RatchetTooLong => Verdict::Rejected(RejectReason::SecretsGone),
        T::IndexOutOfBounds | T::CodecError(_) => Verdict::Rejected(RejectReason::Malformed),
        T::RatchetTypeError | T::LibraryError | T::CryptoError(_) => {
            log::error!("unexpected MLS secret tree error: {error:?}");
            Verdict::Rejected(RejectReason::Internal)
        }
    }
}

fn store_sha256(store: &SerializableStore) -> CoreResult<String> {
    let canonical = serde_json::to_vec(store).map_err(|error| {
        CoreError::invalid_state(format!("failed to encode MLS provider state: {error}"))
    })?;
    Ok(format!("sha256:{:x}", Sha256::digest(canonical)))
}

fn optional_value_sha256(value: Option<&str>) -> String {
    let mut hasher = Sha256::new();
    match value {
        Some(value) => {
            hasher.update([1_u8]);
            hasher.update(value.as_bytes());
        }
        None => hasher.update([0_u8]),
    }
    format!("sha256:{:x}", hasher.finalize())
}

pub struct MlsAdapter {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential_with_key: CredentialWithKey,
    credential_identity: String,
    local_device_id: String,
    groups: BTreeMap<String, LocalMlsState>,
}

impl std::fmt::Debug for MlsAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlsAdapter")
            .field("credential_identity", &self.credential_identity)
            .field("local_device_id", &self.local_device_id)
            .field("groups_len", &self.groups.len())
            .finish()
    }
}

impl MlsAdapter {
    pub fn fork(&self) -> CoreResult<Self> {
        let serialized = self.export_serializable_state()?;
        if self.groups.is_empty() {
            return Self::restore_from_bootstrap_state(&serialized);
        }
        let persisted_states: Vec<_> = self
            .groups
            .iter()
            .map(|(conversation_id, state)| {
                (
                    conversation_id.clone(),
                    MlsStateSummary {
                        conversation_id: conversation_id.clone(),
                        epoch: state.group.epoch().as_u64(),
                        member_device_ids: state.member_device_ids.iter().cloned().collect(),
                        status: state.status,
                        updated_at: state.group.epoch().as_u64(),
                    },
                    Some(serialized.clone()),
                )
            })
            .collect();
        Self::restore_from_persisted_states(&persisted_states)?
            .adapter
            .ok_or_else(|| CoreError::invalid_state("failed to fork MLS adapter state"))
    }

    pub fn conversation_patch(
        &self,
        staged: &Self,
        conversation_id: &str,
    ) -> CoreResult<MlsConversationPatch> {
        if conversation_id.trim().is_empty() {
            return Err(CoreError::invalid_input(
                "conversation_id must not be empty",
            ));
        }
        if self.credential_identity != staged.credential_identity
            || self.local_device_id != staged.local_device_id
        {
            return Err(CoreError::invalid_state(
                "cannot diff MLS adapters belonging to different local identities",
            ));
        }
        let base = self.serializable_store()?;
        let target = staged.serializable_store()?;
        let keys = base
            .values
            .keys()
            .chain(target.values.keys())
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut base_hashes = BTreeMap::new();
        let mut staged_values = BTreeMap::new();
        for key in keys {
            let before = base.values.get(&key).cloned();
            let after = target.values.get(&key).cloned();
            if before != after {
                base_hashes.insert(key.clone(), optional_value_sha256(before.as_deref()));
                staged_values.insert(key, after);
            }
        }
        Ok(MlsConversationPatch {
            conversation_id: conversation_id.to_string(),
            base_state_sha256: store_sha256(&base)?,
            staged_state_sha256: store_sha256(&target)?,
            base_hashes,
            staged_values,
        })
    }

    /// Apply a previously staged target-conversation delta to the current
    /// adapter.  Every changed provider entry is compared with its base value;
    /// a mismatch means the target conversation advanced concurrently and the
    /// caller must reconcile instead of overwriting it.
    pub fn apply_conversation_patch(
        &self,
        patch: &MlsConversationPatch,
        summaries: &BTreeMap<String, MlsStateSummary>,
    ) -> CoreResult<Self> {
        let mut current = self.serializable_store()?;
        for (key, expected_hash) in &patch.base_hashes {
            let actual = current.values.get(key).map(String::as_str);
            if optional_value_sha256(actual) != *expected_hash {
                return Err(CoreError::invalid_state(format!(
                    "MLS conversation patch CAS failed for {}",
                    patch.conversation_id
                )));
            }
        }
        for (key, value) in &patch.staged_values {
            if let Some(value) = value {
                current.values.insert(key.clone(), value.clone());
            } else {
                current.values.remove(key);
            }
        }
        let serialized = self.serialize_with_store(current, None)?;
        Self::restore_serialized_state(&serialized, summaries)
    }

    pub fn restore_serialized_state(
        serialized: &str,
        summaries: &BTreeMap<String, MlsStateSummary>,
    ) -> CoreResult<Self> {
        let persisted_states: Vec<_> = summaries
            .iter()
            .map(|(conversation_id, summary)| {
                (
                    conversation_id.clone(),
                    summary.clone(),
                    Some(serialized.to_string()),
                )
            })
            .collect();
        Self::restore_from_persisted_states(&persisted_states)?
            .adapter
            .ok_or_else(|| CoreError::invalid_state("failed to restore staged MLS adapter state"))
    }
    pub fn bootstrap(
        local_identity: &LocalIdentityState,
    ) -> CoreResult<(Self, PublishedKeyPackage)> {
        let provider = OpenMlsRustCrypto::default();
        let signer =
            SignatureKeyPair::new(DEFAULT_CIPHERSUITE.signature_algorithm()).map_err(|error| {
                CoreError::invalid_state(format!("failed to create MLS signer: {error}"))
            })?;
        signer.store(provider.storage()).map_err(|error| {
            CoreError::invalid_state(format!("failed to store MLS signer: {error}"))
        })?;

        let credential_identity = build_credential_identity(local_identity);
        let credential = BasicCredential::new(credential_identity.clone().into_bytes());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.to_public_vec().into(),
        };
        let credential_identity = build_credential_identity(local_identity);
        let package = Self::build_published_key_package(
            &provider,
            &signer,
            credential_with_key.clone(),
            credential_identity.clone(),
            current_unix_time_ms()?,
        )?;

        let adapter = Self {
            provider,
            signer,
            credential_with_key,
            credential_identity: credential_identity.clone(),
            local_device_id: local_identity.device_identity.device_id.clone(),
            groups: BTreeMap::new(),
        };

        Ok((adapter, package))
    }

    pub fn generate_key_package(
        local_identity: &LocalIdentityState,
        now: u64,
    ) -> CoreResult<PublishedKeyPackage> {
        let provider = OpenMlsRustCrypto::default();
        let signer =
            SignatureKeyPair::new(DEFAULT_CIPHERSUITE.signature_algorithm()).map_err(|error| {
                CoreError::invalid_state(format!("failed to generate MLS signer: {error}"))
            })?;
        signer.store(provider.storage()).map_err(|error| {
            CoreError::invalid_state(format!("failed to store MLS signer: {error}"))
        })?;
        let credential_identity = build_credential_identity(local_identity);
        let credential = BasicCredential::new(credential_identity.clone().into_bytes());
        Self::build_published_key_package(
            &provider,
            &signer,
            CredentialWithKey {
                credential: credential.into(),
                signature_key: signer.to_public_vec().into(),
            },
            credential_identity,
            now,
        )
    }

    pub fn rotate_key_package(&mut self, now: u64) -> CoreResult<PublishedKeyPackage> {
        Self::build_published_key_package(
            &self.provider,
            &self.signer,
            self.credential_with_key.clone(),
            self.credential_identity.clone(),
            now,
        )
    }

    /// Builds `count` one-time KeyPackages for the one-time pool, each with its
    /// own independently generated MLS init secret (openmls stores each by the
    /// KeyPackage's own hash, so these coexist without collision). Unlike the
    /// single long-lived last-resort KeyPackage, these are meant to be claimed
    /// and consumed exactly once each.
    pub fn generate_one_time_key_packages(
        &self,
        count: u32,
        now: u64,
    ) -> CoreResult<Vec<PublishedKeyPackage>> {
        (0..count)
            .map(|_| {
                Self::build_published_key_package(
                    &self.provider,
                    &self.signer,
                    self.credential_with_key.clone(),
                    self.credential_identity.clone(),
                    now,
                )
            })
            .collect()
    }

    pub fn create_conversation(
        &mut self,
        conversation_id: &str,
        peer_devices_with_keypackages: &[PeerDeviceKeyPackage],
    ) -> CoreResult<CreateConversationArtifacts> {
        if conversation_id.trim().is_empty() {
            return Err(CoreError::invalid_input(
                "conversation_id must not be empty",
            ));
        }
        if peer_devices_with_keypackages.is_empty() {
            return Err(CoreError::invalid_input(
                "peer_devices_with_keypackages must not be empty",
            ));
        }
        if self.groups.contains_key(conversation_id) {
            return Err(CoreError::invalid_state(
                "conversation MLS state already exists",
            ));
        }

        let group_id = GroupId::from_slice(conversation_id.as_bytes());
        self.delete_stale_persisted_group(&group_id)?;
        // max_past_epochs(1): tolerate one epoch of reordering/late delivery.
        // Trade-off: the forward-secrecy boundary is epoch e-1, not e — a
        // compromise while in epoch e can still decrypt epoch e-1 traffic,
        // since that epoch's key material is deliberately kept around.
        let config = MlsGroupCreateConfig::builder()
            .use_ratchet_tree_extension(true)
            .max_past_epochs(1)
            .build();
        let mut group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            group_id,
            self.credential_with_key.clone(),
        )
        .map_err(|error| {
            CoreError::invalid_state(format!("failed to create MLS group: {error}"))
        })?;

        let mut member_device_ids = BTreeSet::from([self.local_device_id.clone()]);
        let mut key_packages = Vec::with_capacity(peer_devices_with_keypackages.len());
        for peer in peer_devices_with_keypackages {
            if peer.device_id.trim().is_empty() {
                return Err(CoreError::invalid_input("peer device_id must not be empty"));
            }
            member_device_ids.insert(peer.device_id.clone());
            key_packages.push(decode_key_package(&peer.key_package_b64)?);
        }

        let (commit, welcome, _group_info) = group
            .add_members(&self.provider, &self.signer, &key_packages)
            .map_err(|error| {
                CoreError::invalid_state(format!("failed to add MLS members: {error}"))
            })?;
        group
            .merge_pending_commit(&self.provider)
            .map_err(|error| {
                CoreError::invalid_state(format!("failed to merge pending commit: {error}"))
            })?;

        let commit_b64 = encode_mls_message(commit)?;
        let welcome_b64 = encode_mls_message(welcome)?;

        self.groups.insert(
            conversation_id.to_string(),
            local_mls_state(group, member_device_ids.clone(), MlsStateStatus::Active),
        );

        Ok(CreateConversationArtifacts {
            commit_b64,
            welcomes: peer_devices_with_keypackages
                .iter()
                .map(|peer| WelcomeEnvelope {
                    recipient_device_id: peer.device_id.clone(),
                    payload_b64: welcome_b64.clone(),
                })
                .collect(),
            member_device_ids: member_device_ids.into_iter().collect(),
            epoch: self.export_group_summary(conversation_id)?.epoch,
        })
    }

    /// Create the canonical provisional MLS group containing only the local
    /// owner.  Initial invitees are added on a fork and become canonical only
    /// after the roster-0 -> roster-1 transition is acknowledged.
    pub fn create_owner_conversation(
        &mut self,
        conversation_id: &str,
    ) -> CoreResult<MlsStateSummary> {
        if conversation_id.trim().is_empty() {
            return Err(CoreError::invalid_input(
                "conversation_id must not be empty",
            ));
        }
        if self.groups.contains_key(conversation_id) {
            return Err(CoreError::invalid_state(
                "conversation MLS state already exists",
            ));
        }
        let group_id = GroupId::from_slice(conversation_id.as_bytes());
        self.delete_stale_persisted_group(&group_id)?;
        // max_past_epochs(1): see the comment in create_conversation — same
        // reorder-tolerance trade-off, same epoch e-1 forward-secrecy boundary.
        let config = MlsGroupCreateConfig::builder()
            .use_ratchet_tree_extension(true)
            .max_past_epochs(1)
            .build();
        let group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            group_id,
            self.credential_with_key.clone(),
        )
        .map_err(|error| {
            CoreError::invalid_state(format!("failed to create owner MLS group: {error}"))
        })?;
        self.groups.insert(
            conversation_id.to_string(),
            local_mls_state(
                group,
                BTreeSet::from([self.local_device_id.clone()]),
                MlsStateStatus::Active,
            ),
        );
        self.export_group_summary(conversation_id)
    }

    pub fn add_members(
        &mut self,
        conversation_id: &str,
        peer_devices_with_keypackages: &[PeerDeviceKeyPackage],
    ) -> CoreResult<CreateConversationArtifacts> {
        if peer_devices_with_keypackages.is_empty() {
            return Err(CoreError::invalid_input(
                "peer_devices_with_keypackages must not be empty",
            ));
        }
        let state = self
            .groups
            .get_mut(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation MLS state does not exist"))?;

        let mut key_packages = Vec::with_capacity(peer_devices_with_keypackages.len());
        for peer in peer_devices_with_keypackages {
            if peer.device_id.trim().is_empty() {
                return Err(CoreError::invalid_input("peer device_id must not be empty"));
            }
            key_packages.push(decode_key_package(&peer.key_package_b64)?);
        }

        let (commit, welcome, _group_info) = state
            .group
            .add_members(&self.provider, &self.signer, &key_packages)
            .map_err(|error| {
                CoreError::invalid_state(format!("failed to add MLS members: {error}"))
            })?;
        state
            .group
            .merge_pending_commit(&self.provider)
            .map_err(|error| {
                CoreError::invalid_state(format!("failed to merge pending commit: {error}"))
            })?;
        for peer in peer_devices_with_keypackages {
            state.member_device_ids.insert(peer.device_id.clone());
        }
        state.status = MlsStateStatus::Active;

        let commit_b64 = encode_mls_message(commit)?;
        let welcome_b64 = encode_mls_message(welcome)?;
        Ok(CreateConversationArtifacts {
            commit_b64,
            welcomes: peer_devices_with_keypackages
                .iter()
                .map(|peer| WelcomeEnvelope {
                    recipient_device_id: peer.device_id.clone(),
                    payload_b64: welcome_b64.clone(),
                })
                .collect(),
            member_device_ids: state.member_device_ids.iter().cloned().collect(),
            epoch: state.group.epoch().as_u64(),
        })
    }

    pub fn remove_members(
        &mut self,
        conversation_id: &str,
        device_ids: &[String],
    ) -> CoreResult<RemoveMembersArtifacts> {
        if device_ids.is_empty() {
            return Err(CoreError::invalid_input("device_ids must not be empty"));
        }
        let state = self
            .groups
            .get_mut(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation MLS state does not exist"))?;

        let leaf_indices = member_leaf_indices_for_devices(&state.group, device_ids)?;
        let (commit, _welcome, _group_info) = state
            .group
            .remove_members(&self.provider, &self.signer, &leaf_indices)
            .map_err(|error| {
                CoreError::invalid_state(format!("failed to remove MLS members: {error}"))
            })?;
        state
            .group
            .merge_pending_commit(&self.provider)
            .map_err(|error| {
                CoreError::invalid_state(format!("failed to merge pending commit: {error}"))
            })?;
        for device_id in device_ids {
            state.member_device_ids.remove(device_id);
        }
        state.status = MlsStateStatus::Active;

        Ok(RemoveMembersArtifacts {
            commit_b64: encode_mls_message(commit)?,
            removed_device_ids: device_ids.to_vec(),
            member_device_ids: state.member_device_ids.iter().cloned().collect(),
            epoch: state.group.epoch().as_u64(),
        })
    }

    pub fn encrypt_application(
        &mut self,
        conversation_id: &str,
        plaintext_bytes: &[u8],
    ) -> CoreResult<OutboundMlsMessage> {
        let provider = &self.provider;
        let signer = &self.signer;
        let state = self
            .groups
            .get_mut(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation MLS state does not exist"))?;
        let message = state
            .group
            .create_message(provider, signer, plaintext_bytes)
            .map_err(|error| {
                CoreError::invalid_state(format!("failed to create MLS application: {error}"))
            })?;
        Ok(OutboundMlsMessage {
            payload_b64: encode_mls_message(message)?,
            epoch: state.group.epoch().as_u64(),
        })
    }

    pub fn propose_self_update(&mut self, conversation_id: &str) -> CoreResult<OutboundMlsMessage> {
        let provider = &self.provider;
        let signer = &self.signer;
        let state = self
            .groups
            .get_mut(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation MLS state does not exist"))?;
        let (message, _proposal_ref) = state
            .group
            .propose_self_update(provider, signer, LeafNodeParameters::default())
            .map_err(|error| {
                CoreError::invalid_state(format!("failed to propose MLS self-update: {error}"))
            })?;
        let pending: Vec<_> = state.group.pending_proposals().cloned().collect();
        state
            .group
            .clear_pending_proposals(provider.storage())
            .map_err(|error| {
                CoreError::invalid_state(format!(
                    "failed to clear live MLS proposal store: {error}"
                ))
            })?;
        for proposal in pending {
            push_pcs_update(state, proposal);
        }
        Ok(OutboundMlsMessage {
            payload_b64: encode_mls_message(message)?,
            epoch: state.group.epoch().as_u64(),
        })
    }

    pub fn has_pending_proposals(&self, conversation_id: &str) -> CoreResult<bool> {
        let state = self
            .groups
            .get(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation MLS state does not exist"))?;
        Ok(state.group.has_pending_proposals())
    }

    pub fn has_pcs_update_proposals(&self, conversation_id: &str) -> CoreResult<bool> {
        let state = self
            .groups
            .get(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation MLS state does not exist"))?;
        Ok(state.pcs_update_epoch == state.group.epoch().as_u64() && !state.pcs_updates.is_empty())
    }

    #[cfg(test)]
    pub fn pcs_update_count(&self, conversation_id: &str) -> CoreResult<usize> {
        let state = self
            .groups
            .get(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation MLS state does not exist"))?;
        if state.pcs_update_epoch != state.group.epoch().as_u64() {
            return Ok(0);
        }
        Ok(state.pcs_updates.len())
    }

    pub fn own_leaf_key_b64(&self, conversation_id: &str) -> CoreResult<String> {
        let state = self
            .groups
            .get(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation MLS state does not exist"))?;
        leaf_key_b64_for_group(&state.group)
    }

    pub fn clear_pcs_update_sidecar(&mut self, conversation_id: &str) {
        if let Some(state) = self.groups.get_mut(conversation_id) {
            state.pcs_updates.clear();
            state.pcs_update_epoch = state.group.epoch().as_u64();
        }
    }

    pub fn propose_remove_member(
        &mut self,
        conversation_id: &str,
        device_id: &str,
    ) -> CoreResult<OutboundMlsMessage> {
        let indices = {
            let state = self
                .groups
                .get(conversation_id)
                .ok_or_else(|| CoreError::invalid_input("conversation MLS state does not exist"))?;
            member_leaf_indices_for_devices(&state.group, &[device_id.to_string()])?
        };
        let leaf_index = *indices
            .first()
            .ok_or_else(|| CoreError::invalid_input("MLS member for device does not exist"))?;
        let provider = &self.provider;
        let signer = &self.signer;
        let state = self
            .groups
            .get_mut(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation MLS state does not exist"))?;
        let (message, _proposal_ref) = state
            .group
            .propose_remove_member(provider, signer, leaf_index)
            .map_err(|error| {
                CoreError::invalid_state(format!("failed to propose MLS remove: {error}"))
            })?;
        state
            .group
            .clear_pending_proposals(provider.storage())
            .map_err(|error| {
                CoreError::invalid_state(format!(
                    "failed to clear live MLS proposal store: {error}"
                ))
            })?;
        Ok(OutboundMlsMessage {
            payload_b64: encode_mls_message(message)?,
            epoch: state.group.epoch().as_u64(),
        })
    }

    fn inject_pcs_updates(&mut self, conversation_id: &str) -> CoreResult<()> {
        let provider = &self.provider;
        let state = self
            .groups
            .get_mut(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation MLS state does not exist"))?;
        align_pcs_sidecar_epoch(state);
        for proposal in state.pcs_updates.clone() {
            if !is_member_self_update(&proposal) {
                continue;
            }
            state
                .group
                .store_pending_proposal(provider.storage(), proposal)
                .map_err(|error| {
                    CoreError::invalid_state(format!(
                        "failed to restore PCS update proposal: {error:?}"
                    ))
                })?;
        }
        Ok(())
    }

    pub fn stage_group_pcs_commit(
        &mut self,
        conversation_id: &str,
    ) -> CoreResult<OutboundMlsMessage> {
        self.inject_pcs_updates(conversation_id)?;
        let provider = &self.provider;
        let signer = &self.signer;
        let state = self
            .groups
            .get_mut(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation MLS state does not exist"))?;
        if state
            .group
            .pending_proposals()
            .any(|proposal| !is_member_self_update(proposal))
        {
            return Err(CoreError::invalid_state(
                "PCS commit store contains a non-update proposal",
            ));
        }
        let members_before = state.member_device_ids.clone();
        let bundle = state
            .group
            .self_update(provider, signer, LeafNodeParameters::default())
            .map_err(|error| {
                CoreError::invalid_state(format!("failed to create group PCS commit: {error}"))
            })?;
        let commit = bundle.into_commit();
        state
            .group
            .merge_pending_commit(&self.provider)
            .map_err(|error| {
                CoreError::invalid_state(format!("failed to merge group PCS commit: {error}"))
            })?;
        state.member_device_ids = extract_member_device_ids(&state.group)?;
        if state.member_device_ids != members_before {
            return Err(CoreError::invalid_state(
                "group PCS commit changed MLS membership",
            ));
        }
        state.pcs_updates.clear();
        state.pcs_update_epoch = state.group.epoch().as_u64();
        state.status = MlsStateStatus::Active;
        Ok(OutboundMlsMessage {
            payload_b64: encode_mls_message(commit)?,
            epoch: state.group.epoch().as_u64(),
        })
    }

    /// Replace this device's leaf key and merge the commit immediately.
    ///
    /// Staging alone heals nothing: `self_update` only produces a pending
    /// commit, and the old leaf key stays in use until the merge. Post-compromise
    /// healing therefore has to be a single unilateral step, which is what makes
    /// it independent of the counterparty.
    pub fn rotate_direct_self_update(
        &mut self,
        conversation_id: &str,
    ) -> CoreResult<DirectSelfUpdate> {
        if !self.groups.contains_key(conversation_id) {
            return Err(CoreError::invalid_input(
                "conversation MLS state does not exist",
            ));
        }
        let base_epoch = self.export_group_summary(conversation_id)?.epoch;
        let provider = &self.provider;
        let signer = &self.signer;
        let state = self
            .groups
            .get_mut(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation MLS state does not exist"))?;
        let members_before = state.member_device_ids.clone();
        let bundle = state
            .group
            .self_update(provider, signer, LeafNodeParameters::default())
            .map_err(|error| {
                CoreError::invalid_state(format!(
                    "failed to create direct PCS self-update: {error}"
                ))
            })?;
        let commit = bundle.into_commit();
        state
            .group
            .merge_pending_commit(provider)
            .map_err(|error| {
                CoreError::invalid_state(format!("failed to merge direct PCS self-update: {error}"))
            })?;
        state.member_device_ids = extract_member_device_ids(&state.group)?;
        if state.member_device_ids != members_before {
            return Err(CoreError::invalid_state(
                "direct PCS self-update changed MLS membership",
            ));
        }
        state.pcs_updates.clear();
        state.pcs_update_epoch = state.group.epoch().as_u64();
        state.status = MlsStateStatus::Active;
        let commit_b64 = encode_mls_message(commit)?;
        let commit_hash = crate::direct_pcs::commit_hash_from_b64(&commit_b64)?;
        Ok(DirectSelfUpdate {
            commit_b64,
            commit_hash,
            base_epoch,
        })
    }

    /// Produce a self-update commit for the live epoch **without** advancing
    /// this adapter, by building it on a `fork()`.
    ///
    /// The only way to construct a rival commit for a same-epoch collision, so
    /// the arbitration tests can exercise a race that is otherwise a
    /// one-message-wide window in wall-clock time.
    pub fn create_forked_direct_self_update(
        &self,
        conversation_id: &str,
    ) -> CoreResult<DirectSelfUpdate> {
        if !self.groups.contains_key(conversation_id) {
            return Err(CoreError::invalid_input(
                "conversation MLS state does not exist",
            ));
        }
        let base_epoch = self.export_group_summary(conversation_id)?.epoch;
        let mut fork = self.fork()?;
        let provider = &fork.provider;
        let signer = &fork.signer;
        let state = fork.groups.get_mut(conversation_id).ok_or_else(|| {
            CoreError::invalid_state("forked MLS adapter is missing the conversation")
        })?;
        let bundle = state
            .group
            .self_update(provider, signer, LeafNodeParameters::default())
            .map_err(|error| {
                CoreError::invalid_state(format!(
                    "failed to create forked direct PCS self-update: {error}"
                ))
            })?;
        let commit = bundle.into_commit();
        let commit_b64 = encode_mls_message(commit)?;
        let commit_hash = crate::direct_pcs::commit_hash_from_b64(&commit_b64)?;
        Ok(DirectSelfUpdate {
            commit_b64,
            commit_hash,
            base_epoch,
        })
    }

    pub fn member_device_ids(&self, conversation_id: &str) -> CoreResult<Vec<String>> {
        Ok(self
            .export_group_summary(conversation_id)?
            .member_device_ids)
    }

    pub fn ingest_message(
        &mut self,
        conversation_id: &str,
        sender_device_id: &str,
        message_type: MessageType,
        payload_b64: &str,
    ) -> CoreResult<IngestResult> {
        match message_type {
            MessageType::MlsWelcome => {
                self.ingest_welcome(conversation_id, sender_device_id, payload_b64)
            }
            MessageType::MlsCommit | MessageType::MlsApplication | MessageType::MlsProposal => {
                if !self.groups.contains_key(conversation_id) {
                    return Ok(IngestResult::Deferred(DeferReason::NoLocalGroup));
                }
                self.ingest_protocol_message(
                    conversation_id,
                    sender_device_id,
                    message_type,
                    payload_b64,
                )
            }
            _ => Err(CoreError::unsupported(
                "mls adapter only supports MLS message types",
            )),
        }
    }

    pub fn export_group_summary(&self, conversation_id: &str) -> CoreResult<MlsStateSummary> {
        let state = self
            .groups
            .get(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation MLS state does not exist"))?;
        Ok(MlsStateSummary {
            conversation_id: conversation_id.to_string(),
            epoch: state.group.epoch().as_u64(),
            member_device_ids: state.member_device_ids.iter().cloned().collect(),
            status: state.status,
            updated_at: state.group.epoch().as_u64(),
        })
    }

    pub fn mark_recovery_needed(&mut self, conversation_id: &str) {
        if let Some(state) = self.groups.get_mut(conversation_id) {
            state.status = MlsStateStatus::NeedsRecovery;
        }
    }

    pub fn mark_needs_rebuild(&mut self, conversation_id: &str) {
        if let Some(state) = self.groups.get_mut(conversation_id) {
            state.status = MlsStateStatus::NeedsRebuild;
        }
    }

    pub fn attempt_recovery(&mut self, conversation_id: &str) -> CoreResult<MlsStateSummary> {
        let state = self
            .groups
            .get_mut(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation MLS state does not exist"))?;
        if state.status == MlsStateStatus::NeedsRebuild {
            return Err(CoreError::invalid_state(
                "conversation MLS state requires rebuild",
            ));
        }
        state.status = MlsStateStatus::Active;
        self.export_group_summary(conversation_id)
    }

    pub fn clear_conversation(&mut self, conversation_id: &str) {
        if let Some(mut state) = self.groups.remove(conversation_id) {
            let _ = state.group.delete(self.provider.storage());
        }
    }

    fn delete_stale_persisted_group(&mut self, group_id: &GroupId) -> CoreResult<bool> {
        let Some(mut group) =
            MlsGroup::load(self.provider.storage(), group_id).map_err(|error| {
                CoreError::invalid_state(format!("failed to load stale MLS group state: {error}"))
            })?
        else {
            return Ok(false);
        };
        group.delete(self.provider.storage()).map_err(|error| {
            CoreError::invalid_state(format!("failed to delete stale MLS group state: {error}"))
        })?;
        Ok(true)
    }

    pub fn has_conversation(&self, conversation_id: &str) -> bool {
        self.groups.contains_key(conversation_id)
    }

    /// Content hash of the whole OpenMLS provider store.
    ///
    /// This is the oracle for the "authentication failure leaves no trace"
    /// invariant: an inbound record that fails to authenticate must leave this
    /// value unchanged. It covers everything OpenMLS persists — ratchet state,
    /// queued proposals, epoch key pairs, KeyPackage private material — so it
    /// catches the pre-verdict writes that a per-field assertion would miss.
    ///
    /// Pair it with [`Self::state_fingerprint`]: the store hash alone does not
    /// cover the adapter's in-memory sidecars.
    pub fn provider_state_sha256(&self) -> CoreResult<String> {
        store_sha256(&self.serializable_store()?)
    }

    /// Everything the adapter holds that a caller can observe, in one value.
    ///
    /// `provider_state_sha256` plus the per-conversation summaries, which carry
    /// the in-memory-only `status` and the PCS sidecar epoch. Comparing two
    /// fingerprints is the strongest "nothing moved" assertion available
    /// without reaching into private fields.
    pub fn state_fingerprint(&self) -> CoreResult<MlsStateFingerprint> {
        let mut conversations = BTreeMap::new();
        let mut pcs_sidecars = BTreeMap::new();
        for (conversation_id, state) in &self.groups {
            conversations.insert(
                conversation_id.clone(),
                self.export_group_summary(conversation_id)?,
            );
            pcs_sidecars.insert(
                conversation_id.clone(),
                (state.pcs_update_epoch, state.pcs_updates.len()),
            );
        }
        Ok(MlsStateFingerprint {
            provider_state_sha256: self.provider_state_sha256()?,
            conversations,
            pcs_sidecars,
        })
    }

    pub fn member_device_ids_for_user(
        &self,
        conversation_id: &str,
        user_id: &str,
    ) -> CoreResult<Vec<String>> {
        let state = self
            .groups
            .get(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation MLS state does not exist"))?;
        let mut result = Vec::new();
        for member in state.group.members() {
            let identity = extract_sender_identity(&member.credential)?;
            let parts: Vec<&str> = identity.split('|').collect();
            if parts.first() == Some(&user_id) {
                if let Some(device_id) = parts.get(1) {
                    result.push(device_id.to_string());
                }
            }
        }
        Ok(result)
    }

    pub fn export_persisted_group_state(&self, conversation_id: &str) -> CoreResult<String> {
        if !self.groups.contains_key(conversation_id) {
            return Err(CoreError::invalid_input(
                "conversation MLS state does not exist",
            ));
        }
        self.serialize_with_store(self.serializable_store()?, Some(conversation_id))
    }

    pub fn export_bootstrap_state(&self) -> CoreResult<String> {
        self.export_serializable_state()
    }

    /// Delete a MLS group for a conversation.
    /// This removes the group state from memory and should be followed by
    /// persistence deletion of the serialized state.
    pub fn delete_group(&mut self, conversation_id: &str) -> CoreResult<()> {
        if let Some(mut state) = self.groups.remove(conversation_id) {
            state
                .group
                .delete(self.provider.storage())
                .map_err(|error| {
                    CoreError::invalid_state(format!("failed to delete MLS group state: {error}"))
                })?;
            return Ok(());
        }

        let group_id = GroupId::from_slice(conversation_id.as_bytes());
        self.delete_stale_persisted_group(&group_id)?;
        Ok(())
    }

    pub fn restore_from_bootstrap_state(serialized_state: &str) -> CoreResult<Self> {
        let provider = OpenMlsRustCrypto::default();
        let parsed: PersistedGroupState =
            serde_json::from_str(serialized_state).map_err(|error| {
                CoreError::invalid_state(format!(
                    "failed to decode persisted MLS bootstrap state: {error}"
                ))
            })?;
        let PersistedGroupState {
            credential_identity,
            local_device_id,
            signer,
            credential_with_key,
            storage,
            pcs_update_sidecar: _,
        } = parsed;
        {
            let mut values = provider.storage().values.write().map_err(|_| {
                CoreError::invalid_state("failed to write restored MLS provider storage")
            })?;
            for (key, value) in &storage.values {
                let decoded_key = BASE64
                    .decode(key)
                    .map_err(|_| CoreError::invalid_input("invalid persisted MLS storage key"))?;
                let decoded_value = BASE64
                    .decode(value)
                    .map_err(|_| CoreError::invalid_input("invalid persisted MLS storage value"))?;
                values.insert(decoded_key, decoded_value);
            }
        }
        Ok(Self {
            provider,
            signer,
            credential_with_key,
            credential_identity,
            local_device_id,
            groups: BTreeMap::new(),
        })
    }

    fn export_serializable_state(&self) -> CoreResult<String> {
        self.serialize_with_store(self.serializable_store()?, None)
    }

    fn serializable_store(&self) -> CoreResult<SerializableStore> {
        let values = self.provider.storage().values.read().map_err(|_| {
            CoreError::invalid_state("failed to read MLS provider storage for persistence")
        })?;
        Ok(SerializableStore {
            values: values
                .iter()
                .map(|(key, value)| (BASE64.encode(key), BASE64.encode(value)))
                .collect(),
        })
    }

    fn serialize_with_store(
        &self,
        storage: SerializableStore,
        only_conversation_id: Option<&str>,
    ) -> CoreResult<String> {
        let pcs_update_sidecar = self
            .groups
            .iter()
            .filter(|(conversation_id, state)| {
                only_conversation_id.is_none_or(|id| id == conversation_id.as_str())
                    && (only_conversation_id.is_some() || !state.pcs_updates.is_empty())
            })
            .map(|(conversation_id, state)| {
                (
                    conversation_id.clone(),
                    PcsUpdateSidecar {
                        epoch: state.pcs_update_epoch,
                        proposals: state.pcs_updates.clone(),
                    },
                )
            })
            .collect();
        serde_json::to_string(&PersistedGroupState {
            credential_identity: self.credential_identity.clone(),
            local_device_id: self.local_device_id.clone(),
            signer: copy_signer(&self.signer)?,
            credential_with_key: self.credential_with_key.clone(),
            storage,
            pcs_update_sidecar,
        })
        .map_err(|error| {
            CoreError::invalid_state(format!("failed to serialize MLS group state: {error}"))
        })
    }

    pub fn restore_from_persisted_states(
        persisted_states: &[(String, MlsStateSummary, Option<String>)],
    ) -> CoreResult<RestoreMlsStateResult> {
        if persisted_states.is_empty() {
            return Ok(RestoreMlsStateResult::default());
        }

        let mut parsed_states = Vec::new();
        let mut failed_conversation_ids = Vec::new();
        let mut failures = Vec::new();
        let provider = OpenMlsRustCrypto::default();
        let mut template: Option<(SignatureKeyPair, CredentialWithKey, String, String)> = None;
        let mut restored_sidecars: BTreeMap<String, PcsUpdateSidecar> = BTreeMap::new();

        for (conversation_id, summary, serialized_state) in persisted_states {
            let Some(serialized_state) = serialized_state.as_ref() else {
                if summary.status == MlsStateStatus::NeedsRebuild {
                    parsed_states.push((conversation_id.clone(), summary.clone()));
                    continue;
                }
                record_restore_failure(
                    &mut failed_conversation_ids,
                    &mut failures,
                    RestoreMlsFailure::new(
                        conversation_id,
                        "missing_serialized_state",
                        Some("persisted MLS summary has no serialized group state".into()),
                    ),
                );
                continue;
            };
            let parsed: PersistedGroupState = match serde_json::from_str(serialized_state) {
                Ok(parsed) => parsed,
                Err(error) => {
                    record_restore_failure(
                        &mut failed_conversation_ids,
                        &mut failures,
                        RestoreMlsFailure::new(
                            conversation_id,
                            "invalid_serialized_state",
                            Some(format!(
                                "failed to parse persisted MLS group state: {error}"
                            )),
                        ),
                    );
                    continue;
                }
            };

            let PersistedGroupState {
                credential_identity,
                local_device_id,
                signer,
                credential_with_key,
                storage,
                mut pcs_update_sidecar,
            } = parsed;
            restored_sidecars.insert(
                conversation_id.clone(),
                pcs_update_sidecar
                    .remove(conversation_id)
                    .unwrap_or_default(),
            );

            if let Some((_, _, template_identity, template_device_id)) = template.as_ref() {
                if template_identity != &credential_identity
                    || template_device_id != &local_device_id
                {
                    record_restore_failure(
                        &mut failed_conversation_ids,
                        &mut failures,
                        RestoreMlsFailure::new(
                            conversation_id,
                            "identity_mismatch",
                            Some(
                                "persisted MLS group belongs to a different local identity or device"
                                    .into(),
                            ),
                        ),
                    );
                    continue;
                }
            } else {
                template = Some((
                    signer,
                    credential_with_key,
                    credential_identity.clone(),
                    local_device_id.clone(),
                ));
            }

            {
                let mut decoded_values = Vec::with_capacity(storage.values.len());
                let mut storage_decode_failed = false;
                for (key, value) in &storage.values {
                    let decoded_key = match BASE64.decode(key) {
                        Ok(value) => value,
                        Err(error) => {
                            record_restore_failure(
                                &mut failed_conversation_ids,
                                &mut failures,
                                RestoreMlsFailure::new(
                                    conversation_id,
                                    "invalid_storage_key",
                                    Some(format!(
                                        "persisted MLS storage key is not base64: {error}"
                                    )),
                                ),
                            );
                            storage_decode_failed = true;
                            break;
                        }
                    };
                    let decoded_value = match BASE64.decode(value) {
                        Ok(value) => value,
                        Err(error) => {
                            record_restore_failure(
                                &mut failed_conversation_ids,
                                &mut failures,
                                RestoreMlsFailure::new(
                                    conversation_id,
                                    "invalid_storage_value",
                                    Some(format!(
                                        "persisted MLS storage value is not base64: {error}"
                                    )),
                                ),
                            );
                            storage_decode_failed = true;
                            break;
                        }
                    };
                    decoded_values.push((decoded_key, decoded_value));
                }
                if storage_decode_failed {
                    continue;
                }
                let mut values = provider.storage().values.write().map_err(|_| {
                    CoreError::invalid_state("failed to write restored MLS provider storage")
                })?;
                values.extend(decoded_values);
            }

            if failures
                .iter()
                .any(|failure| failure.conversation_id == *conversation_id)
            {
                continue;
            }

            parsed_states.push((conversation_id.clone(), summary.clone()));
        }

        let Some((signer, credential_with_key, credential_identity, local_device_id)) = template
        else {
            let summaries = persisted_states
                .iter()
                .map(|(conversation_id, summary, _)| (conversation_id.clone(), summary.clone()))
                .collect();
            return Ok(RestoreMlsStateResult {
                adapter: None,
                summaries,
                failed_conversation_ids,
                failures,
            });
        };

        let mut adapter = Self {
            provider,
            signer,
            credential_with_key,
            credential_identity,
            local_device_id,
            groups: BTreeMap::new(),
        };
        let mut summaries = BTreeMap::new();

        for (conversation_id, mut summary) in parsed_states {
            if summary.status == MlsStateStatus::NeedsRebuild {
                summaries.insert(conversation_id, summary);
                continue;
            }
            let group_id = GroupId::from_slice(conversation_id.as_bytes());
            let group = match MlsGroup::load(adapter.provider.storage(), &group_id) {
                Ok(Some(group)) => group,
                Ok(None) => {
                    record_restore_failure(
                        &mut failed_conversation_ids,
                        &mut failures,
                        RestoreMlsFailure::new(
                            &conversation_id,
                            "missing_group_state",
                            Some("persisted MLS provider storage has no matching group".into()),
                        ),
                    );
                    summary.status = MlsStateStatus::NeedsRebuild;
                    summaries.insert(conversation_id, summary);
                    continue;
                }
                Err(error) => {
                    record_restore_failure(
                        &mut failed_conversation_ids,
                        &mut failures,
                        RestoreMlsFailure::new(
                            &conversation_id,
                            "load_group_state_failed",
                            Some(format!("failed to load persisted MLS group state: {error}")),
                        ),
                    );
                    summary.status = MlsStateStatus::NeedsRebuild;
                    summaries.insert(conversation_id, summary);
                    continue;
                }
            };

            let member_device_ids = match extract_member_device_ids(&group) {
                Ok(member_device_ids) => member_device_ids,
                Err(error) => {
                    record_restore_failure(
                        &mut failed_conversation_ids,
                        &mut failures,
                        RestoreMlsFailure::new(
                            &conversation_id,
                            "extract_members_failed",
                            Some(format!("failed to read MLS member devices: {error}")),
                        ),
                    );
                    summary.status = MlsStateStatus::NeedsRebuild;
                    summaries.insert(conversation_id, summary);
                    continue;
                }
            };

            if summary.status == MlsStateStatus::NeedsRebuild {
                summary.status = MlsStateStatus::NeedsRebuild;
                summaries.insert(conversation_id, summary);
                continue;
            }

            let status = summary.status;
            let epoch = group.epoch().as_u64();
            let sidecar = restored_sidecars
                .remove(&conversation_id)
                .unwrap_or_default();
            let (pcs_updates, pcs_update_epoch) = if sidecar.epoch == epoch {
                (sidecar.proposals, sidecar.epoch)
            } else {
                (Vec::new(), epoch)
            };
            let exported = MlsStateSummary {
                conversation_id: conversation_id.clone(),
                epoch,
                member_device_ids: member_device_ids.iter().cloned().collect(),
                status,
                updated_at: epoch,
            };
            adapter.groups.insert(
                conversation_id.clone(),
                LocalMlsState {
                    group,
                    member_device_ids,
                    status,
                    pcs_updates,
                    pcs_update_epoch,
                },
            );
            summaries.insert(conversation_id, exported);
        }

        Ok(RestoreMlsStateResult {
            adapter: Some(adapter),
            summaries,
            failed_conversation_ids,
            failures,
        })
    }

    /// Join a group from an inbound Welcome, on a fork, adopting only if the
    /// Welcome authenticates as the one the envelope claims it is.
    ///
    /// Everything here runs against `fork()` and is adopted with `*self =
    /// fork` only on success, because two of the steps write to provider
    /// storage *before* anything is validated:
    ///
    /// * Rebuild semantics require clearing the live group first — openmls
    ///   refuses to stage a Welcome whose `GroupId` already exists in storage
    ///   (`WelcomeError::GroupAlreadyExists`), and the `GroupId` is derived
    ///   deterministically from `conversation_id`. Done on the live adapter,
    ///   a forged Welcome for an existing conversation deletes that
    ///   conversation's group outright.
    /// * `StagedWelcome::new_from_welcome` deletes the matched KeyPackage from
    ///   storage as soon as it finds one — before group-secret decryption,
    ///   before the GroupInfo signature check, before the confirmation tag.
    ///   openmls documents this ("calling this function will consume the key
    ///   material ... even if the caller does not turn the StagedWelcome into
    ///   an MlsGroup"). Since published KeyPackage hash refs are public,
    ///   anyone could otherwise drain our one-time KeyPackage pool by minting
    ///   Welcomes with garbage secrets. Last-resort KeyPackages are exempt
    ///   from the delete, so the pool is the exposed surface.
    ///
    /// On any rejection the fork is dropped and the live adapter is unchanged,
    /// bit for bit — which is what `state_fingerprint()` asserts in the tests.
    fn ingest_welcome(
        &mut self,
        conversation_id: &str,
        sender_device_id: &str,
        payload_b64: &str,
    ) -> CoreResult<IngestResult> {
        let Some(welcome) = decode_welcome_body(payload_b64) else {
            log::warn!(
                "ingest_welcome: discarding undecodable welcome for conversation {}",
                redact_id("conversation", conversation_id)
            );
            return Ok(IngestResult::Rejected(RejectReason::Malformed));
        };

        let mut fork = self.fork()?;
        // Rebuild/rejoin semantics treat a fresh welcome as authoritative for
        // this conversation, so stale local state is replaced — but on the
        // fork, so a Welcome that fails the checks below replaces nothing.
        fork.clear_conversation(conversation_id);

        // max_past_epochs(1): see the comment in create_conversation — same
        // reorder-tolerance trade-off, same epoch e-1 forward-secrecy boundary.
        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .max_past_epochs(1)
            .build();
        let staged = match StagedWelcome::new_from_welcome(&fork.provider, &config, welcome, None) {
            Ok(staged) => staged,
            Err(error) => {
                log::warn!(
                    "ingest_welcome: discarding unusable welcome for conversation {}: {error}",
                    redact_id("conversation", conversation_id)
                );
                return Ok(IngestResult::Rejected(RejectReason::Malformed));
            }
        };

        // Bind the Welcome to the conversation the envelope claims. Without
        // this, replaying a legitimate Welcome for conversation A under an
        // envelope naming conversation B installs A's group as B and destroys
        // B's live group.
        let expected_group_id = GroupId::from_slice(conversation_id.as_bytes());
        if staged.group_context().group_id() != &expected_group_id {
            log::warn!(
                "ingest_welcome: welcome group_id does not match conversation {}",
                redact_id("conversation", conversation_id)
            );
            return Ok(IngestResult::Rejected(RejectReason::Malformed));
        }

        // Bind the Welcome's author to the envelope's sender, so a third party
        // who fetched our published KeyPackage cannot hand us a group that we
        // would then treat as this conversation.
        let Ok(welcome_sender) = staged.welcome_sender() else {
            log::warn!(
                "ingest_welcome: welcome has no resolvable sender leaf for conversation {}",
                redact_id("conversation", conversation_id)
            );
            return Ok(IngestResult::Rejected(RejectReason::Malformed));
        };
        let author = extract_sender_identity(welcome_sender.credential())?;
        if credential_device_id(&author).as_deref() != Some(sender_device_id) {
            log::warn!(
                "ingest_welcome: welcome author is not the envelope sender for conversation {}",
                redact_id("conversation", conversation_id)
            );
            return Ok(IngestResult::Rejected(RejectReason::Malformed));
        }

        let group = match staged.into_group(&fork.provider) {
            Ok(group) => group,
            Err(error) => {
                log::warn!(
                    "ingest_welcome: failed to join group for conversation {}: {error}",
                    redact_id("conversation", conversation_id)
                );
                return Ok(IngestResult::Rejected(RejectReason::Malformed));
            }
        };
        let member_device_ids = extract_member_device_ids(&group)?;
        fork.groups.insert(
            conversation_id.to_string(),
            local_mls_state(group, member_device_ids, MlsStateStatus::Active),
        );
        let epoch = fork.export_group_summary(conversation_id)?.epoch;

        // Authenticated: adopt the fork.
        *self = fork;
        Ok(IngestResult::AppliedWelcome { epoch })
    }

    pub fn protocol_message_epoch(payload_b64: &str) -> CoreResult<u64> {
        Ok(decode_mls_message(payload_b64)?
            .try_into_protocol_message()
            .map_err(|_| CoreError::invalid_input("expected a protocol MLS message"))?
            .epoch()
            .as_u64())
    }

    /// Process an inbound MLS protocol message on a fork, adopting the result
    /// only if it applied.
    ///
    /// Three writes here happen *before* the frame is known to be
    /// authentic, so all of them run against `fork()`:
    ///
    /// * `store_pending_proposal` persists a queued proposal for any commit at
    ///   `epoch >= live`, forged ones included.
    /// * `process_message` ratchets the sender's decryption ratchet forward
    ///   and prunes past secrets *before* attempting the AEAD open, so a
    ///   forged frame with a far-future generation destroys the key material
    ///   for the legitimate generations it skipped.
    /// * The status transitions this function used to make on failure.
    ///
    /// Dropping the fork therefore leaves `state_fingerprint()` untouched,
    /// which is what the "leaves no trace" tests assert.
    fn ingest_protocol_message(
        &mut self,
        conversation_id: &str,
        _sender_device_id: &str,
        message_type: MessageType,
        payload_b64: &str,
    ) -> CoreResult<IngestResult> {
        let Some(protocol_message) = decode_protocol_message(payload_b64) else {
            log::warn!(
                "ingest_protocol_message: discarding undecodable payload for conversation {}",
                redact_id("conversation", conversation_id)
            );
            return Ok(IngestResult::Rejected(RejectReason::Malformed));
        };
        let live_epoch = self
            .groups
            .get(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation MLS state does not exist"))?
            .group
            .epoch()
            .as_u64();
        let message_epoch = protocol_message.epoch().as_u64();
        let from_previous_epoch = message_epoch < live_epoch;
        // A handshake message for an epoch we have already left can never
        // apply. Decided here, before `process_message`, so a stale frame
        // never touches the ratchet.
        if matches!(
            message_type,
            MessageType::MlsCommit | MessageType::MlsProposal
        ) && from_previous_epoch
        {
            return Ok(IngestResult::Rejected(RejectReason::Replay));
        }

        let mut fork = self.fork()?;
        let verdict = Self::ingest_protocol_message_on(
            &mut fork,
            conversation_id,
            message_type,
            protocol_message,
            from_previous_epoch,
        )?;
        if matches!(
            verdict,
            IngestResult::AppliedApplication(_)
                | IngestResult::AppliedCommit { .. }
                | IngestResult::AppliedProposal
        ) {
            *self = fork;
        }
        Ok(verdict)
    }

    fn ingest_protocol_message_on(
        adapter: &mut Self,
        conversation_id: &str,
        message_type: MessageType,
        protocol_message: ProtocolMessage,
        from_previous_epoch: bool,
    ) -> CoreResult<IngestResult> {
        let provider = &adapter.provider;
        let state = adapter.groups.get_mut(conversation_id).ok_or_else(|| {
            CoreError::invalid_state("forked adapter is missing the conversation")
        })?;
        if message_type == MessageType::MlsCommit && !from_previous_epoch {
            align_pcs_sidecar_epoch(state);
            for proposal in state.pcs_updates.clone() {
                if !is_member_self_update(&proposal) {
                    continue;
                }
                state
                    .group
                    .store_pending_proposal(provider.storage(), proposal)
                    .map_err(|error| {
                        CoreError::invalid_state(format!(
                            "failed to restore PCS update proposal: {error:?}"
                        ))
                    })?;
            }
        }
        let processed = match state.group.process_message(provider, protocol_message) {
            Ok(processed) => processed,
            Err(error) => {
                let verdict = classify_process_error(error)?;
                log::warn!(
                    "ingest_protocol_message: {verdict:?} for conversation {}",
                    redact_id("conversation", conversation_id)
                );
                return Ok(verdict.into());
            }
        };
        let sender_identity = extract_sender_identity(processed.credential())?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(application) => {
                state.status = MlsStateStatus::Active;
                Ok(IngestResult::AppliedApplication(
                    DecryptedApplicationMessage {
                        plaintext: application.into_bytes(),
                        sender_identity,
                        from_previous_epoch,
                    },
                ))
            }
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                if message_type != MessageType::MlsCommit {
                    return Ok(IngestResult::Rejected(RejectReason::Malformed));
                }
                state
                    .group
                    .merge_staged_commit(provider, *staged_commit)
                    .map_err(|_| CoreError::invalid_state("failed to merge staged commit"))?;
                state.member_device_ids = extract_member_device_ids(&state.group)?;
                state.pcs_updates.clear();
                state.pcs_update_epoch = state.group.epoch().as_u64();
                state.status = MlsStateStatus::Active;
                Ok(IngestResult::AppliedCommit {
                    epoch: state.group.epoch().as_u64(),
                })
            }
            ProcessedMessageContent::ProposalMessage(proposal) => {
                if message_type != MessageType::MlsProposal {
                    return Ok(IngestResult::Rejected(RejectReason::Malformed));
                }
                if is_member_self_update(&proposal) {
                    push_pcs_update(state, *proposal);
                } else {
                    log::warn!(
                        "ignoring non-self-update MLS proposal for conversation {}",
                        redact_id("conversation", conversation_id)
                    );
                }
                state.status = MlsStateStatus::Active;
                Ok(IngestResult::AppliedProposal)
            }
            // An external join proposal or other content type we do not
            // accept from this path. Terminal: no future local state makes it
            // acceptable, so discard rather than retry forever.
            _ => Ok(IngestResult::Rejected(RejectReason::Unauthorized)),
        }
    }

    fn build_published_key_package(
        provider: &OpenMlsRustCrypto,
        signer: &SignatureKeyPair,
        credential_with_key: CredentialWithKey,
        credential_identity: String,
        now_ms: u64,
    ) -> CoreResult<PublishedKeyPackage> {
        let now_seconds = now_ms / 1000;
        let not_before_seconds = now_ms.saturating_sub(KEY_PACKAGE_CLOCK_SKEW_MS) / 1000;
        let not_after_ms = now_ms
            .checked_add(KEY_PACKAGE_LIFETIME_MS)
            .ok_or_else(|| CoreError::invalid_input("key package lifetime overflows timestamp"))?;
        let not_after_seconds = not_after_ms / 1000;
        let lifetime = Lifetime::init(not_before_seconds, not_after_seconds);
        let key_package_bundle = KeyPackage::builder()
            .key_package_lifetime(lifetime)
            .build(DEFAULT_CIPHERSUITE, provider, signer, credential_with_key)
            .map_err(|error| {
                CoreError::invalid_state(format!("failed to build key package: {error}"))
            })?;
        let key_package = key_package_bundle.key_package().clone();
        let key_package_bytes = MlsMessageOut::from(key_package)
            .to_bytes()
            .map_err(|error| {
                CoreError::invalid_state(format!("failed to encode key package: {error}"))
            })?;
        let key_package_b64 = BASE64.encode(key_package_bytes);
        Ok(PublishedKeyPackage {
            key_package_ref: key_package_b64.clone(),
            key_package_b64,
            lifecycle_version: KEY_PACKAGE_LIFECYCLE_VERSION,
            not_before: not_before_seconds.saturating_mul(1000),
            created_at: now_seconds.saturating_mul(1000),
            expires_at: not_after_seconds.saturating_mul(1000),
            state: PublishedKeyPackageState::Advertised,
            credential_identity,
        })
    }

    /// Returns true if the Welcome's encrypted group secrets target
    /// `key_package_b64` specifically, i.e. this KeyPackage (rather than
    /// some other one, such as a one-time pool entry) was the one consumed
    /// to build this Welcome for us. Used to scope the reactive
    /// "rotate the last-resort KeyPackage after a Welcome arrives" behavior
    /// to Welcomes that actually consumed the last-resort KeyPackage —
    /// Welcomes built from a claimed one-time pool entry must not trigger
    /// it, since the pool's own count already dropped server-side and the
    /// periodic maintenance timer is what tops it back up.
    pub fn welcome_targets_key_package(
        &self,
        welcome_payload_b64: &str,
        key_package_b64: &str,
    ) -> CoreResult<bool> {
        let welcome_bytes = BASE64
            .decode(welcome_payload_b64)
            .map_err(|_| CoreError::invalid_input("invalid base64 welcome payload"))?;
        let welcome_message =
            MlsMessageIn::tls_deserialize_exact(welcome_bytes).map_err(|error| {
                CoreError::invalid_input(format!("failed to decode welcome message: {error}"))
            })?;
        let welcome = match welcome_message.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => {
                return Err(CoreError::invalid_input(
                    "decoded MLS message was not a welcome",
                ));
            }
        };
        let candidate = decode_key_package(key_package_b64)?;
        let candidate_ref = candidate
            .hash_ref(self.provider.crypto())
            .map_err(|error| {
                CoreError::invalid_state(format!("failed to hash key package: {error}"))
            })?;
        Ok(welcome
            .secrets()
            .iter()
            .any(|secret| secret.new_member() == candidate_ref))
    }
}

fn current_unix_time_ms() -> CoreResult<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .map_err(|_| CoreError::invalid_state("system clock is before the Unix epoch"))
}

fn build_credential_identity(local_identity: &LocalIdentityState) -> String {
    format!(
        "{}|{}|{}|{}",
        local_identity.user_identity.user_id,
        local_identity.device_identity.device_id,
        local_identity.device_identity.device_public_key,
        local_identity.device_identity.binding.signature,
    )
}

fn is_member_self_update(proposal: &QueuedProposal) -> bool {
    matches!(proposal.proposal(), Proposal::Update(_))
        && matches!(proposal.sender(), Sender::Member(_))
}

fn align_pcs_sidecar_epoch(state: &mut LocalMlsState) {
    let epoch = state.group.epoch().as_u64();
    if state.pcs_update_epoch != epoch {
        state.pcs_updates.clear();
        state.pcs_update_epoch = epoch;
    }
}

fn push_pcs_update(state: &mut LocalMlsState, proposal: QueuedProposal) {
    if !is_member_self_update(&proposal) {
        log::warn!("dropping non-self-update MLS proposal from PCS sidecar");
        return;
    }
    align_pcs_sidecar_epoch(state);
    if state
        .pcs_updates
        .iter()
        .any(|queued| queued.proposal_reference_ref() == proposal.proposal_reference_ref())
    {
        return;
    }
    state.pcs_updates.push(proposal);
}

fn leaf_key_b64_for_group(group: &MlsGroup) -> CoreResult<String> {
    let own_index = group.own_leaf_index();
    let member = group
        .members()
        .find(|member| member.index == own_index)
        .ok_or_else(|| CoreError::invalid_state("own MLS leaf is missing"))?;
    Ok(BASE64.encode(member.encryption_key))
}

fn extract_sender_identity(credential: &Credential) -> CoreResult<String> {
    let basic = BasicCredential::try_from(credential.clone())
        .map_err(|_| CoreError::invalid_input("unsupported MLS credential type"))?;
    String::from_utf8(basic.identity().to_vec())
        .map_err(|_| CoreError::invalid_input("credential identity must be utf-8"))
}

fn extract_member_device_ids(group: &MlsGroup) -> CoreResult<BTreeSet<String>> {
    let mut members = BTreeSet::new();
    for member in group.members() {
        let identity = extract_sender_identity(&member.credential)?;
        let device_id = identity
            .split('|')
            .nth(1)
            .ok_or_else(|| CoreError::invalid_input("credential identity missing device_id"))?;
        members.insert(device_id.to_string());
    }
    Ok(members)
}

fn member_leaf_indices_for_devices(
    group: &MlsGroup,
    device_ids: &[String],
) -> CoreResult<Vec<LeafNodeIndex>> {
    let mut indices = Vec::with_capacity(device_ids.len());
    for device_id in device_ids {
        let member = group
            .members()
            .find(|member| {
                extract_sender_identity(&member.credential)
                    .ok()
                    .and_then(|identity| identity.split('|').nth(1).map(str::to_string))
                    .as_deref()
                    == Some(device_id.as_str())
            })
            .ok_or_else(|| {
                CoreError::invalid_input(format!(
                    "MLS member for device {device_id} does not exist"
                ))
            })?;
        indices.push(member.index);
    }
    Ok(indices)
}

fn encode_mls_message(message: MlsMessageOut) -> CoreResult<String> {
    Ok(BASE64.encode(message.to_bytes().map_err(|error| {
        CoreError::invalid_state(format!("failed to encode MLS message: {error}"))
    })?))
}

fn decode_mls_message(payload_b64: &str) -> CoreResult<MlsMessageIn> {
    let bytes = BASE64
        .decode(payload_b64)
        .map_err(|_| CoreError::invalid_input("invalid base64 MLS message payload"))?;
    MlsMessageIn::tls_deserialize_exact(bytes)
        .map_err(|error| CoreError::invalid_input(format!("failed to decode MLS message: {error}")))
}

/// Decode a base64 MLS message and extract its protocol message body.
///
/// `None` for anything an adversary can author. See `decode_welcome_body` for
/// why this must not be an `Err`.
fn decode_protocol_message(payload_b64: &str) -> Option<ProtocolMessage> {
    let bytes = BASE64.decode(payload_b64).ok()?;
    MlsMessageIn::tls_deserialize_exact(bytes)
        .ok()?
        .try_into_protocol_message()
        .ok()
}

/// Decode a base64 MLS message and extract its Welcome body.
///
/// Returns `None` for anything an adversary can author: bad base64, bad TLS,
/// or a well-formed MLS message that is not a Welcome. None of that is a local
/// fault, so none of it may escape as an `Err` — an `Err` out of the ingest
/// path aborts the whole inbox batch and stalls the device permanently.
fn decode_welcome_body(payload_b64: &str) -> Option<Welcome> {
    let bytes = BASE64.decode(payload_b64).ok()?;
    match MlsMessageIn::tls_deserialize_exact(bytes).ok()?.extract() {
        MlsMessageBodyIn::Welcome(welcome) => Some(welcome),
        _ => None,
    }
}

/// The device id field of an MLS credential identity.
///
/// Identities are built by `build_credential_identity` as
/// `user_id|device_id|device_public_key|binding_signature`.
fn credential_device_id(identity: &str) -> Option<String> {
    let parts: Vec<&str> = identity.split('|').collect();
    if parts.len() != 4 {
        return None;
    }
    parts.get(1).map(|device_id| device_id.to_string())
}

fn decode_key_package(payload_b64: &str) -> CoreResult<KeyPackage> {
    let bytes = BASE64
        .decode(payload_b64)
        .map_err(|_| CoreError::invalid_input("invalid base64 key package payload"))?;
    let message = MlsMessageIn::tls_deserialize_exact(bytes).map_err(|error| {
        CoreError::invalid_input(format!("failed to decode key package message: {error}"))
    })?;
    match message.extract() {
        MlsMessageBodyIn::KeyPackage(key_package) => {
            let provider = OpenMlsRustCrypto::default();
            key_package
                .validate(provider.crypto(), ProtocolVersion::Mls10)
                .map_err(|error| {
                    CoreError::invalid_input(format!("failed to validate key package: {error}"))
                })
        }
        _ => Err(CoreError::invalid_input(
            "decoded MLS message was not a key package",
        )),
    }
}

pub fn validate_published_key_package_lifetime(
    payload_b64: &str,
    lifecycle_version: u16,
    not_before_ms: u64,
    created_at_ms: u64,
    expires_at_ms: u64,
) -> CoreResult<()> {
    if lifecycle_version != KEY_PACKAGE_LIFECYCLE_VERSION
        || expires_at_ms.saturating_sub(created_at_ms) != KEY_PACKAGE_LIFETIME_MS
        || not_before_ms != created_at_ms.saturating_sub(KEY_PACKAGE_CLOCK_SKEW_MS)
    {
        return Err(CoreError::new(
            "keypackage_lifetime_invalid",
            "key package lifecycle metadata is invalid",
        ));
    }
    let key_package = decode_key_package(payload_b64).map_err(|_| {
        CoreError::new(
            "keypackage_lifetime_invalid",
            "key package payload is invalid",
        )
    })?;
    let lifetime = key_package.life_time();
    if lifetime.not_before().saturating_mul(1000) != not_before_ms
        || lifetime.not_after().saturating_mul(1000) != expires_at_ms
    {
        return Err(CoreError::new(
            "keypackage_lifetime_invalid",
            "key package metadata does not match the MLS lifetime",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        key_package_rotation_jitter_ms, validate_published_key_package_lifetime, IngestResult,
        MlsAdapter, MlsAdapterModule, PeerDeviceKeyPackage, PublishedKeyPackage,
        RejectReason, KEY_PACKAGE_CLOCK_SKEW_MS, KEY_PACKAGE_LIFECYCLE_VERSION,
        KEY_PACKAGE_LIFETIME_MS, KEY_PACKAGE_ROTATION_WINDOW_MS, ONE_TIME_KEY_PACKAGE_POOL_TARGET,
    };
    use crate::identity::IdentityManager;
    use crate::model::{MessageType, MlsStateStatus};

    const ALICE_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const BOB_MNEMONIC: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";

    fn test_now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test clock")
            .as_millis() as u64
    }

    #[test]
    fn module_name_is_stable() {
        assert_eq!(MlsAdapterModule.name(), "mls_adapter");
    }

    #[test]
    fn key_package_can_be_generated() {
        let identity = IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone"))
            .expect("identity");
        let package = MlsAdapter::generate_key_package(&identity, test_now_ms()).expect("package");
        assert!(!package.key_package_b64.is_empty());
    }

    #[test]
    fn key_package_uses_explicit_84_day_mls_lifetime() {
        let identity = IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone"))
            .expect("identity");
        let package = MlsAdapter::generate_key_package(&identity, test_now_ms()).expect("package");
        assert_eq!(package.lifecycle_version, KEY_PACKAGE_LIFECYCLE_VERSION);
        assert_eq!(
            package.expires_at - package.created_at,
            KEY_PACKAGE_LIFETIME_MS
        );
        assert_eq!(
            package.created_at - package.not_before,
            KEY_PACKAGE_CLOCK_SKEW_MS
        );
        validate_published_key_package_lifetime(
            &package.key_package_b64,
            package.lifecycle_version,
            package.not_before,
            package.created_at,
            package.expires_at,
        )
        .expect("outer metadata must match MLS lifetime");
    }

    #[test]
    fn one_time_key_package_batch_has_distinct_init_secrets() {
        let identity = IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone"))
            .expect("identity");
        let (adapter, _) = MlsAdapter::bootstrap(&identity).expect("adapter");
        let batch = adapter
            .generate_one_time_key_packages(ONE_TIME_KEY_PACKAGE_POOL_TARGET, test_now_ms())
            .expect("batch");
        assert_eq!(batch.len(), ONE_TIME_KEY_PACKAGE_POOL_TARGET as usize);
        let unique: std::collections::BTreeSet<_> = batch
            .iter()
            .map(|package| package.key_package_b64.clone())
            .collect();
        assert_eq!(
            unique.len(),
            batch.len(),
            "every one-time key package must carry a distinct init secret"
        );
        for package in &batch {
            validate_published_key_package_lifetime(
                &package.key_package_b64,
                package.lifecycle_version,
                package.not_before,
                package.created_at,
                package.expires_at,
            )
            .expect("each pool entry must have valid MLS lifecycle metadata");
        }
    }

    #[test]
    fn rotation_boundary_and_device_jitter_are_stable() {
        let device_id = "device:alice:phone";
        let jitter = key_package_rotation_jitter_ms(device_id);
        assert_eq!(jitter, key_package_rotation_jitter_ms(device_id));
        let package = PublishedKeyPackage {
            key_package_ref: "ref".into(),
            key_package_b64: "payload".into(),
            lifecycle_version: KEY_PACKAGE_LIFECYCLE_VERSION,
            not_before: 1,
            created_at: KEY_PACKAGE_CLOCK_SKEW_MS + 1,
            expires_at: KEY_PACKAGE_CLOCK_SKEW_MS + 1 + KEY_PACKAGE_LIFETIME_MS,
            state: Default::default(),
            credential_identity: "device:alice:phone".into(),
        };
        let threshold = package
            .expires_at
            .saturating_sub(KEY_PACKAGE_ROTATION_WINDOW_MS + jitter);
        assert!(!package.should_rotate_at(threshold - 1, device_id));
        assert!(package.should_rotate_at(threshold, device_id));
        assert!(package.should_rotate_at(package.expires_at, device_id));
    }

    #[test]
    fn mismatched_outer_lifetime_is_rejected() {
        let identity = IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone"))
            .expect("identity");
        let package = MlsAdapter::generate_key_package(&identity, test_now_ms()).expect("package");
        let error = validate_published_key_package_lifetime(
            &package.key_package_b64,
            package.lifecycle_version,
            package.not_before,
            package.created_at,
            package.expires_at + 1_000,
        )
        .expect_err("mismatched outer expiry must fail");
        assert_eq!(error.code(), "keypackage_lifetime_invalid");
    }

    #[test]
    fn welcome_import_and_application_message_round_trip() {
        let alice_identity =
            IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone")).expect("alice");
        let bob_identity =
            IdentityManager::create_or_recover(Some(BOB_MNEMONIC), Some("phone")).expect("bob");

        let (mut alice_adapter, _) = MlsAdapter::bootstrap(&alice_identity).expect("alice adapter");
        let (mut bob_adapter, bob_package) =
            MlsAdapter::bootstrap(&bob_identity).expect("bob adapter");

        let artifacts = alice_adapter
            .create_conversation(
                "conv:alice:bob",
                &[PeerDeviceKeyPackage {
                    user_id: bob_identity.user_identity.user_id.clone(),
                    device_id: bob_identity.device_identity.device_id.clone(),
                    device_public_key: bob_identity.device_identity.device_public_key.clone(),
                    key_package_b64: bob_package.key_package_b64,
                }],
            )
            .expect("create conversation");

        let welcome_result = bob_adapter
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsWelcome,
                &artifacts.welcomes[0].payload_b64,
            )
            .expect("welcome");
        assert!(matches!(
            welcome_result,
            IngestResult::AppliedWelcome { .. }
        ));

        let commit_result = bob_adapter
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsCommit,
                &artifacts.commit_b64,
            )
            .expect("commit");
        assert_eq!(commit_result, IngestResult::Rejected(RejectReason::Replay));

        let outbound = alice_adapter
            .encrypt_application("conv:alice:bob", b"hello bob")
            .expect("application");
        let received = bob_adapter
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsApplication,
                &outbound.payload_b64,
            )
            .expect("receive");
        match received {
            IngestResult::AppliedApplication(application) => {
                assert_eq!(application.plaintext, b"hello bob");
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn replayed_application_message_is_ignored_without_recovery() {
        let alice_identity =
            IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone")).expect("alice");
        let bob_identity =
            IdentityManager::create_or_recover(Some(BOB_MNEMONIC), Some("phone")).expect("bob");

        let (mut alice_adapter, _) = MlsAdapter::bootstrap(&alice_identity).expect("alice adapter");
        let (mut bob_adapter, bob_package) =
            MlsAdapter::bootstrap(&bob_identity).expect("bob adapter");

        let artifacts = alice_adapter
            .create_conversation(
                "conv:alice:bob",
                &[PeerDeviceKeyPackage {
                    user_id: bob_identity.user_identity.user_id.clone(),
                    device_id: bob_identity.device_identity.device_id.clone(),
                    device_public_key: bob_identity.device_identity.device_public_key.clone(),
                    key_package_b64: bob_package.key_package_b64,
                }],
            )
            .expect("create conversation");

        bob_adapter
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsWelcome,
                &artifacts.welcomes[0].payload_b64,
            )
            .expect("welcome");
        let _ = bob_adapter
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsCommit,
                &artifacts.commit_b64,
            )
            .expect("commit");

        let outbound = alice_adapter
            .encrypt_application("conv:alice:bob", b"hello once")
            .expect("application");
        let first = bob_adapter
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsApplication,
                &outbound.payload_b64,
            )
            .expect("first receive");
        assert!(matches!(first, IngestResult::AppliedApplication(_)));

        let replay = bob_adapter
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsApplication,
                &outbound.payload_b64,
            )
            .expect("replay receive");
        assert_eq!(replay, IngestResult::Rejected(RejectReason::Replay));
        assert_eq!(
            bob_adapter
                .export_group_summary("conv:alice:bob")
                .expect("summary")
                .status,
            MlsStateStatus::Active
        );
    }

    #[test]
    fn delete_group_allows_recreating_same_conversation_id() {
        let alice_identity =
            IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone")).expect("alice");
        let bob_identity =
            IdentityManager::create_or_recover(Some(BOB_MNEMONIC), Some("phone")).expect("bob");

        let (mut alice_adapter, _) = MlsAdapter::bootstrap(&alice_identity).expect("alice adapter");
        let first_bob_package = MlsAdapter::generate_key_package(&bob_identity, test_now_ms())
            .expect("first bob package");
        alice_adapter
            .create_conversation(
                "conv:alice:bob",
                &[PeerDeviceKeyPackage {
                    user_id: bob_identity.user_identity.user_id.clone(),
                    device_id: bob_identity.device_identity.device_id.clone(),
                    device_public_key: bob_identity.device_identity.device_public_key.clone(),
                    key_package_b64: first_bob_package.key_package_b64,
                }],
            )
            .expect("create conversation");

        alice_adapter
            .delete_group("conv:alice:bob")
            .expect("delete group");
        let second_bob_package =
            MlsAdapter::generate_key_package(&bob_identity, test_now_ms().saturating_add(1_000))
                .expect("second bob package");
        alice_adapter
            .create_conversation(
                "conv:alice:bob",
                &[PeerDeviceKeyPackage {
                    user_id: bob_identity.user_identity.user_id.clone(),
                    device_id: bob_identity.device_identity.device_id.clone(),
                    device_public_key: bob_identity.device_identity.device_public_key.clone(),
                    key_package_b64: second_bob_package.key_package_b64,
                }],
            )
            .expect("recreate conversation");
    }

    #[test]
    fn persisted_group_state_restores_application_flow() {
        let alice_identity =
            IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone")).expect("alice");
        let bob_identity =
            IdentityManager::create_or_recover(Some(BOB_MNEMONIC), Some("phone")).expect("bob");

        let (mut alice_adapter, _) = MlsAdapter::bootstrap(&alice_identity).expect("alice adapter");
        let (mut bob_adapter, bob_package) =
            MlsAdapter::bootstrap(&bob_identity).expect("bob adapter");

        let artifacts = alice_adapter
            .create_conversation(
                "conv:alice:bob",
                &[PeerDeviceKeyPackage {
                    user_id: bob_identity.user_identity.user_id.clone(),
                    device_id: bob_identity.device_identity.device_id.clone(),
                    device_public_key: bob_identity.device_identity.device_public_key.clone(),
                    key_package_b64: bob_package.key_package_b64,
                }],
            )
            .expect("create conversation");

        bob_adapter
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsWelcome,
                &artifacts.welcomes[0].payload_b64,
            )
            .expect("welcome");
        let _ = bob_adapter
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsCommit,
                &artifacts.commit_b64,
            )
            .expect("commit");

        let serialized = bob_adapter
            .export_persisted_group_state("conv:alice:bob")
            .expect("persisted state");
        let summary = bob_adapter
            .export_group_summary("conv:alice:bob")
            .expect("summary");

        let restored = MlsAdapter::restore_from_persisted_states(&[(
            "conv:alice:bob".into(),
            summary,
            Some(serialized),
        )])
        .expect("restore");
        let mut restored_bob = restored.adapter.expect("adapter");

        let outbound = alice_adapter
            .encrypt_application("conv:alice:bob", b"after restore")
            .expect("application");
        let received = restored_bob
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsApplication,
                &outbound.payload_b64,
            )
            .expect("receive");

        match received {
            IngestResult::AppliedApplication(application) => {
                assert_eq!(application.plaintext, b"after restore");
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn persisted_bootstrap_state_restores_welcome_staging() {
        let alice_identity =
            IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone")).expect("alice");
        let bob_identity =
            IdentityManager::create_or_recover(Some(BOB_MNEMONIC), Some("phone")).expect("bob");

        let (mut alice_adapter, _) = MlsAdapter::bootstrap(&alice_identity).expect("alice adapter");
        let (bob_adapter, bob_package) = MlsAdapter::bootstrap(&bob_identity).expect("bob adapter");
        let bootstrap_state = bob_adapter
            .export_bootstrap_state()
            .expect("bootstrap state");

        let artifacts = alice_adapter
            .create_conversation(
                "conv:alice:bob",
                &[PeerDeviceKeyPackage {
                    user_id: bob_identity.user_identity.user_id.clone(),
                    device_id: bob_identity.device_identity.device_id.clone(),
                    device_public_key: bob_identity.device_identity.device_public_key.clone(),
                    key_package_b64: bob_package.key_package_b64,
                }],
            )
            .expect("create conversation");

        let mut restored_bob =
            MlsAdapter::restore_from_bootstrap_state(&bootstrap_state).expect("restore");
        let welcome_result = restored_bob
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsWelcome,
                &artifacts.welcomes[0].payload_b64,
            )
            .expect("welcome");

        assert!(matches!(
            welcome_result,
            IngestResult::AppliedWelcome { .. }
        ));
    }

    #[test]
    fn restore_marks_missing_serialized_state_as_failed() {
        let restored = MlsAdapter::restore_from_persisted_states(&[(
            "conv:broken".into(),
            crate::model::MlsStateSummary {
                conversation_id: "conv:broken".into(),
                epoch: 1,
                member_device_ids: vec!["device:bob:phone".into()],
                status: MlsStateStatus::Active,
                updated_at: 1,
            },
            None,
        )])
        .expect("restore");

        assert!(restored.adapter.is_none());
        assert_eq!(
            restored.failed_conversation_ids,
            vec!["conv:broken".to_string()]
        );
        assert_eq!(
            restored
                .summaries
                .get("conv:broken")
                .expect("summary")
                .conversation_id,
            "conv:broken"
        );
    }

    fn pair_adapters() -> (
        MlsAdapter,
        MlsAdapter,
        crate::identity::LocalIdentityState,
        crate::identity::LocalIdentityState,
        String,
    ) {
        let alice_identity =
            IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone")).expect("alice");
        let bob_identity =
            IdentityManager::create_or_recover(Some(BOB_MNEMONIC), Some("phone")).expect("bob");
        let (mut alice_adapter, _) = MlsAdapter::bootstrap(&alice_identity).expect("alice adapter");
        let (mut bob_adapter, bob_package) =
            MlsAdapter::bootstrap(&bob_identity).expect("bob adapter");
        let artifacts = alice_adapter
            .create_conversation(
                "conv:alice:bob",
                &[PeerDeviceKeyPackage {
                    user_id: bob_identity.user_identity.user_id.clone(),
                    device_id: bob_identity.device_identity.device_id.clone(),
                    device_public_key: bob_identity.device_identity.device_public_key.clone(),
                    key_package_b64: bob_package.key_package_b64,
                }],
            )
            .expect("create conversation");
        bob_adapter
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsWelcome,
                &artifacts.welcomes[0].payload_b64,
            )
            .expect("welcome");
        let _ = bob_adapter
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsCommit,
                &artifacts.commit_b64,
            )
            .expect("genesis commit");
        (
            alice_adapter,
            bob_adapter,
            alice_identity,
            bob_identity,
            artifacts.commit_b64,
        )
    }

    // ---- R2 Phase 0: the "leaves no trace" oracle -------------------------
    //
    // Every later phase asserts that a rejected inbound record leaves
    // `state_fingerprint()` unchanged, and that a rejected record processed on
    // a fork can be discarded by simply dropping the fork. Both properties
    // rest on `fork()` being a faithful, complete copy. These tests pin that
    // down, so a regression in `fork()` fails here instead of silently
    // weakening the security tests downstream.

    #[test]
    fn fork_round_trips_the_state_fingerprint_exactly() {
        let (alice, bob, _, _, _) = pair_adapters();

        for (label, adapter) in [("alice", &alice), ("bob", &bob)] {
            let original = adapter.state_fingerprint().expect("fingerprint");
            let fork = adapter.fork().expect("fork");
            assert_eq!(
                fork.state_fingerprint().expect("fork fingerprint"),
                original,
                "{label}: fork() must reproduce the adapter's observable state exactly"
            );
        }
    }

    #[test]
    fn adopting_an_unmodified_fork_is_the_identity() {
        let (mut alice, _bob, _, _, _) = pair_adapters();
        let before = alice.state_fingerprint().expect("fingerprint");

        // This is the exact move Phase 7's fork-classify-adopt performs on the
        // success path. On the rejection path the fork is dropped instead, so
        // if adopting an untouched fork is the identity then dropping one
        // cannot lose state either.
        let fork = alice.fork().expect("fork");
        alice = fork;

        assert_eq!(
            alice.state_fingerprint().expect("fingerprint after adopt"),
            before
        );
    }

    #[test]
    fn fork_round_trips_the_pcs_sidecar() {
        // The PCS sidecar lives only in memory, so `provider_state_sha256`
        // does not cover it. Without this test a fork that silently dropped
        // staged self-updates would still satisfy the store hash.
        let (mut alice, mut bob, _, _, _) = pair_adapters();
        let proposal = bob.propose_self_update("conv:alice:bob").expect("propose");
        alice
            .ingest_message(
                "conv:alice:bob",
                &bob.local_device_id,
                MessageType::MlsProposal,
                &proposal.payload_b64,
            )
            .expect("proposal");

        let before = alice.state_fingerprint().expect("fingerprint");
        assert_eq!(
            before
                .pcs_sidecars
                .get("conv:alice:bob")
                .map(|entry| entry.1),
            Some(1),
            "the proposal should be staged in the sidecar"
        );
        assert_eq!(
            alice.fork().expect("fork").state_fingerprint().expect("fp"),
            before
        );
    }

    #[test]
    fn fingerprint_moves_when_state_moves() {
        // A snapshot oracle that never changes proves nothing. This is the
        // negative control for the three tests above.
        let (mut alice, mut bob, _, _, _) = pair_adapters();
        let before = alice.state_fingerprint().expect("fingerprint");

        let proposal = bob.propose_self_update("conv:alice:bob").expect("propose");
        alice
            .ingest_message(
                "conv:alice:bob",
                &bob.local_device_id,
                MessageType::MlsProposal,
                &proposal.payload_b64,
            )
            .expect("proposal");

        assert_ne!(alice.state_fingerprint().expect("fingerprint"), before);
    }

    // ---- R2: authentication failure leaves no trace -----------------------

    /// Alice creates a conversation for Bob and returns the welcome Bob is
    /// supposed to receive, plus Bob's untouched adapter.
    fn welcome_for_bob() -> (MlsAdapter, String, crate::identity::LocalIdentityState) {
        let alice_identity =
            IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone")).expect("alice");
        let bob_identity =
            IdentityManager::create_or_recover(Some(BOB_MNEMONIC), Some("phone")).expect("bob");
        let (mut alice_adapter, _) = MlsAdapter::bootstrap(&alice_identity).expect("alice adapter");
        let (bob_adapter, bob_package) = MlsAdapter::bootstrap(&bob_identity).expect("bob adapter");
        let artifacts = alice_adapter
            .create_conversation(
                "conv:alice:bob",
                &[PeerDeviceKeyPackage {
                    user_id: bob_identity.user_identity.user_id.clone(),
                    device_id: bob_identity.device_identity.device_id.clone(),
                    device_public_key: bob_identity.device_identity.device_public_key.clone(),
                    key_package_b64: bob_package.key_package_b64,
                }],
            )
            .expect("create conversation");
        (
            bob_adapter,
            artifacts.welcomes[0].payload_b64.clone(),
            alice_identity,
        )
    }

    #[test]
    fn welcome_for_another_conversation_leaves_no_trace() {
        // Replaying a legitimate welcome under a different conversation id
        // used to install that group under the claimed id — destroying
        // whatever live group the claimed id already had.
        let (mut bob, welcome, alice_identity) = welcome_for_bob();
        let before = bob.state_fingerprint().expect("fingerprint");

        let verdict = bob
            .ingest_message(
                "conv:alice:mallory",
                &alice_identity.device_identity.device_id,
                MessageType::MlsWelcome,
                &welcome,
            )
            .expect("a mismatched welcome is discarded, not an error");

        assert!(matches!(verdict, IngestResult::Rejected(_)), "{verdict:?}");
        assert_eq!(bob.state_fingerprint().expect("fingerprint"), before);
        assert!(!bob.has_conversation("conv:alice:mallory"));
    }

    #[test]
    fn welcome_from_an_unexpected_sender_leaves_no_trace() {
        let (mut bob, welcome, _) = welcome_for_bob();
        let before = bob.state_fingerprint().expect("fingerprint");

        let verdict = bob
            .ingest_message(
                "conv:alice:bob",
                "device:mallory:phone",
                MessageType::MlsWelcome,
                &welcome,
            )
            .expect("a sender-mismatched welcome is discarded, not an error");

        assert!(matches!(verdict, IngestResult::Rejected(_)), "{verdict:?}");
        assert_eq!(bob.state_fingerprint().expect("fingerprint"), before);
        assert!(!bob.has_conversation("conv:alice:bob"));
    }

    #[test]
    fn undecodable_welcome_leaves_no_trace() {
        let (mut bob, _, alice_identity) = welcome_for_bob();
        let before = bob.state_fingerprint().expect("fingerprint");

        for payload in ["!!!not base64!!!", "aGVsbG8gd29ybGQ="] {
            let verdict = bob
                .ingest_message(
                    "conv:alice:bob",
                    &alice_identity.device_identity.device_id,
                    MessageType::MlsWelcome,
                    payload,
                )
                .expect("an undecodable welcome is discarded, not an error");
            assert!(matches!(verdict, IngestResult::Rejected(_)), "{verdict:?}");
        }
        assert_eq!(bob.state_fingerprint().expect("fingerprint"), before);
    }

    #[test]
    fn rejected_welcome_does_not_consume_the_key_package() {
        // `StagedWelcome::new_from_welcome` deletes the matched KeyPackage
        // before it validates anything, so staging a welcome on the live
        // provider burns the key material even when the welcome is then
        // rejected. Anyone can read our published KeyPackage hash refs, so
        // without the fork this drains the one-time pool for free — and the
        // legitimate welcome that follows can no longer be joined.
        let (mut bob, welcome, alice_identity) = welcome_for_bob();

        let rejected = bob
            .ingest_message(
                "conv:alice:mallory",
                &alice_identity.device_identity.device_id,
                MessageType::MlsWelcome,
                &welcome,
            )
            .expect("rejected welcome");
        assert!(
            matches!(rejected, IngestResult::Rejected(_)),
            "{rejected:?}"
        );

        // The KeyPackage must have survived, so the real welcome still joins.
        let accepted = bob
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsWelcome,
                &welcome,
            )
            .expect("legitimate welcome");
        assert!(
            matches!(accepted, IngestResult::AppliedWelcome { .. }),
            "the KeyPackage was consumed by the rejected welcome: {accepted:?}"
        );
    }

    #[test]
    fn legitimate_welcome_still_replaces_a_live_group() {
        // The fork must not break rebuild: the peer receiving a rebuild
        // welcome still holds a live group under the same conversation id.
        let (mut bob, welcome, alice_identity) = welcome_for_bob();
        bob.ingest_message(
            "conv:alice:bob",
            &alice_identity.device_identity.device_id,
            MessageType::MlsWelcome,
            &welcome,
        )
        .expect("first join");
        let first_epoch = bob
            .export_group_summary("conv:alice:bob")
            .expect("summary")
            .epoch;

        // Alice rebuilds the conversation from scratch and re-welcomes Bob.
        let bob_identity =
            IdentityManager::create_or_recover(Some(BOB_MNEMONIC), Some("phone")).expect("bob");
        // Must be minted by Bob's own adapter: the private init key has to land
        // in Bob's provider storage, or the welcome is simply not for him.
        let fresh_package = bob.rotate_key_package(test_now_ms()).expect("package");
        let (mut alice_adapter, _) = MlsAdapter::bootstrap(&alice_identity).expect("alice");
        let rebuilt = alice_adapter
            .create_conversation(
                "conv:alice:bob",
                &[PeerDeviceKeyPackage {
                    user_id: bob_identity.user_identity.user_id.clone(),
                    device_id: bob_identity.device_identity.device_id.clone(),
                    device_public_key: bob_identity.device_identity.device_public_key.clone(),
                    key_package_b64: fresh_package.key_package_b64,
                }],
            )
            .expect("rebuild conversation");

        let verdict = bob
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsWelcome,
                &rebuilt.welcomes[0].payload_b64,
            )
            .expect("rebuild welcome");
        assert!(
            matches!(verdict, IngestResult::AppliedWelcome { .. }),
            "a legitimate rebuild welcome must still replace the live group: {verdict:?}"
        );
        assert!(bob.has_conversation("conv:alice:bob"));
        let _ = first_epoch;
    }

    #[test]
    fn frame_from_another_group_leaves_no_trace() {
        // A frame that authenticates for a different group must not touch this
        // group's state. This is the forgery shape we can exercise in a debug
        // build: openmls has a `debug_assert!(false)` on the AEAD failure path
        // (framing/private_message_in.rs:136), so a byte-flipped ciphertext
        // aborts the test process instead of returning `AeadError`. Release
        // builds classify it correctly; the assert is upstream's, not ours.
        let (mut alice, _bob, _, bob_identity, _) = pair_adapters();

        // An independent conversation between the same two identities.
        let other_identity =
            IdentityManager::create_or_recover(Some(BOB_MNEMONIC), Some("tablet")).expect("other");
        let (mut other_alice, _) = MlsAdapter::bootstrap(
            &IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("tablet"))
                .expect("alice tablet"),
        )
        .expect("other alice adapter");
        let (_other_bob, other_package) =
            MlsAdapter::bootstrap(&other_identity).expect("other bob adapter");
        let other = other_alice
            .create_conversation(
                "conv:other:pair",
                &[PeerDeviceKeyPackage {
                    user_id: other_identity.user_identity.user_id.clone(),
                    device_id: other_identity.device_identity.device_id.clone(),
                    device_public_key: other_identity.device_identity.device_public_key.clone(),
                    key_package_b64: other_package.key_package_b64,
                }],
            )
            .expect("other conversation");

        let before = alice.state_fingerprint().expect("fingerprint");
        let verdict = alice
            .ingest_message(
                "conv:alice:bob",
                &bob_identity.device_identity.device_id,
                MessageType::MlsCommit,
                &other.commit_b64,
            )
            .expect("a foreign frame is discarded, not an error");

        // Which reject reason wins depends on which cheap check fires first
        // (here the stale-epoch pre-gate, before group binding is examined).
        // The reason is telemetry; the property under test is that a foreign
        // frame is rejected and moves nothing.
        assert!(
            matches!(verdict, IngestResult::Rejected(_)),
            "a frame bound to another group must be rejected: {verdict:?}"
        );
        assert_eq!(
            alice.state_fingerprint().expect("fingerprint"),
            before,
            "a foreign frame must not move any adapter state"
        );
    }

    #[test]
    fn undecodable_protocol_payload_leaves_no_trace() {
        let (mut alice, _, _, bob_identity, _) = pair_adapters();
        let before = alice.state_fingerprint().expect("fingerprint");

        for message_type in [
            MessageType::MlsApplication,
            MessageType::MlsCommit,
            MessageType::MlsProposal,
        ] {
            let verdict = alice
                .ingest_message(
                    "conv:alice:bob",
                    &bob_identity.device_identity.device_id,
                    message_type,
                    "!!!not base64!!!",
                )
                .expect("an undecodable payload is discarded, not an error");
            assert!(matches!(verdict, IngestResult::Rejected(_)), "{verdict:?}");
        }
        assert_eq!(alice.state_fingerprint().expect("fingerprint"), before);
    }

    #[test]
    fn group_pcs_proposal_then_commit_advances_epoch() {
        let (mut alice, mut bob, alice_identity, bob_identity, _) = pair_adapters();
        let before = alice
            .export_group_summary("conv:alice:bob")
            .expect("summary")
            .epoch;
        let proposal = bob.propose_self_update("conv:alice:bob").expect("propose");
        match alice
            .ingest_message(
                "conv:alice:bob",
                &bob_identity.device_identity.device_id,
                MessageType::MlsProposal,
                &proposal.payload_b64,
            )
            .expect("ingest proposal")
        {
            IngestResult::AppliedProposal => {}
            other => panic!("expected AppliedProposal, got {other:?}"),
        }
        assert!(!alice
            .has_pending_proposals("conv:alice:bob")
            .expect("live store"));
        assert!(alice
            .has_pcs_update_proposals("conv:alice:bob")
            .expect("sidecar"));
        alice
            .encrypt_application("conv:alice:bob", b"while waiting")
            .expect("sender can still encrypt with pending PCS proposal");
        bob.encrypt_application("conv:alice:bob", b"proposer still sending")
            .expect("proposer can still encrypt after proposing");
        let commit = alice
            .stage_group_pcs_commit("conv:alice:bob")
            .expect("commit");
        assert_eq!(
            alice
                .export_group_summary("conv:alice:bob")
                .expect("alice epoch")
                .epoch,
            before + 1
        );
        match bob
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsCommit,
                &commit.payload_b64,
            )
            .expect("bob merge")
        {
            IngestResult::AppliedCommit { epoch } => assert_eq!(epoch, before + 1),
            other => panic!("expected AppliedCommit, got {other:?}"),
        }
        let plaintext = b"after group pcs";
        let outbound = alice
            .encrypt_application("conv:alice:bob", plaintext)
            .expect("encrypt");
        match bob
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsApplication,
                &outbound.payload_b64,
            )
            .expect("decrypt")
        {
            IngestResult::AppliedApplication(application) => {
                assert_eq!(application.plaintext, plaintext);
            }
            other => panic!("expected application, got {other:?}"),
        }
    }

    #[test]
    fn group_pcs_rejects_remove_proposal_and_keeps_membership() {
        let (mut alice, mut bob, alice_identity, bob_identity, _) = pair_adapters();
        let members_before = alice
            .export_group_summary("conv:alice:bob")
            .expect("summary")
            .member_device_ids;
        let remove = bob
            .propose_remove_member("conv:alice:bob", &alice_identity.device_identity.device_id)
            .expect("remove proposal");
        match alice
            .ingest_message(
                "conv:alice:bob",
                &bob_identity.device_identity.device_id,
                MessageType::MlsProposal,
                &remove.payload_b64,
            )
            .expect("ingest remove")
        {
            IngestResult::AppliedProposal => {}
            other => panic!("expected AppliedProposal, got {other:?}"),
        }
        assert!(!alice
            .has_pcs_update_proposals("conv:alice:bob")
            .expect("sidecar"));
        let commit = alice
            .stage_group_pcs_commit("conv:alice:bob")
            .expect("pcs commit");
        let members_after = alice
            .export_group_summary("conv:alice:bob")
            .expect("after")
            .member_device_ids;
        assert_eq!(members_before, members_after);
        match bob
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsCommit,
                &commit.payload_b64,
            )
            .expect("bob merge")
        {
            IngestResult::AppliedCommit { .. } => {}
            other => panic!("expected AppliedCommit, got {other:?}"),
        }
        let plaintext = b"still in the group";
        let outbound = alice
            .encrypt_application("conv:alice:bob", plaintext)
            .expect("encrypt");
        match bob
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsApplication,
                &outbound.payload_b64,
            )
            .expect("decrypt")
        {
            IngestResult::AppliedApplication(application) => {
                assert_eq!(application.plaintext, plaintext);
            }
            other => panic!("expected application, got {other:?}"),
        }
    }

    #[test]
    fn group_pcs_restore_uses_own_empty_sidecar_not_stale_peer_snapshot() {
        let (mut alice, mut bob, _, bob_identity, _) = pair_adapters();
        alice
            .create_owner_conversation("conv:solo")
            .expect("solo conversation");
        let proposal = bob.propose_self_update("conv:alice:bob").expect("propose");
        match alice
            .ingest_message(
                "conv:alice:bob",
                &bob_identity.device_identity.device_id,
                MessageType::MlsProposal,
                &proposal.payload_b64,
            )
            .expect("ingest")
        {
            IngestResult::AppliedProposal => {}
            other => panic!("expected AppliedProposal, got {other:?}"),
        }
        assert!(alice
            .has_pcs_update_proposals("conv:alice:bob")
            .expect("sidecar"));
        let stale_full = alice.export_bootstrap_state().expect("stale full dump");
        alice.clear_pcs_update_sidecar("conv:alice:bob");
        assert!(!alice
            .has_pcs_update_proposals("conv:alice:bob")
            .expect("cleared"));
        let fresh_b = alice
            .export_persisted_group_state("conv:alice:bob")
            .expect("fresh b");
        let summary_solo = alice.export_group_summary("conv:solo").expect("solo");
        let summary_b = alice.export_group_summary("conv:alice:bob").expect("group");
        let restored = MlsAdapter::restore_from_persisted_states(&[
            ("conv:solo".into(), summary_solo, Some(stale_full)),
            ("conv:alice:bob".into(), summary_b, Some(fresh_b)),
        ])
        .expect("restore")
        .adapter
        .expect("adapter");
        assert!(
            !restored
                .has_pcs_update_proposals("conv:alice:bob")
                .expect("b sidecar after restore"),
            "latest empty sidecar for this conversation must win over a stale peer dump"
        );
    }

    #[test]
    fn group_pcs_retains_distinct_updates_per_epoch() {
        let (mut alice, mut bob, alice_identity, bob_identity, _) = pair_adapters();
        let first = bob
            .propose_self_update("conv:alice:bob")
            .expect("first propose");
        match alice
            .ingest_message(
                "conv:alice:bob",
                &bob_identity.device_identity.device_id,
                MessageType::MlsProposal,
                &first.payload_b64,
            )
            .expect("ingest first")
        {
            IngestResult::AppliedProposal => {}
            other => panic!("expected AppliedProposal, got {other:?}"),
        }
        assert_eq!(alice.pcs_update_count("conv:alice:bob").expect("count"), 1);
        let second = bob
            .propose_self_update("conv:alice:bob")
            .expect("second propose");
        match alice
            .ingest_message(
                "conv:alice:bob",
                &bob_identity.device_identity.device_id,
                MessageType::MlsProposal,
                &second.payload_b64,
            )
            .expect("ingest second")
        {
            IngestResult::AppliedProposal => {}
            other => panic!("expected AppliedProposal, got {other:?}"),
        }
        assert_eq!(alice.pcs_update_count("conv:alice:bob").expect("count"), 2);
        let commit = alice
            .stage_group_pcs_commit("conv:alice:bob")
            .expect("commit with both updates");
        match bob
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsCommit,
                &commit.payload_b64,
            )
            .expect("bob merge")
        {
            IngestResult::AppliedCommit { .. } => {}
            other => panic!("expected AppliedCommit, got {other:?}"),
        }
        let plaintext = b"after distinct leaf updates";
        let outbound = alice
            .encrypt_application("conv:alice:bob", plaintext)
            .expect("encrypt");
        match bob
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsApplication,
                &outbound.payload_b64,
            )
            .expect("decrypt")
        {
            IngestResult::AppliedApplication(application) => {
                assert_eq!(application.plaintext, plaintext);
            }
            other => panic!("expected application, got {other:?}"),
        }
    }

    #[test]
    fn group_pcs_commit_resolves_referenced_update_after_newer_proposal() {
        let (mut alice, mut bob, alice_identity, bob_identity, _) = pair_adapters();
        let first = bob
            .propose_self_update("conv:alice:bob")
            .expect("first propose");
        match alice
            .ingest_message(
                "conv:alice:bob",
                &bob_identity.device_identity.device_id,
                MessageType::MlsProposal,
                &first.payload_b64,
            )
            .expect("ingest first")
        {
            IngestResult::AppliedProposal => {}
            other => panic!("expected AppliedProposal, got {other:?}"),
        }
        let commit = alice
            .stage_group_pcs_commit("conv:alice:bob")
            .expect("commit referencing first update");
        let _second = bob
            .propose_self_update("conv:alice:bob")
            .expect("second propose");
        assert_eq!(
            bob.pcs_update_count("conv:alice:bob").expect("bob sidecar"),
            2,
            "newer update must not drop the proposal already referenced by a pending commit"
        );
        match bob
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsCommit,
                &commit.payload_b64,
            )
            .expect("bob merge referenced first update")
        {
            IngestResult::AppliedCommit { .. } => {}
            other => panic!("expected AppliedCommit, got {other:?}"),
        }
        let plaintext = b"after stale-then-newer update";
        let outbound = alice
            .encrypt_application("conv:alice:bob", plaintext)
            .expect("encrypt");
        match bob
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsApplication,
                &outbound.payload_b64,
            )
            .expect("decrypt")
        {
            IngestResult::AppliedApplication(application) => {
                assert_eq!(application.plaintext, plaintext);
            }
            other => panic!("expected application, got {other:?}"),
        }
    }

    /// The whole point of R1: rotating replaces our leaf key and advances our
    /// epoch in one step, with no input from the counterparty.
    #[test]
    fn direct_self_update_advances_the_epoch_immediately() {
        let (mut alice, mut bob, alice_identity, _, _) = pair_adapters();
        let live_epoch = alice
            .export_group_summary("conv:alice:bob")
            .expect("summary")
            .epoch;
        let rotated = alice
            .rotate_direct_self_update("conv:alice:bob")
            .expect("rotate");
        assert_eq!(rotated.base_epoch, live_epoch);
        assert_eq!(
            alice
                .export_group_summary("conv:alice:bob")
                .expect("live")
                .epoch,
            live_epoch + 1,
            "the committer must not wait for anyone to merge its own commit"
        );
        match bob
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsCommit,
                &rotated.commit_b64,
            )
            .expect("bob ingest commit")
        {
            IngestResult::AppliedCommit { epoch } => assert_eq!(epoch, live_epoch + 1),
            other => panic!("expected an applied commit, got {other:?}"),
        }

        let outbound = alice
            .encrypt_application("conv:alice:bob", b"after pcs")
            .expect("encrypt");
        match bob
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsApplication,
                &outbound.payload_b64,
            )
            .expect("bob decrypt new epoch")
        {
            IngestResult::AppliedApplication(application) => {
                assert_eq!(application.plaintext, b"after pcs");
            }
            other => panic!("unexpected ingest: {other:?}"),
        }
    }

    #[test]
    fn previous_epoch_still_decrypts_after_rotation() {
        let (mut alice, mut bob, alice_identity, _, _) = pair_adapters();
        let stale = alice
            .encrypt_application("conv:alice:bob", b"stale epoch")
            .expect("stale");
        let rotated = alice
            .rotate_direct_self_update("conv:alice:bob")
            .expect("rotate");
        assert!(matches!(
            bob.ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsCommit,
                &rotated.commit_b64,
            )
            .expect("bob ingest commit"),
            IngestResult::AppliedCommit { .. }
        ));
        match bob
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsApplication,
                &stale.payload_b64,
            )
            .expect("previous epoch decrypt")
        {
            IngestResult::AppliedApplication(application) => {
                assert_eq!(application.plaintext, b"stale epoch");
                assert!(application.from_previous_epoch);
            }
            other => panic!("expected previous-epoch application, got {other:?}"),
        }
    }

    /// A rotation lands between two sends; the receiver adopts the commit and
    /// must still read both, one as a previous-epoch message.
    #[test]
    fn rotation_keeps_both_adjacent_epochs_decryptable() {
        let (mut alice, mut bob, alice_identity, _, _) = pair_adapters();
        let live_epoch = alice
            .export_group_summary("conv:alice:bob")
            .expect("summary")
            .epoch;
        let stale = alice
            .encrypt_application("conv:alice:bob", b"before rotation")
            .expect("encrypt before rotation");
        let rotated = alice
            .rotate_direct_self_update("conv:alice:bob")
            .expect("rotate");
        assert_eq!(
            alice
                .export_group_summary("conv:alice:bob")
                .expect("live")
                .epoch,
            live_epoch + 1
        );
        assert!(matches!(
            bob.ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsCommit,
                &rotated.commit_b64,
            )
            .expect("bob ingest commit"),
            IngestResult::AppliedCommit { .. }
        ));
        match bob
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsApplication,
                &stale.payload_b64,
            )
            .expect("pre-rotation decrypt")
        {
            IngestResult::AppliedApplication(application) => {
                assert_eq!(application.plaintext, b"before rotation");
                assert!(application.from_previous_epoch);
            }
            other => panic!("expected previous-epoch application, got {other:?}"),
        }
        let outbound = alice
            .encrypt_application("conv:alice:bob", b"new epoch")
            .expect("encrypt new epoch");
        match bob
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsApplication,
                &outbound.payload_b64,
            )
            .expect("new epoch decrypt")
        {
            IngestResult::AppliedApplication(application) => {
                assert_eq!(application.plaintext, b"new epoch");
            }
            other => panic!("unexpected ingest: {other:?}"),
        }
    }

    #[test]
    fn live_merge_does_not_drop_other_conversations() {
        let (mut alice, _, _, bob_identity, _) = pair_adapters();
        let second_package =
            MlsAdapter::generate_key_package(&bob_identity, test_now_ms()).expect("second package");
        alice
            .create_conversation(
                "conv:alice:bob2",
                &[PeerDeviceKeyPackage {
                    user_id: bob_identity.user_identity.user_id.clone(),
                    device_id: bob_identity.device_identity.device_id.clone(),
                    device_public_key: bob_identity.device_identity.device_public_key.clone(),
                    key_package_b64: second_package.key_package_b64,
                }],
            )
            .expect("second conversation");
        alice
            .rotate_direct_self_update("conv:alice:bob")
            .expect("rotate");
        assert!(alice.has_conversation("conv:alice:bob"));
        assert!(alice.has_conversation("conv:alice:bob2"));
    }

    #[test]
    fn persisted_live_cannot_rebuild_consumed_next_epoch_keys() {
        let (mut alice, mut bob, alice_identity, _, _) = pair_adapters();
        let late_e = alice
            .encrypt_application("conv:alice:bob", b"late e")
            .expect("late e");
        let rotated = alice
            .rotate_direct_self_update("conv:alice:bob")
            .expect("rotate");
        assert!(matches!(
            bob.ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsCommit,
                &rotated.commit_b64,
            )
            .expect("bob ingest commit"),
            IngestResult::AppliedCommit { .. }
        ));
        let consumed = alice
            .encrypt_application("conv:alice:bob", b"e+1")
            .expect("e+1");
        match bob
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsApplication,
                &consumed.payload_b64,
            )
            .expect("consume e+1")
        {
            IngestResult::AppliedApplication(application) => {
                assert_eq!(application.plaintext, b"e+1");
                assert!(!application.from_previous_epoch);
            }
            other => panic!("expected e+1 application, got {other:?}"),
        }
        let serialized = bob
            .export_persisted_group_state("conv:alice:bob")
            .expect("persist");
        let summary = bob.export_group_summary("conv:alice:bob").expect("summary");
        let restored = MlsAdapter::restore_from_persisted_states(&[(
            "conv:alice:bob".into(),
            summary,
            Some(serialized),
        )])
        .expect("restore")
        .adapter
        .expect("adapter");
        let mut restored = restored;
        match restored
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsCommit,
                &rotated.commit_b64,
            )
            .expect("replay C")
        {
            IngestResult::Rejected(_) | IngestResult::Deferred(_) => {}
            IngestResult::AppliedCommit { .. } => {
                panic!("persisted live must not re-merge certified commit C")
            }
            other => panic!("unexpected C ingest: {other:?}"),
        }
        match restored
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsApplication,
                &consumed.payload_b64,
            )
            .expect("replay consumed e+1")
        {
            IngestResult::Rejected(_) => {}
            IngestResult::AppliedApplication(_) => {
                panic!("consumed e+1 generation must not decrypt from persisted live + C")
            }
            other => panic!("unexpected consumed ingest: {other:?}"),
        }
        match restored
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsApplication,
                &late_e.payload_b64,
            )
            .expect("late e")
        {
            IngestResult::AppliedApplication(application) => {
                assert_eq!(application.plaintext, b"late e");
                assert!(application.from_previous_epoch);
            }
            other => panic!("expected late-e application, got {other:?}"),
        }
    }
}

fn copy_signer(signer: &SignatureKeyPair) -> CoreResult<SignatureKeyPair> {
    let serialized = serde_json::to_vec(signer).map_err(|error| {
        CoreError::invalid_state(format!("failed to encode MLS signer: {error}"))
    })?;
    serde_json::from_slice(&serialized)
        .map_err(|error| CoreError::invalid_state(format!("failed to decode MLS signer: {error}")))
}

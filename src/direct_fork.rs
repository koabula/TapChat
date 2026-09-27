//! Fork detection on the 1:1 path.
//!
//! A snapshot of P lets the adversary commit in P's name. If Q merges that
//! commit before P's own, the parties continue in different epochs, and P —
//! which never saw the forged commit — builds its next commit on the **same
//! base epoch**. Every commit carries its author's detached signature over
//! the base epoch and the commit's hash, and an honest device never signs two
//! different commits on one base epoch of one group. Two such signatures at Q
//! are therefore proof that someone else holds P's device key.
//!
//! The detection point is Q, not P. P's signal is a commit from its own leaf
//! that it never made, and the adversary can simply not deliver it. Q's
//! signal is P's own healing commit, which liveness forces through.
//!
//! What the pair proves is the stolen key, not the fork. Q cannot tell which
//! of the two commits is the forged one, so the same evidence appears when P
//! healed first and the adversary commits afterwards on the base epoch P's
//! commit left. That case is gated exactly like `Inject`: the forged frame
//! must be wrapped under an epoch key the adversary holds. A fork forces the
//! evidence; a snapshot can also volunteer it, but only inside its window.
//!
//! By the time that commit arrives Q may have moved several epochs on, and a
//! frame is wrapped under its own base epoch's key, which Q has overwritten.
//! So for each peer commit it merges, Q keeps the inbound wrap key of that
//! commit's base epoch (`K_c`, the commit key; see `lane_wrap`) alongside its
//! signature data. The key also scopes the comparison: a frame opens under it
//! only if it was wrapped at that epoch of this incarnation of the group, so a
//! rebuild that restarts the epoch count cannot produce a false match, and
//! witnesses survive a rebuild. They have to: a rebuild the adversary can
//! provoke from a forked branch would otherwise erase the evidence.

use serde::{Deserialize, Serialize};

use crate::direct_pcs::{DIRECT_DELIVERY_BOUND_MS, DIRECT_PCS_MAX_AGE_MS};
use crate::lane_wrap::WRAP_KEY_LEN;

/// How long a witness is kept after its commit merged: `τ ≥ T + Δ`.
///
/// An honest device rotates at least once every `T = 2 × DIRECT_PCS_MAX_AGE_MS`
/// (the non-designated party's deadline in `DirectPcsState::should_rotate`),
/// so its first commit after a fork is made within `T`, and it arrives within
/// the delivery bound `Δ`. A commit arriving later than this falls outside the
/// liveness premise the detection is claimed under.
pub const FORK_WITNESS_TTL_MS: u64 = 2 * DIRECT_PCS_MAX_AGE_MS + DIRECT_DELIVERY_BOUND_MS;

/// A peer commit this device merged, kept so a second commit on the same base
/// epoch can be recognised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerCommitWitness {
    pub base_epoch: u64,
    /// The signer. A double sign is two commits from **one** device key; two
    /// devices of the same user committing on one epoch is an ordinary race.
    pub device_id: String,
    /// Empty for a session this device left for a rebuild Welcome from
    /// `device_id`: no commit of that device's is expected under this key at
    /// all, so any commit contradicts it.
    pub commit_hash: String,
    /// `K(base_epoch, inbound)`.
    pub wrap_key: [u8; WRAP_KEY_LEN],
    /// Local clock; what the TTL runs on.
    pub merged_at_ms: u64,
    /// The host's `received_at` for the record that carried the commit: the
    /// clock inbound messages are stamped with, so the two can be compared.
    #[serde(default)]
    pub received_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ForkGuard {
    /// Pruned by age only. Every entry is a commit that authenticated and
    /// merged, so the list grows with the peer's rotations the way the
    /// transcript grows with its messages.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub witnesses: Vec<PeerCommitWitness>,
    /// When the record carrying the commit that the double sign contradicts
    /// was received, by the host's clock: messages attributed to the peer and
    /// stamped from then on may not be from the peer. Set once the fork is
    /// detected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forked_since_ms: Option<u64>,
}

impl ForkGuard {
    pub fn is_empty(&self) -> bool {
        self.witnesses.is_empty() && self.forked_since_ms.is_none()
    }

    pub fn record(&mut self, witness: PeerCommitWitness, now_ms: u64) {
        self.prune(now_ms);
        self.witnesses.push(witness);
    }

    pub fn prune(&mut self, now_ms: u64) {
        self.witnesses
            .retain(|witness| now_ms.saturating_sub(witness.merged_at_ms) < FORK_WITNESS_TTL_MS);
    }

    /// The keys to try on a frame that neither the current nor the previous
    /// epoch's key opens.
    pub fn wrap_keys(&self) -> impl Iterator<Item = &[u8; WRAP_KEY_LEN]> {
        self.witnesses.iter().map(|witness| &witness.wrap_key)
    }

    /// The witness whose base epoch a frame opened under `key` was wrapped at.
    /// One merge per epoch, so at most one.
    pub fn witness_for_key(&self, key: &[u8; WRAP_KEY_LEN]) -> Option<&PeerCommitWitness> {
        self.witnesses
            .iter()
            .find(|witness| &witness.wrap_key == key)
    }

    /// Whether a commit opened under `witness.wrap_key` contradicts it. The
    /// caller still has to verify the signature under `witness.device_id`.
    pub fn contradicts(witness: &PeerCommitWitness, base_epoch: u64, commit_hash: &str) -> bool {
        witness.base_epoch == base_epoch && witness.commit_hash != commit_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn witness(base_epoch: u64, key: u8, merged_at_ms: u64) -> PeerCommitWitness {
        PeerCommitWitness {
            base_epoch,
            device_id: "device:bob:phone".into(),
            commit_hash: format!("sha256:{base_epoch}"),
            wrap_key: [key; WRAP_KEY_LEN],
            merged_at_ms,
            received_at_ms: merged_at_ms,
        }
    }

    #[test]
    fn witnesses_expire_after_the_ttl() {
        let mut guard = ForkGuard::default();
        guard.record(witness(3, 1, 0), 0);
        guard.record(
            witness(4, 2, FORK_WITNESS_TTL_MS - 1),
            FORK_WITNESS_TTL_MS - 1,
        );
        guard.prune(FORK_WITNESS_TTL_MS);
        assert!(guard.witness_for_key(&[1; WRAP_KEY_LEN]).is_none());
        assert!(guard.witness_for_key(&[2; WRAP_KEY_LEN]).is_some());
    }

    #[test]
    fn only_a_different_commit_on_the_same_base_epoch_contradicts() {
        let merged = witness(3, 1, 0);
        // The same bytes again is a retransmission, not a second signature.
        assert!(!ForkGuard::contradicts(&merged, 3, "sha256:3"));
        assert!(!ForkGuard::contradicts(&merged, 4, "sha256:other"));
        assert!(ForkGuard::contradicts(&merged, 3, "sha256:other"));
    }

    #[test]
    fn a_witness_is_found_only_by_its_own_key() {
        let mut guard = ForkGuard::default();
        guard.record(witness(3, 1, 0), 0);
        assert_eq!(
            guard
                .witness_for_key(&[1; WRAP_KEY_LEN])
                .map(|w| w.base_epoch),
            Some(3)
        );
        assert!(guard.witness_for_key(&[9; WRAP_KEY_LEN]).is_none());
    }
}

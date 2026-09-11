use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{CoreError, CoreResult};

pub const DIRECT_PCS_COMMIT_INTERVAL: u32 = 32;
/// Time-based fallback for `should_rotate`: a low-traffic conversation may
/// never reach `DIRECT_PCS_COMMIT_INTERVAL` messages, which would otherwise
/// let post-compromise healing stall indefinitely.
pub const DIRECT_PCS_MAX_AGE_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// Our own commit for `base_epoch`, retained only long enough to arbitrate a
/// same-epoch race with the peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnCommit {
    pub base_epoch: u64,
    pub commit_hash: String,
    /// `designated_committer(roster@base_epoch, base_epoch) == this device`,
    /// evaluated **when the commit was made**. Re-deriving it later would read
    /// the roster of whichever epoch we ended up in, and two racing membership
    /// commits leave the two sides with different rosters — the arbitration
    /// verdict has to be the same on both sides or the fork never resolves.
    pub won_arbitration: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DirectPcsState {
    /// Application messages observed since **this device** last replaced its
    /// own leaf key.
    ///
    /// Deliberately not epoch-scoped. A peer's commit rotates the group secret
    /// but not our leaf, so an attacker holding our snapshot follows it
    /// straight through; only our own commit heals us. If a peer's commit
    /// cleared this counter, a peer that commits often enough would keep us
    /// permanently below the threshold and our leaf would never rotate — the
    /// separation R1 exists to close, wearing a different hat.
    #[serde(default)]
    pub self_debt: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_rotated_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub own_commit: Option<OwnCommit>,
}

impl DirectPcsState {
    pub fn note_application_message(&mut self) {
        self.self_debt = self.self_debt.saturating_add(1);
    }

    /// Whether this device should replace its own leaf key now.
    ///
    /// The designated committer goes first, at one interval. Everyone else
    /// waits two, which is how "it did not go" is measured without a clock
    /// shared with the peer or a reply from it. Exactly one party sits at the
    /// 1× threshold at any epoch, so the common case produces no race at all;
    /// the 2× party only fires when the designated one is absent, and an
    /// absent peer cannot race.
    pub fn should_rotate(&self, is_designated: bool, now_ms: u64) -> bool {
        let factor = if is_designated { 1 } else { 2 };
        self.self_debt >= DIRECT_PCS_COMMIT_INTERVAL.saturating_mul(factor)
            || self.rotation_overdue(now_ms, DIRECT_PCS_MAX_AGE_MS.saturating_mul(factor as u64))
    }

    fn rotation_overdue(&self, now_ms: u64, max_age_ms: u64) -> bool {
        self.self_rotated_at_ms
            .is_some_and(|at| now_ms.saturating_sub(at) >= max_age_ms)
    }

    /// Record that our own leaf key was just replaced. The only place the
    /// rotation debt is cleared.
    pub fn mark_rotated(&mut self, own_commit: OwnCommit, now_ms: u64) {
        self.self_debt = 0;
        self.self_rotated_at_ms = Some(now_ms);
        self.own_commit = Some(own_commit);
    }

    /// Close the race window.
    ///
    /// Called when a peer commit merges. To merge, its epoch had to equal our
    /// live epoch, which is already past the base epoch of our own commit — so
    /// the peer demonstrably moved past it and can no longer race us there.
    /// Note this does **not** touch `self_debt`; see the field comment.
    pub fn clear_own_commit(&mut self) {
        self.own_commit = None;
    }

    /// `Some(won)` when `incoming` is a peer commit racing our own commit at
    /// the same base epoch — `true` if we win the arbitration. `None` when
    /// there is no race and the frame should take the ordinary ingest path.
    pub fn arbitrate(&self, incoming_epoch: u64, incoming_hash: &str) -> Option<bool> {
        let own = self.own_commit.as_ref()?;
        (incoming_epoch == own.base_epoch && incoming_hash != own.commit_hash)
            .then_some(own.won_arbitration)
    }
}

/// Who wins a same-epoch collision.
///
/// This is an **arbiter, not a gatekeeper**: any member may commit at any
/// epoch. The function also orders the two duties — the device it names goes
/// first, at `DIRECT_PCS_COMMIT_INTERVAL`, and everyone else waits twice that
/// (see [`DirectPcsState::should_rotate`]).
pub fn designated_committer(member_device_ids: &[String], epoch: u64) -> CoreResult<String> {
    let mut ids = member_device_ids.to_vec();
    ids.retain(|id| !id.trim().is_empty());
    ids.sort();
    ids.dedup();
    if ids.is_empty() {
        return Err(CoreError::invalid_input(
            "direct PCS committer requires at least one member device",
        ));
    }
    let index = (epoch as usize) % ids.len();
    Ok(ids[index].clone())
}

pub fn commit_hash_from_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

pub fn commit_hash_from_b64(payload_b64: &str) -> CoreResult<String> {
    let bytes = BASE64
        .decode(payload_b64.trim())
        .map_err(|_| CoreError::invalid_input("invalid base64 MLS commit payload"))?;
    Ok(commit_hash_from_bytes(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn own_commit(base_epoch: u64, hash: &str, won: bool) -> OwnCommit {
        OwnCommit {
            base_epoch,
            commit_hash: hash.into(),
            won_arbitration: won,
        }
    }

    #[test]
    fn committer_rotates_with_epoch() {
        let ids = vec!["device:alice:phone".into(), "device:bob:phone".into()];
        let first = designated_committer(&ids, 1).expect("epoch 1");
        let second = designated_committer(&ids, 2).expect("epoch 2");
        assert_ne!(first, second);
        assert_eq!(first, designated_committer(&ids, 3).expect("epoch 3"));
    }

    #[test]
    fn designated_goes_first_and_the_other_waits_one_extra_interval() {
        let mut state = DirectPcsState {
            self_debt: DIRECT_PCS_COMMIT_INTERVAL,
            ..Default::default()
        };
        assert!(state.should_rotate(true, 0));
        assert!(!state.should_rotate(false, 0));
        state.self_debt = DIRECT_PCS_COMMIT_INTERVAL * 2;
        assert!(state.should_rotate(false, 0));
    }

    #[test]
    fn stale_rotation_triggers_even_with_few_messages() {
        let mut state = DirectPcsState {
            self_rotated_at_ms: Some(0),
            ..Default::default()
        };
        state.note_application_message();
        assert!(!state.should_rotate(true, DIRECT_PCS_MAX_AGE_MS - 1));
        assert!(state.should_rotate(true, DIRECT_PCS_MAX_AGE_MS));
        // The non-designated device waits twice as long here too.
        assert!(!state.should_rotate(false, DIRECT_PCS_MAX_AGE_MS));
        assert!(state.should_rotate(false, DIRECT_PCS_MAX_AGE_MS * 2));
    }

    #[test]
    fn mark_rotated_clears_the_debt_and_resets_the_staleness_clock() {
        let mut state = DirectPcsState {
            self_rotated_at_ms: Some(0),
            ..Default::default()
        };
        state.self_debt = DIRECT_PCS_COMMIT_INTERVAL;
        state.mark_rotated(
            own_commit(7, "sha256:mine", true),
            DIRECT_PCS_MAX_AGE_MS,
        );
        assert_eq!(state.self_debt, 0);
        assert_eq!(state.self_rotated_at_ms, Some(DIRECT_PCS_MAX_AGE_MS));
        assert!(!state.should_rotate(true, DIRECT_PCS_MAX_AGE_MS * 2 - 1));
    }

    #[test]
    fn clearing_the_race_window_does_not_clear_the_rotation_debt() {
        // A peer commit closes the arbitration window but heals nothing of
        // ours, so our debt must survive it — otherwise a peer that commits
        // often enough starves our own rotation.
        let mut state = DirectPcsState {
            self_debt: DIRECT_PCS_COMMIT_INTERVAL,
            own_commit: Some(own_commit(3, "sha256:mine", false)),
            ..Default::default()
        };
        state.clear_own_commit();
        assert_eq!(state.self_debt, DIRECT_PCS_COMMIT_INTERVAL);
        assert!(state.should_rotate(true, 0));
    }

    #[test]
    fn arbitration_fires_only_on_a_different_hash_at_our_base_epoch() {
        let mut state = DirectPcsState::default();
        assert_eq!(state.arbitrate(3, "sha256:theirs"), None);

        state.own_commit = Some(own_commit(3, "sha256:mine", true));
        // Our own bytes echoed back are not a race.
        assert_eq!(state.arbitrate(3, "sha256:mine"), None);
        // Neither is a commit from any other epoch.
        assert_eq!(state.arbitrate(2, "sha256:theirs"), None);
        assert_eq!(state.arbitrate(4, "sha256:theirs"), None);
        // A different commit at our base epoch is the collision.
        assert_eq!(state.arbitrate(3, "sha256:theirs"), Some(true));

        state.own_commit = Some(own_commit(3, "sha256:mine", false));
        assert_eq!(state.arbitrate(3, "sha256:theirs"), Some(false));
    }
}

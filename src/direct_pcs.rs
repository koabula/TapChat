use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{CoreError, CoreResult};

pub const DIRECT_PCS_COMMIT_INTERVAL: u32 = 32;
/// Time-based fallback for `should_rotate`: a low-traffic conversation may
/// never reach `DIRECT_PCS_COMMIT_INTERVAL` messages, which would otherwise
/// let post-compromise healing stall indefinitely.
///
/// The non-designated party waits twice this, so an honest device's leaf is
/// never older than `2 × DIRECT_PCS_MAX_AGE_MS` when it next sends: that is
/// the `T` of `LIVE(T, Δ)`, and it also bounds how long a counterparty's stale
/// leaf can reach back when it is later corrupted. A week costs at most one
/// commit a week in a quiet conversation.
pub const DIRECT_PCS_MAX_AGE_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// The longest a record is taken to wait for delivery: the `Δ` of
/// `LIVE(T, Δ)`. An inbox drops records older than its retention period
/// (`RETENTION_DAYS`, 30 in the reference deployment), so a record that has
/// not been fetched by then is gone, and nothing that waits for one needs to
/// wait longer. A deployment that keeps records longer lengthens `Δ` beyond
/// what the waits below cover.
pub const DIRECT_DELIVERY_BOUND_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// How long a pending commit can still matter: `2Δ`, plus clock skew.
///
/// A race on our commit `c`, made at `t₀`, needs what `c` keeps until the
/// last message of the race arrives. The rival commit was made before its
/// author had `c`, so by `t₀ + Δ`, and arrives within `Δ` of that. A loser's
/// rebuild Welcome goes out when the loser receives `c`, again by `t₀ + Δ`,
/// and arrives within `Δ`. So nothing that needs `c` arrives after `t₀ + 2Δ`:
/// the bound `EXPECTED_REBUILD_TTL_MS` rests on too. The host's retention,
/// `Δ` alone, is not enough: `c` can reach its peer just inside it, while the
/// rival made just before is still on its way.
pub const PENDING_COMMIT_TTL_MS: u64 =
    2 * DIRECT_DELIVERY_BOUND_MS + crate::mls_adapter::KEY_PACKAGE_CLOCK_SKEW_MS;

/// One of our own commits that the peer has not yet been seen to follow.
///
/// A commit is *pending* until this device is delivered a frame of the peer
/// from the epoch the commit created or a later one. Until then the peer may
/// have committed on the same base epoch, and either side of that race needs
/// what is kept here: the winner opens the rival commit and then the loser's
/// rebuild Welcome with `inbound_key`, and joins with the private keys of
/// `key_package_b64`; the loser wraps its Welcome under `wrap_key`. Once the
/// peer has followed, none of it has a use left, and all of it is deleted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingCommit {
    pub base_epoch: u64,
    pub commit_hash: String,
    /// `designated_committer(roster@base_epoch, base_epoch) == this device`,
    /// evaluated **when the commit was made**. Re-deriving it later would read
    /// the roster of whichever epoch we ended up in, and two racing membership
    /// commits leave the two sides with different rosters — the arbitration
    /// verdict has to be the same on both sides or the fork never resolves.
    pub won_arbitration: bool,
    /// `K_c(base_epoch, outbound)`, the key this commit went out under. If it
    /// loses, the rebuild Welcome goes out under it too, and the winner, which
    /// opened the commit with it, can tell that Welcome from a forgery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrap_key: Option<[u8; crate::lane_wrap::WRAP_KEY_LEN]>,
    /// `K_c(base_epoch, inbound)`: what a rival commit on the same base epoch
    /// travels under, and later the loser's rebuild Welcome. By the time
    /// either arrives this device may have rotated again, and the current and
    /// previous epoch's keys no longer reach back to `base_epoch`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound_key: Option<[u8; crate::lane_wrap::WRAP_KEY_LEN]>,
    /// The fresh KeyPackage the commit carried, whose private keys this
    /// device holds while the commit is pending. A peer that loses a race
    /// against this commit re-enters by a new group built to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_package_b64: Option<String>,
    /// Local clock, when the commit was made; see [`PENDING_COMMIT_TTL_MS`].
    /// Zero for a commit recorded before this was kept.
    #[serde(default)]
    pub made_at_ms: u64,
}

impl PendingCommit {
    /// The epoch this commit created.
    pub fn created_epoch(&self) -> u64 {
        self.base_epoch.saturating_add(1)
    }
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
    /// Oldest first. More than one only when this device rotates again before
    /// hearing from the peer in the epoch its previous commit created.
    #[serde(
        default,
        alias = "ownCommit",
        deserialize_with = "pending_commits_or_legacy_one",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub pending_commits: Vec<PendingCommit>,
    /// Our leaf must be replaced at the next settled decision, whatever the
    /// schedule says. Set when a Welcome replaces a session we had and the
    /// leaf it gives us is older than our latest rotation there: a peer's
    /// reset, which joins us from a published KeyPackage, or a race we won
    /// but rotated past before the loser's rebuild arrived. Either way we had
    /// healed beyond that leaf, and it must not outlive the join.
    #[serde(
        default,
        alias = "leafFromKeyPackage",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub rotate_now: bool,
}

/// Before the pending set, state kept at most one own commit, as
/// `ownCommit`; read it as a set of one.
fn pending_commits_or_legacy_one<'de, D>(deserializer: D) -> Result<Vec<PendingCommit>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Stored {
        Many(Vec<PendingCommit>),
        One(Option<PendingCommit>),
    }
    Ok(match Stored::deserialize(deserializer)? {
        Stored::Many(commits) => commits,
        Stored::One(commit) => commit.into_iter().collect(),
    })
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
        if self.rotate_now {
            return true;
        }
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
    pub fn mark_rotated(&mut self, commit: PendingCommit, now_ms: u64) {
        self.self_debt = 0;
        self.self_rotated_at_ms = Some(now_ms);
        self.pending_commits.push(commit);
        self.rotate_now = false;
    }

    /// Our latest commit that is still pending.
    pub fn own_commit(&self) -> Option<&PendingCommit> {
        self.pending_commits.last()
    }

    /// The peer was seen in `peer_epoch`: every commit of ours that created
    /// that epoch or an earlier one is no longer pending. Returns them, so
    /// the caller can delete what they kept. Does **not** touch `self_debt`;
    /// see the field comment.
    pub fn resolve_pending(&mut self, peer_epoch: u64) -> Vec<PendingCommit> {
        let (resolved, pending) = std::mem::take(&mut self.pending_commits)
            .into_iter()
            .partition(|commit| commit.created_epoch() <= peer_epoch);
        self.pending_commits = pending;
        resolved
    }

    /// The pending commit that a peer commit on `incoming_epoch` with hash
    /// `incoming_hash` races, if any. `None` when there is no race and the
    /// frame should take the ordinary ingest path.
    pub fn arbitrate(&self, incoming_epoch: u64, incoming_hash: &str) -> Option<&PendingCommit> {
        self.pending_commits
            .iter()
            .find(|own| own.base_epoch == incoming_epoch && own.commit_hash != incoming_hash)
    }

    /// Pending commits past [`PENDING_COMMIT_TTL_MS`], taken out and returned
    /// so the caller can delete what they kept. Under `LIVE` no race can reach
    /// them any more, and all their keys could still do is be read from a
    /// snapshot.
    ///
    /// Two are kept whatever their age. The latest: it holds the key the ideal
    /// lets a party keep at the latest epoch it created, one entry however
    /// quiet the peer is, and a peer that returns late can still follow it.
    /// And the one whose KeyPackage is `awaited`: we won its race and wait for
    /// the loser's rebuild, which is built to that package.
    pub fn expire_pending(&mut self, now_ms: u64, awaited: Option<&str>) -> Vec<PendingCommit> {
        let latest = self.pending_commits.len().saturating_sub(1);
        let (kept, expired): (Vec<_>, Vec<_>) = std::mem::take(&mut self.pending_commits)
            .into_iter()
            .enumerate()
            .partition(|(index, commit)| {
                *index == latest
                    || (awaited.is_some() && commit.key_package_b64.as_deref() == awaited)
                    || now_ms.saturating_sub(commit.made_at_ms) < PENDING_COMMIT_TTL_MS
            });
        self.pending_commits = kept.into_iter().map(|(_, commit)| commit).collect();
        expired.into_iter().map(|(_, commit)| commit).collect()
    }

    /// Whether this device committed again after its commit on `base_epoch`.
    pub fn rotated_since(&self, base_epoch: u64) -> bool {
        self.pending_commits
            .iter()
            .any(|own| own.base_epoch > base_epoch)
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

    fn own_commit(base_epoch: u64, hash: &str, won: bool) -> PendingCommit {
        PendingCommit {
            base_epoch,
            commit_hash: hash.into(),
            won_arbitration: won,
            wrap_key: None,
            inbound_key: None,
            key_package_b64: None,
            made_at_ms: 0,
        }
    }

    fn made_at(base_epoch: u64, made_at_ms: u64, key_package: &str) -> PendingCommit {
        PendingCommit {
            made_at_ms,
            key_package_b64: Some(key_package.into()),
            ..own_commit(base_epoch, &format!("sha256:{base_epoch}"), true)
        }
    }

    #[test]
    fn a_pending_commit_expires_after_the_race_window_unless_it_is_still_needed() {
        let now = 10 * PENDING_COMMIT_TTL_MS;
        let mut state = DirectPcsState {
            pending_commits: vec![
                made_at(3, now - PENDING_COMMIT_TTL_MS, "expired"),
                made_at(4, now - PENDING_COMMIT_TTL_MS + 1, "inside"),
                made_at(5, now - PENDING_COMMIT_TTL_MS, "awaited"),
                made_at(6, 0, "latest"),
            ],
            ..Default::default()
        };
        let expired = state.expire_pending(now, Some("awaited"));
        let names = |commits: &[PendingCommit]| {
            commits
                .iter()
                .map(|commit| commit.key_package_b64.clone().unwrap_or_default())
                .collect::<Vec<_>>()
        };
        assert_eq!(names(&expired), ["expired"]);
        assert_eq!(
            names(&state.pending_commits),
            ["inside", "awaited", "latest"]
        );
        // Past the host's retention but inside 2Δ is still inside.
        let mut state = DirectPcsState {
            pending_commits: vec![
                made_at(3, now - DIRECT_DELIVERY_BOUND_MS - 1, "past retention"),
                made_at(4, now, "latest"),
            ],
            ..Default::default()
        };
        assert!(state.expire_pending(now, None).is_empty());
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
        state.mark_rotated(own_commit(7, "sha256:mine", true), DIRECT_PCS_MAX_AGE_MS);
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
            pending_commits: vec![own_commit(3, "sha256:mine", false)],
            ..Default::default()
        };
        assert_eq!(state.resolve_pending(4).len(), 1);
        assert!(state.pending_commits.is_empty());
        assert_eq!(state.self_debt, DIRECT_PCS_COMMIT_INTERVAL);
        assert!(state.should_rotate(true, 0));
    }

    #[test]
    fn a_commit_stays_pending_until_the_peer_is_seen_in_the_epoch_it_created() {
        let mut state = DirectPcsState {
            pending_commits: vec![
                own_commit(3, "sha256:first", true),
                own_commit(4, "sha256:second", false),
            ],
            ..Default::default()
        };
        // The peer still in our commit's base epoch has not followed it.
        assert!(state.resolve_pending(3).is_empty());
        let resolved = state.resolve_pending(4);
        assert_eq!(resolved, vec![own_commit(3, "sha256:first", true)]);
        assert_eq!(
            state.own_commit().map(|own| own.base_epoch),
            Some(4),
            "the later commit is still pending"
        );
        assert!(!state.rotated_since(4));
        state
            .pending_commits
            .insert(0, own_commit(3, "sha256:first", true));
        assert!(state.rotated_since(3));
    }

    #[test]
    fn a_stored_single_own_commit_reads_as_a_pending_set_of_one() {
        let legacy = r#"{"selfDebt":2,"ownCommit":{"baseEpoch":3,"commitHash":"sha256:mine","wonArbitration":true},"leafFromKeyPackage":true}"#;
        let state: DirectPcsState = serde_json::from_str(legacy).expect("legacy state");
        assert_eq!(
            state.pending_commits,
            vec![own_commit(3, "sha256:mine", true)]
        );
        assert!(state.rotate_now);
        let empty: DirectPcsState =
            serde_json::from_str(r#"{"ownCommit":null}"#).expect("no own commit");
        assert!(empty.pending_commits.is_empty());
        let round_trip: DirectPcsState =
            serde_json::from_str(&serde_json::to_string(&state).expect("encode")).expect("decode");
        assert_eq!(round_trip, state);
    }

    #[test]
    fn arbitration_fires_only_on_a_different_hash_at_our_base_epoch() {
        let mut state = DirectPcsState::default();
        assert_eq!(state.arbitrate(3, "sha256:theirs"), None);

        state.pending_commits = vec![own_commit(3, "sha256:mine", true)];
        let won = |state: &DirectPcsState, epoch, hash| {
            state.arbitrate(epoch, hash).map(|own| own.won_arbitration)
        };
        // Our own bytes echoed back are not a race.
        assert_eq!(won(&state, 3, "sha256:mine"), None);
        // Neither is a commit from any other epoch.
        assert_eq!(won(&state, 2, "sha256:theirs"), None);
        assert_eq!(won(&state, 4, "sha256:theirs"), None);
        // A different commit at our base epoch is the collision.
        assert_eq!(won(&state, 3, "sha256:theirs"), Some(true));

        state.pending_commits = vec![own_commit(3, "sha256:mine", false)];
        assert_eq!(won(&state, 3, "sha256:theirs"), Some(false));

        // A later commit of ours does not hide an earlier one still pending.
        state.pending_commits = vec![
            own_commit(3, "sha256:mine", true),
            own_commit(4, "sha256:later", false),
        ];
        assert_eq!(won(&state, 3, "sha256:theirs"), Some(true));
        assert_eq!(won(&state, 4, "sha256:theirs"), Some(false));
    }
}

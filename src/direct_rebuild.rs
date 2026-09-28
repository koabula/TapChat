//! Who may replace a 1:1 session this device already holds.
//!
//! A Welcome is how a leaf joins a group, and for a conversation that already
//! exists it replaces the group outright. Its author is authenticated by the
//! device key, and the device key is the MLS leaf key for good: a snapshot of
//! the peer signs as the peer long after the peer has healed. So for an
//! existing conversation the device key is not enough. The Welcome has to be
//! authenticated by the session it replaces, or this device has to be in a
//! state where there is no session left to do it.
//!
//! - **A lost commit race.** The loser rebuilds to the KeyPackage the winning
//!   commit carried, and its Welcome travels wrapped under the key its losing
//!   commit travelled under. The winner opened that commit with the same key,
//!   keeps it, and accepts a Welcome under it from that device, once, and only
//!   one built to that KeyPackage. A thief that healed out of the session has
//!   neither the commit nor the key, and the winner joins with a leaf no
//!   snapshot from before its commit holds. The Welcome also carries the
//!   loser's signature for the race, and the winner keeps the digest of the
//!   one it joined: a holder of the loser's device key and of the race's epoch
//!   can build a rebuild too, and whichever of the two arrives second is the
//!   evidence (`direct_fork`).
//! - **No session left.** A local MLS fault or a failed restore tears this
//!   device's group down; there is nothing to authenticate with, so the peer's
//!   plain Welcome is accepted until one arrives. The peer's user starts that
//!   rebuild ([`RebuildAuthority::reset_requested`] on their side). A snapshot
//!   holder that happens to strike inside this window is a known residual.
//!
//! Nothing a remote party sends sets either of these; the first needs a commit
//! that authenticated under the session's keys, the second a local fault or
//! the user. First contact, where no conversation of that id exists, is
//! establishment and is not governed here.

use serde::{Deserialize, Serialize};

use crate::direct_pcs::DIRECT_DELIVERY_BOUND_MS;
use crate::lane_wrap::WRAP_KEY_LEN;

/// How long a race winner waits for the loser's rebuild. The loser rebuilds
/// the moment it sees the winning commit, so this only has to cover delivery:
/// the winning commit's and then the Welcome's, each within `Δ`.
pub const EXPECTED_REBUILD_TTL_MS: u64 = 2 * DIRECT_DELIVERY_BOUND_MS;

/// A rebuild this device agreed to when it won a commit race.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpectedRebuild {
    /// The device whose commit lost. Its Welcome is the only one admitted.
    pub device_id: String,
    /// The key the losing commit opened under: `K_c` of the race's base epoch.
    pub key: [u8; WRAP_KEY_LEN],
    pub at_ms: u64,
    /// The epoch both commits built on: what the loser's rebuild signature
    /// names.
    #[serde(default)]
    pub base_epoch: u64,
    /// The KeyPackage our winning commit carried. The rebuild must be built
    /// to it: any other of our packages may be older than a snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_package_b64: Option<String>,
}

/// What a race loser re-enters to: the winner's device, and the KeyPackage
/// its winning commit carried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReentryTarget {
    pub device_id: String,
    pub key_package_b64: String,
    /// The epoch the race was on, which the rebuild Welcome's signature names.
    #[serde(default)]
    pub base_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RebuildAuthority {
    /// Lost a commit race: the rebuild Welcome goes out wrapped under this
    /// key, the one the losing commit went out under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrap_out: Option<[u8; WRAP_KEY_LEN]>,
    /// Lost a commit race: the new group is built to this, not to anything
    /// the host would hand out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reentry: Option<ReentryTarget>,
    /// Won a commit race: the loser's rebuild Welcome will arrive under this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected: Option<ExpectedRebuild>,
    /// This device's group is gone to a local fault; the peer's rebuild
    /// Welcome is accepted without a session key, because there is none.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub awaits_peer_welcome: bool,
    /// The user asked for this session to be rebuilt from here. Without it, or
    /// `wrap_out`, this device does not start a rebuild its peer would have no
    /// way to authenticate.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reset_requested: bool,
}

impl RebuildAuthority {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    /// Whether this device may build a new group for the conversation and
    /// Welcome its peer into it.
    pub fn may_bootstrap(&self) -> bool {
        self.wrap_out.is_some() || self.reset_requested
    }

    /// Whether a Welcome that opened under `key` from `device_id` is the
    /// rebuild this device expects, as far as the wrap tells. The caller
    /// still checks that it was built to [`ExpectedRebuild::key_package_b64`].
    pub fn admits_wrapped(&self, key: &[u8; WRAP_KEY_LEN], device_id: &str, now_ms: u64) -> bool {
        self.expected.as_ref().is_some_and(|expected| {
            &expected.key == key
                && expected.device_id == device_id
                && now_ms.saturating_sub(expected.at_ms) < EXPECTED_REBUILD_TTL_MS
        })
    }

    /// The expected rebuild's key, for a frame none of the session's current
    /// keys open: by the time the loser's Welcome arrives the winner may have
    /// moved on.
    pub fn expected_key(&self) -> Option<&[u8; WRAP_KEY_LEN]> {
        self.expected.as_ref().map(|expected| &expected.key)
    }

    /// A rebuild went out: what authorised it is spent.
    pub fn bootstrapped(&mut self) {
        self.wrap_out = None;
        self.reentry = None;
        self.reset_requested = false;
    }

    /// A Welcome was adopted: nothing is awaited or expected any more.
    pub fn settled(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expecting(key: u8, at_ms: u64) -> RebuildAuthority {
        RebuildAuthority {
            expected: Some(ExpectedRebuild {
                device_id: "device:bob:phone".into(),
                key: [key; WRAP_KEY_LEN],
                at_ms,
                base_epoch: 0,
                key_package_b64: None,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn a_wrapped_welcome_is_admitted_only_under_the_expected_key_from_the_expected_device() {
        let authority = expecting(1, 0);
        assert!(authority.admits_wrapped(&[1; WRAP_KEY_LEN], "device:bob:phone", 0));
        assert!(!authority.admits_wrapped(&[2; WRAP_KEY_LEN], "device:bob:phone", 0));
        assert!(!authority.admits_wrapped(&[1; WRAP_KEY_LEN], "device:bob:laptop", 0));
        assert!(!RebuildAuthority::default().admits_wrapped(
            &[1; WRAP_KEY_LEN],
            "device:bob:phone",
            0
        ));
    }

    #[test]
    fn an_expected_rebuild_expires() {
        let authority = expecting(1, 0);
        assert!(authority.admits_wrapped(
            &[1; WRAP_KEY_LEN],
            "device:bob:phone",
            EXPECTED_REBUILD_TTL_MS - 1
        ));
        assert!(!authority.admits_wrapped(
            &[1; WRAP_KEY_LEN],
            "device:bob:phone",
            EXPECTED_REBUILD_TTL_MS
        ));
    }

    #[test]
    fn only_a_lost_race_or_the_user_authorises_a_rebuild() {
        let mut authority = RebuildAuthority {
            awaits_peer_welcome: true,
            ..Default::default()
        };
        assert!(
            !authority.may_bootstrap(),
            "a local fault waits for the peer"
        );
        authority.reset_requested = true;
        assert!(authority.may_bootstrap());
        authority.bootstrapped();
        assert!(!authority.may_bootstrap());
        authority.wrap_out = Some([3; WRAP_KEY_LEN]);
        assert!(authority.may_bootstrap());
        authority.settled();
        assert!(authority.is_empty());
    }
}

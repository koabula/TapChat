use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{CoreError, CoreResult};
use crate::identity::LocalIdentityState;

pub const DIRECT_PCS_COMMIT_INTERVAL: u32 = 32;
pub const DIRECT_PCS_DEBT_HARD: u32 = 256;
/// Time-based fallback for `should_initiate_commit`: a low-traffic
/// conversation may never reach `DIRECT_PCS_COMMIT_INTERVAL` messages, which
/// would otherwise let post-compromise healing stall indefinitely.
pub const DIRECT_PCS_MAX_AGE_MS: u64 = 30 * 24 * 60 * 60 * 1000;

const SIGNING_DOMAIN: &str = "tapchat-direct-pcs-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectPcsRole {
    Committer,
    Acceptor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectCommitCertificate {
    pub conversation_id: String,
    pub epoch: u64,
    pub parent_commit_hash: String,
    pub commit_hash: String,
    pub committer_device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acceptor_device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub committer_sig: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acceptor_sig: Option<String>,
}

impl DirectCommitCertificate {
    pub fn signing_payload(&self) -> Vec<u8> {
        certificate_signing_payload(
            &self.conversation_id,
            self.epoch,
            &self.parent_commit_hash,
            &self.commit_hash,
        )
    }

    pub fn is_complete(&self) -> bool {
        self.committer_sig.as_ref().is_some_and(|s| !s.is_empty())
            && self.acceptor_sig.as_ref().is_some_and(|s| !s.is_empty())
            && self
                .acceptor_device_id
                .as_ref()
                .is_some_and(|s| !s.is_empty())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectPcsHandshake {
    pub role: DirectPcsRole,
    pub epoch: u64,
    pub commit_hash: String,
    pub commit_b64: String,
    pub parent_commit_hash: String,
    pub committer_device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acceptor_device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub committer_sig: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acceptor_sig: Option<String>,
}

impl DirectPcsHandshake {
    pub fn certificate(&self, conversation_id: &str) -> DirectCommitCertificate {
        DirectCommitCertificate {
            conversation_id: conversation_id.to_string(),
            epoch: self.epoch,
            parent_commit_hash: self.parent_commit_hash.clone(),
            commit_hash: self.commit_hash.clone(),
            committer_device_id: self.committer_device_id.clone(),
            acceptor_device_id: self.acceptor_device_id.clone(),
            committer_sig: self.committer_sig.clone(),
            acceptor_sig: self.acceptor_sig.clone(),
        }
    }

    pub fn is_promised(&self) -> bool {
        self.acceptor_sig
            .as_ref()
            .is_some_and(|sig| !sig.is_empty())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DirectPcsState {
    #[serde(default)]
    pub epoch_app_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_certified_commit_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_certified_commit_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_certified_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_commit_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handshake: Option<DirectPcsHandshake>,
    #[serde(default)]
    pub degraded: bool,
}

impl DirectPcsState {
    pub fn record_signature(&mut self, epoch: u64, commit_hash: &str) -> CoreResult<()> {
        if let (Some(signed_epoch), Some(signed_hash)) =
            (self.signed_epoch, self.signed_commit_hash.as_ref())
        {
            if signed_epoch == epoch && signed_hash != commit_hash {
                return Err(CoreError::invalid_state(
                    "already signed a different commit for this epoch",
                ));
            }
        }
        self.signed_epoch = Some(epoch);
        self.signed_commit_hash = Some(commit_hash.to_string());
        Ok(())
    }

    pub fn note_application_message(&mut self) {
        self.epoch_app_count = self.epoch_app_count.saturating_add(1);
        if self.epoch_app_count >= DIRECT_PCS_DEBT_HARD {
            self.degraded = true;
        }
    }

    pub fn should_initiate_commit(
        &self,
        local_device_id: &str,
        committer_device_id: &str,
        now_ms: u64,
    ) -> bool {
        self.handshake.is_none()
            && local_device_id == committer_device_id
            && (self.epoch_app_count >= DIRECT_PCS_COMMIT_INTERVAL || self.commit_overdue(now_ms))
    }

    fn commit_overdue(&self, now_ms: u64) -> bool {
        self.last_certified_at_ms
            .is_some_and(|at| now_ms.saturating_sub(at) >= DIRECT_PCS_MAX_AGE_MS)
    }

    pub fn abort_handshake(&mut self) {
        self.handshake = None;
    }

    pub fn handshake_is_promised(&self) -> bool {
        self.handshake
            .as_ref()
            .is_some_and(DirectPcsHandshake::is_promised)
    }

    pub fn is_certified_hash(&self, commit_hash: &str) -> bool {
        self.last_certified_commit_hash.as_deref() == Some(commit_hash)
            || self.previous_certified_commit_hash.as_deref() == Some(commit_hash)
    }

    pub fn mark_certified(&mut self, commit_hash: String, now_ms: u64) {
        self.previous_certified_commit_hash = self.last_certified_commit_hash.clone();
        self.last_certified_commit_hash = Some(commit_hash);
        self.last_certified_at_ms = Some(now_ms);
        self.epoch_app_count = 0;
        self.degraded = false;
        self.handshake = None;
        self.signed_epoch = None;
        self.signed_commit_hash = None;
    }
}

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

pub fn certificate_signing_payload(
    conversation_id: &str,
    epoch: u64,
    parent_commit_hash: &str,
    commit_hash: &str,
) -> Vec<u8> {
    format!("{SIGNING_DOMAIN}\n{conversation_id}\n{epoch}\n{parent_commit_hash}\n{commit_hash}")
        .into_bytes()
}

pub fn sign_certificate(
    identity: &LocalIdentityState,
    conversation_id: &str,
    epoch: u64,
    parent_commit_hash: &str,
    commit_hash: &str,
) -> String {
    identity.sign_sender_proof(&certificate_signing_payload(
        conversation_id,
        epoch,
        parent_commit_hash,
        commit_hash,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityManager;

    const ALICE_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const BOB_MNEMONIC: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";

    #[test]
    fn committer_rotates_with_epoch() {
        let ids = vec!["device:alice:phone".into(), "device:bob:phone".into()];
        let first = designated_committer(&ids, 1).expect("epoch 1");
        let second = designated_committer(&ids, 2).expect("epoch 2");
        assert_ne!(first, second);
        assert_eq!(first, designated_committer(&ids, 3).expect("epoch 3"));
    }

    #[test]
    fn sign_once_rejects_a_second_hash_in_the_same_epoch() {
        let mut state = DirectPcsState::default();
        state
            .record_signature(1, "sha256:aaa")
            .expect("first signature");
        state
            .record_signature(1, "sha256:aaa")
            .expect("same hash is idempotent");
        let error = state
            .record_signature(1, "sha256:bbb")
            .expect_err("different hash must fail");
        assert_eq!(error.code(), "invalid_state");
    }

    #[test]
    fn handshake_is_promised_only_after_acceptor_signature() {
        let handshake = DirectPcsHandshake {
            role: DirectPcsRole::Acceptor,
            epoch: 1,
            commit_hash: "sha256:commit".into(),
            commit_b64: "commit".into(),
            parent_commit_hash: "sha256:parent".into(),
            committer_device_id: "device:alice:phone".into(),
            acceptor_device_id: Some("device:bob:phone".into()),
            committer_sig: Some("committer".into()),
            acceptor_sig: None,
        };
        assert!(!handshake.is_promised());
        let mut promised = handshake.clone();
        promised.acceptor_sig = Some("acceptor".into());
        assert!(promised.is_promised());
    }

    #[test]
    fn certificate_requires_both_signatures() {
        let alice =
            IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone")).expect("alice");
        let bob =
            IdentityManager::create_or_recover(Some(BOB_MNEMONIC), Some("phone")).expect("bob");
        let mut cert = DirectCommitCertificate {
            conversation_id: "conv:alice:bob".into(),
            epoch: 1,
            parent_commit_hash: "sha256:parent".into(),
            commit_hash: "sha256:commit".into(),
            committer_device_id: alice.device_identity.device_id.clone(),
            acceptor_device_id: Some(bob.device_identity.device_id.clone()),
            committer_sig: Some(sign_certificate(
                &alice,
                "conv:alice:bob",
                1,
                "sha256:parent",
                "sha256:commit",
            )),
            acceptor_sig: None,
        };
        assert!(!cert.is_complete());
        cert.acceptor_sig = Some(sign_certificate(
            &bob,
            "conv:alice:bob",
            1,
            "sha256:parent",
            "sha256:commit",
        ));
        assert!(cert.is_complete());
        crate::identity::verify_device_payload_signature(
            &alice.device_identity.device_public_key,
            &cert.signing_payload(),
            cert.committer_sig.as_deref().expect("committer sig"),
        )
        .expect("alice signature");
        crate::identity::verify_device_payload_signature(
            &bob.device_identity.device_public_key,
            &cert.signing_payload(),
            cert.acceptor_sig.as_deref().expect("acceptor sig"),
        )
        .expect("bob signature");
    }

    #[test]
    fn wrong_parent_hash_changes_the_signed_payload() {
        let alice =
            IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone")).expect("alice");
        let sig = sign_certificate(
            &alice,
            "conv:alice:bob",
            1,
            "sha256:parent",
            "sha256:commit",
        );
        let error = crate::identity::verify_device_payload_signature(
            &alice.device_identity.device_public_key,
            &certificate_signing_payload("conv:alice:bob", 1, "sha256:other", "sha256:commit"),
            &sig,
        )
        .expect_err("parent mismatch must fail verification");
        assert_eq!(error.code(), "invalid_input");
    }

    #[test]
    fn debt_hard_marks_degraded_without_resetting_count() {
        let mut state = DirectPcsState::default();
        state.epoch_app_count = DIRECT_PCS_DEBT_HARD - 1;
        state.note_application_message();
        assert!(state.degraded);
        assert_eq!(state.epoch_app_count, DIRECT_PCS_DEBT_HARD);
    }

    #[test]
    fn stale_epoch_triggers_commit_even_with_few_messages() {
        let mut state = DirectPcsState {
            last_certified_at_ms: Some(0),
            ..Default::default()
        };
        state.epoch_app_count = 1;
        let committer = "device:alice:phone";
        assert!(!state.should_initiate_commit(committer, committer, DIRECT_PCS_MAX_AGE_MS - 1));
        assert!(state.should_initiate_commit(committer, committer, DIRECT_PCS_MAX_AGE_MS));
    }

    #[test]
    fn mark_certified_resets_the_staleness_clock() {
        let mut state = DirectPcsState {
            last_certified_at_ms: Some(0),
            ..Default::default()
        };
        state.mark_certified("sha256:commit".into(), DIRECT_PCS_MAX_AGE_MS);
        assert_eq!(state.last_certified_at_ms, Some(DIRECT_PCS_MAX_AGE_MS));
        let committer = "device:alice:phone";
        assert!(!state.should_initiate_commit(
            committer,
            committer,
            DIRECT_PCS_MAX_AGE_MS + DIRECT_PCS_MAX_AGE_MS - 1
        ));
    }
}

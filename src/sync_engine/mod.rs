use std::collections::{BTreeMap, BTreeSet};

use crate::model::{Ack, InboxRecord, SyncCheckpoint};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SyncEngineModule;

impl SyncEngineModule {
    pub fn name(&self) -> &'static str {
        "sync_engine"
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSyncState {
    pub checkpoint: SyncCheckpoint,
    pub seen_message_ids: BTreeSet<String>,
    pub pending_records: BTreeMap<u64, InboxRecord>,
    pub pending_record_seqs: BTreeSet<u64>,
    pub pending_retry: bool,
    pub last_head_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncDecision {
    pub from_seq: u64,
    pub to_seq: u64,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SyncEngine;

impl SyncEngine {
    pub fn new_device_state(device_id: &str) -> DeviceSyncState {
        DeviceSyncState {
            checkpoint: SyncCheckpoint {
                device_id: device_id.to_string(),
                last_fetched_seq: 0,
                last_acked_seq: 0,
                updated_at: 0,
            },
            seen_message_ids: BTreeSet::new(),
            pending_records: BTreeMap::new(),
            pending_record_seqs: BTreeSet::new(),
            pending_retry: false,
            last_head_seq: 0,
        }
    }

    pub fn register_fetch(
        state: &mut DeviceSyncState,
        records: &[InboxRecord],
        to_seq: u64,
    ) -> Vec<InboxRecord> {
        let mut fresh = Vec::new();
        for record in records {
            if state.seen_message_ids.insert(record.message_id.clone()) {
                fresh.push(record.clone());
            }
        }
        state.checkpoint.last_fetched_seq = to_seq.max(state.checkpoint.last_fetched_seq);
        state.checkpoint.updated_at = state.checkpoint.last_fetched_seq;
        fresh
    }

    pub fn register_head(state: &mut DeviceSyncState, head_seq: u64) {
        state.last_head_seq = head_seq.max(state.last_head_seq);
        state.checkpoint.updated_at = state.last_head_seq;
    }

    pub fn next_fetch(state: &DeviceSyncState) -> Option<SyncDecision> {
        let from_seq = state.checkpoint.last_acked_seq.saturating_add(1);
        if state.pending_retry || from_seq <= state.last_head_seq {
            Some(SyncDecision {
                from_seq,
                to_seq: state.last_head_seq,
            })
        } else {
            None
        }
    }

    pub fn note_pending_retry(state: &mut DeviceSyncState, seq: u64) {
        state.pending_retry = true;
        state.pending_record_seqs.insert(seq);
    }

    pub fn store_pending_record(state: &mut DeviceSyncState, record: &InboxRecord) {
        state.pending_records.insert(record.seq, record.clone());
        Self::note_pending_retry(state, record.seq);
    }

    pub fn clear_pending_retry(state: &mut DeviceSyncState, seq: u64) {
        state.pending_record_seqs.remove(&seq);
        state.pending_records.remove(&seq);
        state.pending_retry = !state.pending_record_seqs.is_empty();
    }

    pub fn ack_up_to(state: &mut DeviceSyncState, ack_seq: u64) -> Ack {
        state.checkpoint.last_acked_seq = ack_seq.max(state.checkpoint.last_acked_seq);
        state.checkpoint.updated_at = state.checkpoint.last_acked_seq;
        Ack {
            device_id: state.checkpoint.device_id.clone(),
            ack_seq: state.checkpoint.last_acked_seq,
            acked_message_ids: Vec::new(),
            acked_at: state.checkpoint.updated_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SyncEngine, SyncEngineModule};
    use crate::model::{
        DeliveryClass, Envelope, InboxRecord, InboxRecordState, MessageType, SenderProof,
        WakeHint, CURRENT_MODEL_VERSION,
    };

    #[test]
    fn module_name_is_stable() {
        assert_eq!(SyncEngineModule.name(), "sync_engine");
    }

    #[test]
    fn duplicate_records_are_filtered_during_fetch_registration() {
        let mut state = SyncEngine::new_device_state("device:bob:phone");
        let record = sample_record("msg:1", 1);
        let fresh = SyncEngine::register_fetch(&mut state, &[record.clone(), record], 1);

        assert_eq!(fresh.len(), 1);
        assert_eq!(state.checkpoint.last_fetched_seq, 1);
    }

    #[test]
    fn ack_advances_checkpoint() {
        let mut state = SyncEngine::new_device_state("device:bob:phone");
        let ack = SyncEngine::ack_up_to(&mut state, 10);
        assert_eq!(ack.ack_seq, 10);
        assert_eq!(state.checkpoint.last_acked_seq, 10);
    }

    #[test]
    fn next_fetch_uses_head_and_retry_state() {
        let mut state = SyncEngine::new_device_state("device:bob:phone");
        SyncEngine::register_head(&mut state, 5);
        let decision = SyncEngine::next_fetch(&state).expect("should fetch");
        assert_eq!(decision.from_seq, 1);
        assert_eq!(decision.to_seq, 5);
    }

    #[test]
    fn pending_retry_keeps_fetching_from_last_acked_seq() {
        let mut state = SyncEngine::new_device_state("device:bob:phone");
        state.checkpoint.last_fetched_seq = 5;
        state.checkpoint.last_acked_seq = 3;
        SyncEngine::note_pending_retry(&mut state, 4);

        let decision = SyncEngine::next_fetch(&state).expect("should retry");
        assert_eq!(decision.from_seq, 4);
        assert_eq!(decision.to_seq, 0);
    }

    #[test]
    fn clear_pending_retry_resets_retry_flag() {
        let mut state = SyncEngine::new_device_state("device:bob:phone");
        let record = sample_record("msg:1", 1);
        SyncEngine::store_pending_record(&mut state, &record);
        assert!(state.pending_retry);

        SyncEngine::clear_pending_retry(&mut state, 1);

        assert!(!state.pending_retry);
        assert!(state.pending_records.is_empty());
    }

    fn sample_record(message_id: &str, seq: u64) -> InboxRecord {
        InboxRecord {
            seq,
            recipient_device_id: "device:bob:phone".into(),
            message_id: message_id.into(),
            received_at: seq,
            expires_at: None,
            state: InboxRecordState::Available,
            envelope: Envelope {
                version: CURRENT_MODEL_VERSION.to_string(),
                message_id: message_id.into(),
                conversation_id: "conv:user:alice:user:bob".into(),
                sender_user_id: "user:alice".into(),
                sender_device_id: "device:alice:phone".into(),
                recipient_device_id: "device:bob:phone".into(),
                created_at: seq,
                message_type: MessageType::MlsApplication,
                inline_ciphertext: Some("cipher".into()),
                storage_refs: vec![],
                delivery_class: DeliveryClass::Normal,
                wake_hint: Some(WakeHint {
                    latest_seq_hint: Some(seq),
                }),
                sender_proof: SenderProof {
                    proof_type: "signature".into(),
                    value: "proof".into(),
                },
            },
        }
    }
}

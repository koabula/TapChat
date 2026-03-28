use std::collections::BTreeSet;

use crate::model::{Ack, InboxRecord, SyncCheckpoint};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SyncEngineModule;

impl SyncEngineModule {
    pub fn name(&self) -> &'static str {
        "sync_engine"
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSyncState {
    pub checkpoint: SyncCheckpoint,
    pub seen_message_ids: BTreeSet<String>,
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
    use crate::model::{Envelope, InboxRecord, MessageType, SenderProof, CURRENT_MODEL_VERSION};

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

    fn sample_record(message_id: &str, seq: u64) -> InboxRecord {
        InboxRecord {
            seq,
            recipient_device_id: "device:bob:phone".into(),
            message_id: message_id.into(),
            received_at: seq,
            expires_at: None,
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
                sender_proof: SenderProof {
                    proof_type: "signature".into(),
                    value: "proof".into(),
                },
            },
        }
    }
}

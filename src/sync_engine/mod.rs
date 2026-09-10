use std::collections::{BTreeMap, BTreeSet};

use crate::model::{Ack, InboxRecord, SyncCheckpoint};
use serde::{Deserialize, Serialize};

/// Device-wide cap on retained retry copies.
///
/// Sized by write amplification rather than by protocol need: the whole
/// `DeviceSyncState` is a single JSON blob in the `sync_checkpoints` table and
/// is rebuilt from scratch on every persist effect, so 64 records of roughly
/// 4 KB each is about 256 KB rewritten per persist, which is the ceiling we
/// are willing to pay.
pub const MAX_QUARANTINED_RECORDS: usize = 64;

/// Per-conversation cap, so one conversation cannot starve the others.
///
/// The transport allows one epoch-changing commit at a time, so a legitimate
/// reorder window for a single conversation is a handful of frames; 16 is
/// generous.
pub const MAX_QUARANTINED_RECORDS_PER_CONVERSATION: usize = 16;

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
    /// Records that could not be applied yet, keyed by seq.
    ///
    /// One map, not a map plus a key set plus a flag: the other two were
    /// derivations that could disagree with it. Ask `has_quarantine` rather
    /// than carrying a separate boolean.
    #[serde(default)]
    pub quarantine: BTreeMap<u64, InboxRecord>,
    pub last_head_seq: u64,
    #[serde(default)]
    pub consecutive_failures: u32,
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
            quarantine: BTreeMap::new(),
            last_head_seq: 0,
            consecutive_failures: 0,
        }
    }

    /// Select records that have not reached a terminal local disposition.
    ///
    /// This function is intentionally side-effect free. Callers must not
    /// advance `seen_message_ids` or the fetched checkpoint until validation
    /// and record processing have completed successfully.
    pub fn select_fresh(state: &DeviceSyncState, records: &[InboxRecord]) -> Vec<InboxRecord> {
        records
            .iter()
            .filter(|record| !state.seen_message_ids.contains(&record.message_id))
            .cloned()
            .collect()
    }

    pub fn commit_fetched_record(state: &mut DeviceSyncState, record: &InboxRecord) {
        state.seen_message_ids.insert(record.message_id.clone());
        state.checkpoint.last_fetched_seq = record.seq.max(state.checkpoint.last_fetched_seq);
        state.checkpoint.updated_at = state.checkpoint.last_fetched_seq;
    }

    pub fn register_head(state: &mut DeviceSyncState, head_seq: u64) {
        state.last_head_seq = head_seq.max(state.last_head_seq);
        state.checkpoint.updated_at = state.last_head_seq;
        state.consecutive_failures = 0;
    }

    pub fn note_sync_failure(state: &mut DeviceSyncState) -> u32 {
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        state.consecutive_failures
    }

    pub fn clear_sync_failures(state: &mut DeviceSyncState) {
        state.consecutive_failures = 0;
    }

    /// The next range worth fetching, if any.
    ///
    /// This used to also fetch whenever `pending_retry` was set, which — with
    /// the ack cursor pinned by that same pending record — meant it returned
    /// `Some` forever and the client refetched an already-seen range on every
    /// tick. Records are now acked regardless of whether a local retry copy
    /// was kept (see `RecordRetention`), so `last_acked_seq` reaches
    /// `last_head_seq` at the end of every batch and this returns `None` when
    /// there is genuinely nothing new. Retry progress is driven by epoch
    /// advance re-ingesting the retained copies, not by refetching.
    pub fn next_fetch(state: &DeviceSyncState) -> Option<SyncDecision> {
        let from_seq = state.checkpoint.last_acked_seq.saturating_add(1);
        (from_seq <= state.last_head_seq).then_some(SyncDecision {
            from_seq,
            to_seq: state.last_head_seq,
        })
    }

    /// Whether anything is waiting in the retry buffer.
    pub fn has_quarantine(state: &DeviceSyncState) -> bool {
        !state.quarantine.is_empty()
    }

    /// Retain a local copy of a record that could not be applied yet.
    ///
    /// Bounded on purpose. A frame that cannot be authenticated yet is
    /// indistinguishable from a forgery — see `DeferReason` — so an adversary
    /// can mint entries here at will by sending frames for a future epoch.
    /// Without a cap that is unbounded RAM, an unbounded `sync_checkpoints`
    /// row, and unbounded work per replay.
    ///
    /// Eviction drops the *lowest* seq: it has waited longest, so if it were
    /// going to become authenticable it most likely already would have, and
    /// the frames that repair an out-of-order burst arrive *after* the frame
    /// they repair — so the newest arrival is the one worth keeping.
    ///
    /// Eviction needs no ack bookkeeping: every record is acked in the batch
    /// that first sees it (see `RecordRetention`), so there is never an
    /// unacked entry in here to settle.
    pub fn quarantine_record(state: &mut DeviceSyncState, record: &InboxRecord) {
        state.quarantine.insert(record.seq, record.clone());

        let conversation_id = record.envelope.conversation_id.clone();
        while Self::quarantined_for_conversation(state, &conversation_id)
            > MAX_QUARANTINED_RECORDS_PER_CONVERSATION
        {
            let Some(oldest) = state
                .quarantine
                .iter()
                .find(|(_, held)| held.envelope.conversation_id == conversation_id)
                .map(|(seq, _)| *seq)
            else {
                break;
            };
            state.quarantine.remove(&oldest);
        }
        while state.quarantine.len() > MAX_QUARANTINED_RECORDS {
            let Some(oldest) = state.quarantine.keys().next().copied() else {
                break;
            };
            state.quarantine.remove(&oldest);
        }
    }

    fn quarantined_for_conversation(state: &DeviceSyncState, conversation_id: &str) -> usize {
        state
            .quarantine
            .values()
            .filter(|held| held.envelope.conversation_id == conversation_id)
            .count()
    }

    pub fn release_quarantined(state: &mut DeviceSyncState, seq: u64) {
        state.quarantine.remove(&seq);
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
    use super::{
        SyncEngine, SyncEngineModule, MAX_QUARANTINED_RECORDS,
        MAX_QUARANTINED_RECORDS_PER_CONVERSATION,
    };
    use crate::model::{
        DeliveryClass, Envelope, InboxRecord, InboxRecordState, MessageType, SenderProof,
        CURRENT_MODEL_VERSION,
    };

    #[test]
    fn module_name_is_stable() {
        assert_eq!(SyncEngineModule.name(), "sync_engine");
    }

    #[test]
    fn duplicate_records_are_filtered_during_fetch_registration() {
        let mut state = SyncEngine::new_device_state("device:bob:phone");
        let record = sample_record("msg:1", 1);
        let fresh = SyncEngine::select_fresh(&state, &[record.clone(), record.clone()]);

        assert_eq!(fresh.len(), 2);
        assert_eq!(state.checkpoint.last_fetched_seq, 0);
        SyncEngine::commit_fetched_record(&mut state, &record);
        assert_eq!(state.checkpoint.last_fetched_seq, 1);
        assert!(SyncEngine::select_fresh(&state, &[record]).is_empty());
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
    fn a_quarantined_record_alone_does_not_drive_a_refetch() {
        // A retained retry copy is local state. It must not make the client
        // refetch a range it has already consumed: the record is already
        // acked, so refetching returns nothing new and the loop would spin on
        // every tick. Retry progress comes from re-ingesting the local copy
        // once the conversation's epoch advances.
        let mut state = SyncEngine::new_device_state("device:bob:phone");
        state.checkpoint.last_fetched_seq = 5;
        state.checkpoint.last_acked_seq = 5;
        state.last_head_seq = 5;
        SyncEngine::quarantine_record(&mut state, &sample_record("msg:4", 4));

        assert!(SyncEngine::next_fetch(&state).is_none());

        // A genuinely new record at the head still triggers a fetch.
        SyncEngine::register_head(&mut state, 6);
        let decision = SyncEngine::next_fetch(&state).expect("should fetch the new record");
        assert_eq!(decision.from_seq, 6);
        assert_eq!(decision.to_seq, 6);
    }

    #[test]
    fn quarantine_is_bounded_per_device_and_per_conversation() {
        let mut state = SyncEngine::new_device_state("device:bob:phone");

        // One conversation floods the buffer, as an adversary sending
        // future-epoch frames would.
        for seq in 1..=(MAX_QUARANTINED_RECORDS_PER_CONVERSATION as u64 * 4) {
            let record = sample_record(&format!("msg:{seq}"), seq);
            SyncEngine::quarantine_record(&mut state, &record);
        }
        assert_eq!(
            state.quarantine.len(),
            MAX_QUARANTINED_RECORDS_PER_CONVERSATION
        );
        // The newest arrivals are the ones kept: an out-of-order burst is
        // repaired by frames that arrive after the frame they repair.
        let lowest = *state.quarantine.keys().next().expect("non-empty");
        assert_eq!(
            lowest,
            MAX_QUARANTINED_RECORDS_PER_CONVERSATION as u64 * 4
                - MAX_QUARANTINED_RECORDS_PER_CONVERSATION as u64
                + 1
        );

        // Many conversations together respect the device-wide cap.
        let mut state = SyncEngine::new_device_state("device:bob:phone");
        let mut seq = 0_u64;
        for conversation in 0..40 {
            for _ in 0..8 {
                seq += 1;
                let mut record = sample_record(&format!("msg:{seq}"), seq);
                record.envelope.conversation_id = format!("conv:{conversation}");
                SyncEngine::quarantine_record(&mut state, &record);
            }
        }
        assert_eq!(state.quarantine.len(), MAX_QUARANTINED_RECORDS);
        assert!(SyncEngine::has_quarantine(&state));
    }

    #[test]
    fn releasing_the_last_record_empties_the_quarantine() {
        let mut state = SyncEngine::new_device_state("device:bob:phone");
        let record = sample_record("msg:1", 1);
        SyncEngine::quarantine_record(&mut state, &record);
        assert!(SyncEngine::has_quarantine(&state));

        SyncEngine::release_quarantined(&mut state, 1);

        assert!(!SyncEngine::has_quarantine(&state));
        assert!(state.quarantine.is_empty());
    }

    #[test]
    fn duplicate_fetch_and_replay_keep_checkpoint_monotonic() {
        let mut state = SyncEngine::new_device_state("device:bob:phone");
        let record = sample_record("msg:1", 4);

        let fresh = SyncEngine::select_fresh(&state, std::slice::from_ref(&record));
        assert_eq!(fresh.len(), 1);
        SyncEngine::commit_fetched_record(&mut state, &record);
        SyncEngine::quarantine_record(&mut state, &record);
        let ack = SyncEngine::ack_up_to(&mut state, 4);
        assert_eq!(ack.ack_seq, 4);

        let duplicate = SyncEngine::select_fresh(&state, std::slice::from_ref(&record));
        assert!(duplicate.is_empty());
        assert_eq!(state.checkpoint.last_fetched_seq, 4);
        assert_eq!(state.checkpoint.last_acked_seq, 4);

        SyncEngine::release_quarantined(&mut state, 4);
        assert_eq!(state.checkpoint.last_acked_seq, 4);
        assert_eq!(state.checkpoint.last_fetched_seq, 4);
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
                sender_proof: SenderProof {
                    proof_type: "signature".into(),
                    value: "proof".into(),
                },
            },
        }
    }
}

//! Reading the host this device moved away from.
//!
//! A move tells every contact the new address in a lane notice inside its
//! session, and until a contact applies that notice it keeps appending to the
//! old host. So the device reads the old host too, from the cursor it had
//! there, under the credential it held there, and with the inbound lanes it
//! used there. It stops once every conversation's peer has been seen at the
//! new host and the old one has nothing left to fetch, or after Δ, the bound
//! within which a contact is held to follow.
//!
//! The old host's records go through the ordinary inbound path under a sync
//! key of their own, so they have their own cursor, dedup set and quarantine.
//! They are never acknowledged there: the device leaves no state at that host
//! that it would have to clean up, and the records expire on their own.

use super::*;
use crate::direct_pcs::DIRECT_DELIVERY_BOUND_MS;
use crate::persistence::PreviousInbox;

/// Prefixes the sync key of the previous host's inbox. The current inbox is
/// keyed by the device id alone.
pub(crate) const PREVIOUS_INBOX_SYNC_PREFIX: &str = "previous:";

/// How often the previous host is read while it is drained: it has no push
/// channel.
pub(crate) const PREVIOUS_INBOX_POLL_MS: u64 = 5 * 60 * 1000;

pub(crate) fn previous_inbox_key(device_id: &str) -> String {
    format!("{PREVIOUS_INBOX_SYNC_PREFIX}{device_id}")
}

pub(crate) fn is_previous_inbox_key(key: &str) -> bool {
    key.starts_with(PREVIOUS_INBOX_SYNC_PREFIX)
}

/// The device an inbox's sync key names.
pub(crate) fn inbox_device_id(key: &str) -> &str {
    key.strip_prefix(PREVIOUS_INBOX_SYNC_PREFIX).unwrap_or(key)
}

/// Where the requests for one inbox go, and under which credential.
pub(super) struct InboxRoute {
    pub(super) http_endpoint: String,
    pub(super) device_id: String,
    pub(super) auth: TransportAuthRequirement,
}

impl CoreEngine {
    /// The endpoint, device id and credential of the inbox a sync key names.
    pub(super) fn inbox_route(&self, key: &str) -> CoreResult<InboxRoute> {
        let deployment = if is_previous_inbox_key(key) {
            self.state
                .previous_inbox
                .as_ref()
                .map(|previous| &previous.deployment_bundle)
                .ok_or_else(|| CoreError::invalid_state("no previous inbox is being read"))?
        } else {
            self.state
                .deployment_bundle
                .as_ref()
                .ok_or_else(|| CoreError::invalid_state("deployment bundle is not initialized"))?
        };
        let device_id = inbox_device_id(key).to_string();
        let http_endpoint = deployment.inbox_http_endpoint.trim_end_matches('/');
        Ok(InboxRoute {
            http_endpoint: http_endpoint.to_string(),
            auth: TransportAuthRequirement::DeviceRuntime {
                runtime_id: deployment.runtime_id.clone(),
                device_id: device_id.clone(),
            },
            device_id,
        })
    }

    /// Start reading the host this device is leaving, which `previous`
    /// describes. Called on a move, before the inbound lanes are replaced:
    /// the cursor and the lanes it keeps are the old host's.
    pub(super) fn begin_previous_inbox_drain(
        &mut self,
        previous: crate::model::DeploymentBundle,
        device_id: &str,
    ) -> Vec<PersistOp> {
        let key = previous_inbox_key(device_id);
        // A second move while the first is drained leaves the first host
        // behind: only the host just left is read.
        let cursor = self
            .state
            .sync_states
            .remove(device_id)
            .unwrap_or_else(|| SyncEngine::new_device_state(device_id));
        self.state.sync_states.insert(key.clone(), cursor);
        let fresh = SyncEngine::new_device_state(device_id);
        self.state.sync_states.insert(device_id.to_string(), fresh);
        self.state.pending_acks.remove(device_id);
        let mut lanes = BTreeMap::new();
        for (conversation_id, conversation) in &self.state.conversations {
            if conversation.conversation.kind != ConversationKind::Direct {
                continue;
            }
            if let Some(conversation_lanes) = conversation.lanes.as_ref() {
                lanes.insert(
                    conversation_lanes.inbound_lane.clone(),
                    conversation_id.clone(),
                );
            }
        }
        let awaiting = lanes.values().cloned().collect();
        self.state.previous_inbox = Some(PreviousInbox {
            deployment_bundle: previous,
            moved_at_ms: current_unix_millis(self.state.message_nonce),
            lanes,
            awaiting,
        });
        vec![
            PersistOp::SaveDeployment,
            PersistOp::SaveSyncState { device_id: key },
            PersistOp::SaveSyncState {
                device_id: device_id.to_string(),
            },
            PersistOp::DeletePendingAck {
                device_id: device_id.to_string(),
            },
        ]
    }

    /// Read the previous host once more, and schedule the next read, unless
    /// the drain is over.
    pub(super) fn drain_previous_inbox(&mut self) -> CoreResult<CoreOutput> {
        let Some(moved_at_ms) = self
            .state
            .previous_inbox
            .as_ref()
            .map(|previous| previous.moved_at_ms)
        else {
            return Ok(CoreOutput::default());
        };
        let now_ms = current_unix_millis(self.state.message_nonce);
        if now_ms.saturating_sub(moved_at_ms) >= DIRECT_DELIVERY_BOUND_MS {
            return Ok(self.end_previous_inbox_drain());
        }
        let device_id = self.local_device_id_required()?;
        let key = previous_inbox_key(&device_id);
        let InboxRoute {
            http_endpoint,
            device_id: inbox_device,
            auth,
        } = self.inbox_route(&key)?;
        let request_id = self.next_request_id(&format!("get_head:{key}"));
        self.state.pending_requests.insert(
            request_id.clone(),
            PendingRequest::GetHead {
                device_id: key.clone(),
            },
        );
        Ok(CoreOutput {
            state_update: CoreStateUpdate::default(),
            effects: vec![
                CoreEffect::ExecuteHttpRequest {
                    request: HttpRequestEffect {
                        request_id,
                        method: HttpMethod::Get,
                        url: format!("{http_endpoint}/v1/inbox/{inbox_device}/head"),
                        headers: BTreeMap::new(),
                        auth: Some(auth),
                        body: None,
                    },
                },
                CoreEffect::ScheduleTimer {
                    timer: TimerEffect {
                        timer_id: format!("sync:{key}"),
                        delay_ms: PREVIOUS_INBOX_POLL_MS,
                    },
                },
            ],
            view_model: None,
        })
    }

    /// Note that these conversations' peers have written to the current host,
    /// so they follow the move and stop writing to the old one.
    pub(super) fn note_peers_followed(&mut self, conversation_ids: &BTreeSet<String>) {
        if let Some(previous) = self.state.previous_inbox.as_mut() {
            previous
                .awaiting
                .retain(|conversation_id| !conversation_ids.contains(conversation_id));
        }
    }

    /// After a read of the previous host: end the drain if every peer has
    /// followed and the read reached the end of what the old host holds.
    pub(super) fn finish_previous_inbox_read(&mut self, key: &str) -> CoreOutput {
        let caught_up = self
            .state
            .sync_states
            .get(key)
            .is_none_or(|state| SyncEngine::next_fetch(state).is_none());
        let followed = self
            .state
            .previous_inbox
            .as_ref()
            .is_some_and(|previous| previous.awaiting.is_empty());
        if caught_up && followed {
            self.end_previous_inbox_drain()
        } else {
            CoreOutput::default()
        }
    }

    /// A record the previous host no longer holds can no longer be read: move
    /// the cursor past it. Unlike the current host, nothing is marked for
    /// recovery, since the move announced the new address in every session.
    pub(super) fn skip_previous_inbox_floor(&mut self, key: &str, history_floor_seq: u64) {
        let Some(sync_state) = self.state.sync_states.get_mut(key) else {
            return;
        };
        if history_floor_seq <= sync_state.checkpoint.last_fetched_seq {
            return;
        }
        sync_state.checkpoint.last_fetched_seq = history_floor_seq;
        sync_state.last_head_seq = sync_state.last_head_seq.max(history_floor_seq);
        sync_state
            .quarantine
            .retain(|seq, _| *seq > history_floor_seq);
        SyncEngine::ack_up_to(sync_state, history_floor_seq);
    }

    /// Stop reading the previous host.
    pub(super) fn end_previous_inbox_drain(&mut self) -> CoreOutput {
        if self.state.previous_inbox.take().is_none() {
            return CoreOutput::default();
        }
        let mut ops = vec![PersistOp::SaveDeployment];
        if let Ok(device_id) = self.local_device_id_required() {
            let key = previous_inbox_key(&device_id);
            self.state.sync_states.remove(&key);
            ops.push(PersistOp::DeleteSyncState { device_id: key });
        }
        CoreOutput {
            state_update: CoreStateUpdate {
                checkpoints_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(&self.state, ops)],
            view_model: None,
        }
    }

    /// Whether `lane` was `conversation_id`'s inbound lane at the host this
    /// device left and still reads.
    pub(super) fn is_previous_inbound_lane(&self, conversation_id: &str, lane: &str) -> bool {
        self.state
            .previous_inbox
            .as_ref()
            .and_then(|previous| previous.lanes.get(lane))
            .is_some_and(|owner| owner == conversation_id)
    }
}

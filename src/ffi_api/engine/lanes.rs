use super::*;
use crate::conversation::{ConversationLanes, LaneWrapCache};
use crate::lane_wrap::{self, WRAP_DIR_C1, WRAP_DIR_C2};
use crate::mls_adapter::{WelcomeAuthor, WelcomeInspection};
use crate::model::{is_opaque_id, random_opaque_id};
use base64::{engine::general_purpose::STANDARD, Engine as _};

impl CoreEngine {
    pub(super) fn rebuild_lane_index(&mut self) {
        self.state.lane_index.clear();
        for (conversation_id, conversation) in &self.state.conversations {
            if let Some(lanes) = &conversation.lanes {
                self.state
                    .lane_index
                    .insert(lanes.inbound_lane.clone(), conversation_id.clone());
                self.state
                    .lane_index
                    .insert(lanes.outbound_lane.clone(), conversation_id.clone());
            }
        }
    }

    pub(super) fn conversation_id_for_lane(&self, lane: &str) -> Option<String> {
        self.state.lane_index.get(lane).cloned().or_else(|| {
            self.state
                .conversations
                .iter()
                .find_map(|(id, conversation)| {
                    conversation.lanes.as_ref().and_then(|lanes| {
                        (lanes.inbound_lane == lane || lanes.outbound_lane == lane)
                            .then(|| id.clone())
                    })
                })
        })
    }

    pub(super) fn index_inbound_lane(&mut self, lane: &str, conversation_id: &str) {
        self.state
            .lane_index
            .insert(lane.to_string(), conversation_id.to_string());
    }

    pub(super) fn assign_initiator_lanes(
        &mut self,
        conversation_id: &str,
        outbound_c1: String,
        inbound_c2: String,
    ) {
        if let Some(conversation) = self.state.conversations.get_mut(conversation_id) {
            conversation.lanes = Some(ConversationLanes {
                inbound_lane: inbound_c2.clone(),
                outbound_lane: outbound_c1.clone(),
                outbound_dir: WRAP_DIR_C1,
                wrap_prev: None,
            });
        }
        self.index_inbound_lane(&inbound_c2, conversation_id);
        self.index_inbound_lane(&outbound_c1, conversation_id);
    }

    pub(super) fn assign_recipient_lanes(
        &mut self,
        conversation_id: &str,
        inbound_c1: String,
        outbound_c2: String,
    ) {
        if let Some(conversation) = self.state.conversations.get_mut(conversation_id) {
            conversation.lanes = Some(ConversationLanes {
                inbound_lane: inbound_c1.clone(),
                outbound_lane: outbound_c2.clone(),
                outbound_dir: WRAP_DIR_C2,
                wrap_prev: None,
            });
        }
        self.index_inbound_lane(&inbound_c1, conversation_id);
        self.index_inbound_lane(&outbound_c2, conversation_id);
    }

    pub(super) fn register_accepted_lane(&mut self, lane: String) -> CoreResult<CoreOutput> {
        if !is_opaque_id(&lane) {
            return Err(CoreError::invalid_input("lane must be a 128-bit hex id"));
        }
        let device_id = self.local_device_id_required()?;
        Ok(CoreOutput {
            state_update: CoreStateUpdate::default(),
            effects: vec![CoreEffect::RegisterAcceptedLane {
                register: RegisterAcceptedLaneRequest {
                    device_id,
                    lane,
                    endpoint: self.inbox_management_endpoint("accepted-lanes")?,
                    headers: BTreeMap::new(),
                    auth: Some(self.device_runtime_auth_requirement()?),
                },
            }],
            view_model: None,
        })
    }

    pub(super) fn revoke_contact_lanes(&mut self, user_id: String) -> CoreResult<CoreOutput> {
        let device_id = self.local_device_id_required()?;
        let lanes = self
            .state
            .conversations
            .values()
            .filter(|conversation| conversation.peer_user_id == user_id)
            .filter_map(|conversation| conversation.lanes.as_ref())
            .map(|lanes| lanes.inbound_lane.clone())
            .collect::<BTreeSet<_>>();
        if lanes.is_empty() {
            return Ok(CoreOutput::default());
        }
        Ok(CoreOutput {
            state_update: CoreStateUpdate::default(),
            effects: vec![CoreEffect::RevokeAcceptedLanes {
                revoke: RevokeAcceptedLanesRequest {
                    device_id,
                    lanes: lanes.into_iter().collect(),
                    endpoint: self.inbox_management_endpoint("accepted-lanes")?,
                    headers: BTreeMap::new(),
                    auth: Some(self.device_runtime_auth_requirement()?),
                },
            }],
            view_model: None,
        })
    }

    pub(super) fn snapshot_wrap_prev(&mut self, conversation_id: &str) -> CoreResult<()> {
        let Some(inbound_dir) = self
            .state
            .conversations
            .get(conversation_id)
            .and_then(|conversation| conversation.lanes.as_ref())
            .map(|lanes| lanes.inbound_dir())
        else {
            return Ok(());
        };
        let adapter = self
            .state
            .mls_adapter
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?;
        if !adapter.has_conversation(conversation_id) {
            return Ok(());
        }
        let outbound_dir = self
            .state
            .conversations
            .get(conversation_id)
            .and_then(|conversation| conversation.lanes.as_ref())
            .map(|lanes| lanes.outbound_dir)
            .unwrap_or(WRAP_DIR_C1);
        let epoch = adapter.export_group_summary(conversation_id)?.epoch;
        let key = adapter.export_lane_wrap_key(conversation_id, inbound_dir)?;
        let outbound_key = adapter.export_lane_wrap_key(conversation_id, outbound_dir)?;
        if let Some(lanes) = self
            .state
            .conversations
            .get_mut(conversation_id)
            .and_then(|conversation| conversation.lanes.as_mut())
        {
            lanes.wrap_prev = Some(LaneWrapCache {
                epoch,
                key,
                outbound_key: Some(outbound_key),
            });
        }
        Ok(())
    }

    pub(super) fn export_outbound_wrap_key(
        &self,
        conversation_id: &str,
    ) -> CoreResult<[u8; lane_wrap::WRAP_KEY_LEN]> {
        let dir = self
            .state
            .conversations
            .get(conversation_id)
            .and_then(|conversation| conversation.lanes.as_ref())
            .map(|lanes| lanes.outbound_dir)
            .unwrap_or(WRAP_DIR_C1);
        let adapter = self
            .state
            .mls_adapter
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?;
        adapter.export_lane_wrap_key(conversation_id, dir)
    }

    pub(super) fn unwrap_inbound_bytes(
        &self,
        conversation_id: &str,
        payload_b64: &str,
    ) -> Option<String> {
        let lanes = self
            .state
            .conversations
            .get(conversation_id)
            .and_then(|conversation| conversation.lanes.as_ref())?;
        let adapter = self.state.mls_adapter.as_ref()?;
        if !adapter.has_conversation(conversation_id) {
            return None;
        }
        let current = adapter
            .export_lane_wrap_key(conversation_id, lanes.inbound_dir())
            .ok()?;
        let previous = lanes.wrap_prev.as_ref().map(|cache| &cache.key);
        let wrapped = STANDARD.decode(payload_b64).ok()?;
        let frame = lane_wrap::unwrap_with_cached_keys(&current, previous, &wrapped)?;
        Some(STANDARD.encode(frame))
    }

    pub(super) fn wrap_frame_b64(
        key: &[u8; lane_wrap::WRAP_KEY_LEN],
        payload_b64: &str,
    ) -> CoreResult<String> {
        let frame = STANDARD.decode(payload_b64).map_err(|error| {
            CoreError::invalid_input(format!("outbound MLS frame is not base64: {error}"))
        })?;
        let wrapped = lane_wrap::wrap_frame(key, &frame)?;
        Ok(STANDARD.encode(wrapped))
    }

    pub(super) fn resolve_inbound_frame(
        &mut self,
        local_user_id: &str,
        device_id: &str,
        record: &InboxRecord,
    ) -> CoreResult<Option<ResolvedInbound>> {
        let payload_b64 = record.envelope.payload_b64().unwrap_or_default();
        if let Some(conversation_id) = self.conversation_id_for_lane(&record.envelope.lane) {
            if let Some(unwrapped) = self.unwrap_inbound_bytes(&conversation_id, payload_b64) {
                let Some(message_type) = MlsAdapter::classify_mls_payload(&unwrapped) else {
                    return Ok(None);
                };
                let peer_user_id = self
                    .state
                    .conversations
                    .get(&conversation_id)
                    .map(|conversation| conversation.peer_user_id.clone())
                    .unwrap_or_default();
                return Ok(Some(ResolvedInbound {
                    conversation_id,
                    peer_user_id,
                    message_type,
                    payload_b64: unwrapped,
                    welcome_author: None,
                }));
            }
            if MlsAdapter::payload_is_welcome(payload_b64) {
                return self.resolve_welcome_frame(local_user_id, device_id, record, payload_b64);
            }
            return Ok(None);
        }
        if MlsAdapter::payload_is_welcome(payload_b64) {
            return self.resolve_welcome_frame(local_user_id, device_id, record, payload_b64);
        }
        Ok(None)
    }

    fn resolve_welcome_frame(
        &mut self,
        local_user_id: &str,
        device_id: &str,
        record: &InboxRecord,
        payload_b64: &str,
    ) -> CoreResult<Option<ResolvedInbound>> {
        let Some(adapter) = self.state.mls_adapter.as_ref() else {
            return Ok(None);
        };
        let Some(inspection) = adapter.inspect_welcome(payload_b64) else {
            return Ok(None);
        };
        let Ok(author) = self.trusted_welcome_author(&inspection) else {
            return Ok(None);
        };
        if !self
            .state
            .conversations
            .contains_key(&inspection.conversation_id)
        {
            let mut local = ConversationManager::create_direct_conversation_with_id(
                inspection.conversation_id.clone(),
                local_user_id,
                device_id,
                &inspection.author_user_id,
                &[inspection.author_device_id.clone()],
            )?;
            local.conversation.updated_at = record.received_at;
            self.state
                .conversations
                .insert(inspection.conversation_id.clone(), local);
        }
        let reply_lane = self
            .state
            .mls_adapter
            .as_ref()
            .and_then(|adapter| adapter.reply_lane_from_group(&inspection.conversation_id))
            .filter(|lane| is_opaque_id(lane));
        // reply_lane is inside the Welcome; we only learn it after ingest.
        // Recipient lanes are assigned after AppliedWelcome.
        let _ = reply_lane;
        self.index_inbound_lane(&record.envelope.lane, &inspection.conversation_id);
        Ok(Some(ResolvedInbound {
            conversation_id: inspection.conversation_id,
            peer_user_id: inspection.author_user_id,
            message_type: MessageType::MlsWelcome,
            payload_b64: payload_b64.to_string(),
            welcome_author: Some(author),
        }))
    }

    pub(super) fn adopt_welcome_lanes(
        &mut self,
        conversation_id: &str,
        inbound_lane: &str,
    ) -> Option<String> {
        let reply = self
            .state
            .mls_adapter
            .as_ref()
            .and_then(|adapter| adapter.reply_lane_from_group(conversation_id))?;
        if !is_opaque_id(&reply) {
            return None;
        }
        self.assign_recipient_lanes(conversation_id, inbound_lane.to_string(), reply.clone());
        Some(reply)
    }

    pub(super) fn trusted_welcome_author(
        &self,
        inspection: &WelcomeInspection,
    ) -> CoreResult<WelcomeAuthor> {
        let device_public_key = self
            .trusted_device_public_key(&inspection.author_user_id, &inspection.author_device_id)?;
        Ok(WelcomeAuthor {
            device_id: inspection.author_device_id.clone(),
            device_public_key,
        })
    }

    pub(super) fn preview_welcome(&self, welcome_bytes: String) -> CoreResult<CoreOutput> {
        let adapter = self
            .state
            .mls_adapter
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?;
        let inspection = adapter
            .inspect_welcome(&welcome_bytes)
            .ok_or_else(|| CoreError::invalid_input("welcome could not be inspected"))?;
        Ok(CoreOutput {
            state_update: CoreStateUpdate::default(),
            effects: Vec::new(),
            view_model: Some(CoreViewModel {
                welcome_preview: Some(crate::ffi_api::WelcomePreview {
                    conversation_id: inspection.conversation_id,
                    author_user_id: inspection.author_user_id,
                    author_device_id: inspection.author_device_id,
                    identity_bundle_ref: inspection.identity_bundle_ref,
                }),
                ..CoreViewModel::default()
            }),
        })
    }
}

pub(super) struct ResolvedInbound {
    pub conversation_id: String,
    pub peer_user_id: String,
    pub message_type: MessageType,
    pub payload_b64: String,
    pub welcome_author: Option<WelcomeAuthor>,
}

pub(super) fn new_lane_pair() -> (String, String) {
    let first = random_opaque_id();
    let mut second = random_opaque_id();
    while second == first {
        second = random_opaque_id();
    }
    (first, second)
}

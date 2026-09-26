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

    pub(super) fn replace_inbound_lane(
        &mut self,
        conversation_id: &str,
        new_inbound: String,
    ) -> CoreResult<()> {
        if !is_opaque_id(&new_inbound) {
            return Err(CoreError::invalid_input("lane must be a 128-bit hex id"));
        }
        let old_inbound = self
            .state
            .conversations
            .get(conversation_id)
            .and_then(|conversation| conversation.lanes.as_ref())
            .map(|lanes| lanes.inbound_lane.clone())
            .ok_or_else(|| CoreError::invalid_state("conversation has no inbound lane"))?;
        if old_inbound == new_inbound {
            return Ok(());
        }
        if let Some(lanes) = self
            .state
            .conversations
            .get_mut(conversation_id)
            .and_then(|conversation| conversation.lanes.as_mut())
        {
            lanes.inbound_lane = new_inbound.clone();
        }
        self.state.lane_index.remove(&old_inbound);
        self.index_inbound_lane(&new_inbound, conversation_id);
        Ok(())
    }

    pub(super) fn switch_outbound_lane(
        &mut self,
        conversation_id: &str,
        new_outbound: String,
    ) -> CoreResult<()> {
        if !is_opaque_id(&new_outbound) {
            return Err(CoreError::invalid_input("lane must be a 128-bit hex id"));
        }
        let old_outbound = self
            .state
            .conversations
            .get(conversation_id)
            .and_then(|conversation| conversation.lanes.as_ref())
            .map(|lanes| lanes.outbound_lane.clone())
            .ok_or_else(|| CoreError::invalid_state("conversation has no outbound lane"))?;
        if old_outbound == new_outbound {
            return Ok(());
        }
        if let Some(lanes) = self
            .state
            .conversations
            .get_mut(conversation_id)
            .and_then(|conversation| conversation.lanes.as_mut())
        {
            lanes.outbound_lane = new_outbound.clone();
        }
        self.state.lane_index.remove(&old_outbound);
        self.index_inbound_lane(&new_outbound, conversation_id);
        Ok(())
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

    pub(super) fn capture_previous_inbound_wrap(
        &self,
        conversation_id: &str,
    ) -> CoreResult<Option<LaneWrapCache>> {
        let Some(inbound_dir) = self
            .state
            .conversations
            .get(conversation_id)
            .and_then(|conversation| conversation.lanes.as_ref())
            .map(|lanes| lanes.inbound_dir())
        else {
            return Ok(None);
        };
        let adapter = self
            .state
            .mls_adapter
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?;
        if !adapter.has_conversation(conversation_id) {
            return Ok(None);
        }
        let epoch = adapter.export_group_summary(conversation_id)?.epoch;
        let key = adapter.export_lane_wrap_key(conversation_id, inbound_dir)?;
        let commit_key = adapter.export_commit_wrap_key(conversation_id, inbound_dir)?;
        Ok(Some(LaneWrapCache {
            epoch,
            key,
            commit_key: Some(commit_key),
        }))
    }

    pub(super) fn install_previous_inbound_wrap(
        &mut self,
        conversation_id: &str,
        previous: Option<LaneWrapCache>,
    ) {
        let Some(previous) = previous else {
            return;
        };
        if let Some(lanes) = self
            .state
            .conversations
            .get_mut(conversation_id)
            .and_then(|conversation| conversation.lanes.as_mut())
        {
            lanes.wrap_prev = Some(previous);
        }
    }

    /// `K_c(e, outbound)` for the current epoch: what a commit made from it
    /// has to travel under, exported before the commit moves the group on.
    pub(super) fn export_outbound_commit_wrap_key(
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
        adapter.export_commit_wrap_key(conversation_id, dir)
    }

    /// The frame under one of the current or previous epoch's keys, the key
    /// that opened it, and which of the epoch's two keys that was.
    fn open_inbound_frame(
        &self,
        conversation_id: &str,
        payload_b64: &str,
    ) -> Option<(Vec<u8>, [u8; lane_wrap::WRAP_KEY_LEN], WrapKind)> {
        let lanes = self
            .state
            .conversations
            .get(conversation_id)
            .and_then(|conversation| conversation.lanes.as_ref())?;
        let adapter = self.state.mls_adapter.as_ref()?;
        if !adapter.has_conversation(conversation_id) {
            return None;
        }
        let dir = lanes.inbound_dir();
        let current = adapter.export_lane_wrap_key(conversation_id, dir).ok()?;
        let current_commit = adapter.export_commit_wrap_key(conversation_id, dir).ok()?;
        let previous = lanes.wrap_prev.as_ref();
        let wrapped = STANDARD.decode(payload_b64).ok()?;
        [
            Some((current, WrapKind::Frame)),
            Some((current_commit, WrapKind::Commit)),
            previous.map(|cache| (cache.key, WrapKind::Frame)),
            previous
                .and_then(|cache| cache.commit_key)
                .map(|key| (key, WrapKind::Commit)),
        ]
        .into_iter()
        .flatten()
        .find_map(|(key, kind)| {
            lane_wrap::unwrap_frame(&key, &wrapped).map(|frame| (frame, key, kind))
        })
    }

    /// The frame under the base-epoch key of a peer commit this device merged.
    /// Only ever consulted for fork evidence; see [`crate::direct_fork`].
    fn open_under_witness_keys(
        &self,
        conversation_id: &str,
        payload_b64: &str,
    ) -> Option<(Vec<u8>, [u8; lane_wrap::WRAP_KEY_LEN])> {
        let conversation = self.state.conversations.get(conversation_id)?;
        let mut keys = conversation.fork.wrap_keys().peekable();
        keys.peek()?;
        let wrapped = STANDARD.decode(payload_b64).ok()?;
        keys.find_map(|key| lane_wrap::unwrap_frame(key, &wrapped).map(|frame| (frame, *key)))
    }

    fn unwrap_inbound_plaintext(
        &self,
        conversation_id: &str,
        payload_b64: &str,
    ) -> Option<Vec<u8>> {
        self.open_inbound_frame(conversation_id, payload_b64)
            .map(|(frame, _, _)| frame)
    }

    pub(crate) fn unwrap_inbound_bytes(
        &self,
        conversation_id: &str,
        payload_b64: &str,
    ) -> Option<String> {
        let plaintext = self.unwrap_inbound_plaintext(conversation_id, payload_b64)?;
        crate::direct_frame::decode(&plaintext)
            .ok()
            .map(|(mls_b64, _)| mls_b64)
    }

    pub(super) fn resolve_inbound_frame(
        &self,
        record: &InboxRecord,
    ) -> CoreResult<InboundFrameResolution> {
        let payload_b64 = record.envelope.payload_b64().unwrap_or_default();
        if let Some(conversation_id) = self.conversation_id_for_lane(&record.envelope.lane) {
            let opened = self.open_inbound_frame(&conversation_id, payload_b64);
            let evidence = match opened.as_ref() {
                Some((frame, key, _)) => self.double_sign_evidence(&conversation_id, frame, key),
                None => self
                    .open_under_witness_keys(&conversation_id, payload_b64)
                    .and_then(|(frame, key)| {
                        self.double_sign_evidence(&conversation_id, &frame, &key)
                    }),
            };
            if let Some(forked_since_ms) = evidence {
                return Ok(InboundFrameResolution::Forked {
                    conversation_id,
                    forked_since_ms,
                });
            }
            let opened = opened
                .or_else(|| self.open_under_expected_rebuild_key(&conversation_id, payload_b64));
            if let Some((plaintext, key, kind)) = opened {
                let Ok((mls_b64, commit_signature)) = crate::direct_frame::decode(&plaintext)
                else {
                    return Ok(InboundFrameResolution::Rejected);
                };
                let Some(message_type) = MlsAdapter::classify_mls_payload(&mls_b64) else {
                    return Ok(InboundFrameResolution::Rejected);
                };
                // A Welcome inside the wrap is a race loser's rebuild; whether
                // this is the one expected is decided by the key alone.
                if message_type == MessageType::MlsWelcome {
                    if commit_signature.is_some() {
                        return Ok(InboundFrameResolution::Rejected);
                    }
                    return self.resolve_welcome_frame(
                        Some(&conversation_id),
                        &mls_b64,
                        Some(&key),
                    );
                }
                // The key a frame opened under is part of what it claims to
                // be: a commit under the frame key, or anything else under
                // the commit key, does not match its own wrapping.
                if (message_type == MessageType::MlsCommit) != (kind == WrapKind::Commit) {
                    return Ok(InboundFrameResolution::Rejected);
                }
                let authenticated_commit = match message_type {
                    MessageType::MlsCommit => {
                        let Some(commit) = self.authenticate_direct_commit(
                            &conversation_id,
                            &mls_b64,
                            commit_signature.as_ref(),
                            key,
                        ) else {
                            return Ok(InboundFrameResolution::Rejected);
                        };
                        Some(commit)
                    }
                    // A signature on anything but a commit is a frame whose
                    // shape does not match what it claims to be.
                    _ if commit_signature.is_some() => {
                        return Ok(InboundFrameResolution::Rejected);
                    }
                    _ => None,
                };
                let peer_user_id = self
                    .state
                    .conversations
                    .get(&conversation_id)
                    .map(|conversation| conversation.peer_user_id.clone())
                    .unwrap_or_default();
                return Ok(InboundFrameResolution::Ready(ResolvedInbound {
                    conversation_id,
                    peer_user_id,
                    message_type,
                    payload_b64: mls_b64,
                    welcome_author: None,
                    authenticated_commit,
                }));
            }
            if MlsAdapter::payload_is_welcome(payload_b64) {
                return self.resolve_welcome_frame(Some(&conversation_id), payload_b64, None);
            }
            return Ok(InboundFrameResolution::Deferred);
        }
        if MlsAdapter::payload_is_welcome(payload_b64) {
            return self.resolve_welcome_frame(None, payload_b64, None);
        }
        Ok(InboundFrameResolution::Deferred)
    }

    /// A frame under the key a race loser's rebuild Welcome is expected
    /// under. Consulted only once the session's own keys have failed.
    fn open_under_expected_rebuild_key(
        &self,
        conversation_id: &str,
        payload_b64: &str,
    ) -> Option<(Vec<u8>, [u8; lane_wrap::WRAP_KEY_LEN], WrapKind)> {
        let key = *self
            .state
            .conversations
            .get(conversation_id)?
            .rebuild
            .expected_key()?;
        let wrapped = STANDARD.decode(payload_b64).ok()?;
        lane_wrap::unwrap_frame(&key, &wrapped).map(|frame| (frame, key, WrapKind::Commit))
    }

    /// Admit a Welcome. For a conversation this device already holds, see
    /// [`crate::direct_rebuild`]: the author's device key is not enough, since
    /// it outlives the peer's healing. `lane_conversation` is the conversation
    /// of the pairwise address the record arrived on, and `wrapped_under` the
    /// key a wrapped Welcome opened under.
    fn resolve_welcome_frame(
        &self,
        lane_conversation: Option<&str>,
        payload_b64: &str,
        wrapped_under: Option<&[u8; lane_wrap::WRAP_KEY_LEN]>,
    ) -> CoreResult<InboundFrameResolution> {
        let Some(adapter) = self.state.mls_adapter.as_ref() else {
            return Ok(InboundFrameResolution::Rejected);
        };
        let Some(inspection) = adapter.inspect_welcome(payload_b64) else {
            return Ok(InboundFrameResolution::Rejected);
        };
        let Ok(author) = self.trusted_welcome_author(&inspection) else {
            return Ok(InboundFrameResolution::Rejected);
        };
        // A Welcome speaks for the conversation whose address it came on.
        if lane_conversation.is_some_and(|lane| lane != inspection.conversation_id) {
            return Ok(InboundFrameResolution::Rejected);
        }
        if let Some(existing) = self.state.conversations.get(&inspection.conversation_id) {
            let now_ms = current_unix_millis(self.state.message_nonce);
            let admitted = existing.peer_user_id == inspection.author_user_id
                && existing.conversation.state != ConversationState::Compromised
                && match wrapped_under {
                    Some(key) => existing
                        .rebuild
                        .admits_wrapped(key, &author.device_id, now_ms),
                    None => existing.rebuild.awaits_peer_welcome,
                };
            if !admitted {
                return Ok(InboundFrameResolution::Rejected);
            }
        } else if wrapped_under.is_some() {
            return Ok(InboundFrameResolution::Rejected);
        }
        Ok(InboundFrameResolution::Ready(ResolvedInbound {
            conversation_id: inspection.conversation_id,
            peer_user_id: inspection.author_user_id,
            message_type: MessageType::MlsWelcome,
            payload_b64: payload_b64.to_string(),
            welcome_author: Some(author),
            authenticated_commit: None,
        }))
    }

    /// Whether `frame`, opened under `key`, is a second commit signed by the
    /// device whose commit this device merged at the same base epoch.
    ///
    /// The key scopes the comparison to one epoch of one incarnation of the
    /// group, so no epoch check against local MLS state is needed -- and none
    /// is possible, since that state has moved on. The signature is checked
    /// against the device key the identity chain vouches for rather than the
    /// member leaf: after a fork the leaf in the local group is whatever the
    /// forged commit put there. Returns when the contradicted commit merged.
    fn double_sign_evidence(
        &self,
        conversation_id: &str,
        frame: &[u8],
        key: &[u8; lane_wrap::WRAP_KEY_LEN],
    ) -> Option<u64> {
        let conversation = self.state.conversations.get(conversation_id)?;
        if conversation.fork.forked_since_ms.is_some() {
            return None;
        }
        let witness = conversation.fork.witness_for_key(key)?;
        let (mls_b64, Some(signature)) = crate::direct_frame::decode(frame).ok()? else {
            return None;
        };
        if MlsAdapter::classify_mls_payload(&mls_b64) != Some(MessageType::MlsCommit) {
            return None;
        }
        let base_epoch = MlsAdapter::protocol_message_epoch(&mls_b64).ok()?;
        let digest = crate::direct_frame::commit_sha256(&mls_b64).ok()?;
        let commit_hash = crate::direct_frame::commit_hash(&digest);
        if !crate::direct_fork::ForkGuard::contradicts(witness, base_epoch, &commit_hash) {
            return None;
        }
        let peer_user_id = &conversation.peer_user_id;
        let trusted_key = self
            .trusted_device_public_key(peer_user_id, &witness.device_id)
            .ok()?;
        crate::identity::verify_device_payload_signature(
            &trusted_key,
            crate::model::signing::direct_commit_arbitration_payload(
                conversation_id,
                peer_user_id,
                &witness.device_id,
                base_epoch,
                &digest,
            ),
            &crate::identity::encode_hex(&signature),
        )
        .ok()?;
        Some(if witness.received_at_ms > 0 {
            witness.received_at_ms
        } else {
            witness.merged_at_ms
        })
    }

    /// Establish that a rival commit really came from the counterparty.
    ///
    /// MLS cannot say so: by now the local group has merged its own commit for
    /// the same epoch, and a handshake message for a superseded epoch is
    /// refused against the current group context before it is ever decrypted.
    /// Without this the frame would only have to be a syntactically valid
    /// commit at the right epoch, so a stale wrap key would be enough to force
    /// a rebuild.
    ///
    /// The signature names no one on the wire. A two-party conversation has
    /// one counterparty, so the candidates are its devices; each is accepted
    /// only where the MLS member leaf key and the device key the identity
    /// chain vouches for are the same key, which is the R0 invariant.
    fn authenticate_direct_commit(
        &self,
        conversation_id: &str,
        payload_b64: &str,
        signature: Option<&[u8; crate::direct_frame::COMMIT_SIGNATURE_LEN]>,
        wrap_key: [u8; lane_wrap::WRAP_KEY_LEN],
    ) -> Option<crate::direct_frame::AuthenticatedDirectCommit> {
        let signature_hex = crate::identity::encode_hex(signature?);
        let conversation = self.state.conversations.get(conversation_id)?;
        let peer_user_id = conversation.peer_user_id.clone();
        let base_epoch = MlsAdapter::protocol_message_epoch(payload_b64).ok()?;
        let digest = crate::direct_frame::commit_sha256(payload_b64).ok()?;
        let adapter = self.state.mls_adapter.as_ref()?;

        let candidates = adapter
            .member_device_ids_for_user(conversation_id, &peer_user_id)
            .ok()?;
        for device_id in candidates {
            let Ok(trusted_key) = self.trusted_device_public_key(&peer_user_id, &device_id) else {
                continue;
            };
            let Ok(member_key) =
                adapter.member_signature_key(conversation_id, &peer_user_id, &device_id)
            else {
                continue;
            };
            if member_key != trusted_key {
                continue;
            }
            if crate::identity::verify_device_payload_signature(
                &trusted_key,
                crate::model::signing::direct_commit_arbitration_payload(
                    conversation_id,
                    &peer_user_id,
                    &device_id,
                    base_epoch,
                    &digest,
                ),
                &signature_hex,
            )
            .is_ok()
            {
                return Some(crate::direct_frame::AuthenticatedDirectCommit {
                    base_epoch,
                    commit_hash: crate::direct_frame::commit_hash(&digest),
                    device_id,
                    wrap_key,
                });
            }
        }
        None
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
    pub authenticated_commit: Option<crate::direct_frame::AuthenticatedDirectCommit>,
}

/// Which of an epoch's two wrap keys opened a frame; see `lane_wrap`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WrapKind {
    Frame,
    Commit,
}

pub(super) enum InboundFrameResolution {
    Ready(ResolvedInbound),
    Deferred,
    Rejected,
    /// The counterparty's device key signed two commits on one base epoch.
    Forked {
        conversation_id: String,
        forked_since_ms: u64,
    },
}

pub(super) fn new_lane_pair() -> (String, String) {
    let first = random_opaque_id();
    let mut second = random_opaque_id();
    while second == first {
        second = random_opaque_id();
    }
    (first, second)
}

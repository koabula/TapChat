use crate::error::{CoreError, CoreResult};
use crate::model::{
    Conversation, ConversationKind, ConversationMember, ConversationState, DeviceStatusKind,
    Envelope, MessageType,
};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConversationModule;

impl ConversationModule {
    pub fn name(&self) -> &'static str {
        "conversation"
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMessage {
    pub message_id: String,
    pub sender_device_id: String,
    pub recipient_device_id: String,
    pub message_type: MessageType,
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalConversationState {
    pub conversation: Conversation,
    pub messages: Vec<StoredMessage>,
    pub last_message_type: Option<MessageType>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ConversationManager;

impl ConversationManager {
    pub fn create_direct_conversation(
        local_user_id: &str,
        local_device_id: &str,
        peer_user_id: &str,
        peer_device_ids: &[String],
    ) -> CoreResult<LocalConversationState> {
        if local_user_id.trim().is_empty() || local_device_id.trim().is_empty() {
            return Err(CoreError::invalid_input(
                "local identity must be available before creating a conversation",
            ));
        }
        if peer_user_id.trim().is_empty() {
            return Err(CoreError::invalid_input("peer_user_id must not be empty"));
        }
        if peer_device_ids.is_empty() {
            return Err(CoreError::invalid_input(
                "peer conversation must contain at least one active device",
            ));
        }

        let conversation_id = build_direct_conversation_id(local_user_id, peer_user_id);
        let mut member_users = vec![local_user_id.to_string(), peer_user_id.to_string()];
        member_users.sort();
        member_users.dedup();

        let mut member_devices = vec![ConversationMember {
            user_id: local_user_id.to_string(),
            device_id: local_device_id.to_string(),
            status: DeviceStatusKind::Active,
        }];
        for peer_device_id in peer_device_ids {
            member_devices.push(ConversationMember {
                user_id: peer_user_id.to_string(),
                device_id: peer_device_id.clone(),
                status: DeviceStatusKind::Active,
            });
        }

        Ok(LocalConversationState {
            conversation: Conversation {
                conversation_id,
                kind: ConversationKind::Direct,
                member_users,
                member_devices,
                state: ConversationState::Active,
                updated_at: 0,
            },
            messages: Vec::new(),
            last_message_type: None,
        })
    }

    pub fn apply_incoming_envelope(
        state: &mut LocalConversationState,
        envelope: &Envelope,
    ) -> CoreResult<AppliedEnvelopeEffect> {
        if envelope.conversation_id != state.conversation.conversation_id {
            return Err(CoreError::invalid_input(
                "incoming envelope conversation_id does not match local conversation",
            ));
        }

        state.messages.push(StoredMessage {
            message_id: envelope.message_id.clone(),
            sender_device_id: envelope.sender_device_id.clone(),
            recipient_device_id: envelope.recipient_device_id.clone(),
            message_type: envelope.message_type,
            created_at: envelope.created_at,
        });
        state.last_message_type = Some(envelope.message_type);
        state.conversation.updated_at = envelope.created_at;

        let mut effect = AppliedEnvelopeEffect::default();
        match envelope.message_type {
            MessageType::ControlConversationNeedsRebuild => {
                state.conversation.state = ConversationState::NeedsRebuild;
                effect.needs_rebuild = true;
            }
            MessageType::ControlDeviceMembershipChanged
            | MessageType::ControlIdentityStateUpdated => {
                effect.identity_refresh_needed = true;
            }
            _ => {}
        }

        Ok(effect)
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AppliedEnvelopeEffect {
    pub identity_refresh_needed: bool,
    pub needs_rebuild: bool,
}

fn build_direct_conversation_id(a: &str, b: &str) -> String {
    let mut parts = [a.to_string(), b.to_string()];
    parts.sort();
    format!("conv:{}:{}", parts[0], parts[1])
}

#[cfg(test)]
mod tests {
    use super::{ConversationManager, ConversationModule};
    use crate::model::{Envelope, MessageType, SenderProof};

    #[test]
    fn module_name_is_stable() {
        assert_eq!(ConversationModule.name(), "conversation");
    }

    #[test]
    fn direct_conversation_includes_local_and_peer_devices() {
        let state = ConversationManager::create_direct_conversation(
            "user:alice",
            "device:alice:phone",
            "user:bob",
            &["device:bob:phone".into(), "device:bob:laptop".into()],
        )
        .expect("conversation should be created");

        assert_eq!(state.conversation.kind, crate::model::ConversationKind::Direct);
        assert_eq!(state.conversation.member_devices.len(), 3);
    }

    #[test]
    fn control_needs_rebuild_updates_conversation_state() {
        let mut state = ConversationManager::create_direct_conversation(
            "user:alice",
            "device:alice:phone",
            "user:bob",
            &["device:bob:phone".into()],
        )
        .expect("conversation should be created");
        let conversation_id = state.conversation.conversation_id.clone();
        let effect = ConversationManager::apply_incoming_envelope(
            &mut state,
            &Envelope {
                version: crate::model::CURRENT_MODEL_VERSION.to_string(),
                message_id: "msg:1".into(),
                conversation_id,
                sender_user_id: "user:bob".into(),
                sender_device_id: "device:bob:phone".into(),
                recipient_device_id: "device:alice:phone".into(),
                created_at: 1,
                message_type: MessageType::ControlConversationNeedsRebuild,
                inline_ciphertext: Some("cipher".into()),
                storage_refs: vec![],
                sender_proof: SenderProof {
                    proof_type: "signature".into(),
                    value: "proof".into(),
                },
            },
        )
        .expect("apply should succeed");

        assert!(effect.needs_rebuild);
        assert_eq!(
            state.conversation.state,
            crate::model::ConversationState::NeedsRebuild
        );
    }
}

use std::collections::BTreeSet;

use crate::error::{CoreError, CoreResult};
use crate::model::{
    Conversation, ConversationKind, ConversationMember, ConversationState, DeviceStatusKind,
    Envelope, MessageType,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConversationModule;

impl ConversationModule {
    pub fn name(&self) -> &'static str {
        "conversation"
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredMessage {
    pub message_id: String,
    pub sender_device_id: String,
    pub recipient_device_id: String,
    pub message_type: MessageType,
    pub created_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryStatus {
    Healthy,
    NeedsRecovery,
    NeedsRebuild,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalConversationState {
    pub conversation: Conversation,
    pub messages: Vec<StoredMessage>,
    pub last_message_type: Option<MessageType>,
    pub peer_user_id: String,
    pub last_known_peer_active_devices: BTreeSet<String>,
    pub recovery_status: RecoveryStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileMembershipInput<'a> {
    pub local_user_id: &'a str,
    pub local_device_id: &'a str,
    pub peer_user_id: &'a str,
    pub peer_active_device_ids: &'a [String],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileMembershipResult {
    pub changed: bool,
    pub added_devices: Vec<String>,
    pub revoked_devices: Vec<String>,
    pub member_devices: Vec<ConversationMember>,
    pub should_mark_recovery: bool,
    pub should_mark_rebuild: bool,
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

        let reconcile = Self::reconcile_direct_membership(
            None,
            ReconcileMembershipInput {
                local_user_id,
                local_device_id,
                peer_user_id,
                peer_active_device_ids: peer_device_ids,
            },
        )?;
        let conversation_id = build_direct_conversation_id(local_user_id, peer_user_id);
        let mut member_users = vec![local_user_id.to_string(), peer_user_id.to_string()];
        member_users.sort();
        member_users.dedup();

        Ok(LocalConversationState {
            conversation: Conversation {
                conversation_id,
                kind: ConversationKind::Direct,
                member_users,
                member_devices: reconcile.member_devices,
                state: ConversationState::Active,
                updated_at: 0,
            },
            messages: Vec::new(),
            last_message_type: None,
            peer_user_id: peer_user_id.to_string(),
            last_known_peer_active_devices: peer_device_ids.iter().cloned().collect(),
            recovery_status: RecoveryStatus::Healthy,
        })
    }

    pub fn reconcile_direct_membership(
        state: Option<&LocalConversationState>,
        input: ReconcileMembershipInput<'_>,
    ) -> CoreResult<ReconcileMembershipResult> {
        if input.local_user_id.trim().is_empty() || input.local_device_id.trim().is_empty() {
            return Err(CoreError::invalid_input(
                "local identity must be available before reconciling a conversation",
            ));
        }
        if input.peer_user_id.trim().is_empty() {
            return Err(CoreError::invalid_input("peer_user_id must not be empty"));
        }
        if input.peer_active_device_ids.is_empty() {
            return Err(CoreError::invalid_input(
                "peer conversation must contain at least one active device",
            ));
        }

        let desired_active: BTreeSet<String> =
            input.peer_active_device_ids.iter().cloned().collect();
        let previous_active = state
            .map(|value| value.last_known_peer_active_devices.clone())
            .unwrap_or_default();

        let added_devices: Vec<String> = desired_active
            .difference(&previous_active)
            .cloned()
            .collect();
        let revoked_devices: Vec<String> = previous_active
            .difference(&desired_active)
            .cloned()
            .collect();

        let mut member_devices = vec![ConversationMember {
            user_id: input.local_user_id.to_string(),
            device_id: input.local_device_id.to_string(),
            status: DeviceStatusKind::Active,
        }];

        let mut peer_devices: BTreeSet<String> = desired_active.clone();
        peer_devices.extend(revoked_devices.iter().cloned());
        for device_id in peer_devices {
            member_devices.push(ConversationMember {
                user_id: input.peer_user_id.to_string(),
                device_id: device_id.clone(),
                status: if desired_active.contains(&device_id) {
                    DeviceStatusKind::Active
                } else {
                    DeviceStatusKind::Revoked
                },
            });
        }

        let changed = !added_devices.is_empty() || !revoked_devices.is_empty();
        Ok(ReconcileMembershipResult {
            changed,
            added_devices,
            revoked_devices,
            member_devices,
            should_mark_recovery: changed,
            should_mark_rebuild: false,
        })
    }

    pub fn apply_reconciled_membership(
        state: &mut LocalConversationState,
        reconcile: &ReconcileMembershipResult,
        peer_active_device_ids: &[String],
        updated_at: u64,
    ) {
        state.conversation.member_devices = reconcile.member_devices.clone();
        state.last_known_peer_active_devices = peer_active_device_ids.iter().cloned().collect();
        state.conversation.updated_at = updated_at;
        if reconcile.should_mark_rebuild {
            state.conversation.state = ConversationState::NeedsRebuild;
            state.recovery_status = RecoveryStatus::NeedsRebuild;
        } else if reconcile.should_mark_recovery {
            state.recovery_status = RecoveryStatus::NeedsRecovery;
        } else if state.conversation.state != ConversationState::NeedsRebuild {
            state.recovery_status = RecoveryStatus::Healthy;
        }
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
        if state
            .messages
            .iter()
            .any(|message| message.message_id == envelope.message_id)
        {
            return Ok(AppliedEnvelopeEffect {
                duplicate_message: true,
                ..AppliedEnvelopeEffect::default()
            });
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
                state.recovery_status = RecoveryStatus::NeedsRebuild;
                effect.needs_rebuild = true;
            }
            MessageType::ControlDeviceMembershipChanged => {
                state.recovery_status = RecoveryStatus::NeedsRecovery;
                effect.identity_refresh_needed = true;
                effect.membership_refresh_needed = true;
            }
            MessageType::ControlIdentityStateUpdated => {
                state.recovery_status = RecoveryStatus::NeedsRecovery;
                effect.identity_refresh_needed = true;
            }
            MessageType::MlsApplication => {
                state
                    .last_known_peer_active_devices
                    .insert(envelope.sender_device_id.clone());
            }
            _ => {}
        }

        Ok(effect)
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AppliedEnvelopeEffect {
    pub identity_refresh_needed: bool,
    pub membership_refresh_needed: bool,
    pub needs_rebuild: bool,
    pub duplicate_message: bool,
}

fn build_direct_conversation_id(a: &str, b: &str) -> String {
    let mut parts = [a.to_string(), b.to_string()];
    parts.sort();
    format!("conv:{}:{}", parts[0], parts[1])
}

#[cfg(test)]
mod tests {
    use super::{
        ConversationManager, ConversationModule, LocalConversationState, ReconcileMembershipInput,
        RecoveryStatus,
    };
    use crate::model::{
        ConversationState, DeliveryClass, Envelope, MessageType, SenderProof, WakeHint,
    };

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
    fn reconcile_marks_revoked_devices_without_dropping_them() {
        let state = ConversationManager::create_direct_conversation(
            "user:alice",
            "device:alice:phone",
            "user:bob",
            &["device:bob:phone".into(), "device:bob:laptop".into()],
        )
        .expect("conversation should be created");

        let reconcile = ConversationManager::reconcile_direct_membership(
            Some(&state),
            ReconcileMembershipInput {
                local_user_id: "user:alice",
                local_device_id: "device:alice:phone",
                peer_user_id: "user:bob",
                peer_active_device_ids: &["device:bob:phone".into()],
            },
        )
        .expect("reconcile");

        assert_eq!(reconcile.revoked_devices, vec!["device:bob:laptop"]);
        assert!(reconcile.should_mark_recovery);
        assert!(
            reconcile
                .member_devices
                .iter()
                .any(|member| member.device_id == "device:bob:laptop"
                    && member.status == crate::model::DeviceStatusKind::Revoked)
        );
    }

    #[test]
    fn apply_reconcile_updates_snapshot_and_recovery_state() {
        let mut state = ConversationManager::create_direct_conversation(
            "user:alice",
            "device:alice:phone",
            "user:bob",
            &["device:bob:phone".into()],
        )
        .expect("conversation should be created");
        let active_devices = vec!["device:bob:phone".into(), "device:bob:laptop".into()];
        let reconcile = ConversationManager::reconcile_direct_membership(
            Some(&state),
            ReconcileMembershipInput {
                local_user_id: "user:alice",
                local_device_id: "device:alice:phone",
                peer_user_id: "user:bob",
                peer_active_device_ids: &active_devices,
            },
        )
        .expect("reconcile");

        ConversationManager::apply_reconciled_membership(
            &mut state,
            &reconcile,
            &active_devices,
            7,
        );

        assert_eq!(state.last_known_peer_active_devices.len(), 2);
        assert_eq!(state.recovery_status, RecoveryStatus::NeedsRecovery);
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
                delivery_class: DeliveryClass::Normal,
                wake_hint: Some(WakeHint {
                    latest_seq_hint: Some(1),
                }),
                sender_proof: SenderProof {
                    proof_type: "signature".into(),
                    value: "proof".into(),
                },
            },
        )
        .expect("apply should succeed");

        assert!(effect.needs_rebuild);
        assert_eq!(state.conversation.state, ConversationState::NeedsRebuild);
        assert_eq!(state.recovery_status, RecoveryStatus::NeedsRebuild);
    }

    #[test]
    fn control_membership_changed_requests_refresh() {
        let mut state: LocalConversationState = ConversationManager::create_direct_conversation(
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
                message_id: "msg:2".into(),
                conversation_id,
                sender_user_id: "user:bob".into(),
                sender_device_id: "device:bob:phone".into(),
                recipient_device_id: "device:alice:phone".into(),
                created_at: 2,
                message_type: MessageType::ControlDeviceMembershipChanged,
                inline_ciphertext: Some("cipher".into()),
                storage_refs: vec![],
                delivery_class: DeliveryClass::Normal,
                wake_hint: Some(WakeHint {
                    latest_seq_hint: Some(2),
                }),
                sender_proof: SenderProof {
                    proof_type: "signature".into(),
                    value: "proof".into(),
                },
            },
        )
        .expect("apply should succeed");

        assert!(effect.identity_refresh_needed);
        assert!(effect.membership_refresh_needed);
        assert_eq!(state.recovery_status, RecoveryStatus::NeedsRecovery);
    }

    #[test]
    fn duplicate_message_is_ignored_without_duplication() {
        let mut state = ConversationManager::create_direct_conversation(
            "user:alice",
            "device:alice:phone",
            "user:bob",
            &["device:bob:phone".into()],
        )
        .expect("conversation should be created");
        let conversation_id = state.conversation.conversation_id.clone();
        let envelope = Envelope {
            version: crate::model::CURRENT_MODEL_VERSION.to_string(),
            message_id: "msg:2".into(),
            conversation_id,
            sender_user_id: "user:bob".into(),
            sender_device_id: "device:bob:phone".into(),
            recipient_device_id: "device:alice:phone".into(),
            created_at: 2,
            message_type: MessageType::MlsApplication,
            inline_ciphertext: Some("cipher".into()),
            storage_refs: vec![],
            delivery_class: DeliveryClass::Normal,
            wake_hint: None,
            sender_proof: SenderProof {
                proof_type: "signature".into(),
                value: "proof".into(),
            },
        };

        let first = ConversationManager::apply_incoming_envelope(&mut state, &envelope)
            .expect("first apply");
        let second = ConversationManager::apply_incoming_envelope(&mut state, &envelope)
            .expect("second apply");

        assert!(!first.duplicate_message);
        assert!(second.duplicate_message);
        assert_eq!(state.messages.len(), 1);
    }
}

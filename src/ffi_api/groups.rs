use crate::error::{CoreError, CoreResult};
use crate::mls_adapter::PeerDeviceKeyPackage;
use crate::model::{
    DeviceStatusKind, GroupCapabilityOperation, GroupMessageType, GroupRole, IdentityBundle,
    MessageType,
};

pub(super) fn group_capability_operations(role: GroupRole) -> Vec<GroupCapabilityOperation> {
    match role {
        GroupRole::Owner => vec![
            GroupCapabilityOperation::Read,
            GroupCapabilityOperation::Subscribe,
            GroupCapabilityOperation::AppendApplication,
            GroupCapabilityOperation::AppendControl,
            GroupCapabilityOperation::AppendMembership,
            GroupCapabilityOperation::AppendEpoch,
            GroupCapabilityOperation::ManageInvites,
            GroupCapabilityOperation::ApproveJoin,
            GroupCapabilityOperation::RemoveMember,
            GroupCapabilityOperation::UpdateGroupMetadata,
            // Only the owner may seal the outbox (PROTOCOL_GROUP_CN.md §10.4).
            GroupCapabilityOperation::SealGroup,
        ],
        GroupRole::Admin => vec![
            GroupCapabilityOperation::Read,
            GroupCapabilityOperation::Subscribe,
            GroupCapabilityOperation::AppendApplication,
            GroupCapabilityOperation::AppendControl,
            GroupCapabilityOperation::AppendMembership,
            GroupCapabilityOperation::AppendEpoch,
            GroupCapabilityOperation::ManageInvites,
            GroupCapabilityOperation::ApproveJoin,
            GroupCapabilityOperation::RemoveMember,
            GroupCapabilityOperation::UpdateGroupMetadata,
        ],
        GroupRole::Member => vec![
            GroupCapabilityOperation::Read,
            GroupCapabilityOperation::Subscribe,
            GroupCapabilityOperation::AppendApplication,
            GroupCapabilityOperation::AppendControl,
            GroupCapabilityOperation::AppendEpoch,
        ],
    }
}

#[cfg(test)]
pub(crate) fn test_group_capability_operations(role: GroupRole) -> Vec<GroupCapabilityOperation> {
    group_capability_operations(role)
}

pub(super) fn group_message_type_to_direct(message_type: GroupMessageType) -> MessageType {
    match message_type {
        GroupMessageType::MlsApplication => MessageType::MlsApplication,
        GroupMessageType::MlsCommit => MessageType::MlsCommit,
        GroupMessageType::ControlConversationNeedsRebuild => {
            MessageType::ControlConversationNeedsRebuild
        }
        GroupMessageType::ControlGroupDissolved
        | GroupMessageType::ControlGroupMembershipChanged
        | GroupMessageType::ControlGroupMetadataUpdated
        | GroupMessageType::ControlGroupStateEvent => MessageType::ControlGroupStateEvent,
        GroupMessageType::ControlGroupJoinRequested
        | GroupMessageType::ControlGroupJoinApproved
        | GroupMessageType::ControlGroupJoinRejected
        | GroupMessageType::ControlGroupLeaveRequested => {
            // Dissolve is a terminal membership-change event; fold it into the
            // existing membership-changed bucket here so direct-chat message
            // type derivation stays a pure model projection. The
            // dissolve-specific behaviour (owner-only, seal outbox, etc.)
            // lives in the engine path added by later A.2-A.6 tasks.
            MessageType::ControlDeviceMembershipChanged
        }
    }
}

pub(super) fn active_peer_key_packages(
    bundle: &IdentityBundle,
) -> CoreResult<Vec<PeerDeviceKeyPackage>> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .map_err(|_| CoreError::new("device_clock_invalid", "system clock is invalid"))?;
    Ok(bundle
        .devices
        .iter()
        .filter(|device| matches!(device.status, DeviceStatusKind::Active))
        .filter_map(|device| {
            let keypackage_ref = device.keypackage_ref.as_ref()?;
            keypackage_ref
                .is_usable_at(now_ms)
                .then(|| PeerDeviceKeyPackage {
                    user_id: bundle.user_id.clone(),
                    device_id: device.device_id.clone(),
                    device_public_key: device.device_public_key.clone(),
                    key_package_b64: keypackage_ref.object_ref.clone(),
                })
        })
        .collect())
}

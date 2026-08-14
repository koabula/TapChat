use tapchat_core::conversation::StoredMessage;
use tapchat_core::model::{
    ConversationState, GroupMessageType, GroupStateEvent, GroupStateEventKind, MessageType,
};
use tapchat_core::persistence::PersistedGroupInvite;

pub(super) fn canonical_group_invite_url(invite: &PersistedGroupInvite) -> String {
    let Ok(parsed) = url::Url::parse(&invite.invite_url) else {
        return invite.invite_url.clone();
    };
    let origin = parsed.origin().ascii_serialization();
    if origin == "null" {
        return invite.invite_url.clone();
    }
    let origin = origin.trim_end_matches('/');
    format!(
        "{origin}/v1/group-invite/{}/{}",
        urlencoding::encode(&invite.group_id),
        urlencoding::encode(&invite.invite_id)
    )
}

pub(super) fn conversation_state_string(state: ConversationState) -> String {
    match state {
        ConversationState::Active => "active".into(),
        ConversationState::NeedsRebuild => "needs_rebuild".into(),
        ConversationState::Closed => "closed".into(),
        ConversationState::Archived => "archived".into(),
        ConversationState::Dissolved => "dissolved".into(),
    }
}

pub(super) fn system_banner_text(message_type: GroupMessageType) -> String {
    // Localised copy is the UI's job; for now we emit a stable English
    // string that R3.6 requires to be fixed for control_group_dissolved.
    // Other visible control messages are surfaced verbatim so the UI can
    // decide how to render them.
    match message_type {
        GroupMessageType::ControlGroupDissolved => {
            "This group has been dissolved by the owner.".into()
        }
        GroupMessageType::ControlGroupMembershipChanged => "Group membership changed.".into(),
        GroupMessageType::ControlGroupMetadataUpdated => "Group metadata updated.".into(),
        GroupMessageType::ControlGroupJoinRequested => "A new join request was submitted.".into(),
        GroupMessageType::ControlGroupJoinApproved => "A join request was approved.".into(),
        GroupMessageType::ControlGroupJoinRejected => "A join request was rejected.".into(),
        GroupMessageType::ControlGroupLeaveRequested => "A member requested to leave.".into(),
        GroupMessageType::ControlGroupStateEvent => "Group state changed.".into(),
        GroupMessageType::ControlConversationNeedsRebuild => {
            "This conversation needs to be rebuilt.".into()
        }
        // Non-control types should never reach this helper; fall back to
        // a neutral label rather than panicking so an unexpected code
        // path does not crash the UI thread.
        other => format!("{:?}", other),
    }
}

pub(super) fn group_state_event_text(plaintext: Option<&str>) -> String {
    let Some(event) =
        plaintext.and_then(|value| serde_json::from_str::<GroupStateEvent>(value).ok())
    else {
        return "Group state changed.".into();
    };
    let subjects = if event.subject_user_ids.is_empty() {
        "the group".to_string()
    } else {
        event.subject_user_ids.join(", ")
    };
    match event.kind {
        GroupStateEventKind::MemberJoined => format!("{subjects} joined the group."),
        GroupStateEventKind::MemberLeft => format!("{subjects} left the group."),
        GroupStateEventKind::MemberRemoved => {
            format!("{} removed {subjects} from the group.", event.actor_user_id)
        }
        GroupStateEventKind::RoleChanged => format!("{subjects}'s group role changed."),
        GroupStateEventKind::OwnershipTransferred => {
            format!("Group ownership was transferred to {subjects}.")
        }
        GroupStateEventKind::GroupMetadataChanged => "Group details were updated.".into(),
        GroupStateEventKind::GroupDissolved => "This group has been dissolved by the owner.".into(),
    }
}

/// Extract the short preview used in the sidebar — the plaintext of the
/// last `mls_application` message (or None when the group has only had
/// protocol traffic). Truncates to 50 chars to stay UI-friendly.
pub(super) fn last_application_preview(messages: &[StoredMessage]) -> Option<String> {
    messages
        .iter()
        .rev()
        .find(|msg| matches!(msg.message_type, MessageType::MlsApplication))
        .and_then(|msg| msg.plaintext.as_ref())
        .map(|text| super::conversation_view::visible_plaintext_preview(text))
}

/// Count the user-facing application messages in a conversation so the
/// sidebar can surface a total. Mirrors the convention used by
/// `commands/conversation.rs::list_conversations`.
pub(super) fn application_message_count(messages: &[StoredMessage]) -> usize {
    messages
        .iter()
        .filter(|msg| matches!(msg.message_type, MessageType::MlsApplication))
        .count()
}

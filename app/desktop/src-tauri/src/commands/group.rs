//! Tauri command layer exposing TapChat's group core primitives to the
//! desktop React UI.
//!
//! Architecture invariants enforced across this module (requirements
//! R4.3 / R18.1 / R18.2 / R19.3 in `desktop-group-ui-mvp/requirements.md`):
//!
//!   - Every command returns `Result<T, String>` so failures are surfaced
//!     to the UI as toast/banner text, never silently swallowed.
//!   - Every state-mutating command drives the core through
//!     `drive_core_with_handle(CoreInput::Command(...))` — the single
//!     authoritative entry point — so view-model projections and
//!     `core-update` events remain consistent.
//!   - Read-only projections (`list_*`, `get_*_snapshot`, `get_*_messages`)
//!     call `engine.refresh_snapshot()` under the `AppState` read lock
//!     without emitting `CoreCommand`/`CoreEvent`. They MUST NOT mutate
//!     core state; they only flatten the snapshot into JSON-friendly
//!     shapes for the UI.
//!   - Welcome pickup URLs are produced via
//!     `WelcomePickupDescriptor::to_welcome_pickup_url` (the single
//!     source of truth shared with the CLI). No local base64 plumbing.
//!   - UI-side role gating is cosmetic: the core's `local_group_role`,
//!     the Cloudflare outbox capability check, and receiver-side
//!     manifest validation remain the three authoritative gates.

use std::collections::{BTreeMap, BTreeSet};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager, State};

use tapchat_core::model::{
    GroupCursor, GroupJoinPolicy, GroupJoinRequest, GroupLeaveRequest, GroupLeaveRequestStatus,
    GroupManifest, GroupMemberInvitePolicy, GroupMemberStatus, GroupMessageType, GroupRole,
    StorageRef, WelcomePickupDescriptor,
};
use tapchat_core::persistence::PersistedGroupInvite;
use tapchat_core::{CoreCommand, CoreEffect, CoreOutput};

use super::group_view::{
    application_message_count, canonical_group_invite_url, conversation_state_string,
    group_state_event_text, last_application_preview, system_banner_text,
};
use crate::commands::cloudflare::{
    runtime_missing_group_outbox_message, runtime_status_for_deployment,
};
use crate::lifecycle::{drive_core_with_handle, CoreInput};
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Serialised projections returned to the React UI.
//
// These structs mirror the TypeScript views in
// `app/desktop/src/lib/types.ts` / `app/desktop/src/lib/tauri.ts`. They are
// narrowly scoped to the data the UI actually renders; anything outside
// their fields stays inside the core `CoreViewModel` / `CorePersistenceSnapshot`.
// ---------------------------------------------------------------------------

/// Sidebar row for a single group conversation.
#[derive(Debug, Clone, Serialize)]
pub struct GroupConversationSummary {
    pub group_id: String,
    pub conversation_id: String,
    pub title: String,
    pub owner_user_id: String,
    pub member_count: usize,
    pub local_role: Option<GroupRole>,
    pub conversation_state: String,
    /// `Some(sealed_at_ms)` once the owner has dissolved this group.
    pub dissolved_at: Option<u64>,
    pub last_message_preview: Option<String>,
    pub message_count: usize,
}

/// Full projection for a single group (member drawer / settings panel).
#[derive(Debug, Clone, Serialize)]
pub struct GroupSnapshotView {
    pub group_id: String,
    pub conversation_id: String,
    pub manifest: GroupManifest,
    pub local_role: Option<GroupRole>,
    pub cursor: Option<GroupCursor>,
    pub invites: Vec<GroupInviteView>,
    pub join_requests: Vec<GroupJoinRequestView>,
    pub leave_requests: Vec<GroupLeaveRequestView>,
    pub pending_outbox_count: usize,
    pub dissolved_at: Option<u64>,
    pub conversation_state: String,
    pub consistency_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_transition_stage: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GroupMessageView {
    Bubble {
        message_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        sender_user_id: Option<String>,
        sender_device_id: String,
        created_at: u64,
        plaintext: Option<String>,
        has_attachment: bool,
        storage_refs: Vec<StorageRef>,
        /// Original GroupEnvelope.message_type for debugging.
        raw_message_type: String,
    },
    SystemBanner {
        message_id: String,
        created_at: u64,
        /// Locked UI copy for each visible control message kind.
        text: String,
        raw_message_type: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        transition_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        event_kind: Option<tapchat_core::model::GroupStateEventKind>,
        #[serde(skip_serializing_if = "Option::is_none")]
        actor_user_id: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        subject_user_ids: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        old_role: Option<GroupRole>,
        #[serde(skip_serializing_if = "Option::is_none")]
        new_role: Option<GroupRole>,
    },
}

/// Shareable welcome pickup descriptor with its canonical URL pre-computed.
#[derive(Debug, Clone, Serialize)]
pub struct WelcomePickupShareable {
    pub group_id: String,
    pub device_id: String,
    pub endpoint: String,
    pub capability: String,
    pub expires_at: u64,
    /// `tapchat://welcome-pickup/<base64(descriptor json)>` — identical
    /// to the URL produced by `cli_welcome_pickup_url`, so the two code
    /// paths surface the same string for the same descriptor (R1.4).
    pub url: String,
}

impl From<&WelcomePickupDescriptor> for WelcomePickupShareable {
    fn from(descriptor: &WelcomePickupDescriptor) -> Self {
        Self {
            group_id: descriptor.group_id.clone(),
            device_id: descriptor.device_id.clone(),
            endpoint: descriptor.endpoint.clone(),
            capability: descriptor.capability.clone(),
            expires_at: descriptor.expires_at,
            url: descriptor.to_welcome_pickup_url(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct GroupInviteView {
    pub group_id: String,
    pub invite_id: String,
    pub invite_url: String,
    pub join_policy: GroupJoinPolicy,
    pub expires_at: u64,
    pub max_uses: Option<u64>,
    pub uses: u64,
    pub status: tapchat_core::transport_contract::GroupInviteStatus,
    pub revision: u64,
    pub revoked_at: Option<u64>,
    pub inviter_user_id: String,
    pub created_at: u64,
}

impl From<&PersistedGroupInvite> for GroupInviteView {
    fn from(invite: &PersistedGroupInvite) -> Self {
        Self {
            group_id: invite.group_id.clone(),
            invite_id: invite.invite_id.clone(),
            invite_url: canonical_group_invite_url(invite),
            join_policy: invite.document.join_policy,
            expires_at: invite.document.expires_at,
            max_uses: invite.max_uses.or(invite.document.max_uses),
            uses: invite.uses,
            status: invite.status.clone(),
            revision: invite.revision,
            revoked_at: invite.revoked_at,
            inviter_user_id: invite.document.inviter_user_id.clone(),
            created_at: invite.document.created_at,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct GroupJoinRequestView {
    pub request_id: String,
    pub group_id: String,
    pub joiner_user_id: String,
    pub joiner_device_id: String,
    pub requested_at: u64,
    pub status: String,
    pub invite_id: String,
}

impl From<&GroupJoinRequest> for GroupJoinRequestView {
    fn from(request: &GroupJoinRequest) -> Self {
        let status = group_join_status_str(request.status);
        Self {
            request_id: request.request_id.clone(),
            group_id: request.group_id.clone(),
            joiner_user_id: request.joiner_user_id.clone(),
            joiner_device_id: request.joiner_device_id.clone(),
            requested_at: request.requested_at,
            status: status.into(),
            invite_id: request.invite_id.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct GroupLeaveRequestView {
    pub request_id: String,
    pub group_id: String,
    pub leaver_user_id: String,
    pub leaver_device_id: String,
    pub requested_at: u64,
    pub status: String,
}

impl From<&GroupLeaveRequest> for GroupLeaveRequestView {
    fn from(request: &GroupLeaveRequest) -> Self {
        let status = match request.status {
            GroupLeaveRequestStatus::WaitingForGroupCommit => "waiting_for_group_commit",
            GroupLeaveRequestStatus::TransitionInProgress => "transition_in_progress",
            GroupLeaveRequestStatus::Completed => "completed",
            GroupLeaveRequestStatus::Expired => "expired",
            GroupLeaveRequestStatus::Revoked => "revoked",
        };
        Self {
            request_id: request.request_id.clone(),
            group_id: request.group_id.clone(),
            leaver_user_id: request.leaver_user_id.clone(),
            leaver_device_id: request.leaver_device_id.clone(),
            requested_at: request.requested_at,
            status: status.into(),
        }
    }
}

fn group_join_status_str(status: tapchat_core::model::GroupJoinRequestStatus) -> &'static str {
    use tapchat_core::model::GroupJoinRequestStatus;
    match status {
        GroupJoinRequestStatus::Pending => "pending",
        GroupJoinRequestStatus::Approved => "approved",
        GroupJoinRequestStatus::PendingApproval => "pending_approval",
        GroupJoinRequestStatus::WaitingForGroupCommit => "waiting_for_group_commit",
        GroupJoinRequestStatus::TransitionInProgress => "transition_in_progress",
        GroupJoinRequestStatus::WelcomeAvailable => "welcome_available",
        GroupJoinRequestStatus::Joined => "joined",
        GroupJoinRequestStatus::Rejected => "rejected",
        GroupJoinRequestStatus::Expired => "expired",
        GroupJoinRequestStatus::Revoked => "revoked",
    }
}

fn group_consistency_state_str(
    state: &tapchat_core::persistence::GroupConsistencyState,
) -> &'static str {
    use tapchat_core::persistence::GroupConsistencyState;
    match state {
        GroupConsistencyState::Ready => "ready",
        GroupConsistencyState::Reconciling => "reconciling",
        GroupConsistencyState::BlockedNeedsRebuild => "blocked_needs_rebuild",
        GroupConsistencyState::Dissolved => "dissolved",
    }
}

fn pending_transition_stage_str(
    stage: &tapchat_core::persistence::PendingGroupTransitionStage,
) -> &'static str {
    use tapchat_core::persistence::PendingGroupTransitionStage;
    match stage {
        PendingGroupTransitionStage::AwaitingAuthorizationBootstrap => {
            "awaiting_authorization_bootstrap"
        }
        PendingGroupTransitionStage::Prepared => "prepared",
        PendingGroupTransitionStage::Submitting => "submitting",
        PendingGroupTransitionStage::ReconcilingAfterConflict => "reconciling_after_conflict",
        PendingGroupTransitionStage::AcceptedPublishingWelcomes => "accepted_publishing_welcomes",
        PendingGroupTransitionStage::CompletingJoin => "completing_join",
    }
}

fn dedupe_pending_join_request_views<'a>(
    requests: impl IntoIterator<Item = &'a GroupJoinRequest>,
) -> Vec<GroupJoinRequestView> {
    let mut seen_pending_devices = BTreeSet::new();
    let mut views = Vec::new();
    for request in requests {
        let is_pending = matches!(
            request.status,
            tapchat_core::model::GroupJoinRequestStatus::Pending
                | tapchat_core::model::GroupJoinRequestStatus::PendingApproval
        );
        if is_pending
            && !seen_pending_devices.insert((
                request.group_id.clone(),
                request.joiner_user_id.clone(),
                request.joiner_device_id.clone(),
            ))
        {
            continue;
        }
        views.push(GroupJoinRequestView::from(request));
    }
    views
}

#[tauri::command]
pub async fn apply_group_realtime_plan(
    app: AppHandle,
    websocket_group_ids: Vec<String>,
) -> Result<(), String> {
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::ApplyGroupRealtimePlan {
            websocket_group_ids,
        }),
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn notification_error_from_output(output: &CoreOutput, fallback: &str) -> String {
    notification_message_from_output(output).unwrap_or_else(|| fallback.to_string())
}

fn notification_message_from_output(output: &CoreOutput) -> Option<String> {
    output.effects.iter().rev().find_map(|effect| match effect {
        CoreEffect::EmitUserNotification { notification } => Some(notification.message.clone()),
        _ => None,
    })
}

// ---------------------------------------------------------------------------
// D.1.a — Read-only projections.
// ---------------------------------------------------------------------------

/// List every group conversation visible to the active profile.
///
/// Reads directly from `engine.refresh_snapshot()` because the sidebar
/// only needs a flattened view; this is purely a projection, no core
/// state is mutated (R18.2 "reads may still observe the snapshot that
/// drive_core_with_handle returned, but MUST NOT mutate core state").
#[tauri::command]
pub async fn list_group_conversations(
    state: State<'_, AppState>,
) -> Result<Vec<GroupConversationSummary>, String> {
    list_group_conversations_impl(state.inner()).await
}

/// Shared body for [`list_group_conversations`] and the test-path
/// equivalent used by `tests/desktop_group_e2e.rs`. Reads the
/// engine snapshot and projects every group conversation into the
/// sidebar-ready view.
pub async fn list_group_conversations_impl(
    state: &AppState,
) -> Result<Vec<GroupConversationSummary>, String> {
    let inner = state.inner.read().await;
    let snapshot = inner.engine.refresh_snapshot();

    // Index conversations by id for O(1) lookup.
    let mut conversations_by_id: BTreeMap<&str, &tapchat_core::persistence::PersistedConversation> =
        BTreeMap::new();
    for conversation in &snapshot.conversations {
        conversations_by_id.insert(&conversation.conversation_id, conversation);
    }

    let mut rows = Vec::new();
    for group in &snapshot.group_states {
        let conversation = conversations_by_id.get(group.conversation_id.as_str());
        let state_str = conversation
            .map(|c| conversation_state_string(c.state.conversation.state))
            .unwrap_or_else(|| "active".into());
        let messages: &[tapchat_core::conversation::StoredMessage] = conversation
            .map(|c| c.state.messages.as_slice())
            .unwrap_or(&[]);
        rows.push(GroupConversationSummary {
            group_id: group.group_id.clone(),
            conversation_id: group.conversation_id.clone(),
            title: group.manifest.title.clone(),
            owner_user_id: group.manifest.owner_user_id.clone(),
            member_count: group
                .manifest
                .members
                .iter()
                .filter(|m| m.status == GroupMemberStatus::Active)
                .count(),
            local_role: group.local_role,
            conversation_state: state_str,
            dissolved_at: group.dissolved_at,
            last_message_preview: last_application_preview(messages),
            message_count: application_message_count(messages),
        });
    }
    Ok(rows)
}

/// Full snapshot view for a single group (member drawer, settings panel,
/// approval panel).
#[tauri::command]
pub async fn get_group_snapshot(
    state: State<'_, AppState>,
    group_id: String,
) -> Result<GroupSnapshotView, String> {
    get_group_snapshot_impl(state.inner(), group_id).await
}

/// Shared body for [`get_group_snapshot`]. Mirrors the production
/// command behaviour except that tests don't need an `AppHandle`.
pub async fn get_group_snapshot_impl(
    state: &AppState,
    group_id: String,
) -> Result<GroupSnapshotView, String> {
    let inner = state.inner.read().await;
    let snapshot = inner.engine.refresh_snapshot();

    let group = snapshot
        .group_states
        .iter()
        .find(|state| state.group_id == group_id)
        .ok_or_else(|| format!("group '{group_id}' not found in local snapshot"))?;

    let cursor = snapshot
        .group_cursors
        .iter()
        .find(|persisted| persisted.group_id == group_id)
        .map(|persisted| persisted.cursor.clone());

    let invites: Vec<GroupInviteView> = snapshot
        .group_invites
        .iter()
        .filter(|invite| invite.group_id == group_id)
        .map(GroupInviteView::from)
        .collect();

    let join_requests = dedupe_pending_join_request_views(
        snapshot
            .group_join_requests
            .iter()
            .filter(|persisted| persisted.group_id == group_id)
            .map(|persisted| &persisted.request),
    );

    let leave_requests = group
        .leave_requests
        .iter()
        .map(|stored| GroupLeaveRequestView::from(&stored.request))
        .collect();

    let pending_outbox_count = snapshot
        .pending_group_outbox
        .iter()
        .filter(|item| item.envelope.group_id == group_id)
        .count();

    let conversation_state = snapshot
        .conversations
        .iter()
        .find(|c| c.conversation_id == group.conversation_id)
        .map(|c| conversation_state_string(c.state.conversation.state))
        .unwrap_or_else(|| "active".into());

    Ok(GroupSnapshotView {
        group_id: group.group_id.clone(),
        conversation_id: group.conversation_id.clone(),
        manifest: group.manifest.clone(),
        local_role: group.local_role,
        cursor,
        invites,
        join_requests,
        leave_requests,
        pending_outbox_count,
        dissolved_at: group.dissolved_at,
        conversation_state,
        consistency_state: group_consistency_state_str(&group.consistency_state).into(),
        pending_transition_stage: group
            .pending_group_transition
            .as_ref()
            .map(|pending| pending_transition_stage_str(&pending.stage).into()),
    })
}

/// Render the message log of a group conversation as a mixed list of
/// chat bubbles and visible system banners.
///
/// Rules (R3.1–R3.6):
///   - `visibility == protocol` entries are hidden (they are MLS commit /
///     routing plumbing that should not appear in the chat UI).
///   - `visibility == visible` control messages (`message_type` starts
///     with `control_`) render as system banners with a locked UI string.
///     `control_group_dissolved` specifically locks to
///     "This group has been dissolved by the owner." per R3.6.
///   - All other visible messages (application, attachments) render as
///     ordinary chat bubbles.
#[tauri::command]
pub async fn get_group_messages(
    state: State<'_, AppState>,
    conversation_id: String,
) -> Result<Vec<GroupMessageView>, String> {
    get_group_messages_impl(state.inner(), conversation_id).await
}

/// Shared body for [`get_group_messages`]. Identical snapshot walk;
/// the only difference vs. the production command is the lack of
/// `State<'_, AppState>` indirection.
pub async fn get_group_messages_impl(
    state: &AppState,
    conversation_id: String,
) -> Result<Vec<GroupMessageView>, String> {
    let inner = state.inner.read().await;
    let snapshot = inner.engine.refresh_snapshot();

    let conversation = snapshot
        .conversations
        .iter()
        .find(|c| c.conversation_id == conversation_id)
        .ok_or_else(|| format!("conversation '{conversation_id}' not found"))?;
    let device_user_ids: BTreeMap<&str, &str> = snapshot
        .group_states
        .iter()
        .find(|group| group.conversation_id == conversation_id)
        .map(|group| {
            group
                .manifest
                .member_devices
                .iter()
                .map(|device| (device.device_id.as_str(), device.user_id.as_str()))
                .collect()
        })
        .unwrap_or_default();

    let mut out = Vec::with_capacity(conversation.state.messages.len());
    for message in &conversation.state.messages {
        match message.message_type {
            tapchat_core::model::MessageType::MlsApplication => {
                out.push(GroupMessageView::Bubble {
                    message_id: message.message_id.clone(),
                    sender_user_id: message.sender_user_id.clone().or_else(|| {
                        device_user_ids
                            .get(message.sender_device_id.as_str())
                            .map(|user_id| (*user_id).to_string())
                    }),
                    sender_device_id: message.sender_device_id.clone(),
                    created_at: message.created_at,
                    plaintext: message.plaintext.clone(),
                    has_attachment: !message.storage_refs.is_empty(),
                    storage_refs: message.storage_refs.clone(),
                    raw_message_type: "mls_application".into(),
                });
            }
            tapchat_core::model::MessageType::ControlDeviceMembershipChanged => {
                // Direct-conversation plumbing — the group UI does not
                // render it. (Direct rebuild / membership banners are
                // handled by the ChatView direct branch.)
            }
            tapchat_core::model::MessageType::ControlIdentityStateUpdated => {
                // Same as above — direct conversation concern.
            }
            tapchat_core::model::MessageType::ControlGroupStateEvent => {
                let event = message.plaintext.as_deref().and_then(|value| {
                    serde_json::from_str::<tapchat_core::model::GroupStateEvent>(value).ok()
                });
                let raw_message_type = event
                    .as_ref()
                    .and_then(|event| serde_json::to_value(event.kind).ok())
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .unwrap_or_else(|| "control_group_state_event".into());
                out.push(GroupMessageView::SystemBanner {
                    message_id: message.message_id.clone(),
                    created_at: message.created_at,
                    text: group_state_event_text(message.plaintext.as_deref()),
                    raw_message_type,
                    transition_id: event.as_ref().map(|event| event.transition_id.clone()),
                    event_kind: event.as_ref().map(|event| event.kind),
                    actor_user_id: event.as_ref().map(|event| event.actor_user_id.clone()),
                    subject_user_ids: event
                        .as_ref()
                        .map(|event| event.subject_user_ids.clone())
                        .unwrap_or_default(),
                    old_role: event.as_ref().and_then(|event| event.old_role),
                    new_role: event.as_ref().and_then(|event| event.new_role),
                });
            }
            tapchat_core::model::MessageType::ControlContactRemoved => {
                // Direct relationship lifecycle message.
            }
            tapchat_core::model::MessageType::ControlContactAccepted => {
                // Direct relationship lifecycle protocol message.
            }
            tapchat_core::model::MessageType::MlsWelcome
            | tapchat_core::model::MessageType::MlsCommit
            | tapchat_core::model::MessageType::ControlGroupWelcomePickup => {
                // Protocol messages never surface in the chat UI.
            }
            tapchat_core::model::MessageType::ControlConversationNeedsRebuild => {
                let is_dissolved = message.plaintext.as_deref() == Some("control_group_dissolved");
                out.push(GroupMessageView::SystemBanner {
                    message_id: message.message_id.clone(),
                    created_at: message.created_at,
                    text: if is_dissolved {
                        system_banner_text(GroupMessageType::ControlGroupDissolved)
                    } else {
                        system_banner_text(GroupMessageType::ControlConversationNeedsRebuild)
                    },
                    raw_message_type: if is_dissolved {
                        "control_group_dissolved".into()
                    } else {
                        "control_conversation_needs_rebuild".into()
                    },
                    transition_id: None,
                    event_kind: None,
                    actor_user_id: None,
                    subject_user_ids: Vec::new(),
                    old_role: None,
                    new_role: None,
                });
            }
        }
    }

    // Also surface visible group control messages that are recorded in
    // the engine's stored group records. These arrive with
    // `message_type = MlsCommit` for the transport, but carry an
    // associated `control_*` marker in the engine's group-outbox
    // bookkeeping. For now the transport side stores them verbatim in
    // the conversation log, so the switch above covers the normal cases.
    // Future control types can be added to `system_banner_text`.

    Ok(out)
}

// ---------------------------------------------------------------------------
// D.1.b — Core write paths: create / text / attachment / sync.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct CreateGroupConversationResult {
    pub group_id: String,
    pub conversation_id: String,
    pub title: String,
    pub member_count: usize,
    pub local_role: Option<GroupRole>,
    pub welcome_pickups: Vec<WelcomePickupShareable>,
    pub pending_group_outbox: usize,
}

/// Create a new group conversation.
///
/// Validates inputs (title non-empty after trim, at least one member),
/// dispatches exactly one `CoreCommand::CreateGroupConversation` through
/// `drive_core_with_handle`, then projects the resulting view model +
/// snapshot into a compact result the UI can render immediately
/// (R1.1–R1.6).
#[tauri::command]
pub async fn create_group_conversation(
    app: AppHandle,
    title: String,
    member_user_ids: Vec<String>,
) -> Result<CreateGroupConversationResult, String> {
    let (trimmed_title, members) = normalize_create_group_inputs(&title, &member_user_ids)?;
    let deployment = {
        let state = app.state::<AppState>();
        let inner = state.inner.read().await;
        inner.engine.refresh_snapshot().deployment
    };
    let runtime_status = runtime_status_for_deployment(deployment).await;
    if let Some(message) = runtime_missing_group_outbox_message(&runtime_status) {
        return Err(message);
    }

    for member_user_id in &members {
        log::info!(
            "create_group_conversation: refreshing contact identity before group welcome user_id={}",
            member_user_id
        );
        drive_core_with_handle(
            &app,
            CoreInput::Command(CoreCommand::RefreshIdentityState {
                user_id: member_user_id.clone(),
            }),
        )
        .await
        .unwrap_or_else(|error| {
            log::warn!(
                "create_group_conversation: contact identity refresh preflight failed user_id={} error={}",
                member_user_id,
                error
            );
            CoreOutput::default()
        });
    }

    let output = drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::CreateGroupConversation {
            title: trimmed_title,
            member_user_ids: members,
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    // Snapshot the latest state after effects have drained so the UI
    // sees the post-flush pending_group_outbox count + the final
    // manifest owner role.
    let state = app.state::<AppState>();
    let inner = state.inner.read().await;
    let snapshot = inner.engine.refresh_snapshot();

    // The first `conversations` entry in the returned view model is the
    // newly-created group (the core places it there explicitly).
    let summary = output
        .view_model
        .as_ref()
        .and_then(|vm| vm.conversations.first())
        .ok_or_else(|| {
            "core did not return a conversation summary for the new group".to_string()
        })?;
    let group_id = summary
        .group_id
        .clone()
        .ok_or_else(|| "new conversation is missing a group_id".to_string())?;
    let conversation_id = summary.conversation_id.clone();

    let mut welcome_pickups_by_device = BTreeMap::new();
    if let Some(view_model) = output.view_model.as_ref() {
        for descriptor in &view_model.welcome_pickups {
            welcome_pickups_by_device.insert(
                descriptor.device_id.clone(),
                WelcomePickupShareable::from(descriptor),
            );
        }
    }
    let welcome_pickups = welcome_pickups_by_device.into_values().collect();

    let member_count = snapshot
        .group_states
        .iter()
        .find(|state| state.group_id == group_id)
        .map(|state| {
            state
                .manifest
                .members
                .iter()
                .filter(|member| member.status == tapchat_core::model::GroupMemberStatus::Active)
                .count()
        })
        .unwrap_or_default();
    let local_role = snapshot
        .group_states
        .iter()
        .find(|state| state.group_id == group_id)
        .and_then(|state| state.local_role);

    let pending_group_outbox = snapshot
        .pending_group_outbox
        .iter()
        .filter(|item| item.envelope.group_id == group_id)
        .count();

    Ok(CreateGroupConversationResult {
        group_id,
        conversation_id,
        title: summary.title.clone().unwrap_or_default(),
        member_count,
        local_role,
        welcome_pickups,
        pending_group_outbox,
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct SendGroupTextResult {
    pub message_id: String,
    pub conversation_id: String,
    pub sender_user_id: String,
    pub sender_device_id: String,
    pub plaintext: String,
    pub created_at: u64,
    pub pending_group_outbox: usize,
}

#[tauri::command]
pub async fn send_group_text_message(
    app: AppHandle,
    conversation_id: String,
    plaintext: String,
) -> Result<SendGroupTextResult, String> {
    if plaintext.is_empty() {
        return Err("plaintext must not be empty".into());
    }

    let output = drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::SendGroupTextMessage {
            conversation_id: conversation_id.clone(),
            plaintext: plaintext.clone(),
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    if output
        .state_update
        .system_statuses_changed
        .contains(&tapchat_core::ffi_api::SystemStatus::GroupMembershipRevoked)
    {
        return Err("group_membership_revoked".into());
    }

    let message_id = output
        .view_model
        .as_ref()
        .and_then(|vm| vm.messages.first())
        .map(|m| m.message_id.clone())
        .unwrap_or_default();

    let state = app.state::<AppState>();
    let inner = state.inner.read().await;
    let snapshot = inner.engine.refresh_snapshot();
    let (sender_user_id, sender_device_id) = snapshot
        .local_identity
        .as_ref()
        .map(|li| {
            (
                li.state.user_identity.user_id.clone(),
                li.state.device_identity.device_id.clone(),
            )
        })
        .unwrap_or_default();

    // Locate the group for the `pending_group_outbox` counter, falling
    // back to zero if the conversation no longer exists (e.g. just
    // dissolved).
    let group_id = snapshot
        .group_states
        .iter()
        .find(|g| g.conversation_id == conversation_id)
        .map(|g| g.group_id.clone());
    let pending_group_outbox = group_id
        .as_ref()
        .map(|gid| {
            snapshot
                .pending_group_outbox
                .iter()
                .filter(|item| item.envelope.group_id == *gid)
                .count()
        })
        .unwrap_or_default();

    Ok(SendGroupTextResult {
        message_id,
        conversation_id,
        sender_user_id,
        sender_device_id,
        plaintext,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        pending_group_outbox,
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncGroupOutboxResult {
    pub group_id: String,
    pub cursor: Option<GroupCursor>,
    pub dissolved_at: Option<u64>,
}

#[tauri::command]
pub async fn sync_group_outbox(
    app: AppHandle,
    group_id: String,
    reason: Option<String>,
) -> Result<SyncGroupOutboxResult, String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::SyncGroupOutbox {
            group_id: group_id.clone(),
            reason,
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    let state = app.state::<AppState>();
    let inner = state.inner.read().await;
    let snapshot = inner.engine.refresh_snapshot();
    let cursor = snapshot
        .group_cursors
        .iter()
        .find(|persisted| persisted.group_id == group_id)
        .map(|persisted| persisted.cursor.clone());
    let dissolved_at = snapshot
        .group_states
        .iter()
        .find(|state| state.group_id == group_id)
        .and_then(|state| state.dissolved_at);

    Ok(SyncGroupOutboxResult {
        group_id,
        cursor,
        dissolved_at,
    })
}

// ---------------------------------------------------------------------------
// D.1.c — Invite lifecycle: invite-to-group, create / revoke / list invite links.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct InviteToGroupResult {
    pub group_id: String,
    pub welcome_pickups: Vec<WelcomePickupShareable>,
}

#[tauri::command]
pub async fn invite_to_group(
    app: AppHandle,
    group_id: String,
    invitee_user_ids: Vec<String>,
) -> Result<InviteToGroupResult, String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }
    let invitees: Vec<String> = invitee_user_ids
        .into_iter()
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if invitees.is_empty() {
        return Err("at least one invitee user id is required".into());
    }

    for invitee_user_id in &invitees {
        log::info!(
            "invite_to_group: refreshing contact identity before group welcome user_id={}",
            invitee_user_id
        );
        drive_core_with_handle(
            &app,
            CoreInput::Command(CoreCommand::RefreshIdentityState {
                user_id: invitee_user_id.clone(),
            }),
        )
        .await
        .unwrap_or_else(|error| {
            log::warn!(
                "invite_to_group: contact identity refresh preflight failed user_id={} error={}",
                invitee_user_id,
                error
            );
            CoreOutput::default()
        });
    }

    let output = drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::InviteToGroup {
            group_id: group_id.clone(),
            invitee_user_ids: invitees,
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    let mut welcome_pickups_by_device = BTreeMap::new();
    if let Some(view_model) = output.view_model.as_ref() {
        for descriptor in &view_model.welcome_pickups {
            welcome_pickups_by_device.insert(
                descriptor.device_id.clone(),
                WelcomePickupShareable::from(descriptor),
            );
        }
    }
    let welcome_pickups = welcome_pickups_by_device.into_values().collect();

    Ok(InviteToGroupResult {
        group_id,
        welcome_pickups,
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateGroupInviteLinkResult {
    pub group_id: String,
    pub invite_id: String,
    pub invite_url: String,
    pub expires_at: u64,
    pub max_uses: Option<u64>,
    pub join_policy: GroupJoinPolicy,
}

#[tauri::command]
pub async fn create_group_invite_link(
    app: AppHandle,
    group_id: String,
    expires_at: u64,
    max_uses: Option<u64>,
) -> Result<CreateGroupInviteLinkResult, String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    if expires_at <= now_ms {
        return Err("expires_at must be in the future".into());
    }
    if let Some(max) = max_uses {
        if max == 0 {
            return Err("max_uses must be greater than zero when supplied".into());
        }
    }

    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::CreateGroupInviteLink {
            group_id: group_id.clone(),
            expires_at,
            max_uses,
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    // Pull the newly-minted invite back from the snapshot. The core
    // appends to `group_invites` in insertion order so the most recent
    // invite for this group is the last matching entry.
    let state = app.state::<AppState>();
    let inner = state.inner.read().await;
    let snapshot = inner.engine.refresh_snapshot();
    let invite = snapshot
        .group_invites
        .iter()
        .filter(|invite| invite.group_id == group_id)
        .next_back()
        .cloned()
        .ok_or_else(|| "core did not persist the new invite".to_string())?;

    Ok(CreateGroupInviteLinkResult {
        group_id: invite.group_id.clone(),
        invite_id: invite.invite_id.clone(),
        invite_url: canonical_group_invite_url(&invite),
        expires_at: invite.document.expires_at,
        max_uses: invite.document.max_uses,
        join_policy: invite.document.join_policy,
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct RevokeGroupInviteLinkResult {
    pub group_id: String,
    pub invite_id: String,
}

#[tauri::command]
pub async fn revoke_group_invite_link(
    app: AppHandle,
    group_id: String,
    invite_id: String,
) -> Result<RevokeGroupInviteLinkResult, String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }
    if invite_id.trim().is_empty() {
        return Err("invite_id must not be empty".into());
    }

    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::RevokeGroupInviteLink {
            group_id: group_id.clone(),
            invite_id: invite_id.clone(),
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    Ok(RevokeGroupInviteLinkResult {
        group_id,
        invite_id,
    })
}

#[tauri::command]
pub async fn list_group_invites(
    app: AppHandle,
    group_id: String,
) -> Result<Vec<GroupInviteView>, String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }
    let output = drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::ListGroupInvites {
            group_id: group_id.clone(),
        }),
    )
    .await
    .map_err(|error| error.to_string())?;
    let invites = output
        .view_model
        .map(|view_model| {
            view_model
                .group_invites
                .iter()
                .filter(|invite| invite.group_id == group_id)
                .map(GroupInviteView::from)
                .collect()
        })
        .unwrap_or_default();
    Ok(invites)
}

// ---------------------------------------------------------------------------
// D.1.d — Join flow: submit / list / status / approve / reject / pickup-direct.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct SubmitGroupJoinRequestResult {
    pub request_id: String,
    pub group_id: String,
    pub status: String,
}

/// Submit a join request against either an invite-link URL (new joiner
/// who has a `/v1/group-invite/<token>` URL) or a welcome-pickup URL
/// (new joiner receiving a `tapchat://welcome-pickup/...` URL directly).
///
/// The core dispatcher routes the two cases internally; the Tauri layer
/// just forwards the URL string (R8.1 / R8.2).
#[tauri::command]
pub async fn submit_group_join_request(
    app: AppHandle,
    invite_url: String,
) -> Result<SubmitGroupJoinRequestResult, String> {
    let trimmed = invite_url.trim().to_string();
    if trimmed.is_empty() {
        return Err("invite_url must not be empty".into());
    }

    // Detect the welcome-pickup form and route it through
    // `RequestJoinGroup` (which directly imports the group) rather than
    // through the invite-link submit pipeline.
    let is_welcome_pickup = trimmed.starts_with("tapchat://welcome-pickup/");
    let command = if is_welcome_pickup {
        CoreCommand::RequestJoinGroup {
            invite_url: trimmed.clone(),
        }
    } else {
        CoreCommand::SubmitGroupJoinRequest {
            invite_url: trimmed.clone(),
        }
    };

    log::info!(
        "submit_group_join_request: starting url_kind={} url={}",
        if is_welcome_pickup {
            "welcome_pickup"
        } else {
            "group_invite"
        },
        trimmed
    );

    let output = drive_core_with_handle(&app, CoreInput::Command(command))
        .await
        .map_err(|e| e.to_string())?;

    // For welcome-pickup URLs the core imports the group immediately
    // and returns the new conversation summary; the request_id is a
    // synthetic marker the UI won't need to poll.
    if is_welcome_pickup {
        let state = app.state::<AppState>();
        let inner = state.inner.read().await;
        let snapshot = inner.engine.refresh_snapshot();
        let group = output
            .view_model
            .as_ref()
            .and_then(|vm| vm.conversations.first())
            .and_then(|summary| summary.group_id.clone())
            .or_else(|| {
                snapshot
                    .group_states
                    .last()
                    .map(|state| state.group_id.clone())
            })
            .ok_or_else(|| "welcome pickup did not import a group".to_string())?;
        return Ok(SubmitGroupJoinRequestResult {
            request_id: format!("pickup:{group}"),
            group_id: group,
            status: "approved".into(),
        });
    }

    if output.view_model.is_none() || notification_message_from_output(&output).is_some() {
        let detail = notification_error_from_output(&output, "core did not return a join request");
        log::warn!(
            "submit_group_join_request: failed url_kind=group_invite url={} detail={}",
            trimmed,
            detail
        );
        return Err(detail);
    }

    let request = if let Some(request) = output
        .view_model
        .as_ref()
        .and_then(|vm| vm.group_join_requests.first())
        .cloned()
    {
        request
    } else {
        let state = app.state::<AppState>();
        let inner = state.inner.read().await;
        inner
            .engine
            .refresh_snapshot()
            .group_join_requests
            .last()
            .map(|persisted| persisted.request.clone())
            .ok_or_else(|| {
                notification_error_from_output(&output, "core did not return a join request")
            })?
    };
    log::info!(
        "submit_group_join_request: submitted group_id={} request_id={} status={:?}",
        request.group_id,
        request.request_id,
        request.status
    );
    Ok(SubmitGroupJoinRequestResult {
        request_id: request.request_id,
        group_id: request.group_id,
        status: group_join_status_str(request.status).into(),
    })
}

#[tauri::command]
pub async fn list_group_join_requests(
    app: AppHandle,
    group_id: String,
) -> Result<Vec<GroupJoinRequestView>, String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }
    let output = drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::ListGroupJoinRequests {
            group_id: group_id.clone(),
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    let requests = output
        .view_model
        .map(|vm| {
            dedupe_pending_join_request_views(
                vm.group_join_requests
                    .iter()
                    .filter(|request| request.group_id == group_id),
            )
        })
        .unwrap_or_default();
    Ok(requests)
}

#[derive(Debug, Clone, Serialize)]
pub struct GroupJoinStatusView {
    pub group_id: String,
    pub request_id: String,
    pub status: String,
    pub group_imported: bool,
    pub welcome_pickup: Option<WelcomePickupShareable>,
}

#[tauri::command]
pub async fn get_group_join_request_status(
    app: AppHandle,
    group_id: String,
    request_id: String,
) -> Result<GroupJoinStatusView, String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }
    if request_id.trim().is_empty() {
        return Err("request_id must not be empty".into());
    }

    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::GetGroupJoinRequestStatus {
            group_id: group_id.clone(),
            request_id: request_id.clone(),
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    let state = app.state::<AppState>();
    let inner = state.inner.read().await;
    let snapshot = inner.engine.refresh_snapshot();

    let persisted = snapshot
        .group_join_requests
        .iter()
        .find(|persisted| persisted.group_id == group_id && persisted.request_id == request_id)
        .ok_or_else(|| format!("join request '{request_id}' not found for group '{group_id}'"))?;

    let group_imported = snapshot
        .group_states
        .iter()
        .any(|state| state.group_id == group_id);

    let welcome_pickup = persisted
        .welcome_pickup
        .as_ref()
        .map(WelcomePickupShareable::from);

    Ok(GroupJoinStatusView {
        group_id: persisted.group_id.clone(),
        request_id: persisted.request_id.clone(),
        status: group_join_status_str(persisted.request.status).into(),
        group_imported,
        welcome_pickup,
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct ApproveGroupJoinResult {
    pub group_id: String,
    pub request_id: String,
    pub status: String,
    pub welcome_pickups: Vec<WelcomePickupShareable>,
}

#[tauri::command]
pub async fn approve_group_join(
    app: AppHandle,
    group_id: String,
    request_id: String,
) -> Result<ApproveGroupJoinResult, String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }
    if request_id.trim().is_empty() {
        return Err("request_id must not be empty".into());
    }

    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::ListGroupJoinRequests {
            group_id: group_id.clone(),
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    let output = match drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::ApproveGroupJoin {
            group_id: group_id.clone(),
            request_id: request_id.clone(),
        }),
    )
    .await
    {
        Ok(output) => output,
        Err(error) => {
            let detail = error.to_string();
            if detail.contains("already_member") {
                return Ok(ApproveGroupJoinResult {
                    group_id,
                    request_id,
                    status: "already_member".into(),
                    welcome_pickups: Vec::new(),
                });
            }
            return Err(detail);
        }
    };

    let mut welcome_pickups_by_device = BTreeMap::new();
    if let Some(view_model) = output.view_model.as_ref() {
        for descriptor in &view_model.welcome_pickups {
            welcome_pickups_by_device.insert(
                descriptor.device_id.clone(),
                WelcomePickupShareable::from(descriptor),
            );
        }
    }
    let welcome_pickups = welcome_pickups_by_device.into_values().collect();

    Ok(ApproveGroupJoinResult {
        group_id,
        request_id,
        status: "approved".into(),
        welcome_pickups,
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessGroupJoinRequestsResult {
    pub group_id: String,
    pub processed: usize,
    pub approved: usize,
    pub already_member: usize,
    pub failed: usize,
}

#[tauri::command]
pub async fn process_group_join_requests(
    app: AppHandle,
    group_id: String,
) -> Result<ProcessGroupJoinRequestsResult, String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }

    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::ListGroupJoinRequests {
            group_id: group_id.clone(),
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    let snapshot = {
        let state = app.state::<AppState>();
        let inner = state.inner.read().await;
        inner.engine.refresh_snapshot()
    };
    let Some(group) = snapshot
        .group_states
        .iter()
        .find(|state| state.group_id == group_id)
        .cloned()
    else {
        return Err(format!("group '{group_id}' not found in local snapshot"));
    };
    let role = group.local_role.unwrap_or(GroupRole::Member);
    if !matches!(role, GroupRole::Owner | GroupRole::Admin)
        || group.manifest.join_policy != GroupJoinPolicy::OpenByInvite
    {
        return Ok(ProcessGroupJoinRequestsResult {
            group_id,
            processed: 0,
            approved: 0,
            already_member: 0,
            failed: 0,
        });
    }

    let mut seen = BTreeSet::new();
    let candidates: Vec<_> = snapshot
        .group_join_requests
        .iter()
        .filter(|persisted| persisted.group_id == group_id)
        .filter(|persisted| {
            matches!(
                persisted.request.status,
                tapchat_core::model::GroupJoinRequestStatus::Pending
                    | tapchat_core::model::GroupJoinRequestStatus::WaitingForGroupCommit
            ) && persisted.request.auto_approve.unwrap_or(false)
        })
        .filter(|persisted| {
            seen.insert((
                persisted.request.joiner_user_id.clone(),
                persisted.request.joiner_device_id.clone(),
            ))
        })
        .map(|persisted| persisted.request_id.clone())
        .collect();

    let mut result = ProcessGroupJoinRequestsResult {
        group_id: group_id.clone(),
        processed: candidates.len(),
        approved: 0,
        already_member: 0,
        failed: 0,
    };
    for request_id in candidates {
        match drive_core_with_handle(
            &app,
            CoreInput::Command(CoreCommand::ApproveGroupJoin {
                group_id: group_id.clone(),
                request_id,
            }),
        )
        .await
        {
            Ok(_) => result.approved += 1,
            Err(error) => {
                let detail = error.to_string();
                if detail.contains("already_member") {
                    result.already_member += 1;
                } else {
                    result.failed += 1;
                    log::warn!(
                        "process_group_join_requests: auto-approve failed group_id={} detail={}",
                        group_id,
                        detail
                    );
                }
            }
        }
    }
    Ok(result)
}

#[tauri::command]
pub async fn retry_pending_welcome_pickups(app: AppHandle) -> Result<(), String> {
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::RetryPendingWelcomePickups),
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn reject_group_join(
    app: AppHandle,
    group_id: String,
    request_id: String,
    reason: Option<String>,
) -> Result<(), String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }
    if request_id.trim().is_empty() {
        return Err("request_id must not be empty".into());
    }
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::RejectGroupJoin {
            group_id,
            request_id,
            reason,
        }),
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// D.1.e — Membership management + metadata updates.
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn leave_group(app: AppHandle, group_id: String) -> Result<(), String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::LeaveGroup { group_id }),
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn list_group_leave_requests(
    app: AppHandle,
    group_id: String,
) -> Result<Vec<GroupLeaveRequestView>, String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }
    let output = drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::ListGroupLeaveRequests { group_id }),
    )
    .await
    .map_err(|error| error.to_string())?;
    Ok(output
        .view_model
        .map(|view| {
            view.group_leave_requests
                .iter()
                .map(GroupLeaveRequestView::from)
                .collect()
        })
        .unwrap_or_default())
}

#[tauri::command]
pub async fn approve_group_leave(
    app: AppHandle,
    group_id: String,
    request_id: String,
) -> Result<(), String> {
    if group_id.trim().is_empty() || request_id.trim().is_empty() {
        return Err("group_id and request_id must not be empty".into());
    }
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::ListGroupLeaveRequests {
            group_id: group_id.clone(),
        }),
    )
    .await
    .map_err(|error| error.to_string())?;
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::ApproveGroupLeave {
            group_id,
            request_id,
        }),
    )
    .await
    .map_err(|error| error.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn remove_group_member(
    app: AppHandle,
    group_id: String,
    target_user_id: String,
) -> Result<(), String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }
    if target_user_id.trim().is_empty() {
        return Err("target_user_id must not be empty".into());
    }
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::RemoveGroupMember {
            group_id,
            target_user_id,
        }),
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn transfer_group_ownership(
    app: AppHandle,
    group_id: String,
    new_owner_user_id: String,
) -> Result<(), String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }
    if new_owner_user_id.trim().is_empty() {
        return Err("new_owner_user_id must not be empty".into());
    }
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::TransferGroupOwnership {
            group_id,
            new_owner_user_id,
        }),
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn set_group_admin(
    app: AppHandle,
    group_id: String,
    target_user_id: String,
    is_admin: bool,
) -> Result<(), String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }
    if target_user_id.trim().is_empty() {
        return Err("target_user_id must not be empty".into());
    }
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::SetGroupAdmin {
            group_id,
            target_user_id,
            is_admin,
        }),
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateGroupMetadataResult {
    pub group_id: String,
    pub title: Option<String>,
    pub join_policy: Option<GroupJoinPolicy>,
    pub member_invite_policy: Option<GroupMemberInvitePolicy>,
    pub roster_version: Option<u64>,
}

/// Parse a UI-supplied `joinPolicy` string into the core enum variant.
///
/// Accepts the three documented values (case-insensitive,
/// whitespace-trimmed) and rejects anything else rather than silently
/// defaulting, so the UI surfaces a clear error when the user picks
/// something the server would refuse anyway.
pub(crate) fn parse_join_policy(value: &str) -> Result<GroupJoinPolicy, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "closed" => Ok(GroupJoinPolicy::Closed),
        "approval_required" => Ok(GroupJoinPolicy::ApprovalRequired),
        "open_by_invite" => Ok(GroupJoinPolicy::OpenByInvite),
        other => Err(format!(
            "unknown join policy '{other}'; expected closed|approval_required|open_by_invite"
        )),
    }
}

/// Parse a UI-supplied `memberInvitePolicy` string into the core enum.
///
/// Only the two documented variants are accepted (see
/// `doc/PROTOCOL_GROUP_CN.md`).
pub(crate) fn parse_member_invite_policy(value: &str) -> Result<GroupMemberInvitePolicy, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "owner_admin_only" => Ok(GroupMemberInvitePolicy::OwnerAdminOnly),
        "request_owner_approval" => Ok(GroupMemberInvitePolicy::RequestOwnerApproval),
        other => Err(format!(
            "unknown member invite policy '{other}'; expected owner_admin_only|request_owner_approval"
        )),
    }
}

#[tauri::command]
pub async fn update_group_metadata(
    app: AppHandle,
    group_id: String,
    title: Option<String>,
    join_policy: Option<String>,
    member_invite_policy: Option<String>,
) -> Result<UpdateGroupMetadataResult, String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }
    // Reject a no-op call so we don't waste a roster_version bump.
    if title.is_none() && join_policy.is_none() && member_invite_policy.is_none() {
        return Err(
            "at least one field (title, join_policy, member_invite_policy) must be supplied".into(),
        );
    }
    let parsed_join_policy = join_policy.as_deref().map(parse_join_policy).transpose()?;
    let parsed_member_invite_policy = member_invite_policy
        .as_deref()
        .map(parse_member_invite_policy)
        .transpose()?;
    let trimmed_title = title.map(|s| s.trim().to_string());
    if let Some(ref t) = trimmed_title {
        if t.is_empty() {
            return Err("title must not be whitespace-only".into());
        }
    }

    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::UpdateGroupMetadata {
            group_id: group_id.clone(),
            title: trimmed_title,
            join_policy: parsed_join_policy,
            member_invite_policy: parsed_member_invite_policy,
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    let state = app.state::<AppState>();
    let inner = state.inner.read().await;
    let snapshot = inner.engine.refresh_snapshot();
    let manifest = snapshot
        .group_states
        .iter()
        .find(|state| state.group_id == group_id)
        .map(|state| state.manifest.clone())
        .ok_or_else(|| format!("group '{group_id}' not found after update"))?;

    Ok(UpdateGroupMetadataResult {
        group_id,
        title: Some(manifest.title),
        join_policy: Some(manifest.join_policy),
        member_invite_policy: Some(manifest.member_invite_policy),
        roster_version: Some(manifest.roster_version),
    })
}

// ---------------------------------------------------------------------------
// D.1.f — Dissolve (owner-only).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct DissolveGroupResult {
    pub group_id: String,
    pub conversation_id: Option<String>,
    /// Set to `Some(ts)` when the seal has already been acknowledged by
    /// the server before this command returned. When still `None`, the
    /// seal is in flight; the UI should wait for the next `core-update`
    /// carrying a refreshed `group_snapshot.dissolved_at`.
    pub dissolved_at: Option<u64>,
    pub conversation_state: String,
    /// Lets the UI display a spinner while the MLS commit + control
    /// message are still draining.
    pub pending_group_outbox: usize,
}

/// Owner-only atomic dissolve (R12.5 / R12.6). The authoritative role
/// check lives in the core (`engine::dissolve_group`); the desktop UI's
/// `canPerform("dissolve", ...)` gate is purely cosmetic and the
/// server-side `seal_group` capability is what actually enforces it on
/// the wire.
#[tauri::command]
pub async fn dissolve_group(
    app: AppHandle,
    group_id: String,
) -> Result<DissolveGroupResult, String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }

    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::DissolveGroup {
            group_id: group_id.clone(),
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    // Re-read snapshot — step (c) of the dissolve schedules a
    // SealGroupOutbox effect that may or may not have completed by now.
    // We deliberately do NOT block waiting for the seal ack to avoid
    // stalling the UI thread; the caller should refresh via core-update.
    let state = app.state::<AppState>();
    let inner = state.inner.read().await;
    let snapshot = inner.engine.refresh_snapshot();
    let group = snapshot
        .group_states
        .iter()
        .find(|state| state.group_id == group_id)
        .ok_or_else(|| format!("group '{group_id}' not found after dissolve"))?;
    let conversation_state = snapshot
        .conversations
        .iter()
        .find(|c| c.conversation_id == group.conversation_id)
        .map(|c| conversation_state_string(c.state.conversation.state))
        .unwrap_or_else(|| "active".into());
    let pending_group_outbox = snapshot
        .pending_group_outbox
        .iter()
        .filter(|item| item.envelope.group_id == group_id)
        .count();

    Ok(DissolveGroupResult {
        group_id: group.group_id.clone(),
        conversation_id: Some(group.conversation_id.clone()),
        dissolved_at: group.dissolved_at,
        conversation_state,
        pending_group_outbox,
    })
}

// The `Digest` / `Sha256` / `BASE64` imports are reserved for any
// follow-up command (e.g. a future server-side fingerprint of
// capability artifacts for observability). They stay in the import
// list today so additions during iterative development don't keep
// re-touching the top-of-file imports.
#[allow(dead_code)]
fn _reserve_crypto_imports() {
    let _ = BASE64.encode([0u8; 0]);
    let _ = Sha256::new();
}

// ---------------------------------------------------------------------------
// Pure argument-normalisation helper for `create_group_conversation`.
//
// Extracted so the input validation rules can be reasoned about in
// isolation. Integration tests in `tests/desktop_group_e2e.rs` (Wave
// G.4) exercise the full command path including the core dispatch.
//
// Unit tests for this helper live in `tapchat_core`'s test suite (where
// pure-Rust cargo test runs without the Tauri WebView2 DLL linkage the
// `tapchat-desktop` cdylib introduces on Windows). The equivalence of
// the normalisation logic to the CLI is additionally guaranteed by the
// CLI's own integration tests and by the fact that the inputs are
// plain-Rust strings with no platform surface.
// ---------------------------------------------------------------------------

/// Normalise and validate the `(title, member_user_ids)` pair the UI
/// hands to [`create_group_conversation`]. Returns the trimmed title and
/// the deduplicated non-empty member list when the input is valid, or a
/// stable error string otherwise.
pub(crate) fn normalize_create_group_inputs(
    title: &str,
    member_user_ids: &[String],
) -> Result<(String, Vec<String>), String> {
    let trimmed_title = title.trim().to_string();
    if trimmed_title.is_empty() {
        return Err("group title must not be empty".into());
    }
    let members: Vec<String> = member_user_ids
        .iter()
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if members.is_empty() {
        return Err("at least one member user id is required".into());
    }
    Ok((trimmed_title, members))
}

// ---------------------------------------------------------------------------
// Test-accessible `_impl` siblings for every write-path Tauri command.
//
// Architecture note (Wave G.4 / Path C from the spec investigation):
//
// The desktop crate is a `cdylib` (Tauri needs it to build the webview
// container). Rust integration tests under `tests/*.rs` live in the
// root crate and therefore cannot call `#[tauri::command]` functions
// directly — those bodies require an `AppHandle`, which in turn
// requires a running webview event loop we deliberately don't start
// for unit tests.
//
// So for every write-path group Tauri command `foo(app, ...)` we
// expose a sibling `foo_impl(state: &AppState, ...)` whose body
// mirrors the production command's logic **byte-for-byte**, except:
//
//   1. `drive_core_with_handle(&app, ...)` is replaced with
//      `drive_core_without_handle(state, ...)` — same effect-draining
//      and persistence semantics, skipping only the UI emit and the
//      `AppHandle::emit("core-update", ...)`.
//   2. `app.state::<AppState>()` reads become direct `state.inner.read()`
//      calls (the `State<'_, AppState>` indirection from Tauri is
//      absent here).
//
// The production `#[tauri::command]` bodies above are left **unchanged**
// to keep the regression surface at zero. Any divergence between the
// two paths is either an input-validation rule (which lives in a
// pure helper: `normalize_create_group_inputs`, `parse_join_policy`,
// `parse_member_invite_policy`, all called by both paths) or an
// arithmetic projection over the post-drive snapshot (which is small
// enough per-command that duplication is cheaper than a generic
// async-closure-taking helper).
// ---------------------------------------------------------------------------

#[cfg(any(test, feature = "test-support"))]
use crate::lifecycle::drive_core_without_handle;

#[cfg(any(test, feature = "test-support"))]
pub async fn create_group_conversation_impl(
    state: &AppState,
    title: String,
    member_user_ids: Vec<String>,
) -> Result<CreateGroupConversationResult, String> {
    let (trimmed_title, members) = normalize_create_group_inputs(&title, &member_user_ids)?;
    let deployment = {
        let inner = state.inner.read().await;
        inner.engine.refresh_snapshot().deployment
    };
    let runtime_status = runtime_status_for_deployment(deployment).await;
    if let Some(message) = runtime_missing_group_outbox_message(&runtime_status) {
        return Err(message);
    }

    for member_user_id in &members {
        drive_core_without_handle(
            state,
            CoreInput::Command(CoreCommand::RefreshIdentityState {
                user_id: member_user_id.clone(),
            }),
        )
        .await
        .unwrap_or_else(|_| CoreOutput::default());
    }

    let output = drive_core_without_handle(
        state,
        CoreInput::Command(CoreCommand::CreateGroupConversation {
            title: trimmed_title,
            member_user_ids: members,
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    let inner = state.inner.read().await;
    let snapshot = inner.engine.refresh_snapshot();

    let summary = output
        .view_model
        .as_ref()
        .and_then(|vm| vm.conversations.first())
        .ok_or_else(|| {
            "core did not return a conversation summary for the new group".to_string()
        })?;
    let group_id = summary
        .group_id
        .clone()
        .ok_or_else(|| "new conversation is missing a group_id".to_string())?;
    let conversation_id = summary.conversation_id.clone();

    let mut welcome_pickups_by_device = BTreeMap::new();
    if let Some(view_model) = output.view_model.as_ref() {
        for descriptor in &view_model.welcome_pickups {
            welcome_pickups_by_device.insert(
                descriptor.device_id.clone(),
                WelcomePickupShareable::from(descriptor),
            );
        }
    }
    let welcome_pickups = welcome_pickups_by_device.into_values().collect();

    let member_count = snapshot
        .group_states
        .iter()
        .find(|state| state.group_id == group_id)
        .map(|state| {
            state
                .manifest
                .members
                .iter()
                .filter(|member| member.status == tapchat_core::model::GroupMemberStatus::Active)
                .count()
        })
        .unwrap_or_default();
    let local_role = snapshot
        .group_states
        .iter()
        .find(|st| st.group_id == group_id)
        .and_then(|st| st.local_role);

    let pending_group_outbox = snapshot
        .pending_group_outbox
        .iter()
        .filter(|item| item.envelope.group_id == group_id)
        .count();

    Ok(CreateGroupConversationResult {
        group_id,
        conversation_id,
        title: summary.title.clone().unwrap_or_default(),
        member_count,
        local_role,
        welcome_pickups,
        pending_group_outbox,
    })
}

#[cfg(any(test, feature = "test-support"))]
pub async fn send_group_text_message_impl(
    state: &AppState,
    conversation_id: String,
    plaintext: String,
) -> Result<SendGroupTextResult, String> {
    if plaintext.is_empty() {
        return Err("plaintext must not be empty".into());
    }

    let output = drive_core_without_handle(
        state,
        CoreInput::Command(CoreCommand::SendGroupTextMessage {
            conversation_id: conversation_id.clone(),
            plaintext: plaintext.clone(),
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    if output
        .state_update
        .system_statuses_changed
        .contains(&tapchat_core::ffi_api::SystemStatus::GroupMembershipRevoked)
    {
        return Err("group_membership_revoked".into());
    }

    let message_id = output
        .view_model
        .as_ref()
        .and_then(|vm| vm.messages.first())
        .map(|m| m.message_id.clone())
        .unwrap_or_default();

    let inner = state.inner.read().await;
    let snapshot = inner.engine.refresh_snapshot();
    let (sender_user_id, sender_device_id) = snapshot
        .local_identity
        .as_ref()
        .map(|li| {
            (
                li.state.user_identity.user_id.clone(),
                li.state.device_identity.device_id.clone(),
            )
        })
        .unwrap_or_default();

    let group_id = snapshot
        .group_states
        .iter()
        .find(|g| g.conversation_id == conversation_id)
        .map(|g| g.group_id.clone());
    let pending_group_outbox = group_id
        .as_ref()
        .map(|gid| {
            snapshot
                .pending_group_outbox
                .iter()
                .filter(|item| item.envelope.group_id == *gid)
                .count()
        })
        .unwrap_or_default();

    Ok(SendGroupTextResult {
        message_id,
        conversation_id,
        sender_user_id,
        sender_device_id,
        plaintext,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        pending_group_outbox,
    })
}

#[cfg(any(test, feature = "test-support"))]
pub async fn sync_group_outbox_impl(
    state: &AppState,
    group_id: String,
    reason: Option<String>,
) -> Result<SyncGroupOutboxResult, String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }
    drive_core_without_handle(
        state,
        CoreInput::Command(CoreCommand::SyncGroupOutbox {
            group_id: group_id.clone(),
            reason,
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    let inner = state.inner.read().await;
    let snapshot = inner.engine.refresh_snapshot();
    let cursor = snapshot
        .group_cursors
        .iter()
        .find(|persisted| persisted.group_id == group_id)
        .map(|persisted| persisted.cursor.clone());
    let dissolved_at = snapshot
        .group_states
        .iter()
        .find(|st| st.group_id == group_id)
        .and_then(|st| st.dissolved_at);

    Ok(SyncGroupOutboxResult {
        group_id,
        cursor,
        dissolved_at,
    })
}

#[cfg(any(test, feature = "test-support"))]
pub async fn invite_to_group_impl(
    state: &AppState,
    group_id: String,
    invitee_user_ids: Vec<String>,
) -> Result<InviteToGroupResult, String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }
    let invitees: Vec<String> = invitee_user_ids
        .into_iter()
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if invitees.is_empty() {
        return Err("at least one invitee user id is required".into());
    }

    for invitee_user_id in &invitees {
        drive_core_without_handle(
            state,
            CoreInput::Command(CoreCommand::RefreshIdentityState {
                user_id: invitee_user_id.clone(),
            }),
        )
        .await
        .unwrap_or_else(|_| CoreOutput::default());
    }

    let output = drive_core_without_handle(
        state,
        CoreInput::Command(CoreCommand::InviteToGroup {
            group_id: group_id.clone(),
            invitee_user_ids: invitees,
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    let welcome_pickups: Vec<WelcomePickupShareable> = output
        .view_model
        .as_ref()
        .map(|vm| {
            vm.welcome_pickups
                .iter()
                .map(WelcomePickupShareable::from)
                .collect()
        })
        .unwrap_or_default();

    Ok(InviteToGroupResult {
        group_id,
        welcome_pickups,
    })
}

#[cfg(any(test, feature = "test-support"))]
pub async fn create_group_invite_link_impl(
    state: &AppState,
    group_id: String,
    expires_at: u64,
    max_uses: Option<u64>,
) -> Result<CreateGroupInviteLinkResult, String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    if expires_at <= now_ms {
        return Err("expires_at must be in the future".into());
    }
    if let Some(max) = max_uses {
        if max == 0 {
            return Err("max_uses must be greater than zero when supplied".into());
        }
    }

    drive_core_without_handle(
        state,
        CoreInput::Command(CoreCommand::CreateGroupInviteLink {
            group_id: group_id.clone(),
            expires_at,
            max_uses,
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    let inner = state.inner.read().await;
    let snapshot = inner.engine.refresh_snapshot();
    let invite = snapshot
        .group_invites
        .iter()
        .filter(|invite| invite.group_id == group_id)
        .next_back()
        .cloned()
        .ok_or_else(|| "core did not persist the new invite".to_string())?;

    Ok(CreateGroupInviteLinkResult {
        group_id: invite.group_id,
        invite_id: invite.invite_id,
        invite_url: invite.invite_url,
        expires_at: invite.document.expires_at,
        max_uses: invite.document.max_uses,
        join_policy: invite.document.join_policy,
    })
}

#[cfg(any(test, feature = "test-support"))]
pub async fn revoke_group_invite_link_impl(
    state: &AppState,
    group_id: String,
    invite_id: String,
) -> Result<RevokeGroupInviteLinkResult, String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }
    if invite_id.trim().is_empty() {
        return Err("invite_id must not be empty".into());
    }
    drive_core_without_handle(
        state,
        CoreInput::Command(CoreCommand::RevokeGroupInviteLink {
            group_id: group_id.clone(),
            invite_id: invite_id.clone(),
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    Ok(RevokeGroupInviteLinkResult {
        group_id,
        invite_id,
    })
}

#[cfg(any(test, feature = "test-support"))]
pub async fn list_group_invites_impl(
    state: &AppState,
    group_id: String,
) -> Result<Vec<GroupInviteView>, String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }
    let inner = state.inner.read().await;
    let snapshot = inner.engine.refresh_snapshot();
    let invites = snapshot
        .group_invites
        .iter()
        .filter(|invite| invite.group_id == group_id)
        .map(GroupInviteView::from)
        .collect();
    Ok(invites)
}

#[cfg(any(test, feature = "test-support"))]
pub async fn submit_group_join_request_impl(
    state: &AppState,
    invite_url: String,
) -> Result<SubmitGroupJoinRequestResult, String> {
    let trimmed = invite_url.trim().to_string();
    if trimmed.is_empty() {
        return Err("invite_url must not be empty".into());
    }

    let is_welcome_pickup = trimmed.starts_with("tapchat://welcome-pickup/");
    let command = if is_welcome_pickup {
        CoreCommand::RequestJoinGroup {
            invite_url: trimmed.clone(),
        }
    } else {
        CoreCommand::SubmitGroupJoinRequest {
            invite_url: trimmed.clone(),
        }
    };

    let output = drive_core_without_handle(state, CoreInput::Command(command))
        .await
        .map_err(|e| e.to_string())?;

    if is_welcome_pickup {
        let inner = state.inner.read().await;
        let snapshot = inner.engine.refresh_snapshot();
        let group = output
            .view_model
            .as_ref()
            .and_then(|vm| vm.conversations.first())
            .and_then(|summary| summary.group_id.clone())
            .or_else(|| snapshot.group_states.last().map(|st| st.group_id.clone()))
            .ok_or_else(|| "welcome pickup did not import a group".to_string())?;
        return Ok(SubmitGroupJoinRequestResult {
            request_id: format!("pickup:{group}"),
            group_id: group,
            status: "approved".into(),
        });
    }

    let request = if let Some(request) = output
        .view_model
        .as_ref()
        .and_then(|vm| vm.group_join_requests.first())
        .cloned()
    {
        request
    } else {
        let inner = state.inner.read().await;
        inner
            .engine
            .refresh_snapshot()
            .group_join_requests
            .last()
            .map(|persisted| persisted.request.clone())
            .ok_or_else(|| {
                notification_error_from_output(&output, "core did not return a join request")
            })?
    };
    Ok(SubmitGroupJoinRequestResult {
        request_id: request.request_id,
        group_id: request.group_id,
        status: group_join_status_str(request.status).into(),
    })
}

#[cfg(any(test, feature = "test-support"))]
pub async fn list_group_join_requests_impl(
    state: &AppState,
    group_id: String,
) -> Result<Vec<GroupJoinRequestView>, String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }
    let output = drive_core_without_handle(
        state,
        CoreInput::Command(CoreCommand::ListGroupJoinRequests {
            group_id: group_id.clone(),
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    let requests = output
        .view_model
        .map(|vm| {
            vm.group_join_requests
                .iter()
                .filter(|request| request.group_id == group_id)
                .map(GroupJoinRequestView::from)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(requests)
}

#[cfg(any(test, feature = "test-support"))]
pub async fn get_group_join_request_status_impl(
    state: &AppState,
    group_id: String,
    request_id: String,
) -> Result<GroupJoinStatusView, String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }
    if request_id.trim().is_empty() {
        return Err("request_id must not be empty".into());
    }

    drive_core_without_handle(
        state,
        CoreInput::Command(CoreCommand::GetGroupJoinRequestStatus {
            group_id: group_id.clone(),
            request_id: request_id.clone(),
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    let inner = state.inner.read().await;
    let snapshot = inner.engine.refresh_snapshot();

    let persisted = snapshot
        .group_join_requests
        .iter()
        .find(|persisted| persisted.group_id == group_id && persisted.request_id == request_id)
        .ok_or_else(|| format!("join request '{request_id}' not found for group '{group_id}'"))?;

    let group_imported = snapshot
        .group_states
        .iter()
        .any(|st| st.group_id == group_id);

    let welcome_pickup = persisted
        .welcome_pickup
        .as_ref()
        .map(WelcomePickupShareable::from);

    Ok(GroupJoinStatusView {
        group_id: persisted.group_id.clone(),
        request_id: persisted.request_id.clone(),
        status: group_join_status_str(persisted.request.status).into(),
        group_imported,
        welcome_pickup,
    })
}

#[cfg(any(test, feature = "test-support"))]
pub async fn approve_group_join_impl(
    state: &AppState,
    group_id: String,
    request_id: String,
) -> Result<ApproveGroupJoinResult, String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }
    if request_id.trim().is_empty() {
        return Err("request_id must not be empty".into());
    }

    drive_core_without_handle(
        state,
        CoreInput::Command(CoreCommand::ListGroupJoinRequests {
            group_id: group_id.clone(),
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    let output = match drive_core_without_handle(
        state,
        CoreInput::Command(CoreCommand::ApproveGroupJoin {
            group_id: group_id.clone(),
            request_id: request_id.clone(),
        }),
    )
    .await
    {
        Ok(output) => output,
        Err(error) => {
            let detail = error.to_string();
            if detail.contains("already_member") {
                return Ok(ApproveGroupJoinResult {
                    group_id,
                    request_id,
                    status: "already_member".into(),
                    welcome_pickups: Vec::new(),
                });
            }
            return Err(detail);
        }
    };

    let welcome_pickups: Vec<WelcomePickupShareable> = output
        .view_model
        .as_ref()
        .map(|vm| {
            vm.welcome_pickups
                .iter()
                .map(WelcomePickupShareable::from)
                .collect()
        })
        .unwrap_or_default();

    Ok(ApproveGroupJoinResult {
        group_id,
        request_id,
        status: "approved".into(),
        welcome_pickups,
    })
}

#[cfg(any(test, feature = "test-support"))]
pub async fn reject_group_join_impl(
    state: &AppState,
    group_id: String,
    request_id: String,
    reason: Option<String>,
) -> Result<(), String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }
    if request_id.trim().is_empty() {
        return Err("request_id must not be empty".into());
    }
    drive_core_without_handle(
        state,
        CoreInput::Command(CoreCommand::RejectGroupJoin {
            group_id,
            request_id,
            reason,
        }),
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(any(test, feature = "test-support"))]
pub async fn leave_group_impl(state: &AppState, group_id: String) -> Result<(), String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }
    drive_core_without_handle(
        state,
        CoreInput::Command(CoreCommand::LeaveGroup { group_id }),
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(any(test, feature = "test-support"))]
pub async fn list_group_leave_requests_impl(
    state: &AppState,
    group_id: String,
) -> Result<Vec<GroupLeaveRequestView>, String> {
    let output = drive_core_without_handle(
        state,
        CoreInput::Command(CoreCommand::ListGroupLeaveRequests { group_id }),
    )
    .await
    .map_err(|error| error.to_string())?;
    Ok(output
        .view_model
        .map(|view| {
            view.group_leave_requests
                .iter()
                .map(GroupLeaveRequestView::from)
                .collect()
        })
        .unwrap_or_default())
}

#[cfg(any(test, feature = "test-support"))]
pub async fn approve_group_leave_impl(
    state: &AppState,
    group_id: String,
    request_id: String,
) -> Result<(), String> {
    list_group_leave_requests_impl(state, group_id.clone()).await?;
    drive_core_without_handle(
        state,
        CoreInput::Command(CoreCommand::ApproveGroupLeave {
            group_id,
            request_id,
        }),
    )
    .await
    .map_err(|error| error.to_string())?;
    Ok(())
}

#[cfg(any(test, feature = "test-support"))]
pub async fn remove_group_member_impl(
    state: &AppState,
    group_id: String,
    target_user_id: String,
) -> Result<(), String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }
    if target_user_id.trim().is_empty() {
        return Err("target_user_id must not be empty".into());
    }
    drive_core_without_handle(
        state,
        CoreInput::Command(CoreCommand::RemoveGroupMember {
            group_id,
            target_user_id,
        }),
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(any(test, feature = "test-support"))]
pub async fn transfer_group_ownership_impl(
    state: &AppState,
    group_id: String,
    new_owner_user_id: String,
) -> Result<(), String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }
    if new_owner_user_id.trim().is_empty() {
        return Err("new_owner_user_id must not be empty".into());
    }
    drive_core_without_handle(
        state,
        CoreInput::Command(CoreCommand::TransferGroupOwnership {
            group_id,
            new_owner_user_id,
        }),
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(any(test, feature = "test-support"))]
pub async fn set_group_admin_impl(
    state: &AppState,
    group_id: String,
    target_user_id: String,
    is_admin: bool,
) -> Result<(), String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }
    if target_user_id.trim().is_empty() {
        return Err("target_user_id must not be empty".into());
    }
    drive_core_without_handle(
        state,
        CoreInput::Command(CoreCommand::SetGroupAdmin {
            group_id,
            target_user_id,
            is_admin,
        }),
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(any(test, feature = "test-support"))]
pub async fn update_group_metadata_impl(
    state: &AppState,
    group_id: String,
    title: Option<String>,
    join_policy: Option<String>,
    member_invite_policy: Option<String>,
) -> Result<UpdateGroupMetadataResult, String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }
    if title.is_none() && join_policy.is_none() && member_invite_policy.is_none() {
        return Err(
            "at least one field (title, join_policy, member_invite_policy) must be supplied".into(),
        );
    }
    let parsed_join_policy = join_policy.as_deref().map(parse_join_policy).transpose()?;
    let parsed_member_invite_policy = member_invite_policy
        .as_deref()
        .map(parse_member_invite_policy)
        .transpose()?;
    let trimmed_title = title.map(|s| s.trim().to_string());
    if let Some(ref t) = trimmed_title {
        if t.is_empty() {
            return Err("title must not be whitespace-only".into());
        }
    }

    drive_core_without_handle(
        state,
        CoreInput::Command(CoreCommand::UpdateGroupMetadata {
            group_id: group_id.clone(),
            title: trimmed_title,
            join_policy: parsed_join_policy,
            member_invite_policy: parsed_member_invite_policy,
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    let inner = state.inner.read().await;
    let snapshot = inner.engine.refresh_snapshot();
    let manifest = snapshot
        .group_states
        .iter()
        .find(|st| st.group_id == group_id)
        .map(|st| st.manifest.clone())
        .ok_or_else(|| format!("group '{group_id}' not found after update"))?;

    Ok(UpdateGroupMetadataResult {
        group_id,
        title: Some(manifest.title),
        join_policy: Some(manifest.join_policy),
        member_invite_policy: Some(manifest.member_invite_policy),
        roster_version: Some(manifest.roster_version),
    })
}

#[cfg(any(test, feature = "test-support"))]
pub async fn dissolve_group_impl(
    state: &AppState,
    group_id: String,
) -> Result<DissolveGroupResult, String> {
    if group_id.trim().is_empty() {
        return Err("group_id must not be empty".into());
    }

    drive_core_without_handle(
        state,
        CoreInput::Command(CoreCommand::DissolveGroup {
            group_id: group_id.clone(),
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    let inner = state.inner.read().await;
    let snapshot = inner.engine.refresh_snapshot();
    let group = snapshot
        .group_states
        .iter()
        .find(|st| st.group_id == group_id)
        .ok_or_else(|| format!("group '{group_id}' not found after dissolve"))?;
    let conversation_state = snapshot
        .conversations
        .iter()
        .find(|c| c.conversation_id == group.conversation_id)
        .map(|c| conversation_state_string(c.state.conversation.state))
        .unwrap_or_else(|| "active".into());
    let pending_group_outbox = snapshot
        .pending_group_outbox
        .iter()
        .filter(|item| item.envelope.group_id == group_id)
        .count();

    Ok(DissolveGroupResult {
        group_id: group.group_id.clone(),
        conversation_id: Some(group.conversation_id.clone()),
        dissolved_at: group.dissolved_at,
        conversation_state,
        pending_group_outbox,
    })
}

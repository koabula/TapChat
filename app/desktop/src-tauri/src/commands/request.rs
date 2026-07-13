use tapchat_core::conversation::RecoveryStatus;
use tapchat_core::ffi_api::{CoreViewModel, MessageRequestActionSummary};
use tapchat_core::model::{ConversationKind, ConversationState};
use tapchat_core::persistence::ContactRelationshipStatus;
use tapchat_core::transport_contract::MessageRequestAction;
use tapchat_core::{CoreCommand, CoreOutput, CoreStateUpdate};
use tauri::{AppHandle, Emitter, State};

use crate::lifecycle::{drive_core_with_handle, CoreInput};
use crate::platform::log_sanitize::redact_id;
use crate::runtime_auth::ensure_fresh_device_runtime_auth_for_state;
use crate::state::AppState;

/// View model for message request action returned to frontend.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MessageRequestActionOutput {
    pub accepted: bool,
    pub request_id: String,
    pub sender_user_id: String,
    pub action: String,
    pub contact_available: bool,
    pub conversation_available: bool,
    pub auto_created_conversation: bool,
    pub conversation_id: Option<String>,
}

#[tauri::command]
pub async fn list_message_requests(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CoreOutput, String> {
    ensure_fresh_device_runtime_auth_for_state(state.inner())
        .await
        .map_err(|error| error.to_string())?;
    drive_core_with_handle(&app, CoreInput::Command(CoreCommand::ListMessageRequests))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn act_on_message_request(
    app: AppHandle,
    state: State<'_, AppState>,
    request_id: String,
    action: String,
    sender_bundle_share_url: Option<String>,
) -> Result<MessageRequestActionOutput, String> {
    let action_enum = match action.as_str() {
        "accept" => MessageRequestAction::Accept,
        "reject" => MessageRequestAction::Reject,
        _ => return Err("Invalid action: must be 'accept' or 'reject'".into()),
    };

    match action_enum {
        MessageRequestAction::Accept => {
            ensure_fresh_device_runtime_auth_for_state(state.inner())
                .await
                .map_err(|error| error.to_string())?;
            let sender_bundle_share_url = match sender_bundle_share_url {
                Some(url) if !url.trim().is_empty() => url,
                _ => {
                    let output = drive_core_with_handle(
                        &app,
                        CoreInput::Command(CoreCommand::ListMessageRequests),
                    )
                    .await
                    .map_err(|e| e.to_string())?;
                    output
                        .view_model
                        .and_then(|vm| {
                            vm.message_requests
                                .into_iter()
                                .find(|request| request.request_id == request_id)
                        })
                        .and_then(|request| request.sender_bundle_share_url)
                        .ok_or_else(|| {
                            "sender bundle share url is missing; cannot safely accept this request"
                                .to_string()
                        })?
                }
            };

            let approval = state.ports.lock().await.take_external_url_approval(
                tapchat_core::external_fetch::ExternalResourceKind::ContactShare,
            );
            let sender_bundle =
                tapchat_core::contact_workflows::fetch_identity_bundle_from_url_with_approval(
                    &sender_bundle_share_url,
                    approval,
                )
                .await
                .map_err(|error| error.to_string())?;
            let imported_sender_user_id = sender_bundle.user_id.clone();

            drive_core_with_handle(
                &app,
                CoreInput::Command(CoreCommand::ImportIdentityBundleWithRelationshipStatus {
                    bundle: sender_bundle,
                    relationship_status: ContactRelationshipStatus::Available,
                }),
            )
            .await
            .map_err(|e| e.to_string())?;

            let output = drive_core_with_handle(
                &app,
                CoreInput::Command(CoreCommand::ActOnMessageRequest {
                    request_id: request_id.clone(),
                    action: MessageRequestAction::Accept,
                }),
            )
            .await
            .map_err(|e| e.to_string())?;

            let action_summary = output
                .view_model
                .as_ref()
                .and_then(|vm| vm.message_request_action.clone())
                .ok_or("Message request action result not returned")?;
            let sender_user_id = if action_summary.sender_user_id.is_empty() {
                imported_sender_user_id
            } else {
                action_summary.sender_user_id.clone()
            };

            let (contact_available, conversation_id) = {
                let inner = state.inner.read().await;
                let snapshot = inner.engine.refresh_snapshot();
                let contact_available = snapshot.contacts.iter().any(|contact| {
                    contact.user_id == sender_user_id
                        && contact.relationship_status == ContactRelationshipStatus::Available
                });
                let conversation_id = snapshot
                    .conversations
                    .iter()
                    .filter(|conversation| {
                        conversation.state.peer_user_id == sender_user_id
                            && conversation.state.conversation.kind == ConversationKind::Direct
                            && conversation.state.recovery_status == RecoveryStatus::Healthy
                            && matches!(
                                conversation.state.conversation.state,
                                ConversationState::Active
                            )
                            && snapshot
                                .mls_states
                                .iter()
                                .any(|state| state.conversation_id == conversation.conversation_id)
                    })
                    .max_by_key(|conversation| {
                        (
                            conversation.state.recovery_status == RecoveryStatus::Healthy,
                            conversation.state.conversation.updated_at,
                        )
                    })
                    .map(|conversation| conversation.conversation_id.clone());
                (contact_available, conversation_id)
            };

            if action_summary.accepted && !contact_available {
                return Err(format!(
                    "accepted request but sender contact was not available for {sender_user_id}"
                ));
            }

            if action_summary.accepted && conversation_id.is_none() {
                log::warn!(
                    "[act_on_message_request] accepted request {} from {} but no conversation is available yet",
                    redact_id("request", &request_id),
                    redact_id("user", &sender_user_id)
                );
            }

            let _ = app.emit(
                "core-update",
                CoreOutput {
                    state_update: CoreStateUpdate {
                        contacts_changed: true,
                        conversations_changed: conversation_id.is_some(),
                        messages_changed: true,
                        ..CoreStateUpdate::default()
                    },
                    effects: vec![],
                    view_model: Some(CoreViewModel {
                        message_request_action: Some(MessageRequestActionSummary {
                            accepted: action_summary.accepted,
                            request_id: action_summary.request_id.clone(),
                            sender_user_id: sender_user_id.clone(),
                            promoted_count: action_summary.promoted_count,
                            action: MessageRequestAction::Accept,
                        }),
                        ..CoreViewModel::default()
                    }),
                },
            );

            Ok(MessageRequestActionOutput {
                accepted: action_summary.accepted,
                request_id: action_summary.request_id,
                sender_user_id,
                action: "accept".to_string(),
                contact_available,
                conversation_available: conversation_id.is_some(),
                auto_created_conversation: false,
                conversation_id,
            })
        }
        MessageRequestAction::Reject => {
            ensure_fresh_device_runtime_auth_for_state(state.inner())
                .await
                .map_err(|error| error.to_string())?;
            // For reject, use the normal CoreCommand flow
            let output = drive_core_with_handle(
                &app,
                CoreInput::Command(CoreCommand::ActOnMessageRequest {
                    request_id,
                    action: MessageRequestAction::Reject,
                }),
            )
            .await
            .map_err(|e| e.to_string())?;

            // Extract result from output
            let action_summary = output
                .view_model
                .and_then(|vm| vm.message_request_action)
                .ok_or("Message request action result not returned")?;

            Ok(MessageRequestActionOutput {
                accepted: action_summary.accepted,
                request_id: action_summary.request_id,
                sender_user_id: action_summary.sender_user_id,
                action: "reject".to_string(),
                contact_available: false,
                conversation_available: false,
                auto_created_conversation: false,
                conversation_id: None,
            })
        }
    }
}

#[tauri::command]
pub async fn get_allowlist(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CoreOutput, String> {
    ensure_fresh_device_runtime_auth_for_state(state.inner())
        .await
        .map_err(|error| error.to_string())?;
    drive_core_with_handle(&app, CoreInput::Command(CoreCommand::ListAllowlist))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn add_to_allowlist(
    app: AppHandle,
    state: State<'_, AppState>,
    user_id: String,
) -> Result<CoreOutput, String> {
    ensure_fresh_device_runtime_auth_for_state(state.inner())
        .await
        .map_err(|error| error.to_string())?;
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::AddAllowlistUser { user_id }),
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn remove_from_allowlist(
    app: AppHandle,
    state: State<'_, AppState>,
    user_id: String,
) -> Result<CoreOutput, String> {
    ensure_fresh_device_runtime_auth_for_state(state.inner())
        .await
        .map_err(|error| error.to_string())?;
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::RemoveAllowlistUser { user_id }),
    )
    .await
    .map_err(|e| e.to_string())
}

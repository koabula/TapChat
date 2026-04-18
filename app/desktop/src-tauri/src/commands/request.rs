use tauri::{AppHandle, Emitter, State};
use tapchat_core::{CoreCommand, CoreOutput, CoreStateUpdate, CoreEngine};
use tapchat_core::transport_contract::MessageRequestAction;
use tapchat_core::ffi_api::{CoreViewModel, MessageRequestActionSummary};

use crate::lifecycle::{CoreInput, drive_core_with_handle};
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
) -> Result<CoreOutput, String> {
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::ListMessageRequests),
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn act_on_message_request(
    app: AppHandle,
    state: State<'_, AppState>,
    request_id: String,
    action: String,
) -> Result<MessageRequestActionOutput, String> {
    let action_enum = match action.as_str() {
        "accept" => MessageRequestAction::Accept,
        "reject" => MessageRequestAction::Reject,
        _ => return Err("Invalid action: must be 'accept' or 'reject'".into()),
    };

    // Get profile path from state
    let profile_path = {
        let inner = state.inner.read().await;
        inner.profile_path.clone()
    };

    match action_enum {
        MessageRequestAction::Accept => {
            // Accept through the desktop helper so we import the sender bundle
            // and sync promoted inbox records before the UI navigates.
            let profile_path = profile_path.ok_or("Profile path not set")?;

            let result = tapchat_core::desktop_app::message_request_accept(
                profile_path,
                &request_id,
            )
            .await
            .map_err(|e| e.to_string())?;

            // Reload engine from profile to sync memory state with disk
            {
                let mut inner = state.inner.write().await;

                // Load fresh snapshot from disk via ProfileManager
                let snapshot = inner.profile_manager.load_snapshot()
                    .await
                    .map_err(|e| e.to_string())?;

                // Reinitialize engine from updated snapshot
                inner.engine = CoreEngine::from_restored_state(snapshot);

                log::info!(
                    "[act_on_message_request] Reloaded engine: {} conversations, {} contacts",
                    inner.engine.refresh_snapshot().conversations.len(),
                    inner.engine.refresh_snapshot().contacts.len()
                );
            }

            // Emit core-update to refresh frontend state
            let _ = app.emit("core-update", CoreOutput {
                state_update: CoreStateUpdate {
                    contacts_changed: true,
                    conversations_changed: result.conversation_available,
                    ..CoreStateUpdate::default()
                },
                effects: vec![],
                view_model: Some(CoreViewModel {
                    message_request_action: Some(MessageRequestActionSummary {
                        accepted: result.accepted,
                        request_id: result.request_id.clone(),
                        sender_user_id: result.sender_user_id.clone(),
                        promoted_count: result.promoted_count,
                        action: MessageRequestAction::Accept,
                    }),
                    ..CoreViewModel::default()
                }),
            });

            Ok(MessageRequestActionOutput {
                accepted: result.accepted,
                request_id: result.request_id,
                sender_user_id: result.sender_user_id,
                action: "accept".to_string(),
                contact_available: result.contact_available,
                conversation_available: result.conversation_available,
                auto_created_conversation: result.auto_created_conversation,
                conversation_id: result.conversation_id,
            })
        }
        MessageRequestAction::Reject => {
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
            let action_summary = output.view_model
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
) -> Result<CoreOutput, String> {
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::ListAllowlist),
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn add_to_allowlist(
    app: AppHandle,
    user_id: String,
) -> Result<CoreOutput, String> {
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
    user_id: String,
) -> Result<CoreOutput, String> {
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::RemoveAllowlistUser { user_id }),
    )
    .await
    .map_err(|e| e.to_string())
}

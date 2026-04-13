use tauri::State;

use tapchat_core::{CoreCommand, CoreOutput};
use tapchat_core::ffi_api::{ContactSummary, ConversationSummary};
use tapchat_core::model::ConversationKind;

use crate::lifecycle::{CoreInput, drive_core_with_handle};
use crate::state::AppState;

#[tauri::command]
pub async fn list_conversations(
    state: State<'_, AppState>,
) -> Result<Vec<ConversationSummary>, String> {
    let inner = state.inner.read().await;

    // Get snapshot from engine which contains all conversations
    let snapshot = inner.engine.refresh_snapshot();

    // Build conversation summaries from snapshot
    let summaries: Vec<ConversationSummary> = snapshot.conversations
        .iter()
        .map(|persisted| {
            ConversationSummary {
                conversation_id: persisted.conversation_id.clone(),
                state: format!("{:?}", persisted.state.conversation.state).to_lowercase(),
                last_message_type: persisted.state.last_message_type,
                recovery: None, // TODO: add recovery diagnostics if needed
            }
        })
        .collect();

    Ok(summaries)
}

#[tauri::command]
pub async fn create_conversation(
    app: tauri::AppHandle,
    peer_user_id: String,
) -> Result<CoreOutput, String> {
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::CreateConversation {
            peer_user_id,
            conversation_kind: ConversationKind::Direct,
        }),
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_messages(
    state: State<'_, AppState>,
    conversation_id: String,
) -> Result<Vec<serde_json::Value>, String> {
    let inner = state.inner.read().await;

    // Get snapshot to find the conversation
    let snapshot = inner.engine.refresh_snapshot();

    // Find the conversation and extract messages
    let messages: Vec<serde_json::Value> = snapshot.conversations
        .iter()
        .find(|c| c.conversation_id == conversation_id)
        .map(|persisted| {
            persisted.state.messages.iter()
                .map(|msg| serde_json::json!({
                    "message_id": msg.message_id,
                    "sender_device_id": msg.sender_device_id,
                    "recipient_device_id": msg.recipient_device_id,
                    "message_type": format!("{:?}", msg.message_type).to_lowercase(),
                    "created_at": msg.created_at,
                    "plaintext": msg.plaintext,
                    "has_attachment": !msg.storage_refs.is_empty(),
                }))
                .collect()
        })
        .unwrap_or_default();

    Ok(messages)
}
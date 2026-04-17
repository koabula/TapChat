use serde::Serialize;
use tauri::State;

use tapchat_core::CoreCommand;
use tapchat_core::ffi_api::ConversationSummary;
use tapchat_core::model::ConversationKind;

use crate::lifecycle::{CoreInput, drive_core_with_handle};
use crate::state::AppState;

/// Simplified result for create_conversation command
#[derive(Debug, Clone, Serialize)]
pub struct CreateConversationResult {
    pub conversation_id: String,
}

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
                peer_user_id: persisted.state.peer_user_id.clone(),
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
) -> Result<CreateConversationResult, String> {
    let output = drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::CreateConversation {
            peer_user_id,
            conversation_kind: ConversationKind::Direct,
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    // Extract conversation_id from CoreOutput view_model
    let conversation_id = output
        .view_model
        .and_then(|vm| vm.conversations.first().map(|c| c.conversation_id.clone()))
        .ok_or_else(|| "Failed to get conversation_id from response".to_string())?;

    Ok(CreateConversationResult { conversation_id })
}

#[tauri::command]
pub async fn get_messages(
    state: State<'_, AppState>,
    conversation_id: String,
) -> Result<Vec<serde_json::Value>, String> {
    let inner = state.inner.read().await;

    // Get snapshot to find the conversation and local device_id
    let snapshot = inner.engine.refresh_snapshot();

    // Get local device_id to determine message direction
    let local_device_id = snapshot.local_identity
        .as_ref()
        .map(|li| li.state.device_identity.device_id.clone());

    // Find the conversation and extract messages
    let conversation_messages: Vec<serde_json::Value> = snapshot.conversations
        .iter()
        .find(|c| c.conversation_id == conversation_id)
        .map(|persisted| {
            persisted.state.messages.iter()
                .map(|msg| {
                    // Determine if this is a sent or received message
                    let direction = if local_device_id.as_ref() == Some(&msg.sender_device_id) {
                        "sent"
                    } else {
                        "received"
                    };
                    serde_json::json!({
                        "message_id": msg.message_id,
                        "sender_device_id": msg.sender_device_id,
                        "recipient_device_id": msg.recipient_device_id,
                        "message_type": direction,
                        "created_at": msg.created_at,
                        "plaintext": msg.plaintext,
                        "has_attachment": !msg.storage_refs.is_empty(),
                        "storage_refs": msg.storage_refs,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    // Merge pending outbox messages (sent but not yet acked)
    // These are outgoing messages that haven't been confirmed yet
    let outbox_messages: Vec<serde_json::Value> = snapshot.pending_outbox
        .iter()
        .filter(|env| env.envelope.conversation_id == conversation_id)
        .filter_map(|env| {
            // Only include if not already in conversation messages
            let already_exists = conversation_messages.iter()
                .any(|msg| msg["message_id"] == env.envelope.message_id);
            if already_exists {
                return None;
            }
            // This is an outgoing message
            Some(serde_json::json!({
                "message_id": env.envelope.message_id,
                "sender_device_id": env.envelope.sender_device_id,
                "recipient_device_id": env.envelope.recipient_device_id,
                "message_type": "sent",
                "created_at": env.envelope.created_at,
                "plaintext": env.plaintext_cache, // Use cached plaintext if available
                "has_attachment": !env.envelope.storage_refs.is_empty(),
                "storage_refs": env.envelope.storage_refs,
            }))
        })
        .collect();

    // Combine and sort by created_at
    let mut all_messages: Vec<serde_json::Value> = conversation_messages;
    all_messages.extend(outbox_messages);
    all_messages.sort_by_key(|msg| msg["created_at"].as_u64().unwrap_or(0));

    Ok(all_messages)
}
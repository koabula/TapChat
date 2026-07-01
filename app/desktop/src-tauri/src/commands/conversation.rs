use std::collections::BTreeMap;

use serde::Serialize;
use tauri::State;

use tapchat_core::conversation::RecoveryStatus;
use tapchat_core::ffi_api::ConversationSummary;
use tapchat_core::model::{ConversationKind, ConversationState};
use tapchat_core::CoreCommand;

use super::conversation_view::{
    application_plaintext_message_count, generate_last_message_preview, summarize_plaintext,
};
use crate::lifecycle::{drive_core_with_handle, CoreInput};
use crate::state::{AppState, SessionState};

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
    let recovery_by_conversation: BTreeMap<_, _> = inner
        .engine
        .recovery_conversations_snapshot()
        .into_iter()
        .map(|diagnostics| (diagnostics.conversation_id.clone(), diagnostics))
        .collect();
    let snapshot = inner.engine.refresh_snapshot();

    // Build conversation summaries from snapshot
    let summaries: Vec<ConversationSummary> = snapshot
        .conversations
        .iter()
        .map(|persisted| ConversationSummary {
            conversation_id: persisted.conversation_id.clone(),
            peer_user_id: persisted.state.peer_user_id.clone(),
            state: match persisted.state.conversation.state {
                ConversationState::Active => match persisted.state.recovery_status {
                    RecoveryStatus::Healthy => "active".into(),
                    RecoveryStatus::NeedsRecovery => "needs_recovery".into(),
                    RecoveryStatus::NeedsRebuild => "needs_rebuild".into(),
                },
                ConversationState::NeedsRebuild => "needs_rebuild".into(),
                ConversationState::Closed => "closed".into(),
                ConversationState::Archived => "archived".into(),
                ConversationState::Dissolved => "dissolved".into(),
            },
            kind: Some(persisted.state.conversation.kind),
            title: None,
            display_name: persisted
                .state
                .archive_metadata
                .as_ref()
                .and_then(|metadata| metadata.peer_display_name.clone()),
            group_id: None,
            member_count: None,
            group_role: None,
            group_cursor: None,
            last_message_preview: generate_last_message_preview(&persisted.state.messages),
            last_message_type: persisted.state.last_message_type,
            message_count: Some(application_plaintext_message_count(
                &persisted.state.messages,
            )),
            recovery: recovery_by_conversation
                .get(&persisted.conversation_id)
                .cloned(),
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
pub async fn recover_conversation(
    app: tauri::AppHandle,
    conversation_id: String,
) -> Result<tapchat_core::CoreOutput, String> {
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::ReconcileConversationMembership { conversation_id }),
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

    // Get snapshot to find the conversation and local device_id
    let snapshot = inner.engine.refresh_snapshot();

    // Get local device_id to determine message direction
    // Primary source: local_identity from snapshot
    // Fallback: device_id from session state (set during profile switch/startup)
    let local_device_id = snapshot
        .local_identity
        .as_ref()
        .map(|li| li.state.device_identity.device_id.clone())
        .or_else(|| {
            // Fallback to session state device_id
            match &inner.session {
                SessionState::Active { device_id } => Some(device_id.clone()),
                _ => None,
            }
        });

    // Log for debugging
    log::debug!(
        "get_messages: conversation_id={}, local_device_id={}, messages_count={}",
        conversation_id,
        local_device_id.as_deref().unwrap_or("NONE"),
        snapshot
            .conversations
            .iter()
            .find(|c| c.conversation_id == conversation_id)
            .map(|p| p.state.messages.len())
            .unwrap_or(0)
    );

    // Find the conversation and extract messages
    // Filter out MLS protocol messages (Welcome, Commit) - they have no plaintext and shouldn't be displayed
    let conversation_messages: Vec<serde_json::Value> = snapshot
        .conversations
        .iter()
        .find(|c| c.conversation_id == conversation_id)
        .map(|persisted| {
            persisted
                .state
                .messages
                .iter()
                .filter(|msg| {
                    // Show application messages plus direct lifecycle system
                    // messages that carry plaintext. MLS protocol messages
                    // remain hidden.
                    (matches!(
                        msg.message_type,
                        tapchat_core::model::MessageType::MlsApplication
                    ) && msg.plaintext.is_some())
                        || (msg.plaintext.is_some()
                            && matches!(
                                msg.message_type,
                                tapchat_core::model::MessageType::ControlContactRemoved
                                    | tapchat_core::model::MessageType::ControlIdentityStateUpdated
                            ))
                })
                .map(|msg| {
                    // Log plaintext status for debugging
                    log::debug!(
                        "get_messages: message_id={}, message_type={:?}, {}",
                        msg.message_id,
                        msg.message_type,
                        summarize_plaintext(msg.plaintext.as_deref())
                    );
                    // Determine if this is a sent or received message
                    let direction = if matches!(
                        msg.message_type,
                        tapchat_core::model::MessageType::ControlContactRemoved
                            | tapchat_core::model::MessageType::ControlIdentityStateUpdated
                    ) {
                        "system"
                    } else if local_device_id.as_ref() == Some(&msg.sender_device_id) {
                        "sent"
                    } else {
                        "received"
                    };
                    serde_json::json!({
                        "message_id": msg.message_id,
                        "sender_device_id": msg.sender_device_id,
                        "recipient_device_id": msg.recipient_device_id,
                        "message_type": direction,
                        "raw_message_type": format!("{:?}", msg.message_type).to_lowercase(),
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
    // All pending outbox messages are MlsApplication type (actual user messages)
    let outbox_messages: Vec<serde_json::Value> = snapshot
        .pending_outbox
        .iter()
        .filter(|env| env.envelope.conversation_id == conversation_id)
        .filter(|env| {
            matches!(
                env.envelope.message_type,
                tapchat_core::model::MessageType::MlsApplication
            )
        })
        .filter_map(|env| {
            // Only include if not already in conversation messages
            let already_exists = conversation_messages
                .iter()
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
                "raw_message_type": "mls_application",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarize_plaintext_never_includes_plaintext_contents() {
        let summary = summarize_plaintext(Some("hello secret world"));
        assert_eq!(summary, "has_plaintext=true plaintext_len=18");
        assert!(!summary.contains("hello"));
        assert!(!summary.contains("secret"));
    }
}

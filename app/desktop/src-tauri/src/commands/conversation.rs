use std::collections::BTreeMap;

use serde::Serialize;
use tauri::State;

use tapchat_core::attachment_crypto::{AttachmentKind, AttachmentManifestV2};
use tapchat_core::conversation::RecoveryStatus;
use tapchat_core::ffi_api::ConversationSummary;
use tapchat_core::model::{ConversationKind, ConversationState, StorageRef};
use tapchat_core::{CoreCommand, ErrorDomain};

use super::conversation_view::{generate_last_message_preview, summarize_plaintext};
use crate::errors::{DesktopError, DesktopResult};
use crate::lifecycle::{drive_core_with_handle, CoreInput};
use crate::state::{AppState, SessionState};

/// Simplified result for create_conversation command
#[derive(Debug, Clone, Serialize)]
pub struct CreateConversationResult {
    pub conversation_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MessagePage {
    pub items: Vec<MessageView>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageDirection {
    Sent,
    Received,
    System,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageDeliveryState {
    Sending,
    Sent,
    PendingApproval,
    Failed,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageAttachmentState {
    Pending,
    Published,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttachmentManifestView {
    pub version: u32,
    pub attachment_id: String,
    pub kind: AttachmentKind,
    pub file_name: Option<String>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub blur_hash: Option<String>,
    pub mime_type: String,
    pub size_bytes: u64,
    pub preview_available: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct MessageView {
    pub message_id: String,
    pub sender_device_id: String,
    pub recipient_device_id: String,
    pub message_type: MessageDirection,
    pub raw_message_type: String,
    pub created_at: u64,
    pub plaintext: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachment_manifest: Option<AttachmentManifestView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachment_state: Option<MessageAttachmentState>,
    pub has_attachment: bool,
    pub storage_refs: Vec<StorageRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery_state: Option<MessageDeliveryState>,
}

#[tauri::command]
pub async fn list_conversations(
    state: State<'_, AppState>,
) -> crate::errors::DesktopResult<Vec<ConversationSummary>> {
    let inner = state.inner.read().await;

    // Get snapshot from engine which contains all conversations
    let recovery_by_conversation: BTreeMap<_, _> = inner
        .engine
        .recovery_conversations_snapshot()
        .into_iter()
        .map(|diagnostics| (diagnostics.conversation_id.clone(), diagnostics))
        .collect();
    let snapshot = inner.engine.refresh_snapshot();
    let message_summaries: BTreeMap<_, _> = {
        let pm = inner.profile_manager.inner.read().await;
        pm.active_profile
            .as_ref()
            .map(|profile| profile.load_conversation_message_summaries())
            .transpose()
            .map_err(|error| error.to_string())?
            .unwrap_or_default()
            .into_iter()
            .map(|summary| (summary.conversation_id.clone(), summary))
            .collect()
    };

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
            last_message_preview: message_summaries
                .get(&persisted.conversation_id)
                .and_then(|summary| summary.last_visible_message.as_ref())
                .and_then(|message| generate_last_message_preview(std::slice::from_ref(message))),
            last_message_type: persisted.state.last_message_type,
            message_count: message_summaries
                .get(&persisted.conversation_id)
                .map(|summary| summary.message_count.min(usize::MAX as u64) as usize),
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
) -> DesktopResult<CreateConversationResult> {
    let first = drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::CreateConversation {
            peer_user_id: peer_user_id.clone(),
            conversation_kind: ConversationKind::Direct,
        }),
    )
    .await;
    let output = match first {
        Ok(output) => output,
        Err(error)
            if error
                .downcast_ref::<tapchat_core::CoreError>()
                .is_some_and(|core| core.code() == "keypackage_expired") =>
        {
            if drive_core_with_handle(
                &app,
                CoreInput::Command(CoreCommand::RefreshIdentityState {
                    user_id: peer_user_id.clone(),
                }),
            )
            .await
            .is_err()
            {
                log::warn!("create_conversation: contact identity refresh did not produce a usable key package");
            }
            drive_core_with_handle(
                &app,
                CoreInput::Command(CoreCommand::CreateConversation {
                    peer_user_id,
                    conversation_kind: ConversationKind::Direct,
                }),
            )
            .await
            .map_err(DesktopError::from)?
        }
        Err(error) => return Err(DesktopError::from(error)),
    };

    // Extract conversation_id from CoreOutput view_model
    let conversation_id = output
        .view_model
        .and_then(|vm| vm.conversations.first().map(|c| c.conversation_id.clone()))
        .ok_or_else(|| DesktopError::new("invalid_state", ErrorDomain::Core, false))?;

    Ok(CreateConversationResult { conversation_id })
}

#[tauri::command]
pub async fn recover_conversation(
    app: tauri::AppHandle,
    conversation_id: String,
) -> crate::errors::DesktopResult<tapchat_core::CoreOutput> {
    Ok(drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::ReconcileConversationMembership { conversation_id }),
    )
    .await
    .map_err(crate::errors::DesktopError::from)?)
}

#[tauri::command]
pub async fn get_messages(
    state: State<'_, AppState>,
    conversation_id: String,
    before_cursor: Option<String>,
    limit: Option<usize>,
) -> crate::errors::DesktopResult<MessagePage> {
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

    let repository_page = {
        let pm = inner.profile_manager.inner.read().await;
        let profile = pm
            .active_profile
            .as_ref()
            .ok_or_else(|| "No active profile".to_string())?;
        profile
            .query_messages(&tapchat_core::local_store::MessageQuery {
                conversation_id: conversation_id.clone(),
                before_cursor: before_cursor.clone(),
                limit: limit.unwrap_or(50).clamp(1, 100),
            })
            .map_err(|error| error.to_string())?
    };

    // Log for debugging
    log::debug!(
        "get_messages: conversation_id={}, local_device_id={}, messages_count={}",
        conversation_id,
        local_device_id.as_deref().unwrap_or("NONE"),
        repository_page.messages.len()
    );

    // Find the conversation and extract messages
    // Filter out MLS protocol messages (Welcome, Commit) - they have no plaintext and shouldn't be displayed
    let conversation_messages: Vec<MessageView> = repository_page
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
            let logical_message_id = msg.app_message_id.as_deref().unwrap_or(&msg.message_id);
            let attachment_manifest = msg
                .plaintext
                .as_deref()
                .and_then(|plaintext| {
                    serde_json::from_str::<tapchat_core::attachment_crypto::AttachmentManifestV2>(
                        plaintext,
                    )
                    .ok()
                })
                .filter(|manifest| manifest.version == 2)
                .map(attachment_manifest_view);
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
                MessageDirection::System
            } else if local_device_id.as_ref() == Some(&msg.sender_device_id) {
                MessageDirection::Sent
            } else {
                MessageDirection::Received
            };
            let has_manifest = attachment_manifest.is_some();
            MessageView {
                message_id: logical_message_id.to_string(),
                sender_device_id: msg.sender_device_id.clone(),
                recipient_device_id: msg.recipient_device_id.clone(),
                message_type: direction,
                raw_message_type: format!("{:?}", msg.message_type).to_lowercase(),
                created_at: msg.created_at,
                plaintext: if has_manifest {
                    None
                } else {
                    msg.plaintext.clone()
                },
                attachment_manifest,
                attachment_state: has_manifest.then_some(MessageAttachmentState::Published),
                has_attachment: !msg.storage_refs.is_empty() || has_manifest,
                storage_refs: if has_manifest {
                    Vec::new()
                } else {
                    msg.storage_refs.clone()
                },
                delivery_state: matches!(direction, MessageDirection::Sent).then(|| {
                    match msg.delivery_state {
                        Some(tapchat_core::conversation::StoredMessageDeliveryState::Sending) => {
                            MessageDeliveryState::Sending
                        }
                        Some(
                            tapchat_core::conversation::StoredMessageDeliveryState::PendingApproval,
                        ) => MessageDeliveryState::PendingApproval,
                        Some(tapchat_core::conversation::StoredMessageDeliveryState::Failed) => {
                            MessageDeliveryState::Failed
                        }
                        _ => MessageDeliveryState::Sent,
                    }
                }),
            }
        })
        .collect();

    // Blob preparation happens before an envelope exists. Surface one local
    // placeholder per attachment message so reliable background retries are
    // visible instead of making the composer item disappear at 0%.
    let pending_attachment_messages: Vec<MessageView> = snapshot
        .pending_blob_transfers
        .iter()
        .filter_map(|transfer| match transfer {
            tapchat_core::persistence::PersistedPendingBlobTransfer::Upload {
                conversation_id: pending_conversation_id,
                message_id,
                created_at,
                descriptor,
                variant: tapchat_core::attachment_crypto::AttachmentVariant::Original,
                ..
            } if pending_conversation_id == &conversation_id
                && !snapshot
                    .pending_outbox
                    .iter()
                    .any(|item| item.envelope.message_id == *message_id) =>
            {
                Some(MessageView {
                    message_id: message_id.clone(),
                    sender_device_id: local_device_id.clone().unwrap_or_default(),
                    recipient_device_id: String::new(),
                    message_type: MessageDirection::Sent,
                    raw_message_type: "mls_application".into(),
                    created_at: *created_at,
                    plaintext: None,
                    attachment_manifest: Some(AttachmentManifestView {
                        version: 2,
                        attachment_id: message_id.clone(),
                        kind: if descriptor.mime_type.starts_with("image/") {
                            AttachmentKind::Image
                        } else if descriptor.mime_type.starts_with("video/") {
                            AttachmentKind::Video
                        } else if descriptor.mime_type.starts_with("audio/") {
                            AttachmentKind::Audio
                        } else {
                            AttachmentKind::File
                        },
                        file_name: descriptor.file_name.clone(),
                        width: descriptor.width,
                        height: descriptor.height,
                        blur_hash: descriptor.blur_hash.clone(),
                        mime_type: descriptor.mime_type.clone(),
                        size_bytes: descriptor.size_bytes,
                        preview_available: descriptor.preview.is_some(),
                    }),
                    attachment_state: Some(MessageAttachmentState::Pending),
                    has_attachment: true,
                    storage_refs: Vec::new(),
                    delivery_state: Some(if snapshot.pending_blob_transfers.iter().any(|candidate| matches!(candidate,
                        tapchat_core::persistence::PersistedPendingBlobTransfer::Upload {
                            message_id: candidate_message_id,
                            retries,
                            ..
                        } if candidate_message_id == message_id && *retries >= tapchat_core::ffi_api::MAX_TRANSPORT_RETRIES
                    )) {
                        MessageDeliveryState::Failed
                    } else {
                        MessageDeliveryState::Sending
                    }),
                })
            }
            _ => None,
        })
        .collect();

    // Merge pending outbox messages (sent but not yet acked)
    // These are outgoing messages that haven't been confirmed yet
    // All pending outbox messages are MlsApplication type (actual user messages)
    let outbox_messages: Vec<MessageView> = snapshot
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
            let logical_message_id = env
                .app_message_id
                .as_deref()
                .unwrap_or(&env.envelope.message_id);
            // Only include if not already in conversation messages
            let already_exists = conversation_messages
                .iter()
                .any(|msg| msg.message_id == logical_message_id);
            if already_exists {
                return None;
            }
            let attachment_manifest = env
                .plaintext_cache
                .as_deref()
                .and_then(|plaintext| {
                    serde_json::from_str::<tapchat_core::attachment_crypto::AttachmentManifestV2>(
                        plaintext,
                    )
                    .ok()
                })
                .filter(|manifest| manifest.version == 2)
                .map(attachment_manifest_view);
            let has_manifest = attachment_manifest.is_some();
            // This is an outgoing message
            Some(MessageView {
                message_id: logical_message_id.to_string(),
                sender_device_id: env.envelope.sender_device_id.clone(),
                recipient_device_id: env.envelope.recipient_device_id.clone(),
                message_type: MessageDirection::Sent,
                raw_message_type: "mls_application".into(),
                created_at: env.envelope.created_at,
                plaintext: if has_manifest {
                    None
                } else {
                    env.plaintext_cache.clone()
                },
                attachment_manifest,
                attachment_state: has_manifest.then_some(MessageAttachmentState::Published),
                has_attachment: !env.envelope.storage_refs.is_empty() || has_manifest,
                storage_refs: if has_manifest {
                    Vec::new()
                } else {
                    env.envelope.storage_refs.clone()
                },
                delivery_state: Some(
                    if env.retries >= tapchat_core::ffi_api::MAX_TRANSPORT_RETRIES {
                        MessageDeliveryState::Failed
                    } else {
                        MessageDeliveryState::Sending
                    },
                ),
            })
        })
        .collect();

    // Combine and sort by created_at
    // One logical attachment/text message may have one transport envelope per
    // recipient device. Collapse those envelopes and replace the upload
    // placeholder deterministically, with persisted conversation state taking
    // precedence over outbox state and outbox over the placeholder.
    let mut messages_by_id = BTreeMap::<String, MessageView>::new();
    let include_pending = before_cursor.is_none();
    for message in (include_pending
        .then_some(pending_attachment_messages)
        .into_iter()
        .flatten())
    .chain(
        include_pending
            .then_some(outbox_messages)
            .into_iter()
            .flatten(),
    )
    .chain(conversation_messages)
    {
        messages_by_id.insert(message.message_id.clone(), message);
    }
    let mut all_messages = messages_by_id.into_values().collect::<Vec<_>>();
    all_messages.sort_by_key(|message| message.created_at);

    Ok(MessagePage {
        items: all_messages,
        next_cursor: repository_page.next_cursor,
    })
}

pub(crate) fn attachment_manifest_view(manifest: AttachmentManifestV2) -> AttachmentManifestView {
    AttachmentManifestView {
        version: manifest.version,
        attachment_id: manifest.attachment_id,
        kind: manifest.kind,
        file_name: manifest.file_name,
        width: manifest.width,
        height: manifest.height,
        blur_hash: manifest.blur_hash,
        mime_type: manifest.original.mime_type,
        size_bytes: manifest.original.plaintext_size,
        preview_available: manifest.preview.is_some(),
    }
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

    #[test]
    fn typed_attachment_message_serializes_the_desktop_contract() {
        let message = MessageView {
            message_id: "msg:logical".into(),
            sender_device_id: "device:peer".into(),
            recipient_device_id: "device:local".into(),
            message_type: MessageDirection::Received,
            raw_message_type: "mls_application".into(),
            created_at: 42,
            plaintext: None,
            attachment_manifest: Some(AttachmentManifestView {
                version: 2,
                attachment_id: "attachment:1".into(),
                kind: AttachmentKind::Image,
                file_name: Some("photo.webp".into()),
                width: Some(640),
                height: Some(480),
                blur_hash: Some("LEHV6nWB2yk8pyo0adR*.7kCMdnj".into()),
                mime_type: "image/webp".into(),
                size_bytes: 123,
                preview_available: true,
            }),
            attachment_state: Some(MessageAttachmentState::Published),
            has_attachment: true,
            storage_refs: Vec::new(),
            delivery_state: None,
        };

        let value = serde_json::to_value(message).expect("message view should serialize");
        assert_eq!(value["message_id"], "msg:logical");
        assert_eq!(value["message_type"], "received");
        assert_eq!(value["attachment_state"], "published");
        assert_eq!(value["attachment_manifest"]["kind"], "image");
        assert!(value.get("delivery_state").is_none());
    }
}

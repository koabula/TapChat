use tauri::State;

use tapchat_core::ffi_api::ContactSummary;
use tapchat_core::model::ConversationKind;
use tapchat_core::persistence::{ContactRelationshipStatus, PersistedContact};
use tapchat_core::{CoreCommand, CoreOutput};

use crate::lifecycle::{drive_core_with_handle, CoreInput};
use crate::state::AppState;

#[derive(Debug, Clone, serde::Serialize)]
pub struct ContactLinkPreview {
    pub user_id: String,
    pub display_name: Option<String>,
    pub device_count: usize,
    pub link: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StartDirectChatResult {
    pub user_id: String,
    pub conversation_id: String,
    pub relationship_status: ContactRelationshipStatus,
    pub contact: ContactSummary,
}

fn contact_summary(persisted: &PersistedContact) -> ContactSummary {
    ContactSummary {
        user_id: persisted.user_id.clone(),
        display_name: persisted
            .display_name
            .clone()
            .or(persisted.original_name.clone()),
        device_count: persisted.bundle.devices.len(),
        relationship_status: persisted.relationship_status.clone(),
    }
}

async fn fetch_contact_bundle(
    state: &State<'_, AppState>,
    share_link: &str,
) -> Result<tapchat_core::model::IdentityBundle, String> {
    let approval = state.ports.lock().await.take_external_url_approval(
        tapchat_core::external_fetch::ExternalResourceKind::ContactShare,
    );
    tapchat_core::contact_workflows::fetch_identity_bundle_from_url_with_approval(
        share_link, approval,
    )
    .await
    .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn preview_contact_link(
    state: State<'_, AppState>,
    share_link: String,
) -> Result<ContactLinkPreview, String> {
    let link = share_link.trim().to_string();
    if link.is_empty() {
        return Err("share link must not be empty".into());
    }
    let bundle = fetch_contact_bundle(&state, &link).await?;
    Ok(ContactLinkPreview {
        user_id: bundle.user_id,
        display_name: bundle.display_name,
        device_count: bundle.devices.len(),
        link,
    })
}

#[tauri::command]
pub async fn start_direct_chat_from_link(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    share_link: String,
) -> Result<StartDirectChatResult, String> {
    let link = share_link.trim().to_string();
    if link.is_empty() {
        return Err("share link must not be empty".into());
    }
    let bundle = fetch_contact_bundle(&state, &link).await?;
    let user_id = bundle.user_id.clone();

    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::ImportIdentityBundleWithRelationshipStatus {
            bundle,
            relationship_status: ContactRelationshipStatus::PendingOutbound,
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    let output = drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::CreateConversation {
            peer_user_id: user_id.clone(),
            conversation_kind: ConversationKind::Direct,
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    let conversation_id = output
        .view_model
        .as_ref()
        .and_then(|vm| vm.conversations.first())
        .map(|conversation| conversation.conversation_id.clone())
        .ok_or_else(|| "failed to create or find direct conversation".to_string())?;

    let contact = {
        let inner = state.inner.read().await;
        let snapshot = inner.engine.refresh_snapshot();
        snapshot
            .contacts
            .iter()
            .find(|contact| contact.user_id == user_id)
            .map(contact_summary)
            .ok_or_else(|| "direct contact was not saved after starting chat".to_string())?
    };

    Ok(StartDirectChatResult {
        user_id,
        conversation_id,
        relationship_status: contact.relationship_status.clone(),
        contact,
    })
}

#[tauri::command]
pub async fn import_contact_by_link(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    share_link: String,
) -> Result<CoreOutput, String> {
    let link = share_link.trim().to_string();
    if link.is_empty() {
        return Err("share link must not be empty".into());
    }
    let bundle = fetch_contact_bundle(&state, &link).await?;

    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::ImportIdentityBundleWithRelationshipStatus {
            bundle,
            relationship_status: ContactRelationshipStatus::PendingOutbound,
        }),
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn list_contacts(state: State<'_, AppState>) -> Result<Vec<ContactSummary>, String> {
    let inner = state.inner.read().await;

    // Get snapshot from engine which contains all contacts
    let snapshot = inner.engine.refresh_snapshot();

    // Build contact summaries from snapshot
    let summaries: Vec<ContactSummary> = snapshot
        .contacts
        .iter()
        .filter(|contact| {
            !matches!(
                contact.relationship_status,
                ContactRelationshipStatus::RemovedByMe | ContactRelationshipStatus::RemovedByPeer
            )
        })
        .map(contact_summary)
        .collect();

    Ok(summaries)
}

#[tauri::command]
pub async fn refresh_contact(app: tauri::AppHandle, user_id: String) -> Result<CoreOutput, String> {
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::RefreshIdentityState { user_id }),
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn set_contact_display_name(
    app: tauri::AppHandle,
    user_id: String,
    display_name: Option<String>,
) -> Result<CoreOutput, String> {
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::SetContactDisplayName {
            user_id,
            display_name,
        }),
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn delete_contact(app: tauri::AppHandle, user_id: String) -> Result<CoreOutput, String> {
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::DeleteContact { user_id }),
    )
    .await
    .map_err(|e| e.to_string())
}

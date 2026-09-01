use tauri::State;

use tapchat_core::ffi_api::ContactSummary;
use tapchat_core::model::ConversationKind;
use tapchat_core::persistence::{ContactRelationshipStatus, PersistedContact};
use tapchat_core::{CoreCommand, CoreOutput};

use crate::lifecycle::{CoreInput, drive_core_with_handle};
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
        verified: persisted.is_verified(),
    }
}

async fn fetch_contact_bundle(
    share_link: &str,
) -> Result<tapchat_core::model::IdentityBundle, String> {
    tapchat_core::contact_workflows::fetch_identity_bundle_from_url(share_link)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn preview_contact_link(
    share_link: String,
) -> crate::errors::DesktopResult<ContactLinkPreview> {
    let link = share_link.trim().to_string();
    if link.is_empty() {
        return Err("share link must not be empty".into());
    }
    let bundle = fetch_contact_bundle(&link).await?;
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
) -> crate::errors::DesktopResult<StartDirectChatResult> {
    let link = share_link.trim().to_string();
    if link.is_empty() {
        return Err("share link must not be empty".into());
    }
    let bundle = fetch_contact_bundle(&link).await?;
    let user_id = bundle.user_id.clone();

    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::ImportIdentityBundleWithRelationshipStatus {
            bundle,
            relationship_status: ContactRelationshipStatus::PendingOutbound,
        }),
    )
    .await
    .map_err(crate::errors::DesktopError::from)?;

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
    share_link: String,
) -> crate::errors::DesktopResult<CoreOutput> {
    let link = share_link.trim().to_string();
    if link.is_empty() {
        return Err("share link must not be empty".into());
    }
    let bundle = fetch_contact_bundle(&link).await?;

    Ok(drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::ImportIdentityBundleWithRelationshipStatus {
            bundle,
            relationship_status: ContactRelationshipStatus::PendingOutbound,
        }),
    )
    .await
    .map_err(crate::errors::DesktopError::from)?)
}

#[tauri::command]
pub async fn list_contacts(
    state: State<'_, AppState>,
) -> crate::errors::DesktopResult<Vec<ContactSummary>> {
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
pub async fn refresh_contact(
    app: tauri::AppHandle,
    user_id: String,
) -> crate::errors::DesktopResult<CoreOutput> {
    Ok(drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::RefreshIdentityState { user_id }),
    )
    .await
    .map_err(crate::errors::DesktopError::from)?)
}

#[tauri::command]
pub async fn set_contact_display_name(
    app: tauri::AppHandle,
    user_id: String,
    display_name: Option<String>,
) -> crate::errors::DesktopResult<CoreOutput> {
    Ok(drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::SetContactDisplayName {
            user_id,
            display_name,
        }),
    )
    .await
    .map_err(crate::errors::DesktopError::from)?)
}

#[tauri::command]
pub async fn delete_contact(
    app: tauri::AppHandle,
    user_id: String,
) -> crate::errors::DesktopResult<CoreOutput> {
    Ok(drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::DeleteContact { user_id }),
    )
    .await
    .map_err(crate::errors::DesktopError::from)?)
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SafetyNumberView {
    pub groups: Vec<String>,
    pub digits: String,
    pub qr_svg: String,
    pub verified: bool,
}

fn render_safety_number_qr(payload: &str) -> Result<String, String> {
    let code = qrcode::QrCode::new(payload.as_bytes()).map_err(|error| error.to_string())?;
    Ok(code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(192, 192)
        .dark_color(qrcode::render::svg::Color("#2E3440"))
        .light_color(qrcode::render::svg::Color("#FFFFFF"))
        .quiet_zone(true)
        .build())
}

#[tauri::command]
pub async fn get_safety_number(
    state: State<'_, AppState>,
    user_id: String,
) -> crate::errors::DesktopResult<SafetyNumberView> {
    let inner = state.inner.read().await;
    let local_public_key = inner
        .engine
        .local_identity()
        .map(|identity| identity.user_identity.user_public_key.clone())
        .ok_or_else(|| {
            tapchat_core::CoreError::invalid_state("local identity is not initialized")
        })?;
    let snapshot = inner.engine.refresh_snapshot();
    let contact = snapshot
        .contacts
        .iter()
        .find(|contact| contact.user_id == user_id)
        .ok_or_else(|| tapchat_core::CoreError::invalid_input("contact does not exist"))?;
    let number =
        tapchat_core::safety_number::compute(&local_public_key, &contact.bundle.user_public_key)?;
    Ok(SafetyNumberView {
        qr_svg: render_safety_number_qr(&number.qr_payload)?,
        groups: number.groups,
        digits: number.digits,
        verified: contact.is_verified(),
    })
}

#[tauri::command]
pub async fn set_contact_verified(
    app: tauri::AppHandle,
    user_id: String,
    verified: bool,
) -> crate::errors::DesktopResult<CoreOutput> {
    Ok(drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::SetContactVerified { user_id, verified }),
    )
    .await
    .map_err(crate::errors::DesktopError::from)?)
}

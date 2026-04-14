use tauri::State;

use tapchat_core::ffi_api::ContactSummary;
use tapchat_core::{CoreCommand, CoreOutput};

use crate::lifecycle::{CoreInput, drive_core_with_handle};
use crate::state::AppState;

#[tauri::command]
pub async fn import_contact_by_link(
    app: tauri::AppHandle,
    share_link: String,
) -> Result<CoreOutput, String> {
    // The share_link is a URL that points to the identity bundle endpoint.
    // We need to fetch it and then import the bundle.

    // First, fetch the bundle via HTTP
    let client = reqwest::Client::new();
    let response = client
        .get(&share_link)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch identity bundle: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("Failed to fetch bundle: HTTP {}", response.status()));
    }

    // Parse the identity bundle
    let bundle: tapchat_core::model::IdentityBundle = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse identity bundle: {}", e))?;

    // Import the bundle into CoreEngine
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::ImportIdentityBundle { bundle }),
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn list_contacts(
    state: State<'_, AppState>,
) -> Result<Vec<ContactSummary>, String> {
    let inner = state.inner.read().await;

    // Get snapshot from engine which contains all contacts
    let snapshot = inner.engine.refresh_snapshot();

    // Build contact summaries from snapshot
    let summaries: Vec<ContactSummary> = snapshot.contacts
        .iter()
        .map(|persisted| {
            ContactSummary {
                user_id: persisted.user_id.clone(),
                display_name: persisted.display_name.clone().or(persisted.original_name.clone()),
                device_count: persisted.bundle.devices.len(),
            }
        })
        .collect();

    Ok(summaries)
}

#[tauri::command]
pub async fn refresh_contact(
    app: tauri::AppHandle,
    user_id: String,
) -> Result<CoreOutput, String> {
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
pub async fn delete_contact(
    app: tauri::AppHandle,
    user_id: String,
) -> Result<CoreOutput, String> {
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::DeleteContact { user_id }),
    )
    .await
    .map_err(|e| e.to_string())
}
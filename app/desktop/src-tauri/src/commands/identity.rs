use serde::Serialize;
use tauri::State;

use tapchat_core::{CoreCommand, CoreOutput};

use crate::lifecycle::{CoreInput, drive_core_with_handle};
use crate::state::AppState;

#[derive(Debug, Clone, Serialize)]
pub struct IdentityInfo {
    pub user_id: String,
    pub device_id: String,
    pub mnemonic: String,
}

#[tauri::command]
pub async fn create_or_load_identity(
    app: tauri::AppHandle,
    mnemonic: Option<String>,
    device_name: Option<String>,
) -> Result<CoreOutput, String> {
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::CreateOrLoadIdentity {
            mnemonic,
            device_name,
        }),
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_identity_info(
    state: State<'_, AppState>,
) -> Result<Option<IdentityInfo>, String> {
    let inner = state.inner.read().await;

    let identity = inner.engine.local_identity();
    let bundle = inner.engine.local_bundle();

    match (identity, bundle) {
        (Some(id), Some(b)) => Ok(Some(IdentityInfo {
            user_id: b.user_id.clone(),
            device_id: id.device_identity.device_id.clone(),
            mnemonic: id.mnemonic.clone(),
        })),
        _ => Ok(None),
    }
}

#[tauri::command]
pub async fn get_share_link(
    state: State<'_, AppState>,
) -> Result<Option<String>, String> {
    let inner = state.inner.read().await;

    // Get the share link from the deployment bundle
    let bundle = inner.engine.local_bundle();
    let deployment = inner.engine.refresh_snapshot().deployment;

    // The share link is typically constructed from the inbox_http_endpoint
    // and user_id from the deployment bundle
    match (bundle, deployment) {
        (Some(b), Some(d)) => {
            // Get HTTP endpoint from deployment bundle
            let http_endpoint = d.deployment_bundle.inbox_http_endpoint;
            // Construct share link: {endpoint}/v1/users/{user_id}/bundle
            Ok(Some(format!("{}/v1/users/{}/bundle", http_endpoint, b.user_id)))
        }
        _ => Ok(None),
    }
}
use std::path::PathBuf;

use serde::Serialize;
use tauri::{AppHandle, State};

use tapchat_core::{CoreCommand, CoreOutput};
use tapchat_core::model::DeviceStatusKind;

use crate::lifecycle::{CoreInput, drive_core_with_handle};
use crate::platform::profile::ProfileSummary;
use crate::state::AppState;

#[derive(Debug, Clone, Serialize)]
pub struct IdentityInfo {
    pub user_id: String,
    pub device_id: String,
    pub mnemonic: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

/// Result of identity creation/recovery
#[derive(Debug, Clone, Serialize)]
pub struct CreateIdentityResult {
    pub user_id: String,
    pub device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
}

/// Initialize a new profile for onboarding
/// This creates the profile directory structure before identity creation
#[tauri::command]
pub async fn init_onboarding_profile(
    state: State<'_, AppState>,
    profile_name: String,
) -> Result<ProfileSummary, String> {
    // Use default path: APPDATA/TapChat/profiles/{profile_name}
    let data_dir = dirs::data_dir()
        .ok_or_else(|| {
            log::error!("Could not get data directory from dirs crate");
            "Could not determine app data directory. Please ensure APPDATA environment variable is set.".to_string()
        })?;

    log::info!("Data dir: {:?}", data_dir);

    let path = data_dir.join("TapChat").join("profiles").join(&profile_name);
    log::info!("Creating profile '{}' at path: {:?}", profile_name, path);

    // Create profile
    let summary = {
        let pm = &state.inner.read().await.profile_manager;
        pm.create_profile(&profile_name, path.clone())
            .await
            .map_err(|e| {
                log::error!("Failed to create profile at {:?}: {}", path, e);
                format!("Failed to create profile directory: {}", e)
            })?
    };

    log::info!("Profile created successfully: {:?}", summary);

    // Update profile_path in state
    {
        let mut inner = state.inner.write().await;
        inner.profile_path = Some(path);
    }

    Ok(summary)
}

/// Create or load identity with profile persistence
#[tauri::command]
pub async fn create_or_load_identity(
    app: AppHandle,
    state: State<'_, AppState>,
    mnemonic: Option<String>,
    device_name: Option<String>,
) -> Result<CreateIdentityResult, String> {
    // First ensure profile exists
    {
        let inner = state.inner.read().await;
        if inner.profile_manager.get_active_metadata().await.is_none() {
            // No profile - create default one
            drop(inner);

            let default_path = dirs::data_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("TapChat")
                .join("profiles")
                .join("default");

            state.inner.read().await
                .profile_manager
                .create_profile("default", default_path.clone())
                .await
                .map_err(|e| e.to_string())?;

            let mut inner = state.inner.write().await;
            inner.profile_path = Some(default_path);
        }
    }

    // Run the core command
    let _output = drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::CreateOrLoadIdentity {
            mnemonic,
            device_name,
            display_name: None,
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    // Get the identity info from engine
    let inner = state.inner.read().await;
    let identity = inner.engine.local_identity();

    let result = match identity {
        Some(id) => {
            let user_id = id.user_identity.user_id.clone();
            let device_id = id.device_identity.device_id.clone();
            let mnemonic = id.mnemonic.clone();

            // Update profile metadata with identity info
            drop(inner);
            state.inner.read().await
                .profile_manager
                .update_identity(Some(user_id.clone()), Some(device_id.clone()))
                .await
                .map_err(|e| e.to_string())?;

            // Persist snapshot to profile
            {
                let inner = state.inner.write().await;
                let snapshot = inner.engine.refresh_snapshot();
                inner.profile_manager.save_snapshot(&snapshot).await
                    .map_err(|e| e.to_string())?;
            }

            CreateIdentityResult {
                user_id,
                device_id,
                mnemonic: Some(mnemonic),
            }
        }
        None => Err("Identity creation failed - no local identity found".to_string())?,
    };

    Ok(result)
}

#[tauri::command]
pub async fn get_identity_info(
    state: State<'_, AppState>,
) -> Result<Option<IdentityInfo>, String> {
    let inner = state.inner.read().await;

    let identity = inner.engine.local_identity();
    let bundle = inner.engine.local_bundle();
    let local_display_name = inner.engine.local_display_name();

    match (identity, bundle) {
        (Some(id), Some(b)) => Ok(Some(IdentityInfo {
            user_id: b.user_id.clone(),
            device_id: id.device_identity.device_id.clone(),
            mnemonic: id.mnemonic.clone(),
            display_name: b.display_name.clone().or(local_display_name),
        })),
        (Some(id), None) => Ok(Some(IdentityInfo {
            user_id: id.user_identity.user_id.clone(),
            device_id: id.device_identity.device_id.clone(),
            mnemonic: id.mnemonic.clone(),
            display_name: local_display_name,
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
            // Construct share link: {endpoint}/v1/shared-state/{user_id}/identity-bundle
            Ok(Some(format!("{}/v1/shared-state/{}/identity-bundle", http_endpoint.trim_end_matches('/'), b.user_id)))
        }
        _ => Ok(None),
    }
}

#[tauri::command]
pub async fn rotate_share_link(
    app: AppHandle,
) -> Result<CoreOutput, String> {
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::RotateContactShareLink),
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn update_device_status(
    app: AppHandle,
    target_device_id: String,
    status: String,
) -> Result<CoreOutput, String> {
    // Parse status string to DeviceStatusKind
    let device_status = match status.to_lowercase().as_str() {
        "active" => DeviceStatusKind::Active,
        "revoked" => DeviceStatusKind::Revoked,
        _ => return Err(format!("Invalid device status: {}", status)),
    };

    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::UpdateLocalDeviceStatus {
            target_device_id,
            status: device_status,
        }),
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn set_local_display_name(
    app: AppHandle,
    display_name: Option<String>,
) -> Result<CoreOutput, String> {
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::SetLocalDisplayName {
            display_name,
        }),
    )
    .await
    .map_err(|e| e.to_string())
}
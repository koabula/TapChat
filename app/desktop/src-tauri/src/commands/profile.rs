use std::path::PathBuf;

use tauri::{AppHandle, Emitter, State};

use tapchat_core::CoreEngine;

use crate::commands::session::SessionStatus;
use crate::lifecycle::{CoreInput, drive_core_with_handle};
use crate::platform::profile::ProfileSummary;
use crate::state::{AppState, SessionState};

#[tauri::command]
pub async fn list_profiles(
    state: State<'_, AppState>,
) -> Result<Vec<ProfileSummary>, String> {
    let pm = &state.inner.read().await.profile_manager;
    Ok(pm.list_profiles().await)
}

#[tauri::command]
pub async fn create_profile(
    state: State<'_, AppState>,
    name: String,
) -> Result<ProfileSummary, String> {
    // Use default path: APPDATA/TapChat/profiles/{name}
    let data_dir = dirs::data_dir()
        .ok_or_else(|| "Could not determine app data directory".to_string())?;

    let path = data_dir.join("TapChat").join("profiles").join(&name);

    // Check if profile with this name already exists
    let pm = &state.inner.read().await.profile_manager;
    let existing = pm.list_profiles().await;
    if existing.iter().any(|p| p.name == name) {
        return Err(format!("Profile '{}' already exists", name));
    }

    pm.create_profile(&name, path.clone())
        .await
        .map_err(|e| e.to_string())
}

/// Start onboarding for a new profile.
/// This does NOT create the profile yet - it just transitions the session state to onboarding.
/// The profile will be created during the Identity step of onboarding via init_onboarding_profile.
#[tauri::command]
pub async fn start_new_profile_onboarding(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    // Set session state to Onboarding Welcome
    {
        let mut inner = state.inner.write().await;
        inner.session = SessionState::Onboarding { step: crate::state::OnboardingStep::Welcome };
        inner.profile_path = None; // Clear profile path - will be set during onboarding

        // Reset engine to fresh state
        inner.engine = CoreEngine::default();
    }

    // Emit session-status event to notify frontend - this triggers route change
    let _ = app.emit("session-status", SessionStatus {
        state: "onboarding:welcome".to_string(),
        device_id: None,
        ws_connected: false,
    });

    Ok(())
}

#[tauri::command]
pub async fn activate_profile(
    app: AppHandle,
    state: State<'_, AppState>,
    path: PathBuf,
) -> Result<(), String> {
    // Activate the profile
    {
        let pm = &state.inner.read().await.profile_manager;
        pm.activate_profile(&path)
            .await
            .map_err(|e| e.to_string())?;
    }

    // Reload the engine from the new profile
    reload_engine_from_profile(&app, &state).await?;

    Ok(())
}

#[tauri::command]
pub async fn delete_profile(
    app: AppHandle,
    state: State<'_, AppState>,
    path: PathBuf,
) -> Result<(), String> {
    // Check if this is the active profile
    let is_active = {
        let inner = state.inner.read().await;
        inner.profile_manager.inner.read().await.registry.active_profile.as_ref() == Some(&path)
    };

    if is_active {
        return Err("Cannot delete the active profile. Switch to another profile first.".to_string());
    }

    let pm = &state.inner.read().await.profile_manager;
    pm.delete_profile(&path)
        .await
        .map_err(|e| e.to_string())?;

    // Refresh profiles list
    let profiles: Vec<ProfileSummary> = pm.list_profiles().await;
    let _ = app.emit("profiles-updated", profiles);

    Ok(())
}

#[tauri::command]
pub async fn reload_engine(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    reload_engine_from_profile(&app, &state).await
}

/// Helper function to reload engine from current active profile
async fn reload_engine_from_profile(
    app: &AppHandle,
    state: &State<'_, AppState>,
) -> Result<(), String> {
    // First, close all existing realtime connections silently to avoid disconnect notifications
    {
        let inner = state.inner.read().await;
        if let Err(e) = inner.ports.realtime.close_all_silent().await {
            log::warn!("Failed to close realtime connections silently: {}", e);
        }
    }

    // Load snapshot from active profile
    let snapshot = {
        let inner = state.inner.read().await;
        inner.profile_manager.load_snapshot().await
            .map_err(|e| format!("Failed to load snapshot: {}", e))?
    };

    // Get device_id from profile metadata
    let device_id = {
        let inner = state.inner.read().await;
        inner.profile_manager.get_active_metadata().await
            .and_then(|m| m.device_id)
            .unwrap_or_else(|| "unknown-device".to_string())
    };

    // Reinitialize engine from snapshot
    {
        let mut inner = state.inner.write().await;
        inner.engine = CoreEngine::from_restored_state(snapshot);
        inner.session = SessionState::Active { device_id: device_id.clone() };
    }

    // Emit session-status event - this happens BEFORE websocket connect
    let _ = app.emit("session-status", SessionStatus {
        state: "active".to_string(),
        device_id: Some(device_id.clone()),
        ws_connected: false,
    });

    // Notify frontend of the reload (for clearing stores)
    let _ = app.emit("engine-reloaded", {});

    // Start session with AppStarted event - this may fail on websocket connect
    // but profile switch is already successful, so we don't propagate this error
    if let Err(e) = drive_core_with_handle(app, CoreInput::Event(tapchat_core::CoreEvent::AppStarted)).await {
        // Log the error but don't fail the profile switch
        log::warn!("Failed to start realtime session after profile switch: {}", e);
        // Return success anyway - profile switch is complete, just realtime failed
    }

    Ok(())
}
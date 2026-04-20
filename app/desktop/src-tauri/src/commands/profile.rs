use std::path::PathBuf;

use tauri::{AppHandle, Emitter, State};

use tapchat_core::CoreEngine;

use crate::commands::session::{SessionStatus, set_ws_connection_snapshot};
use crate::lifecycle::{CoreInput, drive_core_with_handle};
use crate::platform::profile::ProfileSummary;
use crate::runtime_auth::ensure_fresh_device_runtime_auth;
use crate::state::{AppState, SessionState};

#[tauri::command]
pub async fn list_profiles(
    state: State<'_, AppState>,
) -> Result<Vec<ProfileSummary>, String> {
    let pm = &state.inner.read().await.profile_manager;
    let profiles = pm.list_profiles().await;
    log::info!("list_profiles: returning {} profiles", profiles.len());
    for p in &profiles {
        log::info!(
            "list_profiles: profile '{}' at {}, is_active={}, user_id={}, device_id={}",
            p.name,
            p.path.display(),
            p.is_active,
            p.user_id.as_deref().unwrap_or("None"),
            p.device_id.as_deref().unwrap_or("None")
        );
    }
    Ok(profiles)
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

    set_ws_connection_snapshot(&state, None, false).await;

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
    log::info!("activate_profile: activating profile at {}", path.display());

    // Activate the profile
    {
        let pm = &state.inner.read().await.profile_manager;
        pm.activate_profile(&path)
            .await
            .map_err(|e| e.to_string())?;
    }

    // Reload the engine from the new profile
    reload_engine_from_profile(&app, &state).await?;

    log::info!("activate_profile: completed successfully");
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
        let pm_inner = inner.profile_manager.inner.read().await;
        let result = pm_inner
            .active_profile
            .as_ref()
            .map(|profile| profile.root().to_path_buf())
            .or_else(|| pm_inner.registry.active_profile.clone())
            .as_ref()
            == Some(&path);
        // Explicitly drop to avoid borrow issues
        drop(pm_inner);
        drop(inner);
        result
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
    // Emit profile-switch-start to notify frontend that we're beginning a switch
    let _ = app.emit("profile-switch-start", {});

    // Step 1: Close all existing realtime connections silently
    {
        let inner = state.inner.read().await;
        if let Err(e) = inner.ports.realtime.close_all_silent().await {
            log::warn!("Failed to close realtime connections silently: {}", e);
        }
    }

    // Step 2: Wait for old connections to fully close
    // This prevents race conditions where old websocket events might
    // arrive during the new profile initialization
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

    // Step 2.5: Refresh device runtime auth on disk before loading snapshot.
    {
        let inner = state.inner.read().await;
        ensure_fresh_device_runtime_auth(&inner.profile_manager)
            .await
            .map_err(|e| format!("Failed to refresh device runtime auth: {}", e))?;
    }

    // Step 3: Load snapshot from active profile
    let snapshot = {
        let inner = state.inner.read().await;
        log::info!(
            "reload_engine_from_profile: loading snapshot, active_profile={}",
            inner.profile_manager.inner.read().await.active_profile.is_some()
        );
        inner.profile_manager.load_snapshot().await
            .map_err(|e| format!("Failed to load snapshot: {}", e))?
    };

    log::info!(
        "reload_engine_from_profile: snapshot loaded, local_identity={}, deployment={}, contacts={}, conversations={}",
        snapshot.local_identity.is_some(),
        snapshot.deployment.is_some(),
        snapshot.contacts.len(),
        snapshot.conversations.len()
    );

    if let Some(deployment) = &snapshot.deployment {
        log::info!(
            "reload_engine_from_profile: deployment_bundle has inbox_websocket_endpoint={}, inbox_http_endpoint={}",
            deployment.deployment_bundle.inbox_websocket_endpoint,
            deployment.deployment_bundle.inbox_http_endpoint
        );
    }

    // Step 4: Get device_id from profile metadata
    let device_id = {
        let inner = state.inner.read().await;
        inner.profile_manager.get_active_metadata().await
            .and_then(|m| m.device_id)
            .unwrap_or_else(|| "unknown-device".to_string())
    };

    log::info!("reload_engine_from_profile: device_id={}", device_id);

    // Step 5: Reinitialize engine from snapshot
    {
        let mut inner = state.inner.write().await;
        inner.engine = CoreEngine::from_restored_state(snapshot);
        inner.session = SessionState::Active { device_id: device_id.clone() };
    }

    set_ws_connection_snapshot(&state, Some(device_id.clone()), false).await;

    // Step 6: Emit session-status event - this happens BEFORE websocket connect
    let _ = app.emit("session-status", SessionStatus {
        state: "active".to_string(),
        device_id: Some(device_id.clone()),
        ws_connected: false,
    });

    // Step 7: Notify frontend of the reload (for clearing stores)
    // This triggers the frontend to clear its state and prepare for new data
    let _ = app.emit("engine-reloaded", {});

    log::info!("reload_engine_from_profile: events emitted, starting AppStarted");

    // Step 8: Start session with AppStarted event - this will establish new websocket
    // If websocket connect fails, profile switch still succeeded, just realtime failed
    if let Err(e) = drive_core_with_handle(app, CoreInput::Event(tapchat_core::CoreEvent::AppStarted)).await {
        log::warn!("Failed to start realtime session after profile switch: {}", e);
        // Return success anyway - profile switch is complete, just realtime failed
    }

    // Step 9: Emit profile-switch-complete to notify frontend that switch is done
    let _ = app.emit("profile-switch-complete", {});

    log::info!("reload_engine_from_profile: completed successfully");

    Ok(())
}

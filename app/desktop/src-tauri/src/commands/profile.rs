use std::path::PathBuf;

use tauri::{AppHandle, Emitter, Manager, State};

use tapchat_core::CoreEngine;

use crate::commands::session::{
    SessionStatus, read_session_status_snapshot, set_ws_connection_snapshot,
};
use crate::lifecycle::{CoreInput, drive_core_with_handle};
use crate::platform::log_sanitize::{redact_id, sanitize_url_for_log};
use crate::platform::profile::{ProfileProtectionMode, ProfileSummary};
use crate::state::{AppState, LockReason, SessionState};

#[tauri::command]
pub async fn list_profiles(
    state: State<'_, AppState>,
) -> crate::errors::DesktopResult<Vec<ProfileSummary>> {
    let pm = &state.inner.read().await.profile_manager;
    let profiles = pm.list_profiles().await;
    log::info!("list_profiles: returning {} profiles", profiles.len());
    Ok(profiles)
}

#[tauri::command]
pub async fn create_profile(
    state: State<'_, AppState>,
    name: String,
    passphrase: Option<String>,
    protection_mode: Option<ProfileProtectionMode>,
) -> crate::errors::DesktopResult<ProfileSummary> {
    let pm = &state.inner.read().await.profile_manager;
    let protection_mode = protection_mode.unwrap_or_else(|| {
        if passphrase.as_deref().is_some_and(|value| !value.is_empty()) {
            ProfileProtectionMode::KeychainAndPassphrase
        } else {
            ProfileProtectionMode::KeychainOnly
        }
    });
    Ok(pm
        .create_profile(&name, passphrase, protection_mode)
        .await
        .map_err(|e| e.to_string())?)
}

/// Start onboarding for a new profile.
/// This does NOT create the profile yet - it just transitions the session state to onboarding.
/// The profile will be created during the Identity step of onboarding via init_onboarding_profile.
#[tauri::command]
pub async fn start_new_profile_onboarding(
    app: AppHandle,
    state: State<'_, AppState>,
    mode: Option<String>,
) -> crate::errors::DesktopResult<()> {
    {
        let realtime = {
            let ports = state.ports.lock().await;
            ports.realtime.clone()
        };
        if let Err(_error) = realtime.close_all_silent().await {
            log::warn!("Failed to close realtime before onboarding");
        }
    }

    let step = match mode.as_deref() {
        None | Some("welcome") => crate::state::OnboardingStep::Welcome,
        Some("create") => crate::state::OnboardingStep::CreateIdentity,
        Some("recover") => crate::state::OnboardingStep::RecoverIdentity,
        Some(_) => return Err("invalid_input".into()),
    };

    {
        let mut inner = state.inner.write().await;
        inner.session = SessionState::Onboarding { step };
        inner.profile_path = None; // Clear profile path - will be set during onboarding

        // Reset engine to fresh state
        inner.engine = CoreEngine::default();
    }

    set_ws_connection_snapshot(&state, None, false).await;

    let _ = app.emit("session-status", read_session_status_snapshot(&state).await);

    Ok(())
}

#[tauri::command]
pub async fn activate_profile(
    app: AppHandle,
    state: State<'_, AppState>,
    path: PathBuf,
    passphrase: Option<String>,
) -> crate::errors::DesktopResult<()> {
    if let Err(error) = crate::commands::message::run_attachment_maintenance(&app).await {
        log::warn!("pre-switch attachment maintenance failed: {error}");
    }
    let passphrase_supplied = passphrase.as_deref().is_some_and(|value| !value.is_empty());
    log::info!(
        "activate_profile: activating {}",
        redact_id("profile-path", &path.to_string_lossy())
    );

    // Activate the profile
    {
        let pm = &state.inner.read().await.profile_manager;
        pm.activate_profile(&path, passphrase)
            .await
            .map_err(|_| profile_access_error(passphrase_supplied))?;
    }

    let onboarding_window = app.get_webview_window("onboarding");
    if let Some(window) = onboarding_window.as_ref() {
        window.hide().map_err(|error| error.to_string())?;
    }

    if let Err(error) = reload_engine_from_profile(&app, &state).await {
        if let Some(window) = onboarding_window.as_ref() {
            let _ = window.show();
            let _ = window.set_focus();
        }
        return Err(error.into());
    }
    if let Some(window) = onboarding_window {
        if let Some(main_window) = app.get_webview_window("main") {
            main_window.show().map_err(|error| error.to_string())?;
            let _ = main_window.set_focus();
        }
        window.close().map_err(|error| error.to_string())?;
    }
    if let Err(error) = crate::commands::message::run_attachment_maintenance(&app).await {
        log::warn!("post-switch attachment maintenance failed: {error}");
    }

    log::info!("activate_profile: completed successfully");
    Ok(())
}

#[tauri::command]
pub async fn select_profile_for_restart(
    state: State<'_, AppState>,
    path: PathBuf,
    passphrase: Option<String>,
) -> crate::errors::DesktopResult<()> {
    let passphrase_supplied = passphrase.as_deref().is_some_and(|value| !value.is_empty());
    log::info!(
        "select_profile_for_restart: selecting {} for next launch",
        redact_id("profile-path", &path.to_string_lossy())
    );
    let pm = &state.inner.read().await.profile_manager;
    pm.select_profile_for_restart(&path, passphrase)
        .await
        .map_err(|_| profile_access_error(passphrase_supplied))?;
    log::info!("select_profile_for_restart: completed successfully");
    Ok(())
}

#[tauri::command]
pub async fn unlock_active_profile(
    app: AppHandle,
    state: State<'_, AppState>,
    passphrase: String,
) -> crate::errors::DesktopResult<()> {
    let path = {
        let inner = state.inner.read().await;
        let pm_inner = inner.profile_manager.inner.read().await;
        pm_inner
            .registry
            .current()
            .map(|entry| entry.root_dir.clone())
            .map_err(|e| e.to_string())?
    };
    {
        let pm = &state.inner.read().await.profile_manager;
        pm.activate_profile(&path, Some(passphrase))
            .await
            .map_err(|_| profile_access_error(true))?;
    }
    Ok(reload_engine_from_profile(&app, &state).await?)
}

#[tauri::command]
pub async fn retry_locked_profile_startup(
    app: AppHandle,
    state: State<'_, AppState>,
    passphrase: Option<String>,
) -> crate::errors::DesktopResult<()> {
    let reason = {
        let inner = state.inner.read().await;
        match &inner.session {
            SessionState::Locked { reason, .. } => *reason,
            _ => return Ok(reload_engine_from_profile(&app, &state).await?),
        }
    };

    if matches!(reason, LockReason::ProfileLocked) {
        return unlock_active_profile(app, state, passphrase.unwrap_or_default()).await;
    }

    Ok(reload_engine_from_profile(&app, &state).await?)
}

#[tauri::command]
pub async fn delete_profile(
    app: AppHandle,
    state: State<'_, AppState>,
    path: PathBuf,
) -> crate::errors::DesktopResult<()> {
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
        return Err(
            "Cannot delete the active profile. Switch to another profile first."
                .to_string()
                .into(),
        );
    }

    let pm = &state.inner.read().await.profile_manager;
    pm.delete_profile(&path).await.map_err(|e| e.to_string())?;

    // Refresh profiles list
    let profiles: Vec<ProfileSummary> = pm.list_profiles().await;
    let _ = app.emit("profiles-updated", profiles);

    Ok(())
}

#[tauri::command]
pub async fn reload_engine(
    app: AppHandle,
    state: State<'_, AppState>,
) -> crate::errors::DesktopResult<()> {
    Ok(reload_engine_from_profile(&app, &state).await?)
}

fn profile_access_error(passphrase_supplied: bool) -> crate::errors::DesktopError {
    crate::errors::DesktopError::from(if passphrase_supplied {
        "auth_failed"
    } else {
        "profile_passphrase_required"
    })
}

/// Helper function to reload engine from current active profile
async fn reload_engine_from_profile(
    app: &AppHandle,
    state: &State<'_, AppState>,
) -> Result<(), String> {
    state.runtime_auth.invalidate();
    state
        .profile_generation
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    state.media_handles.write().await.clear();
    state.staged_attachments.lock().await.clear();
    state.media_inflight.lock().await.clear();
    // Emit profile-switch-start to notify frontend that we're beginning a switch
    let _ = app.emit("profile-switch-start", {});

    // Step 1: Close all existing realtime connections silently
    {
        let realtime = {
            let ports = state.ports.lock().await;
            ports.realtime.clone()
        };
        if let Err(_error) = realtime.close_all_silent().await {
            log::warn!("Failed to close realtime connections silently");
        }
    }

    // Step 2: Wait for old connections to fully close
    // This prevents race conditions where old websocket events might
    // arrive during the new profile initialization
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

    // Step 2.5: Refresh device runtime auth on disk before loading snapshot.
    {
        let inner = state.inner.read().await;
        if state
            .runtime_auth
            .ensure(&inner.profile_manager, false)
            .await
            .is_err()
        {
            let auth = state.runtime_auth.snapshot().await;
            log::warn!(
                "profile switch runtime authorization unavailable: code={} retryable={} next_retry_at={}",
                auth.error_code
                    .as_deref()
                    .unwrap_or("temporary_unavailable"),
                auth.retryable,
                auth.next_retry_at
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".into())
            );
        }
    }

    // Step 3: Load snapshot from active profile
    let snapshot = {
        let inner = state.inner.read().await;
        log::info!(
            "reload_engine_from_profile: loading snapshot, active_profile={}",
            inner
                .profile_manager
                .inner
                .read()
                .await
                .active_profile
                .is_some()
        );
        match inner.profile_manager.load_snapshot().await {
            Ok(snapshot) => snapshot,
            Err(error) => {
                let profile_path = inner.profile_manager.active_profile_root().await;
                drop(inner);
                let message = format!("Failed to load snapshot: {error}");
                set_locked_session(
                    app,
                    state,
                    profile_path,
                    message.clone(),
                    LockReason::SnapshotLoadFailed,
                )
                .await;
                return Err(message);
            }
        }
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
            sanitize_url_for_log(&deployment.deployment_bundle.inbox_websocket_endpoint),
            sanitize_url_for_log(&deployment.deployment_bundle.inbox_http_endpoint)
        );
    }

    // Step 4: Get device_id from profile metadata
    let device_id = {
        let inner = state.inner.read().await;
        inner
            .profile_manager
            .get_active_metadata()
            .await
            .and_then(|m| m.device_id)
            .unwrap_or_else(|| "unknown-device".to_string())
    };

    log::info!(
        "reload_engine_from_profile: device_id={}",
        redact_id("device", &device_id)
    );

    // Step 5: Reinitialize engine from snapshot
    let restored_engine = match CoreEngine::try_from_restored_state(snapshot) {
        Ok(engine) => engine,
        Err(error) => {
            let profile_path = {
                let inner = state.inner.read().await;
                inner.profile_manager.active_profile_root().await
            };
            let message = format!("Failed to restore profile state: {error}");
            set_locked_session(
                app,
                state,
                profile_path,
                message.clone(),
                LockReason::RestoreFailed,
            )
            .await;
            return Err(message);
        }
    };
    {
        let mut inner = state.inner.write().await;
        inner.engine = restored_engine;
        inner.session = SessionState::Active {
            device_id: device_id.clone(),
        };
    }

    set_ws_connection_snapshot(&state, Some(device_id.clone()), false).await;

    // Step 6: Emit session-status event - this happens BEFORE websocket connect
    let _ = app.emit(
        "session-status",
        SessionStatus {
            state: "active".to_string(),
            device_id: Some(device_id.clone()),
            ws_connected: false,
            profile_path: None,
            error: None,
            lock_reason: None,
        },
    );

    // Step 7: Notify frontend of the reload (for clearing stores)
    // This triggers the frontend to clear its state and prepare for new data
    let _ = app.emit("engine-reloaded", {});

    log::info!("reload_engine_from_profile: events emitted, starting AppStarted");

    // Step 8: Start session with AppStarted event - this will establish new websocket
    // If websocket connect fails, profile switch still succeeded, just realtime failed
    if let Err(_error) =
        drive_core_with_handle(app, CoreInput::Event(tapchat_core::CoreEvent::AppStarted)).await
    {
        log::warn!("Failed to start realtime session after profile switch");
        // Return success anyway - profile switch is complete, just realtime failed
    }

    // Step 9: Emit profile-switch-complete to notify frontend that switch is done
    let _ = app.emit("profile-switch-complete", {});

    log::info!("reload_engine_from_profile: completed successfully");

    Ok(())
}

async fn set_locked_session(
    app: &AppHandle,
    state: &State<'_, AppState>,
    profile_path: Option<std::path::PathBuf>,
    error: String,
    reason: LockReason,
) {
    {
        let realtime = {
            let ports = state.ports.lock().await;
            ports.realtime.clone()
        };
        if let Err(_error) = realtime.close_all_silent().await {
            log::warn!("Failed to close realtime after profile lock: close_failed");
        }
    }
    {
        let mut inner = state.inner.write().await;
        inner.engine = CoreEngine::new();
        inner.session = SessionState::Locked {
            profile_path: profile_path.clone(),
            error: error.clone(),
            reason,
        };
        inner.profile_path = profile_path.clone();
        inner.startup_phase = crate::state::StartupPhase::Ready;
    }
    set_ws_connection_snapshot(state, None, false).await;
    let _ = app.emit(
        "session-status",
        SessionStatus {
            state: "locked".to_string(),
            device_id: None,
            ws_connected: false,
            profile_path: profile_path.map(|path| path.to_string_lossy().to_string()),
            error: Some(error),
            lock_reason: Some(reason.as_str().to_string()),
        },
    );
}

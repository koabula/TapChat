use std::sync::Arc;

use anyhow::Result;
use tauri::{AppHandle, Emitter, Manager, WebviewUrl, WindowEvent};
use tauri::webview::WebviewWindowBuilder;
use std::time::Instant;

use tapchat_core::{CoreCommand, CoreEngine, CoreEvent, CoreOutput};
use tapchat_core::persistence::CorePersistenceSnapshot;
use tapchat_core::platform_ports::execute_platform_effect;

use crate::commands::session::{SessionStatus, set_ws_connection_snapshot};
use crate::runtime_auth::ensure_fresh_device_runtime_auth;
use crate::state::{AppState, SessionState, StartupPhase};

/// Input to the core engine — either a user-initiated command or a platform event.
pub enum CoreInput {
    Command(CoreCommand),
    Event(CoreEvent),
}

/// Called once after Tauri setup completes. Determines whether to show
/// onboarding or the main window based on ProfileManager session check.
pub async fn on_app_ready(app: &AppHandle) {
    let state = app.state::<AppState>();
    let startup_started_at = Instant::now();

    // Set startup phase to LoadingProfile before reading files
    {
        let mut inner = state.inner.write().await;
        inner.startup_phase = StartupPhase::LoadingProfile;
    }

    // Check session startup using ProfileManager
    let startup_check_started_at = Instant::now();
    let startup_check = {
        let inner = state.inner.read().await;
        inner.profile_manager.check_session_startup().await
    };
    log::info!(
        "on_app_ready: check_session_startup completed in {}ms",
        startup_check_started_at.elapsed().as_millis()
    );

    log::info!("Session startup check: {:?}", startup_check);

    // Update state based on startup check
    let needs_onboarding = startup_check.needs_onboarding;

    if needs_onboarding {
        // Determine onboarding step based on what's missing
        let step = determine_onboarding_step(&startup_check);

        log::info!("Needs onboarding, step: {:?}", step);

        let mut inner = state.inner.write().await;
        inner.session = SessionState::Onboarding { step };
        inner.profile_path = startup_check.profile_path;
        inner.startup_phase = StartupPhase::Ready;  // Backend is ready, just needs onboarding
        drop(inner);
        set_ws_connection_snapshot(&state, None, false).await;

        // Open onboarding window
        let _onboarding = WebviewWindowBuilder::new(
            app,
            "onboarding",
            WebviewUrl::App("/onboarding".into()),
        )
        .title("TapChat Setup")
        .inner_size(960.0, 640.0)
        .resizable(false)
        .center()
        .build()
        .expect("failed to create onboarding window");
    } else {
        log::info!("Session ready, loading snapshot and showing main window");

        let refresh_started_at = Instant::now();
        {
            let inner = state.inner.read().await;
            match ensure_fresh_device_runtime_auth(&inner.profile_manager).await {
                Ok(Some(_)) => {
                    log::info!(
                        "on_app_ready: refreshed device runtime auth in {}ms",
                        refresh_started_at.elapsed().as_millis()
                    );
                }
                Ok(None) => {
                    log::info!(
                        "on_app_ready: device runtime auth refresh not needed ({}ms)",
                        refresh_started_at.elapsed().as_millis()
                    );
                }
                Err(error) => {
                    log::warn!(
                        "on_app_ready: device runtime auth refresh failed in {}ms: {}",
                        refresh_started_at.elapsed().as_millis(),
                        error
                    );
                }
            }
        }

        // Load snapshot from profile and initialize engine
        let load_snapshot_started_at = Instant::now();
        let (snapshot, device_id) = {
            let inner = state.inner.read().await;

            // Load snapshot from active profile
            let snapshot = inner.profile_manager.load_snapshot().await
                .unwrap_or_else(|e| {
                    log::error!("Failed to load snapshot: {}", e);
                    CorePersistenceSnapshot::default()
                });

            // Get device_id from profile metadata
            let device_id = inner.profile_manager.get_active_metadata().await
                .and_then(|m| m.device_id)
                .unwrap_or_else(|| "unknown-device".to_string());

            (snapshot, device_id)
        };
        log::info!(
            "on_app_ready: load_snapshot completed in {}ms",
            load_snapshot_started_at.elapsed().as_millis()
        );

        log::info!("Loaded snapshot with {} contacts, {} conversations, deployment: {:?}",
            snapshot.contacts.len(),
            snapshot.conversations.len(),
            snapshot.deployment.as_ref().map(|d| d.deployment_bundle.inbox_http_endpoint.clone()));

        // Initialize engine from snapshot
        let restore_engine_started_at = Instant::now();
        {
            let mut inner = state.inner.write().await;

            // Create engine from restored state
            inner.engine = CoreEngine::from_restored_state(snapshot);

            inner.session = SessionState::Active { device_id };
            inner.profile_path = startup_check.profile_path;
            inner.startup_phase = StartupPhase::Ready;  // Backend is fully ready
        }
        log::info!(
            "on_app_ready: CoreEngine::from_restored_state completed in {}ms",
            restore_engine_started_at.elapsed().as_millis()
        );

        let active_device_id = {
            let inner = state.inner.read().await;
            match &inner.session {
                SessionState::Active { device_id } => Some(device_id.clone()),
                _ => None,
            }
        };
        set_ws_connection_snapshot(&state, active_device_id, false).await;

        // Show main window (created hidden in tauri.conf.json)
        let show_window_started_at = Instant::now();
        if let Some(main_window) = app.get_webview_window("main") {
            main_window.show().expect("failed to show main window");
        }
        log::info!(
            "on_app_ready: main_window.show completed in {}ms",
            show_window_started_at.elapsed().as_millis()
        );

        // Start session
        let app_clone = app.clone();
        tauri::async_runtime::spawn(async move {
            let app_started_at = Instant::now();
            // Fire AppStarted to kick off sync
            if let Err(e) = drive_core_with_handle(&app_clone, CoreInput::Event(CoreEvent::AppStarted)).await {
                log::error!("Failed to start session: {}", e);
            }
            log::info!(
                "on_app_ready: AppStarted finished in {}ms",
                app_started_at.elapsed().as_millis()
            );
        });
    }

    log::info!(
        "on_app_ready: total startup path completed in {}ms",
        startup_started_at.elapsed().as_millis()
    );
}

/// Determine the appropriate onboarding step based on startup check.
fn determine_onboarding_step(check: &crate::platform::profile::SessionStartupCheck) -> crate::state::OnboardingStep {
    if !check.has_active_profile {
        // No profile at all - start fresh
        crate::state::OnboardingStep::Welcome
    } else if !check.has_identity {
        // Profile exists but no identity - need to create/recover
        crate::state::OnboardingStep::CreateIdentity
    } else if !check.has_runtime_binding {
        // Has identity but no Cloudflare binding - need setup
        crate::state::OnboardingStep::CloudflareSetup
    } else {
        // Everything complete
        crate::state::OnboardingStep::Complete
    }
}

/// Central window event handler. Manages close behavior based on SessionState.
pub fn handle_window_event(window: &tauri::Window, event: &WindowEvent) {
    if let WindowEvent::CloseRequested { api, .. } = event {
        let label = window.label();
        let app = window.app_handle();
        let state = app.state::<AppState>();

        // We need to check session state synchronously here.
        // Use try_read to avoid blocking — if locked, allow close.
        let inner = match state.inner.try_read() {
            Ok(guard) => guard,
            Err(_) => return, // Lock contention — allow default close
        };

        match label {
            "main" => {
                // Main window: hide to tray instead of closing (unless quitting)
                if inner.session != SessionState::Quitting {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
            "onboarding" => {
                // Onboarding: prevent close if setup is incomplete
                match &inner.session {
                    SessionState::Onboarding { step } => {
                        if *step != crate::state::OnboardingStep::Complete {
                            api.prevent_close();
                            // Show notification that setup is incomplete
                            log::warn!("Onboarding close prevented - setup not complete");
                        }
                    }
                    _ => {} // Allow close in other states
                }
            }
            _ => {}
        }
    }
}

/// The single entry point for all core state changes. Processes a command or event
/// through CoreEngine, executes resulting effects, and pushes UI updates to the frontend.
pub async fn drive_core_with_handle(
    app: &AppHandle,
    input: CoreInput,
) -> Result<CoreOutput> {
    let state = app.state::<AppState>();
    let app_arc = Arc::new(app.clone());

    let output = {
        let mut inner = state.inner.write().await;
        // Set app handle on ports for progress events
        inner.ports.set_app_handle(app_arc.clone());
        match input {
            CoreInput::Command(cmd) => inner.engine.handle_command(cmd)?,
            CoreInput::Event(evt) => inner.engine.handle_event(evt)?,
        }
    };

    // Push UI update to frontend
    let has_updates = output.view_model.is_some()
        || output.state_update.conversations_changed
        || output.state_update.messages_changed
        || output.state_update.contacts_changed
        || output.state_update.checkpoints_changed
        || !output.state_update.system_statuses_changed.is_empty();
    if has_updates {
        let _ = app.emit("core-update", &output);
    }

    // Execute effects — each may produce new events that feed back into the engine
    let effects = output.effects.clone();
    for effect in effects {
        let events = {
            let mut inner = state.inner.write().await;
            // Ensure app handle is set
            inner.ports.set_app_handle(app_arc.clone());
            execute_platform_effect(&mut inner.ports, effect).await?
        };
        for event in events {
            Box::pin(drive_core_with_handle(app, CoreInput::Event(event))).await?;
        }
    }

    Ok(output)
}

/// Transition from onboarding to active session.
/// Called when onboarding completes successfully.
#[tauri::command]
pub async fn complete_onboarding(app: AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();

    // Get device_id from profile and persist session state
    let device_id = {
        let inner = state.inner.read().await;
        inner.profile_manager.get_active_metadata().await
            .and_then(|m| m.device_id)
            .unwrap_or_else(|| "unknown-device".to_string())
    };

    // Update session state
    {
        let mut inner = state.inner.write().await;
        inner.session = SessionState::Active { device_id: device_id.clone() };
        inner.startup_phase = StartupPhase::Ready;  // Ensure startup phase is ready

        // Persist the current snapshot to profile
        let snapshot = inner.engine.refresh_snapshot();
        if let Err(e) = inner.profile_manager.save_snapshot(&snapshot).await {
            log::error!("Failed to save snapshot: {}", e);
        }
    }

    set_ws_connection_snapshot(&state, Some(device_id.clone()), false).await;

    // Emit session-status event to notify frontend - this triggers route change
    let _ = app.emit("session-status", SessionStatus {
        state: "active".to_string(),
        device_id: Some(device_id),
        ws_connected: false,
    });

    // Close onboarding window if exists
    if let Some(onboarding_window) = app.get_webview_window("onboarding") {
        onboarding_window.close().map_err(|e| e.to_string())?;
    }

    // Show main window
    if let Some(main_window) = app.get_webview_window("main") {
        main_window.show().map_err(|e| e.to_string())?;
        if let Err(e) = main_window.set_focus() {
            log::error!("Failed to focus main window: {}", e);
        }
    }

    // Start session with AppStarted event
    drive_core_with_handle(&app, CoreInput::Event(CoreEvent::AppStarted))
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}

/// Update onboarding step. Called by frontend when advancing through setup.
#[tauri::command]
pub async fn set_onboarding_step(app: AppHandle, step: String) -> Result<(), String> {
    let state = app.state::<AppState>();

    // Parse step string to OnboardingStep enum
    let onboarding_step = match step.to_lowercase().as_str() {
        "welcome" => crate::state::OnboardingStep::Welcome,
        "create_identity" | "createidentity" => crate::state::OnboardingStep::CreateIdentity,
        "recover_identity" | "recoveridentity" => crate::state::OnboardingStep::RecoverIdentity,
        "backup_mnemonic" | "backupmnemonic" => crate::state::OnboardingStep::BackupMnemonic,
        "cloudflare_setup" | "cloudflaresetup" => crate::state::OnboardingStep::CloudflareSetup,
        "complete" => crate::state::OnboardingStep::Complete,
        _ => return Err(format!("Invalid onboarding step: {}", step)),
    };

    let mut inner = state.inner.write().await;

    if let SessionState::Onboarding { .. } = &inner.session {
        inner.session = SessionState::Onboarding { step: onboarding_step };
    }

    Ok(())
}

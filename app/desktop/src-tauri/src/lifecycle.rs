use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use std::time::{Duration, Instant};
use tauri::webview::WebviewWindowBuilder;
use tauri::{AppHandle, Emitter, Manager, State, WebviewUrl, WindowEvent};

use tapchat_core::ffi_api::CoreViewModel;
use tapchat_core::platform_ports::execute_platform_effect;
use tapchat_core::{CoreCommand, CoreEffect, CoreEngine, CoreEvent, CoreOutput};

use crate::commands::session::{set_ws_connection_snapshot, SessionStatus};
use crate::state::{AppState, DeferredTransportBatch, LockReason, SessionState, StartupPhase};

/// Input to the core engine — either a user-initiated command or a platform event.
pub enum CoreInput {
    Command(CoreCommand),
    Event(CoreEvent),
}

enum DriverWork {
    Input(CoreInput),
    Effect(CoreEffect),
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

    log::info!(
        "Session startup check: active_profile={} identity={} runtime_bound={} needs_onboarding={} locked={}",
        startup_check.has_active_profile,
        startup_check.has_identity,
        startup_check.has_runtime_binding,
        startup_check.needs_onboarding,
        startup_check.unlock_error.is_some()
    );

    if let Some(unlock_error) = startup_check.unlock_error.clone() {
        let lock_reason = lock_reason_from_startup(startup_check.lock_reason.as_deref());
        log::warn!("Active profile is locked or failed to unlock");
        {
            let mut inner = state.inner.write().await;
            inner.session = SessionState::Locked {
                profile_path: startup_check.profile_path.clone(),
                error: unlock_error.clone(),
                reason: lock_reason,
            };
            inner.profile_path = startup_check.profile_path.clone();
            inner.startup_phase = StartupPhase::Ready;
        }
        set_ws_connection_snapshot(&state, None, false).await;
        let _ = app.emit(
            "session-status",
            SessionStatus {
                state: "locked".to_string(),
                device_id: None,
                ws_connected: false,
                profile_path: startup_check
                    .profile_path
                    .as_ref()
                    .map(|path| path.to_string_lossy().to_string()),
                error: Some(unlock_error),
                lock_reason: Some(lock_reason.as_str().to_string()),
            },
        );
        if let Some(main_window) = app.get_webview_window("main") {
            if let Err(_error) = main_window.show() {
                log::error!("Failed to show main window");
            }
            let _ = main_window.set_focus();
        }
        log::info!(
            "on_app_ready: total startup path completed in {}ms",
            startup_started_at.elapsed().as_millis()
        );
        return;
    }

    // Update state based on startup check
    let needs_onboarding = startup_check.needs_onboarding;

    if needs_onboarding {
        // Determine onboarding step based on what's missing
        let step = determine_onboarding_step(&startup_check);

        log::info!("Needs onboarding, step: {:?}", step);

        let mut inner = state.inner.write().await;
        inner.session = SessionState::Onboarding { step };
        inner.profile_path = startup_check.profile_path;
        inner.startup_phase = StartupPhase::Ready; // Backend is ready, just needs onboarding
        let session_status = SessionStatus {
            state: match &inner.session {
                SessionState::Onboarding { step } => {
                    format!("onboarding:{:?}", step).to_lowercase()
                }
                _ => "onboarding:welcome".to_string(),
            },
            device_id: None,
            ws_connected: false,
            profile_path: None,
            error: None,
            lock_reason: None,
        };
        drop(inner);
        set_ws_connection_snapshot(&state, None, false).await;
        let _ = app.emit("session-status", session_status);

        // Open onboarding window
        if let Err(_error) =
            WebviewWindowBuilder::new(app, "onboarding", WebviewUrl::App("/onboarding".into()))
                .title("TapChat Setup")
                .inner_size(1080.0, 720.0)
                .min_inner_size(800.0, 600.0)
                .resizable(true)
                .center()
                .build()
        {
            log::error!("Failed to create onboarding window");
        }
    } else {
        log::info!("Session ready, loading snapshot and showing main window");

        // Load snapshot from profile and initialize engine
        let load_snapshot_started_at = Instant::now();
        let (snapshot, device_id) = {
            let inner = state.inner.read().await;

            // Load snapshot from active profile
            let snapshot = match inner.profile_manager.load_snapshot().await {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    let error = format!("Failed to load snapshot: {error}");
                    drop(inner);
                    enter_locked_session(
                        app,
                        &state,
                        startup_check.profile_path.clone(),
                        error,
                        LockReason::SnapshotLoadFailed,
                    )
                    .await;
                    log::info!(
                        "on_app_ready: total startup path completed in {}ms",
                        startup_started_at.elapsed().as_millis()
                    );
                    return;
                }
            };

            // Get device_id from profile metadata
            let device_id = inner
                .profile_manager
                .get_active_metadata()
                .await
                .and_then(|m| m.device_id)
                .unwrap_or_else(|| "unknown-device".to_string());

            (snapshot, device_id)
        };
        log::info!(
            "on_app_ready: load_snapshot completed in {}ms",
            load_snapshot_started_at.elapsed().as_millis()
        );

        log::info!(
            "Loaded snapshot with {} contacts, {} conversations, deployment: {:?}",
            snapshot.contacts.len(),
            snapshot.conversations.len(),
            snapshot
                .deployment
                .as_ref()
                .map(|d| d.deployment_bundle.inbox_http_endpoint.clone())
        );

        // Initialize engine from snapshot
        let restore_engine_started_at = Instant::now();
        let restored_engine = match CoreEngine::try_from_restored_state(snapshot) {
            Ok(engine) => engine,
            Err(error) => {
                enter_locked_session(
                    app,
                    &state,
                    startup_check.profile_path.clone(),
                    format!("Failed to restore profile state: {error}"),
                    LockReason::RestoreFailed,
                )
                .await;
                log::info!(
                    "on_app_ready: total startup path completed in {}ms",
                    startup_started_at.elapsed().as_millis()
                );
                return;
            }
        };
        {
            let mut inner = state.inner.write().await;

            // Create engine from restored state
            inner.engine = restored_engine;

            inner.session = SessionState::Active {
                device_id: device_id.clone(),
            };
            inner.profile_path = startup_check.profile_path;
            inner.startup_phase = StartupPhase::Ready; // Backend is fully ready
        }
        log::info!(
            "on_app_ready: CoreEngine::try_from_restored_state completed in {}ms",
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

        // Show main window (created hidden in tauri.conf.json)
        let show_window_started_at = Instant::now();
        if let Some(main_window) = app.get_webview_window("main") {
            if let Err(_error) = main_window.show() {
                log::error!("Failed to show main window");
            }
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
            if let Err(_error) =
                drive_core_with_handle(&app_clone, CoreInput::Event(CoreEvent::AppStarted)).await
            {
                log::error!("Failed to start session");
            }
            if let Err(_error) =
                crate::commands::cloudflare::maybe_run_due_secret_rotation(&app_clone).await
            {
                log::warn!("automatic runtime secret rotation check failed");
            }
            log::info!(
                "on_app_ready: AppStarted finished in {}ms",
                app_started_at.elapsed().as_millis()
            );
        });
        spawn_runtime_auth_scheduler(app.clone());
    }

    log::info!(
        "on_app_ready: total startup path completed in {}ms",
        startup_started_at.elapsed().as_millis()
    );
}

fn spawn_runtime_auth_scheduler(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            let state = app.state::<AppState>();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let manager_snapshot = state.runtime_auth.snapshot().await;
            let next_retry = manager_snapshot.next_retry_at;
            let credential_expiry = {
                let inner = state.inner.read().await;
                let pm = inner.profile_manager.inner.read().await;
                pm.active_profile
                    .as_ref()
                    .and_then(|profile| profile.load_runtime_credential().ok().flatten())
                    .map(|credential| credential.expires_at)
            };
            let jitter_ms = rand::random::<u64>() % (5 * 60 * 1000);
            let wake_at = next_retry.or_else(|| {
                credential_expiry.map(|expires_at| {
                    expires_at
                        .saturating_sub(crate::runtime_auth::DEVICE_RUNTIME_REFRESH_SKEW_MS)
                        .saturating_sub(jitter_ms)
                })
            });
            let delay_ms = wake_at
                .map(|wake_at| wake_at.saturating_sub(now).clamp(30_000, 60 * 60 * 1000))
                .unwrap_or(15 * 60 * 1000);
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;

            let profile_manager = {
                let inner = state.inner.read().await;
                if !matches!(inner.session, SessionState::Active { .. }) {
                    continue;
                }
                inner.profile_manager.clone()
            };
            let before = state.runtime_auth.snapshot().await.state;
            match state.runtime_auth.ensure(&profile_manager, false).await {
                Ok(Some(_)) if before != crate::runtime_auth::RuntimeAuthState::Ready => {
                    if let Err(_error) =
                        drive_core_with_handle(&app, CoreInput::Event(CoreEvent::AppForegrounded))
                            .await
                    {
                        log::warn!("runtime authorization recovered but sync restart failed");
                    }
                }
                Ok(_) => {}
                Err(_error) => {
                    let snapshot = state.runtime_auth.snapshot().await;
                    log::warn!(
                        "scheduled runtime authorization refresh failed: code={} retryable={} next_retry_at={}",
                        snapshot.error_code.as_deref().unwrap_or("temporary_unavailable"),
                        snapshot.retryable,
                        snapshot
                            .next_retry_at
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "none".into())
                    );
                }
            }
        }
    });
}

/// Determine the appropriate onboarding step based on startup check.
fn determine_onboarding_step(
    check: &crate::platform::profile::SessionStartupCheck,
) -> crate::state::OnboardingStep {
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

fn lock_reason_from_startup(reason: Option<&str>) -> LockReason {
    match reason {
        Some("snapshot_load_failed") => LockReason::SnapshotLoadFailed,
        Some("restore_failed") => LockReason::RestoreFailed,
        _ => LockReason::ProfileLocked,
    }
}

async fn enter_locked_session(
    app: &AppHandle,
    state: &State<'_, AppState>,
    profile_path: Option<PathBuf>,
    error: String,
    reason: LockReason,
) {
    {
        let mut inner = state.inner.write().await;
        inner.session = SessionState::Locked {
            profile_path: profile_path.clone(),
            error: error.clone(),
            reason,
        };
        inner.profile_path = profile_path.clone();
        inner.startup_phase = StartupPhase::Ready;
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
    if let Some(main_window) = app.get_webview_window("main") {
        if let Err(_error) = main_window.show() {
            log::error!("Failed to show main window");
        }
        let _ = main_window.set_focus();
    }
}

/// Central window event handler. Manages close behavior based on SessionState.
pub fn handle_window_event(window: &tauri::Window, event: &WindowEvent) {
    if let WindowEvent::Focused(true) = event {
        if window.label() == "main" {
            let app = window.app_handle().clone();
            tauri::async_runtime::spawn(async move {
                let state = app.state::<AppState>();
                let is_active = {
                    let inner = state.inner.read().await;
                    matches!(inner.session, SessionState::Active { .. })
                };
                if !is_active {
                    return;
                }

                let now = Instant::now();
                {
                    let mut gate = state.foreground_sync_gate.lock().await;
                    if gate
                        .last_triggered_at
                        .is_some_and(|last| now.duration_since(last) < Duration::from_secs(30))
                    {
                        return;
                    }
                    gate.last_triggered_at = Some(now);
                }

                if let Err(_error) =
                    drive_core_with_handle(&app, CoreInput::Event(CoreEvent::AppForegrounded)).await
                {
                    log::warn!("foreground sync failed");
                }
                if let Err(_error) =
                    crate::commands::cloudflare::maybe_run_due_secret_rotation(&app).await
                {
                    log::warn!("foreground runtime secret rotation check failed");
                }
            });
        }
    }

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
pub async fn drive_core_with_handle(app: &AppHandle, input: CoreInput) -> Result<CoreOutput> {
    drive_core_work_queue(app, vec![DriverWork::Input(input)]).await
}

/// Drain core inputs, platform effects and the events they produce without
/// recursively re-entering the driver. Attachment upload and inbox recovery
/// can each produce long effect/event chains; a heap-backed work stack keeps
/// the native thread stack constant on Windows.
async fn drive_core_work_queue(
    app: &AppHandle,
    mut pending: Vec<DriverWork>,
) -> Result<CoreOutput> {
    let state = app.state::<AppState>();
    let app_arc = Arc::new(app.clone());
    let mut aggregate = CoreOutput::default();

    while let Some(work) = pending.pop() {
        match work {
            DriverWork::Input(input) => {
                let output = {
                    let mut inner = state.inner.write().await;
                    match input {
                        CoreInput::Command(command) => inner.engine.handle_command(command)?,
                        CoreInput::Event(event) => inner.engine.handle_event(event)?,
                    }
                };
                emit_core_update(app, &output);
                for effect in output.effects.iter().cloned().rev() {
                    pending.push(DriverWork::Effect(effect));
                }
                merge_core_outputs(&mut aggregate, output);
            }
            DriverWork::Effect(effect) => {
                let events = {
                    let mut ports = state.ports.lock().await;
                    ports.set_app_handle(app_arc.clone());
                    execute_platform_effect(&mut *ports, effect).await?
                };
                for event in events.into_iter().rev() {
                    pending.push(DriverWork::Input(CoreInput::Event(event)));
                }
            }
        }
    }

    Ok(aggregate)
}

/// Execute the command's foreground effect (for example accepting a message
/// request), commit any persistence produced by its result, then enqueue the
/// remaining notification/sync effects. This keeps the user-visible commit
/// boundary synchronous without making the dialog wait for unrelated inbox
/// reconciliation.
pub async fn drive_core_then_defer_event_effects(
    app: &AppHandle,
    input: CoreInput,
) -> Result<CoreOutput> {
    let state = app.state::<AppState>();
    let app_arc = Arc::new(app.clone());
    let mut output = {
        let mut inner = state.inner.write().await;
        match input {
            CoreInput::Command(cmd) => inner.engine.handle_command(cmd)?,
            CoreInput::Event(evt) => inner.engine.handle_event(evt)?,
        }
    };
    emit_core_update(app, &output);
    for effect in output.effects.clone() {
        let events = {
            let mut ports = state.ports.lock().await;
            ports.set_app_handle(app_arc.clone());
            execute_platform_effect(&mut *ports, effect).await?
        };
        for event in events {
            let event_output = drive_core_event_persist_then_defer(app, event).await?;
            merge_core_outputs(&mut output, event_output);
        }
    }
    Ok(output)
}

async fn drive_core_event_persist_then_defer(
    app: &AppHandle,
    event: CoreEvent,
) -> Result<CoreOutput> {
    let state = app.state::<AppState>();
    let _send_order = state.deferred_send_gate.lock().await;
    let app_arc = Arc::new(app.clone());
    let mut output = {
        let mut inner = state.inner.write().await;
        inner.engine.handle_event(event)?
    };
    let (persistence_effects, deferred_effects) = split_persistence_prefix(output.effects.clone());
    for effect in persistence_effects {
        execute_effect_with_handle(app, &app_arc, &mut output, effect).await?;
    }
    emit_core_update(app, &output);
    if deferred_effects.is_empty() {
        return Ok(output);
    }
    ensure_deferred_transport_worker(app).await;
    let profile_path = state.inner.read().await.profile_path.clone();
    state
        .deferred_transport_tx
        .send(DeferredTransportBatch {
            effects: deferred_effects,
            profile_path,
            enqueued_at: Instant::now(),
        })
        .await
        .map_err(|_| anyhow::anyhow!("deferred transport queue is unavailable"))?;
    Ok(output)
}

/// Send-only driver: commit all leading persistence effects before returning,
/// then dispatch the remaining transport effects through one bounded FIFO.
/// This preserves MLS serialization and persistence-before-network while
/// removing network latency from the Tauri command response.
pub async fn drive_core_persist_then_defer_transport(
    app: &AppHandle,
    input: CoreInput,
) -> Result<CoreOutput> {
    let core_started_at = Instant::now();
    let state = app.state::<AppState>();
    let _send_order = state.deferred_send_gate.lock().await;
    let app_arc = Arc::new(app.clone());
    let mut output = {
        let mut inner = state.inner.write().await;
        match input {
            CoreInput::Command(cmd) => inner.engine.handle_command(cmd)?,
            CoreInput::Event(evt) => inner.engine.handle_event(evt)?,
        }
    };
    crate::timetest!(
        "deferred_send_core elapsed_ms={}",
        core_started_at.elapsed().as_millis()
    );

    let (persistence_effects, transport_effects) = split_persistence_prefix(output.effects.clone());
    if persistence_effects.is_empty() || transport_effects.is_empty() {
        emit_core_update(app, &output);
        // Unexpected effect shapes retain the established synchronous behavior.
        for effect in persistence_effects.into_iter().chain(transport_effects) {
            execute_effect_with_handle(app, &app_arc, &mut output, effect).await?;
        }
        return Ok(output);
    }

    let persistence_started_at = Instant::now();
    for effect in persistence_effects {
        execute_effect_with_handle(app, &app_arc, &mut output, effect).await?;
    }
    crate::timetest!(
        "deferred_send_persistence elapsed_ms={}",
        persistence_started_at.elapsed().as_millis()
    );
    emit_core_update(app, &output);

    ensure_deferred_transport_worker(app).await;
    let profile_path = state.inner.read().await.profile_path.clone();
    state
        .deferred_transport_tx
        .send(DeferredTransportBatch {
            effects: transport_effects,
            profile_path,
            enqueued_at: Instant::now(),
        })
        .await
        .map_err(|_| anyhow::anyhow!("deferred transport queue is unavailable"))?;

    Ok(output)
}

fn split_persistence_prefix(effects: Vec<CoreEffect>) -> (Vec<CoreEffect>, Vec<CoreEffect>) {
    let prefix_len = effects
        .iter()
        .take_while(|effect| matches!(effect, CoreEffect::PersistState { .. }))
        .count();
    let mut effects = effects;
    let transport = effects.split_off(prefix_len);
    (effects, transport)
}

#[cfg(test)]
mod deferred_send_tests {
    use super::split_persistence_prefix;
    use std::sync::Arc;
    use std::time::Duration;
    use tapchat_core::ffi_api::{PersistStateEffect, TimerEffect};
    use tapchat_core::CoreEffect;
    use tokio::sync::{mpsc, oneshot, Mutex, Notify};

    #[test]
    fn persistence_prefix_is_removed_without_reordering_transport() {
        let persist = || CoreEffect::PersistState {
            persist: PersistStateEffect {
                ops: Vec::new(),
                snapshot: None,
            },
        };
        let timer = |id: &str| CoreEffect::ScheduleTimer {
            timer: TimerEffect {
                timer_id: id.into(),
                delay_ms: 1,
            },
        };
        let (persistence, transport) =
            split_persistence_prefix(vec![persist(), persist(), timer("first"), timer("second")]);

        assert_eq!(persistence.len(), 2);
        assert!(matches!(
            &transport[0],
            CoreEffect::ScheduleTimer { timer } if timer.timer_id == "first"
        ));
        assert!(matches!(
            &transport[1],
            CoreEffect::ScheduleTimer { timer } if timer.timer_id == "second"
        ));
    }

    #[tokio::test]
    async fn persisted_commands_return_before_blocked_fake_transport_and_keep_fifo() {
        let (tx, mut rx) = mpsc::channel::<u8>(2);
        let release_network = Arc::new(Notify::new());
        let (network_started_tx, network_started_rx) = oneshot::channel();
        let order = Arc::new(Mutex::new(Vec::new()));
        let worker_order = order.clone();
        let worker_release = release_network.clone();
        let worker = tokio::spawn(async move {
            let mut network_started_tx = Some(network_started_tx);
            while let Some(id) = rx.recv().await {
                if let Some(started) = network_started_tx.take() {
                    let _ = started.send(());
                    worker_release.notified().await;
                }
                worker_order.lock().await.push(format!("network:{id}"));
            }
        });

        // Model the production boundary: persistence completes synchronously,
        // then the command only waits for bounded-queue admission.
        order.lock().await.push("persist:1".into());
        tokio::time::timeout(Duration::from_millis(100), tx.send(1))
            .await
            .expect("first command must return before fake network release")
            .expect("queue first command");
        tokio::time::timeout(Duration::from_millis(100), network_started_rx)
            .await
            .expect("fake transport should start")
            .expect("fake transport start signal");

        order.lock().await.push("persist:2".into());
        tx.send(2).await.expect("queue second command");
        release_network.notify_one();
        drop(tx);
        worker.await.expect("join fake transport worker");

        assert_eq!(
            *order.lock().await,
            ["persist:1", "persist:2", "network:1", "network:2"]
        );
    }
}

fn emit_core_update(app: &AppHandle, output: &CoreOutput) {
    let has_updates = output.view_model.is_some()
        || output.state_update.conversations_changed
        || output.state_update.messages_changed
        || output.state_update.contacts_changed
        || output.state_update.identity_changed
        || output.state_update.checkpoints_changed
        || !output.state_update.system_statuses_changed.is_empty();
    if has_updates {
        let _ = app.emit("core-update", output);
    }
    if output.state_update.messages_changed {
        crate::commands::message::schedule_preview_prefetch(app);
    }
}

async fn execute_effect_with_handle(
    app: &AppHandle,
    _app_arc: &Arc<AppHandle>,
    output: &mut CoreOutput,
    effect: CoreEffect,
) -> Result<()> {
    let event_output = drive_core_work_queue(app, vec![DriverWork::Effect(effect)]).await?;
    merge_core_outputs(output, event_output);
    Ok(())
}

async fn ensure_deferred_transport_worker(app: &AppHandle) {
    let state = app.state::<AppState>();
    let Some(mut receiver) = state.deferred_transport_rx.lock().await.take() else {
        return;
    };
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(batch) = receiver.recv().await {
            crate::timetest!(
                "deferred_send_queue elapsed_ms={}",
                batch.enqueued_at.elapsed().as_millis()
            );
            let state = app.state::<AppState>();
            if state.inner.read().await.profile_path != batch.profile_path {
                log::info!("skipping deferred transport batch after profile switch");
                continue;
            }

            let app_arc = Arc::new(app.clone());
            let http_started_at = Instant::now();
            let mut background_output = CoreOutput::default();
            for effect in batch.effects {
                if let Err(_error) =
                    execute_effect_with_handle(&app, &app_arc, &mut background_output, effect).await
                {
                    log::warn!("deferred transport effect failed");
                    break;
                }
            }
            crate::timetest!(
                "deferred_send_http elapsed_ms={}",
                http_started_at.elapsed().as_millis()
            );
        }
    });
}

/// Test-only sibling of [`drive_core_with_handle`] that does NOT require
/// a `tauri::AppHandle`. Used by the desktop integration test
/// `tests/desktop_group_e2e.rs` to exercise the group Tauri command
/// `_impl` functions without spinning up a webview (the webview2
/// DLL linkage Tauri's `cdylib` introduces on Windows is the main reason
/// we can't just call the `#[tauri::command]` bodies directly from a
/// pure `cargo test` integration binary).
///
/// Behavioural parity with `drive_core_with_handle`, minus the two
/// UI-only bits:
///   1. `ports.set_app_handle(..)` is **not** called. A downstream
///      effect that genuinely depends on the handle (realtime progress
///      emits, timer callbacks that drive core, etc.) will no-op
///      instead of panicking — platform ports already guard for the
///      "no handle" case, per `ports/timer.rs::schedule_timer`.
///   2. `app.emit("core-update", ..)` is skipped. Integration tests
///      query snapshots directly via `AppState.inner` rather than
///      subscribing to UI events.
///
/// Everything else — effect draining, ack flushing, persistence, retry
/// semantics — is identical.
#[cfg(any(test, feature = "test-support"))]
pub async fn drive_core_without_handle(state: &AppState, input: CoreInput) -> Result<CoreOutput> {
    let mut pending = vec![DriverWork::Input(input)];
    let mut aggregate = CoreOutput::default();
    while let Some(work) = pending.pop() {
        match work {
            DriverWork::Input(input) => {
                let output = {
                    let mut inner = state.inner.write().await;
                    match input {
                        CoreInput::Command(command) => inner.engine.handle_command(command)?,
                        CoreInput::Event(event) => inner.engine.handle_event(event)?,
                    }
                };
                for effect in output.effects.iter().cloned().rev() {
                    pending.push(DriverWork::Effect(effect));
                }
                merge_core_outputs(&mut aggregate, output);
            }
            DriverWork::Effect(effect) => {
                let events = {
                    let mut ports = state.ports.lock().await;
                    execute_platform_effect(&mut *ports, effect).await?
                };
                for event in events.into_iter().rev() {
                    pending.push(DriverWork::Input(CoreInput::Event(event)));
                }
            }
        }
    }
    Ok(aggregate)
}

pub(crate) fn merge_core_outputs(base: &mut CoreOutput, mut next: CoreOutput) {
    base.state_update.conversations_changed |= next.state_update.conversations_changed;
    base.state_update.messages_changed |= next.state_update.messages_changed;
    base.state_update.contacts_changed |= next.state_update.contacts_changed;
    base.state_update.checkpoints_changed |= next.state_update.checkpoints_changed;
    base.state_update
        .system_statuses_changed
        .append(&mut next.state_update.system_statuses_changed);
    base.effects.append(&mut next.effects);

    match (&mut base.view_model, next.view_model) {
        (Some(base_vm), Some(next_vm)) => merge_view_models(base_vm, next_vm),
        (None, Some(next_vm)) => base.view_model = Some(next_vm),
        _ => {}
    }
}

fn merge_view_models(base: &mut CoreViewModel, mut next: CoreViewModel) {
    base.conversations.append(&mut next.conversations);
    base.messages.append(&mut next.messages);
    base.contacts.append(&mut next.contacts);
    base.banners.append(&mut next.banners);
    base.message_requests.append(&mut next.message_requests);
    if next.allowlist.is_some() {
        base.allowlist = next.allowlist;
    }
    if next.message_request_action.is_some() {
        base.message_request_action = next.message_request_action;
    }
    if next.append_result.is_some() {
        base.append_result = next.append_result;
    }
    base.group_invites.append(&mut next.group_invites);
    base.group_join_requests
        .append(&mut next.group_join_requests);
    base.group_leave_requests
        .append(&mut next.group_leave_requests);
    base.welcome_pickups.append(&mut next.welcome_pickups);
    if next.group_sync_results.is_some() {
        base.group_sync_results = next.group_sync_results;
    }
}

/// Transition from onboarding to active session.
/// Called when onboarding completes successfully.
#[tauri::command]
pub async fn complete_onboarding(app: AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();

    // Hide setup immediately so the active route never renders in the setup window.
    if let Some(onboarding_window) = app.get_webview_window("onboarding") {
        onboarding_window.hide().map_err(|e| e.to_string())?;
    }

    // Get device_id from profile and persist session state
    let device_id = {
        let inner = state.inner.read().await;
        inner
            .profile_manager
            .get_active_metadata()
            .await
            .and_then(|m| m.device_id)
            .unwrap_or_else(|| "unknown-device".to_string())
    };

    // Update session state
    {
        let mut inner = state.inner.write().await;
        inner.session = SessionState::Active {
            device_id: device_id.clone(),
        };
        inner.startup_phase = StartupPhase::Ready; // Ensure startup phase is ready

        // Persist the current snapshot to profile
        let snapshot = inner.engine.refresh_snapshot();
        if let Err(_error) = inner.profile_manager.save_snapshot(&snapshot).await {
            log::error!("Failed to save snapshot");
        }
    }

    set_ws_connection_snapshot(&state, Some(device_id.clone()), false).await;

    let session_status = SessionStatus {
        state: "active".to_string(),
        device_id: Some(device_id),
        ws_connected: false,
        profile_path: None,
        error: None,
        lock_reason: None,
    };

    // Show main window and notify only that frontend so onboarding cannot route into the app shell.
    if let Some(main_window) = app.get_webview_window("main") {
        main_window
            .set_title("TapChat")
            .map_err(|e| e.to_string())?;
        let _ = main_window.emit("session-status", session_status.clone());
        main_window.show().map_err(|e| e.to_string())?;
        if let Err(_error) = main_window.set_focus() {
            log::error!("Failed to focus main window");
        }
    } else {
        let _ = app.emit("session-status", session_status);
    }

    // Close onboarding window after main is ready.
    if let Some(onboarding_window) = app.get_webview_window("onboarding") {
        onboarding_window.close().map_err(|e| e.to_string())?;
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
        inner.session = SessionState::Onboarding {
            step: onboarding_step,
        };
    }

    Ok(())
}

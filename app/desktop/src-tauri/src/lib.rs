use std::collections::HashMap;
use std::env;
use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tauri::menu::{MenuBuilder, MenuItemBuilder};
use tauri::tray::TrayIconBuilder;
use tauri::webview::WebviewWindowBuilder;
use tauri::{AppHandle, Emitter, Manager, State, WebviewUrl, WindowEvent};
use tauri_plugin_notification::NotificationExt;

use tapchat_core::cli::runtime::CloudflareDeployOverrides;
use tapchat_core::cli::driver::CoreDriver;
use tapchat_core::cli::profile::Profile;
use tapchat_core::ffi_api::CoreOutput;
use tapchat_core::CoreEvent;
use tapchat_core::desktop_app;

#[derive(Debug, Clone, Default)]
struct SessionStatus {
    device_id: Option<String>,
    connected: bool,
    needs_reconnect: bool,
    last_known_seq: u64,
}

struct SessionHandle {
    status: Arc<Mutex<SessionStatus>>,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tauri::async_runtime::JoinHandle<()>,
}

#[derive(Default)]
struct RealtimeManager {
    sessions: Mutex<HashMap<String, SessionHandle>>,
    generations: Mutex<HashMap<String, u64>>,
}

#[derive(Default)]
struct LifecycleManager {
    quitting: AtomicBool,
}

#[derive(Debug, Clone)]
struct BackgroundDownloadTask {
    profile_path: String,
}

#[derive(Default)]
struct BackgroundDownloadManager {
    active: Mutex<HashMap<String, BackgroundDownloadTask>>,
    last_error: Mutex<Option<String>>,
}

#[derive(Default)]
struct CloudflareWizardManager {
    statuses: Mutex<HashMap<String, desktop_app::CloudflareWizardStatusView>>,
    generations: Mutex<HashMap<String, u64>>,
}

fn into_string_error(error: anyhow::Error) -> String {
    error.to_string()
}

fn desktop_runtime_platform_dir() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "windows-x64"
    }
    #[cfg(target_os = "macos")]
    {
        "macos-universal"
    }
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        "linux-x64"
    }
}

fn possible_runtime_roots(app: &AppHandle) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(resource_dir) = app.path().resource_dir() {
        candidates.push(resource_dir);
    }
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            candidates.push(parent.to_path_buf());
            candidates.push(parent.join("resources"));
        }
    }
    candidates
}

fn configure_embedded_cloudflare_runtime(app: &AppHandle) {
    let platform_dir = desktop_runtime_platform_dir();
    for root in possible_runtime_roots(app) {
        let runtime_root = root.join("runtime").join("dist").join(platform_dir);
        let service_root = runtime_root.join("cloudflare-service");
        if !service_root.exists() {
            continue;
        }
        env::set_var("TAPCHAT_DESKTOP_RUNTIME_ROOT", &runtime_root);
        env::set_var("TAPCHAT_CLOUDFLARE_SERVICE_ROOT", &service_root);
        env::set_var("TAPCHAT_CLOUDFLARE_WORKSPACE_ROOT", &runtime_root);
        break;
    }
}

fn session_status_for(
    manager: &State<'_, RealtimeManager>,
    profile_path: &str,
) -> Option<SessionStatus> {
    let sessions = manager.sessions.lock().ok()?;
    let handle = sessions.get(profile_path)?;
    handle.status.lock().ok().map(|value| value.clone())
}

fn active_download_count(manager: &BackgroundDownloadManager, profile_path: Option<&str>) -> usize {
    manager
        .active
        .lock()
        .ok()
        .map(|tasks| {
            tasks.values().filter(|task| {
                profile_path.is_none_or(|value| value == task.profile_path)
            }).count()
        })
        .unwrap_or_default()
}

fn last_background_error(manager: &BackgroundDownloadManager) -> Option<String> {
    manager.last_error.lock().ok().and_then(|value| value.clone())
}

fn set_last_background_error(manager: &BackgroundDownloadManager, error: Option<String>) {
    if let Ok(mut current) = manager.last_error.lock() {
        *current = error;
    }
}

fn load_realtime_driver(profile: &Profile) -> anyhow::Result<CoreDriver> {
    let snapshot = profile.load_snapshot()?;
    let base_url = snapshot
        .deployment
        .as_ref()
        .map(|deployment| deployment.deployment_bundle.inbox_http_endpoint.clone());
    CoreDriver::from_snapshot(snapshot, base_url, None)
}

fn persist_realtime_driver(profile: &mut Profile, driver: &CoreDriver) -> anyhow::Result<()> {
    if let Some(snapshot) = driver.latest_snapshot() {
        profile.save_snapshot(snapshot)?;
    }
    let user_id = driver
        .local_identity()
        .map(|identity| identity.user_identity.user_id.clone());
    let device_id = driver
        .local_identity()
        .map(|identity| identity.device_identity.device_id.clone());
    profile.update_identity(user_id, device_id)?;
    Ok(())
}

fn bump_realtime_generation(manager: &RealtimeManager, profile_path: &str) -> Result<u64, String> {
    let mut generations = manager
        .generations
        .lock()
        .map_err(|_| "realtime generations lock poisoned".to_string())?;
    let next = generations
        .get(profile_path)
        .copied()
        .unwrap_or_default()
        .saturating_add(1);
    generations.insert(profile_path.to_string(), next);
    Ok(next)
}

fn realtime_generation_matches(
    manager: &RealtimeManager,
    profile_path: &str,
    generation: u64,
) -> bool {
    manager
        .generations
        .lock()
        .ok()
        .and_then(|generations| generations.get(profile_path).copied())
        .is_some_and(|current| current == generation)
}

async fn stop_realtime_session(
    manager: &RealtimeManager,
    profile_path: &str,
) -> Result<bool, String> {
    let _ = bump_realtime_generation(manager, profile_path)?;
    let handle = {
        let mut sessions = manager
            .sessions
            .lock()
            .map_err(|_| "lock poisoned".to_string())?;
        sessions.remove(profile_path)
    };
    let Some(handle) = handle else {
        return Ok(false);
    };
    let _ = handle.stop.send(());
    handle.task.await.map_err(|error| error.to_string())?;
    Ok(true)
}

async fn run_with_paused_realtime<T, Fut>(
    app: AppHandle,
    manager: &RealtimeManager,
    profile_path: String,
    task: Fut,
) -> Result<T, String>
where
    Fut: Future<Output = Result<T, String>>,
{
    let should_resume = stop_realtime_session(manager, &profile_path).await?;
    let result = task.await;
    let resume_result = if should_resume {
        start_realtime_session(profile_path.clone(), app, manager).map(|_| ())
    } else {
        Ok(())
    };
    match (result, resume_result) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(_resume_error)) => Err(error),
    }
}

fn outputs_changed_message_requests(outputs: &[CoreOutput]) -> bool {
    outputs.iter().any(|output| {
        output
            .view_model
            .as_ref()
            .map(|view| !view.message_requests.is_empty() || view.message_request_action.is_some())
            .unwrap_or(false)
    })
}

fn stop_all_realtime_sessions(manager: &RealtimeManager) {
    if let Ok(mut sessions) = manager.sessions.lock() {
        for (_, handle) in sessions.drain() {
            let _ = handle.stop.send(());
        }
    }
}

fn bump_wizard_generation(
    manager: &CloudflareWizardManager,
    profile_path: &str,
) -> Result<u64, String> {
    let mut generations = manager
        .generations
        .lock()
        .map_err(|_| "wizard generations lock poisoned".to_string())?;
    let next = generations.get(profile_path).copied().unwrap_or_default().saturating_add(1);
    generations.insert(profile_path.to_string(), next);
    Ok(next)
}

fn wizard_generation_matches(
    manager: &CloudflareWizardManager,
    profile_path: &str,
    generation: u64,
) -> bool {
    manager
        .generations
        .lock()
        .ok()
        .and_then(|generations| generations.get(profile_path).copied())
        .is_some_and(|current| current == generation)
}

fn set_wizard_status(
    manager: &CloudflareWizardManager,
    profile_path: &str,
    status: desktop_app::CloudflareWizardStatusView,
) {
    if let Ok(mut statuses) = manager.statuses.lock() {
        statuses.insert(profile_path.to_string(), status);
    }
}

fn wizard_status_for(
    manager: &CloudflareWizardManager,
    profile_path: &str,
) -> desktop_app::CloudflareWizardStatusView {
    manager
        .statuses
        .lock()
        .ok()
        .and_then(|statuses| statuses.get(profile_path).cloned())
        .unwrap_or(desktop_app::CloudflareWizardStatusView {
            state: "idle".into(),
            message: "Ready to set up Cloudflare transport.".into(),
            blocking_error: None,
            deploy_url: None,
            worker_name: None,
            bundle_imported: false,
            last_error_code: None,
            last_error_detail: None,
            diagnostic_bootstrap_url: None,
            diagnostic_deploy_url: None,
            diagnostic_runtime_url: None,
        })
}

fn update_tray_tooltip(app: &AppHandle, active_profile: Option<&str>) {
    let Some(tray) = app.tray_by_id("tapchat-tray") else {
        return;
    };
    let background = app.state::<BackgroundDownloadManager>();
    let downloads = active_download_count(&background, active_profile);
    let last_error = last_background_error(&background).unwrap_or_else(|| "None".into());
    let tooltip = format!(
        "TapChat Desktop\nProfile: {}\nActive downloads: {}\nLast error: {}",
        active_profile.unwrap_or("none"),
        downloads,
        last_error,
    );
    let _ = tray.set_tooltip(Some(tooltip));
}

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn ensure_onboarding_window(app: &AppHandle) -> tauri::Result<()> {
    if app.get_webview_window("onboarding").is_some() {
        return Ok(());
    }
    let builder = WebviewWindowBuilder::new(app, "onboarding", WebviewUrl::default())
        .title("TapChat Setup")
        .inner_size(920.0, 760.0)
        .min_inner_size(760.0, 620.0)
        .center()
        .visible(false)
        .resizable(true);
    let _ = builder.build()?;
    Ok(())
}

fn sync_window_visibility_from_bootstrap(app: &AppHandle) -> tauri::Result<String> {
    let bootstrap = desktop_app::app_bootstrap()
        .map_err(|error| tauri::Error::Anyhow(anyhow::anyhow!(error.to_string())))?;
    let onboarding_complete = bootstrap.onboarding.step == "complete";
    let main = app.get_webview_window("main");

    if onboarding_complete {
        if let Some(onboarding) = app.get_webview_window("onboarding") {
            let _ = onboarding.hide();
        }
        if let Some(main) = main {
            let _ = main.show();
            let _ = main.set_focus();
        }
        if let Some(profile) = bootstrap.active_profile.as_ref() {
            let profile_path = profile.path.to_string_lossy().to_string();
            update_tray_tooltip(app, Some(&profile_path));
        }
        return Ok(String::from("main"));
    }

    if let Some(main) = main {
        let _ = main.hide();
    }
    ensure_onboarding_window(app)?;
    if let Some(onboarding) = app.get_webview_window("onboarding") {
        let _ = onboarding.show();
        let _ = onboarding.set_focus();
    }
    update_tray_tooltip(app, bootstrap.active_profile.as_ref().map(|profile| profile.path.to_string_lossy()).as_deref());
    Ok(String::from("onboarding"))
}

fn notify_attachment_event(
    app: &AppHandle,
    title: &str,
    body: &str,
) {
    let _ = app
        .notification()
        .builder()
        .title(title)
        .body(body)
        .show();
}

fn start_realtime_session(
    profile_path: String,
    app: AppHandle,
    manager: &RealtimeManager,
) -> Result<bool, String> {
    let generation = bump_realtime_generation(manager, &profile_path)?;
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel();
    let status = Arc::new(Mutex::new(SessionStatus::default()));
    let status_for_task = Arc::clone(&status);
    let profile_for_task = profile_path.clone();
    let app_for_task = app.clone();

    let task = tauri::async_runtime::spawn(async move {
        let manager_state = app_for_task.state::<RealtimeManager>();
        let mut profile = match Profile::open(&profile_for_task) {
            Ok(profile) => profile,
            Err(_) => {
                if let Ok(mut current) = status_for_task.lock() {
                    current.connected = false;
                    current.needs_reconnect = true;
                }
                return;
            }
        };
        let mut driver = match load_realtime_driver(&profile) {
            Ok(driver) => driver,
            Err(_) => {
                if let Ok(mut current) = status_for_task.lock() {
                    current.connected = false;
                    current.needs_reconnect = true;
                }
                return;
            }
        };
        let Some(device_id) = driver
            .local_identity()
            .map(|identity| identity.device_identity.device_id.clone())
        else {
            if let Ok(mut current) = status_for_task.lock() {
                current.connected = false;
                current.needs_reconnect = true;
            }
            return;
        };
        let mut reconnect_attempt = 0u32;
        let mut initialized = false;
        loop {
            if stop_rx.try_recv().is_ok()
                || !realtime_generation_matches(&manager_state, &profile_for_task, generation)
            {
                break;
            }
            let mut emit_dirty = false;
            let step_result = if !initialized {
                initialized = true;
                driver
                    .inject_event_until_idle(CoreEvent::AppForegrounded)
                    .await
                    .map(|_| Vec::new())
            } else {
                driver.pump_until_idle(Duration::from_secs(45)).await
            };

            match step_result {
                Ok(outputs) => {
                    reconnect_attempt = 0;
                    if !outputs.is_empty() {
                        if realtime_generation_matches(&manager_state, &profile_for_task, generation)
                        {
                            let _ = persist_realtime_driver(&mut profile, &driver);
                            emit_dirty = true;
                            if outputs_changed_message_requests(&outputs) {
                                let _ = app_for_task.emit(
                                    "tapchat://message-requests-dirty",
                                    &profile_for_task,
                                );
                            }
                        } else {
                            break;
                        }
                    }
                    if let Some(snapshot) = driver.realtime_session_snapshot(&device_id) {
                        if let Ok(mut current) = status_for_task.lock() {
                            let connected = !snapshot.needs_reconnect;
                            let changed = current.connected != connected
                                || current.needs_reconnect != snapshot.needs_reconnect
                                || current.last_known_seq != snapshot.last_known_seq;
                            current.connected = connected;
                            current.needs_reconnect = snapshot.needs_reconnect;
                            current.last_known_seq = snapshot.last_known_seq;
                            current.device_id = Some(device_id.clone());
                            if changed {
                                emit_dirty = true;
                            }
                        }
                    }
                    if emit_dirty {
                        let _ =
                            app_for_task.emit("tapchat://direct-shell-dirty", &profile_for_task);
                        update_tray_tooltip(&app_for_task, Some(&profile_for_task));
                    }
                }
                Err(_) => {
                    reconnect_attempt = reconnect_attempt.saturating_add(1);
                    if let Ok(mut current) = status_for_task.lock() {
                        current.connected = false;
                        current.needs_reconnect = true;
                        current.device_id = Some(device_id.clone());
                    }
                    let _ = app_for_task.emit("tapchat://direct-shell-dirty", &profile_for_task);
                    let delay_seconds = [1u64, 2, 4, 8, 15]
                        [usize::min(reconnect_attempt.saturating_sub(1) as usize, 4)];
                    tokio::select! {
                        _ = &mut stop_rx => break,
                        _ = tokio::time::sleep(Duration::from_secs(delay_seconds)) => {}
                    }
                }
            }
        }

        if let Ok(mut current) = status_for_task.lock() {
            current.connected = false;
        }
        let _ = app_for_task.emit("tapchat://direct-shell-dirty", &profile_for_task);
    });

    let mut sessions = manager
        .sessions
        .lock()
        .map_err(|_| "lock poisoned".to_string())?;
    let previous = sessions.insert(
        profile_path,
        SessionHandle {
            status,
            stop: stop_tx,
            task,
        },
    );
    drop(sessions);
    if let Some(handle) = previous {
        let _ = handle.stop.send(());
        tauri::async_runtime::spawn(async move {
            let _ = handle.task.await;
        });
    }
    Ok(true)
}

fn spawn_resume_pending_downloads(app: AppHandle, profile_path: String) {
    tauri::async_runtime::spawn(async move {
        let manager = app.state::<RealtimeManager>();
        let result = run_with_paused_realtime(
            app.clone(),
            &manager,
            profile_path.clone(),
            async { desktop_app::sync_foreground(&profile_path).await.map_err(into_string_error) },
        )
        .await;
        if let Err(error) = result {
            let background = app.state::<BackgroundDownloadManager>();
            set_last_background_error(&background, Some(error.to_string()));
        }
        let _ = app.emit("tapchat://direct-shell-dirty", &profile_path);
        update_tray_tooltip(&app, Some(&profile_path));
    });
}

fn spawn_background_download(
    app: AppHandle,
    profile_path: String,
    conversation_id: String,
    message_id: String,
    reference: String,
    destination: PathBuf,
) -> desktop_app::BackgroundDownloadTicketView {
    let transfer_id = format!("download:{conversation_id}:{message_id}");
    let ticket_conversation_id = conversation_id.clone();
    let ticket_message_id = message_id.clone();
    let ticket_destination = destination.clone();
    {
        let background = app.state::<BackgroundDownloadManager>();
        if let Ok(mut active) = background.active.lock() {
            active.insert(
                transfer_id.clone(),
                BackgroundDownloadTask {
                    profile_path: profile_path.clone(),
                },
            );
        }
        set_last_background_error(&background, None);
    }
    let _ = desktop_app::record_background_download_status(
        &profile_path,
        &conversation_id,
        &message_id,
        &reference,
        Some(&destination),
        "in_flight",
        None,
    );
    let _ = app.emit("tapchat://direct-shell-dirty", &profile_path);
    update_tray_tooltip(&app, Some(&profile_path));

    let task_app = app.clone();
    let task_transfer_id = transfer_id.clone();
    let task_profile_path = profile_path.clone();
    let task_conversation_id = conversation_id.clone();
    let task_message_id = message_id.clone();
    let task_reference = reference.clone();
    let task_destination = destination.clone();
    tauri::async_runtime::spawn(async move {
        let result = desktop_app::message_download_attachment(
            &task_profile_path,
            &task_conversation_id,
            &task_message_id,
            &task_reference,
            Some(task_destination.clone()),
        )
        .await;

        match result {
            Ok(view) => {
                let preview = desktop_app::attachment_preview_source(
                    &task_profile_path,
                    &task_message_id,
                    Some(&task_reference),
                )
                .ok();
                let display_name = preview
                    .map(|item| item.display_name)
                    .unwrap_or_else(|| task_message_id.clone());
                notify_attachment_event(
                    &task_app,
                    "TapChat attachment",
                    &format!("Attachment saved: {display_name}"),
                );
                let _ = task_app.emit("tapchat://background-download-complete", &view);
            }
            Err(error) => {
                let background = task_app.state::<BackgroundDownloadManager>();
                set_last_background_error(&background, Some(error.to_string()));
                let _ = desktop_app::record_background_download_status(
                    &task_profile_path,
                    &task_conversation_id,
                    &task_message_id,
                    &task_reference,
                    Some(&task_destination),
                    "failed",
                    Some(&error.to_string()),
                );
                notify_attachment_event(
                    &task_app,
                    "TapChat attachment",
                    &format!("Attachment download failed: {task_message_id}"),
                );
            }
        }

        {
            let background = task_app.state::<BackgroundDownloadManager>();
            if let Ok(mut active) = background.active.lock() {
                active.remove(&task_transfer_id);
            };
        }
        let _ = task_app.emit("tapchat://direct-shell-dirty", &task_profile_path);
        update_tray_tooltip(&task_app, Some(&task_profile_path));
    });

    desktop_app::BackgroundDownloadTicketView {
        transfer_id,
        conversation_id: ticket_conversation_id,
        message_id: ticket_message_id,
        destination: ticket_destination,
        started: true,
    }
}

#[tauri::command]
fn app_bootstrap() -> Result<desktop_app::AppBootstrapView, String> {
    desktop_app::app_bootstrap().map_err(into_string_error)
}

#[tauri::command]
fn sync_window_visibility(app: AppHandle) -> Result<String, String> {
    sync_window_visibility_from_bootstrap(&app).map_err(|error| error.to_string())
}

#[tauri::command]
fn profile_list() -> Result<Vec<desktop_app::ProfileSummary>, String> {
    desktop_app::profile_list().map_err(into_string_error)
}

#[tauri::command]
fn profile_activate(
    profile_id_or_path: String,
    app: AppHandle,
) -> Result<desktop_app::AppBootstrapView, String> {
    let bootstrap = desktop_app::profile_activate(&profile_id_or_path).map_err(into_string_error)?;
    update_tray_tooltip(
        &app,
        bootstrap.active_profile.as_ref().map(|profile| profile.path.to_string_lossy()).as_deref(),
    );
    Ok(bootstrap)
}

#[tauri::command]
fn profile_create(name: String, root: String) -> Result<desktop_app::ProfileSummary, String> {
    desktop_app::profile_create(&name, root).map_err(into_string_error)
}

#[tauri::command]
fn profile_open_or_import(root_dir: String) -> Result<desktop_app::ProfileSummary, String> {
    desktop_app::profile_open_or_import(root_dir).map_err(into_string_error)
}

#[tauri::command]
fn profile_reveal_in_shell(profile_path: String) -> Result<bool, String> {
    let path = std::path::PathBuf::from(profile_path);
    if !path.exists() {
        return Err("profile path does not exist".into());
    }
    open::that_detached(path).map_err(|error| error.to_string())?;
    Ok(true)
}

#[tauri::command]
fn show_onboarding_window(app: AppHandle) -> Result<String, String> {
    if let Some(main) = app.get_webview_window("main") {
        let _ = main.hide();
    }
    ensure_onboarding_window(&app).map_err(|error| error.to_string())?;
    if let Some(onboarding) = app.get_webview_window("onboarding") {
        let _ = onboarding.show();
        let _ = onboarding.set_focus();
    }
    Ok(String::from("onboarding"))
}

#[tauri::command]
fn complete_onboarding_handoff(
    app: AppHandle,
    profile_path: Option<String>,
) -> Result<desktop_app::AppBootstrapView, String> {
    if let Some(profile_path) = profile_path.as_deref() {
        let _ = desktop_app::profile_activate(profile_path).map_err(into_string_error)?;
    }
    let bootstrap = desktop_app::app_bootstrap().map_err(into_string_error)?;
    if bootstrap.onboarding.step != "complete" {
        return Err(String::from("onboarding is not complete"));
    }
    if let Some(active_profile) = bootstrap.active_profile.as_ref() {
        let active_profile_path = active_profile.path.to_string_lossy().to_string();
        let _ = desktop_app::profile_activate(&active_profile_path).map_err(into_string_error)?;
    }
    let bootstrap = desktop_app::app_bootstrap().map_err(into_string_error)?;
    sync_window_visibility_from_bootstrap(&app).map_err(|error| error.to_string())?;
    let _ = app.emit("tapchat://bootstrap-dirty", &bootstrap);
    Ok(bootstrap)
}

#[tauri::command]
async fn identity_create(
    profile_path: String,
    device_name: String,
) -> Result<desktop_app::IdentitySummaryView, String> {
    tauri::async_runtime::spawn_blocking(move || {
        tauri::async_runtime::block_on(desktop_app::identity_create(profile_path, &device_name))
            .map_err(into_string_error)
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn identity_recover(
    profile_path: String,
    device_name: String,
    mnemonic: String,
) -> Result<desktop_app::IdentitySummaryView, String> {
    tauri::async_runtime::spawn_blocking(move || {
        tauri::async_runtime::block_on(desktop_app::identity_recover(
            profile_path,
            &device_name,
            mnemonic,
        ))
        .map_err(into_string_error)
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn deployment_import(
    profile_path: String,
    bundle_json_or_path: String,
) -> Result<desktop_app::RuntimeStatusView, String> {
    desktop_app::deployment_import(profile_path, &bundle_json_or_path)
        .await
        .map_err(into_string_error)
}

#[tauri::command]
async fn cloudflare_provision_auto(
    profile_path: String,
) -> Result<desktop_app::ProvisionProgressView, String> {
    desktop_app::cloudflare_provision_auto(profile_path)
        .await
        .map_err(into_string_error)
}

#[tauri::command]
fn cloudflare_preflight(
    profile_path: String,
) -> Result<desktop_app::CloudflarePreflightView, String> {
    desktop_app::cloudflare_preflight(profile_path).map_err(into_string_error)
}

#[tauri::command]
async fn cloudflare_provision_custom(
    profile_path: String,
    overrides: CloudflareDeployOverrides,
) -> Result<desktop_app::ProvisionProgressView, String> {
    desktop_app::cloudflare_provision_custom(profile_path, overrides)
        .await
        .map_err(into_string_error)
}

#[tauri::command]
fn cloudflare_status(profile_path: String) -> Result<desktop_app::RuntimeStatusView, String> {
    desktop_app::cloudflare_status(profile_path).map_err(into_string_error)
}

#[tauri::command]
fn cloudflare_runtime_details(
    profile_path: String,
) -> Result<desktop_app::CloudflareRuntimeDetailsView, String> {
    desktop_app::cloudflare_runtime_details(profile_path).map_err(into_string_error)
}

#[tauri::command]
async fn cloudflare_redeploy(
    profile_path: String,
) -> Result<desktop_app::CloudflareActionResultView, String> {
    desktop_app::cloudflare_redeploy(profile_path)
        .await
        .map_err(into_string_error)
}

#[tauri::command]
async fn cloudflare_rotate_secrets(
    profile_path: String,
) -> Result<desktop_app::CloudflareActionResultView, String> {
    desktop_app::cloudflare_rotate_secrets(profile_path)
        .await
        .map_err(into_string_error)
}

#[tauri::command]
fn cloudflare_detach(
    profile_path: String,
) -> Result<desktop_app::CloudflareActionResultView, String> {
    desktop_app::cloudflare_detach(profile_path).map_err(into_string_error)
}

#[tauri::command]
fn cloudflare_setup_wizard_status(
    profile_path: String,
    manager: State<'_, CloudflareWizardManager>,
) -> Result<desktop_app::CloudflareWizardStatusView, String> {
    Ok(wizard_status_for(&manager, &profile_path))
}

#[tauri::command]
fn cloudflare_setup_wizard_cancel(
    profile_path: String,
    manager: State<'_, CloudflareWizardManager>,
) -> Result<desktop_app::CloudflareWizardStatusView, String> {
    let _ = bump_wizard_generation(&manager, &profile_path)?;
    let status = desktop_app::CloudflareWizardStatusView {
        state: "idle".into(),
        message: "Cloudflare setup canceled.".into(),
        blocking_error: None,
        deploy_url: None,
        worker_name: None,
        bundle_imported: false,
        last_error_code: None,
        last_error_detail: None,
        diagnostic_bootstrap_url: None,
        diagnostic_deploy_url: None,
        diagnostic_runtime_url: None,
    };
    set_wizard_status(&manager, &profile_path, status.clone());
    Ok(status)
}

#[tauri::command]
fn cloudflare_setup_wizard_start(
    profile_path: String,
    mode: String,
    overrides: Option<CloudflareDeployOverrides>,
    app: AppHandle,
    manager: State<'_, CloudflareWizardManager>,
) -> Result<desktop_app::CloudflareWizardStatusView, String> {
    let generation = bump_wizard_generation(&manager, &profile_path)?;
    let initial = desktop_app::CloudflareWizardStatusView {
        state: "preflight".into(),
        message: "Checking Cloudflare workspace and profile readiness.".into(),
        blocking_error: None,
        deploy_url: None,
        worker_name: None,
        bundle_imported: false,
        last_error_code: None,
        last_error_detail: None,
        diagnostic_bootstrap_url: None,
        diagnostic_deploy_url: None,
        diagnostic_runtime_url: None,
    };
    set_wizard_status(&manager, &profile_path, initial.clone());

    let app_for_task = app.clone();
    let profile_for_task = profile_path.clone();
    let mode_for_task = mode.clone();
    let overrides_for_task = overrides.clone();
    tauri::async_runtime::spawn(async move {
        let manager = app_for_task.state::<CloudflareWizardManager>();
        let result = desktop_app::cloudflare_setup_wizard_execute(
            &profile_for_task,
            &mode_for_task,
            overrides_for_task,
            |status| {
                if wizard_generation_matches(&manager, &profile_for_task, generation) {
                    set_wizard_status(&manager, &profile_for_task, status.clone());
                    let _ = app_for_task.emit("tapchat://cloudflare-wizard", &status);
                }
            },
        )
        .await;

        if wizard_generation_matches(&manager, &profile_for_task, generation) {
            if let Ok(status) = result {
                set_wizard_status(&manager, &profile_for_task, status);
                let _ = app_for_task.emit("tapchat://direct-shell-dirty", &profile_for_task);
            }
        }
    });

    Ok(initial)
}

#[tauri::command]
fn contact_list(profile_path: String) -> Result<Vec<desktop_app::ContactListItem>, String> {
    desktop_app::contact_list(profile_path).map_err(into_string_error)
}

#[tauri::command]
async fn contact_import_identity(
    profile_path: String,
    bundle_json_or_path: String,
    app: AppHandle,
    manager: State<'_, RealtimeManager>,
) -> Result<desktop_app::ContactDetailView, String> {
    run_with_paused_realtime(app, &manager, profile_path.clone(), async move {
        desktop_app::contact_import_identity(profile_path, &bundle_json_or_path)
            .await
            .map_err(into_string_error)
    })
    .await
}

#[tauri::command]
async fn contact_import_share_link(
    profile_path: String,
    url: String,
    app: AppHandle,
    manager: State<'_, RealtimeManager>,
) -> Result<desktop_app::ContactDetailView, String> {
    run_with_paused_realtime(app, &manager, profile_path.clone(), async move {
        desktop_app::contact_import_share_link(profile_path, &url)
            .await
            .map_err(into_string_error)
    })
    .await
}

#[tauri::command]
async fn contact_share_link_get(
    profile_path: String,
) -> Result<desktop_app::ContactShareLinkView, String> {
    desktop_app::contact_share_link_get(profile_path)
        .await
        .map_err(into_string_error)
}

#[tauri::command]
async fn contact_share_link_rotate(
    profile_path: String,
) -> Result<desktop_app::ContactShareLinkView, String> {
    desktop_app::contact_share_link_rotate(profile_path)
        .await
        .map_err(into_string_error)
}

#[tauri::command]
fn contact_show(
    profile_path: String,
    user_id: String,
) -> Result<desktop_app::ContactDetailView, String> {
    desktop_app::contact_show(profile_path, &user_id).map_err(into_string_error)
}

#[tauri::command]
async fn message_requests_list(
    profile_path: String,
) -> Result<Vec<desktop_app::MessageRequestItemView>, String> {
    desktop_app::message_requests_list(profile_path)
        .await
        .map_err(into_string_error)
}

#[tauri::command]
async fn message_request_accept(
    profile_path: String,
    request_id: String,
    app: AppHandle,
    manager: State<'_, RealtimeManager>,
) -> Result<desktop_app::MessageRequestActionView, String> {
    run_with_paused_realtime(app, &manager, profile_path.clone(), async move {
        desktop_app::message_request_accept(profile_path, &request_id)
            .await
            .map_err(into_string_error)
    })
    .await
}

#[tauri::command]
async fn message_request_reject(
    profile_path: String,
    request_id: String,
    app: AppHandle,
    manager: State<'_, RealtimeManager>,
) -> Result<desktop_app::MessageRequestActionView, String> {
    run_with_paused_realtime(app, &manager, profile_path.clone(), async move {
        desktop_app::message_request_reject(profile_path, &request_id)
            .await
            .map_err(into_string_error)
    })
    .await
}

#[tauri::command]
async fn allowlist_get(profile_path: String) -> Result<desktop_app::AllowlistView, String> {
    desktop_app::allowlist_get(profile_path)
        .await
        .map_err(into_string_error)
}

#[tauri::command]
async fn allowlist_add(
    profile_path: String,
    user_id: String,
    app: AppHandle,
    manager: State<'_, RealtimeManager>,
) -> Result<desktop_app::AllowlistView, String> {
    run_with_paused_realtime(app, &manager, profile_path.clone(), async move {
        desktop_app::allowlist_add(profile_path, &user_id)
            .await
            .map_err(into_string_error)
    })
    .await
}

#[tauri::command]
async fn allowlist_remove(
    profile_path: String,
    user_id: String,
    app: AppHandle,
    manager: State<'_, RealtimeManager>,
) -> Result<desktop_app::AllowlistView, String> {
    run_with_paused_realtime(app, &manager, profile_path.clone(), async move {
        desktop_app::allowlist_remove(profile_path, &user_id)
            .await
            .map_err(into_string_error)
    })
    .await
}

#[tauri::command]
async fn contact_refresh(
    profile_path: String,
    user_id: String,
    app: AppHandle,
    manager: State<'_, RealtimeManager>,
) -> Result<desktop_app::ContactDetailView, String> {
    run_with_paused_realtime(app, &manager, profile_path.clone(), async move {
        desktop_app::contact_refresh(profile_path, &user_id)
            .await
            .map_err(into_string_error)
    })
    .await
}

#[tauri::command]
async fn conversation_create_direct(
    profile_path: String,
    peer_user_id: String,
    app: AppHandle,
    manager: State<'_, RealtimeManager>,
) -> Result<desktop_app::ConversationDetailView, String> {
    run_with_paused_realtime(app, &manager, profile_path.clone(), async move {
        desktop_app::conversation_create_direct(profile_path, &peer_user_id)
            .await
            .map_err(into_string_error)
    })
    .await
}

#[tauri::command]
async fn conversation_reconcile(
    profile_path: String,
    conversation_id: String,
    app: AppHandle,
    manager: State<'_, RealtimeManager>,
) -> Result<desktop_app::ConversationDetailView, String> {
    run_with_paused_realtime(app, &manager, profile_path.clone(), async move {
        desktop_app::conversation_reconcile(profile_path, &conversation_id)
            .await
            .map_err(into_string_error)
    })
    .await
}

#[tauri::command]
async fn conversation_rebuild(
    profile_path: String,
    conversation_id: String,
    app: AppHandle,
    manager: State<'_, RealtimeManager>,
) -> Result<desktop_app::ConversationDetailView, String> {
    run_with_paused_realtime(app, &manager, profile_path.clone(), async move {
        desktop_app::conversation_rebuild(profile_path, &conversation_id)
            .await
            .map_err(into_string_error)
    })
    .await
}

#[tauri::command]
async fn message_send_text(
    profile_path: String,
    conversation_id: String,
    text: String,
    app: AppHandle,
    manager: State<'_, RealtimeManager>,
) -> Result<desktop_app::SendMessageResultView, String> {
    run_with_paused_realtime(app, &manager, profile_path.clone(), async move {
        desktop_app::message_send_text(profile_path, &conversation_id, &text)
            .await
            .map_err(into_string_error)
    })
    .await
}

#[tauri::command]
async fn message_send_attachment(
    profile_path: String,
    conversation_id: String,
    file_path: String,
    app: AppHandle,
    manager: State<'_, RealtimeManager>,
) -> Result<desktop_app::SendAttachmentResultView, String> {
    run_with_paused_realtime(app, &manager, profile_path.clone(), async move {
        desktop_app::message_send_attachment(profile_path, &conversation_id, &file_path)
            .await
            .map_err(into_string_error)
    })
    .await
}

#[tauri::command]
async fn message_send_attachments(
    profile_path: String,
    conversation_id: String,
    file_paths: Vec<String>,
    app: AppHandle,
    manager: State<'_, RealtimeManager>,
) -> Result<desktop_app::BatchSendAttachmentResultView, String> {
    run_with_paused_realtime(app, &manager, profile_path.clone(), async move {
        desktop_app::message_send_attachments(profile_path, &conversation_id, file_paths)
            .await
            .map_err(into_string_error)
    })
    .await
}

#[tauri::command]
async fn message_download_attachment(
    profile_path: String,
    conversation_id: String,
    message_id: String,
    reference: String,
    destination: Option<String>,
) -> Result<desktop_app::DownloadAttachmentResultView, String> {
    desktop_app::message_download_attachment(
        profile_path,
        &conversation_id,
        &message_id,
        &reference,
        destination.as_deref(),
    )
    .await
    .map_err(into_string_error)
}

#[tauri::command]
fn message_download_attachment_background(
    profile_path: String,
    conversation_id: String,
    message_id: String,
    reference: String,
    destination: Option<String>,
    app: AppHandle,
) -> Result<desktop_app::BackgroundDownloadTicketView, String> {
    let destination = if let Some(destination) = destination {
        PathBuf::from(destination)
    } else {
        desktop_app::default_attachment_destination(&profile_path, &message_id)
            .map_err(into_string_error)?
    };
    Ok(spawn_background_download(
        app,
        profile_path,
        conversation_id,
        message_id,
        reference,
        destination,
    ))
}

#[tauri::command]
fn attachment_open_local(profile_path: String, message_id: String) -> Result<bool, String> {
    desktop_app::attachment_open_local(profile_path, &message_id).map_err(into_string_error)
}

#[tauri::command]
fn attachment_preview_source(
    profile_path: String,
    message_id: String,
    reference: Option<String>,
) -> Result<desktop_app::AttachmentPreviewView, String> {
    desktop_app::attachment_preview_source(profile_path, &message_id, reference.as_deref())
        .map_err(into_string_error)
}

#[tauri::command]
fn attachment_transfer_history(
    profile_path: String,
    conversation_id: Option<String>,
) -> Result<Vec<desktop_app::AttachmentTransferView>, String> {
    desktop_app::attachment_transfer_history(profile_path, conversation_id.as_deref())
        .map_err(into_string_error)
}

#[tauri::command]
fn app_set_background_mode(profile_path: String, enabled: bool) -> Result<bool, String> {
    desktop_app::app_set_background_mode(profile_path, enabled).map_err(into_string_error)
}

#[tauri::command]
fn app_background_mode(profile_path: String) -> Result<bool, String> {
    desktop_app::app_background_mode(profile_path).map_err(into_string_error)
}

#[tauri::command]
async fn sync_once(
    profile_path: String,
    app: AppHandle,
    manager: State<'_, RealtimeManager>,
) -> Result<desktop_app::SyncStatusView, String> {
    run_with_paused_realtime(app, &manager, profile_path.clone(), async move {
        desktop_app::sync_once(profile_path)
            .await
            .map_err(into_string_error)
    })
    .await
}

#[tauri::command]
async fn sync_foreground(
    profile_path: String,
    app: AppHandle,
    manager: State<'_, RealtimeManager>,
) -> Result<desktop_app::SyncStatusView, String> {
    run_with_paused_realtime(app, &manager, profile_path.clone(), async move {
        desktop_app::sync_foreground(profile_path)
            .await
            .map_err(into_string_error)
    })
    .await
}

#[tauri::command]
fn direct_shell(
    profile_path: String,
    selected_conversation_id: Option<String>,
    selected_contact_user_id: Option<String>,
    manager: State<'_, RealtimeManager>,
) -> Result<desktop_app::DirectShellView, String> {
    let mut shell = desktop_app::direct_shell(
        &profile_path,
        selected_conversation_id.as_deref(),
        selected_contact_user_id.as_deref(),
    )
    .map_err(into_string_error)?;
    let snapshot = session_status_for(&manager, &profile_path);
    shell.realtime = desktop_app::map_realtime_snapshot(
        snapshot
            .as_ref()
            .and_then(|value| value.device_id.clone())
            .or(shell.sync.device_id.clone()),
        None,
        snapshot.as_ref().map(|value| value.connected).unwrap_or(false),
    );
    if let Some(status) = snapshot {
        shell.realtime.last_known_seq = status.last_known_seq;
        shell.realtime.needs_reconnect = status.needs_reconnect;
    }
    Ok(shell)
}

#[tauri::command]
fn attachment_transfers(
    profile_path: String,
    conversation_id: Option<String>,
) -> Result<Vec<desktop_app::AttachmentTransferView>, String> {
    desktop_app::attachment_transfers(profile_path, conversation_id.as_deref())
        .map_err(into_string_error)
}

#[tauri::command]
async fn sync_realtime_close(
    profile_path: String,
    manager: State<'_, RealtimeManager>,
) -> Result<bool, String> {
    stop_realtime_session(&manager, &profile_path).await
}

#[tauri::command]
async fn sync_realtime_connect(
    profile_path: String,
    app: AppHandle,
    manager: State<'_, RealtimeManager>,
) -> Result<bool, String> {
    let _ = stop_realtime_session(&manager, &profile_path).await?;
    start_realtime_session(profile_path, app, &manager)
}

#[cfg(test)]
mod tests {
    use super::{bump_realtime_generation, realtime_generation_matches, RealtimeManager};

    #[test]
    fn realtime_generation_bump_invalidates_prior_session() {
        let manager = RealtimeManager::default();
        let first = bump_realtime_generation(&manager, "profile-a").unwrap();
        assert_eq!(first, 1);
        assert!(realtime_generation_matches(&manager, "profile-a", first));

        let second = bump_realtime_generation(&manager, "profile-a").unwrap();
        assert_eq!(second, 2);
        assert!(!realtime_generation_matches(&manager, "profile-a", first));
        assert!(realtime_generation_matches(&manager, "profile-a", second));
    }

    #[test]
    fn realtime_generation_isolated_per_profile() {
        let manager = RealtimeManager::default();
        let first = bump_realtime_generation(&manager, "profile-a").unwrap();
        let other = bump_realtime_generation(&manager, "profile-b").unwrap();
        assert_eq!(first, 1);
        assert_eq!(other, 1);
        assert!(realtime_generation_matches(&manager, "profile-a", first));
        assert!(realtime_generation_matches(&manager, "profile-b", other));
        assert!(!realtime_generation_matches(&manager, "profile-a", other + 1));
    }
}

pub fn run() {
    tauri::Builder::default()
        .manage(RealtimeManager::default())
        .manage(BackgroundDownloadManager::default())
        .manage(CloudflareWizardManager::default())
        .manage(LifecycleManager::default())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            configure_embedded_cloudflare_runtime(app.handle());
            let show = MenuItemBuilder::with_id("show", "Show TapChat").build(app)?;
            let quit = MenuItemBuilder::with_id("quit", "Quit").build(app)?;
            let menu = MenuBuilder::new(app).items(&[&show, &quit]).build()?;
            let _tray = TrayIconBuilder::with_id("tapchat-tray")
                .tooltip("TapChat Desktop")
                .menu(&menu)
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "show" => {
                        let _ = sync_window_visibility_from_bootstrap(app);
                        show_main_window(app);
                    }
                    "quit" => {
                        let lifecycle = app.state::<LifecycleManager>();
                        lifecycle.quitting.store(true, Ordering::SeqCst);
                        stop_all_realtime_sessions(&app.state::<RealtimeManager>());
                        if let Ok(mut active) = app.state::<BackgroundDownloadManager>().active.lock() {
                            active.clear();
                        }
                        app.exit(0)
                    }
                    _ => {}
                })
                .build(app)?;
            let routed = sync_window_visibility_from_bootstrap(app.handle()).ok();
            if routed.as_deref() == Some("main") {
                if let Ok(bootstrap) = desktop_app::app_bootstrap() {
                    if let Some(profile) = bootstrap.active_profile.as_ref() {
                        let profile_path = profile.path.to_string_lossy().to_string();
                        if desktop_app::app_background_mode(&profile_path).unwrap_or(true)
                            && desktop_app::attachment_transfers(&profile_path, None)
                                .map(|transfers| transfers.iter().any(|transfer| transfer.task_kind == "download"))
                                .unwrap_or(false)
                        {
                            spawn_resume_pending_downloads(app.handle().clone(), profile_path.clone());
                        }
                    }
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                let quitting = window
                    .app_handle()
                    .state::<LifecycleManager>()
                    .quitting
                    .load(Ordering::SeqCst);
                if quitting {
                    return;
                }
                if window.label() == "main" {
                    api.prevent_close();
                    let _ = window.hide();
                } else if window.label() == "onboarding" {
                    // Don't close the onboarding window if it's in the middle of setup
                    let onboarding_complete = desktop_app::app_bootstrap()
                        .map(|bootstrap| bootstrap.onboarding.step == "complete")
                        .unwrap_or(false);
                    if !onboarding_complete {
                        // Prevent closing if onboarding is not complete
                        api.prevent_close();
                    }
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            app_bootstrap,
            sync_window_visibility,
            profile_list,
            profile_activate,
            profile_create,
            profile_open_or_import,
            profile_reveal_in_shell,
            show_onboarding_window,
            complete_onboarding_handoff,
            identity_create,
            identity_recover,
            deployment_import,
            cloudflare_provision_auto,
            cloudflare_preflight,
            cloudflare_provision_custom,
            cloudflare_status,
            cloudflare_runtime_details,
            cloudflare_redeploy,
            cloudflare_rotate_secrets,
            cloudflare_detach,
            cloudflare_setup_wizard_start,
            cloudflare_setup_wizard_status,
            cloudflare_setup_wizard_cancel,
            contact_list,
            contact_import_identity,
            contact_import_share_link,
            contact_share_link_get,
            contact_share_link_rotate,
            contact_show,
            message_requests_list,
            message_request_accept,
            message_request_reject,
            allowlist_get,
            allowlist_add,
            allowlist_remove,
            contact_refresh,
            conversation_create_direct,
            conversation_reconcile,
            conversation_rebuild,
            message_send_text,
            message_send_attachment,
            message_send_attachments,
            message_download_attachment,
            message_download_attachment_background,
            attachment_open_local,
            attachment_preview_source,
            attachment_transfer_history,
            app_set_background_mode,
            app_background_mode,
            sync_once,
            sync_foreground,
            direct_shell,
            attachment_transfers,
            sync_realtime_close,
            sync_realtime_connect,
        ])
        .run(tauri::generate_context!())
        .unwrap_or_else(|error| eprintln!("error while running tapchat desktop: {error}"));
}

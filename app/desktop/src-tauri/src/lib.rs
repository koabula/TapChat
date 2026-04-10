use std::collections::HashMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::future::Future;
use std::io::Write;
use std::panic;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tauri::menu::{MenuBuilder, MenuItemBuilder};
use tauri::tray::TrayIconBuilder;
use tauri::webview::WebviewWindowBuilder;
use tauri::{AppHandle, Emitter, Manager, State, WebviewUrl, WindowEvent};
use tauri_plugin_notification::NotificationExt;

use tapchat_core::cli::driver::CoreDriver;
use tapchat_core::cli::profile::Profile;
use tapchat_core::cli::runtime::CloudflareDeployOverrides;
use tapchat_core::desktop_app;
use tapchat_core::ffi_api::CoreOutput;
use tapchat_core::CoreEvent;

static APP_LOG_DIR: OnceLock<PathBuf> = OnceLock::new();
static ACTIVE_PROFILE_LOG_ROOT: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();
static ONBOARDING_HANDOFF_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowRoute {
    Main,
    Onboarding,
}

#[derive(Debug, Clone, Default)]
struct WindowRoutingSnapshot {
    route: Option<WindowRoute>,
    onboarding_complete: bool,
    active_profile_path: Option<String>,
}

#[derive(Default)]
struct WindowRoutingState {
    snapshot: Mutex<WindowRoutingSnapshot>,
    deferred_onboarding_close_in_flight: AtomicBool,
}

fn window_route_label(route: WindowRoute) -> &'static str {
    match route {
        WindowRoute::Main => "main",
        WindowRoute::Onboarding => "onboarding",
    }
}

fn route_is_unchanged(current: Option<WindowRoute>, next: WindowRoute) -> bool {
    current.is_some_and(|value| value == next)
}

fn route_target_available(app: &AppHandle, route: WindowRoute) -> bool {
    match route {
        WindowRoute::Main => app.get_webview_window("main").is_some(),
        WindowRoute::Onboarding => app.get_webview_window("onboarding").is_some(),
    }
}

fn should_exit_on_onboarding_close(onboarding_complete: bool) -> bool {
    !onboarding_complete
}

fn cache_window_bootstrap_state(
    app: &AppHandle,
    active_profile_path: Option<&str>,
    onboarding_complete: bool,
) {
    if let Ok(mut snapshot) = app.state::<WindowRoutingState>().snapshot.lock() {
        snapshot.onboarding_complete = onboarding_complete;
        snapshot.active_profile_path = active_profile_path.map(str::to_string);
    }
}

fn cache_window_route_state(
    app: &AppHandle,
    route: WindowRoute,
    active_profile_path: Option<&str>,
    onboarding_complete: bool,
) {
    if let Ok(mut snapshot) = app.state::<WindowRoutingState>().snapshot.lock() {
        snapshot.route = Some(route);
        snapshot.onboarding_complete = onboarding_complete;
        snapshot.active_profile_path = active_profile_path.map(str::to_string);
    }
}

fn cached_window_snapshot(app: &AppHandle) -> WindowRoutingSnapshot {
    app.state::<WindowRoutingState>()
        .snapshot
        .lock()
        .ok()
        .map(|snapshot| snapshot.clone())
        .unwrap_or_default()
}

fn active_profile_log_root() -> &'static Mutex<Option<PathBuf>> {
    ACTIVE_PROFILE_LOG_ROOT.get_or_init(|| Mutex::new(None))
}

fn update_active_profile_log_root(profile_path: Option<&str>) {
    if let Ok(mut current) = active_profile_log_root().lock() {
        *current = profile_path.map(PathBuf::from);
    }
}

fn default_app_log_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Ok(local_app_data) = env::var("LOCALAPPDATA") {
            return PathBuf::from(local_app_data)
                .join("TapChat Desktop")
                .join("logs");
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = env::var("HOME") {
            return PathBuf::from(home)
                .join("Library")
                .join("Logs")
                .join("TapChat Desktop");
        }
    }
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        if let Ok(xdg_state_home) = env::var("XDG_STATE_HOME") {
            return PathBuf::from(xdg_state_home)
                .join("tapchat-desktop")
                .join("logs");
        }
        if let Ok(home) = env::var("HOME") {
            return PathBuf::from(home)
                .join(".local")
                .join("state")
                .join("tapchat-desktop")
                .join("logs");
        }
    }
    env::temp_dir().join("tapchat-desktop").join("logs")
}

fn register_app_log_dir(app: Option<&AppHandle>) -> PathBuf {
    let path = app
        .and_then(|handle| handle.path().app_log_dir().ok())
        .unwrap_or_else(default_app_log_dir);
    let _ = fs::create_dir_all(&path);
    let _ = APP_LOG_DIR.set(path.clone());
    path
}

fn resolve_log_path(profile_path: Option<&str>) -> PathBuf {
    if let Some(profile_path) = profile_path {
        return PathBuf::from(profile_path).join("logs").join("desktop.log");
    }
    if let Ok(current) = active_profile_log_root().lock() {
        if let Some(profile_root) = current.as_ref() {
            return profile_root.join("logs").join("desktop.log");
        }
    }
    APP_LOG_DIR
        .get()
        .cloned()
        .unwrap_or_else(default_app_log_dir)
        .join("desktop.log")
}

fn append_log(profile_path: Option<&str>, level: &str, scope: &str, message: impl AsRef<str>) {
    let path = resolve_log_path(profile_path);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(
            file,
            "[{timestamp}] [{level}] [{scope}] {}",
            message.as_ref().replace('\n', " | ")
        );
    }
}

fn install_panic_hook() {
    panic::set_hook(Box::new(|panic_info| {
        let payload = panic_info
            .payload()
            .downcast_ref::<&str>()
            .map(|value| (*value).to_string())
            .or_else(|| panic_info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown panic payload".into());
        let location = panic_info
            .location()
            .map(|location| {
                format!(
                    "{}:{}:{}",
                    location.file(),
                    location.line(),
                    location.column()
                )
            })
            .unwrap_or_else(|| "unknown location".into());
        let backtrace = std::backtrace::Backtrace::force_capture();
        let message = format!(
            "thread={} payload={} location={} backtrace={backtrace}",
            std::thread::current().name().unwrap_or("unnamed"),
            payload,
            location
        );
        // Always write to the app-level log.
        append_log(None, "ERROR", "panic", &message);
        // Also write to the active profile log so crash details appear in the
        // same file that the frontend reads for diagnostics.
        if let Ok(current) = active_profile_log_root().lock() {
            if let Some(profile_root) = current.as_ref() {
                append_log(
                    Some(profile_root.to_string_lossy().as_ref()),
                    "ERROR",
                    "panic",
                    &message,
                );
            }
        }
    }));
}

struct OnboardingHandoffGuard;

impl OnboardingHandoffGuard {
    fn try_acquire() -> Option<Self> {
        ONBOARDING_HANDOFF_IN_FLIGHT
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .ok()?;
        Some(Self)
    }
}

impl Drop for OnboardingHandoffGuard {
    fn drop(&mut self) {
        ONBOARDING_HANDOFF_IN_FLIGHT.store(false, Ordering::SeqCst);
    }
}

fn log_command_error(command: &str, profile_path: Option<&str>, error: &str) {
    append_log(
        profile_path,
        "ERROR",
        "command",
        format!("{command} failed: {error}"),
    );
}

fn into_string_error(error: anyhow::Error) -> String {
    let rendered = error.to_string();
    append_log(None, "ERROR", "command", &rendered);
    rendered
}

fn into_string_error_for(
    command: &str,
    profile_path: Option<&str>,
    error: anyhow::Error,
) -> String {
    let rendered = error.to_string();
    log_command_error(command, profile_path, &rendered);
    rendered
}

fn log_realtime_transition(
    profile_path: &str,
    status: &Arc<Mutex<SessionStatus>>,
    device_id: Option<&str>,
    connected: bool,
    needs_reconnect: bool,
    last_known_seq: Option<u64>,
    reason: &str,
) {
    if let Ok(mut current) = status.lock() {
        let changed = current.connected != connected
            || current.needs_reconnect != needs_reconnect
            || last_known_seq.is_some_and(|seq| seq != current.last_known_seq)
            || device_id.map(str::to_string) != current.device_id;
        current.connected = connected;
        current.needs_reconnect = needs_reconnect;
        if let Some(seq) = last_known_seq {
            current.last_known_seq = seq;
        }
        current.device_id = device_id.map(str::to_string);
        if changed {
            append_log(
                Some(profile_path),
                "INFO",
                "realtime",
                format!(
                    "session status reason={reason} device_id={:?} connected={} needs_reconnect={} last_known_seq={}",
                    current.device_id,
                    current.connected,
                    current.needs_reconnect,
                    current.last_known_seq
                ),
            );
        }
    }
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
            tasks
                .values()
                .filter(|task| profile_path.is_none_or(|value| value == task.profile_path))
                .count()
        })
        .unwrap_or_default()
}

fn last_background_error(manager: &BackgroundDownloadManager) -> Option<String> {
    manager
        .last_error
        .lock()
        .ok()
        .and_then(|value| value.clone())
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
    append_log(
        Some(profile_path),
        "INFO",
        "realtime",
        "stop session requested",
    );
    let _ = bump_realtime_generation(manager, profile_path)?;
    let handle = {
        let mut sessions = manager
            .sessions
            .lock()
            .map_err(|_| "lock poisoned".to_string())?;
        sessions.remove(profile_path)
    };
    let Some(handle) = handle else {
        append_log(
            Some(profile_path),
            "INFO",
            "realtime",
            "stop session skipped because no active session existed",
        );
        return Ok(false);
    };
    let _ = handle.stop.send(());
    handle.task.await.map_err(|error| {
        let rendered = error.to_string();
        log_command_error("stop_realtime_session", Some(profile_path), &rendered);
        rendered
    })?;
    append_log(
        Some(profile_path),
        "INFO",
        "realtime",
        "stop session completed",
    );
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
    append_log(
        Some(&profile_path),
        "INFO",
        "realtime",
        "run_with_paused_realtime begin",
    );
    let should_resume = stop_realtime_session(manager, &profile_path).await?;
    let result = task.await;
    let resume_result = if should_resume {
        start_realtime_session(profile_path.clone(), app, manager).map(|_| ())
    } else {
        Ok(())
    };
    if let Err(error) = result.as_ref() {
        log_command_error("run_with_paused_realtime.task", Some(&profile_path), error);
    }
    if let Err(error) = resume_result.as_ref() {
        log_command_error(
            "run_with_paused_realtime.resume",
            Some(&profile_path),
            error,
        );
    }
    match (result, resume_result) {
        (Ok(value), Ok(())) => {
            append_log(
                Some(&profile_path),
                "INFO",
                "realtime",
                "run_with_paused_realtime completed",
            );
            Ok(value)
        }
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
    let next = generations
        .get(profile_path)
        .copied()
        .unwrap_or_default()
        .saturating_add(1);
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

fn window_route_for_onboarding_complete(onboarding_complete: bool) -> WindowRoute {
    if onboarding_complete {
        WindowRoute::Main
    } else {
        WindowRoute::Onboarding
    }
}

fn active_profile_path(bootstrap: &desktop_app::AppBootstrapView) -> Option<String> {
    bootstrap
        .active_profile
        .as_ref()
        .map(|profile| profile.path.to_string_lossy().to_string())
}

fn log_window_action(profile_path: Option<&str>, window_label: &str, action: &str) {
    append_log(
        profile_path,
        "INFO",
        "window",
        format!("{window_label} {action}"),
    );
}

fn show_main_window(app: &AppHandle, profile_path: Option<&str>) {
    if let Some(window) = app.get_webview_window("main") {
        log_window_action(profile_path, "main", "show");
        let _ = window.show();
        log_window_action(profile_path, "main", "focus");
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

fn show_onboarding_window_internal(
    app: &AppHandle,
    profile_path: Option<&str>,
) -> tauri::Result<()> {
    ensure_onboarding_window(app)?;
    if let Some(onboarding) = app.get_webview_window("onboarding") {
        log_window_action(profile_path, "onboarding", "show");
        let _ = onboarding.show();
        log_window_action(profile_path, "onboarding", "focus");
        let _ = onboarding.set_focus();
    }
    Ok(())
}

fn hide_main_window(app: &AppHandle, profile_path: Option<&str>) {
    if let Some(main) = app.get_webview_window("main") {
        log_window_action(profile_path, "main", "hide");
        let _ = main.hide();
    }
}

fn close_onboarding_window(app: &AppHandle, profile_path: Option<&str>) {
    if let Some(onboarding) = app.get_webview_window("onboarding") {
        log_window_action(profile_path, "onboarding", "close");
        let _ = onboarding.close();
    }
}

fn close_onboarding_window_deferred(app: AppHandle, profile_path: Option<String>) {
    if app
        .state::<WindowRoutingState>()
        .deferred_onboarding_close_in_flight
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        append_log(
            profile_path.as_deref(),
            "INFO",
            "window",
            "close_deferred skipped because another deferred close is in flight",
        );
        return;
    }
    append_log(
        profile_path.as_deref(),
        "INFO",
        "window",
        "close_deferred scheduled",
    );
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        close_onboarding_window(&app, profile_path.as_deref());
        append_log(profile_path.as_deref(), "INFO", "window", "close_deferred completed");
        app.state::<WindowRoutingState>()
            .deferred_onboarding_close_in_flight
            .store(false, Ordering::SeqCst);
    });
}

fn apply_window_route(
    app: &AppHandle,
    route: WindowRoute,
    active_profile_path: Option<&str>,
    onboarding_complete: bool,
    close_onboarding_immediately: bool,
) -> tauri::Result<String> {
    let cached = cached_window_snapshot(app);
    append_log(
        active_profile_path,
        "INFO",
        "window",
        format!(
            "route_apply_enter target={route:?} current={:?} onboarding_complete={onboarding_complete}",
            cached.route
        ),
    );
    if route_is_unchanged(cached.route, route) && route_target_available(app, route) {
        append_log(
            active_profile_path,
            "INFO",
            "window",
            format!("route_apply_skip unchanged route={route:?}"),
        );
        cache_window_route_state(app, route, active_profile_path, onboarding_complete);
        return Ok(String::from(window_route_label(route)));
    }

    match route {
        WindowRoute::Main => {
            if close_onboarding_immediately {
                close_onboarding_window(app, active_profile_path);
            } else {
                append_log(
                    active_profile_path,
                    "INFO",
                    "window",
                    "route_apply_main deferred onboarding close",
                );
            }
            show_main_window(app, active_profile_path);
            if let Some(profile_path) = active_profile_path {
                update_tray_tooltip(app, Some(profile_path));
            }
            cache_window_route_state(app, route, active_profile_path, onboarding_complete);
            append_log(
                active_profile_path,
                "INFO",
                "window",
                "route_apply_exit route=Main",
            );
            Ok(String::from(window_route_label(route)))
        }
        WindowRoute::Onboarding => {
            hide_main_window(app, active_profile_path);
            show_onboarding_window_internal(app, active_profile_path)?;
            update_tray_tooltip(app, active_profile_path);
            cache_window_route_state(app, route, active_profile_path, onboarding_complete);
            append_log(
                active_profile_path,
                "INFO",
                "window",
                "route_apply_exit route=Onboarding",
            );
            Ok(String::from(window_route_label(route)))
        }
    }
}

fn sync_window_visibility_from_bootstrap(app: &AppHandle) -> tauri::Result<String> {
    let bootstrap = desktop_app::app_bootstrap()
        .map_err(|error| tauri::Error::Anyhow(anyhow::anyhow!(error.to_string())))?;
    let onboarding_complete = bootstrap.onboarding.step == "complete";
    let route = window_route_for_onboarding_complete(onboarding_complete);
    let active_profile_path = active_profile_path(&bootstrap);
    update_active_profile_log_root(active_profile_path.as_deref());
    cache_window_bootstrap_state(app, active_profile_path.as_deref(), onboarding_complete);
    append_log(
        active_profile_path.as_deref(),
        "INFO",
        "window",
        format!("sync_window_visibility onboarding_complete={onboarding_complete}"),
    );
    apply_window_route(
        app,
        route,
        active_profile_path.as_deref(),
        onboarding_complete,
        true,
    )
}

fn notify_attachment_event(app: &AppHandle, title: &str, body: &str) {
    let _ = app.notification().builder().title(title).body(body).show();
}

fn start_realtime_session(
    profile_path: String,
    app: AppHandle,
    manager: &RealtimeManager,
) -> Result<bool, String> {
    update_active_profile_log_root(Some(&profile_path));
    append_log(
        Some(&profile_path),
        "INFO",
        "realtime",
        "start session requested",
    );
    let generation = bump_realtime_generation(manager, &profile_path)?;
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel();
    let status = Arc::new(Mutex::new(SessionStatus::default()));
    let status_for_task = Arc::clone(&status);
    let profile_for_task = profile_path.clone();
    let app_for_task = app.clone();

    let task = tauri::async_runtime::spawn(async move {
        let manager_state = app_for_task.state::<RealtimeManager>();
        let should_emit_dirty =
            || realtime_generation_matches(&manager_state, &profile_for_task, generation);
        append_log(
            Some(&profile_for_task),
            "INFO",
            "realtime",
            format!("spawned session task generation={generation}"),
        );
        let mut profile = match Profile::open(&profile_for_task) {
            Ok(profile) => {
                append_log(
                    Some(&profile_for_task),
                    "INFO",
                    "realtime",
                    "stage=profile_open ok",
                );
                profile
            }
            Err(error) => {
                log_realtime_transition(
                    &profile_for_task,
                    &status_for_task,
                    None,
                    false,
                    true,
                    Some(0),
                    "profile_open_failed",
                );
                log_command_error(
                    "realtime.profile_open",
                    Some(&profile_for_task),
                    &error.to_string(),
                );
                if should_emit_dirty() {
                    let _ = app_for_task.emit("tapchat://direct-shell-dirty", &profile_for_task);
                }
                return;
            }
        };
        let mut driver = match load_realtime_driver(&profile) {
            Ok(driver) => {
                append_log(
                    Some(&profile_for_task),
                    "INFO",
                    "realtime",
                    "stage=driver_load ok",
                );
                driver
            }
            Err(error) => {
                log_realtime_transition(
                    &profile_for_task,
                    &status_for_task,
                    None,
                    false,
                    true,
                    Some(0),
                    "driver_load_failed",
                );
                log_command_error(
                    "realtime.driver_load",
                    Some(&profile_for_task),
                    &error.to_string(),
                );
                if should_emit_dirty() {
                    let _ = app_for_task.emit("tapchat://direct-shell-dirty", &profile_for_task);
                }
                return;
            }
        };
        let Some(device_id) = driver
            .local_identity()
            .map(|identity| identity.device_identity.device_id.clone())
        else {
            log_realtime_transition(
                &profile_for_task,
                &status_for_task,
                None,
                false,
                true,
                Some(0),
                "local_device_missing",
            );
            log_command_error(
                "realtime.local_device",
                Some(&profile_for_task),
                "local identity device_id is missing",
            );
            if should_emit_dirty() {
                let _ = app_for_task.emit("tapchat://direct-shell-dirty", &profile_for_task);
            }
            return;
        };
        append_log(
            Some(&profile_for_task),
            "INFO",
            "realtime",
            format!("stage=local_device_resolved device_id={device_id}"),
        );
        let mut reconnect_attempt = 0u32;
        let mut initialized = false;
        let mut emit_shutdown_dirty = true;
        loop {
            if stop_rx.try_recv().is_ok()
                || !realtime_generation_matches(&manager_state, &profile_for_task, generation)
            {
                emit_shutdown_dirty = false;
                break;
            }
            let mut emit_dirty = false;
            let step_result = if !initialized {
                initialized = true;
                append_log(
                    Some(&profile_for_task),
                    "INFO",
                    "realtime",
                    "stage=foreground_sync begin",
                );
                driver
                    .inject_event_until_idle(CoreEvent::AppForegrounded)
                    .await
                    .map(|_| Vec::new())
            } else {
                append_log(
                    Some(&profile_for_task),
                    "INFO",
                    "realtime",
                    format!("stage=pump begin reconnect_attempt={reconnect_attempt}"),
                );
                driver.pump_until_idle(Duration::from_secs(45)).await
            };

            match step_result {
                Ok(outputs) => {
                    reconnect_attempt = 0;
                    if !outputs.is_empty() {
                        if realtime_generation_matches(
                            &manager_state,
                            &profile_for_task,
                            generation,
                        ) {
                            if let Err(error) = persist_realtime_driver(&mut profile, &driver) {
                                log_command_error(
                                    "realtime.persist",
                                    Some(&profile_for_task),
                                    &error.to_string(),
                                );
                            } else {
                                append_log(
                                    Some(&profile_for_task),
                                    "INFO",
                                    "realtime",
                                    "stage=persist ok",
                                );
                            }
                            emit_dirty = true;
                            if outputs_changed_message_requests(&outputs) && should_emit_dirty() {
                                let _ = app_for_task
                                    .emit("tapchat://message-requests-dirty", &profile_for_task);
                            }
                        } else {
                            break;
                        }
                    }
                    if let Some(snapshot) = driver.realtime_session_snapshot(&device_id) {
                        let connected = !snapshot.needs_reconnect;
                        let previous = status_for_task.lock().ok().map(|current| current.clone());
                        log_realtime_transition(
                            &profile_for_task,
                            &status_for_task,
                            Some(&device_id),
                            connected,
                            snapshot.needs_reconnect,
                            Some(snapshot.last_known_seq),
                            "snapshot",
                        );
                        let changed = previous.is_none_or(|current| {
                            current.connected != connected
                                || current.needs_reconnect != snapshot.needs_reconnect
                                || current.last_known_seq != snapshot.last_known_seq
                        });
                        if changed {
                            emit_dirty = true;
                        }
                    }
                    if emit_dirty && should_emit_dirty() {
                        let _ =
                            app_for_task.emit("tapchat://direct-shell-dirty", &profile_for_task);
                        update_tray_tooltip(&app_for_task, Some(&profile_for_task));
                        append_log(
                            Some(&profile_for_task),
                            "INFO",
                            "realtime",
                            "emitted direct-shell-dirty",
                        );
                    }
                }
                Err(error) => {
                    reconnect_attempt = reconnect_attempt.saturating_add(1);
                    log_command_error(
                        "realtime.step",
                        Some(&profile_for_task),
                        &format!("attempt={reconnect_attempt} error={error}"),
                    );
                    log_realtime_transition(
                        &profile_for_task,
                        &status_for_task,
                        Some(&device_id),
                        false,
                        true,
                        None,
                        "step_error",
                    );
                    if should_emit_dirty() {
                        let _ =
                            app_for_task.emit("tapchat://direct-shell-dirty", &profile_for_task);
                    }
                    let delay_seconds = [1u64, 2, 4, 8, 15]
                        [usize::min(reconnect_attempt.saturating_sub(1) as usize, 4)];
                    tokio::select! {
                        _ = &mut stop_rx => {
                            emit_shutdown_dirty = false;
                            break;
                        },
                        _ = tokio::time::sleep(Duration::from_secs(delay_seconds)) => {}
                    }
                }
            }
        }

        log_realtime_transition(
            &profile_for_task,
            &status_for_task,
            Some(&device_id),
            false,
            false,
            None,
            "task_shutdown",
        );
        if emit_shutdown_dirty && should_emit_dirty() {
            let _ = app_for_task.emit("tapchat://direct-shell-dirty", &profile_for_task);
        }
        append_log(
            Some(&profile_for_task),
            "INFO",
            "realtime",
            "session task exited",
        );
    });

    let mut sessions = manager
        .sessions
        .lock()
        .map_err(|_| "lock poisoned".to_string())?;
    let previous = sessions.insert(
        profile_path.clone(),
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
    append_log(
        Some(&profile_path),
        "INFO",
        "realtime",
        format!("session registered generation={generation}"),
    );
    Ok(true)
}

fn spawn_resume_pending_downloads(app: AppHandle, profile_path: String) {
    tauri::async_runtime::spawn(async move {
        let manager = app.state::<RealtimeManager>();
        let result = run_with_paused_realtime(app.clone(), &manager, profile_path.clone(), async {
            desktop_app::sync_foreground(&profile_path)
                .await
                .map_err(into_string_error)
        })
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
fn app_bootstrap(app: AppHandle) -> Result<desktop_app::AppBootstrapView, String> {
    let bootstrap = desktop_app::app_bootstrap().map_err(into_string_error)?;
    let active_profile_path = bootstrap
        .active_profile
        .as_ref()
        .map(|profile| profile.path.to_string_lossy().to_string());
    let onboarding_complete = bootstrap.onboarding.step == "complete";
    update_active_profile_log_root(active_profile_path.as_deref());
    cache_window_bootstrap_state(&app, active_profile_path.as_deref(), onboarding_complete);
    append_log(
        active_profile_path.as_deref(),
        "INFO",
        "command",
        "app_bootstrap completed",
    );
    Ok(bootstrap)
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
    let bootstrap = desktop_app::profile_activate(&profile_id_or_path)
        .map_err(|error| into_string_error_for("profile_activate", None, error))?;
    let active_profile_path = bootstrap
        .active_profile
        .as_ref()
        .map(|profile| profile.path.to_string_lossy().to_string());
    update_active_profile_log_root(active_profile_path.as_deref());
    append_log(
        active_profile_path.as_deref(),
        "INFO",
        "command",
        format!("profile_activate requested={profile_id_or_path}"),
    );
    let onboarding_complete = bootstrap.onboarding.step == "complete";
    let route = window_route_for_onboarding_complete(onboarding_complete);
    cache_window_bootstrap_state(&app, active_profile_path.as_deref(), onboarding_complete);
    let _ = apply_window_route(
        &app,
        route,
        active_profile_path.as_deref(),
        onboarding_complete,
        true,
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
    let bootstrap = desktop_app::app_bootstrap().map_err(|error| {
        into_string_error_for("show_onboarding_window.app_bootstrap", None, error)
    })?;
    let active_profile_path = active_profile_path(&bootstrap);
    let onboarding_complete = bootstrap.onboarding.step == "complete";
    cache_window_bootstrap_state(&app, active_profile_path.as_deref(), onboarding_complete);
    apply_window_route(
        &app,
        WindowRoute::Onboarding,
        active_profile_path.as_deref(),
        onboarding_complete,
        true,
    )
    .map_err(|error| error.to_string())
}

#[tauri::command]
fn complete_onboarding_handoff(
    app: AppHandle,
    profile_path: Option<String>,
) -> Result<desktop_app::AppBootstrapView, String> {
    let _handoff_guard = match OnboardingHandoffGuard::try_acquire() {
        Some(guard) => guard,
        None => {
            append_log(
                profile_path.as_deref(),
                "INFO",
                "command",
                "complete_onboarding_handoff coalesced while another handoff is in progress",
            );
            return desktop_app::app_bootstrap().map_err(|error| {
                into_string_error_for(
                    "complete_onboarding_handoff.coalesced_app_bootstrap",
                    profile_path.as_deref(),
                    error,
                )
            });
        }
    };
    append_log(
        profile_path.as_deref(),
        "INFO",
        "command",
        "complete_onboarding_handoff begin",
    );
    if let Some(profile_path) = profile_path.as_deref() {
        let _ = desktop_app::profile_activate(profile_path).map_err(|error| {
            into_string_error_for(
                "complete_onboarding_handoff.profile_activate",
                Some(profile_path),
                error,
            )
        })?;
    }
    let bootstrap = desktop_app::app_bootstrap().map_err(|error| {
        into_string_error_for(
            "complete_onboarding_handoff.app_bootstrap",
            profile_path.as_deref(),
            error,
        )
    })?;
    if bootstrap.onboarding.step != "complete" {
        log_command_error(
            "complete_onboarding_handoff",
            profile_path.as_deref(),
            "onboarding is not complete",
        );
        return Err(String::from("onboarding is not complete"));
    }
    if let Some(active_profile) = bootstrap.active_profile.as_ref() {
        let active_profile_path = active_profile.path.to_string_lossy().to_string();
        let _ = desktop_app::profile_activate(&active_profile_path).map_err(|error| {
            into_string_error_for(
                "complete_onboarding_handoff.active_profile_activate",
                Some(&active_profile_path),
                error,
            )
        })?;
    }
    let bootstrap = desktop_app::app_bootstrap().map_err(|error| {
        into_string_error_for(
            "complete_onboarding_handoff.final_bootstrap",
            profile_path.as_deref(),
            error,
        )
    })?;
    let active_profile_path = active_profile_path(&bootstrap);
    update_active_profile_log_root(active_profile_path.as_deref());
    let onboarding_complete = bootstrap.onboarding.step == "complete";
    cache_window_bootstrap_state(&app, active_profile_path.as_deref(), onboarding_complete);
    apply_window_route(
        &app,
        WindowRoute::Main,
        active_profile_path.as_deref(),
        onboarding_complete,
        false,
    )
    .map_err(|error| error.to_string())?;
    let _ = app.emit("tapchat://bootstrap-dirty", &bootstrap);
    close_onboarding_window_deferred(app.clone(), active_profile_path.clone());
    append_log(
        active_profile_path.as_deref(),
        "INFO",
        "command",
        "complete_onboarding_handoff completed",
    );
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
    append_log(
        Some(&profile_path),
        "INFO",
        "command",
        "sync_foreground begin",
    );
    let profile_for_log = profile_path.clone();
    run_with_paused_realtime(app, &manager, profile_path.clone(), async move {
        desktop_app::sync_foreground(profile_path)
            .await
            .map_err(|error| {
                into_string_error_for("sync_foreground", Some(&profile_for_log), error)
            })
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
    update_active_profile_log_root(Some(&profile_path));
    append_log(
        Some(&profile_path),
        "INFO",
        "command",
        format!(
            "direct_shell refresh selected_conversation_id={:?} selected_contact_user_id={:?}",
            selected_conversation_id, selected_contact_user_id
        ),
    );
    let mut shell = desktop_app::direct_shell(
        &profile_path,
        selected_conversation_id.as_deref(),
        selected_contact_user_id.as_deref(),
    )
    .map_err(|error| into_string_error_for("direct_shell", Some(&profile_path), error))?;
    let snapshot = session_status_for(&manager, &profile_path);
    shell.realtime = desktop_app::map_realtime_snapshot(
        snapshot
            .as_ref()
            .and_then(|value| value.device_id.clone())
            .or(shell.sync.device_id.clone()),
        None,
        snapshot
            .as_ref()
            .map(|value| value.connected)
            .unwrap_or(false),
    );
    if let Some(status) = snapshot {
        shell.realtime.last_known_seq = status.last_known_seq;
        shell.realtime.needs_reconnect = status.needs_reconnect;
    }
    append_log(
        Some(&profile_path),
        "INFO",
        "command",
        format!(
            "direct_shell completed connected={} needs_reconnect={} last_known_seq={}",
            shell.realtime.connected, shell.realtime.needs_reconnect, shell.realtime.last_known_seq
        ),
    );
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
    append_log(
        Some(&profile_path),
        "INFO",
        "command",
        "sync_realtime_close begin",
    );
    stop_realtime_session(&manager, &profile_path).await
}

#[tauri::command]
async fn sync_realtime_connect(
    profile_path: String,
    app: AppHandle,
    manager: State<'_, RealtimeManager>,
) -> Result<bool, String> {
    append_log(
        Some(&profile_path),
        "INFO",
        "command",
        "sync_realtime_connect begin",
    );
    let _ = stop_realtime_session(&manager, &profile_path).await?;
    start_realtime_session(profile_path, app, &manager)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::Ordering;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        active_profile_log_root, bump_realtime_generation, default_app_log_dir,
        realtime_generation_matches, resolve_log_path, route_is_unchanged,
        should_exit_on_onboarding_close, window_route_for_onboarding_complete,
        window_route_label, OnboardingHandoffGuard, RealtimeManager, WindowRoute,
        ONBOARDING_HANDOFF_IN_FLIGHT,
    };

    fn unique_temp_profile(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("tapchat-{name}-{stamp}"))
    }

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
        assert!(!realtime_generation_matches(
            &manager,
            "profile-a",
            other + 1
        ));
    }

    #[test]
    fn resolve_log_path_prefers_explicit_profile_root() {
        let profile_root = unique_temp_profile("profile-log");
        let resolved = resolve_log_path(Some(profile_root.to_string_lossy().as_ref()));
        assert_eq!(resolved, profile_root.join("logs").join("desktop.log"));
    }

    #[test]
    fn resolve_log_path_uses_active_profile_root_when_available() {
        let profile_root = unique_temp_profile("active-profile-log");
        {
            let mut current = active_profile_log_root().lock().unwrap();
            *current = Some(profile_root.clone());
        }
        let resolved = resolve_log_path(None);
        assert_eq!(resolved, profile_root.join("logs").join("desktop.log"));
    }

    #[test]
    fn default_app_log_dir_has_logs_suffix() {
        assert!(default_app_log_dir().ends_with("logs"));
    }

    #[test]
    fn window_route_maps_onboarding_state() {
        assert_eq!(
            window_route_for_onboarding_complete(false),
            WindowRoute::Onboarding
        );
        assert_eq!(
            window_route_for_onboarding_complete(true),
            WindowRoute::Main
        );
    }

    #[test]
    fn route_helpers_are_deterministic() {
        assert!(route_is_unchanged(Some(WindowRoute::Main), WindowRoute::Main));
        assert!(!route_is_unchanged(
            Some(WindowRoute::Onboarding),
            WindowRoute::Main
        ));
        assert!(!route_is_unchanged(None, WindowRoute::Main));
        assert_eq!(window_route_label(WindowRoute::Main), "main");
        assert_eq!(window_route_label(WindowRoute::Onboarding), "onboarding");
    }

    #[test]
    fn onboarding_close_policy_matches_bootstrap_state() {
        assert!(should_exit_on_onboarding_close(false));
        assert!(!should_exit_on_onboarding_close(true));
    }

    #[test]
    fn onboarding_handoff_guard_is_exclusive() {
        ONBOARDING_HANDOFF_IN_FLIGHT.store(false, Ordering::SeqCst);
        let first = OnboardingHandoffGuard::try_acquire();
        assert!(first.is_some());
        assert!(OnboardingHandoffGuard::try_acquire().is_none());
        drop(first);
        let second = OnboardingHandoffGuard::try_acquire();
        assert!(second.is_some());
        drop(second);
        ONBOARDING_HANDOFF_IN_FLIGHT.store(false, Ordering::SeqCst);
    }
}

pub fn run() {
    tauri::Builder::default()
        .manage(RealtimeManager::default())
        .manage(BackgroundDownloadManager::default())
        .manage(CloudflareWizardManager::default())
        .manage(LifecycleManager::default())
        .manage(WindowRoutingState::default())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            register_app_log_dir(Some(app.handle()));
            install_panic_hook();
            append_log(None, "INFO", "startup", "desktop host setup begin");
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
                        show_main_window(app, None);
                    }
                    "quit" => {
                        let lifecycle = app.state::<LifecycleManager>();
                        lifecycle.quitting.store(true, Ordering::SeqCst);
                        stop_all_realtime_sessions(&app.state::<RealtimeManager>());
                        if let Ok(mut active) =
                            app.state::<BackgroundDownloadManager>().active.lock()
                        {
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
                        update_active_profile_log_root(Some(&profile_path));
                        if desktop_app::app_background_mode(&profile_path).unwrap_or(true)
                            && desktop_app::attachment_transfers(&profile_path, None)
                                .map(|transfers| {
                                    transfers
                                        .iter()
                                        .any(|transfer| transfer.task_kind == "download")
                                })
                                .unwrap_or(false)
                        {
                            spawn_resume_pending_downloads(
                                app.handle().clone(),
                                profile_path.clone(),
                            );
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
                let snapshot = cached_window_snapshot(&window.app_handle());
                let active_profile_path = snapshot.active_profile_path;
                let onboarding_complete = snapshot.onboarding_complete;
                append_log(
                    active_profile_path.as_deref(),
                    "INFO",
                    "window",
                    format!(
                        "close_requested label={} onboarding_complete={} route={:?}",
                        window.label(),
                        onboarding_complete,
                        snapshot.route
                    ),
                );
                if window.label() == "main" {
                    api.prevent_close();
                    log_window_action(active_profile_path.as_deref(), "main", "hide");
                    let _ = window.hide();
                } else if window.label() == "onboarding" {
                    if should_exit_on_onboarding_close(onboarding_complete) {
                        append_log(
                            active_profile_path.as_deref(),
                            "INFO",
                            "window",
                            "onboarding close requested while incomplete; exiting app",
                        );
                        window.app_handle().exit(0);
                    } else {
                        append_log(
                            active_profile_path.as_deref(),
                            "INFO",
                            "window",
                            "onboarding close allowed because onboarding is complete",
                        );
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

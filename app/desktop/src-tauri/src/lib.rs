use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tauri::menu::{MenuBuilder, MenuItemBuilder};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager, State, WindowEvent};
use tauri_plugin_notification::NotificationExt;

use tapchat_core::cli::runtime::CloudflareDeployOverrides;
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
}

#[derive(Default)]
struct RealtimeManager {
    sessions: Mutex<HashMap<String, SessionHandle>>,
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

fn into_string_error(error: anyhow::Error) -> String {
    error.to_string()
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

fn spawn_resume_pending_downloads(app: AppHandle, profile_path: String) {
    tauri::async_runtime::spawn(async move {
        let result = desktop_app::sync_foreground(&profile_path).await;
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
async fn identity_create(
    profile_path: String,
    device_name: String,
) -> Result<desktop_app::IdentitySummaryView, String> {
    desktop_app::identity_create(profile_path, &device_name)
        .await
        .map_err(into_string_error)
}

#[tauri::command]
async fn identity_recover(
    profile_path: String,
    device_name: String,
    mnemonic: String,
) -> Result<desktop_app::IdentitySummaryView, String> {
    desktop_app::identity_recover(profile_path, &device_name, mnemonic)
        .await
        .map_err(into_string_error)
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
fn contact_list(profile_path: String) -> Result<Vec<desktop_app::ContactListItem>, String> {
    desktop_app::contact_list(profile_path).map_err(into_string_error)
}

#[tauri::command]
async fn contact_import_identity(
    profile_path: String,
    bundle_json_or_path: String,
) -> Result<desktop_app::ContactDetailView, String> {
    desktop_app::contact_import_identity(profile_path, &bundle_json_or_path)
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
) -> Result<desktop_app::MessageRequestActionView, String> {
    desktop_app::message_request_accept(profile_path, &request_id)
        .await
        .map_err(into_string_error)
}

#[tauri::command]
async fn message_request_reject(
    profile_path: String,
    request_id: String,
) -> Result<desktop_app::MessageRequestActionView, String> {
    desktop_app::message_request_reject(profile_path, &request_id)
        .await
        .map_err(into_string_error)
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
) -> Result<desktop_app::AllowlistView, String> {
    desktop_app::allowlist_add(profile_path, &user_id)
        .await
        .map_err(into_string_error)
}

#[tauri::command]
async fn allowlist_remove(
    profile_path: String,
    user_id: String,
) -> Result<desktop_app::AllowlistView, String> {
    desktop_app::allowlist_remove(profile_path, &user_id)
        .await
        .map_err(into_string_error)
}

#[tauri::command]
async fn contact_refresh(
    profile_path: String,
    user_id: String,
) -> Result<desktop_app::ContactDetailView, String> {
    desktop_app::contact_refresh(profile_path, &user_id)
        .await
        .map_err(into_string_error)
}

#[tauri::command]
async fn conversation_create_direct(
    profile_path: String,
    peer_user_id: String,
) -> Result<desktop_app::ConversationDetailView, String> {
    desktop_app::conversation_create_direct(profile_path, &peer_user_id)
        .await
        .map_err(into_string_error)
}

#[tauri::command]
async fn conversation_reconcile(
    profile_path: String,
    conversation_id: String,
) -> Result<desktop_app::ConversationDetailView, String> {
    desktop_app::conversation_reconcile(profile_path, &conversation_id)
        .await
        .map_err(into_string_error)
}

#[tauri::command]
async fn conversation_rebuild(
    profile_path: String,
    conversation_id: String,
) -> Result<desktop_app::ConversationDetailView, String> {
    desktop_app::conversation_rebuild(profile_path, &conversation_id)
        .await
        .map_err(into_string_error)
}

#[tauri::command]
async fn message_send_text(
    profile_path: String,
    conversation_id: String,
    text: String,
) -> Result<desktop_app::SendMessageResultView, String> {
    desktop_app::message_send_text(profile_path, &conversation_id, &text)
        .await
        .map_err(into_string_error)
}

#[tauri::command]
async fn message_send_attachment(
    profile_path: String,
    conversation_id: String,
    file_path: String,
) -> Result<desktop_app::SendAttachmentResultView, String> {
    desktop_app::message_send_attachment(profile_path, &conversation_id, file_path)
        .await
        .map_err(into_string_error)
}

#[tauri::command]
async fn message_send_attachments(
    profile_path: String,
    conversation_id: String,
    file_paths: Vec<String>,
) -> Result<desktop_app::BatchSendAttachmentResultView, String> {
    desktop_app::message_send_attachments(profile_path, &conversation_id, file_paths)
        .await
        .map_err(into_string_error)
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
async fn sync_once(profile_path: String) -> Result<desktop_app::SyncStatusView, String> {
    desktop_app::sync_once(profile_path)
        .await
        .map_err(into_string_error)
}

#[tauri::command]
async fn sync_foreground(profile_path: String) -> Result<desktop_app::SyncStatusView, String> {
    desktop_app::sync_foreground(profile_path)
        .await
        .map_err(into_string_error)
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
fn sync_realtime_close(
    profile_path: String,
    manager: State<'_, RealtimeManager>,
) -> Result<bool, String> {
    let mut sessions = manager.sessions.lock().map_err(|_| "lock poisoned".to_string())?;
    if let Some(handle) = sessions.remove(&profile_path) {
        let _ = handle.stop.send(());
        return Ok(true);
    }
    Ok(false)
}

#[tauri::command]
fn sync_realtime_connect(
    profile_path: String,
    app: AppHandle,
    manager: State<'_, RealtimeManager>,
) -> Result<bool, String> {
    {
        let mut sessions = manager.sessions.lock().map_err(|_| "lock poisoned".to_string())?;
        if let Some(handle) = sessions.remove(&profile_path) {
            let _ = handle.stop.send(());
        }
    }

    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel();
    let status = Arc::new(Mutex::new(SessionStatus::default()));
    let status_for_task = Arc::clone(&status);
    let profile_for_task = profile_path.clone();
    let app_for_task = app.clone();

    tauri::async_runtime::spawn(async move {
        let mut first_pass = true;
        loop {
            if stop_rx.try_recv().is_ok() {
                break;
            }

            let result = if first_pass {
                desktop_app::sync_foreground(&profile_for_task).await
            } else {
                desktop_app::sync_once(&profile_for_task).await
            };
            first_pass = false;

            match result {
                Ok(sync) => {
                    if let Ok(mut current) = status_for_task.lock() {
                        current.connected = true;
                        current.needs_reconnect = false;
                        current.device_id = sync.device_id.clone();
                        current.last_known_seq = sync
                            .checkpoint
                            .as_ref()
                            .map(|value| value.last_fetched_seq)
                            .unwrap_or_default();
                    }
                    let _ = app_for_task.emit("tapchat://direct-shell-dirty", &profile_for_task);
                    update_tray_tooltip(&app_for_task, Some(&profile_for_task));
                }
                Err(_) => {
                    if let Ok(mut current) = status_for_task.lock() {
                        current.connected = false;
                        current.needs_reconnect = true;
                    }
                }
            }

            tokio::select! {
                _ = &mut stop_rx => break,
                _ = tokio::time::sleep(Duration::from_secs(2)) => {}
            }
        }

        if let Ok(mut current) = status_for_task.lock() {
            current.connected = false;
        }
        let _ = app_for_task.emit("tapchat://direct-shell-dirty", &profile_for_task);
    });

    let mut sessions = manager.sessions.lock().map_err(|_| "lock poisoned".to_string())?;
    sessions.insert(
        profile_path,
        SessionHandle {
            status,
            stop: stop_tx,
        },
    );
    Ok(true)
}

pub fn run() {
    tauri::Builder::default()
        .manage(RealtimeManager::default())
        .manage(BackgroundDownloadManager::default())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            let show = MenuItemBuilder::with_id("show", "Show TapChat").build(app)?;
            let quit = MenuItemBuilder::with_id("quit", "Quit").build(app)?;
            let menu = MenuBuilder::new(app).items(&[&show, &quit]).build()?;
            let _tray = TrayIconBuilder::with_id("tapchat-tray")
                .tooltip("TapChat Desktop")
                .menu(&menu)
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "show" => show_main_window(app),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .build(app)?;

            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
            }

            if let Ok(bootstrap) = desktop_app::app_bootstrap() {
                if bootstrap.onboarding.step == "complete" {
                    if let Some(profile) = bootstrap.active_profile.as_ref() {
                        let profile_path = profile.path.to_string_lossy().to_string();
                        if desktop_app::app_background_mode(&profile_path).unwrap_or(true)
                            && desktop_app::attachment_transfers(&profile_path, None)
                                .map(|transfers| {
                                    transfers.iter().any(|transfer| transfer.task_kind == "download")
                                })
                                .unwrap_or(false)
                        {
                            spawn_resume_pending_downloads(app.handle().clone(), profile_path.clone());
                        }
                        update_tray_tooltip(app.handle(), Some(&profile_path));
                    }
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            app_bootstrap,
            profile_list,
            profile_activate,
            profile_create,
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
            contact_list,
            contact_import_identity,
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
        .expect("error while running tapchat desktop");
}

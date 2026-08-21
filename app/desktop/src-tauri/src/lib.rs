#![cfg_attr(all(feature = "test-support", not(feature = "gui")), allow(dead_code))]

mod commands;
mod errors;
mod lifecycle;
mod platform;
mod ports;
mod runtime_auth;
mod state;
mod storage_layout;

use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "gui")]
use tauri::menu::{Menu, MenuItem};
#[cfg(feature = "gui")]
use tauri::tray::TrayIconBuilder;
#[cfg(feature = "gui")]
use tauri::Manager;

pub use state::{AppState, SessionState};

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

/// Debug mode flag — when enabled, [TIMETEST] instrumentation is logged.
pub static DEBUG_MODE: AtomicBool = AtomicBool::new(false);

/// Log a timing-test event when debug mode is active.
#[doc(hidden)]
pub fn timetest_log(msg: std::fmt::Arguments<'_>) {
    if DEBUG_MODE.load(Ordering::Relaxed) {
        log::info!("[TIMETEST] {}", msg);
    }
}

/// Return current UNIX time in milliseconds, for cross-process correlation.
#[doc(hidden)]
pub fn ts_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

/// Emit a `[TIMETEST]` log line. No-op when debug mode is off.
#[macro_export]
macro_rules! timetest {
    ($($arg:tt)*) => {
        $crate::timetest_log(format_args!($($arg)*));
    };
}

/// Startup configuration parsed from command line arguments.
#[cfg(feature = "gui")]
struct StartupConfig {
    /// Specific profile name to load (enables multi-instance mode).
    profile_name: Option<String>,
    /// Force multi-instance mode even without --profile.
    multi_instance: bool,
}

/// Parse command line arguments to determine startup mode.
#[cfg(feature = "gui")]
fn parse_startup_args() -> StartupConfig {
    let args: Vec<String> = std::env::args().collect();
    let mut profile_name = None;
    let mut multi_instance = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--profile" | "-p" => {
                if i + 1 < args.len() {
                    profile_name = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--multi-instance" | "-m" => {
                multi_instance = true;
                i += 1;
            }
            _ => i += 1,
        }
    }

    // If a profile is specified, implicitly enable multi-instance mode
    if profile_name.is_some() {
        multi_instance = true;
    }

    StartupConfig {
        profile_name,
        multi_instance,
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
#[cfg(feature = "gui")]
pub fn run() {
    // Parse startup arguments
    let config = parse_startup_args();

    // Updater public key for signature verification
    let updater_pubkey = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IEExOTAyMUI4NTBDM0U1QjAKUldTdzVjTlF1Q0dRb1VPeGZYQ3M1dC9kcEJ5S1hidHNFVFQrZVRzWks2RGQ3NEZWSGI0YkpTQVQK";

    // Build Tauri app
    let builder = tauri::Builder::default().register_asynchronous_uri_scheme_protocol(
        "tapchat-media",
        |context, request, responder| {
            let app = context.app_handle().clone();
            let handle = request.uri().path().trim_start_matches('/').to_string();
            let range = request
                .headers()
                .get(http::header::RANGE)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string);
            tauri::async_runtime::spawn(async move {
                let response =
                    commands::message::media_protocol_response(&app, &handle, range.as_deref())
                        .await;
                responder.respond(response);
            });
        },
    );

    // Only load single-instance plugin when NOT in multi-instance mode
    let builder = if !config.multi_instance {
        builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            // When a second instance tries to start, focus the main window instead
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
    } else {
        // In multi-instance mode, skip single-instance plugin
        // Each instance runs independently
        builder
    };

    // Determine log file name based on profile (multi-instance mode)
    let log_file_name = config.profile_name.as_ref().map(|n| format!("{}.log", n));

    let builder = builder.plugin(tauri_plugin_notification::init());
    #[cfg(feature = "gui")]
    let builder = builder.plugin(tauri_plugin_dialog::init());

    builder
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(
            tauri_plugin_log::Builder::new()
                .level(if cfg!(debug_assertions) {
                    log::LevelFilter::Info
                } else {
                    log::LevelFilter::Warn
                })
                // Keep a small, redacted attachment state-machine breadcrumb
                // trail in release builds. It contains phases and variants
                // only—never file names, object refs, capabilities, or bytes.
                .level_for("tapchat_attachment", log::LevelFilter::Info)
                .max_file_size(10_000_000)
                .targets([tauri_plugin_log::Target::new(
                    tauri_plugin_log::TargetKind::LogDir {
                        file_name: log_file_name,
                    },
                )])
                .build(),
        )
        .plugin(
            tauri_plugin_updater::Builder::new()
                .pubkey(updater_pubkey)
                .build(),
        )
        .plugin(tauri_plugin_process::init())
        .setup(move |app| {
            let handle = app.handle().clone();
            let storage_layout = storage_layout::DesktopStorageLayout::from_app(&handle)?;
            storage_layout.ensure_base_dirs()?;
            let app_state = if let Some(name) = &config.profile_name {
                AppState::with_profile_name_and_storage_layout(name, storage_layout)
            } else {
                AppState::with_storage_layout(storage_layout)
            };
            app.manage(app_state);

            // Log startup mode for debugging
            if config.multi_instance {
                log::info!("TapChat started in multi-instance mode");
                if let Some(name) = &config.profile_name {
                    log::info!(
                        "Loading profile {}",
                        crate::platform::log_sanitize::redact_id("profile", name)
                    );
                }
            }

            // Create tray menu
            let show_item = MenuItem::with_id(app, "show", "Show TapChat", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_item, &quit_item])?;

            // Build tray icon with menu when the app bundle provides an icon.
            if let Some(icon) = app.default_window_icon().cloned() {
                let _tray = TrayIconBuilder::new()
                    .icon(icon)
                    .menu(&menu)
                    .show_menu_on_left_click(true)
                    .on_menu_event(|app, event| match event.id.as_ref() {
                        "show" => {
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                        "quit" => {
                            let handle = app.clone();
                            tauri::async_runtime::spawn(async move {
                                let state = handle.state::<AppState>();
                                let profile_manager = {
                                    let inner = state.inner.read().await;
                                    inner.profile_manager.clone()
                                };
                                if let Err(error) =
                                    profile_manager.checkpoint_active_profile().await
                                {
                                    log::warn!("profile checkpoint before exit failed: {error}");
                                }
                                handle.exit(0);
                            });
                        }
                        _ => {}
                    })
                    .build(app)?;
            } else {
                log::warn!("Skipping tray icon setup because no default window icon is available");
            }

            // Spawn app ready handler
            tauri::async_runtime::spawn(async move {
                lifecycle::on_app_ready(&handle).await;
            });
            Ok(())
        })
        .on_window_event(lifecycle::handle_window_event)
        .invoke_handler(tauri::generate_handler![
            // Identity
            commands::identity::init_onboarding_profile,
            commands::identity::create_or_load_identity,
            commands::identity::get_identity_info,
            commands::identity::begin_recovery_phrase_reveal,
            commands::identity::complete_recovery_phrase_reveal,
            commands::identity::get_share_link,
            commands::identity::rotate_share_link,
            commands::identity::update_device_status,
            commands::identity::sync_groups_for_new_device,
            commands::identity::sync_groups_for_removed_device,
            commands::identity::set_local_display_name,
            // Conversations
            commands::conversation::list_conversations,
            commands::conversation::create_conversation,
            commands::conversation::recover_conversation,
            commands::conversation::get_messages,
            // Groups (Phase 6 / PLAN_GROUP)
            commands::group::list_group_conversations,
            commands::group::get_group_snapshot,
            commands::group::get_group_messages,
            commands::group::apply_group_realtime_plan,
            commands::group::create_group_conversation,
            commands::group::send_group_text_message,
            commands::group::sync_group_outbox,
            commands::group::invite_to_group,
            commands::group::create_group_invite_link,
            commands::group::revoke_group_invite_link,
            commands::group::list_group_invites,
            commands::group::submit_group_join_request,
            commands::group::list_group_join_requests,
            commands::group::process_group_join_requests,
            commands::group::retry_pending_welcome_pickups,
            commands::group::get_group_join_request_status,
            commands::group::approve_group_join,
            commands::group::reject_group_join,
            commands::group::leave_group,
            commands::group::list_group_leave_requests,
            commands::group::approve_group_leave,
            commands::group::remove_group_member,
            commands::group::transfer_group_ownership,
            commands::group::set_group_admin,
            commands::group::update_group_metadata,
            commands::group::dissolve_group,
            // Messages
            commands::message::send_text,
            commands::message::stage_attachment,
            commands::message::stage_attachments_from_dialog,
            commands::message::stage_clipboard_image,
            commands::message::release_staged_attachment,
            commands::message::send_attachment,
            commands::message::download_attachment,
            commands::message::download_attachment_to_default_path,
            commands::message::get_attachment_media_state,
            commands::message::open_media,
            commands::message::release_media,
            commands::message::clear_attachment_cache,
            // Contacts
            commands::contact::preview_contact_link,
            commands::contact::start_direct_chat_from_link,
            commands::contact::import_contact_by_link,
            commands::contact::list_contacts,
            commands::contact::refresh_contact,
            commands::contact::set_contact_display_name,
            commands::contact::delete_contact,
            // Profile
            commands::profile::list_profiles,
            commands::profile::create_profile,
            commands::profile::start_new_profile_onboarding,
            commands::profile::activate_profile,
            commands::profile::select_profile_for_restart,
            commands::profile::unlock_active_profile,
            commands::profile::retry_locked_profile_startup,
            commands::profile::delete_profile,
            commands::profile::reload_engine,
            // Message Requests
            commands::request::list_message_requests,
            commands::request::act_on_message_request,
            // Allowlist
            commands::request::get_allowlist,
            commands::request::add_to_allowlist,
            commands::request::remove_from_allowlist,
            // Cloudflare
            commands::cloudflare::cloudflare_preflight,
            commands::cloudflare::cloudflare_login,
            commands::cloudflare::cloudflare_import_legacy_wrangler_token,
            commands::cloudflare::cloudflare_deploy,
            commands::cloudflare::cloudflare_status,
            commands::cloudflare::cloudflare_refresh_runtime_auth,
            commands::cloudflare::cloudflare_rotate_runtime_secrets,
            commands::cloudflare::cloudflare_resume_secret_rotation,
            commands::cloudflare::cloudflare_finalize_secret_rotation,
            // Session
            commands::session::start_realtime_session,
            commands::session::stop_realtime_session,
            commands::session::sync_now,
            commands::session::get_session_status,
            // Lifecycle (onboarding)
            lifecycle::complete_onboarding,
            lifecycle::set_onboarding_step,
            // Utility
            commands::utility::get_app_metadata,
            commands::utility::open_file,
            commands::utility::open_containing_folder,
            commands::utility::path_exists,
            commands::utility::check_notification_permission,
            commands::utility::request_notification_permission,
            commands::utility::show_notification,
            commands::utility::get_file_metadata,
            commands::utility::set_debug_mode,
            commands::utility::get_debug_mode,
            // Attachment settings
            commands::attachment_settings::get_attachment_settings,
            commands::attachment_settings::set_attachment_settings,
            commands::attachment_settings::get_attachment_cache_dir,
            commands::group_sync_settings::get_group_sync_settings,
            commands::group_sync_settings::set_group_sync_settings,
        ])
        .run(tauri::generate_context!())
        .expect("error while running TapChat");
}

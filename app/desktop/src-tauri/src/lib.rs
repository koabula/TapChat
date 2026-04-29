mod commands;
mod lifecycle;
mod platform;
mod ports;
mod runtime_auth;
mod state;

use std::sync::atomic::{AtomicBool, Ordering};

use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::Manager;

pub use state::{AppState, SessionState};

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
struct StartupConfig {
    /// Specific profile name to load (enables multi-instance mode).
    profile_name: Option<String>,
    /// Force multi-instance mode even without --profile.
    multi_instance: bool,
}

/// Parse command line arguments to determine startup mode.
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
pub fn run() {
    // Parse startup arguments
    let config = parse_startup_args();

    // Updater public key for signature verification
    let updater_pubkey = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IEExOTAyMUI4NTBDM0U1QjAKUldTdzVjTlF1Q0dRb1VPeGZYQ3M1dC9kcEJ5S1hidHNFVFQrZVRzWks2RGQ3NEZWSGI0YkpTQVQK";

    // Create AppState based on startup config
    let app_state = if let Some(name) = &config.profile_name {
        AppState::with_profile_name(name)
    } else {
        AppState::new()
    };

    // Build Tauri app
    let builder = tauri::Builder::default();

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

    builder
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(
            tauri_plugin_log::Builder::new()
                .level(log::LevelFilter::Info)
                .max_file_size(100_000_000) // ~100 MB — effectively disable rotation
                .targets([tauri_plugin_log::Target::new(
                    tauri_plugin_log::TargetKind::Folder {
                        path: dirs::data_local_dir()
                            .unwrap_or_else(|| std::path::PathBuf::from("."))
                            .join("TapChat")
                            .join("logs"),
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
        .manage(app_state)
        .setup(move |app| {
            let handle = app.handle().clone();

            // Log startup mode for debugging
            if config.multi_instance {
                log::info!("TapChat started in multi-instance mode");
                if let Some(name) = &config.profile_name {
                    log::info!("Loading profile: {}", name);
                }
            }

            // Create tray menu
            let show_item = MenuItem::with_id(app, "show", "Show TapChat", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_item, &quit_item])?;

            // Build tray icon with menu
            let _tray = TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .show_menu_on_left_click(true)
                .on_menu_event(|app, event| {
                    match event.id.as_ref() {
                        "show" => {
                            // Show the main window
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                        "quit" => {
                            // Set quitting state and exit
                            app.exit(0);
                        }
                        _ => {}
                    }
                })
                .build(app)?;

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
            commands::identity::get_share_link,
            commands::identity::rotate_share_link,
            commands::identity::update_device_status,
            commands::identity::set_local_display_name,
            // Conversations
            commands::conversation::list_conversations,
            commands::conversation::create_conversation,
            commands::conversation::get_messages,
            // Messages
            commands::message::send_text,
            commands::message::send_attachment,
            commands::message::download_attachment,
            commands::message::download_attachment_to_default_path,
            commands::message::cache_attachment,
            commands::message::get_attachment_preview,
            // Contacts
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
            commands::cloudflare::cloudflare_deploy,
            commands::cloudflare::cloudflare_status,
            // Session
            commands::session::start_realtime_session,
            commands::session::stop_realtime_session,
            commands::session::sync_now,
            commands::session::get_session_status,
            // Lifecycle (onboarding)
            lifecycle::complete_onboarding,
            lifecycle::set_onboarding_step,
            // Utility
            commands::utility::open_file,
            commands::utility::path_exists,
            commands::utility::check_notification_permission,
            commands::utility::request_notification_permission,
            commands::utility::show_notification,
            commands::utility::write_temp_file,
            commands::utility::get_file_metadata,
            commands::utility::set_debug_mode,
            commands::utility::get_debug_mode,
            // Attachment settings
            commands::attachment_settings::get_attachment_settings,
            commands::attachment_settings::set_attachment_settings,
            commands::attachment_settings::get_attachment_cache_dir,
        ])
        .run(tauri::generate_context!())
        .expect("error while running TapChat");
}

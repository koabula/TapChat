mod commands;
mod lifecycle;
mod platform;
mod ports;
mod state;

use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::Manager;

pub use state::{AppState, SessionState};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Updater public key for signature verification
    let updater_pubkey = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IEExOTAyMUI4NTBDM0U1QjAKUldTdzVjTlF1Q0dRb1VPeGZYQ3M1dC9kcEJ5S1hidHNFVFQrZVRzWks2RGQ3NEZWSGI0YkpTQVQK";

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            // When a second instance tries to start, focus the main window instead
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(
            tauri_plugin_updater::Builder::new()
                .pubkey(updater_pubkey)
                .build()
        )
        .plugin(tauri_plugin_process::init())
        .manage(AppState::new())
        .setup(|app| {
            let handle = app.handle().clone();

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
            commands::identity::create_or_load_identity,
            commands::identity::get_identity_info,
            commands::identity::get_share_link,
            commands::identity::rotate_share_link,
            commands::identity::update_device_status,
            // Conversations
            commands::conversation::list_conversations,
            commands::conversation::create_conversation,
            commands::conversation::get_messages,
            // Messages
            commands::message::send_text,
            commands::message::send_attachment,
            commands::message::download_attachment,
            commands::message::get_attachment_preview,
            // Contacts
            commands::contact::import_contact_by_link,
            commands::contact::list_contacts,
            commands::contact::refresh_contact,
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
            commands::utility::check_notification_permission,
            commands::utility::request_notification_permission,
            commands::utility::show_notification,
            commands::utility::write_temp_file,
        ])
        .run(tauri::generate_context!())
        .expect("error while running TapChat");
}

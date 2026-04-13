mod commands;
mod lifecycle;
mod platform;
mod ports;
mod state;

use tauri::Manager;

pub use state::{AppState, SessionState};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(AppState::new())
        .setup(|app| {
            let handle = app.handle().clone();
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
            // Conversations
            commands::conversation::list_conversations,
            commands::conversation::create_conversation,
            commands::conversation::get_messages,
            // Messages
            commands::message::send_text,
            commands::message::send_attachment,
            commands::message::download_attachment,
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running TapChat");
}

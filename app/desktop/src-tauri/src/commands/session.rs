use serde::Serialize;
use tauri::{AppHandle, Emitter, State};

use tapchat_core::{CoreCommand, CoreOutput};
use tapchat_core::transport_contract::RealtimeSubscriptionRequest;

use crate::lifecycle::{CoreInput, drive_core_with_handle};
use crate::state::{AppState, SessionState};

#[derive(Debug, Clone, Serialize)]
pub struct SessionStatus {
    pub state: String,
    pub device_id: Option<String>,
    pub ws_connected: bool,
}

#[tauri::command]
pub async fn start_realtime_session(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let inner = state.inner.read().await;

    // Get device_id and endpoint from active session
    let (device_id, endpoint) = match &inner.session {
        SessionState::Active { device_id } => {
            // Get runtime metadata to find WebSocket endpoint
            let runtime = inner.profile_manager.get_runtime_metadata().await;
            let ws_endpoint = runtime.and_then(|r| r.websocket_base_url);
            (device_id.clone(), ws_endpoint)
        }
        _ => return Err("No active session".into()),
    };

    let endpoint = endpoint.ok_or("No WebSocket endpoint configured")?;

    // Get last acked seq from sync state
    let snapshot = inner.engine.refresh_snapshot();
    let last_acked_seq = snapshot.sync_states
        .iter()
        .find(|s| s.device_id == device_id)
        .map(|s| s.state.checkpoint.last_acked_seq)
        .unwrap_or(0);

    drop(inner);

    // Create realtime subscription request
    let subscription = RealtimeSubscriptionRequest {
        device_id,
        endpoint,
        last_acked_seq,
        headers: Default::default(),
    };

    // Open WebSocket through drive_core
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::SyncInbox {
            device_id: subscription.device_id.clone(),
            reason: Some("realtime start".into()),
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    Ok(())
}

#[tauri::command]
pub async fn stop_realtime_session(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let inner = state.inner.read().await;

    let device_id = match &inner.session {
        SessionState::Active { device_id } => device_id.clone(),
        _ => return Err("No active session".into()),
    };

    drop(inner);

    // Close WebSocket through ports
    // Note: This would be better as an effect, but for now we emit a disconnect event
    let _ = app.emit("session-status", SessionStatus {
        state: "active".into(),
        device_id: Some(device_id),
        ws_connected: false,
    });

    Ok(())
}

#[tauri::command]
pub async fn sync_now(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CoreOutput, String> {
    let inner = state.inner.read().await;

    let device_id = match &inner.session {
        SessionState::Active { device_id } => device_id.clone(),
        _ => return Err("No active session".into()),
    };

    drop(inner);

    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::SyncInbox {
            device_id,
            reason: Some("manual".into()),
        }),
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_session_status(
    state: State<'_, AppState>,
) -> Result<SessionStatus, String> {
    let inner = state.inner.read().await;

    // Check WebSocket connection status from realtime manager
    let ws_connected = match &inner.session {
        SessionState::Active { device_id } => {
            inner.ports.realtime.is_connected(device_id).await
        }
        _ => false,
    };

    match &inner.session {
        SessionState::Active { device_id } => Ok(SessionStatus {
            state: "active".into(),
            device_id: Some(device_id.clone()),
            ws_connected,
        }),
        SessionState::Onboarding { step } => Ok(SessionStatus {
            state: format!("onboarding:{:?}", step).to_lowercase(),
            device_id: None,
            ws_connected,
        }),
        SessionState::Uninitialized => Ok(SessionStatus {
            state: "uninitialized".into(),
            device_id: None,
            ws_connected,
        }),
        SessionState::Quitting => Ok(SessionStatus {
            state: "quitting".into(),
            device_id: None,
            ws_connected,
        }),
    }
}
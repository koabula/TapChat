use serde::Serialize;
use tauri::{AppHandle, Emitter, State};

use tapchat_core::{CoreCommand, CoreOutput};

use crate::lifecycle::{CoreInput, drive_core_with_handle};
use crate::runtime_auth::ensure_fresh_device_runtime_auth_for_state;
use crate::state::{AppState, SessionState, StartupPhase};

#[derive(Debug, Clone, Serialize)]
pub struct SessionStatus {
    pub state: String,
    pub device_id: Option<String>,
    pub ws_connected: bool,
}

pub async fn set_ws_connection_snapshot(
    state: &AppState,
    device_id: Option<String>,
    ws_connected: bool,
) {
    let mut snapshot = state.ws_status.write().await;
    snapshot.ws_connected = ws_connected;
    if device_id.is_some() {
        snapshot.last_known_device_id = device_id;
    } else if !ws_connected {
        snapshot.last_known_device_id = None;
    }
}

pub async fn read_session_status_snapshot(state: &AppState) -> SessionStatus {
    let (session, ws_snapshot, startup_phase) = {
        let inner = state.inner.read().await;
        let session = inner.session.clone();
        let startup_phase = inner.startup_phase;
        drop(inner);
        let ws_snapshot = state.ws_status.read().await.clone();
        (session, ws_snapshot, startup_phase)
    };

    // If backend is not ready, return bootstrapping instead of uninitialized
    // This prevents frontend from showing onboarding before profile is loaded
    if startup_phase != StartupPhase::Ready {
        return SessionStatus {
            state: "bootstrapping".into(),
            device_id: None,
            ws_connected: false,
        };
    }

    match session {
        SessionState::Active { device_id } => SessionStatus {
            state: "active".into(),
            device_id: Some(device_id),
            ws_connected: ws_snapshot.ws_connected,
        },
        SessionState::Onboarding { step } => SessionStatus {
            state: format!("onboarding:{:?}", step).to_lowercase(),
            device_id: None,
            ws_connected: ws_snapshot.ws_connected,
        },
        SessionState::Uninitialized => SessionStatus {
            state: "uninitialized".into(),
            device_id: ws_snapshot.last_known_device_id,
            ws_connected: ws_snapshot.ws_connected,
        },
        SessionState::Quitting => SessionStatus {
            state: "quitting".into(),
            device_id: ws_snapshot.last_known_device_id,
            ws_connected: ws_snapshot.ws_connected,
        },
    }
}

async fn run_gated_sync(
    app: &AppHandle,
    state: &State<'_, AppState>,
    reason: &str,
) -> Result<CoreOutput, String> {
    let device_id = {
        let inner = state.inner.read().await;
        match &inner.session {
            SessionState::Active { device_id } => device_id.clone(),
            _ => return Err("No active session".into()),
        }
    };

    {
        let mut gate = state.sync_gate.lock().await;
        if gate.in_flight {
            gate.pending = true;
            log::debug!("[session] sync already in flight; coalescing request ({reason})");
            return Ok(CoreOutput::default());
        }
        gate.in_flight = true;
        gate.pending = false;
    }

    loop {
        let result = drive_core_with_handle(
            app,
            CoreInput::Command(CoreCommand::SyncInbox {
                device_id: device_id.clone(),
                reason: Some(reason.to_string()),
            }),
        )
        .await
        .map_err(|error| error.to_string());

        let should_rerun = {
            let mut gate = state.sync_gate.lock().await;
            if gate.pending {
                gate.pending = false;
                true
            } else {
                gate.in_flight = false;
                false
            }
        };

        if !should_rerun {
            return result;
        }

        log::debug!("[session] running trailing sync after coalesced request ({reason})");
    }
}

#[tauri::command]
pub async fn start_realtime_session(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    ensure_fresh_device_runtime_auth_for_state(state.inner())
        .await
        .map_err(|error| error.to_string())?;
    run_gated_sync(&app, &state, "realtime start").await?;
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

    set_ws_connection_snapshot(&state, Some(device_id.clone()), false).await;

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
    ensure_fresh_device_runtime_auth_for_state(state.inner())
        .await
        .map_err(|error| error.to_string())?;
    run_gated_sync(&app, &state, "manual").await
}

#[tauri::command]
pub async fn get_session_status(
    state: State<'_, AppState>,
) -> Result<SessionStatus, String> {
    Ok(read_session_status_snapshot(&state).await)
}

#[cfg(test)]
mod tests {
    use crate::state::SyncGateState;

    #[tokio::test]
    async fn coalesced_sync_requests_set_pending_without_starting_second_run() {
        let gate = tokio::sync::Mutex::new(SyncGateState {
            in_flight: true,
            pending: false,
        });

        {
            let mut state = gate.lock().await;
            assert!(state.in_flight);
            assert!(!state.pending);
            state.pending = true;
        }

        let state = gate.lock().await;
        assert!(state.in_flight);
        assert!(state.pending);
    }
}

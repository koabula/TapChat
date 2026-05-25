use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use futures_util::{SinkExt, StreamExt};
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::tungstenite::handshake::client::Request;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{connect_async_tls_with_config, WebSocketStream};

use tapchat_core::cli::util::to_camel_case_json_string;
use tapchat_core::ffi_api::{CoreEvent, RealtimeEvent};
use tapchat_core::transport_contract::{
    GroupRealtimeSubscriptionRequest, RealtimeSubscriptionRequest,
};

use crate::commands::session::set_ws_connection_snapshot;
use crate::lifecycle::{drive_core_with_handle, CoreInput};
use crate::platform::profile::ProfileManagerInner;
use crate::state::AppState;
use crate::timetest;

/// Unique identifier for each WebSocket connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionId(String);

impl ConnectionId {
    pub fn new() -> Self {
        Self(format!("conn:{}", uuid::Uuid::new_v4()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for ConnectionId {
    fn default() -> Self {
        Self::new()
    }
}

/// Realtime connection manager for WebSocket subscriptions.
pub struct RealtimeManager {
    sessions: Arc<RwLock<HashMap<String, RealtimeSession>>>,
    group_sessions: Arc<RwLock<HashMap<String, RealtimeSession>>>,
    #[allow(dead_code)]
    profile_inner: Arc<RwLock<ProfileManagerInner>>,
    app_handle: Option<Arc<AppHandle>>,
    /// Counter for generating unique connection IDs
    connection_counter: Arc<RwLock<u64>>,
}

#[allow(dead_code)]
struct RealtimeSession {
    device_id: String,
    endpoint: String,
    connection_id: ConnectionId,
    connecting: bool,
    connected: bool,
    /// If true, this session is stale and should not process messages
    stale: bool,
    stop_tx: mpsc::Sender<()>,
    /// Time when connection was established
    connected_at: Option<Instant>,
}

enum ConnectionReservation {
    Existing,
    Reserved {
        connection_id: ConnectionId,
        stop_rx: mpsc::Receiver<()>,
        stale_stop_tx: Option<mpsc::Sender<()>>,
    },
}

/// Events received from WebSocket.
/// Note: Cloudflare uses camelCase for field names (deviceId, senderUserId, requestId)
/// but snake_case for event types (head_updated, inbox_record_available, message_request_changed)
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
#[allow(dead_code)]
pub enum WsServerEvent {
    HeadUpdated {
        #[serde(rename = "deviceId")]
        device_id: String,
        seq: u64,
    },
    InboxRecordAvailable {
        #[serde(rename = "deviceId")]
        device_id: String,
        seq: u64,
        record: Option<serde_json::Value>,
    },
    MessageRequestChanged {
        #[serde(rename = "deviceId")]
        device_id: String,
        #[serde(rename = "senderUserId")]
        sender_user_id: String,
        #[serde(rename = "requestId")]
        request_id: String,
        change: String,
    },
    GroupHeadUpdated {
        #[serde(rename = "groupId")]
        group_id: String,
        seq: u64,
    },
    GroupOutboxRecordAvailable {
        #[serde(rename = "groupId")]
        group_id: String,
        seq: u64,
        record: Option<serde_json::Value>,
    },
    GroupJoinRequestAvailable {
        #[serde(rename = "groupId")]
        group_id: String,
        #[serde(rename = "requestId")]
        request_id: String,
    },
}

impl RealtimeManager {
    pub fn new(profile_inner: Arc<RwLock<ProfileManagerInner>>) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            group_sessions: Arc::new(RwLock::new(HashMap::new())),
            profile_inner,
            app_handle: None,
            connection_counter: Arc::new(RwLock::new(0)),
        }
    }

    /// Set the app handle for emitting events to frontend.
    pub fn set_app_handle(&mut self, handle: Arc<AppHandle>) {
        self.app_handle = Some(handle);
    }

    /// Generate a unique connection ID
    async fn next_connection_id(&self) -> ConnectionId {
        let mut counter = self.connection_counter.write().await;
        *counter += 1;
        ConnectionId(format!(
            "conn:{}:{}",
            *counter,
            uuid::Uuid::new_v4().simple()
        ))
    }

    /// Open a realtime WebSocket connection.
    /// If an existing connection exists for this device, it will be marked stale and closed.
    pub async fn open_connection(
        &self,
        subscription: RealtimeSubscriptionRequest,
    ) -> Result<Vec<CoreEvent>> {
        let device_id = subscription.device_id.clone();
        let endpoint = subscription.endpoint.clone();

        log::info!(
            "RealtimeManager::open_connection: device_id={}, endpoint={}, last_acked_seq={}",
            device_id,
            summarize_endpoint(&endpoint),
            subscription.last_acked_seq
        );
        let reservation = self.reserve_connection(&device_id, &endpoint).await;
        let (connection_id, stop_rx, stale_stop_tx) = match reservation {
            ConnectionReservation::Existing => {
                log::debug!(
                    "RealtimeManager: reusing active or connecting session for device_id={}",
                    device_id
                );
                return Ok(Vec::new());
            }
            ConnectionReservation::Reserved {
                connection_id,
                stop_rx,
                stale_stop_tx,
            } => (connection_id, stop_rx, stale_stop_tx),
        };

        if let Some(tx) = stale_stop_tx {
            let _ = tx.send(()).await;
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }

        // Step 3: Build WebSocket URL
        let ws_url = self.build_ws_url(&endpoint, &device_id, subscription.last_acked_seq)?;

        log::info!("RealtimeManager: built ws_url={}", ws_url);

        // Step 6: Create request with headers
        let mut request = Request::builder()
            .uri(&ws_url)
            .method("GET")
            .header("Host", self.extract_host(&endpoint)?)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header(
                "Sec-WebSocket-Key",
                tokio_tungstenite::tungstenite::handshake::client::generate_key(),
            )
            .header("Sec-WebSocket-Version", "13")
            .body(())
            .context("build websocket request")?;

        for (key, value) in subscription.headers.iter() {
            use http::header::HeaderName;
            use http::HeaderValue;
            let name: HeaderName = key.parse().context("parse header name")?;
            let val: HeaderValue = value.parse().context("parse header value")?;
            request.headers_mut().insert(name, val);
        }

        // Step 7: Connect
        let (ws_stream, _) = match connect_async_tls_with_config(request, None, false, None).await {
            Ok(result) => result,
            Err(error) => {
                let mut sessions = self.sessions.write().await;
                if sessions
                    .get(&device_id)
                    .is_some_and(|session| session.connection_id == connection_id)
                {
                    sessions.remove(&device_id);
                }
                let detail = format!("websocket connect: {}", error);
                log::warn!(
                    "RealtimeManager: websocket connect failed device_id={} endpoint={} error={}",
                    device_id,
                    summarize_endpoint(&endpoint),
                    detail
                );
                if let Some(app) = &self.app_handle {
                    set_ws_connection_snapshot(
                        app.state::<AppState>().inner(),
                        Some(device_id.clone()),
                        false,
                    )
                    .await;
                    let _ = app.emit(
                        "realtime-event",
                        RealtimeEventPayload {
                            device_id: device_id.clone(),
                            event_type: "error".to_string(),
                            data: Some(detail.clone()),
                        },
                    );
                }
                return Ok(vec![CoreEvent::WebSocketDisconnected {
                    device_id,
                    reason: Some(detail),
                }]);
            }
        };

        log::info!(
            "RealtimeManager: WebSocket connected for device_id={}, connection_id={}",
            device_id,
            connection_id.as_str()
        );
        timetest!("ws_connected device_id={} ts={}", device_id, crate::ts_ms());

        // Step 8: Emit WebSocketConnected to frontend
        if let Some(app) = &self.app_handle {
            set_ws_connection_snapshot(
                app.state::<AppState>().inner(),
                Some(device_id.clone()),
                true,
            )
            .await;
            let _ = app.emit(
                "realtime-event",
                RealtimeEventPayload {
                    device_id: device_id.clone(),
                    event_type: "connected".to_string(),
                    data: None,
                },
            );
        }

        // Step 9: Store new session (replace any stale entry)
        {
            let mut sessions = self.sessions.write().await;
            if let Some(session) = sessions.get_mut(&device_id) {
                if session.connection_id == connection_id {
                    session.connecting = false;
                    session.connected = true;
                    session.stale = false;
                    session.connected_at = Some(Instant::now());
                }
            }
        }

        // Step 10: Spawn background task to read messages
        let sessions_clone = self.sessions.clone();
        let device_id_clone = device_id.clone();
        let connection_id_clone = connection_id.clone();
        let app_handle_clone = self.app_handle.clone();
        tokio::spawn(async move {
            Self::read_loop(
                ws_stream,
                sessions_clone,
                device_id_clone,
                connection_id_clone,
                stop_rx,
                app_handle_clone,
            )
            .await;
        });

        Ok(vec![CoreEvent::WebSocketConnected { device_id }])
    }

    /// Close a realtime connection.
    pub async fn close_connection(&self, device_id: &str) -> Result<Vec<CoreEvent>> {
        let mut sessions = self.sessions.write().await;

        if let Some(session) = sessions.remove(device_id) {
            // Mark as stale first to prevent read_loop from emitting events
            // (session is removed, so read_loop will fail to find it anyway)
            // Send stop signal
            let _ = session.stop_tx.send(()).await;
        }

        // Emit WebSocketDisconnected to frontend
        if let Some(app) = &self.app_handle {
            set_ws_connection_snapshot(
                app.state::<AppState>().inner(),
                Some(device_id.to_string()),
                false,
            )
            .await;
            let _ = app.emit(
                "realtime-event",
                RealtimeEventPayload {
                    device_id: device_id.to_string(),
                    event_type: "disconnected".to_string(),
                    data: None,
                },
            );
        }

        Ok(vec![CoreEvent::WebSocketDisconnected {
            device_id: device_id.to_string(),
            reason: Some("closed by user".into()),
        }])
    }

    /// Close all realtime connections silently (no notifications).
    /// Used when switching profiles to avoid triggering disconnect notifications.
    /// Marks all connections as stale before closing.
    pub async fn close_all_silent(&self) -> Result<()> {
        let mut sessions = self.sessions.write().await;

        // Mark all as stale and close
        for (_, session) in sessions.iter_mut() {
            session.stale = true;
            session.connecting = false;
            session.connected = false;
            let _ = session.stop_tx.send(()).await;
        }

        // Clear all sessions
        sessions.clear();

        Ok(())
    }

    /// Check if a session is connected and not stale.
    pub async fn is_connected(&self, device_id: &str) -> bool {
        let sessions = self.sessions.read().await;
        sessions
            .get(device_id)
            .map(|s| s.connected && !s.stale)
            .unwrap_or(false)
    }

    /// Get connection info for diagnostics.
    pub async fn get_connection_info(&self, device_id: &str) -> Option<(String, bool, bool)> {
        let sessions = self.sessions.read().await;
        sessions
            .get(device_id)
            .map(|s| (s.connection_id.as_str().to_string(), s.connected, s.stale))
    }

    /// Open a group outbox realtime WebSocket connection.
    /// If an existing connection exists for this group, it will be marked stale and closed.
    pub async fn open_group_connection(
        &self,
        subscription: GroupRealtimeSubscriptionRequest,
    ) -> Result<Vec<CoreEvent>> {
        let group_id = subscription.group_id.clone();
        let endpoint = subscription.endpoint.clone();

        log::info!(
            "RealtimeManager::open_group_connection: group_id={}, endpoint={}, last_seq={}",
            group_id,
            summarize_endpoint(&endpoint),
            subscription.last_seq
        );

        // Check for existing group session
        {
            let sessions = self.group_sessions.read().await;
            if let Some(session) = sessions.get(&group_id) {
                if session.endpoint == endpoint && (session.connecting || session.connected) {
                    log::debug!(
                        "RealtimeManager: reusing active or connecting group session for group_id={}",
                        group_id
                    );
                    return Ok(vec![CoreEvent::GroupWebSocketConnected { group_id }]);
                }
            }
        }

        let connection_id = self.next_connection_id().await;
        let (stop_tx, stop_rx) = mpsc::channel::<()>(1);

        // Mark existing stale and replace
        let stale_stop_tx;
        {
            let mut sessions = self.group_sessions.write().await;
            let old = sessions.insert(
                group_id.clone(),
                RealtimeSession {
                    device_id: group_id.clone(),
                    endpoint: endpoint.clone(),
                    connection_id: connection_id.clone(),
                    connecting: true,
                    connected: false,
                    stale: false,
                    stop_tx: stop_tx.clone(),
                    connected_at: None,
                },
            );

            if let Some(old_session) = old {
                stale_stop_tx = Some(old_session.stop_tx.clone());
            } else {
                stale_stop_tx = None;
            }
        }

        if let Some(tx) = stale_stop_tx {
            let _ = tx.send(()).await;
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }

        // Build WebSocket URL: the group outbox subscribe endpoint is already a full URL
        let ws_url = {
            let url = if endpoint.starts_with("https://") {
                endpoint.replace("https://", "wss://")
            } else if endpoint.starts_with("http://") {
                endpoint.replace("http://", "ws://")
            } else {
                endpoint.clone()
            };
            format!("{url}?last_seq={}", subscription.last_seq)
        };

        log::info!("RealtimeManager: built group ws_url={}", ws_url);

        // Create request with group capability header
        let capability_json = to_camel_case_json_string(
            &serde_json::to_string(&subscription.capability)
                .map_err(|e| anyhow::anyhow!("serialize group capability: {e}"))?,
        )
        .map_err(|e| anyhow::anyhow!("serialize group capability camelCase: {e}"))?;
        let bearer = format!("Bearer {}", subscription.capability.signature);

        let request = Request::builder()
            .uri(&ws_url)
            .method("GET")
            .header("Host", self.extract_host(&endpoint)?)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header(
                "Sec-WebSocket-Key",
                tokio_tungstenite::tungstenite::handshake::client::generate_key(),
            )
            .header("Sec-WebSocket-Version", "13")
            .header("Authorization", bearer)
            .header("X-Tapchat-Group-Capability", &capability_json)
            .body(())
            .context("build group websocket request")?;

        // Connect
        let (ws_stream, _) = match connect_async_tls_with_config(request, None, false, None).await {
            Ok(result) => result,
            Err(error) => {
                let mut sessions = self.group_sessions.write().await;
                if sessions
                    .get(&group_id)
                    .is_some_and(|session| session.connection_id == connection_id)
                {
                    sessions.remove(&group_id);
                }
                let detail = format!("group websocket connect: {}", error);
                log::warn!(
                    "RealtimeManager: group websocket connect failed group_id={} error={}",
                    group_id,
                    detail
                );
                if let Some(app) = &self.app_handle {
                    let _ = app.emit(
                        "realtime-event",
                        RealtimeEventPayload {
                            device_id: group_id.clone(),
                            event_type: "group_error".to_string(),
                            data: Some(detail.clone()),
                        },
                    );
                }
                return Ok(vec![CoreEvent::GroupWebSocketDisconnected {
                    group_id,
                    error: Some(detail),
                }]);
            }
        };

        // Mark connected
        {
            let mut sessions = self.group_sessions.write().await;
            if let Some(session) = sessions.get_mut(&group_id) {
                if session.connection_id == connection_id && !session.stale {
                    session.connecting = false;
                    session.connected = true;
                    session.connected_at = Some(Instant::now());
                }
            }
        }

        if let Some(app) = &self.app_handle {
            let _ = app.emit(
                "realtime-event",
                RealtimeEventPayload {
                    device_id: group_id.clone(),
                    event_type: "group_connected".to_string(),
                    data: None,
                },
            );
        }

        // Spawn read loop with group-specific semantics
        let sessions_ref = self.group_sessions.clone();
        let app_handle_ref = self.app_handle.clone();
        let group_id_clone = group_id.clone();
        tokio::spawn(async move {
            Self::group_read_loop(
                ws_stream,
                sessions_ref,
                group_id_clone,
                connection_id,
                stop_rx,
                app_handle_ref,
            )
            .await;
        });

        Ok(vec![CoreEvent::GroupWebSocketConnected { group_id }])
    }

    pub async fn close_group_connection(&self, group_id: &str) -> Result<Vec<CoreEvent>> {
        let stop_tx = {
            let mut sessions = self.group_sessions.write().await;
            sessions.remove(group_id).map(|session| session.stop_tx)
        };
        if let Some(tx) = stop_tx {
            let _ = tx.send(()).await;
        }
        Ok(Vec::new())
    }

    async fn group_read_loop(
        ws_stream: WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
        sessions: Arc<RwLock<HashMap<String, RealtimeSession>>>,
        group_id: String,
        connection_id: ConnectionId,
        mut stop_rx: mpsc::Receiver<()>,
        app_handle: Option<Arc<AppHandle>>,
    ) {
        let (mut write, mut read) = ws_stream.split();

        loop {
            tokio::select! {
                _ = stop_rx.recv() => {
                    let _ = write.close().await;
                    let should_emit = {
                        let sessions_guard = sessions.read().await;
                        match sessions_guard.get(&group_id) {
                            Some(session) => session.connection_id == connection_id && !session.stale,
                            None => false,
                        }
                    };
                    if should_emit {
                        if let Some(app) = &app_handle {
                            let _ = app.emit("realtime-event", RealtimeEventPayload {
                                device_id: group_id.clone(),
                                event_type: "group_disconnected".to_string(),
                                data: None,
                            });
                        }
                    }
                    break;
                }

                msg = read.next() => {
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            let is_active = {
                                let sessions_guard = sessions.read().await;
                                match sessions_guard.get(&group_id) {
                                    Some(session) => session.connection_id == connection_id && !session.stale,
                                    None => false,
                                }
                            };

                            if !is_active {
                                log::warn!(
                                    "RealtimeManager: ignoring group message for stale connection {}",
                                    connection_id.as_str()
                                );
                                continue;
                            }

                            if let Ok(event) = serde_json::from_str::<WsServerEvent>(&text) {
                                log::info!("RealtimeManager: group {}", summarize_ws_event(&group_id, &event));

                                if let Some(app) = &app_handle {
                                    let _ = app.emit("realtime-event", RealtimeEventPayload {
                                        device_id: group_id.clone(),
                                        event_type: event.event_type_name(),
                                        data: Some(text.to_string()),
                                    });
                                }
                                if let (Some(app), Some(core_event)) = (
                                    app_handle.as_ref(),
                                    group_core_event_from_ws_event(&group_id, &event),
                                ) {
                                    let app = app.clone();
                                    std::thread::spawn(move || {
                                        tauri::async_runtime::handle().block_on(async move {
                                            if let Err(error) = Box::pin(drive_core_with_handle(
                                                app.as_ref(),
                                                CoreInput::Event(core_event),
                                            ))
                                            .await
                                            {
                                                log::warn!(
                                                    "RealtimeManager: failed to drive core from group realtime event: {}",
                                                    error
                                                );
                                            }
                                        });
                                    });
                                }
                            } else {
                                log::warn!("Group WS event failed to parse for {}: {}", group_id, text);
                            }
                        }
                        Some(Ok(Message::Ping(data))) => {
                            let is_active = {
                                let sessions_guard = sessions.read().await;
                                match sessions_guard.get(&group_id) {
                                    Some(session) => session.connection_id == connection_id && !session.stale,
                                    None => false,
                                }
                            };
                            if is_active {
                                let _ = write.send(Message::Pong(data)).await;
                            }
                        }
                        Some(Ok(Message::Close(_))) => {
                            let should_emit = {
                                let mut sessions_guard = sessions.write().await;
                                match sessions_guard.get_mut(&group_id) {
                                    Some(session) if session.connection_id == connection_id && !session.stale => {
                                        session.connected = false;
                                        true
                                    }
                                    _ => false,
                                }
                            };

                            if should_emit {
                                if let Some(app) = &app_handle {
                                    let _ = app.emit("realtime-event", RealtimeEventPayload {
                                        device_id: group_id.clone(),
                                        event_type: "group_disconnected".to_string(),
                                        data: None,
                                    });
                                }
                            }
                            break;
                        }
                        Some(Err(e)) => {
                            log::error!("Group WS error for {}: {:?}", group_id, e);

                            let should_emit = {
                                let mut sessions_guard = sessions.write().await;
                                match sessions_guard.get_mut(&group_id) {
                                    Some(session) if session.connection_id == connection_id && !session.stale => {
                                        session.connected = false;
                                        true
                                    }
                                    _ => false,
                                }
                            };

                            if should_emit {
                                if let Some(app) = &app_handle {
                                    let _ = app.emit("realtime-event", RealtimeEventPayload {
                                        device_id: group_id.clone(),
                                        event_type: "group_error".to_string(),
                                        data: Some(e.to_string()),
                                    });
                                }
                            }
                            break;
                        }
                        None => break,
                        _ => {}
                    }
                }
            }
        }

        let mut sessions_guard = sessions.write().await;
        if let Some(session) = sessions_guard.get(&group_id) {
            if session.connection_id == connection_id {
                sessions_guard.remove(&group_id);
            }
        }
    }

    async fn reserve_connection(&self, device_id: &str, endpoint: &str) -> ConnectionReservation {
        let connection_id = self.next_connection_id().await;
        let (stop_tx, stop_rx) = mpsc::channel::<()>(1);
        let mut sessions = self.sessions.write().await;
        let mut stale_stop_tx = None;

        if let Some(existing) = sessions.get_mut(device_id) {
            if !existing.stale && (existing.connecting || existing.connected) {
                return ConnectionReservation::Existing;
            }

            if !existing.stale {
                log::info!(
                    "RealtimeManager: marking existing connection {} as stale for device_id={}",
                    existing.connection_id.as_str(),
                    device_id
                );
                existing.stale = true;
                existing.connecting = false;
                existing.connected = false;
                stale_stop_tx = Some(existing.stop_tx.clone());
            }
        }

        sessions.insert(
            device_id.to_string(),
            RealtimeSession {
                device_id: device_id.to_string(),
                endpoint: endpoint.to_string(),
                connection_id: connection_id.clone(),
                connecting: true,
                connected: false,
                stale: false,
                stop_tx: stop_tx.clone(),
                connected_at: None,
            },
        );

        ConnectionReservation::Reserved {
            connection_id,
            stop_rx,
            stale_stop_tx,
        }
    }

    fn build_ws_url(&self, endpoint: &str, device_id: &str, last_acked_seq: u64) -> Result<String> {
        // Replace {deviceId} placeholder with actual device_id
        // The endpoint format from deployment bundle is:
        // wss://worker-url/v1/inbox/{deviceId}/subscribe
        let url_with_device = endpoint.replace("{deviceId}", &urlencoding::encode(device_id));

        // Convert HTTP endpoint to WebSocket URL if needed
        let ws_base = if url_with_device.starts_with("https://") {
            url_with_device.replace("https://", "wss://")
        } else if url_with_device.starts_with("http://") {
            url_with_device.replace("http://", "ws://")
        } else {
            url_with_device
        };

        // Append query parameter
        Ok(format!("{}?last_acked_seq={}", ws_base, last_acked_seq))
    }

    fn extract_host(&self, endpoint: &str) -> Result<String> {
        let url = url::Url::parse(endpoint).context("parse endpoint URL")?;
        url.host_str()
            .map(|h| h.to_string())
            .ok_or_else(|| anyhow!("no host in endpoint"))
    }

    async fn read_loop(
        ws_stream: WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
        sessions: Arc<RwLock<HashMap<String, RealtimeSession>>>,
        device_id: String,
        connection_id: ConnectionId,
        mut stop_rx: mpsc::Receiver<()>,
        app_handle: Option<Arc<AppHandle>>,
    ) {
        let (mut write, mut read) = ws_stream.split();

        loop {
            tokio::select! {
                // Stop signal
                _ = stop_rx.recv() => {
                    let _ = write.close().await;
                    // Only emit disconnect if this connection is still the active one
                    let should_emit = {
                        let sessions_guard = sessions.read().await;
                        match sessions_guard.get(&device_id) {
                            Some(session) => session.connection_id == connection_id && !session.stale,
                            None => true, // Session removed, emit disconnect
                        }
                    };
                    if should_emit {
                        if let Some(app) = &app_handle {
                            set_ws_connection_snapshot(
                                app.state::<AppState>().inner(),
                                Some(device_id.clone()),
                                false,
                            ).await;
                            let _ = app.emit("realtime-event", RealtimeEventPayload {
                                device_id: device_id.clone(),
                                event_type: "disconnected".to_string(),
                                data: None,
                            });
                        }
                    }
                    break;
                }

                // Read message
                msg = read.next() => {
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            // Check if this connection is still active (not stale)
                            let is_active = {
                                let sessions_guard = sessions.read().await;
                                match sessions_guard.get(&device_id) {
                                    Some(session) => session.connection_id == connection_id && !session.stale,
                                    None => false, // Session removed, don't process
                                }
                            };

                            if !is_active {
                                log::warn!(
                                    "RealtimeManager: ignoring message for stale/removed connection {}",
                                    connection_id.as_str()
                                );
                                continue;
                            }

                            // Parse and emit as realtime event to frontend
                            if let Ok(event) = serde_json::from_str::<WsServerEvent>(&text) {
                                log::info!("RealtimeManager: {}", summarize_ws_event(&device_id, &event));

                                // Emit [TIMETEST] for key realtime events
                                match &event {
                                    WsServerEvent::InboxRecordAvailable { seq, record, .. } => {
                                        let msg_id = record
                                            .as_ref()
                                            .and_then(|r| r.get("messageId"))
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("?");
                                        timetest!("ws_recv device_id={} seq={} msg_id={} event=inbox_record_available ts={}",
                                            device_id, seq, msg_id, crate::ts_ms());
                                    }
                                    WsServerEvent::HeadUpdated { seq, .. } => {
                                        timetest!("ws_recv device_id={} seq={} event=head_updated ts={}",
                                            device_id, seq, crate::ts_ms());
                                    }
                                    WsServerEvent::MessageRequestChanged { .. } => {}
                                    WsServerEvent::GroupHeadUpdated { .. } => {}
                                    WsServerEvent::GroupOutboxRecordAvailable { .. } => {}
                                    WsServerEvent::GroupJoinRequestAvailable { .. } => {}
                                }

                                // Emit to frontend
                                if let Some(app) = &app_handle {
                                    let _ = app.emit("realtime-event", RealtimeEventPayload {
                                        device_id: device_id.clone(),
                                        event_type: event.event_type_name(),
                                        data: Some(text.to_string()),
                                    });
                                }
                            } else {
                                log::warn!("WS event failed to parse for {}: {}", device_id, text);
                            }
                        }
                        Some(Ok(Message::Ping(data))) => {
                            // Check if still active before responding
                            let is_active = {
                                let sessions_guard = sessions.read().await;
                                match sessions_guard.get(&device_id) {
                                    Some(session) => session.connection_id == connection_id && !session.stale,
                                    None => false,
                                }
                            };
                            if is_active {
                                let _ = write.send(Message::Pong(data)).await;
                            }
                        }
                        Some(Ok(Message::Close(_))) => {
                            // Mark disconnected and emit event only if still active
                            let should_emit = {
                                let mut sessions_guard = sessions.write().await;
                                match sessions_guard.get_mut(&device_id) {
                                    Some(session) if session.connection_id == connection_id && !session.stale => {
                                        session.connected = false;
                                        true
                                    }
                                    _ => false,
                                }
                            };

                            if should_emit {
                                if let Some(app) = &app_handle {
                                    set_ws_connection_snapshot(
                                        app.state::<AppState>().inner(),
                                        Some(device_id.clone()),
                                        false,
                                    ).await;
                                    let _ = app.emit("realtime-event", RealtimeEventPayload {
                                        device_id: device_id.clone(),
                                        event_type: "disconnected".to_string(),
                                        data: None,
                                    });
                                }
                            }
                            break;
                        }
                        Some(Err(e)) => {
                            log::error!("WS error for {}: {:?}", device_id, e);
                            timetest!("ws_error device_id={} error={:?} ts={}", device_id, e, crate::ts_ms());

                            // Only emit error if this connection is still active
                            let should_emit = {
                                let mut sessions_guard = sessions.write().await;
                                match sessions_guard.get_mut(&device_id) {
                                    Some(session) if session.connection_id == connection_id && !session.stale => {
                                        session.connected = false;
                                        true
                                    }
                                    _ => false,
                                }
                            };

                            if should_emit {
                                if let Some(app) = &app_handle {
                                    set_ws_connection_snapshot(
                                        app.state::<AppState>().inner(),
                                        Some(device_id.clone()),
                                        false,
                                    ).await;
                                    let _ = app.emit("realtime-event", RealtimeEventPayload {
                                        device_id: device_id.clone(),
                                        event_type: "error".to_string(),
                                        data: Some(e.to_string()),
                                    });
                                }
                            }
                            break;
                        }
                        None => break,
                        _ => {}
                    }
                }
            }
        }

        // Cleanup: remove session if it's still ours
        let mut sessions_guard = sessions.write().await;
        if let Some(session) = sessions_guard.get(&device_id) {
            if session.connection_id == connection_id {
                sessions_guard.remove(&device_id);
            }
        }
    }
}

fn summarize_endpoint(endpoint: &str) -> String {
    let Ok(parsed) = url::Url::parse(endpoint) else {
        return "<invalid-endpoint>".into();
    };
    let host = parsed.host_str().unwrap_or_default();
    format!("{host}{}", parsed.path())
}

/// Event payload sent to frontend via Tauri event.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RealtimeEventPayload {
    pub device_id: String,
    pub event_type: String,
    pub data: Option<String>,
}

impl WsServerEvent {
    fn event_type_name(&self) -> String {
        match self {
            WsServerEvent::HeadUpdated { .. } => "head_updated",
            WsServerEvent::InboxRecordAvailable { .. } => "inbox_record_available",
            WsServerEvent::MessageRequestChanged { .. } => "message_request_changed",
            WsServerEvent::GroupHeadUpdated { .. } => "group_head_updated",
            WsServerEvent::GroupOutboxRecordAvailable { .. } => "group_outbox_record_available",
            WsServerEvent::GroupJoinRequestAvailable { .. } => "group_join_request_available",
        }
        .to_string()
    }
}

fn group_core_event_from_ws_event(
    subscribed_group_id: &str,
    event: &WsServerEvent,
) -> Option<CoreEvent> {
    match event {
        WsServerEvent::GroupHeadUpdated { group_id, seq } if group_id == subscribed_group_id => {
            Some(CoreEvent::GroupRealtimeEventReceived {
                group_id: group_id.clone(),
                event: RealtimeEvent::GroupHeadUpdated {
                    group_id: group_id.clone(),
                    seq: *seq,
                },
            })
        }
        WsServerEvent::GroupOutboxRecordAvailable { group_id, seq, .. }
            if group_id == subscribed_group_id =>
        {
            Some(CoreEvent::GroupRealtimeEventReceived {
                group_id: group_id.clone(),
                event: RealtimeEvent::GroupOutboxRecordAvailable {
                    group_id: group_id.clone(),
                    seq: *seq,
                    record: None,
                },
            })
        }
        _ => None,
    }
}

fn summarize_ws_event(device_id: &str, event: &WsServerEvent) -> String {
    match event {
        WsServerEvent::HeadUpdated { seq, .. } => {
            format!("device_id={device_id} type=head_updated seq={seq}")
        }
        WsServerEvent::InboxRecordAvailable { seq, .. } => {
            format!("device_id={device_id} type=inbox_record_available seq={seq}")
        }
        WsServerEvent::MessageRequestChanged {
            sender_user_id,
            request_id,
            change,
            ..
        } => format!(
            "device_id={device_id} type=message_request_changed sender_user_id={sender_user_id} request_id={request_id} change={change}"
        ),
        WsServerEvent::GroupHeadUpdated {
            group_id, seq, ..
        } => {
            format!("group_id={group_id} type=group_head_updated seq={seq}")
        }
        WsServerEvent::GroupOutboxRecordAvailable {
            group_id, seq, ..
        } => {
            format!("group_id={group_id} type=group_outbox_record_available seq={seq}")
        }
        WsServerEvent::GroupJoinRequestAvailable {
            group_id,
            request_id,
        } => {
            format!("group_id={group_id} type=group_join_request_available request_id={request_id}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tapchat_core::cli::profile::ProfileRegistry;

    #[tokio::test]
    async fn reserve_connection_skips_second_active_or_connecting_session() {
        let manager = RealtimeManager::new(Arc::new(RwLock::new(ProfileManagerInner {
            registry: ProfileRegistry::default(),
            active_profile: None,
            locked_profile_path: None,
            unlock_error: None,
        })));

        let first = manager
            .reserve_connection("device:test", "wss://example.com/ws")
            .await;
        assert!(matches!(first, ConnectionReservation::Reserved { .. }));

        let second = manager
            .reserve_connection("device:test", "wss://example.com/ws")
            .await;
        assert!(matches!(second, ConnectionReservation::Existing));

        let sessions = manager.sessions.read().await;
        let session = sessions.get("device:test").expect("session");
        assert!(session.connecting);
        assert!(!session.connected);
        assert!(!session.stale);
    }

    #[test]
    fn summarize_ws_event_omits_payload_contents() {
        let summary = summarize_ws_event(
            "device:test",
            &WsServerEvent::InboxRecordAvailable {
                device_id: "device:test".into(),
                seq: 9,
                record: Some(serde_json::json!({
                    "envelope": {
                        "inlineCiphertext": "secret",
                        "senderProof": { "value": "proof" }
                    }
                })),
            },
        );

        assert!(summary.contains("type=inbox_record_available"));
        assert!(summary.contains("seq=9"));
        assert!(!summary.contains("inlineCiphertext"));
        assert!(!summary.contains("senderProof"));
        assert!(!summary.contains("secret"));
    }

    #[test]
    fn group_head_ws_event_maps_to_core_realtime_event() {
        let event = WsServerEvent::GroupHeadUpdated {
            group_id: "group:alpha".into(),
            seq: 42,
        };

        let mapped = group_core_event_from_ws_event("group:alpha", &event);

        assert!(matches!(
            mapped,
            Some(CoreEvent::GroupRealtimeEventReceived {
                group_id,
                event: RealtimeEvent::GroupHeadUpdated {
                    group_id: event_group_id,
                    seq: 42
                }
            }) if group_id == "group:alpha" && event_group_id == "group:alpha"
        ));
    }

    #[test]
    fn group_record_ws_event_maps_to_fetch_backfill_core_event() {
        let event = WsServerEvent::GroupOutboxRecordAvailable {
            group_id: "group:alpha".into(),
            seq: 43,
            record: Some(serde_json::json!({"messageId": "ignored"})),
        };

        let mapped = group_core_event_from_ws_event("group:alpha", &event);

        assert!(matches!(
            mapped,
            Some(CoreEvent::GroupRealtimeEventReceived {
                group_id,
                event: RealtimeEvent::GroupOutboxRecordAvailable {
                    group_id: event_group_id,
                    seq: 43,
                    record: None
                }
            }) if group_id == "group:alpha" && event_group_id == "group:alpha"
        ));
    }

    #[test]
    fn non_matching_or_non_group_outbox_ws_events_do_not_drive_core() {
        let mismatched = WsServerEvent::GroupHeadUpdated {
            group_id: "group:other".into(),
            seq: 1,
        };
        let inbox = WsServerEvent::HeadUpdated {
            device_id: "device:local".into(),
            seq: 1,
        };

        assert!(group_core_event_from_ws_event("group:alpha", &mismatched).is_none());
        assert!(group_core_event_from_ws_event("group:alpha", &inbox).is_none());
    }
}

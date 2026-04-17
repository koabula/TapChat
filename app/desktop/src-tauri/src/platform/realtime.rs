use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::{connect_async_tls_with_config, WebSocketStream};
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::tungstenite::handshake::client::Request;
use tauri::{AppHandle, Emitter};

use tapchat_core::ffi_api::CoreEvent;
use tapchat_core::transport_contract::RealtimeSubscriptionRequest;

use crate::platform::profile::ProfileManagerInner;

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
    connected: bool,
    /// If true, this session is stale and should not process messages
    stale: bool,
    stop_tx: mpsc::Sender<()>,
    /// Time when connection was established
    connected_at: Option<Instant>,
}

/// Events received from WebSocket.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
#[allow(dead_code)]
pub enum WsServerEvent {
    HeadUpdated { seq: u64 },
    InboxRecordAvailable { seq: u64, record: Option<serde_json::Value> },
    MessageRequestChanged {
        sender_user_id: String,
        request_id: String,
        change: String,
    },
}

impl RealtimeManager {
    pub fn new(profile_inner: Arc<RwLock<ProfileManagerInner>>) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
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
        ConnectionId(format!("conn:{}:{}", *counter, uuid::Uuid::new_v4().simple()))
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
            endpoint,
            subscription.last_acked_seq
        );

        // Step 1: Mark any existing connection as stale and close it
        {
            let mut sessions = self.sessions.write().await;
            if let Some(existing) = sessions.get_mut(&device_id) {
                if existing.connected && !existing.stale {
                    log::info!(
                        "RealtimeManager: marking existing connection {} as stale for device_id={}",
                        existing.connection_id.as_str(),
                        device_id
                    );
                    existing.stale = true;
                    existing.connected = false;
                    // Send stop signal to old connection's read_loop
                    let _ = existing.stop_tx.send(()).await;
                }
            }
        }

        // Step 2: Wait a brief moment for old connection to stop processing
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Step 3: Build WebSocket URL
        let ws_url = self.build_ws_url(&endpoint, &device_id, subscription.last_acked_seq)?;

        log::info!("RealtimeManager: built ws_url={}", ws_url);

        // Step 4: Create stop channel for new connection
        let (stop_tx, stop_rx) = mpsc::channel::<()>(1);

        // Step 5: Generate unique connection ID
        let connection_id = self.next_connection_id().await;

        // Step 6: Create request with headers
        let mut request = Request::builder()
            .uri(&ws_url)
            .method("GET")
            .header("Host", self.extract_host(&endpoint)?)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Key", tokio_tungstenite::tungstenite::handshake::client::generate_key())
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
        let (ws_stream, _) = connect_async_tls_with_config(request, None, false, None)
            .await
            .context("websocket connect")?;

        log::info!(
            "RealtimeManager: WebSocket connected for device_id={}, connection_id={}",
            device_id,
            connection_id.as_str()
        );

        // Step 8: Emit WebSocketConnected to frontend
        if let Some(app) = &self.app_handle {
            let _ = app.emit("realtime-event", RealtimeEventPayload {
                device_id: device_id.clone(),
                event_type: "connected".to_string(),
                data: None,
            });
        }

        // Step 9: Store new session (replace any stale entry)
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(
                device_id.clone(),
                RealtimeSession {
                    device_id: device_id.clone(),
                    endpoint: endpoint.clone(),
                    connection_id: connection_id.clone(),
                    connected: true,
                    stale: false,
                    stop_tx,
                    connected_at: Some(Instant::now()),
                },
            );
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
            ).await;
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
            let _ = app.emit("realtime-event", RealtimeEventPayload {
                device_id: device_id.to_string(),
                event_type: "disconnected".to_string(),
                data: None,
            });
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
        sessions.get(device_id)
            .map(|s| s.connected && !s.stale)
            .unwrap_or(false)
    }

    /// Get connection info for diagnostics.
    pub async fn get_connection_info(&self, device_id: &str) -> Option<(String, bool, bool)> {
        let sessions = self.sessions.read().await;
        sessions.get(device_id).map(|s| {
            (s.connection_id.as_str().to_string(), s.connected, s.stale)
        })
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
        Ok(format!(
            "{}?last_acked_seq={}",
            ws_base,
            last_acked_seq
        ))
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
                            log::info!("RealtimeManager: received WS text for {}: {}", device_id, &text);
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
                                log::info!("WS event parsed successfully for {}: {:?}", device_id, event);

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
        }.to_string()
    }
}
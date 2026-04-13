use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::{connect_async_tls_with_config, WebSocketStream};
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::tungstenite::handshake::client::Request;

use tapchat_core::ffi_api::CoreEvent;
use tapchat_core::transport_contract::RealtimeSubscriptionRequest;

use crate::platform::profile::ProfileManagerInner;

/// Realtime connection manager for WebSocket subscriptions.
pub struct RealtimeManager {
    sessions: Arc<RwLock<HashMap<String, RealtimeSession>>>,
    profile_inner: Arc<RwLock<ProfileManagerInner>>,
}

struct RealtimeSession {
    device_id: String,
    endpoint: String,
    connected: bool,
    stop_tx: mpsc::Sender<()>,
}

/// Events received from WebSocket.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
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
        }
    }

    /// Open a realtime WebSocket connection.
    pub async fn open_connection(
        &self,
        subscription: RealtimeSubscriptionRequest,
    ) -> Result<Vec<CoreEvent>> {
        let device_id = subscription.device_id.clone();
        let endpoint = subscription.endpoint.clone();

        // Build WebSocket URL
        let ws_url = self.build_ws_url(&endpoint, &device_id, subscription.last_acked_seq)?;

        // Create stop channel
        let (stop_tx, stop_rx) = mpsc::channel::<()>(1);

        // Create request with headers
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

        // Connect - pass None for connector to use default TLS
        let (ws_stream, _) = connect_async_tls_with_config(request, None, false, None)
            .await
            .context("websocket connect")?;

        // Store session
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(
                device_id.clone(),
                RealtimeSession {
                    device_id: device_id.clone(),
                    endpoint: endpoint.clone(),
                    connected: true,
                    stop_tx,
                },
            );
        }

        // Spawn background task to read messages
        let sessions_clone = self.sessions.clone();
        let device_id_clone = device_id.clone();
        tokio::spawn(async move {
            Self::read_loop(ws_stream, sessions_clone, device_id_clone, stop_rx).await;
        });

        Ok(vec![CoreEvent::WebSocketConnected { device_id }])
    }

    /// Close a realtime connection.
    pub async fn close_connection(&self, device_id: &str) -> Result<Vec<CoreEvent>> {
        let mut sessions = self.sessions.write().await;

        if let Some(session) = sessions.remove(device_id) {
            // Send stop signal
            let _ = session.stop_tx.send(()).await;
        }

        Ok(vec![CoreEvent::WebSocketDisconnected {
            device_id: device_id.to_string(),
            reason: Some("closed by user".into()),
        }])
    }

    /// Check if a session is connected.
    pub async fn is_connected(&self, device_id: &str) -> bool {
        let sessions = self.sessions.read().await;
        sessions.get(device_id).map(|s| s.connected).unwrap_or(false)
    }

    fn build_ws_url(&self, endpoint: &str, device_id: &str, last_acked_seq: u64) -> Result<String> {
        // Convert HTTP endpoint to WebSocket URL
        let ws_base = if endpoint.starts_with("https://") {
            endpoint.replace("https://", "wss://")
        } else if endpoint.starts_with("http://") {
            endpoint.replace("http://", "ws://")
        } else {
            endpoint.to_string()
        };

        // Append subscription path
        let encoded_device = urlencoding::encode(device_id);
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
        mut stop_rx: mpsc::Receiver<()>,
    ) {
        let (mut write, mut read) = ws_stream.split();

        loop {
            tokio::select! {
                // Stop signal
                _ = stop_rx.recv() => {
                    let _ = write.close().await;
                    break;
                }

                // Read message
                msg = read.next() => {
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            // Parse and emit as CoreEvent
                            if let Ok(event) = serde_json::from_str::<WsServerEvent>(&text) {
                                // TODO: Emit event via Tauri
                                log::info!("WS event for {}: {:?}", device_id, event);
                            }
                        }
                        Some(Ok(Message::Ping(data))) => {
                            let _ = write.send(Message::Pong(data)).await;
                        }
                        Some(Ok(Message::Close(_))) => {
                            // Mark disconnected
                            let mut sessions = sessions.write().await;
                            if let Some(session) = sessions.get_mut(&device_id) {
                                session.connected = false;
                            }
                            break;
                        }
                        Some(Err(e)) => {
                            log::error!("WS error for {}: {:?}", device_id, e);
                            let mut sessions = sessions.write().await;
                            if let Some(session) = sessions.get_mut(&device_id) {
                                session.connected = false;
                            }
                            break;
                        }
                        None => break,
                        _ => {}
                    }
                }
            }
        }
    }
}
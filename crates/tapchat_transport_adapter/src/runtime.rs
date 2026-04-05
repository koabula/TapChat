use std::net::TcpListener;
use std::path::Path;
use std::process::Stdio;

use anyhow::{Context, Result, anyhow, bail};
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use tapchat_core::model::{
    CURRENT_MODEL_VERSION, DeploymentBundle, DeviceRuntimeAuth, IdentityBundle,
};
use tapchat_core::transport_contract::{FetchMessagesResult, GetHeadResult};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::{Duration, Instant, sleep};

use crate::util::{sign_hmac_token, to_camel_case_json_string, to_snake_case_json_string};

#[derive(Debug, Clone, Deserialize)]
pub struct RuntimeMessageRequest {
    pub request_id: String,
    pub recipient_device_id: String,
    pub sender_user_id: String,
    pub first_seen_at: u64,
    pub last_seen_at: u64,
    pub message_count: u64,
    pub last_message_id: String,
    pub last_conversation_id: String,
}

#[derive(Debug, Clone, Deserialize)]
struct RuntimeMessageRequestList {
    pub requests: Vec<RuntimeMessageRequest>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuntimeAllowlistDocument {
    pub allowed_sender_user_ids: Vec<String>,
    pub rejected_sender_user_ids: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct CloudflareRuntimeOptions {
    pub max_inline_bytes: Option<u64>,
    pub retention_days: Option<u64>,
    pub rate_limit_per_minute: Option<u64>,
    pub rate_limit_per_hour: Option<u64>,
}

pub struct CloudflareRuntimeHandle {
    child: Child,
    _temp_dir: TempDir,
    client: Client,
    base_url: String,
    websocket_base_url: String,
    bootstrap_secret: String,
}

impl CloudflareRuntimeHandle {
    pub async fn start(workspace_root: impl AsRef<Path>) -> Result<Self> {
        Self::start_with_options(workspace_root, CloudflareRuntimeOptions::default()).await
    }

    pub async fn start_with_options(
        workspace_root: impl AsRef<Path>,
        options: CloudflareRuntimeOptions,
    ) -> Result<Self> {
        let workspace_root = workspace_root.as_ref();
        let service_root = workspace_root.join("services").join("cloudflare");
        let temp_dir = tempfile::tempdir_in(workspace_root).context("create transport temp dir")?;
        let port = reserve_port()?;
        let base_url = format!("http://127.0.0.1:{port}");
        let websocket_base_url = format!("ws://127.0.0.1:{port}");
        let bootstrap_secret = format!("transport-bootstrap-{port}");
        let sharing_secret = format!("transport-sharing-{port}");

        let mut child = Command::new("node");
        child
            .arg("scripts/transport-runtime.mjs")
            .current_dir(&service_root)
            .env("TAPCHAT_TRANSPORT_PORT", port.to_string())
            .env("TAPCHAT_TRANSPORT_PERSIST_TO", temp_dir.path())
            .env("TAPCHAT_TRANSPORT_BOOTSTRAP_SECRET", &bootstrap_secret)
            .env("TAPCHAT_TRANSPORT_SHARING_SECRET", &sharing_secret)
            .env_remove("MAX_INLINE_BYTES")
            .env_remove("RETENTION_DAYS")
            .env_remove("RATE_LIMIT_PER_MINUTE")
            .env_remove("RATE_LIMIT_PER_HOUR")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .stdin(Stdio::piped());
        if let Some(value) = options.max_inline_bytes {
            child.env("MAX_INLINE_BYTES", value.to_string());
        }
        if let Some(value) = options.retention_days {
            child.env("RETENTION_DAYS", value.to_string());
        }
        if let Some(value) = options.rate_limit_per_minute {
            child.env("RATE_LIMIT_PER_MINUTE", value.to_string());
        }
        if let Some(value) = options.rate_limit_per_hour {
            child.env("RATE_LIMIT_PER_HOUR", value.to_string());
        }

        let mut child = child
            .spawn()
            .context("spawn cloudflare transport runtime")?;
        let stdout = child.stdout.take().context("runtime stdout unavailable")?;
        let mut lines = BufReader::new(stdout).lines();
        let line = tokio::time::timeout(Duration::from_secs(30), lines.next_line())
            .await
            .context("timed out waiting for runtime metadata")??
            .context("runtime exited before emitting metadata")?;
        let metadata: serde_json::Value =
            serde_json::from_str(&line).context("parse runtime metadata")?;
        let announced_base_url = metadata
            .get("baseUrl")
            .and_then(|value| value.as_str())
            .unwrap_or(&base_url)
            .to_string();
        let announced_ws_base_url = metadata
            .get("websocketBaseUrl")
            .and_then(|value| value.as_str())
            .unwrap_or(&websocket_base_url)
            .to_string();

        let handle = Self {
            child,
            _temp_dir: temp_dir,
            client: Client::builder().build().context("build reqwest client")?,
            base_url: announced_base_url,
            websocket_base_url: announced_ws_base_url,
            bootstrap_secret,
        };
        handle.wait_until_ready().await?;
        Ok(handle)
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn websocket_base_url(&self) -> &str {
        &self.websocket_base_url
    }

    pub async fn bootstrap_device_bundle(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<DeploymentBundle> {
        let token = self.bootstrap_token(user_id, device_id)?;
        let response = self
            .client
            .post(format!("{}/v1/bootstrap/device", self.base_url))
            .header("Authorization", format!("Bearer {token}"))
            .json(&json!({
                "version": CURRENT_MODEL_VERSION,
                "userId": user_id,
                "deviceId": device_id,
            }))
            .send()
            .await
            .context("bootstrap request failed")?;
        if !response.status().is_success() {
            bail!("bootstrap failed with status {}", response.status());
        }
        let body = response.text().await.context("read bootstrap response")?;
        Ok(serde_json::from_str(&to_snake_case_json_string(&body)?)?)
    }

    pub async fn put_identity_bundle(
        &self,
        auth: &DeviceRuntimeAuth,
        bundle: &IdentityBundle,
    ) -> Result<()> {
        let reference = bundle
            .identity_bundle_ref
            .clone()
            .ok_or_else(|| anyhow!("identity bundle missing identity_bundle_ref"))?
            .replace("{userId}", &bundle.user_id);
        let body = serde_json::to_string(bundle)?;
        let response = self
            .client
            .put(reference)
            .header("Authorization", format!("Bearer {}", auth.token))
            .header("Content-Type", "application/json")
            .body(to_camel_case_json_string(&body)?)
            .send()
            .await
            .context("put identity bundle")?;
        if !response.status().is_success() {
            bail!(
                "put identity bundle failed with status {}",
                response.status()
            );
        }
        Ok(())
    }

    pub async fn put_allowlist(
        &self,
        auth: &DeviceRuntimeAuth,
        allowed_sender_user_ids: &[String],
    ) -> Result<()> {
        let response = self
            .client
            .put(format!(
                "{}/v1/inbox/{}/allowlist",
                self.base_url,
                urlencoding::encode(&auth.device_id)
            ))
            .header("Authorization", format!("Bearer {}", auth.token))
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&json!({
                "allowedSenderUserIds": allowed_sender_user_ids,
                "rejectedSenderUserIds": []
            }))?)
            .send()
            .await
            .context("put allowlist")?;
        if !response.status().is_success() {
            bail!("put allowlist failed with status {}", response.status());
        }
        Ok(())
    }

    pub async fn get_allowlist(
        &self,
        auth: &DeviceRuntimeAuth,
    ) -> Result<RuntimeAllowlistDocument> {
        let response = self
            .client
            .get(format!(
                "{}/v1/inbox/{}/allowlist",
                self.base_url,
                urlencoding::encode(&auth.device_id)
            ))
            .header("Authorization", format!("Bearer {}", auth.token))
            .send()
            .await
            .context("get allowlist")?;
        if !response.status().is_success() {
            bail!("get allowlist failed with status {}", response.status());
        }
        let body = response.text().await?;
        let normalized = to_snake_case_json_string(&body)?;
        Ok(serde_json::from_str::<RuntimeAllowlistDocument>(
            &normalized,
        )?)
    }

    pub async fn list_message_requests(
        &self,
        auth: &DeviceRuntimeAuth,
    ) -> Result<Vec<RuntimeMessageRequest>> {
        let response = self
            .client
            .get(format!(
                "{}/v1/inbox/{}/message-requests",
                self.base_url,
                urlencoding::encode(&auth.device_id)
            ))
            .header("Authorization", format!("Bearer {}", auth.token))
            .send()
            .await
            .context("list message requests")?;
        if !response.status().is_success() {
            bail!(
                "list message requests failed with status {}",
                response.status()
            );
        }
        let body = response.text().await?;
        let normalized = to_snake_case_json_string(&body)?;
        Ok(serde_json::from_str::<RuntimeMessageRequestList>(&normalized)?.requests)
    }

    pub async fn accept_message_request(
        &self,
        auth: &DeviceRuntimeAuth,
        request_id: &str,
    ) -> Result<()> {
        let response = self
            .client
            .post(format!(
                "{}/v1/inbox/{}/message-requests/{}/accept",
                self.base_url,
                urlencoding::encode(&auth.device_id),
                urlencoding::encode(request_id)
            ))
            .header("Authorization", format!("Bearer {}", auth.token))
            .send()
            .await
            .context("accept message request")?;
        if !response.status().is_success() {
            bail!(
                "accept message request failed with status {}",
                response.status()
            );
        }
        Ok(())
    }

    pub async fn reject_message_request(
        &self,
        auth: &DeviceRuntimeAuth,
        request_id: &str,
    ) -> Result<()> {
        let response = self
            .client
            .post(format!(
                "{}/v1/inbox/{}/message-requests/{}/reject",
                self.base_url,
                urlencoding::encode(&auth.device_id),
                urlencoding::encode(request_id)
            ))
            .header("Authorization", format!("Bearer {}", auth.token))
            .send()
            .await
            .context("reject message request")?;
        if !response.status().is_success() {
            bail!(
                "reject message request failed with status {}",
                response.status()
            );
        }
        Ok(())
    }

    pub async fn get_identity_bundle(&self, user_id: &str) -> Result<IdentityBundle> {
        let response = self
            .client
            .get(format!(
                "{}/v1/shared-state/{}/identity-bundle",
                self.base_url,
                urlencoding::encode(user_id)
            ))
            .send()
            .await
            .context("get identity bundle request")?;
        if !response.status().is_success() {
            bail!(
                "get identity bundle failed with status {}",
                response.status()
            );
        }
        let body = response.text().await?;
        Ok(serde_json::from_str(&to_snake_case_json_string(&body)?)?)
    }

    pub async fn get_head(
        &self,
        auth: &DeviceRuntimeAuth,
        device_id: &str,
    ) -> Result<GetHeadResult> {
        let response = self
            .client
            .get(format!(
                "{}/v1/inbox/{}/head",
                self.base_url,
                urlencoding::encode(device_id)
            ))
            .header("Authorization", format!("Bearer {}", auth.token))
            .send()
            .await
            .context("get head request")?;
        if !response.status().is_success() {
            bail!("get head failed with status {}", response.status());
        }
        let body = response.text().await?;
        Ok(serde_json::from_str(&to_snake_case_json_string(&body)?)?)
    }

    pub async fn fetch_messages(
        &self,
        auth: &DeviceRuntimeAuth,
        device_id: &str,
        from_seq: u64,
        limit: u64,
    ) -> Result<FetchMessagesResult> {
        let response = self
            .client
            .get(format!(
                "{}/v1/inbox/{}/messages?fromSeq={from_seq}&limit={limit}",
                self.base_url,
                urlencoding::encode(device_id)
            ))
            .header("Authorization", format!("Bearer {}", auth.token))
            .send()
            .await
            .context("fetch messages request")?;
        if !response.status().is_success() {
            bail!("fetch messages failed with status {}", response.status());
        }
        let body = response.text().await?;
        Ok(serde_json::from_str(&to_snake_case_json_string(&body)?)?)
    }

    pub async fn ack_messages(
        &self,
        auth: &DeviceRuntimeAuth,
        device_id: &str,
        ack_seq: u64,
    ) -> Result<()> {
        let response = self
            .client
            .post(format!(
                "{}/v1/inbox/{}/ack",
                self.base_url,
                urlencoding::encode(device_id)
            ))
            .header("Authorization", format!("Bearer {}", auth.token))
            .json(&json!({ "ackSeq": ack_seq }))
            .send()
            .await
            .context("ack messages request")?;
        if !response.status().is_success() {
            bail!("ack messages failed with status {}", response.status());
        }
        Ok(())
    }

    async fn wait_until_ready(&self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let response = self
                .client
                .get(format!("{}/v1/deployment-bundle", self.base_url))
                .send()
                .await;
            if let Ok(response) = response {
                if response.status().is_success() {
                    return Ok(());
                }
            }
            if Instant::now() >= deadline {
                bail!("cloudflare runtime did not become ready in time");
            }
            sleep(Duration::from_millis(200)).await;
        }
    }

    fn bootstrap_token(&self, user_id: &str, device_id: &str) -> Result<String> {
        sign_hmac_token(
            &self.bootstrap_secret,
            &json!({
                "version": CURRENT_MODEL_VERSION,
                "service": "bootstrap",
                "userId": user_id,
                "deviceId": device_id,
                "operations": ["issue_device_bundle"],
                "expiresAt": 4_102_444_800_000u64,
            }),
        )
    }
}

impl Drop for CloudflareRuntimeHandle {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

fn reserve_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("bind random port")?;
    let port = listener.local_addr().context("get local addr")?.port();
    drop(listener);
    Ok(port)
}

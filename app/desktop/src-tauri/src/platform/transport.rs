use std::sync::Arc;

use anyhow::{Context, Result};
use reqwest::Client;
use tokio::sync::RwLock;

use tapchat_core::ffi_api::{CoreEvent, HttpMethod, HttpRequestEffect};
use tapchat_core::model::{Ack, IdentityBundle, InboxRecord};
use tapchat_core::transport_contract::{
    AckRequest, AckResult,
    AppendEnvelopeRequest, AppendEnvelopeResult,
    FetchAllowlistRequest,
    FetchIdentityBundleRequest,
    FetchMessageRequestsRequest,
    GetHeadResult,
    MessageRequestActionRequest, MessageRequestActionResult,
    PrepareBlobUploadRequest, PrepareBlobUploadResult,
    PublishSharedStateRequest,
    ReplaceAllowlistRequest,
    RealtimeSubscriptionRequest,
};

use crate::platform::profile::ProfileManagerInner;

/// HTTP transport implementation for desktop app.
/// Executes HTTP requests to the Cloudflare backend.
#[derive(Clone)]
pub struct DesktopTransport {
    client: Client,
    profile_inner: Arc<RwLock<ProfileManagerInner>>,
}

impl DesktopTransport {
    pub fn new(profile_inner: Arc<RwLock<ProfileManagerInner>>) -> Self {
        Self {
            client: Client::new(),
            profile_inner,
        }
    }

    /// Get the base URL for API calls.
    async fn get_base_url(&self) -> Option<String> {
        let pm = self.profile_inner.read().await;
        // Access the active profile's runtime metadata
        pm.active_profile
            .as_ref()
            .and_then(|p| p.load_runtime_metadata().ok())
            .and_then(|r| r.base_url)
    }

    /// Execute a generic HTTP request.
    pub async fn execute_http_request(
        &self,
        request: HttpRequestEffect,
    ) -> Result<Vec<CoreEvent>> {
        let method = match request.method {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
            HttpMethod::Put => reqwest::Method::PUT,
            HttpMethod::Delete => reqwest::Method::DELETE,
        };

        log::info!("HTTP request: {} {}", method, request.url);

        let mut builder = self.client.request(method.clone(), &request.url);
        for (key, value) in &request.headers {
            builder = builder.header(key, value);
        }
        if let Some(body) = &request.body {
            builder = builder.body(body.clone());
        }

        match builder.send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                log::info!("HTTP response: {} {} - status {}", method, request.url, status);
                let body = response.text().await.ok();
                Ok(vec![CoreEvent::HttpResponseReceived {
                    request_id: request.request_id,
                    status,
                    body,
                }])
            }
            Err(e) => {
                let retryable = e.is_timeout() || e.is_connect();
                log::warn!(
                    "HTTP request failed: {} {} - error: {} (retryable: {})",
                    method,
                    request.url,
                    e,
                    retryable
                );
                Ok(vec![CoreEvent::HttpRequestFailed {
                    request_id: request.request_id,
                    retryable,
                    detail: Some(e.to_string()),
                }])
            }
        }
    }

    /// Append an envelope to the inbox.
    pub async fn append_envelope(
        &self,
        request: AppendEnvelopeRequest,
    ) -> Result<AppendEnvelopeResult> {
        let base_url = self.get_base_url().await
            .ok_or_else(|| anyhow::anyhow!("no base URL configured"))?;

        let url = format!(
            "{}/v1/inbox/{}/messages",
            base_url,
            urlencoding::encode(&request.recipient_device_id)
        );

        let body = serde_json::to_string(&request)?;
        let response = self.client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .context("append envelope request")?;

        let status = response.status();
        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_default();
            anyhow::bail!("append failed: {} - {}", status, error_body);
        }

        response.json().await.context("parse append result")
    }

    /// Fetch messages from inbox.
    pub async fn fetch_messages(
        &self,
        device_id: &str,
        from_seq: u64,
        limit: u64,
    ) -> Result<(u64, Vec<InboxRecord>)> {
        let base_url = self.get_base_url().await
            .ok_or_else(|| anyhow::anyhow!("no base URL configured"))?;

        let url = format!(
            "{}/v1/inbox/{}/messages?fromSeq={}&limit={}",
            base_url,
            urlencoding::encode(device_id),
            from_seq,
            limit
        );

        let response = self.client
            .get(&url)
            .send()
            .await
            .context("fetch messages request")?;

        let status = response.status();
        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_default();
            anyhow::bail!("fetch failed: {} - {}", status, error_body);
        }

        let result: FetchMessagesResult = response.json().await.context("parse fetch result")?;
        Ok((result.to_seq, result.records))
    }

    /// Acknowledge messages.
    pub async fn ack(&self, device_id: &str, ack: Ack) -> Result<AckResult> {
        let base_url = self.get_base_url().await
            .ok_or_else(|| anyhow::anyhow!("no base URL configured"))?;

        let url = format!(
            "{}/v1/inbox/{}/ack",
            base_url,
            urlencoding::encode(device_id)
        );

        let body = serde_json::to_string(&AckRequest { ack })?;
        let response = self.client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .context("ack request")?;

        let status = response.status();
        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_default();
            anyhow::bail!("ack failed: {} - {}", status, error_body);
        }

        response.json().await.context("parse ack result")
    }

    /// Get inbox head sequence.
    pub async fn get_head(&self, device_id: &str) -> Result<u64> {
        let base_url = self.get_base_url().await
            .ok_or_else(|| anyhow::anyhow!("no base URL configured"))?;

        let url = format!(
            "{}/v1/inbox/{}/head",
            base_url,
            urlencoding::encode(device_id)
        );

        let response = self.client
            .get(&url)
            .send()
            .await
            .context("get head request")?;

        let status = response.status();
        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_default();
            anyhow::bail!("get head failed: {} - {}", status, error_body);
        }

        let result: GetHeadResult = response.json().await.context("parse head result")?;
        Ok(result.head_seq)
    }

    /// Fetch identity bundle from URL.
    pub async fn fetch_identity_bundle(
        &self,
        request: FetchIdentityBundleRequest,
    ) -> Result<IdentityBundle> {
        // The share URL points to the bundle endpoint
        let response = self.client
            .get(&request.user_id) // user_id is actually the share URL in this context
            .send()
            .await
            .context("fetch identity bundle")?;

        let status = response.status();
        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_default();
            anyhow::bail!("fetch bundle failed: {} - {}", status, error_body);
        }

        response.json().await.context("parse identity bundle")
    }

    /// Prepare blob upload.
    pub async fn prepare_blob_upload(
        &self,
        request: PrepareBlobUploadRequest,
    ) -> Result<PrepareBlobUploadResult> {
        let base_url = self.get_base_url().await
            .ok_or_else(|| anyhow::anyhow!("no base URL configured"))?;

        let url = format!("{}/v1/storage/prepare", base_url);
        let body = serde_json::to_string(&request)?;

        let response = self.client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .context("prepare blob upload")?;

        let status = response.status();
        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_default();
            anyhow::bail!("prepare upload failed: {} - {}", status, error_body);
        }

        response.json().await.context("parse prepare result")
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
struct FetchMessagesResult {
    to_seq: u64,
    records: Vec<InboxRecord>,
}
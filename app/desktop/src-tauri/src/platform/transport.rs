use std::sync::Arc;

use anyhow::{Context, Result};
use reqwest::Client;
use tokio::sync::RwLock;

use tapchat_core::ffi_api::{CoreEvent, HttpMethod, HttpRequestEffect};
use tapchat_core::model::{Ack, IdentityBundle, InboxRecord};
use tapchat_core::transport_contract::{
    AckRequest, AckResult,
    AppendEnvelopeRequest, AppendEnvelopeResult,
    FetchIdentityBundleRequest,
    GetHeadResult,
    PrepareBlobUploadRequest, PrepareBlobUploadResult,
};
use tapchat_core::cli::util::{to_camel_case_json_string, to_snake_case_json_string};

use crate::platform::profile::ProfileManagerInner;
use crate::timetest;

/// Helper to check if a string looks like JSON
fn looks_like_json(s: &str) -> bool {
    s.trim().starts_with('{') || s.trim().starts_with('[')
}

fn sanitize_url_for_log(raw: &str) -> String {
    let Ok(url) = url::Url::parse(raw) else {
        return raw.split('?').next().unwrap_or(raw).to_string();
    };

    let mut path = url.path().to_string();
    if let Some(prefix) = path.strip_prefix("/v1/contact-share/") {
        if !prefix.is_empty() {
            path = "/v1/contact-share/<redacted>".into();
        }
    }

    let mut sanitized = format!("{}://{}", url.scheme(), url.host_str().unwrap_or_default());
    if let Some(port) = url.port() {
        sanitized.push(':');
        sanitized.push_str(&port.to_string());
    }
    sanitized.push_str(&path);

    if url.query().is_some() {
        sanitized.push_str("?<redacted>");
    }

    sanitized
}

/// HTTP transport implementation for desktop app.
/// Executes HTTP requests to the Cloudflare backend.
#[derive(Clone)]
pub struct DesktopTransport {
    client: Client,
    pub profile_inner: Arc<RwLock<ProfileManagerInner>>,
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
    /// Converts snake_case JSON (from CoreEngine) to camelCase (for server),
    /// and converts camelCase response back to snake_case.
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

        log::info!("HTTP request: {} {}", method, sanitize_url_for_log(&request.url));

        let start = std::time::Instant::now();
        let url_snapshot = request.url.clone();

        let mut builder = self.client.request(method.clone(), &request.url);
        for (key, value) in &request.headers {
            // Convert X-Tapchat-Capability header value to camelCase
            let header_value = if key.eq_ignore_ascii_case("X-Tapchat-Capability") {
                to_camel_case_json_string(value).unwrap_or_else(|_| value.clone())
            } else {
                value.clone()
            };
            builder = builder.header(key, header_value);
        }
        if let Some(body) = &request.body {
            // Convert JSON body to camelCase for server
            let converted = if looks_like_json(body) {
                to_camel_case_json_string(body).unwrap_or_else(|_| body.clone())
            } else {
                body.clone()
            };
            builder = builder.body(converted);
        }

        match builder.send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                let content_type = response
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                let elapsed_ms = start.elapsed().as_millis();
                log::info!(
                    "HTTP response: {} {} - status {}",
                    method,
                    sanitize_url_for_log(&url_snapshot),
                    status
                );

                timetest!("http_req method={} url={} status={} elapsed_ms={} ts={}",
                    method, sanitize_url_for_log(&url_snapshot), status, elapsed_ms, crate::ts_ms());

                let body = response
                    .text()
                    .await
                    .ok()
                    .filter(|value| !value.is_empty())
                    .map(|value| {
                        // Convert camelCase response back to snake_case for CoreEngine
                        if content_type.contains("application/json") {
                            to_snake_case_json_string(&value).unwrap_or(value)
                        } else {
                            value
                        }
                    });

                Ok(vec![CoreEvent::HttpResponseReceived {
                    request_id: request.request_id,
                    status,
                    body,
                }])
            }
            Err(e) => {
                let retryable = e.is_timeout() || e.is_connect();
                let elapsed_ms = start.elapsed().as_millis();
                log::warn!(
                    "HTTP request failed: {} {} - error: {} (retryable: {})",
                    method,
                    sanitize_url_for_log(&url_snapshot),
                    e,
                    retryable
                );
                timetest!("http_req method={} url={} error=1 retryable={} elapsed_ms={} ts={}",
                    method, sanitize_url_for_log(&url_snapshot), retryable, elapsed_ms, crate::ts_ms());
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
        let start = std::time::Instant::now();
        let msg_id = request.envelope.message_id.clone();
        let base_url = self.get_base_url().await
            .ok_or_else(|| anyhow::anyhow!("no base URL configured"))?;

        let url = format!(
            "{}/v1/inbox/{}/messages",
            base_url,
            urlencoding::encode(&request.recipient_device_id)
        );

        timetest!("append_begin msg_id={} ts={}", msg_id, crate::ts_ms());

        let body = serde_json::to_string(&request)?;
        let response = self.client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .context("append envelope request")?;

        let status = response.status();
        let elapsed_ms = start.elapsed().as_millis();
        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_default();
            timetest!("append_done msg_id={} status={} error=1 elapsed_ms={} ts={}", msg_id, status, elapsed_ms, crate::ts_ms());
            anyhow::bail!("append failed: {} - {}", status, error_body);
        }

        let result: AppendEnvelopeResult = response.json().await.context("parse append result")?;
        timetest!("append_done msg_id={} seq={} status={} elapsed_ms={} ts={}",
            msg_id, result.seq, status, elapsed_ms, crate::ts_ms());
        Ok(result)
    }

    /// Fetch messages from inbox.
    pub async fn fetch_messages(
        &self,
        device_id: &str,
        from_seq: u64,
        limit: u64,
    ) -> Result<(u64, Vec<InboxRecord>)> {
        let start = std::time::Instant::now();
        let base_url = self.get_base_url().await
            .ok_or_else(|| anyhow::anyhow!("no base URL configured"))?;

        let url = format!(
            "{}/v1/inbox/{}/messages?fromSeq={}&limit={}",
            base_url,
            urlencoding::encode(device_id),
            from_seq,
            limit
        );

        timetest!("fetch_begin device_id={} from_seq={} limit={} ts={}", device_id, from_seq, limit, crate::ts_ms());

        let response = self.client
            .get(&url)
            .send()
            .await
            .context("fetch messages request")?;

        let status = response.status();
        let elapsed_ms = start.elapsed().as_millis();
        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_default();
            timetest!("fetch_done device_id={} status={} error=1 elapsed_ms={} ts={}", device_id, status, elapsed_ms, crate::ts_ms());
            anyhow::bail!("fetch failed: {} - {}", status, error_body);
        }

        let result: FetchMessagesResult = response.json().await.context("parse fetch result")?;
        let record_count = result.records.len();
        timetest!("fetch_done device_id={} from_seq={} to_seq={} records={} elapsed_ms={} ts={}",
            device_id, from_seq, result.to_seq, record_count, elapsed_ms, crate::ts_ms());
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
        let start = std::time::Instant::now();
        let base_url = self.get_base_url().await
            .ok_or_else(|| anyhow::anyhow!("no base URL configured"))?;

        let url = format!(
            "{}/v1/inbox/{}/head",
            base_url,
            urlencoding::encode(device_id)
        );

        timetest!("get_head_begin device_id={} ts={}", device_id, crate::ts_ms());

        let response = self.client
            .get(&url)
            .send()
            .await
            .context("get head request")?;

        let status = response.status();
        let elapsed_ms = start.elapsed().as_millis();
        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_default();
            timetest!("get_head_done device_id={} status={} error=1 elapsed_ms={} ts={}", device_id, status, elapsed_ms, crate::ts_ms());
            anyhow::bail!("get head failed: {} - {}", status, error_body);
        }

        let result: GetHeadResult = response.json().await.context("parse head result")?;
        timetest!("get_head_done device_id={} head_seq={} elapsed_ms={} ts={}",
            device_id, result.head_seq, elapsed_ms, crate::ts_ms());
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

        let url = format!("{}/v1/storage/prepare-upload", base_url);

        // Serialize to snake_case JSON, then convert to camelCase for server
        let snake_case_body = serde_json::to_string(&request)?;
        let body = to_camel_case_json_string(&snake_case_body)
            .context("convert prepare upload request to camelCase")?;

        let mut builder = self.client
            .post(&url)
            .header("Content-Type", "application/json");

        // Add authorization headers from the request
        for (key, value) in &request.headers {
            builder = builder.header(key, value);
        }

        let response = builder
            .body(body)
            .send()
            .await
            .context("prepare blob upload")?;

        let status = response.status();
        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_default();
            anyhow::bail!("prepare upload failed: {} - {}", status, error_body);
        }

        // Convert camelCase response back to snake_case for Rust
        let response_text = response.text().await.context("read prepare result")?;
        let snake_case_response = to_snake_case_json_string(&response_text)
            .context("convert prepare result to snake_case")?;
        let result: PrepareBlobUploadResult = serde_json::from_str(&snake_case_response)
            .context("parse prepare result")?;

        Ok(result)
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
struct FetchMessagesResult {
    to_seq: u64,
    records: Vec<InboxRecord>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_url_for_log_redacts_tokens_and_queries() {
        let sanitized = sanitize_url_for_log(
            "https://example.com/v1/contact-share/secret-token?last_acked_seq=3",
        );

        assert_eq!(
            sanitized,
            "https://example.com/v1/contact-share/<redacted>?<redacted>"
        );
        assert!(!sanitized.contains("secret-token"));
        assert!(!sanitized.contains("last_acked_seq=3"));
    }
}

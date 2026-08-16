use std::sync::Arc;

use anyhow::{Context, Result};
use reqwest::Client;
use tokio::sync::RwLock;

use tapchat_core::cli::util::{to_camel_case_json_string, to_snake_case_json_string};
use tapchat_core::ffi_api::{CoreEvent, HttpMethod, HttpRequestEffect};
use tapchat_core::model::{Ack, IdentityBundle, InboxRecord};
use tapchat_core::transport_contract::{
    AckRequest, AckResult, AppendEnvelopeRequest, AppendEnvelopeResult, FetchIdentityBundleRequest,
    GetHeadResult, PrepareBlobUploadRequest, PrepareBlobUploadResult,
};

use crate::platform::log_sanitize::{
    redact_id, sanitize_url_for_log as sanitize_shared_url_for_log,
};
use crate::platform::profile::ProfileManagerInner;
use crate::timetest;

pub fn build_desktop_http_client() -> Client {
    Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(45))
        .pool_idle_timeout(std::time::Duration::from_secs(60))
        .build()
        .unwrap_or_else(|_| {
            log::warn!("Failed to build timeout-configured desktop HTTP client");
            Client::new()
        })
}

/// Helper to check if a string looks like JSON
fn looks_like_json(s: &str) -> bool {
    s.trim().starts_with('{') || s.trim().starts_with('[')
}

fn sanitize_url_for_log(raw: &str) -> String {
    sanitize_shared_url_for_log(raw)
}

fn request_error_class(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else if error.is_body() {
        "body"
    } else if error.is_decode() {
        "decode"
    } else if error.is_builder() {
        "builder"
    } else if error.is_redirect() {
        "redirect"
    } else if error.is_request() {
        "request"
    } else {
        "transport"
    }
}

fn request_error_is_retryable(error: &reqwest::Error) -> bool {
    !error.is_builder() && !error.is_redirect()
}

/// HTTP transport implementation for desktop app.
/// Executes HTTP requests to the Cloudflare backend.
#[derive(Clone)]
pub struct DesktopTransport {
    client: Client,
    pub profile_inner: Arc<RwLock<ProfileManagerInner>>,
}

impl DesktopTransport {
    pub fn new(profile_inner: Arc<RwLock<ProfileManagerInner>>, client: Client) -> Self {
        Self {
            client,
            profile_inner,
        }
    }

    /// Get the base URL for API calls.
    async fn get_base_url(&self) -> Option<String> {
        let pm = self.profile_inner.read().await;
        let profile = pm.active_profile.as_ref()?;
        profile
            .load_runtime_metadata()
            .ok()
            .and_then(|runtime| runtime.base_url.or(runtime.public_base_url))
            .or_else(|| {
                profile
                    .load_snapshot()
                    .ok()
                    .and_then(|snapshot| snapshot.deployment)
                    .map(|deployment| deployment.deployment_bundle.inbox_http_endpoint)
            })
    }

    /// Execute a generic HTTP request.
    /// Converts snake_case JSON (from CoreEngine) to camelCase (for server),
    /// and converts camelCase response back to snake_case.
    pub async fn execute_http_request(&self, request: HttpRequestEffect) -> Result<Vec<CoreEvent>> {
        let method = match request.method {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
            HttpMethod::Put => reqwest::Method::PUT,
            HttpMethod::Delete => reqwest::Method::DELETE,
        };

        log::info!(
            "HTTP request: {} {}",
            method,
            sanitize_url_for_log(&request.url)
        );

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

                timetest!(
                    "http_req method={} url={} status={} elapsed_ms={} ts={}",
                    method,
                    sanitize_url_for_log(&url_snapshot),
                    status,
                    elapsed_ms,
                    crate::ts_ms()
                );

                let response_body = match response.text().await {
                    Ok(body) => body,
                    Err(error) => {
                        let error_class = request_error_class(&error);
                        log::warn!(
                            "HTTP response body failed: {} {} - error_class={} retryable=true",
                            method,
                            sanitize_url_for_log(&url_snapshot),
                            error_class
                        );
                        return Ok(vec![CoreEvent::HttpRequestFailed {
                            request_id: request.request_id,
                            failure: tapchat_core::AppErrorV1::from_registered_code(
                                "temporary_failure",
                            ),
                        }]);
                    }
                };
                let body = (!response_body.is_empty()).then(|| {
                    // Convert camelCase response back to snake_case for CoreEngine
                    if content_type.contains("application/json") {
                        to_snake_case_json_string(&response_body).unwrap_or(response_body)
                    } else {
                        response_body
                    }
                });

                Ok(vec![CoreEvent::HttpResponseReceived {
                    request_id: request.request_id,
                    status,
                    body,
                }])
            }
            Err(e) => {
                let retryable = request_error_is_retryable(&e);
                let error_class = request_error_class(&e);
                let elapsed_ms = start.elapsed().as_millis();
                log::warn!(
                    "HTTP request failed: {} {} - error_class={} (retryable: {})",
                    method,
                    sanitize_url_for_log(&url_snapshot),
                    error_class,
                    retryable
                );
                timetest!(
                    "http_req method={} url={} error=1 retryable={} elapsed_ms={} ts={}",
                    method,
                    sanitize_url_for_log(&url_snapshot),
                    retryable,
                    elapsed_ms,
                    crate::ts_ms()
                );
                Ok(vec![CoreEvent::HttpRequestFailed {
                    request_id: request.request_id,
                    failure: tapchat_core::AppErrorV1::new(
                        "network_unavailable",
                        tapchat_core::ErrorDomain::Transport,
                        retryable,
                    ),
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
        let msg_ref = redact_id("msg", &msg_id);
        let base_url = self
            .get_base_url()
            .await
            .ok_or_else(|| anyhow::anyhow!("no base URL configured"))?;

        let url = format!(
            "{}/v1/inbox/{}/messages",
            base_url,
            urlencoding::encode(&request.recipient_device_id)
        );

        timetest!("append_begin msg_id={} ts={}", msg_ref, crate::ts_ms());

        let body = serde_json::to_string(&request)?;
        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .context("append envelope request")?;

        let status = response.status();
        let elapsed_ms = start.elapsed().as_millis();
        if !status.is_success() {
            timetest!(
                "append_done msg_id={} status={} error=1 elapsed_ms={} ts={}",
                msg_ref,
                status,
                elapsed_ms,
                crate::ts_ms()
            );
            anyhow::bail!("append failed with status {}", status);
        }

        let result: AppendEnvelopeResult = response.json().await.context("parse append result")?;
        timetest!(
            "append_done msg_id={} seq={} status={} elapsed_ms={} ts={}",
            msg_ref,
            result.seq,
            status,
            elapsed_ms,
            crate::ts_ms()
        );
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
        let device_ref = redact_id("device", device_id);
        let base_url = self
            .get_base_url()
            .await
            .ok_or_else(|| anyhow::anyhow!("no base URL configured"))?;

        let url = format!(
            "{}/v1/inbox/{}/messages?fromSeq={}&limit={}",
            base_url,
            urlencoding::encode(device_id),
            from_seq,
            limit
        );

        timetest!(
            "fetch_begin device_id={} from_seq={} limit={} ts={}",
            device_ref,
            from_seq,
            limit,
            crate::ts_ms()
        );

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("fetch messages request")?;

        let status = response.status();
        let elapsed_ms = start.elapsed().as_millis();
        if !status.is_success() {
            timetest!(
                "fetch_done device_id={} status={} error=1 elapsed_ms={} ts={}",
                device_ref,
                status,
                elapsed_ms,
                crate::ts_ms()
            );
            anyhow::bail!("fetch failed with status {}", status);
        }

        let result: FetchMessagesResult = response.json().await.context("parse fetch result")?;
        let record_count = result.records.len();
        timetest!(
            "fetch_done device_id={} from_seq={} to_seq={} records={} elapsed_ms={} ts={}",
            device_ref,
            from_seq,
            result.to_seq,
            record_count,
            elapsed_ms,
            crate::ts_ms()
        );
        Ok((result.to_seq, result.records))
    }

    /// Acknowledge messages.
    pub async fn ack(&self, device_id: &str, ack: Ack) -> Result<AckResult> {
        let base_url = self
            .get_base_url()
            .await
            .ok_or_else(|| anyhow::anyhow!("no base URL configured"))?;

        let url = format!(
            "{}/v1/inbox/{}/ack",
            base_url,
            urlencoding::encode(device_id)
        );

        let body = serde_json::to_string(&AckRequest { ack })?;
        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .context("ack request")?;

        let status = response.status();
        if !status.is_success() {
            anyhow::bail!("ack failed with status {}", status);
        }

        response.json().await.context("parse ack result")
    }

    /// Get inbox head sequence.
    pub async fn get_head(&self, device_id: &str) -> Result<u64> {
        let start = std::time::Instant::now();
        let device_ref = redact_id("device", device_id);
        let base_url = self
            .get_base_url()
            .await
            .ok_or_else(|| anyhow::anyhow!("no base URL configured"))?;

        let url = format!(
            "{}/v1/inbox/{}/head",
            base_url,
            urlencoding::encode(device_id)
        );

        timetest!(
            "get_head_begin device_id={} ts={}",
            device_ref,
            crate::ts_ms()
        );

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("get head request")?;

        let status = response.status();
        let elapsed_ms = start.elapsed().as_millis();
        if !status.is_success() {
            timetest!(
                "get_head_done device_id={} status={} error=1 elapsed_ms={} ts={}",
                device_ref,
                status,
                elapsed_ms,
                crate::ts_ms()
            );
            anyhow::bail!("get head failed with status {}", status);
        }

        let result: GetHeadResult = response.json().await.context("parse head result")?;
        timetest!(
            "get_head_done device_id={} head_seq={} elapsed_ms={} ts={}",
            device_ref,
            result.head_seq,
            elapsed_ms,
            crate::ts_ms()
        );
        Ok(result.head_seq)
    }

    /// Fetch identity bundle from URL.
    pub async fn fetch_identity_bundle(
        &self,
        request: FetchIdentityBundleRequest,
    ) -> Result<IdentityBundle> {
        let reference = request
            .reference
            .as_ref()
            .context("identity bundle fetch missing reference")?;
        let response = self
            .client
            .get(reference)
            .send()
            .await
            .context("fetch identity bundle")?;

        let status = response.status();
        if !status.is_success() {
            anyhow::bail!("fetch bundle failed with status {}", status);
        }

        let body = response.text().await.context("read identity bundle")?;
        let body = to_snake_case_json_string(&body)?;
        serde_json::from_str(&body).context("parse identity bundle")
    }

    /// Prepare blob upload.
    pub async fn prepare_blob_upload(
        &self,
        request: PrepareBlobUploadRequest,
    ) -> Result<PrepareBlobUploadResult> {
        let base_url = self
            .get_base_url()
            .await
            .ok_or_else(|| anyhow::anyhow!("no base URL configured"))?;

        let url = format!("{}/v1/storage/prepare-upload", base_url);

        // Serialize to snake_case JSON, then convert to camelCase for server
        let snake_case_body = serde_json::to_string(&request)?;
        let body = to_camel_case_json_string(&snake_case_body)
            .context("convert prepare upload request to camelCase")?;

        let mut builder = self
            .client
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
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("prepare upload failed with status {status}: {body}");
        }

        // Convert camelCase response back to snake_case for Rust
        let response_text = response.text().await.context("read prepare result")?;
        let snake_case_response = to_snake_case_json_string(&response_text)
            .context("convert prepare result to snake_case")?;
        let result: PrepareBlobUploadResult =
            serde_json::from_str(&snake_case_response).context("parse prepare result")?;

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
    fn sanitize_url_for_log_redacts_host_path_ids_and_queries() {
        let sanitized = sanitize_url_for_log(
            "https://example.com/v1/contact-share/secret-token?last_acked_seq=3",
        );

        assert!(sanitized.starts_with("https://<host:"));
        assert!(sanitized.ends_with("/v1/contact-share/<redacted>"));
        assert!(!sanitized.contains("example.com"));
        assert!(!sanitized.contains("secret-token"));
        assert!(!sanitized.contains("last_acked_seq=3"));
    }
}

use anyhow::Result;
use tapchat_core::ffi_api::{CoreEvent, HttpMethod, HttpRequestEffect};
use tapchat_core::transport_contract::{
    FetchAllowlistRequest, FetchIdentityBundleRequest, FetchMessageRequestsRequest,
    MessageRequestActionRequest, PublishSharedStateRequest, ReplaceAllowlistRequest,
};

/// Execute a generic HTTP request and return the corresponding CoreEvent.
/// This is used by DesktopTransport for generic HTTP effects.
pub async fn execute_http_request(
    client: &reqwest::Client,
    request: HttpRequestEffect,
) -> Result<Vec<CoreEvent>> {
    let method = match request.method {
        HttpMethod::Get => reqwest::Method::GET,
        HttpMethod::Post => reqwest::Method::POST,
        HttpMethod::Put => reqwest::Method::PUT,
        HttpMethod::Delete => reqwest::Method::DELETE,
    };

    let mut builder = client.request(method, &request.url);
    for (key, value) in &request.headers {
        builder = builder.header(key, value);
    }
    if let Some(body) = &request.body {
        builder = builder.body(body.clone());
    }

    match builder.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let body = response.text().await.ok();
            Ok(vec![CoreEvent::HttpResponseReceived {
                request_id: request.request_id,
                status,
                body,
            }])
        }
        Err(e) => {
            let retryable = e.is_timeout() || e.is_connect();
            Ok(vec![CoreEvent::HttpRequestFailed {
                request_id: request.request_id,
                retryable,
                detail: Some(e.to_string()),
            }])
        }
    }
}

/// Stub: fetch identity bundle via HTTP.
pub async fn fetch_identity_bundle_stub(
    _fetch: FetchIdentityBundleRequest,
) -> Result<Vec<CoreEvent>> {
    // TODO: Implement via DesktopTransport
    log::warn!("fetch_identity_bundle_stub called - not implemented");
    Ok(Vec::new())
}

/// Stub: fetch message requests from backend.
pub async fn fetch_message_requests_stub(
    _fetch: FetchMessageRequestsRequest,
) -> Result<Vec<CoreEvent>> {
    // TODO: Implement message requests fetch
    log::warn!("fetch_message_requests_stub called - not implemented");
    Ok(Vec::new())
}

/// Stub: act on message request (accept/block/ignore).
pub async fn act_on_message_request_stub(
    _action: MessageRequestActionRequest,
) -> Result<Vec<CoreEvent>> {
    // TODO: Implement message request action
    log::warn!("act_on_message_request_stub called - not implemented");
    Ok(Vec::new())
}

/// Stub: fetch allowlist from backend.
pub async fn fetch_allowlist_stub(
    _fetch: FetchAllowlistRequest,
) -> Result<Vec<CoreEvent>> {
    // TODO: Implement allowlist fetch
    log::warn!("fetch_allowlist_stub called - not implemented");
    Ok(Vec::new())
}

/// Stub: replace allowlist on backend.
pub async fn replace_allowlist_stub(
    _update: ReplaceAllowlistRequest,
) -> Result<Vec<CoreEvent>> {
    // TODO: Implement allowlist replace
    log::warn!("replace_allowlist_stub called - not implemented");
    Ok(Vec::new())
}

/// Stub: publish shared state to backend.
pub async fn publish_shared_state_stub(
    _publish: PublishSharedStateRequest,
) -> Result<Vec<CoreEvent>> {
    // TODO: Implement shared state publish
    log::warn!("publish_shared_state_stub called - not implemented");
    Ok(Vec::new())
}
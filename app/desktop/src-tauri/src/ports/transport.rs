//! Transport port stub implementations
//!
//! These functions implement the TransportPort methods that were previously stubs.
//! They handle HTTP requests to the backend for message requests, allowlist, and shared state.

use anyhow::Result;
use reqwest::Client;

use tapchat_core::ffi_api::CoreEvent;
use tapchat_core::transport_contract::{
    FetchAllowlistRequest, FetchMessageRequestsRequest, MessageRequestActionRequest,
    MessageRequestAction, PublishSharedStateRequest, ReplaceAllowlistRequest,
};

/// Convert JSON keys from camelCase to snake_case for parsing
fn to_snake_case_json_string(input: &str) -> Result<String> {
    let value: serde_json::Value = serde_json::from_str(input)?;
    Ok(convert_json_keys_to_snake_case(value).to_string())
}

/// Convert JSON keys from snake_case to camelCase for sending
fn to_camel_case_json_string(input: &str) -> Result<String> {
    let value: serde_json::Value = serde_json::from_str(input)?;
    Ok(convert_json_keys_to_camel_case(value).to_string())
}

fn convert_json_keys_to_snake_case(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let new_map = map.into_iter().map(|(k, v)| {
                let new_key = camel_to_snake(&k);
                (new_key, convert_json_keys_to_snake_case(v))
            }).collect();
            serde_json::Value::Object(new_map)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(convert_json_keys_to_snake_case).collect())
        }
        other => other,
    }
}

fn convert_json_keys_to_camel_case(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let new_map = map.into_iter().map(|(k, v)| {
                let new_key = snake_to_camel(&k);
                (new_key, convert_json_keys_to_camel_case(v))
            }).collect();
            serde_json::Value::Object(new_map)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(convert_json_keys_to_camel_case).collect())
        }
        other => other,
    }
}

fn camel_to_snake(s: &str) -> String {
    let mut result = String::new();
    for c in s.chars() {
        if c.is_uppercase() {
            if !result.is_empty() {
                result.push('_');
            }
            result.push(c.to_lowercase().next().unwrap_or(c));
        } else {
            result.push(c);
        }
    }
    result
}

fn snake_to_camel(s: &str) -> String {
    let mut result = String::new();
    let mut capitalize_next = false;
    for c in s.chars() {
        if c == '_' {
            capitalize_next = true;
        } else if capitalize_next {
            result.push(c.to_uppercase().next().unwrap_or(c));
            capitalize_next = false;
        } else {
            result.push(c);
        }
    }
    result
}

/// Fetch message requests from backend.
pub async fn fetch_message_requests(
    client: &Client,
    fetch: FetchMessageRequestsRequest,
) -> Result<Vec<CoreEvent>> {
    let mut request = client.get(&fetch.endpoint);
    for (key, value) in &fetch.headers {
        request = request.header(key, value);
    }

    match request.send().await {
        Ok(response) if response.status().is_success() => {
            let body = response.text().await?;
            let normalized = to_snake_case_json_string(&body)?;
            let value: serde_json::Value = serde_json::from_str(&normalized)?;
            let requests = serde_json::from_value(
                value.get("requests").cloned().unwrap_or_else(|| serde_json::json!([])),
            )?;
            Ok(vec![CoreEvent::MessageRequestsFetched { requests }])
        }
        Ok(response) => Ok(vec![CoreEvent::MessageRequestsFetchFailed {
            retryable: false,
            detail: Some(format!("list message requests failed with status {}", response.status())),
        }]),
        Err(error) => Ok(vec![CoreEvent::MessageRequestsFetchFailed {
            retryable: true,
            detail: Some(error.to_string()),
        }]),
    }
}

/// Act on message request (accept/block/ignore).
pub async fn act_on_message_request(
    client: &Client,
    action: MessageRequestActionRequest,
) -> Result<Vec<CoreEvent>> {
    let url = format!(
        "{}/{}/{}",
        action.endpoint.trim_end_matches('/'),
        urlencoding::encode(&action.request_id),
        match action.action {
            MessageRequestAction::Accept => "accept",
            MessageRequestAction::Reject => "reject",
        }
    );

    let mut request = client.post(&url);
    for (key, value) in &action.headers {
        request = request.header(key, value);
    }

    match request.send().await {
        Ok(response) if response.status().is_success() => {
            let body = response.text().await?;
            let normalized = to_snake_case_json_string(&body)?;
            let value: serde_json::Value = serde_json::from_str(&normalized)?;

            let result = tapchat_core::transport_contract::MessageRequestActionResult {
                accepted: value
                    .get("accepted")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                request_id: value
                    .get("request_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&action.request_id)
                    .to_string(),
                sender_user_id: value
                    .get("sender_user_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                sender_bundle_share_url: value
                    .get("sender_bundle_share_url")
                    .and_then(|v| v.as_str())
                    .map(ToOwned::to_owned),
                sender_bundle_hash: value
                    .get("sender_bundle_hash")
                    .and_then(|v| v.as_str())
                    .map(ToOwned::to_owned),
                sender_display_name: value
                    .get("sender_display_name")
                    .and_then(|v| v.as_str())
                    .map(ToOwned::to_owned),
                promoted_count: value
                    .get("promoted_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or_default(),
                action: action.action,
            };
            Ok(vec![CoreEvent::MessageRequestActionCompleted { result }])
        }
        Ok(response) => Ok(vec![CoreEvent::MessageRequestActionFailed {
            request_id: action.request_id,
            action: action.action,
            retryable: false,
            detail: Some(format!(
                "message request action failed with status {}",
                response.status()
            )),
        }]),
        Err(error) => Ok(vec![CoreEvent::MessageRequestActionFailed {
            request_id: action.request_id,
            action: action.action,
            retryable: true,
            detail: Some(error.to_string()),
        }]),
    }
}

/// Fetch allowlist from backend.
pub async fn fetch_allowlist(
    client: &Client,
    fetch: FetchAllowlistRequest,
) -> Result<Vec<CoreEvent>> {
    let mut request = client.get(&fetch.endpoint);
    for (key, value) in &fetch.headers {
        request = request.header(key, value);
    }

    match request.send().await {
        Ok(response) if response.status().is_success() => {
            let body = response.text().await?;
            let document = serde_json::from_str(&to_snake_case_json_string(&body)?)?;
            Ok(vec![CoreEvent::AllowlistFetched { document }])
        }
        Ok(response) => Ok(vec![CoreEvent::AllowlistFetchFailed {
            retryable: false,
            detail: Some(format!("get allowlist failed with status {}", response.status())),
        }]),
        Err(error) => Ok(vec![CoreEvent::AllowlistFetchFailed {
            retryable: true,
            detail: Some(error.to_string()),
        }]),
    }
}

/// Replace allowlist on backend.
pub async fn replace_allowlist(
    client: &Client,
    update: ReplaceAllowlistRequest,
) -> Result<Vec<CoreEvent>> {
    let mut request = client.put(&update.endpoint);
    for (key, value) in &update.headers {
        request = request.header(key, value);
    }

    let body = serde_json::to_string(&serde_json::json!({
        "allowedSenderUserIds": update.document.allowed_sender_user_ids,
        "rejectedSenderUserIds": update.document.rejected_sender_user_ids,
    }))?;

    match request
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            let body = response.text().await?;
            let document = serde_json::from_str(&to_snake_case_json_string(&body)?)?;
            Ok(vec![CoreEvent::AllowlistReplaced { document }])
        }
        Ok(response) => Ok(vec![CoreEvent::AllowlistReplaceFailed {
            retryable: false,
            detail: Some(format!("put allowlist failed with status {}", response.status())),
        }]),
        Err(error) => Ok(vec![CoreEvent::AllowlistReplaceFailed {
            retryable: true,
            detail: Some(error.to_string()),
        }]),
    }
}

/// Publish shared state to backend.
pub async fn publish_shared_state(
    client: &Client,
    publish: PublishSharedStateRequest,
) -> Result<Vec<CoreEvent>> {
    let mut request = client.put(&publish.reference);
    for (key, value) in &publish.headers {
        request = request.header(key, value);
    }

    match request
        .header("Content-Type", "application/json")
        .body(to_camel_case_json_string(&publish.body)?)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => Ok(vec![CoreEvent::SharedStatePublished {
            document_kind: publish.document_kind,
            reference: publish.reference,
        }]),
        Ok(response) => Ok(vec![CoreEvent::SharedStatePublishFailed {
            document_kind: publish.document_kind,
            reference: publish.reference,
            retryable: false,
            detail: Some(format!(
                "shared state publish failed with status {}",
                response.status()
            )),
        }]),
        Err(error) => Ok(vec![CoreEvent::SharedStatePublishFailed {
            document_kind: publish.document_kind,
            reference: publish.reference,
            retryable: true,
            detail: Some(error.to_string()),
        }]),
    }
}
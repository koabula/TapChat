//! Cloudflare REST API Deployment Module
//!
//! This module implements direct deployment to Cloudflare via REST API,
//! bypassing the need for wrangler CLI. It uses the OAuth tokens obtained
//! from our minimal login implementation.

use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;

/// Cloudflare API base URL
const CF_API_BASE: &str = "https://api.cloudflare.com/client/v4";
const WORKER_COMPATIBILITY_DATE: &str = "2026-07-09";
const TAPCHAT_LIFECYCLE_RULE_IDS: &[&str] = &[
    "tapchat-blobs-retention-v1",
    "tapchat-inbox-spill-retention-v1",
    "tapchat-group-spill-retention-v1",
    "tapchat-group-transition-spill-retention-v1",
];

fn reject_unauthorized(status: StatusCode) -> Result<(), String> {
    if status == StatusCode::UNAUTHORIZED {
        Err("cloudflare_api_unauthorized".into())
    } else {
        Ok(())
    }
}

/// OAuth token result used by the native Rust login flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTokens {
    pub success: bool,
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub account_name: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

/// Account query result used by the native Rust REST flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoamiResult {
    pub authenticated: bool,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub accounts: Vec<AccountInfo>,
    #[serde(default)]
    pub active_account_id: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    pub account_id: String,
    pub account_name: String,
}

/// Worker deployment configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerDeployConfig {
    pub worker_name: String,
    pub runtime_id: String,
    pub owner_user_id: String,
    pub owner_user_public_key: String,
    pub public_base_url: Option<String>,
    pub deployment_region: String,
    pub bucket_name: String,
    pub worker_build_id: String,
    pub sharing_token_secret: String,
    pub device_runtime_secret: String,
    pub device_runtime_key_id: String,
    pub previous_device_runtime_secret: Option<String>,
    pub previous_device_runtime_key_id: Option<String>,
    pub auth_rotation_grace_until_ms: Option<u64>,
    pub max_inline_bytes: u32,
    pub retention_days: u32,
    pub rate_limit_per_minute: u32,
    pub rate_limit_per_hour: u32,
    pub message_request_max_body_bytes: u32,
    pub message_request_max_per_sender: u32,
    pub message_request_max_senders: u32,
    pub message_request_max_total_bytes: u32,
    pub message_request_ttl_seconds: u32,
    pub message_request_rate_limit_minute: u32,
    pub message_request_rate_limit_hour: u32,
}

/// Deployment result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployResult {
    pub success: bool,
    pub worker_name: String,
    pub worker_url: String,
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub bucket_name: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

/// Progress phase for UI updates
#[derive(Debug, Clone, Serialize)]
pub struct DeployProgress {
    pub phase: DeployPhase,
    pub message: String,
    pub progress_percent: u8,
}

#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
pub enum DeployPhase {
    Preflight,
    CreatingBuckets,
    UploadingWorker,
    ConfiguringBindings,
    VerifyingDeployment,
    Complete,
    Failed,
}

/// Cloudflare API error response
#[derive(Debug, Clone, Deserialize)]
struct CloudflareError {
    #[serde(default)]
    errors: Vec<CloudflareErrorDetail>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct CloudflareErrorDetail {
    #[serde(default)]
    code: Option<i64>,
    #[serde(default)]
    message: Option<String>,
}

fn build_worker_metadata(config: &WorkerDeployConfig) -> Value {
    let mut bindings = vec![
        serde_json::json!({
            "type": "durable_object_namespace",
            "name": "INBOX",
            "class_name": "InboxDurableObject",
        }),
        serde_json::json!({
            "type": "durable_object_namespace",
            "name": "GROUP_OUTBOX",
            "class_name": "GroupOutboxDurableObject",
        }),
        serde_json::json!({
            "type": "durable_object_namespace",
            "name": "DEVICE_REGISTRY",
            "class_name": "DeviceRegistryDurableObject",
        }),
        serde_json::json!({
            "type": "r2_bucket",
            "name": "TAPCHAT_STORAGE",
            "bucket_name": config.bucket_name,
        }),
    ];
    for (name, text) in [
        ("DEPLOYMENT_REGION", config.deployment_region.clone()),
        ("RUNTIME_ID", config.runtime_id.clone()),
        ("OWNER_USER_ID", config.owner_user_id.clone()),
        (
            "OWNER_USER_PUBLIC_KEY",
            config.owner_user_public_key.clone(),
        ),
        ("WORKER_BUILD_ID", config.worker_build_id.clone()),
        ("MAX_INLINE_BYTES", config.max_inline_bytes.to_string()),
        ("RETENTION_DAYS", config.retention_days.to_string()),
        (
            "RATE_LIMIT_PER_MINUTE",
            config.rate_limit_per_minute.to_string(),
        ),
        (
            "RATE_LIMIT_PER_HOUR",
            config.rate_limit_per_hour.to_string(),
        ),
        (
            "MESSAGE_REQUEST_MAX_BODY_BYTES",
            config.message_request_max_body_bytes.to_string(),
        ),
        (
            "MESSAGE_REQUEST_MAX_PER_SENDER",
            config.message_request_max_per_sender.to_string(),
        ),
        (
            "MESSAGE_REQUEST_MAX_SENDERS",
            config.message_request_max_senders.to_string(),
        ),
        (
            "MESSAGE_REQUEST_MAX_TOTAL_BYTES",
            config.message_request_max_total_bytes.to_string(),
        ),
        (
            "MESSAGE_REQUEST_TTL_SECONDS",
            config.message_request_ttl_seconds.to_string(),
        ),
        (
            "MESSAGE_REQUEST_RATE_LIMIT_MINUTE",
            config.message_request_rate_limit_minute.to_string(),
        ),
        (
            "MESSAGE_REQUEST_RATE_LIMIT_HOUR",
            config.message_request_rate_limit_hour.to_string(),
        ),
        (
            "DEVICE_RUNTIME_SECRET_KEY_ID",
            config.device_runtime_key_id.clone(),
        ),
        (
            "DEVICE_RUNTIME_SECRET_PREVIOUS_KEY_ID",
            config
                .previous_device_runtime_key_id
                .clone()
                .unwrap_or_default(),
        ),
        (
            "AUTH_ROTATION_GRACE_UNTIL_MS",
            config
                .auth_rotation_grace_until_ms
                .map(|value| value.to_string())
                .unwrap_or_default(),
        ),
    ] {
        bindings.push(serde_json::json!({ "type": "plain_text", "name": name, "text": text }));
    }
    for (name, text) in [
        (
            "SHARING_INTERNAL_SECRET",
            Some(config.sharing_token_secret.clone()),
        ),
        (
            "DEVICE_RUNTIME_SECRET",
            Some(config.device_runtime_secret.clone()),
        ),
        (
            "DEVICE_RUNTIME_SECRET_PREVIOUS",
            config.previous_device_runtime_secret.clone(),
        ),
    ] {
        if let Some(text) = text.filter(|value| !value.is_empty()) {
            bindings.push(serde_json::json!({ "type": "secret_text", "name": name, "text": text }));
        }
    }

    serde_json::json!({
        "main_module": "worker.js",
        "compatibility_date": WORKER_COMPATIBILITY_DATE,
        "compatibility_flags": ["nodejs_compat"],
        "exports": {
            "InboxDurableObject": { "type": "durable-object", "storage": "sqlite" },
            "GroupOutboxDurableObject": { "type": "durable-object", "storage": "sqlite" },
            "DeviceRegistryDurableObject": { "type": "durable-object", "storage": "sqlite" },
        },
        "observability": {
            "enabled": true,
            "logs": {
                "enabled": true,
                "head_sampling_rate": 0.01,
                "invocation_logs": false,
                "persist": true,
            },
            "traces": {
                "enabled": false,
                "head_sampling_rate": 0.0,
                "persist": false,
            },
        },
        "bindings": bindings,
    })
}

/// Create R2 bucket via REST API
pub async fn create_r2_bucket(
    client: &Client,
    api_token: &str,
    account_id: &str,
    bucket_name: &str,
) -> Result<(), String> {
    let url = format!(
        "{}/accounts/{}/r2/buckets/{}",
        CF_API_BASE, account_id, bucket_name
    );

    let response = client
        .put(&url)
        .header("Authorization", format!("Bearer {}", api_token))
        .json(&serde_json::json!({
            "name": bucket_name,
        }))
        .send()
        .await
        .map_err(|e| format!("R2 bucket create request failed: {}", e))?;

    let status = response.status();
    reject_unauthorized(status)?;

    // 200 OK = bucket created
    // 409 Conflict = bucket already exists (acceptable)
    if status.is_success() || status.as_u16() == 409 {
        return Ok(());
    }

    // Parse error
    let error_body = response
        .text()
        .await
        .map_err(|e| format!("Failed to read error response: {}", e))?;

    let cf_error: CloudflareError = serde_json::from_str(&error_body)
        .map_err(|e| format!("Failed to parse error response: {}", e))?;

    let error_msg = cf_error
        .errors
        .first()
        .and_then(|e| e.message.clone())
        .unwrap_or_else(|| format!("HTTP {}", status));

    Err(format!(
        "Failed to create bucket {}: {}",
        bucket_name, error_msg
    ))
}

fn merge_tapchat_lifecycle_rules(mut existing: Vec<Value>, retention_days: u32) -> Vec<Value> {
    existing.retain(|rule| {
        !rule
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| TAPCHAT_LIFECYCLE_RULE_IDS.contains(&id))
    });
    let max_age = u64::from(retention_days.max(1)) * 24 * 60 * 60;
    for (id, prefix) in [
        ("tapchat-blobs-retention-v1", "blobs/"),
        ("tapchat-inbox-spill-retention-v1", "inbox-payload/"),
        ("tapchat-group-spill-retention-v1", "group-outbox-payload/"),
        (
            "tapchat-group-transition-spill-retention-v1",
            "group-outbox-transition/",
        ),
    ] {
        existing.push(serde_json::json!({
            "id": id,
            "enabled": true,
            "conditions": { "prefix": prefix },
            "deleteObjectsTransition": {
                "condition": { "type": "Age", "maxAge": max_age }
            }
        }));
    }
    existing
}

/// Merge TapChat-owned retention rules without replacing rules created by the
/// bucket owner. Deployment fails closed when lifecycle configuration cannot
/// be read or written, because an unbounded transport bucket is unsafe.
pub async fn configure_r2_lifecycle(
    client: &Client,
    api_token: &str,
    account_id: &str,
    bucket_name: &str,
    retention_days: u32,
) -> Result<(), String> {
    let url = format!(
        "{}/accounts/{}/r2/buckets/{}/lifecycle",
        CF_API_BASE, account_id, bucket_name
    );
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", api_token))
        .send()
        .await
        .map_err(|error| format!("R2 lifecycle read request failed: {error}"))?;
    reject_unauthorized(response.status())?;
    if !response.status().is_success() {
        return Err(format!(
            "Failed to read lifecycle rules for bucket {bucket_name}: HTTP {}",
            response.status()
        ));
    }
    let body: Value = response
        .json()
        .await
        .map_err(|error| format!("Failed to decode R2 lifecycle rules: {error}"))?;
    let existing = body
        .get("result")
        .and_then(|result| result.get("rules"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let rules = merge_tapchat_lifecycle_rules(existing, retention_days);

    let response = client
        .put(&url)
        .header("Authorization", format!("Bearer {}", api_token))
        .json(&serde_json::json!({ "rules": rules }))
        .send()
        .await
        .map_err(|error| format!("R2 lifecycle update request failed: {error}"))?;
    reject_unauthorized(response.status())?;
    if !response.status().is_success() {
        return Err(format!(
            "Failed to configure lifecycle rules for bucket {bucket_name}: HTTP {}",
            response.status()
        ));
    }
    Ok(())
}

/// Upload Worker script via REST API
///
/// Cloudflare Workers API uses PUT /accounts/{account_id}/workers/scripts/{script_name}
/// The script can be uploaded with bindings metadata as a multipart upload
pub async fn upload_worker_script(
    client: &Client,
    api_token: &str,
    account_id: &str,
    worker_name: &str,
    worker_script: &str,
    config: &WorkerDeployConfig,
) -> Result<(), String> {
    let metadata = build_worker_metadata(config);
    // Build multipart form data
    // Cloudflare expects: metadata (JSON) + script (JS file named 'worker.js')
    let form = reqwest::multipart::Form::new()
        .part(
            "metadata",
            reqwest::multipart::Part::text(metadata.to_string())
                .mime_str("application/json")
                .map_err(|e| format!("MIME type error: {}", e))?,
        )
        .part(
            "worker.js",
            reqwest::multipart::Part::text(worker_script.to_string())
                .file_name("worker.js")
                .mime_str("application/javascript+module")
                .map_err(|e| format!("MIME type error: {}", e))?,
        );

    let url = format!(
        "{}/accounts/{}/workers/scripts/{}",
        CF_API_BASE, account_id, worker_name
    );

    let response = client
        .put(&url)
        .header("Authorization", format!("Bearer {}", api_token))
        .multipart(form)
        .send()
        .await
        .map_err(|e| format!("Worker upload request failed: {}", e))?;

    let status = response.status();
    reject_unauthorized(status)?;

    if !status.is_success() {
        let error_body = response
            .text()
            .await
            .map_err(|e| format!("Failed to read error response: {}", e))?;

        let cf_error: CloudflareError = serde_json::from_str(&error_body)
            .map_err(|e| format!("Failed to parse error response: {}", e))?;

        let error_msg = cf_error
            .errors
            .first()
            .and_then(|e| e.message.clone())
            .unwrap_or_else(|| format!("HTTP {}", status));

        return Err(format!("Failed to upload worker: {error_msg}"));
    }

    Ok(())
}

pub async fn delete_worker_secret(
    client: &Client,
    api_token: &str,
    account_id: &str,
    worker_name: &str,
    secret_name: &str,
) -> Result<(), String> {
    let url = format!(
        "{}/accounts/{}/workers/scripts/{}/secrets/{}",
        CF_API_BASE, account_id, worker_name, secret_name
    );
    let response = client
        .delete(&url)
        .header("Authorization", format!("Bearer {}", api_token))
        .send()
        .await
        .map_err(|error| format!("Secret delete request failed: {error}"))?;
    reject_unauthorized(response.status())?;
    if response.status().is_success() || response.status() == StatusCode::NOT_FOUND {
        return Ok(());
    }
    Err(format!(
        "Failed to delete secret {secret_name}: HTTP {}",
        response.status()
    ))
}

/// Enable workers.dev subdomain routing for a Worker
/// This creates a workers.dev route that makes the Worker accessible via workers.dev URL
pub async fn enable_workers_dev_routing(
    client: &Client,
    api_token: &str,
    account_id: &str,
    worker_name: &str,
) -> Result<(), String> {
    // First ensure the account has a workers.dev subdomain
    let subdomain = ensure_account_workers_dev_subdomain(client, api_token, account_id).await?;
    eprintln!("Account workers.dev subdomain: {}", subdomain);

    // POST to this endpoint enables workers.dev routing for the worker
    // The worker will be accessible at https://{worker_name}.{subdomain}.workers.dev
    let url = format!(
        "{}/accounts/{}/workers/scripts/{}/subdomain",
        CF_API_BASE, account_id, worker_name
    );

    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", api_token))
        .json(&serde_json::json!({
            "enabled": true,
        }))
        .send()
        .await
        .map_err(|e| format!("Workers.dev routing request failed: {}", e))?;

    let status = response.status();
    reject_unauthorized(status)?;
    let response_body = response
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    if !status.is_success() {
        eprintln!("Error enabling workers.dev routing: HTTP {}", status);
        return Err(format!(
            "Failed to enable workers.dev routing: HTTP {}",
            status
        ));
    }

    let _ = response_body;
    eprintln!(
        "Successfully enabled workers.dev routing for {}",
        worker_name
    );
    Ok(())
}

/// Get Worker deployment info (account's workers.dev subdomain)
pub async fn get_worker_subdomain(
    client: &Client,
    api_token: &str,
    account_id: &str,
) -> Result<String, String> {
    // Get the account's workers.dev subdomain
    let url = format!("{}/accounts/{}/workers/subdomain", CF_API_BASE, account_id);

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", api_token))
        .send()
        .await
        .map_err(|e| format!("Worker subdomain request failed: {}", e))?;

    let status = response.status();
    reject_unauthorized(status)?;

    if !status.is_success() {
        return Err(format!("Failed to get worker subdomain: HTTP {}", status));
    }

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    // Extract subdomain from response
    body.get("result")
        .and_then(|r| r.get("subdomain"))
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "No subdomain found in response".to_string())
}

/// Ensure account has a workers.dev subdomain set (required for workers.dev routing)
/// Returns the account's workers.dev subdomain
pub async fn ensure_account_workers_dev_subdomain(
    client: &Client,
    api_token: &str,
    account_id: &str,
) -> Result<String, String> {
    // Get the existing subdomain - most accounts already have one set
    let subdomain_result = get_worker_subdomain(client, api_token, account_id).await;

    match subdomain_result {
        Ok(subdomain) => {
            eprintln!("Account workers.dev subdomain exists: {}", subdomain);
            return Ok(subdomain);
        }
        Err(err) => {
            eprintln!("Could not get existing subdomain: {}", err);
            // Account might not have a subdomain set yet
            // Try to create one using the account ID as a fallback identifier
            // (Cloudflare requires a subdomain name for PUT)
        }
    }

    // If no subdomain exists, try to set one
    // Use account_id prefix as a reasonable subdomain name
    // (most accounts already have a subdomain, so this is a fallback)
    let url = format!("{}/accounts/{}/workers/subdomain", CF_API_BASE, account_id);

    // Use a short identifier derived from account_id
    let subdomain_name = format!("tc-{}", &account_id[..8.min(account_id.len())]);

    eprintln!(
        "Attempting to create workers.dev subdomain: {}",
        subdomain_name
    );

    let response = client
        .put(&url)
        .header("Authorization", format!("Bearer {}", api_token))
        .json(&serde_json::json!({
            "subdomain": subdomain_name,
        }))
        .send()
        .await
        .map_err(|e| format!("Create subdomain request failed: {}", e))?;

    let status = response.status();
    reject_unauthorized(status)?;

    if !status.is_success() {
        eprintln!("Failed to set workers.dev subdomain: HTTP {}", status);
        return Err(format!(
            "Failed to set workers.dev subdomain: HTTP {}",
            status
        ));
    }

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    eprintln!("Workers.dev subdomain configured");

    // Extract subdomain from response
    body.get("result")
        .and_then(|r| r.get("subdomain"))
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "No subdomain in response".to_string())
}

/// Full deployment flow via REST API
pub async fn deploy_via_rest_api(
    api_token: &str,
    account_id: &str,
    worker_script: &str,
    config: &WorkerDeployConfig,
    progress_callback: impl Fn(DeployProgress),
) -> Result<DeployResult, String> {
    let client = Client::builder()
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    // Phase 1: Create R2 buckets
    progress_callback(DeployProgress {
        phase: DeployPhase::CreatingBuckets,
        message: "Creating storage buckets...".into(),
        progress_percent: 20,
    });

    create_r2_bucket(&client, api_token, account_id, &config.bucket_name).await?;
    configure_r2_lifecycle(
        &client,
        api_token,
        account_id,
        &config.bucket_name,
        config.retention_days,
    )
    .await?;

    // Phase 2: Upload Worker script
    progress_callback(DeployProgress {
        phase: DeployPhase::UploadingWorker,
        message: "Uploading Worker script...".into(),
        progress_percent: 40,
    });

    upload_worker_script(
        &client,
        api_token,
        account_id,
        &config.worker_name,
        worker_script,
        config,
    )
    .await?;

    // Phase 2.5: Enable workers.dev subdomain routing
    progress_callback(DeployProgress {
        phase: DeployPhase::UploadingWorker,
        message: "Enabling workers.dev routing...".into(),
        progress_percent: 50,
    });

    enable_workers_dev_routing(&client, api_token, account_id, &config.worker_name).await?;

    // Phase 3: Get deployment URL. Authentication secrets were committed in
    // the same script upload, so there is no partially configured Worker.
    progress_callback(DeployProgress {
        phase: DeployPhase::VerifyingDeployment,
        message: "Verifying deployment...".into(),
        progress_percent: 80,
    });

    // Get workers.dev subdomain or custom URL
    let worker_url = if let Some(public_url) = &config.public_base_url {
        if !public_url.is_empty() {
            public_url.clone()
        } else {
            // Get the account's workers.dev subdomain and construct URL
            match get_worker_subdomain(&client, api_token, account_id).await {
                Ok(subdomain) => {
                    format!("https://{}.{}.workers.dev", config.worker_name, subdomain)
                }
                Err(_) => format!("https://{}.workers.dev", config.worker_name),
            }
        }
    } else {
        // Get the account's workers.dev subdomain and construct URL
        match get_worker_subdomain(&client, api_token, account_id).await {
            Ok(subdomain) => format!("https://{}.{}.workers.dev", config.worker_name, subdomain),
            Err(_) => format!("https://{}.workers.dev", config.worker_name),
        }
    };

    // Phase 5: Complete
    progress_callback(DeployProgress {
        phase: DeployPhase::Complete,
        message: "Deployment complete!".into(),
        progress_percent: 100,
    });

    Ok(DeployResult {
        success: true,
        worker_name: config.worker_name.clone(),
        worker_url,
        account_id: Some(account_id.to_string()),
        bucket_name: Some(config.bucket_name.clone()),
        error: None,
    })
}

/// Load embedded Worker script
pub fn load_embedded_worker_script(runtime_root: &Path) -> Result<String, String> {
    let worker_path = runtime_root.join("worker.js");

    std::fs::read_to_string(&worker_path)
        .map_err(|e| format!("Failed to read embedded worker script: {}", e))
}

/// Get accounts using OAuth token
#[allow(dead_code)]
pub async fn get_accounts(api_token: &str) -> Result<Vec<AccountInfo>, String> {
    let client = Client::builder()
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    let url = format!("{}/user/accounts", CF_API_BASE);

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", api_token))
        .send()
        .await
        .map_err(|e| format!("Accounts request failed: {}", e))?;

    let status = response.status();

    if !status.is_success() {
        return Err(format!("Failed to get accounts: HTTP {}", status));
    }

    let body = response
        .json::<serde_json::Value>()
        .await
        .map_err(|e| format!("Failed to parse accounts response: {}", e))?;

    let accounts = body
        .get("result")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| {
                    Some(AccountInfo {
                        account_id: item.get("id")?.as_str()?.to_string(),
                        account_name: item.get("name")?.as_str()?.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(accounts)
}

#[cfg(test)]
mod tests {
    use super::{
        build_worker_metadata, merge_tapchat_lifecycle_rules, WorkerDeployConfig,
        WORKER_COMPATIBILITY_DATE,
    };

    fn deploy_config() -> WorkerDeployConfig {
        WorkerDeployConfig {
            worker_name: "tapchat-test".into(),
            public_base_url: None,
            deployment_region: "test".into(),
            bucket_name: "tapchat-storage".into(),
            worker_build_id: "tapchat-worker-v5-test".into(),
            sharing_token_secret: "sharing".into(),
            runtime_id: "runtime-test".into(),
            owner_user_id: "user:test".into(),
            owner_user_public_key: "owner-public-key".into(),
            device_runtime_secret: "runtime".into(),
            device_runtime_key_id: "runtime-key".into(),
            previous_device_runtime_secret: None,
            previous_device_runtime_key_id: None,
            auth_rotation_grace_until_ms: None,
            max_inline_bytes: 4096,
            retention_days: 30,
            rate_limit_per_minute: 60,
            rate_limit_per_hour: 600,
            message_request_max_body_bytes: 327_680,
            message_request_max_per_sender: 16,
            message_request_max_senders: 64,
            message_request_max_total_bytes: 4_194_304,
            message_request_ttl_seconds: 604_800,
            message_request_rate_limit_minute: 30,
            message_request_rate_limit_hour: 300,
        }
    }

    #[test]
    fn worker_metadata_uses_declarative_sqlite_exports_and_embeds_secrets() {
        let metadata = build_worker_metadata(&deploy_config());
        assert_eq!(
            metadata["compatibility_date"].as_str(),
            Some(WORKER_COMPATIBILITY_DATE)
        );
        assert_eq!(metadata["compatibility_flags"][0], "nodejs_compat");
        assert_eq!(metadata["observability"]["logs"]["enabled"], true);
        assert_eq!(
            metadata["observability"]["logs"]["head_sampling_rate"],
            0.01
        );
        assert_eq!(metadata["observability"]["logs"]["invocation_logs"], false);
        assert_eq!(metadata["observability"]["traces"]["enabled"], false);

        let bindings = metadata["bindings"].as_array().expect("bindings");
        assert!(bindings.iter().any(|binding| {
            binding["name"] == "INBOX" && binding["class_name"] == "InboxDurableObject"
        }));
        assert!(bindings.iter().any(|binding| {
            binding["name"] == "GROUP_OUTBOX" && binding["class_name"] == "GroupOutboxDurableObject"
        }));
        assert!(bindings.iter().any(|binding| {
            binding["name"] == "DEVICE_REGISTRY"
                && binding["class_name"] == "DeviceRegistryDurableObject"
        }));

        assert!(metadata.get("migrations").is_none());
        for class in [
            "InboxDurableObject",
            "GroupOutboxDurableObject",
            "DeviceRegistryDurableObject",
        ] {
            assert_eq!(metadata["exports"][class]["type"], "durable-object");
            assert_eq!(metadata["exports"][class]["storage"], "sqlite");
        }
        let bindings = metadata["bindings"].as_array().expect("bindings");
        assert_eq!(
            bindings
                .iter()
                .filter(|binding| binding["type"] == "r2_bucket")
                .count(),
            1
        );
        for name in ["SHARING_INTERNAL_SECRET", "DEVICE_RUNTIME_SECRET"] {
            assert!(bindings
                .iter()
                .any(|binding| { binding["type"] == "secret_text" && binding["name"] == name }));
        }
    }

    #[test]
    fn lifecycle_merge_preserves_user_rules_and_replaces_only_tapchat_rules() {
        let rules = merge_tapchat_lifecycle_rules(
            vec![
                serde_json::json!({
                    "id": "owner-rule",
                    "enabled": true,
                    "conditions": { "prefix": "archive/" }
                }),
                serde_json::json!({
                    "id": "tapchat-blobs-retention-v1",
                    "enabled": false,
                    "conditions": { "prefix": "old/" }
                }),
            ],
            30,
        );
        assert!(rules.iter().any(|rule| rule["id"] == "owner-rule"));
        assert_eq!(
            rules
                .iter()
                .filter(|rule| rule["id"] == "tapchat-blobs-retention-v1")
                .count(),
            1
        );
        let blob_rule = rules
            .iter()
            .find(|rule| rule["id"] == "tapchat-blobs-retention-v1")
            .expect("blob rule");
        assert_eq!(blob_rule["conditions"]["prefix"], "blobs/");
        assert_eq!(
            blob_rule["deleteObjectsTransition"]["condition"]["maxAge"],
            30 * 24 * 60 * 60
        );
    }
}

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

fn reject_auth_failure(status: StatusCode) -> Result<(), String> {
    if status == StatusCode::UNAUTHORIZED {
        Err("cloudflare_api_unauthorized".into())
    } else if status == StatusCode::FORBIDDEN {
        Err("cloudflare_permission_denied:http_status=403".into())
    } else {
        Ok(())
    }
}

fn cloudflare_api_failure(app_code: &str, status: StatusCode, body: &str) -> String {
    let cloudflare_code = serde_json::from_str::<CloudflareError>(body)
        .ok()
        .and_then(|error| error.errors.first().and_then(|detail| detail.code));
    match cloudflare_code {
        Some(code) => format!("{app_code}:http_status={} cf_code={code}", status.as_u16()),
        None => format!("{app_code}:http_status={}", status.as_u16()),
    }
}

fn request_failure(app_code: &str) -> String {
    format!("{app_code}:network_request_failed")
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
struct CloudflareErrorDetail {
    #[serde(default)]
    code: Option<i64>,
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

/// Ensure the R2 bucket exists via the documented Cloudflare REST API.
pub async fn create_r2_bucket(
    client: &Client,
    api_token: &str,
    account_id: &str,
    bucket_name: &str,
) -> Result<(), String> {
    create_r2_bucket_at(client, api_token, CF_API_BASE, account_id, bucket_name).await
}

async fn create_r2_bucket_at(
    client: &Client,
    api_token: &str,
    api_base: &str,
    account_id: &str,
    bucket_name: &str,
) -> Result<(), String> {
    let bucket_url = format!(
        "{}/accounts/{}/r2/buckets/{}",
        api_base, account_id, bucket_name
    );
    let lookup = client
        .get(&bucket_url)
        .header("Authorization", format!("Bearer {}", api_token))
        .send()
        .await
        .map_err(|_| request_failure("cloudflare_storage_setup_failed"))?;
    let lookup_status = lookup.status();
    reject_auth_failure(lookup_status)?;
    if lookup_status.is_success() {
        return Ok(());
    }
    if lookup_status != StatusCode::NOT_FOUND {
        let body = lookup.text().await.unwrap_or_default();
        return Err(cloudflare_api_failure(
            "cloudflare_storage_setup_failed",
            lookup_status,
            &body,
        ));
    }

    let url = format!("{}/accounts/{}/r2/buckets", api_base, account_id);

    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", api_token))
        .json(&serde_json::json!({
            "name": bucket_name,
        }))
        .send()
        .await
        .map_err(|_| request_failure("cloudflare_storage_setup_failed"))?;

    let status = response.status();
    reject_auth_failure(status)?;

    if status.is_success() {
        return Ok(());
    }

    // A concurrent retry may have created the bucket after our lookup. Only
    // accept a conflict after verifying that the exact bucket now exists.
    if status == StatusCode::CONFLICT {
        let verify = client
            .get(&bucket_url)
            .header("Authorization", format!("Bearer {}", api_token))
            .send()
            .await
            .map_err(|_| request_failure("cloudflare_storage_setup_failed"))?;
        let verify_status = verify.status();
        reject_auth_failure(verify_status)?;
        if verify_status.is_success() {
            return Ok(());
        }
        let body = verify.text().await.unwrap_or_default();
        return Err(cloudflare_api_failure(
            "cloudflare_storage_setup_failed",
            verify_status,
            &body,
        ));
    }

    let body = response.text().await.unwrap_or_default();
    Err(cloudflare_api_failure(
        "cloudflare_storage_setup_failed",
        status,
        &body,
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
        .map_err(|_| request_failure("cloudflare_storage_setup_failed"))?;
    let status = response.status();
    reject_auth_failure(status)?;
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(cloudflare_api_failure(
            "cloudflare_storage_setup_failed",
            status,
            &body,
        ));
    }
    let body: Value = response
        .json()
        .await
        .map_err(|_| "cloudflare_storage_setup_failed:invalid_response".to_string())?;
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
        .map_err(|_| request_failure("cloudflare_storage_setup_failed"))?;
    let status = response.status();
    reject_auth_failure(status)?;
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(cloudflare_api_failure(
            "cloudflare_storage_setup_failed",
            status,
            &body,
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
                .map_err(|_| "cloudflare_worker_deploy_failed:invalid_metadata".to_string())?,
        )
        .part(
            "worker.js",
            reqwest::multipart::Part::text(worker_script.to_string())
                .file_name("worker.js")
                .mime_str("application/javascript+module")
                .map_err(|_| "cloudflare_worker_deploy_failed:invalid_script".to_string())?,
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
        .map_err(|_| request_failure("cloudflare_worker_deploy_failed"))?;

    let status = response.status();
    reject_auth_failure(status)?;

    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(cloudflare_api_failure(
            "cloudflare_worker_deploy_failed",
            status,
            &body,
        ));
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
        .map_err(|_| request_failure("cloudflare_worker_deploy_failed"))?;
    reject_auth_failure(response.status())?;
    if response.status().is_success() || response.status() == StatusCode::NOT_FOUND {
        return Ok(());
    }
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    Err(cloudflare_api_failure(
        "cloudflare_worker_deploy_failed",
        status,
        &body,
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
        .map_err(|_| request_failure("cloudflare_worker_deploy_failed"))?;

    let status = response.status();
    reject_auth_failure(status)?;
    let response_body = response.text().await.unwrap_or_default();

    if !status.is_success() {
        return Err(cloudflare_api_failure(
            "cloudflare_worker_deploy_failed",
            status,
            &response_body,
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
        .map_err(|_| request_failure("cloudflare_worker_deploy_failed"))?;

    let status = response.status();
    reject_auth_failure(status)?;

    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(cloudflare_api_failure(
            "cloudflare_worker_deploy_failed",
            status,
            &body,
        ));
    }

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|_| "cloudflare_worker_deploy_failed:invalid_response".to_string())?;

    // Extract subdomain from response
    body.get("result")
        .and_then(|r| r.get("subdomain"))
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "cloudflare_worker_deploy_failed:missing_subdomain".to_string())
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
        Err(error)
            if error.starts_with("cloudflare_api_unauthorized")
                || error.starts_with("cloudflare_permission_denied") =>
        {
            return Err(error);
        }
        Err(_) => {
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
        .map_err(|_| request_failure("cloudflare_worker_deploy_failed"))?;

    let status = response.status();
    reject_auth_failure(status)?;

    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(cloudflare_api_failure(
            "cloudflare_worker_deploy_failed",
            status,
            &body,
        ));
    }

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|_| "cloudflare_worker_deploy_failed:invalid_response".to_string())?;

    eprintln!("Workers.dev subdomain configured");

    // Extract subdomain from response
    body.get("result")
        .and_then(|r| r.get("subdomain"))
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "cloudflare_worker_deploy_failed:missing_subdomain".to_string())
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
        .map_err(|_| "cloudflare_worker_deploy_failed:http_client_unavailable".to_string())?;

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

    // Get the workers.dev subdomain or use an explicitly configured URL.
    let worker_url = if let Some(public_url) = config
        .public_base_url
        .as_ref()
        .filter(|url| !url.is_empty())
    {
        public_url.clone()
    } else {
        let subdomain = get_worker_subdomain(&client, api_token, account_id).await?;
        format!("https://{}.{}.workers.dev", config.worker_name, subdomain)
    };

    // The Worker upload is complete, but device enrollment and local
    // writeback are finalized by the caller.
    progress_callback(DeployProgress {
        phase: DeployPhase::VerifyingDeployment,
        message: "Worker uploaded. Finishing device setup...".into(),
        progress_percent: 80,
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
        WORKER_COMPATIBILITY_DATE, WorkerDeployConfig, build_worker_metadata, create_r2_bucket_at,
        merge_tapchat_lifecycle_rules,
    };
    use reqwest::Client;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    struct ExpectedRequest {
        request_line: &'static str,
        body_contains: Option<&'static str>,
        status: u16,
        response_body: &'static str,
    }

    async fn test_server(
        expectations: Vec<ExpectedRequest>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("local address");
        let handle = tokio::spawn(async move {
            for expected in expectations {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let mut request = Vec::new();
                let mut buffer = [0_u8; 4096];
                loop {
                    let read = stream.read(&mut buffer).await.expect("read request");
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..read]);
                    let Some(header_end) =
                        request.windows(4).position(|bytes| bytes == b"\r\n\r\n")
                    else {
                        continue;
                    };
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                        .unwrap_or_default();
                    if request.len() >= header_end + 4 + content_length {
                        break;
                    }
                }
                let request = String::from_utf8_lossy(&request);
                assert!(request.starts_with(expected.request_line), "{request}");
                if let Some(fragment) = expected.body_contains {
                    assert!(request.contains(fragment), "{request}");
                }
                let reason = match expected.status {
                    200 => "OK",
                    403 => "Forbidden",
                    404 => "Not Found",
                    409 => "Conflict",
                    _ => "Test",
                };
                let response = format!(
                    "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    expected.status,
                    reason,
                    expected.response_body.len(),
                    expected.response_body
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write response");
            }
        });
        (format!("http://{address}"), handle)
    }

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
            assert!(
                bindings
                    .iter()
                    .any(|binding| { binding["type"] == "secret_text" && binding["name"] == name })
            );
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

    #[tokio::test]
    async fn r2_bucket_creation_uses_get_then_documented_post() {
        let (api_base, server) = test_server(vec![
            ExpectedRequest {
                request_line: "GET /accounts/account/r2/buckets/tapchat-storage HTTP/1.1",
                body_contains: None,
                status: 404,
                response_body: r#"{"success":false,"errors":[]}"#,
            },
            ExpectedRequest {
                request_line: "POST /accounts/account/r2/buckets HTTP/1.1",
                body_contains: Some(r#""name":"tapchat-storage""#),
                status: 200,
                response_body: r#"{"success":true,"result":{"name":"tapchat-storage"}}"#,
            },
        ])
        .await;

        create_r2_bucket_at(
            &Client::new(),
            "token",
            &api_base,
            "account",
            "tapchat-storage",
        )
        .await
        .expect("create bucket");
        server.await.expect("server");
    }

    #[tokio::test]
    async fn r2_bucket_conflict_is_accepted_only_after_exact_lookup() {
        let (api_base, server) = test_server(vec![
            ExpectedRequest {
                request_line: "GET /accounts/account/r2/buckets/tapchat-storage HTTP/1.1",
                body_contains: None,
                status: 404,
                response_body: r#"{"success":false,"errors":[]}"#,
            },
            ExpectedRequest {
                request_line: "POST /accounts/account/r2/buckets HTTP/1.1",
                body_contains: Some(r#""name":"tapchat-storage""#),
                status: 409,
                response_body: r#"{"success":false,"errors":[]}"#,
            },
            ExpectedRequest {
                request_line: "GET /accounts/account/r2/buckets/tapchat-storage HTTP/1.1",
                body_contains: None,
                status: 200,
                response_body: r#"{"success":true,"result":{"name":"tapchat-storage"}}"#,
            },
        ])
        .await;

        create_r2_bucket_at(
            &Client::new(),
            "token",
            &api_base,
            "account",
            "tapchat-storage",
        )
        .await
        .expect("verify concurrent create");
        server.await.expect("server");
    }

    #[tokio::test]
    async fn r2_permission_failure_is_structured_and_redacted() {
        let (api_base, server) = test_server(vec![ExpectedRequest {
            request_line: "GET /accounts/account/r2/buckets/tapchat-storage HTTP/1.1",
            body_contains: None,
            status: 403,
            response_body: r#"{"success":false,"errors":[{"code":10000,"message":"token=secret"}]}"#,
        }])
        .await;

        let error = create_r2_bucket_at(
            &Client::new(),
            "token",
            &api_base,
            "account",
            "tapchat-storage",
        )
        .await
        .expect_err("permission must fail");
        assert_eq!(error, "cloudflare_permission_denied:http_status=403");
        assert!(!error.contains("secret"));
        server.await.expect("server");
    }
}

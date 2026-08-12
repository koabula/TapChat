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

fn reject_unauthorized(status: StatusCode) -> Result<(), String> {
    if status == StatusCode::UNAUTHORIZED {
        Err("cloudflare_api_unauthorized".into())
    } else {
        Ok(())
    }
}

/// OAuth login result from login.mjs
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

/// Whoami result from whoami.mjs
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
    pub preview_bucket_name: String,
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
    pub preview_bucket_name: Option<String>,
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
    WritingSecrets,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkerMigrationPlan {
    FreshV3,
    UpgradeDeviceRegistry,
    None,
}

fn worker_migration_metadata(plan: WorkerMigrationPlan) -> Option<Value> {
    match plan {
        WorkerMigrationPlan::FreshV3 => Some(serde_json::json!({
            "tag": "v3",
            "new_sqlite_classes": ["InboxDurableObject", "GroupOutboxDurableObject", "DeviceRegistryDurableObject"],
        })),
        WorkerMigrationPlan::UpgradeDeviceRegistry => Some(serde_json::json!({
            "tag": "v3",
            "new_sqlite_classes": ["DeviceRegistryDurableObject"],
        })),
        WorkerMigrationPlan::None => None,
    }
}

fn build_worker_metadata(config: &WorkerDeployConfig, plan: WorkerMigrationPlan) -> Value {
    let mut metadata = serde_json::json!({
        "main_module": "worker.js",
        "compatibility_date": WORKER_COMPATIBILITY_DATE,
        "compatibility_flags": ["nodejs_compat"],
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
        "bindings": [
            {
                "type": "durable_object_namespace",
                "name": "INBOX",
                "class_name": "InboxDurableObject",
            },
            {
                "type": "durable_object_namespace",
                "name": "GROUP_OUTBOX",
                "class_name": "GroupOutboxDurableObject",
            },
            {
                "type": "durable_object_namespace",
                "name": "DEVICE_REGISTRY",
                "class_name": "DeviceRegistryDurableObject",
            },
            {
                "type": "r2_bucket",
                "name": "TAPCHAT_STORAGE",
                "bucket_name": config.bucket_name,
            },
            {
                "type": "plain_text",
                "name": "DEPLOYMENT_REGION",
                "text": config.deployment_region,
            },
            {
                "type": "plain_text",
                "name": "RUNTIME_ID",
                "text": config.runtime_id,
            },
            {
                "type": "plain_text",
                "name": "OWNER_USER_ID",
                "text": config.owner_user_id,
            },
            {
                "type": "plain_text",
                "name": "OWNER_USER_PUBLIC_KEY",
                "text": config.owner_user_public_key,
            },
            {
                "type": "plain_text",
                "name": "MAX_INLINE_BYTES",
                "text": config.max_inline_bytes.to_string(),
            },
            {
                "type": "plain_text",
                "name": "RETENTION_DAYS",
                "text": config.retention_days.to_string(),
            },
            {
                "type": "plain_text",
                "name": "RATE_LIMIT_PER_MINUTE",
                "text": config.rate_limit_per_minute.to_string(),
            },
            {
                "type": "plain_text",
                "name": "RATE_LIMIT_PER_HOUR",
                "text": config.rate_limit_per_hour.to_string(),
            },
            {
                "type": "plain_text",
                "name": "MESSAGE_REQUEST_MAX_BODY_BYTES",
                "text": config.message_request_max_body_bytes.to_string(),
            },
            {
                "type": "plain_text",
                "name": "MESSAGE_REQUEST_MAX_PER_SENDER",
                "text": config.message_request_max_per_sender.to_string(),
            },
            {
                "type": "plain_text",
                "name": "MESSAGE_REQUEST_MAX_SENDERS",
                "text": config.message_request_max_senders.to_string(),
            },
            {
                "type": "plain_text",
                "name": "MESSAGE_REQUEST_MAX_TOTAL_BYTES",
                "text": config.message_request_max_total_bytes.to_string(),
            },
            {
                "type": "plain_text",
                "name": "MESSAGE_REQUEST_TTL_SECONDS",
                "text": config.message_request_ttl_seconds.to_string(),
            },
            {
                "type": "plain_text",
                "name": "MESSAGE_REQUEST_RATE_LIMIT_MINUTE",
                "text": config.message_request_rate_limit_minute.to_string(),
            },
            {
                "type": "plain_text",
                "name": "MESSAGE_REQUEST_RATE_LIMIT_HOUR",
                "text": config.message_request_rate_limit_hour.to_string(),
            },
            {
                "type": "plain_text",
                "name": "DEVICE_RUNTIME_SECRET_KEY_ID",
                "text": config.device_runtime_key_id,
            },
            {
                "type": "plain_text",
                "name": "DEVICE_RUNTIME_SECRET_PREVIOUS_KEY_ID",
                "text": config.previous_device_runtime_key_id.clone().unwrap_or_default(),
            },
            {
                "type": "plain_text",
                "name": "AUTH_ROTATION_GRACE_UNTIL_MS",
                "text": config.auth_rotation_grace_until_ms.map(|value| value.to_string()).unwrap_or_default(),
            },
        ],
    });

    if let Some(migration) = worker_migration_metadata(plan) {
        metadata["migrations"] = migration;
    }

    metadata
}

fn is_duplicate_sqlite_class_migration_error(message: &str, class_name: &str) -> bool {
    message.contains(class_name)
        && message.contains("Cannot apply new-sqlite-class migration")
        && message.contains("already depended on by existing Durable Objects")
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
    migration_plan: WorkerMigrationPlan,
) -> Result<(), String> {
    let metadata = build_worker_metadata(config, migration_plan);
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

async fn upload_worker_script_with_migration_retry(
    client: &Client,
    api_token: &str,
    account_id: &str,
    worker_name: &str,
    worker_script: &str,
    config: &WorkerDeployConfig,
    worker_exists: bool,
) -> Result<(), String> {
    let migration_plan = if worker_exists {
        WorkerMigrationPlan::UpgradeDeviceRegistry
    } else {
        WorkerMigrationPlan::FreshV3
    };

    match upload_worker_script(
        client,
        api_token,
        account_id,
        worker_name,
        worker_script,
        config,
        migration_plan,
    )
    .await
    {
        Ok(()) => Ok(()),
        Err(error)
            if migration_plan == WorkerMigrationPlan::UpgradeDeviceRegistry
                && is_duplicate_sqlite_class_migration_error(
                    &error,
                    "DeviceRegistryDurableObject",
                ) =>
        {
            eprintln!(
                "DeviceRegistryDurableObject migration already exists; retrying worker upload without migrations"
            );
            upload_worker_script(
                client,
                api_token,
                account_id,
                worker_name,
                worker_script,
                config,
                WorkerMigrationPlan::None,
            )
            .await
        }
        Err(error)
            if migration_plan == WorkerMigrationPlan::FreshV3
                && is_duplicate_sqlite_class_migration_error(&error, "InboxDurableObject") =>
        {
            Err(format!(
                "{error}. The Cloudflare account already has Durable Object state for this worker name; retry Upgrade Cloudflare runtime so TapChat can apply only the device registry migration."
            ))
        }
        Err(error) => Err(error),
    }
}

/// Write secret to Worker via REST API
pub async fn write_worker_secret(
    client: &Client,
    api_token: &str,
    account_id: &str,
    worker_name: &str,
    secret_name: &str,
    secret_value: &str,
) -> Result<(), String> {
    let url = format!(
        "{}/accounts/{}/workers/scripts/{}/secrets",
        CF_API_BASE, account_id, worker_name
    );

    let response = client
        .put(&url)
        .header("Authorization", format!("Bearer {}", api_token))
        .json(&serde_json::json!({
            "name": secret_name,
            "text": secret_value,
            "type": "secret_text",
        }))
        .send()
        .await
        .map_err(|e| format!("Secret write request failed: {}", e))?;

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

        return Err(format!(
            "Failed to write secret {}: {}",
            secret_name, error_msg
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

/// Check if a Worker script exists
pub async fn check_worker_exists(
    client: &Client,
    api_token: &str,
    account_id: &str,
    worker_name: &str,
) -> Result<bool, String> {
    let url = format!(
        "{}/accounts/{}/workers/scripts/{}/",
        CF_API_BASE, account_id, worker_name
    );

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", api_token))
        .send()
        .await
        .map_err(|e| format!("Worker check request failed: {}", e))?;

    let status = response.status();
    reject_unauthorized(status)?;
    if status.is_success() {
        return Ok(true);
    }
    if status == StatusCode::NOT_FOUND {
        return Ok(false);
    }

    Err(format!("Worker check failed before upload: HTTP {status}"))
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
    create_r2_bucket(&client, api_token, account_id, &config.preview_bucket_name).await?;

    // Phase 2: Upload Worker script
    progress_callback(DeployProgress {
        phase: DeployPhase::UploadingWorker,
        message: "Uploading Worker script...".into(),
        progress_percent: 40,
    });

    let worker_exists =
        check_worker_exists(&client, api_token, account_id, &config.worker_name).await?;

    upload_worker_script_with_migration_retry(
        &client,
        api_token,
        account_id,
        &config.worker_name,
        worker_script,
        config,
        worker_exists,
    )
    .await?;

    // Phase 2.5: Enable workers.dev subdomain routing
    progress_callback(DeployProgress {
        phase: DeployPhase::UploadingWorker,
        message: "Enabling workers.dev routing...".into(),
        progress_percent: 50,
    });

    enable_workers_dev_routing(&client, api_token, account_id, &config.worker_name).await?;

    // Phase 3: Write secrets
    progress_callback(DeployProgress {
        phase: DeployPhase::WritingSecrets,
        message: "Writing authentication secrets...".into(),
        progress_percent: 60,
    });

    write_worker_secret(
        &client,
        api_token,
        account_id,
        &config.worker_name,
        "SHARING_INTERNAL_SECRET",
        &config.sharing_token_secret,
    )
    .await?;
    write_worker_secret(
        &client,
        api_token,
        account_id,
        &config.worker_name,
        "DEVICE_RUNTIME_SECRET",
        &config.device_runtime_secret,
    )
    .await?;
    if let Some(previous) = &config.previous_device_runtime_secret {
        write_worker_secret(
            &client,
            api_token,
            account_id,
            &config.worker_name,
            "DEVICE_RUNTIME_SECRET_PREVIOUS",
            previous,
        )
        .await?;
    }
    // Phase 4: Get deployment URL
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

    // Verify Worker exists before returning
    progress_callback(DeployProgress {
        phase: DeployPhase::VerifyingDeployment,
        message: "Verifying Worker deployment...".into(),
        progress_percent: 85,
    });

    // Wait for Worker to be globally deployed (check existence first)
    let worker_exists = check_worker_exists(&client, api_token, account_id, &config.worker_name)
        .await
        .unwrap_or(false);

    if !worker_exists {
        // Worker might still be deploying, wait a bit and retry
        for i in 0..5 {
            progress_callback(DeployProgress {
                phase: DeployPhase::VerifyingDeployment,
                message: format!("Waiting for deployment... (attempt {})", i + 1),
                progress_percent: 85 + i as u8,
            });
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            if check_worker_exists(&client, api_token, account_id, &config.worker_name)
                .await
                .unwrap_or(false)
            {
                break;
            }
        }
    }

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
        preview_bucket_name: Some(config.preview_bucket_name.clone()),
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
        build_worker_metadata, is_duplicate_sqlite_class_migration_error, WorkerDeployConfig,
        WorkerMigrationPlan, WORKER_COMPATIBILITY_DATE,
    };

    fn deploy_config() -> WorkerDeployConfig {
        WorkerDeployConfig {
            worker_name: "tapchat-test".into(),
            public_base_url: None,
            deployment_region: "test".into(),
            bucket_name: "tapchat-storage".into(),
            preview_bucket_name: "tapchat-storage-preview".into(),
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
    fn fresh_worker_metadata_includes_v3_device_registry() {
        let metadata = build_worker_metadata(&deploy_config(), WorkerMigrationPlan::FreshV3);
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

        let classes = metadata["migrations"]["new_sqlite_classes"]
            .as_array()
            .expect("new sqlite classes");
        assert!(classes.iter().any(|class| class == "InboxDurableObject"));
        assert!(classes
            .iter()
            .any(|class| class == "GroupOutboxDurableObject"));
        assert!(classes
            .iter()
            .any(|class| class == "DeviceRegistryDurableObject"));
        assert_eq!(metadata["migrations"]["tag"].as_str(), Some("v3"));
    }

    #[test]
    fn upgrade_worker_metadata_only_creates_device_registry() {
        let metadata =
            build_worker_metadata(&deploy_config(), WorkerMigrationPlan::UpgradeDeviceRegistry);
        let classes = metadata["migrations"]["new_sqlite_classes"]
            .as_array()
            .expect("new sqlite classes");
        assert!(!classes.iter().any(|class| class == "InboxDurableObject"));
        assert_eq!(classes.len(), 1);
        assert_eq!(classes[0].as_str(), Some("DeviceRegistryDurableObject"));
    }

    #[test]
    fn no_migration_plan_keeps_bindings_without_migration_payload() {
        let metadata = build_worker_metadata(&deploy_config(), WorkerMigrationPlan::None);
        assert!(metadata.get("migrations").is_none());
        let bindings = metadata["bindings"].as_array().expect("bindings");
        assert!(bindings
            .iter()
            .any(|binding| binding["name"] == "GROUP_OUTBOX"));
    }

    #[test]
    fn duplicate_sqlite_class_error_detection_is_class_specific() {
        let error = "Failed to upload worker: Cannot apply new-sqlite-class migration to class 'InboxDurableObject' that is already depended on by existing Durable Objects";
        assert!(is_duplicate_sqlite_class_migration_error(
            error,
            "InboxDurableObject"
        ));
        assert!(!is_duplicate_sqlite_class_migration_error(
            error,
            "GroupOutboxDurableObject"
        ));
    }
}

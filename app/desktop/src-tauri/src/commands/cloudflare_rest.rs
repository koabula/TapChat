//! Cloudflare REST API Deployment Module
//!
//! This module implements direct deployment to Cloudflare via REST API,
//! bypassing the need for wrangler CLI. It uses the OAuth tokens obtained
//! from our minimal login implementation.

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Cloudflare API base URL
const CF_API_BASE: &str = "https://api.cloudflare.com/client/v4";

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
    pub public_base_url: Option<String>,
    pub deployment_region: String,
    pub bucket_name: String,
    pub preview_bucket_name: String,
    pub sharing_token_secret: String,
    pub bootstrap_token_secret: String,
    pub max_inline_bytes: u32,
    pub retention_days: u32,
    pub rate_limit_per_minute: u32,
    pub rate_limit_per_hour: u32,
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
struct CloudflareErrorDetail {
    #[serde(default)]
    code: Option<i64>,
    #[serde(default)]
    message: Option<String>,
}

/// Create R2 bucket via REST API
pub async fn create_r2_bucket(
    client: &Client,
    api_token: &str,
    account_id: &str,
    bucket_name: &str,
) -> Result<(), String> {
    let url = format!("{}/accounts/{}/r2/buckets/{}", CF_API_BASE, account_id, bucket_name);

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

    Err(format!("Failed to create bucket {}: {}", bucket_name, error_msg))
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
    // Build metadata for bindings
    let metadata = serde_json::json!({
        "main_module": "worker.js",
        "compatibility_date": "2024-01-01",
        "compatibility_flags": ["nodejs_compat_v2"],
        "bindings": [
            {
                "type": "durable_object_namespace",
                "binding_id": "INBOX",
                "name": "INBOX",
                "class_name": "InboxDurableObject",
                "script_name": worker_name,
            },
            {
                "type": "r2_bucket",
                "binding_id": "STORAGE",
                "name": "STORAGE",
                "bucket_name": config.bucket_name,
            },
            {
                "type": "r2_bucket",
                "binding_id": "STORAGE_PREVIEW",
                "name": "STORAGE_PREVIEW",
                "bucket_name": config.preview_bucket_name,
            },
            {
                "type": "var_text",
                "binding_id": "DEPLOYMENT_REGION",
                "name": "DEPLOYMENT_REGION",
                "text": config.deployment_region,
            },
            {
                "type": "var_text",
                "binding_id": "MAX_INLINE_BYTES",
                "name": "MAX_INLINE_BYTES",
                "text": config.max_inline_bytes.to_string(),
            },
            {
                "type": "var_text",
                "binding_id": "RETENTION_DAYS",
                "name": "RETENTION_DAYS",
                "text": config.retention_days.to_string(),
            },
            {
                "type": "var_text",
                "binding_id": "RATE_LIMIT_PER_MINUTE",
                "name": "RATE_LIMIT_PER_MINUTE",
                "text": config.rate_limit_per_minute.to_string(),
            },
            {
                "type": "var_text",
                "binding_id": "RATE_LIMIT_PER_HOUR",
                "name": "RATE_LIMIT_PER_HOUR",
                "text": config.rate_limit_per_hour.to_string(),
            },
        ],
        "migrations": [
            {
                "tag": "v1",
                "new_classes": ["InboxDurableObject"],
            }
        ],
    });

    // Build multipart form data
    // Cloudflare expects: metadata (JSON) + script (JS)
    let form = reqwest::multipart::Form::new()
        .part("metadata", reqwest::multipart::Part::text(metadata.to_string())
            .mime_str("application/json")
            .map_err(|e| format!("MIME type error: {}", e))?)
        .part("worker.js", reqwest::multipart::Part::text(worker_script.to_string())
            .file_name("worker.js")
            .mime_str("application/javascript+module")
            .map_err(|e| format!("MIME type error: {}", e))?)
        .text("main_module", "worker.js");

    let url = format!("{}/accounts/{}/workers/scripts/{}/contents",
        CF_API_BASE, account_id, worker_name);

    let response = client
        .put(&url)
        .header("Authorization", format!("Bearer {}", api_token))
        .multipart(form)
        .send()
        .await
        .map_err(|e| format!("Worker upload request failed: {}", e))?;

    let status = response.status();

    if !status.is_success() {
        let error_body = response
            .text()
            .await
            .map_err(|e| format!("Failed to read error response: {}", e))?;

        let cf_error: CloudflareError = serde_json::from_str(&error_body)
            .map_err(|e| format!("Failed to parse error response: {} (body: {})", e, error_body))?;

        let error_msg = cf_error
            .errors
            .first()
            .and_then(|e| e.message.clone())
            .unwrap_or_else(|| format!("HTTP {}", status));

        return Err(format!("Failed to upload worker: {}", error_msg));
    }

    Ok(())
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
    let url = format!("{}/accounts/{}/workers/scripts/{}/secrets",
        CF_API_BASE, account_id, worker_name);

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

        return Err(format!("Failed to write secret {}: {}", secret_name, error_msg));
    }

    Ok(())
}

/// Get Worker deployment info
pub async fn get_worker_info(
    client: &Client,
    api_token: &str,
    account_id: &str,
    worker_name: &str,
) -> Result<serde_json::Value, String> {
    let url = format!("{}/accounts/{}/workers/scripts/{}/subdomain",
        CF_API_BASE, account_id, worker_name);

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", api_token))
        .send()
        .await
        .map_err(|e| format!("Worker info request failed: {}", e))?;

    let status = response.status();

    if !status.is_success() {
        let error_body = response
            .text()
            .await
            .map_err(|e| format!("Failed to read error response: {}", e))?;

        return Err(format!("Failed to get worker info: HTTP {} - {}", status, error_body));
    }

    response
        .json()
        .await
        .map_err(|e| format!("Failed to parse worker info response: {}", e))
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

    upload_worker_script(&client, api_token, account_id, &config.worker_name, worker_script, config).await?;

    // Phase 3: Write secrets
    progress_callback(DeployProgress {
        phase: DeployPhase::WritingSecrets,
        message: "Writing authentication secrets...".into(),
        progress_percent: 60,
    });

    write_worker_secret(&client, api_token, account_id, &config.worker_name,
        "SHARING_TOKEN_SECRET", &config.sharing_token_secret).await?;
    write_worker_secret(&client, api_token, account_id, &config.worker_name,
        "BOOTSTRAP_TOKEN_SECRET", &config.bootstrap_token_secret).await?;

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
            format!("https://{}.workers.dev", config.worker_name)
        }
    } else {
        // Try to get the actual workers.dev subdomain
        let subdomain_info = get_worker_info(&client, api_token, account_id, &config.worker_name)
            .await.ok();

        // Extract subdomain as String to avoid lifetime issues
        let subdomain = subdomain_info
            .and_then(|v| {
                v.get("result")
                    .and_then(|r| r.get("subdomain"))
                    .and_then(|s| s.as_str())
                    .map(|s| s.to_string())
            });

        match subdomain {
            Some(s) => format!("https://{}.{}.workers.dev", config.worker_name, s),
            None => format!("https://{}.workers.dev", config.worker_name),
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
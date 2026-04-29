//! Cloudflare deployment commands for Desktop App
//!
//! Uses embedded minimal wrangler for OAuth login and REST API for deployment.

use std::path::PathBuf;

use serde::Serialize;
use tauri::{AppHandle, Emitter, State};

use tapchat_core::cli::profile::RuntimeMetadata;
use tapchat_core::cli::runtime::derive_cloudflare_defaults;
use tapchat_core::{CoreCommand};

use crate::commands::cloudflare_rest::{
    self, DeployPhase, DeployProgress, DeployResult, OAuthTokens, WhoamiResult, WorkerDeployConfig,
};
use crate::lifecycle::{CoreInput, drive_core_with_handle};
use crate::state::AppState;
use crate::timetest;

/// Preflight check result
#[derive(Debug, Clone, Serialize)]
pub struct PreflightResult {
    /// Has valid OAuth token stored
    pub authenticated: bool,
    /// OAuth token exists but needs verification
    pub token_stored: bool,
    /// Embedded runtime is available
    pub embedded_available: bool,
    /// Can proceed with deployment
    pub ready: bool,
    /// Blocking error message
    pub error: Option<String>,
    /// Account info if authenticated
    pub account: Option<AccountInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountInfo {
    pub account_id: String,
    pub account_name: String,
    pub email: Option<String>,
}

/// OAuth login result for frontend
#[derive(Debug, Clone, Serialize)]
pub struct LoginResult {
    pub success: bool,
    pub account_id: Option<String>,
    pub account_name: Option<String>,
    pub error: Option<String>,
}

/// Resolve embedded runtime root
fn resolve_embedded_runtime_root() -> Option<PathBuf> {
    // Check environment variable first
    if let Ok(root) = std::env::var("TAPCHAT_DESKTOP_RUNTIME_ROOT") {
        let path = PathBuf::from(&root);
        if path.exists() {
            return Some(path);
        }
    }

    // In bundled mode, check relative to executable
    let exe_path = std::env::current_exe().ok()?;
    let exe_dir = exe_path.parent()?;

    // Check for embedded directory
    let embedded = exe_dir.join("embedded");
    if embedded.exists() {
        return Some(embedded);
    }

    // Development mode: check project structure
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dev_embedded = manifest_dir.join("embedded");
    if dev_embedded.exists() {
        return Some(dev_embedded);
    }

    None
}

/// Resolve embedded Node.js path
fn resolve_embedded_node() -> Option<PathBuf> {
    let runtime_root = resolve_embedded_runtime_root()?;

    // Windows
    if cfg!(windows) {
        let node_exe = runtime_root.join("node").join("node.exe");
        if node_exe.exists() {
            return Some(node_exe);
        }
    }

    // macOS/Linux
    let node_bin = runtime_root.join("node").join("bin").join("node");
    if node_bin.exists() {
        return Some(node_bin);
    }

    // Fallback to system node
    None
}

/// Run embedded wrangler script (login.mjs or whoami.mjs)
async fn run_wrangler_script(script_name: &str) -> Result<String, String> {
    let runtime_root = resolve_embedded_runtime_root()
        .ok_or_else(|| "Embedded runtime not found. Please reinstall TapChat.")?;

    let script_path = runtime_root.join("wrangler").join(script_name);

    if !script_path.exists() {
        return Err(format!("Script {} not found in embedded runtime", script_name));
    }

    // Get Node.js path
    let node_path = resolve_embedded_node()
        .unwrap_or_else(|| PathBuf::from("node")); // Fallback to system node

    // Run script
    let output = tokio::process::Command::new(&node_path)
        .arg(&script_path)
        .output()
        .await
        .map_err(|e| format!("Failed to run {}: {}", script_name, e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(format!("{} failed: {}", script_name, stderr.trim()));
    }

    Ok(stdout)
}

/// Parse JSON output from wrangler scripts
fn parse_wrangler_output<T: serde::de::DeserializeOwned>(output: &str) -> Result<T, String> {
    // Output may have multiple JSON lines, we want the last one (final result)
    let json_lines = output
        .lines()
        .filter(|line| line.trim().starts_with('{'))
        .collect::<Vec<_>>();

    let json = json_lines
        .last()
        .ok_or_else(|| "No JSON output found".to_string())?;

    serde_json::from_str(json)
        .map_err(|e| format!("Failed to parse JSON output: {} (input: {})", e, json))
}

/// Check preflight status
#[tauri::command]
pub async fn cloudflare_preflight() -> Result<PreflightResult, String> {
    // Check if embedded runtime is available
    let embedded_available = resolve_embedded_runtime_root().is_some();

    // Run whoami to check authentication
    let whoami_result = run_wrangler_script("whoami.mjs").await;

    // Determine token_stored before matching
    let token_stored = whoami_result.is_ok();

    let (authenticated, account) = match whoami_result {
        Ok(output) => {
            let whoami: WhoamiResult = parse_wrangler_output(&output)?;

            if whoami.authenticated {
                let account = whoami.accounts
                    .first()
                    .map(|a| AccountInfo {
                        account_id: a.account_id.clone(),
                        account_name: a.account_name.clone(),
                        email: whoami.email.clone(),
                    });

                (true, account)
            } else {
                (false, None)
            }
        }
        Err(_) => (false, None),
    };

    // Determine if ready
    let ready = embedded_available && authenticated;
    let error = if !embedded_available {
        Some("Embedded runtime not found. Please reinstall TapChat.".into())
    } else if !authenticated {
        Some("Not logged in to Cloudflare. Click 'Connect Cloudflare' to authorize.".into())
    } else {
        None
    };

    Ok(PreflightResult {
        authenticated,
        token_stored,
        embedded_available,
        ready,
        error,
        account,
    })
}

/// Perform OAuth login
#[tauri::command]
pub async fn cloudflare_login(app: AppHandle) -> Result<LoginResult, String> {
    // Emit progress
    let _ = app.emit("cloudflare-progress", DeployProgress {
        phase: DeployPhase::Preflight,
        message: "Starting Cloudflare authorization...".into(),
        progress_percent: 10,
    });

    // Run login script
    let login_output = run_wrangler_script("login.mjs").await?;

    // Parse result
    let login_result: OAuthTokens = parse_wrangler_output(&login_output)?;

    if !login_result.success {
        return Ok(LoginResult {
            success: false,
            account_id: None,
            account_name: None,
            error: login_result.error,
        });
    }

    let _ = app.emit("cloudflare-progress", DeployProgress {
        phase: DeployPhase::Complete,
        message: "Authorization successful!".into(),
        progress_percent: 100,
    });

    Ok(LoginResult {
        success: true,
        account_id: login_result.account_id,
        account_name: login_result.account_name,
        error: None,
    })
}

/// Deploy Cloudflare Worker via REST API
#[tauri::command]
pub async fn cloudflare_deploy(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<DeployResult, String> {
    let deploy_start = std::time::Instant::now();
    let abs_start = crate::ts_ms();
    timetest!("deploy_begin ts={}", abs_start);

    let inner = state.inner.read().await;

    // Get identity info - identity must exist, but bundle is optional for first deployment
    let identity = inner.engine.local_identity();

    if identity.is_none() {
        return Ok(DeployResult {
            success: false,
            worker_name: "".into(),
            worker_url: "".into(),
            error: Some("No identity created yet. Please complete initial setup first.".into()),
            account_id: None,
            bucket_name: None,
            preview_bucket_name: None,
        });
    }

    let identity_ref = identity.unwrap();
    let user_id = identity_ref.user_identity.user_id.clone();
    let device_id = identity_ref.device_identity.device_id.clone();

    // Get profile name
    let profile_name = inner.profile_manager.get_active_metadata().await
        .map(|m| m.name)
        .unwrap_or_else(|| "default".to_string());

    drop(inner);

    // Run whoami to get OAuth token
    let _ = app.emit("cloudflare-progress", DeployProgress {
        phase: DeployPhase::Preflight,
        message: "Checking authentication...".into(),
        progress_percent: 5,
    });

    let whoami_output = run_wrangler_script("whoami.mjs").await?;
    let whoami: WhoamiResult = parse_wrangler_output(&whoami_output)?;

    if !whoami.authenticated {
        return Ok(DeployResult {
            success: false,
            worker_name: "".into(),
            worker_url: "".into(),
            error: Some("Not authenticated. Please login first.".into()),
            account_id: None,
            bucket_name: None,
            preview_bucket_name: None,
        });
    }

    // Get account_id and API token
    let account_id = whoami.active_account_id
        .or_else(|| whoami.accounts.first().map(|a| a.account_id.clone()))
        .ok_or_else(|| "No Cloudflare account found".to_string())?;

    // Load OAuth token from stored location (wrangler config)
    let api_token = load_oauth_token()?;

    // Load embedded Worker script
    let runtime_root = resolve_embedded_runtime_root()
        .ok_or_else(|| "Embedded runtime not found".to_string())?;

    let worker_script = cloudflare_rest::load_embedded_worker_script(&runtime_root)?;

    // Generate deployment config
    let defaults = derive_cloudflare_defaults(&profile_name, &user_id, &device_id);

    let config = WorkerDeployConfig {
        worker_name: defaults.worker_name,
        public_base_url: Some(defaults.public_base_url).filter(|s| !s.is_empty()),
        deployment_region: defaults.deployment_region,
        bucket_name: defaults.bucket_name,
        preview_bucket_name: defaults.preview_bucket_name,
        sharing_token_secret: defaults.sharing_token_secret,
        bootstrap_token_secret: defaults.bootstrap_token_secret,
        max_inline_bytes: 4096,
        retention_days: 30,
        rate_limit_per_minute: 60,
        rate_limit_per_hour: 600,
    };

    // Deploy via REST API
    let result = cloudflare_rest::deploy_via_rest_api(
        &api_token,
        &account_id,
        &worker_script,
        &config,
        |progress| {
            let _ = app.emit("cloudflare-progress", progress);
        },
    ).await?;

    if !result.success {
        let elapsed_ms = deploy_start.elapsed().as_millis();
        timetest!("deploy_done success=false elapsed_ms={} ts={}", elapsed_ms, abs_start + elapsed_ms as u128);
        return Ok(result);
    }

    // Wait for deployment to be ready
    let _ = app.emit("cloudflare-progress", DeployProgress {
        phase: DeployPhase::VerifyingDeployment,
        message: "Waiting for deployment to be ready...".into(),
        progress_percent: 85,
    });

    tapchat_core::cli::runtime::wait_until_ready(&result.worker_url)
        .await
        .map_err(|e| format!("Deployment not ready: {}", e))?;

    // Wait for secrets to propagate in Worker environment
    // Cloudflare Workers secrets need additional time to become available
    let _ = app.emit("cloudflare-progress", DeployProgress {
        phase: DeployPhase::VerifyingDeployment,
        message: "Waiting for secrets to propagate...".into(),
        progress_percent: 88,
    });
    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

    // Bootstrap device bundle
    let _ = app.emit("cloudflare-progress", DeployProgress {
        phase: DeployPhase::VerifyingDeployment,
        message: "Bootstrapping device...".into(),
        progress_percent: 90,
    });

    let deployment_bundle = tapchat_core::cli::runtime::bootstrap_device_bundle(
        &result.worker_url,
        &config.bootstrap_token_secret,
        &user_id,
        &device_id,
    )
    .await
    .map_err(|e| format!("Bootstrap failed: {}", e))?;

    // Import deployment bundle
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::ImportDeploymentBundle {
            bundle: deployment_bundle,
        }),
    )
    .await
    .map_err(|e| format!("Import deployment failed: {}", e))?;

    // Save runtime metadata
    {
        let inner = state.inner.read().await;
        let service_root = resolve_embedded_runtime_root();

        let runtime = RuntimeMetadata {
            pid: None,
            base_url: Some(result.worker_url.clone()),
            websocket_base_url: Some(result.worker_url.replace("https://", "wss://").replace("http://", "ws://")),
            bootstrap_secret: Some(config.bootstrap_token_secret.clone()),
            sharing_secret: Some(config.sharing_token_secret.clone()),
            mode: Some("cloudflare".into()),
            workspace_root: None,
            service_root: service_root,
            worker_name: Some(config.worker_name.clone()),
            public_base_url: Some(result.worker_url.clone()),
            deploy_url: Some(result.worker_url.clone()),
            deployment_region: Some(config.deployment_region.clone()),
            bucket_name: Some(config.bucket_name.clone()),
            preview_bucket_name: Some(config.preview_bucket_name.clone()),
            last_deployed_at: None,
        };

        inner.profile_manager.save_runtime_metadata(&runtime).await
            .map_err(|e| format!("Save runtime metadata failed: {}", e))?;
    }

    let _ = app.emit("cloudflare-progress", DeployProgress {
        phase: DeployPhase::Complete,
        message: "Deployment complete!".into(),
        progress_percent: 100,
    });

    let elapsed_secs = deploy_start.elapsed().as_secs_f64();
    timetest!("deploy_done success=true worker_url={} elapsed_secs={:.1} ts={}",
        result.worker_url, elapsed_secs, abs_start + ((elapsed_secs * 1000.0) as u128));

    Ok(result)
}

/// Load OAuth token from wrangler config file
fn load_oauth_token() -> Result<String, String> {
    use std::fs;

    let config_file = dirs::home_dir()
        .ok_or_else(|| "Cannot determine home directory".to_string())?
        .join(".wrangler")
        .join("config")
        .join("default.toml");

    if !config_file.exists() {
        return Err("OAuth token not found. Please login first.".into());
    }

    let content = fs::read_to_string(&config_file)
        .map_err(|e| format!("Failed to read token file: {}", e))?;

    // Parse simple TOML format: oauth_token = "..."
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("oauth_token") {
            // Extract value between quotes
            let start = trimmed.find('"').ok_or_else(|| "Invalid token format".to_string())?;
            let end = trimmed.rfind('"').ok_or_else(|| "Invalid token format".to_string())?;

            if start < end {
                let token = trimmed[start + 1..end].to_string();
                if !token.is_empty() {
                    return Ok(token);
                }
            }
        }
    }

    Err("OAuth token not found in config file".into())
}

/// Check deployment status
#[tauri::command]
pub async fn cloudflare_status(
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let inner = state.inner.read().await;

    let deployment = inner.engine.refresh_snapshot().deployment;

    Ok(serde_json::json!({
        "bound": deployment.is_some(),
        "endpoint": deployment.as_ref().map(|d| d.deployment_bundle.inbox_http_endpoint.clone())
    }))
}
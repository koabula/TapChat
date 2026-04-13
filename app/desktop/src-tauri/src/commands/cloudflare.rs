use std::path::PathBuf;
use std::sync::Arc;

use serde::Serialize;
use tauri::{AppHandle, Emitter, State};
use tokio::sync::RwLock;

use tapchat_core::cli::profile::RuntimeMetadata;
use tapchat_core::model::DeploymentBundle;
use tapchat_core::{CoreCommand, CoreOutput};

use crate::lifecycle::{CoreInput, drive_core_with_handle};
use crate::platform::profile::ProfileManagerInner;
use crate::state::AppState;

#[derive(Debug, Clone, Serialize)]
pub struct PreflightResult {
    pub wrangler_installed: bool,
    pub wrangler_logged_in: bool,
    pub ready: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeployProgress {
    pub phase: String,
    pub message: String,
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeployResult {
    pub success: bool,
    pub worker_url: Option<String>,
    pub error: Option<String>,
}

// Find the service root for the Cloudflare worker
fn resolve_service_root() -> Option<PathBuf> {
    // In bundled mode, use embedded runtime root
    if let Ok(root) = std::env::var("TAPCHAT_DESKTOP_RUNTIME_ROOT") {
        let path = PathBuf::from(&root);
        if path.exists() {
            return Some(path.join("services").join("cloudflare"));
        }
    }

    // In dev mode, look relative to the project root
    let exe_path = std::env::current_exe().ok()?;
    let project_root = exe_path
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())?;

    let service_root = project_root.join("services").join("cloudflare");
    if service_root.exists() {
        return Some(service_root);
    }

    None
}

#[tauri::command]
pub async fn cloudflare_preflight() -> Result<PreflightResult, String> {
    // Check if wrangler is available in PATH
    let wrangler_installed = tokio::process::Command::new("wrangler")
        .arg("--version")
        .output()
        .await
        .is_ok();

    if !wrangler_installed {
        return Ok(PreflightResult {
            wrangler_installed: false,
            wrangler_logged_in: false,
            ready: false,
            error: Some("wrangler CLI not found. Install it with: npm install -g wrangler".into()),
        });
    }

    // Check if logged in
    let whoami = tokio::process::Command::new("wrangler")
        .arg("whoami")
        .output()
        .await
        .map_err(|e| e.to_string())?;

    let wrangler_logged_in = whoami.status.success();

    // Check if service root exists
    let service_root_exists = resolve_service_root().is_some();

    Ok(PreflightResult {
        wrangler_installed,
        wrangler_logged_in,
        ready: wrangler_installed && wrangler_logged_in && service_root_exists,
        error: if !service_root_exists {
            Some("Cloudflare worker source not found. Please run from project directory or set TAPCHAT_DESKTOP_RUNTIME_ROOT".into())
        } else {
            None
        },
    })
}

#[tauri::command]
pub async fn cloudflare_login() -> Result<bool, String> {
    // Spawn `wrangler login` — it opens the browser for OAuth
    let status = tokio::process::Command::new("wrangler")
        .arg("login")
        .status()
        .await
        .map_err(|e| e.to_string())?;

    Ok(status.success())
}

#[tauri::command]
pub async fn cloudflare_deploy(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<DeployResult, String> {
    let inner = state.inner.read().await;

    // Get identity info
    let identity = inner.engine.local_identity();
    let bundle = inner.engine.local_bundle();

    if identity.is_none() || bundle.is_none() {
        return Ok(DeployResult {
            success: false,
            worker_url: None,
            error: Some("No identity created yet".into()),
        });
    }

    let user_id = bundle.unwrap().user_id.clone();
    let device_id = identity.unwrap().device_identity.device_id.clone();

    // Get profile name
    let profile_name = inner.profile_manager.get_active_metadata().await
        .map(|m| m.name)
        .unwrap_or_else(|| "default".to_string());

    drop(inner);

    // Emit progress
    let _ = app.emit("cloudflare-progress", DeployProgress {
        phase: "config".to_string(),
        message: "Preparing deployment config...".to_string(),
        complete: false,
    });

    // Find service root
    let service_root = resolve_service_root()
        .ok_or_else(|| "Could not find Cloudflare worker source directory")?;

    // Generate config defaults
    let defaults = tapchat_core::cli::runtime::derive_cloudflare_defaults(
        &profile_name,
        &user_id,
        &device_id,
    );

    // For now, use defaults without overrides
    let config = tapchat_core::cli::runtime::resolve_cloudflare_config(
        &defaults,
        &tapchat_core::cli::runtime::CloudflareDeployOverrides::default(),
    );

    let _ = app.emit("cloudflare-progress", DeployProgress {
        phase: "deploy".to_string(),
        message: "Deploying Cloudflare worker...".to_string(),
        complete: false,
    });

    // Run deploy
    let deploy_result = tapchat_core::cli::runtime::deploy_cloudflare_runtime(
        &service_root,
        &config,
    )
    .await
    .map_err(|e| e.to_string())?;

    if !deploy_result.success {
        return Ok(DeployResult {
            success: false,
            worker_url: None,
            error: deploy_result.stderr_summary,
        });
    }

    let base_url = deploy_result.effective_public_base_url.clone();
    let bootstrap_secret = config.bootstrap_token_secret.clone();

    let _ = app.emit("cloudflare-progress", DeployProgress {
        phase: "wait".to_string(),
        message: "Waiting for deployment to be ready...".to_string(),
        complete: false,
    });

    // Wait for deployment to be ready
    tapchat_core::cli::runtime::wait_until_ready(&base_url)
        .await
        .map_err(|e| e.to_string())?;

    let _ = app.emit("cloudflare-progress", DeployProgress {
        phase: "bootstrap".to_string(),
        message: "Bootstrapping device bundle...".to_string(),
        complete: false,
    });

    // Bootstrap device bundle
    let deployment_bundle = tapchat_core::cli::runtime::bootstrap_device_bundle(
        &base_url,
        &bootstrap_secret,
        &user_id,
        &device_id,
    )
    .await
    .map_err(|e| e.to_string())?;

    // Import deployment bundle into CoreEngine
    drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::ImportDeploymentBundle {
            bundle: deployment_bundle,
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    // Save runtime metadata to profile
    {
        let inner = state.inner.read().await;
        let runtime = RuntimeMetadata {
            pid: None,
            base_url: Some(base_url.clone()),
            websocket_base_url: Some(base_url.replace("https://", "wss://").replace("http://", "ws://")),
            bootstrap_secret: Some(bootstrap_secret),
            sharing_secret: Some(config.sharing_token_secret),
            mode: Some("cloudflare".to_string()),
            workspace_root: None,
            service_root: Some(service_root),
            worker_name: Some(deploy_result.worker_name.clone()),
            public_base_url: Some(deploy_result.effective_public_base_url.clone()),
            deploy_url: Some(deploy_result.deploy_url.clone()),
            deployment_region: Some(deploy_result.deployment_region.clone()),
            bucket_name: Some(deploy_result.bucket_name.clone()),
            preview_bucket_name: Some(deploy_result.preview_bucket_name.clone()),
            last_deployed_at: None,
        };
        inner.profile_manager.save_runtime_metadata(&runtime).await
            .map_err(|e| e.to_string())?;
    }

    let _ = app.emit("cloudflare-progress", DeployProgress {
        phase: "complete".to_string(),
        message: "Deployment complete!".to_string(),
        complete: true,
    });

    Ok(DeployResult {
        success: true,
        worker_url: Some(base_url),
        error: None,
    })
}

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
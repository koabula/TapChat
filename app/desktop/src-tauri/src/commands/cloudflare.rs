//! Cloudflare deployment commands for Desktop App
//!
//! Uses Rust Cloudflare OAuth and REST API deployment.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

use tapchat_core::cli::profile::{Profile, RuntimeMetadata};
use tapchat_core::cli::runtime::derive_cloudflare_defaults;
use tapchat_core::cli::util::to_snake_case_json_string;
use tapchat_core::model::DeploymentBundle;
use tapchat_core::persistence::PersistedDeployment;
use tapchat_core::{CoreCommand, CoreEvent};

use crate::commands::cloudflare_rest::{
    self, DeployPhase, DeployProgress, DeployResult, WorkerDeployConfig,
};
use crate::commands::session::{set_ws_connection_snapshot, SessionStatus};
use crate::lifecycle::{drive_core_with_handle, CoreInput};
use crate::state::AppState;
use crate::state::SessionState;
use crate::timetest;

static CLOUDFLARE_DEPLOY_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

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

#[derive(Debug, Clone, Serialize)]
pub struct CloudflareRuntimeStatus {
    pub bound: bool,
    pub endpoint: Option<String>,
    pub features: Vec<String>,
    pub supports_group_outbox: bool,
    pub supports_welcome_pickup: bool,
    pub needs_upgrade: bool,
    pub last_error: Option<String>,
    pub state: String,
    pub action: Option<String>,
    pub details: Option<String>,
}

const REQUIRED_GROUP_RUNTIME_FEATURES: &[&str] = &[
    "group_outbox_mvp",
    "welcome_pickup_mvp",
    "message_requests",
    "short_group_invite",
    "group_member_subscribe",
];

fn status_from_features(
    bound: bool,
    endpoint: Option<String>,
    features: Vec<String>,
    last_error: Option<String>,
) -> CloudflareRuntimeStatus {
    let supports_group_outbox = features.iter().any(|feature| feature == "group_outbox_mvp");
    let supports_welcome_pickup = features
        .iter()
        .any(|feature| feature == "welcome_pickup_mvp");
    let has_message_requests = features.iter().any(|feature| feature == "message_requests");
    let has_short_group_invite = features
        .iter()
        .any(|feature| feature == "short_group_invite");
    let has_group_member_subscribe = features
        .iter()
        .any(|feature| feature == "group_member_subscribe");
    let needs_upgrade = bound
        && !(supports_group_outbox
            && supports_welcome_pickup
            && has_message_requests
            && has_short_group_invite
            && has_group_member_subscribe);
    let (state, action, details) = if !bound {
        (
            "missing".to_string(),
            Some("deploy".to_string()),
            Some("Cloudflare runtime is not deployed.".to_string()),
        )
    } else if last_error.is_some() {
        (
            "unreachable".to_string(),
            Some("redeploy".to_string()),
            last_error.clone(),
        )
    } else if needs_upgrade {
        (
            "outdated".to_string(),
            Some("upgrade".to_string()),
            Some("Cloudflare runtime is missing required features.".to_string()),
        )
    } else {
        ("ready".to_string(), None, None)
    };
    CloudflareRuntimeStatus {
        bound,
        endpoint,
        features,
        supports_group_outbox,
        supports_welcome_pickup,
        needs_upgrade,
        last_error,
        state,
        action,
        details,
    }
}

fn runtime_status(
    state: &str,
    action: Option<&str>,
    bound: bool,
    endpoint: Option<String>,
    features: Vec<String>,
    last_error: Option<String>,
    details: Option<String>,
) -> CloudflareRuntimeStatus {
    let mut status = status_from_features(bound, endpoint, features, last_error);
    status.state = state.to_string();
    status.action = action.map(str::to_string);
    status.details = details;
    status
}

pub async fn runtime_status_for_deployment(
    deployment: Option<PersistedDeployment>,
) -> CloudflareRuntimeStatus {
    let Some(deployment) = deployment else {
        return status_from_features(false, None, Vec::new(), None);
    };
    let endpoint = deployment.deployment_bundle.inbox_http_endpoint.clone();
    let local_features = deployment.deployment_bundle.runtime_config.features.clone();
    let client = match reqwest::Client::builder().build() {
        Ok(client) => client,
        Err(error) => {
            return status_from_features(
                true,
                Some(endpoint),
                local_features,
                Some(format!("failed to build runtime status client: {error}")),
            );
        }
    };
    let url = format!("{}/v1/deployment-bundle", endpoint.trim_end_matches('/'));
    match client.get(url).send().await {
        Ok(response) => {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            if !status.is_success() {
                return status_from_features(
                    true,
                    Some(endpoint),
                    local_features,
                    Some(format!(
                        "deployment bundle check returned HTTP {status}: {body}"
                    )),
                );
            }
            let normalized = to_snake_case_json_string(&body).unwrap_or(body);
            match serde_json::from_str::<DeploymentBundle>(&normalized) {
                Ok(bundle) => {
                    status_from_features(true, Some(endpoint), bundle.runtime_config.features, None)
                }
                Err(error) => status_from_features(
                    true,
                    Some(endpoint),
                    local_features,
                    Some(format!("deployment bundle parse failed: {error}")),
                ),
            }
        }
        Err(error) => status_from_features(
            true,
            Some(endpoint),
            local_features,
            Some(format!("deployment bundle check failed: {error}")),
        ),
    }
}

pub fn runtime_missing_group_outbox_message(status: &CloudflareRuntimeStatus) -> Option<String> {
    if !status.bound {
        return Some("runtime_missing_group_outbox: Cloudflare runtime is not deployed.".into());
    }
    if status.needs_upgrade {
        let missing = REQUIRED_GROUP_RUNTIME_FEATURES
            .iter()
            .filter(|feature| !status.features.iter().any(|value| value == **feature))
            .copied()
            .collect::<Vec<_>>();
        let suffix = if missing.is_empty() {
            status
                .last_error
                .as_ref()
                .map(|error| format!(" Runtime check failed: {error}"))
                .unwrap_or_default()
        } else {
            format!(" Missing features: {}.", missing.join(", "))
        };
        return Some(format!(
            "runtime_missing_group_outbox: Cloudflare runtime does not support group outbox. Upgrade runtime.{suffix}"
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{runtime_missing_group_outbox_message, status_from_features};

    #[test]
    fn runtime_status_requires_group_features_for_upgrade_clearance() {
        let legacy = status_from_features(
            true,
            Some("https://example.worker.dev".into()),
            vec!["generic_sync".into(), "message_requests".into()],
            None,
        );
        assert!(legacy.needs_upgrade);
        assert!(runtime_missing_group_outbox_message(&legacy)
            .expect("upgrade message")
            .contains("runtime_missing_group_outbox"));

        let current = status_from_features(
            true,
            Some("https://example.worker.dev".into()),
            vec![
                "generic_sync".into(),
                "message_requests".into(),
                "group_outbox_mvp".into(),
                "welcome_pickup_mvp".into(),
                "short_group_invite".into(),
                "group_member_subscribe".into(),
            ],
            None,
        );
        assert!(!current.needs_upgrade);
        assert!(runtime_missing_group_outbox_message(&current).is_none());
    }
}

/// Resolve embedded runtime root.
///
/// Resolution order (first match wins):
/// 1. `TAPCHAT_DESKTOP_RUNTIME_ROOT` environment variable
/// 2. Tauri resource directory (platform-correct for AppImage / .deb / .rpm / .app / .exe)
/// 3. `embedded/` next to the current executable
/// 4. `CARGO_MANIFEST_DIR/embedded` (development mode)
fn resolve_embedded_runtime_root(app_handle: Option<&AppHandle>) -> Option<PathBuf> {
    // 1. Environment variable override (highest priority)
    if let Ok(root) = std::env::var("TAPCHAT_DESKTOP_RUNTIME_ROOT") {
        let path = PathBuf::from(&root);
        if path.exists() {
            return Some(path);
        }
    }

    // 2. Tauri resource directory — the canonical path for bundled resources on every platform.
    //    On Linux this returns e.g. /usr/lib/tapchat-desktop for .deb/.rpm, or
    //    $APPDIR/usr/lib/tapchat-desktop for AppImage.
    if let Some(handle) = app_handle {
        if let Ok(resource_dir) = handle.path().resource_dir() {
            let embedded = resource_dir.join("embedded");
            if embedded.exists() {
                return Some(embedded);
            }
            // If resources were flattened, resource_dir itself may contain wrangler/
            if resource_dir.join("wrangler").exists() {
                return Some(resource_dir);
            }
        }
    }

    // 3. Relative to executable (works for portable / non-Tauri bundles)
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let embedded = exe_dir.join("embedded");
            if embedded.exists() {
                return Some(embedded);
            }
        }
    }

    // 4. Development mode: check project source tree
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dev_embedded = manifest_dir.join("embedded");
    if dev_embedded.exists() {
        return Some(dev_embedded);
    }

    None
}

/// Check preflight status
#[tauri::command]
pub async fn cloudflare_preflight(app: AppHandle) -> Result<PreflightResult, String> {
    let app_ref = Some(&app);

    // Check if embedded runtime is available
    let embedded_available = resolve_embedded_runtime_root(app_ref).is_some();

    // Rust OAuth/whoami; falls back to legacy Wrangler token reading, but never
    // launches Node.
    let whoami_result = crate::commands::cloudflare_oauth::whoami().await;
    let token_stored = whoami_result.is_ok();
    let (authenticated, account, auth_error) = match whoami_result {
        Ok(whoami) if whoami.authenticated => {
            let account = whoami.accounts.first().map(|a| AccountInfo {
                account_id: a.account_id.clone(),
                account_name: a.account_name.clone(),
                email: whoami.email.clone(),
            });
            (account.is_some(), account, None)
        }
        Ok(whoami) => (false, None, whoami.error),
        Err(error) => (false, None, Some(error.to_string())),
    };

    // Determine if ready
    let ready = embedded_available && authenticated;
    let error = if !embedded_available {
        Some("Embedded runtime not found. Please reinstall TapChat.".into())
    } else if !authenticated {
        Some(auth_error.unwrap_or_else(|| {
            "Not logged in to Cloudflare. Click 'Connect Cloudflare' to authorize.".into()
        }))
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
    let _ = app.emit(
        "cloudflare-progress",
        DeployProgress {
            phase: DeployPhase::Preflight,
            message: "Starting Cloudflare authorization...".into(),
            progress_percent: 10,
        },
    );

    let login_result = crate::commands::cloudflare_oauth::login()
        .await
        .map_err(|error| error.to_string())?;

    if !login_result.success {
        return Ok(LoginResult {
            success: false,
            account_id: None,
            account_name: None,
            error: login_result.error,
        });
    }

    let _ = app.emit(
        "cloudflare-progress",
        DeployProgress {
            phase: DeployPhase::Complete,
            message: "Authorization successful!".into(),
            progress_percent: 100,
        },
    );

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
    if CLOUDFLARE_DEPLOY_IN_PROGRESS
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Ok(DeployResult {
            success: false,
            worker_name: "".into(),
            worker_url: "".into(),
            error: Some("Cloudflare deployment already in progress.".into()),
            account_id: None,
            bucket_name: None,
            preview_bucket_name: None,
        });
    }
    let _deploy_guard = DeployProgressGuard;
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
    let profile_name = inner
        .profile_manager
        .get_active_metadata()
        .await
        .map(|m| m.name)
        .unwrap_or_else(|| "default".to_string());

    drop(inner);

    // Run Rust whoami to get OAuth token/account without launching Node.
    let _ = app.emit(
        "cloudflare-progress",
        DeployProgress {
            phase: DeployPhase::Preflight,
            message: "Checking authentication...".into(),
            progress_percent: 5,
        },
    );

    let whoami = crate::commands::cloudflare_oauth::whoami()
        .await
        .map_err(|error| error.to_string())?;

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
    let account_id = whoami
        .active_account_id
        .or_else(|| whoami.accounts.first().map(|a| a.account_id.clone()))
        .ok_or_else(|| "No Cloudflare account found".to_string())?;

    let api_token = crate::commands::cloudflare_oauth::load_access_token()
        .map_err(|error| error.to_string())?;

    // Load embedded Worker script
    let runtime_root = resolve_embedded_runtime_root(Some(&app))
        .ok_or_else(|| "Embedded runtime not found".to_string())?;

    let worker_script = cloudflare_rest::load_embedded_worker_script(&runtime_root)?;

    // Generate deployment config. Redeploy/upgrade reuses existing runtime
    // names and secrets so the same Worker/storage remain authoritative.
    let defaults = derive_cloudflare_defaults(&profile_name, &user_id, &device_id);
    let existing_runtime = {
        let inner = state.inner.read().await;
        inner.profile_manager.get_runtime_metadata().await
    };

    let config = WorkerDeployConfig {
        worker_name: existing_runtime
            .as_ref()
            .and_then(|runtime| runtime.worker_name.clone())
            .unwrap_or(defaults.worker_name),
        public_base_url: existing_runtime
            .as_ref()
            .and_then(|runtime| runtime.public_base_url.clone().or(runtime.base_url.clone()))
            .or_else(|| Some(defaults.public_base_url).filter(|s| !s.is_empty())),
        deployment_region: existing_runtime
            .as_ref()
            .and_then(|runtime| runtime.deployment_region.clone())
            .unwrap_or(defaults.deployment_region),
        bucket_name: existing_runtime
            .as_ref()
            .and_then(|runtime| runtime.bucket_name.clone())
            .unwrap_or(defaults.bucket_name),
        preview_bucket_name: existing_runtime
            .as_ref()
            .and_then(|runtime| runtime.preview_bucket_name.clone())
            .unwrap_or(defaults.preview_bucket_name),
        sharing_token_secret: existing_runtime
            .as_ref()
            .and_then(|runtime| runtime.sharing_secret.clone())
            .unwrap_or(defaults.sharing_token_secret),
        bootstrap_token_secret: existing_runtime
            .as_ref()
            .and_then(|runtime| runtime.bootstrap_secret.clone())
            .unwrap_or(defaults.bootstrap_token_secret),
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
    )
    .await?;

    if !result.success {
        let elapsed_ms = deploy_start.elapsed().as_millis();
        timetest!(
            "deploy_done success=false elapsed_ms={} ts={}",
            elapsed_ms,
            abs_start + elapsed_ms as u128
        );
        return Ok(result);
    }

    // Wait for deployment to be ready
    let _ = app.emit(
        "cloudflare-progress",
        DeployProgress {
            phase: DeployPhase::VerifyingDeployment,
            message: "Waiting for deployment to be ready...".into(),
            progress_percent: 85,
        },
    );

    tapchat_core::cli::runtime::wait_until_ready(&result.worker_url)
        .await
        .map_err(|e| format!("Deployment not ready: {}", e))?;

    // Wait for secrets to propagate in Worker environment
    // Cloudflare Workers secrets need additional time to become available
    let _ = app.emit(
        "cloudflare-progress",
        DeployProgress {
            phase: DeployPhase::VerifyingDeployment,
            message: "Waiting for secrets to propagate...".into(),
            progress_percent: 88,
        },
    );
    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

    // Bootstrap device bundle
    let _ = app.emit(
        "cloudflare-progress",
        DeployProgress {
            phase: DeployPhase::VerifyingDeployment,
            message: "Bootstrapping device...".into(),
            progress_percent: 90,
        },
    );

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

    let deployment_bundle = {
        let inner = state.inner.read().await;
        inner
            .engine
            .refresh_snapshot()
            .deployment
            .as_ref()
            .map(|deployment| deployment.deployment_bundle.clone())
            .ok_or_else(|| "Import deployment did not update engine snapshot".to_string())?
    };

    let pending_group_ids = {
        let inner = state.inner.read().await;
        inner
            .engine
            .refresh_snapshot()
            .pending_group_outbox
            .iter()
            .map(|item| item.group_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
    };
    for group_id in pending_group_ids {
        drive_core_with_handle(
            &app,
            CoreInput::Command(CoreCommand::SyncGroupOutbox {
                group_id,
                reason: Some("runtime_upgraded".into()),
            }),
        )
        .await
        .map_err(|e| format!("Retry pending group outbox failed: {}", e))?;
    }

    // Save runtime metadata and deployment bundle, then verify all runtime
    // persistence surfaces agree.
    {
        let service_root = resolve_embedded_runtime_root(Some(&app));

        let runtime = RuntimeMetadata {
            pid: None,
            base_url: Some(result.worker_url.clone()),
            websocket_base_url: Some(
                result
                    .worker_url
                    .replace("https://", "wss://")
                    .replace("http://", "ws://"),
            ),
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
            last_deployed_at: Some(chrono::Utc::now().to_rfc3339()),
        };

        persist_runtime_writeback(&state, &deployment_bundle, &runtime, &result.worker_url).await?;
    }

    let _ = app.emit(
        "cloudflare-progress",
        DeployProgress {
            phase: DeployPhase::Complete,
            message: "Deployment complete!".into(),
            progress_percent: 100,
        },
    );

    let elapsed_secs = deploy_start.elapsed().as_secs_f64();
    timetest!(
        "deploy_done success=true worker_url={} elapsed_secs={:.1} ts={}",
        result.worker_url,
        elapsed_secs,
        abs_start + ((elapsed_secs * 1000.0) as u128)
    );

    restart_runtime_session_after_deploy(&app, &state, &device_id).await;

    Ok(result)
}

struct DeployProgressGuard;

impl Drop for DeployProgressGuard {
    fn drop(&mut self) {
        CLOUDFLARE_DEPLOY_IN_PROGRESS.store(false, Ordering::SeqCst);
    }
}

async fn persist_runtime_writeback(
    state: &State<'_, AppState>,
    deployment_bundle: &DeploymentBundle,
    runtime: &RuntimeMetadata,
    expected_worker_url: &str,
) -> Result<(), String> {
    let snapshot = {
        let inner = state.inner.read().await;
        inner.engine.refresh_snapshot()
    };

    {
        let inner = state.inner.read().await;
        let mut pm_inner = inner.profile_manager.inner.write().await;
        let profile = pm_inner
            .active_profile
            .as_mut()
            .ok_or_else(|| "writeback_incomplete: active profile is missing".to_string())?;
        profile
            .save_snapshot(&snapshot)
            .map_err(|e| format!("writeback_incomplete: save snapshot failed: {e}"))?;
        profile
            .save_deployment_bundle(deployment_bundle)
            .map_err(|e| format!("writeback_incomplete: save deployment bundle failed: {e}"))?;
        profile
            .save_runtime_metadata(runtime)
            .map_err(|e| format!("writeback_incomplete: save runtime metadata failed: {e}"))?;

        let reloaded_snapshot = profile
            .load_snapshot()
            .map_err(|e| format!("writeback_incomplete: reload snapshot failed: {e}"))?;
        let reloaded_runtime = profile
            .load_runtime_metadata()
            .map_err(|e| format!("writeback_incomplete: reload runtime metadata failed: {e}"))?;
        let bundle_path = profile
            .metadata()
            .deployment_bundle_path
            .clone()
            .ok_or_else(|| {
                "writeback_incomplete: profile metadata missing deployment_bundle_path".to_string()
            })?;
        let reloaded_bundle = Profile::load_deployment_bundle_file(bundle_path)
            .map_err(|e| format!("writeback_incomplete: reload deployment bundle failed: {e}"))?;
        let snapshot_endpoint = reloaded_snapshot
            .deployment
            .as_ref()
            .map(|deployment| deployment.deployment_bundle.inbox_http_endpoint.clone())
            .ok_or_else(|| "writeback_incomplete: snapshot missing deployment".to_string())?;
        let runtime_endpoint = reloaded_runtime
            .public_base_url
            .clone()
            .or(reloaded_runtime.base_url.clone())
            .ok_or_else(|| "writeback_incomplete: runtime metadata missing endpoint".to_string())?;
        if snapshot_endpoint != expected_worker_url
            || runtime_endpoint != expected_worker_url
            || reloaded_bundle.inbox_http_endpoint != expected_worker_url
        {
            return Err(format!(
                "writeback_incomplete: endpoint mismatch snapshot={snapshot_endpoint} runtime={runtime_endpoint} bundle={} expected={expected_worker_url}",
                reloaded_bundle.inbox_http_endpoint
            ));
        }
    }

    Ok(())
}

async fn restart_runtime_session_after_deploy(
    app: &AppHandle,
    state: &State<'_, AppState>,
    device_id: &str,
) {
    {
        let inner = state.inner.read().await;
        if let Err(error) = inner.ports.realtime.close_all_silent().await {
            log::warn!("cloudflare_deploy: failed to close old realtime sessions: {error}");
        }
    }
    set_ws_connection_snapshot(state, Some(device_id.to_string()), false).await;
    {
        let mut inner = state.inner.write().await;
        inner.session = SessionState::Active {
            device_id: device_id.to_string(),
        };
    }
    let _ = app.emit(
        "session-status",
        SessionStatus {
            state: "active".into(),
            device_id: Some(device_id.to_string()),
            ws_connected: false,
            profile_path: None,
            error: None,
        },
    );
    if let Ok(status) = cloudflare_status_impl(state).await {
        let _ = app.emit("runtime-status-changed", status);
    }
    if let Err(error) = drive_core_with_handle(app, CoreInput::Event(CoreEvent::AppStarted)).await {
        log::warn!("cloudflare_deploy: runtime deployed but AppStarted failed: {error}");
    }
}

/// Check deployment status
#[tauri::command]
pub async fn cloudflare_status(
    state: State<'_, AppState>,
) -> Result<CloudflareRuntimeStatus, String> {
    cloudflare_status_impl(&state).await
}

async fn cloudflare_status_impl(
    state: &State<'_, AppState>,
) -> Result<CloudflareRuntimeStatus, String> {
    let (runtime, snapshot_deployment, bundle_file, metadata_bundle_path) = {
        let inner = state.inner.read().await;
        let pm_inner = inner.profile_manager.inner.read().await;
        let Some(profile) = pm_inner.active_profile.as_ref() else {
            return Ok(runtime_status(
                "missing",
                Some("deploy"),
                false,
                None,
                Vec::new(),
                None,
                Some("No active profile is loaded.".into()),
            ));
        };
        let runtime = profile.load_runtime_metadata().map_err(|e| e.to_string())?;
        let snapshot = profile.load_snapshot().map_err(|e| e.to_string())?;
        let bundle_path = profile.metadata().deployment_bundle_path.clone();
        let bundle_file = bundle_path
            .as_ref()
            .and_then(|path| Profile::load_deployment_bundle_file(path).ok());
        (runtime, snapshot.deployment, bundle_file, bundle_path)
    };

    let endpoint = runtime.public_base_url.clone().or(runtime.base_url.clone());
    if endpoint.is_none() && snapshot_deployment.is_none() && bundle_file.is_none() {
        return Ok(runtime_status(
            "missing",
            Some("deploy"),
            false,
            None,
            Vec::new(),
            None,
            Some("Cloudflare runtime is not deployed.".into()),
        ));
    }

    let Some(deployment) = snapshot_deployment else {
        return Ok(runtime_status(
            "writeback_incomplete",
            Some("retry_writeback"),
            endpoint.is_some(),
            endpoint,
            bundle_file
                .map(|bundle| bundle.runtime_config.features)
                .unwrap_or_default(),
            None,
            Some("Runtime metadata exists, but the encrypted snapshot is missing the deployment bundle.".into()),
        ));
    };

    let snapshot_endpoint = deployment.deployment_bundle.inbox_http_endpoint.clone();
    let endpoint = endpoint.unwrap_or_else(|| snapshot_endpoint.clone());
    let bundle_endpoint = bundle_file
        .as_ref()
        .map(|bundle| bundle.inbox_http_endpoint.clone());
    if metadata_bundle_path.is_none()
        || bundle_endpoint.as_deref() != Some(snapshot_endpoint.as_str())
        || endpoint != snapshot_endpoint
    {
        return Ok(runtime_status(
            "writeback_incomplete",
            Some("retry_writeback"),
            true,
            Some(endpoint),
            deployment.deployment_bundle.runtime_config.features.clone(),
            None,
            Some(
                "Runtime metadata, deployment bundle file, and snapshot are not consistent.".into(),
            ),
        ));
    }

    let mut status = runtime_status_for_deployment(Some(deployment.clone())).await;
    if status.state == "ready" && device_runtime_auth_expired(&deployment) {
        status.state = "auth_expired".into();
        status.action = Some("refresh_auth".into());
        status.details = Some("Device runtime authorization is missing or expired.".into());
    }
    Ok(status)
}

fn device_runtime_auth_expired(deployment: &PersistedDeployment) -> bool {
    let Some(auth) = deployment.deployment_bundle.device_runtime_auth.as_ref() else {
        return true;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    auth.expires_at <= now
}

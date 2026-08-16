//! Cloudflare deployment commands for Desktop App
//!
//! Uses Rust Cloudflare OAuth and REST API deployment.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

use tapchat_core::cli::profile::{
    PendingRuntimeProvisioning, RuntimeMetadata, RuntimeProvisioningPhase,
    RuntimeSecretRotationMetadata, RuntimeSecretRotationPhase, RuntimeSecrets,
};
use tapchat_core::cli::runtime::derive_cloudflare_defaults;
use tapchat_core::model::DeploymentBundle;
use tapchat_core::persistence::PersistedDeployment;
use tapchat_core::{CoreCommand, CoreEvent};

use crate::commands::cloudflare_rest::{
    self, DeployPhase, DeployProgress, DeployResult, WorkerDeployConfig,
};
use crate::commands::session::{set_ws_connection_snapshot, SessionStatus};
use crate::lifecycle::{drive_core_with_handle, CoreInput};
use crate::platform::log_sanitize::sanitize_url_for_log;
use crate::runtime_auth::wait_for_runtime_ready;
use crate::state::AppState;
use crate::state::SessionState;
use crate::timetest;

static CLOUDFLARE_DEPLOY_IN_PROGRESS: AtomicBool = AtomicBool::new(false);
const AUTH_ROTATION_GRACE_MS: u64 = 48 * 60 * 60 * 1000;
const AUTH_ROTATION_INTERVAL_MS: u64 = 90 * 24 * 60 * 60 * 1000;
const WORKER_BUILD_ID: &str = concat!("tapchat-worker-v5-", env!("CARGO_PKG_VERSION"));

fn generate_runtime_key_id(prefix: &str) -> String {
    let mut bytes = [0_u8; 8];
    OsRng.fill_bytes(&mut bytes);
    let suffix: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{prefix}-{suffix}")
}

fn valid_worker_secret(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.as_bytes().len() >= 32
        && !matches!(
            trimmed.to_ascii_lowercase().as_str(),
            "replace-me" | "replace-me-bootstrap" | "changeme" | "change-me" | "secret"
        )
}

fn repair_worker_secret(candidate: Option<String>) -> (String, bool) {
    if let Some(secret) = candidate.filter(|secret| valid_worker_secret(secret)) {
        return (secret, false);
    }
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let generated = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    (generated, true)
}

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
    pub secret_rotation: Option<RuntimeSecretRotationMetadata>,
    pub credential_expires_at: Option<u64>,
    pub error_code: Option<String>,
}

const REQUIRED_GROUP_RUNTIME_FEATURES: &[&str] = &[
    "group_outbox_mvp",
    "welcome_pickup_mvp",
    "message_requests",
    "short_group_invite",
    "group_member_subscribe",
    "group_authorization_v2",
    "group_membership_fsm_v2",
    "runtime_secret_rotation_v1",
    "device_runtime_refresh_v2",
    "device_registry_v1",
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
    let has_group_authorization_v2 = features
        .iter()
        .any(|feature| feature == "group_authorization_v2");
    let has_group_membership_fsm_v2 = features
        .iter()
        .any(|feature| feature == "group_membership_fsm_v2");
    let needs_upgrade = bound
        && !(supports_group_outbox
            && supports_welcome_pickup
            && has_message_requests
            && has_short_group_invite
            && has_group_member_subscribe
            && has_group_authorization_v2
            && has_group_membership_fsm_v2);
    let (state, action, details) = if !bound {
        (
            "provisioning_required".to_string(),
            Some("deploy".to_string()),
            Some("Cloudflare runtime is not deployed.".to_string()),
        )
    } else if last_error.is_some() {
        ("degraded".to_string(), None, last_error.clone())
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
        secret_rotation: None,
        credential_expires_at: None,
        error_code: None,
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
    if deployment.deployment_bundle.protocol_version != 5
        || deployment.deployment_bundle.registry_schema_version != 2
        || deployment
            .deployment_bundle
            .worker_build_id
            .trim()
            .is_empty()
    {
        return runtime_status(
            "upgrade_required",
            Some("upgrade"),
            true,
            Some(endpoint),
            local_features,
            None,
            Some("Cloudflare runtime protocol is not supported by this app.".into()),
        );
    }
    let client = match reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(12))
        .build()
    {
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
    let url = format!("{}/v2/runtime/ready", endpoint.trim_end_matches('/'));
    match client.get(url).send().await {
        Ok(response) => {
            let status = response.status();
            let body = match response.text().await {
                Ok(body) => body,
                Err(_) => {
                    return runtime_status(
                        "degraded",
                        None,
                        true,
                        Some(endpoint),
                        local_features,
                        Some("runtime readiness response body was interrupted".into()),
                        Some("Cloudflare runtime is temporarily unreachable.".into()),
                    );
                }
            };
            if !status.is_success() {
                return runtime_status(
                    "degraded",
                    None,
                    true,
                    Some(endpoint),
                    local_features,
                    Some(format!("runtime readiness check returned HTTP {status}")),
                    Some("Cloudflare runtime is temporarily unreachable.".into()),
                );
            }
            match crate::runtime_auth::parse_runtime_ready_manifest(&body) {
                Ok(manifest)
                    if manifest.ready
                        && manifest.runtime_id == deployment.deployment_bundle.runtime_id
                        && manifest.protocol_version == 5
                        && manifest.registry_schema_version == 2
                        && manifest.worker_build_id
                            == deployment.deployment_bundle.worker_build_id =>
                {
                    status_from_features(true, Some(endpoint), local_features, None)
                }
                Ok(_) => runtime_status(
                    "upgrade_required",
                    Some("upgrade"),
                    true,
                    Some(endpoint),
                    local_features,
                    None,
                    Some("Runtime manifest does not match this Profile.".into()),
                ),
                Err(error) => runtime_status(
                    "protocol_invalid",
                    None,
                    true,
                    Some(endpoint),
                    local_features,
                    Some(format!("runtime readiness response parse failed: {error}")),
                    Some("Cloudflare runtime returned an invalid readiness response.".into()),
                ),
            }
        }
        Err(error) => runtime_status(
            "offline",
            None,
            true,
            Some(endpoint),
            local_features,
            Some(format!("runtime readiness check failed: {error}")),
            Some("Cloudflare runtime is offline; local messages remain available.".into()),
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
    use super::{
        repair_worker_secret, runtime_missing_group_outbox_message, status_from_features,
        valid_worker_secret,
    };

    #[test]
    fn worker_secret_reuses_valid_input() {
        let same = "same-runtime-secret-0123456789abcdef0123456789abcdef".to_string();
        let (sharing, repaired_sharing) = repair_worker_secret(Some(same.clone()));
        assert!(!repaired_sharing);
        assert!(valid_worker_secret(&sharing));
        assert_eq!(sharing, same);
    }

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
                "group_authorization_v2".into(),
                "group_membership_fsm_v2".into(),
                "device_runtime_refresh_v2".into(),
                "device_registry_v1".into(),
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
pub async fn cloudflare_preflight(app: AppHandle) -> crate::errors::DesktopResult<PreflightResult> {
    let app_ref = Some(&app);

    // Check if embedded runtime is available
    let embedded_available = resolve_embedded_runtime_root(app_ref).is_some();

    // Rust OAuth/whoami uses only the OS keychain at runtime. Legacy Wrangler
    // plaintext tokens require an explicit import command before deployment.
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
pub async fn cloudflare_login(app: AppHandle) -> crate::errors::DesktopResult<LoginResult> {
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

#[tauri::command]
pub async fn cloudflare_import_legacy_wrangler_token() -> crate::errors::DesktopResult<LoginResult>
{
    crate::commands::cloudflare_oauth::import_legacy_wrangler_token()
        .map_err(|error| error.to_string())?;
    let whoami = crate::commands::cloudflare_oauth::whoami()
        .await
        .map_err(|error| error.to_string())?;
    let account = whoami.accounts.first();
    Ok(LoginResult {
        success: whoami.authenticated && account.is_some(),
        account_id: account.map(|account| account.account_id.clone()),
        account_name: account.map(|account| account.account_name.clone()),
        error: whoami.error,
    })
}

/// Deploy Cloudflare Worker via REST API
#[tauri::command]
pub async fn cloudflare_deploy(
    app: AppHandle,
    state: State<'_, AppState>,
) -> crate::errors::DesktopResult<DeployResult> {
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
        });
    }
    let _deploy_guard = DeployProgressGuard;
    let deploy_start = std::time::Instant::now();
    let abs_start = crate::ts_ms();
    timetest!("deploy_begin ts={}", abs_start);

    let inner = state.inner.read().await;

    // Get identity info - identity must exist, but bundle is optional for first deployment
    let Some(identity_ref) = inner.engine.local_identity() else {
        return Ok(DeployResult {
            success: false,
            worker_name: "".into(),
            worker_url: "".into(),
            error: Some("No identity created yet. Please complete initial setup first.".into()),
            account_id: None,
            bucket_name: None,
        });
    };
    let user_id = identity_ref.user_identity.user_id.clone();
    let user_public_key = identity_ref.user_identity.user_public_key.clone();
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
        });
    }

    // Get account_id and API token
    let account_id = whoami
        .active_account_id
        .or_else(|| whoami.accounts.first().map(|a| a.account_id.clone()))
        .ok_or_else(|| "No Cloudflare account found".to_string())?;

    let api_token = crate::commands::cloudflare_oauth::load_access_token()
        .await
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
    let pending_provisioning = {
        let inner = state.inner.read().await;
        let pm = inner.profile_manager.inner.read().await;
        let profile = pm
            .active_profile
            .as_ref()
            .ok_or_else(|| "active profile is missing".to_string())?;
        profile
            .load_pending_runtime_provisioning()
            .map_err(|error| format!("failed to load provisioning journal: {error}"))?
    };
    let runtime_id = pending_provisioning
        .as_ref()
        .map(|pending| pending.runtime_id.clone())
        .or_else(|| {
            existing_runtime
                .as_ref()
                .and_then(|runtime| runtime.runtime_id.clone())
        })
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let existing_secrets = {
        if let Some(pending) = pending_provisioning.as_ref() {
            pending.generated_secrets.clone()
        } else {
            let inner = state.inner.read().await;
            let pm_inner = inner.profile_manager.inner.read().await;
            pm_inner
                .active_profile
                .as_ref()
                .and_then(|profile| profile.load_runtime_secrets().ok())
                .unwrap_or_default()
        }
    };
    let (sharing_token_secret, repaired_sharing_secret) = repair_worker_secret(
        existing_runtime
            .as_ref()
            .and_then(|_| existing_secrets.sharing_secret.clone())
            .or_else(|| {
                existing_runtime
                    .as_ref()
                    .and_then(|runtime| runtime.sharing_secret.clone())
            })
            .or_else(|| Some(defaults.sharing_token_secret.clone())),
    );

    let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
    let (device_runtime_secret, generated_device_runtime_secret) =
        repair_worker_secret(existing_secrets.device_runtime_secret.clone());
    let device_runtime_key_id = existing_secrets
        .device_runtime_key_id
        .clone()
        .unwrap_or_else(|| generate_runtime_key_id("runtime"));
    let first_keyed_deploy = existing_secrets.device_runtime_secret.is_none();
    let previous_device_runtime_secret = existing_secrets
        .previous_device_runtime_secret
        .clone()
        .or_else(|| first_keyed_deploy.then(|| sharing_token_secret.clone()));
    let previous_device_runtime_key_id = existing_secrets.previous_device_runtime_key_id.clone();
    let grace_until_ms = existing_runtime
        .as_ref()
        .and_then(|runtime| runtime.secret_rotation.grace_until_ms)
        .or_else(|| first_keyed_deploy.then_some(now_ms.saturating_add(AUTH_ROTATION_GRACE_MS)));
    let prepared_secrets = RuntimeSecrets {
        bootstrap_secret: None,
        sharing_secret: Some(sharing_token_secret.clone()),
        device_runtime_secret: Some(device_runtime_secret.clone()),
        device_runtime_key_id: Some(device_runtime_key_id.clone()),
        previous_device_runtime_secret: previous_device_runtime_secret.clone(),
        previous_device_runtime_key_id: previous_device_runtime_key_id.clone(),
        bootstrap_key_id: None,
        previous_bootstrap_secret: None,
        previous_bootstrap_key_id: None,
    };
    {
        // Transaction phase 1: persist exactly one prepared key set before any
        // Worker mutation. A retry reuses this state and cannot create a third key.
        let inner = state.inner.read().await;
        let pm_inner = inner.profile_manager.inner.read().await;
        let profile = pm_inner
            .active_profile
            .as_ref()
            .ok_or_else(|| "active profile is missing".to_string())?;
        if let Some(mut runtime) = existing_runtime.clone() {
            runtime.secret_rotation = RuntimeSecretRotationMetadata {
                phase: RuntimeSecretRotationPhase::Prepared,
                current_key_id: Some(device_runtime_key_id.clone()),
                previous_key_id: previous_device_runtime_key_id.clone(),
                prepared_at_ms: Some(now_ms),
                grace_until_ms,
                ..runtime.secret_rotation
            };
            profile
                .save_runtime_rotation_state(&runtime, &prepared_secrets)
                .map_err(|error| format!("failed to persist prepared rotation state: {error}"))?;
        } else {
            profile
                .save_runtime_secrets(&prepared_secrets)
                .map_err(|error| format!("failed to persist prepared runtime secrets: {error}"))?;
        }
        if pending_provisioning.is_none() {
            profile
                .save_pending_runtime_provisioning(Some(PendingRuntimeProvisioning {
                    runtime_id: runtime_id.clone(),
                    worker_name: existing_runtime
                        .as_ref()
                        .and_then(|runtime| runtime.worker_name.clone())
                        .unwrap_or_else(|| defaults.worker_name.clone()),
                    bucket_name: existing_runtime
                        .as_ref()
                        .and_then(|runtime| runtime.bucket_name.clone())
                        .unwrap_or_else(|| defaults.bucket_name.clone()),
                    worker_build_id: WORKER_BUILD_ID.to_string(),
                    generated_secrets: prepared_secrets.clone(),
                    phase: RuntimeProvisioningPhase::Prepared,
                }))
                .map_err(|error| format!("failed to persist provisioning journal: {error}"))?;
        }
    }

    let config = WorkerDeployConfig {
        worker_name: pending_provisioning
            .as_ref()
            .map(|pending| pending.worker_name.clone())
            .or_else(|| {
                existing_runtime
                    .as_ref()
                    .and_then(|runtime| runtime.worker_name.clone())
            })
            .unwrap_or(defaults.worker_name),
        runtime_id,
        owner_user_id: user_id.clone(),
        owner_user_public_key: user_public_key,
        public_base_url: existing_runtime
            .as_ref()
            .and_then(|runtime| runtime.public_base_url.clone().or(runtime.base_url.clone()))
            .or_else(|| Some(defaults.public_base_url).filter(|s| !s.is_empty())),
        deployment_region: existing_runtime
            .as_ref()
            .and_then(|runtime| runtime.deployment_region.clone())
            .unwrap_or(defaults.deployment_region),
        bucket_name: pending_provisioning
            .as_ref()
            .map(|pending| pending.bucket_name.clone())
            .or_else(|| {
                existing_runtime
                    .as_ref()
                    .and_then(|runtime| runtime.bucket_name.clone())
            })
            .unwrap_or(defaults.bucket_name),
        worker_build_id: pending_provisioning
            .as_ref()
            .map(|pending| pending.worker_build_id.clone())
            .unwrap_or_else(|| WORKER_BUILD_ID.to_string()),
        sharing_token_secret,
        device_runtime_secret,
        device_runtime_key_id: device_runtime_key_id.clone(),
        previous_device_runtime_secret,
        previous_device_runtime_key_id: previous_device_runtime_key_id.clone(),
        auth_rotation_grace_until_ms: grace_until_ms,
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
    };

    if repaired_sharing_secret || generated_device_runtime_secret {
        let _ = app.emit(
            "cloudflare-progress",
            DeployProgress {
                phase: DeployPhase::Preflight,
                message: "Invalid or missing runtime secrets were rotated.".into(),
                progress_percent: 20,
            },
        );
    }

    // Deploy via REST API
    let first_deploy = cloudflare_rest::deploy_via_rest_api(
        &api_token,
        &account_id,
        &worker_script,
        &config,
        |progress| {
            let _ = app.emit("cloudflare-progress", progress);
        },
    )
    .await;
    let result = match first_deploy {
        Ok(result) => result,
        Err(error) if error.contains("cloudflare_api_unauthorized") => {
            let refreshed =
                crate::commands::cloudflare_oauth::force_refresh_access_token(&api_token)
                    .await
                    .map_err(|refresh_error| refresh_error.to_string())?;
            cloudflare_rest::deploy_via_rest_api(
                &refreshed,
                &account_id,
                &worker_script,
                &config,
                |progress| {
                    let _ = app.emit("cloudflare-progress", progress);
                },
            )
            .await?
        }
        Err(error) => return Err(error.into()),
    };

    if !result.success {
        let elapsed_ms = deploy_start.elapsed().as_millis();
        timetest!(
            "deploy_done success=false elapsed_ms={} ts={}",
            elapsed_ms,
            abs_start + elapsed_ms as u128
        );
        return Ok(result);
    }
    advance_provisioning_journal(&state, RuntimeProvisioningPhase::CloudDeployed).await?;

    // Wait for deployment to be ready
    let _ = app.emit(
        "cloudflare-progress",
        DeployProgress {
            phase: DeployPhase::VerifyingDeployment,
            message: "Waiting for deployment to be ready...".into(),
            progress_percent: 85,
        },
    );

    wait_for_runtime_ready(
        &result.worker_url,
        &config.runtime_id,
        &config.worker_build_id,
    )
    .await
    .map_err(|error| format!("Runtime not ready: {error}"))?;
    advance_provisioning_journal(&state, RuntimeProvisioningPhase::RuntimeReady).await?;

    // Fetch the public deployment descriptor, build the root-signed local
    // IdentityBundle, then enroll the current device with its long-lived key.
    let _ = app.emit(
        "cloudflare-progress",
        DeployProgress {
            phase: DeployPhase::VerifyingDeployment,
            message: "Enrolling this device...".into(),
            progress_percent: 90,
        },
    );

    let deployment_bundle = reqwest::Client::new()
        .get(format!(
            "{}/v1/deployment-bundle",
            result.worker_url.trim_end_matches('/')
        ))
        .send()
        .await
        .map_err(|error| format!("Fetch deployment descriptor failed: {error}"))?
        .error_for_status()
        .map_err(|error| format!("Fetch deployment descriptor rejected: {error}"))?
        .json::<DeploymentBundle>()
        .await
        .map_err(|error| format!("Decode deployment descriptor failed: {error}"))?;

    let profile_manager = {
        let inner = state.inner.read().await;
        inner.profile_manager.clone()
    };
    let (local_bundle, local_identity, prepared_snapshot) = {
        let mut inner = state.inner.write().await;
        inner
            .engine
            .handle_command(CoreCommand::ImportDeploymentBundle {
                bundle: deployment_bundle.clone(),
            })
            .map_err(|error| format!("Prepare deployment import failed: {error}"))?;
        let snapshot = inner.engine.refresh_snapshot();
        let local_bundle = snapshot
            .deployment
            .as_ref()
            .and_then(|deployment| deployment.local_bundle.clone())
            .ok_or_else(|| {
                "Local IdentityBundle is unavailable for device enrollment".to_string()
            })?;
        let local_identity = snapshot
            .local_identity
            .as_ref()
            .map(|identity| identity.state.clone())
            .ok_or_else(|| "Local identity is unavailable for device enrollment".to_string())?;
        (local_bundle, local_identity, snapshot)
    };
    {
        let mut pm_inner = profile_manager.inner.write().await;
        let profile = pm_inner
            .active_profile
            .as_mut()
            .ok_or_else(|| "active profile disappeared during enrollment".to_string())?;
        profile
            .save_snapshot(&prepared_snapshot)
            .map_err(|error| format!("Persist prepared enrollment snapshot failed: {error}"))?;
        profile
            .save_deployment_bundle(&deployment_bundle)
            .map_err(|error| format!("Persist deployment descriptor failed: {error}"))?;
    }
    state
        .runtime_auth
        .enroll(
            &profile_manager,
            &deployment_bundle,
            &local_bundle,
            &local_identity,
        )
        .await
        .map_err(|error| format!("Device enrollment failed: {error}"))?;
    advance_provisioning_journal(&state, RuntimeProvisioningPhase::DeviceEnrolled).await?;

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
            runtime_id: Some(config.runtime_id.clone()),
            pid: None,
            base_url: Some(result.worker_url.clone()),
            websocket_base_url: Some(
                result
                    .worker_url
                    .replace("https://", "wss://")
                    .replace("http://", "ws://"),
            ),
            bootstrap_secret: None,
            sharing_secret: Some(config.sharing_token_secret.clone()),
            mode: Some("cloudflare".into()),
            workspace_root: None,
            service_root: service_root,
            worker_name: Some(config.worker_name.clone()),
            public_base_url: Some(result.worker_url.clone()),
            deploy_url: Some(result.worker_url.clone()),
            deployment_region: Some(config.deployment_region.clone()),
            bucket_name: Some(config.bucket_name.clone()),
            last_deployed_at: Some(chrono::Utc::now().to_rfc3339()),
            secret_rotation: RuntimeSecretRotationMetadata {
                phase: if grace_until_ms.is_some() {
                    RuntimeSecretRotationPhase::Grace
                } else {
                    RuntimeSecretRotationPhase::Stable
                },
                current_key_id: Some(device_runtime_key_id),
                previous_key_id: previous_device_runtime_key_id,
                prepared_at_ms: None,
                last_rotated_at_ms: Some(now_ms),
                next_rotation_at_ms: Some(now_ms.saturating_add(AUTH_ROTATION_INTERVAL_MS)),
                grace_until_ms,
                last_error: None,
            },
        };

        persist_runtime_writeback(&state, &deployment_bundle, &runtime, &result.worker_url).await?;
    }
    advance_provisioning_journal(&state, RuntimeProvisioningPhase::Complete).await?;
    {
        let inner = state.inner.read().await;
        let pm = inner.profile_manager.inner.read().await;
        let profile = pm
            .active_profile
            .as_ref()
            .ok_or_else(|| "active profile is missing".to_string())?;
        profile
            .save_pending_runtime_provisioning(None)
            .map_err(|error| format!("failed to clear provisioning journal: {error}"))?;
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
        sanitize_url_for_log(&result.worker_url),
        elapsed_secs,
        abs_start + ((elapsed_secs * 1000.0) as u128)
    );

    restart_runtime_session_after_deploy(&app, &state, &device_id).await;

    Ok(result)
}

async fn advance_provisioning_journal(
    state: &State<'_, AppState>,
    phase: RuntimeProvisioningPhase,
) -> Result<(), String> {
    let inner = state.inner.read().await;
    let pm = inner.profile_manager.inner.read().await;
    let profile = pm
        .active_profile
        .as_ref()
        .ok_or_else(|| "active profile is missing".to_string())?;
    profile
        .advance_runtime_provisioning(phase)
        .map_err(|error| format!("failed to advance provisioning journal: {error}"))
}

async fn prepare_runtime_secret_rotation(state: &State<'_, AppState>) -> Result<(), String> {
    let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
    let inner = state.inner.read().await;
    let pm_inner = inner.profile_manager.inner.read().await;
    let profile = pm_inner
        .active_profile
        .as_ref()
        .ok_or_else(|| "No active profile is loaded.".to_string())?;
    let mut runtime = profile.load_runtime_metadata().map_err(|e| e.to_string())?;
    let mut secrets = profile.load_runtime_secrets().map_err(|e| e.to_string())?;

    match runtime.secret_rotation.phase {
        RuntimeSecretRotationPhase::Prepared
        | RuntimeSecretRotationPhase::Deploying
        | RuntimeSecretRotationPhase::Failed => return Ok(()),
        RuntimeSecretRotationPhase::Grace => {
            return Err(
                "The current rotation is still in grace; finalize it before rotating again.".into(),
            )
        }
        RuntimeSecretRotationPhase::PendingAuthorization
            if secrets.previous_device_runtime_secret.is_some() =>
        {
            // Authorization expired after preparation. Reuse the exact prepared
            // key set instead of creating a third generation.
            return Ok(());
        }
        RuntimeSecretRotationPhase::Stable | RuntimeSecretRotationPhase::PendingAuthorization => {}
    }

    let old_runtime_secret = secrets
        .device_runtime_secret
        .clone()
        .or_else(|| secrets.sharing_secret.clone())
        .ok_or_else(|| "Current device runtime secret is missing.".to_string())?;
    let old_runtime_key_id = secrets.device_runtime_key_id.clone();
    let (new_runtime_secret, _) = repair_worker_secret(None);
    let new_runtime_key_id = generate_runtime_key_id("runtime");
    let grace_until_ms = now_ms.saturating_add(AUTH_ROTATION_GRACE_MS);

    secrets.previous_device_runtime_secret = Some(old_runtime_secret);
    secrets.previous_device_runtime_key_id = old_runtime_key_id.clone();
    secrets.device_runtime_secret = Some(new_runtime_secret);
    secrets.device_runtime_key_id = Some(new_runtime_key_id.clone());
    secrets.previous_bootstrap_secret = None;
    secrets.previous_bootstrap_key_id = None;
    secrets.bootstrap_secret = None;
    secrets.bootstrap_key_id = None;

    runtime.secret_rotation = RuntimeSecretRotationMetadata {
        phase: RuntimeSecretRotationPhase::Prepared,
        current_key_id: Some(new_runtime_key_id),
        previous_key_id: old_runtime_key_id,
        prepared_at_ms: Some(now_ms),
        last_rotated_at_ms: runtime.secret_rotation.last_rotated_at_ms,
        next_rotation_at_ms: runtime.secret_rotation.next_rotation_at_ms,
        grace_until_ms: Some(grace_until_ms),
        last_error: None,
    };
    profile
        .save_runtime_rotation_state(&runtime, &secrets)
        .map_err(|error| format!("Failed to persist prepared rotation state: {error}"))
}

#[tauri::command]
pub async fn cloudflare_rotate_runtime_secrets(
    app: AppHandle,
    state: State<'_, AppState>,
) -> crate::errors::DesktopResult<DeployResult> {
    prepare_runtime_secret_rotation(&state).await?;
    cloudflare_deploy(app, state).await
}

#[tauri::command]
pub async fn cloudflare_resume_secret_rotation(
    app: AppHandle,
    state: State<'_, AppState>,
) -> crate::errors::DesktopResult<DeployResult> {
    cloudflare_deploy(app, state).await
}

#[tauri::command]
pub async fn cloudflare_finalize_secret_rotation(
    app: AppHandle,
    state: State<'_, AppState>,
) -> crate::errors::DesktopResult<DeployResult> {
    let worker_name = {
        let inner = state.inner.read().await;
        let pm_inner = inner.profile_manager.inner.read().await;
        let profile = pm_inner
            .active_profile
            .as_ref()
            .ok_or_else(|| "No active profile is loaded.".to_string())?;
        let mut runtime = profile.load_runtime_metadata().map_err(|e| e.to_string())?;
        let mut secrets = profile.load_runtime_secrets().map_err(|e| e.to_string())?;
        let worker_name = runtime
            .worker_name
            .clone()
            .ok_or_else(|| "Cloudflare worker name is missing.".to_string())?;
        secrets.previous_device_runtime_secret = None;
        secrets.previous_device_runtime_key_id = None;
        secrets.previous_bootstrap_secret = None;
        secrets.previous_bootstrap_key_id = None;
        runtime.secret_rotation.phase = RuntimeSecretRotationPhase::Stable;
        runtime.secret_rotation.previous_key_id = None;
        runtime.secret_rotation.grace_until_ms = None;
        runtime.secret_rotation.last_error = None;
        profile
            .save_runtime_rotation_state(&runtime, &secrets)
            .map_err(|error| format!("Failed to finalize rotation state: {error}"))?;
        worker_name
    };

    let result = cloudflare_deploy(app, state).await?;
    if result.success {
        let whoami = crate::commands::cloudflare_oauth::whoami().await;
        let api_token = crate::commands::cloudflare_oauth::load_access_token().await;
        if let (Ok(whoami), Ok(api_token)) = (whoami, api_token) {
            if let Some(account_id) = whoami
                .active_account_id
                .or_else(|| whoami.accounts.first().map(|item| item.account_id.clone()))
            {
                let client = reqwest::Client::new();
                // Rejection no longer depends on deletion: the deployed grace
                // deadline is cleared first. Deletion is best-effort cleanup.
                let _ = cloudflare_rest::delete_worker_secret(
                    &client,
                    &api_token,
                    &account_id,
                    &worker_name,
                    "DEVICE_RUNTIME_SECRET_PREVIOUS",
                )
                .await;
            }
        }
    }
    Ok(result)
}

pub async fn maybe_run_due_secret_rotation(app: &AppHandle) -> Result<bool, String> {
    let state = app.state::<AppState>();
    let (phase, next_rotation_at_ms, grace_until_ms, prepared_at_ms, has_previous) = {
        let inner = state.inner.read().await;
        let pm_inner = inner.profile_manager.inner.read().await;
        let Some(profile) = pm_inner.active_profile.as_ref() else {
            return Ok(false);
        };
        let runtime = profile.load_runtime_metadata().map_err(|e| e.to_string())?;
        let secrets = profile.load_runtime_secrets().map_err(|e| e.to_string())?;
        (
            runtime.secret_rotation.phase,
            runtime.secret_rotation.next_rotation_at_ms,
            runtime.secret_rotation.grace_until_ms,
            runtime.secret_rotation.prepared_at_ms,
            secrets.previous_device_runtime_secret.is_some(),
        )
    };
    let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
    let due = match phase {
        RuntimeSecretRotationPhase::Stable => next_rotation_at_ms.is_some_and(|due| due <= now_ms),
        RuntimeSecretRotationPhase::Prepared
        | RuntimeSecretRotationPhase::Deploying
        | RuntimeSecretRotationPhase::Failed => true,
        RuntimeSecretRotationPhase::Grace => grace_until_ms.is_some_and(|until| until <= now_ms),
        RuntimeSecretRotationPhase::PendingAuthorization => true,
    };
    if !due {
        return Ok(false);
    }

    let whoami = crate::commands::cloudflare_oauth::whoami()
        .await
        .map_err(|error| error.to_string())?;
    if !whoami.authenticated {
        let inner = state.inner.read().await;
        let pm_inner = inner.profile_manager.inner.read().await;
        if let Some(profile) = pm_inner.active_profile.as_ref() {
            let mut runtime = profile.load_runtime_metadata().map_err(|e| e.to_string())?;
            runtime.secret_rotation.phase = RuntimeSecretRotationPhase::PendingAuthorization;
            runtime.secret_rotation.last_error =
                Some("Cloudflare authorization is required to continue secret rotation.".into());
            profile
                .save_runtime_metadata(&runtime)
                .map_err(|error| error.to_string())?;
        }
        return Ok(false);
    }

    let result = match phase {
        RuntimeSecretRotationPhase::Stable => {
            cloudflare_rotate_runtime_secrets(app.clone(), state).await?
        }
        RuntimeSecretRotationPhase::PendingAuthorization
            if has_previous && grace_until_ms.is_some_and(|until| until <= now_ms) =>
        {
            cloudflare_finalize_secret_rotation(app.clone(), state).await?
        }
        RuntimeSecretRotationPhase::PendingAuthorization
            if has_previous || prepared_at_ms.is_some() =>
        {
            cloudflare_resume_secret_rotation(app.clone(), state).await?
        }
        RuntimeSecretRotationPhase::PendingAuthorization => {
            cloudflare_rotate_runtime_secrets(app.clone(), state).await?
        }
        RuntimeSecretRotationPhase::Grace => {
            cloudflare_finalize_secret_rotation(app.clone(), state).await?
        }
        RuntimeSecretRotationPhase::Prepared
        | RuntimeSecretRotationPhase::Deploying
        | RuntimeSecretRotationPhase::Failed => {
            cloudflare_resume_secret_rotation(app.clone(), state).await?
        }
    };
    Ok(result.success)
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
        let reloaded_bundle = profile
            .load_deployment_bundle()
            .map_err(|e| format!("writeback_incomplete: reload deployment bundle failed: {e}"))?;
        let reloaded_bundle = reloaded_bundle.ok_or_else(|| {
            "writeback_incomplete: profile metadata missing deployment_bundle_path".to_string()
        })?;
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
        let realtime = {
            let ports = state.ports.lock().await;
            ports.realtime.clone()
        };
        if let Err(_error) = realtime.close_all_silent().await {
            log::warn!("cloudflare_deploy: failed to close old realtime sessions");
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
            lock_reason: None,
        },
    );
    if let Ok(status) = cloudflare_status_impl(state).await {
        let _ = app.emit("runtime-status-changed", status);
    }
    if let Err(_error) = drive_core_with_handle(app, CoreInput::Event(CoreEvent::AppStarted)).await
    {
        log::warn!("cloudflare_deploy: runtime deployed but AppStarted failed");
    }
}

/// Check deployment status
#[tauri::command]
pub async fn cloudflare_status(
    state: State<'_, AppState>,
) -> crate::errors::DesktopResult<CloudflareRuntimeStatus> {
    Ok(cloudflare_status_impl(&state).await?)
}

async fn cloudflare_status_impl(
    state: &State<'_, AppState>,
) -> Result<CloudflareRuntimeStatus, String> {
    let (runtime, snapshot_deployment, bundle_file, metadata_bundle_path, credential) = {
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
        let bundle_file = profile.load_deployment_bundle().ok().flatten();
        let credential = profile.load_runtime_credential().ok().flatten();
        (
            runtime,
            snapshot.deployment,
            bundle_file,
            bundle_path,
            credential,
        )
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
    status.secret_rotation = Some(runtime.secret_rotation.clone());
    match runtime.secret_rotation.phase {
        RuntimeSecretRotationPhase::Prepared | RuntimeSecretRotationPhase::Deploying => {
            status.action = Some("resume_secret_rotation".into());
        }
        RuntimeSecretRotationPhase::Grace => {
            status.action = Some("finalize_secret_rotation".into());
        }
        RuntimeSecretRotationPhase::PendingAuthorization => {
            status.action = Some("cloudflare_login".into());
        }
        RuntimeSecretRotationPhase::Failed => {
            status.action = Some("resume_secret_rotation".into());
        }
        RuntimeSecretRotationPhase::Stable => {}
    }
    status.credential_expires_at = credential.as_ref().map(|value| value.expires_at);
    if status.state == "ready" {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        match credential {
            None => {
                status.state = "enrollment_required".into();
                status.action = Some("refresh_auth".into());
                status.error_code = Some("enrollment_required".into());
                status.details = Some("This device must enroll with the upgraded runtime.".into());
            }
            Some(auth) if auth.runtime_id != deployment.deployment_bundle.runtime_id => {
                status.state = "enrollment_required".into();
                status.action = Some("refresh_auth".into());
                status.error_code = Some("runtime_mismatch".into());
                status.details =
                    Some("The saved runtime credential belongs to another runtime.".into());
            }
            Some(auth) if auth.expires_at <= now => {
                status.state = "offline_expired".into();
                status.action = Some("refresh_auth".into());
                status.error_code = Some("runtime_auth_expired".into());
                status.details = Some("Runtime authorization is expired; local data remains available while refresh retries.".into());
            }
            _ => {}
        }
    }
    if status.state == "ready" {
        let auth = state.runtime_auth.snapshot().await;
        status.credential_expires_at = auth.expires_at.or(status.credential_expires_at);
        status.error_code = auth.error_code.clone();
        match auth.state {
            crate::runtime_auth::RuntimeAuthState::Ready => {}
            crate::runtime_auth::RuntimeAuthState::Refreshing => {
                status.state = "refreshing".into();
            }
            crate::runtime_auth::RuntimeAuthState::Degraded => {
                status.state = "degraded".into();
                status.details = Some("Runtime authorization refresh will retry automatically; the current credential is still valid.".into());
            }
            crate::runtime_auth::RuntimeAuthState::OfflineExpired => {
                status.state = "offline_expired".into();
                status.action = Some("refresh_auth".into());
            }
            crate::runtime_auth::RuntimeAuthState::UpgradeRequired => {
                status.state = "upgrade_required".into();
                status.action = Some("upgrade".into());
            }
            crate::runtime_auth::RuntimeAuthState::EnrollmentRequired => {
                status.state = "enrollment_required".into();
                status.action = Some("refresh_auth".into());
            }
            crate::runtime_auth::RuntimeAuthState::DeviceRevoked => {
                status.state = "device_revoked".into();
                status.action = None;
                status.details = Some(
                    "This device has been revoked. Restore the identity or create a new device."
                        .into(),
                );
            }
        }
    }
    Ok(status)
}

#[tauri::command]
pub async fn cloudflare_refresh_runtime_auth(
    state: State<'_, AppState>,
) -> crate::errors::DesktopResult<CloudflareRuntimeStatus> {
    let profile_manager = {
        let inner = state.inner.read().await;
        inner.profile_manager.clone()
    };
    state
        .runtime_auth
        .ensure(&profile_manager, true)
        .await
        .map_err(|error| error.to_string())?;
    Ok(cloudflare_status_impl(&state).await?)
}

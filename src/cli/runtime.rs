use std::io::{self, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(not(windows))]
use std::io::{BufRead, BufReader};
#[cfg(windows)]
use std::os::windows::process::CommandExt;

use anyhow::{bail, Context, Result};
use rand::RngCore;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::identity::LocalIdentityState;
use crate::model::{
    DeploymentBundle, DeviceContactProfile, DeviceRuntimeAuth, DeviceRuntimeRefreshChallenge,
    DeviceRuntimeRefreshProof, IdentityBundle, Validate, CURRENT_MODEL_VERSION,
};

use super::util::to_snake_case_json_string;

#[derive(Debug)]
pub struct LocalRuntimeInstance {
    pub pid: u32,
    pub base_url: String,
    pub websocket_base_url: String,
    pub sharing_secret: String,
    pub service_root: PathBuf,
    cleanup_on_drop: bool,
}

impl LocalRuntimeInstance {
    /// Keep the detached runtime alive after startup has been fully persisted.
    pub fn detach(&mut self) {
        self.cleanup_on_drop = false;
    }
}

impl Drop for LocalRuntimeInstance {
    fn drop(&mut self) {
        if self.cleanup_on_drop {
            let _ = stop_local_runtime(self.pid);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareDeployDefaults {
    pub worker_name: String,
    pub public_base_url: String,
    pub deployment_region: String,
    pub max_inline_bytes: String,
    pub retention_days: String,
    pub rate_limit_per_minute: String,
    pub rate_limit_per_hour: String,
    pub bucket_name: String,
    pub preview_bucket_name: String,
    pub sharing_token_secret: String,
    pub device_runtime_secret: String,
    pub device_runtime_key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CloudflareDeployOverrides {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_inline_bytes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_days: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_per_minute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_per_hour: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_bucket_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedCloudflareDeployConfig {
    pub runtime_id: String,
    pub owner_user_id: String,
    pub owner_user_public_key: String,
    pub worker_name: String,
    pub public_base_url: String,
    pub deployment_region: String,
    pub max_inline_bytes: String,
    pub retention_days: String,
    pub rate_limit_per_minute: String,
    pub rate_limit_per_hour: String,
    pub bucket_name: String,
    pub preview_bucket_name: String,
    pub sharing_token_secret: String,
    pub device_runtime_secret: String,
    pub device_runtime_key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_runtime_previous_secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_runtime_previous_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_rotation_grace_until_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareDeploymentResult {
    pub success: bool,
    pub worker_name: String,
    pub deploy_url: String,
    pub effective_public_base_url: String,
    pub bucket_name: String,
    pub preview_bucket_name: String,
    pub deployment_region: String,
    #[serde(default)]
    pub generated_secrets: CloudflareGeneratedSecrets,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr_summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflarePreflight {
    pub workspace_root_found: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_root: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_root: Option<PathBuf>,
    pub wrangler_available: bool,
    pub wrangler_logged_in: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocking_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CloudflareGeneratedSecrets {
    pub sharing_token_secret: bool,
}

const DESKTOP_EMBEDDED_RUNTIME_ROOT_ENV: &str = "TAPCHAT_DESKTOP_RUNTIME_ROOT";
const DESKTOP_EMBEDDED_WORKSPACE_ROOT_ENV: &str = "TAPCHAT_CLOUDFLARE_WORKSPACE_ROOT";
const DESKTOP_EMBEDDED_SERVICE_ROOT_ENV: &str = "TAPCHAT_CLOUDFLARE_SERVICE_ROOT";
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[cfg(windows)]
fn apply_windows_command_flags(command: &mut Command) {
    command.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(windows))]
fn apply_windows_command_flags(_: &mut Command) {}

pub fn start_local_runtime(
    service_root: impl AsRef<Path>,
    persist_to: impl AsRef<Path>,
    runtime_id: &str,
    owner_user_id: &str,
    owner_user_public_key: &str,
) -> Result<LocalRuntimeInstance> {
    let service_root = service_root.as_ref().to_path_buf();
    let port = reserve_port()?;
    let base_url = format!("http://127.0.0.1:{port}");
    let runtime_secret = generate_hex_secret();
    let sharing_secret = generate_hex_secret();
    let persist_to = persist_to.as_ref();

    #[cfg(windows)]
    {
        start_local_runtime_windows(
            &service_root,
            persist_to,
            port,
            &base_url,
            runtime_id,
            owner_user_id,
            owner_user_public_key,
            &runtime_secret,
            &sharing_secret,
        )
    }

    #[cfg(not(windows))]
    {
        let mut child = Command::new("node");
        child
            .arg("scripts/transport-runtime.mjs")
            .current_dir(&service_root)
            .env("TAPCHAT_TRANSPORT_PORT", port.to_string())
            .env("TAPCHAT_TRANSPORT_PERSIST_TO", persist_to)
            .env("TAPCHAT_TRANSPORT_RUNTIME_ID", runtime_id)
            .env("TAPCHAT_TRANSPORT_OWNER_USER_ID", owner_user_id)
            .env(
                "TAPCHAT_TRANSPORT_OWNER_USER_PUBLIC_KEY",
                owner_user_public_key,
            )
            .env("TAPCHAT_TRANSPORT_RUNTIME_SECRET", &runtime_secret)
            .env("TAPCHAT_TRANSPORT_SHARING_SECRET", &sharing_secret)
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        let mut child = child
            .spawn()
            .context("spawn cloudflare transport runtime")?;
        let pid = child.id();
        let stdout = child.stdout.take().context("runtime stdout unavailable")?;
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .context("read runtime metadata line")?;
        let metadata: serde_json::Value =
            serde_json::from_str(&line).context("parse runtime metadata")?;

        Ok(LocalRuntimeInstance {
            pid,
            base_url: metadata
                .get("baseUrl")
                .and_then(|value| value.as_str())
                .unwrap_or(&base_url)
                .to_string(),
            websocket_base_url: metadata
                .get("websocketBaseUrl")
                .and_then(|value| value.as_str())
                .unwrap_or(&base_url.replace("http", "ws"))
                .to_string(),
            sharing_secret,
            service_root,
            cleanup_on_drop: true,
        })
    }
}

pub fn derive_cloudflare_defaults(
    profile_name: &str,
    user_id: &str,
    device_id: &str,
) -> CloudflareDeployDefaults {
    let worker_name = sanitize_cloudflare_name(&format!(
        "tapchat-{}-{}",
        profile_name,
        short_identifier(user_id, 8)
    ));
    let bucket_name = format!("{worker_name}-storage");
    let preview_bucket_name = format!("{worker_name}-storage-preview");
    let _ = device_id;
    CloudflareDeployDefaults {
        worker_name,
        public_base_url: String::new(),
        deployment_region: "global".into(),
        max_inline_bytes: "4096".into(),
        retention_days: "30".into(),
        rate_limit_per_minute: "60".into(),
        rate_limit_per_hour: "600".into(),
        bucket_name,
        preview_bucket_name,
        sharing_token_secret: std::env::var("TAPCHAT_CLOUDFLARE_SHARING_SECRET")
            .unwrap_or_else(|_| generate_hex_secret()),
        device_runtime_secret: generate_hex_secret(),
        device_runtime_key_id: generate_secret_key_id(),
    }
}

pub fn resolve_cloudflare_config(
    defaults: &CloudflareDeployDefaults,
    overrides: &CloudflareDeployOverrides,
) -> ResolvedCloudflareDeployConfig {
    ResolvedCloudflareDeployConfig {
        runtime_id: uuid::Uuid::new_v4().to_string(),
        owner_user_id: String::new(),
        owner_user_public_key: String::new(),
        worker_name: overrides
            .worker_name
            .clone()
            .unwrap_or_else(|| defaults.worker_name.clone()),
        public_base_url: overrides
            .public_base_url
            .clone()
            .unwrap_or_else(|| defaults.public_base_url.clone()),
        deployment_region: overrides
            .deployment_region
            .clone()
            .unwrap_or_else(|| defaults.deployment_region.clone()),
        max_inline_bytes: overrides
            .max_inline_bytes
            .clone()
            .unwrap_or_else(|| defaults.max_inline_bytes.clone()),
        retention_days: overrides
            .retention_days
            .clone()
            .unwrap_or_else(|| defaults.retention_days.clone()),
        rate_limit_per_minute: overrides
            .rate_limit_per_minute
            .clone()
            .unwrap_or_else(|| defaults.rate_limit_per_minute.clone()),
        rate_limit_per_hour: overrides
            .rate_limit_per_hour
            .clone()
            .unwrap_or_else(|| defaults.rate_limit_per_hour.clone()),
        bucket_name: overrides
            .bucket_name
            .clone()
            .unwrap_or_else(|| defaults.bucket_name.clone()),
        preview_bucket_name: overrides
            .preview_bucket_name
            .clone()
            .unwrap_or_else(|| defaults.preview_bucket_name.clone()),
        sharing_token_secret: defaults.sharing_token_secret.clone(),
        device_runtime_secret: defaults.device_runtime_secret.clone(),
        device_runtime_key_id: defaults.device_runtime_key_id.clone(),
        device_runtime_previous_secret: None,
        device_runtime_previous_key_id: None,
        auth_rotation_grace_until_ms: None,
    }
}

pub fn prompt_cloudflare_overrides(
    defaults: &CloudflareDeployDefaults,
) -> Result<CloudflareDeployOverrides> {
    Ok(CloudflareDeployOverrides {
        worker_name: prompt_override("worker_name", &defaults.worker_name)?,
        public_base_url: prompt_override_allow_blank(
            "public_base_url",
            "leave blank to use deployed worker URL / request origin",
            &defaults.public_base_url,
        )?,
        deployment_region: prompt_override("deployment_region", &defaults.deployment_region)?,
        max_inline_bytes: prompt_override("max_inline_bytes", &defaults.max_inline_bytes)?,
        retention_days: prompt_override("retention_days", &defaults.retention_days)?,
        rate_limit_per_minute: prompt_override(
            "rate_limit_per_minute",
            &defaults.rate_limit_per_minute,
        )?,
        rate_limit_per_hour: prompt_override("rate_limit_per_hour", &defaults.rate_limit_per_hour)?,
        bucket_name: prompt_override("bucket_name", &defaults.bucket_name)?,
        preview_bucket_name: prompt_override("preview_bucket_name", &defaults.preview_bucket_name)?,
    })
}

pub async fn deploy_cloudflare_runtime(
    service_root: &Path,
    config: &ResolvedCloudflareDeployConfig,
) -> Result<CloudflareDeploymentResult> {
    if let Ok(stub) = std::env::var("TAPCHAT_CLOUDFLARE_DEPLOY_STUB_RESULT") {
        return serde_json::from_str(&stub).context("decode TAPCHAT_CLOUDFLARE_DEPLOY_STUB_RESULT");
    }
    let script_path = service_root.join("scripts").join("deploy-cloudflare.mjs");
    if !script_path.exists() {
        bail!(
            "cloudflare deploy script not found at {}; run from a workspace containing services/cloudflare",
            script_path.display()
        );
    }
    let config_json = serde_json::to_string(config)?;
    let node = resolve_node_command(service_root);
    let mut command = Command::new(node);
    command
        .arg(&script_path)
        .current_dir(service_root)
        .env("TAPCHAT_CLOUDFLARE_DEPLOY_CONFIG_JSON", config_json)
        .env("TAPCHAT_CLOUDFLARE_DEPLOY_OUTPUT", "json")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if resolve_embedded_runtime_root().is_some() {
        command.env("TAPCHAT_DESKTOP_BUNDLED", "1");
    }
    apply_windows_command_flags(&mut command);
    let output = command.output().context("run cloudflare deploy script")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        if let Some(json_line) = stdout
            .lines()
            .rev()
            .find(|line| line.trim_start().starts_with('{'))
        {
            if let Ok(parsed) = serde_json::from_str::<CloudflareDeploymentResult>(json_line) {
                let detail = parsed
                    .stderr_summary
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or_else(|| String::from_utf8_lossy(&output.stderr).trim().to_string());
                let failure_class = parsed.failure_class.unwrap_or_else(|| "unknown".into());
                bail!("cloudflare deploy script failed (failure_class={failure_class}): {detail}");
            }
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout_fallback = stdout.trim();
        let detail = if stderr.trim().is_empty() {
            stdout_fallback
        } else {
            stderr.trim()
        };
        bail!("cloudflare deploy script failed: {}", detail);
    }
    let json_line = stdout
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with('{'))
        .ok_or_else(|| anyhow::anyhow!("cloudflare deploy script did not emit a JSON result"))?;
    serde_json::from_str(json_line).context("decode cloudflare deploy result")
}

#[cfg(windows)]
fn start_local_runtime_windows(
    service_root: &Path,
    persist_to: &Path,
    port: u16,
    base_url: &str,
    runtime_id: &str,
    owner_user_id: &str,
    owner_user_public_key: &str,
    runtime_secret: &str,
    sharing_secret: &str,
) -> Result<LocalRuntimeInstance> {
    let stdout_path = persist_to.join("runtime-stdout.log");
    let stderr_path = persist_to.join("runtime-stderr.log");
    let launch_script_path = persist_to.join("runtime-launch.ps1");
    let runtime_script_path = service_root.join("scripts").join("transport-runtime.mjs");
    let _ = std::fs::remove_file(&stdout_path);
    let _ = std::fs::remove_file(&stderr_path);
    std::fs::write(
        &launch_script_path,
        format!(
            "$env:TAPCHAT_TRANSPORT_PORT = \"{port}\"\n\
$env:TAPCHAT_TRANSPORT_PERSIST_TO = \"{}\"\n\
$env:TAPCHAT_TRANSPORT_RUNTIME_ID = \"{}\"\n\
$env:TAPCHAT_TRANSPORT_OWNER_USER_ID = \"{}\"\n\
$env:TAPCHAT_TRANSPORT_OWNER_USER_PUBLIC_KEY = \"{}\"\n\
$env:TAPCHAT_TRANSPORT_RUNTIME_SECRET = \"{}\"\n\
$env:TAPCHAT_TRANSPORT_SHARING_SECRET = \"{}\"\n\
node \"{}\" *> \"{}\"\n",
            escape_ps_double_quoted(&persist_to.to_string_lossy()),
            escape_ps_double_quoted(runtime_id),
            escape_ps_double_quoted(owner_user_id),
            escape_ps_double_quoted(owner_user_public_key),
            escape_ps_double_quoted(runtime_secret),
            escape_ps_double_quoted(sharing_secret),
            escape_ps_double_quoted(&runtime_script_path.to_string_lossy()),
            escape_ps_double_quoted(&stdout_path.to_string_lossy()),
        ),
    )
    .context("write detached runtime launch script")?;

    let mut starter = Command::new("pwsh");
    starter
        .args(["-NoProfile", "-Command"])
        .arg(format!(
            "$proc = Start-Process -FilePath 'pwsh' -ArgumentList '-NoProfile', '-File', '{}' -WorkingDirectory '{}' -WindowStyle Hidden -PassThru; $proc.Id",
            escape_ps_single_quoted(&launch_script_path.to_string_lossy()),
            escape_ps_single_quoted(&service_root.to_string_lossy()),
        ))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    apply_windows_command_flags(&mut starter);

    let output = starter
        .output()
        .context("spawn detached cloudflare transport runtime")?;
    if !output.status.success() {
        bail!(
            "failed to launch detached cloudflare runtime: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let pid = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u32>()
        .context("parse detached runtime pid")?;

    let metadata = wait_for_runtime_metadata(&stdout_path, &stderr_path)?;
    Ok(LocalRuntimeInstance {
        pid,
        base_url: metadata
            .get("baseUrl")
            .and_then(|value| value.as_str())
            .unwrap_or(base_url)
            .to_string(),
        websocket_base_url: metadata
            .get("websocketBaseUrl")
            .and_then(|value| value.as_str())
            .unwrap_or(&base_url.replace("http", "ws"))
            .to_string(),
        sharing_secret: sharing_secret.to_string(),
        service_root: service_root.to_path_buf(),
        cleanup_on_drop: true,
    })
}

#[cfg(windows)]
fn wait_for_runtime_metadata(stdout_path: &Path, stderr_path: &Path) -> Result<serde_json::Value> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(contents) = std::fs::read_to_string(stdout_path) {
            for line in contents.lines().filter(|line| !line.trim().is_empty()) {
                if let Ok(metadata) = serde_json::from_str(line) {
                    return Ok(metadata);
                }
            }
        }
        if Instant::now() >= deadline {
            let stderr = std::fs::read_to_string(stderr_path).unwrap_or_default();
            let stdout = std::fs::read_to_string(stdout_path).unwrap_or_default();
            bail!(
                "cloudflare runtime metadata was not emitted in time{}{}",
                if stdout.trim().is_empty() {
                    String::new()
                } else {
                    format!("; stdout: {}", stdout.trim())
                },
                if stderr.trim().is_empty() {
                    String::new()
                } else {
                    format!("; stderr: {}", stderr.trim())
                },
            );
        }
        thread::sleep(Duration::from_millis(200));
    }
}

#[cfg(windows)]
fn escape_ps_single_quoted(value: &str) -> String {
    value.replace('\'', "''")
}

#[cfg(windows)]
fn escape_ps_double_quoted(value: &str) -> String {
    value.replace('`', "``").replace('"', "`\"")
}

pub async fn wait_until_ready(base_url: &str) -> Result<()> {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("build reqwest client")?;

    // Initial wait for global deployment propagation (Cloudflare needs ~3-5 seconds)
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(90);
    #[allow(unused_assignments)]
    let mut last_error = String::new();
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let response = client
            .get(format!("{base_url}/v1/deployment-bundle"))
            .send()
            .await;
        match response {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    if let Ok(body) = resp.text().await {
                        if let Ok(json_body) = to_snake_case_json_string(&body) {
                            match serde_json::from_str::<DeploymentBundle>(&json_body) {
                                Ok(_) => return Ok(()),
                                Err(e) => {
                                    last_error = format!(
                                        "Parse error: {} (body: {})",
                                        e,
                                        &body[..body.len().min(200)]
                                    );
                                }
                            }
                        } else {
                            last_error = format!(
                                "JSON conversion failed (body: {})",
                                &body[..body.len().min(200)]
                            );
                        }
                    } else {
                        last_error = "Failed to read response body".to_string();
                    }
                } else {
                    if let Ok(body) = resp.text().await {
                        last_error =
                            format!("HTTP {} (body: {})", status, &body[..body.len().min(200)]);
                    } else {
                        last_error = format!("HTTP {}", status);
                    }
                }
            }
            Err(e) => {
                last_error = format!("Request error: {}", e);
            }
        }
        if attempt % 10 == 0 {
            eprintln!(
                "wait_until_ready attempt {} - last error: {}",
                attempt, last_error
            );
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("runtime_not_ready_in_time: cloudflare runtime did not become ready in time for {base_url}. Last error: {last_error}");
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeCredentialResponse {
    runtime_credential: DeviceRuntimeAuth,
}

async fn runtime_auth_response_error(response: reqwest::Response, stage: &str) -> anyhow::Error {
    let status = response.status();
    let code = response
        .json::<serde_json::Value>()
        .await
        .ok()
        .and_then(|body| {
            body.get("error")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| format!("http_{}", status.as_u16()));
    anyhow::anyhow!("runtime_auth_error:{stage}:{code}")
}

fn unix_time_ms() -> Result<u64> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before unix epoch")?;
    u64::try_from(elapsed.as_millis()).context("current time does not fit in u64")
}

/// Fetches the public v3 deployment descriptor. Runtime bearer credentials are
/// deliberately returned by enrollment/refresh and never embedded in this value.
pub async fn fetch_deployment_bundle_v3(
    base_url: &str,
    user_id: &str,
    device_id: &str,
) -> Result<DeploymentBundle> {
    let mut bundle = Client::new()
        .get(format!(
            "{}/v1/deployment-bundle",
            base_url.trim_end_matches('/')
        ))
        .send()
        .await
        .context("fetch runtime deployment descriptor")?
        .error_for_status()
        .context("runtime deployment descriptor was rejected")?
        .json::<DeploymentBundle>()
        .await
        .context("decode runtime deployment descriptor")?;
    bundle.expected_user_id = Some(user_id.to_string());
    bundle.expected_device_id = Some(device_id.to_string());
    bundle
        .validate()
        .context("validate runtime deployment descriptor")?;
    if !bundle
        .runtime_config
        .features
        .iter()
        .any(|feature| feature == "device_runtime_refresh_v2")
    {
        bail!("upgrade_required: runtime does not support device_runtime_refresh_v2");
    }
    Ok(bundle)
}

async fn request_device_runtime_credential_v2(
    deployment: &DeploymentBundle,
    identity: &LocalIdentityState,
    purpose: &str,
    device: Option<&DeviceContactProfile>,
) -> Result<DeviceRuntimeAuth> {
    let user_id = &identity.user_identity.user_id;
    let device_id = &identity.device_identity.device_id;
    let base_url = deployment.inbox_http_endpoint.trim_end_matches('/');
    let client = Client::new();
    let response = client
        .post(format!("{base_url}/v2/runtime-auth/challenge"))
        .json(&json!({
            "purpose": purpose,
            "userId": user_id,
            "deviceId": device_id,
        }))
        .send()
        .await
        .context("request runtime authorization challenge")?;
    if !response.status().is_success() {
        return Err(runtime_auth_response_error(response, "challenge").await);
    }
    let challenge = response
        .json::<DeviceRuntimeRefreshChallenge>()
        .await
        .context("decode runtime authorization challenge")?;
    if challenge.version != CURRENT_MODEL_VERSION
        || challenge.purpose != purpose
        || challenge.runtime_id != deployment.runtime_id
        || challenge.user_id != *user_id
        || challenge.device_id != *device_id
        || challenge.expires_at <= unix_time_ms()?
    {
        bail!("runtime_auth_error:challenge:runtime_mismatch");
    }
    let proof = DeviceRuntimeRefreshProof {
        signature: identity.sign_sender_proof(challenge.signing_payload().as_bytes()),
        challenge,
    };
    let (endpoint, body) = match (purpose, device) {
        ("enroll", Some(device)) => (
            "enroll",
            json!({
                "challenge": proof.challenge,
                "signature": proof.signature,
                "device": device,
            }),
        ),
        ("refresh", None) => (
            "refresh",
            serde_json::to_value(&proof).context("encode runtime refresh proof")?,
        ),
        _ => bail!("invalid runtime authorization proof inputs"),
    };
    let response = client
        .post(format!("{base_url}/v2/runtime-auth/{endpoint}"))
        .json(&body)
        .send()
        .await
        .with_context(|| format!("submit runtime authorization {endpoint} proof"))?;
    if !response.status().is_success() {
        return Err(runtime_auth_response_error(response, endpoint).await);
    }
    let credential = response
        .json::<RuntimeCredentialResponse>()
        .await
        .context("decode runtime credential")?
        .runtime_credential;
    credential
        .validate()
        .context("validate runtime credential")?;
    if credential.runtime_id != deployment.runtime_id
        || credential.user_id != *user_id
        || credential.device_id != *device_id
        || credential.expires_at.saturating_sub(credential.issued_at) != 24 * 60 * 60 * 1_000
    {
        bail!("runtime_auth_error:{endpoint}:runtime_mismatch");
    }
    Ok(credential)
}

pub async fn enroll_device_runtime_v2(
    deployment: &DeploymentBundle,
    identity: &LocalIdentityState,
    identity_bundle: &IdentityBundle,
) -> Result<DeviceRuntimeAuth> {
    let device = identity_bundle
        .devices
        .iter()
        .find(|device| device.device_id == identity.device_identity.device_id)
        .ok_or_else(|| {
            anyhow::anyhow!("enrollment_required: local device is absent from IdentityBundle")
        })?;
    request_device_runtime_credential_v2(deployment, identity, "enroll", Some(device)).await
}

pub async fn refresh_device_runtime_v2(
    deployment: &DeploymentBundle,
    identity: &LocalIdentityState,
) -> Result<DeviceRuntimeAuth> {
    request_device_runtime_credential_v2(deployment, identity, "refresh", None).await
}

// v1 bootstrap issuance was removed by the v3 runtime authorization cutover.

pub fn cloudflare_preflight(profile_root: Option<&Path>) -> CloudflarePreflight {
    let service_root = resolve_service_root(None, profile_root).ok();
    let workspace_root = resolve_workspace_root(None, profile_root).ok().or_else(|| {
        service_root
            .as_ref()
            .and_then(|root| root.parent().map(PathBuf::from))
    });
    let wrangler_entry = service_root.as_ref().map(|root| {
        root.join("node_modules")
            .join("wrangler")
            .join("bin")
            .join("wrangler.js")
    });
    let wrangler_available = wrangler_entry.as_ref().is_some_and(|path| path.exists());
    let wrangler_logged_in = if wrangler_available {
        check_wrangler_logged_in(service_root.as_deref()).unwrap_or(false)
    } else {
        false
    };
    let blocking_error = if workspace_root.is_none() {
        Some(
            "Workspace root not found. Expected services/cloudflare/scripts/transport-runtime.mjs."
                .into(),
        )
    } else if service_root.is_none() {
        Some("Cloudflare deploy runtime is not available.".into())
    } else if !wrangler_available {
        Some(
            "Embedded Cloudflare deploy runtime is incomplete. Reinstall TapChat or rebuild the desktop bundle.".into(),
        )
    } else if !wrangler_logged_in {
        Some("Cloudflare authorization is required before deployment can continue.".into())
    } else {
        None
    };

    CloudflarePreflight {
        workspace_root_found: workspace_root.is_some(),
        workspace_root,
        service_root,
        wrangler_available,
        wrangler_logged_in,
        blocking_error,
    }
}

pub fn ensure_cloudflare_runtime_metadata(
    runtime: &crate::cli::profile::RuntimeMetadata,
) -> Result<()> {
    if runtime.mode.as_deref() != Some("cloudflare") {
        bail!("runtime metadata is not bound to a cloudflare deployment");
    }
    Ok(())
}

/// Prepare the first keyed deployment for a legacy profile without rotating
/// the long-lived sharing secret. The exact two-slot state is persisted before
/// any deployment command, so a retry cannot create a third key generation.
pub fn prepare_legacy_runtime_secret_migration(
    profile: &crate::cli::profile::Profile,
    runtime: &mut crate::cli::profile::RuntimeMetadata,
    secrets: &mut crate::cli::profile::RuntimeSecrets,
) -> Result<bool> {
    let needs_runtime_key =
        secrets.device_runtime_secret.is_none() || secrets.device_runtime_key_id.is_none();
    if !needs_runtime_key {
        return Ok(false);
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64;
    let grace_until_ms = now_ms.saturating_add(48 * 60 * 60 * 1_000);
    if needs_runtime_key {
        let sharing = secrets
            .sharing_secret
            .clone()
            .or_else(|| runtime.sharing_secret.clone())
            .ok_or_else(|| anyhow::anyhow!("cloudflare sharing_secret is not recorded"))?;
        secrets.previous_device_runtime_secret = Some(sharing);
        secrets.previous_device_runtime_key_id = None;
        secrets.device_runtime_secret = Some(generate_hex_secret());
        secrets.device_runtime_key_id = Some(generate_secret_key_id());
    }
    secrets.bootstrap_secret = None;
    secrets.bootstrap_key_id = None;
    secrets.previous_bootstrap_secret = None;
    secrets.previous_bootstrap_key_id = None;
    runtime.secret_rotation = crate::cli::profile::RuntimeSecretRotationMetadata {
        phase: crate::cli::profile::RuntimeSecretRotationPhase::Prepared,
        current_key_id: secrets.device_runtime_key_id.clone(),
        previous_key_id: secrets.previous_device_runtime_key_id.clone(),
        prepared_at_ms: Some(now_ms),
        last_rotated_at_ms: runtime.secret_rotation.last_rotated_at_ms,
        next_rotation_at_ms: runtime.secret_rotation.next_rotation_at_ms,
        grace_until_ms: Some(grace_until_ms),
        last_error: None,
    };
    profile.save_runtime_rotation_state(runtime, secrets)?;
    Ok(true)
}

pub fn prepare_runtime_secret_rotation(
    profile: &crate::cli::profile::Profile,
    runtime: &mut crate::cli::profile::RuntimeMetadata,
    secrets: &mut crate::cli::profile::RuntimeSecrets,
) -> Result<()> {
    use crate::cli::profile::{RuntimeSecretRotationMetadata, RuntimeSecretRotationPhase};

    match runtime.secret_rotation.phase {
        RuntimeSecretRotationPhase::Prepared
        | RuntimeSecretRotationPhase::Deploying
        | RuntimeSecretRotationPhase::Failed => return Ok(()),
        RuntimeSecretRotationPhase::Grace => {
            bail!("the previous secret rotation must be finalized before starting another")
        }
        RuntimeSecretRotationPhase::PendingAuthorization
            if secrets.previous_device_runtime_secret.is_some() =>
        {
            return Ok(())
        }
        RuntimeSecretRotationPhase::Stable | RuntimeSecretRotationPhase::PendingAuthorization => {}
    }

    let old_runtime_secret = secrets
        .device_runtime_secret
        .clone()
        .or_else(|| secrets.sharing_secret.clone())
        .or_else(|| runtime.sharing_secret.clone())
        .ok_or_else(|| anyhow::anyhow!("device runtime secret is not recorded"))?;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64;
    let new_runtime_key_id = generate_secret_key_id();
    secrets.previous_device_runtime_secret = Some(old_runtime_secret);
    secrets.previous_device_runtime_key_id = secrets.device_runtime_key_id.clone();
    secrets.device_runtime_secret = Some(generate_hex_secret());
    secrets.device_runtime_key_id = Some(new_runtime_key_id.clone());
    secrets.bootstrap_secret = None;
    secrets.bootstrap_key_id = None;
    secrets.previous_bootstrap_secret = None;
    secrets.previous_bootstrap_key_id = None;
    runtime.secret_rotation = RuntimeSecretRotationMetadata {
        phase: RuntimeSecretRotationPhase::Prepared,
        current_key_id: Some(new_runtime_key_id),
        previous_key_id: secrets.previous_device_runtime_key_id.clone(),
        prepared_at_ms: Some(now_ms),
        last_rotated_at_ms: runtime.secret_rotation.last_rotated_at_ms,
        next_rotation_at_ms: runtime.secret_rotation.next_rotation_at_ms,
        grace_until_ms: Some(now_ms.saturating_add(48 * 60 * 60 * 1_000)),
        last_error: None,
    };
    profile.save_runtime_rotation_state(runtime, secrets)?;
    Ok(())
}

pub fn rebuild_cloudflare_config(
    runtime: &crate::cli::profile::RuntimeMetadata,
    secrets: &crate::cli::profile::RuntimeSecrets,
) -> Result<ResolvedCloudflareDeployConfig> {
    Ok(ResolvedCloudflareDeployConfig {
        runtime_id: runtime
            .runtime_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        owner_user_id: String::new(),
        owner_user_public_key: String::new(),
        worker_name: runtime
            .worker_name
            .clone()
            .ok_or_else(|| anyhow::anyhow!("cloudflare worker_name is not recorded"))?,
        public_base_url: runtime.public_base_url.clone().unwrap_or_default(),
        deployment_region: runtime
            .deployment_region
            .clone()
            .unwrap_or_else(|| "global".into()),
        max_inline_bytes: "4096".into(),
        retention_days: "30".into(),
        rate_limit_per_minute: "60".into(),
        rate_limit_per_hour: "600".into(),
        bucket_name: runtime
            .bucket_name
            .clone()
            .ok_or_else(|| anyhow::anyhow!("cloudflare bucket_name is not recorded"))?,
        preview_bucket_name: runtime
            .preview_bucket_name
            .clone()
            .ok_or_else(|| anyhow::anyhow!("cloudflare preview_bucket_name is not recorded"))?,
        sharing_token_secret: secrets
            .sharing_secret
            .clone()
            .or_else(|| runtime.sharing_secret.clone())
            .ok_or_else(|| anyhow::anyhow!("cloudflare sharing_secret is not recorded"))?,
        device_runtime_secret: secrets.device_runtime_secret.clone().unwrap_or_else(|| {
            runtime
                .sharing_secret
                .clone()
                .unwrap_or_else(generate_hex_secret)
        }),
        device_runtime_key_id: secrets
            .device_runtime_key_id
            .clone()
            .unwrap_or_else(|| "legacy-runtime".into()),
        device_runtime_previous_secret: secrets.previous_device_runtime_secret.clone(),
        device_runtime_previous_key_id: secrets.previous_device_runtime_key_id.clone(),
        auth_rotation_grace_until_ms: runtime.secret_rotation.grace_until_ms,
    })
}

pub fn resolve_workspace_root(
    explicit: Option<&Path>,
    profile_root: Option<&Path>,
) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return resolve_workspace_candidate(path)
            .with_context(|| format!("resolve workspace root from {}", path.display()));
    }

    if let Some(embedded) = resolve_embedded_workspace_root() {
        return Ok(embedded);
    }

    let mut candidates = Vec::new();
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            candidates.push(parent.to_path_buf());
        }
    }
    if let Some(profile_root) = profile_root {
        candidates.push(profile_root.to_path_buf());
    }
    if let Ok(current_dir) = std::env::current_dir() {
        candidates.push(current_dir);
    }
    candidates.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")));

    for candidate in candidates {
        if let Ok(root) = resolve_workspace_candidate(&candidate) {
            return Ok(root);
        }
    }

    bail!(
        "unable to locate workspace root containing services/cloudflare/scripts/transport-runtime.mjs; pass --workspace-root explicitly"
    )
}

pub fn resolve_service_root(
    explicit: Option<&Path>,
    profile_root: Option<&Path>,
) -> Result<PathBuf> {
    if let Some(path) = explicit {
        let direct_script = path.join("scripts").join("transport-runtime.mjs");
        if direct_script.exists() {
            return Ok(path.to_path_buf());
        }
        let workspace_script = path
            .join("services")
            .join("cloudflare")
            .join("scripts")
            .join("transport-runtime.mjs");
        if workspace_script.exists() {
            return Ok(path.join("services").join("cloudflare"));
        }
        return Ok(path.to_path_buf());
    }

    if let Some(embedded) = resolve_embedded_service_root() {
        return Ok(embedded);
    }

    Ok(resolve_workspace_root(explicit, profile_root)?
        .join("services")
        .join("cloudflare"))
}

pub fn resolve_embedded_runtime_root() -> Option<PathBuf> {
    // 1. Environment variable override (highest priority)
    if let Some(path) = std::env::var_os(DESKTOP_EMBEDDED_RUNTIME_ROOT_ENV)
        .map(PathBuf::from)
        .filter(|p| p.exists())
    {
        return Some(path);
    }

    // 2. Relative to executable (bundled mode — works on Windows, macOS .app, and typical Linux installs)
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let embedded = exe_dir.join("embedded");
            if embedded.exists() {
                return Some(embedded);
            }
        }
    }

    None
}

pub fn resolve_embedded_workspace_root() -> Option<PathBuf> {
    std::env::var_os(DESKTOP_EMBEDDED_WORKSPACE_ROOT_ENV)
        .map(PathBuf::from)
        .filter(|path| path.exists())
        .or_else(|| {
            resolve_embedded_service_root()
                .and_then(|service_root| service_root.parent().map(PathBuf::from))
        })
}

pub fn resolve_embedded_service_root() -> Option<PathBuf> {
    std::env::var_os(DESKTOP_EMBEDDED_SERVICE_ROOT_ENV)
        .map(PathBuf::from)
        .filter(|path| path.exists())
        .or_else(|| {
            let runtime_root = resolve_embedded_runtime_root()?;
            let candidate = runtime_root.join("cloudflare-service");
            candidate.exists().then_some(candidate)
        })
}

pub fn resolve_node_command(service_root: &Path) -> String {
    if let Ok(explicit) = std::env::var("TAPCHAT_NODE_PATH") {
        return explicit;
    }

    if let Some(runtime_root) = resolve_embedded_runtime_root() {
        let node_name = if cfg!(windows) { "node.exe" } else { "node" };
        let candidate = runtime_root.join("node").join(node_name);
        if candidate.exists() {
            return candidate.to_string_lossy().to_string();
        }
    }

    let node_name = if cfg!(windows) { "node.exe" } else { "node" };
    let bundled_candidate = service_root
        .parent()
        .map(|root| root.join("node").join(node_name));
    if let Some(candidate) = bundled_candidate.filter(|path| path.exists()) {
        return candidate.to_string_lossy().to_string();
    }

    "node".into()
}

fn resolve_workspace_candidate(start: &Path) -> Result<PathBuf> {
    for candidate in start.ancestors() {
        let script = candidate
            .join("services")
            .join("cloudflare")
            .join("scripts")
            .join("transport-runtime.mjs");
        if script.exists() {
            return Ok(candidate.to_path_buf());
        }
    }
    bail!("workspace root not found")
}

pub fn stop_local_runtime(pid: u32) -> Result<()> {
    #[cfg(windows)]
    {
        let mut command = Command::new("taskkill");
        command.args(["/PID", &pid.to_string(), "/T", "/F"]);
        apply_windows_command_flags(&mut command);
        let output = command.output().context("run taskkill")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let detail = stderr.trim();
            if detail.is_empty() {
                bail!("taskkill failed for pid {pid}: {}", stdout.trim());
            }
            bail!("taskkill failed for pid {pid}: {detail}");
        }
        wait_for_process_exit(pid, Duration::from_secs(15))?;
    }
    #[cfg(not(windows))]
    {
        let output = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .output()
            .context("run kill")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let detail = stderr.trim();
            if detail.is_empty() {
                bail!("kill failed for pid {pid}: {}", stdout.trim());
            }
            bail!("kill failed for pid {pid}: {detail}");
        }
        wait_for_process_exit(pid, Duration::from_secs(15))?;
    }
    Ok(())
}

fn wait_for_process_exit(pid: u32, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !process_is_running(pid)? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    bail!("process {pid} did not exit in time")
}

fn process_is_running(pid: u32) -> Result<bool> {
    #[cfg(windows)]
    {
        let mut command = Command::new("tasklist");
        command.args(["/FI", &format!("PID eq {pid}")]);
        apply_windows_command_flags(&mut command);
        let output = command.output().context("run tasklist")?;
        if !output.status.success() {
            bail!(
                "tasklist failed for pid {pid}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.lines().any(|line| line.contains(&pid.to_string())))
    }
    #[cfg(not(windows))]
    {
        let output = Command::new("kill")
            .args(["-0", &pid.to_string()])
            .output()
            .context("run kill -0")?;
        Ok(output.status.success())
    }
}

fn check_wrangler_logged_in(service_root: Option<&Path>) -> Result<bool> {
    let Some(service_root) = service_root else {
        return Ok(false);
    };
    let wrangler_entry = service_root
        .join("node_modules")
        .join("wrangler")
        .join("bin")
        .join("wrangler.js");
    if !wrangler_entry.exists() {
        return Ok(false);
    }
    let node = resolve_node_command(service_root);
    let mut command = Command::new(node);
    command
        .arg(&wrangler_entry)
        .arg("whoami")
        .current_dir(service_root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    apply_windows_command_flags(&mut command);
    let output = command.output();
    let Ok(output) = output else {
        return Ok(false);
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
        let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
        if stderr.contains("not authenticated")
            || stderr.contains("wrangler login")
            || stdout.contains("not authenticated")
            || stdout.contains("wrangler login")
        {
            return Ok(false);
        }
    }
    Ok(output.status.success())
}

fn reserve_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("bind random port")?;
    let port = listener.local_addr().context("get local addr")?.port();
    drop(listener);
    Ok(port)
}

fn prompt_override(label: &str, default_value: &str) -> Result<Option<String>> {
    let answer = prompt_line(&format!(
        "Override {label}? [default: {}] Leave blank to keep default: ",
        display_default(default_value)
    ))?;
    if answer.is_empty() {
        Ok(None)
    } else {
        Ok(Some(answer))
    }
}

fn prompt_override_allow_blank(
    label: &str,
    blank_note: &str,
    default_value: &str,
) -> Result<Option<String>> {
    let answer = prompt_line(&format!(
        "Override {label}? [default: {}] Leave blank to keep default; use '-' for empty ({blank_note}): ",
        display_default(default_value)
    ))?;
    if answer.is_empty() {
        Ok(None)
    } else if answer == "-" {
        Ok(Some(String::new()))
    } else {
        Ok(Some(answer))
    }
}

fn prompt_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush().context("flush stdout")?;
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer).context("read stdin")?;
    Ok(buffer.trim().to_string())
}

fn display_default(value: &str) -> &str {
    if value.is_empty() {
        "<empty>"
    } else {
        value
    }
}

pub fn generate_hex_secret() -> String {
    let mut bytes = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn generate_secret_key_id() -> String {
    format!("key-{}", &generate_hex_secret()[..16])
}

fn short_identifier(value: &str, max_len: usize) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .take(max_len)
        .collect()
}

fn sanitize_cloudflare_name(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for ch in value.chars() {
        let mapped = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_lowercase()
        } else {
            '-'
        };
        output.push(mapped);
    }
    let trimmed = output.trim_matches('-');
    let collapsed = trimmed
        .split('-')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    if collapsed.is_empty() {
        "tapchat-cloudflare".into()
    } else {
        collapsed
    }
}

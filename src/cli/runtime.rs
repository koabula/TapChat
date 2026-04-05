use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(not(windows))]
use std::io::{BufRead, BufReader};

use anyhow::{Context, Result, anyhow, bail};
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;

use crate::model::{CURRENT_MODEL_VERSION, DeploymentBundle, DeviceRuntimeAuth, IdentityBundle};

use super::util::{sign_hmac_token, to_camel_case_json_string, to_snake_case_json_string};

#[derive(Debug, Clone)]
pub struct LocalRuntimeInstance {
    pub pid: u32,
    pub base_url: String,
    pub websocket_base_url: String,
    pub bootstrap_secret: String,
    pub sharing_secret: String,
}

pub fn start_local_runtime(workspace_root: impl AsRef<Path>, persist_to: impl AsRef<Path>) -> Result<LocalRuntimeInstance> {
    let workspace_root = workspace_root.as_ref();
    let service_root = workspace_root.join("services").join("cloudflare");
    let port = reserve_port()?;
    let base_url = format!("http://127.0.0.1:{port}");
    let bootstrap_secret = format!("transport-bootstrap-{port}");
    let sharing_secret = format!("transport-sharing-{port}");
    let persist_to = persist_to.as_ref();

    #[cfg(windows)]
    {
        start_local_runtime_windows(
            &service_root,
            persist_to,
            port,
            &base_url,
            &bootstrap_secret,
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
            .env("TAPCHAT_TRANSPORT_BOOTSTRAP_SECRET", &bootstrap_secret)
            .env("TAPCHAT_TRANSPORT_SHARING_SECRET", &sharing_secret)
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        let mut child = child.spawn().context("spawn cloudflare transport runtime")?;
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
            bootstrap_secret,
            sharing_secret,
        })
    }
}

#[cfg(windows)]
fn start_local_runtime_windows(
    service_root: &Path,
    persist_to: &Path,
    port: u16,
    base_url: &str,
    bootstrap_secret: &str,
    sharing_secret: &str,
) -> Result<LocalRuntimeInstance> {
    let stdout_path = persist_to.join("runtime-stdout.log");
    let stderr_path = persist_to.join("runtime-stderr.log");
    let launch_script_path = persist_to.join("runtime-launch.ps1");
    let _ = std::fs::remove_file(&stdout_path);
    let _ = std::fs::remove_file(&stderr_path);
    std::fs::write(
        &launch_script_path,
        format!(
            "$env:TAPCHAT_TRANSPORT_PORT = \"{port}\"\n\
$env:TAPCHAT_TRANSPORT_PERSIST_TO = \"{}\"\n\
$env:TAPCHAT_TRANSPORT_BOOTSTRAP_SECRET = \"{}\"\n\
$env:TAPCHAT_TRANSPORT_SHARING_SECRET = \"{}\"\n\
node scripts/transport-runtime.mjs *> \"{}\"\n",
            escape_ps_double_quoted(&persist_to.to_string_lossy()),
            escape_ps_double_quoted(bootstrap_secret),
            escape_ps_double_quoted(sharing_secret),
            escape_ps_double_quoted(&stdout_path.to_string_lossy()),
        ),
    )
    .context("write detached runtime launch script")?;

    let mut starter = Command::new("pwsh");
    starter
        .args(["-NoProfile", "-Command"])
        .arg(format!(
            "$proc = Start-Process -FilePath 'pwsh' -ArgumentList '-NoProfile', '-File', '{}' -WorkingDirectory '{}' -PassThru; $proc.Id",
            escape_ps_single_quoted(&launch_script_path.to_string_lossy()),
            escape_ps_single_quoted(&service_root.to_string_lossy()),
        ))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = starter.output().context("spawn detached cloudflare transport runtime")?;
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
        bootstrap_secret: bootstrap_secret.to_string(),
        sharing_secret: sharing_secret.to_string(),
    })
}

#[cfg(windows)]
fn wait_for_runtime_metadata(
    stdout_path: &Path,
    stderr_path: &Path,
) -> Result<serde_json::Value> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(contents) = std::fs::read_to_string(stdout_path) {
            if let Some(line) = contents.lines().find(|line| !line.trim().is_empty()) {
                return serde_json::from_str(line).context("parse detached runtime metadata");
            }
        }
        if Instant::now() >= deadline {
            let stderr = std::fs::read_to_string(stderr_path).unwrap_or_default();
            bail!(
                "cloudflare runtime metadata was not emitted in time{}",
                if stderr.trim().is_empty() {
                    String::new()
                } else {
                    format!("; stderr: {}", stderr.trim())
                }
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
    let client = Client::builder().build().context("build reqwest client")?;
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(30);
    loop {
        let response = client.get(format!("{base_url}/v1/deployment-bundle")).send().await;
        if let Ok(response) = response {
            if response.status().is_success() {
                return Ok(());
            }
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("cloudflare runtime did not become ready in time");
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    }
}

pub async fn bootstrap_device_bundle(
    base_url: &str,
    bootstrap_secret: &str,
    user_id: &str,
    device_id: &str,
) -> Result<DeploymentBundle> {
    let token = sign_hmac_token(
        bootstrap_secret,
        &json!({
            "version": CURRENT_MODEL_VERSION,
            "service": "bootstrap",
            "userId": user_id,
            "deviceId": device_id,
            "operations": ["issue_device_bundle"],
            "expiresAt": 4_102_444_800_000u64,
        }),
    )?;
    let client = Client::builder().build().context("build reqwest client")?;
    let response = client
        .post(format!("{base_url}/v1/bootstrap/device"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "version": CURRENT_MODEL_VERSION,
            "userId": user_id,
            "deviceId": device_id,
        }))
        .send()
        .await
        .context("bootstrap request failed")?;
    if !response.status().is_success() {
        bail!("bootstrap failed with status {}", response.status());
    }
    let body = response.text().await.context("read bootstrap response")?;
    Ok(serde_json::from_str(&to_snake_case_json_string(&body)?)?)
}

pub async fn put_identity_bundle(auth: &DeviceRuntimeAuth, bundle: &IdentityBundle) -> Result<()> {
    let reference = bundle
        .identity_bundle_ref
        .clone()
        .ok_or_else(|| anyhow!("identity bundle missing identity_bundle_ref"))?
        .replace("{userId}", &bundle.user_id);
    let client = Client::builder().build().context("build reqwest client")?;
    let body = serde_json::to_string(bundle)?;
    let response = client
        .put(reference)
        .header("Authorization", format!("Bearer {}", auth.token))
        .header("Content-Type", "application/json")
        .body(to_camel_case_json_string(&body)?)
        .send()
        .await
        .context("put identity bundle")?;
    if !response.status().is_success() {
        bail!("put identity bundle failed with status {}", response.status());
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct CliAllowlistDocument {
    allowed_sender_user_ids: Vec<String>,
    rejected_sender_user_ids: Vec<String>,
}

pub async fn allow_sender_user(auth: &DeviceRuntimeAuth, base_url: &str, sender_user_id: &str) -> Result<()> {
    let client = Client::builder().build().context("build reqwest client")?;
    let allowlist_url = format!(
        "{}/v1/inbox/{}/allowlist",
        base_url.trim_end_matches('/'),
        urlencoding::encode(&auth.device_id)
    );
    let existing = client
        .get(&allowlist_url)
        .header("Authorization", format!("Bearer {}", auth.token))
        .send()
        .await
        .context("get allowlist")?;
    let mut allowed_sender_user_ids = Vec::new();
    let mut rejected_sender_user_ids = Vec::new();
    if existing.status().is_success() {
        let body = existing.text().await.context("read allowlist response")?;
        let normalized = to_snake_case_json_string(&body)?;
        let document: CliAllowlistDocument = serde_json::from_str(&normalized)?;
        allowed_sender_user_ids = document.allowed_sender_user_ids;
        rejected_sender_user_ids = document.rejected_sender_user_ids;
    }
    if !allowed_sender_user_ids.iter().any(|user_id| user_id == sender_user_id) {
        allowed_sender_user_ids.push(sender_user_id.to_string());
        allowed_sender_user_ids.sort();
        allowed_sender_user_ids.dedup();
    }
    rejected_sender_user_ids.retain(|user_id| user_id != sender_user_id);
    let response = client
        .put(&allowlist_url)
        .header("Authorization", format!("Bearer {}", auth.token))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&json!({
            "allowedSenderUserIds": allowed_sender_user_ids,
            "rejectedSenderUserIds": rejected_sender_user_ids,
        }))?)
        .send()
        .await
        .context("put allowlist")?;
    if !response.status().is_success() {
        bail!("put allowlist failed with status {}", response.status());
    }
    Ok(())
}
pub fn stop_local_runtime(pid: u32) -> Result<()> {
    #[cfg(windows)]
    {
        let output = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .output()
            .context("run taskkill")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let detail = stderr.trim();
            if detail.is_empty() {
                bail!("taskkill failed for pid {pid}: {}", stdout.trim());
            }
            bail!("taskkill failed for pid {pid}: {detail}");
        }
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
    }
    Ok(())
}

fn reserve_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("bind random port")?;
    let port = listener.local_addr().context("get local addr")?.port();
    drop(listener);
    Ok(port)
}



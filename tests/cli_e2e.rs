use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;
use tapchat_core::model::{DeploymentBundle, DeviceRuntimeAuth, IdentityBundle};
use tapchat_transport_adapter::CloudflareRuntimeHandle;
use tempfile::{Builder, TempDir};

const ALICE_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const BOB_MNEMONIC: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

#[test]
fn cli_runtime_local_start_stop_and_status_work() -> Result<()> {
    let _guard = test_lock();
    let temp_root = repo_temp_dir("runtime")?;
    let profile_root = temp_root.path().join("runtime-profile");

    run_cli_json([
        "profile",
        "init",
        "--name",
        "runtime",
        "--root",
        &profile_root.to_string_lossy(),
    ])?;
    let device = run_cli_json([
        "device",
        "create",
        "--profile",
        &profile_root.to_string_lossy(),
        "--device-name",
        "phone",
    ])?;
    assert!(device["user_id"].is_string());
    assert!(device["device_id"].is_string());

    let started = run_cli_json([
        "runtime",
        "local-start",
        "--profile",
        &profile_root.to_string_lossy(),
    ])?;
    let pid = started["pid"].as_u64().context("runtime start missing pid")? as u32;
    let mut pid_guard = RuntimePidGuard::new(pid);
    assert_eq!(started["started"], Value::Bool(true));
    assert!(started["base_url"].as_str().unwrap_or_default().starts_with("http://127.0.0.1:"));
    assert!(
        started["websocket_base_url"]
            .as_str()
            .unwrap_or_default()
            .starts_with("ws://127.0.0.1:")
    );

    let status = run_cli_json([
        "runtime",
        "local-status",
        "--profile",
        &profile_root.to_string_lossy(),
    ])?;
    assert_eq!(status["pid"].as_u64(), Some(pid as u64));
    assert_eq!(status["mode"].as_str(), Some("local"));
    assert!(status["base_url"].as_str().unwrap_or_default().starts_with("http://127.0.0.1:"));
    assert!(
        status["websocket_base_url"]
            .as_str()
            .unwrap_or_default()
            .starts_with("ws://127.0.0.1:")
    );

    let stopped = run_cli_json([
        "runtime",
        "local-stop",
        "--profile",
        &profile_root.to_string_lossy(),
    ])?;
    assert_eq!(stopped["stopped"], Value::Bool(true));
    pid_guard.clear();

    let cleared = run_cli_json([
        "runtime",
        "local-status",
        "--profile",
        &profile_root.to_string_lossy(),
    ])?;
    assert!(cleared["pid"].is_null());
    assert!(cleared["base_url"].is_null());
    assert!(cleared["websocket_base_url"].is_null());
    assert!(cleared["mode"].is_null());

    Ok(())
}

#[test]
fn cli_direct_message_and_attachment_e2e_work() -> Result<()> {
    let _guard = test_lock();
    let workspace_root = workspace_root();
    let runtime = runtime_handle(&workspace_root)?;
    let temp_root = repo_temp_dir("direct")?;
    let alice_profile = temp_root.path().join("alice");
    let bob_profile = temp_root.path().join("bob");
    let alice_mnemonic = write_mnemonic_file(temp_root.path(), "alice-mnemonic.txt", ALICE_MNEMONIC)?;
    let bob_mnemonic = write_mnemonic_file(temp_root.path(), "bob-mnemonic.txt", BOB_MNEMONIC)?;

    run_cli_json([
        "profile",
        "init",
        "--name",
        "alice",
        "--root",
        &alice_profile.to_string_lossy(),
    ])?;
    run_cli_json([
        "profile",
        "init",
        "--name",
        "bob",
        "--root",
        &bob_profile.to_string_lossy(),
    ])?;

    let alice_identity = run_cli_json([
        "device",
        "recover",
        "--profile",
        &alice_profile.to_string_lossy(),
        "--device-name",
        "phone",
        "--mnemonic-file",
        &alice_mnemonic.to_string_lossy(),
    ])?;
    let bob_identity = run_cli_json([
        "device",
        "recover",
        "--profile",
        &bob_profile.to_string_lossy(),
        "--device-name",
        "phone",
        "--mnemonic-file",
        &bob_mnemonic.to_string_lossy(),
    ])?;

    let alice_user_id = required_str(&alice_identity, "user_id")?;
    let alice_device_id = required_str(&alice_identity, "device_id")?;
    let bob_user_id = required_str(&bob_identity, "user_id")?;
    let bob_device_id = required_str(&bob_identity, "device_id")?;

    let alice_bundle = runtime_bootstrap_device_bundle(&runtime, &alice_user_id, &alice_device_id)?;
    let bob_bundle = runtime_bootstrap_device_bundle(&runtime, &bob_user_id, &bob_device_id)?;
    let alice_bundle_path = write_json_file(temp_root.path(), "alice-deployment.json", &alice_bundle)?;
    let bob_bundle_path = write_json_file(temp_root.path(), "bob-deployment.json", &bob_bundle)?;

    run_cli_json([
        "profile",
        "import-deployment",
        "--profile",
        &alice_profile.to_string_lossy(),
        &alice_bundle_path.to_string_lossy(),
    ])?;
    run_cli_json([
        "profile",
        "import-deployment",
        "--profile",
        &bob_profile.to_string_lossy(),
        &bob_bundle_path.to_string_lossy(),
    ])?;

    let alice_identity_path = temp_root.path().join("alice-identity.json");
    let bob_identity_path = temp_root.path().join("bob-identity.json");
    let alice_export = run_cli_json([
        "profile",
        "export-identity",
        "--profile",
        &alice_profile.to_string_lossy(),
        "--out",
        &alice_identity_path.to_string_lossy(),
    ])?;
    let bob_export = run_cli_json([
        "profile",
        "export-identity",
        "--profile",
        &bob_profile.to_string_lossy(),
        "--out",
        &bob_identity_path.to_string_lossy(),
    ])?;
    assert_eq!(required_str(&alice_export, "written")?, alice_identity_path.to_string_lossy());
    assert_eq!(required_str(&bob_export, "written")?, bob_identity_path.to_string_lossy());

    let alice_identity_bundle: IdentityBundle = read_json_file(&alice_identity_path)?;
    let bob_identity_bundle: IdentityBundle = read_json_file(&bob_identity_path)?;
    runtime_put_identity_bundle(&runtime, bundle_auth(&alice_bundle)?, &alice_identity_bundle)?;
    runtime_put_identity_bundle(&runtime, bundle_auth(&bob_bundle)?, &bob_identity_bundle)?;

    run_cli_json([
        "contact",
        "import-identity",
        "--profile",
        &alice_profile.to_string_lossy(),
        &bob_identity_path.to_string_lossy(),
    ])?;
    run_cli_json([
        "contact",
        "import-identity",
        "--profile",
        &bob_profile.to_string_lossy(),
        &alice_identity_path.to_string_lossy(),
    ])?;

    let created = run_cli_json([
        "conversation",
        "create-direct",
        "--profile",
        &alice_profile.to_string_lossy(),
        "--peer-user-id",
        &bob_user_id,
    ])?;
    let conversation_id = required_str(&created, "conversation_id")?;

    run_cli_json([
        "message",
        "send-text",
        "--profile",
        &alice_profile.to_string_lossy(),
        "--conversation-id",
        &conversation_id,
        "--text",
        "hello from cli e2e",
    ])?;
    let first_sync = run_cli_json([
        "sync",
        "once",
        "--profile",
        &bob_profile.to_string_lossy(),
    ])?;
    assert_eq!(first_sync["synced"], Value::Bool(true));
    assert!(first_sync["checkpoint"]["last_acked_seq"].as_u64().unwrap_or_default() >= 3);

    let bob_conversations = run_cli_json([
        "conversation",
        "list",
        "--profile",
        &bob_profile.to_string_lossy(),
    ])?;
    assert!(bob_conversations
        .as_array()
        .context("conversation list not array")?
        .iter()
        .any(|row| row["conversation_id"].as_str() == Some(conversation_id.as_str())));

    let bob_show = run_cli_json([
        "conversation",
        "show",
        "--profile",
        &bob_profile.to_string_lossy(),
        "--conversation-id",
        &conversation_id,
    ])?;
    assert_eq!(bob_show["conversation_state"].as_str(), Some("active"));
    assert_eq!(bob_show["recovery_status"].as_str(), Some("Healthy"));
    assert!(bob_show["message_count"].as_u64().unwrap_or_default() >= 3);

    let first_messages = run_cli_json([
        "message",
        "list",
        "--profile",
        &bob_profile.to_string_lossy(),
        "--conversation-id",
        &conversation_id,
    ])?;
    assert!(first_messages
        .as_array()
        .context("message list not array")?
        .iter()
        .any(|message| message["plaintext"].as_str() == Some("hello from cli e2e")));

    let attachment_path = temp_root.path().join("attachment.txt");
    fs::write(&attachment_path, "hello from cli attachment e2e")?;
    let attachment_send = run_cli_json([
        "message",
        "send-attachment",
        "--profile",
        &alice_profile.to_string_lossy(),
        "--conversation-id",
        &conversation_id,
        "--file",
        &attachment_path.to_string_lossy(),
    ])?;
    assert_eq!(attachment_send["queued"], Value::Bool(true));
    assert_eq!(attachment_send["pending_outbox"].as_u64(), Some(0));
    assert_eq!(attachment_send["pending_blob_uploads"].as_u64(), Some(0));

    let alice_sync_status = run_cli_json([
        "sync",
        "status",
        "--profile",
        &alice_profile.to_string_lossy(),
    ])?;
    assert_eq!(alice_sync_status["pending_outbox"].as_u64(), Some(0));
    assert_eq!(alice_sync_status["pending_blob_uploads"].as_u64(), Some(0));

    let second_sync = run_cli_json([
        "sync",
        "once",
        "--profile",
        &bob_profile.to_string_lossy(),
    ])?;
    assert_eq!(second_sync["synced"], Value::Bool(true));
    assert!(second_sync["checkpoint"]["last_acked_seq"].as_u64().unwrap_or_default() >= 4);

    let second_messages = run_cli_json([
        "message",
        "list",
        "--profile",
        &bob_profile.to_string_lossy(),
        "--conversation-id",
        &conversation_id,
    ])?;
    let attachment_message = second_messages
        .as_array()
        .context("second message list not array")?
        .iter()
        .find(|message| {
            message["storage_refs"]
                .as_array()
                .map(|refs| !refs.is_empty())
                .unwrap_or(false)
        })
        .cloned()
        .context("attachment message missing from bob message list")?;
    let attachment_message_id = required_str(&attachment_message, "message_id")?;
    let attachment_reference = attachment_message["storage_refs"][0]["ref"]
        .as_str()
        .context("attachment storage ref missing")?
        .to_string();

    let downloaded_path = bob_profile
        .join("attachments")
        .join("inbox")
        .join("downloaded-attachment.txt");
    let downloaded = run_cli_json([
        "message",
        "download-attachment",
        "--profile",
        &bob_profile.to_string_lossy(),
        "--conversation-id",
        &conversation_id,
        "--message-id",
        &attachment_message_id,
        "--reference",
        &attachment_reference,
        "--out",
        &downloaded_path.to_string_lossy(),
    ])?;
    assert_eq!(downloaded["downloaded"], Value::Bool(true));
    assert_eq!(fs::read_to_string(&downloaded_path)?, "hello from cli attachment e2e");

    let snapshot: Value = read_json_file(&bob_profile.join("snapshot.json"))?;
    let conversations = snapshot["snapshot"]["conversations"]
        .as_array()
        .context("snapshot conversations missing")?;
    assert!(conversations
        .iter()
        .any(|row| row["conversation_id"].as_str() == Some(conversation_id.as_str())));
    let sync_states = snapshot["snapshot"]["sync_states"]
        .as_array()
        .context("snapshot sync states missing")?;
    assert!(sync_states.iter().any(|row| {
        row["device_id"].as_str() == Some(bob_device_id.as_str())
            && row["state"]["checkpoint"]["last_acked_seq"].as_u64().unwrap_or_default() >= 4
    }));

    Ok(())
}

#[cfg(windows)]
#[test]
fn cleanup_test_temp_script_removes_cli_temp_artifacts() -> Result<()> {
    let _guard = test_lock();
    let workspace_root = workspace_root();
    let root_temp_dir = workspace_root.join(".cli-smoke-cleanup-generated");
    let root_temp_file_ps1 = workspace_root.join(".cli-smoke-cleanup-generated.ps1");
    let root_temp_file_txt = workspace_root.join(".cli-smoke-cleanup-generated.txt");
    let service_temp_dir = workspace_root
        .join("services")
        .join("cloudflare")
        .join(".cli-smoke-cleanup-generated");
    let wrangler_tmp_dir = workspace_root
        .join("services")
        .join("cloudflare")
        .join(".wrangler")
        .join("tmp");
    let wrangler_tmp_file = wrangler_tmp_dir.join("cleanup-generated.txt");

    fs::create_dir_all(&root_temp_dir)?;
    fs::create_dir_all(&service_temp_dir)?;
    fs::create_dir_all(&wrangler_tmp_dir)?;
    fs::write(root_temp_dir.join("marker.txt"), "cleanup")?;
    fs::write(&root_temp_file_ps1, "# cleanup")?;
    fs::write(&root_temp_file_txt, "cleanup")?;
    fs::write(service_temp_dir.join("marker.txt"), "cleanup")?;
    fs::write(&wrangler_tmp_file, "cleanup")?;

    let dry_run = run_cleanup_script(&workspace_root, true)?;
    assert!(dry_run.contains(".cli-smoke-cleanup-generated"));
    assert!(root_temp_dir.exists());
    assert!(root_temp_file_ps1.exists());
    assert!(root_temp_file_txt.exists());
    assert!(service_temp_dir.exists());
    assert!(wrangler_tmp_file.exists());

    let actual = run_cleanup_script(&workspace_root, false)?;
    assert!(actual.contains("Cleanup complete."));
    assert!(!root_temp_dir.exists());
    assert!(!root_temp_file_ps1.exists());
    assert!(!root_temp_file_txt.exists());
    assert!(!service_temp_dir.exists());
    assert!(wrangler_tmp_dir.exists());
    assert!(!wrangler_tmp_file.exists());

    Ok(())
}

struct RuntimePidGuard {
    pid: Option<u32>,
}

impl RuntimePidGuard {
    fn new(pid: u32) -> Self {
        Self { pid: Some(pid) }
    }

    fn clear(&mut self) {
        self.pid = None;
    }
}

impl Drop for RuntimePidGuard {
    fn drop(&mut self) {
        let Some(pid) = self.pid.take() else {
            return;
        };
        #[cfg(windows)]
        let _ = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .output();
        #[cfg(not(windows))]
        let _ = Command::new("kill").args(["-TERM", &pid.to_string()]).output();
    }
}

fn runtime_handle(workspace_root: &Path) -> Result<CloudflareRuntimeHandle> {
    with_tokio(|| async { CloudflareRuntimeHandle::start(workspace_root).await })
        .context("start cloudflare runtime")
}

fn run_cleanup_script(workspace_root: &Path, what_if: bool) -> Result<String> {
    let script_path = workspace_root.join("scripts").join("cleanup-test-temp.ps1");
    let mut command = Command::new("pwsh");
    command
        .arg("-NoProfile")
        .arg("-File")
        .arg(script_path)
        .arg("-RepoRoot")
        .arg(workspace_root);
    if what_if {
        command.arg("-WhatIf");
    } else {
        command.arg("-Confirm:$false");
    }
    let output = command.output().context("run cleanup-test-temp.ps1")?;
    if !output.status.success() {
        bail!(
            "cleanup-test-temp.ps1 failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

fn run_cli_json<I, S>(args: I) -> Result<Value>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut command = Command::new(binary_path());
    command
        .current_dir(workspace_root())
        .arg("--output")
        .arg("json");
    for arg in args {
        command.arg(arg.as_ref());
    }
    let output = command.output().context("run tapchat cli")?;
    if !output.status.success() {
        bail!(
            "tapchat command failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8(output.stdout).context("decode cli stdout as utf-8")?;
    serde_json::from_str(&stdout).map_err(|error| {
        anyhow!(
            "failed to parse cli json output: {error}\nstdout:\n{}\nstderr:\n{}",
            stdout,
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tapchat"))
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn repo_temp_dir(suffix: &str) -> Result<TempDir> {
    Builder::new()
        .prefix(&format!(".tmp-cli-e2e-{suffix}-"))
        .tempdir_in(workspace_root())
        .context("create repo temp dir")
}

fn write_mnemonic_file(root: &Path, name: &str, mnemonic: &str) -> Result<PathBuf> {
    let path = root.join(name);
    fs::write(&path, mnemonic)?;
    Ok(path)
}

fn write_json_file<T: serde::Serialize>(root: &Path, name: &str, value: &T) -> Result<PathBuf> {
    let path = root.join(name);
    fs::write(&path, serde_json::to_vec_pretty(value)?)?;
    Ok(path)
}

fn read_json_file<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(serde_json::from_slice(&bytes).with_context(|| format!("decode {}", path.display()))?)
}

fn required_str(value: &Value, field: &str) -> Result<String> {
    value[field]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("missing string field {field}"))
}

fn bundle_auth(bundle: &DeploymentBundle) -> Result<&DeviceRuntimeAuth> {
    bundle
        .device_runtime_auth
        .as_ref()
        .context("deployment bundle missing device runtime auth")
}

fn test_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .expect("lock cli e2e tests")
}

fn runtime_bootstrap_device_bundle(
    runtime: &CloudflareRuntimeHandle,
    user_id: &str,
    device_id: &str,
) -> Result<DeploymentBundle> {
    with_tokio(|| async { runtime.bootstrap_device_bundle(user_id, device_id).await })
}

fn runtime_put_identity_bundle(
    runtime: &CloudflareRuntimeHandle,
    auth: &DeviceRuntimeAuth,
    bundle: &IdentityBundle,
) -> Result<()> {
    with_tokio(|| async { runtime.put_identity_bundle(auth, bundle).await })
}

fn with_tokio<F, Fut, T>(build: F) -> Result<T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime for cli e2e helper")?
        .block_on(build())
}

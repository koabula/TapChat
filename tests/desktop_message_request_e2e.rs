use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tapchat_core::desktop_app;
use tapchat_core::model::{DeploymentBundle, DeviceRuntimeAuth, IdentityBundle, MessageType};
use tapchat_transport_adapter::CloudflareRuntimeHandle;
use tempfile::{Builder, TempDir};

const ALICE_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const BOB_MNEMONIC: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

#[test]
fn desktop_message_request_accept_syncs_promoted_messages_and_preserves_plaintext() -> Result<()> {
    let workspace_root = workspace_root();
    let runtime = with_tokio(|| async {
        CloudflareRuntimeHandle::start(&workspace_root).await
    })?;
    let temp_root = repo_temp_dir("desktop-message-request")?;
    let registry_path = temp_root.path().join("desktop-message-request.profiles.json");
    let alice_profile = temp_root.path().join("alice");
    let bob_profile = temp_root.path().join("bob");

    let alice_mnemonic =
        write_mnemonic_file(temp_root.path(), "alice-mnemonic.txt", ALICE_MNEMONIC)?;
    let bob_mnemonic =
        write_mnemonic_file(temp_root.path(), "bob-mnemonic.txt", BOB_MNEMONIC)?;

    run_cli_json(
        &registry_path,
        [
            "profile",
            "init",
            "--name",
            "alice",
            "--root",
            &alice_profile.to_string_lossy(),
        ],
    )?;
    run_cli_json(
        &registry_path,
        [
            "profile",
            "init",
            "--name",
            "bob",
            "--root",
            &bob_profile.to_string_lossy(),
        ],
    )?;

    let alice_identity = run_cli_json(
        &registry_path,
        [
            "device",
            "recover",
            "--profile",
            &alice_profile.to_string_lossy(),
            "--device-name",
            "phone",
            "--mnemonic-file",
            &alice_mnemonic.to_string_lossy(),
        ],
    )?;
    let bob_identity = run_cli_json(
        &registry_path,
        [
            "device",
            "recover",
            "--profile",
            &bob_profile.to_string_lossy(),
            "--device-name",
            "phone",
            "--mnemonic-file",
            &bob_mnemonic.to_string_lossy(),
        ],
    )?;

    let alice_user_id = required_str(&alice_identity, "user_id")?;
    let alice_device_id = required_str(&alice_identity, "device_id")?;
    let bob_user_id = required_str(&bob_identity, "user_id")?;
    let bob_device_id = required_str(&bob_identity, "device_id")?;

    let alice_bundle = with_tokio(|| async {
        runtime.bootstrap_device_bundle(&alice_user_id, &alice_device_id).await
    })?;
    let bob_bundle = with_tokio(|| async {
        runtime.bootstrap_device_bundle(&bob_user_id, &bob_device_id).await
    })?;
    let alice_bundle_path =
        write_json_file(temp_root.path(), "alice-deployment.json", &alice_bundle)?;
    let bob_bundle_path = write_json_file(temp_root.path(), "bob-deployment.json", &bob_bundle)?;

    run_cli_json(
        &registry_path,
        [
            "profile",
            "import-deployment",
            "--profile",
            &alice_profile.to_string_lossy(),
            &alice_bundle_path.to_string_lossy(),
        ],
    )?;
    run_cli_json(
        &registry_path,
        [
            "profile",
            "import-deployment",
            "--profile",
            &bob_profile.to_string_lossy(),
            &bob_bundle_path.to_string_lossy(),
        ],
    )?;

    let alice_identity_path =
        export_identity_bundle_to_path(&registry_path, temp_root.path(), &alice_profile, "alice-identity.json")?;
    let bob_identity_path =
        export_identity_bundle_to_path(&registry_path, temp_root.path(), &bob_profile, "bob-identity.json")?;
    let alice_identity_bundle: IdentityBundle = read_json_file(&alice_identity_path)?;
    let bob_identity_bundle: IdentityBundle = read_json_file(&bob_identity_path)?;

    with_tokio(|| async {
        runtime
            .put_identity_bundle(bundle_auth(&alice_bundle)?, &alice_identity_bundle)
            .await
    })?;
    with_tokio(|| async {
        runtime
            .put_identity_bundle(bundle_auth(&bob_bundle)?, &bob_identity_bundle)
            .await
    })?;

    run_cli_json(
        &registry_path,
        [
            "contact",
            "import-identity",
            "--profile",
            &alice_profile.to_string_lossy(),
            &bob_identity_path.to_string_lossy(),
        ],
    )?;

    let created = run_cli_json(
        &registry_path,
        [
            "conversation",
            "create-direct",
            "--profile",
            &alice_profile.to_string_lossy(),
            "--peer-user-id",
            &bob_user_id,
        ],
    )?;
    let alice_conversation_id = required_str(&created, "conversation_id")?;

    let first_send = run_cli_json(
        &registry_path,
        [
            "message",
            "send-text",
            "--profile",
            &alice_profile.to_string_lossy(),
            "--conversation-id",
            &alice_conversation_id,
            "--text",
            "hello before accept",
        ],
    )?;
    assert!(
        first_send["latest_notification"]
            .as_str()
            .unwrap_or_default()
            .contains("queued as a message request")
    );

    assert!(
        desktop_app::conversation_list(&bob_profile)?.is_empty(),
        "desktop accept should materialize the first conversation; it must not already exist"
    );

    let requests = with_tokio(|| async { desktop_app::message_requests_list(&bob_profile).await })?;
    assert_eq!(requests.len(), 1);
    let request_id = requests[0].request_id.clone();

    let accept = with_tokio(|| async {
        desktop_app::message_request_accept(&bob_profile, &request_id).await
    })?;
    assert!(accept.accepted);
    assert!(accept.contact_available);
    assert!(accept.conversation_available);
    assert!(accept.auto_created_conversation);
    let bob_conversation_id = accept
        .conversation_id
        .clone()
        .context("desktop accept should return the promoted conversation id")?;
    assert_eq!(bob_conversation_id, alice_conversation_id);

    let bob_conversations = desktop_app::conversation_list(&bob_profile)?;
    assert_eq!(bob_conversations.len(), 1);
    assert_eq!(bob_conversations[0].conversation_id, bob_conversation_id);

    let bob_messages = desktop_app::message_list(&bob_profile, &bob_conversation_id)?;
    assert_has_plaintext_application(&bob_messages, "hello before accept")?;

    with_tokio(|| async {
        desktop_app::message_send_text(&bob_profile, &bob_conversation_id, "reply from bob").await
    })?;
    with_tokio(|| async { desktop_app::sync_once(&alice_profile).await })?;

    let alice_messages = desktop_app::message_list(&alice_profile, &alice_conversation_id)?;
    assert_has_plaintext_application(&alice_messages, "reply from bob")?;

    with_tokio(|| async {
        desktop_app::message_send_text(&alice_profile, &alice_conversation_id, "second from alice")
            .await
    })?;
    with_tokio(|| async { desktop_app::sync_once(&bob_profile).await })?;

    let bob_messages_after = desktop_app::message_list(&bob_profile, &bob_conversation_id)?;
    assert_has_plaintext_application(&bob_messages_after, "second from alice")?;

    Ok(())
}

fn assert_has_plaintext_application(
    messages: &[desktop_app::MessageItemView],
    plaintext: &str,
) -> Result<()> {
    if messages.iter().any(|message| {
        message.message_type == MessageType::MlsApplication
            && message.plaintext.as_deref() == Some(plaintext)
    }) {
        return Ok(());
    }

    Err(anyhow!(
        "expected an mls_application with plaintext {plaintext:?}, got {:?}",
        messages
            .iter()
            .map(|message| (&message.message_type, &message.plaintext))
            .collect::<Vec<_>>()
    ))
}

fn bundle_auth(bundle: &DeploymentBundle) -> Result<&DeviceRuntimeAuth> {
    bundle
        .device_runtime_auth
        .as_ref()
        .ok_or_else(|| anyhow!("deployment bundle missing device runtime auth"))
}

fn export_identity_bundle_to_path(
    registry_path: &Path,
    root: &Path,
    profile: &Path,
    name: &str,
) -> Result<PathBuf> {
    let output = root.join(name);
    let exported = run_cli_json(
        registry_path,
        [
            "profile",
            "export-identity",
            "--profile",
            &profile.to_string_lossy(),
            "--out",
            &output.to_string_lossy(),
        ],
    )?;
    assert_eq!(required_str(&exported, "written")?, output.to_string_lossy());
    Ok(output)
}

fn run_cli_json<I, S>(registry_path: &Path, args: I) -> Result<Value>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut command = Command::new(binary_path());
    command
        .current_dir(workspace_root())
        .arg("--output")
        .arg("json")
        .env("TAPCHAT_PROFILE_REGISTRY_PATH", registry_path);
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

fn required_str(value: &Value, field: &str) -> Result<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("missing string field {field}"))
}

fn write_mnemonic_file(root: &Path, name: &str, mnemonic: &str) -> Result<PathBuf> {
    let path = root.join(name);
    fs::write(&path, mnemonic).with_context(|| format!("write mnemonic {}", path.display()))?;
    Ok(path)
}

fn write_json_file<T: Serialize>(root: &Path, name: &str, value: &T) -> Result<PathBuf> {
    let path = root.join(name);
    fs::write(&path, serde_json::to_vec_pretty(value)?)
        .with_context(|| format!("write json {}", path.display()))?;
    Ok(path)
}

fn read_json_file<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("decode {}", path.display()))
}

fn repo_temp_dir(suffix: &str) -> Result<TempDir> {
    Builder::new()
        .prefix(&format!(".tmp-desktop-e2e-{suffix}-"))
        .tempdir_in(workspace_root())
        .context("create desktop e2e temp dir")
}

fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tapchat"))
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn with_tokio<F, Fut, T>(build: F) -> Result<T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime for desktop e2e helper")?
        .block_on(build())
}

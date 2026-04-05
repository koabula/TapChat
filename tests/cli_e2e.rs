use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;
use tapchat_core::identity::{IdentityManager, LocalIdentityState};
use tapchat_core::model::{DeploymentBundle, DeviceRuntimeAuth, IdentityBundle};
use tapchat_transport_adapter::{
    CloudflareRuntimeHandle, CloudflareRuntimeOptions, RuntimeMessageRequest,
};
use tempfile::{Builder, TempDir};

const ALICE_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const BOB_MNEMONIC: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

#[allow(dead_code)]
struct CliPairContext {
    runtime: CloudflareRuntimeHandle,
    temp_root: TempDir,
    alice_profile: PathBuf,
    bob_profile: PathBuf,
    alice_bundle: DeploymentBundle,
    bob_bundle: DeploymentBundle,
    alice_user_id: String,
    bob_user_id: String,
    alice_device_id: String,
    bob_device_id: String,
    conversation_id: String,
}

#[allow(dead_code)]
struct CliLaptopContext {
    laptop_profile: PathBuf,
    laptop_device_id: String,
    merged_identity_path: PathBuf,
}

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
    let pid = started["pid"]
        .as_u64()
        .context("runtime start missing pid")? as u32;
    let mut pid_guard = RuntimePidGuard::new(pid);
    assert_eq!(started["started"], Value::Bool(true));
    assert!(
        started["base_url"]
            .as_str()
            .unwrap_or_default()
            .starts_with("http://127.0.0.1:")
    );
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
    assert!(
        status["base_url"]
            .as_str()
            .unwrap_or_default()
            .starts_with("http://127.0.0.1:")
    );
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
fn cli_message_request_accept_flow_works() -> Result<()> {
    let _guard = test_lock();
    let workspace_root = workspace_root();
    let runtime = runtime_handle(&workspace_root)?;
    let temp_root = repo_temp_dir("message-requests")?;
    let alice_profile = temp_root.path().join("alice");
    let bob_profile = temp_root.path().join("bob");
    let alice_mnemonic =
        write_mnemonic_file(temp_root.path(), "alice-mnemonic.txt", ALICE_MNEMONIC)?;
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
    let alice_bundle_path =
        write_json_file(temp_root.path(), "alice-deployment.json", &alice_bundle)?;
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

    let alice_identity_path =
        export_identity_bundle_to_path(temp_root.path(), &alice_profile, "alice-identity.json")?;
    let bob_identity_path =
        export_identity_bundle_to_path(temp_root.path(), &bob_profile, "bob-identity.json")?;
    let alice_identity_bundle: IdentityBundle = read_json_file(&alice_identity_path)?;
    let bob_identity_bundle: IdentityBundle = read_json_file(&bob_identity_path)?;
    runtime_put_identity_bundle(
        &runtime,
        bundle_auth(&alice_bundle)?,
        &alice_identity_bundle,
    )?;
    runtime_put_identity_bundle(&runtime, bundle_auth(&bob_bundle)?, &bob_identity_bundle)?;

    run_cli_json([
        "contact",
        "import-identity",
        "--profile",
        &alice_profile.to_string_lossy(),
        &bob_identity_path.to_string_lossy(),
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
        "pending request message",
    ])?;

    let requests = runtime_list_message_requests(&runtime, bundle_auth(&bob_bundle)?)?;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].sender_user_id, alice_user_id);
    assert!(requests[0].message_count >= 1);

    let pre_accept_sync = sync_once(&bob_profile)?;
    assert_eq!(
        required_u64(&pre_accept_sync["checkpoint"], "last_acked_seq")?,
        0
    );

    runtime_accept_message_request(&runtime, bundle_auth(&bob_bundle)?, &requests[0].request_id)?;

    let post_accept_sync = sync_once(&bob_profile)?;
    assert_eq!(post_accept_sync["synced"], Value::Bool(true));
    assert!(required_u64(&post_accept_sync["checkpoint"], "last_acked_seq")? >= 1);
    let repeat_sync = sync_once(&bob_profile)?;
    assert_eq!(repeat_sync["synced"], Value::Bool(true));
    assert!(
        required_u64(&repeat_sync["checkpoint"], "last_acked_seq")?
            >= required_u64(&post_accept_sync["checkpoint"], "last_acked_seq")?
    );

    let messages = run_cli_json([
        "message",
        "list",
        "--profile",
        &bob_profile.to_string_lossy(),
        "--conversation-id",
        &conversation_id,
    ])?;
    assert_eq!(
        count_plaintext_messages(&messages, "pending request message"),
        1
    );
    let repeat_messages = run_cli_json([
        "message",
        "list",
        "--profile",
        &bob_profile.to_string_lossy(),
        "--conversation-id",
        &conversation_id,
    ])?;
    assert_eq!(
        count_plaintext_messages(&repeat_messages, "pending request message"),
        1
    );

    Ok(())
}
#[test]
fn cli_contact_request_and_allowlist_commands_work() -> Result<()> {
    let _guard = test_lock();
    let workspace_root = workspace_root();
    let runtime = runtime_handle(&workspace_root)?;
    let temp_root = repo_temp_dir("contact-policy")?;
    let alice_profile = temp_root.path().join("alice");
    let bob_profile = temp_root.path().join("bob");
    let alice_mnemonic =
        write_mnemonic_file(temp_root.path(), "alice-mnemonic.txt", ALICE_MNEMONIC)?;
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
    let alice_bundle_path =
        write_json_file(temp_root.path(), "alice-deployment.json", &alice_bundle)?;
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

    let alice_identity_path =
        export_identity_bundle_to_path(temp_root.path(), &alice_profile, "alice-identity.json")?;
    let bob_identity_path =
        export_identity_bundle_to_path(temp_root.path(), &bob_profile, "bob-identity.json")?;
    let alice_identity_bundle: IdentityBundle = read_json_file(&alice_identity_path)?;
    let bob_identity_bundle: IdentityBundle = read_json_file(&bob_identity_path)?;
    runtime_put_identity_bundle(
        &runtime,
        bundle_auth(&alice_bundle)?,
        &alice_identity_bundle,
    )?;
    runtime_put_identity_bundle(&runtime, bundle_auth(&bob_bundle)?, &bob_identity_bundle)?;

    run_cli_json([
        "contact",
        "import-identity",
        "--profile",
        &alice_profile.to_string_lossy(),
        &bob_identity_path.to_string_lossy(),
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

    let first_send = run_cli_json([
        "message",
        "send-text",
        "--profile",
        &alice_profile.to_string_lossy(),
        "--conversation-id",
        &conversation_id,
        "--text",
        "policy request 1",
    ])?;
    assert_eq!(first_send["sent"], Value::Bool(true));
    assert_eq!(first_send["pending_outbox"], Value::from(0));
    assert!(
        first_send["latest_notification"]
            .as_str()
            .unwrap_or_default()
            .contains("queued as a message request")
    );

    let requests = run_cli_json([
        "contact",
        "requests",
        "list",
        "--profile",
        &bob_profile.to_string_lossy(),
    ])?;
    let requests = requests.as_array().context("requests list not array")?;
    assert_eq!(requests.len(), 1);
    let request_id = required_str(&requests[0], "request_id")?;
    assert_eq!(
        requests[0]["sender_user_id"].as_str(),
        Some(alice_user_id.as_str())
    );

    let rejected = run_cli_json([
        "contact",
        "requests",
        "reject",
        "--profile",
        &bob_profile.to_string_lossy(),
        "--request-id",
        &request_id,
    ])?;
    assert_eq!(rejected["rejected"], Value::Bool(true));

    let second_send = run_cli_json([
        "message",
        "send-text",
        "--profile",
        &alice_profile.to_string_lossy(),
        "--conversation-id",
        &conversation_id,
        "--text",
        "policy request 2",
    ])?;
    assert_eq!(second_send["sent"], Value::Bool(true));
    assert_eq!(second_send["pending_outbox"], Value::from(0));
    assert!(
        second_send["latest_notification"]
            .as_str()
            .unwrap_or_default()
            .contains("rejected by inbox policy")
    );
    let blocked_sync = sync_once(&bob_profile)?;
    assert_eq!(
        required_u64(&blocked_sync["checkpoint"], "last_acked_seq")?,
        0
    );

    let updated = run_cli_json([
        "contact",
        "allowlist",
        "add",
        "--profile",
        &bob_profile.to_string_lossy(),
        "--user-id",
        &alice_user_id,
    ])?;
    assert_eq!(updated["updated"], Value::Bool(true));
    let allowlist = run_cli_json([
        "contact",
        "allowlist",
        "list",
        "--profile",
        &bob_profile.to_string_lossy(),
    ])?;
    assert!(
        allowlist["allowed_sender_user_ids"]
            .as_array()
            .context("allowlist missing allowed_sender_user_ids")?
            .iter()
            .any(|value| value.as_str() == Some(alice_user_id.as_str()))
    );

    run_cli_json([
        "contact",
        "import-identity",
        "--profile",
        &bob_profile.to_string_lossy(),
        &alice_identity_path.to_string_lossy(),
    ])?;
    let allowlist_requests = run_cli_json([
        "contact",
        "requests",
        "list",
        "--profile",
        &bob_profile.to_string_lossy(),
    ])?;
    assert!(
        allowlist_requests
            .as_array()
            .context("allowlist requests not array")?
            .is_empty()
    );

    let removed = run_cli_json([
        "contact",
        "allowlist",
        "remove",
        "--profile",
        &bob_profile.to_string_lossy(),
        "--user-id",
        &alice_user_id,
    ])?;
    assert_eq!(removed["updated"], Value::Bool(true));
    let allowlist_after_remove = run_cli_json([
        "contact",
        "allowlist",
        "list",
        "--profile",
        &bob_profile.to_string_lossy(),
    ])?;
    assert!(
        !allowlist_after_remove["allowed_sender_user_ids"]
            .as_array()
            .context("allowlist after remove missing allowed_sender_user_ids")?
            .iter()
            .any(|value| value.as_str() == Some(alice_user_id.as_str()))
    );

    Ok(())
}

#[test]
fn cli_sender_policy_and_recovery_status_remain_consistent_e2e_work() -> Result<()> {
    let _guard = test_lock();
    let workspace_root = workspace_root();
    let runtime = runtime_handle(&workspace_root)?;
    let temp_root = repo_temp_dir("sender-policy-recovery")?;
    let alice_profile = temp_root.path().join("alice");
    let bob_profile = temp_root.path().join("bob");
    let alice_mnemonic =
        write_mnemonic_file(temp_root.path(), "alice-mnemonic.txt", ALICE_MNEMONIC)?;
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
    let alice_bundle_path =
        write_json_file(temp_root.path(), "alice-deployment.json", &alice_bundle)?;
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

    let alice_identity_path =
        export_identity_bundle_to_path(temp_root.path(), &alice_profile, "alice-identity.json")?;
    let bob_identity_path =
        export_identity_bundle_to_path(temp_root.path(), &bob_profile, "bob-identity.json")?;
    let alice_identity_bundle: IdentityBundle = read_json_file(&alice_identity_path)?;
    let bob_identity_bundle: IdentityBundle = read_json_file(&bob_identity_path)?;
    runtime_put_identity_bundle(
        &runtime,
        bundle_auth(&alice_bundle)?,
        &alice_identity_bundle,
    )?;
    runtime_put_identity_bundle(&runtime, bundle_auth(&bob_bundle)?, &bob_identity_bundle)?;

    run_cli_json([
        "contact",
        "import-identity",
        "--profile",
        &alice_profile.to_string_lossy(),
        &bob_identity_path.to_string_lossy(),
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

    let first_send = run_cli_json([
        "message",
        "send-text",
        "--profile",
        &alice_profile.to_string_lossy(),
        "--conversation-id",
        &conversation_id,
        "--text",
        "policy recovery request",
    ])?;
    assert_eq!(first_send["sent"], Value::Bool(true));
    assert_eq!(first_send["pending_outbox"], Value::from(0));
    assert!(
        first_send["latest_notification"]
            .as_str()
            .unwrap_or_default()
            .contains("queued as a message request")
    );

    let blocked_sync = sync_once(&bob_profile)?;
    assert_eq!(
        required_u64(&blocked_sync["checkpoint"], "last_acked_seq")?,
        0
    );
    assert!(blocked_sync["notifications"].is_array());
    assert!(blocked_sync.get("realtime").is_some());
    assert!(recovery_conversations(&blocked_sync)?.is_empty());

    let requests = run_cli_json([
        "contact",
        "requests",
        "list",
        "--profile",
        &bob_profile.to_string_lossy(),
    ])?;
    let request_id = required_str(
        requests
            .as_array()
            .context("requests list not array")?
            .first()
            .context("missing request")?,
        "request_id",
    )?;
    run_cli_json([
        "contact",
        "requests",
        "reject",
        "--profile",
        &bob_profile.to_string_lossy(),
        "--request-id",
        &request_id,
    ])?;

    let second_send = run_cli_json([
        "message",
        "send-text",
        "--profile",
        &alice_profile.to_string_lossy(),
        "--conversation-id",
        &conversation_id,
        "--text",
        "policy recovery rejected",
    ])?;
    assert_eq!(second_send["sent"], Value::Bool(true));
    assert_eq!(second_send["pending_outbox"], Value::from(0));
    assert!(
        second_send["latest_notification"]
            .as_str()
            .unwrap_or_default()
            .contains("rejected by inbox policy")
    );

    run_cli_json([
        "contact",
        "allowlist",
        "add",
        "--profile",
        &bob_profile.to_string_lossy(),
        "--user-id",
        &alice_user_id,
    ])?;
    run_cli_json([
        "contact",
        "import-identity",
        "--profile",
        &bob_profile.to_string_lossy(),
        &alice_identity_path.to_string_lossy(),
    ])?;
    let requests_after_allow = run_cli_json([
        "contact",
        "requests",
        "list",
        "--profile",
        &bob_profile.to_string_lossy(),
    ])?;
    assert!(
        requests_after_allow
            .as_array()
            .context("requests after allowlist not array")?
            .is_empty()
    );

    let third_send = run_cli_json([
        "message",
        "send-text",
        "--profile",
        &alice_profile.to_string_lossy(),
        "--conversation-id",
        &conversation_id,
        "--text",
        "policy recovery delivered",
    ])?;
    assert_eq!(third_send["sent"], Value::Bool(true));
    assert_eq!(third_send["pending_outbox"], Value::from(0));
    assert!(third_send["latest_notification"].is_null());

    let delivered_sync = sync_once(&bob_profile)?;
    assert!(
        required_u64(&delivered_sync["checkpoint"], "last_acked_seq")? > 0
    );
    assert!(delivered_sync["notifications"].is_array());
    assert!(delivered_sync.get("realtime").is_some());
    assert!(delivered_sync["recovery_conversations"].is_array());

    let bob_messages = run_cli_json([
        "message",
        "list",
        "--profile",
        &bob_profile.to_string_lossy(),
        "--conversation-id",
        &conversation_id,
    ])?;
    assert_eq!(
        count_plaintext_messages(&bob_messages, "policy recovery request"),
        0
    );
    assert_eq!(
        count_plaintext_messages(&bob_messages, "policy recovery rejected"),
        0
    );
    assert!(
        count_plaintext_messages(&bob_messages, "policy recovery delivered") <= 1
    );

    let ctx = CliPairContext {
        runtime,
        temp_root,
        alice_profile,
        bob_profile,
        alice_bundle,
        bob_bundle,
        alice_user_id,
        bob_user_id,
        alice_device_id,
        bob_device_id,
        conversation_id,
    };
    let laptop = start_bob_laptop_recovery(&ctx)?;

    let recovering = conversation_show(&ctx.alice_profile, &ctx.conversation_id)?;
    assert_conversation_show_recovery(
        &recovering,
        &["NeedsRecovery", "NeedsRebuild"],
        &["membership_changed"],
        &["waiting_for_explicit_reconcile", "escalated_to_rebuild"],
        None,
    )?;
    let recovering_status = run_cli_json([
        "sync",
        "status",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
    ])?;
    assert!(recovering_status["checkpoint"].is_object());
    assert!(recovering_status.get("realtime").is_some());
    assert!(recovering_status["notifications"].is_array());
    assert_eq!(recovering_status["pending_outbox"].as_u64(), Some(0));
    assert_eq!(recovering_status["pending_blob_uploads"].as_u64(), Some(0));
    let mut last_phase = assert_recovery_conversation_matches(
        &recovering_status,
        &ctx.conversation_id,
        &["NeedsRecovery", "NeedsRebuild"],
        &["membership_changed"],
        &["waiting_for_explicit_reconcile", "escalated_to_rebuild"],
        None,
    )?;

    for _ in 0..4 {
        run_cli_json([
            "conversation",
            "reconcile",
            "--profile",
            &ctx.alice_profile.to_string_lossy(),
            "--conversation-id",
            &ctx.conversation_id,
        ])?;
        let _ = sync_once(&laptop.laptop_profile)?;
        let phase_snapshot = run_cli_json([
            "sync",
            "status",
            "--profile",
            &ctx.alice_profile.to_string_lossy(),
        ])?;
        if let Ok(current_phase) = assert_recovery_conversation_matches(
            &phase_snapshot,
            &ctx.conversation_id,
            &["NeedsRecovery", "NeedsRebuild"],
            &["membership_changed"],
            &[
                "waiting_for_explicit_reconcile",
                "waiting_for_sync",
                "waiting_for_pending_replay",
                "escalated_to_rebuild",
            ],
            None,
        ) {
            assert_recovery_phase_not_regressed(&last_phase, &current_phase);
            last_phase = current_phase;
        }
        if conversation_recovery_status(&ctx.alice_profile, &ctx.conversation_id)?.as_deref()
            == Some("Healthy")
        {
            break;
        }
    }

    let alice_final = conversation_show(&ctx.alice_profile, &ctx.conversation_id)?;
    assert_conversation_show_healthy(&alice_final);
    let alice_final_status = run_cli_json([
        "sync",
        "status",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
    ])?;
    assert!(recovery_conversations(&alice_final_status)?.is_empty());

    let bob_messages_after_recovery = run_cli_json([
        "message",
        "send-text",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
        "--text",
        "policy recovery post heal",
    ])?;
    assert_eq!(bob_messages_after_recovery["sent"], Value::Bool(true));
    assert!(bob_messages_after_recovery["latest_notification"].is_null());

    let post_heal_sync = sync_once(&ctx.bob_profile)?;
    assert!(required_u64(&post_heal_sync["checkpoint"], "last_acked_seq")? > 0);
    assert!(post_heal_sync["notifications"].is_array());
    assert!(post_heal_sync.get("realtime").is_some());
    let requests_after_recovery = run_cli_json([
        "contact",
        "requests",
        "list",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
    ])?;
    assert!(
        requests_after_recovery
            .as_array()
            .context("requests after recovery not array")?
            .is_empty()
    );

    let bob_messages_after_recovery = run_cli_json([
        "message",
        "list",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;
    assert_eq!(
        count_plaintext_messages(&bob_messages_after_recovery, "policy recovery delivered"),
        0
    );
    assert!(
        count_plaintext_messages(&bob_messages_after_recovery, "policy recovery post heal") <= 1
    );

    Ok(())
}

#[test]
fn cli_sender_policy_identity_refresh_and_reconcile_do_not_overclaim_delivery_e2e_work(
) -> Result<()> {
    let _guard = test_lock();
    let workspace_root = workspace_root();
    let runtime = runtime_handle(&workspace_root)?;
    let temp_root = repo_temp_dir("sender-policy-refresh-reconcile")?;
    let alice_profile = temp_root.path().join("alice");
    let bob_profile = temp_root.path().join("bob");
    let alice_mnemonic =
        write_mnemonic_file(temp_root.path(), "alice-mnemonic.txt", ALICE_MNEMONIC)?;
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
    let alice_bundle_path =
        write_json_file(temp_root.path(), "alice-deployment.json", &alice_bundle)?;
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

    let alice_identity_path =
        export_identity_bundle_to_path(temp_root.path(), &alice_profile, "alice-identity.json")?;
    let bob_identity_path =
        export_identity_bundle_to_path(temp_root.path(), &bob_profile, "bob-identity.json")?;
    let alice_identity_bundle: IdentityBundle = read_json_file(&alice_identity_path)?;
    let bob_identity_bundle: IdentityBundle = read_json_file(&bob_identity_path)?;
    runtime_put_identity_bundle(
        &runtime,
        bundle_auth(&alice_bundle)?,
        &alice_identity_bundle,
    )?;
    runtime_put_identity_bundle(&runtime, bundle_auth(&bob_bundle)?, &bob_identity_bundle)?;

    run_cli_json([
        "contact",
        "import-identity",
        "--profile",
        &alice_profile.to_string_lossy(),
        &bob_identity_path.to_string_lossy(),
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

    let first_send = run_cli_json([
        "message",
        "send-text",
        "--profile",
        &alice_profile.to_string_lossy(),
        "--conversation-id",
        &conversation_id,
        "--text",
        "policy refresh request",
    ])?;
    assert_eq!(first_send["sent"], Value::Bool(true));
    assert!(
        first_send["latest_notification"]
            .as_str()
            .unwrap_or_default()
            .contains("queued as a message request")
    );

    let blocked_sync = sync_once(&bob_profile)?;
    assert_eq!(
        required_u64(&blocked_sync["checkpoint"], "last_acked_seq")?,
        0
    );
    assert!(recovery_conversations(&blocked_sync)?.is_empty());

    let requests = run_cli_json([
        "contact",
        "requests",
        "list",
        "--profile",
        &bob_profile.to_string_lossy(),
    ])?;
    let request_id = required_str(
        requests
            .as_array()
            .context("requests list not array")?
            .first()
            .context("missing request")?,
        "request_id",
    )?;
    run_cli_json([
        "contact",
        "requests",
        "reject",
        "--profile",
        &bob_profile.to_string_lossy(),
        "--request-id",
        &request_id,
    ])?;

    let second_send = run_cli_json([
        "message",
        "send-text",
        "--profile",
        &alice_profile.to_string_lossy(),
        "--conversation-id",
        &conversation_id,
        "--text",
        "policy refresh rejected",
    ])?;
    assert_eq!(second_send["sent"], Value::Bool(true));
    assert!(
        second_send["latest_notification"]
            .as_str()
            .unwrap_or_default()
            .contains("rejected by inbox policy")
    );

    run_cli_json([
        "contact",
        "allowlist",
        "add",
        "--profile",
        &bob_profile.to_string_lossy(),
        "--user-id",
        &alice_user_id,
    ])?;
    run_cli_json([
        "contact",
        "import-identity",
        "--profile",
        &bob_profile.to_string_lossy(),
        &alice_identity_path.to_string_lossy(),
    ])?;

    let ctx = CliPairContext {
        runtime,
        temp_root,
        alice_profile,
        bob_profile,
        alice_bundle,
        bob_bundle,
        alice_user_id,
        bob_user_id,
        alice_device_id,
        bob_device_id,
        conversation_id,
    };
    let laptop = start_bob_laptop_recovery(&ctx)?;

    let recovering_show = conversation_show(&ctx.alice_profile, &ctx.conversation_id)?;
    let mut last_phase = assert_conversation_show_recovery(
        &recovering_show,
        &["NeedsRecovery", "NeedsRebuild"],
        &["membership_changed"],
        &["waiting_for_explicit_reconcile", "escalated_to_rebuild"],
        None,
    )?;
    let recovering_status = run_cli_json([
        "sync",
        "status",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
    ])?;
    let current_phase = assert_recovery_conversation_matches(
        &recovering_status,
        &ctx.conversation_id,
        &["NeedsRecovery", "NeedsRebuild"],
        &["membership_changed"],
        &["waiting_for_explicit_reconcile", "escalated_to_rebuild"],
        None,
    )?;
    assert_recovery_phase_not_regressed(&last_phase, &current_phase);
    last_phase = current_phase;

    let third_send = run_cli_output([
        "message",
        "send-text",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
        "--text",
        "policy refresh during recovery",
    ])?;
    assert!(!third_send.status.success());
    assert!(
        String::from_utf8_lossy(&third_send.stderr)
            .contains("conversation membership is still recovering"),
        "sender must fail closed while recovery is still in progress"
    );

    let laptop_messages_before_heal = if conversation_exists(
        &laptop.laptop_profile,
        &ctx.conversation_id,
    )? {
        run_cli_json([
            "message",
            "list",
            "--profile",
            &laptop.laptop_profile.to_string_lossy(),
            "--conversation-id",
            &ctx.conversation_id,
        ])?
    } else {
        Value::Array(Vec::new())
    };
    assert_eq!(
        count_plaintext_messages(&laptop_messages_before_heal, "policy refresh request"),
        0
    );
    assert_eq!(
        count_plaintext_messages(&laptop_messages_before_heal, "policy refresh rejected"),
        0
    );

    for _ in 0..4 {
        run_cli_json([
            "conversation",
            "reconcile",
            "--profile",
            &ctx.alice_profile.to_string_lossy(),
            "--conversation-id",
            &ctx.conversation_id,
        ])?;
        let _ = sync_once(&laptop.laptop_profile)?;
        let phase_snapshot = run_cli_json([
            "sync",
            "status",
            "--profile",
            &ctx.alice_profile.to_string_lossy(),
        ])?;
        if let Ok(next_phase) = assert_recovery_conversation_matches(
            &phase_snapshot,
            &ctx.conversation_id,
            &["NeedsRecovery", "NeedsRebuild"],
            &["membership_changed"],
            &[
                "waiting_for_explicit_reconcile",
                "waiting_for_sync",
                "waiting_for_pending_replay",
                "escalated_to_rebuild",
            ],
            None,
        ) {
            assert_recovery_phase_not_regressed(&last_phase, &next_phase);
            last_phase = next_phase;
        }
        if conversation_recovery_status(&ctx.alice_profile, &ctx.conversation_id)?.as_deref()
            == Some("Healthy")
        {
            break;
        }
    }

    let alice_healthy = conversation_show(&ctx.alice_profile, &ctx.conversation_id)?;
    assert_conversation_show_healthy(&alice_healthy);
    let healthy_status = run_cli_json([
        "sync",
        "status",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
    ])?;
    assert!(recovery_conversations(&healthy_status)?.is_empty());

    run_cli_json([
        "conversation",
        "reconcile",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;
    run_cli_json([
        "conversation",
        "reconcile",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;
    let _ = sync_once(&laptop.laptop_profile)?;
    let post_reconcile_status = run_cli_json([
        "sync",
        "status",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
    ])?;
    assert!(recovery_conversations(&post_reconcile_status)?.is_empty());

    let fourth_send = run_cli_json([
        "message",
        "send-text",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
        "--text",
        "policy refresh after heal",
    ])?;
    assert_eq!(fourth_send["sent"], Value::Bool(true));
    assert!(fourth_send["latest_notification"].is_null());

    let laptop_sync_after_heal = sync_once(&laptop.laptop_profile)?;
    assert_eq!(laptop_sync_after_heal["synced"], Value::Bool(true));
    assert!(
        required_u64(&laptop_sync_after_heal["checkpoint"], "last_acked_seq")? > 0
    );

    let laptop_messages = run_cli_json([
        "message",
        "list",
        "--profile",
        &laptop.laptop_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;
    assert_eq!(
        count_plaintext_messages(&laptop_messages, "policy refresh request"),
        0
    );
    assert_eq!(
        count_plaintext_messages(&laptop_messages, "policy refresh rejected"),
        0
    );
    assert!(
        count_plaintext_messages(&laptop_messages, "policy refresh during recovery") == 0
    );
    assert_eq!(
        count_plaintext_messages(&laptop_messages, "policy refresh after heal"),
        1
    );

    let laptop_after_reconcile = conversation_show(&laptop.laptop_profile, &ctx.conversation_id)?;
    assert_conversation_show_healthy(&laptop_after_reconcile);

    Ok(())
}

#[test]
fn cli_device_revoke_remote_target_updates_published_bundle() -> Result<()> {
    let _guard = test_lock();
    let ctx = setup_cli_pair("revoke-remote")?;
    let laptop = start_bob_laptop_recovery(&ctx)?;
    let merged_identity = runtime_get_identity_bundle(&ctx.runtime, &ctx.bob_user_id)?;
    assert!(
        merged_identity
            .devices
            .iter()
            .any(|device| device.device_id == laptop.laptop_device_id)
    );

    let mut snapshot: Value = read_json_file(&ctx.bob_profile.join("snapshot.json"))?;
    snapshot["snapshot"]["deployment"]["local_bundle"] = serde_json::to_value(&merged_identity)?;
    assert!(
        snapshot["snapshot"]["deployment"]["local_bundle"]["devices"]
            .as_array()
            .context("patched local bundle devices missing")?
            .iter()
            .any(|device| device["device_id"].as_str() == Some(laptop.laptop_device_id.as_str()))
    );
    fs::write(
        ctx.bob_profile.join("snapshot.json"),
        serde_json::to_vec_pretty(&snapshot)?,
    )?;

    let revoked = run_cli_json([
        "device",
        "revoke",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
        "--target-device-id",
        &laptop.laptop_device_id,
    ])?;
    assert_eq!(revoked["revoked"], Value::Bool(true));

    run_cli_json([
        "contact",
        "refresh",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--user-id",
        &ctx.bob_user_id,
    ])?;
    let alice_contact = run_cli_json([
        "contact",
        "show",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--user-id",
        &ctx.bob_user_id,
    ])?;
    assert!(
        alice_contact["devices"]
            .as_array()
            .context("alice contact devices missing after revoke")?
            .iter()
            .any(|device| {
                device["device_id"].as_str() == Some(laptop.laptop_device_id.as_str())
                    && device["status"].as_str() == Some("revoked")
            })
    );

    let exported_identity_path = export_identity_bundle_to_path(
        ctx.temp_root.path(),
        &ctx.bob_profile,
        "bob-post-revoke-identity.json",
    )?;
    let exported_identity: IdentityBundle = read_json_file(&exported_identity_path)?;
    assert!(exported_identity.devices.iter().any(|device| {
        device.device_id == laptop.laptop_device_id
            && matches!(
                device.status,
                tapchat_core::model::DeviceStatusKind::Revoked
            )
    }));

    Ok(())
}

#[test]
fn cli_runtime_local_start_accepts_explicit_workspace_root() -> Result<()> {
    let _guard = test_lock();
    let temp_root = repo_temp_dir("runtime-workspace")?;
    let profile_root = temp_root.path().join("runtime-profile");

    run_cli_json([
        "profile",
        "init",
        "--name",
        "runtime",
        "--root",
        &profile_root.to_string_lossy(),
    ])?;
    run_cli_json([
        "device",
        "create",
        "--profile",
        &profile_root.to_string_lossy(),
        "--device-name",
        "phone",
    ])?;

    let started = run_cli_json([
        "runtime",
        "local-start",
        "--profile",
        &profile_root.to_string_lossy(),
        "--workspace-root",
        &workspace_root().to_string_lossy(),
    ])?;
    let pid = started["pid"]
        .as_u64()
        .context("runtime start missing pid")? as u32;
    let mut pid_guard = RuntimePidGuard::new(pid);
    assert_eq!(
        started["workspace_root"].as_str(),
        Some(workspace_root().to_string_lossy().as_ref())
    );
    assert!(
        started["service_root"]
            .as_str()
            .unwrap_or_default()
            .ends_with("services\\cloudflare")
            || started["service_root"]
                .as_str()
                .unwrap_or_default()
                .ends_with("services/cloudflare")
    );

    let status = run_cli_json([
        "runtime",
        "local-status",
        "--profile",
        &profile_root.to_string_lossy(),
    ])?;
    assert_eq!(
        status["workspace_root"].as_str(),
        Some(workspace_root().to_string_lossy().as_ref())
    );

    let failure = run_cli_output([
        "runtime",
        "local-start",
        "--profile",
        &profile_root.to_string_lossy(),
        "--workspace-root",
        &temp_root.path().join("missing-root").to_string_lossy(),
    ])?;
    assert!(!failure.status.success());

    let stopped = run_cli_json([
        "runtime",
        "local-stop",
        "--profile",
        &profile_root.to_string_lossy(),
    ])?;
    assert_eq!(stopped["stopped"], Value::Bool(true));
    pid_guard.clear();

    Ok(())
}
#[test]
fn cli_runtime_local_start_discovers_workspace_from_binary_outside_repo_cwd() -> Result<()> {
    let _guard = test_lock();
    let temp_root = repo_temp_dir("runtime-cwd")?;
    let profile_root = temp_root.path().join("runtime-profile");

    run_cli_json([
        "profile",
        "init",
        "--name",
        "runtime",
        "--root",
        &profile_root.to_string_lossy(),
    ])?;
    run_cli_json([
        "device",
        "create",
        "--profile",
        &profile_root.to_string_lossy(),
        "--device-name",
        "phone",
    ])?;

    let started = run_cli_json_in_cwd(
        temp_root.path(),
        [
            "runtime",
            "local-start",
            "--profile",
            &profile_root.to_string_lossy(),
        ],
    )?;
    let pid = started["pid"]
        .as_u64()
        .context("runtime start missing pid")? as u32;
    let mut pid_guard = RuntimePidGuard::new(pid);
    assert_eq!(started["started"], Value::Bool(true));
    assert_eq!(
        started["workspace_root"].as_str(),
        Some(workspace_root().to_string_lossy().as_ref())
    );

    let stopped = run_cli_json([
        "runtime",
        "local-stop",
        "--profile",
        &profile_root.to_string_lossy(),
    ])?;
    assert_eq!(stopped["stopped"], Value::Bool(true));
    pid_guard.clear();
    Ok(())
}

#[test]
fn cli_device_revoke_missing_target_returns_stable_error() -> Result<()> {
    let _guard = test_lock();
    let ctx = setup_cli_pair("revoke-missing-target")?;

    let failure = run_cli_output([
        "device",
        "revoke",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
        "--target-device-id",
        "device:bob:missing",
    ])?;
    assert!(!failure.status.success());
    let stderr = String::from_utf8_lossy(&failure.stderr);
    assert!(stderr.contains("target device is not present in local identity bundle"));

    Ok(())
}

#[test]
fn cli_direct_message_and_attachment_e2e_work() -> Result<()> {
    let _guard = test_lock();
    let ctx = setup_cli_pair("direct")?;

    run_cli_json([
        "message",
        "send-text",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
        "--text",
        "hello from cli e2e",
    ])?;
    let first_sync = run_cli_json([
        "sync",
        "once",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
    ])?;
    assert_eq!(first_sync["synced"], Value::Bool(true));
    let first_acked = required_u64(&first_sync["checkpoint"], "last_acked_seq")?;
    assert!(first_acked >= 3);
    assert_realtime_not_connected(&first_sync["realtime"]);
    assert!(first_sync["notifications"].is_array());

    let bob_conversations = run_cli_json([
        "conversation",
        "list",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
    ])?;
    assert!(
        bob_conversations
            .as_array()
            .context("conversation list not array")?
            .iter()
            .any(|row| row["conversation_id"].as_str() == Some(ctx.conversation_id.as_str()))
    );

    let bob_show = run_cli_json([
        "conversation",
        "show",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;
    assert_eq!(bob_show["conversation_state"].as_str(), Some("active"));
    assert_eq!(bob_show["recovery_status"].as_str(), Some("Healthy"));
    assert!(bob_show["message_count"].as_u64().unwrap_or_default() >= 3);
    assert!(bob_show["checkpoint"].is_object());
    assert_realtime_not_connected(&bob_show["realtime"]);
    assert!(bob_show["recovery"].is_null());

    let first_messages = run_cli_json([
        "message",
        "list",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;
    assert_eq!(
        count_plaintext_messages(&first_messages, "hello from cli e2e"),
        1
    );

    let attachment_path = ctx.temp_root.path().join("attachment.txt");
    fs::write(&attachment_path, "hello from cli attachment e2e")?;
    let attachment_send = run_cli_json([
        "message",
        "send-attachment",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
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
        &ctx.alice_profile.to_string_lossy(),
    ])?;
    assert_eq!(alice_sync_status["pending_outbox"].as_u64(), Some(0));
    assert_eq!(alice_sync_status["pending_blob_uploads"].as_u64(), Some(0));
    assert!(alice_sync_status["checkpoint"].is_object());
    assert!(alice_sync_status["notifications"].is_array());
    assert_realtime_not_connected(&alice_sync_status["realtime"]);

    let second_sync = run_cli_json([
        "sync",
        "once",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
    ])?;
    assert_eq!(second_sync["synced"], Value::Bool(true));
    let second_acked = required_u64(&second_sync["checkpoint"], "last_acked_seq")?;
    assert!(second_acked >= 4);
    assert!(second_acked >= first_acked);
    assert_realtime_not_connected(&second_sync["realtime"]);

    let second_messages = run_cli_json([
        "message",
        "list",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
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

    let downloaded_path = ctx
        .bob_profile
        .join("attachments")
        .join("inbox")
        .join("downloaded-attachment.txt");
    let downloaded = run_cli_json([
        "message",
        "download-attachment",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
        "--message-id",
        &attachment_message_id,
        "--reference",
        &attachment_reference,
        "--out",
        &downloaded_path.to_string_lossy(),
    ])?;
    assert_eq!(downloaded["downloaded"], Value::Bool(true));
    assert_eq!(
        fs::read_to_string(&downloaded_path)?,
        "hello from cli attachment e2e"
    );

    for text in ["offline batch 1", "offline batch 2", "offline batch 3"] {
        run_cli_json([
            "message",
            "send-text",
            "--profile",
            &ctx.alice_profile.to_string_lossy(),
            "--conversation-id",
            &ctx.conversation_id,
            "--text",
            text,
        ])?;
    }

    let head_before_offline_sync = run_cli_json([
        "sync",
        "head",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
    ])?;
    let head_seq = required_u64(&head_before_offline_sync, "head_seq")?;

    let receiver_status_before = run_cli_json([
        "sync",
        "status",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
    ])?;
    let receiver_before_acked =
        required_u64(&receiver_status_before["checkpoint"], "last_acked_seq")?;
    assert!(receiver_before_acked < head_seq);
    assert!(receiver_status_before["notifications"].is_array());

    let offline_recovery_sync = run_cli_json([
        "sync",
        "once",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
    ])?;
    assert_eq!(offline_recovery_sync["synced"], Value::Bool(true));
    let offline_recovery_acked =
        required_u64(&offline_recovery_sync["checkpoint"], "last_acked_seq")?;
    assert_eq!(offline_recovery_acked, head_seq);
    assert_realtime_not_connected(&offline_recovery_sync["realtime"]);

    let third_messages = run_cli_json([
        "message",
        "list",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;
    for text in ["offline batch 1", "offline batch 2", "offline batch 3"] {
        assert_eq!(count_plaintext_messages(&third_messages, text), 1);
    }

    let bob_show_after_offline = run_cli_json([
        "conversation",
        "show",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;
    assert_eq!(
        bob_show_after_offline["recovery_status"].as_str(),
        Some("Healthy")
    );
    assert_eq!(
        required_u64(&bob_show_after_offline["checkpoint"], "last_acked_seq")?,
        head_seq
    );

    let repeat_sync = run_cli_json([
        "sync",
        "once",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
    ])?;
    assert_eq!(
        required_u64(&repeat_sync["checkpoint"], "last_acked_seq")?,
        head_seq
    );
    let repeated_messages = run_cli_json([
        "message",
        "list",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;
    for text in [
        "hello from cli e2e",
        "offline batch 1",
        "offline batch 2",
        "offline batch 3",
    ] {
        assert_eq!(count_plaintext_messages(&repeated_messages, text), 1);
    }
    let repeated_status = run_cli_json([
        "sync",
        "status",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
    ])?;
    assert_eq!(
        required_u64(&repeated_status["checkpoint"], "last_acked_seq")?,
        head_seq
    );
    assert!(repeated_status["realtime"].is_object());
    assert!(repeated_status["notifications"].is_array());
    assert_eq!(
        conversation_show(&ctx.bob_profile, &ctx.conversation_id)?["recovery_status"].as_str(),
        Some("Healthy")
    );

    let snapshot: Value = read_json_file(&ctx.bob_profile.join("snapshot.json"))?;
    let conversations = snapshot["snapshot"]["conversations"]
        .as_array()
        .context("snapshot conversations missing")?;
    assert!(
        conversations
            .iter()
            .any(|row| row["conversation_id"].as_str() == Some(ctx.conversation_id.as_str()))
    );
    let sync_states = snapshot["snapshot"]["sync_states"]
        .as_array()
        .context("snapshot sync states missing")?;
    assert!(sync_states.iter().any(|row| {
        row["device_id"].as_str() == Some(ctx.bob_device_id.as_str())
            && row["state"]["checkpoint"]["last_acked_seq"]
                .as_u64()
                .unwrap_or_default()
                == head_seq
    }));

    Ok(())
}

#[test]
fn cli_multi_device_join_and_switch_e2e_work() -> Result<()> {
    let _guard = test_lock();
    let ctx = setup_cli_pair("multi-device")?;
    let laptop = start_bob_laptop_recovery(&ctx)?;

    let alice_show = run_cli_json([
        "conversation",
        "show",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;
    assert!(matches!(
        alice_show["conversation_state"].as_str(),
        Some("active") | Some("needs_rebuild")
    ));
    assert_conversation_show_recovery(
        &alice_show,
        &["NeedsRecovery", "NeedsRebuild"],
        &["membership_changed"],
        &["waiting_for_explicit_reconcile", "escalated_to_rebuild"],
        None,
    )?;
    assert!(alice_show["checkpoint"].is_object());
    assert!(snapshot_has_recovery_context(
        &ctx.alice_profile,
        &ctx.conversation_id
    )?);
    assert!(laptop.merged_identity_path.exists());

    let laptop_sync = sync_once(&laptop.laptop_profile)?;
    assert_eq!(laptop_sync["synced"], Value::Bool(true));
    assert_realtime_not_connected(&laptop_sync["realtime"]);
    assert!(conversation_exists(
        &laptop.laptop_profile,
        &ctx.conversation_id
    )?);

    for _ in 0..4 {
        run_cli_json([
            "conversation",
            "reconcile",
            "--profile",
            &ctx.alice_profile.to_string_lossy(),
            "--conversation-id",
            &ctx.conversation_id,
        ])?;
        let _ = sync_once(&laptop.laptop_profile)?;
        if conversation_exists(&laptop.laptop_profile, &ctx.conversation_id)?
            && conversation_recovery_status(&ctx.alice_profile, &ctx.conversation_id)?.as_deref()
                == Some("Healthy")
        {
            break;
        }
    }

    let alice_show_after = conversation_show(&ctx.alice_profile, &ctx.conversation_id)?;
    assert_conversation_show_healthy(&alice_show_after);
    assert!(conversation_exists(
        &laptop.laptop_profile,
        &ctx.conversation_id
    )?);
    let laptop_show_after_reconcile =
        conversation_show(&laptop.laptop_profile, &ctx.conversation_id)?;
    assert_eq!(
        laptop_show_after_reconcile["conversation_state"].as_str(),
        Some("active")
    );
    assert_conversation_show_healthy(&laptop_show_after_reconcile);

    run_cli_json([
        "message",
        "send-text",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
        "--text",
        "hello laptop",
    ])?;
    let laptop_sync_after_message = sync_once(&laptop.laptop_profile)?;
    assert_eq!(laptop_sync_after_message["synced"], Value::Bool(true));
    let laptop_messages = run_cli_json([
        "message",
        "list",
        "--profile",
        &laptop.laptop_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;
    assert_eq!(
        count_plaintext_messages(&laptop_messages, "hello laptop"),
        1
    );

    Ok(())
}

#[test]
fn cli_recovery_restart_e2e_work() -> Result<()> {
    let _guard = test_lock();
    let ctx = setup_cli_pair("restart-recovery")?;
    let laptop = start_bob_laptop_recovery(&ctx)?;

    let alice_show_before = run_cli_json([
        "conversation",
        "show",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;
    assert!(matches!(
        alice_show_before["conversation_state"].as_str(),
        Some("active") | Some("needs_rebuild")
    ));
    assert_conversation_show_recovery(
        &alice_show_before,
        &["NeedsRecovery", "NeedsRebuild"],
        &["membership_changed"],
        &["waiting_for_explicit_reconcile", "escalated_to_rebuild"],
        None,
    )?;
    assert!(snapshot_has_recovery_context(
        &ctx.alice_profile,
        &ctx.conversation_id
    )?);

    let alice_snapshot_before = read_json_file::<Value>(&ctx.alice_profile.join("snapshot.json"))?;
    let alice_sync_before = snapshot_sync_state(&alice_snapshot_before, &ctx.alice_device_id)?;
    let before_restart_acked = required_u64(alice_sync_before, "last_acked_seq")?;

    let alice_show_after = run_cli_json([
        "conversation",
        "show",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;
    assert!(matches!(
        alice_show_after["conversation_state"].as_str(),
        Some("active") | Some("needs_rebuild")
    ));
    assert_conversation_show_recovery(
        &alice_show_after,
        &["NeedsRecovery", "NeedsRebuild"],
        &["membership_changed"],
        &["waiting_for_explicit_reconcile", "escalated_to_rebuild"],
        None,
    )?;

    let alice_snapshot_after = read_json_file::<Value>(&ctx.alice_profile.join("snapshot.json"))?;
    let alice_sync_after = snapshot_sync_state(&alice_snapshot_after, &ctx.alice_device_id)?;
    let after_restart_acked = required_u64(alice_sync_after, "last_acked_seq")?;
    assert!(after_restart_acked >= before_restart_acked);
    assert!(snapshot_has_conversation(
        &ctx.alice_profile,
        &ctx.conversation_id
    )?);
    assert!(snapshot_has_recovery_context(
        &ctx.alice_profile,
        &ctx.conversation_id
    )?);
    assert!(laptop.merged_identity_path.exists());

    let laptop_sync = sync_once(&laptop.laptop_profile)?;
    assert_eq!(laptop_sync["synced"], Value::Bool(true));

    for _ in 0..4 {
        run_cli_json([
            "conversation",
            "reconcile",
            "--profile",
            &ctx.alice_profile.to_string_lossy(),
            "--conversation-id",
            &ctx.conversation_id,
        ])?;
        let _ = sync_once(&laptop.laptop_profile)?;
        if conversation_recovery_status(&ctx.alice_profile, &ctx.conversation_id)?.as_deref()
            == Some("Healthy")
        {
            break;
        }
    }

    let alice_show_healthy = conversation_show(&ctx.alice_profile, &ctx.conversation_id)?;
    assert_eq!(
        alice_show_healthy["conversation_state"].as_str(),
        Some("active")
    );
    assert_conversation_show_healthy(&alice_show_healthy);
    assert!(alice_show_healthy["checkpoint"].is_object());
    assert!(conversation_exists(
        &laptop.laptop_profile,
        &ctx.conversation_id
    )?);

    let alice_snapshot_final = read_json_file::<Value>(&ctx.alice_profile.join("snapshot.json"))?;
    let alice_sync_final = snapshot_sync_state(&alice_snapshot_final, &ctx.alice_device_id)?;
    let final_acked = required_u64(alice_sync_final, "last_acked_seq")?;
    assert!(final_acked >= after_restart_acked);
    assert!(snapshot_has_conversation(
        &ctx.alice_profile,
        &ctx.conversation_id
    )?);
    let alice_status_final = run_cli_json([
        "sync",
        "status",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
    ])?;
    assert!(alice_status_final["notifications"].is_array());
    assert!(alice_status_final["checkpoint"].is_object());
    assert!(alice_status_final.get("realtime").is_some());
    assert!(recovery_conversations(&alice_status_final)?.is_empty());

    Ok(())
}

#[test]
fn cli_attachment_restart_and_delayed_recovery_work() -> Result<()> {
    let _guard = test_lock();
    let ctx = setup_cli_pair("attachment-restart")?;
    let laptop = start_bob_laptop_recovery(&ctx)?;

    let attachment_path = ctx.temp_root.path().join("recovery-attachment.txt");
    fs::write(&attachment_path, "attachment during delayed recovery")?;

    for _ in 0..4 {
        run_cli_json([
            "conversation",
            "reconcile",
            "--profile",
            &ctx.alice_profile.to_string_lossy(),
            "--conversation-id",
            &ctx.conversation_id,
        ])?;
        let _ = sync_once(&laptop.laptop_profile)?;
        if conversation_recovery_status(&ctx.alice_profile, &ctx.conversation_id)?.as_deref()
            == Some("Healthy")
        {
            break;
        }
    }

    run_cli_json([
        "message",
        "send-attachment",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
        "--file",
        &attachment_path.to_string_lossy(),
    ])?;
    let _ = sync_once(&laptop.laptop_profile)?;

    let merged_identity = runtime_get_identity_bundle(&ctx.runtime, &ctx.bob_user_id)?;
    patch_profile_local_bundle(&laptop.laptop_profile, &merged_identity)?;
    let revoked = run_cli_json([
        "device",
        "revoke",
        "--profile",
        &laptop.laptop_profile.to_string_lossy(),
        "--target-device-id",
        &ctx.bob_device_id,
    ])?;
    assert_eq!(revoked["revoked"], Value::Bool(true));
    run_cli_json([
        "contact",
        "refresh",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--user-id",
        &ctx.bob_user_id,
    ])?;

    let recovering_show = conversation_show(&ctx.alice_profile, &ctx.conversation_id)?;
    assert_conversation_show_recovery(
        &recovering_show,
        &["NeedsRecovery", "NeedsRebuild"],
        &["membership_changed"],
        &["waiting_for_explicit_reconcile", "escalated_to_rebuild"],
        None,
    )?;
    let recovering_status = run_cli_json([
        "sync",
        "status",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
    ])?;
    assert!(recovering_status["checkpoint"].is_object());
    assert!(recovering_status["notifications"].is_array());
    assert!(recovering_status.get("realtime").is_some());
    let mut last_phase = assert_recovery_conversation_matches(
        &recovering_status,
        &ctx.conversation_id,
        &["NeedsRecovery", "NeedsRebuild"],
        &["membership_changed"],
        &["waiting_for_explicit_reconcile", "escalated_to_rebuild"],
        None,
    )?;

    for _ in 0..4 {
        run_cli_json([
            "conversation",
            "reconcile",
            "--profile",
            &ctx.alice_profile.to_string_lossy(),
            "--conversation-id",
            &ctx.conversation_id,
        ])?;
        let _ = sync_once(&laptop.laptop_profile)?;
        let phase_snapshot = run_cli_json([
            "sync",
            "status",
            "--profile",
            &ctx.alice_profile.to_string_lossy(),
        ])?;
        if let Ok(current_phase) = assert_recovery_conversation_matches(
            &phase_snapshot,
            &ctx.conversation_id,
            &["NeedsRecovery", "NeedsRebuild"],
            &["membership_changed"],
            &[
                "waiting_for_explicit_reconcile",
                "waiting_for_sync",
                "waiting_for_pending_replay",
                "escalated_to_rebuild",
            ],
            None,
        ) {
            assert_recovery_phase_not_regressed(&last_phase, &current_phase);
            last_phase = current_phase;
        }
        if conversation_recovery_status(&ctx.alice_profile, &ctx.conversation_id)?.as_deref()
            == Some("Healthy")
        {
            break;
        }
    }

    let alice_show = conversation_show(&ctx.alice_profile, &ctx.conversation_id)?;
    assert_conversation_show_healthy(&alice_show);
    let laptop_show = conversation_show(&laptop.laptop_profile, &ctx.conversation_id)?;
    assert_eq!(laptop_show["conversation_state"].as_str(), Some("active"));
    assert_conversation_show_healthy(&laptop_show);

    let laptop_messages = run_cli_json([
        "message",
        "list",
        "--profile",
        &laptop.laptop_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;
    let attachment_message = laptop_messages
        .as_array()
        .context("laptop message list not array")?
        .iter()
        .find(|message| {
            message["storage_refs"]
                .as_array()
                .map(|refs| !refs.is_empty())
                .unwrap_or(false)
        })
        .cloned()
        .context("laptop attachment message missing after delayed recovery")?;
    let attachment_message_id = required_str(&attachment_message, "message_id")?;
    let attachment_reference = attachment_message["storage_refs"][0]["ref"]
        .as_str()
        .context("laptop attachment reference missing")?
        .to_string();

    let downloaded_path = laptop
        .laptop_profile
        .join("attachments")
        .join("inbox")
        .join("recovered-attachment.txt");
    let downloaded = run_cli_json([
        "message",
        "download-attachment",
        "--profile",
        &laptop.laptop_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
        "--message-id",
        &attachment_message_id,
        "--reference",
        &attachment_reference,
        "--out",
        &downloaded_path.to_string_lossy(),
    ])?;
    assert_eq!(downloaded["downloaded"], Value::Bool(true));
    assert_eq!(
        fs::read_to_string(&downloaded_path)?,
        "attachment during delayed recovery"
    );

    Ok(())
}

#[test]
fn cli_cleanup_after_ack_keeps_checkpoint_monotonic() -> Result<()> {
    let _guard = test_lock();
    let workspace_root = workspace_root();
    let runtime = runtime_handle_with_options(
        &workspace_root,
        CloudflareRuntimeOptions {
            retention_days: Some(0),
            ..Default::default()
        },
    )?;
    let ctx = setup_cli_pair_with_runtime("cleanup-after-ack", runtime)?;

    run_cli_json([
        "message",
        "send-text",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
        "--text",
        "cleanup baseline",
    ])?;
    let first_sync = sync_once(&ctx.bob_profile)?;
    assert_eq!(first_sync["synced"], Value::Bool(true));
    let head = runtime_get_head(
        &ctx.runtime,
        bundle_auth(&ctx.bob_bundle)?,
        &ctx.bob_device_id,
    )?;
    let acked_seq = required_u64(&first_sync["checkpoint"], "last_acked_seq")?;
    assert_eq!(acked_seq, head);

    wait_for_runtime_cleanup(
        &ctx.runtime,
        bundle_auth(&ctx.bob_bundle)?,
        &ctx.bob_device_id,
        1,
    )?;

    let second_sync = sync_once(&ctx.bob_profile)?;
    assert_eq!(second_sync["synced"], Value::Bool(true));
    assert_eq!(
        required_u64(&second_sync["checkpoint"], "last_acked_seq")?,
        acked_seq
    );
    let messages = run_cli_json([
        "message",
        "list",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;
    assert_eq!(count_plaintext_messages(&messages, "cleanup baseline"), 1);
    assert_eq!(
        conversation_show(&ctx.bob_profile, &ctx.conversation_id)?["recovery_status"].as_str(),
        Some("Healthy")
    );

    Ok(())
}

#[test]
fn cli_cleanup_recovery_remains_idempotent_across_repeated_sync() -> Result<()> {
    let _guard = test_lock();
    let workspace_root = workspace_root();
    let runtime = runtime_handle_with_options(
        &workspace_root,
        CloudflareRuntimeOptions {
            retention_days: Some(0),
            ..Default::default()
        },
    )?;
    let ctx = setup_cli_pair_with_runtime("cleanup-repeated-sync", runtime)?;

    for text in ["cleanup repeated 1", "cleanup repeated 2"] {
        let sent = run_cli_json([
            "message",
            "send-text",
            "--profile",
            &ctx.alice_profile.to_string_lossy(),
            "--conversation-id",
            &ctx.conversation_id,
            "--text",
            text,
        ])?;
        assert_eq!(sent["sent"], Value::Bool(true));
        assert_eq!(sent["pending_outbox"].as_u64(), Some(0));
    }

    let first_sync = sync_once(&ctx.bob_profile)?;
    assert_eq!(first_sync["synced"], Value::Bool(true));
    assert!(first_sync["notifications"].is_array());
    assert!(first_sync["realtime"].is_object());
    let acked_seq = required_u64(&first_sync["checkpoint"], "last_acked_seq")?;
    assert_eq!(
        acked_seq,
        runtime_get_head(&ctx.runtime, bundle_auth(&ctx.bob_bundle)?, &ctx.bob_device_id)?
    );

    wait_for_runtime_cleanup(
        &ctx.runtime,
        bundle_auth(&ctx.bob_bundle)?,
        &ctx.bob_device_id,
        1,
    )?;

    let second_sync = sync_once(&ctx.bob_profile)?;
    assert_eq!(second_sync["synced"], Value::Bool(true));
    assert_eq!(
        required_u64(&second_sync["checkpoint"], "last_acked_seq")?,
        acked_seq
    );
    assert!(second_sync["realtime"].is_object());

    let third_sync = sync_once(&ctx.bob_profile)?;
    assert_eq!(third_sync["synced"], Value::Bool(true));
    assert_eq!(
        required_u64(&third_sync["checkpoint"], "last_acked_seq")?,
        acked_seq
    );

    let status = run_cli_json([
        "sync",
        "status",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
    ])?;
    assert_eq!(status["pending_outbox"].as_u64(), Some(0));
    assert_eq!(status["pending_blob_uploads"].as_u64(), Some(0));
    assert_eq!(required_u64(&status["checkpoint"], "last_acked_seq")?, acked_seq);
    assert!(status["realtime"].is_object());

    let messages = run_cli_json([
        "message",
        "list",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;
    assert_eq!(count_plaintext_messages(&messages, "cleanup repeated 1"), 1);
    assert_eq!(count_plaintext_messages(&messages, "cleanup repeated 2"), 1);

    let conversation = conversation_show(&ctx.bob_profile, &ctx.conversation_id)?;
    assert_eq!(conversation["recovery_status"].as_str(), Some("Healthy"));
    assert!(conversation["checkpoint"].is_object());
    assert!(conversation["realtime"].is_object());
    assert!(conversation["recovery"].is_null());

    Ok(())
}

#[test]
fn cli_long_offline_attachment_and_membership_change_recover_e2e_work() -> Result<()> {
    let _guard = test_lock();
    let ctx = setup_cli_pair("long-offline-attachment-membership")?;
    let laptop = start_bob_laptop_recovery(&ctx)?;

    for _ in 0..4 {
        run_cli_json([
            "conversation",
            "reconcile",
            "--profile",
            &ctx.alice_profile.to_string_lossy(),
            "--conversation-id",
            &ctx.conversation_id,
        ])?;
        let _ = sync_once(&laptop.laptop_profile)?;
        if conversation_recovery_status(&ctx.alice_profile, &ctx.conversation_id)?.as_deref()
            == Some("Healthy")
        {
            break;
        }
    }

    let alice_initial = conversation_show(&ctx.alice_profile, &ctx.conversation_id)?;
    assert_eq!(alice_initial["recovery_status"].as_str(), Some("Healthy"));
    assert!(alice_initial["checkpoint"].is_object());
    let laptop_initial = conversation_show(&laptop.laptop_profile, &ctx.conversation_id)?;
    assert_eq!(laptop_initial["conversation_state"].as_str(), Some("active"));
    assert_eq!(laptop_initial["recovery_status"].as_str(), Some("Healthy"));
    let alice_initial_status = run_cli_json([
        "sync",
        "status",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
    ])?;
    assert!(alice_initial_status.get("realtime").is_some());
    let laptop_initial_status = run_cli_json([
        "sync",
        "status",
        "--profile",
        &laptop.laptop_profile.to_string_lossy(),
    ])?;
    assert!(laptop_initial_status.get("realtime").is_some());

    let attachment_path = ctx.temp_root.path().join("long-offline-attachment.txt");
    fs::write(&attachment_path, "attachment during long offline membership change")?;
    let attachment_send = run_cli_json([
        "message",
        "send-attachment",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
        "--file",
        &attachment_path.to_string_lossy(),
    ])?;
    assert_eq!(attachment_send["queued"], Value::Bool(true));
    assert_eq!(attachment_send["pending_outbox"].as_u64(), Some(0));
    assert_eq!(attachment_send["pending_blob_uploads"].as_u64(), Some(0));

    let laptop_sync_before_revoke = sync_once(&laptop.laptop_profile)?;
    assert_eq!(laptop_sync_before_revoke["synced"], Value::Bool(true));
    let laptop_sync_before_revoke_seq =
        required_u64(&laptop_sync_before_revoke["checkpoint"], "last_acked_seq")?;
    assert!(laptop_sync_before_revoke_seq >= 1);
    assert!(laptop_sync_before_revoke["realtime"].is_object());

    let merged_identity = runtime_get_identity_bundle(&ctx.runtime, &ctx.bob_user_id)?;
    patch_profile_local_bundle(&laptop.laptop_profile, &merged_identity)?;
    let revoked = run_cli_json([
        "device",
        "revoke",
        "--profile",
        &laptop.laptop_profile.to_string_lossy(),
        "--target-device-id",
        &ctx.bob_device_id,
    ])?;
    assert_eq!(revoked["revoked"], Value::Bool(true));

    run_cli_json([
        "contact",
        "refresh",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--user-id",
        &ctx.bob_user_id,
    ])?;

    let alice_recovering = conversation_show(&ctx.alice_profile, &ctx.conversation_id)?;
    assert_conversation_show_recovery(
        &alice_recovering,
        &["NeedsRecovery", "NeedsRebuild"],
        &["membership_changed"],
        &["waiting_for_explicit_reconcile", "escalated_to_rebuild"],
        None,
    )?;
    let alice_recovering_status = run_cli_json([
        "sync",
        "status",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
    ])?;
    assert!(alice_recovering_status["checkpoint"].is_object());
    assert!(alice_recovering_status["notifications"].is_array());
    assert!(alice_recovering_status.get("realtime").is_some());
    assert_eq!(alice_recovering_status["pending_outbox"].as_u64(), Some(0));
    assert_eq!(
        alice_recovering_status["pending_blob_uploads"].as_u64(),
        Some(0)
    );
    let mut last_phase = assert_recovery_conversation_matches(
        &alice_recovering_status,
        &ctx.conversation_id,
        &["NeedsRecovery", "NeedsRebuild"],
        &["membership_changed"],
        &["waiting_for_explicit_reconcile", "escalated_to_rebuild"],
        None,
    )?;

    for _ in 0..4 {
        run_cli_json([
            "conversation",
            "reconcile",
            "--profile",
            &ctx.alice_profile.to_string_lossy(),
            "--conversation-id",
            &ctx.conversation_id,
        ])?;
        let _ = sync_once(&laptop.laptop_profile)?;
        let phase_snapshot = run_cli_json([
            "sync",
            "status",
            "--profile",
            &ctx.alice_profile.to_string_lossy(),
        ])?;
        if let Ok(current_phase) = assert_recovery_conversation_matches(
            &phase_snapshot,
            &ctx.conversation_id,
            &["NeedsRecovery", "NeedsRebuild"],
            &["membership_changed"],
            &[
                "waiting_for_explicit_reconcile",
                "waiting_for_sync",
                "waiting_for_pending_replay",
                "escalated_to_rebuild",
            ],
            None,
        ) {
            assert_recovery_phase_not_regressed(&last_phase, &current_phase);
            last_phase = current_phase;
        }
        if conversation_recovery_status(&ctx.alice_profile, &ctx.conversation_id)?.as_deref()
            == Some("Healthy")
        {
            break;
        }
    }

    let alice_final = conversation_show(&ctx.alice_profile, &ctx.conversation_id)?;
    assert_conversation_show_healthy(&alice_final);
    assert!(alice_final["checkpoint"].is_object());
    assert!(alice_final.get("realtime").is_some());

    run_cli_json([
        "message",
        "send-text",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
        "--text",
        "post revoke long offline message",
    ])?;
    let laptop_post_revoke_sync = sync_once(&laptop.laptop_profile)?;
    assert_eq!(laptop_post_revoke_sync["synced"], Value::Bool(true));

    let delayed_phone_sync = sync_once(&ctx.bob_profile)?;
    assert_eq!(delayed_phone_sync["synced"], Value::Bool(true));
    let delayed_phone_seq =
        required_u64(&delayed_phone_sync["checkpoint"], "last_acked_seq")?;
    assert!(delayed_phone_seq >= 1);

    let phone_status = run_cli_json([
        "sync",
        "status",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
    ])?;
    assert_eq!(phone_status["pending_outbox"].as_u64(), Some(0));
    assert_eq!(phone_status["pending_blob_uploads"].as_u64(), Some(0));
    assert!(phone_status.get("realtime").is_some());

    let phone_messages = run_cli_json([
        "message",
        "list",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;
    let phone_attachment_count = phone_messages
        .as_array()
        .context("phone message list not array")?
        .iter()
        .filter(|message| {
            message["storage_refs"]
                .as_array()
                .map(|refs| !refs.is_empty())
                .unwrap_or(false)
        })
        .count();
    assert_eq!(
        count_plaintext_messages(&phone_messages, "post revoke long offline message"),
        0
    );
    let phone_conversation = conversation_show(&ctx.bob_profile, &ctx.conversation_id)?;
    assert!(matches!(
        phone_conversation["recovery_status"].as_str(),
        Some("Healthy") | Some("NeedsRebuild")
    ));
    assert!(phone_conversation.get("realtime").is_some());
    assert!(phone_attachment_count <= 1);

    let laptop_show = conversation_show(&laptop.laptop_profile, &ctx.conversation_id)?;
    assert_eq!(laptop_show["conversation_state"].as_str(), Some("active"));
    assert_conversation_show_healthy(&laptop_show);
    assert!(laptop_show["checkpoint"].is_object());
    assert!(laptop_show.get("realtime").is_some());

    let laptop_messages = run_cli_json([
        "message",
        "list",
        "--profile",
        &laptop.laptop_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;
    let attachment_message = laptop_messages
        .as_array()
        .context("laptop message list not array")?
        .iter()
        .find(|message| {
            message["storage_refs"]
                .as_array()
                .map(|refs| !refs.is_empty())
                .unwrap_or(false)
        })
        .cloned()
        .context("laptop attachment message missing after long offline recovery")?;
    assert_eq!(
        count_plaintext_messages(&laptop_messages, "post revoke long offline message"),
        1
    );
    let attachment_message_id = required_str(&attachment_message, "message_id")?;
    let attachment_reference = attachment_message["storage_refs"][0]["ref"]
        .as_str()
        .context("laptop attachment reference missing after long offline recovery")?
        .to_string();
    let downloaded_path = laptop
        .laptop_profile
        .join("attachments")
        .join("inbox")
        .join("long-offline-recovered-attachment.txt");
    let downloaded = run_cli_json([
        "message",
        "download-attachment",
        "--profile",
        &laptop.laptop_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
        "--message-id",
        &attachment_message_id,
        "--reference",
        &attachment_reference,
        "--out",
        &downloaded_path.to_string_lossy(),
    ])?;
    assert_eq!(downloaded["downloaded"], Value::Bool(true));
    assert_eq!(
        fs::read_to_string(&downloaded_path)?,
        "attachment during long offline membership change"
    );

    Ok(())
}

#[test]
fn cli_repeated_realtime_and_sync_do_not_duplicate_delivery_e2e_work() -> Result<()> {
    let _guard = test_lock();
    let ctx = setup_cli_pair("repeated-realtime-sync")?;

    let foreground = run_cli_json([
        "sync",
        "foreground",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
    ])?;
    assert_eq!(foreground["foreground_sync"], Value::Bool(true));

    let initial_status = run_cli_json([
        "sync",
        "status",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
    ])?;
    assert!(initial_status["checkpoint"].is_object());
    assert!(initial_status.get("realtime").is_some());
    assert!(initial_status["notifications"].is_array());
    assert!(recovery_conversations(&initial_status)?.is_empty());

    run_cli_json([
        "message",
        "send-text",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
        "--text",
        "duplicate realtime sync one",
    ])?;

    let first_sync = sync_once(&ctx.bob_profile)?;
    let first_acked = required_u64(&first_sync["checkpoint"], "last_acked_seq")?;
    let first_notifications_len = first_sync["notifications"]
        .as_array()
        .context("first sync notifications not array")?
        .len();
    assert!(first_sync.get("realtime").is_some());

    let second_sync = sync_once(&ctx.bob_profile)?;
    let second_acked = required_u64(&second_sync["checkpoint"], "last_acked_seq")?;
    let second_notifications_len = second_sync["notifications"]
        .as_array()
        .context("second sync notifications not array")?
        .len();
    assert!(second_acked >= first_acked);
    assert_eq!(second_notifications_len, first_notifications_len);

    let status_after_repeat = run_cli_json([
        "sync",
        "status",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
    ])?;
    assert!(status_after_repeat.get("realtime").is_some());
    assert_eq!(
        required_u64(&status_after_repeat["checkpoint"], "last_acked_seq")?,
        second_acked
    );
    assert!(recovery_conversations(&status_after_repeat)?.is_empty());

    let first_messages = run_cli_json([
        "message",
        "list",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;
    assert_eq!(
        count_plaintext_messages(&first_messages, "duplicate realtime sync one"),
        1
    );

    run_cli_json([
        "message",
        "send-text",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
        "--text",
        "duplicate realtime sync two",
    ])?;

    let third_sync = sync_once(&ctx.bob_profile)?;
    let third_acked = required_u64(&third_sync["checkpoint"], "last_acked_seq")?;
    assert!(third_acked >= second_acked);
    let fourth_sync = sync_once(&ctx.bob_profile)?;
    let fourth_acked = required_u64(&fourth_sync["checkpoint"], "last_acked_seq")?;
    assert!(fourth_acked >= third_acked);

    let final_messages = run_cli_json([
        "message",
        "list",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;
    assert_eq!(
        count_plaintext_messages(&final_messages, "duplicate realtime sync one"),
        1
    );
    assert_eq!(
        count_plaintext_messages(&final_messages, "duplicate realtime sync two"),
        1
    );

    let final_status = run_cli_json([
        "sync",
        "status",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
    ])?;
    assert!(final_status.get("realtime").is_some());
    assert!(final_status["notifications"].is_array());
    assert_eq!(final_status["pending_outbox"].as_u64(), Some(0));
    assert_eq!(final_status["pending_blob_uploads"].as_u64(), Some(0));
    assert!(recovery_conversations(&final_status)?.is_empty());

    Ok(())
}

#[test]
fn cli_revoke_with_delayed_sync_keeps_revoked_device_isolated() -> Result<()> {
    let _guard = test_lock();
    let ctx = setup_cli_pair("revoke-delayed-sync")?;
    let laptop = start_bob_laptop_recovery(&ctx)?;

    for _ in 0..4 {
        run_cli_json([
            "conversation",
            "reconcile",
            "--profile",
            &ctx.alice_profile.to_string_lossy(),
            "--conversation-id",
            &ctx.conversation_id,
        ])?;
        let _ = sync_once(&laptop.laptop_profile)?;
        if conversation_recovery_status(&ctx.alice_profile, &ctx.conversation_id)?.as_deref()
            == Some("Healthy")
        {
            break;
        }
    }

    let merged_identity = runtime_get_identity_bundle(&ctx.runtime, &ctx.bob_user_id)?;
    patch_profile_local_bundle(&laptop.laptop_profile, &merged_identity)?;
    let revoked = run_cli_json([
        "device",
        "revoke",
        "--profile",
        &laptop.laptop_profile.to_string_lossy(),
        "--target-device-id",
        &ctx.bob_device_id,
    ])?;
    assert_eq!(revoked["revoked"], Value::Bool(true));
    run_cli_json([
        "contact",
        "refresh",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--user-id",
        &ctx.bob_user_id,
    ])?;
    run_cli_json([
        "conversation",
        "reconcile",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;

    run_cli_json([
        "message",
        "send-text",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
        "--text",
        "post revoke delayed sync",
    ])?;
    let delayed_laptop_sync = sync_once(&laptop.laptop_profile)?;
    assert_eq!(delayed_laptop_sync["synced"], Value::Bool(true));

    let laptop_messages = run_cli_json([
        "message",
        "list",
        "--profile",
        &laptop.laptop_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;
    assert_eq!(
        count_plaintext_messages(&laptop_messages, "post revoke delayed sync"),
        1
    );

    let delayed_phone_sync = sync_once(&ctx.bob_profile)?;
    assert_eq!(delayed_phone_sync["synced"], Value::Bool(true));
    let phone_messages = run_cli_json([
        "message",
        "list",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;
    assert_eq!(
        count_plaintext_messages(&phone_messages, "post revoke delayed sync"),
        0
    );

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
        let _ = stop_pid_and_wait(pid);
    }
}

fn runtime_handle(workspace_root: &Path) -> Result<CloudflareRuntimeHandle> {
    runtime_handle_with_options(workspace_root, CloudflareRuntimeOptions::default())
}

fn runtime_handle_with_options(
    workspace_root: &Path,
    options: CloudflareRuntimeOptions,
) -> Result<CloudflareRuntimeHandle> {
    with_tokio(|| async {
        CloudflareRuntimeHandle::start_with_options(workspace_root, options).await
    })
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

fn run_cli_output<I, S>(args: I) -> Result<std::process::Output>
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
    command.output().context("run tapchat cli")
}
fn run_cli_json_in_cwd<I, S>(cwd: &Path, args: I) -> Result<Value>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut command = Command::new(binary_path());
    command.current_dir(cwd).arg("--output").arg("json");
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

fn sync_once(profile: &Path) -> Result<Value> {
    run_cli_json(["sync", "once", "--profile", &profile.to_string_lossy()])
}

fn conversation_show(profile: &Path, conversation_id: &str) -> Result<Value> {
    run_cli_json([
        "conversation",
        "show",
        "--profile",
        &profile.to_string_lossy(),
        "--conversation-id",
        conversation_id,
    ])
}

fn conversation_exists(profile: &Path, conversation_id: &str) -> Result<bool> {
    let rows = run_cli_json([
        "conversation",
        "list",
        "--profile",
        &profile.to_string_lossy(),
    ])?;
    Ok(rows
        .as_array()
        .context("conversation list not array")?
        .iter()
        .any(|row| row["conversation_id"].as_str() == Some(conversation_id)))
}

fn conversation_recovery_status(profile: &Path, conversation_id: &str) -> Result<Option<String>> {
    Ok(
        conversation_show(profile, conversation_id)?["recovery_status"]
            .as_str()
            .map(|value| value.to_string()),
    )
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

fn required_u64(value: &Value, field: &str) -> Result<u64> {
    value[field]
        .as_u64()
        .ok_or_else(|| anyhow!("missing u64 field {field}"))
}

fn count_plaintext_messages(messages: &Value, plaintext: &str) -> usize {
    messages
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter(|message| message["plaintext"].as_str() == Some(plaintext))
                .count()
        })
        .unwrap_or_default()
}

fn assert_realtime_not_connected(snapshot: &Value) {
    if snapshot.is_null() {
        return;
    }
    assert_eq!(snapshot["needs_reconnect"].as_bool(), Some(false));
}

fn recovery_conversations(value: &Value) -> Result<&Vec<Value>> {
    value["recovery_conversations"]
        .as_array()
        .context("recovery_conversations missing")
}

fn find_recovery_conversation<'a>(value: &'a Value, conversation_id: &str) -> Result<&'a Value> {
    recovery_conversations(value)?
        .iter()
        .find(|row| row["conversation_id"].as_str() == Some(conversation_id))
        .with_context(|| format!("missing recovery conversation {conversation_id}"))
}

fn assert_recovery_row_shape(row: &Value) -> Result<()> {
    assert!(row["conversation_id"].is_string());
    assert!(row["recovery_status"].is_string());
    assert_recovery_object_shape(row)
}

fn assert_recovery_object_shape(value: &Value) -> Result<()> {
    assert!(value["reason"].is_string());
    assert!(value["phase"].is_string());
    assert!(
        value["escalation_reason"].is_null() || value["escalation_reason"].is_string(),
        "escalation_reason must be null or string"
    );
    Ok(())
}

fn assert_recovery_conversation_matches(
    value: &Value,
    conversation_id: &str,
    expected_statuses: &[&str],
    expected_reasons: &[&str],
    expected_phases: &[&str],
    escalation_required: Option<bool>,
) -> Result<String> {
    let row = find_recovery_conversation(value, conversation_id)?;
    assert_recovery_row_shape(row)?;
    let status = row["recovery_status"]
        .as_str()
        .context("recovery_status missing")?;
    let reason = row["reason"].as_str().context("reason missing")?;
    let phase = row["phase"].as_str().context("phase missing")?;
    assert!(
        expected_statuses.contains(&status),
        "unexpected recovery_status {status:?}"
    );
    assert!(
        expected_reasons.contains(&reason),
        "unexpected recovery reason {reason:?}"
    );
    assert!(
        expected_phases.contains(&phase),
        "unexpected recovery phase {phase:?}"
    );
    if let Some(required) = escalation_required {
        assert_eq!(row["escalation_reason"].is_null(), !required);
    }
    Ok(phase.to_string())
}

fn assert_conversation_show_recovery(
    value: &Value,
    expected_statuses: &[&str],
    expected_reasons: &[&str],
    expected_phases: &[&str],
    escalation_required: Option<bool>,
) -> Result<String> {
    let recovery = &value["recovery"];
    assert!(
        !recovery.is_null(),
        "conversation show expected recovery object, found null"
    );
    assert_recovery_object_shape(recovery)?;
    let status = value["recovery_status"]
        .as_str()
        .context("conversation recovery_status missing")?;
    let reason = recovery["reason"].as_str().context("reason missing")?;
    let phase = recovery["phase"].as_str().context("phase missing")?;
    assert!(
        expected_statuses.contains(&status),
        "unexpected conversation recovery_status {status:?}"
    );
    assert!(
        expected_reasons.contains(&reason),
        "unexpected conversation recovery reason {reason:?}"
    );
    assert!(
        expected_phases.contains(&phase),
        "unexpected conversation recovery phase {phase:?}"
    );
    if let Some(required) = escalation_required {
        assert_eq!(recovery["escalation_reason"].is_null(), !required);
    }
    Ok(phase.to_string())
}

fn assert_conversation_show_healthy(value: &Value) {
    assert_eq!(value["recovery_status"].as_str(), Some("Healthy"));
    assert!(value["recovery"].is_null());
}

fn recovery_phase_rank(phase: &str) -> u8 {
    match phase {
        "waiting_for_explicit_reconcile" => 0,
        "waiting_for_identity_refresh" => 1,
        "waiting_for_sync" => 2,
        "waiting_for_pending_replay" => 3,
        "escalated_to_rebuild" => 4,
        other => panic!("unknown recovery phase {other}"),
    }
}

fn assert_recovery_phase_not_regressed(previous: &str, current: &str) {
    assert!(
        recovery_phase_rank(current) >= recovery_phase_rank(previous),
        "recovery phase regressed from {previous} to {current}"
    );
}

fn setup_cli_pair(suffix: &str) -> Result<CliPairContext> {
    let workspace_root = workspace_root();
    let runtime = runtime_handle(&workspace_root)?;
    setup_cli_pair_with_runtime(suffix, runtime)
}

fn setup_cli_pair_with_runtime(
    suffix: &str,
    runtime: CloudflareRuntimeHandle,
) -> Result<CliPairContext> {
    let temp_root = repo_temp_dir(suffix)?;
    let alice_profile = temp_root.path().join("alice");
    let bob_profile = temp_root.path().join("bob");
    let alice_mnemonic =
        write_mnemonic_file(temp_root.path(), "alice-mnemonic.txt", ALICE_MNEMONIC)?;
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
    let alice_bundle_path =
        write_json_file(temp_root.path(), "alice-deployment.json", &alice_bundle)?;
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

    let alice_identity_path =
        export_identity_bundle_to_path(temp_root.path(), &alice_profile, "alice-identity.json")?;
    let bob_identity_path =
        export_identity_bundle_to_path(temp_root.path(), &bob_profile, "bob-identity.json")?;
    let alice_identity_bundle: IdentityBundle = read_json_file(&alice_identity_path)?;
    let bob_identity_bundle: IdentityBundle = read_json_file(&bob_identity_path)?;
    runtime_put_identity_bundle(
        &runtime,
        bundle_auth(&alice_bundle)?,
        &alice_identity_bundle,
    )?;
    runtime_put_identity_bundle(&runtime, bundle_auth(&bob_bundle)?, &bob_identity_bundle)?;
    runtime_put_allowlist(
        &runtime,
        bundle_auth(&alice_bundle)?,
        std::slice::from_ref(&bob_user_id),
    )?;
    runtime_put_allowlist(
        &runtime,
        bundle_auth(&bob_bundle)?,
        std::slice::from_ref(&alice_user_id),
    )?;

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

    Ok(CliPairContext {
        runtime,
        temp_root,
        alice_profile,
        bob_profile,
        alice_bundle,
        bob_bundle,
        alice_user_id,
        bob_user_id,
        alice_device_id,
        bob_device_id,
        conversation_id,
    })
}

fn start_bob_laptop_recovery(ctx: &CliPairContext) -> Result<CliLaptopContext> {
    let laptop_profile = ctx.temp_root.path().join("bob-laptop");
    let bob_mnemonic = write_mnemonic_file(
        ctx.temp_root.path(),
        "bob-laptop-mnemonic.txt",
        BOB_MNEMONIC,
    )?;
    let public_bundle_path = write_json_file(
        ctx.temp_root.path(),
        "bob-laptop-public-deployment.json",
        &ctx.bob_bundle,
    )?;
    run_cli_json([
        "profile",
        "init",
        "--name",
        "bob-laptop",
        "--root",
        &laptop_profile.to_string_lossy(),
    ])?;
    run_cli_json([
        "profile",
        "import-deployment",
        "--profile",
        &laptop_profile.to_string_lossy(),
        &public_bundle_path.to_string_lossy(),
    ])?;
    let laptop_identity = run_cli_json([
        "device",
        "add",
        "--profile",
        &laptop_profile.to_string_lossy(),
        "--device-name",
        "laptop",
        "--mnemonic-file",
        &bob_mnemonic.to_string_lossy(),
    ])?;
    let laptop_device_id = required_str(&laptop_identity, "device_id")?;

    let laptop_bundle =
        runtime_bootstrap_device_bundle(&ctx.runtime, &ctx.bob_user_id, &laptop_device_id)?;
    let laptop_bundle_path = write_json_file(
        ctx.temp_root.path(),
        "bob-laptop-deployment.json",
        &laptop_bundle,
    )?;
    run_cli_json([
        "profile",
        "import-deployment",
        "--profile",
        &laptop_profile.to_string_lossy(),
        &laptop_bundle_path.to_string_lossy(),
    ])?;

    let phone_identity_path = export_identity_bundle_to_path(
        ctx.temp_root.path(),
        &ctx.bob_profile,
        "bob-phone-refresh-identity.json",
    )?;
    let laptop_identity_path = export_identity_bundle_to_path(
        ctx.temp_root.path(),
        &laptop_profile,
        "bob-laptop-identity.json",
    )?;
    let phone_bundle: IdentityBundle = read_json_file(&phone_identity_path)?;
    let laptop_identity_bundle: IdentityBundle = read_json_file(&laptop_identity_path)?;
    let merged_identity = merge_identity_bundles(
        &laptop_bundle,
        &laptop_profile,
        &[phone_bundle.clone(), laptop_identity_bundle],
    )?;
    let merged_identity_path = write_json_file(
        ctx.temp_root.path(),
        "bob-identity-merged.json",
        &merged_identity,
    )?;
    runtime_put_identity_bundle(&ctx.runtime, bundle_auth(&laptop_bundle)?, &merged_identity)?;
    runtime_put_allowlist(
        &ctx.runtime,
        bundle_auth(&laptop_bundle)?,
        std::slice::from_ref(&ctx.alice_user_id),
    )?;
    let runtime_identity = runtime_get_identity_bundle(&ctx.runtime, &ctx.bob_user_id)?;
    assert!(
        runtime_identity
            .devices
            .iter()
            .any(|device| device.device_id == laptop_device_id)
    );

    run_cli_json([
        "contact",
        "refresh",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--user-id",
        &ctx.bob_user_id,
    ])?;
    let alice_contact = run_cli_json([
        "contact",
        "show",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--user-id",
        &ctx.bob_user_id,
    ])?;
    assert!(
        alice_contact["devices"]
            .as_array()
            .context("alice contact devices missing")?
            .iter()
            .any(|device| device["device_id"].as_str() == Some(laptop_device_id.as_str()))
    );
    run_cli_json([
        "sync",
        "once",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
    ])?;
    run_cli_json([
        "contact",
        "import-identity",
        "--profile",
        &laptop_profile.to_string_lossy(),
        &ctx.temp_root
            .path()
            .join("alice-identity.json")
            .to_string_lossy(),
    ])?;

    Ok(CliLaptopContext {
        laptop_profile,
        laptop_device_id,
        merged_identity_path,
    })
}

fn export_identity_bundle_to_path(root: &Path, profile: &Path, name: &str) -> Result<PathBuf> {
    let output = root.join(name);
    let exported = run_cli_json([
        "profile",
        "export-identity",
        "--profile",
        &profile.to_string_lossy(),
        "--out",
        &output.to_string_lossy(),
    ])?;
    assert_eq!(
        required_str(&exported, "written")?,
        output.to_string_lossy()
    );
    Ok(output)
}

fn merge_identity_bundles(
    deployment: &DeploymentBundle,
    signer_profile: &Path,
    bundles: &[IdentityBundle],
) -> Result<IdentityBundle> {
    let local_identity: LocalIdentityState = snapshot_local_identity(&read_json_file::<Value>(
        &signer_profile.join("snapshot.json"),
    )?)?;
    let deployment = concrete_deployment_bundle(deployment, &local_identity.user_identity.user_id);
    let mut devices = Vec::new();
    for bundle in bundles {
        devices.extend(bundle.devices.clone());
    }
    Ok(IdentityManager::export_identity_bundle_with_devices(
        &local_identity,
        &deployment,
        devices,
    )?)
}

fn concrete_deployment_bundle(bundle: &DeploymentBundle, user_id: &str) -> DeploymentBundle {
    let mut concrete = bundle.clone();
    let encoded_user_id = urlencoding::encode(user_id).into_owned();
    if let Some(reference) = concrete.runtime_config.identity_bundle_ref.as_mut() {
        *reference = reference.replace("{userId}", &encoded_user_id);
    }
    if let Some(reference) = concrete.runtime_config.device_status_ref.as_mut() {
        *reference = reference.replace("{userId}", &encoded_user_id);
    }
    concrete
}

fn snapshot_local_identity(snapshot: &Value) -> Result<LocalIdentityState> {
    serde_json::from_value(snapshot["snapshot"]["local_identity"]["state"].clone())
        .context("decode local identity from snapshot")
}

fn snapshot_sync_state<'a>(snapshot: &'a Value, device_id: &str) -> Result<&'a Value> {
    snapshot["snapshot"]["sync_states"]
        .as_array()
        .context("snapshot sync states missing")?
        .iter()
        .find(|row| row["device_id"].as_str() == Some(device_id))
        .map(|row| &row["state"]["checkpoint"])
        .context("sync state for device missing")
}

fn snapshot_has_recovery_context(profile: &Path, conversation_id: &str) -> Result<bool> {
    let snapshot: Value = read_json_file(&profile.join("snapshot.json"))?;
    Ok(snapshot["snapshot"]["recovery_contexts"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .any(|row| row["conversation_id"].as_str() == Some(conversation_id))
        })
        .unwrap_or(false))
}

fn snapshot_has_conversation(profile: &Path, conversation_id: &str) -> Result<bool> {
    let snapshot: Value = read_json_file(&profile.join("snapshot.json"))?;
    Ok(snapshot["snapshot"]["conversations"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .any(|row| row["conversation_id"].as_str() == Some(conversation_id))
        })
        .unwrap_or(false))
}

fn patch_profile_local_bundle(profile: &Path, bundle: &IdentityBundle) -> Result<()> {
    let mut snapshot: Value = read_json_file(&profile.join("snapshot.json"))?;
    snapshot["snapshot"]["deployment"]["local_bundle"] = serde_json::to_value(bundle)?;
    fs::write(
        profile.join("snapshot.json"),
        serde_json::to_vec_pretty(&snapshot)?,
    )?;
    Ok(())
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
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn runtime_bootstrap_device_bundle(
    runtime: &CloudflareRuntimeHandle,
    user_id: &str,
    device_id: &str,
) -> Result<DeploymentBundle> {
    with_tokio(|| async { runtime.bootstrap_device_bundle(user_id, device_id).await })
}

fn runtime_put_allowlist(
    runtime: &CloudflareRuntimeHandle,
    auth: &DeviceRuntimeAuth,
    allowed_sender_user_ids: &[String],
) -> Result<()> {
    with_tokio(|| async { runtime.put_allowlist(auth, allowed_sender_user_ids).await })
}
fn runtime_put_identity_bundle(
    runtime: &CloudflareRuntimeHandle,
    auth: &DeviceRuntimeAuth,
    bundle: &IdentityBundle,
) -> Result<()> {
    with_tokio(|| async { runtime.put_identity_bundle(auth, bundle).await })
}

fn runtime_list_message_requests(
    runtime: &CloudflareRuntimeHandle,
    auth: &DeviceRuntimeAuth,
) -> Result<Vec<RuntimeMessageRequest>> {
    with_tokio(|| async { runtime.list_message_requests(auth).await })
}

fn runtime_accept_message_request(
    runtime: &CloudflareRuntimeHandle,
    auth: &DeviceRuntimeAuth,
    request_id: &str,
) -> Result<()> {
    with_tokio(|| async { runtime.accept_message_request(auth, request_id).await })
}
fn runtime_get_identity_bundle(
    runtime: &CloudflareRuntimeHandle,
    user_id: &str,
) -> Result<IdentityBundle> {
    with_tokio(|| async { runtime.get_identity_bundle(user_id).await })
}

fn runtime_get_head(
    runtime: &CloudflareRuntimeHandle,
    auth: &DeviceRuntimeAuth,
    device_id: &str,
) -> Result<u64> {
    with_tokio(|| async { Ok(runtime.get_head(auth, device_id).await?.head_seq) })
}

fn wait_for_runtime_cleanup(
    runtime: &CloudflareRuntimeHandle,
    auth: &DeviceRuntimeAuth,
    device_id: &str,
    from_seq: u64,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let records = with_tokio(|| async {
            Ok(runtime
                .fetch_messages(auth, device_id, from_seq, 100)
                .await?
                .records)
        })?;
        if records.is_empty() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    bail!("runtime cleanup did not remove acked records in time")
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

fn stop_pid_and_wait(pid: u32) -> Result<()> {
    #[cfg(windows)]
    {
        let output = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .output()
            .context("run taskkill for cli e2e runtime")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let detail = stderr.trim();
            let combined = if detail.is_empty() {
                stdout.trim().to_string()
            } else {
                detail.to_string()
            };
            let lower = combined.to_ascii_lowercase();
            if !(lower.contains("not found")
                || lower.contains("no running instance")
                || combined.contains("找不到")
                || combined.contains("没有运行的任务"))
            {
                bail!("taskkill failed for pid {pid}: {combined}");
            }
        }
    }
    #[cfg(not(windows))]
    {
        let output = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .output()
            .context("run kill for cli e2e runtime")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let detail = stderr.trim();
            if !(detail.contains("No such process") || stdout.contains("No such process")) {
                let combined = if detail.is_empty() {
                    stdout.trim().to_string()
                } else {
                    detail.to_string()
                };
                bail!("kill failed for pid {pid}: {combined}");
            }
        }
    }
    wait_for_pid_exit(pid, Duration::from_secs(15))
}

fn wait_for_pid_exit(pid: u32, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !pid_is_running(pid)? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    bail!("process {pid} did not exit in time")
}

fn pid_is_running(pid: u32) -> Result<bool> {
    #[cfg(windows)]
    {
        let output = Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}")])
            .output()
            .context("run tasklist for cli e2e runtime")?;
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
            .context("run kill -0 for cli e2e runtime")?;
        Ok(output.status.success())
    }
}

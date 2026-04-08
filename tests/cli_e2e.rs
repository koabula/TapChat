use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;
use tapchat_core::identity::{IdentityManager, LocalIdentityState};
use tapchat_core::model::{
    CapabilityOperation, CapabilityService, DeploymentBundle, DeliveryClass, DeviceRuntimeAuth,
    Envelope, IdentityBundle, InboxAppendCapability, MessageType, SenderProof,
};
use tapchat_core::transport_contract::AppendEnvelopeRequest;
use tapchat_transport_adapter::{
    CloudflareRuntimeHandle, CloudflareRuntimeOptions, RuntimeMessageRequest,
};
use tempfile::{Builder, TempDir};

const ALICE_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const BOB_MNEMONIC: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";
const ORCHESTRATED_CASE_TIMEOUT: Duration = Duration::from_secs(180);

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
fn cli_e2e_stable_suite() -> Result<()> {
    for test_name in [
        "cleanup_test_temp_script_removes_cli_temp_artifacts",
        "cli_attachment_restart_and_delayed_recovery_work",
        "cli_cleanup_after_ack_keeps_checkpoint_monotonic",
        "cli_cleanup_recovery_remains_idempotent_across_repeated_sync",
        "cli_contact_request_and_allowlist_commands_work",
        "cli_device_revoke_missing_target_returns_stable_error",
        "cli_device_revoke_remote_target_updates_published_bundle",
        "cli_direct_message_and_attachment_e2e_work",
        "cli_explicit_needs_rebuild_control_e2e_work",
        "cli_identity_refresh_retry_exhausted_e2e_work",
        "cli_message_request_accept_flow_works",
        "cli_needs_rebuild_surfaces_escalation_reason_e2e_work",
        "cli_profile_registry_and_cloudflare_provision_auto_work",
        "cli_realtime_out_of_order_or_duplicate_delivery_e2e_work",
        "cli_rebuild_command_surfaces_stable_escalation_reason_e2e_work",
        "cli_recovery_policy_exhausted_e2e_work",
        "cli_repeated_realtime_and_sync_do_not_duplicate_delivery_e2e_work",
        "cli_revoke_with_delayed_sync_keeps_revoked_device_isolated",
        "cli_runtime_local_start_accepts_explicit_workspace_root",
        "cli_runtime_local_start_discovers_workspace_from_binary_outside_repo_cwd",
        "cli_runtime_local_start_stop_and_status_work",
        "cli_sender_policy_and_recovery_status_remain_consistent_e2e_work",
        "cli_sender_policy_identity_refresh_and_reconcile_do_not_overclaim_delivery_e2e_work",
    ] {
        run_orchestrated_cli_case(test_name)?;
    }
    Ok(())
}

#[test]
#[ignore = "orchestrated by cli_e2e_stable_suite"]
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
#[ignore = "orchestrated by cli_e2e_stable_suite"]
fn cli_profile_registry_and_cloudflare_provision_auto_work() -> Result<()> {
    let _guard = test_lock();
    let workspace_root = workspace_root();
    let runtime = runtime_handle(&workspace_root)?;
    let temp_root = repo_temp_dir("cloudflare-provision-auto")?;
    let registry_path = temp_root.path().join("device-profiles.json");
    let alice_profile = temp_root.path().join("alice");
    let bob_profile = temp_root.path().join("bob");

    let registry_env = registry_path.to_string_lossy().to_string();

    run_cli_json_with_env(
        [("TAPCHAT_PROFILE_REGISTRY_PATH", registry_env.as_str())],
        [
            "profile",
            "init",
            "--name",
            "alice",
            "--root",
            &alice_profile.to_string_lossy(),
        ],
    )?;
    run_cli_json_with_env(
        [("TAPCHAT_PROFILE_REGISTRY_PATH", registry_env.as_str())],
        [
            "profile",
            "init",
            "--name",
            "bob",
            "--root",
            &bob_profile.to_string_lossy(),
        ],
    )?;

    let listed = run_cli_json_with_env(
        [("TAPCHAT_PROFILE_REGISTRY_PATH", registry_env.as_str())],
        ["profile", "list"],
    )?;
    assert_eq!(listed["profiles"].as_array().map(|value| value.len()), Some(2));
    assert_eq!(
        listed["active_profile"].as_str(),
        Some(alice_profile.to_string_lossy().as_ref())
    );

    run_cli_json_with_env(
        [("TAPCHAT_PROFILE_REGISTRY_PATH", registry_env.as_str())],
        ["profile", "activate", "--profile", &bob_profile.to_string_lossy()],
    )?;
    let current = run_cli_json_with_env(
        [("TAPCHAT_PROFILE_REGISTRY_PATH", registry_env.as_str())],
        ["profile", "current"],
    )?;
    assert_eq!(current["name"].as_str(), Some("bob"));
    assert_eq!(
        current["root_dir"].as_str(),
        Some(bob_profile.to_string_lossy().as_ref())
    );

    let identity = run_cli_json_with_env(
        [("TAPCHAT_PROFILE_REGISTRY_PATH", registry_env.as_str())],
        [
            "device",
            "create",
            "--profile",
            &alice_profile.to_string_lossy(),
            "--device-name",
            "phone",
        ],
    )?;
    let user_id = required_str(&identity, "user_id")?;
    let device_id = required_str(&identity, "device_id")?;

    let deploy_stub = serde_json::json!({
        "success": true,
        "worker_name": "tapchat-test-worker",
        "deploy_url": runtime.base_url(),
        "effective_public_base_url": runtime.base_url(),
        "bucket_name": "tapchat-test-worker-storage",
        "preview_bucket_name": "tapchat-test-worker-storage-preview",
        "deployment_region": "global",
        "generated_secrets": {
            "sharing_token_secret": false,
            "bootstrap_token_secret": false
        },
        "mode": "stub"
    })
    .to_string();
    let bootstrap_secret = runtime.bootstrap_secret().to_string();

    let provisioned = run_cli_json_with_env(
        [
            ("TAPCHAT_PROFILE_REGISTRY_PATH", registry_env.as_str()),
            ("TAPCHAT_CLOUDFLARE_DEPLOY_STUB_RESULT", deploy_stub.as_str()),
            ("TAPCHAT_CLOUDFLARE_BOOTSTRAP_SECRET", bootstrap_secret.as_str()),
        ],
        [
            "runtime",
            "cloudflare",
            "provision",
            "auto",
            "--profile",
            &alice_profile.to_string_lossy(),
        ],
    )?;
    assert_eq!(provisioned["provisioned"], Value::Bool(true));
    assert_eq!(provisioned["mode"].as_str(), Some("cloudflare"));
    assert_eq!(provisioned["user_id"].as_str(), Some(user_id.as_str()));
    assert_eq!(provisioned["device_id"].as_str(), Some(device_id.as_str()));

    let status = run_cli_json_with_env(
        [("TAPCHAT_PROFILE_REGISTRY_PATH", registry_env.as_str())],
        [
            "runtime",
            "cloudflare",
            "status",
            "--profile",
            &alice_profile.to_string_lossy(),
        ],
    )?;
    assert_eq!(status["mode"].as_str(), Some("cloudflare"));
    assert_eq!(status["deployment_bound"], Value::Bool(true));
    assert_eq!(status["worker_name"].as_str(), Some("tapchat-test-worker"));
    assert_eq!(status["public_base_url"].as_str(), Some(runtime.base_url()));

    run_cli_json_with_env(
        [("TAPCHAT_PROFILE_REGISTRY_PATH", registry_env.as_str())],
        ["profile", "activate", "--name", "alice"],
    )?;
    let device_status = run_cli_json_with_env(
        [("TAPCHAT_PROFILE_REGISTRY_PATH", registry_env.as_str())],
        ["device", "status"],
    )?;
    assert_eq!(device_status["user_id"].as_str(), Some(user_id.as_str()));
    assert_eq!(device_status["device_id"].as_str(), Some(device_id.as_str()));

    let redeployed = run_cli_json_with_env(
        [
            ("TAPCHAT_PROFILE_REGISTRY_PATH", registry_env.as_str()),
            ("TAPCHAT_CLOUDFLARE_DEPLOY_STUB_RESULT", deploy_stub.as_str()),
        ],
        [
            "runtime",
            "cloudflare",
            "redeploy",
            "--profile",
            &alice_profile.to_string_lossy(),
        ],
    )?;
    assert_eq!(redeployed["provisioned"], Value::Bool(true));

    let rotated = run_cli_json_with_env(
        [
            ("TAPCHAT_PROFILE_REGISTRY_PATH", registry_env.as_str()),
            ("TAPCHAT_CLOUDFLARE_DEPLOY_STUB_RESULT", deploy_stub.as_str()),
            ("TAPCHAT_CLOUDFLARE_BOOTSTRAP_SECRET", bootstrap_secret.as_str()),
        ],
        [
            "runtime",
            "cloudflare",
            "rotate-secrets",
            "--profile",
            &alice_profile.to_string_lossy(),
        ],
    )?;
    assert_eq!(rotated["provisioned"], Value::Bool(true));

    let detached = run_cli_json_with_env(
        [("TAPCHAT_PROFILE_REGISTRY_PATH", registry_env.as_str())],
        [
            "runtime",
            "cloudflare",
            "detach",
            "--profile",
            &alice_profile.to_string_lossy(),
        ],
    )?;
    assert_eq!(detached["detached"], Value::Bool(true));

    let detached_status = run_cli_json_with_env(
        [("TAPCHAT_PROFILE_REGISTRY_PATH", registry_env.as_str())],
        [
            "runtime",
            "cloudflare",
            "status",
            "--profile",
            &alice_profile.to_string_lossy(),
        ],
    )?;
    assert!(detached_status["mode"].is_null());
    assert_eq!(detached_status["deployment_bound"], Value::Bool(false));

    let removed = run_cli_json_with_env(
        [("TAPCHAT_PROFILE_REGISTRY_PATH", registry_env.as_str())],
        ["profile", "remove", "--profile", &bob_profile.to_string_lossy()],
    )?;
    assert_eq!(removed["removed"], Value::Bool(true));

    Ok(())
}

#[test]
#[ignore = "orchestrated by cli_e2e_stable_suite"]
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
#[ignore = "orchestrated by cli_e2e_stable_suite"]
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
    assert_append_result(&first_send, "message_request", true, Some(true))?;
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
    assert_append_result(&second_send, "rejected", true, None)?;
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
#[ignore = "orchestrated by cli_e2e_stable_suite"]
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
    assert_append_result(&third_send, "inbox", true, None)?;
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
    assert_append_result(&bob_messages_after_recovery, "inbox", true, None)?;
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
#[ignore = "orchestrated by cli_e2e_stable_suite"]
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
    assert_append_result(&first_send, "message_request", true, Some(true))?;
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
    assert_append_result(&second_send, "rejected", true, None)?;
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
    assert_append_result(&fourth_send, "inbox", true, None)?;
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
#[ignore = "orchestrated by cli_e2e_stable_suite"]
fn cli_needs_rebuild_surfaces_escalation_reason_e2e_work() -> Result<()> {
    let _guard = test_lock();
    let ctx = setup_cli_pair("needs-rebuild-escalation")?;

    let baseline_send = run_cli_json([
        "message",
        "send-text",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
        "--text",
        "before corruption",
    ])?;
    assert_append_result(&baseline_send, "inbox", true, None)?;
    let baseline_sync = sync_once(&ctx.bob_profile)?;
    let baseline_acked = required_u64(&baseline_sync["checkpoint"], "last_acked_seq")?;
    assert!(baseline_acked > 0);

    corrupt_first_mls_state(&ctx.alice_profile)?;

    let alice_show = conversation_show(&ctx.alice_profile, &ctx.conversation_id)?;
    assert_conversation_show_needs_rebuild(&alice_show, "mls_marked_unrecoverable")?;
    let alice_status = run_cli_json([
        "sync",
        "status",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
    ])?;
    let rebuild_phase = assert_recovery_conversation_matches(
        &alice_status,
        &ctx.conversation_id,
        &["NeedsRebuild"],
        &["missing_commit"],
        &["escalated_to_rebuild"],
        Some(true),
    )?;
    assert_eq!(rebuild_phase, "escalated_to_rebuild");
    assert_eq!(
        find_recovery_conversation(&alice_status, &ctx.conversation_id)?["escalation_reason"]
            .as_str(),
        Some("mls_marked_unrecoverable")
    );

    let rebuilt = run_cli_json([
        "conversation",
        "rebuild",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;
    assert_eq!(rebuilt["rebuilt"], Value::Bool(true));

    run_cli_json([
        "device",
        "rotate-key-package",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
    ])?;
    publish_identity_bundle_for_profile(
        ctx.temp_root.path(),
        &ctx.runtime,
        bundle_auth(&ctx.bob_bundle)?,
        &ctx.bob_profile,
        "bob-post-rebuild-identity.json",
    )?;
    run_cli_json([
        "contact",
        "refresh",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--user-id",
        &ctx.bob_user_id,
    ])?;

    let mut last_acked = baseline_acked;
    for _ in 0..4 {
        run_cli_json([
            "conversation",
            "reconcile",
            "--profile",
            &ctx.alice_profile.to_string_lossy(),
            "--conversation-id",
            &ctx.conversation_id,
        ])?;
        let sync = sync_once(&ctx.bob_profile)?;
        let acked = required_u64(&sync["checkpoint"], "last_acked_seq")?;
        assert!(acked >= last_acked);
        last_acked = acked;
        if conversation_recovery_status(&ctx.alice_profile, &ctx.conversation_id)?.as_deref()
            == Some("Healthy")
        {
            break;
        }
    }

    let healed_show = conversation_show(&ctx.alice_profile, &ctx.conversation_id)?;
    assert_conversation_show_healthy(&healed_show);
    let healed_status = run_cli_json([
        "sync",
        "status",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
    ])?;
    assert!(recovery_conversations(&healed_status)?.is_empty());

    let after_send = run_cli_json([
        "message",
        "send-text",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
        "--text",
        "after rebuild",
    ])?;
    assert_append_result(&after_send, "inbox", true, None)?;
    let final_sync = sync_once(&ctx.bob_profile)?;
    let final_acked = required_u64(&final_sync["checkpoint"], "last_acked_seq")?;
    assert!(final_acked >= last_acked);
    let bob_messages = run_cli_json([
        "message",
        "list",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;
    assert_eq!(count_plaintext_messages(&bob_messages, "after rebuild"), 1);

    Ok(())
}

#[test]
#[ignore = "orchestrated by cli_e2e_stable_suite"]
fn cli_rebuild_command_surfaces_stable_escalation_reason_e2e_work() -> Result<()> {
    let _guard = test_lock();
    let ctx = setup_cli_pair("rebuild-policy-exhausted")?;

    let baseline_send = run_cli_json([
        "message",
        "send-text",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
        "--text",
        "before policy exhausted rebuild",
    ])?;
    assert_append_result(&baseline_send, "inbox", true, None)?;
    let baseline_sync = sync_once(&ctx.bob_profile)?;
    let mut last_acked = required_u64(&baseline_sync["checkpoint"], "last_acked_seq")?;

    let rebuilt = run_cli_json([
        "conversation",
        "rebuild",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;
    assert_eq!(rebuilt["rebuilt"], Value::Bool(true));

    let alice_show = conversation_show(&ctx.alice_profile, &ctx.conversation_id)?;
    assert_conversation_show_needs_rebuild(&alice_show, "recovery_policy_exhausted")?;
    let alice_status = run_cli_json([
        "sync",
        "status",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
    ])?;
    assert_recovery_conversation_matches(
        &alice_status,
        &ctx.conversation_id,
        &["NeedsRebuild"],
        &["identity_changed", "missing_commit"],
        &["escalated_to_rebuild"],
        Some(true),
    )?;
    assert_eq!(
        find_recovery_conversation(&alice_status, &ctx.conversation_id)?["escalation_reason"]
            .as_str(),
        Some("recovery_policy_exhausted")
    );

    run_cli_json([
        "device",
        "rotate-key-package",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
    ])?;
    publish_identity_bundle_for_profile(
        ctx.temp_root.path(),
        &ctx.runtime,
        bundle_auth(&ctx.bob_bundle)?,
        &ctx.bob_profile,
        "bob-post-policy-rebuild-identity.json",
    )?;
    run_cli_json([
        "contact",
        "refresh",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--user-id",
        &ctx.bob_user_id,
    ])?;

    for _ in 0..4 {
        run_cli_json([
            "conversation",
            "reconcile",
            "--profile",
            &ctx.alice_profile.to_string_lossy(),
            "--conversation-id",
            &ctx.conversation_id,
        ])?;
        let sync = sync_once(&ctx.bob_profile)?;
        let acked = required_u64(&sync["checkpoint"], "last_acked_seq")?;
        assert!(acked >= last_acked);
        last_acked = acked;
        if conversation_recovery_status(&ctx.alice_profile, &ctx.conversation_id)?.as_deref()
            == Some("Healthy")
        {
            break;
        }
    }

    let healed_show = conversation_show(&ctx.alice_profile, &ctx.conversation_id)?;
    assert_conversation_show_healthy(&healed_show);
    let healed_status = run_cli_json([
        "sync",
        "status",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
    ])?;
    assert!(recovery_conversations(&healed_status)?.is_empty());

    let after_send = run_cli_json([
        "message",
        "send-text",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
        "--text",
        "after stable rebuild escalation",
    ])?;
    assert_append_result(&after_send, "inbox", true, None)?;
    let final_sync = sync_once(&ctx.bob_profile)?;
    let final_acked = required_u64(&final_sync["checkpoint"], "last_acked_seq")?;
    assert!(final_acked >= last_acked);
    let bob_messages = run_cli_json([
        "message",
        "list",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;
    assert_eq!(
        count_plaintext_messages(&bob_messages, "after stable rebuild escalation"),
        1
    );

    Ok(())
}

#[test]
#[ignore = "orchestrated by cli_e2e_stable_suite"]
fn cli_realtime_out_of_order_or_duplicate_delivery_e2e_work() -> Result<()> {
    let _guard = test_lock();
    let ctx = setup_cli_pair("realtime-duplicate-delivery")?;
    let _realtime = RealtimeConnectGuard::spawn(&ctx.bob_profile)?;

    let first_send = run_cli_json([
        "message",
        "send-text",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
        "--text",
        "duplicate realtime delivery",
    ])?;
    assert_append_result(&first_send, "inbox", true, None)?;

    let first_sync = sync_once(&ctx.bob_profile)?;
    let first_acked = required_u64(&first_sync["checkpoint"], "last_acked_seq")?;
    let second_sync = sync_once(&ctx.bob_profile)?;
    let second_acked = required_u64(&second_sync["checkpoint"], "last_acked_seq")?;
    assert!(second_acked >= first_acked);

    let messages = run_cli_json([
        "message",
        "list",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;
    assert_eq!(count_plaintext_messages(&messages, "duplicate realtime delivery"), 1);

    let show = conversation_show(&ctx.bob_profile, &ctx.conversation_id)?;
    assert_conversation_show_healthy(&show);
    let status = run_cli_json([
        "sync",
        "status",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
    ])?;
    assert!(recovery_conversations(&status)?.is_empty());
    Ok(())
}

#[test]
#[ignore = "orchestrated by cli_e2e_stable_suite"]
fn cli_explicit_needs_rebuild_control_e2e_work() -> Result<()> {
    let _guard = test_lock();
    let ctx = setup_cli_pair("explicit-needs-rebuild-control")?;

    append_runtime_control_message(
        &ctx.runtime,
        &ctx.alice_device_id,
        &ctx.conversation_id,
        &ctx.bob_user_id,
        &ctx.bob_device_id,
        MessageType::ControlConversationNeedsRebuild,
        "explicit rebuild control",
    )?;
    let fetched = with_tokio(|| async {
        ctx.runtime
            .fetch_messages(bundle_auth(&ctx.alice_bundle)?, &ctx.alice_device_id, 1, 20)
            .await
    })?;
    assert!(
        fetched.records.iter().any(|record| {
            record.envelope.message_type == MessageType::ControlConversationNeedsRebuild
        }),
        "expected runtime inbox to contain control_conversation_needs_rebuild"
    );
    let sync = sync_once(&ctx.alice_profile)?;
    assert!(
        required_u64(&sync["checkpoint"], "last_acked_seq")? > 0,
        "explicit rebuild control should advance acked seq"
    );

    let show = conversation_show(&ctx.alice_profile, &ctx.conversation_id)?;
    assert_conversation_show_needs_rebuild(&show, "explicit_needs_rebuild_control")?;
    let status = run_cli_json([
        "sync",
        "status",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
    ])?;
    let phase = assert_recovery_conversation_matches(
        &status,
        &ctx.conversation_id,
        &["NeedsRebuild"],
        &["identity_changed"],
        &["escalated_to_rebuild"],
        Some(true),
    )?;
    assert_eq!(phase, "escalated_to_rebuild");
    assert_eq!(
        find_recovery_conversation(&status, &ctx.conversation_id)?["escalation_reason"].as_str(),
        Some("explicit_needs_rebuild_control")
    );
    assert_recovery_contract_alignment(&ctx.alice_profile, &ctx.conversation_id, &show, &status)?;
    Ok(())
}

#[test]
#[ignore = "orchestrated by cli_e2e_stable_suite"]
fn cli_identity_refresh_retry_exhausted_e2e_work() -> Result<()> {
    let _guard = test_lock();
    let ctx = setup_cli_pair("identity-refresh-retry-exhausted")?;
    let _laptop = start_bob_laptop_recovery(&ctx)?;

    let initial_show = conversation_show(&ctx.alice_profile, &ctx.conversation_id)?;
    let initial_phase = assert_recovery_conversation_from_show(
        &initial_show,
        &["NeedsRecovery", "NeedsRebuild"],
        &["identity_changed", "membership_changed"],
        &["waiting_for_explicit_reconcile", "escalated_to_rebuild"],
        None,
    )?;
    assert_eq!(initial_phase, "waiting_for_explicit_reconcile");

    patch_contact_identity_bundle_ref(
        &ctx.alice_profile,
        &ctx.bob_user_id,
        "http://127.0.0.1:1/identity-bundle-unreachable",
    )?;

    run_cli_json([
        "contact",
        "refresh",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--user-id",
        &ctx.bob_user_id,
    ])?;

    let show = conversation_show(&ctx.alice_profile, &ctx.conversation_id)?;
    assert_conversation_show_needs_rebuild(&show, "identity_refresh_retry_exhausted")?;
    assert_eq!(
        show["recovery"]["phase"].as_str(),
        Some("escalated_to_rebuild")
    );
    assert!(
        show["recovery"]["identity_refresh_retry_count"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );
    let status = run_cli_json([
        "sync",
        "status",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
    ])?;
    assert_eq!(
        find_recovery_conversation(&status, &ctx.conversation_id)?["escalation_reason"].as_str(),
        Some("identity_refresh_retry_exhausted")
    );
    assert_recovery_contract_alignment(&ctx.alice_profile, &ctx.conversation_id, &show, &status)?;
    Ok(())
}

#[test]
#[ignore = "orchestrated by cli_e2e_stable_suite"]
fn cli_recovery_policy_exhausted_e2e_work() -> Result<()> {
    let _guard = test_lock();
    let ctx = setup_cli_pair("recovery-policy-exhausted")?;

    let rebuilt = run_cli_json([
        "conversation",
        "rebuild",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;
    assert_eq!(rebuilt["rebuilt"], Value::Bool(true));

    let show = conversation_show(&ctx.alice_profile, &ctx.conversation_id)?;
    assert_conversation_show_needs_rebuild(&show, "recovery_policy_exhausted")?;
    let status = run_cli_json([
        "sync",
        "status",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
    ])?;
    assert_eq!(
        find_recovery_conversation(&status, &ctx.conversation_id)?["escalation_reason"].as_str(),
        Some("recovery_policy_exhausted")
    );
    assert_recovery_contract_alignment(&ctx.alice_profile, &ctx.conversation_id, &show, &status)?;
    Ok(())
}

#[test]
#[ignore = "orchestrated by cli_e2e_stable_suite"]
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
#[ignore = "orchestrated by cli_e2e_stable_suite"]
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
#[ignore = "orchestrated by cli_e2e_stable_suite"]
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
#[ignore = "orchestrated by cli_e2e_stable_suite"]
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
#[ignore = "orchestrated by cli_e2e_stable_suite"]
fn cli_direct_message_and_attachment_e2e_work() -> Result<()> {
    let _guard = test_lock();
    let ctx = setup_cli_pair("direct")?;

    let text_send = run_cli_json([
        "message",
        "send-text",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
        "--text",
        "hello from cli e2e",
    ])?;
    assert_append_result(&text_send, "inbox", true, None)?;
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
    assert_append_result(&attachment_send, "inbox", true, None)?;

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
#[ignore = "stress"]
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
#[ignore = "stress"]
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
#[ignore = "orchestrated by cli_e2e_stable_suite"]
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
#[ignore = "orchestrated by cli_e2e_stable_suite"]
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
#[ignore = "orchestrated by cli_e2e_stable_suite"]
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
#[ignore = "stress"]
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
#[ignore = "orchestrated by cli_e2e_stable_suite"]
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
#[ignore = "stress"]
fn cli_multi_device_restart_rebuild_and_repeated_sync_remain_consistent_e2e_work() -> Result<()> {
    let _guard = test_lock();
    let ctx = setup_cli_pair("multi-device-restart-rebuild")?;
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

    let pre_rebuild_send = run_cli_json([
        "message",
        "send-text",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
        "--text",
        "before multi device rebuild",
    ])?;
    assert_append_result(&pre_rebuild_send, "inbox", true, None)?;
    let laptop_sync_before = sync_once(&laptop.laptop_profile)?;
    let baseline_acked = required_u64(&laptop_sync_before["checkpoint"], "last_acked_seq")?;
    assert!(baseline_acked > 0);

    corrupt_first_mls_state(&ctx.alice_profile)?;
    let rebuild_show = conversation_show(&ctx.alice_profile, &ctx.conversation_id)?;
    assert_conversation_show_needs_rebuild(&rebuild_show, "mls_marked_unrecoverable")?;

    let rebuild_cmd = run_cli_json([
        "conversation",
        "rebuild",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;
    assert_eq!(rebuild_cmd["rebuilt"], Value::Bool(true));

    run_cli_json([
        "device",
        "rotate-key-package",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
    ])?;
    run_cli_json([
        "device",
        "rotate-key-package",
        "--profile",
        &laptop.laptop_profile.to_string_lossy(),
    ])?;
    let merged_identity = publish_merged_identity_bundle_for_profiles(
        ctx.temp_root.path(),
        &ctx.runtime,
        bundle_auth(&ctx.bob_bundle)?,
        &ctx.bob_bundle,
        &ctx.bob_profile,
        &[
            (&ctx.bob_profile, "bob-phone-post-rebuild-identity.json"),
            (&laptop.laptop_profile, "bob-laptop-post-rebuild-identity.json"),
        ],
    )?;
    patch_profile_local_bundle(&laptop.laptop_profile, &merged_identity)?;
    run_cli_json([
        "contact",
        "refresh",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--user-id",
        &ctx.bob_user_id,
    ])?;

    let sync_after_rebuild_one = sync_once(&ctx.bob_profile)?;
    let phone_acked_after_one =
        required_u64(&sync_after_rebuild_one["checkpoint"], "last_acked_seq")?;
    let phone_sync_after_rebuild_two = sync_once(&ctx.bob_profile)?;
    let phone_acked_after_two =
        required_u64(&phone_sync_after_rebuild_two["checkpoint"], "last_acked_seq")?;
    assert!(phone_acked_after_two >= phone_acked_after_one);

    let sync_after_rebuild_one = sync_once(&laptop.laptop_profile)?;
    let acked_after_one =
        required_u64(&sync_after_rebuild_one["checkpoint"], "last_acked_seq")?;
    let sync_after_rebuild_two = sync_once(&laptop.laptop_profile)?;
    let acked_after_two =
        required_u64(&sync_after_rebuild_two["checkpoint"], "last_acked_seq")?;
    assert!(acked_after_two >= acked_after_one);

    for _ in 0..4 {
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
        let phone_sync_one = sync_once(&ctx.bob_profile)?;
        let phone_sync_two = sync_once(&ctx.bob_profile)?;
        let phone_seq_one = required_u64(&phone_sync_one["checkpoint"], "last_acked_seq")?;
        let phone_seq_two = required_u64(&phone_sync_two["checkpoint"], "last_acked_seq")?;
        assert!(phone_seq_two >= phone_seq_one);
        let laptop_sync_one = sync_once(&laptop.laptop_profile)?;
        let laptop_sync_two = sync_once(&laptop.laptop_profile)?;
        let laptop_seq_one = required_u64(&laptop_sync_one["checkpoint"], "last_acked_seq")?;
        let laptop_seq_two = required_u64(&laptop_sync_two["checkpoint"], "last_acked_seq")?;
        assert!(laptop_seq_two >= laptop_seq_one);
        if conversation_recovery_status(&ctx.alice_profile, &ctx.conversation_id)?.as_deref()
            == Some("Healthy")
        {
            break;
        }
    }

    let final_alice_show = conversation_show(&ctx.alice_profile, &ctx.conversation_id)?;
    assert_conversation_show_healthy(&final_alice_show);
    let final_alice_status = run_cli_json([
        "sync",
        "status",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
    ])?;
    assert!(recovery_conversations(&final_alice_status)?.is_empty());

    let post_rebuild_send = run_cli_json([
        "message",
        "send-text",
        "--profile",
        &ctx.alice_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
        "--text",
        "after multi device rebuild",
    ])?;
    assert_append_result(&post_rebuild_send, "inbox", true, None)?;
    let final_phone_sync_one = sync_once(&ctx.bob_profile)?;
    let final_phone_sync_two = sync_once(&ctx.bob_profile)?;
    let final_phone_seq_one =
        required_u64(&final_phone_sync_one["checkpoint"], "last_acked_seq")?;
    let final_phone_seq_two =
        required_u64(&final_phone_sync_two["checkpoint"], "last_acked_seq")?;
    assert!(final_phone_seq_two >= final_phone_seq_one);
    let final_sync_one = sync_once(&laptop.laptop_profile)?;
    let final_sync_two = sync_once(&laptop.laptop_profile)?;
    let final_seq_one = required_u64(&final_sync_one["checkpoint"], "last_acked_seq")?;
    let final_seq_two = required_u64(&final_sync_two["checkpoint"], "last_acked_seq")?;
    assert!(final_seq_two >= final_seq_one);
    assert!(final_seq_two >= baseline_acked);

    let laptop_messages = run_cli_json([
        "message",
        "list",
        "--profile",
        &laptop.laptop_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;
    assert_eq!(
        count_plaintext_messages(&laptop_messages, "before multi device rebuild"),
        1
    );
    assert_eq!(
        count_plaintext_messages(&laptop_messages, "after multi device rebuild"),
        1
    );
    let bob_messages = run_cli_json([
        "message",
        "list",
        "--profile",
        &ctx.bob_profile.to_string_lossy(),
        "--conversation-id",
        &ctx.conversation_id,
    ])?;
    assert_eq!(
        count_plaintext_messages(&bob_messages, "after multi device rebuild"),
        1
    );

    Ok(())
}

#[test]
#[ignore = "orchestrated by cli_e2e_stable_suite"]
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
#[ignore = "orchestrated by cli_e2e_stable_suite"]
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

struct RealtimeConnectGuard {
    child: Option<Child>,
}

impl RealtimeConnectGuard {
    fn spawn(profile: &Path) -> Result<Self> {
        let mut command = Command::new(binary_path());
        command
            .current_dir(workspace_root())
            .arg("--output")
            .arg("json")
            .args(["sync", "realtime-connect", "--profile"])
            .arg(profile)
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        apply_default_cli_test_env(&mut command)?;
        let mut child = command.spawn().context("spawn tapchat realtime-connect")?;
        thread::sleep(Duration::from_millis(750));
        if let Some(status) = child
            .try_wait()
            .context("poll tapchat realtime-connect process")?
        {
            let output = child
                .wait_with_output()
                .context("collect tapchat realtime-connect output")?;
            bail!(
                "tapchat realtime-connect exited early with status {status}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(Self { child: Some(child) })
    }
}

impl Drop for RealtimeConnectGuard {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = stop_pid_and_wait(child.id());
        let _ = child.wait();
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
    apply_default_cli_test_env(&mut command)?;
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
    apply_default_cli_test_env(&mut command)?;
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
    run_cli_json_with_env(std::iter::empty::<(&str, &str)>(), args)
}

fn run_cli_json_with_env<I, S, K, V>(envs: impl IntoIterator<Item = (K, V)>, args: I) -> Result<Value>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
    K: AsRef<str>,
    V: AsRef<str>,
{
    let mut command = Command::new(binary_path());
    command
        .current_dir(workspace_root())
        .arg("--output")
        .arg("json");
    apply_default_cli_test_env(&mut command)?;
    for (key, value) in envs {
        command.env(key.as_ref(), value.as_ref());
    }
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

fn apply_default_cli_test_env(command: &mut Command) -> Result<()> {
    let registry_path = default_cli_test_registry_path();
    if let Some(parent) = registry_path.parent() {
        fs::create_dir_all(parent)?;
    }
    command.env("TAPCHAT_PROFILE_REGISTRY_PATH", registry_path);
    Ok(())
}

fn default_cli_test_registry_path() -> &'static PathBuf {
    static REGISTRY_PATH: OnceLock<PathBuf> = OnceLock::new();
    REGISTRY_PATH.get_or_init(|| {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        workspace_root()
            .join(".tmp")
            .join(format!("cli-e2e-{}-{millis}.profiles.json", std::process::id()))
    })
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

fn corrupt_first_mls_state(profile: &Path) -> Result<()> {
    let snapshot_path = profile.join("snapshot.json");
    let mut snapshot: Value = read_json_file(&snapshot_path)?;
    let states = snapshot["snapshot"]["mls_states"]
        .as_array_mut()
        .context("snapshot mls_states missing")?;
    let first = states.first_mut().context("missing persisted mls state")?;
    first["serialized_group_state"] = Value::String("{broken".into());
    fs::write(snapshot_path, serde_json::to_vec_pretty(&snapshot)?)?;
    Ok(())
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

fn append_result<'a>(value: &'a Value) -> Result<&'a Value> {
    value.get("append_result")
        .context("append_result missing")?
        .as_object()
        .map(|_| &value["append_result"])
        .context("append_result not object")
}

fn assert_append_result(
    value: &Value,
    delivered_to: &str,
    accepted: bool,
    request_expected: Option<bool>,
) -> Result<()> {
    let result = append_result(value)?;
    assert_eq!(result["accepted"].as_bool(), Some(accepted));
    assert_eq!(result["delivered_to"].as_str(), Some(delivered_to));
    match request_expected {
        Some(expected) => assert_eq!(result["queued_as_request"].as_bool(), Some(expected)),
        None => assert!(
            result["queued_as_request"].as_bool() == Some(false)
                || result["queued_as_request"].is_null()
        ),
    }
    Ok(())
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
    assert!(value["attempt_count"].is_u64());
    assert!(value["identity_refresh_retry_count"].is_u64());
    assert!(value["last_error"].is_null() || value["last_error"].is_string());
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

fn assert_conversation_show_needs_rebuild(
    value: &Value,
    expected_escalation_reason: &str,
) -> Result<()> {
    assert_eq!(value["recovery_status"].as_str(), Some("NeedsRebuild"));
    let recovery = &value["recovery"];
    assert_recovery_object_shape(recovery)?;
    assert_eq!(recovery["phase"].as_str(), Some("escalated_to_rebuild"));
    assert_eq!(
        recovery["escalation_reason"].as_str(),
        Some(expected_escalation_reason)
    );
    Ok(())
}

fn assert_recovery_conversation_from_show(
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
        None,
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

fn snapshot_recovery_context(profile: &Path, conversation_id: &str) -> Result<Option<Value>> {
    let snapshot: Value = read_json_file(&profile.join("snapshot.json"))?;
    Ok(snapshot["snapshot"]["recovery_contexts"]
        .as_array()
        .and_then(|rows| {
            rows.iter()
                .find(|row| row["conversation_id"].as_str() == Some(conversation_id))
                .cloned()
        }))
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

fn patch_contact_identity_bundle_ref(
    profile: &Path,
    user_id: &str,
    reference: &str,
) -> Result<()> {
    let path = profile.join("snapshot.json");
    let mut snapshot: Value = read_json_file(&path)?;
    let contacts = snapshot["snapshot"]["contacts"]
        .as_array_mut()
        .context("snapshot contacts missing")?;
    let contact = contacts
        .iter_mut()
        .find(|row| row["user_id"].as_str() == Some(user_id))
        .context("contact missing in snapshot")?;
    contact["bundle"]["identity_bundle_ref"] = Value::String(reference.to_string());
    fs::write(path, serde_json::to_vec_pretty(&snapshot)?)?;
    Ok(())
}

fn append_runtime_control_message(
    runtime: &CloudflareRuntimeHandle,
    recipient_device_id: &str,
    conversation_id: &str,
    sender_user_id: &str,
    sender_device_id: &str,
    message_type: MessageType,
    payload: &str,
) -> Result<Value> {
    with_tokio(|| async {
        let endpoint = format!(
            "{}/v1/inbox/{}/messages",
            runtime.base_url(),
            urlencoding::encode(recipient_device_id)
        );
        let signature = format!("test-append-capability-{recipient_device_id}");
        let capability = InboxAppendCapability {
            version: tapchat_core::model::CURRENT_MODEL_VERSION.to_string(),
            service: CapabilityService::Inbox,
            user_id: sender_user_id.to_string(),
            target_device_id: recipient_device_id.to_string(),
            endpoint: endpoint.clone(),
            operations: vec![CapabilityOperation::Append],
            conversation_scope: vec![conversation_id.to_string()],
            expires_at: 4_102_444_800_000u64,
            constraints: None,
            signature: signature.clone(),
        };
        let request = AppendEnvelopeRequest {
            version: tapchat_core::model::CURRENT_MODEL_VERSION.to_string(),
            recipient_device_id: recipient_device_id.to_string(),
            sender_bundle_share_url: None,
            sender_bundle_hash: None,
            sender_display_name: None,
            envelope: Envelope {
                version: tapchat_core::model::CURRENT_MODEL_VERSION.to_string(),
                message_id: format!(
                    "msg:{conversation_id}:{}:{recipient_device_id}",
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .context("system clock before unix epoch")?
                        .as_millis()
                ),
                conversation_id: conversation_id.to_string(),
                sender_user_id: sender_user_id.to_string(),
                sender_device_id: sender_device_id.to_string(),
                recipient_device_id: recipient_device_id.to_string(),
                created_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .context("system clock before unix epoch")?
                    .as_millis() as u64,
                message_type,
                inline_ciphertext: Some(payload.to_string()),
                storage_refs: vec![],
                delivery_class: DeliveryClass::Normal,
                wake_hint: None,
                sender_proof: SenderProof {
                    proof_type: "signature".into(),
                    value: "proof".into(),
                },
            },
        };
        let capability_json = to_camel_case_json_value(serde_json::to_value(&capability)?);
        let request_json = to_camel_case_json_value(serde_json::to_value(&request)?);
        let response = reqwest::Client::new()
            .post(endpoint)
            .header("Authorization", format!("Bearer {signature}"))
            .header("X-Tapchat-Capability", serde_json::to_string(&capability_json)?)
            .header("Content-Type", "application/json")
            .body(serde_json::to_vec(&request_json)?)
            .send()
            .await
            .context("append runtime control message")?;
        if !response.status().is_success() {
            bail!("append runtime control failed with status {}", response.status());
        }
        let body = response.text().await.context("read append runtime control response")?;
        serde_json::from_str(&body).context("parse append runtime control response")
    })
}

fn to_camel_case_json_value(value: Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.into_iter().map(to_camel_case_json_value).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (snake_to_camel(&key), to_camel_case_json_value(value)))
                .collect(),
        ),
        other => other,
    }
}

fn snake_to_camel(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut uppercase = false;
    for ch in value.chars() {
        if ch == '_' {
            uppercase = true;
        } else if uppercase {
            output.extend(ch.to_uppercase());
            uppercase = false;
        } else {
            output.push(ch);
        }
    }
    output
}

fn assert_recovery_contract_alignment(
    profile: &Path,
    conversation_id: &str,
    conversation: &Value,
    status: &Value,
) -> Result<()> {
    let recovery = &conversation["recovery"];
    assert!(!recovery.is_null(), "conversation recovery must not be null");
    let status_row = find_recovery_conversation(status, conversation_id)?;
    let snapshot_row =
        snapshot_recovery_context(profile, conversation_id)?.context("missing snapshot recovery context")?;
    for field in [
        "recovery_status",
        "reason",
        "phase",
        "attempt_count",
        "identity_refresh_retry_count",
        "last_error",
        "escalation_reason",
    ] {
        let conversation_field = if field == "recovery_status" {
            &conversation[field]
        } else {
            &recovery[field]
        };
        assert_eq!(
            conversation_field,
            &status_row[field],
            "conversation/status mismatch for {field}"
        );
        if field != "recovery_status" {
            assert_eq!(
                conversation_field,
                &snapshot_row[field],
                "conversation/snapshot mismatch for {field}"
            );
        }
    }
    Ok(())
}

fn publish_identity_bundle_for_profile(
    root: &Path,
    runtime: &CloudflareRuntimeHandle,
    auth: &DeviceRuntimeAuth,
    profile: &Path,
    name: &str,
) -> Result<IdentityBundle> {
    let identity_path = export_identity_bundle_to_path(root, profile, name)?;
    let identity_bundle: IdentityBundle = read_json_file(&identity_path)?;
    runtime_put_identity_bundle(runtime, auth, &identity_bundle)?;
    Ok(identity_bundle)
}

fn publish_merged_identity_bundle_for_profiles(
    root: &Path,
    runtime: &CloudflareRuntimeHandle,
    auth: &DeviceRuntimeAuth,
    deployment: &DeploymentBundle,
    signer_profile: &Path,
    profiles: &[(&Path, &str)],
) -> Result<IdentityBundle> {
    let mut exported = Vec::with_capacity(profiles.len());
    for (profile, name) in profiles {
        let identity_path = export_identity_bundle_to_path(root, profile, name)?;
        exported.push(read_json_file::<IdentityBundle>(&identity_path)?);
    }
    let merged_identity = merge_identity_bundles(deployment, signer_profile, &exported)?;
    runtime_put_identity_bundle(runtime, auth, &merged_identity)?;
    Ok(merged_identity)
}

fn bundle_auth(bundle: &DeploymentBundle) -> Result<&DeviceRuntimeAuth> {
    bundle
        .device_runtime_auth
        .as_ref()
        .context("deployment bundle missing device runtime auth")
}

fn run_orchestrated_cli_case(test_name: &str) -> Result<()> {
    let exe = std::env::current_exe().context("resolve cli_e2e test binary path")?;
    eprintln!("cli_e2e_stable_suite: starting {test_name}");
    let mut child = Command::new(exe)
        .current_dir(workspace_root())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .args([test_name, "--ignored", "--nocapture"])
        .spawn()
        .with_context(|| format!("spawn orchestrated cli_e2e case {test_name}"))?;
    let deadline = Instant::now() + ORCHESTRATED_CASE_TIMEOUT;
    loop {
        if child
            .try_wait()
            .with_context(|| format!("poll orchestrated cli_e2e case {test_name}"))?
            .is_some()
        {
            break;
        }
        if Instant::now() >= deadline {
            let pid = child.id();
            let _ = stop_pid_and_wait(pid);
            let output = child
                .wait_with_output()
                .with_context(|| format!("collect timed out orchestrated cli_e2e case {test_name}"))?;
            bail!(
                "orchestrated cli_e2e case {test_name} timed out after {:?}\nstdout:\n{}\nstderr:\n{}",
                ORCHESTRATED_CASE_TIMEOUT,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(200));
    }
    let output = child
        .wait_with_output()
        .with_context(|| format!("collect orchestrated cli_e2e case {test_name}"))?;
    if !output.status.success() {
        bail!(
            "orchestrated cli_e2e case {test_name} failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    eprintln!("cli_e2e_stable_suite: finished {test_name}");
    Ok(())
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

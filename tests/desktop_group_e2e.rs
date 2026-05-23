//! Desktop group end-to-end test (Wave G.4).
//!
//! Drives the 14-step group lifecycle scenario from
//! `.kiro/specs/desktop-group-ui-mvp/tasks.md` through the actual
//! group Tauri command `_impl` functions, exercising the same core
//! driver, effects loop, and persistence the webview would see —
//! minus the webview itself. Sits on the shared CLI `.test-runtime`
//! Cloudflare harness so we get real HTTP / WS / durable-object
//! semantics.
//!
//! Architecture (Path C from the Wave G.4 investigation):
//!
//!   - Profiles are bootstrapped by the real CLI (`tapchat profile
//!     init`, `device recover`, `profile import-deployment`,
//!     `profile export-identity`, `contact import-identity`). This
//!     keeps steps 1–3 identical to how the CLI e2e suite sets up
//!     the same four profiles.
//!   - Once the profiles exist on disk we hand each profile path to
//!     `tapchat_desktop_lib::test_support::build_test_app_state_for_profile`
//!     which constructs an `AppState` without any webview.
//!   - Every subsequent action goes through the group command `_impl`
//!     siblings (re-exported from `tapchat_desktop_lib::test_support`).
//!     Those call `drive_core_without_handle` which drains effects
//!     through the same `DesktopPlatformPorts` the production
//!     command would use.
//!   - For step 14d we bypass the command layer and POST a raw HTTP
//!     append directly to the Cloudflare outbox so we can assert the
//!     `403 group_sealed` on the wire per R13.5.

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use common::{
    bundle_auth, export_identity_bundle_to_path, read_json_file, repo_temp_dir, required_str,
    run_cli_json, with_tokio, workspace_root, write_json_file, write_mnemonic_file,
};
use reqwest::StatusCode;
use serde_json::Value;
use tapchat_core::ffi_api::RealtimeEvent;
use tapchat_core::model::{DeploymentBundle, IdentityBundle};
use tapchat_core::CoreEvent;
use tapchat_desktop_lib::test_support::{
    approve_group_join_impl, build_test_app_state_for_profile, create_group_conversation_impl,
    create_group_invite_link_impl, dissolve_group_impl, download_attachment_impl,
    drive_core_without_handle, get_group_messages_impl, get_group_snapshot_impl, leave_group_impl,
    list_group_conversations_impl, remove_group_member_impl, send_attachment_impl,
    send_group_text_message_impl, set_group_admin_impl, submit_group_join_request_impl,
    sync_group_outbox_impl, transfer_group_ownership_impl, update_group_metadata_impl, CoreInput,
    GroupMessageView,
};
use tapchat_desktop_lib::AppState;
use tapchat_transport_adapter::CloudflareRuntimeHandle;
use tempfile::TempDir;

// Mnemonics mirror the ones used by `tests/cli_e2e.rs` so the
// bootstrap runtime produces identical device ids across test
// cases — makes debugging cross-harness failures trivial.
const ALICE_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const BOB_MNEMONIC: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";
const CAROL_MNEMONIC: &str =
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";
const DANA_MNEMONIC: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";

struct QuartetContext {
    #[allow(dead_code)]
    runtime: CloudflareRuntimeHandle,
    #[allow(dead_code)]
    temp_root: TempDir,
    alice_profile: PathBuf,
    bob_profile: PathBuf,
    carol_profile: PathBuf,
    dana_profile: PathBuf,
    alice_bundle: DeploymentBundle,
    #[allow(dead_code)]
    alice_user_id: String,
    bob_user_id: String,
    carol_user_id: String,
    #[allow(dead_code)]
    dana_user_id: String,
    #[allow(dead_code)]
    alice_device_id: String,
    bob_device_id: String,
    carol_device_id: String,
    #[allow(dead_code)]
    dana_device_id: String,
}

/// Bootstrap four profiles (alice owner, bob, carol, dana) via the
/// real CLI. Mirrors the first phase of `setup_cli_group_quartet` in
/// the CLI e2e suite but keeps its own registry file per test case
/// so concurrent runs don't stomp on each other.
fn bootstrap_quartet(suffix: &str) -> Result<QuartetContext> {
    let workspace_root = workspace_root();
    let runtime = with_tokio(|| async { CloudflareRuntimeHandle::start(&workspace_root).await })?;
    let temp_root = repo_temp_dir(suffix)?;
    let registry_path = temp_root.path().join(format!("{suffix}.profiles.json"));

    let alice_profile = temp_root.path().join("alice");
    let bob_profile = temp_root.path().join("bob");
    let carol_profile = temp_root.path().join("carol");
    let dana_profile = temp_root.path().join("dana");

    let mnemonics = [
        ("alice", ALICE_MNEMONIC, &alice_profile),
        ("bob", BOB_MNEMONIC, &bob_profile),
        ("carol", CAROL_MNEMONIC, &carol_profile),
        ("dana", DANA_MNEMONIC, &dana_profile),
    ];

    let mut identities = Vec::new();
    for (name, mnemonic, profile) in mnemonics.iter() {
        run_cli_json(
            &registry_path,
            [
                "profile",
                "init",
                "--name",
                name,
                "--root",
                &profile.to_string_lossy(),
            ],
        )?;
        let mnemonic_path =
            write_mnemonic_file(temp_root.path(), &format!("{name}-mnemonic.txt"), mnemonic)?;
        let identity = run_cli_json(
            &registry_path,
            [
                "device",
                "recover",
                "--profile",
                &profile.to_string_lossy(),
                "--device-name",
                "phone",
                "--mnemonic-file",
                &mnemonic_path.to_string_lossy(),
            ],
        )?;
        identities.push(identity);
    }

    let alice_user_id = required_str(&identities[0], "user_id")?;
    let alice_device_id = required_str(&identities[0], "device_id")?;
    let bob_user_id = required_str(&identities[1], "user_id")?;
    let bob_device_id = required_str(&identities[1], "device_id")?;
    let carol_user_id = required_str(&identities[2], "user_id")?;
    let carol_device_id = required_str(&identities[2], "device_id")?;
    let dana_user_id = required_str(&identities[3], "user_id")?;
    let dana_device_id = required_str(&identities[3], "device_id")?;

    let bundles = with_tokio(|| async {
        let alice = runtime
            .bootstrap_device_bundle(&alice_user_id, &alice_device_id)
            .await?;
        let bob = runtime
            .bootstrap_device_bundle(&bob_user_id, &bob_device_id)
            .await?;
        let carol = runtime
            .bootstrap_device_bundle(&carol_user_id, &carol_device_id)
            .await?;
        let dana = runtime
            .bootstrap_device_bundle(&dana_user_id, &dana_device_id)
            .await?;
        Ok::<_, anyhow::Error>([alice, bob, carol, dana])
    })?;

    let bundle_paths = [
        write_json_file(temp_root.path(), "alice-deployment.json", &bundles[0])?,
        write_json_file(temp_root.path(), "bob-deployment.json", &bundles[1])?,
        write_json_file(temp_root.path(), "carol-deployment.json", &bundles[2])?,
        write_json_file(temp_root.path(), "dana-deployment.json", &bundles[3])?,
    ];

    for (profile, bundle_path) in [
        (&alice_profile, &bundle_paths[0]),
        (&bob_profile, &bundle_paths[1]),
        (&carol_profile, &bundle_paths[2]),
        (&dana_profile, &bundle_paths[3]),
    ] {
        run_cli_json(
            &registry_path,
            [
                "profile",
                "import-deployment",
                "--profile",
                &profile.to_string_lossy(),
                &bundle_path.to_string_lossy(),
            ],
        )?;
    }

    let identity_paths = [
        export_identity_bundle_to_path(
            &registry_path,
            temp_root.path(),
            &alice_profile,
            "alice-identity.json",
        )?,
        export_identity_bundle_to_path(
            &registry_path,
            temp_root.path(),
            &bob_profile,
            "bob-identity.json",
        )?,
        export_identity_bundle_to_path(
            &registry_path,
            temp_root.path(),
            &carol_profile,
            "carol-identity.json",
        )?,
        export_identity_bundle_to_path(
            &registry_path,
            temp_root.path(),
            &dana_profile,
            "dana-identity.json",
        )?,
    ];

    for (bundle, identity_path) in bundles.iter().zip(identity_paths.iter()) {
        let identity_bundle: IdentityBundle = read_json_file(identity_path)?;
        with_tokio(|| async {
            runtime
                .put_identity_bundle(bundle_auth(bundle)?, &identity_bundle)
                .await
        })?;
    }

    // Allowlist mutual traffic so membership commits + identity
    // refreshes aren't shadowed by the message-request policy.
    let all_user_ids = [&alice_user_id, &bob_user_id, &carol_user_id, &dana_user_id];
    for (bundle, me) in bundles.iter().zip(all_user_ids.iter()) {
        let allowed: Vec<String> = all_user_ids
            .iter()
            .filter(|other| **other != *me)
            .map(|id| id.to_string())
            .collect();
        with_tokio(|| async { runtime.put_allowlist(bundle_auth(bundle)?, &allowed).await })?;
    }

    // Contact graph needed before MLS add_members can look up each
    // peer's active KeyPackage.
    let import_contact = |profile: &Path, identity: &Path| -> Result<()> {
        run_cli_json(
            &registry_path,
            [
                "contact",
                "import-identity",
                "--profile",
                &profile.to_string_lossy(),
                &identity.to_string_lossy(),
            ],
        )?;
        Ok(())
    };
    import_contact(&alice_profile, &identity_paths[1])?;
    import_contact(&alice_profile, &identity_paths[2])?;
    import_contact(&alice_profile, &identity_paths[3])?;
    import_contact(&bob_profile, &identity_paths[0])?;
    import_contact(&bob_profile, &identity_paths[2])?;
    import_contact(&bob_profile, &identity_paths[3])?;
    import_contact(&carol_profile, &identity_paths[0])?;
    import_contact(&carol_profile, &identity_paths[1])?;
    import_contact(&dana_profile, &identity_paths[0])?;

    Ok(QuartetContext {
        runtime,
        temp_root,
        alice_profile,
        bob_profile,
        carol_profile,
        dana_profile,
        alice_bundle: bundles[0].clone(),
        alice_user_id,
        bob_user_id,
        carol_user_id,
        dana_user_id,
        alice_device_id,
        bob_device_id,
        carol_device_id,
        dana_device_id,
    })
}

/// Per-profile test harness: wraps the AppState built from a profile
/// directory + convenience methods to run the group commands.
struct DesktopHarness {
    state: AppState,
}

fn find_welcome_pickup_url(pickups: &[Value], device_id: &str) -> Result<String> {
    pickups
        .iter()
        .find(|entry| entry["device_id"].as_str() == Some(device_id))
        .and_then(|entry| entry["url"].as_str().map(|s| s.to_string()))
        .with_context(|| format!("welcome pickup for {device_id} missing in create output"))
}

fn has_system_banner(messages: &[GroupMessageView], raw_message_type: &str) -> bool {
    messages.iter().any(|message| match message {
        GroupMessageView::SystemBanner {
            raw_message_type: rmt,
            ..
        } => rmt == raw_message_type,
        _ => false,
    })
}

fn has_bubble_with_plaintext(messages: &[GroupMessageView], plaintext: &str) -> bool {
    messages.iter().any(|message| match message {
        GroupMessageView::Bubble {
            plaintext: Some(text),
            ..
        } => text == plaintext,
        _ => false,
    })
}

impl DesktopHarness {
    async fn new(profile_root: &Path) -> Result<Self> {
        let state = build_test_app_state_for_profile(profile_root)
            .await
            .with_context(|| format!("build test app state for {}", profile_root.display()))?;
        Ok(Self { state })
    }
}

#[test]
fn desktop_group_full_lifecycle_e2e() -> Result<()> {
    let handle = std::thread::Builder::new()
        .name("desktop_group_full_lifecycle_e2e_large_stack".into())
        .stack_size(64 * 1024 * 1024)
        .spawn(|| -> Result<()> {
            let ctx = bootstrap_quartet("desktop-group-full")?;

            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("build tokio runtime for desktop_group_e2e")?;

            rt.block_on(async {
                tokio::time::timeout(Duration::from_secs(120), run_lifecycle(&ctx))
                    .await
                    .context("desktop_group_full_lifecycle_e2e timed out after 120 seconds")?
            })?;
            Ok(())
        })
        .context("spawn desktop_group_full_lifecycle_e2e large-stack thread")?;

    match handle.join() {
        Ok(result) => result,
        Err(payload) => {
            let message = payload
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                .unwrap_or("unknown panic payload");
            Err(anyhow!(
                "desktop_group_full_lifecycle_e2e panicked: {message}"
            ))
        }
    }
}

#[test]
fn desktop_group_three_user_text_minimal_e2e() -> Result<()> {
    let ctx = bootstrap_quartet("desktop-group-three-user-text")?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime for desktop_group_three_user_text_minimal_e2e")?;

    rt.block_on(run_three_user_text_minimal(&ctx))?;
    Ok(())
}

#[test]
fn desktop_group_membership_management_minimal_e2e() -> Result<()> {
    let ctx = bootstrap_quartet("desktop-group-membership")?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime for desktop_group_membership_management_minimal_e2e")?;

    rt.block_on(run_membership_management_minimal(&ctx))?;
    Ok(())
}

#[test]
fn desktop_group_attachment_minimal_e2e() -> Result<()> {
    let ctx = bootstrap_quartet("desktop-group-attachment")?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime for desktop_group_attachment_minimal_e2e")?;

    rt.block_on(run_group_attachment_minimal(&ctx))?;
    Ok(())
}

#[test]
fn desktop_group_restart_recovery_minimal_e2e() -> Result<()> {
    let ctx = bootstrap_quartet("desktop-group-restart-recovery")?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime for desktop_group_restart_recovery_minimal_e2e")?;

    rt.block_on(run_group_restart_recovery_minimal(&ctx))?;
    Ok(())
}

#[test]
fn desktop_group_dana_post_approval_send_sync_regression() -> Result<()> {
    let ctx = bootstrap_quartet("desktop-group-dana-post-approval")?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime for desktop_group_dana_post_approval_send_sync_regression")?;

    rt.block_on(run_dana_post_approval_send_sync_regression(&ctx))?;
    Ok(())
}

#[test]
fn desktop_group_realtime_event_drives_owner_message_sync_regression() -> Result<()> {
    let ctx = bootstrap_quartet("desktop-group-realtime-owner-sync")?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime for desktop_group_realtime_event_drives_owner_message_sync_regression")?;

    rt.block_on(run_realtime_event_drives_owner_message_sync(&ctx))?;
    Ok(())
}

async fn run_three_user_text_minimal(ctx: &QuartetContext) -> Result<()> {
    let alice = DesktopHarness::new(&ctx.alice_profile).await?;

    let created = create_group_conversation_impl(
        &alice.state,
        "Three User Text".into(),
        vec![ctx.bob_user_id.clone(), ctx.carol_user_id.clone()],
    )
    .await
    .map_err(|e| anyhow!("create_group_conversation_impl: {e}"))?;
    assert_eq!(created.member_count, 3);
    assert_eq!(created.welcome_pickups.len(), 2);

    let group_id = created.group_id.clone();
    let conversation_id = created.conversation_id.clone();

    let welcome_pickups: Vec<Value> = created
        .welcome_pickups
        .iter()
        .map(|p| {
            serde_json::json!({
                "device_id": p.device_id,
                "url": p.url,
            })
        })
        .collect();
    let bob_pickup = find_welcome_pickup_url(&welcome_pickups, &ctx.bob_device_id)?;
    let carol_pickup = find_welcome_pickup_url(&welcome_pickups, &ctx.carol_device_id)?;

    let bob = DesktopHarness::new(&ctx.bob_profile).await?;
    let carol = DesktopHarness::new(&ctx.carol_profile).await?;

    let bob_result = submit_group_join_request_impl(&bob.state, bob_pickup)
        .await
        .map_err(|e| anyhow!("bob submit_group_join_request_impl: {e}"))?;
    assert_eq!(bob_result.status, "approved");
    assert_eq!(bob_result.group_id, group_id);

    let carol_result = submit_group_join_request_impl(&carol.state, carol_pickup)
        .await
        .map_err(|e| anyhow!("carol submit_group_join_request_impl: {e}"))?;
    assert_eq!(carol_result.status, "approved");
    assert_eq!(carol_result.group_id, group_id);

    sync_all_group_outboxes(&group_id, [&alice, &bob, &carol]).await?;

    let exchanges = [
        (&alice, "alice", "alice says hello"),
        (&bob, "bob", "bob says hello"),
        (&carol, "carol", "carol says hello"),
    ];

    for (sender, label, plaintext) in exchanges {
        send_group_text_message_impl(
            &sender.state,
            conversation_id.clone(),
            plaintext.to_string(),
        )
        .await
        .map_err(|e| anyhow!("{label} send_group_text_message_impl: {e}"))?;
        sync_all_group_outboxes(&group_id, [&alice, &bob, &carol]).await?;
    }

    for (label, harness) in [("alice", &alice), ("bob", &bob), ("carol", &carol)] {
        let messages = get_group_messages_impl(&harness.state, conversation_id.clone())
            .await
            .map_err(|e| anyhow!("{label} get_group_messages_impl: {e}"))?;
        for plaintext in ["alice says hello", "bob says hello", "carol says hello"] {
            assert!(
                has_bubble_with_plaintext(&messages, plaintext),
                "{label} did not decrypt {plaintext:?}"
            );
        }
    }

    Ok(())
}

async fn run_group_attachment_minimal(ctx: &QuartetContext) -> Result<()> {
    let (alice, bob, carol, group_id, conversation_id) =
        create_three_user_group(ctx, "Desktop Group Attachment").await?;

    let attachment_id = "desktop-group-attachment.bin";
    let attachment_path = ctx.alice_profile.join("attachments").join(attachment_id);
    std::fs::create_dir_all(attachment_path.parent().expect("attachment parent"))?;
    std::fs::write(&attachment_path, [9_u8, 8, 7, 6])?;

    send_attachment_impl(
        &alice.state,
        conversation_id.clone(),
        attachment_id.into(),
        "application/octet-stream".into(),
        4,
        Some("desktop-group-attachment.bin".into()),
    )
    .await
    .map_err(|e| anyhow!("alice send_attachment_impl: {e}"))?;

    sync_group_outbox_impl(&bob.state, group_id.clone(), None)
        .await
        .map_err(|e| anyhow!("bob sync_group_outbox_impl attachment: {e}"))?;
    sync_group_outbox_impl(&carol.state, group_id.clone(), None)
        .await
        .map_err(|e| anyhow!("carol sync_group_outbox_impl attachment: {e}"))?;

    let bob_messages = get_group_messages_impl(&bob.state, conversation_id.clone())
        .await
        .map_err(|e| anyhow!("bob get_group_messages_impl attachment: {e}"))?;
    let carol_messages = get_group_messages_impl(&carol.state, conversation_id.clone())
        .await
        .map_err(|e| anyhow!("carol get_group_messages_impl attachment: {e}"))?;
    let (message_id, reference) = find_attachment_message(&bob_messages)?;
    assert!(
        find_attachment_message(&carol_messages).is_ok(),
        "carol should see the group attachment projection"
    );

    let destination = "desktop-group-downloads/bob.bin";
    download_attachment_impl(
        &bob.state,
        conversation_id,
        message_id,
        reference,
        destination.into(),
    )
    .await
    .map_err(|e| anyhow!("bob download_attachment_impl: {e}"))?;
    let downloaded = std::fs::read(ctx.bob_profile.join("attachments").join(destination))
        .context("read bob downloaded group attachment")?;
    assert_eq!(downloaded, vec![9, 8, 7, 6]);

    Ok(())
}

async fn run_group_restart_recovery_minimal(ctx: &QuartetContext) -> Result<()> {
    let (alice, bob, _carol, group_id, conversation_id) =
        create_three_user_group(ctx, "Desktop Group Restart").await?;

    send_group_text_message_impl(
        &alice.state,
        conversation_id.clone(),
        "restart visible message".into(),
    )
    .await
    .map_err(|e| anyhow!("alice send_group_text_message_impl restart: {e}"))?;
    sync_group_outbox_impl(&bob.state, group_id.clone(), None)
        .await
        .map_err(|e| anyhow!("bob sync before restart: {e}"))?;
    let before = get_group_snapshot_impl(&bob.state, group_id.clone())
        .await
        .map_err(|e| anyhow!("bob snapshot before restart: {e}"))?;
    let before_cursor = before
        .cursor
        .as_ref()
        .map(|cursor| cursor.last_fetched_seq)
        .unwrap_or_default();
    assert!(before_cursor > 0);

    let restarted_bob = DesktopHarness::new(&ctx.bob_profile).await?;
    let conversations = list_group_conversations_impl(&restarted_bob.state)
        .await
        .map_err(|e| anyhow!("bob list_group_conversations_impl after restart: {e}"))?;
    assert!(conversations.iter().any(|row| row.group_id == group_id));
    let after = get_group_snapshot_impl(&restarted_bob.state, group_id.clone())
        .await
        .map_err(|e| anyhow!("bob snapshot after restart: {e}"))?;
    assert_eq!(after.local_role, before.local_role);
    assert_eq!(
        after
            .cursor
            .as_ref()
            .map(|cursor| cursor.last_fetched_seq)
            .unwrap_or_default(),
        before_cursor
    );
    let messages = get_group_messages_impl(&restarted_bob.state, conversation_id.clone())
        .await
        .map_err(|e| anyhow!("bob messages after restart: {e}"))?;
    assert!(
        has_bubble_with_plaintext(&messages, "restart visible message"),
        "restarted bob should restore group messages"
    );

    let attachment_id = "desktop-group-restart.bin";
    let attachment_path = ctx.alice_profile.join("attachments").join(attachment_id);
    std::fs::create_dir_all(attachment_path.parent().expect("attachment parent"))?;
    std::fs::write(&attachment_path, [5_u8, 4, 3, 2])?;
    send_attachment_impl(
        &alice.state,
        conversation_id.clone(),
        attachment_id.into(),
        "application/octet-stream".into(),
        4,
        Some("desktop-group-restart.bin".into()),
    )
    .await
    .map_err(|e| anyhow!("alice send restart attachment: {e}"))?;
    sync_group_outbox_impl(&restarted_bob.state, group_id.clone(), None)
        .await
        .map_err(|e| anyhow!("restarted bob sync attachment: {e}"))?;
    let messages = get_group_messages_impl(&restarted_bob.state, conversation_id.clone())
        .await
        .map_err(|e| anyhow!("restarted bob messages attachment: {e}"))?;
    let (message_id, reference) = find_attachment_message(&messages)?;

    let destination = "desktop-group-downloads/restarted-bob.bin";
    download_attachment_impl(
        &restarted_bob.state,
        conversation_id,
        message_id,
        reference,
        destination.into(),
    )
    .await
    .map_err(|e| anyhow!("restarted bob download attachment: {e}"))?;
    let downloaded = std::fs::read(ctx.bob_profile.join("attachments").join(destination))
        .context("read restarted bob downloaded group attachment")?;
    assert_eq!(downloaded, vec![5, 4, 3, 2]);

    Ok(())
}

async fn create_three_user_group(
    ctx: &QuartetContext,
    title: &str,
) -> Result<(
    DesktopHarness,
    DesktopHarness,
    DesktopHarness,
    String,
    String,
)> {
    let alice = DesktopHarness::new(&ctx.alice_profile).await?;
    let created = create_group_conversation_impl(
        &alice.state,
        title.into(),
        vec![ctx.bob_user_id.clone(), ctx.carol_user_id.clone()],
    )
    .await
    .map_err(|e| anyhow!("create_group_conversation_impl: {e}"))?;
    let group_id = created.group_id.clone();
    let conversation_id = created.conversation_id.clone();
    let welcome_pickups: Vec<Value> = created
        .welcome_pickups
        .iter()
        .map(|p| {
            serde_json::json!({
                "device_id": p.device_id,
                "url": p.url,
            })
        })
        .collect();
    let bob_pickup = find_welcome_pickup_url(&welcome_pickups, &ctx.bob_device_id)?;
    let carol_pickup = find_welcome_pickup_url(&welcome_pickups, &ctx.carol_device_id)?;
    let bob = DesktopHarness::new(&ctx.bob_profile).await?;
    let carol = DesktopHarness::new(&ctx.carol_profile).await?;
    submit_group_join_request_impl(&bob.state, bob_pickup)
        .await
        .map_err(|e| anyhow!("bob submit_group_join_request_impl: {e}"))?;
    submit_group_join_request_impl(&carol.state, carol_pickup)
        .await
        .map_err(|e| anyhow!("carol submit_group_join_request_impl: {e}"))?;
    sync_all_group_outboxes(&group_id, [&alice, &bob, &carol]).await?;
    Ok((alice, bob, carol, group_id, conversation_id))
}

fn find_attachment_message(messages: &[GroupMessageView]) -> Result<(String, String)> {
    messages
        .iter()
        .find_map(|message| match message {
            GroupMessageView::Bubble {
                message_id,
                storage_refs,
                ..
            } => storage_refs
                .iter()
                .find(|reference| !reference.object_ref.is_empty())
                .map(|reference| (message_id.clone(), reference.object_ref.clone())),
            _ => None,
        })
        .context("group attachment message missing")
}

async fn run_dana_post_approval_send_sync_regression(ctx: &QuartetContext) -> Result<()> {
    let (alice, bob, carol, group_id, conversation_id) =
        create_three_user_group(ctx, "Desktop Dana Approval Regression").await?;

    tokio::time::timeout(
        Duration::from_secs(15),
        update_group_metadata_impl(
            &alice.state,
            group_id.clone(),
            None,
            Some("approval_required".into()),
            None,
        ),
    )
    .await
    .context("alice update_group_metadata_impl timed out")?
    .map_err(|e| anyhow!("alice update_group_metadata_impl: {e}"))?;
    sync_all_group_outboxes(&group_id, [&alice, &bob, &carol]).await?;

    let expires_at = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64)
        + 3_600_000;
    let invite = tokio::time::timeout(
        Duration::from_secs(15),
        create_group_invite_link_impl(&alice.state, group_id.clone(), expires_at, None),
    )
    .await
    .context("alice create_group_invite_link_impl timed out")?
    .map_err(|e| anyhow!("alice create_group_invite_link_impl: {e}"))?;

    let dana = DesktopHarness::new(&ctx.dana_profile).await?;
    let dana_submit = tokio::time::timeout(
        Duration::from_secs(15),
        submit_group_join_request_impl(&dana.state, invite.invite_url.clone()),
    )
    .await
    .context("dana submit_group_join_request_impl timed out")?
    .map_err(|e| anyhow!("dana submit_group_join_request_impl: {e}"))?;
    assert_eq!(dana_submit.group_id, group_id);
    assert_eq!(dana_submit.status, "pending");

    let approval = tokio::time::timeout(
        Duration::from_secs(15),
        approve_group_join_impl(
            &alice.state,
            group_id.clone(),
            dana_submit.request_id.clone(),
        ),
    )
    .await
    .context("alice approve_group_join_impl timed out")?
    .map_err(|e| anyhow!("alice approve_group_join_impl: {e}"))?;
    let dana_pickup = approval
        .welcome_pickups
        .iter()
        .find(|pickup| pickup.device_id == ctx.dana_device_id)
        .map(|pickup| pickup.url.clone())
        .context("approval did not return dana welcome pickup")?;

    let dana_import = tokio::time::timeout(
        Duration::from_secs(15),
        submit_group_join_request_impl(&dana.state, dana_pickup),
    )
    .await
    .context("dana import approved welcome pickup timed out")?
    .map_err(|e| anyhow!("dana import approved welcome pickup: {e}"))?;
    assert_eq!(dana_import.group_id, group_id);
    assert_eq!(dana_import.status, "approved");

    tokio::time::timeout(
        Duration::from_secs(15),
        sync_group_outbox_impl(&dana.state, group_id.clone(), None),
    )
    .await
    .context("dana sync_group_outbox_impl after import timed out")?
    .map_err(|e| anyhow!("dana sync_group_outbox_impl after import: {e}"))?;

    tokio::time::timeout(
        Duration::from_secs(15),
        send_group_text_message_impl(
            &dana.state,
            conversation_id.clone(),
            "dana focused regression".into(),
        ),
    )
    .await
    .context("dana send_group_text_message_impl timed out")?
    .map_err(|e| anyhow!("dana send_group_text_message_impl: {e}"))?;

    for (label, harness) in [("alice", &alice), ("bob", &bob), ("carol", &carol)] {
        tokio::time::timeout(
            Duration::from_secs(15),
            sync_group_outbox_impl(&harness.state, group_id.clone(), None),
        )
        .await
        .with_context(|| format!("{label} sync_group_outbox_impl after dana send timed out"))?
        .map_err(|e| anyhow!("{label} sync_group_outbox_impl after dana send: {e}"))?;
        let messages = get_group_messages_impl(&harness.state, conversation_id.clone())
            .await
            .map_err(|e| anyhow!("{label} get_group_messages_impl after dana send: {e}"))?;
        assert!(
            has_bubble_with_plaintext(&messages, "dana focused regression"),
            "{label} did not receive dana's focused regression text"
        );
    }

    Ok(())
}

async fn run_realtime_event_drives_owner_message_sync(ctx: &QuartetContext) -> Result<()> {
    let (alice, bob, _carol, group_id, conversation_id) =
        create_three_user_group(ctx, "Desktop Realtime Owner Sync").await?;

    let before_snapshot = get_group_snapshot_impl(&bob.state, group_id.clone())
        .await
        .map_err(|e| anyhow!("bob snapshot before realtime sync: {e}"))?;
    let before_cursor = before_snapshot
        .cursor
        .as_ref()
        .map(|cursor| cursor.last_fetched_seq)
        .unwrap_or_default();

    send_group_text_message_impl(
        &alice.state,
        conversation_id.clone(),
        "owner realtime delivery".into(),
    )
    .await
    .map_err(|e| anyhow!("alice send owner realtime delivery: {e}"))?;

    drive_core_without_handle(
        &bob.state,
        CoreInput::Event(CoreEvent::GroupRealtimeEventReceived {
            group_id: group_id.clone(),
            event: RealtimeEvent::GroupOutboxRecordAvailable {
                group_id: group_id.clone(),
                seq: before_cursor.saturating_add(1),
                record: None,
            },
        }),
    )
    .await
    .map_err(|e| anyhow!("bob realtime event drive: {e}"))?;

    let messages = get_group_messages_impl(&bob.state, conversation_id)
        .await
        .map_err(|e| anyhow!("bob messages after realtime event: {e}"))?;
    assert!(
        has_bubble_with_plaintext(&messages, "owner realtime delivery"),
        "bob should receive owner text through realtime-driven core sync"
    );

    let after_snapshot = get_group_snapshot_impl(&bob.state, group_id)
        .await
        .map_err(|e| anyhow!("bob snapshot after realtime sync: {e}"))?;
    let after_cursor = after_snapshot
        .cursor
        .as_ref()
        .map(|cursor| cursor.last_fetched_seq)
        .unwrap_or_default();
    assert!(
        after_cursor > before_cursor,
        "bob cursor should advance after realtime-driven sync; before={before_cursor} after={after_cursor}"
    );

    Ok(())
}

async fn run_membership_management_minimal(ctx: &QuartetContext) -> Result<()> {
    let alice = DesktopHarness::new(&ctx.alice_profile).await?;

    let created = create_group_conversation_impl(
        &alice.state,
        "Membership Project".into(),
        vec![
            ctx.bob_user_id.clone(),
            ctx.carol_user_id.clone(),
            ctx.dana_user_id.clone(),
        ],
    )
    .await
    .map_err(|e| anyhow!("create_group_conversation_impl: {e}"))?;
    assert_eq!(created.member_count, 4);
    assert_eq!(created.welcome_pickups.len(), 3);

    let group_id = created.group_id.clone();
    let conversation_id = created.conversation_id.clone();

    let welcome_pickups: Vec<Value> = created
        .welcome_pickups
        .iter()
        .map(|p| {
            serde_json::json!({
                "device_id": p.device_id,
                "url": p.url,
            })
        })
        .collect();
    let bob_pickup = find_welcome_pickup_url(&welcome_pickups, &ctx.bob_device_id)?;
    let carol_pickup = find_welcome_pickup_url(&welcome_pickups, &ctx.carol_device_id)?;
    let dana_pickup = find_welcome_pickup_url(&welcome_pickups, &ctx.dana_device_id)?;

    let bob = DesktopHarness::new(&ctx.bob_profile).await?;
    let carol = DesktopHarness::new(&ctx.carol_profile).await?;
    let dana = DesktopHarness::new(&ctx.dana_profile).await?;

    for (label, harness, pickup) in [
        ("bob", &bob, bob_pickup),
        ("carol", &carol, carol_pickup),
        ("dana", &dana, dana_pickup),
    ] {
        let result = submit_group_join_request_impl(&harness.state, pickup)
            .await
            .map_err(|e| anyhow!("{label} submit_group_join_request_impl: {e}"))?;
        assert_eq!(result.status, "approved");
        assert_eq!(result.group_id, group_id);
    }

    sync_all_group_outboxes(&group_id, [&alice, &bob, &carol, &dana]).await?;

    leave_group_impl(&bob.state, group_id.clone())
        .await
        .map_err(|e| anyhow!("bob leave_group_impl: {e}"))?;
    let bob_send = send_group_text_message_impl(
        &bob.state,
        conversation_id.clone(),
        "bob after leave".into(),
    )
    .await;
    assert!(
        bob_send.is_err(),
        "bob must fail-closed after leave but got Ok: {bob_send:?}"
    );

    set_group_admin_impl(
        &alice.state,
        group_id.clone(),
        ctx.carol_user_id.clone(),
        true,
    )
    .await
    .map_err(|e| anyhow!("alice set_group_admin_impl: {e}"))?;
    sync_group_outbox_impl(&carol.state, group_id.clone(), None)
        .await
        .ok();
    let carol_snapshot = get_group_snapshot_impl(&carol.state, group_id.clone())
        .await
        .map_err(|e| anyhow!("carol get_group_snapshot_impl after admin: {e}"))?;
    assert_eq!(format!("{:?}", carol_snapshot.local_role), "Some(Admin)");

    transfer_group_ownership_impl(&alice.state, group_id.clone(), ctx.carol_user_id.clone())
        .await
        .map_err(|e| anyhow!("alice transfer_group_ownership_impl: {e}"))?;
    sync_group_outbox_impl(&carol.state, group_id.clone(), None)
        .await
        .ok();
    let carol_snapshot = get_group_snapshot_impl(&carol.state, group_id.clone())
        .await
        .map_err(|e| anyhow!("carol get_group_snapshot_impl after transfer: {e}"))?;
    assert_eq!(format!("{:?}", carol_snapshot.local_role), "Some(Owner)");

    let former_owner_admin_change = set_group_admin_impl(
        &alice.state,
        group_id.clone(),
        ctx.dana_user_id.clone(),
        false,
    )
    .await;
    assert!(
        former_owner_admin_change.is_err(),
        "former owner must not perform owner-only admin changes"
    );

    leave_group_impl(&alice.state, group_id.clone())
        .await
        .map_err(|e| anyhow!("alice leave_group_impl after transfer: {e}"))?;
    let alice_send = send_group_text_message_impl(
        &alice.state,
        conversation_id.clone(),
        "alice after leave".into(),
    )
    .await;
    assert!(
        alice_send.is_err(),
        "alice must fail-closed after leaving but got Ok: {alice_send:?}"
    );

    remove_group_member_impl(&carol.state, group_id.clone(), ctx.dana_user_id.clone())
        .await
        .map_err(|e| anyhow!("carol remove_group_member_impl: {e}"))?;
    sync_group_outbox_impl(&dana.state, group_id.clone(), None)
        .await
        .ok();
    let dana_send =
        send_group_text_message_impl(&dana.state, conversation_id, "dana after remove".into())
            .await;
    assert!(
        dana_send.is_err(),
        "dana must fail-closed after removal but got Ok: {dana_send:?}"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 10 completeness: sync gap recovery for groups
//
// These tests verify that a group member who falls behind (for any
// reason — WS disconnect, missed wakeup, manual refresh, app resume)
// can catch up through `SyncGroupOutbox` alone. The recovery path
// (GetHead → FetchMessages → Ack for the group outbox log) is the
// same regardless of the cause of the gap; realtime connect/disconnect
// lifecycle is tested at the transport-adapter layer (phase10_e2e.rs).
// ---------------------------------------------------------------------------

/// Group sync gap recovery: a member who stops syncing while messages
/// continue to flow must catch every missed message when they resume
/// syncing through `SyncGroupOutbox`.
///
/// Exercises the group outbox equivalent of PLAN.md §7.4: GetHead →
/// FetchMessages → Ack, using only the cursor-based pull path with no
/// realtime push events.
#[test]
fn desktop_group_sync_gap_recovery_e2e() -> Result<()> {
    let ctx = bootstrap_quartet("desktop-group-sync-gap")?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime for desktop_group_sync_gap_recovery_e2e")?;

    rt.block_on(run_group_sync_gap_recovery(&ctx))?;
    Ok(())
}

async fn run_group_sync_gap_recovery(ctx: &QuartetContext) -> Result<()> {
    // Step 1: create a 3-user group (alice owner, bob + carol members).
    let (alice, bob, carol, group_id, conversation_id) =
        create_three_user_group(ctx, "Sync Gap Recovery").await?;

    // Step 2: alice sends several initial messages while all members
    // sync to establish a common baseline.
    send_group_text_message_impl(
        &alice.state,
        conversation_id.clone(),
        "pre-offline-1".into(),
    )
    .await
    .map_err(|e| anyhow!("alice send pre-offline-1: {e}"))?;
    sync_group_outbox_impl(&alice.state, group_id.clone(), None)
        .await
        .ok();
    sync_group_outbox_impl(&bob.state, group_id.clone(), None)
        .await
        .ok();
    sync_group_outbox_impl(&carol.state, group_id.clone(), None)
        .await
        .ok();

    send_group_text_message_impl(
        &alice.state,
        conversation_id.clone(),
        "pre-offline-2".into(),
    )
    .await
    .map_err(|e| anyhow!("alice send pre-offline-2: {e}"))?;
    sync_group_outbox_impl(&alice.state, group_id.clone(), None)
        .await
        .ok();
    sync_group_outbox_impl(&bob.state, group_id.clone(), None)
        .await
        .ok();
    sync_group_outbox_impl(&carol.state, group_id.clone(), None)
        .await
        .ok();

    // Step 3: bob stops syncing while alice sends several messages.
    // Carol stays synced as a control group.
    let offline_messages = &["offline-msg-alpha", "offline-msg-beta", "offline-msg-gamma"];
    for plaintext in offline_messages {
        send_group_text_message_impl(&alice.state, conversation_id.clone(), plaintext.to_string())
            .await
            .map_err(|e| anyhow!("alice send offline {plaintext}: {e}"))?;
        // Only carol (online member) syncs.
        sync_group_outbox_impl(&carol.state, group_id.clone(), None)
            .await
            .map_err(|e| anyhow!("carol sync offline {plaintext}: {e}"))?;
    }

    // Verify carol sees all offline messages.
    let carol_messages = get_group_messages_impl(&carol.state, conversation_id.clone())
        .await
        .map_err(|e| anyhow!("carol get_group_messages_impl: {e}"))?;
    for plaintext in offline_messages {
        assert!(
            has_bubble_with_plaintext(&carol_messages, plaintext),
            "carol should see offline message \"{plaintext}\""
        );
    }

    // Step 4: bob resumes syncing. Having missed the messages, he must
    // recover purely through SyncGroupOutbox (internal head check +
    // fetch). This is the same recovery path used for wakeup loss,
    // WS disconnect, or manual refresh.
    sync_group_outbox_impl(&bob.state, group_id.clone(), None)
        .await
        .map_err(|e| anyhow!("bob sync after wakeup loss: {e}"))?;

    // Step 5: verify bob sees every offline message.
    let bob_messages = get_group_messages_impl(&bob.state, conversation_id.clone())
        .await
        .map_err(|e| anyhow!("bob get_group_messages_impl after wakeup loss: {e}"))?;
    for plaintext in offline_messages {
        assert!(
            has_bubble_with_plaintext(&bob_messages, plaintext),
            "bob should recover offline message \"{plaintext}\" via wakeup loss recovery"
        );
    }

    // bob must also see the pre-offline messages.
    for plaintext in ["pre-offline-1", "pre-offline-2"] {
        assert!(
            has_bubble_with_plaintext(&bob_messages, plaintext),
            "bob should still have pre-offline message \"{plaintext}\""
        );
    }

    // Step 6: cursor must be fully advanced.
    let bob_snapshot = get_group_snapshot_impl(&bob.state, group_id.clone())
        .await
        .map_err(|e| anyhow!("bob snapshot after wakeup loss: {e}"))?;
    let bob_cursor = bob_snapshot
        .cursor
        .as_ref()
        .map(|cursor| cursor.last_fetched_seq)
        .unwrap_or_default();
    let carol_snapshot = get_group_snapshot_impl(&carol.state, group_id.clone())
        .await
        .map_err(|e| anyhow!("carol snapshot after wakeup loss: {e}"))?;
    let carol_cursor = carol_snapshot
        .cursor
        .as_ref()
        .map(|cursor| cursor.last_fetched_seq)
        .unwrap_or_default();
    assert!(
        bob_cursor >= carol_cursor,
        "bob cursor ({bob_cursor}) should be >= carol cursor ({carol_cursor}) after wakeup loss recovery"
    );

    // Step 7: after recovery, bob can receive new messages normally.
    send_group_text_message_impl(
        &alice.state,
        conversation_id.clone(),
        "post-recovery".into(),
    )
    .await
    .map_err(|e| anyhow!("alice send post-recovery: {e}"))?;
    sync_group_outbox_impl(&bob.state, group_id.clone(), None)
        .await
        .map_err(|e| anyhow!("bob sync post-recovery: {e}"))?;
    let bob_final = get_group_messages_impl(&bob.state, conversation_id.clone())
        .await
        .map_err(|e| anyhow!("bob messages post-recovery: {e}"))?;
    assert!(
        has_bubble_with_plaintext(&bob_final, "post-recovery"),
        "bob should receive post-recovery message normally"
    );

    Ok(())
}

/// Group sync gap recovery with cursor alignment: simulates a member who
/// stops syncing while messages continue to flow, then catches up through
/// `SyncGroupOutbox`. The recovered member's cursor must reach the online
/// member's cursor, and all members must converge so future messages are
/// seen by everyone.
#[test]
fn desktop_group_sync_gap_with_cursor_alignment_e2e() -> Result<()> {
    let ctx = bootstrap_quartet("desktop-group-sync-gap-cursor")?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime for desktop_group_sync_gap_with_cursor_alignment_e2e")?;

    rt.block_on(run_group_sync_gap_with_cursor_alignment(&ctx))?;
    Ok(())
}

async fn run_group_sync_gap_with_cursor_alignment(ctx: &QuartetContext) -> Result<()> {
    // Step 1: create 3-user group.
    let (alice, bob, carol, group_id, conversation_id) =
        create_three_user_group(ctx, "Sync Gap Cursor Align").await?;

    // Establish baseline sync.
    send_group_text_message_impl(&alice.state, conversation_id.clone(), "baseline".into())
        .await
        .map_err(|e| anyhow!("alice send baseline: {e}"))?;
    sync_all_group_outboxes(&group_id, [&alice, &bob, &carol]).await?;
    let bob_baseline = get_group_messages_impl(&bob.state, conversation_id.clone())
        .await
        .map_err(|e| anyhow!("bob baseline messages: {e}"))?;
    assert!(has_bubble_with_plaintext(&bob_baseline, "baseline"));

    // Step 2: bob stops syncing. Alice sends messages during this
    // window while carol (who stays synced) sees them. bob does NOT
    // sync during this window, creating a cursor gap.
    let disconnect_messages = &[
        "during-disconnect-A",
        "during-disconnect-B",
        "during-disconnect-C",
    ];
    for plaintext in disconnect_messages {
        send_group_text_message_impl(&alice.state, conversation_id.clone(), plaintext.to_string())
            .await
            .map_err(|e| anyhow!("alice send disconnect {plaintext}: {e}"))?;
        // Only carol syncs.
        sync_group_outbox_impl(&carol.state, group_id.clone(), None)
            .await
            .map_err(|e| anyhow!("carol sync disconnect {plaintext}: {e}"))?;
    }

    // Carol must see all disconnect messages.
    let carol_during = get_group_messages_impl(&carol.state, conversation_id.clone())
        .await
        .map_err(|e| anyhow!("carol messages during disconnect: {e}"))?;
    for plaintext in disconnect_messages {
        assert!(
            has_bubble_with_plaintext(&carol_during, plaintext),
            "carol should see disconnect message \"{plaintext}\""
        );
    }

    // Step 3: bob resumes syncing. He must catch all missed messages.
    sync_group_outbox_impl(&bob.state, group_id.clone(), None)
        .await
        .map_err(|e| anyhow!("bob sync after reconnect: {e}"))?;

    let bob_recovered = get_group_messages_impl(&bob.state, conversation_id.clone())
        .await
        .map_err(|e| anyhow!("bob messages after reconnect: {e}"))?;
    for plaintext in disconnect_messages {
        assert!(
            has_bubble_with_plaintext(&bob_recovered, plaintext),
            "bob should recover disconnect message \"{plaintext}\""
        );
    }

    // Step 4: verify bob's cursor caught up to carol's (the online member).
    let bob_snapshot = get_group_snapshot_impl(&bob.state, group_id.clone())
        .await
        .map_err(|e| anyhow!("bob snapshot after reconnect: {e}"))?;
    let carol_snapshot = get_group_snapshot_impl(&carol.state, group_id.clone())
        .await
        .map_err(|e| anyhow!("carol snapshot after disconnect: {e}"))?;
    let bob_cursor = bob_snapshot
        .cursor
        .as_ref()
        .map(|cursor| cursor.last_fetched_seq)
        .unwrap_or_default();
    let carol_cursor = carol_snapshot
        .cursor
        .as_ref()
        .map(|cursor| cursor.last_fetched_seq)
        .unwrap_or_default();
    assert!(
        bob_cursor >= carol_cursor,
        "bob cursor ({bob_cursor}) should be >= carol cursor ({carol_cursor}) after reconnect"
    );

    // Step 5: after catching up, bob can send and receive normally.
    send_group_text_message_impl(
        &bob.state,
        conversation_id.clone(),
        "bob-post-reconnect".into(),
    )
    .await
    .map_err(|e| anyhow!("bob send post-reconnect: {e}"))?;
    sync_all_group_outboxes(&group_id, [&alice, &bob, &carol]).await?;
    for (label, harness) in [("alice", &alice), ("carol", &carol)] {
        let messages = get_group_messages_impl(&harness.state, conversation_id.clone())
            .await
            .map_err(|e| anyhow!("{label} messages post-reconnect: {e}"))?;
        assert!(
            has_bubble_with_plaintext(&messages, "bob-post-reconnect"),
            "{label} should see bob's post-reconnect message"
        );
    }

    // Step 6: send one more round through alice, verify all three members
    // see it normally (confirming the group is fully converged).
    send_group_text_message_impl(
        &alice.state,
        conversation_id.clone(),
        "final-convergence".into(),
    )
    .await
    .map_err(|e| anyhow!("alice send final-convergence: {e}"))?;
    sync_all_group_outboxes(&group_id, [&alice, &bob, &carol]).await?;
    for (label, harness) in [("alice", &alice), ("bob", &bob), ("carol", &carol)] {
        let messages = get_group_messages_impl(&harness.state, conversation_id.clone())
            .await
            .map_err(|e| anyhow!("{label} final messages: {e}"))?;
        assert!(
            has_bubble_with_plaintext(&messages, "final-convergence"),
            "{label} should see final-convergence message"
        );
    }

    Ok(())
}

async fn sync_all_group_outboxes<'a, const N: usize>(
    group_id: &str,
    harnesses: [&'a DesktopHarness; N],
) -> Result<()> {
    for harness in harnesses {
        sync_group_outbox_impl(&harness.state, group_id.to_string(), None)
            .await
            .map_err(|e| anyhow!("sync_group_outbox_impl: {e}"))?;
    }
    Ok(())
}

async fn run_lifecycle(ctx: &QuartetContext) -> Result<()> {
    // Step 4: alice builds an AppState and creates the 3-person group.
    let alice = DesktopHarness::new(&ctx.alice_profile).await?;

    let created = create_group_conversation_impl(
        &alice.state,
        "Desktop Project".into(),
        vec![ctx.bob_user_id.clone(), ctx.carol_user_id.clone()],
    )
    .await
    .map_err(|e| anyhow!("create_group_conversation_impl: {e}"))?;
    assert_eq!(created.title, "Desktop Project");
    assert_eq!(created.member_count, 3);
    assert_eq!(created.welcome_pickups.len(), 2);

    let group_id = created.group_id.clone();
    let conversation_id = created.conversation_id.clone();

    let welcome_pickups: Vec<Value> = created
        .welcome_pickups
        .iter()
        .map(|p| {
            serde_json::json!({
                "device_id": p.device_id,
                "url": p.url,
            })
        })
        .collect();
    let bob_pickup = find_welcome_pickup_url(&welcome_pickups, &ctx.bob_device_id)?;
    let carol_pickup = find_welcome_pickup_url(&welcome_pickups, &ctx.carol_device_id)?;

    // Steps 5-6: bob and carol each build their own AppState and
    // submit the welcome-pickup URL. The _impl dispatches through
    // `RequestJoinGroup` and auto-imports on success.
    let bob = DesktopHarness::new(&ctx.bob_profile).await?;
    let carol = DesktopHarness::new(&ctx.carol_profile).await?;
    let bob_result = submit_group_join_request_impl(&bob.state, bob_pickup)
        .await
        .map_err(|e| anyhow!("bob submit_group_join_request_impl: {e}"))?;
    assert_eq!(bob_result.status, "approved");
    assert_eq!(bob_result.group_id, group_id);
    let carol_result = submit_group_join_request_impl(&carol.state, carol_pickup)
        .await
        .map_err(|e| anyhow!("carol submit_group_join_request_impl: {e}"))?;
    assert_eq!(carol_result.status, "approved");
    assert_eq!(carol_result.group_id, group_id);

    sync_group_outbox_impl(&alice.state, group_id.clone(), None)
        .await
        .map_err(|e| anyhow!("alice sync after creation: {e}"))?;
    sync_group_outbox_impl(&bob.state, group_id.clone(), None)
        .await
        .map_err(|e| anyhow!("bob sync after creation: {e}"))?;
    sync_group_outbox_impl(&carol.state, group_id.clone(), None)
        .await
        .map_err(|e| anyhow!("carol sync after creation: {e}"))?;

    // Step 7: alice sends a text; bob/carol must see it after sync.
    send_group_text_message_impl(
        &alice.state,
        conversation_id.clone(),
        "hello desktop team".into(),
    )
    .await
    .map_err(|e| anyhow!("alice send_group_text_message_impl: {e}"))?;
    sync_group_outbox_impl(&bob.state, group_id.clone(), None)
        .await
        .ok();
    sync_group_outbox_impl(&carol.state, group_id.clone(), None)
        .await
        .ok();

    for (label, harness) in [("bob", &bob), ("carol", &carol)] {
        let messages = get_group_messages_impl(&harness.state, conversation_id.clone())
            .await
            .map_err(|e| anyhow!("{label} get_group_messages_impl: {e}"))?;
        assert!(
            has_bubble_with_plaintext(&messages, "hello desktop team"),
            "{label} did not see alice's text"
        );
    }

    // Step 8: alice updates metadata so invite links are accepted.
    update_group_metadata_impl(
        &alice.state,
        group_id.clone(),
        None,
        Some("approval_required".into()),
        None,
    )
    .await
    .map_err(|e| anyhow!("update_group_metadata_impl: {e}"))?;
    sync_group_outbox_impl(&alice.state, group_id.clone(), None)
        .await
        .ok();
    sync_group_outbox_impl(&bob.state, group_id.clone(), None)
        .await
        .ok();
    sync_group_outbox_impl(&carol.state, group_id.clone(), None)
        .await
        .ok();

    // Step 9: alice creates an invite link. Dana submits a join
    // request against the invite URL.
    let expires_at = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64)
        + 3_600_000;
    let invite = create_group_invite_link_impl(&alice.state, group_id.clone(), expires_at, None)
        .await
        .map_err(|e| anyhow!("create_group_invite_link_impl: {e}"))?;
    assert!(invite.invite_url.contains("/v1/group-invite/"));

    let dana = DesktopHarness::new(&ctx.dana_profile).await?;
    let dana_submit = submit_group_join_request_impl(&dana.state, invite.invite_url.clone())
        .await
        .map_err(|e| anyhow!("dana submit_group_join_request_impl: {e}"))?;
    assert_eq!(dana_submit.group_id, group_id);
    assert_eq!(dana_submit.status, "pending");
    let request_id = dana_submit.request_id.clone();

    // Step 10: alice approves.
    let approval = tokio::time::timeout(
        Duration::from_secs(30),
        approve_group_join_impl(&alice.state, group_id.clone(), request_id.clone()),
    )
    .await
    .context("approve_group_join_impl timed out after 30 seconds")?
    .map_err(|e| anyhow!("approve_group_join_impl: {e}"))?;

    // Step 11: dana imports the approved welcome pickup through the
    // same command boundary. The status-poll path is better kept as a
    // focused test; this full lifecycle should continue once approval
    // has produced a pickup for the joining device.
    let dana_pickup = approval
        .welcome_pickups
        .iter()
        .find(|pickup| pickup.device_id == ctx.dana_device_id)
        .map(|pickup| pickup.url.clone())
        .context("approval did not return dana welcome pickup")?;
    let dana_import = tokio::time::timeout(
        Duration::from_secs(30),
        submit_group_join_request_impl(&dana.state, dana_pickup),
    )
    .await
    .context("dana import approved welcome pickup timed out after 30 seconds")?
    .map_err(|e| anyhow!("dana import approved welcome pickup: {e}"))?;
    assert_eq!(dana_import.group_id, group_id);
    assert_eq!(dana_import.status, "approved");

    sync_group_outbox_impl(&dana.state, group_id.clone(), None)
        .await
        .ok();

    // Step 12: dana sends text; everyone receives.
    send_group_text_message_impl(
        &dana.state,
        conversation_id.clone(),
        "dana joins desktop".into(),
    )
    .await
    .map_err(|e| anyhow!("dana send_group_text_message_impl: {e}"))?;
    for harness in [&alice, &bob, &carol] {
        sync_group_outbox_impl(&harness.state, group_id.clone(), None)
            .await
            .ok();
    }
    for (label, harness) in [("alice", &alice), ("bob", &bob), ("carol", &carol)] {
        let messages = get_group_messages_impl(&harness.state, conversation_id.clone())
            .await
            .map_err(|e| anyhow!("{label} get_group_messages_impl (dana text): {e}"))?;
        assert!(
            has_bubble_with_plaintext(&messages, "dana joins desktop"),
            "{label} did not receive dana's text"
        );
    }

    // Step 13: alice removes carol; carol's subsequent send must fail
    // because her local role flips and `ensure_group_ready_for_send`
    // rejects.
    remove_group_member_impl(&alice.state, group_id.clone(), ctx.carol_user_id.clone())
        .await
        .map_err(|e| anyhow!("remove_group_member_impl: {e}"))?;
    sync_group_outbox_impl(&alice.state, group_id.clone(), None)
        .await
        .ok();
    sync_group_outbox_impl(&carol.state, group_id.clone(), None)
        .await
        .ok();
    let carol_send = send_group_text_message_impl(
        &carol.state,
        conversation_id.clone(),
        "carol post-remove".into(),
    )
    .await;
    assert!(
        carol_send.is_err(),
        "carol must fail-closed after removal but got Ok: {carol_send:?}"
    );

    // Step 14: alice dissolves the group.
    let dissolve = dissolve_group_impl(&alice.state, group_id.clone())
        .await
        .map_err(|e| anyhow!("dissolve_group_impl: {e}"))?;
    assert_eq!(dissolve.group_id, group_id);

    // Poll alice until her `dissolved_at` flips to Some (server ack
    // of the SealGroupOutbox effect).
    let mut alice_dissolved_at: Option<u64> = None;
    for _ in 0..20 {
        let snapshot = get_group_snapshot_impl(&alice.state, group_id.clone())
            .await
            .map_err(|e| anyhow!("alice get_group_snapshot_impl during dissolve poll: {e}"))?;
        if let Some(ts) = snapshot.dissolved_at {
            alice_dissolved_at = Some(ts);
            break;
        }
        sync_group_outbox_impl(&alice.state, group_id.clone(), None)
            .await
            .ok();
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let _alice_dissolved_at =
        alice_dissolved_at.context("alice dissolved_at never became Some within timeout")?;
    let alice_snapshot = get_group_snapshot_impl(&alice.state, group_id.clone())
        .await
        .map_err(|e| anyhow!("alice get_group_snapshot_impl post-dissolve: {e}"))?;
    assert_eq!(alice_snapshot.conversation_state, "dissolved");

    // (b) bob and dana should both see a ControlGroupDissolved system
    //     banner after their next sync.
    for _ in 0..20 {
        for harness in [&bob, &dana] {
            sync_group_outbox_impl(&harness.state, group_id.clone(), None)
                .await
                .ok();
        }
        let bob_messages = get_group_messages_impl(&bob.state, conversation_id.clone())
            .await
            .map_err(|e| anyhow!("bob get_group_messages_impl post-dissolve: {e}"))?;
        let dana_messages = get_group_messages_impl(&dana.state, conversation_id.clone())
            .await
            .map_err(|e| anyhow!("dana get_group_messages_impl post-dissolve: {e}"))?;
        if has_system_banner(&bob_messages, "control_group_dissolved")
            && has_system_banner(&dana_messages, "control_group_dissolved")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let bob_messages = get_group_messages_impl(&bob.state, conversation_id.clone())
        .await
        .map_err(|e| anyhow!("final bob get_group_messages_impl: {e}"))?;
    let dana_messages = get_group_messages_impl(&dana.state, conversation_id.clone())
        .await
        .map_err(|e| anyhow!("final dana get_group_messages_impl: {e}"))?;
    assert!(
        has_system_banner(&bob_messages, "control_group_dissolved"),
        "bob did not receive control_group_dissolved banner"
    );
    assert!(
        has_system_banner(&dana_messages, "control_group_dissolved"),
        "dana did not receive control_group_dissolved banner"
    );

    // (c) bob + dana sends must return Err after dissolve.
    let bob_send = send_group_text_message_impl(
        &bob.state,
        conversation_id.clone(),
        "bob post-dissolve".into(),
    )
    .await;
    assert!(
        bob_send.is_err(),
        "bob must fail-closed after dissolve but got Ok: {bob_send:?}"
    );
    let dana_send = send_group_text_message_impl(
        &dana.state,
        conversation_id.clone(),
        "dana post-dissolve".into(),
    )
    .await;
    assert!(
        dana_send.is_err(),
        "dana must fail-closed after dissolve but got Ok: {dana_send:?}"
    );

    // (d) Raw HTTP POST to the append endpoint must not be accepted.
    // This request intentionally has no valid group capability; depending
    // on validation order it can fail before or at the sealed-state check.
    let append_url = format!(
        "{}/v1/groups/{}/outbox/messages",
        ctx.alice_bundle.inbox_http_endpoint.trim_end_matches('/'),
        urlencoding::encode(&group_id)
    );
    let client = reqwest::Client::new();
    let response = client
        .post(&append_url)
        .header("X-Tapchat-Group-Capability", "eyJub25zZW5zZSI6dHJ1ZX0=")
        .header("Content-Type", "application/json")
        .body("{}")
        .send()
        .await?;
    let http_response = (response.status(), response.text().await.unwrap_or_default());
    assert!(
        matches!(
            http_response.0,
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ),
        "append after dissolve must be rejected, got {}: {}",
        http_response.0,
        http_response.1
    );
    assert!(
        http_response.1.contains("invalid_capability") || http_response.1.contains("group_sealed"),
        "expected invalid_capability or group_sealed body, got: {}",
        http_response.1
    );

    // Step 15: list_group_conversations still includes the dissolved
    // group and shows the dissolved marker.
    let alice_list = list_group_conversations_impl(&alice.state)
        .await
        .map_err(|e| anyhow!("list_group_conversations_impl: {e}"))?;
    let entry = alice_list
        .iter()
        .find(|row| row.group_id == group_id)
        .context("alice list_group_conversations should still include dissolved group")?;
    assert_eq!(entry.conversation_state, "dissolved");
    assert!(
        entry.dissolved_at.is_some(),
        "dissolved_at must be set on sidebar row"
    );

    Ok(())
}

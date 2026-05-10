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

use anyhow::{Context, Result, anyhow};
use common::{
    bundle_auth, export_identity_bundle_to_path, read_json_file, repo_temp_dir, required_str,
    run_cli_json, with_tokio, workspace_root, write_json_file, write_mnemonic_file,
};
use reqwest::StatusCode;
use serde_json::Value;
use tapchat_core::model::{DeploymentBundle, IdentityBundle};
use tapchat_desktop_lib::AppState;
use tapchat_desktop_lib::test_support::{
    GroupMessageView, approve_group_join_impl, build_test_app_state_for_profile,
    create_group_conversation_impl, create_group_invite_link_impl, dissolve_group_impl,
    get_group_join_request_status_impl, get_group_messages_impl, get_group_snapshot_impl,
    leave_group_impl, list_group_conversations_impl, remove_group_member_impl,
    send_group_text_message_impl, set_group_admin_impl, submit_group_join_request_impl,
    sync_group_outbox_impl, transfer_group_ownership_impl, update_group_metadata_impl,
};
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
    let ctx = bootstrap_quartet("desktop-group-full")?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime for desktop_group_e2e")?;

    rt.block_on(run_lifecycle(&ctx))?;
    Ok(())
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
    approve_group_join_impl(&alice.state, group_id.clone(), request_id.clone())
        .await
        .map_err(|e| anyhow!("approve_group_join_impl: {e}"))?;
    sync_group_outbox_impl(&alice.state, group_id.clone(), None)
        .await
        .ok();
    sync_group_outbox_impl(&bob.state, group_id.clone(), None)
        .await
        .ok();
    sync_group_outbox_impl(&carol.state, group_id.clone(), None)
        .await
        .ok();

    // Step 11: dana polls until approval + import completes.
    let mut dana_status = None;
    for _ in 0..20 {
        let status =
            get_group_join_request_status_impl(&dana.state, group_id.clone(), request_id.clone())
                .await
                .map_err(|e| anyhow!("dana get_group_join_request_status_impl: {e}"))?;
        if status.status == "approved" && status.group_imported {
            dana_status = Some(status);
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let dana_status =
        dana_status.context("dana never observed approved + group_imported within timeout")?;
    assert_eq!(dana_status.group_id, group_id);

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

    // (d) Raw HTTP POST to the append endpoint must return 403 group_sealed.
    let append_url = format!(
        "{}/v1/groups/{}/outbox/messages",
        ctx.alice_bundle.inbox_http_endpoint.trim_end_matches('/'),
        urlencoding::encode(&group_id)
    );
    let http_response = with_tokio(|| async {
        let client = reqwest::Client::new();
        let response = client
            .post(&append_url)
            .header("X-Tapchat-Group-Capability", "eyJub25zZW5zZSI6dHJ1ZX0=")
            .header("Content-Type", "application/json")
            .body("{}")
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        Ok::<(StatusCode, String), anyhow::Error>((status, body))
    })?;
    assert_eq!(
        http_response.0,
        StatusCode::FORBIDDEN,
        "append after dissolve must return 403, got {}: {}",
        http_response.0,
        http_response.1
    );
    assert!(
        http_response.1.contains("group_sealed"),
        "expected response body to contain group_sealed, got: {}",
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

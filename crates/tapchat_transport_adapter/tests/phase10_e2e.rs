use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use tapchat_core::conversation::RecoveryStatus;
use tapchat_core::ffi_api::{AttachmentDescriptor, CoreCommand, CoreEvent};
use tapchat_core::identity::IdentityManager;
use tapchat_core::model::{
    ConversationKind, DeploymentBundle, DeviceContactProfile, DeviceRuntimeAuth, DeviceStatusKind,
    IdentityBundle,
};
use tapchat_transport_adapter::{CloudflareRuntimeHandle, CoreDriver};

const ALICE_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const BOB_MNEMONIC: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

struct PairContext {
    runtime: CloudflareRuntimeHandle,
    alice: CoreDriver,
    bob: CoreDriver,
    conversation_id: String,
    bob_user_id: String,
    bob_bundle: DeploymentBundle,
    bob_device_id: String,
    bob_auth: DeviceRuntimeAuth,
}

struct TrioContext {
    runtime: CloudflareRuntimeHandle,
    alice: CoreDriver,
    bob_phone: CoreDriver,
    bob_laptop: CoreDriver,
    conversation_id: String,
    alice_user_id: String,
    bob_user_id: String,
    bob_phone_device_id: String,
    bob_laptop_device_id: String,
    alice_bundle: DeploymentBundle,
    bob_phone_bundle: DeploymentBundle,
    bob_laptop_bundle: DeploymentBundle,
    bob_phone_auth: DeviceRuntimeAuth,
    bob_laptop_auth: DeviceRuntimeAuth,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn text_happy_path_and_reconnect_recovery_work() -> Result<()> {
    let mut ctx = setup_pair().await?;

    ctx.alice
        .run_command_until_idle(CoreCommand::SendTextMessage {
            conversation_id: ctx.conversation_id.clone(),
            plaintext: "hello bob".into(),
        })
        .await?;
    sync_bob(&mut ctx, "after-send").await?;

    let conversation = ctx
        .bob
        .engine()
        .conversation_state(&ctx.conversation_id)
        .context("bob conversation missing after first text")?;
    assert!(conversation
        .messages
        .iter()
        .any(|message| message.plaintext.as_deref() == Some("hello bob")));

    let sync_state = ctx
        .bob
        .engine()
        .sync_state(&ctx.bob_device_id)
        .context("bob sync state missing")?;
    assert!(sync_state.checkpoint.last_acked_seq > 0);

    let head = ctx.runtime.get_head(&ctx.bob_auth, &ctx.bob_device_id).await?;
    assert!(head.head_seq > 0);

    ctx.bob.close_realtime(&ctx.bob_device_id).await?;
    ctx.alice
        .run_command_until_idle(CoreCommand::SendTextMessage {
            conversation_id: ctx.conversation_id.clone(),
            plaintext: "after reconnect".into(),
        })
        .await?;
    sync_bob(&mut ctx, "reconnect").await?;

    let recovered = ctx
        .bob
        .engine()
        .conversation_state(&ctx.conversation_id)
        .context("bob conversation missing after reconnect")?;
    assert!(recovered
        .messages
        .iter()
        .any(|message| message.plaintext.as_deref() == Some("after reconnect")));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attachment_happy_path_uploads_and_downloads_blob() -> Result<()> {
    let mut ctx = setup_pair().await?;
    let temp_dir = tempfile::tempdir()?;
    let source_path = temp_dir.path().join("payload.bin");
    let original = b"transport attachment bytes".to_vec();
    tokio::fs::write(&source_path, &original).await?;

    ctx.alice
        .run_command_until_idle(CoreCommand::SendAttachmentMessage {
            conversation_id: ctx.conversation_id.clone(),
            attachment_descriptor: AttachmentDescriptor {
                source: source_path.to_string_lossy().to_string(),
                mime_type: "application/octet-stream".into(),
                size_bytes: original.len() as u64,
                file_name: Some("payload.bin".into()),
            },
        })
        .await?;
    sync_bob(&mut ctx, "after-attachment").await?;

    let conversation = ctx
        .bob
        .engine()
        .conversation_state(&ctx.conversation_id)
        .context("bob conversation missing after attachment")?;
    let attachment_message = conversation
        .messages
        .iter()
        .find(|message| !message.storage_refs.is_empty())
        .context("attachment message not found")?;
    assert!(attachment_message
        .plaintext
        .as_deref()
        .unwrap_or_default()
        .contains("payload.bin"));

    let attachment_message_id = attachment_message.message_id.clone();
    let attachment_reference = attachment_message.storage_refs[0].object_ref.clone();
    let raw_blob = reqwest::get(&attachment_reference).await?.bytes().await?;
    assert_ne!(raw_blob.as_ref(), original.as_slice());
    let destination = temp_dir.path().join("downloaded.bin");
    ctx.bob
        .run_command_until_idle(CoreCommand::DownloadAttachment {
            conversation_id: ctx.conversation_id.clone(),
            message_id: attachment_message_id.clone(),
            reference: attachment_reference,
            destination: destination.to_string_lossy().to_string(),
        })
        .await?;

    let downloaded = tokio::fs::read(&destination).await?;
    assert_eq!(downloaded, original);

    let updated = ctx
        .bob
        .engine()
        .conversation_state(&ctx.conversation_id)
        .context("bob conversation missing after attachment download")?;
    let downloaded_message = updated
        .messages
        .iter()
        .find(|message| message.message_id == attachment_message_id)
        .context("downloaded attachment message not found")?;
    let blob_ciphertext = downloaded_message
        .downloaded_blob_b64
        .as_ref()
        .context("downloaded blob bytes missing")?;
    assert_eq!(STANDARD.decode(blob_ciphertext)?, raw_blob);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn identity_refresh_sees_new_device_in_runtime() -> Result<()> {
    let mut ctx = setup_trio().await?;

    let merged = publish_bob_bundle(&ctx, DeviceStatusKind::Active, DeviceStatusKind::Active).await?;
    assert_eq!(merged.devices.len(), 2);
    let runtime_bundle = ctx.runtime.get_identity_bundle(&ctx.bob_user_id).await?;
    assert_eq!(runtime_bundle.devices.len(), 2);
    refresh_alice_contact(&mut ctx).await?;

    let devices = ctx.alice.contact_devices(&ctx.bob_user_id);
    assert_eq!(devices.len(), 2);
    assert!(devices.iter().any(|device| device.device_id == ctx.bob_laptop_device_id));
    assert!(devices.iter().any(|device| {
        device.device_id == ctx.bob_phone_device_id && device.status == DeviceStatusKind::Active
    }));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconcile_emits_welcome_and_commit_for_new_device() -> Result<()> {
    let mut ctx = setup_trio().await?;

    publish_bob_bundle(&ctx, DeviceStatusKind::Active, DeviceStatusKind::Active).await?;
    ctx.alice.clear_recent_transport_activity();
    refresh_alice_contact(&mut ctx).await?;

    let pending = ctx.alice.pending_mls_artifacts(&ctx.conversation_id);
    assert!(
        pending.pending_welcome_count > 0
    );
    assert!(
        pending.pending_commit_count > 0
    );
    assert_eq!(
        ctx.alice.conversation_recovery_status(&ctx.conversation_id),
        Some(RecoveryStatus::NeedsRecovery)
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn new_device_ingests_welcome_and_joins_existing_conversation() -> Result<()> {
    let mut ctx = setup_trio().await?;
    add_bob_laptop_to_conversation(&mut ctx).await?;

    ctx.alice
        .run_command_until_idle(CoreCommand::SendTextMessage {
            conversation_id: ctx.conversation_id.clone(),
            plaintext: "hello laptop".into(),
        })
        .await?;
    sync_driver_until_stable(
        &mut ctx.bob_laptop,
        &ctx.runtime,
        &ctx.bob_laptop_auth,
        &ctx.bob_laptop_device_id,
        "laptop-joined-message",
    )
    .await?;

    let conversation = ctx
        .bob_laptop
        .engine()
        .conversation_state(&ctx.conversation_id)
        .context("bob laptop conversation missing after welcome ingest")?;
    assert!(conversation
        .messages
        .iter()
        .any(|message| message.plaintext.as_deref() == Some("hello laptop")));

    let members = ctx.alice.conversation_members(&ctx.conversation_id);
    assert!(members.iter().any(|member| member.device_id == ctx.bob_laptop_device_id));
    assert_eq!(
        ctx.alice.conversation_recovery_status(&ctx.conversation_id),
        Some(RecoveryStatus::Healthy)
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoke_shrinks_membership_and_stops_delivery_to_old_device() -> Result<()> {
    let mut ctx = setup_trio().await?;
    add_bob_laptop_to_conversation(&mut ctx).await?;

    ctx.bob_phone
        .run_command_until_idle(CoreCommand::ApplyLocalDeviceStatusUpdate {
            status: DeviceStatusKind::Revoked,
        })
        .await?;
    publish_bob_bundle(&ctx, DeviceStatusKind::Revoked, DeviceStatusKind::Active).await?;
    ctx.alice.clear_recent_transport_activity();
    refresh_alice_contact(&mut ctx).await?;

    let pending_after_revoke = ctx.alice.pending_mls_artifacts(&ctx.conversation_id);
    assert_eq!(pending_after_revoke.pending_welcome_count, 0);
    assert!(pending_after_revoke.pending_commit_count > 0);

    sync_driver_until_stable(
        &mut ctx.bob_phone,
        &ctx.runtime,
        &ctx.bob_phone_auth,
        &ctx.bob_phone_device_id,
        "phone-remove-commit",
    )
    .await?;
    ctx.alice
        .run_command_until_idle(CoreCommand::ReconcileConversationMembership {
            conversation_id: ctx.conversation_id.clone(),
        })
        .await?;
    let phone_head_before = ctx
        .runtime
        .get_head(&ctx.bob_phone_auth, &ctx.bob_phone_device_id)
        .await?
        .head_seq;

    ctx.alice
        .run_command_until_idle(CoreCommand::SendTextMessage {
            conversation_id: ctx.conversation_id.clone(),
            plaintext: "post revoke".into(),
        })
        .await?;
    sync_driver_until_stable(
        &mut ctx.bob_laptop,
        &ctx.runtime,
        &ctx.bob_laptop_auth,
        &ctx.bob_laptop_device_id,
        "laptop-post-revoke",
    )
    .await?;
    sync_driver_until_stable(
        &mut ctx.bob_phone,
        &ctx.runtime,
        &ctx.bob_phone_auth,
        &ctx.bob_phone_device_id,
        "phone-post-revoke",
    )
    .await?;

    let phone_head_after = ctx
        .runtime
        .get_head(&ctx.bob_phone_auth, &ctx.bob_phone_device_id)
        .await?
        .head_seq;
    assert_eq!(phone_head_after, phone_head_before);

    let laptop_conversation = ctx
        .bob_laptop
        .engine()
        .conversation_state(&ctx.conversation_id)
        .context("bob laptop conversation missing after revoke send")?;
    assert!(laptop_conversation
        .messages
        .iter()
        .any(|message| message.plaintext.as_deref() == Some("post revoke")));

    let phone_conversation = ctx
        .bob_phone
        .engine()
        .conversation_state(&ctx.conversation_id)
        .context("bob phone conversation missing after revoke")?;
    assert!(!phone_conversation
        .messages
        .iter()
        .any(|message| message.plaintext.as_deref() == Some("post revoke")));

    let members = ctx.alice.conversation_members(&ctx.conversation_id);
    assert!(
        members.iter().any(|member| {
            member.device_id == ctx.bob_phone_device_id && member.status == DeviceStatusKind::Revoked
        }) || members.iter().all(|member| member.device_id != ctx.bob_phone_device_id)
    );
    assert_eq!(
        ctx.alice.conversation_recovery_status(&ctx.conversation_id),
        Some(RecoveryStatus::Healthy)
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delayed_welcome_delivery_recovers_after_sync_and_reconcile() -> Result<()> {
    let mut ctx = setup_trio().await?;

    publish_bob_bundle(&ctx, DeviceStatusKind::Active, DeviceStatusKind::Active).await?;
    refresh_alice_contact(&mut ctx).await?;
    assert_eq!(
        ctx.alice.conversation_recovery_status(&ctx.conversation_id),
        Some(RecoveryStatus::NeedsRecovery)
    );
    assert!(ctx
        .bob_laptop
        .engine()
        .conversation_state(&ctx.conversation_id)
        .is_none());

    sync_driver_until_stable(
        &mut ctx.bob_laptop,
        &ctx.runtime,
        &ctx.bob_laptop_auth,
        &ctx.bob_laptop_device_id,
        "delayed-welcome",
    )
    .await?;
    ctx.alice
        .run_command_until_idle(CoreCommand::ReconcileConversationMembership {
            conversation_id: ctx.conversation_id.clone(),
        })
        .await?;

    assert!(ctx
        .bob_laptop
        .engine()
        .conversation_state(&ctx.conversation_id)
        .is_some());
    assert_eq!(
        ctx.alice.conversation_recovery_status(&ctx.conversation_id),
        Some(RecoveryStatus::Healthy)
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_from_snapshot_during_recovery_resumes_and_converges() -> Result<()> {
    let mut ctx = setup_trio().await?;

    publish_bob_bundle(&ctx, DeviceStatusKind::Active, DeviceStatusKind::Active).await?;
    refresh_alice_contact(&mut ctx).await?;
    assert_eq!(
        ctx.alice.conversation_recovery_status(&ctx.conversation_id),
        Some(RecoveryStatus::NeedsRecovery)
    );

    let snapshot = ctx
        .alice
        .latest_snapshot()
        .cloned()
        .context("alice recovery snapshot missing")?;
    let mut restored = CoreDriver::from_snapshot(snapshot, Some(ctx.runtime.base_url().to_string()))?;
    restored.inject_event_until_idle(CoreEvent::AppStarted).await?;
    ctx.alice = restored;

    sync_driver_until_stable(
        &mut ctx.bob_laptop,
        &ctx.runtime,
        &ctx.bob_laptop_auth,
        &ctx.bob_laptop_device_id,
        "restart-recovery-laptop",
    )
    .await?;
    ctx.alice
        .run_command_until_idle(CoreCommand::ReconcileConversationMembership {
            conversation_id: ctx.conversation_id.clone(),
        })
        .await?;

    assert!(ctx
        .bob_laptop
        .engine()
        .conversation_state(&ctx.conversation_id)
        .is_some());
    assert_eq!(
        ctx.alice.conversation_recovery_status(&ctx.conversation_id),
        Some(RecoveryStatus::Healthy)
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn corrupted_snapshot_marks_conversation_needs_rebuild_in_runtime() -> Result<()> {
    let mut ctx = setup_pair().await?;

    ctx.alice
        .run_command_until_idle(CoreCommand::SendTextMessage {
            conversation_id: ctx.conversation_id.clone(),
            plaintext: "before corruption".into(),
        })
        .await?;
    sync_bob(&mut ctx, "before-corruption").await?;

    let mut snapshot = ctx
        .alice
        .latest_snapshot()
        .cloned()
        .context("alice snapshot missing for corruption test")?;
    snapshot
        .mls_states
        .first_mut()
        .context("missing persisted mls state")?
        .serialized_group_state = Some("{broken".into());

    let restored = CoreDriver::from_snapshot(snapshot, Some(ctx.runtime.base_url().to_string()))?;
    assert_eq!(
        restored.conversation_recovery_status(&ctx.conversation_id),
        Some(RecoveryStatus::NeedsRebuild)
    );
    assert_eq!(
        restored
            .engine()
            .conversation_state(&ctx.conversation_id)
            .context("conversation missing after corruption restore")?
            .conversation
            .state,
        tapchat_core::model::ConversationState::NeedsRebuild
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebuild_command_recreates_direct_conversation_and_recovers() -> Result<()> {
    let mut ctx = setup_pair().await?;

    ctx.alice
        .run_command_until_idle(CoreCommand::SendTextMessage {
            conversation_id: ctx.conversation_id.clone(),
            plaintext: "before rebuild".into(),
        })
        .await?;
    sync_bob(&mut ctx, "before-rebuild").await?;

    let mut snapshot = ctx
        .alice
        .latest_snapshot()
        .cloned()
        .context("alice snapshot missing for rebuild test")?;
    snapshot
        .mls_states
        .first_mut()
        .context("missing persisted mls state")?
        .serialized_group_state = Some("{broken".into());
    ctx.alice = CoreDriver::from_snapshot(snapshot, Some(ctx.runtime.base_url().to_string()))?;
    assert_eq!(
        ctx.alice.conversation_recovery_status(&ctx.conversation_id),
        Some(RecoveryStatus::NeedsRebuild)
    );

    ctx.alice
        .run_command_until_idle(CoreCommand::RebuildConversation {
            conversation_id: ctx.conversation_id.clone(),
        })
        .await?;
    ctx.bob
        .run_command_until_idle(CoreCommand::RotateLocalKeyPackage)
        .await?;
    let refreshed_bob_bundle = publish_local_identity_bundle(
        &ctx.bob,
        &concrete_deployment_bundle(&ctx.bob_bundle, &ctx.bob_user_id),
    )?;
    ctx.runtime
        .put_identity_bundle(&ctx.bob_auth, &refreshed_bob_bundle)
        .await?;
    ctx.alice
        .run_command_until_idle(CoreCommand::RefreshIdentityState {
            user_id: ctx.bob_user_id.clone(),
        })
        .await?;
    ctx.alice.clear_recent_transport_activity();
    ctx.alice
        .run_command_until_idle(CoreCommand::ReconcileConversationMembership {
            conversation_id: ctx.conversation_id.clone(),
        })
        .await?;

    sync_bob(&mut ctx, "after-rebuild-welcome").await?;
    ctx.alice
        .run_command_until_idle(CoreCommand::ReconcileConversationMembership {
            conversation_id: ctx.conversation_id.clone(),
        })
        .await?;
    assert_eq!(
        ctx.alice.conversation_recovery_status(&ctx.conversation_id),
        Some(RecoveryStatus::Healthy)
    );

    ctx.alice
        .run_command_until_idle(CoreCommand::SendTextMessage {
            conversation_id: ctx.conversation_id.clone(),
            plaintext: "after rebuild".into(),
        })
        .await?;
    sync_bob(&mut ctx, "after-rebuild-message").await?;

    let conversation = ctx
        .bob
        .engine()
        .conversation_state(&ctx.conversation_id)
        .context("bob conversation missing after rebuild recovery")?;
    assert!(conversation
        .messages
        .iter()
        .any(|message| message.plaintext.as_deref() == Some("after rebuild")));

    Ok(())
}

async fn sync_bob(ctx: &mut PairContext, reason: &str) -> Result<()> {
    sync_driver_until_stable(&mut ctx.bob, &ctx.runtime, &ctx.bob_auth, &ctx.bob_device_id, reason).await
}

async fn setup_pair() -> Result<PairContext> {
    let workspace_root = workspace_root();
    let runtime = CloudflareRuntimeHandle::start(&workspace_root).await?;
    let mut alice = CoreDriver::new_with_storage_base(Some(runtime.base_url().to_string()))?;
    let mut bob = CoreDriver::new_with_storage_base(Some(runtime.base_url().to_string()))?;

    alice
        .run_command_until_idle(CoreCommand::CreateOrLoadIdentity {
            mnemonic: Some(ALICE_MNEMONIC.into()),
            device_name: Some("phone".into()),
        })
        .await?;
    bob
        .run_command_until_idle(CoreCommand::CreateOrLoadIdentity {
            mnemonic: Some(BOB_MNEMONIC.into()),
            device_name: Some("phone".into()),
        })
        .await?;

    let alice_user_id = IdentityManager::recover_user_root(ALICE_MNEMONIC)?.user_identity.user_id;
    let bob_user_id = IdentityManager::recover_user_root(BOB_MNEMONIC)?.user_identity.user_id;
    let alice_device_id = alice.engine().local_device_id().context("alice device id")?.to_string();
    let bob_device_id = bob.engine().local_device_id().context("bob device id")?.to_string();

    let alice_bundle = runtime.bootstrap_device_bundle(&alice_user_id, &alice_device_id).await?;
    let bob_bundle = runtime.bootstrap_device_bundle(&bob_user_id, &bob_device_id).await?;

    alice
        .run_command_until_idle(CoreCommand::ImportDeploymentBundle {
            bundle: alice_bundle.clone(),
        })
        .await?;
    bob
        .run_command_until_idle(CoreCommand::ImportDeploymentBundle {
            bundle: bob_bundle.clone(),
        })
        .await?;

    let alice_local_bundle = publish_local_identity_bundle(
        &alice,
        &concrete_deployment_bundle(&alice_bundle, &alice_user_id),
    )?;
    let bob_local_bundle = publish_local_identity_bundle(
        &bob,
        &concrete_deployment_bundle(&bob_bundle, &bob_user_id),
    )?;
    let alice_auth = alice_bundle.device_runtime_auth.clone().context("alice device auth")?;
    let bob_auth = bob_bundle.device_runtime_auth.clone().context("bob device auth")?;

    runtime.put_identity_bundle(&alice_auth, &alice_local_bundle).await?;
    runtime.put_identity_bundle(&bob_auth, &bob_local_bundle).await?;

    alice
        .run_command_until_idle(CoreCommand::ImportIdentityBundle {
            bundle: bob_local_bundle.clone(),
        })
        .await?;
    bob
        .run_command_until_idle(CoreCommand::ImportIdentityBundle {
            bundle: alice_local_bundle.clone(),
        })
        .await?;

    let created = alice
        .run_command_until_idle(CoreCommand::CreateConversation {
            peer_user_id: bob_user_id.clone(),
            conversation_kind: ConversationKind::Direct,
        })
        .await?;
    let conversation_id = created
        .view_model
        .as_ref()
        .and_then(|model| model.conversations.first())
        .map(|summary| summary.conversation_id.clone())
        .context("conversation id missing")?;

    sync_bob_inner(&mut bob, &runtime, &bob_auth, &bob_device_id, "initial").await?;

    Ok(PairContext {
        runtime,
        alice,
        bob,
        conversation_id,
        bob_user_id,
        bob_bundle,
        bob_device_id,
        bob_auth,
    })
}

async fn setup_trio() -> Result<TrioContext> {
    let pair = setup_pair().await?;
    let PairContext {
        runtime,
        alice,
        bob,
        conversation_id,
        bob_device_id,
        bob_auth,
        ..
    } = pair;

    let mut bob_laptop = CoreDriver::new_with_storage_base(Some(runtime.base_url().to_string()))?;
    let public_bundle = public_deployment_bundle(
        alice.engine().local_bundle().context("alice local bundle for trio")?,
        &runtime,
    )?;
    bob_laptop
        .run_command_until_idle(CoreCommand::ImportDeploymentBundle {
            bundle: public_bundle,
        })
        .await?;
    bob_laptop
        .run_command_until_idle(CoreCommand::CreateAdditionalDeviceIdentity {
            mnemonic: Some(BOB_MNEMONIC.into()),
            device_name: Some("laptop".into()),
        })
        .await?;

    let alice_user_id = IdentityManager::recover_user_root(ALICE_MNEMONIC)?.user_identity.user_id;
    let bob_user_id = IdentityManager::recover_user_root(BOB_MNEMONIC)?.user_identity.user_id;
    let bob_laptop_device_id = bob_laptop
        .engine()
        .local_device_id()
        .context("bob laptop device id")?
        .to_string();
    let bob_laptop_bundle = runtime
        .bootstrap_device_bundle(&bob_user_id, &bob_laptop_device_id)
        .await?;
    let alice_bundle = runtime
        .bootstrap_device_bundle(&alice_user_id, alice.engine().local_device_id().context("alice device")?)
        .await?;
    let bob_phone_bundle = runtime
        .bootstrap_device_bundle(&bob_user_id, &bob_device_id)
        .await?;
    bob_laptop
        .run_command_until_idle(CoreCommand::ImportDeploymentBundle {
            bundle: bob_laptop_bundle.clone(),
        })
        .await?;
    bob_laptop
        .run_command_until_idle(CoreCommand::ImportIdentityBundle {
            bundle: publish_local_identity_bundle(
                &alice,
                &concrete_deployment_bundle(&alice_bundle, &alice_user_id),
            )?,
        })
        .await?;
    let bob_laptop_auth = bob_laptop_bundle
        .device_runtime_auth
        .clone()
        .context("bob laptop auth")?;

    Ok(TrioContext {
        runtime,
        alice,
        bob_phone: bob,
        bob_laptop,
        conversation_id,
        alice_user_id,
        bob_user_id,
        bob_phone_device_id: bob_device_id,
        bob_laptop_device_id,
        alice_bundle,
        bob_phone_bundle,
        bob_laptop_bundle,
        bob_phone_auth: bob_auth,
        bob_laptop_auth,
    })
}

async fn add_bob_laptop_to_conversation(ctx: &mut TrioContext) -> Result<()> {
    publish_bob_bundle(ctx, DeviceStatusKind::Active, DeviceStatusKind::Active).await?;
    refresh_alice_contact(ctx).await?;
    ctx.alice
        .run_command_until_idle(CoreCommand::ReconcileConversationMembership {
            conversation_id: ctx.conversation_id.clone(),
        })
        .await?;
    sync_driver_until_stable(
        &mut ctx.bob_laptop,
        &ctx.runtime,
        &ctx.bob_laptop_auth,
        &ctx.bob_laptop_device_id,
        "laptop-join",
    )
    .await?;
    ctx.alice
        .run_command_until_idle(CoreCommand::ReconcileConversationMembership {
            conversation_id: ctx.conversation_id.clone(),
        })
        .await?;
    Ok(())
}

async fn refresh_alice_contact(ctx: &mut TrioContext) -> Result<()> {
    ctx.alice
        .run_command_until_idle(CoreCommand::RefreshIdentityState {
            user_id: ctx.bob_user_id.clone(),
        })
        .await?;
    Ok(())
}

async fn publish_bob_bundle(
    ctx: &TrioContext,
    phone_status: DeviceStatusKind,
    laptop_status: DeviceStatusKind,
) -> Result<IdentityBundle> {
    let mut phone_profile = ctx
        .bob_phone
        .engine()
        .local_bundle()
        .context("bob phone local bundle")?
        .devices[0]
        .clone();
    phone_profile.status = phone_status;

    let mut laptop_profile = ctx
        .bob_laptop
        .engine()
        .local_bundle()
        .context("bob laptop local bundle")?
        .devices[0]
        .clone();
    laptop_profile.status = laptop_status;

    let merged = IdentityManager::export_identity_bundle_with_devices(
        ctx.bob_laptop
            .engine()
            .local_identity()
            .context("bob laptop local identity")?,
        &concrete_deployment_bundle(&ctx.bob_laptop_bundle, &ctx.bob_user_id),
        vec![phone_profile, laptop_profile],
    )?;
    ctx.runtime
        .put_identity_bundle(&ctx.bob_laptop_auth, &merged)
        .await?;
    Ok(merged)
}

fn publish_local_identity_bundle(
    driver: &CoreDriver,
    deployment: &DeploymentBundle,
) -> Result<IdentityBundle> {
    let local_identity = driver
        .engine()
        .local_identity()
        .context("local identity missing for publish")?;
    let devices = driver
        .engine()
        .local_bundle()
        .context("local bundle missing for publish")?
        .devices
        .clone();
    publish_identity_bundle_with_devices(local_identity, deployment, devices)
}

fn publish_identity_bundle_with_devices(
    local_identity: &tapchat_core::identity::LocalIdentityState,
    deployment: &DeploymentBundle,
    devices: Vec<DeviceContactProfile>,
) -> Result<IdentityBundle> {
    Ok(IdentityManager::export_identity_bundle_with_devices(
        local_identity,
        deployment,
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

fn public_deployment_bundle(
    source_bundle: &IdentityBundle,
    runtime: &CloudflareRuntimeHandle,
) -> Result<DeploymentBundle> {
    let bundle = source_bundle;
    let identity_ref = bundle
        .identity_bundle_ref
        .clone()
        .context("identity bundle ref missing")?;
    let device_status_ref = bundle
        .device_status_ref
        .clone()
        .context("device status ref missing")?;
    Ok(DeploymentBundle {
        version: tapchat_core::model::CURRENT_MODEL_VERSION.to_string(),
        region: "local-transport".into(),
        inbox_http_endpoint: runtime.base_url().to_string(),
        inbox_websocket_endpoint: format!("{}/v1/inbox/{{deviceId}}/subscribe", runtime.websocket_base_url()),
        storage_base_info: tapchat_core::model::StorageBaseInfo {
            base_url: Some(runtime.base_url().to_string()),
            bucket_hint: Some("tapchat-storage".into()),
        },
        runtime_config: tapchat_core::model::RuntimeConfig {
            supported_realtime_kinds: vec![tapchat_core::model::RealtimeKind::Websocket],
            identity_bundle_ref: Some(identity_ref),
            device_status_ref: Some(device_status_ref),
            keypackage_ref_base: Some(format!("{}/v1/shared-state/keypackages", runtime.base_url())),
            max_inline_bytes: Some(4096),
            features: vec!["generic_sync".into(), "attachment_v1".into()],
        },
        device_runtime_auth: None,
        expected_user_id: None,
        expected_device_id: None,
    })
}

async fn sync_bob_inner(
    bob: &mut CoreDriver,
    runtime: &CloudflareRuntimeHandle,
    auth: &DeviceRuntimeAuth,
    device_id: &str,
    reason: &str,
) -> Result<()> {
    sync_driver_until_stable(bob, runtime, auth, device_id, reason).await
}

async fn sync_driver_until_stable(
    driver: &mut CoreDriver,
    runtime: &CloudflareRuntimeHandle,
    auth: &DeviceRuntimeAuth,
    device_id: &str,
    reason: &str,
) -> Result<()> {
    for attempt in 0..6 {
        driver
            .run_command_until_idle(CoreCommand::SyncInbox {
                device_id: device_id.to_string(),
                reason: Some(format!("{reason}-{attempt}")),
            })
            .await?;
        let head = runtime.get_head(auth, device_id).await?.head_seq;
        let sync_state = driver.engine().sync_state(device_id).context("sync state missing after sync")?;
        if sync_state.checkpoint.last_acked_seq >= head {
            return Ok(());
        }
    }
    let head = runtime.get_head(auth, device_id).await?.head_seq;
    let sync_state = driver.engine().sync_state(device_id).context("sync state missing after retries")?;
    bail!(
        "sync did not stabilize for {device_id}; head_seq={head}, acked_seq={}, pending_records={}",
        sync_state.checkpoint.last_acked_seq,
        sync_state.pending_records.len()
    )
}

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}

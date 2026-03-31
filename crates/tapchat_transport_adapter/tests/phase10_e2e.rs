use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use tapchat_core::ffi_api::{AttachmentDescriptor, CoreCommand};
use tapchat_core::identity::IdentityManager;
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
    bob_device_id: String,
    bob_auth: tapchat_core::model::DeviceRuntimeAuth,
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

    let alice_local_bundle = alice.engine().local_bundle().context("alice local bundle")?.clone();
    let bob_local_bundle = bob.engine().local_bundle().context("bob local bundle")?.clone();
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
            peer_user_id: bob_user_id,
            conversation_kind: tapchat_core::model::ConversationKind::Direct,
        })
        .await?;
    let conversation_id = created
        .view_model
        .as_ref()
        .and_then(|model| model.conversations.first())
        .map(|summary| summary.conversation_id.clone())
        .context("conversation id missing")?;

    let head_after_create = runtime.get_head(&bob_auth, &bob_device_id).await?;
    assert!(
        head_after_create.head_seq > 0,
        "alice create conversation did not append transport messages; notifications={:?}; timers={:?}",
        alice.notifications(),
        alice.scheduled_timers()
    );

    sync_bob_inner(&mut bob, &runtime, &bob_auth, &bob_device_id, "initial").await?;

    Ok(PairContext {
        runtime,
        alice,
        bob,
        conversation_id,
        bob_device_id,
        bob_auth,
    })
}

async fn sync_bob_inner(
    bob: &mut CoreDriver,
    runtime: &CloudflareRuntimeHandle,
    auth: &tapchat_core::model::DeviceRuntimeAuth,
    device_id: &str,
    reason: &str,
) -> Result<()> {
    sync_driver_until_stable(bob, runtime, auth, device_id, reason).await
}

async fn sync_driver_until_stable(
    driver: &mut CoreDriver,
    runtime: &CloudflareRuntimeHandle,
    auth: &tapchat_core::model::DeviceRuntimeAuth,
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
    anyhow::bail!(
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




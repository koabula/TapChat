mod common;

use anyhow::{anyhow, Context, Result};
use common::{
    binary_path, bundle_auth, export_identity_bundle_to_path, read_json_file, repo_temp_dir,
    required_str, run_cli_json, with_tokio, workspace_root, write_json_file, write_mnemonic_file,
};
use tapchat_core::cli::profile::{Profile, RuntimeMetadata};
use tapchat_core::desktop_app;
use tapchat_core::external_fetch::{assess_external_url, ExternalResourceKind};
use tapchat_core::model::{IdentityBundle, MessageType};
use tapchat_transport_adapter::CloudflareRuntimeHandle;

const ALICE_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const BOB_MNEMONIC: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

#[test]
fn desktop_message_request_accept_syncs_promoted_messages_and_preserves_plaintext() -> Result<()> {
    let workspace_root = workspace_root();
    let runtime = with_tokio(|| async { CloudflareRuntimeHandle::start(&workspace_root).await })?;
    let temp_root = repo_temp_dir("desktop-message-request")?;
    let registry_path = temp_root
        .path()
        .join("desktop-message-request.profiles.json");
    unsafe {
        std::env::set_var("TAPCHAT_PROFILE_REGISTRY_PATH", &registry_path);
    }
    let alice_profile = temp_root.path().join("alice");
    let bob_profile = temp_root.path().join("bob");

    let alice_mnemonic =
        write_mnemonic_file(temp_root.path(), "alice-mnemonic.txt", ALICE_MNEMONIC)?;
    let bob_mnemonic = write_mnemonic_file(temp_root.path(), "bob-mnemonic.txt", BOB_MNEMONIC)?;

    run_cli_json(
        &registry_path,
        [
            "profile",
            "init",
            "--no-keychain",
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
            "--no-keychain",
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
        runtime
            .bootstrap_device_bundle(&alice_user_id, &alice_device_id)
            .await
    })?;
    let bob_bundle = with_tokio(|| async {
        runtime
            .bootstrap_device_bundle(&bob_user_id, &bob_device_id)
            .await
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
    for profile_path in [&alice_profile, &bob_profile] {
        let profile = Profile::open(profile_path)?;
        profile.save_runtime_metadata(&RuntimeMetadata {
            base_url: Some(runtime.base_url().to_string()),
            websocket_base_url: Some(runtime.websocket_base_url().to_string()),
            bootstrap_secret: Some(runtime.bootstrap_secret().to_string()),
            sharing_secret: Some(runtime.sharing_secret().to_string()),
            ..RuntimeMetadata::default()
        })?;
    }

    let alice_identity_path = export_identity_bundle_to_path(
        &registry_path,
        temp_root.path(),
        &alice_profile,
        "alice-identity.json",
    )?;
    let bob_identity_path = export_identity_bundle_to_path(
        &registry_path,
        temp_root.path(),
        &bob_profile,
        "bob-identity.json",
    )?;
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

    assert!(
        desktop_app::conversation_list(&bob_profile)?.is_empty(),
        "desktop accept should materialize the first conversation; it must not already exist"
    );

    let requests = with_tokio(|| async { desktop_app::message_requests_list(&bob_profile).await })?;
    assert_eq!(requests.len(), 1);
    let request_id = requests[0].request_id.clone();
    let request_share_url = requests[0]
        .sender_bundle_share_url
        .as_deref()
        .context("initial message request must include a sender share URL")?;
    let request_approval = with_tokio(|| async {
        Ok::<_, anyhow::Error>(
            assess_external_url(request_share_url, ExternalResourceKind::ContactShare)
                .await?
                .approve(),
        )
    })?;

    let accept = with_tokio(|| async {
        desktop_app::message_request_accept_with_approval(
            &bob_profile,
            &request_id,
            Some(request_approval),
        )
        .await
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

    with_tokio(|| async { desktop_app::sync_once(&alice_profile).await })?;

    with_tokio(|| async {
        desktop_app::message_send_text(&alice_profile, &alice_conversation_id, "hello after accept")
            .await
    })?;
    with_tokio(|| async { desktop_app::sync_once(&bob_profile).await })?;

    let bob_messages = desktop_app::message_list(&bob_profile, &bob_conversation_id)?;
    assert_has_plaintext_application(&bob_messages, "hello after accept")?;

    with_tokio(|| async {
        desktop_app::message_send_text(&bob_profile, &bob_conversation_id, "reply from bob").await
    })?;
    with_tokio(|| async { desktop_app::sync_once(&alice_profile).await })?;

    let alice_messages = desktop_app::message_list(&alice_profile, &alice_conversation_id)?;
    assert_has_plaintext_application(&alice_messages, "reply from bob")?;

    with_tokio(|| async { desktop_app::contact_delete(&alice_profile, &bob_user_id).await })?;
    with_tokio(|| async { desktop_app::sync_once(&bob_profile).await })?;

    let alice_share_link =
        with_tokio(|| async { desktop_app::contact_share_link_get(&alice_profile).await })?;
    let share_approval = with_tokio(|| async {
        Ok::<_, anyhow::Error>(
            assess_external_url(&alice_share_link.url, ExternalResourceKind::ContactShare)
                .await?
                .approve(),
        )
    })?;
    let bob_readd_conversation = with_tokio(|| async {
        desktop_app::contact_start_direct_from_share_link_with_approval(
            &bob_profile,
            &alice_share_link.url,
            Some(share_approval),
        )
        .await
    })?;
    let bob_readd_conversation_id = bob_readd_conversation.conversation_id.clone();

    let pending_send = with_tokio(|| async {
        desktop_app::message_send_text(
            &bob_profile,
            &bob_readd_conversation_id,
            "should wait for accept",
        )
        .await
    });
    assert!(
        pending_send.is_err(),
        "pending outbound direct chat must not allow user application messages"
    );

    let readd_requests =
        with_tokio(|| async { desktop_app::message_requests_list(&alice_profile).await })?;
    let readd_request = readd_requests
        .iter()
        .find(|request| request.sender_user_id == bob_user_id)
        .with_context(|| {
            format!(
                "expected Alice to receive Bob's re-add request, got {:?}",
                readd_requests
            )
        })?;
    assert_eq!(
        readd_request.last_conversation_id, bob_readd_conversation_id,
        "message request should point at the fresh re-add conversation"
    );
    let readd_share_url = readd_request
        .sender_bundle_share_url
        .as_deref()
        .context("re-add request must include a sender share URL")?;
    let readd_approval = with_tokio(|| async {
        Ok::<_, anyhow::Error>(
            assess_external_url(readd_share_url, ExternalResourceKind::ContactShare)
                .await?
                .approve(),
        )
    })?;

    let readd_accept = with_tokio(|| async {
        desktop_app::message_request_accept_with_approval(
            &alice_profile,
            &readd_request.request_id,
            Some(readd_approval),
        )
        .await
    })?;
    assert!(readd_accept.accepted);
    assert!(readd_accept.contact_available);
    assert!(
        readd_accept.conversation_available,
        "accept should not expose a direct chat until MLS state is complete"
    );
    let alice_readd_conversation_id = readd_accept
        .conversation_id
        .clone()
        .context("re-add accept should return the promoted conversation id")?;
    assert_eq!(alice_readd_conversation_id, bob_readd_conversation_id);

    with_tokio(|| async { desktop_app::sync_once(&bob_profile).await })?;
    with_tokio(|| async {
        desktop_app::message_send_text(
            &bob_profile,
            &bob_readd_conversation_id,
            "hello after re-add",
        )
        .await
    })?;
    with_tokio(|| async { desktop_app::sync_once(&alice_profile).await })?;

    let alice_readd_messages =
        desktop_app::message_list(&alice_profile, &alice_readd_conversation_id)?;
    assert_has_plaintext_application(&alice_readd_messages, "hello after re-add")?;

    // Silence the unused-import warning — these helpers are exercised
    // only when this test is stressed; keeping the binding lets the
    // common module surface dead-code in a single place.
    let _ = (binary_path(), alice_device_id, bob_device_id, alice_user_id);

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

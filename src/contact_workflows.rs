use anyhow::{anyhow, Context, Result};

use crate::cli::driver::CoreDriver;
use crate::cli::profile::Profile;
use crate::cli::util::to_snake_case_json_string;
use crate::contact_share::contact_share_url_user_id;
use crate::error::{CoreError, CoreResult};
use crate::external_fetch::{fetch_external_json, ExternalResourceKind};
use crate::ffi_api::{CoreCommand, CoreOutput, MessageRequestActionSummary, WelcomePreview};
use crate::identity::{parse_verifying_key, IdentityManager};
use crate::model::{DeviceStatusKind, IdentityBundle, Validate};
use crate::transport_contract::{MessageRequestAction, MessageRequestItem};

pub async fn import_identity_bundle_into_profile(
    profile: &mut Profile,
    driver: &mut CoreDriver,
    bundle: IdentityBundle,
) -> Result<IdentityBundle> {
    driver
        .run_command_until_idle(CoreCommand::ImportIdentityBundle {
            bundle: bundle.clone(),
        })
        .await?;
    profile.save_identity_bundle(
        &bundle,
        &format!("identity_{}.json", bundle.user_id.replace(':', "_")),
    )?;
    persist_driver(profile, driver)?;
    Ok(bundle)
}

pub async fn list_message_requests(driver: &mut CoreDriver) -> Result<Vec<MessageRequestItem>> {
    let output = driver
        .run_command_until_idle(CoreCommand::ListMessageRequests)
        .await?;
    Ok(message_requests_from_output(&output)?.clone())
}

pub async fn accept_message_request_with_bundle_import(
    profile: &mut Profile,
    driver: &mut CoreDriver,
    request_id: &str,
) -> Result<MessageRequestActionSummary> {
    let request = list_message_requests(driver)
        .await?
        .into_iter()
        .find(|item| item.request_id == request_id)
        .ok_or_else(|| anyhow!("message request not found"))?;
    let welcome_bytes = request
        .welcome_bytes
        .clone()
        .ok_or_else(|| anyhow!("message request is missing the Welcome that names the sender"))?;
    let preview = driver
        .run_command_until_idle(CoreCommand::PreviewWelcome { welcome_bytes })
        .await?;
    let preview = preview
        .view_model
        .as_ref()
        .and_then(|view| view.welcome_preview.clone())
        .ok_or_else(|| anyhow!("welcome preview was not returned by core"))?;
    let sender_bundle_share_url = preview
        .identity_bundle_ref
        .clone()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow!("the Welcome did not include an importable identity bundle"))?;
    let bundle = fetch_identity_bundle_from_url(&sender_bundle_share_url).await?;
    ensure_welcome_signed_by_bundle(&preview, &bundle)?;
    import_identity_bundle_into_profile(profile, driver, bundle).await?;
    let output = driver
        .run_command_until_idle(CoreCommand::ActOnMessageRequest {
            request_id: request_id.to_string(),
            action: MessageRequestAction::Accept,
        })
        .await?;
    persist_driver(profile, driver)?;
    let mut summary = message_request_action_from_output(&output)?.clone();
    if summary.sender_user_id.trim().is_empty() {
        summary.sender_user_id = preview.author_user_id;
    }
    Ok(summary)
}

/// Whether `bundle` belongs to whoever signed the Welcome that `preview`
/// describes. A request names its sender only inside the Welcome, and the
/// bundle comes from wherever the Welcome points, so neither is evidence on
/// its own: the Welcome is the bundle owner's only if the device key in the
/// bundle signed it. Checked before the bundle is imported, so a Welcome that
/// merely names someone leaves no contact behind.
pub fn ensure_welcome_signed_by_bundle(
    preview: &WelcomePreview,
    bundle: &IdentityBundle,
) -> CoreResult<()> {
    if bundle.user_id != preview.author_user_id {
        return Err(CoreError::invalid_input(
            "fetched identity bundle user_id does not match the Welcome author",
        ));
    }
    let device = bundle
        .devices
        .iter()
        .find(|device| {
            device.device_id == preview.author_device_id
                && matches!(device.status, DeviceStatusKind::Active)
        })
        .ok_or_else(|| {
            CoreError::invalid_input("the Welcome author is not an active device of the bundle")
        })?;
    let trusted = parse_verifying_key(&device.device_public_key)?;
    let signer = parse_verifying_key(&preview.author_device_public_key)?;
    if trusted.as_bytes() != signer.as_bytes() {
        return Err(CoreError::invalid_input(
            "the Welcome was not signed by the device key in the sender's bundle",
        ));
    }
    Ok(())
}

fn ensure_bundle_matches_link(bundle: &IdentityBundle, link_user_id: &str) -> CoreResult<()> {
    if bundle.user_id != link_user_id {
        return Err(CoreError::invalid_input(
            "fetched identity bundle belongs to a different user than the link names",
        ));
    }
    Ok(())
}

/// Fetches the identity bundle behind a contact share or identity bundle URL.
///
/// Every import from such a URL comes through here. The host behind the URL
/// is not trusted, and a bundle that verifies proves only that it is
/// consistent with itself, so it is accepted only as the bundle of the user
/// the URL names; otherwise the host would choose whose root key is pinned.
pub async fn fetch_identity_bundle_from_url(url: &str) -> Result<IdentityBundle> {
    let link_user_id = contact_share_url_user_id(url)?;
    let body = fetch_external_json(url, ExternalResourceKind::ContactShare)
        .await
        .map_err(anyhow::Error::from)?;
    let normalized = to_snake_case_json_string(&body).context("normalize contact share json")?;
    let mut bundle: IdentityBundle =
        serde_json::from_str(&normalized).context("decode contact share bundle")?;
    ensure_bundle_matches_link(&bundle, &link_user_id)?;
    if bundle.identity_bundle_ref.is_none() {
        bundle.identity_bundle_ref = Some(url.to_string());
    }
    bundle
        .validate()
        .map_err(|error| anyhow!(error.to_string()))?;
    IdentityManager::verify_identity_bundle(&bundle).map_err(|error| anyhow!(error.to_string()))?;
    Ok(bundle)
}

pub fn persist_driver(profile: &mut Profile, driver: &CoreDriver) -> Result<()> {
    if let Some(snapshot) = driver.latest_snapshot() {
        profile.save_snapshot(snapshot)?;
    }
    let user_id = driver
        .local_identity()
        .map(|identity| identity.user_identity.user_id.clone());
    let device_id = driver
        .local_identity()
        .map(|identity| identity.device_identity.device_id.clone());
    profile.update_identity(user_id, device_id)?;
    Ok(())
}

pub fn message_requests_from_output(output: &CoreOutput) -> Result<&Vec<MessageRequestItem>> {
    output
        .view_model
        .as_ref()
        .map(|view_model| &view_model.message_requests)
        .ok_or_else(|| anyhow!("message requests were not returned by core"))
}

pub fn message_request_action_from_output(
    output: &CoreOutput,
) -> Result<&MessageRequestActionSummary> {
    output
        .view_model
        .as_ref()
        .and_then(|view_model| view_model.message_request_action.as_ref())
        .ok_or_else(|| anyhow!("message request action was not returned by core"))
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    use super::{ensure_welcome_signed_by_bundle, fetch_identity_bundle_from_url};
    use crate::contact_share::encode_contact_share_url;
    use crate::ffi_api::WelcomePreview;
    use crate::identity::{IdentityManager, LocalIdentityState};
    use crate::mls_adapter::{MlsAdapter, PeerDeviceKeyPackage};
    use crate::model::IdentityBundle;

    const NAMED_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const IMPOSTOR_MNEMONIC: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";
    const RECEIVER_MNEMONIC: &str =
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";
    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn identity(mnemonic: &str) -> LocalIdentityState {
        IdentityManager::create_or_recover(Some(mnemonic), None).expect("root")
    }

    /// A bundle signed by the root key `mnemonic` recovers, as its host serves it.
    fn signed_bundle(mnemonic: &str) -> IdentityBundle {
        signed_bundle_of(&identity(mnemonic))
    }

    /// `identity`'s bundle, as its host serves it.
    fn signed_bundle_of(identity: &LocalIdentityState) -> IdentityBundle {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test clock")
            .as_millis() as u64;
        let package = MlsAdapter::generate_key_package(identity, now_ms).expect("key package");
        let mut deployment = crate::ffi_api::tests::tests::sample_deployment();
        deployment.runtime_config.identity_bundle_ref =
            Some("https://runtime.example/v1/shared-state/{userId}/identity-bundle".into());
        let bundle = IdentityManager::export_identity_bundle(
            identity,
            &deployment,
            package.key_package_b64,
            package.expires_at,
        )
        .expect("bundle");
        IdentityManager::verify_identity_bundle(&bundle).expect("the test bundle verifies");
        bundle
    }

    /// Answers one request with `body` as JSON; returns the server's base URL.
    fn serve_json_once(body: String) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let address = listener.local_addr().expect("server address");
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len(),
            )
            .expect("write response");
        });
        format!("http://{address}")
    }

    /// A base URL at which nothing listens.
    fn closed_base_url() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test port");
        let address = listener.local_addr().expect("test port address");
        drop(listener);
        format!("http://{address}")
    }

    fn share_link(base: &str, user_id: &str) -> String {
        encode_contact_share_url(base, SECRET, user_id, "share:1").expect("share URL")
    }

    fn bundle_link(base: &str, user_id: &str) -> String {
        let user_id = urlencoding::encode(user_id);
        format!("{base}/v1/shared-state/{user_id}/identity-bundle")
    }

    #[tokio::test]
    async fn fetch_rejects_a_valid_bundle_of_another_user_than_the_link_names() {
        let named = signed_bundle(NAMED_MNEMONIC);
        let impostor = signed_bundle(IMPOSTOR_MNEMONIC);
        assert_ne!(impostor.user_id, named.user_id);
        let served = serde_json::to_string(&impostor).expect("bundle json");
        for link in [
            share_link(&serve_json_once(served.clone()), &named.user_id),
            bundle_link(&serve_json_once(served.clone()), &named.user_id),
        ] {
            let error = fetch_identity_bundle_from_url(&link)
                .await
                .expect_err("a bundle of another user must be rejected");
            let message = error.to_string();
            assert!(message.contains("different user"), "{message}");
        }
    }

    #[tokio::test]
    async fn fetch_accepts_the_bundle_of_the_user_the_link_names() {
        let named = signed_bundle(NAMED_MNEMONIC);
        let served = serde_json::to_string(&named).expect("bundle json");
        for link in [
            share_link(&serve_json_once(served.clone()), &named.user_id),
            bundle_link(&serve_json_once(served.clone()), &named.user_id),
        ] {
            let fetched = fetch_identity_bundle_from_url(&link)
                .await
                .expect("the bundle of the named user is accepted");
            assert_eq!(fetched.user_id, named.user_id);
            assert_eq!(fetched.user_public_key, named.user_public_key);
        }
    }

    #[tokio::test]
    async fn fetch_rejects_a_link_that_names_no_user_before_any_request() {
        // Nothing listens at `base`, so a request would fail as a fetch error.
        let base = closed_base_url();
        let blank_user = format!("{base}/v1/shared-state/%20/identity-bundle");
        let bad_token = format!("{base}/v1/contact-share/not-a-token");
        for (link, expected) in [
            (blank_user, "does not name a user"),
            (bad_token, "token is malformed"),
        ] {
            let error = fetch_identity_bundle_from_url(&link)
                .await
                .expect_err("a link that names no user must be rejected");
            let message = error.to_string();
            assert!(message.contains(expected), "{link}: {message}");
        }
    }

    /// The preview the receiver's core shows for a Welcome `author` made to it.
    fn preview_of_welcome_from(author: &LocalIdentityState) -> WelcomePreview {
        let receiver = identity(RECEIVER_MNEMONIC);
        let (mut author_adapter, _) = MlsAdapter::bootstrap(author).expect("author adapter");
        let (receiver_adapter, receiver_package) =
            MlsAdapter::bootstrap(&receiver).expect("receiver adapter");
        let artifacts = author_adapter
            .create_conversation(
                &crate::model::random_opaque_id(),
                &[PeerDeviceKeyPackage {
                    user_id: receiver.user_identity.user_id.clone(),
                    device_id: receiver.device_identity.device_id.clone(),
                    device_public_key: receiver.device_identity.device_public_key.clone(),
                    key_package_b64: receiver_package.key_package_b64,
                }],
            )
            .expect("welcome");
        let inspection = receiver_adapter
            .inspect_welcome(&artifacts.welcomes[0].payload_b64)
            .expect("inspect");
        WelcomePreview {
            conversation_id: inspection.conversation_id,
            author_user_id: inspection.author_user_id,
            author_device_id: inspection.author_device_id,
            author_device_public_key: inspection.author_signature_key,
            identity_bundle_ref: inspection.identity_bundle_ref,
        }
    }

    #[test]
    fn a_welcome_is_accepted_with_the_bundle_whose_device_key_signed_it() {
        let named = identity(NAMED_MNEMONIC);
        let preview = preview_of_welcome_from(&named);
        ensure_welcome_signed_by_bundle(&preview, &signed_bundle_of(&named))
            .expect("the author's own bundle is accepted");
    }

    #[test]
    fn a_welcome_that_only_names_a_user_is_refused_with_that_users_bundle() {
        // The credential is a string the Welcome's maker chooses; the key that
        // signs the Welcome is not.
        let named = identity(NAMED_MNEMONIC);
        let mut preview = preview_of_welcome_from(&identity(IMPOSTOR_MNEMONIC));
        preview.author_user_id = named.user_identity.user_id.clone();
        preview.author_device_id = named.device_identity.device_id.clone();
        let error = ensure_welcome_signed_by_bundle(&preview, &signed_bundle_of(&named))
            .expect_err("a Welcome the named device did not sign must be refused");
        assert!(
            error.to_string().contains("not signed by the device key"),
            "{error}"
        );
    }

    #[test]
    fn a_bundle_of_another_user_than_the_welcome_names_is_refused() {
        let preview = preview_of_welcome_from(&identity(NAMED_MNEMONIC));
        let error = ensure_welcome_signed_by_bundle(&preview, &signed_bundle(IMPOSTOR_MNEMONIC))
            .expect_err("another user's bundle must be refused");
        assert!(
            error.to_string().contains("does not match the Welcome author"),
            "{error}"
        );
    }
}

use anyhow::{Context, Result, anyhow};

use crate::cli::driver::CoreDriver;
use crate::cli::profile::Profile;
use crate::cli::util::to_snake_case_json_string;
use crate::external_fetch::{ExternalResourceKind, fetch_external_json};
use crate::ffi_api::{CoreCommand, CoreOutput, MessageRequestActionSummary};
use crate::identity::IdentityManager;
use crate::model::{IdentityBundle, Validate};
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
    let sender_bundle_share_url = request.sender_bundle_share_url.clone().ok_or_else(|| {
        anyhow!(
            "sender bundle share url is missing; the request did not include an importable identity bundle"
        )
    })?;
    let bundle = fetch_identity_bundle_from_url(&sender_bundle_share_url).await?;
    ensure_fetched_bundle_matches_expected_sender(&bundle, &request.sender_user_id)?;
    import_identity_bundle_into_profile(profile, driver, bundle).await?;
    let output = driver
        .run_command_until_idle(CoreCommand::ActOnMessageRequest {
            request_id: request_id.to_string(),
            action: MessageRequestAction::Accept,
        })
        .await?;
    persist_driver(profile, driver)?;
    Ok(message_request_action_from_output(&output)?.clone())
}

fn ensure_fetched_bundle_matches_expected_sender(
    bundle: &IdentityBundle,
    expected_sender_user_id: &str,
) -> Result<()> {
    if bundle.user_id != expected_sender_user_id {
        return Err(anyhow!(
            "fetched identity bundle user_id does not match the message request's sender_user_id"
        ));
    }
    Ok(())
}

pub async fn fetch_identity_bundle_from_url(url: &str) -> Result<IdentityBundle> {
    let body = fetch_external_json(url, ExternalResourceKind::ContactShare)
        .await
        .map_err(anyhow::Error::from)?;
    let normalized = to_snake_case_json_string(&body).context("normalize contact share json")?;
    let mut bundle: IdentityBundle =
        serde_json::from_str(&normalized).context("decode contact share bundle")?;
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
    use super::ensure_fetched_bundle_matches_expected_sender;
    use crate::model::IdentityBundle;

    fn bundle_with_user_id(user_id: &str) -> IdentityBundle {
        serde_json::from_value(serde_json::json!({
            "version": "v1",
            "user_id": user_id,
            "user_public_key": "aa",
            "devices": [],
            "updated_at": 0,
            "signature": "sig",
        }))
        .expect("minimal identity bundle")
    }

    #[test]
    fn rejects_bundle_whose_user_id_does_not_match_expected_sender() {
        let bundle = bundle_with_user_id("user:alice");
        let error = ensure_fetched_bundle_matches_expected_sender(&bundle, "user:mallory")
            .expect_err("mismatched sender should be rejected");
        assert!(error.to_string().contains("does not match"));
    }

    #[test]
    fn accepts_bundle_whose_user_id_matches_expected_sender() {
        let bundle = bundle_with_user_id("user:alice");
        ensure_fetched_bundle_matches_expected_sender(&bundle, "user:alice")
            .expect("matching sender should be accepted");
    }
}

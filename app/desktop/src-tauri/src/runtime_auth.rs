use anyhow::{anyhow, Context, Result};
use tapchat_core::cli::runtime::bootstrap_device_bundle_with_key_id;
use tapchat_core::model::{
    DeploymentBundle, DeviceRuntimeAuth, DeviceRuntimeRefreshChallenge, DeviceRuntimeRefreshProof,
};
use tapchat_core::persistence::PersistedDeployment;
use tapchat_core::CoreCommand;

use crate::platform::log_sanitize::redact_id;
use crate::platform::profile::ProfileManager;
use crate::state::AppState;

const DEVICE_RUNTIME_REFRESH_SKEW_MS: u64 = 5 * 60 * 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
enum RefreshReason {
    MissingAuth,
    Expired,
    ExpiringSoon,
}

fn refresh_reason(expires_at: Option<u64>, now_ms: u64) -> Option<RefreshReason> {
    match expires_at {
        None => Some(RefreshReason::MissingAuth),
        Some(value) if value <= now_ms => Some(RefreshReason::Expired),
        Some(value) if value <= now_ms.saturating_add(DEVICE_RUNTIME_REFRESH_SKEW_MS) => {
            Some(RefreshReason::ExpiringSoon)
        }
        Some(_) => None,
    }
}

fn now_ms() -> Result<u64> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock before unix epoch")?;
    let millis = duration.as_millis();
    u64::try_from(millis).context("current time does not fit in u64")
}

async fn refresh_device_runtime_auth_with_proof(
    base_url: &str,
    user_id: &str,
    device_id: &str,
    identity: &tapchat_core::identity::LocalIdentityState,
) -> Result<DeviceRuntimeAuth> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RefreshResponse {
        device_runtime_auth: DeviceRuntimeAuth,
    }

    let client = reqwest::Client::builder()
        .build()
        .context("build runtime refresh client")?;
    let base_url = base_url.trim_end_matches('/');
    let challenge = client
        .post(format!("{base_url}/v1/runtime-auth/challenge"))
        .json(&serde_json::json!({
            "userId": user_id,
            "deviceId": device_id,
        }))
        .send()
        .await
        .context("request runtime auth challenge")?
        .error_for_status()
        .context("runtime auth challenge rejected")?
        .json::<DeviceRuntimeRefreshChallenge>()
        .await
        .context("decode runtime auth challenge")?;
    if challenge.user_id != user_id
        || challenge.device_id != device_id
        || challenge.expires_at <= now_ms()?
        || challenge.origin != url::Url::parse(base_url)?.origin().ascii_serialization()
    {
        return Err(anyhow!("runtime auth challenge scope is invalid"));
    }
    let proof = DeviceRuntimeRefreshProof {
        signature: identity.sign_sender_proof(challenge.signing_payload().as_bytes()),
        challenge,
    };
    let response = client
        .post(format!("{base_url}/v1/runtime-auth/refresh"))
        .json(&proof)
        .send()
        .await
        .context("submit runtime auth refresh proof")?
        .error_for_status()
        .context("runtime auth refresh proof rejected")?
        .json::<RefreshResponse>()
        .await
        .context("decode refreshed runtime auth")?;
    Ok(response.device_runtime_auth)
}

pub async fn ensure_fresh_device_runtime_auth(
    profile_manager: &ProfileManager,
) -> Result<Option<DeploymentBundle>> {
    let (
        base_url,
        bootstrap_secret,
        bootstrap_key_id,
        user_id,
        device_id,
        reason,
        mut current_bundle,
        local_identity,
    ) = {
        let inner = profile_manager.inner.read().await;
        let profile = match inner.active_profile.as_ref() {
            Some(profile) => profile,
            None => return Ok(None),
        };

        let runtime = profile
            .load_runtime_metadata()
            .context("load runtime metadata for device runtime refresh")?;
        let snapshot = profile
            .load_snapshot()
            .context("load snapshot for device runtime refresh")?;
        let deployment = match snapshot.deployment.as_ref() {
            Some(deployment) => deployment,
            None => return Ok(None),
        };

        let Some(base_url) = runtime.public_base_url.clone().or(runtime.base_url.clone()) else {
            return Ok(None);
        };
        let Some(bootstrap_secret) = runtime.bootstrap_secret.clone() else {
            return Ok(None);
        };
        let bootstrap_key_id = profile
            .load_runtime_secrets()
            .context("load private runtime secrets for device runtime refresh")?
            .bootstrap_key_id;
        let user_id = profile
            .metadata()
            .user_id
            .clone()
            .or_else(|| {
                snapshot
                    .local_identity
                    .as_ref()
                    .map(|identity| identity.state.user_identity.user_id.clone())
            })
            .ok_or_else(|| anyhow!("active profile missing user_id for device runtime refresh"))?;
        let device_id = profile
            .metadata()
            .device_id
            .clone()
            .or_else(|| {
                snapshot
                    .local_identity
                    .as_ref()
                    .map(|identity| identity.state.device_identity.device_id.clone())
            })
            .ok_or_else(|| {
                anyhow!("active profile missing device_id for device runtime refresh")
            })?;
        let expires_at = deployment
            .deployment_bundle
            .device_runtime_auth
            .as_ref()
            .map(|auth| auth.expires_at);
        let Some(reason) = refresh_reason(expires_at, now_ms()?) else {
            return Ok(None);
        };

        let local_identity = snapshot
            .local_identity
            .as_ref()
            .map(|identity| identity.state.clone())
            .ok_or_else(|| anyhow!("active profile missing local identity for runtime refresh"))?;
        (
            base_url,
            bootstrap_secret,
            bootstrap_key_id,
            user_id,
            device_id,
            reason,
            deployment.deployment_bundle.clone(),
            local_identity,
        )
    };

    log::info!(
        "device runtime auth refresh needed: reason={:?} user_id={} device_id={}",
        reason,
        redact_id("user", &user_id),
        redact_id("device", &device_id)
    );

    let refreshed_bundle = if current_bundle
        .runtime_config
        .features
        .iter()
        .any(|feature| feature == "device_runtime_refresh_v1")
    {
        current_bundle.device_runtime_auth = Some(
            refresh_device_runtime_auth_with_proof(
                &base_url,
                &user_id,
                &device_id,
                &local_identity,
            )
            .await
            .context("refresh device runtime auth with device proof")?,
        );
        current_bundle
    } else {
        bootstrap_device_bundle_with_key_id(
            &base_url,
            &bootstrap_secret,
            bootstrap_key_id.as_deref(),
            &user_id,
            &device_id,
        )
        .await
        .context("refresh legacy device runtime auth")?
    };

    {
        let mut inner = profile_manager.inner.write().await;
        let profile = inner
            .active_profile
            .as_mut()
            .ok_or_else(|| anyhow!("active profile disappeared during device runtime refresh"))?;
        let mut snapshot = profile
            .load_snapshot()
            .context("reload snapshot during device runtime refresh")?;

        if let Some(deployment) = snapshot.deployment.as_mut() {
            deployment.deployment_bundle = refreshed_bundle.clone();
        } else {
            snapshot.deployment = Some(PersistedDeployment {
                deployment_bundle: refreshed_bundle.clone(),
                local_bundle: None,
                published_key_package: None,
                serialized_mls_bootstrap_state: None,
            });
        }

        profile
            .save_deployment_bundle(&refreshed_bundle)
            .context("persist refreshed deployment bundle")?;
        profile
            .save_snapshot(&snapshot)
            .context("persist snapshot with refreshed deployment bundle")?;
    }

    log::info!(
        "device runtime auth refreshed successfully for user_id={} device_id={} expires_at={}",
        redact_id("user", &user_id),
        redact_id("device", &device_id),
        refreshed_bundle
            .device_runtime_auth
            .as_ref()
            .map(|auth| auth.expires_at.to_string())
            .unwrap_or_else(|| "none".into())
    );

    Ok(Some(refreshed_bundle))
}

pub async fn ensure_fresh_device_runtime_auth_for_state(state: &AppState) -> Result<bool> {
    let profile_manager = {
        let inner = state.inner.read().await;
        inner.profile_manager.clone()
    };
    let refreshed = { ensure_fresh_device_runtime_auth(&profile_manager).await? };

    let Some(bundle) = refreshed else {
        return Ok(false);
    };

    let mut inner = state.inner.write().await;
    let _ = inner
        .engine
        .handle_command(CoreCommand::ImportDeploymentBundle {
            bundle: bundle.clone(),
        })
        .context("import refreshed deployment bundle into engine")?;

    let snapshot = inner.engine.refresh_snapshot();
    {
        let mut pm_inner = profile_manager.inner.write().await;
        let profile = pm_inner.active_profile.as_mut().ok_or_else(|| {
            anyhow!("active profile disappeared while updating engine runtime auth")
        })?;
        profile
            .save_snapshot(&snapshot)
            .context("persist refreshed engine snapshot")?;
        profile
            .save_deployment_bundle(&bundle)
            .context("persist refreshed deployment bundle after engine import")?;
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_reason_requires_refresh_for_missing_or_expired_tokens() {
        let now = 1_000_000_u64;
        assert_eq!(refresh_reason(None, now), Some(RefreshReason::MissingAuth));
        assert_eq!(
            refresh_reason(Some(now.saturating_sub(1)), now),
            Some(RefreshReason::Expired)
        );
        assert_eq!(
            refresh_reason(Some(now + 60_000), now),
            Some(RefreshReason::ExpiringSoon)
        );
        assert_eq!(refresh_reason(Some(now + 10_000_000), now), None);
    }
}

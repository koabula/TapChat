use anyhow::{Context, Result, anyhow};
use tapchat_core::CoreCommand;
use tapchat_core::cli::runtime::bootstrap_device_bundle;
use tapchat_core::model::DeploymentBundle;
use tapchat_core::persistence::PersistedDeployment;

use crate::platform::profile::ProfileManager;
use crate::state::AppState;

const DEVICE_RUNTIME_REFRESH_SKEW_MS: u64 = 5 * 60 * 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
enum RefreshReason {
    MissingAuth,
    Expired,
    ExpiringSoon,
}

fn refresh_reason(
    expires_at: Option<u64>,
    now_ms: u64,
) -> Option<RefreshReason> {
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

pub async fn ensure_fresh_device_runtime_auth(
    profile_manager: &ProfileManager,
) -> Result<Option<DeploymentBundle>> {
    let (base_url, bootstrap_secret, user_id, device_id, reason) = {
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
            .ok_or_else(|| anyhow!("active profile missing device_id for device runtime refresh"))?;
        let expires_at = deployment
            .deployment_bundle
            .device_runtime_auth
            .as_ref()
            .map(|auth| auth.expires_at);
        let Some(reason) = refresh_reason(expires_at, now_ms()?) else {
            return Ok(None);
        };

        (base_url, bootstrap_secret, user_id, device_id, reason)
    };

    log::info!(
        "device runtime auth refresh needed: reason={:?} user_id={} device_id={}",
        reason,
        user_id,
        device_id
    );

    let refreshed_bundle = bootstrap_device_bundle(
        &base_url,
        &bootstrap_secret,
        &user_id,
        &device_id,
    )
    .await
    .with_context(|| {
        format!(
            "refresh device runtime auth for user_id={} device_id={} via {}",
            user_id, device_id, base_url
        )
    })?;

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
        user_id,
        device_id,
        refreshed_bundle
            .device_runtime_auth
            .as_ref()
            .map(|auth| auth.expires_at.to_string())
            .unwrap_or_else(|| "none".into())
    );

    Ok(Some(refreshed_bundle))
}

pub async fn ensure_fresh_device_runtime_auth_for_state(
    state: &AppState,
) -> Result<bool> {
    let refreshed = {
        let inner = state.inner.read().await;
        ensure_fresh_device_runtime_auth(&inner.profile_manager).await?
    };

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
        let mut pm_inner = inner.profile_manager.inner.write().await;
        let profile = pm_inner
            .active_profile
            .as_mut()
            .ok_or_else(|| anyhow!("active profile disappeared while updating engine runtime auth"))?;
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

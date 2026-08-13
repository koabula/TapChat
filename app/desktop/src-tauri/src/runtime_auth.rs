use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use tapchat_core::identity::LocalIdentityState;
use tapchat_core::model::{
    DeploymentBundle, DeviceContactProfile, DeviceRuntimeAuth, DeviceRuntimeRefreshChallenge,
    DeviceRuntimeRefreshProof, IdentityBundle, Validate,
};
use tokio::sync::{Mutex, RwLock};

use crate::platform::log_sanitize::redact_id;
use crate::platform::profile::ProfileManager;
use crate::state::AppState;

pub const DEVICE_RUNTIME_REFRESH_SKEW_MS: u64 = 6 * 60 * 60 * 1000;
const DEVICE_RUNTIME_TOKEN_TTL_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeAuthState {
    Ready,
    Refreshing,
    Degraded,
    OfflineExpired,
    UpgradeRequired,
    EnrollmentRequired,
    DeviceRevoked,
}

#[derive(Debug, Clone)]
pub struct RuntimeAuthSnapshot {
    pub state: RuntimeAuthState,
    pub expires_at: Option<u64>,
    pub error_code: Option<String>,
    pub retryable: bool,
    pub next_retry_at: Option<u64>,
}

impl Default for RuntimeAuthSnapshot {
    fn default() -> Self {
        Self {
            state: RuntimeAuthState::Ready,
            expires_at: None,
            error_code: None,
            retryable: false,
            next_retry_at: None,
        }
    }
}

#[derive(Clone, Default)]
pub struct RuntimeAuthManager {
    gate: Arc<Mutex<()>>,
    generation: Arc<AtomicU64>,
    failure_count: Arc<AtomicU64>,
    retry_at_ms: Arc<AtomicU64>,
    snapshot: Arc<RwLock<RuntimeAuthSnapshot>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProofPurpose {
    Enroll,
    Refresh,
}

impl ProofPurpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::Enroll => "enroll",
            Self::Refresh => "refresh",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialResponse {
    runtime_credential: DeviceRuntimeAuth,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeRegistryReadyResponse {
    ready: bool,
    runtime_id: String,
}

fn now_ms() -> Result<u64> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock before unix epoch")?;
    u64::try_from(duration.as_millis()).context("current time does not fit in u64")
}

pub fn runtime_credential_needs_refresh(credential: Option<&DeviceRuntimeAuth>, now: u64) -> bool {
    credential
        .is_none_or(|value| value.expires_at <= now.saturating_add(DEVICE_RUNTIME_REFRESH_SKEW_MS))
}

fn runtime_error(code: &str) -> anyhow::Error {
    anyhow!("runtime_auth_error:{code}")
}

fn runtime_error_code(error: &anyhow::Error) -> String {
    error
        .to_string()
        .strip_prefix("runtime_auth_error:")
        .unwrap_or("temporary_unavailable")
        .to_string()
}

async fn decode_runtime_error(response: reqwest::Response, stage: &str) -> anyhow::Error {
    let status = response.status();
    let code = response
        .json::<ErrorResponse>()
        .await
        .ok()
        .and_then(|body| body.error)
        .unwrap_or_else(|| format!("http_{}", status.as_u16()));
    log::warn!(
        "runtime authorization request failed: stage={} code={} retryable={}",
        stage,
        code,
        status.is_server_error() || status.as_u16() == 429
    );
    runtime_error(&code)
}

async fn request_runtime_credential(
    deployment: &DeploymentBundle,
    identity: &LocalIdentityState,
    purpose: ProofPurpose,
    device: Option<&DeviceContactProfile>,
) -> Result<DeviceRuntimeAuth> {
    let user_id = &identity.user_identity.user_id;
    let device_id = &identity.device_identity.device_id;
    let base_url = deployment.inbox_http_endpoint.trim_end_matches('/');
    let client = reqwest::Client::builder()
        .build()
        .context("build runtime authorization client")?;

    let response = client
        .post(format!("{base_url}/v2/runtime-auth/challenge"))
        .json(&serde_json::json!({
            "purpose": purpose.as_str(),
            "userId": user_id,
            "deviceId": device_id,
        }))
        .send()
        .await
        .context("request runtime authorization challenge")?;
    if !response.status().is_success() {
        return Err(decode_runtime_error(response, "challenge").await);
    }
    let challenge = response
        .json::<DeviceRuntimeRefreshChallenge>()
        .await
        .context("decode runtime authorization challenge")?;
    if challenge.version != tapchat_core::model::CURRENT_MODEL_VERSION
        || challenge.purpose != purpose.as_str()
        || challenge.runtime_id != deployment.runtime_id
        || challenge.user_id != *user_id
        || challenge.device_id != *device_id
        || challenge.expires_at <= now_ms()?
    {
        return Err(runtime_error("runtime_mismatch"));
    }
    let proof = DeviceRuntimeRefreshProof {
        signature: identity.sign_sender_proof(challenge.signing_payload().as_bytes()),
        challenge,
    };
    let (endpoint, body) = match (purpose, device) {
        (ProofPurpose::Enroll, Some(device)) => (
            "enroll",
            serde_json::json!({
                "challenge": proof.challenge,
                "signature": proof.signature,
                "device": device,
            }),
        ),
        (ProofPurpose::Refresh, None) => (
            "refresh",
            serde_json::to_value(&proof).context("encode runtime refresh proof")?,
        ),
        _ => return Err(anyhow!("invalid runtime authorization proof inputs")),
    };
    let response = client
        .post(format!("{base_url}/v2/runtime-auth/{endpoint}"))
        .json(&body)
        .send()
        .await
        .with_context(|| format!("submit runtime authorization {endpoint} proof"))?;
    if !response.status().is_success() {
        return Err(decode_runtime_error(response, endpoint).await);
    }
    let credential = response
        .json::<CredentialResponse>()
        .await
        .context("decode runtime credential")?
        .runtime_credential;
    credential
        .validate()
        .context("validate runtime credential")?;
    if credential.runtime_id != deployment.runtime_id
        || credential.user_id != *user_id
        || credential.device_id != *device_id
        || credential.expires_at.saturating_sub(credential.issued_at) != DEVICE_RUNTIME_TOKEN_TTL_MS
    {
        return Err(runtime_error("runtime_mismatch"));
    }
    Ok(credential)
}

fn runtime_request_is_retryable(error: &anyhow::Error) -> bool {
    let code = runtime_error_code(error);
    code == "temporary_unavailable"
        || code == "internal_error"
        || code == "rate_limited"
        || code.starts_with("http_5")
}

async fn request_runtime_credential_with_retry(
    deployment: &DeploymentBundle,
    identity: &LocalIdentityState,
    purpose: ProofPurpose,
    device: Option<&DeviceContactProfile>,
) -> Result<DeviceRuntimeAuth> {
    const RETRY_DELAYS_MS: &[u64] = &[0, 500, 1_000, 2_000, 5_000, 10_000];
    let mut last_error = None;
    for (attempt, delay_ms) in RETRY_DELAYS_MS.iter().enumerate() {
        if *delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(*delay_ms)).await;
        }
        match request_runtime_credential(deployment, identity, purpose, device).await {
            Ok(credential) => return Ok(credential),
            Err(error)
                if runtime_request_is_retryable(&error) && attempt + 1 < RETRY_DELAYS_MS.len() =>
            {
                log::warn!(
                    "runtime authorization will retry: stage={} code={} attempt={}",
                    purpose.as_str(),
                    runtime_error_code(&error),
                    attempt + 1
                );
                last_error = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error.unwrap_or_else(|| runtime_error("temporary_unavailable")))
}

pub async fn wait_for_runtime_registry(deployment: &DeploymentBundle) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("build runtime registry readiness client")?;
    let endpoint = format!(
        "{}/v2/runtime-auth/ready",
        deployment.inbox_http_endpoint.trim_end_matches('/')
    );
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(90);
    loop {
        let last_code = match client.get(&endpoint).send().await {
            Ok(response) if response.status().is_success() => {
                let ready = response
                    .json::<RuntimeRegistryReadyResponse>()
                    .await
                    .context("decode runtime registry readiness response")?;
                if ready.ready && ready.runtime_id == deployment.runtime_id {
                    return Ok(());
                }
                "runtime_mismatch".to_string()
            }
            Ok(response) => {
                let status = response.status();
                let code = response
                    .json::<ErrorResponse>()
                    .await
                    .ok()
                    .and_then(|body| body.error)
                    .unwrap_or_else(|| format!("http_{}", status.as_u16()));
                if !status.is_server_error() && status.as_u16() != 429 {
                    return Err(runtime_error(&code));
                }
                code
            }
            Err(_) => "temporary_unavailable".to_string(),
        };
        if tokio::time::Instant::now() >= deadline {
            return Err(anyhow!("runtime_registry_not_ready:{last_code}"));
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

impl RuntimeAuthManager {
    pub fn invalidate(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    pub async fn snapshot(&self) -> RuntimeAuthSnapshot {
        self.snapshot.read().await.clone()
    }

    async fn set_snapshot(&self, snapshot: RuntimeAuthSnapshot) {
        *self.snapshot.write().await = snapshot;
    }

    pub async fn ensure(
        &self,
        profile_manager: &ProfileManager,
        force: bool,
    ) -> Result<Option<DeviceRuntimeAuth>> {
        let _guard = self.gate.lock().await;
        let generation = self.generation.load(Ordering::SeqCst);
        let (profile_path, deployment, identity_bundle, identity, current) = {
            let inner = profile_manager.inner.read().await;
            let Some(profile) = inner.active_profile.as_ref() else {
                return Ok(None);
            };
            let snapshot = profile
                .load_snapshot()
                .context("load snapshot for runtime authorization")?;
            let Some(persisted_deployment) = snapshot.deployment else {
                return Ok(None);
            };
            let deployment = persisted_deployment.deployment_bundle;
            if !deployment
                .runtime_config
                .features
                .iter()
                .any(|feature| feature == "device_runtime_refresh_v2")
            {
                self.set_snapshot(RuntimeAuthSnapshot {
                    state: RuntimeAuthState::UpgradeRequired,
                    error_code: Some("upgrade_required".into()),
                    ..RuntimeAuthSnapshot::default()
                })
                .await;
                return Err(runtime_error("upgrade_required"));
            }
            let identity = snapshot
                .local_identity
                .map(|value| value.state)
                .ok_or_else(|| runtime_error("enrollment_required"))?;
            let identity_bundle = persisted_deployment
                .local_bundle
                .ok_or_else(|| runtime_error("enrollment_required"))?;
            (
                profile.root().to_path_buf(),
                deployment,
                identity_bundle,
                identity,
                profile
                    .load_runtime_credential()
                    .context("load private runtime credential")?,
            )
        };
        let now = now_ms()?;
        let retry_at = self.retry_at_ms.load(Ordering::SeqCst);
        if !force && retry_at > now {
            let expired = current.as_ref().is_none_or(|value| value.expires_at <= now);
            self.set_snapshot(RuntimeAuthSnapshot {
                state: if expired {
                    RuntimeAuthState::OfflineExpired
                } else {
                    RuntimeAuthState::Degraded
                },
                expires_at: current.as_ref().map(|value| value.expires_at),
                error_code: Some("temporary_unavailable".into()),
                retryable: true,
                next_retry_at: Some(retry_at),
            })
            .await;
            if expired {
                return Err(runtime_error("temporary_unavailable"));
            }
            return Ok(current);
        }
        if !force && !runtime_credential_needs_refresh(current.as_ref(), now) {
            self.set_snapshot(RuntimeAuthSnapshot {
                state: RuntimeAuthState::Ready,
                expires_at: current.as_ref().map(|value| value.expires_at),
                ..RuntimeAuthSnapshot::default()
            })
            .await;
            return Ok(current);
        }
        self.set_snapshot(RuntimeAuthSnapshot {
            state: RuntimeAuthState::Refreshing,
            expires_at: current.as_ref().map(|value| value.expires_at),
            ..RuntimeAuthSnapshot::default()
        })
        .await;
        log::info!(
            "runtime authorization refresh started: runtime_id={} device_id={}",
            redact_id("runtime", &deployment.runtime_id),
            redact_id("device", &identity.device_identity.device_id)
        );
        let local_device = identity_bundle
            .devices
            .iter()
            .find(|device| device.device_id == identity.device_identity.device_id)
            .ok_or_else(|| runtime_error("enrollment_required"))?;
        let mut refreshed = if current.is_none() {
            request_runtime_credential_with_retry(
                &deployment,
                &identity,
                ProofPurpose::Enroll,
                Some(local_device),
            )
            .await
        } else {
            request_runtime_credential_with_retry(
                &deployment,
                &identity,
                ProofPurpose::Refresh,
                None,
            )
            .await
        };
        if refreshed
            .as_ref()
            .is_err_and(|error| runtime_error_code(error) == "enrollment_required")
        {
            refreshed = request_runtime_credential_with_retry(
                &deployment,
                &identity,
                ProofPurpose::Enroll,
                Some(local_device),
            )
            .await;
        }
        let refreshed = match refreshed {
            Ok(value) => value,
            Err(error) => {
                let code = runtime_error_code(&error);
                let expired = current.as_ref().is_none_or(|value| value.expires_at <= now);
                let state = match code.as_str() {
                    "device_revoked" => RuntimeAuthState::DeviceRevoked,
                    "enrollment_required" => RuntimeAuthState::EnrollmentRequired,
                    _ if expired => RuntimeAuthState::OfflineExpired,
                    _ => RuntimeAuthState::Degraded,
                };
                let retryable = matches!(
                    state,
                    RuntimeAuthState::Degraded | RuntimeAuthState::OfflineExpired
                ) && !matches!(
                    code.as_str(),
                    "runtime_mismatch" | "runtime_auth_invalid" | "challenge_replayed"
                );
                let next_retry_at = if retryable {
                    let failure = self.failure_count.fetch_add(1, Ordering::SeqCst);
                    let delay_minutes = match failure {
                        0 => 1,
                        1 => 5,
                        2 => 15,
                        _ => 60,
                    };
                    let retry_at = now.saturating_add(delay_minutes * 60 * 1000);
                    self.retry_at_ms.store(retry_at, Ordering::SeqCst);
                    Some(retry_at)
                } else {
                    self.retry_at_ms.store(0, Ordering::SeqCst);
                    None
                };
                self.set_snapshot(RuntimeAuthSnapshot {
                    state,
                    expires_at: current.as_ref().map(|value| value.expires_at),
                    error_code: Some(code),
                    retryable,
                    next_retry_at,
                })
                .await;
                if !expired {
                    return Ok(current);
                }
                return Err(error);
            }
        };
        self.failure_count.store(0, Ordering::SeqCst);
        self.retry_at_ms.store(0, Ordering::SeqCst);
        {
            let inner = profile_manager.inner.write().await;
            let profile = inner
                .active_profile
                .as_ref()
                .ok_or_else(|| anyhow!("active profile disappeared during runtime refresh"))?;
            if profile.root() != profile_path
                || self.generation.load(Ordering::SeqCst) != generation
            {
                return Err(anyhow!(
                    "runtime refresh result belongs to a stale profile generation"
                ));
            }
            profile
                .save_runtime_credential(Some(refreshed.clone()))
                .context("atomically persist refreshed runtime credential")?;
        }
        self.set_snapshot(RuntimeAuthSnapshot {
            state: RuntimeAuthState::Ready,
            expires_at: Some(refreshed.expires_at),
            ..RuntimeAuthSnapshot::default()
        })
        .await;
        log::info!(
            "runtime authorization refreshed: runtime_id={} device_id={} expires_at={}",
            redact_id("runtime", &refreshed.runtime_id),
            redact_id("device", &refreshed.device_id),
            refreshed.expires_at
        );
        Ok(Some(refreshed))
    }

    pub async fn enroll(
        &self,
        profile_manager: &ProfileManager,
        deployment: &DeploymentBundle,
        identity_bundle: &IdentityBundle,
        identity: &LocalIdentityState,
    ) -> Result<DeviceRuntimeAuth> {
        let device = identity_bundle
            .devices
            .iter()
            .find(|device| device.device_id == identity.device_identity.device_id)
            .ok_or_else(|| runtime_error("enrollment_required"))?;
        let credential = request_runtime_credential_with_retry(
            deployment,
            identity,
            ProofPurpose::Enroll,
            Some(device),
        )
        .await?;
        let inner = profile_manager.inner.read().await;
        let profile = inner
            .active_profile
            .as_ref()
            .ok_or_else(|| anyhow!("active profile disappeared during enrollment"))?;
        profile
            .save_runtime_credential(Some(credential.clone()))
            .context("atomically persist enrolled runtime credential")?;
        Ok(credential)
    }
}

pub async fn ensure_fresh_device_runtime_auth_for_state(state: &AppState) -> Result<bool> {
    let profile_manager = {
        let inner = state.inner.read().await;
        inner.profile_manager.clone()
    };
    Ok(state
        .runtime_auth
        .ensure(&profile_manager, false)
        .await?
        .is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_window_is_six_hours() {
        let now = 1_000_000;
        let credential = DeviceRuntimeAuth {
            scheme: "bearer".into(),
            token: "secret".into(),
            issued_at: now,
            expires_at: now + DEVICE_RUNTIME_REFRESH_SKEW_MS,
            runtime_id: "runtime".into(),
            user_id: "user".into(),
            device_id: "device".into(),
            scopes: vec!["inbox_read".into()],
            registration_version: 1,
            key_id: Some("current".into()),
        };
        assert!(runtime_credential_needs_refresh(Some(&credential), now));
    }

    #[test]
    fn enrollment_retry_only_accepts_transient_failures() {
        for code in [
            "temporary_unavailable",
            "internal_error",
            "rate_limited",
            "http_500",
            "http_503",
        ] {
            assert!(runtime_request_is_retryable(&runtime_error(code)), "{code}");
        }
        for code in [
            "runtime_auth_invalid",
            "runtime_mismatch",
            "device_revoked",
            "enrollment_required",
        ] {
            assert!(
                !runtime_request_is_retryable(&runtime_error(code)),
                "{code}"
            );
        }
    }
}

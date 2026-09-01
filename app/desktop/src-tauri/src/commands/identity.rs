use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use serde::Serialize;
use subtle::ConstantTimeEq;
use tauri::{AppHandle, Manager, State};
use zeroize::Zeroizing;

use tapchat_core::model::DeviceStatusKind;
use tapchat_core::{CoreCommand, CoreOperationStatus, CoreOutput, ErrorDomain, RecoveryAction};

use crate::errors::{DesktopError, DesktopResult};
use crate::lifecycle::{CoreInput, drive_core_with_handle, merge_core_outputs};
use crate::platform::log_sanitize::redact_id;
use crate::platform::profile::{ProfileProtectionMode, ProfileSummary};
use crate::state::{
    AppState, RecoveryPhraseAuthMode, RecoveryPhraseChallenge, RecoveryPhraseGate, SessionState,
};

#[derive(Debug, Clone, Serialize)]
pub struct IdentityInfo {
    pub user_id: String,
    pub device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryPhraseAuthModeView {
    Passphrase,
    ConfirmationOnly,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoveryPhraseRevealChallenge {
    pub challenge_id: String,
    pub auth_mode: RecoveryPhraseAuthModeView,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoveryPhraseRevealResult {
    pub mnemonic: String,
}

/// Result of identity creation/recovery
#[derive(Debug, Clone, Serialize)]
pub struct CreateIdentityResult {
    pub user_id: String,
    pub device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
}

/// Initialize a new profile for onboarding
/// This creates the profile directory structure before identity creation
#[tauri::command]
pub async fn init_onboarding_profile(
    state: State<'_, AppState>,
    profile_name: String,
    passphrase: Option<String>,
    protection_mode: Option<ProfileProtectionMode>,
) -> crate::errors::DesktopResult<ProfileSummary> {
    let profile_ref = redact_id("profile", &profile_name);
    log::info!("Creating profile {}", profile_ref);

    // Create profile
    let summary = {
        let pm = &state.inner.read().await.profile_manager;
        let protection_mode = protection_mode.unwrap_or_else(|| {
            if passphrase.as_deref().is_some_and(|value| !value.is_empty()) {
                ProfileProtectionMode::KeychainAndPassphrase
            } else {
                ProfileProtectionMode::KeychainOnly
            }
        });
        pm.create_profile(&profile_name, passphrase, protection_mode)
            .await
            .map_err(|e| {
                log::error!("Failed to create profile {}", profile_ref);
                format!("Failed to create profile: {}", e)
            })?
    };

    log::info!("Profile created successfully {}", profile_ref);

    // Update profile_path in state
    {
        let mut inner = state.inner.write().await;
        inner.profile_path = Some(summary.path.clone());
    }

    Ok(summary)
}

/// Create or load identity with profile persistence
#[tauri::command]
pub async fn create_or_load_identity(
    app: AppHandle,
    state: State<'_, AppState>,
    mnemonic: Option<String>,
    device_name: Option<String>,
    display_name: Option<String>,
) -> crate::errors::DesktopResult<CreateIdentityResult> {
    let supplied_mnemonic = mnemonic.is_some();
    let had_identity = state.inner.read().await.engine.local_identity().is_some();
    // First ensure profile exists
    {
        let inner = state.inner.read().await;
        if inner.profile_manager.get_active_metadata().await.is_none() {
            return Err(
                "profile_required: create a protected profile before creating or recovering an identity"
                    .to_string()
                    .into(),
            );
        }
    }

    // Run the core command
    let _output = drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::CreateOrLoadIdentity {
            mnemonic,
            device_name,
            display_name,
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    // Get the identity info from engine
    let inner = state.inner.read().await;
    let identity = inner.engine.local_identity();

    let result = match identity {
        Some(id) => {
            let user_id = id.user_identity.user_id.clone();
            let device_id = id.device_identity.device_id.clone();
            let mnemonic = (!had_identity && !supplied_mnemonic).then(|| id.mnemonic.clone());

            // Update profile metadata with identity info
            drop(inner);
            state
                .inner
                .read()
                .await
                .profile_manager
                .update_identity(Some(user_id.clone()), Some(device_id.clone()))
                .await
                .map_err(|e| e.to_string())?;

            // Persist snapshot to profile
            {
                let inner = state.inner.write().await;
                let snapshot = inner.engine.refresh_snapshot();
                inner
                    .profile_manager
                    .save_snapshot(&snapshot)
                    .await
                    .map_err(|e| e.to_string())?;
            }

            CreateIdentityResult {
                user_id,
                device_id,
                mnemonic,
            }
        }
        None => Err("Identity creation failed - no local identity found".to_string())?,
    };

    Ok(result)
}

#[tauri::command]
pub async fn get_identity_info(
    state: State<'_, AppState>,
) -> crate::errors::DesktopResult<Option<IdentityInfo>> {
    let inner = state.inner.read().await;

    let identity = inner.engine.local_identity();
    let bundle = inner.engine.local_bundle();
    let local_display_name = inner.engine.local_display_name();

    match (identity, bundle) {
        (Some(id), Some(b)) => Ok(Some(IdentityInfo {
            user_id: b.user_id.clone(),
            device_id: id.device_identity.device_id.clone(),
            display_name: local_display_name,
        })),
        (Some(id), None) => Ok(Some(IdentityInfo {
            user_id: id.user_identity.user_id.clone(),
            device_id: id.device_identity.device_id.clone(),
            display_name: local_display_name,
        })),
        _ => Ok(None),
    }
}

#[tauri::command]
pub async fn begin_recovery_phrase_reveal(
    state: State<'_, AppState>,
) -> crate::errors::DesktopResult<RecoveryPhraseRevealChallenge> {
    const CHALLENGE_TTL: Duration = Duration::from_secs(60);

    let (profile_path, auth_mode) = {
        let inner = state.inner.read().await;
        if !matches!(inner.session, SessionState::Active { .. }) {
            return Err("recovery_phrase_auth_required".into());
        }
        let profile_inner = inner.profile_manager.inner.read().await;
        let profile = profile_inner
            .active_profile
            .as_ref()
            .ok_or_else(|| "recovery_phrase_auth_required".to_string())?;
        let mode = if profile.has_passphrase_wrapper() {
            RecoveryPhraseAuthMode::Passphrase
        } else {
            RecoveryPhraseAuthMode::ConfirmationOnly
        };
        (profile.root().to_path_buf(), mode)
    };

    let mut challenge_bytes = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge_bytes);
    let challenge_id = URL_SAFE_NO_PAD.encode(challenge_bytes);
    let expires_at_instant = Instant::now() + CHALLENGE_TTL;
    let expires_at = SystemTime::now()
        .checked_add(CHALLENGE_TTL)
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map(|value| value.as_millis() as u64)
        .ok_or_else(|| "recovery_phrase_challenge_failed".to_string())?;

    state.recovery_phrase_gate.lock().await.pending = Some(RecoveryPhraseChallenge {
        challenge_id: challenge_id.clone(),
        profile_path,
        auth_mode,
        expires_at: expires_at_instant,
    });

    Ok(RecoveryPhraseRevealChallenge {
        challenge_id,
        auth_mode: match auth_mode {
            RecoveryPhraseAuthMode::Passphrase => RecoveryPhraseAuthModeView::Passphrase,
            RecoveryPhraseAuthMode::ConfirmationOnly => {
                RecoveryPhraseAuthModeView::ConfirmationOnly
            }
        },
        expires_at,
    })
}

#[tauri::command]
pub async fn complete_recovery_phrase_reveal(
    state: State<'_, AppState>,
    challenge_id: String,
    passphrase: Option<String>,
    confirmed: bool,
) -> crate::errors::DesktopResult<RecoveryPhraseRevealResult> {
    let challenge = {
        let mut gate = state.recovery_phrase_gate.lock().await;
        consume_recovery_phrase_challenge(&mut *gate, &challenge_id, Instant::now())?
    };

    let passphrase = passphrase.map(Zeroizing::new);
    let mnemonic = {
        let inner = state.inner.read().await;
        if !matches!(inner.session, SessionState::Active { .. }) {
            return Err("recovery_phrase_auth_required".into());
        }
        let profile_inner = inner.profile_manager.inner.read().await;
        let profile = profile_inner
            .active_profile
            .as_ref()
            .filter(|profile| profile.root() == challenge.profile_path)
            .ok_or_else(|| "recovery_phrase_auth_required".to_string())?;

        match challenge.auth_mode {
            RecoveryPhraseAuthMode::Passphrase => {
                let supplied = passphrase
                    .as_deref()
                    .ok_or_else(|| "recovery_phrase_auth_required".to_string())?;
                profile
                    .verify_passphrase(supplied)
                    .map_err(|_| "recovery_phrase_auth_failed".to_string())?;
            }
            RecoveryPhraseAuthMode::ConfirmationOnly if !confirmed => {
                return Err("recovery_phrase_confirmation_required".into());
            }
            RecoveryPhraseAuthMode::ConfirmationOnly => {}
        }

        inner
            .engine
            .local_identity()
            .map(|identity| identity.mnemonic.clone())
            .ok_or_else(|| "recovery_phrase_unavailable".to_string())?
    };

    Ok(RecoveryPhraseRevealResult { mnemonic })
}

fn consume_recovery_phrase_challenge(
    gate: &mut RecoveryPhraseGate,
    candidate_id: &str,
    now: Instant,
) -> Result<RecoveryPhraseChallenge, String> {
    let challenge = gate
        .pending
        .take()
        .ok_or_else(|| "recovery_phrase_challenge_expired".to_string())?;
    let matches = candidate_id
        .as_bytes()
        .ct_eq(challenge.challenge_id.as_bytes())
        .unwrap_u8()
        == 1;
    if challenge.expires_at <= now || !matches {
        return Err("recovery_phrase_challenge_expired".into());
    }
    Ok(challenge)
}

#[tauri::command]
pub async fn get_share_link(state: State<'_, AppState>) -> DesktopResult<Option<String>> {
    if state.inner.read().await.engine.has_pending_share_rotation() {
        return Err(DesktopError::new(
            "contact_share_rotation_unverified",
            ErrorDomain::Identity,
            true,
        )
        .with_action(RecoveryAction::Reconnect));
    }
    state
        .ports
        .lock()
        .await
        .build_contact_share_url()
        .await
        .map_err(DesktopError::from)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareLinkRotationResult {
    pub url: String,
    pub publication_revision: u64,
    pub rotated_at: u64,
}

#[tauri::command]
pub async fn rotate_share_link(app: AppHandle) -> DesktopResult<ShareLinkRotationResult> {
    let state = app.state::<AppState>();
    let current_url = state
        .ports
        .lock()
        .await
        .build_contact_share_url()
        .await
        .map_err(DesktopError::from)?
        .ok_or_else(|| {
            DesktopError::new("contact_share_offline", ErrorDomain::Identity, true)
                .with_action(RecoveryAction::Reconnect)
        })?;
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(12))
        .build()
        .map_err(|_| DesktopError::new("network_unavailable", ErrorDomain::Transport, true))?;
    let current = client.get(&current_url).send().await.map_err(|_| {
        DesktopError::new("contact_share_offline", ErrorDomain::Identity, true)
            .with_action(RecoveryAction::Reconnect)
    })?;
    if !current.status().is_success() {
        return Err(
            DesktopError::new("contact_share_offline", ErrorDomain::Identity, true)
                .with_action(RecoveryAction::Reconnect),
        );
    }

    drive_core_with_handle(
        &app,
        CoreInput::Event(tapchat_core::CoreEvent::CredentialMaintenanceRequested {
            now_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        }),
    )
    .await
    .map_err(DesktopError::from)?;

    let output = drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::RotateContactShareLink),
    )
    .await
    .map_err(DesktopError::from)?;
    let operation = output
        .view_model
        .as_ref()
        .and_then(|view| {
            view.operation_results
                .iter()
                .find(|result| result.operation_id.starts_with("contact_share_rotation:"))
        })
        .ok_or_else(|| {
            DesktopError::new(
                "contact_share_rotation_unverified",
                ErrorDomain::Identity,
                true,
            )
            .with_action(RecoveryAction::Reconnect)
        })?;
    if operation.status == CoreOperationStatus::Failed {
        return Err(operation
            .failure
            .clone()
            .map(DesktopError::from)
            .unwrap_or_else(|| {
                DesktopError::new(
                    "contact_share_rotation_unverified",
                    ErrorDomain::Identity,
                    true,
                )
                .with_action(RecoveryAction::Reconnect)
            }));
    }

    let url = state
        .ports
        .lock()
        .await
        .build_contact_share_url()
        .await
        .map_err(DesktopError::from)?
        .ok_or_else(|| {
            DesktopError::new(
                "contact_share_rotation_unverified",
                ErrorDomain::Identity,
                true,
            )
        })?;
    let verification = client.get(&url).send().await.map_err(|_| {
        DesktopError::new(
            "contact_share_rotation_unverified",
            ErrorDomain::Identity,
            true,
        )
        .with_action(RecoveryAction::Reconnect)
    })?;
    if !verification.status().is_success() {
        return Err(DesktopError::new(
            "contact_share_rotation_unverified",
            ErrorDomain::Identity,
            true,
        )
        .with_action(RecoveryAction::Reconnect));
    }
    let publication_revision = state
        .inner
        .read()
        .await
        .engine
        .local_bundle()
        .map(|bundle| bundle.publication_revision)
        .unwrap_or_default();
    Ok(ShareLinkRotationResult {
        url,
        publication_revision,
        rotated_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
    })
}

#[tauri::command]
pub async fn update_device_status(
    app: AppHandle,
    target_device_id: String,
    status: String,
) -> crate::errors::DesktopResult<CoreOutput> {
    // Parse status string to DeviceStatusKind
    let device_status = match status.to_lowercase().as_str() {
        "active" => DeviceStatusKind::Active,
        "revoked" => DeviceStatusKind::Revoked,
        _ => return Err(format!("Invalid device status: {}", status).into()),
    };

    let mut output = drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::UpdateLocalDeviceStatus {
            target_device_id: target_device_id.clone(),
            status: device_status.clone(),
        }),
    )
    .await
    .map_err(|e| e.to_string())?;

    if let Some(command) =
        group_sync_command_for_device_status(&app, &target_device_id, device_status).await
    {
        let sync_output = drive_core_with_handle(&app, CoreInput::Command(command))
            .await
            .map_err(|e| e.to_string())?;
        merge_core_outputs(&mut output, sync_output);
    }

    Ok(output)
}

#[tauri::command]
pub async fn sync_groups_for_new_device(
    app: AppHandle,
    device_id: String,
) -> crate::errors::DesktopResult<CoreOutput> {
    Ok(drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::SyncGroupsForNewDevice { device_id }),
    )
    .await
    .map_err(crate::errors::DesktopError::from)?)
}

#[tauri::command]
pub async fn sync_groups_for_removed_device(
    app: AppHandle,
    device_id: String,
) -> crate::errors::DesktopResult<CoreOutput> {
    Ok(drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::SyncGroupsForRemovedDevice { device_id }),
    )
    .await
    .map_err(crate::errors::DesktopError::from)?)
}

async fn group_sync_command_for_device_status(
    app: &AppHandle,
    target_device_id: &str,
    status: DeviceStatusKind,
) -> Option<CoreCommand> {
    let state = app.state::<AppState>();
    let local_device_id = {
        let inner = state.inner.read().await;
        inner
            .engine
            .local_identity()
            .map(|identity| identity.device_identity.device_id.clone())
    };
    if local_device_id.as_deref() == Some(target_device_id) {
        return None;
    }

    match status {
        DeviceStatusKind::Active => Some(CoreCommand::SyncGroupsForNewDevice {
            device_id: target_device_id.to_string(),
        }),
        DeviceStatusKind::Revoked => Some(CoreCommand::SyncGroupsForRemovedDevice {
            device_id: target_device_id.to_string(),
        }),
    }
}

#[tauri::command]
pub async fn set_local_display_name(
    app: AppHandle,
    display_name: Option<String>,
) -> crate::errors::DesktopResult<CoreOutput> {
    Ok(drive_core_with_handle(
        &app,
        CoreInput::Command(CoreCommand::SetLocalDisplayName { display_name }),
    )
    .await
    .map_err(crate::errors::DesktopError::from)?)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn challenge(expires_at: Instant) -> RecoveryPhraseChallenge {
        RecoveryPhraseChallenge {
            challenge_id: "challenge-value".into(),
            profile_path: PathBuf::from("profile"),
            auth_mode: RecoveryPhraseAuthMode::ConfirmationOnly,
            expires_at,
        }
    }

    #[test]
    fn recovery_phrase_challenge_is_single_use() {
        let now = Instant::now();
        let mut gate = RecoveryPhraseGate {
            pending: Some(challenge(now + Duration::from_secs(60))),
        };

        consume_recovery_phrase_challenge(&mut gate, "challenge-value", now)
            .expect("first use succeeds");
        assert_eq!(
            consume_recovery_phrase_challenge(&mut gate, "challenge-value", now)
                .err()
                .expect("replay fails"),
            "recovery_phrase_challenge_expired"
        );
    }

    #[test]
    fn expired_or_mismatched_recovery_phrase_challenge_is_consumed() {
        let now = Instant::now();
        let mut expired = RecoveryPhraseGate {
            pending: Some(challenge(now)),
        };
        assert!(consume_recovery_phrase_challenge(&mut expired, "challenge-value", now).is_err());
        assert!(expired.pending.is_none());

        let mut mismatched = RecoveryPhraseGate {
            pending: Some(challenge(now + Duration::from_secs(60))),
        };
        assert!(consume_recovery_phrase_challenge(&mut mismatched, "other", now).is_err());
        assert!(mismatched.pending.is_none());
    }

    #[test]
    fn regular_identity_info_serialization_never_contains_mnemonic() {
        let value = serde_json::to_value(IdentityInfo {
            user_id: "user".into(),
            device_id: "device".into(),
            display_name: Some("Alice".into()),
        })
        .expect("serialize identity info");

        assert!(value.get("mnemonic").is_none());
    }
}

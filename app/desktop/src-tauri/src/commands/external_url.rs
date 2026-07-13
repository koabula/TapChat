use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use serde::Serialize;
use tapchat_core::external_fetch::{
    assess_external_url, ExternalNetworkClass, ExternalResourceKind,
};
use tauri::State;

use crate::state::AppState;

#[derive(Debug, Clone, Serialize)]
pub struct ExternalUrlPreflight {
    pub purpose: String,
    pub origin: String,
    pub requires_confirmation: bool,
    pub insecure_http: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

fn parse_purpose(value: &str) -> Result<ExternalResourceKind, String> {
    match value {
        "contact_share" => Ok(ExternalResourceKind::ContactShare),
        "group_invite" => Ok(ExternalResourceKind::GroupInvite),
        _ => Err("external_url_rejected".into()),
    }
}

#[tauri::command]
pub async fn preflight_external_url(
    state: State<'_, AppState>,
    url: String,
    purpose: String,
) -> Result<ExternalUrlPreflight, String> {
    let purpose = parse_purpose(&purpose)?;
    let assessment = assess_external_url(&url, purpose)
        .await
        .map_err(|error| error.to_string())?;
    let origin = assessment.origin().to_string();
    let insecure_http = assessment.insecure_http();
    let requires_confirmation = assessment.network_class() == ExternalNetworkClass::Private;
    if !requires_confirmation {
        return Ok(ExternalUrlPreflight {
            purpose: purpose.as_str().into(),
            origin,
            requires_confirmation: false,
            insecure_http,
            approval_id: None,
            expires_at: None,
        });
    }

    let mut token = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut token);
    let approval_id = URL_SAFE_NO_PAD.encode(token);
    let expires_at = SystemTime::now()
        .checked_add(Duration::from_secs(60))
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map(|value| value.as_millis() as u64)
        .ok_or_else(|| "external_url_rejected".to_string())?;
    state.ports.lock().await.stage_external_url_approval(
        approval_id.clone(),
        purpose,
        assessment.approve(),
    );
    Ok(ExternalUrlPreflight {
        purpose: purpose.as_str().into(),
        origin,
        requires_confirmation: true,
        insecure_http,
        approval_id: Some(approval_id),
        expires_at: Some(expires_at),
    })
}

#[tauri::command]
pub async fn approve_external_url(
    state: State<'_, AppState>,
    approval_id: String,
) -> Result<(), String> {
    if state
        .ports
        .lock()
        .await
        .activate_external_url_approval(&approval_id)
    {
        Ok(())
    } else {
        Err("external_url_approval_expired".into())
    }
}

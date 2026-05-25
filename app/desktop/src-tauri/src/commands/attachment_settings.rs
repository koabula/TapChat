use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tauri::State;

use crate::state::AppState;
use tapchat_core::cli::profile::Profile;

const ATTACHMENT_SETTINGS_KEY: &str = "desktop.attachment_settings";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentSettings {
    /// When true, automatically download image/audio/video attachments (<=10MB)
    /// from trusted contacts during sync.
    #[serde(default)]
    pub auto_download_media: bool,
    /// When true, show a save dialog every time the user downloads an attachment.
    /// When false, download silently to the profile's attachments directory.
    #[serde(default)]
    pub always_ask_save_path: bool,
}

impl Default for AttachmentSettings {
    fn default() -> Self {
        Self {
            auto_download_media: true,
            always_ask_save_path: false,
        }
    }
}

fn settings_path(profile_root: &PathBuf) -> PathBuf {
    profile_root.join("attachment_settings.json")
}

fn load_settings(profile: &Profile) -> AttachmentSettings {
    match profile.load_private_setting(ATTACHMENT_SETTINGS_KEY) {
        Ok(Some(settings)) => settings,
        _ => migrate_legacy_settings(profile).unwrap_or_default(),
    }
}

fn save_settings(profile: &Profile, settings: &AttachmentSettings) -> Result<(), String> {
    profile
        .save_private_setting(ATTACHMENT_SETTINGS_KEY, settings)
        .map_err(|e| e.to_string())?;
    let legacy_path = settings_path(&profile.root().to_path_buf());
    if legacy_path.exists() {
        std::fs::remove_file(&legacy_path).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn migrate_legacy_settings(profile: &Profile) -> Result<AttachmentSettings, String> {
    let path = settings_path(&profile.root().to_path_buf());
    if !path.exists() {
        return Ok(AttachmentSettings::default());
    }
    let settings = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    profile
        .save_private_setting(ATTACHMENT_SETTINGS_KEY, &settings)
        .map_err(|e| e.to_string())?;
    std::fs::remove_file(&path).map_err(|e| e.to_string())?;
    Ok(settings)
}

#[tauri::command]
pub async fn get_attachment_settings(
    state: State<'_, AppState>,
) -> Result<AttachmentSettings, String> {
    let inner = state.inner.read().await;
    let pm = inner.profile_manager.inner.read().await;
    match &pm.active_profile {
        Some(profile) => Ok(load_settings(profile)),
        None => Ok(AttachmentSettings::default()),
    }
}

#[tauri::command]
pub async fn set_attachment_settings(
    state: State<'_, AppState>,
    settings: AttachmentSettings,
) -> Result<(), String> {
    let inner = state.inner.read().await;
    let pm = inner.profile_manager.inner.read().await;
    match &pm.active_profile {
        Some(profile) => save_settings(profile, &settings),
        None => Err("No active profile".into()),
    }
}

/// Returns the cache directory path for downloaded attachments.
#[tauri::command]
pub async fn get_attachment_cache_dir(state: State<'_, AppState>) -> Result<String, String> {
    let inner = state.inner.read().await;
    let dir = inner.ports.persistence.attachments_dir().await;
    match dir {
        Some(path) => Ok(path.to_string_lossy().into()),
        None => Err("No profile active".into()),
    }
}

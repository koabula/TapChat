use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tauri::State;

use crate::state::AppState;
use tapchat_core::cli::profile::Profile;

const ATTACHMENT_SETTINGS_KEY: &str = "desktop.attachment_settings";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentSettings {
    /// When true, prefetch only screen previews from accepted conversations.
    /// The alias migrates the former setting without enabling original downloads.
    #[serde(default = "default_prefetch_previews", alias = "auto_download_media")]
    pub prefetch_previews: bool,
    /// When true, show a save dialog every time the user downloads an attachment.
    /// When false, save to the operating system Downloads directory.
    #[serde(default)]
    pub always_ask_save_path: bool,
}

impl Default for AttachmentSettings {
    fn default() -> Self {
        Self {
            prefetch_previews: true,
            always_ask_save_path: false,
        }
    }
}

fn default_prefetch_previews() -> bool {
    true
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

pub(crate) async fn preview_prefetch_enabled(state: &AppState) -> bool {
    let inner = state.inner.read().await;
    let pm = inner.profile_manager.inner.read().await;
    pm.active_profile
        .as_ref()
        .map(load_settings)
        .unwrap_or_default()
        .prefetch_previews
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
) -> crate::errors::DesktopResult<AttachmentSettings> {
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
) -> crate::errors::DesktopResult<()> {
    let inner = state.inner.read().await;
    let pm = inner.profile_manager.inner.read().await;
    match &pm.active_profile {
        Some(profile) => Ok(save_settings(profile, &settings)?),
        None => Err("No active profile".into()),
    }
}

/// Returns the cache directory path for downloaded attachments.
#[tauri::command]
pub async fn get_attachment_cache_dir(
    state: State<'_, AppState>,
) -> crate::errors::DesktopResult<String> {
    let persistence = {
        let ports = state.ports.lock().await;
        ports.persistence.clone()
    };
    let dir = persistence.attachments_dir().await;
    match dir {
        Some(path) => Ok(path.to_string_lossy().into()),
        None => Err("No profile active".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_auto_download_setting_migrates_only_to_preview_prefetch() {
        let migrated: AttachmentSettings =
            serde_json::from_str(r#"{"auto_download_media":false,"always_ask_save_path":true}"#)
                .expect("legacy settings");
        assert!(!migrated.prefetch_previews);
        assert!(migrated.always_ask_save_path);
        let fresh: AttachmentSettings = serde_json::from_str("{}").expect("default settings");
        assert!(fresh.prefetch_previews);
    }
}

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tauri::State;

use crate::state::AppState;

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

fn load_settings(profile_root: &PathBuf) -> AttachmentSettings {
    let path = settings_path(profile_root);
    if path.exists() {
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    } else {
        AttachmentSettings::default()
    }
}

fn save_settings(profile_root: &PathBuf, settings: &AttachmentSettings) -> Result<(), String> {
    let path = settings_path(profile_root);
    let json = serde_json::to_string_pretty(settings).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_attachment_settings(
    state: State<'_, AppState>,
) -> Result<AttachmentSettings, String> {
    let inner = state.inner.read().await;
    let pm = inner.profile_manager.inner.read().await;
    match &pm.active_profile {
        Some(profile) => Ok(load_settings(&profile.root().to_path_buf())),
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
        Some(profile) => save_settings(&profile.root().to_path_buf(), &settings),
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

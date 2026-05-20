use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::PathBuf;
use tauri::State;

use crate::state::AppState;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupSyncMode {
    Auto,
    Polling,
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupSyncSettings {
    #[serde(default = "default_mode")]
    pub mode: GroupSyncMode,
    #[serde(default = "default_max_websocket_groups")]
    pub max_websocket_groups: u16,
    #[serde(default = "default_poll_interval_minutes")]
    pub poll_interval_minutes: u16,
    #[serde(default)]
    pub important_group_ids: Vec<String>,
}

impl Default for GroupSyncSettings {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            max_websocket_groups: default_max_websocket_groups(),
            poll_interval_minutes: default_poll_interval_minutes(),
            important_group_ids: Vec::new(),
        }
    }
}

fn default_mode() -> GroupSyncMode {
    GroupSyncMode::Auto
}

fn default_max_websocket_groups() -> u16 {
    5
}

fn default_poll_interval_minutes() -> u16 {
    5
}

fn normalize_settings(mut settings: GroupSyncSettings) -> GroupSyncSettings {
    settings.max_websocket_groups = settings.max_websocket_groups.min(50);
    settings.poll_interval_minutes = settings.poll_interval_minutes.clamp(1, 1440);
    let mut seen = BTreeSet::new();
    settings.important_group_ids = settings
        .important_group_ids
        .into_iter()
        .map(|group_id| group_id.trim().to_string())
        .filter(|group_id| !group_id.is_empty() && seen.insert(group_id.clone()))
        .collect();
    settings
}

fn settings_path(profile_root: &PathBuf) -> PathBuf {
    profile_root.join("group_sync_settings.json")
}

fn load_settings(profile_root: &PathBuf) -> GroupSyncSettings {
    let path = settings_path(profile_root);
    if path.exists() {
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .map(normalize_settings)
            .unwrap_or_default()
    } else {
        GroupSyncSettings::default()
    }
}

fn save_settings(profile_root: &PathBuf, settings: &GroupSyncSettings) -> Result<(), String> {
    let path = settings_path(profile_root);
    let normalized = normalize_settings(settings.clone());
    let json = serde_json::to_string_pretty(&normalized).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_group_sync_settings(
    state: State<'_, AppState>,
) -> Result<GroupSyncSettings, String> {
    let inner = state.inner.read().await;
    let pm = inner.profile_manager.inner.read().await;
    match &pm.active_profile {
        Some(profile) => Ok(load_settings(&profile.root().to_path_buf())),
        None => Ok(GroupSyncSettings::default()),
    }
}

#[tauri::command]
pub async fn set_group_sync_settings(
    state: State<'_, AppState>,
    settings: GroupSyncSettings,
) -> Result<GroupSyncSettings, String> {
    let inner = state.inner.read().await;
    let pm = inner.profile_manager.inner.read().await;
    match &pm.active_profile {
        Some(profile) => {
            let normalized = normalize_settings(settings);
            save_settings(&profile.root().to_path_buf(), &normalized)?;
            Ok(normalized)
        }
        None => Err("No active profile".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_clamps_ranges_and_deduplicates_groups() {
        let settings = normalize_settings(GroupSyncSettings {
            mode: GroupSyncMode::Auto,
            max_websocket_groups: 80,
            poll_interval_minutes: 0,
            important_group_ids: vec![
                "group-a".into(),
                " ".into(),
                "group-a".into(),
                "group-b".into(),
            ],
        });

        assert_eq!(settings.max_websocket_groups, 50);
        assert_eq!(settings.poll_interval_minutes, 1);
        assert_eq!(
            settings.important_group_ids,
            vec!["group-a".to_string(), "group-b".to_string()]
        );
    }
}

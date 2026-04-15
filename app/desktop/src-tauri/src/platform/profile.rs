use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use tapchat_core::cli::profile::{Profile, ProfileRegistry, ProfileMetadata, RuntimeMetadata};
use tapchat_core::persistence::CorePersistenceSnapshot;

/// Desktop profile manager - wraps CLI ProfileRegistry and provides
/// async access for the Tauri app.
pub struct ProfileManager {
    pub inner: Arc<RwLock<ProfileManagerInner>>,
}

pub struct ProfileManagerInner {
    pub registry: ProfileRegistry,
    pub active_profile: Option<Profile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ProfileSummary {
    pub name: String,
    pub path: PathBuf,
    pub is_active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_bound: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStartupCheck {
    pub has_active_profile: bool,
    pub has_identity: bool,
    pub has_runtime_binding: bool,
    pub needs_onboarding: bool,
    pub profile_path: Option<PathBuf>,
}

impl ProfileManager {
    pub fn new() -> Self {
        let registry = ProfileRegistry::load().unwrap_or_default();
        let active_profile = registry
            .active_profile
            .as_ref()
            .and_then(|path| Profile::open(path).ok());

        Self {
            inner: Arc::new(RwLock::new(ProfileManagerInner {
                registry,
                active_profile,
            })),
        }
    }

    /// Create ProfileManager with a specific profile name (for multi-instance mode).
    /// This loads the named profile instead of the registry's active_profile.
    pub fn with_profile_name(name: &str) -> Self {
        let registry = ProfileRegistry::load().unwrap_or_default();

        // Find profile by name in registry
        let profile = registry
            .profiles
            .iter()
            .find(|entry| entry.name == name)
            .and_then(|entry| Profile::open(&entry.root_dir).ok());

        if profile.is_none() {
            log::warn!(
                "Profile '{}' not found in registry. Available profiles: {}",
                name,
                registry.profiles.iter().map(|e| e.name.as_str()).collect::<Vec<_>>().join(", ")
            );
        }

        Self {
            inner: Arc::new(RwLock::new(ProfileManagerInner {
                registry,
                active_profile: profile,
            })),
        }
    }

    /// Get the inner Arc for sharing with platform ports.
    pub fn inner_arc(&self) -> Arc<RwLock<ProfileManagerInner>> {
        self.inner.clone()
    }

    /// Create ProfileManager from an existing inner Arc.
    pub fn from_inner(inner: Arc<RwLock<ProfileManagerInner>>) -> Self {
        Self { inner }
    }

    /// Check if we need onboarding or can go directly to active session.
    pub async fn check_session_startup(&self) -> SessionStartupCheck {
        let inner = self.inner.read().await;

        let has_active_profile = inner.active_profile.is_some();
        let profile = inner.active_profile.as_ref();

        let has_identity = profile
            .map(|p| p.metadata().user_id.is_some() && p.metadata().device_id.is_some())
            .unwrap_or(false);

        let has_runtime_binding = profile
            .map(|p| {
                // Check if runtime metadata exists and has base_url
                p.load_runtime_metadata()
                    .map(|r| r.base_url.is_some())
                    .unwrap_or(false)
            })
            .unwrap_or(false);

        let needs_onboarding = !has_active_profile || !has_identity;

        SessionStartupCheck {
            has_active_profile,
            has_identity,
            has_runtime_binding,
            needs_onboarding,
            profile_path: profile.map(|p| p.root().to_path_buf()),
        }
    }

    /// List all registered profiles.
    pub async fn list_profiles(&self) -> Vec<ProfileSummary> {
        let inner = self.inner.read().await;
        let active_path = inner.registry.active_profile.as_ref();

        inner
            .registry
            .profiles
            .iter()
            .map(|entry| {
                let is_active = active_path
                    .as_ref()
                    .is_some_and(|active| active == &&entry.root_dir);

                let runtime_bound = if is_active {
                    inner
                        .active_profile
                        .as_ref()
                        .and_then(|p| p.load_runtime_metadata().ok())
                        .map(|r| r.base_url.is_some())
                } else {
                    Profile::open(&entry.root_dir)
                        .ok()
                        .and_then(|p| p.load_runtime_metadata().ok())
                        .map(|r| r.base_url.is_some())
                };

                ProfileSummary {
                    name: entry.name.clone(),
                    path: entry.root_dir.clone(),
                    is_active,
                    user_id: entry.user_id.clone(),
                    device_id: entry.device_id.clone(),
                    runtime_bound,
                }
            })
            .collect()
    }

    /// Create a new profile.
    pub async fn create_profile(&self, name: &str, root: PathBuf) -> Result<ProfileSummary> {
        let mut inner = self.inner.write().await;

        // Profile::init calls sync_registry_entry which saves registry to disk.
        // We need to reload the registry from disk to sync our in-memory state.
        let profile = Profile::init(name, &root)?;

        // Reload registry to get the entry that was just saved by sync_registry_entry
        inner.registry = tapchat_core::cli::profile::ProfileRegistry::load()
            .map_err(|e| anyhow!("Failed to reload registry after profile init: {}", e))?;

        // Set this profile as active if no active profile exists
        let is_active = if inner.registry.active_profile.is_none() {
            inner.registry.active_profile = Some(root.clone());
            inner.active_profile = Some(profile);
            inner.registry.save()?;
            true
        } else {
            inner.active_profile = Some(profile);
            inner.registry.active_profile.as_ref() == Some(&root)
        };

        let entry = inner.active_profile.as_ref().unwrap().metadata();

        Ok(ProfileSummary {
            name: entry.name.clone(),
            path: entry.root_dir.clone(),
            is_active,
            user_id: entry.user_id.clone(),
            device_id: entry.device_id.clone(),
            runtime_bound: None,
        })
    }

    /// Activate an existing profile.
    pub async fn activate_profile(&self, path: &PathBuf) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.registry.set_active(path)?;
        inner.active_profile = Some(Profile::open(path)?);
        inner.registry.save()?;
        Ok(())
    }

    /// Delete a profile (removes registry entry and directory).
    /// Cannot delete the active profile.
    pub async fn delete_profile(&self, path: &PathBuf) -> Result<()> {
        let mut inner = self.inner.write().await;

        // Cannot delete active profile
        if inner.registry.active_profile.as_ref() == Some(path) {
            return Err(anyhow!("Cannot delete the active profile"));
        }

        // Check if profile exists in registry
        if !inner.registry.profiles.iter().any(|entry| entry.root_dir == *path) {
            return Err(anyhow!("Profile not found in registry"));
        }

        // Remove from registry
        inner.registry.remove(path);
        inner.registry.save()?;

        // Delete the directory
        if path.exists() {
            std::fs::remove_dir_all(path)
                .map_err(|e| anyhow!("Failed to delete profile directory: {}", e))?;
        }

        Ok(())
    }

    /// Get the active profile's metadata.
    pub async fn get_active_metadata(&self) -> Option<ProfileMetadata> {
        let inner = self.inner.read().await;
        inner.active_profile.as_ref().map(|p| p.metadata().clone())
    }

    /// Get the active profile's runtime metadata.
    pub async fn get_runtime_metadata(&self) -> Option<RuntimeMetadata> {
        let inner = self.inner.read().await;
        inner
            .active_profile
            .as_ref()
            .and_then(|p| p.load_runtime_metadata().ok())
    }

    /// Update identity in active profile.
    /// This updates the profile metadata and syncs the registry entry.
    pub async fn update_identity(
        &self,
        user_id: Option<String>,
        device_id: Option<String>,
    ) -> Result<()> {
        let mut inner = self.inner.write().await;
        if let Some(ref mut profile) = inner.active_profile {
            profile.update_identity(user_id, device_id)?;
            // Reload registry from disk to sync in-memory state
            // (profile.update_identity saves to disk but we need to update our in-memory copy)
            inner.registry = tapchat_core::cli::profile::ProfileRegistry::load()
                .map_err(|e| anyhow!("Failed to reload registry: {}", e))?;
        }
        Ok(())
    }

    /// Save runtime metadata to active profile.
    pub async fn save_runtime_metadata(&self, runtime: &RuntimeMetadata) -> Result<()> {
        let inner = self.inner.read().await;
        if let Some(ref profile) = inner.active_profile {
            profile.save_runtime_metadata(runtime)?;
        }
        Ok(())
    }

    /// Load snapshot from active profile.
    pub async fn load_snapshot(&self) -> Result<CorePersistenceSnapshot> {
        let inner = self.inner.read().await;
        match &inner.active_profile {
            Some(profile) => profile.load_snapshot(),
            None => Ok(CorePersistenceSnapshot::default()),
        }
    }

    /// Save snapshot to active profile.
    pub async fn save_snapshot(&self, snapshot: &CorePersistenceSnapshot) -> Result<()> {
        let inner = self.inner.read().await;
        if let Some(ref profile) = inner.active_profile {
            profile.save_snapshot(snapshot)?;
        }
        Ok(())
    }

    /// Get the base URL for API calls from runtime metadata.
    pub async fn get_base_url(&self) -> Option<String> {
        self.get_runtime_metadata()
            .await
            .and_then(|r| r.base_url)
    }

    /// Get WebSocket URL from runtime metadata.
    pub async fn get_websocket_url(&self) -> Option<String> {
        self.get_runtime_metadata()
            .await
            .and_then(|r| r.websocket_base_url)
    }
}

impl Default for ProfileManager {
    fn default() -> Self {
        Self::new()
    }
}
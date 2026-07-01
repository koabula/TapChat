use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use tapchat_core::cli::profile::{
    Profile, ProfileInitOptions, ProfileMetadata, ProfileRegistry, RuntimeMetadata,
};
use tapchat_core::persistence::CorePersistenceSnapshot;

/// Desktop profile manager - wraps CLI ProfileRegistry and provides
/// async access for the Tauri app.
pub struct ProfileManager {
    pub inner: Arc<RwLock<ProfileManagerInner>>,
}

pub struct ProfileManagerInner {
    pub registry: ProfileRegistry,
    pub active_profile: Option<Profile>,
    pub locked_profile_path: Option<PathBuf>,
    pub unlock_error: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unlock_error: Option<String>,
}

impl ProfileManager {
    pub fn new() -> Self {
        let registry = ProfileRegistry::load().unwrap_or_default();
        let (active_profile, locked_profile_path, unlock_error) =
            load_registry_active_profile(&registry);

        Self {
            inner: Arc::new(RwLock::new(ProfileManagerInner {
                registry,
                active_profile,
                locked_profile_path,
                unlock_error,
            })),
        }
    }

    /// Create ProfileManager with a specific profile name (for multi-instance mode).
    /// This loads the named profile instead of the registry's active_profile.
    pub fn with_profile_name(name: &str) -> Self {
        let registry = ProfileRegistry::load().unwrap_or_default();

        // Find profile by name in registry
        let selected_path = registry
            .profiles
            .iter()
            .find(|entry| entry.name == name)
            .map(|entry| entry.root_dir.clone());
        let (profile, locked_profile_path, unlock_error) = match selected_path {
            Some(path) => match Profile::open(&path) {
                Ok(profile) => (Some(profile), None, None),
                Err(error) => {
                    log::error!(
                        "Failed to unlock profile '{}' at {}: {error:#}",
                        name,
                        path.display()
                    );
                    (None, Some(path), Some(error.to_string()))
                }
            },
            None => (None, None, None),
        };

        if profile.is_none() {
            log::warn!(
                "Profile '{}' not found in registry. Available profiles: {}",
                name,
                registry
                    .profiles
                    .iter()
                    .map(|e| e.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }

        Self {
            inner: Arc::new(RwLock::new(ProfileManagerInner {
                registry,
                active_profile: profile,
                locked_profile_path,
                unlock_error,
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
        let locked_profile_path = inner.locked_profile_path.clone();
        let unlock_error = inner.unlock_error.clone();

        let has_identity = profile
            .map(|p| p.metadata().user_id.is_some() && p.metadata().device_id.is_some())
            .unwrap_or(false);

        let has_runtime_binding = profile
            .map(|p| {
                let runtime_bound = p
                    .load_runtime_metadata()
                    .map(|r| r.base_url.is_some() || r.public_base_url.is_some())
                    .unwrap_or(false);
                let snapshot_bound = p
                    .load_snapshot()
                    .map(|snapshot| snapshot.deployment.is_some())
                    .unwrap_or(false);
                runtime_bound && snapshot_bound
            })
            .unwrap_or(false);

        let needs_onboarding = unlock_error.is_none()
            && (!has_active_profile || !has_identity || !has_runtime_binding);

        SessionStartupCheck {
            has_active_profile,
            has_identity,
            has_runtime_binding,
            needs_onboarding,
            profile_path: profile
                .map(|p| p.root().to_path_buf())
                .or(locked_profile_path),
            unlock_error,
        }
    }

    /// List all registered profiles.
    pub async fn list_profiles(&self) -> Vec<ProfileSummary> {
        let inner = self.inner.read().await;
        let active_path = inner
            .active_profile
            .as_ref()
            .map(|profile| profile.root().to_path_buf())
            .or_else(|| inner.registry.active_profile.clone());

        inner
            .registry
            .profiles
            .iter()
            .map(|entry| {
                let is_active = active_path
                    .as_ref()
                    .is_some_and(|active| active == &entry.root_dir);

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
    pub async fn create_profile(
        &self,
        name: &str,
        root: PathBuf,
        passphrase: Option<String>,
    ) -> Result<ProfileSummary> {
        let mut inner = self.inner.write().await;

        // Profile::init calls sync_registry_entry which saves registry to disk.
        // We need to reload the registry from disk to sync our in-memory state.
        let profile = Profile::init_with_options(
            name,
            &root,
            ProfileInitOptions {
                passphrase,
                use_keychain: true,
            },
        )?;

        // Reload registry to get the entry that was just saved by sync_registry_entry
        inner.registry = tapchat_core::cli::profile::ProfileRegistry::load()
            .map_err(|e| anyhow!("Failed to reload registry after profile init: {}", e))?;

        inner.registry.active_profile = Some(root.clone());
        inner.active_profile = Some(profile);
        inner.locked_profile_path = None;
        inner.unlock_error = None;
        inner.registry.save()?;
        let is_active = true;

        let entry = inner
            .active_profile
            .as_ref()
            .ok_or_else(|| anyhow!("active profile missing after profile creation"))?
            .metadata();

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
    pub async fn activate_profile(&self, path: &PathBuf, passphrase: Option<String>) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.registry.set_active(path)?;
        inner.active_profile = Some(Profile::open_with_passphrase(path, passphrase)?);
        inner.locked_profile_path = None;
        inner.unlock_error = None;
        inner.registry.save()?;
        Ok(())
    }

    /// Select an existing profile for the next process start.
    ///
    /// This validates that the target profile can be opened, then writes the
    /// registry's active profile on disk. It deliberately does not replace the
    /// in-process active profile or engine; the desktop UI relaunches after this
    /// command so the new process can perform a clean startup.
    pub async fn select_profile_for_restart(
        &self,
        path: &PathBuf,
        passphrase: Option<String>,
    ) -> Result<()> {
        {
            let inner = self.inner.read().await;
            if !inner
                .registry
                .profiles
                .iter()
                .any(|entry| entry.root_dir == *path)
            {
                return Err(anyhow!(
                    "profile {} is not registered on this device",
                    path.display()
                ));
            }
        }

        let profile = Profile::open_with_passphrase(path, passphrase)?;
        drop(profile);

        let mut inner = self.inner.write().await;
        let mut registry = inner.registry.clone();
        registry.set_active(path)?;
        registry.save()?;
        inner.registry = registry;
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
        if !inner
            .registry
            .profiles
            .iter()
            .any(|entry| entry.root_dir == *path)
        {
            return Err(anyhow!("Profile not found in registry"));
        }

        Profile::cleanup_profile_keychain_entries(path)?;

        // Delete the directory
        if path.exists() {
            std::fs::remove_dir_all(path)
                .map_err(|e| anyhow!("Failed to delete profile directory: {}", e))?;
        }

        // Remove from registry after keychain and directory deletion succeed.
        inner.registry.remove(path);
        inner.registry.save()?;

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
        self.get_runtime_metadata().await.and_then(|r| r.base_url)
    }

    /// Get WebSocket URL from runtime metadata.
    pub async fn get_websocket_url(&self) -> Option<String> {
        self.get_runtime_metadata()
            .await
            .and_then(|r| r.websocket_base_url)
    }
}

fn load_registry_active_profile(
    registry: &ProfileRegistry,
) -> (Option<Profile>, Option<PathBuf>, Option<String>) {
    let Some(path) = registry.active_profile.as_ref() else {
        return (None, None, None);
    };
    match Profile::open(path) {
        Ok(profile) => (Some(profile), None, None),
        Err(error) => {
            log::error!(
                "Failed to unlock active profile at {}: {error:#}",
                path.display()
            );
            (None, Some(path.clone()), Some(error.to_string()))
        }
    }
}

impl Default for ProfileManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    use tapchat_core::cli::profile::{Profile, ProfileInitOptions, ProfileRegistry};

    use super::ProfileManager;

    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock")
    }

    fn test_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tapchat-desktop-profile-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).expect("create test dir");
        dir
    }

    #[tokio::test]
    async fn select_profile_for_restart_rejects_wrong_passphrase_without_saving_active_profile() {
        let _guard = env_lock();
        let dir = test_dir();
        let registry_path = dir.join("config").join("profiles.json");
        unsafe {
            std::env::set_var("TAPCHAT_PROFILE_REGISTRY_PATH", &registry_path);
        }

        let alice_root = dir.join("alice");
        let bob_root = dir.join("bob");
        let alice = Profile::init_with_options(
            "alice",
            &alice_root,
            ProfileInitOptions {
                passphrase: Some("alice-passphrase".into()),
                use_keychain: false,
            },
        )
        .expect("init alice");
        let bob = Profile::init_with_options(
            "bob",
            &bob_root,
            ProfileInitOptions {
                passphrase: Some("bob-passphrase".into()),
                use_keychain: false,
            },
        )
        .expect("init bob");
        drop(alice);
        drop(bob);

        let manager = ProfileManager::new();
        let error = manager
            .select_profile_for_restart(&bob_root, Some("wrong".into()))
            .await
            .expect_err("wrong passphrase should fail");

        assert!(error
            .to_string()
            .contains("failed to unlock encrypted profile"));
        let registry = ProfileRegistry::load().expect("load registry");
        assert_eq!(
            registry.active_profile.as_deref(),
            Some(alice_root.as_path())
        );

        unsafe {
            std::env::remove_var("TAPCHAT_PROFILE_REGISTRY_PATH");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn select_profile_for_restart_saves_target_as_next_active_profile() {
        let _guard = env_lock();
        let dir = test_dir();
        let registry_path = dir.join("config").join("profiles.json");
        unsafe {
            std::env::set_var("TAPCHAT_PROFILE_REGISTRY_PATH", &registry_path);
        }

        let alice_root = dir.join("alice");
        let bob_root = dir.join("bob");
        let alice = Profile::init_with_options(
            "alice",
            &alice_root,
            ProfileInitOptions {
                passphrase: Some("alice-passphrase".into()),
                use_keychain: false,
            },
        )
        .expect("init alice");
        let bob = Profile::init_with_options(
            "bob",
            &bob_root,
            ProfileInitOptions {
                passphrase: Some("bob-passphrase".into()),
                use_keychain: false,
            },
        )
        .expect("init bob");
        drop(alice);
        drop(bob);

        let manager = ProfileManager::new();
        manager
            .select_profile_for_restart(&bob_root, Some("bob-passphrase".into()))
            .await
            .expect("select bob");

        let registry = ProfileRegistry::load().expect("load registry");
        assert_eq!(registry.active_profile.as_deref(), Some(bob_root.as_path()));

        unsafe {
            std::env::remove_var("TAPCHAT_PROFILE_REGISTRY_PATH");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

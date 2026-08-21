use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use tapchat_core::cli::profile::{
    Profile, ProfileInitOptions, ProfileMetadata, ProfileOpenOptions, ProfileRegistry,
    RuntimeMetadata,
};
use tapchat_core::persistence::CorePersistenceSnapshot;

use crate::platform::log_sanitize::redact_id;
use crate::storage_layout::DesktopStorageLayout;

/// Desktop profile manager - wraps CLI ProfileRegistry and provides
/// async access for the Tauri app.
#[derive(Clone)]
pub struct ProfileManager {
    pub inner: Arc<RwLock<ProfileManagerInner>>,
}

pub struct ProfileManagerInner {
    pub registry: ProfileRegistry,
    pub active_profile: Option<Profile>,
    pub locked_profile_path: Option<PathBuf>,
    pub unlock_error: Option<String>,
    pub storage_layout: DesktopStorageLayout,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileProtectionMode {
    KeychainAndPassphrase,
    KeychainOnly,
    PassphraseOnly,
}

impl ProfileProtectionMode {
    fn init_options(self, passphrase: Option<String>) -> Result<ProfileInitOptions> {
        let passphrase = passphrase.filter(|value| !value.is_empty());
        match self {
            Self::KeychainAndPassphrase => {
                if passphrase.is_none() {
                    return Err(anyhow!(
                        "profile_passphrase_required: enter a passphrase for keychain backup protection"
                    ));
                }
                Ok(ProfileInitOptions {
                    passphrase,
                    use_keychain: true,
                })
            }
            Self::KeychainOnly => Ok(ProfileInitOptions {
                passphrase: None,
                use_keychain: true,
            }),
            Self::PassphraseOnly => {
                if passphrase.is_none() {
                    return Err(anyhow!(
                        "profile_passphrase_required: enter a passphrase for passphrase-only protection"
                    ));
                }
                Ok(ProfileInitOptions {
                    passphrase,
                    use_keychain: false,
                })
            }
        }
    }
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock_reason: Option<String>,
}

impl ProfileManager {
    pub fn new() -> Self {
        let layout = DesktopStorageLayout::system_default()
            .expect("desktop storage directories must be available");
        Self::with_layout(layout)
    }

    pub fn with_layout(layout: DesktopStorageLayout) -> Self {
        if let Err(error) = layout.ensure_base_dirs() {
            log::error!("Failed to initialize desktop storage layout: {error}");
        }
        let registry = ProfileRegistry::load_from(&layout.registry_path).unwrap_or_default();
        let (active_profile, locked_profile_path, unlock_error) =
            load_registry_active_profile(&registry, &layout);

        Self {
            inner: Arc::new(RwLock::new(ProfileManagerInner {
                registry,
                active_profile,
                locked_profile_path,
                unlock_error,
                storage_layout: layout,
            })),
        }
    }

    /// Create ProfileManager with a specific registered profile selector.
    pub fn with_profile_selector(selector: &str) -> Self {
        let layout = DesktopStorageLayout::system_default()
            .expect("desktop storage directories must be available");
        Self::with_profile_selector_and_layout(selector, layout)
    }

    pub fn with_profile_selector_and_layout(selector: &str, layout: DesktopStorageLayout) -> Self {
        if let Err(error) = layout.ensure_base_dirs() {
            log::error!("Failed to initialize desktop storage layout: {error}");
        }
        let registry = ProfileRegistry::load_from(&layout.registry_path).unwrap_or_default();

        let selected_path = resolve_profile_selector(&registry, &layout, selector);
        let (profile, locked_profile_path, unlock_error) = match selected_path {
            Ok(path) => match open_managed_profile(&layout, &path, None) {
                Ok(profile) => (Some(profile), None, None),
                Err(error) => {
                    log::error!(
                        "Failed to unlock profile {}: unlock_failed",
                        redact_id("profile", &format!("{selector}:{}", path.display()))
                    );
                    (None, Some(path), Some(error.to_string()))
                }
            },
            Err(error) => (None, None, Some(error)),
        };

        if profile.is_none() && locked_profile_path.is_none() {
            log::warn!(
                "Profile selector {} could not be resolved; available_profile_count={}",
                redact_id("profile", selector),
                registry.profiles.len()
            );
        }

        Self {
            inner: Arc::new(RwLock::new(ProfileManagerInner {
                registry,
                active_profile: profile,
                locked_profile_path,
                unlock_error,
                storage_layout: layout,
            })),
        }
    }

    /// Get the inner Arc for sharing with platform ports.
    pub fn inner_arc(&self) -> Arc<RwLock<ProfileManagerInner>> {
        self.inner.clone()
    }

    pub async fn active_profile_root(&self) -> Option<PathBuf> {
        let inner = self.inner.read().await;
        inner
            .active_profile
            .as_ref()
            .map(|profile| profile.root().to_path_buf())
            .or_else(|| inner.locked_profile_path.clone())
            .or_else(|| inner.registry.active_profile.clone())
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

        let snapshot_result = profile.map(|p| p.load_snapshot());
        let snapshot_load_error = match &snapshot_result {
            Some(Err(error)) => Some(format!("Failed to load snapshot: {error}")),
            _ => None,
        };
        let has_runtime_binding = profile
            .map(|p| {
                let runtime_bound = p
                    .load_runtime_metadata()
                    .map(|r| r.base_url.is_some() || r.public_base_url.is_some())
                    .unwrap_or(false);
                let snapshot_bound = snapshot_result
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .map(|snapshot| snapshot.deployment.is_some())
                    .unwrap_or(false);
                runtime_bound && snapshot_bound
            })
            .unwrap_or(false);

        let startup_error = unlock_error.clone().or(snapshot_load_error);
        let lock_reason = if unlock_error.as_deref().is_some_and(|error| {
            error.starts_with("profile_not_found:") || error.starts_with("profile_ambiguous:")
        }) {
            Some("profile_selection_required".to_string())
        } else if unlock_error.is_some() {
            Some("profile_locked".to_string())
        } else if startup_error.is_some() {
            Some("snapshot_load_failed".to_string())
        } else {
            None
        };

        let needs_onboarding = startup_error.is_none()
            && (!has_active_profile || !has_identity || !has_runtime_binding);

        SessionStartupCheck {
            has_active_profile,
            has_identity,
            has_runtime_binding,
            needs_onboarding,
            profile_path: profile
                .map(|p| p.root().to_path_buf())
                .or(locked_profile_path),
            unlock_error: startup_error,
            lock_reason,
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
                    open_managed_profile(&inner.storage_layout, &entry.root_dir, None)
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
        passphrase: Option<String>,
        protection_mode: ProfileProtectionMode,
    ) -> Result<ProfileSummary> {
        let mut inner = self.inner.write().await;
        let init_options = protection_mode.init_options(passphrase)?;
        let (profile_id, storage_paths) = inner.storage_layout.new_profile();
        let root = storage_paths.profile_root.clone();
        let registry_path = inner.storage_layout.registry_path.clone();

        let profile = Profile::init_with_storage(
            name,
            profile_id,
            storage_paths,
            Some(registry_path.clone()),
            init_options,
        )?;

        inner.registry = ProfileRegistry::load_from(&registry_path)
            .map_err(|e| anyhow!("Failed to reload registry after profile init: {}", e))?;

        inner.registry.active_profile = Some(root.clone());
        inner.active_profile = Some(profile);
        inner.locked_profile_path = None;
        inner.unlock_error = None;
        inner.registry.save_to(&registry_path)?;
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
        let profile = open_managed_profile(&inner.storage_layout, path, passphrase)?;
        if let Some(current) = inner.active_profile.as_ref() {
            current.checkpoint_local_store()?;
        }
        inner.registry.set_active(path)?;
        inner.active_profile = Some(profile);
        inner.locked_profile_path = None;
        inner.unlock_error = None;
        inner
            .registry
            .save_to(&inner.storage_layout.registry_path)?;
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

        let layout = { self.inner.read().await.storage_layout.clone() };
        let profile = open_managed_profile(&layout, path, passphrase)?;
        drop(profile);

        let mut inner = self.inner.write().await;
        let mut registry = inner.registry.clone();
        registry.set_active(path)?;
        registry.save_to(&inner.storage_layout.registry_path)?;
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

        let storage_paths = inner.storage_layout.profile_paths_for_root(path)?;
        let transfer_root = storage_paths
            .transfer_staging_dir
            .parent()
            .ok_or_else(|| anyhow!("invalid transfer staging path"))?
            .to_path_buf();

        Profile::cleanup_profile_keychain_entries(path)?;

        // Every target is derived from a validated UUID profile root.
        if path.exists() {
            std::fs::remove_dir_all(path)
                .map_err(|e| anyhow!("Failed to delete profile directory: {}", e))?;
        }
        if transfer_root.exists() {
            std::fs::remove_dir_all(&transfer_root)
                .map_err(|e| anyhow!("Failed to delete profile transfer directory: {}", e))?;
        }
        if storage_paths.attachment_cache_dir.exists() {
            std::fs::remove_dir_all(&storage_paths.attachment_cache_dir)
                .map_err(|e| anyhow!("Failed to delete profile cache directory: {}", e))?;
        }

        // Remove from registry after keychain and directory deletion succeed.
        inner.registry.remove(path);
        inner
            .registry
            .save_to(&inner.storage_layout.registry_path)?;

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
            inner.registry = ProfileRegistry::load_from(&inner.storage_layout.registry_path)
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

    pub async fn checkpoint_active_profile(&self) -> Result<()> {
        let inner = self.inner.read().await;
        if let Some(profile) = inner.active_profile.as_ref() {
            profile.checkpoint_local_store()?;
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

fn resolve_profile_selector(
    registry: &ProfileRegistry,
    layout: &DesktopStorageLayout,
    selector: &str,
) -> std::result::Result<PathBuf, String> {
    if selector.starts_with("profile:") {
        let path = layout
            .profile_paths_for_id(selector)
            .map_err(|_| "profile_not_found: profile id is invalid".to_string())?
            .profile_root;
        return registry
            .profiles
            .iter()
            .any(|entry| entry.root_dir == path)
            .then_some(path)
            .ok_or_else(|| "profile_not_found: profile id is not registered".to_string());
    }

    let candidate_path = PathBuf::from(selector);
    if registry
        .profiles
        .iter()
        .any(|entry| entry.root_dir == candidate_path)
    {
        return Ok(candidate_path);
    }

    let matches: Vec<_> = registry
        .profiles
        .iter()
        .filter(|entry| entry.name == selector)
        .collect();
    match matches.as_slice() {
        [] => Err("profile_not_found: no registered profile matches the selector".to_string()),
        [entry] => Ok(entry.root_dir.clone()),
        _ => Err(
            "profile_ambiguous: multiple profiles share this name; select by profile id or path"
                .to_string(),
        ),
    }
}

fn load_registry_active_profile(
    registry: &ProfileRegistry,
    layout: &DesktopStorageLayout,
) -> (Option<Profile>, Option<PathBuf>, Option<String>) {
    let Some(path) = registry.active_profile.as_ref() else {
        return (None, None, None);
    };
    match open_managed_profile(layout, path, None) {
        Ok(profile) => (Some(profile), None, None),
        Err(error) => {
            log::error!(
                "Failed to unlock active profile {}: unlock_failed",
                redact_id("profile", &path.to_string_lossy())
            );
            (None, Some(path.clone()), Some(error.to_string()))
        }
    }
}

fn open_managed_profile(
    layout: &DesktopStorageLayout,
    path: &PathBuf,
    passphrase: Option<String>,
) -> Result<Profile> {
    Profile::open_with_storage(
        layout.profile_paths_for_root(path)?,
        Some(layout.registry_path.clone()),
        ProfileOpenOptions { passphrase },
    )
}

impl Default for ProfileManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use tapchat_core::cli::profile::{
        Profile, ProfileInitOptions, ProfileRegistry, ProfileRegistryEntry,
    };

    use super::{resolve_profile_selector, ProfileManager, ProfileProtectionMode};
    use crate::storage_layout::DesktopStorageLayout;

    #[test]
    fn profile_protection_modes_require_the_expected_passphrase_and_keychain() {
        let dual = ProfileProtectionMode::KeychainAndPassphrase
            .init_options(Some("secret".into()))
            .expect("dual protection");
        assert!(dual.use_keychain);
        assert_eq!(dual.passphrase.as_deref(), Some("secret"));

        let passphrase_only = ProfileProtectionMode::PassphraseOnly
            .init_options(Some("secret".into()))
            .expect("passphrase protection");
        assert!(!passphrase_only.use_keychain);
        assert!(ProfileProtectionMode::PassphraseOnly
            .init_options(None)
            .is_err());

        let keychain_only = ProfileProtectionMode::KeychainOnly
            .init_options(Some("ignored".into()))
            .expect("keychain protection");
        assert!(keychain_only.use_keychain);
        assert!(keychain_only.passphrase.is_none());
    }

    fn test_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tapchat-desktop-profile-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).expect("create test dir");
        dir
    }

    #[test]
    fn profile_selector_requires_unique_names_but_accepts_profile_ids() {
        let dir = test_dir();
        let layout =
            DesktopStorageLayout::from_roots(dir.join("data"), dir.join("cache"), dir.join("logs"));
        let (alice_id, alice_paths) = layout.new_profile();
        let (_other_id, other_paths) = layout.new_profile();
        let registry = ProfileRegistry {
            profiles: vec![
                ProfileRegistryEntry {
                    name: "default".into(),
                    root_dir: alice_paths.profile_root.clone(),
                    user_id: None,
                    device_id: None,
                },
                ProfileRegistryEntry {
                    name: "default".into(),
                    root_dir: other_paths.profile_root,
                    user_id: None,
                    device_id: None,
                },
            ],
            ..ProfileRegistry::default()
        };

        let error = resolve_profile_selector(&registry, &layout, "default")
            .expect_err("duplicate display names must be ambiguous");
        assert!(error.starts_with("profile_ambiguous:"));
        assert_eq!(
            resolve_profile_selector(&registry, &layout, &alice_id).expect("profile id"),
            alice_paths.profile_root
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn profile_selector_reports_missing_profiles_instead_of_starting_onboarding() {
        let dir = test_dir();
        let layout =
            DesktopStorageLayout::from_roots(dir.join("data"), dir.join("cache"), dir.join("logs"));
        let registry = ProfileRegistry::default();

        let error = resolve_profile_selector(&registry, &layout, "missing")
            .expect_err("missing selector must fail");
        assert!(error.starts_with("profile_not_found:"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn profile_selector_accepts_a_unique_name_or_registered_path() {
        let dir = test_dir();
        let layout =
            DesktopStorageLayout::from_roots(dir.join("data"), dir.join("cache"), dir.join("logs"));
        let (_profile_id, paths) = layout.new_profile();
        let registry = ProfileRegistry {
            profiles: vec![ProfileRegistryEntry {
                name: "default".into(),
                root_dir: paths.profile_root.clone(),
                user_id: None,
                device_id: None,
            }],
            ..ProfileRegistry::default()
        };

        assert_eq!(
            resolve_profile_selector(&registry, &layout, "default").expect("unique name"),
            paths.profile_root
        );
        assert_eq!(
            resolve_profile_selector(
                &registry,
                &layout,
                registry.profiles[0].root_dir.to_string_lossy().as_ref(),
            )
            .expect("registered path"),
            registry.profiles[0].root_dir
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn select_profile_for_restart_rejects_wrong_passphrase_without_saving_active_profile() {
        let dir = test_dir();
        let layout =
            DesktopStorageLayout::from_roots(dir.join("data"), dir.join("cache"), dir.join("logs"));
        layout.ensure_base_dirs().expect("layout");
        let (alice_id, alice_paths) = layout.new_profile();
        let (bob_id, bob_paths) = layout.new_profile();
        let alice_root = alice_paths.profile_root.clone();
        let bob_root = bob_paths.profile_root.clone();
        let alice = Profile::init_with_storage(
            "alice",
            alice_id,
            alice_paths,
            Some(layout.registry_path.clone()),
            ProfileInitOptions {
                passphrase: Some("alice-passphrase".into()),
                use_keychain: false,
            },
        )
        .expect("init alice");
        let bob = Profile::init_with_storage(
            "bob",
            bob_id,
            bob_paths,
            Some(layout.registry_path.clone()),
            ProfileInitOptions {
                passphrase: Some("bob-passphrase".into()),
                use_keychain: false,
            },
        )
        .expect("init bob");
        drop(alice);
        drop(bob);

        let manager = ProfileManager::with_layout(layout.clone());
        let error = manager
            .select_profile_for_restart(&bob_root, Some("wrong".into()))
            .await
            .expect_err("wrong passphrase should fail");

        assert!(error
            .to_string()
            .contains("failed to unlock encrypted profile"));
        let registry = ProfileRegistry::load_from(&layout.registry_path).expect("load registry");
        assert_eq!(
            registry.active_profile.as_deref(),
            Some(alice_root.as_path())
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn select_profile_for_restart_saves_target_as_next_active_profile() {
        let dir = test_dir();
        let layout =
            DesktopStorageLayout::from_roots(dir.join("data"), dir.join("cache"), dir.join("logs"));
        layout.ensure_base_dirs().expect("layout");
        let (alice_id, alice_paths) = layout.new_profile();
        let (bob_id, bob_paths) = layout.new_profile();
        let bob_root = bob_paths.profile_root.clone();
        let alice = Profile::init_with_storage(
            "alice",
            alice_id,
            alice_paths,
            Some(layout.registry_path.clone()),
            ProfileInitOptions {
                passphrase: Some("alice-passphrase".into()),
                use_keychain: false,
            },
        )
        .expect("init alice");
        let bob = Profile::init_with_storage(
            "bob",
            bob_id,
            bob_paths,
            Some(layout.registry_path.clone()),
            ProfileInitOptions {
                passphrase: Some("bob-passphrase".into()),
                use_keychain: false,
            },
        )
        .expect("init bob");
        drop(alice);
        drop(bob);

        let manager = ProfileManager::with_layout(layout.clone());
        manager
            .select_profile_for_restart(&bob_root, Some("bob-passphrase".into()))
            .await
            .expect("select bob");

        let registry = ProfileRegistry::load_from(&layout.registry_path).expect("load registry");
        assert_eq!(registry.active_profile.as_deref(), Some(bob_root.as_path()));

        let _ = std::fs::remove_dir_all(&dir);
    }
}

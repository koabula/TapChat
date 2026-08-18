use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use tapchat_core::cli::profile::ProfileStoragePaths;
use tauri::{AppHandle, Manager};

const PROFILE_ID_PREFIX: &str = "profile:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopStorageLayout {
    pub local_data_root: PathBuf,
    pub cache_root: PathBuf,
    pub log_root: PathBuf,
    pub registry_path: PathBuf,
    pub profiles_root: PathBuf,
    pub transfers_root: PathBuf,
    pub attachments_cache_root: PathBuf,
}

impl DesktopStorageLayout {
    pub fn from_app(app: &AppHandle) -> Result<Self> {
        let local_data_root = app
            .path()
            .app_local_data_dir()
            .context("resolve app local data directory")?;
        let cache_root = app
            .path()
            .app_cache_dir()
            .context("resolve app cache directory")?;
        let log_root = app
            .path()
            .app_log_dir()
            .context("resolve app log directory")?;
        Ok(Self::from_roots(local_data_root, cache_root, log_root))
    }

    pub fn system_default() -> Result<Self> {
        if let Some(registry_path) = std::env::var_os("TAPCHAT_PROFILE_REGISTRY_PATH") {
            let registry_path = PathBuf::from(registry_path);
            let local_data_root = registry_path
                .parent()
                .and_then(Path::parent)
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf();
            return Ok(Self::from_roots(
                local_data_root.clone(),
                local_data_root.join("cache"),
                local_data_root.join("logs"),
            )
            .with_registry_path(registry_path));
        }

        let local_data_root = dirs::data_local_dir()
            .ok_or_else(|| anyhow!("could not resolve local data directory"))?
            .join("com.tapchat.desktop");
        let cache_root = dirs::cache_dir()
            .ok_or_else(|| anyhow!("could not resolve cache directory"))?
            .join("com.tapchat.desktop");
        let log_root = local_data_root.join("logs");
        Ok(Self::from_roots(local_data_root, cache_root, log_root))
    }

    pub fn from_roots(local_data_root: PathBuf, cache_root: PathBuf, log_root: PathBuf) -> Self {
        Self {
            registry_path: local_data_root.join("registry").join("profiles.json"),
            profiles_root: local_data_root.join("profiles"),
            transfers_root: local_data_root.join("transfers"),
            attachments_cache_root: cache_root.join("attachments"),
            local_data_root,
            cache_root,
            log_root,
        }
    }

    fn with_registry_path(mut self, registry_path: PathBuf) -> Self {
        self.registry_path = registry_path;
        self
    }

    pub fn new_profile(&self) -> (String, ProfileStoragePaths) {
        let component = uuid::Uuid::new_v4().to_string();
        let profile_id = format!("{PROFILE_ID_PREFIX}{component}");
        (profile_id, self.profile_paths_for_component(&component))
    }

    pub fn profile_paths_for_root(&self, root: &Path) -> Result<ProfileStoragePaths> {
        let component = root
            .file_name()
            .and_then(|value| value.to_str())
            .filter(|value| uuid::Uuid::parse_str(value).is_ok())
            .ok_or_else(|| anyhow!("managed profile directory name is not a UUID"))?;
        let expected = self.profiles_root.join(component);
        if root != expected {
            return Err(anyhow!(
                "profile root is outside the managed profiles directory"
            ));
        }
        Ok(self.profile_paths_for_component(component))
    }

    pub fn profile_paths_for_id(&self, profile_id: &str) -> Result<ProfileStoragePaths> {
        let component = profile_id
            .strip_prefix(PROFILE_ID_PREFIX)
            .filter(|value| uuid::Uuid::parse_str(value).is_ok())
            .ok_or_else(|| anyhow!("profile id is invalid"))?;
        Ok(self.profile_paths_for_component(component))
    }

    pub fn profile_paths_for_component(&self, component: &str) -> ProfileStoragePaths {
        let profile_root = self.profiles_root.join(component);
        ProfileStoragePaths {
            bundles_dir: profile_root.join("bundles"),
            runtime_dir: profile_root.join("runtime"),
            transfer_staging_dir: self
                .transfers_root
                .join(component)
                .join("attachment-staging"),
            attachment_cache_dir: self.attachments_cache_root.join(component),
            profile_root,
        }
    }

    pub fn ensure_base_dirs(&self) -> Result<()> {
        std::fs::create_dir_all(&self.profiles_root).context("create profiles directory")?;
        std::fs::create_dir_all(&self.transfers_root).context("create transfers directory")?;
        std::fs::create_dir_all(&self.attachments_cache_root)
            .context("create attachments cache directory")?;
        if let Some(parent) = self.registry_path.parent() {
            std::fs::create_dir_all(parent).context("create registry directory")?;
        }
        Ok(())
    }
}

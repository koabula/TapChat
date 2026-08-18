use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::RwLock;

use tapchat_core::cli::profile::Profile;
use tapchat_core::ffi_api::PersistStateEffect;
use tapchat_core::persistence::CorePersistenceSnapshot;

use crate::platform::profile::ProfileManagerInner;

/// Persistence implementation for desktop app.
/// Stores state in the active profile's encrypted snapshot file.
#[derive(Clone)]
pub struct DesktopPersistence {
    profile_inner: Arc<RwLock<ProfileManagerInner>>,
}

impl DesktopPersistence {
    pub fn new(profile_inner: Arc<RwLock<ProfileManagerInner>>) -> Self {
        Self { profile_inner }
    }

    /// Get the per-profile discardable encrypted attachment cache root.
    pub async fn attachment_cache_dir(&self) -> Option<PathBuf> {
        let pm = self.profile_inner.read().await;
        pm.active_profile
            .as_ref()
            .map(|p| p.storage_paths().attachment_cache_dir.clone())
    }

    /// Get the durable encrypted transfer staging directory.
    pub async fn transfer_staging_dir(&self) -> Option<PathBuf> {
        let pm = self.profile_inner.read().await;
        pm.active_profile
            .as_ref()
            .map(|p| p.storage_paths().transfer_staging_dir.clone())
    }

    /// Deprecated cache alias retained for non-staging call sites.
    pub async fn attachments_dir(&self) -> Option<PathBuf> {
        self.attachment_cache_dir().await
    }

    /// Get the inbox attachments directory (deprecated alias for attachments_dir).
    pub async fn inbox_attachments_dir(&self) -> Option<PathBuf> {
        self.attachment_cache_dir().await
    }

    /// Get the outbox attachments directory (deprecated alias for attachments_dir).
    pub async fn outbox_attachments_dir(&self) -> Option<PathBuf> {
        self.attachment_cache_dir().await
    }

    /// Handle PersistState effect from CoreEngine.
    pub async fn persist(&self, effect: PersistStateEffect) -> Result<()> {
        let pm = self.profile_inner.read().await;
        if let Some(ref profile) = pm.active_profile {
            profile.persist_state(&effect)?;
        } else {
            log::warn!("persist called but no active_profile set!");
        }
        Ok(())
    }

    /// Save a full snapshot to the profile.
    pub async fn save_snapshot(&self, snapshot: &CorePersistenceSnapshot) -> Result<()> {
        let pm = self.profile_inner.read().await;
        log::info!(
            "save_snapshot called: active_profile={}, local_identity={}, contacts={}",
            pm.active_profile.is_some(),
            snapshot.local_identity.is_some(),
            snapshot.contacts.len()
        );
        if let Some(ref profile) = pm.active_profile {
            profile.save_snapshot(snapshot)?;
            log::info!("Snapshot saved successfully to profile");
        } else {
            log::warn!("save_snapshot called but no active_profile set!");
        }
        Ok(())
    }

    /// Load snapshot from the profile.
    pub async fn load_snapshot(&self) -> Result<CorePersistenceSnapshot> {
        let pm = self.profile_inner.read().await;
        match &pm.active_profile {
            Some(profile) => profile.load_snapshot(),
            None => Ok(CorePersistenceSnapshot::default()),
        }
    }
}

/// Synchronous persistence for use in non-async contexts.
/// Writes directly to disk without going through ProfileManager.
#[allow(dead_code)]
pub fn persist_state_sync(effect: &PersistStateEffect, profile_path: Option<&PathBuf>) {
    if let Some(path) = profile_path {
        if let Ok(profile) = Profile::open(path) {
            let _ = profile.persist_state(effect);
        }
    }
}

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::RwLock;

use tapchat_core::ffi_api::PersistStateEffect;
use tapchat_core::persistence::{CorePersistenceSnapshot, PersistOp, encode_snapshot};

use crate::platform::profile::ProfileManagerInner;

/// Persistence implementation for desktop app.
/// Stores state in the active profile's snapshot.json file.
#[derive(Clone)]
pub struct DesktopPersistence {
    profile_inner: Arc<RwLock<ProfileManagerInner>>,
}

impl DesktopPersistence {
    pub fn new(profile_inner: Arc<RwLock<ProfileManagerInner>>) -> Self {
        Self {
            profile_inner,
        }
    }

    /// Get the inbox attachments directory.
    pub async fn inbox_attachments_dir(&self) -> Option<PathBuf> {
        let pm = self.profile_inner.read().await;
        pm.active_profile
            .as_ref()
            .map(|p| p.metadata().inbox_attachments_dir.clone())
    }

    /// Get the outbox attachments directory.
    pub async fn outbox_attachments_dir(&self) -> Option<PathBuf> {
        let pm = self.profile_inner.read().await;
        pm.active_profile
            .as_ref()
            .map(|p| p.metadata().outbox_attachments_dir.clone())
    }

    /// Handle PersistState effect from CoreEngine.
    pub async fn persist(&self, effect: PersistStateEffect) -> Result<()> {
        // Handle individual ops first (incremental updates)
        for op in &effect.ops {
            self.handle_persist_op(op).await?;
        }

        // If there's a full snapshot, save it
        if let Some(ref snapshot) = effect.snapshot {
            self.save_snapshot(snapshot).await?;
        }

        Ok(())
    }

    async fn handle_persist_op(&self, op: &PersistOp) -> Result<()> {
        match op {
            // Most persist ops are handled via the snapshot mechanism
            // The incremental ops are mostly for future optimization
            _ => Ok(()),
        }
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
        let snapshot_path = path.join("snapshot.json");

        if let Some(ref snapshot) = effect.snapshot {
            if let Ok(encoded) = encode_snapshot(snapshot) {
                // Write atomically
                let tmp = snapshot_path.with_extension("tmp");
                if std::fs::write(&tmp, &encoded).is_ok() {
                    let _ = std::fs::rename(&tmp, &snapshot_path);
                }
            }
        }
    }
}
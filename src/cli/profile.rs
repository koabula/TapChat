use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::model::{DeploymentBundle, IdentityBundle};
use crate::persistence::{CorePersistenceSnapshot, decode_snapshot, encode_snapshot};

use super::util::to_snake_case_json_string;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileMetadata {
    pub name: String,
    pub root_dir: PathBuf,
    pub bundles_dir: PathBuf,
    pub inbox_attachments_dir: PathBuf,
    pub outbox_attachments_dir: PathBuf,
    pub runtime_dir: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_bundle_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RuntimeMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub websocket_base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sharing_secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_root: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_root: Option<PathBuf>,
}
pub struct Profile {
    root: PathBuf,
    meta: ProfileMetadata,
}

impl Profile {
    pub fn init(name: &str, root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root).context("create profile root")?;
        let meta = ProfileMetadata {
            name: name.to_string(),
            bundles_dir: root.join("bundles"),
            inbox_attachments_dir: root.join("attachments").join("inbox"),
            outbox_attachments_dir: root.join("attachments").join("outbox"),
            runtime_dir: root.join("runtime"),
            root_dir: root.clone(),
            user_id: None,
            device_id: None,
            deployment_bundle_path: None,
        };
        let profile = Self { root, meta };
        profile.ensure_layout()?;
        profile.save_metadata()?;
        if !profile.snapshot_path().exists() {
            profile.save_snapshot(&CorePersistenceSnapshot::default())?;
        }
        Ok(profile)
    }

    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let meta_path = root.join("profile.json");
        if !meta_path.exists() {
            bail!("profile.json not found at {}", meta_path.display());
        }
        let meta: ProfileMetadata =
            serde_json::from_slice(&fs::read(&meta_path).context("read profile metadata")?)
                .context("decode profile metadata")?;
        Ok(Self { root, meta })
    }

    pub fn metadata(&self) -> &ProfileMetadata {
        &self.meta
    }

    pub fn update_identity(
        &mut self,
        user_id: Option<String>,
        device_id: Option<String>,
    ) -> Result<()> {
        self.meta.user_id = user_id;
        self.meta.device_id = device_id;
        self.save_metadata()
    }

    pub fn set_deployment_bundle_path(&mut self, path: PathBuf) -> Result<()> {
        self.meta.deployment_bundle_path = Some(path);
        self.save_metadata()
    }

    pub fn snapshot_path(&self) -> PathBuf {
        self.root.join("snapshot.json")
    }

    pub fn runtime_meta_path(&self) -> PathBuf {
        self.meta.runtime_dir.join("runtime.json")
    }

    pub fn load_snapshot(&self) -> Result<CorePersistenceSnapshot> {
        let path = self.snapshot_path();
        if !path.exists() {
            return Ok(CorePersistenceSnapshot::default());
        }
        decode_snapshot(&fs::read(&path).context("read snapshot")?).map_err(anyhow::Error::from)
    }

    pub fn save_snapshot(&self, snapshot: &CorePersistenceSnapshot) -> Result<()> {
        let encoded = encode_snapshot(snapshot).map_err(anyhow::Error::from)?;
        write_atomic(&self.snapshot_path(), &encoded)
    }

    pub fn save_deployment_bundle(&mut self, bundle: &DeploymentBundle) -> Result<PathBuf> {
        let path = self.meta.bundles_dir.join("deployment_bundle.json");
        let bytes = serde_json::to_vec_pretty(bundle)?;
        write_atomic(&path, &bytes)?;
        self.set_deployment_bundle_path(path.clone())?;
        Ok(path)
    }

    pub fn save_identity_bundle(
        &self,
        bundle: &IdentityBundle,
        file_name: &str,
    ) -> Result<PathBuf> {
        let path = self.meta.bundles_dir.join(file_name);
        let bytes = serde_json::to_vec_pretty(bundle)?;
        write_atomic(&path, &bytes)?;
        Ok(path)
    }

    pub fn load_deployment_bundle_file(path: impl AsRef<Path>) -> Result<DeploymentBundle> {
        let raw = fs::read_to_string(path).context("read deployment bundle")?;
        let normalized = normalize_json(&raw)?;
        Ok(serde_json::from_str(&normalized).context("decode deployment bundle")?)
    }

    pub fn load_identity_bundle_file(path: impl AsRef<Path>) -> Result<IdentityBundle> {
        let raw = fs::read_to_string(path).context("read identity bundle")?;
        let normalized = normalize_json(&raw)?;
        Ok(serde_json::from_str(&normalized).context("decode identity bundle")?)
    }

    pub fn load_runtime_metadata(&self) -> Result<RuntimeMetadata> {
        let path = self.runtime_meta_path();
        if !path.exists() {
            return Ok(RuntimeMetadata::default());
        }
        Ok(serde_json::from_slice(
            &fs::read(path).context("read runtime metadata")?,
        )?)
    }

    pub fn save_runtime_metadata(&self, runtime: &RuntimeMetadata) -> Result<()> {
        write_atomic(
            &self.runtime_meta_path(),
            &serde_json::to_vec_pretty(runtime)?,
        )
    }

    pub fn clear_runtime_metadata(&self) -> Result<()> {
        let path = self.runtime_meta_path();
        if path.exists() {
            fs::remove_file(path).context("remove runtime metadata")?;
        }
        Ok(())
    }

    fn ensure_layout(&self) -> Result<()> {
        fs::create_dir_all(&self.meta.bundles_dir)?;
        fs::create_dir_all(&self.meta.inbox_attachments_dir)?;
        fs::create_dir_all(&self.meta.outbox_attachments_dir)?;
        fs::create_dir_all(&self.meta.runtime_dir)?;
        Ok(())
    }

    fn save_metadata(&self) -> Result<()> {
        write_atomic(
            &self.root.join("profile.json"),
            &serde_json::to_vec_pretty(&self.meta)?,
        )
    }
}

fn normalize_json(raw: &str) -> Result<String> {
    match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(_) => to_snake_case_json_string(raw),
        Err(error) => Err(anyhow::Error::new(error).context("parse json")),
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("replace {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::Profile;
    use crate::persistence::CorePersistenceSnapshot;

    #[test]
    fn init_creates_profile_layout_and_snapshot() {
        let dir = tempdir().expect("tempdir");
        let profile = Profile::init("alice", dir.path()).expect("init profile");
        assert!(profile.snapshot_path().exists());
        assert!(profile.metadata().bundles_dir.exists());
        let snapshot = profile.load_snapshot().expect("load snapshot");
        assert_eq!(snapshot, CorePersistenceSnapshot::default());
    }
}

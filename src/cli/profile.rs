use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use keyring::{credential::CredentialPersistence, default};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::ffi_api::PersistStateEffect;
use crate::local_store::{
    active_store, migrate_snapshot_to_state_db, PRIVATE_STATE_DOCUMENT_KIND, STATE_DB_FILE_NAME,
};
use crate::model::{DeploymentBundle, DeviceRuntimeAuth, IdentityBundle};
use crate::persistence::CorePersistenceSnapshot;
use crate::profile_crypto::{
    build_os_keychain_wrapper, build_passphrase_wrapper,
    decrypt_profile_document as decrypt_profile_document_bytes, default_encryption_metadata,
    encrypt_profile_document as encrypt_profile_document_bytes, generate_pdek, generate_wrap_key,
    unwrap_with_key, unwrap_with_passphrase, validate_encryption_metadata,
    ProfileEncryptionMetadata, ProfileKeyWrapperKind, LEGACY_SNAPSHOT_FILE_NAME,
    OS_KEYCHAIN_SERVICE, PDEK_LEN, SNAPSHOT_FILE_NAME,
};

use super::util::to_snake_case_json_string;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileMetadata {
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub profile_id: String,
    pub root_dir: PathBuf,
    pub bundles_dir: PathBuf,
    pub inbox_attachments_dir: PathBuf,
    pub outbox_attachments_dir: PathBuf,
    #[serde(default)]
    pub attachments_dir: PathBuf,
    pub runtime_dir: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_bundle_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<ProfileEncryptionMetadata>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deploy_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_bucket_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_deployed_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfilePrivateState {
    pub version: u32,
    #[serde(default)]
    pub runtime_secrets: RuntimeSecrets,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_runtime_auth: Option<DeviceRuntimeAuth>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub settings: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attachment_cache: BTreeMap<String, AttachmentCacheEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RuntimeSecrets {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sharing_secret: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AttachmentCacheEntry {
    pub cache_id: String,
    pub relative_path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    pub updated_at_ms: u64,
}

impl Default for ProfilePrivateState {
    fn default() -> Self {
        Self {
            version: 1,
            runtime_secrets: RuntimeSecrets::default(),
            deployment_runtime_auth: None,
            settings: BTreeMap::new(),
            attachment_cache: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileRegistryEntry {
    pub name: String,
    pub root_dir: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ProfileRegistry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_profile: Option<PathBuf>,
    #[serde(default)]
    pub profiles: Vec<ProfileRegistryEntry>,
}
pub struct Profile {
    root: PathBuf,
    meta: ProfileMetadata,
    pdek: Zeroizing<[u8; PDEK_LEN]>,
}

#[derive(Debug, Clone)]
pub struct ProfileInitOptions {
    pub passphrase: Option<String>,
    pub use_keychain: bool,
}

impl Default for ProfileInitOptions {
    fn default() -> Self {
        Self {
            passphrase: None,
            use_keychain: true,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProfileOpenOptions {
    pub passphrase: Option<String>,
}

impl Profile {
    pub fn init(name: &str, root: impl AsRef<Path>) -> Result<Self> {
        Self::init_with_options(
            name,
            root,
            ProfileInitOptions {
                passphrase: None,
                use_keychain: true,
            },
        )
    }

    pub fn init_with_options(
        name: &str,
        root: impl AsRef<Path>,
        options: ProfileInitOptions,
    ) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root).context("create profile root")?;
        if root.join(LEGACY_SNAPSHOT_FILE_NAME).exists() {
            bail!(
                "insecure plaintext snapshot.json exists at {}; recreate the profile before using encrypted snapshots",
                root.display()
            );
        }
        let profile_id = format!("profile:{}", Uuid::new_v4());
        let pdek = generate_pdek();
        let mut wrappers = Vec::new();

        if options.use_keychain {
            let wrapper_id = format!("wrapper:{}", Uuid::new_v4());
            let os_kek = generate_wrap_key();
            match store_os_kek(&profile_id, &wrapper_id, &*os_kek) {
                Ok(()) => wrappers.push(
                    build_os_keychain_wrapper(&profile_id, &wrapper_id, &*os_kek, &*pdek)
                        .map_err(anyhow::Error::from)?,
                ),
                Err(error) if options.passphrase.is_some() => {
                    log::warn!("OS keychain unavailable for profile {profile_id}: {error}");
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        "OS keychain is unavailable; provide a passphrase to create this profile"
                    });
                }
            }
        }

        if let Some(passphrase) = options.passphrase.as_deref() {
            if passphrase.is_empty() {
                bail!("profile passphrase must not be empty");
            }
            let wrapper_id = format!("wrapper:{}", Uuid::new_v4());
            wrappers.push(
                build_passphrase_wrapper(&profile_id, &wrapper_id, passphrase, &*pdek)
                    .map_err(anyhow::Error::from)?,
            );
        }

        if wrappers.is_empty() {
            bail!("profile encryption requires at least one key wrapper");
        }

        let meta = ProfileMetadata {
            name: name.to_string(),
            profile_id: profile_id.clone(),
            bundles_dir: root.join("bundles"),
            inbox_attachments_dir: root.join("attachments"),
            outbox_attachments_dir: root.join("attachments"),
            attachments_dir: root.join("attachments"),
            runtime_dir: root.join("runtime"),
            root_dir: root.clone(),
            user_id: None,
            device_id: None,
            deployment_bundle_path: None,
            encryption: Some(default_encryption_metadata(wrappers)),
        };
        let profile = Self { root, meta, pdek };
        profile.ensure_layout()?;
        profile.save_metadata()?;
        if !profile.snapshot_path().exists() {
            profile.save_snapshot(&CorePersistenceSnapshot::default())?;
        }
        profile.ensure_local_store_migrated()?;
        profile.sync_registry_entry()?;
        Ok(profile)
    }

    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_options(root, ProfileOpenOptions::default())
    }

    pub fn open_with_passphrase(
        root: impl AsRef<Path>,
        passphrase: Option<String>,
    ) -> Result<Self> {
        Self::open_with_options(root, ProfileOpenOptions { passphrase })
    }

    pub fn open_with_options(root: impl AsRef<Path>, options: ProfileOpenOptions) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let meta_path = root.join("profile.json");
        if !meta_path.exists() {
            bail!("profile.json not found at {}", meta_path.display());
        }
        let mut meta: ProfileMetadata =
            serde_json::from_slice(&fs::read(&meta_path).context("read profile metadata")?)
                .context("decode profile metadata")?;
        // Backward compat: old profiles don't have attachments_dir; derive from root
        if meta.attachments_dir.as_os_str().is_empty() {
            meta.attachments_dir = root.join("attachments");
            meta.inbox_attachments_dir = meta.attachments_dir.clone();
            meta.outbox_attachments_dir = meta.attachments_dir.clone();
        }
        if meta.profile_id.is_empty() || meta.encryption.is_none() {
            if root.join(LEGACY_SNAPSHOT_FILE_NAME).exists() {
                bail!(
                    "insecure plaintext snapshot.json exists at {}; recreate the profile before using encrypted snapshots",
                    root.display()
                );
            }
            bail!("profile metadata is missing encryption settings");
        }
        let env_passphrase = if options.passphrase.is_none() {
            env::var("TAPCHAT_PROFILE_PASSPHRASE").ok()
        } else {
            None
        };
        let pdek = unlock_profile_pdek(
            &meta,
            options.passphrase.as_deref().or(env_passphrase.as_deref()),
        )?;
        let profile = Self { root, meta, pdek };
        profile.ensure_layout()?;
        profile.ensure_local_store_migrated()?;
        profile.scrub_legacy_plaintext_state()?;
        Ok(profile)
    }

    pub fn metadata(&self) -> &ProfileMetadata {
        &self.meta
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn update_identity(
        &mut self,
        user_id: Option<String>,
        device_id: Option<String>,
    ) -> Result<()> {
        self.meta.user_id = user_id;
        self.meta.device_id = device_id;
        self.save_metadata()?;
        self.sync_registry_entry()
    }

    pub fn set_deployment_bundle_path(&mut self, path: PathBuf) -> Result<()> {
        self.meta.deployment_bundle_path = Some(path);
        self.save_metadata()
    }

    pub fn clear_deployment_bundle_path(&mut self) -> Result<()> {
        self.meta.deployment_bundle_path = None;
        self.save_metadata()
    }

    pub fn snapshot_path(&self) -> PathBuf {
        self.root.join(SNAPSHOT_FILE_NAME)
    }

    pub fn state_db_path(&self) -> PathBuf {
        self.root.join(STATE_DB_FILE_NAME)
    }

    pub fn runtime_meta_path(&self) -> PathBuf {
        self.meta.runtime_dir.join("runtime.json")
    }

    pub fn load_snapshot(&self) -> Result<CorePersistenceSnapshot> {
        active_store(&self.root, &self.meta.profile_id, &*self.pdek).load_snapshot()
    }

    pub fn save_snapshot(&self, snapshot: &CorePersistenceSnapshot) -> Result<()> {
        active_store(&self.root, &self.meta.profile_id, &*self.pdek).save_snapshot(snapshot)
    }

    pub fn persist_state(&self, persist: &PersistStateEffect) -> Result<()> {
        active_store(&self.root, &self.meta.profile_id, &*self.pdek).persist_state(persist)
    }

    pub fn save_deployment_bundle(&mut self, bundle: &DeploymentBundle) -> Result<PathBuf> {
        let path = self.meta.bundles_dir.join("deployment_bundle.json");
        let mut private = self.load_private_state()?;
        private.deployment_runtime_auth = bundle.device_runtime_auth.clone();
        self.save_private_state(&private)?;

        let mut public_bundle = bundle.clone();
        public_bundle.device_runtime_auth = None;
        let bytes = serde_json::to_vec_pretty(&public_bundle)?;
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

    pub fn load_deployment_bundle(&self) -> Result<Option<DeploymentBundle>> {
        let Some(path) = self.meta.deployment_bundle_path.as_ref() else {
            return Ok(None);
        };
        let mut bundle = Self::load_deployment_bundle_file(path)?;
        if bundle.device_runtime_auth.is_some() {
            let mut private = self.load_private_state()?;
            private.deployment_runtime_auth = bundle.device_runtime_auth.clone();
            self.save_private_state(&private)?;
            bundle.device_runtime_auth = private.deployment_runtime_auth;
            let mut public_bundle = bundle.clone();
            public_bundle.device_runtime_auth = None;
            write_atomic(path, &serde_json::to_vec_pretty(&public_bundle)?)?;
            return Ok(Some(bundle));
        }
        if let Some(auth) = self.load_private_state()?.deployment_runtime_auth {
            bundle.device_runtime_auth = Some(auth);
        }
        Ok(Some(bundle))
    }

    pub fn load_identity_bundle_file(path: impl AsRef<Path>) -> Result<IdentityBundle> {
        let raw = fs::read_to_string(path).context("read identity bundle")?;
        let normalized = normalize_json(&raw)?;
        Ok(serde_json::from_str(&normalized).context("decode identity bundle")?)
    }

    pub fn load_runtime_metadata(&self) -> Result<RuntimeMetadata> {
        let path = self.runtime_meta_path();
        let mut runtime = if path.exists() {
            serde_json::from_slice(&fs::read(&path).context("read runtime metadata")?)?
        } else {
            RuntimeMetadata::default()
        };
        let mut private = self.load_private_state()?;
        let had_plaintext_secrets =
            runtime.bootstrap_secret.is_some() || runtime.sharing_secret.is_some();
        if runtime.bootstrap_secret.is_some() {
            private.runtime_secrets.bootstrap_secret = runtime.bootstrap_secret.take();
        }
        if runtime.sharing_secret.is_some() {
            private.runtime_secrets.sharing_secret = runtime.sharing_secret.take();
        }
        if had_plaintext_secrets {
            self.save_private_state(&private)?;
            write_atomic(&path, &serde_json::to_vec_pretty(&runtime)?)?;
        }
        runtime.bootstrap_secret = private.runtime_secrets.bootstrap_secret;
        runtime.sharing_secret = private.runtime_secrets.sharing_secret;
        Ok(runtime)
    }

    pub fn save_runtime_metadata(&self, runtime: &RuntimeMetadata) -> Result<()> {
        let mut private = self.load_private_state()?;
        private.runtime_secrets.bootstrap_secret = runtime.bootstrap_secret.clone();
        private.runtime_secrets.sharing_secret = runtime.sharing_secret.clone();
        self.save_private_state(&private)?;

        let mut public_runtime = runtime.clone();
        public_runtime.bootstrap_secret = None;
        public_runtime.sharing_secret = None;
        write_atomic(
            &self.runtime_meta_path(),
            &serde_json::to_vec_pretty(&public_runtime)?,
        )
    }

    pub fn clear_runtime_metadata(&self) -> Result<()> {
        let path = self.runtime_meta_path();
        if path.exists() {
            fs::remove_file(path).context("remove runtime metadata")?;
        }
        let mut private = self.load_private_state()?;
        private.runtime_secrets = RuntimeSecrets::default();
        self.save_private_state(&private)?;
        Ok(())
    }

    pub fn load_private_setting<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        let private = self.load_private_state()?;
        private
            .settings
            .get(key)
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(anyhow::Error::from)
    }

    pub fn save_private_setting<T: Serialize>(&self, key: &str, value: &T) -> Result<()> {
        let mut private = self.load_private_state()?;
        private
            .settings
            .insert(key.to_string(), serde_json::to_value(value)?);
        self.save_private_state(&private)
    }

    pub fn load_private_state(&self) -> Result<ProfilePrivateState> {
        let Some(bytes) = active_store(&self.root, &self.meta.profile_id, &*self.pdek)
            .load_document(PRIVATE_STATE_DOCUMENT_KIND)?
        else {
            return Ok(ProfilePrivateState::default());
        };
        Ok(serde_json::from_slice(&bytes).context("decode private profile state")?)
    }

    pub fn save_private_state(&self, private: &ProfilePrivateState) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(private)?;
        active_store(&self.root, &self.meta.profile_id, &*self.pdek)
            .save_document(PRIVATE_STATE_DOCUMENT_KIND, &bytes)
    }

    pub fn load_attachment_cache_entries(&self) -> Result<Vec<AttachmentCacheEntry>> {
        let store = active_store(&self.root, &self.meta.profile_id, &*self.pdek);
        let mut entries = store
            .load_attachment_cache_entries()?
            .into_iter()
            .map(|bytes| serde_json::from_slice::<AttachmentCacheEntry>(&bytes))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if entries.is_empty() {
            let mut private = self.load_private_state()?;
            entries = private.attachment_cache.values().cloned().collect();
            if !entries.is_empty() && self.state_db_path().exists() {
                for entry in &entries {
                    let bytes = serde_json::to_vec(entry)?;
                    store.save_attachment_cache_entry(
                        &entry.cache_id,
                        &bytes,
                        entry.mime_type.as_deref(),
                        entry.size_bytes,
                    )?;
                }
                private.attachment_cache.clear();
                self.save_private_state(&private)?;
            }
        }
        Ok(entries)
    }

    pub fn save_attachment_cache_entry(&self, entry: &AttachmentCacheEntry) -> Result<()> {
        let bytes = serde_json::to_vec(entry)?;
        active_store(&self.root, &self.meta.profile_id, &*self.pdek).save_attachment_cache_entry(
            &entry.cache_id,
            &bytes,
            entry.mime_type.as_deref(),
            entry.size_bytes,
        )
    }

    pub fn delete_attachment_cache_entry(&self, cache_id: &str) -> Result<()> {
        active_store(&self.root, &self.meta.profile_id, &*self.pdek)
            .delete_attachment_cache_entry(cache_id)
    }

    pub fn clear_attachment_cache_entries(&self) -> Result<()> {
        active_store(&self.root, &self.meta.profile_id, &*self.pdek)
            .clear_attachment_cache_entries()?;
        let mut private = self.load_private_state()?;
        if !private.attachment_cache.is_empty() {
            private.attachment_cache.clear();
            self.save_private_state(&private)?;
        }
        Ok(())
    }

    pub fn encrypt_profile_document(&self, document_kind: &str, bytes: &[u8]) -> Result<Vec<u8>> {
        encrypt_profile_document_bytes(&self.meta.profile_id, &*self.pdek, document_kind, bytes)
            .map_err(anyhow::Error::from)
    }

    pub fn decrypt_profile_document(&self, document_kind: &str, bytes: &[u8]) -> Result<Vec<u8>> {
        decrypt_profile_document_bytes(&self.meta.profile_id, &*self.pdek, document_kind, bytes)
            .map_err(anyhow::Error::from)
    }

    fn ensure_layout(&self) -> Result<()> {
        fs::create_dir_all(&self.meta.bundles_dir)?;
        fs::create_dir_all(&self.meta.attachments_dir)?;
        fs::create_dir_all(&self.meta.runtime_dir)?;
        Ok(())
    }

    fn save_metadata(&self) -> Result<()> {
        write_atomic(
            &self.root.join("profile.json"),
            &serde_json::to_vec_pretty(&self.meta)?,
        )
    }

    fn ensure_local_store_migrated(&self) -> Result<()> {
        migrate_snapshot_to_state_db(&self.root, &self.meta.profile_id, &*self.pdek)
    }

    fn scrub_legacy_plaintext_state(&self) -> Result<()> {
        let _ = self.load_runtime_metadata()?;
        if self.meta.deployment_bundle_path.is_some() {
            let _ = self.load_deployment_bundle()?;
        }
        Ok(())
    }

    pub fn sync_registry_entry(&self) -> Result<()> {
        let mut registry = ProfileRegistry::load()?;
        registry.upsert(self.registry_entry());
        if registry.active_profile.is_none() {
            registry.active_profile = Some(self.root.clone());
        }
        registry.save()
    }

    fn registry_entry(&self) -> ProfileRegistryEntry {
        ProfileRegistryEntry {
            name: self.meta.name.clone(),
            root_dir: self.root.clone(),
            user_id: self.meta.user_id.clone(),
            device_id: self.meta.device_id.clone(),
        }
    }
}

impl ProfileRegistry {
    pub fn load() -> Result<Self> {
        let path = profile_registry_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read(path).context("read profile registry")?;

        // Handle empty file case
        if content.is_empty() || content.iter().all(|b| b.is_ascii_whitespace()) {
            return Ok(Self::default());
        }

        Ok(serde_json::from_slice(&content)?)
    }

    pub fn save(&self) -> Result<()> {
        write_atomic(&profile_registry_path()?, &serde_json::to_vec_pretty(self)?)
    }

    pub fn upsert(&mut self, entry: ProfileRegistryEntry) {
        if let Some(existing) = self
            .profiles
            .iter_mut()
            .find(|existing| existing.root_dir == entry.root_dir)
        {
            *existing = entry;
            return;
        }
        self.profiles.push(entry);
        self.profiles.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then(left.root_dir.cmp(&right.root_dir))
        });
    }

    pub fn remove(&mut self, root_dir: &Path) {
        self.profiles.retain(|entry| entry.root_dir != root_dir);
        if self
            .active_profile
            .as_ref()
            .is_some_and(|active| active == root_dir)
        {
            self.active_profile = self.profiles.first().map(|entry| entry.root_dir.clone());
        }
    }

    pub fn set_active(&mut self, root_dir: &Path) -> Result<()> {
        if !self.profiles.iter().any(|entry| entry.root_dir == root_dir) {
            bail!(
                "profile {} is not registered on this device",
                root_dir.display()
            );
        }
        self.active_profile = Some(root_dir.to_path_buf());
        Ok(())
    }

    pub fn set_active_by_name(&mut self, name: &str) -> Result<PathBuf> {
        let matches: Vec<_> = self
            .profiles
            .iter()
            .filter(|entry| entry.name == name)
            .collect();
        match matches.as_slice() {
            [] => bail!("profile named {name} is not registered on this device"),
            [entry] => {
                self.active_profile = Some(entry.root_dir.clone());
                Ok(entry.root_dir.clone())
            }
            _ => bail!(
                "multiple registered profiles share the name {name}; activate by path instead"
            ),
        }
    }

    pub fn current(&self) -> Result<&ProfileRegistryEntry> {
        let active = self
            .active_profile
            .as_ref()
            .ok_or_else(|| anyhow!("no active profile is configured on this device"))?;
        self.profiles
            .iter()
            .find(|entry| &entry.root_dir == active)
            .ok_or_else(|| {
                anyhow!(
                    "active profile {} is no longer registered",
                    active.display()
                )
            })
    }
}

pub fn profile_registry_path() -> Result<PathBuf> {
    if let Ok(path) = env::var("TAPCHAT_PROFILE_REGISTRY_PATH") {
        return Ok(PathBuf::from(path));
    }
    let config_root = if cfg!(windows) {
        env::var_os("APPDATA")
            .map(PathBuf::from)
            .ok_or_else(|| anyhow!("APPDATA is not set"))?
    } else if let Some(xdg) = env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(xdg)
    } else {
        let home = env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?;
        PathBuf::from(home).join(".config")
    };
    Ok(config_root.join("TapChat").join("profiles.json"))
}

fn normalize_json(raw: &str) -> Result<String> {
    match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(_) => to_snake_case_json_string(raw),
        Err(error) => Err(anyhow::Error::new(error).context("parse json")),
    }
}

fn unlock_profile_pdek(
    meta: &ProfileMetadata,
    passphrase: Option<&str>,
) -> Result<Zeroizing<[u8; PDEK_LEN]>> {
    let encryption = meta
        .encryption
        .as_ref()
        .ok_or_else(|| anyhow!("profile metadata is missing encryption settings"))?;
    validate_encryption_metadata(encryption).map_err(anyhow::Error::from)?;

    let mut errors = Vec::new();
    for wrapper in encryption
        .wrappers
        .iter()
        .filter(|wrapper| wrapper.kind == ProfileKeyWrapperKind::OsKeychain)
    {
        match load_os_kek(wrapper).and_then(|key| {
            unwrap_with_key(&meta.profile_id, wrapper, &key).map_err(anyhow::Error::from)
        }) {
            Ok(pdek) => return Ok(pdek),
            Err(error) => errors.push(error.to_string()),
        }
    }

    if let Some(passphrase) = passphrase {
        for wrapper in encryption
            .wrappers
            .iter()
            .filter(|wrapper| wrapper.kind == ProfileKeyWrapperKind::PassphraseArgon2id)
        {
            match unwrap_with_passphrase(&meta.profile_id, wrapper, passphrase)
                .map_err(anyhow::Error::from)
            {
                Ok(pdek) => return Ok(pdek),
                Err(error) => errors.push(error.to_string()),
            }
        }
    }

    if passphrase.is_none()
        && encryption
            .wrappers
            .iter()
            .any(|wrapper| wrapper.kind == ProfileKeyWrapperKind::PassphraseArgon2id)
    {
        bail!(
            "profile is encrypted and requires a passphrase because OS keychain unlock failed: {}",
            errors.join("; ")
        );
    }

    bail!(
        "failed to unlock encrypted profile{}",
        if errors.is_empty() {
            String::new()
        } else {
            format!(": {}", errors.join("; "))
        }
    )
}

fn store_os_kek(profile_id: &str, wrapper_id: &str, key: &[u8]) -> Result<()> {
    ensure_persistent_os_keychain()?;
    let account = crate::profile_crypto::generate_keychain_account(profile_id, wrapper_id);
    let entry = keyring::Entry::new(OS_KEYCHAIN_SERVICE, &account)
        .with_context(|| format!("create OS keychain entry for {account}"))?;
    entry
        .set_password(&STANDARD.encode(key))
        .with_context(|| format!("store OS keychain entry for {account}"))?;
    let stored = entry
        .get_password()
        .with_context(|| format!("verify OS keychain entry for {account}"))?;
    let stored = STANDARD
        .decode(stored)
        .context("decode OS keychain verification secret")?;
    if stored != key {
        bail!("OS keychain verification failed for {account}");
    }
    Ok(())
}

fn ensure_persistent_os_keychain() -> Result<()> {
    let persistence = default::default_credential_builder().persistence();
    if !matches!(persistence, CredentialPersistence::UntilDelete) {
        bail!(
            "OS keychain backend is not persistent ({})",
            credential_persistence_label(&persistence)
        );
    }
    Ok(())
}

fn credential_persistence_label(persistence: &CredentialPersistence) -> &'static str {
    match persistence {
        CredentialPersistence::EntryOnly => "entry-only",
        CredentialPersistence::ProcessOnly => "process-only",
        CredentialPersistence::UntilReboot => "until-reboot",
        CredentialPersistence::UntilDelete => "until-delete",
        _ => "unknown",
    }
}

fn load_os_kek(
    wrapper: &crate::profile_crypto::ProfileKeyWrapperMetadata,
) -> Result<Zeroizing<Vec<u8>>> {
    let service = wrapper
        .keychain_service
        .as_deref()
        .unwrap_or(OS_KEYCHAIN_SERVICE);
    let account = wrapper
        .keychain_account
        .as_deref()
        .ok_or_else(|| anyhow!("OS keychain wrapper is missing account"))?;
    let entry = keyring::Entry::new(service, account)
        .with_context(|| format!("create OS keychain entry for {account}"))?;
    let encoded = entry
        .get_password()
        .with_context(|| format!("read OS keychain entry for {account}"))?;
    let key = STANDARD
        .decode(encoded)
        .context("decode OS keychain secret")?;
    if key.len() != PDEK_LEN {
        bail!("OS keychain secret has invalid length");
    }
    Ok(Zeroizing::new(key))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("replace {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, MutexGuard, OnceLock};

    use tempfile::tempdir;

    use keyring::{credential::CredentialPersistence, default};

    use super::{Profile, ProfileInitOptions, ProfileRegistry, RuntimeMetadata};
    use crate::persistence::CorePersistenceSnapshot;

    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock")
    }

    #[test]
    fn init_creates_profile_layout_and_snapshot() {
        let _guard = env_lock();
        let dir = tempdir().expect("tempdir");
        unsafe {
            std::env::set_var(
                "TAPCHAT_PROFILE_REGISTRY_PATH",
                dir.path().join("config").join("profiles.json"),
            );
        }
        let profile = Profile::init_with_options(
            "alice",
            dir.path(),
            ProfileInitOptions {
                passphrase: Some("test-passphrase".into()),
                use_keychain: false,
            },
        )
        .expect("init profile");
        assert!(profile.snapshot_path().exists());
        assert!(profile.state_db_path().exists());
        assert!(!dir.path().join("snapshot.json").exists());
        assert!(profile.metadata().bundles_dir.exists());
        let snapshot = profile.load_snapshot().expect("load snapshot");
        assert_eq!(snapshot, CorePersistenceSnapshot::default());
        let registry = ProfileRegistry::load().expect("load registry");
        assert_eq!(registry.profiles.len(), 1);
        assert_eq!(registry.active_profile.as_deref(), Some(dir.path()));
        unsafe {
            std::env::remove_var("TAPCHAT_PROFILE_REGISTRY_PATH");
        }
    }

    #[test]
    fn registry_updates_identity_fields() {
        let _guard = env_lock();
        let dir = tempdir().expect("tempdir");
        unsafe {
            std::env::set_var(
                "TAPCHAT_PROFILE_REGISTRY_PATH",
                dir.path().join("config").join("profiles.json"),
            );
        }
        let mut profile = Profile::init_with_options(
            "alice",
            dir.path().join("alice"),
            ProfileInitOptions {
                passphrase: Some("test-passphrase".into()),
                use_keychain: false,
            },
        )
        .expect("init profile");
        profile
            .update_identity(Some("user:alice".into()), Some("device:alice:phone".into()))
            .expect("update identity");
        let registry = ProfileRegistry::load().expect("load registry");
        let entry = registry.profiles.first().expect("entry");
        assert_eq!(entry.user_id.as_deref(), Some("user:alice"));
        assert_eq!(entry.device_id.as_deref(), Some("device:alice:phone"));
        unsafe {
            std::env::remove_var("TAPCHAT_PROFILE_REGISTRY_PATH");
        }
    }

    #[test]
    fn encrypted_snapshot_does_not_contain_plaintext_marker() {
        let _guard = env_lock();
        let dir = tempdir().expect("tempdir");
        unsafe {
            std::env::set_var(
                "TAPCHAT_PROFILE_REGISTRY_PATH",
                dir.path().join("config").join("profiles.json"),
            );
        }
        let profile = Profile::init_with_options(
            "alice",
            dir.path().join("alice"),
            ProfileInitOptions {
                passphrase: Some("test-passphrase".into()),
                use_keychain: false,
            },
        )
        .expect("init profile");
        let mut snapshot = CorePersistenceSnapshot::default();
        snapshot
            .realtime_sessions
            .push(crate::persistence::PersistedRealtimeSession {
                device_id: "visible-marker".into(),
                last_known_seq: 42,
                needs_reconnect: true,
            });
        profile.save_snapshot(&snapshot).expect("save snapshot");

        let bytes = std::fs::read(profile.snapshot_path()).expect("read encrypted snapshot");
        assert!(!bytes
            .windows("visible-marker".len())
            .any(|window| window == b"visible-marker"));

        let reopened =
            Profile::open_with_passphrase(dir.path().join("alice"), Some("test-passphrase".into()))
                .expect("open profile");
        assert_eq!(reopened.load_snapshot().expect("load"), snapshot);
        let state_db = std::fs::read(reopened.state_db_path()).expect("read state db");
        assert!(!state_db
            .windows("visible-marker".len())
            .any(|window| window == b"visible-marker"));
        unsafe {
            std::env::remove_var("TAPCHAT_PROFILE_REGISTRY_PATH");
        }
    }

    #[test]
    fn runtime_metadata_secrets_are_stored_in_private_state() {
        let _guard = env_lock();
        let dir = tempdir().expect("tempdir");
        unsafe {
            std::env::set_var(
                "TAPCHAT_PROFILE_REGISTRY_PATH",
                dir.path().join("config").join("profiles.json"),
            );
        }
        let profile = Profile::init_with_options(
            "alice",
            dir.path().join("alice"),
            ProfileInitOptions {
                passphrase: Some("test-passphrase".into()),
                use_keychain: false,
            },
        )
        .expect("init profile");
        profile
            .save_runtime_metadata(&RuntimeMetadata {
                base_url: Some("https://example.test".into()),
                bootstrap_secret: Some("bootstrap-visible-marker".into()),
                sharing_secret: Some("sharing-visible-marker".into()),
                ..RuntimeMetadata::default()
            })
            .expect("save runtime");

        let runtime_json =
            std::fs::read_to_string(profile.runtime_meta_path()).expect("read runtime metadata");
        assert!(runtime_json.contains("https://example.test"));
        assert!(!runtime_json.contains("bootstrap-visible-marker"));
        assert!(!runtime_json.contains("sharing-visible-marker"));
        let loaded = profile.load_runtime_metadata().expect("load runtime");
        assert_eq!(
            loaded.bootstrap_secret.as_deref(),
            Some("bootstrap-visible-marker")
        );
        assert_eq!(
            loaded.sharing_secret.as_deref(),
            Some("sharing-visible-marker")
        );
        unsafe {
            std::env::remove_var("TAPCHAT_PROFILE_REGISTRY_PATH");
        }
    }

    #[test]
    fn deployment_bundle_file_strips_runtime_auth_token() {
        let _guard = env_lock();
        let dir = tempdir().expect("tempdir");
        unsafe {
            std::env::set_var(
                "TAPCHAT_PROFILE_REGISTRY_PATH",
                dir.path().join("config").join("profiles.json"),
            );
        }
        let mut profile = Profile::init_with_options(
            "alice",
            dir.path().join("alice"),
            ProfileInitOptions {
                passphrase: Some("test-passphrase".into()),
                use_keychain: false,
            },
        )
        .expect("init profile");
        let bundle = crate::model::DeploymentBundle {
            version: crate::model::CURRENT_MODEL_VERSION.to_string(),
            region: "test".into(),
            inbox_http_endpoint: "https://inbox.test".into(),
            inbox_websocket_endpoint: "wss://inbox.test".into(),
            storage_base_info: crate::model::StorageBaseInfo {
                base_url: Some("https://storage.test".into()),
                bucket_hint: Some("bucket".into()),
            },
            runtime_config: crate::model::RuntimeConfig::default(),
            device_runtime_auth: Some(crate::model::DeviceRuntimeAuth {
                scheme: "bearer".into(),
                token: "runtime-token-visible-marker".into(),
                expires_at: 42,
                user_id: "user:alice".into(),
                device_id: "device:alice".into(),
                scopes: vec!["inbox:append".into()],
            }),
            expected_user_id: None,
            expected_device_id: None,
        };
        let path = profile
            .save_deployment_bundle(&bundle)
            .expect("save deployment");
        let public_json = std::fs::read_to_string(path).expect("read deployment");
        assert!(!public_json.contains("runtime-token-visible-marker"));
        assert!(!public_json.contains("device_runtime_auth"));
        let loaded = profile
            .load_deployment_bundle()
            .expect("load deployment")
            .expect("deployment present");
        assert_eq!(
            loaded
                .device_runtime_auth
                .as_ref()
                .map(|auth| auth.token.as_str()),
            Some("runtime-token-visible-marker")
        );
        unsafe {
            std::env::remove_var("TAPCHAT_PROFILE_REGISTRY_PATH");
        }
    }

    #[test]
    fn attachment_cache_index_is_stored_in_state_db() {
        let _guard = env_lock();
        let dir = tempdir().expect("tempdir");
        unsafe {
            std::env::set_var(
                "TAPCHAT_PROFILE_REGISTRY_PATH",
                dir.path().join("config").join("profiles.json"),
            );
        }
        let profile = Profile::init_with_options(
            "alice",
            dir.path().join("alice"),
            ProfileInitOptions {
                passphrase: Some("test-passphrase".into()),
                use_keychain: false,
            },
        )
        .expect("init profile");
        profile
            .save_attachment_cache_entry(&super::AttachmentCacheEntry {
                cache_id: "cache-marker".into(),
                relative_path: std::path::PathBuf::from("attachment-cache/cache-marker.enc"),
                mime_type: Some("application/octet-stream".into()),
                size_bytes: Some(42),
                updated_at_ms: 7,
            })
            .expect("save cache entry");

        let entries = profile
            .load_attachment_cache_entries()
            .expect("load cache entries");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].cache_id, "cache-marker");
        assert!(profile
            .load_private_state()
            .expect("private state")
            .attachment_cache
            .is_empty());
        unsafe {
            std::env::remove_var("TAPCHAT_PROFILE_REGISTRY_PATH");
        }
    }

    #[test]
    fn default_keyring_backend_is_persistent_on_supported_targets() {
        if cfg!(any(
            target_os = "windows",
            target_os = "macos",
            target_os = "linux"
        )) {
            assert!(matches!(
                default::default_credential_builder().persistence(),
                CredentialPersistence::UntilDelete
            ));
        }
    }

    #[test]
    fn plaintext_snapshot_without_encrypted_snapshot_is_rejected() {
        let _guard = env_lock();
        let dir = tempdir().expect("tempdir");
        let root = dir.path().join("legacy");
        std::fs::create_dir_all(&root).expect("create root");
        std::fs::write(
            root.join("profile.json"),
            serde_json::json!({
                "name": "legacy",
                "root_dir": root,
                "bundles_dir": root.join("bundles"),
                "inbox_attachments_dir": root.join("attachments"),
                "outbox_attachments_dir": root.join("attachments"),
                "attachments_dir": root.join("attachments"),
                "runtime_dir": root.join("runtime")
            })
            .to_string(),
        )
        .expect("write profile");
        std::fs::write(root.join("snapshot.json"), b"{}").expect("write legacy snapshot");

        let error = match Profile::open(&root) {
            Ok(_) => panic!("legacy profile should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("insecure plaintext snapshot.json"));
    }
}

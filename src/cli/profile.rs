use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use fs2::FileExt;
use keyring::{credential::CredentialPersistence, default};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::ffi_api::PersistStateEffect;
use crate::fs_util::write_atomic_unique;
use crate::local_store::{
    active_store, inspect_storage, migrate_snapshot_to_state_db, LocalStoreDiagnostics,
    PRIVATE_STATE_DOCUMENT_KIND, STATE_DB_FILE_NAME,
};
use crate::log_sanitize::redact_id;
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

const PROFILE_LOCK_FILE_NAME: &str = ".profile.lock";
const PROFILE_LOCK_INFO_FILE_NAME: &str = ".profile.lock.info";
const PROFILE_METADATA_FILE_NAME: &str = "profile.json";

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
    _lock: ProfileLockGuard,
}

struct InProcessProfileLock {
    file: File,
    ref_count: usize,
}

struct ProfileLockGuard {
    root: PathBuf,
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProfileKeychainEntryRef {
    pub service: String,
    pub account: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileKeychainProbeReport {
    pub attempted: bool,
    pub persistent_backend: bool,
    pub writable: bool,
    pub readable: bool,
    pub deleted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileKeychainDoctorReport {
    pub backend_persistence: String,
    pub persistent_backend: bool,
    pub cleanup_supported: bool,
    pub registered_profiles: usize,
    pub registered_os_wrappers: usize,
    pub matched_registered_targets: usize,
    pub missing_registered_targets: usize,
    pub tapchat_keychain_targets: usize,
    pub orphan_targets: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_registered_accounts: Vec<String>,
    pub probe: ProfileKeychainProbeReport,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ProfileKeychainCleanupReport {
    pub dry_run: bool,
    pub would_delete: usize,
    pub deleted: usize,
    pub skipped_registered: usize,
    pub orphan_accounts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_registered_accounts: Vec<String>,
    pub errors: Vec<String>,
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
        let mut created_keychain_refs = Vec::new();
        let init_result = (|| -> Result<Self> {
            fs::create_dir_all(&root).context("create profile root")?;
            let profile_lock = ProfileLockGuard::acquire(&root)?;
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
                let keychain_ref = keychain_ref_for_wrapper(&profile_id, &wrapper_id);
                match store_os_kek_entry(&keychain_ref, &*os_kek) {
                    Ok(()) => {
                        created_keychain_refs.push(keychain_ref);
                        wrappers.push(
                            build_os_keychain_wrapper(&profile_id, &wrapper_id, &*os_kek, &*pdek)
                                .map_err(anyhow::Error::from)?,
                        );
                    }
                    Err(_error) if options.passphrase.is_some() => {
                        log::warn!(
                            "OS keychain unavailable for profile {}: error=keychain_unavailable",
                            redact_id("profile", &profile_id)
                        );
                    }
                    Err(error) => {
                        return Err(error).with_context(keychain_unavailable_create_message);
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
            let profile = Self {
                root: root.clone(),
                meta,
                pdek,
                _lock: profile_lock,
            };
            profile.ensure_layout()?;
            profile.save_metadata()?;
            if !profile.snapshot_path().exists() {
                profile.save_snapshot(&CorePersistenceSnapshot::default())?;
            }
            profile.ensure_local_store_migrated()?;
            profile.sync_registry_entry()?;
            Ok(profile)
        })();
        if init_result.is_err() {
            rollback_created_keychain_entries(&created_keychain_refs);
        }
        init_result
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
        let meta_path = root.join(PROFILE_METADATA_FILE_NAME);
        if !meta_path.exists() {
            bail!("profile.json not found at {}", meta_path.display());
        }
        let profile_lock = ProfileLockGuard::acquire(&root)?;
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
        let profile = Self {
            root,
            meta,
            pdek,
            _lock: profile_lock,
        };
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

    pub fn storage_diagnostics(&self) -> Result<LocalStoreDiagnostics> {
        inspect_storage(&self.root, &self.meta.profile_id, &*self.pdek)
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
        write_atomic_unique(&path, &bytes)?;
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
        write_atomic_unique(&path, &bytes)?;
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
            write_atomic_unique(path, &serde_json::to_vec_pretty(&public_bundle)?)?;
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
            write_atomic_unique(&path, &serde_json::to_vec_pretty(&runtime)?)?;
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
        write_atomic_unique(
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
        write_atomic_unique(
            &self.root.join(PROFILE_METADATA_FILE_NAME),
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

    pub fn keychain_doctor() -> Result<ProfileKeychainDoctorReport> {
        profile_keychain_doctor()
    }

    pub fn cleanup_orphan_keychain_entries(dry_run: bool) -> Result<ProfileKeychainCleanupReport> {
        cleanup_orphan_keychain_entries(dry_run)
    }

    pub fn cleanup_profile_keychain_entries(
        root: impl AsRef<Path>,
    ) -> Result<ProfileKeychainCleanupReport> {
        cleanup_profile_keychain_entries(root.as_ref())
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
        write_atomic_unique(&profile_registry_path()?, &serde_json::to_vec_pretty(self)?)
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

impl ProfileLockGuard {
    fn acquire(root: &Path) -> Result<Self> {
        fs::create_dir_all(root)
            .with_context(|| format!("create profile root {}", root.display()))?;
        let canonical_root = fs::canonicalize(root)
            .with_context(|| format!("canonicalize profile root {}", root.display()))?;
        let locks = profile_locks();
        let mut table = locks
            .lock()
            .map_err(|_| anyhow!("profile lock table is poisoned"))?;
        if let Some(entry) = table.get_mut(&canonical_root) {
            entry.ref_count += 1;
            return Ok(Self {
                root: canonical_root,
            });
        }

        let lock_path = canonical_root.join(PROFILE_LOCK_FILE_NAME);
        let lock_info_path = canonical_root.join(PROFILE_LOCK_INFO_FILE_NAME);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&lock_path)
            .with_context(|| format!("open profile lock {}", lock_path.display()))?;
        if let Err(error) = file.try_lock_exclusive() {
            let holder = read_profile_lock_pid(&lock_info_path)
                .or_else(|| read_profile_lock_pid(&lock_path))
                .map(|pid| format!(" lock holder pid={pid}."))
                .unwrap_or_else(|| " lock holder pid=unknown.".into());
            bail!(
                "{}",
                profile_lock_error_message(root, &holder, &error.to_string())
            );
        }
        let _ = file.set_len(0);
        let _ = writeln!(file, "pid={}", std::process::id());
        let _ = file.flush();
        let _ = write_atomic_unique(
            &lock_info_path,
            format!("pid={}\n", std::process::id()).as_bytes(),
        );
        table.insert(
            canonical_root.clone(),
            InProcessProfileLock { file, ref_count: 1 },
        );
        Ok(Self {
            root: canonical_root,
        })
    }
}

impl Drop for ProfileLockGuard {
    fn drop(&mut self) {
        let Some(locks) = PROFILE_LOCKS.get() else {
            return;
        };
        let Ok(mut table) = locks.lock() else {
            return;
        };
        if let Some(entry) = table.get_mut(&self.root) {
            if entry.ref_count > 1 {
                entry.ref_count -= 1;
                return;
            }
        }
        if let Some(entry) = table.remove(&self.root) {
            let _ = FileExt::unlock(&entry.file);
        }
    }
}

static PROFILE_LOCKS: OnceLock<Mutex<BTreeMap<PathBuf, InProcessProfileLock>>> = OnceLock::new();

fn profile_locks() -> &'static Mutex<BTreeMap<PathBuf, InProcessProfileLock>> {
    PROFILE_LOCKS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn read_profile_lock_pid(lock_path: &Path) -> Option<u32> {
    let content = fs::read_to_string(lock_path).ok()?;
    content.lines().find_map(|line| {
        let value = line.strip_prefix("pid=")?;
        value.trim().parse::<u32>().ok()
    })
}

fn profile_lock_error_message(root: &Path, holder: &str, error: &str) -> String {
    format!(
        "profile {} is already in use by another TapChat process; close the other TapChat window or stop the other tapchat CLI before trying again.{} ({error})",
        root.display(),
        holder
    )
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
            "profile is encrypted and requires a passphrase because OS keychain unlock failed: {}. {}",
            errors.join("; "),
            keychain_unlock_hint()
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

#[derive(Debug, Clone, Default)]
struct RegisteredProfileKeychainRefs {
    registered_profiles: usize,
    refs: BTreeSet<ProfileKeychainEntryRef>,
    errors: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct OrphanKeychainClassification {
    orphan_accounts: Vec<String>,
    missing_registered_accounts: Vec<String>,
    skipped_registered: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeychainDeleteOutcome {
    Deleted,
    NoEntry,
}

fn keychain_ref_for_wrapper(profile_id: &str, wrapper_id: &str) -> ProfileKeychainEntryRef {
    ProfileKeychainEntryRef {
        service: OS_KEYCHAIN_SERVICE.into(),
        account: crate::profile_crypto::generate_keychain_account(profile_id, wrapper_id),
    }
}

fn keychain_ref_from_wrapper(
    wrapper: &crate::profile_crypto::ProfileKeyWrapperMetadata,
) -> Result<ProfileKeychainEntryRef> {
    let service = wrapper
        .keychain_service
        .as_deref()
        .unwrap_or(OS_KEYCHAIN_SERVICE)
        .to_string();
    let account = wrapper
        .keychain_account
        .as_deref()
        .ok_or_else(|| anyhow!("OS keychain wrapper is missing account"))?
        .to_string();
    Ok(ProfileKeychainEntryRef { service, account })
}

fn store_os_kek_entry(entry_ref: &ProfileKeychainEntryRef, key: &[u8]) -> Result<()> {
    ensure_persistent_os_keychain()?;
    let entry = keyring::Entry::new(&entry_ref.service, &entry_ref.account)
        .with_context(|| format!("create OS keychain entry for {}", entry_ref.account))?;
    entry.set_password(&STANDARD.encode(key)).with_context(|| {
        format!(
            "OS keychain cannot save new credentials for {}",
            entry_ref.account
        )
    })?;
    let stored = entry
        .get_password()
        .with_context(|| format!("verify OS keychain entry for {}", entry_ref.account))?;
    let stored = STANDARD
        .decode(stored)
        .context("decode OS keychain verification secret")?;
    if stored != key {
        bail!("OS keychain verification failed for {}", entry_ref.account);
    }
    Ok(())
}

fn delete_os_keychain_entry(entry_ref: &ProfileKeychainEntryRef) -> Result<KeychainDeleteOutcome> {
    let entry = keyring::Entry::new(&entry_ref.service, &entry_ref.account)
        .with_context(|| format!("create OS keychain entry for {}", entry_ref.account))?;
    match entry.delete_credential() {
        Ok(()) => Ok(KeychainDeleteOutcome::Deleted),
        Err(keyring::Error::NoEntry) => Ok(KeychainDeleteOutcome::NoEntry),
        Err(error) => Err(anyhow::Error::new(error).context(format!(
            "delete OS keychain entry for {}",
            entry_ref.account
        ))),
    }
}

fn rollback_created_keychain_entries(entries: &[ProfileKeychainEntryRef]) {
    for entry_ref in entries {
        if let Err(_error) = delete_os_keychain_entry(entry_ref) {
            log::warn!(
                "failed to roll back OS keychain entry {}: rollback_failed",
                redact_id("keychain-account", &entry_ref.account)
            );
        }
    }
}

fn profile_keychain_doctor() -> Result<ProfileKeychainDoctorReport> {
    let persistence = default::default_credential_builder().persistence();
    let persistent_backend = matches!(persistence, CredentialPersistence::UntilDelete);
    let registered = collect_registered_os_keychain_refs()?;
    let cleanup_supported = keychain_cleanup_supported();
    let mut errors = registered.errors;
    let tapchat_accounts = if cleanup_supported {
        match enumerate_tapchat_keychain_accounts() {
            Ok(accounts) => accounts,
            Err(error) => {
                errors.push(format!("enumerate TapChat keychain targets: {error:#}"));
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    let classification = classify_orphan_keychain_accounts(&tapchat_accounts, &registered.refs);
    Ok(ProfileKeychainDoctorReport {
        backend_persistence: credential_persistence_label(&persistence).into(),
        persistent_backend,
        cleanup_supported,
        registered_profiles: registered.registered_profiles,
        registered_os_wrappers: registered.refs.len(),
        matched_registered_targets: classification.skipped_registered,
        missing_registered_targets: classification.missing_registered_accounts.len(),
        tapchat_keychain_targets: tapchat_accounts.len(),
        orphan_targets: classification.orphan_accounts.len(),
        missing_registered_accounts: classification.missing_registered_accounts,
        probe: probe_os_keychain(),
        errors,
    })
}

fn cleanup_orphan_keychain_entries(dry_run: bool) -> Result<ProfileKeychainCleanupReport> {
    let mut report = ProfileKeychainCleanupReport {
        dry_run,
        ..ProfileKeychainCleanupReport::default()
    };
    if !keychain_cleanup_supported() {
        report
            .errors
            .push("TapChat keychain cleanup is only supported on Windows in this release".into());
        return Ok(report);
    }

    let registered = collect_registered_os_keychain_refs()?;
    report.errors.extend(registered.errors);
    if !report.errors.is_empty() {
        return Ok(report);
    }

    let tapchat_accounts = match enumerate_tapchat_keychain_accounts() {
        Ok(accounts) => accounts,
        Err(error) => {
            report
                .errors
                .push(format!("enumerate TapChat keychain targets: {error:#}"));
            return Ok(report);
        }
    };
    let classification = classify_orphan_keychain_accounts(&tapchat_accounts, &registered.refs);
    report.skipped_registered = classification.skipped_registered;
    report.would_delete = classification.orphan_accounts.len();
    report.orphan_accounts = classification.orphan_accounts.clone();
    report.missing_registered_accounts = classification.missing_registered_accounts.clone();

    if dry_run {
        return Ok(report);
    }

    for account in classification.orphan_accounts {
        let entry_ref = ProfileKeychainEntryRef {
            service: OS_KEYCHAIN_SERVICE.into(),
            account,
        };
        match delete_os_keychain_entry(&entry_ref) {
            Ok(KeychainDeleteOutcome::Deleted) => report.deleted += 1,
            Ok(KeychainDeleteOutcome::NoEntry) => {}
            Err(error) => report.errors.push(error.to_string()),
        }
    }
    Ok(report)
}

fn cleanup_profile_keychain_entries(root: &Path) -> Result<ProfileKeychainCleanupReport> {
    let refs = profile_os_keychain_refs_from_path(root)?;
    let mut report = ProfileKeychainCleanupReport {
        dry_run: false,
        would_delete: refs.len(),
        orphan_accounts: refs
            .iter()
            .map(|entry_ref| entry_ref.account.clone())
            .collect(),
        ..ProfileKeychainCleanupReport::default()
    };
    for entry_ref in refs {
        match delete_os_keychain_entry(&entry_ref) {
            Ok(KeychainDeleteOutcome::Deleted) => report.deleted += 1,
            Ok(KeychainDeleteOutcome::NoEntry) => {}
            Err(error) => report.errors.push(error.to_string()),
        }
    }
    if !report.errors.is_empty() {
        bail!(
            "failed to delete profile OS keychain wrappers: {}",
            report.errors.join("; ")
        );
    }
    Ok(report)
}

fn collect_registered_os_keychain_refs() -> Result<RegisteredProfileKeychainRefs> {
    let registry = ProfileRegistry::load()?;
    let mut result = RegisteredProfileKeychainRefs {
        registered_profiles: registry.profiles.len(),
        ..RegisteredProfileKeychainRefs::default()
    };
    for entry in registry.profiles {
        match read_profile_metadata_if_present(&entry.root_dir) {
            Ok(Some(meta)) => match os_keychain_refs_from_metadata(&meta) {
                Ok(refs) => result.refs.extend(refs),
                Err(error) => result.errors.push(format!(
                    "failed to inspect OS keychain wrappers in {}: {error:#}",
                    entry.root_dir.display()
                )),
            },
            Ok(None) => result.errors.push(format!(
                "registered profile {} has no profile.json",
                entry.root_dir.display()
            )),
            Err(error) => result.errors.push(format!(
                "failed to read registered profile metadata at {}: {error:#}",
                entry.root_dir.display()
            )),
        }
    }
    Ok(result)
}

fn profile_os_keychain_refs_from_path(root: &Path) -> Result<Vec<ProfileKeychainEntryRef>> {
    let Some(meta) = read_profile_metadata_if_present(root)? else {
        return Ok(Vec::new());
    };
    os_keychain_refs_from_metadata(&meta)
}

fn read_profile_metadata_if_present(root: &Path) -> Result<Option<ProfileMetadata>> {
    let meta_path = root.join(PROFILE_METADATA_FILE_NAME);
    if !meta_path.exists() {
        return Ok(None);
    }
    let mut meta: ProfileMetadata =
        serde_json::from_slice(&fs::read(&meta_path).context("read profile metadata")?)
            .with_context(|| format!("decode profile metadata at {}", meta_path.display()))?;
    if meta.attachments_dir.as_os_str().is_empty() {
        meta.attachments_dir = root.join("attachments");
        meta.inbox_attachments_dir = meta.attachments_dir.clone();
        meta.outbox_attachments_dir = meta.attachments_dir.clone();
    }
    Ok(Some(meta))
}

fn os_keychain_refs_from_metadata(meta: &ProfileMetadata) -> Result<Vec<ProfileKeychainEntryRef>> {
    let Some(encryption) = meta.encryption.as_ref() else {
        return Ok(Vec::new());
    };
    encryption
        .wrappers
        .iter()
        .filter(|wrapper| wrapper.kind == ProfileKeyWrapperKind::OsKeychain)
        .map(keychain_ref_from_wrapper)
        .collect()
}

fn classify_orphan_keychain_accounts(
    tapchat_accounts: &[String],
    registered_refs: &BTreeSet<ProfileKeychainEntryRef>,
) -> OrphanKeychainClassification {
    let registered_accounts: BTreeSet<String> = registered_refs
        .iter()
        .filter(|entry_ref| entry_ref.service == OS_KEYCHAIN_SERVICE)
        .map(|entry_ref| entry_ref.account.clone())
        .collect();
    let tapchat_account_set: BTreeSet<_> = tapchat_accounts.iter().map(String::as_str).collect();
    let mut classification = OrphanKeychainClassification::default();
    for account in tapchat_accounts {
        if registered_accounts.contains(account.as_str()) {
            classification.skipped_registered += 1;
        } else {
            classification.orphan_accounts.push(account.clone());
        }
    }
    classification.missing_registered_accounts = registered_accounts
        .iter()
        .filter(|account| !tapchat_account_set.contains(account.as_str()))
        .cloned()
        .collect();
    classification.orphan_accounts.sort();
    classification.orphan_accounts.dedup();
    classification.missing_registered_accounts.sort();
    classification
}

fn probe_os_keychain() -> ProfileKeychainProbeReport {
    let persistence = default::default_credential_builder().persistence();
    let persistent_backend = matches!(persistence, CredentialPersistence::UntilDelete);
    let mut report = ProfileKeychainProbeReport {
        attempted: persistent_backend,
        persistent_backend,
        writable: false,
        readable: false,
        deleted: false,
        error: None,
    };
    if !persistent_backend {
        append_probe_error(
            &mut report,
            format!(
                "OS keychain backend is not persistent ({})",
                credential_persistence_label(&persistence)
            ),
        );
        return report;
    }

    let entry_ref = ProfileKeychainEntryRef {
        service: OS_KEYCHAIN_SERVICE.into(),
        account: format!("probe:{}", Uuid::new_v4()),
    };
    let entry = match keyring::Entry::new(&entry_ref.service, &entry_ref.account) {
        Ok(entry) => entry,
        Err(error) => {
            append_probe_error(
                &mut report,
                format!("create probe OS keychain entry: {error}"),
            );
            return report;
        }
    };
    let probe_secret = generate_wrap_key();
    let encoded = STANDARD.encode(&*probe_secret);
    if let Err(error) = entry.set_password(&encoded) {
        append_probe_error(
            &mut report,
            format!("write probe OS keychain entry: {error}"),
        );
        return report;
    }
    report.writable = true;

    match entry.get_password() {
        Ok(stored) if stored == encoded => report.readable = true,
        Ok(_) => append_probe_error(&mut report, "probe OS keychain verification mismatch"),
        Err(error) => append_probe_error(
            &mut report,
            format!("read probe OS keychain entry: {error}"),
        ),
    }

    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => report.deleted = true,
        Err(error) => append_probe_error(
            &mut report,
            format!(
                "delete probe OS keychain entry {}: {error}",
                entry_ref.account
            ),
        ),
    }
    report
}

fn append_probe_error(report: &mut ProfileKeychainProbeReport, error: impl Into<String>) {
    let error = error.into();
    if let Some(existing) = report.error.as_mut() {
        existing.push_str("; ");
        existing.push_str(&error);
    } else {
        report.error = Some(error);
    }
}

#[cfg(target_os = "windows")]
fn keychain_cleanup_supported() -> bool {
    true
}

#[cfg(not(target_os = "windows"))]
fn keychain_cleanup_supported() -> bool {
    false
}

#[cfg(target_os = "windows")]
fn enumerate_tapchat_keychain_accounts() -> Result<Vec<String>> {
    use windows_sys::Win32::{
        Foundation::ERROR_NOT_FOUND,
        Security::Credentials::{CredEnumerateW, CredFree, CREDENTIALW},
    };

    let mut count = 0_u32;
    let mut credentials: *mut *mut CREDENTIALW = std::ptr::null_mut();
    let ok = unsafe { CredEnumerateW(std::ptr::null(), 0, &mut count, &mut credentials) };
    if ok == 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_NOT_FOUND as i32) {
            return Ok(Vec::new());
        }
        return Err(anyhow!(
            "Windows Credential Manager enumeration failed: {}",
            error
        ));
    }
    let mut accounts = Vec::new();
    if !credentials.is_null() {
        let credential_slice = unsafe { std::slice::from_raw_parts(credentials, count as usize) };
        for credential_ptr in credential_slice {
            if credential_ptr.is_null() {
                continue;
            }
            let credential = unsafe { &**credential_ptr };
            if credential.TargetName.is_null() {
                continue;
            }
            let target_name = unsafe { wide_ptr_to_string(credential.TargetName) };
            if let Some(account) = tapchat_account_from_windows_target(&target_name) {
                accounts.push(account);
            }
        }
    }
    unsafe { CredFree(credentials.cast()) };
    accounts.sort();
    accounts.dedup();
    Ok(accounts)
}

#[cfg(target_os = "windows")]
fn tapchat_account_from_windows_target(target_name: &str) -> Option<String> {
    target_name
        .strip_suffix(&format!(".{OS_KEYCHAIN_SERVICE}"))
        .map(str::to_string)
}

#[cfg(target_os = "windows")]
unsafe fn wide_ptr_to_string(ptr: *const u16) -> String {
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
}

#[cfg(not(target_os = "windows"))]
fn enumerate_tapchat_keychain_accounts() -> Result<Vec<String>> {
    bail!("TapChat keychain cleanup is only supported on Windows in this release")
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

fn keychain_unavailable_create_message() -> String {
    format!(
        "OS keychain is unavailable; provide a passphrase to create this profile, or create a passphrase-only profile with --no-keychain. {}",
        keychain_unlock_hint()
    )
}

fn keychain_unlock_hint() -> &'static str {
    if cfg!(target_os = "linux") {
        "Use --passphrase-stdin or TAPCHAT_PROFILE_PASSPHRASE for passphrase unlock; on Linux, a persistent Secret Service keyring over DBus is required for OS keychain unlock."
    } else {
        "Use --passphrase-stdin during profile init or TAPCHAT_PROFILE_PASSPHRASE when opening a passphrase-protected profile."
    }
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    use tempfile::tempdir;

    use keyring::{credential::CredentialPersistence, default};

    use super::{
        Profile, ProfileInitOptions, ProfileKeychainEntryRef, ProfileRegistry, RuntimeMetadata,
    };
    use crate::persistence::CorePersistenceSnapshot;
    use crate::profile_crypto::OS_KEYCHAIN_SERVICE;

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
    fn short_passphrase_profile_round_trips_and_rejects_wrong_passphrase() {
        let _guard = env_lock();
        let dir = tempdir().expect("tempdir");
        unsafe {
            std::env::set_var(
                "TAPCHAT_PROFILE_REGISTRY_PATH",
                dir.path().join("config").join("profiles.json"),
            );
        }
        let profile = Profile::init_with_options(
            "short",
            dir.path().join("short"),
            ProfileInitOptions {
                passphrase: Some("abc".into()),
                use_keychain: false,
            },
        )
        .expect("init profile");
        let diagnostics = profile.storage_diagnostics().expect("storage diagnostics");
        assert!(diagnostics.state_db_exists);
        assert_eq!(diagnostics.schema_version, Some(1));
        assert_eq!(diagnostics.migration_complete, Some(true));
        drop(profile);

        let reopened = Profile::open_with_passphrase(dir.path().join("short"), Some("abc".into()))
            .expect("open with short passphrase");
        assert_eq!(
            reopened.load_snapshot().expect("load snapshot"),
            CorePersistenceSnapshot::default()
        );
        drop(reopened);

        let error =
            match Profile::open_with_passphrase(dir.path().join("short"), Some("wrong".into())) {
                Ok(_) => panic!("wrong passphrase should be rejected"),
                Err(error) => error,
            };
        assert!(error
            .to_string()
            .contains("failed to unlock encrypted profile"));
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
    fn keychain_orphan_classification_keeps_registered_wrappers() {
        let registered = BTreeSet::from([ProfileKeychainEntryRef {
            service: OS_KEYCHAIN_SERVICE.into(),
            account: "profile:live:wrapper:live".into(),
        }]);
        let accounts = vec![
            "profile:live:wrapper:live".to_string(),
            "profile:old:wrapper:old".to_string(),
        ];

        let classification = super::classify_orphan_keychain_accounts(&accounts, &registered);

        assert_eq!(classification.skipped_registered, 1);
        assert_eq!(
            classification.orphan_accounts,
            vec!["profile:old:wrapper:old".to_string()]
        );
        assert!(classification.missing_registered_accounts.is_empty());
    }

    #[test]
    fn keychain_orphan_classification_reports_missing_registered_wrapper() {
        let registered = BTreeSet::from([ProfileKeychainEntryRef {
            service: OS_KEYCHAIN_SERVICE.into(),
            account: "profile:missing:wrapper:missing".into(),
        }]);
        let accounts = vec!["profile:old:wrapper:old".to_string()];

        let classification = super::classify_orphan_keychain_accounts(&accounts, &registered);

        assert_eq!(classification.skipped_registered, 0);
        assert_eq!(
            classification.missing_registered_accounts,
            vec!["profile:missing:wrapper:missing".to_string()]
        );
        assert_eq!(
            classification.orphan_accounts,
            vec!["profile:old:wrapper:old".to_string()]
        );
    }

    #[test]
    fn cleanup_profile_keychain_entries_without_metadata_is_noop() {
        let dir = tempdir().expect("tempdir");
        let report = super::cleanup_profile_keychain_entries(dir.path()).expect("cleanup");

        assert_eq!(report.would_delete, 0);
        assert_eq!(report.deleted, 0);
        assert!(report.errors.is_empty());
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

    #[test]
    fn profile_lock_is_reentrant_in_process_and_released() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path().join("locked");
        std::fs::create_dir_all(&root).expect("create root");

        let first = super::ProfileLockGuard::acquire(&root).expect("first lock");
        let second = super::ProfileLockGuard::acquire(&root).expect("same process reentrant lock");
        drop(first);
        drop(second);
        super::ProfileLockGuard::acquire(&root).expect("lock released");
    }

    #[test]
    fn profile_lock_error_includes_pid_metadata() {
        let dir = tempdir().expect("tempdir");
        let message =
            super::profile_lock_error_message(dir.path(), " lock holder pid=12345.", "locked");
        assert!(message.contains("already in use"));
        assert!(message.contains("lock holder pid=12345"));
    }
}

use bip39::{Language, Mnemonic};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha512;

use crate::capability::CapabilityManager;
use crate::error::{CoreError, CoreResult};
use crate::model::{
    DeploymentBundle, DeviceBinding, DeviceIdentity, DeviceStatus, DeviceStatusKind,
    IdentityBundle, StorageProfile, UserIdentity, Validate, CURRENT_MODEL_VERSION,
};

type HmacSha512 = Hmac<Sha512>;

const HARDENED_OFFSET: u32 = 0x8000_0000;
const USER_ROOT_DERIVATION_PATH: [u32; 5] = [44, 7330, 0, 0, 0];
const DEFAULT_MNEMONIC_WORDS: usize = 12;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IdentityModule;

impl IdentityModule {
    pub fn name(&self) -> &'static str {
        "identity"
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalIdentityState {
    pub mnemonic: String,
    pub user_identity: UserIdentity,
    pub device_identity: DeviceIdentity,
    pub device_status: DeviceStatus,
    // Restored from the BIP-39 mnemonic through the fixed TapChat HD path.
    user_root_signing_key: [u8; 32],
    // Generated per device and persisted locally; not recovered from the mnemonic.
    device_signing_key: [u8; 32],
}

impl LocalIdentityState {
    pub fn user_root_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.user_root_signing_key)
    }

    pub fn device_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.device_signing_key)
    }

    pub fn device_signing_key_bytes(&self) -> [u8; 32] {
        self.device_signing_key
    }

    pub fn sign_sender_proof(&self, payload: &[u8]) -> String {
        let signature = self.device_signing_key().sign(payload);
        encode_hex(&signature.to_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredUserRoot {
    pub mnemonic: String,
    pub user_identity: UserIdentity,
    user_root_signing_key: [u8; 32],
}

impl RecoveredUserRoot {
    pub fn user_root_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.user_root_signing_key)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct IdentityManager;

impl IdentityManager {
    pub fn generate_mnemonic() -> CoreResult<String> {
        let entropy_len = match DEFAULT_MNEMONIC_WORDS {
            12 => 16,
            15 => 20,
            18 => 24,
            21 => 28,
            24 => 32,
            _ => {
                return Err(CoreError::invalid_state(
                    "unsupported default BIP-39 mnemonic word count",
                ))
            }
        };
        let mut entropy = vec![0_u8; entropy_len];
        rand::thread_rng().fill_bytes(&mut entropy);
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .map_err(|error| CoreError::invalid_state(format!("failed to generate mnemonic: {error}")))?;
        Ok(mnemonic.to_string())
    }

    pub fn recover_user_root(mnemonic: &str) -> CoreResult<RecoveredUserRoot> {
        let normalized_mnemonic = normalize_mnemonic(mnemonic)?;
        let bip39 = parse_mnemonic(&normalized_mnemonic)?;
        let seed = bip39.to_seed("");
        let user_root_seed = derive_slip10_ed25519_key(&seed, &USER_ROOT_DERIVATION_PATH)?;
        let user_root_key = SigningKey::from_bytes(&user_root_seed);
        let user_public_key = encode_hex(user_root_key.verifying_key().as_bytes());
        let user_id = format!(
            "user:{}",
            short_fingerprint(user_root_key.verifying_key().as_bytes(), 16)
        );
        let user_identity = UserIdentity {
            version: CURRENT_MODEL_VERSION.to_string(),
            user_id,
            user_public_key,
            created_at: 0,
        };
        user_identity.validate()?;

        Ok(RecoveredUserRoot {
            mnemonic: normalized_mnemonic,
            user_identity,
            user_root_signing_key: user_root_seed,
        })
    }

    pub fn create_new_device_for_user(
        user_root: &RecoveredUserRoot,
        existing_device_key: Option<[u8; 32]>,
    ) -> CoreResult<LocalIdentityState> {
        let user_root_key = user_root.user_root_signing_key();
        let device_seed = existing_device_key.unwrap_or_else(generate_random_signing_key_bytes);
        let device_key = SigningKey::from_bytes(&device_seed);
        let device_public_key = encode_hex(device_key.verifying_key().as_bytes());
        let user_fingerprint = short_fingerprint(user_root_key.verifying_key().as_bytes(), 12);
        let device_id = format!(
            "device:{user_fingerprint}:{}",
            short_fingerprint(device_key.verifying_key().as_bytes(), 12)
        );
        let created_at = 0;

        let binding = build_device_binding(
            &user_root_key,
            &user_root.user_identity.user_id,
            &device_id,
            &device_public_key,
            created_at,
        );
        let device_identity = DeviceIdentity {
            version: CURRENT_MODEL_VERSION.to_string(),
            user_id: user_root.user_identity.user_id.clone(),
            device_id: device_id.clone(),
            device_public_key,
            created_at,
            binding,
        };
        let device_status = DeviceStatus {
            version: CURRENT_MODEL_VERSION.to_string(),
            user_id: user_root.user_identity.user_id.clone(),
            device_id,
            status: DeviceStatusKind::Active,
            updated_at: created_at,
        };

        device_identity.validate()?;
        device_status.validate()?;

        Ok(LocalIdentityState {
            mnemonic: user_root.mnemonic.clone(),
            user_identity: user_root.user_identity.clone(),
            device_identity,
            device_status,
            user_root_signing_key: user_root.user_root_signing_key,
            device_signing_key: device_seed,
        })
    }

    pub fn create_or_recover(
        mnemonic: Option<&str>,
        _device_name: Option<&str>,
    ) -> CoreResult<LocalIdentityState> {
        let mnemonic = match mnemonic {
            Some(value) if !value.trim().is_empty() => value.trim().to_string(),
            _ => Self::generate_mnemonic()?,
        };
        let user_root = Self::recover_user_root(&mnemonic)?;
        Self::create_new_device_for_user(&user_root, None)
    }

    pub fn verify_device_binding(
        user_public_key: &str,
        binding: &DeviceBinding,
    ) -> CoreResult<()> {
        binding.validate()?;
        let verifying_key = parse_verifying_key(user_public_key)?;
        if binding.device_public_key.trim().is_empty() {
            return Err(CoreError::invalid_input("device binding device_public_key is empty"));
        }
        let signature = parse_signature(&binding.signature)?;
        verifying_key
            .verify(
                build_binding_payload(
                    &binding.user_id,
                    &binding.device_id,
                    &binding.device_public_key,
                    binding.created_at,
                )
                .as_bytes(),
                &signature,
            )
            .map_err(|_| CoreError::invalid_input("device binding signature mismatch"))?;
        Ok(())
    }

    pub fn verify_identity_bundle(bundle: &IdentityBundle) -> CoreResult<()> {
        bundle.validate()?;
        let verifying_key = parse_verifying_key(&bundle.user_public_key)?;
        let signature = parse_signature(&bundle.signature)?;
        verifying_key
            .verify(identity_bundle_payload(bundle).as_bytes(), &signature)
            .map_err(|_| CoreError::invalid_input("identity bundle signature mismatch"))?;
        for device in &bundle.devices {
            Self::verify_device_binding(&bundle.user_public_key, &device.binding)?;
            CapabilityManager::verify_device_contact_profile(device)?;
            if device.binding.user_id != bundle.user_id {
                return Err(CoreError::invalid_input(
                    "device binding user_id does not match identity bundle user_id",
                ));
            }
            if device.binding.device_id != device.device_id {
                return Err(CoreError::invalid_input(
                    "device binding device_id does not match device profile device_id",
                ));
            }
            if device.binding.device_public_key != device.device_public_key {
                return Err(CoreError::invalid_input(
                    "device binding device_public_key does not match device profile device_public_key",
                ));
            }
        }
        Ok(())
    }

    pub fn export_identity_bundle(
        local_identity: &LocalIdentityState,
        deployment: &DeploymentBundle,
        key_package_ref: String,
        key_package_expires_at: u64,
    ) -> CoreResult<IdentityBundle> {
        let device_profile = CapabilityManager::build_device_contact_profile(
            local_identity,
            deployment,
            key_package_ref,
            key_package_expires_at,
        )?;
        let unsigned = IdentityBundle {
            version: CURRENT_MODEL_VERSION.to_string(),
            user_id: local_identity.user_identity.user_id.clone(),
            user_public_key: local_identity.user_identity.user_public_key.clone(),
            devices: vec![device_profile],
            // Deployment runtime config may provide bootstrap references for publishing the
            // local user's shared state. Contact refresh must not infer these values.
            identity_bundle_ref: deployment.runtime_config.identity_bundle_ref.clone(),
            device_status_ref: deployment.runtime_config.device_status_ref.clone(),
            storage_profile: Some(StorageProfile {
                base_url: deployment.storage_base_info.base_url.clone(),
                profile_ref: None,
            }),
            updated_at: local_identity.device_status.updated_at,
            signature: String::new(),
        };
        let signature = local_identity
            .user_root_signing_key()
            .sign(identity_bundle_payload(&unsigned).as_bytes());
        Ok(IdentityBundle {
            signature: encode_hex(&signature.to_bytes()),
            ..unsigned
        })
    }
}

fn build_device_binding(
    user_root_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    device_public_key: &str,
    created_at: u64,
) -> DeviceBinding {
    DeviceBinding {
        version: CURRENT_MODEL_VERSION.to_string(),
        user_id: user_id.to_string(),
        device_id: device_id.to_string(),
        device_public_key: device_public_key.to_string(),
        created_at,
        signature: encode_hex(
            &user_root_key
                .sign(build_binding_payload(user_id, device_id, device_public_key, created_at).as_bytes())
                .to_bytes(),
        ),
    }
}

fn build_binding_payload(
    user_id: &str,
    device_id: &str,
    device_public_key: &str,
    created_at: u64,
) -> String {
    format!("{CURRENT_MODEL_VERSION}:{user_id}:{device_id}:{device_public_key}:{created_at}")
}

fn parse_mnemonic(mnemonic: &str) -> CoreResult<Mnemonic> {
    Mnemonic::parse_in_normalized(Language::English, mnemonic)
        .map_err(|error| CoreError::invalid_input(format!("invalid BIP-39 mnemonic: {error}")))
}

fn normalize_mnemonic(mnemonic: &str) -> CoreResult<String> {
    let trimmed = mnemonic.trim();
    if trimmed.is_empty() {
        return Err(CoreError::invalid_input("mnemonic must not be empty"));
    }
    Ok(parse_mnemonic(trimmed)?.to_string())
}

fn generate_random_signing_key_bytes() -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

fn derive_slip10_ed25519_key(seed: &[u8], path: &[u32]) -> CoreResult<[u8; 32]> {
    let mut mac = HmacSha512::new_from_slice(b"ed25519 seed")
        .map_err(|_| CoreError::invalid_state("failed to initialize SLIP-0010 root HMAC"))?;
    mac.update(seed);
    let output = mac.finalize().into_bytes();
    let mut secret = [0_u8; 32];
    let mut chain_code = [0_u8; 32];
    secret.copy_from_slice(&output[..32]);
    chain_code.copy_from_slice(&output[32..]);

    for index in path {
        let hardened_index = index
            .checked_add(HARDENED_OFFSET)
            .ok_or_else(|| CoreError::invalid_state("invalid hardened derivation index"))?;
        let mut mac = HmacSha512::new_from_slice(&chain_code)
            .map_err(|_| CoreError::invalid_state("failed to initialize child derivation HMAC"))?;
        let mut data = Vec::with_capacity(1 + secret.len() + 4);
        data.push(0);
        data.extend_from_slice(&secret);
        data.extend_from_slice(&hardened_index.to_be_bytes());
        mac.update(&data);
        let output = mac.finalize().into_bytes();
        secret.copy_from_slice(&output[..32]);
        chain_code.copy_from_slice(&output[32..]);
    }

    Ok(secret)
}

fn identity_bundle_payload(bundle: &IdentityBundle) -> String {
    let mut parts = vec![
        bundle.version.clone(),
        bundle.user_id.clone(),
        bundle.user_public_key.clone(),
        bundle.updated_at.to_string(),
        bundle.identity_bundle_ref.clone().unwrap_or_default(),
        bundle.device_status_ref.clone().unwrap_or_default(),
        bundle
            .storage_profile
            .as_ref()
            .and_then(|profile| profile.base_url.clone())
            .unwrap_or_default(),
        bundle
            .storage_profile
            .as_ref()
            .and_then(|profile| profile.profile_ref.clone())
            .unwrap_or_default(),
    ];
    for device in &bundle.devices {
        parts.push(device.device_id.clone());
        parts.push(device.device_public_key.clone());
        parts.push(device.binding.signature.clone());
        parts.push(device.inbox_append_capability.signature.clone());
        parts.push(device.keypackage_ref.object_ref.clone());
        parts.push(device.keypackage_ref.expires_at.to_string());
    }
    parts.join("|")
}

fn short_fingerprint(bytes: &[u8], len: usize) -> String {
    encode_hex(bytes)[..len].to_string()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_hex(input: &str) -> CoreResult<Vec<u8>> {
    let trimmed = input.trim();
    if trimmed.len() % 2 != 0 {
        return Err(CoreError::invalid_input("hex input must have even length"));
    }
    let mut output = Vec::with_capacity(trimmed.len() / 2);
    let chars: Vec<char> = trimmed.chars().collect();
    for chunk in chars.chunks(2) {
        let value = u8::from_str_radix(&chunk.iter().collect::<String>(), 16)
            .map_err(|_| CoreError::invalid_input("invalid hex input"))?;
        output.push(value);
    }
    Ok(output)
}

pub fn parse_verifying_key(input: &str) -> CoreResult<VerifyingKey> {
    let bytes = parse_hex(input)?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| CoreError::invalid_input("verifying key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&array)
        .map_err(|_| CoreError::invalid_input("invalid verifying key bytes"))
}

pub fn parse_signature(input: &str) -> CoreResult<Signature> {
    let bytes = parse_hex(input)?;
    let array: [u8; 64] = bytes
        .try_into()
        .map_err(|_| CoreError::invalid_input("signature must be 64 bytes"))?;
    Ok(Signature::from_bytes(&array))
}

#[cfg(test)]
mod tests {
    use super::{IdentityManager, IdentityModule, DEFAULT_MNEMONIC_WORDS};
    use bip39::Language;
    use crate::model::{
        CapabilityConstraints, CapabilityOperation, CapabilityService, DeploymentBundle,
        DeviceContactProfile, DeviceRuntimeAuth, DeviceStatusKind, IdentityBundle,
        InboxAppendCapability, KeyPackageRef, StorageBaseInfo, CURRENT_MODEL_VERSION,
    };

    const ALICE_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const BOB_MNEMONIC: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";

    #[test]
    fn module_name_is_stable() {
        assert_eq!(IdentityModule.name(), "identity");
    }

    #[test]
    fn generated_mnemonic_is_valid_bip39() {
        let mnemonic = IdentityManager::generate_mnemonic().expect("mnemonic");
        let parsed = bip39::Mnemonic::parse_in_normalized(Language::English, &mnemonic)
            .expect("valid bip39");
        assert_eq!(parsed.word_count(), DEFAULT_MNEMONIC_WORDS);
    }

    #[test]
    fn invalid_mnemonic_is_rejected() {
        let error = IdentityManager::recover_user_root("alpha beta gamma")
            .expect_err("invalid mnemonic should fail");
        assert_eq!(error.code(), "invalid_input");
    }

    #[test]
    fn same_mnemonic_recovers_same_user_identity() {
        let first = IdentityManager::recover_user_root(ALICE_MNEMONIC).expect("first identity");
        let second = IdentityManager::recover_user_root(ALICE_MNEMONIC).expect("second identity");

        assert_eq!(first.user_identity.user_id, second.user_identity.user_id);
        assert_eq!(
            first.user_identity.user_public_key,
            second.user_identity.user_public_key
        );
    }

    #[test]
    fn same_mnemonic_creates_distinct_random_devices() {
        let user_root = IdentityManager::recover_user_root(ALICE_MNEMONIC).expect("user root");
        let first = IdentityManager::create_new_device_for_user(&user_root, None).expect("first");
        let second = IdentityManager::create_new_device_for_user(&user_root, None).expect("second");

        assert_eq!(first.user_identity.user_id, second.user_identity.user_id);
        assert_ne!(first.device_identity.device_id, second.device_identity.device_id);
    }

    #[test]
    fn existing_device_key_restores_same_device() {
        let first = IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone"))
            .expect("first identity");
        let recovered_root = IdentityManager::recover_user_root(ALICE_MNEMONIC).expect("user root");
        let restored = IdentityManager::create_new_device_for_user(
            &recovered_root,
            Some(first.device_signing_key_bytes()),
        )
        .expect("restored identity");

        assert_eq!(first.user_identity.user_id, restored.user_identity.user_id);
        assert_eq!(first.device_identity.device_id, restored.device_identity.device_id);
    }

    #[test]
    fn different_mnemonics_produce_different_users() {
        let alice = IdentityManager::recover_user_root(ALICE_MNEMONIC).expect("alice");
        let bob = IdentityManager::recover_user_root(BOB_MNEMONIC).expect("bob");

        assert_ne!(alice.user_identity.user_id, bob.user_identity.user_id);
    }

    #[test]
    fn device_binding_can_be_verified() {
        let identity = IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone"))
            .expect("identity");
        IdentityManager::verify_device_binding(
            &identity.user_identity.user_public_key,
            &identity.device_identity.binding,
        )
        .expect("binding should verify");
    }

    #[test]
    fn identity_bundle_verification_rejects_tampered_binding() {
        let identity = IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone"))
            .expect("identity");
        let mut bundle = IdentityBundle {
            version: CURRENT_MODEL_VERSION.to_string(),
            user_id: identity.user_identity.user_id.clone(),
            user_public_key: identity.user_identity.user_public_key.clone(),
            devices: vec![DeviceContactProfile {
                version: CURRENT_MODEL_VERSION.to_string(),
                device_id: identity.device_identity.device_id.clone(),
                device_public_key: identity.device_identity.device_public_key.clone(),
                binding: identity.device_identity.binding.clone(),
                status: DeviceStatusKind::Active,
                inbox_append_capability: InboxAppendCapability {
                    version: CURRENT_MODEL_VERSION.to_string(),
                    service: CapabilityService::Inbox,
                    user_id: identity.user_identity.user_id.clone(),
                    target_device_id: identity.device_identity.device_id.clone(),
                    endpoint: "https://example.com/inbox".into(),
                    operations: vec![CapabilityOperation::Append],
                    conversation_scope: vec![],
                    expires_at: 999,
                    constraints: Some(CapabilityConstraints {
                        max_bytes: Some(1024),
                        max_ops_per_minute: Some(10),
                    }),
                    signature: "cap-sig".into(),
                },
                keypackage_ref: KeyPackageRef {
                    version: CURRENT_MODEL_VERSION.to_string(),
                    user_id: identity.user_identity.user_id.clone(),
                    device_id: identity.device_identity.device_id.clone(),
                    object_ref: "s3://keypackage".into(),
                    expires_at: 999,
                },
            }],
            identity_bundle_ref: None,
            device_status_ref: None,
            storage_profile: None,
            updated_at: 0,
            signature: "bundle-sig".into(),
        };
        bundle.devices[0].binding.signature = "tampered".into();

        let error = IdentityManager::verify_identity_bundle(&bundle)
            .expect_err("tampered bundle should fail");
        assert_eq!(error.code(), "invalid_input");
    }

    #[test]
    fn exported_identity_bundle_can_be_verified() {
        let identity = IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone"))
            .expect("identity");
        let bundle = IdentityManager::export_identity_bundle(
            &identity,
            &sample_deployment(),
            "kp-ref".into(),
            999,
        )
        .expect("bundle");
        IdentityManager::verify_identity_bundle(&bundle).expect("bundle should verify");
    }

    #[test]
    fn exported_identity_bundle_uses_runtime_config_bootstrap_refs_only() {
        let identity = IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone"))
            .expect("identity");
        let bundle = IdentityManager::export_identity_bundle(
            &identity,
            &sample_deployment(),
            "kp-ref".into(),
            999,
        )
        .expect("bundle");

        assert_eq!(
            bundle.identity_bundle_ref.as_deref(),
            Some("https://storage.example.com/state/user:alice/identity_bundle.json")
        );
        assert_eq!(
            bundle.device_status_ref.as_deref(),
            Some("https://storage.example.com/state/user:alice/device_status.json")
        );
        assert_eq!(
            bundle
                .storage_profile
                .as_ref()
                .and_then(|profile| profile.base_url.as_deref()),
            Some("https://storage.example.com")
        );
        assert_eq!(
            bundle
                .storage_profile
                .as_ref()
                .and_then(|profile| profile.profile_ref.as_deref()),
            None
        );
    }

    #[test]
    fn exported_identity_bundle_does_not_infer_state_paths_from_base_url() {
        let identity = IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone"))
            .expect("identity");
        let mut deployment = sample_deployment();
        deployment.runtime_config.identity_bundle_ref = None;
        deployment.runtime_config.device_status_ref = None;

        let bundle =
            IdentityManager::export_identity_bundle(&identity, &deployment, "kp-ref".into(), 999)
                .expect("bundle");

        assert_eq!(bundle.identity_bundle_ref, None);
        assert_eq!(bundle.device_status_ref, None);
        assert_eq!(
            bundle
                .storage_profile
                .as_ref()
                .and_then(|profile| profile.base_url.as_deref()),
            Some("https://storage.example.com")
        );
        assert_eq!(
            bundle
                .storage_profile
                .as_ref()
                .and_then(|profile| profile.profile_ref.as_deref()),
            None
        );
    }

    fn sample_deployment() -> DeploymentBundle {
        DeploymentBundle {
            version: CURRENT_MODEL_VERSION.to_string(),
            region: "local".into(),
            inbox_http_endpoint: "https://example.com".into(),
            inbox_websocket_endpoint: "wss://example.com/ws".into(),
            storage_base_info: StorageBaseInfo {
                base_url: Some("https://storage.example.com".into()),
                bucket_hint: None,
            },
            runtime_config: crate::model::RuntimeConfig {
                supported_realtime_kinds: vec![crate::model::RealtimeKind::Websocket],
                identity_bundle_ref: Some(
                    "https://storage.example.com/state/user:alice/identity_bundle.json".into(),
                ),
                device_status_ref: Some(
                    "https://storage.example.com/state/user:alice/device_status.json".into(),
                ),
                keypackage_ref_base: Some("https://storage.example.com/keypackages".into()),
                max_inline_bytes: Some(4096),
                features: vec!["generic_sync".into()],
            },
            device_runtime_auth: Some(DeviceRuntimeAuth {
                scheme: "bearer".into(),
                token: "device-runtime-token".into(),
                expires_at: 999,
                user_id: "user:alice".into(),
                device_id: "device:alice:phone".into(),
                scopes: vec!["inbox_read".into(), "shared_state_write".into()],
            }),
            expected_user_id: None,
            expected_device_id: None,
        }
    }
}

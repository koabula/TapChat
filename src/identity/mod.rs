use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::capability::CapabilityManager;
use crate::error::{CoreError, CoreResult};
use crate::model::{
    DeploymentBundle, DeviceBinding, DeviceIdentity, DeviceStatus, DeviceStatusKind,
    IdentityBundle, StorageProfile, UserIdentity, Validate, CURRENT_MODEL_VERSION,
};

const DEFAULT_DEVICE_NAME: &str = "device";

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IdentityModule;

impl IdentityModule {
    pub fn name(&self) -> &'static str {
        "identity"
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalIdentityState {
    pub mnemonic: String,
    pub user_identity: UserIdentity,
    pub device_identity: DeviceIdentity,
    pub device_status: DeviceStatus,
    user_root_signing_key: [u8; 32],
    device_signing_key: [u8; 32],
}

impl LocalIdentityState {
    pub fn user_root_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.user_root_signing_key)
    }

    pub fn device_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.device_signing_key)
    }

    pub fn sign_sender_proof(&self, payload: &[u8]) -> String {
        let signature = self.device_signing_key().sign(payload);
        encode_hex(&signature.to_bytes())
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct IdentityManager;

impl IdentityManager {
    pub fn create_or_recover(
        mnemonic: Option<&str>,
        device_name: Option<&str>,
    ) -> CoreResult<LocalIdentityState> {
        let mnemonic = match mnemonic {
            Some(value) if !value.trim().is_empty() => value.trim().to_string(),
            _ => generate_placeholder_mnemonic(),
        };
        let device_name = normalize_device_name(device_name.unwrap_or(DEFAULT_DEVICE_NAME));
        let user_root_seed = derive_seed("user_root", mnemonic.as_bytes());
        let device_seed = derive_seed(
            "device_key",
            format!("{mnemonic}:{device_name}").as_bytes(),
        );

        let user_root_key = SigningKey::from_bytes(&user_root_seed);
        let device_key = SigningKey::from_bytes(&device_seed);
        let user_public_key = encode_hex(&user_root_key.verifying_key().to_bytes());
        let device_public_key = encode_hex(&device_key.verifying_key().to_bytes());
        let user_id = format!("user:{}", short_fingerprint(user_root_key.verifying_key().as_bytes(), 16));
        let device_id = format!(
            "device:{}:{}",
            short_fingerprint(user_root_key.verifying_key().as_bytes(), 12),
            short_fingerprint(device_key.verifying_key().as_bytes(), 12)
        );
        let created_at = 0;

        let user_identity = UserIdentity {
            version: CURRENT_MODEL_VERSION.to_string(),
            user_id: user_id.clone(),
            user_public_key: user_public_key.clone(),
            created_at,
        };
        let binding = build_device_binding(&user_root_key, &user_id, &device_id, &device_public_key, created_at);
        let device_identity = DeviceIdentity {
            version: CURRENT_MODEL_VERSION.to_string(),
            user_id: user_id.clone(),
            device_id: device_id.clone(),
            device_public_key,
            created_at,
            binding,
        };
        let device_status = DeviceStatus {
            version: CURRENT_MODEL_VERSION.to_string(),
            user_id,
            device_id,
            status: DeviceStatusKind::Active,
            updated_at: created_at,
        };

        user_identity.validate()?;
        device_identity.validate()?;
        device_status.validate()?;

        Ok(LocalIdentityState {
            mnemonic,
            user_identity,
            device_identity,
            device_status,
            user_root_signing_key: user_root_seed,
            device_signing_key: device_seed,
        })
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
            device_status_ref: Some(format!(
                "{}/state/{}/device_status.json",
                deployment.storage_base_info.base_url.clone().unwrap_or_default(),
                local_identity.user_identity.user_id
            )),
            storage_profile: Some(StorageProfile {
                base_url: deployment.storage_base_info.base_url.clone(),
                profile_ref: Some(format!(
                    "{}/state/{}/storage_profile.json",
                    deployment.storage_base_info.base_url.clone().unwrap_or_default(),
                    local_identity.user_identity.user_id
                )),
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

fn generate_placeholder_mnemonic() -> String {
    let mut bytes = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn normalize_device_name(name: &str) -> String {
    let normalized = name.trim().to_lowercase().replace(' ', "-");
    if normalized.is_empty() {
        DEFAULT_DEVICE_NAME.to_string()
    } else {
        normalized
    }
}

fn derive_seed(label: &str, input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.update([0]);
    hasher.update(input);
    hasher.finalize().into()
}

fn identity_bundle_payload(bundle: &IdentityBundle) -> String {
    let mut parts = vec![
        bundle.version.clone(),
        bundle.user_id.clone(),
        bundle.user_public_key.clone(),
        bundle.updated_at.to_string(),
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
    use super::{IdentityManager, IdentityModule};
    use crate::model::{
        CapabilityConstraints, CapabilityOperation, CapabilityService, DeploymentBundle,
        DeviceContactProfile, DeviceStatusKind, IdentityBundle, InboxAppendCapability,
        KeyPackageRef, StorageBaseInfo, CURRENT_MODEL_VERSION,
    };

    #[test]
    fn module_name_is_stable() {
        assert_eq!(IdentityModule.name(), "identity");
    }

    #[test]
    fn same_mnemonic_recovers_same_user_identity() {
        let first = IdentityManager::create_or_recover(Some("alpha beta gamma"), Some("phone"))
            .expect("first identity");
        let second = IdentityManager::create_or_recover(Some("alpha beta gamma"), Some("phone"))
            .expect("second identity");

        assert_eq!(first.user_identity.user_id, second.user_identity.user_id);
        assert_eq!(
            first.user_identity.user_public_key,
            second.user_identity.user_public_key
        );
        assert_eq!(first.device_identity.device_id, second.device_identity.device_id);
    }

    #[test]
    fn different_device_names_produce_different_device_ids() {
        let phone = IdentityManager::create_or_recover(Some("alpha beta gamma"), Some("phone"))
            .expect("phone identity");
        let laptop = IdentityManager::create_or_recover(Some("alpha beta gamma"), Some("laptop"))
            .expect("laptop identity");

        assert_ne!(phone.device_identity.device_id, laptop.device_identity.device_id);
        assert_eq!(phone.user_identity.user_id, laptop.user_identity.user_id);
    }

    #[test]
    fn device_binding_can_be_verified() {
        let identity = IdentityManager::create_or_recover(Some("alpha beta gamma"), Some("phone"))
            .expect("identity");
        IdentityManager::verify_device_binding(
            &identity.user_identity.user_public_key,
            &identity.device_identity.binding,
        )
        .expect("binding should verify");
    }

    #[test]
    fn identity_bundle_verification_rejects_tampered_binding() {
        let identity = IdentityManager::create_or_recover(Some("alpha beta gamma"), Some("phone"))
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
        let identity = IdentityManager::create_or_recover(Some("alpha beta gamma"), Some("phone"))
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
            runtime_config: crate::model::RuntimeConfig::default(),
            expected_user_id: None,
            expected_device_id: None,
        }
    }
}

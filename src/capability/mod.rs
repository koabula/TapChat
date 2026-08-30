use ed25519_dalek::{Signer, Verifier};

use crate::error::{CoreError, CoreResult};
use crate::identity::{encode_hex, parse_verifying_key, LocalIdentityState};
use crate::model::{
    CapabilityConstraints, CapabilityOperation, CapabilityService, DeploymentBundle,
    DeviceContactProfile, InboxAppendCapability, KeyPackageRef, Validate, CURRENT_MODEL_VERSION,
};

pub const INBOX_APPEND_CAPABILITY_LIFETIME_MS: u64 = 365 * 24 * 60 * 60 * 1000;
pub const INBOX_APPEND_CAPABILITY_RENEWAL_WINDOW_MS: u64 = 30 * 24 * 60 * 60 * 1000;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CapabilityModule;

impl CapabilityModule {
    pub fn name(&self) -> &'static str {
        "capability"
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct CapabilityManager;

impl CapabilityManager {
    pub fn build_inbox_append_capability(
        local_identity: &LocalIdentityState,
        deployment: &DeploymentBundle,
        expires_at: u64,
    ) -> CoreResult<InboxAppendCapability> {
        let endpoint = format!(
            "{}/v1/inbox/{}/messages",
            deployment.inbox_http_endpoint.trim_end_matches('/'),
            local_identity.device_identity.device_id
        );
        let unsigned = InboxAppendCapability {
            version: CURRENT_MODEL_VERSION.to_string(),
            service: CapabilityService::Inbox,
            user_id: local_identity.user_identity.user_id.clone(),
            target_device_id: local_identity.device_identity.device_id.clone(),
            endpoint,
            operations: vec![CapabilityOperation::Append],
            conversation_scope: vec![],
            expires_at,
            constraints: Some(CapabilityConstraints {
                max_bytes: Some(256 * 1024),
                max_ops_per_minute: Some(60),
            }),
            signature: String::new(),
        };
        let signature = local_identity
            .device_signing_key()
            .sign(capability_payload(&unsigned).as_bytes());
        Ok(InboxAppendCapability {
            signature: encode_hex(&signature.to_bytes()),
            ..unsigned
        })
    }

    pub fn build_key_package_ref(
        local_identity: &LocalIdentityState,
        key_package_ref: String,
        expires_at: u64,
    ) -> KeyPackageRef {
        let created_at = expires_at.saturating_sub(crate::mls_adapter::KEY_PACKAGE_LIFETIME_MS);
        KeyPackageRef {
            version: CURRENT_MODEL_VERSION.to_string(),
            lifecycle_version: crate::mls_adapter::KEY_PACKAGE_LIFECYCLE_VERSION,
            user_id: local_identity.user_identity.user_id.clone(),
            device_id: local_identity.device_identity.device_id.clone(),
            object_ref: key_package_ref,
            not_before: created_at.saturating_sub(crate::mls_adapter::KEY_PACKAGE_CLOCK_SKEW_MS),
            created_at,
            expires_at,
        }
    }

    pub fn build_key_package_ref_with_lifetime(
        local_identity: &LocalIdentityState,
        key_package_ref: String,
        lifecycle_version: u16,
        not_before: u64,
        created_at: u64,
        expires_at: u64,
    ) -> KeyPackageRef {
        KeyPackageRef {
            version: CURRENT_MODEL_VERSION.to_string(),
            lifecycle_version,
            user_id: local_identity.user_identity.user_id.clone(),
            device_id: local_identity.device_identity.device_id.clone(),
            object_ref: key_package_ref,
            not_before,
            created_at,
            expires_at,
        }
    }

    pub fn build_device_contact_profile(
        local_identity: &LocalIdentityState,
        deployment: &DeploymentBundle,
        key_package_ref: String,
        key_package_expires_at: u64,
    ) -> CoreResult<DeviceContactProfile> {
        let now_ms =
            key_package_expires_at.saturating_sub(crate::mls_adapter::KEY_PACKAGE_LIFETIME_MS);
        Self::build_device_contact_profile_with_lifetime(
            local_identity,
            deployment,
            key_package_ref,
            crate::mls_adapter::KEY_PACKAGE_LIFECYCLE_VERSION,
            now_ms.saturating_sub(crate::mls_adapter::KEY_PACKAGE_CLOCK_SKEW_MS),
            now_ms,
            key_package_expires_at,
            now_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build_device_contact_profile_with_lifetime(
        local_identity: &LocalIdentityState,
        deployment: &DeploymentBundle,
        key_package_ref: String,
        lifecycle_version: u16,
        key_package_not_before: u64,
        key_package_created_at: u64,
        key_package_expires_at: u64,
        now_ms: u64,
    ) -> CoreResult<DeviceContactProfile> {
        let capability = Self::build_inbox_append_capability(
            local_identity,
            deployment,
            now_ms.saturating_add(INBOX_APPEND_CAPABILITY_LIFETIME_MS),
        )?;
        Ok(DeviceContactProfile {
            version: CURRENT_MODEL_VERSION.to_string(),
            device_id: local_identity.device_identity.device_id.clone(),
            device_public_key: local_identity.device_identity.device_public_key.clone(),
            binding: local_identity.device_identity.binding.clone(),
            status: local_identity.device_status.status,
            inbox_append_capability: Some(capability),
            keypackage_ref: Some(Self::build_key_package_ref_with_lifetime(
                local_identity,
                key_package_ref,
                lifecycle_version,
                key_package_not_before,
                key_package_created_at,
                key_package_expires_at,
            )),
        })
    }

    pub fn verify_inbox_append_capability(
        capability: &InboxAppendCapability,
        device_public_key: &str,
    ) -> CoreResult<()> {
        capability.validate()?;
        let signature_bytes = crate::identity::parse_signature(&capability.signature)?;
        let verifying_key = parse_verifying_key(device_public_key)?;
        verifying_key
            .verify(capability_payload(capability).as_bytes(), &signature_bytes)
            .map_err(|_| CoreError::invalid_input("capability signature mismatch"))?;
        Ok(())
    }

    pub fn verify_device_contact_profile(profile: &DeviceContactProfile) -> CoreResult<()> {
        profile.validate()?;
        if let Some(capability) = &profile.inbox_append_capability {
            Self::verify_inbox_append_capability(capability, &profile.device_public_key)?;
        }
        if let Some(keypackage_ref) = &profile.keypackage_ref {
            if keypackage_ref.device_id != profile.device_id {
                return Err(CoreError::invalid_input(
                    "key package ref device_id must match device profile",
                ));
            }
            if keypackage_ref.lifecycle_version > 0 {
                crate::mls_adapter::validate_published_key_package_lifetime(
                    &keypackage_ref.object_ref,
                    keypackage_ref.lifecycle_version,
                    keypackage_ref.not_before,
                    keypackage_ref.created_at,
                    keypackage_ref.expires_at,
                )?;
            }
        }
        Ok(())
    }
}

fn capability_payload(capability: &InboxAppendCapability) -> String {
    let constraints = capability
        .constraints
        .as_ref()
        .map(|constraints| {
            format!(
                "{}:{}",
                constraints
                    .max_bytes
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
                constraints
                    .max_ops_per_minute
                    .map(|value| value.to_string())
                    .unwrap_or_default()
            )
        })
        .unwrap_or_default();
    format!(
        "{}|{:?}|{}|{}|{}|{:?}|{}|{}|{}",
        capability.version,
        capability.service,
        capability.user_id,
        capability.target_device_id,
        capability.endpoint,
        capability.operations,
        capability.conversation_scope.join(","),
        capability.expires_at,
        constraints
    )
}

#[cfg(test)]
mod tests {
    use super::{CapabilityManager, CapabilityModule};
    use crate::identity::IdentityManager;
    use crate::model::DeploymentBundle;

    const ALICE_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn module_name_is_stable() {
        assert_eq!(CapabilityModule.name(), "capability");
    }

    #[test]
    fn generated_capability_can_be_verified() {
        let identity = IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone"))
            .expect("identity");
        let deployment = sample_deployment();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test clock")
            .as_millis() as u64;
        let package = crate::mls_adapter::MlsAdapter::generate_key_package(&identity, now_ms)
            .expect("key package");
        let profile = CapabilityManager::build_device_contact_profile(
            &identity,
            &deployment,
            package.key_package_b64,
            package.expires_at,
        )
        .expect("profile");
        CapabilityManager::verify_device_contact_profile(&profile).expect("profile should verify");
    }

    fn sample_deployment() -> DeploymentBundle {
        DeploymentBundle {
            version: crate::model::CURRENT_MODEL_VERSION.to_string(),
            runtime_id: "runtime:test".into(),
            protocol_version: 6,
            worker_build_id: "test-worker-v4".into(),
            registry_schema_version: 2,
            region: "local".into(),
            inbox_http_endpoint: "https://example.com".into(),
            inbox_websocket_endpoint: "wss://example.com/ws".into(),
            storage_base_info: crate::model::StorageBaseInfo::default(),
            runtime_config: crate::model::RuntimeConfig {
                supported_realtime_kinds: vec![crate::model::RealtimeKind::Websocket],
                identity_bundle_ref: None,
                device_status_ref: None,
                keypackage_ref_base: Some("https://example.com/keypackages".into()),
                max_inline_bytes: Some(4096),
                features: vec!["generic_sync".into(), "group_crypto_epoch_v1".into()],
            },
            expected_user_id: None,
            expected_device_id: None,
        }
    }
}

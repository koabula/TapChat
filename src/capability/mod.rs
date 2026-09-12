use crate::error::{CoreError, CoreResult};
use crate::identity::LocalIdentityState;
use crate::model::signing::{SignatureDomain, SigningPayload};
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
        Ok(InboxAppendCapability {
            signature: local_identity.sign_payload(inbox_append_capability_payload(&unsigned)),
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
        crate::identity::verify_device_payload_signature(
            device_public_key,
            inbox_append_capability_payload(capability),
            &capability.signature,
        )
        .map_err(|_| CoreError::invalid_input("capability signature mismatch"))
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

/// The exact bytes an inbox append capability signs.
///
/// Every variable-length field is length-prefixed and every list carries a
/// count, so no field value can shift a boundary. The previous encoding
/// joined the fields with `|` and took two of them from Rust `Debug` output:
/// an `endpoint` or a `conversation_scope` entry containing `|` could reframe
/// the capability into a different one bearing the same signature, and the
/// worker had to reconstruct `Debug` formatting by hand to verify anything.
///
/// `constraints` needs a presence byte of its own because it is an `Option`
/// wrapping two more: the old encoding collapsed absent, empty and zero into
/// the same text.
pub fn inbox_append_capability_payload(capability: &InboxAppendCapability) -> SigningPayload {
    let mut payload = SigningPayload::new(SignatureDomain::InboxAppendCapability);
    payload.push_str(&capability.version);
    payload.push_str(capability.service.wire_name());
    payload.push_str(&capability.user_id);
    payload.push_str(&capability.target_device_id);
    payload.push_str(&capability.endpoint);
    payload.push_u32(capability.operations.len() as u32);
    for operation in &capability.operations {
        payload.push_str(operation.wire_name());
    }
    payload.push_u32(capability.conversation_scope.len() as u32);
    for conversation_id in &capability.conversation_scope {
        payload.push_str(conversation_id);
    }
    payload.push_u64(capability.expires_at);
    match &capability.constraints {
        Some(constraints) => {
            payload.push_u32(1);
            payload.push_optional_u64(constraints.max_bytes);
            payload.push_optional_u64(constraints.max_ops_per_minute.map(u64::from));
        }
        None => payload.push_u32(0),
    }
    payload
}

#[cfg(test)]
mod tests {
    use super::{inbox_append_capability_payload, CapabilityManager, CapabilityModule};
    use crate::identity::IdentityManager;
    use crate::model::{
        CapabilityConstraints, CapabilityOperation, CapabilityService, DeploymentBundle,
        InboxAppendCapability, CURRENT_MODEL_VERSION,
    };

    const ALICE_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn sample_capability() -> InboxAppendCapability {
        InboxAppendCapability {
            version: CURRENT_MODEL_VERSION.to_string(),
            service: CapabilityService::Inbox,
            user_id: "user:alice".into(),
            target_device_id: "device:alice:phone".into(),
            endpoint: "https://example.com/v1/inbox/device/messages".into(),
            operations: vec![CapabilityOperation::Append],
            conversation_scope: vec![],
            expires_at: 1_775_004_800_000,
            constraints: Some(CapabilityConstraints {
                max_bytes: Some(256 * 1024),
                max_ops_per_minute: Some(60),
            }),
            signature: String::new(),
        }
    }

    fn payload_bytes(capability: &InboxAppendCapability) -> Vec<u8> {
        crate::model::signing::signing_payload_bytes_for_test(inbox_append_capability_payload(
            capability,
        ))
    }

    #[test]
    fn module_name_is_stable() {
        assert_eq!(CapabilityModule.name(), "capability");
    }

    /// The bug a delimiter-joined domain has, on the one pair of adjacent
    /// free-form fields: under the old `|`-joined encoding both of these
    /// produce the byte-identical string
    /// `0.1|Inbox|user:alice|b|device:alice:phone|...`, so one signature was
    /// valid for a capability naming a different device.
    #[test]
    fn capability_field_boundaries_cannot_be_shifted() {
        let mut left = sample_capability();
        left.user_id = "user:alice".into();
        left.target_device_id = "b|device:alice:phone".into();

        let mut right = sample_capability();
        right.user_id = "user:alice|b".into();
        right.target_device_id = "device:alice:phone".into();

        assert_ne!(payload_bytes(&left), payload_bytes(&right));
    }

    /// The scope list was `join(",")`, so one entry containing a comma and two
    /// entries split on it were the same bytes. It is length-prefixed per
    /// entry now.
    #[test]
    fn capability_scope_entries_cannot_be_merged() {
        let mut joined = sample_capability();
        joined.conversation_scope = vec!["conv:one,conv:two".into()];

        let mut split = sample_capability();
        split.conversation_scope = vec!["conv:one".into(), "conv:two".into()];

        assert_ne!(payload_bytes(&joined), payload_bytes(&split));
    }

    /// Unlike the two above, these three states were already distinguishable
    /// under the old encoding (`""`, `":"`, `"0:0"`). The explicit presence
    /// bytes are what keep them distinguishable now that the text formatting
    /// is gone, so the property is pinned rather than newly acquired.
    #[test]
    fn capability_absent_and_zero_constraints_differ() {
        let mut absent = sample_capability();
        absent.constraints = None;

        let mut empty = sample_capability();
        empty.constraints = Some(CapabilityConstraints {
            max_bytes: None,
            max_ops_per_minute: None,
        });

        let mut zero = sample_capability();
        zero.constraints = Some(CapabilityConstraints {
            max_bytes: Some(0),
            max_ops_per_minute: Some(0),
        });

        let encodings = [
            payload_bytes(&absent),
            payload_bytes(&empty),
            payload_bytes(&zero),
        ];
        for (index, left) in encodings.iter().enumerate() {
            for right in &encodings[index + 1..] {
                assert_ne!(left, right, "constraint states must not share an encoding");
            }
        }
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
            protocol_version: 5,
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
                keypackage_pool_base: Some("https://example.com/keypackages".into()),
                max_inline_bytes: Some(4096),
                features: vec!["generic_sync".into()],
            },
            expected_user_id: None,
            expected_device_id: None,
        }
    }
}

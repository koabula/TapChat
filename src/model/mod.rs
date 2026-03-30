use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};

pub const CURRENT_MODEL_VERSION: &str = "0.1";

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ModelModule;

impl ModelModule {
    pub fn name(&self) -> &'static str {
        "model"
    }
}

pub trait Validate {
    fn validate(&self) -> CoreResult<()>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserIdentity {
    pub version: String,
    pub user_id: String,
    pub user_public_key: String,
    pub created_at: u64,
}

impl Validate for UserIdentity {
    fn validate(&self) -> CoreResult<()> {
        validate_version(&self.version)?;
        validate_required("user_id", &self.user_id)?;
        validate_required("user_public_key", &self.user_public_key)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceBinding {
    pub version: String,
    pub user_id: String,
    pub device_id: String,
    pub device_public_key: String,
    pub created_at: u64,
    pub signature: String,
}

impl Validate for DeviceBinding {
    fn validate(&self) -> CoreResult<()> {
        validate_version(&self.version)?;
        validate_required("user_id", &self.user_id)?;
        validate_required("device_id", &self.device_id)?;
        validate_required("device_public_key", &self.device_public_key)?;
        validate_required("signature", &self.signature)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub version: String,
    pub user_id: String,
    pub device_id: String,
    pub device_public_key: String,
    pub created_at: u64,
    pub binding: DeviceBinding,
}

impl Validate for DeviceIdentity {
    fn validate(&self) -> CoreResult<()> {
        validate_version(&self.version)?;
        validate_required("user_id", &self.user_id)?;
        validate_required("device_id", &self.device_id)?;
        validate_required("device_public_key", &self.device_public_key)?;
        self.binding.validate()?;
        if self.binding.user_id != self.user_id {
            return Err(CoreError::invalid_input(
                "device binding user_id must match device identity user_id",
            ));
        }
        if self.binding.device_id != self.device_id {
            return Err(CoreError::invalid_input(
                "device binding device_id must match device identity device_id",
            ));
        }
        if self.binding.device_public_key != self.device_public_key {
            return Err(CoreError::invalid_input(
                "device binding device_public_key must match device identity device_public_key",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatusKind {
    Active,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceStatus {
    pub version: String,
    pub user_id: String,
    pub device_id: String,
    pub status: DeviceStatusKind,
    pub updated_at: u64,
}

impl Validate for DeviceStatus {
    fn validate(&self) -> CoreResult<()> {
        validate_version(&self.version)?;
        validate_required("user_id", &self.user_id)?;
        validate_required("device_id", &self.device_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CapabilityConstraints {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_ops_per_minute: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityService {
    Inbox,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityOperation {
    Append,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxAppendCapability {
    pub version: String,
    pub service: CapabilityService,
    pub user_id: String,
    pub target_device_id: String,
    pub endpoint: String,
    pub operations: Vec<CapabilityOperation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conversation_scope: Vec<String>,
    pub expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints: Option<CapabilityConstraints>,
    pub signature: String,
}

impl Validate for InboxAppendCapability {
    fn validate(&self) -> CoreResult<()> {
        validate_version(&self.version)?;
        validate_required("user_id", &self.user_id)?;
        validate_required("target_device_id", &self.target_device_id)?;
        validate_required("endpoint", &self.endpoint)?;
        validate_required("signature", &self.signature)?;
        if self.service != CapabilityService::Inbox {
            return Err(CoreError::invalid_input(
                "service must be inbox for inbox append capability",
            ));
        }
        if self.operations.is_empty() {
            return Err(CoreError::invalid_input(
                "operations must contain at least one capability operation",
            ));
        }
        if self
            .operations
            .iter()
            .any(|operation| *operation != CapabilityOperation::Append)
        {
            return Err(CoreError::invalid_input(
                "operations must only contain append",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPackageRef {
    pub version: String,
    pub user_id: String,
    pub device_id: String,
    #[serde(rename = "ref")]
    pub object_ref: String,
    pub expires_at: u64,
}

impl Validate for KeyPackageRef {
    fn validate(&self) -> CoreResult<()> {
        validate_version(&self.version)?;
        validate_required("user_id", &self.user_id)?;
        validate_required("device_id", &self.device_id)?;
        validate_required("ref", &self.object_ref)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageRef {
    pub kind: String,
    #[serde(rename = "ref")]
    pub object_ref: String,
    pub size_bytes: u64,
    pub mime_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

impl Validate for StorageRef {
    fn validate(&self) -> CoreResult<()> {
        validate_required("kind", &self.kind)?;
        validate_required("ref", &self.object_ref)?;
        validate_required("mime_type", &self.mime_type)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryClass {
    Normal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct WakeHint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_seq_hint: Option<u64>,
}

impl Validate for WakeHint {
    fn validate(&self) -> CoreResult<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceContactProfile {
    pub version: String,
    pub device_id: String,
    pub device_public_key: String,
    pub binding: DeviceBinding,
    pub status: DeviceStatusKind,
    pub inbox_append_capability: InboxAppendCapability,
    pub keypackage_ref: KeyPackageRef,
}

impl Validate for DeviceContactProfile {
    fn validate(&self) -> CoreResult<()> {
        validate_version(&self.version)?;
        validate_required("device_id", &self.device_id)?;
        validate_required("device_public_key", &self.device_public_key)?;
        self.binding.validate()?;
        if self.binding.device_id != self.device_id {
            return Err(CoreError::invalid_input(
                "device binding device_id must match device profile device_id",
            ));
        }
        if self.binding.device_public_key != self.device_public_key {
            return Err(CoreError::invalid_input(
                "device binding device_public_key must match device profile device_public_key",
            ));
        }
        self.inbox_append_capability.validate()?;
        if self.inbox_append_capability.target_device_id != self.device_id {
            return Err(CoreError::invalid_input(
                "capability target_device_id must match device profile device_id",
            ));
        }
        self.keypackage_ref.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct StorageProfile {
    // Optional shared storage access hint for platform adapters. It is metadata only and
    // must not be treated as an implicit locator for identity or device-state refresh.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    // Optional profile object reference for storage metadata. This is not an identity bundle
    // reference and must not be used as a fallback for shared-state discovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_ref: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealtimeKind {
    Websocket,
    ServerSentEvents,
    Polling,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityBundle {
    pub version: String,
    pub user_id: String,
    pub user_public_key: String,
    pub devices: Vec<DeviceContactProfile>,
    // Canonical shared-state reference for this identity bundle. Contact refresh must only
    // use this explicit reference and must not infer object locations from storage hints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_bundle_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_status_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_profile: Option<StorageProfile>,
    pub updated_at: u64,
    pub signature: String,
}

impl Validate for IdentityBundle {
    fn validate(&self) -> CoreResult<()> {
        validate_version(&self.version)?;
        validate_required("user_id", &self.user_id)?;
        validate_required("user_public_key", &self.user_public_key)?;
        validate_required("signature", &self.signature)?;
        if let Some(identity_bundle_ref) = &self.identity_bundle_ref {
            validate_required("identity_bundle_ref", identity_bundle_ref)?;
        }
        if self.devices.is_empty() {
            return Err(CoreError::invalid_input(
                "identity bundle must contain at least one device profile",
            ));
        }
        for device in &self.devices {
            device.validate()?;
            if device.binding.user_id != self.user_id {
                return Err(CoreError::invalid_input(
                    "device binding user_id must match bundle user_id",
                ));
            }
            if device.inbox_append_capability.user_id != self.user_id {
                return Err(CoreError::invalid_input(
                    "capability user_id must match bundle user_id",
                ));
            }
            if device.keypackage_ref.user_id != self.user_id {
                return Err(CoreError::invalid_input(
                    "key package ref user_id must match bundle user_id",
                ));
            }
            if device.keypackage_ref.device_id != device.device_id {
                return Err(CoreError::invalid_input(
                    "key package ref device_id must match device profile device_id",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub value: String,
}

impl Validate for SenderProof {
    fn validate(&self) -> CoreResult<()> {
        validate_required("type", &self.proof_type)?;
        validate_required("value", &self.value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageType {
    MlsApplication,
    MlsCommit,
    MlsWelcome,
    ControlDeviceMembershipChanged,
    ControlIdentityStateUpdated,
    ControlConversationNeedsRebuild,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub version: String,
    pub message_id: String,
    pub conversation_id: String,
    pub sender_user_id: String,
    pub sender_device_id: String,
    pub recipient_device_id: String,
    pub created_at: u64,
    pub message_type: MessageType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inline_ciphertext: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub storage_refs: Vec<StorageRef>,
    pub delivery_class: DeliveryClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wake_hint: Option<WakeHint>,
    pub sender_proof: SenderProof,
}

impl Validate for Envelope {
    fn validate(&self) -> CoreResult<()> {
        validate_version(&self.version)?;
        validate_required("message_id", &self.message_id)?;
        validate_required("conversation_id", &self.conversation_id)?;
        validate_required("sender_user_id", &self.sender_user_id)?;
        validate_required("sender_device_id", &self.sender_device_id)?;
        validate_required("recipient_device_id", &self.recipient_device_id)?;
        match self.delivery_class {
            DeliveryClass::Normal => {}
        }
        if let Some(wake_hint) = &self.wake_hint {
            wake_hint.validate()?;
        }
        self.sender_proof.validate()?;
        if self.inline_ciphertext.is_none() && self.storage_refs.is_empty() {
            return Err(CoreError::invalid_input(
                "envelope must include inline_ciphertext or at least one storage_ref",
            ));
        }
        if self
            .inline_ciphertext
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(CoreError::invalid_input(
                "inline_ciphertext must not be empty when provided",
            ));
        }
        for reference in &self.storage_refs {
            reference.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InboxRecordState {
    Available,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxRecord {
    pub seq: u64,
    pub recipient_device_id: String,
    pub message_id: String,
    pub received_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub state: InboxRecordState,
    pub envelope: Envelope,
}

impl Validate for InboxRecord {
    fn validate(&self) -> CoreResult<()> {
        validate_required("recipient_device_id", &self.recipient_device_id)?;
        validate_required("message_id", &self.message_id)?;
        self.envelope.validate()?;
        if self.message_id != self.envelope.message_id {
            return Err(CoreError::invalid_input(
                "inbox record message_id must match envelope message_id",
            ));
        }
        if self.recipient_device_id != self.envelope.recipient_device_id {
            return Err(CoreError::invalid_input(
                "inbox record recipient_device_id must match envelope recipient_device_id",
            ));
        }
        match self.state {
            InboxRecordState::Available => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ack {
    pub device_id: String,
    pub ack_seq: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub acked_message_ids: Vec<String>,
    pub acked_at: u64,
}

impl Validate for Ack {
    fn validate(&self) -> CoreResult<()> {
        validate_required("device_id", &self.device_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationMember {
    pub user_id: String,
    pub device_id: String,
    pub status: DeviceStatusKind,
}

impl Validate for ConversationMember {
    fn validate(&self) -> CoreResult<()> {
        validate_required("user_id", &self.user_id)?;
        validate_required("device_id", &self.device_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversationKind {
    Direct,
    Group,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversationState {
    Active,
    NeedsRebuild,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conversation {
    pub conversation_id: String,
    pub kind: ConversationKind,
    pub member_users: Vec<String>,
    pub member_devices: Vec<ConversationMember>,
    pub state: ConversationState,
    pub updated_at: u64,
}

impl Validate for Conversation {
    fn validate(&self) -> CoreResult<()> {
        validate_required("conversation_id", &self.conversation_id)?;
        if self.member_users.is_empty() {
            return Err(CoreError::invalid_input(
                "conversation must contain at least one member user",
            ));
        }
        if self.member_devices.is_empty() {
            return Err(CoreError::invalid_input(
                "conversation must contain at least one member device",
            ));
        }
        for member in &self.member_devices {
            member.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncCheckpoint {
    pub device_id: String,
    pub last_fetched_seq: u64,
    pub last_acked_seq: u64,
    pub updated_at: u64,
}

impl Validate for SyncCheckpoint {
    fn validate(&self) -> CoreResult<()> {
        validate_required("device_id", &self.device_id)?;
        if self.last_acked_seq > self.last_fetched_seq {
            return Err(CoreError::invalid_input(
                "last_acked_seq must not exceed last_fetched_seq",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MlsStateStatus {
    Active,
    NeedsRecovery,
    NeedsRebuild,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsStateSummary {
    pub conversation_id: String,
    pub epoch: u64,
    pub member_device_ids: Vec<String>,
    pub status: MlsStateStatus,
    pub updated_at: u64,
}

impl Validate for MlsStateSummary {
    fn validate(&self) -> CoreResult<()> {
        validate_required("conversation_id", &self.conversation_id)?;
        if self.member_device_ids.is_empty() {
            return Err(CoreError::invalid_input(
                "mls state summary must contain at least one member device id",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct StorageBaseInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRuntimeAuth {
    pub scheme: String,
    pub token: String,
    pub expires_at: u64,
    pub user_id: String,
    pub device_id: String,
    pub scopes: Vec<String>,
}

impl Validate for DeviceRuntimeAuth {
    fn validate(&self) -> CoreResult<()> {
        validate_required("scheme", &self.scheme)?;
        validate_required("token", &self.token)?;
        validate_required("user_id", &self.user_id)?;
        validate_required("device_id", &self.device_id)?;
        if self.scheme != "bearer" {
            return Err(CoreError::invalid_input(
                "device_runtime_auth scheme must be bearer",
            ));
        }
        if self.scopes.is_empty() {
            return Err(CoreError::invalid_input(
                "device_runtime_auth scopes must not be empty",
            ));
        }
        for scope in &self.scopes {
            validate_required("device_runtime_auth.scopes", scope)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_realtime_kinds: Vec<RealtimeKind>,
    // Optional bootstrap hint for exporting the local user's shared identity bundle.
    // It must not be used as a fallback source when refreshing a contact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_bundle_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_status_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keypackage_ref_base: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_inline_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentBundle {
    pub version: String,
    pub region: String,
    pub inbox_http_endpoint: String,
    pub inbox_websocket_endpoint: String,
    pub storage_base_info: StorageBaseInfo,
    pub runtime_config: RuntimeConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_runtime_auth: Option<DeviceRuntimeAuth>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_user_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_device_id: Option<String>,
}

impl Validate for DeploymentBundle {
    fn validate(&self) -> CoreResult<()> {
        validate_version(&self.version)?;
        validate_required("region", &self.region)?;
        validate_required("inbox_http_endpoint", &self.inbox_http_endpoint)?;
        validate_required(
            "inbox_websocket_endpoint",
            &self.inbox_websocket_endpoint,
        )?;
        validate_runtime_config(&self.runtime_config)?;
        if let Some(auth) = &self.device_runtime_auth {
            auth.validate()?;
        }
        if let Some(user_id) = &self.expected_user_id {
            validate_required("expected_user_id", user_id)?;
        }
        if let Some(device_id) = &self.expected_device_id {
            validate_required("expected_device_id", device_id)?;
        }
        Ok(())
    }
}

fn validate_required(field: &str, value: &str) -> CoreResult<()> {
    if value.trim().is_empty() {
        return Err(CoreError::invalid_input(format!(
            "{field} must not be empty"
        )));
    }
    Ok(())
}

fn validate_version(value: &str) -> CoreResult<()> {
    validate_required("version", value)?;
    if value != CURRENT_MODEL_VERSION {
        return Err(CoreError::invalid_input(format!(
            "unsupported version {value}, expected {CURRENT_MODEL_VERSION}"
        )));
    }
    Ok(())
}

fn validate_runtime_config(config: &RuntimeConfig) -> CoreResult<()> {
    if let Some(identity_bundle_ref) = &config.identity_bundle_ref {
        validate_required("runtime_config.identity_bundle_ref", identity_bundle_ref)?;
    }
    if let Some(device_status_ref) = &config.device_status_ref {
        validate_required("runtime_config.device_status_ref", device_status_ref)?;
    }
    if let Some(keypackage_ref_base) = &config.keypackage_ref_base {
        validate_required("runtime_config.keypackage_ref_base", keypackage_ref_base)?;
    }
    for feature in &config.features {
        validate_required("runtime_config.features", feature)?;
        let normalized = feature.to_ascii_lowercase();
        if normalized.contains("cloudflare")
            || normalized.contains("worker")
            || normalized.contains("durable_object")
            || normalized.contains("r2")
            || normalized.contains("bucket")
            || normalized.contains("path_template")
            || normalized.contains("route")
            || normalized.contains("storage_provider")
        {
            return Err(CoreError::invalid_input(format!(
                "runtime_config feature {feature} must remain platform-neutral"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_name_is_stable() {
        assert_eq!(ModelModule.name(), "model");
    }

    #[test]
    fn identity_bundle_round_trips_json() {
        let bundle = sample_identity_bundle();
        let json = serde_json::to_string(&bundle).expect("serialize bundle");
        let decoded: IdentityBundle =
            serde_json::from_str(&json).expect("deserialize bundle");
        assert_eq!(decoded, bundle);
    }

    #[test]
    fn envelope_round_trips_json() {
        let envelope = sample_envelope();
        let json = serde_json::to_string(&envelope).expect("serialize envelope");
        let decoded: Envelope =
            serde_json::from_str(&json).expect("deserialize envelope");
        assert_eq!(decoded, envelope);
    }

    #[test]
    fn validation_rejects_missing_required_fields() {
        let bundle = IdentityBundle {
            user_id: String::new(),
            ..sample_identity_bundle()
        };
        let error = bundle.validate().expect_err("bundle should be invalid");
        assert_eq!(error.code(), "invalid_input");
    }

    #[test]
    fn message_type_serializes_as_snake_case() {
        let json = serde_json::to_string(&MessageType::ControlIdentityStateUpdated)
            .expect("serialize enum");
        assert_eq!(json, "\"control_identity_state_updated\"");
    }

    #[test]
    fn delivery_class_serializes_as_snake_case() {
        let json = serde_json::to_string(&DeliveryClass::Normal).expect("serialize enum");
        assert_eq!(json, "\"normal\"");
    }

    #[test]
    fn conversation_kind_parses_from_snake_case() {
        let kind: ConversationKind =
            serde_json::from_str("\"direct\"").expect("deserialize enum");
        assert_eq!(kind, ConversationKind::Direct);
    }

    #[test]
    fn delivery_class_rejects_unknown_value() {
        let error = serde_json::from_str::<DeliveryClass>("\"priority\"")
            .expect_err("unknown delivery class should fail");
        assert!(error.is_data());
    }

    #[test]
    fn inbox_record_state_rejects_unknown_value() {
        let error = serde_json::from_str::<InboxRecordState>("\"deleted\"")
            .expect_err("unknown record state should fail");
        assert!(error.is_data());
    }

    #[test]
    fn validation_rejects_unsupported_version() {
        let bundle = IdentityBundle {
            version: "9.9".into(),
            ..sample_identity_bundle()
        };
        let error = bundle.validate().expect_err("bundle should reject version");
        assert_eq!(error.code(), "invalid_input");
    }

    #[test]
    fn device_identity_validation_rejects_binding_mismatch() {
        let mut device = DeviceIdentity {
            version: CURRENT_MODEL_VERSION.to_string(),
            user_id: "user:alice".into(),
            device_id: "device:alice:phone".into(),
            device_public_key: "device-pub".into(),
            created_at: 0,
            binding: DeviceBinding {
                version: CURRENT_MODEL_VERSION.to_string(),
                user_id: "user:alice".into(),
                device_id: "device:alice:laptop".into(),
                device_public_key: "device-pub".into(),
                created_at: 0,
                signature: "sig".into(),
            },
        };
        let error = device.validate().expect_err("binding mismatch should fail");
        assert_eq!(error.code(), "invalid_input");

        device.binding.device_id = device.device_id.clone();
        device.binding.device_public_key = "other-device-pub".into();
        let error = device
            .validate()
            .expect_err("device public key mismatch should fail");
        assert_eq!(error.code(), "invalid_input");
    }

    #[test]
    fn envelope_validation_rejects_empty_inline_ciphertext() {
        let mut envelope = sample_envelope();
        envelope.inline_ciphertext = Some(String::new());
        let error = envelope
            .validate()
            .expect_err("empty inline ciphertext should fail");
        assert_eq!(error.code(), "invalid_input");
    }

    #[test]
    fn inbox_record_validation_rejects_envelope_mismatch() {
        let mut record = InboxRecord {
            seq: 1,
            recipient_device_id: "device:bob:phone".into(),
            message_id: "msg:1".into(),
            received_at: 1,
            expires_at: None,
            state: InboxRecordState::Available,
            envelope: sample_envelope(),
        };
        record.envelope.recipient_device_id = "device:bob:laptop".into();
        let error = record
            .validate()
            .expect_err("recipient mismatch should fail");
        assert_eq!(error.code(), "invalid_input");
    }

    #[test]
    fn inbox_record_round_trips_json_with_state() {
        let record = InboxRecord {
            seq: 1,
            recipient_device_id: "device:bob:phone".into(),
            message_id: "msg:1".into(),
            received_at: 1,
            expires_at: Some(10),
            state: InboxRecordState::Available,
            envelope: sample_envelope(),
        };
        let json = serde_json::to_string(&record).expect("serialize record");
        let decoded: InboxRecord = serde_json::from_str(&json).expect("deserialize record");
        assert_eq!(decoded, record);
    }

    #[test]
    fn sync_checkpoint_validation_rejects_acked_past_fetched() {
        let checkpoint = SyncCheckpoint {
            device_id: "device:bob:phone".into(),
            last_fetched_seq: 2,
            last_acked_seq: 3,
            updated_at: 3,
        };
        let error = checkpoint
            .validate()
            .expect_err("acked past fetched should fail");
        assert_eq!(error.code(), "invalid_input");
    }

    #[test]
    fn deployment_bundle_validation_rejects_empty_expected_ids() {
        let bundle = DeploymentBundle {
            version: CURRENT_MODEL_VERSION.to_string(),
            region: "local".into(),
            inbox_http_endpoint: "https://example.com".into(),
            inbox_websocket_endpoint: "wss://example.com/ws".into(),
            storage_base_info: StorageBaseInfo::default(),
            runtime_config: RuntimeConfig::default(),
            device_runtime_auth: None,
            expected_user_id: Some(String::new()),
            expected_device_id: None,
        };
        let error = bundle
            .validate()
            .expect_err("empty expected_user_id should fail");
        assert_eq!(error.code(), "invalid_input");
    }

    #[test]
    fn runtime_config_rejects_platform_specific_features() {
        let bundle = DeploymentBundle {
            version: CURRENT_MODEL_VERSION.to_string(),
            region: "local".into(),
            inbox_http_endpoint: "https://example.com".into(),
            inbox_websocket_endpoint: "wss://example.com/ws".into(),
            storage_base_info: StorageBaseInfo::default(),
            runtime_config: RuntimeConfig {
                features: vec!["cloudflare_worker".into()],
                ..RuntimeConfig::default()
            },
            device_runtime_auth: None,
            expected_user_id: None,
            expected_device_id: None,
        };
        let error = bundle.validate().expect_err("platform feature should fail");
        assert_eq!(error.code(), "invalid_input");
    }

    #[test]
    fn runtime_config_rejects_unknown_fields_during_decode() {
        let error = serde_json::from_str::<RuntimeConfig>(
            r#"{"worker_route":"/v1/inbox","features":["generic_sync"]}"#,
        )
        .expect_err("unknown field should fail");
        assert!(error.is_data());
    }

    #[test]
    fn runtime_config_round_trips_with_generic_fields_only() {
        let config = RuntimeConfig {
            supported_realtime_kinds: vec![RealtimeKind::Websocket, RealtimeKind::Polling],
            identity_bundle_ref: Some("ref:identity:alice".into()),
            device_status_ref: Some("ref:device-status:alice".into()),
            keypackage_ref_base: Some("ref:keypackages:alice".into()),
            max_inline_bytes: Some(4096),
            features: vec!["generic_sync".into(), "attachment_v1".into()],
        };

        let json = serde_json::to_string(&config).expect("serialize runtime config");
        let decoded: RuntimeConfig =
            serde_json::from_str(&json).expect("deserialize runtime config");

        assert_eq!(decoded, config);
        assert!(!json.contains("cloudflare"));
        assert!(!json.contains("worker_route"));
    }

    #[test]
    fn deployment_bundle_round_trips_with_device_runtime_auth() {
        let bundle = DeploymentBundle {
            version: CURRENT_MODEL_VERSION.to_string(),
            region: "local".into(),
            inbox_http_endpoint: "https://example.com".into(),
            inbox_websocket_endpoint: "wss://example.com/ws".into(),
            storage_base_info: StorageBaseInfo::default(),
            runtime_config: RuntimeConfig::default(),
            device_runtime_auth: Some(DeviceRuntimeAuth {
                scheme: "bearer".into(),
                token: "token-1".into(),
                expires_at: 99,
                user_id: "user:alice".into(),
                device_id: "device:alice:phone".into(),
                scopes: vec![
                    "inbox_read".into(),
                    "inbox_ack".into(),
                    "inbox_subscribe".into(),
                    "storage_prepare_upload".into(),
                    "shared_state_write".into(),
                    "keypackage_write".into(),
                ],
            }),
            expected_user_id: Some("user:alice".into()),
            expected_device_id: Some("device:alice:phone".into()),
        };

        let json = serde_json::to_string(&bundle).expect("serialize deployment bundle");
        let decoded: DeploymentBundle =
            serde_json::from_str(&json).expect("deserialize deployment bundle");

        assert_eq!(decoded, bundle);
    }

    #[test]
    fn deployment_bundle_rejects_invalid_device_runtime_auth_scheme() {
        let bundle = DeploymentBundle {
            version: CURRENT_MODEL_VERSION.to_string(),
            region: "local".into(),
            inbox_http_endpoint: "https://example.com".into(),
            inbox_websocket_endpoint: "wss://example.com/ws".into(),
            storage_base_info: StorageBaseInfo::default(),
            runtime_config: RuntimeConfig::default(),
            device_runtime_auth: Some(DeviceRuntimeAuth {
                scheme: "mac".into(),
                token: "token-1".into(),
                expires_at: 99,
                user_id: "user:alice".into(),
                device_id: "device:alice:phone".into(),
                scopes: vec!["inbox_read".into()],
            }),
            expected_user_id: None,
            expected_device_id: None,
        };

        let error = bundle
            .validate()
            .expect_err("invalid auth scheme should fail");
        assert_eq!(error.code(), "invalid_input");
    }

    fn sample_identity_bundle() -> IdentityBundle {
        IdentityBundle {
            version: CURRENT_MODEL_VERSION.to_string(),
            user_id: "user:alice".into(),
            user_public_key: "alice-pub".into(),
            devices: vec![DeviceContactProfile {
                version: CURRENT_MODEL_VERSION.to_string(),
                device_id: "device:alice:phone".into(),
                device_public_key: "device-pub".into(),
                binding: DeviceBinding {
                    version: CURRENT_MODEL_VERSION.to_string(),
                    user_id: "user:alice".into(),
                    device_id: "device:alice:phone".into(),
                    device_public_key: "device-pub".into(),
                    created_at: 1,
                    signature: "binding-sig".into(),
                },
                status: DeviceStatusKind::Active,
                inbox_append_capability: InboxAppendCapability {
                    version: CURRENT_MODEL_VERSION.to_string(),
                    service: CapabilityService::Inbox,
                    user_id: "user:alice".into(),
                    target_device_id: "device:alice:phone".into(),
                    endpoint: "https://example.com/inbox".into(),
                    operations: vec![CapabilityOperation::Append],
                    conversation_scope: vec!["conv:alice-bob".into()],
                    expires_at: 999,
                    constraints: Some(CapabilityConstraints {
                        max_bytes: Some(4096),
                        max_ops_per_minute: Some(60),
                    }),
                    signature: "cap-sig".into(),
                },
                keypackage_ref: KeyPackageRef {
                    version: CURRENT_MODEL_VERSION.to_string(),
                    user_id: "user:alice".into(),
                    device_id: "device:alice:phone".into(),
                    object_ref: "s3://keypackages/alice-phone".into(),
                    expires_at: 999,
                },
            }],
            identity_bundle_ref: Some("https://storage.example.com/state/user:alice/identity_bundle.json".into()),
            device_status_ref: Some("s3://state/device_status.json".into()),
            storage_profile: Some(StorageProfile {
                base_url: Some("https://storage.example.com".into()),
                profile_ref: Some("s3://state/storage_profile.json".into()),
            }),
            updated_at: 2,
            signature: "bundle-sig".into(),
        }
    }

    fn sample_envelope() -> Envelope {
        Envelope {
            version: CURRENT_MODEL_VERSION.to_string(),
            message_id: "msg:1".into(),
            conversation_id: "conv:alice-bob".into(),
            sender_user_id: "user:alice".into(),
            sender_device_id: "device:alice:phone".into(),
            recipient_device_id: "device:bob:phone".into(),
            created_at: 3,
            message_type: MessageType::MlsApplication,
            inline_ciphertext: Some("ciphertext".into()),
            storage_refs: vec![],
            delivery_class: DeliveryClass::Normal,
            wake_hint: Some(WakeHint {
                latest_seq_hint: Some(3),
            }),
            sender_proof: SenderProof {
                proof_type: "signature".into(),
                value: "proof".into(),
            },
        }
    }
}

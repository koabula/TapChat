use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::model::{
    Ack, Envelope, GroupCapability, GroupCursor, GroupEnvelope, GroupInviteDocument,
    GroupJoinRequest, GroupManifest, GroupOutboxRecord, IdentityBundle, InboxRecord,
    WelcomePickupDescriptor,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppendEnvelopeRequest {
    pub version: String,
    pub recipient_device_id: String,
    pub envelope: Envelope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_bundle_share_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_bundle_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppendDeliveryDisposition {
    Inbox,
    MessageRequest,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageRequestRealtimeChange {
    Queued,
    Accepted,
    Rejected,
}

impl Default for AppendDeliveryDisposition {
    fn default() -> Self {
        Self::Inbox
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppendEnvelopeResult {
    pub accepted: bool,
    pub seq: u64,
    #[serde(default)]
    pub delivered_to: AppendDeliveryDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued_as_request: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchMessagesRequest {
    pub device_id: String,
    pub from_seq: u64,
    pub limit: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchMessagesResult {
    pub to_seq: u64,
    pub records: Vec<InboxRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AckRequest {
    pub ack: Ack,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AckResult {
    pub accepted: bool,
    pub ack_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetHeadRequest {
    pub device_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetHeadResult {
    pub head_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealtimeSubscriptionRequest {
    pub device_id: String,
    pub endpoint: String,
    pub last_acked_seq: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppendGroupEnvelopeRequest {
    pub version: String,
    pub group_id: String,
    pub envelope: GroupEnvelope,
    pub capability: GroupCapability,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppendGroupEnvelopeResult {
    pub accepted: bool,
    pub seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchGroupOutboxRequest {
    pub group_id: String,
    pub from_seq: u64,
    pub limit: u64,
    pub capability: GroupCapability,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchGroupOutboxResult {
    pub to_seq: u64,
    pub records: Vec<GroupOutboxRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetGroupOutboxHeadRequest {
    pub group_id: String,
    pub capability: GroupCapability,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetGroupOutboxHeadResult {
    pub head_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupRealtimeSubscriptionRequest {
    pub group_id: String,
    pub endpoint: String,
    pub last_seq: u64,
    pub capability: GroupCapability,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchWelcomePickupRequest {
    pub descriptor: WelcomePickupDescriptor,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchWelcomePickupResult {
    pub welcome_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<GroupManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutWelcomePickupRequest {
    pub descriptor: WelcomePickupDescriptor,
    pub welcome_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<GroupManifest>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutWelcomePickupResult {
    pub accepted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateGroupInviteRequest {
    pub version: String,
    pub group_id: String,
    pub document: GroupInviteDocument,
    pub capability: GroupCapability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateGroupInviteResult {
    pub invite_url: String,
    pub invite: GroupInviteDocument,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeGroupInviteRequest {
    pub version: String,
    pub group_id: String,
    pub invite_id: String,
    pub capability: GroupCapability,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeGroupInviteResult {
    pub accepted: bool,
    pub invite_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchGroupInviteRequest {
    pub invite_url: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchGroupInviteResult {
    pub invite: GroupInviteDocument,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitGroupJoinRequest {
    pub version: String,
    pub invite_token: String,
    pub request: GroupJoinRequest,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitGroupJoinResult {
    pub accepted: bool,
    pub request: GroupJoinRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_approve: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListGroupJoinRequestsRequest {
    pub group_id: String,
    pub capability: GroupCapability,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListGroupJoinRequestsResult {
    pub requests: Vec<GroupJoinRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetGroupJoinRequestStatusRequest {
    pub group_id: String,
    pub request_id: String,
    pub request_capability: String,
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetGroupJoinRequestStatusResult {
    pub request: GroupJoinRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub welcome_pickup: Option<WelcomePickupDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<GroupManifest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_cursor: Option<GroupCursor>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupJoinDecision {
    Approve,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecideGroupJoinRequest {
    pub version: String,
    pub group_id: String,
    pub request_id: String,
    pub decision: GroupJoinDecision,
    pub capability: GroupCapability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub welcome_pickup: Option<WelcomePickupDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<GroupManifest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_cursor: Option<GroupCursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecideGroupJoinResult {
    pub accepted: bool,
    pub request: GroupJoinRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrepareBlobUploadRequest {
    pub task_id: String,
    pub conversation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_scope: Option<String>,
    pub message_id: String,
    pub mime_type: String,
    pub size_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrepareBlobUploadResult {
    pub blob_ref: String,
    pub upload_target: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub upload_headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobUploadRequest {
    pub task_id: String,
    pub blob_ciphertext_b64: String,
    pub upload_target: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub upload_headers: BTreeMap<String, String>,
    pub blob_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobDownloadRequest {
    pub task_id: String,
    pub blob_ref: String,
    pub download_target: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub download_headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchIdentityBundleRequest {
    pub user_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchIdentityBundleResult {
    pub bundle: IdentityBundle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageRequestItem {
    pub request_id: String,
    pub recipient_device_id: String,
    pub sender_user_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_bundle_share_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_bundle_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_display_name: Option<String>,
    pub first_seen_at: u64,
    pub last_seen_at: u64,
    pub message_count: u64,
    pub last_message_id: String,
    pub last_conversation_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchMessageRequestsRequest {
    pub device_id: String,
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchMessageRequestsResult {
    pub requests: Vec<MessageRequestItem>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageRequestAction {
    Accept,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageRequestActionRequest {
    pub device_id: String,
    pub request_id: String,
    pub action: MessageRequestAction,
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageRequestActionResult {
    pub accepted: bool,
    pub request_id: String,
    pub sender_user_id: String,
    pub promoted_count: u64,
    pub action: MessageRequestAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_bundle_share_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_bundle_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowlistDocument {
    pub allowed_sender_user_ids: Vec<String>,
    pub rejected_sender_user_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchAllowlistRequest {
    pub device_id: String,
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplaceAllowlistRequest {
    pub device_id: String,
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    pub document: AllowlistDocument,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SharedStateDocumentKind {
    IdentityBundle,
    DeviceStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceStatusRecord {
    pub version: String,
    pub user_id: String,
    pub device_id: String,
    pub status: crate::model::DeviceStatusKind,
    pub updated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceStatusDocument {
    pub version: String,
    pub user_id: String,
    pub updated_at: u64,
    pub devices: Vec<DeviceStatusRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishSharedStateRequest {
    pub reference: String,
    pub document_kind: SharedStateDocumentKind,
    pub body: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        CapabilityService, DeliveryClass, GroupCapability, GroupCapabilityOperation, GroupEnvelope,
        GroupEnvelopeVisibility, GroupMessageType, GroupOutboxRecord, GroupOutboxRecordState,
        GroupRole, MessageType, SenderProof, StorageRef, WelcomePickupDescriptor,
        CURRENT_MODEL_VERSION,
    };

    #[test]
    fn contract_types_round_trip_without_platform_fields() {
        let append = AppendEnvelopeRequest {
            version: CURRENT_MODEL_VERSION.to_string(),
            recipient_device_id: "device:bob:phone".into(),
            envelope: Envelope {
                version: CURRENT_MODEL_VERSION.to_string(),
                message_id: "msg:1".into(),
                conversation_id: "conv:alice:bob".into(),
                sender_user_id: "user:alice".into(),
                sender_device_id: "device:alice:phone".into(),
                recipient_device_id: "device:bob:phone".into(),
                created_at: 1,
                message_type: MessageType::MlsApplication,
                inline_ciphertext: Some("cipher".into()),
                storage_refs: vec![StorageRef {
                    kind: "attachment".into(),
                    object_ref: "blob:1".into(),
                    size_bytes: 1,
                    mime_type: "application/octet-stream".into(),
                    file_name: None,
                    expires_at: Some(10),
                }],
                delivery_class: DeliveryClass::Normal,
                wake_hint: None,
                sender_proof: SenderProof {
                    proof_type: "signature".into(),
                    value: "proof".into(),
                },
            },
            sender_bundle_share_url: None,
            sender_bundle_hash: None,
            sender_display_name: None,
        };
        let json = serde_json::to_string(&append).expect("serialize");
        assert!(!json.contains("cloudflare"));
        assert!(!json.contains("worker"));
        let decoded: AppendEnvelopeRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.recipient_device_id, "device:bob:phone");
    }

    #[test]
    fn append_result_round_trips_policy_outcome() {
        let result = AppendEnvelopeResult {
            accepted: true,
            seq: 0,
            delivered_to: AppendDeliveryDisposition::MessageRequest,
            queued_as_request: Some(true),
            request_id: Some("request:user:alice".into()),
        };

        let json = serde_json::to_string(&result).expect("serialize");
        let decoded: AppendEnvelopeResult = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(
            decoded.delivered_to,
            AppendDeliveryDisposition::MessageRequest
        );
        assert_eq!(decoded.queued_as_request, Some(true));
        assert_eq!(decoded.request_id.as_deref(), Some("request:user:alice"));
    }

    #[test]
    fn management_contract_types_round_trip_without_platform_fields() {
        let request = ReplaceAllowlistRequest {
            device_id: "device:bob:phone".into(),
            endpoint: "https://transport.example/v1/inbox/device%3Abob%3Aphone/allowlist".into(),
            headers: BTreeMap::from([("Authorization".into(), "Bearer token".into())]),
            document: AllowlistDocument {
                allowed_sender_user_ids: vec!["user:alice".into()],
                rejected_sender_user_ids: vec!["user:mallory".into()],
            },
        };

        let json = serde_json::to_string(&request).expect("serialize");
        assert!(!json.contains("cloudflare"));
        assert!(!json.contains("durable"));

        let decoded: ReplaceAllowlistRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.document.allowed_sender_user_ids, vec!["user:alice"]);
    }

    #[test]
    fn group_transport_contract_types_round_trip() {
        let append = AppendGroupEnvelopeRequest {
            version: CURRENT_MODEL_VERSION.to_string(),
            group_id: "group:project".into(),
            envelope: sample_group_envelope(),
            capability: sample_group_capability(),
        };
        let json = serde_json::to_string(&append).expect("serialize append");
        let decoded: AppendGroupEnvelopeRequest =
            serde_json::from_str(&json).expect("deserialize append");
        assert_eq!(decoded, append);

        let fetch = FetchGroupOutboxResult {
            to_seq: 7,
            records: vec![GroupOutboxRecord {
                seq: 7,
                group_id: "group:project".into(),
                message_id: "msg:group:1".into(),
                received_at: 10,
                expires_at: None,
                state: GroupOutboxRecordState::Available,
                envelope: sample_group_envelope(),
            }],
        };
        let json = serde_json::to_string(&fetch).expect("serialize fetch");
        let decoded: FetchGroupOutboxResult =
            serde_json::from_str(&json).expect("deserialize fetch");
        assert_eq!(decoded, fetch);

        let pickup = PutWelcomePickupRequest {
            descriptor: WelcomePickupDescriptor {
                group_id: "group:project".into(),
                device_id: "device:bob:phone".into(),
                endpoint: "https://example.com/welcome/group%3Aproject/device%3Abob%3Aphone".into(),
                capability: "cap:welcome:1".into(),
                expires_at: 99,
            },
            welcome_b64: "d2VsY29tZQ==".into(),
            manifest: None,
            headers: BTreeMap::new(),
        };
        let json = serde_json::to_string(&pickup).expect("serialize welcome");
        let decoded: PutWelcomePickupRequest =
            serde_json::from_str(&json).expect("deserialize welcome");
        assert_eq!(decoded, pickup);
    }

    fn sample_group_capability() -> GroupCapability {
        GroupCapability {
            version: CURRENT_MODEL_VERSION.to_string(),
            service: CapabilityService::GroupOutbox,
            group_id: "group:project".into(),
            user_id: "user:alice".into(),
            device_id: "device:alice:phone".into(),
            operations: vec![
                GroupCapabilityOperation::Read,
                GroupCapabilityOperation::AppendApplication,
            ],
            role: GroupRole::Owner,
            expires_at: 999,
            signature: "cap-sig".into(),
        }
    }

    fn sample_group_envelope() -> GroupEnvelope {
        GroupEnvelope {
            version: CURRENT_MODEL_VERSION.to_string(),
            message_id: "msg:group:1".into(),
            group_id: "group:project".into(),
            conversation_id: "conv:group:project".into(),
            sender_user_id: "user:alice".into(),
            sender_device_id: "device:alice:phone".into(),
            created_at: 9,
            message_type: GroupMessageType::MlsApplication,
            visibility: GroupEnvelopeVisibility::Visible,
            inline_ciphertext: Some("ciphertext".into()),
            storage_refs: vec![],
            sender_proof: SenderProof {
                proof_type: "signature".into(),
                value: "proof".into(),
            },
            membership_proof: Some(SenderProof {
                proof_type: "membership".into(),
                value: "member-proof".into(),
            }),
        }
    }
}

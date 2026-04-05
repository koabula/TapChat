use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::model::{Ack, Envelope, IdentityBundle, InboxRecord};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppendEnvelopeRequest {
    pub version: String,
    pub recipient_device_id: String,
    pub envelope: Envelope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppendDeliveryDisposition {
    Inbox,
    MessageRequest,
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
pub struct PrepareBlobUploadRequest {
    pub task_id: String,
    pub conversation_id: String,
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
        CURRENT_MODEL_VERSION, DeliveryClass, MessageType, SenderProof, StorageRef,
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
                    expires_at: Some(10),
                }],
                delivery_class: DeliveryClass::Normal,
                wake_hint: None,
                sender_proof: SenderProof {
                    proof_type: "signature".into(),
                    value: "proof".into(),
                },
            },
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

        assert_eq!(decoded.delivered_to, AppendDeliveryDisposition::MessageRequest);
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
}

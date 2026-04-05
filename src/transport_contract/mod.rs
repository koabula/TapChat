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
pub struct AppendEnvelopeResult {
    pub accepted: bool,
    pub seq: u64,
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
}

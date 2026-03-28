use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::conversation::{ConversationManager, LocalConversationState};
use crate::error::{CoreError, CoreResult};
use crate::identity::{IdentityManager, LocalIdentityState};
use crate::mls_adapter::{IngestResult, MlsAdapter, PeerDeviceKeyPackage, PublishedKeyPackage};
use crate::model::{
    ConversationKind, ConversationState, DeploymentBundle, Envelope, IdentityBundle, InboxRecord,
    MessageType, MlsStateSummary, SenderProof,
};
use crate::sync_engine::{DeviceSyncState, SyncEngine};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FfiApiModule;
impl FfiApiModule {
    pub fn name(&self) -> &'static str {
        "ffi_api"
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CoreCommand {
    CreateOrLoadIdentity { mnemonic: Option<String>, device_name: Option<String> },
    ImportDeploymentBundle { bundle: DeploymentBundle },
    ImportIdentityBundle { bundle: IdentityBundle },
    CreateConversation { peer_user_id: String, conversation_kind: ConversationKind },
    SendTextMessage { conversation_id: String, plaintext: String },
    SendAttachmentMessage { conversation_id: String, attachment_descriptor: AttachmentDescriptor },
    SyncInbox { device_id: String, reason: Option<String> },
    RefreshIdentityState { user_id: String },
    RebuildConversation { conversation_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CoreEvent {
    AppStarted,
    AppForegrounded,
    WebSocketConnected { device_id: String },
    WebSocketDisconnected { device_id: String, reason: Option<String> },
    WakeupReceived { device_id: String, latest_seq_hint: Option<u64> },
    InboxRecordsFetched { device_id: String, records: Vec<InboxRecord>, to_seq: u64 },
    HttpResponseReceived { request_id: String, status: u16, body: Option<String> },
    BlobUploaded { task_id: String, reference: String },
    BlobDownloaded { task_id: String, destination: String },
    TimerTriggered { timer_id: String },
    UserConfirmedRebuild { conversation_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentDescriptor {
    pub source: String,
    pub mime_type: String,
    pub size_bytes: u64,
    pub file_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequestEffect {
    pub request_id: String,
    pub method: HttpMethod,
    pub url: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealtimeConnectionEffect {
    pub device_id: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobTransferEffect {
    pub task_id: String,
    pub source: String,
    pub target: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistStateEffect {
    pub operations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimerEffect {
    pub timer_id: String,
    pub delay_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserNotificationEffect {
    pub status: SystemStatus,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CoreEffect {
    ExecuteHttpRequest { request: HttpRequestEffect },
    OpenRealtimeConnection { connection: RealtimeConnectionEffect },
    CloseRealtimeConnection { device_id: String },
    UploadBlob { transfer: BlobTransferEffect },
    DownloadBlob { transfer: BlobTransferEffect },
    PersistState { persist: PersistStateEffect },
    ScheduleTimer { timer: TimerEffect },
    EmitUserNotification { notification: UserNotificationEffect },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemStatus {
    SyncInProgress,
    IdentityRefreshNeeded,
    ConversationNeedsRebuild,
    AttachmentUploadFailed,
    TemporaryNetworkFailure,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CoreStateUpdate {
    #[serde(default)]
    pub conversations_changed: bool,
    #[serde(default)]
    pub messages_changed: bool,
    #[serde(default)]
    pub contacts_changed: bool,
    #[serde(default)]
    pub checkpoints_changed: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub system_statuses_changed: Vec<SystemStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationSummary {
    pub conversation_id: String,
    pub state: String,
    pub last_message_type: Option<MessageType>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageSummary {
    pub conversation_id: String,
    pub message_id: String,
    pub message_type: MessageType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactSummary {
    pub user_id: String,
    pub device_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemBanner {
    pub status: SystemStatus,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CoreViewModel {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conversations: Vec<ConversationSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub messages: Vec<MessageSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contacts: Vec<ContactSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub banners: Vec<SystemBanner>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CoreOutput {
    #[serde(default)]
    pub state_update: CoreStateUpdate,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effects: Vec<CoreEffect>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view_model: Option<CoreViewModel>,
}

#[derive(Debug)]
struct CoreState {
    local_identity: Option<LocalIdentityState>,
    deployment_bundle: Option<DeploymentBundle>,
    contacts: BTreeMap<String, IdentityBundle>,
    conversations: BTreeMap<String, LocalConversationState>,
    sync_states: BTreeMap<String, DeviceSyncState>,
    outbox: Vec<Envelope>,
    mls_adapter: Option<MlsAdapter>,
    mls_summaries: BTreeMap<String, MlsStateSummary>,
    published_key_package: Option<PublishedKeyPackage>,
}

impl Default for CoreState {
    fn default() -> Self {
        Self {
            local_identity: None,
            deployment_bundle: None,
            contacts: BTreeMap::new(),
            conversations: BTreeMap::new(),
            sync_states: BTreeMap::new(),
            outbox: Vec::new(),
            mls_adapter: None,
            mls_summaries: BTreeMap::new(),
            published_key_package: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct CoreEngine {
    state: CoreState,
}

impl CoreEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn handle_command(&mut self, command: CoreCommand) -> CoreResult<CoreOutput> {
        match command {
            CoreCommand::CreateOrLoadIdentity { mnemonic, device_name } => self.create_or_load_identity(mnemonic, device_name),
            CoreCommand::ImportDeploymentBundle { bundle } => {
                bundle.validate()?;
                self.state.deployment_bundle = Some(bundle);
                Ok(output_with_persist(vec!["save_deployment_bundle"]))
            }
            CoreCommand::ImportIdentityBundle { bundle } => {
                IdentityManager::verify_identity_bundle(&bundle)?;
                self.state.contacts.insert(bundle.user_id.clone(), bundle);
                Ok(CoreOutput {
                    state_update: CoreStateUpdate { contacts_changed: true, ..CoreStateUpdate::default() },
                    effects: vec![persist_effect(vec!["save_identity_bundle", "save_contact_keypackage_ref"])],
                    view_model: None,
                })
            }
            CoreCommand::CreateConversation { peer_user_id, conversation_kind } => self.create_conversation(peer_user_id, conversation_kind),
            CoreCommand::SendTextMessage { conversation_id, plaintext } => self.send_text_message(conversation_id, plaintext),
            CoreCommand::SyncInbox { device_id, .. } => {
                if device_id.trim().is_empty() {
                    return Err(CoreError::invalid_input("device_id must not be empty"));
                }
                Ok(CoreOutput {
                    state_update: CoreStateUpdate {
                        checkpoints_changed: true,
                        system_statuses_changed: vec![SystemStatus::SyncInProgress],
                        ..CoreStateUpdate::default()
                    },
                    effects: vec![CoreEffect::ScheduleTimer { timer: TimerEffect { timer_id: format!("sync:{device_id}"), delay_ms: 0 } }],
                    view_model: None,
                })
            }
            _ => Ok(CoreOutput::default()),
        }
    }

    pub fn handle_event(&mut self, event: CoreEvent) -> CoreResult<CoreOutput> {
        match event {
            CoreEvent::WakeupReceived { device_id, .. } => {
                if device_id.trim().is_empty() {
                    return Err(CoreError::invalid_input("device_id must not be empty"));
                }
                Ok(CoreOutput {
                    state_update: CoreStateUpdate {
                        checkpoints_changed: true,
                        system_statuses_changed: vec![SystemStatus::SyncInProgress],
                        ..CoreStateUpdate::default()
                    },
                    effects: vec![CoreEffect::ScheduleTimer { timer: TimerEffect { timer_id: format!("sync_after_wakeup:{device_id}"), delay_ms: 0 } }],
                    view_model: None,
                })
            }
            CoreEvent::InboxRecordsFetched { device_id, records, to_seq } => self.handle_inbox_records(device_id, records, to_seq),
            _ => Ok(CoreOutput::default()),
        }
    }

    fn create_or_load_identity(
        &mut self,
        mnemonic: Option<String>,
        device_name: Option<String>,
    ) -> CoreResult<CoreOutput> {
        let identity = IdentityManager::create_or_recover(mnemonic.as_deref(), device_name.as_deref())?;
        let (adapter, package) = MlsAdapter::bootstrap(&identity)?;
        let user_id = identity.user_identity.user_id.clone();
        let device_id = identity.device_identity.device_id.clone();
        self.state.local_identity = Some(identity);
        self.state.mls_adapter = Some(adapter);
        self.state.published_key_package = Some(package);
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                checkpoints_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(vec!["save_local_identity", "save_local_device_identity", "save_local_key_package"])],
            view_model: Some(CoreViewModel {
                contacts: vec![ContactSummary { user_id, device_count: 1 }],
                banners: vec![SystemBanner {
                    status: SystemStatus::IdentityRefreshNeeded,
                    message: format!("local identity ready for {device_id}"),
                }],
                ..CoreViewModel::default()
            }),
        })
    }

    fn create_conversation(&mut self, peer_user_id: String, conversation_kind: ConversationKind) -> CoreResult<CoreOutput> {
        if conversation_kind != ConversationKind::Direct {
            return Err(CoreError::unsupported("phase 5 only supports direct conversations"));
        }
        let local_identity = self.state.local_identity.as_ref().ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?;
        let contact_bundle = self.state.contacts.get(&peer_user_id).ok_or_else(|| CoreError::invalid_input("peer identity bundle has not been imported"))?;
        let peer_device_ids: Vec<String> = contact_bundle.devices.iter().filter(|d| matches!(d.status, crate::model::DeviceStatusKind::Active)).map(|d| d.device_id.clone()).collect();
        let local_conversation = ConversationManager::create_direct_conversation(
            &local_identity.user_identity.user_id,
            &local_identity.device_identity.device_id,
            &peer_user_id,
            &peer_device_ids,
        )?;
        let conversation_id = local_conversation.conversation.conversation_id.clone();
        let peer_keypackages: Vec<PeerDeviceKeyPackage> = contact_bundle.devices.iter().filter(|d| matches!(d.status, crate::model::DeviceStatusKind::Active)).map(|device| PeerDeviceKeyPackage {
            user_id: peer_user_id.clone(),
            device_id: device.device_id.clone(),
            device_public_key: device.device_public_key.clone(),
            key_package_b64: device.keypackage_ref.object_ref.clone(),
        }).collect();
        let artifacts = self.state.mls_adapter.as_mut().ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?.create_conversation(&conversation_id, &peer_keypackages)?;
        let summary = self.state.mls_adapter.as_ref().ok_or_else(|| CoreError::invalid_state("mls adapter missing after create"))?.export_group_summary(&conversation_id)?;
        self.state.mls_summaries.insert(conversation_id.clone(), summary);
        self.state.conversations.insert(conversation_id.clone(), local_conversation);

        let mut generated = Vec::new();
        for device_id in &peer_device_ids {
            generated.push(self.build_envelope(&conversation_id, device_id, MessageType::MlsCommit, artifacts.commit_b64.clone())?);
        }
        for welcome in &artifacts.welcomes {
            generated.push(self.build_envelope(&conversation_id, &welcome.recipient_device_id, MessageType::MlsWelcome, welcome.payload_b64.clone())?);
        }
        self.state.outbox.extend(generated.clone());
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                conversations_changed: true,
                messages_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(vec!["save_conversation", "save_mls_group_state", "queue_conversation_bootstrap_messages"])],
            view_model: Some(CoreViewModel {
                conversations: vec![ConversationSummary { conversation_id, state: "active".into(), last_message_type: Some(MessageType::MlsCommit) }],
                messages: generated.iter().map(|envelope| MessageSummary {
                    conversation_id: envelope.conversation_id.clone(),
                    message_id: envelope.message_id.clone(),
                    message_type: envelope.message_type,
                }).collect(),
                ..CoreViewModel::default()
            }),
        })
    }

    fn send_text_message(&mut self, conversation_id: String, plaintext: String) -> CoreResult<CoreOutput> {
        if conversation_id.trim().is_empty() {
            return Err(CoreError::invalid_input("conversation_id must not be empty"));
        }
        if plaintext.trim().is_empty() {
            return Err(CoreError::invalid_input("plaintext must not be empty"));
        }
        let payload = self.state.mls_adapter.as_mut().ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?.encrypt_application(&conversation_id, plaintext.as_bytes())?;
        let local_user_id = self.state.local_identity.as_ref().ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?.user_identity.user_id.clone();
        let recipient_device_ids: Vec<String> = self.state.conversations.get(&conversation_id).ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?.conversation.member_devices.iter().filter(|member| member.user_id != local_user_id).map(|member| member.device_id.clone()).collect();
        let new_envelopes: Vec<Envelope> = recipient_device_ids.iter().map(|device_id| self.build_envelope(&conversation_id, device_id, MessageType::MlsApplication, payload.payload_b64.clone())).collect::<CoreResult<Vec<_>>>()?;
        self.state.outbox.extend(new_envelopes.clone());
        Ok(CoreOutput {
            state_update: CoreStateUpdate { messages_changed: true, ..CoreStateUpdate::default() },
            effects: vec![persist_effect(vec!["queue_outgoing_text_message", "save_mls_group_state"])],
            view_model: Some(CoreViewModel {
                messages: new_envelopes.iter().map(|envelope| MessageSummary {
                    conversation_id: envelope.conversation_id.clone(),
                    message_id: envelope.message_id.clone(),
                    message_type: envelope.message_type,
                }).collect(),
                ..CoreViewModel::default()
            }),
        })
    }

    fn handle_inbox_records(&mut self, device_id: String, records: Vec<InboxRecord>, to_seq: u64) -> CoreResult<CoreOutput> {
        let sync_state = self.state.sync_states.entry(device_id.clone()).or_insert_with(|| SyncEngine::new_device_state(&device_id));
        for record in &records {
            record.validate()?;
        }
        let fresh_records = SyncEngine::register_fetch(sync_state, &records, to_seq);
        let ack = SyncEngine::ack_up_to(sync_state, sync_state.checkpoint.last_fetched_seq);
        let mut state_update = CoreStateUpdate { checkpoints_changed: true, ..CoreStateUpdate::default() };
        let mut persist_ops = vec!["ingest_inbox_records".into(), "save_sync_checkpoint".into()];
        let mut view_model = CoreViewModel::default();
        let local_user_id = self.state.local_identity.as_ref().map(|i| i.user_identity.user_id.clone()).unwrap_or_else(|| "user:local".into());

        for record in fresh_records {
            let conversation_id = record.envelope.conversation_id.clone();
            let conversation_state = self.state.conversations.entry(conversation_id.clone()).or_insert_with(|| LocalConversationState {
                conversation: crate::model::Conversation {
                    conversation_id: conversation_id.clone(),
                    kind: ConversationKind::Direct,
                    member_users: vec![record.envelope.sender_user_id.clone(), local_user_id.clone()],
                    member_devices: vec![
                        crate::model::ConversationMember {
                            user_id: record.envelope.sender_user_id.clone(),
                            device_id: record.envelope.sender_device_id.clone(),
                            status: crate::model::DeviceStatusKind::Active,
                        },
                        crate::model::ConversationMember {
                            user_id: local_user_id.clone(),
                            device_id: device_id.clone(),
                            status: crate::model::DeviceStatusKind::Active,
                        },
                    ],
                    state: ConversationState::Active,
                    updated_at: record.envelope.created_at,
                },
                messages: Vec::new(),
                last_message_type: None,
            });
            match record.envelope.message_type {
                MessageType::MlsApplication | MessageType::MlsCommit | MessageType::MlsWelcome => {
                    let payload = record.envelope.inline_ciphertext.as_deref().ok_or_else(|| CoreError::invalid_input("MLS envelope payload missing"))?;
                    let result = self.state.mls_adapter.as_mut().ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?.ingest_message(&conversation_id, &record.envelope.sender_device_id, record.envelope.message_type, payload)?;
                    match result {
                        IngestResult::AppliedApplication(_) => {
                            let _ = ConversationManager::apply_incoming_envelope(conversation_state, &record.envelope)?;
                            state_update.messages_changed = true;
                            state_update.conversations_changed = true;
                        }
                        IngestResult::AppliedCommit { .. } | IngestResult::AppliedWelcome { .. } => {
                            state_update.conversations_changed = true;
                            persist_ops.push("save_mls_group_state".into());
                        }
                        IngestResult::PendingRetry => state_update.system_statuses_changed.push(SystemStatus::SyncInProgress),
                        IngestResult::NeedsRebuild => {
                            conversation_state.conversation.state = ConversationState::NeedsRebuild;
                            state_update.conversations_changed = true;
                            state_update.system_statuses_changed.push(SystemStatus::ConversationNeedsRebuild);
                        }
                    }
                    if let Some(summary) = self.state.mls_adapter.as_ref().and_then(|adapter| adapter.export_group_summary(&conversation_id).ok()) {
                        self.state.mls_summaries.insert(conversation_id.clone(), summary);
                    }
                }
                _ => {
                    let effect = ConversationManager::apply_incoming_envelope(conversation_state, &record.envelope)?;
                    state_update.messages_changed = true;
                    state_update.conversations_changed = true;
                    if effect.identity_refresh_needed {
                        state_update.contacts_changed = true;
                        state_update.system_statuses_changed.push(SystemStatus::IdentityRefreshNeeded);
                    }
                    if effect.needs_rebuild {
                        state_update.system_statuses_changed.push(SystemStatus::ConversationNeedsRebuild);
                    }
                }
            }

            view_model.messages.push(MessageSummary {
                conversation_id: conversation_id.clone(),
                message_id: record.message_id.clone(),
                message_type: record.envelope.message_type,
            });
            view_model.conversations.push(ConversationSummary {
                conversation_id: conversation_id.clone(),
                state: match conversation_state.conversation.state {
                    ConversationState::Active => "active".into(),
                    ConversationState::NeedsRebuild => "needs_rebuild".into(),
                },
                last_message_type: conversation_state.last_message_type,
            });
        }

        if ack.ack_seq > 0 {
            persist_ops.push("save_inbox_ack".into());
        }
        Ok(CoreOutput {
            state_update,
            effects: vec![CoreEffect::PersistState { persist: PersistStateEffect { operations: persist_ops } }],
            view_model: Some(view_model),
        })
    }

    fn build_envelope(&self, conversation_id: &str, recipient_device_id: &str, message_type: MessageType, payload_b64: String) -> CoreResult<Envelope> {
        let identity = self.state.local_identity.as_ref().ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?;
        Ok(Envelope {
            version: crate::model::CURRENT_MODEL_VERSION.to_string(),
            message_id: format!("msg:{}:{}:{}", conversation_id, self.state.outbox.len() + 1, recipient_device_id),
            conversation_id: conversation_id.to_string(),
            sender_user_id: identity.user_identity.user_id.clone(),
            sender_device_id: identity.device_identity.device_id.clone(),
            recipient_device_id: recipient_device_id.to_string(),
            created_at: (self.state.outbox.len() + 1) as u64,
            message_type,
            inline_ciphertext: Some(payload_b64.clone()),
            storage_refs: vec![],
            sender_proof: SenderProof {
                proof_type: "device_signature".into(),
                value: identity.sign_sender_proof(payload_b64.as_bytes()),
            },
        })
    }
}

fn persist_effect(operations: Vec<&str>) -> CoreEffect {
    CoreEffect::PersistState {
        persist: PersistStateEffect { operations: operations.into_iter().map(str::to_string).collect() },
    }
}

fn output_with_persist(operations: Vec<&str>) -> CoreOutput {
    CoreOutput {
        state_update: CoreStateUpdate { checkpoints_changed: true, ..CoreStateUpdate::default() },
        effects: vec![persist_effect(operations)],
        view_model: None,
    }
}

trait ValidateBundle {
    fn validate(&self) -> CoreResult<()>;
}

impl ValidateBundle for DeploymentBundle {
    fn validate(&self) -> CoreResult<()> {
        crate::model::Validate::validate(self)
    }
}

impl ValidateBundle for InboxRecord {
    fn validate(&self) -> CoreResult<()> {
        crate::model::Validate::validate(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityManager;
    use crate::mls_adapter::MlsAdapter;
    use crate::model::{
        CapabilityConstraints, CapabilityOperation, CapabilityService, DeviceContactProfile,
        DeviceStatusKind, InboxAppendCapability, KeyPackageRef, CURRENT_MODEL_VERSION,
    };

    #[test]
    fn module_name_is_stable() {
        assert_eq!(FfiApiModule.name(), "ffi_api");
    }

    #[test]
    fn create_or_load_identity_initializes_mls_material() {
        let mut engine = CoreEngine::new();
        engine.handle_command(CoreCommand::CreateOrLoadIdentity {
            mnemonic: Some("alpha beta gamma".into()),
            device_name: Some("phone".into()),
        }).expect("identity");
        assert!(engine.state.mls_adapter.is_some());
        assert!(engine.state.published_key_package.is_some());
    }

    #[test]
    fn create_conversation_generates_bootstrap_envelopes() {
        let bob_bundle = sample_identity_bundle("delta epsilon zeta", "phone");
        let mut alice = seeded_engine("alpha beta gamma", "phone", bob_bundle.clone());
        let peer_user_id = bob_bundle.user_id.clone();
        alice.handle_command(CoreCommand::CreateConversation {
            peer_user_id,
            conversation_kind: ConversationKind::Direct,
        }).expect("conversation");
        assert!(alice.state.outbox.iter().any(|e| e.message_type == MessageType::MlsCommit));
        assert!(alice.state.outbox.iter().any(|e| e.message_type == MessageType::MlsWelcome));
    }

    #[test]
    fn send_text_message_generates_real_application_payload() {
        let bob_bundle = sample_identity_bundle("delta epsilon zeta", "phone");
        let mut alice = seeded_engine("alpha beta gamma", "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        alice.handle_command(CoreCommand::SendTextMessage {
            conversation_id,
            plaintext: "hello".into(),
        }).expect("send");
        assert!(alice.state.outbox.iter().any(|e| e.message_type == MessageType::MlsApplication && e.inline_ciphertext.as_deref() != Some("hello")));
    }

    #[test]
    fn end_to_end_flow_ingests_welcome_commit_and_application() {
        let mut bob = CoreEngine::new();
        bob.handle_command(CoreCommand::CreateOrLoadIdentity {
            mnemonic: Some("delta epsilon zeta".into()),
            device_name: Some("phone".into()),
        }).expect("bob identity");
        let bob_bundle = bundle_from_engine(&bob);

        let mut alice = seeded_engine("alpha beta gamma", "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        let bootstrap = alice.state.outbox.clone();

        let welcome = bootstrap.iter().find(|e| e.message_type == MessageType::MlsWelcome).unwrap().clone();
        let commit = bootstrap.iter().find(|e| e.message_type == MessageType::MlsCommit).unwrap().clone();
        bob.handle_event(CoreEvent::InboxRecordsFetched {
            device_id: welcome.recipient_device_id.clone(),
            records: vec![record_from_envelope(1, welcome)],
            to_seq: 1,
        }).expect("welcome");
        bob.handle_event(CoreEvent::InboxRecordsFetched {
            device_id: commit.recipient_device_id.clone(),
            records: vec![record_from_envelope(2, commit)],
            to_seq: 2,
        }).expect("commit");

        alice.handle_command(CoreCommand::SendTextMessage {
            conversation_id,
            plaintext: "hello bob".into(),
        }).expect("send");
        let application = alice.state.outbox.iter().rev().find(|e| e.message_type == MessageType::MlsApplication).unwrap().clone();
        let output = bob.handle_event(CoreEvent::InboxRecordsFetched {
            device_id: application.recipient_device_id.clone(),
            records: vec![record_from_envelope(3, application)],
            to_seq: 3,
        }).expect("application");
        assert!(output.state_update.messages_changed);
    }

    fn sample_identity_bundle(mnemonic: &str, device_name: &str) -> IdentityBundle {
        let identity = IdentityManager::create_or_recover(Some(mnemonic), Some(device_name)).expect("identity");
        let package = MlsAdapter::generate_key_package(&identity, 0).expect("package");
        IdentityBundle {
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
                    constraints: Some(CapabilityConstraints { max_bytes: Some(1024), max_ops_per_minute: Some(30) }),
                    signature: "cap-sig".into(),
                },
                keypackage_ref: KeyPackageRef {
                    version: CURRENT_MODEL_VERSION.to_string(),
                    user_id: identity.user_identity.user_id.clone(),
                    device_id: identity.device_identity.device_id.clone(),
                    object_ref: package.key_package_b64,
                    expires_at: package.expires_at,
                },
            }],
            device_status_ref: None,
            storage_profile: None,
            updated_at: 2,
            signature: "bundle-sig".into(),
        }
    }

    fn seeded_engine(mnemonic: &str, device_name: &str, bundle: IdentityBundle) -> CoreEngine {
        let mut engine = CoreEngine::new();
        engine.handle_command(CoreCommand::CreateOrLoadIdentity {
            mnemonic: Some(mnemonic.into()),
            device_name: Some(device_name.into()),
        }).expect("identity");
        engine.handle_command(CoreCommand::ImportIdentityBundle { bundle }).expect("import");
        engine
    }

    fn create_direct_conversation(engine: &mut CoreEngine, peer_user_id: String) -> String {
        engine.handle_command(CoreCommand::CreateConversation {
            peer_user_id,
            conversation_kind: ConversationKind::Direct,
        }).expect("conversation").view_model.unwrap().conversations[0].conversation_id.clone()
    }

    fn record_from_envelope(seq: u64, envelope: Envelope) -> InboxRecord {
        InboxRecord {
            seq,
            recipient_device_id: envelope.recipient_device_id.clone(),
            message_id: envelope.message_id.clone(),
            received_at: seq,
            expires_at: None,
            envelope,
        }
    }

    fn bundle_from_engine(engine: &CoreEngine) -> IdentityBundle {
        let identity = engine.state.local_identity.as_ref().expect("local identity");
        let package = engine.state.published_key_package.as_ref().expect("package");
        IdentityBundle {
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
                    constraints: Some(CapabilityConstraints { max_bytes: Some(1024), max_ops_per_minute: Some(30) }),
                    signature: "cap-sig".into(),
                },
                keypackage_ref: KeyPackageRef {
                    version: CURRENT_MODEL_VERSION.to_string(),
                    user_id: identity.user_identity.user_id.clone(),
                    device_id: identity.device_identity.device_id.clone(),
                    object_ref: package.key_package_b64.clone(),
                    expires_at: package.expires_at,
                },
            }],
            device_status_ref: None,
            storage_profile: None,
            updated_at: 2,
            signature: "bundle-sig".into(),
        }
    }
}

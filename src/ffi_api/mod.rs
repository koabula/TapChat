use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::conversation::{
    ConversationManager, LocalConversationState, ReconcileMembershipInput, RecoveryStatus,
};
use crate::error::{CoreError, CoreResult};
use crate::identity::{IdentityManager, LocalIdentityState};
use crate::mls_adapter::{
    CreateConversationArtifacts, IngestResult, MlsAdapter, PeerDeviceKeyPackage,
    PublishedKeyPackage, RemoveMembersArtifacts,
};
use crate::model::{
    ConversationKind, ConversationState, DeploymentBundle, Envelope, IdentityBundle, InboxRecord,
    MessageType, MlsStateStatus, MlsStateSummary, SenderProof, Validate,
};
use crate::sync_engine::{DeviceSyncState, SyncDecision, SyncEngine};

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
    ApplyIdentityBundleUpdate { bundle: IdentityBundle },
    CreateConversation { peer_user_id: String, conversation_kind: ConversationKind },
    ReconcileConversationMembership { conversation_id: String },
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
    local_bundle: Option<IdentityBundle>,
    deployment_bundle: Option<DeploymentBundle>,
    contacts: BTreeMap<String, IdentityBundle>,
    conversations: BTreeMap<String, LocalConversationState>,
    sync_states: BTreeMap<String, DeviceSyncState>,
    outbox: Vec<Envelope>,
    mls_adapter: Option<MlsAdapter>,
    mls_summaries: BTreeMap<String, MlsStateSummary>,
    published_key_package: Option<PublishedKeyPackage>,
    pending_requests: BTreeMap<String, PendingRequest>,
    recovery_contexts: BTreeMap<String, RecoveryContext>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PendingRequest {
    GetHead { device_id: String },
    FetchMessages { device_id: String, from_seq: u64, limit: u64 },
    GetIdentityBundle { user_id: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryReason {
    MissingCommit,
    MissingWelcome,
    MembershipChanged,
    IdentityChanged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecoveryContext {
    conversation_id: String,
    reason: RecoveryReason,
    sync_attempted: bool,
    identity_refresh_attempted: bool,
}

impl Default for CoreState {
    fn default() -> Self {
        Self {
            local_identity: None,
            local_bundle: None,
            deployment_bundle: None,
            contacts: BTreeMap::new(),
            conversations: BTreeMap::new(),
            sync_states: BTreeMap::new(),
            outbox: Vec::new(),
            mls_adapter: None,
            mls_summaries: BTreeMap::new(),
            published_key_package: None,
            pending_requests: BTreeMap::new(),
            recovery_contexts: BTreeMap::new(),
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
            CoreCommand::ImportDeploymentBundle { bundle } => self.import_deployment_bundle(bundle),
            CoreCommand::ImportIdentityBundle { bundle } => self.import_identity_bundle(bundle),
            CoreCommand::ApplyIdentityBundleUpdate { bundle } => self.apply_identity_bundle_update(bundle),
            CoreCommand::CreateConversation { peer_user_id, conversation_kind } => self.create_conversation(peer_user_id, conversation_kind),
            CoreCommand::ReconcileConversationMembership { conversation_id } => {
                self.reconcile_conversation_membership(conversation_id)
            }
            CoreCommand::SendTextMessage { conversation_id, plaintext } => self.send_text_message(conversation_id, plaintext),
            CoreCommand::SendAttachmentMessage { .. } => {
                Err(CoreError::unsupported("attachments are not implemented in phase 6"))
            }
            CoreCommand::SyncInbox { device_id, .. } => self.sync_inbox(device_id),
            CoreCommand::RefreshIdentityState { user_id } => self.refresh_identity_state(user_id),
            CoreCommand::RebuildConversation { conversation_id } => self.rebuild_conversation(conversation_id),
        }
    }

    pub fn handle_event(&mut self, event: CoreEvent) -> CoreResult<CoreOutput> {
        match event {
            CoreEvent::AppStarted | CoreEvent::AppForegrounded => self.start_foreground_sync(),
            CoreEvent::WebSocketConnected { device_id } => self.handle_websocket_connected(device_id),
            CoreEvent::WebSocketDisconnected { device_id, .. } => self.handle_websocket_disconnected(device_id),
            CoreEvent::WakeupReceived { device_id, .. } => self.sync_inbox(device_id),
            CoreEvent::InboxRecordsFetched { device_id, records, to_seq } => self.handle_inbox_records(device_id, records, to_seq),
            CoreEvent::HttpResponseReceived { request_id, status, body } => {
                self.handle_http_response(request_id, status, body)
            }
            CoreEvent::TimerTriggered { timer_id } => self.handle_timer(timer_id),
            CoreEvent::UserConfirmedRebuild { conversation_id } => {
                self.rebuild_conversation(conversation_id)
            }
            CoreEvent::BlobUploaded { .. } | CoreEvent::BlobDownloaded { .. } => {
                Ok(CoreOutput::default())
            }
        }
    }

    fn import_deployment_bundle(&mut self, bundle: DeploymentBundle) -> CoreResult<CoreOutput> {
        bundle.validate()?;
        self.state.deployment_bundle = Some(bundle);
        self.refresh_local_bundle()?;
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: self.state.local_bundle.is_some(),
                checkpoints_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(vec![
                "save_deployment_bundle",
                "save_local_identity_bundle",
            ])],
            view_model: None,
        })
    }

    fn import_identity_bundle(&mut self, bundle: IdentityBundle) -> CoreResult<CoreOutput> {
        IdentityManager::verify_identity_bundle(&bundle)?;
        self.state.contacts.insert(bundle.user_id.clone(), bundle);
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(vec![
                "save_identity_bundle",
                "save_contact_keypackage_ref",
            ])],
            view_model: None,
        })
    }

    fn apply_identity_bundle_update(&mut self, bundle: IdentityBundle) -> CoreResult<CoreOutput> {
        IdentityManager::verify_identity_bundle(&bundle)?;
        let user_id = bundle.user_id.clone();
        let affected_conversations = self.affected_conversations_for_peer(&user_id);
        self.state.contacts.insert(user_id.clone(), bundle);

        let mut output = CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(vec![
                "save_identity_bundle",
                "save_contact_keypackage_ref",
            ])],
            view_model: None,
        };
        for conversation_id in affected_conversations {
            self.mark_recovery_needed(&conversation_id, RecoveryReason::IdentityChanged);
            output = merge_outputs(
                output,
                self.reconcile_conversation_membership(conversation_id)?,
            );
        }
        Ok(output)
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
        self.state.sync_states.insert(
            device_id.clone(),
            SyncEngine::new_device_state(&device_id),
        );
        self.refresh_local_bundle()?;
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                checkpoints_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(vec![
                "save_local_identity",
                "save_local_device_identity",
                "save_local_key_package",
                "save_local_identity_bundle",
            ])],
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

    fn refresh_local_bundle(&mut self) -> CoreResult<()> {
        let Some(local_identity) = self.state.local_identity.as_ref() else {
            return Ok(());
        };
        let Some(deployment) = self.state.deployment_bundle.as_ref() else {
            self.state.local_bundle = None;
            return Ok(());
        };
        let package = self
            .state
            .published_key_package
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("published key package missing"))?;
        self.state.local_bundle = Some(IdentityManager::export_identity_bundle(
            local_identity,
            deployment,
            package.key_package_ref.clone(),
            package.expires_at,
        )?);
        Ok(())
    }

    fn affected_conversations_for_peer(&self, peer_user_id: &str) -> Vec<String> {
        self.state
            .conversations
            .iter()
            .filter_map(|(conversation_id, state)| {
                if state.peer_user_id == peer_user_id {
                    Some(conversation_id.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    fn peer_active_device_ids(&self, peer_user_id: &str) -> CoreResult<Vec<String>> {
        let bundle = self
            .state
            .contacts
            .get(peer_user_id)
            .ok_or_else(|| CoreError::invalid_input("peer identity bundle has not been imported"))?;
        let devices: Vec<String> = bundle
            .devices
            .iter()
            .filter(|device| matches!(device.status, crate::model::DeviceStatusKind::Active))
            .map(|device| device.device_id.clone())
            .collect();
        if devices.is_empty() {
            return Err(CoreError::invalid_input(
                "peer identity bundle does not contain any active devices",
            ));
        }
        Ok(devices)
    }

    fn peer_key_packages(
        &self,
        peer_user_id: &str,
        device_ids: &[String],
    ) -> CoreResult<Vec<PeerDeviceKeyPackage>> {
        let wanted: BTreeSet<String> = device_ids.iter().cloned().collect();
        let bundle = self
            .state
            .contacts
            .get(peer_user_id)
            .ok_or_else(|| CoreError::invalid_input("peer identity bundle has not been imported"))?;
        let devices: Vec<PeerDeviceKeyPackage> = bundle
            .devices
            .iter()
            .filter(|device| wanted.contains(&device.device_id))
            .map(|device| PeerDeviceKeyPackage {
                user_id: peer_user_id.to_string(),
                device_id: device.device_id.clone(),
                device_public_key: device.device_public_key.clone(),
                key_package_b64: device.keypackage_ref.object_ref.clone(),
            })
            .collect();
        if devices.len() != wanted.len() {
            return Err(CoreError::invalid_input(
                "some requested peer key packages are missing",
            ));
        }
        Ok(devices)
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
        if matches!(
            self.state
                .conversations
                .get(&conversation_id)
                .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?
                .conversation
                .state,
            ConversationState::NeedsRebuild
        ) {
            return Err(CoreError::invalid_state(
                "conversation needs rebuild before sending new messages",
            ));
        }
        if self
            .state
            .conversations
            .get(&conversation_id)
            .map(|state| state.recovery_status != RecoveryStatus::Healthy)
            .unwrap_or(false)
        {
            return Err(CoreError::temporary_failure(
                "conversation membership is still recovering",
            ));
        }
        if self
            .state
            .mls_summaries
            .get(&conversation_id)
            .map(|summary| summary.status != MlsStateStatus::Active)
            .unwrap_or(false)
        {
            return Err(CoreError::temporary_failure(
                "conversation MLS state is recovering",
            ));
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

    fn reconcile_conversation_membership(
        &mut self,
        conversation_id: String,
    ) -> CoreResult<CoreOutput> {
        let local_identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?;
        let peer_user_id = self
            .state
            .conversations
            .get(&conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?
            .peer_user_id
            .clone();
        let peer_active_device_ids = self.peer_active_device_ids(&peer_user_id)?;
        let reconcile = {
            let conversation_state = self
                .state
                .conversations
                .get(&conversation_id)
                .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?;
            ConversationManager::reconcile_direct_membership(
                Some(conversation_state),
                ReconcileMembershipInput {
                    local_user_id: &local_identity.user_identity.user_id,
                    local_device_id: &local_identity.device_identity.device_id,
                    peer_user_id: &peer_user_id,
                    peer_active_device_ids: &peer_active_device_ids,
                },
            )?
        };

        {
            let conversation_state = self
                .state
                .conversations
                .get_mut(&conversation_id)
                .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?;
            ConversationManager::apply_reconciled_membership(
                conversation_state,
                &reconcile,
                &peer_active_device_ids,
                current_timestamp_hint(self.state.outbox.len()),
            );
        }

        if !reconcile.changed {
            if let Some(adapter) = self.state.mls_adapter.as_mut() {
                if let Ok(summary) = adapter.attempt_recovery(&conversation_id) {
                    self.state.mls_summaries.insert(conversation_id.clone(), summary);
                }
            }
            self.state.recovery_contexts.remove(&conversation_id);
            return Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    conversations_changed: true,
                    ..CoreStateUpdate::default()
                },
                effects: vec![persist_effect(vec!["save_conversation"])],
                view_model: Some(CoreViewModel {
                    conversations: vec![self.conversation_summary(&conversation_id)?],
                    ..CoreViewModel::default()
                }),
            });
        }

        let mut generated = Vec::new();
        generated.extend(self.build_control_membership_changed_messages(
            &conversation_id,
            &peer_user_id,
            &peer_active_device_ids,
        )?);

        if !reconcile.added_devices.is_empty() {
            let key_packages = self.peer_key_packages(&peer_user_id, &reconcile.added_devices)?;
            let artifacts = self
                .state
                .mls_adapter
                .as_mut()
                .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
                .add_members(&conversation_id, &key_packages)?;
            generated.extend(self.commit_envelopes_for_artifacts(
                &conversation_id,
                &peer_active_device_ids,
                &artifacts,
            )?);
            generated.extend(self.welcome_envelopes_for_artifacts(
                &conversation_id,
                &artifacts,
            )?);
            self.state.mls_summaries.insert(
                conversation_id.clone(),
                self.state
                    .mls_adapter
                    .as_ref()
                    .ok_or_else(|| CoreError::invalid_state("mls adapter missing"))?
                    .export_group_summary(&conversation_id)?,
            );
        }

        if !reconcile.revoked_devices.is_empty() {
            let active_targets: Vec<String> = peer_active_device_ids.clone();
            let artifacts = self
                .state
                .mls_adapter
                .as_mut()
                .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
                .remove_members(&conversation_id, &reconcile.revoked_devices)?;
            generated.extend(self.commit_envelopes_for_remove(
                &conversation_id,
                &active_targets,
                &artifacts,
            )?);
            self.state.mls_summaries.insert(
                conversation_id.clone(),
                self.state
                    .mls_adapter
                    .as_ref()
                    .ok_or_else(|| CoreError::invalid_state("mls adapter missing"))?
                    .export_group_summary(&conversation_id)?,
            );
        }

        self.state.outbox.extend(generated.clone());
        self.mark_recovery_needed(&conversation_id, RecoveryReason::MembershipChanged);
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                conversations_changed: true,
                messages_changed: true,
                contacts_changed: true,
                system_statuses_changed: vec![SystemStatus::SyncInProgress],
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(vec![
                "save_conversation",
                "save_mls_group_state",
                "queue_membership_change_messages",
            ])],
            view_model: Some(CoreViewModel {
                conversations: vec![self.conversation_summary(&conversation_id)?],
                messages: generated
                    .iter()
                    .map(|envelope| MessageSummary {
                        conversation_id: envelope.conversation_id.clone(),
                        message_id: envelope.message_id.clone(),
                        message_type: envelope.message_type,
                    })
                    .collect(),
                ..CoreViewModel::default()
            }),
        })
    }

    fn sync_inbox(&mut self, device_id: String) -> CoreResult<CoreOutput> {
        if device_id.trim().is_empty() {
            return Err(CoreError::invalid_input("device_id must not be empty"));
        }
        let deployment = self
            .state
            .deployment_bundle
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("deployment bundle is not initialized"))?;
        let sync_state = self
            .state
            .sync_states
            .entry(device_id.clone())
            .or_insert_with(|| SyncEngine::new_device_state(&device_id));
        let request_id = format!("get_head:{device_id}:{}", self.state.pending_requests.len() + 1);
        self.state.pending_requests.insert(
            request_id.clone(),
            PendingRequest::GetHead {
                device_id: device_id.clone(),
            },
        );
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                checkpoints_changed: true,
                system_statuses_changed: vec![SystemStatus::SyncInProgress],
                ..CoreStateUpdate::default()
            },
            effects: vec![
                CoreEffect::OpenRealtimeConnection {
                    connection: RealtimeConnectionEffect {
                        device_id: device_id.clone(),
                        url: deployment.inbox_websocket_endpoint.clone(),
                        headers: BTreeMap::new(),
                    },
                },
                CoreEffect::ExecuteHttpRequest {
                    request: HttpRequestEffect {
                        request_id,
                        method: HttpMethod::Get,
                        url: format!(
                            "{}/v1/inbox/{}/head",
                            deployment.inbox_http_endpoint.trim_end_matches('/'),
                            device_id
                        ),
                        headers: BTreeMap::new(),
                        body: None,
                    },
                },
                CoreEffect::PersistState {
                    persist: PersistStateEffect {
                        operations: vec![
                            "save_sync_checkpoint".into(),
                            format!("last_known_head:{}", sync_state.last_head_seq),
                        ],
                    },
                },
            ],
            view_model: None,
        })
    }

    fn refresh_identity_state(&mut self, user_id: String) -> CoreResult<CoreOutput> {
        if user_id.trim().is_empty() {
            return Err(CoreError::invalid_input("user_id must not be empty"));
        }
        let bundle = self
            .state
            .contacts
            .get(&user_id)
            .ok_or_else(|| CoreError::invalid_input("contact does not exist"))?;
        let base_url = bundle
            .storage_profile
            .as_ref()
            .and_then(|profile| profile.base_url.clone())
            .or_else(|| {
                self.state
                    .deployment_bundle
                    .as_ref()
                    .and_then(|deployment| deployment.storage_base_info.base_url.clone())
            })
            .ok_or_else(|| CoreError::invalid_state("storage profile base_url is missing"))?;
        let request_id = format!("identity_bundle:{user_id}:{}", self.state.pending_requests.len() + 1);
        self.state.pending_requests.insert(
            request_id.clone(),
            PendingRequest::GetIdentityBundle {
                user_id: user_id.clone(),
            },
        );
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                system_statuses_changed: vec![SystemStatus::IdentityRefreshNeeded],
                ..CoreStateUpdate::default()
            },
            effects: vec![CoreEffect::ExecuteHttpRequest {
                request: HttpRequestEffect {
                    request_id,
                    method: HttpMethod::Get,
                    url: format!("{}/identity_bundle.json", base_url.trim_end_matches('/')),
                    headers: BTreeMap::new(),
                    body: None,
                },
            }],
            view_model: None,
        })
    }

    fn rebuild_conversation(&mut self, conversation_id: String) -> CoreResult<CoreOutput> {
        let conversation_state = self
            .state
            .conversations
            .get_mut(&conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?;
        conversation_state.conversation.state = ConversationState::NeedsRebuild;
        conversation_state.recovery_status = RecoveryStatus::NeedsRebuild;
        if let Some(adapter) = self.state.mls_adapter.as_mut() {
            adapter.mark_needs_rebuild(&conversation_id);
            adapter.clear_conversation(&conversation_id);
        }
        self.state.recovery_contexts.remove(&conversation_id);
        self.state.mls_summaries.insert(
            conversation_id.clone(),
            MlsStateSummary {
                conversation_id: conversation_id.clone(),
                epoch: 0,
                member_device_ids: conversation_state
                    .conversation
                    .member_devices
                    .iter()
                    .map(|member| member.device_id.clone())
                    .collect(),
                status: MlsStateStatus::NeedsRebuild,
                updated_at: 0,
            },
        );
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                conversations_changed: true,
                system_statuses_changed: vec![SystemStatus::ConversationNeedsRebuild],
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(vec!["save_conversation", "save_mls_group_state"])],
            view_model: Some(CoreViewModel {
                conversations: vec![ConversationSummary {
                    conversation_id,
                    state: "needs_rebuild".into(),
                    last_message_type: conversation_state.last_message_type,
                }],
                ..CoreViewModel::default()
            }),
        })
    }

    fn start_foreground_sync(&mut self) -> CoreResult<CoreOutput> {
        let device_id = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .device_identity
            .device_id
            .clone();
        self.sync_inbox(device_id)
    }

    fn handle_websocket_connected(&mut self, device_id: String) -> CoreResult<CoreOutput> {
        if device_id.trim().is_empty() {
            return Err(CoreError::invalid_input("device_id must not be empty"));
        }
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                checkpoints_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![],
            view_model: None,
        })
    }

    fn handle_websocket_disconnected(&mut self, device_id: String) -> CoreResult<CoreOutput> {
        if device_id.trim().is_empty() {
            return Err(CoreError::invalid_input("device_id must not be empty"));
        }
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                checkpoints_changed: true,
                system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                ..CoreStateUpdate::default()
            },
            effects: vec![CoreEffect::ScheduleTimer {
                timer: TimerEffect {
                    timer_id: format!("sync:{device_id}"),
                    delay_ms: 0,
                },
            }],
            view_model: None,
        })
    }

    fn handle_timer(&mut self, timer_id: String) -> CoreResult<CoreOutput> {
        if let Some(device_id) = timer_id.strip_prefix("sync:") {
            return self.sync_inbox(device_id.to_string());
        }
        if let Some(user_id) = timer_id.strip_prefix("refresh_identity:") {
            return self.refresh_identity_state(user_id.to_string());
        }
        Ok(CoreOutput::default())
    }

    fn handle_http_response(
        &mut self,
        request_id: String,
        status: u16,
        body: Option<String>,
    ) -> CoreResult<CoreOutput> {
        let request = self
            .state
            .pending_requests
            .remove(&request_id)
            .ok_or_else(|| CoreError::invalid_input("unknown request_id"))?;
        if status >= 500 {
            return Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                    ..CoreStateUpdate::default()
                },
                effects: vec![CoreEffect::ScheduleTimer {
                    timer: TimerEffect {
                        timer_id: retry_timer_for_request(&request),
                        delay_ms: 0,
                    },
                }],
                view_model: None,
            });
        }
        match request {
            PendingRequest::GetHead { device_id } => {
                let head = parse_head_response(body.as_deref())?;
                let sync_state = self
                    .state
                    .sync_states
                    .entry(device_id.clone())
                    .or_insert_with(|| SyncEngine::new_device_state(&device_id));
                SyncEngine::register_head(sync_state, head.head_seq);
                if let Some(decision) = SyncEngine::next_fetch(sync_state) {
                    self.issue_fetch(device_id, decision)
                } else {
                    Ok(CoreOutput {
                        state_update: CoreStateUpdate {
                            checkpoints_changed: true,
                            ..CoreStateUpdate::default()
                        },
                        effects: vec![persist_effect(vec!["save_sync_checkpoint"])],
                        view_model: None,
                    })
                }
            }
            PendingRequest::FetchMessages { device_id, .. } => {
                let response = parse_fetch_response(body.as_deref())?;
                self.handle_inbox_records(device_id, response.records, response.to_seq)
            }
            PendingRequest::GetIdentityBundle { user_id: _ } => {
                let bundle: IdentityBundle = serde_json::from_str(
                    body.as_deref()
                        .ok_or_else(|| CoreError::invalid_input("identity bundle body missing"))?,
                )
                .map_err(|error| {
                    CoreError::invalid_input(format!("failed to decode identity bundle: {error}"))
                })?;
                self.handle_command(CoreCommand::ApplyIdentityBundleUpdate { bundle })
            }
        }
    }

    fn issue_fetch(
        &mut self,
        device_id: String,
        decision: SyncDecision,
    ) -> CoreResult<CoreOutput> {
        let deployment = self
            .state
            .deployment_bundle
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("deployment bundle is not initialized"))?;
        let limit = decision
            .to_seq
            .saturating_sub(decision.from_seq)
            .saturating_add(1)
            .max(1);
        let request_id = format!("fetch:{device_id}:{}", self.state.pending_requests.len() + 1);
        self.state.pending_requests.insert(
            request_id.clone(),
            PendingRequest::FetchMessages {
                device_id: device_id.clone(),
                from_seq: decision.from_seq,
                limit,
            },
        );
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                checkpoints_changed: true,
                system_statuses_changed: vec![SystemStatus::SyncInProgress],
                ..CoreStateUpdate::default()
            },
            effects: vec![CoreEffect::ExecuteHttpRequest {
                request: HttpRequestEffect {
                    request_id,
                    method: HttpMethod::Get,
                    url: format!(
                        "{}/v1/inbox/{}/messages?fromSeq={}&limit={}",
                        deployment.inbox_http_endpoint.trim_end_matches('/'),
                        device_id,
                        decision.from_seq,
                        limit
                    ),
                    headers: BTreeMap::new(),
                    body: None,
                },
            }],
            view_model: None,
        })
    }

    fn handle_inbox_records(
        &mut self,
        device_id: String,
        records: Vec<InboxRecord>,
        to_seq: u64,
    ) -> CoreResult<CoreOutput> {
        for record in &records {
            record.validate()?;
        }
        let mut fresh_records = {
            let sync_state = self
                .state
                .sync_states
                .entry(device_id.clone())
                .or_insert_with(|| SyncEngine::new_device_state(&device_id));
            let mut fresh = SyncEngine::register_fetch(sync_state, &records, to_seq);
            for pending in sync_state.pending_records.values() {
                if !fresh.iter().any(|record| record.seq == pending.seq) {
                    fresh.push(pending.clone());
                }
            }
            fresh
        };
        fresh_records.sort_by_key(|record| record.seq);

        let mut output = CoreOutput {
            state_update: CoreStateUpdate {
                checkpoints_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![],
            view_model: Some(CoreViewModel::default()),
        };
        let local_user_id = self
            .state
            .local_identity
            .as_ref()
            .map(|identity| identity.user_identity.user_id.clone())
            .unwrap_or_else(|| "user:local".into());
        let mut persist_ops = vec!["ingest_inbox_records".into(), "save_sync_checkpoint".into()];
        let mut contiguous_ack = self
            .state
            .sync_states
            .get(&device_id)
            .map(|state| state.checkpoint.last_acked_seq)
            .unwrap_or(0);

        for record in fresh_records {
            let conversation_id = record.envelope.conversation_id.clone();
            self.ensure_local_conversation_for_record(&device_id, &local_user_id, &record);
            let mut applied = false;
            match record.envelope.message_type {
                MessageType::MlsApplication | MessageType::MlsCommit | MessageType::MlsWelcome => {
                    let payload = record
                        .envelope
                        .inline_ciphertext
                        .as_deref()
                        .ok_or_else(|| CoreError::invalid_input("MLS envelope payload missing"))?;
                    let result = self
                        .state
                        .mls_adapter
                        .as_mut()
                        .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
                        .ingest_message(
                            &conversation_id,
                            &record.envelope.sender_device_id,
                            record.envelope.message_type,
                            payload,
                        )?;
                    match result {
                        IngestResult::AppliedApplication(_) => {
                            let conversation_state = self
                                .state
                                .conversations
                                .get_mut(&conversation_id)
                                .ok_or_else(|| {
                                    CoreError::invalid_input("conversation does not exist")
                                })?;
                            let _ = ConversationManager::apply_incoming_envelope(
                                conversation_state,
                                &record.envelope,
                            )?;
                            conversation_state.recovery_status = RecoveryStatus::Healthy;
                            output.state_update.messages_changed = true;
                            output.state_update.conversations_changed = true;
                            self.state.recovery_contexts.remove(&conversation_id);
                            applied = true;
                        }
                        IngestResult::AppliedCommit { .. } | IngestResult::AppliedWelcome { .. } => {
                            if let Some(conversation_state) =
                                self.state.conversations.get_mut(&conversation_id)
                            {
                                conversation_state.recovery_status = RecoveryStatus::Healthy;
                            }
                            output.state_update.conversations_changed = true;
                            persist_ops.push("save_mls_group_state".into());
                            self.state.recovery_contexts.remove(&conversation_id);
                            applied = true;
                        }
                        IngestResult::PendingRetry => {
                            output
                                .state_update
                                .system_statuses_changed
                                .push(SystemStatus::SyncInProgress);
                            {
                                let sync_state = self
                                    .state
                                    .sync_states
                                    .entry(device_id.clone())
                                    .or_insert_with(|| SyncEngine::new_device_state(&device_id));
                                SyncEngine::store_pending_record(sync_state, &record);
                            }
                            let reason = if record.envelope.message_type == MessageType::MlsWelcome
                            {
                                RecoveryReason::MissingWelcome
                            } else {
                                RecoveryReason::MissingCommit
                            };
                            self.mark_recovery_needed(&conversation_id, reason);
                        }
                        IngestResult::NeedsRebuild => {
                            let rebuild_output = self.rebuild_conversation(conversation_id.clone())?;
                            output = merge_outputs(output, rebuild_output);
                            {
                                let sync_state = self
                                    .state
                                    .sync_states
                                    .entry(device_id.clone())
                                    .or_insert_with(|| SyncEngine::new_device_state(&device_id));
                                SyncEngine::store_pending_record(sync_state, &record);
                            }
                        }
                    }
                    if let Some(summary) = self
                        .state
                        .mls_adapter
                        .as_ref()
                        .and_then(|adapter| adapter.export_group_summary(&conversation_id).ok())
                    {
                        self.state.mls_summaries.insert(conversation_id.clone(), summary);
                    }
                }
                _ => {
                    let effect = {
                        let conversation_state = self
                            .state
                            .conversations
                            .get_mut(&conversation_id)
                            .ok_or_else(|| {
                                CoreError::invalid_input("conversation does not exist")
                            })?;
                        ConversationManager::apply_incoming_envelope(
                            conversation_state,
                            &record.envelope,
                        )?
                    };
                    output.state_update.messages_changed = true;
                    output.state_update.conversations_changed = true;
                    if effect.identity_refresh_needed {
                        output.state_update.contacts_changed = true;
                        output
                            .state_update
                            .system_statuses_changed
                            .push(SystemStatus::IdentityRefreshNeeded);
                        output = merge_outputs(
                            output,
                            self.refresh_identity_state(record.envelope.sender_user_id.clone())?,
                        );
                    }
                    if effect.membership_refresh_needed {
                        self.mark_recovery_needed(
                            &conversation_id,
                            RecoveryReason::MembershipChanged,
                        );
                    }
                    if effect.needs_rebuild {
                        output
                            .state_update
                            .system_statuses_changed
                            .push(SystemStatus::ConversationNeedsRebuild);
                    }
                    applied = true;
                }
            }

            if !applied {
                if let Some(recovery_output) =
                    self.attempt_recovery_flow(&device_id, &conversation_id)?
                {
                    output = merge_outputs(output, recovery_output);
                }
            } else {
                {
                    let sync_state = self
                        .state
                        .sync_states
                        .entry(device_id.clone())
                        .or_insert_with(|| SyncEngine::new_device_state(&device_id));
                    SyncEngine::clear_pending_retry(sync_state, record.seq);
                }
                if record.seq == contiguous_ack.saturating_add(1) {
                    contiguous_ack = record.seq;
                }
            }

            let conversation_summary = self.conversation_summary(&conversation_id)?;
            if let Some(view_model) = output.view_model.as_mut() {
                view_model.messages.push(MessageSummary {
                    conversation_id: conversation_id.clone(),
                    message_id: record.message_id.clone(),
                    message_type: record.envelope.message_type,
                });
                view_model.conversations.push(conversation_summary);
            }
        }

        let (ack, pending_retry) = {
            let sync_state = self
                .state
                .sync_states
                .entry(device_id.clone())
                .or_insert_with(|| SyncEngine::new_device_state(&device_id));
            let ack = SyncEngine::ack_up_to(sync_state, contiguous_ack);
            (ack, sync_state.pending_retry)
        };
        if ack.ack_seq > 0 {
            persist_ops.push("save_inbox_ack".into());
        }
        if pending_retry {
            persist_ops.push("save_pending_inbox_retry".into());
        }
        output.effects.push(CoreEffect::PersistState {
            persist: PersistStateEffect {
                operations: persist_ops,
            },
        });
        Ok(output)
    }

    fn ensure_local_conversation_for_record(
        &mut self,
        device_id: &str,
        local_user_id: &str,
        record: &InboxRecord,
    ) {
        self.state
            .conversations
            .entry(record.envelope.conversation_id.clone())
            .or_insert_with(|| LocalConversationState {
                conversation: crate::model::Conversation {
                    conversation_id: record.envelope.conversation_id.clone(),
                    kind: ConversationKind::Direct,
                    member_users: vec![
                        record.envelope.sender_user_id.clone(),
                        local_user_id.to_string(),
                    ],
                    member_devices: vec![
                        crate::model::ConversationMember {
                            user_id: record.envelope.sender_user_id.clone(),
                            device_id: record.envelope.sender_device_id.clone(),
                            status: crate::model::DeviceStatusKind::Active,
                        },
                        crate::model::ConversationMember {
                            user_id: local_user_id.to_string(),
                            device_id: device_id.to_string(),
                            status: crate::model::DeviceStatusKind::Active,
                        },
                    ],
                    state: ConversationState::Active,
                    updated_at: record.envelope.created_at,
                },
                messages: Vec::new(),
                last_message_type: None,
                peer_user_id: record.envelope.sender_user_id.clone(),
                last_known_peer_active_devices: BTreeSet::from([
                    record.envelope.sender_device_id.clone(),
                ]),
                recovery_status: RecoveryStatus::Healthy,
            });
    }

    fn mark_recovery_needed(
        &mut self,
        conversation_id: &str,
        reason: RecoveryReason,
    ) {
        self.state.recovery_contexts
            .entry(conversation_id.to_string())
            .and_modify(|context| context.reason = reason)
            .or_insert(RecoveryContext {
                conversation_id: conversation_id.to_string(),
                reason,
                sync_attempted: false,
                identity_refresh_attempted: false,
            });
        if let Some(state) = self.state.conversations.get_mut(conversation_id) {
            state.recovery_status = RecoveryStatus::NeedsRecovery;
        }
        if let Some(adapter) = self.state.mls_adapter.as_mut() {
            adapter.mark_recovery_needed(conversation_id);
        }
        if let Some(summary) = self.state.mls_summaries.get_mut(conversation_id) {
            summary.status = MlsStateStatus::NeedsRecovery;
        }
    }

    fn attempt_recovery_flow(
        &mut self,
        device_id: &str,
        conversation_id: &str,
    ) -> CoreResult<Option<CoreOutput>> {
        let Some(context) = self.state.recovery_contexts.get_mut(conversation_id) else {
            return Ok(None);
        };
        if !context.sync_attempted {
            context.sync_attempted = true;
            return Ok(Some(self.sync_inbox(device_id.to_string())?));
        }

        if !context.identity_refresh_attempted {
            context.identity_refresh_attempted = true;
            let peer_user_id = self
                .state
                .conversations
                .get(conversation_id)
                .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?
                .peer_user_id
                .clone();
            return Ok(Some(self.refresh_identity_state(peer_user_id)?));
        }

        Ok(Some(self.rebuild_conversation(conversation_id.to_string())?))
    }

    fn build_control_membership_changed_messages(
        &self,
        conversation_id: &str,
        peer_user_id: &str,
        peer_active_device_ids: &[String],
    ) -> CoreResult<Vec<Envelope>> {
        let payload = format!(
            "membership_changed:{}:{}:{}",
            conversation_id,
            peer_user_id,
            peer_active_device_ids.len()
        );
        peer_active_device_ids
            .iter()
            .map(|device_id| {
                self.build_envelope(
                    conversation_id,
                    device_id,
                    MessageType::ControlDeviceMembershipChanged,
                    payload.clone(),
                )
            })
            .collect()
    }

    fn commit_envelopes_for_artifacts(
        &self,
        conversation_id: &str,
        peer_active_device_ids: &[String],
        artifacts: &CreateConversationArtifacts,
    ) -> CoreResult<Vec<Envelope>> {
        peer_active_device_ids
            .iter()
            .map(|device_id| {
                self.build_envelope(
                    conversation_id,
                    device_id,
                    MessageType::MlsCommit,
                    artifacts.commit_b64.clone(),
                )
            })
            .collect()
    }

    fn welcome_envelopes_for_artifacts(
        &self,
        conversation_id: &str,
        artifacts: &CreateConversationArtifacts,
    ) -> CoreResult<Vec<Envelope>> {
        artifacts
            .welcomes
            .iter()
            .map(|welcome| {
                self.build_envelope(
                    conversation_id,
                    &welcome.recipient_device_id,
                    MessageType::MlsWelcome,
                    welcome.payload_b64.clone(),
                )
            })
            .collect()
    }

    fn commit_envelopes_for_remove(
        &self,
        conversation_id: &str,
        peer_active_device_ids: &[String],
        artifacts: &RemoveMembersArtifacts,
    ) -> CoreResult<Vec<Envelope>> {
        peer_active_device_ids
            .iter()
            .map(|device_id| {
                self.build_envelope(
                    conversation_id,
                    device_id,
                    MessageType::MlsCommit,
                    artifacts.commit_b64.clone(),
                )
            })
            .collect()
    }

    fn conversation_summary(&self, conversation_id: &str) -> CoreResult<ConversationSummary> {
        let conversation = self
            .state
            .conversations
            .get(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?;
        Ok(ConversationSummary {
            conversation_id: conversation_id.to_string(),
            state: match conversation.conversation.state {
                ConversationState::Active => match conversation.recovery_status {
                    RecoveryStatus::Healthy => "active".into(),
                    RecoveryStatus::NeedsRecovery => "needs_recovery".into(),
                    RecoveryStatus::NeedsRebuild => "needs_rebuild".into(),
                },
                ConversationState::NeedsRebuild => "needs_rebuild".into(),
            },
            last_message_type: conversation.last_message_type,
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

#[derive(Debug, Deserialize)]
struct HeadResponse {
    head_seq: u64,
}

#[derive(Debug, Deserialize)]
struct FetchResponse {
    to_seq: u64,
    records: Vec<InboxRecord>,
}

fn parse_head_response(body: Option<&str>) -> CoreResult<HeadResponse> {
    serde_json::from_str(
        body.ok_or_else(|| CoreError::invalid_input("head response body missing"))?,
    )
    .map_err(|error| CoreError::invalid_input(format!("failed to decode head response: {error}")))
}

fn parse_fetch_response(body: Option<&str>) -> CoreResult<FetchResponse> {
    serde_json::from_str(
        body.ok_or_else(|| CoreError::invalid_input("fetch response body missing"))?,
    )
    .map_err(|error| CoreError::invalid_input(format!("failed to decode fetch response: {error}")))
}

fn current_timestamp_hint(outbox_len: usize) -> u64 {
    outbox_len as u64 + 1
}

fn retry_timer_for_request(request: &PendingRequest) -> String {
    match request {
        PendingRequest::GetHead { device_id } | PendingRequest::FetchMessages { device_id, .. } => {
            format!("sync:{device_id}")
        }
        PendingRequest::GetIdentityBundle { user_id } => format!("refresh_identity:{user_id}"),
    }
}

fn persist_effect(operations: Vec<&str>) -> CoreEffect {
    CoreEffect::PersistState {
        persist: PersistStateEffect { operations: operations.into_iter().map(str::to_string).collect() },
    }
}

fn merge_outputs(mut base: CoreOutput, mut next: CoreOutput) -> CoreOutput {
    base.state_update.conversations_changed |= next.state_update.conversations_changed;
    base.state_update.messages_changed |= next.state_update.messages_changed;
    base.state_update.contacts_changed |= next.state_update.contacts_changed;
    base.state_update.checkpoints_changed |= next.state_update.checkpoints_changed;
    base.state_update
        .system_statuses_changed
        .append(&mut next.state_update.system_statuses_changed);
    base.effects.append(&mut next.effects);

    match (&mut base.view_model, next.view_model.take()) {
        (Some(base_view), Some(mut next_view)) => {
            base_view.conversations.append(&mut next_view.conversations);
            base_view.messages.append(&mut next_view.messages);
            base_view.contacts.append(&mut next_view.contacts);
            base_view.banners.append(&mut next_view.banners);
        }
        (None, Some(next_view)) => {
            base.view_model = Some(next_view);
        }
        _ => {}
    }
    base
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::CapabilityManager;
    use crate::identity::IdentityManager;
    use crate::mls_adapter::MlsAdapter;
    use crate::model::{
        DeploymentBundle, IdentityBundle, StorageBaseInfo, CURRENT_MODEL_VERSION,
    };
    use ed25519_dalek::Signer;

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

    #[test]
    fn sync_inbox_emits_head_request_and_realtime_effect() {
        let mut engine = CoreEngine::new();
        engine
            .handle_command(CoreCommand::ImportDeploymentBundle {
                bundle: sample_deployment(),
            })
            .expect("deployment");
        let identity_output = engine
            .handle_command(CoreCommand::CreateOrLoadIdentity {
                mnemonic: Some("alpha beta gamma".into()),
                device_name: Some("phone".into()),
            })
            .expect("identity");
        assert!(identity_output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::PersistState { .. }
        )));
        let device_id = engine
            .state
            .local_identity
            .as_ref()
            .expect("identity")
            .device_identity
            .device_id
            .clone();
        let output = engine
            .handle_command(CoreCommand::SyncInbox {
                device_id,
                reason: Some("test".into()),
            })
            .expect("sync");
        assert!(output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::OpenRealtimeConnection { .. }
        )));
        assert!(output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::ExecuteHttpRequest { request } if request.url.contains("/head")
        )));
    }

    #[test]
    fn http_head_response_triggers_fetch_request() {
        let mut engine = CoreEngine::new();
        engine
            .handle_command(CoreCommand::ImportDeploymentBundle {
                bundle: sample_deployment(),
            })
            .expect("deployment");
        engine
            .handle_command(CoreCommand::CreateOrLoadIdentity {
                mnemonic: Some("alpha beta gamma".into()),
                device_name: Some("phone".into()),
            })
            .expect("identity");
        let device_id = engine
            .state
            .local_identity
            .as_ref()
            .expect("identity")
            .device_identity
            .device_id
            .clone();
        let output = engine
            .handle_command(CoreCommand::SyncInbox {
                device_id: device_id.clone(),
                reason: None,
            })
            .expect("sync");
        let request_id = output
            .effects
            .iter()
            .find_map(|effect| match effect {
                CoreEffect::ExecuteHttpRequest { request } => Some(request.request_id.clone()),
                _ => None,
            })
            .expect("head request id");
        let response = engine
            .handle_event(CoreEvent::HttpResponseReceived {
                request_id,
                status: 200,
                body: Some("{\"head_seq\":3}".into()),
            })
            .expect("http response");
        assert!(response.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::ExecuteHttpRequest { request } if request.url.contains("fromSeq=1")
        )));
    }

    #[test]
    fn refresh_identity_state_emits_identity_fetch_request() {
        let bob_bundle = sample_identity_bundle("delta epsilon zeta", "phone");
        let mut alice = seeded_engine("alpha beta gamma", "phone", bob_bundle.clone());
        let output = alice
            .handle_command(CoreCommand::RefreshIdentityState {
                user_id: bob_bundle.user_id.clone(),
            })
            .expect("refresh");
        assert!(output.effects.iter().any(|effect| matches!(
            effect,
            CoreEffect::ExecuteHttpRequest { request } if request.url.contains("identity_bundle.json")
        )));
    }

    #[test]
    fn apply_identity_bundle_update_reconciles_membership_and_queues_phase6_messages() {
        let bob_bundle = sample_identity_bundle("delta epsilon zeta", "phone");
        let mut alice = seeded_engine("alpha beta gamma", "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());

        let updated_bundle = sample_identity_bundle_with_extra_device(
            "delta epsilon zeta",
            "phone",
            "laptop",
        );
        let output = alice
            .handle_command(CoreCommand::ApplyIdentityBundleUpdate {
                bundle: updated_bundle,
            })
            .expect("apply identity update");

        assert!(output.state_update.conversations_changed);
        assert!(output.state_update.messages_changed);
        assert_eq!(
            alice.state.conversations[&conversation_id].recovery_status,
            RecoveryStatus::NeedsRecovery
        );
        assert!(alice.state.outbox.iter().any(|envelope| {
            envelope.message_type == MessageType::ControlDeviceMembershipChanged
                && envelope.conversation_id == conversation_id
        }));
        assert!(alice.state.outbox.iter().any(|envelope| {
            envelope.message_type == MessageType::MlsWelcome
                && envelope.conversation_id == conversation_id
        }));
    }

    #[test]
    fn send_text_message_is_rejected_while_membership_recovers() {
        let bob_bundle = sample_identity_bundle("delta epsilon zeta", "phone");
        let mut alice = seeded_engine("alpha beta gamma", "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());

        alice
            .handle_command(CoreCommand::ApplyIdentityBundleUpdate {
                bundle: sample_identity_bundle_with_extra_device(
                    "delta epsilon zeta",
                    "phone",
                    "laptop",
                ),
            })
            .expect("apply identity update");

        let error = alice
            .handle_command(CoreCommand::SendTextMessage {
                conversation_id,
                plaintext: "hello".into(),
            })
            .expect_err("send should fail while recovering");
        assert_eq!(error.code(), "temporary_failure");
    }

    #[test]
    fn rebuild_conversation_marks_conversation_and_mls_state() {
        let bob_bundle = sample_identity_bundle("delta epsilon zeta", "phone");
        let mut alice = seeded_engine("alpha beta gamma", "phone", bob_bundle.clone());
        let conversation_id = create_direct_conversation(&mut alice, bob_bundle.user_id.clone());
        let output = alice
            .handle_command(CoreCommand::RebuildConversation {
                conversation_id: conversation_id.clone(),
            })
            .expect("rebuild");
        assert!(output.state_update.conversations_changed);
        assert_eq!(
            alice.state.conversations[&conversation_id].conversation.state,
            ConversationState::NeedsRebuild
        );
        assert_eq!(
            alice.state.mls_summaries[&conversation_id].status,
            MlsStateStatus::NeedsRebuild
        );
    }

    fn sample_identity_bundle(mnemonic: &str, device_name: &str) -> IdentityBundle {
        let identity = IdentityManager::create_or_recover(Some(mnemonic), Some(device_name)).expect("identity");
        let package = MlsAdapter::generate_key_package(&identity, 0).expect("package");
        IdentityManager::export_identity_bundle(
            &identity,
            &sample_deployment(),
            package.key_package_b64,
            package.expires_at,
        )
        .expect("bundle")
    }

    fn sample_identity_bundle_with_extra_device(
        mnemonic: &str,
        primary_device_name: &str,
        extra_device_name: &str,
    ) -> IdentityBundle {
        let primary = IdentityManager::create_or_recover(Some(mnemonic), Some(primary_device_name))
            .expect("primary identity");
        let extra = IdentityManager::create_or_recover(Some(mnemonic), Some(extra_device_name))
            .expect("extra identity");
        let primary_package = MlsAdapter::generate_key_package(&primary, 0).expect("primary package");
        let extra_package = MlsAdapter::generate_key_package(&extra, 0).expect("extra package");

        let primary_profile = CapabilityManager::build_device_contact_profile(
            &primary,
            &sample_deployment(),
            primary_package.key_package_b64.clone(),
            primary_package.expires_at,
        )
        .expect("primary profile");
        let extra_profile = CapabilityManager::build_device_contact_profile(
            &extra,
            &sample_deployment(),
            extra_package.key_package_b64.clone(),
            extra_package.expires_at,
        )
        .expect("extra profile");

        let mut bundle = IdentityBundle {
            version: CURRENT_MODEL_VERSION.to_string(),
            user_id: primary.user_identity.user_id.clone(),
            user_public_key: primary.user_identity.user_public_key.clone(),
            devices: vec![primary_profile, extra_profile],
            device_status_ref: Some(format!(
                "{}/state/{}/device_status.json",
                sample_deployment()
                    .storage_base_info
                    .base_url
                    .clone()
                    .unwrap_or_default(),
                primary.user_identity.user_id
            )),
            storage_profile: Some(crate::model::StorageProfile {
                base_url: sample_deployment().storage_base_info.base_url.clone(),
                profile_ref: Some(format!(
                    "{}/state/{}/storage_profile.json",
                    sample_deployment()
                        .storage_base_info
                        .base_url
                        .clone()
                        .unwrap_or_default(),
                    primary.user_identity.user_id
                )),
            }),
            updated_at: 1,
            signature: String::new(),
        };
        let payload = {
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
        };
        bundle.signature = crate::identity::encode_hex(
            &primary
                .user_root_signing_key()
                .sign(payload.as_bytes())
                .to_bytes(),
        );
        bundle
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
        IdentityManager::export_identity_bundle(
            identity,
            &sample_deployment(),
            package.key_package_b64.clone(),
            package.expires_at,
        )
        .expect("bundle")
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

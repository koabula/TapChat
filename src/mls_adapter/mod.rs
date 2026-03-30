use std::collections::{BTreeMap, BTreeSet};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use openmls::prelude::{tls_codec::Deserialize, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde::{Deserialize as SerdeDeserialize, Serialize};

use crate::error::{CoreError, CoreResult};
use crate::identity::LocalIdentityState;
use crate::model::{MessageType, MlsStateStatus, MlsStateSummary};

pub const DEFAULT_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MlsAdapterModule;

impl MlsAdapterModule {
    pub fn name(&self) -> &'static str {
        "mls_adapter"
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, SerdeDeserialize)]
pub struct PublishedKeyPackage {
    pub key_package_ref: String,
    pub key_package_b64: String,
    pub expires_at: u64,
    pub credential_identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerDeviceKeyPackage {
    pub user_id: String,
    pub device_id: String,
    pub device_public_key: String,
    pub key_package_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WelcomeEnvelope {
    pub recipient_device_id: String,
    pub payload_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateConversationArtifacts {
    pub commit_b64: String,
    pub welcomes: Vec<WelcomeEnvelope>,
    pub member_device_ids: Vec<String>,
    pub epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoveMembersArtifacts {
    pub commit_b64: String,
    pub removed_device_ids: Vec<String>,
    pub member_device_ids: Vec<String>,
    pub epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundMlsMessage {
    pub payload_b64: String,
    pub epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedApplicationMessage {
    pub plaintext: Vec<u8>,
    pub sender_identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestResult {
    AppliedApplication(DecryptedApplicationMessage),
    AppliedCommit { epoch: u64 },
    AppliedWelcome { epoch: u64 },
    PendingRetry,
    NeedsRebuild,
}

#[derive(Debug)]
struct LocalMlsState {
    group: MlsGroup,
    member_device_ids: BTreeSet<String>,
    status: MlsStateStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, SerdeDeserialize)]
struct SerializableStore {
    values: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, SerdeDeserialize)]
struct PersistedGroupState {
    credential_identity: String,
    local_device_id: String,
    signer: SignatureKeyPair,
    credential_with_key: CredentialWithKey,
    storage: SerializableStore,
}

#[derive(Debug, Default)]
pub struct RestoreMlsStateResult {
    pub adapter: Option<MlsAdapter>,
    pub summaries: BTreeMap<String, MlsStateSummary>,
    pub failed_conversation_ids: Vec<String>,
}

pub struct MlsAdapter {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential_with_key: CredentialWithKey,
    credential_identity: String,
    local_device_id: String,
    groups: BTreeMap<String, LocalMlsState>,
}

impl std::fmt::Debug for MlsAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlsAdapter")
            .field("credential_identity", &self.credential_identity)
            .field("local_device_id", &self.local_device_id)
            .field("groups_len", &self.groups.len())
            .finish()
    }
}

impl MlsAdapter {
    pub fn bootstrap(local_identity: &LocalIdentityState) -> CoreResult<(Self, PublishedKeyPackage)> {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(DEFAULT_CIPHERSUITE.signature_algorithm())
            .map_err(|error| CoreError::invalid_state(format!("failed to create MLS signer: {error}")))?;
        signer
            .store(provider.storage())
            .map_err(|error| CoreError::invalid_state(format!("failed to store MLS signer: {error}")))?;

        let credential_identity = build_credential_identity(local_identity);
        let credential = BasicCredential::new(credential_identity.clone().into_bytes());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.to_public_vec().into(),
        };
        let key_package_bundle = KeyPackage::builder()
            .build(DEFAULT_CIPHERSUITE, &provider, &signer, credential_with_key.clone())
            .map_err(|error| CoreError::invalid_state(format!("failed to build key package: {error}")))?;
        let key_package = key_package_bundle.key_package().clone();
        let key_package_bytes = MlsMessageOut::from(key_package)
            .to_bytes()
            .map_err(|error| CoreError::invalid_state(format!("failed to encode key package: {error}")))?;
        let key_package_b64 = BASE64.encode(key_package_bytes);

        let adapter = Self {
            provider,
            signer,
            credential_with_key,
            credential_identity: credential_identity.clone(),
            local_device_id: local_identity.device_identity.device_id.clone(),
            groups: BTreeMap::new(),
        };

        Ok((
            adapter,
            PublishedKeyPackage {
                key_package_ref: key_package_b64.clone(),
                key_package_b64,
                expires_at: 86_400,
                credential_identity,
            },
        ))
    }

    pub fn generate_key_package(local_identity: &LocalIdentityState, _now: u64) -> CoreResult<PublishedKeyPackage> {
        let (_, package) = Self::bootstrap(local_identity)?;
        Ok(package)
    }

    pub fn create_conversation(
        &mut self,
        conversation_id: &str,
        peer_devices_with_keypackages: &[PeerDeviceKeyPackage],
    ) -> CoreResult<CreateConversationArtifacts> {
        if conversation_id.trim().is_empty() {
            return Err(CoreError::invalid_input("conversation_id must not be empty"));
        }
        if peer_devices_with_keypackages.is_empty() {
            return Err(CoreError::invalid_input(
                "peer_devices_with_keypackages must not be empty",
            ));
        }

        let group_id = GroupId::from_slice(conversation_id.as_bytes());
        let config = MlsGroupCreateConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let mut group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            group_id,
            self.credential_with_key.clone(),
        )
        .map_err(|error| CoreError::invalid_state(format!("failed to create MLS group: {error}")))?;

        let mut member_device_ids = BTreeSet::from([self.local_device_id.clone()]);
        let mut key_packages = Vec::with_capacity(peer_devices_with_keypackages.len());
        for peer in peer_devices_with_keypackages {
            if peer.device_id.trim().is_empty() {
                return Err(CoreError::invalid_input("peer device_id must not be empty"));
            }
            member_device_ids.insert(peer.device_id.clone());
            key_packages.push(decode_key_package(&peer.key_package_b64)?);
        }

        let (commit, welcome, _group_info) = group
            .add_members(&self.provider, &self.signer, &key_packages)
            .map_err(|error| CoreError::invalid_state(format!("failed to add MLS members: {error}")))?;
        group
            .merge_pending_commit(&self.provider)
            .map_err(|error| CoreError::invalid_state(format!("failed to merge pending commit: {error}")))?;

        let commit_b64 = encode_mls_message(commit)?;
        let welcome_b64 = encode_mls_message(welcome)?;

        self.groups.insert(
            conversation_id.to_string(),
            LocalMlsState {
                group,
                member_device_ids: member_device_ids.clone(),
                status: MlsStateStatus::Active,
            },
        );

        Ok(CreateConversationArtifacts {
            commit_b64,
            welcomes: peer_devices_with_keypackages
                .iter()
                .map(|peer| WelcomeEnvelope {
                    recipient_device_id: peer.device_id.clone(),
                    payload_b64: welcome_b64.clone(),
                })
                .collect(),
            member_device_ids: member_device_ids.into_iter().collect(),
            epoch: self.export_group_summary(conversation_id)?.epoch,
        })
    }

    pub fn add_members(
        &mut self,
        conversation_id: &str,
        peer_devices_with_keypackages: &[PeerDeviceKeyPackage],
    ) -> CoreResult<CreateConversationArtifacts> {
        if peer_devices_with_keypackages.is_empty() {
            return Err(CoreError::invalid_input(
                "peer_devices_with_keypackages must not be empty",
            ));
        }
        let state = self
            .groups
            .get_mut(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation MLS state does not exist"))?;

        let mut key_packages = Vec::with_capacity(peer_devices_with_keypackages.len());
        for peer in peer_devices_with_keypackages {
            if peer.device_id.trim().is_empty() {
                return Err(CoreError::invalid_input("peer device_id must not be empty"));
            }
            key_packages.push(decode_key_package(&peer.key_package_b64)?);
        }

        let (commit, welcome, _group_info) = state
            .group
            .add_members(&self.provider, &self.signer, &key_packages)
            .map_err(|error| {
                CoreError::invalid_state(format!("failed to add MLS members: {error}"))
            })?;
        state
            .group
            .merge_pending_commit(&self.provider)
            .map_err(|error| {
                CoreError::invalid_state(format!("failed to merge pending commit: {error}"))
            })?;
        for peer in peer_devices_with_keypackages {
            state.member_device_ids.insert(peer.device_id.clone());
        }
        state.status = MlsStateStatus::Active;

        let commit_b64 = encode_mls_message(commit)?;
        let welcome_b64 = encode_mls_message(welcome)?;
        Ok(CreateConversationArtifacts {
            commit_b64,
            welcomes: peer_devices_with_keypackages
                .iter()
                .map(|peer| WelcomeEnvelope {
                    recipient_device_id: peer.device_id.clone(),
                    payload_b64: welcome_b64.clone(),
                })
                .collect(),
            member_device_ids: state.member_device_ids.iter().cloned().collect(),
            epoch: state.group.epoch().as_u64(),
        })
    }

    pub fn remove_members(
        &mut self,
        conversation_id: &str,
        device_ids: &[String],
    ) -> CoreResult<RemoveMembersArtifacts> {
        if device_ids.is_empty() {
            return Err(CoreError::invalid_input("device_ids must not be empty"));
        }
        let state = self
            .groups
            .get_mut(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation MLS state does not exist"))?;

        let leaf_indices = member_leaf_indices_for_devices(&state.group, device_ids)?;
        let (commit, _welcome, _group_info) = state
            .group
            .remove_members(&self.provider, &self.signer, &leaf_indices)
            .map_err(|error| {
                CoreError::invalid_state(format!("failed to remove MLS members: {error}"))
            })?;
        state
            .group
            .merge_pending_commit(&self.provider)
            .map_err(|error| {
                CoreError::invalid_state(format!("failed to merge pending commit: {error}"))
            })?;
        for device_id in device_ids {
            state.member_device_ids.remove(device_id);
        }
        state.status = MlsStateStatus::Active;

        Ok(RemoveMembersArtifacts {
            commit_b64: encode_mls_message(commit)?,
            removed_device_ids: device_ids.to_vec(),
            member_device_ids: state.member_device_ids.iter().cloned().collect(),
            epoch: state.group.epoch().as_u64(),
        })
    }

    pub fn encrypt_application(
        &mut self,
        conversation_id: &str,
        plaintext_bytes: &[u8],
    ) -> CoreResult<OutboundMlsMessage> {
        let provider = &self.provider;
        let signer = &self.signer;
        let state = self
            .groups
            .get_mut(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation MLS state does not exist"))?;
        let message = state
            .group
            .create_message(provider, signer, plaintext_bytes)
            .map_err(|error| CoreError::invalid_state(format!("failed to create MLS application: {error}")))?;
        Ok(OutboundMlsMessage {
            payload_b64: encode_mls_message(message)?,
            epoch: state.group.epoch().as_u64(),
        })
    }

    pub fn ingest_message(
        &mut self,
        conversation_id: &str,
        sender_device_id: &str,
        message_type: MessageType,
        payload_b64: &str,
    ) -> CoreResult<IngestResult> {
        match message_type {
            MessageType::MlsWelcome => self.ingest_welcome(conversation_id, payload_b64),
            MessageType::MlsCommit | MessageType::MlsApplication => {
                if !self.groups.contains_key(conversation_id) {
                    return Ok(IngestResult::PendingRetry);
                }
                self.ingest_protocol_message(conversation_id, sender_device_id, message_type, payload_b64)
            }
            _ => Err(CoreError::unsupported(
                "mls adapter only supports MLS message types",
            )),
        }
    }

    pub fn export_group_summary(&self, conversation_id: &str) -> CoreResult<MlsStateSummary> {
        let state = self
            .groups
            .get(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation MLS state does not exist"))?;
        Ok(MlsStateSummary {
            conversation_id: conversation_id.to_string(),
            epoch: state.group.epoch().as_u64(),
            member_device_ids: state.member_device_ids.iter().cloned().collect(),
            status: state.status,
            updated_at: state.group.epoch().as_u64(),
        })
    }

    pub fn mark_recovery_needed(&mut self, conversation_id: &str) {
        if let Some(state) = self.groups.get_mut(conversation_id) {
            state.status = MlsStateStatus::NeedsRecovery;
        }
    }

    pub fn mark_needs_rebuild(&mut self, conversation_id: &str) {
        if let Some(state) = self.groups.get_mut(conversation_id) {
            state.status = MlsStateStatus::NeedsRebuild;
        }
    }

    pub fn attempt_recovery(&mut self, conversation_id: &str) -> CoreResult<MlsStateSummary> {
        let state = self
            .groups
            .get_mut(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation MLS state does not exist"))?;
        if state.status == MlsStateStatus::NeedsRebuild {
            return Err(CoreError::invalid_state(
                "conversation MLS state requires rebuild",
            ));
        }
        state.status = MlsStateStatus::Active;
        self.export_group_summary(conversation_id)
    }

    pub fn clear_conversation(&mut self, conversation_id: &str) {
        self.groups.remove(conversation_id);
    }

    pub fn export_persisted_group_state(&self, conversation_id: &str) -> CoreResult<String> {
        if !self.groups.contains_key(conversation_id) {
            return Err(CoreError::invalid_input("conversation MLS state does not exist"));
        }
        let values = self.provider.storage().values.read().map_err(|_| {
            CoreError::invalid_state("failed to read MLS provider storage for persistence")
        })?;
        let storage = SerializableStore {
            values: values
                .iter()
                .map(|(key, value)| (BASE64.encode(key), BASE64.encode(value)))
                .collect(),
        };
        serde_json::to_string(&PersistedGroupState {
            credential_identity: self.credential_identity.clone(),
            local_device_id: self.local_device_id.clone(),
            signer: copy_signer(&self.signer)?,
            credential_with_key: self.credential_with_key.clone(),
            storage,
        })
        .map_err(|error| {
            CoreError::invalid_state(format!("failed to serialize MLS group state: {error}"))
        })
    }

    pub fn restore_from_persisted_states(
        persisted_states: &[(String, MlsStateSummary, Option<String>)],
    ) -> CoreResult<RestoreMlsStateResult> {
        if persisted_states.is_empty() {
            return Ok(RestoreMlsStateResult::default());
        }

        let mut parsed_states = Vec::new();
        let mut failed_conversation_ids = Vec::new();
        let provider = OpenMlsRustCrypto::default();
        let mut template: Option<(SignatureKeyPair, CredentialWithKey, String, String)> = None;

        for (conversation_id, summary, serialized_state) in persisted_states {
            let Some(serialized_state) = serialized_state.as_ref() else {
                failed_conversation_ids.push(conversation_id.clone());
                continue;
            };
            let parsed: PersistedGroupState = match serde_json::from_str(serialized_state) {
                Ok(parsed) => parsed,
                Err(_) => {
                    failed_conversation_ids.push(conversation_id.clone());
                    continue;
                }
            };

            let PersistedGroupState {
                credential_identity,
                local_device_id,
                signer,
                credential_with_key,
                storage,
            } = parsed;

            if let Some((_, _, template_identity, template_device_id)) = template.as_ref() {
                if template_identity != &credential_identity
                    || template_device_id != &local_device_id
                {
                    failed_conversation_ids.push(conversation_id.clone());
                    continue;
                }
            } else {
                template = Some((
                    signer,
                    credential_with_key,
                    credential_identity.clone(),
                    local_device_id.clone(),
                ));
            }

            {
                let mut values = provider.storage().values.write().map_err(|_| {
                    CoreError::invalid_state("failed to write restored MLS provider storage")
                })?;
                for (key, value) in &storage.values {
                    let decoded_key = BASE64.decode(key).map_err(|_| {
                        CoreError::invalid_input("invalid persisted MLS storage key")
                    })?;
                    let decoded_value = BASE64.decode(value).map_err(|_| {
                        CoreError::invalid_input("invalid persisted MLS storage value")
                    })?;
                    values.insert(decoded_key, decoded_value);
                }
            }

            parsed_states.push((conversation_id.clone(), summary.clone()));
        }

        let Some((signer, credential_with_key, credential_identity, local_device_id)) = template
        else {
            let summaries = persisted_states
                .iter()
                .map(|(conversation_id, summary, _)| (conversation_id.clone(), summary.clone()))
                .collect();
            return Ok(RestoreMlsStateResult {
                adapter: None,
                summaries,
                failed_conversation_ids,
            });
        };

        let mut adapter = Self {
            provider,
            signer,
            credential_with_key,
            credential_identity,
            local_device_id,
            groups: BTreeMap::new(),
        };
        let mut summaries = BTreeMap::new();

        for (conversation_id, mut summary) in parsed_states {
            let group_id = GroupId::from_slice(conversation_id.as_bytes());
            let Some(group) = MlsGroup::load(adapter.provider.storage(), &group_id)
                .map_err(|error| {
                    CoreError::invalid_state(format!(
                        "failed to load persisted MLS group state: {error}"
                    ))
                })? else {
                failed_conversation_ids.push(conversation_id.clone());
                summary.status = MlsStateStatus::NeedsRebuild;
                summaries.insert(conversation_id, summary);
                continue;
            };

            let member_device_ids = extract_member_device_ids(&group)?;
            let status = summary.status;
            adapter.groups.insert(
                conversation_id.clone(),
                LocalMlsState {
                    group,
                    member_device_ids,
                    status,
                },
            );
            let exported = adapter.export_group_summary(&conversation_id)?;
            summaries.insert(
                conversation_id,
                MlsStateSummary {
                    status,
                    ..exported
                },
            );
        }

        Ok(RestoreMlsStateResult {
            adapter: Some(adapter),
            summaries,
            failed_conversation_ids,
        })
    }

    fn ingest_welcome(&mut self, conversation_id: &str, payload_b64: &str) -> CoreResult<IngestResult> {
        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let welcome_bytes = BASE64
            .decode(payload_b64)
            .map_err(|_| CoreError::invalid_input("invalid base64 welcome payload"))?;
        let welcome_message =
            MlsMessageIn::tls_deserialize_exact(welcome_bytes).map_err(|error| {
                CoreError::invalid_input(format!("failed to decode welcome message: {error}"))
            })?;
        let welcome = match welcome_message.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => {
                return Err(CoreError::invalid_input(
                    "decoded MLS message was not a welcome",
                ))
            }
        };
        let staged = StagedWelcome::new_from_welcome(
            &self.provider,
            &config,
            welcome,
            None,
        )
        .map_err(|error| CoreError::invalid_state(format!("failed to stage welcome: {error}")))?;
        let group = staged
            .into_group(&self.provider)
            .map_err(|error| CoreError::invalid_state(format!("failed to join group from welcome: {error}")))?;
        let member_device_ids = extract_member_device_ids(&group)?;
        self.groups.insert(
            conversation_id.to_string(),
            LocalMlsState {
                group,
                member_device_ids,
                status: MlsStateStatus::Active,
            },
        );
        Ok(IngestResult::AppliedWelcome {
            epoch: self.export_group_summary(conversation_id)?.epoch,
        })
    }

    fn ingest_protocol_message(
        &mut self,
        conversation_id: &str,
        _sender_device_id: &str,
        message_type: MessageType,
        payload_b64: &str,
    ) -> CoreResult<IngestResult> {
        let provider = &self.provider;
        let state = self
            .groups
            .get_mut(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation MLS state does not exist"))?;
        let message_in = decode_mls_message(payload_b64)?;
        let protocol_message = message_in
            .try_into_protocol_message()
            .map_err(|_| CoreError::invalid_input("expected a protocol MLS message"))?;
        let processed = match state.group.process_message(provider, protocol_message) {
            Ok(processed) => processed,
            Err(_) => {
                state.status = MlsStateStatus::NeedsRecovery;
                return Ok(IngestResult::PendingRetry);
            }
        };
        let sender_identity = extract_sender_identity(processed.credential())?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(application) => {
                state.status = MlsStateStatus::Active;
                Ok(IngestResult::AppliedApplication(DecryptedApplicationMessage {
                    plaintext: application.into_bytes(),
                    sender_identity,
                }))
            }
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                if message_type != MessageType::MlsCommit {
                    state.status = MlsStateStatus::NeedsRebuild;
                    return Ok(IngestResult::NeedsRebuild);
                }
                state
                    .group
                    .merge_staged_commit(provider, *staged_commit)
                    .map_err(|_| CoreError::invalid_state("failed to merge staged commit"))?;
                state.member_device_ids = extract_member_device_ids(&state.group)?;
                state.status = MlsStateStatus::Active;
                Ok(IngestResult::AppliedCommit {
                    epoch: state.group.epoch().as_u64(),
                })
            }
            _ => {
                state.status = MlsStateStatus::NeedsRecovery;
                Ok(IngestResult::PendingRetry)
            }
        }
    }
}

fn build_credential_identity(local_identity: &LocalIdentityState) -> String {
    format!(
        "{}|{}|{}|{}",
        local_identity.user_identity.user_id,
        local_identity.device_identity.device_id,
        local_identity.device_identity.device_public_key,
        local_identity.device_identity.binding.signature,
    )
}

fn extract_sender_identity(credential: &Credential) -> CoreResult<String> {
    let basic = BasicCredential::try_from(credential.clone())
        .map_err(|_| CoreError::invalid_input("unsupported MLS credential type"))?;
    String::from_utf8(basic.identity().to_vec())
        .map_err(|_| CoreError::invalid_input("credential identity must be utf-8"))
}

fn extract_member_device_ids(group: &MlsGroup) -> CoreResult<BTreeSet<String>> {
    let mut members = BTreeSet::new();
    for member in group.members() {
        let identity = extract_sender_identity(&member.credential)?;
        let device_id = identity
            .split('|')
            .nth(1)
            .ok_or_else(|| CoreError::invalid_input("credential identity missing device_id"))?;
        members.insert(device_id.to_string());
    }
    Ok(members)
}

fn member_leaf_indices_for_devices(
    group: &MlsGroup,
    device_ids: &[String],
) -> CoreResult<Vec<LeafNodeIndex>> {
    let mut indices = Vec::with_capacity(device_ids.len());
    for device_id in device_ids {
        let member = group
            .members()
            .find(|member| {
                extract_sender_identity(&member.credential)
                    .ok()
                    .and_then(|identity| identity.split('|').nth(1).map(str::to_string))
                    .as_deref()
                    == Some(device_id.as_str())
            })
            .ok_or_else(|| {
                CoreError::invalid_input(format!(
                    "MLS member for device {device_id} does not exist"
                ))
            })?;
        indices.push(member.index);
    }
    Ok(indices)
}

fn encode_mls_message(message: MlsMessageOut) -> CoreResult<String> {
    Ok(BASE64.encode(
        message
            .to_bytes()
            .map_err(|error| CoreError::invalid_state(format!("failed to encode MLS message: {error}")))?,
    ))
}

fn decode_mls_message(payload_b64: &str) -> CoreResult<MlsMessageIn> {
    let bytes = BASE64
        .decode(payload_b64)
        .map_err(|_| CoreError::invalid_input("invalid base64 MLS message payload"))?;
    MlsMessageIn::tls_deserialize_exact(bytes)
        .map_err(|error| CoreError::invalid_input(format!("failed to decode MLS message: {error}")))
}

fn decode_key_package(payload_b64: &str) -> CoreResult<KeyPackage> {
    let bytes = BASE64
        .decode(payload_b64)
        .map_err(|_| CoreError::invalid_input("invalid base64 key package payload"))?;
    let message = MlsMessageIn::tls_deserialize_exact(bytes)
        .map_err(|error| CoreError::invalid_input(format!("failed to decode key package message: {error}")))?;
    match message.extract() {
        MlsMessageBodyIn::KeyPackage(key_package) => {
            let provider = OpenMlsRustCrypto::default();
            key_package
                .validate(provider.crypto(), ProtocolVersion::Mls10)
                .map_err(|error| {
                    CoreError::invalid_input(format!("failed to validate key package: {error}"))
                })
        }
        _ => Err(CoreError::invalid_input(
            "decoded MLS message was not a key package",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        IngestResult, MlsAdapter, MlsAdapterModule, PeerDeviceKeyPackage,
    };
    use crate::identity::IdentityManager;
    use crate::model::{MessageType, MlsStateStatus};

    const ALICE_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const BOB_MNEMONIC: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";

    #[test]
    fn module_name_is_stable() {
        assert_eq!(MlsAdapterModule.name(), "mls_adapter");
    }

    #[test]
    fn key_package_can_be_generated() {
        let identity = IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone"))
            .expect("identity");
        let package = MlsAdapter::generate_key_package(&identity, 0).expect("package");
        assert!(!package.key_package_b64.is_empty());
    }

    #[test]
    fn welcome_import_and_application_message_round_trip() {
        let alice_identity =
            IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone"))
                .expect("alice");
        let bob_identity = IdentityManager::create_or_recover(Some(BOB_MNEMONIC), Some("phone"))
            .expect("bob");

        let (mut alice_adapter, _) = MlsAdapter::bootstrap(&alice_identity).expect("alice adapter");
        let (mut bob_adapter, bob_package) = MlsAdapter::bootstrap(&bob_identity).expect("bob adapter");

        let artifacts = alice_adapter
            .create_conversation(
                "conv:alice:bob",
                &[PeerDeviceKeyPackage {
                    user_id: bob_identity.user_identity.user_id.clone(),
                    device_id: bob_identity.device_identity.device_id.clone(),
                    device_public_key: bob_identity.device_identity.device_public_key.clone(),
                    key_package_b64: bob_package.key_package_b64,
                }],
            )
            .expect("create conversation");

        let welcome_result = bob_adapter
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsWelcome,
                &artifacts.welcomes[0].payload_b64,
            )
            .expect("welcome");
        assert!(matches!(welcome_result, IngestResult::AppliedWelcome { .. }));

        let commit_result = bob_adapter
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsCommit,
                &artifacts.commit_b64,
            )
            .expect("commit");
        assert!(matches!(
            commit_result,
            IngestResult::AppliedCommit { .. } | IngestResult::PendingRetry
        ));

        let outbound = alice_adapter
            .encrypt_application("conv:alice:bob", b"hello bob")
            .expect("application");
        let received = bob_adapter
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsApplication,
                &outbound.payload_b64,
            )
            .expect("receive");
        match received {
            IngestResult::AppliedApplication(application) => {
                assert_eq!(application.plaintext, b"hello bob");
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn persisted_group_state_restores_application_flow() {
        let alice_identity =
            IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone"))
                .expect("alice");
        let bob_identity = IdentityManager::create_or_recover(Some(BOB_MNEMONIC), Some("phone"))
            .expect("bob");

        let (mut alice_adapter, _) = MlsAdapter::bootstrap(&alice_identity).expect("alice adapter");
        let (mut bob_adapter, bob_package) = MlsAdapter::bootstrap(&bob_identity).expect("bob adapter");

        let artifacts = alice_adapter
            .create_conversation(
                "conv:alice:bob",
                &[PeerDeviceKeyPackage {
                    user_id: bob_identity.user_identity.user_id.clone(),
                    device_id: bob_identity.device_identity.device_id.clone(),
                    device_public_key: bob_identity.device_identity.device_public_key.clone(),
                    key_package_b64: bob_package.key_package_b64,
                }],
            )
            .expect("create conversation");

        bob_adapter
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsWelcome,
                &artifacts.welcomes[0].payload_b64,
            )
            .expect("welcome");
        let _ = bob_adapter
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsCommit,
                &artifacts.commit_b64,
            )
            .expect("commit");

        let serialized = bob_adapter
            .export_persisted_group_state("conv:alice:bob")
            .expect("persisted state");
        let summary = bob_adapter
            .export_group_summary("conv:alice:bob")
            .expect("summary");

        let restored = MlsAdapter::restore_from_persisted_states(&[(
            "conv:alice:bob".into(),
            summary,
            Some(serialized),
        )])
        .expect("restore");
        let mut restored_bob = restored.adapter.expect("adapter");

        let outbound = alice_adapter
            .encrypt_application("conv:alice:bob", b"after restore")
            .expect("application");
        let received = restored_bob
            .ingest_message(
                "conv:alice:bob",
                &alice_identity.device_identity.device_id,
                MessageType::MlsApplication,
                &outbound.payload_b64,
            )
            .expect("receive");

        match received {
            IngestResult::AppliedApplication(application) => {
                assert_eq!(application.plaintext, b"after restore");
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn restore_marks_missing_serialized_state_as_failed() {
        let restored = MlsAdapter::restore_from_persisted_states(&[(
            "conv:broken".into(),
            crate::model::MlsStateSummary {
                conversation_id: "conv:broken".into(),
                epoch: 1,
                member_device_ids: vec!["device:bob:phone".into()],
                status: MlsStateStatus::Active,
                updated_at: 1,
            },
            None,
        )])
        .expect("restore");

        assert!(restored.adapter.is_none());
        assert_eq!(restored.failed_conversation_ids, vec!["conv:broken".to_string()]);
        assert_eq!(
            restored
                .summaries
                .get("conv:broken")
                .expect("summary")
                .conversation_id,
            "conv:broken"
        );
    }
}

fn copy_signer(signer: &SignatureKeyPair) -> CoreResult<SignatureKeyPair> {
    let serialized = serde_json::to_vec(signer)
        .map_err(|error| CoreError::invalid_state(format!("failed to encode MLS signer: {error}")))?;
    serde_json::from_slice(&serialized)
        .map_err(|error| CoreError::invalid_state(format!("failed to decode MLS signer: {error}")))
}

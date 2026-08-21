use bip39::{Language, Mnemonic};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

use crate::capability::CapabilityManager;
use crate::error::{CoreError, CoreResult};
use crate::model::{
    DeploymentBundle, DeviceBinding, DeviceIdentity, DeviceStatus, DeviceStatusKind, EnvelopeV2,
    IdentityBundle, MlsDeviceKeyBinding, RelationshipDecisionProofV2, RelationshipProposalV2,
    StorageProfile, UserIdentity, Validate, CURRENT_MODEL_VERSION, ENVELOPE_SENDER_PROOF_V2,
    IDENTITY_PUBLICATION_VERSION_V2, MLS_CIPHERSUITE_V2,
};

type HmacSha512 = Hmac<Sha512>;

const HARDENED_OFFSET: u32 = 0x8000_0000;
const USER_ROOT_DERIVATION_PATH: [u32; 5] = [44, 7330, 0, 0, 0];
const DEFAULT_MNEMONIC_WORDS: usize = 12;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IdentityModule;

impl IdentityModule {
    pub fn name(&self) -> &'static str {
        "identity"
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalIdentityState {
    pub mnemonic: String,
    pub user_identity: UserIdentity,
    pub device_identity: DeviceIdentity,
    pub device_status: DeviceStatus,
    // Restored from the BIP-39 mnemonic through the fixed TapChat HD path.
    user_root_signing_key: [u8; 32],
    // Generated per device and persisted locally; not recovered from the mnemonic.
    device_signing_key: [u8; 32],
}

impl LocalIdentityState {
    pub fn user_root_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.user_root_signing_key)
    }

    pub fn device_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.device_signing_key)
    }

    pub fn device_signing_key_bytes(&self) -> [u8; 32] {
        self.device_signing_key
    }

    pub fn sign_sender_proof(&self, payload: &[u8]) -> String {
        let signature = self.device_signing_key().sign(payload);
        encode_hex(&signature.to_bytes())
    }

    /// Signs a protocol payload with the persisted device key.  Callers must
    /// construct a domain-separated canonical payload before invoking this
    /// method; the raw private key never crosses the identity boundary.
    pub fn sign_device_payload(&self, payload: &[u8]) -> String {
        self.sign_sender_proof(payload)
    }

    pub fn build_mls_device_key_binding(
        &self,
        mls_signature_public_key: String,
        created_at: u64,
    ) -> MlsDeviceKeyBinding {
        let unsigned = MlsDeviceKeyBinding {
            version: CURRENT_MODEL_VERSION.to_string(),
            user_id: self.user_identity.user_id.clone(),
            device_id: self.device_identity.device_id.clone(),
            device_public_key: self.device_identity.device_public_key.clone(),
            mls_signature_public_key,
            ciphersuite: MLS_CIPHERSUITE_V2.to_string(),
            created_at,
            signature: String::new(),
        };
        let signature = self
            .device_signing_key()
            .sign(&mls_device_key_binding_payload(&unsigned));
        MlsDeviceKeyBinding {
            signature: encode_hex(&signature.to_bytes()),
            ..unsigned
        }
    }

    pub fn sign_envelope_v2(&self, envelope: &mut EnvelopeV2) -> CoreResult<()> {
        envelope.sender_proof.proof_type = ENVELOPE_SENDER_PROOF_V2.to_string();
        envelope.sender_proof.value.clear();
        envelope.sender_proof.value =
            self.sign_sender_proof(&envelope_v2_signing_payload(envelope)?);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredUserRoot {
    pub mnemonic: String,
    pub user_identity: UserIdentity,
    user_root_signing_key: [u8; 32],
}

impl RecoveredUserRoot {
    pub fn user_root_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.user_root_signing_key)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct IdentityManager;

impl IdentityManager {
    pub fn generate_mnemonic() -> CoreResult<String> {
        let entropy_len = match DEFAULT_MNEMONIC_WORDS {
            12 => 16,
            15 => 20,
            18 => 24,
            21 => 28,
            24 => 32,
            _ => {
                return Err(CoreError::invalid_state(
                    "unsupported default BIP-39 mnemonic word count",
                ));
            }
        };
        let mut entropy = vec![0_u8; entropy_len];
        rand::thread_rng().fill_bytes(&mut entropy);
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy).map_err(|error| {
            CoreError::invalid_state(format!("failed to generate mnemonic: {error}"))
        })?;
        Ok(mnemonic.to_string())
    }

    pub fn recover_user_root(mnemonic: &str) -> CoreResult<RecoveredUserRoot> {
        let normalized_mnemonic = normalize_mnemonic(mnemonic)?;
        let bip39 = parse_mnemonic(&normalized_mnemonic)?;
        let seed = bip39.to_seed("");
        let user_root_seed = derive_slip10_ed25519_key(&seed, &USER_ROOT_DERIVATION_PATH)?;
        let user_root_key = SigningKey::from_bytes(&user_root_seed);
        let user_public_key = encode_hex(user_root_key.verifying_key().as_bytes());
        let user_id = format!(
            "user:{}",
            short_fingerprint(user_root_key.verifying_key().as_bytes(), 16)
        );
        let user_identity = UserIdentity {
            version: CURRENT_MODEL_VERSION.to_string(),
            user_id,
            user_public_key,
            created_at: 0,
        };
        user_identity.validate()?;

        Ok(RecoveredUserRoot {
            mnemonic: normalized_mnemonic,
            user_identity,
            user_root_signing_key: user_root_seed,
        })
    }

    pub fn create_new_device_for_user(
        user_root: &RecoveredUserRoot,
        existing_device_key: Option<[u8; 32]>,
    ) -> CoreResult<LocalIdentityState> {
        let user_root_key = user_root.user_root_signing_key();
        let device_seed = existing_device_key.unwrap_or_else(generate_random_signing_key_bytes);
        let device_key = SigningKey::from_bytes(&device_seed);
        let device_public_key = encode_hex(device_key.verifying_key().as_bytes());
        let user_fingerprint = short_fingerprint(user_root_key.verifying_key().as_bytes(), 12);
        let device_id = format!(
            "device:{user_fingerprint}:{}",
            short_fingerprint(device_key.verifying_key().as_bytes(), 12)
        );
        let created_at = 0;

        let binding = build_device_binding(
            &user_root_key,
            &user_root.user_identity.user_id,
            &device_id,
            &device_public_key,
            created_at,
        );
        let device_identity = DeviceIdentity {
            version: CURRENT_MODEL_VERSION.to_string(),
            user_id: user_root.user_identity.user_id.clone(),
            device_id: device_id.clone(),
            device_public_key,
            created_at,
            binding,
        };
        let device_status = DeviceStatus {
            version: CURRENT_MODEL_VERSION.to_string(),
            user_id: user_root.user_identity.user_id.clone(),
            device_id,
            status: DeviceStatusKind::Active,
            updated_at: created_at,
        };

        device_identity.validate()?;
        device_status.validate()?;

        Ok(LocalIdentityState {
            mnemonic: user_root.mnemonic.clone(),
            user_identity: user_root.user_identity.clone(),
            device_identity,
            device_status,
            user_root_signing_key: user_root.user_root_signing_key,
            device_signing_key: device_seed,
        })
    }

    pub fn create_or_recover(
        mnemonic: Option<&str>,
        _device_name: Option<&str>,
    ) -> CoreResult<LocalIdentityState> {
        let mnemonic = match mnemonic {
            Some(value) if !value.trim().is_empty() => value.trim().to_string(),
            _ => Self::generate_mnemonic()?,
        };
        let user_root = Self::recover_user_root(&mnemonic)?;
        Self::create_new_device_for_user(&user_root, None)
    }

    pub fn verify_device_binding(user_public_key: &str, binding: &DeviceBinding) -> CoreResult<()> {
        binding.validate()?;
        let verifying_key = parse_verifying_key(user_public_key)?;
        if binding.device_public_key.trim().is_empty() {
            return Err(CoreError::invalid_input(
                "device binding device_public_key is empty",
            ));
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
        if derive_user_id_from_public_key(&bundle.user_public_key)? != bundle.user_id {
            return Err(CoreError::invalid_input(
                "identity bundle user_id is not derived from its root public key",
            ));
        }
        let verifying_key = parse_verifying_key(&bundle.user_public_key)?;
        let signature = parse_signature(&bundle.signature)?;
        let verified = verifying_key
            .verify(identity_bundle_payload(bundle).as_bytes(), &signature)
            .is_ok()
            || (bundle.publication_version == 0
                && verifying_key
                    .verify(
                        legacy_identity_bundle_payload(bundle).as_bytes(),
                        &signature,
                    )
                    .is_ok());
        if !verified {
            return Err(CoreError::invalid_input(
                "identity bundle signature mismatch",
            ));
        }
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
            if bundle.publication_version >= IDENTITY_PUBLICATION_VERSION_V2 {
                let mls_binding = device.mls_device_key_binding.as_ref().ok_or_else(|| {
                    CoreError::invalid_input("IdentityBundle V2 device is missing MLS binding")
                })?;
                Self::verify_mls_device_key_binding(mls_binding)?;
                if mls_binding.user_id != bundle.user_id
                    || mls_binding.device_id != device.device_id
                    || mls_binding.device_public_key != device.device_public_key
                {
                    return Err(CoreError::invalid_input(
                        "MLS device key binding does not match IdentityBundle device",
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn verify_mls_device_key_binding(binding: &MlsDeviceKeyBinding) -> CoreResult<()> {
        binding.validate()?;
        if binding.ciphersuite != MLS_CIPHERSUITE_V2 {
            return Err(CoreError::invalid_input(
                "unsupported MLS device key binding ciphersuite",
            ));
        }
        let signature = parse_signature(&binding.signature)?;
        parse_verifying_key(&binding.device_public_key)?
            .verify(&mls_device_key_binding_payload(binding), &signature)
            .map_err(|_| CoreError::invalid_input("MLS device key binding signature mismatch"))
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
        Self::export_identity_bundle_with_devices(
            local_identity,
            deployment,
            vec![device_profile],
            None,
            None,
        )
    }

    pub fn export_identity_bundle_with_devices(
        local_identity: &LocalIdentityState,
        deployment: &DeploymentBundle,
        devices: Vec<crate::model::DeviceContactProfile>,
        bundle_share_id: Option<String>,
        display_name: Option<String>,
    ) -> CoreResult<IdentityBundle> {
        let encoded_user_id =
            urlencoding::encode(&local_identity.user_identity.user_id).into_owned();
        let unsigned = IdentityBundle {
            version: CURRENT_MODEL_VERSION.to_string(),
            publication_version: if devices.iter().all(|device| {
                device.status != DeviceStatusKind::Active
                    || (device.mls_device_key_binding.is_some()
                        && device.key_package_claim_capability.is_some())
            }) {
                IDENTITY_PUBLICATION_VERSION_V2
            } else {
                1
            },
            publication_revision: local_identity.device_status.updated_at.max(1),
            user_id: local_identity.user_identity.user_id.clone(),
            user_public_key: local_identity.user_identity.user_public_key.clone(),
            devices,
            bundle_share_id: Some(bundle_share_id.unwrap_or_else(generate_bundle_share_id)),
            // Deployment runtime config may provide bootstrap references for publishing the
            // local user's shared state. Contact refresh must not infer these values.
            identity_bundle_ref: deployment
                .runtime_config
                .identity_bundle_ref
                .clone()
                .map(|reference| reference.replace("{userId}", &encoded_user_id)),
            device_status_ref: deployment
                .runtime_config
                .device_status_ref
                .clone()
                .map(|reference| reference.replace("{userId}", &encoded_user_id)),
            storage_profile: Some(StorageProfile {
                base_url: deployment.storage_base_info.base_url.clone(),
                profile_ref: None,
            }),
            display_name,
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
                .sign(
                    build_binding_payload(user_id, device_id, device_public_key, created_at)
                        .as_bytes(),
                )
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

fn parse_mnemonic(mnemonic: &str) -> CoreResult<Mnemonic> {
    Mnemonic::parse_in_normalized(Language::English, mnemonic)
        .map_err(|error| CoreError::invalid_input(format!("invalid BIP-39 mnemonic: {error}")))
}

fn normalize_mnemonic(mnemonic: &str) -> CoreResult<String> {
    let trimmed = mnemonic.trim();
    if trimmed.is_empty() {
        return Err(CoreError::invalid_input("mnemonic must not be empty"));
    }
    Ok(parse_mnemonic(trimmed)?.to_string())
}

fn generate_random_signing_key_bytes() -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

fn derive_slip10_ed25519_key(seed: &[u8], path: &[u32]) -> CoreResult<[u8; 32]> {
    let mut mac = HmacSha512::new_from_slice(b"ed25519 seed")
        .map_err(|_| CoreError::invalid_state("failed to initialize SLIP-0010 root HMAC"))?;
    mac.update(seed);
    let output = mac.finalize().into_bytes();
    let mut secret = [0_u8; 32];
    let mut chain_code = [0_u8; 32];
    secret.copy_from_slice(&output[..32]);
    chain_code.copy_from_slice(&output[32..]);

    for index in path {
        let hardened_index = index
            .checked_add(HARDENED_OFFSET)
            .ok_or_else(|| CoreError::invalid_state("invalid hardened derivation index"))?;
        let mut mac = HmacSha512::new_from_slice(&chain_code)
            .map_err(|_| CoreError::invalid_state("failed to initialize child derivation HMAC"))?;
        let mut data = Vec::with_capacity(1 + secret.len() + 4);
        data.push(0);
        data.extend_from_slice(&secret);
        data.extend_from_slice(&hardened_index.to_be_bytes());
        mac.update(&data);
        let output = mac.finalize().into_bytes();
        secret.copy_from_slice(&output[..32]);
        chain_code.copy_from_slice(&output[32..]);
    }

    Ok(secret)
}

pub fn identity_bundle_payload(bundle: &IdentityBundle) -> String {
    if bundle.publication_version >= IDENTITY_PUBLICATION_VERSION_V2 {
        return identity_bundle_v2_payload(bundle);
    }
    identity_bundle_payload_with_display_name(bundle, true)
}

pub fn legacy_identity_bundle_payload(bundle: &IdentityBundle) -> String {
    identity_bundle_payload_with_display_name(bundle, false)
}

fn identity_bundle_payload_with_display_name(
    bundle: &IdentityBundle,
    include_display_name: bool,
) -> String {
    let mut parts = vec![
        bundle.version.clone(),
        bundle.user_id.clone(),
        bundle.user_public_key.clone(),
    ];
    if bundle.publication_version > 0 {
        parts.push(bundle.publication_version.to_string());
        parts.push(bundle.publication_revision.to_string());
    }
    if include_display_name {
        parts.push(bundle.display_name.clone().unwrap_or_default());
    }
    parts.extend([
        bundle.updated_at.to_string(),
        bundle.bundle_share_id.clone().unwrap_or_default(),
        bundle.identity_bundle_ref.clone().unwrap_or_default(),
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
    ]);
    for device in &bundle.devices {
        parts.push(device.device_id.clone());
        parts.push(device.device_public_key.clone());
        parts.push(device.binding.signature.clone());
        parts.push(
            device
                .inbox_append_capability
                .as_ref()
                .map(|capability| capability.signature.clone())
                .unwrap_or_default(),
        );
        if bundle.publication_version > 0 {
            if let Some(keypackage_ref) = &device.keypackage_ref {
                parts.push(keypackage_ref.lifecycle_version.to_string());
                parts.push(keypackage_ref.object_ref.clone());
                parts.push(keypackage_ref.not_before.to_string());
                parts.push(keypackage_ref.created_at.to_string());
                parts.push(keypackage_ref.expires_at.to_string());
            } else {
                parts.extend([
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                ]);
            }
        } else if let Some(keypackage_ref) = &device.keypackage_ref {
            parts.push(keypackage_ref.object_ref.clone());
            parts.push(keypackage_ref.expires_at.to_string());
        } else {
            parts.extend([String::new(), String::new()]);
        }
    }
    parts.join("|")
}

fn identity_bundle_v2_payload(bundle: &IdentityBundle) -> String {
    let devices = bundle
        .devices
        .iter()
        .map(|device| {
            serde_json::json!([
                device.version,
                device.device_id,
                device.device_public_key,
                [
                    device.binding.version,
                    device.binding.user_id,
                    device.binding.device_id,
                    device.binding.device_public_key,
                    device.binding.created_at,
                    device.binding.signature
                ],
                device.status,
                device
                    .inbox_append_capability
                    .as_ref()
                    .map(|capability| serde_json::json!([
                        capability.version,
                        capability.service,
                        capability.user_id,
                        capability.target_device_id,
                        capability.endpoint,
                        capability.operations,
                        capability.conversation_scope,
                        capability.expires_at,
                        capability
                            .constraints
                            .as_ref()
                            .map(|constraints| serde_json::json!([
                                constraints.max_bytes,
                                constraints.max_ops_per_minute
                            ])),
                        capability.signature
                    ])),
                device
                    .key_package_claim_capability
                    .as_ref()
                    .map(|capability| serde_json::json!([
                        capability.version,
                        capability.service,
                        capability.user_id,
                        capability.target_device_id,
                        capability.endpoint,
                        capability.expires_at,
                        capability.nonce,
                        capability.signature
                    ])),
                device
                    .mls_device_key_binding
                    .as_ref()
                    .map(|binding| serde_json::json!([
                        binding.version,
                        binding.user_id,
                        binding.device_id,
                        binding.device_public_key,
                        binding.mls_signature_public_key,
                        binding.ciphersuite,
                        binding.created_at,
                        binding.signature
                    ]))
            ])
        })
        .collect::<Vec<_>>();
    serde_json::json!([
        "tapchat-identity-bundle-v2",
        bundle.version,
        bundle.publication_version,
        bundle.publication_revision,
        bundle.user_id,
        bundle.user_public_key,
        devices,
        bundle.bundle_share_id,
        bundle.identity_bundle_ref,
        bundle.device_status_ref,
        bundle
            .storage_profile
            .as_ref()
            .and_then(|profile| profile.base_url.as_ref()),
        bundle
            .storage_profile
            .as_ref()
            .and_then(|profile| profile.profile_ref.as_ref()),
        bundle.display_name,
        bundle.updated_at
    ])
    .to_string()
}

pub fn mls_device_key_binding_payload(binding: &MlsDeviceKeyBinding) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!([
        "tapchat-mls-device-key-binding-v2",
        binding.version,
        binding.user_id,
        binding.device_id,
        binding.device_public_key,
        binding.mls_signature_public_key,
        binding.ciphersuite,
        binding.created_at
    ]))
    .expect("MLS device binding canonical JSON is serializable")
}

pub fn derive_user_id_from_public_key(user_public_key: &str) -> CoreResult<String> {
    let key = parse_verifying_key(user_public_key)?;
    Ok(format!("user:{}", short_fingerprint(key.as_bytes(), 16)))
}

pub fn identity_bundle_digest(bundle: &IdentityBundle) -> CoreResult<String> {
    IdentityManager::verify_identity_bundle(bundle)?;
    let canonical = serde_json::to_vec(&serde_json::json!([
        "tapchat-identity-bundle-digest-v2",
        identity_bundle_payload(bundle),
        bundle.signature
    ]))
    .map_err(|error| {
        CoreError::invalid_state(format!("failed to encode identity bundle digest: {error}"))
    })?;
    Ok(format!("sha256:{}", encode_hex(&Sha256::digest(canonical))))
}

pub fn relationship_proposal_signing_payload(proposal: &RelationshipProposalV2) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!([
        "tapchat-relationship-proposal-v2",
        proposal.proposal_id,
        proposal.initiator_user_id,
        proposal.initiator_device_id,
        proposal.relationship_id_candidate,
        proposal.generation,
        proposal.attempt,
        proposal.peer_user_id,
        proposal.sender_bundle_digest,
        proposal.created_at,
        proposal.expires_at,
    ]))
    .expect("fixed relationship proposal payload is serializable")
}

pub fn relationship_ticket_secret_proof(
    ticket_id: &str,
    device_id: &str,
    issued_at: u64,
    ticket_secret: &str,
) -> String {
    let secret_hash = encode_hex(&Sha256::digest(ticket_secret.as_bytes()));
    let canonical = serde_json::to_vec(&serde_json::json!([
        "tapchat-relationship-ticket-secret-proof-v2",
        ticket_id,
        device_id,
        issued_at,
        secret_hash,
    ]))
    .expect("fixed relationship ticket secret proof is serializable");
    encode_hex(&Sha256::digest(canonical))
}

pub fn relationship_ticket_status_signing_payload(
    ticket_id: &str,
    device_id: &str,
    issued_at: u64,
    ticket_secret_proof: &str,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!([
        "tapchat-relationship-ticket-status-v2",
        ticket_id,
        device_id,
        issued_at,
        ticket_secret_proof,
    ]))
    .expect("fixed relationship ticket status payload is serializable")
}

pub fn relationship_decision_proof_signing_payload(proof: &RelationshipDecisionProofV2) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!([
        "tapchat-relationship-decision-v2",
        proof.version,
        proof.ticket_id,
        proof.relationship_id,
        proof.generation,
        proof.proposal_id,
        proof.decision,
        proof.actor_user_id,
        proof.actor_device_id,
        proof.peer_user_id,
        proof.peer_bundle_digest,
        proof.decided_at,
    ]))
    .expect("fixed relationship decision proof payload is serializable")
}

pub fn verify_relationship_decision_proof(
    proof: &RelationshipDecisionProofV2,
    actor_bundle: &IdentityBundle,
) -> CoreResult<()> {
    IdentityManager::verify_identity_bundle(actor_bundle)?;
    if proof.version != crate::model::ENVELOPE_VERSION_V2
        || proof.actor_user_id != actor_bundle.user_id
        || !matches!(proof.decision.as_str(), "accept" | "reject")
    {
        return Err(CoreError::invalid_input(
            "relationship decision proof context is invalid",
        ));
    }
    let device = actor_bundle
        .devices
        .iter()
        .find(|device| device.device_id == proof.actor_device_id)
        .filter(|device| device.status == crate::model::DeviceStatusKind::Active)
        .ok_or_else(|| CoreError::invalid_input("relationship decision actor is not active"))?;
    parse_verifying_key(&device.device_public_key)?
        .verify(
            &relationship_decision_proof_signing_payload(proof),
            &parse_signature(&proof.signature)?,
        )
        .map_err(|_| CoreError::invalid_input("relationship decision proof signature mismatch"))
}

pub fn verify_relationship_proposal(
    proposal: &RelationshipProposalV2,
    bundle: &IdentityBundle,
) -> CoreResult<()> {
    if proposal.initiator_user_id != bundle.user_id
        || proposal.sender_bundle_digest != identity_bundle_digest(bundle)?
    {
        return Err(CoreError::invalid_input(
            "relationship proposal is not bound to the supplied IdentityBundle",
        ));
    }
    let device = bundle
        .devices
        .iter()
        .find(|device| device.device_id == proposal.initiator_device_id)
        .filter(|device| device.status == crate::model::DeviceStatusKind::Active)
        .ok_or_else(|| CoreError::invalid_input("relationship initiator device is not active"))?;
    parse_verifying_key(&device.device_public_key)?
        .verify(
            &relationship_proposal_signing_payload(proposal),
            &parse_signature(&proposal.signature)?,
        )
        .map_err(|_| CoreError::invalid_input("relationship proposal signature mismatch"))
}

fn sha256_tagged_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", encode_hex(&Sha256::digest(bytes)))
}

pub fn envelope_v2_signing_payload(envelope: &EnvelopeV2) -> CoreResult<Vec<u8>> {
    let storage_refs = envelope
        .storage_refs
        .iter()
        .map(|reference| {
            serde_json::json!([
                reference.kind,
                reference.object_ref,
                reference.size_bytes,
                reference.mime_type,
                reference.file_name,
                reference.expires_at
            ])
        })
        .collect::<Vec<_>>();
    let storage_refs_json = serde_json::to_vec(&storage_refs).map_err(|error| {
        CoreError::invalid_state(format!(
            "failed to encode Envelope V2 storage refs: {error}"
        ))
    })?;
    let message_type = serde_json::to_value(envelope.message_type).map_err(|error| {
        CoreError::invalid_state(format!("message type encode failed: {error}"))
    })?;
    let delivery_class = serde_json::to_value(envelope.delivery_class).map_err(|error| {
        CoreError::invalid_state(format!("delivery class encode failed: {error}"))
    })?;
    serde_json::to_vec(&serde_json::json!([
        "tapchat-envelope-v2",
        envelope.version,
        envelope.message_id,
        envelope.conversation_id,
        envelope.relationship_id,
        envelope.generation,
        envelope.attempt,
        envelope.proposal_id,
        envelope.claim_id,
        envelope.sender_user_id,
        envelope.sender_device_id,
        envelope.recipient_user_id,
        envelope.recipient_device_id,
        envelope.created_at,
        message_type,
        delivery_class,
        envelope
            .wake_hint
            .as_ref()
            .and_then(|hint| hint.latest_seq_hint),
        sha256_tagged_bytes(
            envelope
                .inline_ciphertext
                .as_deref()
                .unwrap_or_default()
                .as_bytes()
        ),
        sha256_tagged_bytes(&storage_refs_json),
        envelope.sender_bundle_digest
    ]))
    .map_err(|error| {
        CoreError::invalid_state(format!(
            "failed to encode Envelope V2 signing payload: {error}"
        ))
    })
}

pub fn verify_envelope_v2(envelope: &EnvelopeV2, bundle: &IdentityBundle) -> CoreResult<()> {
    envelope.validate()?;
    IdentityManager::verify_identity_bundle(bundle)?;
    if bundle.publication_version != IDENTITY_PUBLICATION_VERSION_V2 {
        return Err(CoreError::invalid_input(
            "Envelope V2 requires IdentityBundle publication version 2",
        ));
    }
    if bundle.user_id != envelope.sender_user_id {
        return Err(CoreError::invalid_input(
            "Envelope V2 sender user does not match IdentityBundle",
        ));
    }
    if identity_bundle_digest(bundle)? != envelope.sender_bundle_digest {
        return Err(CoreError::invalid_input(
            "Envelope V2 sender bundle digest mismatch",
        ));
    }
    let sender = bundle
        .devices
        .iter()
        .find(|device| device.device_id == envelope.sender_device_id)
        .ok_or_else(|| CoreError::invalid_input("Envelope V2 sender device is not in bundle"))?;
    if sender.status != DeviceStatusKind::Active {
        return Err(CoreError::invalid_input(
            "Envelope V2 sender device is not active",
        ));
    }
    let signature = parse_signature(&envelope.sender_proof.value)?;
    parse_verifying_key(&sender.device_public_key)?
        .verify(&envelope_v2_signing_payload(envelope)?, &signature)
        .map_err(|_| CoreError::invalid_input("Envelope V2 sender proof mismatch"))
}

pub fn generate_bundle_share_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    encode_hex(&bytes)
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
    use super::{
        envelope_v2_signing_payload, identity_bundle_digest, identity_bundle_payload,
        mls_device_key_binding_payload, relationship_decision_proof_signing_payload,
        relationship_ticket_secret_proof, verify_relationship_decision_proof, IdentityManager,
        IdentityModule, DEFAULT_MNEMONIC_WORDS,
    };
    use crate::model::{
        CapabilityConstraints, CapabilityOperation, CapabilityService, DeploymentBundle,
        DeviceContactProfile, DeviceStatusKind, EnvelopeV2, IdentityBundle, InboxAppendCapability,
        KeyPackageRef, MlsDeviceKeyBinding, RelationshipDecisionProofV2, StorageBaseInfo,
        CURRENT_MODEL_VERSION, ENVELOPE_VERSION_V2,
    };
    use bip39::Language;

    const ALICE_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const BOB_MNEMONIC: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";

    #[test]
    fn module_name_is_stable() {
        assert_eq!(IdentityModule.name(), "identity");
    }

    #[test]
    fn generated_mnemonic_is_valid_bip39() {
        let mnemonic = IdentityManager::generate_mnemonic().expect("mnemonic");
        let parsed = bip39::Mnemonic::parse_in_normalized(Language::English, &mnemonic)
            .expect("valid bip39");
        assert_eq!(parsed.word_count(), DEFAULT_MNEMONIC_WORDS);
    }

    #[test]
    fn invalid_mnemonic_is_rejected() {
        let error = IdentityManager::recover_user_root("alpha beta gamma")
            .expect_err("invalid mnemonic should fail");
        assert_eq!(error.code(), "invalid_input");
    }

    #[test]
    fn same_mnemonic_recovers_same_user_identity() {
        let first = IdentityManager::recover_user_root(ALICE_MNEMONIC).expect("first identity");
        let second = IdentityManager::recover_user_root(ALICE_MNEMONIC).expect("second identity");

        assert_eq!(first.user_identity.user_id, second.user_identity.user_id);
        assert_eq!(
            first.user_identity.user_public_key,
            second.user_identity.user_public_key
        );
    }

    #[test]
    fn same_mnemonic_creates_distinct_random_devices() {
        let user_root = IdentityManager::recover_user_root(ALICE_MNEMONIC).expect("user root");
        let first = IdentityManager::create_new_device_for_user(&user_root, None).expect("first");
        let second = IdentityManager::create_new_device_for_user(&user_root, None).expect("second");

        assert_eq!(first.user_identity.user_id, second.user_identity.user_id);
        assert_ne!(
            first.device_identity.device_id,
            second.device_identity.device_id
        );
    }

    #[test]
    fn existing_device_key_restores_same_device() {
        let first = IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone"))
            .expect("first identity");
        let recovered_root = IdentityManager::recover_user_root(ALICE_MNEMONIC).expect("user root");
        let restored = IdentityManager::create_new_device_for_user(
            &recovered_root,
            Some(first.device_signing_key_bytes()),
        )
        .expect("restored identity");

        assert_eq!(first.user_identity.user_id, restored.user_identity.user_id);
        assert_eq!(
            first.device_identity.device_id,
            restored.device_identity.device_id
        );
    }

    #[test]
    fn different_mnemonics_produce_different_users() {
        let alice = IdentityManager::recover_user_root(ALICE_MNEMONIC).expect("alice");
        let bob = IdentityManager::recover_user_root(BOB_MNEMONIC).expect("bob");

        assert_ne!(alice.user_identity.user_id, bob.user_identity.user_id);
    }

    #[test]
    fn device_binding_can_be_verified() {
        let identity = IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone"))
            .expect("identity");
        IdentityManager::verify_device_binding(
            &identity.user_identity.user_public_key,
            &identity.device_identity.binding,
        )
        .expect("binding should verify");
    }

    #[test]
    fn identity_bundle_verification_rejects_tampered_binding() {
        let identity = IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone"))
            .expect("identity");
        let mut bundle = IdentityBundle {
            version: CURRENT_MODEL_VERSION.to_string(),
            publication_version: 0,
            publication_revision: 0,
            user_id: identity.user_identity.user_id.clone(),
            user_public_key: identity.user_identity.user_public_key.clone(),
            display_name: None,
            devices: vec![DeviceContactProfile {
                version: CURRENT_MODEL_VERSION.to_string(),
                device_id: identity.device_identity.device_id.clone(),
                device_public_key: identity.device_identity.device_public_key.clone(),
                binding: identity.device_identity.binding.clone(),
                status: DeviceStatusKind::Active,
                inbox_append_capability: Some(InboxAppendCapability {
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
                }),
                key_package_claim_capability: None,
                mls_device_key_binding: None,
                keypackage_ref: Some(KeyPackageRef {
                    version: CURRENT_MODEL_VERSION.to_string(),
                    user_id: identity.user_identity.user_id.clone(),
                    device_id: identity.device_identity.device_id.clone(),
                    object_ref: "s3://keypackage".into(),
                    lifecycle_version: 0,
                    not_before: 0,
                    created_at: 0,
                    expires_at: 999,
                }),
            }],
            bundle_share_id: Some("share-id".into()),
            identity_bundle_ref: None,
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
        let identity = IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone"))
            .expect("identity");
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test clock")
            .as_millis() as u64;
        let package = crate::mls_adapter::MlsAdapter::generate_key_package(&identity, now_ms)
            .expect("key package");
        let bundle = IdentityManager::export_identity_bundle(
            &identity,
            &sample_deployment(),
            package.key_package_b64,
            package.expires_at,
        )
        .expect("bundle");
        IdentityManager::verify_identity_bundle(&bundle).expect("bundle should verify");
    }

    #[test]
    fn exported_identity_bundle_uses_runtime_config_bootstrap_refs_only() {
        let identity = IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone"))
            .expect("identity");
        let bundle = IdentityManager::export_identity_bundle(
            &identity,
            &sample_deployment(),
            "kp-ref".into(),
            999,
        )
        .expect("bundle");

        assert_eq!(
            bundle.identity_bundle_ref.as_deref(),
            Some("https://storage.example.com/state/user:alice/identity_bundle.json")
        );
        assert_eq!(
            bundle.device_status_ref.as_deref(),
            Some("https://storage.example.com/state/user:alice/device_status.json")
        );
        assert_eq!(
            bundle
                .storage_profile
                .as_ref()
                .and_then(|profile| profile.base_url.as_deref()),
            Some("https://storage.example.com")
        );
        assert_eq!(
            bundle
                .storage_profile
                .as_ref()
                .and_then(|profile| profile.profile_ref.as_deref()),
            None
        );
    }

    #[test]
    fn exported_identity_bundle_does_not_infer_state_paths_from_base_url() {
        let identity = IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone"))
            .expect("identity");
        let mut deployment = sample_deployment();
        deployment.runtime_config.identity_bundle_ref = None;
        deployment.runtime_config.device_status_ref = None;

        let bundle =
            IdentityManager::export_identity_bundle(&identity, &deployment, "kp-ref".into(), 999)
                .expect("bundle");

        assert_eq!(bundle.identity_bundle_ref, None);
        assert_eq!(bundle.device_status_ref, None);
        assert_eq!(
            bundle
                .storage_profile
                .as_ref()
                .and_then(|profile| profile.base_url.as_deref()),
            Some("https://storage.example.com")
        );
        assert_eq!(
            bundle
                .storage_profile
                .as_ref()
                .and_then(|profile| profile.profile_ref.as_deref()),
            None
        );
    }

    #[test]
    fn exported_identity_bundle_materializes_runtime_refs_for_local_user() {
        let identity = IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone"))
            .expect("identity");
        let mut deployment = sample_deployment();
        deployment.runtime_config.identity_bundle_ref =
            Some("https://storage.example.com/state/{userId}/identity_bundle.json".into());
        deployment.runtime_config.device_status_ref =
            Some("https://storage.example.com/state/{userId}/device_status.json".into());

        let bundle =
            IdentityManager::export_identity_bundle(&identity, &deployment, "kp-ref".into(), 999)
                .expect("bundle");
        let encoded_user_id = urlencoding::encode(&identity.user_identity.user_id).into_owned();
        let expected_identity_ref =
            format!("https://storage.example.com/state/{encoded_user_id}/identity_bundle.json");
        let expected_status_ref =
            format!("https://storage.example.com/state/{encoded_user_id}/device_status.json");

        assert_eq!(
            bundle.identity_bundle_ref.as_deref(),
            Some(expected_identity_ref.as_str())
        );
        assert_eq!(
            bundle.device_status_ref.as_deref(),
            Some(expected_status_ref.as_str())
        );
    }

    #[test]
    fn protocol_v2_signing_payloads_match_shared_golden_vector() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../test-vectors/protocol-v2.json"))
                .expect("protocol V2 fixture");
        let binding: MlsDeviceKeyBinding =
            serde_json::from_value(fixture["mlsDeviceKeyBinding"].clone())
                .expect("MLS binding fixture");
        let envelope: EnvelopeV2 =
            serde_json::from_value(fixture["envelope"].clone()).expect("Envelope V2 fixture");
        let bundle: IdentityBundle = serde_json::from_value(fixture["identityBundle"].clone())
            .expect("IdentityBundle fixture");

        assert_eq!(
            String::from_utf8(mls_device_key_binding_payload(&binding)).expect("utf8"),
            fixture["mlsDeviceKeyBindingSigningPayload"]
                .as_str()
                .expect("binding payload")
        );
        assert_eq!(
            String::from_utf8(envelope_v2_signing_payload(&envelope).expect("payload"))
                .expect("utf8"),
            fixture["envelopeSigningPayload"]
                .as_str()
                .expect("envelope payload")
        );
        assert_eq!(
            identity_bundle_payload(&bundle),
            fixture["identityBundleSigningPayload"]
                .as_str()
                .expect("IdentityBundle payload")
        );
        assert_eq!(
            identity_bundle_digest(&bundle).expect("IdentityBundle digest"),
            fixture["identityBundleDigest"]
                .as_str()
                .expect("IdentityBundle digest fixture")
        );
    }

    #[test]
    fn relationship_ticket_secret_proof_is_context_bound_and_does_not_expose_secret() {
        let first = relationship_ticket_secret_proof(
            "ticket:opaque",
            "device:alice:phone",
            42,
            "private-ticket-secret",
        );
        assert_eq!(first.len(), 64);
        assert!(!first.contains("private-ticket-secret"));
        assert_eq!(
            first,
            relationship_ticket_secret_proof(
                "ticket:opaque",
                "device:alice:phone",
                42,
                "private-ticket-secret",
            )
        );
        assert_ne!(
            first,
            relationship_ticket_secret_proof(
                "ticket:opaque",
                "device:alice:laptop",
                42,
                "private-ticket-secret",
            )
        );
        assert_ne!(
            first,
            relationship_ticket_secret_proof(
                "ticket:opaque",
                "device:alice:phone",
                43,
                "private-ticket-secret",
            )
        );
    }

    #[test]
    fn relationship_decision_proof_rejects_tampered_security_context() {
        let identity = IdentityManager::create_or_recover(Some(ALICE_MNEMONIC), Some("phone"))
            .expect("identity");
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test clock")
            .as_millis() as u64;
        let package = crate::mls_adapter::MlsAdapter::generate_key_package(&identity, now_ms)
            .expect("key package");
        let bundle = IdentityManager::export_identity_bundle(
            &identity,
            &sample_deployment(),
            package.key_package_b64,
            package.expires_at,
        )
        .expect("bundle");
        let mut proof = RelationshipDecisionProofV2 {
            version: ENVELOPE_VERSION_V2.into(),
            ticket_id: "ticket:opaque".into(),
            relationship_id: "relationship:opaque".into(),
            generation: 0,
            proposal_id: "proposal:opaque".into(),
            decision: "accept".into(),
            actor_user_id: bundle.user_id.clone(),
            actor_device_id: bundle.devices[0].device_id.clone(),
            peer_user_id: "user:peer".into(),
            peer_bundle_digest: "sha256:peer-bundle".into(),
            decided_at: now_ms,
            signature: String::new(),
        };
        proof.signature =
            identity.sign_device_payload(&relationship_decision_proof_signing_payload(&proof));
        verify_relationship_decision_proof(&proof, &bundle).expect("valid decision proof");

        proof.generation = 1;
        let error = verify_relationship_decision_proof(&proof, &bundle)
            .expect_err("tampered generation must invalidate the proof");
        assert_eq!(error.code(), "invalid_input");
    }

    fn sample_deployment() -> DeploymentBundle {
        DeploymentBundle {
            version: CURRENT_MODEL_VERSION.to_string(),
            runtime_id: "runtime:test".into(),
            protocol_version: 6,
            worker_build_id: "test-worker-v4".into(),
            registry_schema_version: 3,
            region: "local".into(),
            inbox_http_endpoint: "https://example.com".into(),
            inbox_websocket_endpoint: "wss://example.com/ws".into(),
            storage_base_info: StorageBaseInfo {
                base_url: Some("https://storage.example.com".into()),
                bucket_hint: None,
            },
            runtime_config: crate::model::RuntimeConfig {
                supported_realtime_kinds: vec![crate::model::RealtimeKind::Websocket],
                identity_bundle_ref: Some(
                    "https://storage.example.com/state/user:alice/identity_bundle.json".into(),
                ),
                device_status_ref: Some(
                    "https://storage.example.com/state/user:alice/device_status.json".into(),
                ),
                keypackage_ref_base: Some("https://storage.example.com/keypackages".into()),
                max_inline_bytes: Some(4096),
                features: vec!["generic_sync".into()],
            },
            expected_user_id: None,
            expected_device_id: None,
        }
    }
}

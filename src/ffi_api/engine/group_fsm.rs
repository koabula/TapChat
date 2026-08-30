use super::*;

impl CoreEngine {
    pub(super) fn build_envelope(
        &mut self,
        conversation_id: &str,
        recipient_device_id: &str,
        message_type: MessageType,
        payload_b64: String,
    ) -> CoreResult<Envelope> {
        let identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .clone();
        let sender_user_id = identity.user_identity.user_id.clone();
        let sender_device_id = identity.device_identity.device_id.clone();
        let sender_proof = identity.sign_sender_proof(payload_b64.as_bytes());
        let message_nonce = self.next_message_nonce();
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(message_nonce);
        Ok(Envelope {
            version: crate::model::CURRENT_MODEL_VERSION.to_string(),
            message_id: self.next_message_id(conversation_id, recipient_device_id, message_nonce),
            conversation_id: conversation_id.to_string(),
            sender_user_id,
            sender_device_id,
            recipient_device_id: recipient_device_id.to_string(),
            created_at,
            message_type,
            inline_ciphertext: Some(payload_b64.clone()),
            storage_refs: vec![],
            delivery_class: DeliveryClass::Normal,
            wake_hint: None,
            sender_proof: SenderProof {
                proof_type: "device_signature".into(),
                value: sender_proof,
            },
        })
    }

    pub(super) fn build_group_manifest(
        &self,
        group_id: &str,
        conversation_id: &str,
        title: &str,
        identity: &crate::identity::LocalIdentityState,
        member_user_ids: &[String],
        member_devices: Vec<GroupMemberDevice>,
        epoch: u64,
        now: u64,
    ) -> CoreResult<GroupManifest> {
        let mut members = vec![GroupMember {
            user_id: identity.user_identity.user_id.clone(),
            role: GroupRole::Owner,
            status: GroupMemberStatus::Active,
        }];
        members.extend(member_user_ids.iter().cloned().map(|user_id| GroupMember {
            user_id,
            role: GroupRole::Member,
            status: GroupMemberStatus::Active,
        }));
        let messages_endpoint = self.group_outbox_messages_endpoint(group_id)?;
        let subscribe_endpoint = self.state.deployment_bundle.as_ref().map(|deployment| {
            let base = deployment
                .inbox_http_endpoint
                .trim_end_matches('/')
                .replace("https://", "wss://")
                .replace("http://", "ws://");
            format!("{base}/v1/groups/{group_id}/outbox/subscribe")
        });
        let outbox = GroupOutboxDescriptor {
            endpoint: messages_endpoint,
            subscribe_endpoint,
        };
        let mut manifest = GroupManifest {
            version: crate::model::CURRENT_MODEL_VERSION.to_string(),
            group_id: group_id.to_string(),
            conversation_id: conversation_id.to_string(),
            title: title.to_string(),
            owner_user_id: identity.user_identity.user_id.clone(),
            admins: Vec::new(),
            members,
            member_devices,
            join_policy: GroupJoinPolicy::Closed,
            member_invite_policy: GroupMemberInvitePolicy::OwnerAdminOnly,
            roster_version: 1,
            mls_epoch_hint: epoch,
            last_commit_message_id: None,
            outbox,
            updated_at: now,
            signer_user_id: identity.user_identity.user_id.clone(),
            signer_device_id: identity.device_identity.device_id.clone(),
            signature: String::new(),
        };
        manifest.signature =
            identity.sign_sender_proof(&Self::manifest_signing_payload(&manifest)?);
        Ok(manifest)
    }

    pub(super) fn build_group_envelope(
        &mut self,
        group_id: &str,
        conversation_id: &str,
        message_type: GroupMessageType,
        visibility: GroupEnvelopeVisibility,
        payload_b64: String,
    ) -> CoreResult<GroupEnvelope> {
        let identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .clone();
        let message_nonce = self.next_message_nonce();
        let created_at = current_unix_millis(message_nonce);
        let sender_proof = identity.sign_sender_proof(payload_b64.as_bytes());
        let message_id = format!(
            "msg:{conversation_id}:{}:{message_nonce}:group",
            identity.device_identity.device_id
        );
        Ok(GroupEnvelope {
            version: crate::model::CURRENT_MODEL_VERSION.to_string(),
            message_id,
            group_id: group_id.to_string(),
            conversation_id: conversation_id.to_string(),
            sender_user_id: identity.user_identity.user_id.clone(),
            sender_device_id: identity.device_identity.device_id.clone(),
            created_at,
            message_type,
            visibility,
            inline_ciphertext: Some(payload_b64),
            storage_refs: Vec::new(),
            sender_proof: SenderProof {
                proof_type: "device_signature".into(),
                value: sender_proof,
            },
            membership_proof: None,
            transition_id: None,
            mls_epoch: None,
            epoch_head_hash: None,
            epoch_authenticator_sha256: None,
        })
    }

    pub(super) fn group_crypto_head_hash(
        previous_head_hash: &str,
        next_epoch: u64,
        commit_b64: &str,
        epoch_authenticator_sha256: &str,
        committer_user_id: &str,
        committer_device_id: &str,
    ) -> CoreResult<String> {
        let commit = STANDARD.decode(commit_b64).map_err(|error| {
            CoreError::invalid_input(format!("group MLS commit is not base64: {error}"))
        })?;
        Ok(format!(
            "{:x}",
            Sha256::digest(
                format!(
                    "tapchat.group_crypto_head.v1\n{}\n{}\n{:x}\n{}\n{}\n{}",
                    previous_head_hash,
                    next_epoch,
                    Sha256::digest(commit),
                    epoch_authenticator_sha256,
                    committer_user_id,
                    committer_device_id,
                )
                .as_bytes()
            )
        ))
    }

    pub(super) fn bind_group_envelope_epoch(
        &self,
        envelope: &mut GroupEnvelope,
        epoch: u64,
        head_hash: &str,
        epoch_authenticator_sha256: Option<&str>,
    ) -> CoreResult<()> {
        let identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?;
        let payload = envelope.inline_ciphertext.as_deref().unwrap_or_default();
        let signing_payload = Self::group_envelope_epoch_signature_payload(
            payload,
            epoch,
            head_hash,
            epoch_authenticator_sha256,
        );
        envelope.mls_epoch = Some(epoch);
        envelope.epoch_head_hash = Some(head_hash.to_string());
        envelope.epoch_authenticator_sha256 = epoch_authenticator_sha256.map(str::to_string);
        envelope.sender_proof.value = identity.sign_sender_proof(signing_payload.as_bytes());
        Ok(())
    }

    pub(super) fn group_envelope_epoch_signature_payload(
        payload: &str,
        epoch: u64,
        head_hash: &str,
        epoch_authenticator_sha256: Option<&str>,
    ) -> String {
        format!(
            "tapchat.group_envelope_epoch.v1\npayload={}\nmls_epoch={}\nepoch_head_hash={}\nepoch_authenticator_sha256={}",
            payload,
            epoch,
            head_hash,
            epoch_authenticator_sha256.unwrap_or_default()
        )
    }

    pub(super) fn enqueue_group_envelope(
        &mut self,
        envelope: GroupEnvelope,
        _capability: GroupCapability,
        plaintext: Option<String>,
    ) {
        self.state
            .pending_group_outbox
            .push(PendingGroupOutboxItem {
                envelope,
                retries: 0,
                in_flight: false,
                plaintext_cache: plaintext,
            });
    }

    pub(super) fn group_outbox_messages_endpoint(&self, group_id: &str) -> CoreResult<String> {
        let deployment = self
            .state
            .deployment_bundle
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("deployment bundle is not initialized"))?;
        Ok(format!(
            "{}/v1/groups/{}/outbox/messages",
            deployment.inbox_http_endpoint.trim_end_matches('/'),
            group_id
        ))
    }

    pub(super) fn deployment_http_base(&self) -> CoreResult<String> {
        let deployment = self
            .state
            .deployment_bundle
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("deployment bundle is not initialized"))?;
        Ok(deployment
            .inbox_http_endpoint
            .trim_end_matches('/')
            .to_string())
    }

    pub(super) fn stable_scoped_id(&self, prefix: &str, scope: &str, nonce: u64) -> String {
        let local_user_id = self
            .state
            .local_identity
            .as_ref()
            .map(|identity| identity.user_identity.user_id.as_str())
            .unwrap_or("user:local");
        let mut hasher = Sha256::new();
        hasher.update(prefix.as_bytes());
        hasher.update(b":");
        hasher.update(scope.as_bytes());
        hasher.update(b":");
        hasher.update(local_user_id.as_bytes());
        hasher.update(b":");
        hasher.update(nonce.to_le_bytes());
        format!("{prefix}:{}", hex_lower(&hasher.finalize()[..16]))
    }

    pub(super) fn sign_manifest(&self, manifest: &GroupManifest) -> CoreResult<String> {
        let identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .clone();
        Ok(identity.sign_sender_proof(&Self::manifest_signing_payload(manifest)?))
    }

    pub(super) fn manifest_signing_payload(manifest: &GroupManifest) -> CoreResult<Vec<u8>> {
        let mut unsigned = manifest.clone();
        unsigned.signature.clear();
        let encoded = serde_json::to_vec(&unsigned).map_err(|error| {
            CoreError::invalid_input(format!(
                "failed to encode manifest signing payload: {error}"
            ))
        })?;
        let mut payload = b"tapchat.group_manifest.v1\n".to_vec();
        payload.extend(encoded);
        Ok(payload)
    }

    pub(crate) fn manifest_sha256(manifest: &GroupManifest) -> CoreResult<String> {
        let mut unsigned = manifest.clone();
        unsigned.signature.clear();
        let encoded = serde_json::to_vec(&unsigned).map_err(|error| {
            CoreError::invalid_input(format!("failed to encode manifest hash payload: {error}"))
        })?;
        Ok(hex_lower(&Sha256::digest(encoded)))
    }

    pub(crate) fn membership_proof_payload(proof: &GroupMembershipProof) -> Vec<u8> {
        let mut payload = format!(
            "tapchat.group.membership.v1\nproof_type={}\noperation={}\nsigner_user_id={}\nsigner_device_id={}\nprevious_roster_version={}\nnew_roster_version={}\nprevious_commit_message_id={}\ncommit_message_id={}\ncontrol_message_id={}\nnew_manifest_sha256={}",
            proof.proof_type,
            proof.operation,
            proof.signer_user_id,
            proof.signer_device_id,
            proof.previous_roster_version,
            proof.new_roster_version,
            proof.previous_commit_message_id.as_deref().unwrap_or(""),
            proof.commit_message_id,
            proof.control_message_id,
            proof.new_manifest_sha256,
        );
        if let Some(message_id) = &proof.state_event_message_id {
            payload.push_str("\nstate_event_message_id=");
            payload.push_str(message_id);
        }
        payload.into_bytes()
    }

    pub(super) fn verify_device_signature(
        &self,
        signer_user_id: &str,
        signer_device_id: &str,
        payload: &[u8],
        signature_hex: &str,
    ) -> CoreResult<()> {
        let bundle = if self
            .state
            .local_identity
            .as_ref()
            .is_some_and(|identity| identity.user_identity.user_id == signer_user_id)
        {
            self.state.local_bundle.as_ref()
        } else {
            self.state
                .contacts
                .get(signer_user_id)
                .map(|contact| &contact.bundle)
        }
        .ok_or_else(|| CoreError::invalid_input("signer identity bundle is missing"))?;
        let device = bundle
            .devices
            .iter()
            .find(|device| {
                device.device_id == signer_device_id
                    && matches!(device.status, DeviceStatusKind::Active)
            })
            .ok_or_else(|| CoreError::invalid_input("signer device is not active"))?;
        let verifying_key = parse_verifying_key(&device.device_public_key)?;
        let signature = parse_signature(signature_hex)?;
        verifying_key
            .verify(payload, &signature)
            .map_err(|_| CoreError::invalid_input("device signature mismatch"))
    }

    pub(super) fn verify_manifest_signature(&self, manifest: &GroupManifest) -> CoreResult<()> {
        self.verify_device_signature(
            &manifest.signer_user_id,
            &manifest.signer_device_id,
            &Self::manifest_signing_payload(manifest)?,
            &manifest.signature,
        )
    }

    pub(super) fn verify_epoch_bound_group_envelope(
        &self,
        envelope: &GroupEnvelope,
    ) -> CoreResult<()> {
        let epoch = envelope
            .mls_epoch
            .ok_or_else(|| CoreError::invalid_input("group envelope is missing MLS epoch"))?;
        let head_hash = envelope
            .epoch_head_hash
            .as_deref()
            .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or_else(|| CoreError::invalid_input("group envelope has an invalid crypto head"))?;
        if envelope.sender_proof.proof_type != "device_signature" {
            return Err(CoreError::invalid_input(
                "group envelope requires a device signature",
            ));
        }
        self.verify_device_signature(
            &envelope.sender_user_id,
            &envelope.sender_device_id,
            Self::group_envelope_epoch_signature_payload(
                envelope.inline_ciphertext.as_deref().unwrap_or_default(),
                epoch,
                head_hash,
                envelope.epoch_authenticator_sha256.as_deref(),
            )
            .as_bytes(),
            &envelope.sender_proof.value,
        )
    }

    pub(super) fn local_identity_user_id(&self) -> CoreResult<String> {
        Ok(self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .user_identity
            .user_id
            .clone())
    }

    pub(super) fn local_identity_device_id(&self) -> CoreResult<String> {
        Ok(self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .device_identity
            .device_id
            .clone())
    }

    pub(super) fn build_membership_proof(
        &self,
        operation: &str,
        previous: &GroupManifest,
        updated: &GroupManifest,
        commit_message_id: &str,
        control_message_id: &str,
    ) -> CoreResult<GroupMembershipProof> {
        let identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?;
        let mut proof = GroupMembershipProof {
            proof_type: "membership_signature".into(),
            operation: operation.to_string(),
            signer_user_id: identity.user_identity.user_id.clone(),
            signer_device_id: identity.device_identity.device_id.clone(),
            previous_roster_version: previous.roster_version,
            new_roster_version: updated.roster_version,
            previous_commit_message_id: previous.last_commit_message_id.clone(),
            commit_message_id: commit_message_id.to_string(),
            control_message_id: control_message_id.to_string(),
            state_event_message_id: None,
            new_manifest_sha256: Self::manifest_sha256(updated)?,
            signature: String::new(),
        };
        proof.signature = identity.sign_sender_proof(&Self::membership_proof_payload(&proof));
        proof.validate()?;
        Ok(proof)
    }

    pub(super) fn apply_membership_change_to_manifest(
        &self,
        manifest: &mut GroupManifest,
        epoch: u64,
        now: u64,
    ) -> CoreResult<()> {
        let identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .clone();
        manifest.roster_version = manifest.roster_version.saturating_add(1);
        manifest.mls_epoch_hint = epoch;
        manifest.updated_at = now;
        manifest.signer_user_id = identity.user_identity.user_id.clone();
        manifest.signer_device_id = identity.device_identity.device_id.clone();
        manifest.signature = self.sign_manifest(manifest)?;
        manifest.validate()
    }

    pub(super) fn sync_conversation_members_from_manifest(
        &mut self,
        conversation_id: &str,
        manifest: &GroupManifest,
    ) -> CoreResult<()> {
        let local_identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?;
        let conversation = self
            .state
            .conversations
            .get_mut(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?;
        let mut member_users: Vec<String> = manifest
            .members
            .iter()
            .filter(|m| matches!(m.status, GroupMemberStatus::Active))
            .map(|m| m.user_id.clone())
            .collect();
        member_users.sort();
        member_users.dedup();
        conversation.conversation.member_users = member_users;
        let mut member_devices = vec![ConversationMember {
            user_id: local_identity.user_identity.user_id.clone(),
            device_id: local_identity.device_identity.device_id.clone(),
            status: DeviceStatusKind::Active,
        }];
        if let Ok(summary) = self
            .state
            .mls_adapter
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .export_group_summary(conversation_id)
        {
            for device_id in &summary.member_device_ids {
                if device_id != &local_identity.device_identity.device_id {
                    member_devices.push(ConversationMember {
                        user_id: String::new(),
                        device_id: device_id.clone(),
                        status: DeviceStatusKind::Active,
                    });
                }
            }
        }
        conversation.conversation.member_devices = member_devices;
        conversation.conversation.updated_at = manifest.updated_at;
        Ok(())
    }

    pub(super) fn verify_membership_operation_authority(
        &self,
        envelope: &GroupEnvelope,
        manifest: &GroupManifest,
    ) -> CoreResult<GroupMembershipProof> {
        let sender_role = manifest
            .members
            .iter()
            .find(|m| {
                m.user_id == envelope.sender_user_id
                    && matches!(m.status, GroupMemberStatus::Active)
            })
            .map(|m| m.role);
        match sender_role {
            Some(GroupRole::Owner | GroupRole::Admin) => {}
            Some(GroupRole::Member) | None => {
                return Err(CoreError::invalid_input(
                    "sender is not an active owner or admin; membership operation rejected",
                ));
            }
        }
        let proof = envelope.membership_proof.as_ref().ok_or_else(|| {
            CoreError::invalid_input("membership operation requires membership_proof")
        })?;
        proof.validate()?;
        if proof.signer_user_id != envelope.sender_user_id
            || proof.signer_device_id != envelope.sender_device_id
        {
            return Err(CoreError::invalid_input(
                "membership proof signer must match envelope sender",
            ));
        }
        Self::verify_membership_proof_message_binding(envelope, proof)?;
        self.verify_device_signature(
            &proof.signer_user_id,
            &proof.signer_device_id,
            &Self::membership_proof_payload(proof),
            &proof.signature,
        )?;
        if !Self::manifest_has_active_device(
            manifest,
            &proof.signer_user_id,
            &proof.signer_device_id,
        ) {
            return Err(CoreError::invalid_input(
                "membership proof signer device is not active in the current group manifest",
            ));
        }
        if self.is_reflected_membership_proof(envelope, manifest, proof)? {
            return Ok(proof.clone());
        }
        if proof.previous_roster_version != manifest.roster_version {
            return Err(CoreError::invalid_input(
                "membership proof previous roster_version does not match local manifest",
            ));
        }
        if proof.previous_commit_message_id != manifest.last_commit_message_id {
            return Err(CoreError::invalid_input(
                "membership proof previous commit does not match local manifest",
            ));
        }
        Ok(proof.clone())
    }

    pub(super) fn verify_membership_proof_message_binding(
        envelope: &GroupEnvelope,
        proof: &GroupMembershipProof,
    ) -> CoreResult<()> {
        match envelope.message_type {
            GroupMessageType::MlsCommit => {
                if proof.commit_message_id != envelope.message_id {
                    return Err(CoreError::invalid_input(
                        "membership commit proof does not reference this commit",
                    ));
                }
                if proof.control_message_id.trim().is_empty() {
                    return Err(CoreError::invalid_input(
                        "membership commit proof must reference a control message",
                    ));
                }
            }
            GroupMessageType::ControlGroupMembershipChanged
            | GroupMessageType::ControlGroupMetadataUpdated
            | GroupMessageType::ControlGroupDissolved => {
                if proof.control_message_id != envelope.message_id {
                    return Err(CoreError::invalid_input(
                        "membership control proof does not reference this control message",
                    ));
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub(super) fn is_reflected_membership_proof(
        &self,
        envelope: &GroupEnvelope,
        manifest: &GroupManifest,
        proof: &GroupMembershipProof,
    ) -> CoreResult<bool> {
        if !matches!(
            envelope.message_type,
            GroupMessageType::MlsCommit
                | GroupMessageType::ControlGroupMembershipChanged
                | GroupMessageType::ControlGroupMetadataUpdated
                | GroupMessageType::ControlGroupDissolved
        ) {
            return Ok(false);
        }
        if manifest.roster_version != proof.new_roster_version {
            return Ok(false);
        }
        if manifest.last_commit_message_id.as_ref() != Some(&proof.commit_message_id) {
            return Ok(false);
        }
        Ok(Self::manifest_sha256(manifest)? == proof.new_manifest_sha256)
    }

    pub(super) fn try_apply_control_manifest_update(
        &mut self,
        conversation_id: &str,
        group_id: &str,
        record: &GroupOutboxRecord,
        current_state: &PersistedGroupState,
    ) -> bool {
        if !matches!(
            record.envelope.message_type,
            GroupMessageType::ControlGroupMembershipChanged
                | GroupMessageType::ControlGroupMetadataUpdated
                | GroupMessageType::ControlGroupDissolved
        ) {
            return false;
        }
        let Some(ciphertext) = &record.envelope.inline_ciphertext else {
            return false;
        };
        let mls = match self.state.mls_adapter.as_mut() {
            Some(adapter) => adapter,
            None => return false,
        };
        let result = match mls.ingest_message(
            conversation_id,
            &record.envelope.sender_device_id,
            MessageType::MlsApplication,
            ciphertext,
        ) {
            Ok(result) => result,
            Err(_) => return false,
        };
        let plaintext = match result {
            IngestResult::AppliedApplication(app) => app.plaintext,
            _ => return false,
        };
        let updated = match serde_json::from_slice::<GroupManifest>(&plaintext) {
            Ok(manifest) => manifest,
            Err(_) => return false,
        };
        if updated.group_id != group_id {
            return false;
        }
        if let Some(pending) = &current_state.pending_membership_transition {
            if pending.control_message_id != record.envelope.message_id {
                log::warn!(
                    "rejected manifest control for group {}: control id does not match pending membership transition",
                    redact_id("group", group_id)
                );
                return false;
            }
            if record.envelope.membership_proof.as_ref() != Some(&pending.proof) {
                log::warn!(
                    "rejected manifest control for group {}: proof does not match pending membership transition",
                    redact_id("group", group_id)
                );
                return false;
            }
        }
        if updated.roster_version <= current_state.manifest.roster_version {
            log::warn!(
                "rejected stale manifest update for group {}: new roster_version {} is not newer than current {}",
                redact_id("group", group_id),
                updated.roster_version,
                current_state.manifest.roster_version
            );
            return false;
        }
        if let Err(_err) = updated.validate() {
            log::warn!(
                "rejected invalid manifest update for group {}: validation_failed",
                redact_id("group", group_id)
            );
            return false;
        }
        let Some(proof) = record.envelope.membership_proof.as_ref() else {
            log::warn!(
                "rejected manifest update for group {}: missing membership proof",
                redact_id("group", group_id)
            );
            return false;
        };
        let manifest_hash = match Self::manifest_sha256(&updated) {
            Ok(hash) => hash,
            Err(_err) => {
                log::warn!(
                    "failed to hash manifest update for group {}: hash_failed",
                    redact_id("group", group_id)
                );
                return false;
            }
        };
        let commit_matches =
            if record.envelope.message_type == GroupMessageType::ControlGroupMembershipChanged {
                updated.last_commit_message_id.as_ref() == Some(&proof.commit_message_id)
            } else {
                true
            };
        if manifest_hash != proof.new_manifest_sha256
            || updated.roster_version != proof.new_roster_version
            || current_state.manifest.roster_version != proof.previous_roster_version
            || current_state.manifest.last_commit_message_id != proof.previous_commit_message_id
            || !commit_matches
        {
            log::warn!(
                "rejected manifest update for group {}: manifest transition does not match proof",
                redact_id("group", group_id)
            );
            return false;
        }
        if !Self::validate_manifest_transition_for_operation(
            &current_state.manifest,
            &updated,
            proof,
        ) {
            log::warn!(
                "rejected invalid manifest transition for group {} at roster_version {} -> {}",
                redact_id("group", group_id),
                current_state.manifest.roster_version,
                updated.roster_version
            );
            return false;
        }
        if let Err(_err) = self.verify_manifest_signature(&updated) {
            log::warn!(
                "rejected manifest update with invalid signature for group {}: signature_invalid",
                redact_id("group", group_id)
            );
            return false;
        }
        let local_user_id = self
            .state
            .local_identity
            .as_ref()
            .map(|id| id.user_identity.user_id.clone());
        let updated_local_role = local_user_id.as_ref().and_then(|uid| {
            updated
                .members
                .iter()
                .find(|m| &m.user_id == uid && m.status == GroupMemberStatus::Active)
                .map(|m| m.role)
        });
        self.state.group_states.insert(
            group_id.to_string(),
            PersistedGroupState {
                group_id: group_id.to_string(),
                conversation_id: conversation_id.to_string(),
                manifest: updated.clone(),
                local_role: updated_local_role,
                welcome_pickup: current_state.welcome_pickup.clone(),
                dissolved_at: current_state.dissolved_at,
                pending_membership_transition: None,
                consistency_state: GroupConsistencyState::Ready,
                pending_group_transition: None,
                leave_requests: current_state.leave_requests.clone(),
                pcs_state: current_state.pcs_state.clone(),
                crypto_epoch: current_state.crypto_epoch,
                crypto_head_hash: current_state.crypto_head_hash.clone(),
                pending_secure_send: current_state.pending_secure_send.clone(),
                pending_epoch_transition: current_state.pending_epoch_transition.clone(),
            },
        );
        let _ = self.sync_conversation_members_from_manifest(conversation_id, &updated);
        true
    }

    pub(super) fn manifest_has_active_device(
        manifest: &GroupManifest,
        user_id: &str,
        device_id: &str,
    ) -> bool {
        manifest.member_devices.iter().any(|device| {
            device.user_id == user_id
                && device.device_id == device_id
                && device.status == GroupMemberStatus::Active
        })
    }

    pub(super) fn validate_manifest_transition(old: &GroupManifest, new: &GroupManifest) -> bool {
        if old.group_id != new.group_id || old.conversation_id != new.conversation_id {
            return false;
        }
        if new.roster_version != old.roster_version.saturating_add(1) {
            return false;
        }
        if new.mls_epoch_hint < old.mls_epoch_hint {
            return false;
        }
        let signer_role = old
            .members
            .iter()
            .find(|member| {
                member.user_id == new.signer_user_id && member.status == GroupMemberStatus::Active
            })
            .map(|member| member.role);
        if !matches!(signer_role, Some(GroupRole::Owner | GroupRole::Admin)) {
            return false;
        }
        if !Self::manifest_has_active_device(old, &new.signer_user_id, &new.signer_device_id) {
            return false;
        }
        let active_count = |m: &GroupManifest| {
            m.members
                .iter()
                .filter(|m| m.status == GroupMemberStatus::Active)
                .count()
        };
        let active_owner_count = |m: &GroupManifest| {
            m.members
                .iter()
                .filter(|m| m.role == GroupRole::Owner && m.status == GroupMemberStatus::Active)
                .count()
        };
        if active_owner_count(new) != 1 {
            return false;
        }
        if new.owner_user_id
            != new
                .members
                .iter()
                .find(|m| m.role == GroupRole::Owner && m.status == GroupMemberStatus::Active)
                .map(|m| m.user_id.as_str())
                .unwrap_or("")
        {
            return false;
        }
        if active_count(new) == 0 {
            return false;
        }
        true
    }

    pub(super) fn validate_manifest_transition_for_operation(
        old: &GroupManifest,
        new: &GroupManifest,
        proof: &GroupMembershipProof,
    ) -> bool {
        if !Self::validate_manifest_transition(old, new) {
            return false;
        }
        if proof.signer_user_id != new.signer_user_id
            || proof.signer_device_id != new.signer_device_id
        {
            return false;
        }
        match proof.operation.as_str() {
            "create" => Self::manifest_transition_matches(old, new, |expected| {
                expected.last_commit_message_id = new.last_commit_message_id.clone();
            }),
            "invite" | "approve_join" => {
                Self::membership_additions_are_well_formed(old, new)
                    && Self::manifest_transition_matches(old, new, |expected| {
                        expected.members = new.members.clone();
                        expected.member_devices = new.member_devices.clone();
                        expected.last_commit_message_id = new.last_commit_message_id.clone();
                    })
            }
            operation @ ("remove" | "leave") => {
                let expected_status = if operation == "leave" {
                    GroupMemberStatus::Left
                } else {
                    GroupMemberStatus::Removed
                };
                Self::member_removal_is_well_formed(old, new, expected_status)
                    && Self::member_devices_for_removal_are_well_formed(old, new)
                    && Self::manifest_transition_matches(old, new, |expected| {
                        expected.members = new.members.clone();
                        expected.member_devices = new.member_devices.clone();
                        expected.admins = new.admins.clone();
                        expected.last_commit_message_id = new.last_commit_message_id.clone();
                    })
            }
            "add_device" => {
                Self::device_addition_is_well_formed(old, new)
                    && Self::manifest_transition_matches(old, new, |expected| {
                        expected.member_devices = new.member_devices.clone();
                        expected.last_commit_message_id = new.last_commit_message_id.clone();
                    })
            }
            "remove_device" => {
                Self::device_removal_is_well_formed(old, new)
                    && Self::manifest_transition_matches(old, new, |expected| {
                        expected.member_devices = new.member_devices.clone();
                        expected.last_commit_message_id = new.last_commit_message_id.clone();
                    })
            }
            "update_metadata" => {
                new.last_commit_message_id == old.last_commit_message_id
                    && Self::metadata_update_is_well_formed(old, new)
                    && Self::manifest_transition_matches(old, new, |expected| {
                        expected.title = new.title.clone();
                        expected.join_policy = new.join_policy;
                        expected.member_invite_policy = new.member_invite_policy;
                        expected.last_commit_message_id = new.last_commit_message_id.clone();
                    })
            }
            "set_admin" => {
                Self::admin_update_is_well_formed(old, new)
                    && Self::manifest_transition_matches(old, new, |expected| {
                        expected.members = new.members.clone();
                        expected.admins = new.admins.clone();
                        expected.last_commit_message_id = new.last_commit_message_id.clone();
                    })
            }
            "transfer_ownership" => {
                Self::ownership_transfer_is_well_formed(old, new)
                    && Self::manifest_transition_matches(old, new, |expected| {
                        expected.owner_user_id = new.owner_user_id.clone();
                        expected.members = new.members.clone();
                        expected.admins = new.admins.clone();
                        expected.last_commit_message_id = new.last_commit_message_id.clone();
                    })
            }
            "dissolve" => {
                Self::dissolve_transition_is_well_formed(old, new)
                    && Self::manifest_transition_matches(old, new, |expected| {
                        expected.members = new.members.clone();
                        expected.last_commit_message_id = new.last_commit_message_id.clone();
                    })
            }
            _ => false,
        }
    }

    pub(super) fn manifest_transition_matches<F>(
        old: &GroupManifest,
        new: &GroupManifest,
        apply_allowed_changes: F,
    ) -> bool
    where
        F: FnOnce(&mut GroupManifest),
    {
        let mut expected = old.clone();
        expected.roster_version = new.roster_version;
        expected.mls_epoch_hint = new.mls_epoch_hint;
        expected.updated_at = new.updated_at;
        expected.signer_user_id = new.signer_user_id.clone();
        expected.signer_device_id = new.signer_device_id.clone();
        expected.signature = new.signature.clone();
        apply_allowed_changes(&mut expected);
        expected == *new
    }

    pub(super) fn membership_additions_are_well_formed(
        old: &GroupManifest,
        new: &GroupManifest,
    ) -> bool {
        if new.members.len() <= old.members.len() {
            return false;
        }
        let old_members: BTreeMap<&str, &GroupMember> = old
            .members
            .iter()
            .map(|member| (member.user_id.as_str(), member))
            .collect();
        let mut added = 0usize;
        for member in &new.members {
            match old_members.get(member.user_id.as_str()) {
                Some(old_member) if **old_member == *member => {}
                Some(_) => return false,
                None => {
                    if member.role != GroupRole::Member
                        || member.status != GroupMemberStatus::Active
                    {
                        return false;
                    }
                    added = added.saturating_add(1);
                }
            }
        }
        added > 0
    }

    pub(super) fn member_removal_is_well_formed(
        old: &GroupManifest,
        new: &GroupManifest,
        expected_status: GroupMemberStatus,
    ) -> bool {
        if old.members.len() != new.members.len() {
            return false;
        }
        let mut removals = 0usize;
        for old_member in &old.members {
            let Some(new_member) = new
                .members
                .iter()
                .find(|member| member.user_id == old_member.user_id)
            else {
                return false;
            };
            if old_member == new_member {
                continue;
            }
            if old_member.role == new_member.role
                && old_member.status == GroupMemberStatus::Active
                && new_member.status == expected_status
                && old_member.role != GroupRole::Owner
            {
                removals = removals.saturating_add(1);
                continue;
            }
            return false;
        }
        removals == 1
    }

    pub(super) fn member_devices_for_removal_are_well_formed(
        old: &GroupManifest,
        new: &GroupManifest,
    ) -> bool {
        if old.member_devices.len() != new.member_devices.len() {
            return false;
        }
        let removed_user = old.members.iter().find_map(|old_member| {
            new.members
                .iter()
                .find(|member| member.user_id == old_member.user_id)
                .filter(|member| {
                    old_member.status == GroupMemberStatus::Active
                        && member.status != GroupMemberStatus::Active
                })
                .map(|_| old_member.user_id.as_str())
        });
        let Some(removed_user) = removed_user else {
            return false;
        };
        old.member_devices.iter().all(|old_device| {
            new.member_devices
                .iter()
                .find(|device| {
                    device.user_id == old_device.user_id && device.device_id == old_device.device_id
                })
                .is_some_and(|new_device| {
                    if old_device.user_id == removed_user
                        && old_device.status == GroupMemberStatus::Active
                    {
                        new_device.status == GroupMemberStatus::Removed
                    } else {
                        new_device == old_device
                    }
                })
        })
    }

    pub(super) fn device_addition_is_well_formed(old: &GroupManifest, new: &GroupManifest) -> bool {
        if old.members != new.members || new.member_devices.len() != old.member_devices.len() + 1 {
            return false;
        }
        let mut added = 0usize;
        for device in &new.member_devices {
            if old.member_devices.contains(device) {
                continue;
            }
            if device.status != GroupMemberStatus::Active
                || !old.members.iter().any(|member| {
                    member.user_id == device.user_id && member.status == GroupMemberStatus::Active
                })
            {
                return false;
            }
            added = added.saturating_add(1);
        }
        added == 1
    }

    pub(super) fn device_removal_is_well_formed(old: &GroupManifest, new: &GroupManifest) -> bool {
        if old.members != new.members || old.member_devices.len() != new.member_devices.len() {
            return false;
        }
        let mut removals = 0usize;
        for old_device in &old.member_devices {
            let Some(new_device) = new
                .member_devices
                .iter()
                .find(|device| device.device_id == old_device.device_id)
            else {
                return false;
            };
            if old_device == new_device {
                continue;
            }
            if old_device.user_id == new_device.user_id
                && old_device.status == GroupMemberStatus::Active
                && new_device.status == GroupMemberStatus::Removed
            {
                removals = removals.saturating_add(1);
                continue;
            }
            return false;
        }
        removals == 1
    }

    pub(super) fn metadata_update_is_well_formed(old: &GroupManifest, new: &GroupManifest) -> bool {
        old.title != new.title
            || old.join_policy != new.join_policy
            || old.member_invite_policy != new.member_invite_policy
    }

    pub(super) fn admin_update_is_well_formed(old: &GroupManifest, new: &GroupManifest) -> bool {
        if old.members.len() != new.members.len() {
            return false;
        }
        let mut role_changes = 0usize;
        for old_member in &old.members {
            let Some(new_member) = new
                .members
                .iter()
                .find(|member| member.user_id == old_member.user_id)
            else {
                return false;
            };
            if old_member == new_member {
                continue;
            }
            if old_member.status == new_member.status
                && old_member.status == GroupMemberStatus::Active
                && old_member.role != GroupRole::Owner
                && matches!(
                    (old_member.role, new_member.role),
                    (GroupRole::Member, GroupRole::Admin) | (GroupRole::Admin, GroupRole::Member)
                )
            {
                role_changes = role_changes.saturating_add(1);
                continue;
            }
            return false;
        }
        role_changes == 1
    }

    pub(super) fn ownership_transfer_is_well_formed(
        old: &GroupManifest,
        new: &GroupManifest,
    ) -> bool {
        if old.owner_user_id == new.owner_user_id || old.members.len() != new.members.len() {
            return false;
        }
        let mut old_owner_changed = false;
        let mut new_owner_changed = false;
        for old_member in &old.members {
            let Some(new_member) = new
                .members
                .iter()
                .find(|member| member.user_id == old_member.user_id)
            else {
                return false;
            };
            if old_member == new_member {
                continue;
            }
            if old_member.user_id == old.owner_user_id
                && new_member.user_id == old.owner_user_id
                && old_member.role == GroupRole::Owner
                && new_member.role == GroupRole::Admin
                && old_member.status == new_member.status
                && new_member.status == GroupMemberStatus::Active
            {
                old_owner_changed = true;
                continue;
            }
            if old_member.user_id == new.owner_user_id
                && new_member.user_id == new.owner_user_id
                && old_member.role != GroupRole::Owner
                && new_member.role == GroupRole::Owner
                && old_member.status == new_member.status
                && new_member.status == GroupMemberStatus::Active
            {
                new_owner_changed = true;
                continue;
            }
            return false;
        }
        old_owner_changed && new_owner_changed
    }

    pub(super) fn dissolve_transition_is_well_formed(
        old: &GroupManifest,
        new: &GroupManifest,
    ) -> bool {
        if old.members.len() != new.members.len() {
            return false;
        }
        let mut removed_count = 0usize;
        for old_member in &old.members {
            let Some(new_member) = new
                .members
                .iter()
                .find(|member| member.user_id == old_member.user_id)
            else {
                return false;
            };
            if old_member.user_id == old.owner_user_id {
                if old_member != new_member {
                    return false;
                }
                continue;
            }
            if old_member.status == GroupMemberStatus::Active
                && new_member.status == GroupMemberStatus::Removed
                && old_member.role == new_member.role
            {
                removed_count = removed_count.saturating_add(1);
                continue;
            }
            if old_member == new_member {
                continue;
            }
            return false;
        }
        removed_count > 0 || old.members.len() == 1
    }

    pub(super) fn welcome_pickup_descriptor(
        &self,
        group_id: &str,
        device_id: &str,
    ) -> CoreResult<WelcomePickupDescriptor> {
        let deployment = self
            .state
            .deployment_bundle
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("deployment bundle is not initialized"))?;
        let identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?;
        let expires_at = current_unix_millis(self.state.message_nonce) + 24 * 60 * 60 * 1000;
        let endpoint = format!(
            "{}/v1/groups/{}/welcome-pickup/{}",
            deployment.inbox_http_endpoint.trim_end_matches('/'),
            group_id,
            device_id
        );
        let capability = identity.sign_sender_proof(
            format!("welcome_pickup:{group_id}:{device_id}:{expires_at}").as_bytes(),
        );
        Ok(WelcomePickupDescriptor {
            group_id: group_id.to_string(),
            device_id: device_id.to_string(),
            endpoint,
            capability,
            expires_at,
            start_seq: None,
            roster_version: None,
            last_commit_message_id: None,
            request_id: None,
        })
    }

    pub(super) fn group_capability(
        &self,
        group_id: &str,
        role: GroupRole,
    ) -> CoreResult<GroupCapability> {
        self.require_group_authorization_v2()?;
        let identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?;
        let expires_at = current_unix_millis(self.state.message_nonce) + 24 * 60 * 60 * 1000;
        let operations = group_capability_operations(role);
        let mut capability = GroupCapability {
            version: crate::model::CURRENT_MODEL_VERSION.to_string(),
            service: CapabilityService::GroupOutbox,
            group_id: group_id.to_string(),
            user_id: identity.user_identity.user_id.clone(),
            device_id: identity.device_identity.device_id.clone(),
            operations,
            role,
            expires_at,
            signature: String::new(),
        };
        capability.signature =
            identity.sign_sender_proof(group_capability_signing_payload(&capability).as_bytes());
        Ok(capability)
    }

    pub(super) fn require_group_authorization_v2(&self) -> CoreResult<()> {
        let supported = self
            .state
            .deployment_bundle
            .as_ref()
            .is_some_and(|deployment| {
                deployment
                    .runtime_config
                    .features
                    .iter()
                    .any(|feature| feature == "group_authorization_v2")
            });
        if supported {
            Ok(())
        } else {
            Err(CoreError::invalid_state(
                "group operations require a runtime with group_authorization_v2; upgrade or redeploy the transport",
            ))
        }
    }

    pub(super) fn require_group_membership_fsm_v2(&self) -> CoreResult<()> {
        let supported = self
            .state
            .deployment_bundle
            .as_ref()
            .is_some_and(|deployment| {
                deployment
                    .runtime_config
                    .features
                    .iter()
                    .any(|feature| feature == "group_membership_fsm_v2")
            });
        if supported {
            Ok(())
        } else {
            Err(CoreError::invalid_state(
                "group state changes require a runtime with group_membership_fsm_v2; upgrade or redeploy the transport",
            ))
        }
    }

    pub(super) fn ensure_group_state_operation_ready(&self, group_id: &str) -> CoreResult<()> {
        let state = self
            .state
            .group_states
            .get(group_id)
            .ok_or_else(|| CoreError::invalid_input("group does not exist"))?;
        if state.consistency_state != GroupConsistencyState::Ready {
            return Err(CoreError::invalid_state(
                "group state is reconciling or blocked; wait for synchronization before changing membership",
            ));
        }
        if state.pending_group_transition.is_some() {
            return Err(CoreError::invalid_state(
                "another group state transition is already in progress",
            ));
        }
        Ok(())
    }

    pub(super) fn group_capability_for_state(
        &self,
        state: &PersistedGroupState,
    ) -> CoreResult<GroupCapability> {
        let local_user_id = self.local_identity_user_id()?;
        let role = state
            .local_role
            .or_else(|| {
                state
                    .manifest
                    .members
                    .iter()
                    .find(|member| member.user_id == local_user_id)
                    .map(|member| member.role)
            })
            .ok_or_else(|| CoreError::invalid_input("local group role is missing"))?;
        self.group_capability(&state.group_id, role)
    }

    pub(super) fn group_authorization_update(
        &self,
        group_id: &str,
    ) -> CoreResult<GroupAuthorizationUpdate> {
        let group_state = self
            .state
            .group_states
            .get(group_id)
            .ok_or_else(|| CoreError::invalid_input("group does not exist"))?;
        let manifest = group_state
            .pending_group_transition
            .as_ref()
            .map(|transition| &transition.proposed_manifest)
            .unwrap_or(&group_state.manifest);
        self.group_authorization_update_for_manifest(manifest, false)
    }

    pub(super) fn group_authorization_update_for_manifest(
        &self,
        manifest: &GroupManifest,
        require_all_active_members: bool,
    ) -> CoreResult<GroupAuthorizationUpdate> {
        let mut user_ids = manifest
            .members
            .iter()
            .filter(|member| member.status == GroupMemberStatus::Active)
            .map(|member| member.user_id.clone())
            .collect::<BTreeSet<_>>();
        user_ids.insert(manifest.signer_user_id.clone());

        let local_user_id = self
            .state
            .local_identity
            .as_ref()
            .map(|identity| identity.user_identity.user_id.as_str());
        let mut identity_bundles = Vec::new();
        for user_id in user_ids {
            let bundle = if local_user_id == Some(user_id.as_str()) {
                self.state.local_bundle.clone()
            } else {
                self.state
                    .contacts
                    .get(&user_id)
                    .map(|contact| contact.bundle.clone())
            };
            match bundle {
                Some(bundle) => identity_bundles.push(bundle),
                None if require_all_active_members || user_id == manifest.signer_user_id => {
                    return Err(CoreError::invalid_state(format!(
                        "identity bundle is missing for active group member {user_id}"
                    )));
                }
                None => {}
            }
        }
        identity_bundles.sort_by(|left, right| left.user_id.cmp(&right.user_id));
        Ok(GroupAuthorizationUpdate {
            manifest: manifest.clone(),
            identity_bundles,
        })
    }

    pub(super) fn initialize_group_authorization_request(
        &self,
        group_id: &str,
    ) -> CoreResult<InitializeGroupAuthorizationRequest> {
        let manifest = &self
            .state
            .group_states
            .get(group_id)
            .ok_or_else(|| CoreError::invalid_input("group does not exist"))?
            .manifest;
        let update = self.group_authorization_update_for_manifest(manifest, true)?;
        Ok(InitializeGroupAuthorizationRequest {
            version: crate::model::CURRENT_MODEL_VERSION.to_string(),
            group_id: group_id.to_string(),
            manifest: update.manifest,
            identity_bundles: update.identity_bundles,
            headers: BTreeMap::new(),
            auth: Some(self.device_runtime_auth_requirement()?),
        })
    }

    pub(super) fn local_group_role(&self, group_id: &str) -> CoreResult<GroupRole> {
        self.state
            .group_states
            .get(group_id)
            .and_then(|state| state.local_role)
            .ok_or_else(|| CoreError::invalid_input("local group role is missing"))
    }

    pub(super) fn group_id_for_conversation(&self, conversation_id: &str) -> CoreResult<&str> {
        self.state
            .group_states
            .values()
            .find(|state| state.conversation_id == conversation_id)
            .map(|state| state.group_id.as_str())
            .ok_or_else(|| CoreError::invalid_input("group conversation does not exist"))
    }

    pub(super) fn ensure_group_ready_for_send(&self, conversation_id: &str) -> CoreResult<()> {
        let conversation = self
            .state
            .conversations
            .get(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?;
        if conversation.conversation.kind != ConversationKind::Group {
            return Err(CoreError::invalid_input("conversation is not a group"));
        }
        if conversation.conversation.state == ConversationState::Dissolved {
            return Err(CoreError::invalid_input("group is dissolved"));
        }
        if conversation.conversation.state == ConversationState::NeedsRebuild
            || conversation.recovery_status != RecoveryStatus::Healthy
        {
            return Err(CoreError::temporary_failure(
                "group conversation is not ready for sending",
            ));
        }
        let summary = self
            .state
            .mls_summaries
            .get(conversation_id)
            .ok_or_else(|| CoreError::invalid_state("group MLS state is missing"))?;
        if summary.status != MlsStateStatus::Active {
            return Err(CoreError::temporary_failure(
                "group MLS state is not active",
            ));
        }
        let local_identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?;
        let group_state = self
            .state
            .group_states
            .values()
            .find(|state| state.conversation_id == conversation_id)
            .ok_or_else(|| CoreError::invalid_input("group conversation does not exist"))?;
        // A.5: dissolved groups fail-closed locally before any transport
        // layer gets involved — even if `ConversationState` has not yet been
        // flipped to Dissolved (the transition happens on
        // `CoreEvent::GroupOutboxSealed`, so between the initial
        // `DissolveGroup` command and the seal ack there is a brief window
        // where `dissolved_at.is_some()` but conversation state is still
        // Active).
        if group_state.dissolved_at.is_some() {
            return Err(CoreError::invalid_input("group is dissolved"));
        }
        // The pending membership transition check protects receivers from
        // sending application messages before the matching control message
        // for a membership change is processed. When the pending transition
        // was signed by the local user the sender is the same user who
        // initiated the change and already holds a consistent manifest —
        // no need to block.
        if let Some(ref pending) = group_state.pending_membership_transition {
            let local_user_id = &local_identity.user_identity.user_id;
            if pending.proof.signer_user_id != *local_user_id {
                return Err(CoreError::temporary_failure(
                    "group has a pending membership transition from another user; send is blocked until manifest control is verified",
                ));
            }
        }
        let Some(local_role) = group_state.local_role else {
            return Err(CoreError::invalid_input("local group member is not active"));
        };
        let local_is_active = group_state.manifest.members.iter().any(|member| {
            member.user_id == local_identity.user_identity.user_id
                && member.role == local_role
                && member.status == GroupMemberStatus::Active
        });
        if !local_is_active {
            return Err(CoreError::invalid_input("local group member is not active"));
        }
        let has_pending_membership_commit = self.state.pending_group_outbox.iter().any(|item| {
            item.envelope.group_id == group_state.group_id
                && item.envelope.message_type == GroupMessageType::MlsCommit
        });
        if has_pending_membership_commit {
            return Err(CoreError::temporary_failure(
                "group has a pending membership commit; send is blocked until MLS state converges",
            ));
        }
        Ok(())
    }

    pub(super) fn next_group_id(&mut self, title: &str, members: &[String]) -> String {
        let nonce = self.next_message_nonce();
        let local_user_id = self
            .state
            .local_identity
            .as_ref()
            .map(|identity| identity.user_identity.user_id.as_str())
            .unwrap_or("user:local");
        let mut hasher = Sha256::new();
        hasher.update(local_user_id.as_bytes());
        hasher.update(title.as_bytes());
        for member in members {
            hasher.update(member.as_bytes());
        }
        hasher.update(nonce.to_be_bytes());
        let digest = hasher.finalize();
        format!("group:{}", hex_prefix(&digest, 16))
    }
}

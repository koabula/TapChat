use super::*;

impl CoreEngine {
    pub(super) fn import_deployment_bundle(
        &mut self,
        bundle: crate::model::DeploymentBundle,
    ) -> CoreResult<CoreOutput> {
        bundle.validate()?;
        self.state.deployment_bundle = Some(bundle);
        self.refresh_local_bundle()?;
        let mut output = CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: self.state.local_bundle.is_some(),
                checkpoints_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(
                &self.state,
                vec![PersistOp::SaveDeployment, PersistOp::SaveLocalIdentity],
            )],
            view_model: None,
        };
        output
            .effects
            .extend(self.local_shared_state_publish_effects()?);
        if self.state.pending_key_package_publish.is_some() {
            output.effects.push(self.key_package_publish_effect()?);
        }
        Ok(output)
    }

    pub(super) fn import_identity_bundle(
        &mut self,
        bundle: IdentityBundle,
    ) -> CoreResult<CoreOutput> {
        let relationship_status = self
            .state
            .contacts
            .get(&bundle.user_id)
            .map(|c| c.relationship_status.clone())
            .filter(|status| !Self::relationship_is_removed(status))
            .unwrap_or_default();
        self.import_identity_bundle_with_relationship_status(bundle, relationship_status)
    }

    pub(super) fn import_identity_bundle_with_relationship_status(
        &mut self,
        bundle: IdentityBundle,
        relationship_status: ContactRelationshipStatus,
    ) -> CoreResult<CoreOutput> {
        IdentityManager::verify_identity_bundle(&bundle)?;
        let user_id = bundle.user_id.clone();
        let original_name = bundle.display_name.clone();
        let now = current_timestamp_hint(self.state.outbox.len());

        // Check if contact already exists to preserve user's display_name
        let existing_display_name = self
            .state
            .contacts
            .get(&user_id)
            .and_then(|c| c.display_name.clone());
        let existing_relationship_status = self
            .state
            .contacts
            .get(&user_id)
            .map(|c| c.relationship_status.clone());
        let relationship_status = if Self::relationship_is_removed(&relationship_status) {
            ContactRelationshipStatus::default()
        } else {
            relationship_status
        };
        let relationship_status =
            match (existing_relationship_status.as_ref(), &relationship_status) {
                (
                    Some(ContactRelationshipStatus::Available),
                    ContactRelationshipStatus::PendingOutbound,
                ) => ContactRelationshipStatus::Available,
                _ => relationship_status,
            };

        let persisted_contact = PersistedContact {
            user_id: user_id.clone(),
            bundle,
            display_name: existing_display_name,
            original_name,
            relationship_status,
            added_at: now,
        };

        self.state
            .contacts
            .insert(user_id.clone(), persisted_contact);
        let persist_ops = vec![PersistOp::SaveContact {
            user_id: user_id.clone(),
        }];
        let mut output = CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(&self.state, persist_ops)],
            view_model: None,
        };
        if self.state.deployment_bundle.is_some() {
            output = merge_outputs(output, self.add_allowlist_user(user_id)?);
        }
        Ok(output)
    }

    pub(super) fn apply_identity_bundle_update(
        &mut self,
        bundle: IdentityBundle,
    ) -> CoreResult<CoreOutput> {
        IdentityManager::verify_identity_bundle(&bundle)?;
        let user_id = bundle.user_id.clone();
        let affected_conversations = self.affected_conversations_for_peer(&user_id);

        // Preserve existing display_name, update original_name if bundle has display_name
        let existing = self.state.contacts.get(&user_id);
        let display_name = existing.and_then(|c| c.display_name.clone());
        let original_name = bundle
            .display_name
            .clone()
            .or(existing.and_then(|c| c.original_name.clone()));
        let added_at = existing
            .map(|c| c.added_at)
            .unwrap_or_else(|| current_timestamp_hint(self.state.outbox.len()));
        let relationship_status = existing
            .map(|c| c.relationship_status.clone())
            .unwrap_or_default();

        let persisted_contact = PersistedContact {
            user_id: user_id.clone(),
            bundle,
            display_name,
            original_name,
            relationship_status,
            added_at,
        };

        self.state
            .contacts
            .insert(user_id.clone(), persisted_contact);

        let mut output = CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(
                &self.state,
                vec![PersistOp::SaveContact {
                    user_id: user_id.clone(),
                }],
            )],
            view_model: None,
        };
        for conversation_id in affected_conversations {
            self.mark_recovery_needed(&conversation_id, RecoveryReason::IdentityChanged);
            self.transition_recovery_phase(
                &conversation_id,
                RecoveryPhase::WaitingForExplicitReconcile,
            );
            output = merge_outputs(
                output,
                self.reconcile_conversation_membership(conversation_id)?,
            );
        }
        if let Some(device_id) = self
            .state
            .local_identity
            .as_ref()
            .map(|identity| identity.device_identity.device_id.clone())
        {
            output = merge_outputs(output, self.replay_pending_records_for_device(device_id)?);
        }
        self.merge_with_transport_flush(output)
    }

    pub(super) fn create_or_load_identity(
        &mut self,
        mnemonic: Option<String>,
        device_name: Option<String>,
        display_name: Option<String>,
    ) -> CoreResult<CoreOutput> {
        let display_name_was_provided = display_name.is_some();
        let display_name = normalize_display_name(display_name)?;
        let effective_display_name = if display_name_was_provided {
            display_name
        } else {
            self.local_display_name()
        };

        let identity = if let Some(existing) = self.state.local_identity.clone() {
            if let Some(provided_mnemonic) = mnemonic.as_deref() {
                let recovered = IdentityManager::recover_user_root(provided_mnemonic)?;
                if recovered.user_identity.user_id != existing.user_identity.user_id {
                    return Err(CoreError::invalid_input(
                        "provided mnemonic does not match persisted local identity",
                    ));
                }
            }
            existing
        } else {
            IdentityManager::create_or_recover(mnemonic.as_deref(), device_name.as_deref())?
        };
        let (mut adapter, package) = crate::mls_adapter::MlsAdapter::bootstrap(&identity)?;
        let now_ms = current_unix_millis(self.state.message_nonce);
        let mut packages = vec![package];
        packages.extend(adapter.generate_key_package_pool(
            now_ms,
            crate::mls_adapter::KEY_PACKAGE_POOL_TARGET.saturating_sub(1),
        )?);
        let user_id = identity.user_identity.user_id.clone();
        let device_id = identity.device_identity.device_id.clone();
        self.state.local_identity = Some(identity);
        self.state.mls_adapter = Some(adapter);
        self.stage_initial_key_package_pool(packages, now_ms);
        self.state.local_display_name = effective_display_name.clone();
        self.state
            .sync_states
            .insert(device_id.clone(), SyncEngine::new_device_state(&device_id));
        self.refresh_local_bundle()?;
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                identity_changed: true,
                checkpoints_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(
                &self.state,
                vec![PersistOp::SaveLocalIdentity, PersistOp::SaveDeployment],
            )],
            view_model: Some(CoreViewModel {
                identity: Some(LocalIdentitySummary {
                    user_id,
                    device_id: device_id.clone(),
                    display_name: effective_display_name,
                }),
                banners: vec![SystemBanner {
                    status: SystemStatus::IdentityRefreshNeeded,
                    message: format!("local identity ready for {device_id}"),
                }],
                ..CoreViewModel::default()
            }),
        })
    }

    pub(super) fn create_additional_device_identity(
        &mut self,
        mnemonic: Option<String>,
        device_name: Option<String>,
        display_name: Option<String>,
    ) -> CoreResult<CoreOutput> {
        self.ensure_identity_publication_idle()?;
        let display_name_was_provided = display_name.is_some();
        let display_name = normalize_display_name(display_name)?;
        let effective_display_name = if display_name_was_provided {
            display_name
        } else {
            self.local_display_name()
        };
        let mnemonic = mnemonic.ok_or_else(|| {
            CoreError::invalid_input("mnemonic is required to create an additional device")
        })?;
        let recovered = IdentityManager::recover_user_root(&mnemonic)?;
        if let Some(existing) = self.state.local_identity.as_ref() {
            if existing.user_identity.user_id != recovered.user_identity.user_id {
                return Err(CoreError::invalid_input(
                    "provided mnemonic does not match persisted local identity",
                ));
            }
        }
        let _ = device_name;
        let identity = IdentityManager::create_new_device_for_user(&recovered, None)?;
        let (mut adapter, package) = crate::mls_adapter::MlsAdapter::bootstrap(&identity)?;
        let now_ms = current_unix_millis(self.state.message_nonce);
        let mut packages = vec![package];
        packages.extend(adapter.generate_key_package_pool(
            now_ms,
            crate::mls_adapter::KEY_PACKAGE_POOL_TARGET.saturating_sub(1),
        )?);
        let user_id = identity.user_identity.user_id.clone();
        let device_id = identity.device_identity.device_id.clone();
        self.state.local_identity = Some(identity);
        self.state.mls_adapter = Some(adapter);
        self.stage_initial_key_package_pool(packages, now_ms);
        self.state.local_display_name = effective_display_name.clone();
        self.state
            .sync_states
            .insert(device_id.clone(), SyncEngine::new_device_state(&device_id));
        self.refresh_local_bundle()?;
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                identity_changed: true,
                checkpoints_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(
                &self.state,
                vec![PersistOp::SaveLocalIdentity, PersistOp::SaveDeployment],
            )],
            view_model: Some(CoreViewModel {
                identity: Some(LocalIdentitySummary {
                    user_id,
                    device_id: device_id.clone(),
                    display_name: effective_display_name,
                }),
                banners: vec![SystemBanner {
                    status: SystemStatus::IdentityRefreshNeeded,
                    message: format!("additional local device ready for {device_id}"),
                }],
                ..CoreViewModel::default()
            }),
        })
    }

    pub(super) fn rotate_local_key_package(&mut self) -> CoreResult<CoreOutput> {
        let now_ms = current_unix_millis(self.state.message_nonce);
        self.stage_key_package_pool_refill(now_ms, false, true)
    }

    pub(super) fn local_credential_maintenance_due(&self, now_ms: u64) -> bool {
        if let Some(pending) = self.state.pending_identity_publication.as_ref() {
            return now_ms >= pending.next_retry_at;
        }
        if self.state.deployment_bundle.is_none() || self.state.mls_adapter.is_none() {
            return false;
        }
        let Some(device_id) = self
            .state
            .local_identity
            .as_ref()
            .map(|identity| identity.device_identity.device_id.as_str())
        else {
            return false;
        };
        self.state
            .pending_key_package_publish
            .as_ref()
            .is_some_and(|pending| now_ms >= pending.next_retry_at)
            || self.usable_key_package_count(now_ms)
                < crate::mls_adapter::KEY_PACKAGE_POOL_REFILL_THRESHOLD
            || self.local_inbox_capability_due(now_ms, device_id)
    }

    pub(super) fn maintain_local_credentials(&mut self, now_ms: u64) -> CoreResult<CoreOutput> {
        let timer = CoreEffect::ScheduleTimer {
            timer: TimerEffect {
                timer_id: "credential_maintenance".into(),
                delay_ms: 24 * 60 * 60 * 1000,
            },
        };
        if self.state.deployment_bundle.is_none() || self.state.mls_adapter.is_none() {
            return Ok(CoreOutput {
                effects: vec![timer],
                ..CoreOutput::default()
            });
        }
        if let Some(pending) = self.state.pending_identity_publication.clone() {
            let mut effects = vec![timer];
            if now_ms >= pending.next_retry_at {
                effects.insert(
                    0,
                    self.identity_bundle_publish_effect(
                        &pending.candidate_bundle,
                        pending.operation_id,
                        pending.expected_etag.as_deref(),
                    )?,
                );
            }
            return Ok(CoreOutput {
                effects,
                ..CoreOutput::default()
            });
        }
        let device_id = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .device_identity
            .device_id
            .clone();
        if self
            .state
            .pending_key_package_publish
            .as_ref()
            .is_some_and(|pending| now_ms >= pending.next_retry_at)
            || self.usable_key_package_count(now_ms)
                < crate::mls_adapter::KEY_PACKAGE_POOL_REFILL_THRESHOLD
        {
            return self.stage_key_package_pool_refill(now_ms, true, false);
        }
        if self.local_inbox_capability_due(now_ms, &device_id) {
            return self.stage_local_inbox_capability_renewal(now_ms, true);
        }
        {
            return Ok(CoreOutput {
                effects: vec![timer],
                ..CoreOutput::default()
            });
        }
    }

    fn local_inbox_capability_due(&self, now_ms: u64, device_id: &str) -> bool {
        self.state
            .local_bundle
            .as_ref()
            .and_then(|bundle| {
                bundle
                    .devices
                    .iter()
                    .find(|device| device.device_id == device_id)
            })
            .and_then(|device| device.inbox_append_capability.as_ref())
            .is_none_or(|capability| {
                capability.expires_at
                    <= now_ms.saturating_add(
                        crate::capability::INBOX_APPEND_CAPABILITY_RENEWAL_WINDOW_MS,
                    )
            })
    }

    fn stage_initial_key_package_pool(
        &mut self,
        mut packages: Vec<crate::mls_adapter::PublishedKeyPackage>,
        now_ms: u64,
    ) {
        for package in &mut packages {
            package.state = crate::mls_adapter::PublishedKeyPackageState::PendingPublish;
        }
        let package_ids = packages
            .iter()
            .map(|package| package.key_package_id.clone())
            .collect();
        let device_id = self
            .state
            .local_identity
            .as_ref()
            .map(|identity| identity.device_identity.device_id.clone())
            .unwrap_or_default();
        self.state.published_key_package = None;
        self.state.key_package_inventory = packages;
        self.state.pending_key_package_publish = Some(PendingKeyPackagePublish {
            idempotency_key: random_opaque_id("kppub"),
            device_id,
            package_ids,
            created_at: now_ms,
            attempt_count: 0,
            next_retry_at: now_ms,
        });
    }

    fn usable_key_package_count(&self, now_ms: u64) -> usize {
        self.state
            .key_package_inventory
            .iter()
            .filter(|package| {
                !package.is_expired_at(now_ms)
                    && matches!(
                        package.state,
                        crate::mls_adapter::PublishedKeyPackageState::PendingPublish
                            | crate::mls_adapter::PublishedKeyPackageState::Advertised
                    )
            })
            .count()
    }

    pub(super) fn stage_key_package_pool_refill(
        &mut self,
        now_ms: u64,
        schedule_next_check: bool,
        force: bool,
    ) -> CoreResult<CoreOutput> {
        if self.state.deployment_bundle.is_none() || self.state.local_bundle.is_none() {
            return Err(CoreError::invalid_state(
                "deployment and IdentityBundle V2 are required to publish KeyPackages",
            ));
        }
        if self.state.local_bundle.as_ref().is_none_or(|bundle| {
            bundle.publication_version < crate::model::IDENTITY_PUBLICATION_VERSION_V2
        }) {
            return Err(CoreError::new(
                "protocol_upgrade_required",
                "KeyPackage pools require IdentityBundle V2",
            ));
        }

        self.state
            .key_package_inventory
            .iter_mut()
            .for_each(|package| {
                if package.is_expired_at(now_ms)
                    && !matches!(
                        package.state,
                        crate::mls_adapter::PublishedKeyPackageState::Claimed
                    )
                {
                    package.state = crate::mls_adapter::PublishedKeyPackageState::Expired;
                }
            });

        if self.state.pending_key_package_publish.is_none() {
            let current = self.usable_key_package_count(now_ms);
            let desired = crate::mls_adapter::KEY_PACKAGE_POOL_TARGET.saturating_sub(current);
            let count = if force {
                desired
                    .max(1)
                    .min(crate::mls_adapter::KEY_PACKAGE_POOL_TARGET)
            } else {
                desired
            };
            if count > 0 {
                let mut generated = self
                    .state
                    .mls_adapter
                    .as_mut()
                    .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
                    .generate_key_package_pool(now_ms, count)?;
                for package in &mut generated {
                    package.state = crate::mls_adapter::PublishedKeyPackageState::PendingPublish;
                }
                let package_ids = generated
                    .iter()
                    .map(|package| package.key_package_id.clone())
                    .collect::<Vec<_>>();
                let device_id = self.local_identity_device_id()?;
                self.state.key_package_inventory.extend(generated);
                self.state.pending_key_package_publish = Some(PendingKeyPackagePublish {
                    idempotency_key: random_opaque_id("kppub"),
                    device_id,
                    package_ids,
                    created_at: now_ms,
                    attempt_count: 0,
                    next_retry_at: now_ms,
                });
            }
        }

        let mut effects = vec![persist_effect(
            &self.state,
            vec![PersistOp::SaveLocalIdentity, PersistOp::SaveDeployment],
        )];
        if self.state.pending_key_package_publish.is_some() {
            effects.push(self.key_package_publish_effect()?);
        }
        if schedule_next_check {
            effects.push(CoreEffect::ScheduleTimer {
                timer: TimerEffect {
                    timer_id: "credential_maintenance".into(),
                    delay_ms: 24 * 60 * 60 * 1000,
                },
            });
        }
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                system_statuses_changed: vec![SystemStatus::SyncInProgress],
                ..CoreStateUpdate::default()
            },
            effects,
            view_model: None,
        })
    }

    pub(super) fn key_package_publish_effect(&mut self) -> CoreResult<CoreEffect> {
        let pending = self
            .state
            .pending_key_package_publish
            .clone()
            .ok_or_else(|| CoreError::invalid_state("no KeyPackage publication is pending"))?;
        let identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?;
        let bundle = self
            .state
            .local_bundle
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local IdentityBundle is unavailable"))?;
        if bundle.publication_version < crate::model::IDENTITY_PUBLICATION_VERSION_V2 {
            return Err(CoreError::new(
                "protocol_upgrade_required",
                "KeyPackage publication requires IdentityBundle V2",
            ));
        }
        let mls_signature_public_key = self
            .state
            .mls_adapter
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .signature_public_key();
        let packages = pending
            .package_ids
            .iter()
            .map(|package_id| {
                let package = self
                    .state
                    .key_package_inventory
                    .iter()
                    .find(|package| package.key_package_id == *package_id)
                    .ok_or_else(|| {
                        CoreError::invalid_state("pending KeyPackage inventory entry is missing")
                    })?;
                Ok(PublishedKeyPackageV2 {
                    key_package_id: package.key_package_id.clone(),
                    key_package_b64: package.key_package_b64.clone(),
                    lifecycle_version: package.lifecycle_version,
                    not_before: package.not_before,
                    created_at: package.created_at,
                    expires_at: package.expires_at,
                    mls_signature_public_key: mls_signature_public_key.clone(),
                })
            })
            .collect::<CoreResult<Vec<_>>>()?;
        let mut request_body = PublishKeyPackageBatchRequest {
            version: crate::model::ENVELOPE_VERSION_V2.into(),
            device_id: pending.device_id.clone(),
            packages,
            idempotency_key: pending.idempotency_key.clone(),
            signature: String::new(),
        };
        request_body.signature = identity.sign_device_payload(&request_body.signing_payload());
        let request_id = format!("keypackage-publish:{}", pending.idempotency_key);
        self.state.pending_requests.insert(
            request_id.clone(),
            PendingRequest::PublishKeyPackages {
                idempotency_key: pending.idempotency_key,
                package_ids: pending.package_ids,
            },
        );
        let endpoint = self
            .state
            .deployment_bundle
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("deployment is unavailable"))?
            .inbox_http_endpoint
            .trim_end_matches('/')
            .to_string();
        Ok(CoreEffect::ExecuteHttpRequest {
            request: HttpRequestEffect {
                request_id,
                method: HttpMethod::Post,
                url: format!("{endpoint}/v2/device-registry/key-packages"),
                headers: BTreeMap::new(),
                auth: Some(self.device_runtime_auth_requirement()?),
                body: Some(serde_json::to_string(&request_body).map_err(|error| {
                    CoreError::invalid_input(format!("failed to encode KeyPackage batch: {error}"))
                })?),
            },
        })
    }

    fn stage_local_key_package_rotation(
        &mut self,
        now_ms: u64,
        schedule_next_check: bool,
    ) -> CoreResult<CoreOutput> {
        let previous_bundle = self.state.local_bundle.clone();
        let package = self
            .state
            .mls_adapter
            .as_mut()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .rotate_key_package(now_ms)?;
        self.install_published_key_package(
            package,
            crate::mls_adapter::PublishedKeyPackageState::Retired,
        );
        let updated_at = self
            .state
            .local_bundle
            .as_ref()
            .map(|bundle| bundle.updated_at.saturating_add(1))
            .unwrap_or(now_ms.max(1));
        if let Some(identity) = self.state.local_identity.as_mut() {
            identity.device_status.updated_at = updated_at;
        }
        self.refresh_local_bundle_with_updated_at_at(updated_at, now_ms)?;
        let candidate_bundle =
            self.state.local_bundle.clone().ok_or_else(|| {
                CoreError::invalid_state("candidate identity bundle is unavailable")
            })?;
        let operation_id = format!(
            "credential_maintenance:{}",
            candidate_bundle.publication_revision
        );
        if candidate_bundle.identity_bundle_ref.is_some() {
            if let Some(previous_bundle) = previous_bundle {
                self.state.local_bundle = Some(previous_bundle.clone());
                self.state.pending_identity_publication =
                    Some(crate::persistence::PendingIdentityPublication {
                        operation_id: operation_id.clone(),
                        reason: "keypackage_rotation".into(),
                        previous_bundle,
                        candidate_bundle: candidate_bundle.clone(),
                        expected_etag: None,
                        stage: crate::persistence::PendingIdentityPublicationStage::AwaitingPublish,
                        attempt_count: 0,
                        next_retry_at: now_ms,
                    });
            }
        }
        let mut effects = vec![persist_effect(
            &self.state,
            vec![PersistOp::SaveLocalIdentity, PersistOp::SaveDeployment],
        )];
        if candidate_bundle.identity_bundle_ref.is_some() {
            effects.push(self.identity_bundle_publish_effect(
                &candidate_bundle,
                operation_id,
                None,
            )?);
        }
        if schedule_next_check {
            effects.push(CoreEffect::ScheduleTimer {
                timer: TimerEffect {
                    timer_id: "credential_maintenance".into(),
                    delay_ms: 24 * 60 * 60 * 1000,
                },
            });
        }
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                system_statuses_changed: vec![SystemStatus::SyncInProgress],
                ..CoreStateUpdate::default()
            },
            effects,
            view_model: Some(CoreViewModel {
                banners: vec![SystemBanner {
                    status: SystemStatus::SyncInProgress,
                    message: "TapChat is refreshing your secure contact information. Existing conversations still work.".into(),
                }],
                ..CoreViewModel::default()
            }),
        })
    }

    fn stage_local_inbox_capability_renewal(
        &mut self,
        now_ms: u64,
        schedule_next_check: bool,
    ) -> CoreResult<CoreOutput> {
        let previous_bundle = self
            .state
            .local_bundle
            .clone()
            .ok_or_else(|| CoreError::invalid_state("local identity bundle is unavailable"))?;
        let updated_at = previous_bundle.updated_at.saturating_add(1);
        if let Some(identity) = self.state.local_identity.as_mut() {
            identity.device_status.updated_at = updated_at;
        }
        self.refresh_local_bundle_with_updated_at_at(updated_at, now_ms)?;
        let candidate_bundle =
            self.state.local_bundle.clone().ok_or_else(|| {
                CoreError::invalid_state("candidate identity bundle is unavailable")
            })?;
        let operation_id = format!(
            "credential_maintenance:{}",
            candidate_bundle.publication_revision
        );
        if candidate_bundle.identity_bundle_ref.is_some() {
            self.state.local_bundle = Some(previous_bundle.clone());
            self.state.pending_identity_publication =
                Some(crate::persistence::PendingIdentityPublication {
                    operation_id: operation_id.clone(),
                    reason: "inbox_capability_renewal".into(),
                    previous_bundle,
                    candidate_bundle: candidate_bundle.clone(),
                    expected_etag: None,
                    stage: crate::persistence::PendingIdentityPublicationStage::AwaitingPublish,
                    attempt_count: 0,
                    next_retry_at: now_ms,
                });
        }
        let mut effects = vec![persist_effect(
            &self.state,
            vec![PersistOp::SaveLocalIdentity, PersistOp::SaveDeployment],
        )];
        if candidate_bundle.identity_bundle_ref.is_some() {
            effects.push(self.identity_bundle_publish_effect(
                &candidate_bundle,
                operation_id,
                None,
            )?);
        }
        if schedule_next_check {
            effects.push(CoreEffect::ScheduleTimer {
                timer: TimerEffect {
                    timer_id: "credential_maintenance".into(),
                    delay_ms: 24 * 60 * 60 * 1000,
                },
            });
        }
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                system_statuses_changed: vec![SystemStatus::SyncInProgress],
                ..CoreStateUpdate::default()
            },
            effects,
            view_model: Some(CoreViewModel {
                banners: vec![SystemBanner {
                    status: SystemStatus::SyncInProgress,
                    message: "TapChat is refreshing your secure contact information. Existing conversations still work.".into(),
                }],
                ..CoreViewModel::default()
            }),
        })
    }

    pub(super) fn rotate_local_key_package_after_welcome(&mut self) -> CoreResult<Vec<CoreEffect>> {
        let now_ms = current_unix_millis(self.state.message_nonce);
        // A claimed KeyPackage is one-shot and is burned by OpenMLS while the
        // corresponding Welcome is staged. Replenishment is therefore a pool
        // publication, never an IdentityBundle mutation. `force` guarantees
        // that a successful Welcome replaces one server-side consumed slot;
        // an already pending batch remains idempotent and is simply retried.
        Ok(self
            .stage_key_package_pool_refill(now_ms, false, true)?
            .effects)
    }

    fn install_published_key_package(
        &mut self,
        mut package: crate::mls_adapter::PublishedKeyPackage,
        prior_state: crate::mls_adapter::PublishedKeyPackageState,
    ) {
        if let Some(current) = self.state.published_key_package.as_ref() {
            if let Some(existing) = self
                .state
                .key_package_inventory
                .iter_mut()
                .find(|item| item.key_package_ref == current.key_package_ref)
            {
                existing.state = prior_state;
            } else {
                let mut retained = current.clone();
                retained.state = prior_state;
                self.state.key_package_inventory.push(retained);
            }
        }
        package.state = crate::mls_adapter::PublishedKeyPackageState::Advertised;
        self.state
            .key_package_inventory
            .retain(|item| item.key_package_ref != package.key_package_ref);
        self.state.key_package_inventory.push(package.clone());
        self.state.published_key_package = Some(package);
    }

    pub(super) fn apply_local_device_status_update(
        &mut self,
        status: crate::model::DeviceStatusKind,
    ) -> CoreResult<CoreOutput> {
        let device_id = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .device_identity
            .device_id
            .clone();
        self.update_local_device_status(device_id, status)
    }

    pub(super) fn update_local_device_status(
        &mut self,
        target_device_id: String,
        status: crate::model::DeviceStatusKind,
    ) -> CoreResult<CoreOutput> {
        self.ensure_identity_publication_idle()?;
        let local_device_id = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .device_identity
            .device_id
            .clone();
        let updated_at = if target_device_id == local_device_id {
            let identity = self
                .state
                .local_identity
                .as_mut()
                .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?;
            identity.device_status.status = status;
            identity.device_status.updated_at = identity.device_status.updated_at.saturating_add(1);
            identity.device_status.updated_at
        } else {
            let local_bundle =
                self.state.local_bundle.as_mut().ok_or_else(|| {
                    CoreError::invalid_state("local identity bundle is unavailable")
                })?;
            let device = local_bundle
                .devices
                .iter_mut()
                .find(|device| device.device_id == target_device_id)
                .ok_or_else(|| {
                    CoreError::invalid_input(
                        "target device is not present in local identity bundle",
                    )
                })?;
            device.status = status;
            local_bundle.updated_at = local_bundle.updated_at.saturating_add(1);
            local_bundle.updated_at
        };
        self.refresh_local_bundle_with_updated_at(updated_at)?;
        let mut output = CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(
                &self.state,
                vec![PersistOp::SaveLocalIdentity, PersistOp::SaveDeployment],
            )],
            view_model: None,
        };
        output
            .effects
            .extend(self.local_shared_state_publish_effects()?);
        Ok(output)
    }

    pub(super) fn create_conversation(
        &mut self,
        peer_user_id: String,
        conversation_kind: ConversationKind,
    ) -> CoreResult<CoreOutput> {
        if conversation_kind != ConversationKind::Direct {
            return Err(CoreError::unsupported(
                "phase 5 only supports direct conversations",
            ));
        }
        let local_identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .clone();
        let relationship_status = self
            .state
            .contacts
            .get(&peer_user_id)
            .map(|contact| contact.relationship_status.clone())
            .ok_or_else(|| CoreError::invalid_input("peer contact is missing"))?;
        if !Self::relationship_allows_session_setup(&relationship_status) {
            return Err(Self::relationship_closed_error(&peer_user_id));
        }
        let contact_bundle = self.direct_peer_contact_bundle(&peer_user_id)?.clone();
        if contact_bundle.publication_version < crate::model::IDENTITY_PUBLICATION_VERSION_V2 {
            return Err(CoreError::new(
                "protocol_upgrade_required",
                "the contact must publish IdentityBundle V2 before a Direct relationship can be created",
            ));
        }
        IdentityManager::verify_identity_bundle(&contact_bundle)?;
        let now_ms = current_unix_millis(self.state.message_nonce);
        let peer_device_ids: Vec<String> = contact_bundle
            .devices
            .iter()
            .filter(|device| {
                matches!(device.status, crate::model::DeviceStatusKind::Active)
                    && device
                        .key_package_claim_capability
                        .as_ref()
                        .is_some_and(|capability| capability.expires_at > now_ms)
                    && device.mls_device_key_binding.is_some()
            })
            .map(|d| d.device_id.clone())
            .collect();
        let active_device_count = contact_bundle
            .devices
            .iter()
            .filter(|device| device.status == crate::model::DeviceStatusKind::Active)
            .count();
        if peer_device_ids.is_empty() || peer_device_ids.len() != active_device_count {
            return Err(CoreError::new(
                "identity_refresh_required",
                "every active peer device must expose a valid MLS binding and KeyPackage claim capability",
            ));
        }
        if let Some((conversation_id, existing)) =
            self.active_direct_conversation_for_peer(&peer_user_id)
        {
            let existing_last_message_type = existing.last_message_type;
            let existing_state = existing.conversation.state;
            let missing_mls_state = !self.state.mls_summaries.contains_key(&conversation_id);
            if missing_mls_state {
                self.mark_recovery_needed(&conversation_id, RecoveryReason::MissingWelcome);
            }
            let recovery = self.recovery_snapshot_for_conversation(&conversation_id);
            let state = if missing_mls_state {
                "needs_recovery".into()
            } else {
                format!("{:?}", existing_state).to_lowercase()
            };
            let effects = if missing_mls_state {
                vec![persist_effect(
                    &self.state,
                    vec![
                        PersistOp::SaveConversation {
                            conversation_id: conversation_id.clone(),
                        },
                        PersistOp::SaveRecoveryContext {
                            conversation_id: conversation_id.clone(),
                        },
                    ],
                )]
            } else {
                Vec::new()
            };
            return Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    conversations_changed: missing_mls_state,
                    ..CoreStateUpdate::default()
                },
                effects,
                view_model: Some(CoreViewModel {
                    conversations: vec![ConversationSummary {
                        conversation_id: conversation_id.clone(),
                        peer_user_id: peer_user_id.clone(),
                        state,
                        kind: Some(ConversationKind::Direct),
                        title: None,
                        display_name: self.contact_archive_display_name(&peer_user_id),
                        group_id: None,
                        member_count: None,
                        group_role: None,
                        group_cursor: None,
                        last_message_preview: None,
                        last_message_type: existing_last_message_type,
                        message_count: None,
                        recovery,
                        relationship: self.relationship_view_state(&conversation_id),
                    }],
                    ..CoreViewModel::default()
                }),
            });
        }

        if let Some(pending) = self.state.relationships.values().find(|relationship| {
            relationship.peer_user_id == peer_user_id
                && relationship.account_state == RelationshipAccountState::Pending
                && relationship.setup_state != RelationshipSetupState::Superseded
        }) {
            let conversation_id = format!(
                "conv:direct:v2:{}:g{}",
                pending.relationship_id, pending.generation
            );
            return Ok(CoreOutput {
                state_update: CoreStateUpdate::default(),
                effects: Vec::new(),
                view_model: Some(CoreViewModel {
                    conversations: vec![ConversationSummary {
                        conversation_id: conversation_id.clone(),
                        peer_user_id: peer_user_id.clone(),
                        state: "claiming".into(),
                        kind: Some(ConversationKind::Direct),
                        title: None,
                        display_name: self.contact_archive_display_name(&peer_user_id),
                        group_id: None,
                        member_count: None,
                        group_role: None,
                        group_cursor: None,
                        last_message_preview: None,
                        last_message_type: None,
                        message_count: None,
                        recovery: None,
                        relationship: self.relationship_view_state(&conversation_id),
                    }],
                    ..CoreViewModel::default()
                }),
            });
        }

        let relationship_id = random_opaque_id("relationship");
        let proposal_id = random_opaque_id("proposal");
        let idempotency_key = random_opaque_id("claim");
        let sender_bundle = self
            .state
            .local_bundle
            .as_ref()
            .filter(|bundle| {
                bundle.publication_version >= crate::model::IDENTITY_PUBLICATION_VERSION_V2
            })
            .cloned()
            .ok_or_else(|| {
                CoreError::new(
                    "protocol_upgrade_required",
                    "local IdentityBundle V2 is required to create a Direct relationship",
                )
            })?;
        let sender_bundle_digest = crate::identity::identity_bundle_digest(&sender_bundle)?;
        let generation = self
            .state
            .relationships
            .values()
            .filter(|relationship| relationship.peer_user_id == peer_user_id)
            .map(|relationship| relationship.generation)
            .max()
            .map_or(1, |generation| generation.saturating_add(1));
        let mut proposal = RelationshipProposalV2 {
            proposal_id: proposal_id.clone(),
            initiator_user_id: local_identity.user_identity.user_id.clone(),
            initiator_device_id: local_identity.device_identity.device_id.clone(),
            relationship_id_candidate: relationship_id.clone(),
            generation,
            attempt: 1,
            peer_user_id: peer_user_id.clone(),
            sender_bundle_digest,
            created_at: now_ms,
            expires_at: now_ms.saturating_add(7 * 24 * 60 * 60 * 1000),
            signature: String::new(),
        };
        proposal.signature = local_identity.sign_device_payload(
            &crate::identity::relationship_proposal_signing_payload(&proposal),
        );
        crate::identity::verify_relationship_proposal(&proposal, &sender_bundle)?;
        let targets = contact_bundle
            .devices
            .iter()
            .filter(|device| device.status == crate::model::DeviceStatusKind::Active)
            .map(|device| {
                Ok(crate::transport_contract::KeyPackageClaimTarget {
                    device_id: device.device_id.clone(),
                    capability: device.key_package_claim_capability.clone().ok_or_else(|| {
                        CoreError::invalid_input("active peer device is missing a claim capability")
                    })?,
                })
            })
            .collect::<CoreResult<Vec<_>>>()?;
        let endpoint = targets
            .first()
            .map(|target| target.capability.endpoint.clone())
            .ok_or_else(|| CoreError::invalid_input("claim target set is empty"))?;
        if targets
            .iter()
            .any(|target| target.capability.endpoint != endpoint)
        {
            return Err(CoreError::invalid_input(
                "all devices in an account must use one authoritative claim endpoint",
            ));
        }
        let request_body = ClaimKeyPackagesRequest {
            version: crate::model::ENVELOPE_VERSION_V2.into(),
            purpose: crate::transport_contract::KeyPackageClaimPurpose::Direct,
            idempotency_key: idempotency_key.clone(),
            requester_bundle: sender_bundle.clone(),
            proposal: proposal.clone(),
            targets,
        };
        let self_targets = sender_bundle
            .devices
            .iter()
            .filter(|device| {
                device.status == DeviceStatusKind::Active
                    && device.device_id != local_identity.device_identity.device_id
            })
            .map(|device| {
                Ok(crate::transport_contract::KeyPackageClaimTarget {
                    device_id: device.device_id.clone(),
                    capability: device.key_package_claim_capability.clone().ok_or_else(|| {
                        CoreError::invalid_input(
                            "active sibling device is missing a claim capability",
                        )
                    })?,
                })
            })
            .collect::<CoreResult<Vec<_>>>()?;
        let self_claim = if self_targets.is_empty() {
            None
        } else {
            let self_endpoint = self_targets[0].capability.endpoint.clone();
            if self_targets
                .iter()
                .any(|target| target.capability.endpoint != self_endpoint)
            {
                return Err(CoreError::invalid_input(
                    "all sibling devices must use one authoritative claim endpoint",
                ));
            }
            let self_idempotency_key = random_opaque_id("self-claim");
            Some((
                self_endpoint,
                self_idempotency_key.clone(),
                ClaimKeyPackagesRequest {
                    version: crate::model::ENVELOPE_VERSION_V2.into(),
                    purpose: crate::transport_contract::KeyPackageClaimPurpose::SelfJoin,
                    idempotency_key: self_idempotency_key,
                    requester_bundle: sender_bundle.clone(),
                    proposal: proposal.clone(),
                    targets: self_targets,
                },
            ))
        };
        let local_join_states = sender_bundle
            .devices
            .iter()
            .filter(|device| device.status == DeviceStatusKind::Active)
            .map(|device| {
                (
                    device.device_id.clone(),
                    if device.device_id == local_identity.device_identity.device_id {
                        DeviceJoinState::Ready
                    } else {
                        DeviceJoinState::WaitingWelcome
                    },
                )
            })
            .collect();
        self.state.relationships.insert(
            relationship_id.clone(),
            PersistedRelationship {
                relationship_id: relationship_id.clone(),
                peer_user_id: peer_user_id.clone(),
                peer_root_public_key: contact_bundle.user_public_key.clone(),
                peer_bundle_digest: crate::identity::identity_bundle_digest(&contact_bundle)?,
                peer_bundle_revision: contact_bundle.publication_revision,
                generation,
                canonical_proposal: proposal.clone(),
                account_state: RelationshipAccountState::Pending,
                setup_state: RelationshipSetupState::Claiming,
                local_device_join_states: local_join_states,
                attempts: vec![RelationshipAttempt {
                    attempt: 1,
                    proposal_id: proposal_id.clone(),
                    ticket_id: String::new(),
                    ticket_secret: String::new(),
                    ticket_status_endpoint: None,
                    remote_claim_idempotency_key: idempotency_key.clone(),
                    self_claim_idempotency_key: self_claim
                        .as_ref()
                        .map(|(_, idempotency_key, _)| idempotency_key.clone()),
                    claim_retry_count: 0,
                    claim_ids: Vec::new(),
                    welcome_digests: Vec::new(),
                    claim_sets: Vec::new(),
                    created_at: now_ms,
                    expires_at: now_ms.saturating_add(7 * 24 * 60 * 60 * 1000),
                }],
                version: 1,
                updated_at: now_ms,
            },
        );
        let conversation_id = format!("conv:direct:v2:{relationship_id}:g{generation}");
        let request_id = self.next_request_id(&format!("claim:{proposal_id}"));
        self.state.pending_requests.insert(
            request_id.clone(),
            PendingRequest::ClaimKeyPackages {
                purpose: crate::transport_contract::KeyPackageClaimPurpose::Direct,
                peer_user_id: peer_user_id.clone(),
                relationship_id: relationship_id.clone(),
                proposal_id: proposal_id.clone(),
                idempotency_key,
                claim_endpoint: endpoint.clone(),
            },
        );
        let mut effects = vec![
            persist_effect(&self.state, vec![PersistOp::SaveDeployment]),
            CoreEffect::ExecuteHttpRequest {
                request: HttpRequestEffect {
                    request_id,
                    method: HttpMethod::Post,
                    url: endpoint,
                    headers: BTreeMap::from([("Content-Type".into(), "application/json".into())]),
                    auth: None,
                    body: Some(serde_json::to_string(&request_body).map_err(|error| {
                        CoreError::invalid_input(format!(
                            "failed to encode KeyPackage claim: {error}"
                        ))
                    })?),
                },
            },
        ];
        if let Some((self_endpoint, self_idempotency_key, self_request)) = self_claim {
            let self_request_id = self.next_request_id(&format!("self-claim:{proposal_id}"));
            self.state.pending_requests.insert(
                self_request_id.clone(),
                PendingRequest::ClaimKeyPackages {
                    purpose: crate::transport_contract::KeyPackageClaimPurpose::SelfJoin,
                    peer_user_id: peer_user_id.clone(),
                    relationship_id: relationship_id.clone(),
                    proposal_id: proposal_id.clone(),
                    idempotency_key: self_idempotency_key,
                    claim_endpoint: self_endpoint.clone(),
                },
            );
            effects.push(CoreEffect::ExecuteHttpRequest {
                request: HttpRequestEffect {
                    request_id: self_request_id,
                    method: HttpMethod::Post,
                    url: self_endpoint,
                    headers: BTreeMap::from([("Content-Type".into(), "application/json".into())]),
                    auth: None,
                    body: Some(serde_json::to_string(&self_request).map_err(|error| {
                        CoreError::invalid_input(format!(
                            "failed to encode authenticated self claim: {error}"
                        ))
                    })?),
                },
            });
        }
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                ..CoreStateUpdate::default()
            },
            effects,
            view_model: Some(CoreViewModel {
                conversations: vec![ConversationSummary {
                    conversation_id: conversation_id.clone(),
                    peer_user_id: peer_user_id.clone(),
                    state: "claiming".into(),
                    kind: Some(ConversationKind::Direct),
                    title: None,
                    display_name: self.contact_archive_display_name(&peer_user_id),
                    group_id: None,
                    member_count: None,
                    group_role: None,
                    group_cursor: None,
                    last_message_preview: None,
                    last_message_type: None,
                    message_count: None,
                    recovery: None,
                    relationship: self.relationship_view_state(&conversation_id),
                }],
                ..CoreViewModel::default()
            }),
        })
    }

    pub(super) fn send_text_message(
        &mut self,
        conversation_id: String,
        plaintext: String,
    ) -> CoreResult<CoreOutput> {
        self.ensure_conversation_ready_for_send(&conversation_id)?;
        if plaintext.trim().is_empty() {
            return Err(CoreError::invalid_input("plaintext must not be empty"));
        }
        let local_identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?;
        let sender_user_id = local_identity.user_identity.user_id.clone();
        let sender_device_id = local_identity.device_identity.device_id.clone();
        let peer_user_id = self.peer_user_for_conversation(&conversation_id)?;
        let recipient_device_ids = self.recipient_device_ids(&conversation_id)?;
        // Authorization must be checked before encrypting. OpenMLS advances the
        // sender ratchet when `encrypt_application` succeeds, so discovering a
        // pending/rejected relationship afterwards would corrupt the local MLS
        // state even though the command is returned as an error.
        let relationship_id = self
            .state
            .relationships
            .values()
            .find(|relationship| {
                format!(
                    "conv:direct:v2:{}:g{}",
                    relationship.relationship_id, relationship.generation
                ) == conversation_id
                    && relationship.account_state == RelationshipAccountState::Accepted
            })
            .map(|relationship| relationship.relationship_id.clone())
            .ok_or_else(|| {
                CoreError::new(
                    "relationship_not_ready",
                    "Direct V2 relationship is not accepted",
                )
            })?;
        let app_message_nonce = self.next_message_nonce();
        let app_message_id =
            self.next_app_message_id(&conversation_id, &sender_device_id, app_message_nonce);
        let protected_message = ProtectedAppMessage::new_text(
            app_message_id.clone(),
            conversation_id.clone(),
            sender_user_id,
            sender_device_id,
            peer_user_id.clone(),
            recipient_device_ids.clone(),
            plaintext.clone(),
        )?;
        let protected_bytes = protected_message.to_json_bytes()?;
        let payload = self
            .state
            .mls_adapter
            .as_mut()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .encrypt_application(&conversation_id, &protected_bytes)?;
        let envelopes = recipient_device_ids
            .iter()
            .map(|device_id| {
                self.build_envelope_v2(
                    &relationship_id,
                    &peer_user_id,
                    device_id,
                    MessageType::MlsApplication,
                    payload.payload_b64.clone(),
                    None,
                )
            })
            .collect::<CoreResult<Vec<_>>>()?;
        // Cache plaintext for display until message is synced
        self.enqueue_envelopes_v2_with_plaintext(
            peer_user_id,
            envelopes.clone(),
            plaintext.clone(),
            Some(app_message_id.clone()),
        );
        self.merge_with_transport_flush(CoreOutput {
            state_update: CoreStateUpdate {
                messages_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(
                &self.state,
                vec![
                    PersistOp::SaveMlsState {
                        conversation_id: conversation_id.clone(),
                    },
                    PersistOp::SaveOutgoingEnvelope {
                        message_id: envelopes
                            .first()
                            .map(|envelope| envelope.message_id.clone())
                            .unwrap_or_default(),
                    },
                ],
            )],
            view_model: Some(CoreViewModel {
                // The protected application id is the only user-visible
                // identity. Envelope ids are per-recipient transport details.
                messages: vec![MessageSummary {
                    conversation_id: conversation_id.clone(),
                    message_id: app_message_id,
                    message_type: MessageType::MlsApplication,
                }],
                ..CoreViewModel::default()
            }),
        })
    }

    pub(super) fn refresh_local_bundle(&mut self) -> CoreResult<()> {
        let updated_at = self
            .state
            .local_bundle
            .as_ref()
            .map(|bundle| bundle.updated_at)
            .unwrap_or_else(|| {
                self.state
                    .local_identity
                    .as_ref()
                    .map(|identity| identity.device_status.updated_at)
                    .unwrap_or_default()
            });
        self.refresh_local_bundle_with_updated_at(updated_at)
    }

    pub(super) fn refresh_local_bundle_with_updated_at(
        &mut self,
        updated_at: u64,
    ) -> CoreResult<()> {
        self.refresh_local_bundle_with_updated_at_at(
            updated_at,
            current_unix_millis(self.state.message_nonce),
        )
    }

    fn refresh_local_bundle_with_updated_at_at(
        &mut self,
        updated_at: u64,
        now_ms: u64,
    ) -> CoreResult<()> {
        let Some(local_identity) = self.state.local_identity.as_ref() else {
            return Ok(());
        };
        let Some(deployment) = self.state.deployment_bundle.as_ref() else {
            self.state.local_bundle = None;
            return Ok(());
        };
        let mls_signature_public_key = self
            .state
            .mls_adapter
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("MLS adapter missing"))?
            .signature_public_key();
        let mut signing_identity = local_identity.clone();
        signing_identity.device_status.updated_at = updated_at;
        let mut devices = self
            .state
            .local_bundle
            .as_ref()
            .map(|bundle| {
                bundle
                    .devices
                    .iter()
                    .filter(|device| device.device_id != local_identity.device_identity.device_id)
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for device in &mut devices {
            if device
                .keypackage_ref
                .as_ref()
                .is_some_and(|keypackage| !keypackage.is_usable_at(now_ms))
            {
                device.keypackage_ref = None;
            }
            if device
                .inbox_append_capability
                .as_ref()
                .is_some_and(|capability| capability.expires_at <= now_ms)
            {
                device.inbox_append_capability = None;
            }
        }
        let bundle_share_id = self
            .state
            .local_bundle
            .as_ref()
            .and_then(|bundle| bundle.bundle_share_id.clone());
        devices.push(
            crate::capability::CapabilityManager::build_device_contact_profile_v2(
                &signing_identity,
                deployment,
                mls_signature_public_key,
                now_ms,
            )?,
        );
        devices.sort_by(|left, right| left.device_id.cmp(&right.device_id));
        let bundle = IdentityManager::export_identity_bundle_with_devices(
            &signing_identity,
            deployment,
            devices,
            bundle_share_id,
            self.state.local_display_name.clone(),
        )?;
        self.state.local_bundle = Some(bundle);
        Ok(())
    }

    pub(super) fn rotate_contact_share_link(&mut self) -> CoreResult<CoreOutput> {
        if self.state.pending_identity_publication.is_some() {
            return Err(CoreError::new(
                "contact_share_rotation_unverified",
                "another identity publication is awaiting verification",
            ));
        }
        let previous_bundle = self
            .state
            .local_bundle
            .clone()
            .ok_or_else(|| CoreError::invalid_state("local identity bundle is unavailable"))?;
        let updated_at = self
            .state
            .local_bundle
            .as_ref()
            .map(|bundle| bundle.updated_at.saturating_add(1))
            .unwrap_or_else(|| {
                self.state
                    .local_identity
                    .as_ref()
                    .map(|identity| identity.device_status.updated_at.saturating_add(1))
                    .unwrap_or(1)
            });
        self.refresh_local_bundle_with_share_id(updated_at, None)?;
        let operation_id = format!("contact_share_rotation:{updated_at}");
        let candidate_bundle =
            self.state.local_bundle.clone().ok_or_else(|| {
                CoreError::invalid_state("candidate identity bundle is unavailable")
            })?;
        self.state.local_bundle = Some(previous_bundle.clone());
        self.state.pending_identity_publication =
            Some(crate::persistence::PendingIdentityPublication {
                operation_id: operation_id.clone(),
                reason: "share_link_rotation".into(),
                previous_bundle,
                candidate_bundle: candidate_bundle.clone(),
                expected_etag: None,
                stage: crate::persistence::PendingIdentityPublicationStage::AwaitingPublish,
                attempt_count: 0,
                next_retry_at: current_unix_millis(self.state.message_nonce),
            });
        let mut effects = vec![persist_effect(&self.state, vec![PersistOp::SaveDeployment])];
        effects.push(self.identity_bundle_publish_effect(&candidate_bundle, operation_id, None)?);
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                ..CoreStateUpdate::default()
            },
            effects,
            view_model: None,
        })
    }

    pub(super) fn refresh_local_bundle_with_share_id(
        &mut self,
        updated_at: u64,
        bundle_share_id: Option<String>,
    ) -> CoreResult<()> {
        let Some(local_identity) = self.state.local_identity.as_ref() else {
            return Ok(());
        };
        let Some(deployment) = self.state.deployment_bundle.as_ref() else {
            self.state.local_bundle = None;
            return Ok(());
        };
        let mls_signature_public_key = self
            .state
            .mls_adapter
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("MLS adapter missing"))?
            .signature_public_key();
        let mut signing_identity = local_identity.clone();
        signing_identity.device_status.updated_at = updated_at;
        let mut devices = self
            .state
            .local_bundle
            .as_ref()
            .map(|bundle| {
                bundle
                    .devices
                    .iter()
                    .filter(|device| device.device_id != local_identity.device_identity.device_id)
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let now_ms = current_unix_millis(self.state.message_nonce);
        for device in &mut devices {
            device.keypackage_ref = None;
            if device
                .inbox_append_capability
                .as_ref()
                .is_some_and(|capability| capability.expires_at <= now_ms)
            {
                device.inbox_append_capability = None;
            }
            if device
                .key_package_claim_capability
                .as_ref()
                .is_some_and(|capability| capability.expires_at <= now_ms)
            {
                device.key_package_claim_capability = None;
            }
        }
        devices.push(
            crate::capability::CapabilityManager::build_device_contact_profile_v2(
                &signing_identity,
                deployment,
                mls_signature_public_key,
                now_ms,
            )?,
        );
        devices.sort_by(|left, right| left.device_id.cmp(&right.device_id));
        let bundle = IdentityManager::export_identity_bundle_with_devices(
            &signing_identity,
            deployment,
            devices,
            bundle_share_id,
            self.state.local_display_name.clone(),
        )?;
        self.state.local_bundle = Some(bundle);
        Ok(())
    }

    pub(super) fn affected_conversations_for_peer(&self, peer_user_id: &str) -> Vec<String> {
        self.state
            .conversations
            .iter()
            .filter_map(|(conversation_id, state)| {
                if state.peer_user_id == peer_user_id
                    && matches!(
                        state.conversation.state,
                        ConversationState::Active | ConversationState::NeedsRebuild
                    )
                {
                    Some(conversation_id.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    pub(super) fn active_direct_conversation_for_peer(
        &self,
        peer_user_id: &str,
    ) -> Option<(String, &LocalConversationState)> {
        self.state
            .conversations
            .iter()
            .filter(|(_, state)| {
                if state
                    .conversation
                    .conversation_id
                    .starts_with("conv:direct:v2:")
                    && state.peer_user_id == peer_user_id
                    && state.conversation.kind == ConversationKind::Direct
                    && matches!(
                        state.conversation.state,
                        ConversationState::Active | ConversationState::NeedsRebuild
                    )
                {
                    true
                } else {
                    false
                }
            })
            .max_by_key(|(conversation_id, state)| {
                self.direct_conversation_selection_rank(conversation_id, state)
            })
            .map(|(conversation_id, state)| (conversation_id.clone(), state))
    }

    pub(super) fn direct_conversation_selection_rank(
        &self,
        conversation_id: &str,
        state: &LocalConversationState,
    ) -> (bool, bool, bool, u64, u64) {
        (
            state.conversation.state == ConversationState::Active,
            state.recovery_status == RecoveryStatus::Healthy,
            self.state.mls_summaries.contains_key(conversation_id),
            state.conversation.updated_at,
            Self::direct_relationship_nonce(conversation_id),
        )
    }

    pub(super) fn direct_relationship_nonce(conversation_id: &str) -> u64 {
        conversation_id
            .split_once(":rel:")
            .and_then(|(_, suffix)| suffix.split(':').next())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0)
    }

    pub(super) fn direct_conversations_for_peer(&self, peer_user_id: &str) -> Vec<String> {
        self.state
            .conversations
            .iter()
            .filter_map(|(conversation_id, state)| {
                if state.peer_user_id == peer_user_id
                    && state.conversation.kind == ConversationKind::Direct
                    && state.conversation.state != ConversationState::Archived
                {
                    Some(conversation_id.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    pub(super) fn new_direct_relationship_conversation_id(
        &mut self,
        local_user_id: &str,
        peer_user_id: &str,
    ) -> String {
        let mut parts = [local_user_id.to_string(), peer_user_id.to_string()];
        parts.sort();
        let nonce = self.next_message_nonce();
        format!("conv:{}:{}:rel:{}", parts[0], parts[1], nonce)
    }

    pub(super) fn migrate_legacy_removed_relationships(&mut self) -> CoreResult<CoreOutput> {
        let mut legacy_peer_user_ids = self
            .state
            .contacts
            .iter()
            .filter_map(|(user_id, contact)| {
                Self::relationship_is_removed(&contact.relationship_status)
                    .then_some(user_id.clone())
            })
            .collect::<BTreeSet<_>>();
        for conversation in self.state.conversations.values() {
            if conversation.conversation.kind == ConversationKind::Direct
                && conversation.conversation.state == ConversationState::Closed
            {
                legacy_peer_user_ids.insert(conversation.peer_user_id.clone());
            }
        }

        let conversation_ids = self
            .state
            .conversations
            .iter()
            .filter_map(|(conversation_id, state)| {
                let legacy_peer = legacy_peer_user_ids.contains(&state.peer_user_id);
                let legacy_closed = state.conversation.state == ConversationState::Closed;
                if state.conversation.kind == ConversationKind::Direct
                    && state.conversation.state != ConversationState::Archived
                    && (legacy_peer || legacy_closed)
                {
                    Some(conversation_id.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        if legacy_peer_user_ids.is_empty() && conversation_ids.is_empty() {
            return Ok(CoreOutput::default());
        }

        let local_device_id = self.local_identity_device_id()?;
        let mut persist_ops = Vec::new();
        let mut message_summaries = Vec::new();

        for conversation_id in &conversation_ids {
            let peer_user_id = self
                .state
                .conversations
                .get(conversation_id)
                .map(|conversation| conversation.peer_user_id.clone())
                .unwrap_or_default();
            let nonce = self.next_message_nonce();
            let system_message = StoredMessage {
                message_id: format!("{conversation_id}:system:legacy_archive"),
                app_message_id: None,
                mls_ciphertext_sha256: None,
                sender_user_id: None,
                sender_device_id: local_device_id.clone(),
                recipient_device_id: peer_user_id,
                message_type: MessageType::ControlContactRemoved,
                created_at: current_unix_millis(nonce),
                plaintext: Some("This legacy chat was archived.".into()),
                storage_refs: Vec::new(),
                delivery_state: None,
                message_request_id: None,
            };
            if let Some(summary) = self.archive_conversation_with_message(
                conversation_id,
                system_message,
                "legacy_migration",
            ) {
                message_summaries.push(summary);
            }
            persist_ops.extend(self.clear_direct_runtime_state(conversation_id)?);
            persist_ops.push(PersistOp::SaveConversation {
                conversation_id: conversation_id.clone(),
            });
        }

        for user_id in &legacy_peer_user_ids {
            if self.state.contacts.remove(user_id).is_some() {
                persist_ops.push(PersistOp::DeleteContact {
                    user_id: user_id.clone(),
                });
            }
        }

        let mut output = CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: !legacy_peer_user_ids.is_empty(),
                conversations_changed: !conversation_ids.is_empty(),
                messages_changed: !message_summaries.is_empty(),
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(&self.state, persist_ops)],
            view_model: Some(CoreViewModel {
                contacts: self.contact_summaries(),
                messages: message_summaries,
                ..CoreViewModel::default()
            }),
        };
        if self.state.deployment_bundle.is_some() && !legacy_peer_user_ids.is_empty() {
            output = merge_outputs(
                output,
                self.remove_allowlist_users(legacy_peer_user_ids.into_iter().collect())?,
            );
        }
        Ok(output)
    }

    /// Converts a locally trusted V1 Direct relationship into a V2 setup attempt.
    ///
    /// Local history is sufficient to auto-accept an incoming proposal from the
    /// same root identity, but it is deliberately not sufficient to set the
    /// outbound DeviceRegistry row to Accepted.  The outbound side still waits
    /// for the peer device's signed RelationshipDecisionProofV2.
    pub(super) fn migrate_legacy_accepted_relationships(&mut self) -> CoreResult<CoreOutput> {
        let peer_user_ids = self
            .state
            .contacts
            .iter()
            .filter_map(|(peer_user_id, contact)| {
                let has_v2_relationship = self
                    .state
                    .relationships
                    .values()
                    .any(|relationship| relationship.peer_user_id == *peer_user_id);
                let has_legacy_direct =
                    self.state
                        .conversations
                        .iter()
                        .any(|(conversation_id, conversation)| {
                            !conversation_id.starts_with("conv:direct:v2:")
                                && conversation.peer_user_id == *peer_user_id
                                && conversation.conversation.kind == ConversationKind::Direct
                                && conversation.conversation.state != ConversationState::Archived
                        });
                (contact.relationship_status == ContactRelationshipStatus::Available
                    && !has_v2_relationship
                    && has_legacy_direct)
                    .then_some(peer_user_id.clone())
            })
            .collect::<Vec<_>>();
        if peer_user_ids.is_empty() {
            return Ok(CoreOutput::default());
        }

        let mut output = CoreOutput::default();
        for peer_user_id in peer_user_ids {
            let legacy_conversation_ids = self
                .state
                .conversations
                .iter()
                .filter_map(|(conversation_id, conversation)| {
                    (!conversation_id.starts_with("conv:direct:v2:")
                        && conversation.peer_user_id == peer_user_id
                        && conversation.conversation.kind == ConversationKind::Direct
                        && conversation.conversation.state != ConversationState::Archived)
                        .then_some(conversation_id.clone())
                })
                .collect::<Vec<_>>();
            for conversation_id in legacy_conversation_ids {
                output = merge_outputs(output, self.rebuild_conversation(conversation_id)?);
            }

            let supports_v2 = self
                .state
                .contacts
                .get(&peer_user_id)
                .is_some_and(|contact| {
                    contact.bundle.publication_version
                        >= crate::model::IDENTITY_PUBLICATION_VERSION_V2
                });
            output = if supports_v2 {
                merge_outputs(
                    output,
                    self.create_conversation(peer_user_id, ConversationKind::Direct)?,
                )
            } else {
                merge_outputs(output, self.refresh_identity_state(peer_user_id)?)
            };
        }
        Ok(output)
    }

    pub(super) fn peer_active_device_ids(&self, peer_user_id: &str) -> CoreResult<Vec<String>> {
        let bundle = self.direct_peer_contact_bundle(peer_user_id)?;
        let devices: Vec<String> = bundle
            .devices
            .iter()
            .filter(|device| matches!(device.status, crate::model::DeviceStatusKind::Active))
            .map(|device| device.device_id.clone())
            .collect();
        if devices.is_empty() {
            return Err(CoreError::new(
                "identity_refresh_required",
                "peer IdentityBundle does not contain an active device",
            ));
        }
        Ok(devices)
    }

    pub(super) fn peer_user_for_conversation(&self, conversation_id: &str) -> CoreResult<String> {
        self.state
            .conversations
            .get(conversation_id)
            .map(|state| state.peer_user_id.clone())
            .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))
    }

    pub(super) fn recipient_device_ids(&self, conversation_id: &str) -> CoreResult<Vec<String>> {
        let local_user_id = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .user_identity
            .user_id
            .clone();
        let mut device_ids = self
            .state
            .conversations
            .get(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?
            .conversation
            .member_devices
            .iter()
            .filter(|member| member.user_id != local_user_id)
            .map(|member| member.device_id.clone())
            .collect::<Vec<_>>();
        device_ids.sort();
        device_ids.dedup();
        Ok(device_ids)
    }

    pub(super) fn direct_peer_contact_bundle(
        &self,
        peer_user_id: &str,
    ) -> CoreResult<&IdentityBundle> {
        let bundle = self
            .state
            .contacts
            .get(peer_user_id)
            .ok_or_else(|| CoreError::invalid_input("peer contact is missing"))?;
        if bundle.bundle.identity_bundle_ref.is_none() {
            return Err(CoreError::invalid_input(
                "peer identity bundle reference is missing",
            ));
        }
        if !bundle
            .bundle
            .devices
            .iter()
            .any(|device| matches!(device.status, crate::model::DeviceStatusKind::Active))
        {
            return Err(CoreError::invalid_input(
                "peer identity bundle does not contain any active devices",
            ));
        }
        Ok(&bundle.bundle)
    }

    pub(super) fn enqueue_envelopes(&mut self, peer_user_id: String, envelopes: Vec<Envelope>) {
        for envelope in envelopes {
            self.state.outbox.push(envelope.clone());
            self.state.pending_outbox.push(PendingOutboxItem {
                envelope,
                envelope_v2: None,
                peer_user_id: peer_user_id.clone(),
                retries: 0,
                in_flight: false,
                app_message_id: None,
                plaintext_cache: None,
                identity_refresh_attempted: false,
            });
        }
    }

    pub(super) fn build_envelope_v2(
        &mut self,
        relationship_id: &str,
        recipient_user_id: &str,
        recipient_device_id: &str,
        message_type: MessageType,
        payload_b64: String,
        claim_id: Option<String>,
    ) -> CoreResult<crate::model::EnvelopeV2> {
        let relationship = self
            .state
            .relationships
            .get(relationship_id)
            .ok_or_else(|| CoreError::invalid_state("relationship state is missing"))?
            .clone();
        let identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .clone();
        let sender_bundle = self
            .state
            .local_bundle
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local IdentityBundle is unavailable"))?;
        let sender_bundle_digest = crate::identity::identity_bundle_digest(sender_bundle)?;
        let conversation_id = format!(
            "conv:direct:v2:{}:g{}",
            relationship.relationship_id, relationship.generation
        );
        let nonce = self.next_message_nonce();
        let mut envelope = crate::model::EnvelopeV2 {
            version: crate::model::ENVELOPE_VERSION_V2.into(),
            message_id: self.next_message_id(&conversation_id, recipient_device_id, nonce),
            conversation_id,
            relationship_id: relationship.relationship_id,
            generation: relationship.generation,
            attempt: relationship.canonical_proposal.attempt,
            proposal_id: relationship.canonical_proposal.proposal_id,
            claim_id,
            sender_user_id: identity.user_identity.user_id.clone(),
            sender_device_id: identity.device_identity.device_id.clone(),
            recipient_user_id: recipient_user_id.to_string(),
            recipient_device_id: recipient_device_id.to_string(),
            created_at: current_unix_millis(nonce),
            message_type,
            inline_ciphertext: Some(payload_b64),
            storage_refs: Vec::new(),
            delivery_class: DeliveryClass::Normal,
            wake_hint: None,
            sender_bundle_digest,
            sender_proof: SenderProof {
                proof_type: crate::model::ENVELOPE_SENDER_PROOF_V2.into(),
                value: String::new(),
            },
        };
        identity.sign_envelope_v2(&mut envelope)?;
        envelope.validate()?;
        Ok(envelope)
    }

    pub(super) fn handle_key_package_claimed(
        &mut self,
        purpose: crate::transport_contract::KeyPackageClaimPurpose,
        peer_user_id: String,
        relationship_id: String,
        proposal_id: String,
        idempotency_key: String,
        claim_endpoint: String,
        result: ClaimKeyPackagesResult,
    ) -> CoreResult<CoreOutput> {
        if result.idempotency_key != idempotency_key {
            return Err(CoreError::invalid_input(
                "KeyPackage claim response idempotency key mismatch",
            ));
        }
        let contact_bundle = self.direct_peer_contact_bundle(&peer_user_id)?.clone();
        let local_bundle = self
            .state
            .local_bundle
            .as_ref()
            .cloned()
            .ok_or_else(|| CoreError::invalid_state("local IdentityBundle is unavailable"))?;
        let relationship = self
            .state
            .relationships
            .get(&relationship_id)
            .filter(|relationship| relationship.canonical_proposal.proposal_id == proposal_id)
            .cloned()
            .ok_or_else(|| CoreError::invalid_state("pending relationship claim is unavailable"))?;
        let local_device_id = self.local_device_id_required()?;
        let (claim_user_id, active_devices) = match purpose {
            crate::transport_contract::KeyPackageClaimPurpose::Direct => (
                peer_user_id.as_str(),
                contact_bundle
                    .devices
                    .iter()
                    .filter(|device| device.status == DeviceStatusKind::Active)
                    .collect::<Vec<_>>(),
            ),
            crate::transport_contract::KeyPackageClaimPurpose::SelfJoin => (
                local_bundle.user_id.as_str(),
                local_bundle
                    .devices
                    .iter()
                    .filter(|device| {
                        device.status == DeviceStatusKind::Active
                            && device.device_id != local_device_id
                    })
                    .collect::<Vec<_>>(),
            ),
            _ => {
                return Err(CoreError::invalid_input(
                    "Direct relationship received an unrelated KeyPackage claim purpose",
                ));
            }
        };
        if result.claims.len() != active_devices.len() {
            return Err(CoreError::invalid_input(
                "KeyPackage claim response did not cover every required device",
            ));
        }
        for device in active_devices {
            let claim = result
                .claims
                .iter()
                .find(|claim| claim.user_id == claim_user_id && claim.device_id == device.device_id)
                .ok_or_else(|| CoreError::invalid_input("KeyPackage claim target mismatch"))?;
            let binding = device.mls_device_key_binding.as_ref().ok_or_else(|| {
                CoreError::invalid_input("claimed device is missing an MLS key binding")
            })?;
            crate::mls_adapter::validate_key_package_device_binding(
                &claim.key_package_b64,
                binding,
            )?;
        }
        let ticket = match purpose {
            crate::transport_contract::KeyPackageClaimPurpose::Direct => {
                let ticket = result.ticket.clone().ok_or_else(|| {
                    CoreError::invalid_input(
                        "Direct KeyPackage claim did not return a relationship ticket",
                    )
                })?;
                if ticket.relationship_id != relationship_id
                    || ticket.generation != relationship.generation
                    || ticket.attempt != relationship.canonical_proposal.attempt
                {
                    return Err(CoreError::invalid_input(
                        "relationship ticket does not match the pending proposal",
                    ));
                }
                Some(ticket)
            }
            crate::transport_contract::KeyPackageClaimPurpose::SelfJoin => {
                if result.ticket.is_some() {
                    return Err(CoreError::invalid_input(
                        "authenticated self claim unexpectedly returned a relationship ticket",
                    ));
                }
                None
            }
            _ => unreachable!(),
        };
        let claim_ids = result
            .claims
            .iter()
            .map(|claim| claim.claim_id.clone())
            .collect::<Vec<_>>();
        if let Some(stored) = self.state.relationships.get_mut(&relationship_id) {
            stored.setup_state = RelationshipSetupState::Delivering;
            stored.updated_at = current_unix_millis(self.state.message_nonce);
            stored.version = stored.version.saturating_add(1);
            if let Some(attempt) = stored.attempts.last_mut() {
                if let Some(ticket) = ticket.as_ref() {
                    let ticket_secret = ticket
                        .ticket_secret
                        .as_deref()
                        .filter(|secret| {
                            secret.len() == 64
                                && secret.bytes().all(|byte| byte.is_ascii_hexdigit())
                        })
                        .ok_or_else(|| {
                            CoreError::invalid_input(
                                "relationship claim response is missing its opaque ticket secret",
                            )
                        })?;
                    attempt.ticket_id = ticket.ticket_id.clone();
                    // The secret is retained only in the local encrypted
                    // relationship state. Registry/upsert wire copies below
                    // are explicitly sanitized before serialization.
                    attempt.ticket_secret = ticket_secret.to_string();
                    attempt.ticket_status_endpoint = Some(format!(
                        "{}/v2/relationships/{}/status",
                        claim_endpoint
                            .strip_suffix("/v2/key-packages/claims")
                            .unwrap_or(claim_endpoint.trim_end_matches('/')),
                        ticket.ticket_id
                    ));
                }
                for claim_id in &claim_ids {
                    if !attempt.claim_ids.contains(claim_id) {
                        attempt.claim_ids.push(claim_id.clone());
                    }
                }
                let purpose_name = match purpose {
                    crate::transport_contract::KeyPackageClaimPurpose::Direct => "direct",
                    crate::transport_contract::KeyPackageClaimPurpose::SelfJoin => "self_join",
                    _ => unreachable!(),
                };
                attempt.claim_sets.retain(|set| set.purpose != purpose_name);
                attempt.claim_sets.push(KeyPackageClaimSet {
                    purpose: purpose_name.into(),
                    idempotency_key: result.idempotency_key.clone(),
                    claims: result
                        .claims
                        .iter()
                        .map(|claim| KeyPackageClaim {
                            claim_id: claim.claim_id.clone(),
                            user_id: claim.user_id.clone(),
                            device_id: claim.device_id.clone(),
                            key_package_id: claim.key_package_id.clone(),
                            key_package_b64: claim.key_package_b64.clone(),
                            created_at: claim.created_at,
                            expires_at: claim.expires_at,
                        })
                        .collect(),
                    ticket: ticket.clone().map(|mut ticket| {
                        ticket.ticket_secret = None;
                        ticket
                    }),
                });
            }
        }
        let stored_relationship = self
            .state
            .relationships
            .get(&relationship_id)
            .cloned()
            .ok_or_else(|| CoreError::invalid_state("relationship disappeared after claim"))?;
        let attempt = stored_relationship
            .attempts
            .last()
            .ok_or_else(|| CoreError::invalid_state("relationship attempt is unavailable"))?;
        let needs_self_claim = local_bundle.devices.iter().any(|device| {
            device.status == DeviceStatusKind::Active && device.device_id != local_device_id
        });
        let has_remote_claim = attempt.claim_sets.iter().any(|set| set.purpose == "direct");
        let has_self_claim = attempt
            .claim_sets
            .iter()
            .any(|set| set.purpose == "self_join");
        if !has_remote_claim || (needs_self_claim && !has_self_claim) {
            return Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    contacts_changed: true,
                    ..CoreStateUpdate::default()
                },
                effects: vec![persist_effect(&self.state, vec![PersistOp::SaveDeployment])],
                view_model: None,
            });
        }
        let mut registry_relationship = self
            .state
            .relationships
            .get(&relationship_id)
            .cloned()
            .ok_or_else(|| CoreError::invalid_state("relationship disappeared after claim"))?;
        for attempt in &mut registry_relationship.attempts {
            attempt.ticket_secret.clear();
            for claim_set in &mut attempt.claim_sets {
                if let Some(ticket) = claim_set.ticket.as_mut() {
                    ticket.ticket_secret = None;
                }
            }
        }
        let ticket_status_endpoint = attempt.ticket_status_endpoint.clone().ok_or_else(|| {
            CoreError::invalid_state("relationship ticket status endpoint is missing")
        })?;
        let mut public_ticket = attempt
            .claim_sets
            .iter()
            .find(|set| set.purpose == "direct")
            .and_then(|set| set.ticket.clone())
            .ok_or_else(|| CoreError::invalid_state("relationship ticket is missing"))?;
        public_ticket.ticket_secret = None;
        let upsert = UpsertOutboundRelationshipRequest {
            version: crate::model::ENVELOPE_VERSION_V2.into(),
            relationship: registry_relationship,
            peer_bundle: contact_bundle,
            ticket: public_ticket,
            ticket_status_endpoint,
        };
        let endpoint = self
            .state
            .deployment_bundle
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("deployment bundle is not initialized"))?
            .inbox_http_endpoint
            .trim_end_matches('/')
            .to_string();
        let request_id = self.next_request_id("relationship-upsert");
        self.state.pending_requests.insert(
            request_id.clone(),
            PendingRequest::UpsertOutboundRelationship {
                relationship_id: relationship_id.clone(),
            },
        );
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![
                persist_effect(&self.state, vec![PersistOp::SaveDeployment]),
                CoreEffect::ExecuteHttpRequest {
                    request: HttpRequestEffect {
                        request_id,
                        method: HttpMethod::Post,
                        url: format!("{endpoint}/v2/device-registry/relationships/outbound"),
                        headers: BTreeMap::from([(
                            "Content-Type".into(),
                            "application/json".into(),
                        )]),
                        auth: Some(self.device_runtime_auth_requirement()?),
                        body: Some(serde_json::to_string(&upsert).map_err(|error| {
                            CoreError::invalid_input(format!(
                                "failed to encode outbound relationship: {error}"
                            ))
                        })?),
                    },
                },
            ],
            view_model: None,
        })
    }

    pub(super) fn handle_relationship_claim_failure(
        &mut self,
        relationship_id: String,
        response_body: Option<&str>,
    ) -> CoreResult<CoreOutput> {
        let error_code = response_body
            .and_then(|body| serde_json::from_str::<serde_json::Value>(body).ok())
            .and_then(|value| value.get("code")?.as_str().map(str::to_owned));
        let retry_count = {
            let relationship = self
                .state
                .relationships
                .get_mut(&relationship_id)
                .ok_or_else(|| {
                    CoreError::invalid_state("relationship claim state is unavailable")
                })?;
            relationship.setup_state = if error_code.as_deref() == Some("keypackage_pool_exhausted")
            {
                RelationshipSetupState::PoolExhausted
            } else {
                RelationshipSetupState::Claiming
            };
            relationship.version = relationship.version.saturating_add(1);
            relationship.updated_at = current_unix_millis(self.state.message_nonce);
            let attempt = relationship
                .attempts
                .last_mut()
                .ok_or_else(|| CoreError::invalid_state("relationship attempt is unavailable"))?;
            attempt.claim_retry_count = attempt.claim_retry_count.saturating_add(1);
            attempt.claim_retry_count
        };
        let exponent = retry_count.saturating_sub(1).min(8);
        let base_delay = (5 * 60 * 1000_u64)
            .saturating_mul(1_u64 << exponent)
            .min(24 * 60 * 60 * 1000);
        let jitter_window = (base_delay / 5).max(1);
        let delay_ms = base_delay.saturating_add(self.state.message_nonce % jitter_window);
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                conversations_changed: true,
                system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                ..CoreStateUpdate::default()
            },
            effects: vec![
                persist_effect(&self.state, vec![PersistOp::SaveDeployment]),
                CoreEffect::ScheduleTimer {
                    timer: TimerEffect {
                        timer_id: format!("relationship_claim:{relationship_id}"),
                        delay_ms,
                    },
                },
            ],
            view_model: None,
        })
    }

    pub(super) fn retry_relationship_claim_requests(
        &mut self,
        relationship_id: &str,
    ) -> CoreResult<CoreOutput> {
        let relationship = self
            .state
            .relationships
            .get(relationship_id)
            .filter(|relationship| relationship.account_state == RelationshipAccountState::Pending)
            .cloned()
            .ok_or_else(|| CoreError::invalid_state("pending relationship is unavailable"))?;
        let attempt = relationship
            .attempts
            .last()
            .cloned()
            .ok_or_else(|| CoreError::invalid_state("relationship attempt is unavailable"))?;
        if attempt.expires_at <= current_unix_millis(self.state.message_nonce) {
            return self.restart_expired_relationship(relationship_id);
        }
        let local_bundle = self
            .state
            .local_bundle
            .as_ref()
            .cloned()
            .ok_or_else(|| CoreError::invalid_state("local IdentityBundle is unavailable"))?;
        let peer_bundle = self
            .direct_peer_contact_bundle(&relationship.peer_user_id)?
            .clone();
        let mut effects = vec![persist_effect(&self.state, vec![PersistOp::SaveDeployment])];
        let has_remote = attempt.claim_sets.iter().any(|set| set.purpose == "direct");
        if !has_remote {
            if attempt.remote_claim_idempotency_key.is_empty() {
                return Err(CoreError::invalid_state(
                    "remote claim idempotency key is unavailable",
                ));
            }
            let targets = peer_bundle
                .devices
                .iter()
                .filter(|device| device.status == DeviceStatusKind::Active)
                .map(|device| {
                    Ok(crate::transport_contract::KeyPackageClaimTarget {
                        device_id: device.device_id.clone(),
                        capability: device.key_package_claim_capability.clone().ok_or_else(
                            || {
                                CoreError::invalid_input(
                                    "active peer device is missing claim capability",
                                )
                            },
                        )?,
                    })
                })
                .collect::<CoreResult<Vec<_>>>()?;
            let endpoint = targets
                .first()
                .map(|target| target.capability.endpoint.clone())
                .ok_or_else(|| CoreError::invalid_input("peer has no active claim targets"))?;
            if targets
                .iter()
                .any(|target| target.capability.endpoint != endpoint)
            {
                return Err(CoreError::invalid_input(
                    "peer claim authority is inconsistent",
                ));
            }
            let request = ClaimKeyPackagesRequest {
                version: crate::model::ENVELOPE_VERSION_V2.into(),
                purpose: crate::transport_contract::KeyPackageClaimPurpose::Direct,
                idempotency_key: attempt.remote_claim_idempotency_key.clone(),
                requester_bundle: local_bundle.clone(),
                proposal: relationship.canonical_proposal.clone(),
                targets,
            };
            let request_id = self.next_request_id(&format!(
                "claim:{}",
                relationship.canonical_proposal.proposal_id
            ));
            self.state.pending_requests.insert(
                request_id.clone(),
                PendingRequest::ClaimKeyPackages {
                    purpose: crate::transport_contract::KeyPackageClaimPurpose::Direct,
                    peer_user_id: relationship.peer_user_id.clone(),
                    relationship_id: relationship_id.to_string(),
                    proposal_id: relationship.canonical_proposal.proposal_id.clone(),
                    idempotency_key: attempt.remote_claim_idempotency_key.clone(),
                    claim_endpoint: endpoint.clone(),
                },
            );
            effects.push(CoreEffect::ExecuteHttpRequest {
                request: HttpRequestEffect {
                    request_id,
                    method: HttpMethod::Post,
                    url: endpoint,
                    headers: BTreeMap::from([("Content-Type".into(), "application/json".into())]),
                    auth: None,
                    body: Some(serde_json::to_string(&request).map_err(|error| {
                        CoreError::invalid_input(format!("failed to encode claim retry: {error}"))
                    })?),
                },
            });
        }
        let local_device_id = self.local_device_id_required()?;
        let sibling_targets = local_bundle
            .devices
            .iter()
            .filter(|device| {
                device.status == DeviceStatusKind::Active && device.device_id != local_device_id
            })
            .map(|device| {
                Ok(crate::transport_contract::KeyPackageClaimTarget {
                    device_id: device.device_id.clone(),
                    capability: device.key_package_claim_capability.clone().ok_or_else(|| {
                        CoreError::invalid_input("active sibling is missing claim capability")
                    })?,
                })
            })
            .collect::<CoreResult<Vec<_>>>()?;
        let has_self = attempt
            .claim_sets
            .iter()
            .any(|set| set.purpose == "self_join");
        if !sibling_targets.is_empty() && !has_self {
            let idempotency_key = attempt.self_claim_idempotency_key.clone().ok_or_else(|| {
                CoreError::invalid_state("self claim idempotency key is unavailable")
            })?;
            let endpoint = sibling_targets[0].capability.endpoint.clone();
            if sibling_targets
                .iter()
                .any(|target| target.capability.endpoint != endpoint)
            {
                return Err(CoreError::invalid_input(
                    "sibling claim authority is inconsistent",
                ));
            }
            let request = ClaimKeyPackagesRequest {
                version: crate::model::ENVELOPE_VERSION_V2.into(),
                purpose: crate::transport_contract::KeyPackageClaimPurpose::SelfJoin,
                idempotency_key: idempotency_key.clone(),
                requester_bundle: local_bundle,
                proposal: relationship.canonical_proposal.clone(),
                targets: sibling_targets,
            };
            let request_id = self.next_request_id(&format!(
                "self-claim:{}",
                relationship.canonical_proposal.proposal_id
            ));
            self.state.pending_requests.insert(
                request_id.clone(),
                PendingRequest::ClaimKeyPackages {
                    purpose: crate::transport_contract::KeyPackageClaimPurpose::SelfJoin,
                    peer_user_id: relationship.peer_user_id.clone(),
                    relationship_id: relationship_id.to_string(),
                    proposal_id: relationship.canonical_proposal.proposal_id.clone(),
                    idempotency_key,
                    claim_endpoint: endpoint.clone(),
                },
            );
            effects.push(CoreEffect::ExecuteHttpRequest {
                request: HttpRequestEffect {
                    request_id,
                    method: HttpMethod::Post,
                    url: endpoint,
                    headers: BTreeMap::from([("Content-Type".into(), "application/json".into())]),
                    auth: None,
                    body: Some(serde_json::to_string(&request).map_err(|error| {
                        CoreError::invalid_input(format!(
                            "failed to encode self claim retry: {error}"
                        ))
                    })?),
                },
            });
        }
        if let Some(stored) = self.state.relationships.get_mut(relationship_id) {
            stored.setup_state = RelationshipSetupState::Claiming;
            stored.version = stored.version.saturating_add(1);
        }
        effects[0] = persist_effect(&self.state, vec![PersistOp::SaveDeployment]);
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                conversations_changed: true,
                ..CoreStateUpdate::default()
            },
            effects,
            view_model: None,
        })
    }

    pub(super) fn restart_expired_relationship(
        &mut self,
        relationship_id: &str,
    ) -> CoreResult<CoreOutput> {
        let now_ms = current_unix_millis(self.state.message_nonce);
        let existing = self
            .state
            .relationships
            .get(relationship_id)
            .filter(|relationship| relationship.account_state == RelationshipAccountState::Pending)
            .cloned()
            .ok_or_else(|| CoreError::invalid_state("pending relationship is unavailable"))?;
        let local_identity = self
            .state
            .local_identity
            .as_ref()
            .cloned()
            .ok_or_else(|| CoreError::invalid_state("local identity is unavailable"))?;
        let local_bundle = self
            .state
            .local_bundle
            .as_ref()
            .cloned()
            .ok_or_else(|| CoreError::invalid_state("local IdentityBundle is unavailable"))?;
        let peer_bundle = self
            .direct_peer_contact_bundle(&existing.peer_user_id)?
            .clone();
        let next_attempt = existing.canonical_proposal.attempt.saturating_add(1);
        let proposal_id = random_opaque_id("proposal");
        let mut proposal = RelationshipProposalV2 {
            proposal_id: proposal_id.clone(),
            initiator_user_id: local_bundle.user_id.clone(),
            initiator_device_id: local_identity.device_identity.device_id.clone(),
            relationship_id_candidate: existing.relationship_id.clone(),
            generation: existing.generation,
            attempt: next_attempt,
            peer_user_id: existing.peer_user_id.clone(),
            sender_bundle_digest: crate::identity::identity_bundle_digest(&local_bundle)?,
            created_at: now_ms,
            expires_at: now_ms.saturating_add(7 * 24 * 60 * 60 * 1000),
            signature: String::new(),
        };
        proposal.signature = local_identity.sign_device_payload(
            &crate::identity::relationship_proposal_signing_payload(&proposal),
        );
        crate::identity::verify_relationship_proposal(&proposal, &local_bundle)?;

        let remote_targets = peer_bundle
            .devices
            .iter()
            .filter(|device| device.status == DeviceStatusKind::Active)
            .map(|device| {
                Ok(crate::transport_contract::KeyPackageClaimTarget {
                    device_id: device.device_id.clone(),
                    capability: device.key_package_claim_capability.clone().ok_or_else(|| {
                        CoreError::invalid_input("active peer device is missing claim capability")
                    })?,
                })
            })
            .collect::<CoreResult<Vec<_>>>()?;
        let remote_endpoint = remote_targets
            .first()
            .map(|target| target.capability.endpoint.clone())
            .ok_or_else(|| CoreError::invalid_input("peer has no active claim targets"))?;
        if remote_targets
            .iter()
            .any(|target| target.capability.endpoint != remote_endpoint)
        {
            return Err(CoreError::invalid_input(
                "peer claim targets do not share one authority",
            ));
        }
        let remote_idempotency = random_opaque_id("claim");
        let remote_request = ClaimKeyPackagesRequest {
            version: crate::model::ENVELOPE_VERSION_V2.into(),
            purpose: crate::transport_contract::KeyPackageClaimPurpose::Direct,
            idempotency_key: remote_idempotency.clone(),
            requester_bundle: local_bundle.clone(),
            proposal: proposal.clone(),
            targets: remote_targets,
        };
        let sibling_targets = local_bundle
            .devices
            .iter()
            .filter(|device| {
                device.status == DeviceStatusKind::Active
                    && device.device_id != local_identity.device_identity.device_id
            })
            .map(|device| {
                Ok(crate::transport_contract::KeyPackageClaimTarget {
                    device_id: device.device_id.clone(),
                    capability: device.key_package_claim_capability.clone().ok_or_else(|| {
                        CoreError::invalid_input("active sibling is missing claim capability")
                    })?,
                })
            })
            .collect::<CoreResult<Vec<_>>>()?;

        if let Some(relationship) = self.state.relationships.get_mut(relationship_id) {
            relationship.canonical_proposal = proposal.clone();
            relationship.setup_state = RelationshipSetupState::RetryingExpired;
            relationship.version = relationship.version.saturating_add(1);
            relationship.updated_at = now_ms;
            relationship.attempts.push(RelationshipAttempt {
                attempt: next_attempt,
                proposal_id: proposal_id.clone(),
                ticket_id: String::new(),
                ticket_secret: String::new(),
                ticket_status_endpoint: None,
                remote_claim_idempotency_key: remote_idempotency.clone(),
                self_claim_idempotency_key: None,
                claim_retry_count: 0,
                claim_ids: Vec::new(),
                welcome_digests: Vec::new(),
                claim_sets: Vec::new(),
                created_at: now_ms,
                expires_at: proposal.expires_at,
            });
        }
        let mut stale_message_ids = Vec::new();
        for item in &mut self.state.pending_outbox {
            if item.envelope_v2.as_ref().is_some_and(|envelope| {
                envelope.relationship_id == relationship_id && envelope.attempt < next_attempt
            }) {
                item.retries = MAX_TRANSPORT_RETRIES;
                item.in_flight = false;
                stale_message_ids.push(item.envelope.message_id.clone());
            }
        }
        let remote_request_id = self.next_request_id(&format!("claim:{proposal_id}"));
        self.state.pending_requests.insert(
            remote_request_id.clone(),
            PendingRequest::ClaimKeyPackages {
                purpose: crate::transport_contract::KeyPackageClaimPurpose::Direct,
                peer_user_id: existing.peer_user_id.clone(),
                relationship_id: relationship_id.to_string(),
                proposal_id: proposal_id.clone(),
                idempotency_key: remote_idempotency,
                claim_endpoint: remote_endpoint.clone(),
            },
        );
        let mut retry_persist_ops = vec![PersistOp::SaveDeployment];
        retry_persist_ops.extend(
            stale_message_ids
                .into_iter()
                .map(|message_id| PersistOp::SaveOutgoingEnvelope { message_id }),
        );
        let mut effects = vec![
            persist_effect(&self.state, retry_persist_ops.clone()),
            CoreEffect::ExecuteHttpRequest {
                request: HttpRequestEffect {
                    request_id: remote_request_id,
                    method: HttpMethod::Post,
                    url: remote_endpoint,
                    headers: BTreeMap::from([("Content-Type".into(), "application/json".into())]),
                    auth: None,
                    body: Some(serde_json::to_string(&remote_request).map_err(|error| {
                        CoreError::invalid_input(format!(
                            "failed to encode relationship retry claim: {error}"
                        ))
                    })?),
                },
            },
        ];
        if !sibling_targets.is_empty() {
            let sibling_endpoint = sibling_targets[0].capability.endpoint.clone();
            if sibling_targets
                .iter()
                .any(|target| target.capability.endpoint != sibling_endpoint)
            {
                return Err(CoreError::invalid_input(
                    "sibling claim targets do not share one authority",
                ));
            }
            let self_idempotency = random_opaque_id("self-claim");
            if let Some(attempt) = self
                .state
                .relationships
                .get_mut(relationship_id)
                .and_then(|relationship| relationship.attempts.last_mut())
            {
                attempt.self_claim_idempotency_key = Some(self_idempotency.clone());
            }
            let self_request = ClaimKeyPackagesRequest {
                version: crate::model::ENVELOPE_VERSION_V2.into(),
                purpose: crate::transport_contract::KeyPackageClaimPurpose::SelfJoin,
                idempotency_key: self_idempotency.clone(),
                requester_bundle: local_bundle,
                proposal,
                targets: sibling_targets,
            };
            let self_request_id = self.next_request_id(&format!("self-claim:{proposal_id}"));
            self.state.pending_requests.insert(
                self_request_id.clone(),
                PendingRequest::ClaimKeyPackages {
                    purpose: crate::transport_contract::KeyPackageClaimPurpose::SelfJoin,
                    peer_user_id: existing.peer_user_id.clone(),
                    relationship_id: relationship_id.to_string(),
                    proposal_id,
                    idempotency_key: self_idempotency,
                    claim_endpoint: sibling_endpoint.clone(),
                },
            );
            effects.push(CoreEffect::ExecuteHttpRequest {
                request: HttpRequestEffect {
                    request_id: self_request_id,
                    method: HttpMethod::Post,
                    url: sibling_endpoint,
                    headers: BTreeMap::from([("Content-Type".into(), "application/json".into())]),
                    auth: None,
                    body: Some(serde_json::to_string(&self_request).map_err(|error| {
                        CoreError::invalid_input(format!(
                            "failed to encode relationship self-retry claim: {error}"
                        ))
                    })?),
                },
            });
        }
        effects[0] = persist_effect(&self.state, retry_persist_ops);
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                conversations_changed: true,
                ..CoreStateUpdate::default()
            },
            effects,
            view_model: None,
        })
    }

    pub(super) fn handle_outbound_relationship_upserted(
        &mut self,
        relationship_id: String,
        result: UpsertOutboundRelationshipResult,
    ) -> CoreResult<CoreOutput> {
        crate::identity::IdentityManager::verify_identity_bundle(&result.peer_bundle)?;
        if !result.canonical || result.relationship.relationship_id != relationship_id {
            if let Some(losing) = self.state.relationships.get_mut(&relationship_id) {
                losing.setup_state = RelationshipSetupState::Superseded;
                losing.version = losing.version.saturating_add(1);
            }
            let losing_conversation_id =
                self.state
                    .relationships
                    .get(&relationship_id)
                    .map(|relationship| {
                        format!(
                            "conv:direct:v2:{}:g{}",
                            relationship.relationship_id, relationship.generation
                        )
                    });
            if let Some(conversation_id) = losing_conversation_id {
                if let Some(conversation) = self.state.conversations.get_mut(&conversation_id) {
                    conversation.conversation.state = ConversationState::Archived;
                }
            }
            self.state.relationships.insert(
                result.relationship.relationship_id.clone(),
                result.relationship.clone(),
            );
            return Ok(CoreOutput {
                state_update: CoreStateUpdate {
                    conversations_changed: true,
                    contacts_changed: true,
                    ..CoreStateUpdate::default()
                },
                effects: vec![persist_effect(&self.state, vec![PersistOp::SaveDeployment])],
                view_model: None,
            });
        }

        let relationship = self
            .state
            .relationships
            .get(&relationship_id)
            .cloned()
            .ok_or_else(|| CoreError::invalid_state("canonical relationship is unavailable"))?;
        let direct_claim_set = relationship
            .attempts
            .last()
            .and_then(|attempt| {
                attempt
                    .claim_sets
                    .iter()
                    .find(|set| set.purpose == "direct")
            })
            .cloned()
            .ok_or_else(|| CoreError::invalid_state("persisted Direct claim set is unavailable"))?;
        let self_claim_set = relationship
            .attempts
            .last()
            .and_then(|attempt| {
                attempt
                    .claim_sets
                    .iter()
                    .find(|set| set.purpose == "self_join")
            })
            .cloned();
        let all_claims = direct_claim_set
            .claims
            .iter()
            .chain(
                self_claim_set
                    .iter()
                    .flat_map(|claim_set| claim_set.claims.iter()),
            )
            .cloned()
            .collect::<Vec<_>>();
        let peer_user_id = relationship.peer_user_id.clone();
        let peer_devices = result
            .peer_bundle
            .devices
            .iter()
            .filter(|device| device.status == DeviceStatusKind::Active)
            .collect::<Vec<_>>();
        let mut peer_packages = Vec::with_capacity(peer_devices.len());
        for device in peer_devices {
            let claim = direct_claim_set
                .claims
                .iter()
                .find(|claim| claim.user_id == peer_user_id && claim.device_id == device.device_id)
                .ok_or_else(|| CoreError::invalid_input("persisted claim target mismatch"))?;
            crate::mls_adapter::validate_key_package_device_binding(
                &claim.key_package_b64,
                device.mls_device_key_binding.as_ref().ok_or_else(|| {
                    CoreError::invalid_input("peer device is missing MLS binding")
                })?,
            )?;
            peer_packages.push(PeerDeviceKeyPackage {
                user_id: peer_user_id.clone(),
                device_id: device.device_id.clone(),
                device_public_key: device.device_public_key.clone(),
                key_package_b64: claim.key_package_b64.clone(),
            });
        }
        if let Some(self_claim_set) = self_claim_set.as_ref() {
            let local_bundle =
                self.state.local_bundle.as_ref().ok_or_else(|| {
                    CoreError::invalid_state("local IdentityBundle is unavailable")
                })?;
            let local_device_id = self.local_device_id_required()?;
            for device in local_bundle.devices.iter().filter(|device| {
                device.status == DeviceStatusKind::Active && device.device_id != local_device_id
            }) {
                let claim = self_claim_set
                    .claims
                    .iter()
                    .find(|claim| {
                        claim.user_id == local_bundle.user_id && claim.device_id == device.device_id
                    })
                    .ok_or_else(|| {
                        CoreError::invalid_input("persisted self claim target mismatch")
                    })?;
                crate::mls_adapter::validate_key_package_device_binding(
                    &claim.key_package_b64,
                    device.mls_device_key_binding.as_ref().ok_or_else(|| {
                        CoreError::invalid_input("sibling device is missing MLS binding")
                    })?,
                )?;
                peer_packages.push(PeerDeviceKeyPackage {
                    user_id: local_bundle.user_id.clone(),
                    device_id: device.device_id.clone(),
                    device_public_key: device.device_public_key.clone(),
                    key_package_b64: claim.key_package_b64.clone(),
                });
            }
        }
        let conversation_id = format!(
            "conv:direct:v2:{}:g{}",
            relationship.relationship_id, relationship.generation
        );
        let local_identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .clone();
        let peer_device_ids = direct_claim_set
            .claims
            .iter()
            .map(|claim| claim.device_id.clone())
            .collect::<Vec<_>>();
        let local_conversation = ConversationManager::create_direct_conversation_with_id(
            conversation_id.clone(),
            &local_identity.user_identity.user_id,
            &local_identity.device_identity.device_id,
            &peer_user_id,
            &peer_device_ids,
        )?;
        let replacing_expired_attempt = relationship.canonical_proposal.attempt > 1
            && self.state.mls_summaries.contains_key(&conversation_id);
        let adapter = self
            .state
            .mls_adapter
            .as_mut()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?;
        let artifacts = if replacing_expired_attempt {
            adapter.rebuild_unaccepted_conversation(&conversation_id, &peer_packages)?
        } else {
            adapter.create_conversation(&conversation_id, &peer_packages)?
        };
        let summary = self
            .state
            .mls_adapter
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("mls adapter missing after Direct V2 setup"))?
            .export_group_summary(&conversation_id)?;
        self.state
            .mls_summaries
            .insert(conversation_id.clone(), summary);
        self.state
            .conversations
            .insert(conversation_id.clone(), local_conversation);

        let mut envelopes = Vec::new();
        for welcome in artifacts.welcomes {
            let claim = all_claims
                .iter()
                .find(|claim| claim.device_id == welcome.recipient_device_id)
                .ok_or_else(|| CoreError::invalid_input("Welcome recipient has no claim"))?;
            envelopes.push(self.build_envelope_v2(
                &relationship_id,
                &claim.user_id,
                &welcome.recipient_device_id,
                MessageType::MlsWelcome,
                welcome.payload_b64,
                Some(claim.claim_id.clone()),
            )?);
        }
        let message_summaries = envelopes
            .iter()
            .map(|envelope| MessageSummary {
                conversation_id: envelope.conversation_id.clone(),
                message_id: envelope.message_id.clone(),
                message_type: envelope.message_type,
            })
            .collect::<Vec<_>>();
        self.enqueue_envelopes_v2(peer_user_id.clone(), envelopes);
        if let Some(stored) = self.state.relationships.get_mut(&relationship_id) {
            stored.setup_state = RelationshipSetupState::WaitingAcceptance;
        }
        let mut persist_ops = vec![
            PersistOp::SaveDeployment,
            PersistOp::SaveConversation {
                conversation_id: conversation_id.clone(),
            },
            PersistOp::SaveMlsState {
                conversation_id: conversation_id.clone(),
            },
        ];
        persist_ops.extend(self.state.pending_outbox.iter().filter_map(|item| {
            item.envelope_v2
                .as_ref()
                .filter(|envelope| envelope.relationship_id == relationship_id)
                .map(|envelope| PersistOp::SaveOutgoingEnvelope {
                    message_id: envelope.message_id.clone(),
                })
        }));
        self.merge_with_transport_flush(CoreOutput {
            state_update: CoreStateUpdate {
                conversations_changed: true,
                messages_changed: true,
                contacts_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![
                persist_effect(&self.state, persist_ops),
                CoreEffect::ScheduleTimer {
                    timer: TimerEffect {
                        timer_id: format!("relationship_status:{relationship_id}"),
                        delay_ms: 6 * 60 * 60 * 1000,
                    },
                },
            ],
            view_model: Some(CoreViewModel {
                conversations: vec![ConversationSummary {
                    conversation_id: conversation_id.clone(),
                    peer_user_id: peer_user_id.clone(),
                    state: "waiting_acceptance".into(),
                    kind: Some(ConversationKind::Direct),
                    title: None,
                    display_name: self.contact_archive_display_name(&peer_user_id),
                    group_id: None,
                    member_count: None,
                    group_role: None,
                    group_cursor: None,
                    last_message_preview: None,
                    last_message_type: Some(MessageType::MlsWelcome),
                    message_count: None,
                    recovery: None,
                    relationship: self.relationship_view_state(&conversation_id),
                }],
                messages: message_summaries,
                ..CoreViewModel::default()
            }),
        })
    }

    pub(super) fn enqueue_envelopes_v2(
        &mut self,
        _peer_user_id: String,
        envelopes: Vec<crate::model::EnvelopeV2>,
    ) {
        for envelope_v2 in envelopes {
            let peer_user_id = envelope_v2.recipient_user_id.clone();
            let shadow = Envelope {
                version: crate::model::CURRENT_MODEL_VERSION.into(),
                message_id: envelope_v2.message_id.clone(),
                conversation_id: envelope_v2.conversation_id.clone(),
                sender_user_id: envelope_v2.sender_user_id.clone(),
                sender_device_id: envelope_v2.sender_device_id.clone(),
                recipient_device_id: envelope_v2.recipient_device_id.clone(),
                created_at: envelope_v2.created_at,
                message_type: envelope_v2.message_type,
                inline_ciphertext: envelope_v2.inline_ciphertext.clone(),
                storage_refs: envelope_v2.storage_refs.clone(),
                delivery_class: envelope_v2.delivery_class,
                wake_hint: envelope_v2.wake_hint.clone(),
                sender_proof: envelope_v2.sender_proof.clone(),
            };
            self.state.outbox.push(shadow.clone());
            self.state.pending_outbox.push(PendingOutboxItem {
                envelope: shadow,
                envelope_v2: Some(envelope_v2),
                peer_user_id,
                retries: 0,
                in_flight: false,
                app_message_id: None,
                plaintext_cache: None,
                identity_refresh_attempted: false,
            });
        }
    }

    pub(super) fn enqueue_envelopes_v2_with_plaintext(
        &mut self,
        peer_user_id: String,
        envelopes: Vec<crate::model::EnvelopeV2>,
        plaintext: String,
        app_message_id: Option<String>,
    ) {
        let start = self.state.pending_outbox.len();
        self.enqueue_envelopes_v2(peer_user_id, envelopes);
        for item in &mut self.state.pending_outbox[start..] {
            item.plaintext_cache = Some(plaintext.clone());
            item.app_message_id = app_message_id.clone();
        }
    }

    /// Enqueue envelopes with plaintext cache for sent messages

    pub(super) fn enqueue_envelopes_with_plaintext(
        &mut self,
        peer_user_id: String,
        envelopes: Vec<Envelope>,
        plaintext: String,
        app_message_id: Option<String>,
    ) {
        for envelope in envelopes {
            self.state.outbox.push(envelope.clone());
            self.state.pending_outbox.push(PendingOutboxItem {
                envelope,
                envelope_v2: None,
                peer_user_id: peer_user_id.clone(),
                retries: 0,
                in_flight: false,
                app_message_id: app_message_id.clone(),
                plaintext_cache: Some(plaintext.clone()),
                identity_refresh_attempted: false,
            });
        }
    }

    pub(super) fn evaluate_direct_application_plaintext(
        &self,
        record: &InboxRecord,
        local_user_id: &str,
        local_device_id: &str,
        application: DecryptedApplicationMessage,
    ) -> ApplicationPlaintextDecision {
        let Some(mls_sender) = Self::parse_mls_sender_identity(&application.sender_identity) else {
            return ApplicationPlaintextDecision::RejectedProtocol {
                reason: "MLS sender identity is malformed".into(),
            };
        };
        if mls_sender.user_id != record.envelope.sender_user_id
            || mls_sender.device_id != record.envelope.sender_device_id
        {
            return ApplicationPlaintextDecision::RejectedProtocol {
                reason: "MLS sender identity does not match envelope sender".into(),
            };
        }

        match ProtectedAppMessage::from_json_slice(&application.plaintext) {
            Ok(protected) => {
                if protected.sender_user_id != record.envelope.sender_user_id
                    || protected.sender_device_id != record.envelope.sender_device_id
                    || protected.sender_user_id != mls_sender.user_id
                    || protected.sender_device_id != mls_sender.device_id
                {
                    return ApplicationPlaintextDecision::RejectedProtocol {
                        reason: "protected sender does not match MLS/envelope sender".into(),
                    };
                }
                if protected.conversation_id != record.envelope.conversation_id {
                    return ApplicationPlaintextDecision::RejectedProtocol {
                        reason: "protected conversation_id does not match envelope".into(),
                    };
                }
                if protected.recipient_user_id != local_user_id {
                    return ApplicationPlaintextDecision::RejectedProtocol {
                        reason: "protected recipient_user_id does not match local user".into(),
                    };
                }
                if record.envelope.recipient_device_id != local_device_id {
                    return ApplicationPlaintextDecision::RejectedProtocol {
                        reason: "envelope recipient_device_id does not match local device".into(),
                    };
                }
                if !protected
                    .audience_device_ids
                    .iter()
                    .any(|device_id| device_id == local_device_id)
                {
                    return ApplicationPlaintextDecision::RejectedProtocol {
                        reason: "local device is not in protected audience".into(),
                    };
                }
                if protected.payload_kind != ProtectedPayloadKind::Text {
                    return ApplicationPlaintextDecision::RejectedProtocol {
                        reason: "unsupported protected payload kind".into(),
                    };
                }
                let app_prefix = format!("app:{}:", protected.conversation_id);
                let app_suffix = format!(":{}", protected.sender_device_id);
                if !protected.app_message_id.starts_with(&app_prefix)
                    || !protected.app_message_id.ends_with(&app_suffix)
                {
                    return ApplicationPlaintextDecision::RejectedProtocol {
                        reason: "protected app_message_id does not bind conversation and sender"
                            .into(),
                    };
                }
                if self.conversation_has_app_message(
                    &record.envelope.conversation_id,
                    &protected.app_message_id,
                ) {
                    return ApplicationPlaintextDecision::DuplicateAppMessage {
                        app_message_id: protected.app_message_id,
                    };
                }
                ApplicationPlaintextDecision::Accepted {
                    plaintext: protected.body,
                    app_message_id: Some(protected.app_message_id),
                }
            }
            Err(error) => {
                if Self::plaintext_looks_like_protected_app_message(&application.plaintext) {
                    return ApplicationPlaintextDecision::RejectedProtocol {
                        reason: format!("malformed protected app message: {}", error.message()),
                    };
                }
                match String::from_utf8(application.plaintext) {
                    Ok(plaintext) => ApplicationPlaintextDecision::Accepted {
                        plaintext,
                        app_message_id: None,
                    },
                    Err(_) => ApplicationPlaintextDecision::RejectedProtocol {
                        reason: "legacy application plaintext is not utf-8".into(),
                    },
                }
            }
        }
    }

    pub(super) fn parse_mls_sender_identity(value: &str) -> Option<ParsedMlsSenderIdentity> {
        let parts = value.split('|').collect::<Vec<_>>();
        if parts.len() != 4 || parts[0].trim().is_empty() || parts[1].trim().is_empty() {
            return None;
        }
        Some(ParsedMlsSenderIdentity {
            user_id: parts[0].to_string(),
            device_id: parts[1].to_string(),
        })
    }

    pub(super) fn plaintext_looks_like_protected_app_message(bytes: &[u8]) -> bool {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
            return false;
        };
        let Some(object) = value.as_object() else {
            return false;
        };
        [
            "app_message_id",
            "audience_device_ids",
            "payload_kind",
            "recipient_user_id",
        ]
        .iter()
        .any(|key| object.contains_key(*key))
    }

    pub(super) fn conversation_has_app_message(
        &self,
        conversation_id: &str,
        app_message_id: &str,
    ) -> bool {
        self.state
            .conversations
            .get(conversation_id)
            .is_some_and(|state| {
                state
                    .messages
                    .iter()
                    .any(|message| message.app_message_id.as_deref() == Some(app_message_id))
            })
    }

    pub(super) fn conversation_has_mls_ciphertext(
        &self,
        conversation_id: &str,
        ciphertext_sha256: &str,
    ) -> bool {
        self.state
            .conversations
            .get(conversation_id)
            .is_some_and(|state| {
                state.messages.iter().any(|message| {
                    message.mls_ciphertext_sha256.as_deref() == Some(ciphertext_sha256)
                })
            })
    }

    pub(super) fn store_accepted_application_message(
        &mut self,
        record: &InboxRecord,
        plaintext: String,
        app_message_id: Option<String>,
        mls_ciphertext_sha256: String,
    ) -> CoreResult<bool> {
        let conversation_id = &record.envelope.conversation_id;
        let state = self
            .state
            .conversations
            .get_mut(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?;
        let duplicate = state.messages.iter().any(|message| {
            message.message_id == record.message_id
                || app_message_id
                    .as_deref()
                    .is_some_and(|app_id| message.app_message_id.as_deref() == Some(app_id))
        });
        if duplicate {
            return Ok(false);
        }
        state.messages.push(StoredMessage {
            message_id: record.message_id.clone(),
            app_message_id,
            mls_ciphertext_sha256: Some(mls_ciphertext_sha256),
            sender_user_id: Some(record.envelope.sender_user_id.clone()),
            sender_device_id: record.envelope.sender_device_id.clone(),
            recipient_device_id: record.envelope.recipient_device_id.clone(),
            message_type: record.envelope.message_type,
            created_at: record.envelope.created_at,
            plaintext: Some(plaintext),
            storage_refs: record.envelope.storage_refs.clone(),
            delivery_state: None,
            message_request_id: None,
        });
        state.last_message_type = Some(record.envelope.message_type);
        state.conversation.updated_at = record.envelope.created_at;
        state
            .last_known_peer_active_devices
            .insert(record.envelope.sender_device_id.clone());
        Ok(true)
    }

    pub(super) fn ensure_conversation_ready_for_send(
        &mut self,
        conversation_id: &str,
    ) -> CoreResult<()> {
        if conversation_id.trim().is_empty() {
            return Err(CoreError::invalid_input(
                "conversation_id must not be empty",
            ));
        }
        // Get conversation state info first (immutable borrow)
        let (conv_state, recovery_status, peer_user_id) = {
            let conversation = self
                .state
                .conversations
                .get(conversation_id)
                .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?;
            (
                conversation.conversation.state,
                conversation.recovery_status,
                conversation.peer_user_id.clone(),
            )
        };

        if conv_state == ConversationState::NeedsRebuild {
            return Err(CoreError::invalid_state(
                "conversation needs rebuild before sending new messages",
            ));
        }
        if matches!(
            conv_state,
            ConversationState::Closed | ConversationState::Archived
        ) {
            return Err(Self::relationship_closed_error(&peer_user_id));
        }
        if !self.state.mls_summaries.contains_key(conversation_id)
            || !self
                .state
                .mls_adapter
                .as_ref()
                .is_some_and(|adapter| adapter.has_conversation(conversation_id))
        {
            return Err(CoreError::temporary_failure(
                "conversation setup is still syncing",
            ));
        }

        // Check if conversation is still recovering
        if recovery_status == RecoveryStatus::NeedsRecovery {
            // The authoritative signal is the active recovery context: if a
            // context still exists, recovery has not converged and we must
            // fail-closed so the sender does not overclaim delivery.
            //
            // `mls_summaries` staying `Active` is *not* sufficient evidence
            // that recovery completed -- e.g. after a peer device change the
            // MLS group may still be cryptographically valid for the old
            // roster while a new commit is being prepared. Trusting the MLS
            // status alone here caused the sender to accept new messages
            // during recovery and regress the "fail-closed during recovery"
            // guarantee.
            if self.state.recovery_contexts.contains_key(conversation_id) {
                return Err(CoreError::temporary_failure(
                    "conversation membership is still recovering",
                ));
            }
            // No active recovery context left: recovery completed in a prior
            // step but the conversation's recovery_status field was never
            // cleared. Treat the conversation as healthy going forward.
            if let Some(state) = self.state.conversations.get_mut(conversation_id) {
                state.recovery_status = RecoveryStatus::Healthy;
            }
        }
        let contact_status = self
            .state
            .contacts
            .get(&peer_user_id)
            .map(|contact| contact.relationship_status.clone())
            .ok_or_else(|| CoreError::invalid_input("peer contact is missing"))?;
        if !Self::relationship_allows_user_message(&contact_status) {
            return Err(Self::relationship_closed_error(&peer_user_id));
        }
        self.direct_peer_contact_bundle(&peer_user_id)?;
        Ok(())
    }

    pub(super) fn conversation_summary(
        &self,
        conversation_id: &str,
    ) -> CoreResult<ConversationSummary> {
        let conversation = self
            .state
            .conversations
            .get(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?;
        if conversation.conversation.kind == ConversationKind::Group {
            let group_state = self
                .state
                .group_states
                .values()
                .find(|state| state.conversation_id == conversation_id);
            return Ok(ConversationSummary {
                conversation_id: conversation_id.to_string(),
                peer_user_id: conversation.peer_user_id.clone(),
                state: match conversation.recovery_status {
                    RecoveryStatus::Healthy => "active".into(),
                    RecoveryStatus::NeedsRecovery => "needs_recovery".into(),
                    RecoveryStatus::NeedsRebuild => "needs_rebuild".into(),
                },
                kind: Some(ConversationKind::Group),
                title: group_state.map(|state| state.manifest.title.clone()),
                display_name: None,
                group_id: group_state.map(|state| state.group_id.clone()),
                member_count: group_state.map(|state| {
                    state
                        .manifest
                        .members
                        .iter()
                        .filter(|member| member.status == GroupMemberStatus::Active)
                        .count()
                }),
                group_role: group_state.and_then(|state| state.local_role),
                group_cursor: group_state
                    .and_then(|state| self.state.group_cursors.get(&state.group_id).cloned()),
                last_message_preview: None,
                last_message_type: conversation.last_message_type,
                message_count: Some(conversation.messages.len()),
                recovery: self.recovery_snapshot_for_conversation(conversation_id),
                relationship: None,
            });
        }
        Ok(ConversationSummary {
            conversation_id: conversation_id.to_string(),
            peer_user_id: conversation.peer_user_id.clone(),
            state: match conversation.conversation.state {
                ConversationState::Active => match conversation.recovery_status {
                    RecoveryStatus::Healthy => "active".into(),
                    RecoveryStatus::NeedsRecovery => "needs_recovery".into(),
                    RecoveryStatus::NeedsRebuild => "needs_rebuild".into(),
                },
                ConversationState::NeedsRebuild => "needs_rebuild".into(),
                ConversationState::Closed => "closed".into(),
                ConversationState::Archived => "archived".into(),
                ConversationState::Dissolved => "dissolved".into(),
            },
            kind: Some(ConversationKind::Direct),
            title: None,
            display_name: conversation
                .archive_metadata
                .as_ref()
                .and_then(|metadata| metadata.peer_display_name.clone())
                .or_else(|| self.contact_archive_display_name(&conversation.peer_user_id)),
            group_id: None,
            member_count: None,
            group_role: None,
            group_cursor: None,
            last_message_preview: None,
            last_message_type: conversation.last_message_type,
            message_count: None,
            recovery: self.recovery_snapshot_for_conversation(conversation_id),
            relationship: self.relationship_view_state(conversation_id),
        })
    }

    pub(super) fn set_local_display_name(
        &mut self,
        display_name: Option<String>,
    ) -> CoreResult<CoreOutput> {
        self.ensure_identity_publication_idle()?;
        let display_name = normalize_display_name(display_name)?;
        self.state.local_display_name = display_name.clone();

        if self.state.local_identity.is_some() {
            let updated_at = self
                .state
                .local_bundle
                .as_ref()
                .map(|bundle| bundle.updated_at.saturating_add(1))
                .or_else(|| {
                    self.state
                        .local_identity
                        .as_ref()
                        .map(|identity| identity.device_status.updated_at.saturating_add(1))
                })
                .unwrap_or(1);
            self.refresh_local_bundle_with_updated_at(updated_at)?;
        } else if let Some(ref mut bundle) = self.state.local_bundle {
            bundle.display_name = display_name.clone();
            bundle.updated_at = bundle.updated_at.saturating_add(1);
        }

        let mut effects = if self.state.local_bundle.is_some() {
            self.local_shared_state_publish_effects()?
        } else {
            vec![]
        };
        effects.push(persist_effect(&self.state, vec![PersistOp::SaveDeployment]));

        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                identity_changed: true,
                ..CoreStateUpdate::default()
            },
            effects,
            view_model: Some(CoreViewModel {
                identity: self.local_identity_summary(),
                ..CoreViewModel::default()
            }),
        })
    }

    pub(super) fn set_contact_display_name(
        &mut self,
        user_id: String,
        display_name: Option<String>,
    ) -> CoreResult<CoreOutput> {
        let display_name = normalize_display_name(display_name)?;

        // Check if contact exists
        if !self.state.contacts.contains_key(&user_id) {
            return Err(CoreError::invalid_input("contact does not exist"));
        }

        // Update display_name
        if let Some(contact) = self.state.contacts.get_mut(&user_id) {
            contact.display_name = display_name.clone();
        }

        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(
                &self.state,
                vec![PersistOp::SaveContact { user_id }],
            )],
            view_model: Some(CoreViewModel {
                contacts: self
                    .state
                    .contacts
                    .iter()
                    .map(|(uid, c)| self.contact_summary(uid, c))
                    .collect(),
                ..CoreViewModel::default()
            }),
        })
    }

    fn ensure_identity_publication_idle(&self) -> CoreResult<()> {
        let Some(pending) = self.state.pending_identity_publication.as_ref() else {
            return Ok(());
        };
        let code = if pending.reason == "share_link_rotation" {
            "contact_share_rotation_unverified"
        } else {
            "keypackage_refresh_pending"
        };
        Err(CoreError::new(
            code,
            "identity publication is awaiting server confirmation",
        ))
    }

    pub(super) fn contact_summary(
        &self,
        user_id: &str,
        contact: &PersistedContact,
    ) -> ContactSummary {
        ContactSummary {
            user_id: user_id.to_string(),
            display_name: contact
                .display_name
                .clone()
                .or(contact.original_name.clone()),
            device_count: contact.bundle.devices.len(),
            relationship_status: contact.relationship_status.clone(),
        }
    }

    pub(super) fn set_contact_relationship_status(
        &mut self,
        user_id: &str,
        status: ContactRelationshipStatus,
    ) -> bool {
        let Some(contact) = self.state.contacts.get_mut(user_id) else {
            return false;
        };
        if contact.relationship_status == status {
            return false;
        }
        contact.relationship_status = status;
        true
    }

    pub(super) fn contact_summaries(&self) -> Vec<ContactSummary> {
        self.state
            .contacts
            .iter()
            .filter(|(_, contact)| !Self::relationship_is_removed(&contact.relationship_status))
            .map(|(uid, c)| self.contact_summary(uid, c))
            .collect()
    }

    pub(super) fn relationship_closed_error(peer_user_id: &str) -> CoreError {
        CoreError::new(
            "relationship_closed",
            format!("direct relationship with {peer_user_id} is closed"),
        )
    }

    pub(super) fn relationship_allows_session_setup(status: &ContactRelationshipStatus) -> bool {
        matches!(
            status,
            ContactRelationshipStatus::Available | ContactRelationshipStatus::PendingOutbound
        )
    }

    pub(super) fn relationship_allows_user_message(status: &ContactRelationshipStatus) -> bool {
        matches!(status, ContactRelationshipStatus::Available)
    }

    pub(super) fn relationship_can_promote_from_peer_accept(
        status: &ContactRelationshipStatus,
    ) -> bool {
        matches!(status, ContactRelationshipStatus::PendingOutbound)
    }

    pub(super) fn relationship_is_removed(status: &ContactRelationshipStatus) -> bool {
        matches!(
            status,
            ContactRelationshipStatus::RemovedByMe | ContactRelationshipStatus::RemovedByPeer
        )
    }

    pub(super) fn contact_label(&self, user_id: &str) -> String {
        self.state
            .contacts
            .get(user_id)
            .and_then(|contact| {
                contact
                    .display_name
                    .clone()
                    .or_else(|| contact.original_name.clone())
                    .or_else(|| contact.bundle.display_name.clone())
            })
            .unwrap_or_else(|| user_id.to_string())
    }

    pub(super) fn contact_archive_display_name(&self, user_id: &str) -> Option<String> {
        self.state.contacts.get(user_id).and_then(|contact| {
            contact
                .display_name
                .clone()
                .or_else(|| contact.original_name.clone())
                .or_else(|| contact.bundle.display_name.clone())
        })
    }

    pub(super) fn next_system_message(
        &mut self,
        conversation_id: &str,
        message_type: MessageType,
        sender_user_id: Option<String>,
        sender_device_id: String,
        recipient_device_id: String,
        plaintext: String,
        tag: &str,
    ) -> StoredMessage {
        let nonce = self.next_message_nonce();
        StoredMessage {
            message_id: format!("{conversation_id}:system:{tag}:{nonce}"),
            app_message_id: None,
            mls_ciphertext_sha256: None,
            sender_user_id,
            sender_device_id,
            recipient_device_id,
            message_type,
            created_at: current_unix_millis(nonce),
            plaintext: Some(plaintext),
            storage_refs: Vec::new(),
            delivery_state: None,
            message_request_id: None,
        }
    }

    pub(super) fn push_system_message(
        &mut self,
        conversation_id: &str,
        message: StoredMessage,
    ) -> Option<String> {
        let conversation = self.state.conversations.get_mut(conversation_id)?;
        if conversation
            .messages
            .iter()
            .any(|existing| existing.message_id == message.message_id)
        {
            return None;
        }
        let message_id = message.message_id.clone();
        conversation.last_message_type = Some(message.message_type);
        conversation.messages.push(message);
        Some(message_id)
    }

    pub(super) fn archive_conversation_with_message(
        &mut self,
        conversation_id: &str,
        message: StoredMessage,
        archive_reason: &str,
    ) -> Option<MessageSummary> {
        let message_id = message.message_id.clone();
        let message_type = message.message_type;
        let created_at = message.created_at;
        let archive_metadata =
            self.state
                .conversations
                .get(conversation_id)
                .and_then(|conversation| {
                    if conversation.conversation.kind != ConversationKind::Direct {
                        return None;
                    }
                    let peer_user_id = conversation.peer_user_id.clone();
                    let peer_display_name = self
                        .contact_archive_display_name(&peer_user_id)
                        .or_else(|| {
                            conversation
                                .archive_metadata
                                .as_ref()
                                .and_then(|metadata| metadata.peer_display_name.clone())
                        });
                    Some(ConversationArchiveMetadata {
                        peer_user_id,
                        peer_display_name,
                        archive_reason: archive_reason.to_string(),
                        archived_at: created_at,
                    })
                });
        if let Some(conversation) = self.state.conversations.get_mut(conversation_id) {
            conversation.conversation.state = ConversationState::Archived;
            conversation.conversation.updated_at =
                conversation.conversation.updated_at.max(created_at);
            conversation.recovery_status = RecoveryStatus::Healthy;
            conversation.archive_metadata = archive_metadata;
        }
        self.push_system_message(conversation_id, message)
            .map(|_| MessageSummary {
                conversation_id: conversation_id.to_string(),
                message_id,
                message_type,
            })
    }

    pub(super) fn clear_direct_runtime_state(
        &mut self,
        conversation_id: &str,
    ) -> CoreResult<Vec<PersistOp>> {
        let conversation_message_ids = self
            .state
            .conversations
            .get(conversation_id)
            .map(|conversation| {
                conversation
                    .messages
                    .iter()
                    .map(|message| message.message_id.clone())
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        self.state.mls_summaries.remove(conversation_id);
        self.state.recovery_contexts.remove(conversation_id);

        let removed_outbox_message_ids: Vec<String> = self
            .state
            .pending_outbox
            .iter()
            .filter(|item| {
                item.envelope.conversation_id == conversation_id
                    && item.envelope.message_type != MessageType::ControlContactRemoved
            })
            .map(|item| item.envelope.message_id.clone())
            .collect();
        self.state.pending_outbox.retain(|item| {
            item.envelope.conversation_id != conversation_id
                || item.envelope.message_type == MessageType::ControlContactRemoved
        });

        let removed_blob_task_ids: Vec<String> = self
            .state
            .pending_blob_uploads
            .iter()
            .filter(|(_, task)| task.conversation_id == conversation_id)
            .map(|(task_id, _)| task_id.clone())
            .chain(
                self.state
                    .pending_blob_downloads
                    .iter()
                    .filter(|(_, task)| task.conversation_id == conversation_id)
                    .map(|(task_id, _)| task_id.clone()),
            )
            .collect();
        self.state
            .pending_blob_uploads
            .retain(|_, task| task.conversation_id != conversation_id);
        self.state
            .pending_blob_downloads
            .retain(|_, task| task.conversation_id != conversation_id);

        let removed_ack_device_ids: Vec<String> = self
            .state
            .pending_acks
            .iter()
            .filter(|(_, ack)| {
                ack.ack
                    .acked_message_ids
                    .iter()
                    .any(|message_id| conversation_message_ids.contains(message_id))
            })
            .map(|(device_id, _)| device_id.clone())
            .collect();
        for device_id in &removed_ack_device_ids {
            self.state.pending_acks.remove(device_id);
        }

        let changed_sync_device_ids: Vec<String> = self
            .state
            .sync_states
            .iter_mut()
            .filter_map(|(device_id, sync_state)| {
                let pending_seqs = sync_state
                    .pending_records
                    .iter()
                    .filter_map(|(seq, record)| {
                        (record.envelope.conversation_id == conversation_id).then_some(*seq)
                    })
                    .collect::<Vec<_>>();
                if pending_seqs.is_empty() {
                    return None;
                }
                for seq in &pending_seqs {
                    sync_state.pending_records.remove(seq);
                    sync_state.pending_record_seqs.remove(seq);
                }
                sync_state.pending_retry = !sync_state.pending_record_seqs.is_empty();
                Some(device_id.clone())
            })
            .collect();

        if let Some(ref mut mls_adapter) = self.state.mls_adapter {
            mls_adapter.delete_group(conversation_id)?;
        }

        let mut persist_ops = vec![
            PersistOp::DeleteMlsState {
                conversation_id: conversation_id.to_string(),
            },
            PersistOp::DeleteRecoveryContext {
                conversation_id: conversation_id.to_string(),
            },
        ];
        persist_ops.extend(
            removed_outbox_message_ids
                .into_iter()
                .map(|message_id| PersistOp::DeleteOutgoingEnvelope { message_id }),
        );
        persist_ops.extend(
            removed_blob_task_ids
                .into_iter()
                .map(|task_id| PersistOp::DeletePendingBlobTransfer { task_id }),
        );
        persist_ops.extend(
            removed_ack_device_ids
                .into_iter()
                .map(|device_id| PersistOp::DeletePendingAck { device_id }),
        );
        persist_ops.extend(
            changed_sync_device_ids
                .into_iter()
                .map(|device_id| PersistOp::SaveSyncState { device_id }),
        );
        Ok(persist_ops)
    }

    pub(super) fn build_contact_removed_envelopes(
        &mut self,
        peer_user_id: &str,
        conversation_id: &str,
        created_at: u64,
    ) -> CoreResult<Vec<Envelope>> {
        let Some(contact) = self.state.contacts.get(peer_user_id) else {
            return Ok(Vec::new());
        };
        let peer_device_ids = contact
            .bundle
            .devices
            .iter()
            .filter(|device| matches!(device.status, DeviceStatusKind::Active))
            .map(|device| device.device_id.clone())
            .collect::<Vec<_>>();
        if peer_device_ids.is_empty() {
            return Ok(Vec::new());
        }
        let local_user_id = self.local_identity_user_id()?;
        let payload = ContactRemovedControl {
            version: crate::model::CURRENT_MODEL_VERSION.to_string(),
            conversation_id: conversation_id.to_string(),
            actor_user_id: local_user_id,
            removed_user_id: peer_user_id.to_string(),
            created_at,
        };
        let payload_b64 = STANDARD.encode(serde_json::to_vec(&payload).map_err(|error| {
            CoreError::invalid_input(format!("failed to encode contact removed control: {error}"))
        })?);
        peer_device_ids
            .iter()
            .map(|device_id| {
                self.build_envelope(
                    conversation_id,
                    device_id,
                    MessageType::ControlContactRemoved,
                    payload_b64.clone(),
                )
            })
            .collect()
    }

    pub(super) fn build_contact_removed_envelopes_v2(
        &mut self,
        peer_user_id: &str,
        relationship_id: &str,
        created_at: u64,
    ) -> CoreResult<Vec<crate::model::EnvelopeV2>> {
        let contact = self
            .state
            .contacts
            .get(peer_user_id)
            .ok_or_else(|| CoreError::invalid_input("peer contact is missing"))?
            .clone();
        let conversation_id = self
            .state
            .relationships
            .get(relationship_id)
            .map(|relationship| {
                format!(
                    "conv:direct:v2:{}:g{}",
                    relationship.relationship_id, relationship.generation
                )
            })
            .ok_or_else(|| CoreError::invalid_state("relationship state is missing"))?;
        let local_user_id = self.local_identity_user_id()?;
        let payload = ContactRemovedControl {
            version: crate::model::ENVELOPE_VERSION_V2.to_string(),
            conversation_id,
            actor_user_id: local_user_id,
            removed_user_id: peer_user_id.to_string(),
            created_at,
        };
        let payload_b64 = STANDARD.encode(serde_json::to_vec(&payload).map_err(|error| {
            CoreError::invalid_input(format!("failed to encode contact removed control: {error}"))
        })?);
        contact
            .bundle
            .devices
            .iter()
            .filter(|device| device.status == DeviceStatusKind::Active)
            .map(|device| {
                self.build_envelope_v2(
                    relationship_id,
                    peer_user_id,
                    &device.device_id,
                    MessageType::ControlContactRemoved,
                    payload_b64.clone(),
                    None,
                )
            })
            .collect()
    }

    fn remove_relationship_from_registry(
        &mut self,
        relationship_id: &str,
        generation: u64,
    ) -> CoreResult<CoreOutput> {
        let endpoint = self
            .state
            .deployment_bundle
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("deployment bundle is not initialized"))?
            .inbox_http_endpoint
            .trim_end_matches('/')
            .to_string();
        let request_id = self.next_request_id("relationship-remove");
        self.state.pending_requests.insert(
            request_id.clone(),
            PendingRequest::RemoveRelationship {
                relationship_id: relationship_id.to_string(),
            },
        );
        let body = RemoveRelationshipRequest {
            version: crate::model::ENVELOPE_VERSION_V2.into(),
            relationship_id: relationship_id.to_string(),
            generation,
        };
        Ok(CoreOutput {
            effects: vec![CoreEffect::ExecuteHttpRequest {
                request: HttpRequestEffect {
                    request_id,
                    method: HttpMethod::Post,
                    url: format!(
                        "{endpoint}/v2/device-registry/relationships/{}/remove",
                        urlencoding::encode(relationship_id)
                    ),
                    headers: BTreeMap::from([("Content-Type".into(), "application/json".into())]),
                    auth: Some(self.device_runtime_auth_requirement()?),
                    body: Some(serde_json::to_string(&body).map_err(|error| {
                        CoreError::invalid_input(format!(
                            "failed to encode relationship removal: {error}"
                        ))
                    })?),
                },
            }],
            ..CoreOutput::default()
        })
    }

    pub(super) fn contact_accepted_conversation_ids(
        &self,
        peer_user_id: &str,
        promoted_conversation_ids: &[String],
    ) -> CoreResult<Vec<String>> {
        const MAX_ACCEPTED_CONVERSATION_IDS: usize = 16;
        let mut conversation_ids = promoted_conversation_ids
            .iter()
            .filter(|conversation_id| !conversation_id.trim().is_empty())
            .cloned()
            .collect::<Vec<_>>();
        conversation_ids.sort();
        conversation_ids.dedup();
        if let Some((conversation_id, _)) = self.active_direct_conversation_for_peer(peer_user_id) {
            if !conversation_ids.contains(&conversation_id) {
                conversation_ids.insert(0, conversation_id);
            }
        }
        if conversation_ids.len() > MAX_ACCEPTED_CONVERSATION_IDS {
            log::warn!(
                "contact accept completed for {} with too many promoted direct conversation ids; truncating the compatibility fanout",
                redact_id("user", peer_user_id)
            );
            conversation_ids.truncate(MAX_ACCEPTED_CONVERSATION_IDS);
        }
        Ok(conversation_ids)
    }

    pub(super) fn build_contact_accepted_envelopes(
        &mut self,
        peer_user_id: &str,
        request_id: &str,
        promoted_conversation_ids: &[String],
        created_at: u64,
    ) -> CoreResult<Vec<Envelope>> {
        let Some(contact) = self.state.contacts.get(peer_user_id) else {
            return Ok(Vec::new());
        };
        let peer_device_ids = contact
            .bundle
            .devices
            .iter()
            .filter(|device| matches!(device.status, DeviceStatusKind::Active))
            .map(|device| device.device_id.clone())
            .collect::<Vec<_>>();
        if peer_device_ids.is_empty() {
            return Ok(Vec::new());
        }
        let local_user_id = self.local_identity_user_id()?;
        let conversation_ids =
            self.contact_accepted_conversation_ids(peer_user_id, promoted_conversation_ids)?;
        let mut envelopes = Vec::new();
        for conversation_id in conversation_ids {
            let payload = ContactAcceptedControl {
                version: crate::model::CURRENT_MODEL_VERSION.to_string(),
                conversation_id: conversation_id.clone(),
                actor_user_id: local_user_id.clone(),
                accepted_user_id: peer_user_id.to_string(),
                request_id: request_id.to_string(),
                created_at,
            };
            let payload_b64 = STANDARD.encode(serde_json::to_vec(&payload).map_err(|error| {
                CoreError::invalid_input(format!(
                    "failed to encode contact accepted control: {error}"
                ))
            })?);
            for device_id in &peer_device_ids {
                envelopes.push(self.build_envelope(
                    &conversation_id,
                    device_id,
                    MessageType::ControlContactAccepted,
                    payload_b64.clone(),
                )?);
            }
        }
        Ok(envelopes)
    }

    pub(super) fn direct_relationship_open_for_record(
        &self,
        peer_user_id: &str,
        conversation_id: &str,
    ) -> bool {
        self.state
            .conversations
            .get(conversation_id)
            .is_some_and(|conversation| {
                conversation.conversation.kind == ConversationKind::Direct
                    && conversation.peer_user_id == peer_user_id
                    && !matches!(
                        conversation.conversation.state,
                        ConversationState::Archived
                            | ConversationState::Closed
                            | ConversationState::Dissolved
                    )
            })
    }

    pub(super) fn promote_pending_outbound_contact(
        &mut self,
        peer_user_id: &str,
        reason: &str,
    ) -> CoreResult<CoreOutput> {
        let Some(contact) = self.state.contacts.get(peer_user_id) else {
            return Ok(CoreOutput::default());
        };
        if !Self::relationship_can_promote_from_peer_accept(&contact.relationship_status) {
            return Ok(CoreOutput::default());
        }
        if !self.set_contact_relationship_status(peer_user_id, ContactRelationshipStatus::Available)
        {
            return Ok(CoreOutput::default());
        }
        log::info!(
            "contact relationship promoted to available peer_user_id={} reason={}",
            peer_user_id,
            reason
        );
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(
                &self.state,
                vec![PersistOp::SaveContact {
                    user_id: peer_user_id.to_string(),
                }],
            )],
            view_model: Some(CoreViewModel {
                contacts: self.contact_summaries(),
                ..CoreViewModel::default()
            }),
        })
    }

    pub(super) fn should_ignore_closed_relationship_record(
        &self,
        local_user_id: &str,
        record: &InboxRecord,
    ) -> bool {
        if record.envelope.message_type == MessageType::ControlContactRemoved {
            return false;
        }
        let peer_user_id = record.envelope.sender_user_id.as_str();
        if peer_user_id == local_user_id {
            return false;
        }
        let contact_removed = self
            .state
            .contacts
            .get(peer_user_id)
            .is_some_and(|contact| Self::relationship_is_removed(&contact.relationship_status));
        let conversation_closed = self
            .state
            .conversations
            .get(&record.envelope.conversation_id)
            .is_some_and(|conversation| {
                matches!(
                    conversation.conversation.state,
                    ConversationState::Closed | ConversationState::Archived
                )
            });
        contact_removed || conversation_closed
    }

    pub(super) fn should_ignore_idempotent_contact_removed_record(
        &self,
        local_user_id: &str,
        record: &InboxRecord,
    ) -> bool {
        if record.envelope.message_type != MessageType::ControlContactRemoved {
            return false;
        }
        let peer_user_id = record.envelope.sender_user_id.as_str();
        if peer_user_id == local_user_id || self.state.contacts.contains_key(peer_user_id) {
            return false;
        }
        self.state
            .conversations
            .get(&record.envelope.conversation_id)
            .map(|conversation| {
                conversation.conversation.kind == ConversationKind::Direct
                    && conversation.peer_user_id == peer_user_id
                    && matches!(
                        conversation.conversation.state,
                        ConversationState::Closed | ConversationState::Archived
                    )
            })
            .unwrap_or(true)
    }

    pub(super) fn should_ignore_contact_accepted_record(
        &self,
        local_user_id: &str,
        record: &InboxRecord,
    ) -> bool {
        if record.envelope.message_type != MessageType::ControlContactAccepted {
            return false;
        }
        let peer_user_id = record.envelope.sender_user_id.as_str();
        if peer_user_id == local_user_id {
            return true;
        }
        let Some(contact) = self.state.contacts.get(peer_user_id) else {
            return true;
        };
        if Self::relationship_is_removed(&contact.relationship_status) {
            return true;
        }
        false
    }

    pub(super) fn ensure_archived_direct_conversation_for_control(
        &mut self,
        conversation_id: &str,
        peer_user_id: &str,
        local_user_id: &str,
        local_device_id: &str,
    ) -> CoreResult<bool> {
        if self.state.conversations.contains_key(conversation_id) {
            return Ok(false);
        }
        let peer_device_ids = self
            .state
            .contacts
            .get(peer_user_id)
            .ok_or_else(|| CoreError::invalid_input("peer contact is missing"))?
            .bundle
            .devices
            .iter()
            .filter(|device| matches!(device.status, DeviceStatusKind::Active))
            .map(|device| device.device_id.clone())
            .collect::<Vec<_>>();
        if peer_device_ids.is_empty() {
            return Err(CoreError::invalid_input(
                "peer identity bundle does not contain any active devices",
            ));
        }
        let mut conversation = ConversationManager::create_direct_conversation_with_id(
            conversation_id.to_string(),
            local_user_id,
            local_device_id,
            peer_user_id,
            &peer_device_ids,
        )?;
        conversation.conversation.state = ConversationState::Archived;
        self.state
            .conversations
            .insert(conversation_id.to_string(), conversation);
        Ok(true)
    }

    pub(super) fn handle_contact_removed_record(
        &mut self,
        local_user_id: &str,
        local_device_id: &str,
        record: &InboxRecord,
    ) -> CoreResult<CoreOutput> {
        let envelope = &record.envelope;
        let payload_b64 = envelope.inline_ciphertext.as_deref().ok_or_else(|| {
            CoreError::invalid_input("contact removed control is missing payload")
        })?;
        if record.envelope_v2.is_none() {
            self.verify_device_signature(
                &envelope.sender_user_id,
                &envelope.sender_device_id,
                payload_b64.as_bytes(),
                &envelope.sender_proof.value,
            )?;
        }
        let payload = STANDARD.decode(payload_b64).map_err(|error| {
            CoreError::invalid_input(format!("failed to decode contact removed control: {error}"))
        })?;
        let control: ContactRemovedControl = serde_json::from_slice(&payload).map_err(|error| {
            CoreError::invalid_input(format!("failed to parse contact removed control: {error}"))
        })?;
        if control.conversation_id != envelope.conversation_id {
            return Err(CoreError::invalid_input(
                "contact removed control conversation_id mismatch",
            ));
        }
        if control.actor_user_id != envelope.sender_user_id {
            return Err(CoreError::invalid_input(
                "contact removed control actor_user_id mismatch",
            ));
        }
        if control.removed_user_id != local_user_id {
            return Err(CoreError::invalid_input(
                "contact removed control is not addressed to local user",
            ));
        }

        let peer_user_id = envelope.sender_user_id.clone();
        if !self.state.contacts.contains_key(&peer_user_id) {
            return Err(CoreError::invalid_input("peer contact is missing"));
        }

        let peer_label = self.contact_label(&peer_user_id);
        let created_conversation = self.ensure_archived_direct_conversation_for_control(
            &envelope.conversation_id,
            &peer_user_id,
            local_user_id,
            local_device_id,
        )?;
        let system_message = StoredMessage {
            message_id: envelope.message_id.clone(),
            app_message_id: None,
            mls_ciphertext_sha256: None,
            sender_user_id: Some(peer_user_id.clone()),
            sender_device_id: envelope.sender_device_id.clone(),
            recipient_device_id: envelope.recipient_device_id.clone(),
            message_type: MessageType::ControlContactRemoved,
            created_at: envelope.created_at,
            plaintext: Some(format!("{peer_label} removed you. This chat was archived.")),
            storage_refs: Vec::new(),
            delivery_state: None,
            message_request_id: None,
        };
        let message_summary = self.archive_conversation_with_message(
            &envelope.conversation_id,
            system_message,
            "removed_by_peer",
        );
        self.state.contacts.remove(&peer_user_id);
        let relationship = record.envelope_v2.as_ref().and_then(|envelope_v2| {
            self.state
                .relationships
                .get(&envelope_v2.relationship_id)
                .cloned()
        });
        if let Some(relationship) = &relationship {
            if let Some(stored) = self
                .state
                .relationships
                .get_mut(&relationship.relationship_id)
            {
                stored.account_state = RelationshipAccountState::Removed;
                stored.version = stored.version.saturating_add(1);
                stored.updated_at = envelope.created_at;
            }
        }
        let mut persist_ops = vec![PersistOp::DeleteContact {
            user_id: peer_user_id.clone(),
        }];
        if relationship.is_some() {
            persist_ops.push(PersistOp::SaveDeployment);
        }
        persist_ops.extend(self.clear_direct_runtime_state(&envelope.conversation_id)?);
        persist_ops.push(PersistOp::SaveConversation {
            conversation_id: envelope.conversation_id.clone(),
        });

        let mut output = CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                conversations_changed: true,
                messages_changed: message_summary.is_some(),
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(&self.state, persist_ops)],
            view_model: Some(CoreViewModel {
                contacts: self.contact_summaries(),
                messages: message_summary.into_iter().collect(),
                ..CoreViewModel::default()
            }),
        };
        if let Some(relationship) = relationship {
            output = merge_outputs(
                output,
                self.remove_relationship_from_registry(
                    &relationship.relationship_id,
                    relationship.generation,
                )?,
            );
        }
        if created_conversation {
            log::info!(
                "handle_contact_removed_record: created archived direct conversation shell {}",
                envelope.conversation_id
            );
        }
        Ok(output)
    }

    pub(super) fn handle_contact_accepted_record(
        &mut self,
        local_user_id: &str,
        record: &InboxRecord,
    ) -> CoreResult<CoreOutput> {
        let envelope = &record.envelope;
        if self.should_ignore_contact_accepted_record(local_user_id, record) {
            log::info!(
                "handle_contact_accepted_record: acking and ignoring ControlContactAccepted for non-open relationship conversation_id={} sender_user_id={} message_id={}",
                envelope.conversation_id,
                envelope.sender_user_id,
                record.message_id
            );
            return Ok(CoreOutput::default());
        }

        let payload_b64 = envelope.inline_ciphertext.as_deref().ok_or_else(|| {
            CoreError::invalid_input("contact accepted control is missing payload")
        })?;
        self.verify_device_signature(
            &envelope.sender_user_id,
            &envelope.sender_device_id,
            payload_b64.as_bytes(),
            &envelope.sender_proof.value,
        )?;
        let payload = STANDARD.decode(payload_b64).map_err(|error| {
            CoreError::invalid_input(format!(
                "failed to decode contact accepted control: {error}"
            ))
        })?;
        let control: ContactAcceptedControl =
            serde_json::from_slice(&payload).map_err(|error| {
                CoreError::invalid_input(format!(
                    "failed to parse contact accepted control: {error}"
                ))
            })?;
        if control.conversation_id != envelope.conversation_id {
            return Err(CoreError::invalid_input(
                "contact accepted control conversation_id mismatch",
            ));
        }
        if control.actor_user_id != envelope.sender_user_id {
            return Err(CoreError::invalid_input(
                "contact accepted control actor_user_id mismatch",
            ));
        }
        if control.accepted_user_id != local_user_id {
            return Err(CoreError::invalid_input(
                "contact accepted control is not addressed to local user",
            ));
        }
        if control.request_id.trim().is_empty() {
            return Err(CoreError::invalid_input(
                "contact accepted control request_id is empty",
            ));
        }
        let exact_conversation_is_open = self.direct_relationship_open_for_record(
            &envelope.sender_user_id,
            &envelope.conversation_id,
        );
        let request_matches_local_message = self.state.conversations.values().any(|conversation| {
            conversation.conversation.kind == ConversationKind::Direct
                && conversation.peer_user_id == envelope.sender_user_id
                && conversation.messages.iter().any(|message| {
                    message.message_request_id.as_deref() == Some(control.request_id.as_str())
                })
        });
        if !exact_conversation_is_open && !request_matches_local_message {
            log::info!(
                "handle_contact_accepted_record: acking and ignoring unmatched accepted control conversation_id={} sender_user_id={} message_id={}",
                envelope.conversation_id,
                envelope.sender_user_id,
                record.message_id
            );
            return Ok(CoreOutput::default());
        }

        let mut output = self.promote_pending_outbound_contact(
            &envelope.sender_user_id,
            "contact_accepted_control",
        )?;
        let mut changed_conversations = Vec::new();
        for (conversation_id, conversation) in &mut self.state.conversations {
            if conversation.conversation.kind != ConversationKind::Direct
                || conversation.peer_user_id != envelope.sender_user_id
            {
                continue;
            }
            let mut changed = false;
            for message in &mut conversation.messages {
                if message.message_request_id.as_deref() == Some(control.request_id.as_str())
                    && message.delivery_state
                        == Some(crate::conversation::StoredMessageDeliveryState::PendingApproval)
                {
                    message.delivery_state =
                        Some(crate::conversation::StoredMessageDeliveryState::Sent);
                    changed = true;
                }
            }
            if changed {
                changed_conversations.push(conversation_id.clone());
            }
        }
        if !changed_conversations.is_empty() {
            output = merge_outputs(
                output,
                CoreOutput {
                    state_update: CoreStateUpdate {
                        messages_changed: true,
                        conversations_changed: true,
                        ..CoreStateUpdate::default()
                    },
                    effects: vec![persist_effect(
                        &self.state,
                        changed_conversations
                            .into_iter()
                            .map(|conversation_id| PersistOp::SaveConversation { conversation_id })
                            .collect(),
                    )],
                    view_model: None,
                },
            );
        }
        Ok(output)
    }

    pub(super) fn delete_contact(&mut self, user_id: String) -> CoreResult<CoreOutput> {
        if !self.state.contacts.contains_key(&user_id) {
            return Err(CoreError::invalid_input("contact does not exist"));
        }

        let local_user_id = self.local_identity_user_id()?;
        let local_device_id = self.local_identity_device_id()?;
        let peer_label = self.contact_label(&user_id);
        let mut conversation_ids = self.direct_conversations_for_peer(&user_id);
        conversation_ids.extend(
            self.state
                .pending_outbox
                .iter()
                .filter(|item| item.peer_user_id == user_id)
                .map(|item| item.envelope.conversation_id.clone()),
        );
        conversation_ids.sort();
        conversation_ids.dedup();
        let relationship = self
            .state
            .relationships
            .values()
            .filter(|relationship| {
                relationship.peer_user_id == user_id
                    && relationship.setup_state != RelationshipSetupState::Superseded
            })
            .max_by_key(|relationship| relationship.generation)
            .cloned();
        let control_conversation_id = relationship
            .as_ref()
            .map(|relationship| {
                format!(
                    "conv:direct:v2:{}:g{}",
                    relationship.relationship_id, relationship.generation
                )
            })
            .or_else(|| conversation_ids.first().cloned())
            .unwrap_or_else(|| direct_conversation_id(&local_user_id, &user_id));
        let control_created_at = current_unix_millis(self.next_message_nonce());
        let control_envelopes = if let Some(relationship) = &relationship {
            self.build_contact_removed_envelopes_v2(
                &user_id,
                &relationship.relationship_id,
                control_created_at,
            )?
        } else {
            Vec::new()
        };
        let control_message_ids = control_envelopes
            .iter()
            .map(|envelope| envelope.message_id.clone())
            .collect::<Vec<_>>();

        let mut persist_ops: Vec<PersistOp> = Vec::new();
        let mut message_summaries = Vec::new();
        for conversation_id in &conversation_ids {
            let system_message = self.next_system_message(
                conversation_id,
                MessageType::ControlContactRemoved,
                Some(local_user_id.clone()),
                local_device_id.clone(),
                user_id.clone(),
                format!("You removed {peer_label}. This chat was archived."),
                "contact_removed_by_me",
            );
            if let Some(summary) = self.archive_conversation_with_message(
                conversation_id,
                system_message,
                "removed_by_me",
            ) {
                message_summaries.push(summary);
            }
            persist_ops.extend(self.clear_direct_runtime_state(conversation_id)?);
            if self.state.conversations.contains_key(conversation_id) {
                persist_ops.push(PersistOp::SaveConversation {
                    conversation_id: conversation_id.clone(),
                });
            }
        }
        if conversation_ids.is_empty() {
            persist_ops.extend(self.clear_direct_runtime_state(&control_conversation_id)?);
        }

        self.enqueue_envelopes_v2(user_id.clone(), control_envelopes.clone());
        persist_ops.extend(
            control_message_ids
                .into_iter()
                .map(|message_id| PersistOp::SaveOutgoingEnvelope { message_id }),
        );

        if let Some(relationship) = relationship.as_ref() {
            if let Some(stored) = self
                .state
                .relationships
                .get_mut(&relationship.relationship_id)
            {
                stored.account_state = RelationshipAccountState::Removed;
                stored.version = stored.version.saturating_add(1);
                stored.updated_at = control_created_at;
                persist_ops.push(PersistOp::SaveDeployment);
            }
        }

        let transport_output = if control_envelopes.is_empty() {
            CoreOutput::default()
        } else {
            self.flush_pending_transport()?
        };

        self.state.contacts.remove(&user_id);
        persist_ops.push(PersistOp::DeleteContact {
            user_id: user_id.clone(),
        });

        let mut output = CoreOutput {
            state_update: CoreStateUpdate {
                contacts_changed: true,
                conversations_changed: !conversation_ids.is_empty(),
                messages_changed: !message_summaries.is_empty(),
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(&self.state, persist_ops)],
            view_model: Some(CoreViewModel {
                contacts: self.contact_summaries(),
                messages: message_summaries,
                ..CoreViewModel::default()
            }),
        };
        if let Some(relationship) = relationship {
            output = merge_outputs(
                output,
                self.remove_relationship_from_registry(
                    &relationship.relationship_id,
                    relationship.generation,
                )?,
            );
        }
        Ok(merge_outputs(output, transport_output))
    }

    pub(super) fn build_control_membership_changed_messages(
        &mut self,
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

    pub(super) fn direct_relationship_id_for_conversation(
        &self,
        conversation_id: &str,
    ) -> CoreResult<String> {
        self.state
            .relationships
            .values()
            .find(|relationship| {
                format!(
                    "conv:direct:v2:{}:g{}",
                    relationship.relationship_id, relationship.generation
                ) == conversation_id
                    && relationship.setup_state != RelationshipSetupState::Superseded
            })
            .map(|relationship| relationship.relationship_id.clone())
            .ok_or_else(|| {
                CoreError::new(
                    "protocol_upgrade_required",
                    "Direct MLS recovery requires an account-level V2 relationship",
                )
            })
    }

    pub(super) fn commit_envelopes_v2_for_artifacts(
        &mut self,
        relationship_id: &str,
        peer_user_id: &str,
        peer_active_device_ids: &[String],
        artifacts: &CreateConversationArtifacts,
    ) -> CoreResult<Vec<crate::model::EnvelopeV2>> {
        peer_active_device_ids
            .iter()
            .map(|device_id| {
                self.build_envelope_v2(
                    relationship_id,
                    peer_user_id,
                    device_id,
                    MessageType::MlsCommit,
                    artifacts.commit_b64.clone(),
                    None,
                )
            })
            .collect()
    }

    pub(super) fn welcome_envelopes_v2_for_artifacts(
        &mut self,
        relationship_id: &str,
        peer_user_id: &str,
        artifacts: &CreateConversationArtifacts,
        claim_ids_by_device: &BTreeMap<String, String>,
    ) -> CoreResult<Vec<crate::model::EnvelopeV2>> {
        artifacts
            .welcomes
            .iter()
            .map(|welcome| {
                let claim_id = claim_ids_by_device
                    .get(&welcome.recipient_device_id)
                    .cloned()
                    .ok_or_else(|| {
                        CoreError::invalid_state(
                            "MLS Welcome is missing its one-time KeyPackage claim ID",
                        )
                    })?;
                self.build_envelope_v2(
                    relationship_id,
                    peer_user_id,
                    &welcome.recipient_device_id,
                    MessageType::MlsWelcome,
                    welcome.payload_b64.clone(),
                    Some(claim_id),
                )
            })
            .collect()
    }

    pub(super) fn commit_envelopes_v2_for_remove(
        &mut self,
        relationship_id: &str,
        peer_user_id: &str,
        peer_active_device_ids: &[String],
        artifacts: &RemoveMembersArtifacts,
    ) -> CoreResult<Vec<crate::model::EnvelopeV2>> {
        peer_active_device_ids
            .iter()
            .map(|device_id| {
                self.build_envelope_v2(
                    relationship_id,
                    peer_user_id,
                    device_id,
                    MessageType::MlsCommit,
                    artifacts.commit_b64.clone(),
                    None,
                )
            })
            .collect()
    }

    pub(super) fn build_control_membership_changed_messages_v2(
        &mut self,
        relationship_id: &str,
        peer_user_id: &str,
        peer_active_device_ids: &[String],
    ) -> CoreResult<Vec<crate::model::EnvelopeV2>> {
        let payload = STANDARD.encode(format!(
            "membership_changed:{}:{}:{}",
            relationship_id,
            peer_user_id,
            peer_active_device_ids.len()
        ));
        peer_active_device_ids
            .iter()
            .map(|device_id| {
                self.build_envelope_v2(
                    relationship_id,
                    peer_user_id,
                    device_id,
                    MessageType::ControlDeviceMembershipChanged,
                    payload.clone(),
                    None,
                )
            })
            .collect()
    }

    pub(super) fn commit_envelopes_for_artifacts(
        &mut self,
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

    pub(super) fn welcome_envelopes_for_artifacts(
        &mut self,
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

    pub(super) fn commit_envelopes_for_remove(
        &mut self,
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

    pub(super) fn next_message_id(
        &self,
        conversation_id: &str,
        suffix: &str,
        message_nonce: u64,
    ) -> String {
        format!("msg:{conversation_id}:{message_nonce}:{suffix}")
    }

    pub(super) fn next_app_message_id(
        &self,
        conversation_id: &str,
        sender_device_id: &str,
        message_nonce: u64,
    ) -> String {
        format!("app:{conversation_id}:{message_nonce}:{sender_device_id}")
    }
}

use super::*;

enum DirectPcsRosterCheck {
    Allowed,
    Ignore,
    Rebuild(&'static str),
}

enum DirectPcsApplyOutcome {
    Applied(CoreOutput),
    Skipped(CoreOutput),
}

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

        let existing = self.state.contacts.get(&user_id);
        let existing_display_name = existing.and_then(|c| c.display_name.clone());
        let existing_relationship_status = existing.map(|c| c.relationship_status.clone());
        let existing_verified_at = existing.and_then(|c| c.verified_at);
        let existing_verified_root_key = existing.and_then(|c| c.verified_root_key.clone());
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

        let mut persisted_contact = PersistedContact {
            user_id: user_id.clone(),
            bundle,
            display_name: existing_display_name,
            original_name,
            relationship_status,
            added_at: now,
            verified_at: existing_verified_at,
            verified_root_key: existing_verified_root_key,
        };
        persisted_contact.align_verification();

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
        let verified_at = existing.and_then(|c| c.verified_at);
        let verified_root_key = existing.and_then(|c| c.verified_root_key.clone());

        let mut persisted_contact = PersistedContact {
            user_id: user_id.clone(),
            bundle,
            display_name,
            original_name,
            relationship_status,
            added_at,
            verified_at,
            verified_root_key,
        };
        persisted_contact.align_verification();

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
        let (adapter, package) = crate::mls_adapter::MlsAdapter::bootstrap(&identity)?;
        let user_id = identity.user_identity.user_id.clone();
        let device_id = identity.device_identity.device_id.clone();
        self.state.local_identity = Some(identity);
        self.state.mls_adapter = Some(adapter);
        self.state.key_package_inventory.clear();
        self.install_published_key_package(
            package,
            crate::mls_adapter::PublishedKeyPackageState::Retired,
        );
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
        let (adapter, package) = crate::mls_adapter::MlsAdapter::bootstrap(&identity)?;
        let user_id = identity.user_identity.user_id.clone();
        let device_id = identity.device_identity.device_id.clone();
        self.state.local_identity = Some(identity);
        self.state.mls_adapter = Some(adapter);
        self.state.key_package_inventory.clear();
        self.install_published_key_package(
            package,
            crate::mls_adapter::PublishedKeyPackageState::Retired,
        );
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
        if self.state.pending_identity_publication.is_some() {
            return Err(CoreError::new(
                "keypackage_refresh_pending",
                "an identity publication is already awaiting confirmation",
            ));
        }
        let now_ms = current_unix_millis(self.state.message_nonce);
        self.stage_local_key_package_rotation(now_ms, false)
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
        let key_package_due = self
            .state
            .published_key_package
            .as_ref()
            .map(|package| package.should_rotate_at(now_ms, device_id))
            .unwrap_or(true);
        key_package_due || self.local_inbox_capability_due(now_ms, device_id)
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
        let key_package_due = self
            .state
            .published_key_package
            .as_ref()
            .map(|package| package.should_rotate_at(now_ms, &device_id))
            .unwrap_or(true);
        if key_package_due {
            return self.stage_local_key_package_rotation(now_ms, true);
        }
        if self.local_inbox_capability_due(now_ms, &device_id) {
            return self.stage_local_inbox_capability_renewal(now_ms, true);
        }
        {
            // Best-effort top-up check for the one-time KeyPackage pool,
            // right after the existing last-resort rotation check. This is
            // background maintenance: failures here (see
            // `handle_key_package_pool_count`/the ReplenishKeyPackagePool
            // arms in transport.rs) are never surfaced to the user.
            let pool_check = self.key_package_pool_count_check_effect()?;
            return Ok(CoreOutput {
                effects: vec![pool_check, timer],
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

    /// Rotates the last-resort KeyPackage after an inbound Welcome — but
    /// only when that Welcome actually consumed the currently-advertised
    /// last-resort KeyPackage. A Welcome built from a claimed one-time pool
    /// entry must not trigger this: the pool entry was already atomically
    /// removed server-side on claim, and the periodic maintenance timer
    /// (not this reactive path) is what notices a shrinking pool and tops
    /// it back up.
    pub(super) fn rotate_local_key_package_after_welcome(
        &mut self,
        welcome_payload_b64: &str,
    ) -> CoreResult<Vec<CoreEffect>> {
        let Some(published) = self.state.published_key_package.clone() else {
            return Ok(Vec::new());
        };
        let targets_last_resort = self
            .state
            .mls_adapter
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .welcome_targets_key_package(welcome_payload_b64, &published.key_package_b64)
            .unwrap_or(false);
        if !targets_last_resort {
            return Ok(Vec::new());
        }
        let now_ms = current_unix_millis(self.state.message_nonce);
        let pending = self.state.pending_identity_publication.clone();
        let confirmed_bundle = self.state.local_bundle.clone();
        if let Some(pending) = pending.as_ref() {
            // A delayed Welcome may arrive while another identity publication is
            // awaiting confirmation. Build on that candidate so the consumed
            // KeyPackage replacement cannot overwrite a pending share-id or
            // capability change, while keeping the confirmed bundle visible
            // locally until the server acknowledges the combined candidate.
            self.state.local_bundle = Some(pending.candidate_bundle.clone());
        }
        let package = self
            .state
            .mls_adapter
            .as_mut()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .rotate_key_package(now_ms)?;
        self.install_published_key_package(
            package,
            crate::mls_adapter::PublishedKeyPackageState::Consumed,
        );
        let updated_at = {
            let identity = self
                .state
                .local_identity
                .as_mut()
                .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?;
            let candidate_revision = pending
                .as_ref()
                .map(|publication| publication.candidate_bundle.publication_revision)
                .unwrap_or_default();
            identity.device_status.updated_at = identity
                .device_status
                .updated_at
                .max(candidate_revision)
                .saturating_add(1);
            identity.device_status.updated_at
        };
        self.refresh_local_bundle_with_updated_at_at(updated_at, now_ms)?;
        let candidate_bundle =
            self.state.local_bundle.clone().ok_or_else(|| {
                CoreError::invalid_state("candidate identity bundle is unavailable")
            })?;

        let (operation_id, expected_etag) = if let Some(mut pending) = pending {
            let operation_id = pending.operation_id.clone();
            let expected_etag = pending.expected_etag.clone();
            pending.candidate_bundle = candidate_bundle.clone();
            pending.stage = crate::persistence::PendingIdentityPublicationStage::AwaitingPublish;
            pending.next_retry_at = now_ms;
            self.state.pending_identity_publication = Some(pending);
            self.state.local_bundle = confirmed_bundle;
            (operation_id, expected_etag)
        } else if candidate_bundle.identity_bundle_ref.is_some() {
            let operation_id = format!(
                "credential_maintenance:{}",
                candidate_bundle.publication_revision
            );
            if let Some(previous_bundle) = confirmed_bundle {
                self.state.local_bundle = Some(previous_bundle.clone());
                self.state.pending_identity_publication =
                    Some(crate::persistence::PendingIdentityPublication {
                        operation_id: operation_id.clone(),
                        reason: "keypackage_rotation_after_welcome".into(),
                        previous_bundle,
                        candidate_bundle: candidate_bundle.clone(),
                        expected_etag: None,
                        stage: crate::persistence::PendingIdentityPublicationStage::AwaitingPublish,
                        attempt_count: 0,
                        next_retry_at: now_ms,
                    });
            }
            (operation_id, None)
        } else {
            (String::new(), None)
        };
        let mut effects = vec![persist_effect(
            &self.state,
            vec![PersistOp::SaveLocalIdentity, PersistOp::SaveDeployment],
        )];
        if candidate_bundle.identity_bundle_ref.is_some() {
            effects.push(self.identity_bundle_publish_effect(
                &candidate_bundle,
                operation_id,
                expected_etag.as_deref(),
            )?);
        }
        Ok(effects)
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
        let now_ms = current_unix_millis(self.state.message_nonce);
        let peer_device_ids: Vec<String> = contact_bundle
            .devices
            .iter()
            .filter(|device| {
                matches!(device.status, crate::model::DeviceStatusKind::Active)
                    && device
                        .keypackage_ref
                        .as_ref()
                        .is_some_and(|keypackage_ref| keypackage_ref.is_usable_at(now_ms))
            })
            .map(|d| d.device_id.clone())
            .collect();
        if peer_device_ids.is_empty()
            && self
                .active_direct_conversation_for_peer(&peer_user_id)
                .is_none()
        {
            if contact_bundle.devices.iter().any(|device| {
                matches!(device.status, crate::model::DeviceStatusKind::Active)
                    && device.keypackage_ref.as_ref().is_some_and(|keypackage| {
                        keypackage.created_at
                            > now_ms
                                .saturating_add(crate::mls_adapter::KEY_PACKAGE_CLOCK_TOLERANCE_MS)
                    })
            }) {
                return Err(CoreError::new(
                    "device_clock_invalid",
                    "contact key package was created too far in the future",
                ));
            }
            return Err(CoreError::new(
                "keypackage_expired",
                "peer identity bundle does not contain a usable key package",
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
                        conversation_id,
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
                        pcs_degraded: None,
                    }],
                    ..CoreViewModel::default()
                }),
            });
        }

        let conversation_id = self.new_direct_relationship_conversation_id(
            &local_identity.user_identity.user_id,
            &peer_user_id,
        );
        // The actual MLS `create_conversation` call (and everything that
        // depends on its artifacts: persistence, envelope generation, view
        // model) is deferred to `finalize_direct_conversation_creation`,
        // which runs once every target device's one-time KeyPackage has
        // been claimed from its owner's runtime (falling back to the
        // cached last-resort KeyPackage on `pool_empty`). Claims are
        // strictly sequential, one device in flight at a time.
        let remaining_devices: std::collections::VecDeque<(String, String)> = peer_device_ids
            .iter()
            .map(|device_id| (peer_user_id.clone(), device_id.clone()))
            .collect();
        self.start_key_package_claim_batch(
            KeyPackageClaimBatchKind::Direct {
                peer_user_id: peer_user_id.clone(),
                conversation_id,
                peer_device_ids,
            },
            remaining_devices,
        )
    }

    pub(super) fn finalize_direct_conversation_creation(
        &mut self,
        peer_user_id: String,
        conversation_id: String,
        peer_device_ids: Vec<String>,
        peer_keypackages: Vec<PeerDeviceKeyPackage>,
    ) -> CoreResult<CoreOutput> {
        let local_identity = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .clone();
        let local_conversation = ConversationManager::create_direct_conversation_with_id(
            conversation_id.clone(),
            &local_identity.user_identity.user_id,
            &local_identity.device_identity.device_id,
            &peer_user_id,
            &peer_device_ids,
        )?;
        let artifacts = self
            .state
            .mls_adapter
            .as_mut()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .create_conversation(&conversation_id, &peer_keypackages)?;
        let summary = self
            .state
            .mls_adapter
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("mls adapter missing after create"))?
            .export_group_summary(&conversation_id)?;
        self.state
            .mls_summaries
            .insert(conversation_id.clone(), summary);
        self.state
            .conversations
            .insert(conversation_id.clone(), local_conversation);
        self.initialize_direct_pcs_from_mls(&conversation_id)?;

        let mut generated = Vec::new();
        for device_id in &peer_device_ids {
            generated.push(self.build_envelope(
                &conversation_id,
                device_id,
                MessageType::MlsCommit,
                artifacts.commit_b64.clone(),
            )?);
        }
        for welcome in &artifacts.welcomes {
            generated.push(self.build_envelope(
                &conversation_id,
                &welcome.recipient_device_id,
                MessageType::MlsWelcome,
                welcome.payload_b64.clone(),
            )?);
        }
        self.enqueue_envelopes(peer_user_id.clone(), generated.clone());
        let persist_ops = vec![
            PersistOp::SaveConversation {
                conversation_id: conversation_id.clone(),
            },
            PersistOp::SaveMlsState {
                conversation_id: conversation_id.clone(),
            },
        ];
        self.merge_with_transport_flush(CoreOutput {
            state_update: CoreStateUpdate {
                conversations_changed: true,
                messages_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(&self.state, persist_ops)],
            view_model: Some(CoreViewModel {
                conversations: vec![ConversationSummary {
                    conversation_id,
                    peer_user_id: peer_user_id.clone(),
                    state: "active".into(),
                    kind: Some(ConversationKind::Direct),
                    title: None,
                    display_name: self.contact_archive_display_name(&peer_user_id),
                    group_id: None,
                    member_count: None,
                    group_role: None,
                    group_cursor: None,
                    last_message_preview: None,
                    last_message_type: Some(MessageType::MlsCommit),
                    message_count: None,
                    recovery: None,
                    pcs_degraded: None,
                }],
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
        let app_message_nonce = self.next_message_nonce();
        let app_message_id =
            self.next_app_message_id(&conversation_id, &sender_device_id, app_message_nonce);
        let last_certified_commit_hash = self
            .state
            .conversations
            .get(&conversation_id)
            .and_then(|state| state.pcs.last_certified_commit_hash.clone())
            .ok_or_else(|| {
                CoreError::invalid_state("direct conversation is missing a certified commit hash")
            })?;
        let protected_message = ProtectedAppMessage::new_text(
            app_message_id.clone(),
            conversation_id.clone(),
            sender_user_id,
            sender_device_id,
            peer_user_id.clone(),
            recipient_device_ids.clone(),
            plaintext.clone(),
            last_certified_commit_hash,
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
                self.build_envelope(
                    &conversation_id,
                    device_id,
                    MessageType::MlsApplication,
                    payload.payload_b64.clone(),
                )
            })
            .collect::<CoreResult<Vec<_>>>()?;
        // Cache plaintext for display until message is synced
        self.enqueue_envelopes_with_plaintext(
            peer_user_id.clone(),
            envelopes.clone(),
            plaintext.clone(),
            Some(app_message_id.clone()),
        );
        self.observe_direct_application(&conversation_id)?;
        self.enqueue_direct_pcs_protocol(&conversation_id, &peer_user_id)?;
        self.merge_with_transport_flush(CoreOutput {
            state_update: CoreStateUpdate {
                messages_changed: true,
                conversations_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(
                &self.state,
                self.direct_send_persist_ops(&conversation_id),
            )],
            view_model: Some(CoreViewModel {
                // The protected application id is the only user-visible
                // identity. Envelope ids are per-recipient transport details.
                messages: vec![MessageSummary {
                    conversation_id,
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
        let package = self
            .state
            .published_key_package
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("published key package missing"))?;
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
            crate::capability::CapabilityManager::build_device_contact_profile_with_lifetime(
                &signing_identity,
                deployment,
                package.key_package_ref.clone(),
                package.lifecycle_version,
                package.not_before,
                package.created_at,
                package.expires_at,
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
        let package = self
            .state
            .published_key_package
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("published key package missing"))?;
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
        devices.push(
            crate::capability::CapabilityManager::build_device_contact_profile_with_lifetime(
                &signing_identity,
                deployment,
                package.key_package_ref.clone(),
                package.lifecycle_version,
                package.not_before,
                package.created_at,
                package.expires_at,
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
                if state.peer_user_id == peer_user_id
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

    pub(super) fn peer_active_device_ids(&self, peer_user_id: &str) -> CoreResult<Vec<String>> {
        let bundle = self.direct_peer_contact_bundle(peer_user_id)?;
        let now_ms = current_unix_millis(self.state.message_nonce);
        let devices: Vec<String> = bundle
            .devices
            .iter()
            .filter(|device| {
                matches!(device.status, crate::model::DeviceStatusKind::Active)
                    && device
                        .keypackage_ref
                        .as_ref()
                        .is_some_and(|keypackage_ref| keypackage_ref.is_usable_at(now_ms))
            })
            .map(|device| device.device_id.clone())
            .collect();
        if devices.is_empty() {
            return Err(CoreError::new(
                "keypackage_expired",
                "peer identity bundle does not contain a usable key package",
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
                peer_user_id: peer_user_id.clone(),
                retries: 0,
                in_flight: false,
                app_message_id: None,
                plaintext_cache: None,
                identity_refresh_attempted: false,
            });
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
                if let Some(pcs) = self
                    .state
                    .conversations
                    .get(&record.envelope.conversation_id)
                    .map(|state| &state.pcs)
                {
                    let expected = if application.from_previous_epoch {
                        pcs.previous_certified_commit_hash.as_ref()
                    } else {
                        pcs.last_certified_commit_hash.as_ref()
                    };
                    if let Some(expected) = expected {
                        if &protected.last_certified_commit_hash != expected {
                            return ApplicationPlaintextDecision::RejectedProtocol {
                                reason: "protected last_certified_commit_hash does not match decrypted epoch"
                                    .into(),
                            };
                        }
                    }
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
                pcs_degraded: None,
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
            pcs_degraded: conversation.pcs.degraded.then_some(true),
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

    pub(super) fn set_contact_verified(
        &mut self,
        user_id: String,
        verified: bool,
    ) -> CoreResult<CoreOutput> {
        if !self.state.contacts.contains_key(&user_id) {
            return Err(CoreError::invalid_input("contact does not exist"));
        }
        let now = current_unix_millis(self.state.message_nonce);
        if let Some(contact) = self.state.contacts.get_mut(&user_id) {
            contact.set_verified(verified, now);
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
                contacts: self.contact_summaries(),
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
            verified: contact.is_verified(),
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
        self.verify_device_signature(
            &envelope.sender_user_id,
            &envelope.sender_device_id,
            payload_b64.as_bytes(),
            &envelope.sender_proof.value,
        )?;
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
        let mut persist_ops = vec![PersistOp::DeleteContact {
            user_id: peer_user_id.clone(),
        }];
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
        if self.state.deployment_bundle.is_some() {
            output = merge_outputs(output, self.remove_allowlist_user(peer_user_id)?);
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
        let control_conversation_id = conversation_ids
            .first()
            .cloned()
            .unwrap_or_else(|| direct_conversation_id(&local_user_id, &user_id));
        let control_created_at = current_unix_millis(self.next_message_nonce());
        let control_envelopes = self.build_contact_removed_envelopes(
            &user_id,
            &control_conversation_id,
            control_created_at,
        )?;
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

        self.enqueue_envelopes(user_id.clone(), control_envelopes.clone());
        persist_ops.extend(
            control_message_ids
                .into_iter()
                .map(|message_id| PersistOp::SaveOutgoingEnvelope { message_id }),
        );

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
        if self.state.deployment_bundle.is_some() {
            output = merge_outputs(output, self.remove_allowlist_user(user_id)?);
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

    pub(super) fn conversation_is_direct(&self, conversation_id: &str) -> bool {
        self.state
            .conversations
            .get(conversation_id)
            .is_some_and(|state| state.conversation.kind == ConversationKind::Direct)
    }

    /// Called only after locally creating a group or successfully joining a Welcome.
    pub(super) fn initialize_direct_pcs_from_mls(
        &mut self,
        conversation_id: &str,
    ) -> CoreResult<()> {
        if !self.conversation_is_direct(conversation_id) {
            return Ok(());
        }
        let initial_hash = self
            .state
            .mls_adapter
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .direct_pcs_initial_hash(conversation_id)?;
        let state = self
            .state
            .conversations
            .get_mut(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?;
        state.pcs = crate::direct_pcs::DirectPcsState {
            last_certified_commit_hash: Some(initial_hash),
            ..Default::default()
        };
        Ok(())
    }

    pub(super) fn observe_direct_application(&mut self, conversation_id: &str) -> CoreResult<()> {
        if !self.conversation_is_direct(conversation_id) {
            return Ok(());
        }
        if let Some(state) = self.state.conversations.get_mut(conversation_id) {
            state.pcs.note_application_message();
        }
        self.maybe_stage_direct_pcs(conversation_id)
    }

    fn maybe_stage_direct_pcs(&mut self, conversation_id: &str) -> CoreResult<()> {
        let local_device_id = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .device_identity
            .device_id
            .clone();
        let member_device_ids = self
            .state
            .mls_adapter
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .member_device_ids(conversation_id)?;
        let epoch = self
            .state
            .mls_summaries
            .get(conversation_id)
            .map(|summary| summary.epoch)
            .or_else(|| {
                self.state
                    .mls_adapter
                    .as_ref()
                    .and_then(|adapter| adapter.export_group_summary(conversation_id).ok())
                    .map(|summary| summary.epoch)
            })
            .unwrap_or(1);
        let committer = designated_committer(&member_device_ids, epoch)?;
        let should_initiate = self
            .state
            .conversations
            .get(conversation_id)
            .is_some_and(|state| {
                state
                    .pcs
                    .should_initiate_commit(&local_device_id, &committer)
            });
        if !should_initiate {
            return Ok(());
        }
        let parent = self
            .state
            .conversations
            .get(conversation_id)
            .and_then(|state| state.pcs.last_certified_commit_hash.clone())
            .ok_or_else(|| {
                CoreError::invalid_state("direct PCS commit is missing a parent commit hash")
            })?;
        let staged = self
            .state
            .mls_adapter
            .as_mut()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .stage_direct_self_update(conversation_id)?;
        let identity = self
            .state
            .local_identity
            .clone()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?;
        let committer_sig = sign_certificate(
            &identity,
            conversation_id,
            staged.base_epoch,
            &parent,
            &staged.commit_hash,
        );
        let conversation = self
            .state
            .conversations
            .get_mut(conversation_id)
            .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?;
        conversation
            .pcs
            .record_signature(staged.base_epoch, &staged.commit_hash)?;
        conversation.pcs.handshake = Some(DirectPcsHandshake {
            role: DirectPcsRole::Committer,
            epoch: staged.base_epoch,
            commit_hash: staged.commit_hash,
            commit_b64: staged.commit_b64,
            parent_commit_hash: parent,
            committer_device_id: committer,
            acceptor_device_id: None,
            committer_sig: Some(committer_sig),
            acceptor_sig: None,
        });
        Ok(())
    }

    pub(super) fn enqueue_direct_pcs_protocol(
        &mut self,
        conversation_id: &str,
        peer_user_id: &str,
    ) -> CoreResult<()> {
        let handshake = match self
            .state
            .conversations
            .get(conversation_id)
            .and_then(|state| state.pcs.handshake.clone())
        {
            Some(handshake) => handshake,
            None => return Ok(()),
        };
        let recipient_device_ids = self.recipient_device_ids(conversation_id)?;
        match handshake.role {
            DirectPcsRole::Committer => {
                let already_pending = self.state.pending_outbox.iter().any(|item| {
                    item.envelope.conversation_id == conversation_id
                        && item.envelope.message_type == MessageType::MlsCommit
                        && item.envelope.inline_ciphertext.as_deref()
                            == Some(handshake.commit_b64.as_str())
                });
                if already_pending {
                    return Ok(());
                }
                let envelopes = recipient_device_ids
                    .iter()
                    .map(|device_id| {
                        self.build_envelope(
                            conversation_id,
                            device_id,
                            MessageType::MlsCommit,
                            handshake.commit_b64.clone(),
                        )
                    })
                    .collect::<CoreResult<Vec<_>>>()?;
                self.enqueue_envelopes(peer_user_id.to_string(), envelopes);
            }
            DirectPcsRole::Acceptor => {
                let cert = handshake.certificate(conversation_id);
                if cert.acceptor_sig.is_none() {
                    return Ok(());
                }
                self.enqueue_direct_commit_accept(conversation_id, peer_user_id, &cert)?;
            }
        }
        Ok(())
    }

    pub(super) fn retransmit_pending_direct_pcs(&mut self) -> CoreResult<bool> {
        let pending: Vec<(String, String)> = self
            .state
            .conversations
            .iter()
            .filter(|(_, state)| {
                state.conversation.kind == ConversationKind::Direct && state.pcs.handshake.is_some()
            })
            .map(|(conversation_id, state)| (conversation_id.clone(), state.peer_user_id.clone()))
            .collect();
        let outbox_before = self.state.pending_outbox.len();
        for (conversation_id, peer_user_id) in pending {
            self.enqueue_direct_pcs_protocol(&conversation_id, &peer_user_id)?;
        }
        Ok(self.state.pending_outbox.len() > outbox_before)
    }

    fn enqueue_direct_commit_accept(
        &mut self,
        conversation_id: &str,
        peer_user_id: &str,
        cert: &DirectCommitCertificate,
    ) -> CoreResult<()> {
        let payload_b64 = STANDARD.encode(serde_json::to_vec(cert).map_err(|error| {
            CoreError::invalid_input(format!(
                "failed to encode direct commit certificate: {error}"
            ))
        })?);
        let already_pending = self.state.pending_outbox.iter().any(|item| {
            item.envelope.conversation_id == conversation_id
                && item.envelope.message_type == MessageType::ControlDirectCommitAccept
                && item.envelope.inline_ciphertext.as_deref() == Some(payload_b64.as_str())
        });
        if already_pending {
            return Ok(());
        }
        let recipient_device_ids = self.recipient_device_ids(conversation_id)?;
        let envelopes = recipient_device_ids
            .iter()
            .map(|device_id| {
                self.build_envelope(
                    conversation_id,
                    device_id,
                    MessageType::ControlDirectCommitAccept,
                    payload_b64.clone(),
                )
            })
            .collect::<CoreResult<Vec<_>>>()?;
        self.enqueue_envelopes(peer_user_id.to_string(), envelopes);
        Ok(())
    }

    pub(super) fn handle_direct_mls_commit(
        &mut self,
        conversation_id: &str,
        record: &InboxRecord,
    ) -> CoreResult<Option<CoreOutput>> {
        if !self.conversation_is_direct(conversation_id) {
            return Ok(None);
        }
        let payload_b64 = record
            .envelope
            .inline_ciphertext
            .as_deref()
            .unwrap_or_default();
        let payload_hash = commit_hash_from_b64(payload_b64).ok();
        let already_certified = payload_hash.as_ref().is_some_and(|incoming| {
            self.state
                .conversations
                .get(conversation_id)
                .is_some_and(|state| state.pcs.is_certified_hash(incoming))
        });
        let has_group = self
            .state
            .mls_adapter
            .as_ref()
            .is_some_and(|adapter| adapter.has_conversation(conversation_id));
        if has_group && already_certified {
            return Ok(Some(CoreOutput::default()));
        }
        let class = self
            .state
            .mls_adapter
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .classify_direct_commit(conversation_id, payload_b64)?;
        match class {
            DirectCommitClass::MembershipOrOther | DirectCommitClass::PendingRetry => Ok(None),
            DirectCommitClass::IgnoredReplay => Ok(Some(CoreOutput::default())),
            DirectCommitClass::NeedsRebuild => Ok(Some(self.escalate_conversation_to_rebuild(
                conversation_id,
                RecoveryEscalationReason::MlsMarkedUnrecoverable,
                "direct PCS commit could not be classified",
            )?)),
            DirectCommitClass::PcsSelfUpdate {
                commit_hash,
                base_epoch,
                sender_identity,
            } => Ok(Some(self.accept_direct_pcs_commit(
                conversation_id,
                record,
                commit_hash,
                base_epoch,
                payload_b64,
                sender_identity,
            )?)),
        }
    }

    fn accept_direct_pcs_commit(
        &mut self,
        conversation_id: &str,
        record: &InboxRecord,
        commit_hash: String,
        base_epoch: u64,
        payload_b64: &str,
        sender_identity: String,
    ) -> CoreResult<CoreOutput> {
        let Some(mls_sender) = Self::parse_mls_sender_identity(&sender_identity) else {
            return Ok(CoreOutput::default());
        };
        if record.envelope.sender_user_id != mls_sender.user_id
            || record.envelope.sender_device_id != mls_sender.device_id
        {
            return Ok(CoreOutput::default());
        }
        let local_device_id = self
            .state
            .local_identity
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
            .device_identity
            .device_id
            .clone();
        let member_device_ids = self
            .state
            .mls_adapter
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .member_device_ids(conversation_id)?;
        let expected_committer = designated_committer(&member_device_ids, base_epoch)?;
        if mls_sender.device_id != expected_committer {
            return self.escalate_conversation_to_rebuild(
                conversation_id,
                RecoveryEscalationReason::MlsMarkedUnrecoverable,
                "direct PCS commit sender is not the designated committer",
            );
        }
        match self.check_direct_pcs_roster_signer(
            conversation_id,
            base_epoch,
            &mls_sender.user_id,
            &mls_sender.device_id,
            Some(DirectPcsRole::Committer),
        )? {
            DirectPcsRosterCheck::Ignore => return Ok(CoreOutput::default()),
            DirectPcsRosterCheck::Rebuild(reason) => {
                return self.escalate_conversation_to_rebuild(
                    conversation_id,
                    RecoveryEscalationReason::MlsMarkedUnrecoverable,
                    reason,
                );
            }
            DirectPcsRosterCheck::Allowed => {}
        }
        let parent = self
            .state
            .conversations
            .get(conversation_id)
            .and_then(|state| state.pcs.last_certified_commit_hash.clone())
            .unwrap_or_default();
        if parent.is_empty() {
            return self.escalate_conversation_to_rebuild(
                conversation_id,
                RecoveryEscalationReason::MlsMarkedUnrecoverable,
                "direct PCS commit is missing a parent hash",
            );
        }
        if let Some(existing_hash) = self
            .state
            .conversations
            .get(conversation_id)
            .and_then(|state| state.pcs.handshake.as_ref().map(|h| h.commit_hash.clone()))
        {
            if existing_hash != commit_hash {
                return self.escalate_conversation_to_rebuild(
                    conversation_id,
                    RecoveryEscalationReason::MlsMarkedUnrecoverable,
                    "direct PCS epoch already has a different staged commit",
                );
            }
            let peer_user_id = record.envelope.sender_user_id.clone();
            let cert = self
                .state
                .conversations
                .get(conversation_id)
                .and_then(|state| state.pcs.handshake.as_ref())
                .map(|handshake| handshake.certificate(conversation_id))
                .expect("handshake exists");
            self.enqueue_direct_commit_accept(conversation_id, &peer_user_id, &cert)?;
            return self.direct_pcs_persist_output(conversation_id);
        }
        let identity = self
            .state
            .local_identity
            .clone()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?;
        let acceptor_sig = sign_certificate(
            &identity,
            conversation_id,
            base_epoch,
            &parent,
            &commit_hash,
        );
        let signature_conflict = {
            let conversation = self
                .state
                .conversations
                .get_mut(conversation_id)
                .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?;
            conversation
                .pcs
                .record_signature(base_epoch, &commit_hash)
                .is_err()
        };
        if signature_conflict {
            return self.escalate_conversation_to_rebuild(
                conversation_id,
                RecoveryEscalationReason::MlsMarkedUnrecoverable,
                "direct PCS epoch already has a different signed commit",
            );
        }
        {
            let conversation = self
                .state
                .conversations
                .get_mut(conversation_id)
                .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?;
            conversation.pcs.handshake = Some(DirectPcsHandshake {
                role: DirectPcsRole::Acceptor,
                epoch: base_epoch,
                commit_hash: commit_hash.clone(),
                commit_b64: payload_b64.to_string(),
                parent_commit_hash: parent,
                committer_device_id: expected_committer,
                acceptor_device_id: Some(local_device_id),
                committer_sig: None,
                acceptor_sig: Some(acceptor_sig),
            });
        }
        let peer_user_id = record.envelope.sender_user_id.clone();
        let cert = self
            .state
            .conversations
            .get(conversation_id)
            .and_then(|state| state.pcs.handshake.as_ref())
            .map(|handshake| handshake.certificate(conversation_id))
            .expect("handshake just stored");
        self.enqueue_direct_commit_accept(conversation_id, &peer_user_id, &cert)?;
        self.direct_pcs_persist_output(conversation_id)
    }

    pub(super) fn handle_direct_commit_accept(
        &mut self,
        record: &InboxRecord,
    ) -> CoreResult<CoreOutput> {
        let conversation_id = record.envelope.conversation_id.clone();
        if !self.conversation_is_direct(&conversation_id) {
            return Ok(CoreOutput::default());
        }
        let payload_b64 = record
            .envelope
            .inline_ciphertext
            .as_deref()
            .ok_or_else(|| CoreError::invalid_input("direct commit accept is missing payload"))?;
        let payload = match STANDARD.decode(payload_b64) {
            Ok(payload) => payload,
            Err(_) => return Ok(CoreOutput::default()),
        };
        let mut cert: DirectCommitCertificate = match serde_json::from_slice(&payload) {
            Ok(cert) => cert,
            Err(_) => return Ok(CoreOutput::default()),
        };
        if self
            .verify_device_signature(
                &record.envelope.sender_user_id,
                &record.envelope.sender_device_id,
                payload_b64.as_bytes(),
                &record.envelope.sender_proof.value,
            )
            .is_err()
        {
            return Ok(CoreOutput::default());
        }
        match self.check_direct_pcs_roster_signer(
            &conversation_id,
            cert.epoch,
            &record.envelope.sender_user_id,
            &record.envelope.sender_device_id,
            None,
        )? {
            DirectPcsRosterCheck::Ignore => return Ok(CoreOutput::default()),
            DirectPcsRosterCheck::Rebuild(reason) => {
                return self.escalate_conversation_to_rebuild(
                    &conversation_id,
                    RecoveryEscalationReason::MlsMarkedUnrecoverable,
                    reason,
                );
            }
            DirectPcsRosterCheck::Allowed => {}
        }
        if cert.conversation_id != conversation_id {
            return Ok(CoreOutput::default());
        }
        let already_certified = self
            .state
            .conversations
            .get(&conversation_id)
            .is_some_and(|state| state.pcs.is_certified_hash(&cert.commit_hash));
        if already_certified {
            return self.handle_direct_commit_accept_without_handshake(record, &mut cert);
        }
        let handshake = match self
            .state
            .conversations
            .get(&conversation_id)
            .and_then(|state| state.pcs.handshake.clone())
        {
            Some(handshake) => handshake,
            None => {
                return self.handle_direct_commit_accept_without_handshake(record, &mut cert);
            }
        };
        if cert.epoch < handshake.epoch {
            return Ok(CoreOutput::default());
        }
        if handshake.epoch == cert.epoch && handshake.commit_hash != cert.commit_hash {
            return self.escalate_conversation_to_rebuild(
                &conversation_id,
                RecoveryEscalationReason::MlsMarkedUnrecoverable,
                "direct commit certificate does not match staged commit",
            );
        }
        if handshake.commit_hash != cert.commit_hash
            || handshake.epoch != cert.epoch
            || handshake.parent_commit_hash != cert.parent_commit_hash
        {
            return self.escalate_conversation_to_rebuild(
                &conversation_id,
                RecoveryEscalationReason::MlsMarkedUnrecoverable,
                "direct commit certificate does not match staged commit",
            );
        }
        let parent = self
            .state
            .conversations
            .get(&conversation_id)
            .and_then(|state| state.pcs.last_certified_commit_hash.clone())
            .unwrap_or_default();
        if cert.parent_commit_hash != parent {
            return self.escalate_conversation_to_rebuild(
                &conversation_id,
                RecoveryEscalationReason::MlsMarkedUnrecoverable,
                "direct commit certificate parent hash mismatch",
            );
        }
        let expected_role = match handshake.role {
            DirectPcsRole::Committer => DirectPcsRole::Acceptor,
            DirectPcsRole::Acceptor => DirectPcsRole::Committer,
        };
        match self.check_direct_pcs_roster_signer(
            &conversation_id,
            cert.epoch,
            &record.envelope.sender_user_id,
            &record.envelope.sender_device_id,
            Some(expected_role),
        )? {
            DirectPcsRosterCheck::Ignore => return Ok(CoreOutput::default()),
            DirectPcsRosterCheck::Rebuild(reason) => {
                return self.escalate_conversation_to_rebuild(
                    &conversation_id,
                    RecoveryEscalationReason::MlsMarkedUnrecoverable,
                    reason,
                );
            }
            DirectPcsRosterCheck::Allowed => {}
        }
        let handshake_role = handshake.role;
        match handshake.role {
            DirectPcsRole::Committer => {
                if cert.acceptor_sig.is_none() {
                    return Ok(CoreOutput::default());
                }
                if self
                    .verify_certificate_signature(
                        &record.envelope.sender_user_id,
                        &record.envelope.sender_device_id,
                        &cert,
                        cert.acceptor_sig.as_deref().unwrap_or_default(),
                    )
                    .is_err()
                {
                    return self.escalate_conversation_to_rebuild(
                        &conversation_id,
                        RecoveryEscalationReason::MlsMarkedUnrecoverable,
                        "direct commit acceptor signature is invalid",
                    );
                }
                let missing_committer_sig = self
                    .state
                    .conversations
                    .get(&conversation_id)
                    .and_then(|state| state.pcs.handshake.as_ref())
                    .is_some_and(|handshake| handshake.committer_sig.is_none());
                if missing_committer_sig {
                    return self.escalate_conversation_to_rebuild(
                        &conversation_id,
                        RecoveryEscalationReason::MlsMarkedUnrecoverable,
                        "direct PCS committer signature is missing",
                    );
                }
                if let Some(handshake) = self
                    .state
                    .conversations
                    .get_mut(&conversation_id)
                    .and_then(|state| state.pcs.handshake.as_mut())
                {
                    handshake.acceptor_sig = cert.acceptor_sig.clone();
                    handshake.acceptor_device_id = Some(record.envelope.sender_device_id.clone());
                    cert.committer_sig = handshake.committer_sig.clone();
                    cert.acceptor_device_id = handshake.acceptor_device_id.clone();
                }
            }
            DirectPcsRole::Acceptor => {
                if !cert.is_complete() {
                    return Ok(CoreOutput::default());
                }
                if self
                    .verify_certificate_signature(
                        &record.envelope.sender_user_id,
                        &record.envelope.sender_device_id,
                        &cert,
                        cert.committer_sig.as_deref().unwrap_or_default(),
                    )
                    .is_err()
                {
                    return self.escalate_conversation_to_rebuild(
                        &conversation_id,
                        RecoveryEscalationReason::MlsMarkedUnrecoverable,
                        "direct commit committer signature is invalid",
                    );
                }
                let conversation = self
                    .state
                    .conversations
                    .get_mut(&conversation_id)
                    .ok_or_else(|| CoreError::invalid_input("conversation does not exist"))?;
                if let Some(handshake) = conversation.pcs.handshake.as_mut() {
                    handshake.committer_sig = cert.committer_sig.clone();
                }
            }
        }
        let complete = self
            .state
            .conversations
            .get(&conversation_id)
            .and_then(|state| state.pcs.handshake.as_ref())
            .map(|handshake| handshake.certificate(&conversation_id).is_complete())
            .unwrap_or(false);
        if !complete {
            return self.direct_pcs_persist_output(&conversation_id);
        }
        match self.apply_certified_direct_pcs(&conversation_id)? {
            DirectPcsApplyOutcome::Applied(applied) => {
                if matches!(handshake_role, DirectPcsRole::Committer) && cert.is_complete() {
                    let peer_user_id = record.envelope.sender_user_id.clone();
                    self.enqueue_direct_commit_accept(&conversation_id, &peer_user_id, &cert)?;
                }
                let membership = self.reconcile_conversation_membership(conversation_id.clone())?;
                let mut output = merge_outputs(applied, membership);
                if let Some(device_id) = self
                    .state
                    .local_identity
                    .as_ref()
                    .map(|identity| identity.device_identity.device_id.clone())
                {
                    output =
                        merge_outputs(output, self.replay_pending_records_for_device(device_id)?);
                }
                Ok(output)
            }
            DirectPcsApplyOutcome::Skipped(output) => Ok(output),
        }
    }

    fn handle_direct_commit_accept_without_handshake(
        &mut self,
        record: &InboxRecord,
        cert: &mut DirectCommitCertificate,
    ) -> CoreResult<CoreOutput> {
        let conversation_id = record.envelope.conversation_id.clone();
        let last_certified = self
            .state
            .conversations
            .get(&conversation_id)
            .and_then(|state| state.pcs.last_certified_commit_hash.clone())
            .unwrap_or_default();
        let already_certified = self
            .state
            .conversations
            .get(&conversation_id)
            .is_some_and(|state| state.pcs.is_certified_hash(&cert.commit_hash));
        let local_device_id = self
            .state
            .local_identity
            .as_ref()
            .map(|identity| identity.device_identity.device_id.clone())
            .unwrap_or_default();
        if last_certified.is_empty()
            || !already_certified
            || cert.committer_device_id != local_device_id
            || cert.acceptor_sig.is_none()
        {
            return Ok(CoreOutput::default());
        }
        match self.check_direct_pcs_roster_signer(
            &conversation_id,
            cert.epoch,
            &record.envelope.sender_user_id,
            &record.envelope.sender_device_id,
            Some(DirectPcsRole::Acceptor),
        )? {
            DirectPcsRosterCheck::Ignore => return Ok(CoreOutput::default()),
            DirectPcsRosterCheck::Rebuild(reason) => {
                return self.escalate_conversation_to_rebuild(
                    &conversation_id,
                    RecoveryEscalationReason::MlsMarkedUnrecoverable,
                    reason,
                );
            }
            DirectPcsRosterCheck::Allowed => {}
        }
        if self
            .verify_certificate_signature(
                &record.envelope.sender_user_id,
                &record.envelope.sender_device_id,
                cert,
                cert.acceptor_sig.as_deref().unwrap_or_default(),
            )
            .is_err()
        {
            return self.escalate_conversation_to_rebuild(
                &conversation_id,
                RecoveryEscalationReason::MlsMarkedUnrecoverable,
                "direct commit acceptor signature is invalid",
            );
        }
        let identity = self
            .state
            .local_identity
            .clone()
            .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?;
        cert.committer_sig = Some(sign_certificate(
            &identity,
            &conversation_id,
            cert.epoch,
            &cert.parent_commit_hash,
            &cert.commit_hash,
        ));
        cert.acceptor_device_id = Some(record.envelope.sender_device_id.clone());
        let peer_user_id = record.envelope.sender_user_id.clone();
        self.enqueue_direct_commit_accept(&conversation_id, &peer_user_id, cert)?;
        self.direct_pcs_persist_output(&conversation_id)
    }

    fn check_direct_pcs_roster_signer(
        &self,
        conversation_id: &str,
        epoch: u64,
        signer_user_id: &str,
        signer_device_id: &str,
        expected_role: Option<DirectPcsRole>,
    ) -> CoreResult<DirectPcsRosterCheck> {
        let member_users = self
            .state
            .conversations
            .get(conversation_id)
            .map(|state| state.conversation.member_users.clone())
            .unwrap_or_default();
        if !member_users.iter().any(|user_id| user_id == signer_user_id) {
            return Ok(DirectPcsRosterCheck::Ignore);
        }
        let member_device_ids = match self
            .state
            .mls_adapter
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .member_device_ids(conversation_id)
        {
            Ok(ids) => ids,
            Err(_) => return Ok(DirectPcsRosterCheck::Ignore),
        };
        if !member_device_ids
            .iter()
            .any(|device_id| device_id == signer_device_id)
        {
            return Ok(DirectPcsRosterCheck::Ignore);
        }
        let Some(expected_role) = expected_role else {
            return Ok(DirectPcsRosterCheck::Allowed);
        };
        let committer = designated_committer(&member_device_ids, epoch)?;
        match expected_role {
            DirectPcsRole::Committer => {
                if signer_device_id != committer {
                    return Ok(DirectPcsRosterCheck::Rebuild(
                        "direct PCS committer is not the designated roster committer",
                    ));
                }
            }
            DirectPcsRole::Acceptor => {
                if signer_device_id == committer {
                    return Ok(DirectPcsRosterCheck::Rebuild(
                        "direct PCS acceptor must not be the designated committer",
                    ));
                }
            }
        }
        Ok(DirectPcsRosterCheck::Allowed)
    }

    fn verify_certificate_signature(
        &self,
        signer_user_id: &str,
        signer_device_id: &str,
        cert: &DirectCommitCertificate,
        signature_hex: &str,
    ) -> CoreResult<()> {
        self.verify_device_signature(
            signer_user_id,
            signer_device_id,
            &cert.signing_payload(),
            signature_hex,
        )
    }

    fn apply_certified_direct_pcs(
        &mut self,
        conversation_id: &str,
    ) -> CoreResult<DirectPcsApplyOutcome> {
        let handshake = self
            .state
            .conversations
            .get(conversation_id)
            .and_then(|state| state.pcs.handshake.clone())
            .ok_or_else(|| CoreError::invalid_state("direct PCS handshake is missing"))?;
        let live_epoch = self
            .state
            .mls_adapter
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .export_group_summary(conversation_id)?
            .epoch;
        if live_epoch != handshake.epoch {
            return Ok(DirectPcsApplyOutcome::Skipped(
                self.direct_pcs_persist_output(conversation_id)?,
            ));
        }
        let summary = self
            .state
            .mls_adapter
            .as_mut()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .apply_certified_direct_commit(conversation_id, &handshake.commit_b64)?;
        self.state
            .mls_summaries
            .insert(conversation_id.to_string(), summary);
        if let Some(state) = self.state.conversations.get_mut(conversation_id) {
            state.pcs.mark_certified(handshake.commit_hash);
        }
        Ok(DirectPcsApplyOutcome::Applied(
            self.direct_pcs_persist_output(conversation_id)?,
        ))
    }

    pub(super) fn direct_send_persist_ops(&self, conversation_id: &str) -> Vec<PersistOp> {
        let mut ops = vec![
            PersistOp::SaveConversation {
                conversation_id: conversation_id.to_string(),
            },
            PersistOp::SaveMlsState {
                conversation_id: conversation_id.to_string(),
            },
        ];
        ops.extend(self.state.pending_outbox.iter().filter_map(|item| {
            if item.envelope.conversation_id == conversation_id {
                Some(PersistOp::SaveOutgoingEnvelope {
                    message_id: item.envelope.message_id.clone(),
                })
            } else {
                None
            }
        }));
        ops
    }

    fn direct_pcs_persist_output(&self, conversation_id: &str) -> CoreResult<CoreOutput> {
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                conversations_changed: true,
                ..CoreStateUpdate::default()
            },
            effects: vec![persist_effect(
                &self.state,
                vec![
                    PersistOp::SaveConversation {
                        conversation_id: conversation_id.to_string(),
                    },
                    PersistOp::SaveMlsState {
                        conversation_id: conversation_id.to_string(),
                    },
                ],
            )],
            view_model: None,
        })
    }
}

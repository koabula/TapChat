use super::*;

pub(super) enum KeyPackageClaimReadiness {
    Deferred(CoreOutput),
    Ready(ClaimedKeyPackages),
}

pub(super) struct ClaimedKeyPackages {
    pub(super) packages: Vec<PeerDeviceKeyPackage>,
    pub(super) claim_ids_by_device: BTreeMap<String, String>,
}

impl CoreEngine {
    pub(super) fn resume_key_package_claim_operations(&mut self) -> CoreResult<CoreOutput> {
        let operation_ids = self
            .state
            .key_package_claim_operations
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let mut output = CoreOutput::default();
        for operation_id in operation_ids {
            output = merge_outputs(
                output,
                self.issue_key_package_claim_operation(&operation_id)?,
            );
        }
        Ok(output)
    }

    pub(super) fn claim_key_packages_for_operation(
        &mut self,
        purpose: crate::transport_contract::KeyPackageClaimPurpose,
        continuation: PersistedKeyPackageClaimContinuation,
        mut targets_by_user: Vec<(String, Vec<String>)>,
    ) -> CoreResult<KeyPackageClaimReadiness> {
        targets_by_user.sort_by(|left, right| left.0.cmp(&right.0));
        for (_, device_ids) in &mut targets_by_user {
            device_ids.sort();
            device_ids.dedup();
        }
        if targets_by_user.is_empty() || targets_by_user.iter().any(|(_, ids)| ids.is_empty()) {
            return Err(CoreError::invalid_input(
                "KeyPackage claim operation requires at least one target device per account",
            ));
        }

        let existing_id = self
            .state
            .key_package_claim_operations
            .values()
            .find(|operation| operation.continuation == continuation)
            .map(|operation| operation.operation_id.clone());
        let operation_id = if let Some(operation_id) = existing_id {
            operation_id
        } else {
            let local_identity = self
                .state
                .local_identity
                .as_ref()
                .ok_or_else(|| CoreError::invalid_state("local identity is not initialized"))?
                .clone();
            let local_bundle = self
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
                        "IdentityBundle V2 is required for KeyPackage claims",
                    )
                })?;
            let sender_bundle_digest = crate::identity::identity_bundle_digest(&local_bundle)?;
            let operation_id = random_opaque_id("kp-operation");
            let now = current_unix_millis(self.state.message_nonce);
            let mut accounts = Vec::with_capacity(targets_by_user.len());
            for (target_user_id, target_device_ids) in targets_by_user {
                let target_bundle = self.bundle_for_key_package_claim(&target_user_id)?;
                let endpoint =
                    self.claim_endpoint_for_devices(&target_bundle, &target_device_ids)?;
                let target_bundle_digest = crate::identity::identity_bundle_digest(&target_bundle)?;
                let mut proposal = RelationshipProposalV2 {
                    proposal_id: random_opaque_id("kp-proposal"),
                    initiator_user_id: local_bundle.user_id.clone(),
                    initiator_device_id: local_identity.device_identity.device_id.clone(),
                    relationship_id_candidate: operation_id.clone(),
                    generation: 1,
                    attempt: 1,
                    peer_user_id: target_user_id.clone(),
                    sender_bundle_digest: sender_bundle_digest.clone(),
                    created_at: now,
                    expires_at: now.saturating_add(7 * 24 * 60 * 60 * 1000),
                    signature: String::new(),
                };
                proposal.signature = local_identity.sign_device_payload(
                    &crate::identity::relationship_proposal_signing_payload(&proposal),
                );
                crate::identity::verify_relationship_proposal(&proposal, &local_bundle)?;
                accounts.push(PersistedAccountKeyPackageClaim {
                    user_id: target_user_id,
                    target_device_ids,
                    target_bundle_digest,
                    target_bundle_revision: target_bundle.publication_revision,
                    endpoint,
                    idempotency_key: random_opaque_id("kp-claim"),
                    proposal,
                    result: None,
                    retry_count: 0,
                });
            }
            self.state.key_package_claim_operations.insert(
                operation_id.clone(),
                PersistedKeyPackageClaimOperation {
                    operation_id: operation_id.clone(),
                    purpose,
                    continuation,
                    accounts,
                    created_at: now,
                },
            );
            operation_id
        };

        let operation = self
            .state
            .key_package_claim_operations
            .get(&operation_id)
            .cloned()
            .ok_or_else(|| CoreError::invalid_state("KeyPackage claim operation disappeared"))?;
        if operation
            .accounts
            .iter()
            .all(|account| account.result.is_some())
        {
            let packages = self.validated_operation_packages(&operation)?;
            self.state
                .key_package_claim_operations
                .remove(&operation_id);
            return Ok(KeyPackageClaimReadiness::Ready(packages));
        }
        Ok(KeyPackageClaimReadiness::Deferred(
            self.issue_key_package_claim_operation(&operation_id)?,
        ))
    }

    fn bundle_for_key_package_claim(&self, user_id: &str) -> CoreResult<IdentityBundle> {
        if self
            .state
            .local_bundle
            .as_ref()
            .is_some_and(|bundle| bundle.user_id == user_id)
        {
            return self
                .state
                .local_bundle
                .clone()
                .ok_or_else(|| CoreError::invalid_state("local IdentityBundle is unavailable"));
        }
        Ok(self.direct_peer_contact_bundle(user_id)?.clone())
    }

    fn claim_endpoint_for_devices(
        &self,
        bundle: &IdentityBundle,
        device_ids: &[String],
    ) -> CoreResult<String> {
        let wanted: BTreeSet<&str> = device_ids.iter().map(String::as_str).collect();
        let devices = bundle
            .devices
            .iter()
            .filter(|device| wanted.contains(device.device_id.as_str()))
            .collect::<Vec<_>>();
        if devices.len() != wanted.len()
            || devices
                .iter()
                .any(|device| device.status != DeviceStatusKind::Active)
        {
            return Err(CoreError::new(
                "identity_refresh_required",
                "KeyPackage claim targets are not all active in the exact IdentityBundle",
            ));
        }
        let endpoints = devices
            .iter()
            .map(|device| {
                device
                    .key_package_claim_capability
                    .as_ref()
                    .map(|capability| capability.endpoint.clone())
                    .ok_or_else(|| {
                        CoreError::new(
                            "identity_refresh_required",
                            "KeyPackage claim target is missing its claim capability",
                        )
                    })
            })
            .collect::<CoreResult<Vec<_>>>()?;
        let endpoint = endpoints
            .first()
            .cloned()
            .ok_or_else(|| CoreError::invalid_input("KeyPackage claim target set is empty"))?;
        if endpoints.iter().any(|candidate| candidate != &endpoint) {
            return Err(CoreError::invalid_input(
                "one account must use one authoritative KeyPackage claim endpoint",
            ));
        }
        Ok(endpoint)
    }

    pub(super) fn issue_key_package_claim_operation(
        &mut self,
        operation_id: &str,
    ) -> CoreResult<CoreOutput> {
        let operation = self
            .state
            .key_package_claim_operations
            .get(operation_id)
            .cloned()
            .ok_or_else(|| CoreError::invalid_state("KeyPackage claim operation is unavailable"))?;
        let requester_bundle = self
            .state
            .local_bundle
            .clone()
            .ok_or_else(|| CoreError::invalid_state("local IdentityBundle is unavailable"))?;
        let mut effects = vec![persist_effect(&self.state, vec![PersistOp::SaveDeployment])];
        for account in operation
            .accounts
            .iter()
            .filter(|account| account.result.is_none())
        {
            let target_bundle = self.bundle_for_key_package_claim(&account.user_id)?;
            if account.target_bundle_digest
                != crate::identity::identity_bundle_digest(&target_bundle)?
                || account.target_bundle_revision != target_bundle.publication_revision
            {
                return Err(CoreError::new(
                    "identity_refresh_required",
                    "target IdentityBundle changed during the KeyPackage claim operation",
                ));
            }
            let wanted: BTreeSet<&str> = account
                .target_device_ids
                .iter()
                .map(String::as_str)
                .collect();
            let targets = target_bundle
                .devices
                .iter()
                .filter(|device| wanted.contains(device.device_id.as_str()))
                .map(|device| {
                    Ok(crate::transport_contract::KeyPackageClaimTarget {
                        device_id: device.device_id.clone(),
                        capability: device.key_package_claim_capability.clone().ok_or_else(
                            || {
                                CoreError::new(
                                    "identity_refresh_required",
                                    "KeyPackage claim target capability is unavailable",
                                )
                            },
                        )?,
                    })
                })
                .collect::<CoreResult<Vec<_>>>()?;
            if targets.len() != wanted.len() {
                return Err(CoreError::new(
                    "identity_refresh_required",
                    "KeyPackage claim target set changed before delivery",
                ));
            }
            let request_body = ClaimKeyPackagesRequest {
                version: crate::model::ENVELOPE_VERSION_V2.into(),
                purpose: operation.purpose,
                idempotency_key: account.idempotency_key.clone(),
                requester_bundle: requester_bundle.clone(),
                proposal: account.proposal.clone(),
                targets,
            };
            let request_id = self.next_request_id("kp-operation-claim");
            self.state.pending_requests.insert(
                request_id.clone(),
                PendingRequest::ClaimOperationKeyPackages {
                    operation_id: operation_id.to_string(),
                    target_user_id: account.user_id.clone(),
                    idempotency_key: account.idempotency_key.clone(),
                },
            );
            effects.push(CoreEffect::ExecuteHttpRequest {
                request: HttpRequestEffect {
                    request_id,
                    method: HttpMethod::Post,
                    url: account.endpoint.clone(),
                    headers: BTreeMap::from([("Content-Type".into(), "application/json".into())]),
                    auth: None,
                    body: Some(serde_json::to_string(&request_body).map_err(|error| {
                        CoreError::invalid_input(format!(
                            "failed to encode KeyPackage claim operation: {error}"
                        ))
                    })?),
                },
            });
        }
        Ok(CoreOutput {
            effects,
            ..CoreOutput::default()
        })
    }

    pub(super) fn handle_operation_key_packages_claimed(
        &mut self,
        operation_id: String,
        target_user_id: String,
        idempotency_key: String,
        result: ClaimKeyPackagesResult,
    ) -> CoreResult<CoreOutput> {
        if result.idempotency_key != idempotency_key || result.ticket.is_some() {
            return Err(CoreError::invalid_input(
                "non-Direct KeyPackage claim response is not bound to its request",
            ));
        }
        let operation = self
            .state
            .key_package_claim_operations
            .get(&operation_id)
            .cloned()
            .ok_or_else(|| CoreError::invalid_state("KeyPackage claim operation is unavailable"))?;
        let account = operation
            .accounts
            .iter()
            .find(|account| {
                account.user_id == target_user_id && account.idempotency_key == idempotency_key
            })
            .ok_or_else(|| CoreError::invalid_input("KeyPackage claim response target mismatch"))?;
        let expected: BTreeSet<&str> = account
            .target_device_ids
            .iter()
            .map(String::as_str)
            .collect();
        let actual: BTreeSet<&str> = result
            .claims
            .iter()
            .filter(|claim| claim.user_id == target_user_id)
            .map(|claim| claim.device_id.as_str())
            .collect();
        if actual != expected || result.claims.len() != expected.len() {
            return Err(CoreError::invalid_input(
                "KeyPackage claim response did not cover the exact target set",
            ));
        }
        let bundle = self.bundle_for_key_package_claim(&target_user_id)?;
        if account.target_bundle_digest != crate::identity::identity_bundle_digest(&bundle)?
            || account.target_bundle_revision != bundle.publication_revision
        {
            return Err(CoreError::new(
                "identity_refresh_required",
                "claimed KeyPackages do not match the persisted target IdentityBundle",
            ));
        }
        for claim in &result.claims {
            let device = bundle
                .devices
                .iter()
                .find(|device| {
                    device.device_id == claim.device_id && device.status == DeviceStatusKind::Active
                })
                .ok_or_else(|| CoreError::invalid_input("claimed device is not active"))?;
            let binding = device.mls_device_key_binding.as_ref().ok_or_else(|| {
                CoreError::invalid_input("claimed device is missing an MLS key binding")
            })?;
            crate::mls_adapter::validate_key_package_device_binding(
                &claim.key_package_b64,
                binding,
            )?;
        }
        let purpose = match operation.purpose {
            crate::transport_contract::KeyPackageClaimPurpose::GroupInvite => "group_invite",
            crate::transport_contract::KeyPackageClaimPurpose::DeviceReconcile => {
                "device_reconcile"
            }
            crate::transport_contract::KeyPackageClaimPurpose::Recovery => "recovery",
            _ => {
                return Err(CoreError::invalid_state(
                    "Direct claims cannot be finalized as a generic claim operation",
                ));
            }
        };
        let claim_set = KeyPackageClaimSet {
            purpose: purpose.into(),
            idempotency_key: result.idempotency_key,
            claims: result
                .claims
                .into_iter()
                .map(|claim| KeyPackageClaim {
                    claim_id: claim.claim_id,
                    user_id: claim.user_id,
                    device_id: claim.device_id,
                    key_package_id: claim.key_package_id,
                    key_package_b64: claim.key_package_b64,
                    created_at: claim.created_at,
                    expires_at: claim.expires_at,
                })
                .collect(),
            ticket: None,
        };
        let operation = self
            .state
            .key_package_claim_operations
            .get_mut(&operation_id)
            .ok_or_else(|| CoreError::invalid_state("KeyPackage claim operation disappeared"))?;
        let account = operation
            .accounts
            .iter_mut()
            .find(|account| account.user_id == target_user_id)
            .ok_or_else(|| CoreError::invalid_state("KeyPackage claim account disappeared"))?;
        if let Some(existing) = &account.result {
            if existing != &claim_set {
                return Err(CoreError::invalid_input(
                    "KeyPackage claim idempotency returned a different result",
                ));
            }
        } else {
            account.result = Some(claim_set);
        }
        let complete = operation
            .accounts
            .iter()
            .all(|account| account.result.is_some());
        if !complete {
            return Ok(CoreOutput {
                effects: vec![persist_effect(&self.state, vec![PersistOp::SaveDeployment])],
                ..CoreOutput::default()
            });
        }

        let continuation = operation.continuation.clone();
        let mut staged = CoreEngine {
            state: fork_core_state(&self.state)?,
            pending_inbound_commits: BTreeMap::new(),
        };
        let output = staged.resume_key_package_claim_continuation(continuation)?;
        self.state = staged.state;
        Ok(output)
    }

    fn validated_operation_packages(
        &self,
        operation: &PersistedKeyPackageClaimOperation,
    ) -> CoreResult<ClaimedKeyPackages> {
        let mut packages = Vec::new();
        let mut claim_ids_by_device = BTreeMap::new();
        for account in &operation.accounts {
            let bundle = self.bundle_for_key_package_claim(&account.user_id)?;
            if account.target_bundle_digest != crate::identity::identity_bundle_digest(&bundle)?
                || account.target_bundle_revision != bundle.publication_revision
            {
                return Err(CoreError::new(
                    "identity_refresh_required",
                    "target IdentityBundle changed before MLS consumed its KeyPackages",
                ));
            }
            let claim_set = account.result.as_ref().ok_or_else(|| {
                CoreError::invalid_state("KeyPackage claim operation is incomplete")
            })?;
            for claim in &claim_set.claims {
                let device = bundle
                    .devices
                    .iter()
                    .find(|device| {
                        device.device_id == claim.device_id
                            && device.status == DeviceStatusKind::Active
                    })
                    .ok_or_else(|| {
                        CoreError::invalid_input("claimed device is no longer active")
                    })?;
                let binding = device.mls_device_key_binding.as_ref().ok_or_else(|| {
                    CoreError::invalid_input("claimed device lost its MLS key binding")
                })?;
                crate::mls_adapter::validate_key_package_device_binding(
                    &claim.key_package_b64,
                    binding,
                )?;
                packages.push(PeerDeviceKeyPackage {
                    user_id: claim.user_id.clone(),
                    device_id: claim.device_id.clone(),
                    device_public_key: device.device_public_key.clone(),
                    key_package_b64: claim.key_package_b64.clone(),
                });
                claim_ids_by_device.insert(claim.device_id.clone(), claim.claim_id.clone());
            }
        }
        Ok(ClaimedKeyPackages {
            packages,
            claim_ids_by_device,
        })
    }

    fn resume_key_package_claim_continuation(
        &mut self,
        continuation: PersistedKeyPackageClaimContinuation,
    ) -> CoreResult<CoreOutput> {
        match continuation {
            PersistedKeyPackageClaimContinuation::CreateGroup {
                title,
                member_user_ids,
            } => self.handle_command(CoreCommand::CreateGroupConversation {
                title,
                member_user_ids,
            }),
            PersistedKeyPackageClaimContinuation::InviteToGroup {
                group_id,
                invitee_user_ids,
            } => self.handle_command(CoreCommand::InviteToGroup {
                group_id,
                invitee_user_ids,
            }),
            PersistedKeyPackageClaimContinuation::ApproveGroupJoin {
                group_id,
                request_id,
            } => self.handle_command(CoreCommand::ApproveGroupJoin {
                group_id,
                request_id,
            }),
            PersistedKeyPackageClaimContinuation::AddGroupMemberDevice {
                group_id,
                user_id,
                device_id,
            } => self.handle_command(CoreCommand::AddGroupMemberDevice {
                group_id,
                user_id,
                device_id,
            }),
            PersistedKeyPackageClaimContinuation::ReconcileConversation { conversation_id } => self
                .handle_command(CoreCommand::ReconcileConversationMembership { conversation_id }),
            PersistedKeyPackageClaimContinuation::RebuildConversation { conversation_id } => {
                self.handle_command(CoreCommand::RebuildConversation { conversation_id })
            }
        }
    }

    pub(super) fn handle_key_package_claim_operation_failure(
        &mut self,
        operation_id: String,
        target_user_id: String,
        body: Option<&str>,
    ) -> CoreResult<CoreOutput> {
        let operation = self
            .state
            .key_package_claim_operations
            .get_mut(&operation_id)
            .ok_or_else(|| CoreError::invalid_state("KeyPackage claim operation is unavailable"))?;
        if let Some(account) = operation
            .accounts
            .iter_mut()
            .find(|account| account.user_id == target_user_id)
        {
            account.retry_count = account.retry_count.saturating_add(1);
        }
        let pool_exhausted = body.is_some_and(|body| body.contains("keypackage_pool_exhausted"));
        let timer_id = format!("key_package_claim:{operation_id}");
        let retry_count = operation
            .accounts
            .iter()
            .map(|account| account.retry_count)
            .max()
            .unwrap_or(1);
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                ..CoreStateUpdate::default()
            },
            effects: vec![
                persist_effect(&self.state, vec![PersistOp::SaveDeployment]),
                CoreEffect::ScheduleTimer {
                    timer: TimerEffect {
                        timer_id: timer_id.clone(),
                        delay_ms: retry_delay_ms(&timer_id, retry_count).min(24 * 60 * 60 * 1000),
                    },
                },
                CoreEffect::EmitUserNotification {
                    notification: UserNotificationEffect {
                        status: SystemStatus::TemporaryNetworkFailure,
                        message: if pool_exhausted {
                            "A target device has no available one-time KeyPackage; retry scheduled"
                                .into()
                        } else {
                            "KeyPackage claim failed; retry scheduled".into()
                        },
                    },
                },
            ],
            view_model: None,
        })
    }
}

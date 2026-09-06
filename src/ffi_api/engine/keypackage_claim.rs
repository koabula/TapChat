use super::*;

use sha2::{Digest, Sha256};

/// Response body for `POST {origin}/v1/keypackage-pool/{deviceId}/claim`.
#[derive(Debug, Deserialize)]
struct ClaimKeyPackagePoolResponse {
    #[serde(rename = "keyPackage")]
    entry: ClaimedKeyPackagePoolEntry,
}

#[derive(Debug, Deserialize)]
struct ClaimedKeyPackagePoolEntry {
    #[serde(rename = "keyPackage")]
    key_package_b64: String,
}

/// Body for `PUT {own_origin}/v1/keypackage-pool/{deviceId}`.
#[derive(Debug, Serialize)]
struct ReplenishKeyPackagePoolRequest {
    version: String,
    #[serde(rename = "deviceId")]
    device_id: String,
    #[serde(rename = "keyPackages")]
    key_packages: Vec<ReplenishKeyPackagePoolEntry>,
}

#[derive(Debug, Serialize)]
struct ReplenishKeyPackagePoolEntry {
    #[serde(rename = "keyPackageId")]
    key_package_id: String,
    #[serde(rename = "keyPackage")]
    key_package: String,
    #[serde(rename = "lifecycleVersion")]
    lifecycle_version: u16,
    #[serde(rename = "notBefore")]
    not_before: u64,
    #[serde(rename = "createdAt")]
    created_at: u64,
    #[serde(rename = "expiresAt")]
    expires_at: u64,
}

/// Response body for `GET {own_origin}/v1/keypackage-pool/{deviceId}`.
#[derive(Debug, Deserialize)]
struct KeyPackagePoolCountResponse {
    #[serde(default)]
    count: u32,
}

impl CoreEngine {
    /// Kicks off a claim-then-finalize batch: stashes `kind` plus the full
    /// ordered device queue, then issues the first (and only the first —
    /// claims are strictly sequential) `ClaimKeyPackage` HTTP effect. The
    /// caller has already done every synchronous precondition check
    /// (title/member validation, duplicate-conversation checks, "does this
    /// contact have any eligible device at all" checks). An empty device
    /// queue is a legitimate outcome (e.g. a reconciliation that only
    /// revokes devices) and finalizes immediately with no network round
    /// trip, rather than being treated as an error.
    pub(super) fn start_key_package_claim_batch(
        &mut self,
        kind: KeyPackageClaimBatchKind,
        mut remaining_devices: VecDeque<(String, String)>,
    ) -> CoreResult<CoreOutput> {
        let creation_id = self.next_request_id("conv_create");
        let Some((user_id, device_id)) = remaining_devices.pop_front() else {
            self.state.pending_key_package_claim_batches.insert(
                creation_id.clone(),
                PendingKeyPackageClaimBatch {
                    kind,
                    remaining_devices,
                    resolved_key_packages: Vec::new(),
                },
            );
            return self.finalize_key_package_claim_batch(&creation_id);
        };
        self.state.pending_key_package_claim_batches.insert(
            creation_id.clone(),
            PendingKeyPackageClaimBatch {
                kind,
                remaining_devices,
                resolved_key_packages: Vec::new(),
            },
        );
        self.build_claim_key_package_effect(creation_id, user_id, device_id)
    }

    fn build_claim_key_package_effect(
        &mut self,
        creation_id: String,
        user_id: String,
        device_id: String,
    ) -> CoreResult<CoreOutput> {
        let url = self.key_package_claim_url(&user_id, &device_id)?;
        let request_id = self.next_request_id(&format!("claim_keypackage:{creation_id}"));
        self.state.pending_requests.insert(
            request_id.clone(),
            PendingRequest::ClaimKeyPackage {
                creation_id,
                user_id,
                device_id,
            },
        );
        Ok(CoreOutput {
            effects: vec![CoreEffect::ExecuteHttpRequest {
                request: HttpRequestEffect {
                    request_id,
                    method: HttpMethod::Post,
                    url,
                    headers: BTreeMap::new(),
                    auth: None,
                    body: None,
                },
            }],
            ..CoreOutput::default()
        })
    }

    /// Builds the claim URL for a target device, dispatching on whether the
    /// device belongs to the local user (an additional device of ours,
    /// claimed from our own runtime) or to a contact (claimed from their
    /// runtime, looked up via the cached contact bundle).
    fn key_package_claim_url(&self, user_id: &str, device_id: &str) -> CoreResult<String> {
        if user_id == self.local_identity_user_id()? {
            self.own_key_package_claim_url(device_id)
        } else {
            self.peer_key_package_claim_url(user_id, device_id)
        }
    }

    fn own_key_package_claim_url(&self, device_id: &str) -> CoreResult<String> {
        let deployment = self
            .state
            .deployment_bundle
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("deployment bundle is not initialized"))?;
        Ok(format!(
            "{}/v1/keypackage-pool/{}/claim",
            deployment.inbox_http_endpoint.trim_end_matches('/'),
            urlencoding::encode(device_id)
        ))
    }

    fn peer_key_package_claim_url(
        &self,
        peer_user_id: &str,
        device_id: &str,
    ) -> CoreResult<String> {
        let bundle = self.direct_peer_contact_bundle(peer_user_id)?;
        let reference = bundle
            .identity_bundle_ref
            .as_deref()
            .ok_or_else(|| CoreError::invalid_input("peer identity bundle reference is missing"))?;
        let origin = origin_from_url(reference)?;
        Ok(format!(
            "{origin}/v1/keypackage-pool/{}/claim",
            urlencoding::encode(device_id)
        ))
    }

    /// Handles a successful (2xx) claim response: resolves the device's
    /// `PeerDeviceKeyPackage` from the claimed bytes plus the locally cached
    /// device profile (the local user's own bundle for an own-device claim,
    /// otherwise the cached contact bundle), then advances the queue.
    pub(super) fn handle_key_package_claimed(
        &mut self,
        creation_id: String,
        user_id: String,
        device_id: String,
        body: Option<String>,
    ) -> CoreResult<CoreOutput> {
        if !self
            .state
            .pending_key_package_claim_batches
            .contains_key(&creation_id)
        {
            // The batch was already aborted by an earlier failure. With
            // strictly sequential claiming this should not happen (only one
            // claim is ever in flight per creation_id), but a stray/duplicate
            // response is handled defensively.
            return Ok(CoreOutput::default());
        }
        let response: ClaimKeyPackagePoolResponse =
            serde_json::from_str(body.as_deref().unwrap_or("")).map_err(|error| {
                CoreError::invalid_input(format!(
                    "failed to decode key package claim response: {error}"
                ))
            })?;
        let device_public_key = self
            .cached_device_public_key(&user_id, &device_id)
            .ok_or_else(|| {
                CoreError::invalid_state("claimed device is missing from cached contact bundle")
            })?;
        let resolved = PeerDeviceKeyPackage {
            user_id,
            device_id,
            device_public_key,
            key_package_b64: response.entry.key_package_b64,
        };
        self.push_resolved_key_package_and_continue(creation_id, resolved)
    }

    /// Handles a `pool_empty` claim rejection: falls back to the peer
    /// device's cached last-resort KeyPackage, if any is still usable. For
    /// an own-device claim (`add_group_member_device`), "peer" here means
    /// the local user's own cached bundle rather than a contact's.
    pub(super) fn handle_key_package_claim_pool_empty(
        &mut self,
        creation_id: String,
        user_id: String,
        device_id: String,
    ) -> CoreResult<CoreOutput> {
        if !self
            .state
            .pending_key_package_claim_batches
            .contains_key(&creation_id)
        {
            return Ok(CoreOutput::default());
        }
        let now_ms = current_unix_millis(self.state.message_nonce);
        let fallback = self
            .cached_device_profile(&user_id, &device_id)
            .and_then(|device| {
                let keypackage_ref = device
                    .keypackage_ref
                    .as_ref()
                    .filter(|keypackage_ref| keypackage_ref.is_usable_at(now_ms))?;
                Some((
                    device.device_public_key.clone(),
                    keypackage_ref.object_ref.clone(),
                ))
            });
        let Some((device_public_key, key_package_b64)) = fallback else {
            return self.abort_key_package_claim_batch(
                &creation_id,
                format!(
                    "no usable key package is available for {user_id}/{device_id} \
                     (one-time pool is empty and no last-resort key package is cached)"
                ),
            );
        };
        let resolved = PeerDeviceKeyPackage {
            user_id,
            device_id,
            device_public_key,
            key_package_b64,
        };
        self.push_resolved_key_package_and_continue(creation_id, resolved)
    }

    /// Looks up a device's cached profile — the local user's own bundle for
    /// an own-device claim, otherwise a contact's cached bundle.
    fn cached_device_profile(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Option<&crate::model::DeviceContactProfile> {
        let is_own_device = self
            .local_identity_user_id()
            .is_ok_and(|local_user_id| local_user_id == user_id);
        let bundle = if is_own_device {
            self.state.local_bundle.as_ref()?
        } else {
            self.direct_peer_contact_bundle(user_id).ok()?
        };
        bundle
            .devices
            .iter()
            .find(|device| device.device_id == device_id)
    }

    fn cached_device_public_key(&self, user_id: &str, device_id: &str) -> Option<String> {
        self.cached_device_profile(user_id, device_id)
            .map(|device| device.device_public_key.clone())
    }

    fn push_resolved_key_package_and_continue(
        &mut self,
        creation_id: String,
        resolved: PeerDeviceKeyPackage,
    ) -> CoreResult<CoreOutput> {
        let Some(pending) = self
            .state
            .pending_key_package_claim_batches
            .get_mut(&creation_id)
        else {
            return Ok(CoreOutput::default());
        };
        pending.resolved_key_packages.push(resolved);
        match pending.remaining_devices.pop_front() {
            Some((next_user_id, next_device_id)) => {
                self.build_claim_key_package_effect(creation_id, next_user_id, next_device_id)
            }
            None => self.finalize_key_package_claim_batch(&creation_id),
        }
    }

    fn finalize_key_package_claim_batch(&mut self, creation_id: &str) -> CoreResult<CoreOutput> {
        let pending = self
            .state
            .pending_key_package_claim_batches
            .remove(creation_id)
            .ok_or_else(|| CoreError::invalid_state("key package claim batch is not pending"))?;
        match pending.kind {
            KeyPackageClaimBatchKind::Direct {
                peer_user_id,
                conversation_id,
                peer_device_ids,
            } => self.finalize_direct_conversation_creation(
                peer_user_id,
                conversation_id,
                peer_device_ids,
                pending.resolved_key_packages,
            ),
            KeyPackageClaimBatchKind::Group {
                title,
                member_user_ids,
                group_id,
                conversation_id,
            } => self.finalize_group_conversation_creation(
                title,
                member_user_ids,
                group_id,
                conversation_id,
                pending.resolved_key_packages,
            ),
            KeyPackageClaimBatchKind::ApproveGroupJoin {
                group_id,
                request_id,
                join,
            } => {
                self.ensure_group_state_operation_ready(&group_id)?;
                let resolved = pending.resolved_key_packages;
                let staged_request_id = Some(request_id.clone());
                self.run_staged_group_mutation(staged_request_id, move |engine| {
                    engine.finalize_group_join_approval(group_id, request_id, join, resolved)
                })
            }
            KeyPackageClaimBatchKind::InviteToGroup {
                group_id,
                invitee_user_ids,
            } => {
                self.ensure_group_state_operation_ready(&group_id)?;
                let resolved = pending.resolved_key_packages;
                self.run_staged_group_mutation(None, move |engine| {
                    engine.finalize_invite_to_group(group_id, invitee_user_ids, resolved)
                })
            }
            KeyPackageClaimBatchKind::AddGroupMemberDevice {
                group_id,
                device_id,
            } => {
                self.ensure_group_state_operation_ready(&group_id)?;
                let resolved = pending.resolved_key_packages;
                self.run_staged_group_mutation(None, move |engine| {
                    engine.finalize_add_group_member_device(group_id, device_id, resolved)
                })
            }
            KeyPackageClaimBatchKind::ReconcileMembershipRebootstrap {
                conversation_id,
                peer_user_id,
                peer_active_device_ids,
                member_devices,
            } => self.finalize_reconcile_membership_rebootstrap(
                conversation_id,
                peer_user_id,
                peer_active_device_ids,
                member_devices,
                pending.resolved_key_packages,
            ),
            KeyPackageClaimBatchKind::ReconcileMembershipAddDevices {
                conversation_id,
                peer_user_id,
                peer_active_device_ids,
                revoked_devices,
            } => self.finalize_reconcile_membership_add_devices(
                conversation_id,
                peer_user_id,
                peer_active_device_ids,
                revoked_devices,
                pending.resolved_key_packages,
            ),
        }
    }

    /// Aborts an in-flight KeyPackage claim batch: drops the pending state
    /// (no partial conversation/group state was ever written, since the
    /// actual MLS call only happens at finalize) and surfaces a retriable,
    /// user-visible notification rather than a hard command error.
    pub(super) fn abort_key_package_claim_batch(
        &mut self,
        creation_id: &str,
        message: String,
    ) -> CoreResult<CoreOutput> {
        self.state
            .pending_key_package_claim_batches
            .remove(creation_id);
        Ok(CoreOutput {
            state_update: CoreStateUpdate {
                system_statuses_changed: vec![SystemStatus::TemporaryNetworkFailure],
                ..CoreStateUpdate::default()
            },
            effects: vec![CoreEffect::EmitUserNotification {
                notification: UserNotificationEffect {
                    status: SystemStatus::TemporaryNetworkFailure,
                    message,
                },
            }],
            view_model: None,
        })
    }

    // --- Own-pool maintenance (credential_maintenance timer top-up) ---

    fn own_key_package_pool_url(&self) -> CoreResult<String> {
        let deployment = self
            .state
            .deployment_bundle
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("deployment bundle is not initialized"))?;
        let device_id = self.local_device_id_required()?;
        Ok(format!(
            "{}/v1/keypackage-pool/{}",
            deployment.inbox_http_endpoint.trim_end_matches('/'),
            urlencoding::encode(&device_id)
        ))
    }

    /// Builds the effect that checks the remaining count of the local
    /// device's own one-time KeyPackage pool. Called once per maintenance
    /// cycle, right after the existing last-resort rotation check.
    pub(super) fn key_package_pool_count_check_effect(&mut self) -> CoreResult<CoreEffect> {
        let url = format!("{}/count", self.own_key_package_pool_url()?);
        let auth = self.device_runtime_auth_requirement()?;
        let request_id = self.next_request_id("keypackage_pool_count");
        self.state
            .pending_requests
            .insert(request_id.clone(), PendingRequest::KeyPackagePoolCount);
        Ok(CoreEffect::ExecuteHttpRequest {
            request: HttpRequestEffect {
                request_id,
                method: HttpMethod::Get,
                url,
                headers: BTreeMap::new(),
                auth: Some(auth),
                body: None,
            },
        })
    }

    /// Handles the pool-count response: if the remaining count is below the
    /// low-water mark, generates fresh one-time KeyPackages locally and
    /// uploads them to top the pool back up to the target size. Best-effort
    /// background maintenance — failures here are never surfaced to the
    /// user (unlike an aborted, user-initiated conversation creation).
    pub(super) fn handle_key_package_pool_count(
        &mut self,
        body: Option<String>,
    ) -> CoreResult<CoreOutput> {
        let response: KeyPackagePoolCountResponse =
            serde_json::from_str(body.as_deref().unwrap_or("{\"count\":0}")).map_err(|error| {
                CoreError::invalid_input(format!(
                    "failed to decode key package pool count response: {error}"
                ))
            })?;
        if response.count >= crate::mls_adapter::ONE_TIME_KEY_PACKAGE_POOL_LOW_WATER {
            return Ok(CoreOutput::default());
        }
        let deficit =
            crate::mls_adapter::ONE_TIME_KEY_PACKAGE_POOL_TARGET.saturating_sub(response.count);
        if deficit == 0 {
            return Ok(CoreOutput::default());
        }
        let now_ms = current_unix_millis(self.state.message_nonce);
        let packages = self
            .state
            .mls_adapter
            .as_ref()
            .ok_or_else(|| CoreError::invalid_state("mls adapter is not initialized"))?
            .generate_one_time_key_packages(deficit, now_ms)?;
        let effect = self.replenish_key_package_pool_effect(packages)?;
        Ok(CoreOutput {
            effects: vec![effect],
            ..CoreOutput::default()
        })
    }

    fn replenish_key_package_pool_effect(
        &mut self,
        packages: Vec<crate::mls_adapter::PublishedKeyPackage>,
    ) -> CoreResult<CoreEffect> {
        let device_id = self.local_device_id_required()?;
        let url = self.own_key_package_pool_url()?;
        let auth = self.device_runtime_auth_requirement()?;
        let body = ReplenishKeyPackagePoolRequest {
            version: crate::model::CURRENT_MODEL_VERSION.to_string(),
            device_id,
            key_packages: packages
                .iter()
                .map(|package| ReplenishKeyPackagePoolEntry {
                    key_package_id: hex_sha256(&package.key_package_b64),
                    key_package: package.key_package_b64.clone(),
                    lifecycle_version: package.lifecycle_version,
                    not_before: package.not_before,
                    created_at: package.created_at,
                    expires_at: package.expires_at,
                })
                .collect(),
        };
        let request_id = self.next_request_id("keypackage_pool_replenish");
        self.state
            .pending_requests
            .insert(request_id.clone(), PendingRequest::ReplenishKeyPackagePool);
        let mut headers = BTreeMap::new();
        headers.insert("Content-Type".into(), "application/json".into());
        Ok(CoreEffect::ExecuteHttpRequest {
            request: HttpRequestEffect {
                request_id,
                method: HttpMethod::Put,
                url,
                headers,
                auth: Some(auth),
                body: Some(serde_json::to_string(&body).map_err(|error| {
                    CoreError::invalid_input(format!(
                        "failed to encode key package pool replenish request: {error}"
                    ))
                })?),
            },
        })
    }
}

fn origin_from_url(raw: &str) -> CoreResult<String> {
    let parsed = url::Url::parse(raw)
        .map_err(|_| CoreError::invalid_input("identity bundle reference is not a valid URL"))?;
    let origin = parsed.origin().ascii_serialization();
    if origin == "null" {
        return Err(CoreError::invalid_input(
            "identity bundle reference does not have a usable origin",
        ));
    }
    Ok(origin)
}

fn hex_sha256(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

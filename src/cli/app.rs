use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use reqwest::Client;
use serde::Serialize;

use crate::contact_workflows::{
    accept_message_request_with_bundle_import, import_identity_bundle_into_profile,
    message_request_action_from_output, message_requests_from_output, persist_driver,
};
use crate::ffi_api::{AttachmentDescriptor, CoreCommand, CoreEvent};
use crate::model::{ConversationKind, DeploymentBundle, DeviceStatusKind, Validate};
use crate::persistence::CorePersistenceSnapshot;
use crate::transport_contract::{AllowlistDocument, GetHeadResult};

use super::args::{
    Cli, CloudflareProvisionCommand, CloudflareProvisionSubcommand, CloudflareRuntimeCommand,
    CloudflareRuntimeSubcommand, Command, ContactAllowlistCommand, ContactAllowlistSubcommand,
    ContactCommand, ContactRequestsCommand, ContactRequestsSubcommand, ContactSubcommand,
    ConversationCommand, ConversationSubcommand, DeviceCommand, DeviceSubcommand,
    MessageCommand, MessageSubcommand, OutputFormat, ProfileCommand, ProfileSubcommand,
    RuntimeCommand, RuntimeSubcommand, SyncCommand, SyncSubcommand,
};
use super::driver::CoreDriver;
use super::profile::{Profile, ProfileRegistry, RuntimeMetadata};
use super::runtime::{
    bootstrap_device_bundle, deploy_cloudflare_runtime, derive_cloudflare_defaults,
    prompt_cloudflare_overrides, resolve_cloudflare_config, resolve_service_root,
    resolve_workspace_root, start_local_runtime, stop_local_runtime, wait_until_ready,
};
use super::util::to_snake_case_json_string;
pub async fn run() -> Result<()> {
    let cli = Cli::parse();
    let app = CliApp::new(cli.output);
    app.run_command(cli.command).await
}

struct CliApp {
    output: OutputFormat,
}

impl CliApp {
    fn new(output: OutputFormat) -> Self {
        Self { output }
    }

    async fn run_command(&self, command: Command) -> Result<()> {
        match command {
            Command::Profile(command) => self.run_profile(command).await,
            Command::Device(command) => self.run_device(command).await,
            Command::Contact(command) => self.run_contact(command).await,
            Command::Conversation(command) => self.run_conversation(command).await,
            Command::Message(command) => self.run_message(command).await,
            Command::Sync(command) => self.run_sync(command).await,
            Command::Runtime(command) => self.run_runtime(command).await,
        }
    }

    async fn run_profile(&self, command: ProfileCommand) -> Result<()> {
        match command.command {
            ProfileSubcommand::Init { name, root } => {
                let profile = Profile::init(&name, &root)?;
                self.print_value(profile.metadata())
            }
            ProfileSubcommand::Show { profile } => {
                let profile = Profile::open(resolve_profile_path(profile)?)?;
                let runtime = profile.load_runtime_metadata()?;
                self.print_value(&serde_json::json!({
                    "profile": profile.metadata(),
                    "runtime": runtime,
                }))
            }
            ProfileSubcommand::ImportDeployment {
                profile,
                bundle_file,
            } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let bundle = Profile::load_deployment_bundle_file(&bundle_file)?;
                bundle.validate().map_err(anyhow::Error::from)?;
                let mut driver = load_driver(&profile)?;
                driver
                    .run_command_until_idle(CoreCommand::ImportDeploymentBundle {
                        bundle: bundle.clone(),
                    })
                    .await?;
                profile.save_deployment_bundle(&bundle)?;
                persist_driver(&mut profile, &driver)?;
                self.print_value(&serde_json::json!({
                    "imported": true,
                    "inbox_http_endpoint": bundle.inbox_http_endpoint,
                    "inbox_websocket_endpoint": bundle.inbox_websocket_endpoint,
                }))
            }
            ProfileSubcommand::ExportIdentity { profile, out } => {
                let profile = Profile::open(resolve_profile_path(profile)?)?;
                let driver = load_driver(&profile)?;
                let bundle = driver.local_bundle().cloned().ok_or_else(|| {
                    anyhow!("local identity bundle is unavailable; import deployment first")
                })?;
                if let Some(path) = out {
                    std::fs::write(&path, serde_json::to_vec_pretty(&bundle)?)?;
                    self.print_value(&serde_json::json!({
                        "written": path,
                        "user_id": bundle.user_id,
                    }))
                } else {
                    self.print_value(&bundle)
                }
            }
            ProfileSubcommand::List => {
                let registry = ProfileRegistry::load()?;
                self.print_value(&serde_json::json!({
                    "active_profile": registry.active_profile,
                    "profiles": registry.profiles,
                }))
            }
            ProfileSubcommand::Activate { profile, name } => {
                let mut registry = ProfileRegistry::load()?;
                let active_profile = match (profile, name) {
                    (Some(profile), None) => {
                        registry.set_active(&profile)?;
                        profile
                    }
                    (None, Some(name)) => registry.set_active_by_name(&name)?,
                    _ => bail!("specify either --profile or --name"),
                };
                registry.save()?;
                self.print_value(&serde_json::json!({
                    "activated": true,
                    "profile": active_profile,
                }))
            }
            ProfileSubcommand::Current => {
                let registry = ProfileRegistry::load()?;
                self.print_value(registry.current()?)
            }
            ProfileSubcommand::Remove { profile } => {
                let profile = resolve_profile_path(profile)?;
                let mut registry = ProfileRegistry::load()?;
                registry.remove(&profile);
                registry.save()?;
                self.print_value(&serde_json::json!({
                    "removed": true,
                    "profile": profile,
                    "active_profile": registry.active_profile,
                }))
            }
        }
    }

    async fn run_device(&self, command: DeviceCommand) -> Result<()> {
        match command.command {
            DeviceSubcommand::Create {
                profile,
                device_name,
                mnemonic_file,
            } => {
                self.run_identity_command(profile, device_name, mnemonic_file, false)
                    .await
            }
            DeviceSubcommand::Recover {
                profile,
                device_name,
                mnemonic_file,
            } => {
                self.run_identity_command(profile, device_name, Some(mnemonic_file), false)
                    .await
            }
            DeviceSubcommand::Add {
                profile,
                device_name,
                mnemonic_file,
            } => {
                self.run_identity_command(profile, device_name, Some(mnemonic_file), true)
                    .await
            }
            DeviceSubcommand::RotateKeyPackage { profile } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                driver
                    .run_command_until_idle(CoreCommand::RotateLocalKeyPackage)
                    .await?;
                persist_driver(&mut profile, &driver)?;
                self.print_value(&serde_json::json!({ "rotated": true }))
            }
            DeviceSubcommand::Status { profile } => {
                let profile = Profile::open(resolve_profile_path(profile)?)?;
                let driver = load_driver(&profile)?;
                let identity = driver
                    .local_identity()
                    .ok_or_else(|| anyhow!("local identity is not initialized"))?;
                self.print_value(&serde_json::json!({
                    "user_id": identity.user_identity.user_id,
                    "device_id": identity.device_identity.device_id,
                    "device_status": identity.device_status.status,
                    "has_local_bundle": driver.local_bundle().is_some(),
                    "mnemonic": identity.mnemonic,
                }))
            }
            DeviceSubcommand::Revoke {
                profile,
                target_device_id,
            } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                driver
                    .run_command_until_idle(CoreCommand::UpdateLocalDeviceStatus {
                        target_device_id: target_device_id.clone(),
                        status: DeviceStatusKind::Revoked,
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                self.print_value(&serde_json::json!({
                    "revoked": true,
                    "device_id": target_device_id,
                }))
            }
        }
    }

    async fn run_contact(&self, command: ContactCommand) -> Result<()> {
        match command.command {
            ContactSubcommand::ImportIdentity {
                profile,
                bundle_file,
            } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let bundle = Profile::load_identity_bundle_file(bundle_file)?;
                let mut driver = load_driver(&profile)?;
                let bundle =
                    import_identity_bundle_into_profile(&mut profile, &mut driver, bundle).await?;
                self.print_value(&serde_json::json!({
                    "imported": true,
                    "user_id": bundle.user_id,
                    "device_count": bundle.devices.len(),
                }))
            }
            ContactSubcommand::Refresh { profile, user_id } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                driver
                    .run_command_until_idle(CoreCommand::RefreshIdentityState {
                        user_id: user_id.clone(),
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                self.print_value(&serde_json::json!({ "refreshed": true, "user_id": user_id }))
            }
            ContactSubcommand::Show { profile, user_id } => {
                let profile = Profile::open(resolve_profile_path(profile)?)?;
                let driver = load_driver(&profile)?;
                let bundle = driver
                    .contact_bundle(&user_id)
                    .ok_or_else(|| anyhow!("contact not found"))?;
                self.print_value(bundle)
            }
            ContactSubcommand::List { profile } => {
                let profile = Profile::open(resolve_profile_path(profile)?)?;
                let snapshot = profile.load_snapshot()?;
                let driver = load_driver(&profile)?;
                let contacts: Vec<_> = snapshot
                    .contacts
                    .iter()
                    .map(|contact| {
                        serde_json::json!({
                            "user_id": contact.user_id,
                            "device_count": driver.contact_devices(&contact.user_id).len(),
                        })
                    })
                    .collect();
                self.print_value(&contacts)
            }
            ContactSubcommand::Requests(command) => self.run_contact_requests(command).await,
            ContactSubcommand::Allowlist(command) => self.run_contact_allowlist(command).await,
        }
    }

    async fn run_contact_requests(&self, command: ContactRequestsCommand) -> Result<()> {
        match command.command {
            ContactRequestsSubcommand::List { profile } => {
                let profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                let output = driver
                    .run_command_until_idle(CoreCommand::ListMessageRequests)
                    .await?;
                self.print_value(message_requests_from_output(&output)?)
            }
            ContactRequestsSubcommand::Accept {
                profile,
                request_id,
            } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                let result = accept_message_request_with_bundle_import(
                    &mut profile,
                    &mut driver,
                    &request_id,
                )
                .await?;
                self.print_value(&serde_json::json!({
                    "accepted": result.accepted,
                    "request_id": result.request_id,
                    "sender_user_id": result.sender_user_id,
                    "promoted_count": result.promoted_count,
                    "action": result.action,
                }))
            }
            ContactRequestsSubcommand::Reject {
                profile,
                request_id,
            } => {
                let profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                let output = driver
                    .run_command_until_idle(CoreCommand::ActOnMessageRequest {
                        request_id,
                        action: crate::transport_contract::MessageRequestAction::Reject,
                    })
                    .await?;
                let result = message_request_action_from_output(&output)?;
                self.print_value(&serde_json::json!({
                    "rejected": result.accepted,
                    "request_id": result.request_id,
                    "sender_user_id": result.sender_user_id,
                    "promoted_count": result.promoted_count,
                    "action": result.action,
                }))
            }
        }
    }

    async fn run_contact_allowlist(&self, command: ContactAllowlistCommand) -> Result<()> {
        match command.command {
            ContactAllowlistSubcommand::List { profile } => {
                let profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                let output = driver
                    .run_command_until_idle(CoreCommand::ListAllowlist)
                    .await?;
                self.print_value(allowlist_from_output(&output)?)
            }
            ContactAllowlistSubcommand::Add { profile, user_id } => {
                let profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                let output = driver
                    .run_command_until_idle(CoreCommand::AddAllowlistUser {
                        user_id: user_id.clone(),
                    })
                    .await?;
                self.print_value(&serde_json::json!({
                    "updated": true,
                    "user_id": user_id,
                    "allowlist": allowlist_from_output(&output)?,
                }))
            }
            ContactAllowlistSubcommand::Remove { profile, user_id } => {
                let profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                let output = driver
                    .run_command_until_idle(CoreCommand::RemoveAllowlistUser {
                        user_id: user_id.clone(),
                    })
                    .await?;
                self.print_value(&serde_json::json!({
                    "updated": true,
                    "user_id": user_id,
                    "allowlist": allowlist_from_output(&output)?,
                }))
            }
        }
    }
    async fn run_conversation(&self, command: ConversationCommand) -> Result<()> {
        match command.command {
            ConversationSubcommand::CreateDirect {
                profile,
                peer_user_id,
            } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                driver
                    .run_command_until_idle(CoreCommand::CreateConversation {
                        peer_user_id: peer_user_id.clone(),
                        conversation_kind: ConversationKind::Direct,
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                let snapshot = profile.load_snapshot()?;
                let conversation = snapshot
                    .conversations
                    .into_iter()
                    .find(|conversation| conversation.state.peer_user_id == peer_user_id)
                    .ok_or_else(|| anyhow!("conversation was not persisted"))?;
                self.print_value(&serde_json::json!({
                    "created": true,
                    "conversation_id": conversation.conversation_id,
                }))
            }
            ConversationSubcommand::List { profile } => {
                let profile = Profile::open(resolve_profile_path(profile)?)?;
                let snapshot = profile.load_snapshot()?;
                let driver = load_driver(&profile)?;
                let rows: Vec<_> = snapshot
                    .conversations
                    .iter()
                    .map(|conversation| {
                        let state = driver.conversation_state(&conversation.conversation_id);
                        serde_json::json!({
                            "conversation_id": conversation.conversation_id,
                            "peer_user_id": conversation.state.peer_user_id,
                            "state": conversation.state.conversation.state,
                            "recovery_status": state.map(|value| value.recovery_status),
                        })
                    })
                    .collect();
                self.print_value(&rows)
            }
            ConversationSubcommand::Show {
                profile,
                conversation_id,
            } => {
                let profile = Profile::open(resolve_profile_path(profile)?)?;
                let driver = load_driver(&profile)?;
                let state = driver
                    .conversation_state(&conversation_id)
                    .ok_or_else(|| anyhow!("conversation not found"))?;
                let local_device_id = local_device_id(&driver)?;
                self.print_value(&serde_json::json!({
                    "conversation_id": conversation_id,
                    "peer_user_id": state.peer_user_id,
                    "conversation_state": state.conversation.state,
                    "recovery_status": state.recovery_status,
                    "message_count": state.messages.len(),
                    "mls_status": driver.mls_status(&conversation_id),
                    "recovery": driver.recovery_context_snapshot(&conversation_id),
                    "checkpoint": driver.sync_checkpoint_snapshot(&local_device_id),
                    "realtime": driver.realtime_session_snapshot(&local_device_id),
                }))
            }
            ConversationSubcommand::Members {
                profile,
                conversation_id,
            } => {
                let profile = Profile::open(resolve_profile_path(profile)?)?;
                let driver = load_driver(&profile)?;
                self.print_value(&driver.conversation_members(&conversation_id))
            }
            ConversationSubcommand::Rebuild {
                profile,
                conversation_id,
            } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                driver
                    .run_command_until_idle(CoreCommand::RebuildConversation {
                        conversation_id: conversation_id.clone(),
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                self.print_value(
                    &serde_json::json!({ "rebuilt": true, "conversation_id": conversation_id }),
                )
            }
            ConversationSubcommand::Reconcile {
                profile,
                conversation_id,
            } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                driver
                    .run_command_until_idle(CoreCommand::ReconcileConversationMembership {
                        conversation_id: conversation_id.clone(),
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                self.print_value(
                    &serde_json::json!({ "reconciled": true, "conversation_id": conversation_id }),
                )
            }
        }
    }

    async fn run_message(&self, command: MessageCommand) -> Result<()> {
        match command.command {
            MessageSubcommand::SendText {
                profile,
                conversation_id,
                text,
            } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                let notification_offset = driver.notifications().len();
                let output = driver
                    .run_command_until_idle(CoreCommand::SendTextMessage {
                        conversation_id: conversation_id.clone(),
                        plaintext: text,
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                self.print_value(&serde_json::json!({
                    "sent": true,
                    "conversation_id": conversation_id,
                    "pending_outbox": driver.pending_outbox_count(),
                    "append_result": append_result_from_output(&output),
                    "latest_notification": latest_notification_since(&driver, notification_offset),
                }))
            }
            MessageSubcommand::SendAttachment {
                profile,
                conversation_id,
                file,
            } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                let descriptor = attachment_descriptor(&file)?;
                let notification_offset = driver.notifications().len();
                let output = driver
                    .run_command_until_idle(CoreCommand::SendAttachmentMessage {
                        conversation_id: conversation_id.clone(),
                        attachment_descriptor: descriptor,
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                self.print_value(&serde_json::json!({
                    "queued": true,
                    "conversation_id": conversation_id,
                    "file": file,
                    "pending_outbox": driver.pending_outbox_count(),
                    "pending_blob_uploads": driver.pending_blob_upload_count(),
                    "append_result": append_result_from_output(&output),
                    "latest_notification": latest_notification_since(&driver, notification_offset),
                }))
            }
            MessageSubcommand::DownloadAttachment {
                profile,
                conversation_id,
                message_id,
                reference,
                out,
            } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let destination = out.unwrap_or_else(|| {
                    profile
                        .metadata()
                        .inbox_attachments_dir
                        .join(format!("{message_id}.bin"))
                });
                let mut driver = load_driver(&profile)?;
                driver
                    .run_command_until_idle(CoreCommand::DownloadAttachment {
                        conversation_id: conversation_id.clone(),
                        message_id: message_id.clone(),
                        reference,
                        destination: destination.to_string_lossy().to_string(),
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                self.print_value(&serde_json::json!({
                    "downloaded": true,
                    "conversation_id": conversation_id,
                    "message_id": message_id,
                    "destination": destination,
                }))
            }
            MessageSubcommand::List {
                profile,
                conversation_id,
            } => {
                let profile = Profile::open(resolve_profile_path(profile)?)?;
                let driver = load_driver(&profile)?;
                let state = driver
                    .conversation_state(&conversation_id)
                    .ok_or_else(|| anyhow!("conversation not found"))?;
                self.print_value(&state.messages)
            }
        }
    }

    async fn run_sync(&self, command: SyncCommand) -> Result<()> {
        match command.command {
            SyncSubcommand::Once { profile } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                let device_id = local_device_id(&driver)?;
                driver
                    .run_command_until_idle_without_realtime(CoreCommand::SyncInbox {
                        device_id: device_id.clone(),
                        reason: Some("cli_once".into()),
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                self.print_value(&serde_json::json!({
                    "synced": true,
                    "device_id": device_id,
                    "checkpoint": driver.sync_checkpoint_snapshot(&device_id),
                    "realtime": driver.realtime_session_snapshot(&device_id),
                    "notifications": driver.notifications(),
                    "recovery_conversations": driver.recovery_conversations(),
                }))
            }
            SyncSubcommand::Foreground { profile } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                driver
                    .inject_event_until_idle(CoreEvent::AppForegrounded)
                    .await?;
                persist_driver(&mut profile, &driver)?;
                self.print_value(&serde_json::json!({ "foreground_sync": true }))
            }
            SyncSubcommand::RealtimeConnect { profile } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                driver
                    .inject_event_until_idle(CoreEvent::AppForegrounded)
                    .await?;
                self.print_value(&serde_json::json!({
                    "realtime": "connected",
                    "device_id": local_device_id(&driver)?,
                }))?;
                loop {
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => {
                            let device_id = local_device_id(&driver)?;
                            driver.close_realtime(&device_id).await?;
                            persist_driver(&mut profile, &driver)?;
                            break;
                        }
                        result = driver.pump_until_idle(tokio::time::Duration::from_secs(1)) => {
                            result?;
                            persist_driver(&mut profile, &driver)?;
                        }
                    }
                }
                Ok(())
            }
            SyncSubcommand::RealtimeClose { profile } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                let device_id = local_device_id(&driver)?;
                driver.close_realtime(&device_id).await?;
                persist_driver(&mut profile, &driver)?;
                self.print_value(
                    &serde_json::json!({ "realtime": "closed", "device_id": device_id }),
                )
            }
            SyncSubcommand::Status { profile } => {
                let profile = Profile::open(resolve_profile_path(profile)?)?;
                let driver = load_driver(&profile)?;
                let device_id = local_device_id(&driver)?;
                self.print_value(&serde_json::json!({
                    "device_id": device_id,
                    "checkpoint": driver.sync_checkpoint_snapshot(&device_id),
                    "realtime": driver.realtime_session_snapshot(&device_id),
                    "notifications": driver.notifications(),
                    "pending_outbox": driver.pending_outbox_count(),
                    "pending_blob_uploads": driver.pending_blob_upload_count(),
                    "recovery_conversations": driver.recovery_conversations(),
                }))
            }
            SyncSubcommand::Head { profile, device_id } => {
                let profile = Profile::open(resolve_profile_path(profile)?)?;
                let driver = load_driver(&profile)?;
                let deployment = load_deployment_from_snapshot(profile.load_snapshot()?)?;
                let device_id = device_id.unwrap_or(local_device_id(&driver)?);
                let head = get_head(&deployment, &device_id).await?;
                self.print_value(&serde_json::json!({
                    "device_id": device_id,
                    "head_seq": head.head_seq,
                }))
            }
        }
    }

    async fn run_runtime(&self, command: RuntimeCommand) -> Result<()> {
        match command.command {
            RuntimeSubcommand::LocalStart {
                profile,
                workspace_root,
            } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                let identity = driver
                    .local_identity()
                    .cloned()
                    .ok_or_else(|| anyhow!("local identity is not initialized"))?;
                let resolved_workspace_root = resolve_workspace_root(
                    workspace_root.as_deref(),
                    Some(profile.metadata().root_dir.as_path()),
                )?;
                let service_root = resolve_service_root(
                    workspace_root.as_deref(),
                    Some(profile.metadata().root_dir.as_path()),
                )?;
                let persist_dir = profile.metadata().runtime_dir.join("cloudflare-data");
                std::fs::create_dir_all(&persist_dir)?;
                let instance = start_local_runtime(&service_root, &persist_dir)?;
                wait_until_ready(&instance.base_url).await?;
                let bundle = bootstrap_device_bundle(
                    &instance.base_url,
                    &instance.bootstrap_secret,
                    &identity.user_identity.user_id,
                    &identity.device_identity.device_id,
                )
                .await?;
                driver
                    .run_command_until_idle(CoreCommand::ImportDeploymentBundle {
                        bundle: bundle.clone(),
                    })
                    .await?;
                profile.save_deployment_bundle(&bundle)?;
                profile.save_runtime_metadata(&RuntimeMetadata {
                    pid: Some(instance.pid),
                    base_url: Some(instance.base_url.clone()),
                    websocket_base_url: Some(instance.websocket_base_url.clone()),
                    bootstrap_secret: Some(instance.bootstrap_secret),
                    sharing_secret: Some(instance.sharing_secret),
                    mode: Some("local".into()),
                    workspace_root: Some(resolved_workspace_root),
                    service_root: Some(instance.service_root.clone()),
                    worker_name: None,
                    public_base_url: None,
                    deploy_url: None,
                    deployment_region: None,
                    bucket_name: None,
                    preview_bucket_name: None,
                    last_deployed_at: None,
                })?;
                persist_driver(&mut profile, &driver)?;
                self.print_value(&serde_json::json!({
                    "started": true,
                    "pid": instance.pid,
                    "base_url": instance.base_url,
                    "websocket_base_url": instance.websocket_base_url,
                    "workspace_root": profile.load_runtime_metadata()?.workspace_root,
                    "service_root": profile.load_runtime_metadata()?.service_root,
                    "user_id": identity.user_identity.user_id,
                    "device_id": identity.device_identity.device_id,
                }))
            }
            RuntimeSubcommand::LocalStop { profile } => {
                let profile = Profile::open(resolve_profile_path(profile)?)?;
                let runtime = profile.load_runtime_metadata()?;
                let pid = runtime
                    .pid
                    .ok_or_else(|| anyhow!("no runtime pid recorded"))?;
                stop_local_runtime(pid)?;
                profile.clear_runtime_metadata()?;
                self.print_value(&serde_json::json!({ "stopped": true, "pid": pid }))
            }
            RuntimeSubcommand::LocalStatus { profile } => {
                let profile = Profile::open(resolve_profile_path(profile)?)?;
                let runtime = profile.load_runtime_metadata()?;
                self.print_value(&serde_json::json!({
                    "pid": runtime.pid,
                    "base_url": runtime.base_url,
                    "websocket_base_url": runtime.websocket_base_url,
                    "bootstrap_secret": runtime.bootstrap_secret,
                    "sharing_secret": runtime.sharing_secret,
                    "mode": runtime.mode,
                    "workspace_root": runtime.workspace_root,
                    "service_root": runtime.service_root,
                }))
            }
            RuntimeSubcommand::Cloudflare(command) => self.run_cloudflare_runtime(command).await,
        }
    }

    async fn run_cloudflare_runtime(&self, command: CloudflareRuntimeCommand) -> Result<()> {
        match command.command {
            CloudflareRuntimeSubcommand::Provision(command) => {
                self.run_cloudflare_provision(command).await
            }
            CloudflareRuntimeSubcommand::Status { profile } => {
                let profile = Profile::open(resolve_profile_path(profile)?)?;
                let runtime = profile.load_runtime_metadata()?;
                self.print_value(&serde_json::json!({
                    "mode": runtime.mode,
                    "worker_name": runtime.worker_name,
                    "public_base_url": runtime.public_base_url,
                    "deploy_url": runtime.deploy_url,
                    "deployment_region": runtime.deployment_region,
                    "bucket_name": runtime.bucket_name,
                    "preview_bucket_name": runtime.preview_bucket_name,
                    "service_root": runtime.service_root,
                    "deployment_bound": profile.metadata().deployment_bundle_path.is_some(),
                    "user_id": profile.metadata().user_id,
                    "device_id": profile.metadata().device_id,
                }))
            }
            CloudflareRuntimeSubcommand::Redeploy { profile } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let runtime = profile.load_runtime_metadata()?;
                ensure_cloudflare_runtime_metadata(&runtime)?;
                let mut driver = load_driver(&profile)?;
                let identity = driver
                    .local_identity()
                    .cloned()
                    .ok_or_else(|| anyhow!("local identity is not initialized"))?;
                let service_root = runtime
                    .service_root
                    .clone()
                    .ok_or_else(|| anyhow!("cloudflare service_root is not recorded"))?;
                let config = rebuild_cloudflare_config(&runtime)?;
                self.provision_cloudflare_profile(
                    &mut profile,
                    &mut driver,
                    &identity.user_identity.user_id,
                    &identity.device_identity.device_id,
                    &service_root,
                    config,
                )
                .await
            }
            CloudflareRuntimeSubcommand::RotateSecrets { profile } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let runtime = profile.load_runtime_metadata()?;
                ensure_cloudflare_runtime_metadata(&runtime)?;
                let mut driver = load_driver(&profile)?;
                let identity = driver
                    .local_identity()
                    .cloned()
                    .ok_or_else(|| anyhow!("local identity is not initialized"))?;
                let service_root = runtime
                    .service_root
                    .clone()
                    .ok_or_else(|| anyhow!("cloudflare service_root is not recorded"))?;
                let mut defaults = derive_cloudflare_defaults(
                    &profile.metadata().name,
                    &identity.user_identity.user_id,
                    &identity.device_identity.device_id,
                );
                defaults.worker_name = runtime.worker_name.clone().unwrap_or(defaults.worker_name);
                defaults.public_base_url = runtime.public_base_url.clone().unwrap_or_default();
                defaults.deployment_region = runtime
                    .deployment_region
                    .clone()
                    .unwrap_or(defaults.deployment_region);
                defaults.bucket_name = runtime.bucket_name.clone().unwrap_or(defaults.bucket_name);
                defaults.preview_bucket_name = runtime
                    .preview_bucket_name
                    .clone()
                    .unwrap_or(defaults.preview_bucket_name);
                let config = resolve_cloudflare_config(
                    &defaults,
                    &super::runtime::CloudflareDeployOverrides::default(),
                );
                self.provision_cloudflare_profile(
                    &mut profile,
                    &mut driver,
                    &identity.user_identity.user_id,
                    &identity.device_identity.device_id,
                    &service_root,
                    config,
                )
                .await
            }
            CloudflareRuntimeSubcommand::Detach { profile } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut snapshot = profile.load_snapshot()?;
                snapshot.deployment = None;
                profile.save_snapshot(&snapshot)?;
                profile.clear_runtime_metadata()?;
                profile.clear_deployment_bundle_path()?;
                self.print_value(&serde_json::json!({
                    "detached": true,
                    "profile": profile.root(),
                }))
            }
        }
    }

    async fn run_cloudflare_provision(&self, command: CloudflareProvisionCommand) -> Result<()> {
        match command.command {
            CloudflareProvisionSubcommand::Auto { profile } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                let identity = driver
                    .local_identity()
                    .cloned()
                    .ok_or_else(|| anyhow!("local identity is not initialized"))?;
                let service_root = resolve_service_root(
                    None,
                    Some(profile.metadata().root_dir.as_path()),
                )?;
                let defaults = derive_cloudflare_defaults(
                    &profile.metadata().name,
                    &identity.user_identity.user_id,
                    &identity.device_identity.device_id,
                );
                let config = resolve_cloudflare_config(
                    &defaults,
                    &super::runtime::CloudflareDeployOverrides::default(),
                );
                self.provision_cloudflare_profile(
                    &mut profile,
                    &mut driver,
                    &identity.user_identity.user_id,
                    &identity.device_identity.device_id,
                    &service_root,
                    config,
                )
                .await
            }
            CloudflareProvisionSubcommand::Custom { profile } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                let identity = driver
                    .local_identity()
                    .cloned()
                    .ok_or_else(|| anyhow!("local identity is not initialized"))?;
                let service_root = resolve_service_root(
                    None,
                    Some(profile.metadata().root_dir.as_path()),
                )?;
                let defaults = derive_cloudflare_defaults(
                    &profile.metadata().name,
                    &identity.user_identity.user_id,
                    &identity.device_identity.device_id,
                );
                let overrides = prompt_cloudflare_overrides(&defaults)?;
                let config = resolve_cloudflare_config(&defaults, &overrides);
                self.provision_cloudflare_profile(
                    &mut profile,
                    &mut driver,
                    &identity.user_identity.user_id,
                    &identity.device_identity.device_id,
                    &service_root,
                    config,
                )
                .await
            }
        }
    }
    async fn run_identity_command(
        &self,
        profile_root: Option<PathBuf>,
        device_name: String,
        mnemonic_file: Option<PathBuf>,
        additional: bool,
    ) -> Result<()> {
        let mut profile = Profile::open(resolve_profile_path(profile_root)?)?;
        let mut driver = load_driver(&profile)?;
        let mnemonic = match mnemonic_file {
            Some(path) => Some(read_trimmed_string(path)?),
            None => None,
        };
        let command = if additional {
            CoreCommand::CreateAdditionalDeviceIdentity {
                mnemonic,
                device_name: Some(device_name),
            }
        } else {
            CoreCommand::CreateOrLoadIdentity {
                mnemonic,
                device_name: Some(device_name),
            }
        };
        driver.run_command_until_idle(command).await?;
        persist_driver(&mut profile, &driver)?;
        let identity = driver
            .local_identity()
            .ok_or_else(|| anyhow!("identity creation did not persist local identity"))?;
        self.print_value(&serde_json::json!({
            "user_id": identity.user_identity.user_id,
            "device_id": identity.device_identity.device_id,
            "mnemonic": identity.mnemonic,
        }))
    }

    async fn provision_cloudflare_profile(
        &self,
        profile: &mut Profile,
        driver: &mut CoreDriver,
        user_id: &str,
        device_id: &str,
        service_root: &Path,
        config: super::runtime::ResolvedCloudflareDeployConfig,
    ) -> Result<()> {
        let deployment = deploy_cloudflare_runtime(service_root, &config).await?;
        wait_until_ready(&deployment.effective_public_base_url).await?;
        let bundle = bootstrap_device_bundle(
            &deployment.effective_public_base_url,
            &config.bootstrap_token_secret,
            user_id,
            device_id,
        )
        .await?;
        driver
            .run_command_until_idle(CoreCommand::ImportDeploymentBundle {
                bundle: bundle.clone(),
            })
            .await?;
        profile.save_deployment_bundle(&bundle)?;
        profile.save_runtime_metadata(&RuntimeMetadata {
            pid: None,
            base_url: Some(deployment.effective_public_base_url.clone()),
            websocket_base_url: None,
            bootstrap_secret: Some(config.bootstrap_token_secret.clone()),
            sharing_secret: Some(config.sharing_token_secret.clone()),
            mode: Some("cloudflare".into()),
            workspace_root: service_root.parent().and_then(|value| value.parent()).map(PathBuf::from),
            service_root: Some(service_root.to_path_buf()),
            worker_name: Some(deployment.worker_name.clone()),
            public_base_url: Some(deployment.effective_public_base_url.clone()),
            deploy_url: Some(deployment.deploy_url.clone()),
            deployment_region: Some(deployment.deployment_region.clone()),
            bucket_name: Some(deployment.bucket_name.clone()),
            preview_bucket_name: Some(deployment.preview_bucket_name.clone()),
            last_deployed_at: Some(format!("{:?}", std::time::SystemTime::now())),
        })?;
        persist_driver(profile, driver)?;
        self.print_value(&serde_json::json!({
            "provisioned": true,
            "mode": "cloudflare",
            "worker_name": deployment.worker_name,
            "public_base_url": deployment.effective_public_base_url,
            "deploy_url": deployment.deploy_url,
            "bucket_name": deployment.bucket_name,
            "preview_bucket_name": deployment.preview_bucket_name,
            "deployment_region": deployment.deployment_region,
            "generated_secrets": deployment.generated_secrets,
            "user_id": user_id,
            "device_id": device_id,
        }))
    }

    fn print_value<T: Serialize>(&self, value: &T) -> Result<()> {
        match self.output {
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(value)?),
            OutputFormat::Text => println!("{}", serde_json::to_string_pretty(value)?),
        }
        Ok(())
    }
}

fn resolve_profile_path(profile: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(profile) = profile {
        return Ok(profile);
    }
    Ok(ProfileRegistry::load()?.current()?.root_dir.clone())
}

fn load_driver(profile: &Profile) -> Result<CoreDriver> {
    let snapshot = profile.load_snapshot()?;
    let base_url = snapshot
        .deployment
        .as_ref()
        .map(|deployment| deployment.deployment_bundle.inbox_http_endpoint.clone());
    CoreDriver::from_snapshot(snapshot, base_url, None)
}

fn load_deployment_from_snapshot(snapshot: CorePersistenceSnapshot) -> Result<DeploymentBundle> {
    snapshot
        .deployment
        .map(|deployment| deployment.deployment_bundle)
        .ok_or_else(|| anyhow!("deployment bundle is not configured"))
}

fn attachment_descriptor(path: &Path) -> Result<AttachmentDescriptor> {
    let metadata =
        std::fs::metadata(path).with_context(|| format!("read metadata for {}", path.display()))?;
    let file_name = path
        .file_name()
        .map(|value| value.to_string_lossy().to_string());
    let mime_type = match path.extension().and_then(|value| value.to_str()) {
        Some("txt") => "text/plain",
        Some("json") => "application/json",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("png") => "image/png",
        Some("pdf") => "application/pdf",
        _ => "application/octet-stream",
    };
    Ok(AttachmentDescriptor {
        attachment_id: path.to_string_lossy().to_string(),
        mime_type: mime_type.to_string(),
        size_bytes: metadata.len(),
        file_name,
    })
}

fn read_trimmed_string(path: impl AsRef<Path>) -> Result<String> {
    Ok(std::fs::read_to_string(path)?.trim().to_string())
}

fn local_device_id(driver: &CoreDriver) -> Result<String> {
    driver
        .local_identity()
        .map(|identity| identity.device_identity.device_id.clone())
        .ok_or_else(|| anyhow!("local identity is not initialized"))
}

fn allowlist_from_output(output: &crate::ffi_api::CoreOutput) -> Result<&AllowlistDocument> {
    output
        .view_model
        .as_ref()
        .and_then(|view| view.allowlist.as_ref())
        .ok_or_else(|| anyhow!("allowlist document was not returned by core"))
}

fn latest_notification_since(driver: &crate::cli::driver::CoreDriver, offset: usize) -> Option<String> {
    driver
        .notifications()
        .get(offset..)
        .and_then(|notifications| notifications.last().cloned())
}

fn append_result_from_output(
    output: &crate::ffi_api::CoreOutput,
) -> Option<&crate::ffi_api::AppendResultSummary> {
    output
        .view_model
        .as_ref()
        .and_then(|view| view.append_result.as_ref())
}

fn ensure_cloudflare_runtime_metadata(runtime: &RuntimeMetadata) -> Result<()> {
    if runtime.mode.as_deref() != Some("cloudflare") {
        bail!("runtime metadata is not bound to a cloudflare deployment");
    }
    Ok(())
}

fn rebuild_cloudflare_config(
    runtime: &RuntimeMetadata,
) -> Result<super::runtime::ResolvedCloudflareDeployConfig> {
    Ok(super::runtime::ResolvedCloudflareDeployConfig {
        worker_name: runtime
            .worker_name
            .clone()
            .ok_or_else(|| anyhow!("cloudflare worker_name is not recorded"))?,
        public_base_url: runtime.public_base_url.clone().unwrap_or_default(),
        deployment_region: runtime
            .deployment_region
            .clone()
            .unwrap_or_else(|| "global".into()),
        max_inline_bytes: "4096".into(),
        retention_days: "30".into(),
        rate_limit_per_minute: "60".into(),
        rate_limit_per_hour: "600".into(),
        bucket_name: runtime
            .bucket_name
            .clone()
            .ok_or_else(|| anyhow!("cloudflare bucket_name is not recorded"))?,
        preview_bucket_name: runtime
            .preview_bucket_name
            .clone()
            .ok_or_else(|| anyhow!("cloudflare preview_bucket_name is not recorded"))?,
        sharing_token_secret: runtime
            .sharing_secret
            .clone()
            .ok_or_else(|| anyhow!("cloudflare sharing_secret is not recorded"))?,
        bootstrap_token_secret: runtime
            .bootstrap_secret
            .clone()
            .ok_or_else(|| anyhow!("cloudflare bootstrap_secret is not recorded"))?,
    })
}

async fn get_head(bundle: &DeploymentBundle, device_id: &str) -> Result<GetHeadResult> {
    let auth = bundle
        .device_runtime_auth
        .as_ref()
        .ok_or_else(|| anyhow!("deployment bundle missing device runtime auth"))?;
    let client = Client::builder().build().context("build reqwest client")?;
    let response = client
        .get(format!(
            "{}/v1/inbox/{}/head",
            bundle.inbox_http_endpoint.trim_end_matches('/'),
            urlencoding::encode(device_id)
        ))
        .header("Authorization", format!("Bearer {}", auth.token))
        .send()
        .await
        .context("get head request")?;
    if !response.status().is_success() {
        bail!("get head failed with status {}", response.status());
    }
    let body = response.text().await?;
    Ok(serde_json::from_str(&to_snake_case_json_string(&body)?)?)
}



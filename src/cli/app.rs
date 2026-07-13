use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use reqwest::Client;
use serde::Serialize;

use crate::contact_workflows::{
    accept_message_request_with_bundle_import, import_identity_bundle_into_profile,
    list_message_requests, message_request_action_from_output, message_requests_from_output,
    persist_driver,
};
use crate::external_fetch::{ExternalNetworkClass, ExternalResourceKind};
use crate::ffi_api::{AttachmentDescriptor, CoreCommand, CoreEvent};
use crate::model::{ConversationKind, DeploymentBundle, DeviceStatusKind, Validate};
use crate::passphrase_strength::evaluate_passphrase_strength;
use crate::persistence::CorePersistenceSnapshot;
use crate::transport_contract::{AllowlistDocument, GetHeadResult};

use super::args::{
    Cli, CloudflareProvisionCommand, CloudflareProvisionSubcommand, CloudflareRuntimeCommand,
    CloudflareRuntimeSubcommand, Command, ContactAllowlistCommand, ContactAllowlistSubcommand,
    ContactCommand, ContactRequestsCommand, ContactRequestsSubcommand, ContactSubcommand,
    ConversationCommand, ConversationSubcommand, DeviceCommand, DeviceSubcommand, GroupCommand,
    GroupInviteCommand, GroupInviteSubcommand, GroupJoinCommand, GroupJoinSubcommand,
    GroupMemberCommand, GroupMemberSubcommand, GroupSubcommand, MessageCommand, MessageSubcommand,
    OutputFormat, ProfileCommand, ProfileKeychainCommand, ProfileKeychainSubcommand,
    ProfileSubcommand, RuntimeCommand, RuntimeSubcommand, SyncCommand, SyncSubcommand,
};
use super::driver::CoreDriver;
use super::profile::{Profile, ProfileInitOptions, ProfileRegistry, RuntimeMetadata};
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
            Command::Group(command) => self.run_group(command).await,
            Command::Sync(command) => self.run_sync(command).await,
            Command::Runtime(command) => self.run_runtime(command).await,
        }
    }

    async fn run_profile(&self, command: ProfileCommand) -> Result<()> {
        match command.command {
            ProfileSubcommand::Init {
                name,
                root,
                passphrase_stdin,
                no_keychain,
                allow_weak_passphrase,
            } => {
                let passphrase = if passphrase_stdin {
                    let mut passphrase = String::new();
                    std::io::stdin()
                        .read_to_string(&mut passphrase)
                        .context("read passphrase from stdin")?;
                    Some(passphrase.trim_end_matches(['\r', '\n']).to_string())
                } else if let Ok(passphrase) = std::env::var("TAPCHAT_PROFILE_PASSPHRASE") {
                    Some(passphrase)
                } else {
                    None
                };
                enforce_profile_passphrase_policy(
                    passphrase.as_deref(),
                    &name,
                    allow_weak_passphrase,
                )?;
                let profile = Profile::init_with_options(
                    &name,
                    &root,
                    ProfileInitOptions {
                        passphrase,
                        use_keychain: !no_keychain,
                    },
                )?;
                self.print_value(profile.metadata())
            }
            ProfileSubcommand::Show { profile } => {
                let profile = Profile::open(resolve_profile_path(profile)?)?;
                let runtime = profile.load_runtime_metadata()?;
                let storage = profile.storage_diagnostics()?;
                self.print_value(&serde_json::json!({
                    "profile": profile.metadata(),
                    "runtime": runtime,
                    "storage": storage,
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
            ProfileSubcommand::Delete { profile } => {
                let mut registry = ProfileRegistry::load()?;
                if registry.active_profile.as_ref() == Some(&profile) {
                    bail!("cannot delete the active profile; activate another profile first");
                }
                if !registry
                    .profiles
                    .iter()
                    .any(|entry| entry.root_dir == profile)
                {
                    bail!(
                        "profile {} is not registered on this device",
                        profile.display()
                    );
                }
                let keychain_cleanup = Profile::cleanup_profile_keychain_entries(&profile)?;
                if profile.exists() {
                    std::fs::remove_dir_all(&profile).with_context(|| {
                        format!("delete profile directory {}", profile.display())
                    })?;
                }
                registry.remove(&profile);
                registry.save()?;
                self.print_value(&serde_json::json!({
                    "deleted": true,
                    "profile": profile,
                    "active_profile": registry.active_profile,
                    "keychain_cleanup": keychain_cleanup,
                }))
            }
            ProfileSubcommand::Keychain(ProfileKeychainCommand { command }) => match command {
                ProfileKeychainSubcommand::Doctor => {
                    let report = Profile::keychain_doctor()?;
                    self.print_value(&report)
                }
                ProfileKeychainSubcommand::Cleanup { dry_run, apply } => {
                    let report = Profile::cleanup_orphan_keychain_entries(dry_run || !apply)?;
                    self.print_value(&report)
                }
            },
        }
    }

    async fn run_device(&self, command: DeviceCommand) -> Result<()> {
        match command.command {
            DeviceSubcommand::Create {
                profile,
                device_name,
                display_name,
                mnemonic_file,
            } => {
                self.run_identity_command(profile, device_name, display_name, mnemonic_file, false)
                    .await
            }
            DeviceSubcommand::Recover {
                profile,
                device_name,
                display_name,
                mnemonic_file,
            } => {
                self.run_identity_command(
                    profile,
                    device_name,
                    display_name,
                    Some(mnemonic_file),
                    false,
                )
                .await
            }
            DeviceSubcommand::Add {
                profile,
                device_name,
                display_name,
                mnemonic_file,
            } => {
                self.run_identity_command(
                    profile,
                    device_name,
                    display_name,
                    Some(mnemonic_file),
                    true,
                )
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
                }))
            }
            DeviceSubcommand::SyncGroups { profile, device_id } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                driver
                    .run_command_until_idle(CoreCommand::SyncGroupsForNewDevice {
                        device_id: device_id.clone(),
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                self.print_value(&serde_json::json!({
                    "device_id": device_id,
                    "synced": true,
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
                allow_private_url,
            } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                let share_url = list_message_requests(&mut driver)
                    .await?
                    .into_iter()
                    .find(|request| request.request_id == request_id)
                    .and_then(|request| request.sender_bundle_share_url)
                    .ok_or_else(|| anyhow!("sender bundle share url is missing"))?;
                self.prepare_external_url(
                    &mut driver,
                    &share_url,
                    ExternalResourceKind::ContactShare,
                    allow_private_url,
                )
                .await?;
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

    async fn run_group(&self, command: GroupCommand) -> Result<()> {
        match command.command {
            GroupSubcommand::Create {
                profile,
                title,
                members,
            } => {
                if title.trim().is_empty() {
                    bail!("group title must not be empty");
                }
                let member_user_ids: Vec<String> = members
                    .into_iter()
                    .map(|value| value.trim().to_string())
                    .filter(|value| !value.is_empty())
                    .collect();
                if member_user_ids.is_empty() {
                    bail!(
                        "at least one member user id is required (pass --members as a comma separated list)"
                    );
                }
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                let output = driver
                    .run_command_until_idle(CoreCommand::CreateGroupConversation {
                        title: title.clone(),
                        member_user_ids: member_user_ids.clone(),
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                let view = output
                    .view_model
                    .as_ref()
                    .ok_or_else(|| anyhow!("core did not return a view model for group create"))?;
                let summary = view
                    .conversations
                    .first()
                    .ok_or_else(|| anyhow!("core did not return a group summary"))?;
                let group_id = summary
                    .group_id
                    .clone()
                    .ok_or_else(|| anyhow!("core created a conversation without a group id"))?;
                let welcome_pickups: Vec<_> = view
                    .welcome_pickups
                    .iter()
                    .map(|descriptor| {
                        serde_json::json!({
                            "group_id": descriptor.group_id,
                            "device_id": descriptor.device_id,
                            "endpoint": descriptor.endpoint,
                            "expires_at": descriptor.expires_at,
                            "url": welcome_pickup_url(descriptor),
                        })
                    })
                    .collect();
                self.print_value(&serde_json::json!({
                    "created": true,
                    "group_id": group_id,
                    "conversation_id": summary.conversation_id,
                    "title": summary.title,
                    "member_count": summary.member_count,
                    "group_role": summary.group_role,
                    "invited_user_ids": member_user_ids,
                    "welcome_pickups": welcome_pickups,
                    "pending_outbox": driver.pending_outbox_count(),
                }))
            }
            GroupSubcommand::List { profile } => {
                let profile = Profile::open(resolve_profile_path(profile)?)?;
                let driver = load_driver(&profile)?;
                let snapshot = profile.load_snapshot()?;
                let cursors: std::collections::BTreeMap<String, _> = snapshot
                    .group_cursors
                    .into_iter()
                    .map(|persisted| (persisted.group_id.clone(), persisted.cursor))
                    .collect();
                let rows: Vec<_> = snapshot
                    .group_states
                    .into_iter()
                    .map(|state| {
                        let conversation = driver.conversation_state(&state.conversation_id);
                        let mls_status = driver.mls_status(&state.conversation_id);
                        serde_json::json!({
                            "group_id": state.group_id,
                            "conversation_id": state.conversation_id,
                            "title": state.manifest.title,
                            "local_role": state.local_role,
                            "owner_user_id": state.manifest.owner_user_id,
                            "member_count": state.manifest.members.len(),
                            "roster_version": state.manifest.roster_version,
                            "conversation_state":
                                conversation.map(|state| state.conversation.state),
                            "recovery_status":
                                conversation.map(|state| state.recovery_status),
                            "mls_status": mls_status,
                            "cursor": cursors.get(&state.group_id),
                            "dissolved_at": state.dissolved_at,
                        })
                    })
                    .collect();
                self.print_value(&rows)
            }
            GroupSubcommand::Show { profile, group_id } => {
                let profile = Profile::open(resolve_profile_path(profile)?)?;
                let driver = load_driver(&profile)?;
                let snapshot = profile.load_snapshot()?;
                let group = snapshot
                    .group_states
                    .iter()
                    .find(|state| state.group_id == group_id)
                    .cloned()
                    .ok_or_else(|| anyhow!("group does not exist"))?;
                let cursor = snapshot
                    .group_cursors
                    .iter()
                    .find(|persisted| persisted.group_id == group_id)
                    .map(|persisted| persisted.cursor.clone());
                let invites: Vec<_> = snapshot
                    .group_invites
                    .iter()
                    .filter(|invite| invite.group_id == group_id)
                    .cloned()
                    .collect();
                let join_requests: Vec<_> = snapshot
                    .group_join_requests
                    .iter()
                    .filter(|request| request.group_id == group_id)
                    .cloned()
                    .collect();
                let conversation_state = driver.conversation_state(&group.conversation_id);
                let members = driver.conversation_members(&group.conversation_id);
                self.print_value(&serde_json::json!({
                    "group_id": group.group_id,
                    "conversation_id": group.conversation_id,
                    "manifest": group.manifest,
                    "local_role": group.local_role,
                    "welcome_pickup": group.welcome_pickup,
                    "dissolved_at": group.dissolved_at,
                    "cursor": cursor,
                    "conversation_state":
                        conversation_state.map(|state| state.conversation.state),
                    "recovery_status":
                        conversation_state.map(|state| state.recovery_status),
                    "recovery":
                        driver.recovery_context_snapshot(&group.conversation_id),
                    "mls_status": driver.mls_status(&group.conversation_id),
                    "message_count": conversation_state
                        .map(|state| state.messages.len()),
                    "members": members,
                    "invites": invites,
                    "join_requests": join_requests,
                }))
            }
            GroupSubcommand::SendText {
                profile,
                conversation_id,
                text,
            } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                let notification_offset = driver.notifications().len();
                let output = driver
                    .run_command_until_idle(CoreCommand::SendGroupTextMessage {
                        conversation_id: conversation_id.clone(),
                        plaintext: text,
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                self.print_value(&serde_json::json!({
                    "sent": true,
                    "conversation_id": conversation_id,
                    "message_id": output
                        .view_model
                        .as_ref()
                        .and_then(|view| view.messages.first())
                        .map(|msg| msg.message_id.clone()),
                    "pending_group_outbox": driver
                        .latest_snapshot()
                        .map(|snapshot| snapshot.pending_group_outbox.len())
                        .unwrap_or_default(),
                    "latest_notification":
                        latest_notification_since(&driver, notification_offset),
                }))
            }
            GroupSubcommand::SendAttachment {
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
                    "message_id": output
                        .view_model
                        .as_ref()
                        .and_then(|view| view.messages.first())
                        .map(|msg| msg.message_id.clone()),
                    "pending_group_outbox": driver
                        .latest_snapshot()
                        .map(|snapshot| snapshot.pending_group_outbox.len())
                        .unwrap_or_default(),
                    "pending_blob_uploads": driver.pending_blob_upload_count(),
                    "latest_notification":
                        latest_notification_since(&driver, notification_offset),
                }))
            }
            GroupSubcommand::DownloadAttachment {
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
            GroupSubcommand::ListMessages {
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
            GroupSubcommand::Sync { profile, group_id } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                let notification_offset = driver.notifications().len();
                driver
                    .run_command_until_idle(CoreCommand::SyncGroupOutbox {
                        group_id: group_id.clone(),
                        reason: Some("cli-group-sync".into()),
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                let snapshot = profile.load_snapshot()?;
                let cursor = snapshot
                    .group_cursors
                    .into_iter()
                    .find(|persisted| persisted.group_id == group_id)
                    .map(|persisted| persisted.cursor);
                self.print_value(&serde_json::json!({
                    "synced": true,
                    "group_id": group_id,
                    "cursor": cursor,
                    "latest_notification":
                        latest_notification_since(&driver, notification_offset),
                }))
            }
            GroupSubcommand::Leave { profile, group_id } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                driver
                    .run_command_until_idle(CoreCommand::LeaveGroup {
                        group_id: group_id.clone(),
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                let request = driver.latest_snapshot().and_then(|snapshot| {
                    snapshot
                        .group_states
                        .iter()
                        .find(|state| state.group_id == group_id)
                        .into_iter()
                        .flat_map(|state| state.leave_requests.iter())
                        .max_by_key(|persisted| persisted.request.requested_at)
                        .map(|persisted| persisted.request.clone())
                });
                self.print_value(&serde_json::json!({
                    "submitted": true,
                    "group_id": group_id,
                    "request_id": request.as_ref().map(|request| request.request_id.clone()),
                    "status": request.as_ref().map(|request| request.status),
                }))
            }
            GroupSubcommand::LeaveRequests { profile, group_id } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                let output = driver
                    .run_command_until_idle(CoreCommand::ListGroupLeaveRequests {
                        group_id: group_id.clone(),
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                let rows = output
                    .view_model
                    .as_ref()
                    .map(|view| view.group_leave_requests.clone())
                    .unwrap_or_default();
                self.print_value(&rows)
            }
            GroupSubcommand::ApproveLeave {
                profile,
                group_id,
                request_id,
            } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                let output = driver
                    .run_command_until_idle(CoreCommand::ApproveGroupLeave {
                        group_id: group_id.clone(),
                        request_id: request_id.clone(),
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                let request = output
                    .view_model
                    .as_ref()
                    .and_then(|view| {
                        view.group_leave_requests
                            .iter()
                            .find(|request| request.request_id == request_id)
                    })
                    .cloned()
                    .or_else(|| {
                        driver.latest_snapshot().and_then(|snapshot| {
                            snapshot
                                .group_states
                                .iter()
                                .find(|state| state.group_id == group_id)
                                .into_iter()
                                .flat_map(|state| state.leave_requests.iter())
                                .find(|persisted| persisted.request.request_id == request_id)
                                .map(|persisted| persisted.request.clone())
                        })
                    })
                    .ok_or_else(|| anyhow!("group leave request not found after approval"))?;
                self.print_value(&serde_json::json!({
                    "group_id": group_id,
                    "request_id": request_id,
                    "status": request.status,
                }))
            }
            GroupSubcommand::TransferOwnership {
                profile,
                group_id,
                new_owner_user_id,
            } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                driver
                    .run_command_until_idle(CoreCommand::TransferGroupOwnership {
                        group_id: group_id.clone(),
                        new_owner_user_id: new_owner_user_id.clone(),
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                self.print_value(&serde_json::json!({
                    "transferred": true,
                    "group_id": group_id,
                    "new_owner_user_id": new_owner_user_id,
                }))
            }
            GroupSubcommand::SetAdmin {
                profile,
                group_id,
                user_id,
                admin,
            } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                driver
                    .run_command_until_idle(CoreCommand::SetGroupAdmin {
                        group_id: group_id.clone(),
                        target_user_id: user_id.clone(),
                        is_admin: admin,
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                self.print_value(&serde_json::json!({
                    "updated": true,
                    "group_id": group_id,
                    "user_id": user_id,
                    "is_admin": admin,
                }))
            }
            GroupSubcommand::UpdateMetadata {
                profile,
                group_id,
                title,
                join_policy,
                member_invite_policy,
            } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                let parsed_join_policy = join_policy
                    .as_deref()
                    .map(parse_group_join_policy)
                    .transpose()?;
                let parsed_member_invite_policy = member_invite_policy
                    .as_deref()
                    .map(parse_group_member_invite_policy)
                    .transpose()?;
                driver
                    .run_command_until_idle(CoreCommand::UpdateGroupMetadata {
                        group_id: group_id.clone(),
                        title: title.clone(),
                        join_policy: parsed_join_policy,
                        member_invite_policy: parsed_member_invite_policy,
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                let snapshot = profile.load_snapshot()?;
                let manifest = snapshot
                    .group_states
                    .iter()
                    .find(|state| state.group_id == group_id)
                    .map(|state| state.manifest.clone());
                self.print_value(&serde_json::json!({
                    "updated": true,
                    "group_id": group_id,
                    "title": manifest.as_ref().map(|m| m.title.clone()),
                    "join_policy": manifest.as_ref().map(|m| m.join_policy),
                    "member_invite_policy":
                        manifest.as_ref().map(|m| m.member_invite_policy),
                    "roster_version": manifest.as_ref().map(|m| m.roster_version),
                }))
            }
            GroupSubcommand::Dissolve {
                profile,
                group_id,
                yes,
            } => self.run_group_dissolve(profile, group_id, yes).await,
            GroupSubcommand::Invite(command) => self.run_group_invite(command).await,
            GroupSubcommand::Join(command) => self.run_group_join(command).await,
            GroupSubcommand::Member(command) => self.run_group_member(command).await,
        }
    }

    /// Owner-only interactive group dissolve.
    ///
    /// Per task C.2, when `--yes` is absent the CLI MUST read a line from
    /// stdin and accept only `"y"` / `"yes"` (case-insensitive) as the
    /// confirmation token. All other inputs (including empty lines,
    /// EOF, and unrecognised strings) abort with exit code 0 and the
    /// message `"Aborted."`. This applies uniformly to interactive, CI,
    /// and piped stdin environments — there is no `isatty` bypass.
    async fn run_group_dissolve(
        &self,
        profile: Option<PathBuf>,
        group_id: String,
        yes: bool,
    ) -> Result<()> {
        use std::io::{BufRead, Write};

        if !yes {
            let mut stdout = std::io::stdout().lock();
            write!(
                stdout,
                "Dissolve group '{}'? This cannot be undone. [y/N]: ",
                group_id
            )?;
            stdout.flush()?;
            drop(stdout);

            let mut line = String::new();
            let bytes_read = std::io::stdin().lock().read_line(&mut line)?;
            if !dissolve_confirmation_accepted(bytes_read, &line) {
                println!("Aborted.");
                return Ok(());
            }
        }

        let mut profile = Profile::open(resolve_profile_path(profile)?)?;
        let mut driver = load_driver(&profile)?;
        driver
            .run_command_until_idle(CoreCommand::DissolveGroup {
                group_id: group_id.clone(),
            })
            .await?;
        persist_driver(&mut profile, &driver)?;

        let snapshot = profile.load_snapshot()?;
        let group_state = snapshot
            .group_states
            .iter()
            .find(|state| state.group_id == group_id);
        let dissolved_at = group_state.and_then(|state| state.dissolved_at);
        let conversation_state = group_state.and_then(|state| {
            snapshot
                .conversations
                .iter()
                .find(|conversation| conversation.conversation_id == state.conversation_id)
                .map(|conv| format!("{:?}", conv.state.conversation.state).to_lowercase())
        });

        self.print_value(&serde_json::json!({
            "dissolved": true,
            "group_id": group_id,
            "dissolved_at": dissolved_at,
            "conversation_state": conversation_state,
        }))
    }

    async fn prepare_external_url(
        &self,
        driver: &mut CoreDriver,
        url: &str,
        purpose: ExternalResourceKind,
        allow_private_url: bool,
    ) -> Result<()> {
        use std::io::{BufRead, Write};

        let assessment = driver.assess_external_url(url, purpose).await?;
        if assessment.network_class() == ExternalNetworkClass::Public {
            return Ok(());
        }
        if !allow_private_url {
            let mut stdout = std::io::stdout().lock();
            write!(
                stdout,
                "Allow one {} request to private origin {}{}? [y/N]: ",
                purpose.as_str(),
                assessment.origin(),
                if assessment.insecure_http() {
                    " over unencrypted HTTP"
                } else {
                    ""
                }
            )?;
            stdout.flush()?;
            drop(stdout);
            let mut line = String::new();
            let bytes_read = std::io::stdin().lock().read_line(&mut line)?;
            if !dissolve_confirmation_accepted(bytes_read, &line) {
                bail!("private_network_approval_required");
            }
        }
        driver.approve_external_url_once(assessment);
        Ok(())
    }

    async fn run_group_invite(&self, command: GroupInviteCommand) -> Result<()> {
        match command.command {
            GroupInviteSubcommand::Create {
                profile,
                group_id,
                expires_in_secs,
                max_uses,
            } => {
                if expires_in_secs == 0 {
                    bail!("expires_in_secs must be greater than zero");
                }
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|duration| duration.as_millis() as u64)
                    .context("compute current time for invite expiry")?;
                let expires_at = now_ms
                    .checked_add(expires_in_secs.saturating_mul(1_000))
                    .ok_or_else(|| anyhow!("invite expiry overflow"))?;
                let notification_offset = driver.notifications().len();
                driver
                    .run_command_until_idle(CoreCommand::CreateGroupInviteLink {
                        group_id: group_id.clone(),
                        expires_at,
                        max_uses,
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                let snapshot = profile.load_snapshot()?;
                let invite = snapshot
                    .group_invites
                    .into_iter()
                    .filter(|invite| invite.group_id == group_id)
                    .max_by_key(|invite| invite.document.created_at)
                    .ok_or_else(|| {
                        let notification = latest_notification_since(&driver, notification_offset)
                            .unwrap_or_else(|| "(no notification)".into());
                        anyhow!(
                            "group invite was not persisted (transport may have failed): {notification}"
                        )
                    })?;
                self.print_value(&serde_json::json!({
                    "created": true,
                    "group_id": group_id,
                    "invite_id": invite.invite_id,
                    "invite_url": invite.invite_url,
                    "expires_at": invite.document.expires_at,
                    "max_uses": invite.document.max_uses,
                    "join_policy": invite.document.join_policy,
                }))
            }
            GroupInviteSubcommand::Revoke {
                profile,
                group_id,
                invite_id,
            } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                driver
                    .run_command_until_idle(CoreCommand::RevokeGroupInviteLink {
                        group_id: group_id.clone(),
                        invite_id: invite_id.clone(),
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                self.print_value(&serde_json::json!({
                    "revoked": true,
                    "group_id": group_id,
                    "invite_id": invite_id,
                }))
            }
            GroupInviteSubcommand::List { profile, group_id } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                driver
                    .run_command_until_idle(CoreCommand::ListGroupInvites {
                        group_id: group_id.clone(),
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                let snapshot = profile.load_snapshot()?;
                let rows: Vec<_> = snapshot
                    .group_invites
                    .into_iter()
                    .filter(|invite| invite.group_id == group_id)
                    .map(|invite| {
                        serde_json::json!({
                            "invite_id": invite.invite_id,
                            "invite_url": invite.invite_url,
                            "expires_at": invite.document.expires_at,
                            "max_uses": invite.document.max_uses,
                            "join_policy": invite.document.join_policy,
                            "created_at": invite.document.created_at,
                            "status": invite.status,
                            "uses": invite.uses,
                            "revision": invite.revision,
                            "revoked_at": invite.revoked_at,
                        })
                    })
                    .collect();
                self.print_value(&rows)
            }
        }
    }

    async fn run_group_join(&self, command: GroupJoinCommand) -> Result<()> {
        match command.command {
            GroupJoinSubcommand::Submit {
                profile,
                invite_url,
                allow_private_url,
            } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                self.prepare_external_url(
                    &mut driver,
                    &invite_url,
                    ExternalResourceKind::GroupInvite,
                    allow_private_url,
                )
                .await?;
                let notification_offset = driver.notifications().len();
                let output = driver
                    .run_command_until_idle(CoreCommand::FetchGroupInvite {
                        invite_url: invite_url.clone(),
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                let request = output
                    .view_model
                    .as_ref()
                    .and_then(|view| view.group_join_requests.first())
                    .cloned();
                let request_id = request
                    .as_ref()
                    .map(|value| value.request_id.clone())
                    .or_else(|| {
                        driver.latest_snapshot().and_then(|snapshot| {
                            snapshot
                                .group_join_requests
                                .iter()
                                .max_by_key(|persisted| persisted.request.requested_at)
                                .map(|persisted| persisted.request_id.clone())
                        })
                    });
                self.print_value(&serde_json::json!({
                    "submitted": true,
                    "invite_url": invite_url,
                    "request_id": request_id,
                    "group_id": request.as_ref().map(|r| r.group_id.clone()),
                    "status": request.as_ref().map(|r| r.status),
                    "latest_notification":
                        latest_notification_since(&driver, notification_offset),
                }))
            }
            GroupJoinSubcommand::ByPickup { profile, pickup } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                let notification_offset = driver.notifications().len();
                driver
                    .run_command_until_idle(CoreCommand::RequestJoinGroup {
                        invite_url: pickup.clone(),
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                let snapshot = profile.load_snapshot()?;
                let latest_group = snapshot
                    .group_states
                    .into_iter()
                    .max_by_key(|state| state.manifest.updated_at);
                self.print_value(&serde_json::json!({
                    "joined": latest_group.is_some(),
                    "group_id":
                        latest_group.as_ref().map(|state| state.group_id.clone()),
                    "conversation_id":
                        latest_group.as_ref().map(|state| state.conversation_id.clone()),
                    "title":
                        latest_group.as_ref().map(|state| state.manifest.title.clone()),
                    "local_role":
                        latest_group.as_ref().and_then(|state| state.local_role),
                    "latest_notification":
                        latest_notification_since(&driver, notification_offset),
                }))
            }
            GroupJoinSubcommand::List { profile, group_id } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                let output = driver
                    .run_command_until_idle(CoreCommand::ListGroupJoinRequests {
                        group_id: group_id.clone(),
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                let rows = output
                    .view_model
                    .as_ref()
                    .map(|view| view.group_join_requests.clone())
                    .unwrap_or_default();
                self.print_value(&rows)
            }
            GroupJoinSubcommand::Approve {
                profile,
                group_id,
                request_id,
            } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                let output = driver
                    .run_command_until_idle(CoreCommand::ApproveGroupJoin {
                        group_id: group_id.clone(),
                        request_id: request_id.clone(),
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                let request = output
                    .view_model
                    .as_ref()
                    .and_then(|view| {
                        view.group_join_requests
                            .iter()
                            .find(|request| request.request_id == request_id)
                    })
                    .cloned()
                    .or_else(|| {
                        driver.latest_snapshot().and_then(|snapshot| {
                            snapshot
                                .group_join_requests
                                .iter()
                                .find(|persisted| persisted.request_id == request_id)
                                .map(|persisted| persisted.request.clone())
                        })
                    })
                    .ok_or_else(|| anyhow!("group join request not found after approval"))?;
                self.print_value(&serde_json::json!({
                    "approved": matches!(
                        request.status,
                        crate::model::GroupJoinRequestStatus::TransitionInProgress
                            | crate::model::GroupJoinRequestStatus::WelcomeAvailable
                            | crate::model::GroupJoinRequestStatus::Joined
                            | crate::model::GroupJoinRequestStatus::Approved
                    ),
                    "group_id": group_id,
                    "request_id": request_id,
                    "status": request.status,
                }))
            }
            GroupJoinSubcommand::Reject {
                profile,
                group_id,
                request_id,
                reason,
            } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                driver
                    .run_command_until_idle(CoreCommand::RejectGroupJoin {
                        group_id: group_id.clone(),
                        request_id: request_id.clone(),
                        reason: reason.clone(),
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                self.print_value(&serde_json::json!({
                    "rejected": true,
                    "group_id": group_id,
                    "request_id": request_id,
                    "reason": reason,
                }))
            }
            GroupJoinSubcommand::Status {
                profile,
                group_id,
                request_id,
            } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                driver
                    .run_command_until_idle(CoreCommand::GetGroupJoinRequestStatus {
                        group_id: group_id.clone(),
                        request_id: request_id.clone(),
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                let snapshot = profile.load_snapshot()?;
                let persisted = snapshot
                    .group_join_requests
                    .iter()
                    .find(|persisted| persisted.request_id == request_id)
                    .cloned()
                    .ok_or_else(|| anyhow!("group join request not found in snapshot"))?;
                let imported = snapshot
                    .group_states
                    .iter()
                    .any(|state| state.group_id == persisted.group_id);
                self.print_value(&serde_json::json!({
                    "group_id": persisted.group_id,
                    "request_id": persisted.request_id,
                    "status": persisted.request.status,
                    "welcome_pickup": persisted.welcome_pickup,
                    "manifest": persisted.manifest,
                    "start_cursor": persisted.start_cursor,
                    "group_imported": imported,
                }))
            }
        }
    }

    async fn run_group_member(&self, command: GroupMemberCommand) -> Result<()> {
        match command.command {
            GroupMemberSubcommand::Remove {
                profile,
                group_id,
                user_id,
            } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                driver
                    .run_command_until_idle(CoreCommand::RemoveGroupMember {
                        group_id: group_id.clone(),
                        target_user_id: user_id.clone(),
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                self.print_value(&serde_json::json!({
                    "removed": true,
                    "group_id": group_id,
                    "user_id": user_id,
                }))
            }
            GroupMemberSubcommand::AddDevice {
                profile,
                group_id,
                device_id,
            } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                let user_id = local_user_id(&driver)?;
                driver
                    .run_command_until_idle(CoreCommand::AddGroupMemberDevice {
                        group_id: group_id.clone(),
                        user_id,
                        device_id: device_id.clone(),
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                self.print_value(&serde_json::json!({
                    "device_added": true,
                    "group_id": group_id,
                    "device_id": device_id,
                }))
            }
            GroupMemberSubcommand::RemoveDevice {
                profile,
                group_id,
                device_id,
            } => {
                let mut profile = Profile::open(resolve_profile_path(profile)?)?;
                let mut driver = load_driver(&profile)?;
                let user_id = local_user_id(&driver)?;
                driver
                    .run_command_until_idle(CoreCommand::RemoveGroupMemberDevice {
                        group_id: group_id.clone(),
                        user_id,
                        device_id: device_id.clone(),
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                self.print_value(&serde_json::json!({
                    "device_removed": true,
                    "group_id": group_id,
                    "device_id": device_id,
                }))
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
                    "bootstrap_secret_present": runtime.bootstrap_secret.is_some(),
                    "sharing_secret_present": runtime.sharing_secret.is_some(),
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
                let service_root =
                    resolve_service_root(None, Some(profile.metadata().root_dir.as_path()))?;
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
                let service_root =
                    resolve_service_root(None, Some(profile.metadata().root_dir.as_path()))?;
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
        display_name: Option<String>,
        mnemonic_file: Option<PathBuf>,
        additional: bool,
    ) -> Result<()> {
        let mut profile = Profile::open(resolve_profile_path(profile_root)?)?;
        let mut driver = load_driver(&profile)?;
        let had_identity = driver.local_identity().is_some();
        let mnemonic = match mnemonic_file {
            Some(path) => Some(read_trimmed_string(path)?),
            None => None,
        };
        let supplied_mnemonic = mnemonic.is_some();
        let command = if additional {
            CoreCommand::CreateAdditionalDeviceIdentity {
                mnemonic,
                device_name: Some(device_name),
                display_name,
            }
        } else {
            CoreCommand::CreateOrLoadIdentity {
                mnemonic,
                device_name: Some(device_name),
                display_name,
            }
        };
        driver.run_command_until_idle(command).await?;
        persist_driver(&mut profile, &driver)?;
        let identity = driver
            .local_identity()
            .ok_or_else(|| anyhow!("identity creation did not persist local identity"))?;
        let mut result = serde_json::json!({
            "user_id": identity.user_identity.user_id,
            "device_id": identity.device_identity.device_id,
            "display_name": driver.local_display_name(),
        });
        if !additional && !had_identity && !supplied_mnemonic {
            result["mnemonic"] = serde_json::Value::String(identity.mnemonic.clone());
        }
        self.print_value(&result)
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
            workspace_root: service_root
                .parent()
                .and_then(|value| value.parent())
                .map(PathBuf::from),
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
        let raw = serde_json::to_string(value)?;
        let normalized: serde_json::Value = serde_json::from_str(&raw)?;
        let normalized = crate::cli::util::camel_to_snake_value(normalized);
        match self.output {
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&normalized)?),
            OutputFormat::Text => println!("{}", serde_json::to_string_pretty(&normalized)?),
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

fn enforce_profile_passphrase_policy(
    passphrase: Option<&str>,
    profile_name: &str,
    allow_weak_passphrase: bool,
) -> Result<()> {
    let Some(passphrase) = passphrase else {
        return Ok(());
    };
    if passphrase.is_empty() {
        return Ok(());
    }
    let strength = evaluate_passphrase_strength(passphrase, Some(profile_name));
    if strength.requires_confirmation && !allow_weak_passphrase {
        bail!(
            "weak profile passphrase rejected: {}. {} Re-run with --allow-weak-passphrase to use it anyway.",
            strength.label,
            strength.message
        );
    }
    Ok(())
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

/// Encode a welcome pickup descriptor as the `tapchat://welcome-pickup/<base64>`
/// URL the joiner can pass to `group join by-pickup`. Thin delegate to
/// `WelcomePickupDescriptor::to_welcome_pickup_url` so the CLI and the
/// desktop Tauri layer produce byte-identical URLs for the same descriptor
/// (R1.4 / R6.3 shared-encoder invariant).
fn welcome_pickup_url(descriptor: &crate::model::WelcomePickupDescriptor) -> String {
    descriptor.to_welcome_pickup_url()
}

fn parse_group_join_policy(value: &str) -> Result<crate::model::GroupJoinPolicy> {
    match value {
        "closed" => Ok(crate::model::GroupJoinPolicy::Closed),
        "approval_required" => Ok(crate::model::GroupJoinPolicy::ApprovalRequired),
        "open_by_invite" => Ok(crate::model::GroupJoinPolicy::OpenByInvite),
        other => Err(anyhow!(
            "unknown join policy {other:?} (expected closed|approval_required|open_by_invite)"
        )),
    }
}

fn parse_group_member_invite_policy(value: &str) -> Result<crate::model::GroupMemberInvitePolicy> {
    match value {
        "owner_admin_only" => Ok(crate::model::GroupMemberInvitePolicy::OwnerAdminOnly),
        "request_owner_approval" => {
            Ok(crate::model::GroupMemberInvitePolicy::RequestOwnerApproval)
        }
        other => Err(anyhow!(
            "unknown member invite policy {other:?} (expected owner_admin_only|request_owner_approval)"
        )),
    }
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

fn local_user_id(driver: &CoreDriver) -> Result<String> {
    driver
        .local_identity()
        .map(|identity| identity.user_identity.user_id.clone())
        .ok_or_else(|| anyhow!("local identity is not initialized"))
}

fn allowlist_from_output(output: &crate::ffi_api::CoreOutput) -> Result<&AllowlistDocument> {
    output
        .view_model
        .as_ref()
        .and_then(|view| view.allowlist.as_ref())
        .ok_or_else(|| anyhow!("allowlist document was not returned by core"))
}

fn latest_notification_since(
    driver: &crate::cli::driver::CoreDriver,
    offset: usize,
) -> Option<String> {
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

/// Evaluate whether a `group dissolve` confirmation response from stdin
/// should be treated as "proceed".
///
/// Accepts only `"y"` / `"yes"` (case-insensitive, with surrounding
/// whitespace trimmed). Everything else — including EOF (`bytes_read ==
/// 0`), empty lines, `"n"`, `"no"`, and any unrecognised token — is
/// treated as "abort". Per task C.2 the CLI MUST apply this rule
/// uniformly; there is no `isatty` bypass or CI auto-accept.
pub(crate) fn dissolve_confirmation_accepted(bytes_read: usize, raw_input: &str) -> bool {
    if bytes_read == 0 {
        return false;
    }
    let normalized = raw_input.trim().to_ascii_lowercase();
    matches!(normalized.as_str(), "y" | "yes")
}

#[cfg(test)]
mod tests {
    use super::dissolve_confirmation_accepted;

    #[test]
    fn group_dissolve_cli_aborts_on_empty_or_no_input() {
        // Empty line, just Enter, must abort.
        assert!(!dissolve_confirmation_accepted(1, "\n"));
        // Whitespace-only, must abort.
        assert!(!dissolve_confirmation_accepted(4, "   \n"));
        // Explicit `n` / `no`, must abort.
        assert!(!dissolve_confirmation_accepted(2, "n\n"));
        assert!(!dissolve_confirmation_accepted(3, "no\n"));
        assert!(!dissolve_confirmation_accepted(3, "NO\n"));
        // Any unrecognised token, must abort.
        assert!(!dissolve_confirmation_accepted(9, "whatever\n"));
        // EOF (bytes_read == 0), must abort — even if the buffer happens
        // to contain leftover data from a previous read.
        assert!(!dissolve_confirmation_accepted(0, ""));
        assert!(!dissolve_confirmation_accepted(0, "y"));
    }

    #[test]
    fn group_dissolve_cli_proceeds_on_y_yes_case_insensitive() {
        assert!(dissolve_confirmation_accepted(2, "y\n"));
        assert!(dissolve_confirmation_accepted(2, "Y\n"));
        assert!(dissolve_confirmation_accepted(4, "yes\n"));
        assert!(dissolve_confirmation_accepted(4, "YES\n"));
        assert!(dissolve_confirmation_accepted(4, "Yes\n"));
        // Surrounding whitespace is trimmed before normalisation.
        assert!(dissolve_confirmation_accepted(6, "  y \n"));
        assert!(dissolve_confirmation_accepted(8, "  YES \n"));
    }

    #[test]
    fn group_dissolve_cli_yes_flag_bypasses_stdin() {
        // The `--yes` flag is evaluated by the command handler *before*
        // calling `dissolve_confirmation_accepted`, so the helper itself
        // only governs the interactive path. This test documents the
        // contract: any non-empty `y`/`yes` input is accepted; every
        // other path is a caller-side choice.
        //
        // If `--yes` were ever to delegate to this helper with a
        // sentinel value, the helper would still refuse because the
        // sentinel is not `y`/`yes`:
        assert!(!dissolve_confirmation_accepted(4, "--yes\n"));
    }
}

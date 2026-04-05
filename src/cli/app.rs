use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use reqwest::Client;
use serde::Serialize;

use crate::ffi_api::{AttachmentDescriptor, CoreCommand, CoreEvent};
use crate::model::{ConversationKind, DeploymentBundle, DeviceStatusKind, Validate};
use crate::persistence::CorePersistenceSnapshot;
use crate::transport_contract::GetHeadResult;

use super::args::{
    Cli, Command, ContactCommand, ContactSubcommand, ConversationCommand, ConversationSubcommand,
    DeviceCommand, DeviceSubcommand, MessageCommand, MessageSubcommand, OutputFormat,
    ProfileCommand, ProfileSubcommand, RuntimeCommand, RuntimeSubcommand, SyncCommand,
    SyncSubcommand,
};
use super::driver::CoreDriver;
use super::profile::{Profile, RuntimeMetadata};
use super::runtime::{
    allow_sender_user, bootstrap_device_bundle, put_identity_bundle, start_local_runtime, stop_local_runtime,
    wait_until_ready,
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
                let profile = Profile::open(profile)?;
                let runtime = profile.load_runtime_metadata()?;
                self.print_value(&serde_json::json!({
                    "profile": profile.metadata(),
                    "runtime": runtime,
                }))
            }
            ProfileSubcommand::ImportDeployment { profile, bundle_file } => {
                let mut profile = Profile::open(profile)?;
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
                let profile = Profile::open(profile)?;
                let driver = load_driver(&profile)?;
                let bundle = driver
                    .local_bundle()
                    .cloned()
                    .ok_or_else(|| anyhow!("local identity bundle is unavailable; import deployment first"))?;
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
                let mut profile = Profile::open(profile)?;
                let mut driver = load_driver(&profile)?;
                driver
                    .run_command_until_idle(CoreCommand::RotateLocalKeyPackage)
                    .await?;
                persist_driver(&mut profile, &driver)?;
                self.print_value(&serde_json::json!({ "rotated": true }))
            }
            DeviceSubcommand::Status { profile } => {
                let profile = Profile::open(profile)?;
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
                let mut profile = Profile::open(profile)?;
                let mut driver = load_driver(&profile)?;
                let local = driver
                    .local_identity()
                    .ok_or_else(|| anyhow!("local identity is not initialized"))?;
                if local.device_identity.device_id != target_device_id {
                    bail!("phase 1 CLI can only revoke the current local device");
                }
                driver
                    .run_command_until_idle(CoreCommand::ApplyLocalDeviceStatusUpdate {
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
            ContactSubcommand::ImportIdentity { profile, bundle_file } => {
                let mut profile = Profile::open(profile)?;
                let bundle = Profile::load_identity_bundle_file(bundle_file)?;
                let mut driver = load_driver(&profile)?;
                driver
                    .run_command_until_idle(CoreCommand::ImportIdentityBundle {
                        bundle: bundle.clone(),
                    })
                    .await?;
                profile.save_identity_bundle(
                    &bundle,
                    &format!("identity_{}.json", bundle.user_id.replace(':', "_")),
                )?;
                if let Some(deployment_bundle_path) = profile.metadata().deployment_bundle_path.clone() {
                    let deployment = Profile::load_deployment_bundle_file(&deployment_bundle_path)?;
                    if let Some(auth) = deployment.device_runtime_auth.as_ref() {
                        allow_sender_user(auth, &deployment.inbox_http_endpoint, &bundle.user_id).await?;
                    }
                }
                persist_driver(&mut profile, &driver)?;
                self.print_value(&serde_json::json!({
                    "imported": true,
                    "user_id": bundle.user_id,
                    "device_count": bundle.devices.len(),
                }))
            }
            ContactSubcommand::Refresh { profile, user_id } => {
                let mut profile = Profile::open(profile)?;
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
                let profile = Profile::open(profile)?;
                let driver = load_driver(&profile)?;
                let bundle = driver
                    .contact_bundle(&user_id)
                    .ok_or_else(|| anyhow!("contact not found"))?;
                self.print_value(bundle)
            }
            ContactSubcommand::List { profile } => {
                let profile = Profile::open(profile)?;
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
        }
    }

    async fn run_conversation(&self, command: ConversationCommand) -> Result<()> {
        match command.command {
            ConversationSubcommand::CreateDirect {
                profile,
                peer_user_id,
            } => {
                let mut profile = Profile::open(profile)?;
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
                let profile = Profile::open(profile)?;
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
                let profile = Profile::open(profile)?;
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
                let profile = Profile::open(profile)?;
                let driver = load_driver(&profile)?;
                self.print_value(&driver.conversation_members(&conversation_id))
            }
            ConversationSubcommand::Rebuild {
                profile,
                conversation_id,
            } => {
                let mut profile = Profile::open(profile)?;
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
                let mut profile = Profile::open(profile)?;
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
                let mut profile = Profile::open(profile)?;
                let mut driver = load_driver(&profile)?;
                driver
                    .run_command_until_idle(CoreCommand::SendTextMessage {
                        conversation_id: conversation_id.clone(),
                        plaintext: text,
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                self.print_value(&serde_json::json!({ "sent": true, "conversation_id": conversation_id }))
            }
            MessageSubcommand::SendAttachment {
                profile,
                conversation_id,
                file,
            } => {
                let mut profile = Profile::open(profile)?;
                let mut driver = load_driver(&profile)?;
                let descriptor = attachment_descriptor(&file)?;
                driver
                    .run_command_until_idle(CoreCommand::SendAttachmentMessage {
                        conversation_id: conversation_id.clone(),
                        attachment_descriptor: descriptor,
                    })
                    .await?;
                persist_driver(&mut profile, &driver)?;
                self.print_value(
                    &serde_json::json!({
                        "queued": true,
                        "conversation_id": conversation_id,
                        "file": file,
                        "pending_outbox": driver.pending_outbox_count(),
                        "pending_blob_uploads": driver.pending_blob_upload_count(),
                        "latest_notification": driver.latest_notification(),
                    }),
                )
            }
            MessageSubcommand::DownloadAttachment {
                profile,
                conversation_id,
                message_id,
                reference,
                out,
            } => {
                let mut profile = Profile::open(profile)?;
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
                let profile = Profile::open(profile)?;
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
                let mut profile = Profile::open(profile)?;
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
                }))
            }
            SyncSubcommand::Foreground { profile } => {
                let mut profile = Profile::open(profile)?;
                let mut driver = load_driver(&profile)?;
                driver.inject_event_until_idle(CoreEvent::AppForegrounded).await?;
                persist_driver(&mut profile, &driver)?;
                self.print_value(&serde_json::json!({ "foreground_sync": true }))
            }
            SyncSubcommand::RealtimeConnect { profile } => {
                let mut profile = Profile::open(profile)?;
                let mut driver = load_driver(&profile)?;
                driver.inject_event_until_idle(CoreEvent::AppForegrounded).await?;
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
                let mut profile = Profile::open(profile)?;
                let mut driver = load_driver(&profile)?;
                let device_id = local_device_id(&driver)?;
                driver.close_realtime(&device_id).await?;
                persist_driver(&mut profile, &driver)?;
                self.print_value(&serde_json::json!({ "realtime": "closed", "device_id": device_id }))
            }
            SyncSubcommand::Status { profile } => {
                let profile = Profile::open(profile)?;
                let driver = load_driver(&profile)?;
                let device_id = local_device_id(&driver)?;
                self.print_value(&serde_json::json!({
                    "device_id": device_id,
                    "checkpoint": driver.sync_checkpoint_snapshot(&device_id),
                    "realtime": driver.realtime_session_snapshot(&device_id),
                    "notifications": driver.notifications(),
                    "pending_outbox": driver.pending_outbox_count(),
                    "pending_blob_uploads": driver.pending_blob_upload_count(),
                }))
            }
            SyncSubcommand::Head { profile, device_id } => {
                let profile = Profile::open(profile)?;
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
            RuntimeSubcommand::LocalStart { profile } => {
                let mut profile = Profile::open(profile)?;
                let mut driver = load_driver(&profile)?;
                let identity = driver
                    .local_identity()
                    .cloned()
                    .ok_or_else(|| anyhow!("local identity is not initialized"))?;
                let workspace_root = workspace_root()?;
                let persist_dir = profile.metadata().runtime_dir.join("cloudflare-data");
                std::fs::create_dir_all(&persist_dir)?;
                let instance = start_local_runtime(&workspace_root, &persist_dir)?;
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
                let auth = bundle
                    .device_runtime_auth
                    .as_ref()
                    .ok_or_else(|| anyhow!("local runtime bootstrap did not return device runtime auth"))?;
                let local_bundle = driver
                    .local_bundle()
                    .cloned()
                    .ok_or_else(|| anyhow!("local bundle unavailable after deployment import"))?;
                put_identity_bundle(auth, &local_bundle).await?;
                profile.save_deployment_bundle(&bundle)?;
                profile.save_runtime_metadata(&RuntimeMetadata {
                    pid: Some(instance.pid),
                    base_url: Some(instance.base_url.clone()),
                    websocket_base_url: Some(instance.websocket_base_url.clone()),
                    bootstrap_secret: Some(instance.bootstrap_secret),
                    sharing_secret: Some(instance.sharing_secret),
                    mode: Some("local".into()),
                })?;
                persist_driver(&mut profile, &driver)?;
                self.print_value(&serde_json::json!({
                    "started": true,
                    "pid": instance.pid,
                    "base_url": instance.base_url,
                    "websocket_base_url": instance.websocket_base_url,
                    "user_id": identity.user_identity.user_id,
                    "device_id": identity.device_identity.device_id,
                }))
            }
            RuntimeSubcommand::LocalStop { profile } => {
                let profile = Profile::open(profile)?;
                let runtime = profile.load_runtime_metadata()?;
                let pid = runtime.pid.ok_or_else(|| anyhow!("no runtime pid recorded"))?;
                stop_local_runtime(pid)?;
                profile.clear_runtime_metadata()?;
                self.print_value(&serde_json::json!({ "stopped": true, "pid": pid }))
            }
            RuntimeSubcommand::LocalStatus { profile } => {
                let profile = Profile::open(profile)?;
                let runtime = profile.load_runtime_metadata()?;
                self.print_value(&serde_json::json!({
                    "pid": runtime.pid,
                    "base_url": runtime.base_url,
                    "websocket_base_url": runtime.websocket_base_url,
                    "bootstrap_secret": runtime.bootstrap_secret,
                    "sharing_secret": runtime.sharing_secret,
                    "mode": runtime.mode,
                }))
            }
        }
    }

    async fn run_identity_command(
        &self,
        profile_root: PathBuf,
        device_name: String,
        mnemonic_file: Option<PathBuf>,
        additional: bool,
    ) -> Result<()> {
        let mut profile = Profile::open(profile_root)?;
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

    fn print_value<T: Serialize>(&self, value: &T) -> Result<()> {
        match self.output {
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(value)?),
            OutputFormat::Text => println!("{}", serde_json::to_string_pretty(value)?),
        }
        Ok(())
    }
}

fn persist_driver(profile: &mut Profile, driver: &CoreDriver) -> Result<()> {
    if let Some(snapshot) = driver.latest_snapshot() {
        profile.save_snapshot(snapshot)?;
    }
    let user_id = driver
        .local_identity()
        .map(|identity| identity.user_identity.user_id.clone());
    let device_id = driver
        .local_identity()
        .map(|identity| identity.device_identity.device_id.clone());
    profile.update_identity(user_id, device_id)?;
    Ok(())
}

fn load_driver(profile: &Profile) -> Result<CoreDriver> {
    let snapshot = profile.load_snapshot()?;
    let base_url = snapshot
        .deployment
        .as_ref()
        .map(|deployment| deployment.deployment_bundle.inbox_http_endpoint.clone());
    CoreDriver::from_snapshot(snapshot, base_url)
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
    let file_name = path.file_name().map(|value| value.to_string_lossy().to_string());
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

fn workspace_root() -> Result<PathBuf> {
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR")))
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



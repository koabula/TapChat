use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::cli::driver::{ContactDeviceSnapshot, CoreDriver};
use crate::cli::profile::{Profile, ProfileRegistry, RuntimeMetadata};
use crate::cli::runtime::{
    CloudflareDeployOverrides, CloudflarePreflight, ResolvedCloudflareDeployConfig,
    bootstrap_device_bundle, cloudflare_preflight as runtime_cloudflare_preflight,
    deploy_cloudflare_runtime,
    derive_cloudflare_defaults, ensure_cloudflare_runtime_metadata, rebuild_cloudflare_config,
    resolve_cloudflare_config, resolve_service_root,
};
use crate::conversation::StoredMessage;
use crate::ffi_api::{
    AppendResultSummary, AttachmentDescriptor, CoreCommand, CoreEvent, CoreOutput,
    RealtimeSessionSnapshot, RecoveryContextSnapshot, SyncCheckpointSnapshot,
};
use crate::model::{DeploymentBundle, IdentityBundle, MessageType, StorageRef, Validate};
use crate::persistence::PersistedPendingBlobTransfer;
use crate::transport_contract::{AllowlistDocument, MessageRequestAction, MessageRequestItem};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProfileSummary {
    pub name: String,
    pub path: PathBuf,
    pub is_active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IdentitySummaryView {
    pub user_id: String,
    pub device_id: String,
    pub device_status: String,
    pub profile_path: PathBuf,
    pub mnemonic: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeStatusView {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    pub deployment_bound: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provisioned_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CloudflarePreflightView {
    pub workspace_root_found: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_root: Option<PathBuf>,
    pub wrangler_available: bool,
    pub wrangler_logged_in: bool,
    pub runtime_bound: bool,
    pub deployment_bundle_present: bool,
    pub identity_ready: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocking_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CloudflareRuntimeDetailsView {
    #[serde(flatten)]
    pub runtime: RuntimeStatusView,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deploy_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_bucket_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_root: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_root: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_bundle_path: Option<PathBuf>,
    pub bootstrap_secret_present: bool,
    pub sharing_secret_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CloudflareActionResultView {
    pub action: String,
    pub updated_runtime: bool,
    pub deployment_bound: bool,
    pub banner: BannerView,
    pub runtime: CloudflareRuntimeDetailsView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BannerView {
    pub severity: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OnboardingStateView {
    pub has_profiles: bool,
    pub has_identity: bool,
    pub has_runtime_binding: bool,
    pub step: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AppBootstrapView {
    pub profiles: Vec<ProfileSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_profile: Option<ProfileSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentitySummaryView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<RuntimeStatusView>,
    pub onboarding: OnboardingStateView,
    #[serde(default)]
    pub banners: Vec<BannerView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProvisionProgressView {
    pub provisioned: bool,
    pub mode: String,
    pub runtime: RuntimeStatusView,
    pub identity: IdentitySummaryView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContactDeviceView {
    pub device_id: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContactListItem {
    pub user_id: String,
    pub device_count: usize,
    pub has_conversation: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_bundle_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContactDetailView {
    pub user_id: String,
    pub devices: Vec<ContactDeviceView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_bundle_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_refresh_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MessageRequestItemView {
    pub request_id: String,
    pub recipient_device_id: String,
    pub sender_user_id: String,
    pub first_seen_at: u64,
    pub last_seen_at: u64,
    pub message_count: u64,
    pub last_message_id: String,
    pub last_conversation_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MessageRequestActionView {
    pub accepted: bool,
    pub request_id: String,
    pub sender_user_id: String,
    pub promoted_count: u64,
    pub action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AllowlistView {
    pub allowed_sender_user_ids: Vec<String>,
    pub rejected_sender_user_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConversationListItem {
    pub conversation_id: String,
    pub peer_user_id: String,
    pub conversation_state: String,
    pub recovery_status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_message_preview: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_message_type: Option<MessageType>,
    pub message_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConversationDetailView {
    pub conversation_id: String,
    pub peer_user_id: String,
    pub conversation_state: String,
    pub recovery_status: String,
    pub message_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<RecoveryContextSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MessageItemView {
    pub conversation_id: String,
    pub message_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_user_id: Option<String>,
    pub direction: String,
    pub message_type: MessageType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plaintext: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub storage_refs: Vec<StorageRef>,
    pub has_attachment: bool,
    pub attachment_count: usize,
    pub downloaded_attachment_available: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachment_refs: Vec<StorageRef>,
    pub primary_attachment_previewable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_attachment_local_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_attachment_display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SyncStatusView {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<SyncCheckpointSnapshot>,
    pub pending_outbox: usize,
    pub pending_blob_uploads: usize,
    pub recovery_conversations: Vec<crate::ffi_api::RecoveryDiagnostics>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RealtimeStatusView {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    pub connected: bool,
    pub last_known_seq: u64,
    pub needs_reconnect: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SendMessageResultView {
    pub conversation_id: String,
    pub pending_outbox: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub append_result: Option<AppendResultSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_notification: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DirectShellView {
    pub contacts: Vec<ContactListItem>,
    pub conversations: Vec<ConversationListItem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_contact: Option<ContactDetailView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_conversation: Option<ConversationDetailView>,
    pub messages: Vec<MessageItemView>,
    pub sync: SyncStatusView,
    pub realtime: RealtimeStatusView,
    pub attachment_transfers: Vec<AttachmentTransferView>,
    #[serde(default)]
    pub banners: Vec<BannerView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttachmentTransferView {
    pub transfer_id: String,
    pub task_kind: String,
    pub conversation_id: String,
    pub scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retryable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opened: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SendAttachmentResultView {
    pub conversation_id: String,
    pub file_name: String,
    pub pending_outbox: usize,
    pub pending_blob_uploads: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub append_result: Option<AppendResultSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_notification: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DownloadAttachmentResultView {
    pub conversation_id: String,
    pub message_id: String,
    pub destination: PathBuf,
    pub downloaded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BatchSendAttachmentResultView {
    pub conversation_id: String,
    pub queued_count: usize,
    pub results: Vec<SendAttachmentResultView>,
    pub pending_blob_uploads: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_notification: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BackgroundDownloadTicketView {
    pub transfer_id: String,
    pub conversation_id: String,
    pub message_id: String,
    pub destination: PathBuf,
    pub started: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttachmentPreviewView {
    pub kind: String,
    pub mime_type: String,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_path: Option<PathBuf>,
    pub message_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
struct DesktopProfileState {
    #[serde(default = "default_background_enabled")]
    background_enabled: bool,
    #[serde(default)]
    saved_attachments: BTreeMap<String, SavedAttachmentRecord>,
    #[serde(default)]
    recent_transfers: Vec<RecordedAttachmentTransfer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SavedAttachmentRecord {
    local_path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mime_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(default)]
    opened: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RecordedAttachmentTransfer {
    transfer_id: String,
    task_kind: String,
    conversation_id: String,
    scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    message_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    file_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reference: Option<String>,
    state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retryable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    progress_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    destination_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    opened: Option<bool>,
}

pub fn app_bootstrap() -> Result<AppBootstrapView> {
    let registry = ProfileRegistry::load()?;
    let profiles = registry_summaries(&registry);
    let active_profile = registry
        .active_profile
        .clone()
        .and_then(|path| profiles.iter().find(|profile| profile.path == path).cloned());
    let (identity, runtime) = if let Some(profile) = active_profile.as_ref() {
        let profile = Profile::open(&profile.path)?;
        (
            identity_summary_from_profile(&profile)?,
            Some(runtime_status_from_profile(&profile)?),
        )
    } else {
        (None, None)
    };
    let onboarding = OnboardingStateView {
        has_profiles: !profiles.is_empty(),
        has_identity: identity.is_some(),
        has_runtime_binding: runtime
            .as_ref()
            .map(|value| value.deployment_bound)
            .unwrap_or(false),
        step: onboarding_step(!profiles.is_empty(), identity.is_some(), runtime.as_ref()),
    };
    Ok(AppBootstrapView {
        profiles,
        active_profile,
        identity,
        runtime,
        onboarding,
        banners: Vec::new(),
    })
}

pub fn profile_list() -> Result<Vec<ProfileSummary>> {
    let registry = ProfileRegistry::load()?;
    Ok(registry_summaries(&registry))
}

pub fn profile_activate(profile_id_or_path: &str) -> Result<AppBootstrapView> {
    let mut registry = ProfileRegistry::load()?;
    let candidate_path = PathBuf::from(profile_id_or_path);
    if candidate_path.exists()
        || registry
            .profiles
            .iter()
            .any(|entry| entry.root_dir == candidate_path)
    {
        registry.set_active(&candidate_path)?;
    } else {
        let _ = registry.set_active_by_name(profile_id_or_path)?;
    }
    registry.save()?;
    app_bootstrap()
}

pub fn profile_create(name: &str, root: impl AsRef<Path>) -> Result<ProfileSummary> {
    let profile = Profile::init(name, root)?;
    let registry = ProfileRegistry::load()?;
    let active = registry
        .active_profile
        .as_ref()
        .is_some_and(|path| path == profile.root());
    Ok(ProfileSummary {
        name: profile.metadata().name.clone(),
        path: profile.root().to_path_buf(),
        is_active: active,
        user_id: profile.metadata().user_id.clone(),
        device_id: profile.metadata().device_id.clone(),
    })
}

pub async fn identity_create(
    profile_path: impl AsRef<Path>,
    device_name: &str,
) -> Result<IdentitySummaryView> {
    run_identity_command(profile_path.as_ref(), device_name, None, false).await
}

pub async fn identity_recover(
    profile_path: impl AsRef<Path>,
    device_name: &str,
    mnemonic: String,
) -> Result<IdentitySummaryView> {
    run_identity_command(profile_path.as_ref(), device_name, Some(mnemonic), false).await
}

pub async fn deployment_import(
    profile_path: impl AsRef<Path>,
    bundle_json_or_path: &str,
) -> Result<RuntimeStatusView> {
    let mut profile = Profile::open(profile_path)?;
    let bundle = if Path::new(bundle_json_or_path).exists() {
        Profile::load_deployment_bundle_file(bundle_json_or_path)?
    } else {
        serde_json::from_str::<DeploymentBundle>(bundle_json_or_path)
            .context("decode deployment bundle json")?
    };
    bundle.validate().map_err(anyhow::Error::from)?;
    let mut driver = load_driver(&profile)?;
    driver
        .run_command_until_idle(CoreCommand::ImportDeploymentBundle {
            bundle: bundle.clone(),
        })
        .await?;
    profile.save_deployment_bundle(&bundle)?;
    persist_driver(&mut profile, &driver)?;
    runtime_status_from_profile(&profile)
}

pub async fn cloudflare_provision_auto(
    profile_path: impl AsRef<Path>,
) -> Result<ProvisionProgressView> {
    let mut profile = Profile::open(profile_path)?;
    let mut driver = load_driver(&profile)?;
    let identity = driver
        .local_identity()
        .cloned()
        .ok_or_else(|| anyhow!("local identity is not initialized"))?;
    let service_root = resolve_service_root(None, Some(profile.metadata().root_dir.as_path()))?;
    let defaults = derive_cloudflare_defaults(
        &profile.metadata().name,
        &identity.user_identity.user_id,
        &identity.device_identity.device_id,
    );
    let config = resolve_cloudflare_config(&defaults, &CloudflareDeployOverrides::default());
    provision_cloudflare_profile(
        &mut profile,
        &mut driver,
        &identity.user_identity.user_id,
        &identity.device_identity.device_id,
        &service_root,
        config,
    )
    .await
}

pub fn cloudflare_preflight(profile_path: impl AsRef<Path>) -> Result<CloudflarePreflightView> {
    let profile = Profile::open(profile_path)?;
    let driver = load_driver(&profile)?;
    let preflight = runtime_cloudflare_preflight(Some(profile.root()));
    Ok(map_cloudflare_preflight(
        &profile,
        profile.metadata().deployment_bundle_path.is_some(),
        driver.local_identity().is_some(),
        preflight,
    ))
}

pub async fn cloudflare_provision_custom(
    profile_path: impl AsRef<Path>,
    overrides: CloudflareDeployOverrides,
) -> Result<ProvisionProgressView> {
    let mut profile = Profile::open(profile_path)?;
    let mut driver = load_driver(&profile)?;
    let identity = driver
        .local_identity()
        .cloned()
        .ok_or_else(|| anyhow!("local identity is not initialized"))?;
    let service_root = resolve_service_root(None, Some(profile.metadata().root_dir.as_path()))?;
    let defaults = derive_cloudflare_defaults(
        &profile.metadata().name,
        &identity.user_identity.user_id,
        &identity.device_identity.device_id,
    );
    let config = resolve_cloudflare_config(&defaults, &overrides);
    provision_cloudflare_profile(
        &mut profile,
        &mut driver,
        &identity.user_identity.user_id,
        &identity.device_identity.device_id,
        &service_root,
        config,
    )
    .await
}

pub fn cloudflare_status(profile_path: impl AsRef<Path>) -> Result<RuntimeStatusView> {
    let profile = Profile::open(profile_path)?;
    runtime_status_from_profile(&profile)
}

pub fn cloudflare_runtime_details(
    profile_path: impl AsRef<Path>,
) -> Result<CloudflareRuntimeDetailsView> {
    let profile = Profile::open(profile_path)?;
    cloudflare_runtime_details_from_profile(&profile)
}

pub async fn cloudflare_redeploy(
    profile_path: impl AsRef<Path>,
) -> Result<CloudflareActionResultView> {
    let mut profile = Profile::open(profile_path)?;
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
    provision_cloudflare_action(
        "redeploy",
        &mut profile,
        &mut driver,
        &identity.user_identity.user_id,
        &identity.device_identity.device_id,
        &service_root,
        config,
    )
    .await
}

pub async fn cloudflare_rotate_secrets(
    profile_path: impl AsRef<Path>,
) -> Result<CloudflareActionResultView> {
    let mut profile = Profile::open(profile_path)?;
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
    let config = resolve_cloudflare_config(&defaults, &CloudflareDeployOverrides::default());
    provision_cloudflare_action(
        "rotate_secrets",
        &mut profile,
        &mut driver,
        &identity.user_identity.user_id,
        &identity.device_identity.device_id,
        &service_root,
        config,
    )
    .await
}

pub fn cloudflare_detach(profile_path: impl AsRef<Path>) -> Result<CloudflareActionResultView> {
    let mut profile = Profile::open(profile_path)?;
    let mut snapshot = profile.load_snapshot()?;
    snapshot.deployment = None;
    profile.save_snapshot(&snapshot)?;
    profile.clear_runtime_metadata()?;
    profile.clear_deployment_bundle_path()?;
    let runtime = cloudflare_runtime_details_from_profile(&profile)?;
    Ok(CloudflareActionResultView {
        action: "detach".into(),
        updated_runtime: true,
        deployment_bound: runtime.runtime.deployment_bound,
        banner: BannerView {
            severity: "success".into(),
            message: "Detached current profile from Cloudflare runtime. Cloud resources were not deleted.".into(),
        },
        runtime,
    })
}

pub fn contact_list(profile_path: impl AsRef<Path>) -> Result<Vec<ContactListItem>> {
    let profile = Profile::open(profile_path)?;
    let snapshot = profile.load_snapshot()?;
    let driver = load_driver(&profile)?;
    let conversations = snapshot.conversations;
    let contacts = snapshot
        .contacts
        .into_iter()
        .map(|contact| {
            let has_conversation = conversations
                .iter()
                .any(|conversation| conversation.state.peer_user_id == contact.user_id);
            let bundle_ref = driver
                .contact_bundle(&contact.user_id)
                .and_then(|bundle| bundle.identity_bundle_ref.clone());
            ContactListItem {
                user_id: contact.user_id.clone(),
                device_count: driver.contact_devices(&contact.user_id).len(),
                has_conversation,
                identity_bundle_ref: bundle_ref,
            }
        })
        .collect();
    Ok(contacts)
}

pub async fn contact_import_identity(
    profile_path: impl AsRef<Path>,
    bundle_json_or_path: &str,
) -> Result<ContactDetailView> {
    let mut profile = Profile::open(profile_path)?;
    let bundle = load_identity_bundle(bundle_json_or_path)?;
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
    persist_driver(&mut profile, &driver)?;
    contact_show(profile.root(), &bundle.user_id)
}

pub fn contact_show(profile_path: impl AsRef<Path>, user_id: &str) -> Result<ContactDetailView> {
    let profile = Profile::open(profile_path)?;
    let driver = load_driver(&profile)?;
    let bundle = driver
        .contact_bundle(user_id)
        .ok_or_else(|| anyhow!("contact not found"))?;
    Ok(ContactDetailView {
        user_id: bundle.user_id.clone(),
        devices: map_contact_devices(driver.contact_devices(user_id)),
        identity_bundle_ref: bundle.identity_bundle_ref.clone(),
        last_refresh_error: None,
    })
}

pub async fn contact_refresh(
    profile_path: impl AsRef<Path>,
    user_id: &str,
) -> Result<ContactDetailView> {
    let mut profile = Profile::open(profile_path)?;
    let mut driver = load_driver(&profile)?;
    driver
        .run_command_until_idle(CoreCommand::RefreshIdentityState {
            user_id: user_id.to_string(),
        })
        .await?;
    persist_driver(&mut profile, &driver)?;
    contact_show(profile.root(), user_id)
}

pub async fn message_requests_list(
    profile_path: impl AsRef<Path>,
) -> Result<Vec<MessageRequestItemView>> {
    let profile = Profile::open(profile_path)?;
    let mut driver = load_driver(&profile)?;
    let output = driver
        .run_command_until_idle(CoreCommand::ListMessageRequests)
        .await?;
    Ok(message_requests_from_output(&output)?
        .iter()
        .cloned()
        .map(map_message_request)
        .collect())
}

pub async fn message_request_accept(
    profile_path: impl AsRef<Path>,
    request_id: &str,
) -> Result<MessageRequestActionView> {
    let mut profile = Profile::open(profile_path)?;
    let mut driver = load_driver(&profile)?;
    let output = driver
        .run_command_until_idle(CoreCommand::ActOnMessageRequest {
            request_id: request_id.to_string(),
            action: MessageRequestAction::Accept,
        })
        .await?;
    persist_driver(&mut profile, &driver)?;
    Ok(map_message_request_action(
        message_request_action_from_output(&output)?,
    ))
}

pub async fn message_request_reject(
    profile_path: impl AsRef<Path>,
    request_id: &str,
) -> Result<MessageRequestActionView> {
    let mut profile = Profile::open(profile_path)?;
    let mut driver = load_driver(&profile)?;
    let output = driver
        .run_command_until_idle(CoreCommand::ActOnMessageRequest {
            request_id: request_id.to_string(),
            action: MessageRequestAction::Reject,
        })
        .await?;
    persist_driver(&mut profile, &driver)?;
    Ok(map_message_request_action(
        message_request_action_from_output(&output)?,
    ))
}

pub async fn allowlist_get(profile_path: impl AsRef<Path>) -> Result<AllowlistView> {
    let profile = Profile::open(profile_path)?;
    let mut driver = load_driver(&profile)?;
    let output = driver
        .run_command_until_idle(CoreCommand::ListAllowlist)
        .await?;
    Ok(map_allowlist(allowlist_from_output(&output)?))
}

pub async fn allowlist_add(
    profile_path: impl AsRef<Path>,
    user_id: &str,
) -> Result<AllowlistView> {
    let mut profile = Profile::open(profile_path)?;
    let mut driver = load_driver(&profile)?;
    let output = driver
        .run_command_until_idle(CoreCommand::AddAllowlistUser {
            user_id: user_id.to_string(),
        })
        .await?;
    persist_driver(&mut profile, &driver)?;
    Ok(map_allowlist(allowlist_from_output(&output)?))
}

pub async fn allowlist_remove(
    profile_path: impl AsRef<Path>,
    user_id: &str,
) -> Result<AllowlistView> {
    let mut profile = Profile::open(profile_path)?;
    let mut driver = load_driver(&profile)?;
    let output = driver
        .run_command_until_idle(CoreCommand::RemoveAllowlistUser {
            user_id: user_id.to_string(),
        })
        .await?;
    persist_driver(&mut profile, &driver)?;
    Ok(map_allowlist(allowlist_from_output(&output)?))
}

pub fn conversation_list(profile_path: impl AsRef<Path>) -> Result<Vec<ConversationListItem>> {
    let profile = Profile::open(profile_path)?;
    let snapshot = profile.load_snapshot()?;
    let driver = load_driver(&profile)?;
    let rows = snapshot
        .conversations
        .iter()
        .map(|conversation| {
            let state = driver.conversation_state(&conversation.conversation_id);
            let last_message = state.and_then(|value| value.messages.last());
            ConversationListItem {
                conversation_id: conversation.conversation_id.clone(),
                peer_user_id: conversation.state.peer_user_id.clone(),
                conversation_state: format!("{:?}", conversation.state.conversation.state),
                recovery_status: state
                    .map(|value| format!("{:?}", value.recovery_status))
                    .unwrap_or_else(|| "Unknown".into()),
                last_message_preview: last_message.and_then(message_preview),
                last_message_type: state.and_then(|value| value.last_message_type),
                message_count: state.map(|value| value.messages.len()).unwrap_or_default(),
            }
        })
        .collect();
    Ok(rows)
}

pub async fn conversation_create_direct(
    profile_path: impl AsRef<Path>,
    peer_user_id: &str,
) -> Result<ConversationDetailView> {
    let mut profile = Profile::open(profile_path)?;
    let mut driver = load_driver(&profile)?;
    driver
        .run_command_until_idle(CoreCommand::CreateConversation {
            peer_user_id: peer_user_id.to_string(),
            conversation_kind: crate::model::ConversationKind::Direct,
        })
        .await?;
    persist_driver(&mut profile, &driver)?;
    let snapshot = profile.load_snapshot()?;
    let conversation = snapshot
        .conversations
        .into_iter()
        .find(|conversation| conversation.state.peer_user_id == peer_user_id)
        .ok_or_else(|| anyhow!("conversation was not persisted"))?;
    conversation_show(profile.root(), &conversation.conversation_id)
}

pub fn conversation_show(
    profile_path: impl AsRef<Path>,
    conversation_id: &str,
) -> Result<ConversationDetailView> {
    let profile = Profile::open(profile_path)?;
    let driver = load_driver(&profile)?;
    let state = driver
        .conversation_state(conversation_id)
        .ok_or_else(|| anyhow!("conversation not found"))?;
    Ok(ConversationDetailView {
        conversation_id: conversation_id.to_string(),
        peer_user_id: state.peer_user_id.clone(),
        conversation_state: format!("{:?}", state.conversation.state),
        recovery_status: format!("{:?}", state.recovery_status),
        message_count: state.messages.len(),
        mls_status: driver.mls_status(conversation_id).map(|status| format!("{:?}", status)),
        recovery: driver.recovery_context_snapshot(conversation_id),
    })
}

pub async fn conversation_rebuild(
    profile_path: impl AsRef<Path>,
    conversation_id: &str,
) -> Result<ConversationDetailView> {
    let mut profile = Profile::open(profile_path)?;
    let mut driver = load_driver(&profile)?;
    driver
        .run_command_until_idle(CoreCommand::RebuildConversation {
            conversation_id: conversation_id.to_string(),
        })
        .await?;
    persist_driver(&mut profile, &driver)?;
    conversation_show(profile.root(), conversation_id)
}

pub async fn conversation_reconcile(
    profile_path: impl AsRef<Path>,
    conversation_id: &str,
) -> Result<ConversationDetailView> {
    let mut profile = Profile::open(profile_path)?;
    let mut driver = load_driver(&profile)?;
    driver
        .run_command_until_idle(CoreCommand::ReconcileConversationMembership {
            conversation_id: conversation_id.to_string(),
        })
        .await?;
    persist_driver(&mut profile, &driver)?;
    conversation_show(profile.root(), conversation_id)
}

pub fn message_list(
    profile_path: impl AsRef<Path>,
    conversation_id: &str,
) -> Result<Vec<MessageItemView>> {
    let profile = Profile::open(profile_path)?;
    let driver = load_driver(&profile)?;
    let attachment_state = load_desktop_profile_state(profile.root())?;
    let state = driver
        .conversation_state(conversation_id)
        .ok_or_else(|| anyhow!("conversation not found"))?;
    let local_identity = driver.local_identity();
    Ok(state
        .messages
        .iter()
        .map(|message| {
            map_message(
                conversation_id,
                message,
                &state.peer_user_id,
                local_identity,
                Some(&attachment_state),
                Some(&profile),
            )
        })
        .collect())
}

pub async fn message_send_text(
    profile_path: impl AsRef<Path>,
    conversation_id: &str,
    text: &str,
) -> Result<SendMessageResultView> {
    let mut profile = Profile::open(profile_path)?;
    let mut driver = load_driver(&profile)?;
    let notification_offset = driver.notifications().len();
    let output = driver
        .run_command_until_idle(CoreCommand::SendTextMessage {
            conversation_id: conversation_id.to_string(),
            plaintext: text.to_string(),
        })
        .await?;
    persist_driver(&mut profile, &driver)?;
    Ok(SendMessageResultView {
        conversation_id: conversation_id.to_string(),
        pending_outbox: driver.pending_outbox_count(),
        append_result: output.view_model.and_then(|view| view.append_result),
        latest_notification: latest_notification_since(&driver, notification_offset),
    })
}

pub async fn message_send_attachment(
    profile_path: impl AsRef<Path>,
    conversation_id: &str,
    file_path: impl AsRef<Path>,
) -> Result<SendAttachmentResultView> {
    let mut profile = Profile::open(profile_path)?;
    let mut driver = load_driver(&profile)?;
    let descriptor = attachment_descriptor(file_path.as_ref())?;
    let file_name = descriptor
        .file_name
        .clone()
        .unwrap_or_else(|| file_path.as_ref().display().to_string());
    let notification_offset = driver.notifications().len();
    let output = driver
        .run_command_until_idle(CoreCommand::SendAttachmentMessage {
            conversation_id: conversation_id.to_string(),
            attachment_descriptor: descriptor,
        })
        .await?;
    persist_driver(&mut profile, &driver)?;
    Ok(SendAttachmentResultView {
        conversation_id: conversation_id.to_string(),
        file_name,
        pending_outbox: driver.pending_outbox_count(),
        pending_blob_uploads: attachment_transfer_counts(profile.root())?.pending_uploads,
        append_result: output.view_model.and_then(|view| view.append_result),
        latest_notification: latest_notification_since(&driver, notification_offset),
    })
}

pub async fn message_send_attachments(
    profile_path: impl AsRef<Path>,
    conversation_id: &str,
    file_paths: Vec<String>,
) -> Result<BatchSendAttachmentResultView> {
    let mut results = Vec::new();
    let mut latest_notification = None;
    for file_path in file_paths {
        let result = message_send_attachment(&profile_path, conversation_id, &file_path).await?;
        latest_notification = result.latest_notification.clone().or(latest_notification);
        record_recent_transfer(
            profile_path.as_ref(),
            RecordedAttachmentTransfer {
                transfer_id: format!("upload:{}:{}", conversation_id, result.file_name),
                task_kind: "upload".into(),
                conversation_id: conversation_id.to_string(),
                scope: "conversation".into(),
                message_id: None,
                file_name: Some(result.file_name.clone()),
                reference: None,
                state: if result.pending_blob_uploads > 0 {
                    "in_flight".into()
                } else {
                    "completed".into()
                },
                retryable: None,
                detail: result.latest_notification.clone(),
                progress_label: Some(format!("queued {}", result.file_name)),
                destination_path: None,
                opened: Some(false),
            },
        )?;
        results.push(result);
    }
    Ok(BatchSendAttachmentResultView {
        conversation_id: conversation_id.to_string(),
        queued_count: results.len(),
        pending_blob_uploads: attachment_transfer_counts(profile_path.as_ref())?.pending_uploads,
        latest_notification,
        results,
    })
}

pub async fn message_download_attachment(
    profile_path: impl AsRef<Path>,
    conversation_id: &str,
    message_id: &str,
    reference: &str,
    destination: Option<impl AsRef<Path>>,
) -> Result<DownloadAttachmentResultView> {
    let mut profile = Profile::open(profile_path)?;
    let preview = attachment_preview_source(profile.root(), message_id, Some(reference)).ok();
    let destination = destination
        .map(|value| value.as_ref().to_path_buf())
        .unwrap_or_else(|| {
            profile
                .metadata()
                .inbox_attachments_dir
                .join(format!("{message_id}.bin"))
        });
    let mut driver = load_driver(&profile)?;
    driver
        .run_command_until_idle(CoreCommand::DownloadAttachment {
            conversation_id: conversation_id.to_string(),
            message_id: message_id.to_string(),
            reference: reference.to_string(),
            destination: destination.to_string_lossy().to_string(),
        })
        .await?;
    persist_driver(&mut profile, &driver)?;
    record_saved_attachment(
        profile.root(),
        message_id,
        &destination,
        preview.as_ref().map(|view| view.mime_type.clone()),
        preview.as_ref().map(|view| view.display_name.clone()),
    )?;
    record_recent_transfer(
        profile.root(),
        RecordedAttachmentTransfer {
            transfer_id: format!("download:{conversation_id}:{message_id}"),
            task_kind: "download".into(),
            conversation_id: conversation_id.to_string(),
            scope: "conversation".into(),
            message_id: Some(message_id.to_string()),
            file_name: preview.as_ref().map(|view| view.display_name.clone()),
            reference: Some(reference.to_string()),
            state: "completed".into(),
            retryable: Some(false),
            detail: Some("saved".into()),
            progress_label: Some("download complete".into()),
            destination_path: Some(destination.clone()),
            opened: Some(false),
        },
    )?;
    Ok(DownloadAttachmentResultView {
        conversation_id: conversation_id.to_string(),
        message_id: message_id.to_string(),
        destination,
        downloaded: true,
    })
}

pub fn default_attachment_destination(
    profile_path: impl AsRef<Path>,
    message_id: &str,
) -> Result<PathBuf> {
    let profile = Profile::open(profile_path.as_ref())?;
    Ok(profile
        .metadata()
        .inbox_attachments_dir
        .join(format!("{message_id}.bin")))
}

pub fn attachment_preview_source(
    profile_path: impl AsRef<Path>,
    message_id: &str,
    reference: Option<&str>,
) -> Result<AttachmentPreviewView> {
    let profile = Profile::open(profile_path.as_ref())?;
    let desktop_state = load_desktop_profile_state(profile.root())?;
    let (message, attachment_ref) = find_message_with_attachment(&profile, message_id, reference)?;
    let mime_type = attachment_ref
        .as_ref()
        .map(|value| value.mime_type.clone())
        .unwrap_or_else(|| "application/octet-stream".into());
    let local_path = attachment_local_path(&profile, &desktop_state, message_id);
    let is_image = mime_type.starts_with("image/");
    Ok(AttachmentPreviewView {
        kind: if is_image && local_path.as_ref().is_some_and(|path| path.exists()) {
            "image".into()
        } else {
            "unsupported".into()
        },
        mime_type,
        display_name: attachment_display_name(&desktop_state, message_id, attachment_ref.as_ref()),
        local_path,
        message_id: message.message_id.clone(),
    })
}

pub fn attachment_open_local(
    profile_path: impl AsRef<Path>,
    message_id: &str,
) -> Result<bool> {
    let profile = Profile::open(profile_path.as_ref())?;
    let mut desktop_state = load_desktop_profile_state(profile.root())?;
    let local_path = attachment_local_path(&profile, &desktop_state, message_id)
        .filter(|path| path.exists())
        .ok_or_else(|| anyhow!("no local attachment found for {message_id}"))?;
    open::that(&local_path).with_context(|| format!("open {}", local_path.display()))?;
    if let Some(record) = desktop_state.saved_attachments.get_mut(message_id) {
        record.opened = true;
    }
    if let Some(record) = desktop_state
        .recent_transfers
        .iter_mut()
        .find(|transfer| transfer.message_id.as_deref() == Some(message_id))
    {
        record.opened = Some(true);
    }
    save_desktop_profile_state(profile.root(), &desktop_state)?;
    Ok(true)
}

pub fn app_set_background_mode(profile_path: impl AsRef<Path>, enabled: bool) -> Result<bool> {
    let profile = Profile::open(profile_path.as_ref())?;
    let mut desktop_state = load_desktop_profile_state(profile.root())?;
    desktop_state.background_enabled = enabled;
    save_desktop_profile_state(profile.root(), &desktop_state)?;
    Ok(enabled)
}

pub fn app_background_mode(profile_path: impl AsRef<Path>) -> Result<bool> {
    let profile = Profile::open(profile_path.as_ref())?;
    Ok(load_desktop_profile_state(profile.root())?.background_enabled)
}

pub fn record_background_download_status(
    profile_path: impl AsRef<Path>,
    conversation_id: &str,
    message_id: &str,
    reference: &str,
    destination: Option<impl AsRef<Path>>,
    state: &str,
    detail: Option<&str>,
) -> Result<()> {
    let profile = Profile::open(profile_path.as_ref())?;
    record_recent_transfer(
        profile.root(),
        RecordedAttachmentTransfer {
            transfer_id: format!("download:{conversation_id}:{message_id}"),
            task_kind: "download".into(),
            conversation_id: conversation_id.to_string(),
            scope: "conversation".into(),
            message_id: Some(message_id.to_string()),
            file_name: None,
            reference: Some(reference.to_string()),
            state: state.to_string(),
            retryable: Some(state != "completed"),
            detail: detail.map(ToOwned::to_owned),
            progress_label: Some(match state {
                "failed" => "download failed".into(),
                "completed" => "download complete".into(),
                _ => "downloading".into(),
            }),
            destination_path: destination.map(|value| value.as_ref().to_path_buf()),
            opened: Some(false),
        },
    )
}

pub fn attachment_transfers(
    profile_path: impl AsRef<Path>,
    conversation_id: Option<&str>,
) -> Result<Vec<AttachmentTransferView>> {
    let profile = Profile::open(profile_path)?;
    let snapshot = profile.load_snapshot()?;
    let mut pending: Vec<AttachmentTransferView> = snapshot
        .pending_blob_transfers
        .into_iter()
        .filter_map(|transfer| map_transfer(transfer, conversation_id))
        .collect();
    let desktop_state = load_desktop_profile_state(profile.root())?;
    let mut history = desktop_state
        .recent_transfers
        .into_iter()
        .filter(|transfer| {
            conversation_id.is_none_or(|value| value == transfer.conversation_id)
                && !pending.iter().any(|item| item.transfer_id == transfer.transfer_id)
        })
        .map(map_recorded_transfer)
        .collect::<Vec<_>>();
    history.sort_by(|left, right| right.transfer_id.cmp(&left.transfer_id));
    pending.extend(history.into_iter().take(8));
    Ok(pending)
}

pub fn attachment_transfer_history(
    profile_path: impl AsRef<Path>,
    conversation_id: Option<&str>,
) -> Result<Vec<AttachmentTransferView>> {
    attachment_transfers(profile_path, conversation_id)
}

pub async fn sync_once(profile_path: impl AsRef<Path>) -> Result<SyncStatusView> {
    let mut profile = Profile::open(profile_path)?;
    let mut driver = load_driver(&profile)?;
    let device_id = local_device_id(&driver)?;
    driver
        .run_command_until_idle_without_realtime(CoreCommand::SyncInbox {
            device_id: device_id.clone(),
            reason: Some("desktop_once".into()),
        })
        .await?;
    persist_driver(&mut profile, &driver)?;
    Ok(sync_status_from_driver(&driver, Some(device_id)))
}

pub fn sync_status(profile_path: impl AsRef<Path>) -> Result<SyncStatusView> {
    let profile = Profile::open(profile_path)?;
    let driver = load_driver(&profile)?;
    let device_id = local_device_id(&driver).ok();
    Ok(sync_status_from_driver(&driver, device_id))
}

pub async fn sync_foreground(profile_path: impl AsRef<Path>) -> Result<SyncStatusView> {
    let mut profile = Profile::open(profile_path)?;
    let mut driver = load_driver(&profile)?;
    driver
        .inject_event_until_idle(CoreEvent::AppForegrounded)
        .await?;
    persist_driver(&mut profile, &driver)?;
    let device_id = local_device_id(&driver).ok();
    Ok(sync_status_from_driver(&driver, device_id))
}

pub fn direct_shell(
    profile_path: impl AsRef<Path>,
    selected_conversation_id: Option<&str>,
    selected_contact_user_id: Option<&str>,
) -> Result<DirectShellView> {
    let profile = Profile::open(profile_path)?;
    let contacts = contact_list(profile.root())?;
    let conversations = conversation_list(profile.root())?;
    let sync = sync_status(profile.root())?;
    let selected_conversation = if let Some(conversation_id) = selected_conversation_id {
        Some(conversation_show(profile.root(), conversation_id)?)
    } else {
        None
    };
    let selected_contact = if let Some(user_id) = selected_contact_user_id {
        Some(contact_show(profile.root(), user_id)?)
    } else {
        None
    };
    let messages = if let Some(conversation) = selected_conversation.as_ref() {
        message_list(profile.root(), &conversation.conversation_id)?
    } else {
        Vec::new()
    };
    let attachment_filter = selected_conversation_id
        .map(str::to_string)
        .or_else(|| selected_conversation.as_ref().map(|value| value.conversation_id.clone()));
    Ok(DirectShellView {
        contacts,
        conversations,
        selected_contact,
        selected_conversation,
        messages,
        sync,
        realtime: RealtimeStatusView {
            device_id: None,
            connected: false,
            last_known_seq: 0,
            needs_reconnect: false,
        },
        attachment_transfers: attachment_transfers(profile.root(), attachment_filter.as_deref())?,
        banners: Vec::new(),
    })
}

fn registry_summaries(registry: &ProfileRegistry) -> Vec<ProfileSummary> {
    registry
        .profiles
        .iter()
        .map(|entry| ProfileSummary {
            name: entry.name.clone(),
            path: entry.root_dir.clone(),
            is_active: registry.active_profile.as_ref() == Some(&entry.root_dir),
            user_id: entry.user_id.clone(),
            device_id: entry.device_id.clone(),
        })
        .collect()
}

fn identity_summary_from_profile(profile: &Profile) -> Result<Option<IdentitySummaryView>> {
    let driver = load_driver(profile)?;
    Ok(driver.local_identity().map(|identity| IdentitySummaryView {
        user_id: identity.user_identity.user_id.clone(),
        device_id: identity.device_identity.device_id.clone(),
        device_status: format!("{:?}", identity.device_status.status).to_lowercase(),
        profile_path: profile.root().to_path_buf(),
        mnemonic: identity.mnemonic.clone(),
    }))
}

fn runtime_status_from_profile(profile: &Profile) -> Result<RuntimeStatusView> {
    let runtime = profile.load_runtime_metadata()?;
    Ok(RuntimeStatusView {
        mode: runtime.mode.clone(),
        deployment_bound: profile.metadata().deployment_bundle_path.is_some(),
        public_base_url: runtime.public_base_url.or(runtime.base_url),
        worker_name: runtime.worker_name,
        provisioned_at: runtime.last_deployed_at,
        last_error: None,
    })
}

fn cloudflare_runtime_details_from_profile(profile: &Profile) -> Result<CloudflareRuntimeDetailsView> {
    let runtime = profile.load_runtime_metadata()?;
    let workspace_root = runtime.workspace_root.clone();
    Ok(CloudflareRuntimeDetailsView {
        runtime: RuntimeStatusView {
            mode: runtime.mode.clone(),
            deployment_bound: profile.metadata().deployment_bundle_path.is_some(),
            public_base_url: runtime.public_base_url.clone().or(runtime.base_url.clone()),
            worker_name: runtime.worker_name.clone(),
            provisioned_at: runtime.last_deployed_at.clone(),
            last_error: None,
        },
        deploy_url: runtime.deploy_url,
        deployment_region: runtime.deployment_region,
        bucket_name: runtime.bucket_name,
        preview_bucket_name: runtime.preview_bucket_name,
        service_root: runtime.service_root,
        workspace_root,
        deployment_bundle_path: profile.metadata().deployment_bundle_path.clone(),
        bootstrap_secret_present: runtime.bootstrap_secret.is_some(),
        sharing_secret_present: runtime.sharing_secret.is_some(),
    })
}

fn map_cloudflare_preflight(
    profile: &Profile,
    deployment_bundle_present: bool,
    identity_ready: bool,
    preflight: CloudflarePreflight,
) -> CloudflarePreflightView {
    let runtime_bound = profile
        .load_runtime_metadata()
        .map(|runtime| runtime.mode.as_deref() == Some("cloudflare"))
        .unwrap_or(false);
    CloudflarePreflightView {
        workspace_root_found: preflight.workspace_root_found,
        service_root: preflight.service_root,
        wrangler_available: preflight.wrangler_available,
        wrangler_logged_in: preflight.wrangler_logged_in,
        runtime_bound,
        deployment_bundle_present,
        identity_ready,
        blocking_error: if !identity_ready {
            Some("Local identity is not initialized.".into())
        } else {
            preflight.blocking_error
        },
    }
}

fn onboarding_step(
    has_profiles: bool,
    has_identity: bool,
    runtime: Option<&RuntimeStatusView>,
) -> String {
    if !has_profiles {
        return "welcome".into();
    }
    if !has_identity {
        return "identity".into();
    }
    if !runtime.map(|value| value.deployment_bound).unwrap_or(false) {
        return "runtime".into();
    }
    "complete".into()
}

fn load_driver(profile: &Profile) -> Result<CoreDriver> {
    let snapshot = profile.load_snapshot()?;
    let base_url = snapshot
        .deployment
        .as_ref()
        .map(|deployment| deployment.deployment_bundle.inbox_http_endpoint.clone());
    CoreDriver::from_snapshot(snapshot, base_url)
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

async fn run_identity_command(
    profile_path: &Path,
    device_name: &str,
    mnemonic: Option<String>,
    additional: bool,
) -> Result<IdentitySummaryView> {
    let mut profile = Profile::open(profile_path)?;
    let mut driver = load_driver(&profile)?;
    let command = if additional {
        CoreCommand::CreateAdditionalDeviceIdentity {
            mnemonic,
            device_name: Some(device_name.to_string()),
        }
    } else {
        CoreCommand::CreateOrLoadIdentity {
            mnemonic,
            device_name: Some(device_name.to_string()),
        }
    };
    driver.run_command_until_idle(command).await?;
    persist_driver(&mut profile, &driver)?;
    let identity = driver
        .local_identity()
        .ok_or_else(|| anyhow!("identity creation did not persist local identity"))?;
    Ok(IdentitySummaryView {
        user_id: identity.user_identity.user_id.clone(),
        device_id: identity.device_identity.device_id.clone(),
        device_status: format!("{:?}", identity.device_status.status).to_lowercase(),
        profile_path: profile.root().to_path_buf(),
        mnemonic: identity.mnemonic.clone(),
    })
}

async fn provision_cloudflare_profile(
    profile: &mut Profile,
    driver: &mut CoreDriver,
    user_id: &str,
    device_id: &str,
    service_root: &Path,
    config: ResolvedCloudflareDeployConfig,
) -> Result<ProvisionProgressView> {
    let deployment = deploy_cloudflare_runtime(service_root, &config).await?;
    crate::cli::runtime::wait_until_ready(&deployment.effective_public_base_url).await?;
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
    let identity = identity_summary_from_profile(profile)?
        .ok_or_else(|| anyhow!("local identity is not available after provision"))?;
    let runtime = runtime_status_from_profile(profile)?;
    Ok(ProvisionProgressView {
        provisioned: true,
        mode: "cloudflare".into(),
        runtime,
        identity,
    })
}

async fn provision_cloudflare_action(
    action: &str,
    profile: &mut Profile,
    driver: &mut CoreDriver,
    user_id: &str,
    device_id: &str,
    service_root: &Path,
    config: ResolvedCloudflareDeployConfig,
) -> Result<CloudflareActionResultView> {
    let _ = provision_cloudflare_profile(
        profile,
        driver,
        user_id,
        device_id,
        service_root,
        config,
    )
    .await?;
    let runtime = cloudflare_runtime_details_from_profile(profile)?;
    Ok(CloudflareActionResultView {
        action: action.into(),
        updated_runtime: true,
        deployment_bound: runtime.runtime.deployment_bound,
        banner: BannerView {
            severity: "success".into(),
            message: match action {
                "redeploy" => "Cloudflare runtime redeployed.".into(),
                "rotate_secrets" => {
                    "Cloudflare secrets rotated and deployment rebound.".into()
                }
                _ => "Cloudflare runtime updated.".into(),
            },
        },
        runtime,
    })
}

fn local_device_id(driver: &CoreDriver) -> Result<String> {
    driver
        .local_identity()
        .map(|identity| identity.device_identity.device_id.clone())
        .ok_or_else(|| anyhow!("local identity is not initialized"))
}

fn sync_status_from_driver(driver: &CoreDriver, device_id: Option<String>) -> SyncStatusView {
    let checkpoint = device_id
        .as_deref()
        .and_then(|value| driver.sync_checkpoint_snapshot(value));
    let transfer_counts = driver
        .latest_snapshot()
        .map(|snapshot| {
            let mut pending_uploads = 0usize;
            for transfer in &snapshot.pending_blob_transfers {
                if matches!(transfer, PersistedPendingBlobTransfer::Upload { .. }) {
                    pending_uploads = pending_uploads.saturating_add(1);
                }
            }
            pending_uploads
        })
        .unwrap_or_default();
    SyncStatusView {
        device_id,
        checkpoint,
        pending_outbox: driver.pending_outbox_count(),
        pending_blob_uploads: transfer_counts,
        recovery_conversations: driver.recovery_conversations(),
    }
}

fn map_contact_devices(devices: Vec<ContactDeviceSnapshot>) -> Vec<ContactDeviceView> {
    devices
        .into_iter()
        .map(|device| ContactDeviceView {
            device_id: device.device_id,
            status: format!("{:?}", device.status).to_lowercase(),
        })
        .collect()
}

fn map_message_request(item: MessageRequestItem) -> MessageRequestItemView {
    MessageRequestItemView {
        request_id: item.request_id,
        recipient_device_id: item.recipient_device_id,
        sender_user_id: item.sender_user_id,
        first_seen_at: item.first_seen_at,
        last_seen_at: item.last_seen_at,
        message_count: item.message_count,
        last_message_id: item.last_message_id,
        last_conversation_id: item.last_conversation_id,
    }
}

fn map_message_request_action(
    summary: &crate::ffi_api::MessageRequestActionSummary,
) -> MessageRequestActionView {
    MessageRequestActionView {
        accepted: summary.accepted,
        request_id: summary.request_id.clone(),
        sender_user_id: summary.sender_user_id.clone(),
        promoted_count: summary.promoted_count,
        action: format!("{:?}", summary.action).to_lowercase(),
    }
}

fn map_allowlist(document: &AllowlistDocument) -> AllowlistView {
    AllowlistView {
        allowed_sender_user_ids: document.allowed_sender_user_ids.clone(),
        rejected_sender_user_ids: document.rejected_sender_user_ids.clone(),
    }
}

fn map_message(
    conversation_id: &str,
    message: &StoredMessage,
    peer_user_id: &str,
    local_identity: Option<&crate::identity::LocalIdentityState>,
    attachment_state: Option<&DesktopProfileState>,
    profile: Option<&Profile>,
) -> MessageItemView {
    let local_user_id = local_identity.map(|identity| identity.user_identity.user_id.as_str());
    let local_device_id = local_identity.map(|identity| identity.device_identity.device_id.as_str());
    let is_outgoing = local_device_id == Some(message.sender_device_id.as_str());
    let sender_user_id = if is_outgoing {
        local_user_id.map(ToOwned::to_owned)
    } else {
        Some(peer_user_id.to_string())
    };
    let primary_attachment_local_path = attachment_state
        .and_then(|state| profile.and_then(|profile| attachment_local_path(profile, state, &message.message_id)));
    let primary_attachment_display_name = attachment_state
        .map(|state| attachment_display_name(state, &message.message_id, message.storage_refs.first()));
    let primary_attachment_previewable = primary_attachment_local_path
        .as_ref()
        .is_some_and(|path| path.exists())
        && message
            .storage_refs
            .first()
            .map(|reference| reference.mime_type.starts_with("image/"))
            .unwrap_or(false);
    MessageItemView {
        conversation_id: conversation_id.to_string(),
        message_id: message.message_id.clone(),
        sender_user_id,
        direction: if is_outgoing {
            "outgoing".into()
        } else {
            "incoming".into()
        },
        message_type: message.message_type,
        plaintext: message.plaintext.clone(),
        created_at: Some(message.created_at.to_string()),
        storage_refs: message.storage_refs.clone(),
        has_attachment: !message.storage_refs.is_empty(),
        attachment_count: message.storage_refs.len(),
        downloaded_attachment_available: message.downloaded_blob_b64.is_some()
            || primary_attachment_local_path
                .as_ref()
                .is_some_and(|path| path.exists()),
        attachment_refs: message.storage_refs.clone(),
        primary_attachment_previewable,
        primary_attachment_local_path,
        primary_attachment_display_name,
    }
}

fn load_identity_bundle(bundle_json_or_path: &str) -> Result<IdentityBundle> {
    let bundle = if Path::new(bundle_json_or_path).exists() {
        Profile::load_identity_bundle_file(bundle_json_or_path)?
    } else {
        serde_json::from_str::<IdentityBundle>(bundle_json_or_path)
            .context("decode identity bundle json")?
    };
    bundle.validate().map_err(anyhow::Error::from)?;
    Ok(bundle)
}

fn latest_notification_since(driver: &CoreDriver, offset: usize) -> Option<String> {
    driver
        .notifications()
        .get(offset..)
        .and_then(|notifications| notifications.last().cloned())
}

fn message_requests_from_output(output: &CoreOutput) -> Result<&Vec<MessageRequestItem>> {
    output
        .view_model
        .as_ref()
        .map(|view| &view.message_requests)
        .ok_or_else(|| anyhow!("message requests were not returned by core"))
}

fn message_request_action_from_output(
    output: &CoreOutput,
) -> Result<&crate::ffi_api::MessageRequestActionSummary> {
    output
        .view_model
        .as_ref()
        .and_then(|view| view.message_request_action.as_ref())
        .ok_or_else(|| anyhow!("message request action result was not returned by core"))
}

fn allowlist_from_output(output: &CoreOutput) -> Result<&AllowlistDocument> {
    output
        .view_model
        .as_ref()
        .and_then(|view| view.allowlist.as_ref())
        .ok_or_else(|| anyhow!("allowlist document was not returned by core"))
}

fn message_preview(message: &StoredMessage) -> Option<String> {
    if let Some(text) = message.plaintext.as_deref() {
        return Some(text.to_string());
    }
    if !message.storage_refs.is_empty() {
        return Some("Attachment".into());
    }
    None
}

fn default_background_enabled() -> bool {
    true
}

fn desktop_profile_state_path(profile_root: &Path) -> PathBuf {
    profile_root.join("desktop_state.json")
}

fn load_desktop_profile_state(profile_root: &Path) -> Result<DesktopProfileState> {
    let path = desktop_profile_state_path(profile_root);
    if !path.exists() {
        return Ok(DesktopProfileState::default());
    }
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("read desktop state {}", path.display()))?;
    Ok(serde_json::from_str(&raw).context("decode desktop state")?)
}

fn save_desktop_profile_state(profile_root: &Path, state: &DesktopProfileState) -> Result<()> {
    let path = desktop_profile_state_path(profile_root);
    let raw = serde_json::to_string_pretty(state).context("encode desktop state")?;
    fs::write(&path, raw).with_context(|| format!("write desktop state {}", path.display()))?;
    Ok(())
}

fn record_recent_transfer(profile_root: &Path, transfer: RecordedAttachmentTransfer) -> Result<()> {
    let mut state = load_desktop_profile_state(profile_root)?;
    state.recent_transfers.retain(|item| item.transfer_id != transfer.transfer_id);
    state.recent_transfers.insert(0, transfer);
    state.recent_transfers.truncate(20);
    save_desktop_profile_state(profile_root, &state)
}

fn record_saved_attachment(
    profile_root: &Path,
    message_id: &str,
    local_path: &Path,
    mime_type: Option<String>,
    display_name: Option<String>,
) -> Result<()> {
    let mut state = load_desktop_profile_state(profile_root)?;
    state.saved_attachments.insert(
        message_id.to_string(),
        SavedAttachmentRecord {
            local_path: local_path.to_path_buf(),
            mime_type,
            display_name,
            opened: false,
        },
    );
    save_desktop_profile_state(profile_root, &state)
}

fn attachment_local_path(
    profile: &Profile,
    desktop_state: &DesktopProfileState,
    message_id: &str,
) -> Option<PathBuf> {
    if let Some(saved) = desktop_state.saved_attachments.get(message_id) {
        return Some(saved.local_path.clone());
    }
    let default_path = profile
        .metadata()
        .inbox_attachments_dir
        .join(format!("{message_id}.bin"));
    default_path.exists().then_some(default_path)
}

fn attachment_display_name(
    desktop_state: &DesktopProfileState,
    message_id: &str,
    attachment_ref: Option<&StorageRef>,
) -> String {
    if let Some(saved) = desktop_state.saved_attachments.get(message_id) {
        if let Some(display_name) = saved.display_name.as_ref() {
            return display_name.clone();
        }
        if let Some(file_name) = saved.local_path.file_name() {
            return file_name.to_string_lossy().to_string();
        }
    }
    attachment_ref
        .map(|reference| reference.mime_type.clone())
        .unwrap_or_else(|| "attachment".into())
}

fn find_message_with_attachment(
    profile: &Profile,
    message_id: &str,
    reference: Option<&str>,
) -> Result<(StoredMessage, Option<StorageRef>)> {
    let driver = load_driver(profile)?;
    for conversation in driver
        .latest_snapshot()
        .into_iter()
        .flat_map(|snapshot| snapshot.conversations.clone())
    {
        if let Some(message) = conversation
            .state
            .messages
            .into_iter()
            .find(|message| message.message_id == message_id)
        {
            let attachment_ref = message.storage_refs.iter().find(|item| {
                reference.is_none_or(|value| value == item.object_ref.as_str())
            }).cloned();
            return Ok((message, attachment_ref));
        }
    }
    Err(anyhow!("message {message_id} not found"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AttachmentTransferCounts {
    pending_uploads: usize,
    pending_downloads: usize,
}

fn attachment_transfer_counts(profile_path: impl AsRef<Path>) -> Result<AttachmentTransferCounts> {
    let profile = Profile::open(profile_path)?;
    let snapshot = profile.load_snapshot()?;
    let mut pending_uploads = 0usize;
    let mut pending_downloads = 0usize;
    for transfer in snapshot.pending_blob_transfers {
        match transfer {
            PersistedPendingBlobTransfer::Upload { .. } => {
                pending_uploads = pending_uploads.saturating_add(1);
            }
            PersistedPendingBlobTransfer::Download { .. } => {
                pending_downloads = pending_downloads.saturating_add(1);
            }
        }
    }
    Ok(AttachmentTransferCounts {
        pending_uploads,
        pending_downloads,
    })
}

fn map_transfer(
    transfer: PersistedPendingBlobTransfer,
    conversation_filter: Option<&str>,
) -> Option<AttachmentTransferView> {
    match transfer {
        PersistedPendingBlobTransfer::Upload {
            task_id,
            conversation_id,
            message_id,
            file_name,
            prepared_upload,
            retries,
            ..
        } => {
            if conversation_filter.is_some_and(|value| value != conversation_id) {
                return None;
            }
            Some(AttachmentTransferView {
                transfer_id: task_id.clone(),
                task_kind: "upload".into(),
                conversation_id,
                scope: "conversation".into(),
                message_id: Some(message_id),
                file_name,
                reference: None,
                state: if prepared_upload.is_some() {
                    "in_flight".into()
                } else {
                    "pending".into()
                },
                retryable: Some(retries < 3),
                detail: None,
                progress_label: Some("uploading".into()),
                destination_path: None,
                opened: Some(false),
            })
        }
        PersistedPendingBlobTransfer::Download {
            task_id,
            conversation_id,
            message_id,
            reference,
            destination_id,
            retries,
            ..
        } => {
            if conversation_filter.is_some_and(|value| value != conversation_id) {
                return None;
            }
            Some(AttachmentTransferView {
                transfer_id: task_id,
                task_kind: "download".into(),
                conversation_id,
                scope: "conversation".into(),
                message_id: Some(message_id),
                file_name: None,
                reference: Some(reference),
                state: "in_flight".into(),
                retryable: Some(retries < 3),
                detail: None,
                progress_label: Some("downloading".into()),
                destination_path: Some(PathBuf::from(destination_id)),
                opened: Some(false),
            })
        }
    }
}

fn map_recorded_transfer(transfer: RecordedAttachmentTransfer) -> AttachmentTransferView {
    AttachmentTransferView {
        transfer_id: transfer.transfer_id,
        task_kind: transfer.task_kind,
        conversation_id: transfer.conversation_id,
        scope: transfer.scope,
        message_id: transfer.message_id,
        file_name: transfer.file_name,
        reference: transfer.reference,
        state: transfer.state,
        retryable: transfer.retryable,
        detail: transfer.detail,
        progress_label: transfer.progress_label,
        destination_path: transfer.destination_path,
        opened: transfer.opened,
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

pub fn map_realtime_snapshot(
    device_id: Option<String>,
    snapshot: Option<RealtimeSessionSnapshot>,
    connected: bool,
) -> RealtimeStatusView {
    RealtimeStatusView {
        device_id,
        connected,
        last_known_seq: snapshot.map(|value| value.last_known_seq).unwrap_or_default(),
        needs_reconnect: snapshot.map(|value| value.needs_reconnect).unwrap_or(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn onboarding_step_transitions_match_expected_order() {
        assert_eq!(onboarding_step(false, false, None), "welcome");
        assert_eq!(onboarding_step(true, false, None), "identity");
        assert_eq!(
            onboarding_step(
                true,
                true,
                Some(&RuntimeStatusView {
                    mode: None,
                    deployment_bound: false,
                    public_base_url: None,
                    worker_name: None,
                    provisioned_at: None,
                    last_error: None,
                }),
            ),
            "runtime"
        );
        assert_eq!(
            onboarding_step(
                true,
                true,
                Some(&RuntimeStatusView {
                    mode: Some("cloudflare".into()),
                    deployment_bound: true,
                    public_base_url: Some("https://example.com".into()),
                    worker_name: Some("tapchat".into()),
                    provisioned_at: None,
                    last_error: None,
                }),
            ),
            "complete"
        );
    }
}

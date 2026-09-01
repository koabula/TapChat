//! Test-only helpers for desktop integration tests.
//!
//! Gated behind `#[cfg(any(test, feature = "test-support"))]` so the
//! surface is not accidentally exposed in production builds. Exposes:
//!
//!   - [`build_test_app_state_for_profile`] — construct an `AppState`
//!     bound to an on-disk profile directory without any Tauri webview.
//!   - Re-exports of the group-command `_impl` functions so
//!     `tests/desktop_group_e2e.rs` can drive each command directly as
//!     an ordinary async fn.
//!
//! Production builds never touch this module.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::{Mutex, RwLock, mpsc};

use tapchat_core::CoreEngine;
use tapchat_core::cli::profile::Profile;

use crate::platform::profile::{ProfileManager, ProfileManagerInner};
use crate::ports::DesktopPlatformPorts;
use crate::state::{
    AppState, AppStateInner, ForegroundSyncGate, RecoveryPhraseGate, SessionState, StartupPhase,
    SyncGateState, WsStatusSnapshot,
};

// Re-export the no-handle driver so integration tests can drive the
// engine through the same retry / effects plumbing the production
// `drive_core_with_handle` uses (minus the UI emit and the `AppHandle`
// registration).
pub use crate::lifecycle::{CoreInput, drive_core_without_handle};

// Re-export all group Tauri command `_impl` functions so integration
// tests can call them as plain async functions.
pub use crate::commands::group::{
    approve_group_join_impl, approve_group_leave_impl, create_group_conversation_impl,
    create_group_invite_link_impl, dissolve_group_impl, get_group_join_request_status_impl,
    get_group_messages_impl, get_group_snapshot_impl, invite_to_group_impl, leave_group_impl,
    list_group_conversations_impl, list_group_invites_impl, list_group_join_requests_impl,
    list_group_leave_requests_impl, reject_group_join_impl, remove_group_member_impl,
    revoke_group_invite_link_impl, send_group_text_message_impl, set_group_admin_impl,
    submit_group_join_request_impl, sync_group_outbox_impl, transfer_group_ownership_impl,
    update_group_metadata_impl,
};
pub use crate::commands::message::{download_attachment_impl, send_attachment_impl};

// Re-export the projection types so integration tests can pattern-
// match against them (`GroupMessageView::SystemBanner { .. }`, etc.)
// without needing to reach into the private command module directly.
pub use crate::commands::group::{
    ApproveGroupJoinResult, CreateGroupConversationResult, CreateGroupInviteLinkResult,
    DissolveGroupResult, GroupConversationSummary, GroupInviteView, GroupJoinRequestView,
    GroupJoinStatusView, GroupLeaveRequestView, GroupMessageView, GroupSnapshotView,
    InviteToGroupResult, RevokeGroupInviteLinkResult, SendGroupTextResult,
    SubmitGroupJoinRequestResult, SyncGroupOutboxResult, UpdateGroupMetadataResult,
    WelcomePickupShareable,
};

/// Construct an [`AppState`] bound to an existing on-disk profile.
///
/// Used by `tests/desktop_group_e2e.rs` to exercise the desktop Tauri
/// command surface without standing up a webview. Mirrors the relevant
/// subset of the real startup path in
/// [`crate::lifecycle::on_app_ready`]:
///
///   - Opens the profile via [`Profile::open`].
///   - Loads the persisted snapshot and propagates any load error.
///   - Restores the engine via
///     [`CoreEngine::try_from_restored_state`], propagating fatal restore errors.
///   - Constructs [`DesktopPlatformPorts`] without ever calling
///     `set_app_handle` (the handle is only required for UI progress
///     emits which tests don't observe).
///   - Marks the session `Active` with the device id recorded on the
///     profile (falling back to `"unknown-device"` when the profile has
///     not recorded one yet).
///   - Sets `startup_phase = Ready`.
///
/// The returned `AppState` is directly callable by every
/// `*_impl(state: &AppState, ...)` group command.
pub async fn build_test_app_state_for_profile(profile_root: &Path) -> Result<AppState> {
    let profile = Profile::open(profile_root)
        .with_context(|| format!("open desktop test profile at {}", profile_root.display()))?;

    // Capture the fields we need before moving `profile` into the inner
    // ProfileManagerInner. `device_id` is used to tag the `SessionState`
    // so downstream commands (which read it via `AppState`) behave
    // exactly like a real logged-in session.
    let device_id = profile
        .metadata()
        .device_id
        .clone()
        .unwrap_or_else(|| "unknown-device".to_string());
    let profile_path = profile.root().to_path_buf();
    let snapshot = profile.load_snapshot().with_context(|| {
        format!(
            "load desktop test profile snapshot at {}",
            profile_path.display()
        )
    })?;

    // The ProfileManager wraps a shared registry; we don't need a real
    // registry for test usage — an empty default suffices because no
    // test path calls `list_profiles` or similar multi-profile APIs.
    let registry = Default::default();

    let inner_lock: Arc<RwLock<ProfileManagerInner>> = Arc::new(RwLock::new(ProfileManagerInner {
        registry,
        active_profile: Some(profile),
        locked_profile_path: None,
        unlock_error: None,
        storage_layout: crate::storage_layout::DesktopStorageLayout::system_default()?,
    }));
    let profile_manager = ProfileManager::from_inner(inner_lock.clone());

    let engine = CoreEngine::try_from_restored_state(snapshot)
        .context("restore desktop test profile snapshot")?;
    let runtime_auth = crate::runtime_auth::RuntimeAuthManager::default();
    let ports = DesktopPlatformPorts::new(inner_lock.clone(), runtime_auth.clone());
    let (deferred_transport_tx, deferred_transport_rx) = mpsc::channel(128);

    Ok(AppState {
        inner: Arc::new(RwLock::new(AppStateInner {
            engine,
            profile_manager,
            session: SessionState::Active { device_id },
            profile_path: Some(profile_path),
            startup_phase: StartupPhase::Ready,
        })),
        ports: Arc::new(Mutex::new(ports)),
        sync_gate: Arc::new(Mutex::new(SyncGateState::default())),
        ws_status: Arc::new(RwLock::new(WsStatusSnapshot::default())),
        foreground_sync_gate: Arc::new(Mutex::new(ForegroundSyncGate::default())),
        recovery_phrase_gate: Arc::new(Mutex::new(RecoveryPhraseGate::default())),
        deferred_transport_tx,
        deferred_transport_rx: Arc::new(Mutex::new(Some(deferred_transport_rx))),
        deferred_send_gate: Arc::new(Mutex::new(())),
        runtime_auth,
        media_handles: Arc::new(RwLock::new(std::collections::HashMap::new())),
        staged_attachments: Arc::new(Mutex::new(std::collections::HashMap::new())),
        saved_attachment_paths: Arc::new(RwLock::new(std::collections::HashSet::new())),
        media_inflight: Arc::new(Mutex::new(std::collections::HashMap::new())),
        media_network_limit: Arc::new(tokio::sync::Semaphore::new(3)),
        media_decode_limit: Arc::new(tokio::sync::Semaphore::new(2)),
        preview_prefetch_running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        profile_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        persistence_revision: Arc::new(std::sync::atomic::AtomicU64::new(0)),
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use tapchat_core::cli::profile::{
        Profile, ProfileInitOptions, override_profile_registry_path_for_test,
    };
    use uuid::Uuid;

    use super::build_test_app_state_for_profile;

    fn test_profile_root() -> PathBuf {
        let root = std::env::temp_dir()
            .join(format!("tapchat-desktop-fail-closed-{}", Uuid::new_v4()))
            .join("broken");
        std::fs::create_dir_all(&root).expect("create profile root");
        root
    }

    #[tokio::test]
    async fn build_test_app_state_for_profile_rejects_corrupt_snapshot_store() {
        let root = test_profile_root();
        let passphrase = "test-passphrase";
        let registry_path = root
            .parent()
            .expect("profile test parent")
            .join("config")
            .join("profiles.json");
        let _registry_override = override_profile_registry_path_for_test(&registry_path);
        let profile = Profile::init_with_options(
            "broken",
            &root,
            ProfileInitOptions {
                passphrase: Some(passphrase.into()),
                use_keychain: false,
            },
        )
        .expect("init profile");
        let state_db_path = profile.state_db_path();
        drop(profile);
        std::fs::write(&state_db_path, b"not a sqlite database").expect("corrupt state db");

        unsafe {
            std::env::set_var("TAPCHAT_PROFILE_PASSPHRASE", passphrase);
        }
        let error = match build_test_app_state_for_profile(&root).await {
            Ok(_) => panic!("corrupt store should not start with an empty engine"),
            Err(error) => error,
        };
        unsafe {
            std::env::remove_var("TAPCHAT_PROFILE_PASSPHRASE");
        }

        let message = format!("{error:#}");
        assert!(
            message.contains("open desktop test profile")
                || message.contains("load desktop test profile snapshot"),
            "unexpected error: {message}"
        );
        assert_eq!(
            std::fs::read(&state_db_path).expect("read corrupted db"),
            b"not a sqlite database"
        );
    }
}

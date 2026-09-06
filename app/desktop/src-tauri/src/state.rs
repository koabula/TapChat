use std::collections::HashMap;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tapchat_core::ffi_api::AttachmentDescriptor;
use tapchat_core::{CoreEffect, CoreEngine};
use tokio::sync::{mpsc, Mutex, RwLock, Semaphore};

use crate::platform::profile::ProfileManager;
use crate::ports::DesktopPlatformPorts;
use crate::runtime_auth::RuntimeAuthManager;
use crate::storage_layout::DesktopStorageLayout;

/// Startup phase to track initialization progress.
/// Prevents race conditions where frontend queries session status before backend is ready.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StartupPhase {
    #[default]
    NotStarted,
    LoadingProfile,
    Ready,
}

/// Central application state, shared across all Tauri commands via `tauri::State`.
/// Uses `tokio::sync::RwLock` — never `std::sync::Mutex` — to avoid blocking the
/// async runtime.
pub struct AppState {
    pub inner: Arc<RwLock<AppStateInner>>,
    pub ports: Arc<Mutex<DesktopPlatformPorts>>,
    pub sync_gate: Arc<Mutex<SyncGateState>>,
    pub ws_status: Arc<RwLock<WsStatusSnapshot>>,
    pub foreground_sync_gate: Arc<Mutex<ForegroundSyncGate>>,
    pub recovery_phrase_gate: Arc<Mutex<RecoveryPhraseGate>>,
    pub deferred_transport_tx: mpsc::Sender<DeferredTransportBatch>,
    pub deferred_transport_rx: Arc<Mutex<Option<mpsc::Receiver<DeferredTransportBatch>>>>,
    pub deferred_send_gate: Arc<Mutex<()>>,
    pub runtime_auth: RuntimeAuthManager,
    pub media_handles: Arc<RwLock<HashMap<String, MediaHandle>>>,
    pub staged_attachments: Arc<Mutex<HashMap<String, StagedAttachment>>>,
    pub saved_attachment_paths: Arc<RwLock<HashSet<PathBuf>>>,
    pub media_inflight: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
    pub media_network_limit: Arc<Semaphore>,
    pub media_decode_limit: Arc<Semaphore>,
    pub preview_prefetch_running: Arc<AtomicBool>,
    pub profile_generation: Arc<AtomicU64>,
    /// Monotonic, process-local revision for committed Desktop state updates.
    /// This is deliberately not part of Core or the transport protocol.
    pub persistence_revision: Arc<AtomicU64>,
}

#[derive(Clone)]
pub struct MediaHandle {
    pub source: MediaHandleSource,
    pub mime_type: String,
    pub profile_path: Option<PathBuf>,
    pub profile_generation: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone)]
pub enum MediaHandleSource {
    InMemory {
        bytes: Arc<Vec<u8>>,
    },
    ChunkedVideo {
        conversation_id: String,
        message_id: String,
        descriptor: tapchat_core::attachment_crypto::EncryptedBlobDescriptor,
    },
}

#[derive(Clone)]
pub struct StagedAttachment {
    pub descriptor: AttachmentDescriptor,
    pub profile_path: Option<PathBuf>,
    pub profile_generation: u64,
    pub preview_handle: Option<String>,
}

/// A persisted batch waiting for serialized network dispatch. The profile path
/// prevents a queued send from borrowing credentials after a profile switch.
pub struct DeferredTransportBatch {
    pub effects: Vec<CoreEffect>,
    pub profile_path: Option<PathBuf>,
    pub enqueued_at: Instant,
}

const DEFERRED_TRANSPORT_QUEUE_CAPACITY: usize = 128;

pub struct AppStateInner {
    pub engine: CoreEngine,
    pub profile_manager: ProfileManager,
    pub session: SessionState,
    pub profile_path: Option<PathBuf>,
    pub startup_phase: StartupPhase,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SessionState {
    Uninitialized,
    Onboarding {
        step: OnboardingStep,
    },
    Active {
        device_id: String,
    },
    Locked {
        profile_path: Option<PathBuf>,
        error: String,
        reason: LockReason,
    },
    Quitting,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockReason {
    ProfileLocked,
    ProfileSelectionRequired,
    SnapshotLoadFailed,
    RestoreFailed,
}

impl LockReason {
    pub fn as_str(self) -> &'static str {
        match self {
            LockReason::ProfileLocked => "profile_locked",
            LockReason::ProfileSelectionRequired => "profile_selection_required",
            LockReason::SnapshotLoadFailed => "snapshot_load_failed",
            LockReason::RestoreFailed => "restore_failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnboardingStep {
    Welcome,
    CreateIdentity,
    RecoverIdentity,
    BackupMnemonic,
    CloudflareSetup,
    Complete,
}

#[derive(Debug, Default)]
pub struct SyncGateState {
    pub in_flight: bool,
    pub pending: bool,
}

#[derive(Debug, Default)]
pub struct ForegroundSyncGate {
    pub last_triggered_at: Option<Instant>,
}

#[derive(Debug, Clone, Default)]
pub struct WsStatusSnapshot {
    pub ws_connected: bool,
    pub last_known_device_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryPhraseAuthMode {
    Passphrase,
    ConfirmationOnly,
}

pub struct RecoveryPhraseChallenge {
    pub challenge_id: String,
    pub profile_path: PathBuf,
    pub auth_mode: RecoveryPhraseAuthMode,
    pub expires_at: Instant,
}

#[derive(Default)]
pub struct RecoveryPhraseGate {
    pub pending: Option<RecoveryPhraseChallenge>,
}

impl AppState {
    pub fn new() -> Self {
        Self::with_profile_manager(ProfileManager::new())
    }

    pub fn with_storage_layout(layout: DesktopStorageLayout) -> Self {
        Self::with_profile_manager(ProfileManager::with_layout(layout))
    }

    /// Create AppState with a specific registered profile selector.
    pub fn with_profile_selector(selector: &str) -> Self {
        Self::with_profile_manager(ProfileManager::with_profile_selector(selector))
    }

    pub fn with_profile_selector_and_storage_layout(
        selector: &str,
        layout: DesktopStorageLayout,
    ) -> Self {
        Self::with_profile_manager(ProfileManager::with_profile_selector_and_layout(
            selector, layout,
        ))
    }

    fn with_profile_manager(profile_manager: ProfileManager) -> Self {
        let inner_arc = profile_manager.inner_arc();
        let runtime_auth = RuntimeAuthManager::default();
        let ports = DesktopPlatformPorts::new(inner_arc, runtime_auth.clone());
        let (deferred_transport_tx, deferred_transport_rx) =
            mpsc::channel(DEFERRED_TRANSPORT_QUEUE_CAPACITY);
        Self {
            inner: Arc::new(RwLock::new(AppStateInner {
                engine: CoreEngine::new(),
                profile_manager,
                session: SessionState::Uninitialized,
                profile_path: None,
                startup_phase: StartupPhase::NotStarted,
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
            media_handles: Arc::new(RwLock::new(HashMap::new())),
            staged_attachments: Arc::new(Mutex::new(HashMap::new())),
            saved_attachment_paths: Arc::new(RwLock::new(HashSet::new())),
            media_inflight: Arc::new(Mutex::new(HashMap::new())),
            media_network_limit: Arc::new(Semaphore::new(3)),
            media_decode_limit: Arc::new(Semaphore::new(2)),
            preview_prefetch_running: Arc::new(AtomicBool::new(false)),
            profile_generation: Arc::new(AtomicU64::new(0)),
            persistence_revision: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Get the inner Arc for use with helper functions.
    pub fn inner(&self) -> &Arc<RwLock<AppStateInner>> {
        &self.inner
    }
}

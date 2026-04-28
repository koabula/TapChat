use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tapchat_core::CoreEngine;
use tokio::sync::{Mutex, RwLock};

use crate::platform::profile::ProfileManager;
use crate::ports::DesktopPlatformPorts;

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
    pub sync_gate: Arc<Mutex<SyncGateState>>,
    pub ws_status: Arc<RwLock<WsStatusSnapshot>>,
}

pub struct AppStateInner {
    pub engine: CoreEngine,
    pub ports: DesktopPlatformPorts,
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
    Quitting,
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

#[derive(Debug, Clone, Default)]
pub struct WsStatusSnapshot {
    pub ws_connected: bool,
    pub last_known_device_id: Option<String>,
}

impl AppState {
    pub fn new() -> Self {
        let profile_manager = ProfileManager::new();
        let inner_arc = profile_manager.inner_arc();
        Self {
            inner: Arc::new(RwLock::new(AppStateInner {
                engine: CoreEngine::new(),
                ports: DesktopPlatformPorts::new(inner_arc),
                profile_manager,
                session: SessionState::Uninitialized,
                profile_path: None,
                startup_phase: StartupPhase::NotStarted,
            })),
            sync_gate: Arc::new(Mutex::new(SyncGateState::default())),
            ws_status: Arc::new(RwLock::new(WsStatusSnapshot::default())),
        }
    }

    /// Create AppState with a specific profile name (for multi-instance mode).
    pub fn with_profile_name(name: &str) -> Self {
        let profile_manager = ProfileManager::with_profile_name(name);
        let inner_arc = profile_manager.inner_arc();
        Self {
            inner: Arc::new(RwLock::new(AppStateInner {
                engine: CoreEngine::new(),
                ports: DesktopPlatformPorts::new(inner_arc),
                profile_manager,
                session: SessionState::Uninitialized,
                profile_path: None,
                startup_phase: StartupPhase::NotStarted,
            })),
            sync_gate: Arc::new(Mutex::new(SyncGateState::default())),
            ws_status: Arc::new(RwLock::new(WsStatusSnapshot::default())),
        }
    }

    /// Get the inner Arc for use with helper functions.
    pub fn inner(&self) -> &Arc<RwLock<AppStateInner>> {
        &self.inner
    }
}

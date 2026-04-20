use std::sync::Arc;

use tauri::AppHandle;
use tapchat_core::CoreEvent;
use tokio::time::{sleep, Duration};

use crate::lifecycle::{CoreInput, drive_core_with_handle};

/// Schedule a timer that will fire after the given delay.
/// The timer triggers a CoreEvent::TimerTriggered that gets fed back into the core engine.
pub fn schedule_timer(app_handle: Option<Arc<AppHandle>>, timer_id: String, delay_ms: u64) {
    tokio::spawn(async move {
        sleep(Duration::from_millis(delay_ms)).await;

        log::info!("Timer triggered: {}", timer_id);

        if let Some(app) = app_handle {
            if let Err(error) = drive_core_with_handle(
                &app,
                CoreInput::Event(CoreEvent::TimerTriggered { timer_id: timer_id.clone() }),
            ).await {
                log::error!("Timer {} failed to drive core: {}", timer_id, error);
            }
        } else {
            log::warn!("Timer {} fired without app handle; dropping event", timer_id);
        }
    });
}

/// Timer manager that holds app handle for proper event emission.
/// This is set up during app initialization.
#[allow(dead_code)]
pub struct TimerManager {
    app_handle: Option<Arc<AppHandle>>,
}

impl TimerManager {
    pub fn new() -> Self {
        Self { app_handle: None }
    }

    /// Set the app handle for timer callbacks.
    pub fn set_app_handle(&mut self, handle: tauri::AppHandle) {
        self.app_handle = Some(Arc::new(handle));
    }

    /// Schedule a timer with proper event emission.
    pub fn schedule_with_handle(&self, timer_id: String, delay_ms: u64) {
        schedule_timer(self.app_handle.clone(), timer_id, delay_ms);
    }
}

impl Default for TimerManager {
    fn default() -> Self {
        Self::new()
    }
}

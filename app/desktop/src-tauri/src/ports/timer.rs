use std::sync::Arc;

use tauri::Emitter;
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration};

/// Schedule a timer that will fire after the given delay.
/// The timer triggers a CoreEvent::TimerTriggered that gets fed back into the core engine.
pub fn schedule_timer(timer_id: String, delay_ms: u64) {
    // Get app handle from global state (set during setup)
    // For now, we'll spawn a task that logs the timer event
    // The actual integration needs the app handle to emit events

    tokio::spawn(async move {
        sleep(Duration::from_millis(delay_ms)).await;

        // TODO: Get app handle and call drive_core_with_handle
        // For now, just log
        log::info!("Timer triggered: {}", timer_id);

        // In production, this would emit:
        // CoreEvent::TimerTriggered { timer_id }
        // which would be fed back into drive_core
    });
}

/// Timer manager that holds app handle for proper event emission.
/// This is set up during app initialization.
#[allow(dead_code)]
pub struct TimerManager {
    app_handle: Option<Arc<RwLock<Option<tauri::AppHandle>>>>,
}

impl TimerManager {
    pub fn new() -> Self {
        Self { app_handle: None }
    }

    /// Set the app handle for timer callbacks.
    #[allow(dead_code)]
    pub fn set_app_handle(&mut self, _handle: tauri::AppHandle) {
        // Store handle for timer callbacks to use
        // This requires global state management
    }

    /// Schedule a timer with proper event emission.
    #[allow(dead_code)]
    pub fn schedule_with_handle(&self, timer_id: String, delay_ms: u64, app: tauri::AppHandle) {
        tokio::spawn(async move {
            sleep(Duration::from_millis(delay_ms)).await;

            // Emit timer event to frontend
            let _ = app.emit("timer-triggered", &timer_id);

            // The frontend or lifecycle handler will feed this into drive_core
            log::info!("Timer {} triggered after {}ms", timer_id, delay_ms);
        });
    }
}

impl Default for TimerManager {
    fn default() -> Self {
        Self::new()
    }
}
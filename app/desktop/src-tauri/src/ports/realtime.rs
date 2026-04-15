use anyhow::Result;
use tapchat_core::ffi_api::CoreEvent;
use tapchat_core::transport_contract::RealtimeSubscriptionRequest;

/// Legacy stub for realtime - now delegated to platform/realtime.rs
#[allow(dead_code)]
pub async fn open_realtime(
    _subscription: RealtimeSubscriptionRequest,
) -> Result<Vec<CoreEvent>> {
    // This function is deprecated - use RealtimeManager.open_connection() instead
    log::warn!("open_realtime stub called - use RealtimeManager");
    Ok(Vec::new())
}

#[allow(dead_code)]
pub async fn close_realtime(_device_id: String) -> Result<Vec<CoreEvent>> {
    // This function is deprecated - use RealtimeManager.close_connection() instead
    log::warn!("close_realtime stub called - use RealtimeManager");
    Ok(Vec::new())
}
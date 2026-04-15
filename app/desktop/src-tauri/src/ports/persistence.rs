use tapchat_core::ffi_api::PersistStateEffect;

/// Legacy stub for persistence - now delegated to platform/persistence.rs
#[allow(dead_code)]
pub fn persist_state(_persist: PersistStateEffect) {
    // This function is deprecated - use DesktopPersistence.persist() instead
    log::warn!("persist_state stub called - use DesktopPersistence");
}
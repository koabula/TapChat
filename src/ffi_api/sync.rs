/// Batch size for group outbox fetches during sync catch-up.
/// Increased from 100 to reduce round-trips when many messages accumulated
/// while the member was offline.
pub(super) const GROUP_OUTBOX_FETCH_LIMIT: u64 = 1000;

pub(super) const WELCOME_PICKUP_RETRY_TIMER_PREFIX: &str = "retry_welcome_pickup:";

pub(super) fn pending_welcome_pickup_key(group_id: &str, device_id: &str) -> String {
    format!("{group_id}::{device_id}")
}

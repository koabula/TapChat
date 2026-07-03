/// Batch size for group outbox fetches during sync catch-up.
/// Increased from 100 to reduce round-trips when many messages accumulated
/// while the member was offline.
pub(super) const GROUP_OUTBOX_FETCH_LIMIT: u64 = 1000;

pub(super) const WELCOME_PICKUP_RETRY_TIMER_PREFIX: &str = "retry_welcome_pickup:";

const RETRY_BASE_DELAY_MS: u64 = 1_000;
const RETRY_MAX_DELAY_MS: u64 = 60_000;
const RETRY_JITTER_BUCKETS: u64 = 251;

pub(super) fn retry_delay_ms(timer_id: &str, attempt: u32) -> u64 {
    let attempt = attempt.max(1);
    let shift = attempt.saturating_sub(1).min(16);
    let base = RETRY_BASE_DELAY_MS
        .saturating_mul(1_u64 << shift)
        .min(RETRY_MAX_DELAY_MS);
    base.saturating_add(stable_jitter_ms(timer_id))
}

fn stable_jitter_ms(timer_id: &str) -> u64 {
    timer_id.bytes().fold(0_u64, |acc, byte| {
        acc.wrapping_mul(31).wrapping_add(u64::from(byte))
    }) % RETRY_JITTER_BUCKETS
}

pub(super) fn pending_welcome_pickup_key(group_id: &str, device_id: &str) -> String {
    format!("{group_id}::{device_id}")
}

#[cfg(test)]
mod tests {
    use super::retry_delay_ms;

    #[test]
    fn retry_delay_is_exponential_capped_and_stable() {
        let timer_id = "retry_append:msg:1";
        let first = retry_delay_ms(timer_id, 1);
        let second = retry_delay_ms(timer_id, 2);
        let capped = retry_delay_ms(timer_id, 10);

        assert!((1_000..=1_250).contains(&first));
        assert!((2_000..=2_250).contains(&second));
        assert!((60_000..=60_250).contains(&capped));
        assert_eq!(first, retry_delay_ms(timer_id, 1));
    }
}

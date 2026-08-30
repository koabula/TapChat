use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};

pub const GROUP_APPLICATION_LIMIT: u32 = 32;
pub const GROUP_MAX_ACTIVE_LEAVES: usize = 16;

/// Scheduler state derived from the canonical Group Outbox application order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupPcsState {
    #[serde(default)]
    pub group_app_count_since_update: u32,
    #[serde(default)]
    pub application_index: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub leaf_last_update_index: BTreeMap<String, u64>,
}

impl GroupPcsState {
    /// Call only for an accepted, unique MLS application record.
    pub fn accepted_application(&mut self) {
        self.application_index = self.application_index.saturating_add(1);
        self.group_app_count_since_update = self.group_app_count_since_update.saturating_add(1);
    }

    /// Any canonical update-path Commit resets the global interval; only the
    /// committer leaf receives a new fairness baseline.
    pub fn update_ordered(&mut self, committer_device_id: &str) {
        self.group_app_count_since_update = 0;
        self.leaf_last_update_index
            .insert(committer_device_id.to_string(), self.application_index);
    }

    pub fn register_leaf(&mut self, device_id: &str) {
        self.leaf_last_update_index
            .entry(device_id.to_string())
            .or_insert(self.application_index);
    }

    pub fn remove_leaf(&mut self, device_id: &str) {
        self.leaf_last_update_index.remove(device_id);
    }

    pub fn leaf_age(&self, device_id: &str) -> u64 {
        self.application_index.saturating_sub(
            self.leaf_last_update_index
                .get(device_id)
                .copied()
                .unwrap_or(self.application_index),
        )
    }

    pub fn update_due(&self, device_id: &str, active_leaf_count: usize) -> bool {
        if active_leaf_count == 0 {
            return false;
        }
        self.group_app_count_since_update >= GROUP_APPLICATION_LIMIT
            || self.leaf_age(device_id)
                >= u64::from(GROUP_APPLICATION_LIMIT).saturating_mul(active_leaf_count as u64)
    }
}

pub fn validate_active_leaf_limit(active_leaf_count: usize) -> CoreResult<()> {
    if active_leaf_count > GROUP_MAX_ACTIVE_LEAVES {
        return Err(CoreError::new(
            "group_leaf_limit_exceeded",
            format!(
                "group has {active_leaf_count} active MLS leaves; maximum is {GROUP_MAX_ACTIVE_LEAVES}"
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_global_and_leaf_fairness_boundaries_are_exact() {
        let mut state = GroupPcsState::default();
        state.register_leaf("device:alice");
        for _ in 0..31 {
            state.accepted_application();
        }
        assert!(!state.update_due("device:alice", 16));
        state.accepted_application();
        assert!(state.update_due("device:alice", 16));

        state.update_ordered("device:alice");
        assert!(!state.update_due("device:alice", 16));
        for _ in 0..(GROUP_APPLICATION_LIMIT as usize * 16) {
            state.accepted_application();
            if state.group_app_count_since_update == GROUP_APPLICATION_LIMIT {
                // Model other leaves keeping the global interval fresh while
                // Alice's per-leaf age continues to grow.
                state.update_ordered("device:bob");
            }
        }
        assert_eq!(state.leaf_age("device:alice"), 32 * 16);
        assert!(state.update_due("device:alice", 16));
    }

    #[test]
    fn active_leaf_limit_accepts_sixteen_and_rejects_seventeen() {
        validate_active_leaf_limit(1).expect("one-leaf group uses the group policy");
        validate_active_leaf_limit(16).expect("sixteen leaves");
        assert_eq!(
            validate_active_leaf_limit(17)
                .expect_err("seventeen leaves")
                .code(),
            "group_leaf_limit_exceeded"
        );
    }

    #[test]
    fn leaf_age_threshold_is_exact_for_supported_group_sizes() {
        for active_leaf_count in [1usize, 2, 3, 16] {
            let mut state = GroupPcsState::default();
            state.register_leaf("device:alice");
            state.application_index =
                u64::from(GROUP_APPLICATION_LIMIT) * active_leaf_count as u64 - 1;
            state.group_app_count_since_update = 0;
            assert!(!state.update_due("device:alice", active_leaf_count));
            state.application_index += 1;
            assert!(state.update_due("device:alice", active_leaf_count));
        }
    }
}

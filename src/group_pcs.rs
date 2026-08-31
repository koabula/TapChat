use serde::{Deserialize, Serialize};

pub const GROUP_PCS_COMMIT_INTERVAL: u32 = 32;
pub const GROUP_PCS_DEBT_HARD: u32 = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GroupPcsState {
    #[serde(default)]
    pub epoch_app_count: u32,
    #[serde(default)]
    pub proposal_in_flight: bool,
    #[serde(default)]
    pub degraded: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub own_leaf_key: Option<String>,
}

impl GroupPcsState {
    pub fn note_application_message(&mut self) {
        self.epoch_app_count = self.epoch_app_count.saturating_add(1);
        if self.epoch_app_count >= GROUP_PCS_DEBT_HARD {
            self.degraded = true;
        }
    }

    pub fn should_propose(&self) -> bool {
        !self.proposal_in_flight && self.epoch_app_count >= GROUP_PCS_COMMIT_INTERVAL
    }

    pub fn should_commit(&self, is_owner_or_admin: bool, has_pending_proposals: bool) -> bool {
        is_owner_or_admin
            && (has_pending_proposals || self.epoch_app_count >= GROUP_PCS_COMMIT_INTERVAL)
    }

    pub fn mark_proposal_in_flight(&mut self) {
        self.proposal_in_flight = true;
    }

    /// Record that an MLS commit was merged.
    ///
    /// Only a change to this device's leaf encryption key clears PCS debt.
    /// A foreign epoch advance merely invalidates any in-flight proposal.
    pub fn on_commit_merged(&mut self, current_leaf_key: &str) {
        self.proposal_in_flight = false;
        match self.own_leaf_key.as_deref() {
            Some(previous) if previous == current_leaf_key => {}
            Some(_) => {
                self.own_leaf_key = Some(current_leaf_key.to_string());
                self.epoch_app_count = 0;
                self.degraded = false;
            }
            None => {
                self.own_leaf_key = Some(current_leaf_key.to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn propose_after_interval_without_in_flight() {
        let mut state = GroupPcsState::default();
        assert!(!state.should_propose());
        state.epoch_app_count = GROUP_PCS_COMMIT_INTERVAL;
        assert!(state.should_propose());
        state.mark_proposal_in_flight();
        assert!(!state.should_propose());
    }

    #[test]
    fn commit_requires_privileged_role() {
        let mut state = GroupPcsState::default();
        state.epoch_app_count = GROUP_PCS_COMMIT_INTERVAL;
        assert!(!state.should_commit(false, false));
        assert!(state.should_commit(true, false));
        state.epoch_app_count = 0;
        assert!(state.should_commit(true, true));
        assert!(!state.should_commit(true, false));
    }

    #[test]
    fn debt_hard_marks_degraded() {
        let mut state = GroupPcsState::default();
        state.epoch_app_count = GROUP_PCS_DEBT_HARD - 1;
        state.note_application_message();
        assert!(state.degraded);
        state.on_commit_merged("leaf-a");
        assert!(state.degraded);
        assert_eq!(state.epoch_app_count, GROUP_PCS_DEBT_HARD);
        state.on_commit_merged("leaf-b");
        assert!(!state.degraded);
        assert_eq!(state.epoch_app_count, 0);
        assert!(!state.proposal_in_flight);
        assert_eq!(state.own_leaf_key.as_deref(), Some("leaf-b"));
    }

    #[test]
    fn foreign_epoch_keeps_debt_until_own_leaf_rotates() {
        let mut state = GroupPcsState::default();
        state.on_commit_merged("leaf-a");
        state.epoch_app_count = GROUP_PCS_COMMIT_INTERVAL;
        state.mark_proposal_in_flight();
        state.degraded = true;
        state.on_commit_merged("leaf-a");
        assert_eq!(state.epoch_app_count, GROUP_PCS_COMMIT_INTERVAL);
        assert!(!state.proposal_in_flight);
        assert!(state.degraded);
        assert!(state.should_propose());
        state.mark_proposal_in_flight();
        state.on_commit_merged("leaf-b");
        assert_eq!(state.epoch_app_count, 0);
        assert!(!state.proposal_in_flight);
        assert!(!state.degraded);
        assert!(!state.should_propose());
    }
}

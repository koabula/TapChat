use crate::conversation::RecoveryStatus;
use crate::ffi_api::types::RecoveryDiagnostics;
use crate::model::ConversationState;

pub(super) fn recovery_recoverable(
    conversation_state: ConversationState,
    restore_recoverable: Option<bool>,
) -> bool {
    restore_recoverable.unwrap_or(!matches!(
        conversation_state,
        ConversationState::Closed | ConversationState::Archived
    ))
}

pub(super) fn suggested_recovery_action(
    recovery_status: RecoveryStatus,
    conversation_state: ConversationState,
    context_action: Option<String>,
) -> String {
    context_action.unwrap_or_else(|| {
        if recovery_status == RecoveryStatus::NeedsRebuild
            || conversation_state == ConversationState::NeedsRebuild
        {
            "reconcile_conversation_membership".into()
        } else {
            "sync_then_retry".into()
        }
    })
}

pub(super) fn is_degraded_restore_diagnostic(recovery: &RecoveryDiagnostics) -> bool {
    recovery.restore_failure_reason.is_some()
        || recovery.recovery_status == RecoveryStatus::NeedsRebuild
}

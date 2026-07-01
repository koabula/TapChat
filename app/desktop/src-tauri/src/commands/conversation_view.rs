use tapchat_core::conversation::StoredMessage;
use tapchat_core::model::MessageType;

pub(super) fn summarize_plaintext(plaintext: Option<&str>) -> String {
    match plaintext {
        Some(value) => format!("has_plaintext=true plaintext_len={}", value.len()),
        None => "has_plaintext=false plaintext_len=0".into(),
    }
}

/// Generate a preview string for the last message in a conversation.
/// Returns None if there are no messages or the last message has no plaintext.
pub(super) fn generate_last_message_preview(messages: &[StoredMessage]) -> Option<String> {
    // Find the last application message (not protocol messages like Welcome/Commit)
    let last_app_message = messages
        .iter()
        .rev()
        .find(|msg| matches!(msg.message_type, MessageType::MlsApplication));

    last_app_message.and_then(|msg| {
        msg.plaintext.as_ref().map(|p| {
            // Truncate to 50 characters for preview
            if p.len() > 50 {
                format!("{}...", &p[..50])
            } else {
                p.clone()
            }
        })
    })
}

pub(super) fn application_plaintext_message_count(messages: &[StoredMessage]) -> usize {
    messages
        .iter()
        .filter(|msg| {
            matches!(msg.message_type, MessageType::MlsApplication) && msg.plaintext.is_some()
        })
        .count()
}

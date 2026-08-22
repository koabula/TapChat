use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tauri::State;

use tapchat_core::cli::profile::Profile;
use tapchat_core::local_store::MessageReadCursor;
use tapchat_core::model::ConversationKind;

use crate::errors::DesktopResult;
use crate::state::AppState;

pub(crate) const READ_STATE_KEY: &str = "desktop.conversation_read_state";
const READ_STATE_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConversationReadState {
    #[serde(default = "default_read_state_version")]
    pub version: u32,
    #[serde(default)]
    pub initialized: bool,
    #[serde(default)]
    pub cursors: BTreeMap<String, MessageReadCursor>,
}

fn default_read_state_version() -> u32 {
    READ_STATE_VERSION
}

impl Default for ConversationReadState {
    fn default() -> Self {
        Self {
            version: READ_STATE_VERSION,
            initialized: false,
            cursors: BTreeMap::new(),
        }
    }
}

pub(crate) fn load(profile: &Profile) -> ConversationReadState {
    match profile.load_private_setting::<ConversationReadState>(READ_STATE_KEY) {
        Ok(Some(mut state)) if state.version == READ_STATE_VERSION => {
            state.version = READ_STATE_VERSION;
            state
        }
        Ok(Some(_)) => {
            log::warn!("conversation read state has an unsupported version; resetting it");
            ConversationReadState::default()
        }
        Ok(None) => ConversationReadState::default(),
        Err(error) => {
            log::warn!("conversation read state could not be loaded: {error}");
            ConversationReadState::default()
        }
    }
}

pub(crate) fn save(profile: &Profile, state: &ConversationReadState) -> Result<(), String> {
    profile
        .save_private_setting(READ_STATE_KEY, state)
        .map_err(|error| error.to_string())
}

pub(crate) fn unread_count(
    profile: &Profile,
    conversation_id: &str,
    local_device_id: &str,
    kind: ConversationKind,
    state: &ConversationReadState,
) -> Result<usize, String> {
    profile
        .count_received_visible_messages(
            conversation_id,
            local_device_id,
            kind,
            state.cursors.get(conversation_id),
        )
        .map(|count| count.min(usize::MAX as u64) as usize)
        .map_err(|error| error.to_string())
}

/// Establish the first-run baseline before AppStarted can trigger realtime
/// sync. Existing local history is treated as read; subsequent messages are
/// counted from the resulting cursors.
pub(crate) async fn ensure_baseline(state: &AppState) -> Result<(), String> {
    let inner = state.inner.read().await;
    let pm = inner.profile_manager.inner.read().await;
    let Some(profile) = pm.active_profile.as_ref() else {
        return Ok(());
    };

    let mut read_state = load(profile);
    if read_state.initialized {
        return Ok(());
    }

    let snapshot = inner.engine.refresh_snapshot();
    for conversation in &snapshot.conversations {
        let kind = conversation.state.conversation.kind;
        if let Some(cursor) = profile
            .latest_visible_message_cursor(&conversation.conversation_id, kind)
            .map_err(|error| error.to_string())?
        {
            read_state
                .cursors
                .insert(conversation.conversation_id.clone(), cursor);
        }
    }
    read_state.initialized = true;
    save(profile, &read_state)
}

#[tauri::command]
pub async fn mark_conversation_read(
    state: State<'_, AppState>,
    conversation_id: String,
    last_message_id: String,
) -> DesktopResult<()> {
    if conversation_id.trim().is_empty() || last_message_id.trim().is_empty() {
        return Err("conversation_id and last_message_id are required".into());
    }

    let inner = state.inner.read().await;
    let pm = inner.profile_manager.inner.read().await;
    let profile = pm
        .active_profile
        .as_ref()
        .ok_or_else(|| "No active profile".to_string())?;
    let kind = inner
        .engine
        .refresh_snapshot()
        .conversations
        .into_iter()
        .find(|conversation| conversation.conversation_id == conversation_id)
        .map(|conversation| conversation.state.conversation.kind)
        .ok_or_else(|| "conversation not found".to_string())?;
    let cursor = profile
        .visible_message_cursor(&conversation_id, &last_message_id, kind)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "message is not a visible message in this conversation".to_string())?;

    let mut read_state = load(profile);
    read_state.initialized = true;
    read_state.cursors.insert(conversation_id, cursor);
    save(profile, &read_state).map_err(Into::into)
}

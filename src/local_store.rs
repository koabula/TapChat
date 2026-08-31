use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::conversation::StoredMessage;
use crate::ffi_api::{
    PersistStateEffect, PersistedMessageAttachmentState, PersistenceMutation, PersistenceTable,
    PersistenceValue,
};
use crate::fs_util::write_atomic_unique;
use crate::model::ConversationKind;
use crate::persistence::{
    decode_snapshot, encode_snapshot, CorePersistenceSnapshot, PersistOp, PersistedContact,
    PersistedConversation, PersistedGroupCursor, PersistedGroupInvite, PersistedGroupJoinRequest,
    PersistedGroupRealtimeSession, PersistedGroupState, PersistedMlsState,
    PersistedOutgoingEnvelope, PersistedOutgoingGroupEnvelope, PersistedPendingAck,
    PersistedPendingBlobTransfer, PersistedPendingGroupJoinApproval, PersistedPendingWelcomePickup,
    PersistedRealtimeSession, PersistedRecoveryContext, PersistedSyncState,
};
use crate::profile_crypto::{
    decrypt_profile_document, decrypt_snapshot, derive_profile_document_key,
    encrypt_profile_document, encrypt_snapshot, LEGACY_SNAPSHOT_FILE_NAME, PRIVATE_STATE_FILE_NAME,
    SNAPSHOT_FILE_NAME,
};
use crate::transport_contract::SealGroupOutboxRequest;

pub const STATE_DB_FILE_NAME: &str = "state.db";
pub const STATE_DB_TMP_FILE_NAME: &str = "state.db.tmp";
pub const SNAPSHOT_DB_BACKUP_FILE_NAME: &str = "snapshot.enc.pre-state-db";
pub const PRIVATE_STATE_DOCUMENT_KIND: &str = "private-state";

const DB_KEY_DOCUMENT_KIND: &str = "state-db";
const SCHEMA_VERSION: u32 = 2;
const SCHEMA_VERSION_KEY: &str = "schema_version";
const MIGRATION_COMPLETE_KEY: &str = "migration_complete";
const JSON_TABLES: &[&str] = &[
    "identity",
    "deployment",
    "contacts",
    "conversations",
    "sync_checkpoints",
    "mls_states",
    "pending_outbox",
    "group_states",
    "group_cursors",
    "pending_group_outbox",
    "pending_group_seal",
    "group_invites",
    "group_join_requests",
    "pending_group_join_approvals",
    "pending_welcome_pickups",
    "pending_acks",
    "pending_blob_transfers",
    "recovery_contexts",
    "realtime_sessions",
    "group_realtime_sessions",
    "settings",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalStoreDiagnostics {
    pub state_db_exists: bool,
    pub schema_version: Option<u32>,
    pub migration_complete: Option<bool>,
    pub encrypted_snapshot_exists: bool,
    pub encrypted_snapshot_backup_exists: bool,
    pub legacy_plaintext_snapshot_exists: bool,
    pub private_enc_exists: bool,
    pub state_db_size_bytes: Option<u64>,
    pub encrypted_snapshot_size_bytes: Option<u64>,
    pub encrypted_snapshot_backup_size_bytes: Option<u64>,
    pub legacy_files_present: Vec<String>,
}

pub trait LocalStore {
    fn load_snapshot(&self) -> Result<CorePersistenceSnapshot>;
    fn save_snapshot(&self, snapshot: &CorePersistenceSnapshot) -> Result<()>;
    fn persist_state(&self, persist: &PersistStateEffect) -> Result<()>;
    fn load_document(&self, kind: &str) -> Result<Option<Vec<u8>>>;
    fn save_document(&self, kind: &str, plaintext: &[u8]) -> Result<()>;
    fn load_attachment_cache_entries(&self) -> Result<Vec<Vec<u8>>> {
        Ok(Vec::new())
    }
    fn save_attachment_cache_entry(
        &self,
        key: &str,
        value: &[u8],
        mime_type: Option<&str>,
        size_bytes: Option<u64>,
    ) -> Result<()> {
        let _ = key;
        let _ = value;
        let _ = mime_type;
        let _ = size_bytes;
        Ok(())
    }
    fn delete_attachment_cache_entry(&self, key: &str) -> Result<()> {
        let _ = key;
        Ok(())
    }
    fn clear_attachment_cache_entries(&self) -> Result<()> {
        Ok(())
    }
}

pub struct EncryptedSnapshotStore<'a> {
    root: &'a Path,
    profile_id: &'a str,
    pdek: &'a [u8],
}

impl<'a> EncryptedSnapshotStore<'a> {
    pub fn new(root: &'a Path, profile_id: &'a str, pdek: &'a [u8]) -> Self {
        Self {
            root,
            profile_id,
            pdek,
        }
    }

    fn snapshot_path(&self) -> PathBuf {
        self.root.join(SNAPSHOT_FILE_NAME)
    }

    fn document_path(&self, kind: &str) -> Result<PathBuf> {
        match kind {
            PRIVATE_STATE_DOCUMENT_KIND => Ok(self.root.join(PRIVATE_STATE_FILE_NAME)),
            _ => Err(anyhow::anyhow!(
                "unsupported encrypted profile document kind {kind}"
            )),
        }
    }
}

impl LocalStore for EncryptedSnapshotStore<'_> {
    fn load_snapshot(&self) -> Result<CorePersistenceSnapshot> {
        let path = self.snapshot_path();
        let legacy_path = self.root.join(LEGACY_SNAPSHOT_FILE_NAME);
        if legacy_path.exists() && !path.exists() {
            anyhow::bail!(
                "insecure plaintext snapshot.json exists at {}; recreate the profile before using encrypted snapshots",
                legacy_path.display()
            );
        }
        if !path.exists() {
            return Ok(CorePersistenceSnapshot::default());
        }
        let plaintext = decrypt_snapshot(
            self.profile_id,
            self.pdek,
            &fs::read(&path).context("read encrypted snapshot")?,
        )
        .map_err(anyhow::Error::from)?;
        decode_snapshot(&plaintext).map_err(anyhow::Error::from)
    }

    fn save_snapshot(&self, snapshot: &CorePersistenceSnapshot) -> Result<()> {
        let encoded = encode_snapshot(snapshot).map_err(anyhow::Error::from)?;
        let encrypted =
            encrypt_snapshot(self.profile_id, self.pdek, &encoded).map_err(anyhow::Error::from)?;
        write_atomic_unique(&self.snapshot_path(), &encrypted)
    }

    fn persist_state(&self, persist: &PersistStateEffect) -> Result<()> {
        if let Some(snapshot) = persist.snapshot.as_ref() {
            self.save_snapshot(snapshot)?;
        }
        Ok(())
    }

    fn load_document(&self, kind: &str) -> Result<Option<Vec<u8>>> {
        let path = self.document_path(kind)?;
        if !path.exists() {
            return Ok(None);
        }
        let plaintext = decrypt_profile_document(
            self.profile_id,
            self.pdek,
            kind,
            &fs::read(path).context("read encrypted profile document")?,
        )
        .map_err(anyhow::Error::from)?;
        Ok(Some(plaintext))
    }

    fn save_document(&self, kind: &str, plaintext: &[u8]) -> Result<()> {
        let path = self.document_path(kind)?;
        let encrypted = encrypt_profile_document(self.profile_id, self.pdek, kind, plaintext)
            .map_err(anyhow::Error::from)?;
        write_atomic_unique(&path, &encrypted)
    }
}

pub struct SqlCipherLocalStore<'a> {
    path: PathBuf,
    profile_id: &'a str,
    pdek: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageQuery {
    pub conversation_id: String,
    pub before_cursor: Option<String>,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessagePage {
    pub messages: Vec<StoredMessage>,
    pub next_cursor: Option<String>,
}

/// Stable local cursor used by the Desktop-only read state. It is intentionally
/// not part of the transport or Core protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageReadCursor {
    pub created_at: u64,
    pub message_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationMessageSummary {
    pub conversation_id: String,
    pub message_count: u64,
    pub last_visible_message: Option<StoredMessage>,
}

type StorageJob = Box<dyn FnOnce(&mut Connection) + Send + 'static>;

/// A profile-scoped SQLCipher session. The only database connection lives on
/// this blocking thread; callers communicate through a bounded queue so no
/// rusqlite work runs on Tokio workers or while owning the connection mutex.
pub struct ProfileStorageSession {
    sender: mpsc::SyncSender<StorageJob>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl ProfileStorageSession {
    pub fn open(root: &Path, profile_id: &str, pdek: &[u8]) -> Result<Self> {
        let path = root.join(STATE_DB_FILE_NAME);
        let profile_id = profile_id.to_string();
        let pdek = Zeroizing::new(pdek.to_vec());
        let (sender, receiver) = mpsc::sync_channel::<StorageJob>(64);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let handle = thread::Builder::new()
            .name(format!("tapchat-storage-{}", profile_id.replace(':', "-")))
            .spawn(move || {
                let opened =
                    open_sqlcipher_connection(&path, &profile_id, &pdek).and_then(|connection| {
                        ensure_schema(&connection)?;
                        Ok(connection)
                    });
                let mut connection = match opened {
                    Ok(connection) => {
                        let _ = ready_tx.send(Ok(()));
                        connection
                    }
                    Err(error) => {
                        let _ = ready_tx.send(Err(format!("{error:#}")));
                        return;
                    }
                };
                while let Ok(job) = receiver.recv() {
                    job(&mut connection);
                }
                let _ = connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
                drop(connection);
                drop(pdek);
            })
            .context("spawn profile storage thread")?;
        match ready_rx.recv().context("wait for profile storage thread")? {
            Ok(()) => Ok(Self {
                sender,
                thread: Mutex::new(Some(handle)),
            }),
            Err(error) => {
                let _ = handle.join();
                anyhow::bail!(error)
            }
        }
    }

    fn execute<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
    {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.sender
            .send(Box::new(move |connection| {
                let _ = reply_tx.send(operation(connection));
            }))
            .map_err(|_| anyhow::anyhow!("profile storage session is closed"))?;
        reply_rx
            .recv()
            .map_err(|_| anyhow::anyhow!("profile storage session stopped without a response"))?
    }

    pub fn load_snapshot(&self) -> Result<CorePersistenceSnapshot> {
        self.execute(|connection| load_snapshot_from_conn(connection))
    }

    pub fn save_snapshot(&self, snapshot: &CorePersistenceSnapshot) -> Result<()> {
        let snapshot = snapshot.clone();
        self.execute(move |connection| save_snapshot_to_conn(connection, &snapshot))
    }

    pub fn persist_state(&self, persist: &PersistStateEffect) -> Result<()> {
        let persist = persist.clone();
        self.execute(move |connection| persist_state_to_conn(connection, &persist))
    }

    pub fn load_document(&self, kind: &str) -> Result<Option<Vec<u8>>> {
        let kind = kind.to_string();
        self.execute(move |connection| load_document_from_conn(connection, &kind))
    }

    pub fn save_document(&self, kind: &str, plaintext: &[u8]) -> Result<()> {
        let kind = kind.to_string();
        let plaintext = plaintext.to_vec();
        self.execute(move |connection| {
            let tx = connection.transaction()?;
            save_document_in_tx(&tx, &kind, &plaintext)?;
            tx.commit()?;
            Ok(())
        })
    }

    pub fn query_messages(&self, query: &MessageQuery) -> Result<MessagePage> {
        let query = query.clone();
        self.execute(move |connection| query_messages_from_conn(connection, &query))
    }

    pub fn get_message(
        &self,
        conversation_id: &str,
        message_id: &str,
    ) -> Result<Option<StoredMessage>> {
        let conversation_id = conversation_id.to_string();
        let message_id = message_id.to_string();
        self.execute(move |connection| {
            get_message_from_conn(connection, &conversation_id, &message_id)
        })
    }

    pub fn count_received_visible_messages(
        &self,
        conversation_id: &str,
        local_device_id: &str,
        kind: ConversationKind,
        after: Option<&MessageReadCursor>,
    ) -> Result<u64> {
        let conversation_id = conversation_id.to_string();
        let local_device_id = local_device_id.to_string();
        let after = after.cloned();
        self.execute(move |connection| {
            count_received_visible_messages_from_conn(
                connection,
                &conversation_id,
                &local_device_id,
                kind,
                after.as_ref(),
            )
        })
    }

    pub fn latest_visible_message_cursor(
        &self,
        conversation_id: &str,
        kind: ConversationKind,
    ) -> Result<Option<MessageReadCursor>> {
        let conversation_id = conversation_id.to_string();
        self.execute(move |connection| {
            latest_visible_message_cursor_from_conn(connection, &conversation_id, kind)
        })
    }

    pub fn visible_message_cursor(
        &self,
        conversation_id: &str,
        message_id: &str,
        kind: ConversationKind,
    ) -> Result<Option<MessageReadCursor>> {
        let conversation_id = conversation_id.to_string();
        let message_id = message_id.to_string();
        self.execute(move |connection| {
            visible_message_cursor_from_conn(connection, &conversation_id, &message_id, kind)
        })
    }

    pub fn checkpoint(&self) -> Result<()> {
        self.execute(|connection| {
            connection
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .context("checkpoint SQLCipher WAL")
        })
    }

    pub fn load_conversation_message_summaries(&self) -> Result<Vec<ConversationMessageSummary>> {
        self.execute(|connection| load_conversation_message_summaries_from_conn(connection))
    }

    pub fn load_attachment_cache_entries(&self) -> Result<Vec<Vec<u8>>> {
        self.execute(|connection| load_attachment_cache_entries_from_conn(connection))
    }

    pub fn save_attachment_cache_entry(
        &self,
        key: &str,
        value: &[u8],
        mime_type: Option<&str>,
        size_bytes: Option<u64>,
    ) -> Result<()> {
        let key = key.to_string();
        let value = value.to_vec();
        let mime_type = mime_type.map(str::to_string);
        self.execute(move |connection| {
            save_attachment_cache_entry_in_conn(
                connection,
                &key,
                &value,
                mime_type.as_deref(),
                size_bytes,
            )
        })
    }

    pub fn delete_attachment_cache_entry(&self, key: &str) -> Result<()> {
        let key = key.to_string();
        self.execute(move |connection| {
            connection.execute("DELETE FROM attachment_blobs WHERE key = ?1", params![key])?;
            Ok(())
        })
    }

    pub fn clear_attachment_cache_entries(&self) -> Result<()> {
        self.execute(|connection| {
            connection.execute("DELETE FROM attachment_blobs", [])?;
            Ok(())
        })
    }
}

impl Drop for ProfileStorageSession {
    fn drop(&mut self) {
        // Replacing the sender closes the original bounded channel after this
        // method returns; an explicit checkpoint job keeps shutdown durable.
        let _ = self.checkpoint();
        let (replacement, _receiver) = mpsc::sync_channel(1);
        let sender = std::mem::replace(&mut self.sender, replacement);
        drop(sender);
        if let Ok(mut slot) = self.thread.lock() {
            if let Some(handle) = slot.take() {
                let _ = handle.join();
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MessageCursorV1 {
    version: u8,
    created_at: u64,
    message_id: String,
}

impl<'a> SqlCipherLocalStore<'a> {
    pub fn new(root: &Path, profile_id: &'a str, pdek: &'a [u8]) -> Self {
        Self::new_at(root.join(STATE_DB_FILE_NAME), profile_id, pdek)
    }

    fn new_at(path: PathBuf, profile_id: &'a str, pdek: &'a [u8]) -> Self {
        Self {
            path,
            profile_id,
            pdek,
        }
    }

    pub fn exists(root: &Path) -> bool {
        root.join(STATE_DB_FILE_NAME).exists()
    }

    fn connect(&self) -> Result<Connection> {
        open_sqlcipher_connection(&self.path, self.profile_id, self.pdek)
    }

    pub fn query_messages(&self, query: &MessageQuery) -> Result<MessagePage> {
        let conn = self.connect()?;
        ensure_schema(&conn)?;
        query_messages_from_conn(&conn, query)
    }

    pub fn get_message(
        &self,
        conversation_id: &str,
        message_id: &str,
    ) -> Result<Option<StoredMessage>> {
        let conn = self.connect()?;
        ensure_schema(&conn)?;
        get_message_from_conn(&conn, conversation_id, message_id)
    }

    pub fn count_received_visible_messages(
        &self,
        conversation_id: &str,
        local_device_id: &str,
        kind: ConversationKind,
        after: Option<&MessageReadCursor>,
    ) -> Result<u64> {
        let conn = self.connect()?;
        ensure_schema(&conn)?;
        count_received_visible_messages_from_conn(
            &conn,
            conversation_id,
            local_device_id,
            kind,
            after,
        )
    }

    pub fn latest_visible_message_cursor(
        &self,
        conversation_id: &str,
        kind: ConversationKind,
    ) -> Result<Option<MessageReadCursor>> {
        let conn = self.connect()?;
        ensure_schema(&conn)?;
        latest_visible_message_cursor_from_conn(&conn, conversation_id, kind)
    }

    pub fn visible_message_cursor(
        &self,
        conversation_id: &str,
        message_id: &str,
        kind: ConversationKind,
    ) -> Result<Option<MessageReadCursor>> {
        let conn = self.connect()?;
        ensure_schema(&conn)?;
        visible_message_cursor_from_conn(&conn, conversation_id, message_id, kind)
    }

    pub fn checkpoint(&self) -> Result<()> {
        let conn = self.connect()?;
        ensure_schema(&conn)?;
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .context("checkpoint SQLCipher WAL")?;
        Ok(())
    }

    pub fn load_conversation_message_summaries(&self) -> Result<Vec<ConversationMessageSummary>> {
        let conn = self.connect()?;
        ensure_schema(&conn)?;
        let mut stmt = conn.prepare(
            "SELECT key, message_count, last_visible_message
             FROM conversations ORDER BY position, key",
        )?;
        let rows = stmt.query_map([], |row| {
            let last_message: Option<Vec<u8>> = row.get(2)?;
            Ok(ConversationMessageSummary {
                conversation_id: row.get(0)?,
                message_count: row.get::<_, i64>(1)?.max(0) as u64,
                last_visible_message: last_message
                    .map(|bytes| serde_json::from_slice(&bytes))
                    .transpose()
                    .map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            2,
                            rusqlite::types::Type::Blob,
                            Box::new(error),
                        )
                    })?,
            })
        })?;
        let mut summaries = Vec::new();
        for row in rows {
            summaries.push(row?);
        }
        Ok(summaries)
    }
}

impl LocalStore for SqlCipherLocalStore<'_> {
    fn load_snapshot(&self) -> Result<CorePersistenceSnapshot> {
        let conn = self.connect()?;
        ensure_schema(&conn)?;
        load_snapshot_from_conn(&conn)
    }

    fn save_snapshot(&self, snapshot: &CorePersistenceSnapshot) -> Result<()> {
        let mut conn = self.connect()?;
        ensure_schema(&conn)?;
        save_snapshot_to_conn(&mut conn, snapshot)
    }

    fn persist_state(&self, persist: &PersistStateEffect) -> Result<()> {
        let mut conn = self.connect()?;
        ensure_schema(&conn)?;
        persist_state_to_conn(&mut conn, persist)
    }

    fn load_document(&self, kind: &str) -> Result<Option<Vec<u8>>> {
        let conn = self.connect()?;
        ensure_schema(&conn)?;
        load_document_from_conn(&conn, kind)
    }

    fn save_document(&self, kind: &str, plaintext: &[u8]) -> Result<()> {
        let mut conn = self.connect()?;
        ensure_schema(&conn)?;
        let tx = conn.transaction()?;
        save_document_in_tx(&tx, kind, plaintext)?;
        tx.commit()?;
        Ok(())
    }

    fn load_attachment_cache_entries(&self) -> Result<Vec<Vec<u8>>> {
        let conn = self.connect()?;
        ensure_schema(&conn)?;
        load_attachment_cache_entries_from_conn(&conn)
    }

    fn save_attachment_cache_entry(
        &self,
        key: &str,
        value: &[u8],
        mime_type: Option<&str>,
        size_bytes: Option<u64>,
    ) -> Result<()> {
        let conn = self.connect()?;
        ensure_schema(&conn)?;
        save_attachment_cache_entry_in_conn(&conn, key, value, mime_type, size_bytes)
    }

    fn delete_attachment_cache_entry(&self, key: &str) -> Result<()> {
        let conn = self.connect()?;
        ensure_schema(&conn)?;
        conn.execute("DELETE FROM attachment_blobs WHERE key = ?1", params![key])?;
        Ok(())
    }

    fn clear_attachment_cache_entries(&self) -> Result<()> {
        let conn = self.connect()?;
        ensure_schema(&conn)?;
        conn.execute("DELETE FROM attachment_blobs", [])?;
        Ok(())
    }
}

fn load_snapshot_from_conn(conn: &Connection) -> Result<CorePersistenceSnapshot> {
    let has_state = conn
        .query_row(
            "SELECT 1 FROM state_meta WHERE key = 'message_nonce' LIMIT 1",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !has_state {
        return Ok(CorePersistenceSnapshot::default());
    }
    let mut conversations: Vec<PersistedConversation> = load_table(conn, "conversations")?;
    load_message_security_index(conn, &mut conversations)?;
    Ok(CorePersistenceSnapshot {
        message_nonce: load_meta_u64(conn, "message_nonce")?.unwrap_or_default(),
        local_display_name: load_meta_string(conn, "local_display_name")?,
        local_identity: load_singleton(conn, "identity", "local")?,
        deployment: load_singleton(conn, "deployment", "active")?,
        contacts: load_table(conn, "contacts")?,
        conversations,
        sync_states: load_table(conn, "sync_checkpoints")?,
        mls_states: load_table(conn, "mls_states")?,
        pending_outbox: load_table(conn, "pending_outbox")?,
        group_states: load_table(conn, "group_states")?,
        group_cursors: load_table(conn, "group_cursors")?,
        pending_group_outbox: load_table(conn, "pending_group_outbox")?,
        pending_group_seal: load_table(conn, "pending_group_seal")?,
        group_invites: load_table(conn, "group_invites")?,
        group_join_requests: load_table(conn, "group_join_requests")?,
        pending_group_join_approvals: load_table(conn, "pending_group_join_approvals")?,
        pending_welcome_pickups: load_table(conn, "pending_welcome_pickups")?,
        pending_acks: load_table(conn, "pending_acks")?,
        pending_blob_transfers: load_table(conn, "pending_blob_transfers")?,
        recovery_contexts: load_table(conn, "recovery_contexts")?,
        realtime_sessions: load_table(conn, "realtime_sessions")?,
        group_realtime_sessions: load_table(conn, "group_realtime_sessions")?,
        mls_state_persistence_blocked: load_meta_bool(conn, "mls_state_persistence_blocked")?
            .unwrap_or_default(),
    })
}

fn save_snapshot_to_conn(conn: &mut Connection, snapshot: &CorePersistenceSnapshot) -> Result<()> {
    let tx = conn.transaction()?;
    save_snapshot_tables(&tx, snapshot)?;
    tx.commit()?;
    Ok(())
}

fn persist_state_to_conn(conn: &mut Connection, persist: &PersistStateEffect) -> Result<()> {
    if !persist.mutations.is_empty() {
        let tx = conn.transaction()?;
        apply_persistence_mutations(&tx, &persist.mutations)?;
        tx.commit()?;
        return Ok(());
    }
    let Some(snapshot) = persist.snapshot.as_ref() else {
        return Ok(());
    };
    if persist.ops.is_empty() {
        return save_snapshot_to_conn(conn, snapshot);
    }
    let tx = conn.transaction()?;
    save_snapshot_meta(&tx, snapshot)?;
    apply_persist_ops(&tx, snapshot, &persist.ops)?;
    tx.commit()?;
    Ok(())
}

fn persistence_table_name(table: PersistenceTable) -> &'static str {
    match table {
        PersistenceTable::Identity => "identity",
        PersistenceTable::Deployment => "deployment",
        PersistenceTable::Contacts => "contacts",
        PersistenceTable::Conversations => "conversations",
        PersistenceTable::SyncCheckpoints => "sync_checkpoints",
        PersistenceTable::MlsStates => "mls_states",
        PersistenceTable::PendingOutbox => "pending_outbox",
        PersistenceTable::GroupStates => "group_states",
        PersistenceTable::GroupCursors => "group_cursors",
        PersistenceTable::PendingGroupOutbox => "pending_group_outbox",
        PersistenceTable::PendingGroupSeal => "pending_group_seal",
        PersistenceTable::GroupInvites => "group_invites",
        PersistenceTable::GroupJoinRequests => "group_join_requests",
        PersistenceTable::PendingGroupJoinApprovals => "pending_group_join_approvals",
        PersistenceTable::PendingWelcomePickups => "pending_welcome_pickups",
        PersistenceTable::PendingAcks => "pending_acks",
        PersistenceTable::PendingBlobTransfers => "pending_blob_transfers",
        PersistenceTable::RecoveryContexts => "recovery_contexts",
        PersistenceTable::RealtimeSessions => "realtime_sessions",
        PersistenceTable::GroupRealtimeSessions => "group_realtime_sessions",
    }
}

fn apply_persistence_mutations(
    tx: &Transaction<'_>,
    mutations: &[PersistenceMutation],
) -> Result<()> {
    for mutation in mutations {
        match mutation {
            PersistenceMutation::SaveMetadata {
                message_nonce,
                local_display_name,
                mls_state_persistence_blocked,
            } => {
                save_meta(tx, "message_nonce", message_nonce.to_string())?;
                match local_display_name {
                    Some(display_name) => save_meta(tx, "local_display_name", display_name)?,
                    None => {
                        tx.execute(
                            "DELETE FROM state_meta WHERE key = ?1",
                            params!["local_display_name"],
                        )?;
                    }
                }
                save_meta(
                    tx,
                    "mls_state_persistence_blocked",
                    if *mls_state_persistence_blocked {
                        "true"
                    } else {
                        "false"
                    },
                )?;
            }
            PersistenceMutation::Delete { table, key } => {
                delete_key(tx, persistence_table_name(*table), key)?;
            }
            PersistenceMutation::InsertMessage {
                conversation_id,
                message,
            } => insert_message_if_missing(tx, conversation_id, message)?,
            PersistenceMutation::UpdateMessageDelivery {
                conversation_id,
                message_id,
                delivery_state,
                message_request_id,
            } => update_message_delivery(
                tx,
                conversation_id,
                message_id,
                *delivery_state,
                message_request_id.as_deref(),
            )?,
            PersistenceMutation::UpdateAttachmentState {
                conversation_id,
                message_id,
                attachment_state,
                plaintext,
                storage_refs,
            } => update_attachment_state(
                tx,
                conversation_id,
                message_id,
                *attachment_state,
                plaintext.as_deref(),
                storage_refs,
            )?,
            PersistenceMutation::DeleteMessage {
                conversation_id,
                message_id,
            } => delete_message(tx, conversation_id, message_id)?,
            PersistenceMutation::Save {
                table,
                key,
                position,
                value,
            } => match value {
                PersistenceValue::Conversation(conversation) => {
                    if *table != PersistenceTable::Conversations
                        || key != &conversation.conversation_id
                    {
                        anyhow::bail!("conversation persistence mutation key mismatch");
                    }
                    insert_conversation(tx, conversation, *position, false)?;
                }
                PersistenceValue::ConversationSummary(summary) => {
                    if *table != PersistenceTable::Conversations
                        || key != &summary.conversation.conversation_id
                        || !summary.conversation.state.messages.is_empty()
                    {
                        anyhow::bail!("conversation summary persistence mutation mismatch");
                    }
                    insert_conversation_summary(tx, summary, *position)?;
                }
                PersistenceValue::LocalIdentity(value) => insert_typed_mutation(
                    tx,
                    *table,
                    PersistenceTable::Identity,
                    key,
                    *position,
                    value,
                )?,
                PersistenceValue::Deployment(value) => insert_typed_mutation(
                    tx,
                    *table,
                    PersistenceTable::Deployment,
                    key,
                    *position,
                    value,
                )?,
                PersistenceValue::Contact(value) => insert_typed_mutation(
                    tx,
                    *table,
                    PersistenceTable::Contacts,
                    key,
                    *position,
                    value,
                )?,
                PersistenceValue::SyncState(value) => insert_typed_mutation(
                    tx,
                    *table,
                    PersistenceTable::SyncCheckpoints,
                    key,
                    *position,
                    value,
                )?,
                PersistenceValue::MlsState(value) => insert_typed_mutation(
                    tx,
                    *table,
                    PersistenceTable::MlsStates,
                    key,
                    *position,
                    value,
                )?,
                PersistenceValue::OutgoingEnvelope(value) => insert_typed_mutation(
                    tx,
                    *table,
                    PersistenceTable::PendingOutbox,
                    key,
                    *position,
                    value,
                )?,
                PersistenceValue::GroupState(value) => insert_typed_mutation(
                    tx,
                    *table,
                    PersistenceTable::GroupStates,
                    key,
                    *position,
                    value,
                )?,
                PersistenceValue::GroupCursor(value) => insert_typed_mutation(
                    tx,
                    *table,
                    PersistenceTable::GroupCursors,
                    key,
                    *position,
                    value,
                )?,
                PersistenceValue::OutgoingGroupEnvelope(value) => insert_typed_mutation(
                    tx,
                    *table,
                    PersistenceTable::PendingGroupOutbox,
                    key,
                    *position,
                    value,
                )?,
                PersistenceValue::PendingGroupSeal(value) => insert_typed_mutation(
                    tx,
                    *table,
                    PersistenceTable::PendingGroupSeal,
                    key,
                    *position,
                    value,
                )?,
                PersistenceValue::GroupInvite(value) => insert_typed_mutation(
                    tx,
                    *table,
                    PersistenceTable::GroupInvites,
                    key,
                    *position,
                    value,
                )?,
                PersistenceValue::GroupJoinRequest(value) => insert_typed_mutation(
                    tx,
                    *table,
                    PersistenceTable::GroupJoinRequests,
                    key,
                    *position,
                    value,
                )?,
                PersistenceValue::PendingGroupJoinApproval(value) => insert_typed_mutation(
                    tx,
                    *table,
                    PersistenceTable::PendingGroupJoinApprovals,
                    key,
                    *position,
                    value,
                )?,
                PersistenceValue::PendingWelcomePickup(value) => insert_typed_mutation(
                    tx,
                    *table,
                    PersistenceTable::PendingWelcomePickups,
                    key,
                    *position,
                    value,
                )?,
                PersistenceValue::PendingAck(value) => insert_typed_mutation(
                    tx,
                    *table,
                    PersistenceTable::PendingAcks,
                    key,
                    *position,
                    value,
                )?,
                PersistenceValue::PendingBlobTransfer(value) => insert_typed_mutation(
                    tx,
                    *table,
                    PersistenceTable::PendingBlobTransfers,
                    key,
                    *position,
                    value,
                )?,
                PersistenceValue::RecoveryContext(value) => insert_typed_mutation(
                    tx,
                    *table,
                    PersistenceTable::RecoveryContexts,
                    key,
                    *position,
                    value,
                )?,
                PersistenceValue::RealtimeSession(value) => insert_typed_mutation(
                    tx,
                    *table,
                    PersistenceTable::RealtimeSessions,
                    key,
                    *position,
                    value,
                )?,
                PersistenceValue::GroupRealtimeSession(value) => insert_typed_mutation(
                    tx,
                    *table,
                    PersistenceTable::GroupRealtimeSessions,
                    key,
                    *position,
                    value,
                )?,
            },
        }
    }
    Ok(())
}

fn insert_typed_mutation<T: Serialize>(
    tx: &Transaction<'_>,
    actual: PersistenceTable,
    expected: PersistenceTable,
    key: &str,
    position: usize,
    value: &T,
) -> Result<()> {
    if actual != expected {
        anyhow::bail!("persistence mutation table/type mismatch");
    }
    insert_json(tx, persistence_table_name(actual), key, position, value)
}

fn load_attachment_cache_entries_from_conn(conn: &Connection) -> Result<Vec<Vec<u8>>> {
    let mut stmt =
        conn.prepare("SELECT value FROM attachment_blobs ORDER BY updated_at_ms DESC, key")?;
    let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
    let mut values = Vec::new();
    for row in rows {
        values.push(row?);
    }
    Ok(values)
}

fn save_attachment_cache_entry_in_conn(
    conn: &Connection,
    key: &str,
    value: &[u8],
    mime_type: Option<&str>,
    size_bytes: Option<u64>,
) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO attachment_blobs(key, value, mime_type, size_bytes, updated_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            key,
            value,
            mime_type,
            size_bytes.map(|value| value as i64),
            now_ms() as i64
        ],
    )?;
    Ok(())
}

fn load_conversation_message_summaries_from_conn(
    conn: &Connection,
) -> Result<Vec<ConversationMessageSummary>> {
    let mut stmt = conn.prepare(
        "SELECT key, message_count, last_visible_message
         FROM conversations ORDER BY position, key",
    )?;
    let rows = stmt.query_map([], |row| {
        let last_message: Option<Vec<u8>> = row.get(2)?;
        Ok(ConversationMessageSummary {
            conversation_id: row.get(0)?,
            message_count: row.get::<_, i64>(1)?.max(0) as u64,
            last_visible_message: last_message
                .map(|bytes| serde_json::from_slice(&bytes))
                .transpose()
                .map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        2,
                        rusqlite::types::Type::Blob,
                        Box::new(error),
                    )
                })?,
        })
    })?;
    let mut summaries = Vec::new();
    for row in rows {
        summaries.push(row?);
    }
    Ok(summaries)
}

pub fn active_store<'a>(
    root: &'a Path,
    profile_id: &'a str,
    pdek: &'a [u8],
) -> Box<dyn LocalStore + 'a> {
    if SqlCipherLocalStore::exists(root) {
        Box::new(SqlCipherLocalStore::new(root, profile_id, pdek))
    } else {
        Box::new(EncryptedSnapshotStore::new(root, profile_id, pdek))
    }
}

pub fn migrate_snapshot_to_state_db(root: &Path, profile_id: &str, pdek: &[u8]) -> Result<()> {
    let db_path = root.join(STATE_DB_FILE_NAME);
    let tmp_path = root.join(STATE_DB_TMP_FILE_NAME);
    if tmp_path.exists() {
        fs::remove_file(&tmp_path)
            .with_context(|| format!("remove incomplete state DB {}", tmp_path.display()))?;
    }

    if db_path.exists() {
        let store = SqlCipherLocalStore::new(root, profile_id, pdek);
        let conn = store.connect().with_context(|| {
            format!(
                "open existing state DB {}; refusing snapshot fallback",
                db_path.display()
            )
        })?;
        ensure_schema(&conn)?;
        if !schema_migration_complete(&conn)? {
            if !root.join(SNAPSHOT_FILE_NAME).exists() {
                anyhow::bail!(
                    "state DB migration is incomplete and encrypted snapshot backup is missing"
                );
            }
            drop(conn);
            fs::remove_file(&db_path)
                .with_context(|| format!("remove incomplete state DB {}", db_path.display()))?;
        } else {
            let version = load_schema_version(&conn)?;
            if version != SCHEMA_VERSION {
                anyhow::bail!(
                    "unsupported local store schema version {version}; expected {SCHEMA_VERSION}"
                );
            }
            let _ = store.load_snapshot()?;
            return Ok(());
        }
    }

    let snapshot_store = EncryptedSnapshotStore::new(root, profile_id, pdek);
    let snapshot = snapshot_store.load_snapshot()?;
    let private_state = snapshot_store.load_document(PRIVATE_STATE_DOCUMENT_KIND)?;

    let tmp_store = SqlCipherLocalStore::new_at(tmp_path.clone(), profile_id, pdek);
    tmp_store.save_snapshot(&snapshot)?;
    if let Some(private_state) = private_state {
        tmp_store.save_document(PRIVATE_STATE_DOCUMENT_KIND, &private_state)?;
    }
    mark_schema_migration_complete(&tmp_store)?;
    let round_trip = tmp_store.load_snapshot()?;
    if round_trip != snapshot {
        anyhow::bail!("state DB migration verification failed");
    }
    fs::rename(&tmp_path, &db_path)
        .with_context(|| format!("promote {} to {}", tmp_path.display(), db_path.display()))?;

    let snapshot_path = root.join(SNAPSHOT_FILE_NAME);
    if snapshot_path.exists() {
        let backup_path = root.join(SNAPSHOT_DB_BACKUP_FILE_NAME);
        if !backup_path.exists() {
            fs::copy(&snapshot_path, &backup_path).with_context(|| {
                format!(
                    "backup encrypted snapshot from {} to {}",
                    snapshot_path.display(),
                    backup_path.display()
                )
            })?;
        }
    }
    Ok(())
}

pub fn inspect_storage(
    root: &Path,
    profile_id: &str,
    pdek: &[u8],
) -> Result<LocalStoreDiagnostics> {
    let db_path = root.join(STATE_DB_FILE_NAME);
    let encrypted_snapshot_path = root.join(SNAPSHOT_FILE_NAME);
    let encrypted_snapshot_backup_path = root.join(SNAPSHOT_DB_BACKUP_FILE_NAME);
    let legacy_plaintext_snapshot_path = root.join(LEGACY_SNAPSHOT_FILE_NAME);
    let private_enc_path = root.join(PRIVATE_STATE_FILE_NAME);
    let legacy_plaintext_snapshot_exists = legacy_plaintext_snapshot_path.exists();
    let private_enc_exists = private_enc_path.exists();
    let mut legacy_files_present = Vec::new();
    if legacy_plaintext_snapshot_exists {
        legacy_files_present.push(LEGACY_SNAPSHOT_FILE_NAME.to_string());
    }
    if private_enc_exists {
        legacy_files_present.push(PRIVATE_STATE_FILE_NAME.to_string());
    }
    let mut diagnostics = LocalStoreDiagnostics {
        state_db_exists: db_path.exists(),
        schema_version: None,
        migration_complete: None,
        encrypted_snapshot_exists: encrypted_snapshot_path.exists(),
        encrypted_snapshot_backup_exists: encrypted_snapshot_backup_path.exists(),
        legacy_plaintext_snapshot_exists,
        private_enc_exists,
        state_db_size_bytes: file_size_if_exists(&db_path)?,
        encrypted_snapshot_size_bytes: file_size_if_exists(&encrypted_snapshot_path)?,
        encrypted_snapshot_backup_size_bytes: file_size_if_exists(&encrypted_snapshot_backup_path)?,
        legacy_files_present,
    };

    if diagnostics.state_db_exists {
        let conn = open_sqlcipher_connection(&db_path, profile_id, pdek).with_context(|| {
            format!(
                "inspect encrypted state DB diagnostics for {}",
                db_path.display()
            )
        })?;
        let has_schema_meta = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_meta' LIMIT 1",
                [],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if has_schema_meta {
            diagnostics.schema_version = load_optional_schema_meta(&conn, SCHEMA_VERSION_KEY)?
                .map(|value| {
                    value
                        .parse::<u32>()
                        .context("parse local store schema version")
                })
                .transpose()?;
            diagnostics.migration_complete =
                load_optional_schema_meta(&conn, MIGRATION_COMPLETE_KEY)?
                    .map(|value| value == "true");
        }
    }

    Ok(diagnostics)
}

fn file_size_if_exists(path: &Path) -> Result<Option<u64>> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(Some(metadata.len())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read metadata for {}", path.display())),
    }
}

fn open_sqlcipher_connection(path: &Path, profile_id: &str, pdek: &[u8]) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let conn = Connection::open(path).with_context(|| format!("open {}", path.display()))?;
    let key = derive_profile_document_key(profile_id, pdek, DB_KEY_DOCUMENT_KIND)
        .map_err(anyhow::Error::from)?;
    conn.execute_batch(&format!(
        "PRAGMA key = \"x'{}'\";
         PRAGMA cipher_memory_security = ON;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;
         PRAGMA secure_delete = ON;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;
         PRAGMA wal_autocheckpoint = 1000;",
        hex_encode(&*key)
    ))
    .context("configure SQLCipher key")?;
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .context("verify SQLCipher database key")?;
    Ok(conn)
}

fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );",
    )
    .context("create local store schema metadata")?;
    let existing_version: Option<u32> = conn
        .query_row(
            "SELECT value FROM schema_meta WHERE key = ?1",
            params![SCHEMA_VERSION_KEY],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(|value| value.parse())
        .transpose()
        .context("parse local store schema version")?;
    match existing_version {
        Some(version) if version != SCHEMA_VERSION => anyhow::bail!(
            "unsupported local store schema version {version}; expected {SCHEMA_VERSION}"
        ),
        None => {
            conn.execute(
                "INSERT INTO schema_meta(key, value) VALUES (?1, ?2)",
                params![SCHEMA_VERSION_KEY, SCHEMA_VERSION.to_string()],
            )?;
        }
        _ => {}
    }
    conn.execute_batch(
        "
        INSERT OR IGNORE INTO schema_meta(key, value)
        VALUES ('migration_complete', 'false');

        CREATE TABLE IF NOT EXISTS documents (
            kind TEXT PRIMARY KEY,
            format_version INTEGER NOT NULL,
            payload BLOB NOT NULL,
            updated_at_ms INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS state_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS identity (key TEXT PRIMARY KEY, value BLOB NOT NULL, position INTEGER NOT NULL DEFAULT 0, updated_at_ms INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS deployment (key TEXT PRIMARY KEY, value BLOB NOT NULL, position INTEGER NOT NULL DEFAULT 0, updated_at_ms INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS contacts (key TEXT PRIMARY KEY, value BLOB NOT NULL, position INTEGER NOT NULL DEFAULT 0, updated_at_ms INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS conversations (
            key TEXT PRIMARY KEY,
            value BLOB NOT NULL,
            position INTEGER NOT NULL DEFAULT 0,
            message_count INTEGER NOT NULL DEFAULT 0,
            last_visible_message BLOB,
            updated_at_ms INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS messages (
            conversation_id TEXT NOT NULL,
            message_id TEXT NOT NULL,
            app_message_id TEXT,
            mls_ciphertext_sha256 TEXT,
            sender_user_id TEXT,
            sender_device_id TEXT NOT NULL,
            recipient_device_id TEXT NOT NULL,
            message_type TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            plaintext TEXT,
            storage_refs BLOB NOT NULL,
            delivery_state TEXT,
            attachment_state TEXT,
            message_request_id TEXT,
            payload_version INTEGER NOT NULL DEFAULT 1,
            updated_at_ms INTEGER NOT NULL,
            PRIMARY KEY (conversation_id, message_id),
            FOREIGN KEY (conversation_id) REFERENCES conversations(key) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS messages_page_idx
            ON messages(conversation_id, created_at DESC, message_id DESC);
        CREATE UNIQUE INDEX IF NOT EXISTS messages_app_id_unique
            ON messages(conversation_id, app_message_id) WHERE app_message_id IS NOT NULL;
        CREATE UNIQUE INDEX IF NOT EXISTS messages_mls_hash_unique
            ON messages(conversation_id, mls_ciphertext_sha256)
            WHERE mls_ciphertext_sha256 IS NOT NULL;
        CREATE INDEX IF NOT EXISTS messages_delivery_idx ON messages(delivery_state);
        CREATE INDEX IF NOT EXISTS messages_request_idx ON messages(message_request_id);
        CREATE TABLE IF NOT EXISTS sync_checkpoints (key TEXT PRIMARY KEY, value BLOB NOT NULL, position INTEGER NOT NULL DEFAULT 0, updated_at_ms INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS mls_states (key TEXT PRIMARY KEY, value BLOB NOT NULL, position INTEGER NOT NULL DEFAULT 0, updated_at_ms INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS pending_outbox (key TEXT PRIMARY KEY, value BLOB NOT NULL, position INTEGER NOT NULL DEFAULT 0, updated_at_ms INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS group_states (key TEXT PRIMARY KEY, value BLOB NOT NULL, position INTEGER NOT NULL DEFAULT 0, updated_at_ms INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS group_cursors (key TEXT PRIMARY KEY, value BLOB NOT NULL, position INTEGER NOT NULL DEFAULT 0, updated_at_ms INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS pending_group_outbox (key TEXT PRIMARY KEY, value BLOB NOT NULL, position INTEGER NOT NULL DEFAULT 0, updated_at_ms INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS pending_group_seal (key TEXT PRIMARY KEY, value BLOB NOT NULL, position INTEGER NOT NULL DEFAULT 0, updated_at_ms INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS group_invites (key TEXT PRIMARY KEY, value BLOB NOT NULL, position INTEGER NOT NULL DEFAULT 0, updated_at_ms INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS group_join_requests (key TEXT PRIMARY KEY, value BLOB NOT NULL, position INTEGER NOT NULL DEFAULT 0, updated_at_ms INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS pending_group_join_approvals (key TEXT PRIMARY KEY, value BLOB NOT NULL, position INTEGER NOT NULL DEFAULT 0, updated_at_ms INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS pending_welcome_pickups (key TEXT PRIMARY KEY, value BLOB NOT NULL, position INTEGER NOT NULL DEFAULT 0, updated_at_ms INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS pending_acks (key TEXT PRIMARY KEY, value BLOB NOT NULL, position INTEGER NOT NULL DEFAULT 0, updated_at_ms INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS pending_blob_transfers (key TEXT PRIMARY KEY, value BLOB NOT NULL, position INTEGER NOT NULL DEFAULT 0, updated_at_ms INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS recovery_contexts (key TEXT PRIMARY KEY, value BLOB NOT NULL, position INTEGER NOT NULL DEFAULT 0, updated_at_ms INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS realtime_sessions (key TEXT PRIMARY KEY, value BLOB NOT NULL, position INTEGER NOT NULL DEFAULT 0, updated_at_ms INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS group_realtime_sessions (key TEXT PRIMARY KEY, value BLOB NOT NULL, position INTEGER NOT NULL DEFAULT 0, updated_at_ms INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value BLOB NOT NULL, position INTEGER NOT NULL DEFAULT 0, updated_at_ms INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS attachment_blobs (
            key TEXT PRIMARY KEY,
            value BLOB NOT NULL,
            mime_type TEXT,
            size_bytes INTEGER,
            updated_at_ms INTEGER NOT NULL
        );
        ",
    )
    .context("create local store schema")?;
    for table in JSON_TABLES {
        ensure_column(conn, table, "updated_at_ms", "INTEGER NOT NULL DEFAULT 0")?;
    }
    Ok(())
}

fn ensure_column(conn: &Connection, table: &str, column: &str, definition: &str) -> Result<()> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for existing in columns {
        if existing? == column {
            return Ok(());
        }
    }
    conn.execute(
        &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
        [],
    )?;
    Ok(())
}

fn save_snapshot_tables(tx: &Transaction<'_>, snapshot: &CorePersistenceSnapshot) -> Result<()> {
    save_snapshot_meta(tx, snapshot)?;
    replace_singleton(tx, "identity", "local", snapshot.local_identity.as_ref())?;
    replace_singleton(tx, "deployment", "active", snapshot.deployment.as_ref())?;
    replace_table(
        tx,
        "contacts",
        &snapshot.contacts,
        |item: &PersistedContact| item.user_id.clone(),
    )?;
    replace_conversations(tx, &snapshot.conversations)?;
    replace_table(
        tx,
        "sync_checkpoints",
        &snapshot.sync_states,
        |item: &PersistedSyncState| item.device_id.clone(),
    )?;
    replace_table(
        tx,
        "mls_states",
        &snapshot.mls_states,
        |item: &PersistedMlsState| item.conversation_id.clone(),
    )?;
    replace_table(
        tx,
        "pending_outbox",
        &snapshot.pending_outbox,
        |item: &PersistedOutgoingEnvelope| item.message_id.clone(),
    )?;
    replace_table(
        tx,
        "group_states",
        &snapshot.group_states,
        |item: &PersistedGroupState| item.group_id.clone(),
    )?;
    replace_table(
        tx,
        "group_cursors",
        &snapshot.group_cursors,
        |item: &PersistedGroupCursor| item.group_id.clone(),
    )?;
    replace_table(
        tx,
        "pending_group_outbox",
        &snapshot.pending_group_outbox,
        |item: &PersistedOutgoingGroupEnvelope| item.message_id.clone(),
    )?;
    replace_table(
        tx,
        "pending_group_seal",
        &snapshot.pending_group_seal,
        |item: &SealGroupOutboxRequest| item.group_id.clone(),
    )?;
    replace_table(
        tx,
        "group_invites",
        &snapshot.group_invites,
        |item: &PersistedGroupInvite| item.invite_id.clone(),
    )?;
    replace_table(
        tx,
        "group_join_requests",
        &snapshot.group_join_requests,
        |item: &PersistedGroupJoinRequest| item.request_id.clone(),
    )?;
    replace_table(
        tx,
        "pending_group_join_approvals",
        &snapshot.pending_group_join_approvals,
        |item: &PersistedPendingGroupJoinApproval| item.request_id.clone(),
    )?;
    replace_table(
        tx,
        "pending_welcome_pickups",
        &snapshot.pending_welcome_pickups,
        |item: &PersistedPendingWelcomePickup| format!("{}::{}", item.group_id, item.device_id),
    )?;
    replace_table(
        tx,
        "pending_acks",
        &snapshot.pending_acks,
        |item: &PersistedPendingAck| item.device_id.clone(),
    )?;
    replace_table(
        tx,
        "pending_blob_transfers",
        &snapshot.pending_blob_transfers,
        |item: &PersistedPendingBlobTransfer| match item {
            PersistedPendingBlobTransfer::Upload { task_id, .. }
            | PersistedPendingBlobTransfer::Download { task_id, .. }
            | PersistedPendingBlobTransfer::Delete { task_id, .. } => task_id.clone(),
        },
    )?;
    replace_table(
        tx,
        "recovery_contexts",
        &snapshot.recovery_contexts,
        |item: &PersistedRecoveryContext| item.conversation_id.clone(),
    )?;
    replace_table(
        tx,
        "realtime_sessions",
        &snapshot.realtime_sessions,
        |item: &PersistedRealtimeSession| item.device_id.clone(),
    )?;
    replace_table(
        tx,
        "group_realtime_sessions",
        &snapshot.group_realtime_sessions,
        |item: &PersistedGroupRealtimeSession| item.group_id.clone(),
    )?;
    Ok(())
}

fn save_snapshot_meta(tx: &Transaction<'_>, snapshot: &CorePersistenceSnapshot) -> Result<()> {
    save_meta(tx, "message_nonce", snapshot.message_nonce.to_string())?;
    match snapshot.local_display_name.as_ref() {
        Some(display_name) => save_meta(tx, "local_display_name", display_name)?,
        None => {
            tx.execute(
                "DELETE FROM state_meta WHERE key = ?1",
                params!["local_display_name"],
            )?;
        }
    }
    save_meta(
        tx,
        "mls_state_persistence_blocked",
        if snapshot.mls_state_persistence_blocked {
            "true"
        } else {
            "false"
        },
    )?;
    Ok(())
}

fn apply_persist_ops(
    tx: &Transaction<'_>,
    snapshot: &CorePersistenceSnapshot,
    ops: &[PersistOp],
) -> Result<()> {
    for op in ops {
        match op {
            PersistOp::SaveLocalIdentity => {
                replace_singleton(tx, "identity", "local", snapshot.local_identity.as_ref())?;
            }
            PersistOp::SaveDeployment => {
                replace_singleton(tx, "deployment", "active", snapshot.deployment.as_ref())?;
            }
            PersistOp::SaveContact { user_id } => upsert_from_snapshot(
                tx,
                "contacts",
                &snapshot.contacts,
                |item: &PersistedContact| item.user_id.clone(),
                user_id,
            )?,
            PersistOp::DeleteContact { user_id } => delete_key(tx, "contacts", user_id)?,
            PersistOp::SaveConversation { conversation_id } => {
                match snapshot
                    .conversations
                    .iter()
                    .enumerate()
                    .find(|(_, item)| item.conversation_id == *conversation_id)
                {
                    Some((position, conversation)) => {
                        insert_conversation(tx, conversation, position, false)?;
                    }
                    None => delete_conversation(tx, conversation_id)?,
                }
            }
            PersistOp::DeleteConversation { conversation_id } => {
                delete_conversation(tx, conversation_id)?;
            }
            PersistOp::SaveSyncState { device_id } => upsert_from_snapshot(
                tx,
                "sync_checkpoints",
                &snapshot.sync_states,
                |item: &PersistedSyncState| item.device_id.clone(),
                device_id,
            )?,
            PersistOp::DeleteSyncState { device_id } => {
                delete_key(tx, "sync_checkpoints", device_id)?;
            }
            PersistOp::SaveMlsState { conversation_id } => upsert_from_snapshot(
                tx,
                "mls_states",
                &snapshot.mls_states,
                |item: &PersistedMlsState| item.conversation_id.clone(),
                conversation_id,
            )?,
            PersistOp::DeleteMlsState { conversation_id } => {
                delete_key(tx, "mls_states", conversation_id)?;
            }
            PersistOp::SaveOutgoingEnvelope { message_id } => upsert_from_snapshot(
                tx,
                "pending_outbox",
                &snapshot.pending_outbox,
                |item: &PersistedOutgoingEnvelope| item.message_id.clone(),
                message_id,
            )?,
            PersistOp::DeleteOutgoingEnvelope { message_id } => {
                delete_key(tx, "pending_outbox", message_id)?;
            }
            PersistOp::SaveGroupState { group_id } => upsert_from_snapshot(
                tx,
                "group_states",
                &snapshot.group_states,
                |item: &PersistedGroupState| item.group_id.clone(),
                group_id,
            )?,
            PersistOp::DeleteGroupState { group_id } => {
                delete_key(tx, "group_states", group_id)?;
            }
            PersistOp::SaveGroupCursor { group_id } => upsert_from_snapshot(
                tx,
                "group_cursors",
                &snapshot.group_cursors,
                |item: &PersistedGroupCursor| item.group_id.clone(),
                group_id,
            )?,
            PersistOp::DeleteGroupCursor { group_id } => {
                delete_key(tx, "group_cursors", group_id)?;
            }
            PersistOp::SaveOutgoingGroupEnvelope { message_id } => upsert_from_snapshot(
                tx,
                "pending_group_outbox",
                &snapshot.pending_group_outbox,
                |item: &PersistedOutgoingGroupEnvelope| item.message_id.clone(),
                message_id,
            )?,
            PersistOp::DeleteOutgoingGroupEnvelope { message_id } => {
                delete_key(tx, "pending_group_outbox", message_id)?;
            }
            PersistOp::SavePendingGroupSeal { group_id } => upsert_from_snapshot(
                tx,
                "pending_group_seal",
                &snapshot.pending_group_seal,
                |item: &SealGroupOutboxRequest| item.group_id.clone(),
                group_id,
            )?,
            PersistOp::DeletePendingGroupSeal { group_id } => {
                delete_key(tx, "pending_group_seal", group_id)?;
            }
            PersistOp::SaveGroupInvite { invite_id } => upsert_from_snapshot(
                tx,
                "group_invites",
                &snapshot.group_invites,
                |item: &PersistedGroupInvite| item.invite_id.clone(),
                invite_id,
            )?,
            PersistOp::DeleteGroupInvite { invite_id } => {
                delete_key(tx, "group_invites", invite_id)?;
            }
            PersistOp::SaveGroupJoinRequest { request_id } => upsert_from_snapshot(
                tx,
                "group_join_requests",
                &snapshot.group_join_requests,
                |item: &PersistedGroupJoinRequest| item.request_id.clone(),
                request_id,
            )?,
            PersistOp::DeleteGroupJoinRequest { request_id } => {
                delete_key(tx, "group_join_requests", request_id)?;
            }
            PersistOp::SavePendingGroupJoinApproval { request_id } => upsert_from_snapshot(
                tx,
                "pending_group_join_approvals",
                &snapshot.pending_group_join_approvals,
                |item: &PersistedPendingGroupJoinApproval| item.request_id.clone(),
                request_id,
            )?,
            PersistOp::DeletePendingGroupJoinApproval { request_id } => {
                delete_key(tx, "pending_group_join_approvals", request_id)?;
            }
            PersistOp::SavePendingWelcomePickup {
                group_id,
                device_id,
            } => {
                let key = pending_welcome_pickup_key(group_id, device_id);
                upsert_from_snapshot(
                    tx,
                    "pending_welcome_pickups",
                    &snapshot.pending_welcome_pickups,
                    |item: &PersistedPendingWelcomePickup| {
                        pending_welcome_pickup_key(&item.group_id, &item.device_id)
                    },
                    &key,
                )?;
            }
            PersistOp::DeletePendingWelcomePickup {
                group_id,
                device_id,
            } => {
                delete_key(
                    tx,
                    "pending_welcome_pickups",
                    &pending_welcome_pickup_key(group_id, device_id),
                )?;
            }
            PersistOp::SavePendingAck { device_id } => upsert_from_snapshot(
                tx,
                "pending_acks",
                &snapshot.pending_acks,
                |item: &PersistedPendingAck| item.device_id.clone(),
                device_id,
            )?,
            PersistOp::DeletePendingAck { device_id } => {
                delete_key(tx, "pending_acks", device_id)?;
            }
            PersistOp::SavePendingBlobTransfer { task_id } => upsert_from_snapshot(
                tx,
                "pending_blob_transfers",
                &snapshot.pending_blob_transfers,
                |item: &PersistedPendingBlobTransfer| pending_blob_transfer_key(item),
                task_id,
            )?,
            PersistOp::DeletePendingBlobTransfer { task_id } => {
                delete_key(tx, "pending_blob_transfers", task_id)?;
            }
            PersistOp::SaveRecoveryContext { conversation_id } => upsert_from_snapshot(
                tx,
                "recovery_contexts",
                &snapshot.recovery_contexts,
                |item: &PersistedRecoveryContext| item.conversation_id.clone(),
                conversation_id,
            )?,
            PersistOp::DeleteRecoveryContext { conversation_id } => {
                delete_key(tx, "recovery_contexts", conversation_id)?;
            }
            PersistOp::SaveRealtimeSession { device_id } => upsert_from_snapshot(
                tx,
                "realtime_sessions",
                &snapshot.realtime_sessions,
                |item: &PersistedRealtimeSession| item.device_id.clone(),
                device_id,
            )?,
            PersistOp::DeleteRealtimeSession { device_id } => {
                delete_key(tx, "realtime_sessions", device_id)?;
            }
        }
    }
    Ok(())
}

fn upsert_from_snapshot<T, F>(
    tx: &Transaction<'_>,
    table: &str,
    values: &[T],
    key_fn: F,
    key: &str,
) -> Result<()>
where
    T: Serialize,
    F: Fn(&T) -> String,
{
    match values
        .iter()
        .enumerate()
        .find(|(_, item)| key_fn(item) == key)
    {
        Some((position, value)) => insert_json(tx, table, key, position, value)?,
        None => delete_key(tx, table, key)?,
    }
    Ok(())
}

fn delete_key(tx: &Transaction<'_>, table: &str, key: &str) -> Result<()> {
    tx.execute(&format!("DELETE FROM {table} WHERE key = ?1"), params![key])?;
    Ok(())
}

fn delete_conversation(tx: &Transaction<'_>, conversation_id: &str) -> Result<()> {
    delete_key(tx, "conversations", conversation_id)?;
    Ok(())
}

fn pending_welcome_pickup_key(group_id: &str, device_id: &str) -> String {
    format!("{group_id}::{device_id}")
}

fn pending_blob_transfer_key(item: &PersistedPendingBlobTransfer) -> String {
    match item {
        PersistedPendingBlobTransfer::Upload { task_id, .. }
        | PersistedPendingBlobTransfer::Download { task_id, .. }
        | PersistedPendingBlobTransfer::Delete { task_id, .. } => task_id.clone(),
    }
}

fn replace_singleton<T: Serialize>(
    tx: &Transaction<'_>,
    table: &str,
    key: &str,
    value: Option<&T>,
) -> Result<()> {
    tx.execute(&format!("DELETE FROM {table}"), [])?;
    if let Some(value) = value {
        insert_json(tx, table, key, 0, value)?;
    }
    Ok(())
}

fn replace_table<T, F>(tx: &Transaction<'_>, table: &str, values: &[T], key_fn: F) -> Result<()>
where
    T: Serialize,
    F: Fn(&T) -> String,
{
    tx.execute(&format!("DELETE FROM {table}"), [])?;
    for (position, value) in values.iter().enumerate() {
        insert_json(tx, table, &key_fn(value), position, value)?;
    }
    Ok(())
}

fn replace_conversations(tx: &Transaction<'_>, values: &[PersistedConversation]) -> Result<()> {
    tx.execute("DELETE FROM conversations", [])?;
    tx.execute("DELETE FROM messages", [])?;
    for (position, value) in values.iter().enumerate() {
        insert_conversation(tx, value, position, true)?;
    }
    Ok(())
}

fn insert_conversation(
    tx: &Transaction<'_>,
    conversation: &PersistedConversation,
    position: usize,
    replace_all_messages: bool,
) -> Result<()> {
    let mut conversation_row = conversation.clone();
    conversation_row.state.messages.clear();
    let value = serde_json::to_vec(&conversation_row)?;
    let last_visible_message = conversation
        .state
        .messages
        .last()
        .filter(|message| message.plaintext.is_some() || !message.storage_refs.is_empty())
        .map(serde_json::to_vec)
        .transpose()?;
    tx.execute(
        "INSERT INTO conversations(
            key, value, position, message_count, last_visible_message, updated_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(key) DO UPDATE SET
            value = excluded.value,
            position = excluded.position,
            message_count = MAX(conversations.message_count, excluded.message_count),
            last_visible_message = COALESCE(
                excluded.last_visible_message,
                conversations.last_visible_message
            ),
            updated_at_ms = excluded.updated_at_ms",
        params![
            conversation.conversation_id,
            value,
            position as i64,
            conversation.state.messages.len() as i64,
            last_visible_message,
            now_ms() as i64
        ],
    )?;
    if replace_all_messages {
        save_conversation_messages(tx, conversation)?;
    } else {
        save_incremental_conversation_messages(tx, conversation)?;
    }
    Ok(())
}

fn insert_conversation_summary(
    tx: &Transaction<'_>,
    summary: &crate::ffi_api::PersistedConversationSummary,
    position: usize,
) -> Result<()> {
    let value = serde_json::to_vec(&summary.conversation)?;
    let last_visible_message = summary
        .last_visible_message
        .as_ref()
        .map(serde_json::to_vec)
        .transpose()?;
    tx.execute(
        "INSERT INTO conversations(
            key, value, position, message_count, last_visible_message, updated_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(key) DO UPDATE SET
            value = excluded.value,
            position = excluded.position,
            message_count = MAX(conversations.message_count, excluded.message_count),
            last_visible_message = COALESCE(
                excluded.last_visible_message,
                conversations.last_visible_message
            ),
            updated_at_ms = excluded.updated_at_ms",
        params![
            summary.conversation.conversation_id,
            value,
            position as i64,
            summary.message_count as i64,
            last_visible_message,
            now_ms() as i64,
        ],
    )?;
    Ok(())
}

fn save_conversation_messages(
    tx: &Transaction<'_>,
    conversation: &PersistedConversation,
) -> Result<()> {
    for message in &conversation.state.messages {
        upsert_message(tx, &conversation.conversation_id, message)?;
    }
    Ok(())
}

/// Incremental conversation saves must remain bounded even when the compact
/// replay index contains years of message IDs. New protocol bundles contain at
/// most a handful of messages, so persist a fixed tail plus the small set of
/// still-mutable delivery rows. Historical sent rows are immutable and remain
/// in SQLCipher without being revisited.
fn save_incremental_conversation_messages(
    tx: &Transaction<'_>,
    conversation: &PersistedConversation,
) -> Result<()> {
    const MUTABLE_TAIL: usize = 16;
    let tail_start = conversation
        .state
        .messages
        .len()
        .saturating_sub(MUTABLE_TAIL);
    let mut saved = std::collections::BTreeSet::new();
    for message in conversation.state.messages.iter().skip(tail_start).chain(
        conversation.state.messages.iter().filter(|message| {
            matches!(
                message.delivery_state,
                Some(
                    crate::conversation::StoredMessageDeliveryState::Sending
                        | crate::conversation::StoredMessageDeliveryState::PendingApproval
                        | crate::conversation::StoredMessageDeliveryState::Failed
                )
            )
        }),
    ) {
        if saved.insert(message.message_id.clone()) {
            upsert_message(tx, &conversation.conversation_id, message)?;
        }
    }
    Ok(())
}

fn upsert_message(
    tx: &Transaction<'_>,
    conversation_id: &str,
    message: &StoredMessage,
) -> Result<()> {
    let message_type = serde_json::to_string(&message.message_type)?;
    let storage_refs = serde_json::to_vec(&message.storage_refs)?;
    let delivery_state = message
        .delivery_state
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?;
    let mut statement = tx.prepare_cached(
        "INSERT INTO messages(
            conversation_id, message_id, app_message_id, mls_ciphertext_sha256,
            sender_user_id, sender_device_id, recipient_device_id, message_type,
            created_at, plaintext, storage_refs, delivery_state, attachment_state,
            message_request_id, payload_version, updated_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, NULL, ?13, 1, ?14)
         ON CONFLICT(conversation_id, message_id) DO UPDATE SET
            app_message_id = excluded.app_message_id,
            mls_ciphertext_sha256 = excluded.mls_ciphertext_sha256,
            sender_user_id = excluded.sender_user_id,
            sender_device_id = excluded.sender_device_id,
            recipient_device_id = excluded.recipient_device_id,
            message_type = excluded.message_type,
            created_at = excluded.created_at,
            plaintext = COALESCE(excluded.plaintext, messages.plaintext),
            storage_refs = CASE
                WHEN excluded.storage_refs = x'5b5d' THEN messages.storage_refs
                ELSE excluded.storage_refs
            END,
            delivery_state = excluded.delivery_state,
            message_request_id = excluded.message_request_id,
            payload_version = excluded.payload_version,
            updated_at_ms = excluded.updated_at_ms
         WHERE app_message_id IS NOT excluded.app_message_id
            OR mls_ciphertext_sha256 IS NOT excluded.mls_ciphertext_sha256
            OR sender_user_id IS NOT excluded.sender_user_id
            OR sender_device_id != excluded.sender_device_id
            OR recipient_device_id != excluded.recipient_device_id
            OR message_type != excluded.message_type
            OR created_at != excluded.created_at
            OR (excluded.plaintext IS NOT NULL AND plaintext IS NOT excluded.plaintext)
            OR (excluded.storage_refs != x'5b5d' AND storage_refs != excluded.storage_refs)
            OR delivery_state IS NOT excluded.delivery_state
            OR message_request_id IS NOT excluded.message_request_id",
    )?;
    statement.execute(params![
        conversation_id,
        message.message_id,
        message.app_message_id,
        message.mls_ciphertext_sha256,
        message.sender_user_id,
        message.sender_device_id,
        message.recipient_device_id,
        message_type,
        message.created_at as i64,
        message.plaintext,
        storage_refs,
        delivery_state,
        message.message_request_id,
        now_ms() as i64,
    ])?;
    Ok(())
}

fn insert_message_if_missing(
    tx: &Transaction<'_>,
    conversation_id: &str,
    message: &StoredMessage,
) -> Result<()> {
    let exists: bool = tx.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM messages WHERE conversation_id = ?1 AND message_id = ?2
         )",
        params![conversation_id, message.message_id],
        |row| row.get(0),
    )?;
    if !exists {
        upsert_message(tx, conversation_id, message)?;
    }
    Ok(())
}

fn update_message_delivery(
    tx: &Transaction<'_>,
    conversation_id: &str,
    message_id: &str,
    delivery_state: Option<crate::conversation::StoredMessageDeliveryState>,
    message_request_id: Option<&str>,
) -> Result<()> {
    let delivery_state = delivery_state
        .map(|state| serde_json::to_string(&state))
        .transpose()?;
    let changed = tx.execute(
        "UPDATE messages
         SET delivery_state = ?3, message_request_id = ?4, updated_at_ms = ?5
         WHERE conversation_id = ?1 AND message_id = ?2",
        params![
            conversation_id,
            message_id,
            delivery_state,
            message_request_id,
            now_ms() as i64,
        ],
    )?;
    if changed != 1 {
        anyhow::bail!("message delivery mutation references a missing message");
    }
    Ok(())
}

fn update_attachment_state(
    tx: &Transaction<'_>,
    conversation_id: &str,
    message_id: &str,
    attachment_state: PersistedMessageAttachmentState,
    plaintext: Option<&str>,
    storage_refs: &[crate::model::StorageRef],
) -> Result<()> {
    let attachment_state = match attachment_state {
        PersistedMessageAttachmentState::Sending => "sending",
        PersistedMessageAttachmentState::Published => "published",
        PersistedMessageAttachmentState::Failed => "failed",
    };
    let storage_refs = serde_json::to_vec(storage_refs)?;
    let changed = tx.execute(
        "UPDATE messages
         SET attachment_state = ?3, plaintext = ?4, storage_refs = ?5, updated_at_ms = ?6
         WHERE conversation_id = ?1 AND message_id = ?2",
        params![
            conversation_id,
            message_id,
            attachment_state,
            plaintext,
            storage_refs,
            now_ms() as i64,
        ],
    )?;
    if changed != 1 {
        anyhow::bail!("attachment mutation references a missing message");
    }
    Ok(())
}

fn delete_message(tx: &Transaction<'_>, conversation_id: &str, message_id: &str) -> Result<()> {
    tx.execute(
        "DELETE FROM messages WHERE conversation_id = ?1 AND message_id = ?2",
        params![conversation_id, message_id],
    )?;
    let message_count: i64 = tx.query_row(
        "SELECT COUNT(*) FROM messages WHERE conversation_id = ?1",
        params![conversation_id],
        |row| row.get(0),
    )?;
    let columns = "message_id, app_message_id, mls_ciphertext_sha256, sender_user_id,
                   sender_device_id, recipient_device_id, message_type, created_at,
                   plaintext, storage_refs, delivery_state, message_request_id";
    let last_visible_message = tx
        .query_row(
            &format!(
                "SELECT {columns} FROM messages
                 WHERE conversation_id = ?1
                   AND (plaintext IS NOT NULL OR storage_refs != x'5b5d')
                 ORDER BY created_at DESC, message_id DESC LIMIT 1"
            ),
            params![conversation_id],
            decode_message_row,
        )
        .optional()?
        .as_ref()
        .map(serde_json::to_vec)
        .transpose()?;
    tx.execute(
        "UPDATE conversations
         SET message_count = ?2, last_visible_message = ?3, updated_at_ms = ?4
         WHERE key = ?1",
        params![
            conversation_id,
            message_count,
            last_visible_message,
            now_ms() as i64,
        ],
    )?;
    Ok(())
}

fn insert_json<T: Serialize>(
    tx: &Transaction<'_>,
    table: &str,
    key: &str,
    position: usize,
    value: &T,
) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    tx.execute(
        &format!(
            "INSERT OR REPLACE INTO {table}(key, value, position, updated_at_ms) VALUES (?1, ?2, ?3, ?4)"
        ),
        params![key, bytes, position as i64, now_ms() as i64],
    )?;
    Ok(())
}

fn load_singleton<T: DeserializeOwned>(
    conn: &Connection,
    table: &str,
    key: &str,
) -> Result<Option<T>> {
    let bytes: Option<Vec<u8>> = conn
        .query_row(
            &format!("SELECT value FROM {table} WHERE key = ?1"),
            params![key],
            |row| row.get(0),
        )
        .optional()?;
    bytes
        .map(|bytes| serde_json::from_slice(&bytes).map_err(anyhow::Error::from))
        .transpose()
}

fn load_table<T: DeserializeOwned>(conn: &Connection, table: &str) -> Result<Vec<T>> {
    let mut stmt = conn.prepare(&format!("SELECT value FROM {table} ORDER BY position, key"))?;
    let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
    let mut values = Vec::new();
    for row in rows {
        let bytes = row?;
        values.push(serde_json::from_slice(&bytes)?);
    }
    Ok(values)
}

fn load_message_security_index(
    conn: &Connection,
    conversations: &mut [PersistedConversation],
) -> Result<()> {
    let mut conversation_positions: HashMap<String, usize> = conversations
        .iter()
        .enumerate()
        .map(|(position, conversation)| (conversation.conversation_id.clone(), position))
        .collect();
    let mut stmt = conn.prepare(
        "SELECT conversation_id, message_id, app_message_id, mls_ciphertext_sha256,
                sender_user_id, sender_device_id, recipient_device_id, message_type,
                created_at, delivery_state, message_request_id
         FROM messages
         WHERE app_message_id IS NOT NULL
            OR mls_ciphertext_sha256 IS NOT NULL
            OR delivery_state = '\"pending_approval\"'
         ORDER BY conversation_id, created_at, message_id",
    )?;
    let rows = stmt.query_map([], |row| {
        let message_type: String = row.get(7)?;
        let delivery_state: Option<String> = row.get(9)?;
        Ok((
            row.get::<_, String>(0)?,
            StoredMessage {
                message_id: row.get(1)?,
                app_message_id: row.get(2)?,
                mls_ciphertext_sha256: row.get(3)?,
                sender_user_id: row.get(4)?,
                sender_device_id: row.get(5)?,
                recipient_device_id: row.get(6)?,
                message_type: serde_json::from_str(&message_type).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        7,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?,
                created_at: row.get::<_, i64>(8)?.max(0) as u64,
                plaintext: None,
                storage_refs: Vec::new(),
                delivery_state: delivery_state
                    .map(|value| serde_json::from_str(&value))
                    .transpose()
                    .map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            9,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?,
                message_request_id: row.get(10)?,
            },
        ))
    })?;
    for row in rows {
        let (conversation_id, message) = row?;
        if let Some(position) = conversation_positions.get_mut(&conversation_id) {
            conversations[*position].state.messages.push(message);
        }
    }
    Ok(())
}

fn get_message_from_conn(
    conn: &Connection,
    conversation_id: &str,
    message_id: &str,
) -> Result<Option<StoredMessage>> {
    let columns = "message_id, app_message_id, mls_ciphertext_sha256, sender_user_id,
                   sender_device_id, recipient_device_id, message_type, created_at,
                   plaintext, storage_refs, delivery_state, message_request_id";
    let sql = format!(
        "SELECT {columns} FROM messages
         WHERE conversation_id = ?1
           AND (message_id = ?2 OR app_message_id = ?2)
         ORDER BY created_at DESC, message_id DESC LIMIT 1"
    );
    conn.query_row(
        &sql,
        params![conversation_id, message_id],
        decode_message_row,
    )
    .optional()
    .map_err(anyhow::Error::from)
}

fn query_messages_from_conn(conn: &Connection, query: &MessageQuery) -> Result<MessagePage> {
    let limit = query.limit.clamp(1, 200);
    let cursor = query
        .before_cursor
        .as_deref()
        .map(decode_message_cursor)
        .transpose()?;
    let columns = "message_id, app_message_id, mls_ciphertext_sha256, sender_user_id,
                   sender_device_id, recipient_device_id, message_type, created_at,
                   plaintext, storage_refs, delivery_state, message_request_id";
    let mut messages = Vec::with_capacity(limit.saturating_add(1));
    if let Some(cursor) = cursor {
        let sql = format!(
            "SELECT {columns} FROM messages
             WHERE conversation_id = ?1
               AND (created_at < ?2 OR (created_at = ?2 AND message_id < ?3))
             ORDER BY created_at DESC, message_id DESC LIMIT ?4"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(
            params![
                query.conversation_id,
                cursor.created_at as i64,
                cursor.message_id,
                limit.saturating_add(1) as i64
            ],
            decode_message_row,
        )?;
        for row in rows {
            messages.push(row?);
        }
    } else {
        let sql = format!(
            "SELECT {columns} FROM messages
             WHERE conversation_id = ?1
             ORDER BY created_at DESC, message_id DESC LIMIT ?2"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(
            params![query.conversation_id, limit.saturating_add(1) as i64],
            decode_message_row,
        )?;
        for row in rows {
            messages.push(row?);
        }
    }
    let has_more = messages.len() > limit;
    messages.truncate(limit);
    let next_cursor = has_more
        .then(|| messages.last())
        .flatten()
        .map(|message| encode_message_cursor(message.created_at, &message.message_id))
        .transpose()?;
    messages.reverse();
    Ok(MessagePage {
        messages,
        next_cursor,
    })
}

const DIRECT_VISIBLE_MESSAGE_TYPES_SQL: &str = concat!(
    "'\"mls_application\"',",
    "'\"control_contact_removed\"',",
    "'\"control_identity_state_updated\"'",
);
const GROUP_VISIBLE_MESSAGE_TYPES_SQL: &str = concat!(
    "'\"mls_application\"',",
    "'\"control_group_state_event\"',",
    "'\"control_conversation_needs_rebuild\"'",
);

fn visible_message_types_sql(kind: ConversationKind) -> &'static str {
    match kind {
        ConversationKind::Direct => DIRECT_VISIBLE_MESSAGE_TYPES_SQL,
        ConversationKind::Group => GROUP_VISIBLE_MESSAGE_TYPES_SQL,
    }
}

fn count_received_visible_messages_from_conn(
    conn: &Connection,
    conversation_id: &str,
    local_device_id: &str,
    kind: ConversationKind,
    after: Option<&MessageReadCursor>,
) -> Result<u64> {
    let type_filter = visible_message_types_sql(kind);
    let count = match after {
        Some(after) => {
            let sql = format!(
                "SELECT COUNT(*) FROM messages
                 WHERE conversation_id = ?1
                   AND sender_device_id <> ?2
                   AND plaintext IS NOT NULL
                   AND message_type IN ({type_filter})
                   AND (created_at > ?3 OR (created_at = ?3 AND message_id > ?4))"
            );
            conn.query_row(
                &sql,
                params![
                    conversation_id,
                    local_device_id,
                    after.created_at as i64,
                    after.message_id
                ],
                |row| row.get::<_, i64>(0),
            )?
        }
        None => {
            let sql = format!(
                "SELECT COUNT(*) FROM messages
                 WHERE conversation_id = ?1
                   AND sender_device_id <> ?2
                   AND plaintext IS NOT NULL
                   AND message_type IN ({type_filter})"
            );
            conn.query_row(&sql, params![conversation_id, local_device_id], |row| {
                row.get::<_, i64>(0)
            })?
        }
    };
    Ok(count.max(0) as u64)
}

fn latest_visible_message_cursor_from_conn(
    conn: &Connection,
    conversation_id: &str,
    kind: ConversationKind,
) -> Result<Option<MessageReadCursor>> {
    let type_filter = visible_message_types_sql(kind);
    let sql = format!(
        "SELECT created_at, message_id FROM messages
         WHERE conversation_id = ?1
         AND plaintext IS NOT NULL
         AND message_type IN ({type_filter})
         ORDER BY created_at DESC, message_id DESC LIMIT 1"
    );
    conn.query_row(&sql, params![conversation_id], |row| {
        Ok(MessageReadCursor {
            created_at: row.get::<_, i64>(0)?.max(0) as u64,
            message_id: row.get(1)?,
        })
    })
    .optional()
    .map_err(anyhow::Error::from)
}

fn visible_message_cursor_from_conn(
    conn: &Connection,
    conversation_id: &str,
    message_id: &str,
    kind: ConversationKind,
) -> Result<Option<MessageReadCursor>> {
    let type_filter = visible_message_types_sql(kind);
    let sql = format!(
        "SELECT created_at, message_id FROM messages
         WHERE conversation_id = ?1
         AND (message_id = ?2 OR app_message_id = ?2)
         AND plaintext IS NOT NULL
         AND message_type IN ({type_filter})
         ORDER BY created_at DESC, message_id DESC LIMIT 1"
    );
    conn.query_row(&sql, params![conversation_id, message_id], |row| {
        Ok(MessageReadCursor {
            created_at: row.get::<_, i64>(0)?.max(0) as u64,
            message_id: row.get(1)?,
        })
    })
    .optional()
    .map_err(anyhow::Error::from)
}

fn decode_message_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredMessage> {
    let message_type: String = row.get(6)?;
    let storage_refs: Vec<u8> = row.get(9)?;
    let delivery_state: Option<String> = row.get(10)?;
    Ok(StoredMessage {
        message_id: row.get(0)?,
        app_message_id: row.get(1)?,
        mls_ciphertext_sha256: row.get(2)?,
        sender_user_id: row.get(3)?,
        sender_device_id: row.get(4)?,
        recipient_device_id: row.get(5)?,
        message_type: serde_json::from_str(&message_type).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                6,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        created_at: row.get::<_, i64>(7)?.max(0) as u64,
        plaintext: row.get(8)?,
        storage_refs: serde_json::from_slice(&storage_refs).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                9,
                rusqlite::types::Type::Blob,
                Box::new(error),
            )
        })?,
        delivery_state: delivery_state
            .map(|value| serde_json::from_str(&value))
            .transpose()
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    10,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?,
        message_request_id: row.get(11)?,
    })
}

fn encode_message_cursor(created_at: u64, message_id: &str) -> Result<String> {
    let bytes = serde_json::to_vec(&MessageCursorV1 {
        version: 1,
        created_at,
        message_id: message_id.to_string(),
    })?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn decode_message_cursor(cursor: &str) -> Result<MessageCursorV1> {
    let bytes = URL_SAFE_NO_PAD
        .decode(cursor)
        .context("invalid message cursor encoding")?;
    let cursor: MessageCursorV1 =
        serde_json::from_slice(&bytes).context("invalid message cursor payload")?;
    if cursor.version != 1 || cursor.message_id.is_empty() {
        anyhow::bail!("unsupported message cursor")
    }
    Ok(cursor)
}

fn save_meta(tx: &Transaction<'_>, key: &str, value: impl AsRef<str>) -> Result<()> {
    tx.execute(
        "INSERT OR REPLACE INTO state_meta(key, value) VALUES (?1, ?2)",
        params![key, value.as_ref()],
    )?;
    Ok(())
}

fn load_meta_u64(conn: &Connection, key: &str) -> Result<Option<u64>> {
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM state_meta WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()?;
    value
        .map(|value| value.parse::<u64>().context("parse local store u64 meta"))
        .transpose()
}

fn load_meta_string(conn: &Connection, key: &str) -> Result<Option<String>> {
    conn.query_row(
        "SELECT value FROM state_meta WHERE key = ?1",
        params![key],
        |row| row.get(0),
    )
    .optional()
    .map_err(Into::into)
}

fn load_meta_bool(conn: &Connection, key: &str) -> Result<Option<bool>> {
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM state_meta WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()?;
    Ok(value.map(|value| value == "true"))
}

fn load_schema_version(conn: &Connection) -> Result<u32> {
    let value: String = conn
        .query_row(
            "SELECT value FROM schema_meta WHERE key = ?1",
            params![SCHEMA_VERSION_KEY],
            |row| row.get(0),
        )
        .context("read local store schema version")?;
    value
        .parse::<u32>()
        .context("parse local store schema version")
}

fn schema_migration_complete(conn: &Connection) -> Result<bool> {
    let value = load_optional_schema_meta(conn, MIGRATION_COMPLETE_KEY)?;
    Ok(value.as_deref() == Some("true"))
}

fn load_optional_schema_meta(conn: &Connection, key: &str) -> Result<Option<String>> {
    conn.query_row(
        "SELECT value FROM schema_meta WHERE key = ?1",
        params![key],
        |row| row.get(0),
    )
    .optional()
    .map_err(anyhow::Error::from)
}

fn mark_schema_migration_complete(store: &SqlCipherLocalStore<'_>) -> Result<()> {
    let conn = store.connect()?;
    ensure_schema(&conn)?;
    conn.execute(
        "INSERT OR REPLACE INTO schema_meta(key, value) VALUES (?1, 'true')",
        params![MIGRATION_COMPLETE_KEY],
    )?;
    Ok(())
}

fn load_document_from_conn(conn: &Connection, kind: &str) -> Result<Option<Vec<u8>>> {
    conn.query_row(
        "SELECT payload FROM documents WHERE kind = ?1",
        params![kind],
        |row| row.get(0),
    )
    .optional()
    .map_err(anyhow::Error::from)
}

fn save_document_in_tx(tx: &Transaction<'_>, kind: &str, plaintext: &[u8]) -> Result<()> {
    tx.execute(
        "INSERT OR REPLACE INTO documents(kind, format_version, payload, updated_at_ms)
         VALUES (?1, ?2, ?3, ?4)",
        params![kind, SCHEMA_VERSION as i64, plaintext, now_ms() as i64],
    )?;
    Ok(())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        CapabilityService, Conversation, ConversationKind, ConversationMember, ConversationState,
        DeviceStatusKind, GroupCapability, GroupCapabilityOperation, GroupRole, MessageType,
        CURRENT_MODEL_VERSION,
    };
    use crate::profile_crypto::generate_pdek;
    use tempfile::tempdir;

    fn sample_snapshot(device_id: &str, nonce: u64) -> CorePersistenceSnapshot {
        CorePersistenceSnapshot {
            message_nonce: nonce,
            realtime_sessions: vec![PersistedRealtimeSession {
                device_id: device_id.to_string(),
                last_known_seq: nonce,
                needs_reconnect: true,
            }],
            ..CorePersistenceSnapshot::default()
        }
    }

    #[test]
    fn migration_uses_tmp_db_and_marks_complete() {
        let dir = tempdir().expect("tempdir");
        let pdek = generate_pdek();
        let snapshot = sample_snapshot("device:alice:phone", 7);
        let encrypted = EncryptedSnapshotStore::new(dir.path(), "profile:test", &*pdek);
        encrypted.save_snapshot(&snapshot).expect("save snapshot");

        migrate_snapshot_to_state_db(dir.path(), "profile:test", &*pdek).expect("migrate");

        assert!(dir.path().join(STATE_DB_FILE_NAME).exists());
        assert!(!dir.path().join(STATE_DB_TMP_FILE_NAME).exists());
        assert!(dir.path().join(SNAPSHOT_DB_BACKUP_FILE_NAME).exists());
        let store = SqlCipherLocalStore::new(dir.path(), "profile:test", &*pdek);
        let conn = store.connect().expect("connect");
        ensure_schema(&conn).expect("schema");
        assert!(schema_migration_complete(&conn).expect("marker"));
        assert_eq!(store.load_snapshot().expect("load"), snapshot);
        let diagnostics =
            inspect_storage(dir.path(), "profile:test", &*pdek).expect("inspect storage");
        assert!(diagnostics.state_db_exists);
        assert_eq!(diagnostics.schema_version, Some(SCHEMA_VERSION));
        assert_eq!(diagnostics.migration_complete, Some(true));
        assert!(diagnostics.encrypted_snapshot_exists);
        assert!(diagnostics.encrypted_snapshot_backup_exists);
        assert!(diagnostics.state_db_size_bytes.is_some_and(|size| size > 0));
        assert!(diagnostics
            .encrypted_snapshot_size_bytes
            .is_some_and(|size| size > 0));
        assert!(diagnostics
            .encrypted_snapshot_backup_size_bytes
            .is_some_and(|size| size > 0));
        assert!(
            diagnostics
                .legacy_files_present
                .contains(&PRIVATE_STATE_FILE_NAME.to_string())
                || !diagnostics.private_enc_exists
        );
    }

    #[test]
    fn incomplete_state_db_is_rebuilt_from_encrypted_snapshot() {
        let dir = tempdir().expect("tempdir");
        let pdek = generate_pdek();
        let snapshot = sample_snapshot("device:alice:phone", 11);
        EncryptedSnapshotStore::new(dir.path(), "profile:test", &*pdek)
            .save_snapshot(&snapshot)
            .expect("save encrypted snapshot");
        SqlCipherLocalStore::new(dir.path(), "profile:test", &*pdek)
            .save_snapshot(&CorePersistenceSnapshot::default())
            .expect("write incomplete db");

        migrate_snapshot_to_state_db(dir.path(), "profile:test", &*pdek).expect("remigrate");

        let store = SqlCipherLocalStore::new(dir.path(), "profile:test", &*pdek);
        assert_eq!(store.load_snapshot().expect("load"), snapshot);
        let conn = store.connect().expect("connect");
        ensure_schema(&conn).expect("schema");
        assert!(schema_migration_complete(&conn).expect("marker"));
    }

    #[test]
    fn persist_state_applies_typed_mutations_transactionally() {
        let dir = tempdir().expect("tempdir");
        let pdek = generate_pdek();
        let store = SqlCipherLocalStore::new(dir.path(), "profile:test", &*pdek);
        let before = sample_snapshot("device:alice:phone", 1);
        store.save_snapshot(&before).expect("save before");

        let after = sample_snapshot("device:alice:phone", 2);
        store
            .persist_state(&PersistStateEffect {
                mutations: vec![
                    PersistenceMutation::SaveMetadata {
                        message_nonce: after.message_nonce,
                        local_display_name: None,
                        mls_state_persistence_blocked: false,
                    },
                    PersistenceMutation::Save {
                        table: PersistenceTable::RealtimeSessions,
                        key: "device:alice:phone".into(),
                        position: 0,
                        value: PersistenceValue::RealtimeSession(
                            after.realtime_sessions[0].clone(),
                        ),
                    },
                ],
                ops: vec![],
                snapshot: None,
            })
            .expect("persist typed mutations");

        assert_eq!(store.load_snapshot().expect("load after"), after);
    }

    #[test]
    fn invalid_typed_mutation_rolls_back_the_whole_batch() {
        let dir = tempdir().expect("tempdir");
        let pdek = generate_pdek();
        let store = SqlCipherLocalStore::new(dir.path(), "profile:test", &*pdek);
        let before = sample_snapshot("device:alice:phone", 1);
        store.save_snapshot(&before).expect("save before");

        let result = store.persist_state(&PersistStateEffect {
            mutations: vec![
                PersistenceMutation::SaveMetadata {
                    message_nonce: 99,
                    local_display_name: Some("must roll back".into()),
                    mls_state_persistence_blocked: true,
                },
                PersistenceMutation::Save {
                    table: PersistenceTable::Contacts,
                    key: "device:alice:phone".into(),
                    position: 0,
                    value: PersistenceValue::RealtimeSession(before.realtime_sessions[0].clone()),
                },
            ],
            ops: vec![],
            snapshot: None,
        });

        assert!(result.is_err());
        assert_eq!(store.load_snapshot().expect("load after rollback"), before);
    }

    #[test]
    fn persist_state_applies_pending_group_seal_ops() {
        let dir = tempdir().expect("tempdir");
        let pdek = generate_pdek();
        let store = SqlCipherLocalStore::new(dir.path(), "profile:test", &*pdek);
        store
            .save_snapshot(&CorePersistenceSnapshot::default())
            .expect("save before");

        let seal = SealGroupOutboxRequest {
            group_id: "group:seal".into(),
            capability: GroupCapability {
                version: CURRENT_MODEL_VERSION.to_string(),
                service: CapabilityService::GroupOutbox,
                group_id: "group:seal".into(),
                user_id: "user:alice".into(),
                device_id: "device:alice:phone".into(),
                operations: vec![GroupCapabilityOperation::SealGroup],
                role: GroupRole::Owner,
                expires_at: 999,
                signature: "sig".into(),
            },
        };
        let after_save = CorePersistenceSnapshot {
            pending_group_seal: vec![seal],
            ..CorePersistenceSnapshot::default()
        };
        store
            .persist_state(&PersistStateEffect {
                mutations: vec![],
                ops: vec![PersistOp::SavePendingGroupSeal {
                    group_id: "group:seal".into(),
                }],
                snapshot: Some(after_save.clone()),
            })
            .expect("save pending seal");
        assert_eq!(store.load_snapshot().expect("load seal"), after_save);

        store
            .persist_state(&PersistStateEffect {
                mutations: vec![],
                ops: vec![PersistOp::DeletePendingGroupSeal {
                    group_id: "group:seal".into(),
                }],
                snapshot: Some(CorePersistenceSnapshot::default()),
            })
            .expect("delete pending seal");
        assert!(store
            .load_snapshot()
            .expect("load after delete")
            .pending_group_seal
            .is_empty());
    }

    #[test]
    fn message_delivery_attachment_and_delete_mutations_are_atomic() {
        let dir = tempdir().expect("tempdir");
        let pdek = generate_pdek();
        let store = SqlCipherLocalStore::new(dir.path(), "profile:test", &*pdek);
        let conversation_id = "conversation:attachment".to_string();
        let message_id = "message:attachment".to_string();
        let message = StoredMessage {
            message_id: message_id.clone(),
            app_message_id: Some("app:attachment".into()),
            mls_ciphertext_sha256: Some("hash:attachment".into()),
            sender_user_id: Some("user:alice".into()),
            sender_device_id: "device:alice:phone".into(),
            recipient_device_id: "device:bob:phone".into(),
            message_type: MessageType::MlsApplication,
            created_at: 42,
            plaintext: Some("encrypted attachment manifest".into()),
            storage_refs: vec![crate::model::StorageRef {
                kind: "attachment_original".into(),
                object_ref: "blob:test".into(),
                size_bytes: 16,
                mime_type: "application/octet-stream".into(),
                file_name: None,
                expires_at: Some(999),
            }],
            delivery_state: Some(crate::conversation::StoredMessageDeliveryState::Sending),
            message_request_id: None,
        };
        let conversation = PersistedConversation {
            conversation_id: conversation_id.clone(),
            state: crate::conversation::LocalConversationState {
                conversation: Conversation {
                    conversation_id: conversation_id.clone(),
                    kind: ConversationKind::Direct,
                    member_users: vec!["user:alice".into(), "user:bob".into()],
                    member_devices: vec![],
                    state: ConversationState::Active,
                    updated_at: 42,
                },
                messages: vec![message],
                last_message_type: Some(MessageType::MlsApplication),
                peer_user_id: "user:bob".into(),
                last_known_peer_active_devices: Default::default(),
                recovery_status: crate::conversation::RecoveryStatus::Healthy,
                archive_metadata: None,
                pcs: Default::default(),
            },
        };
        store
            .save_snapshot(&CorePersistenceSnapshot {
                conversations: vec![conversation],
                ..CorePersistenceSnapshot::default()
            })
            .expect("seed attachment message");

        store
            .persist_state(&PersistStateEffect {
                mutations: vec![
                    PersistenceMutation::UpdateMessageDelivery {
                        conversation_id: conversation_id.clone(),
                        message_id: message_id.clone(),
                        delivery_state: Some(
                            crate::conversation::StoredMessageDeliveryState::Failed,
                        ),
                        message_request_id: None,
                    },
                    PersistenceMutation::UpdateAttachmentState {
                        conversation_id: conversation_id.clone(),
                        message_id: message_id.clone(),
                        attachment_state: PersistedMessageAttachmentState::Failed,
                        plaintext: None,
                        storage_refs: vec![],
                    },
                ],
                ops: vec![],
                snapshot: None,
            })
            .expect("mark attachment failed");
        let page = store
            .query_messages(&MessageQuery {
                conversation_id: conversation_id.clone(),
                before_cursor: None,
                limit: 10,
            })
            .expect("query failed attachment");
        assert_eq!(page.messages.len(), 1);
        assert_eq!(
            page.messages[0].delivery_state,
            Some(crate::conversation::StoredMessageDeliveryState::Failed)
        );
        assert!(page.messages[0].plaintext.is_none());
        assert!(page.messages[0].storage_refs.is_empty());
        let conn = store.connect().expect("connect");
        let attachment_state: String = conn
            .query_row(
                "SELECT attachment_state FROM messages
                 WHERE conversation_id = ?1 AND message_id = ?2",
                params![conversation_id, message_id],
                |row| row.get(0),
            )
            .expect("attachment state");
        assert_eq!(attachment_state, "failed");

        store
            .persist_state(&PersistStateEffect {
                mutations: vec![PersistenceMutation::DeleteMessage {
                    conversation_id: conversation_id.clone(),
                    message_id: message_id.clone(),
                }],
                ops: vec![],
                snapshot: None,
            })
            .expect("delete message");
        assert!(store
            .query_messages(&MessageQuery {
                conversation_id: conversation_id.clone(),
                before_cursor: None,
                limit: 10,
            })
            .expect("query after delete")
            .messages
            .is_empty());
        let summary: (i64, Option<Vec<u8>>) = conn
            .query_row(
                "SELECT message_count, last_visible_message FROM conversations WHERE key = ?1",
                params![conversation_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("conversation summary after delete");
        assert_eq!(summary, (0, None));
    }

    #[test]
    fn get_message_returns_plaintext_after_security_index_restore() {
        let dir = tempdir().expect("tempdir");
        let pdek = generate_pdek();
        let store = SqlCipherLocalStore::new(dir.path(), "profile:test", &*pdek);
        let conversation_id = "conversation:hydrate".to_string();
        let message_id = "message:hydrate".to_string();
        let plaintext = r#"{"version":2,"attachment_id":"att:1"}"#;
        let message = StoredMessage {
            message_id: message_id.clone(),
            app_message_id: Some("app:hydrate".into()),
            mls_ciphertext_sha256: Some("hash:hydrate".into()),
            sender_user_id: Some("user:alice".into()),
            sender_device_id: "device:alice:phone".into(),
            recipient_device_id: "device:bob:phone".into(),
            message_type: MessageType::MlsApplication,
            created_at: 42,
            plaintext: Some(plaintext.into()),
            storage_refs: vec![crate::model::StorageRef {
                kind: "attachment_original".into(),
                object_ref: "blob:hydrate".into(),
                size_bytes: 16,
                mime_type: "application/octet-stream".into(),
                file_name: None,
                expires_at: Some(999),
            }],
            delivery_state: None,
            message_request_id: None,
        };
        let conversation = PersistedConversation {
            conversation_id: conversation_id.clone(),
            state: crate::conversation::LocalConversationState {
                conversation: Conversation {
                    conversation_id: conversation_id.clone(),
                    kind: ConversationKind::Direct,
                    member_users: vec!["user:alice".into(), "user:bob".into()],
                    member_devices: vec![],
                    state: ConversationState::Active,
                    updated_at: 42,
                },
                messages: vec![message.clone()],
                last_message_type: Some(MessageType::MlsApplication),
                peer_user_id: "user:bob".into(),
                last_known_peer_active_devices: Default::default(),
                recovery_status: crate::conversation::RecoveryStatus::Healthy,
                archive_metadata: None,
                pcs: Default::default(),
            },
        };
        store
            .save_snapshot(&CorePersistenceSnapshot {
                conversations: vec![conversation],
                ..CorePersistenceSnapshot::default()
            })
            .expect("seed attachment message");

        let snapshot = store.load_snapshot().expect("load snapshot");
        let restored = snapshot
            .conversations
            .iter()
            .find(|conversation| conversation.conversation_id == conversation_id)
            .and_then(|conversation| {
                conversation
                    .state
                    .messages
                    .iter()
                    .find(|candidate| candidate.message_id == message_id)
            })
            .expect("security index row");
        assert!(restored.plaintext.is_none());
        assert!(restored.storage_refs.is_empty());

        let loaded = store
            .get_message(&conversation_id, &message_id)
            .expect("get_message")
            .expect("message present");
        assert_eq!(loaded.plaintext.as_deref(), Some(plaintext));
        assert_eq!(loaded.storage_refs, message.storage_refs);

        let by_app = store
            .get_message(&conversation_id, "app:hydrate")
            .expect("get_message by app id")
            .expect("message present");
        assert_eq!(by_app.message_id, message_id);
    }

    #[test]
    #[ignore = "100k-message storage regression; run explicitly in release validation"]
    fn hundred_thousand_messages_use_indexed_cursor_pages_and_compact_bootstrap() {
        let dir = tempdir().expect("tempdir");
        let pdek = generate_pdek();
        let store = SqlCipherLocalStore::new(dir.path(), "profile:scale", &*pdek);
        let conversation_id = "conversation:scale".to_string();
        let messages = (0..100_000_u64)
            .map(|index| StoredMessage {
                message_id: format!("message:{index:06}"),
                app_message_id: Some(format!("app:{index:06}")),
                mls_ciphertext_sha256: Some(format!("hash:{index:06}")),
                sender_user_id: Some("user:alice".into()),
                sender_device_id: "device:alice:phone".into(),
                recipient_device_id: "device:bob:phone".into(),
                message_type: MessageType::MlsApplication,
                created_at: index,
                plaintext: Some(format!("body {index}")),
                storage_refs: Vec::new(),
                delivery_state: None,
                message_request_id: None,
            })
            .collect::<Vec<_>>();
        let conversation = PersistedConversation {
            conversation_id: conversation_id.clone(),
            state: crate::conversation::LocalConversationState {
                conversation: Conversation {
                    conversation_id: conversation_id.clone(),
                    kind: ConversationKind::Direct,
                    member_users: vec!["user:alice".into(), "user:bob".into()],
                    member_devices: vec![ConversationMember {
                        user_id: "user:alice".into(),
                        device_id: "device:alice:phone".into(),
                        status: DeviceStatusKind::Active,
                    }],
                    state: ConversationState::Active,
                    updated_at: 100_000,
                },
                messages,
                last_message_type: Some(MessageType::MlsApplication),
                peer_user_id: "user:bob".into(),
                last_known_peer_active_devices: Default::default(),
                recovery_status: crate::conversation::RecoveryStatus::Healthy,
                archive_metadata: None,
                pcs: Default::default(),
            },
        };
        let snapshot = CorePersistenceSnapshot {
            conversations: vec![conversation.clone()],
            ..CorePersistenceSnapshot::default()
        };
        store.save_snapshot(&snapshot).expect("save 100k messages");

        let first = store
            .query_messages(&MessageQuery {
                conversation_id: conversation_id.clone(),
                before_cursor: None,
                limit: 50,
            })
            .expect("latest page");
        assert_eq!(first.messages.len(), 50);
        assert_eq!(first.messages.first().unwrap().message_id, "message:099950");
        assert_eq!(first.messages.last().unwrap().message_id, "message:099999");
        let second = store
            .query_messages(&MessageQuery {
                conversation_id: conversation_id.clone(),
                before_cursor: first.next_cursor,
                limit: 50,
            })
            .expect("history page");
        assert_eq!(
            second.messages.first().unwrap().message_id,
            "message:099900"
        );
        assert_eq!(second.messages.last().unwrap().message_id, "message:099949");

        let bootstrap = store.load_snapshot().expect("compact bootstrap");
        let compact = &bootstrap.conversations[0].state.messages;
        assert_eq!(compact.len(), 100_000);
        assert!(compact
            .iter()
            .all(|message| message.plaintext.is_none() && message.storage_refs.is_empty()));

        let mut after = snapshot;
        let new_message = StoredMessage {
            message_id: "message:100000".into(),
            app_message_id: Some("app:100000".into()),
            mls_ciphertext_sha256: Some("hash:100000".into()),
            sender_user_id: Some("user:alice".into()),
            sender_device_id: "device:alice:phone".into(),
            recipient_device_id: "device:bob:phone".into(),
            message_type: MessageType::MlsApplication,
            created_at: 100_000,
            plaintext: Some("new body".into()),
            storage_refs: Vec::new(),
            delivery_state: None,
            message_request_id: None,
        };
        after.conversations[0]
            .state
            .messages
            .push(new_message.clone());
        let mut conversation_summary = after.conversations[0].clone();
        conversation_summary.state.messages.clear();
        let mutations = vec![
            PersistenceMutation::SaveMetadata {
                message_nonce: 0,
                local_display_name: None,
                mls_state_persistence_blocked: false,
            },
            PersistenceMutation::Save {
                table: PersistenceTable::Conversations,
                key: conversation_id.clone(),
                position: 0,
                value: PersistenceValue::ConversationSummary(
                    crate::ffi_api::PersistedConversationSummary {
                        conversation: conversation_summary,
                        message_count: 100_001,
                        last_visible_message: Some(new_message.clone()),
                    },
                ),
            },
            PersistenceMutation::InsertMessage {
                conversation_id: conversation_id.clone(),
                message: new_message.clone(),
            },
            PersistenceMutation::UpdateMessageDelivery {
                conversation_id: conversation_id.clone(),
                message_id: new_message.message_id.clone(),
                delivery_state: None,
                message_request_id: None,
            },
        ];
        assert_eq!(mutations.len(), 4, "one append has a fixed mutation count");
        store
            .persist_state(&PersistStateEffect {
                mutations,
                ops: vec![],
                snapshot: None,
            })
            .expect("append one message");
        let conn = store.connect().expect("connect");
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE conversation_id = ?1",
                params![conversation_id],
                |row| row.get(0),
            )
            .expect("count messages");
        assert_eq!(count, 100_001);
        let plan = conn
            .prepare(
                "EXPLAIN QUERY PLAN
                 SELECT message_id FROM messages
                 WHERE conversation_id = ?1
                   AND (created_at < ?2 OR (created_at = ?2 AND message_id < ?3))
                 ORDER BY created_at DESC, message_id DESC LIMIT 50",
            )
            .expect("prepare query plan")
            .query_map(
                params![conversation_id, 100_000_i64, "message:100000"],
                |row| row.get::<_, String>(3),
            )
            .expect("query plan")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect query plan")
            .join("\n");
        assert!(plan.contains("messages_page_idx"), "query plan: {plan}");
    }

    #[test]
    fn received_visible_message_count_uses_device_and_message_cursor() {
        let dir = tempdir().expect("tempdir");
        let pdek = generate_pdek();
        let store = SqlCipherLocalStore::new(dir.path(), "profile:test", &*pdek);
        let conversation_id = "conversation:unread".to_string();
        let local_device_id = "device:alice:phone";
        let remote_device_id = "device:bob:phone";

        let message = |message_id: &str,
                       sender_device_id: &str,
                       message_type: MessageType,
                       created_at: u64,
                       plaintext: Option<&str>| StoredMessage {
            message_id: message_id.into(),
            app_message_id: Some(format!("app:{message_id}")),
            mls_ciphertext_sha256: None,
            sender_user_id: Some("user:bob".into()),
            sender_device_id: sender_device_id.into(),
            recipient_device_id: local_device_id.into(),
            message_type,
            created_at,
            plaintext: plaintext.map(str::to_string),
            storage_refs: Vec::new(),
            delivery_state: None,
            message_request_id: None,
        };

        let conversation = Conversation {
            conversation_id: conversation_id.clone(),
            kind: ConversationKind::Direct,
            member_users: vec!["user:alice".into(), "user:bob".into()],
            member_devices: vec![
                ConversationMember {
                    user_id: "user:alice".into(),
                    device_id: local_device_id.into(),
                    status: DeviceStatusKind::Active,
                },
                ConversationMember {
                    user_id: "user:bob".into(),
                    device_id: remote_device_id.into(),
                    status: DeviceStatusKind::Active,
                },
            ],
            state: ConversationState::Active,
            updated_at: 12,
        };
        let messages = vec![
            message(
                "message:received-1",
                remote_device_id,
                MessageType::MlsApplication,
                10,
                Some("one"),
            ),
            message(
                "message:received-2",
                remote_device_id,
                MessageType::MlsApplication,
                10,
                Some("two"),
            ),
            message(
                "message:sent",
                local_device_id,
                MessageType::MlsApplication,
                11,
                Some("local"),
            ),
            message(
                "message:commit",
                remote_device_id,
                MessageType::MlsCommit,
                12,
                None,
            ),
            message(
                "message:group-control",
                remote_device_id,
                MessageType::ControlConversationNeedsRebuild,
                13,
                Some("control_group_dissolved"),
            ),
        ];
        let last_message_type = messages.last().map(|value| value.message_type);
        let state = crate::conversation::LocalConversationState {
            conversation: conversation.clone(),
            messages,
            last_message_type,
            peer_user_id: "user:bob".into(),
            last_known_peer_active_devices: [remote_device_id.to_string()].into_iter().collect(),
            recovery_status: crate::conversation::RecoveryStatus::Healthy,
            archive_metadata: None,
            pcs: Default::default(),
        };
        store
            .save_snapshot(&CorePersistenceSnapshot {
                conversations: vec![PersistedConversation {
                    conversation_id: conversation_id.clone(),
                    state,
                }],
                ..CorePersistenceSnapshot::default()
            })
            .expect("save conversation");

        assert_eq!(
            store
                .count_received_visible_messages(
                    &conversation_id,
                    local_device_id,
                    ConversationKind::Direct,
                    None,
                )
                .expect("count all"),
            2
        );
        assert_eq!(
            store
                .count_received_visible_messages(
                    &conversation_id,
                    local_device_id,
                    ConversationKind::Direct,
                    Some(&MessageReadCursor {
                        created_at: 10,
                        message_id: "message:received-1".into(),
                    }),
                )
                .expect("count after cursor"),
            1
        );
        assert_eq!(
            store
                .count_received_visible_messages(
                    &conversation_id,
                    local_device_id,
                    ConversationKind::Group,
                    None,
                )
                .expect("count group-visible messages"),
            3
        );
        assert_eq!(
            store
                .latest_visible_message_cursor(&conversation_id, ConversationKind::Direct)
                .expect("latest cursor"),
            Some(MessageReadCursor {
                created_at: 11,
                message_id: "message:sent".into(),
            })
        );
        assert_eq!(
            store
                .visible_message_cursor(
                    &conversation_id,
                    "app:message:received-2",
                    ConversationKind::Direct,
                )
                .expect("logical message cursor"),
            Some(MessageReadCursor {
                created_at: 10,
                message_id: "message:received-2".into(),
            })
        );
    }
}

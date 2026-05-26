use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::conversation::StoredMessage;
use crate::ffi_api::PersistStateEffect;
use crate::fs_util::write_atomic_unique;
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

const CORE_SNAPSHOT_DOCUMENT: &str = "core-snapshot";
const DB_KEY_DOCUMENT_KIND: &str = "state-db";
const SCHEMA_VERSION: u32 = 1;
const SCHEMA_VERSION_KEY: &str = "schema_version";
const MIGRATION_COMPLETE_KEY: &str = "migration_complete";
const JSON_TABLES: &[&str] = &[
    "identity",
    "deployment",
    "contacts",
    "conversations",
    "messages",
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
struct PersistedMessageRow {
    conversation_id: String,
    message: StoredMessage,
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
}

impl LocalStore for SqlCipherLocalStore<'_> {
    fn load_snapshot(&self) -> Result<CorePersistenceSnapshot> {
        let conn = self.connect()?;
        ensure_schema(&conn)?;

        let has_tables = conn
            .query_row(
                "SELECT 1 FROM state_meta WHERE key = 'message_nonce' LIMIT 1",
                [],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !has_tables {
            return match self.load_document(CORE_SNAPSHOT_DOCUMENT)? {
                Some(bytes) => decode_snapshot(&bytes).map_err(anyhow::Error::from),
                None => Ok(CorePersistenceSnapshot::default()),
            };
        }

        let mut conversations: Vec<PersistedConversation> = load_table(&conn, "conversations")?;
        let mut messages_by_conversation: BTreeMap<String, Vec<StoredMessage>> = BTreeMap::new();
        for row in load_table::<PersistedMessageRow>(&conn, "messages")? {
            messages_by_conversation
                .entry(row.conversation_id)
                .or_default()
                .push(row.message);
        }
        for conversation in &mut conversations {
            conversation.state.messages = messages_by_conversation
                .remove(&conversation.conversation_id)
                .unwrap_or_default();
        }

        Ok(CorePersistenceSnapshot {
            message_nonce: load_meta_u64(&conn, "message_nonce")?.unwrap_or_default(),
            local_display_name: load_meta_string(&conn, "local_display_name")?,
            local_identity: load_singleton(&conn, "identity", "local")?,
            deployment: load_singleton(&conn, "deployment", "active")?,
            contacts: load_table(&conn, "contacts")?,
            conversations,
            sync_states: load_table(&conn, "sync_checkpoints")?,
            mls_states: load_table(&conn, "mls_states")?,
            pending_outbox: load_table(&conn, "pending_outbox")?,
            group_states: load_table(&conn, "group_states")?,
            group_cursors: load_table(&conn, "group_cursors")?,
            pending_group_outbox: load_table(&conn, "pending_group_outbox")?,
            pending_group_seal: load_table(&conn, "pending_group_seal")?,
            group_invites: load_table(&conn, "group_invites")?,
            group_join_requests: load_table(&conn, "group_join_requests")?,
            pending_group_join_approvals: load_table(&conn, "pending_group_join_approvals")?,
            pending_welcome_pickups: load_table(&conn, "pending_welcome_pickups")?,
            pending_acks: load_table(&conn, "pending_acks")?,
            pending_blob_transfers: load_table(&conn, "pending_blob_transfers")?,
            recovery_contexts: load_table(&conn, "recovery_contexts")?,
            realtime_sessions: load_table(&conn, "realtime_sessions")?,
            group_realtime_sessions: load_table(&conn, "group_realtime_sessions")?,
            mls_state_persistence_blocked: load_meta_bool(&conn, "mls_state_persistence_blocked")?
                .unwrap_or_default(),
        })
    }

    fn save_snapshot(&self, snapshot: &CorePersistenceSnapshot) -> Result<()> {
        let mut conn = self.connect()?;
        ensure_schema(&conn)?;
        let tx = conn.transaction()?;
        save_snapshot_tables(&tx, snapshot)?;
        let encoded = encode_snapshot(snapshot).map_err(anyhow::Error::from)?;
        save_document_in_tx(&tx, CORE_SNAPSHOT_DOCUMENT, &encoded)?;
        tx.commit()?;
        Ok(())
    }

    fn persist_state(&self, persist: &PersistStateEffect) -> Result<()> {
        let Some(snapshot) = persist.snapshot.as_ref() else {
            return Ok(());
        };
        if persist.ops.is_empty() {
            return self.save_snapshot(snapshot);
        }

        let mut conn = self.connect()?;
        ensure_schema(&conn)?;
        let tx = conn.transaction()?;
        save_snapshot_meta(&tx, snapshot)?;
        apply_persist_ops(&tx, snapshot, &persist.ops)?;
        let encoded = encode_snapshot(snapshot).map_err(anyhow::Error::from)?;
        save_document_in_tx(&tx, CORE_SNAPSHOT_DOCUMENT, &encoded)?;
        tx.commit()?;
        Ok(())
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
        let mut stmt =
            conn.prepare("SELECT value FROM attachment_blobs ORDER BY updated_at_ms DESC, key")?;
        let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut values = Vec::new();
        for row in rows {
            values.push(row?);
        }
        Ok(values)
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
         PRAGMA journal_mode = DELETE;",
        hex_encode(&*key)
    ))
    .context("configure SQLCipher key")?;
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .context("verify SQLCipher database key")?;
    Ok(conn)
}

fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS schema_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        INSERT OR IGNORE INTO schema_meta(key, value)
        VALUES ('schema_version', '1');
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
        CREATE TABLE IF NOT EXISTS conversations (key TEXT PRIMARY KEY, value BLOB NOT NULL, position INTEGER NOT NULL DEFAULT 0, updated_at_ms INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS messages (key TEXT PRIMARY KEY, value BLOB NOT NULL, position INTEGER NOT NULL DEFAULT 0, updated_at_ms INTEGER NOT NULL DEFAULT 0);
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
    let version = load_schema_version(conn)?;
    if version != SCHEMA_VERSION {
        anyhow::bail!(
            "unsupported local store schema version {version}; expected {SCHEMA_VERSION}"
        );
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
            | PersistedPendingBlobTransfer::Download { task_id, .. } => task_id.clone(),
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
                        insert_conversation(tx, conversation, position)?;
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
    tx.execute(
        "DELETE FROM messages WHERE key LIKE ?1",
        params![format!("{conversation_id}::%")],
    )?;
    Ok(())
}

fn pending_welcome_pickup_key(group_id: &str, device_id: &str) -> String {
    format!("{group_id}::{device_id}")
}

fn pending_blob_transfer_key(item: &PersistedPendingBlobTransfer) -> String {
    match item {
        PersistedPendingBlobTransfer::Upload { task_id, .. }
        | PersistedPendingBlobTransfer::Download { task_id, .. } => task_id.clone(),
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
        insert_conversation(tx, value, position)?;
    }
    Ok(())
}

fn insert_conversation(
    tx: &Transaction<'_>,
    conversation: &PersistedConversation,
    position: usize,
) -> Result<()> {
    let mut conversation_row = conversation.clone();
    conversation_row.state.messages.clear();
    insert_json(
        tx,
        "conversations",
        &conversation.conversation_id,
        position,
        &conversation_row,
    )?;
    save_conversation_messages(tx, conversation)?;
    Ok(())
}

fn save_conversation_messages(
    tx: &Transaction<'_>,
    conversation: &PersistedConversation,
) -> Result<()> {
    tx.execute(
        "DELETE FROM messages WHERE key LIKE ?1",
        params![format!("{}::%", conversation.conversation_id)],
    )?;
    for (position, message) in conversation.state.messages.iter().enumerate() {
        let row = PersistedMessageRow {
            conversation_id: conversation.conversation_id.clone(),
            message: message.clone(),
        };
        insert_json(
            tx,
            "messages",
            &message_key(&conversation.conversation_id, &message.message_id),
            position,
            &row,
        )?;
    }
    Ok(())
}

fn message_key(conversation_id: &str, message_id: &str) -> String {
    format!("{conversation_id}::{message_id}")
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
    fn persist_state_applies_incremental_ops_transactionally() {
        let dir = tempdir().expect("tempdir");
        let pdek = generate_pdek();
        let store = SqlCipherLocalStore::new(dir.path(), "profile:test", &*pdek);
        let before = sample_snapshot("device:alice:phone", 1);
        store.save_snapshot(&before).expect("save before");

        let after = sample_snapshot("device:alice:phone", 2);
        store
            .persist_state(&PersistStateEffect {
                ops: vec![PersistOp::SaveRealtimeSession {
                    device_id: "device:alice:phone".into(),
                }],
                snapshot: Some(after.clone()),
            })
            .expect("persist op");

        assert_eq!(store.load_snapshot().expect("load after"), after);
    }
}

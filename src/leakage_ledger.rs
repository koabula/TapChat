//! Mechanical enumeration of the surface an untrusted host observes.
//!
//! The leakage tables in the write-up (`tab:inbox` for `L_ibx`, the storage
//! section for `L_stg`) are claims about what a host can see. Twice those
//! claims were wrong in the same way: a field existed in the wire format,
//! nobody counted it, and it was recovered only on retrospective review — a
//! plaintext certificate base64'd into `inline_ciphertext`, and the four
//! identifiers baked into the storage object key. A third manual pass found
//! three more, including that `conversation_id` is a plaintext concatenation
//! of both parties' user ids.
//!
//! Re-reading the types by eye a fourth time has no reason to work better, so
//! this module derives the surface from the code and compares it against
//! `contracts/leakage-ledger.json`. That file is the recorded decision; a
//! mismatch in either direction fails:
//!
//! * a path present in the code but not the ledger is an unrecorded leak;
//! * a path in the ledger but absent from the code means the write-up
//!   overstates the leakage.
//!
//! Two properties carry the weight, and both come from the compiler rather
//! than from diligence:
//!
//! 1. **Exhaustive struct literals.** The fixtures name every field, so adding
//!    a field to a wire type fails to compile. This works only because no
//!    in-scope wire type has a `Default` impl — never introduce
//!    `..Default::default()` into a fixture, it would silently reopen the hole.
//! 2. **Exhaustive matches.** `payload_class` matches every `MessageType`, so
//!    a new variant fails to compile until its payload confidentiality is
//!    declared.
//!
//! The limits are real and recorded in the ledger header. Chief among them:
//! this checks *substring containment*, so a leak that is a hash or a size
//! bucket of a secret passes clean.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use serde::Deserialize;
use serde_json::Value;

const LEDGER_JSON: &str = include_str!("../contracts/leakage-ledger.json");

/// How a `MessageType`'s `inline_ciphertext` payload is protected.
///
/// `build_envelope` does not encrypt payloads, so this is a property of the
/// producer, not of the transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PayloadClass {
    /// MLS frame. The payload is ciphertext but the PrivateMessage header
    /// (group_id, epoch, content_type) is not, and is searched after base64
    /// decoding like everything else.
    Opaque,
    /// Base64 of `serde_json` output using the struct's own field names, which
    /// are snake_case (the struct carries no `rename_all`).
    Base64JsonSnake,
    /// Base64 of `serde_json` output with `rename_all = "camelCase"`.
    Base64JsonCamel,
    /// Base64 of a hand-formatted ASCII string.
    Base64Ascii,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Bits {
    /// Takes at least two distinct values across the corpus.
    Inhabited,
    /// Always serialized, always the same value. `value` is then required.
    Constant,
    /// Structurally present (an `Option`/`Vec` with `skip_serializing_if`) but
    /// never populated by any producer.
    Absent,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Entry {
    pub(crate) surface: String,
    pub(crate) path: String,
    pub(crate) bits: Bits,
    #[serde(default)]
    pub(crate) value: Option<String>,
    #[serde(default)]
    pub(crate) carries: Vec<String>,
    pub(crate) signed: bool,
    pub(crate) table: String,
    /// Prose for a human reading the ledger. Declared so `deny_unknown_fields`
    /// accepts it; nothing machine-checks prose.
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Visibility {
    /// Must never appear anywhere in the host-visible corpus.
    Confidential,
    /// Also present in the cleartext header, so carrying it inside the
    /// ciphertext leaks nothing further. Recorded so the claim is explicit.
    DuplicatedInHeader,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct ProtectedField {
    pub(crate) field: String,
    pub(crate) visibility: Visibility,
    /// Prose for a human reading the ledger. Declared so `deny_unknown_fields`
    /// accepts it; nothing machine-checks prose.
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) note: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Sentinels {
    /// Values a test may choose freely.
    pub(crate) literal: Vec<String>,
    /// Values derived by the implementation (key fingerprints, ids built by
    /// `format!`), captured at runtime rather than chosen.
    pub(crate) captured: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct ExcludedSurface {
    pub(crate) surface: String,
    pub(crate) reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct NonSyntactic {
    pub(crate) channel: String,
    pub(crate) checked: bool,
    /// Prose for a human reading the ledger. Declared so `deny_unknown_fields`
    /// accepts it; nothing machine-checks prose.
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) note: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Scope {
    /// Declared so `deny_unknown_fields` accepts them, and so the scope of the
    /// enumeration is stated where the data lives rather than in a comment
    /// somewhere else. `excluded_route_prefixes` and `internal_path_matchers`
    /// are consumed by the worker-side checks in
    /// `services/cloudflare/test/leakage-ledger.test.ts`, which reads this same
    /// file — they are not dead, just read from the other language.
    #[allow(dead_code)]
    pub(crate) modeled: Vec<String>,
    #[allow(dead_code)]
    pub(crate) note: String,
    pub(crate) excluded_surfaces: Vec<ExcludedSurface>,
    #[allow(dead_code)]
    pub(crate) excluded_route_prefixes: Vec<String>,
    #[allow(dead_code)]
    pub(crate) internal_path_matchers: Vec<String>,
    pub(crate) non_syntactic_leakage: Vec<NonSyntactic>,
    pub(crate) limits: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Ledger {
    pub(crate) version: u32,
    pub(crate) scope: Scope,
    pub(crate) tables: BTreeMap<String, String>,
    pub(crate) sentinels: Sentinels,
    pub(crate) inline_ciphertext: BTreeMap<String, PayloadClass>,
    pub(crate) entries: Vec<Entry>,
    pub(crate) protected_fields: Vec<ProtectedField>,
    /// Wire types deliberately left out of `entries`, each bucket carrying the
    /// reason. Together with the types the fixtures enumerate, these must
    /// partition every `pub struct`/`pub enum` in the wire modules — see
    /// `every_wire_type_is_classified`.
    ///
    /// Field-level completeness is free (exhaustive struct literals), but
    /// *type*-level completeness is not: a new type that never gets a fixture
    /// would otherwise leave the whole mechanism silent, which is the shape of
    /// both original misses.
    pub(crate) not_enumerated: BTreeMap<String, NotEnumerated>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct NotEnumerated {
    pub(crate) reason: String,
    pub(crate) types: Vec<String>,
}

impl Ledger {
    /// Deserialization *is* the schema check: `deny_unknown_fields` plus the
    /// enum-typed fields reject a malformed ledger, so no separate validator
    /// script is needed.
    pub(crate) fn load() -> Self {
        serde_json::from_str(LEDGER_JSON).expect("contracts/leakage-ledger.json must parse")
    }

    pub(crate) fn paths_for(&self, surface: &str) -> BTreeSet<String> {
        self.entries
            .iter()
            .filter(|entry| entry.surface == surface)
            .map(|entry| entry.path.clone())
            .collect()
    }

    pub(crate) fn entry(&self, surface: &str, path: &str) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|entry| entry.surface == surface && entry.path == path)
    }
}

/// Flatten a JSON value to its leaf paths. Arrays collapse to `field[]`, so the
/// path set does not depend on how many elements a fixture happens to carry.
pub(crate) fn leaf_paths(value: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    walk(value, "", &mut |path, _| {
        out.insert(path.to_string());
    });
    out
}

/// Leaf paths whose scalar value contains `needle`.
///
/// Numbers and booleans are stringified before searching: a captured sentinel
/// can be a numeric nonce, which a string-only search would hide.
pub(crate) fn occurrences(value: &Value, needle: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if needle.is_empty() {
        return out;
    }
    walk(value, "", &mut |path, leaf| {
        let haystack = match leaf {
            Value::String(text) => text.clone(),
            Value::Number(number) => number.to_string(),
            Value::Bool(flag) => flag.to_string(),
            Value::Null => return,
            // Containers never reach the visitor.
            Value::Object(_) | Value::Array(_) => return,
        };
        if haystack.contains(needle) {
            out.insert(path.to_string());
            return;
        }
        // Base64 alignment shifts with offset, so a sentinel inside a decoded
        // payload is not a substring of the JSON leaf. Search after decode.
        if matches!(leaf, Value::String(_)) {
            let (bytes, parsed) = decode_inline(&haystack);
            if String::from_utf8_lossy(&bytes).contains(needle) {
                out.insert(path.to_string());
                return;
            }
            if let Some(json) = parsed.as_ref() {
                if !occurrences(json, needle).is_empty() {
                    out.insert(path.to_string());
                }
            }
        }
    });
    out
}

fn walk(value: &Value, prefix: &str, visit: &mut impl FnMut(&str, &Value)) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                walk(child, &path, visit);
            }
        }
        Value::Array(items) => {
            let path = format!("{prefix}[]");
            for child in items {
                walk(child, &path, visit);
            }
        }
        leaf => visit(prefix, leaf),
    }
}

/// Decode an `inline_ciphertext` payload for sentinel searching.
///
/// Returns the decoded bytes and, when the payload is structured JSON, its
/// parsed form. **Both are searched even for [`PayloadClass::Opaque`]**: a
/// base64'd sentinel is not a substring of the serialized envelope, because
/// base64 alignment shifts with offset. Searching only the outer JSON would
/// have missed every cleartext control payload — precisely the class of leak
/// this module exists to catch.
pub(crate) fn decode_inline(payload: &str) -> (Vec<u8>, Option<Value>) {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(payload)
        .unwrap_or_else(|_| payload.as_bytes().to_vec());
    let parsed = serde_json::from_slice::<Value>(&bytes).ok();
    (bytes, parsed)
}

/// Names of the sentinels that appear inside a decoded payload.
pub(crate) fn sentinels_in_payload(
    payload: &str,
    bindings: &BTreeMap<String, String>,
) -> BTreeSet<String> {
    let (bytes, parsed) = decode_inline(payload);
    let text = String::from_utf8_lossy(&bytes).to_string();
    let mut found = BTreeSet::new();
    for (name, value) in bindings {
        if value.is_empty() {
            continue;
        }
        if text.contains(value.as_str()) {
            found.insert(name.clone());
            continue;
        }
        if let Some(json) = parsed.as_ref() {
            if !occurrences(json, value).is_empty() {
                found.insert(name.clone());
            }
        }
    }
    found
}

/// A *maximal* protected application message, for the confidentiality boundary
/// check. Exhaustive literal: a new field must be classified before it compiles.
pub(crate) fn maximal_protected_message() -> crate::model::ProtectedAppMessage {
    use crate::model::{ProtectedAppMessage, ProtectedPayloadKind, CURRENT_MODEL_VERSION};

    ProtectedAppMessage {
        version: CURRENT_MODEL_VERSION.to_string(),
        app_message_id: format!("app:conv:x:{}:device:y", sentinel::MESSAGE_NONCE),
        conversation_id: "conv:x".to_string(),
        sender_user_id: format!("user:{}", sentinel::SENDER_USER_FP),
        sender_device_id: format!(
            "device:{}:{}",
            sentinel::SENDER_USER_FP,
            sentinel::SENDER_DEVICE_FP
        ),
        recipient_user_id: format!("user:{}", sentinel::RECIPIENT_USER_FP),
        audience_device_ids: vec![format!(
            "device:{}:{}",
            sentinel::RECIPIENT_USER_FP,
            sentinel::RECIPIENT_DEVICE_FP
        )],
        payload_kind: ProtectedPayloadKind::Text,
        body: sentinel::PLAINTEXT_BODY.to_string(),
    }
}

/// Replace the scalar at `path` with a distinguishable value, in place.
///
/// Used to prove that a field the ledger marks `signed` really is covered by
/// the sender-proof domain. Returns whether the path was found.
pub(crate) fn mutate_at(value: &mut Value, path: &str) -> bool {
    let (head, rest) = match path.split_once('.') {
        Some((head, rest)) => (head, Some(rest)),
        None => (path, None),
    };
    let (key, is_array) = match head.strip_suffix("[]") {
        Some(key) => (key, true),
        None => (head, false),
    };
    let Some(child) = value.get_mut(key) else {
        return false;
    };
    let targets: Vec<&mut Value> = if is_array {
        match child.as_array_mut() {
            Some(items) => items.iter_mut().collect(),
            None => return false,
        }
    } else {
        vec![child]
    };
    let mut touched = false;
    for target in targets {
        match rest {
            Some(rest) => touched |= mutate_at(target, rest),
            None => {
                match target {
                    Value::String(text) => *text = format!("{text}-mutated"),
                    Value::Number(number) => {
                        *target = Value::from(number.as_u64().unwrap_or(0).wrapping_add(1))
                    }
                    Value::Bool(flag) => *target = Value::Bool(!*flag),
                    // A single-variant enum has nothing to mutate to; the
                    // caller skips these and the ledger records why.
                    _ => return false,
                }
                touched = true;
            }
        }
    }
    touched
}

/// Every `pub struct` / `pub enum` declared in a Rust source file.
///
/// A deliberately dumb textual scan, matching existing practice in this repo
/// (`scripts/check-tauri-command-errors.mjs` hand-scans Rust with `indexOf`).
/// It only needs to be complete, not clever: over-reporting a type forces an
/// explicit classification, which is the desired direction of failure.
pub(crate) fn declared_wire_types(source: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in source.lines() {
        let line = line.trim();
        for keyword in ["pub struct ", "pub enum "] {
            if let Some(rest) = line.strip_prefix(keyword) {
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !name.is_empty() {
                    out.insert(name);
                }
            }
        }
    }
    out
}

/// Sentinel values. Ten alphanumeric characters, embedded in otherwise
/// constant scaffolding.
///
/// Alphanumeric is not cosmetic: `endpoint` fields are percent-encoded
/// (`.../inbox/device%3A.../allowlist`), so a sentinel containing `:` would be
/// invisible at exactly the places worth checking.
///
/// The *shape* of an identifier cannot be chosen. `user_id` is
/// `format!("user:{}", fingerprint(pubkey))` and `device_id` is
/// `format!("device:{user_fp}:{device_fp}")` (`src/identity/mod.rs`), both key
/// fingerprints, and device keys are random — so ids are not even stable
/// across runs. These constants stand in for the fingerprint portion, and the
/// engine-driven checks capture the real values at runtime instead.
pub(crate) mod sentinel {
    pub(crate) const SENDER_USER_FP: &str = "ZQ7X2M1PDA";
    pub(crate) const RECIPIENT_USER_FP: &str = "TP6YB3HSLM";
    pub(crate) const SENDER_DEVICE_FP: &str = "K4N8VR2WQJ";
    pub(crate) const RECIPIENT_DEVICE_FP: &str = "D9WFC5XKQZ";
    pub(crate) const PLAINTEXT_BODY: &str = "M2JQ8NVTXR";
    pub(crate) const ATTACHMENT_FILE_NAME: &str = "F7RKD4XNPW";
    pub(crate) const GROUP_TITLE: &str = "G3HLW8QTYB";
    pub(crate) const DISPLAY_NAME: &str = "N5VPX2CJRK";
    pub(crate) const MESSAGE_NONCE: u64 = 8_675_309;
}

/// Bind sentinel names to the bare tokens to search for.
///
/// Bind the **token**, never the scaffolded id. `device:A:B` is percent-encoded
/// to `device%3AA%3AB` inside `endpoint` fields, so searching for the assembled
/// id reports "clean" at exactly the places worth checking; searching for `B`
/// finds it either way.
///
/// A consequence falls out that the hand enumeration missed: because
/// `device_id` is `format!("device:{user_fp}:{device_fp}")`, **every device id
/// transitively names its user**. So `sender_device` sites also report
/// `sender_user`, and removing `sender_user_id` from the envelope while keeping
/// `sender_device_id` would not stop naming the sender.
pub(crate) fn fixture_bindings() -> BTreeMap<String, String> {
    [
        ("sender_user", sentinel::SENDER_USER_FP),
        ("recipient_user", sentinel::RECIPIENT_USER_FP),
        ("sender_device", sentinel::SENDER_DEVICE_FP),
        ("recipient_device", sentinel::RECIPIENT_DEVICE_FP),
        ("attachment_file_name", sentinel::ATTACHMENT_FILE_NAME),
        ("plaintext_body", sentinel::PLAINTEXT_BODY),
        ("group_title", sentinel::GROUP_TITLE),
        ("display_name", sentinel::DISPLAY_NAME),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_string(), value.to_string()))
    .chain(std::iter::once((
        "message_nonce".to_string(),
        sentinel::MESSAGE_NONCE.to_string(),
    )))
    .collect()
}

/// A *maximal* append request: every `Option` is `Some` and every `Vec` is
/// non-empty.
///
/// Maximality is required, not tidiness. `inline_ciphertext`, `storage_refs`,
/// `file_name` and `expires_at` all carry `skip_serializing_if`, so leaving any
/// of them empty silently removes paths from the enumeration — the check would
/// then pass while claiming to have seen a surface it never saw.
///
/// The struct literals below are exhaustive on purpose: adding a field to any
/// of these types must fail to compile here. Never relax one with
/// `..Default::default()`.
pub(crate) fn maximal_append_request() -> crate::transport_contract::AppendEnvelopeRequest {
    use crate::model::{
        DeliveryClass, Envelope, MessageType, SenderProof, StorageRef, CURRENT_MODEL_VERSION,
    };

    let sender_user_id = format!("user:{}", sentinel::SENDER_USER_FP);
    let recipient_user_id = format!("user:{}", sentinel::RECIPIENT_USER_FP);
    let sender_device_id = format!(
        "device:{}:{}",
        sentinel::SENDER_USER_FP,
        sentinel::SENDER_DEVICE_FP
    );
    let recipient_device_id = format!(
        "device:{}:{}",
        sentinel::RECIPIENT_USER_FP,
        sentinel::RECIPIENT_DEVICE_FP
    );

    // Derived by the real implementation rather than hand-written, so that a
    // change to the derivation shows up here instead of being mirrored.
    let conversation_id =
        crate::conversation::direct_conversation_id(&sender_user_id, &recipient_user_id);
    let message_id = format!(
        "msg:{conversation_id}:{}:{recipient_device_id}",
        sentinel::MESSAGE_NONCE
    );

    let envelope = Envelope {
        version: CURRENT_MODEL_VERSION.to_string(),
        message_id,
        conversation_id: conversation_id.clone(),
        sender_user_id,
        sender_device_id,
        recipient_device_id,
        created_at: 1_775_000_000_000,
        message_type: MessageType::MlsApplication,
        inline_ciphertext: Some(representative_mls_frame(&conversation_id)),
        storage_refs: vec![StorageRef {
            kind: "attachment_original".to_string(),
            object_ref: format!(
                "blobs/original/user:{}/device:{}:{}/direct/direct/conv/msg-task",
                sentinel::SENDER_USER_FP,
                sentinel::SENDER_USER_FP,
                sentinel::SENDER_DEVICE_FP
            ),
            size_bytes: 4096,
            mime_type: "application/octet-stream".to_string(),
            file_name: Some(sentinel::ATTACHMENT_FILE_NAME.to_string()),
            expires_at: Some(1_777_000_000_000),
        }],
        delivery_class: DeliveryClass::Normal,
        sender_proof: SenderProof {
            proof_type: "signature".to_string(),
            value: "c2lnbmF0dXJl".to_string(),
        },
    };

    crate::transport_contract::AppendEnvelopeRequest {
        version: CURRENT_MODEL_VERSION.to_string(),
        recipient_device_id: envelope.recipient_device_id.clone(),
        envelope,
        sender_bundle_share_url: Some(
            "https://runtime.example/v1/contact-share/abcdef".to_string(),
        ),
        sender_bundle_hash: Some("f".repeat(64)),
        sender_display_name: Some(sentinel::DISPLAY_NAME.to_string()),
    }
}

/// RFC 9420 §6.3 MLSMessage wrapping a PrivateMessage. Existence proof:
/// `mls_frame_header_names_the_conversation_in_the_clear` in mls_adapter.
fn representative_mls_frame(conversation_id: &str) -> String {
    fn push_vlbytes(out: &mut Vec<u8>, bytes: &[u8]) {
        let len = bytes.len();
        if len < 64 {
            out.push(len as u8);
        } else {
            let encoded = 0x4000 | (len as u16);
            out.extend_from_slice(&encoded.to_be_bytes());
        }
        out.extend_from_slice(bytes);
    }
    let mut frame = Vec::new();
    frame.extend_from_slice(&1u16.to_be_bytes()); // version: mls10
    frame.extend_from_slice(&2u16.to_be_bytes()); // wire_format: mls_private_message
    push_vlbytes(&mut frame, conversation_id.as_bytes());
    frame.extend_from_slice(&3u64.to_be_bytes()); // epoch
    frame.push(1); // content_type: application
    push_vlbytes(&mut frame, &[]);
    push_vlbytes(&mut frame, &[0xA1; 16]);
    push_vlbytes(&mut frame, &[0xC3; 32]);
    base64::engine::general_purpose::STANDARD.encode(frame)
}

/// The other client-to-host request bodies on the inbox and storage paths.
///
/// Same exhaustiveness rule as [`maximal_append_request`]: every literal names
/// every field, so a new field fails to compile here.
pub(crate) fn inbox_path_surfaces() -> Vec<(&'static str, Value)> {
    use crate::model::Ack;
    use crate::transport_contract::{
        AckRequest, AllowlistDocument, FetchMessagesRequest, MessageRequestAction,
        MessageRequestActionRequest, PrepareBlobUploadRequest, ReplaceAllowlistRequest,
        TransportAuthRequirement,
    };
    use std::collections::BTreeMap;

    let recipient_device_id = format!(
        "device:{}:{}",
        sentinel::RECIPIENT_USER_FP,
        sentinel::RECIPIENT_DEVICE_FP
    );
    let sender_user_id = format!("user:{}", sentinel::SENDER_USER_FP);
    let recipient_user_id = format!("user:{}", sentinel::RECIPIENT_USER_FP);
    let conversation_id =
        crate::conversation::direct_conversation_id(&sender_user_id, &recipient_user_id);

    let auth = Some(TransportAuthRequirement::DeviceRuntime {
        runtime_id: "runtime:example".to_string(),
        device_id: recipient_device_id.clone(),
    });

    vec![
        (
            "ack_request",
            host_view(&AckRequest {
                ack: Ack {
                    device_id: recipient_device_id.clone(),
                    ack_seq: 42,
                    // Non-empty on purpose: this carries message ids, which
                    // carry the conversation id, which names both parties.
                    acked_message_ids: vec![format!(
                        "msg:{conversation_id}:{}:{recipient_device_id}",
                        sentinel::MESSAGE_NONCE
                    )],
                    acked_at: 1_775_000_000_000,
                },
            }),
        ),
        (
            "fetch_messages_request",
            host_view(&FetchMessagesRequest {
                device_id: recipient_device_id.clone(),
                from_seq: 1,
                limit: 100,
            }),
        ),
        (
            "replace_allowlist_request",
            host_view(&ReplaceAllowlistRequest {
                device_id: recipient_device_id.clone(),
                endpoint: format!(
                    "https://runtime.example/v1/inbox/{}/allowlist",
                    urlencoding_colon(&recipient_device_id)
                ),
                headers: BTreeMap::new(),
                auth: auth.clone(),
                document: AllowlistDocument {
                    allowed_sender_user_ids: vec![sender_user_id.clone()],
                    rejected_sender_user_ids: vec![format!("user:{}", sentinel::RECIPIENT_USER_FP)],
                },
            }),
        ),
        (
            "message_request_action_request",
            host_view(&MessageRequestActionRequest {
                device_id: recipient_device_id.clone(),
                request_id: format!("request:{sender_user_id}"),
                action: MessageRequestAction::Accept,
                endpoint: "https://runtime.example/v1/inbox/d/message-requests/r/accept"
                    .to_string(),
                headers: BTreeMap::new(),
                auth: auth.clone(),
            }),
        ),
        (
            "prepare_blob_upload_request",
            host_view(&PrepareBlobUploadRequest {
                task_id: "task-1".to_string(),
                conversation_id: conversation_id.clone(),
                message_id: format!(
                    "msg:{conversation_id}:{}:{recipient_device_id}",
                    sentinel::MESSAGE_NONCE
                ),
                variant: "original".to_string(),
                size_bytes: 4096,
                storage_scope: Some("direct".to_string()),
                group_id: Some("group:example".to_string()),
                headers: BTreeMap::new(),
                auth: auth.clone(),
            }),
        ),
    ]
}

/// Percent-encode `:` the way the endpoint builders do, so a sentinel embedded
/// in a device id stays findable in this fixture.
fn urlencoding_colon(value: &str) -> String {
    value.replace(':', "%3A")
}

/// The host-visible (camelCase) rendering of a wire value.
///
/// The core emits snake_case in `HttpRequestEffect.body`; the platform driver
/// converts before sending (`src/cli/driver.rs`). The ledger describes what the
/// host receives, so the conversion has to happen before enumeration.
pub(crate) fn host_view<T: serde::Serialize>(value: &T) -> Value {
    crate::transport_contract::json_case::snake_to_camel_value(
        serde_json::to_value(value).expect("wire types must serialize"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ledger parses, and its cross-references resolve.
    ///
    /// Deserialization already enforces the schema; this covers the parts
    /// serde cannot express.
    #[test]
    fn ledger_is_internally_consistent() {
        let ledger = Ledger::load();
        assert_eq!(ledger.version, 1, "ledger version");
        assert!(
            !ledger.scope.limits.is_empty(),
            "scope.limits must record what this mechanism cannot see"
        );

        let declared: BTreeSet<&str> = ledger
            .sentinels
            .literal
            .iter()
            .chain(ledger.sentinels.captured.iter())
            .map(String::as_str)
            .collect();

        for entry in &ledger.entries {
            assert!(
                ledger.tables.contains_key(&entry.table),
                "{}:{} names table {:?}, which is not declared in `tables`",
                entry.surface,
                entry.path,
                entry.table
            );
            for sentinel in &entry.carries {
                assert!(
                    declared.contains(sentinel.as_str()),
                    "{}:{} carries {:?}, which is not a declared sentinel",
                    entry.surface,
                    entry.path,
                    sentinel
                );
            }
            match entry.bits {
                Bits::Constant => assert!(
                    entry.value.is_some(),
                    "{}:{} is `constant` but declares no `value`; without it the \
                     zero-bit claim is unfalsifiable",
                    entry.surface,
                    entry.path
                ),
                Bits::Inhabited | Bits::Absent => assert!(
                    entry.value.is_none(),
                    "{}:{} declares a `value` but is not `constant`",
                    entry.surface,
                    entry.path
                ),
            }
        }

        let mut seen = BTreeSet::new();
        for entry in &ledger.entries {
            let key = format!("{}:{}", entry.surface, entry.path);
            assert!(seen.insert(key.clone()), "duplicate ledger entry {key}");
        }
    }

    /// No host-visible datum may exist without a recorded decision about where
    /// it belongs in the write-up.
    ///
    /// This is the gate the whole exercise is for. Both previous misses were
    /// not "we did not know" but "we knew and never wrote it down".
    #[test]
    fn every_entry_has_a_recorded_placement() {
        let ledger = Ledger::load();
        let unmapped: Vec<String> = ledger
            .entries
            .iter()
            .filter(|entry| entry.table == "unmapped")
            .map(|entry| format!("  {}:{}", entry.surface, entry.path))
            .collect();
        assert!(
            unmapped.is_empty(),
            "{} host-visible datum(s) have no recorded placement in the write-up.\n{}\n\
             Give each a `table` from the ledger's `tables` map, or record why it is \
             acceptable. Do not invent a placement to silence this — widening the \
             claim is a change to a published table.",
            unmapped.len(),
            unmapped.join("\n")
        );
    }

    /// Bootstrap aid: prints the observed surface so ledger entries are derived
    /// rather than transcribed. Ignored by default; run with
    /// `cargo test --lib bootstrap_dump -- --ignored --nocapture`.
    #[test]
    #[ignore = "bootstrap aid, not a check"]
    fn bootstrap_dump() {
        let bindings = fixture_bindings();
        let mut surfaces = vec![("append_request", host_view(&maximal_append_request()))];
        surfaces.extend(inbox_path_surfaces());
        for (surface, view) in &surfaces {
            for path in leaf_paths(view) {
                let carried: Vec<&str> = bindings
                    .iter()
                    .filter(|(_, value)| occurrences(view, value).contains(&path))
                    .map(|(name, _)| name.as_str())
                    .collect();
                println!("{surface}\t{path}\t{}", carried.join(","));
            }
        }
        println!("---- wire types ----");
        for name in declared_wire_types(include_str!("model/mod.rs")).union(&declared_wire_types(
            include_str!("transport_contract/mod.rs"),
        )) {
            println!("{name}");
        }
    }

    /// Every surface the fixtures build, paired with its ledger name.
    fn surfaces() -> Vec<(&'static str, Value)> {
        let mut all = vec![("append_request", host_view(&maximal_append_request()))];
        all.extend(inbox_path_surfaces());
        all
    }

    /// **Check S.** The structural path set of each surface equals the ledger.
    ///
    /// Catches a field that compiles but was never recorded — including the
    /// zero-bit constants that carry no sentinel and are therefore invisible to
    /// the sentinel check.
    #[test]
    fn surface_paths_match_the_ledger() {
        let ledger = Ledger::load();
        for (surface, view) in surfaces() {
            let observed = leaf_paths(&view);
            let declared = ledger.paths_for(surface);
            let undeclared: Vec<&String> = observed.difference(&declared).collect();
            let stale: Vec<&String> = declared.difference(&observed).collect();
            assert!(
                undeclared.is_empty(),
                "surface {surface}: {} path(s) are visible to the host but absent from \
                 contracts/leakage-ledger.json: {undeclared:?}\n\
                 Add an entry for each, with a `table` placement.",
                undeclared.len()
            );
            assert!(
                stale.is_empty(),
                "surface {surface}: the ledger declares {} path(s) the code no longer \
                 produces: {stale:?}\n\
                 Remove them - leaving them in overstates the leakage claim.",
                stale.len()
            );
        }
    }

    /// **Check X.** Each path carries exactly the sentinels the ledger declares.
    ///
    /// This is the check with teeth, and the only one that catches a derived
    /// identifier regardless of how it was derived: `conversation_id` is
    /// `conv:{userA}:{userB}` and `message_id` embeds it, so both report the
    /// user sentinels without anyone having to notice the `format!`.
    ///
    /// Measured against the *maximal* fixture, so an `absent` field reports
    /// what it WOULD carry if a producer ever populated it. That is the
    /// conservative direction: it documents the latent leak rather than hiding
    /// it behind "no producer sets this today".
    #[test]
    fn sentinels_appear_only_where_the_ledger_says() {
        let ledger = Ledger::load();
        let bindings = fixture_bindings();
        for (surface, view) in surfaces() {
            for path in leaf_paths(&view) {
                let observed: BTreeSet<String> = bindings
                    .iter()
                    .filter(|(_, value)| occurrences(&view, value).contains(&path))
                    .map(|(name, _)| name.clone())
                    .collect();
                let entry = ledger
                    .entry(surface, &path)
                    .unwrap_or_else(|| panic!("{surface}:{path} missing from the ledger"));
                let declared: BTreeSet<String> = entry.carries.iter().cloned().collect();
                assert_eq!(
                    observed, declared,
                    "{surface}:{path} carries {observed:?} but the ledger declares \
                     {declared:?}.\nA new sentinel here is an unrecorded leak. Do not \
                     simply widen `carries` to make this pass - that publishes a wider \
                     leakage claim, and it is the same failure as the two this mechanism \
                     exists to prevent."
                );
            }
        }
    }

    /// **Check V.** Every deliverable `MessageType` declares how its payload is
    /// protected, and the exhaustive match makes a new variant a compile error.
    #[test]
    fn deliverable_message_types_declare_payload_protection() {
        use crate::model::MessageType;

        // Exhaustive on purpose: a new variant must not compile until someone
        // decides whether it is deliverable and how its payload is protected.
        const ALL: [MessageType; 11] = [
            MessageType::MlsApplication,
            MessageType::MlsCommit,
            MessageType::MlsProposal,
            MessageType::MlsWelcome,
            MessageType::ControlDeviceMembershipChanged,
            MessageType::ControlIdentityStateUpdated,
            MessageType::ControlConversationNeedsRebuild,
            MessageType::ControlContactRemoved,
            MessageType::ControlContactAccepted,
            MessageType::ControlGroupWelcomePickup,
            MessageType::ControlGroupStateEvent,
        ];

        let ledger = Ledger::load();
        let declared: BTreeSet<&str> = ledger
            .inline_ciphertext
            .keys()
            .map(String::as_str)
            .collect();
        let deliverable: BTreeSet<&str> = ALL
            .iter()
            .filter(|kind| crate::ffi_api::engine::inbox_deliverable(**kind))
            .map(|kind| kind.wire_name())
            .collect();

        assert_eq!(
            declared, deliverable,
            "contracts/leakage-ledger.json must declare the payload protection of exactly \
             the inbox-deliverable message types. Four of them are cleartext today, which \
             is the same class of leak as the certificate removed in R1."
        );
    }

    /// **Check P.** The confidentiality boundary holds in both directions.
    ///
    /// Every field of `ProtectedAppMessage` is classified, and the ones marked
    /// `confidential` appear nowhere in the host-visible surface — including
    /// inside base64-decoded payloads, so a cleartext value smuggled alongside
    /// an "opaque" MLS blob would still be caught.
    #[test]
    fn protected_fields_stay_inside_the_ciphertext() {
        let ledger = Ledger::load();
        let protected = maximal_protected_message();
        let serialized = serde_json::to_value(&protected).expect("protected message");

        let declared: BTreeSet<&str> = ledger
            .protected_fields
            .iter()
            .map(|field| field.field.as_str())
            .collect();
        let actual: BTreeSet<&str> = serialized
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            actual, declared,
            "every field of ProtectedAppMessage must be classified `confidential` or \
             `duplicated_in_header`"
        );

        let confidential: Vec<&str> = ledger
            .protected_fields
            .iter()
            .filter(|field| field.visibility == Visibility::Confidential)
            .map(|field| field.field.as_str())
            .collect();
        assert!(
            !confidential.is_empty(),
            "if nothing is confidential the check is vacuous"
        );

        for (surface, view) in surfaces() {
            for name in &confidential {
                let value = serialized
                    .get(*name)
                    .and_then(|field| match field {
                        Value::String(text) => Some(text.clone()),
                        other => Some(other.to_string()),
                    })
                    .expect("confidential field present in the fixture");
                assert!(
                    occurrences(&view, &value).is_empty(),
                    "confidential field {name:?} escaped into host-visible surface \
                     {surface}"
                );
            }
        }
    }

    /// **Check `signed`.** Each path the ledger marks `signed` really is covered
    /// by the sender-proof domain, and each unsigned one really is not.
    ///
    /// This also repairs a known weakness of `every_field_is_covered` in
    /// `src/model/signing.rs`: that test drives a *hand-written* mutation list,
    /// so a newly added `Envelope` field does not fail it. Here the list comes
    /// from the ledger, whose completeness `surface_paths_match_the_ledger`
    /// guarantees.
    #[test]
    fn signed_annotations_match_the_sender_proof_domain() {
        use crate::model::{signing::envelope_sender_proof_payload, Envelope};
        use crate::transport_contract::json_case::camel_to_snake_value;

        let ledger = Ledger::load();
        let base_request = maximal_append_request();
        let base_payload = envelope_sender_proof_payload(&base_request.envelope).into_bytes();
        let mut checked = 0usize;
        let mut unprobeable: Vec<String> = Vec::new();

        for entry in &ledger.entries {
            let Some(field_path) = entry
                .path
                .strip_prefix("envelope.")
                .filter(|_| entry.surface == "append_request")
            else {
                continue;
            };
            let mut view = host_view(&base_request.envelope);
            if !mutate_at(&mut view, field_path) {
                // Single-variant enums (`deliveryClass`) have no other value to
                // take, so they cannot be probed this way.
                continue;
            }
            let Ok(mutated) = serde_json::from_value::<Envelope>(camel_to_snake_value(view)) else {
                // An enum-valued field: appending a suffix yields no valid
                // variant, so it cannot be probed this way. Recorded rather
                // than skipped silently, so a new one has to be looked at.
                unprobeable.push(field_path.to_string());
                continue;
            };
            let changed = envelope_sender_proof_payload(&mutated).into_bytes() != base_payload;
            assert_eq!(
                changed,
                entry.signed,
                "envelope.{field_path}: the ledger says signed={}, but mutating it {} the \
                 sender-proof payload. A field that drops out of the signing domain can be \
                 rewritten in transit.",
                entry.signed,
                if changed {
                    "changes"
                } else {
                    "does not change"
                }
            );
            checked += 1;
        }
        assert!(
            checked >= 10,
            "expected to probe most envelope fields, probed only {checked}"
        );
        assert_eq!(
            unprobeable,
            vec!["deliveryClass".to_string(), "messageType".to_string()],
            "these envelope fields are enum-valued, so a string mutation yields no valid              variant and their `signed` claim is unverified. Both are covered by the              hand-written domain test in src/model/signing.rs; a NEW entry here is not."
        );
    }

    /// The scope prose is part of the contract: an excluded surface without a
    /// reason, or an unchecked channel without a name, is an oversight wearing
    /// the costume of a decision.
    #[test]
    fn scope_exclusions_carry_their_reasons() {
        let ledger = Ledger::load();
        for excluded in &ledger.scope.excluded_surfaces {
            assert!(
                !excluded.surface.is_empty() && excluded.reason.len() > 20,
                "excluded surface {:?} needs a real reason",
                excluded.surface
            );
        }
        for channel in &ledger.scope.non_syntactic_leakage {
            assert!(!channel.channel.is_empty(), "unnamed non-syntactic channel");
            assert!(
                !channel.checked,
                "{} claims to be checked, but nothing here measures a non-syntactic \
                 channel; say so honestly or implement the check",
                channel.channel
            );
        }
        for bucket in ledger.not_enumerated.values() {
            assert!(
                bucket.reason.len() > 20,
                "each notEnumerated bucket needs a reason that survives review"
            );
        }
    }

    /// **The type-partition guard.**
    ///
    /// Exhaustive struct literals give *field*-level completeness for free, but
    /// not *type*-level: add a new wire type, never write a fixture, and every
    /// other check here stays green while saying nothing. That is exactly the
    /// shape of the two leaks this module exists to prevent.
    #[test]
    fn every_wire_type_is_classified() {
        // Types the fixtures above construct, directly or as a nested field.
        const ENUMERATED: [&str; 15] = [
            "AppendEnvelopeRequest",
            "Envelope",
            "StorageRef",
            "SenderProof",
            "MessageType",
            "DeliveryClass",
            "Ack",
            "AckRequest",
            "FetchMessagesRequest",
            "AllowlistDocument",
            "ReplaceAllowlistRequest",
            "MessageRequestActionRequest",
            "MessageRequestAction",
            "PrepareBlobUploadRequest",
            "TransportAuthRequirement",
        ];

        let ledger = Ledger::load();
        let mut classified: BTreeSet<String> =
            ENUMERATED.iter().map(|name| name.to_string()).collect();
        for bucket in ledger.not_enumerated.values() {
            for name in &bucket.types {
                assert!(
                    classified.insert(name.clone()),
                    "{name} is classified twice; each wire type belongs to exactly one bucket"
                );
            }
        }

        let declared = declared_wire_types(include_str!("model/mod.rs"))
            .union(&declared_wire_types(include_str!(
                "transport_contract/mod.rs"
            )))
            .cloned()
            .collect::<BTreeSet<String>>();

        let unclassified: Vec<&String> = declared.difference(&classified).collect();
        assert!(
            unclassified.is_empty(),
            "new wire type(s) {unclassified:?}: add their paths to \
             contracts/leakage-ledger.json `entries`, or list them under `notEnumerated` \
             in the bucket whose reason applies."
        );

        let vanished: Vec<&String> = classified.difference(&declared).collect();
        assert!(
            vanished.is_empty(),
            "the ledger classifies type(s) {vanished:?} that no longer exist; remove them"
        );
    }

    #[test]
    fn declared_wire_types_scans_both_keywords() {
        let source = "pub struct Alpha {\n  pub enum_like: u8,\n}\npub enum Beta { X }\n\
                      struct Private;\n    pub struct Indented<T>(T);\n";
        let found = declared_wire_types(source);
        assert!(found.contains("Alpha"));
        assert!(found.contains("Beta"));
        assert!(found.contains("Indented"));
        assert!(
            !found.contains("Private"),
            "a private type is not part of the wire surface"
        );
    }

    #[test]
    fn leaf_paths_collapses_arrays_and_nests_objects() {
        let value = serde_json::json!({
            "a": 1,
            "b": { "c": "x" },
            "d": [ { "e": 1 }, { "e": 2 } ],
        });
        let paths = leaf_paths(&value);
        assert_eq!(
            paths.iter().map(String::as_str).collect::<Vec<_>>(),
            vec!["a", "b.c", "d[].e"]
        );
    }

    #[test]
    fn occurrences_finds_numbers_and_nested_strings() {
        let value = serde_json::json!({
            "id": "msg:conv:AAA:BBB:7",
            "nonce": 7,
            "nested": { "deep": "nothing" },
        });
        assert_eq!(
            occurrences(&value, "AAA").iter().collect::<Vec<_>>(),
            vec!["id"]
        );
        let seven = occurrences(&value, "7");
        assert!(seven.contains("id"), "substring of a string leaf");
        assert!(seven.contains("nonce"), "numbers must be stringified");
    }

    /// The detail that decides whether the sentinel check works at all.
    ///
    /// Control payloads are `serde_json::to_vec` then base64 into
    /// `inline_ciphertext`. Base64 alignment shifts with offset, so a plain
    /// substring search over the serialized envelope finds nothing.
    #[test]
    fn base64_payloads_are_searched_after_decoding() {
        let secret = "ZQ7X2M1PDA";
        let payload = serde_json::json!({ "actorUserId": format!("user:{secret}") });
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&payload).expect("encode"));

        assert!(
            !encoded.contains(secret),
            "precondition: the sentinel must not survive base64 as a substring, \
             otherwise this test proves nothing"
        );

        let bindings: BTreeMap<String, String> = [("actor".to_string(), secret.to_string())]
            .into_iter()
            .collect();
        assert_eq!(
            sentinels_in_payload(&encoded, &bindings)
                .iter()
                .collect::<Vec<_>>(),
            vec!["actor"],
            "decoding must reveal the sentinel"
        );
    }

    /// A bare ASCII payload (`ControlDeviceMembershipChanged` is not even
    /// base64'd) must still be searched.
    #[test]
    fn plain_ascii_payloads_are_searched() {
        let secret = "TP6YB3HSLM";
        let payload = format!("membership_changed:conv:x:user:{secret}:2");
        let bindings: BTreeMap<String, String> = [("peer".to_string(), secret.to_string())]
            .into_iter()
            .collect();
        assert_eq!(
            sentinels_in_payload(&payload, &bindings)
                .iter()
                .collect::<Vec<_>>(),
            vec!["peer"]
        );
    }

    #[test]
    fn representative_frame_parses_as_an_mls_private_message() {
        use openmls::prelude::{tls_codec::Deserialize, MlsMessageIn, WireFormat};

        let conversation_id = "conv:user:TP6YB3HSLM:user:ZQ7X2M1PDA";
        let encoded = representative_mls_frame(conversation_id);
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("base64");
        let message = MlsMessageIn::tls_deserialize_exact(bytes).expect("mls message");
        assert_eq!(message.wire_format(), WireFormat::PrivateMessage);
        let protocol = message
            .try_into_protocol_message()
            .expect("private message");
        assert_eq!(protocol.group_id().as_slice(), conversation_id.as_bytes());
    }
}

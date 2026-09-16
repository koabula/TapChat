//! Engine-driven corpus, and the partition test that measures it.
//!
//! [`crate::leakage_ledger`] asks whether a sentinel string appears in a
//! hand-written fixture. That question is blind to any *function* of a secret:
//! a hash, a size bucket, a first byte all pass it clean. This module asks the
//! information-theoretic question instead, which is the executable form of T1
//! ("the host's view is a function of `L`"):
//!
//! > Run the real engine N times, varying one secret at a time. For each value
//! > the host can read, look at the partition it induces over the runs. Equal
//! > everywhere: it carries nothing. Determined by some set of secrets: it
//! > carries them — a hash lands here exactly like the cleartext would.
//! > Different between two runs with *identical* inputs: it is fresh.
//!
//! That last clause is why no deterministic RNG and no injected clock are
//! needed, and why not one line of engine code is touched: randomness is
//! detected rather than suppressed. The matrix carries three replicate runs
//! whose inputs are byte-identical, and anything that differs among them is
//! fresh by construction.
//!
//! **What bounds the coverage is the matrix, not the classifier.** Every run
//! input outside [`Secret`] is held fixed, so a field carrying one of them
//! measures as constant, and every run input inside it is varied, so a field
//! carrying one of them cannot hide. There is deliberately no "unexplained"
//! verdict: fixing every secret leaves only the replicate block, on which a
//! non-fresh field is constant by definition, so such a verdict would be
//! unreachable and would read as a guarantee the matrix does not give.
//!
//! §A partition algebra, §B leaf decomposition — both pure and unit-tested;
//! §C the recorder, §D the assertions.

use base64::Engine as _;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

// ---------------------------------------------------------------------------
// §A  Partition algebra
// ---------------------------------------------------------------------------

pub(crate) type RunIx = usize;

/// The equivalence classes a value induces over the runs, as blocks of run
/// indices ordered by their least member.
pub(crate) type Partition = Vec<BTreeSet<RunIx>>;

/// A run input that is varied across the matrix.
///
/// Absolute, not role-relative: the ledger says `sender_user`, which resolves
/// against the record that carries it (see `resolve_role` in §D). Role names
/// collapse on self-addressed surfaces, where the issuer *is* the inbox owner,
/// so comparing in role space would make two different claims indistinguishable.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) enum Secret {
    /// The mnemonic, hence the root key, hence `user:{fingerprint}`.
    Identity(Party),
    /// The message text this party sends.
    Body(Party),
    /// The attachment's file name.
    AttachmentName,
    /// The attachment's byte length.
    AttachmentLen,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub(crate) enum Party {
    Alice,
    Bob,
}

impl Party {
    pub(crate) fn other(self) -> Self {
        match self {
            Party::Alice => Party::Bob,
            Party::Bob => Party::Alice,
        }
    }
}

/// Group the runs by the value observed in each. `None` (the path was absent
/// that run) is a value class of its own: a field that is present only for
/// some inputs is carrying those inputs.
pub(crate) fn partition(values: &[Option<String>]) -> Partition {
    let mut groups: BTreeMap<&Option<String>, BTreeSet<RunIx>> = BTreeMap::new();
    for (ix, value) in values.iter().enumerate() {
        groups.entry(value).or_default().insert(ix);
    }
    let mut blocks: Vec<BTreeSet<RunIx>> = groups.into_values().collect();
    blocks.sort_by_key(|block| *block.iter().next().expect("no empty block"));
    blocks
}

/// `fine` refines `coarse`: every block of `fine` lies inside a block of
/// `coarse`. Equivalently — and this is how it is used — runs that agree on
/// `fine` agree on `coarse`, i.e. `coarse` is a function of `fine`.
pub(crate) fn refines(fine: &Partition, coarse: &Partition) -> bool {
    fine.iter()
        .all(|block| coarse.iter().any(|outer| block.is_subset(outer)))
}

/// The common refinement: runs land together only if they agree on every part.
pub(crate) fn meet(parts: &[&Partition]) -> Partition {
    let runs = parts
        .iter()
        .flat_map(|part| part.iter())
        .flat_map(|block| block.iter())
        .copied()
        .max()
        .map_or(0, |max| max + 1);
    let key = |run: RunIx| -> Vec<usize> {
        parts
            .iter()
            .map(|part| {
                part.iter()
                    .position(|block| block.contains(&run))
                    .unwrap_or(usize::MAX)
            })
            .collect()
    };
    let mut groups: BTreeMap<Vec<usize>, BTreeSet<RunIx>> = BTreeMap::new();
    for run in 0..runs {
        groups.entry(key(run)).or_default().insert(run);
    }
    let mut blocks: Vec<BTreeSet<RunIx>> = groups.into_values().collect();
    blocks.sort_by_key(|block| *block.iter().next().expect("no empty block"));
    blocks
}

/// What one host-visible value turned out to be.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum Class {
    /// Never observed in any run.
    Absent,
    /// One value in every run.
    Constant(String),
    /// Differs among runs whose inputs are byte-identical.
    Fresh,
    /// Reproducible, not constant, and determined by these secrets.
    Carries(BTreeSet<Secret>),
}

/// Classify one host-visible value from its per-run observations.
///
/// `replicates` are the runs whose inputs are identical; `secrets` maps each
/// varied input to the partition it induces. The freshness test comes first
/// because it is the cheap one, and because it is the only test that needs the
/// replicates: the rest is a statement about functional dependence.
pub(crate) fn classify(
    values: &[Option<String>],
    replicates: &BTreeSet<RunIx>,
    secrets: &BTreeMap<Secret, Partition>,
) -> Class {
    if values.iter().all(Option::is_none) {
        return Class::Absent;
    }
    let mut replicated = replicates.iter().map(|run| &values[*run]);
    let first = replicated.next().expect("at least one replicate run");
    if !replicated.all(|value| value == first) {
        return Class::Fresh;
    }
    let observed = partition(values);
    if observed.len() == 1 {
        let value = values
            .iter()
            .flatten()
            .next()
            .expect("a non-absent value")
            .clone();
        return Class::Constant(value);
    }
    let names: Vec<&Secret> = secrets.keys().collect();
    for size in 1..=names.len() {
        for combination in combinations(&names, size) {
            let parts: Vec<&Partition> =
                combination.iter().map(|secret| &secrets[*secret]).collect();
            if refines(&meet(&parts), &observed) {
                return Class::Carries(combination.into_iter().copied().collect());
            }
        }
    }
    // Unreachable: the meet over every secret separates all runs but the
    // replicates, on which a non-fresh value agrees. See the module header.
    unreachable!("a reproducible value that no set of secrets determines")
}

fn combinations<'a, T: Copy>(items: &[T], size: usize) -> Vec<Vec<T>> {
    if size == 0 {
        return vec![Vec::new()];
    }
    let mut out = Vec::new();
    for (index, item) in items.iter().enumerate() {
        for mut rest in combinations(&items[index + 1..], size - 1) {
            rest.insert(0, *item);
            out.push(rest);
        }
    }
    let _ = std::marker::PhantomData::<&'a ()>;
    out
}

// ---------------------------------------------------------------------------
// §B  Leaf decomposition
// ---------------------------------------------------------------------------

/// How deep a derived value may be decomposed again. Three is what the wire
/// needs: a URL, the path segment inside it, the `:`-segment inside that.
const DERIVATION_DEPTH: usize = 3;

/// Every scalar a host can read off `value`, keyed by a stable path.
///
/// The unit of measurement cannot be the JSON leaf. `device_id` is
/// `device:{user_fp}:{device_fp}` and the second segment is minted fresh for
/// every engine, so a whole-leaf partition classifies it `Fresh` and reports
/// that it carries nothing — while it hands the host the owner's user
/// fingerprint in its own prefix. So each leaf is decomposed into everything
/// structurally derivable from it, and the leaf's verdict is the fold over
/// itself and its derivatives. A field may be fresh *and* carrying.
///
/// Derived paths are suffixed after a `#`, which no serde field name contains,
/// so [`root_path`] recovers the ledger row a derived value belongs to.
pub(crate) fn leaves(value: &Value) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    crate::leakage_ledger::walk(value, "", &mut |path, leaf| {
        let text = match leaf {
            Value::String(text) => text.clone(),
            Value::Number(number) => number.to_string(),
            Value::Bool(flag) => flag.to_string(),
            Value::Null => return,
            Value::Object(_) | Value::Array(_) => return,
        };
        let structural = matches!(leaf, Value::String(_));
        derive(path, &text, structural, DERIVATION_DEPTH, &mut out);
    });
    out
}

/// The ledger row a (possibly derived) path belongs to: everything before the
/// first `#`.
pub(crate) fn root_path(path: &str) -> &str {
    path.split('#').next().unwrap_or(path)
}

fn derive(
    path: &str,
    text: &str,
    is_string: bool,
    depth: usize,
    out: &mut BTreeMap<String, String>,
) {
    out.insert(path.to_string(), text.to_string());
    if !is_string || depth == 0 || text.is_empty() {
        return;
    }
    // Length is what makes |m| and the size-distinctive rotation measurable
    // rather than conceded.
    out.insert(format!("{path}#len"), text.len().to_string());

    // A percent-encoded `:` hides a device id's segments as surely as base64
    // hides a frame header. Found by this mechanism reporting an endpoint that
    // names a device as carrying nothing.
    if text.contains('%') {
        if let Ok(decoded) = urlencoding::decode(text) {
            if decoded != text {
                derive(&format!("{path}#pct"), &decoded, true, depth - 1, out);
            }
        }
    }

    if text.starts_with("http://") || text.starts_with("https://") {
        derive_url(path, text, depth, out);
    } else if text.contains(':') {
        for (index, segment) in text.split(':').enumerate() {
            derive(
                &format!("{path}#seg[{index}]"),
                segment,
                true,
                depth - 1,
                out,
            );
        }
    }

    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(text) {
        if let Ok(json) = serde_json::from_slice::<Value>(&bytes) {
            derive_json(&format!("{path}#b64"), &json, depth - 1, out);
        } else {
            derive_mls(path, &bytes, out);
        }
    }
    if let Ok(json) = serde_json::from_str::<Value>(text) {
        if json.is_object() {
            derive_json(&format!("{path}#json"), &json, depth - 1, out);
        }
    }
}

fn derive_url(path: &str, text: &str, depth: usize, out: &mut BTreeMap<String, String>) {
    let (before_query, query) = match text.split_once('?') {
        Some((before, query)) => (before, Some(query)),
        None => (text, None),
    };
    let scheme_end = before_query.find("://").map_or(0, |at| at + 3);
    let (origin, rest) = match before_query[scheme_end..].find('/') {
        Some(at) => before_query.split_at(scheme_end + at),
        None => (before_query, ""),
    };
    out.insert(format!("{path}#origin"), origin.to_string());
    for (index, segment) in rest.split('/').filter(|part| !part.is_empty()).enumerate() {
        derive(
            &format!("{path}#path[{index}]"),
            segment,
            true,
            depth - 1,
            out,
        );
    }
    for pair in query.into_iter().flat_map(|query| query.split('&')) {
        if let Some((key, value)) = pair.split_once('=') {
            out.insert(format!("{path}#query.{key}"), value.to_string());
        }
    }
}

fn derive_json(prefix: &str, json: &Value, depth: usize, out: &mut BTreeMap<String, String>) {
    crate::leakage_ledger::walk(json, prefix, &mut |path, leaf| {
        let text = match leaf {
            Value::String(text) => text.clone(),
            Value::Number(number) => number.to_string(),
            Value::Bool(flag) => flag.to_string(),
            Value::Null => return,
            Value::Object(_) | Value::Array(_) => return,
        };
        derive(path, &text, matches!(leaf, Value::String(_)), depth, out);
    });
}

/// RFC 9420 §6.3 puts `group_id`, `epoch` and `content_type` in the clear in
/// every `PrivateMessage`. Emitting them as leaves is what makes "the wrap
/// hides the frame header" a measurement instead of an argument: on a wrapped
/// payload this parse fails and nothing is emitted, on an unwrapped one the
/// group id shows up at both inboxes.
fn derive_mls(path: &str, bytes: &[u8], out: &mut BTreeMap<String, String>) {
    use openmls::prelude::{tls_codec::Deserialize, MlsMessageIn};

    // A host that has read the protocol description does not give up at the
    // first byte. `direct_frame` prefixes the MLS message with a one-byte tag,
    // and a commit with a tag plus a 64-byte signature, so the parse is tried
    // at each offset a frame can begin at. Without this the tag alone would
    // hide the frame header and the wrap would be credited for it — measured
    // by removing the wrap and watching this stay quiet.
    let starts = [0, 1, 1 + crate::direct_frame::COMMIT_SIGNATURE_LEN];
    let Some(message) = starts
        .into_iter()
        .filter(|start| *start < bytes.len())
        .find_map(|start| MlsMessageIn::tls_deserialize_exact(&bytes[start..]).ok())
    else {
        return;
    };
    out.insert(
        format!("{path}#mls.wire_format"),
        format!("{:?}", message.wire_format()),
    );
    if let Ok(protocol) = message.try_into_protocol_message() {
        out.insert(
            format!("{path}#mls.group_id"),
            String::from_utf8_lossy(protocol.group_id().as_slice()).to_string(),
        );
        out.insert(
            format!("{path}#mls.epoch"),
            protocol.epoch().as_u64().to_string(),
        );
        out.insert(
            format!("{path}#mls.content_type"),
            format!("{:?}", protocol.content_type()),
        );
    }
}

// ---------------------------------------------------------------------------
// §C  The recorder
// ---------------------------------------------------------------------------

use crate::ffi_api::tests::tests as harness;
use crate::ffi_api::{CoreCommand, CoreEffect, CoreEngine, CoreEvent, CoreOutput};
use crate::model::{Envelope, InboxRecord, InboxRecordState};
use crate::transport_contract::{
    AppendEnvelopeRequest, MessageRequestActionResult, MessageRequestItem, PrepareBlobUploadResult,
};

/// A host-visible surface. `Deferred` names a request the ledger does not
/// enumerate (its type sits in `notEnumerated.deferred`); recording it anyway
/// keeps the recorder's match exhaustive and makes the exclusion visible.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) enum Surface {
    Ledger(&'static str),
    Deferred(&'static str),
}

/// One host-visible request, as the host sees it.
#[derive(Clone, Debug)]
pub(crate) struct Record {
    /// The scripted step that produced it. Leaf identity is (step, surface,
    /// path): both parties append, so the surface alone is not unique.
    pub(crate) step: &'static str,
    pub(crate) surface: Surface,
    /// Whose inbox or runtime this addresses. Resolves the ledger's
    /// `recipient_*` roles and drives the cross-inbox assertion.
    pub(crate) inbox: Party,
    /// Who issued it. Resolves the ledger's `sender_*` roles.
    pub(crate) local: Party,
    pub(crate) view: Value,
    /// Derived once: [`leaves`] walks, decodes and re-parses, and the
    /// assertions ask for the same record many times over.
    pub(crate) leaves: BTreeMap<String, String>,
}

/// The run inputs. Everything not named here is held fixed across the matrix,
/// which is what bounds the coverage — see the module header.
#[derive(Clone, Debug)]
pub(crate) struct RunInputs {
    pub(crate) alice_mnemonic: &'static str,
    pub(crate) bob_mnemonic: &'static str,
    pub(crate) body_a_to_b: &'static str,
    pub(crate) body_b_to_a: &'static str,
    pub(crate) attachment_name: &'static str,
    pub(crate) attachment_len: usize,
}

/// One party's inbox, as the host keeps it.
#[derive(Default)]
struct Inbox {
    append_seq: u64,
    records: Vec<InboxRecord>,
    admitted: BTreeSet<String>,
    /// Lane to the first-contact request queued on it. Mirrors
    /// `services/cloudflare/src/inbox/service.ts`: an append on a lane the
    /// owner has not admitted is queued rather than delivered, and accepting
    /// admits the lane and promotes what was queued.
    queued: BTreeMap<String, (String, Vec<Envelope>)>,
}

struct Recorder {
    alice: CoreEngine,
    bob: CoreEngine,
    device: BTreeMap<Party, String>,
    owner: BTreeMap<String, Party>,
    inboxes: BTreeMap<Party, Inbox>,
    blobs: BTreeMap<String, Vec<u8>>,
    step: &'static str,
    out: Vec<Record>,
}

impl Recorder {
    fn engine(&mut self, who: Party) -> &mut CoreEngine {
        match who {
            Party::Alice => &mut self.alice,
            Party::Bob => &mut self.bob,
        }
    }

    fn record(&mut self, surface: Surface, inbox: Party, local: Party, view: Value) {
        self.out.push(Record {
            step: self.step,
            surface,
            inbox,
            local,
            leaves: leaves(&view),
            view,
        });
    }

    /// Issue one command and settle every effect it causes.
    fn step(&mut self, label: &'static str, who: Party, command: CoreCommand) {
        self.step = label;
        let output = self
            .engine(who)
            .handle_command(command)
            .unwrap_or_else(|error| panic!("{label}: {error:?}"));
        self.drain(who, output);
    }

    fn drain(&mut self, who: Party, output: CoreOutput) {
        let mut queue: std::collections::VecDeque<CoreEffect> = output.effects.into();
        let mut guard = 0;
        while let Some(effect) = queue.pop_front() {
            guard += 1;
            assert!(guard < 1000, "{}: effect loop did not settle", self.step);
            let next = self.handle(who, effect);
            queue.extend(next.effects);
        }
    }

    /// Every value the recorder writes on the host's behalf is minted the way
    /// the real host mints it, and never derived from anything the client
    /// sent. A blob ref built from the client's task id, for instance, would
    /// manufacture a conversation identifier into `storageRef.ref`, and the
    /// resulting red would be the recorder's fault rather than the protocol's.
    fn handle(&mut self, who: Party, effect: CoreEffect) -> CoreOutput {
        match effect {
            CoreEffect::ExecuteHttpRequest { request } => self.handle_http(who, request),

            CoreEffect::RegisterAcceptedLane { register } => {
                self.record(
                    Surface::Ledger("register_accepted_lane_request"),
                    who,
                    who,
                    host_view(&register),
                );
                self.inboxes
                    .get_mut(&who)
                    .expect("inbox")
                    .admitted
                    .insert(register.lane.clone());
                self.event(
                    who,
                    CoreEvent::AcceptedLaneRegistered {
                        lane: register.lane,
                    },
                )
            }
            CoreEffect::RevokeAcceptedLanes { revoke } => {
                self.record(
                    Surface::Deferred("revoke_accepted_lanes_request"),
                    who,
                    who,
                    host_view(&revoke),
                );
                self.event(
                    who,
                    CoreEvent::AcceptedLanesRevoked {
                        lanes: revoke.lanes,
                    },
                )
            }
            CoreEffect::FetchMessageRequests { fetch } => {
                self.record(
                    Surface::Deferred("fetch_message_requests_request"),
                    who,
                    who,
                    host_view(&fetch),
                );
                let requests = self.inboxes[&who]
                    .queued
                    .values()
                    .map(|(request_id, envelopes)| MessageRequestItem {
                        request_id: request_id.clone(),
                        first_seen_at: 1,
                        message_count: envelopes.len() as u64,
                        welcome_bytes: envelopes.first().and_then(|first| first.bytes.clone()),
                    })
                    .collect();
                self.event(who, CoreEvent::MessageRequestsFetched { requests })
            }
            CoreEffect::ActOnMessageRequest { action } => {
                self.record(
                    Surface::Ledger("message_request_action_request"),
                    who,
                    who,
                    host_view(&action),
                );
                let promoted = self.accept_request(who, &action.request_id);
                self.event(
                    who,
                    CoreEvent::MessageRequestActionCompleted {
                        result: MessageRequestActionResult {
                            accepted: true,
                            request_id: action.request_id,
                            promoted_count: promoted,
                            action: crate::transport_contract::MessageRequestAction::Accept,
                        },
                    },
                )
            }
            CoreEffect::PrepareBlobUpload { task_id, upload } => {
                // A 1:1 payload goes to the recipient's runtime, admitted on
                // the lane the recipient admits us on.
                let inbox = who.other();
                self.record(
                    Surface::Ledger("prepare_blob_upload_request"),
                    inbox,
                    who,
                    host_view(&upload),
                );
                let blob_ref = format!("blobs/{}", crate::model::random_opaque_id());
                let origin = storage_origin(self.engine(who));
                self.event(
                    who,
                    CoreEvent::BlobUploadPrepared {
                        task_id,
                        result: PrepareBlobUploadResult {
                            blob_ref: blob_ref.clone(),
                            upload_target: format!("{origin}/v1/storage/upload"),
                            upload_headers: BTreeMap::new(),
                            read_capability: crate::model::random_opaque_id(),
                            download_target: format!(
                                "{origin}/v1/storage/blob/{}",
                                urlencoding::encode(&blob_ref)
                            ),
                            upload_expires_at: Some(u64::MAX / 2),
                            blob_expires_at: Some(u64::MAX / 2),
                            delete_target: None,
                            delete_capability: None,
                        },
                    },
                )
            }
            CoreEffect::UploadBlob { upload } => {
                // The object is opaque bytes under an opaque key: nothing
                // about it is a leaf the ledger enumerates.
                self.blobs.insert(upload.blob_ref, upload.blob_ciphertext);
                self.event(
                    who,
                    CoreEvent::BlobUploaded {
                        task_id: upload.task_id,
                    },
                )
            }
            CoreEffect::DownloadBlob { download } => {
                let blob_ciphertext = self.blobs.get(&download.blob_ref).cloned();
                self.event(
                    who,
                    CoreEvent::BlobDownloaded {
                        task_id: download.task_id,
                        blob_ciphertext,
                    },
                )
            }
            CoreEffect::ReadAttachmentBytes { read } => {
                let plaintext = std::fs::read(&read.attachment_id).expect("attachment file");
                self.event(
                    who,
                    CoreEvent::AttachmentBytesLoaded {
                        task_id: read.task_id,
                        plaintext,
                    },
                )
            }
            CoreEffect::PublishSharedState { publish } => {
                // Published to the party's own storage, under a key that names
                // it on purpose; the `r2_key` surface covers that on the TS
                // side, where the key is minted.
                let reference = publish.reference.clone();
                let operation_id = publish.operation_id.clone();
                let document_kind = publish.document_kind;
                self.record(
                    Surface::Deferred("publish_shared_state_request"),
                    who,
                    who,
                    host_view(&publish),
                );
                self.event(
                    who,
                    CoreEvent::SharedStatePublished {
                        operation_id,
                        document_kind,
                        reference,
                        etag: None,
                        saved_bundle: None,
                    },
                )
            }

            // Nothing a host sees.
            CoreEffect::PersistState { .. }
            | CoreEffect::ScheduleTimer { .. }
            | CoreEffect::EmitUserNotification { .. }
            | CoreEffect::CacheUploadedAttachment { .. }
            | CoreEffect::WriteDownloadedAttachment { .. }
            | CoreEffect::ReleaseStagedAttachment { .. }
            | CoreEffect::OpenRealtimeConnection { .. }
            | CoreEffect::CloseRealtimeConnection { .. }
            | CoreEffect::DeleteBlob { .. } => CoreOutput::default(),

            // The corpus is 1:1, which is the scope of the write-up. A group
            // effect here means the script drifted, so say so rather than
            // answer quietly.
            other => panic!("{}: the 1:1 corpus saw {other:?}", self.step),
        }
    }

    fn handle_http(
        &mut self,
        who: Party,
        request: crate::ffi_api::HttpRequestEffect,
    ) -> CoreOutput {
        let url = request.url.clone();
        let request_id = request.request_id.clone();
        let view = http_view(&request);

        if url.contains("/keypackage-pool/") {
            self.record(
                Surface::Deferred("key_package_claim"),
                who.other(),
                who,
                view,
            );
            let body = harness::key_package_claim_response(self.engine(who), &url);
            return self.http_response(who, request_id, body);
        }
        if url.contains("/message-requests") {
            self.record(Surface::Deferred("message_requests_http"), who, who, view);
            return self.http_response(who, request_id, "{}".into());
        }
        if url.ends_with("/ack") {
            self.record(Surface::Ledger("ack_request"), who, who, view);
            return self.http_response(who, request_id, r#"{"accepted":true,"ack_seq":0}"#.into());
        }
        if url.ends_with("/head") {
            let head = self.inboxes[&who].append_seq;
            self.record(Surface::Deferred("get_head_request"), who, who, view);
            return self.http_response(who, request_id, format!(r#"{{"head_seq":{head}}}"#));
        }
        if url.contains("/messages?") {
            self.record(Surface::Ledger("fetch_messages_request"), who, who, view);
            let inbox = self.inboxes.get_mut(&who).expect("inbox");
            let records = std::mem::take(&mut inbox.records);
            let to_seq = inbox.append_seq;
            let body = serde_json::json!({
                "to_seq": to_seq,
                "history_floor_seq": 0,
                "records": records,
            })
            .to_string();
            return self.http_response(who, request_id, body);
        }
        if url.ends_with("/messages") {
            let body: AppendEnvelopeRequest =
                serde_json::from_str(request.body.as_deref().expect("append body"))
                    .expect("append body decodes");
            let destination = self.owner[&body.recipient_device_id];
            self.record(Surface::Ledger("append_request"), destination, who, view);
            let seq = self.deposit(destination, body.envelope);
            return self.http_response(who, request_id, format!(r#"{{"seq":{seq}}}"#));
        }
        panic!("{}: unclassified host request {url}", self.step);
    }

    /// Admission, as `inbox/service.ts` performs it: a lane the owner admits
    /// joins the record stream, anything else waits in the first-contact queue
    /// under a request id the host mints.
    fn deposit(&mut self, destination: Party, envelope: Envelope) -> u64 {
        let device_id = self.device[&destination].clone();
        let inbox = self.inboxes.get_mut(&destination).expect("inbox");
        inbox.append_seq += 1;
        let seq = inbox.append_seq;
        if inbox.admitted.contains(&envelope.lane) {
            inbox.records.push(InboxRecord {
                seq,
                recipient_device_id: device_id,
                message_id: envelope.mid.clone(),
                received_at: seq,
                expires_at: None,
                state: InboxRecordState::Available,
                envelope,
            });
        } else {
            inbox
                .queued
                .entry(envelope.lane.clone())
                .or_insert_with(|| {
                    (
                        format!("request:{}", crate::model::random_opaque_id()),
                        Vec::new(),
                    )
                })
                .1
                .push(envelope);
        }
        seq
    }

    fn accept_request(&mut self, who: Party, request_id: &str) -> u64 {
        let device_id = self.device[&who].clone();
        let inbox = self.inboxes.get_mut(&who).expect("inbox");
        let Some(lane) = inbox
            .queued
            .iter()
            .find(|(_, (id, _))| id == request_id)
            .map(|(lane, _)| lane.clone())
        else {
            return 0;
        };
        let (_, envelopes) = inbox.queued.remove(&lane).expect("queued request");
        inbox.admitted.insert(lane);
        let mut promoted = 0;
        for envelope in envelopes {
            inbox.append_seq += 1;
            inbox.records.push(InboxRecord {
                seq: inbox.append_seq,
                recipient_device_id: device_id.clone(),
                message_id: envelope.mid.clone(),
                received_at: inbox.append_seq,
                expires_at: None,
                state: InboxRecordState::Available,
                envelope,
            });
            promoted += 1;
        }
        promoted
    }

    fn http_response(&mut self, who: Party, request_id: String, body: String) -> CoreOutput {
        self.event(
            who,
            CoreEvent::HttpResponseReceived {
                request_id,
                status: 200,
                body: Some(body),
            },
        )
    }

    fn event(&mut self, who: Party, event: CoreEvent) -> CoreOutput {
        let step = self.step;
        self.engine(who)
            .handle_event(event)
            .unwrap_or_else(|error| panic!("{step}: {error:?}"))
    }
}

fn storage_origin(engine: &CoreEngine) -> String {
    engine
        .local_bundle()
        .and_then(|bundle| bundle.storage_profile.as_ref())
        .and_then(|profile| profile.base_url.clone())
        .expect("storage origin")
}

/// The host's view of a value: camelCase, because the core emits snake_case
/// and the platform driver converts before sending.
fn host_view<T: serde::Serialize>(value: &T) -> Value {
    crate::leakage_ledger::host_view(value)
}

/// The host's view of an HTTP effect. The body is not the whole story: the URL
/// names the destination device, and `X-Tapchat-Capability` carries a whole
/// serialized capability. Folding those in under `@`, which no serde field
/// name contains, leaves the body's own paths unchanged.
fn http_view(request: &crate::ffi_api::HttpRequestEffect) -> Value {
    let mut view = serde_json::Map::new();
    view.insert("@url".into(), Value::String(request.url.clone()));
    if !request.headers.is_empty() {
        view.insert("@header".into(), host_view(&request.headers));
    }
    if let Some(auth) = request.auth.as_ref() {
        view.insert("@auth".into(), host_view(auth));
    }
    if let Some(body) = request.body.as_ref() {
        let parsed: Value = serde_json::from_str(body).expect("request body is JSON");
        let camel = crate::transport_contract::json_case::snake_to_camel_value(parsed);
        if let Value::Object(fields) = camel {
            view.extend(fields);
        }
    }
    Value::Object(view)
}

/// Run the scripted scenario once.
///
/// Two requirements on the script, both load-bearing. Every payload differs
/// between the directions, so any value seen at *both* inboxes came from the
/// protocol rather than from the script. And the rotation is primed rather
/// than sent, which saves an interval of MLS encryptions per run.
pub(crate) fn record_run(inputs: &RunInputs) -> Vec<Record> {
    let mut alice = harness::local_engine(inputs.alice_mnemonic, "phone");
    let mut bob = harness::local_engine(inputs.bob_mnemonic, "phone");
    harness::link_contact(&mut alice, &bob);
    harness::link_contact(&mut bob, &alice);
    let alice_device = alice.local_device_id().expect("alice device").to_string();
    let bob_device = bob.local_device_id().expect("bob device").to_string();
    let bob_user = bob.local_bundle().expect("bob bundle").user_id.clone();

    let mut recorder = Recorder {
        alice,
        bob,
        device: BTreeMap::from([
            (Party::Alice, alice_device.clone()),
            (Party::Bob, bob_device.clone()),
        ]),
        owner: BTreeMap::from([
            (alice_device.clone(), Party::Alice),
            (bob_device.clone(), Party::Bob),
        ]),
        inboxes: BTreeMap::from([
            (Party::Alice, Inbox::default()),
            (Party::Bob, Inbox::default()),
        ]),
        blobs: BTreeMap::new(),
        step: "setup",
        out: Vec::new(),
    };

    recorder.step(
        "create",
        Party::Alice,
        CoreCommand::CreateConversation {
            peer_user_id: bob_user,
            conversation_kind: crate::model::ConversationKind::Direct,
        },
    );
    let conversation_id = recorder
        .alice
        .state
        .conversations
        .keys()
        .next()
        .expect("conversation")
        .clone();

    let sync = |device_id: &str| CoreCommand::SyncInbox {
        device_id: device_id.to_string(),
        reason: None,
    };
    recorder.step(
        "b_list_requests",
        Party::Bob,
        CoreCommand::ListMessageRequests,
    );
    let request_id = recorder.inboxes[&Party::Bob]
        .queued
        .values()
        .next()
        .expect("a first-contact request")
        .0
        .clone();
    recorder.step(
        "b_accept",
        Party::Bob,
        CoreCommand::ActOnMessageRequest {
            request_id,
            action: crate::transport_contract::MessageRequestAction::Accept,
        },
    );
    recorder.step("b_welcome", Party::Bob, sync(&bob_device));
    recorder.step(
        "a_to_b",
        Party::Alice,
        CoreCommand::SendTextMessage {
            conversation_id: conversation_id.clone(),
            plaintext: inputs.body_a_to_b.to_string(),
        },
    );
    recorder.step("b_fetch", Party::Bob, sync(&bob_device));
    recorder.step(
        "b_to_a",
        Party::Bob,
        CoreCommand::SendTextMessage {
            conversation_id: conversation_id.clone(),
            plaintext: inputs.body_b_to_a.to_string(),
        },
    );
    recorder.step("a_fetch", Party::Alice, sync(&alice_device));
    recorder.step(
        "a_spill",
        Party::Alice,
        CoreCommand::SendAttachmentMessage {
            conversation_id: conversation_id.clone(),
            attachment_descriptor: corpus_attachment(inputs),
        },
    );
    recorder.step("b_fetch_spill", Party::Bob, sync(&bob_device));
    // The corpus has always run this step, but it only ever measured what the
    // host saw -- so a spill that Bob refused outright still recorded a
    // perfectly normal host view, and the refusal went unnoticed for as long as
    // it existed. Measuring a delivery is not the same as witnessing one.
    assert!(
        recorder
            .bob
            .state
            .conversations
            .get(&conversation_id)
            .expect("bob conversation")
            .messages
            .iter()
            .filter_map(|message| message.plaintext.as_deref())
            .any(|plaintext| {
                serde_json::from_str::<crate::attachment_crypto::AttachmentManifestV2>(plaintext)
                    .is_ok()
            }),
        "the spilled attachment must reach Bob, not just the host"
    );

    harness::set_direct_pcs_debt(
        &mut recorder.alice,
        &conversation_id,
        crate::direct_pcs::DIRECT_PCS_COMMIT_INTERVAL * 2,
    );
    recorder.step(
        "a_rotate",
        Party::Alice,
        CoreCommand::SendTextMessage {
            conversation_id,
            plaintext: inputs.body_a_to_b.to_string(),
        },
    );
    recorder.step("b_fetch_rotation", Party::Bob, sync(&bob_device));

    recorder.out
}

/// An attachment whose on-disk path is a function of the varied file name, so
/// that a path reaching the host would report as carrying it rather than
/// hiding in the fresh class.
fn corpus_attachment(inputs: &RunInputs) -> crate::ffi_api::AttachmentDescriptor {
    // The pid keeps two concurrent test processes from writing each other's
    // byte count into the same file. It is constant within a process, so the
    // partition the path induces is unchanged.
    let path = std::env::temp_dir().join(format!(
        "tapchat-corpus-{}-{}",
        std::process::id(),
        inputs.attachment_name
    ));
    std::fs::write(&path, vec![7_u8; inputs.attachment_len]).expect("write corpus attachment");
    crate::ffi_api::AttachmentDescriptor {
        attachment_id: path.to_string_lossy().to_string(),
        mime_type: "application/octet-stream".into(),
        size_bytes: inputs.attachment_len as u64,
        file_name: Some(inputs.attachment_name.to_string()),
        preview: None,
        width: None,
        height: None,
        blur_hash: None,
    }
}

// ---------------------------------------------------------------------------
// §D  The matrix, and the assertions over it
// ---------------------------------------------------------------------------

/// Two further BIP-39 vectors, so that every identity has a *second*
/// alternative. One alternative would already be sound — freshness is detected
/// by the replicates, so a nonce can never masquerade as carrying — but a
/// field that buckets an identity into one bit would collide with the baseline
/// half the time and read as constant.
const BOB_ALT: &str =
    "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic";
const BOB_ALT2: &str = "scheme spot photo card baby mountain device kick cradle pact join borrow";

/// The runs whose inputs are byte-identical. Three rather than two: a value
/// that is fresh only sometimes would flip verdicts under a single pair.
const REPLICATES: usize = 3;

fn baseline() -> RunInputs {
    RunInputs {
        alice_mnemonic: harness::ALICE_MNEMONIC,
        bob_mnemonic: harness::BOB_MNEMONIC,
        body_a_to_b: "the first direction",
        body_b_to_a: "and the second one, which is longer",
        attachment_name: "one.bin",
        attachment_len: 64,
    }
}

/// One secret varied at a time, from a common baseline.
fn matrix() -> (Vec<RunInputs>, BTreeMap<Secret, Vec<RunIx>>) {
    let mut runs = vec![baseline(), baseline(), baseline()];
    let mut varied: BTreeMap<Secret, Vec<RunIx>> = BTreeMap::new();
    let mut push = |runs: &mut Vec<RunInputs>,
                    varied: &mut BTreeMap<Secret, Vec<RunIx>>,
                    secret: Secret,
                    inputs: RunInputs| {
        varied.entry(secret).or_default().push(runs.len());
        runs.push(inputs);
    };

    for mnemonic in [harness::CAROL_MNEMONIC, harness::DANA_MNEMONIC] {
        push(
            &mut runs,
            &mut varied,
            Secret::Identity(Party::Alice),
            RunInputs {
                alice_mnemonic: mnemonic,
                ..baseline()
            },
        );
    }
    for mnemonic in [BOB_ALT, BOB_ALT2] {
        push(
            &mut runs,
            &mut varied,
            Secret::Identity(Party::Bob),
            RunInputs {
                bob_mnemonic: mnemonic,
                ..baseline()
            },
        );
    }
    // One alternative of the same length and one of a different length, so
    // that content and length are separable.
    for body in ["the first direCTION", "shorter"] {
        push(
            &mut runs,
            &mut varied,
            Secret::Body(Party::Alice),
            RunInputs {
                body_a_to_b: body,
                ..baseline()
            },
        );
    }
    push(
        &mut runs,
        &mut varied,
        Secret::Body(Party::Bob),
        RunInputs {
            body_b_to_a: "a different second direction entirely",
            ..baseline()
        },
    );
    push(
        &mut runs,
        &mut varied,
        Secret::AttachmentName,
        RunInputs {
            attachment_name: "two.bin",
            ..baseline()
        },
    );
    push(
        &mut runs,
        &mut varied,
        Secret::AttachmentLen,
        RunInputs {
            attachment_len: 4096,
            ..baseline()
        },
    );
    (runs, varied)
}

pub(crate) struct Corpus {
    runs: Vec<Vec<Record>>,
    replicates: BTreeSet<RunIx>,
    secrets: BTreeMap<Secret, Partition>,
}

impl Corpus {
    /// Every (step, surface, path) the host saw in any run, in a stable order.
    fn observed_leaves(&self) -> BTreeSet<(&'static str, Surface, String)> {
        self.runs
            .iter()
            .flatten()
            .flat_map(|record| {
                record
                    .leaves
                    .keys()
                    .map(move |path| (record.step, record.surface, path.clone()))
            })
            .collect()
    }

    /// What one derived path was observed to be in each run. A record that a
    /// run did not produce contributes `None`, which is its own value class.
    fn values(&self, step: &'static str, surface: Surface, path: &str) -> Vec<Option<String>> {
        self.runs
            .iter()
            .map(|records| {
                records
                    .iter()
                    .filter(|record| record.step == step && record.surface == surface)
                    .find_map(|record| record.leaves.get(path).cloned())
            })
            .collect()
    }

    fn classify(&self, step: &'static str, surface: Surface, path: &str) -> Class {
        classify(
            &self.values(step, surface, path),
            &self.replicates,
            &self.secrets,
        )
    }
}

/// Built once; all the assertions read it.
fn corpus() -> &'static Corpus {
    static CORPUS: std::sync::OnceLock<Corpus> = std::sync::OnceLock::new();
    CORPUS.get_or_init(|| {
        let (inputs, varied) = matrix();
        let total = inputs.len();
        let runs: Vec<Vec<Record>> = inputs.iter().map(record_run).collect();
        let secrets = varied
            .into_iter()
            .map(|(secret, variant_runs)| {
                // Every run that did not vary this secret holds its baseline
                // value, so they share one block; each variant is its own.
                let mut blocks: Partition = vec![(0..total)
                    .filter(|run| !variant_runs.contains(run))
                    .collect()];
                blocks.extend(variant_runs.into_iter().map(|run| BTreeSet::from([run])));
                blocks.sort_by_key(|block| *block.iter().next().expect("no empty block"));
                (secret, blocks)
            })
            .collect();
        Corpus {
            runs,
            replicates: (0..REPLICATES).collect(),
            secrets,
        }
    })
}

/// The ledger role a measured secret answers to, from the point of view of the
/// record that carried it. Role names are relative — `sender_user` at one
/// record and at another are different people — which is why the corpus
/// measures in absolute terms and translates here.
///
/// A length is not an identifier and has no role: what a payload's size
/// discloses is the ideal's own leak, and it is asserted separately by
/// [`only_a_payloads_size_reaches_the_host`].
fn role_of(secret: Secret, record: &Record) -> Option<&'static str> {
    match secret {
        Secret::Identity(party) if party == record.inbox => Some("recipient_user"),
        Secret::Identity(party) if party == record.local => Some("sender_user"),
        Secret::Identity(_) => unreachable!("a 1:1 record has only two parties"),
        Secret::Body(_) => Some("plaintext_body"),
        Secret::AttachmentName => Some("attachment_file_name"),
        Secret::AttachmentLen => None,
    }
}

/// What the corpus measured for one ledger row: the fold over the structural
/// leaf and everything derivable from it, across every step that produced it.
struct Measured {
    carries: BTreeSet<&'static str>,
    inhabited: bool,
    constant: Option<String>,
    detail: Vec<String>,
}

impl Corpus {
    /// Group the observed leaves by the ledger row they belong to.
    fn rows(&self) -> BTreeMap<(&'static str, String), Measured> {
        let mut rows: BTreeMap<(&'static str, String), Measured> = BTreeMap::new();
        for (step, surface, path) in self.observed_leaves() {
            let Surface::Ledger(name) = surface else {
                continue;
            };
            let record = self
                .runs
                .iter()
                .flatten()
                .find(|record| record.step == step && record.surface == surface)
                .expect("the leaf came from some record");
            let class = self.classify(step, surface, &path);
            let row = rows
                .entry((name, root_path(&path).to_string()))
                .or_insert_with(|| Measured {
                    carries: BTreeSet::new(),
                    inhabited: false,
                    constant: None,
                    detail: Vec::new(),
                });
            row.detail.push(format!("    {step}/{path}: {class:?}"));
            match &class {
                Class::Absent => {}
                Class::Constant(value) => {
                    if path == root_path(&path) {
                        row.constant = Some(value.clone());
                    }
                }
                Class::Fresh => row.inhabited = true,
                Class::Carries(secrets) => {
                    row.inhabited = true;
                    // A length is measured, but it is the ideal's own leak
                    // rather than an identifier, so it does not enter
                    // `carries`.
                    if !path.ends_with("#len") {
                        row.carries
                            .extend(secrets.iter().filter_map(|s| role_of(*s, record)));
                    }
                }
            }
        }
        rows
    }
}

/// T1, as far as a finite matrix can execute it: every value a host sees is
/// constant, fresh, or a function of exactly the secrets the ledger declares.
///
/// The comparison is set equality in both directions. Over-declaration is a
/// failure too: a `carries` widened to silence a red publishes a claim the
/// next run contradicts, and the ledger's own rule against that becomes a
/// machine check here.
#[test]
fn host_view_is_a_function_of_l() {
    let ledger = crate::leakage_ledger::Ledger::load();
    let corpus = corpus();
    let rows = corpus.rows();

    let mut failures = Vec::new();
    for ((surface, path), measured) in &rows {
        let Some(entry) = ledger.entry(surface, path) else {
            failures.push(format!(
                "{surface}:{path} is visible to the host and absent from the ledger\n{}",
                measured.detail.join("\n")
            ));
            continue;
        };
        let declared: BTreeSet<&str> = entry.carries.iter().map(String::as_str).collect();
        if declared != measured.carries {
            failures.push(format!(
                "{surface}:{path} carries {:?}; the ledger declares {declared:?}\n{}",
                measured.carries,
                measured.detail.join("\n")
            ));
        }
        // The corpus can refute `constant` and `absent` — one varying
        // observation is enough — but it cannot establish them: a value this
        // script happens to hold still, like a sequence number, moves in a
        // longer execution. So `inhabited` is corroborated where it can be and
        // otherwise left standing, and the asymmetry is what `bits` is worth.
        let bits_wrong = match entry.bits {
            crate::leakage_ledger::Bits::Absent => true,
            crate::leakage_ledger::Bits::Constant => {
                measured.inhabited || measured.constant.as_deref() != entry.value.as_deref()
            }
            crate::leakage_ledger::Bits::Inhabited => false,
        };
        if bits_wrong {
            failures.push(format!(
                "{surface}:{path} measured inhabited={} constant={:?}; \
                 the ledger declares {:?} value={:?}",
                measured.inhabited, measured.constant, entry.bits, entry.value
            ));
        }
    }

    // The other direction: a row nobody produces is a claim about nothing.
    // `absent` rows are exempt — that is what they record.
    for entry in ledger.rust_surface_entries() {
        if entry.bits == crate::leakage_ledger::Bits::Absent {
            continue;
        }
        if !rows.contains_key(&(entry.surface.as_str(), entry.path.clone())) {
            failures.push(format!(
                "{}:{} is declared and the corpus never observed it",
                entry.surface, entry.path
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "the measured host view and the ledger disagree in {} place(s):\n{}",
        failures.len(),
        failures.join("\n")
    );

    // Non-vacuity: all three verdicts must occur, or the classifier collapsed.
    assert!(
        rows.values().any(|row| !row.carries.is_empty())
            && rows.values().any(|row| row.constant.is_some())
            && rows.values().any(|row| row.inhabited),
        "the corpus produced no useful spread of verdicts"
    );
}

/// The ideal leaks `|m|` and nothing else about `m`. So a payload's content
/// may reach the host as a length and in no other shape.
#[test]
fn only_a_payloads_size_reaches_the_host() {
    let corpus = corpus();
    let mut escapes = Vec::new();
    for (step, surface, path) in corpus.observed_leaves() {
        let Class::Carries(secrets) = corpus.classify(step, surface, &path) else {
            continue;
        };
        let content = secrets
            .iter()
            .any(|secret| matches!(secret, Secret::Body(_) | Secret::AttachmentLen));
        let is_size =
            path.ends_with("#len") || path.ends_with(".size") || path.ends_with("izeBytes");
        if content && !is_size {
            escapes.push(format!("{step}/{surface:?}/{path} carries {secrets:?}"));
        }
    }
    assert!(
        escapes.is_empty(),
        "a message reached the host as something other than its length:\n{}",
        escapes.join("\n")
    );
    // And the size channel must actually be observed, or the assertion above
    // is about an empty set.
    assert!(
        corpus
            .observed_leaves()
            .iter()
            .any(|(step, surface, path)| {
                path.ends_with("#len")
                    && matches!(corpus.classify(step, *surface, path), Class::Carries(_))
            }),
        "no payload length was measured at all"
    );
}

/// Double lane and the frame wrap, as one executable sentence: the two inboxes
/// of one conversation share no value that varies.
///
/// Constants are excluded because a deployment origin or a protocol version
/// appears at every inbox of every user and links nobody. Numbers are excluded
/// because counters and sizes are the volume channel the write-up concedes;
/// asserting disjointness on those would go red on a coincidence rather than
/// on a leak. Every other equal value is a token, and the script gives the two
/// directions different inputs throughout, so a token seen at both inboxes came
/// from the protocol.
#[test]
fn host_view_shares_no_token_across_inboxes() {
    let corpus = corpus();
    for (index, records) in corpus.runs.iter().enumerate() {
        let tokens = |who: Party| -> BTreeSet<String> {
            records
                .iter()
                .filter(|record| record.inbox == who)
                .flat_map(|record| {
                    record
                        .leaves
                        .iter()
                        .map(|(path, value)| (path.clone(), value.clone()))
                        .filter(|(path, _)| {
                            !matches!(
                                corpus.classify(record.step, record.surface, path),
                                Class::Constant(_)
                            )
                        })
                        .filter(|(path, value)| {
                            !path.ends_with("#len") && value.parse::<u128>().is_err()
                        })
                        .map(|(_, value)| value)
                })
                .collect()
        };
        let (at_alice, at_bob) = (tokens(Party::Alice), tokens(Party::Bob));
        assert!(
            !at_alice.is_empty() && !at_bob.is_empty(),
            "run {index}: one inbox saw no varying value, so the test is vacuous"
        );
        let shared: Vec<&String> = at_alice.intersection(&at_bob).collect();
        assert!(
            shared.is_empty(),
            "run {index}: the two inboxes of one conversation share {shared:?}. \
             Under the reference deployment one operator holds both and knows \
             whose they are, so a shared value is the edge between them."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    #[ignore]
    fn dump() {
        let corpus = corpus();
        for (step, surface, path) in corpus.observed_leaves() {
            let class = corpus.classify(step, surface, &path);
            let inbox = corpus
                .runs
                .iter()
                .flatten()
                .find(|r| r.step == step && r.surface == surface)
                .map(|r| format!("{:?}<-{:?}", r.inbox, r.local))
                .unwrap_or_default();
            println!("{step}	{surface:?}	{inbox}	{path}	{class:?}");
        }
    }

    /// Not a leakage claim — a gate on the recorder itself. A recorder that
    /// silently skipped a step would make every verdict below vacuous, so the
    /// script is asserted before anything is measured.
    #[test]
    fn corpus_records_every_modelled_surface() {
        let corpus = corpus();
        let mut seen: BTreeSet<(&'static str, Surface)> = BTreeSet::new();
        for record in corpus.runs.iter().flatten() {
            seen.insert((record.step, record.surface));
        }
        for surface in [
            "append_request",
            "ack_request",
            "fetch_messages_request",
            "register_accepted_lane_request",
            "message_request_action_request",
            "prepare_blob_upload_request",
        ] {
            assert!(
                seen.iter().any(|(_, s)| *s == Surface::Ledger(surface)),
                "the script never produced {surface}; seen: {seen:?}"
            );
        }
        let records: Vec<&Record> = corpus.runs[0].iter().collect();
        assert!(
            records.iter().any(|r| r.inbox == Party::Alice)
                && records.iter().any(|r| r.inbox == Party::Bob),
            "both inboxes must receive traffic or the cross-inbox test is vacuous"
        );
        assert!(
            records
                .iter()
                .any(|r| r.view.pointer("/envelope/bytes").is_some()),
            "no inline payload"
        );
        assert!(
            records
                .iter()
                .any(|r| r.view.pointer("/envelope/storageRef").is_some()),
            "no spilled payload"
        );
    }

    fn blocks(sets: &[&[RunIx]]) -> Partition {
        sets.iter()
            .map(|set| set.iter().copied().collect())
            .collect()
    }

    fn some(values: &[&str]) -> Vec<Option<String>> {
        values.iter().map(|value| Some(value.to_string())).collect()
    }

    #[test]
    fn partition_groups_equal_values_and_keeps_absence_apart() {
        let values = vec![Some("a".into()), Some("b".into()), Some("a".into()), None];
        assert_eq!(partition(&values), blocks(&[&[0, 2], &[1], &[3]]));
    }

    #[test]
    fn refines_rejects_a_block_that_straddles_two() {
        let fine = blocks(&[&[0, 1], &[2]]);
        let coarse = blocks(&[&[0, 1, 2]]);
        assert!(refines(&fine, &coarse));
        assert!(!refines(&coarse, &fine));
        assert!(!refines(
            &blocks(&[&[0, 2], &[1]]),
            &blocks(&[&[0, 1], &[2]])
        ));
    }

    #[test]
    fn meet_separates_runs_that_disagree_on_either_part() {
        let left = blocks(&[&[0, 1], &[2, 3]]);
        let right = blocks(&[&[0, 2], &[1, 3]]);
        assert_eq!(meet(&[&left, &right]), blocks(&[&[0], &[1], &[2], &[3]]));
    }

    /// Three replicate runs and one variant per secret, which is the shape of
    /// the real matrix.
    fn secrets() -> BTreeMap<Secret, Partition> {
        BTreeMap::from([
            (
                Secret::Identity(Party::Alice),
                blocks(&[&[0, 1, 2, 4], &[3]]),
            ),
            (Secret::Body(Party::Alice), blocks(&[&[0, 1, 2, 3], &[4]])),
        ])
    }

    #[test]
    fn classify_names_constant_fresh_and_absent() {
        let replicates = BTreeSet::from([0, 1, 2]);
        assert_eq!(
            classify(&vec![None; 5], &replicates, &secrets()),
            Class::Absent
        );
        assert_eq!(
            classify(&some(&["v", "v", "v", "v", "v"]), &replicates, &secrets()),
            Class::Constant("v".into())
        );
        assert_eq!(
            classify(&some(&["a", "b", "c", "d", "e"]), &replicates, &secrets()),
            Class::Fresh
        );
    }

    #[test]
    fn classify_names_the_single_secret_a_value_tracks() {
        let replicates = BTreeSet::from([0, 1, 2]);
        assert_eq!(
            classify(&some(&["x", "x", "x", "y", "x"]), &replicates, &secrets()),
            Class::Carries(BTreeSet::from([Secret::Identity(Party::Alice)]))
        );
    }

    /// The point of the whole mechanism: a hash of a secret is not a substring
    /// of it, and lands in exactly the same class as the cleartext would.
    #[test]
    fn classify_catches_a_value_that_is_only_a_function_of_a_secret() {
        let replicates = BTreeSet::from([0, 1, 2]);
        let hashed = some(&["9f86d0", "9f86d0", "9f86d0", "2c26b4", "9f86d0"]);
        assert_eq!(
            classify(&hashed, &replicates, &secrets()),
            Class::Carries(BTreeSet::from([Secret::Identity(Party::Alice)]))
        );
    }

    #[test]
    fn classify_reports_a_joint_dependence_rather_than_either_half() {
        let replicates = BTreeSet::from([0, 1, 2]);
        let joint = some(&["x", "x", "x", "y", "z"]);
        assert_eq!(
            classify(&joint, &replicates, &secrets()),
            Class::Carries(BTreeSet::from([
                Secret::Identity(Party::Alice),
                Secret::Body(Party::Alice)
            ]))
        );
    }

    #[test]
    fn leaves_expose_the_user_fingerprint_inside_a_device_id() {
        let view = json!({ "recipientDeviceId": "device:AAAA:BBBB" });
        let leaves = leaves(&view);
        assert_eq!(
            leaves.get("recipientDeviceId#seg[1]").map(String::as_str),
            Some("AAAA")
        );
        assert_eq!(
            leaves.get("recipientDeviceId#seg[2]").map(String::as_str),
            Some("BBBB")
        );
        assert_eq!(root_path("recipientDeviceId#seg[1]"), "recipientDeviceId");
    }

    #[test]
    fn leaves_split_a_url_into_origin_path_and_query() {
        let view = json!({ "@url": "https://example.com/v1/inbox/device:AAAA:BBBB/messages?fromSeq=3&limit=100" });
        let leaves = leaves(&view);
        assert_eq!(
            leaves.get("@url#origin").map(String::as_str),
            Some("https://example.com")
        );
        assert_eq!(
            leaves.get("@url#path[2]").map(String::as_str),
            Some("device:AAAA:BBBB")
        );
        assert_eq!(
            leaves.get("@url#path[2]#seg[1]").map(String::as_str),
            Some("AAAA")
        );
        assert_eq!(
            leaves.get("@url#query.fromSeq").map(String::as_str),
            Some("3")
        );
    }

    #[test]
    fn leaves_decode_a_json_payload_carried_as_base64_or_as_text() {
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(br#"{"userId":"user:AAAA"}"#);
        let view = json!({ "bytes": encoded, "@header": { "X-Cap": r#"{"userId":"user:AAAA"}"# } });
        let leaves = leaves(&view);
        assert_eq!(
            leaves.get("bytes#b64.userId").map(String::as_str),
            Some("user:AAAA")
        );
        assert_eq!(
            leaves.get("@header.X-Cap#json.userId").map(String::as_str),
            Some("user:AAAA")
        );
    }

    #[test]
    fn leaves_read_the_cleartext_header_of_an_unwrapped_mls_frame() {
        let group_id = "the-group";
        let encoded = crate::leakage_ledger::representative_mls_frame(group_id);
        let frame = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .expect("base64");
        let view = json!({ "bytes": encoded });
        let unwrapped = leaves(&view);
        assert_eq!(
            unwrapped.get("bytes#mls.group_id").map(String::as_str),
            Some(group_id)
        );
        assert_eq!(
            unwrapped.get("bytes#mls.epoch").map(String::as_str),
            Some("3")
        );

        // And nothing at all once it is wrapped, which is the claim tab:inbox
        // makes about `bytes`.
        let wrapped = crate::lane_wrap::wrap_frame(&[0xA5; 32], &frame).expect("wrap");
        let view = json!({ "bytes": base64::engine::general_purpose::STANDARD.encode(&wrapped) });
        assert!(leaves(&view)
            .keys()
            .all(|path| !path.starts_with("bytes#mls")));
    }
}

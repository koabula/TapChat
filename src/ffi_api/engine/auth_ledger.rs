//! Checks for `contracts/auth-ledger.json`: every input from outside the
//! device that can change a direct session is listed, with the secret that
//! authenticates it and whether the peer's rotation replaces that secret.
//!
//! The leakage ledger records what a host sees; this one records who can
//! change a session. It is the executable form of the claim that injection
//! is confined to the exposure window: an input authenticated by something a
//! rotation does not replace has to be an exception or outside the model, and
//! say why.
//!
//! Completeness is structural. The maps below match exhaustively over the
//! enums that carry inputs, so a new variant does not compile until it is
//! given an entry, and every entry they name must exist in the ledger.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::lanes::InboundFrameResolution;
use crate::ffi_api::types::{CoreEvent, PendingRequest};
use crate::model::{MessageType, ProtectedPayloadKind};

const LEDGER: &str = include_str!("../../../contracts/auth-ledger.json");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    version: u32,
    invariant: String,
    scope: String,
    entries: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Entry {
    id: String,
    input: String,
    entry: String,
    scope: Scope,
    #[serde(default)]
    authenticated_by: Option<String>,
    #[serde(default)]
    rotates_with_p: Option<bool>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    witness: Vec<String>,
    #[serde(default)]
    routes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Scope {
    /// Inside the model: authenticated by a secret the peer's rotation replaces.
    Model,
    /// Inside the model's scope but authenticated otherwise, with the reason.
    Exception,
    /// Outside the model, with the reason it cannot inject.
    Excluded,
    /// Routes to the entries that decide it.
    Dispatch,
}

fn ledger() -> Ledger {
    serde_json::from_str(LEDGER).expect("auth ledger parses")
}

// ledger-map:start
#[allow(dead_code)]
fn core_event(event: &CoreEvent) -> &'static str {
    match event {
        CoreEvent::AppStarted { .. }
        | CoreEvent::AppForegrounded { .. }
        | CoreEvent::CredentialMaintenanceRequested { .. }
        | CoreEvent::WebSocketConnected { .. }
        | CoreEvent::WebSocketDisconnected { .. }
        | CoreEvent::AttachmentBytesLoaded { .. }
        | CoreEvent::BlobUploadPrepared { .. }
        | CoreEvent::BlobUploaded { .. }
        | CoreEvent::BlobTransferFailed { .. }
        | CoreEvent::BlobDeleted { .. }
        | CoreEvent::BlobDeleteFailed { .. }
        | CoreEvent::TimerTriggered { .. }
        | CoreEvent::UserConfirmedRebuild { .. } => "local",
        CoreEvent::RealtimeEventReceived { .. }
        | CoreEvent::WakeupReceived { .. }
        | CoreEvent::InboxRecordsFetched { .. } => "inbox-record",
        CoreEvent::InboxHistoryFloorAdvanced { .. } => "history-floor",
        CoreEvent::HttpResponseReceived { .. } => "host-response",
        CoreEvent::HttpRequestFailed { .. } => "host-failure",
        CoreEvent::IdentityBundleFetched { .. } => "identity-bundle",
        CoreEvent::IdentityBundleFetchFailed { .. } => "identity-fetch-failure",
        CoreEvent::MessageRequestsFetched { .. }
        | CoreEvent::MessageRequestsFetchFailed { .. }
        | CoreEvent::MessageRequestActionCompleted { .. }
        | CoreEvent::MessageRequestActionFailed { .. } => "message-requests",
        CoreEvent::AcceptedLaneRegistered { .. }
        | CoreEvent::AcceptedLaneRegisterFailed { .. }
        | CoreEvent::AcceptedLanesRevoked { .. }
        | CoreEvent::AcceptedLanesRevokeFailed { .. } => "own-lane-registration",
        CoreEvent::SharedStatePublished { .. } | CoreEvent::SharedStatePublishFailed { .. } => {
            "own-publication"
        }
        CoreEvent::BlobDownloaded { .. } => "attachment-bytes",
        CoreEvent::GroupOutboxFetched { .. }
        | CoreEvent::GroupHistoryFloorAdvanced { .. }
        | CoreEvent::GroupOutboxFetchFailed { .. }
        | CoreEvent::GroupOutboxHeadFetched { .. }
        | CoreEvent::GroupOutboxHeadFetchFailed { .. }
        | CoreEvent::GroupEnvelopeAppended { .. }
        | CoreEvent::GroupEnvelopeAppendFailed { .. }
        | CoreEvent::GroupTransitionAppended { .. }
        | CoreEvent::GroupTransitionAppendFailed { .. }
        | CoreEvent::GroupAuthorizationStateFetched { .. }
        | CoreEvent::GroupAuthorizationStateFetchFailed { .. }
        | CoreEvent::GroupAuthorizationInitialized { .. }
        | CoreEvent::GroupAuthorizationInitializeFailed { .. }
        | CoreEvent::GroupOutboxSealed { .. }
        | CoreEvent::GroupOutboxSealFailed { .. }
        | CoreEvent::WelcomePickupFetched { .. }
        | CoreEvent::WelcomePickupFetchFailed { .. }
        | CoreEvent::WelcomePickupPut { .. }
        | CoreEvent::WelcomePickupPutFailed { .. }
        | CoreEvent::GroupInviteCreated { .. }
        | CoreEvent::GroupInviteCreateFailed { .. }
        | CoreEvent::GroupInviteFetched { .. }
        | CoreEvent::GroupInviteFetchFailed { .. }
        | CoreEvent::GroupInviteRevoked { .. }
        | CoreEvent::GroupInvitesListed { .. }
        | CoreEvent::GroupJoinRequestSubmitted { .. }
        | CoreEvent::GroupJoinRequestSubmitFailed { .. }
        | CoreEvent::GroupJoinRequestsListed { .. }
        | CoreEvent::GroupJoinRequestStatusFetched { .. }
        | CoreEvent::GroupJoinDecisionApplied { .. }
        | CoreEvent::GroupJoinClaimed { .. }
        | CoreEvent::GroupJoinClaimFailed { .. }
        | CoreEvent::GroupJoinCompleted { .. }
        | CoreEvent::GroupJoinCompleteFailed { .. }
        | CoreEvent::GroupLeaveRequestSubmitted { .. }
        | CoreEvent::GroupLeaveRequestSubmitFailed { .. }
        | CoreEvent::GroupLeaveRequestsListed { .. }
        | CoreEvent::GroupLeaveClaimed { .. }
        | CoreEvent::GroupLeaveClaimFailed { .. }
        | CoreEvent::GroupJoinDecisionFailed { .. }
        | CoreEvent::GroupWebSocketConnected { .. }
        | CoreEvent::GroupWebSocketDisconnected { .. }
        | CoreEvent::GroupRealtimeEventReceived { .. } => "group-path",
    }
}

#[allow(dead_code)]
fn pending_request(request: &PendingRequest) -> &'static str {
    match request {
        PendingRequest::GetHead { .. } => "inbox-head",
        PendingRequest::FetchMessages { .. } => "inbox-record",
        PendingRequest::AppendEnvelope { .. } => "append-result",
        PendingRequest::Ack { .. } => "inbox-ack",
        PendingRequest::ClaimKeyPackage { .. } => "key-package-claim",
        PendingRequest::ReplenishKeyPackagePool { .. }
        | PendingRequest::KeyPackagePoolCount { .. } => "own-key-packages",
        PendingRequest::AppendGroupEnvelope { .. }
        | PendingRequest::FetchGroupOutbox { .. }
        | PendingRequest::PutWelcomePickup { .. }
        | PendingRequest::FetchWelcomePickup { .. }
        | PendingRequest::CreateGroupInvite { .. }
        | PendingRequest::SubmitGroupJoinRequest { .. }
        | PendingRequest::DecideGroupJoinRequest { .. } => "group-path",
    }
}

#[allow(dead_code)]
fn frame_resolution(resolution: &InboundFrameResolution) -> &'static str {
    match resolution {
        InboundFrameResolution::Ready { .. } => "mls-frame",
        InboundFrameResolution::Deferred { .. } => "quarantine",
        InboundFrameResolution::Rejected { .. } => "rejected-record",
        InboundFrameResolution::Forked { .. } => "fork-evidence",
    }
}

#[allow(dead_code)]
fn message_type(message_type: MessageType) -> &'static str {
    match message_type {
        MessageType::MlsApplication => "application-frame",
        MessageType::MlsCommit => "commit",
        MessageType::MlsProposal => "proposal",
        MessageType::MlsWelcome => "welcome",
        MessageType::ControlDeviceMembershipChanged
        | MessageType::ControlIdentityStateUpdated
        | MessageType::ControlConversationNeedsRebuild
        | MessageType::ControlContactRemoved
        | MessageType::ControlContactAccepted
        | MessageType::ControlGroupWelcomePickup
        | MessageType::ControlGroupStateEvent => "not-on-direct-path",
    }
}

#[allow(dead_code)]
fn payload_kind(kind: ProtectedPayloadKind) -> &'static str {
    match kind {
        ProtectedPayloadKind::Text | ProtectedPayloadKind::Attachment => "application-frame",
        ProtectedPayloadKind::LaneRotation => "lane-announcement",
        ProtectedPayloadKind::ContactAccepted => "contact-accepted",
        ProtectedPayloadKind::ContactRemoved => "contact-removed",
        ProtectedPayloadKind::GroupWelcomePickup => "group-welcome-pickup",
    }
}
// ledger-map:end

/// Every id the maps above name, read from this file's own source.
fn mapped_ids() -> BTreeSet<String> {
    let source = include_str!("auth_ledger.rs");
    let start = source.find("// ledger-map:start").expect("map start");
    let end = source.find("// ledger-map:end").expect("map end");
    source[start..end]
        .split("=>")
        .skip(1)
        .filter_map(|arm| {
            let arm = arm.trim_start();
            let arm = arm.strip_prefix('{').unwrap_or(arm).trim_start();
            arm.strip_prefix('"')?.split('"').next()
        })
        .map(str::to_string)
        .collect()
}

fn source_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read src") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            source_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn defined_functions() -> BTreeSet<String> {
    let mut files = Vec::new();
    source_files(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    let mut names = BTreeSet::new();
    for file in files {
        let text = std::fs::read_to_string(&file).expect("read source");
        for piece in text.split("fn ").skip(1) {
            let name: String = piece
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                names.insert(name);
            }
        }
    }
    names
}

#[test]
fn ledger_is_well_formed() {
    let ledger = ledger();
    assert_eq!(ledger.version, 1);
    assert!(!ledger.invariant.trim().is_empty() && !ledger.scope.trim().is_empty());
    let mut ids = BTreeSet::new();
    for entry in &ledger.entries {
        assert!(
            ids.insert(entry.id.as_str()),
            "{} is listed twice",
            entry.id
        );
        assert!(
            !entry.input.trim().is_empty(),
            "{} names no input",
            entry.id
        );
    }
    for entry in &ledger.entries {
        if entry.scope == Scope::Dispatch {
            assert!(!entry.routes.is_empty(), "{} routes nowhere", entry.id);
            assert!(
                entry.authenticated_by.is_none()
                    && entry.rotates_with_p.is_none()
                    && entry.witness.is_empty(),
                "{} dispatches; the entries it routes to carry the claims",
                entry.id
            );
            for route in &entry.routes {
                assert!(
                    ids.contains(route.as_str()),
                    "{} routes to unknown {route}",
                    entry.id
                );
            }
            continue;
        }
        assert!(
            entry.routes.is_empty(),
            "{} decides; it routes nowhere",
            entry.id
        );
        assert!(
            entry
                .authenticated_by
                .as_deref()
                .is_some_and(|by| !by.trim().is_empty()),
            "{} does not say what authenticates it",
            entry.id
        );
        let rotates = entry.rotates_with_p.unwrap_or_else(|| {
            panic!(
                "{} does not say whether rotation replaces its secret",
                entry.id
            )
        });
        assert!(!entry.witness.is_empty(), "{} has no witness", entry.id);
        match entry.scope {
            Scope::Model => assert!(
                rotates,
                "{} is in the model but authenticated by something rotation does not replace",
                entry.id
            ),
            Scope::Exception | Scope::Excluded => assert!(
                entry
                    .reason
                    .as_deref()
                    .is_some_and(|reason| !reason.trim().is_empty()),
                "{} is not in the model and gives no reason",
                entry.id
            ),
            Scope::Dispatch => unreachable!(),
        }
    }
}

#[test]
fn every_entry_and_witness_exists_in_source() {
    let defined = defined_functions();
    for entry in ledger().entries {
        assert!(
            defined.contains(&entry.entry),
            "{}: no fn {}",
            entry.id,
            entry.entry
        );
        for witness in &entry.witness {
            assert!(
                defined.contains(witness),
                "{}: no witness fn {witness}",
                entry.id
            );
        }
    }
}

#[test]
fn every_input_is_in_the_ledger() {
    let ids: BTreeSet<String> = ledger().entries.into_iter().map(|entry| entry.id).collect();
    for id in mapped_ids() {
        assert!(
            ids.contains(&id),
            "an input maps to {id}, which the ledger does not list"
        );
    }
}

#[test]
fn every_entry_is_reachable_from_an_input() {
    let ledger = ledger();
    let routes: BTreeMap<&str, &Vec<String>> = ledger
        .entries
        .iter()
        .map(|entry| (entry.id.as_str(), &entry.routes))
        .collect();
    let mut reached: BTreeSet<String> = BTreeSet::new();
    let mut frontier: Vec<String> = mapped_ids().into_iter().collect();
    while let Some(id) = frontier.pop() {
        if reached.insert(id.clone()) {
            if let Some(next) = routes.get(id.as_str()) {
                frontier.extend(next.iter().cloned());
            }
        }
    }
    for entry in &ledger.entries {
        assert!(
            reached.contains(&entry.id),
            "{} is listed but no input reaches it",
            entry.id
        );
    }
}

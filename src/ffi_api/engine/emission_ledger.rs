//! Checks for `contracts/emission-ledger.json`: every record a client emits
//! in a direct session has a listed trigger, and every network effect reaches
//! one of the two parties' own components.
//!
//! The auth ledger records who can change a session; the leakage ledger, what
//! a host sees in a record. This one records why a record is emitted at all,
//! which is what the simulator needs in order to emit it at the right time:
//! the note's observable-schedule lemma, checked rather than inspected.
//!
//! Completeness is structural, as in the auth ledger. The maps below match
//! exhaustively over the effect enums, so a new kind of effect does not
//! compile until it names a point. A scan of the engine's source finds every
//! function that queues a record for a peer, so a new one fails the test
//! until the ledger gives it a trigger.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Deserialize;

use crate::ffi_api::types::{CoreEffect, PendingRequest};

const LEDGER: &str = include_str!("../../../contracts/emission-ledger.json");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    version: u32,
    invariant: String,
    scope: String,
    points: BTreeMap<String, String>,
    triggers: BTreeMap<String, String>,
    emitters: Vec<String>,
    sites: Vec<Site>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Site {
    #[serde(rename = "fn")]
    function: String,
    trigger: String,
    emits: String,
    #[serde(default)]
    reason: Option<String>,
}

fn ledger() -> Ledger {
    serde_json::from_str(LEDGER).expect("emission ledger parses")
}

/// An HTTP effect reaches the point of the request it was registered under.
const VIA_PENDING_REQUEST: &str = "via-pending-request";

// ledger-map:start
#[allow(dead_code)]
fn core_effect(effect: &CoreEffect) -> &'static str {
    match effect {
        CoreEffect::ExecuteHttpRequest { .. } => VIA_PENDING_REQUEST,
        CoreEffect::OpenRealtimeConnection { .. }
        | CoreEffect::CloseRealtimeConnection { .. }
        | CoreEffect::FetchMessageRequests { .. }
        | CoreEffect::ActOnMessageRequest { .. }
        | CoreEffect::RegisterAcceptedLane { .. }
        | CoreEffect::RevokeAcceptedLanes { .. } => "own-inbox",
        CoreEffect::PublishSharedState { .. } | CoreEffect::DownloadBlob { .. } => "own-storage",
        CoreEffect::PrepareBlobUpload { .. } => "peer-inbox",
        CoreEffect::UploadBlob { .. }
        | CoreEffect::DeleteBlob { .. }
        | CoreEffect::FetchIdentityBundle { .. } => "peer-storage",
        CoreEffect::ReadAttachmentBytes { .. }
        | CoreEffect::WriteDownloadedAttachment { .. }
        | CoreEffect::CacheUploadedAttachment { .. }
        | CoreEffect::ReleaseStagedAttachment { .. }
        | CoreEffect::PersistState { .. }
        | CoreEffect::ScheduleTimer { .. }
        | CoreEffect::EmitUserNotification { .. } => "local",
        CoreEffect::OpenGroupRealtimeConnection { .. }
        | CoreEffect::CloseGroupRealtimeConnection { .. }
        | CoreEffect::AppendGroupEnvelope { .. }
        | CoreEffect::AppendGroupTransition { .. }
        | CoreEffect::InitializeGroupAuthorization { .. }
        | CoreEffect::FetchGroupOutbox { .. }
        | CoreEffect::GetGroupOutboxHead { .. }
        | CoreEffect::GetGroupAuthorizationState { .. }
        | CoreEffect::SealGroupOutbox { .. }
        | CoreEffect::FetchWelcomePickup { .. }
        | CoreEffect::PutWelcomePickup { .. }
        | CoreEffect::CreateGroupInvite { .. }
        | CoreEffect::RevokeGroupInvite { .. }
        | CoreEffect::ListGroupInvites { .. }
        | CoreEffect::FetchGroupInvite { .. }
        | CoreEffect::SubmitGroupJoinRequest { .. }
        | CoreEffect::ListGroupJoinRequests { .. }
        | CoreEffect::GetGroupJoinRequestStatus { .. }
        | CoreEffect::DecideGroupJoinRequest { .. }
        | CoreEffect::ClaimGroupJoinRequest { .. }
        | CoreEffect::CompleteGroupJoinRequest { .. }
        | CoreEffect::SubmitGroupLeaveRequest { .. }
        | CoreEffect::ListGroupLeaveRequests { .. }
        | CoreEffect::ClaimGroupLeaveRequest { .. } => "group-path",
    }
}

#[allow(dead_code)]
fn pending_request(request: &PendingRequest) -> &'static str {
    match request {
        PendingRequest::GetHead { .. }
        | PendingRequest::FetchMessages { .. }
        | PendingRequest::Ack { .. }
        | PendingRequest::ReplenishKeyPackagePool
        | PendingRequest::KeyPackagePoolCount => "own-inbox",
        PendingRequest::AppendEnvelope { .. } | PendingRequest::ClaimKeyPackage { .. } => {
            "peer-inbox"
        }
        PendingRequest::AppendGroupEnvelope { .. }
        | PendingRequest::FetchGroupOutbox { .. }
        | PendingRequest::PutWelcomePickup { .. }
        | PendingRequest::FetchWelcomePickup { .. }
        | PendingRequest::CreateGroupInvite { .. }
        | PendingRequest::SubmitGroupJoinRequest { .. }
        | PendingRequest::DecideGroupJoinRequest { .. } => "group-path",
    }
}
// ledger-map:end

/// Every point the maps above name, read from this file's own source.
fn mapped_points() -> BTreeSet<String> {
    let source = include_str!("emission_ledger.rs");
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

/// The engine's functions, each with the calls of an emitter it makes. A
/// function's body runs to the next `fn`, which is coarse but enough: the
/// engine nests no functions inside the ones that queue records. Test modules
/// are left out, since they drive the engine rather than emit.
fn functions_calling(emitters: &[String]) -> BTreeMap<String, BTreeSet<String>> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ffi_api/engine");
    let mut calls: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for entry in std::fs::read_dir(dir).expect("read engine") {
        let path = entry.expect("dir entry").path();
        if path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .expect("read source")
            .replace("\r\n", "\n");
        let text = text
            .split("#[cfg(test)]\nmod tests")
            .next()
            .unwrap_or_default();
        for piece in text.split("fn ").skip(1) {
            let name: String = piece
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            let called = calls.entry(name).or_default();
            for emitter in emitters {
                if piece.contains(&format!(".{emitter}(")) {
                    called.insert(emitter.clone());
                }
            }
        }
    }
    calls
}

#[test]
fn ledger_is_well_formed() {
    let ledger = ledger();
    assert_eq!(ledger.version, 1);
    assert!(!ledger.invariant.trim().is_empty() && !ledger.scope.trim().is_empty());
    let mut seen = BTreeSet::new();
    for site in &ledger.sites {
        assert!(
            seen.insert(site.function.as_str()),
            "{} is listed twice",
            site.function
        );
        assert!(
            ledger.triggers.contains_key(&site.trigger),
            "{} has the unknown trigger {}",
            site.function,
            site.trigger
        );
        assert!(
            !site.emits.trim().is_empty(),
            "{} says nothing of what it emits",
            site.function
        );
        assert_eq!(
            site.trigger == "out-of-scope",
            site.reason.as_deref().is_some_and(|r| !r.trim().is_empty()),
            "{}: a reason is given exactly when the site is out of scope",
            site.function
        );
        assert!(
            !ledger.emitters.contains(&site.function),
            "{} is both an emitter and a site",
            site.function
        );
    }
}

/// The points are the two parties' own components, and nothing else that
/// leaves the device. A push service, or any third party, would be a new
/// point here and a change to the model.
#[test]
fn every_effect_reaches_a_point_of_one_of_the_two_parties() {
    let ledger = ledger();
    let listed: BTreeSet<&str> = ledger.points.keys().map(String::as_str).collect();
    assert_eq!(
        listed,
        BTreeSet::from([
            "own-inbox",
            "own-storage",
            "peer-inbox",
            "peer-storage",
            "local",
            "group-path",
        ]),
        "the points changed; the model has one inbox and one storage per party"
    );
    let mapped = mapped_points();
    for point in &mapped {
        assert!(
            listed.contains(point.as_str()),
            "an effect reaches {point}, which the ledger does not list"
        );
    }
    for point in listed {
        assert!(mapped.contains(point), "no effect reaches {point}");
    }
}

#[test]
fn every_function_that_queues_a_record_has_a_trigger() {
    let ledger = ledger();
    let calls = functions_calling(&ledger.emitters);
    let sites: BTreeSet<&str> = ledger.sites.iter().map(|s| s.function.as_str()).collect();
    for (function, called) in &calls {
        if called.is_empty() || ledger.emitters.contains(function) {
            continue;
        }
        assert!(
            sites.contains(function.as_str()),
            "{function} queues a record through {called:?} and the emission ledger \
             gives it no trigger"
        );
    }
    for site in &ledger.sites {
        assert!(
            calls.get(&site.function).is_some_and(|c| !c.is_empty()),
            "{} is listed as a site but queues nothing",
            site.function
        );
    }
    for emitter in &ledger.emitters {
        assert!(
            calls.contains_key(emitter),
            "the emitter {emitter} is not defined in the engine"
        );
    }
}

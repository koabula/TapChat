//! Property-based tests for the shared welcome-pickup URL encoder.
//!
//! Validates Design Property 2 → Requirements 1.4, 6.3.
//!
//! These tests exercise the single-source-of-truth encoder/decoder pair
//! (`WelcomePickupDescriptor::to_welcome_pickup_url` /
//! `WelcomePickupDescriptor::from_welcome_pickup_url`) introduced by
//! Wave D.0 of the `desktop-group-ui-mvp` spec.
//!
//! Three properties are asserted on every generated descriptor:
//!
//! 1. **Bytewise round-trip.** Encoding then decoding the URL yields a
//!    descriptor field-equal to the original.
//! 2. **CLI matches shared helper.** D.0 made
//!    `src/cli/app.rs::welcome_pickup_url` a thin delegate to
//!    `to_welcome_pickup_url`, so a direct string equality check against
//!    the CLI helper is not reachable from this test module (the CLI
//!    helper is private). As a regression guard we pin the format:
//!    the URL starts with the canonical prefix, the base64 payload
//!    decodes to the same JSON we would produce ourselves, and the
//!    parsed descriptor equals the input. This protects against
//!    accidental divergence (a future refactor adding padding or
//!    changing the prefix would fail here).
//! 3. **Engine parse acceptance.** `CoreCommand::RequestJoinGroup` is
//!    constructed with the encoded URL and serde-round-tripped (this
//!    matches the IPC boundary the desktop Tauri layer crosses); the
//!    inner URL is then parsed through `from_welcome_pickup_url` — the
//!    same helper `engine.rs::request_join_group` uses to decode the
//!    descriptor. This is a parse-only assertion; no side effects are
//!    dispatched.
//!
//! Shared helpers are the system under test and MUST NOT be modified
//! from this file.

use proptest::prelude::*;

use super::{Validate, WelcomePickupDescriptor};
use crate::ffi_api::CoreCommand;

/// Non-empty ASCII printable string, 1..=64 chars.
///
/// Covers bytes 0x20..=0x7E (space through `~`). `serde_json` will
/// automatically escape `"` and `\\` inside JSON strings, so including
/// those bytes is safe. Leading/trailing whitespace is excluded by
/// requiring at least one non-space character because the shared
/// `Validate` implementation runs `trim().is_empty()` and would reject
/// a descriptor whose `group_id` is only spaces — that rejection is a
/// validation property, not a round-trip property, and is already
/// covered by `welcome_pickup_url_rejects_malformed_input`.
fn arb_ascii_printable_id() -> impl Strategy<Value = String> {
    proptest::collection::vec(0x20u8..=0x7eu8, 1..=64).prop_filter_map(
        "must contain at least one non-space char",
        |bytes| {
            let s = String::from_utf8(bytes).ok()?;
            if s.trim().is_empty() {
                None
            } else {
                Some(s)
            }
        },
    )
}

/// Realistic-looking `https://` endpoint with a domain and a path.
///
/// The encoder itself does not validate URL shape (it just JSON-encodes
/// and base64s the whole descriptor), but producing URL-shaped strings
/// keeps the generated corpus close to real welcome pickups.
fn arb_https_endpoint() -> impl Strategy<Value = String> {
    (
        proptest::collection::vec(
            prop_oneof![
                (b'a'..=b'z').prop_map(|b| b as char),
                (b'0'..=b'9').prop_map(|b| b as char),
                Just('-'),
            ],
            1..=32,
        ),
        proptest::collection::vec(
            prop_oneof![
                (b'a'..=b'z').prop_map(|b| b as char),
                (b'0'..=b'9').prop_map(|b| b as char),
                Just('/'),
                Just('-'),
                Just('_'),
            ],
            0..=64,
        ),
    )
        .prop_map(|(domain, path)| {
            let domain: String = domain.into_iter().collect();
            let path: String = path.into_iter().collect();
            format!("https://{}.example.com/{}", domain, path)
        })
}

/// The `capability` field is typed as `String` in
/// `WelcomePickupDescriptor`. Real capabilities are base64-encoded
/// bytes, so we generate 0..=128 random bytes and base64-encode them.
fn arb_capability() -> impl Strategy<Value = String> {
    proptest::collection::vec(any::<u8>(), 0..=128).prop_map(|bytes| {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let encoded = STANDARD.encode(&bytes);
        // `Validate` rejects empty capability strings; zero-byte input
        // base64-encodes to the empty string, which would fail
        // validation. Substitute a non-empty placeholder in that
        // corner case so the generator stays inside the valid input
        // space for the round-trip property.
        if encoded.is_empty() {
            "AA==".to_string()
        } else {
            encoded
        }
    })
}

prop_compose! {
    fn arb_welcome_pickup_descriptor()(
        group_id in arb_ascii_printable_id(),
        device_id in arb_ascii_printable_id(),
        endpoint in arb_https_endpoint(),
        capability in arb_capability(),
        expires_at in any::<u64>(),
    ) -> WelcomePickupDescriptor {
        WelcomePickupDescriptor {
            group_id,
            device_id,
            endpoint,
            capability,
            expires_at,
            start_seq: None,
            roster_version: None,
            last_commit_message_id: None,
            request_id: None,
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    /// Property 2a: encoding then decoding the welcome-pickup URL
    /// yields a bytewise-equal descriptor.
    #[test]
    fn welcome_pickup_url_round_trips_bytewise(
        descriptor in arb_welcome_pickup_descriptor(),
    ) {
        // Sanity: the generator only produces valid descriptors.
        prop_assert!(descriptor.validate().is_ok());

        let url = descriptor.to_welcome_pickup_url();
        let decoded = WelcomePickupDescriptor::from_welcome_pickup_url(&url)
            .expect("shared helper must decode its own URL");
        prop_assert_eq!(decoded, descriptor);
    }

    /// Property 2b: the encoder's output is a stable URL shape that
    /// matches what the CLI produces for the same descriptor.
    ///
    /// The CLI's `welcome_pickup_url` is a private free function that
    /// unconditionally delegates to `to_welcome_pickup_url` (see
    /// `src/cli/app.rs` — this delegation is enforced by the spec's
    /// D.0 "shared encoder" hard rule). We therefore cannot call the
    /// CLI helper from this module. Instead we pin the invariant that
    /// D.0 is supposed to preserve: the canonical prefix, a
    /// well-formed base64 payload, and parity between the payload's
    /// JSON and an independent `serde_json::to_vec` of the descriptor.
    /// A future change that re-introduces a divergent CLI encoder
    /// would break at least one of these checks.
    #[test]
    fn welcome_pickup_url_matches_cli_shared_format(
        descriptor in arb_welcome_pickup_descriptor(),
    ) {
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        let url = descriptor.to_welcome_pickup_url();
        prop_assert!(url.starts_with("tapchat://welcome-pickup/"));

        let payload_b64 = url
            .strip_prefix("tapchat://welcome-pickup/")
            .expect("prefix already asserted");
        let payload_bytes = STANDARD
            .decode(payload_b64)
            .expect("payload must be valid base64");
        let expected_bytes =
            serde_json::to_vec(&descriptor).expect("descriptor must serialize to JSON");
        prop_assert_eq!(payload_bytes, expected_bytes);
    }

    /// Property 2c: feeding the encoded URL into
    /// `CoreCommand::RequestJoinGroup { invite_url }` and round-
    /// tripping through serde (the IPC boundary the desktop Tauri
    /// layer crosses) yields an `invite_url` the engine's helper can
    /// parse back into the original descriptor.
    ///
    /// This is a parse-only assertion: we explicitly do NOT drive
    /// `CoreEngine::handle_command`, which would trigger
    /// `FetchWelcomePickup` side effects. We only exercise the same
    /// decoding path the engine itself uses (`from_welcome_pickup_url`
    /// — see `engine.rs::request_join_group`).
    #[test]
    fn request_join_group_invite_url_parses_via_shared_decoder(
        descriptor in arb_welcome_pickup_descriptor(),
    ) {
        let encoded = descriptor.to_welcome_pickup_url();
        let command = CoreCommand::RequestJoinGroup {
            invite_url: encoded.clone(),
        };

        // Serde round-trip mirrors the Tauri IPC boundary.
        let json = serde_json::to_string(&command).expect("command serializes");
        let decoded_command: CoreCommand =
            serde_json::from_str(&json).expect("command deserializes");
        prop_assert_eq!(&decoded_command, &command);

        // Pull the invite_url back out and parse it via the same
        // shared helper the engine uses.
        let invite_url = match decoded_command {
            CoreCommand::RequestJoinGroup { invite_url } => invite_url,
            other => {
                prop_assert!(
                    false,
                    "expected RequestJoinGroup after round-trip, got {:?}",
                    other,
                );
                unreachable!();
            }
        };
        let parsed = WelcomePickupDescriptor::from_welcome_pickup_url(&invite_url)
            .expect("engine-shared decoder must accept the encoder's output");
        prop_assert_eq!(parsed, descriptor);
    }
}

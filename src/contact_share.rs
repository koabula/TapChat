use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;

use crate::error::{CoreError, CoreResult};
use crate::external_fetch::{decoded_path_segments, validate_external_url, ExternalResourceKind};
use crate::model::CURRENT_MODEL_VERSION;

const CONTACT_SHARE_SERVICE: &str = "contact_share";

pub fn encode_contact_share_url(
    base_url: &str,
    secret: &str,
    user_id: &str,
    share_id: &str,
) -> CoreResult<String> {
    if base_url.trim().is_empty()
        || secret.is_empty()
        || user_id.trim().is_empty()
        || share_id.trim().is_empty()
    {
        return Err(CoreError::invalid_input(
            "contact share URL inputs must not be empty",
        ));
    }
    let payload = serde_json::json!({
        "version": CURRENT_MODEL_VERSION,
        "service": CONTACT_SHARE_SERVICE,
        "userId": user_id,
        "shareId": share_id,
    });
    let payload_bytes = serde_json::to_vec(&payload)
        .map_err(|_| CoreError::invalid_state("failed to encode contact share payload"))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| CoreError::invalid_state("failed to initialize contact share signer"))?;
    mac.update(&payload_bytes);
    let signature = mac.finalize().into_bytes();
    let token = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(payload_bytes),
        URL_SAFE_NO_PAD.encode(signature)
    );
    Ok(format!(
        "{}/v1/contact-share/{token}",
        base_url.trim_end_matches('/')
    ))
}

/// The user_id a contact share or identity bundle URL names: the `userId` in
/// the token of `/v1/contact-share/{token}`, or the `{user_id}` segment of
/// `/v1/shared-state/{user_id}/identity-bundle`.
///
/// The host behind the URL can serve any bundle that verifies against its own
/// root key, so a bundle fetched from the URL is the named user's only if it
/// carries this user_id.
pub fn contact_share_url_user_id(raw_url: &str) -> CoreResult<String> {
    let decoded = validate_external_url(raw_url, ExternalResourceKind::ContactShare)
        .and_then(|url| decoded_path_segments(&url))
        .map_err(|error| {
            CoreError::invalid_input(format!("contact share link is invalid: {error}"))
        })?;
    let segments: Vec<&str> = decoded.iter().map(String::as_str).collect();
    match segments.as_slice() {
        ["v1", "contact-share", token] => contact_share_token_user_id(token),
        ["v1", "shared-state", user_id, "identity-bundle"] if !user_id.trim().is_empty() => {
            Ok(user_id.to_string())
        }
        _ => Err(no_user_id()),
    }
}

/// The user_id a contact share token names.
///
/// The token is `base64url(payload) "." base64url(hmac)`. The HMAC is keyed
/// with the host's sharing secret, so only the host can check it; it must
/// still be present and well formed.
pub fn contact_share_token_user_id(token: &str) -> CoreResult<String> {
    let (payload_part, signature_part) = token.split_once('.').ok_or_else(malformed_token)?;
    if payload_part.is_empty() || signature_part.is_empty() {
        return Err(malformed_token());
    }
    URL_SAFE_NO_PAD
        .decode(signature_part)
        .map_err(|_| malformed_token())?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload_part)
        .map_err(|_| malformed_token())?;
    let payload: Value = serde_json::from_slice(&bytes).map_err(|_| malformed_payload())?;
    let payload = payload.as_object().ok_or_else(malformed_payload)?;
    if payload.get("service").and_then(Value::as_str) != Some(CONTACT_SHARE_SERVICE) {
        return Err(CoreError::invalid_input(
            "contact share link is not for the contact_share service",
        ));
    }
    payload
        .get("userId")
        .and_then(Value::as_str)
        .filter(|user_id| !user_id.trim().is_empty())
        .map(String::from)
        .ok_or_else(no_user_id)
}

fn malformed_token() -> CoreError {
    CoreError::invalid_input("contact share link token is malformed")
}

fn malformed_payload() -> CoreError {
    CoreError::invalid_input("contact share link payload is malformed")
}

fn no_user_id() -> CoreError {
    CoreError::invalid_input("contact share link does not name a user")
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use serde_json::json;

    use super::{contact_share_token_user_id, contact_share_url_user_id, encode_contact_share_url};

    fn token(payload: serde_json::Value) -> String {
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("json"));
        let signature = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        format!("{payload}.{signature}")
    }

    fn share_url(token: &str) -> String {
        format!("https://runtime.example/v1/contact-share/{token}")
    }

    fn assert_token_rejected(token: &str, expected: &str) {
        let error = contact_share_token_user_id(token).expect_err("token must be rejected");
        assert_eq!(error.code(), "invalid_input");
        assert!(error.message().contains(expected), "{token}: {error}");
    }

    fn assert_url_rejected(url: &str, expected: &str) {
        let error = contact_share_url_user_id(url).expect_err("URL must be rejected");
        assert_eq!(error.code(), "invalid_input");
        assert!(error.message().contains(expected), "{url}: {error}");
    }

    #[test]
    fn encoder_only_emits_canonical_contact_share_path() {
        let url = encode_contact_share_url(
            "https://runtime.example/",
            "0123456789abcdef0123456789abcdef",
            "user:alice",
            "share:1",
        )
        .expect("contact share URL");
        assert!(url.starts_with("https://runtime.example/v1/contact-share/"));
        assert!(!url.contains("identity-bundle"));
    }

    #[test]
    fn user_id_is_read_from_both_url_forms() {
        let encoded = encode_contact_share_url(
            "https://runtime.example/",
            "0123456789abcdef0123456789abcdef",
            "user:alice",
            "share:1",
        )
        .expect("contact share URL");
        let user_id = contact_share_url_user_id(&encoded).expect("token form");
        assert_eq!(user_id, "user:alice");

        let bundle_url = "https://runtime.example/v1/shared-state/user%3Aalice/identity-bundle";
        let user_id = contact_share_url_user_id(bundle_url).expect("path form");
        assert_eq!(user_id, "user:alice");

        // The HMAC is the host's to check; the client reads only the payload.
        let unchecked = token(json!({"service": "contact_share", "userId": "user:bob"}));
        let user_id = contact_share_url_user_id(&share_url(&unchecked)).expect("token form");
        assert_eq!(user_id, "user:bob");
    }

    #[test]
    fn malformed_tokens_and_payloads_are_rejected() {
        let body = URL_SAFE_NO_PAD.encode(br#"{"service":"contact_share","userId":"user:a"}"#);
        let sig = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        assert_token_rejected("no-separator", "token is malformed");
        assert_token_rejected(&format!("{body}."), "token is malformed");
        assert_token_rejected(&format!(".{sig}"), "token is malformed");
        assert_token_rejected(&format!("{body}.not+base64url"), "token is malformed");
        assert_token_rejected(&format!("{body}.{sig}.{sig}"), "token is malformed");
        assert_token_rejected(&format!("!!!.{sig}"), "token is malformed");

        let not_json = URL_SAFE_NO_PAD.encode(b"not json");
        assert_token_rejected(&format!("{not_json}.{sig}"), "payload is malformed");
        let not_object = URL_SAFE_NO_PAD.encode(br#"["contact_share","user:a"]"#);
        assert_token_rejected(&format!("{not_object}.{sig}"), "payload is malformed");
    }

    #[test]
    fn payload_must_be_a_contact_share_that_names_a_user() {
        let wrong_service = token(json!({"service": "group_invite", "userId": "user:a"}));
        assert_token_rejected(&wrong_service, "not for the contact_share service");
        let no_service = token(json!({"userId": "user:a"}));
        assert_token_rejected(&no_service, "not for the contact_share service");
        let no_user = token(json!({"service": "contact_share"}));
        assert_token_rejected(&no_user, "does not name a user");
        let blank_user = token(json!({"service": "contact_share", "userId": " "}));
        assert_token_rejected(&blank_user, "does not name a user");
        let numeric_user = token(json!({"service": "contact_share", "userId": 7}));
        assert_token_rejected(&numeric_user, "does not name a user");
    }

    #[test]
    fn urls_that_name_no_user_are_rejected() {
        let no_user = token(json!({"service": "contact_share"}));
        assert_url_rejected(&share_url(&no_user), "does not name a user");
        let wrong_service = token(json!({"service": "group_invite", "userId": "user:a"}));
        assert_url_rejected(&share_url(&wrong_service), "contact_share service");
        assert_url_rejected(&share_url("not-a-token"), "token is malformed");
        assert_url_rejected(
            "https://runtime.example/v1/shared-state/%20/identity-bundle",
            "does not name a user",
        );
        for invalid in [
            "https://runtime.example/v1/shared-state//identity-bundle",
            "https://runtime.example/v1/shared-state/user%3Aa/device-status",
            "https://runtime.example/v1/group-invite/token",
            "file:///v1/shared-state/user%3Aa/identity-bundle",
        ] {
            assert_url_rejected(invalid, "link is invalid");
        }
    }
}

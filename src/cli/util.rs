use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;

pub use crate::transport_contract::json_case::{
    camel_to_snake_value, snake_to_camel_value, to_camel_case_json_string,
    to_snake_case_json_string,
};

pub fn sign_hmac_token(secret: &str, payload: &Value) -> Result<String> {
    let payload_bytes = serde_json::to_vec(payload)?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).context("failed to initialize hmac")?;
    mac.update(&payload_bytes);
    let signature = mac.finalize().into_bytes();
    Ok(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(payload_bytes),
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

/// Best-effort extraction of the `error` or `code` field from a JSON body
/// returned by the Cloudflare group outbox. Both field names are accepted
/// because the current worker returns `{ "error": "..." }` but historical
/// clients observe `{ "code": "..." }` as well.
pub fn extract_error_code(body: &str) -> Option<String> {
    let value: Value = serde_json::from_str(body).ok()?;
    value
        .get("error")
        .or_else(|| value.get("code"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Best-effort extraction of `sealed_at` from a JSON body returned by
/// the Cloudflare group outbox seal endpoint. Returns `None` when the
/// field is missing or not a number — callers can fall back to `0` or
/// the current wall clock as appropriate.
pub fn extract_sealed_at(body: &str) -> Option<u64> {
    let value: Value = serde_json::from_str(body).ok()?;
    value.get("sealed_at").and_then(|v| v.as_u64())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{camel_to_snake_value, snake_to_camel_value};

    #[test]
    fn json_key_transforms_round_trip() {
        let original = json!({
            "device_id": "device:alice:phone",
            "storage_refs": [{ "mime_type": "text/plain", "size_bytes": 4, "ref": "blob:1" }],
            "sender_proof": { "type": "signature", "value": "proof" },
            "wake_hint": { "latest_seq_hint": 2 }
        });
        let camel = snake_to_camel_value(original.clone());
        assert_eq!(camel["deviceId"], "device:alice:phone");
        assert_eq!(camel["storageRefs"][0]["mimeType"], "text/plain");
        let snake = camel_to_snake_value(camel);
        assert_eq!(snake, original);
    }
}

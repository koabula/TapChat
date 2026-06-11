use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
pub use tapchat_core::transport_contract::json_case::{
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
        assert_eq!(camel["storageRefs"][0]["ref"], "blob:1");
        assert_eq!(camel["senderProof"]["type"], "signature");
        let snake = camel_to_snake_value(camel);
        assert_eq!(snake, original);
    }
}

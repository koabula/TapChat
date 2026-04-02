use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::Sha256;

pub fn sign_hmac_token(secret: &str, payload: &Value) -> Result<String> {
    let payload_bytes = serde_json::to_vec(payload)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .context("failed to initialize hmac")?;
    mac.update(&payload_bytes);
    let signature = mac.finalize().into_bytes();
    Ok(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(payload_bytes),
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

pub fn to_camel_case_json_string(input: &str) -> Result<String> {
    let value: Value = serde_json::from_str(input)?;
    Ok(serde_json::to_string(&snake_to_camel_value(value))?)
}

pub fn to_snake_case_json_string(input: &str) -> Result<String> {
    let value: Value = serde_json::from_str(input)?;
    Ok(serde_json::to_string(&camel_to_snake_value(value))?)
}

pub fn snake_to_camel_value(value: Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.into_iter().map(snake_to_camel_value).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (snake_to_camel(&key), snake_to_camel_value(value)))
                .collect::<Map<String, Value>>(),
        ),
        other => other,
    }
}

pub fn camel_to_snake_value(value: Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.into_iter().map(camel_to_snake_value).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (camel_to_snake(&key), camel_to_snake_value(value)))
                .collect::<Map<String, Value>>(),
        ),
        other => other,
    }
}

fn snake_to_camel(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut uppercase = false;
    for ch in value.chars() {
        if ch == '_' {
            uppercase = true;
        } else if uppercase {
            output.extend(ch.to_uppercase());
            uppercase = false;
        } else {
            output.push(ch);
        }
    }
    output
}

fn camel_to_snake(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 4);
    for (index, ch) in value.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if index > 0 {
                output.push('_');
            }
            output.push(ch.to_ascii_lowercase());
        } else {
            output.push(ch);
        }
    }
    output
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

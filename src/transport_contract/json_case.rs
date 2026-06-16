use anyhow::Result;
use serde_json::{Map, Value};

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

    #[test]
    fn transport_json_case_handles_inbox_and_group_contracts() {
        let snake = json!({
            "records": [{
                "message_id": "msg:1",
                "sender_device_id": "device:alice:phone",
                "membership_proof": {
                    "previous_roster_version": 7,
                    "new_roster_version": 8,
                    "commit_message_id": "msg:commit",
                    "control_message_id": "msg:control",
                    "new_manifest_sha256": "sha256:abc"
                }
            }],
            "current_roster_version": 8,
            "last_commit_message_id": "msg:commit"
        });

        let camel = snake_to_camel_value(snake.clone());
        assert_eq!(camel["records"][0]["messageId"], "msg:1");
        assert_eq!(
            camel["records"][0]["membershipProof"]["newManifestSha256"],
            "sha256:abc"
        );
        assert_eq!(camel["currentRosterVersion"], 8);

        let round_trip = camel_to_snake_value(camel);
        assert_eq!(round_trip, snake);
    }
}

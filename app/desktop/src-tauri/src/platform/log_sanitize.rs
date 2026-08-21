use sha2::{Digest, Sha256};

pub(crate) fn redact_id(kind: &str, value: &str) -> String {
    if value.is_empty() {
        return format!("<{kind}:empty>");
    }
    format!("<{kind}:{}>", short_hash(value))
}

pub(crate) fn sanitize_url_for_log(raw: &str) -> String {
    let Ok(url) = url::Url::parse(raw) else {
        return "<invalid-url>".into();
    };

    let host = url
        .host_str()
        .map(|host| redact_id("host", host))
        .unwrap_or_else(|| "<host:none>".into());

    format!("{}://{}{}", url.scheme(), host, coarse_route(url.path()))
}

fn short_hash(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn coarse_route(path: &str) -> String {
    let segments: Vec<&str> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    if segments.is_empty() {
        return "/".into();
    }

    let redacted: Vec<String> = segments
        .iter()
        .map(|segment| {
            if is_route_word(segment) {
                (*segment).to_string()
            } else {
                "<redacted>".to_string()
            }
        })
        .collect();

    format!("/{}", redacted.join("/"))
}

fn is_route_word(segment: &str) -> bool {
    matches!(
        segment,
        "v1" | "contact-share"
            | "messages"
            | "head"
            | "ack"
            | "message-requests"
            | "allowlist"
            | "identity-bundles"
            | "groups"
            | "group"
            | "outbox"
            | "welcome-pickup"
            | "invite"
            | "join-requests"
            | "seal"
            | "blob"
            | "blobs"
            | "upload"
            | "download"
            | "ws"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_id_is_stable_and_does_not_include_raw_value() {
        let first = redact_id("device", "device:alice-secret");
        let second = redact_id("device", "device:alice-secret");

        assert_eq!(first, second);
        assert!(first.starts_with("<device:"));
        assert!(!first.contains("alice"));
        assert!(!first.contains("secret"));
    }
}

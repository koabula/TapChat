use sha2::{Digest, Sha256};

pub(crate) fn redact_id(kind: &str, value: &str) -> String {
    if value.is_empty() {
        return format!("<{kind}:empty>");
    }

    let digest = Sha256::digest(value.as_bytes());
    let hash: String = digest[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("<{kind}:{hash}>")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_id_is_stable_and_hides_raw_value() {
        let first = redact_id("msg", "message:alice-secret");
        let second = redact_id("msg", "message:alice-secret");

        assert_eq!(first, second);
        assert!(first.starts_with("<msg:"));
        assert!(!first.contains("alice"));
        assert!(!first.contains("secret"));
    }
}

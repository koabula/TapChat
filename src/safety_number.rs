use sha2::{Digest, Sha256};

use crate::error::{CoreError, CoreResult};

pub const QR_PAYLOAD_PREFIX: &str = "tapchat:sn:1:";
pub const GROUP_COUNT: usize = 12;
pub const DIGITS_PER_GROUP: usize = 5;
const PUBLIC_KEY_LEN: usize = 32;
const FINGERPRINT_BYTES: usize = 30;
const CHUNKS_PER_PARTY: usize = 6;
const CHUNK_LEN: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyNumber {
    pub groups: Vec<String>,
    pub digits: String,
    pub qr_payload: String,
}

pub fn compute(local_public_key: &str, remote_public_key: &str) -> CoreResult<SafetyNumber> {
    let mut keys = [
        parse_public_key(local_public_key)?,
        parse_public_key(remote_public_key)?,
    ];
    keys.sort_unstable();

    let mut groups = Vec::with_capacity(GROUP_COUNT);
    groups.extend(party_groups(&keys[0]));
    groups.extend(party_groups(&keys[1]));

    let digits = groups.concat();
    Ok(SafetyNumber {
        qr_payload: format!("{QR_PAYLOAD_PREFIX}{digits}"),
        digits,
        groups,
    })
}

pub fn normalize_digits(input: &str) -> String {
    input.chars().filter(|ch| ch.is_ascii_digit()).collect()
}

fn parse_public_key(input: &str) -> CoreResult<[u8; PUBLIC_KEY_LEN]> {
    let trimmed = input.trim();
    if trimmed.len() != PUBLIC_KEY_LEN * 2 {
        return Err(CoreError::invalid_input(
            "root public key must be 32-byte hex",
        ));
    }
    let mut output = [0u8; PUBLIC_KEY_LEN];
    for (index, chunk) in trimmed.as_bytes().chunks(2).enumerate() {
        let hex = std::str::from_utf8(chunk)
            .map_err(|_| CoreError::invalid_input("invalid public key hex"))?;
        output[index] = u8::from_str_radix(hex, 16)
            .map_err(|_| CoreError::invalid_input("invalid public key hex"))?;
    }
    Ok(output)
}

fn party_groups(public_key: &[u8; PUBLIC_KEY_LEN]) -> Vec<String> {
    let digest = Sha256::digest(public_key);
    (0..CHUNKS_PER_PARTY)
        .map(|index| encode_chunk(&digest[..FINGERPRINT_BYTES], index * CHUNK_LEN))
        .collect()
}

fn encode_chunk(bytes: &[u8], offset: usize) -> String {
    let value = (u64::from(bytes[offset]) << 32)
        | (u64::from(bytes[offset + 1]) << 24)
        | (u64::from(bytes[offset + 2]) << 16)
        | (u64::from(bytes[offset + 3]) << 8)
        | u64::from(bytes[offset + 4]);
    format!("{:05}", value % 100_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: &str = "0101010101010101010101010101010101010101010101010101010101010101";
    const KEY_B: &str = "0202020202020202020202020202020202020202020202020202020202020202";
    const KEY_C: &str = "0303030303030303030303030303030303030303030303030303030303030303";

    #[test]
    fn compute_is_order_independent() {
        let forward = compute(KEY_A, KEY_B).expect("forward");
        let reverse = compute(KEY_B, KEY_A).expect("reverse");
        assert_eq!(forward, reverse);
        assert_eq!(forward.groups.len(), GROUP_COUNT);
        assert!(
            forward
                .groups
                .iter()
                .all(|group| group.len() == DIGITS_PER_GROUP
                    && group.chars().all(|ch| ch.is_ascii_digit()))
        );
        assert_eq!(forward.digits.len(), GROUP_COUNT * DIGITS_PER_GROUP);
        assert_eq!(
            forward.qr_payload,
            format!("{QR_PAYLOAD_PREFIX}{}", forward.digits)
        );
    }

    #[test]
    fn different_keys_produce_different_numbers() {
        let ab = compute(KEY_A, KEY_B).expect("ab");
        let ac = compute(KEY_A, KEY_C).expect("ac");
        assert_ne!(ab.digits, ac.digits);
    }

    #[test]
    fn rejects_invalid_public_keys() {
        assert!(compute("zz", KEY_B).is_err());
        assert!(compute("01", KEY_B).is_err());
        assert!(compute(KEY_A, "not-hex").is_err());
    }

    #[test]
    fn normalize_digits_strips_whitespace() {
        let number = compute(KEY_A, KEY_B).expect("number");
        let spaced = number
            .groups
            .chunks(4)
            .map(|row| row.join(" "))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(normalize_digits(&spaced), number.digits);
    }
}

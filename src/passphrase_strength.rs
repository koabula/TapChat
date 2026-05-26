#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassphraseStrengthLevel {
    Empty,
    VeryWeak,
    Weak,
    Fair,
    Strong,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PassphraseStrength {
    pub level: PassphraseStrengthLevel,
    pub score: u8,
    pub label: &'static str,
    pub message: &'static str,
    pub requires_confirmation: bool,
}

const COMMON_WEAK_TERMS: &[&str] = &[
    "password",
    "passphrase",
    "tapchat",
    "qwerty",
    "admin",
    "letmein",
    "welcome",
    "test",
    "secret",
    "123456",
    "111111",
    "000000",
];

const EMPTY_STRENGTH: PassphraseStrength = PassphraseStrength {
    level: PassphraseStrengthLevel::Empty,
    score: 0,
    label: "No passphrase",
    message: "TapChat will rely on the operating system keychain for this profile.",
    requires_confirmation: false,
};

pub fn evaluate_passphrase_strength(
    passphrase: &str,
    profile_name: Option<&str>,
) -> PassphraseStrength {
    let value = passphrase.trim();
    if value.is_empty() {
        return EMPTY_STRENGTH;
    }

    let lower = value.to_ascii_lowercase();
    let classes = character_class_count(value);
    let has_common_term = COMMON_WEAK_TERMS.iter().any(|term| lower.contains(term));
    let repeats_single_character = repeats_single_character(value);
    let has_sequence = contains_sequence(&lower);
    let includes_profile_name = profile_name
        .map(str::trim)
        .filter(|name| name.len() >= 3)
        .is_some_and(|name| lower.contains(&name.to_ascii_lowercase()));

    if value.len() <= 4 || repeats_single_character || has_common_term || has_sequence {
        return PassphraseStrength {
            level: PassphraseStrengthLevel::VeryWeak,
            score: 0,
            label: "Very weak",
            message: "This passphrase is easy to guess. Use it only if you understand the risk.",
            requires_confirmation: true,
        };
    }

    if value.len() <= 7 || classes <= 1 || includes_profile_name {
        return PassphraseStrength {
            level: PassphraseStrengthLevel::Weak,
            score: 1,
            label: "Weak",
            message:
                "Short or predictable passphrases protect less well than longer unique phrases.",
            requires_confirmation: true,
        };
    }

    if (value.len() >= 12 && classes >= 3) || (value.len() >= 16 && classes >= 2) {
        return PassphraseStrength {
            level: PassphraseStrengthLevel::Strong,
            score: if value.len() >= 18 && classes >= 3 {
                4
            } else {
                3
            },
            label: "Strong",
            message: "This passphrase has a healthier mix of length and variety.",
            requires_confirmation: false,
        };
    }

    PassphraseStrength {
        level: PassphraseStrengthLevel::Fair,
        score: 2,
        label: "Fair",
        message: "This passphrase is accepted. A longer unique phrase would be safer.",
        requires_confirmation: false,
    }
}

fn character_class_count(value: &str) -> u8 {
    let mut count = 0;
    if value.chars().any(|ch| ch.is_ascii_lowercase()) {
        count += 1;
    }
    if value.chars().any(|ch| ch.is_ascii_uppercase()) {
        count += 1;
    }
    if value.chars().any(|ch| ch.is_ascii_digit()) {
        count += 1;
    }
    if value.chars().any(|ch| !ch.is_ascii_alphanumeric()) {
        count += 1;
    }
    count
}

fn repeats_single_character(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    chars.all(|ch| ch == first)
}

fn contains_sequence(value: &str) -> bool {
    let compact: String = value.chars().filter(|ch| !ch.is_whitespace()).collect();
    if compact.len() < 5 {
        return false;
    }

    ["abcdefghijklmnopqrstuvwxyz", "0123456789"]
        .iter()
        .any(|sequence| {
            (0..=sequence.len() - 5).any(|index| {
                let slice = &sequence[index..index + 5];
                compact.contains(slice) || compact.contains(&reverse(slice))
            })
        })
}

fn reverse(value: &str) -> String {
    value.chars().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::{evaluate_passphrase_strength, PassphraseStrengthLevel};

    #[derive(serde::Deserialize)]
    struct StrengthCase {
        name: String,
        passphrase: String,
        profile_name: Option<String>,
        level: String,
        requires_confirmation: bool,
    }

    fn level_name(level: PassphraseStrengthLevel) -> &'static str {
        match level {
            PassphraseStrengthLevel::Empty => "empty",
            PassphraseStrengthLevel::VeryWeak => "very_weak",
            PassphraseStrengthLevel::Weak => "weak",
            PassphraseStrengthLevel::Fair => "fair",
            PassphraseStrengthLevel::Strong => "strong",
        }
    }

    #[test]
    fn shared_fixture_matches_desktop_strength_expectations() {
        let cases: Vec<StrengthCase> = serde_json::from_str(include_str!(
            "../tests/fixtures/passphrase_strength_cases.json"
        ))
        .expect("passphrase strength fixture should parse");

        for test_case in cases {
            let strength = evaluate_passphrase_strength(
                &test_case.passphrase,
                test_case.profile_name.as_deref(),
            );
            assert_eq!(
                level_name(strength.level),
                test_case.level,
                "{}",
                test_case.name
            );
            assert_eq!(
                strength.requires_confirmation, test_case.requires_confirmation,
                "{}",
                test_case.name
            );
        }
    }

    #[test]
    fn empty_passphrase_does_not_require_confirmation() {
        let strength = evaluate_passphrase_strength("   ", None);
        assert_eq!(strength.level, PassphraseStrengthLevel::Empty);
        assert!(!strength.requires_confirmation);
    }

    #[test]
    fn short_common_and_sequential_passphrases_are_very_weak() {
        for passphrase in ["abc", "password123", "abcdefg!", "aaaaaaaa"] {
            let strength = evaluate_passphrase_strength(passphrase, None);
            assert_eq!(strength.level, PassphraseStrengthLevel::VeryWeak);
            assert!(strength.requires_confirmation);
        }
    }

    #[test]
    fn profile_name_reuse_is_weak() {
        let strength = evaluate_passphrase_strength("alice-chat-key", Some("alice"));
        assert_eq!(strength.level, PassphraseStrengthLevel::Weak);
        assert!(strength.requires_confirmation);
    }

    #[test]
    fn fair_passphrase_is_accepted_without_confirmation() {
        let strength = evaluate_passphrase_strength("paper moon", None);
        assert_eq!(strength.level, PassphraseStrengthLevel::Fair);
        assert!(!strength.requires_confirmation);
    }

    #[test]
    fn longer_varied_passphrase_is_strong() {
        let strength = evaluate_passphrase_strength("correct-Horse-42-sunrise", None);
        assert_eq!(strength.level, PassphraseStrengthLevel::Strong);
        assert!(!strength.requires_confirmation);
    }
}

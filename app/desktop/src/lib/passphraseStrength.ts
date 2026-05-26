export type PassphraseStrengthLevel =
  | "empty"
  | "very_weak"
  | "weak"
  | "fair"
  | "strong";

export interface PassphraseStrength {
  level: PassphraseStrengthLevel;
  score: 0 | 1 | 2 | 3 | 4;
  label: string;
  message: string;
  requiresConfirmation: boolean;
}

const COMMON_WEAK_TERMS = [
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

const EMPTY_STRENGTH: PassphraseStrength = {
  level: "empty",
  score: 0,
  label: "No passphrase",
  message: "TapChat will rely on the operating system keychain for this profile.",
  requiresConfirmation: false,
};

export function evaluatePassphraseStrength(
  passphrase: string,
  profileName?: string,
): PassphraseStrength {
  const value = passphrase.trim();
  if (!value) {
    return EMPTY_STRENGTH;
  }

  const lower = value.toLowerCase();
  const classes = characterClassCount(value);
  const hasCommonTerm = COMMON_WEAK_TERMS.some((term) => lower.includes(term));
  const repeatsSingleCharacter = /^(.)(\1)+$/.test(value);
  const hasSequence = containsSequence(lower);
  const includesProfileName = Boolean(
    profileName && profileName.trim().length >= 3 && lower.includes(profileName.trim().toLowerCase()),
  );

  if (value.length <= 4 || repeatsSingleCharacter || hasCommonTerm || hasSequence) {
    return {
      level: "very_weak",
      score: 0,
      label: "Very weak",
      message: "This passphrase is easy to guess. Use it only if you understand the risk.",
      requiresConfirmation: true,
    };
  }

  if (value.length <= 7 || classes <= 1 || includesProfileName) {
    return {
      level: "weak",
      score: 1,
      label: "Weak",
      message: "Short or predictable passphrases protect less well than longer unique phrases.",
      requiresConfirmation: true,
    };
  }

  if ((value.length >= 12 && classes >= 3) || (value.length >= 16 && classes >= 2)) {
    return {
      level: "strong",
      score: value.length >= 18 && classes >= 3 ? 4 : 3,
      label: "Strong",
      message: "This passphrase has a healthier mix of length and variety.",
      requiresConfirmation: false,
    };
  }

  return {
    level: "fair",
    score: 2,
    label: "Fair",
    message: "This passphrase is accepted. A longer unique phrase would be safer.",
    requiresConfirmation: false,
  };
}

function characterClassCount(value: string): number {
  let count = 0;
  if (/[a-z]/.test(value)) count += 1;
  if (/[A-Z]/.test(value)) count += 1;
  if (/[0-9]/.test(value)) count += 1;
  if (/[^a-zA-Z0-9]/.test(value)) count += 1;
  return count;
}

function containsSequence(value: string): boolean {
  const compact = value.replace(/\s+/g, "");
  if (compact.length < 5) {
    return false;
  }

  const sequences = ["abcdefghijklmnopqrstuvwxyz", "0123456789"];
  return sequences.some((sequence) => {
    for (let index = 0; index <= sequence.length - 5; index += 1) {
      const slice = sequence.slice(index, index + 5);
      if (compact.includes(slice) || compact.includes(reverse(slice))) {
        return true;
      }
    }
    return false;
  });
}

function reverse(value: string): string {
  return [...value].reverse().join("");
}

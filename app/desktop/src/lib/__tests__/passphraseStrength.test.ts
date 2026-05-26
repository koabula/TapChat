import { describe, expect, it } from "vitest";

import fixture from "../../../../../tests/fixtures/passphrase_strength_cases.json";
import {
  evaluatePassphraseStrength,
  type PassphraseStrengthLevel,
} from "../passphraseStrength";

interface StrengthCase {
  name: string;
  passphrase: string;
  profile_name: string | null;
  level: PassphraseStrengthLevel;
  requires_confirmation: boolean;
}

describe("passphrase strength evaluation", () => {
  it.each(fixture as StrengthCase[])(
    "matches the shared Rust/Desktop fixture: $name",
    (testCase) => {
      const strength = evaluatePassphraseStrength(
        testCase.passphrase,
        testCase.profile_name ?? undefined,
      );

      expect(strength.level).toBe(testCase.level);
      expect(strength.requiresConfirmation).toBe(testCase.requires_confirmation);
    },
  );

  it("treats an empty passphrase as keychain-only and does not require confirmation", () => {
    expect(evaluatePassphraseStrength("   ")).toMatchObject({
      level: "empty",
      requiresConfirmation: false,
    });
  });

  it("flags short passphrases as accepted but requiring confirmation", () => {
    expect(evaluatePassphraseStrength("abc")).toMatchObject({
      level: "very_weak",
      requiresConfirmation: true,
    });
  });

  it("flags common weak terms and sequences", () => {
    expect(evaluatePassphraseStrength("password123")).toMatchObject({
      level: "very_weak",
      requiresConfirmation: true,
    });
    expect(evaluatePassphraseStrength("abcdefg!")).toMatchObject({
      level: "very_weak",
      requiresConfirmation: true,
    });
  });

  it("flags profile-name reuse as weak", () => {
    expect(evaluatePassphraseStrength("alice-chat-key", "alice")).toMatchObject({
      level: "weak",
      requiresConfirmation: true,
    });
  });

  it("accepts fair passphrases without forced confirmation", () => {
    expect(evaluatePassphraseStrength("paper moon")).toMatchObject({
      level: "fair",
      requiresConfirmation: false,
    });
  });

  it("recognizes longer varied passphrases as strong", () => {
    expect(evaluatePassphraseStrength("correct-Horse-42-sunrise")).toMatchObject({
      level: "strong",
      requiresConfirmation: false,
    });
  });
});

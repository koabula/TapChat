import { beforeEach, describe, expect, it, vi } from "vitest";

const tauriMocks = vi.hoisted(() => ({
  invoke: vi.fn(),
  listen: vi.fn(),
}));

vi.mock("@tauri-apps/api/core", () => ({
  invoke: tauriMocks.invoke,
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: tauriMocks.listen,
}));

import {
  beginRecoveryPhraseReveal,
  completeRecoveryPhraseReveal,
  createOrLoadIdentity,
  initOnboardingProfile,
  selectProfileForRestart,
  setLocalDisplayName,
} from "../tauri";

describe("tauri identity wrappers", () => {
  beforeEach(() => {
    tauriMocks.invoke.mockReset();
  });

  it("forwards display name when creating or loading an identity", async () => {
    tauriMocks.invoke.mockResolvedValueOnce({});

    await createOrLoadIdentity("test mnemonic", "Laptop", "Alice");

    expect(tauriMocks.invoke).toHaveBeenCalledWith("create_or_load_identity", {
      mnemonic: "test mnemonic",
      deviceName: "Laptop",
      displayName: "Alice",
    });
  });

  it("forwards null display name when clearing local identity name", async () => {
    tauriMocks.invoke.mockResolvedValueOnce({});

    await setLocalDisplayName(null);

    expect(tauriMocks.invoke).toHaveBeenCalledWith("set_local_display_name", {
      displayName: null,
    });
  });

  it("forwards the explicit profile protection mode during onboarding", async () => {
    tauriMocks.invoke.mockResolvedValueOnce({});

    await initOnboardingProfile("default", "profile password", "passphrase_only");

    expect(tauriMocks.invoke).toHaveBeenCalledWith("init_onboarding_profile", {
      profileName: "default",
      passphrase: "profile password",
      protectionMode: "passphrase_only",
    });
  });

  it("uses the explicit sensitive IPC flow to reveal a recovery phrase", async () => {
    tauriMocks.invoke.mockResolvedValueOnce({
      challenge_id: "challenge",
      auth_mode: "passphrase",
      expires_at: 123,
    });
    tauriMocks.invoke.mockResolvedValueOnce({ mnemonic: "recovery words" });

    await beginRecoveryPhraseReveal();
    await completeRecoveryPhraseReveal("challenge", "profile password", true);

    expect(tauriMocks.invoke).toHaveBeenNthCalledWith(
      1,
      "begin_recovery_phrase_reveal",
    );
    expect(tauriMocks.invoke).toHaveBeenNthCalledWith(
      2,
      "complete_recovery_phrase_reveal",
      {
        challengeId: "challenge",
        passphrase: "profile password",
        confirmed: true,
      },
    );
  });

  it("selects a profile for restart without invoking the hot-switch command", async () => {
    tauriMocks.invoke.mockResolvedValueOnce({});

    await selectProfileForRestart("D:/TapChat/profiles/bob", "secret");

    expect(tauriMocks.invoke).toHaveBeenCalledWith("select_profile_for_restart", {
      path: "D:/TapChat/profiles/bob",
      passphrase: "secret",
    });
    expect(tauriMocks.invoke).not.toHaveBeenCalledWith(
      "activate_profile",
      expect.anything(),
    );
  });
});

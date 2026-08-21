import { describe, expect, it } from "vitest";

import {
  lockedProfileRetryDisabled,
  lockedProfileRetryPayload,
  lockedProfileView,
} from "../lockedProfile";

describe("locked profile retry view model", () => {
  it("requires an explicit profile choice for ambiguous startup selectors", () => {
    const view = lockedProfileView("profile_selection_required");

    expect(view.reasonLabel).toBe("Choose a profile");
    expect(view.needsPassphrase).toBe(false);
    expect(view.canRetry).toBe(false);
  });

  it("treats restore_failed as a repair retry without passphrase", () => {
    const view = lockedProfileView("restore_failed");

    expect(view.reasonLabel).toBe("Profile state could not be restored");
    expect(view.needsPassphrase).toBe(false);
    expect(view.primaryActionLabel).toBe("Retry");
    expect(lockedProfileRetryDisabled("restore_failed", "", false)).toBe(false);
    expect(lockedProfileRetryPayload("restore_failed", "ignored")).toEqual({
      passphrase: null,
    });
  });

  it("keeps profile_locked as a passphrase unlock flow", () => {
    const view = lockedProfileView("profile_locked");

    expect(view.reasonLabel).toBe("Profile locked");
    expect(view.needsPassphrase).toBe(true);
    expect(view.primaryActionLabel).toBe("Unlock");
    expect(lockedProfileRetryDisabled("profile_locked", "", false)).toBe(true);
    expect(lockedProfileRetryPayload("profile_locked", "secret")).toEqual({
      passphrase: "secret",
    });
  });
});

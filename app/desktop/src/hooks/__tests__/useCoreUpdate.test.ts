import { beforeEach, describe, expect, it } from "vitest";

import { useSessionStore } from "@/store/session";
import { applyIdentitySummaryToSession } from "../useCoreUpdate";

describe("core identity updates", () => {
  beforeEach(() => {
    useSessionStore.getState().setUserId(null);
    useSessionStore.getState().setDeviceId(null);
    useSessionStore.getState().setDisplayName(null);
  });

  it("applies identity_changed summaries to the session store", () => {
    applyIdentitySummaryToSession({
      user_id: "user:alice",
      device_id: "device:alice:phone",
      display_name: "Alice",
    });

    expect(useSessionStore.getState().userId).toBe("user:alice");
    expect(useSessionStore.getState().deviceId).toBe("device:alice:phone");
    expect(useSessionStore.getState().displayName).toBe("Alice");
  });

  it("clears the local display name when identity summary omits it", () => {
    useSessionStore.getState().setDisplayName("Alice");

    applyIdentitySummaryToSession({
      user_id: "user:alice",
      device_id: "device:alice:phone",
      display_name: null,
    });

    expect(useSessionStore.getState().displayName).toBeNull();
  });
});

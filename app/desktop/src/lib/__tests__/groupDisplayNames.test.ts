import { describe, expect, it } from "vitest";

import { buildGroupNameResolver } from "../groupDisplayNames";
import type { GroupManifest } from "../types";

const manifest = {
  member_devices: [
    { user_id: "user:alice", device_id: "device:alice:phone", status: "active" },
    { user_id: "user:bob", device_id: "device:bob:phone", status: "active" },
  ],
} as GroupManifest;

describe("group display name resolver", () => {
  it("uses local display name, contact name, user fallback, then device fallback", () => {
    const resolve = buildGroupNameResolver({
      manifest,
      contacts: [{ user_id: "user:bob", display_name: "Bobby" }],
      localUserId: "user:alice",
      localDisplayName: "Alice",
    });

    expect(resolve({ userId: "user:alice" })).toBe("Alice");
    expect(resolve({ deviceId: "device:bob:phone" })).toBe("Bobby");
    expect(resolve({ userId: "user:charlie:very-long-tail-value" })).toBe("very-l...alue");
    expect(resolve({ deviceId: "device:unknown:very-long-tail-value" })).toBe("very-l...alue");
  });

  it("labels the local user as You when no display name is set", () => {
    const resolve = buildGroupNameResolver({
      manifest,
      contacts: [],
      localUserId: "user:alice",
      localDisplayName: null,
    });

    expect(resolve({ deviceId: "device:alice:phone" })).toBe("You");
  });
});

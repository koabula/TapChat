import { describe, expect, test } from "vitest";
import type {
  CoreEffect,
  GroupCapability,
  GroupCapabilityOperation,
  GroupMessageType,
  SealGroupOutboxRequest,
} from "../types";

describe("group wire contract parity", () => {
  test("desktop contract includes dissolve message and seal capability", () => {
    const dissolved: GroupMessageType = "control_group_dissolved";
    const seal: GroupCapabilityOperation = "seal_group";

    expect(dissolved).toBe("control_group_dissolved");
    expect(seal).toBe("seal_group");
  });

  test("seal group outbox effect keeps desktop core-effect snake_case", () => {
    const capability: GroupCapability = {
      version: "0.1",
      service: "group_outbox",
      group_id: "group:project",
      user_id: "user:alice",
      device_id: "device:alice:laptop",
      operations: ["read", "append_membership", "seal_group"],
      role: "owner",
      expires_at: 1_775_004_800_000,
      signature: "cap-sig",
    };
    const seal: SealGroupOutboxRequest = {
      group_id: "group:project",
      capability,
    };
    const effect: CoreEffect = {
      type: "seal_group_outbox",
      seal,
    };

    expect(Object.keys(effect.seal)).toEqual(["group_id", "capability"]);
    expect(effect.seal.group_id).toBe("group:project");
    expect(effect.seal.capability.operations).toContain("seal_group");
  });
});

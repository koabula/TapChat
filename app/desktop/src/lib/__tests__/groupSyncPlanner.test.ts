import { describe, expect, it } from "vitest";

import {
  chooseWebsocketGroups,
  pollingInitialDelayMs,
  shouldPollGroup,
} from "../groupSyncPlanner";
import type { GroupSyncSettings } from "../tauri";

const settings: GroupSyncSettings = {
  mode: "auto",
  max_websocket_groups: 3,
  poll_interval_minutes: 5,
  important_group_ids: ["g3", "g2"],
  recent_group_ids: [],
};

describe("groupSyncPlanner", () => {
  it("prioritizes current, important, then recently opened groups within budget", () => {
    expect(
      chooseWebsocketGroups({
        groupIds: ["g1", "g2", "g3", "g4"],
        currentGroupId: "g4",
        recentGroupIds: ["g1", "g2"],
        settings,
      }),
    ).toEqual(["g4", "g3", "g2"]);
  });

  it("uses active groups after current, important, and persisted recent groups", () => {
    expect(
      chooseWebsocketGroups({
        groupIds: ["g1", "g2", "g3", "g4", "g5"],
        currentGroupId: null,
        recentGroupIds: ["g4"],
        activeGroupIds: ["g5", "g1"],
        settings: { ...settings, max_websocket_groups: 4 },
      }),
    ).toEqual(["g3", "g2", "g4", "g5"]);
  });

  it("disables websocket groups outside auto mode or when budget is zero", () => {
    expect(
      chooseWebsocketGroups({
        groupIds: ["g1"],
        currentGroupId: "g1",
        recentGroupIds: [],
        settings: { ...settings, mode: "polling" },
      }),
    ).toEqual([]);
    expect(
      chooseWebsocketGroups({
        groupIds: ["g1"],
        currentGroupId: "g1",
        recentGroupIds: [],
        settings: { ...settings, max_websocket_groups: 0 },
      }),
    ).toEqual([]);
  });

  it("uses stable polling phases inside the interval", () => {
    const interval = 300_000;
    const first = pollingInitialDelayMs("group-a", interval);
    const second = pollingInitialDelayMs("group-a", interval);
    const other = pollingInitialDelayMs("group-b", interval);

    expect(first).toBe(second);
    expect(first).toBeGreaterThanOrEqual(0);
    expect(first).toBeLessThan(interval);
    expect(other).toBeGreaterThanOrEqual(0);
    expect(other).toBeLessThan(interval);
  });

  it("polls only non-websocket groups in auto mode", () => {
    expect(shouldPollGroup("g1", ["g1"], settings)).toBe(false);
    expect(shouldPollGroup("g2", ["g1"], settings)).toBe(true);
    expect(shouldPollGroup("g1", ["g1"], { ...settings, mode: "polling" })).toBe(true);
    expect(shouldPollGroup("g1", [], { ...settings, mode: "manual" })).toBe(false);
  });
});

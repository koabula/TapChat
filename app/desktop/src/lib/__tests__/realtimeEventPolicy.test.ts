import { describe, expect, it } from "vitest";

import {
  directRealtimeEventHandledByRustCore,
  shouldFrontendInvokeSyncForRealtimeEvent,
} from "../realtimeEventPolicy";

describe("realtime event policy", () => {
  it("keeps direct realtime sync in Rust core", () => {
    expect(shouldFrontendInvokeSyncForRealtimeEvent("inbox_record_available")).toBe(false);
    expect(shouldFrontendInvokeSyncForRealtimeEvent("head_updated")).toBe(false);
    expect(shouldFrontendInvokeSyncForRealtimeEvent("disconnected")).toBe(false);
    expect(shouldFrontendInvokeSyncForRealtimeEvent("error")).toBe(false);
  });

  it("identifies direct record/head events as core-handled", () => {
    expect(directRealtimeEventHandledByRustCore("inbox_record_available")).toBe(true);
    expect(directRealtimeEventHandledByRustCore("head_updated")).toBe(true);
    expect(directRealtimeEventHandledByRustCore("message_request_changed")).toBe(false);
  });
});

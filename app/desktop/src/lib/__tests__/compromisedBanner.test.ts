import { describe, expect, it } from "vitest";

import { compromisedNotice } from "../compromisedBanner";

describe("compromisedNotice", () => {
  it("says nothing unless the conversation is compromised", () => {
    for (const state of [undefined, "active", "needs_rebuild", "closed", "archived"]) {
      expect(compromisedNotice(state, 1_000, "Bob")).toBeNull();
    }
  });

  it("dates the warning from the contradicted commit", () => {
    const notice = compromisedNotice("compromised", 1_000, "Bob", (ms) => `t=${ms}`);
    expect(notice?.headline).toBe("Session compromised");
    expect(notice?.detail).toContain("Messages received since t=1000 may not be from Bob.");
  });

  it("sends the contact to a new identity, not to the old safety number", () => {
    const notice = compromisedNotice("compromised", null, "Bob");
    expect(notice?.detail).toContain("Recent messages may not be from Bob.");
    expect(notice?.advice).toContain("Tell Bob outside TapChat");
    expect(notice?.advice).toContain("new recovery phrase");
    expect(notice?.advice).toContain("verify its safety number in person");
    expect(notice?.advice).toContain("current safety number still matches");
  });
});

import { describe, expect, it } from "vitest";

import {
  awaitingResetDetail,
  compromisedNotice,
  isUnconfirmedSender,
  resetSessionConfirmText,
} from "../compromisedBanner";

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

describe("isUnconfirmedSender", () => {
  it("marks inbound messages from the contradicted commit on", () => {
    expect(isUnconfirmedSender("received", 100, 100)).toBe(true);
    expect(isUnconfirmedSender("received", 101, 100)).toBe(true);
    expect(isUnconfirmedSender("received", 99, 100)).toBe(false);
  });

  it("never marks this side's own messages, or anything without a fork", () => {
    expect(isUnconfirmedSender("sent", 200, 100)).toBe(false);
    expect(isUnconfirmedSender("system", 200, 100)).toBe(false);
    expect(isUnconfirmedSender("received", 200, null)).toBe(false);
  });
});

describe("session reset copy", () => {
  it("sends the side that lost its group to its peer", () => {
    expect(awaitingResetDetail("Bob")).toContain("Ask Bob to reset it from their side");
  });

  it("warns that a reset the peer did not ask for is refused", () => {
    const text = resetSessionConfirmText("Bob");
    expect(text).toContain("Only do this if Bob's app says the chat needs a reset");
    expect(text).toContain("their app refuses the reset and the chat stops working");
  });
});

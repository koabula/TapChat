import { describe, expect, it } from "vitest";

import { chatHeaderActionErrorStatus, chatHeaderActions } from "@/lib/chatHeaderActions";

describe("chat header actions", () => {
  it("keeps direct-chat actions non-destructive", () => {
    expect(chatHeaderActions(false).map((action) => action.id)).toEqual([
      "contact_details",
      "refresh_contact",
    ]);
  });

  it("maps group actions to members and sync", () => {
    expect(chatHeaderActions(true).map((action) => action.id)).toEqual([
      "group_members",
      "sync_group",
    ]);
  });

  it("does not expose unstructured refresh failure details", () => {
    expect(chatHeaderActionErrorStatus(new Error("Refresh unavailable"))).toEqual({
      kind: "error",
      text: "Something went wrong. Try again.",
    });
  });

  it("maps structured refresh failures to the registered English message", () => {
    expect(
      chatHeaderActionErrorStatus({
        version: 1,
        code: "network_unavailable",
        domain: "transport",
        retryable: true,
        action: "reconnect",
      }),
    ).toEqual({
      kind: "error",
      text: "Check your connection and try again.",
    });
  });
});

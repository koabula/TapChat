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

  it("maps refresh failures to a visible error status", () => {
    expect(chatHeaderActionErrorStatus(new Error("Refresh unavailable"))).toEqual({
      kind: "error",
      text: "Refresh unavailable",
    });
  });
});

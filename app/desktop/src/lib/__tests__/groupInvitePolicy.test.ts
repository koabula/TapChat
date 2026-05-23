import { describe, expect, test } from "vitest";

import { blockedInviteCreationReason } from "../groupInvitePolicy";

describe("group invite policy UX", () => {
  test("blocks link creation only for closed groups", () => {
    expect(blockedInviteCreationReason("closed")).toContain("group is closed");
    expect(blockedInviteCreationReason("approval_required")).toBeNull();
    expect(blockedInviteCreationReason("open_by_invite")).toBeNull();
    expect(blockedInviteCreationReason(null)).toBeNull();
  });
});

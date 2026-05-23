import type { GroupJoinPolicy } from "./types";

export const CLOSED_GROUP_INVITE_MESSAGE =
  "This group is closed. Change Join policy to Approval required or Open by invite before creating an invite link.";

export function blockedInviteCreationReason(
  joinPolicy: GroupJoinPolicy | null,
): string | null {
  return joinPolicy === "closed" ? CLOSED_GROUP_INVITE_MESSAGE : null;
}

import { describe, expect, test } from "vitest";

import {
  normalizeGroupInvite,
  normalizeGroupJoinRequest,
  normalizeGroupSnapshot,
} from "../tauri";

describe("group snapshot normalizer", () => {
  test("maps Rust camelCase group manifest fields to UI snake_case", () => {
    const snapshot = normalizeGroupSnapshot({
      group_id: "group:project",
      conversation_id: "conv:group:project",
      local_role: "owner",
      cursor: {
        groupId: "group:project",
        lastFetchedSeq: 7,
        updatedAt: 11,
      },
      manifest: {
        version: "0.1",
        groupId: "group:project",
        conversationId: "conv:group:project",
        title: "Project",
        ownerUserId: "user:alice",
        admins: [],
        members: [
          { userId: "user:alice", role: "owner", status: "active" },
          { userId: "user:bob", role: "member", status: "active" },
        ],
        memberDevices: [
          { userId: "user:alice", deviceId: "device:alice:phone", status: "active" },
          { userId: "user:bob", deviceId: "device:bob:phone", status: "active" },
        ],
        joinPolicy: "approval_required",
        memberInvitePolicy: "request_owner_approval",
        rosterVersion: 2,
        mlsEpochHint: 4,
        lastCommitMessageId: "msg:commit",
        outbox: { endpoint: "https://example.com/outbox" },
        updatedAt: 12,
        signerUserId: "user:alice",
        signerDeviceId: "device:alice",
        signature: "sig",
      },
      invites: [],
      joinRequests: [],
      pending_outbox_count: 0,
      dissolved_at: null,
      conversation_state: "active",
    });

    expect(snapshot.manifest.members.map((member) => member.user_id)).toEqual([
      "user:alice",
      "user:bob",
    ]);
    expect(snapshot.manifest.member_devices.map((device) => device.device_id)).toEqual([
      "device:alice:phone",
      "device:bob:phone",
    ]);
    expect(snapshot.manifest.join_policy).toBe("approval_required");
    expect(snapshot.manifest.member_invite_policy).toBe("request_owner_approval");
    expect(snapshot.cursor?.last_fetched_seq).toBe(7);
  });

  test("normalizes invite and join request projections", () => {
    expect(
      normalizeGroupInvite({
        groupId: "group:project",
        inviteId: "group-invite:1",
        inviteUrl: "https://example.com/v1/group-invite/x",
        joinPolicy: "open_by_invite",
        expiresAt: 100,
        maxUses: 2,
        inviterUserId: "user:alice",
        createdAt: 1,
      }),
    ).toMatchObject({
      group_id: "group:project",
      invite_id: "group-invite:1",
      join_policy: "open_by_invite",
      max_uses: 2,
    });

    expect(
      normalizeGroupJoinRequest({
        requestId: "join:1",
        groupId: "group:project",
        joinerUserId: "user:bob",
        joinerDeviceId: "device:bob",
        requestedAt: 10,
        status: "pending",
        inviteId: "group-invite:1",
      }),
    ).toMatchObject({
      request_id: "join:1",
      joiner_user_id: "user:bob",
      joiner_device_id: "device:bob",
      invite_id: "group-invite:1",
    });
  });
});

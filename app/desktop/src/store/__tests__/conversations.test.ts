import { beforeEach, describe, expect, test } from "vitest";

import { useConversationsStore, type Conversation } from "../conversations";

const baseConversation = (id: string): Conversation => ({
  conversation_id: id,
  peer_user_id: `user:${id}`,
  state: "active",
  display_name: id,
  last_message: null,
  last_message_time: null,
  message_count: 0,
  last_activity_key: `${id}|0|`,
  unread_count: 0,
  has_unread: false,
  kind: "direct",
  title: null,
  group_id: null,
  member_count: null,
  group_role: null,
  group_cursor: null,
  recovery: null,
  dissolved_at: null,
});

describe("conversation store snapshot merging", () => {
  beforeEach(() => {
    useConversationsStore.getState().setConversations([], { replace: true });
    useConversationsStore.getState().setActiveConversation(null);
  });

  test("partial snapshots upsert without dropping existing conversations", () => {
    const direct = baseConversation("conv:direct");
    const group = {
      ...baseConversation("conv:group"),
      peer_user_id: "group:project",
      kind: "group" as const,
      title: "Project",
      group_id: "group:project",
      member_count: 2,
    };

    useConversationsStore
      .getState()
      .setConversations([direct, group], { replace: true });
    useConversationsStore.getState().setConversations(
      [
        {
          ...group,
          message_count: 1,
          last_activity_key: "conv:group|1|hello",
          last_message: "hello",
        },
      ],
      { replace: false },
    );

    const ids = useConversationsStore
      .getState()
      .conversations.map((conversation) => conversation.conversation_id);
    expect(ids).toEqual(["conv:group", "conv:direct"]);
  });

  test("authoritative contact snapshot clears stale direct display names", () => {
    useConversationsStore
      .getState()
      .setConversations([baseConversation("bob")], { replace: true });

    useConversationsStore.getState().mergeConversationSnapshot(
      [
        {
          conversation_id: "bob",
          peer_user_id: "user:bob",
          state: "active",
          kind: "direct",
          message_count: 0,
        },
      ],
      [{ user_id: "user:bob", display_name: null }],
      { replace: true },
    );

    expect(useConversationsStore.getState().conversations[0].display_name).toBeNull();
  });

  test("authoritative conversation snapshot clears stale recovery diagnostics", () => {
    useConversationsStore.getState().setConversations(
      [
        {
          ...baseConversation("bob"),
          peer_user_id: "user:bob",
          recovery: {
            conversation_id: "bob",
            recovery_status: "needs_recovery",
            reason: "missing_welcome",
            phase: "waiting_for_sync",
            attempt_count: 1,
            identity_refresh_retry_count: 0,
            pending_record_count: 1,
            pending_record_seqs: [1],
            last_fetched_seq: 1,
            last_acked_seq: 0,
          },
        },
      ],
      { replace: true },
    );

    useConversationsStore.getState().mergeConversationSnapshot(
      [
        {
          conversation_id: "bob",
          peer_user_id: "user:bob",
          state: "active",
          kind: "direct",
          message_count: 0,
        },
      ],
      [{ user_id: "user:bob", display_name: "Bob" }],
      { replace: true },
    );

    expect(useConversationsStore.getState().conversations[0].recovery).toBeNull();
  });

  test("authoritative conversation snapshot uses the backend unread count", () => {
    useConversationsStore.getState().mergeConversationSnapshot(
      [
        {
          conversation_id: "bob",
          peer_user_id: "user:bob",
          state: "active",
          kind: "direct",
          message_count: 4,
          unread_count: 3,
        },
      ],
      [{ user_id: "user:bob", display_name: "Bob" }],
      { replace: true },
    );

    expect(useConversationsStore.getState().conversations[0].unread_count).toBe(3);
    expect(useConversationsStore.getState().conversations[0].has_unread).toBe(true);

    useConversationsStore.getState().mergeConversationSnapshot(
      [
        {
          conversation_id: "bob",
          peer_user_id: "user:bob",
          state: "active",
          kind: "direct",
          message_count: 4,
          unread_count: 0,
        },
      ],
      [{ user_id: "user:bob", display_name: "Bob" }],
      { replace: true },
    );

    expect(useConversationsStore.getState().conversations[0].unread_count).toBe(0);
    expect(useConversationsStore.getState().conversations[0].has_unread).toBe(false);
  });
});

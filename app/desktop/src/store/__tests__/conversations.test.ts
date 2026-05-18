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
});

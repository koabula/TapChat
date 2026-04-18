import { create } from "zustand";
import type { ConversationSummary } from "../lib/types";

export interface Conversation {
  conversation_id: string;
  peer_user_id: string;
  state: string;
  display_name: string | null;
  last_message: string | null;
  last_message_time: number | null;
  message_count: number;
  last_activity_key: string;
  unread_count: number;
  has_unread: boolean;
}

interface ContactDisplayName {
  user_id: string;
  display_name: string | null;
}

interface SetConversationsOptions {
  markUnread?: boolean;
}

interface ConversationsState {
  conversations: Conversation[];
  activeConversationId: string | null;
  setConversations: (
    conversations: Conversation[],
    options?: SetConversationsOptions,
  ) => void;
  mergeConversationSnapshot: (
    snapshots: ConversationSummary[],
    contacts: ContactDisplayName[],
    options?: SetConversationsOptions,
  ) => void;
  setActiveConversation: (id: string | null) => void;
  addConversation: (conversation: Conversation) => void;
  updateConversation: (id: string, updates: Partial<Conversation>) => void;
  clearUnread: (id: string) => void;
  markUnread: (id: string) => void;
}

function displayMessagePreview(conversation: ConversationSummary): string {
  const preview = conversation.last_message_preview?.trim();
  if (preview) {
    return preview;
  }
  return conversation.peer_user_id;
}

function activityKeyForConversationSummary(conversation: ConversationSummary): string {
  return [
    conversation.conversation_id,
    String(conversation.message_count ?? 0),
    conversation.last_message_preview?.trim() ?? "",
  ].join("|");
}

function mergeConversationState(
  previous: Conversation[],
  incoming: Conversation[],
  activeConversationId: string | null,
  markUnread: boolean,
): Conversation[] {
  const previousById = new Map(
    previous.map((conversation) => [conversation.conversation_id, conversation]),
  );

  return incoming.map((conversation) => {
    const prior = previousById.get(conversation.conversation_id);
    const activityChanged =
      prior !== undefined && prior.last_activity_key !== conversation.last_activity_key;
    const previewChanged =
      (conversation.last_message ?? "") !== (prior?.last_message ?? "");
    const messageCountIncreased =
      conversation.message_count > (prior?.message_count ?? 0);
    const hasNewMessages =
      activityChanged && (messageCountIncreased || previewChanged);
    const shouldMarkUnread =
      markUnread &&
      hasNewMessages &&
      conversation.conversation_id !== activeConversationId;

    if (activityChanged) {
      console.debug(
        `[conversations] activity conversation_id=${conversation.conversation_id} active=${activeConversationId ?? "none"} previous_key=${prior?.last_activity_key ?? "none"} next_key=${conversation.last_activity_key} mark_unread=${shouldMarkUnread}`,
      );
    }

    return {
      ...conversation,
      display_name: conversation.display_name ?? prior?.display_name ?? null,
      last_message_time: conversation.last_message_time ?? prior?.last_message_time ?? null,
      unread_count:
        conversation.conversation_id === activeConversationId
          ? 0
          : shouldMarkUnread
            ? 1
            : prior?.unread_count ?? conversation.unread_count,
      has_unread:
        conversation.conversation_id === activeConversationId
          ? false
          : shouldMarkUnread || prior?.has_unread || conversation.has_unread,
    };
  });
}

export const useConversationsStore = create<ConversationsState>((set) => ({
  conversations: [],
  activeConversationId: null,
  setConversations: (conversations, options) =>
    set((state) => ({
      conversations: mergeConversationState(
        state.conversations,
        conversations,
        state.activeConversationId,
        options?.markUnread ?? false,
      ),
    })),
  mergeConversationSnapshot: (snapshots, contacts, options) =>
    set((state) => {
      const displayNameByUserId = new Map(
        contacts.map((contact) => [contact.user_id, contact.display_name]),
      );
      const mappedConversations: Conversation[] = snapshots.map((conversation) => ({
        conversation_id: conversation.conversation_id,
        peer_user_id: conversation.peer_user_id,
        state: conversation.state,
        display_name: displayNameByUserId.get(conversation.peer_user_id) ?? null,
        last_message: displayMessagePreview(conversation),
        last_message_time: null,
        message_count: conversation.message_count ?? 0,
        last_activity_key: activityKeyForConversationSummary(conversation),
        unread_count: 0,
        has_unread: false,
      }));

      return {
        conversations: mergeConversationState(
          state.conversations,
          mappedConversations,
          state.activeConversationId,
          options?.markUnread ?? false,
        ),
      };
    }),
  setActiveConversation: (id) =>
    set((state) => ({
      activeConversationId: id,
      conversations: state.conversations.map((conversation) =>
        conversation.conversation_id === id
          ? { ...conversation, has_unread: false, unread_count: 0 }
          : conversation,
      ),
    })),
  addConversation: (conversation) =>
    set((state) => ({
      conversations: [...state.conversations, conversation],
    })),
  updateConversation: (id, updates) =>
    set((state) => ({
      conversations: state.conversations.map((c) =>
        c.conversation_id === id ? { ...c, ...updates } : c,
      ),
    })),
  clearUnread: (id) =>
    set((state) => ({
      conversations: state.conversations.map((conversation) =>
        conversation.conversation_id === id
          ? { ...conversation, has_unread: false, unread_count: 0 }
          : conversation,
      ),
    })),
  markUnread: (id) =>
    set((state) => ({
      conversations: state.conversations.map((conversation) =>
        conversation.conversation_id === id
          ? { ...conversation, has_unread: true, unread_count: 1 }
          : conversation,
      ),
    })),
}));

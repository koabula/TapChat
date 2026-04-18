import { create } from "zustand";

export interface Conversation {
  conversation_id: string;
  peer_user_id: string;
  state: string;
  display_name: string | null;
  last_message: string | null;
  last_message_time: number | null;
  message_count: number;
  unread_count: number;
  has_unread: boolean;
}

interface ConversationsState {
  conversations: Conversation[];
  activeConversationId: string | null;
  setConversations: (conversations: Conversation[]) => void;
  setActiveConversation: (id: string | null) => void;
  addConversation: (conversation: Conversation) => void;
  updateConversation: (id: string, updates: Partial<Conversation>) => void;
  clearUnread: (id: string) => void;
  markUnread: (id: string) => void;
}

export const useConversationsStore = create<ConversationsState>((set) => ({
  conversations: [],
  activeConversationId: null,
  setConversations: (conversations) => set({ conversations }),
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

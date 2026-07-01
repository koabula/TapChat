import { create } from "zustand";
import type {
  ConversationSummary,
  GroupCursor,
  GroupRole,
  RecoveryDiagnostics,
} from "../lib/types";
import type { GroupConversationSummary } from "../lib/tauri";

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
  // Group-specific metadata (all optional; direct conversations default
  // to the placeholder values below). Mirrors the core's
  // `ConversationSummary` extension added in Phase 6 Wave A.
  kind: "direct" | "group";
  title: string | null;
  group_id: string | null;
  member_count: number | null;
  group_role: GroupRole | null;
  group_cursor: GroupCursor | null;
  recovery: RecoveryDiagnostics | null;
  /**
   * Unix ms timestamp when the group was dissolved (owner-only atomic
   * seal, PLAN_GROUP Phase 6 / Wave A). `null` for active groups and
   * for every direct conversation.
   *
   * Populated from `GroupConversationSummary` via
   * [`mergeGroupConversationSnapshot`]; the underlying
   * `ConversationSummary` sent over the `core-update` event does not
   * carry this field, so direct-only refresh paths always leave it
   * `null`.
   */
  dissolved_at: number | null;
}

interface ContactDisplayName {
  user_id: string;
  display_name: string | null;
}

interface SetConversationsOptions {
  markUnread?: boolean;
  replace?: boolean;
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
  /**
   * Merge authoritative group-specific metadata (title, member_count,
   * group_role, dissolved_at) into the store.
   *
   * Called from `useCoreUpdate` after the hook fetches a fresh
   * `listGroupConversations` payload on every `core-update` that may
   * have touched the group roster. Unlike [`mergeConversationSnapshot`]
   * this method preserves existing `message_count` / `last_message`
   * fields derived from the direct-style snapshot — it only refines
   * group metadata without resetting the chat-preview fields.
   */
  mergeGroupConversationSnapshot: (snapshots: GroupConversationSummary[]) => void;
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
  replace: boolean,
): Conversation[] {
  const previousById = new Map(
    previous.map((conversation) => [conversation.conversation_id, conversation]),
  );

  const mergedIncoming = incoming.map((conversation) => {
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
      display_name: conversation.display_name,
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
      // Preserve group-specific metadata that arrived earlier through a
      // group-only merge path (`mergeGroupConversationSnapshot`) when
      // the direct-style `mergeConversationSnapshot` refresh does not
      // carry it.
      kind: conversation.kind ?? prior?.kind ?? "direct",
      title: conversation.title ?? prior?.title ?? null,
      group_id: conversation.group_id ?? prior?.group_id ?? null,
      member_count: conversation.member_count ?? prior?.member_count ?? null,
      group_role: conversation.group_role ?? prior?.group_role ?? null,
      group_cursor: conversation.group_cursor ?? prior?.group_cursor ?? null,
      recovery: conversation.recovery ?? prior?.recovery ?? null,
      dissolved_at: conversation.dissolved_at ?? prior?.dissolved_at ?? null,
    };
  });
  if (replace) {
    return mergedIncoming;
  }
  const incomingIds = new Set(incoming.map((conversation) => conversation.conversation_id));
  return [
    ...mergedIncoming,
    ...previous.filter((conversation) => !incomingIds.has(conversation.conversation_id)),
  ];
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
        options?.replace ?? false,
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
        display_name:
          displayNameByUserId.get(conversation.peer_user_id) ??
          conversation.display_name ??
          null,
        last_message: displayMessagePreview(conversation),
        last_message_time: null,
        message_count: conversation.message_count ?? 0,
        last_activity_key: activityKeyForConversationSummary(conversation),
        unread_count: 0,
        has_unread: false,
        kind: conversation.kind ?? "direct",
        title: conversation.title ?? null,
        group_id: conversation.group_id ?? null,
        member_count: conversation.member_count ?? null,
        group_role: conversation.group_role ?? null,
        group_cursor: conversation.group_cursor ?? null,
        recovery: conversation.recovery ?? null,
        // `ConversationSummary` does not currently carry `dissolved_at`;
        // the `useCoreUpdate` hook fans out to `getGroupSnapshot` for
        // groups and merges the authoritative dissolved_at via the
        // group-specific merger (see `mergeGroupConversationSnapshot`).
        dissolved_at: null,
      }));

      return {
        conversations: mergeConversationState(
          state.conversations,
          mappedConversations,
          state.activeConversationId,
          options?.markUnread ?? false,
          options?.replace ?? false,
        ),
      };
    }),
  mergeGroupConversationSnapshot: (snapshots) =>
    set((state) => {
      if (snapshots.length === 0) {
        return state;
      }
      const byId = new Map(
        snapshots.map((summary) => [summary.conversation_id, summary]),
      );
      const existingIds = new Set(
        state.conversations.map((conversation) => conversation.conversation_id),
      );
      const conversations = state.conversations.map((conversation) => {
        const group = byId.get(conversation.conversation_id);
        if (!group) {
          return conversation;
        }
        return {
          ...conversation,
          // The group-specific snapshot owns the authoritative group
          // metadata; direct-style last_message / last_activity_key
          // fields are untouched here.
          kind: "group" as const,
          title: group.title,
          group_id: group.group_id,
          member_count: group.member_count,
          group_role: group.local_role,
          recovery: conversation.recovery,
          dissolved_at: group.dissolved_at,
          // Surface the group state (active / dissolved / etc) so UI
          // components can branch on it without a separate fetch.
          state: group.conversation_state,
        };
      });
      const missingGroups: Conversation[] = snapshots
        .filter((group) => !existingIds.has(group.conversation_id))
        .map((group) => ({
          conversation_id: group.conversation_id,
          peer_user_id: group.group_id,
          state: group.conversation_state,
          display_name: group.title,
          last_message: group.last_message_preview ?? group.title,
          last_message_time: null,
          message_count: group.message_count,
          last_activity_key: [
            group.conversation_id,
            String(group.message_count ?? 0),
            group.last_message_preview?.trim() ?? group.title,
          ].join("|"),
          unread_count: 0,
          has_unread: false,
          kind: "group" as const,
          title: group.title,
          group_id: group.group_id,
          member_count: group.member_count,
          group_role: group.local_role,
          group_cursor: null,
          recovery: null,
          dissolved_at: group.dissolved_at,
        }));
      return { conversations: [...conversations, ...missingGroups] };
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

import { useNavigate, useParams } from "react-router";
import { Users } from "lucide-react";
import GroupSyncIndicator from "@/components/group/GroupSyncIndicator";
import { useConversationsStore } from "@/store/conversations";
import { useGroupSyncStore } from "@/store/groupSync";

interface ConversationListProps {
  searchQuery?: string;
}

export default function ConversationList({ searchQuery = "" }: ConversationListProps) {
  const navigate = useNavigate();
  const { id: activeId } = useParams();
  const { conversations } = useConversationsStore();
  const statuses = useGroupSyncStore((s) => s.statuses);

  // Filter conversations based on search query
  const filteredConversations = conversations.filter((conv) => {
    if (!searchQuery.trim()) return true;
    const query = searchQuery.toLowerCase();
    if (conv.kind === "group") {
      return (
        (conv.title?.toLowerCase().includes(query) ?? false) ||
        (conv.group_id?.toLowerCase().includes(query) ?? false)
      );
    }
    return (
      conv.peer_user_id.toLowerCase().includes(query) ||
      conv.display_name?.toLowerCase().includes(query) === true
    );
  });

  const formatTime = (timestamp: number | null | undefined) => {
    if (!timestamp) return "";
    const date = new Date(timestamp);
    const now = new Date();
    const diffDays = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60 * 24));
    if (diffDays === 0) {
      return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    } else if (diffDays < 7) {
      return date.toLocaleDateString([], { weekday: "short" });
    } else {
      return date.toLocaleDateString([], { month: "short", day: "numeric" });
    }
  };

  return (
    <div className="space-y-0.5 p-1.5">
      {filteredConversations.length === 0 && searchQuery.trim() && (
        <div className="px-3 py-8 text-center text-sm">
          <div className="text-muted-color">No conversations match "{searchQuery}"</div>
        </div>
      )}

      {filteredConversations.length === 0 && !searchQuery.trim() && (
        <div className="px-3 py-8 text-center text-sm">
          <div className="text-muted-color">No conversations yet</div>
          <button
            className="btn btn-secondary mt-3 text-sm"
            onClick={() => navigate("/contacts")}
          >
            Add a contact
          </button>
        </div>
      )}

      {filteredConversations.map((conv) => {
        const isGroup = conv.kind === "group";
        // Group rendering ---------------------------------------------------
        // Title fallback order: explicit manifest title → short hash of
        // the group_id (first 8 chars) → "Group". Member pill shows
        // count; role pill only renders for owner/admin (R2.2).
        const groupTitle =
          conv.title?.trim() ||
          (isGroup && conv.group_id
            ? conv.group_id.slice(0, 8)
            : null);
        const memberCountLabel =
          isGroup && typeof conv.member_count === "number"
            ? `${conv.member_count} member${conv.member_count === 1 ? "" : "s"}`
            : null;
        const showRolePill =
          isGroup && (conv.group_role === "owner" || conv.group_role === "admin");
        const dissolved = isGroup && conv.dissolved_at != null;

        const displayLabel = isGroup
          ? groupTitle ?? "Group"
          : conv.display_name || conv.peer_user_id;
        const unreadCount = conv.unread_count ?? (conv.has_unread ? 1 : 0);
        const hasUnread = unreadCount > 0 || conv.has_unread;

        return (
          <button
            key={conv.conversation_id}
            className={`conv-item relative flex min-h-[60px] w-full items-center gap-2.5 rounded-md px-2 py-2 text-left ${
              activeId === conv.conversation_id ? "active" : ""
            } ${dissolved ? "opacity-60" : ""}`}
            onClick={() => navigate(`/chat/${conv.conversation_id}`)}
          >
            {/* Avatar — group icon for groups, initial letter for direct chats. */}
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-surface-elevated text-muted-color">
              {isGroup ? (
                <Users size={17} />
              ) : (
                <span className="text-sm font-medium">
                  {(conv.display_name || conv.peer_user_id)[0]?.toUpperCase() || "?"}
                </span>
              )}
            </div>

            {/* Content */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center justify-between gap-2">
                <span
                  className={`truncate text-sm text-primary-color ${
                    hasUnread ? "font-semibold" : "font-medium"
                  }`}
                  title={displayLabel}
                >
                  {displayLabel}
                </span>
                <span className="w-12 shrink-0 text-right text-[11px] text-muted-color">
                  {formatTime(conv.last_message_time)}
                </span>
              </div>
              <div className="mt-0.5 flex items-center justify-between gap-2">
                <span className="truncate text-xs text-secondary-color">
                  {isGroup
                    ? conv.last_message || memberCountLabel || "Group chat"
                    : conv.last_message || conv.peer_user_id}
                </span>
                <div className="flex shrink-0 items-center gap-1">
                  {dissolved && (
                    <span className="badge badge-muted text-[10px] uppercase tracking-wide">
                      Dissolved
                    </span>
                  )}
                  {showRolePill && !dissolved && (
                    <span className="badge text-[10px] uppercase tracking-wide">
                      {conv.group_role}
                    </span>
                  )}
                  {isGroup && conv.group_id && !dissolved && (
                    <GroupSyncIndicator status={statuses[conv.group_id]} compact />
                  )}
                  {hasUnread && unreadCount > 1 && (
                    <span
                      className="flex h-5 min-w-[1.25rem] items-center justify-center rounded-full bg-primary px-1.5 text-[10px] font-semibold"
                      style={{ color: "var(--bubble-sent-text)" }}
                    >
                      {unreadCount > 99 ? "99+" : unreadCount}
                    </span>
                  )}
                  {hasUnread && unreadCount <= 1 && (
                    <span className="h-2 w-2 rounded-full bg-primary" aria-label="Unread messages" />
                  )}
                </div>
              </div>
            </div>
          </button>
        );
      })}
    </div>
  );
}

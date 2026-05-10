import { useNavigate, useParams } from "react-router";
import { Users } from "lucide-react";
import { useConversationsStore } from "@/store/conversations";

interface ConversationListProps {
  searchQuery?: string;
}

export default function ConversationList({ searchQuery = "" }: ConversationListProps) {
  const navigate = useNavigate();
  const { id: activeId } = useParams();
  const { conversations } = useConversationsStore();

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
    <div className="space-y-1 p-2">
      {filteredConversations.length === 0 && searchQuery.trim() && (
        <div className="text-center py-8 animate-fade-in">
          <div className="text-muted-color">No conversations match "{searchQuery}"</div>
        </div>
      )}

      {filteredConversations.length === 0 && !searchQuery.trim() && (
        <div className="text-center py-8 animate-fade-in">
          <div className="text-muted-color">No conversations yet</div>
          <button
            className="btn btn-secondary mt-2"
            onClick={() => navigate("/contacts")}
          >
            Add a contact
          </button>
        </div>
      )}

      {filteredConversations.map((conv, index) => {
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

        return (
          <button
            key={conv.conversation_id}
            className={`conv-item w-full flex items-center gap-3 p-2 rounded-lg ${
              activeId === conv.conversation_id ? "active" : ""
            } ${dissolved ? "opacity-60" : ""}`}
            onClick={() => navigate(`/chat/${conv.conversation_id}`)}
            style={{ animationDelay: `${index * 50}ms` }}
          >
            {/* Avatar — group icon for groups, initial letter for direct chats. */}
            <div className="avatar transition-medium">
              {isGroup ? (
                <Users size={20} />
              ) : (
                <span className="text-lg font-medium">
                  {(conv.display_name || conv.peer_user_id)[0]?.toUpperCase() || "?"}
                </span>
              )}
            </div>

            {/* Content */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center justify-between gap-2">
                <span className="text-primary-color truncate font-medium">
                  {displayLabel}
                </span>
                <span className="text-muted-color text-xs shrink-0">
                  {formatTime(conv.last_message_time)}
                </span>
              </div>
              <div className="flex items-center justify-between gap-2 mt-1">
                <span className="text-secondary-color truncate text-sm">
                  {isGroup
                    ? conv.last_message || memberCountLabel || "Group chat"
                    : conv.last_message || conv.peer_user_id}
                </span>
                <div className="flex items-center gap-1 shrink-0">
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
                  {conv.has_unread && (
                    <span
                      className="w-2.5 h-2.5 rounded-full bg-primary animate-scale-in"
                      aria-label="Unread messages"
                    />
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

import { useNavigate, useParams } from "react-router";
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
    return conv.peer_user_id.toLowerCase().includes(query);
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

      {filteredConversations.map((conv, index) => (
        <button
          key={conv.conversation_id}
          className={`conv-item w-full flex items-center gap-3 p-2 rounded-lg ${
            activeId === conv.conversation_id ? "active" : ""
          }`}
          onClick={() => navigate(`/chat/${conv.conversation_id}`)}
          style={{ animationDelay: `${index * 50}ms` }}
        >
          {/* Avatar */}
          <div className="avatar transition-medium">
            <span className="text-lg font-medium">{conv.peer_user_id[0]?.toUpperCase() || "?"}</span>
          </div>

          {/* Content */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between">
              <span className="text-primary-color truncate font-medium">
                {conv.peer_user_id}
              </span>
              <span className="text-muted-color text-xs">
                {formatTime(conv.last_message_time)}
              </span>
            </div>
            <div className="flex items-center justify-between mt-1">
              <span className="text-secondary-color truncate text-sm">
                {conv.last_message || "No messages"}
              </span>
              {conv.unread_count && conv.unread_count > 0 && (
                <span className="badge badge-primary animate-scale-in">
                  {conv.unread_count}
                </span>
              )}
            </div>
          </div>
        </button>
      ))}
    </div>
  );
}
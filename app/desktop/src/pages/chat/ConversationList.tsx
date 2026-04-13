import { useNavigate, useParams } from "react-router";
import { useConversationsStore } from "@/store/conversations";

interface ConversationItem {
  conversation_id: string;
  peer_user_id: string;
  last_message?: string | null;
  last_message_time?: number | null;
  unread_count?: number;
}

export default function ConversationList() {
  const navigate = useNavigate();
  const { id: activeId } = useParams();
  const { conversations } = useConversationsStore();

  // Placeholder data if no conversations loaded yet
  const items: ConversationItem[] = conversations.length > 0 ? conversations : [
    { conversation_id: "demo-1", peer_user_id: "Alice", last_message: "Hey there!", last_message_time: Date.now() - 3600000, unread_count: 0 },
    { conversation_id: "demo-2", peer_user_id: "Bob", last_message: "Photo attachment", last_message_time: Date.now() - 7200000, unread_count: 2 },
  ];

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
      {items.length === 0 && (
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

      {items.map((conv, index) => (
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
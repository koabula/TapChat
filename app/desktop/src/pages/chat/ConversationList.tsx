import { useNavigate, useParams } from "react-router";
import { useConversationsStore } from "@/store/conversations";

export default function ConversationList() {
  const navigate = useNavigate();
  const { id: activeId } = useParams();
  const { conversations } = useConversationsStore();

  // Placeholder data if no conversations loaded yet
  const items = conversations.length > 0 ? conversations : [
    { conversation_id: "demo-1", peer_user_id: "Alice", last_message: "Hey there!", last_message_time: Date.now() - 3600000, unread_count: 0 },
    { conversation_id: "demo-2", peer_user_id: "Bob", last_message: "Photo 📎", last_message_time: Date.now() - 7200000, unread_count: 2 },
  ];

  const formatTime = (timestamp: number | null) => {
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
      {items.map((conv) => (
        <button
          key={conv.conversation_id}
          className={`w-full flex items-center gap-3 p-2 rounded-lg hover:bg-surface-elevated ${
            activeId === conv.conversation_id ? "bg-surface-elevated" : ""
          }`}
          onClick={() => navigate(`/chat/${conv.conversation_id}`)}
        >
          {/* Avatar */}
          <div className="avatar">
            <span className="text-lg">{conv.peer_user_id[0]}</span>
          </div>

          {/* Content */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between">
              <span className="text-primary-color truncate">
                {conv.peer_user_id}
              </span>
              <span className="text-muted-color text-xs">
                {formatTime(conv.last_message_time)}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-secondary-color truncate text-sm">
                {conv.last_message}
              </span>
              {conv.unread_count > 0 && (
                <span className="badge badge-primary">
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
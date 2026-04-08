import type { ConversationListItem } from "../../lib/types";

export default function ChatsPane({
  conversations,
  selectedConversationId,
  onSelect,
}: {
  conversations: ConversationListItem[];
  selectedConversationId: string | null;
  onSelect: (conversation: ConversationListItem) => void;
}) {
  function shouldShowRecoveryBadge(recoveryStatus: string) {
    return recoveryStatus.trim().length > 0 && recoveryStatus.toLowerCase() !== "healthy";
  }

  if (!conversations.length) {
    return (
      <div className="pane-empty-state chats-empty-state">
        <strong>Transport is ready</strong>
        <small>Share your contact link or add a contact from the Contacts tab to start your first chat.</small>
      </div>
    );
  }
  return (
    <div className="chat-list">
      {conversations.map((conversation) => (
        <button
          key={conversation.conversation_id}
          className={selectedConversationId === conversation.conversation_id ? "chat-list-item active" : "chat-list-item"}
          onClick={() => onSelect(conversation)}
        >
          <div className="chat-avatar" aria-hidden="true">
            {conversation.peer_user_id.slice(0, 1).toUpperCase()}
          </div>
          <div className="chat-list-copy">
            <div className="chat-list-row">
              <strong>{conversation.peer_user_id}</strong>
              {shouldShowRecoveryBadge(conversation.recovery_status) && (
                <span className="status-chip nav-badge">{conversation.recovery_status}</span>
              )}
            </div>
            <small>{conversation.last_message_preview ?? "No messages yet"}</small>
          </div>
        </button>
      ))}
    </div>
  );
}

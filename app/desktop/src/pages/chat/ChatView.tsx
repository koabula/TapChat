import { useState, useEffect } from "react";
import { useParams } from "react-router";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

import MessageInput from "@/components/MessageInput";
import AttachmentPreview from "@/components/AttachmentPreview";

interface Message {
  message_id: string;
  sender_device_id: string;
  recipient_device_id: string;
  message_type: string;
  created_at: number;
  plaintext: string | null;
  has_attachment: boolean;
}

interface CoreUpdateEvent {
  state_update: {
    conversations_changed: boolean;
    messages_changed: boolean;
    contacts_changed: boolean;
    checkpoints_changed: boolean;
    system_statuses_changed: string[];
  };
  effects: unknown[];
  view_model?: {
    conversations: unknown[];
    messages: unknown[];
    contacts: unknown[];
    banners: unknown[];
    message_requests: unknown[];
    allowlist?: unknown;
  };
}

export default function ChatView() {
  const { id: conversationId } = useParams();
  const [messages, setMessages] = useState<Message[]>([]);
  const [loading, setLoading] = useState(false);
  const [peerName] = useState("Contact");

  // Subscribe to core-update events to refresh messages
  useEffect(() => {
    const unlisten = listen<CoreUpdateEvent>("core-update", (event) => {
      if (event.payload.state_update.messages_changed && conversationId) {
        loadMessages();
      }
    });

    return () => {
      unlisten.then((fn) => fn());
    };
  }, [conversationId]);

  // Load messages when conversation changes
  useEffect(() => {
    if (conversationId) {
      loadMessages();
    }
  }, [conversationId]);

  const loadMessages = async () => {
    if (!conversationId) return;

    setLoading(true);
    try {
      const result = await invoke<Message[]>("get_messages", {
        conversationId,
      });
      setMessages(result);
    } catch (err) {
      console.error("Failed to load messages:", err);
      setMessages([]);
    } finally {
      setLoading(false);
    }
  };

  const formatTime = (timestamp: number) => {
    return new Date(timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  };

  const isMyMessage = (msg: Message) => {
    // If sender_device_id matches our device, it's our message
    // For now, use a simple check - backend should provide this
    return msg.message_type === "sent" || msg.sender_device_id === "me";
  };

  if (!conversationId) {
    return (
      <div className="flex-1 flex items-center justify-center bg-base">
        <div className="text-center">
          <div className="w-16 h-16 rounded-full bg-surface-elevated mb-4 flex items-center justify-center">
            <span className="text-2xl text-muted-color">💬</span>
          </div>
          <h2 className="text-xl text-muted-color mb-2">Select a conversation</h2>
          <p className="text-muted-color text-sm">or create a new one to start messaging</p>
        </div>
      </div>
    );
  }

  // Get display messages - show placeholder if loading or empty
  const displayMessages = loading ? [] : messages.length > 0 ? messages : [
    // Placeholder for new conversations
    { message_id: "placeholder", sender_device_id: "", recipient_device_id: "", message_type: "placeholder", created_at: Date.now(), plaintext: "No messages yet. Say hello!", has_attachment: false },
  ];

  return (
    <div className="flex-1 flex flex-col bg-base">
      {/* Header */}
      <header className="flex items-center gap-3 p-3 border-b border-default bg-surface">
        <div className="avatar">
          <span className="text-lg">{peerName[0]?.toUpperCase() || "?"}</span>
        </div>
        <div className="flex-1">
          <h2 className="text-primary-color font-medium">{peerName}</h2>
          <span className="text-muted-color text-xs flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full status-success" />
            End-to-end encrypted
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button className="btn btn-ghost px-2" title="Search messages">
            🔍
          </button>
          <button className="btn btn-ghost px-2" title="More options">
            ⋮
          </button>
        </div>
      </header>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {loading && (
          <div className="text-center text-muted-color">Loading messages...</div>
        )}

        {displayMessages.map((msg) => (
          <div
            key={msg.message_id}
            className={`flex ${
              isMyMessage(msg) ? "justify-end" : "justify-start"
            }`}
          >
            {msg.has_attachment ? (
              <div className={`bubble ${isMyMessage(msg) ? "bubble-sent" : "bubble-received"}`}>
                <AttachmentPreview
                  messageId={msg.message_id}
                  conversationId={conversationId}
                  reference={msg.message_id} // TODO: proper reference from message
                  mimeType="application/octet-stream"
                  fileName={undefined}
                />
                {msg.plaintext && (
                  <span className="block mt-2">{msg.plaintext}</span>
                )}
                <span className="block text-xs text-right mt-1 opacity-60">
                  {formatTime(msg.created_at)}
                  {isMyMessage(msg) && " ✓✓"}
                </span>
              </div>
            ) : (
              <div className={`bubble ${isMyMessage(msg) ? "bubble-sent" : "bubble-received"}`}>
                <span>{msg.plaintext}</span>
                <span className="block text-xs text-right mt-1 opacity-60">
                  {formatTime(msg.created_at)}
                  {isMyMessage(msg) && " ✓✓"}
                </span>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Input */}
      <MessageInput
        conversationId={conversationId}
        onSent={loadMessages}
      />
    </div>
  );
}
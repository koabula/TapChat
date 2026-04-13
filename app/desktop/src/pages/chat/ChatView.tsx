import { useState } from "react";
import { useParams } from "react-router";
import { invoke } from "@tauri-apps/api/core";

interface Message {
  message_id: string;
  sender_user_id: string;
  content: string | null;
  has_attachment: boolean;
  created_at: number;
}

export default function ChatView() {
  const { id: conversationId } = useParams();
  const [messages] = useState<Message[]>([]);
  const [inputText, setInputText] = useState("");
  const [sending, setSending] = useState(false);

  // Placeholder messages
  const displayMessages = messages.length > 0 ? messages : [
    { message_id: "m1", sender_user_id: "Alice", content: "Hi, how are you?", has_attachment: false, created_at: Date.now() - 600000 },
    { message_id: "m2", sender_user_id: "me", content: "I'm good, thanks!", has_attachment: false, created_at: Date.now() - 300000 },
    { message_id: "m3", sender_user_id: "Alice", content: null, has_attachment: true, created_at: Date.now() },
  ];

  const handleSend = async () => {
    if (!inputText.trim() || !conversationId) return;

    setSending(true);
    try {
      await invoke("send_text", {
        conversationId,
        plaintext: inputText,
      });
      setInputText("");
      // TODO: Refresh messages after send
    } catch (err) {
      console.error("Failed to send:", err);
    } finally {
      setSending(false);
    }
  };

  const formatTime = (timestamp: number) => {
    return new Date(timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  };

  if (!conversationId) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <div className="text-center">
          <h2 className="text-xl text-muted-color mb-2">Select a conversation</h2>
          <p className="text-muted-color text-sm">to start messaging</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 flex flex-col">
      {/* Header */}
      <header className="flex items-center gap-3 p-3 border-b border-default">
        <div className="avatar">
          <span className="text-lg">A</span>
        </div>
        <div>
          <h2 className="text-primary-color font-medium">Alice</h2>
          <span className="text-muted-color text-xs flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full status-success" />
            End-to-end encrypted
          </span>
        </div>
      </header>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {displayMessages.map((msg) => (
          <div
            key={msg.message_id}
            className={`flex ${
              msg.sender_user_id === "me" ? "justify-end" : "justify-start"
            }`}
          >
            {msg.has_attachment ? (
              <div className={`bubble ${msg.sender_user_id === "me" ? "bubble-sent" : "bubble-received"}`}>
                <span className="flex items-center gap-2">
                  📎 <span className="text-sm">photo.jpg</span>
                </span>
                <button className="text-xs underline mt-1">Download</button>
              </div>
            ) : (
              <div className={`bubble ${msg.sender_user_id === "me" ? "bubble-sent" : "bubble-received"}`}>
                <span>{msg.content}</span>
                <span className="block text-xs text-right mt-1 opacity-60">
                  {formatTime(msg.created_at)}
                  {msg.sender_user_id === "me" && " ✓✓"}
                </span>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Input */}
      <div className="p-3 border-t border-default flex items-center gap-2">
        <button className="btn btn-ghost px-2" title="Attach file">
          📎
        </button>
        <input
          className="input flex-1"
          placeholder="Type a message..."
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              handleSend();
            }
          }}
        />
        <button
          className="btn btn-primary px-3"
          onClick={handleSend}
          disabled={sending || !inputText.trim()}
        >
          Send
        </button>
      </div>
    </div>
  );
}
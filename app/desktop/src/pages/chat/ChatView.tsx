import { useState, useEffect, useMemo, useRef } from "react";
import { useParams } from "react-router";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

import MessageInput from "@/components/MessageInput";
import AttachmentPreview from "@/components/AttachmentPreview";
import { useContactsStore } from "@/store/contacts";
import { useConversationsStore } from "@/store/conversations";
import { useSessionStore } from "@/store/session";
import type { Message, CoreUpdateEvent } from "@/lib/types";

// Interface for send_text result
interface SendMessageResult {
  message_id: string;
  conversation_id: string;
  sender_device_id: string;
  plaintext: string;
  created_at: number;
}

export default function ChatView() {
  const { id: conversationId } = useParams();
  const [messages, setMessages] = useState<Message[]>([]);
  const [loading, setLoading] = useState(false);

  // Refs for auto-scrolling
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const messagesContainerRef = useRef<HTMLDivElement>(null);
  const shouldAutoScrollRef = useRef(true);

  // Get stores for peer name resolution
  const { contacts } = useContactsStore();
  const { conversations, setActiveConversation } = useConversationsStore();
  const { deviceId } = useSessionStore();

  const activeConversation = useMemo(
    () => conversations.find((conversation) => conversation.conversation_id === conversationId),
    [conversationId, conversations],
  );

  // Resolve peer name from contacts store
  const peerName = useMemo(() => {
    if (!conversationId) return "Contact";
    if (!activeConversation) return "Contact";

    const contact = contacts.find((item) => item.user_id === activeConversation.peer_user_id);
    return contact?.display_name || activeConversation.display_name || activeConversation.peer_user_id;
  }, [conversationId, activeConversation, contacts]);

  // Scroll to bottom function
  const scrollToBottom = (behavior: "smooth" | "instant" = "smooth") => {
    if (messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({
        behavior: behavior === "smooth" ? "smooth" : "auto",
        block: "end",
      });
    }
  };

  // Track if user is near bottom (for auto-scroll decisions)
  const handleScroll = () => {
    if (messagesContainerRef.current) {
      const { scrollTop, scrollHeight, clientHeight } = messagesContainerRef.current;
      const isNearBottom = scrollHeight - scrollTop - clientHeight < 100;
      shouldAutoScrollRef.current = isNearBottom;
    }
  };

  // Auto-scroll when messages change
  useEffect(() => {
    if (!loading && messages.length > 0) {
      // On initial load, scroll to bottom instantly
      // On message updates, only scroll if user is near bottom
      scrollToBottom(shouldAutoScrollRef.current ? "smooth" : "instant");
    }
  }, [messages, loading]);

  useEffect(() => {
    setActiveConversation(conversationId ?? null);
    return () => {
      setActiveConversation(null);
    };
  }, [conversationId, setActiveConversation]);

  // Subscribe to core-update events to refresh messages
  useEffect(() => {
    if (!conversationId) return;

    const unlisten = listen<CoreUpdateEvent>("core-update", (event) => {
      if (event.payload.state_update.messages_changed) {
        // Refresh messages without showing loading state (avoid UI flicker)
        refreshMessages();
      }
    });

    return () => {
      unlisten.then((fn) => fn());
    };
  }, [conversationId]);

  // Load messages when conversation changes (show loading only on initial load)
  useEffect(() => {
    if (conversationId) {
      loadMessages();
    }
  }, [conversationId]);

  const loadMessages = async () => {
    if (!conversationId) return;

    setLoading(true);
    try {
      const result = await invoke<Message[]>("get_messages", { conversationId });
      setMessages(result);
    } catch (err) {
      console.error(`[ChatView] Failed to load messages: ${String(err)}`);
      setMessages([]);
    } finally {
      setLoading(false);
    }
  };

  // Refresh messages without loading state (for updates)
  const refreshMessages = async () => {
    if (!conversationId) return;

    try {
      const result = await invoke<Message[]>("get_messages", { conversationId });
      setMessages(result);
    } catch (err) {
      console.error(`[ChatView] Failed to refresh messages: ${String(err)}`);
    }
  };

  // Handle sent message - add immediately to local display
  const handleSentMessage = (sentMsg?: SendMessageResult) => {
    if (!sentMsg || !conversationId) return;

    // Create a temporary message for immediate display
    const tempMessage: Message = {
      message_id: sentMsg.message_id,
      sender_device_id: sentMsg.sender_device_id,
      recipient_device_id: deviceId || "",
      message_type: "sent",
      created_at: sentMsg.created_at,
      plaintext: sentMsg.plaintext,
      has_attachment: false,
      storage_refs: [],
    };

    // Add to messages list if not already present
    setMessages(prev => {
      if (prev.some(m => m.message_id === sentMsg.message_id)) {
        return prev;
      }
      return [...prev, tempMessage];
    });
  };

  const formatTime = (timestamp: number) => {
    return new Date(timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  };

  // Format date separator
  const formatDateSeparator = (timestamp: number, now: Date): string | null => {
    const date = new Date(timestamp);
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const messageDate = new Date(date.getFullYear(), date.getMonth(), date.getDate());

    // Same day - no separator
    if (messageDate.getTime() === today.getTime()) {
      return null;
    }

    // Format options
    const monthNames = ["Jan.", "Feb.", "Mar.", "Apr.", "May.", "Jun.", "Jul.", "Aug.", "Sep.", "Oct.", "Nov.", "Dec."];
    const dayNames = ["Sun.", "Mon.", "Tue.", "Wed.", "Thu.", "Fri.", "Sat."];

    const month = monthNames[date.getMonth()];
    const day = date.getDate();
    const weekday = dayNames[date.getDay()];

    // Different year - include year
    if (date.getFullYear() !== now.getFullYear()) {
      return `${date.getFullYear()} ${month} ${day} ${weekday}`;
    }

    // Same year but different day
    return `${month} ${day} ${weekday}`;
  };

  // Build message list with date separators
  const buildMessageListWithSeparators = () => {
    if (loading || messages.length === 0) return null;

    const now = new Date();
    const result: React.ReactNode[] = [];
    let lastDateKey: string | null = null;

    messages.forEach((msg, index) => {
      const dateStr = formatDateSeparator(msg.created_at, now);
      const dateKey = dateStr || "today";

      // Add date separator if this is a new day
      if (dateKey !== lastDateKey && dateStr) {
        result.push(
          <div key={`date-${msg.created_at}`} className="date-separator">
            <span>{dateStr}</span>
          </div>
        );
      }
      lastDateKey = dateKey;

      // Add message
      result.push(
        <div
          key={msg.message_id}
          className={`flex ${isMyMessage(msg) ? "justify-end" : "justify-start"}`}
          style={{ animationDelay: `${index * 30}ms` }}
        >
          {msg.has_attachment && msg.storage_refs && msg.storage_refs.length > 0 ? (
            <div className={`bubble ${isMyMessage(msg) ? "bubble-sent" : "bubble-received"} animate-fade-in-up`}>
              <AttachmentPreview
                messageId={msg.message_id}
                conversationId={conversationId!}
                reference={msg.storage_refs[0]}
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
            <div className={`bubble ${isMyMessage(msg) ? "bubble-sent" : "bubble-received"} animate-fade-in-up`}>
              <span>{msg.plaintext || "[empty message]"}</span>
              <span className="block text-xs text-right mt-1 opacity-60">
                {formatTime(msg.created_at)}
                {isMyMessage(msg) && " ✓✓"}
              </span>
            </div>
          )}
        </div>
      );
    });

    return result;
  };

  // Determine if message was sent by me
  // Backend returns "sent" for outgoing, "received" for incoming
  const isMyMessage = (msg: Message) => {
    return msg.message_type === "sent";
  };

  // No conversation selected - show empty state
  if (!conversationId) {
    return (
      <div className="flex-1 flex items-center justify-center bg-base">
        <div className="text-center animate-fade-in">
          <div className="w-16 h-16 rounded-full bg-surface-elevated mb-4 flex items-center justify-center animate-scale-in">
            <span className="text-2xl text-muted-color">💬</span>
          </div>
          <h2 className="text-xl text-muted-color mb-2">Select a conversation</h2>
          <p className="text-muted-color text-sm">or create a new one to start messaging</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 flex flex-col bg-base min-h-0">
      {/* Header */}
      <header className="flex items-center gap-3 p-3 border-b border-default bg-surface animate-fade-in-down">
        <div className="avatar animate-scale-in">
          <span className="text-lg font-medium">{peerName[0]?.toUpperCase() || "?"}</span>
        </div>
        <div className="flex-1">
          <h2 className="text-primary-color font-medium">{peerName}</h2>
          <span className="text-muted-color text-xs flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full status-success animate-pulse" />
            End-to-end encrypted
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button className="btn btn-ghost px-2 transition-fast" title="Search messages">
            🔍
          </button>
          <button className="btn btn-ghost px-2 transition-fast" title="More options">
            ⋮
          </button>
        </div>
      </header>

      {/* Messages */}
      <div
        ref={messagesContainerRef}
        onScroll={handleScroll}
        className="flex-1 min-h-0 overflow-y-auto overscroll-contain p-4 space-y-3"
      >
        {loading && (
          <div className="text-center py-8">
            <div className="inline-block animate-spin text-2xl text-muted-color">⏳</div>
            <p className="text-muted-color mt-2 animate-pulse">Loading messages...</p>
          </div>
        )}

        {!loading && messages.length === 0 && (
          <div className="text-center py-8 animate-fade-in">
            <div className="text-muted-color">
              <p className="mb-2">Start the conversation</p>
              <p className="text-sm">Send a message below</p>
            </div>
          </div>
        )}

        {buildMessageListWithSeparators()}

        {/* Scroll anchor */}
        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <MessageInput
        conversationId={conversationId}
        onSent={handleSentMessage}
      />
    </div>
  );
}

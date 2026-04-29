import { useState, useEffect, useMemo, useRef } from "react";
import { useParams } from "react-router";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { MessageCircle, Search, Loader, EllipsisVertical } from "lucide-react";

import MessageInput from "@/components/MessageInput";
import AttachmentPreview from "@/components/AttachmentPreview";
import { useContactsStore } from "@/store/contacts";
import { useConversationsStore } from "@/store/conversations";
import { useSessionStore } from "@/store/session";
import type { Message, CoreUpdateEvent } from "@/lib/types";

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

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const messagesContainerRef = useRef<HTMLDivElement>(null);
  const shouldAutoScrollRef = useRef(true);

  const { contacts } = useContactsStore();
  const { conversations, setActiveConversation } = useConversationsStore();
  const { deviceId } = useSessionStore();

  const activeConversation = useMemo(
    () => conversations.find((c) => c.conversation_id === conversationId),
    [conversationId, conversations],
  );

  const peerName = useMemo(() => {
    if (!conversationId || !activeConversation) return "Contact";
    const contact = contacts.find((item) => item.user_id === activeConversation.peer_user_id);
    return contact?.display_name || activeConversation.display_name || activeConversation.peer_user_id;
  }, [conversationId, activeConversation, contacts]);

  const scrollToBottom = (behavior: "smooth" | "instant" = "smooth") => {
    messagesEndRef.current?.scrollIntoView({
      behavior: behavior === "smooth" ? "smooth" : "auto",
      block: "end",
    });
  };

  const handleScroll = () => {
    if (!messagesContainerRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = messagesContainerRef.current;
    shouldAutoScrollRef.current = scrollHeight - scrollTop - clientHeight < 100;
  };

  useEffect(() => {
    if (!loading && messages.length > 0) {
      scrollToBottom(shouldAutoScrollRef.current ? "smooth" : "instant");
    }
  }, [messages, loading]);

  useEffect(() => {
    setActiveConversation(conversationId ?? null);
    return () => { setActiveConversation(null); };
  }, [conversationId, setActiveConversation]);

  useEffect(() => {
    if (!conversationId) return;
    const unlisten = listen<CoreUpdateEvent>("core-update", (event) => {
      if (event.payload.state_update.messages_changed) {
        refreshMessages();
      }
    });
    return () => { unlisten.then((fn) => fn()); };
  }, [conversationId]);

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

  const refreshMessages = async () => {
    if (!conversationId) return;
    try {
      const result = await invoke<Message[]>("get_messages", { conversationId });
      setMessages(result);
    } catch (err) {
      console.error(`[ChatView] Failed to refresh messages: ${String(err)}`);
    }
  };

  const handleSentMessage = (sentMsg?: SendMessageResult) => {
    if (!sentMsg || !conversationId) return;
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
    setMessages((prev) => {
      if (prev.some((m) => m.message_id === sentMsg.message_id)) return prev;
      return [...prev, tempMessage];
    });
  };

  const formatTime = (timestamp: number) => {
    return new Date(timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  };

  const formatDateSeparator = (timestamp: number, now: Date): string | null => {
    const date = new Date(timestamp);
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const messageDate = new Date(date.getFullYear(), date.getMonth(), date.getDate());
    if (messageDate.getTime() === today.getTime()) return "Today";
    const monthNames = ["Jan.", "Feb.", "Mar.", "Apr.", "May.", "Jun.", "Jul.", "Aug.", "Sep.", "Oct.", "Nov.", "Dec."];
    const dayNames = ["Sun.", "Mon.", "Tue.", "Wed.", "Thu.", "Fri.", "Sat."];
    const month = monthNames[date.getMonth()];
    const day = date.getDate();
    const weekday = dayNames[date.getDay()];
    if (date.getFullYear() !== now.getFullYear()) {
      return `${date.getFullYear()} ${month} ${day} ${weekday}`;
    }
    return `${month} ${day} ${weekday}`;
  };

  const buildMessageListWithSeparators = () => {
    if (loading || messages.length === 0) return null;

    const now = new Date();
    const result: React.ReactNode[] = [];
    let lastDateKey: string | null = null;

    messages.forEach((msg, index) => {
      const dateStr = formatDateSeparator(msg.created_at, now);
      const dateKey = dateStr || "today";

      if (dateKey !== lastDateKey && dateStr) {
        result.push(
          <div key={`date-${msg.created_at}`} className="date-separator">
            <span>{dateStr}</span>
          </div>,
        );
      }
      lastDateKey = dateKey;

      result.push(
        <div
          key={msg.message_id}
          className={`flex ${isMyMessage(msg) ? "justify-end" : "justify-start"}`}
          style={{ animationDelay: `${index * 30}ms` }}
        >
          {renderMessageBubble(msg)}
        </div>,
      );
    });

    return result;
  };

  const renderMessageBubble = (msg: Message) => {
    const isSent = isMyMessage(msg);
    const bubbleCls = `bubble ${isSent ? "bubble-sent" : "bubble-received"} animate-fade-in-up`;
    const refs = msg.storage_refs ?? [];
    const hasAttachment = msg.has_attachment || refs.length > 0;

    if (!hasAttachment) {
      const attachmentMeta = tryParseAttachmentFromPlaintext(msg.plaintext);
      if (attachmentMeta) {
        return (
          <div className={bubbleCls}>
            <AttachmentPreview
              messageId={msg.message_id}
              conversationId={conversationId!}
              reference=""
              mimeType={attachmentMeta.mimeType}
              fileName={attachmentMeta.fileName}
              showInline={false}
            />
            <span className="block text-xs text-right mt-1 opacity-60">
              {formatTime(msg.created_at)}
            </span>
          </div>
        );
      }
      return (
        <div className={bubbleCls}>
          <span className="block whitespace-pre-wrap break-words overflow-hidden">
            {msg.plaintext || "[empty message]"}
          </span>
          <span className="block text-xs text-right mt-1 opacity-60">
            {formatTime(msg.created_at)}
          </span>
        </div>
      );
    }

    const validRefs = refs.filter((r) => r.ref);
    const attachmentRefs = validRefs.length > 0 ? validRefs : refs;

    return (
      <div className={bubbleCls}>
        <div className="flex flex-col gap-2">
          {attachmentRefs.map((ref, index) => (
            <AttachmentPreview
              key={`${msg.message_id}-${index}`}
              messageId={msg.message_id}
              conversationId={conversationId!}
              reference={ref.ref || ""}
              mimeType={ref.mime_type || "application/octet-stream"}
              fileName={ref.file_name}
              sizeBytes={ref.size_bytes}
              showInline={false}
            />
          ))}
        </div>
        <span className="block text-xs text-right mt-1 opacity-60">
          {formatTime(msg.created_at)}
        </span>
      </div>
    );
  };

  const tryParseAttachmentFromPlaintext = (plaintext: string | null): { fileName: string; mimeType: string } | null => {
    if (!plaintext) return null;
    try {
      const parsed = JSON.parse(plaintext);
      if (parsed && typeof parsed === "object" && "mime_type" in parsed) {
        return {
          fileName: parsed.file_name || "Attachment",
          mimeType: parsed.mime_type || "application/octet-stream",
        };
      }
    } catch {
      // Plain text.
    }
    return null;
  };

  const isMyMessage = (msg: Message) => msg.message_type === "sent";

  if (!conversationId) {
    return (
      <div className="flex-1 flex items-center justify-center bg-base">
        <div className="text-center animate-fade-in">
          <div className="w-16 h-16 rounded-full bg-surface-elevated mb-4 flex items-center justify-center animate-scale-in">
            <MessageCircle size={28} className="text-muted-color" />
          </div>
          <h2 className="text-xl text-muted-color mb-2">Select a conversation</h2>
          <p className="text-muted-color text-sm">or create a new one to start messaging</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 flex flex-col bg-base min-h-0">
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
            <Search size={18} />
          </button>
          <button className="btn btn-ghost px-2 transition-fast" title="More options">
            <EllipsisVertical size={18} />
          </button>
        </div>
      </header>

      <div
        ref={messagesContainerRef}
        onScroll={handleScroll}
        className="flex-1 min-h-0 overflow-y-auto overscroll-contain p-4 space-y-3"
      >
        {loading && (
          <div className="text-center py-8">
            <div className="inline-block text-2xl text-muted-color">
              <Loader size={28} className="animate-spin" />
            </div>
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
        <div ref={messagesEndRef} />
      </div>

      <MessageInput
        conversationId={conversationId}
        onSent={handleSentMessage}
      />
    </div>
  );
}

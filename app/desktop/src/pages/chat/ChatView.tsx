import { useState, useEffect, useMemo, useRef } from "react";
import { useParams } from "react-router";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  Clapperboard,
  EllipsisVertical,
  Loader,
  MessageCircle,
  Music,
  RefreshCw,
  Search,
  UserX,
  Users,
} from "lucide-react";

import MessageInput from "@/components/MessageInput";
import AttachmentPreview from "@/components/AttachmentPreview";
import ImageGrid from "@/components/ImageGrid";
import MediaLightbox, { type MediaItem } from "@/components/MediaLightbox";
import GroupMemberDrawer from "@/components/group/GroupMemberDrawer";
import GroupSyncIndicator from "@/components/group/GroupSyncIndicator";
import { useContactsStore } from "@/store/contacts";
import { useConversationsStore } from "@/store/conversations";
import { useSessionStore } from "@/store/session";
import { useGroupsStore } from "@/store/groups";
import { useGroupSyncStore } from "@/store/groupSync";
import {
  cloudflareDeploy,
  cloudflareLogin,
  cloudflarePreflight,
  cloudflareStatus,
  getGroupMessages,
  getGroupSnapshot,
  syncGroupOutbox,
  type GroupMessageView,
} from "@/lib/tauri";
import type { Message, CoreUpdateEvent, CloudflareStatus, StorageRef } from "@/lib/types";
import { buildGroupNameResolver } from "@/lib/groupDisplayNames";

interface SendMessageResult {
  message_id: string;
  conversation_id: string;
  sender_user_id?: string;
  sender_device_id: string;
  plaintext: string;
  created_at: number;
}

export default function ChatView() {
  const { id: conversationId } = useParams();
  const [messages, setMessages] = useState<Message[]>([]);
  const [groupMessages, setGroupMessages] = useState<GroupMessageView[]>([]);
  const [loading, setLoading] = useState(false);
  const [memberDrawerOpen, setMemberDrawerOpen] = useState(false);
  const [runtimeStatus, setRuntimeStatus] = useState<CloudflareStatus | null>(null);
  const [transportBusy, setTransportBusy] = useState(false);
  const [transportError, setTransportError] = useState<string | null>(null);
  const [manualSyncBusy, setManualSyncBusy] = useState(false);
  const [lightboxIndex, setLightboxIndex] = useState<number | null>(null);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const messagesContainerRef = useRef<HTMLDivElement>(null);
  const shouldAutoScrollRef = useRef(true);

  const { contacts } = useContactsStore();
  const { conversations, setActiveConversation } = useConversationsStore();
  const { deviceId, displayName: localDisplayName } = useSessionStore();
  const groupSnapshot = useGroupsStore((s) =>
    s.snapshots[
      conversations.find((c) => c.conversation_id === conversationId)?.group_id ?? ""
    ],
  );
  const setActiveGroupId = useGroupsStore((s) => s.setActiveGroupId);
  const setGroupSnapshot = useGroupsStore((s) => s.setSnapshot);

  const activeConversation = useMemo(
    () => conversations.find((c) => c.conversation_id === conversationId),
    [conversationId, conversations],
  );
  const groupSyncStatus = useGroupSyncStore((s) =>
    activeConversation?.group_id ? s.statuses[activeConversation.group_id] : undefined,
  );
  const markGroupOpened = useGroupSyncStore((s) => s.markGroupOpened);
  const markGroupSynced = useGroupSyncStore((s) => s.markSynced);
  const markGroupSyncFailed = useGroupSyncStore((s) => s.markSyncFailed);

  const isGroup = activeConversation?.kind === "group";
  const dissolved = isGroup && activeConversation?.dissolved_at != null;
  const activeDirectContact = useMemo(() => {
    if (!activeConversation || activeConversation.kind === "group") return null;
    return contacts.find((item) => item.user_id === activeConversation.peer_user_id) ?? null;
  }, [activeConversation, contacts]);
  const directClosed =
    !isGroup &&
    Boolean(activeConversation) &&
    (activeConversation?.state === "closed" ||
      activeConversation?.state === "archived" ||
      activeDirectContact?.relationship_status === "removed_by_me" ||
      activeDirectContact?.relationship_status === "removed_by_peer");
  const directClosedReason =
    activeConversation?.state === "archived"
      ? "This chat is archived."
      : directClosed
        ? "This chat is closed."
        : undefined;

  // Determine the local user's current status in this group so we can
  // fail-closed the composer when they have been removed / left /
  // dissolved the group (R15.1 / R15.2 / R15.3).
  const localUserId = useSessionStore((s) => s.userId) ?? "";
  const resolveGroupName = useMemo(
    () =>
      buildGroupNameResolver({
        manifest: groupSnapshot?.manifest ?? null,
        contacts,
        localUserId,
        localDisplayName,
      }),
    [contacts, groupSnapshot?.manifest, localDisplayName, localUserId],
  );
  const localMember = useMemo(() => {
    if (!isGroup || !groupSnapshot) return null;
    return (
      groupSnapshot.manifest.members.find((m) => m.user_id === localUserId) ?? null
    );
  }, [isGroup, groupSnapshot, localUserId]);
  const pendingGroupSetup =
    isGroup && (groupSnapshot?.pending_outbox_count ?? 0) > 0;
  const pendingJoinRequests =
    isGroup
      ? groupSnapshot?.join_requests.filter((request) => request.status === "pending")
          .length ?? 0
      : 0;
  const composerDisabled =
    directClosed ||
    dissolved ||
    pendingGroupSetup ||
    (isGroup &&
      (groupSnapshot?.local_role == null ||
        localMember?.status === "removed" ||
        localMember?.status === "left"));
  const composerTooltip = directClosed
    ? directClosedReason
    : dissolved
    ? "This group has been dissolved."
    : pendingGroupSetup
      ? "Group transport is waiting for Cloudflare runtime upgrade or sync."
    : composerDisabled
      ? "You are no longer a member of this group."
      : undefined;

  useEffect(() => {
    if (!pendingGroupSetup) {
      return;
    }
    cloudflareStatus()
      .then(setRuntimeStatus)
      .catch((err) => {
        console.debug(`[ChatView] cloudflare_status failed: ${String(err)}`);
      });
  }, [pendingGroupSetup]);

  const peerName = useMemo(() => {
    if (!conversationId || !activeConversation) return "Contact";
    if (activeConversation.kind === "group") {
      return (
        activeConversation.title?.trim() ||
        (activeConversation.group_id
          ? activeConversation.group_id.slice(0, 8)
          : "Group")
      );
    }
    const contact = contacts.find((item) => item.user_id === activeConversation.peer_user_id);
    return contact?.display_name || activeConversation.display_name || activeConversation.peer_user_id;
  }, [conversationId, activeConversation, contacts]);

  const conversationMediaItems = useMemo(() => {
    if (!conversationId) return [];
    if (isGroup) {
      return groupMessages.flatMap((message) =>
        message.kind === "bubble"
          ? refsToMediaItems(
              message.storage_refs ?? [],
              message.message_id,
              conversationId,
            )
          : [],
      );
    }
    return messages.flatMap((message) =>
      refsToMediaItems(
        message.storage_refs ?? [],
        message.message_id,
        conversationId,
      ),
    );
  }, [conversationId, groupMessages, isGroup, messages]);

  const openMedia = (item: MediaItem) => {
    const index = conversationMediaItems.findIndex((candidate) =>
      mediaItemKey(candidate) === mediaItemKey(item)
    );
    if (index >= 0) {
      setLightboxIndex(index);
    }
  };

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

  const refreshCurrentGroupSnapshot = async () => {
    if (!activeConversation?.group_id) return;
    const fresh = await getGroupSnapshot(activeConversation.group_id);
    setGroupSnapshot(fresh);
  };

  useEffect(() => {
    if (!isGroup || !activeConversation?.group_id) return;
    void refreshCurrentGroupSnapshot().catch((err) => {
      console.debug(`[ChatView] group snapshot refresh failed: ${String(err)}`);
    });
  }, [isGroup, activeConversation?.group_id]);

  const handleUpgradeRuntime = async () => {
    if (!activeConversation?.group_id) return;
    setTransportBusy(true);
    setTransportError(null);
    try {
      const preflight = await cloudflarePreflight();
      if (!preflight.ready) {
        const login = await cloudflareLogin();
        if (!login.success) {
          setTransportError(login.error || "Cloudflare login failed.");
          return;
        }
      }
      const result = await cloudflareDeploy();
      if (!result.success) {
        setTransportError(result.error || "Cloudflare runtime upgrade failed.");
        return;
      }
      setRuntimeStatus(await cloudflareStatus());
      await syncGroupOutbox(activeConversation.group_id, "runtime_upgraded");
      markGroupSynced(activeConversation.group_id);
      await refreshCurrentGroupSnapshot();
    } catch (err) {
      markGroupSyncFailed(activeConversation.group_id, String(err));
      setTransportError(err instanceof Error ? err.message : String(err));
    } finally {
      setTransportBusy(false);
    }
  };

  const handleSyncGroupTransport = async () => {
    if (!activeConversation?.group_id) return;
    setTransportBusy(true);
    setTransportError(null);
    try {
      await syncGroupOutbox(activeConversation.group_id, "manual_retry");
      markGroupSynced(activeConversation.group_id);
      await refreshCurrentGroupSnapshot();
      setRuntimeStatus(await cloudflareStatus());
    } catch (err) {
      markGroupSyncFailed(activeConversation.group_id, String(err));
      setTransportError(err instanceof Error ? err.message : String(err));
    } finally {
      setTransportBusy(false);
    }
  };

  const syncCurrentGroup = async (reason: string, showBusy = false) => {
    const groupId = activeConversation?.group_id;
    if (!groupId) return;
    if (showBusy) {
      setManualSyncBusy(true);
      setTransportError(null);
    }
    try {
      await syncGroupOutbox(groupId, reason);
      markGroupSynced(groupId);
      await refreshCurrentGroupSnapshot();
      await refreshMessages();
    } catch (err) {
      markGroupSyncFailed(groupId, String(err));
      if (showBusy) {
        setTransportError(err instanceof Error ? err.message : String(err));
      }
    } finally {
      if (showBusy) setManualSyncBusy(false);
    }
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

  // Track which group (if any) the chat view is displaying so the
  // useGroupsStore has a stable pointer for derived selectors.
  useEffect(() => {
    if (isGroup && activeConversation?.group_id) {
      setActiveGroupId(activeConversation.group_id);
      markGroupOpened(activeConversation.group_id);
      void syncCurrentGroup("view_opened").catch((err) => {
        console.debug(`[ChatView] group view sync failed: ${String(err)}`);
      });
      return () => setActiveGroupId(null);
    }
    return;
  }, [isGroup, activeConversation?.group_id, markGroupOpened, setActiveGroupId]);

  useEffect(() => {
    if (!conversationId) return;
    const unlisten = listen<CoreUpdateEvent>("core-update", (event) => {
      if (event.payload.state_update.messages_changed) {
        refreshMessages();
      }
    });
    return () => { unlisten.then((fn) => fn()); };
  }, [conversationId, isGroup]);

  useEffect(() => {
    if (conversationId) {
      loadMessages();
    }
  }, [conversationId, isGroup]);

  const loadMessages = async () => {
    if (!conversationId) return;
    setLoading(true);
    try {
      if (isGroup) {
        const result = await getGroupMessages(conversationId);
        setGroupMessages(result);
        setMessages([]);
      } else {
        const result = await invoke<Message[]>("get_messages", { conversationId });
        setMessages(result);
        setGroupMessages([]);
      }
    } catch (err) {
      console.error(`[ChatView] Failed to load messages: ${String(err)}`);
      setMessages([]);
      setGroupMessages([]);
    } finally {
      setLoading(false);
    }
  };

  const refreshMessages = async () => {
    if (!conversationId) return;
    try {
      if (isGroup) {
        const result = await getGroupMessages(conversationId);
        setGroupMessages(result);
      } else {
        const result = await invoke<Message[]>("get_messages", { conversationId });
        setMessages(result);
      }
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
    if (loading) return null;
    if (isGroup) return buildGroupMessageList();
    if (messages.length === 0) return null;

    const now = new Date();
    const result: React.ReactNode[] = [];
    let lastDateKey: string | null = null;

    messages.forEach((msg) => {
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

      if (msg.message_type === "system") {
        result.push(
          <div
            key={msg.message_id}
            className="date-separator"
            data-raw-type={msg.raw_message_type}
          >
            <span>{msg.plaintext ?? "Conversation updated"}</span>
          </div>,
        );
        return;
      }

      result.push(
        <div
          key={msg.message_id}
          className={`flex ${isMyMessage(msg) ? "justify-end" : "justify-start"}`}
        >
          {renderMessageBubble(msg)}
        </div>,
      );
    });

    return result;
  };

  /**
   * Render a group chat message stream. Unlike direct conversations,
   * groups interleave application bubbles and locked system banners
   * (per R3.3 / R3.5 / R3.6). System banners use the
   * `date-separator` visual style so they read as in-line notices.
   */
  const buildGroupMessageList = () => {
    if (groupMessages.length === 0) return null;
    return groupMessages.map((message) => {
      if (message.kind === "system_banner") {
        return (
          <div
            key={message.message_id}
            className="date-separator"
            data-raw-type={message.raw_message_type}
          >
            <span>{message.text}</span>
          </div>
        );
      }
      const sent =
        message.sender_user_id === localUserId ||
        message.sender_device_id === (deviceId ?? "");
      return (
        <div
          key={message.message_id}
          className={`flex ${sent ? "justify-end" : "justify-start"}`}
        >
          {renderGroupBubble(message, sent)}
        </div>
      );
    });
  };

  const renderGroupBubble = (
    message: Extract<GroupMessageView, { kind: "bubble" }>,
    sent: boolean,
  ) => {
    const bubbleCls = `bubble ${sent ? "bubble-sent" : "bubble-received"}`;
    const refs = message.storage_refs ?? [];
    const hasAttachment = message.has_attachment || refs.length > 0;
    const senderName = resolveGroupName({
      userId: message.sender_user_id,
      deviceId: message.sender_device_id,
    });
    if (!hasAttachment) {
      return (
        <div className={bubbleCls}>
          {!sent && (
            <span className="block text-xs text-muted-color mb-1 truncate">
              {senderName}
            </span>
          )}
          <span className="block whitespace-pre-wrap break-words overflow-hidden">
            {message.plaintext || "Message unavailable"}
          </span>
          <span className="block text-xs text-right mt-1 opacity-60">
            {formatTime(message.created_at)}
          </span>
        </div>
      );
    }
    const validRefs = refs.filter((r) => r.ref);
    const attachmentRefs = validRefs.length > 0 ? validRefs : refs;
    return (
      <div className={bubbleCls}>
        {!sent && (
          <span className="block text-xs text-muted-color mb-1 truncate">
            {senderName}
          </span>
        )}
        {renderAttachmentStack(message.message_id, attachmentRefs)}
        <span className="block text-xs text-right mt-1 opacity-60">
          {formatTime(message.created_at)}
        </span>
      </div>
    );
  };

  const renderMessageBubble = (msg: Message) => {
    const isSent = isMyMessage(msg);
    const bubbleCls = `bubble ${isSent ? "bubble-sent" : "bubble-received"}`;
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
            {msg.plaintext || "Message unavailable"}
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
        {renderAttachmentStack(msg.message_id, attachmentRefs)}
        <span className="block text-xs text-right mt-1 opacity-60">
          {formatTime(msg.created_at)}
        </span>
      </div>
    );
  };

  const renderAttachmentStack = (messageId: string, refs: StorageRef[]) => {
    const mediaItems = refsToMediaItems(refs, messageId, conversationId!);
    const imageItems = mediaItems.filter((item) => item.type === "image");
    const playableItems = mediaItems.filter((item) => item.type === "video" || item.type === "audio");
    const fileRefs = refs.filter((ref) => !isMediaMime(ref.mime_type));

    return (
      <div className="flex flex-col gap-2">
        {imageItems.length > 0 && (
          <ImageGrid
            items={imageItems}
            onImageClick={(index) => openMedia(imageItems[index])}
          />
        )}
        {playableItems.map((item) => (
          <button
            key={mediaItemKey(item)}
            className="flex items-center gap-3 rounded-md border border-subtle bg-surface/40 px-3 py-2 text-left transition-colors hover:border-default hover:bg-surface"
            onClick={() => openMedia(item)}
          >
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-surface-elevated text-muted-color">
              {item.type === "video" ? <Clapperboard size={18} /> : <Music size={18} />}
            </span>
            <span className="min-w-0 flex-1">
              <span className="block truncate text-sm font-medium text-primary-color">
                {item.fileName || (item.type === "video" ? "Video" : "Audio")}
              </span>
              <span className="block text-xs text-muted-color">
                {item.type === "video" ? "Video preview" : "Audio preview"}
                {formatMediaSize(item.sizeBytes)}
              </span>
            </span>
          </button>
        ))}
        {fileRefs.map((ref, index) => (
          <AttachmentPreview
            key={`${messageId}-file-${index}`}
            messageId={messageId}
            conversationId={conversationId!}
            reference={ref.ref || ""}
            mimeType={ref.mime_type || "application/octet-stream"}
            fileName={ref.file_name}
            sizeBytes={ref.size_bytes}
            showInline={false}
          />
        ))}
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
      <div className="flex flex-1 items-center justify-center bg-base px-6">
        <div className="text-center">
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-surface-elevated">
            <MessageCircle size={24} className="shrink-0 leading-none text-muted-color" />
          </div>
          <h2 className="mb-2 text-lg font-medium text-secondary-color">Select a conversation</h2>
          <p className="text-muted-color text-sm">or create a new one to start messaging</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col bg-base">
      <header className="flex h-14 items-center gap-3 border-b border-subtle bg-base px-4">
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-surface-elevated text-muted-color">
          {isGroup ? (
            <Users size={18} />
          ) : (
            <span className="text-sm font-medium">
              {peerName[0]?.toUpperCase() || "?"}
            </span>
          )}
        </div>
        <div className="flex-1 min-w-0">
          <h2 className="text-primary-color font-medium truncate">{peerName}</h2>
          <span className="text-muted-color text-xs flex items-center gap-1">
            {isGroup ? (
              <>
                {dissolved ? (
                  <span className="text-red-500">Dissolved</span>
                ) : (
                  <>
                    <GroupSyncIndicator status={groupSyncStatus} compact />
                    {activeConversation?.member_count ?? 0} members · End-to-end encrypted
                  </>
                )}
                {!dissolved && activeConversation?.group_role && activeConversation.group_role !== "member" && (
                  <span className="ml-2 badge text-[10px] uppercase tracking-wide">
                    {activeConversation.group_role}
                  </span>
                )}
                {!dissolved && pendingJoinRequests > 0 && (
                  <span className="ml-2 badge bg-yellow-500/10 text-[10px] uppercase text-yellow-500">
                    {pendingJoinRequests} pending
                  </span>
                )}
              </>
            ) : (
              <>
                {directClosed ? (
                  <span className="text-muted-color">
                    {activeConversation?.state === "archived" ? "Archived" : "Closed"}
                  </span>
                ) : (
                  <>
                    <span className="w-1.5 h-1.5 rounded-full status-success animate-pulse" />
                    End-to-end encrypted
                  </>
                )}
              </>
            )}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {isGroup && (
            <button
              className="btn btn-ghost px-2 transition-fast"
              title="Sync group messages"
              onClick={() => void syncCurrentGroup("manual", true)}
              disabled={manualSyncBusy}
            >
              <RefreshCw size={18} className={manualSyncBusy ? "animate-spin" : ""} />
            </button>
          )}
          {isGroup && (
            <button
              className="btn btn-ghost px-2 transition-fast"
              title="Members"
              onClick={() => setMemberDrawerOpen(true)}
            >
              <Users size={18} />
            </button>
          )}
          {!isGroup && (
            <button className="btn btn-ghost px-2 transition-fast" title="Search messages">
              <Search size={18} />
            </button>
          )}
          <button className="btn btn-ghost px-2 transition-fast" title="More options">
            <EllipsisVertical size={18} />
          </button>
        </div>
      </header>

      <div
        ref={messagesContainerRef}
        onScroll={handleScroll}
        className="min-h-0 flex-1 overflow-y-auto overscroll-contain px-4 py-5"
      >
        <div className="mx-auto flex w-full max-w-4xl flex-col gap-2">
          {loading && (
            <div className="py-8 text-center">
              <div className="inline-block text-2xl text-muted-color">
                <Loader size={28} className="animate-spin" />
              </div>
              <p className="mt-2 text-muted-color">Loading messages...</p>
            </div>
          )}

          {!loading && !isGroup && messages.length === 0 && (
            <div className="py-8 text-center">
              <div className="text-muted-color">
                <p className="mb-2">Start the conversation</p>
                <p className="text-sm">Send a message below</p>
              </div>
            </div>
          )}
          {!loading && isGroup && groupMessages.length === 0 && (
            <div className="py-8 text-center">
              <div className="text-muted-color">
                <p className="mb-2">No messages in this group yet</p>
                <p className="text-sm">Send the first one below</p>
              </div>
            </div>
          )}

          {buildMessageListWithSeparators()}
          <div ref={messagesEndRef} />
        </div>
      </div>

      {composerDisabled ? (
        <div
          className="flex flex-wrap items-center gap-2 border-t border-subtle bg-base px-4 py-3 text-sm text-muted-color"
          title={composerTooltip}
        >
          <UserX size={16} />
          <span>{composerTooltip ?? "You cannot send messages to this conversation."}</span>
          {pendingGroupSetup && (
            <>
              {runtimeStatus?.needs_upgrade ? (
                <button
                  className="btn btn-primary text-xs"
                  onClick={handleUpgradeRuntime}
                  disabled={transportBusy}
                >
                  {transportBusy ? "Upgrading..." : "Upgrade Cloudflare runtime"}
                </button>
              ) : (
                <button
                  className="btn btn-secondary text-xs"
                  onClick={handleSyncGroupTransport}
                  disabled={transportBusy}
                >
                  {transportBusy ? "Retrying..." : "Retry group transport"}
                </button>
              )}
              {transportError && (
                <span className="basis-full text-error break-words">{transportError}</span>
              )}
            </>
          )}
        </div>
      ) : (
        <MessageInput
          conversationId={conversationId}
          conversationKind={isGroup ? "group" : "direct"}
          onSent={handleSentMessage}
        />
      )}

      {isGroup && activeConversation?.group_id && (
        <GroupMemberDrawer
          open={memberDrawerOpen}
          groupId={activeConversation.group_id}
          localUserId={localUserId}
          onClose={() => setMemberDrawerOpen(false)}
        />
      )}
      {lightboxIndex !== null && conversationMediaItems[lightboxIndex] && (
        <MediaLightbox
          items={conversationMediaItems}
          initialIndex={lightboxIndex}
          onClose={() => setLightboxIndex(null)}
        />
      )}
    </div>
  );
}

function mediaTypeFromMime(mimeType: string): MediaItem["type"] {
  if (mimeType.startsWith("image/")) return "image";
  if (mimeType.startsWith("video/")) return "video";
  if (mimeType.startsWith("audio/")) return "audio";
  return "other";
}

function isMediaMime(mimeType: string | undefined): boolean {
  const type = mediaTypeFromMime(mimeType || "application/octet-stream");
  return type === "image" || type === "video" || type === "audio";
}

function refsToMediaItems(
  refs: StorageRef[],
  messageId: string,
  conversationId: string,
): MediaItem[] {
  return refs
    .filter((ref) => ref.ref && isMediaMime(ref.mime_type))
    .map((ref) => ({
      type: mediaTypeFromMime(ref.mime_type || "application/octet-stream"),
      messageId,
      conversationId,
      reference: ref.ref,
      mimeType: ref.mime_type || "application/octet-stream",
      fileName: ref.file_name,
      sizeBytes: ref.size_bytes,
      metadataReady: true,
    }));
}

function mediaItemKey(item: MediaItem): string {
  return `${item.messageId}:${item.reference}:${item.mimeType}`;
}

function formatMediaSize(sizeBytes?: number): string {
  if (!sizeBytes) return "";
  if (sizeBytes < 1024) return ` · ${sizeBytes} B`;
  if (sizeBytes < 1024 * 1024) return ` · ${(sizeBytes / 1024).toFixed(1)} KB`;
  return ` · ${(sizeBytes / (1024 * 1024)).toFixed(1)} MB`;
}

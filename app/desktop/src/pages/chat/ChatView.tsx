import { useState, useEffect, useMemo, useRef, useCallback } from "react";
import { useNavigate, useParams } from "react-router";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  AlertTriangle,
  Clapperboard,
  Loader,
  MessageCircle,
  Music,
  UserX,
  Users,
} from "lucide-react";

import MessageInput from "@/components/MessageInput";
import AttachmentPreview from "@/components/AttachmentPreview";
import ImageGrid from "@/components/ImageGrid";
import MediaLightbox, { type MediaItem } from "@/components/MediaLightbox";
import GroupMemberDrawer from "@/components/group/GroupMemberDrawer";
import GroupSyncIndicator from "@/components/group/GroupSyncIndicator";
import ChatHeaderActions from "@/components/chat/ChatHeaderActions";
import ChatSearchBar from "@/components/chat/ChatSearchBar";
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
  listContacts,
  listConversations,
  refreshContact,
  syncGroupOutbox,
  type GroupMessageView,
} from "@/lib/tauri";
import type { Message, MessagePage, CoreUpdateEvent, CloudflareStatus, StorageRef } from "@/lib/types";
import { buildGroupNameResolver } from "@/lib/groupDisplayNames";
import { findMessageMatches, moveSearchIndex } from "@/lib/messageSearch";
import { mergeMessagePage, reconcileLatestMessagePage } from "@/lib/messageMerge";

interface SendMessageResult {
  message_id: string;
  conversation_id: string;
  sender_user_id?: string;
  sender_device_id: string;
  plaintext: string;
  created_at: number;
  delivery_state?: "sending" | "sent" | "failed";
}

export default function ChatView() {
  const { id: conversationId } = useParams();
  const navigate = useNavigate();
  const [messages, setMessages] = useState<Message[]>([]);
  const [nextMessageCursor, setNextMessageCursor] = useState<string | null>(null);
  const [loadingOlderMessages, setLoadingOlderMessages] = useState(false);
  const [groupMessages, setGroupMessages] = useState<GroupMessageView[]>([]);
  const [loading, setLoading] = useState(false);
  const [memberDrawerOpen, setMemberDrawerOpen] = useState(false);
  const [runtimeStatus, setRuntimeStatus] = useState<CloudflareStatus | null>(null);
  const [transportBusy, setTransportBusy] = useState(false);
  const [transportError, setTransportError] = useState<string | null>(null);
  const [manualSyncBusy, setManualSyncBusy] = useState(false);
  const [recoveryBusy, setRecoveryBusy] = useState(false);
  const [recoveryError, setRecoveryError] = useState<string | null>(null);
  const [lightboxIndex, setLightboxIndex] = useState<number | null>(null);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchIndex, setSearchIndex] = useState(-1);
  const [autoDownloadMedia, setAutoDownloadMedia] = useState(true);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const messagesContainerRef = useRef<HTMLDivElement>(null);
  const shouldAutoScrollRef = useRef(true);
  const messageRefs = useRef(new Map<string, HTMLDivElement>());

  const { contacts, setContacts } = useContactsStore();
  const { conversations, mergeConversationSnapshot, setActiveConversation } =
    useConversationsStore();
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
  const directPendingOutbound =
    !isGroup && activeDirectContact?.relationship_status === "pending_outbound";
  const conversationRecovery = activeConversation?.recovery ?? null;
  const conversationRecovering =
    Boolean(activeConversation) &&
    (activeConversation?.state === "needs_recovery" ||
      activeConversation?.state === "needs_rebuild" ||
      Boolean(conversationRecovery));
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

  const searchMatches = useMemo(
    () => (isGroup ? [] : findMessageMatches(messages, searchQuery)),
    [isGroup, messages, searchQuery],
  );
  const activeSearchMessageId =
    searchIndex >= 0 && searchIndex < searchMatches.length
      ? searchMatches[searchIndex]
      : null;

  const closeSearch = useCallback(() => {
    setSearchOpen(false);
    setSearchQuery("");
    setSearchIndex(-1);
  }, []);

  const navigateSearch = useCallback(
    (direction: 1 | -1) => {
      setSearchIndex((current) => moveSearchIndex(current, searchMatches.length, direction));
    },
    [searchMatches.length],
  );

  useEffect(() => {
    setSearchIndex(searchMatches.length > 0 ? 0 : -1);
  }, [searchMatches]);

  useEffect(() => {
    closeSearch();
    messageRefs.current.clear();
  }, [closeSearch, conversationId, isGroup]);

  useEffect(() => {
    let mounted = true;
    void invoke<{ auto_download_media: boolean }>("get_attachment_settings")
      .then((settings) => {
        if (mounted) setAutoDownloadMedia(settings.auto_download_media);
      })
      .catch(() => {
        // Keep the default when the private setting is temporarily unavailable.
      });
    return () => {
      mounted = false;
    };
  }, [conversationId]);

  useEffect(() => {
    if (isGroup) return;
    const handleSearchShortcut = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "f") {
        event.preventDefault();
        event.stopPropagation();
        setSearchOpen(true);
      } else if (event.key === "Escape" && searchOpen) {
        event.preventDefault();
        event.stopPropagation();
        closeSearch();
      }
    };
    window.addEventListener("keydown", handleSearchShortcut, true);
    return () => window.removeEventListener("keydown", handleSearchShortcut, true);
  }, [closeSearch, isGroup, searchOpen]);

  useEffect(() => {
    if (!activeSearchMessageId) return;
    const reducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
    messageRefs.current.get(activeSearchMessageId)?.scrollIntoView({
      behavior: reducedMotion ? "auto" : "smooth",
      block: "center",
    });
  }, [activeSearchMessageId]);

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
      ? groupSnapshot?.join_requests.filter(
          (request) => request.status === "pending_approval",
        )
          .length ?? 0
      : 0;
  const composerDisabled =
    directPendingOutbound ||
    conversationRecovering ||
    directClosed ||
    dissolved ||
    pendingGroupSetup ||
    (isGroup &&
      (groupSnapshot?.local_role == null ||
        localMember?.status === "removed" ||
        localMember?.status === "left"));
  const composerTooltip = directPendingOutbound
    ? "Waiting for contact to accept request."
    : conversationRecovering
      ? "Secure chat needs recovery before sending."
    : directClosed
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
          ? message.attachment_manifest
            ? [manifestToMediaItem(message.attachment_manifest, message.message_id, conversationId)]
            : refsToMediaItems(
                message.storage_refs ?? [],
                message.message_id,
                conversationId,
              )
          : [],
      );
    }
    return messages.flatMap((message) => message.attachment_manifest
      ? [manifestToMediaItem(message.attachment_manifest, message.message_id, conversationId, message.attachment_state, message.delivery_state)]
      : refsToMediaItems(message.storage_refs ?? [], message.message_id, conversationId));
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
    const reducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
    messagesEndRef.current?.scrollIntoView({
      behavior: behavior === "smooth" && !reducedMotion ? "smooth" : "auto",
      block: "end",
    });
  };

  const loadOlderMessages = async () => {
    if (!conversationId || isGroup || !nextMessageCursor || loadingOlderMessages) return;
    const container = messagesContainerRef.current;
    const previousHeight = container?.scrollHeight ?? 0;
    setLoadingOlderMessages(true);
    try {
      const page = await invoke<MessagePage>("get_messages", {
        conversationId,
        beforeCursor: nextMessageCursor,
        limit: 50,
      });
      setMessages((current) => mergeMessagePage(current, page.items));
      setNextMessageCursor(page.next_cursor ?? null);
      requestAnimationFrame(() => {
        if (container) container.scrollTop += container.scrollHeight - previousHeight;
      });
    } catch (error) {
      console.error(`[ChatView] Failed to load older messages: ${String(error)}`);
    } finally {
      setLoadingOlderMessages(false);
    }
  };

  const handleScroll = () => {
    if (!messagesContainerRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = messagesContainerRef.current;
    shouldAutoScrollRef.current = scrollHeight - scrollTop - clientHeight < 100;
    if (scrollTop < 80) void loadOlderMessages();
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

  const handleRecoverConversation = async () => {
    if (!conversationId) return;
    setRecoveryBusy(true);
    setRecoveryError(null);
    try {
      await invoke("recover_conversation", { conversationId });
      if (isGroup && activeConversation?.group_id) {
        await refreshCurrentGroupSnapshot();
      }
      const refreshedConversations = await listConversations();
      mergeConversationSnapshot(refreshedConversations, contacts, {
        markUnread: false,
        replace: true,
      });
      await refreshMessages();
    } catch (err) {
      setRecoveryError(err instanceof Error ? err.message : String(err));
    } finally {
      setRecoveryBusy(false);
    }
  };

  const syncCurrentGroup = async (reason: string, showBusy = false) => {
    const groupId = activeConversation?.group_id;
    if (!groupId) return false;
    if (showBusy) {
      setManualSyncBusy(true);
      setTransportError(null);
    }
    try {
      await syncGroupOutbox(groupId, reason);
      markGroupSynced(groupId);
      await refreshCurrentGroupSnapshot();
      await refreshMessages();
      return true;
    } catch (err) {
      markGroupSyncFailed(groupId, String(err));
      if (showBusy) {
        setTransportError(err instanceof Error ? err.message : String(err));
      }
      return false;
    } finally {
      if (showBusy) setManualSyncBusy(false);
    }
  };

  useEffect(() => {
    if (!searchOpen && !loading && messages.length > 0) {
      scrollToBottom(shouldAutoScrollRef.current ? "smooth" : "instant");
    }
  }, [messages, loading, searchOpen]);

  const handleRefreshDirectContact = async () => {
    const userId =
      activeConversation?.kind === "direct" ? activeConversation.peer_user_id : undefined;
    if (!userId) throw new Error("Contact is unavailable");
    await refreshContact(userId);
    const refreshedContacts = await listContacts();
    setContacts(
      refreshedContacts.map((contact) => ({
        user_id: contact.user_id,
        display_name: contact.display_name ?? null,
        device_count: contact.device_count,
        last_refresh: Date.now(),
        relationship_status: contact.relationship_status ?? "available",
      })),
    );
  };

  useEffect(() => {
    setActiveConversation(conversationId ?? null);
    setRecoveryError(null);
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
        const page = await invoke<MessagePage>("get_messages", { conversationId, limit: 50 });
        setMessages(page.items);
        setNextMessageCursor(page.next_cursor ?? null);
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
        const page = await invoke<MessagePage>("get_messages", { conversationId, limit: 50 });
        setMessages((current) => reconcileLatestMessagePage(current, page.items));
        setNextMessageCursor((current) => current ?? page.next_cursor ?? null);
      }
    } catch (err) {
      console.error(`[ChatView] Failed to refresh messages: ${String(err)}`);
    }
  };

  const handleSentMessage = (sentMsg?: SendMessageResult) => {
    if (!sentMsg || !conversationId) return;
    if (isGroup) {
      setGroupMessages((previous) => {
        if (previous.some((message) => message.message_id === sentMsg.message_id)) {
          return previous;
        }
        return [
          ...previous,
          {
            kind: "bubble",
            message_id: sentMsg.message_id,
            sender_user_id: sentMsg.sender_user_id ?? localUserId,
            sender_device_id: sentMsg.sender_device_id,
            created_at: sentMsg.created_at,
            plaintext: sentMsg.plaintext,
            has_attachment: false,
            storage_refs: [],
            raw_message_type: "mls_application",
            delivery_state: sentMsg.delivery_state ?? "sending",
          },
        ];
      });
      return;
    }
    const tempMessage: Message = {
      message_id: sentMsg.message_id,
      sender_device_id: sentMsg.sender_device_id,
      recipient_device_id: deviceId || "",
      message_type: "sent",
      created_at: sentMsg.created_at,
      plaintext: sentMsg.plaintext,
      has_attachment: false,
      storage_refs: [],
      delivery_state: sentMsg.delivery_state ?? "sending",
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
            ref={(element) => {
              if (element) messageRefs.current.set(msg.message_id, element);
              else messageRefs.current.delete(msg.message_id);
            }}
            className={`date-separator ${
              activeSearchMessageId === msg.message_id ? "search-result-active" : ""
            }`}
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
          ref={(element) => {
            if (element) messageRefs.current.set(msg.message_id, element);
            else messageRefs.current.delete(msg.message_id);
          }}
          className={`flex ${isMyMessage(msg) ? "justify-end" : "justify-start"} ${
            activeSearchMessageId === msg.message_id ? "search-result-active" : ""
          }`}
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
    const seenTransitions = new Set<string>();
    return groupMessages.flatMap((message) => {
      if (message.kind === "system_banner") {
        const eventKey = message.transition_id || message.message_id;
        if (seenTransitions.has(eventKey)) return [];
        seenTransitions.add(eventKey);
        return (
          <div
            key={message.message_id}
            className="date-separator"
            data-raw-type={message.raw_message_type}
          >
            <span>{formatGroupStateEvent(message, resolveGroupName)}</span>
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
    if (message.attachment_manifest) {
      const item = manifestToMediaItem(message.attachment_manifest, message.message_id, conversationId ?? "");
      return (
        <div className="max-w-[min(72vw,32rem)]">
          {!sent && <span className="mb-1 block truncate px-1 text-xs text-muted-color">{senderName}</span>}
          {item.type === "image" ? (
            <div className="relative overflow-hidden rounded-xl">
              <ImageGrid items={[item]} onImageClick={() => openMedia(item)} />
              <span className="pointer-events-none absolute bottom-1.5 right-1.5 rounded-full bg-black/55 px-2 py-0.5 text-[10px] text-white/85">
                {formatTime(message.created_at)}
              </span>
            </div>
          ) : item.type === "video" || item.type === "audio" ? (
            <button
              type="button"
              className="flex w-full items-center gap-3 rounded-xl border border-subtle bg-surface-elevated px-4 py-3 text-left transition-colors hover:border-default"
              onClick={() => openMedia(item)}
            >
              <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-surface text-muted-color">
                {item.type === "video" ? <Clapperboard size={20} /> : <Music size={20} />}
              </span>
              <span className="min-w-0 flex-1">
                <span className="block truncate text-sm font-medium">{item.fileName || (item.type === "video" ? "Video" : "Audio")}</span>
                <span className="block text-xs text-muted-color">{formatTime(message.created_at)}{formatMediaSize(item.sizeBytes)}</span>
              </span>
            </button>
          ) : (
            <div className="rounded-xl bg-surface-elevated p-2">
              <AttachmentPreview
                conversationId={item.conversationId}
                messageId={item.messageId}
                reference="original"
                mimeType={item.mimeType}
                fileName={item.fileName}
                sizeBytes={item.sizeBytes}
              />
              <span className="mt-1 block px-1 text-right text-xs opacity-60">{formatTime(message.created_at)}</span>
            </div>
          )}
        </div>
      );
    }
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
            {sent && message.delivery_state === "sending" ? " · Sending…" : ""}
            {sent && message.delivery_state === "failed" ? " · Failed" : ""}
          </span>
        </div>
      );
    }
    const validRefs = refs.filter((r) => r.ref);
    const attachmentRefs = validRefs.length > 0 ? validRefs : refs;
    return (
      <div className="max-w-[min(72vw,32rem)]">
        {!sent && (
          <span className="mb-1 block truncate px-1 text-xs text-muted-color">
            {senderName}
          </span>
        )}
        {renderAttachmentStack(message.message_id, attachmentRefs)}
        <span className="mt-1 block px-1 text-right text-xs opacity-60">
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

    if (msg.attachment_manifest) {
      const item = manifestToMediaItem(msg.attachment_manifest, msg.message_id, conversationId!, msg.attachment_state, msg.delivery_state);
      const status = msg.delivery_state === "sending"
        ? " · Sending…"
        : msg.delivery_state === "failed"
          ? " · Upload failed"
          : "";
      return <div className="max-w-[min(72vw,32rem)]">
        {item.type === "image" ? <div className="relative overflow-hidden rounded-xl">
          <ImageGrid items={[item]} onImageClick={() => openMedia(item)} />
          <span className="pointer-events-none absolute bottom-1.5 right-1.5 rounded-full bg-black/55 px-2 py-0.5 text-[10px] text-white/85">
            {formatTime(msg.created_at)}{status}
          </span>
        </div> : item.type === "video" || item.type === "audio" ? <button
          type="button"
          className="flex w-full items-center gap-3 rounded-xl border border-subtle bg-surface-elevated px-4 py-3 text-left transition-colors hover:border-default"
          onClick={() => openMedia(item)}
        >
          <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-surface text-muted-color">
            {item.type === "video" ? <Clapperboard size={20} /> : <Music size={20} />}
          </span>
          <span className="min-w-0 flex-1">
            <span className="block truncate text-sm font-medium">{item.fileName || (item.type === "video" ? "Video" : "Audio")}</span>
            <span className="block text-xs text-muted-color">{formatTime(msg.created_at)}{status}{formatMediaSize(item.sizeBytes)}</span>
          </span>
        </button> : <div className="rounded-xl bg-surface-elevated p-2">
          <AttachmentPreview messageId={msg.message_id} conversationId={conversationId!} reference="original" mimeType={item.mimeType} fileName={item.fileName} sizeBytes={item.sizeBytes} showInline={false} />
          <span className="mt-1 block px-1 text-right text-xs opacity-60">{formatTime(msg.created_at)}{status}</span>
        </div>}
      </div>;
    }

    if (!hasAttachment) {
      const attachmentMeta = tryParseAttachmentFromPlaintext(msg.plaintext);
      if (attachmentMeta) {
        return (
          <div className="max-w-[min(72vw,32rem)] rounded-xl bg-surface-elevated p-2">
            <AttachmentPreview
              messageId={msg.message_id}
              conversationId={conversationId!}
              reference=""
              mimeType={attachmentMeta.mimeType}
              fileName={attachmentMeta.fileName}
              showInline={false}
            />
            <span className="mt-1 block px-1 text-right text-xs opacity-60">
              {formatTime(msg.created_at)}
            </span>
          </div>
        );
      }
      return (
        <div className={bubbleCls}>
          <span className="block whitespace-pre-wrap break-words overflow-hidden">
            {msg.plaintext ?? ""}
          </span>
          <span className="block text-xs text-right mt-1 opacity-60">
            {formatTime(msg.created_at)}
            {isSent && msg.delivery_state === "sending" ? " · Sending…" : ""}
            {isSent && msg.delivery_state === "failed" ? " · Failed" : ""}
          </span>
        </div>
      );
    }

    const validRefs = refs.filter((r) => r.ref);
    const attachmentRefs = validRefs.length > 0 ? validRefs : refs;

    return (
      <div className="max-w-[min(72vw,32rem)]">
        {renderAttachmentStack(msg.message_id, attachmentRefs)}
        <span className="mt-1 block px-1 text-right text-xs opacity-60">
          {formatTime(msg.created_at)}
          {isSent && msg.delivery_state === "sending" ? " · Sending…" : ""}
          {isSent && msg.delivery_state === "failed" ? " · Failed" : ""}
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
            autoDownloadMedia={autoDownloadMedia}
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
                ) : conversationRecovering ? (
                  <span className="text-yellow-500">Needs recovery</span>
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
                {directPendingOutbound ? (
                  <span className="text-muted-color">Waiting for accept</span>
                ) : conversationRecovering ? (
                  <span className="text-yellow-500">Needs recovery</span>
                ) : directClosed ? (
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
        <ChatHeaderActions
          key={conversationId}
          isGroup={Boolean(isGroup)}
          searchOpen={searchOpen}
          syncBusy={manualSyncBusy}
          onToggleSearch={() => {
            if (searchOpen) closeSearch();
            else setSearchOpen(true);
          }}
          onOpenContactDetails={() => {
            const userId = activeConversation?.peer_user_id;
            if (userId) navigate(`/contacts/${encodeURIComponent(userId)}`);
          }}
          onRefreshContact={handleRefreshDirectContact}
          onOpenMembers={() => setMemberDrawerOpen(true)}
          onSyncGroup={() => syncCurrentGroup("manual", true)}
        />
      </header>

      {searchOpen && !isGroup && (
        <ChatSearchBar
          query={searchQuery}
          currentIndex={searchIndex}
          resultCount={searchMatches.length}
          onQueryChange={setSearchQuery}
          onPrevious={() => navigateSearch(-1)}
          onNext={() => navigateSearch(1)}
          onClose={closeSearch}
        />
      )}

      {conversationRecovery && (
        <div className="border-b border-subtle bg-surface px-4 py-3">
          <div className="mx-auto flex max-w-4xl flex-wrap items-center gap-3 text-sm">
            <AlertTriangle size={16} className="shrink-0 text-yellow-500" />
            <div className="min-w-0 flex-1">
              <div className="font-medium text-primary-color">Secure chat needs recovery</div>
              <div className="break-words text-muted-color">
                {formatRecoveryMessage(
                  conversationRecovery.restore_failure_reason,
                  conversationRecovery.restore_failure_detail,
                  conversationRecovery.last_error,
                )}
              </div>
            </div>
            <button
              className="btn btn-secondary text-xs"
              onClick={handleRecoverConversation}
              disabled={recoveryBusy || conversationRecovery.recoverable === false}
            >
              {recoveryBusy ? "Recovering..." : "Recover"}
            </button>
            {recoveryError && (
              <span className="basis-full text-error break-words">{recoveryError}</span>
            )}
          </div>
        </div>
      )}

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
          {conversationRecovering && !pendingGroupSetup && (
            <>
              <button
                className="btn btn-secondary text-xs"
                onClick={handleRecoverConversation}
                disabled={recoveryBusy || conversationRecovery?.recoverable === false}
              >
                {recoveryBusy ? "Recovering..." : "Recover"}
              </button>
              {recoveryError && (
                <span className="basis-full text-error break-words">{recoveryError}</span>
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

function formatGroupStateEvent(
  message: Extract<GroupMessageView, { kind: "system_banner" }>,
  resolveName: (input: { userId?: string | null; deviceId?: string | null }) => string,
): string {
  if (!message.event_kind) return message.text;
  const actor = message.actor_user_id
    ? resolveName({ userId: message.actor_user_id })
    : "A group administrator";
  const subjects = (message.subject_user_ids ?? [])
    .map((userId) => resolveName({ userId }))
    .join(", ");
  switch (message.event_kind) {
    case "member_joined":
      return `${subjects || "A member"} joined the group.`;
    case "member_left":
      return `${subjects || "A member"} left the group.`;
    case "member_removed":
      return `${actor} removed ${subjects || "a member"} from the group.`;
    case "role_changed":
      return `${actor} changed ${subjects || "a member"} from ${message.old_role ?? "their previous role"} to ${message.new_role ?? "a new role"}.`;
    case "ownership_transferred":
      return `${actor} transferred ownership to ${subjects || "another member"}.`;
    case "group_metadata_changed":
      return `${actor} updated the group details.`;
    case "group_dissolved":
      return `${actor} dissolved the group.`;
  }
}

function formatRecoveryMessage(reason?: string, detail?: string, lastError?: string): string {
  const normalizedReason = reason?.replace(/_/g, " ");
  if (normalizedReason && detail) {
    return `${normalizedReason}: ${detail}`;
  }
  return normalizedReason || lastError || "Secure state could not be restored for this conversation.";
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
      mimeType: ref.mime_type || "application/octet-stream",
      fileName: ref.file_name,
      sizeBytes: ref.size_bytes,
      metadataReady: true,
    }));
}

function manifestToMediaItem(
  manifest: import("@/lib/types").AttachmentManifestView,
  messageId: string,
  conversationId: string,
  attachmentState: "pending" | "published" = "published",
  uploadState: "sending" | "sent" | "failed" = "sent",
): MediaItem {
  return {
    type: manifest.kind === "file" ? "other" : manifest.kind,
    messageId,
    conversationId,
    mimeType: manifest.mime_type,
    fileName: manifest.file_name,
    sizeBytes: manifest.size_bytes,
    width: manifest.width,
    height: manifest.height,
    blurHash: manifest.blur_hash,
    previewAvailable: manifest.preview_available,
    attachmentState,
    uploadState,
  };
}

function mediaItemKey(item: MediaItem): string {
  return `${item.messageId}:${item.mimeType}`;
}

function formatMediaSize(sizeBytes?: number): string {
  if (!sizeBytes) return "";
  if (sizeBytes < 1024) return ` · ${sizeBytes} B`;
  if (sizeBytes < 1024 * 1024) return ` · ${(sizeBytes / 1024).toFixed(1)} KB`;
  return ` · ${(sizeBytes / (1024 * 1024)).toFixed(1)} MB`;
}

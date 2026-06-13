import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { invoke } from "@tauri-apps/api/core";

import { listGroupConversations } from "@/lib/tauri";
import { useContactsStore } from "@/store/contacts";
import { useConversationsStore } from "@/store/conversations";
import { useSessionStore } from "@/store/session";
import {
  filterMessageRequestsForSession,
  isMessageRequestForSession,
  useMessageRequestsStore,
} from "@/store/requests";

import type {
  ContactSummary,
  ConversationSummary,
  MessageRequestActionOutput,
  MessageRequestItem,
} from "@/lib/types";

export default function MessageRequests() {
  const navigate = useNavigate();
  const requests = useMessageRequestsStore((s) => s.requests);
  const removeRequest = useMessageRequestsStore((s) => s.removeRequest);
  const deviceId = useSessionStore((s) => s.deviceId);
  const userId = useSessionStore((s) => s.userId);
  const mergeConversationSnapshot = useConversationsStore(
    (s) => s.mergeConversationSnapshot,
  );
  const setContacts = useContactsStore((s) => s.setContacts);
  const [loading, setLoading] = useState(true);
  const [acting, setActing] = useState<string | null>(null);

  useEffect(() => {
    void loadFromBackend();
  }, []);

  const loadFromBackend = async () => {
    setLoading(true);
    try {
      const result = await invoke<{
        view_model?: { message_requests?: MessageRequestItem[] };
      }>("list_message_requests");
      if (result.view_model?.message_requests) {
        useMessageRequestsStore.getState().setRequests(
          filterMessageRequestsForSession(
            result.view_model.message_requests,
            useSessionStore.getState().deviceId,
            useSessionStore.getState().userId,
          ),
        );
      }
    } catch (err) {
      console.error(`[MessageRequests] Failed to load message requests: ${String(err)}`);
    } finally {
      setLoading(false);
    }
  };

  const formatTime = (timestamp: number) => {
    const diff = Date.now() - timestamp;
    const hours = Math.floor(diff / (1000 * 60 * 60));
    if (hours < 1) return "Just now";
    if (hours < 24) return `${hours}h ago`;
    return `${Math.floor(hours / 24)}d ago`;
  };

  const handleAction = async (
    request: MessageRequestItem,
    action: "accept" | "reject",
  ) => {
    const requestId = request.request_id;
    if (!isMessageRequestForSession(request, deviceId, userId)) {
      console.warn(
        `[MessageRequests] Dropping stale request requestId=${requestId} recipient=${request.recipient_device_id} sender=${request.sender_user_id}`,
      );
      removeRequest(requestId);
      void loadFromBackend();
      return;
    }
    setActing(requestId);
    try {
      const result = await invoke<MessageRequestActionOutput>("act_on_message_request", {
        requestId,
        action,
        senderBundleShareUrl: request.sender_bundle_share_url,
      });
      removeRequest(requestId);

      if (action === "accept" && result.accepted) {
        console.debug(
          `[MessageRequests] Accepted request requestId=${requestId} conversationAvailable=${Boolean(result.conversation_id)}`,
        );

        try {
          const contacts = await invoke<ContactSummary[]>("list_contacts");
          const contactsByUserId = new Map(
            contacts.map((contact) => [contact.user_id, contact.display_name ?? null]),
          );
          const conversations = await invoke<ConversationSummary[]>("list_conversations");
          mergeConversationSnapshot(
            conversations.map((conversation) => ({
              ...conversation,
              last_message_preview:
                conversation.last_message_preview?.trim() ||
                contactsByUserId.get(conversation.peer_user_id) ||
                conversation.peer_user_id,
            })),
            contacts.map((contact) => ({
              user_id: contact.user_id,
              display_name: contact.display_name ?? null,
              relationship_status: contact.relationship_status ?? "available",
            })),
            { markUnread: false, replace: true },
          );
          console.debug(`[MessageRequests] Refreshed conversations count=${conversations.length}`);

          setContacts(
            contacts.map((contact) => ({
              user_id: contact.user_id,
              display_name: contact.display_name ?? null,
              device_count: contact.device_count,
              last_refresh: null,
              relationship_status: contact.relationship_status ?? "available",
            })),
          );
          console.debug(`[MessageRequests] Refreshed contacts count=${contacts.length}`);

          if (request.request_kind === "group_invite" && request.group_id) {
            const groups = await listGroupConversations();
            const group = groups.find((summary) => summary.group_id === request.group_id);
            navigate(group ? `/chat/${group.conversation_id}` : "/");
          } else if (result.conversation_id) {
            navigate(`/chat/${result.conversation_id}`);
          } else {
            navigate("/");
          }
        } catch (err) {
          console.error(`[MessageRequests] Failed to refresh after accept: ${String(err)}`);
          navigate("/");
        }
      }
    } catch (err) {
      console.error(`[MessageRequests] Failed to ${action} request ${requestId}: ${String(err)}`);
      if (
        String(err).includes("message request not found") ||
        String(err).includes("not_found")
      ) {
        removeRequest(requestId);
      }
      void loadFromBackend();
    } finally {
      setActing(null);
    }
  };

  return (
    <div className="flex h-full min-h-0 overflow-hidden bg-base">
      <div className="flex-1 flex min-h-0 flex-col">
        <header className="flex h-14 items-center border-b border-subtle px-4">
          <h1 className="font-semibold text-primary-color">
            Message Requests ({requests.length})
          </h1>
        </header>

        <div className="flex-1 overflow-y-auto overscroll-contain p-4">
          {loading && <div className="text-center text-muted-color">Loading...</div>}

          {!loading && requests.length === 0 && (
            <div className="text-center text-muted-color">
              <p>No pending message requests</p>
            </div>
          )}

          {!loading &&
            requests.map((req) => (
              <div key={req.request_id} className="card mb-4">
                <div className="flex items-center gap-3 mb-2">
                  <div className="avatar">
                    <span>{req.sender_display_name?.[0] || "?"}</span>
                  </div>
                  <div>
                    <span className="text-primary-color">
                      {req.sender_display_name || "Unknown"}
                    </span>
                    <span className="text-muted-color text-xs block truncate">
                      {req.sender_user_id}
                    </span>
                  </div>
                </div>

                <div className="text-secondary-color text-sm mb-2">
                  {req.request_kind === "group_invite" ? (
                    <>
                      Group invite: {req.group_title || "Untitled group"} - First seen{" "}
                      {formatTime(req.first_seen_at)}
                    </>
                  ) : (
                    <>
                      {req.message_count} messages - First seen {formatTime(req.first_seen_at)}
                    </>
                  )}
                </div>

                <div className="flex gap-2">
                  <button
                    className="btn btn-primary"
                    onClick={() => handleAction(req, "accept")}
                    disabled={acting === req.request_id}
                  >
                    {acting === req.request_id ? "Accepting..." : "Accept"}
                  </button>
                  <button
                    className="btn btn-secondary"
                    onClick={() => handleAction(req, "reject")}
                    disabled={acting === req.request_id}
                  >
                    Reject
                  </button>
                </div>
              </div>
            ))}
        </div>
      </div>
    </div>
  );
}

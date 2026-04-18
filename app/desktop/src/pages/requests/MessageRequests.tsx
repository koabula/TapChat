import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { invoke } from "@tauri-apps/api/core";

import { useMessageRequestsStore } from "@/store/requests";
import { useConversationsStore } from "@/store/conversations";
import { useContactsStore } from "@/store/contacts";

import type { ContactSummary, ConversationSummary, MessageRequestActionOutput } from "@/lib/types";

export default function MessageRequests() {
  const navigate = useNavigate();
  const requests = useMessageRequestsStore((s) => s.requests);
  const removeRequest = useMessageRequestsStore((s) => s.removeRequest);
  const mergeConversationSnapshot = useConversationsStore(
    (s) => s.mergeConversationSnapshot,
  );
  const setContacts = useContactsStore((s) => s.setContacts);
  const [loading, setLoading] = useState(true);
  const [acting, setActing] = useState<string | null>(null);

  // Sync from backend on mount
  useEffect(() => {
    loadFromBackend();
  }, []);

  const loadFromBackend = async () => {
    setLoading(true);
    try {
      const result = await invoke<{ view_model?: { message_requests?: typeof requests } }>("list_message_requests");
      if (result.view_model?.message_requests) {
        useMessageRequestsStore.getState().setRequests(result.view_model.message_requests);
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

  const handleAction = async (requestId: string, action: "accept" | "reject") => {
    setActing(requestId);
    try {
      const result = await invoke<MessageRequestActionOutput>("act_on_message_request", { requestId, action });

      // Remove from local store immediately
      removeRequest(requestId);

      // If accepted and conversation was created, refresh conversations and contacts
      if (action === "accept" && result.accepted) {
        console.debug(
          `[MessageRequests] Accepted request requestId=${requestId} conversationAvailable=${Boolean(result.conversation_id)}`,
        );

        // Refresh conversations to show the newly created conversation
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
            })),
            { markUnread: false },
          );
          console.debug(`[MessageRequests] Refreshed conversations count=${conversations.length}`);

          // Refresh contacts
          setContacts(contacts.map(c => ({
            user_id: c.user_id,
            display_name: c.display_name ?? null,
            device_count: c.device_count,
            last_refresh: null,
          })));
          console.debug(`[MessageRequests] Refreshed contacts count=${contacts.length}`);

          // Navigate to the new conversation if one was created
          if (result.conversation_id) {
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
      // Reload from backend on error to restore state
      loadFromBackend();
    } finally {
      setActing(null);
    }
  };

  return (
    <div className="flex h-full min-h-0 overflow-hidden bg-base">
      <div className="flex-1 flex min-h-0 flex-col">
        {/* Header */}
        <header className="flex items-center p-3 border-b border-default">
          <button
            className="btn btn-ghost px-2"
            onClick={() => navigate("/")}
          >
            ←
          </button>
          <h1 className="font-semibold text-primary-color ml-2">
            Message Requests ({requests.length})
          </h1>
        </header>

        {/* Request list */}
        <div className="flex-1 overflow-y-auto overscroll-contain p-4">
          {loading && (
            <div className="text-center text-muted-color">Loading...</div>
          )}

          {!loading && requests.length === 0 && (
            <div className="text-center text-muted-color">
              <p>No pending message requests</p>
            </div>
          )}

          {!loading && requests.map((req) => (
            <div
              key={req.request_id}
              className="card mb-4"
            >
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
                {req.message_count} messages · First seen {formatTime(req.first_seen_at)}
              </div>

              <div className="flex gap-2">
                <button
                  className="btn btn-primary"
                  onClick={() => handleAction(req.request_id, "accept")}
                  disabled={acting === req.request_id}
                >
                  Accept
                </button>
                <button
                  className="btn btn-secondary"
                  onClick={() => handleAction(req.request_id, "reject")}
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

import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { invokeApp as invoke } from "@/lib/tauri";
import { normalizeAppError, presentError } from "@/lib/errors";

import { useContactsStore } from "@/store/contacts";
import { useConversationsStore } from "@/store/conversations";
import { useMessageRequestsStore } from "@/store/requests";

import type {
  ContactSummary,
  ConversationSummary,
  MessageRequestActionOutput,
  MessageRequestItem,
} from "@/lib/types";

interface WelcomePreview {
  conversation_id: string;
  author_user_id: string;
  author_device_id: string;
  identity_bundle_ref?: string;
}

interface RequestRow {
  request: MessageRequestItem;
  preview?: WelcomePreview;
}

function canAccept(preview?: WelcomePreview): boolean {
  return Boolean(preview?.identity_bundle_ref?.trim());
}

export default function MessageRequests() {
  const navigate = useNavigate();
  const requests = useMessageRequestsStore((s) => s.requests);
  const removeRequest = useMessageRequestsStore((s) => s.removeRequest);
  const mergeConversationSnapshot = useConversationsStore(
    (s) => s.mergeConversationSnapshot,
  );
  const setContacts = useContactsStore((s) => s.setContacts);
  const [rows, setRows] = useState<RequestRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [acting, setActing] = useState<string | null>(null);
  const [actionNotice, setActionNotice] = useState<{
    kind: "error" | "info";
    message: string;
  } | null>(null);

  useEffect(() => {
    void loadFromBackend();
  }, []);

  const previewRows = async (items: MessageRequestItem[]): Promise<RequestRow[]> => {
    return Promise.all(
      items.map(async (request) => {
        if (!request.welcome_bytes) {
          return { request };
        }
        try {
          const preview = await invoke<WelcomePreview>("preview_welcome", {
            welcomeBytes: request.welcome_bytes,
          });
          return { request, preview };
        } catch {
          return { request };
        }
      }),
    );
  };

  const loadFromBackend = async () => {
    setLoading(true);
    try {
      const result = await invoke<{
        view_model?: { message_requests?: MessageRequestItem[] };
      }>("list_message_requests");
      const items = result.view_model?.message_requests ?? [];
      useMessageRequestsStore.getState().setRequests(items);
      setRows(await previewRows(items));
    } catch (err) {
      console.error(`[MessageRequests] Failed to load message requests: ${presentError(err).message}`);
      setActionNotice({ kind: "error", message: presentError(err).message });
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
    preview?: WelcomePreview,
  ) => {
    const requestId = request.request_id;
    if (action === "accept" && !canAccept(preview)) {
      setActionNotice({
        kind: "error",
        message: "This request cannot be accepted: the Welcome has no identity bundle.",
      });
      return;
    }
    setActing(requestId);
    setActionNotice(null);
    try {
      const result = await invoke<MessageRequestActionOutput>("act_on_message_request", {
        requestId,
        action,
      });
      removeRequest(requestId);
      setRows((current) => current.filter((row) => row.request.request_id !== requestId));

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
              verified: Boolean(contact.verified),
              key_changed_unverified: Boolean(contact.key_changed_unverified),
            })),
          );
          console.debug(`[MessageRequests] Refreshed contacts count=${contacts.length}`);

          if (result.conversation_id) {
            navigate(`/chat/${result.conversation_id}`);
          } else {
            setActionNotice({
              kind: "info",
              message: "Request accepted. Secure chat setup is still syncing.",
            });
          }
        } catch (err) {
          console.error(`[MessageRequests] Failed to refresh after accept: ${presentError(err).message}`);
          setActionNotice({ kind: "error", message: presentError(err).message });
        }
      } else if (action === "reject") {
        setActionNotice({ kind: "info", message: "Message request rejected." });
      }
    } catch (err) {
      console.error(`[MessageRequests] Failed to ${action} request ${requestId}: ${presentError(err).message}`);
      setActionNotice({ kind: "error", message: presentError(err).message });
      if (normalizeAppError(err).code === "not_found") {
        removeRequest(requestId);
        setRows((current) => current.filter((row) => row.request.request_id !== requestId));
      }
      void loadFromBackend();
    } finally {
      setActing(null);
    }
  };

  const visibleRows: RequestRow[] =
    rows.length > 0
      ? rows
      : requests.map((request) => ({ request }));

  return (
    <div className="flex h-full min-h-0 overflow-hidden bg-base">
      <div className="flex-1 flex min-h-0 flex-col">
        <header className="flex h-14 items-center border-b border-subtle px-4">
          <h1 className="font-semibold text-primary-color">
            Message Requests ({visibleRows.length})
          </h1>
        </header>

        <div className="flex-1 overflow-y-auto overscroll-contain p-4">
          {actionNotice && (
            <div
              className={`mb-4 rounded border px-3 py-2 text-sm ${
                actionNotice.kind === "error"
                  ? "border-error text-error"
                  : "border-subtle text-secondary-color"
              }`}
            >
              {actionNotice.message}
            </div>
          )}

          {loading && <div className="text-center text-muted-color">Loading...</div>}

          {!loading && visibleRows.length === 0 && (
            <div className="text-center text-muted-color">
              <p>No pending message requests</p>
            </div>
          )}

          {!loading &&
            visibleRows.map(({ request, preview }) => {
              const author = preview?.author_user_id;
              const acceptEnabled = canAccept(preview);
              return (
                <div key={request.request_id} className="card mb-4">
                  <div className="flex items-center gap-3 mb-2">
                    <div className="avatar">
                      <span>{author?.[0] || "?"}</span>
                    </div>
                    <div>
                      <span className="text-primary-color">
                        {author ? `From ${author}` : "Unknown"}
                      </span>
                      {author && (
                        <span className="text-muted-color text-xs block truncate">
                          Cryptographically verified
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="text-secondary-color text-sm mb-2">
                    {request.message_count} messages - First seen{" "}
                    {formatTime(request.first_seen_at)}
                  </div>

                  <div className="flex gap-2">
                    <button
                      className="btn btn-primary"
                      onClick={() => handleAction(request, "accept", preview)}
                      disabled={acting === request.request_id || !acceptEnabled}
                    >
                      {acting === request.request_id ? "Accepting..." : "Accept"}
                    </button>
                    <button
                      className="btn btn-secondary"
                      onClick={() => handleAction(request, "reject", preview)}
                      disabled={acting === request.request_id}
                    >
                      Reject
                    </button>
                  </div>
                </div>
              );
            })}
        </div>
      </div>
    </div>
  );
}

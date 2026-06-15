import { useState, useEffect } from "react";
import { useNavigate } from "react-router";

import { useContactsStore } from "@/store/contacts";
import {
  listContacts,
  previewContactLink,
  startDirectChatFromLink,
} from "@/lib/tauri";
import type {
  ContactLinkPreview,
  ContactRelationshipStatus,
  ContactSummary,
} from "@/lib/types";

function relationshipLabel(status: ContactRelationshipStatus | undefined) {
  switch (status) {
    case "pending_outbound":
      return "Pending request";
    case "rejected":
      return "Rejected";
    case "removed_by_me":
      return "Closed";
    case "removed_by_peer":
      return "Closed by contact";
    default:
      return null;
  }
}

export default function ContactList() {
  const navigate = useNavigate();
  const { contacts: storeContacts, setContacts } = useContactsStore();
  const [shareLinkInput, setShareLinkInput] = useState("");
  const [previewing, setPreviewing] = useState(false);
  const [startingChat, setStartingChat] = useState(false);
  const [preview, setPreview] = useState<ContactLinkPreview | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Fetch contacts from backend on mount
  useEffect(() => {
    async function fetchContacts() {
      try {
        const contacts = await listContacts();
        console.debug(`[ContactList] Loaded contacts count=${contacts.length}`);
        const mappedContacts = contacts.map((c: ContactSummary) => ({
          user_id: c.user_id,
          display_name: c.display_name ?? null,
          device_count: c.device_count,
          last_refresh: null,
          relationship_status: c.relationship_status ?? "available",
        }));
        setContacts(mappedContacts);
      } catch (err) {
        console.error(`[ContactList] Failed to load contacts: ${String(err)}`);
      }
    }
    fetchContacts();
  }, [setContacts]);

  // Use contacts from store, show empty state if none
  const displayContacts = storeContacts;

  const handlePreviewByLink = async () => {
    if (!shareLinkInput.trim()) return;

    setPreviewing(true);
    setError(null);
    try {
      const nextPreview = await previewContactLink(shareLinkInput);
      setPreview(nextPreview);
    } catch (err) {
      console.error(`[ContactList] Failed to preview contact: ${String(err)}`);
      setError(String(err));
      setPreview(null);
    } finally {
      setPreviewing(false);
    }
  };

  const handleStartChat = async () => {
    const link = preview?.link || shareLinkInput.trim();
    if (!link) return;

    setStartingChat(true);
    setError(null);
    try {
      const result = await startDirectChatFromLink(link);
      setShareLinkInput("");
      setPreview(null);
      const contacts = await listContacts();
      const mappedContacts = contacts.map((c: ContactSummary) => ({
        user_id: c.user_id,
        display_name: c.display_name ?? null,
        device_count: c.device_count,
        last_refresh: null,
        relationship_status: c.relationship_status ?? "available",
      }));
      setContacts(mappedContacts);
      navigate(`/chat/${result.conversation_id}`);
    } catch (err) {
      console.error(`[ContactList] Failed to start direct chat: ${String(err)}`);
      setError(String(err));
    } finally {
      setStartingChat(false);
    }
  };

  return (
    <div className="flex h-full min-h-0 overflow-hidden bg-base">
      <div className="flex-1 flex min-h-0 flex-col">
        {/* Header */}
        <header className="flex h-14 items-center border-b border-subtle px-4">
          <h1 className="font-semibold text-primary-color">Contacts</h1>
        </header>

        {/* Add contact */}
        <div className="p-3 border-b border-default">
          <div className="flex items-center gap-2">
            <input
              className="input flex-1"
              placeholder="Paste a share link..."
              value={shareLinkInput}
              onChange={(e) => {
                setShareLinkInput(e.target.value);
                setPreview(null);
                setError(null);
              }}
              disabled={previewing || startingChat}
            />
            <button
              className="btn btn-primary px-3"
              onClick={handlePreviewByLink}
              disabled={previewing || startingChat || !shareLinkInput.trim()}
            >
              {previewing ? "Checking..." : "Add"}
            </button>
          </div>
          {preview && (
            <div className="mt-3 p-3 rounded border border-default bg-surface">
              <div className="flex items-center gap-3">
                <div className="avatar">
                  <span>{(preview.display_name || preview.user_id)[0]}</span>
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-primary-color truncate">
                    {preview.display_name || preview.user_id}
                  </div>
                  <div className="text-muted-color text-xs truncate">
                    {preview.user_id} · {preview.device_count} devices
                  </div>
                </div>
                <button
                  className="btn btn-primary px-3"
                  onClick={handleStartChat}
                  disabled={startingChat}
                >
                  {startingChat ? "Starting..." : "Chat"}
                </button>
              </div>
            </div>
          )}
          {error && <div className="text-error text-sm mt-2">{error}</div>}
        </div>

        {/* Contact list */}
        <div className="flex-1 overflow-y-auto overscroll-contain">
          {displayContacts.map((contact) => {
            const statusLabel = relationshipLabel(contact.relationship_status);
            return (
              <button
                key={contact.user_id}
                className="w-full flex items-center gap-3 p-3 hover:bg-surface-elevated border-b border-subtle"
                onClick={() => navigate(`/contacts/${contact.user_id}`)}
              >
                <div className="avatar">
                  <span className="text-lg">{(contact.display_name || contact.user_id)[0]}</span>
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-primary-color truncate">
                      {contact.display_name || contact.user_id}
                    </span>
                    {statusLabel && (
                      <span className="text-muted-color text-xs shrink-0">
                        {statusLabel}
                      </span>
                    )}
                  </div>
                  <span className="text-muted-color text-xs block truncate">
                    {contact.user_id} · {contact.device_count} devices
                  </span>
                </div>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}

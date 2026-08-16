import { useState, useEffect } from "react";
import { useNavigate, useParams } from "react-router";
import { invokeApp as invoke } from "@/lib/tauri";
import { presentError } from "@/lib/errors";

import type { ContactRelationshipStatus, ContactSummary } from "@/lib/types";

function relationshipCopy(status: ContactRelationshipStatus | undefined) {
  switch (status) {
    case "pending_outbound":
      return {
        label: "Pending request",
        detail: "This contact has not accepted your message request yet.",
        chatLabel: "Request pending",
      };
    case "rejected":
      return {
        label: "Rejected",
        detail: "This contact rejected the latest message request.",
        chatLabel: "Request rejected",
      };
    case "removed_by_me":
      return {
        label: "Closed",
        detail: "This legacy contact has been archived. Re-add by importing a share link.",
        chatLabel: "Archived",
      };
    case "removed_by_peer":
      return {
        label: "Closed by contact",
        detail: "This legacy contact has been archived. Re-add by importing a share link.",
        chatLabel: "Archived",
      };
    default:
      return null;
  }
}

export default function ContactDetail() {
  const navigate = useNavigate();
  const { id: userId } = useParams();
  const [refreshing, setRefreshing] = useState(false);
  const [contact, setContact] = useState<ContactSummary | null>(null);
  const [editingDisplayName, setEditingDisplayName] = useState(false);
  const [displayName, setDisplayName] = useState("");
  const [saving, setSaving] = useState(false);
  const relationshipInfo = relationshipCopy(contact?.relationship_status);
  const chatDisabled = Boolean(relationshipInfo);

  // Delete contact state
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    // Load contact info
    loadContact();
  }, [userId]);

  const loadContact = async () => {
    if (!userId) return;
    try {
      const contacts = await invoke<ContactSummary[]>("list_contacts");
      const found = contacts.find(c => c.user_id === userId);
      setContact(found || null);
      setDisplayName(found?.display_name || "");
    } catch (err) {
      console.error(`[ContactDetail] Failed to load contact: ${presentError(err).message}`);
    }
  };

  const handleRefresh = async () => {
    if (!userId) return;
    setRefreshing(true);
    try {
      await invoke("refresh_contact", { userId });
      loadContact();
    } catch (err) {
      console.error(`[ContactDetail] Failed to refresh contact: ${presentError(err).message}`);
    } finally {
      setRefreshing(false);
    }
  };

  const handleSaveDisplayName = async () => {
    if (!userId) return;
    setSaving(true);
    try {
      await invoke("set_contact_display_name", {
        userId,
        displayName: displayName.trim() || null,
      });
      setEditingDisplayName(false);
      loadContact();
    } catch (err) {
      console.error(`[ContactDetail] Failed to save display name: ${presentError(err).message}`);
      alert(presentError(err).message);
    } finally {
      setSaving(false);
    }
  };

  const handleStartChat = async () => {
    if (!userId) return;
    try {
      const result = await invoke<{ conversation_id: string }>("create_conversation", {
        peerUserId: userId,
      });
      navigate(`/chat/${result.conversation_id}`);
    } catch (err) {
      console.error(`[ContactDetail] Failed to create conversation: ${presentError(err).message}`);
      alert(presentError(err).message);
    }
  };

  const handleDeleteContact = async () => {
    setShowDeleteConfirm(true);
  };

  const confirmDeleteContact = async () => {
    if (!userId) return;
    setDeleting(true);
    try {
      await invoke("delete_contact", { userId });
      setShowDeleteConfirm(false);
      // Navigate back to contacts list
      navigate("/contacts");
    } catch (err) {
      console.error(`[ContactDetail] Failed to delete contact: ${presentError(err).message}`);
      alert(presentError(err).message);
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div className="flex h-full min-h-0 overflow-hidden bg-base">
      <div className="flex-1 flex min-h-0 flex-col">
        {/* Header */}
        <header className="flex items-center p-3 border-b border-default">
          <button
            className="btn btn-ghost px-2"
            onClick={() => navigate("/contacts")}
          >
            ←
          </button>
          <h1 className="font-semibold text-primary-color ml-2">
            Contact Details
          </h1>
          <button
            className="btn btn-ghost ml-auto"
            onClick={handleRefresh}
            disabled={refreshing}
          >
            {refreshing ? "Refreshing..." : "Refresh"}
          </button>
        </header>

        {/* Content */}
        <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain p-6">
          {/* Avatar */}
          <div className="flex items-center justify-center mb-4">
            <div className="w-20 h-20 rounded-full bg-surface-elevated flex items-center justify-center">
              <span className="text-3xl">
                {contact?.display_name?.[0] || userId?.[0] || "?"}
              </span>
            </div>
          </div>

          {/* Display Name (备注) */}
          <div className="text-center mb-4">
            {editingDisplayName ? (
              <div className="flex items-center gap-2 justify-center">
                <input
                  className="input text-center"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  placeholder="Enter display name"
                  maxLength={64}
                />
                <button
                  className="btn btn-primary"
                  onClick={handleSaveDisplayName}
                  disabled={saving}
                >
                  {saving ? "Saving..." : "Save"}
                </button>
                <button
                  className="btn btn-ghost"
                  onClick={() => {
                    setEditingDisplayName(false);
                    setDisplayName(contact?.display_name || "");
                  }}
                >
                  Cancel
                </button>
              </div>
            ) : (
              <div className="flex items-center justify-center gap-2">
                <h2 className="text-xl font-semibold text-primary-color">
                  {contact?.display_name || "No display name"}
                </h2>
                <button
                  className="btn btn-ghost text-sm"
                  onClick={() => setEditingDisplayName(true)}
                >
                  Edit
                </button>
              </div>
            )}
                      </div>

          {/* Info */}
          <div className="space-y-4">
            <div className="card">
              <label className="text-muted-color text-xs block mb-1">User ID</label>
              <span className="text-primary-color truncate">{userId}</span>
            </div>

            <div className="card">
              <label className="text-muted-color text-xs block mb-1">Devices</label>
              <span className="text-primary-color">{contact?.device_count || 1} device(s)</span>
            </div>

            {relationshipInfo && (
              <div className="card">
                <label className="text-muted-color text-xs block mb-1">Status</label>
                <span className="text-primary-color">{relationshipInfo.label}</span>
                <p className="text-muted-color text-sm mt-1">
                  {relationshipInfo.detail}
                </p>
              </div>
            )}
          </div>

          {/* Actions */}
          <div className="mt-6 space-y-2">
            <button
              className="btn btn-primary w-full"
              onClick={handleStartChat}
              disabled={chatDisabled}
            >
              {relationshipInfo?.chatLabel ?? "Chat"}
            </button>

            {/* Delete contact button */}
            <button
              className="btn btn-ghost w-full status-error"
              onClick={handleDeleteContact}
            >
              Close Chat
            </button>
          </div>

          {/* Delete confirmation dialog */}
          {showDeleteConfirm && (
            <div className="card mt-4 border-t border-default">
              <p className="status-error mb-3">
                Close this chat?
              </p>
              <p className="text-muted-color text-sm mb-3">
                This closes the chat and keeps message history. New messages are disabled until you add each other again.
              </p>
              <div className="flex items-center gap-2">
                <button
                  className="btn btn-ghost status-error"
                  onClick={confirmDeleteContact}
                  disabled={deleting}
                >
                  {deleting ? "Closing..." : "Close Chat"}
                </button>
                <button
                  className="btn btn-ghost"
                  onClick={() => setShowDeleteConfirm(false)}
                  disabled={deleting}
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

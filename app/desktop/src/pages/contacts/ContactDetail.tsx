import { useState, useEffect } from "react";
import { useNavigate, useParams } from "react-router";
import { invoke } from "@tauri-apps/api/core";

interface ContactSummary {
  user_id: string;
  display_name: string | null;
  device_count: number;
}

export default function ContactDetail() {
  const navigate = useNavigate();
  const { id: userId } = useParams();
  const [refreshing, setRefreshing] = useState(false);
  const [contact, setContact] = useState<ContactSummary | null>(null);
  const [editingDisplayName, setEditingDisplayName] = useState(false);
  const [displayName, setDisplayName] = useState("");
  const [saving, setSaving] = useState(false);

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
      console.error("Failed to load contact:", err);
    }
  };

  const handleRefresh = async () => {
    if (!userId) return;
    setRefreshing(true);
    try {
      await invoke("refresh_contact", { userId });
      loadContact();
    } catch (err) {
      console.error("Failed to refresh:", err);
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
      console.error("Failed to save display name:", err);
      alert(String(err));
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
      console.error("Failed to create conversation:", err);
      const errorMsg = String(err);
      if (errorMsg.includes("network") || errorMsg.includes("http") || errorMsg.includes("request")) {
        alert("Network error: Unable to connect to the peer's inbox. Both profiles need to have Cloudflare deployed to communicate.");
      } else {
        alert(errorMsg);
      }
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
      console.error("Failed to delete contact:", err);
      alert(String(err));
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div className="flex h-screen bg-base">
      <div className="flex-1 flex flex-col">
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
        <div className="p-6">
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
          </div>

          {/* Actions */}
          <div className="mt-6 space-y-2">
            <button
              className="btn btn-primary w-full"
              onClick={handleStartChat}
            >
              Chat
            </button>

            {/* Delete contact button */}
            <button
              className="btn btn-ghost w-full status-error"
              onClick={handleDeleteContact}
            >
              Delete Contact
            </button>
          </div>

          {/* Delete confirmation dialog */}
          {showDeleteConfirm && (
            <div className="card mt-4 border-t border-default">
              <p className="status-error mb-3">
                Delete this contact?
              </p>
              <p className="text-muted-color text-sm mb-3">
                This will also delete any conversations with this contact. This action cannot be undone.
              </p>
              <div className="flex items-center gap-2">
                <button
                  className="btn btn-ghost status-error"
                  onClick={confirmDeleteContact}
                  disabled={deleting}
                >
                  {deleting ? "Deleting..." : "Yes, Delete"}
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
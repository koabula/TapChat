import { useState, useEffect } from "react";
import { useNavigate } from "react-router";
import { invoke } from "@tauri-apps/api/core";

import { useContactsStore } from "@/store/contacts";

interface Contact {
  user_id: string;
  display_name: string | null;
  device_count: number;
}

export default function ContactList() {
  const navigate = useNavigate();
  const { contacts: storeContacts } = useContactsStore();
  const [shareLinkInput, setShareLinkInput] = useState("");
  const [adding, setAdding] = useState(false);

  // Fetch contacts from backend on mount
  useEffect(() => {
    async function fetchContacts() {
      try {
        const contacts = await invoke<Contact[]>("list_contacts");
        console.log("[ContactList] Loaded contacts:", contacts.length);
      } catch (err) {
        console.error("[ContactList] Failed to load contacts:", err);
      }
    }
    fetchContacts();
  }, []);

  // Use contacts from store, show empty state if none
  const displayContacts: Contact[] = storeContacts.length > 0 ? storeContacts : [];

  const handleAddByLink = async () => {
    if (!shareLinkInput.trim()) return;

    setAdding(true);
    try {
      await invoke("import_contact_by_link", { shareLink: shareLinkInput });
      setShareLinkInput("");
      // TODO: Refresh contact list
    } catch (err) {
      console.error("Failed to add contact:", err);
    } finally {
      setAdding(false);
    }
  };

  return (
    <div className="flex h-screen bg-base">
      <div className="flex-1 flex flex-col">
        {/* Header */}
        <header className="flex items-center p-3 border-b border-default">
          <button
            className="btn btn-ghost px-2"
            onClick={() => navigate("/")}
          >
            ←
          </button>
          <h1 className="font-semibold text-primary-color ml-2">Contacts</h1>
        </header>

        {/* Add contact */}
        <div className="p-3 border-b border-default">
          <div className="flex items-center gap-2">
            <input
              className="input flex-1"
              placeholder="Paste a share link to add..."
              value={shareLinkInput}
              onChange={(e) => setShareLinkInput(e.target.value)}
            />
            <button
              className="btn btn-primary px-3"
              onClick={handleAddByLink}
              disabled={adding || !shareLinkInput.trim()}
            >
              Add
            </button>
          </div>
        </div>

        {/* Contact list */}
        <div className="flex-1 overflow-y-auto">
          {displayContacts.map((contact) => (
            <button
              key={contact.user_id}
              className="w-full flex items-center gap-3 p-3 hover:bg-surface-elevated border-b border-subtle"
              onClick={() => navigate(`/contacts/${contact.user_id}`)}
            >
              <div className="avatar">
                <span className="text-lg">{(contact.display_name || contact.user_id)[0]}</span>
              </div>
              <div className="flex-1 min-w-0">
                <span className="text-primary-color truncate">
                  {contact.display_name || contact.user_id}
                </span>
                <span className="text-muted-color text-xs block truncate">
                  {contact.user_id} · {contact.device_count} devices
                </span>
              </div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
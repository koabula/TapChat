import type { ContactListItem } from "../../lib/types";

export default function ContactsPane({
  contacts,
  selectedContactUserId,
  onSelect,
}: {
  contacts: ContactListItem[];
  selectedContactUserId: string | null;
  onSelect: (contact: ContactListItem) => void;
}) {
  return (
    <div className="contacts-pane">
      <div className="contacts-section contacts-list-section">
        <div className="contacts-section-header">
          <strong>Contacts list</strong>
          <small>{contacts.length ? `${contacts.length} contacts` : "Add a contact to start chatting."}</small>
        </div>
        {!contacts.length && (
          <div className="pane-empty-state">
            <strong>No contacts yet</strong>
            <small>Ask a contact for their contact link or bundle file, then add them here to start chatting.</small>
          </div>
        )}
        {contacts.length > 0 && (
          <div className="contact-list">
            {contacts.map((contact) => (
              <button
                key={contact.user_id}
                className={selectedContactUserId === contact.user_id ? "contact-list-item active" : "contact-list-item"}
                onClick={() => onSelect(contact)}
              >
                <div className="contact-list-meta">
                  <strong>{contact.user_id}</strong>
                  <small>{contact.device_count} {contact.device_count === 1 ? "device" : "devices"}</small>
                </div>
                <span className="status-chip contact-badge">{contact.has_conversation ? "Chat ready" : "Contact only"}</span>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

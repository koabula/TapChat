import type { ContactListItem, ContactShareLinkView } from "../../lib/types";

export default function ContactsPane({
  contacts,
  selectedContactUserId,
  onSelect,
  onImportBundle,
  onImportLink,
  contactLinkDraft,
  setContactLinkDraft,
  contactShareLink,
  onCopyContactLink,
  onRotateContactLink,
  onShowQr,
  loading,
}: {
  contacts: ContactListItem[];
  selectedContactUserId: string | null;
  onSelect: (contact: ContactListItem) => void;
  onImportBundle: () => Promise<void>;
  onImportLink: () => Promise<void>;
  contactLinkDraft: string;
  setContactLinkDraft: (value: string) => void;
  contactShareLink: ContactShareLinkView | null;
  onCopyContactLink: () => Promise<void>;
  onRotateContactLink: () => Promise<void>;
  onShowQr: () => void;
  loading: boolean;
}) {
  return (
    <div className="contacts-pane">
      <div className="contacts-section">
        <div className="contact-onboarding-card">
          <div className="contact-onboarding-copy">
            <strong>Share my contact link</strong>
            <small>Send this link to a contact so they can add you and start a chat request.</small>
          </div>
          <div className="stacked-field">
            <input
              readOnly
              value={contactShareLink?.url ?? "Contact link will be available after transport setup."}
            />
            <div className="button-row contact-link-actions">
              <button
                className="ghost-button compact-button"
                disabled={loading || !contactShareLink?.url}
                onClick={() => void onCopyContactLink()}
              >
                Copy link
              </button>
              <button
                className="ghost-button compact-button"
                disabled={loading || !contactShareLink?.url}
                onClick={onShowQr}
              >
                Show QR
              </button>
              <button
                className="ghost-button compact-button"
                disabled={loading || !contactShareLink?.url}
                onClick={() => void onRotateContactLink()}
              >
                Rotate link
              </button>
            </div>
          </div>
        </div>

        <div className="contact-onboarding-card">
          <div className="contact-onboarding-copy">
            <strong>Add contact</strong>
            <small>Ask your contact for their contact link, then paste it here to add them.</small>
          </div>
          <div className="stacked-field">
            <input
              value={contactLinkDraft}
              placeholder="Paste contact link"
              onChange={(event) => setContactLinkDraft(event.target.value)}
            />
            <div className="button-row">
              <button className="primary-button compact-button" disabled={loading || !contactLinkDraft.trim()} onClick={() => void onImportLink()}>
                Add contact by link
              </button>
              <button className="ghost-button compact-button" disabled={loading} onClick={() => void onImportBundle()}>
                Import contact bundle file
              </button>
            </div>
          </div>
        </div>
      </div>

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

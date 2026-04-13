import { useState, useEffect } from "react";
import { useNavigate } from "react-router";
import { invoke } from "@tauri-apps/api/core";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";

export default function Complete() {
  const navigate = useNavigate();

  const [shareLink, setShareLink] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [contactLink, setContactLink] = useState("");
  const [addingContact, setAddingContact] = useState(false);

  // Fetch share link on mount
  useEffect(() => {
    invoke<string | null>("get_share_link")
      .then(setShareLink)
      .catch((err) => console.error("Failed to get share link:", err));
  }, []);

  const handleCopyShareLink = async () => {
    if (shareLink) {
      try {
        await writeText(shareLink);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      } catch (err) {
        console.error("Failed to copy:", err);
      }
    }
  };

  const handleAddContact = async () => {
    if (!contactLink.trim()) return;

    setAddingContact(true);
    try {
      await invoke("import_contact_by_link", { shareLink: contactLink });
      setContactLink("");
    } catch (err) {
      console.error("Failed to add contact:", err);
    } finally {
      setAddingContact(false);
    }
  };

  const handleStartChatting = () => {
    // This will close onboarding window and transition to main
    // The backend should update SessionState to Active
    navigate("/");
  };

  return (
    <div className="flex flex-col h-screen bg-base p-8">
      {/* Header */}
      <div className="flex items-center mb-8">
        <span className="ml-auto text-muted-color">Step 5 of 5</span>
      </div>

      {/* Content */}
      <div className="flex flex-col items-center justify-center flex-1">
        {/* Success icon */}
        <div className="w-16 h-16 rounded-full bg-frost.1 mb-6 flex items-center justify-center">
          <span className="text-2xl text-white">✓</span>
        </div>

        <h2 className="text-xl font-semibold text-primary-color mb-2">
          You're all set!
        </h2>

        {/* Share link */}
        <p className="text-secondary-color text-center mb-4 max-w-md">
          Share this link with friends so they can message you:
        </p>

        {shareLink && (
          <div className="flex items-center gap-2 card mb-6 max-w-sm w-full">
            <span className="text-primary-color truncate flex-1">{shareLink}</span>
            <button
              className="btn btn-ghost px-2"
              onClick={handleCopyShareLink}
            >
              {copied ? "Copied!" : "Copy"}
            </button>
          </div>
        )}

        {/* Add contact */}
        <p className="text-muted-color text-sm mb-2">
          Or add a contact by pasting their link:
        </p>

        <div className="flex items-center gap-2 mb-6 max-w-sm w-full">
          <input
            className="input flex-1"
            placeholder="Paste a share link..."
            value={contactLink}
            onChange={(e) => setContactLink(e.target.value)}
          />
          <button
            className="btn btn-primary px-3"
            onClick={handleAddContact}
            disabled={addingContact || !contactLink.trim()}
          >
            Add
          </button>
        </div>

        {/* Start button */}
        <button
          className="btn btn-primary w-full max-w-xs"
          onClick={handleStartChatting}
        >
          Start Chatting
        </button>
      </div>
    </div>
  );
}
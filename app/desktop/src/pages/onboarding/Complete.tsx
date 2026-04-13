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
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
    setError(null);
    try {
      await invoke("import_contact_by_link", { shareLink: contactLink });
      setContactLink("");
      // Optionally show success message
    } catch (err) {
      setError(String(err));
    } finally {
      setAddingContact(false);
    }
  };

  const handleStartChatting = async () => {
    setStarting(true);
    setError(null);
    try {
      // Call backend to transition from Onboarding to Active state
      // This will close the onboarding window and open the main window
      await invoke("complete_onboarding");
      // Navigate to main app (this may not actually render since window changes)
      navigate("/");
    } catch (err) {
      setError(String(err));
      setStarting(false);
    }
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
        <div className="w-16 h-16 rounded-full bg-frost.1 mb-6 flex items-center justify-center animate-scale-in">
          <span className="text-2xl text-white">✓</span>
        </div>

        <h2 className="text-xl font-semibold text-primary-color mb-2 animate-fade-in-up">
          You're all set!
        </h2>

        {/* Share link */}
        <p className="text-secondary-color text-center mb-4 max-w-md animate-fade-in-up" style={{ animationDelay: "100ms" }}>
          Share this link with friends so they can message you:
        </p>

        {shareLink && (
          <div className="flex items-center gap-2 card mb-6 max-w-sm w-full animate-fade-in-up" style={{ animationDelay: "200ms" }}>
            <span className="text-primary-color truncate flex-1">{shareLink}</span>
            <button
              className="btn btn-ghost px-2 transition-fast"
              onClick={handleCopyShareLink}
            >
              {copied ? "Copied!" : "📋"}
            </button>
          </div>
        )}

        {/* Add contact */}
        <p className="text-muted-color text-sm mb-2 animate-fade-in-up" style={{ animationDelay: "300ms" }}>
          Or add a contact by pasting their link:
        </p>

        <div className="flex items-center gap-2 mb-6 max-w-sm w-full animate-fade-in-up" style={{ animationDelay: "400ms" }}>
          <input
            className="input flex-1"
            placeholder="Paste a share link..."
            value={contactLink}
            onChange={(e) => setContactLink(e.target.value)}
            disabled={addingContact || starting}
          />
          <button
            className="btn btn-primary px-3 transition-fast"
            onClick={handleAddContact}
            disabled={addingContact || starting || !contactLink.trim()}
          >
            {addingContact ? "Adding..." : "Add"}
          </button>
        </div>

        {/* Error display */}
        {error && (
          <div className="text-error text-sm mb-4 animate-fade-in">{error}</div>
        )}

        {/* Start button */}
        <button
          className="btn btn-primary w-full max-w-xs transition-fast animate-fade-in-up"
          style={{ animationDelay: "500ms" }}
          onClick={handleStartChatting}
          disabled={starting}
        >
          {starting ? "Starting..." : "Start Chatting"}
        </button>
      </div>
    </div>
  );
}
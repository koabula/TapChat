import { useLayoutEffect, useRef, type Dispatch, type SetStateAction } from "react";
import { convertFileSrc } from "@tauri-apps/api/core";
import type { ContactDetailView, ConversationDetailView, DirectShellView } from "../../lib/types";
import AttachmentDraftQueue from "../shared/AttachmentDraftQueue";

export default function ConversationView({
  loading,
  step,
  activeConversation,
  selectedContact,
  shell,
  selectedAttachmentPaths,
  setSelectedAttachmentPaths,
  downloadingMessageId,
  dropActive,
  composerText,
  setComposerText,
  composerStatus,
  onCreateDirectConversation,
  onRefreshContact,
  onPreviewAttachment,
  onOpenAttachment,
  onDownloadAttachment,
  onChooseAttachmentFile,
  onSendAttachments,
  onSendMessage,
}: {
  loading: boolean;
  step: string;
  activeConversation: ConversationDetailView | null;
  selectedContact: ContactDetailView | null;
  shell: DirectShellView | null;
  selectedAttachmentPaths: string[];
  setSelectedAttachmentPaths: Dispatch<SetStateAction<string[]>>;
  downloadingMessageId: string | null;
  dropActive: boolean;
  composerText: string;
  setComposerText: Dispatch<SetStateAction<string>>;
  composerStatus: string;
  onCreateDirectConversation: () => Promise<void>;
  onRefreshContact: (userId: string) => Promise<void>;
  onPreviewAttachment: (messageId: string, reference: string) => Promise<void>;
  onOpenAttachment: (messageId: string) => Promise<void>;
  onDownloadAttachment: (messageId: string, reference: string) => Promise<void>;
  onChooseAttachmentFile: () => Promise<void>;
  onSendAttachments: () => Promise<void>;
  onSendMessage: () => Promise<void>;
}) {
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);
  const showAttachmentHint = selectedAttachmentPaths.length > 0;
  const showComposerStatus = Boolean(
    composerStatus &&
      composerStatus.trim() &&
      (showAttachmentHint ||
        !composerStatus.startsWith("Attachments are queued as separate messages.") ||
        composerStatus.toLowerCase().includes("request"))
  );

  useLayoutEffect(() => {
    const textarea = textareaRef.current;
    if (!textarea) {
      return;
    }
    textarea.style.height = "0px";
    const lineHeight = 24;
    const verticalPadding = 16;
    const maxHeight = lineHeight * 5 + verticalPadding;
    textarea.style.height = `${Math.min(textarea.scrollHeight, maxHeight)}px`;
    textarea.style.overflowY = textarea.scrollHeight > maxHeight ? "auto" : "hidden";
  }, [composerText]);

  if (step !== "complete") {
    return (
      <div className="conversation-stage conversation-scroll">
        <div className="empty-state conversation-empty-state">
          <h3>Transport setup is still in progress</h3>
          <p>Finish the remaining setup steps in the onboarding window. Chats will unlock automatically when transport is ready.</p>
        </div>
      </div>
    );
  }

  if (!activeConversation && selectedContact) {
    return (
      <div className="conversation-stage conversation-scroll">
        <div className="conversation-action-panel">
          <h3>{selectedContact.user_id}</h3>
          <p>Create a direct conversation to start chatting.</p>
          <div className="button-row">
            <button className="primary-button" disabled={loading} onClick={() => void onCreateDirectConversation()}>Create direct conversation</button>
            <button className="ghost-button" disabled={loading} onClick={() => void onRefreshContact(selectedContact.user_id)}>Refresh contact</button>
          </div>
        </div>
      </div>
    );
  }

  if (!activeConversation) {
    return (
      <div className="conversation-stage conversation-scroll">
        <div className="empty-state conversation-empty-state">
          <h3>No direct conversations yet</h3>
          <p>Import a contact link or bundle file from the Contacts tab, then start your first direct conversation.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="conversation-stage conversation-session">
      <div className={dropActive ? "message-list drop-active" : "message-list"}>
        {shell?.messages.length === 0 && (
          <div className="timeline-empty-state">
            <strong>No messages yet</strong>
            <small>Start the conversation with a message below.</small>
          </div>
        )}
        {shell?.messages.map((message) => (
          <div key={message.message_id} className={message.direction === "outgoing" ? "message-bubble outgoing" : "message-bubble incoming"}>
            <div className="message-meta"><span>{message.sender_user_id ?? "unknown"}</span><small>{message.created_at ?? ""}</small></div>
            <div>{message.plaintext ?? `[${message.message_type}]`}</div>
            {message.has_attachment && (
              <div className="attachment-card">
                {message.primary_attachment_previewable && message.primary_attachment_local_path && (
                  <button className="attachment-preview-button" disabled={loading || message.attachment_refs.length === 0} onClick={() => void onPreviewAttachment(message.message_id, message.attachment_refs[0].ref)}>
                    <img src={convertFileSrc(message.primary_attachment_local_path)} alt={message.primary_attachment_display_name ?? "attachment"} className="attachment-preview-image" />
                  </button>
                )}
                <div className="attachment-meta">
                  <strong>{message.primary_attachment_display_name ?? message.attachment_refs[0]?.mime_type ?? "attachment"}</strong>
                  <small>{message.attachment_refs[0]?.size_bytes ?? 0} bytes</small>
                </div>
                <div className="button-row">
                  <span className="composer-status">
                    {message.downloaded_attachment_available
                      ? message.primary_attachment_previewable
                        ? "Saved locally. Preview or open it."
                        : "Saved locally. Open or re-download it."
                      : message.attachment_refs[0]?.mime_type?.startsWith("image/")
                        ? "Download to preview."
                        : "Attachment available for download."}
                  </span>
                  {message.downloaded_attachment_available && <button className="ghost-button compact-button" disabled={loading} onClick={() => void onOpenAttachment(message.message_id)}>Open</button>}
                  <button className="ghost-button compact-button" disabled={loading || downloadingMessageId === message.message_id || message.attachment_refs.length === 0} onClick={() => void onDownloadAttachment(message.message_id, message.attachment_refs[0].ref)}>
                    {downloadingMessageId === message.message_id ? "Downloading..." : message.downloaded_attachment_available ? "Re-download" : "Download"}
                  </button>
                </div>
              </div>
            )}
          </div>
        ))}
        {dropActive && <div className="drop-overlay"><strong>Drop files to queue attachments</strong><small>Files will be sent as separate attachment messages.</small></div>}
      </div>
      <div className="composer">
        {selectedAttachmentPaths.length > 0 && (
          <AttachmentDraftQueue
            paths={selectedAttachmentPaths}
            onRemove={(path) => setSelectedAttachmentPaths((current) => current.filter((item) => item !== path))}
          />
        )}
        <div className="composer-row">
          <button className="composer-attach-button" aria-label="Attach files" title="Attach files" disabled={loading} onClick={() => void onChooseAttachmentFile()}>+</button>
          <textarea
            ref={textareaRef}
            rows={1}
            value={composerText}
            placeholder="Write a message"
            onChange={(event) => setComposerText(event.target.value)}
          />
          <button className="primary-button compact-button" disabled={loading || !composerText.trim()} onClick={() => void onSendMessage()}>Send</button>
        </div>
        {(showComposerStatus || selectedAttachmentPaths.length > 0) && (
          <div className="composer-footer">
            <div className="composer-status">{showComposerStatus ? composerStatus : ""}</div>
            {selectedAttachmentPaths.length > 0 && <button className="ghost-button compact-button" disabled={loading} onClick={() => void onSendAttachments()}>Send attachments</button>}
          </div>
        )}
      </div>
    </div>
  );
}

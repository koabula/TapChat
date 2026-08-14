import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  Clapperboard,
  File,
  FileText,
  Image,
  Loader2,
  Music,
  Paperclip,
  Send,
  X,
} from "lucide-react";
import {
  shouldSubmitComposerOnKeyDown,
} from "@/lib/messageComposer";

const MAX_TEXTAREA_ROWS = 5;
const TEXTAREA_LINE_HEIGHT_PX = 24;

interface MessageInputProps {
  conversationId: string;
  conversationKind?: "direct" | "group";
  onSent?: (msg?: SendMessageResult) => void;
}

interface SendMessageResult {
  message_id: string;
  conversation_id: string;
  sender_device_id: string;
  plaintext: string;
  created_at: number;
  delivery_state?: "sending" | "sent" | "failed";
}

interface AttachmentInfo {
  id: string;
  handle: string;
  name: string;
  size: number;
  mimeType: string;
  previewUrl: string | null;
}

interface StagedAttachmentResult {
  handle: string;
  name: string;
  size: number;
  mime_type: string;
  preview_url: string | null;
}

interface UploadProgressEvent {
  task_id: string;
  conversation_id: string;
  progress: number;
  status: string;
}

interface DragDropPayload {
  paths: string[];
}

function attachmentId(): string {
  return globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`;
}

function describeSendError(err: unknown): string {
  const errorMsg = String(err);
  const normalized = errorMsg.toLowerCase();
  if (normalized.includes("relationship_closed:")) {
    return "This chat is archived. Import a fresh share link to start a new chat.";
  }
  if (normalized.includes("temporary_failure:")) {
    return "Temporary delivery failure. Sync and try again.";
  }
  if (normalized.includes("invalid_input:")) {
    return errorMsg.replace(/^invalid_input:\s*/i, "");
  }
  if (
    normalized.includes("network") ||
    normalized.includes("transport") ||
    normalized.includes("timeout") ||
    normalized.includes("timed out") ||
    normalized.includes("connect") ||
    normalized.includes("connection") ||
    normalized.includes("fetch failed") ||
    normalized.includes("http")
  ) {
    return "Network error: Unable to deliver message. Check your connection and try again.";
  }
  return errorMsg;
}

function fileIcon(mimeType: string) {
  const className = "h-5 w-5";
  if (mimeType.startsWith("image/")) return <Image className={`${className} text-file-icon-image`} />;
  if (mimeType.startsWith("audio/")) return <Music className={`${className} text-file-icon-audio`} />;
  if (mimeType.startsWith("video/")) return <Clapperboard className={`${className} text-file-icon-video`} />;
  if (mimeType === "application/pdf") return <FileText className={`${className} text-file-icon-pdf`} />;
  return <File className={`${className} text-file-icon-text`} />;
}

export default function MessageInput({
  conversationId,
  conversationKind = "direct",
  onSent,
}: MessageInputProps) {
  const [inputText, setInputText] = useState("");
  const [sending, setSending] = useState(false);
  const [attachments, setAttachments] = useState<AttachmentInfo[]>([]);
  const [uploadingId, setUploadingId] = useState<string | null>(null);
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);
  const [uploadStatus, setUploadStatus] = useState<string | null>(null);
  const [uploadPosition, setUploadPosition] = useState<{ current: number; total: number } | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const onSentRef = useRef(onSent);
  const uploadActiveRef = useRef(false);
  const attachmentsRef = useRef<AttachmentInfo[]>([]);
  onSentRef.current = onSent;
  attachmentsRef.current = attachments;

  useEffect(() => () => {
    for (const attachment of attachmentsRef.current) {
      void invoke("release_staged_attachment", { handle: attachment.handle });
    }
  }, []);

  const handleFileFromPath = useCallback(async (filePath: string) => {
    try {
      const staged = await invoke<StagedAttachmentResult>("stage_attachment", { filePath });
      setAttachments((previous) => [
        ...previous,
        {
          id: attachmentId(),
          handle: staged.handle,
          name: staged.name,
          size: staged.size,
          mimeType: staged.mime_type,
          previewUrl: staged.preview_url,
        },
      ]);
    } catch (err) {
      console.error(`[MessageInput] Failed to stage attachment: ${String(err)}`);
      alert(`Unable to attach this file: ${String(err)}`);
    }
  }, []);

  const handleClipboardImage = useCallback(async () => {
    try {
      const staged = await invoke<StagedAttachmentResult>("stage_clipboard_image");
      setAttachments((previous) => [
        ...previous,
        {
          id: attachmentId(),
          handle: staged.handle,
          name: staged.name,
          size: staged.size,
          mimeType: staged.mime_type,
          previewUrl: staged.preview_url,
        },
      ]);
    } catch (err) {
      console.error(`[MessageInput] Failed to read clipboard image: ${String(err)}`);
      alert("Unable to attach this clipboard item. Try the attachment button instead.");
    }
  }, []);

  const removeAttachment = useCallback((attachment: AttachmentInfo) => {
    setAttachments((previous) => previous.filter((item) => item.id !== attachment.id));
    void invoke("release_staged_attachment", { handle: attachment.handle });
  }, []);

  useEffect(() => {
    const unlistenProgress = listen<UploadProgressEvent>("upload-progress", (event) => {
      if (event.payload.conversation_id !== conversationId || !uploadActiveRef.current) return;
      setUploadProgress(event.payload.progress);
      setUploadStatus(event.payload.status);
    });
    const unlistenDrop = listen<DragDropPayload>("tauri://drag-drop", (event) => {
      for (const path of event.payload.paths) void handleFileFromPath(path);
      setIsDragging(false);
    });
    const unlistenEnter = listen<void>("tauri://drag-enter", () => setIsDragging(true));
    const unlistenLeave = listen<void>("tauri://drag-leave", () => setIsDragging(false));

    return () => {
      void unlistenProgress.then((unlisten) => unlisten());
      void unlistenDrop.then((unlisten) => unlisten());
      void unlistenEnter.then((unlisten) => unlisten());
      void unlistenLeave.then((unlisten) => unlisten());
    };
  }, [conversationId, handleFileFromPath]);

  useEffect(() => {
    const textarea = textareaRef.current;
    if (!textarea) return;
    textarea.style.height = "auto";
    const maxHeight = MAX_TEXTAREA_ROWS * TEXTAREA_LINE_HEIGHT_PX;
    textarea.style.height = `${Math.min(textarea.scrollHeight, maxHeight)}px`;
    textarea.style.overflowY = textarea.scrollHeight > maxHeight ? "auto" : "hidden";
  }, [inputText]);

  const sendText = async (plaintext: string): Promise<void> => {
    const result = conversationKind === "group"
      ? await invoke<SendMessageResult & { sender_user_id: string; pending_group_outbox: number }>(
          "send_group_text_message",
          { conversationId, plaintext },
        )
      : await invoke<SendMessageResult>("send_text", { conversationId, plaintext });
    setInputText("");
    onSentRef.current?.(result);
  };

  const submitComposer = async () => {
    if (sending) return;
    const text = inputText;
    const pendingAttachments = [...attachments];
    if (!text.trim() && pendingAttachments.length === 0) return;

    setSending(true);
    try {
      // Text and attachments are separate durable messages in the current
      // protocol. Persist optional text once, then upload files in order.
      if (text.trim()) await sendText(text);

      for (const [index, attachment] of pendingAttachments.entries()) {
        setUploadingId(attachment.id);
        setUploadPosition({ current: index + 1, total: pendingAttachments.length });
        setUploadProgress(0);
        setUploadStatus("queued");
        uploadActiveRef.current = true;
        await invoke("send_attachment", {
          conversationId,
          attachmentHandle: attachment.handle,
        });
        uploadActiveRef.current = false;
        setAttachments((previous) => previous.filter((item) => item.id !== attachment.id));
        onSentRef.current?.();
      }
    } catch (err) {
      console.error(`[MessageInput] Failed to send composer contents: ${String(err)}`);
      alert(describeSendError(err));
    } finally {
      setSending(false);
      setUploadingId(null);
      setUploadProgress(null);
      setUploadStatus(null);
      setUploadPosition(null);
      uploadActiveRef.current = false;
    }
  };

  const handleAttachClick = async () => {
    try {
      const staged = await invoke<StagedAttachmentResult[]>("stage_attachments_from_dialog");
      setAttachments((previous) => [
        ...previous,
        ...staged.map((attachment) => ({
          id: attachmentId(),
          handle: attachment.handle,
          name: attachment.name,
          size: attachment.size,
          mimeType: attachment.mime_type,
          previewUrl: attachment.preview_url,
        })),
      ]);
    } catch (err) {
      console.error(`[MessageInput] File selection failed: ${String(err)}`);
    }
  };

  const handlePaste = (event: React.ClipboardEvent) => {
    const files = Array.from(event.clipboardData?.items ?? [])
      .filter((item) => item.kind === "file")
      .map((item) => item.getAsFile())
      .filter((file): file is File => file !== null);
    if (files.length === 0) return;
    event.preventDefault();
    void handleClipboardImage();
  };

  const hasAttachments = attachments.length > 0;
  const sendDisabled = sending || (!hasAttachments && !inputText.trim());
  const statusLabel = sending && uploadPosition
    ? uploadStatus === "retrying"
      ? `Upload will retry (${uploadPosition.current} of ${uploadPosition.total})`
      : `Queueing ${uploadPosition.current} of ${uploadPosition.total}`
    : hasAttachments
      ? `${attachments.length} file${attachments.length === 1 ? "" : "s"} ready`
      : null;

  return (
    <div
      className={`relative border-t border-subtle bg-base px-4 py-3 transition-colors ${
        isDragging ? "bg-primary/10" : ""
      }`}
      onDragOver={(event) => {
        event.preventDefault();
        event.stopPropagation();
        setIsDragging(true);
      }}
      onDragLeave={(event) => {
        const rect = event.currentTarget.getBoundingClientRect();
        if (
          event.clientX < rect.left ||
          event.clientX >= rect.right ||
          event.clientY < rect.top ||
          event.clientY >= rect.bottom
        ) setIsDragging(false);
      }}
      onDrop={(event) => {
        event.preventDefault();
        event.stopPropagation();
        setIsDragging(false);
      }}
    >
      {isDragging ? (
        <div className="absolute inset-0 z-10 flex items-center justify-center rounded-xl bg-primary/10 backdrop-blur-sm">
          <div className="flex items-center gap-2 font-medium text-primary-color">
            <Paperclip size={22} /> Drop files to attach
          </div>
        </div>
      ) : null}

      <div className="mx-auto w-full max-w-4xl rounded-2xl bg-surface shadow-sm ring-1 ring-inset ring-black/5 transition-shadow focus-within:ring-2 focus-within:ring-primary/40">
        {hasAttachments ? (
          <div className="flex gap-2 overflow-x-auto px-3 pt-3">
            {attachments.map((attachment) => {
              const isUploading = attachment.id === uploadingId;
              return (
                <div
                  key={attachment.id}
                  className="group relative h-20 w-20 shrink-0 overflow-hidden rounded-xl bg-surface-elevated"
                  title={attachment.name}
                >
                  {attachment.previewUrl ? (
                    <img
                      src={attachment.previewUrl}
                      alt={attachment.name}
                      className="h-full w-full object-cover"
                    />
                  ) : (
                    <div className="flex h-full flex-col items-center justify-center gap-1 px-1">
                      {fileIcon(attachment.mimeType)}
                      <span className="w-full truncate text-center text-[10px] text-muted-color">
                        {attachment.name}
                      </span>
                    </div>
                  )}
                  {isUploading && uploadProgress !== null ? (
                    <div className="absolute inset-0 flex items-center justify-center bg-black/45 text-xs font-medium text-white">
                      {uploadStatus === "retrying" ? "Retrying…" : `${uploadProgress}%`}
                    </div>
                  ) : null}
                  <button
                    type="button"
                    className="absolute right-1 top-1 flex h-5 w-5 items-center justify-center rounded-full bg-black/60 text-white opacity-90 transition-opacity hover:bg-error group-hover:opacity-100"
                    onClick={() => removeAttachment(attachment)}
                    disabled={sending}
                    title="Remove attachment"
                    aria-label={`Remove ${attachment.name}`}
                  >
                    <X size={11} />
                  </button>
                </div>
              );
            })}
          </div>
        ) : null}

        <div className="flex items-end gap-2 px-2 py-2">
          <button
            type="button"
            className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-xl text-secondary-color transition-colors hover:bg-surface-elevated hover:text-primary-color disabled:opacity-50"
            title="Attach file"
            aria-label="Attach file"
            onClick={() => void handleAttachClick()}
            disabled={sending}
          >
            <Paperclip size={20} />
          </button>
          <textarea
            ref={textareaRef}
            className="min-h-10 flex-1 resize-none border-0 bg-transparent px-1 py-2 text-sm text-primary-color outline-none ring-0 placeholder:text-muted-color focus-visible:ring-0 focus-visible:ring-offset-0 disabled:opacity-70"
            style={{
              lineHeight: `${TEXTAREA_LINE_HEIGHT_PX}px`,
              whiteSpace: "pre-wrap",
              wordBreak: "break-word",
              overflowWrap: "break-word",
            }}
            rows={1}
            placeholder={hasAttachments ? "Add a message (optional)…" : "Type a message…"}
            value={inputText}
            onChange={(event) => setInputText(event.target.value)}
            onKeyDown={(event) => {
              if (shouldSubmitComposerOnKeyDown({
                key: event.key,
                shiftKey: event.shiftKey,
                isComposing: event.nativeEvent.isComposing,
              })) {
                event.preventDefault();
                void submitComposer();
              }
            }}
            onPaste={handlePaste}
            disabled={sending}
          />
          <button
            type="button"
            className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-primary text-[var(--bubble-sent-text)] transition-colors hover:bg-primary-dark disabled:cursor-not-allowed disabled:opacity-50"
            onClick={() => void submitComposer()}
            disabled={sendDisabled}
            title={hasAttachments ? "Send attachments" : "Send message"}
            aria-label={hasAttachments ? "Send attachments" : "Send message"}
          >
            {sending ? <Loader2 size={19} className="animate-spin" /> : <Send size={19} />}
          </button>
        </div>

        {statusLabel ? (
          <div className="flex items-center justify-between px-4 pb-2 text-xs text-muted-color">
            <span>{statusLabel}</span>
            {uploadProgress !== null ? <span>{uploadProgress}%</span> : null}
          </div>
        ) : null}
      </div>
    </div>
  );
}

import { useState, useRef, useCallback, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { listen } from "@tauri-apps/api/event";
import {
  Paperclip,
  X,
  Image,
  Music,
  Clapperboard,
  FileText,
  File,
  Loader2,
  Send,
} from "lucide-react";

const MAX_TEXTAREA_ROWS = 5;
const TEXTAREA_LINE_HEIGHT_PX = 24;

interface MessageInputProps {
  conversationId: string;
  /**
   * Dispatch target for the text send. `"group"` routes to
   * `send_group_text_message` (which maps to
   * `CoreCommand::SendGroupTextMessage`); anything else (or absent)
   * uses the classic direct-conversation `send_text` path.
   */
  conversationKind?: "direct" | "group";
  onSent?: (msg?: { message_id: string; conversation_id: string; sender_device_id: string; plaintext: string; created_at: number }) => void;
}

interface AttachmentInfo {
  path: string;
  name: string;
  size: number;
  mimeType: string;
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
  const transportFailure =
    normalized.includes("network") ||
    normalized.includes("transport") ||
    normalized.includes("timeout") ||
    normalized.includes("timed out") ||
    normalized.includes("connect") ||
    normalized.includes("connection") ||
    normalized.includes("fetch failed") ||
    normalized.includes("http");
  if (transportFailure) {
    return "Network error: Unable to deliver message. Check if your peer has Cloudflare deployed and accessible.";
  }
  return errorMsg;
}

export default function MessageInput({ conversationId, conversationKind = "direct", onSent }: MessageInputProps) {
  const [inputText, setInputText] = useState("");
  const [sending, setSending] = useState(false);
  const [attachments, setAttachments] = useState<AttachmentInfo[]>([]);
  const [uploadingIndex, setUploadingIndex] = useState<number | null>(null);
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const uploadFallbackTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const startedSendingRef = useRef(false);

  // Stabilize onSent callback to avoid useEffect listener churn
  const onSentRef = useRef(onSent);
  onSentRef.current = onSent;

  // Interface for send_text result
  interface SendMessageResult {
    message_id: string;
    conversation_id: string;
    sender_device_id: string;
    plaintext: string;
    created_at: number;
  }

  // Extended onSent callback with message info for immediate display
  const onSentWithMessage = onSent as ((msg?: SendMessageResult) => void) | undefined;

  // Reset upload UI state
  const resetUploadState = useCallback(() => {
    setUploadProgress(null);
    setUploadingIndex(null);
    setSending(false);
    if (uploadFallbackTimeoutRef.current) {
      clearTimeout(uploadFallbackTimeoutRef.current);
      uploadFallbackTimeoutRef.current = null;
    }
  }, []);

  // Listen for upload progress events
  useEffect(() => {
    const unlisten = listen<UploadProgressEvent>("upload-progress", (event) => {
      const { conversation_id, progress, status } = event.payload;

      if (conversation_id === conversationId) {
        setUploadProgress(progress);

        if (status === "complete" || status === "failed") {
          if (uploadFallbackTimeoutRef.current) {
            clearTimeout(uploadFallbackTimeoutRef.current);
            uploadFallbackTimeoutRef.current = null;
          }
          setTimeout(() => {
            setUploadProgress(null);
            if (status === "complete") {
              // Remove the completed attachment from the list
              setAttachments(prev => prev.filter((_, i) => i !== uploadingIndex));
              setUploadingIndex(null);
              onSentRef.current?.();
              // If there are more attachments, continue sending
            }
            setSending(false);
          }, 500);
        }
      }
    });

    // Listen for Tauri drag-drop events (provides file paths)
    const unlistenDragDrop = listen<DragDropPayload>("tauri://drag-drop", (event) => {
      const paths = event.payload.paths;
      if (paths.length > 0) {
        for (const filePath of paths) {
          handleFileFromPath(filePath);
        }
      }
      setIsDragging(false);
    });

    const unlistenDragEnter = listen<void>("tauri://drag-enter", () => {
      setIsDragging(true);
    });

    const unlistenDragLeave = listen<void>("tauri://drag-leave", () => {
      setIsDragging(false);
    });

    return () => {
      unlisten.then((fn) => fn());
      unlistenDragDrop.then((fn) => fn());
      unlistenDragEnter.then((fn) => fn());
      unlistenDragLeave.then((fn) => fn());
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [conversationId, uploadingIndex]);

  // Effect to continue sending remaining attachments after one completes
  useEffect(() => {
    if (startedSendingRef.current && !sending && attachments.length > 0 && uploadingIndex === null) {
      // Previous upload completed, start the next one
      continueSendingAttachments();
    }
    if (attachments.length === 0) {
      startedSendingRef.current = false;
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sending, attachments.length, uploadingIndex]);

  // Auto-resize textarea based on content (up to MAX_TEXTAREA_ROWS)
  const adjustTextareaHeight = useCallback(() => {
    const ta = textareaRef.current;
    if (!ta) return;

    ta.style.height = "auto";
    const scrollHeight = ta.scrollHeight;
    const maxHeight = MAX_TEXTAREA_ROWS * TEXTAREA_LINE_HEIGHT_PX;

    if (scrollHeight > maxHeight) {
      ta.style.height = `${maxHeight}px`;
      ta.style.overflowY = "auto";
    } else {
      ta.style.height = `${scrollHeight}px`;
      ta.style.overflowY = "hidden";
    }
  }, []);

  useEffect(() => {
    adjustTextareaHeight();
  }, [inputText, adjustTextareaHeight]);

  // Handle file from path (from drag-drop, file picker, or paste)
  const handleFileFromPath = async (filePath: string) => {
    const name = filePath.split(/[/\\]/).pop() || "file";

    try {
      const metadata = await invoke<{ size: number; mime_type: string }>("get_file_metadata", {
        path: filePath,
      });

      setAttachments(prev => [...prev, {
        path: filePath,
        name,
        size: metadata.size,
        mimeType: metadata.mime_type,
      }]);
    } catch (err) {
      console.error(`[MessageInput] Failed to get file metadata: ${String(err)}`);
      const ext = name.split(".").pop()?.toLowerCase() || "";
      const mimeType = getMimeType(ext);
      setAttachments(prev => [...prev, {
        path: filePath,
        name,
        size: 0,
        mimeType,
      }]);
    }
  };

  const handleSendText = async () => {
    if (!inputText.trim()) return;

    const textToSend = inputText;
    setSending(true);
    try {
      // Route to the group-specific command when the parent signals a
      // group conversation. Both commands return the same shape
      // (message_id + sender_device_id + created_at + ...), so the UI
      // below can normalise them into the common onSent callback.
      const result =
        conversationKind === "group"
          ? await invoke<SendMessageResult & { sender_user_id: string; pending_group_outbox: number }>(
              "send_group_text_message",
              {
                conversationId,
                plaintext: textToSend,
              },
            )
          : await invoke<SendMessageResult>("send_text", {
              conversationId,
              plaintext: textToSend,
            });
      setInputText("");
      onSentWithMessage?.(result);
    } catch (err) {
      console.error(`[MessageInput] Failed to send message: ${String(err)}`);
      alert(describeSendError(err));
    } finally {
      setSending(false);
    }
  };

  // Send a single attachment at the given index
  const sendOneAttachment = async (info: AttachmentInfo, index: number) => {
    setUploadingIndex(index);
    setUploadProgress(0);

    uploadFallbackTimeoutRef.current = setTimeout(() => {
      console.warn("[MessageInput] Upload fallback timeout — resetting state");
      resetUploadState();
    }, 30000);

    try {
      await invoke("send_attachment", {
        conversationId,
        filePath: info.path,
        mimeType: info.mimeType,
        sizeBytes: info.size,
        fileName: info.name,
      });
      // Upload completed — the upload-progress event will handle cleanup
      // But set a defensive cleanup timer
      setTimeout(() => {
        if (uploadFallbackTimeoutRef.current) {
          clearTimeout(uploadFallbackTimeoutRef.current);
          uploadFallbackTimeoutRef.current = null;
          resetUploadState();
          setAttachments(prev => prev.filter((_, i) => i !== index));
          onSentRef.current?.();
        }
      }, 600);
    } catch (err) {
      if (uploadFallbackTimeoutRef.current) {
        clearTimeout(uploadFallbackTimeoutRef.current);
        uploadFallbackTimeoutRef.current = null;
      }
      console.error(`[MessageInput] Failed to send attachment: ${String(err)}`);
      alert(describeSendError(err));
      setSending(false);
      setUploadProgress(null);
      setUploadingIndex(null);
    }
  };

  // Start sending all attachments one by one
  const continueSendingAttachments = async () => {
    if (attachments.length === 0) return;
    startedSendingRef.current = true;
    setSending(true);
    await sendOneAttachment(attachments[0], 0);
  };

  const handleSendAttachments = async () => {
    if (attachments.length === 0) return;
    await continueSendingAttachments();
  };

  const handleAttachClick = async () => {
    try {
      const selected = await open({
        multiple: true,
        title: "Select files to attach",
      });

      if (selected) {
        const paths = Array.isArray(selected) ? selected : [selected];
        for (const filePath of paths) {
          await handleFileFromPath(filePath as string);
        }
      }
    } catch (err) {
      console.error(`[MessageInput] File selection failed: ${String(err)}`);
    }
  };

  // DOM drag events as fallback (for web context)
  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (!isDragging) setIsDragging(true);
  }, [isDragging]);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    const rect = e.currentTarget.getBoundingClientRect();
    const x = e.clientX;
    const y = e.clientY;
    if (x < rect.left || x >= rect.right || y < rect.top || y >= rect.bottom) {
      setIsDragging(false);
    }
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    const files = e.dataTransfer.files;
    if (files.length > 0) {
      for (let i = 0; i < files.length; i++) {
        handleFileObject(files[i]);
      }
    }
  }, []);

  // Handle File object (from DOM drop or paste)
  const handleFileObject = async (file: File) => {
    try {
      const arrayBuffer = await file.arrayBuffer();
      const base64 = btoa(
        new Uint8Array(arrayBuffer).reduce(
          (data, byte) => data + String.fromCharCode(byte),
          ""
        )
      );

      const tempPath = await invoke<string>("write_temp_file", {
        fileName: file.name,
        contentBase64: base64,
      });

      await handleFileFromPath(tempPath);
    } catch (err) {
      console.error(`[MessageInput] Failed to handle file object: ${String(err)}`);
      alert("Please use the attachment button to select files");
    }
  };

  // Handle paste event — support pasting files from clipboard
  const handlePaste = useCallback((e: React.ClipboardEvent) => {
    const items = e.clipboardData?.items;
    if (!items) return;

    const files: File[] = [];
    for (let i = 0; i < items.length; i++) {
      if (items[i].kind === "file") {
        const file = items[i].getAsFile();
        if (file) files.push(file);
      }
    }

    if (files.length > 0) {
      e.preventDefault(); // Prevent default paste (image URLs, etc.)
      for (const file of files) {
        handleFileObject(file);
      }
    }
    // If clipboard has only text, don't prevent default — allow normal text paste
  }, []);

  const handleRemoveAttachment = (index: number) => {
    setAttachments(prev => prev.filter((_, i) => i !== index));
    // If we're currently uploading this index, reset
    if (uploadingIndex === index) {
      resetUploadState();
    }
  };

  const getFileIcon = (mimeType: string) => {
    if (mimeType.startsWith("image/")) return <Image className="w-5 h-5 text-file-icon-image" />;
    if (mimeType.startsWith("audio/")) return <Music className="w-5 h-5 text-file-icon-audio" />;
    if (mimeType.startsWith("video/")) return <Clapperboard className="w-5 h-5 text-file-icon-video" />;
    if (mimeType === "application/pdf") return <FileText className="w-5 h-5 text-file-icon-pdf" />;
    return <File className="w-5 h-5 text-file-icon-text" />;
  };

  const getMimeType = (ext: string): string => {
    const mimeMap: Record<string, string> = {
      jpg: "image/jpeg",
      jpeg: "image/jpeg",
      png: "image/png",
      gif: "image/gif",
      webp: "image/webp",
      pdf: "application/pdf",
      doc: "application/msword",
      docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      mp3: "audio/mpeg",
      mp4: "video/mp4",
      zip: "application/zip",
      txt: "text/plain",
    };
    return mimeMap[ext] || "application/octet-stream";
  };

  const hasAttachments = attachments.length > 0;
  const primaryDisabled = sending || (!hasAttachments && !inputText.trim());
  const statusLabel = sending
    ? hasAttachments
      ? `Uploading ${(uploadingIndex ?? 0) + 1}/${attachments.length}`
      : "Sending message"
    : hasAttachments
      ? `${attachments.length} file${attachments.length > 1 ? "s" : ""} attached`
      : null;
  const sendTitle = hasAttachments
    ? `Send ${attachments.length} file${attachments.length > 1 ? "s" : ""}`
    : "Send message";
  const handlePrimarySend = () => {
    if (hasAttachments) {
      void handleSendAttachments();
      return;
    }
    void handleSendText();
  };

  return (
    <div
      className={`relative border-t border-subtle bg-base px-4 py-3 transition-colors ${
        isDragging ? "bg-primary/10 border-primary" : ""
      }`}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      {/* Drag overlay */}
      {isDragging && (
        <div className="drag-overlay absolute inset-0 z-10 flex items-center justify-center">
          <div className="text-center">
            <Paperclip size={36} className="mb-2 text-primary-color" />
            <p className="text-primary-color font-medium">Drop files to attach</p>
          </div>
        </div>
      )}

      <div className="mx-auto w-full max-w-4xl">
        <div className="overflow-hidden rounded-lg border border-subtle bg-surface shadow-sm">
          {hasAttachments && (
            <div className="border-b border-subtle px-2 py-2">
              <div className="flex gap-2 overflow-x-auto pb-1">
                {attachments.map((att, index) => (
                  <div
                    key={`${att.path}-${index}`}
                    className={`relative flex h-16 w-16 flex-shrink-0 flex-col items-center justify-center gap-1 rounded-md border transition-colors ${
                      uploadingIndex === index
                        ? "border-primary bg-primary/5"
                        : "border-subtle bg-base hover:border-default"
                    }`}
                  >
                    {uploadingIndex === index && uploadProgress !== null && (
                      <div className="absolute inset-0 flex flex-col items-center justify-center rounded-md bg-black/10">
                        <div className="relative h-8 w-8">
                          <svg className="h-8 w-8 -rotate-90" viewBox="0 0 36 36">
                            <circle
                              className="text-surface-elevated"
                              stroke="currentColor"
                              strokeWidth="3"
                              fill="none"
                              cx="18" cy="18" r="15"
                            />
                            <circle
                              className="text-primary"
                              stroke="currentColor"
                              strokeWidth="3"
                              fill="none"
                              cx="18" cy="18" r="15"
                              strokeDasharray={`${uploadProgress * 0.94} 94`}
                              strokeLinecap="round"
                            />
                          </svg>
                          <span className="absolute inset-0 flex items-center justify-center text-[8px] font-medium text-primary-color">
                            {uploadProgress}%
                          </span>
                        </div>
                      </div>
                    )}

                    {getFileIcon(att.mimeType)}

                    <span className="w-12 truncate text-center text-[10px] leading-tight text-muted-color" title={att.name}>
                      {att.name.length > 12 ? att.name.slice(0, 10) + ".." : att.name}
                    </span>

                    <button
                      className="absolute -right-1.5 -top-1.5 flex h-5 w-5 items-center justify-center rounded-full border border-default bg-surface-elevated transition-colors hover:border-error hover:bg-error hover:text-white"
                      onClick={() => handleRemoveAttachment(index)}
                      disabled={sending}
                      title="Remove attachment"
                      aria-label={`Remove ${att.name}`}
                    >
                      <X size={10} />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="flex items-end gap-2 px-2 py-2">
            <button
              className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-md text-secondary-color transition-colors hover:bg-surface-elevated hover:text-primary-color disabled:opacity-50"
              title="Attach file"
              aria-label="Attach file"
              onClick={handleAttachClick}
              disabled={sending}
            >
              <Paperclip size={19} />
            </button>
            <textarea
              ref={textareaRef}
              className="min-h-9 flex-1 resize-none bg-transparent px-1 py-1.5 text-sm text-primary-color outline-none placeholder:text-muted-color disabled:opacity-70"
              style={{
                lineHeight: `${TEXTAREA_LINE_HEIGHT_PX}px`,
                minHeight: `${TEXTAREA_LINE_HEIGHT_PX + 12}px`,
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
                overflowWrap: "break-word",
              }}
              rows={1}
              placeholder={hasAttachments ? "Add a message (optional)..." : "Type a message..."}
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey && !hasAttachments) {
                  e.preventDefault();
                  void handleSendText();
                }
              }}
              onPaste={handlePaste}
              disabled={sending}
            />
            <button
              className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-primary transition-colors hover:bg-primary-dark disabled:cursor-not-allowed disabled:opacity-50"
              onClick={handlePrimarySend}
              disabled={primaryDisabled}
              title={sendTitle}
              aria-label={sendTitle}
              style={{ color: "var(--bubble-sent-text)" }}
            >
              {sending ? <Loader2 size={18} className="animate-spin" /> : <Send size={18} />}
            </button>
          </div>

          {statusLabel && (
            <div className="border-t border-subtle px-3 pb-2 pt-1">
              <div className="flex items-center justify-between gap-3 text-xs text-muted-color">
                <span>{statusLabel}</span>
                {uploadProgress !== null && (
                  <span>{uploadProgress}%</span>
                )}
              </div>
              {uploadProgress !== null && (
                <div className="mt-1 h-1 rounded-full bg-surface-elevated">
                  <div
                    className="h-1 rounded-full bg-primary"
                    style={{ width: `${uploadProgress}%` }}
                  />
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

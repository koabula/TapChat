import { useState, useRef, useCallback, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { listen } from "@tauri-apps/api/event";

const MAX_TEXTAREA_ROWS = 5;
const TEXTAREA_LINE_HEIGHT_PX = 24;

interface MessageInputProps {
  conversationId: string;
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

export default function MessageInput({ conversationId, onSent }: MessageInputProps) {
  const [inputText, setInputText] = useState("");
  const [sending, setSending] = useState(false);
  const [attachment, setAttachment] = useState<AttachmentInfo | null>(null);
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);
  const [uploadStatus, setUploadStatus] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const uploadFallbackTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

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

  // Reset attachment upload UI state (called on success, failure, or timeout)
  const resetUploadState = useCallback(() => {
    setUploadProgress(null);
    setUploadStatus(null);
    setAttachment(null);
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

      // Only handle progress for current conversation
      if (conversation_id === conversationId) {
        setUploadProgress(progress);
        setUploadStatus(status);

        // Reset on complete or failed
        if (status === "complete" || status === "failed") {
          if (uploadFallbackTimeoutRef.current) {
            clearTimeout(uploadFallbackTimeoutRef.current);
            uploadFallbackTimeoutRef.current = null;
          }
          setTimeout(() => {
            setUploadProgress(null);
            setUploadStatus(null);
            if (status === "complete") {
              setAttachment(null);
              onSentRef.current?.();
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
        const filePath = paths[0];
        handleFileFromPath(filePath);
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
    // onSent intentionally omitted from deps — stabilized via onSentRef
  }, [conversationId]);

  // Auto-resize textarea based on content (up to MAX_TEXTAREA_ROWS)
  const adjustTextareaHeight = useCallback(() => {
    const ta = textareaRef.current;
    if (!ta) return;

    // Reset to single row to measure scroll height correctly
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

  // Handle file from path (from drag-drop or file picker)
  const handleFileFromPath = async (filePath: string) => {
    const name = filePath.split(/[/\\]/).pop() || "file";

    // Get file metadata from backend (size and mime type)
    try {
      const metadata = await invoke<{ size: number; mime_type: string }>("get_file_metadata", {
        path: filePath,
      });

      setAttachment({
        path: filePath,
        name,
        size: metadata.size,
        mimeType: metadata.mime_type,
      });
    } catch (err) {
      console.error(`[MessageInput] Failed to get file metadata: ${String(err)}`);
      // Fallback: set with unknown size and octet-stream
      const ext = name.split(".").pop()?.toLowerCase() || "";
      const mimeType = getMimeType(ext);
      setAttachment({
        path: filePath,
        name,
        size: 0,
        mimeType,
      });
    }
  };

  const handleSendText = async () => {
    if (!inputText.trim()) return;

    const textToSend = inputText;
    setSending(true);
    try {
      const result = await invoke<SendMessageResult>("send_text", {
        conversationId,
        plaintext: textToSend,
      });
      setInputText("");
      // Pass the sent message info for immediate display
      onSentWithMessage?.(result);
    } catch (err) {
      console.error(`[MessageInput] Failed to send message: ${String(err)}`);
      const errorMsg = String(err);
      if (errorMsg.includes("network") || errorMsg.includes("http") || errorMsg.includes("request") || errorMsg.includes("connect")) {
        alert("Network error: Unable to deliver message. Check if your peer has Cloudflare deployed and accessible.");
      } else {
        alert(errorMsg);
      }
    } finally {
      setSending(false);
    }
  };

  const handleSendAttachment = async () => {
    if (!attachment) return;

    setSending(true);
    setUploadProgress(0);
    setUploadStatus("reading");

    // Set a fallback timeout to reset state if the invoke itself hangs (network stall, etc.)
    uploadFallbackTimeoutRef.current = setTimeout(() => {
      console.warn("[MessageInput] Upload fallback timeout — resetting state");
      resetUploadState();
    }, 30000);

    try {
      await invoke("send_attachment", {
        conversationId,
        filePath: attachment.path,
        mimeType: attachment.mimeType,
        sizeBytes: attachment.size,
        fileName: attachment.name,
      });
      // Invoke completed: upload succeeded. The upload-progress event may have
      // already cleaned up via its 500ms deferred reset, but if the event was
      // dropped (e.g. listener re-registration gap), we clean up here defensively.
      // Use a short delay so the progress event's cleanup takes precedence if it fires.
      setTimeout(() => {
        // Only reset if still in sending state (progress event handler may have beaten us)
        if (uploadFallbackTimeoutRef.current) {
          clearTimeout(uploadFallbackTimeoutRef.current);
          uploadFallbackTimeoutRef.current = null;
          resetUploadState();
          onSentRef.current?.();
        }
      }, 600);
    } catch (err) {
      if (uploadFallbackTimeoutRef.current) {
        clearTimeout(uploadFallbackTimeoutRef.current);
        uploadFallbackTimeoutRef.current = null;
      }
      console.error(`[MessageInput] Failed to send attachment: ${String(err)}`);
      setUploadProgress(null);
      setUploadStatus(null);
      setSending(false);
    }
  };

  const handleAttachClick = async () => {
    try {
      const selected = await open({
        multiple: false,
        title: "Select file to attach",
      });

      if (selected) {
        handleFileFromPath(selected as string);
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
    // Only set false if leaving the container entirely
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

    // In Tauri, the tauri://drag-drop event handles this
    // But we also handle DOM drop as fallback
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      // In browser/webview context, we can't get full paths from File objects
      // We need to read the file content instead
      const file = files[0];
      handleFileObject(file);
    }
  }, []);

  // Handle File object (from DOM drop in web context)
  const handleFileObject = async (file: File) => {
    // Read file as ArrayBuffer and convert to base64
    // Then we need to write it to a temp location for Tauri to access
    // This is a workaround for browser-based drag-drop
    try {
      const arrayBuffer = await file.arrayBuffer();
      const base64 = btoa(
        new Uint8Array(arrayBuffer).reduce(
          (data, byte) => data + String.fromCharCode(byte),
          ""
        )
      );

      // Write to temp file via backend
      const tempPath = await invoke<string>("write_temp_file", {
        fileName: file.name,
        contentBase64: base64,
      });

      handleFileFromPath(tempPath);
    } catch (err) {
      console.error(`[MessageInput] Failed to handle dropped file: ${String(err)}`);
      // Fallback: show alert to use picker
      alert("Please use the attachment button to select files");
    }
  };

  const handleRemoveAttachment = () => {
    setAttachment(null);
    setUploadProgress(null);
    setUploadStatus(null);
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

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return "Unknown size";
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const formatStatus = (status: string): string => {
    switch (status) {
      case "reading": return "Reading file...";
      case "preparing": return "Preparing upload...";
      case "uploading": return "Uploading...";
      case "complete": return "Complete!";
      case "failed": return "Failed";
      default: return status;
    }
  };

  return (
    <div
      className={`p-3 border-t border-default transition-all ${
        isDragging ? "bg-primary/10 border-primary" : ""
      }`}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      {/* Drag overlay */}
      {isDragging && (
        <div className="absolute inset-0 drag-overlay flex items-center justify-center z-10">
          <div className="text-center">
            <div className="text-4xl mb-2 animate-bounce">📎</div>
            <p className="text-primary-color font-medium">Drop file to attach</p>
          </div>
        </div>
      )}

      {/* Attachment preview */}
      {attachment && (
        <div className="mb-2 p-3 bg-surface/50 rounded-lg border border-subtle flex items-center gap-3 animate-fade-in-up">
          <div className="w-10 h-10 rounded-lg bg-surface-elevated flex items-center justify-center text-xl flex-shrink-0 shadow-sm">
            {attachment.mimeType.startsWith("image/") ? "🖼️" :
             attachment.mimeType.startsWith("audio/") ? "🎵" :
             attachment.mimeType.startsWith("video/") ? "🎬" :
             attachment.mimeType === "application/pdf" ? "📄" : "📎"}
          </div>
          <div className="flex-1 min-w-0">
            <span className="text-sm text-primary-color truncate block">{attachment.name}</span>
            <span className="text-xs text-muted-color">{formatFileSize(attachment.size)}</span>
          </div>
          {uploadProgress !== null && (
            <div className="w-24 flex-shrink-0">
              <div className="text-xs text-muted-color mb-1">{formatStatus(uploadStatus || "")}</div>
              <div className="w-full bg-surface-elevated rounded-full h-1.5 overflow-hidden">
                <div
                  className={`h-1.5 transition-all duration-300 rounded-full ${
                    uploadStatus === "failed" ? "bg-error" :
                    uploadStatus === "complete" ? "bg-success" : "bg-primary"
                  }`}
                  style={{ width: `${uploadProgress}%` }}
                />
              </div>
            </div>
          )}
          <button
            className="w-6 h-6 flex items-center justify-center rounded-full text-xs text-muted-color hover:text-error hover:bg-error/10 transition-colors flex-shrink-0"
            onClick={handleRemoveAttachment}
            disabled={sending}
            title="Remove attachment"
          >
            ✕
          </button>
        </div>
      )}

      {/* Input row */}
      <div className="flex items-end gap-2">
        <button
          className="btn btn-ghost px-2 transition-fast"
          title="Attach file"
          onClick={handleAttachClick}
          disabled={sending}
        >
          📎
        </button>
        <textarea
          ref={textareaRef}
          className="input flex-1 transition-fast resize-none"
          style={{
            lineHeight: `${TEXTAREA_LINE_HEIGHT_PX}px`,
            minHeight: `${TEXTAREA_LINE_HEIGHT_PX + 24}px`,
            whiteSpace: "pre-wrap",
            wordBreak: "break-word",
            overflowWrap: "break-word",
          }}
          rows={1}
          placeholder={attachment ? "Add a message (optional)..." : "Type a message..."}
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey && !attachment) {
              e.preventDefault();
              handleSendText();
            }
          }}
          disabled={sending}
        />
        {attachment ? (
          <button
            className="btn btn-primary px-3 transition-fast"
            onClick={handleSendAttachment}
            disabled={sending}
          >
            {sending ? "Uploading..." : "Send File"}
          </button>
        ) : (
          <button
            className="btn btn-primary px-3 transition-fast"
            onClick={handleSendText}
            disabled={sending || !inputText.trim()}
          >
            {sending ? "Sending..." : "Send"}
          </button>
        )}
      </div>
    </div>
  );
}

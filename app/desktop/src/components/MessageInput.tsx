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
} from "lucide-react";

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
      const result = await invoke<SendMessageResult>("send_text", {
        conversationId,
        plaintext: textToSend,
      });
      setInputText("");
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
            <Paperclip size={40} className="mb-2 animate-bounce text-primary-color" />
            <p className="text-primary-color font-medium">Drop files to attach</p>
          </div>
        </div>
      )}

      {/* Attachments preview — horizontal scrollable list */}
      {hasAttachments && (
        <div className="mb-2 flex gap-2 overflow-x-auto pb-1">
          {attachments.map((att, index) => (
            <div
              key={`${att.path}-${index}`}
              className={`relative flex-shrink-0 w-20 h-20 rounded-lg border flex flex-col items-center justify-center gap-1 transition-colors ${
                uploadingIndex === index
                  ? "border-primary bg-primary/5"
                  : "border-subtle bg-surface/50 hover:border-default"
              }`}
            >
              {/* Upload progress overlay */}
              {uploadingIndex === index && uploadProgress !== null && (
                <div className="absolute inset-0 bg-black/10 rounded-lg flex flex-col items-center justify-center">
                  <div className="w-8 h-8 relative">
                    <svg className="w-8 h-8 -rotate-90" viewBox="0 0 36 36">
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

              {/* File icon */}
              {getFileIcon(att.mimeType)}

              {/* File name */}
              <span className="text-[10px] text-muted-color truncate w-16 text-center leading-tight" title={att.name}>
                {att.name.length > 12 ? att.name.slice(0, 10) + ".." : att.name}
              </span>

              {/* Remove button */}
              <button
                className="absolute -top-1.5 -right-1.5 w-5 h-5 rounded-full bg-surface-elevated border border-default flex items-center justify-center hover:bg-error hover:text-white hover:border-error transition-colors"
                onClick={() => handleRemoveAttachment(index)}
                disabled={sending}
                title="Remove attachment"
              >
                <X size={10} />
              </button>
            </div>
          ))}
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
          <Paperclip size={20} />
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
          placeholder={hasAttachments ? "Add a message (optional)..." : "Type a message..."}
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey && !hasAttachments) {
              e.preventDefault();
              handleSendText();
            }
          }}
          onPaste={handlePaste}
          disabled={sending}
        />
        {hasAttachments ? (
          <button
            className="btn btn-primary px-3 transition-fast whitespace-nowrap"
            onClick={handleSendAttachments}
            disabled={sending}
          >
            {sending
              ? `Uploading ${(uploadingIndex ?? 0) + 1}/${attachments.length}...`
              : `Send ${attachments.length} file${attachments.length > 1 ? "s" : ""}`}
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

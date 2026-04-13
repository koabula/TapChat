import { useState, useRef, useCallback, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { listen } from "@tauri-apps/api/event";

interface MessageInputProps {
  conversationId: string;
  onSent?: () => void;
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

export default function MessageInput({ conversationId, onSent }: MessageInputProps) {
  const [inputText, setInputText] = useState("");
  const [sending, setSending] = useState(false);
  const [attachment, setAttachment] = useState<AttachmentInfo | null>(null);
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);
  const [uploadStatus, setUploadStatus] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

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
          setTimeout(() => {
            setUploadProgress(null);
            setUploadStatus(null);
            if (status === "complete") {
              setAttachment(null);
              onSent?.();
            }
            setSending(false);
          }, 500);
        }
      }
    });

    return () => {
      unlisten.then((fn) => fn());
    };
  }, [conversationId, onSent]);

  const handleSendText = async () => {
    if (!inputText.trim()) return;

    setSending(true);
    try {
      await invoke("send_text", {
        conversationId,
        plaintext: inputText,
      });
      setInputText("");
      onSent?.();
    } catch (err) {
      console.error("Failed to send:", err);
    } finally {
      setSending(false);
    }
  };

  const handleSendAttachment = async () => {
    if (!attachment) return;

    setSending(true);
    setUploadProgress(0);
    setUploadStatus("reading");

    try {
      await invoke("send_attachment", {
        conversationId,
        filePath: attachment.path,
        mimeType: attachment.mimeType,
        sizeBytes: attachment.size,
        fileName: attachment.name,
      });
      // Progress events will handle the rest
    } catch (err) {
      console.error("Failed to send attachment:", err);
      setUploadProgress(null);
      setUploadStatus(null);
      setSending(false);
    }
  };

  const handleAttachClick = async () => {
    try {
      // Use Tauri dialog plugin for file selection
      const selected = await open({
        multiple: false,
        title: "Select file to attach",
      });

      if (selected) {
        const path = selected as string;
        const name = path.split(/[/\\]/).pop() || "file";

        // Determine MIME type from extension
        const ext = name.split(".").pop()?.toLowerCase() || "";
        const mimeType = getMimeType(ext);

        // For now, we don't have file size from dialog
        // The backend will need to get it from the file
        setAttachment({
          path,
          name,
          size: 0, // Backend will determine
          mimeType,
        });
      }
    } catch (err) {
      console.error("File selection failed:", err);
    }
  };

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();

    const files = e.dataTransfer.files;
    if (files.length > 0) {
      const file = files[0];
      // For drag-drop, we get a File object but need the path for Tauri
      // In web context, we'd read the file; in Tauri, we need the path
      // This is a limitation - drag-drop from outside the app won't work well
      // Users should use the file picker button instead
      console.log("Drag-drop file:", file.name, file.type, file.size);

      // We can't get the path from File object in browser context
      // So we'll show a message to use the picker instead
      alert("Please use the attachment button to select files");
    }
  }, []);

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
      className="p-3 border-t border-default"
      onDragOver={handleDragOver}
      onDrop={handleDrop}
    >
      {/* Attachment preview */}
      {attachment && (
        <div className="mb-2 p-2 card flex items-center gap-2">
          <span className="text-lg">
            {attachment.mimeType.startsWith("image/") ? "🖼️" :
             attachment.mimeType.startsWith("audio/") ? "🎵" :
             attachment.mimeType.startsWith("video/") ? "🎬" : "📎"}
          </span>
          <div className="flex-1 min-w-0">
            <span className="text-primary-color truncate block">{attachment.name}</span>
            <span className="text-muted-color text-xs">{formatFileSize(attachment.size)}</span>
          </div>
          {uploadProgress !== null && (
            <div className="w-24">
              <div className="text-xs text-muted-color mb-1">{formatStatus(uploadStatus || "")}</div>
              <div className="w-full bg-surface rounded-full h-1.5">
                <div
                  className={`rounded-full h-1.5 transition-all ${
                    uploadStatus === "failed" ? "bg-aurora.red" :
                    uploadStatus === "complete" ? "status-success" : "bg-primary"
                  }`}
                  style={{ width: `${uploadProgress}%` }}
                />
              </div>
            </div>
          )}
          <button
            className="btn btn-ghost px-1 text-sm"
            onClick={handleRemoveAttachment}
            disabled={sending}
          >
            ✕
          </button>
        </div>
      )}

      {/* Input row */}
      <div className="flex items-center gap-2">
        <button
          className="btn btn-ghost px-2"
          title="Attach file"
          onClick={handleAttachClick}
          disabled={sending}
        >
          📎
        </button>
        <input
          ref={fileInputRef}
          className="input flex-1"
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
            className="btn btn-primary px-3"
            onClick={handleSendAttachment}
            disabled={sending}
          >
            {sending ? "Uploading..." : "Send File"}
          </button>
        ) : (
          <button
            className="btn btn-primary px-3"
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
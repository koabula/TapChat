import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";

interface AttachmentPreviewProps {
  messageId: string;
  conversationId: string;
  reference: string;
  mimeType: string;
  fileName?: string;
  downloaded?: boolean;
  showInline?: boolean;
}

export default function AttachmentPreview({
  messageId,
  conversationId,
  reference,
  mimeType,
  fileName,
  downloaded = false,
  showInline = true,
}: AttachmentPreviewProps) {
  const [downloading, setDownloading] = useState(false);
  const [downloadedPath, setDownloadedPath] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [imageData, setImageData] = useState<string | null>(null);
  const [loadingPreview, setLoadingPreview] = useState(false);

  // Load inline preview for images
  useEffect(() => {
    if (showInline && mimeType.startsWith("image/") && !imageData) {
      loadImagePreview();
    }
  }, [mimeType, showInline, reference]);

  const loadImagePreview = async () => {
    setLoadingPreview(true);
    try {
      // Request thumbnail/preview from backend
      const result = await invoke<string | null>("get_attachment_preview", {
        conversationId,
        messageId,
        reference,
      });
      if (result) {
        setImageData(result); // Base64 encoded image data
      }
    } catch (err) {
      // Preview failed, fall back to icon display
      console.error(`[AttachmentPreview] Failed to load image preview: ${String(err)}`);
    } finally {
      setLoadingPreview(false);
    }
  };

  const getIcon = () => {
    if (mimeType.startsWith("image/")) return "🖼️";
    if (mimeType.startsWith("audio/")) return "🎵";
    if (mimeType.startsWith("video/")) return "🎬";
    if (mimeType === "application/pdf") return "📄";
    if (mimeType.includes("word") || mimeType.includes("document")) return "📝";
    return "📎";
  };

  const handleDownload = async () => {
    setDownloading(true);
    setError(null);

    try {
      // Prompt user for save location
      const savePath = await save({
        title: "Save attachment",
        defaultPath: fileName || `attachment-${messageId}`,
      });

      if (!savePath) {
        setDownloading(false);
        return;
      }

      await invoke("download_attachment", {
        conversationId,
        messageId,
        reference,
        destination: savePath,
      });

      setDownloadedPath(savePath);
    } catch (err) {
      setError(String(err));
    } finally {
      setDownloading(false);
    }
  };

  const handleOpen = async () => {
    if (!downloadedPath) return;

    // Open the file using shell plugin
    try {
      await invoke("open_file", { path: downloadedPath });
    } catch (err) {
      console.error(`[AttachmentPreview] Failed to open file: ${String(err)}`);
    }
  };

  const formatFileName = () => {
    if (!fileName) return "Attachment";
    return fileName.length > 30 ? fileName.slice(0, 27) + "..." : fileName;
  };

  // Inline image preview
  if (showInline && mimeType.startsWith("image/")) {
    return (
      <div className="flex flex-col gap-2">
        {loadingPreview && (
          <div className="w-full h-32 bg-surface-elevated rounded flex items-center justify-center">
            <span className="text-muted-color animate-pulse">Loading preview...</span>
          </div>
        )}

        {imageData && (
          <img
            src={`data:${mimeType};base64,${imageData}`}
            alt={fileName || "Image attachment"}
            className="max-w-full max-h-48 rounded cursor-pointer hover:opacity-90 transition-opacity"
            onClick={handleDownload}
            onError={() => setImageData(null)}
          />
        )}

        {!imageData && !loadingPreview && (
          <div className="flex items-center gap-2 p-2 bg-surface-elevated rounded">
            <span className="text-lg">{getIcon()}</span>
            <span className="text-sm text-primary-color">{formatFileName()}</span>
          </div>
        )}

        {/* Download/Open controls */}
        <div className="flex items-center gap-2">
          {downloaded || downloadedPath ? (
            <button
              className="text-xs underline text-primary hover:opacity-80"
              onClick={handleOpen}
            >
              Open
            </button>
          ) : (
            <button
              className="text-xs underline text-primary hover:opacity-80"
              onClick={handleDownload}
              disabled={downloading}
            >
              {downloading ? "Downloading..." : "Download original"}
            </button>
          )}
          {error && <span className="text-xs status-error">{error}</span>}
        </div>
      </div>
    );
  }

  // Default file attachment display
  return (
    <div className="flex items-center gap-2">
      <span className="text-lg">{getIcon()}</span>
      <span className="text-sm text-primary-color">{formatFileName()}</span>

      {downloaded || downloadedPath ? (
        <button
          className="text-xs underline text-primary hover:opacity-80"
          onClick={handleOpen}
        >
          Open
        </button>
      ) : (
        <button
          className="text-xs underline text-primary hover:opacity-80"
          onClick={handleDownload}
          disabled={downloading}
        >
          {downloading ? "Downloading..." : "Download"}
        </button>
      )}

      {error && <span className="text-xs status-error">{error}</span>}
    </div>
  );
}

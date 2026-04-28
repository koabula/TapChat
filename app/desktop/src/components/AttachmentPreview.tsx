import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";

interface AttachmentPreviewProps {
  messageId: string;
  conversationId: string;
  reference: string;
  mimeType?: string;
  fileName?: string;
  sizeBytes?: number;
  downloaded?: boolean;
  showInline?: boolean;
}

export default function AttachmentPreview({
  messageId,
  conversationId,
  reference,
  mimeType = "application/octet-stream",
  fileName,
  sizeBytes,
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
      const result = await invoke<string | null>("get_attachment_preview", {
        conversationId,
        messageId,
        reference,
      });
      if (result) {
        setImageData(result);
      }
    } catch (err) {
      console.error(`[AttachmentPreview] Failed to load image preview: ${String(err)}`);
    } finally {
      setLoadingPreview(false);
    }
  };

  const getFileIcon = (): string => {
    if (mimeType.startsWith("image/")) return "🖼️";
    if (mimeType.startsWith("audio/")) return "🎵";
    if (mimeType.startsWith("video/")) return "🎬";
    if (mimeType === "application/pdf") return "📄";
    if (mimeType.includes("word") || mimeType.includes("document")) return "📝";
    if (mimeType.includes("spreadsheet") || mimeType.includes("excel")) return "📊";
    if (mimeType.includes("presentation") || mimeType.includes("powerpoint")) return "📽️";
    if (mimeType === "application/zip" || mimeType.includes("compressed")) return "📦";
    if (mimeType.startsWith("text/")) return "📃";
    return "📎";
  };

  const getFileTypeLabel = (): string => {
    if (mimeType.startsWith("image/")) return "Image";
    if (mimeType.startsWith("audio/")) return "Audio";
    if (mimeType.startsWith("video/")) return "Video";
    if (mimeType === "application/pdf") return "PDF";
    if (mimeType.includes("word") || mimeType.includes("document")) return "Document";
    if (mimeType.includes("spreadsheet") || mimeType.includes("excel")) return "Spreadsheet";
    if (mimeType.includes("presentation") || mimeType.includes("powerpoint")) return "Presentation";
    if (mimeType === "application/zip" || mimeType.includes("compressed")) return "Archive";
    if (mimeType.startsWith("text/")) return "Text";
    return "File";
  };

  const handleDownload = async () => {
    setDownloading(true);
    setError(null);

    try {
      const defaultFileName = fileName || `attachment${getExtensionFromMimeType(mimeType)}`;

      const savePath = await save({
        title: "Save attachment",
        defaultPath: defaultFileName,
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

  const getExtensionFromMimeType = (mime: string): string => {
    const mimeToExt: Record<string, string> = {
      "image/jpeg": ".jpg",
      "image/png": ".png",
      "image/gif": ".gif",
      "image/webp": ".webp",
      "application/pdf": ".pdf",
      "audio/mpeg": ".mp3",
      "audio/wav": ".wav",
      "video/mp4": ".mp4",
      "application/zip": ".zip",
      "text/plain": ".txt",
    };
    return mimeToExt[mime] || "";
  };

  const handleOpen = async () => {
    if (!downloadedPath) return;
    try {
      await invoke("open_file", { path: downloadedPath });
    } catch (err) {
      console.error(`[AttachmentPreview] Failed to open file: ${String(err)}`);
    }
  };

  const formatFileName = (): string => {
    if (!fileName) return "Attachment";
    return fileName.length > 35 ? fileName.slice(0, 32) + "..." : fileName;
  };

  const formatFileSize = (bytes?: number): string | null => {
    if (!bytes || bytes === 0) return null;
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const sizeStr = formatFileSize(sizeBytes);

  // Image attachment with inline preview
  if (showInline && mimeType.startsWith("image/")) {
    return (
      <div className="flex flex-col gap-2">
        {/* Loading placeholder */}
        {loadingPreview && (
          <div className="w-full h-40 bg-surface-elevated rounded-lg flex items-center justify-center">
            <div className="flex flex-col items-center gap-2">
              <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
              <span className="text-xs text-muted-color">Loading preview...</span>
            </div>
          </div>
        )}

        {/* Image thumbnail */}
        {imageData && (
          <div className="relative group">
            <img
              src={`data:${mimeType};base64,${imageData}`}
              alt={fileName || "Image attachment"}
              className="max-w-full max-h-64 rounded-lg object-cover cursor-pointer shadow-sm"
              onClick={handleDownload}
              onError={() => setImageData(null)}
            />
            {/* Hover overlay */}
            <div
              className="absolute inset-0 bg-black/0 group-hover:bg-black/20 rounded-lg transition-colors flex items-center justify-center cursor-pointer"
              onClick={handleDownload}
            >
              <span className="text-white text-sm font-medium opacity-0 group-hover:opacity-100 transition-opacity bg-black/50 px-3 py-1.5 rounded-full">
                {downloaded || downloadedPath ? "Open" : "Download"}
              </span>
            </div>
          </div>
        )}

        {/* Fallback when image can't be previewed */}
        {!imageData && !loadingPreview && (
          <FileCard
            icon={getFileIcon()}
            name={formatFileName()}
            typeLabel={getFileTypeLabel()}
            sizeStr={sizeStr}
            downloaded={downloaded || !!downloadedPath}
            downloading={downloading}
            error={error}
            onDownload={handleDownload}
            onOpen={handleOpen}
          />
        )}
      </div>
    );
  }

  // Non-image file attachment
  return (
    <FileCard
      icon={getFileIcon()}
      name={formatFileName()}
      typeLabel={getFileTypeLabel()}
      sizeStr={sizeStr}
      downloaded={downloaded || !!downloadedPath}
      downloading={downloading}
      error={error}
      onDownload={handleDownload}
      onOpen={handleOpen}
    />
  );
}

/** Polished file card for non-image attachments */
function FileCard({
  icon,
  name,
  typeLabel,
  sizeStr,
  downloaded,
  downloading,
  error,
  onDownload,
  onOpen,
}: {
  icon: string;
  name: string;
  typeLabel: string;
  sizeStr: string | null;
  downloaded: boolean;
  downloading: boolean;
  error: string | null;
  onDownload: () => void;
  onOpen: () => void;
}) {
  return (
    <div className="flex items-center gap-3 p-3 bg-surface/50 rounded-lg border border-subtle hover:border-default transition-colors group/file">
      {/* Icon */}
      <div className="w-10 h-10 rounded-lg bg-surface-elevated flex items-center justify-center text-xl flex-shrink-0 shadow-sm">
        {icon}
      </div>

      {/* File info */}
      <div className="flex-1 min-w-0">
        <div className="text-sm text-primary-color font-medium truncate" title={name}>
          {name}
        </div>
        <div className="flex items-center gap-2 text-xs text-muted-color">
          <span>{typeLabel}</span>
          {sizeStr && (
            <>
              <span className="opacity-40">·</span>
              <span>{sizeStr}</span>
            </>
          )}
        </div>
      </div>

      {/* Action button */}
      {downloaded ? (
        <button
          className="text-xs text-primary hover:underline flex-shrink-0 transition-colors"
          onClick={onOpen}
        >
          Open
        </button>
      ) : (
        <button
          className="text-xs text-primary hover:underline flex-shrink-0 transition-colors disabled:opacity-50"
          onClick={onDownload}
          disabled={downloading}
        >
          {downloading ? (
            <span className="flex items-center gap-1">
              <span className="w-3 h-3 border border-primary border-t-transparent rounded-full animate-spin" />
              Saving...
            </span>
          ) : (
            "Download"
          )}
        </button>
      )}

      {/* Error */}
      {error && (
        <span className="text-xs text-error flex-shrink-0">{error}</span>
      )}
    </div>
  );
}

import { useState } from "react";
import type { ReactNode } from "react";
import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import {
  Image,
  Music,
  Clapperboard,
  FileText,
  FileEdit,
  Sheet,
  Presentation,
  Archive,
  File,
} from "lucide-react";
import AttachmentCard from "./AttachmentCard";

export interface AttachmentPreviewProps {
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
}: AttachmentPreviewProps) {
  const [downloading, setDownloading] = useState(false);
  const [downloadedPath, setDownloadedPath] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const formatAttachmentError = (err: unknown): string => {
    const text = String(err);
    const lower = text.toLowerCase();
    if (
      lower.includes("capability_expired") ||
      lower.includes("sharing token expired") ||
      lower.includes("http 403") ||
      lower.includes("link may have expired")
    ) {
      return "Attachment link expired";
    }
    if (lower.includes("metadata is missing") || lower.includes("attachment metadata missing")) {
      return "Attachment metadata missing";
    }
    return text;
  };

  const getFileIcon = (): ReactNode => {
    const cls = (color: string) => `w-6 h-6 ${color}`;
    if (mimeType.startsWith("image/")) return <Image className={cls("text-file-icon-image")} />;
    if (mimeType.startsWith("audio/")) return <Music className={cls("text-file-icon-audio")} />;
    if (mimeType.startsWith("video/")) return <Clapperboard className={cls("text-file-icon-video")} />;
    if (mimeType === "application/pdf") return <FileText className={cls("text-file-icon-pdf")} />;
    if (mimeType.includes("word") || mimeType.includes("document")) return <FileEdit className={cls("text-file-icon-document")} />;
    if (mimeType.includes("spreadsheet") || mimeType.includes("excel")) return <Sheet className={cls("text-file-icon-spreadsheet")} />;
    if (mimeType.includes("presentation") || mimeType.includes("powerpoint")) return <Presentation className={cls("text-file-icon-presentation")} />;
    if (mimeType === "application/zip" || mimeType.includes("compressed")) return <Archive className={cls("text-file-icon-archive")} />;
    if (mimeType.startsWith("text/")) return <File className={cls("text-file-icon-text")} />;
    return <File className={cls("text-file-icon-text")} />;
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
      const settings = await invoke<{ always_ask_save_path: boolean }>("get_attachment_settings");

      if (settings.always_ask_save_path) {
        const savePath = await save({
          title: "Save attachment",
          defaultPath: defaultFileName,
        });

        if (!savePath) {
          setDownloading(false);
          return null;
        }

        await invoke("download_attachment", {
          conversationId,
          messageId,
          reference,
          destination: savePath,
        });

        setDownloadedPath(savePath);
        return savePath;
      }

      const defaultPath = await invoke<string>("download_attachment_to_default_path", {
        conversationId,
        messageId,
        reference,
        fileName: defaultFileName,
        mimeType,
      });

      setDownloadedPath(defaultPath);
      return defaultPath;
    } catch (err) {
      setError(formatAttachmentError(err));
      return null;
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
    if (!downloadedPath) {
      await handleDownload();
      return;
    }
    try {
      const exists = await invoke<boolean>("path_exists", { path: downloadedPath });
      if (!exists) {
        setDownloadedPath(null);
        const redownloadedPath = await handleDownload();
        if (redownloadedPath) {
          await invoke("open_file", { path: redownloadedPath });
        }
        return;
      }
      await invoke("open_file", { path: downloadedPath });
    } catch (err) {
      setError(formatAttachmentError(err));
    }
  };

  const formatFileName = (): string => {
    if (!fileName) return "Attachment";
    return fileName.length > 35 ? `${fileName.slice(0, 32)}...` : fileName;
  };

  const formatFileSize = (bytes?: number): string | null => {
    if (!bytes || bytes === 0) return null;
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <AttachmentCard
      icon={getFileIcon()}
      name={formatFileName()}
      typeLabel={getFileTypeLabel()}
      sizeStr={formatFileSize(sizeBytes)}
      downloaded={downloaded || !!downloadedPath}
      downloading={downloading}
      error={error}
      onDownload={handleDownload}
      onOpen={handleOpen}
    />
  );
}

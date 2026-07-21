import type { ReactNode } from "react";
import { invoke } from "@tauri-apps/api/core";
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
import { useAttachmentDownload } from "@/hooks/useAttachmentDownload";
import { formatAttachmentDownloadError } from "@/lib/attachmentDownload";

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
  const {
    downloading,
    downloadedPath,
    error,
    setDownloadedPath,
    setError,
    download: handleDownload,
  } = useAttachmentDownload({
    conversationId,
    messageId,
    reference,
    fileName,
    mimeType,
  });

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
      setError(formatAttachmentDownloadError(err));
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

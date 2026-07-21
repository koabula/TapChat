import { useCallback, useEffect, useState } from "react";

import {
  downloadAttachmentWithSettings,
  formatAttachmentDownloadError,
  type AttachmentDownloadRequest,
} from "@/lib/attachmentDownload";

export function useAttachmentDownload(request: AttachmentDownloadRequest) {
  const { conversationId, messageId, reference, fileName, mimeType } = request;
  const [downloading, setDownloading] = useState(false);
  const [downloadedPath, setDownloadedPath] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setDownloading(false);
    setDownloadedPath(null);
    setError(null);
  }, [conversationId, fileName, messageId, mimeType, reference]);

  const download = useCallback(async (): Promise<string | null> => {
    setDownloading(true);
    setError(null);
    try {
      const result = await downloadAttachmentWithSettings({
        conversationId,
        messageId,
        reference,
        fileName,
        mimeType,
      });
      if (result.status === "cancelled") return null;
      setDownloadedPath(result.path);
      return result.path;
    } catch (caught) {
      setError(formatAttachmentDownloadError(caught));
      return null;
    } finally {
      setDownloading(false);
    }
  }, [conversationId, fileName, messageId, mimeType, reference]);

  return { downloading, downloadedPath, error, setDownloadedPath, setError, download };
}

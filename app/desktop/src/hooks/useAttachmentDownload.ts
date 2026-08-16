import { useCallback, useEffect, useState } from "react";
import { invokeApp as invoke } from "@/lib/tauri";

import {
  downloadAttachmentWithSettings,
  formatAttachmentDownloadError,
  type AttachmentDownloadRequest,
} from "@/lib/attachmentDownload";
import {
  attachmentDownloadKey,
  useAttachmentDownloadSession,
} from "@/store/attachmentDownloads";

export function useAttachmentDownload(request: AttachmentDownloadRequest) {
  const { conversationId, messageId, reference, fileName, mimeType } = request;
  const key = attachmentDownloadKey(conversationId, messageId, reference);
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [cancelled, setCancelled] = useState(false);
  const downloadedPath = useAttachmentDownloadSession((state) => state.paths[key] ?? null);
  const remember = useAttachmentDownloadSession((state) => state.remember);
  const forget = useAttachmentDownloadSession((state) => state.forget);
  const setDownloadedPath = useCallback((path: string | null) => {
    if (path) remember(key, path);
    else forget(key);
  }, [forget, key, remember]);

  useEffect(() => {
    setDownloading(false);
    setError(null);
    setCancelled(false);
    if (!downloadedPath) return;
    let cancelled = false;
    void invoke<boolean>("path_exists", { path: downloadedPath }).then((exists) => {
      if (!cancelled && !exists) forget(key);
    }).catch(() => {
      if (!cancelled) forget(key);
    });
    return () => { cancelled = true; };
  }, [downloadedPath, forget, key]);

  const download = useCallback(async (): Promise<string | null> => {
    setDownloading(true);
    setError(null);
    setCancelled(false);
    try {
      if (downloadedPath && await invoke<boolean>("path_exists", { path: downloadedPath })) {
        return downloadedPath;
      }
      if (downloadedPath) forget(key);
      const result = await downloadAttachmentWithSettings({
        conversationId,
        messageId,
        reference,
        fileName,
        mimeType,
      });
      if (result.status === "cancelled") {
        setCancelled(true);
        return null;
      }
      remember(key, result.path);
      return result.path;
    } catch (caught) {
      setError(formatAttachmentDownloadError(caught));
      return null;
    } finally {
      setDownloading(false);
    }
  }, [conversationId, downloadedPath, fileName, forget, key, messageId, mimeType, reference, remember]);

  return { downloading, downloadedPath, error, cancelled, setDownloadedPath, setError, download };
}

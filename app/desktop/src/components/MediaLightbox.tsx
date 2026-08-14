import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { decode } from "blurhash";
import {
  Check,
  ChevronLeft,
  ChevronRight,
  Download,
  ExternalLink,
  FolderOpen,
  Image,
  Loader2,
  ScanSearch,
  X,
} from "lucide-react";
import { useAttachmentDownload } from "@/hooks/useAttachmentDownload";

export interface MediaItem {
  type: "image" | "video" | "audio" | "other";
  messageId: string;
  conversationId: string;
  mimeType: string;
  fileName?: string;
  sizeBytes?: number;
  width?: number;
  height?: number;
  blurHash?: string;
  previewAvailable?: boolean;
  attachmentState?: "pending" | "published";
  uploadState?: "sending" | "sent" | "failed";
}

interface OpenMediaResult {
  handle: string;
  url: string;
  expires_at: number;
  served_variant: "preview" | "original";
  cached: boolean;
  streaming: boolean;
}

interface AttachmentMediaState {
  preview_state: "unavailable" | "remote" | "cached";
  original_state: "remote" | "partial" | "cached";
  cached_bytes: number;
  total_bytes: number;
}

function formatSize(bytes?: number): string {
  if (!bytes) return "";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

function useMedia(item: MediaItem, variant: "preview" | "original", enabled: boolean) {
  const [media, setMedia] = useState<OpenMediaResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (!enabled) {
      setMedia(null);
      setError(null);
      return;
    }
    let cancelled = false;
    let handle: string | null = null;
    setMedia(null);
    setError(null);
    void invoke<OpenMediaResult>("open_media", {
      conversationId: item.conversationId,
      messageId: item.messageId,
      variant,
    }).then((opened) => {
      handle = opened.handle;
      if (cancelled) void invoke("release_media", { handle });
      else setMedia(opened);
    }).catch((reason) => !cancelled && setError(String(reason)));
    return () => {
      cancelled = true;
      if (handle) void invoke("release_media", { handle });
    };
  }, [enabled, item.conversationId, item.messageId, variant]);
  return { media, error };
}

function BlurHashBackdrop({ hash }: { hash: string }) {
  const canvas = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const element = canvas.current;
    if (!element) return;
    try {
      const pixels = decode(hash, 32, 24);
      const context = element.getContext("2d");
      if (!context) return;
      const image = context.createImageData(32, 24);
      image.data.set(pixels);
      context.putImageData(image, 0, 0);
    } catch { /* Invalid placeholders fall back to the image card. */ }
  }, [hash]);
  return <canvas ref={canvas} width={32} height={24} className="max-h-[85vh] max-w-[90vw] scale-105 blur-xl" aria-hidden="true" />;
}

export default function MediaLightbox({ items, initialIndex, onClose }: {
  items: MediaItem[];
  initialIndex: number;
  onClose: () => void;
}) {
  const [index, setIndex] = useState(initialIndex);
  const [showOriginal, setShowOriginal] = useState(false);
  const [mediaStateChecked, setMediaStateChecked] = useState(false);
  const [mediaState, setMediaState] = useState<AttachmentMediaState | null>(null);
  const item = items[index];
  const useOriginal = showOriginal || item.type !== "image" || !item.previewAvailable;
  const requestedVariant = useOriginal ? "original" : "preview";
  const shouldLoad = item.type !== "other" && (item.type !== "image" || mediaStateChecked);
  const { media, error } = useMedia(item, requestedVariant, shouldLoad);
  const save = useAttachmentDownload({
    conversationId: item.conversationId,
    messageId: item.messageId,
    reference: "original",
    fileName: item.fileName,
    mimeType: item.mimeType,
  });
  useEffect(() => {
    setShowOriginal(false);
    setMediaState(null);
    if (item.type !== "image" || item.attachmentState === "pending") {
      setMediaStateChecked(true);
      return;
    }
    let cancelled = false;
    setMediaStateChecked(false);
    void invoke<AttachmentMediaState>("get_attachment_media_state", {
      conversationId: item.conversationId,
      messageId: item.messageId,
    }).then((state) => {
      if (cancelled) return;
      setMediaState(state);
      setShowOriginal(state.original_state === "cached");
    }).catch(() => {
      // Old/pending attachments still fall back to the existing preview path.
    }).finally(() => {
      if (!cancelled) setMediaStateChecked(true);
    });
    return () => { cancelled = true; };
  }, [item.attachmentState, item.conversationId, item.messageId, item.type]);
  useEffect(() => {
    const keydown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
      if (event.key === "ArrowLeft") setIndex((value) => Math.max(0, value - 1));
      if (event.key === "ArrowRight") setIndex((value) => Math.min(items.length - 1, value + 1));
    };
    window.addEventListener("keydown", keydown);
    return () => window.removeEventListener("keydown", keydown);
  }, [items.length, onClose]);
  const openSavedFile = async () => {
    if (!save.downloadedPath) return;
    try {
      await invoke("open_file", { path: save.downloadedPath });
    } catch (reason) {
      save.setError(String(reason));
    }
  };
  const openSavedFolder = async () => {
    if (!save.downloadedPath) return;
    try {
      await invoke("open_containing_folder", { path: save.downloadedPath });
    } catch (reason) {
      save.setError(String(reason));
    }
  };
  return <div className="fixed inset-0 z-50 flex flex-col bg-black/85" onClick={(event) => event.target === event.currentTarget && onClose()}>
    <div className="flex items-center justify-between px-4 py-3 text-white/90">
      <span className="min-w-0 truncate text-sm font-medium">{item.fileName || "Image"}</span>
      <div className="flex items-center gap-1">
        {item.type === "image" && !useOriginal && mediaStateChecked && (
          <button className="rounded-lg px-3 py-2 text-sm hover:bg-white/10" onClick={() => setShowOriginal(true)} title="Load the full-resolution original into TapChat's private cache"><span className="inline-flex items-center gap-1.5"><ScanSearch size={18} />View original{formatSize(mediaState?.total_bytes ?? item.sizeBytes) ? ` · ${formatSize(mediaState?.total_bytes ?? item.sizeBytes)}` : ""}</span></button>
        )}
        <button className="rounded-lg p-2 hover:bg-white/10 disabled:opacity-50" onClick={() => void save.download()} disabled={save.downloading || item.attachmentState === "pending"} aria-label="Save original" title={item.attachmentState === "pending" ? "Available after upload completes" : save.downloadedPath ? "Already saved this session" : "Save original"}>{save.downloading ? <Loader2 size={18} className="animate-spin" /> : save.downloadedPath ? <Check size={18} /> : <Download size={18} />}</button>
        {items.length > 1 && <>
          <button className="rounded-lg p-2 hover:bg-white/10 disabled:opacity-40" disabled={index === 0} onClick={() => setIndex((value) => value - 1)} aria-label="Previous attachment"><ChevronLeft size={20} /></button>
          <button className="rounded-lg p-2 hover:bg-white/10 disabled:opacity-40" disabled={index === items.length - 1} onClick={() => setIndex((value) => value + 1)} aria-label="Next attachment"><ChevronRight size={20} /></button>
        </>}
        <button className="ml-2 rounded-lg p-2 hover:bg-white/10" onClick={onClose} aria-label="Close attachment viewer"><X size={20} /></button>
      </div>
    </div>
    {(save.downloadedPath || save.error || save.cancelled) && <div className="mx-4 flex flex-wrap items-center justify-end gap-2 border-t border-white/10 px-1 py-2 text-xs text-white/70" role="status" aria-live="polite">
      {save.downloadedPath && <><span className="max-w-[50vw] truncate" title={save.downloadedPath}>Saved to {save.downloadedPath}</span><button className="inline-flex items-center gap-1 rounded px-2 py-1 hover:bg-white/10" onClick={() => void openSavedFile()}><ExternalLink size={14} />Open file</button><button className="inline-flex items-center gap-1 rounded px-2 py-1 hover:bg-white/10" onClick={() => void openSavedFolder()}><FolderOpen size={14} />Open folder</button></>}
      {save.error && <span className="text-red-300">Save failed: {save.error}</span>}
      {save.cancelled && !save.downloadedPath && <span>Save cancelled</span>}
    </div>}
    <div className="flex min-h-0 flex-1 items-center justify-center p-4">
      {item.type === "image" && !mediaStateChecked && item.blurHash && <BlurHashBackdrop hash={item.blurHash} />}
      {item.type === "image" && !mediaStateChecked && !item.blurHash && <div className="h-10 w-10 animate-spin rounded-full border-2 border-white/30 border-t-white" aria-label="Checking image cache" />}
      {item.type === "other" && <div className="text-center text-white/60"><Image className="mx-auto mb-2" size={40} /><p>Preview unavailable</p><p className="mt-1 text-xs text-white/40">Use Save to download this attachment.</p></div>}
      {shouldLoad && !media && !error && <div className="h-10 w-10 animate-spin rounded-full border-2 border-white/30 border-t-white" />}
      {error && <div className="text-center text-white/60"><p>Failed to load {requestedVariant}</p><p className="mt-1 text-xs text-white/30">{error}</p>{!useOriginal && <button className="mt-3 rounded-lg bg-white/10 px-4 py-2 text-sm hover:bg-white/15" onClick={() => setShowOriginal(true)}>Try original</button>}</div>}
      {media && item.type === "image" && <div className="flex flex-col items-center gap-3"><img src={media.url} alt={item.fileName || "Image"} className="max-h-[80vh] max-w-[90vw] object-contain" />{item.attachmentState === "pending" && <span className="rounded-full bg-white/10 px-3 py-1 text-xs text-white/70">Stored locally · {item.uploadState === "failed" ? "Upload failed" : "Upload pending"}</span>}</div>}
      {media && item.type === "video" && <video src={media.url} controls autoPlay preload="metadata" className="max-h-[80vh] max-w-[90vw] rounded-lg bg-black" />}
      {media && item.type === "audio" && <audio src={media.url} controls autoPlay className="w-[min(90vw,36rem)]" />}
    </div>
  </div>;
}

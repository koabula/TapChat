import { useState, useEffect, useRef, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { convertFileSrc } from "@tauri-apps/api/core";
import {
  X,
  ChevronLeft,
  ChevronRight,
  Download,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Play,
  Pause,
} from "lucide-react";

export interface MediaItem {
  type: "image" | "video" | "audio" | "other";
  messageId: string;
  conversationId: string;
  reference: string;
  mimeType: string;
  fileName?: string;
  sizeBytes?: number;
  metadataReady?: boolean;
  metadataVersion?: string;
  /** Pre-loaded base64 data for images; when set, skips remote fetch. */
  base64Data?: string;
}

interface MediaLightboxProps {
  items: MediaItem[];
  initialIndex: number;
  onClose: () => void;
}

export default function MediaLightbox({ items, initialIndex, onClose }: MediaLightboxProps) {
  const [currentIndex, setCurrentIndex] = useState(initialIndex);
  const currentItem = items[currentIndex];

  // Keyboard navigation
  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      switch (e.key) {
        case "Escape":
          onClose();
          break;
        case "ArrowLeft":
          if (currentIndex > 0) setCurrentIndex(currentIndex - 1);
          break;
        case "ArrowRight":
          if (currentIndex < items.length - 1) setCurrentIndex(currentIndex + 1);
          break;
      }
    };
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [currentIndex, items.length, onClose]);

  const handleBackdropClick = (e: React.MouseEvent) => {
    if (e.target === e.currentTarget) onClose();
  };

  return (
    <div
      className="fixed inset-0 z-50 bg-black/85 flex flex-col animate-fade-in"
      onClick={handleBackdropClick}
    >
      {/* Top bar */}
      <div className="flex items-center justify-between px-4 py-3 text-white/90">
        <div className="flex items-center gap-3 min-w-0">
          <span className="text-sm font-medium truncate">
            {currentItem.fileName || currentItem.type}
          </span>
          {items.length > 1 && (
            <span className="text-xs text-white/50">
              {currentIndex + 1} / {items.length}
            </span>
          )}
        </div>
        <div className="flex items-center gap-1">
          {items.length > 1 && (
            <>
              <button
                className="p-2 rounded-lg hover:bg-white/10 transition-colors"
                onClick={() => setCurrentIndex(Math.max(0, currentIndex - 1))}
                disabled={currentIndex === 0}
              >
                <ChevronLeft size={20} />
              </button>
              <button
                className="p-2 rounded-lg hover:bg-white/10 transition-colors"
                onClick={() => setCurrentIndex(Math.min(items.length - 1, currentIndex + 1))}
                disabled={currentIndex === items.length - 1}
              >
                <ChevronRight size={20} />
              </button>
            </>
          )}
          <button
            className="p-2 rounded-lg hover:bg-white/10 transition-colors ml-2"
            onClick={onClose}
            title="Close (Esc)"
          >
            <X size={20} />
          </button>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 flex items-center justify-center min-h-0 p-4">
        {currentItem.type === "image" && (
          <ImageLightboxContent item={currentItem} />
        )}
        {currentItem.type === "video" && (
          <VideoLightboxContent item={currentItem} />
        )}
        {currentItem.type === "audio" && (
          <AudioLightboxContent item={currentItem} />
        )}
        {currentItem.type === "other" && (
          <OtherLightboxContent item={currentItem} />
        )}
      </div>
    </div>
  );
}

/** useTempFile hook — downloads a blob to a temp file and returns a local URL. */
function useTempFile(item: MediaItem): { url: string | null; loading: boolean; error: string | null } {
  const [url, setUrl] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    setUrl(null);
    setLoading(true);
    setError(null);

    if (item.metadataReady === false) {
      setLoading(false);
      setError("Preparing attachment...");
      return;
    }

    if (!item.reference) {
      setLoading(false);
      setError("No reference to download");
      return;
    }

    (async () => {
      try {
        // Download into the profile-local cache and expose it through Tauri's asset URL.
        const tempPath = await invoke<string>("cache_attachment", {
          conversationId: item.conversationId,
          messageId: item.messageId,
          reference: item.reference,
          fileName: item.fileName,
        });

        if (mountedRef.current) {
          const localUrl = convertFileSrc(tempPath);
          setUrl(localUrl);
        }
      } catch (err) {
        if (mountedRef.current) {
          setError(formatMediaError(err));
        }
      } finally {
        if (mountedRef.current) {
          setLoading(false);
        }
      }
    })();

    return () => {
      mountedRef.current = false;
    };
  }, [
    item.messageId,
    item.conversationId,
    item.reference,
    item.fileName,
    item.metadataReady,
    item.metadataVersion,
  ]);

  return { url, loading, error };
}

function formatMediaError(err: unknown): string {
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
}

/** Image viewer with wheel zoom and pan */
/** Hook to load an image via get_attachment_preview (base64), avoiding download_attachment. */
function useImageBase64(item: MediaItem): { dataUrl: string | null; loading: boolean; error: string | null } {
  const [dataUrl, setDataUrl] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    setDataUrl(null);
    setLoading(true);
    setError(null);

    if (item.metadataReady === false) {
      setLoading(false);
      setError("Preparing attachment...");
      return;
    }

    if (!item.reference) {
      setLoading(false);
      setError("No reference to load");
      return;
    }

    (async () => {
      try {
        const base64 = await invoke<string | null>("get_attachment_preview", {
          conversationId: item.conversationId,
          messageId: item.messageId,
          reference: item.reference,
        });
        if (mountedRef.current && base64) {
          setDataUrl(`data:image/jpeg;base64,${base64}`);
        } else if (mountedRef.current && !base64) {
          setError("Image not available");
        }
      } catch (err) {
        if (mountedRef.current) setError(formatMediaError(err));
      } finally {
        if (mountedRef.current) setLoading(false);
      }
    })();

    return () => { mountedRef.current = false; };
  }, [
    item.messageId,
    item.conversationId,
    item.reference,
    item.mimeType,
    item.metadataReady,
    item.metadataVersion,
  ]);

  return { dataUrl, loading, error };
}

function ImageLightboxContent({ item }: { item: MediaItem }) {
  const [scale, setScale] = useState(1);
  const [position, setPosition] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const containerRef = useRef<HTMLDivElement>(null);

  // Use pre-loaded base64 if available, otherwise fetch via get_attachment_preview
  const fetched = useImageBase64(item);
  const dataUrl = item.base64Data
    ? `data:image/jpeg;base64,${item.base64Data}`
    : fetched.dataUrl;
  const loading = !item.base64Data && fetched.loading;
  const error = item.base64Data ? null : fetched.error;

  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? -0.2 : 0.2;
    setScale(prev => Math.min(5, Math.max(0.5, prev + delta)));
  }, []);

  const handleMouseDown = (e: React.MouseEvent) => {
    if (scale <= 1) return;
    setIsDragging(true);
    setDragStart({ x: e.clientX - position.x, y: e.clientY - position.y });
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isDragging) return;
    setPosition({
      x: e.clientX - dragStart.x,
      y: e.clientY - dragStart.y,
    });
  };

  const handleMouseUp = () => setIsDragging(false);

  const resetZoom = () => {
    setScale(1);
    setPosition({ x: 0, y: 0 });
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center">
        <div className="w-10 h-10 border-2 border-white/30 border-t-white rounded-full animate-spin" />
      </div>
    );
  }

  if (error || !dataUrl) {
    return (
      <div className="text-white/60 text-center">
        <p>Failed to load image</p>
        <p className="text-xs mt-1 text-white/30">{error}</p>
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className="w-full h-full flex items-center justify-center overflow-hidden select-none"
      onWheel={handleWheel}
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      onMouseLeave={handleMouseUp}
      style={{ cursor: scale > 1 ? (isDragging ? "grabbing" : "grab") : "default" }}
    >
      <img
        src={dataUrl}
        alt={item.fileName || "Image"}
        className="max-w-[90vw] max-h-[85vh] object-contain transition-transform duration-100"
        style={{
          transform: `scale(${scale}) translate(${position.x / scale}px, ${position.y / scale}px)`,
        }}
        draggable={false}
      />

      {/* Zoom controls */}
      <div className="absolute bottom-4 left-1/2 -translate-x-1/2 flex items-center gap-2 bg-black/50 rounded-full px-3 py-2">
        <button
          className="p-1.5 rounded-full hover:bg-white/10 transition-colors text-white/80"
          onClick={() => setScale(s => Math.max(0.5, s - 0.5))}
          title="Zoom out"
        >
          <ZoomOut size={16} />
        </button>
        <button
          className="p-1.5 rounded-full hover:bg-white/10 transition-colors text-white/80"
          onClick={resetZoom}
          title="Reset zoom"
        >
          <RotateCcw size={16} />
        </button>
        <button
          className="p-1.5 rounded-full hover:bg-white/10 transition-colors text-white/80"
          onClick={() => setScale(s => Math.min(5, s + 0.5))}
          title="Zoom in"
        >
          <ZoomIn size={16} />
        </button>
      </div>
    </div>
  );
}

/** Video player */
function VideoLightboxContent({ item }: { item: MediaItem }) {
  const { url, loading, error } = useTempFile(item);
  const [poster, setPoster] = useState<string | null>(null);
  const videoRef = useRef<HTMLVideoElement>(null);

  // Generate thumbnail poster via canvas
  useEffect(() => {
    if (!url) return;
    const video = document.createElement("video");
    video.crossOrigin = "anonymous";
    video.preload = "metadata";
    video.muted = true;
    video.src = url;

    const onLoaded = () => {
      video.currentTime = 1;
    };
    const onSeeked = () => {
      try {
        const canvas = document.createElement("canvas");
        canvas.width = video.videoWidth || 320;
        canvas.height = video.videoHeight || 180;
        const ctx = canvas.getContext("2d");
        if (ctx) {
          ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
          setPoster(canvas.toDataURL("image/jpeg", 0.7));
        }
      } catch {
        // ignore capture errors
      }
      video.remove();
    };

    video.addEventListener("loadeddata", onLoaded);
    video.addEventListener("seeked", onSeeked);
    video.addEventListener("error", () => video.remove());

    return () => {
      video.removeEventListener("loadeddata", onLoaded);
      video.removeEventListener("seeked", onSeeked);
      video.remove();
    };
  }, [url]);

  if (loading) {
    return (
      <div className="flex items-center justify-center">
        <div className="w-10 h-10 border-2 border-white/30 border-t-white rounded-full animate-spin" />
      </div>
    );
  }

  if (error || !url) {
    return (
      <div className="text-white/60 text-center">
        <p>Failed to load video</p>
        <p className="text-xs mt-1 text-white/30">{error}</p>
      </div>
    );
  }

  return (
    <video
      ref={videoRef}
      src={url}
      poster={poster ?? undefined}
      controls
      autoPlay
      className="max-w-[90vw] max-h-[85vh] rounded-lg shadow-2xl"
    >
      Your browser does not support video playback.
    </video>
  );
}

/** Custom audio player */
function AudioLightboxContent({ item }: { item: MediaItem }) {
  const { url, loading, error } = useTempFile(item);
  const audioRef = useRef<HTMLAudioElement>(null);
  const [playing, setPlaying] = useState(false);
  const [currentTime, setCurrentTime] = useState(0);
  const [duration, setDuration] = useState(0);

  useEffect(() => {
    const audio = audioRef.current;
    if (!audio) return;

    const onTime = () => setCurrentTime(audio.currentTime);
    const onDuration = () => setDuration(audio.duration);
    const onEnded = () => setPlaying(false);
    const onPlay = () => setPlaying(true);
    const onPause = () => setPlaying(false);

    audio.addEventListener("timeupdate", onTime);
    audio.addEventListener("loadedmetadata", onDuration);
    audio.addEventListener("ended", onEnded);
    audio.addEventListener("play", onPlay);
    audio.addEventListener("pause", onPause);

    return () => {
      audio.removeEventListener("timeupdate", onTime);
      audio.removeEventListener("loadedmetadata", onDuration);
      audio.removeEventListener("ended", onEnded);
      audio.removeEventListener("play", onPlay);
      audio.removeEventListener("pause", onPause);
    };
  }, [url]);

  const togglePlay = () => {
    const audio = audioRef.current;
    if (!audio) return;
    if (audio.paused) {
      audio.play().catch(() => {});
    } else {
      audio.pause();
    }
  };

  const handleSeek = (e: React.MouseEvent<HTMLDivElement>) => {
    const audio = audioRef.current;
    if (!audio || !duration) return;
    const rect = e.currentTarget.getBoundingClientRect();
    const ratio = (e.clientX - rect.left) / rect.width;
    audio.currentTime = ratio * duration;
  };

  const formatTime = (t: number) => {
    const m = Math.floor(t / 60);
    const s = Math.floor(t % 60);
    return `${m}:${s.toString().padStart(2, "0")}`;
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center">
        <div className="w-10 h-10 border-2 border-white/30 border-t-white rounded-full animate-spin" />
      </div>
    );
  }

  if (error || !url) {
    return (
      <div className="text-white/60 text-center">
        <p>Failed to load audio</p>
        <p className="text-xs mt-1 text-white/30">{error}</p>
      </div>
    );
  }

  return (
    <div className="bg-white/10 backdrop-blur rounded-2xl p-6 w-80 shadow-2xl">
      <audio ref={audioRef} src={url} preload="auto" />

      {/* File name */}
      <p className="text-white/90 text-sm font-medium text-center truncate mb-4">
        {item.fileName || "Audio"}
      </p>

      {/* Play/Pause button */}
      <div className="flex items-center justify-center mb-4">
        <button
          className="w-14 h-14 rounded-full bg-white/20 hover:bg-white/30 transition-colors flex items-center justify-center"
          onClick={togglePlay}
        >
          {playing ? (
            <Pause size={28} className="text-white" />
          ) : (
            <Play size={28} className="text-white ml-1" />
          )}
        </button>
      </div>

      {/* Progress bar */}
      <div
        className="w-full h-1.5 bg-white/20 rounded-full cursor-pointer mb-2"
        onClick={handleSeek}
      >
        <div
          className="h-full bg-white rounded-full transition-all duration-100"
          style={{ width: `${duration > 0 ? (currentTime / duration) * 100 : 0}%` }}
        />
      </div>

      {/* Time display */}
      <div className="flex items-center justify-between text-xs text-white/60">
        <span>{formatTime(currentTime)}</span>
        <span>{formatTime(duration)}</span>
      </div>
    </div>
  );
}

/** Fallback for non-media files */
function OtherLightboxContent({ item }: { item: MediaItem }) {
  return (
    <div className="bg-white/10 backdrop-blur rounded-xl p-8 text-center max-w-sm">
      <Download size={40} className="text-white/40 mx-auto mb-3" />
      <p className="text-white/90 font-medium mb-1">
        {item.fileName || "File"}
      </p>
      <p className="text-white/50 text-sm mb-4">
        This file type cannot be previewed
      </p>
      <button
        className="px-4 py-2 bg-white/20 hover:bg-white/30 text-white rounded-lg transition-colors text-sm"
        onClick={() => {
          // Trigger download through the normal invoke flow
          invoke("download_attachment", {
            conversationId: item.conversationId,
            messageId: item.messageId,
            reference: item.reference,
            destination: "", // Will prompt via save dialog — handled differently
          }).catch(console.error);
        }}
      >
        Download File
      </button>
    </div>
  );
}

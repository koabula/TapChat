import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { decode } from "blurhash";
import { Image } from "lucide-react";

export interface ImageGridItem {
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

interface OpenMediaResult { handle: string; url: string; expires_at: number }

export default function ImageGrid({ items, onImageClick }: {
  items: ImageGridItem[];
  onImageClick: (index: number) => void;
}) {
  const count = items.length;
  // Every child is position-driven while its media is loading, so max-width
  // alone has no intrinsic size and can collapse to 0px inside the chat flex
  // row. Give the grid a real responsive inline size up front.
  const gridClass = count === 1
    ? "grid w-[min(22rem,72vw)] max-w-full grid-cols-1"
    : count <= 4
      ? "grid w-[min(24rem,72vw)] max-w-full grid-cols-2 gap-1"
      : "grid w-[min(28rem,72vw)] max-w-full grid-cols-3 gap-1";
  return <div className={gridClass}>{items.map((item, index) =>
    <ImageCell key={item.messageId} item={item} large={count >= 5 && index === 0} onClick={() => onImageClick(index)} />
  )}</div>;
}

function ImageCell({ item, large, onClick }: { item: ImageGridItem; large: boolean; onClick: () => void }) {
  const root = useRef<HTMLButtonElement>(null);
  const [visible, setVisible] = useState(false);
  const [media, setMedia] = useState<OpenMediaResult | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    const target = root.current;
    if (!target) return;
    const observer = new IntersectionObserver(([entry]) => entry.isIntersecting && setVisible(true), { rootMargin: "300px" });
    observer.observe(target);
    return () => observer.disconnect();
  }, []);
  useEffect(() => {
    if (!visible || !item.previewAvailable) return;
    let cancelled = false;
    let handle: string | null = null;
    void invoke<OpenMediaResult>("open_media", { conversationId: item.conversationId, messageId: item.messageId, variant: "preview" })
      .then((opened) => {
        handle = opened.handle;
        if (cancelled) void invoke("release_media", { handle });
        else setMedia(opened);
      })
      .catch(() => !cancelled && setFailed(true));
    return () => { cancelled = true; if (handle) void invoke("release_media", { handle }); };
  }, [item.conversationId, item.messageId, item.previewAvailable, visible]);
  const sourceRatio = item.width && item.height ? item.width / item.height : 4 / 3;
  const aspectRatio = Math.min(1.8, Math.max(0.65, sourceRatio));
  return <button
    ref={root}
    type="button"
    className={`relative min-h-24 w-full min-w-0 overflow-hidden rounded-xl bg-surface-elevated ${large ? "col-span-2 row-span-2" : ""}`}
    style={{ aspectRatio }}
    onClick={onClick}
  >
    {item.blurHash && !media && <BlurHashCanvas hash={item.blurHash} />}
    {media && <img src={media.url} alt={item.fileName || "Image"} className="h-full w-full object-cover transition-transform duration-200 hover:scale-[1.02]" onError={() => setFailed(true)} />}
    {!item.blurHash && !media && <div className="absolute inset-0 flex flex-col items-center justify-center gap-1 text-muted-color"><Image size={24} /><span className="text-[10px]">Image</span></div>}
    {failed && <div className="pointer-events-none absolute inset-0 z-10 flex flex-col items-center justify-center gap-1 bg-black/45 px-3 text-center text-white"><Image size={24} /><span className="text-xs font-medium">Preview unavailable</span><span className="text-[10px] text-white/70">Open image to retry</span></div>}
    {item.attachmentState === "pending" && <span className="absolute bottom-1.5 left-1.5 rounded-full bg-black/55 px-2 py-0.5 text-[10px] text-white/85">{item.uploadState === "failed" ? "Upload failed" : "Uploading"}</span>}
    <span className="absolute inset-0 bg-black/0 transition-colors hover:bg-black/15" />
  </button>;
}

function BlurHashCanvas({ hash }: { hash: string }) {
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
    } catch { /* invalid placeholders fall back to the icon */ }
  }, [hash]);
  return <canvas ref={canvas} width={32} height={24} className="absolute inset-0 h-full w-full scale-105 blur-md" aria-hidden="true" />;
}

import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Image } from "lucide-react";

export interface ImageGridItem {
  messageId: string;
  conversationId: string;
  reference: string;
  mimeType: string;
  fileName?: string;
  sizeBytes?: number;
  metadataReady?: boolean;
  metadataVersion?: string;
}

interface ImageGridProps {
  items: ImageGridItem[];
  autoDownloadMedia: boolean;
  onImageClick: (index: number) => void;
}

/** Grid layout for multiple image attachments. */
export default function ImageGrid({ items, autoDownloadMedia, onImageClick }: ImageGridProps) {
  const count = items.length;
  const gridClass = getGridClass(count);

  return (
    <div className={gridClass}>
      {items.map((item, index) => (
        <ImageGridCell
          key={`${item.messageId}-${index}`}
          item={item}
          index={index}
          isLarge={count >= 5 && index === 0}
          autoDownload={autoDownloadMedia && (item.sizeBytes ?? 0) <= 10 * 1024 * 1024}
          onClick={() => {
            if (item.metadataReady !== false) onImageClick(index);
          }}
        />
      ))}
    </div>
  );
}

function getGridClass(count: number): string {
  if (count === 1) return "grid grid-cols-1 max-w-[22rem]";
  if (count === 2) return "grid grid-cols-2 gap-1 max-w-[24rem]";
  if (count === 3) return "grid grid-cols-2 gap-1 max-w-[24rem]";
  if (count === 4) return "grid grid-cols-2 gap-1 max-w-[24rem]";
  return "grid grid-cols-3 gap-1 max-w-[28rem]";
}

interface ImageGridCellProps {
  item: ImageGridItem;
  index: number;
  isLarge: boolean;
  autoDownload: boolean;
  onClick: () => void;
}

function ImageGridCell({ item, index, isLarge, autoDownload, onClick }: ImageGridCellProps) {
  const [imageData, setImageData] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [failed, setFailed] = useState(false);
  const [deferred, setDeferred] = useState(false);
  const requestVersionRef = useRef(0);

  const loadThumbnail = useCallback(async () => {
    const requestVersion = ++requestVersionRef.current;
    if (item.metadataReady === false || !item.reference) {
      setFailed(Boolean(item.metadataReady !== false));
      return;
    }
    setDeferred(false);
    setLoading(true);
    setFailed(false);
    try {
      const result = await invoke<string | null>("get_attachment_preview", {
        conversationId: item.conversationId,
        messageId: item.messageId,
        reference: item.reference,
      });
      if (requestVersionRef.current !== requestVersion) return;
      if (result) {
        setImageData(result);
      } else {
        setFailed(true);
      }
    } catch {
      if (requestVersionRef.current === requestVersion) setFailed(true);
    } finally {
      if (requestVersionRef.current === requestVersion) setLoading(false);
    }
  }, [item.conversationId, item.messageId, item.metadataReady, item.reference]);

  useEffect(() => {
    requestVersionRef.current += 1;
    setImageData(null);
    setFailed(false);
    setDeferred(false);
    if (item.metadataReady === false) {
      setLoading(false);
      return () => {
        requestVersionRef.current += 1;
      };
    }
    if (autoDownload) {
      void loadThumbnail();
    } else {
      setLoading(false);
      setDeferred(true);
    }

    return () => {
      requestVersionRef.current += 1;
    };
  }, [item.reference, item.metadataReady, item.metadataVersion, autoDownload, loadThumbnail]);

  const cellClass = isLarge
    ? "col-span-2 row-span-2"
    : "";

  return (
    <div
      className={`relative cursor-pointer overflow-hidden rounded-md bg-surface-elevated ${cellClass}`}
      style={{ aspectRatio: item.mimeType.startsWith("image/") && !isLarge ? "1" : "4 / 3" }}
      onClick={() => {
        if (imageData) {
          onClick();
        } else if (!loading && item.metadataReady !== false) {
          void loadThumbnail();
        }
      }}
    >
      {loading && (
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
        </div>
      )}

      {imageData && (
        <img
          src={`data:image/jpeg;base64,${imageData}`}
          alt={item.fileName || `Image ${index + 1}`}
          className="w-full h-full object-cover transition-transform duration-200 hover:scale-[1.02]"
          onError={() => setFailed(true)}
        />
      )}

      {item.metadataReady === false && !loading && (
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-1 text-muted-color">
          <Image size={24} />
          <span className="text-[10px]">Preparing...</span>
        </div>
      )}

      {deferred && !loading && (
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-1 text-muted-color">
          <Image size={24} />
          <span className="text-[10px]">Click to load</span>
        </div>
      )}

      {failed && !loading && item.metadataReady !== false && (
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-1 text-muted-color">
          <Image size={24} />
          <span className="text-[10px]">No preview</span>
        </div>
      )}

      {/* Hover overlay */}
      <div className="absolute inset-0 rounded-md bg-black/0 transition-colors hover:bg-black/15" />
    </div>
  );
}

import { useState, useEffect, useRef } from "react";
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
  onImageClick: (index: number) => void;
}

/** Grid layout for multiple image attachments. */
export default function ImageGrid({ items, onImageClick }: ImageGridProps) {
  // Determine grid layout based on count
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
          onClick={() => {
            if (item.metadataReady !== false) onImageClick(index);
          }}
        />
      ))}
    </div>
  );
}

function getGridClass(count: number): string {
  if (count === 1) return "grid grid-cols-1 max-w-[70%]";
  if (count === 2) return "grid grid-cols-2 gap-1 max-w-[70%]";
  if (count === 3) return "grid grid-cols-2 gap-1 max-w-[70%]";
  if (count === 4) return "grid grid-cols-2 gap-1 max-w-[70%]";
  return "grid grid-cols-3 gap-1 max-w-[85%]"; // 5+
}

interface ImageGridCellProps {
  item: ImageGridItem;
  index: number;
  isLarge: boolean;
  onClick: () => void;
}

function ImageGridCell({ item, index, isLarge, onClick }: ImageGridCellProps) {
  const [imageData, setImageData] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [failed, setFailed] = useState(false);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    setImageData(null);
    setFailed(false);
    if (item.metadataReady === false) {
      setLoading(false);
      return () => {
        mountedRef.current = false;
      };
    }
    loadThumbnail();

    return () => {
      mountedRef.current = false;
    };
  }, [item.reference, item.metadataReady, item.metadataVersion]);

  const loadThumbnail = async () => {
    if (item.metadataReady === false) {
      setFailed(false);
      return;
    }
    if (!item.reference) {
      setFailed(true);
      return;
    }
    setLoading(true);
    setFailed(false);
    try {
      const result = await invoke<string | null>("get_attachment_preview", {
        conversationId: item.conversationId,
        messageId: item.messageId,
        reference: item.reference,
      });
      if (mountedRef.current && result) {
        setImageData(result);
      } else if (mountedRef.current && !result) {
        setFailed(true);
      }
    } catch {
      if (mountedRef.current) setFailed(true);
    } finally {
      if (mountedRef.current) setLoading(false);
    }
  };

  const cellClass = isLarge
    ? "col-span-2 row-span-2"
    : "";

  return (
    <div
      className={`relative cursor-pointer overflow-hidden rounded-lg bg-surface-elevated ${cellClass}`}
      style={{ aspectRatio: "1" }}
      onClick={onClick}
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
          className="w-full h-full object-cover hover:scale-105 transition-transform duration-200"
          onError={() => setFailed(true)}
        />
      )}

      {item.metadataReady === false && !loading && (
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-1 text-muted-color">
          <Image size={24} />
          <span className="text-[10px]">Preparing...</span>
        </div>
      )}

      {failed && !loading && item.metadataReady !== false && (
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-1 text-muted-color">
          <Image size={24} />
          <span className="text-[10px]">No preview</span>
        </div>
      )}

      {/* Hover overlay */}
      <div className="absolute inset-0 bg-black/0 hover:bg-black/20 transition-colors rounded-lg" />
    </div>
  );
}

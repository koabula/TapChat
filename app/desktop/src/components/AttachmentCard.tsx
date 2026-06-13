import type { ReactNode } from "react";

export interface AttachmentCardProps {
  icon: ReactNode;
  name: string;
  typeLabel: string;
  sizeStr: string | null;
  downloaded: boolean;
  downloading: boolean;
  error: string | null;
  onDownload: () => void;
  onOpen: () => void;
  onClickPreview?: () => void;
}

/** Single file attachment card with icon, name, type, size, and action button. */
export default function AttachmentCard({
  icon,
  name,
  typeLabel,
  sizeStr,
  downloaded,
  downloading,
  error,
  onDownload,
  onOpen,
  onClickPreview,
}: AttachmentCardProps) {
  const handleClick = () => {
    if (onClickPreview) {
      onClickPreview();
    } else if (downloaded) {
      onOpen();
    } else {
      onDownload();
    }
  };

  return (
    <div
      className={`flex items-center gap-2.5 rounded-md border border-subtle bg-surface/30 px-3 py-2 transition-colors hover:border-default hover:bg-surface/60 group/file ${
        onClickPreview ? "cursor-pointer" : ""
      }`}
      onClick={onClickPreview ? handleClick : undefined}
    >
      {/* Icon */}
      <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-md bg-surface-elevated">
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
      {!onClickPreview && (
        downloaded ? (
          <button
            className="text-xs text-primary hover:underline flex-shrink-0 transition-colors"
            onClick={(e) => { e.stopPropagation(); onOpen(); }}
          >
            Open
          </button>
        ) : (
          <button
            className="text-xs text-primary hover:underline flex-shrink-0 transition-colors disabled:opacity-50"
            onClick={(e) => { e.stopPropagation(); onDownload(); }}
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
        )
      )}

      {/* Error */}
      {error && (
        <span className="text-xs text-error flex-shrink-0">{error}</span>
      )}
    </div>
  );
}

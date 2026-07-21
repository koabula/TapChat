import { useEffect, useRef } from "react";
import { ChevronDown, ChevronUp, Search, X } from "lucide-react";

interface ChatSearchBarProps {
  query: string;
  currentIndex: number;
  resultCount: number;
  onQueryChange: (query: string) => void;
  onPrevious: () => void;
  onNext: () => void;
  onClose: () => void;
}

export default function ChatSearchBar({
  query,
  currentIndex,
  resultCount,
  onQueryChange,
  onPrevious,
  onNext,
  onClose,
}: ChatSearchBarProps) {
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const resultLabel = query.trim()
    ? resultCount > 0
      ? `${Math.max(currentIndex, 0) + 1} / ${resultCount}`
      : "No results"
    : "Type to search";

  return (
    <div className="flex items-center gap-2 border-b border-subtle bg-surface px-4 py-2">
      <Search size={16} className="shrink-0 text-muted-color" aria-hidden="true" />
      <input
        ref={inputRef}
        className="input h-9 min-w-0 flex-1"
        type="search"
        value={query}
        placeholder="Search this conversation"
        aria-label="Search messages"
        onChange={(event) => onQueryChange(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === "Enter") {
            event.preventDefault();
            if (event.shiftKey) onPrevious();
            else onNext();
          }
          if (event.key === "Escape") {
            event.preventDefault();
            onClose();
          }
        }}
      />
      <span className="w-24 text-right text-xs text-muted-color" aria-live="polite">
        {resultLabel}
      </span>
      <button
        type="button"
        className="btn btn-ghost px-2"
        aria-label="Previous search result"
        disabled={resultCount === 0}
        onClick={onPrevious}
      >
        <ChevronUp size={17} aria-hidden="true" />
      </button>
      <button
        type="button"
        className="btn btn-ghost px-2"
        aria-label="Next search result"
        disabled={resultCount === 0}
        onClick={onNext}
      >
        <ChevronDown size={17} aria-hidden="true" />
      </button>
      <button
        type="button"
        className="btn btn-ghost px-2"
        aria-label="Close message search"
        onClick={onClose}
      >
        <X size={17} aria-hidden="true" />
      </button>
    </div>
  );
}

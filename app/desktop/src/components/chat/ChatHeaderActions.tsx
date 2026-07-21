import { useCallback, useEffect, useRef, useState } from "react";
import { EllipsisVertical, Search } from "lucide-react";

import {
  chatHeaderActionErrorStatus,
  chatHeaderActions,
  type ChatHeaderActionId,
  type ChatHeaderActionStatus,
} from "@/lib/chatHeaderActions";

interface ChatHeaderActionsProps {
  isGroup: boolean;
  searchOpen: boolean;
  syncBusy: boolean;
  onToggleSearch: () => void;
  onOpenContactDetails: () => void;
  onRefreshContact: () => Promise<void>;
  onOpenMembers: () => void;
  onSyncGroup: () => Promise<boolean>;
}

export default function ChatHeaderActions({
  isGroup,
  searchOpen,
  syncBusy,
  onToggleSearch,
  onOpenContactDetails,
  onRefreshContact,
  onOpenMembers,
  onSyncGroup,
}: ChatHeaderActionsProps) {
  const [menuOpen, setMenuOpen] = useState(false);
  const [actionBusy, setActionBusy] = useState<ChatHeaderActionId | null>(null);
  const [status, setStatus] = useState<ChatHeaderActionStatus | null>(null);
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);

  const closeMenu = useCallback((restoreFocus = false) => {
    setMenuOpen(false);
    if (restoreFocus) {
      requestAnimationFrame(() => triggerRef.current?.focus());
    }
  }, []);

  useEffect(() => {
    if (!menuOpen) return;

    const onPointerDown = (event: PointerEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) closeMenu(true);
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        closeMenu(true);
      }
    };

    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [closeMenu, menuOpen]);

  useEffect(() => {
    setMenuOpen(false);
    setStatus(null);
  }, [isGroup]);

  const runAction = async (action: ChatHeaderActionId) => {
    setStatus(null);
    if (action === "contact_details") {
      closeMenu(false);
      onOpenContactDetails();
      return;
    }
    if (action === "group_members") {
      closeMenu(false);
      onOpenMembers();
      return;
    }

    setActionBusy(action);
    try {
      if (action === "refresh_contact") {
        await onRefreshContact();
        setStatus({ kind: "success", text: "Contact refreshed" });
      } else {
        const succeeded = await onSyncGroup();
        if (!succeeded) throw new Error("Group sync failed");
        setStatus({ kind: "success", text: "Group synced" });
      }
    } catch (error) {
      setStatus(chatHeaderActionErrorStatus(error));
    } finally {
      setActionBusy(null);
    }
  };

  return (
    <div className="relative flex items-center gap-2" ref={rootRef}>
      {!isGroup && (
        <button
          type="button"
          className="btn btn-ghost px-2 transition-fast"
          aria-label={searchOpen ? "Close message search" : "Search messages"}
          aria-pressed={searchOpen}
          onClick={onToggleSearch}
        >
          <Search size={18} aria-hidden="true" />
        </button>
      )}
      <button
        ref={triggerRef}
        type="button"
        className="btn btn-ghost px-2 transition-fast"
        aria-label="More conversation options"
        aria-haspopup="menu"
        aria-expanded={menuOpen}
        onClick={() => {
          setMenuOpen((open) => !open);
          setStatus(null);
        }}
      >
        <EllipsisVertical size={18} aria-hidden="true" />
      </button>
      {menuOpen && (
        <div
          className="absolute right-0 top-11 z-40 min-w-52 rounded-lg border border-default bg-surface-elevated p-1 shadow-xl"
          role="menu"
          aria-label="Conversation options"
        >
          {chatHeaderActions(isGroup).map((action) => (
            <button
              key={action.id}
              type="button"
              className="flex w-full items-center rounded-md px-3 py-2 text-left text-sm text-primary-color hover:bg-surface disabled:opacity-60"
              role="menuitem"
              disabled={actionBusy !== null || (action.id === "sync_group" && syncBusy)}
              onClick={() => void runAction(action.id)}
            >
              {actionBusy === action.id ? `${action.busyLabel}...` : action.label}
            </button>
          ))}
          {status && (
            <div
              className={`border-t border-subtle px-3 py-2 text-xs ${
                status.kind === "success" ? "status-success" : "text-error"
              }`}
              role={status.kind === "error" ? "alert" : "status"}
            >
              {status.text}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

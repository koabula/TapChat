import { useEffect } from "react";
import { useNavigate } from "react-router";

interface KeyboardShortcut {
  key: string;
  ctrl?: boolean;
  shift?: boolean;
  alt?: boolean;
  action: () => void;
  description: string;
}

/**
 * Global keyboard shortcuts hook.
 * Register shortcuts that work across the app.
 */
export function useKeyboardShortcuts(shortcuts: KeyboardShortcut[]) {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Ignore if user is typing in an input field
      const target = e.target as HTMLElement;
      if (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable) {
        // Allow specific shortcuts even in input fields (like Escape)
        if (e.key !== "Escape") {
          return;
        }
      }

      for (const shortcut of shortcuts) {
        const ctrlMatch = shortcut.ctrl ? (e.ctrlKey || e.metaKey) : !(e.ctrlKey || e.metaKey);
        const shiftMatch = shortcut.shift ? e.shiftKey : !e.shiftKey;
        const altMatch = shortcut.alt ? e.altKey : !e.altKey;
        const keyMatch = e.key.toLowerCase() === shortcut.key.toLowerCase();

        if (ctrlMatch && shiftMatch && altMatch && keyMatch) {
          e.preventDefault();
          shortcut.action();
          return;
        }
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [shortcuts]);
}

/**
 * Default global shortcuts for TapChat.
 */
export function useGlobalShortcuts() {
  const navigate = useNavigate();

  useKeyboardShortcuts([
    {
      key: "n",
      ctrl: true,
      action: () => navigate("/contacts"),
      description: "New conversation",
    },
    {
      key: "s",
      ctrl: true,
      action: () => navigate("/settings"),
      description: "Open settings",
    },
    {
      key: "r",
      ctrl: true,
      action: () => navigate("/requests"),
      description: "Message requests",
    },
    {
      key: "Escape",
      action: () => navigate("/"),
      description: "Go back to main view",
    },
    {
      key: "1",
      ctrl: true,
      action: () => navigate("/"),
      description: "Go to conversations",
    },
    {
      key: "2",
      ctrl: true,
      action: () => navigate("/contacts"),
      description: "Go to contacts",
    },
    {
      key: "3",
      ctrl: true,
      action: () => navigate("/requests"),
      description: "Go to requests",
    },
    {
      key: "4",
      ctrl: true,
      action: () => navigate("/settings"),
      description: "Go to settings",
    },
  ]);
}

/**
 * Shortcuts specific to the chat view.
 */
export function useChatShortcuts(
  _conversationId: string | null,
  onSend: () => void,
  onFocusInput: () => void
) {
  useKeyboardShortcuts([
    {
      key: "Enter",
      ctrl: true,
      action: () => onSend(),
      description: "Send message",
    },
    {
      key: "i",
      ctrl: true,
      action: () => onFocusInput(),
      description: "Focus input",
    },
  ]);
}
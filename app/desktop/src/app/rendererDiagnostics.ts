import { getCurrentWindow } from "@tauri-apps/api/window";
import { desktopDebugLog } from "../lib/commands";

type RendererSnapshot = {
  windowLabel?: string;
  activeSection?: string;
  activeProfilePath?: string | null;
  selectedContactUserId?: string | null;
  selectedConversationId?: string | null;
};

declare global {
  interface Window {
    __tapchatRendererSnapshot?: RendererSnapshot;
    __tapchatRendererHandlersInstalled?: boolean;
  }
}

function currentWindowLabel() {
  try {
    return getCurrentWindow().label;
  } catch {
    return "unknown";
  }
}

function snapshotSuffix() {
  const snapshot = window.__tapchatRendererSnapshot;
  if (!snapshot) {
    return "";
  }
  return [
    snapshot.activeSection ? `section=${snapshot.activeSection}` : null,
    snapshot.activeProfilePath ? `profile=${snapshot.activeProfilePath}` : null,
    snapshot.selectedContactUserId ? `contact=${snapshot.selectedContactUserId}` : null,
    snapshot.selectedConversationId ? `conversation=${snapshot.selectedConversationId}` : null,
  ]
    .filter(Boolean)
    .join(" ");
}

export function updateRendererSnapshot(snapshot: RendererSnapshot) {
  window.__tapchatRendererSnapshot = snapshot;
}

export function logRendererCrash(kind: string, message: string) {
  const suffix = snapshotSuffix();
  const fullMessage = suffix ? `${message} ${suffix}` : message;
  return desktopDebugLog("renderer", `${kind}: ${fullMessage}`, currentWindowLabel(), window.__tapchatRendererSnapshot?.activeProfilePath ?? null)
    .catch(() => null);
}

export function installRendererCrashHandlers() {
  if (window.__tapchatRendererHandlersInstalled) {
    return;
  }
  window.__tapchatRendererHandlersInstalled = true;
  window.addEventListener("error", (event) => {
    const stack = event.error instanceof Error && event.error.stack ? ` stack=${event.error.stack}` : "";
    void logRendererCrash("window.error", `${event.message}${stack}`);
  });
  window.addEventListener("unhandledrejection", (event) => {
    const reason = event.reason instanceof Error
      ? `${event.reason.message} stack=${event.reason.stack ?? ""}`
      : String(event.reason);
    void logRendererCrash("unhandledrejection", reason);
  });
}

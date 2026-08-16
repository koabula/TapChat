import { normalizeAppError, presentError } from "@/lib/errors";
import { invokeApp as invoke } from "./tauri";
import { save } from "@tauri-apps/plugin-dialog";

export interface AttachmentDownloadRequest {
  conversationId: string;
  messageId: string;
  reference: string;
  fileName?: string;
  mimeType: string;
}

export type AttachmentDownloadResult =
  | { status: "cancelled"; path: null }
  | { status: "downloaded"; path: string };

export interface AttachmentDownloadDependencies {
  invokeCommand: <T>(command: string, args?: Record<string, unknown>) => Promise<T>;
  saveDialog: (options: { title: string; defaultPath: string }) => Promise<string | null>;
}

const DEFAULT_DEPENDENCIES: AttachmentDownloadDependencies = {
  invokeCommand: (command, args) => invoke(command, args),
  saveDialog: (options) => save(options),
};

const MIME_EXTENSIONS: Record<string, string> = {
  "image/jpeg": ".jpg",
  "image/png": ".png",
  "image/gif": ".gif",
  "image/webp": ".webp",
  "application/pdf": ".pdf",
  "audio/mpeg": ".mp3",
  "audio/wav": ".wav",
  "video/mp4": ".mp4",
  "application/zip": ".zip",
  "text/plain": ".txt",
};

export function attachmentDefaultFileName(fileName: string | undefined, mimeType: string): string {
  return fileName?.trim() || `attachment${MIME_EXTENSIONS[mimeType] ?? ""}`;
}

export function formatAttachmentDownloadError(error: unknown): string {
  const code = normalizeAppError(error).code;
  if (code === "capability_expired" || code === "invalid_capability") {
    return "Attachment link expired";
  }
  return presentError(error).message;
}

function isAbsoluteDestination(path: string): boolean {
  return path.startsWith("/") || path.startsWith("\\\\") || /^[A-Za-z]:[\\/]/.test(path);
}

export async function downloadAttachmentWithSettings(
  request: AttachmentDownloadRequest,
  dependencies: AttachmentDownloadDependencies = DEFAULT_DEPENDENCIES,
): Promise<AttachmentDownloadResult> {
  const defaultFileName = attachmentDefaultFileName(request.fileName, request.mimeType);
  const settings = await dependencies.invokeCommand<{ always_ask_save_path: boolean }>(
    "get_attachment_settings",
  );

  if (settings.always_ask_save_path) {
    const destination = await dependencies.saveDialog({
      title: "Save attachment",
      defaultPath: defaultFileName,
    });
    if (!destination?.trim()) return { status: "cancelled", path: null };
    if (!isAbsoluteDestination(destination)) {
      throw new Error("Save dialog returned a non-absolute destination path");
    }

    await dependencies.invokeCommand("download_attachment", {
      conversationId: request.conversationId,
      messageId: request.messageId,
      reference: request.reference,
      destination,
    });
    return { status: "downloaded", path: destination };
  }

  const path = await dependencies.invokeCommand<string>(
    "download_attachment_to_default_path",
    {
      conversationId: request.conversationId,
      messageId: request.messageId,
      reference: request.reference,
      fileName: defaultFileName,
      mimeType: request.mimeType,
    },
  );
  if (!path?.trim()) throw new Error("Download completed without a destination path");
  return { status: "downloaded", path };
}

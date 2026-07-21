import { describe, expect, it, vi } from "vitest";

import {
  downloadAttachmentWithSettings,
  type AttachmentDownloadDependencies,
} from "@/lib/attachmentDownload";

const request = {
  conversationId: "conversation-a",
  messageId: "message-a",
  reference: "blob-a",
  fileName: "notes.txt",
  mimeType: "text/plain",
};

function dependencies(alwaysAsk: boolean, savePath: string | null) {
  const invokeCommand = vi.fn(async (command: string) => {
    if (command === "get_attachment_settings") return { always_ask_save_path: alwaysAsk };
    if (command === "download_attachment_to_default_path") return "C:\\Downloads\\notes.txt";
    return undefined;
  });
  const saveDialog = vi.fn(async () => savePath);
  return { invokeCommand, saveDialog } as unknown as AttachmentDownloadDependencies & {
    invokeCommand: ReturnType<typeof vi.fn>;
    saveDialog: ReturnType<typeof vi.fn>;
  };
}

describe("attachment download path selection", () => {
  it("does not invoke a download when save is cancelled", async () => {
    const deps = dependencies(true, null);
    await expect(downloadAttachmentWithSettings(request, deps)).resolves.toEqual({
      status: "cancelled",
      path: null,
    });
    expect(deps.invokeCommand).toHaveBeenCalledTimes(1);
  });

  it("never forwards an empty destination", async () => {
    const deps = dependencies(true, "   ");
    await downloadAttachmentWithSettings(request, deps);
    expect(deps.invokeCommand).toHaveBeenCalledTimes(1);
  });

  it("downloads to the selected absolute path", async () => {
    const deps = dependencies(true, "C:\\Selected\\notes.txt");
    await downloadAttachmentWithSettings(request, deps);
    expect(deps.invokeCommand).toHaveBeenLastCalledWith("download_attachment", {
      conversationId: "conversation-a",
      messageId: "message-a",
      reference: "blob-a",
      destination: "C:\\Selected\\notes.txt",
    });
  });

  it("rejects a relative save path without invoking download", async () => {
    const deps = dependencies(true, "relative/notes.txt");
    await expect(downloadAttachmentWithSettings(request, deps)).rejects.toThrow("non-absolute");
    expect(deps.invokeCommand).toHaveBeenCalledTimes(1);
  });

  it("uses the backend default-path command when prompting is disabled", async () => {
    const deps = dependencies(false, null);
    await expect(downloadAttachmentWithSettings(request, deps)).resolves.toEqual({
      status: "downloaded",
      path: "C:\\Downloads\\notes.txt",
    });
    expect(deps.saveDialog).not.toHaveBeenCalled();
    expect(deps.invokeCommand).toHaveBeenLastCalledWith(
      "download_attachment_to_default_path",
      expect.objectContaining({ fileName: "notes.txt", mimeType: "text/plain" }),
    );
  });
});

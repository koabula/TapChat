import { beforeEach, describe, expect, it } from "vitest";

import {
  attachmentDownloadKey,
  useAttachmentDownloadSession,
} from "../attachmentDownloads";

describe("attachment download session map", () => {
  beforeEach(() => {
    useAttachmentDownloadSession.setState({ paths: {} });
  });

  it("reuses one saved path per attachment and forgets missing files", () => {
    const key = attachmentDownloadKey("conversation:1", "message:1", "original");
    useAttachmentDownloadSession.getState().remember(key, "C:\\Downloads\\photo.png");
    expect(useAttachmentDownloadSession.getState().paths[key]).toBe("C:\\Downloads\\photo.png");

    useAttachmentDownloadSession.getState().forget(key);
    expect(useAttachmentDownloadSession.getState().paths[key]).toBeUndefined();
  });
});

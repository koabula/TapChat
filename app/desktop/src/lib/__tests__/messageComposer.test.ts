import { describe, expect, it } from "vitest";

import {
  attachmentSendWasRejected,
  shouldSubmitComposerOnKeyDown,
} from "@/lib/messageComposer";

describe("message composer keyboard submission", () => {
  it("submits Enter regardless of whether the composer contains attachments", () => {
    expect(shouldSubmitComposerOnKeyDown({ key: "Enter", shiftKey: false, isComposing: false })).toBe(true);
  });

  it("keeps Shift+Enter as a newline", () => {
    expect(shouldSubmitComposerOnKeyDown({ key: "Enter", shiftKey: true, isComposing: false })).toBe(false);
  });

  it("does not submit while an IME composition is being confirmed", () => {
    expect(shouldSubmitComposerOnKeyDown({ key: "Enter", shiftKey: false, isComposing: true })).toBe(false);
  });

  it("keeps terminally rejected attachments but treats retryable network failures as queued", () => {
    expect(attachmentSendWasRejected(["attachment_upload_failed"])).toBe(true);
    expect(attachmentSendWasRejected(["temporary_network_failure"])).toBe(false);
  });
});

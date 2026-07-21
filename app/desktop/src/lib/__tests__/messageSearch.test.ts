import { describe, expect, it } from "vitest";

import type { Message } from "@/lib/types";
import {
  findMessageMatches,
  moveSearchIndex,
  searchableMessageText,
} from "@/lib/messageSearch";

function message(overrides: Partial<Message>): Message {
  return {
    message_id: "message-1",
    sender_device_id: "device-a",
    recipient_device_id: "device-b",
    message_type: "received",
    created_at: 1,
    plaintext: null,
    has_attachment: false,
    storage_refs: [],
    ...overrides,
  };
}

describe("message search", () => {
  it("matches visible plaintext and attachment names case-insensitively", () => {
    const messages = [
      message({ message_id: "text", plaintext: "Meet at Dawn" }),
      message({
        message_id: "file",
        has_attachment: true,
        storage_refs: [{
          kind: "attachment",
          ref: "blob",
          file_name: "Field Notes.PDF",
          size_bytes: 42,
          mime_type: "application/pdf",
        }],
      }),
    ];

    expect(findMessageMatches(messages, " dawn ")).toEqual(["text"]);
    expect(findMessageMatches(messages, "notes.pdf")).toEqual(["file"]);
    expect(findMessageMatches(messages, "   ")).toEqual([]);
  });

  it("uses a legacy attachment filename instead of serialized metadata", () => {
    const legacy = message({
      plaintext: JSON.stringify({ file_name: "archive.zip", mime_type: "application/zip" }),
    });
    expect(searchableMessageText(legacy)).toBe("archive.zip");
  });

  it("cycles through matches in both directions", () => {
    expect(moveSearchIndex(-1, 3, 1)).toBe(0);
    expect(moveSearchIndex(2, 3, 1)).toBe(0);
    expect(moveSearchIndex(0, 3, -1)).toBe(2);
    expect(moveSearchIndex(0, 0, 1)).toBe(-1);
  });
});

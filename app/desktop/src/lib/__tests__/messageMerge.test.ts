import { describe, expect, it } from "vitest";

import { mergeMessagePage, reconcileLatestMessagePage } from "@/lib/messageMerge";
import type { Message } from "@/lib/types";

function message(id: string, createdAt: number, deliveryState: "sending" | "sent" | "failed"): Message {
  return {
    message_id: id,
    sender_device_id: "device:local",
    recipient_device_id: "device:peer",
    message_type: "sent",
    created_at: createdAt,
    plaintext: id,
    has_attachment: false,
    storage_refs: [],
    delivery_state: deliveryState,
  };
}

describe("mergeMessagePage", () => {
  it("replaces an optimistic sending message with the authoritative sent record", () => {
    const result = mergeMessagePage(
      [message("msg:1", 1, "sending")],
      [message("msg:1", 1, "sent")],
    );

    expect(result).toHaveLength(1);
    expect(result[0].delivery_state).toBe("sent");
  });

  it("retains loaded history and orders newly received records", () => {
    const result = mergeMessagePage(
      [message("msg:2", 2, "sent")],
      [message("msg:1", 1, "sent"), message("msg:3", 3, "sent")],
    );

    expect(result.map((item) => item.message_id)).toEqual(["msg:1", "msg:2", "msg:3"]);
  });

  it("does not regress sent delivery when an older refresh resolves late", () => {
    const result = mergeMessagePage(
      [message("msg:1", 1, "sent")],
      [message("msg:1", 1, "sending")],
    );

    expect(result[0].delivery_state).toBe("sent");
  });
});

describe("reconcileLatestMessagePage", () => {
  it("removes a stale envelope-id optimistic row when Core returns its logical row", () => {
    const result = reconcileLatestMessagePage(
      [message("msg:transport", 10, "sending")],
      [message("app:logical", 10, "sent")],
    );

    expect(result.map((item) => item.message_id)).toEqual(["app:logical"]);
  });

  it("keeps older paginated history outside the authoritative latest window", () => {
    const result = reconcileLatestMessagePage(
      [message("msg:old", 1, "sent"), message("msg:stale", 11, "sending")],
      [message("msg:new", 10, "sent")],
    );

    expect(result.map((item) => item.message_id)).toEqual(["msg:old", "msg:new"]);
  });

  it("does not clear existing messages when an incremental refresh is empty", () => {
    const current = [message("msg:existing", 10, "sent")];

    expect(reconcileLatestMessagePage(current, [])).toEqual(current);
  });
});

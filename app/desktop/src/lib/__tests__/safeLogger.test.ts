import { describe, expect, it } from "vitest";
import { sanitizeLogText } from "../safeLogger";

describe("safeLogger", () => {
  it("removes URLs, paths, identifiers, tokens, and attachment names", () => {
    const raw = "device:alice-phone group:secret https://example.com/v1/inbox/device:alice?token=secret C:\\Users\\alice\\profile.json vacation-photo.jpg";
    const sanitized = sanitizeLogText(raw);

    expect(sanitized).not.toContain("alice");
    expect(sanitized).not.toContain("example.com");
    expect(sanitized).not.toContain("secret");
    expect(sanitized).not.toContain("vacation-photo.jpg");
  });
});

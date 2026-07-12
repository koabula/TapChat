import { describe, expect, it, vi } from "vitest";
import { clearClipboardIfUnchanged } from "../clipboardSecurity";

describe("clearClipboardIfUnchanged", () => {
  it("clears only when the clipboard still contains the recovery phrase", async () => {
    const writeText = vi.fn(async () => undefined);
    await expect(clearClipboardIfUnchanged("phrase", {
      readText: async () => "phrase",
      writeText
    })).resolves.toBe("cleared");
    expect(writeText).toHaveBeenCalledWith("");
  });

  it("preserves content copied by the user afterwards", async () => {
    const writeText = vi.fn(async () => undefined);
    await expect(clearClipboardIfUnchanged("phrase", {
      readText: async () => "new content",
      writeText
    })).resolves.toBe("unchanged");
    expect(writeText).not.toHaveBeenCalled();
  });

  it("surfaces clipboard permission failures", async () => {
    await expect(clearClipboardIfUnchanged("phrase", {
      readText: async () => { throw new Error("permission denied"); },
      writeText: async () => undefined
    })).rejects.toThrow("permission denied");
  });
});

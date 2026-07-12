import { readText, writeText } from "@tauri-apps/plugin-clipboard-manager";

export interface ClipboardTextAccess {
  readText(): Promise<string>;
  writeText(value: string): Promise<void>;
}

const systemClipboard: ClipboardTextAccess = { readText, writeText };

export async function clearClipboardIfUnchanged(
  expected: string,
  clipboard: ClipboardTextAccess = systemClipboard
): Promise<"cleared" | "unchanged"> {
  if ((await clipboard.readText()) !== expected) {
    return "unchanged";
  }
  await clipboard.writeText("");
  return "cleared";
}

import type { Message } from "@/lib/types";

function attachmentNameFromPlaintext(plaintext: string | null): string | null {
  if (!plaintext) return null;
  try {
    const parsed = JSON.parse(plaintext) as { file_name?: unknown };
    return typeof parsed.file_name === "string" ? parsed.file_name : null;
  } catch {
    return null;
  }
}

export function searchableMessageText(message: Message): string {
  const attachmentNames = (message.storage_refs ?? [])
    .map((reference) => reference.file_name?.trim())
    .filter((name): name is string => Boolean(name));
  const legacyAttachmentName = attachmentNameFromPlaintext(message.plaintext);
  const visiblePlaintext = legacyAttachmentName ? null : message.plaintext;
  return [visiblePlaintext, legacyAttachmentName, ...attachmentNames]
    .filter((value): value is string => Boolean(value))
    .join("\n");
}

export function findMessageMatches(messages: Message[], query: string): string[] {
  const normalizedQuery = query.trim().toLocaleLowerCase();
  if (!normalizedQuery) return [];
  return messages
    .filter((message) =>
      searchableMessageText(message).toLocaleLowerCase().includes(normalizedQuery),
    )
    .map((message) => message.message_id);
}

export function moveSearchIndex(
  currentIndex: number,
  matchCount: number,
  direction: 1 | -1,
): number {
  if (matchCount === 0) return -1;
  if (currentIndex < 0 || currentIndex >= matchCount) {
    return direction === 1 ? 0 : matchCount - 1;
  }
  return (currentIndex + direction + matchCount) % matchCount;
}

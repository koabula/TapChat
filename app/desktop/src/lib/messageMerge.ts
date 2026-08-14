import type { Message } from "@/lib/types";

/**
 * Merge a fresh Core message page into the current optimistic projection.
 * Core is authoritative for an existing message id, so a persisted `sent`
 * record must replace the optimistic `sending` copy instead of being dropped.
 */
export function mergeMessagePage(current: Message[], incoming: Message[]): Message[] {
  const merged = new Map(current.map((message) => [message.message_id, message]));
  for (const message of incoming) {
    const existing = merged.get(message.message_id);
    merged.set(
      message.message_id,
      existing?.delivery_state === "sent" && message.delivery_state !== "sent"
        ? { ...message, delivery_state: "sent" }
        : message,
    );
  }
  return [...merged.values()].sort((left, right) => left.created_at - right.created_at);
}

/**
 * Reconcile the newest Core page. Unlike loading older history, a refresh is
 * authoritative for the covered time window and must remove optimistic rows
 * that Core no longer reports (for example a legacy envelope-id placeholder).
 */
export function reconcileLatestMessagePage(current: Message[], incoming: Message[]): Message[] {
  if (incoming.length === 0) return [];
  const incomingIds = new Set(incoming.map((message) => message.message_id));
  const oldestIncoming = Math.min(...incoming.map((message) => message.created_at));
  const olderHistory = current.filter((message) =>
    message.created_at < oldestIncoming &&
    message.delivery_state !== "sending" &&
    !incomingIds.has(message.message_id)
  );
  return mergeMessagePage(olderHistory, incoming);
}

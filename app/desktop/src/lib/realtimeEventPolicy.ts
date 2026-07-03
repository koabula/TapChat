export function directRealtimeEventHandledByRustCore(eventType: string): boolean {
  return eventType === "inbox_record_available" || eventType === "head_updated";
}

export function shouldFrontendInvokeSyncForRealtimeEvent(eventType: string): boolean {
  return ![
    "inbox_record_available",
    "head_updated",
    "disconnected",
    "error",
  ].includes(eventType);
}

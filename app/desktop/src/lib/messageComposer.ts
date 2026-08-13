export interface ComposerKeyEvent {
  key: string;
  shiftKey: boolean;
  isComposing: boolean;
}

export function shouldSubmitComposerOnKeyDown(event: ComposerKeyEvent): boolean {
  return event.key === "Enter" && !event.shiftKey && !event.isComposing;
}

export function attachmentSendWasRejected(systemStatuses?: readonly string[]): boolean {
  return systemStatuses?.includes("attachment_upload_failed") ?? false;
}

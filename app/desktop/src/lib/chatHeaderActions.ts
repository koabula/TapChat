import { presentError } from "@/lib/errors";
export type ChatHeaderActionId =
  | "contact_details"
  | "refresh_contact"
  | "group_members"
  | "sync_group";

export interface ChatHeaderActionDefinition {
  id: ChatHeaderActionId;
  label: string;
  busyLabel: string;
}

export interface ChatHeaderActionStatus {
  kind: "success" | "error";
  text: string;
}

export function chatHeaderActionErrorStatus(error: unknown): ChatHeaderActionStatus {
  return {
    kind: "error",
    text: presentError(error).message,
  };
}

const DIRECT_ACTIONS: ChatHeaderActionDefinition[] = [
  { id: "contact_details", label: "Contact details", busyLabel: "Opening" },
  { id: "refresh_contact", label: "Refresh contact", busyLabel: "Refreshing" },
];

const GROUP_ACTIONS: ChatHeaderActionDefinition[] = [
  { id: "group_members", label: "Members", busyLabel: "Opening" },
  { id: "sync_group", label: "Sync now", busyLabel: "Syncing" },
];

export function chatHeaderActions(isGroup: boolean): ChatHeaderActionDefinition[] {
  return isGroup ? GROUP_ACTIONS : DIRECT_ACTIONS;
}

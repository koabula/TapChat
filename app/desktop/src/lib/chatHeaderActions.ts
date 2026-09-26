import { presentError } from "@/lib/errors";
export type ChatHeaderActionId =
  | "contact_details"
  | "refresh_contact"
  | "reset_session"
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

const RESET_SESSION: ChatHeaderActionDefinition = {
  id: "reset_session",
  label: "Reset secure session",
  busyLabel: "Resetting",
};

/**
 * `canResetSession` adds the one destructive direct action: rebuilding the
 * session from this side, for when the peer has lost its own.
 */
export function chatHeaderActions(
  isGroup: boolean,
  options: { canResetSession?: boolean } = {},
): ChatHeaderActionDefinition[] {
  if (isGroup) return GROUP_ACTIONS;
  return options.canResetSession ? [...DIRECT_ACTIONS, RESET_SESSION] : DIRECT_ACTIONS;
}

import type { ContactRelationshipStatus, ContactSummary } from "./types";
import type { GroupConversationSummary } from "./tauri";

type ContactSummaryInput = Omit<ContactSummary, "relationship_status"> & {
  relationship_status?: ContactRelationshipStatus;
};

export interface ContactProjection {
  user_id: string;
  display_name: string | null;
  device_count: number;
  last_refresh: number | null;
  relationship_status: ContactRelationshipStatus;
  verified: boolean;
  key_changed_unverified: boolean;
}

export function mapContacts(contacts: ContactSummaryInput[]): ContactProjection[] {
  return contacts.map((contact) => ({
    user_id: contact.user_id,
    display_name: contact.display_name ?? null,
    device_count: contact.device_count,
    last_refresh: null,
    relationship_status: contact.relationship_status ?? "available",
    verified: Boolean(contact.verified),
    key_changed_unverified: Boolean(contact.key_changed_unverified),
  }));
}

export function visibleGroupIds(
  summaries: Pick<GroupConversationSummary, "group_id">[],
): Set<string> {
  return new Set(summaries.map((summary) => summary.group_id));
}

export function staleGroupSnapshotIds(
  knownGroupIds: string[],
  visibleIds: ReadonlySet<string>,
): string[] {
  return knownGroupIds.filter((groupId) => !visibleIds.has(groupId));
}

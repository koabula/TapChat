import type { ContactSummary, GroupManifest } from "./types";

export interface GroupNameContact {
  user_id: string;
  display_name?: string | null;
}

export interface GroupNameResolverInput {
  manifest?: GroupManifest | null;
  contacts: GroupNameContact[] | ContactSummary[];
  localUserId?: string | null;
  localDisplayName?: string | null;
}

export interface ResolveGroupNameInput {
  userId?: string | null;
  deviceId?: string | null;
}

function shortId(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length <= 18) return trimmed;
  const parts = trimmed.split(":");
  const tail = parts[parts.length - 1] || trimmed;
  return tail.length <= 12 ? tail : `${tail.slice(0, 6)}...${tail.slice(-4)}`;
}

export function buildGroupNameResolver(input: GroupNameResolverInput) {
  const contactNames = new Map(
    input.contacts
      .map((contact) => [contact.user_id, contact.display_name?.trim() || null] as const)
      .filter(([, displayName]) => displayName),
  );
  const userByDevice = new Map(
    (input.manifest?.member_devices ?? []).map((device) => [
      device.device_id,
      device.user_id,
    ]),
  );

  return ({ userId, deviceId }: ResolveGroupNameInput): string => {
    const resolvedUserId = userId || (deviceId ? userByDevice.get(deviceId) : undefined);
    if (resolvedUserId) {
      if (resolvedUserId === input.localUserId) {
        return input.localDisplayName?.trim() || "You";
      }
      return contactNames.get(resolvedUserId) || shortId(resolvedUserId);
    }
    return deviceId ? shortId(deviceId) : "Unknown";
  };
}


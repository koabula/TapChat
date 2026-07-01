export interface LockedProfileView {
  reasonLabel: string;
  needsPassphrase: boolean;
  primaryActionLabel: "Unlock" | "Retry";
}

export function lockedProfileView(lockReason: string | null | undefined): LockedProfileView {
  const needsPassphrase = !lockReason || lockReason === "profile_locked";
  return {
    reasonLabel:
      lockReason === "snapshot_load_failed"
        ? "Profile data needs repair"
        : lockReason === "restore_failed"
          ? "Profile state could not be restored"
          : "Profile locked",
    needsPassphrase,
    primaryActionLabel: needsPassphrase ? "Unlock" : "Retry",
  };
}

export function lockedProfileRetryPayload(
  lockReason: string | null | undefined,
  passphrase: string,
): { passphrase: string | null } {
  return {
    passphrase: lockedProfileView(lockReason).needsPassphrase
      ? passphrase || null
      : null,
  };
}

export function lockedProfileRetryDisabled(
  lockReason: string | null | undefined,
  passphrase: string,
  busy: boolean,
): boolean {
  return busy || (lockedProfileView(lockReason).needsPassphrase && !passphrase);
}

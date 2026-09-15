/**
 * Every storage key an untrusted host operator can read.
 *
 * Durable Object keys and R2 object keys are the half of the observable
 * surface that the Rust-side enumeration cannot reach: they are minted here,
 * in TypeScript, and never cross the client-to-host boundary as a value. Both
 * of the leaks that were caught only on retrospective review lived here — the
 * four identifiers baked into the blob key, and the inbox spill object that
 * stores an entire record, cleartext envelope header included.
 *
 * Minting every key in one module is what lets `test/leakage-ledger.test.ts`
 * compare the templates against `contracts/leakage-ledger.json` and check, by
 * rendering them with sentinel inputs, which identifiers each key actually
 * carries. Keep it that way: a key built inline at a call site is invisible to
 * that check, which is exactly how `inbox-payload/...` went unnoticed.
 */

function segment(value: string): string {
  return value.replace(/[^A-Za-z0-9:_-]/g, "_");
}

/**
 * A fresh 256-bit name, base64url.
 *
 * Every object in this bucket except the deliberately public `shared-state/`
 * documents is named by one of these. Read access was always gated on an
 * independent random capability, so the identifiers the keys used to carry
 * bought nothing and cost a cross-inbox token: the same key reached the
 * recipient's inbox as `envelope.storageRef.ref`, and its conversation segment
 * was identical at both ends of a conversation.
 *
 * The namespace prefix stays. It carries no identifier, and the R2 lifecycle
 * rules the desktop provisioner installs match on it.
 */
function opaqueName(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Inbox Durable Object keys. */
export const INBOX_DO_KEYS = {
  meta: "meta",
  acceptedLane: (lane: string): string => `accepted-lane:${lane}`,
  record: (seq: number): string => `record:${seq}`,
  idempotency: (mid: string): string => `idempotency:${mid}`,
  appendResult: (mid: string): string => `append-result:${mid}`,
  messageRequest: (lane: string): string => `message-request:${lane}`,
  messageRequestIndex: "message-request:index",
  messageRequestMeta: "message-request:meta",
  messageRequestRateLimit: "message-request:rate-limit",
  rateLimit: (lane: string): string => `rate-limit:${lane}`,
  rateLimitFirstContact: "rate-limit:first-contact"
} as const;

/** R2 object keys, across every namespace in the single storage bucket. */
export const R2_KEYS = {
  blob: (): string => `blobs/${opaqueName()}`,
  inboxPayload: (): string => `inbox-payload/${opaqueName()}`,
  /**
   * Named by the SHA-256 of the pickup capability rather than by a fresh
   * random, because this is the one object with nowhere to record a fresh
   * one: it is pure R2 with no Durable Object beside it, and the fetcher
   * arrives holding only the descriptor. Hashing the credential it already
   * presents gives an opaque name that both sides recompute, which is also
   * why the expiry path can no longer delete a different key than the one it
   * stored.
   *
   * The caller passes the digest, so unlike the two above, this builder is
   * not itself the guarantee that the name carries nothing — see
   * `scope.limits` in contracts/leakage-ledger.json.
   */
  welcomePickup: (capabilityDigest: string): string => `welcome-pickup/${capabilityDigest}`,
  sharedStateIdentityBundle: (userId: string): string =>
    `shared-state/${segment(userId)}/identity_bundle.json`,
  sharedStateDeviceList: (userId: string): string =>
    `shared-state/${segment(userId)}/device_list.json`,
  sharedStateDeviceStatus: (userId: string): string =>
    `shared-state/${segment(userId)}/device_status.json`
} as const;

/**
 * The template for every builder above.
 *
 * Typed as `Record<keyof typeof ...>`, which is the load-bearing part: adding a
 * builder without adding its template is a `tsc` error, not a silently passing
 * test. Comparing a free-standing list against the ledger would be circular —
 * the list would be checked against itself, and a whole new namespace could
 * appear unnoticed. That is exactly how `inbox-payload/...` was missed.
 */
export const INBOX_DO_KEY_TEMPLATES: Record<keyof typeof INBOX_DO_KEYS, string> = {
  meta: "meta",
  acceptedLane: "accepted-lane:{lane}",
  record: "record:{seq}",
  idempotency: "idempotency:{mid}",
  appendResult: "append-result:{mid}",
  messageRequest: "message-request:{lane}",
  messageRequestIndex: "message-request:index",
  messageRequestMeta: "message-request:meta",
  messageRequestRateLimit: "message-request:rate-limit",
  rateLimit: "rate-limit:{lane}",
  rateLimitFirstContact: "rate-limit:first-contact"
};

export const R2_KEY_TEMPLATES: Record<keyof typeof R2_KEYS, string> = {
  blob: "blobs/{opaque}",
  inboxPayload: "inbox-payload/{opaque}",
  sharedStateIdentityBundle: "shared-state/{userId}/identity_bundle.json",
  sharedStateDeviceList: "shared-state/{userId}/device_list.json",
  sharedStateDeviceStatus: "shared-state/{userId}/device_status.json",
  welcomePickup: "welcome-pickup/{opaque}"
};

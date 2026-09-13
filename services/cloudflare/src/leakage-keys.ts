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

/** Inbox Durable Object keys. */
export const INBOX_DO_KEYS = {
  meta: "meta",
  acceptedLane: (lane: string): string => `accepted-lane:${lane}`,
  laneSeq: (lane: string): string => `lane-seq:${lane}`,
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
  blob: (input: {
    variant: string;
    ownerUserId: string;
    ownerDeviceId: string;
    storageScope: string;
    groupSegment: string;
    conversationId: string;
    messageId: string;
    taskId: string;
  }): string =>
    [
      "blobs",
      input.variant,
      segment(input.ownerUserId),
      segment(input.ownerDeviceId),
      input.storageScope,
      segment(input.groupSegment),
      segment(input.conversationId),
      `${segment(input.messageId)}-${segment(input.taskId)}`
    ].join("/"),
  inboxPayload: (deviceId: string, seq: number): string => `inbox-payload/${deviceId}/${seq}.json`,
  sharedStateIdentityBundle: (userId: string): string =>
    `shared-state/${segment(userId)}/identity_bundle.json`,
  sharedStateDeviceList: (userId: string): string =>
    `shared-state/${segment(userId)}/device_list.json`,
  sharedStateDeviceStatus: (userId: string): string =>
    `shared-state/${segment(userId)}/device_status.json`,
  welcomePickup: (groupId: string, deviceId: string, requestId?: string): string =>
    `welcome-pickup/${groupId}/${deviceId}/${requestId ?? "unbound"}.json`
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
  laneSeq: "lane-seq:{lane}",
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
  blob: "blobs/{variant}/{ownerUserId}/{ownerDeviceId}/{storageScope}/{groupSegment}/{conversationId}/{messageId}-{taskId}",
  inboxPayload: "inbox-payload/{deviceId}/{seq}.json",
  sharedStateIdentityBundle: "shared-state/{userId}/identity_bundle.json",
  sharedStateDeviceList: "shared-state/{userId}/device_list.json",
  sharedStateDeviceStatus: "shared-state/{userId}/device_status.json",
  welcomePickup: "welcome-pickup/{groupId}/{deviceId}/{requestId}.json"
};

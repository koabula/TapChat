import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import {
  INBOX_DO_KEYS,
  INBOX_DO_KEY_TEMPLATES,
  R2_KEYS,
  R2_KEY_TEMPLATES
} from "../src/leakage-keys";
import type { RealtimeEvent } from "../src/types/contracts";

/**
 * The worker half of the leakage enumeration.
 *
 * Durable Object keys and R2 object keys are minted in TypeScript and never
 * cross the client-to-host boundary as a value, so the Rust-side checks cannot
 * see them — and both leaks that were caught only on retrospective review
 * lived here. This file holds the checks for that half, against the same
 * ledger the Rust side reads.
 */

/**
 * Only the fields this file actually reads. The cast below is a plain `as`, so
 * a field declared here but absent from the data would go unnoticed rather
 * than fail to compile — declaring more than is used buys a silent staleness
 * risk and nothing else. `parameter` and `fate` are deliberately omitted.
 */
interface LedgerEntry {
  surface: string;
  path: string;
  bits: string;
  value?: string;
  carries: string[];
  signed: boolean;
  note?: string;
}

const ledger = JSON.parse(
  readFileSync(new URL("../../../contracts/leakage-ledger.json", import.meta.url), "utf8")
) as { entries: LedgerEntry[]; sentinels: { literal: string[]; captured: string[] } };

const pathsFor = (surface: string): string[] =>
  ledger.entries
    .filter((entry) => entry.surface === surface)
    .map((entry) => entry.path)
    .sort();

const entryFor = (surface: string, path: string): LedgerEntry => {
  const found = ledger.entries.find((entry) => entry.surface === surface && entry.path === path);
  assert.ok(found, `${surface}:${path} is missing from contracts/leakage-ledger.json`);
  return found;
};

/**
 * Sentinel tokens, identical to `sentinel` in `src/leakage_ledger.rs`.
 *
 * Alphanumeric only: device ids are percent-encoded inside endpoint strings,
 * so a token containing `:` would read as clean at exactly the places worth
 * checking.
 */
const SENDER_USER_FP = "ZQ7X2M1PDA";
const RECIPIENT_USER_FP = "TP6YB3HSLM";
const SENDER_DEVICE_FP = "K4N8VR2WQJ";
const RECIPIENT_DEVICE_FP = "D9WFC5XKQZ";
const MESSAGE_NONCE = 8675309;

const BINDINGS: Record<string, string> = {
  sender_user: SENDER_USER_FP,
  recipient_user: RECIPIENT_USER_FP,
  sender_device: SENDER_DEVICE_FP,
  recipient_device: RECIPIENT_DEVICE_FP,
  message_nonce: String(MESSAGE_NONCE)
};

const senderUserId = `user:${SENDER_USER_FP}`;
const recipientDeviceId = `device:${RECIPIENT_USER_FP}:${RECIPIENT_DEVICE_FP}`;
const ownerDeviceId = `device:${SENDER_USER_FP}:${SENDER_DEVICE_FP}`;
// Sorted, matching `direct_conversation_id` in src/conversation/mod.rs.
const conversationId = `conv:user:${RECIPIENT_USER_FP}:user:${SENDER_USER_FP}`;
const messageId = `msg:${conversationId}:${MESSAGE_NONCE}:${recipientDeviceId}`;

const sentinelsIn = (value: string): string[] =>
  Object.entries(BINDINGS)
    .filter(([, token]) => value.includes(token))
    .map(([name]) => name)
    .sort();

/** Every key template, paired with the real builder rendered on sentinel input. */
const LANE = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const MID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

const RENDERED: ReadonlyArray<{ surface: string; template: string; key: string }> = [
  { surface: "inbox_do_key", template: "meta", key: INBOX_DO_KEYS.meta },
  { surface: "inbox_do_key", template: "accepted-lane:{lane}", key: INBOX_DO_KEYS.acceptedLane(LANE) },
  { surface: "inbox_do_key", template: "lane-seq:{lane}", key: INBOX_DO_KEYS.laneSeq(LANE) },
  { surface: "inbox_do_key", template: "record:{seq}", key: INBOX_DO_KEYS.record(7) },
  {
    surface: "inbox_do_key",
    template: "idempotency:{mid}",
    key: INBOX_DO_KEYS.idempotency(MID)
  },
  {
    surface: "inbox_do_key",
    template: "append-result:{mid}",
    key: INBOX_DO_KEYS.appendResult(MID)
  },
  {
    surface: "inbox_do_key",
    template: "message-request:{lane}",
    key: INBOX_DO_KEYS.messageRequest(LANE)
  },
  {
    surface: "inbox_do_key",
    template: "message-request:index",
    key: INBOX_DO_KEYS.messageRequestIndex
  },
  {
    surface: "inbox_do_key",
    template: "message-request:meta",
    key: INBOX_DO_KEYS.messageRequestMeta
  },
  {
    surface: "inbox_do_key",
    template: "message-request:rate-limit",
    key: INBOX_DO_KEYS.messageRequestRateLimit
  },
  {
    surface: "inbox_do_key",
    template: "rate-limit:{lane}",
    key: INBOX_DO_KEYS.rateLimit(LANE)
  },
  {
    surface: "inbox_do_key",
    template: "rate-limit:first-contact",
    key: INBOX_DO_KEYS.rateLimitFirstContact
  },
  {
    surface: "r2_key",
    template: "blobs/{opaque}",
    key: R2_KEYS.blob()
  },
  {
    surface: "r2_key",
    template: "inbox-payload/{opaque}",
    key: R2_KEYS.inboxPayload()
  },
  {
    surface: "r2_key",
    template: "shared-state/{userId}/identity_bundle.json",
    key: R2_KEYS.sharedStateIdentityBundle(senderUserId)
  },
  {
    surface: "r2_key",
    template: "shared-state/{userId}/device_list.json",
    key: R2_KEYS.sharedStateDeviceList(senderUserId)
  },
  {
    surface: "r2_key",
    template: "shared-state/{userId}/device_status.json",
    key: R2_KEYS.sharedStateDeviceStatus(senderUserId)
  },
  {
    surface: "r2_key",
    // The production caller passes a SHA-256 of the pickup capability, so the
    // fixture passes one too. Feeding this builder an identifier would be a
    // fixture that tests a key production never mints.
    template: "welcome-pickup/{opaque}",
    key: R2_KEYS.welcomePickup(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
  }
];

test("every minted key template is recorded in the leakage ledger", () => {
  assert.deepEqual(
    Object.values(INBOX_DO_KEY_TEMPLATES).sort(),
    pathsFor("inbox_do_key"),
    "inbox Durable Object key templates must match the ledger exactly"
  );
  assert.deepEqual(
    Object.values(R2_KEY_TEMPLATES).sort(),
    pathsFor("r2_key"),
    "R2 object key templates must match the ledger exactly"
  );
});

test("the rendered key set covers every declared template", () => {
  const covered = RENDERED.map((item) => item.template).sort();
  const declared = [
    ...Object.values(INBOX_DO_KEY_TEMPLATES),
    ...Object.values(R2_KEY_TEMPLATES)
  ].sort();
  assert.deepEqual(
    covered,
    declared,
    "each template must be exercised below, or its `carries` claim is untested"
  );
});

test("each storage key carries exactly the identifiers the ledger declares", () => {
  for (const { surface, template, key } of RENDERED) {
    const declared = [...entryFor(surface, template).carries].sort();
    assert.deepEqual(
      sentinelsIn(key),
      declared,
      `${surface}:${template} rendered as ${JSON.stringify(key)}.\n` +
        "A new identifier here is an unrecorded leak. Do not widen `carries` to make " +
        "this pass — that publishes a wider leakage claim, and it is the same failure " +
        "this check exists to prevent."
    );
  }
});

test("the realtime event shape matches the ledger", () => {
  // `satisfies Required<T>` is the TypeScript counterpart of an exhaustive
  // struct literal: a missing key or an extra key is a compile error, and
  // `tsc --noEmit` covers `test/**/*.ts`.
  const shape = {
    event: "head_updated",
    deviceId: "",
    seq: 0,
    record: undefined as never,
    requestId: "",
    change: "queued"
  } satisfies Required<RealtimeEvent>;

  assert.deepEqual(
    Object.keys(shape).sort(),
    pathsFor("realtime_event"),
    "fields pushed over the inbox socket must all be recorded"
  );
});

test("route path matching stays confined to the files the ledger names", () => {
  // The externally reachable request line is defined in routes/http.ts. The
  // three Durable Object files also match on paths, but only on requests the
  // router has already matched and authorized, so they are internal. Any new
  // file matching on a path is a new externally visible surface until proven
  // otherwise.
  const expected = [
    "src/device-registry/durable.ts",
    "src/group-outbox/durable.ts",
    "src/inbox/durable.ts",
    "src/routes/http.ts"
  ];
  const found: string[] = [];
  const walk = (dir: URL): void => {
    for (const item of readdirSync(dir, { withFileTypes: true })) {
      const child = new URL(`${item.name}${item.isDirectory() ? "/" : ""}`, dir);
      if (item.isDirectory()) {
        walk(child);
      } else if (item.name.endsWith(".ts")) {
        if (readFileSync(child, "utf8").includes("url.pathname")) {
          found.push(child.pathname.slice(child.pathname.indexOf("/src/") + 1));
        }
      }
    }
  };
  walk(new URL("../src/", import.meta.url));
  assert.deepEqual(
    found.sort(),
    expected,
    "a new file matches on url.pathname; either it defines an externally reachable " +
      "route (record it under surface `route`) or it is internal (add it to " +
      "scope.internalPathMatchers)"
  );
});

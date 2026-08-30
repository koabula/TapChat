import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { build } from "esbuild";
import { Miniflare } from "miniflare";
import { ed25519 } from "@noble/curves/ed25519";
import {
  CURRENT_MODEL_VERSION,
  type DeploymentBundle,
  type DeviceRuntimeAuth,
  type DeviceRuntimeRefreshChallenge,
  type DeviceBinding,
  type GroupCapability,
  type GroupManifest,
  type IdentityBundle,
  type InboxAppendCapability,
  type MessageRequestListResult,
  type PrepareBlobUploadRequest
} from "../src/types/contracts";
import {
  groupCapabilitySigningPayload,
  groupManifestSigningPayload,
  verifyIdentityBundle
} from "../src/auth/capability";
import { signSharingPayload } from "../src/storage/sharing";

const ROOT = path.resolve(import.meta.dirname, "..");
const TMP_DIR = path.join(ROOT, "node_modules", ".cache", "tapchat-cloudflare-test-runtime");
const WORKER_BUNDLE = path.join(TMP_DIR, "worker.mjs");
const BASE_URL = "https://example.com";
const RUNTIME_ID = "runtime:integration";
const SHARING_SECRET = "integration-sharing-secret-0123456789abcdef0123456789abcdef";
const DEVICE_RUNTIME_SECRET = "integration-runtime-secret-0123456789abcdef0123456789abcdef";
const DEVICE_RUNTIME_KEY_ID = "integration-runtime-current";
const signedFixtures = new Map<string, {
  bundle: IdentityBundle;
  capability: InboxAppendCapability;
  userSecret: Uint8Array;
  deviceSecret: Uint8Array;
}>();

async function ensureWorkerBundle(): Promise<string> {
  await fs.mkdir(TMP_DIR, { recursive: true });
  await build({
    entryPoints: [path.join(ROOT, "src", "index.ts")],
    outfile: WORKER_BUNDLE,
    bundle: true,
    format: "esm",
    platform: "browser",
    target: "es2022",
    sourcemap: "inline"
  });
  return WORKER_BUNDLE;
}

async function createRuntime(options?: { maxInlineBytes?: string; retentionDays?: string; rateLimitPerMinute?: string; rateLimitPerHour?: string; ownerUserId?: string }) {
  const scriptPath = await ensureWorkerBundle();
  const mf = new Miniflare({
    scriptPath,
    modules: true,
    compatibilityDate: "2026-07-09",
    bindings: {
      PUBLIC_BASE_URL: BASE_URL,
      RUNTIME_ID,
      OWNER_USER_ID: options?.ownerUserId ?? "user:bob",
      OWNER_USER_PUBLIC_KEY: bytesToHex(ed25519.getPublicKey(new Uint8Array(32).fill(11))),
      WORKER_BUILD_ID: "integration-worker-v6",
      DEPLOYMENT_REGION: "local",
      MAX_INLINE_BYTES: options?.maxInlineBytes ?? "128",
      RETENTION_DAYS: options?.retentionDays ?? "1",
      RATE_LIMIT_PER_MINUTE: options?.rateLimitPerMinute ?? "60",
      RATE_LIMIT_PER_HOUR: options?.rateLimitPerHour ?? "600",
      SHARING_INTERNAL_SECRET: SHARING_SECRET,
      DEVICE_RUNTIME_SECRET,
      DEVICE_RUNTIME_SECRET_KEY_ID: DEVICE_RUNTIME_KEY_ID
    },
    durableObjects: {
      INBOX: "InboxDurableObject",
      GROUP_OUTBOX: "GroupOutboxDurableObject",
      DEVICE_REGISTRY: "DeviceRegistryDurableObject"
    },
    r2Buckets: ["TAPCHAT_STORAGE"]
  });
  await mf.ready;
  return mf;
}

function authHeaders(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}` };
}

type IssuedDeployment = DeploymentBundle & { runtimeCredential: DeviceRuntimeAuth };

async function issueDeviceBundle(mf: Miniflare, userId = "user:bob", deviceId = "device:bob:phone"): Promise<IssuedDeployment> {
  const fixture = signedIdentityFixture(userId, deviceId);
  const deploymentResponse = await mf.dispatchFetch(`${BASE_URL}/v1/deployment-bundle`);
  assert.equal(deploymentResponse.status, 200);
  const deployment = (await deploymentResponse.json()) as DeploymentBundle;
  const readyResponse = await mf.dispatchFetch(`${BASE_URL}/v2/runtime/ready`);
  assert.equal(readyResponse.status, 200);
  assert.deepEqual(await readyResponse.json(), {
    ready: true,
    runtimeId: RUNTIME_ID,
    protocolVersion: 6,
    workerBuildId: "integration-worker-v6",
    registrySchemaVersion: 2
  });
  const challengeResponse = await mf.dispatchFetch(`${BASE_URL}/v2/runtime-auth/challenge`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ purpose: "enroll", userId, deviceId })
  });
  assert.equal(challengeResponse.status, 200);
  const challenge = (await challengeResponse.json()) as DeviceRuntimeRefreshChallenge;
  const enrollmentResponse = await mf.dispatchFetch(`${BASE_URL}/v2/runtime-auth/enroll`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      challenge,
      device: fixture.bundle.devices[0],
      signature: signHex(fixture.deviceSecret, [
        "tapchat.device_runtime_auth.v2",
        `purpose=${challenge.purpose}`,
        `runtime_id=${challenge.runtimeId}`,
        `user_id=${challenge.userId}`,
        `device_id=${challenge.deviceId}`,
        `nonce=${challenge.nonce}`,
        `expires_at=${challenge.expiresAt}`
      ].join("\n"))
    })
  });
  assert.equal(enrollmentResponse.status, 200);
  const { runtimeCredential } = (await enrollmentResponse.json()) as { runtimeCredential: DeviceRuntimeAuth };
  assert.equal(verifyIdentityBundle(fixture.bundle), true, "generated identity bundle must verify");
  signedFixtures.set(deviceId, fixture);
  const publish = await mf.dispatchFetch(`${BASE_URL}/v1/shared-state/${encodeURIComponent(userId)}/identity-bundle`, {
    method: "PUT",
    headers: {
      ...authHeaders(runtimeCredential.token),
      "content-type": "application/json"
    },
    body: JSON.stringify(fixture.bundle)
  });
  assert.equal(publish.status, 200);
  return { ...deployment, runtimeCredential };
}

function sampleAppend(deviceId: string, messageId: string, ciphertext: string, senderUserId = "user:alice") {
  return {
    version: CURRENT_MODEL_VERSION,
    recipientDeviceId: deviceId,
    envelope: {
      version: CURRENT_MODEL_VERSION,
      messageId,
      conversationId: "conv:alice:bob",
      senderUserId,
      senderDeviceId: `${senderUserId.replace("user", "device")}:phone`,
      recipientDeviceId: deviceId,
      createdAt: Date.now(),
      messageType: "mls_application",
      inlineCiphertext: ciphertext,
      storageRefs: [],
      deliveryClass: "normal",
      senderProof: {
        type: "signature",
        value: "sig"
      }
    }
  };
}

function sampleCapability(deviceId: string): InboxAppendCapability {
  const fixture = signedFixtures.get(deviceId);
  assert.ok(fixture, `signed identity fixture missing for ${deviceId}`);
  return fixture.capability;
}

function signedIdentityFixture(userId: string, deviceId: string): {
  bundle: IdentityBundle;
  capability: InboxAppendCapability;
  userSecret: Uint8Array;
  deviceSecret: Uint8Array;
} {
  const now = Date.now();
  const userSecret = new Uint8Array(32).fill(11);
  const deviceSecret = new Uint8Array(32).fill(12);
  const userPublicKey = bytesToHex(ed25519.getPublicKey(userSecret));
  const devicePublicKey = bytesToHex(ed25519.getPublicKey(deviceSecret));
  const capability: InboxAppendCapability = {
    version: CURRENT_MODEL_VERSION,
    service: "inbox",
    userId,
    targetDeviceId: deviceId,
    endpoint: `${BASE_URL}/v1/inbox/${encodeURIComponent(deviceId)}/messages`,
    operations: ["append"],
    conversationScope: ["conv:alice:bob"],
    expiresAt: now + 60_000,
    signature: ""
  };
  capability.signature = signHex(deviceSecret, capabilityPayload(capability));
  const binding: DeviceBinding = {
    version: CURRENT_MODEL_VERSION,
    userId,
    deviceId,
    devicePublicKey,
    createdAt: now,
    signature: ""
  };
  binding.signature = signHex(userSecret, `${CURRENT_MODEL_VERSION}:${userId}:${deviceId}:${devicePublicKey}:${now}`);
  const bundle: IdentityBundle = {
    version: CURRENT_MODEL_VERSION,
    publicationVersion: 1,
    publicationRevision: now,
    userId,
    userPublicKey,
    bundleShareId: `share-${deviceId}`,
    updatedAt: now,
    identityBundleRef: `${BASE_URL}/v1/shared-state/${encodeURIComponent(userId)}/identity-bundle`,
    deviceStatusRef: `${BASE_URL}/v1/shared-state/${encodeURIComponent(userId)}/device-status`,
    devices: [{
      version: CURRENT_MODEL_VERSION,
      deviceId,
      devicePublicKey,
      binding,
      status: "active",
      inboxAppendCapability: capability,
      keypackageRef: {
        version: CURRENT_MODEL_VERSION,
        lifecycleVersion: 1,
        userId,
        deviceId,
        ref: `${BASE_URL}/v1/shared-state/keypackages/${encodeURIComponent(userId)}/${encodeURIComponent(deviceId)}/kp1`,
        notBefore: now - 60 * 60 * 1000,
        createdAt: now,
        expiresAt: now + 84 * 24 * 60 * 60 * 1000
      }
    }],
    signature: ""
  };
  bundle.signature = signHex(userSecret, identityBundlePayload(bundle));
  return { bundle, capability, userSecret, deviceSecret };
}

function capabilityPayload(capability: InboxAppendCapability): string {
  return [
    capability.version,
    "Inbox",
    capability.userId,
    capability.targetDeviceId,
    capability.endpoint,
    "[Append]",
    (capability.conversationScope ?? []).join(","),
    String(capability.expiresAt),
    ""
  ].join("|");
}

function identityBundlePayload(bundle: IdentityBundle): string {
  const parts = [
    bundle.version,
    bundle.userId,
    bundle.userPublicKey,
    String(bundle.publicationVersion),
    String(bundle.publicationRevision),
    "",
    String(bundle.updatedAt),
    bundle.bundleShareId ?? "",
    bundle.identityBundleRef ?? "",
    bundle.deviceStatusRef ?? "",
    bundle.storageProfile?.baseUrl ?? "",
    bundle.storageProfile?.profileRef ?? ""
  ];
  for (const device of bundle.devices) {
    parts.push(device.deviceId, device.devicePublicKey, device.binding.signature, device.inboxAppendCapability!.signature);
    parts.push(
      String(device.keypackageRef!.lifecycleVersion),
      device.keypackageRef!.ref,
      String(device.keypackageRef!.notBefore),
      String(device.keypackageRef!.createdAt),
      String(device.keypackageRef!.expiresAt)
    );
  }
  return parts.join("|");
}

function signHex(secret: Uint8Array, payload: string | Uint8Array): string {
  const encoded = typeof payload === "string" ? new TextEncoder().encode(payload) : payload;
  return bytesToHex(ed25519.sign(encoded, secret));
}

test("identity publication enforces lifecycle CAS and atomically revokes the previous share link", async () => {
  const mf = await createRuntime();
  try {
    const userId = "user:bob";
    const deviceId = "device:bob:phone";
    const deployment = await issueDeviceBundle(mf, userId, deviceId);
    const fixture = signedFixtures.get(deviceId);
    assert.ok(fixture);
    const identityUrl = `${BASE_URL}/v1/shared-state/${encodeURIComponent(userId)}/identity-bundle`;
    const initial = await mf.dispatchFetch(identityUrl);
    assert.equal(initial.status, 200);
    const etag = initial.headers.get("etag");
    assert.ok(etag);

    const oldShareId = fixture.bundle.bundleShareId!;
    const oldToken = await signSharingPayload(SHARING_SECRET, {
      version: CURRENT_MODEL_VERSION,
      service: "contact_share",
      userId,
      shareId: oldShareId
    });
    assert.equal((await mf.dispatchFetch(`${BASE_URL}/v1/contact-share/${encodeURIComponent(oldToken)}`)).status, 200);

    const invalid = structuredClone(fixture.bundle);
    invalid.publicationRevision = (invalid.publicationRevision ?? 0) + 1;
    invalid.devices[0].keypackageRef!.expiresAt += 1;
    invalid.signature = signHex(fixture.userSecret, identityBundlePayload(invalid));
    const rejected = await mf.dispatchFetch(identityUrl, {
      method: "PUT",
      headers: {
        ...authHeaders(deployment.runtimeCredential.token),
        "content-type": "application/json",
        "if-match": etag
      },
      body: JSON.stringify(invalid)
    });
    assert.equal(rejected.status, 422);
    assert.equal(((await rejected.json()) as { code: string }).code, "keypackage_lifetime_invalid");

    const candidate = structuredClone(fixture.bundle);
    candidate.publicationRevision = (candidate.publicationRevision ?? 0) + 1;
    candidate.updatedAt += 1;
    candidate.bundleShareId = "share-rotated";
    candidate.signature = signHex(fixture.userSecret, identityBundlePayload(candidate));
    const missingPrecondition = await mf.dispatchFetch(identityUrl, {
      method: "PUT",
      headers: {
        ...authHeaders(deployment.runtimeCredential.token),
        "content-type": "application/json"
      },
      body: JSON.stringify(candidate)
    });
    assert.equal(missingPrecondition.status, 412);
    assert.equal(((await missingPrecondition.json()) as { code: string }).code, "identity_bundle_conflict");

    const committed = await mf.dispatchFetch(identityUrl, {
      method: "PUT",
      headers: {
        ...authHeaders(deployment.runtimeCredential.token),
        "content-type": "application/json",
        "if-match": etag
      },
      body: JSON.stringify(candidate)
    });
    assert.equal(committed.status, 200);
    assert.equal((await mf.dispatchFetch(`${BASE_URL}/v1/contact-share/${encodeURIComponent(oldToken)}`)).status, 404);
    const newToken = await signSharingPayload(SHARING_SECRET, {
      version: CURRENT_MODEL_VERSION,
      service: "contact_share",
      userId,
      shareId: candidate.bundleShareId
    });
    assert.equal((await mf.dispatchFetch(`${BASE_URL}/v1/contact-share/${encodeURIComponent(newToken)}`)).status, 200);
  } finally {
    await mf.dispose();
  }
});

test("legacy R2 identity bundle is lazily migrated into the authoritative registry", async () => {
  const mf = await createRuntime();
  try {
    const userId = "user:bob";
    const fixture = signedIdentityFixture(userId, "device:bob:phone");
    const bucket = (await mf.getR2Bucket("TAPCHAT_STORAGE")) as unknown as {
      put(key: string, value: string): Promise<void>;
      delete(key: string): Promise<void>;
    };
    const legacyKey = `shared-state/${userId}/identity_bundle.json`;
    await bucket.put(legacyKey, JSON.stringify(fixture.bundle));

    const identityUrl = `${BASE_URL}/v1/shared-state/${encodeURIComponent(userId)}/identity-bundle`;
    const migrated = await mf.dispatchFetch(identityUrl);
    assert.equal(migrated.status, 200);
    assert.ok(migrated.headers.get("etag"));

    await bucket.delete(legacyKey);
    const authoritative = await mf.dispatchFetch(identityUrl);
    assert.equal(authoritative.status, 200);
    assert.deepEqual(await authoritative.json(), fixture.bundle);
  } finally {
    await mf.dispose();
  }
});

test("append authorization uses the registry bundle when the R2 mirror is stale", async (t) => {
  const mf = await createRuntime();
  t.after(async () => {
    await mf.dispose();
  });

  const userId = "user:bob";
  const deviceId = "device:bob:authority";
  const deployment = await issueDeviceBundle(mf, userId, deviceId);
  await setAllowlist(mf, deployment.runtimeCredential.token, deviceId, ["user:alice"]);
  const fixture = signedFixtures.get(deviceId);
  assert.ok(fixture);
  const bucket = (await mf.getR2Bucket("TAPCHAT_STORAGE")) as unknown as {
    put(key: string, value: string): Promise<void>;
  };
  await bucket.put(
    `shared-state/${userId}/identity_bundle.json`,
    JSON.stringify({ ...fixture.bundle, signature: "00" })
  );

  const delivered = await appendEnvelope(
    mf,
    deviceId,
    "msg:authoritative-bundle",
    "cipher-authoritative",
    "user:alice"
  );
  assert.equal(delivered.status, 200);
  assert.equal(delivered.deliveredTo, "inbox");
});

test("stale append capability requests an identity refresh without queuing a message request", async (t) => {
  const mf = await createRuntime();
  t.after(async () => {
    await mf.dispose();
  });

  const userId = "user:bob";
  const deviceId = "device:bob:rotated-capability";
  const deployment = await issueDeviceBundle(mf, userId, deviceId);
  const fixture = signedFixtures.get(deviceId);
  assert.ok(fixture);
  const identityUrl = `${BASE_URL}/v1/shared-state/${encodeURIComponent(userId)}/identity-bundle`;
  const currentResponse = await mf.dispatchFetch(identityUrl);
  const etag = currentResponse.headers.get("etag");
  assert.equal(currentResponse.status, 200);
  assert.ok(etag);

  const candidate = structuredClone(fixture.bundle);
  const candidateCapability = candidate.devices[0].inboxAppendCapability!;
  candidateCapability.expiresAt += 30_000;
  candidateCapability.signature = signHex(
    fixture.deviceSecret,
    capabilityPayload(candidateCapability)
  );
  candidate.publicationRevision = (candidate.publicationRevision ?? 0) + 1;
  candidate.updatedAt += 1;
  candidate.signature = signHex(fixture.userSecret, identityBundlePayload(candidate));
  const publish = await mf.dispatchFetch(identityUrl, {
    method: "PUT",
    headers: {
      ...authHeaders(deployment.runtimeCredential.token),
      "content-type": "application/json",
      "if-match": etag
    },
    body: JSON.stringify(candidate)
  });
  assert.equal(publish.status, 200);

  const staleAppend = await appendEnvelope(
    mf,
    deviceId,
    "msg:stale-capability",
    "cipher-stale",
    "user:mallory"
  );
  assert.equal(staleAppend.status, 409);
  assert.equal(staleAppend.code, "identity_refresh_required");

  const requestsResponse = await mf.dispatchFetch(
    `${BASE_URL}/v1/inbox/${encodeURIComponent(deviceId)}/message-requests`,
    { headers: authHeaders(deployment.runtimeCredential.token) }
  );
  const requests = (await requestsResponse.json()) as MessageRequestListResult;
  assert.equal(requests.requests.length, 0);
});

function bytesToHex(input: Uint8Array): string {
  return Array.from(input, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

const GROUP_ID = "group:integration";
const GROUP_OWNER_USER_ID = "user:owner";
const GROUP_OWNER_DEVICE_ID = "device:owner:desktop";
const GROUP_OWNER_DEVICE_SECRET = new Uint8Array(32).fill(12);

function groupManifest(now: number): GroupManifest {
  const manifest: GroupManifest = {
    version: CURRENT_MODEL_VERSION,
    groupId: GROUP_ID,
    conversationId: "conv:group:integration",
    title: "Integration Group",
    ownerUserId: GROUP_OWNER_USER_ID,
    admins: [],
    members: [{ userId: GROUP_OWNER_USER_ID, role: "owner", status: "active" }],
    memberDevices: [{ userId: GROUP_OWNER_USER_ID, deviceId: GROUP_OWNER_DEVICE_ID, status: "active" }],
    joinPolicy: "open_by_invite",
    memberInvitePolicy: "owner_admin_only",
    rosterVersion: 1,
    mlsEpochHint: 1,
    outbox: {
      endpoint: `${BASE_URL}/v1/groups/${encodeURIComponent(GROUP_ID)}/outbox/messages`,
      subscribeEndpoint: `${BASE_URL.replace(/^http/i, "ws")}/v1/groups/${encodeURIComponent(GROUP_ID)}/outbox/subscribe`
    },
    updatedAt: now,
    signerUserId: GROUP_OWNER_USER_ID,
    signerDeviceId: GROUP_OWNER_DEVICE_ID,
    signature: ""
  };
  manifest.signature = signHex(GROUP_OWNER_DEVICE_SECRET, groupManifestSigningPayload(manifest));
  return manifest;
}

function groupCapability(now: number): GroupCapability {
  const capability: GroupCapability = {
    version: CURRENT_MODEL_VERSION,
    service: "group_outbox",
    groupId: GROUP_ID,
    userId: GROUP_OWNER_USER_ID,
    deviceId: GROUP_OWNER_DEVICE_ID,
    role: "owner",
    operations: [
      "read",
      "subscribe",
      "append_application",
      "append_control",
      "append_membership",
      "manage_invites",
      "approve_join",
      "remove_member",
      "update_group_metadata",
      "seal_group"
    ],
    expiresAt: now + 60_000,
    signature: ""
  };
  capability.signature = signHex(GROUP_OWNER_DEVICE_SECRET, groupCapabilitySigningPayload(capability));
  return capability;
}

function groupHeaders(capability: GroupCapability): Record<string, string> {
  return {
    Authorization: `Bearer ${capability.signature}`,
    "X-Tapchat-Group-Capability": JSON.stringify(capability)
  };
}

async function appendEnvelope(
  mf: Miniflare,
  deviceId: string,
  messageId: string,
  ciphertext: string,
  senderUserId = "user:alice"
): Promise<Record<string, unknown>> {
  const capability = sampleCapability(deviceId);
  const request = sampleAppend(deviceId, messageId, ciphertext, senderUserId);
  const response = await mf.dispatchFetch(`${BASE_URL}/v1/inbox/${encodeURIComponent(deviceId)}/messages`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${capability.signature}`,
      "X-Tapchat-Capability": JSON.stringify(capability),
      "content-type": "application/json"
    },
    body: JSON.stringify(request)
  });
  return {
    status: response.status,
    ...(await response.json() as object)
  };
}

async function setAllowlist(mf: Miniflare, token: string, deviceId: string, allowedSenderUserIds: string[]): Promise<void> {
  const response = await mf.dispatchFetch(`${BASE_URL}/v1/inbox/${encodeURIComponent(deviceId)}/allowlist`, {
    method: "PUT",
    headers: {
      ...authHeaders(token),
      "content-type": "application/json"
    },
    body: JSON.stringify({ allowedSenderUserIds, rejectedSenderUserIds: [] })
  });
  assert.equal(response.status, 200);
}

type RuntimeWebSocket = {
  accept(): void;
  close(code?: number, reason?: string): void;
  addEventListener(type: "message", listener: (event: { data: unknown }) => void): void;
};

function waitForWebSocketMessage(socket: RuntimeWebSocket, timeoutMs = 3_000): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("timed out waiting for websocket message")), timeoutMs);
    socket.addEventListener("message", (event) => {
      clearTimeout(timer);
      resolve(JSON.parse(String(event.data)));
    });
  });
}

async function waitForMatchingWebSocketMessage<T>(
  socket: RuntimeWebSocket,
  matcher: (value: unknown) => value is T,
  timeoutMs = 3_000
): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const message = await waitForWebSocketMessage(socket, Math.max(1, deadline - Date.now()));
    if (matcher(message)) {
      return message;
    }
  }
  throw new Error(`timed out waiting for matching websocket message after ${timeoutMs}ms`);
}

async function waitForSubscribeReady(socket: RuntimeWebSocket): Promise<void> {
  socket.accept();
  await new Promise((resolve) => setTimeout(resolve, 25));
}

async function waitForCleanup(mf: Miniflare, token: string, deviceId: string, fromSeq: number, spillKey: string, timeoutMs = 5_000): Promise<void> {
  const bucket = ((await mf.getR2Bucket("TAPCHAT_STORAGE")) as unknown as { get(key: string): Promise<unknown | null> });
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const headResponse = await mf.dispatchFetch(`${BASE_URL}/v1/inbox/${encodeURIComponent(deviceId)}/head`, {
      headers: authHeaders(token)
    });
    assert.equal(headResponse.status, 200);
    const head = (await headResponse.json()) as { headSeq: number };
    if (head.headSeq !== 2) {
      throw new Error(`expected headSeq to remain 2, got ${head.headSeq}`);
    }

    const fetchResponse = await mf.dispatchFetch(`${BASE_URL}/v1/inbox/${encodeURIComponent(deviceId)}/messages?fromSeq=${fromSeq}&limit=10`, {
      headers: authHeaders(token)
    });
    assert.equal(fetchResponse.status, 200);
    const body = (await fetchResponse.json()) as { records: unknown[] };
    const spillObject = await bucket.get(spillKey);
    if (body.records.length === 0 && spillObject === null) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("cleanup did not remove acked expired records in time");
}

test("runtime integration: append -> subscribe push -> reconnect/fetch recovery -> ack -> cleanup", async (t) => {
  const mf = await createRuntime({ maxInlineBytes: "96", retentionDays: "0" });
  t.after(async () => {
    await mf.dispose();
  });

  const deviceId = "device:bob:phone";
  const bundle = await issueDeviceBundle(mf, "user:bob", deviceId);
  const token = bundle.runtimeCredential.token;
  await setAllowlist(mf, token, deviceId, ["user:alice"]);

  const subscribeResponse = await mf.dispatchFetch(`${BASE_URL}/v1/inbox/${encodeURIComponent(deviceId)}/subscribe`, {
    headers: {
      ...authHeaders(token),
      Upgrade: "websocket",
      Connection: "Upgrade"
    }
  });
  assert.equal(subscribeResponse.status, 101);
  assert.ok(subscribeResponse.webSocket);
  const socket = subscribeResponse.webSocket as unknown as RuntimeWebSocket;
  await waitForSubscribeReady(socket);
  const firstMessage = waitForWebSocketMessage(socket);

  const append1 = await appendEnvelope(mf, deviceId, "msg:1", "cipher-1");
  assert.equal(append1.accepted, true);
  assert.equal(append1.seq, 1);
  assert.equal(append1.deliveredTo, "inbox");

  const pushed = (await firstMessage) as { event: string; seq: number; record?: { seq: number; messageId: string } };
  assert.equal(pushed.event, "head_updated");
  const pushedRecordMessage = waitForWebSocketMessage(socket);
  const pushedRecord = (await pushedRecordMessage) as { event: string; seq: number; record: { seq: number; messageId: string } };
  assert.equal(pushedRecord.event, "inbox_record_available");
  assert.equal(pushedRecord.record.seq, 1);
  assert.equal(pushedRecord.record.messageId, "msg:1");

  socket.close(1000, "test reconnect");

  const bigCiphertext = "x".repeat(1_024);
  const append2 = await appendEnvelope(mf, deviceId, "msg:2", bigCiphertext);
  assert.equal(append2.seq, 2);

  const headResponse = await mf.dispatchFetch(`${BASE_URL}/v1/inbox/${encodeURIComponent(deviceId)}/head`, {
    headers: authHeaders(token)
  });
  assert.equal(headResponse.status, 200);
  const head = (await headResponse.json()) as { headSeq: number };
  assert.equal(head.headSeq, 2);

  const fetchResponse = await mf.dispatchFetch(`${BASE_URL}/v1/inbox/${encodeURIComponent(deviceId)}/messages?fromSeq=2&limit=10`, {
    headers: authHeaders(token)
  });
  assert.equal(fetchResponse.status, 200);
  const fetched = (await fetchResponse.json()) as { toSeq: number; records: Array<{ seq: number; messageId: string; envelope: { inlineCiphertext?: string } }> };
  assert.equal(fetched.toSeq, 2);
  assert.equal(fetched.records.length, 1);
  assert.equal(fetched.records[0].seq, 2);
  assert.equal(fetched.records[0].messageId, "msg:2");
  assert.equal(fetched.records[0].envelope.inlineCiphertext, bigCiphertext);

  const ackResponse = await mf.dispatchFetch(`${BASE_URL}/v1/inbox/${encodeURIComponent(deviceId)}/ack`, {
    method: "POST",
    headers: {
      ...authHeaders(token),
      "content-type": "application/json"
    },
    body: JSON.stringify({
      ack: {
        deviceId,
        ackSeq: 2,
        ackedAt: Date.now(),
        ackedMessageIds: ["msg:1", "msg:2"]
      }
    })
  });
  assert.equal(ackResponse.status, 200);
  const ack = (await ackResponse.json()) as { accepted: boolean; ackSeq: number };
  assert.equal(ack.accepted, true);
  assert.equal(ack.ackSeq, 2);

  await waitForCleanup(mf, token, deviceId, 1, `inbox-payload/${deviceId}/2.json`);
});

test("runtime integration: cleanup keeps head monotonic across repeated recovery fetches", async (t) => {
  const mf = await createRuntime({ maxInlineBytes: "96", retentionDays: "0" });
  t.after(async () => {
    await mf.dispose();
  });

  const deviceId = "device:bob:cleanup";
  const bundle = await issueDeviceBundle(mf, "user:bob", deviceId);
  const token = bundle.runtimeCredential.token;
  await setAllowlist(mf, token, deviceId, ["user:alice"]);

  const append1 = await appendEnvelope(mf, deviceId, "msg:cleanup-1", "cipher-cleanup-1");
  const append2 = await appendEnvelope(mf, deviceId, "msg:cleanup-2", "cipher-cleanup-2");
  assert.equal(append1.seq, 1);
  assert.equal(append2.seq, 2);

  const ackResponse = await mf.dispatchFetch(`${BASE_URL}/v1/inbox/${encodeURIComponent(deviceId)}/ack`, {
    method: "POST",
    headers: {
      ...authHeaders(token),
      "content-type": "application/json"
    },
    body: JSON.stringify({
      ack: {
        deviceId,
        ackSeq: 2,
        ackedAt: Date.now(),
        ackedMessageIds: ["msg:cleanup-1", "msg:cleanup-2"]
      }
    })
  });
  assert.equal(ackResponse.status, 200);

  await waitForCleanup(mf, token, deviceId, 1, `inbox-payload/${deviceId}/2.json`);

  for (const fromSeq of [1, 2]) {
    const headResponse = await mf.dispatchFetch(`${BASE_URL}/v1/inbox/${encodeURIComponent(deviceId)}/head`, {
      headers: authHeaders(token)
    });
    assert.equal(headResponse.status, 200);
    const head = (await headResponse.json()) as { headSeq: number };
    assert.equal(head.headSeq, 2);

    const fetchResponse = await mf.dispatchFetch(`${BASE_URL}/v1/inbox/${encodeURIComponent(deviceId)}/messages?fromSeq=${fromSeq}&limit=10`, {
      headers: authHeaders(token)
    });
    assert.equal(fetchResponse.status, 200);
    const fetched = (await fetchResponse.json()) as { toSeq: number; records: unknown[] };
    assert.equal(fetched.toSeq, 2);
    assert.deepEqual(fetched.records, []);
  }
});

test("runtime integration: message request changes push over realtime and inbox stays empty until accepted", async (t) => {
  const mf = await createRuntime();
  t.after(async () => {
    await mf.dispose();
  });

  const deviceId = "device:bob:phone";
  const bundle = await issueDeviceBundle(mf, "user:bob", deviceId);
  const token = bundle.runtimeCredential.token;

  const subscribeResponse = await mf.dispatchFetch(`${BASE_URL}/v1/inbox/${encodeURIComponent(deviceId)}/subscribe`, {
    headers: {
      ...authHeaders(token),
      Upgrade: "websocket",
      Connection: "Upgrade"
    }
  });
  assert.equal(subscribeResponse.status, 101);
  assert.ok(subscribeResponse.webSocket);
  const socket = subscribeResponse.webSocket as unknown as RuntimeWebSocket;
  await waitForSubscribeReady(socket);
  const queuedMessage = waitForWebSocketMessage(socket);

  const queued = await appendEnvelope(mf, deviceId, "msg:req-1", "cipher-req", "user:mallory");
  assert.equal(queued.deliveredTo, "message_request");
  assert.equal(queued.queuedAsRequest, true);
  const queuedEvent = (await queuedMessage) as {
    event: string;
    deviceId: string;
    senderUserId: string;
    requestId: string;
    change: string;
  };
  assert.equal(queuedEvent.event, "message_request_changed");
  assert.equal(queuedEvent.deviceId, deviceId);
  assert.equal(queuedEvent.senderUserId, "user:mallory");
  assert.equal(queuedEvent.change, "queued");

  const headResponse = await mf.dispatchFetch(`${BASE_URL}/v1/inbox/${encodeURIComponent(deviceId)}/head`, {
    headers: authHeaders(token)
  });
  const head = (await headResponse.json()) as { headSeq: number };
  assert.equal(head.headSeq, 0);

  const requestsResponse = await mf.dispatchFetch(`${BASE_URL}/v1/inbox/${encodeURIComponent(deviceId)}/message-requests`, {
    headers: authHeaders(token)
  });
  assert.equal(requestsResponse.status, 200);
  const requests = (await requestsResponse.json()) as MessageRequestListResult;
  assert.equal(requests.requests.length, 1);

  const acceptedEventPromise = waitForMatchingWebSocketMessage(socket, (value): value is {
    event: string;
    senderUserId: string;
    requestId: string;
    change: string;
  } => {
    if (!value || typeof value !== "object") {
      return false;
    }
    const candidate = value as Record<string, unknown>;
    return (
      candidate.event === "message_request_changed" &&
      candidate.change === "accepted" &&
      candidate.senderUserId === "user:mallory" &&
      candidate.requestId === requests.requests[0].requestId
    );
  });
  const acceptResponse = await mf.dispatchFetch(
    `${BASE_URL}/v1/inbox/${encodeURIComponent(deviceId)}/message-requests/${encodeURIComponent(requests.requests[0].requestId)}/accept`,
    {
      method: "POST",
      headers: authHeaders(token)
    }
  );
  assert.equal(acceptResponse.status, 200);
  const acceptedEvent = await acceptedEventPromise;
  assert.equal(acceptedEvent.event, "message_request_changed");
  assert.equal(acceptedEvent.senderUserId, "user:mallory");
  assert.equal(acceptedEvent.requestId, requests.requests[0].requestId);
  assert.equal(acceptedEvent.change, "accepted");

  const deliveredAfterAccept = await appendEnvelope(
    mf,
    deviceId,
    "msg:req-2",
    "cipher-after-accept",
    "user:mallory"
  );
  assert.equal(deliveredAfterAccept.status, 200);
  assert.equal(deliveredAfterAccept.deliveredTo, "inbox");
  assert.notEqual(deliveredAfterAccept.queuedAsRequest, true);

  const fetchResponse = await mf.dispatchFetch(`${BASE_URL}/v1/inbox/${encodeURIComponent(deviceId)}/messages?fromSeq=1&limit=10`, {
    headers: authHeaders(token)
  });
  const fetched = (await fetchResponse.json()) as { records: Array<{ messageId: string }> };
  assert.deepEqual(fetched.records.map((record) => record.messageId), ["msg:req-1", "msg:req-2"]);

  socket.close(1000, "done");
});

test("runtime integration: storage prepare-upload/upload/download uses real R2 binding", async (t) => {
  const mf = await createRuntime();
  t.after(async () => {
    await mf.dispose();
  });

  const bundle = await issueDeviceBundle(mf, "user:bob", "device:bob:laptop");
  const token = bundle.runtimeCredential.token;
  const request: PrepareBlobUploadRequest = {
    taskId: "task-1",
    conversationId: "conv:alice:bob",
    messageId: "msg:blob-1",
    variant: "original",
    sizeBytes: 4
  };
  const prepareResponse = await mf.dispatchFetch(`${BASE_URL}/v1/storage/prepare-upload`, {
    method: "POST",
    headers: {
      ...authHeaders(token),
      "content-type": "application/json"
    },
    body: JSON.stringify(request)
  });
  assert.equal(prepareResponse.status, 200);
  const prepared = (await prepareResponse.json()) as {
    blobRef: string;
    uploadTarget: string;
    downloadTarget: string;
    readCapability: string;
  };

  const uploadResponse = await mf.dispatchFetch(prepared.uploadTarget, {
    method: "PUT",
    headers: {
      "content-type": "application/octet-stream",
      "content-length": "4"
    },
    body: new Uint8Array([1, 2, 3, 4])
  });
  assert.equal(uploadResponse.status, 204);

  const bucket = ((await mf.getR2Bucket("TAPCHAT_STORAGE")) as unknown as { get(key: string): Promise<unknown | null> });
  const object = await bucket.get(prepared.blobRef);
  assert.ok(object);

  const downloadResponse = await mf.dispatchFetch(prepared.downloadTarget, {
    method: "GET",
    headers: {
      Authorization: `TapChat-Blob ${prepared.readCapability}`
    }
  });
  assert.equal(downloadResponse.status, 200);
  const bytes = new Uint8Array(await downloadResponse.arrayBuffer());
  assert.deepEqual(Array.from(bytes), [1, 2, 3, 4]);

  const rangeResponse = await mf.dispatchFetch(prepared.downloadTarget, {
    method: "GET",
    headers: {
      Authorization: `TapChat-Blob ${prepared.readCapability}`,
      Range: "bytes=2-3",
    },
  });
  assert.equal(rangeResponse.status, 206);
  assert.equal(rangeResponse.headers.get("content-range"), "bytes 2-3/4");
  assert.deepEqual(Array.from(new Uint8Array(await rangeResponse.arrayBuffer())), [3, 4]);
});

test("runtime integration: group FSM routes expose open-invite and join lease flow", async (t) => {
  const mf = await createRuntime({ ownerUserId: GROUP_OWNER_USER_ID });
  t.after(async () => {
    await mf.dispose();
  });

  const now = Date.now();
  const deployment = await issueDeviceBundle(mf, GROUP_OWNER_USER_ID, GROUP_OWNER_DEVICE_ID);
  const ownerFixture = signedFixtures.get(GROUP_OWNER_DEVICE_ID);
  assert.ok(ownerFixture);
  const manifest = groupManifest(now);
  const capability = groupCapability(now);

  const bootstrap = await mf.dispatchFetch(
    `${BASE_URL}/v1/groups/${encodeURIComponent(GROUP_ID)}/authorization/bootstrap`,
    {
      method: "POST",
      headers: {
        ...authHeaders(deployment.runtimeCredential.token),
        "content-type": "application/json"
      },
      body: JSON.stringify({
        version: CURRENT_MODEL_VERSION,
        groupId: GROUP_ID,
        manifest,
        identityBundles: [ownerFixture.bundle]
      })
    }
  );
  assert.equal(bootstrap.status, 200);

  const authorizationState = await mf.dispatchFetch(
    `${BASE_URL}/v1/groups/${encodeURIComponent(GROUP_ID)}/authorization/state`,
    { headers: groupHeaders(capability) }
  );
  assert.equal(authorizationState.status, 200);
  assert.equal(((await authorizationState.json()) as { manifest: GroupManifest }).manifest.signature, manifest.signature);

  const subscribe = await mf.dispatchFetch(
    `${BASE_URL}/v1/groups/${encodeURIComponent(GROUP_ID)}/outbox/subscribe`,
    {
      headers: {
        ...groupHeaders(capability),
        Upgrade: "websocket",
        Connection: "Upgrade"
      }
    }
  );
  assert.equal(subscribe.status, 101);
  assert.ok(subscribe.webSocket);
  const socket = subscribe.webSocket as unknown as RuntimeWebSocket;
  await waitForSubscribeReady(socket);
  const groupEvents: unknown[] = [];
  socket.addEventListener("message", (event) => {
    groupEvents.push(JSON.parse(String(event.data)));
  });
  const nextGroupEvent = async (): Promise<unknown> => {
    const deadline = Date.now() + 3_000;
    while (Date.now() < deadline) {
      const next = groupEvents.shift();
      if (next !== undefined) {
        return next;
      }
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    throw new Error("timed out waiting for queued group websocket message");
  };

  const inviteId = "invite:open-integration";
  const createInvite = await mf.dispatchFetch(
    `${BASE_URL}/v1/groups/${encodeURIComponent(GROUP_ID)}/invites`,
    {
      method: "POST",
      headers: { ...groupHeaders(capability), "content-type": "application/json" },
      body: JSON.stringify({
        version: CURRENT_MODEL_VERSION,
        groupId: GROUP_ID,
        capability,
        maxUses: 2,
        document: {
          version: CURRENT_MODEL_VERSION,
          groupId: GROUP_ID,
          title: manifest.title,
          inviteId,
          joinPolicy: "open_by_invite",
          inviterUserId: GROUP_OWNER_USER_ID,
          inviterDeviceId: GROUP_OWNER_DEVICE_ID,
          ownerUserId: GROUP_OWNER_USER_ID,
          joinRequestEndpoint: `${BASE_URL}/v1/groups/${encodeURIComponent(GROUP_ID)}/join-requests`,
          createdAt: now,
          expiresAt: now + 60_000,
          maxUses: 2,
          signature: "unsigned"
        }
      })
    }
  );
  assert.equal(createInvite.status, 200);
  const created = (await createInvite.json()) as { invite: { signature: string } };
  const inviteCreatedEvent = (await nextGroupEvent()) as { event: string; revision: number };
  assert.equal(inviteCreatedEvent.event, "group_invites_changed");
  assert.equal(inviteCreatedEvent.revision, 1);

  const listInvites = await mf.dispatchFetch(
    `${BASE_URL}/v1/groups/${encodeURIComponent(GROUP_ID)}/invites`,
    { headers: groupHeaders(capability) }
  );
  assert.equal(listInvites.status, 200);
  const inviteList = (await listInvites.json()) as { revision: number; invites: Array<{ uses: number; status: string }> };
  assert.equal(inviteList.revision, 1);
  assert.deepEqual(inviteList.invites.map((invite) => [invite.uses, invite.status]), [[0, "active"]]);

  const requestId = "join:open-integration";
  const joinerDeviceId = "device:joiner:phone";
  const submitJoin = await mf.dispatchFetch(
    `${BASE_URL}/v1/groups/${encodeURIComponent(GROUP_ID)}/join-requests`,
    {
      method: "POST",
      headers: { ...authHeaders(created.invite.signature), "content-type": "application/json" },
      body: JSON.stringify({
        version: CURRENT_MODEL_VERSION,
        inviteToken: created.invite.signature,
        request: {
          version: CURRENT_MODEL_VERSION,
          requestId,
          groupId: GROUP_ID,
          inviteId,
          joinerUserId: "user:joiner",
          joinerDeviceId,
          joinerContactShareUrl: `${BASE_URL}/contact/joiner`,
          requestedAt: now,
          requestCapability: "join-request-capability",
          signature: "join-request-signature",
          status: "pending"
        }
      })
    }
  );
  assert.equal(submitJoin.status, 200);
  const submitted = (await submitJoin.json()) as { request: { status: string; autoApprove?: boolean } };
  assert.equal(submitted.request.status, "waiting_for_group_commit");
  assert.equal(submitted.request.autoApprove, true);

  const inviteUsedEvent = (await nextGroupEvent()) as { event: string; revision: number };
  assert.equal(inviteUsedEvent.event, "group_invites_changed");
  assert.equal(inviteUsedEvent.revision, 2);
  const autoJoinEvent = (await nextGroupEvent()) as { event: string; requestId: string };
  assert.equal(autoJoinEvent.event, "group_auto_join_available");
  assert.equal(autoJoinEvent.requestId, requestId);

  const claim = await mf.dispatchFetch(
    `${BASE_URL}/v1/groups/${encodeURIComponent(GROUP_ID)}/join-requests/${encodeURIComponent(requestId)}/claim`,
    {
      method: "POST",
      headers: { ...groupHeaders(capability), "content-type": "application/json" },
      body: JSON.stringify({ version: CURRENT_MODEL_VERSION, groupId: GROUP_ID, requestId, capability })
    }
  );
  assert.equal(claim.status, 200);
  const claimed = (await claim.json()) as {
    request: { status: string };
    leaseToken: string;
    leaseExpiresAt: number;
  };
  assert.equal(claimed.request.status, "transition_in_progress");
  assert.ok(claimed.leaseToken);
  assert.ok(claimed.leaseExpiresAt > now);

  const incompleteTransition = await mf.dispatchFetch(
    `${BASE_URL}/v1/groups/${encodeURIComponent(GROUP_ID)}/outbox/transitions`,
    {
      method: "POST",
      headers: { ...groupHeaders(capability), "content-type": "application/json" },
      body: JSON.stringify({
        version: CURRENT_MODEL_VERSION,
        groupId: GROUP_ID,
        transitionId: "transition:route-probe",
        operation: "add_member",
        expectedPreviousRosterVersion: manifest.rosterVersion,
        envelopes: [],
        authorizationUpdate: { manifest, identityBundles: [] },
        capability
      })
    }
  );
  assert.equal(incompleteTransition.status, 400);
  assert.equal(((await incompleteTransition.json()) as { code: string }).code, "invalid_input");

  const complete = await mf.dispatchFetch(
    `${BASE_URL}/v1/groups/${encodeURIComponent(GROUP_ID)}/join-requests/${encodeURIComponent(requestId)}/complete`,
    {
      method: "POST",
      headers: { ...groupHeaders(capability), "content-type": "application/json" },
      body: JSON.stringify({
        version: CURRENT_MODEL_VERSION,
        groupId: GROUP_ID,
        requestId,
        capability,
        leaseToken: claimed.leaseToken,
        transitionId: "transition:not-committed",
        welcomePickup: {
          groupId: GROUP_ID,
          deviceId: joinerDeviceId,
          endpoint: `${BASE_URL}/v1/groups/${encodeURIComponent(GROUP_ID)}/welcome-pickup/${encodeURIComponent(joinerDeviceId)}`,
          capability: "welcome-capability",
          expiresAt: now + 60_000,
          startSeq: 1
        },
        manifest,
        startCursor: { groupId: GROUP_ID, lastFetchedSeq: 1, updatedAt: now }
      })
    }
  );
  assert.equal(complete.status, 409);
  assert.equal(((await complete.json()) as { code: string }).code, "group_join_lease_invalid");
  socket.close(1000, "done");
});

test.after(async () => {
  await fs.rm(TMP_DIR, { recursive: true, force: true });
});


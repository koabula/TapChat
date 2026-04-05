import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { build } from "esbuild";
import { Miniflare } from "miniflare";
import {
  CURRENT_MODEL_VERSION,
  type BootstrapDeviceRequest,
  type DeploymentBundle,
  type InboxAppendCapability,
  type MessageRequestListResult,
  type PrepareBlobUploadRequest
} from "../src/types/contracts";
import { signSharingPayload } from "../src/storage/sharing";

const ROOT = path.resolve(import.meta.dirname, "..");
const TMP_DIR = path.join(ROOT, ".test-runtime");
const WORKER_BUNDLE = path.join(TMP_DIR, "worker.mjs");
const BASE_URL = "https://example.com";

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

async function createRuntime(options?: { maxInlineBytes?: string; retentionDays?: string; rateLimitPerMinute?: string; rateLimitPerHour?: string }) {
  const scriptPath = await ensureWorkerBundle();
  const mf = new Miniflare({
    scriptPath,
    modules: true,
    compatibilityDate: "2026-03-30",
    bindings: {
      PUBLIC_BASE_URL: BASE_URL,
      DEPLOYMENT_REGION: "local",
      MAX_INLINE_BYTES: options?.maxInlineBytes ?? "128",
      RETENTION_DAYS: options?.retentionDays ?? "1",
      RATE_LIMIT_PER_MINUTE: options?.rateLimitPerMinute ?? "60",
      RATE_LIMIT_PER_HOUR: options?.rateLimitPerHour ?? "600",
      SHARING_TOKEN_SECRET: "secret",
      BOOTSTRAP_TOKEN_SECRET: "bootstrap-secret"
    },
    durableObjects: {
      INBOX: "InboxDurableObject"
    },
    r2Buckets: ["TAPCHAT_STORAGE"]
  });
  await mf.ready;
  return mf;
}

function authHeaders(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}` };
}

async function bootstrapToken(userId: string, deviceId: string): Promise<string> {
  return signSharingPayload("bootstrap-secret", {
    version: CURRENT_MODEL_VERSION,
    service: "bootstrap",
    userId,
    deviceId,
    operations: ["issue_device_bundle"],
    expiresAt: Date.now() + 60_000
  });
}

async function issueDeviceBundle(mf: Miniflare, userId = "user:bob", deviceId = "device:bob:phone"): Promise<DeploymentBundle> {
  const requestBody: BootstrapDeviceRequest = {
    version: CURRENT_MODEL_VERSION,
    userId,
    deviceId
  };
  const response = await mf.dispatchFetch(`${BASE_URL}/v1/bootstrap/device`, {
    method: "POST",
    headers: {
      ...authHeaders(await bootstrapToken(userId, deviceId)),
      "content-type": "application/json"
    },
    body: JSON.stringify(requestBody)
  });
  assert.equal(response.status, 200);
  return (await response.json()) as DeploymentBundle;
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
  return {
    version: CURRENT_MODEL_VERSION,
    service: "inbox",
    userId: "user:bob",
    targetDeviceId: deviceId,
    endpoint: `${BASE_URL}/v1/inbox/${encodeURIComponent(deviceId)}/messages`,
    operations: ["append"],
    conversationScope: ["conv:alice:bob"],
    expiresAt: Date.now() + 60_000,
    signature: "append-cap-sig"
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
  const token = bundle.deviceRuntimeAuth!.token;
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
  const token = bundle.deviceRuntimeAuth!.token;
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

test("runtime integration: message requests do not push until accepted", async (t) => {
  const mf = await createRuntime();
  t.after(async () => {
    await mf.dispose();
  });

  const deviceId = "device:bob:phone";
  const bundle = await issueDeviceBundle(mf, "user:bob", deviceId);
  const token = bundle.deviceRuntimeAuth!.token;

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

  const queued = await appendEnvelope(mf, deviceId, "msg:req-1", "cipher-req", "user:mallory");
  assert.equal(queued.deliveredTo, "message_request");
  assert.equal(queued.queuedAsRequest, true);

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

  const acceptResponse = await mf.dispatchFetch(
    `${BASE_URL}/v1/inbox/${encodeURIComponent(deviceId)}/message-requests/${encodeURIComponent(requests.requests[0].requestId)}/accept`,
    {
      method: "POST",
      headers: authHeaders(token)
    }
  );
  assert.equal(acceptResponse.status, 200);

  const fetchResponse = await mf.dispatchFetch(`${BASE_URL}/v1/inbox/${encodeURIComponent(deviceId)}/messages?fromSeq=1&limit=10`, {
    headers: authHeaders(token)
  });
  const fetched = (await fetchResponse.json()) as { records: Array<{ messageId: string }> };
  assert.deepEqual(fetched.records.map((record) => record.messageId), ["msg:req-1"]);

  socket.close(1000, "done");
});

test("runtime integration: storage prepare-upload/upload/download uses real R2 binding", async (t) => {
  const mf = await createRuntime();
  t.after(async () => {
    await mf.dispose();
  });

  const bundle = await issueDeviceBundle(mf, "user:bob", "device:bob:laptop");
  const token = bundle.deviceRuntimeAuth!.token;
  const request: PrepareBlobUploadRequest = {
    taskId: "task-1",
    conversationId: "conv:alice:bob",
    messageId: "msg:blob-1",
    mimeType: "application/octet-stream",
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
  };

  const uploadResponse = await mf.dispatchFetch(prepared.uploadTarget, {
    method: "PUT",
    headers: {
      "content-type": "application/octet-stream"
    },
    body: new Uint8Array([1, 2, 3, 4])
  });
  assert.equal(uploadResponse.status, 204);

  const bucket = ((await mf.getR2Bucket("TAPCHAT_STORAGE")) as unknown as { get(key: string): Promise<unknown | null> });
  const object = await bucket.get(prepared.blobRef);
  assert.ok(object);

  const downloadResponse = await mf.dispatchFetch(prepared.downloadTarget);
  assert.equal(downloadResponse.status, 200);
  const bytes = new Uint8Array(await downloadResponse.arrayBuffer());
  assert.deepEqual(Array.from(bytes), [1, 2, 3, 4]);
});

process.on("exit", () => {
  void fs.rm(TMP_DIR, { recursive: true, force: true });
});


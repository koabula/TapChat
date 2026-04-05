import test from "node:test";
import assert from "node:assert/strict";
import {
  CURRENT_MODEL_VERSION,
  type AllowlistDocument,
  type AppendEnvelopeRequest,
  type BootstrapDeviceRequest,
  type DeploymentBundle,
  type IdentityBundle,
  type MessageRequestListResult
} from "../src/types/contracts";
import type {
  DurableObjectId,
  DurableObjectNamespace,
  DurableObjectStorageLike,
  DurableObjectStub,
  Env,
  JsonBlobStore,
  R2Bucket,
  R2ObjectBody,
  SessionSink
} from "../src/types/runtime";
import { signSharingPayload } from "../src/storage/sharing";

class TestDurableObject {}
class TestSocket {
  accept(): void {}
  send(_payload: string): void {}
  addEventListener(_type: string, _listener: () => void): void {}
}
class TestWebSocketPair {
  0 = new TestSocket();
  1 = new TestSocket();
}
(globalThis as Record<string, unknown>).DurableObject = TestDurableObject;
(globalThis as Record<string, unknown>).WebSocketPair = TestWebSocketPair;

const { handleRequest } = await import("../src/routes/http");
const { handleInboxDurableRequest } = await import("../src/inbox/durable");
const { InboxService } = await import("../src/inbox/service");

class MemoryState implements DurableObjectStorageLike {
  private readonly map = new Map<string, unknown>();
  alarmAt?: number;

  async get<T>(key: string): Promise<T | undefined> {
    return this.map.get(key) as T | undefined;
  }

  async put<T>(key: string, value: T): Promise<void> {
    this.map.set(key, value);
  }

  async delete(key: string): Promise<void> {
    this.map.delete(key);
  }

  async setAlarm(epochMillis: number): Promise<void> {
    this.alarmAt = epochMillis;
  }
}

class MemoryR2Store implements JsonBlobStore {
  private readonly map = new Map<string, Uint8Array>();

  async putJson<T>(key: string, value: T): Promise<void> {
    this.map.set(key, new TextEncoder().encode(JSON.stringify(value)));
  }

  async getJson<T>(key: string): Promise<T | null> {
    const value = this.map.get(key);
    if (!value) {
      return null;
    }
    return JSON.parse(new TextDecoder().decode(value)) as T;
  }

  async putBytes(key: string, value: ArrayBuffer | Uint8Array): Promise<void> {
    this.map.set(key, value instanceof Uint8Array ? value : new Uint8Array(value));
  }

  async getBytes(key: string): Promise<ArrayBuffer | null> {
    const value = this.map.get(key);
    if (!value) {
      return null;
    }
    return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer;
  }

  async delete(key: string): Promise<void> {
    this.map.delete(key);
  }

  has(key: string): boolean {
    return this.map.has(key);
  }

  asBucket(): R2Bucket {
    const self = this;
    return {
      async put(key: string, value: string | ArrayBuffer | ArrayBufferView) {
        if (typeof value === "string") {
          await self.putBytes(key, new TextEncoder().encode(value));
        } else if (value instanceof ArrayBuffer) {
          await self.putBytes(key, value);
        } else {
          await self.putBytes(
            key,
            value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer
          );
        }
        return null;
      },
      async get(key: string) {
        const value = self.map.get(key);
        if (!value) {
          return null;
        }
        return {
          async json<T>() {
            return JSON.parse(new TextDecoder().decode(value)) as T;
          },
          async arrayBuffer() {
            return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer;
          }
        } satisfies R2ObjectBody;
      },
      async delete(key: string) {
        self.map.delete(key);
      }
    };
  }
}

class FakeInboxStub implements DurableObjectStub {
  private readonly deviceId: string;
  private readonly state: MemoryState;
  private readonly spillStore: MemoryR2Store;
  private readonly sessions: SessionSink[];
  private readonly env: { maxInlineBytes: number; retentionDays: number; rateLimitPerMinute: number; rateLimitPerHour: number };

  constructor(
    deviceId: string,
    state: MemoryState,
    spillStore: MemoryR2Store,
    sessions: SessionSink[],
    env: { maxInlineBytes: number; retentionDays: number; rateLimitPerMinute: number; rateLimitPerHour: number }
  ) {
    this.deviceId = deviceId;
    this.state = state;
    this.spillStore = spillStore;
    this.sessions = sessions;
    this.env = env;
  }

  async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const request = input instanceof Request ? input : new Request(input, init);
    return handleInboxDurableRequest(request, {
      deviceId: this.deviceId,
      state: this.state,
      spillStore: this.spillStore,
      sessions: this.sessions,
      maxInlineBytes: this.env.maxInlineBytes,
      retentionDays: this.env.retentionDays,
      rateLimitPerMinute: this.env.rateLimitPerMinute,
      rateLimitPerHour: this.env.rateLimitPerHour,
      onUpgrade: () => new Response(null, { status: 200 }),
      now: 1_000
    });
  }
}

function createEnv(options?: { rateLimitPerMinute?: string; rateLimitPerHour?: string; retentionDays?: string; maxInlineBytes?: string }) {
  const bucket = new MemoryR2Store();
  const inboxes = new Map<string, FakeInboxStub>();
  const maxInlineBytes = Number(options?.maxInlineBytes ?? "128");
  const retentionDays = Number(options?.retentionDays ?? "30");
  const rateLimitPerMinute = Number(options?.rateLimitPerMinute ?? "60");
  const rateLimitPerHour = Number(options?.rateLimitPerHour ?? "600");

  const env: Env = {
    PUBLIC_BASE_URL: "https://example.com",
    DEPLOYMENT_REGION: "local",
    MAX_INLINE_BYTES: String(maxInlineBytes),
    RETENTION_DAYS: String(retentionDays),
    RATE_LIMIT_PER_MINUTE: String(rateLimitPerMinute),
    RATE_LIMIT_PER_HOUR: String(rateLimitPerHour),
    SHARING_TOKEN_SECRET: "secret",
    BOOTSTRAP_TOKEN_SECRET: "bootstrap-secret",
    TAPCHAT_STORAGE: bucket.asBucket(),
    INBOX: {
      idFromName(name: string) {
        return name as DurableObjectId;
      },
      get(id: DurableObjectId) {
        const deviceId = id as unknown as string;
        if (!inboxes.has(deviceId)) {
          inboxes.set(
            deviceId,
            new FakeInboxStub(deviceId, new MemoryState(), bucket, [], {
              maxInlineBytes,
              retentionDays,
              rateLimitPerMinute,
              rateLimitPerHour
            })
          );
        }
        return inboxes.get(deviceId) as DurableObjectStub;
      }
    } satisfies DurableObjectNamespace
  };

  return { env, bucket };
}

function sampleAppend(deviceId = "device:bob:phone", messageId = "msg:1", conversationId = "conv:alice:bob", senderUserId = "user:alice"): AppendEnvelopeRequest {
  return {
    version: CURRENT_MODEL_VERSION,
    recipientDeviceId: deviceId,
    envelope: {
      version: CURRENT_MODEL_VERSION,
      messageId,
      conversationId,
      senderUserId,
      senderDeviceId: `${senderUserId.replace("user", "device")}:phone`,
      recipientDeviceId: deviceId,
      createdAt: 1,
      messageType: "mls_application",
      inlineCiphertext: "cipher",
      storageRefs: [],
      deliveryClass: "normal",
      senderProof: {
        type: "signature",
        value: "sig"
      }
    }
  };
}

function sampleCapability(deviceId = "device:bob:phone", conversationScope?: string[], maxBytes?: number) {
  return {
    version: CURRENT_MODEL_VERSION,
    service: "inbox" as const,
    userId: "user:bob",
    targetDeviceId: deviceId,
    endpoint: `https://example.com/v1/inbox/${deviceId}/messages`,
    operations: ["append"],
    conversationScope,
    expiresAt: Date.now() + 60_000,
    constraints: maxBytes === undefined ? undefined : { maxBytes },
    signature: "append-cap-sig"
  };
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

async function issueDeviceBundle(env: Env, userId = "user:bob", deviceId = "device:bob:phone"): Promise<DeploymentBundle> {
  const requestBody: BootstrapDeviceRequest = {
    version: CURRENT_MODEL_VERSION,
    userId,
    deviceId
  };
  const response = await handleRequest(
    new Request("https://example.com/v1/bootstrap/device", {
      method: "POST",
      headers: {
        ...authHeaders(await bootstrapToken(userId, deviceId)),
        "Content-Type": "application/json"
      },
      body: JSON.stringify(requestBody)
    }),
    env
  );
  assert.equal(response.status, 200);
  return (await response.json()) as DeploymentBundle;
}

async function appendWithCapability(env: Env, append = sampleAppend()): Promise<Response> {
  const capability = sampleCapability(append.recipientDeviceId);
  return handleRequest(
    new Request(`https://example.com/v1/inbox/${append.recipientDeviceId}/messages`, {
      method: "POST",
      headers: {
        ...authHeaders(capability.signature),
        "X-Tapchat-Capability": JSON.stringify(capability),
        "Content-Type": "application/json"
      },
      body: JSON.stringify(append)
    }),
    env
  );
}

async function setAllowlist(env: Env, token: string, deviceId: string, allowedSenderUserIds: string[], rejectedSenderUserIds: string[] = []): Promise<AllowlistDocument> {
  const response = await handleRequest(
    new Request(`https://example.com/v1/inbox/${deviceId}/allowlist`, {
      method: "PUT",
      headers: {
        ...authHeaders(token),
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        allowedSenderUserIds,
        rejectedSenderUserIds
      })
    }),
    env
  );
  assert.equal(response.status, 200);
  return (await response.json()) as AllowlistDocument;
}

test("issues device deployment bundle with runtime auth and security features", async () => {
  const { env } = createEnv();
  const bundle = await issueDeviceBundle(env);

  assert.equal(bundle.version, CURRENT_MODEL_VERSION);
  assert.equal(bundle.expectedUserId, "user:bob");
  assert.equal(bundle.expectedDeviceId, "device:bob:phone");
  assert.equal(bundle.deviceRuntimeAuth?.scheme, "bearer");
  assert.deepEqual(bundle.deviceRuntimeAuth?.scopes, [
    "inbox_read",
    "inbox_ack",
    "inbox_subscribe",
    "inbox_manage",
    "storage_prepare_upload",
    "shared_state_write",
    "keypackage_write"
  ]);
  assert.ok(bundle.runtimeConfig.features.includes("message_requests"));
  assert.ok(bundle.runtimeConfig.features.includes("allowlist"));
  assert.ok(bundle.runtimeConfig.features.includes("rate_limit"));
});

test("accepts append requests only with explicit capability header", async () => {
  const { env } = createEnv();
  const response = await appendWithCapability(env);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    version: CURRENT_MODEL_VERSION,
    accepted: true,
    seq: 0,
    deliveredTo: "message_request",
    queuedAsRequest: true,
    requestId: "request:user:alice"
  });
});

test("rejects append requests without capability header", async () => {
  const { env } = createEnv();
  const response = await handleRequest(
    new Request("https://example.com/v1/inbox/device:bob:phone/messages", {
      method: "POST",
      headers: {
        ...authHeaders("append-cap-sig"),
        "Content-Type": "application/json"
      },
      body: JSON.stringify(sampleAppend())
    }),
    env
  );

  assert.equal(response.status, 401);
});

test("enforces append conversation scope and payload size", async () => {
  const { env } = createEnv();
  const wrongScope = await handleRequest(
    new Request("https://example.com/v1/inbox/device:bob:phone/messages", {
      method: "POST",
      headers: {
        ...authHeaders("append-cap-sig"),
        "X-Tapchat-Capability": JSON.stringify(sampleCapability("device:bob:phone", ["conv:other"])),
        "Content-Type": "application/json"
      },
      body: JSON.stringify(sampleAppend())
    }),
    env
  );
  assert.equal(wrongScope.status, 403);

  const tooLarge = await handleRequest(
    new Request("https://example.com/v1/inbox/device:bob:phone/messages", {
      method: "POST",
      headers: {
        ...authHeaders("append-cap-sig"),
        "X-Tapchat-Capability": JSON.stringify(sampleCapability("device:bob:phone", undefined, 1)),
        "Content-Type": "application/json"
      },
      body: JSON.stringify(sampleAppend())
    }),
    env
  );
  assert.equal(tooLarge.status, 413);
});

test("message requests stay out of inbox until accepted and reject blocks future appends", async () => {
  const { env } = createEnv();
  const bundle = await issueDeviceBundle(env);
  const token = bundle.deviceRuntimeAuth!.token;

  const queued = await appendWithCapability(env, sampleAppend("device:bob:phone", "msg:req-1"));
  assert.equal(queued.status, 200);

  const head = await handleRequest(
    new Request("https://example.com/v1/inbox/device:bob:phone/head", { headers: authHeaders(token) }),
    env
  );
  assert.deepEqual(await head.json(), { version: CURRENT_MODEL_VERSION, headSeq: 0 });

  const list = await handleRequest(
    new Request("https://example.com/v1/inbox/device:bob:phone/message-requests", { headers: authHeaders(token) }),
    env
  );
  const requests = (await list.json()) as MessageRequestListResult & { version: string };
  assert.equal(requests.requests.length, 1);
  assert.equal(requests.requests[0].senderUserId, "user:alice");

  const accept = await handleRequest(
    new Request(`https://example.com/v1/inbox/device:bob:phone/message-requests/${encodeURIComponent(requests.requests[0].requestId)}/accept`, {
      method: "POST",
      headers: authHeaders(token)
    }),
    env
  );
  assert.equal(accept.status, 200);
  const accepted = await handleRequest(
    new Request("https://example.com/v1/inbox/device:bob:phone/messages?fromSeq=1&limit=10", { headers: authHeaders(token) }),
    env
  );
  const fetched = (await accepted.json()) as { records: Array<{ messageId: string }> };
  assert.deepEqual(fetched.records.map((record) => record.messageId), ["msg:req-1"]);

  const allowlistedAppend = await appendWithCapability(env, sampleAppend("device:bob:phone", "msg:req-2"));
  assert.deepEqual(await allowlistedAppend.json(), {
    version: CURRENT_MODEL_VERSION,
    accepted: true,
    seq: 2,
    deliveredTo: "inbox"
  });

  const rejectList = await appendWithCapability(env, sampleAppend("device:bob:phone", "msg:req-3", "conv:alice:bob", "user:mallory"));
  assert.equal(rejectList.status, 200);
  const rejectRequests = await handleRequest(
    new Request("https://example.com/v1/inbox/device:bob:phone/message-requests", { headers: authHeaders(token) }),
    env
  );
  const pendingMallory = (await rejectRequests.json()) as MessageRequestListResult & { version: string };
  const malloryRequest = pendingMallory.requests.find((request) => request.senderUserId === "user:mallory");
  assert.ok(malloryRequest);

  const reject = await handleRequest(
    new Request(`https://example.com/v1/inbox/device:bob:phone/message-requests/${encodeURIComponent(malloryRequest!.requestId)}/reject`, {
      method: "POST",
      headers: authHeaders(token)
    }),
    env
  );
  assert.equal(reject.status, 200);

  const rejectedAppend = await appendWithCapability(env, sampleAppend("device:bob:phone", "msg:req-4", "conv:alice:bob", "user:mallory"));
  assert.deepEqual(await rejectedAppend.json(), {
    version: CURRENT_MODEL_VERSION,
    accepted: true,
    seq: 0,
    deliveredTo: "rejected",
    queuedAsRequest: false
  });
});

test("requires device runtime auth for head, fetch, ack, subscribe, and manage routes", async () => {
  const { env } = createEnv();
  const bundle = await issueDeviceBundle(env);
  const token = bundle.deviceRuntimeAuth!.token;
  await setAllowlist(env, token, "device:bob:phone", ["user:alice"]);
  await appendWithCapability(env);

  const unauthHead = await handleRequest(new Request("https://example.com/v1/inbox/device:bob:phone/head"), env);
  assert.equal(unauthHead.status, 401);

  const head = await handleRequest(
    new Request("https://example.com/v1/inbox/device:bob:phone/head", { headers: authHeaders(token) }),
    env
  );
  assert.deepEqual(await head.json(), { version: CURRENT_MODEL_VERSION, headSeq: 1 });

  const fetch = await handleRequest(
    new Request("https://example.com/v1/inbox/device:bob:phone/messages?fromSeq=1&limit=10", {
      headers: authHeaders(token)
    }),
    env
  );
  const fetched = (await fetch.json()) as { version: string; records: Array<{ seq: number }> };
  assert.equal(fetched.version, CURRENT_MODEL_VERSION);
  assert.deepEqual(fetched.records.map((record) => record.seq), [1]);

  const ack = await handleRequest(
    new Request("https://example.com/v1/inbox/device:bob:phone/ack", {
      method: "POST",
      headers: {
        ...authHeaders(token),
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        ack: {
          deviceId: "device:bob:phone",
          ackSeq: 1,
          ackedMessageIds: ["msg:1"],
          ackedAt: 2
        }
      })
    }),
    env
  );
  assert.deepEqual(await ack.json(), { version: CURRENT_MODEL_VERSION, accepted: true, ackSeq: 1 });

  const subscribe = await handleRequest(
    new Request("https://example.com/v1/inbox/device:bob:phone/subscribe", {
      headers: {
        ...authHeaders(token),
        Upgrade: "websocket"
      }
    }),
    env
  );
  assert.equal(subscribe.status, 200);

  const listRequests = await handleRequest(
    new Request("https://example.com/v1/inbox/device:bob:phone/message-requests", { headers: authHeaders(token) }),
    env
  );
  assert.equal(listRequests.status, 200);
});

test("rate limit is per recipient sender pair and idempotent retries do not consume extra quota", async () => {
  const { env } = createEnv({ rateLimitPerMinute: "1", rateLimitPerHour: "10" });
  const bundle = await issueDeviceBundle(env);
  const token = bundle.deviceRuntimeAuth!.token;
  await setAllowlist(env, token, "device:bob:phone", ["user:alice", "user:mallory"]);

  const first = await appendWithCapability(env, sampleAppend("device:bob:phone", "msg:rl-1", "conv:alice:bob", "user:alice"));
  assert.equal(first.status, 200);

  const duplicate = await appendWithCapability(env, sampleAppend("device:bob:phone", "msg:rl-1", "conv:alice:bob", "user:alice"));
  assert.equal(duplicate.status, 200);
  assert.deepEqual(await duplicate.json(), {
    version: CURRENT_MODEL_VERSION,
    accepted: true,
    seq: 1,
    deliveredTo: "inbox"
  });

  const limited = await appendWithCapability(env, sampleAppend("device:bob:phone", "msg:rl-2", "conv:alice:bob", "user:alice"));
  assert.equal(limited.status, 429);

  const otherSender = await appendWithCapability(env, sampleAppend("device:bob:phone", "msg:rl-3", "conv:alice:bob", "user:mallory"));
  assert.equal(otherSender.status, 200);
});

test("prepare-upload requires runtime auth and sharing url still gates blob access", async () => {
  const { env } = createEnv();
  const bundle = await issueDeviceBundle(env);

  const unauthorized = await handleRequest(
    new Request("https://example.com/v1/storage/prepare-upload", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        taskId: "task-1",
        conversationId: "conv:alice:bob",
        messageId: "msg:blob",
        mimeType: "application/octet-stream",
        sizeBytes: 4
      })
    }),
    env
  );
  assert.equal(unauthorized.status, 401);

  const prepare = await handleRequest(
    new Request("https://example.com/v1/storage/prepare-upload", {
      method: "POST",
      headers: {
        ...authHeaders(bundle.deviceRuntimeAuth!.token),
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        taskId: "task-1",
        conversationId: "conv:alice:bob",
        messageId: "msg:blob",
        mimeType: "application/octet-stream",
        sizeBytes: 4
      })
    }),
    env
  );
  assert.equal(prepare.status, 200);
  const prepared = (await prepare.json()) as {
    version: string;
    uploadTarget: string;
    downloadTarget: string;
    blobRef: string;
  };
  assert.equal(prepared.version, CURRENT_MODEL_VERSION);
  assert.equal(prepared.blobRef, "blob/user:bob/device:bob:phone/conv:alice:bob/msg:blob-task-1");

  const upload = await handleRequest(
    new Request(prepared.uploadTarget, {
      method: "PUT",
      headers: { "Content-Type": "application/octet-stream" },
      body: new Uint8Array([1, 2, 3, 4])
    }),
    env
  );
  const download = await handleRequest(new Request(prepared.downloadTarget), env);

  assert.equal(upload.status, 204);
  assert.equal(download.status, 200);
  assert.deepEqual(new Uint8Array(await download.arrayBuffer()), new Uint8Array([1, 2, 3, 4]));
});

test("shared-state writes accept device runtime auth", async () => {
  const { env } = createEnv();
  const bundle = await issueDeviceBundle(env, "user:alice", "device:alice:phone");
  const identityBundle: IdentityBundle = {
    version: CURRENT_MODEL_VERSION,
    userId: "user:alice",
    userPublicKey: "alice-pub",
    devices: [],
    updatedAt: 2,
    signature: "bundle-sig"
  };

  const put = await handleRequest(
    new Request("https://example.com/v1/shared-state/user%3Aalice/identity-bundle", {
      method: "PUT",
      headers: {
        ...authHeaders(bundle.deviceRuntimeAuth!.token),
        "Content-Type": "application/json"
      },
      body: JSON.stringify(identityBundle)
    }),
    env
  );
  assert.equal(put.status, 200);
  const get = await handleRequest(new Request("https://example.com/v1/shared-state/user%3Aalice/identity-bundle"), env);
  assert.equal(get.status, 200);
});

test("ack semantics reject backwards ack and cleanup only removes expired acked records", async () => {
  const state = new MemoryState();
  const spillStore = new MemoryR2Store();
  const service = new InboxService("device:bob:phone", state, spillStore, [], {
    headSeq: 0,
    ackedSeq: 0,
    retentionDays: 1,
    maxInlineBytes: 1,
    rateLimitPerMinute: 100,
    rateLimitPerHour: 1000
  });

  await service.replaceAllowlist(["user:alice"], [], 500);
  const delivered = await service.appendEnvelope(sampleAppend(), 1_000);
  assert.equal(delivered.seq, 1);
  assert.equal(spillStore.has("inbox-payload/device:bob:phone/1.json"), true);

  await service.cleanExpiredRecords(1_000 + 2 * 24 * 60 * 60 * 1000);
  const withoutAck = await service.fetchMessages({ deviceId: "device:bob:phone", fromSeq: 1, limit: 10 });
  assert.equal(withoutAck.records.length, 1);

  await service.ack({
    ack: {
      deviceId: "device:bob:phone",
      ackSeq: 1,
      ackedAt: 1_500
    }
  });

  await assert.rejects(
    () => service.ack({
      ack: {
        deviceId: "device:bob:phone",
        ackSeq: 0,
        ackedAt: 1_600
      }
    }),
    /ack_seq must not move backwards/
  );

  await service.cleanExpiredRecords(1_000 + 12 * 60 * 60 * 1000);
  const beforeExpiry = await service.fetchMessages({ deviceId: "device:bob:phone", fromSeq: 1, limit: 10 });
  assert.equal(beforeExpiry.records.length, 1);

  await service.cleanExpiredRecords(1_000 + 2 * 24 * 60 * 60 * 1000);
  const afterExpiry = await service.fetchMessages({ deviceId: "device:bob:phone", fromSeq: 1, limit: 10 });
  assert.equal(afterExpiry.records.length, 0);
  assert.equal(spillStore.has("inbox-payload/device:bob:phone/1.json"), false);
  assert.deepEqual(await service.getHead(), { headSeq: 1 });
});





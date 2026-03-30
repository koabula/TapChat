import test from "node:test";
import assert from "node:assert/strict";
import {
  CURRENT_MODEL_VERSION,
  type AppendEnvelopeRequest,
  type BootstrapDeviceRequest,
  type DeploymentBundle,
  type IdentityBundle
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

  constructor(deviceId: string, state: MemoryState, spillStore: MemoryR2Store, sessions: SessionSink[]) {
    this.deviceId = deviceId;
    this.state = state;
    this.spillStore = spillStore;
    this.sessions = sessions;
  }

  async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const request = input instanceof Request ? input : new Request(input, init);
    return handleInboxDurableRequest(request, {
      deviceId: this.deviceId,
      state: this.state,
      spillStore: this.spillStore,
      sessions: this.sessions,
      maxInlineBytes: 128,
      retentionDays: 30,
      onUpgrade: () => new Response(null, { status: 200 }),
      now: 1_000
    });
  }
}

function createEnv() {
  const bucket = new MemoryR2Store();
  const inboxes = new Map<string, FakeInboxStub>();

  const env: Env = {
    PUBLIC_BASE_URL: "https://example.com",
    DEPLOYMENT_REGION: "local",
    MAX_INLINE_BYTES: "128",
    RETENTION_DAYS: "30",
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
          inboxes.set(deviceId, new FakeInboxStub(deviceId, new MemoryState(), bucket, []));
        }
        return inboxes.get(deviceId) as DurableObjectStub;
      }
    } satisfies DurableObjectNamespace
  };

  return { env, bucket };
}

function sampleAppend(deviceId = "device:bob:phone", messageId = "msg:1", conversationId = "conv:alice:bob"): AppendEnvelopeRequest {
  return {
    version: CURRENT_MODEL_VERSION,
    recipientDeviceId: deviceId,
    envelope: {
      version: CURRENT_MODEL_VERSION,
      messageId,
      conversationId,
      senderUserId: "user:alice",
      senderDeviceId: "device:alice:phone",
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

test("issues device deployment bundle with runtime auth", async () => {
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
    "storage_prepare_upload",
    "shared_state_write",
    "keypackage_write"
  ]);
});

test("accepts append requests only with explicit capability header", async () => {
  const { env } = createEnv();
  const append = sampleAppend();
  const capability = sampleCapability();

  const response = await handleRequest(
    new Request("https://example.com/v1/inbox/device:bob:phone/messages", {
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

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { version: CURRENT_MODEL_VERSION, accepted: true, seq: 1 });
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

test("requires device runtime auth for head, fetch, ack, and subscribe", async () => {
  const { env } = createEnv();
  const bundle = await issueDeviceBundle(env);
  const token = bundle.deviceRuntimeAuth!.token;
  const capability = sampleCapability();

  await handleRequest(
    new Request("https://example.com/v1/inbox/device:bob:phone/messages", {
      method: "POST",
      headers: {
        ...authHeaders(capability.signature),
        "X-Tapchat-Capability": JSON.stringify(capability),
        "Content-Type": "application/json"
      },
      body: JSON.stringify(sampleAppend())
    }),
    env
  );

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

test("ack plus cleanup removes only expired acked records", async () => {
  const state = new MemoryState();
  const spillStore = new MemoryR2Store();
  const service = new InboxService("device:bob:phone", state, spillStore, [], {
    headSeq: 0,
    ackedSeq: 0,
    retentionDays: 1,
    maxInlineBytes: 1
  });

  await service.appendEnvelope(sampleAppend(), 1_000);
  assert.equal(spillStore.has("inbox-payload/device:bob:phone/1.json"), true);

  await service.ack({
    ack: {
      deviceId: "device:bob:phone",
      ackSeq: 1,
      ackedAt: 1_500
    }
  });

  await service.cleanExpiredRecords(1_000 + 12 * 60 * 60 * 1000);
  const beforeExpiry = await service.fetchMessages({ deviceId: "device:bob:phone", fromSeq: 1, limit: 10 });
  assert.equal(beforeExpiry.records.length, 1);

  await service.cleanExpiredRecords(1_000 + 2 * 24 * 60 * 60 * 1000);
  const afterExpiry = await service.fetchMessages({ deviceId: "device:bob:phone", fromSeq: 1, limit: 10 });
  assert.equal(afterExpiry.records.length, 0);
  assert.equal(spillStore.has("inbox-payload/device:bob:phone/1.json"), false);
});




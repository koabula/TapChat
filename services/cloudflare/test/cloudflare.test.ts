import test from "node:test";
import assert from "node:assert/strict";
import { ed25519 } from "@noble/curves/ed25519";
import {
  CURRENT_MODEL_VERSION,
  type AllowlistDocument,
  type AppendEnvelopeRequest,
  type AppendGroupEnvelopeRequest,
  type AppendGroupTransitionRequest,
  type CreateGroupInviteRequest,
  type DecideGroupJoinRequest,
  type DeploymentBundle,
  type DeviceRuntimeAuth,
  type DeviceRuntimeRefreshChallenge,
  type DeviceBinding,
  type GroupCapability,
  type GroupCapabilityOperation,
  type GroupManifest,
  type GroupMembershipProof,
  type GroupMessageType,
  type IdentityBundle,
  type InboxAppendCapability,
  type MessageRequestActionResult,
  type MessageRequestListResult,
  type SubmitGroupJoinRequest
} from "../src/types/contracts";
import type {
  DurableObjectStorageLike,
  JsonBlobStore,
  SessionSink
} from "../src/types/runtime";
import type { Env } from "../src/types/env";
import { requireDeviceRuntimeSecrets } from "../src/auth/runtime-security";
import type { RotatingSecretSet } from "../src/auth/runtime-security";
import type {
  DurableObjectId,
  DurableObjectNamespace,
  DurableObjectStub,
  R2Bucket,
  R2Object,
  R2ObjectBody
} from "./runtime-types";
import { signSharingPayload } from "../src/storage/sharing";
import {
  groupCapabilitySigningPayload,
  groupManifestSigningPayload,
  groupMembershipProofSigningPayload
} from "../src/auth/capability";
import { GroupAuthorizationService } from "../src/group-outbox/authorization";

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
const {
  handleInboxDurableRequest,
  ManagedSession: InboxManagedSession
} = await import("../src/inbox/durable");
const { deviceRuntimeSigningPayload } = await import("../src/auth/runtime-auth");
const { handleGroupOutboxDurableRequest, groupIdFromGroupOutboxRequestUrl, ManagedSession: GroupManagedSession } = await import("../src/group-outbox/durable");
const { InboxService } = await import("../src/inbox/service");
const { GroupOutboxService } = await import("../src/group-outbox/service");
const { routeFamilyForObservability } = await import("../src/index");

const TEST_SHARING_SECRET = "test-sharing-secret-0123456789abcdef0123456789abcdef";
const TEST_BOOTSTRAP_SECRET = "test-bootstrap-secret-0123456789abcdef0123456789abcdef";
const TEST_DEVICE_RUNTIME_SECRET = "test-runtime-secret-0123456789abcdef0123456789abcdef";
const TEST_DEVICE_RUNTIME_KEY_ID = "test-runtime-current";

test("observability route families never include stable path identifiers", () => {
  assert.equal(
    routeFamilyForObservability("https://worker.example/v1/groups/group:secret/outbox/messages"),
    "group_outbox"
  );
  assert.equal(
    routeFamilyForObservability("https://worker.example/v1/inbox/device:secret/messages"),
    "inbox"
  );
  assert.equal(
    routeFamilyForObservability("https://worker.example/v1/contact-share/capability-secret"),
    "contact_share"
  );
});

test("group membership proof payload matches the Rust canonical field order", () => {
  const proof: GroupMembershipProof = {
    type: "membership_signature",
    operation: "create",
    signerUserId: "user:owner",
    signerDeviceId: "device:owner",
    previousRosterVersion: 0,
    newRosterVersion: 1,
    commitMessageId: "msg:commit",
    controlMessageId: "msg:control",
    stateEventMessageId: "msg:event",
    newManifestSha256: "manifest-hash",
    signature: "signature"
  };
  assert.equal(
    groupMembershipProofSigningPayload(proof),
    [
      "tapchat.group.membership.v1",
      "proof_type=membership_signature",
      "operation=create",
      "signer_user_id=user:owner",
      "signer_device_id=device:owner",
      "previous_roster_version=0",
      "new_roster_version=1",
      "previous_commit_message_id=",
      "commit_message_id=msg:commit",
      "control_message_id=msg:control",
      "new_manifest_sha256=manifest-hash",
      "state_event_message_id=msg:event"
    ].join("\n")
  );
});

class MemoryState implements DurableObjectStorageLike {
  private readonly map = new Map<string, unknown>();
  alarmAt?: number;

  async get<T>(key: string): Promise<T | undefined> {
    return this.map.get(key) as T | undefined;
  }

  async put<T>(key: string, value: T): Promise<void> {
    this.map.set(key, value);
  }

  async putEntries(entries: Record<string, unknown>): Promise<void> {
    for (const [key, value] of Object.entries(entries)) {
      this.map.set(key, value);
    }
  }

  async mutateEntries(entries: Record<string, unknown>, deleteKeys: string[]): Promise<void> {
    const next = new Map(this.map);
    for (const [key, value] of Object.entries(entries)) {
      next.set(key, value);
    }
    for (const key of deleteKeys) {
      next.delete(key);
    }
    this.map.clear();
    for (const [key, value] of next) {
      this.map.set(key, value);
    }
  }

  async delete(key: string): Promise<void> {
    this.map.delete(key);
  }

  async list<T>(options?: { prefix?: string }): Promise<Map<string, T>> {
    const output = new Map<string, T>();
    for (const [key, value] of this.map.entries()) {
      if (!options?.prefix || key.startsWith(options.prefix)) {
        output.set(key, value as T);
      }
    }
    return output;
  }

  async setAlarm(epochMillis: number): Promise<void> {
    this.alarmAt = epochMillis;
  }

  async consumeIfEqual<T>(key: string, expected: T): Promise<boolean> {
    const current = this.map.get(key);
    if (JSON.stringify(current) !== JSON.stringify(expected)) return false;
    this.map.delete(key);
    return true;
  }
}

class MemoryR2Store implements JsonBlobStore {
  private readonly map = new Map<string, Uint8Array>();
  private readonly metadata = new Map<string, Record<string, string>>();

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

  async putBytes(key: string, value: ArrayBuffer | Uint8Array, metadata?: Record<string, string>): Promise<void> {
    this.map.set(key, value instanceof Uint8Array ? value : new Uint8Array(value));
    this.metadata.set(key, { ...(metadata ?? {}) });
  }

  async getBytes(key: string): Promise<ArrayBuffer | null> {
    const value = this.map.get(key);
    if (!value) {
      return null;
    }
    return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer;
  }

  async getBytesMetadata(key: string): Promise<{ bytes: ArrayBuffer; customMetadata: Record<string, string> } | null> {
    const bytes = await this.getBytes(key);
    return bytes ? { bytes, customMetadata: { ...(this.metadata.get(key) ?? {}) } } : null;
  }

  async delete(key: string): Promise<void> {
    this.map.delete(key);
    this.metadata.delete(key);
  }

  has(key: string): boolean {
    return this.map.has(key);
  }

  asBucket(): R2Bucket {
    const self = this;
    return {
      async put(key: string, value: string | ArrayBuffer | ArrayBufferView | ReadableStream, options?: R2PutOptions) {
        const customMetadata = options?.customMetadata ?? {};
        if (typeof value === "string") {
          await self.putBytes(key, new TextEncoder().encode(value), customMetadata);
        } else if (value instanceof ReadableStream) {
          await self.putBytes(key, await new Response(value).arrayBuffer(), customMetadata);
        } else if (value instanceof ArrayBuffer) {
          await self.putBytes(key, value, customMetadata);
        } else {
          await self.putBytes(
            key,
            value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer,
            customMetadata
          );
        }
        const size = self.map.get(key)?.byteLength ?? 0;
        return { size, httpEtag: `"memory-${size}"`, customMetadata } as R2Object;
      },
      async head(key: string) {
        const value = self.map.get(key);
        if (!value) return null;
        return {
          size: value.byteLength,
          httpEtag: `"memory-${value.byteLength}"`,
          customMetadata: { ...(self.metadata.get(key) ?? {}) },
        } as R2Object;
      },
      async get(key: string, options?: { range?: { offset: number; length: number } }) {
        const value = self.map.get(key);
        if (!value) {
          return null;
        }
        const range = options?.range;
        const selected = range
          ? value.slice(range.offset, range.offset + range.length)
          : value;
        return {
          body: new Response(
            selected.buffer.slice(selected.byteOffset, selected.byteOffset + selected.byteLength) as ArrayBuffer,
          ).body!,
          size: value.byteLength,
          httpEtag: `"memory-${value.byteLength}"`,
          async json<T>() {
            return JSON.parse(new TextDecoder().decode(selected)) as T;
          },
          async arrayBuffer() {
            return selected.buffer.slice(selected.byteOffset, selected.byteOffset + selected.byteLength) as ArrayBuffer;
          },
          customMetadata: { ...(self.metadata.get(key) ?? {}) }
        } as unknown as R2ObjectBody;
      },
      async delete(key: string) {
        self.map.delete(key);
        self.metadata.delete(key);
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

class FakeGroupOutboxStub implements DurableObjectStub {
  private readonly groupId: string;
  private readonly state: MemoryState;
  private readonly spillStore: MemoryR2Store;
  private readonly env: {
    maxInlineBytes: number;
    retentionDays: number;
    sharingSecret: string;
    deviceRuntimeSecrets: RotatingSecretSet;
  };

  constructor(
    groupId: string,
    state: MemoryState,
    spillStore: MemoryR2Store,
    env: {
      maxInlineBytes: number;
      retentionDays: number;
      sharingSecret: string;
      deviceRuntimeSecrets: RotatingSecretSet;
    }
  ) {
    this.groupId = groupId;
    this.state = state;
    this.spillStore = spillStore;
    this.env = env;
  }

  async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const request = input instanceof Request ? input : new Request(input, init);
    const authorization = new GroupAuthorizationService(this.groupId, this.state);
    const isAuthorizationBootstrap =
      new URL(request.url).pathname.endsWith("/authorization/bootstrap") &&
      request.method === "POST";
    if (!isAuthorizationBootstrap && !(await authorization.getState())) {
      await initializeGroupState(this.state, this.groupId);
    }
    return handleGroupOutboxDurableRequest(request, {
      groupId: this.groupId,
      state: this.state,
      spillStore: this.spillStore,
      maxInlineBytes: this.env.maxInlineBytes,
      retentionDays: this.env.retentionDays,
      sharingSecret: this.env.sharingSecret,
      deviceRuntimeSecrets: this.env.deviceRuntimeSecrets,
      sessions: [],
      now: 1_000
    });
  }
}

class FakeDeviceRegistryStub {
  private readonly challenges = new Map<string, DeviceRuntimeRefreshChallenge>();
  private readonly records = new Map<string, { status: "active" | "revoked"; registrationVersion: number }>();
  private readonly config: () => { runtimeId: string; userId: string; workerBuildId: string };

  constructor(config: () => { runtimeId: string; userId: string; workerBuildId: string }) {
    this.config = config;
  }

  async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const request = input instanceof Request ? input : new Request(input, init);
    const path = new URL(request.url).pathname;
    const body = request.method === "POST" ? await request.json() as Record<string, any> : {};
    const config = this.config();
    if (path.endsWith("/ready")) {
      return Response.json({
        ready: true,
        runtimeId: config.runtimeId,
        protocolVersion: 4,
        workerBuildId: config.workerBuildId,
        registrySchemaVersion: 1
      });
    }
    if (path.endsWith("/challenge")) {
      if (body.userId !== config.userId || (body.purpose !== "enroll" && body.purpose !== "refresh")) {
        return Response.json({ error: "runtime_auth_invalid" }, { status: 400 });
      }
      const record = this.records.get(body.deviceId);
      if (body.purpose === "refresh" && !record) {
        return Response.json({ error: "enrollment_required" }, { status: 403 });
      }
      if (record?.status === "revoked") {
        return Response.json({ error: "device_revoked" }, { status: 403 });
      }
      const challenge: DeviceRuntimeRefreshChallenge = {
        version: CURRENT_MODEL_VERSION,
        purpose: body.purpose,
        runtimeId: config.runtimeId,
        userId: config.userId,
        deviceId: body.deviceId,
        nonce: crypto.randomUUID(),
        expiresAt: Date.now() + 300_000
      };
      this.challenges.set(challenge.nonce, challenge);
      return Response.json(challenge);
    }
    if (path.endsWith("/enroll") || path.endsWith("/refresh")) {
      const challenge = body.challenge as DeviceRuntimeRefreshChallenge;
      const stored = this.challenges.get(challenge?.nonce);
      if (!stored || JSON.stringify(stored) !== JSON.stringify(challenge)) {
        return Response.json({ error: "challenge_replayed" }, { status: 403 });
      }
      if (challenge.expiresAt <= Date.now()) {
        return Response.json({ error: "runtime_auth_invalid" }, { status: 403 });
      }
      this.challenges.delete(challenge.nonce);
      if (path.endsWith("/enroll")) this.records.set(challenge.deviceId, { status: "active", registrationVersion: 1 });
      const record = this.records.get(challenge.deviceId);
      if (!record) return Response.json({ error: "enrollment_required" }, { status: 403 });
      if (record.status === "revoked") return Response.json({ error: "device_revoked" }, { status: 403 });
      return Response.json({ registrationVersion: record.registrationVersion });
    }
    if (path.endsWith("/authorize")) {
      const record = this.records.get(body.deviceId);
      if (record?.status === "revoked") return Response.json({ error: "device_revoked" }, { status: 403 });
      return Response.json({ active: true });
    }
    if (path.endsWith("/sync")) {
      for (const device of body.devices ?? []) {
        const existing = this.records.get(device.deviceId);
        const status = existing?.status === "revoked" || device.status === "revoked" ? "revoked" : "active";
        this.records.set(device.deviceId, {
          status,
          registrationVersion: existing && existing.status !== status ? existing.registrationVersion + 1 : existing?.registrationVersion ?? 1
        });
      }
      return Response.json({ synchronized: body.devices?.length ?? 0 });
    }
    return Response.json({ error: "not_found" }, { status: 404 });
  }
}

function createEnv(options?: {
  rateLimitPerMinute?: string;
  rateLimitPerHour?: string;
  retentionDays?: string;
  maxInlineBytes?: string;
  sharingSecret?: string;
  deviceRuntimeSecret?: string;
  deviceRuntimeKeyId?: string;
  previousDeviceRuntimeSecret?: string;
  previousDeviceRuntimeKeyId?: string;
  authRotationGraceUntilMs?: string;
}) {
  const bucket = new MemoryR2Store();
  const inboxes = new Map<string, FakeInboxStub>();
  const groupOutboxes = new Map<string, FakeGroupOutboxStub>();
  let envConfig = { runtimeId: "runtime:test", userId: "user:bob", workerBuildId: "test-worker-v4" };
  const deviceRegistry = new FakeDeviceRegistryStub(() => envConfig);
  const maxInlineBytes = Number(options?.maxInlineBytes ?? "128");
  const retentionDays = Number(options?.retentionDays ?? "30");
  const rateLimitPerMinute = Number(options?.rateLimitPerMinute ?? "60");
  const rateLimitPerHour = Number(options?.rateLimitPerHour ?? "600");
  const sharingSecret = options?.sharingSecret ?? TEST_SHARING_SECRET;
  const deviceRuntimeSecret = options?.deviceRuntimeSecret ?? TEST_DEVICE_RUNTIME_SECRET;
  const deviceRuntimeKeyId = options?.deviceRuntimeKeyId ?? TEST_DEVICE_RUNTIME_KEY_ID;
  const deviceRuntimeSecrets = requireDeviceRuntimeSecrets({
    SHARING_INTERNAL_SECRET: sharingSecret,
    DEVICE_RUNTIME_SECRET: deviceRuntimeSecret,
    DEVICE_RUNTIME_SECRET_KEY_ID: deviceRuntimeKeyId,
    DEVICE_RUNTIME_SECRET_PREVIOUS: options?.previousDeviceRuntimeSecret,
    DEVICE_RUNTIME_SECRET_PREVIOUS_KEY_ID: options?.previousDeviceRuntimeKeyId,
    AUTH_ROTATION_GRACE_UNTIL_MS: options?.authRotationGraceUntilMs
  } as Env);

  const env = {
    PUBLIC_BASE_URL: "https://example.com",
    RUNTIME_ID: envConfig.runtimeId,
    OWNER_USER_ID: envConfig.userId,
    OWNER_USER_PUBLIC_KEY: signedIdentityFixture().bundle.userPublicKey,
    WORKER_BUILD_ID: envConfig.workerBuildId,
    DEPLOYMENT_REGION: "local",
    MAX_INLINE_BYTES: String(maxInlineBytes),
    RETENTION_DAYS: String(retentionDays),
    RATE_LIMIT_PER_MINUTE: String(rateLimitPerMinute),
    RATE_LIMIT_PER_HOUR: String(rateLimitPerHour),
    SHARING_INTERNAL_SECRET: sharingSecret,
    DEVICE_RUNTIME_SECRET: deviceRuntimeSecret,
    DEVICE_RUNTIME_SECRET_KEY_ID: deviceRuntimeKeyId,
    DEVICE_RUNTIME_SECRET_PREVIOUS: options?.previousDeviceRuntimeSecret,
    DEVICE_RUNTIME_SECRET_PREVIOUS_KEY_ID: options?.previousDeviceRuntimeKeyId,
    AUTH_ROTATION_GRACE_UNTIL_MS: options?.authRotationGraceUntilMs,
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
    } satisfies DurableObjectNamespace,
    GROUP_OUTBOX: {
      idFromName(name: string) {
        return name as DurableObjectId;
      },
      get(id: DurableObjectId) {
        const groupId = id as unknown as string;
        if (!groupOutboxes.has(groupId)) {
          groupOutboxes.set(
            groupId,
            new FakeGroupOutboxStub(groupId, new MemoryState(), bucket, {
              maxInlineBytes,
              retentionDays,
              sharingSecret,
              deviceRuntimeSecrets
            })
          );
        }
        return groupOutboxes.get(groupId) as DurableObjectStub;
      }
    } satisfies DurableObjectNamespace,
    DEVICE_REGISTRY: {
      idFromName(name: string) {
        return name as DurableObjectId;
      },
      get() {
        return deviceRegistry as unknown as DurableObjectStub;
      }
    } satisfies DurableObjectNamespace
  };
  envConfig = {
    get runtimeId() { return env.RUNTIME_ID; },
    get userId() { return env.OWNER_USER_ID; },
    get workerBuildId() { return env.WORKER_BUILD_ID; }
  };

  // Node tests use in-memory structural adapters rather than real branded
  // Workers bindings. Keep the unsafe conversion at this single boundary.
  return { env: env as unknown as Env, bucket };
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

function signedIdentityFixture(options?: {
  capabilityExpiresAt?: number;
  conversationScope?: string[];
  endpoint?: string;
  maxBytes?: number;
  userId?: string;
  deviceId?: string;
}) {
  const now = Date.now();
  const userSecret = new Uint8Array(32).fill(1);
  const deviceSecret = new Uint8Array(32).fill(2);
  const userId = options?.userId ?? "user:bob";
  const deviceId = options?.deviceId ?? "device:bob:phone";
  const userPublicKey = bytesToHex(ed25519.getPublicKey(userSecret));
  const devicePublicKey = bytesToHex(ed25519.getPublicKey(deviceSecret));
  const capability: InboxAppendCapability = {
    version: CURRENT_MODEL_VERSION,
    service: "inbox",
    userId,
    targetDeviceId: deviceId,
    endpoint: options?.endpoint ?? `https://example.com/v1/inbox/${deviceId}/messages`,
    operations: ["append"],
    conversationScope: options?.conversationScope,
    expiresAt: options?.capabilityExpiresAt ?? now + 60_000,
    constraints:
      options?.maxBytes === undefined ? undefined : { maxBytes: options.maxBytes },
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
  binding.signature = signHex(userSecret, bindingPayload(binding));

  const bundle: IdentityBundle = {
    version: CURRENT_MODEL_VERSION,
    userId,
    userPublicKey,
    displayName: "Bob",
    updatedAt: now,
    bundleShareId: "share:bob",
    identityBundleRef: `https://example.com/v1/shared-state/${encodeURIComponent(userId)}/identity-bundle`,
    deviceStatusRef: `https://example.com/v1/shared-state/${encodeURIComponent(userId)}/device-status`,
    storageProfile: {
      baseUrl: "https://example.com",
      profileRef: "profile:bob"
    },
    devices: [
      {
        version: CURRENT_MODEL_VERSION,
        deviceId,
        devicePublicKey,
        binding,
        status: "active",
        inboxAppendCapability: capability,
        keypackageRef: {
          version: CURRENT_MODEL_VERSION,
          userId,
          deviceId,
          ref: `https://example.com/v1/shared-state/keypackages/${encodeURIComponent(userId)}/${encodeURIComponent(deviceId)}/kp1`,
          expiresAt: now + 60_000
        }
      }
    ],
    signature: ""
  };
  bundle.signature = signHex(userSecret, identityBundlePayload(bundle, true));
  return { bundle, capability, deviceId, userId, deviceSecret, userSecret };
}

function capabilityPayload(capability: InboxAppendCapability): string {
  const constraints = capability.constraints
    ? `${capability.constraints.maxBytes ?? ""}:${capability.constraints.maxOpsPerMinute ?? ""}`
    : "";
  return [
    capability.version,
    "Inbox",
    capability.userId,
    capability.targetDeviceId,
    capability.endpoint,
    `[${capability.operations.map((operation) => (operation === "append" ? "Append" : operation)).join(", ")}]`,
    (capability.conversationScope ?? []).join(","),
    String(capability.expiresAt),
    constraints
  ].join("|");
}

function bindingPayload(binding: DeviceBinding): string {
  return `${CURRENT_MODEL_VERSION}:${binding.userId}:${binding.deviceId}:${binding.devicePublicKey}:${binding.createdAt}`;
}

function identityBundlePayload(bundle: IdentityBundle, includeDisplayName: boolean): string {
  const parts = [bundle.version, bundle.userId, bundle.userPublicKey];
  if (includeDisplayName) {
    parts.push(bundle.displayName ?? "");
  }
  parts.push(
    String(bundle.updatedAt),
    bundle.bundleShareId ?? "",
    bundle.identityBundleRef ?? "",
    bundle.deviceStatusRef ?? "",
    bundle.storageProfile?.baseUrl ?? "",
    bundle.storageProfile?.profileRef ?? ""
  );
  for (const device of bundle.devices) {
    parts.push(device.deviceId);
    parts.push(device.devicePublicKey);
    parts.push(device.binding.signature);
    parts.push(device.inboxAppendCapability.signature);
    parts.push(device.keypackageRef.ref);
    parts.push(String(device.keypackageRef.expiresAt));
  }
  return parts.join("|");
}

function signHex(secretKey: Uint8Array, payload: string | Uint8Array): string {
  const encoded = typeof payload === "string" ? new TextEncoder().encode(payload) : payload;
  return bytesToHex(ed25519.sign(encoded, secretKey));
}

function bytesToHex(input: Uint8Array): string {
  return Array.from(input, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function sampleGroupCapability(
  groupId = "group:project",
  operations: GroupCapabilityOperation[] = ["read", "append_application", "append_control", "append_membership"],
  role: GroupCapability["role"] = "owner"
): GroupCapability {
  const identity = groupIdentityForRole(role);
  const capability: GroupCapability = {
    version: CURRENT_MODEL_VERSION,
    service: "group_outbox",
    groupId,
    userId: identity.userId,
    deviceId: identity.deviceId,
    operations,
    role,
    expiresAt: 61_000,
    signature: ""
  };
  capability.signature = signHex(identity.deviceSecret, groupCapabilitySigningPayload(capability));
  return capability;
}

function sampleGroupAppend(
  groupId = "group:project",
  messageId = "msg:group:1",
  messageType: GroupMessageType = "mls_application",
  capability = sampleGroupCapability(groupId)
): AppendGroupEnvelopeRequest {
  return {
    version: CURRENT_MODEL_VERSION,
    groupId,
    envelope: {
      version: CURRENT_MODEL_VERSION,
      messageId,
      groupId,
      conversationId: `conv:${groupId}`,
      senderUserId: capability.userId,
      senderDeviceId: capability.deviceId,
      createdAt: 1,
      messageType,
      visibility: "visible",
      inlineCiphertext: "cipher",
      storageRefs: [],
      senderProof: {
        type: "signature",
        value: "sig"
      }
    },
    capability
  };
}

test("stale group transitions are classified as roster conflicts before proof validation", async () => {
  const { env } = createEnv();
  const groupId = "group:stale-transition";
  const capability = sampleGroupCapability(
    groupId,
    ["read", "append_control", "append_membership", "update_group_metadata"],
    "admin"
  );
  const envelope = sampleGroupAppend(
    groupId,
    "msg:stale-transition",
    "control_group_metadata_updated",
    capability
  ).envelope;
  envelope.membershipProof = {
    type: "membership_signature",
    operation: "update_metadata",
    signerUserId: capability.userId,
    signerDeviceId: capability.deviceId,
    previousRosterVersion: 0,
    newRosterVersion: 1,
    commitMessageId: envelope.messageId,
    controlMessageId: envelope.messageId,
    stateEventMessageId: "msg:stale-event",
    newManifestSha256: "deliberately-not-validated",
    signature: "deliberately-not-validated"
  };
  const request: AppendGroupTransitionRequest = {
    version: CURRENT_MODEL_VERSION,
    groupId,
    transitionId: "transition:stale",
    operation: { type: "update_metadata" },
    expectedPreviousRosterVersion: 0,
    envelopes: [envelope],
    authorizationUpdate: {
      manifest: sampleGroupManifest(groupId),
      identityBundles: []
    },
    capability
  };

  const response = await handleRequest(
    new Request(`https://example.com/v1/groups/${encodeURIComponent(groupId)}/outbox/transitions`, {
      method: "POST",
      headers: {
        ...groupHeaders(capability),
        "Content-Type": "application/json"
      },
      body: JSON.stringify(request)
    }),
    env
  );
  const responseBody = await response.text();
  assert.equal(response.status, 409, responseBody);
  assert.equal((JSON.parse(responseBody) as { error?: string }).error, "roster_version_conflict");
});

interface GroupIdentityFixture {
  userId: string;
  deviceId: string;
  userSecret: Uint8Array;
  deviceSecret: Uint8Array;
  bundle: IdentityBundle;
}

function groupIdentity(userId: string, deviceId: string, userByte: number, deviceByte: number): GroupIdentityFixture {
  const userSecret = new Uint8Array(32).fill(userByte);
  const deviceSecret = new Uint8Array(32).fill(deviceByte);
  const userPublicKey = bytesToHex(ed25519.getPublicKey(userSecret));
  const devicePublicKey = bytesToHex(ed25519.getPublicKey(deviceSecret));
  const inboxCapability: InboxAppendCapability = {
    version: CURRENT_MODEL_VERSION,
    service: "inbox",
    userId,
    targetDeviceId: deviceId,
    endpoint: `https://example.com/v1/inbox/${deviceId}/messages`,
    operations: ["append"],
    expiresAt: 61_000,
    signature: ""
  };
  inboxCapability.signature = signHex(deviceSecret, capabilityPayload(inboxCapability));
  const binding: DeviceBinding = {
    version: CURRENT_MODEL_VERSION,
    userId,
    deviceId,
    devicePublicKey,
    createdAt: 1_000,
    signature: ""
  };
  binding.signature = signHex(userSecret, bindingPayload(binding));
  const bundle: IdentityBundle = {
    version: CURRENT_MODEL_VERSION,
    userId,
    userPublicKey,
    updatedAt: 1_000,
    devices: [{
      version: CURRENT_MODEL_VERSION,
      deviceId,
      devicePublicKey,
      binding,
      status: "active",
      inboxAppendCapability: inboxCapability,
      keypackageRef: {
        version: CURRENT_MODEL_VERSION,
        userId,
        deviceId,
        ref: `https://example.com/v1/shared-state/keypackages/${encodeURIComponent(userId)}/${encodeURIComponent(deviceId)}/kp1`,
        expiresAt: 61_000
      }
    }],
    signature: ""
  };
  bundle.signature = signHex(userSecret, identityBundlePayload(bundle, true));
  return { userId, deviceId, userSecret, deviceSecret, bundle };
}

const GROUP_IDENTITIES = {
  owner: groupIdentity("user:alice", "device:alice:phone", 3, 4),
  admin: groupIdentity("user:bob", "device:bob:phone", 5, 6),
  member: groupIdentity("user:carol", "device:carol:phone", 7, 8)
} as const;

function groupIdentityForRole(role: GroupCapability["role"]): GroupIdentityFixture {
  return GROUP_IDENTITIES[role];
}

function sampleGroupManifest(groupId = "group:project"): GroupManifest {
  const manifest: GroupManifest = {
    version: CURRENT_MODEL_VERSION,
    groupId,
    conversationId: `conv:${groupId}`,
    title: "Project",
    ownerUserId: GROUP_IDENTITIES.owner.userId,
    admins: [GROUP_IDENTITIES.admin.userId],
    members: [
      { userId: GROUP_IDENTITIES.owner.userId, role: "owner", status: "active" },
      { userId: GROUP_IDENTITIES.admin.userId, role: "admin", status: "active" },
      { userId: GROUP_IDENTITIES.member.userId, role: "member", status: "active" }
    ],
    memberDevices: Object.values(GROUP_IDENTITIES).map((identity) => ({
      userId: identity.userId,
      deviceId: identity.deviceId,
      status: "active"
    })),
    joinPolicy: "approval_required",
    memberInvitePolicy: "owner_admin_only",
    rosterVersion: 1,
    mlsEpochHint: 1,
    outbox: {
      endpoint: `https://example.com/v1/groups/${encodeURIComponent(groupId)}/outbox/messages`,
      subscribeEndpoint: `wss://example.com/v1/groups/${encodeURIComponent(groupId)}/outbox/subscribe`
    },
    updatedAt: 1_000,
    signerUserId: GROUP_IDENTITIES.owner.userId,
    signerDeviceId: GROUP_IDENTITIES.owner.deviceId,
    signature: ""
  };
  manifest.signature = signHex(GROUP_IDENTITIES.owner.deviceSecret, groupManifestSigningPayload(manifest));
  return manifest;
}

function sampleProvisioningGroupManifest(groupId: string): GroupManifest {
  const base = sampleGroupManifest(groupId);
  const manifest: GroupManifest = {
    ...base,
    admins: [],
    members: [base.members[0]],
    memberDevices: [base.memberDevices![0]],
    rosterVersion: 0,
    mlsEpochHint: 0,
    lastCommitMessageId: undefined,
    signature: ""
  };
  manifest.signature = signHex(
    GROUP_IDENTITIES.owner.deviceSecret,
    groupManifestSigningPayload(manifest)
  );
  return manifest;
}

async function bootstrapGroupAuthorization(
  env: Env,
  groupId: string,
  token: string
): Promise<Response> {
  return handleRequest(
    new Request(`https://example.com/v1/groups/${encodeURIComponent(groupId)}/authorization/bootstrap`, {
      method: "POST",
      headers: {
        ...authHeaders(token),
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        version: CURRENT_MODEL_VERSION,
        groupId,
        manifest: sampleProvisioningGroupManifest(groupId),
        identityBundles: [GROUP_IDENTITIES.owner.bundle]
      })
    }),
    env
  );
}

async function initializeGroupState(state: MemoryState, groupId = "group:project"): Promise<void> {
  const service = new GroupAuthorizationService(groupId, state);
  const manifest = sampleGroupManifest(groupId);
  await service.initialize(
    {
      version: CURRENT_MODEL_VERSION,
      groupId,
      manifest,
      identityBundles: Object.values(GROUP_IDENTITIES).map((identity) => identity.bundle)
    },
    {
      version: CURRENT_MODEL_VERSION,
      service: "device_runtime",
      runtimeId: "runtime:test",
      userId: GROUP_IDENTITIES.owner.userId,
      deviceId: GROUP_IDENTITIES.owner.deviceId,
      scopes: ["group_authorization_bootstrap"],
      issuedAt: 1_000,
      expiresAt: 61_000
      ,registrationVersion: 1
    },
    1_000
  );
}

test("group authorization provisions owner-only roster zero and rejects bootstrap conflicts", async () => {
  const state = new MemoryState();
  const service = new GroupAuthorizationService("group:provisioning", state);
  const base = sampleGroupManifest("group:provisioning");
  const manifest: GroupManifest = {
    ...base,
    admins: [],
    members: [base.members[0]],
    memberDevices: [base.memberDevices![0]],
    rosterVersion: 0,
    mlsEpochHint: 0,
    lastCommitMessageId: undefined,
    signature: ""
  };
  manifest.signature = signHex(GROUP_IDENTITIES.owner.deviceSecret, groupManifestSigningPayload(manifest));
  const runtime = {
    version: CURRENT_MODEL_VERSION,
    service: "device_runtime" as const,
    runtimeId: "runtime:test",
    userId: GROUP_IDENTITIES.owner.userId,
    deviceId: GROUP_IDENTITIES.owner.deviceId,
    scopes: ["group_authorization_bootstrap" as const],
    issuedAt: 1_000,
    expiresAt: 61_000,
    registrationVersion: 1
  };
  const initialized = await service.initialize({ version: CURRENT_MODEL_VERSION, groupId: manifest.groupId, manifest, identityBundles: [GROUP_IDENTITIES.owner.bundle] }, runtime, 1_000);
  assert.equal(initialized.alreadyInitialized, false);
  assert.deepEqual(await service.getPublicState(), {
    manifest,
    manifestHash: await (await import("../src/auth/capability")).groupManifestSha256(manifest),
    lastTransitionId: undefined,
    phase: "provisioning",
    materialized: false
  });
  const repeated = await service.initialize({ version: CURRENT_MODEL_VERSION, groupId: manifest.groupId, manifest, identityBundles: [GROUP_IDENTITIES.owner.bundle] }, runtime, 1_001);
  assert.equal(repeated.alreadyInitialized, true);
  await assert.rejects(
    () => service.initialize({ version: CURRENT_MODEL_VERSION, groupId: manifest.groupId, manifest: { ...manifest, title: "tampered" }, identityBundles: [GROUP_IDENTITIES.owner.bundle] }, runtime, 1_002),
    (error: unknown) => (error as { code?: string }).code === "group_authorization_conflict"
  );
  const capability = sampleGroupCapability(manifest.groupId, ["append_application"], "owner");
  const request = new Request("https://example.com", { headers: groupHeaders(capability) });
  await assert.rejects(
    () => service.authorize(request, capability, "append_application", ["owner"], 1_000),
    (error: unknown) => (error as { code?: string }).code === "group_membership_uninitialized"
  );
});

function groupHeaders(capability: GroupCapability): Record<string, string> {
  return {
    ...authHeaders(capability.signature),
    "X-Tapchat-Group-Capability": JSON.stringify(capability)
  };
}

function authHeaders(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}` };
}

type IssuedDeployment = DeploymentBundle & { runtimeCredential: DeviceRuntimeAuth };

async function issueDeviceBundle(env: Env, userId = "user:bob", deviceId = "device:bob:phone"): Promise<IssuedDeployment> {
  const fixture = signedIdentityFixture({ userId, deviceId });
  env.OWNER_USER_ID = userId;
  env.OWNER_USER_PUBLIC_KEY = fixture.bundle.userPublicKey;
  const deploymentResponse = await handleRequest(new Request("https://example.com/v1/deployment-bundle"), env);
  assert.equal(deploymentResponse.status, 200);
  const deployment = (await deploymentResponse.json()) as DeploymentBundle;
  const challengeResponse = await handleRequest(
    new Request("https://example.com/v2/runtime-auth/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ purpose: "enroll", userId, deviceId })
    }),
    env
  );
  assert.equal(challengeResponse.status, 200);
  const challenge = (await challengeResponse.json()) as DeviceRuntimeRefreshChallenge;
  const enrolled = await handleRequest(
    new Request("https://example.com/v2/runtime-auth/enroll", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        challenge,
        device: fixture.bundle.devices[0],
        signature: signHex(fixture.deviceSecret, deviceRuntimeSigningPayload(challenge))
      })
    }),
    env
  );
  assert.equal(enrolled.status, 200);
  const { runtimeCredential } = (await enrolled.json()) as { runtimeCredential: DeviceRuntimeAuth };
  const publish = await handleRequest(
    new Request(`https://example.com/v1/shared-state/${encodeURIComponent(userId)}/identity-bundle`, {
      method: "PUT",
      headers: { ...authHeaders(runtimeCredential.token), "Content-Type": "application/json" },
      body: JSON.stringify(fixture.bundle)
    }),
    env
  );
  assert.equal(publish.status, 200);
  return { ...deployment, runtimeCredential };
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

test("runtime readiness checks the device registry and reports its audience", async () => {
  const { env } = createEnv();
  const response = await handleRequest(
    new Request("https://example.com/v2/runtime/ready"),
    env
  );
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    ready: true,
    runtimeId: "runtime:test",
    protocolVersion: 4,
    workerBuildId: "test-worker-v4",
    registrySchemaVersion: 1
  });
});

test("runtime readiness reports a retryable error while the registry binding propagates", async () => {
  const { env } = createEnv();
  delete (env as unknown as Record<string, unknown>).DEVICE_REGISTRY;
  const response = await handleRequest(
    new Request("https://example.com/v2/runtime/ready"),
    env
  );
  assert.equal(response.status, 503);
  assert.equal((await response.json() as { error: string }).error, "temporary_unavailable");
});

test("issues device deployment bundle with runtime auth and security features", async () => {
  const { env } = createEnv();
  const bundle = await issueDeviceBundle(env);

  assert.equal(bundle.version, CURRENT_MODEL_VERSION);
  assert.equal(bundle.runtimeId, "runtime:test");
  assert.equal(bundle.runtimeCredential.scheme, "bearer");
  assert.deepEqual(bundle.runtimeCredential.scopes, [
    "inbox_read",
    "inbox_ack",
    "inbox_subscribe",
    "inbox_manage",
    "group_authorization_bootstrap",
    "storage_prepare_upload",
    "shared_state_write",
    "keypackage_write"
  ]);
  assert.ok(bundle.runtimeConfig.features.includes("message_requests"));
  assert.ok(bundle.runtimeConfig.features.includes("allowlist"));
  assert.ok(bundle.runtimeConfig.features.includes("rate_limit"));
  assert.ok(bundle.runtimeConfig.features.includes("group_outbox_mvp"));
  assert.ok(bundle.runtimeConfig.features.includes("welcome_pickup_mvp"));
  assert.ok(bundle.runtimeConfig.features.includes("group_authorization_v2"));
});

test("group authorization bootstrap uses dedicated rotating device runtime secrets", async () => {
  const currentSecret = "group-runtime-current-0123456789abcdef0123456789abcdef";
  const previousSecret = "group-runtime-previous-0123456789abcdef0123456789abcdef";
  const currentKeyId = "group-runtime-current";
  const previousKeyId = "group-runtime-previous";
  const graceUntil = Date.now() + 60_000;
  const { env } = createEnv({
    deviceRuntimeSecret: currentSecret,
    deviceRuntimeKeyId: currentKeyId,
    previousDeviceRuntimeSecret: previousSecret,
    previousDeviceRuntimeKeyId: previousKeyId,
    authRotationGraceUntilMs: String(graceUntil)
  });

  const runtimePayload = {
    version: CURRENT_MODEL_VERSION,
    service: "device_runtime" as const,
    runtimeId: "runtime:test",
    userId: GROUP_IDENTITIES.owner.userId,
    deviceId: GROUP_IDENTITIES.owner.deviceId,
    scopes: ["group_authorization_bootstrap" as const],
    issuedAt: Date.now(),
    expiresAt: Date.now() + 60_000,
    registrationVersion: 1
  };
  const forgedWithSharingSecret = await signSharingPayload(TEST_SHARING_SECRET, {
    ...runtimePayload,
    keyId: currentKeyId
  });
  assert.equal(
    (await bootstrapGroupAuthorization(env, "group:dedicated-forged", forgedWithSharingSecret)).status,
    403
  );
  const forgedWithBootstrapSecret = await signSharingPayload(TEST_BOOTSTRAP_SECRET, {
    ...runtimePayload,
    keyId: currentKeyId
  });
  assert.equal(
    (await bootstrapGroupAuthorization(env, "group:dedicated-bootstrap-forged", forgedWithBootstrapSecret)).status,
    403
  );

  const bundle = await issueDeviceBundle(
    env,
    GROUP_IDENTITIES.owner.userId,
    GROUP_IDENTITIES.owner.deviceId
  );
  assert.equal(
    (await bootstrapGroupAuthorization(env, "group:dedicated-current", bundle.runtimeCredential.token)).status,
    200
  );

  const previousToken = await signSharingPayload(previousSecret, {
    ...runtimePayload,
    keyId: previousKeyId
  });
  assert.equal(
    (await bootstrapGroupAuthorization(env, "group:dedicated-previous", previousToken)).status,
    200
  );

  const expired = createEnv({
    deviceRuntimeSecret: currentSecret,
    deviceRuntimeKeyId: currentKeyId,
    previousDeviceRuntimeSecret: previousSecret,
    previousDeviceRuntimeKeyId: previousKeyId,
    authRotationGraceUntilMs: "999"
  });
  assert.equal(
    (await bootstrapGroupAuthorization(expired.env, "group:dedicated-expired", previousToken)).status,
    403
  );
});

test("device runtime current and previous keys obey the hard grace deadline", async () => {
  const currentSecret = "runtime-current-secret-0123456789abcdef0123456789abcdef";
  const previousSecret = "runtime-previous-secret-0123456789abcdef0123456789abcdef";
  const graceUntil = Date.now() + 60_000;
  const { env } = createEnv({
    deviceRuntimeSecret: currentSecret,
    deviceRuntimeKeyId: "runtime-current",
    previousDeviceRuntimeSecret: previousSecret,
    previousDeviceRuntimeKeyId: "runtime-previous",
    authRotationGraceUntilMs: String(graceUntil)
  });
  const payload = {
    version: CURRENT_MODEL_VERSION,
    service: "device_runtime",
    runtimeId: "runtime:test",
    userId: "user:bob",
    deviceId: "device:bob:phone",
    scopes: ["inbox_read"],
    issuedAt: Date.now(),
    expiresAt: Date.now() + 60_000,
    registrationVersion: 1
  };
  const current = await signSharingPayload(currentSecret, { ...payload, keyId: "runtime-current" });
  const previous = await signSharingPayload(previousSecret, { ...payload, keyId: "runtime-previous" });
  const unkeyedLegacy = await signSharingPayload(previousSecret, payload);
  for (const token of [current, previous]) {
    const response = await handleRequest(
      new Request("https://example.com/v1/inbox/device:bob:phone/head", { headers: authHeaders(token) }),
      env
    );
    assert.equal(response.status, 200);
  }
  const unkeyed = await handleRequest(
    new Request("https://example.com/v1/inbox/device:bob:phone/head", { headers: authHeaders(unkeyedLegacy) }),
    env
  );
  assert.equal(unkeyed.status, 403);

  const expired = createEnv({
    deviceRuntimeSecret: currentSecret,
    deviceRuntimeKeyId: "runtime-current",
    previousDeviceRuntimeSecret: previousSecret,
    previousDeviceRuntimeKeyId: "runtime-previous",
    authRotationGraceUntilMs: String(Date.now() - 1)
  });
  for (const token of [previous, unkeyedLegacy]) {
    const response = await handleRequest(
      new Request("https://example.com/v1/inbox/device:bob:phone/head", { headers: authHeaders(token) }),
      expired.env
    );
    assert.equal(response.status, 403);
  }
  const currentAfterGrace = await handleRequest(
    new Request("https://example.com/v1/inbox/device:bob:phone/head", { headers: authHeaders(current) }),
    expired.env
  );
  assert.equal(currentAfterGrace.status, 200);
});

test("v2 device-signed runtime refresh issues 24h audience-bound credentials and consumes challenges once", async () => {
  const runtimeSecret = "runtime-refresh-secret-0123456789abcdef0123456789abcdef";
  const { env } = createEnv({
    deviceRuntimeSecret: runtimeSecret,
    deviceRuntimeKeyId: "runtime-refresh"
  });
  const fixture = signedIdentityFixture();
  const issued = await issueDeviceBundle(env);

  const challengeResponse = await handleRequest(
    new Request("https://example.com/v2/runtime-auth/challenge", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ purpose: "refresh", userId: fixture.userId, deviceId: fixture.deviceId })
    }),
    env
  );
  assert.equal(challengeResponse.status, 200);
  const challenge = (await challengeResponse.json()) as DeviceRuntimeRefreshChallenge;
  const proof = {
    challenge,
    signature: signHex(fixture.deviceSecret, deviceRuntimeSigningPayload(challenge))
  };
  const refreshRequest = () =>
    new Request("https://example.com/v2/runtime-auth/refresh", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(proof)
    });
  const refreshed = await handleRequest(refreshRequest(), env);
  assert.equal(refreshed.status, 200);
  const refreshedBody = (await refreshed.json()) as { runtimeCredential: DeviceRuntimeAuth };
  assert.equal(refreshedBody.runtimeCredential.keyId, "runtime-refresh");
  assert.equal(refreshedBody.runtimeCredential.runtimeId, issued.runtimeId);
  assert.equal(refreshedBody.runtimeCredential.expiresAt - refreshedBody.runtimeCredential.issuedAt, 24 * 60 * 60 * 1000);
  assert.ok(refreshedBody.runtimeCredential.token.length > 32);

  const replay = await handleRequest(refreshRequest(), env);
  assert.equal(replay.status, 403);
  assert.equal((await replay.json() as { error: string }).error, "challenge_replayed");

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

test("verified append capability delivers allowlisted sender to inbox", async () => {
  const { env, bucket } = createEnv();
  const bundle = await issueDeviceBundle(env);
  const token = bundle.runtimeCredential.token;
  const fixture = signedIdentityFixture();
  await bucket.putJson("shared-state/user:bob/identity_bundle.json", fixture.bundle);
  await setAllowlist(env, token, fixture.deviceId, ["user:alice"]);

  const append = sampleAppend(fixture.deviceId, "msg:signed");
  const response = await handleRequest(
    new Request(`https://example.com/v1/inbox/${fixture.deviceId}/messages`, {
      method: "POST",
      headers: {
        ...authHeaders(fixture.capability.signature),
        "X-Tapchat-Capability": JSON.stringify(fixture.capability),
        "Content-Type": "application/json"
      },
      body: JSON.stringify(append)
    }),
    env
  );

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    version: CURRENT_MODEL_VERSION,
    accepted: true,
    seq: 1,
    deliveredTo: "inbox"
  });

  const head = await handleRequest(
    new Request(`https://example.com/v1/inbox/${fixture.deviceId}/head`, {
      headers: authHeaders(token)
    }),
    env
  );
  assert.deepEqual(await head.json(), { version: CURRENT_MODEL_VERSION, headSeq: 1 });
});

test("tampered append grant stays in message requests even when sender is allowlisted", async () => {
  const { env, bucket } = createEnv();
  const bundle = await issueDeviceBundle(env);
  const token = bundle.runtimeCredential.token;
  const fixture = signedIdentityFixture();
  await bucket.putJson("shared-state/user:bob/identity_bundle.json", fixture.bundle);
  await setAllowlist(env, token, fixture.deviceId, ["user:alice"]);

  const tamperedSignature = `${fixture.capability.signature[0] === "0" ? "1" : "0"}${fixture.capability.signature.slice(1)}`;
  const response = await handleRequest(
    new Request(`https://example.com/v1/inbox/${fixture.deviceId}/messages`, {
      method: "POST",
      headers: {
        ...authHeaders(tamperedSignature),
        "X-Tapchat-Capability": JSON.stringify(fixture.capability),
        "Content-Type": "application/json"
      },
      body: JSON.stringify(sampleAppend(fixture.deviceId, "msg:tampered"))
    }),
    env
  );

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

test("expired signed append grant stays in message requests even when sender is allowlisted", async () => {
  const { env, bucket } = createEnv();
  const bundle = await issueDeviceBundle(env);
  const token = bundle.runtimeCredential.token;
  const fixture = signedIdentityFixture({ capabilityExpiresAt: Date.now() - 1 });
  await bucket.putJson("shared-state/user:bob/identity_bundle.json", fixture.bundle);
  await setAllowlist(env, token, fixture.deviceId, ["user:alice"]);

  const response = await handleRequest(
    new Request(`https://example.com/v1/inbox/${fixture.deviceId}/messages`, {
      method: "POST",
      headers: {
        ...authHeaders(fixture.capability.signature),
        "X-Tapchat-Capability": JSON.stringify(fixture.capability),
        "Content-Type": "application/json"
      },
      body: JSON.stringify(sampleAppend(fixture.deviceId, "msg:expired-signed"))
    }),
    env
  );

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    version: CURRENT_MODEL_VERSION,
    accepted: true,
    seq: 0,
    deliveredTo: "message_request",
    queuedAsRequest: true,
    requestId: "request:user:alice"
  });

  const head = await handleRequest(
    new Request(`https://example.com/v1/inbox/${fixture.deviceId}/head`, {
      headers: authHeaders(token)
    }),
    env
  );
  assert.deepEqual(await head.json(), { version: CURRENT_MODEL_VERSION, headSeq: 0 });
});

test("signed append grant with mismatched target or endpoint is rejected", async () => {
  {
    const { env, bucket } = createEnv();
    const fixture = signedIdentityFixture();
    await bucket.putJson("shared-state/user:bob/identity_bundle.json", fixture.bundle);
    const response = await handleRequest(
      new Request("https://example.com/v1/inbox/device:bob:tablet/messages", {
        method: "POST",
        headers: {
          ...authHeaders(fixture.capability.signature),
          "X-Tapchat-Capability": JSON.stringify(fixture.capability),
          "Content-Type": "application/json"
        },
        body: JSON.stringify(sampleAppend("device:bob:tablet", "msg:target-mismatch"))
      }),
      env
    );
    assert.equal(response.status, 403);
  }

  {
    const { env, bucket } = createEnv();
    const fixture = signedIdentityFixture({
      endpoint: "https://example.com/v1/inbox/device:bob:phone/wrong"
    });
    await bucket.putJson("shared-state/user:bob/identity_bundle.json", fixture.bundle);
    const response = await handleRequest(
      new Request(`https://example.com/v1/inbox/${fixture.deviceId}/messages`, {
        method: "POST",
        headers: {
          ...authHeaders(fixture.capability.signature),
          "X-Tapchat-Capability": JSON.stringify(fixture.capability),
          "Content-Type": "application/json"
        },
        body: JSON.stringify(sampleAppend(fixture.deviceId, "msg:endpoint-mismatch"))
      }),
      env
    );
    assert.equal(response.status, 403);
  }
});

test("routes append requests without capability header to message requests", async () => {
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
  const token = bundle.runtimeCredential.token;

  const queued = await appendWithCapability(env, sampleAppend("device:bob:phone", "msg:req-1"));
  assert.equal(queued.status, 200);
  const queuedWelcome = await appendWithCapability(env, sampleAppend("device:bob:phone", "msg:req-1b"));
  assert.equal(queuedWelcome.status, 200);

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
  assert.equal(requests.requests[0].messageCount, 2);

  const accept = await handleRequest(
    new Request(`https://example.com/v1/inbox/device:bob:phone/message-requests/${encodeURIComponent(requests.requests[0].requestId)}/accept`, {
      method: "POST",
      headers: authHeaders(token)
    }),
    env
  );
  assert.equal(accept.status, 200);
  const acceptResult = (await accept.json()) as MessageRequestActionResult & { version: string };
  assert.equal(acceptResult.promotedCount, 2);
  assert.deepEqual(acceptResult.promotedConversationIds, ["conv:alice:bob"]);

  const accepted = await handleRequest(
    new Request("https://example.com/v1/inbox/device:bob:phone/messages?fromSeq=1&limit=10", { headers: authHeaders(token) }),
    env
  );
  const fetched = (await accepted.json()) as { records: Array<{ messageId: string }> };
  assert.deepEqual(fetched.records.map((record) => record.messageId), ["msg:req-1", "msg:req-1b"]);

  const allowlistedAppend = await appendWithCapability(env, sampleAppend("device:bob:phone", "msg:req-2"));
  assert.deepEqual(await allowlistedAppend.json(), {
    version: CURRENT_MODEL_VERSION,
    accepted: true,
    seq: 0,
    deliveredTo: "message_request",
    queuedAsRequest: true,
    requestId: "request:user:alice"
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
  const rejectResult = (await reject.json()) as MessageRequestActionResult & { version: string };
  assert.deepEqual(rejectResult.promotedConversationIds, []);

  const rejectedAppend = await appendWithCapability(env, sampleAppend("device:bob:phone", "msg:req-4", "conv:alice:bob", "user:mallory"));
  assert.deepEqual(await rejectedAppend.json(), {
    version: CURRENT_MODEL_VERSION,
    accepted: true,
    seq: 0,
    deliveredTo: "rejected",
    queuedAsRequest: false
  });
});

test("direct message request accept promotes only the latest conversation group", async () => {
  const { env } = createEnv();
  const bundle = await issueDeviceBundle(env);
  const token = bundle.runtimeCredential.token;

  await appendWithCapability(env, sampleAppend("device:bob:phone", "msg:old-commit", "conv:alice:bob:rel:1"));
  await appendWithCapability(env, sampleAppend("device:bob:phone", "msg:old-welcome", "conv:alice:bob:rel:1"));
  await appendWithCapability(env, sampleAppend("device:bob:phone", "msg:new-commit", "conv:alice:bob:rel:2"));
  await appendWithCapability(env, sampleAppend("device:bob:phone", "msg:new-welcome", "conv:alice:bob:rel:2"));

  const list = await handleRequest(
    new Request("https://example.com/v1/inbox/device:bob:phone/message-requests", { headers: authHeaders(token) }),
    env
  );
  const requests = (await list.json()) as MessageRequestListResult & { version: string };
  assert.equal(requests.requests.length, 1);
  assert.equal(requests.requests[0].lastConversationId, "conv:alice:bob:rel:2");
  assert.equal(requests.requests[0].messageCount, 4);

  const accept = await handleRequest(
    new Request(`https://example.com/v1/inbox/device:bob:phone/message-requests/${encodeURIComponent(requests.requests[0].requestId)}/accept`, {
      method: "POST",
      headers: authHeaders(token)
    }),
    env
  );
  assert.equal(accept.status, 200);
  const acceptResult = (await accept.json()) as MessageRequestActionResult & { version: string };
  assert.equal(acceptResult.promotedCount, 2);
  assert.deepEqual(acceptResult.promotedConversationIds, ["conv:alice:bob:rel:2"]);

  const accepted = await handleRequest(
    new Request("https://example.com/v1/inbox/device:bob:phone/messages?fromSeq=1&limit=10", { headers: authHeaders(token) }),
    env
  );
  const fetched = (await accepted.json()) as { records: Array<{ messageId: string; envelope: { conversationId: string } }> };
  assert.deepEqual(fetched.records.map((record) => record.messageId), ["msg:new-commit", "msg:new-welcome"]);
  assert.deepEqual(
    fetched.records.map((record) => record.envelope.conversationId),
    ["conv:alice:bob:rel:2", "conv:alice:bob:rel:2"]
  );

  const oldRetry = await appendWithCapability(env, sampleAppend("device:bob:phone", "msg:old-commit", "conv:alice:bob:rel:1"));
  assert.deepEqual(await oldRetry.json(), {
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
  const token = bundle.runtimeCredential.token;
  await setAllowlist(env, token, "device:bob:phone", ["user:alice"]);
  await appendWithCapability(env);

  const unauthHead = await handleRequest(new Request("https://example.com/v1/inbox/device:bob:phone/head"), env);
  assert.equal(unauthHead.status, 403);

  const head = await handleRequest(
    new Request("https://example.com/v1/inbox/device:bob:phone/head", { headers: authHeaders(token) }),
    env
  );
  assert.deepEqual(await head.json(), { version: CURRENT_MODEL_VERSION, headSeq: 0 });

  const fetch = await handleRequest(
    new Request("https://example.com/v1/inbox/device:bob:phone/messages?fromSeq=1&limit=10", {
      headers: authHeaders(token)
    }),
    env
  );
  const fetched = (await fetch.json()) as { version: string; records: Array<{ seq: number }> };
  assert.equal(fetched.version, CURRENT_MODEL_VERSION);
  assert.deepEqual(fetched.records.map((record) => record.seq), []);

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
          ackSeq: 0,
          ackedMessageIds: [],
          ackedAt: 2
        }
      })
    }),
    env
  );
  assert.deepEqual(await ack.json(), { version: CURRENT_MODEL_VERSION, accepted: true, ackSeq: 0 });

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
  const token = bundle.runtimeCredential.token;
  await setAllowlist(env, token, "device:bob:phone", ["user:alice", "user:mallory"]);

  const first = await appendWithCapability(env, sampleAppend("device:bob:phone", "msg:rl-1", "conv:alice:bob", "user:alice"));
  assert.equal(first.status, 200);

  const duplicate = await appendWithCapability(env, sampleAppend("device:bob:phone", "msg:rl-1", "conv:alice:bob", "user:alice"));
  assert.equal(duplicate.status, 200);
  assert.deepEqual(await duplicate.json(), {
    version: CURRENT_MODEL_VERSION,
    accepted: true,
    seq: 0,
    deliveredTo: "message_request",
    queuedAsRequest: true,
    requestId: "request:user:alice"
  });

  const limited = await appendWithCapability(env, sampleAppend("device:bob:phone", "msg:rl-2", "conv:alice:bob", "user:alice"));
  assert.equal(limited.status, 429);

  const otherSender = await appendWithCapability(env, sampleAppend("device:bob:phone", "msg:rl-3", "conv:alice:bob", "user:mallory"));
  assert.equal(otherSender.status, 200);
});

test("prepare-upload requires runtime auth and blob-scoped capability gates access", async () => {
  const { env } = createEnv();
  const bundle = await issueDeviceBundle(env);

  const unauthorized = await handleRequest(
    new Request("https://example.com/v1/storage/prepare-upload", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        taskId: "task-1",
        conversationId: "conv:alice:bob",
        storageScope: "direct",
        messageId: "msg:blob",
        variant: "original",
        sizeBytes: 4
      })
    }),
    env
  );
  assert.equal(unauthorized.status, 403);

  const prepare = await handleRequest(
    new Request("https://example.com/v1/storage/prepare-upload", {
      method: "POST",
      headers: {
        ...authHeaders(bundle.runtimeCredential.token),
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        taskId: "task-1",
        conversationId: "conv:alice:bob",
        messageId: "msg:blob",
        variant: "original",
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
    readCapability: string;
    blobRef: string;
  };
  assert.equal(prepared.version, CURRENT_MODEL_VERSION);
  assert.equal(prepared.blobRef, "blobs/original/user:bob/device:bob:phone/direct/direct/conv:alice:bob/msg:blob-task-1");
  assert.ok(prepared.downloadTarget);
  assert.ok(prepared.readCapability);

  const wrongSize = await handleRequest(
    new Request(prepared.uploadTarget, {
      method: "PUT",
      headers: { "Content-Type": "application/octet-stream", "Content-Length": "3" },
      body: new Uint8Array([1, 2, 3])
    }),
    env
  );
  assert.equal(wrongSize.status, 400);

  const upload = await handleRequest(
    new Request(prepared.uploadTarget, {
      method: "PUT",
      headers: { "Content-Type": "application/octet-stream", "Content-Length": "4" },
      body: new Uint8Array([1, 2, 3, 4])
    }),
    env
  );

  assert.equal(upload.status, 204);
  const missingCapability = await handleRequest(new Request(prepared.downloadTarget), env);
  assert.equal(missingCapability.status, 401);
  const wrongCapability = await handleRequest(new Request(prepared.downloadTarget, {
    headers: { Authorization: "TapChat-Blob wrong-object-capability" }
  }), env);
  assert.equal(wrongCapability.status, 403);
  const download = await handleRequest(new Request(prepared.downloadTarget, {
    headers: { Authorization: `TapChat-Blob ${prepared.readCapability}` }
  }), env);
  assert.equal(download.status, 200);
  assert.equal(download.headers.get("accept-ranges"), "bytes");
  assert.equal(download.headers.get("content-length"), "4");
  assert.deepEqual(new Uint8Array(await download.arrayBuffer()), new Uint8Array([1, 2, 3, 4]));

  const openRange = await handleRequest(new Request(prepared.downloadTarget, {
    headers: {
      Authorization: `TapChat-Blob ${prepared.readCapability}`,
      Range: "bytes=1-",
    },
  }), env);
  assert.equal(openRange.status, 206);
  assert.equal(openRange.headers.get("content-range"), "bytes 1-3/4");
  assert.deepEqual(Array.from(new Uint8Array(await openRange.arrayBuffer())), [2, 3, 4]);

  const closedRange = await handleRequest(new Request(prepared.downloadTarget, {
    headers: {
      Authorization: `TapChat-Blob ${prepared.readCapability}`,
      Range: "bytes=1-2",
    },
  }), env);
  assert.equal(closedRange.status, 206);
  assert.deepEqual(Array.from(new Uint8Array(await closedRange.arrayBuffer())), [2, 3]);

  const suffixRange = await handleRequest(new Request(prepared.downloadTarget, {
    headers: {
      Authorization: `TapChat-Blob ${prepared.readCapability}`,
      Range: "bytes=-2",
    },
  }), env);
  assert.equal(suffixRange.status, 206);
  assert.deepEqual(Array.from(new Uint8Array(await suffixRange.arrayBuffer())), [3, 4]);

  const head = await handleRequest(new Request(prepared.downloadTarget, {
    method: "HEAD",
    headers: { Authorization: `TapChat-Blob ${prepared.readCapability}` },
  }), env);
  assert.equal(head.status, 200);
  assert.equal(head.headers.get("content-length"), "4");
  assert.equal((await head.arrayBuffer()).byteLength, 0);

  const invalidRange = await handleRequest(new Request(prepared.downloadTarget, {
    headers: {
      Authorization: `TapChat-Blob ${prepared.readCapability}`,
      Range: "bytes=9-10",
    },
  }), env);
  assert.equal(invalidRange.status, 416);
  assert.equal(invalidRange.headers.get("content-range"), "bytes */4");
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
        ...authHeaders(bundle.runtimeCredential.token),
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

test("group outbox appends fetches and returns head with authorized capability", async () => {
  const { env } = createEnv();
  const capability = sampleGroupCapability();

  for (const [messageId, expectedSeq] of [["msg:group:1", 1], ["msg:group:2", 2]] as const) {
    const response = await handleRequest(
      new Request("https://example.com/v1/groups/group%3Aproject/outbox/messages", {
        method: "POST",
        headers: {
          ...groupHeaders(capability),
          "Content-Type": "application/json"
        },
        body: JSON.stringify(sampleGroupAppend("group:project", messageId, "mls_application", capability))
      }),
      env
    );
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { version: CURRENT_MODEL_VERSION, accepted: true, seq: expectedSeq });
  }

  const fetch = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/messages?fromSeq=1&limit=10", {
      headers: groupHeaders(capability)
    }),
    env
  );
  assert.equal(fetch.status, 200);
  const body = await fetch.json() as { toSeq: number; records: Array<{ seq: number; messageId: string }> };
  assert.equal(body.toSeq, 2);
  assert.deepEqual(body.records.map((record) => [record.seq, record.messageId]), [
    [1, "msg:group:1"],
    [2, "msg:group:2"]
  ]);

  const head = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/head", {
      headers: groupHeaders(capability)
    }),
    env
  );
  assert.equal(head.status, 200);
  assert.deepEqual(await head.json(), { version: CURRENT_MODEL_VERSION, headSeq: 2, currentRosterVersion: 1 });

  const empty = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/messages?fromSeq=99&limit=10", {
      headers: groupHeaders(capability)
    }),
    env
  );
  assert.equal(empty.status, 200);
  assert.deepEqual(await empty.json(), { version: CURRENT_MODEL_VERSION, toSeq: 2, records: [] });
});

test("group outbox append is idempotent by message id", async () => {
  const { env } = createEnv();
  const capability = sampleGroupCapability();
  const request = sampleGroupAppend("group:project", "msg:group:idempotent", "mls_application", capability);

  for (let i = 0; i < 2; i += 1) {
    const response = await handleRequest(
      new Request("https://example.com/v1/groups/group%3Aproject/outbox/messages", {
        method: "POST",
        headers: {
          ...groupHeaders(capability),
          "Content-Type": "application/json"
        },
        body: JSON.stringify(request)
      }),
      env
    );
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { version: CURRENT_MODEL_VERSION, accepted: true, seq: 1 });
  }

  const fetch = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/messages?fromSeq=1&limit=10", {
      headers: groupHeaders(capability)
    }),
    env
  );
  const body = await fetch.json() as { records: unknown[] };
  assert.equal(body.records.length, 1);
});

test("group outbox rejects invalid capabilities and scope mismatches", async () => {
  const { env } = createEnv();
  const capability = sampleGroupCapability();

  const missingAuth = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/head", {
      headers: {
        "X-Tapchat-Group-Capability": JSON.stringify(capability)
      }
    }),
    env
  );
  assert.equal(missingAuth.status, 403);

  const invalidJson = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/head", {
      headers: {
        ...authHeaders(capability.signature),
        "X-Tapchat-Group-Capability": "{"
      }
    }),
    env
  );
  assert.equal(invalidJson.status, 400);

  const wrongSignature = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/head", {
      headers: {
        ...authHeaders("wrong"),
        "X-Tapchat-Group-Capability": JSON.stringify(capability)
      }
    }),
    env
  );
  assert.equal(wrongSignature.status, 403);

  const expired = sampleGroupCapability();
  expired.expiresAt = 1;
  const expiredResponse = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/head", {
      headers: groupHeaders(expired)
    }),
    env
  );
  assert.equal(expiredResponse.status, 403);

  const wrongGroup = sampleGroupCapability("group:other");
  const wrongGroupResponse = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/head", {
      headers: groupHeaders(wrongGroup)
    }),
    env
  );
  assert.equal(wrongGroupResponse.status, 403);

  const bodyMismatch = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/messages", {
      method: "POST",
      headers: {
        ...groupHeaders(capability),
        "Content-Type": "application/json"
      },
      body: JSON.stringify(sampleGroupAppend("group:other", "msg:mismatch", "mls_application", capability))
    }),
    env
  );
  assert.equal(bodyMismatch.status, 400);

  const missingBodyCapability = sampleGroupAppend("group:project", "msg:missing-capability");
  delete (missingBodyCapability as Partial<AppendGroupEnvelopeRequest>).capability;
  const missingBodyCapabilityResponse = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/messages", {
      method: "POST",
      headers: {
        ...authHeaders(capability.signature),
        "Content-Type": "application/json"
      },
      body: JSON.stringify(missingBodyCapability)
    }),
    env
  );
  assert.equal(missingBodyCapabilityResponse.status, 403);
});

test("group outbox enforces operation and role permissions", async () => {
  const { env } = createEnv();
  const noRead = sampleGroupCapability("group:project", ["append_application"], "member");
  const unreadable = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/head", {
      headers: groupHeaders(noRead)
    }),
    env
  );
  assert.equal(unreadable.status, 403);

  const noApplication = sampleGroupCapability("group:project", ["read", "append_control"], "admin");
  const appDenied = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/messages", {
      method: "POST",
      headers: {
        ...groupHeaders(noApplication),
        "Content-Type": "application/json"
      },
      body: JSON.stringify(sampleGroupAppend("group:project", "msg:app-denied", "mls_application", noApplication))
    }),
    env
  );
  assert.equal(appDenied.status, 403);

  const memberWithMembership = sampleGroupCapability(
    "group:project",
    ["read", "append_application", "append_control", "append_membership"],
    "member"
  );
  const memberDenied = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/messages", {
      method: "POST",
      headers: {
        ...groupHeaders(memberWithMembership),
        "Content-Type": "application/json"
      },
      body: JSON.stringify(sampleGroupAppend(
        "group:project",
        "msg:membership-denied",
        "control_group_membership_changed",
        memberWithMembership
      ))
    }),
    env
  );
  assert.equal(memberDenied.status, 403);

  const admin = sampleGroupCapability("group:project", ["read", "append_membership"], "admin");
  const adminMembershipAllowed = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/messages", {
      method: "POST",
      headers: {
        ...groupHeaders(admin),
        "Content-Type": "application/json"
      },
      body: JSON.stringify(sampleGroupAppend(
        "group:project",
        "msg:membership-allowed",
        "control_group_membership_changed",
        admin
      ))
    }),
    env
  );
  assert.equal(adminMembershipAllowed.status, 200);

  const memberLeave = sampleGroupCapability("group:project", ["read", "append_control"], "member");
  const leaveAllowed = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/messages", {
      method: "POST",
      headers: {
        ...groupHeaders(memberLeave),
        "Content-Type": "application/json"
      },
      body: JSON.stringify(sampleGroupAppend(
        "group:project",
        "msg:leave-allowed",
        "control_group_leave_requested",
        memberLeave
      ))
    }),
    env
  );
  assert.equal(leaveAllowed.status, 200);

  for (const messageType of ["mls_commit", "control_group_join_approved", "control_group_metadata_updated"] as GroupMessageType[]) {
    const denied = await handleRequest(
      new Request("https://example.com/v1/groups/group%3Aproject/outbox/messages", {
        method: "POST",
        headers: {
          ...groupHeaders(memberWithMembership),
          "Content-Type": "application/json"
        },
        body: JSON.stringify(sampleGroupAppend(
          "group:project",
          `msg:member-denied:${messageType}`,
          messageType,
          memberWithMembership
        ))
      }),
      env
    );
    assert.equal(denied.status, 403, `${messageType} must reject member capability`);
  }

  const adminMetadataWithoutUpdate = sampleGroupCapability("group:project", ["read", "append_membership"], "admin");
  const metadataDenied = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/messages", {
      method: "POST",
      headers: {
        ...groupHeaders(adminMetadataWithoutUpdate),
        "Content-Type": "application/json"
      },
      body: JSON.stringify(sampleGroupAppend(
        "group:project",
        "msg:metadata-denied",
        "control_group_metadata_updated",
        adminMetadataWithoutUpdate
      ))
    }),
    env
  );
  assert.equal(metadataDenied.status, 403);
});

test("group outbox fails closed until authorization is initialized", async () => {
  const capability = sampleGroupCapability();
  const response = await handleGroupOutboxDurableRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/head", {
      headers: groupHeaders(capability)
    }),
    {
      groupId: "group:project",
      state: new MemoryState(),
      spillStore: new MemoryR2Store(),
      maxInlineBytes: 128,
      retentionDays: 30,
      sharingSecret: "secret",
      deviceRuntimeSecrets: {
        current: { secret: "secret" },
        allowUnkeyedCurrent: true
      },
      sessions: [],
      now: 1_000
    }
  );
  assert.equal(response.status, 428);
  assert.equal(((await response.json()) as { error: string }).error, "group_authorization_uninitialized");
});

test("group outbox ignores self-reported owner role and rejects forged seal capability", async () => {
  const { env } = createEnv();
  const forged = sampleGroupCapability("group:project", ["seal_group"], "member");
  forged.role = "owner";
  forged.signature = signHex(
    GROUP_IDENTITIES.member.deviceSecret,
    groupCapabilitySigningPayload(forged)
  );

  const response = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/seal", {
      method: "POST",
      headers: { ...groupHeaders(forged), "Content-Type": "application/json" },
      body: JSON.stringify({ groupId: "group:project", capability: forged })
    }),
    env
  );
  assert.equal(response.status, 403);
  assert.equal(((await response.json()) as { error: string }).error, "invalid_capability");
});

test("group outbox subscribe allows members with subscribe operation only", async () => {
  const memberSubscribe = sampleGroupCapability("group:project", ["read", "subscribe"], "member");
  const memberState = new MemoryState();
  await initializeGroupState(memberState);
  const response = await handleGroupOutboxDurableRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/subscribe", {
      headers: groupHeaders(memberSubscribe)
    }),
    {
      groupId: "group:project",
      state: memberState,
      spillStore: new MemoryR2Store(),
      maxInlineBytes: 128,
      retentionDays: 30,
      sharingSecret: "secret",
      deviceRuntimeSecrets: {
        current: { secret: "secret" },
        allowUnkeyedCurrent: true
      },
      sessions: [],
      now: 1_000,
      onUpgrade: () => new Response(null, { status: 200 })
    }
  );
  assert.equal(response.status, 200);

  const memberMissingSubscribe = sampleGroupCapability("group:project", ["read"], "member");
  const deniedState = new MemoryState();
  await initializeGroupState(deniedState);
  const denied = await handleGroupOutboxDurableRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/subscribe", {
      headers: groupHeaders(memberMissingSubscribe)
    }),
    {
      groupId: "group:project",
      state: deniedState,
      spillStore: new MemoryR2Store(),
      maxInlineBytes: 128,
      retentionDays: 30,
      sharingSecret: "secret",
      deviceRuntimeSecrets: {
        current: { secret: "secret" },
        allowUnkeyedCurrent: true
      },
      sessions: [],
      now: 1_000,
      onUpgrade: () => new Response(null, { status: 200 })
    }
  );
  assert.equal(denied.status, 403);
});

test("group join decision rejects server-generated approval artifacts on reject", async () => {
  const state = new MemoryState();
  const spillStore = new MemoryR2Store();
  await initializeGroupState(state);
  await state.put("join-request:req:1", {
    request: {
      version: CURRENT_MODEL_VERSION,
      requestId: "req:1",
      groupId: "group:project",
      inviteId: "invite:1",
      joinerUserId: "user:dana",
      joinerDeviceId: "device:dana:phone",
      joinerContactShareUrl: "https://example.com/contact/dana",
      requestCapability: "join-capability",
      requestedAt: 1,
      autoApprove: false,
      status: "pending",
      signature: "join-signature"
    }
  });

  const decisionCapability = sampleGroupCapability("group:project", ["approve_join"], "owner");
  const response = await handleGroupOutboxDurableRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/join-requests/req%3A1/decision", {
      method: "POST",
      headers: { ...groupHeaders(decisionCapability), "Content-Type": "application/json" },
      body: JSON.stringify({
        version: CURRENT_MODEL_VERSION,
        groupId: "group:project",
        requestId: "req:1",
        decision: "reject",
        capability: decisionCapability,
        reason: "no",
        welcomePickup: {
          groupId: "group:project",
          deviceId: "device:dana:phone",
          endpoint: "https://example.com/v1/groups/group:project/welcome-pickup/device:dana:phone",
          capability: "welcome-capability",
          expiresAt: Date.now() + 60_000
        },
        manifest: { groupId: "group:project" },
        startCursor: { groupId: "group:project", lastFetchedSeq: 0, updatedAt: 1 }
      })
    }),
    {
      groupId: "group:project",
      state,
      spillStore,
      maxInlineBytes: 128,
      retentionDays: 30,
      sharingSecret: "secret",
      deviceRuntimeSecrets: {
        current: { secret: "secret" },
        allowUnkeyedCurrent: true
      },
      sessions: [],
      now: 1_000
    }
  );

  assert.equal(response.status, 400);
});

test("group join lease is idempotent, exclusive, expiring, and completes only after transition commit", async () => {
  const state = new MemoryState();
  const spillStore = new MemoryR2Store();
  await initializeGroupState(state);
  const manifest = sampleGroupManifest();
  await state.put("join-request:req:lease", {
    request: {
      version: CURRENT_MODEL_VERSION,
      requestId: "req:lease",
      groupId: "group:project",
      inviteId: "invite:lease",
      joinerUserId: "user:dana",
      joinerDeviceId: "device:dana:phone",
      joinerContactShareUrl: "https://example.com/contact/dana",
      requestCapability: "join-capability",
      requestedAt: 1,
      autoApprove: true,
      status: "waiting_for_group_commit",
      signature: "join-signature"
    }
  });
  const service = new GroupOutboxService(
    "group:project",
    state,
    spillStore,
    { headSeq: 0, retentionDays: 30, maxInlineBytes: 128 },
    []
  );
  const owner = sampleGroupCapability("group:project", ["approve_join"], "owner");
  const admin = sampleGroupCapability("group:project", ["approve_join"], "admin");
  const first = await service.claimJoinRequest({
    version: CURRENT_MODEL_VERSION,
    groupId: "group:project",
    requestId: "req:lease",
    capability: owner
  }, 1_000);
  const repeated = await service.claimJoinRequest({
    version: CURRENT_MODEL_VERSION,
    groupId: "group:project",
    requestId: "req:lease",
    capability: owner
  }, 1_001);
  assert.equal(repeated.leaseToken, first.leaseToken);
  await assert.rejects(
    () => service.claimJoinRequest({
      version: CURRENT_MODEL_VERSION,
      groupId: "group:project",
      requestId: "req:lease",
      capability: admin
    }, 1_002),
    (error: unknown) => error instanceof Error && error.message.includes("another administrator")
  );
  const takeover = await service.claimJoinRequest({
    version: CURRENT_MODEL_VERSION,
    groupId: "group:project",
    requestId: "req:lease",
    capability: admin
  }, first.leaseExpiresAt + 1);
  assert.notEqual(takeover.leaseToken, first.leaseToken);

  const joinedManifest = {
    ...manifest,
    members: [...manifest.members, { userId: "user:dana", role: "member" as const, status: "active" as const }],
    memberDevices: [...(manifest.memberDevices ?? []), { userId: "user:dana", deviceId: "device:dana:phone", status: "active" as const }]
  };
  const authorization = await state.get<Record<string, unknown>>("group-authorization:v2");
  await state.put("group-authorization:v2", { ...authorization, manifest: joinedManifest, lastTransitionId: "transition:lease" });
  await state.put("transition:transition:lease", {
    fingerprint: "fixture",
    operation: { type: "approve_join", requestId: "req:lease", userId: "user:dana", deviceId: "device:dana:phone" },
    requestBinding: { type: "join", requestId: "req:lease", leaseToken: takeover.leaseToken },
    result: { accepted: true, transitionId: "transition:lease", firstSeq: 1, lastSeq: 3, rosterVersion: joinedManifest.rosterVersion, lastCommitMessageId: joinedManifest.lastCommitMessageId }
  });
  const claimed = await state.get<Record<string, unknown>>("join-request:req:lease");
  await state.put("join-request:req:lease", {
    ...claimed,
    transitionId: "transition:lease",
    committedBinding: { transitionId: "transition:lease", leaseToken: takeover.leaseToken, committedAt: takeover.leaseExpiresAt - 2 }
  });
  const completed = await service.completeJoinRequest({
    version: CURRENT_MODEL_VERSION,
    groupId: "group:project",
    requestId: "req:lease",
    capability: admin,
    leaseToken: takeover.leaseToken,
    transitionId: "transition:lease",
    welcomePickup: {
      groupId: "group:project",
      deviceId: "device:dana:phone",
      endpoint: "https://example.com/welcome",
      capability: "welcome-capability",
      requestId: "req:lease",
      expiresAt: takeover.leaseExpiresAt + 60_000,
      startSeq: 3,
      rosterVersion: joinedManifest.rosterVersion,
      lastCommitMessageId: joinedManifest.lastCommitMessageId
    },
    manifest: joinedManifest,
    startCursor: { groupId: "group:project", lastFetchedSeq: 3, updatedAt: 1 }
  }, takeover.leaseExpiresAt - 1);
  assert.equal(completed.request.status, "welcome_available");
  await service.markWelcomeClaimed("req:lease", "device:dana:phone", "welcome-capability");
  const joined = await service.getJoinRequestStatus("req:lease", "join-capability");
  assert.equal(joined.request.status, "joined");
});

test("group invite idempotency and leave lease alarm preserve shared FSM state", async () => {
  const state = new MemoryState();
  await initializeGroupState(state);
  const events: string[] = [];
  const service = new GroupOutboxService(
    "group:project",
    state,
    new MemoryR2Store(),
    { headSeq: 0, retentionDays: 30, maxInlineBytes: 128 },
    [{ send: (payload: string) => { events.push(payload); return true; } }]
  );
  const owner = sampleGroupCapability("group:project", ["manage_invites", "approve_join"], "owner");
  const document = {
    version: CURRENT_MODEL_VERSION,
    groupId: "group:project",
    title: "Project",
    inviteId: "invite:idempotent",
    joinPolicy: "open_by_invite" as const,
    inviterUserId: owner.userId,
    inviterDeviceId: owner.deviceId,
    ownerUserId: owner.userId,
    joinRequestEndpoint: "https://example.com/v1/groups/group%3Aproject/join-requests",
    createdAt: 1_000,
    expiresAt: 2_000,
    signature: "client-signature"
  };
  const create = { version: CURRENT_MODEL_VERSION, groupId: "group:project", document, capability: owner };
  const first = await service.createInvite(create, "https://example.com/invite", "server-token", 1_000);
  const repeated = await service.createInvite(create, "https://example.com/ignored", "new-server-token", 1_001);
  assert.equal(repeated.inviteUrl, first.inviteUrl);
  assert.equal((await service.listInvites(1_001)).revision, 1);
  await service.revokeInvite({ version: CURRENT_MODEL_VERSION, groupId: "group:project", inviteId: document.inviteId, capability: owner }, 1_100);
  await service.revokeInvite({ version: CURRENT_MODEL_VERSION, groupId: "group:project", inviteId: document.inviteId, capability: owner }, 1_101);
  assert.equal((await service.listInvites(1_101)).revision, 2);

  const member = sampleGroupCapability("group:project", ["append_control"], "member");
  const leave = await service.submitLeaveRequest({
    version: CURRENT_MODEL_VERSION,
    groupId: "group:project",
    capability: member,
    request: {
      version: CURRENT_MODEL_VERSION,
      requestId: "leave:1",
      groupId: "group:project",
      leaverUserId: member.userId,
      leaverDeviceId: member.deviceId,
      requestedAt: 1_000,
      requestCapability: "leave-cap",
      signature: "leave-signature",
      status: "waiting_for_group_commit"
    }
  }, 1_000);
  assert.equal(leave.request.status, "waiting_for_group_commit");
  const claimed = await service.claimLeaveRequest({ version: CURRENT_MODEL_VERSION, groupId: "group:project", requestId: "leave:1", capability: owner }, 1_100);
  await service.processAlarm(claimed.leaseExpiresAt + 1);
  assert.equal((await service.listLeaveRequests()).requests[0].status, "waiting_for_group_commit");
  assert.ok(events.some((payload) => payload.includes("group_leave_request_available")));
});

test("group outbox spills large records to R2 and fetches them back", async () => {
  const { env, bucket } = createEnv({ maxInlineBytes: "1" });
  const capability = sampleGroupCapability();
  const append = sampleGroupAppend("group:project", "msg:large", "mls_application", capability);
  append.envelope.inlineCiphertext = "large cipher payload";

  const response = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/messages", {
      method: "POST",
      headers: {
        ...groupHeaders(capability),
        "Content-Type": "application/json"
      },
      body: JSON.stringify(append)
    }),
    env
  );
  assert.equal(response.status, 200);
  assert.equal(bucket.has("group-outbox-payload/group:project/1.json"), true);

  const fetch = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/messages?fromSeq=1&limit=10", {
      headers: groupHeaders(capability)
    }),
    env
  );
  assert.equal(fetch.status, 200);
  const body = await fetch.json() as { records: Array<{ messageId: string }> };
  assert.deepEqual(body.records.map((record) => record.messageId), ["msg:large"]);

  await bucket.delete("group-outbox-payload/group:project/1.json");
  const missingSpill = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/messages?fromSeq=1&limit=10", {
      headers: groupHeaders(capability)
    }),
    env
  );
  assert.equal(missingSpill.status, 500);
  assert.equal(((await missingSpill.json()) as { error: string }).error, "storage_integrity_error");
});

test("welcome pickup stores and fetches a device-scoped welcome", async () => {
  const { env } = createEnv();
  const descriptor = {
    groupId: "group:project",
    deviceId: "device:bob:phone",
    endpoint: "https://example.com/v1/groups/group:project/welcome-pickup/device:bob:phone",
    capability: "welcome-cap-1",
    expiresAt: Date.now() + 60_000
  };

  const put = await handleRequest(
    new Request(descriptor.endpoint, {
      method: "PUT",
      headers: {
        ...authHeaders(descriptor.capability),
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        descriptor,
        welcomeB64: "d2VsY29tZQ=="
      })
    }),
    env
  );
  assert.equal(put.status, 200);
  assert.equal(((await put.json()) as { accepted: boolean }).accepted, true);

  const fetched = await handleRequest(
    new Request(descriptor.endpoint, {
      method: "GET",
      headers: {
        ...authHeaders(descriptor.capability),
        "X-Tapchat-Welcome-Pickup": JSON.stringify(descriptor)
      }
    }),
    env
  );
  assert.equal(fetched.status, 200);
  assert.equal(((await fetched.json()) as { welcomeB64: string }).welcomeB64, "d2VsY29tZQ==");

  const rejected = await handleRequest(
    new Request(descriptor.endpoint, {
      method: "GET",
      headers: {
        ...authHeaders("wrong"),
        "X-Tapchat-Welcome-Pickup": JSON.stringify(descriptor)
      }
    }),
    env
  );
  assert.equal(rejected.status, 403);
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

  await assert.rejects(
    () => service.ack({
      ack: {
        deviceId: "device:bob:phone",
        ackSeq: 2,
        ackedAt: 1_100
      }
    }),
    /ack_seq must not move beyond inbox head_seq/
  );
  await assert.rejects(
    () => service.ack({
      ack: {
        deviceId: "device:bob:phone",
        ackSeq: -1,
        ackedAt: 1_100
      }
    }),
    /ack_seq must be a non-negative safe integer/
  );
  await assert.rejects(
    () => service.ack({
      ack: {
        deviceId: "device:bob:phone",
        ackSeq: 0.5,
        ackedAt: 1_100
      }
    }),
    /ack_seq must be a non-negative safe integer/
  );

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

test("inbox fetch fails closed when an R2 spill payload is missing", async () => {
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
  await service.appendEnvelope(sampleAppend(), 1_000);
  await spillStore.delete("inbox-payload/device:bob:phone/1.json");

  await assert.rejects(
    () => service.fetchMessages({ deviceId: "device:bob:phone", fromSeq: 1, limit: 10 }),
    /inbox spill payload is missing at seq 1/
  );
});

test("group outbox seal succeeds for owner and records sealed timestamp", async () => {
  // Owner-signed `seal_group` capability must be accepted on the very
  // first POST to `/outbox/seal`. The response carries `sealedAt` so
  // clients can surface the transition (PROTOCOL_GROUP_CN.md §10.4).
  const { env } = createEnv();
  const capability = sampleGroupCapability(
    "group:project",
    ["read", "seal_group"],
    "owner"
  );

  const response = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/seal", {
      method: "POST",
      headers: groupHeaders(capability),
      body: "{}"
    }),
    env
  );
  assert.equal(response.status, 200);
  const body = (await response.json()) as {
    sealed: boolean;
    sealedAt: number;
    wasAlreadySealed: boolean;
  };
  assert.equal(body.sealed, true);
  assert.equal(body.wasAlreadySealed, false);
  assert.ok(body.sealedAt > 0, "sealedAt must be a positive timestamp");
});

test("group outbox seal returns 409 already_sealed on repeat", async () => {
  // Re-seals must be idempotent at the terminal-state level but observable
  // via HTTP 409 `already_sealed` so operator tooling can distinguish a
  // fresh seal from a no-op retry.
  const { env } = createEnv();
  const capability = sampleGroupCapability(
    "group:project",
    ["read", "seal_group"],
    "owner"
  );

  const first = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/seal", {
      method: "POST",
      headers: groupHeaders(capability),
      body: "{}"
    }),
    env
  );
  assert.equal(first.status, 200);

  const repeat = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/seal", {
      method: "POST",
      headers: groupHeaders(capability),
      body: "{}"
    }),
    env
  );
  assert.equal(repeat.status, 409);
  const body = (await repeat.json()) as { error?: string; message?: string };
  assert.equal(body.error, "already_sealed");
});

test("group outbox seal rejects non-owner capability with 403 unauthorized", async () => {
  // `seal_group` is owner-exclusive per PROTOCOL_GROUP_CN.md §10.4.
  // Even an admin holding the operation in their capability must be
  // rejected at the worker boundary. We also cover the case where an
  // owner signs a capability missing `seal_group` to verify the operation
  // flag is not inferred from role alone.
  const { env } = createEnv();
  const adminWithSealOp = sampleGroupCapability(
    "group:project",
    ["read", "seal_group"],
    "admin"
  );
  const ownerMissingSealOp = sampleGroupCapability(
    "group:project",
    ["read", "append_application"],
    "owner"
  );

  const adminResp = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/seal", {
      method: "POST",
      headers: groupHeaders(adminWithSealOp),
      body: "{}"
    }),
    env
  );
  assert.equal(adminResp.status, 403);
  const adminBody = (await adminResp.json()) as { error?: string };
  assert.equal(adminBody.error, "invalid_capability");

  const ownerResp = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/seal", {
      method: "POST",
      headers: groupHeaders(ownerMissingSealOp),
      body: "{}"
    }),
    env
  );
  assert.equal(ownerResp.status, 403);
  const ownerBody = (await ownerResp.json()) as { error?: string };
  assert.equal(ownerBody.error, "invalid_capability");
});

test("group outbox append after seal returns 403 group_sealed", async () => {
  // After a successful seal, any subsequent append must be rejected with
  // the canonical `403 group_sealed` regardless of capability. Existing
  // reads continue to work.
  const { env } = createEnv();
  const ownerCap = sampleGroupCapability(
    "group:project",
    ["read", "append_application", "append_membership", "manage_invites", "approve_join", "seal_group"],
    "owner"
  );

  const preSealInvite = {
    version: CURRENT_MODEL_VERSION,
    groupId: "group:project",
    capability: ownerCap,
    document: {
      version: CURRENT_MODEL_VERSION,
      groupId: "group:project",
      title: "Project",
      inviteId: "invite:pre-seal",
      joinPolicy: "approval_required",
      inviterUserId: "user:alice",
      inviterDeviceId: "device:alice:phone",
      ownerUserId: "user:alice",
      joinRequestEndpoint: "https://example.com/v1/groups/group%3Aproject/join-requests",
      createdAt: 1_000,
      expiresAt: Date.now() + 60_000,
      signature: "unsigned"
    }
  } satisfies CreateGroupInviteRequest;

  const inviteResp = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/invites", {
      method: "POST",
      headers: {
        ...groupHeaders(ownerCap),
        "Content-Type": "application/json"
      },
      body: JSON.stringify(preSealInvite)
    }),
    env
  );
  assert.equal(inviteResp.status, 200);
  const inviteBody = (await inviteResp.json()) as { inviteUrl: string; invite: { signature: string } };
  assert.match(inviteBody.inviteUrl, /\/v1\/group-invite\/group%3Aproject\/invite%3Apre-seal$/);
  const shortInviteFetch = await handleRequest(new Request(inviteBody.inviteUrl), env);
  assert.equal(shortInviteFetch.status, 200);
  const inviteToken = inviteBody.invite.signature;

  const preSealJoin = {
    version: CURRENT_MODEL_VERSION,
    inviteToken,
    request: {
      version: CURRENT_MODEL_VERSION,
      requestId: "req:pre-seal",
      groupId: "group:project",
      inviteId: "invite:pre-seal",
      joinerUserId: "user:dana",
      joinerDeviceId: "device:dana:phone",
      joinerContactShareUrl: "https://example.com/contact/dana",
      requestedAt: 1_000,
      requestCapability: "join-capability",
      signature: "join-signature",
      status: "pending"
    }
  } satisfies SubmitGroupJoinRequest;

  const joinResp = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/join-requests", {
      method: "POST",
      headers: {
        ...authHeaders(inviteToken),
        "Content-Type": "application/json"
      },
      body: JSON.stringify(preSealJoin)
    }),
    env
  );
  assert.equal(joinResp.status, 200);

  // Append one record prior to sealing so fetch has something to return.
  const initialAppend = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/messages", {
      method: "POST",
      headers: {
        ...groupHeaders(ownerCap),
        "Content-Type": "application/json"
      },
      body: JSON.stringify(
        sampleGroupAppend("group:project", "msg:group:pre-seal", "mls_application", ownerCap)
      )
    }),
    env
  );
  assert.equal(initialAppend.status, 200);

  // Seal the outbox.
  const sealResp = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/seal", {
      method: "POST",
      headers: groupHeaders(ownerCap),
      body: "{}"
    }),
    env
  );
  assert.equal(sealResp.status, 200);

  // Subsequent append must be rejected.
  const postSealAppend = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/messages", {
      method: "POST",
      headers: {
        ...groupHeaders(ownerCap),
        "Content-Type": "application/json"
      },
      body: JSON.stringify(
        sampleGroupAppend("group:project", "msg:group:post-seal", "mls_application", ownerCap)
      )
    }),
    env
  );
  assert.equal(postSealAppend.status, 403);
  const appendBody = (await postSealAppend.json()) as { error?: string };
  assert.equal(appendBody.error, "group_sealed");

  const postSealInvite = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/invites", {
      method: "POST",
      headers: {
        ...groupHeaders(ownerCap),
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        ...preSealInvite,
        document: {
          ...preSealInvite.document,
          inviteId: "invite:post-seal"
        }
      } satisfies CreateGroupInviteRequest)
    }),
    env
  );
  assert.equal(postSealInvite.status, 403);
  assert.equal(((await postSealInvite.json()) as { error?: string }).error, "group_sealed");

  const postSealRevoke = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/invites/invite%3Apre-seal/revoke", {
      method: "POST",
      headers: {
        ...groupHeaders(ownerCap),
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        version: CURRENT_MODEL_VERSION,
        groupId: "group:project",
        inviteId: "invite:pre-seal",
        capability: ownerCap
      })
    }),
    env
  );
  assert.equal(postSealRevoke.status, 403);
  assert.equal(((await postSealRevoke.json()) as { error?: string }).error, "group_sealed");

  const postSealJoin = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/join-requests", {
      method: "POST",
      headers: {
        ...authHeaders(inviteToken),
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        ...preSealJoin,
        request: {
          ...preSealJoin.request,
          requestId: "req:post-seal"
        }
      } satisfies SubmitGroupJoinRequest)
    }),
    env
  );
  assert.equal(postSealJoin.status, 403);
  assert.equal(((await postSealJoin.json()) as { error?: string }).error, "group_sealed");

  const postSealDecision = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/join-requests/req%3Apre-seal/decision", {
      method: "POST",
      headers: {
        ...groupHeaders(ownerCap),
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        version: CURRENT_MODEL_VERSION,
        groupId: "group:project",
        requestId: "req:pre-seal",
        decision: "reject",
        capability: ownerCap,
        reason: "closed"
      } satisfies DecideGroupJoinRequest)
    }),
    env
  );
  assert.equal(postSealDecision.status, 403);
  assert.equal(((await postSealDecision.json()) as { error?: string }).error, "group_sealed");

  // Reads continue to work: fetch the pre-seal record, and head remains
  // the final pre-seal seq.
  const fetchResp = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/messages?fromSeq=1&limit=10", {
      headers: groupHeaders(ownerCap)
    }),
    env
  );
  assert.equal(fetchResp.status, 200);
  const fetchBody = (await fetchResp.json()) as {
    records: Array<{ seq: number; messageId: string }>;
  };
  assert.deepEqual(
    fetchBody.records.map((record) => [record.seq, record.messageId]),
    [[1, "msg:group:pre-seal"]]
  );

  const headResp = await handleRequest(
    new Request("https://example.com/v1/groups/group%3Aproject/outbox/head", {
      headers: groupHeaders(ownerCap)
    }),
    env
  );
  assert.equal(headResp.status, 200);
  const headBody = (await headResp.json()) as { headSeq: number };
  assert.equal(headBody.headSeq, 1);
});

test("group outbox durable recovers group id from short invite URL", async () => {
  const shortInviteUrl = new URL("https://example.com/v1/group-invite/group%3Aproject/invite%3A123");
  assert.equal(
    await groupIdFromGroupOutboxRequestUrl(shortInviteUrl, "secret", Date.now()),
    "group:project"
  );

  const token = await signSharingPayload("secret", {
    version: CURRENT_MODEL_VERSION,
    service: "group_invite",
    groupId: "group:token",
    inviteId: "invite:token",
    inviterUserId: "user:alice",
    inviterDeviceId: "device:alice",
    joinPolicy: "approval_required",
    expiresAt: Date.now() + 60_000
  });
  const tokenInviteUrl = new URL(`https://example.com/v1/group-invite/${encodeURIComponent(token)}`);
  assert.equal(
    await groupIdFromGroupOutboxRequestUrl(tokenInviteUrl, "secret", Date.now()),
    "group:token"
  );
});

test("runtime secrets fail closed when missing, short, or placeholders", async () => {
  const invalidValues = [undefined, "", "short", "replace-me"];
  for (const invalid of invalidValues) {
    const { env } = createEnv();
    env.SHARING_INTERNAL_SECRET = invalid;
    const response = await handleRequest(new Request("https://example.com/v1/deployment-bundle"), env);
    assert.equal(response.status, 503);
    assert.equal(((await response.json()) as { error: string }).error, "runtime_misconfigured");
  }

  const { env } = createEnv();
  env.DEVICE_RUNTIME_SECRET = "replace-me";
  const response = await handleRequest(new Request("https://example.com/v1/deployment-bundle"), env);
  assert.equal(response.status, 503);
  assert.equal(((await response.json()) as { error: string }).error, "runtime_misconfigured");
});

test("append request body limit checks actual streamed bytes", async () => {
  const { env } = createEnv();
  env.MESSAGE_REQUEST_MAX_BODY_BYTES = "128";
  const oversized = JSON.stringify({ ...sampleAppend(), padding: "x".repeat(512) });
  const response = await handleRequest(
    new Request("https://example.com/v1/inbox/device:bob:phone/messages", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Content-Length": "1" },
      body: oversized
    }),
    env
  );
  assert.equal(response.status, 413);
  assert.equal(((await response.json()) as { error: string }).error, "request_too_large");
});

test("message request quotas, global rate limit, expiry, and capacity recovery work", async () => {
  const state = new MemoryState();
  const service = new InboxService("device:bob:phone", state, new MemoryR2Store(), [], {
    headSeq: 0,
    ackedSeq: 0,
    retentionDays: 30,
    maxInlineBytes: 4096,
    rateLimitPerMinute: 100,
    rateLimitPerHour: 1000,
    messageRequestMaxPerSender: 2,
    messageRequestMaxSenders: 1,
    messageRequestMaxTotalBytes: 1024 * 1024,
    messageRequestTtlSeconds: 10,
    messageRequestRateLimitMinute: 100,
    messageRequestRateLimitHour: 20
  });

  await service.appendEnvelope(sampleAppend(undefined, "msg:q1", undefined, "user:one"), 1_000, { mode: "legacy_unverified" });
  await service.appendEnvelope(sampleAppend(undefined, "msg:q2", undefined, "user:one"), 1_001, { mode: "legacy_unverified" });
  await assert.rejects(
    () => service.appendEnvelope(sampleAppend(undefined, "msg:q3", undefined, "user:one"), 1_002, { mode: "legacy_unverified" }),
    (error: unknown) => (error as { code?: string }).code === "message_request_capacity_exceeded"
  );
  await assert.rejects(
    () => service.appendEnvelope(sampleAppend(undefined, "msg:q4", undefined, "user:two"), 1_003, { mode: "legacy_unverified" }),
    (error: unknown) => (error as { code?: string }).code === "message_request_capacity_exceeded"
  );

  const queued = await service.listMessageRequests(1_002);
  assert.equal(queued.length, 1);
  await service.rejectMessageRequest(queued[0].requestId, 1_004);
  await service.appendEnvelope(sampleAppend(undefined, "msg:q5", undefined, "user:two"), 1_005, { mode: "legacy_unverified" });
  assert.equal((await service.listMessageRequests(1_006)).length, 1);
  assert.equal((await service.listMessageRequests(11_006)).length, 0);

  const rateService = new InboxService("device:bob:phone", new MemoryState(), new MemoryR2Store(), [], {
    headSeq: 0,
    ackedSeq: 0,
    retentionDays: 30,
    maxInlineBytes: 4096,
    rateLimitPerMinute: 100,
    rateLimitPerHour: 1000,
    messageRequestMaxPerSender: 16,
    messageRequestMaxSenders: 64,
    messageRequestMaxTotalBytes: 1024 * 1024,
    messageRequestTtlSeconds: 60,
    messageRequestRateLimitMinute: 2,
    messageRequestRateLimitHour: 20
  });
  await rateService.appendEnvelope(sampleAppend(undefined, "msg:r1", undefined, "user:one"), 1_000, { mode: "legacy_unverified" });
  await rateService.appendEnvelope(sampleAppend(undefined, "msg:r2", undefined, "user:two"), 1_001, { mode: "legacy_unverified" });
  await assert.rejects(
    () => rateService.appendEnvelope(sampleAppend(undefined, "msg:r3", undefined, "user:three"), 1_002, { mode: "legacy_unverified" }),
    (error: unknown) => (error as { code?: string; details?: { retryAfterSeconds?: number } }).code === "message_request_rate_limited" &&
      Number((error as { details?: { retryAfterSeconds?: number } }).details?.retryAfterSeconds) > 0
  );
});

test("managed websocket sessions contain send failures and clean themselves up", () => {
  let inboxClosed = 0;
  let groupClosed = 0;
  const failingSocket = {
    readyState: 1,
    send() { throw new TypeError("socket is closed"); },
    close() { throw new TypeError("already closed"); }
  } as unknown as WebSocket;

  const inbox = new InboxManagedSession(failingSocket, () => { inboxClosed += 1; });
  const group = new GroupManagedSession(failingSocket, () => { groupClosed += 1; });
  assert.equal(inbox.send("payload"), false);
  assert.equal(group.send("payload"), false);
  assert.equal(inboxClosed, 1);
  assert.equal(groupClosed, 1);
  assert.equal(inbox.send("payload"), false);
  assert.equal(group.send("payload"), false);
});

test("legacy message request entries are migrated lazily and expire", async () => {
  const state = new MemoryState();
  const pending = sampleAppend(undefined, "msg:legacy", undefined, "user:legacy");
  await state.put("message-request:index", ["user:legacy"]);
  await state.put("message-request:user:legacy", {
    requestId: "request:user:legacy",
    recipientDeviceId: "device:bob:phone",
    senderUserId: "user:legacy",
    firstSeenAt: 1_000,
    lastSeenAt: 1_000,
    messageCount: 1,
    lastMessageId: "msg:legacy",
    lastConversationId: pending.envelope.conversationId,
    pendingRequests: [pending]
  });
  const service = new InboxService("device:bob:phone", state, new MemoryR2Store(), [], {
    headSeq: 0,
    ackedSeq: 0,
    retentionDays: 30,
    maxInlineBytes: 4096,
    rateLimitPerMinute: 100,
    rateLimitPerHour: 1000,
    messageRequestTtlSeconds: 10
  });

  assert.equal((await service.listMessageRequests(1_001)).length, 1);
  const migrated = await state.get<{ byteSize?: number; expiresAt?: number }>("message-request:user:legacy");
  assert.ok((migrated?.byteSize ?? 0) > 0);
  assert.equal(migrated?.expiresAt, 11_000);
  assert.equal((await service.listMessageRequests(11_001)).length, 0);
});

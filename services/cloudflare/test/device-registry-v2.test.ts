import test from "node:test";
import assert from "node:assert/strict";
import { ed25519 } from "@noble/curves/ed25519";
import type {
  ClaimKeyPackagesRequest,
  ClaimKeyPackagesResult,
  DeviceBinding,
  DeviceContactProfile,
  DeviceRegistryRecord,
  IdentityBundle,
  KeyPackageClaimCapability,
  MlsDeviceKeyBinding,
  PublishKeyPackageBatchRequest,
  PublishedKeyPackageV2,
  RelationshipDecisionProofV2,
  RelationshipProposalV2
} from "../src/types/contracts";
import {
  identityBundleDigest,
  identityBundleV2SigningPayload,
  keyPackageClaimCapabilitySigningPayload,
  mlsDeviceKeyBindingSigningPayload,
  publishKeyPackageBatchSigningPayload,
  relationshipDecisionProofSigningPayload,
  relationshipProposalSigningPayload,
  relationshipTicketSecretProof,
  relationshipTicketStatusSigningPayload
} from "../src/auth/capability";
import type { Env } from "../src/types/env";

class TestDurableObject {}
(globalThis as Record<string, unknown>).DurableObject = TestDurableObject;

const { DeviceRegistryDurableObject } = await import("../src/device-registry/durable");

function clone<T>(value: T): T {
  return value === undefined ? value : structuredClone(value);
}

class TransactionalStorage {
  private values = new Map<string, unknown>();
  private tail: Promise<void> = Promise.resolve();

  async get<T>(key: string): Promise<T | undefined> {
    return clone(this.values.get(key) as T | undefined);
  }

  async put<T>(key: string, value: T): Promise<void> {
    this.values.set(key, clone(value));
  }

  async delete(key: string | string[]): Promise<boolean> {
    const keys = Array.isArray(key) ? key : [key];
    let deleted = false;
    for (const item of keys) deleted = this.values.delete(item) || deleted;
    return deleted;
  }

  async list<T>(options?: { prefix?: string }): Promise<Map<string, T>> {
    return this.listFrom<T>(this.values, options);
  }

  async transaction<T>(callback: (transaction: TransactionalStorageView) => Promise<T>): Promise<T> {
    const previous = this.tail;
    let release!: () => void;
    this.tail = new Promise<void>((resolve) => { release = resolve; });
    await previous;
    const draft = new Map(
      Array.from(this.values.entries(), ([key, value]) => [key, clone(value)])
    );
    try {
      const result = await callback(new TransactionalStorageView(draft));
      this.values = draft;
      return result;
    } finally {
      release();
    }
  }

  async setAlarm(_scheduledTime: number): Promise<void> {}

  private listFrom<T>(source: Map<string, unknown>, options?: { prefix?: string }): Map<string, T> {
    const result = new Map<string, T>();
    for (const [key, value] of source) {
      if (!options?.prefix || key.startsWith(options.prefix)) {
        result.set(key, clone(value) as T);
      }
    }
    return result;
  }
}

class TransactionalStorageView {
  constructor(private readonly values: Map<string, unknown>) {}

  async get<T>(key: string): Promise<T | undefined> {
    return clone(this.values.get(key) as T | undefined);
  }

  async put<T>(key: string, value: T): Promise<void> {
    this.values.set(key, clone(value));
  }

  async delete(key: string | string[]): Promise<boolean> {
    const keys = Array.isArray(key) ? key : [key];
    let deleted = false;
    for (const item of keys) deleted = this.values.delete(item) || deleted;
    return deleted;
  }

  async list<T>(options?: { prefix?: string }): Promise<Map<string, T>> {
    const result = new Map<string, T>();
    for (const [key, value] of this.values) {
      if (!options?.prefix || key.startsWith(options.prefix)) {
        result.set(key, clone(value) as T);
      }
    }
    return result;
  }
}

interface DeviceFixture {
  deviceId: string;
  secret: Uint8Array;
  profile: DeviceContactProfile;
}

interface IdentityFixture {
  bundle: IdentityBundle;
  userSecret: Uint8Array;
  devices: DeviceFixture[];
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function sign(secret: Uint8Array, payload: string | Uint8Array): string {
  return hex(ed25519.sign(
    typeof payload === "string" ? new TextEncoder().encode(payload) : payload,
    secret
  ));
}

function identity(byte: number, deviceCount: number, baseUrl: string): IdentityFixture {
  const userSecret = new Uint8Array(32).fill(byte);
  const userPublicKey = hex(ed25519.getPublicKey(userSecret));
  const userId = `user:${userPublicKey.slice(0, 16)}`;
  const devices = Array.from({ length: deviceCount }, (_, index) => {
    const secret = new Uint8Array(32).fill(byte + index + 1);
    const devicePublicKey = hex(ed25519.getPublicKey(secret));
    const deviceId = `device:${userPublicKey.slice(0, 8)}:${index}`;
    const binding: DeviceBinding = {
      version: "0.1",
      userId,
      deviceId,
      devicePublicKey,
      createdAt: 1_700_000_000_000,
      signature: ""
    };
    binding.signature = sign(
      userSecret,
      `0.1:${userId}:${deviceId}:${devicePublicKey}:${binding.createdAt}`
    );
    const mlsBinding: MlsDeviceKeyBinding = {
      version: "0.1",
      userId,
      deviceId,
      devicePublicKey,
      mlsSignaturePublicKey: devicePublicKey,
      ciphersuite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      createdAt: binding.createdAt,
      signature: ""
    };
    mlsBinding.signature = sign(secret, mlsDeviceKeyBindingSigningPayload(mlsBinding));
    const claimCapability: KeyPackageClaimCapability = {
      version: "0.1",
      service: "key_package_claim",
      userId,
      targetDeviceId: deviceId,
      endpoint: `${baseUrl}/v2/key-packages/claims`,
      expiresAt: Date.now() + 365 * 24 * 60 * 60 * 1000,
      nonce: hex(new Uint8Array(32).fill(byte + index + 17)),
      signature: ""
    };
    claimCapability.signature = sign(
      secret,
      keyPackageClaimCapabilitySigningPayload(claimCapability)
    );
    return {
      deviceId,
      secret,
      profile: {
        version: "0.1",
        deviceId,
        devicePublicKey,
        binding,
        status: "active" as const,
        keyPackageClaimCapability: claimCapability,
        mlsDeviceKeyBinding: mlsBinding
      }
    };
  });
  const bundle: IdentityBundle = {
    version: "0.1",
    publicationVersion: 2,
    publicationRevision: 1,
    userId,
    userPublicKey,
    devices: devices.map((device) => device.profile),
    updatedAt: Date.now(),
    signature: ""
  };
  bundle.signature = sign(userSecret, identityBundleV2SigningPayload(bundle));
  return { bundle, userSecret, devices };
}

function packageItem(device: DeviceFixture, marker: number, createdAt: number): PublishedKeyPackageV2 {
  return {
    keyPackageId: hex(new Uint8Array(32).fill(marker)),
    keyPackageB64: btoa(`key-package-${device.deviceId}-${marker}`),
    lifecycleVersion: 1,
    notBefore: createdAt - 60 * 60 * 1000,
    createdAt,
    expiresAt: createdAt + 84 * 24 * 60 * 60 * 1000,
    mlsSignaturePublicKey: device.profile.mlsDeviceKeyBinding!.mlsSignaturePublicKey
  };
}

async function createRegistry(owner: IdentityFixture): Promise<{
  registry: InstanceType<typeof DeviceRegistryDurableObject>;
  storage: TransactionalStorage;
}> {
  const storage = new TransactionalStorage();
  await storage.put("identity_bundle:v2", { bundle: owner.bundle, etag: "test" });
  for (const device of owner.devices) {
    const record: DeviceRegistryRecord = {
      version: "0.1",
      runtimeId: "runtime:test",
      userId: owner.bundle.userId,
      deviceId: device.deviceId,
      devicePublicKey: device.profile.devicePublicKey,
      bindingHash: "test-binding",
      status: "active",
      registrationVersion: 1,
      createdAt: Date.now(),
      updatedAt: Date.now()
    };
    await storage.put(`device:${device.deviceId}`, record);
  }
  const env = {
    RUNTIME_ID: "runtime:test",
    OWNER_USER_ID: owner.bundle.userId,
    OWNER_USER_PUBLIC_KEY: owner.bundle.userPublicKey,
    WORKER_BUILD_ID: "test-worker-v6",
    SHARING_INTERNAL_SECRET: "registry-test-secret-0123456789abcdef0123456789abcdef",
    INBOX: {
      idFromName: (name: string) => name,
      get: () => ({ fetch: async () => Response.json({ accepted: true }) })
    }
  } as unknown as Env;
  const state = { storage } as unknown as DurableObjectState;
  return {
    registry: new DeviceRegistryDurableObject(state, env),
    storage
  };
}

async function publish(
  registry: InstanceType<typeof DeviceRegistryDurableObject>,
  device: DeviceFixture,
  items: PublishedKeyPackageV2[],
  marker: number
): Promise<void> {
  const body: PublishKeyPackageBatchRequest = {
    version: "2",
    deviceId: device.deviceId,
    idempotencyKey: hex(new Uint8Array(32).fill(marker)),
    packages: items,
    signature: ""
  };
  body.signature = sign(device.secret, publishKeyPackageBatchSigningPayload(body));
  const response = await registry.fetch(new Request(
    "https://registry.test/v2/device-registry/key-packages",
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "X-Tapchat-Device-Id": device.deviceId
      },
      body: JSON.stringify(body)
    }
  ));
  assert.equal(response.status, 200, await response.text());
}

async function claimRequest(
  requester: IdentityFixture,
  owner: IdentityFixture,
  targets: DeviceFixture[],
  idempotencyMarker: number,
  relationshipMarker: number,
  purpose: ClaimKeyPackagesRequest["purpose"] = "group_invite"
): Promise<ClaimKeyPackagesRequest> {
  const now = Date.now();
  const proposal: RelationshipProposalV2 = {
    proposalId: hex(new Uint8Array(32).fill(relationshipMarker + 1)),
    initiatorUserId: requester.bundle.userId,
    initiatorDeviceId: requester.devices[0]!.deviceId,
    relationshipIdCandidate: hex(new Uint8Array(32).fill(relationshipMarker)),
    generation: 1,
    attempt: 1,
    peerUserId: owner.bundle.userId,
    senderBundleDigest: await identityBundleDigest(requester.bundle),
    createdAt: now,
    expiresAt: now + 7 * 24 * 60 * 60 * 1000,
    signature: ""
  };
  proposal.signature = sign(
    requester.devices[0]!.secret,
    relationshipProposalSigningPayload(proposal)
  );
  return {
    version: "2",
    purpose,
    idempotencyKey: hex(new Uint8Array(32).fill(idempotencyMarker)),
    requesterBundle: requester.bundle,
    proposal,
    targets: targets.map((device) => ({
      deviceId: device.deviceId,
      capability: device.profile.keyPackageClaimCapability!
    }))
  };
}

async function claim(
  registry: InstanceType<typeof DeviceRegistryDurableObject>,
  request: ClaimKeyPackagesRequest
): Promise<Response> {
  return registry.fetch(new Request("https://registry.test/v2/key-packages/claims", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(request)
  }));
}

test("concurrent claims never receive the same KeyPackage and idempotent replay is exact", async () => {
  const owner = identity(20, 1, "https://registry.test");
  const requester = identity(40, 1, "https://requester.test");
  const { registry } = await createRegistry(owner);
  const createdAt = Date.now();
  await publish(registry, owner.devices[0]!, [
    packageItem(owner.devices[0]!, 1, createdAt),
    packageItem(owner.devices[0]!, 2, createdAt + 1)
  ], 90);
  const firstRequest = await claimRequest(requester, owner, [owner.devices[0]!], 91, 92);
  const secondRequest = await claimRequest(requester, owner, [owner.devices[0]!], 93, 94);
  const [firstResponse, secondResponse] = await Promise.all([
    claim(registry, firstRequest),
    claim(registry, secondRequest)
  ]);
  assert.equal(firstResponse.status, 200, await firstResponse.clone().text());
  assert.equal(secondResponse.status, 200, await secondResponse.clone().text());
  const first = await firstResponse.json() as ClaimKeyPackagesResult;
  const second = await secondResponse.json() as ClaimKeyPackagesResult;
  assert.notEqual(first.claims[0]!.keyPackageId, second.claims[0]!.keyPackageId);

  const replay = await claim(registry, firstRequest);
  assert.equal(replay.status, 200, await replay.clone().text());
  assert.deepEqual(await replay.json(), first);
});

test("canonical proposal ordering is independent of arrival order", async () => {
  const runOrder = async (lowerFirst: boolean): Promise<{ relationshipId: string; claimed: number }> => {
    const owner = identity(21, 1, "https://registry.test");
    const requester = identity(41, 1, "https://requester.test");
    const { registry } = await createRegistry(owner);
    const createdAt = Date.now();
    await publish(registry, owner.devices[0]!, [
      packageItem(owner.devices[0]!, 11, createdAt),
      packageItem(owner.devices[0]!, 12, createdAt + 1)
    ], lowerFirst ? 111 : 112);
    const lower = await claimRequest(
      requester,
      owner,
      [owner.devices[0]!],
      lowerFirst ? 113 : 114,
      10,
      "direct"
    );
    const higher = await claimRequest(
      requester,
      owner,
      [owner.devices[0]!],
      lowerFirst ? 115 : 116,
      20,
      "direct"
    );
    const first = await claim(registry, lowerFirst ? lower : higher);
    assert.equal(first.status, 200, await first.clone().text());
    const second = await claim(registry, lowerFirst ? higher : lower);
    assert.equal(second.status, lowerFirst ? 409 : 200, await second.clone().text());
    if (lowerFirst) {
      assert.equal((await second.json() as { code: string }).code, "relationship_superseded");
    }

    const relationships = await registry.fetch(new Request(
      "https://registry.test/v2/device-registry/relationships",
      { headers: { "X-Tapchat-Device-Id": owner.devices[0]!.deviceId } }
    ));
    assert.equal(relationships.status, 200, await relationships.clone().text());
    const body = await relationships.json() as {
      relationships: Array<{ relationship: { relationshipId: string } }>;
    };
    const status = await registry.fetch(new Request(
      "https://registry.test/v2/device-registry/key-packages/status",
      { headers: { "X-Tapchat-Device-Id": owner.devices[0]!.deviceId } }
    ));
    return {
      relationshipId: body.relationships[0]!.relationship.relationshipId,
      claimed: (await status.json() as { claimed: number }).claimed
    };
  };

  const lowerThenHigher = await runOrder(true);
  const higherThenLower = await runOrder(false);
  assert.equal(lowerThenHigher.relationshipId, hex(new Uint8Array(32).fill(10)));
  assert.equal(higherThenLower.relationshipId, lowerThenHigher.relationshipId);
  assert.equal(lowerThenHigher.claimed, 1);
  assert.equal(higherThenLower.claimed, 2, "the superseded claim remains permanently burned");
});

test("expired relationship retries retain history and burn a fresh KeyPackage", async () => {
  const owner = identity(22, 1, "https://registry.test");
  const requester = identity(42, 1, "https://requester.test");
  const { registry, storage } = await createRegistry(owner);
  const createdAt = Date.now();
  await publish(registry, owner.devices[0]!, [
    packageItem(owner.devices[0]!, 13, createdAt),
    packageItem(owner.devices[0]!, 14, createdAt + 1)
  ], 117);
  const firstRequest = await claimRequest(
    requester,
    owner,
    [owner.devices[0]!],
    118,
    30,
    "direct"
  );
  const firstResponse = await claim(registry, firstRequest);
  assert.equal(firstResponse.status, 200, await firstResponse.clone().text());
  const first = await firstResponse.json() as ClaimKeyPackagesResult;

  const relationshipEntries = await storage.list<{
    canonicalProposal: RelationshipProposalV2;
    attempts?: Array<{ expiresAt: number }>;
  }>({ prefix: "relationship:v2:" });
  const [relationshipKey, storedRelationship] = Array.from(relationshipEntries.entries())[0]!;
  storedRelationship.canonicalProposal.expiresAt = Date.now() - 1;
  storedRelationship.attempts![0]!.expiresAt = storedRelationship.canonicalProposal.expiresAt;
  await storage.put(relationshipKey, storedRelationship);

  const now = Date.now();
  const retryRequest = clone(firstRequest);
  retryRequest.idempotencyKey = hex(new Uint8Array(32).fill(119));
  retryRequest.proposal.proposalId = hex(new Uint8Array(32).fill(31));
  retryRequest.proposal.attempt = 2;
  retryRequest.proposal.createdAt = now;
  retryRequest.proposal.expiresAt = now + 7 * 24 * 60 * 60 * 1000;
  retryRequest.proposal.signature = sign(
    requester.devices[0]!.secret,
    relationshipProposalSigningPayload(retryRequest.proposal)
  );
  const retryResponse = await claim(registry, retryRequest);
  assert.equal(retryResponse.status, 200, await retryResponse.clone().text());
  const retried = await retryResponse.json() as ClaimKeyPackagesResult;
  assert.notEqual(retried.claims[0]!.claimId, first.claims[0]!.claimId);
  assert.notEqual(retried.claims[0]!.keyPackageId, first.claims[0]!.keyPackageId);

  const relationships = await registry.fetch(new Request(
    "https://registry.test/v2/device-registry/relationships",
    { headers: { "X-Tapchat-Device-Id": owner.devices[0]!.deviceId } }
  ));
  const body = await relationships.json() as {
    relationships: Array<{
      relationship: { relationshipId: string; generation: number; attempts: Array<{ attempt: number }> };
    }>;
  };
  assert.equal(body.relationships[0]!.relationship.relationshipId,
    firstRequest.proposal.relationshipIdCandidate);
  assert.equal(body.relationships[0]!.relationship.generation, 1);
  assert.deepEqual(body.relationships[0]!.relationship.attempts.map((attempt) => attempt.attempt), [1, 2]);
});

test("batch claim is all-or-zero when any target device has no inventory", async () => {
  const owner = identity(60, 2, "https://registry.test");
  const requester = identity(80, 1, "https://requester.test");
  const { registry } = await createRegistry(owner);
  await publish(
    registry,
    owner.devices[0]!,
    [packageItem(owner.devices[0]!, 3, Date.now())],
    95
  );
  const request = await claimRequest(requester, owner, owner.devices, 96, 97);
  const failed = await claim(registry, request);
  assert.equal(failed.status, 409, await failed.clone().text());
  assert.equal((await failed.json() as { code: string }).code, "keypackage_pool_exhausted");

  const status = await registry.fetch(new Request(
    "https://registry.test/v2/device-registry/key-packages/status",
    { headers: { "X-Tapchat-Device-Id": owner.devices[0]!.deviceId } }
  ));
  assert.equal(status.status, 200, await status.clone().text());
  assert.deepEqual(
    await status.json(),
    {
      deviceId: owner.devices[0]!.deviceId,
      available: 1,
      claimed: 0,
      expired: 0,
      target: 16,
      refillThreshold: 8
    }
  );
});

test("any active account device can accept and ticket status requires the opaque secret proof", async () => {
  const owner = identity(100, 2, "https://registry.test");
  const requester = identity(110, 1, "https://requester.test");
  const { registry } = await createRegistry(owner);
  const now = Date.now();
  await publish(
    registry,
    owner.devices[0]!,
    [packageItem(owner.devices[0]!, 7, now)],
    101
  );
  await publish(
    registry,
    owner.devices[1]!,
    [packageItem(owner.devices[1]!, 8, now)],
    102
  );
  const request = await claimRequest(
    requester,
    owner,
    owner.devices,
    103,
    104,
    "direct"
  );
  const claimedResponse = await claim(registry, request);
  assert.equal(claimedResponse.status, 200, await claimedResponse.clone().text());
  const claimed = await claimedResponse.json() as ClaimKeyPackagesResult;
  assert.ok(claimed.ticket?.ticketSecret);

  const actor = owner.devices[1]!;
  const decisionProof: RelationshipDecisionProofV2 = {
    version: "2",
    ticketId: claimed.ticket!.ticketId,
    relationshipId: request.proposal.relationshipIdCandidate,
    generation: request.proposal.generation,
    proposalId: request.proposal.proposalId,
    decision: "accept",
    actorUserId: owner.bundle.userId,
    actorDeviceId: actor.deviceId,
    peerUserId: requester.bundle.userId,
    peerBundleDigest: request.proposal.senderBundleDigest,
    decidedAt: Date.now(),
    signature: ""
  };
  decisionProof.signature = sign(
    actor.secret,
    relationshipDecisionProofSigningPayload(decisionProof)
  );
  const decision = await registry.fetch(new Request(
    `https://registry.test/v2/relationships/${claimed.ticket!.ticketId}/decision`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "X-Tapchat-Device-Id": actor.deviceId
      },
      body: JSON.stringify({ version: "2", decision: "accept", proof: decisionProof })
    }
  ));
  assert.equal(decision.status, 200, await decision.clone().text());

  const relationships = await registry.fetch(new Request(
    "https://registry.test/v2/device-registry/relationships",
    { headers: { "X-Tapchat-Device-Id": owner.devices[0]!.deviceId } }
  ));
  assert.equal(relationships.status, 200, await relationships.clone().text());
  const relationshipBody = await relationships.json() as {
    relationships: Array<{ relationship: { accountState: string } }>;
  };
  assert.equal(relationshipBody.relationships[0]!.relationship.accountState, "accepted");

  const issuedAt = Date.now();
  const secretHashBytes = new Uint8Array(await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(claimed.ticket!.ticketSecret!)
  ));
  const secretHash = hex(secretHashBytes);
  const secretProof = await relationshipTicketSecretProof(
    claimed.ticket!.ticketId,
    requester.devices[0]!.deviceId,
    issuedAt,
    secretHash
  );
  const statusProof = sign(
    requester.devices[0]!.secret,
    relationshipTicketStatusSigningPayload(
      claimed.ticket!.ticketId,
      requester.devices[0]!.deviceId,
      issuedAt,
      secretProof
    )
  );
  const statusRequest = (submittedSecretProof: string) => new Request(
    `https://registry.test/v2/relationships/${claimed.ticket!.ticketId}/status`,
    {
      headers: {
        "X-Tapchat-Ticket-Device": requester.devices[0]!.deviceId,
        "X-Tapchat-Ticket-Issued-At": String(issuedAt),
        "X-Tapchat-Ticket-Secret-Proof": submittedSecretProof,
        "X-Tapchat-Ticket-Proof": statusProof
      }
    }
  );
  const status = await registry.fetch(statusRequest(secretProof));
  assert.equal(status.status, 200, await status.clone().text());
  const statusBody = await status.json() as {
    status: string;
    decisionProof: RelationshipDecisionProofV2;
  };
  assert.equal(statusBody.status, "accepted");
  assert.deepEqual(statusBody.decisionProof, decisionProof);

  const wrongSecretProof = `${secretProof[0] === "0" ? "1" : "0"}${secretProof.slice(1)}`;
  const denied = await registry.fetch(statusRequest(wrongSecretProof));
  assert.equal(denied.status, 403);

  const removed = await registry.fetch(new Request(
    `https://registry.test/v2/device-registry/relationships/${request.proposal.relationshipIdCandidate}/remove`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "X-Tapchat-Device-Id": owner.devices[0]!.deviceId
      },
      body: JSON.stringify({
        version: "2",
        relationshipId: request.proposal.relationshipIdCandidate,
        generation: request.proposal.generation
      })
    }
  ));
  assert.equal(removed.status, 200, await removed.clone().text());
  const afterRemoval = await registry.fetch(new Request(
    "https://registry.test/v2/device-registry/relationships",
    { headers: { "X-Tapchat-Device-Id": owner.devices[1]!.deviceId } }
  ));
  const afterRemovalBody = await afterRemoval.json() as {
    relationships: Array<{ relationship: { accountState: string } }>;
  };
  assert.equal(afterRemovalBody.relationships[0]!.relationship.accountState, "removed");
  const removedStatus = await registry.fetch(statusRequest(secretProof));
  assert.equal(removedStatus.status, 200, await removedStatus.clone().text());
  assert.equal((await removedStatus.json() as { status: string }).status, "removed");
});

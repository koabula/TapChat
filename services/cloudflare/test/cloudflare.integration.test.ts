import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { build } from "esbuild";
import { Miniflare } from "miniflare";
import { ed25519 } from "@noble/curves/ed25519";
import {
  type AppendEnvelopeRequestV2,
  type ClaimKeyPackagesRequest,
  type ClaimKeyPackagesResult,
  CURRENT_MODEL_VERSION,
  type DeploymentBundle,
  type DeviceRuntimeAuth,
  type DeviceRuntimeRefreshChallenge,
  type DeviceBinding,
  type EnvelopeV2,
  type GroupCapability,
  type GroupManifest,
  type IdentityBundle,
  type InboxAppendCapability,
  type KeyPackageClaimCapability,
  type MlsDeviceKeyBinding,
  type PrepareBlobUploadRequest,
  type PublishKeyPackageBatchRequest,
  type PublishKeyPackageBatchResult,
  type PublishedKeyPackageV2,
  type RelationshipDecisionProofV2,
  type RelationshipProposalV2
} from "../src/types/contracts";
import {
  envelopeV2SigningPayload,
  groupCapabilitySigningPayload,
  groupManifestSigningPayload,
  identityBundleDigest,
  identityBundleV2SigningPayload,
  keyPackageClaimCapabilitySigningPayload,
  mlsDeviceKeyBindingSigningPayload,
  publishKeyPackageBatchSigningPayload,
  relationshipDecisionProofSigningPayload,
  relationshipProposalSigningPayload,
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
const OWNER_USER_PUBLIC_KEY = bytesToHex(ed25519.getPublicKey(new Uint8Array(32).fill(11)));
const OWNER_USER_ID = `user:${OWNER_USER_PUBLIC_KEY.slice(0, 16)}`;
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
      OWNER_USER_ID: options?.ownerUserId ?? OWNER_USER_ID,
      OWNER_USER_PUBLIC_KEY,
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

async function issueDeviceBundle(mf: Miniflare, userId = OWNER_USER_ID, deviceId = "device:bob:phone"): Promise<IssuedDeployment> {
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
    registrySchemaVersion: 3
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

function signedIdentityFixture(userId: string, deviceId: string, seed?: number): {
  bundle: IdentityBundle;
  capability: InboxAppendCapability;
  userSecret: Uint8Array;
  deviceSecret: Uint8Array;
};
function signedIdentityFixture(userId: string, deviceId: string, seed = 11): {
  bundle: IdentityBundle;
  capability: InboxAppendCapability;
  userSecret: Uint8Array;
  deviceSecret: Uint8Array;
} {
  const now = Date.now();
  const userSecret = new Uint8Array(32).fill(seed);
  const deviceSecret = new Uint8Array(32).fill(seed + 1);
  const mlsSecret = new Uint8Array(32).fill(seed + 2);
  const userPublicKey = bytesToHex(ed25519.getPublicKey(userSecret));
  const devicePublicKey = bytesToHex(ed25519.getPublicKey(deviceSecret));
  const mlsSignaturePublicKey = bytesToHex(ed25519.getPublicKey(mlsSecret));
  const capability: InboxAppendCapability = {
    version: CURRENT_MODEL_VERSION,
    service: "inbox",
    userId,
    targetDeviceId: deviceId,
    endpoint: `${BASE_URL}/v2/inbox/${encodeURIComponent(deviceId)}/messages`,
    operations: ["append"],
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
  const mlsDeviceKeyBinding: MlsDeviceKeyBinding = {
    version: CURRENT_MODEL_VERSION,
    userId,
    deviceId,
    devicePublicKey,
    mlsSignaturePublicKey,
    ciphersuite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
    createdAt: now,
    signature: ""
  };
  mlsDeviceKeyBinding.signature = signHex(
    deviceSecret,
    mlsDeviceKeyBindingSigningPayload(mlsDeviceKeyBinding)
  );
  const keyPackageClaimCapability: KeyPackageClaimCapability = {
    version: CURRENT_MODEL_VERSION,
    service: "key_package_claim",
    userId,
    targetDeviceId: deviceId,
    endpoint: `${BASE_URL}/v2/key-packages/claims`,
    expiresAt: now + 365 * 24 * 60 * 60 * 1000,
    nonce: bytesToHex(new Uint8Array(32).fill(seed + 3)),
    signature: ""
  };
  keyPackageClaimCapability.signature = signHex(
    deviceSecret,
    keyPackageClaimCapabilitySigningPayload(keyPackageClaimCapability)
  );
  const bundle: IdentityBundle = {
    version: CURRENT_MODEL_VERSION,
    publicationVersion: 2,
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
      keyPackageClaimCapability,
      mlsDeviceKeyBinding
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
  if ((bundle.publicationVersion ?? 0) >= 2) {
    return identityBundleV2SigningPayload(bundle);
  }
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
    const userId = OWNER_USER_ID;
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
    invalid.devices[0].keypackageRef = {
      version: CURRENT_MODEL_VERSION,
      lifecycleVersion: 1,
      userId,
      deviceId,
      ref: `${BASE_URL}/v1/shared-state/keypackages/legacy`,
      notBefore: Date.now() - 60 * 60 * 1000,
      createdAt: Date.now(),
      expiresAt: Date.now() + 84 * 24 * 60 * 60 * 1000
    };
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
    assert.equal(rejected.status, 426);
    assert.equal(((await rejected.json()) as { code: string }).code, "upgrade_required");

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
    const userId = OWNER_USER_ID;
    const fixture = signedIdentityFixture(userId, "device:bob:phone");
    const legacyBundle = structuredClone(fixture.bundle);
    legacyBundle.publicationVersion = 1;
    delete legacyBundle.devices[0].mlsDeviceKeyBinding;
    delete legacyBundle.devices[0].keyPackageClaimCapability;
    const createdAt = Date.now();
    legacyBundle.devices[0].keypackageRef = {
      version: CURRENT_MODEL_VERSION,
      lifecycleVersion: 1,
      userId,
      deviceId: legacyBundle.devices[0].deviceId,
      ref: `${BASE_URL}/v1/shared-state/keypackages/legacy`,
      notBefore: createdAt - 60 * 60 * 1000,
      createdAt,
      expiresAt: createdAt + 84 * 24 * 60 * 60 * 1000
    };
    legacyBundle.signature = signHex(fixture.userSecret, identityBundlePayload(legacyBundle));
    const bucket = (await mf.getR2Bucket("TAPCHAT_STORAGE")) as unknown as {
      put(key: string, value: string): Promise<void>;
      delete(key: string): Promise<void>;
    };
    const legacyKey = `shared-state/${userId}/identity_bundle.json`;
    await bucket.put(legacyKey, JSON.stringify(legacyBundle));

    const identityUrl = `${BASE_URL}/v1/shared-state/${encodeURIComponent(userId)}/identity-bundle`;
    const migrated = await mf.dispatchFetch(identityUrl);
    assert.equal(migrated.status, 200);
    assert.ok(migrated.headers.get("etag"));

    await bucket.delete(legacyKey);
    const authoritative = await mf.dispatchFetch(identityUrl);
    assert.equal(authoritative.status, 200);
    assert.deepEqual(await authoritative.json(), legacyBundle);
  } finally {
    await mf.dispose();
  }
});

test("append authorization uses the registry bundle when the R2 mirror is stale", async (t) => {
  const mf = await createRuntime();
  t.after(async () => {
    await mf.dispose();
  });

  const userId = OWNER_USER_ID;
  const deviceId = "device:bob:authority";
  const deployment = await issueDeviceBundle(mf, userId, deviceId);
  const relationship = await prepareIncomingRelationship(mf, deployment, deviceId, 31);
  const decision = await decideIncomingRelationship(mf, relationship);
  assert.equal(decision.status, 200, await decision.clone().text());
  const fixture = signedFixtures.get(deviceId);
  assert.ok(fixture);
  const bucket = (await mf.getR2Bucket("TAPCHAT_STORAGE")) as unknown as {
    put(key: string, value: string): Promise<void>;
  };
  await bucket.put(
    `shared-state/${userId}/identity_bundle.json`,
    JSON.stringify({ ...fixture.bundle, signature: "00" })
  );

  const delivered = await appendEnvelopeV2(
    mf,
    relationship,
    "msg:authoritative-bundle",
    "cipher-authoritative"
  );
  assert.equal(delivered.status, 200);
  assert.equal(delivered.deliveredTo, "inbox");
});

test("stale append capability requests an identity refresh without queuing a message request", async (t) => {
  const mf = await createRuntime();
  t.after(async () => {
    await mf.dispose();
  });

  const userId = OWNER_USER_ID;
  const deviceId = "device:bob:rotated-capability";
  const deployment = await issueDeviceBundle(mf, userId, deviceId);
  const fixture = signedFixtures.get(deviceId);
  assert.ok(fixture);
  const relationship = await prepareIncomingRelationship(mf, deployment, deviceId, 41);
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

  const staleAppend = await appendEnvelopeV2(
    mf,
    relationship,
    "msg:stale-capability",
    "cipher-stale",
    "mls_welcome"
  );
  assert.equal(staleAppend.status, 409);
  assert.equal(staleAppend.code, "identity_refresh_required");

  const headResponse = await mf.dispatchFetch(
    `${BASE_URL}/v2/inbox/${encodeURIComponent(deviceId)}/head`,
    { headers: authHeaders(deployment.runtimeCredential.token) }
  );
  assert.equal(headResponse.status, 200);
  assert.equal(((await headResponse.json()) as { headSeq: number }).headSeq, 0);
});

function bytesToHex(input: Uint8Array): string {
  return Array.from(input, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

const GROUP_ID = "group:integration";
const GROUP_OWNER_USER_ID = OWNER_USER_ID;
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

function opaqueHex(marker: number): string {
  return bytesToHex(new Uint8Array(32).fill(marker));
}

interface IncomingRelationshipContext {
  deployment: IssuedDeployment;
  owner: ReturnType<typeof signedIdentityFixture>;
  sender: ReturnType<typeof signedIdentityFixture>;
  proposal: RelationshipProposalV2;
  claim: ClaimKeyPackagesResult;
  recipientDeviceId: string;
  recipientCapability: InboxAppendCapability;
}

async function prepareIncomingRelationship(
  mf: Miniflare,
  deployment: IssuedDeployment,
  recipientDeviceId: string,
  marker: number
): Promise<IncomingRelationshipContext> {
  const owner = signedFixtures.get(recipientDeviceId);
  assert.ok(owner, `owner fixture missing for ${recipientDeviceId}`);
  const ownerDevice = owner.bundle.devices.find((device) => device.deviceId === recipientDeviceId);
  assert.ok(ownerDevice?.mlsDeviceKeyBinding);
  assert.ok(ownerDevice.keyPackageClaimCapability);

  const createdAt = Date.now();
  const item: PublishedKeyPackageV2 = {
    keyPackageId: opaqueHex(marker),
    keyPackageB64: btoa(`key-package-${recipientDeviceId}-${marker}`),
    lifecycleVersion: 1,
    notBefore: Math.max(0, createdAt - 60 * 60 * 1000),
    createdAt,
    expiresAt: createdAt + 84 * 24 * 60 * 60 * 1000,
    mlsSignaturePublicKey: ownerDevice.mlsDeviceKeyBinding.mlsSignaturePublicKey
  };
  const publish: PublishKeyPackageBatchRequest = {
    version: "2",
    deviceId: recipientDeviceId,
    packages: [item],
    idempotencyKey: opaqueHex(marker + 1),
    signature: ""
  };
  publish.signature = signHex(owner.deviceSecret, publishKeyPackageBatchSigningPayload(publish));
  const published = await mf.dispatchFetch(`${BASE_URL}/v2/device-registry/key-packages`, {
    method: "POST",
    headers: {
      ...authHeaders(deployment.runtimeCredential.token),
      "content-type": "application/json"
    },
    body: JSON.stringify(publish)
  });
  assert.equal(published.status, 200, await published.clone().text());
  const publishResult = await published.json() as PublishKeyPackageBatchResult;
  assert.deepEqual(publishResult, {
    accepted: true,
    idempotencyKey: publish.idempotencyKey,
    published: publish.packages.length
  });

  const replayed = await mf.dispatchFetch(`${BASE_URL}/v2/device-registry/key-packages`, {
    method: "POST",
    headers: {
      ...authHeaders(deployment.runtimeCredential.token),
      "content-type": "application/json"
    },
    body: JSON.stringify(publish)
  });
  assert.equal(replayed.status, 200, await replayed.clone().text());
  assert.deepEqual(await replayed.json(), publishResult);

  const senderSeed = marker + 20;
  const senderUserPublicKey = bytesToHex(ed25519.getPublicKey(new Uint8Array(32).fill(senderSeed)));
  const senderUserId = `user:${senderUserPublicKey.slice(0, 16)}`;
  const sender = signedIdentityFixture(senderUserId, `device:sender:${marker}`, senderSeed);
  const senderBundleDigest = await identityBundleDigest(sender.bundle);
  const now = Date.now();
  const proposal: RelationshipProposalV2 = {
    proposalId: opaqueHex(marker + 2),
    initiatorUserId: sender.bundle.userId,
    initiatorDeviceId: sender.bundle.devices[0].deviceId,
    relationshipIdCandidate: opaqueHex(marker + 3),
    generation: 1,
    attempt: 1,
    peerUserId: owner.bundle.userId,
    senderBundleDigest,
    createdAt: now,
    expiresAt: now + 7 * 24 * 60 * 60 * 1000,
    signature: ""
  };
  proposal.signature = signHex(sender.deviceSecret, relationshipProposalSigningPayload(proposal));
  const claimRequest: ClaimKeyPackagesRequest = {
    version: "2",
    purpose: "direct",
    idempotencyKey: opaqueHex(marker + 4),
    requesterBundle: sender.bundle,
    proposal,
    targets: [{
      deviceId: recipientDeviceId,
      capability: ownerDevice.keyPackageClaimCapability
    }]
  };
  const claimed = await mf.dispatchFetch(`${BASE_URL}/v2/key-packages/claims`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(claimRequest)
  });
  assert.equal(claimed.status, 200, await claimed.clone().text());
  const claim = await claimed.json() as ClaimKeyPackagesResult;
  assert.equal(claim.claims.length, 1);
  assert.ok(claim.ticket);
  return {
    deployment,
    owner,
    sender,
    proposal,
    claim,
    recipientDeviceId,
    recipientCapability: owner.capability
  };
}

async function decideIncomingRelationship(
  mf: Miniflare,
  context: IncomingRelationshipContext,
  decision: "accept" | "reject" = "accept"
) {
  const proof: RelationshipDecisionProofV2 = {
    version: "2",
    ticketId: context.claim.ticket!.ticketId,
    relationshipId: context.proposal.relationshipIdCandidate,
    generation: context.proposal.generation,
    proposalId: context.proposal.proposalId,
    decision,
    actorUserId: context.owner.bundle.userId,
    actorDeviceId: context.recipientDeviceId,
    peerUserId: context.sender.bundle.userId,
    peerBundleDigest: context.proposal.senderBundleDigest,
    decidedAt: Date.now(),
    signature: ""
  };
  proof.signature = signHex(
    context.owner.deviceSecret,
    relationshipDecisionProofSigningPayload(proof)
  );
  return mf.dispatchFetch(
    `${BASE_URL}/v2/relationships/${encodeURIComponent(context.claim.ticket!.ticketId)}/decision`,
    {
      method: "POST",
      headers: {
        ...authHeaders(context.deployment.runtimeCredential.token),
        "content-type": "application/json"
      },
      body: JSON.stringify({ version: "2", decision, proof })
    }
  );
}

async function appendEnvelopeV2(
  mf: Miniflare,
  context: IncomingRelationshipContext,
  messageId: string,
  ciphertext: string,
  messageType: EnvelopeV2["messageType"] = "mls_application"
): Promise<Record<string, unknown>> {
  const envelope: EnvelopeV2 = {
    version: "2",
    messageId,
    conversationId: `conv:direct:v2:${context.proposal.relationshipIdCandidate}:g${context.proposal.generation}`,
    relationshipId: context.proposal.relationshipIdCandidate,
    generation: context.proposal.generation,
    attempt: context.proposal.attempt,
    proposalId: context.proposal.proposalId,
    claimId: context.claim.claims[0].claimId,
    senderUserId: context.sender.bundle.userId,
    senderDeviceId: context.sender.bundle.devices[0].deviceId,
    recipientUserId: context.owner.bundle.userId,
    recipientDeviceId: context.recipientDeviceId,
    createdAt: Date.now(),
    messageType,
    inlineCiphertext: ciphertext,
    storageRefs: [],
    deliveryClass: "normal",
    senderBundleDigest: context.proposal.senderBundleDigest,
    senderProof: { type: "ed25519_device_v2", value: "" }
  };
  envelope.senderProof.value = signHex(
    context.sender.deviceSecret,
    await envelopeV2SigningPayload(envelope)
  );
  const request: AppendEnvelopeRequestV2 = {
    version: "2",
    recipientDeviceId: context.recipientDeviceId,
    envelope,
    senderIdentityBundle: context.sender.bundle,
    recipientCapability: context.recipientCapability,
    relationshipTicketId: context.claim.ticket?.ticketId,
    relationshipProposal: context.proposal
  };
  const response = await mf.dispatchFetch(
    `${BASE_URL}/v2/inbox/${encodeURIComponent(context.recipientDeviceId)}/messages`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${context.recipientCapability.signature}`,
        "X-Tapchat-Capability": JSON.stringify(context.recipientCapability),
        "content-type": "application/json"
      },
      body: JSON.stringify(request)
    }
  );
  return {
    status: response.status,
    ...(await response.json() as object)
  };
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
    const headResponse = await mf.dispatchFetch(`${BASE_URL}/v2/inbox/${encodeURIComponent(deviceId)}/head`, {
      headers: authHeaders(token)
    });
    assert.equal(headResponse.status, 200);
    const head = (await headResponse.json()) as { headSeq: number };
    if (head.headSeq !== 2) {
      throw new Error(`expected headSeq to remain 2, got ${head.headSeq}`);
    }

    const fetchResponse = await mf.dispatchFetch(`${BASE_URL}/v2/inbox/${encodeURIComponent(deviceId)}/messages?fromSeq=${fromSeq}&limit=10`, {
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
  const bundle = await issueDeviceBundle(mf, OWNER_USER_ID, deviceId);
  const token = bundle.runtimeCredential.token;
  const relationship = await prepareIncomingRelationship(mf, bundle, deviceId, 51);
  const relationshipDecision = await decideIncomingRelationship(mf, relationship);
  assert.equal(relationshipDecision.status, 200, await relationshipDecision.clone().text());

  const subscribeResponse = await mf.dispatchFetch(`${BASE_URL}/v2/inbox/${encodeURIComponent(deviceId)}/subscribe`, {
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

  const append1 = await appendEnvelopeV2(mf, relationship, "msg:1", "cipher-1");
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
  const append2 = await appendEnvelopeV2(mf, relationship, "msg:2", bigCiphertext);
  assert.equal(append2.seq, 2);

  const headResponse = await mf.dispatchFetch(`${BASE_URL}/v2/inbox/${encodeURIComponent(deviceId)}/head`, {
    headers: authHeaders(token)
  });
  assert.equal(headResponse.status, 200);
  const head = (await headResponse.json()) as { headSeq: number };
  assert.equal(head.headSeq, 2);

  const fetchResponse = await mf.dispatchFetch(`${BASE_URL}/v2/inbox/${encodeURIComponent(deviceId)}/messages?fromSeq=2&limit=10`, {
    headers: authHeaders(token)
  });
  assert.equal(fetchResponse.status, 200);
  const fetched = (await fetchResponse.json()) as { toSeq: number; records: Array<{ seq: number; messageId: string; envelope: { inlineCiphertext?: string } }> };
  assert.equal(fetched.toSeq, 2);
  assert.equal(fetched.records.length, 1);
  assert.equal(fetched.records[0].seq, 2);
  assert.equal(fetched.records[0].messageId, "msg:2");
  assert.equal(fetched.records[0].envelope.inlineCiphertext, bigCiphertext);

  const ackResponse = await mf.dispatchFetch(`${BASE_URL}/v2/inbox/${encodeURIComponent(deviceId)}/ack`, {
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
  const bundle = await issueDeviceBundle(mf, OWNER_USER_ID, deviceId);
  const token = bundle.runtimeCredential.token;
  const relationship = await prepareIncomingRelationship(mf, bundle, deviceId, 61);
  const relationshipDecision = await decideIncomingRelationship(mf, relationship);
  assert.equal(relationshipDecision.status, 200, await relationshipDecision.clone().text());

  const append1 = await appendEnvelopeV2(mf, relationship, "msg:cleanup-1", "cipher-cleanup-1");
  const append2 = await appendEnvelopeV2(mf, relationship, "msg:cleanup-2", "cipher-cleanup-2");
  assert.equal(append1.seq, 1);
  assert.equal(append2.seq, 2);

  const ackResponse = await mf.dispatchFetch(`${BASE_URL}/v2/inbox/${encodeURIComponent(deviceId)}/ack`, {
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
    const headResponse = await mf.dispatchFetch(`${BASE_URL}/v2/inbox/${encodeURIComponent(deviceId)}/head`, {
      headers: authHeaders(token)
    });
    assert.equal(headResponse.status, 200);
    const head = (await headResponse.json()) as { headSeq: number };
    assert.equal(head.headSeq, 2);

    const fetchResponse = await mf.dispatchFetch(`${BASE_URL}/v2/inbox/${encodeURIComponent(deviceId)}/messages?fromSeq=${fromSeq}&limit=10`, {
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
  const bundle = await issueDeviceBundle(mf, OWNER_USER_ID, deviceId);
  const token = bundle.runtimeCredential.token;
  const relationship = await prepareIncomingRelationship(mf, bundle, deviceId, 71);

  const subscribeResponse = await mf.dispatchFetch(`${BASE_URL}/v2/inbox/${encodeURIComponent(deviceId)}/subscribe`, {
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

  const queued = await appendEnvelopeV2(
    mf,
    relationship,
    "msg:req-1",
    "cipher-req",
    "mls_welcome"
  );
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
  assert.equal(queuedEvent.senderUserId, relationship.sender.bundle.userId);
  assert.equal(queuedEvent.change, "queued");

  const headResponse = await mf.dispatchFetch(`${BASE_URL}/v2/inbox/${encodeURIComponent(deviceId)}/head`, {
    headers: authHeaders(token)
  });
  const head = (await headResponse.json()) as { headSeq: number };
  assert.equal(head.headSeq, 0);

  const requestsResponse = await mf.dispatchFetch(`${BASE_URL}/v2/relationships/requests`, {
    headers: authHeaders(token)
  });
  assert.equal(requestsResponse.status, 200);
  const requests = (await requestsResponse.json()) as {
    requests: Array<{ ticketId: string; peerBundle: IdentityBundle }>;
  };
  assert.equal(requests.requests.length, 1);
  assert.equal(requests.requests[0].ticketId, relationship.claim.ticket!.ticketId);
  assert.equal(requests.requests[0].peerBundle.userId, relationship.sender.bundle.userId);

  const acceptResponse = await decideIncomingRelationship(mf, relationship);
  assert.equal(acceptResponse.status, 200);
  const acceptedEvent = await waitForMatchingWebSocketMessage(socket, (value): value is {
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
      candidate.senderUserId === relationship.sender.bundle.userId &&
      candidate.requestId === queued.requestId
    );
  });
  assert.equal(acceptedEvent.event, "message_request_changed");
  assert.equal(acceptedEvent.senderUserId, relationship.sender.bundle.userId);
  assert.equal(acceptedEvent.requestId, queued.requestId);
  assert.equal(acceptedEvent.change, "accepted");

  const deliveredAfterAccept = await appendEnvelopeV2(
    mf,
    relationship,
    "msg:req-2",
    "cipher-after-accept"
  );
  assert.equal(deliveredAfterAccept.status, 200);
  assert.equal(deliveredAfterAccept.deliveredTo, "inbox");
  assert.notEqual(deliveredAfterAccept.queuedAsRequest, true);

  const fetchResponse = await mf.dispatchFetch(`${BASE_URL}/v2/inbox/${encodeURIComponent(deviceId)}/messages?fromSeq=1&limit=10`, {
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

  const bundle = await issueDeviceBundle(mf, OWNER_USER_ID, "device:bob:laptop");
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


import type { DurableObject as CloudflareDurableObject } from "cloudflare:workers";

import {
  HttpError,
  identityBundleDigest,
  publishKeyPackageBatchSigningPayload,
  relationshipDecisionProofSigningPayload,
  relationshipProposalSigningPayload,
  relationshipTicketSecretProof,
  relationshipTicketStatusSigningPayload,
  verifyDeviceBinding,
  verifyEd25519,
  verifyIdentityBundle,
  verifyKeyPackageClaimCapability
} from "../auth/capability";
import { CONTROL_JSON_MAX_BYTES, readJsonLimited } from "../auth/runtime-security";
import { deviceRuntimeSigningPayload } from "../auth/runtime-auth";
import {
  CURRENT_MODEL_VERSION,
  type ConfirmRelationshipPeerDecisionRequest,
  type ClaimKeyPackagesRequest,
  type ClaimKeyPackagesResult,
  type ClaimedKeyPackage,
  type DeviceContactProfile,
  type DeviceRegistryRecord,
  type DeviceRuntimeEnrollmentProof,
  type DeviceRuntimeRefreshChallenge,
  type DeviceRuntimeRefreshProof,
  type DeviceRuntimeToken,
  type IdentityBundle,
  type KeyPackagePoolStatus,
  type PersistedRelationship,
  type PublishKeyPackageBatchRequest,
  type PublishKeyPackageBatchResult,
  type PublishedKeyPackageV2,
  type RemoveRelationshipRequest,
  type RelationshipDecisionProofV2,
  type RelationshipDecisionRequest,
  type RelationshipProposalV2,
  type RelationshipTicket,
  type UpsertOutboundRelationshipRequest
} from "../types/contracts";
import type { Env } from "../types/env";
import { appErrorBody } from "../errors";

const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const CHALLENGE_PREFIX = "challenge:";
const DEVICE_PREFIX = "device:";
const IDENTITY_BUNDLE_KEY = "identity_bundle:v2";
const MAX_ACTIVE_CHALLENGES = 8;
const KEY_PACKAGE_LIFETIME_MS = 84 * 24 * 60 * 60 * 1000;
const KEY_PACKAGE_NOT_BEFORE_SKEW_MS = 60 * 60 * 1000;
const KEY_PACKAGE_MIN_REMAINING_MS = 7 * 24 * 60 * 60 * 1000;
const CLOCK_TOLERANCE_MS = 5 * 60 * 1000;
const INBOX_CAPABILITY_MAX_LIFETIME_MS = 365 * 24 * 60 * 60 * 1000;
const KEY_PACKAGE_PREFIX = "key-package:v2:";
const KEY_PACKAGE_PUBLISH_IDEMPOTENCY_PREFIX = "key-package-publish-idempotency:v2:";
const KEY_PACKAGE_CLAIM_IDEMPOTENCY_PREFIX = "key-package-claim-idempotency:v2:";
const RELATIONSHIP_PREFIX = "relationship:v2:";
const RELATIONSHIP_TICKET_PREFIX = "relationship-ticket:v2:";
const RELATIONSHIP_PROJECTION_PREFIX = "relationship-projection:v2:";
const KEY_PACKAGE_POOL_TARGET = 16;
const KEY_PACKAGE_POOL_REFILL_THRESHOLD = 8;
const MAX_KEY_PACKAGE_BATCH = 16;
const KEY_PACKAGE_BATCH_MAX_BYTES = 512 * 1024;
const RELATIONSHIP_ATTEMPT_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const OPAQUE_ID_PATTERN = /^[0-9a-f]{64}$/i;
const MLS_CIPHERSUITE_V2 = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";

interface StoredIdentityBundle {
  bundle: IdentityBundle;
  etag: string;
}

interface StoredKeyPackage extends PublishedKeyPackageV2 {
  userId: string;
  deviceId: string;
  state: "available" | "claimed" | "expired";
  claimId?: string;
  claimedAt?: number;
  publishedAt: number;
}

interface StoredClaimResult {
  idempotencyKey: string;
  requestDigest: string;
  claims: ClaimedKeyPackage[];
  ticket?: Omit<RelationshipTicket, "ticketSecret">;
}

interface StoredTicketIndex {
  relationshipKey: string;
  ticketSecretHash: string;
  status?: "active" | "superseded";
}

interface StoredRelationship extends PersistedRelationship {
  direction: "incoming" | "outbound";
  peerBundle: IdentityBundle;
  ticketId: string;
  ticketSecretHash?: string;
  ticketStatusEndpoint?: string;
  decisionProof?: RelationshipDecisionProofV2;
}

interface StoredPublishResult {
  deviceId: string;
  packageIds: string[];
  requestDigest: string;
}

interface RelationshipProjection {
  ticketId: string;
  deviceId: string;
  senderUserId: string;
  proposalId: string;
  decision: "accept" | "reject";
  attemptCount: number;
  nextRetryAt: number;
}

const DurableObjectBase: typeof CloudflareDurableObject<Env> =
  (globalThis as { DurableObject?: typeof CloudflareDurableObject<Env> }).DurableObject ??
  (class {
    constructor(_state: DurableObjectState, _env: Env) {}
  } as unknown as typeof CloudflareDurableObject<Env>);

function jsonResponse(body: unknown, status = 200): Response {
  return Response.json(body, { status });
}

function errorResponse(status: number, code: string): Response {
  return jsonResponse(appErrorBody(status, code, crypto.randomUUID()), status);
}

function runtimeConfig(env: Env): { runtimeId: string; userId: string; userPublicKey: string } {
  const runtimeId = env.RUNTIME_ID?.trim();
  const userId = env.OWNER_USER_ID?.trim();
  const userPublicKey = env.OWNER_USER_PUBLIC_KEY?.trim();
  if (!runtimeId || !userId || !userPublicKey) {
    throw new HttpError(503, "runtime_misconfigured", "runtime owner identity is not configured");
  }
  return { runtimeId, userId, userPublicKey };
}

function challengeKey(nonce: string): string {
  return `${CHALLENGE_PREFIX}${nonce}`;
}

function deviceKey(deviceId: string): string {
  return `${DEVICE_PREFIX}${deviceId}`;
}

function randomNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function requireTicketDerivationSecret(env: Env): string {
  const secret = env.SHARING_INTERNAL_SECRET?.trim() || env.DEVICE_RUNTIME_SECRET?.trim();
  if (!secret) {
    throw new HttpError(503, "runtime_misconfigured", "ticket derivation secret is not configured");
  }
  return secret;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const source = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", source)));
}

async function deriveTicketSecret(env: Env, idempotencyKey: string, ticketId: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(requireTicketDerivationSecret(env)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const input = encoder.encode(`tapchat-relationship-ticket-v2|${idempotencyKey}|${ticketId}`);
  return bytesToHex(new Uint8Array(await crypto.subtle.sign("HMAC", key, input)));
}

async function publishRequestDigest(body: PublishKeyPackageBatchRequest): Promise<string> {
  return sha256Hex(JSON.stringify([
    "tapchat-key-package-publish-v2",
    body.deviceId,
    body.idempotencyKey,
    [...body.packages]
      .sort((left, right) => left.keyPackageId.localeCompare(right.keyPackageId))
      .map((item) => [
        item.keyPackageId,
        item.keyPackageB64,
        item.lifecycleVersion,
        item.notBefore,
        item.createdAt,
        item.expiresAt,
        item.mlsSignaturePublicKey
      ]),
    body.signature
  ]));
}

async function claimRequestDigest(body: ClaimKeyPackagesRequest): Promise<string> {
  const requesterBundleDigest = await identityBundleDigest(body.requesterBundle);
  return sha256Hex(JSON.stringify([
    "tapchat-key-package-claim-v2",
    body.version,
    body.purpose,
    body.idempotencyKey,
    body.requesterBundle.userId,
    requesterBundleDigest,
    body.proposal.proposalId,
    body.proposal.initiatorUserId,
    body.proposal.initiatorDeviceId,
    body.proposal.relationshipIdCandidate,
    body.proposal.generation,
    body.proposal.attempt,
    body.proposal.peerUserId,
    body.proposal.senderBundleDigest,
    body.proposal.createdAt,
    body.proposal.expiresAt,
    body.proposal.signature,
    [...body.targets]
      .sort((left, right) => left.deviceId.localeCompare(right.deviceId))
      .map((target) => [
        target.deviceId,
        target.capability.version,
        target.capability.service,
        target.capability.userId,
        target.capability.targetDeviceId,
        target.capability.endpoint,
        target.capability.expiresAt,
        target.capability.nonce,
        target.capability.signature
      ])
  ]));
}

function packageKey(deviceId: string, keyPackageId: string): string {
  return `${KEY_PACKAGE_PREFIX}${deviceId}:${keyPackageId}`;
}

function relationshipRank(proposal: RelationshipProposalV2): [string, string, string] {
  return [proposal.initiatorUserId, proposal.relationshipIdCandidate, proposal.proposalId];
}

function compareRank(left: RelationshipProposalV2, right: RelationshipProposalV2): number {
  const a = relationshipRank(left);
  const b = relationshipRank(right);
  for (let index = 0; index < a.length; index += 1) {
    const compared = a[index]!.localeCompare(b[index]!);
    if (compared !== 0) return compared;
  }
  return 0;
}

function validateOpaqueId(name: string, value: string): void {
  if (!OPAQUE_ID_PATTERN.test(value)) {
    throw new HttpError(400, "invalid_input", `${name} must be an opaque 256-bit hex identifier`);
  }
}

async function bindingHash(device: DeviceContactProfile): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(JSON.stringify(device.binding))
  );
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function identityBundleEtag(bundle: IdentityBundle): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(JSON.stringify(bundle))
  );
  const value = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `"${value}"`;
}

function validateIdentityBundleLifecycle(bundle: IdentityBundle, writerDeviceId: string, now: number): void {
  if (bundle.publicationVersion !== 2 || !Number.isSafeInteger(bundle.publicationRevision) || bundle.publicationRevision! < 1) {
    throw new HttpError(426, "upgrade_required", "identity bundle publication protocol is not supported");
  }
  const writer = bundle.devices.find((device) => device.deviceId === writerDeviceId);
  if (!writer || writer.status !== "active") {
    throw new HttpError(403, "device_revoked", "publishing device is not active in the identity bundle");
  }
  for (const device of bundle.devices) {
    if (device.keypackageRef) {
      throw new HttpError(426, "upgrade_required", "IdentityBundle V2 must not publish public KeyPackage references");
    }
    const capability = device.inboxAppendCapability;
    if (capability) {
      if (
        capability.userId !== bundle.userId ||
        capability.targetDeviceId !== device.deviceId ||
        capability.expiresAt <= now - CLOCK_TOLERANCE_MS ||
        capability.expiresAt > now + INBOX_CAPABILITY_MAX_LIFETIME_MS + CLOCK_TOLERANCE_MS
      ) {
        throw new HttpError(422, "capability_expired", "inbox append capability lifecycle is invalid");
      }
    }
    if (device.status === "active") {
      const claimCapability = device.keyPackageClaimCapability;
      const mlsBinding = device.mlsDeviceKeyBinding;
      if (
        !claimCapability ||
        !mlsBinding ||
        claimCapability.userId !== bundle.userId ||
        claimCapability.targetDeviceId !== device.deviceId ||
        claimCapability.expiresAt <= now ||
        claimCapability.expiresAt > now + INBOX_CAPABILITY_MAX_LIFETIME_MS + CLOCK_TOLERANCE_MS ||
        mlsBinding.userId !== bundle.userId ||
        mlsBinding.deviceId !== device.deviceId ||
        mlsBinding.devicePublicKey !== device.devicePublicKey ||
        mlsBinding.ciphersuite !== MLS_CIPHERSUITE_V2
      ) {
        throw new HttpError(422, "identity_binding_invalid", "active device V2 bindings are invalid");
      }
    }
  }
  if (
    !writer.inboxAppendCapability ||
    writer.inboxAppendCapability.expiresAt <= now ||
    !writer.keyPackageClaimCapability ||
    writer.keyPackageClaimCapability.expiresAt <= now ||
    !writer.mlsDeviceKeyBinding
  ) {
    throw new HttpError(422, "capability_expired", "publishing device inbox append capability is expired");
  }
}

function assertChallengeScope(
  challenge: DeviceRuntimeRefreshChallenge,
  purpose: DeviceRuntimeRefreshChallenge["purpose"],
  config: ReturnType<typeof runtimeConfig>,
  now: number
): void {
  if (
    challenge.version !== CURRENT_MODEL_VERSION ||
    challenge.purpose !== purpose ||
    challenge.runtimeId !== config.runtimeId ||
    challenge.userId !== config.userId ||
    !challenge.deviceId ||
    !challenge.nonce ||
    challenge.expiresAt <= now
  ) {
    throw new HttpError(403, "runtime_auth_invalid", "runtime authorization challenge is invalid or expired");
  }
}

function sameChallenge(
  stored: DeviceRuntimeRefreshChallenge,
  submitted: DeviceRuntimeRefreshChallenge
): boolean {
  return stored.version === submitted.version
    && stored.purpose === submitted.purpose
    && stored.runtimeId === submitted.runtimeId
    && stored.userId === submitted.userId
    && stored.deviceId === submitted.deviceId
    && stored.nonce === submitted.nonce
    && stored.expiresAt === submitted.expiresAt;
}

export class DeviceRegistryDurableObject extends DurableObjectBase {
  private readonly stateRef: DurableObjectState;
  private readonly envRef: Env;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.stateRef = state;
    this.envRef = env;
  }

  async fetch(request: Request): Promise<Response> {
    try {
      const url = new URL(request.url);
      const now = Date.now();
      if (request.method === "GET" && url.pathname.endsWith("/ready")) {
        return await this.ready();
      }
      if (request.method === "POST" && url.pathname.endsWith("/challenge")) {
        return await this.issueChallenge(request, now);
      }
      if (request.method === "POST" && url.pathname.endsWith("/enroll")) {
        return await this.enroll(request, now);
      }
      if (request.method === "POST" && url.pathname.endsWith("/refresh")) {
        return await this.refresh(request, now);
      }
      if (request.method === "POST" && url.pathname.endsWith("/authorize")) {
        return await this.authorize(request);
      }
      if (request.method === "POST" && url.pathname.endsWith("/device-registry/key-packages")) {
        return await this.publishKeyPackages(request, now);
      }
      if (request.method === "GET" && url.pathname.endsWith("/device-registry/key-packages/status")) {
        return await this.keyPackageStatus(request, now);
      }
      if (request.method === "POST" && url.pathname.endsWith("/key-packages/claims")) {
        return await this.claimKeyPackages(request, now);
      }
      if (request.method === "POST" && url.pathname.endsWith("/relationships/authorize-append")) {
        return await this.authorizeRelationshipAppend(request);
      }
      if (request.method === "GET" && url.pathname.endsWith("/device-registry/relationships")) {
        return await this.listRelationships(request);
      }
      if (request.method === "POST" && url.pathname.endsWith("/device-registry/relationships/outbound")) {
        return await this.upsertOutboundRelationship(request, now);
      }
      const removeRelationship = url.pathname.match(
        /\/device-registry\/relationships\/([^/]+)\/remove$/
      );
      if (request.method === "POST" && removeRelationship) {
        return await this.removeRelationship(
          request,
          decodeURIComponent(removeRelationship[1]!),
          now
        );
      }
      const peerDecision = url.pathname.match(
        /\/device-registry\/relationships\/([^/]+)\/peer-decision$/
      );
      if (request.method === "POST" && peerDecision) {
        return await this.confirmRelationshipPeerDecision(
          request,
          decodeURIComponent(peerDecision[1]!),
          now
        );
      }
      const joinState = url.pathname.match(
        /\/device-registry\/relationships\/([^/]+)\/devices\/([^/]+)\/join-state$/
      );
      if (request.method === "POST" && joinState) {
        return await this.updateRelationshipDeviceJoinState(
          request,
          decodeURIComponent(joinState[1]!),
          decodeURIComponent(joinState[2]!),
          now
        );
      }
      if (request.method === "GET" && url.pathname.endsWith("/relationships/requests")) {
        return await this.listRelationshipRequests(request);
      }
      const relationshipDecision = url.pathname.match(/\/relationships\/([^/]+)\/decision$/);
      if (request.method === "POST" && relationshipDecision) {
        return await this.decideRelationship(
          request,
          decodeURIComponent(relationshipDecision[1]!),
          now
        );
      }
      const relationshipStatus = url.pathname.match(/\/relationships\/([^/]+)\/status$/);
      if (request.method === "GET" && relationshipStatus) {
        return await this.relationshipStatus(
          request,
          decodeURIComponent(relationshipStatus[1]!)
        );
      }
      if (request.method === "POST" && url.pathname.endsWith("/sync")) {
        return await this.syncIdentityBundle(request, now);
      }
      if (request.method === "GET" && url.pathname.endsWith("/identity-bundle")) {
        return await this.getIdentityBundle();
      }
      if (request.method === "POST" && url.pathname.endsWith("/identity-bundle/migrate")) {
        return await this.migrateIdentityBundle(request, now);
      }
      return errorResponse(404, "not_found");
    } catch (error) {
      if (error instanceof HttpError) {
        return errorResponse(error.status, error.code);
      }
      return errorResponse(500, "temporary_unavailable");
    }
  }

  async alarm(): Promise<void> {
    await this.runRelationshipProjections(Date.now());
  }

  private async ready(): Promise<Response> {
    const config = runtimeConfig(this.envRef);
    // Touch storage so this endpoint only succeeds once the namespace, class,
    // and backing storage are all available at the serving location.
    await this.stateRef.storage.get("__runtime_registry_ready__");
    return jsonResponse({
      ready: true,
      runtimeId: config.runtimeId,
      protocolVersion: 6,
      workerBuildId: this.envRef.WORKER_BUILD_ID?.trim() || "tapchat-worker-v6-unknown",
      registrySchemaVersion: 3
    });
  }

  private async issueChallenge(request: Request, now: number): Promise<Response> {
    const config = runtimeConfig(this.envRef);
    const body = await readJsonLimited<{
      purpose?: DeviceRuntimeRefreshChallenge["purpose"];
      userId?: string;
      deviceId?: string;
    }>(request, CONTROL_JSON_MAX_BYTES);
    if (
      (body.purpose !== "enroll" && body.purpose !== "refresh") ||
      body.userId !== config.userId ||
      !body.deviceId
    ) {
      throw new HttpError(400, "runtime_auth_invalid", "runtime authorization challenge scope is invalid");
    }
    if (body.purpose === "refresh") {
      const record = await this.stateRef.storage.get<DeviceRegistryRecord>(deviceKey(body.deviceId));
      if (!record) throw new HttpError(403, "enrollment_required", "device is not registered");
      if (record.status !== "active") throw new HttpError(403, "device_revoked", "device is revoked");
    }
    const existing = await this.stateRef.storage.list<DeviceRuntimeRefreshChallenge>({ prefix: CHALLENGE_PREFIX });
    const expired = Array.from(existing.entries())
      .filter(([, challenge]) => challenge.expiresAt <= now)
      .map(([key]) => key);
    if (expired.length) await this.stateRef.storage.delete(expired);
    if (existing.size - expired.length >= MAX_ACTIVE_CHALLENGES) {
      throw new HttpError(429, "rate_limited", "too many active runtime authorization challenges");
    }
    const challenge: DeviceRuntimeRefreshChallenge = {
      version: CURRENT_MODEL_VERSION,
      purpose: body.purpose,
      runtimeId: config.runtimeId,
      userId: config.userId,
      deviceId: body.deviceId,
      nonce: randomNonce(),
      expiresAt: now + CHALLENGE_TTL_MS
    };
    await this.stateRef.storage.put(challengeKey(challenge.nonce), challenge);
    return jsonResponse(challenge);
  }

  private async consumeChallenge(
    challenge: DeviceRuntimeRefreshChallenge,
    purpose: DeviceRuntimeRefreshChallenge["purpose"],
    now: number
  ): Promise<void> {
    const config = runtimeConfig(this.envRef);
    assertChallengeScope(challenge, purpose, config, now);
    const key = challengeKey(challenge.nonce);
    const consumed = await this.stateRef.storage.transaction(async (transaction) => {
      const stored = await transaction.get<DeviceRuntimeRefreshChallenge>(key);
      if (!stored || !sameChallenge(stored, challenge)) return false;
      await transaction.delete(key);
      return true;
    });
    if (!consumed) {
      throw new HttpError(403, "challenge_replayed", "runtime authorization challenge was already consumed");
    }
  }

  private async enroll(request: Request, now: number): Promise<Response> {
    const config = runtimeConfig(this.envRef);
    const proof = await readJsonLimited<DeviceRuntimeEnrollmentProof>(request, CONTROL_JSON_MAX_BYTES);
    const { challenge, device } = proof;
    assertChallengeScope(challenge, "enroll", config, now);
    if (
      !device ||
      device.status !== "active" ||
      device.deviceId !== challenge.deviceId ||
      device.devicePublicKey !== device.binding.devicePublicKey ||
      device.binding.userId !== config.userId ||
      device.binding.deviceId !== device.deviceId ||
      !verifyDeviceBinding(config.userPublicKey, device.binding) ||
      !verifyEd25519(device.devicePublicKey, proof.signature, deviceRuntimeSigningPayload(challenge))
    ) {
      throw new HttpError(403, "runtime_auth_invalid", "device enrollment proof is invalid");
    }
    const key = deviceKey(device.deviceId);
    const hash = await bindingHash(device);
    const existing = await this.stateRef.storage.get<DeviceRegistryRecord>(key);
    if (existing?.status === "revoked") {
      throw new HttpError(403, "device_revoked", "revoked devices cannot be re-enrolled");
    }
    if (existing && (existing.devicePublicKey !== device.devicePublicKey || existing.bindingHash !== hash)) {
      throw new HttpError(403, "runtime_auth_invalid", "registered device identity does not match");
    }
    await this.consumeChallenge(challenge, "enroll", now);
    const record: DeviceRegistryRecord = existing ?? {
      version: CURRENT_MODEL_VERSION,
      runtimeId: config.runtimeId,
      userId: config.userId,
      deviceId: device.deviceId,
      devicePublicKey: device.devicePublicKey,
      bindingHash: hash,
      status: "active",
      registrationVersion: 1,
      createdAt: now,
      updatedAt: now
    };
    await this.stateRef.storage.put(key, { ...record, updatedAt: now });
    return jsonResponse({ registrationVersion: record.registrationVersion });
  }

  private async refresh(request: Request, now: number): Promise<Response> {
    const proof = await readJsonLimited<DeviceRuntimeRefreshProof>(request, CONTROL_JSON_MAX_BYTES);
    const config = runtimeConfig(this.envRef);
    assertChallengeScope(proof.challenge, "refresh", config, now);
    const record = await this.stateRef.storage.get<DeviceRegistryRecord>(deviceKey(proof.challenge.deviceId));
    if (!record) throw new HttpError(403, "enrollment_required", "device is not registered");
    if (record.status !== "active") throw new HttpError(403, "device_revoked", "device is revoked");
    if (!verifyEd25519(record.devicePublicKey, proof.signature, deviceRuntimeSigningPayload(proof.challenge))) {
      throw new HttpError(403, "runtime_auth_invalid", "runtime authorization proof is invalid");
    }
    await this.consumeChallenge(proof.challenge, "refresh", now);
    return jsonResponse({ registrationVersion: record.registrationVersion });
  }

  private async authorize(request: Request): Promise<Response> {
    const token = await readJsonLimited<DeviceRuntimeToken>(request, CONTROL_JSON_MAX_BYTES);
    const config = runtimeConfig(this.envRef);
    if (token.runtimeId !== config.runtimeId || token.userId !== config.userId) {
      throw new HttpError(403, "runtime_mismatch", "runtime token audience does not match this runtime");
    }
    const record = await this.stateRef.storage.get<DeviceRegistryRecord>(deviceKey(token.deviceId));
    if (!record) throw new HttpError(403, "enrollment_required", "device is not registered");
    if (record.status !== "active") throw new HttpError(403, "device_revoked", "device is revoked");
    if (record.registrationVersion !== token.registrationVersion) {
      throw new HttpError(403, "runtime_auth_invalid", "runtime token registration is stale");
    }
    return jsonResponse({ active: true });
  }

  private async requireLocalActiveDevice(request: Request): Promise<DeviceRegistryRecord> {
    const deviceId = request.headers.get("X-Tapchat-Device-Id")?.trim();
    if (!deviceId) {
      throw new HttpError(401, "runtime_auth_invalid", "authenticated device context is missing");
    }
    const record = await this.stateRef.storage.get<DeviceRegistryRecord>(deviceKey(deviceId));
    if (!record) throw new HttpError(403, "enrollment_required", "device is not registered");
    if (record.status !== "active") throw new HttpError(403, "device_revoked", "device is revoked");
    return record;
  }

  private async publishKeyPackages(request: Request, now: number): Promise<Response> {
    const writer = await this.requireLocalActiveDevice(request);
    const body = await readJsonLimited<PublishKeyPackageBatchRequest>(
      request,
      KEY_PACKAGE_BATCH_MAX_BYTES
    );
    if (
      body.version !== "2" ||
      body.deviceId !== writer.deviceId ||
      !OPAQUE_ID_PATTERN.test(body.idempotencyKey) ||
      body.packages.length < 1 ||
      body.packages.length > MAX_KEY_PACKAGE_BATCH
    ) {
      throw new HttpError(400, "invalid_input", "invalid KeyPackage V2 publish batch");
    }
    const storedIdentity = await this.stateRef.storage.get<StoredIdentityBundle>(IDENTITY_BUNDLE_KEY);
    const device = storedIdentity?.bundle.devices.find((candidate) => candidate.deviceId === body.deviceId);
    if (
      !storedIdentity ||
      !verifyIdentityBundle(storedIdentity.bundle) ||
      !device ||
      device.status !== "active" ||
      !device.mlsDeviceKeyBinding ||
      !verifyEd25519(
        device.devicePublicKey,
        body.signature,
        publishKeyPackageBatchSigningPayload(body)
      )
    ) {
      throw new HttpError(403, "runtime_auth_invalid", "KeyPackage publish proof is invalid");
    }
    const packageIds = new Set<string>();
    for (const item of body.packages) {
      validateOpaqueId("keyPackageId", item.keyPackageId);
      if (packageIds.has(item.keyPackageId)) {
        throw new HttpError(400, "invalid_input", "KeyPackage publish batch contains duplicate IDs");
      }
      packageIds.add(item.keyPackageId);
      if (
        !item.keyPackageB64 ||
        item.keyPackageB64.length > 64 * 1024 ||
        item.lifecycleVersion !== 1 ||
        !Number.isSafeInteger(item.notBefore) ||
        !Number.isSafeInteger(item.createdAt) ||
        !Number.isSafeInteger(item.expiresAt) ||
        item.createdAt > now + CLOCK_TOLERANCE_MS ||
        item.notBefore > now + CLOCK_TOLERANCE_MS ||
        item.expiresAt - item.createdAt !== KEY_PACKAGE_LIFETIME_MS ||
        item.notBefore !== Math.max(0, item.createdAt - KEY_PACKAGE_NOT_BEFORE_SKEW_MS) ||
        item.expiresAt < now + KEY_PACKAGE_MIN_REMAINING_MS ||
        item.mlsSignaturePublicKey !== device.mlsDeviceKeyBinding.mlsSignaturePublicKey
      ) {
        throw new HttpError(422, "keypackage_lifetime_invalid", "KeyPackage V2 metadata is invalid");
      }
    }
    const requestDigest = await publishRequestDigest(body);
    const result = await this.stateRef.storage.transaction(async (transaction) => {
      const idempotencyKey = `${KEY_PACKAGE_PUBLISH_IDEMPOTENCY_PREFIX}${body.deviceId}:${body.idempotencyKey}`;
      const existing = await transaction.get<StoredPublishResult>(idempotencyKey);
      if (existing) {
        if (existing.requestDigest !== requestDigest) {
          throw new HttpError(409, "idempotency_conflict", "publish idempotency key was reused");
        }
        return existing;
      }
      for (const item of body.packages) {
        const key = packageKey(body.deviceId, item.keyPackageId);
        if (await transaction.get<StoredKeyPackage>(key)) {
          throw new HttpError(409, "idempotency_conflict", "KeyPackage ID was already published");
        }
        await transaction.put(key, {
          ...item,
          userId: runtimeConfig(this.envRef).userId,
          deviceId: body.deviceId,
          state: "available",
          publishedAt: now
        } satisfies StoredKeyPackage);
      }
      const published = {
        deviceId: body.deviceId,
        packageIds: body.packages.map((item) => item.keyPackageId),
        requestDigest
      } satisfies StoredPublishResult;
      await transaction.put(idempotencyKey, published);
      return published;
    });
    return jsonResponse({
      accepted: true,
      idempotencyKey: body.idempotencyKey,
      published: result.packageIds.length
    } satisfies PublishKeyPackageBatchResult);
  }

  private async keyPackageStatus(request: Request, now: number): Promise<Response> {
    const device = await this.requireLocalActiveDevice(request);
    const status = await this.stateRef.storage.transaction(async (transaction) => {
      const packages = await transaction.list<StoredKeyPackage>({
        prefix: `${KEY_PACKAGE_PREFIX}${device.deviceId}:`
      });
      let available = 0;
      let claimed = 0;
      let expired = 0;
      for (const [key, item] of packages) {
        if (item.state === "available" && item.expiresAt <= now) {
          item.state = "expired";
          await transaction.put(key, item);
        }
        if (item.state === "available") available += 1;
        else if (item.state === "claimed") claimed += 1;
        else expired += 1;
      }
      return {
        deviceId: device.deviceId,
        available,
        claimed,
        expired,
        target: KEY_PACKAGE_POOL_TARGET,
        refillThreshold: KEY_PACKAGE_POOL_REFILL_THRESHOLD
      } satisfies KeyPackagePoolStatus;
    });
    return jsonResponse(status);
  }

  private async validateClaimRequest(
    body: ClaimKeyPackagesRequest,
    ownerBundle: IdentityBundle,
    now: number
  ): Promise<void> {
    if (
      body.version !== "2" ||
      !["direct", "group_invite", "device_reconcile", "recovery", "self_join"].includes(body.purpose) ||
      body.targets.length < 1 ||
      body.targets.length > MAX_KEY_PACKAGE_BATCH
    ) {
      throw new HttpError(400, "invalid_input", "invalid KeyPackage claim request");
    }
    validateOpaqueId("idempotencyKey", body.idempotencyKey);
    validateOpaqueId("proposalId", body.proposal.proposalId);
    validateOpaqueId("relationshipIdCandidate", body.proposal.relationshipIdCandidate);
    if (
      body.requesterBundle.publicationVersion !== 2 ||
      !verifyIdentityBundle(body.requesterBundle) ||
      body.proposal.initiatorUserId !== body.requesterBundle.userId ||
      (body.purpose === "self_join"
        ? body.requesterBundle.userId !== ownerBundle.userId
        : body.proposal.peerUserId !== ownerBundle.userId) ||
      body.proposal.attempt < 1 ||
      body.proposal.generation < 1 ||
      !Number.isSafeInteger(body.proposal.attempt) ||
      !Number.isSafeInteger(body.proposal.generation) ||
      body.proposal.createdAt > now + CLOCK_TOLERANCE_MS ||
      body.proposal.expiresAt <= now ||
      body.proposal.expiresAt - body.proposal.createdAt > RELATIONSHIP_ATTEMPT_TTL_MS ||
      body.proposal.senderBundleDigest !== await identityBundleDigest(body.requesterBundle)
    ) {
      throw new HttpError(403, "relationship_proposal_invalid", "relationship proposal context is invalid");
    }
    const initiator = body.requesterBundle.devices.find(
      (candidate) => candidate.deviceId === body.proposal.initiatorDeviceId
    );
    if (
      !initiator ||
      initiator.status !== "active" ||
      !verifyEd25519(
        initiator.devicePublicKey,
        body.proposal.signature,
        relationshipProposalSigningPayload(body.proposal)
      )
    ) {
      throw new HttpError(403, "relationship_proposal_invalid", "relationship proposal signature is invalid");
    }
    const targetIds = new Set<string>();
    for (const target of body.targets) {
      if (targetIds.has(target.deviceId)) {
        throw new HttpError(400, "invalid_input", "claim target devices must be unique");
      }
      targetIds.add(target.deviceId);
      const targetDevice = ownerBundle.devices.find((candidate) => candidate.deviceId === target.deviceId);
      if (
        !targetDevice ||
        targetDevice.status !== "active" ||
        !targetDevice.mlsDeviceKeyBinding ||
        !targetDevice.keyPackageClaimCapability ||
        target.capability.signature !== targetDevice.keyPackageClaimCapability.signature ||
        target.capability.userId !== ownerBundle.userId ||
        target.capability.targetDeviceId !== target.deviceId ||
        target.capability.expiresAt <= now ||
        !verifyKeyPackageClaimCapability(target.capability, targetDevice.devicePublicKey)
      ) {
        throw new HttpError(403, "invalid_capability", "KeyPackage claim target is not authorized");
      }
    }
    if (body.purpose === "direct") {
      const activeIds = ownerBundle.devices
        .filter((device) => device.status === "active")
        .map((device) => device.deviceId)
        .sort();
      if (JSON.stringify([...targetIds].sort()) !== JSON.stringify(activeIds)) {
        throw new HttpError(409, "identity_refresh_required", "direct claim must cover every active target device");
      }
    } else if (body.purpose === "self_join") {
      const expectedSiblingIds = ownerBundle.devices
        .filter(
          (device) =>
            device.status === "active" && device.deviceId !== body.proposal.initiatorDeviceId
        )
        .map((device) => device.deviceId)
        .sort();
      if (JSON.stringify([...targetIds].sort()) !== JSON.stringify(expectedSiblingIds)) {
        throw new HttpError(
          409,
          "identity_refresh_required",
          "authenticated self claim must cover every active sibling device"
        );
      }
    }
  }

  private async claimKeyPackages(request: Request, now: number): Promise<Response> {
    const body = await readJsonLimited<ClaimKeyPackagesRequest>(request, KEY_PACKAGE_BATCH_MAX_BYTES);
    const storedIdentity = await this.stateRef.storage.get<StoredIdentityBundle>(IDENTITY_BUNDLE_KEY);
    if (!storedIdentity || !verifyIdentityBundle(storedIdentity.bundle)) {
      throw new HttpError(409, "identity_refresh_required", "target IdentityBundle V2 is unavailable");
    }
    await this.validateClaimRequest(body, storedIdentity.bundle, now);
    const requestDigest = await claimRequestDigest(body);
    const relationshipKey = `${RELATIONSHIP_PREFIX}${await sha256Hex(body.requesterBundle.userPublicKey)}`;
    const generatedTicketId = randomNonce();
    const generatedTicketSecret = await deriveTicketSecret(
      this.envRef,
      body.idempotencyKey,
      generatedTicketId
    );
    const generatedTicketSecretHash = await sha256Hex(generatedTicketSecret);
    const claimIds = new Map(body.targets.map((target) => [target.deviceId, randomNonce()]));
    const storedResult = await this.stateRef.storage.transaction(async (transaction) => {
      const claimIdempotencyKey = `${KEY_PACKAGE_CLAIM_IDEMPOTENCY_PREFIX}${body.idempotencyKey}`;
      const previousResult = await transaction.get<StoredClaimResult>(claimIdempotencyKey);
      if (previousResult) {
        if (previousResult.requestDigest !== requestDigest) {
          throw new HttpError(409, "idempotency_conflict", "claim idempotency key was reused");
        }
        return previousResult;
      }

      let relationship: StoredRelationship | undefined;
      let ticket: Omit<RelationshipTicket, "ticketSecret"> | undefined;
      let retainedAttempts: NonNullable<PersistedRelationship["attempts"]> = [];
      if (body.purpose === "direct") {
        const existing = await transaction.get<StoredRelationship>(relationshipKey);
        if (existing) {
          if (existing.generation > body.proposal.generation) {
            throw new HttpError(409, "relationship_conflict", "a newer relationship generation exists");
          }
          if (existing.generation === body.proposal.generation) {
            if (existing.accountState === "accepted") {
              throw new HttpError(409, "relationship_conflict", "accepted canonical relationship is immutable");
            }
            const isExpiredNextAttempt =
              existing.relationshipId === body.proposal.relationshipIdCandidate &&
              body.proposal.attempt === existing.canonicalProposal.attempt + 1 &&
              existing.canonicalProposal.expiresAt <= now;
            if (isExpiredNextAttempt) {
              retainedAttempts = existing.attempts ?? [];
            }
            if (!isExpiredNextAttempt && compareRank(existing.canonicalProposal, body.proposal) <= 0) {
              throw new HttpError(409, "relationship_superseded", "relationship proposal lost canonical ordering");
            }
            if (existing.direction === "incoming" && existing.ticketSecretHash) {
              await transaction.put(`${RELATIONSHIP_TICKET_PREFIX}${existing.ticketId}`, {
                relationshipKey,
                ticketSecretHash: existing.ticketSecretHash,
                status: "superseded"
              } satisfies StoredTicketIndex);
            }
          } else if (
            existing.accountState !== "removed" ||
            body.proposal.generation !== existing.generation + 1
          ) {
            throw new HttpError(409, "relationship_conflict", "relationship generation cannot advance");
          }
        } else if (body.proposal.generation !== 1) {
          throw new HttpError(409, "relationship_conflict", "initial relationship generation must be 1");
        }
        const localJoinStates = Object.fromEntries(
          storedIdentity.bundle.devices
            .filter((device) => device.status === "active")
            .map((device) => [device.deviceId, "waiting_welcome" as const])
        );
        relationship = {
          relationshipId: body.proposal.relationshipIdCandidate,
          peerUserId: body.requesterBundle.userId,
          peerRootPublicKey: body.requesterBundle.userPublicKey,
          peerBundleDigest: body.proposal.senderBundleDigest,
          peerBundleRevision: body.requesterBundle.publicationRevision ?? 0,
          generation: body.proposal.generation,
          canonicalProposal: body.proposal,
          accountState: "pending",
          setupState: "delivering",
          localDeviceJoinStates: localJoinStates,
          version: (existing?.version ?? 0) + 1,
          updatedAt: now,
          direction: "incoming",
          peerBundle: body.requesterBundle,
          ticketId: generatedTicketId,
          ticketSecretHash: generatedTicketSecretHash
        };
        ticket = {
          ticketId: generatedTicketId,
          relationshipId: relationship.relationshipId,
          generation: relationship.generation,
          attempt: body.proposal.attempt
        };
      }

      const selected: Array<{ key: string; value: StoredKeyPackage; claimId: string }> = [];
      for (const target of body.targets) {
        const entries = await transaction.list<StoredKeyPackage>({
          prefix: `${KEY_PACKAGE_PREFIX}${target.deviceId}:`
        });
        let available: { key: string; value: StoredKeyPackage } | undefined;
        for (const [key, value] of entries) {
          if (value.state === "available" && value.expiresAt <= now) {
            value.state = "expired";
            await transaction.put(key, value);
            continue;
          }
          if (
            value.state === "available" &&
            (!available || value.createdAt < available.value.createdAt ||
              (value.createdAt === available.value.createdAt && key < available.key))
          ) {
            available = { key, value };
          }
        }
        if (!available) {
          throw new HttpError(409, "keypackage_pool_exhausted", "a target device has no available KeyPackage");
        }
        selected.push({ key: available.key, value: available.value, claimId: claimIds.get(target.deviceId)! });
      }

      const claims: ClaimedKeyPackage[] = [];
      for (const selectedPackage of selected) {
        selectedPackage.value.state = "claimed";
        selectedPackage.value.claimId = selectedPackage.claimId;
        selectedPackage.value.claimedAt = now;
        await transaction.put(selectedPackage.key, selectedPackage.value);
        claims.push({
          claimId: selectedPackage.claimId,
          userId: selectedPackage.value.userId,
          deviceId: selectedPackage.value.deviceId,
          keyPackageId: selectedPackage.value.keyPackageId,
          keyPackageB64: selectedPackage.value.keyPackageB64,
          createdAt: selectedPackage.value.createdAt,
          expiresAt: selectedPackage.value.expiresAt
        });
      }
      if (relationship && ticket) {
        relationship.attempts = [...retainedAttempts, {
          attempt: body.proposal.attempt,
          proposalId: body.proposal.proposalId,
          ticketId: ticket.ticketId,
          ticketSecret: "",
          claimIds: claims.map((claim) => claim.claimId),
          welcomeDigests: [],
          claimSets: [{
            purpose: body.purpose,
            idempotencyKey: body.idempotencyKey,
            claims,
            ticket: { ...ticket }
          }],
          createdAt: body.proposal.createdAt,
          expiresAt: body.proposal.expiresAt
        }];
        await transaction.put(relationshipKey, relationship);
        await transaction.put(`${RELATIONSHIP_TICKET_PREFIX}${ticket.ticketId}`, {
          relationshipKey,
          ticketSecretHash: relationship.ticketSecretHash!,
          status: "active"
        } satisfies StoredTicketIndex);
      }
      const result = {
        idempotencyKey: body.idempotencyKey,
        requestDigest,
        claims,
        ...(ticket ? { ticket } : {})
      } satisfies StoredClaimResult;
      await transaction.put(claimIdempotencyKey, result);
      return result;
    });
    const result: ClaimKeyPackagesResult = {
      idempotencyKey: storedResult.idempotencyKey,
      claims: storedResult.claims,
      ...(storedResult.ticket
        ? {
            ticket: {
              ...storedResult.ticket,
              ticketSecret: await deriveTicketSecret(
                this.envRef,
                storedResult.idempotencyKey,
                storedResult.ticket.ticketId
              )
            }
          }
        : {})
    };
    return jsonResponse(result);
  }

  private async listRelationships(request: Request): Promise<Response> {
    await this.requireLocalActiveDevice(request);
    const stored = await this.stateRef.storage.list<StoredRelationship>({ prefix: RELATIONSHIP_PREFIX });
    const relationships = Array.from(stored.values()).map((storedRelationship) => {
      const {
        peerBundle,
        ticketId: _ticketId,
        ticketSecretHash: _ticketSecretHash,
        ticketStatusEndpoint: _ticketStatusEndpoint,
        direction: _direction,
        ...relationship
      } = storedRelationship;
      return { relationship, peerBundle };
    });
    return jsonResponse({ relationships });
  }

  private async upsertOutboundRelationship(request: Request, now: number): Promise<Response> {
    const writer = await this.requireLocalActiveDevice(request);
    const body = await readJsonLimited<UpsertOutboundRelationshipRequest>(
      request,
      KEY_PACKAGE_BATCH_MAX_BYTES
    );
    const owner = await this.stateRef.storage.get<StoredIdentityBundle>(IDENTITY_BUNDLE_KEY);
    const relationship = body.relationship;
    const proposal = relationship.canonicalProposal;
    if (
      body.version !== "2" ||
      !owner ||
      !verifyIdentityBundle(owner.bundle) ||
      !verifyIdentityBundle(body.peerBundle) ||
      relationship.peerUserId !== body.peerBundle.userId ||
      relationship.peerRootPublicKey !== body.peerBundle.userPublicKey ||
      relationship.peerBundleDigest !== await identityBundleDigest(body.peerBundle) ||
      relationship.peerBundleRevision !== (body.peerBundle.publicationRevision ?? 0) ||
      relationship.relationshipId !== proposal.relationshipIdCandidate ||
      relationship.generation !== proposal.generation ||
      relationship.accountState !== "pending" ||
      proposal.initiatorUserId !== owner.bundle.userId ||
      proposal.initiatorDeviceId !== writer.deviceId ||
      proposal.peerUserId !== body.peerBundle.userId ||
      proposal.senderBundleDigest !== await identityBundleDigest(owner.bundle) ||
      body.ticket.relationshipId !== relationship.relationshipId ||
      body.ticket.generation !== relationship.generation ||
      body.ticket.attempt !== proposal.attempt
    ) {
      throw new HttpError(403, "relationship_proposal_invalid", "outbound relationship context is invalid");
    }
    const initiator = owner.bundle.devices.find((device) => device.deviceId === proposal.initiatorDeviceId);
    if (
      !initiator ||
      initiator.status !== "active" ||
      !verifyEd25519(
        initiator.devicePublicKey,
        proposal.signature,
        relationshipProposalSigningPayload(proposal)
      )
    ) {
      throw new HttpError(403, "relationship_proposal_invalid", "outbound proposal signature is invalid");
    }
    const expectedStatusEndpoints = new Set(
      body.peerBundle.devices
        .filter((device) => device.status === "active" && device.keyPackageClaimCapability)
        .map((device) => {
          const claimEndpoint = device.keyPackageClaimCapability!.endpoint;
          const base = claimEndpoint.endsWith("/v2/key-packages/claims")
            ? claimEndpoint.slice(0, -"/v2/key-packages/claims".length)
            : claimEndpoint.replace(/\/+$/, "");
          return `${base}/v2/relationships/${encodeURIComponent(body.ticket.ticketId)}/status`;
        })
    );
    let parsedStatus: URL;
    try {
      parsedStatus = new URL(body.ticketStatusEndpoint);
    } catch {
      throw new HttpError(400, "invalid_input", "relationship status endpoint is invalid");
    }
    if (
      parsedStatus.protocol !== "https:" ||
      parsedStatus.username ||
      parsedStatus.password ||
      parsedStatus.search ||
      parsedStatus.hash ||
      !expectedStatusEndpoints.has(body.ticketStatusEndpoint)
    ) {
      throw new HttpError(403, "relationship_proposal_invalid", "relationship status endpoint is not peer-authorized");
    }
    const activeLocalIds = owner.bundle.devices
      .filter((device) => device.status === "active")
      .map((device) => device.deviceId)
      .sort();
    if (
      JSON.stringify(Object.keys(relationship.localDeviceJoinStates).sort()) !==
      JSON.stringify(activeLocalIds)
    ) {
      throw new HttpError(409, "identity_refresh_required", "outbound relationship must cover every active local device");
    }
    const sanitized: StoredRelationship = {
      ...relationship,
      attempts: relationship.attempts?.map((attempt) => ({
        ...attempt,
        ticketSecret: "",
        ticketStatusEndpoint: body.ticketStatusEndpoint
      })),
      direction: "outbound",
      peerBundle: body.peerBundle,
      ticketId: body.ticket.ticketId,
      ticketStatusEndpoint: body.ticketStatusEndpoint,
      updatedAt: now
    };
    const relationshipKey = `${RELATIONSHIP_PREFIX}${await sha256Hex(body.peerBundle.userPublicKey)}`;
    const stored = await this.stateRef.storage.transaction(async (transaction) => {
      const existing = await transaction.get<StoredRelationship>(relationshipKey);
      if (existing) {
        if (existing.generation > relationship.generation) {
          throw new HttpError(409, "relationship_superseded", "a newer canonical relationship exists");
        }
        if (existing.generation === relationship.generation) {
          if (existing.accountState === "accepted" && existing.relationshipId !== relationship.relationshipId) {
            throw new HttpError(409, "relationship_conflict", "accepted canonical relationship is immutable");
          }
          if (
            existing.canonicalProposal.proposalId !== proposal.proposalId &&
            !(
              existing.relationshipId === relationship.relationshipId &&
              proposal.attempt === existing.canonicalProposal.attempt + 1 &&
              existing.canonicalProposal.expiresAt <= now
            ) &&
            compareRank(existing.canonicalProposal, proposal) <= 0
          ) {
            return existing;
          }
          if (existing.direction === "incoming" && existing.ticketSecretHash) {
            await transaction.put(`${RELATIONSHIP_TICKET_PREFIX}${existing.ticketId}`, {
              relationshipKey,
              ticketSecretHash: existing.ticketSecretHash,
              status: "superseded"
            } satisfies StoredTicketIndex);
          }
        }
      }
      await transaction.put(relationshipKey, sanitized);
      return sanitized;
    });
    return jsonResponse({
      canonical: stored.relationshipId === relationship.relationshipId,
      relationship: (({ peerBundle: _peerBundle, direction: _direction, ticketId: _ticketId,
        ticketSecretHash: _ticketSecretHash, ticketStatusEndpoint: _ticketStatusEndpoint, ...value }) => value)(stored),
      peerBundle: stored.peerBundle
    });
  }

  private async removeRelationship(
    request: Request,
    relationshipId: string,
    now: number
  ): Promise<Response> {
    await this.requireLocalActiveDevice(request);
    validateOpaqueId("relationship", relationshipId);
    const body = await readJsonLimited<RemoveRelationshipRequest>(
      request,
      CONTROL_JSON_MAX_BYTES
    );
    if (
      body.version !== "2" ||
      body.relationshipId !== relationshipId ||
      !Number.isSafeInteger(body.generation) ||
      body.generation < 1
    ) {
      throw new HttpError(400, "invalid_input", "relationship removal context is invalid");
    }
    const relationships = await this.stateRef.storage.list<StoredRelationship>({
      prefix: RELATIONSHIP_PREFIX
    });
    const entry = Array.from(relationships.entries()).find(
      ([, relationship]) => relationship.relationshipId === relationshipId
    );
    if (!entry) {
      throw new HttpError(404, "not_found", "relationship is unavailable");
    }
    const [relationshipKey] = entry;
    const updated = await this.stateRef.storage.transaction(async (transaction) => {
      const current = await transaction.get<StoredRelationship>(relationshipKey);
      if (
        !current ||
        current.relationshipId !== relationshipId ||
        current.generation !== body.generation
      ) {
        throw new HttpError(409, "relationship_conflict", "canonical relationship changed");
      }
      if (current.accountState !== "removed") {
        current.accountState = "removed";
        current.setupState = "ready";
        current.version += 1;
        current.updatedAt = now;
        await transaction.put(relationshipKey, current);
      }
      return current;
    });
    return jsonResponse({
      removed: true,
      relationshipId: updated.relationshipId,
      generation: updated.generation
    });
  }

  private async updateRelationshipDeviceJoinState(
    request: Request,
    relationshipId: string,
    deviceId: string,
    now: number
  ): Promise<Response> {
    const writer = await this.requireLocalActiveDevice(request);
    if (writer.deviceId !== deviceId) {
      throw new HttpError(403, "runtime_auth_invalid", "device join state writer mismatch");
    }
    const body = await readJsonLimited<{
      version?: string;
      state?: "waiting_welcome" | "joining" | "ready" | "failed";
    }>(request, CONTROL_JSON_MAX_BYTES);
    if (
      body.version !== "2" ||
      !body.state ||
      !["waiting_welcome", "joining", "ready", "failed"].includes(body.state)
    ) {
      throw new HttpError(400, "invalid_input", "relationship device join state is invalid");
    }
    const nextState = body.state as "waiting_welcome" | "joining" | "ready" | "failed";
    await this.stateRef.storage.transaction(async (transaction) => {
      const relationships = await transaction.list<StoredRelationship>({
        prefix: RELATIONSHIP_PREFIX
      });
      const entry = Array.from(relationships.entries()).find(
        ([, relationship]) => relationship.relationshipId === relationshipId
      );
      if (!entry || entry[1].localDeviceJoinStates[deviceId] === undefined) {
        throw new HttpError(404, "not_found", "relationship device is unavailable");
      }
      const [key, relationship] = entry;
      relationship.localDeviceJoinStates[deviceId] = nextState;
      if (relationship.accountState === "accepted") {
        relationship.setupState = Object.values(relationship.localDeviceJoinStates)
          .every((state) => state === "ready")
          ? "ready"
          : "delivering";
      }
      relationship.version += 1;
      relationship.updatedAt = now;
      await transaction.put(key, relationship);
    });
    return jsonResponse({ accepted: true, relationshipId, deviceId, state: nextState });
  }

  private async confirmRelationshipPeerDecision(
    request: Request,
    relationshipId: string,
    now: number
  ): Promise<Response> {
    await this.requireLocalActiveDevice(request);
    validateOpaqueId("relationship", relationshipId);
    const body = await readJsonLimited<ConfirmRelationshipPeerDecisionRequest>(
      request,
      CONTROL_JSON_MAX_BYTES
    );
    const owner = await this.stateRef.storage.get<StoredIdentityBundle>(IDENTITY_BUNDLE_KEY);
    if (body.version !== "2" || !owner || !verifyIdentityBundle(owner.bundle)) {
      throw new HttpError(400, "invalid_input", "peer relationship decision is invalid");
    }
    const proof = body.proof;
    const relationships = await this.stateRef.storage.list<StoredRelationship>({
      prefix: RELATIONSHIP_PREFIX
    });
    const entry = Array.from(relationships.entries()).find(
      ([, relationship]) =>
        relationship.relationshipId === relationshipId && relationship.direction === "outbound"
    );
    if (!entry) throw new HttpError(404, "not_found", "outbound relationship is unavailable");
    const [relationshipKey, relationship] = entry;
    const actorDevice = relationship.peerBundle.devices.find(
      (device) => device.deviceId === proof.actorDeviceId
    );
    if (
      proof.version !== "2" ||
      proof.ticketId !== relationship.ticketId ||
      proof.relationshipId !== relationship.relationshipId ||
      proof.generation !== relationship.generation ||
      proof.proposalId !== relationship.canonicalProposal.proposalId ||
      (proof.decision !== "accept" && proof.decision !== "reject") ||
      proof.actorUserId !== relationship.peerBundle.userId ||
      proof.peerUserId !== owner.bundle.userId ||
      proof.peerBundleDigest !== relationship.canonicalProposal.senderBundleDigest ||
      !Number.isSafeInteger(proof.decidedAt) ||
      proof.decidedAt < relationship.canonicalProposal.createdAt ||
      proof.decidedAt > now + CLOCK_TOLERANCE_MS ||
      !actorDevice ||
      actorDevice.status !== "active" ||
      !verifyEd25519(
        actorDevice.devicePublicKey,
        proof.signature,
        relationshipDecisionProofSigningPayload(proof)
      )
    ) {
      throw new HttpError(403, "relationship_proposal_invalid", "peer decision proof is invalid");
    }
    const desired = proof.decision === "accept" ? "accepted" : "rejected";
    const updated = await this.stateRef.storage.transaction(async (transaction) => {
      const current = await transaction.get<StoredRelationship>(relationshipKey);
      if (!current || current.relationshipId !== relationshipId) {
        throw new HttpError(409, "relationship_conflict", "canonical relationship changed");
      }
      if (current.accountState !== "pending" && current.accountState !== desired) {
        throw new HttpError(409, "relationship_conflict", "relationship already has a final decision");
      }
      if (current.accountState === "pending") {
        current.accountState = desired;
        current.setupState = desired === "accepted"
          && Object.values(current.localDeviceJoinStates).every((state) => state === "ready")
          ? "ready"
          : desired === "accepted"
            ? "delivering"
            : "ready";
        current.decisionProof = proof;
        current.version += 1;
        current.updatedAt = now;
        await transaction.put(relationshipKey, current);
      }
      return current;
    });
    return jsonResponse({
      accepted: true,
      relationshipId: updated.relationshipId,
      accountState: updated.accountState
    });
  }

  private async authorizeRelationshipAppend(request: Request): Promise<Response> {
    const body = await readJsonLimited<{
      senderUserId?: string;
      senderRootPublicKey?: string;
      senderBundleDigest?: string;
      senderDeviceId?: string;
      recipientDeviceId?: string;
      relationshipId?: string;
      generation?: number;
      attempt?: number;
      proposalId?: string;
      claimId?: string;
      messageType?: string;
    }>(request, CONTROL_JSON_MAX_BYTES);
    if (!body.senderRootPublicKey || !body.recipientDeviceId) {
      throw new HttpError(400, "invalid_input", "relationship append context is incomplete");
    }
    const owner = await this.stateRef.storage.get<StoredIdentityBundle>(IDENTITY_BUNDLE_KEY);
    const isAuthenticatedSelfDelivery = Boolean(
      owner &&
      verifyIdentityBundle(owner.bundle) &&
      body.senderUserId === owner.bundle.userId &&
      body.senderRootPublicKey === owner.bundle.userPublicKey &&
      body.senderBundleDigest === await identityBundleDigest(owner.bundle)
    );
    let relationship: StoredRelationship | undefined;
    if (isAuthenticatedSelfDelivery) {
      const relationships = await this.stateRef.storage.list<StoredRelationship>({
        prefix: RELATIONSHIP_PREFIX
      });
      relationship = Array.from(relationships.values()).find(
        (candidate) =>
          candidate.direction === "outbound" && candidate.relationshipId === body.relationshipId
      );
    } else {
      const key = `${RELATIONSHIP_PREFIX}${await sha256Hex(body.senderRootPublicKey)}`;
      relationship = await this.stateRef.storage.get<StoredRelationship>(key);
    }
    if (
      !relationship ||
      relationship.accountState === "rejected" ||
      relationship.accountState === "removed" ||
      (!isAuthenticatedSelfDelivery && relationship.peerUserId !== body.senderUserId) ||
      (!isAuthenticatedSelfDelivery && relationship.peerRootPublicKey !== body.senderRootPublicKey) ||
      (!isAuthenticatedSelfDelivery && relationship.peerBundleDigest !== body.senderBundleDigest) ||
      relationship.relationshipId !== body.relationshipId ||
      relationship.generation !== body.generation ||
      relationship.canonicalProposal.proposalId !== body.proposalId ||
      relationship.canonicalProposal.attempt !== body.attempt ||
      relationship.localDeviceJoinStates[body.recipientDeviceId] === undefined
    ) {
      throw new HttpError(403, "relationship_closed", "envelope is outside the canonical relationship");
    }
    if (relationship.accountState === "pending") {
      if (body.messageType !== "mls_welcome" || !body.claimId) {
        throw new HttpError(403, "relationship_closed", "pending relationships only accept claimed setup Welcomes");
      }
      const packages = await this.stateRef.storage.list<StoredKeyPackage>({
        prefix: `${KEY_PACKAGE_PREFIX}${body.recipientDeviceId}:`
      });
      if (!Array.from(packages.values()).some((item) => item.state === "claimed" && item.claimId === body.claimId)) {
        throw new HttpError(403, "relationship_proposal_invalid", "setup Welcome claim is not valid");
      }
    }
    return jsonResponse({
      accountState: relationship.accountState,
      selfDelivery: isAuthenticatedSelfDelivery
    });
  }

  private async listRelationshipRequests(request: Request): Promise<Response> {
    await this.requireLocalActiveDevice(request);
    const stored = await this.stateRef.storage.list<StoredRelationship>({ prefix: RELATIONSHIP_PREFIX });
    const requests = Array.from(stored.values())
      .filter((relationship) =>
        relationship.direction === "incoming"
        && relationship.accountState === "pending"
        && relationship.canonicalProposal.expiresAt > Date.now()
      )
      .map((relationship) => ({
        ticketId: relationship.ticketId,
        relationshipId: relationship.relationshipId,
        generation: relationship.generation,
        attempt: relationship.canonicalProposal.attempt,
        peerBundle: relationship.peerBundle,
        peerBundleDigest: relationship.peerBundleDigest,
        proposal: relationship.canonicalProposal,
        createdAt: relationship.canonicalProposal.createdAt,
        expiresAt: relationship.canonicalProposal.expiresAt
      }));
    return jsonResponse({ requests });
  }

  private async decideRelationship(request: Request, ticketId: string, now: number): Promise<Response> {
    const writer = await this.requireLocalActiveDevice(request);
    validateOpaqueId("ticket", ticketId);
    const body = await readJsonLimited<RelationshipDecisionRequest>(request, CONTROL_JSON_MAX_BYTES);
    const owner = await this.stateRef.storage.get<StoredIdentityBundle>(IDENTITY_BUNDLE_KEY);
    if (
      body.version !== "2" ||
      !owner ||
      !verifyIdentityBundle(owner.bundle) ||
      (body.decision !== "accept" && body.decision !== "reject")
    ) {
      throw new HttpError(400, "invalid_input", "relationship decision is invalid");
    }
    const relationship = await this.stateRef.storage.transaction(async (transaction) => {
      const index = await transaction.get<StoredTicketIndex>(`${RELATIONSHIP_TICKET_PREFIX}${ticketId}`);
      if (!index || index.status === "superseded") {
        throw new HttpError(409, "relationship_superseded", "relationship request was superseded");
      }
      const stored = await transaction.get<StoredRelationship>(index.relationshipKey);
      if (!stored || stored.ticketId !== ticketId) {
        throw new HttpError(404, "not_found", "relationship request was not found");
      }
      if (stored.accountState === "pending" && stored.canonicalProposal.expiresAt <= now) {
        throw new HttpError(409, "relationship_superseded", "relationship request has expired");
      }
      const proof = body.proof;
      const actorDevice = owner.bundle.devices.find((device) => device.deviceId === proof?.actorDeviceId);
      if (
        !proof ||
        proof.version !== "2" ||
        proof.ticketId !== ticketId ||
        proof.relationshipId !== stored.relationshipId ||
        proof.generation !== stored.generation ||
        proof.proposalId !== stored.canonicalProposal.proposalId ||
        proof.decision !== body.decision ||
        proof.actorUserId !== owner.bundle.userId ||
        proof.actorDeviceId !== writer.deviceId ||
        proof.peerUserId !== stored.peerUserId ||
        proof.peerBundleDigest !== stored.peerBundleDigest ||
        !Number.isSafeInteger(proof.decidedAt) ||
        Math.abs(now - proof.decidedAt) > CLOCK_TOLERANCE_MS ||
        !actorDevice ||
        actorDevice.status !== "active" ||
        !verifyEd25519(
          actorDevice.devicePublicKey,
          proof.signature,
          relationshipDecisionProofSigningPayload(proof)
        )
      ) {
        throw new HttpError(403, "relationship_proposal_invalid", "relationship decision proof is invalid");
      }
      const desired = body.decision === "accept" ? "accepted" : "rejected";
      if (stored.accountState !== "pending" && stored.accountState !== desired) {
        throw new HttpError(409, "relationship_conflict", "relationship already has a final decision");
      }
      if (stored.accountState === "pending") {
        stored.accountState = desired;
        stored.setupState = desired === "accepted"
          && Object.values(stored.localDeviceJoinStates).every((state) => state === "ready")
          ? "ready"
          : desired === "accepted"
            ? "delivering"
            : "ready";
        stored.version += 1;
        stored.updatedAt = now;
        stored.decisionProof = proof;
        await transaction.put(index.relationshipKey, stored);
      }
      return stored;
    });
    const activeDevices = Object.keys(relationship.localDeviceJoinStates);
    await this.stateRef.storage.transaction(async (transaction) => {
      for (const deviceId of activeDevices) {
        const projection: RelationshipProjection = {
          ticketId,
          deviceId,
          senderUserId: relationship.peerUserId,
          proposalId: relationship.canonicalProposal.proposalId,
          decision: body.decision,
          attemptCount: 0,
          nextRetryAt: now
        };
        await transaction.put(
          `${RELATIONSHIP_PROJECTION_PREFIX}${ticketId}:${deviceId}`,
          projection
        );
      }
    });
    await this.runRelationshipProjections(now);
    return jsonResponse({
      accepted: true,
      ticketId,
      relationshipId: relationship.relationshipId,
      generation: relationship.generation,
      accountState: relationship.accountState,
      localDeviceJoinStates: relationship.localDeviceJoinStates,
      proof: relationship.decisionProof
    });
  }

  private async runRelationshipProjections(now: number): Promise<void> {
    const pending = await this.stateRef.storage.list<RelationshipProjection>({
      prefix: RELATIONSHIP_PROJECTION_PREFIX
    });
    let nextAlarm: number | undefined;
    const secret = this.envRef.SHARING_INTERNAL_SECRET?.trim();
    if (!secret) {
      if (pending.size > 0) await this.stateRef.storage.setAlarm(now + 5 * 60 * 1000);
      return;
    }
    for (const [key, projection] of pending) {
      if (projection.nextRetryAt > now) {
        nextAlarm = Math.min(nextAlarm ?? projection.nextRetryAt, projection.nextRetryAt);
        continue;
      }
      const response = await this.envRef.INBOX
        .get(this.envRef.INBOX.idFromName(projection.deviceId))
        .fetch(new Request(
          `https://inbox.internal/v2/inbox/${encodeURIComponent(projection.deviceId)}/internal/relationships/promote`,
          {
            method: "POST",
            headers: {
              "content-type": "application/json",
              "X-Tapchat-Internal-Secret": secret
            },
            body: JSON.stringify({
              senderUserId: projection.senderUserId,
              proposalId: projection.proposalId,
              decision: projection.decision
            })
          }
        ));
      if (response.ok) {
        await this.stateRef.storage.delete(key);
        continue;
      }
      projection.attemptCount += 1;
      const delay = Math.min(
        24 * 60 * 60 * 1000,
        5 * 60 * 1000 * 2 ** Math.min(Math.max(projection.attemptCount - 1, 0), 8)
      );
      projection.nextRetryAt = now + delay;
      await this.stateRef.storage.put(key, projection);
      nextAlarm = Math.min(nextAlarm ?? projection.nextRetryAt, projection.nextRetryAt);
    }
    if (nextAlarm !== undefined) await this.stateRef.storage.setAlarm(nextAlarm);
  }

  private async relationshipStatus(request: Request, ticketId: string): Promise<Response> {
    validateOpaqueId("ticket", ticketId);
    const index = await this.stateRef.storage.get<StoredTicketIndex>(`${RELATIONSHIP_TICKET_PREFIX}${ticketId}`);
    if (!index) throw new HttpError(403, "invalid_capability", "relationship ticket is invalid");
    const relationship = await this.stateRef.storage.get<StoredRelationship>(index.relationshipKey);
    if (!relationship) throw new HttpError(404, "not_found", "relationship is unavailable");
    const deviceId = request.headers.get("X-Tapchat-Ticket-Device")?.trim();
    const issuedAt = Number(request.headers.get("X-Tapchat-Ticket-Issued-At"));
    const secretProof = request.headers.get("X-Tapchat-Ticket-Secret-Proof")?.trim();
    const proof = request.headers.get("X-Tapchat-Ticket-Proof")?.trim();
    const device = relationship.peerBundle.devices.find((candidate) => candidate.deviceId === deviceId);
    if (
      !deviceId ||
      !secretProof ||
      !proof ||
      !Number.isSafeInteger(issuedAt) ||
      Math.abs(Date.now() - issuedAt) > CLOCK_TOLERANCE_MS ||
      !device ||
      device.status !== "active" ||
      secretProof !== await relationshipTicketSecretProof(
        ticketId,
        deviceId,
        issuedAt,
        index.ticketSecretHash
      ) ||
      !verifyEd25519(
        device.devicePublicKey,
        proof,
        relationshipTicketStatusSigningPayload(ticketId, deviceId, issuedAt, secretProof)
      )
    ) {
      throw new HttpError(403, "invalid_capability", "relationship ticket proof is invalid");
    }
    return jsonResponse({
      ticketId,
      status: index.status === "superseded" ? "superseded" : relationship.accountState,
      relationshipId: relationship.relationshipId,
      generation: relationship.generation,
      canonicalProposal: relationship.canonicalProposal,
      updatedAt: relationship.updatedAt,
      ...(relationship.decisionProof ? { decisionProof: relationship.decisionProof } : {})
    });
  }

  private async syncIdentityBundle(request: Request, now: number): Promise<Response> {
    const body = await readJsonLimited<{
      bundle?: IdentityBundle;
      expectedEtag?: string;
      writerDeviceId?: string;
    }>(request, CONTROL_JSON_MAX_BYTES);
    const bundle = body.bundle;
    if (!bundle || !body.writerDeviceId) {
      throw new HttpError(426, "upgrade_required", "structured identity publication is required");
    }
    const config = runtimeConfig(this.envRef);
    validateIdentityBundleLifecycle(bundle, body.writerDeviceId, now);
    if (
      bundle.userId !== config.userId ||
      bundle.userPublicKey !== config.userPublicKey ||
      !verifyIdentityBundle(bundle)
    ) {
      throw new HttpError(403, "runtime_auth_invalid", "identity bundle does not match runtime owner");
    }
    const preparedDevices: Array<{ device: DeviceContactProfile; key: string; hash: string }> = [];
    for (const device of bundle.devices) {
      if (
        device.binding.userId !== config.userId ||
        device.binding.deviceId !== device.deviceId ||
        device.binding.devicePublicKey !== device.devicePublicKey ||
        !verifyDeviceBinding(config.userPublicKey, device.binding)
      ) {
        throw new HttpError(403, "runtime_auth_invalid", "identity bundle contains an invalid device binding");
      }
      const key = deviceKey(device.deviceId);
      const hash = await bindingHash(device);
      preparedDevices.push({ device, key, hash });
    }
    const etag = await identityBundleEtag(bundle);
    await this.stateRef.storage.transaction(async (transaction) => {
      const stored = await transaction.get<StoredIdentityBundle>(IDENTITY_BUNDLE_KEY);
      if (stored) {
        if (!body.expectedEtag || body.expectedEtag !== stored.etag) {
          throw new HttpError(412, "identity_bundle_conflict", "identity bundle ETag does not match");
        }
        if ((bundle.publicationRevision ?? 0) <= (stored.bundle.publicationRevision ?? 0)) {
          throw new HttpError(412, "identity_bundle_conflict", "identity bundle revision is not newer");
        }
      } else if (body.expectedEtag && body.expectedEtag !== "*") {
        throw new HttpError(412, "identity_bundle_conflict", "identity bundle does not exist at the expected ETag");
      }
      for (const prepared of preparedDevices) {
        const existing = await transaction.get<DeviceRegistryRecord>(prepared.key);
        if (existing && (existing.devicePublicKey !== prepared.device.devicePublicKey || existing.bindingHash !== prepared.hash)) {
          throw new HttpError(403, "runtime_auth_invalid", "identity bundle attempts to replace a registered device key");
        }
        if (existing?.status === "revoked" && prepared.device.status === "active") {
          throw new HttpError(403, "device_revoked", "identity bundle attempts to reactivate a revoked device");
        }
        const status = existing?.status === "revoked" || prepared.device.status === "revoked" ? "revoked" : "active";
        await transaction.put(prepared.key, {
          version: CURRENT_MODEL_VERSION,
          runtimeId: config.runtimeId,
          userId: config.userId,
          deviceId: prepared.device.deviceId,
          devicePublicKey: prepared.device.devicePublicKey,
          bindingHash: prepared.hash,
          status,
          registrationVersion:
            existing && existing.status !== status
              ? existing.registrationVersion + 1
              : existing?.registrationVersion ?? 1,
          createdAt: existing?.createdAt ?? now,
          updatedAt: now
        } satisfies DeviceRegistryRecord);
      }
      await transaction.put(IDENTITY_BUNDLE_KEY, { bundle, etag } satisfies StoredIdentityBundle);
    });
    const response = jsonResponse(bundle);
    response.headers.set("etag", etag);
    return response;
  }

  private async getIdentityBundle(): Promise<Response> {
    const stored = await this.stateRef.storage.get<StoredIdentityBundle>(IDENTITY_BUNDLE_KEY);
    if (!stored) return errorResponse(404, "not_found");
    const response = jsonResponse(stored.bundle);
    response.headers.set("etag", stored.etag);
    return response;
  }

  private async migrateIdentityBundle(request: Request, now: number): Promise<Response> {
    const body = await readJsonLimited<{ bundle?: IdentityBundle }>(request, CONTROL_JSON_MAX_BYTES);
    const bundle = body.bundle;
    const config = runtimeConfig(this.envRef);
    if (
      !bundle ||
      bundle.userId !== config.userId ||
      bundle.userPublicKey !== config.userPublicKey ||
      !verifyIdentityBundle(bundle)
    ) {
      throw new HttpError(403, "runtime_auth_invalid", "legacy identity bundle is invalid");
    }
    const preparedDevices: Array<{ device: DeviceContactProfile; key: string; hash: string }> = [];
    for (const device of bundle.devices) {
      if (
        device.binding.userId !== config.userId ||
        device.binding.deviceId !== device.deviceId ||
        device.binding.devicePublicKey !== device.devicePublicKey ||
        !verifyDeviceBinding(config.userPublicKey, device.binding)
      ) {
        throw new HttpError(403, "runtime_auth_invalid", "legacy identity bundle contains an invalid device binding");
      }
      preparedDevices.push({
        device,
        key: deviceKey(device.deviceId),
        hash: await bindingHash(device)
      });
    }
    const etag = await identityBundleEtag(bundle);
    const stored = await this.stateRef.storage.transaction(async (transaction) => {
      const existingBundle = await transaction.get<StoredIdentityBundle>(IDENTITY_BUNDLE_KEY);
      if (existingBundle) return existingBundle;
      for (const prepared of preparedDevices) {
        const existing = await transaction.get<DeviceRegistryRecord>(prepared.key);
        if (
          existing &&
          (existing.devicePublicKey !== prepared.device.devicePublicKey || existing.bindingHash !== prepared.hash)
        ) {
          throw new HttpError(403, "runtime_auth_invalid", "legacy identity bundle conflicts with a registered device");
        }
        if (!existing) {
          await transaction.put(prepared.key, {
            version: CURRENT_MODEL_VERSION,
            runtimeId: config.runtimeId,
            userId: config.userId,
            deviceId: prepared.device.deviceId,
            devicePublicKey: prepared.device.devicePublicKey,
            bindingHash: prepared.hash,
            status: prepared.device.status,
            registrationVersion: 1,
            createdAt: now,
            updatedAt: now
          } satisfies DeviceRegistryRecord);
        }
      }
      const migrated = { bundle, etag } satisfies StoredIdentityBundle;
      await transaction.put(IDENTITY_BUNDLE_KEY, migrated);
      return migrated;
    });
    const response = jsonResponse(stored.bundle);
    response.headers.set("etag", stored.etag);
    return response;
  }
}

export function registryStub(env: Env): DurableObjectStub {
  const runtimeId = runtimeConfig(env).runtimeId;
  return env.DEVICE_REGISTRY.get(env.DEVICE_REGISTRY.idFromName(runtimeId));
}

export async function assertRegisteredRuntimeToken(env: Env, token: DeviceRuntimeToken): Promise<void> {
  const response = await registryStub(env).fetch(
    new Request("https://device-registry.internal/v2/device-registry/authorize", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(token)
    })
  );
  if (!response.ok) {
    const body: { code?: string } = await response
      .json<{ code?: string }>()
      .catch(() => ({}));
    const code = body.code ?? "runtime_auth_invalid";
    throw new HttpError(response.status, code, code);
  }
}

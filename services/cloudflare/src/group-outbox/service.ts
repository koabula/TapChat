import { HttpError, verifyEd25519 } from "../auth/capability";
import type {
  AppendGroupEnvelopeRequest,
  AppendGroupEnvelopeResult,
  AppendGroupEpochTransitionRequest,
  AppendGroupEpochTransitionResult,
  AppendGroupTransitionRequest,
  AppendGroupTransitionResult,
  ClaimGroupJoinRequest,
  ClaimGroupJoinResult,
  ClaimGroupLeaveRequest,
  ClaimGroupLeaveResult,
  CompleteGroupJoinRequest,
  CompleteGroupJoinResult,
  CreateGroupInviteRequest,
  CreateGroupInviteResult,
  DecideGroupJoinRequest,
  DecideGroupJoinResult,
  FetchGroupOutboxRequest,
  FetchGroupOutboxResult,
  FetchGroupInviteResult,
  GetGroupOutboxHeadResult,
  GetGroupJoinRequestStatusResult,
  GroupEnvelope,
  GroupInviteDocument,
  GroupInviteTokenPayload,
  GroupJoinRequest,
  GroupLeaveRequest,
  GroupCursor,
  GroupManifest,
  GroupOutboxRecord,
  ListGroupInvitesResult,
  ListGroupJoinRequestsResult,
  ListGroupLeaveRequestsResult,
  RevokeGroupInviteRequest,
  RevokeGroupInviteResult,
  SubmitGroupJoinRequest,
  SubmitGroupJoinResult,
  SubmitGroupLeaveRequest,
  SubmitGroupLeaveResult,
  WelcomePickupDescriptor
} from "../types/contracts";
import type { DurableObjectStorageLike, JsonBlobStore, SessionSink } from "../types/runtime";
import { groupManifestSha256 } from "../auth/capability";
import {
  GROUP_AUTHORIZATION_KEY,
  groupTransitionProofOperation,
  type GroupAuthorizationState
} from "./authorization";

interface GroupOutboxMeta {
  headSeq: number;
  historyFloorSeq?: number;
  retentionDays: number;
  maxInlineBytes: number;
  /**
   * Once true, the durable object permanently rejects all append-type
   * requests with HTTP 403 `group_sealed` regardless of capability. Per
   * PROTOCOL_GROUP_CN.md §10.4 sealing is irreversible in v1; there is no
   * code path that sets this back to false.
   */
  sealed?: boolean;
  /** Millisecond timestamp the seal first succeeded. Defaults to 0. */
  sealedAt?: number;
  /**
   * Latest roster version observed from a successfully appended
   * membership operation. Used for optimistic concurrency: a writer
   * may supply expectedPreviousRosterVersion and the server rejects
   * the append with 409 when the stored version does not match.
   */
  currentRosterVersion?: number;
  /**
   * Latest commit message id from a successfully appended membership
   * operation. Paired with currentRosterVersion for double-entry
   * optimistic concurrency; a stale commit-message-id also triggers
   * 409 `roster_version_conflict`.
   */
  lastCommitMessageId?: string;
  cryptoEpoch?: number;
  cryptoHeadHash?: string;
  groupAppCount?: number;
  applicationIndex?: number;
  leafLastUpdateIndex?: Record<string, number>;
}

interface StoredGroupRecordIndex {
  seq: number;
  groupId: string;
  messageId: string;
  receivedAt: number;
  expiresAt?: number;
  state: "available";
  inlineRecord?: GroupOutboxRecord;
  payloadRef?: string;
  transitionId?: string;
  transitionStartSeq?: number;
  transitionEndSeq?: number;
}

const META_KEY = "meta";
const IDEMPOTENCY_PREFIX = "idempotency:";
const RECORD_PREFIX = "record:";
const INVITE_PREFIX = "invite:";
const JOIN_REQUEST_PREFIX = "join-request:";
const JOIN_REQUEST_IDEMPOTENCY_PREFIX = "join-request-idempotency:";
const LEAVE_REQUEST_PREFIX = "leave-request:";
const LEAVE_REQUEST_IDEMPOTENCY_PREFIX = "leave-request-idempotency:";
const TRANSITION_PREFIX = "transition:";
const INVITE_REVISION_KEY = "invite-revision";
const CLEANUP_BATCH_SIZE = 128;

interface StoredMembershipGroupTransition {
  /** Missing on records written before protocol bundle 6; absence means membership. */
  kind?: "membership";
  fingerprint: string;
  operation: AppendGroupTransitionRequest["operation"];
  requestBinding?: AppendGroupTransitionRequest["requestBinding"];
  result: AppendGroupTransitionResult;
}

interface StoredEpochGroupTransition {
  kind: "epoch";
  fingerprint: string;
  operation: { type: "self_update" };
  result: AppendGroupEpochTransitionResult;
}

type StoredGroupTransition = StoredMembershipGroupTransition | StoredEpochGroupTransition;

interface StoredGroupInvite {
  inviteUrl: string;
  token: string;
  document: GroupInviteDocument;
  uses: number;
  maxUses?: number;
  revokedAt?: number;
  expiredAt?: number;
  exhaustedAt?: number;
}

interface StoredGroupJoinRequest {
  request: GroupJoinRequest;
  welcomePickup?: WelcomePickupDescriptor;
  manifest?: GroupManifest;
  startCursor?: GroupCursor;
  reason?: string;
  transitionId?: string;
  lease?: {
    token: string;
    userId: string;
    deviceId: string;
    expiresAt: number;
  };
  committedBinding?: { transitionId: string; leaseToken: string; committedAt: number };
  completionFingerprint?: string;
}

interface StoredGroupLeaveRequest {
  request: GroupLeaveRequest;
  transitionId?: string;
  lease?: { token: string; userId: string; deviceId: string; expiresAt: number };
}

const JOIN_LEASE_MS = 2 * 60 * 1000;

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function transitionFingerprint(input: AppendGroupTransitionRequest): string {
  const { capability: _capability, ...stable } = input;
  return canonicalJson(stable);
}

function decodeBase64(value: string): Uint8Array {
  try {
    const binary = atob(value);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    throw new HttpError(400, "invalid_crypto_transition", "MLS Commit is not valid base64");
  }
}

async function sha256Hex(value: Uint8Array | string): Promise<string> {
  const bytes = typeof value === "string" ? new TextEncoder().encode(value) : value;
  const digest = await crypto.subtle.digest("SHA-256", Uint8Array.from(bytes).buffer);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function groupCryptoHeadHash(
  previousHeadHash: string,
  nextEpoch: number,
  commitB64: string,
  epochAuthenticatorSha256: string,
  committerUserId: string,
  committerDeviceId: string
): Promise<string> {
  const commitSha256 = await sha256Hex(decodeBase64(commitB64));
  return sha256Hex(
    `tapchat.group_crypto_head.v1\n${previousHeadHash}\n${nextEpoch}\n${commitSha256}\n${epochAuthenticatorSha256}\n${committerUserId}\n${committerDeviceId}`
  );
}

function groupEnvelopeEpochSigningPayload(envelope: GroupEnvelope): string {
  return `tapchat.group_envelope_epoch.v1\npayload=${envelope.inlineCiphertext ?? ""}\nmls_epoch=${envelope.mlsEpoch}\nepoch_head_hash=${envelope.epochHeadHash}\nepoch_authenticator_sha256=${envelope.epochAuthenticatorSha256 ?? ""}`;
}

function verifyEpochBoundEnvelope(envelope: GroupEnvelope, authorization: GroupAuthorizationState): void {
  if (
    envelope.senderProof.type !== "device_signature" ||
    envelope.mlsEpoch === undefined ||
    !envelope.epochHeadHash ||
    !/^[0-9a-f]{64}$/.test(envelope.epochHeadHash)
  ) {
    throw new HttpError(400, "invalid_epoch_binding", "group envelope is missing its epoch binding");
  }
  const device = authorization.devices[`${envelope.senderUserId}\u0000${envelope.senderDeviceId}`];
  if (
    !device || device.status !== "active" ||
    !verifyEd25519(device.publicKey, envelope.senderProof.value, groupEnvelopeEpochSigningPayload(envelope))
  ) {
    throw new HttpError(403, "invalid_sender_proof", "group epoch binding signature is invalid");
  }
}

export class GroupOutboxService {
  private readonly groupId: string;
  private readonly state: DurableObjectStorageLike;
  private readonly spillStore: JsonBlobStore;
  private readonly defaults: GroupOutboxMeta;
  private readonly sessions: SessionSink[];

  constructor(
    groupId: string,
    state: DurableObjectStorageLike,
    spillStore: JsonBlobStore,
    defaults: GroupOutboxMeta,
    sessions: SessionSink[] = []
  ) {
    this.groupId = groupId;
    this.state = state;
    this.spillStore = spillStore;
    this.defaults = defaults;
    this.sessions = sessions;
  }

  async appendEnvelope(input: AppendGroupEnvelopeRequest, now: number): Promise<AppendGroupEnvelopeResult> {
    await this.rejectIfSealed();
    this.validateAppendRequest(input);

    const existingSeq = await this.state.get<number>(`${IDEMPOTENCY_PREFIX}${input.envelope.messageId}`);
    if (existingSeq !== undefined) {
      return { accepted: true, seq: existingSeq };
    }

    const meta = await this.getMeta();
    const authorization = await this.state.get<GroupAuthorizationState>(GROUP_AUTHORIZATION_KEY);
    const isApplication = input.envelope.messageType === "mls_application";
    const activeLeaves = authorization?.manifest.memberDevices?.filter((leaf) => leaf.status === "active") ?? [];
    if (isApplication) {
      if (activeLeaves.length === 0 || activeLeaves.length > 16) {
        throw new HttpError(409, activeLeaves.length > 16 ? "group_leaf_limit_exceeded" : "group_authorization_uninitialized", "group application sending is unavailable for this leaf set");
      }
      if (
        meta.cryptoEpoch === undefined || !meta.cryptoHeadHash ||
        input.expectedCryptoEpoch !== meta.cryptoEpoch ||
        input.expectedCryptoHeadHash !== meta.cryptoHeadHash ||
        input.envelope.mlsEpoch !== meta.cryptoEpoch ||
        input.envelope.epochHeadHash !== meta.cryptoHeadHash ||
        input.envelope.epochAuthenticatorSha256 !== undefined
      ) {
        throw new HttpError(409, "crypto_epoch_conflict", "group application epoch head is stale");
      }
      if (!authorization) {
        throw new HttpError(409, "group_authorization_uninitialized", "group authorization is unavailable");
      }
      verifyEpochBoundEnvelope(input.envelope, authorization);
      const groupAppCount = meta.groupAppCount ?? 0;
      const applicationIndex = meta.applicationIndex ?? 0;
      const leafBaseline = meta.leafLastUpdateIndex?.[input.envelope.senderDeviceId] ?? applicationIndex;
      if (groupAppCount >= 32 || applicationIndex - leafBaseline >= 32 * activeLeaves.length) {
        throw new HttpError(409, "epoch_update_required", "group PCS policy requires an update-path Commit before this application");
      }
    }

    const seq = meta.headSeq + 1;
    const expiresAt = now + meta.retentionDays * 24 * 60 * 60 * 1000;
    const record: GroupOutboxRecord = {
      seq,
      groupId: this.groupId,
      messageId: input.envelope.messageId,
      receivedAt: now,
      expiresAt,
      state: "available",
      envelope: input.envelope
    };
    const serialized = JSON.stringify(record);
    const storageKey = `${RECORD_PREFIX}${seq}`;

    let recordIndex: StoredGroupRecordIndex;
    if (new TextEncoder().encode(serialized).byteLength <= meta.maxInlineBytes && input.envelope.inlineCiphertext) {
      recordIndex = {
        seq,
        groupId: record.groupId,
        messageId: record.messageId,
        receivedAt: record.receivedAt,
        expiresAt,
        state: record.state,
        inlineRecord: record
      };
    } else {
      const payloadRef = `group-outbox-payload/${this.groupId}/${seq}.json`;
      await this.spillStore.putJson(payloadRef, record);
      recordIndex = {
        seq,
        groupId: record.groupId,
        messageId: record.messageId,
        receivedAt: record.receivedAt,
        expiresAt,
        state: record.state,
        payloadRef
      };
      const currentMeta = await this.getMeta();
      const currentIdempotency = await this.state.get<number>(`${IDEMPOTENCY_PREFIX}${record.messageId}`);
      if (currentIdempotency !== undefined) {
        return { accepted: true, seq: currentIdempotency };
      }
      if (
        currentMeta.headSeq !== meta.headSeq ||
        currentMeta.cryptoEpoch !== meta.cryptoEpoch ||
        currentMeta.cryptoHeadHash !== meta.cryptoHeadHash ||
        currentMeta.groupAppCount !== meta.groupAppCount ||
        currentMeta.applicationIndex !== meta.applicationIndex
      ) {
        throw new HttpError(409, "crypto_epoch_conflict", "group head changed while the record was prepared");
      }
    }

    await this.state.putEntries({
      [storageKey]: recordIndex,
      [`${IDEMPOTENCY_PREFIX}${record.messageId}`]: seq,
      [META_KEY]: {
        ...meta,
        headSeq: seq,
        ...(isApplication ? {
          groupAppCount: (meta.groupAppCount ?? 0) + 1,
          applicationIndex: (meta.applicationIndex ?? 0) + 1
        } : {})
      }
    });
    await this.state.setAlarm(expiresAt);

    this.publish({ event: "group_head_updated", groupId: this.groupId, seq });
    this.publish({ event: "group_outbox_record_available", groupId: this.groupId, seq, record });

    return { accepted: true, seq };
  }

  async appendEpochTransition(
    input: AppendGroupEpochTransitionRequest,
    now: number
  ): Promise<AppendGroupEpochTransitionResult> {
    await this.rejectIfSealed();
    this.validateEnvelope(input.envelope);
    if (
      input.groupId !== this.groupId || !input.transitionId ||
      input.nextCryptoEpoch !== input.expectedCryptoEpoch + 1 ||
      input.envelope.groupId !== this.groupId ||
      input.envelope.messageType !== "mls_commit" ||
      input.envelope.visibility !== "protocol" ||
      input.envelope.transitionId !== input.transitionId ||
      input.envelope.mlsEpoch !== input.nextCryptoEpoch ||
      input.envelope.epochHeadHash !== input.nextCryptoHeadHash ||
      !input.envelope.inlineCiphertext ||
      !/^[0-9a-f]{64}$/.test(input.epochAuthenticatorSha256) ||
      !/^[0-9a-f]{64}$/.test(input.nextCryptoHeadHash)
    ) {
      throw new HttpError(400, "invalid_crypto_transition", "group epoch transition is malformed");
    }
    const transitionKey = `${TRANSITION_PREFIX}${input.transitionId}`;
    const { capability: _capability, ...stableInput } = input;
    const fingerprint = canonicalJson(stableInput);
    const existing = await this.state.get<StoredGroupTransition>(transitionKey);
    if (existing) {
      if (existing.kind !== "epoch" || existing.fingerprint !== fingerprint) {
        throw new HttpError(409, "group_transition_conflict", "transition id has different content or transition kind");
      }
      return existing.result;
    }
    const meta = await this.getMeta();
    if (meta.cryptoEpoch !== input.expectedCryptoEpoch || (meta.cryptoHeadHash ?? "") !== input.expectedCryptoHeadHash) {
      throw new HttpError(409, "crypto_epoch_conflict", "group crypto head changed");
    }
    const authorization = await this.state.get<GroupAuthorizationState>(GROUP_AUTHORIZATION_KEY);
    const activeLeaves = authorization?.manifest.memberDevices?.filter((leaf) => leaf.status === "active") ?? [];
    if (activeLeaves.length === 0 || activeLeaves.length > 16) {
      throw new HttpError(409, "group_leaf_limit_exceeded", "group must contain between 1 and 16 active leaves");
    }
    if (!authorization) {
      throw new HttpError(409, "group_authorization_uninitialized", "group authorization is unavailable");
    }
    if (input.envelope.epochAuthenticatorSha256 !== input.epochAuthenticatorSha256) {
      throw new HttpError(400, "invalid_crypto_transition", "Commit authenticator binding does not match the transition");
    }
    verifyEpochBoundEnvelope(input.envelope, authorization);
    const computedHead = await groupCryptoHeadHash(
      input.expectedCryptoHeadHash,
      input.nextCryptoEpoch,
      input.envelope.inlineCiphertext,
      input.epochAuthenticatorSha256,
      input.envelope.senderUserId,
      input.envelope.senderDeviceId
    );
    if (computedHead !== input.nextCryptoHeadHash) {
      throw new HttpError(400, "invalid_crypto_head", "next group crypto head does not match the Commit");
    }
    // WebCrypto yields between the initial reads and this point. Re-read the
    // authoritative keys so two Commit requests based on one epoch cannot both
    // append and fork the MLS state.
    const currentTransition = await this.state.get<StoredGroupTransition>(transitionKey);
    if (currentTransition) {
      if (currentTransition.kind === "epoch" && currentTransition.fingerprint === fingerprint) {
        return currentTransition.result;
      }
      throw new HttpError(409, "group_transition_conflict", "transition id has different content or transition kind");
    }
    const currentMessageSeq = await this.state.get<number>(`${IDEMPOTENCY_PREFIX}${input.envelope.messageId}`);
    if (currentMessageSeq !== undefined) {
      throw new HttpError(409, "group_transition_conflict", "transition message id already belongs to another record");
    }
    const currentMeta = await this.getMeta();
    const currentAuthorization = await this.state.get<GroupAuthorizationState>(GROUP_AUTHORIZATION_KEY);
    if (
      currentMeta.headSeq !== meta.headSeq ||
      currentMeta.cryptoEpoch !== meta.cryptoEpoch ||
      currentMeta.cryptoHeadHash !== meta.cryptoHeadHash ||
      !currentAuthorization ||
      currentAuthorization.manifest.signature !== authorization.manifest.signature
    ) {
      throw new HttpError(409, "crypto_epoch_conflict", "group crypto head changed while the Commit was verified");
    }
    const seq = meta.headSeq + 1;
    const expiresAt = now + meta.retentionDays * 24 * 60 * 60 * 1000;
    const record: GroupOutboxRecord = { seq, groupId: this.groupId, messageId: input.envelope.messageId, receivedAt: now, expiresAt, state: "available", envelope: input.envelope };
    const index: StoredGroupRecordIndex = { seq, groupId: this.groupId, messageId: record.messageId, receivedAt: now, expiresAt, state: "available", inlineRecord: record, transitionId: input.transitionId, transitionStartSeq: seq, transitionEndSeq: seq };
    const result: AppendGroupEpochTransitionResult = { accepted: true, transitionId: input.transitionId, seq, cryptoEpoch: input.nextCryptoEpoch, cryptoHeadHash: input.nextCryptoHeadHash };
    await this.state.putEntries({
      [`${RECORD_PREFIX}${seq}`]: index,
      [`${IDEMPOTENCY_PREFIX}${record.messageId}`]: seq,
      [transitionKey]: { kind: "epoch", fingerprint, operation: { type: "self_update" }, result } satisfies StoredEpochGroupTransition,
      [META_KEY]: {
        ...meta,
        headSeq: seq,
        cryptoEpoch: input.nextCryptoEpoch,
        cryptoHeadHash: input.nextCryptoHeadHash,
        groupAppCount: 0,
        leafLastUpdateIndex: {
          ...(meta.leafLastUpdateIndex ?? {}),
          [input.envelope.senderDeviceId]: meta.applicationIndex ?? 0
        }
      }
    });
    await this.state.setAlarm(expiresAt);
    this.publish({ event: "group_head_updated", groupId: this.groupId, seq });
    this.publish({ event: "group_outbox_record_available", groupId: this.groupId, seq, record });
    return result;
  }

  /** Fail closed before parsing or authorizing an append body on a sealed log. */
  async assertWritable(): Promise<void> {
    await this.rejectIfSealed();
  }

  async appendTransition(
    input: AppendGroupTransitionRequest,
    preparedAuthorization: GroupAuthorizationState,
    now: number
  ): Promise<AppendGroupTransitionResult> {
    await this.rejectIfSealed();
    this.validateTransitionRequest(input);

    const transitionKey = `${TRANSITION_PREFIX}${input.transitionId}`;
    const fingerprint = transitionFingerprint(input);
    const existing = await this.state.get<StoredGroupTransition>(transitionKey);
    if (existing) {
      if (existing.kind === "epoch" || existing.fingerprint !== fingerprint) {
        throw new HttpError(409, "group_transition_conflict", "transition id already exists with different content or transition kind");
      }
      return existing.result;
    }

    const meta = await this.getMeta();
    const authorization = await this.state.get<GroupAuthorizationState>(GROUP_AUTHORIZATION_KEY);
    if (!authorization) {
      throw new HttpError(428, "group_authorization_uninitialized", "group authorization has not been initialized");
    }
    const activeLeaves = preparedAuthorization.manifest.memberDevices?.filter((leaf) => leaf.status === "active") ?? [];
    const overLimitRecoveryOperation =
      input.operation.type === "approve_leave" ||
      input.operation.type === "remove_member" ||
      input.operation.type === "remove_device" ||
      input.operation.type === "dissolve";
    if (activeLeaves.length > 16 && !overLimitRecoveryOperation) {
      throw new HttpError(409, "group_leaf_limit_exceeded", "membership transition would exceed 16 active leaves");
    }
    const initializingCrypto = meta.cryptoEpoch === undefined && input.operation.type === "create";
    if (
      input.expectedCryptoEpoch === undefined ||
      input.expectedCryptoHeadHash === undefined ||
      input.nextCryptoEpoch === undefined ||
      input.nextCryptoHeadHash === undefined ||
      input.epochAuthenticatorSha256 === undefined ||
      (!initializingCrypto && (input.expectedCryptoEpoch !== meta.cryptoEpoch || input.expectedCryptoHeadHash !== (meta.cryptoHeadHash ?? ""))) ||
      (initializingCrypto && (input.expectedCryptoEpoch !== 0 || input.expectedCryptoHeadHash !== "")) ||
      input.nextCryptoEpoch !== input.expectedCryptoEpoch + 1 ||
      !/^[0-9a-f]{64}$/.test(input.nextCryptoHeadHash) ||
      !/^[0-9a-f]{64}$/.test(input.epochAuthenticatorSha256)
    ) {
      throw new HttpError(409, "crypto_epoch_conflict", "membership transition crypto base is stale");
    }
    const commitEnvelope = input.envelopes.find((envelope) => envelope.messageType === "mls_commit");
    if (
      !commitEnvelope || !commitEnvelope.inlineCiphertext ||
      commitEnvelope.mlsEpoch !== input.nextCryptoEpoch ||
      commitEnvelope.epochHeadHash !== input.nextCryptoHeadHash ||
      commitEnvelope.epochAuthenticatorSha256 !== input.epochAuthenticatorSha256
    ) {
      throw new HttpError(409, "group_transition_invalid", "membership Commit does not bind the next crypto head");
    }
    verifyEpochBoundEnvelope(commitEnvelope, authorization);
    const computedHead = await groupCryptoHeadHash(
      input.expectedCryptoHeadHash,
      input.nextCryptoEpoch,
      commitEnvelope.inlineCiphertext,
      input.epochAuthenticatorSha256,
      commitEnvelope.senderUserId,
      commitEnvelope.senderDeviceId
    );
    if (computedHead !== input.nextCryptoHeadHash) {
      throw new HttpError(400, "invalid_crypto_head", "membership Commit does not derive the next crypto head");
    }
    for (const envelope of input.envelopes) {
      if (
        envelope.mlsEpoch !== input.nextCryptoEpoch ||
        envelope.epochHeadHash !== input.nextCryptoHeadHash ||
        (envelope.messageType !== "mls_commit" && envelope.epochAuthenticatorSha256 !== undefined)
      ) {
        throw new HttpError(409, "group_transition_invalid", "transition records must bind one crypto head");
      }
      verifyEpochBoundEnvelope(envelope, authorization);
    }
    const storedRosterVersion = authorization.manifest.rosterVersion;
    const storedCommitMessageId = authorization.manifest.lastCommitMessageId ?? "";
    if (
      (meta.currentRosterVersion !== undefined && meta.currentRosterVersion !== storedRosterVersion) ||
      (meta.lastCommitMessageId !== undefined && meta.lastCommitMessageId !== storedCommitMessageId)
    ) {
      throw new HttpError(500, "storage_integrity_error", "group outbox meta does not match authorization state");
    }
    const requestBindingEntries = await this.validateAndPrepareRequestBinding(input, now);
    for (const envelope of input.envelopes) {
      const existingSeq = await this.state.get<number>(`${IDEMPOTENCY_PREFIX}${envelope.messageId}`);
      if (existingSeq !== undefined) {
        throw new HttpError(409, "group_transition_conflict", "transition message id already belongs to another record");
      }
    }
    if (
      input.expectedPreviousRosterVersion !== storedRosterVersion ||
      (input.expectedPreviousCommitMessageId ?? "") !== storedCommitMessageId
    ) {
      throw new HttpError(409, "roster_version_conflict", "group transition base does not match the authoritative roster");
    }

    const firstSeq = meta.headSeq + 1;
    const lastSeq = firstSeq + input.envelopes.length - 1;
    const expiresAt = now + meta.retentionDays * 24 * 60 * 60 * 1000;
    const records = input.envelopes.map<GroupOutboxRecord>((envelope, offset) => ({
      seq: firstSeq + offset,
      groupId: this.groupId,
      messageId: envelope.messageId,
      receivedAt: now,
      expiresAt,
      state: "available",
      envelope
    }));

    const indexes: Array<[string, StoredGroupRecordIndex]> = [];
    for (const record of records) {
      const serialized = JSON.stringify(record);
      const index: StoredGroupRecordIndex = {
        seq: record.seq,
        groupId: record.groupId,
        messageId: record.messageId,
        receivedAt: record.receivedAt,
        expiresAt,
        state: record.state,
        transitionId: input.transitionId,
        transitionStartSeq: firstSeq,
        transitionEndSeq: lastSeq
      };
      if (new TextEncoder().encode(serialized).byteLength <= meta.maxInlineBytes && record.envelope.inlineCiphertext) {
        index.inlineRecord = record;
      } else {
        const payloadRef = `group-outbox-transition/${this.groupId}/${input.transitionId}/${record.messageId}.json`;
        await this.spillStore.putJson(payloadRef, record);
        index.payloadRef = payloadRef;
      }
      indexes.push([`${RECORD_PREFIX}${record.seq}`, index]);
    }

    // External R2 writes above can yield. Re-read the authoritative keys and
    // reject rather than committing records against a base that raced ahead.
    const currentMeta = await this.getMeta();
    const currentAuthorization = await this.state.get<GroupAuthorizationState>(GROUP_AUTHORIZATION_KEY);
    if (
      currentMeta.headSeq !== meta.headSeq ||
      currentMeta.cryptoEpoch !== meta.cryptoEpoch ||
      currentMeta.cryptoHeadHash !== meta.cryptoHeadHash ||
      (currentMeta.currentRosterVersion !== undefined && currentMeta.currentRosterVersion !== storedRosterVersion) ||
      (currentMeta.lastCommitMessageId !== undefined && currentMeta.lastCommitMessageId !== storedCommitMessageId) ||
      !currentAuthorization ||
      currentAuthorization.manifest.signature !== authorization.manifest.signature ||
      currentAuthorization.manifest.rosterVersion !== input.expectedPreviousRosterVersion ||
      (currentAuthorization.manifest.lastCommitMessageId ?? "") !== storedCommitMessageId
    ) {
      throw new HttpError(409, "roster_version_conflict", "group transition base changed while payloads were prepared");
    }

    const result: AppendGroupTransitionResult = {
      accepted: true,
      transitionId: input.transitionId,
      firstSeq,
      lastSeq,
      rosterVersion: preparedAuthorization.manifest.rosterVersion,
      lastCommitMessageId: preparedAuthorization.manifest.lastCommitMessageId
    };
    const entries: Record<string, unknown> = {
      [META_KEY]: {
        ...meta,
        headSeq: lastSeq,
        currentRosterVersion: preparedAuthorization.manifest.rosterVersion,
        lastCommitMessageId: preparedAuthorization.manifest.lastCommitMessageId,
        cryptoEpoch: input.nextCryptoEpoch,
        cryptoHeadHash: input.nextCryptoHeadHash,
        groupAppCount: 0,
        applicationIndex: meta.applicationIndex ?? 0,
        leafLastUpdateIndex: Object.fromEntries(activeLeaves.map((leaf) => [
          leaf.deviceId,
          leaf.deviceId === input.capability.deviceId
            ? (meta.applicationIndex ?? 0)
            : (meta.leafLastUpdateIndex?.[leaf.deviceId] ?? (meta.applicationIndex ?? 0))
        ]))
      },
      [GROUP_AUTHORIZATION_KEY]: {
        ...preparedAuthorization,
        lastTransitionId: input.transitionId
      },
      [transitionKey]: { kind: "membership", fingerprint, operation: input.operation, requestBinding: input.requestBinding, result } satisfies StoredMembershipGroupTransition,
      ...requestBindingEntries
    };
    for (const [key, index] of indexes) {
      entries[key] = index;
      entries[`${IDEMPOTENCY_PREFIX}${index.messageId}`] = index.seq;
    }
    await this.state.putEntries(entries);
    await this.state.setAlarm(expiresAt);

    for (const record of records) {
      this.publish({ event: "group_head_updated", groupId: this.groupId, seq: record.seq });
      this.publish({ event: "group_outbox_record_available", groupId: this.groupId, seq: record.seq, record });
    }
    return result;
  }

  private validateTransitionRequest(input: AppendGroupTransitionRequest): void {
    if (input.groupId !== this.groupId || !input.transitionId || input.envelopes.length < 2 || input.envelopes.length > 3 || !input.operation || typeof input.operation !== "object") {
      throw new HttpError(400, "invalid_input", "group transition must contain one to three envelopes for this group");
    }
    const messageIds = new Set<string>();
    let proofJson: string | undefined;
    for (const envelope of input.envelopes) {
      if (
        envelope.groupId !== this.groupId ||
        envelope.transitionId !== input.transitionId ||
        envelope.senderUserId !== input.capability.userId ||
        envelope.senderDeviceId !== input.capability.deviceId ||
        messageIds.has(envelope.messageId)
      ) {
        throw new HttpError(409, "group_transition_invalid", "group transition envelope binding is invalid");
      }
      messageIds.add(envelope.messageId);
      if (envelope.membershipProof) {
        const nextProofJson = JSON.stringify(envelope.membershipProof);
        if (proofJson && proofJson !== nextProofJson) {
          throw new HttpError(409, "group_transition_invalid", "group transition envelopes carry different membership proofs");
        }
        proofJson = nextProofJson;
      }
    }
    const proof = input.envelopes.find((envelope) => envelope.membershipProof)?.membershipProof;
    if (
      !proof ||
      proof.operation !== groupTransitionProofOperation(input.operation) ||
      proof.previousRosterVersion !== input.expectedPreviousRosterVersion
    ) {
      throw new HttpError(409, "group_transition_invalid", "group transition proof does not match the request base");
    }
    const commitIsCurrent = proof.commitMessageId === (input.expectedPreviousCommitMessageId ?? "");
    if (!messageIds.has(proof.controlMessageId) || (!messageIds.has(proof.commitMessageId) && !commitIsCurrent)) {
      throw new HttpError(409, "group_transition_invalid", "group transition proof references records outside the bundle");
    }
    if (proof.stateEventMessageId && !messageIds.has(proof.stateEventMessageId)) {
      throw new HttpError(409, "group_transition_invalid", "group state event is not part of the transition bundle");
    }
    if (!proof.stateEventMessageId) {
      throw new HttpError(409, "group_transition_invalid", "group transition must contain a bound state event");
    }
    const controls = input.envelopes.filter((envelope) =>
      envelope.messageId === proof.controlMessageId && envelope.messageType.startsWith("control_group_")
    );
    const stateEvents = input.envelopes.filter((envelope) =>
      envelope.messageId === proof.stateEventMessageId && envelope.messageType === "control_group_state_event"
    );
    if (controls.length !== 1 || stateEvents.length !== 1) {
      throw new HttpError(409, "group_transition_invalid", "group transition control and state event records are invalid");
    }
  }

  private async validateAndPrepareRequestBinding(
    input: AppendGroupTransitionRequest,
    now: number
  ): Promise<Record<string, unknown>> {
    const binding = input.requestBinding;
    if (input.operation.type === "approve_join") {
      if (!binding || binding.type !== "join" || binding.requestId !== input.operation.requestId) {
        throw new HttpError(409, "group_join_lease_invalid", "join transition must bind its claimed join request");
      }
      const key = `${JOIN_REQUEST_PREFIX}${binding.requestId}`;
      const stored = await this.state.get<StoredGroupJoinRequest>(key);
      const lease = stored?.lease;
      if (
        !stored || stored.request.status !== "transition_in_progress" ||
        stored.request.joinerUserId !== input.operation.userId ||
        stored.request.joinerDeviceId !== input.operation.deviceId ||
        !lease || lease.expiresAt <= now || lease.token !== binding.leaseToken ||
        lease.userId !== input.capability.userId || lease.deviceId !== input.capability.deviceId
      ) {
        throw new HttpError(409, "group_join_lease_invalid", "join transition lease is missing, expired, or does not match the joiner");
      }
      return {
        [key]: {
          ...stored,
          transitionId: input.transitionId,
          committedBinding: { transitionId: input.transitionId, leaseToken: binding.leaseToken, committedAt: now }
        } satisfies StoredGroupJoinRequest
      };
    }
    if (input.operation.type === "approve_leave") {
      if (!binding || binding.type !== "leave" || binding.requestId !== input.operation.requestId) {
        throw new HttpError(409, "group_leave_lease_invalid", "leave transition must bind its claimed leave request");
      }
      const key = `${LEAVE_REQUEST_PREFIX}${binding.requestId}`;
      const stored = await this.state.get<StoredGroupLeaveRequest>(key);
      const lease = stored?.lease;
      if (
        !stored || stored.request.status !== "transition_in_progress" ||
        stored.request.leaverUserId !== input.operation.userId ||
        stored.request.leaverDeviceId !== input.operation.deviceId ||
        !lease || lease.expiresAt <= now || lease.token !== binding.leaseToken ||
        lease.userId !== input.capability.userId || lease.deviceId !== input.capability.deviceId
      ) {
        throw new HttpError(409, "group_leave_lease_invalid", "leave transition lease is missing, expired, or does not match the leaver");
      }
      return {
        [key]: {
          ...stored,
          request: { ...stored.request, status: "completed" },
          transitionId: input.transitionId,
          lease: undefined
        } satisfies StoredGroupLeaveRequest
      };
    }
    if (binding) {
      throw new HttpError(409, "group_transition_invalid", "request binding is only valid for join or leave transitions");
    }
    return {};
  }

  async fetchOutbox(input: FetchGroupOutboxRequest): Promise<FetchGroupOutboxResult> {
    if (input.groupId !== this.groupId) {
      throw new HttpError(400, "invalid_input", "group_id does not match group outbox route");
    }
    if (input.limit <= 0) {
      throw new HttpError(400, "invalid_input", "limit must be greater than zero");
    }

    const meta = await this.getMeta();
    const historyFloorSeq = meta.historyFloorSeq ?? 0;
    const start = Math.max(input.fromSeq, historyFloorSeq + 1);
    const records: GroupOutboxRecord[] = [];
    const firstIndex = await this.state.get<StoredGroupRecordIndex>(`${RECORD_PREFIX}${start}`);
    if (
      firstIndex?.transitionStartSeq !== undefined &&
      firstIndex.transitionStartSeq !== start
    ) {
      throw new HttpError(
        409,
        "group_cursor_invalid",
        "requested cursor falls inside a transition bundle",
        { bundleStartSeq: firstIndex.transitionStartSeq }
      );
    }
    let upper = Math.min(meta.headSeq, start + input.limit - 1);
    const boundaryIndex = await this.state.get<StoredGroupRecordIndex>(`${RECORD_PREFIX}${upper}`);
    if (boundaryIndex?.transitionEndSeq !== undefined) {
      upper = Math.min(meta.headSeq, Math.max(upper, boundaryIndex.transitionEndSeq));
    }
    for (let seq = start; seq <= upper; seq += 1) {
      const index = await this.state.get<StoredGroupRecordIndex>(`${RECORD_PREFIX}${seq}`);
      if (!index) {
        throw new HttpError(500, "storage_integrity_error", `group record index is missing at seq ${seq}`);
      }
      this.validateStoredRecordIndex(index, seq);
      if (index.inlineRecord) {
        this.validateMaterializedRecord(index.inlineRecord, index, seq);
        records.push(index.inlineRecord);
        continue;
      }
      if (!index.payloadRef) {
        throw new HttpError(500, "storage_integrity_error", `group record payload reference is missing at seq ${seq}`);
      }
      let record: GroupOutboxRecord | null;
      try {
        record = await this.spillStore.getJson<GroupOutboxRecord>(index.payloadRef);
      } catch {
        throw new HttpError(500, "storage_integrity_error", `group spill payload is invalid at seq ${seq}`);
      }
      if (!record) {
        throw new HttpError(500, "storage_integrity_error", `group spill payload is missing at seq ${seq}`);
      }
      this.validateMaterializedRecord(record, index, seq);
      records.push(record);
    }

    return {
      toSeq: records.length > 0
        ? records[records.length - 1].seq
        : Math.max(historyFloorSeq, Math.min(meta.headSeq, start - 1)),
      historyFloorSeq,
      records
    };
  }

  async getHead(): Promise<GetGroupOutboxHeadResult> {
    const meta = await this.getMeta();
    return {
      headSeq: meta.headSeq,
      currentRosterVersion: meta.currentRosterVersion,
      lastCommitMessageId: meta.lastCommitMessageId,
      cryptoEpoch: meta.cryptoEpoch,
      cryptoHeadHash: meta.cryptoHeadHash,
      groupAppCount: meta.groupAppCount ?? 0,
      applicationIndex: meta.applicationIndex ?? 0,
      activeLeafCount: Object.keys(meta.leafLastUpdateIndex ?? {}).length,
      leafLastUpdateIndex: meta.leafLastUpdateIndex ?? {}
    };
  }

  private validateStoredRecordIndex(index: StoredGroupRecordIndex, seq: number): void {
    if (index.seq !== seq || index.groupId !== this.groupId || !index.messageId) {
      throw new HttpError(500, "storage_integrity_error", `group record index does not match seq ${seq}`);
    }
  }

  private validateMaterializedRecord(record: GroupOutboxRecord, index: StoredGroupRecordIndex, seq: number): void {
    if (
      record.seq !== seq ||
      record.seq !== index.seq ||
      record.messageId !== index.messageId ||
      record.groupId !== this.groupId ||
      record.groupId !== index.groupId
    ) {
      throw new HttpError(500, "storage_integrity_error", `group record payload does not match index at seq ${seq}`);
    }
  }

  async createInvite(
    input: CreateGroupInviteRequest,
    inviteUrl: string,
    token: string,
    now: number
  ): Promise<CreateGroupInviteResult> {
    if (input.groupId !== this.groupId || input.document.groupId !== this.groupId) {
      throw new HttpError(400, "invalid_input", "group_id does not match group invite route");
    }
    await this.rejectIfSealed();
    this.validateInviteDocument(input.document, now);
    const key = `${INVITE_PREFIX}${input.document.inviteId}`;
    const existing = await this.state.get<StoredGroupInvite>(key);
    if (existing) {
      const { signature: _storedToken, ...storedDocument } = existing.document;
      const { signature: _requestedSignature, ...requestedDocument } = input.document;
      if (canonicalJson(storedDocument) !== canonicalJson(requestedDocument) ||
          existing.maxUses !== (input.maxUses ?? input.document.maxUses)) {
        throw new HttpError(409, "conflict", "invite id already exists with a different document");
      }
      return { inviteUrl: existing.inviteUrl, invite: existing.document };
    }
    const stored: StoredGroupInvite = {
      inviteUrl,
      token,
      document: { ...input.document, signature: token },
      uses: 0,
      maxUses: input.maxUses ?? input.document.maxUses
    };
    const revision = (await this.state.get<number>(INVITE_REVISION_KEY)) ?? 0;
    await this.state.putEntries({ [key]: stored, [INVITE_REVISION_KEY]: revision + 1 });
    await this.scheduleNextAlarm(now);
    this.publish({ event: "group_invites_changed", groupId: this.groupId, revision: revision + 1 });
    return { inviteUrl, invite: stored.document };
  }

  async listInvites(now: number): Promise<ListGroupInvitesResult> {
    await this.processAlarm(now);
    const rows = await this.state.list<StoredGroupInvite>({ prefix: INVITE_PREFIX });
    const invites = Array.from(rows.values())
      .filter((stored) => stored.document.groupId === this.groupId)
      .map((stored) => ({
        inviteUrl: stored.inviteUrl,
        invite: stored.document,
        status: stored.revokedAt !== undefined
          ? "revoked" as const
          : stored.document.expiresAt <= now
            ? "expired" as const
            : stored.maxUses !== undefined && stored.uses >= stored.maxUses
              ? "exhausted" as const
              : "active" as const,
        uses: stored.uses,
        maxUses: stored.maxUses,
        revokedAt: stored.revokedAt,
        expiredAt: stored.expiredAt,
        exhaustedAt: stored.exhaustedAt
      }))
      .sort((left, right) => right.invite.createdAt - left.invite.createdAt);
    return { revision: (await this.state.get<number>(INVITE_REVISION_KEY)) ?? 0, invites };
  }

  async fetchInvite(payload: GroupInviteTokenPayload, now: number): Promise<FetchGroupInviteResult> {
    if (payload.groupId !== this.groupId) {
      throw new HttpError(400, "invalid_input", "invite token group does not match route");
    }
    const stored = await this.loadUsableInvite(payload.inviteId, now);
    if (stored.token !== stored.document.signature) {
      throw new HttpError(403, "invalid_capability", "invite signature is invalid");
    }
    return { invite: stored.document };
  }

  async fetchInviteById(inviteId: string, now: number): Promise<FetchGroupInviteResult> {
    const stored = await this.loadUsableInvite(inviteId, now);
    if (stored.token !== stored.document.signature) {
      throw new HttpError(403, "invalid_capability", "invite signature is invalid");
    }
    return { invite: stored.document };
  }

  async revokeInvite(input: RevokeGroupInviteRequest, now: number): Promise<RevokeGroupInviteResult> {
    if (input.groupId !== this.groupId) {
      throw new HttpError(400, "invalid_input", "group_id does not match group invite route");
    }
    await this.rejectIfSealed();
    const key = `${INVITE_PREFIX}${input.inviteId}`;
    const stored = await this.state.get<StoredGroupInvite>(key);
    if (!stored) {
      throw new HttpError(404, "not_found", "invite not found");
    }
    if (stored.revokedAt !== undefined) {
      return { accepted: true, inviteId: input.inviteId };
    }
    const revision = (await this.state.get<number>(INVITE_REVISION_KEY)) ?? 0;
    await this.state.putEntries({
      [key]: { ...stored, revokedAt: now },
      [INVITE_REVISION_KEY]: revision + 1
    });
    this.publish({ event: "group_invites_changed", groupId: this.groupId, revision: revision + 1 });
    await this.scheduleNextAlarm(now);
    return { accepted: true, inviteId: input.inviteId };
  }

  async submitJoinRequest(
    input: SubmitGroupJoinRequest,
    payload: GroupInviteTokenPayload,
    now: number
  ): Promise<SubmitGroupJoinResult> {
    if (payload.groupId !== this.groupId || input.request.groupId !== this.groupId) {
      throw new HttpError(400, "invalid_input", "join request group does not match route");
    }
    await this.rejectIfSealed();
    if (payload.inviteId !== input.request.inviteId) {
      throw new HttpError(403, "invalid_capability", "join request invite does not match bearer token");
    }
    const invite = await this.loadUsableInvite(payload.inviteId, now);
    if (invite.document.joinPolicy === "closed") {
      throw new HttpError(403, "invalid_invite", "invite does not allow link join requests");
    }
    this.validateJoinRequest(input.request, now);
    const idempotencyKey = `${JOIN_REQUEST_IDEMPOTENCY_PREFIX}${encodeURIComponent(payload.inviteId)}:${encodeURIComponent(input.request.joinerUserId)}:${encodeURIComponent(input.request.joinerDeviceId)}`;
    const existingRequestId = await this.state.get<string>(idempotencyKey);
    if (existingRequestId) {
      const existingByIdentity = await this.state.get<StoredGroupJoinRequest>(`${JOIN_REQUEST_PREFIX}${existingRequestId}`);
      if (existingByIdentity) {
        return {
          accepted: true,
          request: existingByIdentity.request,
          autoApprove: existingByIdentity.request.autoApprove
        };
      }
    }
    const key = `${JOIN_REQUEST_PREFIX}${input.request.requestId}`;
    const existing = await this.state.get<StoredGroupJoinRequest>(key);
    if (existing) {
      if (JSON.stringify(existing.request) !== JSON.stringify(input.request)) {
        throw new HttpError(409, "conflict", "join request id already exists with different content");
      }
      return {
        accepted: true,
        request: existing.request,
        autoApprove: existing.request.autoApprove
      };
    }
    const request: GroupJoinRequest = {
      ...input.request,
      status: invite.document.joinPolicy === "open_by_invite" ? "waiting_for_group_commit" : "pending_approval",
      autoApprove: invite.document.joinPolicy === "open_by_invite"
    };
    const inviteRevision = (await this.state.get<number>(INVITE_REVISION_KEY)) ?? 0;
    const nextUses = invite.uses + 1;
    const exhaustedAt = invite.maxUses !== undefined && nextUses >= invite.maxUses ? now : invite.exhaustedAt;
    await this.state.putEntries({
      [key]: { request } satisfies StoredGroupJoinRequest,
      [idempotencyKey]: request.requestId,
      [`${INVITE_PREFIX}${payload.inviteId}`]: {
        ...invite,
        uses: nextUses,
        exhaustedAt
      } satisfies StoredGroupInvite,
      [INVITE_REVISION_KEY]: inviteRevision + 1
    });
    this.publish({ event: "group_invites_changed", groupId: this.groupId, revision: inviteRevision + 1 });
    this.publish(
      request.status === "pending_approval"
        ? { event: "group_join_request_available", groupId: this.groupId, requestId: request.requestId }
        : { event: "group_auto_join_available", groupId: this.groupId, requestId: request.requestId }
    );
    await this.scheduleNextAlarm(now);
    return { accepted: true, request, autoApprove: request.autoApprove };
  }

  async listJoinRequests(): Promise<ListGroupJoinRequestsResult> {
    const result = await this.state.list<StoredGroupJoinRequest>({ prefix: JOIN_REQUEST_PREFIX });
    const requests = Array.from(result.values())
      .map((stored) => stored.request)
      .filter((request) =>
        request.groupId === this.groupId &&
        ["pending", "pending_approval", "waiting_for_group_commit", "transition_in_progress"].includes(request.status)
      )
      .sort((a, b) => a.requestedAt - b.requestedAt || a.requestId.localeCompare(b.requestId));
    return { requests };
  }

  async getJoinRequestStatus(
    requestId: string,
    requestCapability: string
  ): Promise<GetGroupJoinRequestStatusResult> {
    const stored = await this.state.get<StoredGroupJoinRequest>(`${JOIN_REQUEST_PREFIX}${requestId}`);
    if (!stored || stored.request.groupId !== this.groupId) {
      throw new HttpError(404, "not_found", "join request not found");
    }
    if (stored.request.requestCapability !== requestCapability) {
      throw new HttpError(403, "invalid_capability", "join request capability does not match bearer token");
    }
    if (!["approved", "welcome_available", "joined"].includes(stored.request.status)) {
      return { request: stored.request };
    }
    return {
      request: stored.request,
      welcomePickup: stored.welcomePickup,
      manifest: stored.manifest,
      startCursor: stored.startCursor
    };
  }

  async claimJoinRequest(input: ClaimGroupJoinRequest, now: number): Promise<ClaimGroupJoinResult> {
    if (input.groupId !== this.groupId) {
      throw new HttpError(400, "invalid_input", "group_id does not match group join route");
    }
    await this.rejectIfSealed();
    const key = `${JOIN_REQUEST_PREFIX}${input.requestId}`;
    const stored = await this.state.get<StoredGroupJoinRequest>(key);
    if (!stored || stored.request.groupId !== this.groupId) {
      throw new HttpError(404, "not_found", "join request not found");
    }
    if (!["waiting_for_group_commit", "transition_in_progress"].includes(stored.request.status)) {
      throw new HttpError(409, "group_join_terminal", "join request is already terminal");
    }
    if (stored.lease && stored.lease.expiresAt > now) {
      if (
        stored.lease.userId === input.capability.userId &&
        stored.lease.deviceId === input.capability.deviceId
      ) {
        return {
          accepted: true,
          request: stored.request,
          leaseToken: stored.lease.token,
          leaseExpiresAt: stored.lease.expiresAt
        };
      }
      throw new HttpError(409, "group_join_claimed", "join request is claimed by another administrator device");
    }
    const lease = {
      token: crypto.randomUUID(),
      userId: input.capability.userId,
      deviceId: input.capability.deviceId,
      expiresAt: now + JOIN_LEASE_MS
    };
    const request: GroupJoinRequest = { ...stored.request, status: "transition_in_progress" };
    await this.state.put(key, { ...stored, request, lease });
    await this.state.setAlarm(lease.expiresAt);
    return {
      accepted: true,
      request,
      leaseToken: lease.token,
      leaseExpiresAt: lease.expiresAt
    };
  }

  async completeJoinRequest(
    input: CompleteGroupJoinRequest,
    now: number
  ): Promise<CompleteGroupJoinResult> {
    if (input.groupId !== this.groupId) {
      throw new HttpError(400, "invalid_input", "group_id does not match group join route");
    }
    await this.rejectIfSealed();
    const key = `${JOIN_REQUEST_PREFIX}${input.requestId}`;
    const stored = await this.state.get<StoredGroupJoinRequest>(key);
    if (!stored || stored.request.groupId !== this.groupId) {
      throw new HttpError(404, "not_found", "join request not found");
    }
    const completionFingerprint = canonicalJson({
      transitionId: input.transitionId,
      leaseToken: input.leaseToken,
      welcomePickup: input.welcomePickup,
      manifest: input.manifest,
      startCursor: input.startCursor
    });
    if (["welcome_available", "joined"].includes(stored.request.status)) {
      if (stored.transitionId === input.transitionId && stored.completionFingerprint === completionFingerprint) {
        return { accepted: true, request: stored.request };
      }
      throw new HttpError(409, "group_transition_conflict", "join completion differs from the stored completion");
    }
    const lease = stored.lease;
    const committed = stored.committedBinding;
    if (
      stored.request.status !== "transition_in_progress" ||
      !lease || !committed ||
      committed.transitionId !== input.transitionId ||
      committed.leaseToken !== input.leaseToken ||
      lease.token !== input.leaseToken ||
      lease.userId !== input.capability.userId ||
      lease.deviceId !== input.capability.deviceId
    ) {
      throw new HttpError(409, "group_join_lease_invalid", "join request lease is missing, expired, or owned by another device");
    }
    const authorization = await this.state.get<GroupAuthorizationState>(GROUP_AUTHORIZATION_KEY);
    const transition = await this.state.get<StoredGroupTransition>(`${TRANSITION_PREFIX}${input.transitionId}`);
    const manifestHash = await groupManifestSha256(input.manifest);
    const authorizationHash = authorization ? await groupManifestSha256(authorization.manifest) : "";
    const member = input.manifest.members.find((item) => item.userId === stored.request.joinerUserId && item.status === "active");
    const device = (input.manifest.memberDevices ?? []).find((item) =>
      item.userId === stored.request.joinerUserId && item.deviceId === stored.request.joinerDeviceId && item.status === "active"
    );
    if (
      !authorization ||
      !transition || transition.kind === "epoch" || transition.requestBinding?.type !== "join" ||
      transition.requestBinding.requestId !== input.requestId ||
      transition.requestBinding.leaseToken !== input.leaseToken ||
      transition.operation.type !== "approve_join" ||
      authorization.lastTransitionId !== input.transitionId ||
      authorizationHash !== manifestHash || !member || !device ||
      input.welcomePickup.groupId !== this.groupId ||
      input.welcomePickup.deviceId !== stored.request.joinerDeviceId ||
      input.welcomePickup.requestId !== input.requestId ||
      input.startCursor.groupId !== this.groupId ||
      input.startCursor.lastFetchedSeq !== transition.result.lastSeq ||
      input.startCursor.lastFetchedSeq !== input.welcomePickup.startSeq ||
      input.welcomePickup.rosterVersion !== transition.result.rosterVersion ||
      (input.welcomePickup.lastCommitMessageId ?? "") !== (transition.result.lastCommitMessageId ?? "")
    ) {
      throw new HttpError(409, "group_transition_invalid", "join completion does not match the committed group transition");
    }
    const request: GroupJoinRequest = { ...stored.request, status: "welcome_available" };
    await this.state.put(key, {
      ...stored,
      request,
      welcomePickup: input.welcomePickup,
      manifest: input.manifest,
      startCursor: input.startCursor,
      transitionId: input.transitionId,
      lease: undefined,
      completionFingerprint
    } satisfies StoredGroupJoinRequest);
    return { accepted: true, request };
  }

  async markWelcomeClaimed(requestId: string, deviceId: string, capability: string): Promise<void> {
    const key = `${JOIN_REQUEST_PREFIX}${requestId}`;
    const stored = await this.state.get<StoredGroupJoinRequest>(key);
    if (!stored || stored.request.status !== "welcome_available" ||
        stored.request.joinerDeviceId !== deviceId ||
        stored.welcomePickup?.requestId !== requestId || stored.welcomePickup.capability !== capability) {
      throw new HttpError(409, "group_transition_invalid", "welcome claim does not match the completed join request");
    }
    await this.state.put(key, { ...stored, request: { ...stored.request, status: "joined" } } satisfies StoredGroupJoinRequest);
  }

  async authorizeWelcomeUpload(requestId: string, deviceId: string, capability: string): Promise<void> {
    const stored = await this.state.get<StoredGroupJoinRequest>(`${JOIN_REQUEST_PREFIX}${requestId}`);
    if (!stored || stored.request.status !== "transition_in_progress" || !stored.committedBinding ||
        stored.request.joinerDeviceId !== deviceId || !capability) {
      throw new HttpError(409, "group_transition_invalid", "welcome upload is not bound to a committed join transition");
    }
  }

  async submitLeaveRequest(input: SubmitGroupLeaveRequest, now: number): Promise<SubmitGroupLeaveResult> {
    if (input.groupId !== this.groupId || input.request.groupId !== this.groupId ||
        input.request.leaverUserId !== input.capability.userId ||
        input.request.leaverDeviceId !== input.capability.deviceId) {
      throw new HttpError(400, "invalid_input", "leave request does not match its route or capability");
    }
    await this.rejectIfSealed();
    if (!input.request.requestId || !input.request.requestCapability || !input.request.signature ||
        input.request.requestedAt > now + 5 * 60 * 1000) {
      throw new HttpError(400, "invalid_input", "leave request is malformed");
    }
    const authorization = await this.state.get<GroupAuthorizationState>(GROUP_AUTHORIZATION_KEY);
    if (authorization?.manifest.ownerUserId === input.request.leaverUserId) {
      throw new HttpError(409, "group_transition_invalid", "group owner must transfer ownership before leaving");
    }
    const idempotencyKey = `${LEAVE_REQUEST_IDEMPOTENCY_PREFIX}${encodeURIComponent(input.request.leaverUserId)}:${encodeURIComponent(input.request.leaverDeviceId)}`;
    const existingId = await this.state.get<string>(idempotencyKey);
    if (existingId) {
      const existing = await this.state.get<StoredGroupLeaveRequest>(`${LEAVE_REQUEST_PREFIX}${existingId}`);
      if (existing) return { accepted: true, request: existing.request };
    }
    const key = `${LEAVE_REQUEST_PREFIX}${input.request.requestId}`;
    const existing = await this.state.get<StoredGroupLeaveRequest>(key);
    if (existing) {
      if (canonicalJson(existing.request) !== canonicalJson({ ...input.request, status: existing.request.status })) {
        throw new HttpError(409, "group_transition_conflict", "leave request id already exists with different content");
      }
      return { accepted: true, request: existing.request };
    }
    const request: GroupLeaveRequest = { ...input.request, status: "waiting_for_group_commit" };
    await this.state.putEntries({ [key]: { request } satisfies StoredGroupLeaveRequest, [idempotencyKey]: request.requestId });
    this.publish({ event: "group_leave_request_available", groupId: this.groupId, requestId: request.requestId });
    return { accepted: true, request };
  }

  async listLeaveRequests(): Promise<ListGroupLeaveRequestsResult> {
    const rows = await this.state.list<StoredGroupLeaveRequest>({ prefix: LEAVE_REQUEST_PREFIX });
    return {
      requests: Array.from(rows.values()).map((stored) => stored.request)
        .filter((request) => request.groupId === this.groupId && ["waiting_for_group_commit", "transition_in_progress"].includes(request.status))
        .sort((a, b) => a.requestedAt - b.requestedAt || a.requestId.localeCompare(b.requestId))
    };
  }

  async claimLeaveRequest(input: ClaimGroupLeaveRequest, now: number): Promise<ClaimGroupLeaveResult> {
    if (input.groupId !== this.groupId) throw new HttpError(400, "invalid_input", "leave request group does not match route");
    await this.rejectIfSealed();
    const key = `${LEAVE_REQUEST_PREFIX}${input.requestId}`;
    const stored = await this.state.get<StoredGroupLeaveRequest>(key);
    if (!stored) throw new HttpError(404, "not_found", "leave request not found");
    if (!["waiting_for_group_commit", "transition_in_progress"].includes(stored.request.status)) {
      throw new HttpError(409, "group_leave_terminal", "leave request is already terminal");
    }
    if (stored.lease && stored.lease.expiresAt > now) {
      if (stored.lease.userId === input.capability.userId && stored.lease.deviceId === input.capability.deviceId) {
        return { accepted: true, request: stored.request, leaseToken: stored.lease.token, leaseExpiresAt: stored.lease.expiresAt };
      }
      throw new HttpError(409, "group_leave_claimed", "leave request is claimed by another administrator device");
    }
    const lease = { token: crypto.randomUUID(), userId: input.capability.userId, deviceId: input.capability.deviceId, expiresAt: now + JOIN_LEASE_MS };
    const request: GroupLeaveRequest = { ...stored.request, status: "transition_in_progress" };
    await this.state.put(key, { ...stored, request, lease } satisfies StoredGroupLeaveRequest);
    await this.scheduleNextAlarm(now);
    return { accepted: true, request, leaseToken: lease.token, leaseExpiresAt: lease.expiresAt };
  }

  async decideJoinRequest(input: DecideGroupJoinRequest): Promise<DecideGroupJoinResult> {
    if (input.groupId !== this.groupId) {
      throw new HttpError(400, "invalid_input", "group_id does not match group join route");
    }
    await this.rejectIfSealed();
    const key = `${JOIN_REQUEST_PREFIX}${input.requestId}`;
    const stored = await this.state.get<StoredGroupJoinRequest>(key);
    if (!stored || stored.request.groupId !== this.groupId) {
      throw new HttpError(404, "not_found", "join request not found");
    }
    if (!["pending", "pending_approval"].includes(stored.request.status)) {
      throw new HttpError(409, "conflict", "join request is already terminal");
    }
    if (input.decision === "approve") {
      const request: GroupJoinRequest = { ...stored.request, status: "waiting_for_group_commit" };
      await this.state.put(key, { ...stored, request });
      this.publish({ event: "group_auto_join_available", groupId: this.groupId, requestId: request.requestId });
      return { accepted: true, request };
    }
    if (input.decision === "reject" && (input.welcomePickup || input.manifest || input.startCursor)) {
      throw new HttpError(400, "invalid_input", "rejected join request must not include welcome pickup, manifest, or start cursor");
    }
    const request: GroupJoinRequest = {
      ...stored.request,
      status: "rejected"
    };
    const updated: StoredGroupJoinRequest = {
      request,
      welcomePickup: undefined,
      manifest: undefined,
      startCursor: undefined,
      reason: input.decision === "reject" ? input.reason : undefined
    };
    await this.state.put(key, updated);
    return { accepted: true, request };
  }

  async processAlarm(now: number): Promise<void> {
    const entries: Record<string, unknown> = {};
    const deleteKeys: string[] = [];
    const meta = await this.getMeta();
    const records = await this.state.list<StoredGroupRecordIndex>({ prefix: RECORD_PREFIX });
    const expiredRecords = Array.from(records.entries())
      .filter(([, record]) => record.expiresAt !== undefined && record.expiresAt <= now)
      .sort((left, right) => left[1].seq - right[1].seq)
      .slice(0, CLEANUP_BATCH_SIZE);
    for (const [key, record] of expiredRecords) {
      if (record.payloadRef) await this.spillStore.delete(record.payloadRef);
      deleteKeys.push(key, `${IDEMPOTENCY_PREFIX}${record.messageId}`);
      if (record.transitionId && record.transitionEndSeq === record.seq) {
        deleteKeys.push(`${TRANSITION_PREFIX}${record.transitionId}`);
      }
    }
    if (expiredRecords.length > 0) {
      entries[META_KEY] = {
        ...meta,
        historyFloorSeq: Math.max(
          meta.historyFloorSeq ?? 0,
          ...expiredRecords.map(([, record]) => record.seq)
        )
      } satisfies GroupOutboxMeta;
    }
    let inviteChanged = false;
    const invites = await this.state.list<StoredGroupInvite>({ prefix: INVITE_PREFIX });
    for (const [key, stored] of invites) {
      if (stored.revokedAt === undefined && stored.expiredAt === undefined && stored.document.expiresAt <= now) {
        entries[key] = { ...stored, expiredAt: now } satisfies StoredGroupInvite;
        inviteChanged = true;
      } else if (stored.revokedAt === undefined && stored.exhaustedAt === undefined && stored.maxUses !== undefined && stored.uses >= stored.maxUses) {
        entries[key] = { ...stored, exhaustedAt: now } satisfies StoredGroupInvite;
        inviteChanged = true;
      }
    }
    const joins = await this.state.list<StoredGroupJoinRequest>({ prefix: JOIN_REQUEST_PREFIX });
    for (const [key, stored] of joins) {
      if (stored.request.status === "transition_in_progress" && stored.lease && stored.lease.expiresAt <= now && !stored.committedBinding) {
        entries[key] = { ...stored, request: { ...stored.request, status: "waiting_for_group_commit" }, lease: undefined } satisfies StoredGroupJoinRequest;
        this.publish({ event: "group_auto_join_available", groupId: this.groupId, requestId: stored.request.requestId });
      }
    }
    const leaves = await this.state.list<StoredGroupLeaveRequest>({ prefix: LEAVE_REQUEST_PREFIX });
    for (const [key, stored] of leaves) {
      if (stored.request.status === "transition_in_progress" && stored.lease && stored.lease.expiresAt <= now) {
        entries[key] = { ...stored, request: { ...stored.request, status: "waiting_for_group_commit" }, lease: undefined } satisfies StoredGroupLeaveRequest;
        this.publish({ event: "group_leave_request_available", groupId: this.groupId, requestId: stored.request.requestId });
      }
    }
    if (inviteChanged) {
      const revision = (await this.state.get<number>(INVITE_REVISION_KEY)) ?? 0;
      entries[INVITE_REVISION_KEY] = revision + 1;
      this.publish({ event: "group_invites_changed", groupId: this.groupId, revision: revision + 1 });
    }
    if (Object.keys(entries).length > 0 || deleteKeys.length > 0) {
      await this.state.mutateEntries(entries, deleteKeys);
    }
    if (expiredRecords.length === CLEANUP_BATCH_SIZE) {
      await this.state.setAlarm(now + 1);
      return;
    }
    await this.scheduleNextAlarm(now);
  }

  private async scheduleNextAlarm(now: number): Promise<void> {
    const deadlines: number[] = [];
    const records = await this.state.list<StoredGroupRecordIndex>({ prefix: RECORD_PREFIX });
    for (const record of records.values()) {
      if (record.expiresAt !== undefined && record.expiresAt > now) deadlines.push(record.expiresAt);
    }
    const invites = await this.state.list<StoredGroupInvite>({ prefix: INVITE_PREFIX });
    for (const stored of invites.values()) {
      if (stored.revokedAt === undefined && stored.expiredAt === undefined && stored.document.expiresAt > now) deadlines.push(stored.document.expiresAt);
    }
    const joins = await this.state.list<StoredGroupJoinRequest>({ prefix: JOIN_REQUEST_PREFIX });
    for (const stored of joins.values()) if (stored.lease && !stored.committedBinding && stored.lease.expiresAt > now) deadlines.push(stored.lease.expiresAt);
    const leaves = await this.state.list<StoredGroupLeaveRequest>({ prefix: LEAVE_REQUEST_PREFIX });
    for (const stored of leaves.values()) if (stored.lease && stored.lease.expiresAt > now) deadlines.push(stored.lease.expiresAt);
    if (deadlines.length > 0) await this.state.setAlarm(Math.min(...deadlines));
  }

  private async getMeta(): Promise<GroupOutboxMeta> {
    return (await this.state.get<GroupOutboxMeta>(META_KEY)) ?? this.defaults;
  }

  /**
   * Idempotent seal of the group outbox. The very first caller flips
   * `sealed = true` and records `sealedAt = now`; subsequent callers are
   * rejected with HTTP 409 `already_sealed` regardless of their
   * capability (PROTOCOL_GROUP_CN.md §10.4 — seals are irreversible).
   *
   * Callers must already have authenticated owner-signed
   * `seal_group` capability at the transport layer; this method only
   * enforces the storage-side invariant.
   */
  async sealOutbox(now: number): Promise<{ sealed: boolean; sealedAt: number; wasAlreadySealed: boolean }> {
    const meta = await this.getMeta();
    if (meta.sealed === true) {
      throw new HttpError(409, "already_sealed", "group outbox is already sealed");
    }
    const nextMeta: GroupOutboxMeta = { ...meta, sealed: true, sealedAt: now };
    await this.state.put(META_KEY, nextMeta);
    return { sealed: true, sealedAt: now, wasAlreadySealed: false };
  }

  async getSealStatus(): Promise<{ sealed: boolean; sealedAt: number }> {
    const meta = await this.getMeta();
    return { sealed: meta.sealed === true, sealedAt: meta.sealedAt ?? 0 };
  }

  /**
   * Reject any append-type flow on a sealed outbox with the canonical
   * `403 group_sealed` response. Reads (fetch / head / subscribe-replay)
   * are explicitly allowed to continue, so only write paths call this.
   */
  private async rejectIfSealed(): Promise<void> {
    const meta = await this.getMeta();
    if (meta.sealed === true) {
      throw new HttpError(403, "group_sealed", "group outbox is sealed and cannot accept new writes");
    }
  }

  private validateAppendRequest(input: AppendGroupEnvelopeRequest): void {
    if (input.groupId !== this.groupId || input.envelope.groupId !== this.groupId) {
      throw new HttpError(400, "invalid_input", "group_id does not match group outbox route");
    }
    this.validateEnvelope(input.envelope);
  }

  private async loadUsableInvite(inviteId: string, now: number): Promise<StoredGroupInvite> {
    await this.processAlarm(now);
    const stored = await this.state.get<StoredGroupInvite>(`${INVITE_PREFIX}${inviteId}`);
    if (!stored || stored.document.groupId !== this.groupId) {
      throw new HttpError(404, "not_found", "invite not found");
    }
    if (stored.revokedAt !== undefined) {
      throw new HttpError(403, "invalid_invite", "invite is revoked");
    }
    if (stored.expiredAt !== undefined || stored.document.expiresAt <= now) {
      throw new HttpError(403, "capability_expired", "invite is expired");
    }
    if (stored.exhaustedAt !== undefined || (stored.maxUses !== undefined && stored.uses >= stored.maxUses)) {
      throw new HttpError(403, "invalid_invite", "invite max uses exceeded");
    }
    return stored;
  }

  private validateInviteDocument(document: GroupInviteDocument, now: number): void {
    if (
      !document.groupId ||
      !document.inviteId ||
      !document.title ||
      !document.inviterUserId ||
      !document.inviterDeviceId ||
      !document.ownerUserId ||
      !document.joinRequestEndpoint ||
      !document.signature
    ) {
      throw new HttpError(400, "invalid_input", "invite document is missing required fields");
    }
    if (document.expiresAt <= now) {
      throw new HttpError(400, "invalid_input", "invite must not already be expired");
    }
  }

  private validateJoinRequest(request: GroupJoinRequest, now: number): void {
    if (
      !request.requestId ||
      !request.groupId ||
      !request.inviteId ||
      !request.joinerUserId ||
      !request.joinerDeviceId ||
      !request.joinerContactShareUrl ||
      !request.requestCapability ||
      !request.signature
    ) {
      throw new HttpError(400, "invalid_input", "join request is missing required fields");
    }
    if (request.requestedAt > now + 5 * 60 * 1000) {
      throw new HttpError(400, "invalid_input", "join request timestamp is too far in the future");
    }
  }

  private validateEnvelope(envelope: GroupEnvelope): void {
    if (
      !envelope.messageId ||
      !envelope.groupId ||
      !envelope.conversationId ||
      !envelope.senderUserId ||
      !envelope.senderDeviceId
    ) {
      throw new HttpError(400, "invalid_input", "group envelope is missing required fields");
    }
    if (!envelope.senderProof?.type || !envelope.senderProof.value) {
      throw new HttpError(400, "invalid_input", "group envelope sender proof is required");
    }
    const hasInline = Boolean(envelope.inlineCiphertext);
    const hasStorageRefs = (envelope.storageRefs?.length ?? 0) > 0;
    if (!hasInline && !hasStorageRefs) {
      throw new HttpError(400, "invalid_input", "group envelope must include inline_ciphertext or storage_refs");
    }
  }

  private publish(event: Record<string, unknown>): void {
    const payload = JSON.stringify(event);
    for (const session of this.sessions) {
      session.send(payload);
    }
  }
}

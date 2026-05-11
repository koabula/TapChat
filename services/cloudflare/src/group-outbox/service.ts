import { HttpError } from "../auth/capability";
import type {
  AppendGroupEnvelopeRequest,
  AppendGroupEnvelopeResult,
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
  GroupCursor,
  GroupManifest,
  GroupOutboxRecord,
  ListGroupJoinRequestsResult,
  RevokeGroupInviteRequest,
  RevokeGroupInviteResult,
  SubmitGroupJoinRequest,
  SubmitGroupJoinResult,
  WelcomePickupDescriptor
} from "../types/contracts";
import type { DurableObjectStorageLike, JsonBlobStore, SessionSink } from "../types/runtime";

interface GroupOutboxMeta {
  headSeq: number;
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
}

const META_KEY = "meta";
const IDEMPOTENCY_PREFIX = "idempotency:";
const RECORD_PREFIX = "record:";
const INVITE_PREFIX = "invite:";
const JOIN_REQUEST_PREFIX = "join-request:";

interface StoredGroupInvite {
  inviteUrl: string;
  token: string;
  document: GroupInviteDocument;
  uses: number;
  maxUses?: number;
  revokedAt?: number;
}

interface StoredGroupJoinRequest {
  request: GroupJoinRequest;
  welcomePickup?: WelcomePickupDescriptor;
  manifest?: GroupManifest;
  startCursor?: GroupCursor;
  reason?: string;
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
    sessions: SessionSink[]
  ) {
    this.groupId = groupId;
    this.state = state;
    this.spillStore = spillStore;
    this.defaults = defaults;
    this.sessions = sessions;
  }

  async appendEnvelope(input: AppendGroupEnvelopeRequest, now: number): Promise<AppendGroupEnvelopeResult> {
    this.validateAppendRequest(input);
    await this.rejectIfSealed();

    const existingSeq = await this.state.get<number>(`${IDEMPOTENCY_PREFIX}${input.envelope.messageId}`);
    if (existingSeq !== undefined) {
      return { accepted: true, seq: existingSeq };
    }

    const meta = await this.getMeta();
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

    if (new TextEncoder().encode(serialized).byteLength <= meta.maxInlineBytes && input.envelope.inlineCiphertext) {
      await this.state.put<StoredGroupRecordIndex>(storageKey, {
        seq,
        groupId: record.groupId,
        messageId: record.messageId,
        receivedAt: record.receivedAt,
        expiresAt,
        state: record.state,
        inlineRecord: record
      });
    } else {
      const payloadRef = `group-outbox-payload/${this.groupId}/${seq}.json`;
      await this.spillStore.putJson(payloadRef, record);
      await this.state.put<StoredGroupRecordIndex>(storageKey, {
        seq,
        groupId: record.groupId,
        messageId: record.messageId,
        receivedAt: record.receivedAt,
        expiresAt,
        state: record.state,
        payloadRef
      });
    }

    await this.state.put(`${IDEMPOTENCY_PREFIX}${record.messageId}`, seq);
    await this.state.put(META_KEY, { ...meta, headSeq: seq });
    await this.state.setAlarm(expiresAt);

    this.publish({ event: "group_head_updated", groupId: this.groupId, seq });
    this.publish({ event: "group_outbox_record_available", groupId: this.groupId, seq, record });

    return { accepted: true, seq };
  }

  async fetchOutbox(input: FetchGroupOutboxRequest): Promise<FetchGroupOutboxResult> {
    if (input.groupId !== this.groupId) {
      throw new HttpError(400, "invalid_input", "group_id does not match group outbox route");
    }
    if (input.limit <= 0) {
      throw new HttpError(400, "invalid_input", "limit must be greater than zero");
    }

    const meta = await this.getMeta();
    const records: GroupOutboxRecord[] = [];
    const upper = Math.min(meta.headSeq, input.fromSeq + input.limit - 1);
    for (let seq = input.fromSeq; seq <= upper; seq += 1) {
      const index = await this.state.get<StoredGroupRecordIndex>(`${RECORD_PREFIX}${seq}`);
      if (!index) {
        continue;
      }
      if (index.inlineRecord) {
        records.push(index.inlineRecord);
        continue;
      }
      if (!index.payloadRef) {
        throw new HttpError(500, "temporary_unavailable", "group record payload reference is missing");
      }
      const record = await this.spillStore.getJson<GroupOutboxRecord>(index.payloadRef);
      if (record) {
        records.push(record);
      }
    }

    return {
      toSeq: records.length > 0 ? records[records.length - 1].seq : meta.headSeq,
      records
    };
  }

  async getHead(): Promise<GetGroupOutboxHeadResult> {
    const meta = await this.getMeta();
    return { headSeq: meta.headSeq };
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
      if (existing.document.signature !== input.document.signature) {
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
    await this.state.put(key, stored);
    await this.state.setAlarm(input.document.expiresAt);
    return { inviteUrl, invite: stored.document };
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

  async revokeInvite(input: RevokeGroupInviteRequest, now: number): Promise<RevokeGroupInviteResult> {
    if (input.groupId !== this.groupId) {
      throw new HttpError(400, "invalid_input", "group_id does not match group invite route");
    }
    const key = `${INVITE_PREFIX}${input.inviteId}`;
    const stored = await this.state.get<StoredGroupInvite>(key);
    if (!stored) {
      throw new HttpError(404, "not_found", "invite not found");
    }
    await this.state.put(key, { ...stored, revokedAt: now });
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
      status: "pending",
      autoApprove: invite.document.joinPolicy === "open_by_invite"
    };
    await this.state.put<StoredGroupJoinRequest>(key, { request });
    await this.state.put<StoredGroupInvite>(`${INVITE_PREFIX}${payload.inviteId}`, {
      ...invite,
      uses: invite.uses + 1
    });
    return { accepted: true, request, autoApprove: request.autoApprove };
  }

  async listJoinRequests(): Promise<ListGroupJoinRequestsResult> {
    const result = await this.state.list<StoredGroupJoinRequest>({ prefix: JOIN_REQUEST_PREFIX });
    const requests = Array.from(result.values())
      .map((stored) => stored.request)
      .filter((request) => request.groupId === this.groupId && request.status === "pending")
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
    if (stored.request.status !== "approved") {
      return { request: stored.request };
    }
    return {
      request: stored.request,
      welcomePickup: stored.welcomePickup,
      manifest: stored.manifest,
      startCursor: stored.startCursor
    };
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
    if (stored.request.status !== "pending") {
      throw new HttpError(409, "conflict", "join request is already terminal");
    }
    if (input.decision === "approve" && (!input.welcomePickup || !input.manifest || !input.startCursor)) {
      throw new HttpError(400, "invalid_input", "approved join request requires welcome pickup, manifest, and start cursor");
    }
    if (input.decision === "reject" && (input.welcomePickup || input.manifest || input.startCursor)) {
      throw new HttpError(400, "invalid_input", "rejected join request must not include welcome pickup, manifest, or start cursor");
    }
    const request: GroupJoinRequest = {
      ...stored.request,
      status: input.decision === "approve" ? "approved" : "rejected"
    };
    const updated: StoredGroupJoinRequest = {
      request,
      welcomePickup: input.decision === "approve" ? input.welcomePickup : undefined,
      manifest: input.decision === "approve" ? input.manifest : undefined,
      startCursor: input.decision === "approve" ? input.startCursor : undefined,
      reason: input.decision === "reject" ? input.reason : undefined
    };
    await this.state.put(key, updated);
    return { accepted: true, request };
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
    const stored = await this.state.get<StoredGroupInvite>(`${INVITE_PREFIX}${inviteId}`);
    if (!stored || stored.document.groupId !== this.groupId) {
      throw new HttpError(404, "not_found", "invite not found");
    }
    if (stored.revokedAt !== undefined) {
      throw new HttpError(403, "invalid_invite", "invite is revoked");
    }
    if (stored.document.expiresAt <= now) {
      throw new HttpError(403, "capability_expired", "invite is expired");
    }
    if (stored.maxUses !== undefined && stored.uses >= stored.maxUses) {
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

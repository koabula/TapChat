import { HttpError, type AppendAuthContext } from "../auth/capability";
import type {
  AckRequest,
  AckResult,
  AllowlistDocument,
  AppendEnvelopeRequest,
  AppendEnvelopeResult,
  FetchMessagesRequest,
  FetchMessagesResult,
  InboxRecord,
  MessageRequestActionResult,
  MessageRequestItem,
  RealtimeEvent
} from "../types/contracts";
import type { DurableObjectStorageLike, JsonBlobStore, SessionSink } from "../types/runtime";

interface InboxMeta {
  headSeq: number;
  ackedSeq: number;
  retentionDays: number;
  maxInlineBytes: number;
  rateLimitPerMinute: number;
  rateLimitPerHour: number;
  messageRequestMaxPerSender?: number;
  messageRequestMaxSenders?: number;
  messageRequestMaxTotalBytes?: number;
  messageRequestTtlSeconds?: number;
  messageRequestRateLimitMinute?: number;
  messageRequestRateLimitHour?: number;
}

interface StoredRecordIndex {
  seq: number;
  messageId: string;
  recipientDeviceId: string;
  receivedAt: number;
  expiresAt?: number;
  state: "available";
  inlineRecord?: InboxRecord;
  payloadRef?: string;
}

interface MessageRequestEntry {
  requestId: string;
  recipientDeviceId: string;
  senderUserId: string;
  senderBundleShareUrl?: string;
  senderBundleHash?: string;
  senderDisplayName?: string;
  firstSeenAt: number;
  lastSeenAt: number;
  messageCount: number;
  lastMessageId: string;
  lastConversationId: string;
  pendingRequests: AppendEnvelopeRequest[];
  byteSize?: number;
  expiresAt?: number;
}

interface MessageRequestQueueMeta {
  version: 1;
  totalBytes: number;
  senderCount: number;
}

interface RateLimitState {
  minuteWindowStart: number;
  minuteCount: number;
  hourWindowStart: number;
  hourCount: number;
}

interface GroupWelcomePickupControlPayload {
  groupId?: string;
  title?: string;
}

const META_KEY = "meta";
const IDEMPOTENCY_PREFIX = "idempotency:";
const APPEND_RESULT_PREFIX = "append-result:";
const RECORD_PREFIX = "record:";
const ALLOWLIST_KEY = "allowlist";
const MESSAGE_REQUEST_PREFIX = "message-request:";
const RATE_LIMIT_PREFIX = "rate-limit:";
const MESSAGE_REQUEST_META_KEY = `${MESSAGE_REQUEST_PREFIX}meta`;
const MESSAGE_REQUEST_RATE_LIMIT_KEY = `${MESSAGE_REQUEST_PREFIX}rate-limit`;
const CLEANUP_BATCH_SIZE = 128;

export class InboxService {
  private readonly deviceId: string;
  private readonly state: DurableObjectStorageLike;
  private readonly spillStore: JsonBlobStore;
  private readonly sessions: SessionSink[];
  private readonly defaults: InboxMeta;

  constructor(
    deviceId: string,
    state: DurableObjectStorageLike,
    spillStore: JsonBlobStore,
    sessions: SessionSink[],
    defaults: InboxMeta
  ) {
    this.deviceId = deviceId;
    this.state = state;
    this.spillStore = spillStore;
    this.sessions = sessions;
    this.defaults = defaults;
  }

  async appendEnvelope(
    input: AppendEnvelopeRequest,
    now: number,
    authContext: AppendAuthContext = { mode: "verified" }
  ): Promise<AppendEnvelopeResult> {
    this.validateAppendRequest(input);

    const existingResult = await this.state.get<AppendEnvelopeResult>(`${APPEND_RESULT_PREFIX}${input.envelope.messageId}`);
    if (existingResult) {
      return existingResult;
    }

    await this.enforceRateLimit(input.envelope.senderUserId, now);

    const allowlist = await this.getAllowlist(now);
    if (allowlist.rejectedSenderUserIds.includes(input.envelope.senderUserId)) {
      const rejected: AppendEnvelopeResult = {
        accepted: true,
        seq: 0,
        deliveredTo: "rejected",
        queuedAsRequest: false
      };
      await this.state.put(`${APPEND_RESULT_PREFIX}${input.envelope.messageId}`, rejected);
      return rejected;
    }

    if (authContext.mode !== "verified") {
      throw new HttpError(426, "upgrade_required", "verified append authorization is required");
    }

    if (allowlist.allowedSenderUserIds.includes(input.envelope.senderUserId)) {
      const delivered = await this.deliverEnvelope(input, now);
      await this.state.put(`${APPEND_RESULT_PREFIX}${input.envelope.messageId}`, delivered);
      return delivered;
    }

    const request = await this.queueMessageRequestWithLimit(input, now);
    await this.state.put(`${APPEND_RESULT_PREFIX}${input.envelope.messageId}`, request);
    return request;
  }

  async fetchMessages(input: FetchMessagesRequest): Promise<FetchMessagesResult> {
    if (input.deviceId !== this.deviceId) {
      throw new HttpError(400, "invalid_input", "device_id does not match inbox route");
    }
    if (input.limit <= 0) {
      throw new HttpError(400, "invalid_input", "limit must be greater than zero");
    }

    const meta = await this.getMeta();
    const records: InboxRecord[] = [];
    const upper = Math.min(meta.headSeq, input.fromSeq + input.limit - 1);
    for (let seq = input.fromSeq; seq <= upper; seq += 1) {
      const index = await this.state.get<StoredRecordIndex>(`${RECORD_PREFIX}${seq}`);
      if (!index) {
        // Records at or below the acknowledged cursor may already have been
        // removed by retention cleanup. A gap above that cursor is never
        // legitimate and must not be hidden from the client.
        if (seq <= meta.ackedSeq) {
          continue;
        }
        throw new HttpError(500, "storage_integrity_error", `inbox record index is missing at seq ${seq}`);
      }
      this.validateStoredRecordIndex(index, seq);
      if (index.inlineRecord) {
        this.validateMaterializedRecord(index.inlineRecord, index, seq);
        records.push(index.inlineRecord);
        continue;
      }
      if (!index.payloadRef) {
        throw new HttpError(500, "storage_integrity_error", `inbox record payload reference is missing at seq ${seq}`);
      }
      let record: InboxRecord | null;
      try {
        record = await this.spillStore.getJson<InboxRecord>(index.payloadRef);
      } catch {
        throw new HttpError(500, "storage_integrity_error", `inbox spill payload is invalid at seq ${seq}`);
      }
      if (!record) {
        throw new HttpError(500, "storage_integrity_error", `inbox spill payload is missing at seq ${seq}`);
      }
      this.validateMaterializedRecord(record, index, seq);
      records.push(record);
    }
    return {
      toSeq: records.length > 0 ? records[records.length - 1].seq : meta.headSeq,
      records
    };
  }

  async ack(input: AckRequest): Promise<AckResult> {
    if (input.ack.deviceId !== this.deviceId) {
      throw new HttpError(400, "invalid_input", "ack device_id does not match inbox route");
    }
    const meta = await this.getMeta();
    if (!Number.isSafeInteger(input.ack.ackSeq) || input.ack.ackSeq < 0) {
      throw new HttpError(400, "invalid_ack", "ack_seq must be a non-negative safe integer");
    }
    if (input.ack.ackSeq < meta.ackedSeq) {
      throw new HttpError(409, "invalid_ack", "ack_seq must not move backwards");
    }
    if (input.ack.ackSeq > meta.headSeq) {
      throw new HttpError(409, "invalid_ack", "ack_seq must not move beyond inbox head_seq");
    }
    const ackSeq = input.ack.ackSeq;
    if (ackSeq > meta.ackedSeq) {
      await this.state.put(META_KEY, { ...meta, ackedSeq: ackSeq });
      await this.state.setAlarm(Date.now());
    }
    return { accepted: true, ackSeq };
  }

  async getHead(): Promise<{ headSeq: number }> {
    const meta = await this.getMeta();
    return { headSeq: meta.headSeq };
  }

  async getAllowlist(now = Date.now()): Promise<AllowlistDocument> {
    return (await this.state.get<AllowlistDocument>(ALLOWLIST_KEY)) ?? {
      version: "0.1",
      deviceId: this.deviceId,
      updatedAt: now,
      allowedSenderUserIds: [],
      rejectedSenderUserIds: []
    };
  }

  async replaceAllowlist(allowedSenderUserIds: string[], rejectedSenderUserIds: string[], now: number): Promise<AllowlistDocument> {
    const document: AllowlistDocument = {
      version: "0.1",
      deviceId: this.deviceId,
      updatedAt: now,
      allowedSenderUserIds: Array.from(new Set(allowedSenderUserIds)).sort(),
      rejectedSenderUserIds: Array.from(new Set(rejectedSenderUserIds.filter((userId) => !allowedSenderUserIds.includes(userId)))).sort()
    };
    await this.state.put(ALLOWLIST_KEY, document);
    return document;
  }

  async listMessageRequests(now = Date.now()): Promise<MessageRequestItem[]> {
    await this.pruneExpiredMessageRequests(now);
    await this.scheduleNextAlarm(now);
    const requests = await this.state.get<string[]>(this.messageRequestIndexKey());
    if (!requests?.length) {
      return [];
    }
    const items: MessageRequestItem[] = [];
    for (const senderUserId of requests) {
      const entry = await this.state.get<MessageRequestEntry>(this.messageRequestKey(senderUserId));
      if (!entry) {
        continue;
      }
      items.push(this.toMessageRequestItem(entry));
    }
    items.sort((left, right) => left.firstSeenAt - right.firstSeenAt || left.senderUserId.localeCompare(right.senderUserId));
    return items;
  }

  async acceptMessageRequest(requestId: string, now: number): Promise<MessageRequestActionResult> {
    const entry = await this.findMessageRequest(requestId, now);
    if (!entry) {
      throw new HttpError(404, "not_found", "message request not found");
    }
    const allowlist = await this.getAllowlist(now);
    await this.replaceAllowlist(
      [...allowlist.allowedSenderUserIds, entry.senderUserId],
      allowlist.rejectedSenderUserIds.filter((userId) => userId !== entry.senderUserId),
      now
    );

    const requestsToPromote = this.messageRequestsToPromote(entry);
    const promotedMessageIds = new Set(
      requestsToPromote.map((request) => request.envelope.messageId)
    );
    for (const request of entry.pendingRequests) {
      if (promotedMessageIds.has(request.envelope.messageId)) {
        continue;
      }
      await this.state.put(
        `${APPEND_RESULT_PREFIX}${request.envelope.messageId}`,
        this.supersededMessageRequestResult()
      );
    }

    let promotedCount = 0;
    const promotedConversationIds = new Set<string>();
    for (const request of requestsToPromote) {
      const delivered = await this.deliverEnvelope(request, now);
      await this.state.put(`${APPEND_RESULT_PREFIX}${request.envelope.messageId}`, delivered);
      if (delivered.deliveredTo === "inbox") {
        promotedCount += 1;
        promotedConversationIds.add(request.envelope.conversationId);
      }
    }
    await this.deleteMessageRequest(entry.senderUserId, "accepted");
    await this.scheduleNextAlarm(now);
    return {
      accepted: true,
      requestId: entry.requestId,
      senderUserId: entry.senderUserId,
      senderBundleShareUrl: entry.senderBundleShareUrl,
      senderBundleHash: entry.senderBundleHash,
      senderDisplayName: entry.senderDisplayName,
      promotedCount,
      promotedConversationIds: [...promotedConversationIds].sort()
    };
  }

  async rejectMessageRequest(requestId: string, now: number): Promise<MessageRequestActionResult> {
    const entry = await this.findMessageRequest(requestId, now);
    if (!entry) {
      throw new HttpError(404, "not_found", "message request not found");
    }
    const allowlist = await this.getAllowlist(now);
    await this.replaceAllowlist(
      allowlist.allowedSenderUserIds.filter((userId) => userId !== entry.senderUserId),
      [...allowlist.rejectedSenderUserIds, entry.senderUserId],
      now
    );
    await this.deleteMessageRequest(entry.senderUserId, "rejected");
    await this.scheduleNextAlarm(now);
    return {
      accepted: true,
      requestId: entry.requestId,
      senderUserId: entry.senderUserId,
      senderBundleShareUrl: entry.senderBundleShareUrl,
      senderBundleHash: entry.senderBundleHash,
      senderDisplayName: entry.senderDisplayName,
      promotedCount: 0,
      promotedConversationIds: []
    };
  }

  async cleanExpiredRecords(now: number): Promise<void> {
    await this.pruneExpiredMessageRequests(now);
    const meta = await this.getMeta();
    const stored = await this.state.list<StoredRecordIndex>({ prefix: RECORD_PREFIX });
    const eligible = Array.from(stored.entries())
      .filter(([, index]) => index.seq <= meta.ackedSeq && index.expiresAt !== undefined && index.expiresAt <= now)
      .sort((left, right) => left[1].seq - right[1].seq);

    for (const [key, index] of eligible.slice(0, CLEANUP_BATCH_SIZE)) {
      if (index.payloadRef) {
        await this.spillStore.delete(index.payloadRef);
      }
      await this.state.delete(key);
      await this.state.delete(`${IDEMPOTENCY_PREFIX}${index.messageId}`);
    }

    if (eligible.length > CLEANUP_BATCH_SIZE) {
      await this.state.setAlarm(now + 1);
      return;
    }
    await this.scheduleNextAlarm(now);
  }

  private validateStoredRecordIndex(index: StoredRecordIndex, seq: number): void {
    if (index.seq !== seq || index.recipientDeviceId !== this.deviceId || !index.messageId) {
      throw new HttpError(500, "storage_integrity_error", `inbox record index does not match seq ${seq}`);
    }
  }

  private validateMaterializedRecord(record: InboxRecord, index: StoredRecordIndex, seq: number): void {
    if (
      record.seq !== seq ||
      record.seq !== index.seq ||
      record.messageId !== index.messageId ||
      record.recipientDeviceId !== this.deviceId ||
      record.recipientDeviceId !== index.recipientDeviceId
    ) {
      throw new HttpError(500, "storage_integrity_error", `inbox record payload does not match index at seq ${seq}`);
    }
  }

  private async getMeta(): Promise<InboxMeta> {
    return (await this.state.get<InboxMeta>(META_KEY)) ?? this.defaults;
  }

  private async deliverEnvelope(input: AppendEnvelopeRequest, now: number): Promise<AppendEnvelopeResult> {
    const meta = await this.getMeta();
    const existingSeq = await this.state.get<number>(`${IDEMPOTENCY_PREFIX}${input.envelope.messageId}`);
    if (existingSeq !== undefined) {
      return { accepted: true, seq: existingSeq, deliveredTo: "inbox" };
    }

    const seq = meta.headSeq + 1;
    const expiresAt = now + meta.retentionDays * 24 * 60 * 60 * 1000;
    const record: InboxRecord = {
      seq,
      recipientDeviceId: this.deviceId,
      messageId: input.envelope.messageId,
      receivedAt: now,
      expiresAt,
      state: "available",
      envelope: input.envelope
    };
    const serialized = JSON.stringify(record);
    const storageKey = `${RECORD_PREFIX}${seq}`;

    if (new TextEncoder().encode(serialized).byteLength <= meta.maxInlineBytes && input.envelope.inlineCiphertext) {
      const inlineIndex: StoredRecordIndex = {
        seq,
        messageId: record.messageId,
        recipientDeviceId: record.recipientDeviceId,
        receivedAt: record.receivedAt,
        expiresAt,
        state: record.state,
        inlineRecord: record
      };
      await this.state.put(storageKey, inlineIndex);
    } else {
      const payloadRef = `inbox-payload/${this.deviceId}/${seq}.json`;
      await this.spillStore.putJson(payloadRef, record);
      const indexed: StoredRecordIndex = {
        seq,
        messageId: record.messageId,
        recipientDeviceId: record.recipientDeviceId,
        receivedAt: record.receivedAt,
        expiresAt,
        state: record.state,
        payloadRef
      };
      await this.state.put(storageKey, indexed);
    }

    await this.state.put(`${IDEMPOTENCY_PREFIX}${record.messageId}`, seq);
    await this.state.put(META_KEY, { ...meta, headSeq: seq });
    this.publish({
      event: "head_updated",
      deviceId: this.deviceId,
      seq
    });
    this.publish({
      event: "inbox_record_available",
      deviceId: this.deviceId,
      seq,
      record
    });

    return { accepted: true, seq, deliveredTo: "inbox" };
  }

  private async queueMessageRequestWithLimit(input: AppendEnvelopeRequest, now: number): Promise<AppendEnvelopeResult> {
    await this.enforceMessageRequestRateLimit(now);
    await this.pruneExpiredMessageRequests(now);

    const limits = await this.getMeta();
    const senderUserId = input.envelope.senderUserId;
    const key = this.messageRequestKey(senderUserId);
    const requestId = this.requestIdForSender(senderUserId);
    const existing = await this.state.get<MessageRequestEntry>(key);
    const index = (await this.state.get<string[]>(this.messageRequestIndexKey())) ?? [];
    const queueMeta = (await this.state.get<MessageRequestQueueMeta>(MESSAGE_REQUEST_META_KEY)) ?? {
      version: 1,
      totalBytes: 0,
      senderCount: index.length
    };
    const requestBytes = new TextEncoder().encode(JSON.stringify(input)).byteLength;

    if (existing && existing.pendingRequests.length >= (limits.messageRequestMaxPerSender ?? 16)) {
      this.messageRequestCapacityExceeded("message request sender quota exceeded");
    }
    if (!existing && index.length >= (limits.messageRequestMaxSenders ?? 64)) {
      this.messageRequestCapacityExceeded("message request sender capacity exceeded");
    }
    if (queueMeta.totalBytes + requestBytes > (limits.messageRequestMaxTotalBytes ?? 4 * 1024 * 1024)) {
      this.messageRequestCapacityExceeded("message request byte capacity exceeded");
    }

    const entry: MessageRequestEntry = existing ?? {
      requestId,
      recipientDeviceId: this.deviceId,
      senderUserId,
      senderBundleShareUrl: input.senderBundleShareUrl,
      senderBundleHash: input.senderBundleHash,
      senderDisplayName: input.senderDisplayName,
      firstSeenAt: now,
      lastSeenAt: now,
      messageCount: 0,
      lastMessageId: input.envelope.messageId,
      lastConversationId: input.envelope.conversationId,
      pendingRequests: [],
      byteSize: 0,
      expiresAt: now + (limits.messageRequestTtlSeconds ?? 7 * 24 * 60 * 60) * 1000
    };
    entry.senderBundleShareUrl ??= input.senderBundleShareUrl;
    entry.senderBundleHash ??= input.senderBundleHash;
    entry.senderDisplayName ??= input.senderDisplayName;
    entry.lastSeenAt = now;
    entry.messageCount += 1;
    entry.lastMessageId = input.envelope.messageId;
    entry.lastConversationId = input.envelope.conversationId;
    entry.pendingRequests.push(input);
    entry.byteSize = (entry.byteSize ?? this.messageRequestEntryBytes(entry) - requestBytes) + requestBytes;
    entry.expiresAt ??= entry.firstSeenAt + (limits.messageRequestTtlSeconds ?? 7 * 24 * 60 * 60) * 1000;

    const nextIndex = index.includes(senderUserId)
      ? index
      : [...index, senderUserId].sort();
    const nextQueueMeta: MessageRequestQueueMeta = {
      version: 1,
      totalBytes: queueMeta.totalBytes + requestBytes,
      senderCount: nextIndex.length
    };
    await this.state.putEntries({
      [key]: entry,
      [this.messageRequestIndexKey()]: nextIndex,
      [MESSAGE_REQUEST_META_KEY]: nextQueueMeta
    });
    await this.scheduleNextAlarm(now);
    this.publish({
      event: "message_request_changed",
      deviceId: this.deviceId,
      senderUserId,
      requestId,
      change: "queued"
    });
    return {
      accepted: true,
      seq: 0,
      deliveredTo: "message_request",
      queuedAsRequest: true,
      requestId
    };
  }

  private messageRequestCapacityExceeded(message: string): never {
    throw new HttpError(429, "message_request_capacity_exceeded", message);
  }

  private messageRequestsToPromote(entry: MessageRequestEntry): AppendEnvelopeRequest[] {
    if (this.groupInviteMetadata(entry)) {
      return entry.pendingRequests;
    }
    const latestConversationId =
      entry.lastConversationId ||
      entry.pendingRequests[entry.pendingRequests.length - 1]?.envelope.conversationId;
    if (!latestConversationId) {
      return [];
    }
    return entry.pendingRequests.filter(
      (request) => request.envelope.conversationId === latestConversationId
    );
  }

  private supersededMessageRequestResult(): AppendEnvelopeResult {
    return {
      accepted: true,
      seq: 0,
      deliveredTo: "rejected",
      queuedAsRequest: false
    };
  }

  private async enforceRateLimit(senderUserId: string, now: number): Promise<void> {
    const meta = await this.getMeta();
    const minuteLimit = meta.rateLimitPerMinute;
    const hourLimit = meta.rateLimitPerHour;
    if (minuteLimit <= 0 && hourLimit <= 0) {
      return;
    }

    const key = `${RATE_LIMIT_PREFIX}${senderUserId}`;
    const minuteWindowStart = Math.floor(now / 60_000) * 60_000;
    const hourWindowStart = Math.floor(now / 3_600_000) * 3_600_000;
    const state = (await this.state.get<RateLimitState>(key)) ?? {
      minuteWindowStart,
      minuteCount: 0,
      hourWindowStart,
      hourCount: 0
    };

    if (state.minuteWindowStart !== minuteWindowStart) {
      state.minuteWindowStart = minuteWindowStart;
      state.minuteCount = 0;
    }
    if (state.hourWindowStart !== hourWindowStart) {
      state.hourWindowStart = hourWindowStart;
      state.hourCount = 0;
    }
    if (minuteLimit > 0 && state.minuteCount >= minuteLimit) {
      throw new HttpError(429, "rate_limited", "append rate limit exceeded for minute window");
    }
    if (hourLimit > 0 && state.hourCount >= hourLimit) {
      throw new HttpError(429, "rate_limited", "append rate limit exceeded for hour window");
    }

    state.minuteCount += 1;
    state.hourCount += 1;
    await this.state.put(key, state);
  }

  private async enforceMessageRequestRateLimit(now: number): Promise<void> {
    const meta = await this.getMeta();
    const minuteLimit = meta.messageRequestRateLimitMinute ?? 30;
    const hourLimit = meta.messageRequestRateLimitHour ?? 300;
    const minuteWindowStart = Math.floor(now / 60_000) * 60_000;
    const hourWindowStart = Math.floor(now / 3_600_000) * 3_600_000;
    const state = (await this.state.get<RateLimitState>(MESSAGE_REQUEST_RATE_LIMIT_KEY)) ?? {
      minuteWindowStart,
      minuteCount: 0,
      hourWindowStart,
      hourCount: 0
    };
    if (state.minuteWindowStart !== minuteWindowStart) {
      state.minuteWindowStart = minuteWindowStart;
      state.minuteCount = 0;
    }
    if (state.hourWindowStart !== hourWindowStart) {
      state.hourWindowStart = hourWindowStart;
      state.hourCount = 0;
    }
    if (minuteLimit > 0 && state.minuteCount >= minuteLimit) {
      throw new HttpError(
        429,
        "message_request_rate_limited",
        "message request rate limit exceeded for minute window",
        { retryAfterSeconds: Math.max(1, Math.ceil((minuteWindowStart + 60_000 - now) / 1000)) }
      );
    }
    if (hourLimit > 0 && state.hourCount >= hourLimit) {
      throw new HttpError(
        429,
        "message_request_rate_limited",
        "message request rate limit exceeded for hour window",
        { retryAfterSeconds: Math.max(1, Math.ceil((hourWindowStart + 3_600_000 - now) / 1000)) }
      );
    }
    state.minuteCount += 1;
    state.hourCount += 1;
    await this.state.put(MESSAGE_REQUEST_RATE_LIMIT_KEY, state);
  }

  private publish(event: RealtimeEvent): void {
    const payload = JSON.stringify(event);
    for (const session of this.sessions) {
      session.send(payload);
    }
  }

  private validateAppendRequest(input: AppendEnvelopeRequest): void {
    if (input.recipientDeviceId !== this.deviceId) {
      throw new HttpError(400, "invalid_input", "recipient_device_id does not match inbox route");
    }
    if (input.envelope.recipientDeviceId !== this.deviceId) {
      throw new HttpError(400, "invalid_input", "envelope recipient_device_id does not match inbox route");
    }
    if (!input.envelope.messageId || !input.envelope.conversationId || !input.envelope.senderUserId) {
      throw new HttpError(400, "invalid_input", "append request is missing required envelope fields");
    }
    const hasInline = Boolean(input.envelope.inlineCiphertext);
    const hasStorageRefs = (input.envelope.storageRefs?.length ?? 0) > 0;
    if (!hasInline && !hasStorageRefs) {
      throw new HttpError(400, "invalid_input", "envelope must include inline_ciphertext or storage_refs");
    }
  }

  private requestIdForSender(senderUserId: string): string {
    return `request:${senderUserId}`;
  }

  private messageRequestKey(senderUserId: string): string {
    return `${MESSAGE_REQUEST_PREFIX}${senderUserId}`;
  }

  private messageRequestIndexKey(): string {
    return `${MESSAGE_REQUEST_PREFIX}index`;
  }

  private async deleteMessageRequest(
    senderUserId: string,
    change: "accepted" | "rejected"
  ): Promise<void> {
    const existing = await this.state.get<MessageRequestEntry>(this.messageRequestKey(senderUserId));
    const index = (await this.state.get<string[]>(this.messageRequestIndexKey())) ?? [];
    const nextIndex = index.filter((entry) => entry !== senderUserId);
    const queueMeta = (await this.state.get<MessageRequestQueueMeta>(MESSAGE_REQUEST_META_KEY)) ?? {
      version: 1,
      totalBytes: 0,
      senderCount: index.length
    };
    await this.state.mutateEntries({
      [this.messageRequestIndexKey()]: nextIndex,
      [MESSAGE_REQUEST_META_KEY]: {
        version: 1,
        totalBytes: Math.max(0, queueMeta.totalBytes - (existing ? this.messageRequestEntryBytes(existing) : 0)),
        senderCount: nextIndex.length
      } satisfies MessageRequestQueueMeta
    }, [this.messageRequestKey(senderUserId)]);
    if (existing) {
      this.publish({
        event: "message_request_changed",
        deviceId: this.deviceId,
        senderUserId,
        requestId: existing.requestId,
        change
      });
    }
  }

  private async findMessageRequest(requestId: string, now: number): Promise<MessageRequestEntry | null> {
    const requests = await this.listMessageRequests(now);
    const match = requests.find((request) => request.requestId === requestId);
    if (!match) {
      return null;
    }
    return (await this.state.get<MessageRequestEntry>(this.messageRequestKey(match.senderUserId))) ?? null;
  }

  private messageRequestEntryBytes(entry: MessageRequestEntry): number {
    if (entry.byteSize !== undefined && Number.isSafeInteger(entry.byteSize) && entry.byteSize >= 0) {
      return entry.byteSize;
    }
    return entry.pendingRequests.reduce(
      (total, request) => total + new TextEncoder().encode(JSON.stringify(request)).byteLength,
      0
    );
  }

  private async pruneExpiredMessageRequests(now: number): Promise<void> {
    const limits = await this.getMeta();
    const index = (await this.state.get<string[]>(this.messageRequestIndexKey())) ?? [];
    const retained: string[] = [];
    const updates: Record<string, unknown> = {};
    const deleteKeys: string[] = [];
    let totalBytes = 0;

    for (const senderUserId of index) {
      const key = this.messageRequestKey(senderUserId);
      const entry = await this.state.get<MessageRequestEntry>(key);
      if (!entry) {
        continue;
      }
      const byteSize = this.messageRequestEntryBytes(entry);
      const expiresAt = entry.expiresAt ?? entry.firstSeenAt + (limits.messageRequestTtlSeconds ?? 7 * 24 * 60 * 60) * 1000;
      if (expiresAt <= now) {
        deleteKeys.push(key);
        for (const pending of entry.pendingRequests) {
          deleteKeys.push(`${APPEND_RESULT_PREFIX}${pending.envelope.messageId}`);
        }
        continue;
      }
      retained.push(senderUserId);
      totalBytes += byteSize;
      if (entry.byteSize !== byteSize || entry.expiresAt !== expiresAt || entry.messageCount !== entry.pendingRequests.length) {
        updates[key] = {
          ...entry,
          byteSize,
          expiresAt,
          messageCount: entry.pendingRequests.length
        } satisfies MessageRequestEntry;
      }
    }

    updates[this.messageRequestIndexKey()] = retained.sort();
    updates[MESSAGE_REQUEST_META_KEY] = {
      version: 1,
      totalBytes,
      senderCount: retained.length
    } satisfies MessageRequestQueueMeta;
    await this.state.mutateEntries(updates, deleteKeys);
  }

  private async scheduleNextAlarm(now: number): Promise<void> {
    const meta = await this.getMeta();
    const records = await this.state.list<StoredRecordIndex>({ prefix: RECORD_PREFIX });
    const messageRequestSenders = (await this.state.get<string[]>(this.messageRequestIndexKey())) ?? [];
    let nextAt: number | undefined;

    for (const record of records.values()) {
      if (record.seq > meta.ackedSeq || record.expiresAt === undefined) {
        continue;
      }
      nextAt = nextAt === undefined ? record.expiresAt : Math.min(nextAt, record.expiresAt);
    }
    for (const senderUserId of messageRequestSenders) {
      const entry = await this.state.get<MessageRequestEntry>(this.messageRequestKey(senderUserId));
      if (entry?.expiresAt !== undefined) {
        nextAt = nextAt === undefined ? entry.expiresAt : Math.min(nextAt, entry.expiresAt);
      }
    }
    if (nextAt !== undefined) {
      await this.state.setAlarm(Math.max(now + 1, nextAt));
    }
  }

  private toMessageRequestItem(entry: MessageRequestEntry): MessageRequestItem {
    const groupInvite = this.groupInviteMetadata(entry);
    return {
      requestId: entry.requestId,
      recipientDeviceId: entry.recipientDeviceId,
      senderUserId: entry.senderUserId,
      senderBundleShareUrl: entry.senderBundleShareUrl,
      senderBundleHash: entry.senderBundleHash,
      senderDisplayName: entry.senderDisplayName,
      firstSeenAt: entry.firstSeenAt,
      lastSeenAt: entry.lastSeenAt,
      messageCount: entry.messageCount,
      lastMessageId: entry.lastMessageId,
      lastConversationId: entry.lastConversationId,
      requestKind: groupInvite ? "group_invite" : "direct",
      groupId: groupInvite?.groupId,
      groupTitle: groupInvite?.title
    };
  }

  private groupInviteMetadata(entry: MessageRequestEntry): GroupWelcomePickupControlPayload | null {
    for (let index = entry.pendingRequests.length - 1; index >= 0; index -= 1) {
      const request = entry.pendingRequests[index];
      if (request.envelope.messageType !== "control_group_welcome_pickup") {
        continue;
      }
      const encoded = request.envelope.inlineCiphertext;
      if (!encoded) {
        return null;
      }
      try {
        const payload = JSON.parse(atob(encoded)) as GroupWelcomePickupControlPayload;
        if (payload.groupId && payload.title) {
          return payload;
        }
      } catch {
        return null;
      }
    }
    return null;
  }
}







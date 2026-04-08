import { HttpError } from "../auth/capability";
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
}

interface RateLimitState {
  minuteWindowStart: number;
  minuteCount: number;
  hourWindowStart: number;
  hourCount: number;
}

const META_KEY = "meta";
const IDEMPOTENCY_PREFIX = "idempotency:";
const APPEND_RESULT_PREFIX = "append-result:";
const RECORD_PREFIX = "record:";
const ALLOWLIST_KEY = "allowlist";
const MESSAGE_REQUEST_PREFIX = "message-request:";
const RATE_LIMIT_PREFIX = "rate-limit:";

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

  async appendEnvelope(input: AppendEnvelopeRequest, now: number): Promise<AppendEnvelopeResult> {
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

    if (allowlist.allowedSenderUserIds.includes(input.envelope.senderUserId)) {
      const delivered = await this.deliverEnvelope(input, now);
      await this.state.put(`${APPEND_RESULT_PREFIX}${input.envelope.messageId}`, delivered);
      return delivered;
    }

    const request = await this.queueMessageRequest(input, now);
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
        continue;
      }
      if (index.inlineRecord) {
        records.push(index.inlineRecord);
        continue;
      }
      if (!index.payloadRef) {
        throw new HttpError(500, "temporary_unavailable", "record payload reference is missing");
      }
      const record = await this.spillStore.getJson<InboxRecord>(index.payloadRef);
      if (!record) {
        continue;
      }
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
    if (input.ack.ackSeq < meta.ackedSeq) {
      throw new HttpError(409, "invalid_ack", "ack_seq must not move backwards");
    }
    const ackSeq = Math.max(meta.ackedSeq, input.ack.ackSeq);
    await this.state.put(META_KEY, { ...meta, ackedSeq: ackSeq });
    await this.state.setAlarm(Date.now());
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

  async listMessageRequests(): Promise<MessageRequestItem[]> {
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
    const entry = await this.findMessageRequest(requestId);
    if (!entry) {
      throw new HttpError(404, "not_found", "message request not found");
    }
    const allowlist = await this.getAllowlist(now);
    await this.replaceAllowlist(
      [...allowlist.allowedSenderUserIds, entry.senderUserId],
      allowlist.rejectedSenderUserIds.filter((userId) => userId !== entry.senderUserId),
      now
    );

    let promotedCount = 0;
    for (const request of entry.pendingRequests) {
      const delivered = await this.deliverEnvelope(request, now);
      await this.state.put(`${APPEND_RESULT_PREFIX}${request.envelope.messageId}`, delivered);
      promotedCount += delivered.seq === undefined ? 0 : 1;
    }
    await this.deleteMessageRequest(entry.senderUserId);
    return {
      accepted: true,
      requestId: entry.requestId,
      senderUserId: entry.senderUserId,
      senderBundleShareUrl: entry.senderBundleShareUrl,
      senderBundleHash: entry.senderBundleHash,
      senderDisplayName: entry.senderDisplayName,
      promotedCount
    };
  }

  async rejectMessageRequest(requestId: string, now: number): Promise<MessageRequestActionResult> {
    const entry = await this.findMessageRequest(requestId);
    if (!entry) {
      throw new HttpError(404, "not_found", "message request not found");
    }
    const allowlist = await this.getAllowlist(now);
    await this.replaceAllowlist(
      allowlist.allowedSenderUserIds.filter((userId) => userId !== entry.senderUserId),
      [...allowlist.rejectedSenderUserIds, entry.senderUserId],
      now
    );
    await this.deleteMessageRequest(entry.senderUserId);
    return {
      accepted: true,
      requestId: entry.requestId,
      senderUserId: entry.senderUserId,
      senderBundleShareUrl: entry.senderBundleShareUrl,
      senderBundleHash: entry.senderBundleHash,
      senderDisplayName: entry.senderDisplayName,
      promotedCount: 0
    };
  }

  async cleanExpiredRecords(now: number): Promise<void> {
    const meta = await this.getMeta();
    for (let seq = 1; seq <= meta.ackedSeq; seq += 1) {
      const key = `${RECORD_PREFIX}${seq}`;
      const index = await this.state.get<StoredRecordIndex>(key);
      if (!index || index.expiresAt === undefined || index.expiresAt > now) {
        continue;
      }
      if (index.payloadRef) {
        await this.spillStore.delete(index.payloadRef);
      }
      await this.state.delete(key);
      await this.state.delete(`${IDEMPOTENCY_PREFIX}${index.messageId}`);
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
    await this.state.setAlarm(expiresAt);

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

  private async queueMessageRequest(input: AppendEnvelopeRequest, now: number): Promise<AppendEnvelopeResult> {
    const senderUserId = input.envelope.senderUserId;
    const key = this.messageRequestKey(senderUserId);
    const requestId = this.requestIdForSender(senderUserId);
    const existing = await this.state.get<MessageRequestEntry>(key);
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
      pendingRequests: []
    };
    entry.senderBundleShareUrl ??= input.senderBundleShareUrl;
    entry.senderBundleHash ??= input.senderBundleHash;
    entry.senderDisplayName ??= input.senderDisplayName;
    entry.lastSeenAt = now;
    entry.messageCount += 1;
    entry.lastMessageId = input.envelope.messageId;
    entry.lastConversationId = input.envelope.conversationId;
    entry.pendingRequests.push(input);
    await this.state.put(key, entry);
    await this.addMessageRequestIndex(senderUserId);
    return {
      accepted: true,
      seq: 0,
      deliveredTo: "message_request",
      queuedAsRequest: true,
      requestId
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

  private async addMessageRequestIndex(senderUserId: string): Promise<void> {
    const index = (await this.state.get<string[]>(this.messageRequestIndexKey())) ?? [];
    if (!index.includes(senderUserId)) {
      index.push(senderUserId);
      index.sort();
      await this.state.put(this.messageRequestIndexKey(), index);
    }
  }

  private async deleteMessageRequest(senderUserId: string): Promise<void> {
    await this.state.delete(this.messageRequestKey(senderUserId));
    const index = (await this.state.get<string[]>(this.messageRequestIndexKey())) ?? [];
    await this.state.put(
      this.messageRequestIndexKey(),
      index.filter((entry) => entry !== senderUserId)
    );
  }

  private async findMessageRequest(requestId: string): Promise<MessageRequestEntry | null> {
    const requests = await this.listMessageRequests();
    const match = requests.find((request) => request.requestId === requestId);
    if (!match) {
      return null;
    }
    return (await this.state.get<MessageRequestEntry>(this.messageRequestKey(match.senderUserId))) ?? null;
  }

  private toMessageRequestItem(entry: MessageRequestEntry): MessageRequestItem {
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
      lastConversationId: entry.lastConversationId
    };
  }
}







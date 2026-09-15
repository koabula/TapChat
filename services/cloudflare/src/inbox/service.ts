import { HttpError, type AppendAuthContext } from "../auth/capability";
import { INBOX_DO_KEYS, R2_KEYS } from "../leakage-keys";
import type {
  AckRequest,
  AckResult,
  AppendEnvelopeRequest,
  AppendEnvelopeResult,
  Envelope,
  FetchMessagesRequest,
  FetchMessagesResult,
  InboxRecord,
  MessageRequestActionResult,
  MessageRequestItem,
  RealtimeEvent
} from "../types/contracts";
import type { DurableObjectStorageLike, JsonBlobStore, SessionSink } from "../types/runtime";

interface InboxMeta {
  /**
   * What the inbox answers an append with.
   *
   * One counter over every append this device accepts, whatever becomes of
   * the record: a first contact waiting for its recipient and an admitted
   * message draw from the same sequence, so the number discloses nothing
   * about which happened. It used to be `headSeq + 1` for one and a per-lane
   * counter starting at 1 for the other, which told a sender it was still
   * queued on its very first reply.
   *
   * It is also the closer analogue of what the ideal returns: `Send` gives
   * back `|T| + 1`, and the transcript counts every send, not the ones an
   * adversary later chose to deliver. `headSeq` counts only the admitted.
   */
  appendSeq: number;
  headSeq: number;
  ackedSeq: number;
  historyFloorSeq?: number;
  retentionDays: number;
  maxInlineBytes: number;
  rateLimitPerMinute: number;
  rateLimitPerHour: number;
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
  lane: string;
  storageRef?: Envelope["storageRef"];
  inlineBytes?: string;
  payloadRef?: string;
}

interface MessageRequestEntry {
  requestId: string;
  recipientDeviceId: string;
  lane: string;
  firstSeenAt: number;
  messageCount: number;
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

interface AcceptedLaneRecord {
  registeredAt: number;
}

const OPAQUE_ID = /^[0-9a-f]{32}$/;
const ENVELOPE_MAX_BYTES = 256 * 1024;
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

    const existingResult = await this.state.get<AppendEnvelopeResult>(
      INBOX_DO_KEYS.appendResult(input.envelope.mid)
    );
    if (existingResult) {
      return existingResult;
    }

    if (authContext.mode !== "verified") {
      throw new HttpError(426, "upgrade_required", "verified append authorization is required");
    }

    const accepted = await this.isAcceptedLane(input.envelope.lane);
    if (accepted) {
      await this.enforceRateLimit(INBOX_DO_KEYS.rateLimit(input.envelope.lane), now);
      return this.deliverEnvelope(input, now);
    }

    await this.enforceRateLimit(INBOX_DO_KEYS.rateLimitFirstContact, now);
    return this.queueMessageRequestWithLimit(input, now);
  }

  async fetchMessages(input: FetchMessagesRequest): Promise<FetchMessagesResult> {
    if (input.deviceId !== this.deviceId) {
      throw new HttpError(400, "invalid_input", "device_id does not match inbox route");
    }
    if (input.limit <= 0) {
      throw new HttpError(400, "invalid_input", "limit must be greater than zero");
    }

    const meta = await this.getMeta();
    const historyFloorSeq = meta.historyFloorSeq ?? 0;
    const start = Math.max(input.fromSeq, historyFloorSeq + 1);
    const records: InboxRecord[] = [];
    const upper = Math.min(meta.headSeq, start + input.limit - 1);
    for (let seq = start; seq <= upper; seq += 1) {
      const index = await this.state.get<StoredRecordIndex>(INBOX_DO_KEYS.record(seq));
      if (!index) {
        if (seq <= meta.ackedSeq) {
          continue;
        }
        throw new HttpError(500, "storage_integrity_error", `inbox record index is missing at seq ${seq}`);
      }
      this.validateStoredRecordIndex(index, seq);
      records.push(await this.materializeRecord(index, seq));
    }
    return {
      toSeq: records.length > 0
        ? records[records.length - 1].seq
        : Math.max(historyFloorSeq, meta.ackedSeq, Math.min(meta.headSeq, start - 1)),
      historyFloorSeq,
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
    if (ackSeq > meta.ackedSeq || (meta.historyFloorSeq ?? 0) > 0) {
      await this.state.put(INBOX_DO_KEYS.meta, {
        ...meta,
        ackedSeq: ackSeq,
        historyFloorSeq: ackSeq >= (meta.historyFloorSeq ?? 0) ? undefined : meta.historyFloorSeq
      });
      await this.state.setAlarm(Date.now());
    }
    return { accepted: true, ackSeq };
  }

  async getHead(): Promise<{ headSeq: number }> {
    const meta = await this.getMeta();
    return { headSeq: meta.headSeq };
  }

  /**
   * Authorize a sender to place one payload in this runtime's storage.
   *
   * The credential is the lane and nothing else. A lane is admitted only
   * because the owner of this inbox accepted the contact, and revoking it is
   * a single key deletion, so the same act that stops a sender appending also
   * stops it uploading. Issuing a second, storage-specific credential was the
   * alternative, and it has nowhere to be delivered from: at first contact the
   * only channel to the recipient runs through this host.
   *
   * A sender with no admitted lane cannot upload at all. That is the intent
   * rather than a gap — an unaccepted stranger can consume a bounded message
   * request queue, but not storage.
   *
   * The quota is charged on the lane because the lane is already the rate
   * limit partition for appends; a payload and the envelope that references
   * it are one act, and counting them once each against the same bucket is
   * what keeps that true.
   */
  async authorizeBlobUpload(
    lane: string,
    sizeBytes: number,
    now: number
  ): Promise<{ accepted: true }> {
    this.assertOpaqueId(lane, "lane");
    if (!Number.isSafeInteger(sizeBytes) || sizeBytes <= 0) {
      throw new HttpError(400, "invalid_input", "sizeBytes is required");
    }
    if (!(await this.isAcceptedLane(lane))) {
      throw new HttpError(403, "invalid_capability", "lane is not admitted by this inbox");
    }
    await this.enforceRateLimit(INBOX_DO_KEYS.rateLimit(lane), now);
    return { accepted: true };
  }

  async registerAcceptedLane(lane: string, now: number): Promise<{ accepted: true; lane: string }> {
    this.assertOpaqueId(lane, "lane");
    await this.state.put(INBOX_DO_KEYS.acceptedLane(lane), { registeredAt: now } satisfies AcceptedLaneRecord);
    return { accepted: true, lane };
  }

  async revokeAcceptedLane(lane: string): Promise<{ accepted: true; lane: string }> {
    this.assertOpaqueId(lane, "lane");
    await this.state.delete(INBOX_DO_KEYS.acceptedLane(lane));
    return { accepted: true, lane };
  }

  async listMessageRequests(now = Date.now()): Promise<MessageRequestItem[]> {
    await this.pruneExpiredMessageRequests(now);
    await this.scheduleNextAlarm(now);
    const requests = await this.state.get<string[]>(INBOX_DO_KEYS.messageRequestIndex);
    if (!requests?.length) {
      return [];
    }
    const items: MessageRequestItem[] = [];
    for (const lane of requests) {
      const entry = await this.state.get<MessageRequestEntry>(INBOX_DO_KEYS.messageRequest(lane));
      if (!entry) {
        continue;
      }
      items.push(this.toMessageRequestItem(entry));
    }
    items.sort((left, right) => left.firstSeenAt - right.firstSeenAt || left.requestId.localeCompare(right.requestId));
    return items;
  }

  async acceptMessageRequest(requestId: string, now: number): Promise<MessageRequestActionResult> {
    const entry = await this.findMessageRequest(requestId, now);
    if (!entry) {
      throw new HttpError(404, "not_found", "message request not found");
    }
    await this.registerAcceptedLane(entry.lane, now);

    let promotedCount = 0;
    for (const request of entry.pendingRequests) {
      await this.deliverEnvelope(request, now, false);
      promotedCount += 1;
    }
    await this.deleteMessageRequest(entry.lane, "accepted");
    await this.scheduleNextAlarm(now);
    return {
      accepted: true,
      requestId: entry.requestId,
      promotedCount,
      promotedConversationIds: []
    };
  }

  async rejectMessageRequest(requestId: string, now: number): Promise<MessageRequestActionResult> {
    const entry = await this.findMessageRequest(requestId, now);
    if (!entry) {
      throw new HttpError(404, "not_found", "message request not found");
    }
    await this.deleteMessageRequest(entry.lane, "rejected");
    await this.scheduleNextAlarm(now);
    return {
      accepted: true,
      requestId: entry.requestId,
      promotedCount: 0,
      promotedConversationIds: []
    };
  }

  async cleanExpiredRecords(now: number): Promise<void> {
    await this.pruneExpiredMessageRequests(now);
    const meta = await this.getMeta();
    const stored = await this.state.list<StoredRecordIndex>({ prefix: "record:" });
    const eligible = Array.from(stored.entries())
      .filter(([, index]) => index.expiresAt !== undefined && index.expiresAt <= now)
      .sort((left, right) => left[1].seq - right[1].seq);

    const expired = eligible.slice(0, CLEANUP_BATCH_SIZE);
    const deleteKeys: string[] = [];
    for (const [key, index] of expired) {
      if (index.payloadRef) {
        await this.spillStore.delete(index.payloadRef);
      }
      deleteKeys.push(
        key,
        INBOX_DO_KEYS.idempotency(index.messageId),
        INBOX_DO_KEYS.appendResult(index.messageId)
      );
    }
    if (expired.length > 0) {
      const historyFloorSeq = Math.max(
        meta.historyFloorSeq ?? 0,
        ...expired.map(([, index]) => index.seq)
      );
      await this.state.mutateEntries(
        { [INBOX_DO_KEYS.meta]: { ...meta, historyFloorSeq } satisfies InboxMeta },
        deleteKeys
      );
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

  private async materializeRecord(index: StoredRecordIndex, seq: number): Promise<InboxRecord> {
    let bytes = index.inlineBytes;
    if (!bytes && index.payloadRef) {
      let spilled: ArrayBuffer | null;
      try {
        spilled = await this.spillStore.getBytes(index.payloadRef);
      } catch {
        throw new HttpError(500, "storage_integrity_error", `inbox spill payload is invalid at seq ${seq}`);
      }
      if (!spilled) {
        throw new HttpError(500, "storage_integrity_error", `inbox spill payload is missing at seq ${seq}`);
      }
      bytes = this.encodeBytes(new Uint8Array(spilled));
    }
    const record: InboxRecord = {
      seq,
      recipientDeviceId: this.deviceId,
      messageId: index.messageId,
      receivedAt: index.receivedAt,
      expiresAt: index.expiresAt,
      state: "available",
      envelope: {
        recipientDeviceId: this.deviceId,
        lane: index.lane,
        mid: index.messageId,
        ...(bytes ? { bytes } : {}),
        ...(index.storageRef ? { storageRef: index.storageRef } : {})
      }
    };
    if (record.messageId !== index.messageId || record.recipientDeviceId !== index.recipientDeviceId) {
      throw new HttpError(500, "storage_integrity_error", `inbox record payload does not match index at seq ${seq}`);
    }
    return record;
  }

  private async getMeta(): Promise<InboxMeta> {
    return (await this.state.get<InboxMeta>(INBOX_DO_KEYS.meta)) ?? this.defaults;
  }

  private async isAcceptedLane(lane: string): Promise<boolean> {
    return (await this.state.get<AcceptedLaneRecord>(INBOX_DO_KEYS.acceptedLane(lane))) !== undefined;
  }

  private async deliverEnvelope(
    input: AppendEnvelopeRequest,
    now: number,
    persistAppendResult = true
  ): Promise<AppendEnvelopeResult> {
    const meta = await this.getMeta();
    // The idempotency map stores what the append was answered with, not where
    // the record landed: replying with a record position would put the
    // admitted/queued distinction back on the wire through the retry path.
    const existingSeq = await this.state.get<number>(INBOX_DO_KEYS.idempotency(input.envelope.mid));
    if (existingSeq !== undefined) {
      return { seq: existingSeq };
    }

    const appendSeq = meta.appendSeq + 1;
    const seq = meta.headSeq + 1;
    const expiresAt = now + meta.retentionDays * 24 * 60 * 60 * 1000;
    const bytes = input.envelope.bytes;
    const decoded = bytes ? this.decodeBytes(bytes) : null;
    const ciphertextSize = decoded?.byteLength ?? 0;
    const record: InboxRecord = {
      seq,
      recipientDeviceId: this.deviceId,
      messageId: input.envelope.mid,
      receivedAt: now,
      expiresAt,
      state: "available",
      envelope: input.envelope
    };

    let index: StoredRecordIndex;
    if (ciphertextSize > 0 && ciphertextSize <= meta.maxInlineBytes && bytes) {
      index = {
        seq,
        messageId: record.messageId,
        recipientDeviceId: record.recipientDeviceId,
        receivedAt: record.receivedAt,
        expiresAt,
        state: record.state,
        lane: input.envelope.lane,
        storageRef: input.envelope.storageRef,
        inlineBytes: bytes
      };
    } else if (decoded) {
      const payloadRef = R2_KEYS.inboxPayload();
      await this.spillStore.putBytes(payloadRef, decoded);
      index = {
        seq,
        messageId: record.messageId,
        recipientDeviceId: record.recipientDeviceId,
        receivedAt: record.receivedAt,
        expiresAt,
        state: record.state,
        lane: input.envelope.lane,
        storageRef: input.envelope.storageRef,
        payloadRef
      };
    } else {
      index = {
        seq,
        messageId: record.messageId,
        recipientDeviceId: record.recipientDeviceId,
        receivedAt: record.receivedAt,
        expiresAt,
        state: record.state,
        lane: input.envelope.lane,
        storageRef: input.envelope.storageRef
      };
    }

    const result: AppendEnvelopeResult = { seq: appendSeq };
    await this.state.putEntries({
      [INBOX_DO_KEYS.record(seq)]: index,
      [INBOX_DO_KEYS.idempotency(record.messageId)]: appendSeq,
      ...(persistAppendResult ? { [INBOX_DO_KEYS.appendResult(record.messageId)]: result } : {}),
      [INBOX_DO_KEYS.meta]: { ...meta, appendSeq, headSeq: seq } satisfies InboxMeta
    });
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

    return result;
  }

  private async queueMessageRequestWithLimit(input: AppendEnvelopeRequest, now: number): Promise<AppendEnvelopeResult> {
    await this.enforceMessageRequestRateLimit(now);
    await this.pruneExpiredMessageRequests(now);

    const limits = await this.getMeta();
    const lane = input.envelope.lane;
    const key = INBOX_DO_KEYS.messageRequest(lane);
    const existing = await this.state.get<MessageRequestEntry>(key);
    const index = (await this.state.get<string[]>(INBOX_DO_KEYS.messageRequestIndex)) ?? [];
    const queueMeta = (await this.state.get<MessageRequestQueueMeta>(INBOX_DO_KEYS.messageRequestMeta)) ?? {
      version: 1,
      totalBytes: 0,
      senderCount: index.length
    };
    const requestBytes = new TextEncoder().encode(JSON.stringify(input)).byteLength;

    if (!existing && index.length >= (limits.messageRequestMaxSenders ?? 64)) {
      this.messageRequestCapacityExceeded("message request sender capacity exceeded");
    }
    if (queueMeta.totalBytes + requestBytes > (limits.messageRequestMaxTotalBytes ?? 4 * 1024 * 1024)) {
      this.messageRequestCapacityExceeded("message request byte capacity exceeded");
    }

    const entry: MessageRequestEntry = existing ?? {
      requestId: `request:${this.randomOpaqueId()}`,
      recipientDeviceId: this.deviceId,
      lane,
      firstSeenAt: now,
      messageCount: 0,
      pendingRequests: [],
      byteSize: 0,
      expiresAt: now + (limits.messageRequestTtlSeconds ?? 7 * 24 * 60 * 60) * 1000
    };
    entry.messageCount += 1;
    entry.pendingRequests.push(input);
    entry.byteSize = (entry.byteSize ?? this.messageRequestEntryBytes(entry) - requestBytes) + requestBytes;
    entry.expiresAt ??= entry.firstSeenAt + (limits.messageRequestTtlSeconds ?? 7 * 24 * 60 * 60) * 1000;

    const nextIndex = index.includes(lane) ? index : [...index, lane].sort();
    const nextQueueMeta: MessageRequestQueueMeta = {
      version: 1,
      totalBytes: queueMeta.totalBytes + requestBytes,
      senderCount: nextIndex.length
    };
    // The same counter the admitted path draws from, advanced in the same
    // batch that commits the queued envelope. `headSeq` stays where it is:
    // this record has no position in the record stream yet, and giving it one
    // would leave a hole that the next fetch covering it reports as a storage
    // integrity error.
    const meta = await this.getMeta();
    const appendSeq = meta.appendSeq + 1;
    const result: AppendEnvelopeResult = { seq: appendSeq };
    await this.state.putEntries({
      [key]: entry,
      [INBOX_DO_KEYS.messageRequestIndex]: nextIndex,
      [INBOX_DO_KEYS.messageRequestMeta]: nextQueueMeta,
      [INBOX_DO_KEYS.meta]: { ...meta, appendSeq } satisfies InboxMeta,
      [INBOX_DO_KEYS.appendResult(input.envelope.mid)]: result
    });
    await this.scheduleNextAlarm(now);
    this.publish({
      event: "message_request_changed",
      deviceId: this.deviceId,
      requestId: entry.requestId,
      change: "queued"
    });
    return result;
  }

  private messageRequestCapacityExceeded(message: string): never {
    throw new HttpError(429, "message_request_capacity_exceeded", message);
  }

  private async enforceRateLimit(key: string, now: number): Promise<void> {
    const meta = await this.getMeta();
    const minuteLimit = meta.rateLimitPerMinute;
    const hourLimit = meta.rateLimitPerHour;
    if (minuteLimit <= 0 && hourLimit <= 0) {
      return;
    }

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
    const state = (await this.state.get<RateLimitState>(INBOX_DO_KEYS.messageRequestRateLimit)) ?? {
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
    await this.state.put(INBOX_DO_KEYS.messageRequestRateLimit, state);
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
    this.assertOpaqueId(input.envelope.lane, "lane");
    this.assertOpaqueId(input.envelope.mid, "mid");
    const hasBytes = Boolean(input.envelope.bytes);
    const hasStorageRef = Boolean(input.envelope.storageRef?.ref);
    if (!hasBytes && !hasStorageRef) {
      throw new HttpError(400, "invalid_input", "envelope must include bytes or a storage_ref");
    }
    const size = new TextEncoder().encode(JSON.stringify(input.envelope)).byteLength;
    if (size > ENVELOPE_MAX_BYTES) {
      throw new HttpError(413, "payload_too_large", "envelope exceeds worker size limit");
    }
  }

  private assertOpaqueId(value: string, field: string): void {
    if (!OPAQUE_ID.test(value)) {
      throw new HttpError(400, "invalid_input", `${field} must be a 128-bit hex id`);
    }
  }

  private async deleteMessageRequest(
    lane: string,
    change: "accepted" | "rejected"
  ): Promise<void> {
    const existing = await this.state.get<MessageRequestEntry>(INBOX_DO_KEYS.messageRequest(lane));
    const index = (await this.state.get<string[]>(INBOX_DO_KEYS.messageRequestIndex)) ?? [];
    const nextIndex = index.filter((entry) => entry !== lane);
    const queueMeta = (await this.state.get<MessageRequestQueueMeta>(INBOX_DO_KEYS.messageRequestMeta)) ?? {
      version: 1,
      totalBytes: 0,
      senderCount: index.length
    };
    await this.state.mutateEntries({
      [INBOX_DO_KEYS.messageRequestIndex]: nextIndex,
      [INBOX_DO_KEYS.messageRequestMeta]: {
        version: 1,
        totalBytes: Math.max(0, queueMeta.totalBytes - (existing ? this.messageRequestEntryBytes(existing) : 0)),
        senderCount: nextIndex.length
      } satisfies MessageRequestQueueMeta
    }, [INBOX_DO_KEYS.messageRequest(lane)]);
    if (existing) {
      this.publish({
        event: "message_request_changed",
        deviceId: this.deviceId,
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
    const index = (await this.state.get<string[]>(INBOX_DO_KEYS.messageRequestIndex)) ?? [];
    for (const lane of index) {
      const entry = await this.state.get<MessageRequestEntry>(INBOX_DO_KEYS.messageRequest(lane));
      if (entry?.requestId === requestId) {
        return entry;
      }
    }
    return null;
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
    const index = (await this.state.get<string[]>(INBOX_DO_KEYS.messageRequestIndex)) ?? [];
    const retained: string[] = [];
    const updates: Record<string, unknown> = {};
    const deleteKeys: string[] = [];
    let totalBytes = 0;

    for (const lane of index) {
      const key = INBOX_DO_KEYS.messageRequest(lane);
      const entry = await this.state.get<MessageRequestEntry>(key);
      if (!entry) {
        continue;
      }
      const byteSize = this.messageRequestEntryBytes(entry);
      const expiresAt = entry.expiresAt ?? entry.firstSeenAt + (limits.messageRequestTtlSeconds ?? 7 * 24 * 60 * 60) * 1000;
      if (expiresAt <= now) {
        deleteKeys.push(key);
        for (const pending of entry.pendingRequests) {
          deleteKeys.push(INBOX_DO_KEYS.appendResult(pending.envelope.mid));
        }
        continue;
      }
      retained.push(lane);
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

    updates[INBOX_DO_KEYS.messageRequestIndex] = retained.sort();
    updates[INBOX_DO_KEYS.messageRequestMeta] = {
      version: 1,
      totalBytes,
      senderCount: retained.length
    } satisfies MessageRequestQueueMeta;
    await this.state.mutateEntries(updates, deleteKeys);
  }

  private async scheduleNextAlarm(now: number): Promise<void> {
    const records = await this.state.list<StoredRecordIndex>({ prefix: "record:" });
    const messageRequestLanes = (await this.state.get<string[]>(INBOX_DO_KEYS.messageRequestIndex)) ?? [];
    let nextAt: number | undefined;

    for (const record of records.values()) {
      if (record.expiresAt === undefined) {
        continue;
      }
      nextAt = nextAt === undefined ? record.expiresAt : Math.min(nextAt, record.expiresAt);
    }
    for (const lane of messageRequestLanes) {
      const entry = await this.state.get<MessageRequestEntry>(INBOX_DO_KEYS.messageRequest(lane));
      if (entry?.expiresAt !== undefined) {
        nextAt = nextAt === undefined ? entry.expiresAt : Math.min(nextAt, entry.expiresAt);
      }
    }
    if (nextAt !== undefined) {
      await this.state.setAlarm(Math.max(now + 1, nextAt));
    }
  }

  private toMessageRequestItem(entry: MessageRequestEntry): MessageRequestItem {
    return {
      requestId: entry.requestId,
      firstSeenAt: entry.firstSeenAt,
      messageCount: entry.messageCount,
      welcomeBytes: entry.pendingRequests[0]?.envelope.bytes
    };
  }

  private decodeBytes(value: string): Uint8Array {
    try {
      const binary = atob(value);
      const bytes = new Uint8Array(binary.length);
      for (let index = 0; index < binary.length; index += 1) {
        bytes[index] = binary.charCodeAt(index);
      }
      return bytes;
    } catch {
      throw new HttpError(400, "invalid_input", "bytes must be valid base64");
    }
  }

  private encodeBytes(bytes: Uint8Array): string {
    let binary = "";
    for (const byte of bytes) {
      binary += String.fromCharCode(byte);
    }
    return btoa(binary);
  }

  private randomOpaqueId(): string {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  }
}

import { HttpError } from "../auth/capability";
import type {
  AckRequest,
  AckResult,
  AppendEnvelopeRequest,
  AppendEnvelopeResult,
  FetchMessagesRequest,
  FetchMessagesResult,
  InboxRecord,
  RealtimeEvent
} from "../types/contracts";
import type { DurableObjectStorageLike, JsonBlobStore, SessionSink } from "../types/runtime";

interface InboxMeta {
  headSeq: number;
  ackedSeq: number;
  retentionDays: number;
  maxInlineBytes: number;
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

const META_KEY = "meta";
const IDEMPOTENCY_PREFIX = "idempotency:";
const RECORD_PREFIX = "record:";

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
    const meta = await this.getMeta();
    const existingSeq = await this.state.get<number>(`${IDEMPOTENCY_PREFIX}${input.envelope.messageId}`);
    if (existingSeq !== undefined) {
      return { accepted: true, seq: existingSeq };
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

    return { accepted: true, seq };
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
        throw new HttpError(500, "temporary_unavailable", "record payload is missing");
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
    const ackSeq = Math.max(meta.ackedSeq, input.ack.ackSeq);
    await this.state.put(META_KEY, { ...meta, ackedSeq: ackSeq });
    await this.state.setAlarm(Date.now());
    return { accepted: true, ackSeq };
  }

  async getHead(): Promise<{ headSeq: number }> {
    const meta = await this.getMeta();
    return { headSeq: meta.headSeq };
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
}

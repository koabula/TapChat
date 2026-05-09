import { HttpError } from "../auth/capability";
import type {
  AppendGroupEnvelopeRequest,
  AppendGroupEnvelopeResult,
  FetchGroupOutboxRequest,
  FetchGroupOutboxResult,
  GetGroupOutboxHeadResult,
  GroupEnvelope,
  GroupOutboxRecord
} from "../types/contracts";
import type { DurableObjectStorageLike, JsonBlobStore } from "../types/runtime";

interface GroupOutboxMeta {
  headSeq: number;
  retentionDays: number;
  maxInlineBytes: number;
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

export class GroupOutboxService {
  private readonly groupId: string;
  private readonly state: DurableObjectStorageLike;
  private readonly spillStore: JsonBlobStore;
  private readonly defaults: GroupOutboxMeta;

  constructor(
    groupId: string,
    state: DurableObjectStorageLike,
    spillStore: JsonBlobStore,
    defaults: GroupOutboxMeta
  ) {
    this.groupId = groupId;
    this.state = state;
    this.spillStore = spillStore;
    this.defaults = defaults;
  }

  async appendEnvelope(input: AppendGroupEnvelopeRequest, now: number): Promise<AppendGroupEnvelopeResult> {
    this.validateAppendRequest(input);

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

  private async getMeta(): Promise<GroupOutboxMeta> {
    return (await this.state.get<GroupOutboxMeta>(META_KEY)) ?? this.defaults;
  }

  private validateAppendRequest(input: AppendGroupEnvelopeRequest): void {
    if (input.groupId !== this.groupId || input.envelope.groupId !== this.groupId) {
      throw new HttpError(400, "invalid_input", "group_id does not match group outbox route");
    }
    this.validateEnvelope(input.envelope);
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
}

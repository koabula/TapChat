import { HttpError } from "../auth/capability";
import { GroupOutboxService } from "./service";
import type { AppendGroupEnvelopeRequest, FetchGroupOutboxRequest } from "../types/contracts";
import type { DurableObjectStorageLike, Env, JsonBlobStore } from "../types/runtime";

class DurableObjectStorageAdapter implements DurableObjectStorageLike {
  private readonly storage: DurableObjectState["storage"];

  constructor(storage: DurableObjectState["storage"]) {
    this.storage = storage;
  }

  async get<T>(key: string): Promise<T | undefined> {
    return (await this.storage.get<T>(key)) ?? undefined;
  }

  async put<T>(key: string, value: T): Promise<void> {
    await this.storage.put(key, value);
  }

  async delete(key: string): Promise<void> {
    await this.storage.delete(key);
  }

  async setAlarm(epochMillis: number): Promise<void> {
    await this.storage.setAlarm(epochMillis);
  }
}

class R2JsonBlobStore implements JsonBlobStore {
  private readonly bucket: Env["TAPCHAT_STORAGE"];

  constructor(bucket: Env["TAPCHAT_STORAGE"]) {
    this.bucket = bucket;
  }

  async putJson<T>(key: string, value: T): Promise<void> {
    await this.bucket.put(key, JSON.stringify(value));
  }

  async getJson<T>(key: string): Promise<T | null> {
    const object = await this.bucket.get(key);
    if (!object) {
      return null;
    }
    return await object.json<T>();
  }

  async putBytes(key: string, value: ArrayBuffer | Uint8Array): Promise<void> {
    await this.bucket.put(key, value);
  }

  async getBytes(key: string): Promise<ArrayBuffer | null> {
    const object = await this.bucket.get(key);
    if (!object) {
      return null;
    }
    return object.arrayBuffer();
  }

  async delete(key: string): Promise<void> {
    await this.bucket.delete(key);
  }
}

function versionedBody(body: unknown): unknown {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return body;
  }
  const record = body as Record<string, unknown>;
  if (record.version !== undefined) {
    return body;
  }
  return {
    version: "0.1",
    ...record
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(versionedBody(body)), {
    status,
    headers: {
      "content-type": "application/json"
    }
  });
}

const DurableObjectBase: typeof DurableObject =
  (globalThis as { DurableObject?: typeof DurableObject }).DurableObject ??
  (class {
    constructor(_state: DurableObjectState, _env: Env) {}
  } as unknown as typeof DurableObject);

export async function handleGroupOutboxDurableRequest(
  request: Request,
  deps: {
    groupId: string;
    state: DurableObjectStorageLike;
    spillStore: JsonBlobStore;
    maxInlineBytes: number;
    retentionDays: number;
    now?: number;
  }
): Promise<Response> {
  const now = deps.now ?? Date.now();
  const url = new URL(request.url);
  const service = new GroupOutboxService(deps.groupId, deps.state, deps.spillStore, {
    headSeq: 0,
    retentionDays: deps.retentionDays,
    maxInlineBytes: deps.maxInlineBytes
  });

  try {
    if (url.pathname.endsWith("/messages") && request.method === "POST") {
      const body = (await request.json()) as AppendGroupEnvelopeRequest;
      return jsonResponse(await service.appendEnvelope(body, now));
    }

    if (url.pathname.endsWith("/messages") && request.method === "GET") {
      const fromSeq = Number(url.searchParams.get("fromSeq") ?? "1");
      const limit = Number(url.searchParams.get("limit") ?? "100");
      const capability = JSON.parse(request.headers.get("X-Tapchat-Group-Capability") ?? "{}");
      return jsonResponse(await service.fetchOutbox({
        groupId: deps.groupId,
        fromSeq,
        limit,
        capability
      } as FetchGroupOutboxRequest));
    }

    if (url.pathname.endsWith("/head") && request.method === "GET") {
      return jsonResponse(await service.getHead());
    }

    return jsonResponse({ error: "not_found" }, 404);
  } catch (error) {
    if (error instanceof HttpError) {
      return jsonResponse({ error: error.code, message: error.message }, error.status);
    }
    const runtimeError = error as { message?: string };
    const message = runtimeError.message ?? "internal error";
    return jsonResponse({ error: "temporary_unavailable", message }, 500);
  }
}

export class GroupOutboxDurableObject extends DurableObjectBase {
  private readonly stateRef: DurableObjectState;
  private readonly envRef: Env;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.stateRef = state;
    this.envRef = env;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const match = url.pathname.match(/\/v1\/groups\/([^/]+)\/outbox\//);
    const groupId = decodeURIComponent(match?.[1] ?? "");

    return handleGroupOutboxDurableRequest(request, {
      groupId,
      state: new DurableObjectStorageAdapter(this.stateRef.storage),
      spillStore: new R2JsonBlobStore(this.envRef.TAPCHAT_STORAGE),
      maxInlineBytes: Number(this.envRef.MAX_INLINE_BYTES ?? "4096"),
      retentionDays: Number(this.envRef.RETENTION_DAYS ?? "30")
    });
  }
}

import { HttpError } from "../auth/capability";
import { InboxService } from "./service";
import type {
  AckRequest,
  AllowlistDocument,
  AppendEnvelopeRequest,
  FetchMessagesRequest
} from "../types/contracts";
import type { DurableObjectStorageLike, Env, JsonBlobStore, SessionSink } from "../types/runtime";

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

export async function handleInboxDurableRequest(
  request: Request,
  deps: {
    deviceId: string;
    state: DurableObjectStorageLike;
    spillStore: JsonBlobStore;
    sessions: SessionSink[];
    maxInlineBytes: number;
    retentionDays: number;
    rateLimitPerMinute: number;
    rateLimitPerHour: number;
    onUpgrade?: () => Response;
    now?: number;
  }
): Promise<Response> {
  const now = deps.now ?? Date.now();
  const url = new URL(request.url);
  const service = new InboxService(deps.deviceId, deps.state, deps.spillStore, deps.sessions, {
    headSeq: 0,
    ackedSeq: 0,
    retentionDays: deps.retentionDays,
    maxInlineBytes: deps.maxInlineBytes,
    rateLimitPerMinute: deps.rateLimitPerMinute,
    rateLimitPerHour: deps.rateLimitPerHour
  });

  try {
    if (url.pathname.endsWith("/subscribe")) {
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
        throw new HttpError(400, "invalid_input", "subscribe requires websocket upgrade");
      }
      if (!deps.onUpgrade) {
        throw new HttpError(500, "temporary_unavailable", "websocket upgrade handler is unavailable");
      }
      return deps.onUpgrade();
    }

    if (url.pathname.endsWith("/message-requests") && request.method === "GET") {
      return jsonResponse({ requests: await service.listMessageRequests() });
    }

    const requestActionMatch = url.pathname.match(/\/message-requests\/([^/]+)\/(accept|reject)$/);
    if (requestActionMatch && request.method === "POST") {
      const requestId = decodeURIComponent(requestActionMatch[1]);
      const action = requestActionMatch[2];
      const result = action === "accept"
        ? await service.acceptMessageRequest(requestId, now)
        : await service.rejectMessageRequest(requestId, now);
      return jsonResponse(result);
    }

    if (url.pathname.endsWith("/allowlist") && request.method === "GET") {
      return jsonResponse(await service.getAllowlist(now));
    }

    if (url.pathname.endsWith("/allowlist") && request.method === "PUT") {
      const body = (await request.json()) as Partial<AllowlistDocument>;
      const result = await service.replaceAllowlist(
        body.allowedSenderUserIds ?? [],
        body.rejectedSenderUserIds ?? [],
        now
      );
      return jsonResponse(result);
    }

    if (url.pathname.endsWith("/messages") && request.method === "POST") {
      const body = (await request.json()) as AppendEnvelopeRequest;
      const result = await service.appendEnvelope(body, now);
      return jsonResponse(result);
    }

    if (url.pathname.endsWith("/messages") && request.method === "GET") {
      const fromSeq = Number(url.searchParams.get("fromSeq") ?? "1");
      const limit = Number(url.searchParams.get("limit") ?? "100");
      const result = await service.fetchMessages({
        deviceId: deps.deviceId,
        fromSeq,
        limit
      } as FetchMessagesRequest);
      return jsonResponse({
        toSeq: result.toSeq,
        records: result.records
      });
    }

    if (url.pathname.endsWith("/ack") && request.method === "POST") {
      const body = (await request.json()) as AckRequest;
      const result = await service.ack(body);
      return jsonResponse({
        accepted: result.accepted,
        ackSeq: result.ackSeq
      });
    }

    if (url.pathname.endsWith("/head") && request.method === "GET") {
      const result = await service.getHead();
      return jsonResponse(result);
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

export class InboxDurableObject extends DurableObjectBase {
  private readonly sessions = new Map<string, ManagedSession>();
  private readonly stateRef: DurableObjectState;
  private readonly envRef: Env;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.stateRef = state;
    this.envRef = env;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const match = url.pathname.match(/\/v1\/inbox\/([^/]+)\//);
    const deviceId = decodeURIComponent(match?.[1] ?? "");

    return handleInboxDurableRequest(request, {
      deviceId,
      state: new DurableObjectStorageAdapter(this.stateRef.storage),
      spillStore: new R2JsonBlobStore(this.envRef.TAPCHAT_STORAGE),
      sessions: Array.from(this.sessions.values()).map(
        (session) =>
          ({
            send(payload: string): void {
              session.send(payload);
            }
          }) satisfies SessionSink
      ),
      maxInlineBytes: Number(this.envRef.MAX_INLINE_BYTES ?? "4096"),
      retentionDays: Number(this.envRef.RETENTION_DAYS ?? "30"),
      rateLimitPerMinute: Number(this.envRef.RATE_LIMIT_PER_MINUTE ?? "60"),
      rateLimitPerHour: Number(this.envRef.RATE_LIMIT_PER_HOUR ?? "600"),
      onUpgrade: () => {
        const pair = new WebSocketPair();
        const client = pair[0];
        const server = pair[1];
        server.accept();
        const sessionId = crypto.randomUUID();
        const session = new ManagedSession(server);
        this.sessions.set(sessionId, session);
        queueMicrotask(() => {
          session.markReady();
        });
        server.addEventListener("close", () => {
          this.sessions.delete(sessionId);
        });
        return new Response(null, {
          status: 101,
          webSocket: client
        } as ResponseInit & { webSocket: WebSocket });
      }
    });
  }

  async alarm(): Promise<void> {
    const service = new InboxService(
      "",
      new DurableObjectStorageAdapter(this.stateRef.storage),
      new R2JsonBlobStore(this.envRef.TAPCHAT_STORAGE),
      [],
      {
        headSeq: 0,
        ackedSeq: 0,
        retentionDays: Number(this.envRef.RETENTION_DAYS ?? "30"),
        maxInlineBytes: Number(this.envRef.MAX_INLINE_BYTES ?? "4096"),
        rateLimitPerMinute: Number(this.envRef.RATE_LIMIT_PER_MINUTE ?? "60"),
        rateLimitPerHour: Number(this.envRef.RATE_LIMIT_PER_HOUR ?? "600")
      }
    );
    await service.cleanExpiredRecords(Date.now());
  }
}

class ManagedSession {
  private readonly socket: WebSocket;
  private ready = false;
  private readonly queuedPayloads: string[] = [];

  constructor(socket: WebSocket) {
    this.socket = socket;
  }

  send(payload: string): void {
    if (!this.ready) {
      this.queuedPayloads.push(payload);
      return;
    }
    this.dispatch(payload);
  }

  markReady(): void {
    if (this.ready) {
      return;
    }
    this.ready = true;
    while (this.queuedPayloads.length > 0) {
      const payload = this.queuedPayloads.shift();
      if (payload === undefined) {
        break;
      }
      this.dispatch(payload);
    }
  }

  private dispatch(payload: string): void {
    setTimeout(() => {
      this.socket.send(payload);
    }, 0);
  }
}

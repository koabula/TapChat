import {
  APPEND_AUTH_CONTEXT_HEADER,
  APPEND_AUTH_REASON_HEADER,
  HttpError
} from "../auth/capability";
import {
  RELATIONSHIP_AUTHORIZATION_HEADER,
  verifyRelationshipAuthorization
} from "../auth/internal-relationship";
import type { DurableObject as CloudflareDurableObject } from "cloudflare:workers";
import { CONTROL_JSON_MAX_BYTES, DEFAULT_MESSAGE_REQUEST_MAX_BODY_BYTES, readJsonLimited } from "../auth/runtime-security";
import { InboxService } from "./service";
import type {
  AckRequest,
  AllowlistDocument,
  AppendEnvelopeRequest,
  FetchMessagesRequest
} from "../types/contracts";
import type { Env } from "../types/env";
import type { DurableObjectStorageLike, JsonBlobStore, SessionSink } from "../types/runtime";
import { appErrorBody } from "../errors";

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

  async putEntries(entries: Record<string, unknown>): Promise<void> {
    await (this.storage.put as unknown as (values: Record<string, unknown>) => Promise<void>)(entries);
  }

  async mutateEntries(entries: Record<string, unknown>, deleteKeys: string[]): Promise<void> {
    await this.storage.transaction(async (transaction) => {
      if (Object.keys(entries).length > 0) {
        await (transaction.put as unknown as (values: Record<string, unknown>) => Promise<void>)(entries);
      }
      if (deleteKeys.length > 0) {
        await transaction.delete(deleteKeys);
      }
    });
  }

  async delete(key: string): Promise<void> {
    await this.storage.delete(key);
  }

  async list<T>(options?: { prefix?: string }): Promise<Map<string, T>> {
    return this.storage.list<T>(options);
  }

  async setAlarm(epochMillis: number): Promise<void> {
    await this.storage.setAlarm(epochMillis);
  }

  async consumeIfEqual<T>(key: string, expected: T): Promise<boolean> {
    return this.storage.transaction(async (transaction) => {
      const current = await transaction.get<T>(key);
      if (!current || JSON.stringify(current) !== JSON.stringify(expected)) return false;
      await transaction.delete(key);
      return true;
    });
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

function jsonResponse(body: unknown, status = 200, headers?: Record<string, string>): Response {
  return new Response(JSON.stringify(versionedBody(body)), {
    status,
    headers: {
      "content-type": "application/json",
      ...headers
    }
  });
}

const DurableObjectBase: typeof CloudflareDurableObject<Env> =
  (globalThis as { DurableObject?: typeof CloudflareDurableObject<Env> }).DurableObject ??
  (class {
    constructor(_state: DurableObjectState, _env: Env) {}
  } as unknown as typeof CloudflareDurableObject<Env>);

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
    messageRequestMaxBodyBytes?: number;
    messageRequestMaxPerSender?: number;
    messageRequestMaxSenders?: number;
    messageRequestMaxTotalBytes?: number;
    messageRequestTtlSeconds?: number;
    messageRequestRateLimitMinute?: number;
    messageRequestRateLimitHour?: number;
    internalRelationshipSecret?: string;
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
    rateLimitPerHour: deps.rateLimitPerHour,
    messageRequestMaxPerSender: deps.messageRequestMaxPerSender ?? 16,
    messageRequestMaxSenders: deps.messageRequestMaxSenders ?? 64,
    messageRequestMaxTotalBytes: deps.messageRequestMaxTotalBytes ?? 4 * 1024 * 1024,
    messageRequestTtlSeconds: deps.messageRequestTtlSeconds ?? 7 * 24 * 60 * 60,
    messageRequestRateLimitMinute: deps.messageRequestRateLimitMinute ?? 30,
    messageRequestRateLimitHour: deps.messageRequestRateLimitHour ?? 300
  });

  try {
    if (url.pathname.endsWith("/internal/relationships/promote") && request.method === "POST") {
      if (
        !deps.internalRelationshipSecret ||
        request.headers.get("X-Tapchat-Internal-Secret") !== deps.internalRelationshipSecret
      ) {
        throw new HttpError(403, "invalid_capability", "internal relationship authorization failed");
      }
      const body = await readJsonLimited<{
        senderUserId?: string;
        proposalId?: string;
        decision?: "accept" | "reject";
      }>(
        request,
        CONTROL_JSON_MAX_BYTES
      );
      if (!body.senderUserId || !body.proposalId || !body.decision) {
        throw new HttpError(400, "invalid_input", "relationship promotion context is incomplete");
      }
      if (body.decision === "reject") {
        await service.discardRelationshipRequest(body.senderUserId, now);
        return jsonResponse({ promotedCount: 0 });
      }
      return jsonResponse(await service.promoteRelationshipRequest(body.senderUserId, body.proposalId, now));
    }
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
      return jsonResponse({ requests: await service.listMessageRequests(now) });
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
      const body = await readJsonLimited<Partial<AllowlistDocument>>(request, CONTROL_JSON_MAX_BYTES);
      const result = await service.replaceAllowlist(
        body.allowedSenderUserIds ?? [],
        body.rejectedSenderUserIds ?? [],
        now
      );
      return jsonResponse(result);
    }

    if (url.pathname.endsWith("/messages") && request.method === "POST") {
      const body = await readJsonLimited<AppendEnvelopeRequest>(
        request,
        deps.messageRequestMaxBodyBytes ?? DEFAULT_MESSAGE_REQUEST_MAX_BODY_BYTES
      );
      const relationshipAuthorized = deps.internalRelationshipSecret
        ? await verifyRelationshipAuthorization(
            deps.internalRelationshipSecret,
            request.headers.get(RELATIONSHIP_AUTHORIZATION_HEADER),
            deps.deviceId,
            body.envelope.messageId
          )
        : false;
      const mode = relationshipAuthorized
        ? "relationship_accepted"
        : request.headers.get(APPEND_AUTH_CONTEXT_HEADER) === "legacy_unverified"
          ? "legacy_unverified"
          : "verified";
      const result = await service.appendEnvelope(body, now, {
        mode,
        reason: request.headers.get(APPEND_AUTH_REASON_HEADER) ?? undefined
      });
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
        historyFloorSeq: result.historyFloorSeq,
        records: result.records
      });
    }

    if (url.pathname.endsWith("/ack") && request.method === "POST") {
      const body = await readJsonLimited<AckRequest>(request, CONTROL_JSON_MAX_BYTES);
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

    return jsonResponse(appErrorBody(404, "not_found", crypto.randomUUID()), 404);
  } catch (error) {
    if (error instanceof HttpError) {
      const retryAfter = error.details?.retryAfterSeconds;
      return jsonResponse(
        appErrorBody(error.status, error.code, crypto.randomUUID()),
        error.status,
        typeof retryAfter === "number" ? { "Retry-After": String(retryAfter) } : undefined
      );
    }
    return jsonResponse(appErrorBody(500, "temporary_unavailable", crypto.randomUUID()), 500);
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
    const match = url.pathname.match(/\/v[12]\/inbox\/([^/]+)\//);
    const deviceId = decodeURIComponent(match?.[1] ?? "");

    return handleInboxDurableRequest(request, {
      deviceId,
      state: new DurableObjectStorageAdapter(this.stateRef.storage),
      spillStore: new R2JsonBlobStore(this.envRef.TAPCHAT_STORAGE),
      sessions: Array.from(this.sessions.values()).map(
        (session) =>
          ({
            send(payload: string): boolean {
              return session.send(payload);
            }
          }) satisfies SessionSink
      ),
      maxInlineBytes: Number(this.envRef.MAX_INLINE_BYTES ?? "4096"),
      retentionDays: Number(this.envRef.RETENTION_DAYS ?? "30"),
      rateLimitPerMinute: Number(this.envRef.RATE_LIMIT_PER_MINUTE ?? "60"),
      rateLimitPerHour: Number(this.envRef.RATE_LIMIT_PER_HOUR ?? "600"),
      messageRequestMaxBodyBytes: Number(this.envRef.MESSAGE_REQUEST_MAX_BODY_BYTES ?? String(DEFAULT_MESSAGE_REQUEST_MAX_BODY_BYTES)),
      messageRequestMaxPerSender: Number(this.envRef.MESSAGE_REQUEST_MAX_PER_SENDER ?? "16"),
      messageRequestMaxSenders: Number(this.envRef.MESSAGE_REQUEST_MAX_SENDERS ?? "64"),
      messageRequestMaxTotalBytes: Number(this.envRef.MESSAGE_REQUEST_MAX_TOTAL_BYTES ?? String(4 * 1024 * 1024)),
      messageRequestTtlSeconds: Number(this.envRef.MESSAGE_REQUEST_TTL_SECONDS ?? String(7 * 24 * 60 * 60)),
      messageRequestRateLimitMinute: Number(this.envRef.MESSAGE_REQUEST_RATE_LIMIT_MINUTE ?? "30"),
      messageRequestRateLimitHour: Number(this.envRef.MESSAGE_REQUEST_RATE_LIMIT_HOUR ?? "300"),
      internalRelationshipSecret: this.envRef.SHARING_INTERNAL_SECRET?.trim(),
      onUpgrade: () => {
        const pair = new WebSocketPair();
        const client = pair[0];
        const server = pair[1];
        server.accept();
        const sessionId = crypto.randomUUID();
        const removeSession = () => {
          this.sessions.delete(sessionId);
        };
        const session = new ManagedSession(server, removeSession);
        this.sessions.set(sessionId, session);
        server.addEventListener("close", () => {
          session.terminate();
        });
        server.addEventListener("error", (event: Event) => {
          event.preventDefault();
          session.terminate();
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
        rateLimitPerHour: Number(this.envRef.RATE_LIMIT_PER_HOUR ?? "600"),
        messageRequestMaxPerSender: Number(this.envRef.MESSAGE_REQUEST_MAX_PER_SENDER ?? "16"),
        messageRequestMaxSenders: Number(this.envRef.MESSAGE_REQUEST_MAX_SENDERS ?? "64"),
        messageRequestMaxTotalBytes: Number(this.envRef.MESSAGE_REQUEST_MAX_TOTAL_BYTES ?? String(4 * 1024 * 1024)),
        messageRequestTtlSeconds: Number(this.envRef.MESSAGE_REQUEST_TTL_SECONDS ?? String(7 * 24 * 60 * 60)),
        messageRequestRateLimitMinute: Number(this.envRef.MESSAGE_REQUEST_RATE_LIMIT_MINUTE ?? "30"),
        messageRequestRateLimitHour: Number(this.envRef.MESSAGE_REQUEST_RATE_LIMIT_HOUR ?? "300")
      }
    );
    await service.cleanExpiredRecords(Date.now());
  }
}

export class ManagedSession {
  private readonly socket: WebSocket;
  private readonly onClosed: () => void;
  private closed = false;

  constructor(socket: WebSocket, onClosed: () => void) {
    this.socket = socket;
    this.onClosed = onClosed;
  }

  send(payload: string): boolean {
    if (this.closed) {
      return false;
    }
    if (this.socket.readyState !== 1) {
      this.finish(false);
      return false;
    }
    try {
      this.socket.send(payload);
      return true;
    } catch {
      this.close();
      return false;
    }
  }

  close(): void {
    this.finish(true);
  }

  terminate(): void {
    this.finish(false);
  }

  private finish(closeSocket: boolean): void {
    if (this.closed) {
      return;
    }
    this.closed = true;
    if (closeSocket) {
      try {
        this.socket.close(1011, "session closed");
      } catch {
        // The peer may already have closed the socket.
      }
    }
    this.onClosed();
  }
}

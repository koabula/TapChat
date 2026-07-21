import {
  allowedGroupAppendRoles,
  getBearerToken,
  HttpError,
  readGroupCapabilityHeader,
  requiredGroupAppendOperations,
  validateAnyDeviceRuntimeAuthorization
} from "../auth/capability";
import type { DurableObject as CloudflareDurableObject } from "cloudflare:workers";
import {
  CONTROL_JSON_MAX_BYTES,
  DEFAULT_MESSAGE_REQUEST_MAX_BODY_BYTES,
  readJsonLimited,
  requireDeviceRuntimeSecrets,
  requireSharingSecret
} from "../auth/runtime-security";
import type { RotatingSecretSet } from "../auth/runtime-security";
import { GroupOutboxService } from "./service";
import { GroupAuthorizationService } from "./authorization";
import { signSharingPayload, verifySharingPayload } from "../storage/sharing";
import type {
  AppendGroupEnvelopeRequest,
  AppendGroupTransitionRequest,
  ClaimGroupJoinRequest,
  ClaimGroupLeaveRequest,
  CompleteGroupJoinRequest,
  CreateGroupInviteRequest,
  DecideGroupJoinRequest,
  FetchGroupOutboxRequest,
  InitializeGroupAuthorizationRequest,
  GroupInviteTokenPayload,
  RevokeGroupInviteRequest,
  SubmitGroupJoinRequest
  ,SubmitGroupLeaveRequest
} from "../types/contracts";
import type { Env } from "../types/env";
import type { DurableObjectStorageLike, JsonBlobStore, SessionSink } from "../types/runtime";

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

const DurableObjectBase: typeof CloudflareDurableObject<Env> =
  (globalThis as { DurableObject?: typeof CloudflareDurableObject<Env> }).DurableObject ??
  (class {
    constructor(_state: DurableObjectState, _env: Env) {}
  } as unknown as typeof CloudflareDurableObject<Env>);

export async function handleGroupOutboxDurableRequest(
  request: Request,
  deps: {
    groupId: string;
    state: DurableObjectStorageLike;
    spillStore: JsonBlobStore;
    sessions: SessionSink[];
    maxInlineBytes: number;
    retentionDays: number;
    sharingSecret: string;
    deviceRuntimeSecrets: RotatingSecretSet;
    now?: number;
    onUpgrade?: () => Response;
  }
): Promise<Response> {
  const now = deps.now ?? Date.now();
  const url = new URL(request.url);
  const service = new GroupOutboxService(deps.groupId, deps.state, deps.spillStore, {
    headSeq: 0,
    retentionDays: deps.retentionDays,
    maxInlineBytes: deps.maxInlineBytes
  }, deps.sessions);
  const authorization = new GroupAuthorizationService(deps.groupId, deps.state);

  try {
    if (url.pathname.endsWith("/authorization/bootstrap") && request.method === "POST") {
      const runtimeToken = await validateAnyDeviceRuntimeAuthorization(
        request,
        deps.deviceRuntimeSecrets,
        "group_authorization_bootstrap",
        now
      );
      const body = await readJsonLimited<InitializeGroupAuthorizationRequest>(request, CONTROL_JSON_MAX_BYTES);
      return jsonResponse(await authorization.initialize(body, runtimeToken, now));
    }

    if (url.pathname.endsWith("/subscribe") && deps.onUpgrade) {
      await authorization.authorize(
        request,
        readGroupCapabilityHeader(request),
        "subscribe",
        ["owner", "admin", "member"],
        now
      );
      return deps.onUpgrade();
    }

    if (url.pathname.endsWith("/outbox/transitions") && request.method === "POST") {
      const body = await readJsonLimited<AppendGroupTransitionRequest>(request, DEFAULT_MESSAGE_REQUEST_MAX_BODY_BYTES);
      if (!body.capability || body.groupId !== deps.groupId) {
        throw new HttpError(403, "invalid_capability", "missing or mismatched group transition capability");
      }
      let authState;
      const isCreate = body.operation?.type === "create";
      for (const envelope of body.envelopes ?? []) {
        if (
          envelope.senderUserId !== body.capability.userId ||
          envelope.senderDeviceId !== body.capability.deviceId
        ) {
          throw new HttpError(403, "invalid_capability", "group capability does not match transition sender");
        }
        for (const operation of requiredGroupAppendOperations(envelope.messageType)) {
          authState = await authorization.authorize(
            request,
            body.capability,
            operation,
            allowedGroupAppendRoles(envelope.messageType),
            now,
            false,
            isCreate
          );
        }
      }
      if (!authState) {
        throw new HttpError(400, "invalid_input", "group transition contains no envelopes");
      }
      if (isCreate && authState.role !== "owner") {
        throw new HttpError(403, "invalid_capability", "only the current owner may commit group genesis");
      }
      const authoritativeManifest = authState.state.manifest;
      if (
        body.expectedPreviousRosterVersion !== authoritativeManifest.rosterVersion ||
        (body.expectedPreviousCommitMessageId ?? "") !== (authoritativeManifest.lastCommitMessageId ?? "")
      ) {
        // Classify a stale optimistic-concurrency base before validating the
        // proposed proof against the newer manifest. Otherwise a legitimate
        // race is reported as terminal group_transition_invalid and clients
        // cannot enter their reconciliation FSM.
        throw new HttpError(409, "roster_version_conflict", "group transition base does not match the authoritative roster");
      }
      const proof = body.envelopes.find((envelope) => envelope.membershipProof)?.membershipProof;
      const preparedUpdate = await authorization.prepareUpdate(
        authState.state,
        body.authorizationUpdate,
        proof,
        now,
        body.operation
      );
      if (!preparedUpdate) {
        throw new HttpError(409, "group_transition_invalid", "group transition did not produce an authorization update");
      }
      return jsonResponse(await service.appendTransition(body, preparedUpdate, now));
    }

    if (url.pathname.endsWith("/messages") && request.method === "POST") {
      const body = await readJsonLimited<AppendGroupEnvelopeRequest>(request, DEFAULT_MESSAGE_REQUEST_MAX_BODY_BYTES);
      await service.assertWritable();
      if (!body?.envelope) {
        throw new HttpError(400, "invalid_input", "group append envelope is required");
      }
      if (body.envelope.membershipProof) {
        throw new HttpError(409, "group_transition_required", "membership operations must use the atomic transition endpoint");
      }
      if (!body.capability) {
        throw new HttpError(403, "invalid_capability", "missing group capability");
      }
      if (
        body.envelope.senderUserId !== body.capability.userId ||
        body.envelope.senderDeviceId !== body.capability.deviceId
      ) {
        throw new HttpError(403, "invalid_capability", "group capability does not match envelope sender");
      }
      const requiredOperations = requiredGroupAppendOperations(body.envelope.messageType);
      let authState;
      for (const operation of requiredOperations) {
        authState = await authorization.authorize(
          request,
          body.capability,
          operation,
          allowedGroupAppendRoles(body.envelope.messageType),
          now
        );
      }
      const preparedUpdate = await authorization.prepareUpdate(
        authState!.state,
        body.authorizationUpdate,
        body.envelope.membershipProof,
        now
      );
      const result = await service.appendEnvelope(body, now);
      await authorization.commitPreparedUpdate(preparedUpdate);
      return jsonResponse(result);
    }

    if (url.pathname.endsWith("/messages") && request.method === "GET") {
      const fromSeq = Number(url.searchParams.get("fromSeq") ?? "1");
      const limit = Number(url.searchParams.get("limit") ?? "100");
      const capability = JSON.parse(request.headers.get("X-Tapchat-Group-Capability") ?? "{}");
      const sealed = (await service.getSealStatus()).sealed;
      await authorization.authorize(
        request,
        capability,
        "read",
        ["owner", "admin", "member"],
        now,
        sealed
      );
      return jsonResponse(await service.fetchOutbox({
        groupId: deps.groupId,
        fromSeq,
        limit,
        capability
      } as FetchGroupOutboxRequest));
    }

    if (url.pathname.endsWith("/head") && request.method === "GET") {
      const sealed = (await service.getSealStatus()).sealed;
      const auth = await authorization.authorize(
        request,
        readGroupCapabilityHeader(request),
        "read",
        ["owner", "admin", "member"],
        now,
        sealed
      );
      const head = await service.getHead();
      return jsonResponse({
        ...head,
        currentRosterVersion: auth.state.manifest.rosterVersion,
        lastCommitMessageId: auth.state.manifest.lastCommitMessageId
      });
    }

    if (url.pathname.endsWith("/authorization/state") && request.method === "GET") {
      await authorization.authorize(
        request,
        readGroupCapabilityHeader(request),
        "read",
        ["owner", "admin", "member"],
        now,
        false,
        true
      );
      return jsonResponse(await authorization.getPublicState());
    }

    if (url.pathname.endsWith("/outbox/seal") && request.method === "POST") {
      // Owner-signed, owner-only seal of the group outbox. Per
      // PROTOCOL_GROUP_CN.md §10.4 the seal is irreversible: a follow-up
      // request will receive 409 `already_sealed`.
      const capability = readGroupCapabilityHeader(request);
      await authorization.authorize(request, capability, "seal_group", ["owner"], now);
      return jsonResponse(await service.sealOutbox(now));
    }

    if (url.pathname.match(/\/v1\/groups\/[^/]+\/invites$/) && request.method === "POST") {
      const body = await readJsonLimited<CreateGroupInviteRequest>(request, CONTROL_JSON_MAX_BYTES);
      await authorization.authorize(request, body.capability, "manage_invites", ["owner", "admin"], now);
      const token = await signSharingPayload(deps.sharingSecret, {
        version: body.document.version,
        service: "group_invite",
        groupId: deps.groupId,
        inviteId: body.document.inviteId,
        inviterUserId: body.document.inviterUserId,
        inviterDeviceId: body.document.inviterDeviceId,
        joinPolicy: body.document.joinPolicy,
        expiresAt: body.document.expiresAt,
        maxUses: body.maxUses ?? body.document.maxUses
      });
      return jsonResponse(
        await service.createInvite(
          body,
          `${url.origin}/v1/group-invite/${encodeURIComponent(deps.groupId)}/${encodeURIComponent(body.document.inviteId)}`,
          token,
          now
        )
      );
    }


    if (url.pathname.match(/\/v1\/groups\/[^/]+\/invites$/) && request.method === "GET") {
      await authorization.authorize(
        request,
        readGroupCapabilityHeader(request),
        "manage_invites",
        ["owner", "admin"],
        now
      );
      return jsonResponse(await service.listInvites(now));
    }

    const shortInviteFetchMatch = url.pathname.match(/\/v1\/group-invite\/([^/]+)\/([^/]+)$/);
    if (shortInviteFetchMatch && request.method === "GET") {
      const routeGroupId = decodeURIComponent(shortInviteFetchMatch[1]);
      if (routeGroupId !== deps.groupId) {
        throw new HttpError(400, "invalid_input", "group invite route does not match durable object");
      }
      return jsonResponse(await service.fetchInviteById(decodeURIComponent(shortInviteFetchMatch[2]), now));
    }

    const inviteFetchMatch = url.pathname.match(/\/v1\/group-invite\/([^/]+)$/);
    if (inviteFetchMatch && request.method === "GET") {
      const payload = await verifyInviteToken(deps.sharingSecret, decodeURIComponent(inviteFetchMatch[1]), now);
      return jsonResponse(await service.fetchInvite(payload, now));
    }

    const revokeMatch = url.pathname.match(/\/v1\/groups\/[^/]+\/invites\/([^/]+)\/revoke$/);
    if (revokeMatch && request.method === "POST") {
      const body = await readJsonLimited<RevokeGroupInviteRequest>(request, CONTROL_JSON_MAX_BYTES);
      await authorization.authorize(request, body.capability, "manage_invites", ["owner", "admin"], now);
      return jsonResponse(
        await service.revokeInvite(
          {
            version: body.version,
            groupId: deps.groupId,
            inviteId: decodeURIComponent(revokeMatch[1]),
            capability: body.capability
          },
          now
        )
      );
    }

    const joinCollectionMatch = url.pathname.match(/\/v1\/groups\/[^/]+\/join-requests$/);
    if (joinCollectionMatch && request.method === "POST") {
      const token = getBearerToken(request);
      const payload = await verifyInviteToken(deps.sharingSecret, token, now);
      const body = await readJsonLimited<SubmitGroupJoinRequest>(request, CONTROL_JSON_MAX_BYTES);
      return jsonResponse(await service.submitJoinRequest({ ...body, inviteToken: token }, payload, now));
    }

    if (joinCollectionMatch && request.method === "GET") {
      await authorization.authorize(
        request,
        readGroupCapabilityHeader(request),
        "approve_join",
        ["owner", "admin"],
        now
      );
      return jsonResponse(await service.listJoinRequests());
    }

    const joinStatusMatch = url.pathname.match(/\/v1\/groups\/[^/]+\/join-requests\/([^/]+)$/);
    if (joinStatusMatch && request.method === "GET") {
      return jsonResponse(await service.getJoinRequestStatus(decodeURIComponent(joinStatusMatch[1]), getBearerToken(request)));
    }

    const leaveCollectionMatch = url.pathname.match(/\/v1\/groups\/[^/]+\/leave-requests$/);
    if (leaveCollectionMatch && request.method === "POST") {
      const body = await readJsonLimited<SubmitGroupLeaveRequest>(request, CONTROL_JSON_MAX_BYTES);
      await authorization.authorize(request, body.capability, "append_control", ["admin", "member"], now);
      return jsonResponse(await service.submitLeaveRequest(body, now));
    }
    if (leaveCollectionMatch && request.method === "GET") {
      await authorization.authorize(request, readGroupCapabilityHeader(request), "approve_join", ["owner", "admin"], now);
      return jsonResponse(await service.listLeaveRequests());
    }
    const leaveClaimMatch = url.pathname.match(/\/v1\/groups\/[^/]+\/leave-requests\/([^/]+)\/claim$/);
    if (leaveClaimMatch && request.method === "POST") {
      const body = await readJsonLimited<ClaimGroupLeaveRequest>(request, CONTROL_JSON_MAX_BYTES);
      await authorization.authorize(request, body.capability, "approve_join", ["owner", "admin"], now);
      return jsonResponse(await service.claimLeaveRequest({ ...body, groupId: deps.groupId, requestId: decodeURIComponent(leaveClaimMatch[1]) }, now));
    }

    const claimMatch = url.pathname.match(/\/v1\/groups\/[^/]+\/join-requests\/([^/]+)\/claim$/);
    if (claimMatch && request.method === "POST") {
      const body = await readJsonLimited<ClaimGroupJoinRequest>(request, CONTROL_JSON_MAX_BYTES);
      await authorization.authorize(request, body.capability, "approve_join", ["owner", "admin"], now);
      return jsonResponse(
        await service.claimJoinRequest(
          { ...body, groupId: deps.groupId, requestId: decodeURIComponent(claimMatch[1]) },
          now
        )
      );
    }

    const completeMatch = url.pathname.match(/\/v1\/groups\/[^/]+\/join-requests\/([^/]+)\/complete$/);
    if (completeMatch && request.method === "POST") {
      const body = await readJsonLimited<CompleteGroupJoinRequest>(request, CONTROL_JSON_MAX_BYTES);
      await authorization.authorize(request, body.capability, "approve_join", ["owner", "admin"], now);
      return jsonResponse(
        await service.completeJoinRequest(
          { ...body, groupId: deps.groupId, requestId: decodeURIComponent(completeMatch[1]) },
          now
        )
      );
    }

    if (url.pathname.endsWith("/internal/welcome-claimed") && request.method === "POST") {
      if (request.headers.get("X-Tapchat-Internal-Secret") !== deps.sharingSecret) {
        throw new HttpError(403, "invalid_capability", "internal welcome claim authorization failed");
      }
      const body = await readJsonLimited<{ deviceId?: string; requestId?: string; capability?: string }>(request, CONTROL_JSON_MAX_BYTES);
      if (!body.deviceId || !body.requestId || !body.capability) {
        throw new HttpError(400, "invalid_input", "welcome claim request, device and capability are required");
      }
      await service.markWelcomeClaimed(body.requestId, body.deviceId, body.capability);
      return jsonResponse({ accepted: true });
    }

    if (url.pathname.endsWith("/internal/welcome-authorize") && request.method === "POST") {
      if (request.headers.get("X-Tapchat-Internal-Secret") !== deps.sharingSecret) {
        throw new HttpError(403, "invalid_capability", "internal welcome authorization failed");
      }
      const body = await readJsonLimited<{ deviceId?: string; requestId?: string; capability?: string }>(request, CONTROL_JSON_MAX_BYTES);
      if (!body.deviceId || !body.requestId || !body.capability) throw new HttpError(400, "invalid_input", "welcome authorization binding is required");
      await service.authorizeWelcomeUpload(body.requestId, body.deviceId, body.capability);
      return jsonResponse({ accepted: true });
    }

    const decisionMatch = url.pathname.match(/\/v1\/groups\/[^/]+\/join-requests\/([^/]+)\/decision$/);
    if (decisionMatch && request.method === "POST") {
      const body = await readJsonLimited<DecideGroupJoinRequest>(request, CONTROL_JSON_MAX_BYTES);
      await authorization.authorize(request, body.capability, "approve_join", ["owner", "admin"], now);
      return jsonResponse(
        await service.decideJoinRequest({
          ...body,
          groupId: deps.groupId,
          requestId: decodeURIComponent(decisionMatch[1])
        })
      );
    }

    return jsonResponse({ error: "not_found" }, 404);
  } catch (error) {
    if (error instanceof HttpError) {
      return jsonResponse({ error: error.code, message: error.message, ...(error.details ? { details: error.details } : {}) }, error.status);
    }
    const runtimeError = error as { message?: string };
    const message = runtimeError.message ?? "internal error";
    return jsonResponse({ error: "temporary_unavailable", message }, 500);
  }
}

async function verifyInviteToken(secret: string, token: string, now: number): Promise<GroupInviteTokenPayload> {
  try {
    const payload = await verifySharingPayload<GroupInviteTokenPayload>(secret, token, now);
    if (payload.version !== "0.1" || payload.service !== "group_invite" || !payload.groupId || !payload.inviteId) {
      throw new Error("malformed group invite token");
    }
    return payload;
  } catch (error) {
    const message = error instanceof Error ? error.message : "invalid group invite token";
    if (message.includes("expired")) {
      throw new HttpError(403, "capability_expired", message);
    }
    throw new HttpError(403, "invalid_capability", message);
  }
}

export async function groupIdFromGroupOutboxRequestUrl(
  url: URL,
  sharingSecret: string,
  now: number
): Promise<string> {
  const groupMatch = url.pathname.match(/\/v1\/groups\/([^/]+)\//);
  let groupId = decodeURIComponent(groupMatch?.[1] ?? "");
  if (!groupId) {
    const shortInviteMatch = url.pathname.match(/\/v1\/group-invite\/([^/]+)\/([^/]+)$/);
    if (shortInviteMatch) {
      groupId = decodeURIComponent(shortInviteMatch[1]);
    }
  }
  if (!groupId) {
    const inviteMatch = url.pathname.match(/\/v1\/group-invite\/([^/]+)$/);
    if (inviteMatch) {
      const payload = await verifyInviteToken(
        sharingSecret,
        decodeURIComponent(inviteMatch[1]),
        now
      );
      groupId = payload.groupId;
    }
  }
  return groupId;
}

export class GroupOutboxDurableObject extends DurableObjectBase {
  private readonly sessions = new Map<string, ManagedSession>();
  private readonly stateRef: DurableObjectState;
  private readonly envRef: Env;
  private groupIdRef?: string;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.stateRef = state;
    this.envRef = env;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    let sharingSecret: string;
    let deviceRuntimeSecrets: RotatingSecretSet;
    try {
      sharingSecret = requireSharingSecret(this.envRef);
      deviceRuntimeSecrets = requireDeviceRuntimeSecrets(this.envRef);
    } catch (error) {
      if (error instanceof HttpError) {
        return jsonResponse({ error: error.code, message: error.message }, error.status);
      }
      return jsonResponse({ error: "runtime_misconfigured", message: "sharing secret is invalid" }, 503);
    }
    const groupId = await groupIdFromGroupOutboxRequestUrl(url, sharingSecret, Date.now());
    this.groupIdRef = groupId;
    await this.stateRef.storage.put("durable-group-id", groupId);

    return handleGroupOutboxDurableRequest(request, {
      groupId,
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
      sharingSecret,
      deviceRuntimeSecrets,
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
    const groupId = this.groupIdRef ?? await this.stateRef.storage.get<string>("durable-group-id");
    if (!groupId) return;
    const service = new GroupOutboxService(
      groupId,
      new DurableObjectStorageAdapter(this.stateRef.storage),
      new R2JsonBlobStore(this.envRef.TAPCHAT_STORAGE),
      { headSeq: 0, retentionDays: Number(this.envRef.RETENTION_DAYS ?? "30"), maxInlineBytes: Number(this.envRef.MAX_INLINE_BYTES ?? "4096") },
      Array.from(this.sessions.values()).map((session) => ({ send: (payload: string) => session.send(payload) }))
    );
    await service.processAlarm(Date.now());
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

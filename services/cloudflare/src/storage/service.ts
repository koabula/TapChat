import {
  type PrepareBlobUploadRequest,
  type PrepareBlobUploadResult
} from "../types/contracts";
import type { JsonBlobStore } from "../types/runtime";
import { HttpError } from "../auth/capability";
import { signSharingPayload, verifySharingPayload } from "./sharing";

const MAX_BLOB_BYTES = 25 * 1024 * 1024;
const SHORT_BLOB_TOKEN_TTL_MS = 15 * 60 * 1000;
const CAPABILITY_METADATA_KEY = "read-capability-sha256";

function sanitizeSegment(value: string): string {
  return value.replace(/[^a-zA-Z0-9:_-]/g, "_");
}

function requireNonEmpty(value: string | undefined, field: string): string {
  if (!value || value.trim().length === 0) {
    throw new HttpError(400, "invalid_input", `${field} is required`);
  }
  return value;
}

function randomCapability(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function capabilityHash(value: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function constantTimeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

export class StorageService {
  private readonly store: JsonBlobStore;
  private readonly baseUrl: string;
  private readonly secret: string;

  constructor(store: JsonBlobStore, baseUrl: string, secret: string) {
    this.store = store;
    this.baseUrl = baseUrl;
    this.secret = secret;
  }

  async prepareUpload(
    input: PrepareBlobUploadRequest,
    owner: { userId: string; deviceId: string },
    now: number
  ): Promise<PrepareBlobUploadResult> {
    const taskId = requireNonEmpty(input.taskId, "taskId");
    const conversationId = requireNonEmpty(input.conversationId, "conversationId");
    const messageId = requireNonEmpty(input.messageId, "messageId");
    if (input.variant !== "original" && input.variant !== "preview") {
      throw new HttpError(400, "invalid_input", "variant must be original or preview");
    }
    if (!Number.isSafeInteger(input.sizeBytes) || input.sizeBytes <= 0 || input.sizeBytes > MAX_BLOB_BYTES) {
      throw new HttpError(400, "invalid_input", "sizeBytes is outside supported limits");
    }
    const storageScope = input.storageScope ?? (input.groupId ? "group" : "direct");
    if (storageScope !== "direct" && storageScope !== "group") {
      throw new HttpError(400, "invalid_input", "storageScope is invalid");
    }
    if (storageScope === "group" && (!input.groupId || input.groupId.trim().length === 0)) {
      throw new HttpError(400, "invalid_input", "groupId is required for group storage");
    }
    const blobKey = [
      "blobs",
      input.variant,
      sanitizeSegment(owner.userId),
      sanitizeSegment(owner.deviceId),
      storageScope,
      storageScope === "group" ? sanitizeSegment(input.groupId!) : "direct",
      sanitizeSegment(conversationId),
      `${sanitizeSegment(messageId)}-${sanitizeSegment(taskId)}`
    ].join("/");
    const expiresAt = now + SHORT_BLOB_TOKEN_TTL_MS;
    const readCapability = randomCapability();
    const readCapabilityHash = await capabilityHash(readCapability);
    const uploadToken = await signSharingPayload(this.secret, {
      action: "upload",
      blobKey,
      sizeBytes: input.sizeBytes,
      readCapabilityHash,
      expiresAt
    });

    return {
      blobRef: blobKey,
      uploadTarget: `${this.baseUrl}/v1/storage/upload/${encodeURIComponent(blobKey)}?token=${encodeURIComponent(uploadToken)}`,
      uploadHeaders: {
        "content-type": "application/octet-stream"
      },
      readCapability,
      downloadTarget: `${this.baseUrl}/v1/storage/blob/${encodeURIComponent(blobKey)}`,
      expiresAt
    };
  }

  async uploadBlob(blobKey: string, token: string, body: ArrayBuffer, now: number): Promise<void> {
    const payload = await this.verifyToken<{ action: string; blobKey: string; sizeBytes?: number; readCapabilityHash?: string }>(token, now);
    if (payload.action !== "upload" || payload.blobKey !== blobKey) {
      throw new HttpError(403, "invalid_capability", "upload token is not valid for this blob");
    }
    if (!Number.isSafeInteger(payload.sizeBytes) || body.byteLength !== payload.sizeBytes) {
      throw new HttpError(400, "invalid_input", "upload body size does not match prepared size");
    }
    if (!payload.readCapabilityHash) {
      throw new HttpError(403, "invalid_capability", "upload token is missing blob capability binding");
    }
    await this.store.putBytes(blobKey, body, {
      [CAPABILITY_METADATA_KEY]: payload.readCapabilityHash,
      "content-type": "application/octet-stream"
    });
  }

  async fetchBlob(blobKey: string, capability: string): Promise<ArrayBuffer> {
    if (!capability || !this.store.getBytesMetadata) {
      throw new HttpError(403, "invalid_capability", "blob capability cannot be verified");
    }
    const object = await this.store.getBytesMetadata(blobKey);
    if (!object) {
      throw new HttpError(404, "blob_not_found", "blob does not exist");
    }
    const expectedHash = object.customMetadata[CAPABILITY_METADATA_KEY];
    const actualHash = await capabilityHash(capability);
    if (!expectedHash || !constantTimeEqual(expectedHash, actualHash)) {
      throw new HttpError(403, "invalid_capability", "blob capability is not valid for this object");
    }
    return object.bytes;
  }

  async putJson<T>(key: string, value: T): Promise<void> {
    await this.store.putJson(key, value);
  }

  async getJson<T>(key: string): Promise<T | null> {
    return this.store.getJson<T>(key);
  }

  async delete(key: string): Promise<void> {
    await this.store.delete(key);
  }

  private async verifyToken<T>(token: string, now: number): Promise<T> {
    try {
      return await verifySharingPayload<T>(this.secret, token, now);
    } catch (error) {
      const message = error instanceof Error ? error.message : "invalid sharing token";
      if (message.includes("expired")) {
        throw new HttpError(403, "capability_expired", message);
      }
      throw new HttpError(403, "invalid_capability", message);
    }
  }
}

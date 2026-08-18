import {
  type PrepareBlobUploadRequest,
  type PrepareBlobUploadResult
} from "../types/contracts";
import type { BinaryBlobStore, BlobByteRange } from "../types/runtime";
import { HttpError } from "../auth/capability";
import { signSharingPayload, verifySharingPayload } from "./sharing";

// Core caps plaintext at 25 MiB. Storage receives AEAD ciphertext, including
// up to fifty 16-byte chunk tags for the fixed 512 KiB video format.
const MAX_BLOB_BYTES = 25 * 1024 * 1024 + 1024;
const SHORT_BLOB_TOKEN_TTL_MS = 15 * 60 * 1000;
const CAPABILITY_METADATA_KEY = "read-capability-sha256";
const DELETE_CAPABILITY_METADATA_KEY = "delete-capability-sha256";
const BLOB_EXPIRY_METADATA_KEY = "blob-expires-at";

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
  private readonly store: BinaryBlobStore;
  private readonly baseUrl: string;
  private readonly secret: string;
  private readonly retentionMs: number;

  constructor(store: BinaryBlobStore, baseUrl: string, secret: string, retentionDays = 30) {
    this.store = store;
    this.baseUrl = baseUrl;
    this.secret = secret;
    this.retentionMs = Math.max(1, Math.floor(retentionDays)) * 24 * 60 * 60 * 1000;
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
    const uploadExpiresAt = now + SHORT_BLOB_TOKEN_TTL_MS;
    const blobExpiresAt = now + this.retentionMs;
    const readCapability = randomCapability();
    const deleteCapability = randomCapability();
    const readCapabilityHash = await capabilityHash(readCapability);
    const deleteCapabilityHash = await capabilityHash(deleteCapability);
    const uploadToken = await signSharingPayload(this.secret, {
      action: "upload",
      blobKey,
      sizeBytes: input.sizeBytes,
      readCapabilityHash,
      deleteCapabilityHash,
      blobExpiresAt,
      expiresAt: uploadExpiresAt
    });

    return {
      blobRef: blobKey,
      uploadTarget: `${this.baseUrl}/v1/storage/upload/${encodeURIComponent(blobKey)}?token=${encodeURIComponent(uploadToken)}`,
      uploadHeaders: {
        "content-type": "application/octet-stream"
      },
      readCapability,
      downloadTarget: `${this.baseUrl}/v1/storage/blob/${encodeURIComponent(blobKey)}`,
      uploadExpiresAt,
      blobExpiresAt,
      deleteTarget: `${this.baseUrl}/v1/storage/blob/${encodeURIComponent(blobKey)}`,
      deleteCapability
    };
  }

  async uploadBlob(
    blobKey: string,
    token: string,
    body: ReadableStream,
    contentLength: number,
    now: number,
  ): Promise<void> {
    const payload = await this.verifyToken<{
      action: string;
      blobKey: string;
      sizeBytes?: number;
      readCapabilityHash?: string;
      deleteCapabilityHash?: string;
      blobExpiresAt?: number;
    }>(token, now);
    if (payload.action !== "upload" || payload.blobKey !== blobKey) {
      throw new HttpError(403, "invalid_capability", "upload token is not valid for this blob");
    }
    if (!Number.isSafeInteger(payload.sizeBytes) || contentLength !== payload.sizeBytes) {
      throw new HttpError(400, "invalid_input", "upload body size does not match prepared size");
    }
    if (!payload.readCapabilityHash || !payload.deleteCapabilityHash || !Number.isSafeInteger(payload.blobExpiresAt)) {
      throw new HttpError(403, "invalid_capability", "upload token is missing blob capability binding");
    }
    const stored = await this.store.putStream(blobKey, body, {
      [CAPABILITY_METADATA_KEY]: payload.readCapabilityHash,
      [DELETE_CAPABILITY_METADATA_KEY]: payload.deleteCapabilityHash,
      [BLOB_EXPIRY_METADATA_KEY]: String(payload.blobExpiresAt),
      "content-type": "application/octet-stream"
    });
    if (stored.size !== payload.sizeBytes) {
      await this.store.delete(blobKey);
      throw new HttpError(400, "invalid_input", "stored upload size does not match prepared size");
    }
  }

  async fetchBlob(
    blobKey: string,
    capability: string,
    rangeHeader?: string,
    includeBody = true,
    now = Date.now(),
  ): Promise<{
    body: ReadableStream | null;
    size: number;
    contentLength: number;
    range?: BlobByteRange;
    httpEtag?: string;
  }> {
    if (!capability) {
      throw new HttpError(403, "invalid_capability", "blob capability cannot be verified");
    }
    const metadata = await this.store.headBytes(blobKey);
    if (!metadata) {
      throw new HttpError(404, "blob_not_found", "blob does not exist");
    }
    const blobExpiresAt = Number(metadata.customMetadata[BLOB_EXPIRY_METADATA_KEY]);
    if (!Number.isSafeInteger(blobExpiresAt) || blobExpiresAt <= now) {
      await this.store.delete(blobKey);
      throw new HttpError(410, "capability_expired", "blob retention period has expired");
    }
    const expectedHash = metadata.customMetadata[CAPABILITY_METADATA_KEY];
    const actualHash = await capabilityHash(capability);
    if (!expectedHash || !constantTimeEqual(expectedHash, actualHash)) {
      throw new HttpError(403, "invalid_capability", "blob capability is not valid for this object");
    }
    // Capability verification deliberately completes before R2 exposes a body.
    const range = rangeHeader ? parseRange(rangeHeader, metadata.size) : undefined;
    if (!includeBody) {
      return {
        body: null,
        size: metadata.size,
        contentLength: range?.length ?? metadata.size,
        ...(range ? { range } : {}),
        ...(metadata.httpEtag ? { httpEtag: metadata.httpEtag } : {}),
      };
    }
    const object = await this.store.getStream(blobKey, range);
    if (!object) {
      throw new HttpError(404, "blob_not_found", "blob does not exist");
    }
    return {
      body: object.body,
      size: metadata.size,
      contentLength: range?.length ?? metadata.size,
      ...(range ? { range } : {}),
      ...(object.httpEtag ? { httpEtag: object.httpEtag } : metadata.httpEtag ? { httpEtag: metadata.httpEtag } : {}),
    };
  }

  async deleteBlob(blobKey: string, capability: string): Promise<void> {
    if (!capability) {
      throw new HttpError(403, "invalid_capability", "delete capability cannot be verified");
    }
    const metadata = await this.store.headBytes(blobKey);
    if (!metadata) return;
    const expectedHash = metadata.customMetadata[DELETE_CAPABILITY_METADATA_KEY];
    const actualHash = await capabilityHash(capability);
    if (!expectedHash || !constantTimeEqual(expectedHash, actualHash)) {
      throw new HttpError(403, "invalid_capability", "delete capability is not valid for this object");
    }
    await this.store.delete(blobKey);
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

function parseRange(header: string, size: number): BlobByteRange {
  const value = header.startsWith("bytes=") ? header.slice("bytes=".length) : "";
  if (!value || value.includes(",") || !Number.isSafeInteger(size) || size <= 0) {
    throw rangeError(size);
  }
  const separator = value.indexOf("-");
  if (separator < 0 || value.indexOf("-", separator + 1) >= 0) {
    throw rangeError(size);
  }
  const startText = value.slice(0, separator);
  const endText = value.slice(separator + 1);
  if (!startText) {
    const suffix = Number(endText);
    if (!Number.isSafeInteger(suffix) || suffix <= 0) throw rangeError(size);
    const length = Math.min(suffix, size);
    return { offset: size - length, length };
  }
  const offset = Number(startText);
  if (!Number.isSafeInteger(offset) || offset < 0 || offset >= size) throw rangeError(size);
  if (!endText) return { offset, length: size - offset };
  const requestedEnd = Number(endText);
  if (!Number.isSafeInteger(requestedEnd) || requestedEnd < offset) throw rangeError(size);
  const end = Math.min(requestedEnd, size - 1);
  return { offset, length: end - offset + 1 };
}

function rangeError(size: number): HttpError {
  return new HttpError(416, "range_not_satisfiable", "requested byte range is invalid", {
    totalSize: size,
  });
}

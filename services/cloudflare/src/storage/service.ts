import {
  CURRENT_MODEL_VERSION,
  type AuthorizeBlobDownloadResult,
  type BlobDownloadGrant,
  type PrepareBlobUploadRequest,
  type PrepareBlobUploadResult
} from "../types/contracts";
import type { JsonBlobStore } from "../types/runtime";
import { HttpError } from "../auth/capability";
import { signSharingPayload, verifySharingPayload } from "./sharing";

const MAX_BLOB_BYTES = 25 * 1024 * 1024;
const MAX_MIME_TYPE_LENGTH = 255;
const MAX_FILE_NAME_BYTES = 255;
const SHORT_BLOB_TOKEN_TTL_MS = 15 * 60 * 1000;
const DEFAULT_DOWNLOAD_GRANT_TTL_DAYS = 365;
const MAX_DOWNLOAD_GRANT_TTL_DAYS = 3650;

function sanitizeSegment(value: string): string {
  return value.replace(/[^a-zA-Z0-9:_-]/g, "_");
}

function requireNonEmpty(value: string | undefined, field: string): string {
  if (!value || value.trim().length === 0) {
    throw new HttpError(400, "invalid_input", `${field} is required`);
  }
  return value;
}

function validateMimeType(mimeType: string): void {
  if (mimeType.trim().length === 0 || mimeType.length > MAX_MIME_TYPE_LENGTH || /[\r\n]/.test(mimeType)) {
    throw new HttpError(400, "invalid_input", "mime type is invalid");
  }
}

function validateFileName(fileName: string | undefined): void {
  if (fileName === undefined) {
    return;
  }
  if (
    fileName.trim().length === 0 ||
    fileName.length > MAX_FILE_NAME_BYTES ||
    /[\/\\\0\r\n]/.test(fileName)
  ) {
    throw new HttpError(400, "invalid_input", "file name is invalid");
  }
}

export class StorageService {
  private readonly store: JsonBlobStore;
  private readonly baseUrl: string;
  private readonly secret: string;
  private readonly downloadGrantTtlDays: number;

  constructor(store: JsonBlobStore, baseUrl: string, secret: string, downloadGrantTtlDays = DEFAULT_DOWNLOAD_GRANT_TTL_DAYS) {
    this.store = store;
    this.baseUrl = baseUrl;
    this.secret = secret;
    this.downloadGrantTtlDays = clampDownloadGrantTtlDays(downloadGrantTtlDays);
  }

  async prepareUpload(
    input: PrepareBlobUploadRequest,
    owner: { userId: string; deviceId: string },
    now: number
  ): Promise<PrepareBlobUploadResult> {
    const taskId = requireNonEmpty(input.taskId, "taskId");
    const conversationId = requireNonEmpty(input.conversationId, "conversationId");
    const messageId = requireNonEmpty(input.messageId, "messageId");
    validateMimeType(input.mimeType);
    validateFileName(input.fileName);
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
      "blob",
      sanitizeSegment(owner.userId),
      sanitizeSegment(owner.deviceId),
      storageScope,
      storageScope === "group" ? sanitizeSegment(input.groupId!) : "direct",
      sanitizeSegment(conversationId),
      `${sanitizeSegment(messageId)}-${sanitizeSegment(taskId)}`
    ].join("/");
    const expiresAt = now + SHORT_BLOB_TOKEN_TTL_MS;
    const grantExpiresAt = now + this.downloadGrantTtlDays * 24 * 60 * 60 * 1000;
    const uploadToken = await signSharingPayload(this.secret, {
      action: "upload",
      blobKey,
      sizeBytes: input.sizeBytes,
      expiresAt
    });
    const refreshToken = await signSharingPayload(this.secret, {
      service: "storage",
      action: "authorize_download",
      blobKey,
      expiresAt: grantExpiresAt
    });
    const downloadGrant: BlobDownloadGrant = {
      version: CURRENT_MODEL_VERSION,
      service: "storage",
      action: "authorize_download",
      blobRef: blobKey,
      authorizeEndpoint: `${this.baseUrl}/v1/storage/authorize-download`,
      token: refreshToken,
      expiresAt: grantExpiresAt
    };

    return {
      blobRef: blobKey,
      uploadTarget: `${this.baseUrl}/v1/storage/upload/${encodeURIComponent(blobKey)}?token=${encodeURIComponent(uploadToken)}`,
      uploadHeaders: {
        "content-type": input.mimeType
      },
      downloadGrant,
      expiresAt
    };
  }

  async uploadBlob(blobKey: string, token: string, body: ArrayBuffer, metadata: Record<string, string>, now: number): Promise<void> {
    const payload = await this.verifyToken<{ action: string; blobKey: string; sizeBytes?: number }>(token, now);
    if (payload.action !== "upload" || payload.blobKey !== blobKey) {
      throw new HttpError(403, "invalid_capability", "upload token is not valid for this blob");
    }
    if (!Number.isSafeInteger(payload.sizeBytes) || body.byteLength !== payload.sizeBytes) {
      throw new HttpError(400, "invalid_input", "upload body size does not match prepared size");
    }
    await this.store.putBytes(blobKey, body, metadata);
  }

  async fetchBlob(blobKey: string, token: string, now: number): Promise<ArrayBuffer> {
    const payload = await this.verifyToken<{ action: string; blobKey: string }>(token, now);
    if (payload.action !== "download" || payload.blobKey !== blobKey) {
      throw new HttpError(403, "invalid_capability", "download token is not valid for this blob");
    }
    const object = await this.store.getBytes(blobKey);
    if (!object) {
      throw new HttpError(404, "blob_not_found", "blob does not exist");
    }
    return object;
  }

  async authorizeDownload(blobRef: string, token: string, now: number): Promise<AuthorizeBlobDownloadResult> {
    const blobKey = requireNonEmpty(blobRef, "blobRef");
    const payload = await this.verifyToken<{ service?: string; action: string; blobKey: string }>(token, now);
    if (payload.service !== "storage" || payload.action !== "authorize_download" || payload.blobKey !== blobKey) {
      throw new HttpError(403, "invalid_capability", "download refresh grant is not valid for this blob");
    }
    const object = await this.store.getBytes(blobKey);
    if (!object) {
      throw new HttpError(404, "blob_not_found", "blob does not exist");
    }
    const expiresAt = now + SHORT_BLOB_TOKEN_TTL_MS;
    const downloadToken = await signSharingPayload(this.secret, {
      action: "download",
      blobKey,
      expiresAt
    });
    return {
      blobRef: blobKey,
      downloadTarget: `${this.baseUrl}/v1/storage/blob/${encodeURIComponent(blobKey)}?token=${encodeURIComponent(downloadToken)}`,
      downloadHeaders: {},
      expiresAt
    };
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

export function clampDownloadGrantTtlDays(value: number): number {
  if (!Number.isFinite(value) || value <= 0) {
    return DEFAULT_DOWNLOAD_GRANT_TTL_DAYS;
  }
  return Math.min(Math.floor(value), MAX_DOWNLOAD_GRANT_TTL_DAYS);
}

import type { PrepareBlobUploadRequest, PrepareBlobUploadResult } from "../types/contracts";
import type { JsonBlobStore } from "../types/runtime";
import { HttpError } from "../auth/capability";
import { signSharingPayload, verifySharingPayload } from "./sharing";

function sanitizeSegment(value: string): string {
  return value.replace(/[^a-zA-Z0-9:_-]/g, "_");
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
    if (!input.taskId || !input.conversationId || !input.messageId || !input.mimeType || input.sizeBytes <= 0) {
      throw new HttpError(400, "invalid_input", "prepare upload request is missing required fields");
    }
    const blobKey = [
      "blob",
      sanitizeSegment(owner.userId),
      sanitizeSegment(owner.deviceId),
      sanitizeSegment(input.conversationId),
      `${sanitizeSegment(input.messageId)}-${sanitizeSegment(input.taskId)}`
    ].join("/");
    const expiresAt = now + 15 * 60 * 1000;
    const uploadToken = await signSharingPayload(this.secret, {
      action: "upload",
      blobKey,
      expiresAt
    });
    const downloadToken = await signSharingPayload(this.secret, {
      action: "download",
      blobKey,
      expiresAt
    });

    return {
      blobRef: blobKey,
      uploadTarget: `${this.baseUrl}/v1/storage/upload/${encodeURIComponent(blobKey)}?token=${encodeURIComponent(uploadToken)}`,
      uploadHeaders: {
        "content-type": input.mimeType
      },
      downloadTarget: `${this.baseUrl}/v1/storage/blob/${encodeURIComponent(blobKey)}?token=${encodeURIComponent(downloadToken)}`,
      expiresAt
    };
  }

  async uploadBlob(blobKey: string, token: string, body: ArrayBuffer, metadata: Record<string, string>, now: number): Promise<void> {
    const payload = await this.verifyToken<{ action: string; blobKey: string }>(token, now);
    if (payload.action !== "upload" || payload.blobKey !== blobKey) {
      throw new HttpError(403, "invalid_capability", "upload token is not valid for this blob");
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

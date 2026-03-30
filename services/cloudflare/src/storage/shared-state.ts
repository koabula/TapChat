import { HttpError } from "../auth/capability";
import type {
  DeviceListDocument,
  DeviceStatusDocument,
  IdentityBundle,
  KeyPackageRefsDocument
} from "../types/contracts";
import type { JsonBlobStore } from "../types/runtime";

function sanitizeSegment(value: string): string {
  return value.replace(/[^a-zA-Z0-9:_-]/g, "_");
}

export class SharedStateService {
  private readonly store: JsonBlobStore;
  private readonly baseUrl: string;

  constructor(store: JsonBlobStore, baseUrl: string) {
    this.store = store;
    this.baseUrl = baseUrl;
  }

  identityBundleKey(userId: string): string {
    return `shared-state/${sanitizeSegment(userId)}/identity_bundle.json`;
  }

  deviceListKey(userId: string): string {
    return `shared-state/${sanitizeSegment(userId)}/device_list.json`;
  }

  deviceStatusKey(userId: string): string {
    return `shared-state/${sanitizeSegment(userId)}/device_status.json`;
  }

  keyPackageRefsKey(userId: string, deviceId: string): string {
    return `keypackages/${sanitizeSegment(userId)}/${sanitizeSegment(deviceId)}/refs.json`;
  }

  keyPackageObjectKey(userId: string, deviceId: string, keyPackageId: string): string {
    return `keypackages/${sanitizeSegment(userId)}/${sanitizeSegment(deviceId)}/${sanitizeSegment(keyPackageId)}.bin`;
  }

  identityBundleUrl(userId: string): string {
    return `${this.baseUrl}/v1/shared-state/${encodeURIComponent(userId)}/identity-bundle`;
  }

  deviceStatusUrl(userId: string): string {
    return `${this.baseUrl}/v1/shared-state/${encodeURIComponent(userId)}/device-status`;
  }

  keyPackageRefsUrl(userId: string, deviceId: string): string {
    return `${this.baseUrl}/v1/shared-state/keypackages/${encodeURIComponent(userId)}/${encodeURIComponent(deviceId)}`;
  }

  keyPackageObjectUrl(userId: string, deviceId: string, keyPackageId: string): string {
    return `${this.baseUrl}/v1/shared-state/keypackages/${encodeURIComponent(userId)}/${encodeURIComponent(deviceId)}/${encodeURIComponent(keyPackageId)}`;
  }

  async getIdentityBundle(userId: string): Promise<IdentityBundle | null> {
    return this.store.getJson<IdentityBundle>(this.identityBundleKey(userId));
  }

  async putIdentityBundle(userId: string, bundle: IdentityBundle): Promise<void> {
    if (bundle.userId !== userId) {
      throw new HttpError(400, "invalid_input", "identity bundle userId does not match request path");
    }
    const normalized: IdentityBundle = {
      ...bundle,
      identityBundleRef: this.identityBundleUrl(userId),
      deviceStatusRef: bundle.deviceStatusRef ?? this.deviceStatusUrl(userId),
      devices: bundle.devices.map((device) => ({
        ...device,
        keypackageRef: {
          ...device.keypackageRef,
          userId,
          deviceId: device.deviceId,
          ref: device.keypackageRef.ref
        }
      }))
    };
    await this.store.putJson(this.identityBundleKey(userId), normalized);
    await this.store.putJson(this.deviceListKey(userId), this.buildDeviceListDocument(normalized));
  }

  async getDeviceList(userId: string): Promise<DeviceListDocument | null> {
    return this.store.getJson<DeviceListDocument>(this.deviceListKey(userId));
  }

  async getDeviceStatus(userId: string): Promise<DeviceStatusDocument | null> {
    return this.store.getJson<DeviceStatusDocument>(this.deviceStatusKey(userId));
  }

  async putDeviceStatus(userId: string, document: DeviceStatusDocument): Promise<void> {
    if (document.userId !== userId) {
      throw new HttpError(400, "invalid_input", "device status userId does not match request path");
    }
    for (const device of document.devices) {
      if (device.userId !== userId) {
        throw new HttpError(400, "invalid_input", "device status entry userId does not match request path");
      }
    }
    await this.store.putJson(this.deviceStatusKey(userId), document);
  }

  async getKeyPackageRefs(userId: string, deviceId: string): Promise<KeyPackageRefsDocument | null> {
    return this.store.getJson<KeyPackageRefsDocument>(this.keyPackageRefsKey(userId, deviceId));
  }

  async putKeyPackageRefs(userId: string, deviceId: string, document: KeyPackageRefsDocument): Promise<void> {
    if (document.userId !== userId || document.deviceId !== deviceId) {
      throw new HttpError(400, "invalid_input", "keypackage refs scope does not match request path");
    }
    for (const entry of document.refs) {
      if (!entry.ref || !entry.ref.startsWith(this.keyPackageRefsUrl(userId, deviceId))) {
        throw new HttpError(400, "invalid_input", "keypackage ref must be a concrete object URL");
      }
    }
    await this.store.putJson(this.keyPackageRefsKey(userId, deviceId), document);
  }

  async putKeyPackageObject(userId: string, deviceId: string, keyPackageId: string, body: ArrayBuffer): Promise<void> {
    await this.store.putBytes(this.keyPackageObjectKey(userId, deviceId, keyPackageId), body, {
      "content-type": "application/octet-stream"
    });
  }

  async getKeyPackageObject(userId: string, deviceId: string, keyPackageId: string): Promise<ArrayBuffer | null> {
    return this.store.getBytes(this.keyPackageObjectKey(userId, deviceId, keyPackageId));
  }

  private buildDeviceListDocument(bundle: IdentityBundle): DeviceListDocument {
    return {
      version: bundle.version,
      userId: bundle.userId,
      updatedAt: bundle.updatedAt,
      devices: bundle.devices.map((device) => ({
        deviceId: device.deviceId,
        status: device.status
      }))
    };
  }
}
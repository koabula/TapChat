import { HttpError } from "../auth/capability";
import type {
  DeviceListDocument,
  DeviceStatusDocument,
  IdentityBundle
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

  identityBundleUrl(userId: string): string {
    return `${this.baseUrl}/v1/shared-state/${encodeURIComponent(userId)}/identity-bundle`;
  }

  deviceStatusUrl(userId: string): string {
    return `${this.baseUrl}/v1/shared-state/${encodeURIComponent(userId)}/device-status`;
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
      devices: bundle.devices.map((device) => ({
        ...device,
        ...(device.keypackageRef
          ? {
              keypackageRef: {
                ...device.keypackageRef,
                userId,
                deviceId: device.deviceId,
                ref: device.keypackageRef.ref
              }
            }
          : {})
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

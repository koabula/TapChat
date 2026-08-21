import { HttpError } from "../auth/capability";
import type {
  FetchWelcomePickupResult,
  PutWelcomePickupRequest,
  WelcomePickupDescriptor
} from "../types/contracts";
import type { JsonBlobStore } from "../types/runtime";

interface StoredWelcomePickup {
  descriptor: WelcomePickupDescriptor;
  welcomeB64: string;
  manifest?: PutWelcomePickupRequest["manifest"];
  storedAt: number;
}

function pickupKey(groupId: string, deviceId: string, requestId?: string): string {
  return `welcome-pickup/${groupId}/${deviceId}/${requestId ?? "unbound"}.json`;
}

export class WelcomePickupService {
  private readonly store: JsonBlobStore;

  constructor(store: JsonBlobStore) {
    this.store = store;
  }

  async put(request: PutWelcomePickupRequest, now: number): Promise<{ accepted: boolean }> {
    this.validateDescriptor(request.descriptor, now);
    if (!request.welcomeB64?.trim()) {
      throw new HttpError(400, "invalid_input", "welcome_b64 must not be empty");
    }
    const digestBytes = new Uint8Array(await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(request.welcomeB64)
    ));
    const actualDigest = btoa(String.fromCharCode(...digestBytes));
    if (request.descriptor.welcomeDigest !== actualDigest) {
      throw new HttpError(
        403,
        "relationship_proposal_invalid",
        "welcome digest does not match descriptor"
      );
    }
    await this.store.putJson(pickupKey(request.descriptor.groupId, request.descriptor.deviceId, request.descriptor.requestId), {
      descriptor: request.descriptor,
      welcomeB64: request.welcomeB64,
      manifest: request.manifest,
      storedAt: now
    } satisfies StoredWelcomePickup);
    return { accepted: true };
  }

  async fetch(descriptor: WelcomePickupDescriptor, now: number): Promise<FetchWelcomePickupResult> {
    this.validateDescriptor(descriptor, now);
    const stored = await this.store.getJson<StoredWelcomePickup>(pickupKey(descriptor.groupId, descriptor.deviceId, descriptor.requestId));
    if (!stored) {
      throw new HttpError(404, "not_found", "welcome pickup not found");
    }
    if (
      stored.descriptor.capability !== descriptor.capability ||
      stored.descriptor.claimId !== descriptor.claimId ||
      stored.descriptor.welcomeDigest !== descriptor.welcomeDigest
    ) {
      throw new HttpError(403, "invalid_capability", "welcome pickup capability does not match stored descriptor");
    }
    if (stored.descriptor.expiresAt <= now) {
      await this.store.delete(pickupKey(descriptor.groupId, descriptor.deviceId));
      throw new HttpError(403, "capability_expired", "welcome pickup capability is expired");
    }
    return { welcomeB64: stored.welcomeB64, manifest: stored.manifest };
  }

  private validateDescriptor(descriptor: WelcomePickupDescriptor, now: number): void {
    if (
      !descriptor.groupId ||
      !descriptor.deviceId ||
      !descriptor.endpoint ||
      !descriptor.capability ||
      !descriptor.claimId ||
      !descriptor.welcomeDigest
    ) {
      throw new HttpError(400, "invalid_input", "welcome pickup descriptor is missing required fields");
    }
    if (descriptor.expiresAt <= now) {
      throw new HttpError(403, "capability_expired", "welcome pickup capability is expired");
    }
  }
}

import { R2_KEYS } from "../leakage-keys";
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

/**
 * The object is named by the digest of the capability that opens it.
 *
 * Both sides recompute it from the descriptor they already hold, so nothing
 * has to be indexed. It also removes a class of bug rather than one instance:
 * the previous key was assembled from `groupId`, `deviceId` and `requestId`,
 * and the expiry path rebuilt it without the `requestId` — so every pickup
 * that had one was deleted at a key that did not exist, and the real object
 * stayed in the bucket for good.
 */
async function pickupKey(capability: string): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(capability))
  );
  return R2_KEYS.welcomePickup(
    Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("")
  );
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
    await this.store.putJson(await pickupKey(request.descriptor.capability), {
      descriptor: request.descriptor,
      welcomeB64: request.welcomeB64,
      manifest: request.manifest,
      storedAt: now
    } satisfies StoredWelcomePickup);
    return { accepted: true };
  }

  async fetch(descriptor: WelcomePickupDescriptor, now: number): Promise<FetchWelcomePickupResult> {
    this.validateDescriptor(descriptor, now);
    const stored = await this.store.getJson<StoredWelcomePickup>(await pickupKey(descriptor.capability));
    if (!stored) {
      throw new HttpError(404, "not_found", "welcome pickup not found");
    }
    if (stored.descriptor.capability !== descriptor.capability) {
      throw new HttpError(403, "invalid_capability", "welcome pickup capability does not match stored descriptor");
    }
    if (stored.descriptor.expiresAt <= now) {
      await this.store.delete(await pickupKey(descriptor.capability));
      throw new HttpError(403, "capability_expired", "welcome pickup capability is expired");
    }
    return { welcomeB64: stored.welcomeB64, manifest: stored.manifest };
  }

  private validateDescriptor(descriptor: WelcomePickupDescriptor, now: number): void {
    if (!descriptor.groupId || !descriptor.deviceId || !descriptor.endpoint || !descriptor.capability) {
      throw new HttpError(400, "invalid_input", "welcome pickup descriptor is missing required fields");
    }
    if (descriptor.expiresAt <= now) {
      throw new HttpError(403, "capability_expired", "welcome pickup capability is expired");
    }
  }
}

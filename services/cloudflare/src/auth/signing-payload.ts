/**
 * The TypeScript half of the signing framing. Mirrors `src/model/signing.rs`.
 *
 * A signature binds a key to a byte string. If the domain is not inside those
 * bytes the domain does not exist, so every payload this worker verifies must
 * be assembled through `signingPayload(domain)` and never by hand.
 *
 * The Rust side is authoritative for the domain strings and the field order;
 * `test-fixtures/group-protocol-v1.json` pins a digest both sides must
 * reproduce.
 */

/**
 * Every payload signed outside MLS. Must stay in step with `SignatureDomain`
 * in `src/model/signing.rs` -- the shared fixture is what catches drift.
 *
 * Only the domains this worker actually verifies are listed. The group invite
 * and join/leave tokens are never verified as signatures (they are compared as
 * opaque bearer strings), so the worker has no reason to know their domains.
 */
export const SIGNATURE_DOMAIN = {
  groupManifest: "tapchat.group_manifest.v1",
  groupMembershipProof: "tapchat.group.membership.v1",
  groupCapability: "tapchat.group_capability.v2",
  inboxAppendCapability: "tapchat.inbox_append_capability.v1",
  deviceRuntimeAuth: "tapchat.device_runtime_auth.v2",
  deviceBinding: "tapchat.device_binding.v1",
  identityBundle: "tapchat.identity_bundle.v1"
} as const;

export type SignatureDomain = (typeof SIGNATURE_DOMAIN)[keyof typeof SIGNATURE_DOMAIN];

const encoder = new TextEncoder();

/** A length-prefixed byte writer, always opened with a domain. */
export class SigningPayload {
  private readonly chunks: Uint8Array[] = [];

  constructor(domain: SignatureDomain) {
    this.pushStr(domain);
  }

  /** A length-prefixed string: `u32` big-endian length, then UTF-8 bytes. */
  pushStr(value: string): this {
    return this.pushBytes(encoder.encode(value));
  }

  /** A length-prefixed byte string. */
  pushBytes(value: Uint8Array): this {
    const length = new Uint8Array(4);
    new DataView(length.buffer).setUint32(0, value.length, false);
    this.chunks.push(length, value);
    return this;
  }

  bytes() {
    const total = this.chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const chunk of this.chunks) {
      out.set(chunk, offset);
      offset += chunk.length;
    }
    return out;
  }
}

export function signingPayload(domain: SignatureDomain): SigningPayload {
  return new SigningPayload(domain);
}

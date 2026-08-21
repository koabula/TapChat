const HEADER_PREFIX = "v2.";

function payload(deviceId: string, messageId: string, accountState: "accepted"): Uint8Array {
  return new TextEncoder().encode(JSON.stringify([
    "tapchat-inbox-relationship-authorization-v2",
    deviceId,
    messageId,
    accountState
  ]));
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function bufferSource(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function fromHex(value: string): Uint8Array | null {
  if (!/^[0-9a-f]{64}$/i.test(value)) return null;
  return Uint8Array.from(value.match(/.{2}/g)!, (part) => Number.parseInt(part, 16));
}

async function hmacKey(secret: string, usages: KeyUsage[]): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    usages
  );
}

export async function signRelationshipAuthorization(
  secret: string,
  deviceId: string,
  messageId: string
): Promise<string> {
  const signature = await crypto.subtle.sign(
    "HMAC",
    await hmacKey(secret, ["sign"]),
    bufferSource(payload(deviceId, messageId, "accepted"))
  );
  return `${HEADER_PREFIX}${hex(new Uint8Array(signature))}`;
}

export async function verifyRelationshipAuthorization(
  secret: string,
  value: string | null,
  deviceId: string,
  messageId: string
): Promise<boolean> {
  if (!value?.startsWith(HEADER_PREFIX)) return false;
  const signature = fromHex(value.slice(HEADER_PREFIX.length));
  if (!signature) return false;
  return crypto.subtle.verify(
    "HMAC",
    await hmacKey(secret, ["verify"]),
    bufferSource(signature),
    bufferSource(payload(deviceId, messageId, "accepted"))
  );
}

export const RELATIONSHIP_AUTHORIZATION_HEADER = "X-Tapchat-Internal-Relationship-Authorization";

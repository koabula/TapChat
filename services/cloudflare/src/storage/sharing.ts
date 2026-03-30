const encoder = new TextEncoder();

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const output = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    output[i] = binary.charCodeAt(i);
  }
  return output;
}

async function importSecret(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

export async function signSharingPayload(secret: string, payload: Record<string, unknown>): Promise<string> {
  const encodedPayload = encoder.encode(JSON.stringify(payload));
  const key = await importSecret(secret);
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, encodedPayload));
  return `${toBase64Url(encodedPayload)}.${toBase64Url(signature)}`;
}

export async function verifySharingPayload<T>(secret: string, token: string, now: number): Promise<T> {
  const [payloadPart, signaturePart] = token.split(".");
  if (!payloadPart || !signaturePart) {
    throw new Error("invalid sharing token");
  }

  const payloadBytes = fromBase64Url(payloadPart);
  const signatureBytes = fromBase64Url(signaturePart);
  const key = await importSecret(secret);
  const payloadBuffer = payloadBytes.buffer.slice(
    payloadBytes.byteOffset,
    payloadBytes.byteOffset + payloadBytes.byteLength
  ) as ArrayBuffer;
  const signatureBuffer = signatureBytes.buffer.slice(
    signatureBytes.byteOffset,
    signatureBytes.byteOffset + signatureBytes.byteLength
  ) as ArrayBuffer;
  const valid = await crypto.subtle.verify("HMAC", key, signatureBuffer, payloadBuffer);
  if (!valid) {
    throw new Error("invalid sharing token");
  }

  const payload = JSON.parse(new TextDecoder().decode(payloadBytes)) as T & { expiresAt?: number };
  if (payload.expiresAt !== undefined && payload.expiresAt <= now) {
    throw new Error("sharing token expired");
  }
  return payload;
}

import { HttpError } from "./capability";
import type { Env } from "../types/env";

export const CONTROL_JSON_MAX_BYTES = 64 * 1024;
export const DEFAULT_MESSAGE_REQUEST_MAX_BODY_BYTES = 320 * 1024;

const MIN_SECRET_BYTES = 32;
const PLACEHOLDER_SECRETS = new Set([
  "replace-me",
  "replace-me-bootstrap",
  "changeme",
  "change-me",
  "secret"
]);

function requireSecretValue(value: string | undefined, label: string): string {
  const secret = value?.trim();
  if (
    !secret ||
    new TextEncoder().encode(secret).byteLength < MIN_SECRET_BYTES ||
    PLACEHOLDER_SECRETS.has(secret.toLowerCase())
  ) {
    throw new HttpError(
      503,
      "runtime_misconfigured",
      `${label} is missing or invalid`
    );
  }
  return secret;
}

export function requireSharingSecret(env: Env): string {
  return requireSecretValue(env.SHARING_INTERNAL_SECRET, "SHARING_INTERNAL_SECRET");
}

export interface RotatingSecretSet {
  current: { secret: string; keyId?: string };
  previous?: { secret: string; keyId?: string };
  graceUntilMs?: number;
  allowUnkeyedCurrent: boolean;
}

function optionalKeyId(value: string | undefined): string | undefined {
  const keyId = value?.trim();
  return keyId || undefined;
}

function rotationGraceUntilMs(env: Env): number | undefined {
  const raw = env.AUTH_ROTATION_GRACE_UNTIL_MS?.trim();
  if (!raw) return undefined;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new HttpError(503, "runtime_misconfigured", "AUTH_ROTATION_GRACE_UNTIL_MS is invalid");
  }
  return value;
}

export function requireDeviceRuntimeSecrets(env: Env): RotatingSecretSet {
  const currentKeyId = optionalKeyId(env.DEVICE_RUNTIME_SECRET_KEY_ID);
  if (!currentKeyId) {
    throw new HttpError(503, "runtime_misconfigured", "DEVICE_RUNTIME_SECRET_KEY_ID is missing");
  }
  const previousSecret = env.DEVICE_RUNTIME_SECRET_PREVIOUS?.trim();
  return {
    current: {
      secret: requireSecretValue(env.DEVICE_RUNTIME_SECRET, "DEVICE_RUNTIME_SECRET"),
      keyId: currentKeyId
    },
    previous: previousSecret
      ? {
          secret: requireSecretValue(previousSecret, "DEVICE_RUNTIME_SECRET_PREVIOUS"),
          keyId: optionalKeyId(env.DEVICE_RUNTIME_SECRET_PREVIOUS_KEY_ID)
        }
      : undefined,
    graceUntilMs: rotationGraceUntilMs(env),
    allowUnkeyedCurrent: false
  };
}

export async function readRequestTextLimited(request: Request, maxBytes: number): Promise<string> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    throw new HttpError(500, "runtime_misconfigured", "request body limit is invalid");
  }

  const declaredLength = request.headers.get("Content-Length");
  if (declaredLength !== null) {
    const parsed = Number(declaredLength);
    if (!Number.isFinite(parsed) || parsed < 0) {
      throw new HttpError(400, "invalid_input", "Content-Length is invalid");
    }
    if (parsed > maxBytes) {
      throw new HttpError(413, "request_too_large", "request body exceeds the configured limit");
    }
  }

  if (!request.body) {
    return "";
  }

  const reader = request.body.getReader();
  const decoder = new TextDecoder();
  let byteLength = 0;
  let body = "";
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      byteLength += value.byteLength;
      if (byteLength > maxBytes) {
        await reader.cancel("request body exceeds configured limit");
        throw new HttpError(413, "request_too_large", "request body exceeds the configured limit");
      }
      body += decoder.decode(value, { stream: true });
    }
    body += decoder.decode();
    return body;
  } finally {
    reader.releaseLock();
  }
}

export async function readJsonLimited<T>(request: Request, maxBytes: number): Promise<T> {
  const body = await readRequestTextLimited(request, maxBytes);
  try {
    return JSON.parse(body) as T;
  } catch {
    throw new HttpError(400, "invalid_input", "request body is not valid JSON");
  }
}

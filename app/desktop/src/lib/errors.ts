import {
  ERROR_ALLOWED_ARGS,
  ERROR_CATALOG,
  ERROR_DEFAULTS,
  type AppErrorCode,
} from "./error-codes.generated";

export interface AppErrorV1 {
  version: 1;
  code: string;
  domain: string;
  retryable: boolean;
  action?: string;
  args?: Record<string, string>;
  httpStatus?: number;
  correlationId?: string;
}

export interface PresentedError {
  error: AppErrorV1;
  title: string;
  message: string;
  action?: string;
}

const UNKNOWN_ERROR: AppErrorV1 = {
  version: 1,
  code: "unexpected_error",
  domain: "core",
  retryable: true,
  action: "retry",
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function safeCorrelationId(value: unknown): string | undefined {
  return typeof value === "string" && /^[A-Za-z0-9_.:-]{1,128}$/.test(value)
    ? value
    : undefined;
}

export function normalizeAppError(value: unknown): AppErrorV1 {
  let candidate: unknown = value;
  if (typeof candidate === "string") {
    try {
      candidate = JSON.parse(candidate);
    } catch {
      return { ...UNKNOWN_ERROR };
    }
  }
  if (!isRecord(candidate)) return { ...UNKNOWN_ERROR };
  const rawCode = typeof candidate.code === "string" ? candidate.code : undefined;
  if (
    candidate.version !== 1 ||
    !rawCode ||
    !Object.prototype.hasOwnProperty.call(ERROR_CATALOG, rawCode)
  ) {
    return { ...UNKNOWN_ERROR };
  }
  const code = rawCode as AppErrorCode;
  const [domain, defaultRetryable, defaultAction] = ERROR_DEFAULTS[code];
  const allowedArgs = ERROR_ALLOWED_ARGS[code] ?? [];
  const args = isRecord(candidate.args)
    ? Object.fromEntries(
        Object.entries(candidate.args).filter(
          (entry): entry is [string, string] =>
            allowedArgs.includes(entry[0]) && typeof entry[1] === "string",
        ),
      )
    : undefined;
  const correlationId = safeCorrelationId(candidate.correlationId);
  return {
    version: 1,
    code,
    domain,
    retryable:
      typeof candidate.retryable === "boolean" ? candidate.retryable : defaultRetryable,
    ...(defaultAction ? { action: defaultAction } : {}),
    ...(args && Object.keys(args).length > 0 ? { args } : {}),
    ...(Number.isInteger(candidate.httpStatus) && Number(candidate.httpStatus) >= 100
      && Number(candidate.httpStatus) <= 599
      ? { httpStatus: Number(candidate.httpStatus) }
      : {}),
    ...(correlationId ? { correlationId } : {}),
  };
}

export function presentError(value: unknown): PresentedError {
  const error = normalizeAppError(value);
  const entry = ERROR_CATALOG[error.code as AppErrorCode] ?? ERROR_CATALOG.unexpected_error;
  return {
    error,
    title: entry[0],
    message: entry[1],
    action: error.action ?? entry[3] ?? undefined,
  };
}

export class AppInvokeError extends Error {
  readonly appError: AppErrorV1;

  constructor(error: AppErrorV1) {
    super(presentError(error).message);
    this.name = "AppInvokeError";
    this.appError = error;
  }
}

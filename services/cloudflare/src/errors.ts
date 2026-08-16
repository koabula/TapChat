import { ERROR_DEFAULTS, type AppErrorCode } from "./error-codes.generated";
import type { AppErrorV1 } from "./types/contracts";

function registeredCode(code: string): AppErrorCode {
  return Object.prototype.hasOwnProperty.call(ERROR_DEFAULTS, code)
    ? code as AppErrorCode
    : "unexpected_error";
}

export function appErrorBody(
  status: number,
  code: string,
  correlationId: string,
  retryableOverride?: boolean
): AppErrorV1 {
  const safeCode = registeredCode(code);
  const [domain, defaultRetryable, defaultAction] = ERROR_DEFAULTS[safeCode];
  const retryable = retryableOverride ?? defaultRetryable;
  return {
    version: 1,
    code: safeCode,
    domain,
    retryable,
    ...(defaultAction ? { action: defaultAction } : {}),
    httpStatus: status,
    correlationId
  };
}

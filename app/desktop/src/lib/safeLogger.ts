const URL_PATTERN = /\b(?:https?|wss?):\/\/[^\s"']+/gi;
const WINDOWS_PATH_PATTERN = /\b[A-Za-z]:\\(?:[^\s\\]+\\)*[^\s]+/g;
const UNIX_PATH_PATTERN = /(?:^|\s)\/(?:Users|home|var|tmp|opt)\/[^\s]+/g;
const STABLE_ID_PATTERN = /\b(?:device|group|conversation|conv|message|msg|request|user|profile)[_:-][A-Za-z0-9._:@/-]+/gi;
const TOKEN_PATTERN = /\b(?:token|secret|capability|mnemonic|recovery(?:_phrase)?)[=:]\s*[^\s,;]+/gi;
const ATTACHMENT_PATTERN = /\b[^\s/\\]+\.(?:jpe?g|png|gif|webp|pdf|docx?|xlsx?|zip|mp4|mov|mp3|wav)\b/gi;

export function sanitizeLogText(value: string): string {
  return value
    .replace(URL_PATTERN, (raw) => {
      try {
        const url = new URL(raw);
        return `${url.protocol}//<redacted-host>/<redacted>`;
      } catch {
        return "<redacted-url>";
      }
    })
    .replace(WINDOWS_PATH_PATTERN, "<redacted-path>")
    .replace(UNIX_PATH_PATTERN, " <redacted-path>")
    .replace(STABLE_ID_PATTERN, "<redacted-id>")
    .replace(TOKEN_PATTERN, "<redacted-secret>")
    .replace(ATTACHMENT_PATTERN, "<redacted-filename>");
}

function sanitizeLogValue(value: unknown): unknown {
  if (typeof value === "string") {
    return sanitizeLogText(value);
  }
  if (value instanceof Error) {
    return `<${value.name || "Error"}>`;
  }
  if (value !== null && typeof value === "object") {
    return "<redacted-object>";
  }
  return value;
}

export function installProductionLogGuard(isProduction = import.meta.env.PROD): void {
  if (!isProduction) {
    return;
  }
  console.log = () => undefined;
  console.debug = () => undefined;
  console.info = () => undefined;

  const warn = console.warn.bind(console);
  const error = console.error.bind(console);
  console.warn = (...args: unknown[]) => warn(...args.map(sanitizeLogValue));
  console.error = (...args: unknown[]) => error(...args.map(sanitizeLogValue));
}

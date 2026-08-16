import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const registryPath = resolve(root, "contracts/error-codes.json");
const registry = JSON.parse(await readFile(registryPath, "utf8"));
const errors = registry.errors;
const allowedArgs = registry.allowedArgs ?? {};

if (registry.version !== 1 || !Array.isArray(errors) || typeof allowedArgs !== "object") {
  throw new Error("Invalid error contract registry.");
}
const codes = new Set();
for (const entry of errors) {
  if (
    !entry ||
    typeof entry.code !== "string" ||
    !/^[a-z0-9_]+$/.test(entry.code) ||
    codes.has(entry.code) ||
    typeof entry.domain !== "string" ||
    typeof entry.retryable !== "boolean" ||
    (entry.action !== null && typeof entry.action !== "string") ||
    typeof entry.title !== "string" ||
    typeof entry.message !== "string"
  ) {
    throw new Error(`Invalid error contract entry: ${JSON.stringify(entry)}`);
  }
  codes.add(entry.code);
}
for (const [code, args] of Object.entries(allowedArgs)) {
  if (!codes.has(code) || !Array.isArray(args) || args.some((arg) => typeof arg !== "string")) {
    throw new Error(`Invalid allowedArgs entry for ${code}.`);
  }
}

const q = (value) => JSON.stringify(value);
const rustDomain = {
  core: "Core",
  validation: "Validation",
  identity: "Identity",
  mls: "Mls",
  transport: "Transport",
  runtime: "Runtime",
  storage: "Storage",
  security: "Security",
  group: "Group",
};
const rustAction = {
  retry: "Retry",
  retry_later: "RetryLater",
  sync_now: "SyncNow",
  refresh_identity: "RefreshIdentity",
  reconnect: "Reconnect",
  reconnect_runtime: "ReconnectRuntime",
  upgrade_app: "UpgradeApp",
  upgrade_runtime: "UpgradeRuntime",
  restart_app: "RestartApp",
  copy_diagnostics: "CopyDiagnostics",
};

function desktopGenerated() {
  const catalog = errors.map((entry) =>
    `  ${entry.code}: [${q(entry.title)}, ${q(entry.message)}, ${entry.retryable}, ${entry.action === null ? "null" : q(entry.action)}],`
  ).join("\n");
  const defaults = errors.map((entry) =>
    `  ${entry.code}: [${q(entry.domain)}, ${entry.retryable}, ${entry.action === null ? "null" : q(entry.action)}],`
  ).join("\n");
  return `// Generated from contracts/error-codes.json. Do not add user-facing copy elsewhere.\nexport const ERROR_CATALOG = {\n${catalog}\n} as const;\n\nexport const ERROR_DEFAULTS = {\n${defaults}\n} as const;\n\nexport const ERROR_ALLOWED_ARGS: Partial<Record<keyof typeof ERROR_CATALOG, readonly string[]>> = ${JSON.stringify(allowedArgs, null, 2)};\n\nexport type AppErrorCode = keyof typeof ERROR_CATALOG;\n`;
}

function workerGenerated() {
  const defaults = errors.map((entry) =>
    `  ${entry.code}: [${q(entry.domain)}, ${entry.retryable}, ${entry.action === null ? "null" : q(entry.action)}],`
  ).join("\n");
  return `// Generated from contracts/error-codes.json.\nexport const ERROR_DEFAULTS = {\n${defaults}\n} as const;\n\nexport type AppErrorCode = keyof typeof ERROR_DEFAULTS;\n`;
}

function rustGenerated() {
  for (const entry of errors) {
    if (!rustDomain[entry.domain] || (entry.action !== null && !rustAction[entry.action])) {
      throw new Error(`Rust mapping is unavailable for ${entry.code}.`);
    }
  }
  const codeLines = errors.map((entry) => `    ${q(entry.code)},`).join("\n");
  const defaultLines = errors.map((entry) =>
    `    (${q(entry.code)}, ${q(entry.domain)}, ${entry.retryable}, ${entry.action === null ? "None" : `Some(${q(entry.action)})`}),`
  ).join("\n");
  const domainLines = Object.entries(rustDomain).map(([name, variant]) => `        ${q(name)} => ${variant},`).join("\n");
  const actionLines = Object.entries(rustAction).map(([name, variant]) => `        Some(${q(name)}) => Some(${variant}),`).join("\n");
  const argLines = Object.entries(allowedArgs).flatMap(([code, args]) =>
    args.map((arg) => `        (${q(code)}, ${q(arg)}) => true,`)
  ).join("\n");
  return `// Generated from contracts/error-codes.json.\npub const APP_ERROR_CODES: &[&str] = &[\n${codeLines}\n];\n\nconst APP_ERROR_DEFAULTS: &[(&str, &str, bool, Option<&str>)] = &[\n${defaultLines}\n];\n\npub fn is_registered_app_error(code: &str) -> bool {\n    APP_ERROR_CODES.contains(&code)\n}\n\npub fn is_allowed_error_arg(code: &str, arg: &str) -> bool {\n    match (code, arg) {\n${argLines || "        _ => false,"}\n${argLines ? "        _ => false,\n" : ""}    }\n}\n\npub fn app_error_defaults(\n    code: &str,\n) -> Option<(\n    crate::error::ErrorDomain,\n    bool,\n    Option<crate::error::RecoveryAction>,\n)> {\n    use crate::error::{ErrorDomain::*, RecoveryAction::*};\n    let (_, domain, retryable, action) = APP_ERROR_DEFAULTS\n        .iter()\n        .find(|(candidate, _, _, _)| *candidate == code)?;\n    let domain = match *domain {\n${domainLines}\n        _ => return None,\n    };\n    let action = match *action {\n        None => None,\n${actionLines}\n        Some(_) => return None,\n    };\n    Some((domain, *retryable, action))\n}\n`;
}

const outputs = new Map([
  [resolve(root, "app/desktop/src/lib/error-codes.generated.ts"), desktopGenerated()],
  [resolve(root, "services/cloudflare/src/error-codes.generated.ts"), workerGenerated()],
  [resolve(root, "src/error_codes_generated.rs"), rustGenerated()],
]);

if (process.argv.includes("--write")) {
  await Promise.all([...outputs].map(([path, contents]) => writeFile(path, contents, "utf8")));
  console.log(`generated error contract (${errors.length} codes)`);
} else {
  for (const [path, expected] of outputs) {
    const actual = await readFile(path, "utf8");
    const normalizedActual = path.endsWith(".rs")
      ? actual.replace(/\s+/g, "").replace(/,\)/g, ")")
      : actual.replaceAll("\r\n", "\n");
    const normalizedExpected = path.endsWith(".rs")
      ? expected.replace(/\s+/g, "").replace(/,\)/g, ")")
      : expected;
    if (normalizedActual !== normalizedExpected) {
      throw new Error(`Generated error contract is out of date: ${path}. Run this script with --write.`);
    }
  }
  console.log(`error contract ok (${errors.length} codes)`);
}

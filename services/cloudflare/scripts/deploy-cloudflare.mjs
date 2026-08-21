import { createInterface } from "node:readline/promises";
import { randomBytes, randomUUID } from "node:crypto";
import { access, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { stdin, stdout } from "node:process";
import { parse } from "jsonc-parser";

const EXIT_CODES = {
  environment: 2,
  login: 3,
  resource: 4,
  test: 5,
  deploy: 6
};

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const SERVICE_DIR = path.resolve(SCRIPT_DIR, "..");
const CONFIG_PATH = path.join(SERVICE_DIR, "wrangler.jsonc");
const WRANGLER_ENTRY = path.join(SERVICE_DIR, "node_modules", "wrangler", "bin", "wrangler.js");
const NODE_COMMAND = process.execPath;
const NPM_EXEC_PATH = process.env.npm_execpath;
const NPM_COMMAND = process.platform === "win32" ? "npm.cmd" : "npm";
const TEMP_DIR_PREFIX = path.join(os.tmpdir(), "tapchat-cloudflare-deploy-");
const TEMP_CONFIG_NAME = ".wrangler.deploy.jsonc";
const NON_INTERACTIVE_CONFIG = process.env.TAPCHAT_CLOUDFLARE_DEPLOY_CONFIG_JSON;
const JSON_OUTPUT = process.env.TAPCHAT_CLOUDFLARE_DEPLOY_OUTPUT === "json";
const DESKTOP_BUNDLED = process.env.TAPCHAT_DESKTOP_BUNDLED === "1";

const DEFAULTS = {
  workerName: "tapchat-cloudflare",
  deploymentRegion: "global",
  maxInlineBytes: "4096",
  retentionDays: "30",
  rateLimitPerMinute: "60",
  rateLimitPerHour: "600",
  messageRequestMaxBodyBytes: "327680",
  messageRequestMaxPerSender: "16",
  messageRequestMaxSenders: "64",
  messageRequestMaxTotalBytes: "4194304",
  messageRequestTtlSeconds: "604800",
  messageRequestRateLimitMinute: "30",
  messageRequestRateLimitHour: "300"
};

function printUsage() {
  stdout.write(
    [
      "TapChat Cloudflare deployment wizard",
      "",
      "Runs locally and deploys the Cloudflare transport to a real Cloudflare account.",
      "",
      "Usage:",
      "  npm run deploy:cloudflare",
      ""
    ].join("\n")
  );
}

function logStep(message) {
  if (!JSON_OUTPUT) {
    stdout.write(`\n==> ${message}\n`);
  }
}

function deriveBucketNames(workerName) {
  return {
    bucketName: `${workerName}-storage`
  };
}

function normalizeBaseUrl(value) {
  const trimmed = value.trim();
  return trimmed ? trimmed.replace(/\/+$/, "") : "";
}

function ensureServicesDirectory() {
  return path.resolve(process.cwd()) === SERVICE_DIR;
}

function wranglerArgs(...args) {
  return [WRANGLER_ENTRY, ...args];
}

function npmArgs(...args) {
  if (NPM_EXEC_PATH) {
    return [NPM_EXEC_PATH, ...args];
  }
  if (process.platform === "win32") {
    return ["/d", "/s", "/c", NPM_COMMAND, ...args];
  }
  return args;
}

function npmCommand() {
  if (NPM_EXEC_PATH) {
    return NODE_COMMAND;
  }
  if (process.platform === "win32") {
    return process.env.ComSpec ?? "cmd.exe";
  }
  return NPM_COMMAND;
}
function isWranglerUnauthenticated(result) {
  const output = `${result.stdout ?? ""}\n${result.stderr ?? ""}`.toLowerCase();
  return output.includes("you are not authenticated") || output.includes("please run `wrangler login`") || output.includes("please run wrangler login");
}
function isBucketAlreadyExists(result) {
  const output = `${result.stdout ?? ""}\n${result.stderr ?? ""}`.toLowerCase();
  return output.includes("already exists") || output.includes("bucket name is not available") || output.includes("the bucket you are trying to create already exists");
}

function generateSecret() {
  return randomBytes(32).toString("hex");
}

function generateKeyId() {
  return `key-${randomBytes(8).toString("hex")}`;
}

function validateSecret(value, label) {
  const normalized = String(value ?? "").trim();
  if (
    Buffer.byteLength(normalized, "utf8") < 32 ||
    ["replace-me", "replace-me-bootstrap", "changeme", "change-me", "secret"].includes(normalized.toLowerCase())
  ) {
    throw new Error(`${label} must be an independently generated secret of at least 32 bytes.`);
  }
}

async function runCommand(command, args, options = {}) {
  const {
    cwd = SERVICE_DIR,
    env,
    input,
    capture = false,
    allowFailure = false
  } = options;

  return await new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      env: env ? { ...process.env, ...env } : process.env,
      stdio: ["pipe", "pipe", "pipe"],
      shell: false,
      windowsHide: true
    });

    let stdoutBuffer = "";
    let stderrBuffer = "";

    child.stdout.on("data", (chunk) => {
      const text = chunk.toString();
      stdoutBuffer += text;
      if (!capture) {
        stdout.write(text);
      }
    });
    child.stderr.on("data", (chunk) => {
      const text = chunk.toString();
      stderrBuffer += text;
      if (!capture) {
        process.stderr.write(text);
      }
    });

    child.on("error", (error) => {
      reject(error);
    });

    if (input !== undefined) {
      child.stdin.write(input);
    }
    child.stdin.end();

    child.on("close", (code) => {
      const result = {
        code: code ?? 0,
        stdout: stdoutBuffer,
        stderr: stderrBuffer
      };
      if (!allowFailure && result.code !== 0) {
        const error = new Error(`Command failed: ${command} ${args.join(" ")} (exit ${result.code})`);
        error.result = result;
        reject(error);
        return;
      }
      resolve(result);
    });
  });
}

function coerceResolvedConfig(config) {
  const configuredSharingSecret = config.sharing_internal_secret ?? config.sharing_token_secret ?? config.sharingTokenSecret;
  const configuredRuntimeSecret = config.device_runtime_secret ?? config.deviceRuntimeSecret;
  return {
    runtimeId: config.runtime_id ?? config.runtimeId,
    ownerUserId: config.owner_user_id ?? config.ownerUserId,
    ownerUserPublicKey: config.owner_user_public_key ?? config.ownerUserPublicKey,
    workerName: config.worker_name ?? config.workerName,
    publicBaseUrl: normalizeBaseUrl(config.public_base_url ?? config.publicBaseUrl ?? ""),
    deploymentRegion: String(config.deployment_region ?? config.deploymentRegion ?? DEFAULTS.deploymentRegion),
    maxInlineBytes: String(config.max_inline_bytes ?? config.maxInlineBytes ?? DEFAULTS.maxInlineBytes),
    retentionDays: String(config.retention_days ?? config.retentionDays ?? DEFAULTS.retentionDays),
    rateLimitPerMinute: String(config.rate_limit_per_minute ?? config.rateLimitPerMinute ?? DEFAULTS.rateLimitPerMinute),
    rateLimitPerHour: String(config.rate_limit_per_hour ?? config.rateLimitPerHour ?? DEFAULTS.rateLimitPerHour),
    messageRequestMaxBodyBytes: String(config.message_request_max_body_bytes ?? config.messageRequestMaxBodyBytes ?? DEFAULTS.messageRequestMaxBodyBytes),
    messageRequestMaxPerSender: String(config.message_request_max_per_sender ?? config.messageRequestMaxPerSender ?? DEFAULTS.messageRequestMaxPerSender),
    messageRequestMaxSenders: String(config.message_request_max_senders ?? config.messageRequestMaxSenders ?? DEFAULTS.messageRequestMaxSenders),
    messageRequestMaxTotalBytes: String(config.message_request_max_total_bytes ?? config.messageRequestMaxTotalBytes ?? DEFAULTS.messageRequestMaxTotalBytes),
    messageRequestTtlSeconds: String(config.message_request_ttl_seconds ?? config.messageRequestTtlSeconds ?? DEFAULTS.messageRequestTtlSeconds),
    messageRequestRateLimitMinute: String(config.message_request_rate_limit_minute ?? config.messageRequestRateLimitMinute ?? DEFAULTS.messageRequestRateLimitMinute),
    messageRequestRateLimitHour: String(config.message_request_rate_limit_hour ?? config.messageRequestRateLimitHour ?? DEFAULTS.messageRequestRateLimitHour),
    bucketName: config.bucket_name ?? config.bucketName,
    sharingTokenSecret: configuredSharingSecret ?? generateSecret(),
    deviceRuntimeSecret: configuredRuntimeSecret ?? generateSecret(),
    deviceRuntimeKeyId: config.device_runtime_key_id ?? config.deviceRuntimeKeyId ?? generateKeyId(),
    deviceRuntimePreviousSecret: config.device_runtime_previous_secret ?? config.deviceRuntimePreviousSecret,
    deviceRuntimePreviousKeyId: config.device_runtime_previous_key_id ?? config.deviceRuntimePreviousKeyId,
    authRotationGraceUntilMs: config.auth_rotation_grace_until_ms ?? config.authRotationGraceUntilMs,
    generatedPublicBaseUrl: !normalizeBaseUrl(config.public_base_url ?? config.publicBaseUrl ?? ""),
    generatedSharingSecret: !configuredSharingSecret
  };
}

async function collectInputs() {
  if (NON_INTERACTIVE_CONFIG) {
    return coerceResolvedConfig(JSON.parse(NON_INTERACTIVE_CONFIG));
  }

  const rl = createInterface({ input: stdin, output: stdout });
  try {
    const workerName =
      (await rl.question(`Worker name [${DEFAULTS.workerName}]: `)).trim() ||
      DEFAULTS.workerName;
    const generatedRuntimeId = randomUUID();
    const runtimeId = (await rl.question(`RUNTIME_ID [${generatedRuntimeId}]: `)).trim() || generatedRuntimeId;
    const ownerUserId = (await rl.question("OWNER_USER_ID: ")).trim();
    const ownerUserPublicKey = (await rl.question("OWNER_USER_PUBLIC_KEY: ")).trim();
    const derivedBuckets = deriveBucketNames(workerName);

    const publicBaseUrlInput = await rl.question("PUBLIC_BASE_URL [leave blank to use the deployed URL automatically]: ");
    const publicBaseUrl = normalizeBaseUrl(publicBaseUrlInput);
    const deploymentRegion =
      (await rl.question(`DEPLOYMENT_REGION [${DEFAULTS.deploymentRegion}]: `)).trim() ||
      DEFAULTS.deploymentRegion;
    const maxInlineBytes =
      (await rl.question(`MAX_INLINE_BYTES [${DEFAULTS.maxInlineBytes}]: `)).trim() ||
      DEFAULTS.maxInlineBytes;
    const retentionDays =
      (await rl.question(`RETENTION_DAYS [${DEFAULTS.retentionDays}]: `)).trim() ||
      DEFAULTS.retentionDays;
    const rateLimitPerMinute =
      (await rl.question(`RATE_LIMIT_PER_MINUTE [${DEFAULTS.rateLimitPerMinute}]: `)).trim() ||
      DEFAULTS.rateLimitPerMinute;
    const rateLimitPerHour =
      (await rl.question(`RATE_LIMIT_PER_HOUR [${DEFAULTS.rateLimitPerHour}]: `)).trim() ||
      DEFAULTS.rateLimitPerHour;
    const bucketName =
      (await rl.question(`R2 bucket name [${derivedBuckets.bucketName}]: `)).trim() ||
      derivedBuckets.bucketName;

    const generatedSharingSecret = generateSecret();
    const generatedRuntimeSecret = generateSecret();
    const sharingTokenSecret = (
      await rl.question(`SHARING_INTERNAL_SECRET [press Enter to auto-generate]: `)
    ).trim() || generatedSharingSecret;
    return {
      runtimeId,
      ownerUserId,
      ownerUserPublicKey,
      workerName,
      publicBaseUrl,
      deploymentRegion,
      maxInlineBytes,
      retentionDays,
      rateLimitPerMinute,
      rateLimitPerHour,
      messageRequestMaxBodyBytes: DEFAULTS.messageRequestMaxBodyBytes,
      messageRequestMaxPerSender: DEFAULTS.messageRequestMaxPerSender,
      messageRequestMaxSenders: DEFAULTS.messageRequestMaxSenders,
      messageRequestMaxTotalBytes: DEFAULTS.messageRequestMaxTotalBytes,
      messageRequestTtlSeconds: DEFAULTS.messageRequestTtlSeconds,
      messageRequestRateLimitMinute: DEFAULTS.messageRequestRateLimitMinute,
      messageRequestRateLimitHour: DEFAULTS.messageRequestRateLimitHour,
      bucketName,
      sharingTokenSecret,
      deviceRuntimeSecret: generatedRuntimeSecret,
      deviceRuntimeKeyId: generateKeyId(),
      deviceRuntimePreviousSecret: undefined,
      deviceRuntimePreviousKeyId: undefined,
      authRotationGraceUntilMs: undefined,
      generatedPublicBaseUrl: !publicBaseUrl,
      generatedSharingSecret: sharingTokenSecret === generatedSharingSecret
    };
  } finally {
    rl.close();
  }
}

function updateConfig(baseConfig, config) {
  const entryPoint = path.join(SERVICE_DIR, "src", "index.ts").replace(/\\/g, "/");
  const parseErrors = [];
  const rendered = parse(baseConfig, parseErrors, { allowTrailingComma: true });
  if (!rendered || parseErrors.length > 0) {
    throw new Error("wrangler.jsonc is invalid and cannot be used for deployment");
  }
  rendered.name = config.workerName;
  rendered.main = entryPoint;
  rendered.vars = {
    ...rendered.vars,
    RUNTIME_ID: config.runtimeId,
    OWNER_USER_ID: config.ownerUserId,
    OWNER_USER_PUBLIC_KEY: config.ownerUserPublicKey,
    WORKER_BUILD_ID: config.workerBuildId,
    DEPLOYMENT_REGION: config.deploymentRegion,
    MAX_INLINE_BYTES: config.maxInlineBytes,
    RETENTION_DAYS: config.retentionDays,
    RATE_LIMIT_PER_MINUTE: config.rateLimitPerMinute,
    RATE_LIMIT_PER_HOUR: config.rateLimitPerHour,
    MESSAGE_REQUEST_MAX_BODY_BYTES: config.messageRequestMaxBodyBytes,
    MESSAGE_REQUEST_MAX_PER_SENDER: config.messageRequestMaxPerSender,
    MESSAGE_REQUEST_MAX_SENDERS: config.messageRequestMaxSenders,
    MESSAGE_REQUEST_MAX_TOTAL_BYTES: config.messageRequestMaxTotalBytes,
    MESSAGE_REQUEST_TTL_SECONDS: config.messageRequestTtlSeconds,
    MESSAGE_REQUEST_RATE_LIMIT_MINUTE: config.messageRequestRateLimitMinute,
    MESSAGE_REQUEST_RATE_LIMIT_HOUR: config.messageRequestRateLimitHour
  };
  rendered.vars.DEVICE_RUNTIME_SECRET_KEY_ID = config.deviceRuntimeKeyId;
  if (config.deviceRuntimePreviousKeyId) {
    rendered.vars.DEVICE_RUNTIME_SECRET_PREVIOUS_KEY_ID = config.deviceRuntimePreviousKeyId;
  } else {
    delete rendered.vars.DEVICE_RUNTIME_SECRET_PREVIOUS_KEY_ID;
  }
  if (config.authRotationGraceUntilMs != null) {
    rendered.vars.AUTH_ROTATION_GRACE_UNTIL_MS = String(config.authRotationGraceUntilMs);
  } else {
    delete rendered.vars.AUTH_ROTATION_GRACE_UNTIL_MS;
  }
  if (config.publicBaseUrl) {
    rendered.vars.PUBLIC_BASE_URL = config.publicBaseUrl;
  } else {
    delete rendered.vars.PUBLIC_BASE_URL;
  }
  rendered.r2_buckets = rendered.r2_buckets.map((bucket) =>
    bucket.binding === "TAPCHAT_STORAGE"
      ? {
          ...bucket,
          bucket_name: config.bucketName
        }
      : bucket
  );
  return `${JSON.stringify(rendered, null, 2)}\n`;
}

async function ensureBuckets(configPath, bucketNames) {
  for (const bucketName of bucketNames) {
    if (!JSON_OUTPUT) {
      stdout.write(`Ensuring bucket ${bucketName}\n`);
    }
    const createResult = await runCommand(
      NODE_COMMAND,
      wranglerArgs("r2", "bucket", "create", bucketName, "--config", configPath),
      { capture: true, allowFailure: true }
    );

    if (createResult.code === 0) {
      if (!JSON_OUTPUT) {
        stdout.write(createResult.stdout);
      }
      continue;
    }

    if (isBucketAlreadyExists(createResult)) {
      if (!JSON_OUTPUT) {
        stdout.write(`Reusing existing bucket ${bucketName}\n`);
      }
      continue;
    }

    process.exitCode = EXIT_CODES.resource;
    const output = `${createResult.stdout}\n${createResult.stderr}`.trim();
    throw new Error(`Failed to create or reuse bucket ${bucketName}: ${output}`);
  }
}

async function putSecret(configPath, name, value) {
  await runCommand(NODE_COMMAND, wranglerArgs("secret", "put", name, "--config", configPath), {
    input: `${value}\n`
  });
}

function parseDeployUrl(output) {
  const matches = [...output.matchAll(/https:\/\/[^\s]+/g)].map((match) => match[0].replace(/\/+$/, ""));
  if (matches.length === 0) {
    return null;
  }

  const preferred = matches.filter((candidate) => {
    try {
      const url = new URL(candidate);
      return url.hostname.endsWith(".workers.dev") || (url.pathname === "" || url.pathname === "/");
    } catch {
      return false;
    }
  });

  return (preferred.at(-1) ?? matches.at(-1)) ?? null;
}

function validateDeployUrl(publicBaseUrl, deployUrl) {
  if (!deployUrl) {
    return {
      ok: false,
      message: "Wrangler deploy did not print a Worker URL. Verify the deployed route manually before using this environment."
    };
  }

  if (!publicBaseUrl) {
    return { ok: true, effectiveBaseUrl: deployUrl };
  }

  const expected = new URL(publicBaseUrl);
  const actual = new URL(deployUrl);

  if (expected.origin === actual.origin) {
    return { ok: true, effectiveBaseUrl: publicBaseUrl };
  }

  const expectedIsWorkersDev = expected.hostname.endsWith(".workers.dev");
  const actualIsWorkersDev = actual.hostname.endsWith(".workers.dev");
  if (expectedIsWorkersDev && actualIsWorkersDev) {
    return {
      ok: false,
      message: `Configured PUBLIC_BASE_URL ${expected.origin} does not match deployed Worker URL ${actual.origin}.`
    };
  }

  return {
    ok: true,
    effectiveBaseUrl: publicBaseUrl,
    warning: `Deployed Worker URL is ${actual.origin}, while PUBLIC_BASE_URL is ${expected.origin}. If you are using a custom domain, verify routing manually.`
  };
}

async function deleteSecretBestEffort(configPath, name) {
  await runCommand(NODE_COMMAND, wranglerArgs("secret", "delete", name, "--config", configPath), {
    input: "y\n",
    capture: true,
    allowFailure: true
  });
}

async function verifyRuntimeConfiguration(baseUrl, config) {
  const deadline = Date.now() + 90_000;
  let delayMs = 500;
  let lastError = "runtime not ready";
  while (Date.now() < deadline) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);
    try {
      const response = await fetch(`${baseUrl.replace(/\/+$/, "")}/v2/runtime/ready`, {
        signal: controller.signal,
        headers: { Accept: "application/json" }
      });
      if (response.ok) {
        const ready = await response.json();
        if (ready.runtimeId !== config.runtimeId) throw new Error("runtime_mismatch");
        if (ready.protocolVersion !== 6) throw new Error("protocol_mismatch");
        if (ready.workerBuildId !== config.workerBuildId) throw new Error("worker_build_mismatch");
        if (ready.registrySchemaVersion !== 3) throw new Error("registry_schema_mismatch");
        return ready;
      }
      if (![404, 409, 429].includes(response.status) && response.status < 500) {
        throw new Error(`runtime readiness failed with HTTP ${response.status}`);
      }
      lastError = `HTTP ${response.status}`;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (message.endsWith("_mismatch") || message.startsWith("runtime readiness failed")) throw error;
      lastError = message;
    } finally {
      clearTimeout(timeout);
    }
    await new Promise((resolve) => setTimeout(resolve, delayMs));
    delayMs = Math.min(delayMs * 2, 5_000);
  }
  throw new Error(`Runtime readiness timed out after 90 seconds (${lastError}).`);
}

function printStructuredResult(result) {
  stdout.write(`${JSON.stringify(result)}\n`);
}

async function main() {
  if (process.argv.includes("--help")) {
    printUsage();
    return;
  }

  if (!ensureServicesDirectory()) {
    throw new Error("Run this script from services/cloudflare or invoke it via npm run deploy:cloudflare.");
  }

  logStep("Checking local environment");
  try {
    await access(CONFIG_PATH);
    await access(WRANGLER_ENTRY);
  } catch {
    process.exitCode = EXIT_CODES.environment;
    throw new Error("Missing required local tooling. Ensure npm install has completed and local wrangler is available in node_modules.");
  }

  await readFile(CONFIG_PATH, "utf8");

  logStep("Checking Wrangler authentication");
  const whoami = await runCommand(NODE_COMMAND, wranglerArgs("whoami"), {
    capture: true,
    allowFailure: true
  });
  if (whoami.code !== 0 || isWranglerUnauthenticated(whoami)) {
    const initialAuthOutput = `${whoami.stdout || ""}\n${whoami.stderr || ""}`.trim();
    if (initialAuthOutput && !JSON_OUTPUT) {
      stdout.write(`${initialAuthOutput}\n`);
    }
    if (!JSON_OUTPUT) {
      stdout.write("Wrangler is not logged in. Starting `wrangler login`.\n");
    }
    const login = await runCommand(NODE_COMMAND, wranglerArgs("login"), { allowFailure: true });
    if (login.code !== 0) {
      process.exitCode = EXIT_CODES.login;
      throw new Error("Wrangler login failed.");
    }
    const whoamiAfter = await runCommand(NODE_COMMAND, wranglerArgs("whoami"), {
      capture: true,
      allowFailure: true
    });
    if (whoamiAfter.code !== 0 || isWranglerUnauthenticated(whoamiAfter)) {
      process.exitCode = EXIT_CODES.login;
      throw new Error("Wrangler login completed, but whoami still reports an unauthenticated session.");
    }
    if (!JSON_OUTPUT) {
      stdout.write(whoamiAfter.stdout);
    }
  } else if (!JSON_OUTPUT) {
    stdout.write(whoami.stdout);
  }

  logStep("Collecting deployment settings");
  const config = await collectInputs();
  config.workerBuildId = config.workerBuildId ?? "tapchat-worker-v4-dev";
  if (!config.runtimeId || !config.ownerUserId || !config.ownerUserPublicKey) {
    throw new Error("RUNTIME_ID, OWNER_USER_ID, and OWNER_USER_PUBLIC_KEY are required.");
  }
  validateSecret(config.sharingTokenSecret, "SHARING_INTERNAL_SECRET");
  validateSecret(config.deviceRuntimeSecret, "DEVICE_RUNTIME_SECRET");
  if (config.sharingTokenSecret === config.deviceRuntimeSecret) {
    throw new Error("Sharing and device runtime secrets must be independent values.");
  }
  const baseConfig = await readFile(CONFIG_PATH, "utf8");
  const renderedConfig = updateConfig(baseConfig, config);

  const tempDir = await mkdtemp(TEMP_DIR_PREFIX);
  const tempConfigPath = path.join(tempDir, TEMP_CONFIG_NAME);
  await writeFile(tempConfigPath, renderedConfig, "utf8");

  try {
    logStep("Preparing Cloudflare resources");
    await ensureBuckets(tempConfigPath, [config.bucketName]);

    logStep("Writing Cloudflare secrets");
    await putSecret(tempConfigPath, "SHARING_INTERNAL_SECRET", config.sharingTokenSecret);
    if (config.deviceRuntimePreviousSecret) {
      await putSecret(tempConfigPath, "DEVICE_RUNTIME_SECRET_PREVIOUS", config.deviceRuntimePreviousSecret);
    }
    await putSecret(tempConfigPath, "DEVICE_RUNTIME_SECRET", config.deviceRuntimeSecret);

    if (DESKTOP_BUNDLED) {
      logStep("Skipping pre-deploy checks in desktop bundled mode");
    } else {
      logStep("Running pre-deploy checks");
      try {
        await runCommand(npmCommand(), npmArgs("run", "check"));
        await runCommand(npmCommand(), npmArgs("test"));
        await runCommand(npmCommand(), npmArgs("run", "test:integration"));
      } catch (error) {
        process.exitCode = EXIT_CODES.test;
        throw error;
      }
    }

    logStep("Deploying to Cloudflare");
    let deployResult;
    try {
      deployResult = await runCommand(NODE_COMMAND, wranglerArgs("deploy", "--config", tempConfigPath), {
        capture: true
      });
    } catch (error) {
      process.exitCode = EXIT_CODES.deploy;
      throw error;
    }
    if (!JSON_OUTPUT) {
      stdout.write(deployResult.stdout);
      if (deployResult.stderr) {
        stdout.write(deployResult.stderr);
      }
    }

    const deployUrl = parseDeployUrl(`${deployResult.stdout}\n${deployResult.stderr}`);
    const validation = validateDeployUrl(config.publicBaseUrl, deployUrl);
    if (!validation.ok) {
      process.exitCode = EXIT_CODES.deploy;
      throw new Error(validation.message);
    }
    if (validation.warning && !JSON_OUTPUT) {
      stdout.write(`${validation.warning}\n`);
    }

    logStep("Verifying runtime security configuration");
    await verifyRuntimeConfiguration(validation.effectiveBaseUrl ?? deployUrl, config);
    if (!config.deviceRuntimePreviousSecret) {
      await deleteSecretBestEffort(tempConfigPath, "DEVICE_RUNTIME_SECRET_PREVIOUS");
    }

    const structuredResult = {
      success: true,
      worker_name: config.workerName,
      deploy_url: deployUrl,
      effective_public_base_url: validation.effectiveBaseUrl ?? config.publicBaseUrl,
      bucket_name: config.bucketName,
      deployment_region: config.deploymentRegion,
      generated_secrets: {
        sharing_token_secret: config.generatedSharingSecret
      },
      mode: NON_INTERACTIVE_CONFIG ? "non_interactive" : "interactive"
    };

    logStep("Deployment completed");
    if (!JSON_OUTPUT) {
      stdout.write(
        [
          `Worker name: ${config.workerName}`,
          `PUBLIC_BASE_URL: ${validation.effectiveBaseUrl ?? config.publicBaseUrl}`,
          `Storage bucket: ${config.bucketName}`,
          config.generatedPublicBaseUrl ? "PUBLIC_BASE_URL was left blank, so the deployed Worker URL will be used at runtime via request origin fallback." : "PUBLIC_BASE_URL was explicitly configured.",
          config.generatedSharingSecret ? "SHARING_INTERNAL_SECRET was auto-generated for this deployment." : "SHARING_INTERNAL_SECRET was provided manually.",
          "Next step: enroll the current device through POST /v2/runtime-auth/enroll."
        ].join("\n") + "\n"
      );
    }
    if (JSON_OUTPUT) {
      printStructuredResult(structuredResult);
    }
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

main().catch((error) => {
  const stderrSummary =
    error && typeof error === "object" && "result" in error
      ? `${error.result?.stdout ?? ""}\n${error.result?.stderr ?? ""}`.trim() || (error instanceof Error ? error.message : String(error))
      : error instanceof Error
        ? error.message
        : String(error);
  if (JSON_OUTPUT) {
    printStructuredResult({
      success: false,
      worker_name: "",
      deploy_url: "",
      effective_public_base_url: "",
      bucket_name: "",
      deployment_region: "",
      generated_secrets: {
        sharing_token_secret: false
      },
      mode: NON_INTERACTIVE_CONFIG ? "non_interactive" : "interactive",
      failure_class: process.exitCode ? String(process.exitCode) : "unknown",
      stderr_summary: stderrSummary
    });
  }
  if (!process.exitCode) {
    process.exitCode = EXIT_CODES.environment;
  }
  const message = stderrSummary;
  console.error(`Deployment failed: ${message}`);
});









import { createInterface } from "node:readline/promises";
import { randomBytes } from "node:crypto";
import { access, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { stdin, stdout } from "node:process";

const EXIT_CODES = {
  environment: 2,
  login: 3,
  resource: 4,
  test: 5,
  deploy: 6
};

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const SERVICE_DIR = path.resolve(SCRIPT_DIR, "..");
const CONFIG_PATH = path.join(SERVICE_DIR, "wrangler.toml");
const WRANGLER_ENTRY = path.join(SERVICE_DIR, "node_modules", "wrangler", "bin", "wrangler.js");
const NODE_COMMAND = process.execPath;
const NPM_EXEC_PATH = process.env.npm_execpath;
const NPM_COMMAND = process.platform === "win32" ? "npm.cmd" : "npm";
const TEMP_DIR_PREFIX = path.join(os.tmpdir(), "tapchat-cloudflare-deploy-");
const TEMP_CONFIG_NAME = ".wrangler.deploy.toml";
const NON_INTERACTIVE_CONFIG = process.env.TAPCHAT_CLOUDFLARE_DEPLOY_CONFIG_JSON;
const JSON_OUTPUT = process.env.TAPCHAT_CLOUDFLARE_DEPLOY_OUTPUT === "json";

const DEFAULTS = {
  workerName: "tapchat-cloudflare",
  deploymentRegion: "global",
  maxInlineBytes: "4096",
  retentionDays: "30",
  rateLimitPerMinute: "60",
  rateLimitPerHour: "600"
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
    bucketName: `${workerName}-storage`,
    previewBucketName: `${workerName}-storage-preview`
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
  return NPM_EXEC_PATH ? [NPM_EXEC_PATH, ...args] : args;
}

function npmCommand() {
  return NPM_EXEC_PATH ? NODE_COMMAND : NPM_COMMAND;
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
      stdio: capture ? ["pipe", "pipe", "pipe"] : ["pipe", "inherit", "inherit"],
      shell: false
    });

    let stdoutBuffer = "";
    let stderrBuffer = "";

    if (capture) {
      child.stdout.on("data", (chunk) => {
        stdoutBuffer += chunk.toString();
      });
      child.stderr.on("data", (chunk) => {
        stderrBuffer += chunk.toString();
      });
    }

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
  return {
    workerName: config.worker_name ?? config.workerName,
    publicBaseUrl: normalizeBaseUrl(config.public_base_url ?? config.publicBaseUrl ?? ""),
    deploymentRegion: String(config.deployment_region ?? config.deploymentRegion ?? DEFAULTS.deploymentRegion),
    maxInlineBytes: String(config.max_inline_bytes ?? config.maxInlineBytes ?? DEFAULTS.maxInlineBytes),
    retentionDays: String(config.retention_days ?? config.retentionDays ?? DEFAULTS.retentionDays),
    rateLimitPerMinute: String(config.rate_limit_per_minute ?? config.rateLimitPerMinute ?? DEFAULTS.rateLimitPerMinute),
    rateLimitPerHour: String(config.rate_limit_per_hour ?? config.rateLimitPerHour ?? DEFAULTS.rateLimitPerHour),
    bucketName: config.bucket_name ?? config.bucketName,
    previewBucketName: config.preview_bucket_name ?? config.previewBucketName,
    sharingTokenSecret: config.sharing_token_secret ?? config.sharingTokenSecret,
    bootstrapTokenSecret: config.bootstrap_token_secret ?? config.bootstrapTokenSecret,
    generatedPublicBaseUrl: !normalizeBaseUrl(config.public_base_url ?? config.publicBaseUrl ?? ""),
    generatedSharingSecret: false,
    generatedBootstrapSecret: false
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
    const previewBucketName =
      (await rl.question(`R2 preview bucket name [${derivedBuckets.previewBucketName}]: `)).trim() ||
      derivedBuckets.previewBucketName;

    const generatedSharingSecret = generateSecret();
    const generatedBootstrapSecret = generateSecret();
    const sharingTokenSecret = (
      await rl.question(`SHARING_TOKEN_SECRET [press Enter to auto-generate]: `)
    ).trim() || generatedSharingSecret;
    const bootstrapTokenSecret = (
      await rl.question(`BOOTSTRAP_TOKEN_SECRET [press Enter to auto-generate]: `)
    ).trim() || generatedBootstrapSecret;

    return {
      workerName,
      publicBaseUrl,
      deploymentRegion,
      maxInlineBytes,
      retentionDays,
      rateLimitPerMinute,
      rateLimitPerHour,
      bucketName,
      previewBucketName,
      sharingTokenSecret,
      bootstrapTokenSecret,
      generatedPublicBaseUrl: !publicBaseUrl,
      generatedSharingSecret: sharingTokenSecret === generatedSharingSecret,
      generatedBootstrapSecret: bootstrapTokenSecret === generatedBootstrapSecret
    };
  } finally {
    rl.close();
  }
}

function renderVarsBlock(config) {
  return [
    "[vars]",
    ...(config.publicBaseUrl ? [`PUBLIC_BASE_URL = \"${config.publicBaseUrl}\"`] : []),
    `DEPLOYMENT_REGION = \"${config.deploymentRegion}\"`,
    `MAX_INLINE_BYTES = \"${config.maxInlineBytes}\"`,
    `RETENTION_DAYS = \"${config.retentionDays}\"`,
    `RATE_LIMIT_PER_MINUTE = \"${config.rateLimitPerMinute}\"`,
    `RATE_LIMIT_PER_HOUR = \"${config.rateLimitPerHour}\"`,
    ""
  ].join("\n");
}

function updateConfig(baseConfig, config) {
  let rendered = baseConfig.replace(/^name\s*=\s*".*"$/m, `name = \"${config.workerName}\"`);
  rendered = rendered.replace(
    /\[vars\][\s\S]*?\n(?=\[\[durable_objects\.bindings\]\])/m,
    `${renderVarsBlock(config)}`
  );
  rendered = rendered.replace(/bucket_name\s*=\s*".*"$/m, `bucket_name = \"${config.bucketName}\"`);
  rendered = rendered.replace(
    /preview_bucket_name\s*=\s*".*"$/m,
    `preview_bucket_name = \"${config.previewBucketName}\"`
  );
  return rendered;
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
  const match = output.match(/https:\/\/[^\s]+/);
  return match ? match[0].replace(/\/+$/, "") : null;
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
  const baseConfig = await readFile(CONFIG_PATH, "utf8");
  const renderedConfig = updateConfig(baseConfig, config);

  const tempDir = await mkdtemp(TEMP_DIR_PREFIX);
  const tempConfigPath = path.join(tempDir, TEMP_CONFIG_NAME);
  await writeFile(tempConfigPath, renderedConfig, "utf8");

  try {
    logStep("Preparing Cloudflare resources");
    await ensureBuckets(tempConfigPath, [config.bucketName, config.previewBucketName]);

    logStep("Writing Cloudflare secrets");
    await putSecret(tempConfigPath, "SHARING_TOKEN_SECRET", config.sharingTokenSecret);
    await putSecret(tempConfigPath, "BOOTSTRAP_TOKEN_SECRET", config.bootstrapTokenSecret);

    logStep("Running pre-deploy checks");
    try {
      await runCommand(npmCommand(), npmArgs("run", "check"));
      await runCommand(npmCommand(), npmArgs("test"));
      await runCommand(npmCommand(), npmArgs("run", "test:integration"));
    } catch (error) {
      process.exitCode = EXIT_CODES.test;
      throw error;
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

    const structuredResult = {
      success: true,
      worker_name: config.workerName,
      deploy_url: deployUrl,
      effective_public_base_url: validation.effectiveBaseUrl ?? config.publicBaseUrl,
      bucket_name: config.bucketName,
      preview_bucket_name: config.previewBucketName,
      deployment_region: config.deploymentRegion,
      generated_secrets: {
        sharing_token_secret: config.generatedSharingSecret,
        bootstrap_token_secret: config.generatedBootstrapSecret
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
          `Preview bucket: ${config.previewBucketName}`,
          config.generatedPublicBaseUrl ? "PUBLIC_BASE_URL was left blank, so the deployed Worker URL will be used at runtime via request origin fallback." : "PUBLIC_BASE_URL was explicitly configured.",
          config.generatedSharingSecret ? "SHARING_TOKEN_SECRET was auto-generated for this deployment." : "SHARING_TOKEN_SECRET was provided manually.",
          config.generatedBootstrapSecret ? "BOOTSTRAP_TOKEN_SECRET was auto-generated for this deployment." : "BOOTSTRAP_TOKEN_SECRET was provided manually.",
          "Next step: issue a bootstrap token, call POST /v1/bootstrap/device, and import the returned deployment bundle into the TapChat profile."
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
  if (JSON_OUTPUT) {
    printStructuredResult({
      success: false,
      worker_name: "",
      deploy_url: "",
      effective_public_base_url: "",
      bucket_name: "",
      preview_bucket_name: "",
      deployment_region: "",
      generated_secrets: {
        sharing_token_secret: false,
        bootstrap_token_secret: false
      },
      mode: NON_INTERACTIVE_CONFIG ? "non_interactive" : "interactive",
      failure_class: process.exitCode ? String(process.exitCode) : "unknown",
      stderr_summary: error instanceof Error ? error.message : String(error)
    });
  }
  if (!process.exitCode) {
    process.exitCode = EXIT_CODES.environment;
  }
  const message = error instanceof Error ? error.message : String(error);
  console.error(`Deployment failed: ${message}`);
});

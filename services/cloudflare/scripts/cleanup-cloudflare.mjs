import { createInterface } from "node:readline/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { stdin, stdout, stderr } from "node:process";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const SERVICE_DIR = path.resolve(SCRIPT_DIR, "..");
const WRANGLER_ENTRY = path.join(SERVICE_DIR, "node_modules", "wrangler", "bin", "wrangler.js");
const NODE_COMMAND = process.execPath;
const PREFIX = "tapchat-";
const YES_MODE = process.argv.includes("--yes");

function wranglerArgs(...args) {
  return [WRANGLER_ENTRY, ...args];
}

function normalizeJsonOutput(output) {
  const trimmed = output.trim();
  const start = trimmed.indexOf("[");
  const objectStart = trimmed.indexOf("{");
  const index =
    start === -1
      ? objectStart
      : objectStart === -1
        ? start
        : Math.min(start, objectStart);
  return index >= 0 ? trimmed.slice(index) : trimmed;
}

function logStep(message) {
  stdout.write(`${message}\n`);
}

async function runCommand(command, args, options = {}) {
  const { cwd = SERVICE_DIR, capture = true, allowFailure = false, input } = options;
  return await new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      env: process.env,
      stdio: ["pipe", "pipe", "pipe"],
      shell: false,
      windowsHide: true
    });

    let stdoutBuffer = "";
    let stderrBuffer = "";

    child.stdout.on("data", (chunk) => {
      const text = chunk.toString();
      stdoutBuffer += text;
      if (!capture) stdout.write(text);
    });
    child.stderr.on("data", (chunk) => {
      const text = chunk.toString();
      stderrBuffer += text;
      if (!capture) stderr.write(text);
    });
    child.on("error", reject);

    if (input !== undefined) {
      child.stdin.write(input);
    }
    child.stdin.end();

    child.on("close", (code) => {
      const result = { code: code ?? 0, stdout: stdoutBuffer, stderr: stderrBuffer };
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

async function runWranglerWhoAmI() {
  const whoami = await runCommand(NODE_COMMAND, wranglerArgs("whoami", "--json"), {
    capture: true,
    allowFailure: true
  });
  const authOutput = `${whoami.stdout}\n${whoami.stderr}`.toLowerCase();
  if (whoami.code !== 0 || authOutput.includes("not authenticated") || authOutput.includes("wrangler login")) {
    throw new Error("Wrangler is not logged in. Run `npx wrangler login` first.");
  }
  try {
    return JSON.parse(normalizeJsonOutput(whoami.stdout));
  } catch (error) {
    throw new Error(`Unable to parse Wrangler whoami output: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function listBuckets() {
  const result = await runCommand(
    NODE_COMMAND,
    wranglerArgs("r2", "bucket", "list"),
    { capture: true }
  );
  return result.stdout
    .split(/\r?\n/)
    .map((line) => line.match(/^\s*name:\s+(.+?)\s*$/)?.[1] ?? null)
    .filter((name) => typeof name === "string" && name.startsWith(PREFIX));
}

function deriveWorkersFromBuckets(buckets) {
  const workers = new Set();
  for (const bucket of buckets) {
    if (bucket.endsWith("-storage-preview")) {
      workers.add(bucket.slice(0, -"-storage-preview".length));
      continue;
    }
    if (bucket.endsWith("-storage")) {
      workers.add(bucket.slice(0, -"-storage".length));
    }
  }
  return [...workers].filter((name) => name.startsWith(PREFIX));
}

async function deleteWorker(name) {
  await runCommand(NODE_COMMAND, wranglerArgs("delete", name), {
    capture: true,
    input: "y\n"
  });
}

async function deleteBucket(name) {
  await runCommand(NODE_COMMAND, wranglerArgs("r2", "bucket", "delete", name), {
    capture: true,
    input: "y\n"
  });
}

async function confirmDeletion(workers, buckets) {
  if (YES_MODE) {
    return true;
  }
  const rl = createInterface({ input: stdin, output: stdout });
  try {
    stdout.write(`Workers to delete (${workers.length}): ${workers.join(", ") || "<none>"}\n`);
    stdout.write(`Buckets to delete (${buckets.length}): ${buckets.join(", ") || "<none>"}\n`);
    const answer = (await rl.question("Delete these Cloudflare TapChat resources? [y/N] ")).trim().toLowerCase();
    return answer === "y" || answer === "yes";
  } finally {
    rl.close();
  }
}

async function main() {
  logStep("Checking Wrangler login...");
  const whoami = await runWranglerWhoAmI();
  logStep(`Using Cloudflare account: ${whoami.accounts?.[0]?.name ?? "unknown"} (${whoami.accounts?.[0]?.id ?? "unknown"})`);
  logStep("Listing TapChat R2 buckets...");
  const buckets = await listBuckets();
  const workers = deriveWorkersFromBuckets(buckets);
  logStep(`Found ${workers.length} TapChat workers inferred from buckets and ${buckets.length} TapChat R2 buckets.`);

  if (workers.length === 0 && buckets.length === 0) {
    stdout.write("No TapChat Cloudflare resources found.\n");
    return;
  }

  const confirmed = await confirmDeletion(workers, buckets);
  if (!confirmed) {
    stdout.write("Cancelled.\n");
    return;
  }

  const workerFailures = [];
  const bucketFailures = [];

  for (const worker of workers) {
    try {
      stdout.write(`Deleting worker ${worker}\n`);
      await deleteWorker(worker);
    } catch (error) {
      workerFailures.push({ worker, error: error instanceof Error ? error.message : String(error) });
    }
  }

  for (const bucket of buckets) {
    try {
      stdout.write(`Deleting bucket ${bucket}\n`);
      await deleteBucket(bucket);
    } catch (error) {
      bucketFailures.push({ bucket, error: error instanceof Error ? error.message : String(error) });
    }
  }

  stdout.write(
    `Deleted ${workers.length - workerFailures.length}/${workers.length} workers and ${buckets.length - bucketFailures.length}/${buckets.length} buckets.\n`
  );
  if (workerFailures.length > 0 || bucketFailures.length > 0) {
    stdout.write(`${JSON.stringify({ workerFailures, bucketFailures }, null, 2)}\n`);
    process.exitCode = 1;
  }
}

main().catch((error) => {
  stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});

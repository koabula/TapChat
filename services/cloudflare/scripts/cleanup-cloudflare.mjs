import { createInterface } from "node:readline/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { stdin, stdout, stderr } from "node:process";
import fs from "node:fs/promises";
import os from "node:os";
import https from "node:https";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const SERVICE_DIR = path.resolve(SCRIPT_DIR, "..");
const WRANGLER_ENTRY = path.join(SERVICE_DIR, "node_modules", "wrangler", "bin", "wrangler.js");
const NODE_COMMAND = process.execPath;
const MATCH_TEXT = "tapchat";
const YES_MODE = process.argv.includes("--yes");
const CF_API_BASE = "https://api.cloudflare.com/client/v4";

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

function matchesTapChat(value) {
  return String(value ?? "").toLowerCase().includes(MATCH_TEXT);
}

function encodePathSegment(value) {
  return encodeURIComponent(value);
}

function encodeObjectKeyPath(objectKey) {
  // Cloudflare R2 object delete API requires literal "/" separators in object keys.
  return String(objectKey).split("/").map(encodePathSegment).join("/");
}

function sortedUnique(values) {
  return [...new Set(values.filter(Boolean))].sort((a, b) => a.localeCompare(b));
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
    .filter((name) => typeof name === "string" && matchesTapChat(name));
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
  return [...workers].filter(matchesTapChat);
}

async function deleteWorker(name) {
  await runCommand(NODE_COMMAND, wranglerArgs("delete", name), {
    capture: true,
    input: "y\n"
  });
}

// Parse wrangler config to get OAuth token
async function getWranglerConfig() {
  const configPath = path.join(os.homedir(), ".wrangler", "config", "default.toml");
  try {
    const content = await fs.readFile(configPath, "utf-8");
    const config = {};
    // Simple TOML parsing for key = "value" format
    for (const line of content.split(/\r?\n/)) {
      const match = line.match(/^\s*(\w+)\s*=\s*"([^"]*)"\s*$/);
      if (match) {
        config[match[1]] = match[2];
      }
    }
    return config;
  } catch {
    return null;
  }
}

// HTTP request helper using native https module
async function httpGet(url, headers) {
  return await new Promise((resolve, reject) => {
    const req = https.request(url, {
      method: "GET",
      headers,
    }, (res) => {
      let body = "";
      res.on("data", (chunk) => body += chunk);
      res.on("end", () => resolve({ status: res.statusCode, body }));
    });
    req.on("error", reject);
    req.end();
  });
}

async function httpDelete(url, headers) {
  return await new Promise((resolve, reject) => {
    const req = https.request(url, {
      method: "DELETE",
      headers,
    }, (res) => {
      let body = "";
      res.on("data", (chunk) => body += chunk);
      res.on("end", () => resolve({ status: res.statusCode, body }));
    });
    req.on("error", reject);
    req.end();
  });
}

async function listWorkersViaApi(accountId, apiToken) {
  if (!accountId || !apiToken) {
    return [];
  }

  const workers = [];
  let page = 1;
  const perPage = 100;

  while (true) {
    const url = new URL(`${CF_API_BASE}/accounts/${accountId}/workers/scripts`);
    url.searchParams.set("page", String(page));
    url.searchParams.set("per_page", String(perPage));

    const response = await httpGet(url, {
      "Authorization": `Bearer ${apiToken}`,
    });

    if (response.status !== 200) {
      return sortedUnique(workers);
    }

    const parsed = JSON.parse(response.body);
    const scripts = Array.isArray(parsed.result) ? parsed.result : [];
    workers.push(
      ...scripts
        .map((script) => script.id ?? script.name ?? script.script_name)
        .filter(matchesTapChat)
    );

    const info = parsed.result_info;
    if (!info || page >= info.total_pages || scripts.length === 0) {
      break;
    }
    page++;
  }

  return sortedUnique(workers);
}

async function listBucketsViaApi(accountId, apiToken) {
  if (!accountId || !apiToken) {
    return [];
  }

  const buckets = [];
  let cursor;

  while (true) {
    const url = new URL(`${CF_API_BASE}/accounts/${accountId}/r2/buckets`);
    url.searchParams.set("name_contains", MATCH_TEXT);
    url.searchParams.set("per_page", "1000");
    if (cursor) {
      url.searchParams.set("cursor", cursor);
    }

    const response = await httpGet(url, {
      "Authorization": `Bearer ${apiToken}`,
    });

    if (response.status !== 200) {
      return sortedUnique(buckets);
    }

    const parsed = JSON.parse(response.body);
    const result = parsed.result ?? {};
    const items = Array.isArray(result) ? result : result.buckets ?? [];
    buckets.push(...items.map((bucket) => bucket.name ?? bucket).filter(matchesTapChat));

    const nextCursor = result.cursor ?? parsed.result_info?.cursor;
    if (!nextCursor || nextCursor === cursor || items.length === 0) {
      break;
    }
    cursor = nextCursor;
  }

  return sortedUnique(buckets);
}

async function deleteWorkerViaApi(accountId, workerName, apiToken) {
  if (!accountId || !apiToken) {
    return false;
  }

  const url = `${CF_API_BASE}/accounts/${accountId}/workers/scripts/${encodePathSegment(workerName)}`;
  const response = await httpDelete(url, {
    "Authorization": `Bearer ${apiToken}`,
  });

  return response.status === 200 || response.status === 202 || response.status === 204 || response.status === 404;
}

async function listBucketObjects(accountId, bucketName, apiToken) {
  const objects = [];
  let cursor;
  try {
    while (true) {
      const url = new URL(`${CF_API_BASE}/accounts/${accountId}/r2/buckets/${encodePathSegment(bucketName)}/objects`);
      url.searchParams.set("per_page", "1000");
      if (cursor) {
        url.searchParams.set("cursor", cursor);
      }

      const response = await httpGet(url, {
        "Authorization": `Bearer ${apiToken}`,
      });

      if (response.status !== 200) {
        return objects;
      }

      const parsed = JSON.parse(response.body);
      const result = parsed.result ?? {};
      const pageObjects = Array.isArray(result) ? result : result.objects ?? result.items ?? [];
      objects.push(...pageObjects.map(obj => obj.key ?? obj.name ?? obj).filter(Boolean));

      const nextCursor = result.cursor ?? parsed.result_info?.cursor;
      if (!nextCursor || nextCursor === cursor || pageObjects.length === 0) {
        break;
      }
      cursor = nextCursor;
    }
  } catch {
    return objects;
  }
  return objects;
}

async function deleteBucketObjectViaApi(accountId, bucketName, objectKey, apiToken) {
  const url = `${CF_API_BASE}/accounts/${accountId}/r2/buckets/${encodePathSegment(bucketName)}/objects/${encodeObjectKeyPath(objectKey)}`;

  const response = await httpDelete(url, {
    "Authorization": `Bearer ${apiToken}`,
  });

  return response.status === 200 || response.status === 204 || response.status === 404;
}

async function deleteBucketObject(accountId, bucketName, objectKey, apiToken) {
  // Prefer REST API for efficiency, fallback to wrangler CLI if API fails
  try {
    const success = await deleteBucketObjectViaApi(accountId, bucketName, objectKey, apiToken);
    if (success) return true;
  } catch {
    // Fallback to wrangler
  }

  // Fallback: Use wrangler r2 object delete command
  const result = await runCommand(
    NODE_COMMAND,
    wranglerArgs("r2", "object", "delete", `${bucketName}/${objectKey}`),
    { capture: true, allowFailure: true }
  );
  return result.code === 0;
}

async function emptyBucket(accountId, bucketName, apiToken) {
  stdout.write(`Emptying bucket ${bucketName}...\n`);

  let deletedCount = 0;
  let iteration = 0;
  const maxIterations = 100; // Safety limit

  // R2 list API is paginated, so we need to loop until empty
  while (iteration < maxIterations) {
    iteration++;
    const objects = await listBucketObjects(accountId, bucketName, apiToken);

    if (objects.length === 0) {
      stdout.write(`  Bucket ${bucketName} is now empty (deleted ${deletedCount} objects in ${iteration} iterations)\n`);
      return;
    }

    stdout.write(`  Deleting ${objects.length} objects from ${bucketName} (iteration ${iteration})...\n`);

    // Delete objects in parallel batches for efficiency
    const batchSize = 20;
    for (let i = 0; i < objects.length; i += batchSize) {
      const batch = objects.slice(i, i + batchSize);
      const results = await Promise.allSettled(
        batch.map(objectKey => deleteBucketObject(accountId, bucketName, objectKey, apiToken))
      );
      for (const result of results) {
        if (result.status === "fulfilled" && result.value) {
          deletedCount++;
        } else if (result.status === "rejected") {
          stderr.write(`  Warning: ${result.reason?.message || result.reason}\n`);
        }
      }
    }
  }

  stdout.write(`  Emptied ${deletedCount} objects from ${bucketName} (max iterations reached)\n`);
}

async function deleteBucket(name, accountId, apiToken) {
  // First empty the bucket
  await emptyBucket(accountId, name, apiToken);

  // Now delete the empty bucket via REST API
  const url = `${CF_API_BASE}/accounts/${accountId}/r2/buckets/${encodePathSegment(name)}`;
  const response = await httpDelete(url, {
    "Authorization": `Bearer ${apiToken}`,
  });

  if (response.status !== 200 && response.status !== 204) {
    // Fallback to wrangler CLI
    await runCommand(NODE_COMMAND, wranglerArgs("r2", "bucket", "delete", name), {
      capture: true,
      input: "y\n"
    });
  }
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
  const accountId = whoami.accounts?.[0]?.id;
  logStep(`Using Cloudflare account: ${whoami.accounts?.[0]?.name ?? "unknown"} (${accountId ?? "unknown"})`);

  // Get wrangler config for direct API access
  const wranglerConfig = await getWranglerConfig();
  const apiToken = wranglerConfig?.oauth_token;

  if (!apiToken) {
    stderr.write("Warning: Could not get OAuth token from wrangler config. Bucket emptying may be slower.\n");
  }

  logStep("Listing TapChat R2 buckets...");
  const cliBuckets = await listBuckets();
  const apiBuckets = await listBucketsViaApi(accountId, apiToken);
  const buckets = sortedUnique([...cliBuckets, ...apiBuckets]);

  logStep("Listing TapChat workers...");
  const apiWorkers = await listWorkersViaApi(accountId, apiToken);
  const workers = sortedUnique([...deriveWorkersFromBuckets(buckets), ...apiWorkers]);
  logStep(`Found ${workers.length} TapChat workers and ${buckets.length} TapChat R2 buckets.`);

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
      let deletedViaApi = false;
      if (apiToken && accountId) {
        deletedViaApi = await deleteWorkerViaApi(accountId, worker, apiToken);
      }
      if (!deletedViaApi) {
        await deleteWorker(worker);
      }
    } catch (error) {
      workerFailures.push({ worker, error: error instanceof Error ? error.message : String(error) });
    }
  }

  for (const bucket of buckets) {
    try {
      stdout.write(`Deleting bucket ${bucket}\n`);
      if (apiToken && accountId) {
        await deleteBucket(bucket, accountId, apiToken);
      } else {
        // Fallback: try wrangler CLI (will fail if bucket has objects)
        await runCommand(NODE_COMMAND, wranglerArgs("r2", "bucket", "delete", bucket), {
          capture: true,
          input: "y\n"
        });
      }
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

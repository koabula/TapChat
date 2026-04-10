import { cp, mkdir, readFile, realpath, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const DESKTOP_ROOT = path.resolve(SCRIPT_DIR, "..");
const REPO_ROOT = path.resolve(DESKTOP_ROOT, "..", "..");
const SERVICE_ROOT = path.join(REPO_ROOT, "services", "cloudflare");
const OUTPUT_ROOT = path.join(DESKTOP_ROOT, "runtime", "dist");

function currentPlatformDir() {
  switch (process.platform) {
    case "win32":
      return "windows-x64";
    case "darwin":
      return "macos-universal";
    default:
      return "linux-x64";
  }
}

function legacyPlatformDirs(platformDir) {
  if (platformDir === "windows-x64") {
    return ["win32-x64"];
  }
  return [];
}

async function ensureExists(target, message) {
  try {
    await stat(target);
  } catch {
    throw new Error(message);
  }
}

function shouldCopyServiceEntry(source) {
  const relative = path.relative(SERVICE_ROOT, source);
  if (!relative || relative.startsWith("..")) {
    return true;
  }
  const normalized = relative.replaceAll("\\", "/");
  const topLevel = normalized.split("/")[0];
  return ![
    ".wrangler",
    "dist",
    "coverage",
    "tmp",
    ".test-runtime",
    ".test-runtime-debug",
    ".tmp-manual-runtime2",
  ].includes(topLevel) && !normalized.startsWith("node_modules/.cache/");
}

async function copyNodeRuntime(destinationRoot) {
  const resolvedNode = await realpath(process.execPath);
  const nodeDir = path.join(destinationRoot, "node");
  await mkdir(nodeDir, { recursive: true });

  if (process.platform === "win32") {
    await cp(resolvedNode, path.join(nodeDir, "node.exe"));
    return { executable: path.join(nodeDir, "node.exe") };
  }

  const binDir = path.join(nodeDir, "bin");
  await mkdir(binDir, { recursive: true });
  await cp(resolvedNode, path.join(binDir, "node"));
  return { executable: path.join(binDir, "node") };
}

async function copyCloudflareService(destinationRoot) {
  const destination = path.join(destinationRoot, "cloudflare-service");
  await cp(SERVICE_ROOT, destination, {
    recursive: true,
    filter: shouldCopyServiceEntry,
    force: true,
  });
  return destination;
}

async function main() {
  await ensureExists(
    path.join(SERVICE_ROOT, "node_modules", "wrangler", "bin", "wrangler.js"),
    "Embedded desktop runtime requires services/cloudflare/node_modules/wrangler/bin/wrangler.js. Run npm install in services/cloudflare first.",
  );

  const platformDir = currentPlatformDir();
  const outputDir = path.join(OUTPUT_ROOT, platformDir);
  for (const legacyDir of legacyPlatformDirs(platformDir)) {
    await rm(path.join(OUTPUT_ROOT, legacyDir), { recursive: true, force: true });
  }
  await rm(outputDir, { recursive: true, force: true });
  await mkdir(outputDir, { recursive: true });

  const node = await copyNodeRuntime(outputDir);
  const serviceRoot = await copyCloudflareService(outputDir);
  const packageJson = JSON.parse(
    await readFile(path.join(DESKTOP_ROOT, "package.json"), "utf8"),
  );

  await writeFile(
    path.join(outputDir, "manifest.json"),
    JSON.stringify(
      {
        platform: platformDir,
        desktop_version: packageJson.version,
        prepared_at: new Date().toISOString(),
        node_executable: path.relative(outputDir, node.executable).replaceAll("\\", "/"),
        service_root: path.relative(outputDir, serviceRoot).replaceAll("\\", "/"),
      },
      null,
      2,
    ),
  );

  process.stdout.write(`Prepared desktop runtime at ${outputDir}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});

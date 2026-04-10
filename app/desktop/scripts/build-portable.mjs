import { cp, mkdir, rm, stat, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const DESKTOP_ROOT = path.resolve(SCRIPT_DIR, "..");
const TAURI_ROOT = path.join(DESKTOP_ROOT, "src-tauri");
const REPO_ROOT = path.resolve(DESKTOP_ROOT, "..", "..");
const RELEASE_ROOT = path.join(REPO_ROOT, "target", "release");
const PORTABLE_ROOT = path.join(REPO_ROOT, "target", "portable");
const PLATFORM_DIR =
  process.platform === "win32" ? "windows-x64" : process.platform === "darwin" ? "macos-universal" : "linux-x64";

async function ensureExists(target, message) {
  try {
    await stat(target);
  } catch {
    throw new Error(message);
  }
}

async function copyDirectory(source, destination) {
  if (process.platform !== "win32") {
    await cp(source, destination, { recursive: true, force: true });
    return;
  }

  await mkdir(destination, { recursive: true });
  await new Promise((resolve, reject) => {
    const child = spawn(
      "robocopy",
      [source, destination, "/E", "/NFL", "/NDL", "/NJH", "/NJS", "/NC", "/NS", "/NP"],
      { stdio: "inherit" },
    );
    child.on("error", reject);
    child.on("close", (code) => {
      if ((code ?? 16) <= 7) {
        resolve();
        return;
      }
      reject(new Error(`robocopy failed with exit code ${code ?? "unknown"}`));
    });
  });
}

async function main() {
  const executableName = process.platform === "win32" ? "tapchat_desktop.exe" : "tapchat_desktop";
  const executablePath = path.join(RELEASE_ROOT, executableName);
  const runtimePath = path.join(DESKTOP_ROOT, "runtime", "dist", PLATFORM_DIR);

  await ensureExists(
    executablePath,
    "Portable build requires a compiled release executable. Run `npm run tauri:build` first.",
  );
  await ensureExists(
    runtimePath,
    "Portable build requires a prepared embedded runtime. Run `npm run prepare:desktop-runtime` first.",
  );

  await rm(PORTABLE_ROOT, { recursive: true, force: true });
  await mkdir(path.join(PORTABLE_ROOT, "resources"), { recursive: true });
  await cp(executablePath, path.join(PORTABLE_ROOT, executableName));
  await copyDirectory(
    runtimePath,
    path.join(PORTABLE_ROOT, "resources", "runtime", "dist", PLATFORM_DIR),
  );

  await writeFile(
    path.join(PORTABLE_ROOT, "README.txt"),
    [
      "TapChat Desktop Portable",
      "",
      "This directory mirrors the embedded Cloudflare deploy runtime used by the installer build.",
      "Keep the executable and resources directory together.",
    ].join("\n"),
  );

  process.stdout.write(`Portable desktop bundle created at ${PORTABLE_ROOT}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});

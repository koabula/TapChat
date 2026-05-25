import { existsSync } from "node:fs";
import { delimiter, dirname, join, resolve } from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const [command, ...rawArgs] = process.argv.slice(2);
const desktopRoot = dirname(dirname(fileURLToPath(import.meta.url)));

if (!command) {
  console.error("usage: node scripts/with-strawberry-perl.mjs <command> [...args]");
  process.exit(2);
}

const env = { ...process.env };

if (process.platform === "win32") {
  ensureWindowsPerl(env);
  ensureWindowsDesktopTargetDir(env);
}

const args = process.platform === "win32" ? applyWindowsTauriBundleOverride(command, rawArgs) : rawArgs;

const child = spawn(command, args, {
  stdio: "inherit",
  env,
  shell: process.platform === "win32",
});

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 1);
});

child.on("error", (error) => {
  console.error(error.message);
  process.exit(1);
});

function ensureWindowsPerl(env) {
  if (hasPerl(env)) {
    return;
  }

  const roots = [
    env.STRAWBERRY_PERL_HOME,
    env.STRAWBERRY_HOME,
    "D:\\ENV\\Strawberry",
    "C:\\Strawberry",
    "D:\\Strawberry",
  ].filter(Boolean);

  for (const root of roots) {
    const perlBin = join(root, "perl", "bin");
    const perlExe = join(perlBin, "perl.exe");
    if (!existsSync(perlExe)) {
      continue;
    }
    prependPath(env, [
      perlBin,
      join(root, "perl", "site", "bin"),
      join(root, "c", "bin"),
    ]);
    if (hasPerl(env)) {
      return;
    }
  }

  console.error(
    [
      "Strawberry Perl is required to build TapChat on Windows because vendored SQLCipher/OpenSSL runs perl during release builds.",
      "Install Strawberry Perl or set STRAWBERRY_PERL_HOME to its install root, for example D:\\ENV\\Strawberry.",
    ].join("\n"),
  );
  process.exit(1);
}

function hasPerl(env) {
  const result = spawnSync("perl", ["-e", "print qq(ok)"], {
    env,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
  return result.status === 0 && result.stdout === "ok";
}

function prependPath(env, entries) {
  const pathKeys = Object.keys(env).filter((name) => name.toLowerCase() === "path");
  const canonicalKey = pathKeys[0] ?? "Path";
  const existing = env[canonicalKey] ?? "";
  const next = [...entries, existing].filter(Boolean).join(delimiter);
  env[canonicalKey] = next;
  env.PATH = next;
  env.Path = next;
}

function ensureWindowsDesktopTargetDir(env) {
  if (env.CARGO_TARGET_DIR) {
    return;
  }
  env.CARGO_TARGET_DIR = resolve(desktopRoot, "src-tauri", "target");
}

function applyWindowsTauriBundleOverride(command, args) {
  if (
    !process.env.TAPCHAT_WINDOWS_BUNDLES ||
    !isTauriCommand(command) ||
    args[0] !== "build" ||
    hasBundleArg(args)
  ) {
    return args;
  }
  return [...args, "--bundles", process.env.TAPCHAT_WINDOWS_BUNDLES];
}

function isTauriCommand(command) {
  const normalized = command.replaceAll("\\", "/").toLowerCase();
  return (
    normalized === "tauri" ||
    normalized.endsWith("/tauri") ||
    normalized.endsWith("/tauri.cmd")
  );
}

function hasBundleArg(args) {
  return args.some((arg) => arg === "--bundles" || arg.startsWith("--bundles=") || arg === "-b");
}

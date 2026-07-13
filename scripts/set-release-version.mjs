#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const root = path.resolve(import.meta.dirname, "..");
const SEMVER =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

function fail(message) {
  console.error(`set release version failed: ${message}`);
  process.exit(1);
}

function normalizeVersion(raw) {
  if (!raw) {
    fail("usage: node scripts/set-release-version.mjs X.Y.Z");
  }
  const version = raw.trim().replace(/^v/, "");
  if (!SEMVER.test(version)) {
    fail(`not a valid SemVer version: ${raw}`);
  }
  return version;
}

function filePath(relativePath) {
  return path.join(root, relativePath);
}

function read(relativePath) {
  return fs.readFileSync(filePath(relativePath), "utf8");
}

function write(relativePath, text) {
  fs.writeFileSync(filePath(relativePath), text);
}

function updateJsonVersion(relativePath, version) {
  const json = JSON.parse(read(relativePath));
  json.version = version;
  if (json.packages?.[""]?.version) {
    json.packages[""].version = version;
  }
  write(relativePath, `${JSON.stringify(json, null, 2)}\n`);
}

function updateCargoTomlVersion(relativePath, version) {
  const text = read(relativePath);
  const packageVersionPattern =
    /^(\[package\][\s\S]*?^version\s*=\s*")([^"]+)(")/m;
  if (!packageVersionPattern.test(text)) {
    fail(`could not locate [package] version in ${relativePath}`);
  }
  const updated = text.replace(
    packageVersionPattern,
    `$1${version}$3`,
  );
  if (updated !== text) {
    write(relativePath, updated);
  }
}

function updateCargoLockPackageVersion(packageName, version) {
  const relativePath = "Cargo.lock";
  const text = read(relativePath);
  const escapedName = packageName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const packagePattern = new RegExp(
    `(\\[\\[package\\]\\]\\r?\\nname = "${escapedName}"\\r?\\nversion = ")[^"]+(")`,
  );
  const updated = text.replace(packagePattern, `$1${version}$2`);
  if (updated === text && !text.includes(`name = "${packageName}"`)) {
    fail(`could not locate ${packageName} in Cargo.lock`);
  }
  if (updated !== text) {
    write(relativePath, updated);
  }
}

const version = normalizeVersion(process.argv[2]);

updateCargoTomlVersion("Cargo.toml", version);
updateCargoTomlVersion("app/desktop/src-tauri/Cargo.toml", version);
updateCargoLockPackageVersion("TapChat", version);
updateCargoLockPackageVersion("tapchat-desktop", version);
updateJsonVersion("app/desktop/src-tauri/tauri.conf.json", version);
updateJsonVersion("app/desktop/package.json", version);
updateJsonVersion("app/desktop/package-lock.json", version);
updateJsonVersion("services/cloudflare/package.json", version);
updateJsonVersion("services/cloudflare/package-lock.json", version);

console.log(`Set release version to ${version}`);

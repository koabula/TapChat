#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const root = path.resolve(import.meta.dirname, "..");
const SEMVER =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

function argValue(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function fail(message) {
  console.error(`release version check failed: ${message}`);
  process.exit(1);
}

function normalizeTag(rawTag) {
  if (!rawTag) {
    fail("missing --tag vX.Y.Z, RELEASE_TAG, or GITHUB_REF_NAME");
  }
  const name = rawTag.trim().replace(/^refs\/tags\//, "");
  if (!name.startsWith("v")) {
    fail(`release tag must start with "v": ${name}`);
  }
  const version = name.slice(1);
  if (!SEMVER.test(version)) {
    fail(`release tag is not valid SemVer: ${name}`);
  }
  return { tag: name, version };
}

function readText(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), "utf8");
}

function readJson(relativePath) {
  return JSON.parse(readText(relativePath));
}

function packageTomlVersion(relativePath) {
  const text = readText(relativePath);
  const match = text.match(/^\[package\][\s\S]*?^version\s*=\s*"([^"]+)"/m);
  if (!match) {
    fail(`could not find [package] version in ${relativePath}`);
  }
  return match[1];
}

function cargoLockPackageVersion(packageName) {
  const text = readText("Cargo.lock");
  const blocks = text.split(/\r?\n(?=\[\[package\]\])/);
  const block = blocks.find((item) =>
    new RegExp(`^name\\s*=\\s*"${packageName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`, "m").test(item),
  );
  if (!block) {
    fail(`could not find ${packageName} in Cargo.lock`);
  }
  const match = block.match(/^version\s*=\s*"([^"]+)"/m);
  if (!match) {
    fail(`could not find ${packageName} version in Cargo.lock`);
  }
  return match[1];
}

function collectVersions() {
  const desktopLock = readJson("app/desktop/package-lock.json");
  const cloudflareLock = readJson("services/cloudflare/package-lock.json");
  return [
    ["Cargo.toml", packageTomlVersion("Cargo.toml")],
    ["Cargo.lock TapChat", cargoLockPackageVersion("TapChat")],
    ["app/desktop/src-tauri/Cargo.toml", packageTomlVersion("app/desktop/src-tauri/Cargo.toml")],
    ["Cargo.lock tapchat-desktop", cargoLockPackageVersion("tapchat-desktop")],
    ["app/desktop/src-tauri/tauri.conf.json", readJson("app/desktop/src-tauri/tauri.conf.json").version],
    ["app/desktop/package.json", readJson("app/desktop/package.json").version],
    ["app/desktop/package-lock.json", desktopLock.version],
    ["app/desktop/package-lock.json packages[\"\"]", desktopLock.packages?.[""]?.version],
    ["services/cloudflare/package.json", readJson("services/cloudflare/package.json").version],
    ["services/cloudflare/package-lock.json", cloudflareLock.version],
    ["services/cloudflare/package-lock.json packages[\"\"]", cloudflareLock.packages?.[""]?.version],
  ];
}

const inputTag = argValue("--tag") ?? process.env.RELEASE_TAG ?? process.env.GITHUB_REF_NAME;
const { tag, version } = normalizeTag(inputTag);
const mismatches = collectVersions().filter(([, actual]) => actual !== version);

if (mismatches.length > 0) {
  for (const [label, actual] of mismatches) {
    console.error(`${label}: expected ${version}, found ${actual ?? "<missing>"}`);
  }
  fail(`program versions do not match ${tag}`);
}

console.log(`Release version OK: ${tag}`);

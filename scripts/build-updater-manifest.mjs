#!/usr/bin/env node
// Builds the Tauri updater manifest (latest.json) from the release assets that
// the per-platform build jobs staged. tauri-action used to emit this while it
// uploaded assets; the release pipeline now creates the GitHub release from a
// single job, so the manifest is assembled here instead.
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

// Every updater key Tauri may ask for, mapped to the bundle that serves it.
// `match` runs against the staged file names; each entry must resolve to
// exactly one asset that also has a detached `.sig` next to it.
const PLATFORMS = [
  { key: "darwin-x86_64", match: (name) => name === "TapChat_x64.app.tar.gz" },
  { key: "darwin-x86_64-app", match: (name) => name === "TapChat_x64.app.tar.gz" },
  { key: "darwin-aarch64", match: (name) => name === "TapChat_aarch64.app.tar.gz" },
  { key: "darwin-aarch64-app", match: (name) => name === "TapChat_aarch64.app.tar.gz" },
  { key: "linux-x86_64", match: (name) => name.endsWith(".AppImage") },
  { key: "linux-x86_64-appimage", match: (name) => name.endsWith(".AppImage") },
  { key: "linux-x86_64-deb", match: (name) => name.endsWith(".deb") },
  { key: "linux-x86_64-rpm", match: (name) => name.endsWith(".rpm") },
  { key: "windows-x86_64", match: (name) => name.endsWith(".msi") },
  { key: "windows-x86_64-msi", match: (name) => name.endsWith(".msi") },
  { key: "windows-x86_64-nsis", match: (name) => name.endsWith("-setup.exe") },
];

function argValue(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function fail(message) {
  console.error(`updater manifest build failed: ${message}`);
  process.exit(1);
}

const assetDir = argValue("--dir");
const version = argValue("--version");
const tag = argValue("--tag");
const repo = argValue("--repo");
const notes = argValue("--notes") ?? "";

if (!assetDir) fail("missing --dir <staged asset directory>");
if (!version) fail("missing --version <X.Y.Z>");
if (!tag) fail("missing --tag <vX.Y.Z>");
if (!repo) fail("missing --repo <owner/name>");

const resolvedDir = path.resolve(assetDir);
if (!fs.existsSync(resolvedDir)) {
  fail(`asset directory does not exist: ${resolvedDir}`);
}

const names = fs
  .readdirSync(resolvedDir, { withFileTypes: true })
  .filter((entry) => entry.isFile())
  .map((entry) => entry.name);

const platforms = {};
for (const { key, match } of PLATFORMS) {
  const matches = names.filter((name) => !name.endsWith(".sig") && match(name));
  if (matches.length === 0) {
    fail(`no asset found for updater platform "${key}" in ${resolvedDir}`);
  }
  if (matches.length > 1) {
    fail(`updater platform "${key}" matched multiple assets: ${matches.join(", ")}`);
  }

  const asset = matches[0];
  const signaturePath = path.join(resolvedDir, `${asset}.sig`);
  if (!fs.existsSync(signaturePath)) {
    fail(`missing updater signature for ${asset} (expected ${asset}.sig)`);
  }

  const signature = fs.readFileSync(signaturePath, "utf8").trim();
  if (!signature) {
    fail(`updater signature for ${asset} is empty`);
  }

  platforms[key] = {
    signature,
    url: `https://github.com/${repo}/releases/download/${tag}/${encodeURIComponent(asset)}`,
  };
}

const manifest = {
  version,
  notes,
  pub_date: new Date().toISOString(),
  platforms,
};

const outputPath = path.join(resolvedDir, "latest.json");
fs.writeFileSync(outputPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
console.log(`wrote ${outputPath} covering ${Object.keys(platforms).length} updater targets`);

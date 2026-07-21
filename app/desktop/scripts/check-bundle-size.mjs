import { readdir, stat } from "node:fs/promises";
import { resolve } from "node:path";

const MAX_JS_BYTES = 500 * 1024;
const assetsDirectory = resolve(process.cwd(), "dist", "assets");
const assetNames = await readdir(assetsDirectory);
const javascriptAssets = await Promise.all(
  assetNames
    .filter((name) => name.endsWith(".js"))
    .map(async (name) => ({ name, bytes: (await stat(resolve(assetsDirectory, name))).size })),
);
const oversized = javascriptAssets.filter((asset) => asset.bytes > MAX_JS_BYTES);

if (oversized.length > 0) {
  const detail = oversized
    .map((asset) => `${asset.name}: ${(asset.bytes / 1024).toFixed(1)} KiB`)
    .join("\n");
  throw new Error(`JavaScript asset limit exceeded (500 KiB):\n${detail}`);
}

const largest = javascriptAssets.sort((a, b) => b.bytes - a.bytes)[0];
console.log(
  largest
    ? `Bundle size check passed: ${largest.name} is ${(largest.bytes / 1024).toFixed(1)} KiB.`
    : "Bundle size check passed: no JavaScript assets emitted.",
);

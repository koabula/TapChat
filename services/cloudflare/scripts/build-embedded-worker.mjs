import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const outfile = path.resolve(root, "../../app/desktop/src-tauri/embedded/worker.js");
const checkOnly = process.argv.includes("--check");

const result = await build({
  entryPoints: [path.join(root, "src/index.ts")],
  outfile,
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "es2022",
  legalComments: "none",
  sourcemap: false,
  write: false
});

const generated = result.outputFiles[0].text;
if (checkOnly) {
  const existing = await fs.readFile(outfile, "utf8").catch(() => "");
  if (existing !== generated) {
    throw new Error("embedded worker.js is stale; run npm run build:embedded in services/cloudflare");
  }
} else {
  await fs.writeFile(outfile, generated, "utf8");
}

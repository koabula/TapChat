import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cargo = await readFile(path.join(root, "src-tauri", "Cargo.toml"), "utf8");
const config = JSON.parse(await readFile(path.join(root, "src-tauri", "tauri.conf.json"), "utf8"));

if (cargo.includes("tauri/devtools")) {
  throw new Error("release Cargo features must not include tauri/devtools");
}
if (config.app?.withGlobalTauri !== false) {
  throw new Error("withGlobalTauri must remain disabled");
}
const csp = String(config.app?.security?.csp ?? "");
const connectSources = csp
  .split(";")
  .find((directive) => directive.trim().startsWith("connect-src"))
  ?.trim()
  .split(/\s+/)
  .slice(1) ?? [];
if (csp.includes("unsafe-eval") || connectSources.includes("https:") || connectSources.includes("wss:")) {
  throw new Error("production CSP contains an unsafe script or wildcard connection source");
}
for (const required of ["https://api.github.com", "object-src 'none'", "frame-src 'none'", "base-uri 'none'"]) {
  if (!csp.includes(required)) {
    throw new Error(`production CSP is missing required restriction: ${required}`);
  }
}

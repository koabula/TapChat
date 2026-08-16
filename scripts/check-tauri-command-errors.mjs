import { readdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const sourceRoot = resolve(root, "app/desktop/src-tauri/src");
const write = process.argv.includes("--write");
const files = [];

async function collect(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) await collect(path);
    else if (entry.isFile() && entry.name.endsWith(".rs")) files.push(path);
  }
}

function migrateCommands(source) {
  const marker = "#[tauri::command]";
  let cursor = 0;
  let output = "";
  let changed = false;
  while (true) {
    const markerIndex = source.indexOf(marker, cursor);
    if (markerIndex < 0) break;
    const fnIndex = source.indexOf("fn ", markerIndex + marker.length);
    const braceIndex = source.indexOf("{", fnIndex);
    if (fnIndex < 0 || braceIndex < 0) break;
    const signature = source.slice(markerIndex, braceIndex);
    const migrated = signature.replace(
      /->\s*Result<([\s\S]*),\s*String>\s*$/,
      "-> crate::errors::DesktopResult<$1> ",
    );
    output += source.slice(cursor, markerIndex) + migrated;
    changed ||= migrated !== signature;
    cursor = braceIndex;
  }
  return { source: output + source.slice(cursor), changed };
}

await collect(sourceRoot);
const violations = [];
let migratedCount = 0;
for (const file of files) {
  const original = await readFile(file, "utf8");
  const migrated = migrateCommands(original);
  if (write && migrated.changed) {
    await writeFile(file, migrated.source);
    migratedCount += 1;
  }
  const checked = write ? migrated.source : original;
  if (migrateCommands(checked).changed) {
    violations.push(file.slice(root.length + 1));
  }
}

if (violations.length) {
  throw new Error(`Public Tauri commands still return Result<_, String>:\n${violations.join("\n")}`);
}
console.log(write ? `migrated ${migratedCount} Tauri source files` : "Tauri command error contract ok");

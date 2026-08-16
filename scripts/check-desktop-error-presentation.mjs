import { readdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const sourceRoot = resolve(root, "app/desktop/src");
const write = process.argv.includes("--write");
const files = [];

async function collect(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) await collect(path);
    else if (entry.isFile() && /\.tsx?$/.test(entry.name)) files.push(path);
  }
}

function migrate(source) {
  let migrated = source.replace(
    /\b(err|error|reason) instanceof Error \? \1\.message : String\(\1\)/g,
    "presentError($1).message",
  );
  migrated = migrated.replace(/String\((err|error|reason)\)/g, "presentError($1).message");
  if (migrated !== source && !/from ["'][^"']*\/errors["']/.test(migrated)) {
    migrated = `import { presentError } from "@/lib/errors";\n${migrated}`;
  }
  return migrated;
}

await collect(sourceRoot);
const violations = [];
let migratedCount = 0;
for (const file of files) {
  const source = await readFile(file, "utf8");
  const migrated = migrate(source);
  if (write && migrated !== source) {
    await writeFile(file, migrated);
    migratedCount += 1;
  }
  const checked = write ? migrated : source;
  if (/String\((err|error|reason)\)/.test(checked)) {
    violations.push(file.slice(root.length + 1));
  }
}

if (violations.length) {
  throw new Error(`Desktop error paths still stringify raw failures:\n${violations.join("\n")}`);
}
console.log(write ? `migrated ${migratedCount} desktop error presentation files` : "Desktop error presentation contract ok");

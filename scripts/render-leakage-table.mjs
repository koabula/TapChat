import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

/**
 * Render the write-up's leakage table rows from contracts/leakage-ledger.json.
 *
 * This exists for one reason, and it is not convenience. The realistic way a
 * mechanism like this dies is appeasement: six months from now someone's change
 * turns a check red, the two-second fix is to widen `carries` until it goes
 * green, and the ledger then *documents* the leak as intended — the same
 * failure as the two it was built to prevent, laundered through a config file.
 *
 * Rendering the published table from `carries` closes that loop. Widening a
 * claim mechanically widens a generated artifact, and the change shows up as a
 * table row in the diff. Silencing the check now means editing the write-up.
 *
 * The write-up lives outside this repository, so the coupling is diff
 * visibility rather than an automatic `\input`. Diff visibility is precisely
 * the link that failed both times.
 *
 * Default mode verifies the committed render is current; `--write` updates it.
 */

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ledgerPath = resolve(root, "contracts/leakage-ledger.json");
const outputPath = resolve(root, "contracts/leakage-table.tex");

const ledger = JSON.parse(await readFile(ledgerPath, "utf8"));

if (ledger.version !== 1 || !Array.isArray(ledger.entries)) {
  throw new Error("Invalid leakage ledger.");
}

const escape = (value) => value.replace(/([&%#_$])/g, "\\$1");

const byTable = new Map();
for (const entry of ledger.entries) {
  if (!ledger.tables[entry.table]) {
    throw new Error(`Entry ${entry.surface}:${entry.path} names unknown table ${entry.table}.`);
  }
  if (!byTable.has(entry.table)) byTable.set(entry.table, []);
  byTable.get(entry.table).push(entry);
}

const lines = [
  "% Generated from contracts/leakage-ledger.json by scripts/render-leakage-table.mjs.",
  "% Do not edit by hand. Regenerate with --write.",
  "%",
  "% Each row is a datum an untrusted host observes. `carries` names the identifiers",
  "% the value actually contains, measured rather than asserted: a derived id such as",
  "% conversation_id = conv:{userA}:{userB} reports both parties whether or not anyone",
  "% noticed the format!.",
  ""
];

for (const table of Object.keys(ledger.tables)) {
  if (table === "unmapped") continue;
  const entries = byTable.get(table) ?? [];
  if (entries.length === 0) continue;
  lines.push(`% --- ${table}: ${ledger.tables[table]}`);
  for (const entry of entries.sort((a, b) => `${a.surface}${a.path}`.localeCompare(`${b.surface}${b.path}`))) {
    const carries = entry.carries.length > 0 ? entry.carries.join(", ") : "---";
    const bits = entry.bits === "constant" ? ` (constant: ${entry.value})` : entry.bits === "absent" ? " (never populated)" : "";
    lines.push(
      `${escape(entry.surface)} & ${escape(entry.path)}${escape(bits)} & ${escape(carries)} \\\\`
    );
  }
  lines.push("\\addlinespace");
  lines.push("");
}

const rendered = `${lines.join("\n")}\n`;
const write = process.argv.includes("--write");

if (write) {
  await writeFile(outputPath, rendered, "utf8");
  console.log(`rendered leakage table (${ledger.entries.length} entries)`);
} else {
  let actual;
  try {
    actual = await readFile(outputPath, "utf8");
  } catch {
    throw new Error(`Missing ${outputPath}. Run this script with --write.`);
  }
  if (actual.replace(/\r\n/g, "\n") !== rendered) {
    throw new Error(
      `Generated leakage table is out of date: ${outputPath}. Run this script with --write.\n` +
        "If this changed because `carries` widened, the write-up's table widened with it — " +
        "review that before committing."
    );
  }
  console.log(`leakage table ok (${ledger.entries.length} entries)`);
}

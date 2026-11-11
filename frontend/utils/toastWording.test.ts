/**
 * X1 (Nov 11): customer-facing toasts used internal words: "Sast conversation created successfully", "User profile
 * fetched successfully" on every page load, "... export results fetched successfully", "Invalid Input from user", and
 * a delete or rename said it twice (API client and page). Now: "SAST scan created", no toast for reads, "SAST report
 * downloaded", one toast per action. (Members/admin messages and S2/M1x-owned pages are left to their owners.)
 * Run: npx --yes tsx utils/toastWording.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const root = path.join(__dirname, "..");
const api = fs.readFileSync(path.join(root, "utils", "backend_api.ts"), "utf8");
const literals = [...api.matchAll(/toast\.success\((["'])([^"'\n]*)\1/g)].map((m) => m[2]);
assert.ok(literals.includes("SAST scan created") && literals.includes("DAST scan created") && literals.includes("MCP scan created"));
for (const text of literals) {
  assert.ok(!/successfully/.test(text), `API toast says "successfully": ${text}`);
  assert.ok(!/conversation|fetched|Refreshed|^Sast/.test(text), `API toast uses an internal word: ${text}`);
}
assert.ok(!api.includes("User profile fetched"), "a read shows no toast");
assert.ok(!/toast\.success\("(SAST|LLM|MCP|IAC|SCA \+ SBOM|CBOM|AI BOM|DAST) scan (deleted|renamed)/.test(api),
  "delete and rename are said once, by the page");

const scanned = ["app", "components"].flatMap((d) => walk(path.join(root, d)));
const owned = new Set(["components/Settings.tsx", "app/[team_id]/settings/page.tsx", "app/[team_id]/cbom/page.tsx"]);
for (const file of scanned) {
  const rel = path.relative(root, file);
  if (owned.has(rel)) continue;
  const src = fs.readFileSync(file, "utf8");
  for (const m of src.matchAll(/toast\.success\((["'])([^"'\n]*)\1/g)) {
    assert.ok(!/successfully/.test(m[2]), `${rel}: "${m[2]}"`);
  }
  assert.ok(!/Invalid [Ii]nput from user/.test(src), `${rel}: "Invalid input from user"`);
}

function walk(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? walk(path.join(dir, e.name)) : /\.tsx?$/.test(e.name) && !e.name.endsWith(".test.ts") ? [path.join(dir, e.name)] : []);
}
console.log("toast wording: tests passed");

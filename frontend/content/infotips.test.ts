/**
 * F2 (i) info tips: the registry and its coverage.
 *  1. Registry integrity: every entry has a label, a "what it is" and an example of sensible length, and a
 *     `// src: <file>:<line>` note above it naming the backend (or frontend) code the text was checked against;
 *     each named file exists and has that line.
 *  2. Every id used in the app exists, and every entry is used (no orphan text).
 *  3. Coverage: in every covered page, each field, filter, setting, metric and column header has a tip
 *     (rules in content/infotipCoverage.ts). The scanner is also run on fixtures, so it is shown to catch a gap.
 * Run: npx --yes tsx content/infotips.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import { INFO_TIPS } from "./infotips";
import { findGaps, type Gap } from "./infotipCoverage";

const frontend = path.join(__dirname, "..");
const repo = path.join(frontend, "..");
const read = (p: string) => fs.readFileSync(p, "utf8");

/** Pages and components whose user-facing items must all have a tip. Directories include every .tsx below them. */
export const COVERED: string[] = [
  // SAST: list page (dashboard, filters, table, New Scan dialog) and scan configuration
  "app/[team_id]/sast/page.tsx",
  "components/sast-options-sidebar.tsx",
  "components/sast-scan-settings-form.tsx", // the same SAST settings, for CI/CD integrations
  "components/repository-card.tsx",
  "components/path-arrays-input.tsx",
  // SCA + SBOM
  "app/[team_id]/sbom_sca/page.tsx",
  "components/sca-sbom-options-sidebar.tsx",
  // IaC
  "app/[team_id]/iac/page.tsx",
  "components/iac-options-sidebar.tsx",
];
/** Dashboards: their h2/h3 chart titles need a tip as well. */
export const DASHBOARDS = new Set<string>([]);

function expand(entry: string): string[] {
  const abs = path.join(frontend, entry);
  if (!fs.existsSync(abs)) throw new Error(`covered path does not exist: ${entry}`);
  if (fs.statSync(abs).isFile()) return [entry];
  return fs.readdirSync(abs, { withFileTypes: true }).flatMap((e) => {
    const rel = path.join(entry, e.name);
    if (e.isDirectory()) return expand(rel);
    return e.name.endsWith(".tsx") ? [rel] : [];
  });
}

// ---------------------------------------------------------------- 1. registry integrity
const registrySrc = read(path.join(__dirname, "infotips.ts"));
const srcNote = new Map<string, string>();
for (const m of registrySrc.matchAll(/\/\/ src: ([^\n]*)\n(?:[ \t]*\/\/[^\n]*\n)*[ \t]*"([^"]+)":\s*\{/g)) srcNote.set(m[2], m[1]);

const ids = Object.keys(INFO_TIPS);
assert.ok(ids.length > 0, "the registry is empty");
const problems: string[] = [];
for (const id of ids) {
  const tip = INFO_TIPS[id as keyof typeof INFO_TIPS] as { label: string; what: string; example: string; learnMore?: { href: string } };
  if (!/^[a-z0-9]+(\.[a-z0-9_]+)+$/.test(id)) problems.push(`${id}: id must be dotted lower-case (surface.area.item)`);
  if (!tip.label || tip.label.length > 60) problems.push(`${id}: label must be 1-60 characters`);
  if (!tip.what || tip.what.length < 20 || tip.what.length > 420) problems.push(`${id}: "what" must be 20-420 characters (${tip.what?.length})`);
  if (!tip.example || tip.example.length < 5 || tip.example.length > 300) problems.push(`${id}: example must be 5-300 characters (${tip.example?.length})`);
  for (const [k, v] of Object.entries({ what: tip.what, example: tip.example })) {
    if (!/[.!?)]$/.test(v ?? "")) problems.push(`${id}: ${k} must end with a full stop`);
    if (/\b(TODO|TBD|FIXME|lorem)\b/i.test(v ?? "")) problems.push(`${id}: ${k} has a placeholder`);
  }
  if (tip.learnMore && !/^(\/|https:\/\/)/.test(tip.learnMore.href)) problems.push(`${id}: learnMore must be an app path or https URL`);
  const note = srcNote.get(id);
  if (!note) {
    problems.push(`${id}: no "// src: <file>:<line>" comment directly above the entry`);
    continue;
  }
  const refs = [...note.matchAll(/([A-Za-z0-9_.\[\]/-]+\.[a-z]{1,5}):(\d+)(?:-(\d+))?/g)];
  if (refs.length === 0) problems.push(`${id}: src note names no <file>:<line>`);
  for (const r of refs) {
    const file = path.join(repo, r[1]);
    if (!fs.existsSync(file)) {
      problems.push(`${id}: src file not found: ${r[1]}`);
      continue;
    }
    const lines = read(file).split("\n").length;
    const last = Number(r[3] ?? r[2]);
    if (Number(r[2]) < 1 || last > lines) problems.push(`${id}: ${r[1]} has ${lines} lines, the note cites ${r[2]}${r[3] ? "-" + r[3] : ""}`);
  }
}
assert.deepEqual(problems, [], "registry problems:\n" + problems.join("\n"));

// ---------------------------------------------------------------- 2. ids used <-> registry
function sources(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) return e.name === "node_modules" || e.name === ".next" ? [] : sources(p);
    return /\.tsx?$/.test(e.name) && !e.name.endsWith(".test.ts") ? [p] : [];
  });
}
const appFiles = [...sources(path.join(frontend, "app")), ...sources(path.join(frontend, "components"))];
const used = new Set<string>();
const unknown: string[] = [];
for (const f of appFiles) {
  const text = read(f);
  for (const m of text.matchAll(/(?:infoId\s*[=:]\s*\{?\s*|<InfoTip\b[^>]*?\bid=\{?\s*)"([^"]+)"/g)) {
    used.add(m[1]);
    if (!(m[1] in INFO_TIPS)) unknown.push(`${path.relative(frontend, f)}: unknown info tip id "${m[1]}"`);
  }
  // ids passed through typed arrays/objects, e.g. { infoId: "x" } or ["x" as InfoTipId]
  for (const m of text.matchAll(/"([a-z0-9]+(?:\.[a-z0-9_]+)+)"/g)) if (m[1] in INFO_TIPS) used.add(m[1]);
}
assert.deepEqual(unknown, [], unknown.join("\n"));
const orphans = ids.filter((id) => !used.has(id));
assert.deepEqual(orphans, [], "registry entries used nowhere (delete them or use them):\n" + orphans.join("\n"));

// ---------------------------------------------------------------- 3. coverage
// the scanner itself: a fixture with a gap of each kind is caught, and the fixed version passes
const bad = `
  <Label htmlFor="a">Name</Label>
  <Input id="a" />
  <CardTitle>Total scans</CardTitle>
  <TableHead>Credits</TableHead><TableHead>Actions</TableHead>
  <p className="text-xs font-medium text-zinc-600">Pending</p>
  <Input id="b" />`;
const badGaps = findGaps(bad).map((g) => g.rule).sort();
assert.deepEqual(badGaps, ["control", "control", "heading", "heading", "heading", "label"], `fixture gaps: ${badGaps}`);
const good = `
  <FieldLabel htmlFor="a" infoId="x.y">Name</FieldLabel>
  <Input id="a" />
  <CardTitle>Total scans <InfoTip id="x.z" /></CardTitle>
  <TableHead>Credits <InfoTip id="x.c" /></TableHead><TableHead>Actions</TableHead>
  <p className="text-xs font-medium text-zinc-600">Pending <InfoTip id="x.p" /></p>
  {/* infotip-shared: second half of the same range */}
  <Input id="b" />
  <p className="text-xs font-medium">{value}</p>`;
assert.deepEqual(findGaps(good), [], "the fixed fixture must pass");
// one tip between two controls serves one of them, not both
assert.equal(findGaps(`<Input id="a" /> <InfoTip id="x.y" /> <Input id="b" />`).length, 1, "a tip must not serve two controls");
assert.equal(findGaps(`<Input id="a" /> <InfoTip id="x.y" /> <Input id="b" /> <InfoTip id="x.z" />`).length, 0, "a tip after each control");
// a tip far above a control does not cover it
const far = `<InfoTip id="x.y" />` + "\n".repeat(40) + `<Input id="c" />`;
assert.equal(findGaps(far).length, 1, "a tip 40 lines above must not cover a control");
// dashboards: chart titles
assert.equal(findGaps(`<h2 className="x">Daily scan volume</h2>`, { dashboard: true }).length, 1);
assert.equal(findGaps(`<h2 className="x">Daily scan volume <InfoTip id="a.b" /></h2>`, { dashboard: true }).length, 0);

const files = [...new Set(COVERED.flatMap(expand))];
const report: string[] = [];
for (const rel of files) {
  const gaps: Gap[] = findGaps(read(path.join(frontend, rel)), { dashboard: DASHBOARDS.has(rel) });
  for (const g of gaps) report.push(`${rel}:${g.line} [${g.rule}] ${g.snippet}`);
}
assert.deepEqual(report, [], `${report.length} item(s) without an (i) tip:\n` + report.join("\n"));

console.log(`info tips: ${ids.length} entries, ${files.length} covered files, tests passed`);

/**
 * F2 (i) info tips: the registry and its coverage.
 *  1. Registry integrity: every entry has a label, a "what it is" and an example of sensible length, and a
 *     `// src: <file>:<line>` note above it naming the backend (or frontend) code the text was checked against;
 *     each named file exists and has that line.
 *  2. Every id used in the app exists, and every entry is used (no orphan text).
 *  3. Coverage: in every covered page, each field, filter, setting, metric and column header has a tip of its own
 *     (rules in content/infotipCoverage.ts). The scanner is also run on fixtures, so it is shown to catch a gap.
 *  4. Probes: an item without a tip, added to a real covered page in memory, is reported (the review's probes).
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
  "components/SASTResults.tsx", // results view: per-scan dashboard, findings table and filters
  "components/finding-selection-menu.tsx", // the selection's Actions menu, shared by every results view
  // SCA + SBOM
  "app/[team_id]/sbom_sca/page.tsx",
  "components/sca-sbom-options-sidebar.tsx",
  "components/SbomResults.tsx",
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
  const tip = INFO_TIPS[id as keyof typeof INFO_TIPS] as Record<string, string | undefined>;
  const extra = Object.keys(tip).filter((k) => !["label", "what", "example"].includes(k));
  if (extra.length) problems.push(`${id}: unknown field(s) ${extra.join(", ")} (tooltip content is text only)`);
  if (!/^[a-z0-9]+(\.[a-z0-9_]+)+$/.test(id)) problems.push(`${id}: id must be dotted lower-case (surface.area.item)`);
  if (!tip.label || tip.label.length > 60) problems.push(`${id}: label must be 1-60 characters`);
  if (!tip.what || tip.what.length < 20 || tip.what.length > 420) problems.push(`${id}: "what" must be 20-420 characters (${tip.what?.length})`);
  if (!tip.example || tip.example.length < 5 || tip.example.length > 300) problems.push(`${id}: example must be 5-300 characters (${tip.example?.length})`);
  for (const [k, v] of Object.entries({ what: tip.what, example: tip.example })) {
    if (!/[.!?)]$/.test(v ?? "")) problems.push(`${id}: ${k} must end with a full stop`);
    if (/\b(TODO|TBD|FIXME|lorem)\b/i.test(v ?? "")) problems.push(`${id}: ${k} has a placeholder`);
  }
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
// The scanner parses TSX, so fixtures are wrapped in a fragment.
const fx = (jsx: string) => `const f = (<>\n${jsx}\n</>);\n`;
const rules = (jsx: string, opts?: { dashboard?: boolean }) => findGaps(fx(jsx), opts).map((g) => g.rule).sort();
// a fixture with a gap of each kind is caught, and the fixed version passes
const bad = `
  <Label htmlFor="a">Name</Label>
  <Input id="a" />
  <CardTitle>Total scans</CardTitle>
  <TableHead>Credits</TableHead><TableHead>Actions</TableHead>
  <p className="text-xs font-medium text-zinc-600">Pending</p>
  <Input id="b" />`;
assert.deepEqual(rules(bad), ["control", "control", "heading", "heading", "heading", "label"], `fixture gaps: ${rules(bad)}`);
const good = `
  <FieldLabel htmlFor="a" infoId="x.y">Name</FieldLabel>
  <Input id="a" />
  <CardTitle>Total scans <InfoTip id="x.z" /></CardTitle>
  <TableHead>Credits <InfoTip id="x.c" /></TableHead><TableHead>Actions</TableHead>
  <p className="text-xs font-medium text-zinc-600">Pending <InfoTip id="x.p" /></p>
  <div>
    {/* infotip-shared: second half of the same range */}
    <Input id="b" />
  </div>
  <p className="text-xs font-medium">{value}</p>`;
assert.deepEqual(findGaps(fx(good)), [], "the fixed fixture must pass");
// one tip between two controls serves one of them, not both
assert.deepEqual(rules(`<Input id="a" /> <InfoTip id="x.y" /> <Input id="b" />`), ["control"], "a tip must not serve two controls");
assert.deepEqual(rules(`<Input id="a" /> <InfoTip id="x.y" /> <Input id="b" /> <InfoTip id="x.z" />`), [], "a tip after each control");
assert.deepEqual(rules(`<InfoTip id="x.y" /> <Input id="a" /> <InfoTip id="x.z" /> <Input id="b" />`), [], "a tip before each control");
// a control without a tip is caught wherever it is added, in either layout (tips after controls, tips before them)
for (const at of [0, 1, 2]) {
  const after = ["<Input id=\"a\" /> <InfoTip id=\"x.a\" />", "<Input id=\"b\" /> <InfoTip id=\"x.b\" />"];
  const before = ["<InfoTip id=\"x.a\" /> <Input id=\"a\" />", "<InfoTip id=\"x.b\" /> <Input id=\"b\" />"];
  for (const parts of [after, before]) {
    const withProbe = [...parts.slice(0, at), "<Switch id=\"probe\" />", ...parts.slice(at)].join("\n");
    assert.deepEqual(rules(`<div>${withProbe}</div>`), ["control"], `a tipless control at position ${at}:\n${withProbe}`);
  }
}
// a tip in a heading, description or paragraph explains that text; it never serves a control next to it
for (const text of [
  `<CardTitle>Scan scope <InfoTip id="x.y" /></CardTitle>`,
  `<CardDescription>Paths to leave out <InfoTip id="x.y" /></CardDescription>`,
  `<h3>Run scan <InfoTip id="x.y" /></h3>`,
  `<p className="text-xs">Builds the SBOM from your code. <InfoTip id="x.y" /></p>`,
]) {
  assert.deepEqual(rules(`<div>${text}<Switch id="s" /></div>`), ["control"], `a tip in ${text} must not cover a control`);
}
// a FieldLabel bound to another control (htmlFor) never serves this one
assert.deepEqual(rules(`<div><Input id="probe" /><FieldLabel htmlFor="real" infoId="x.y">Real</FieldLabel><Input id="real" /></div>`), ["control"]);
// a tip in another container (beyond MAX_CLIMB levels) or far away does not cover a control
assert.deepEqual(rules(`<div><InfoTip id="x.y" /></div><section><div><div><div><Input id="c" /></div></div></div></section>`), ["control"]);
assert.deepEqual(rules(`<div><InfoTip id="x.y" />${"\n".repeat(40)}<Input id="c" /></div>`), ["control"], "a tip 40 lines above must not cover a control");
// dashboards: chart titles
assert.deepEqual(rules(`<h2 className="x">Daily scan volume</h2>`, { dashboard: true }), ["h2"]);
assert.deepEqual(rules(`<h2 className="x">Daily scan volume <InfoTip id="a.b" /></h2>`, { dashboard: true }), []);

const files = [...new Set(COVERED.flatMap(expand))];
const report: string[] = [];
for (const rel of files) {
  const gaps: Gap[] = findGaps(read(path.join(frontend, rel)), { dashboard: DASHBOARDS.has(rel) });
  for (const g of gaps) report.push(`${rel}:${g.line} [${g.rule}] ${g.snippet}`);
}
assert.deepEqual(report, [], `${report.length} item(s) without an (i) tip:\n` + report.join("\n"));

// ---------------------------------------------------------------- 4. probes on the real pages
// Each probe adds an item without a tip of its own to a covered file (in memory) and must be reported. The first six
// are the probes of the content review of PR #38 (review 5858670025); three of them passed the earlier scanner.
// An anchor that no longer exists fails the test, so the probes keep testing the real layout.
const PROBES: { name: string; file: string; anchor: string; insert: string; where: "before" | "after"; gaps: Gap["rule"][] }[] = [
  {
    name: "review 1: second Input in the rename dialog",
    file: "app/[team_id]/sast/page.tsx",
    anchor: `<Input id="rename-scan-title"`,
    insert: `<Input id="probe-second" />`,
    where: "before",
    gaps: ["control"],
  },
  {
    name: "review 2: bare Label + Switch in the repository card",
    file: "components/repository-card.tsx",
    anchor: `<FieldLabel htmlFor={\`\${id}-branch\`}`,
    insert: `<Label htmlFor="probe-switch">Shallow clone</Label><Switch id="probe-switch" />`,
    where: "before",
    gaps: ["control", "label"],
  },
  {
    name: "review 3: KPI label without a tip",
    file: "app/[team_id]/sast/page.tsx",
    anchor: `<p className="text-xs text-zinc-500 dark:text-zinc-400">Since 00:00 UTC</p>`,
    insert: `<p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Retrying</p>`,
    where: "after",
    gaps: ["heading"],
  },
  {
    name: "review 4: Input above the SBOM-file FieldLabel",
    file: "components/sca-sbom-options-sidebar.tsx",
    anchor: `<FieldLabel htmlFor="sbom-file-upload"`,
    insert: `<Input id="probe-max-depth" />`,
    where: "before",
    gaps: ["control"],
  },
  {
    name: "review 5: Checkbox under the Scan scope CardDescription",
    file: "components/sast-options-sidebar.tsx",
    anchor: `Paths or patterns to exclude from the scan (e.g. vendor, node_modules).\n                </CardDescription>`,
    insert: `<Checkbox id="probe-include-tests" />`,
    where: "after",
    gaps: ["control"],
  },
  {
    name: "review 6: Switch under the Run scan h3",
    file: "components/sca-sbom-options-sidebar.tsx",
    anchor: `Run scan <InfoTip id="scan.cfg.run" /></h3>`,
    insert: `<Switch id="probe-fail-on-critical" />`,
    where: "after",
    gaps: ["control"],
  },
  {
    name: "Switch after the description paragraph that carries a tip",
    file: "components/sca-sbom-options-sidebar.tsx",
    anchor: `<InfoTip id="sbom.cfg.repository" />\n                  </p>`,
    insert: `<Switch id="probe-after-description" />`,
    where: "after",
    gaps: ["control"],
  },
  {
    name: "filter between the search box's tip and the status filter",
    file: "app/[team_id]/sast/page.tsx",
    anchor: `<InfoTip id="scan.filter.search" className="-ml-2" />`,
    insert: `<Select><SelectTrigger className="h-9">Owner</SelectTrigger></Select>`,
    where: "after",
    gaps: ["control"],
  },
  {
    name: "column header without a tip",
    file: "app/[team_id]/sbom_sca/page.tsx",
    anchor: `<TableHead`,
    insert: `<TableHead>Fix version</TableHead>`,
    where: "before",
    gaps: ["heading"],
  },
];
for (const p of PROBES) {
  const original = read(path.join(frontend, p.file));
  const at = original.indexOf(p.anchor);
  assert.ok(at >= 0, `probe "${p.name}": anchor not found in ${p.file}; update the probe`);
  const pos = p.where === "before" ? at : at + p.anchor.length;
  const probed = original.slice(0, pos) + p.insert + original.slice(pos);
  const opts = { dashboard: DASHBOARDS.has(p.file) };
  const added = findGaps(probed, opts).map((g) => g.rule).sort();
  const base = findGaps(original, opts).map((g) => g.rule).sort();
  assert.deepEqual(base, [], `probe "${p.name}": ${p.file} must have no gap before the probe`);
  assert.deepEqual(added, p.gaps, `probe "${p.name}" must be reported as ${p.gaps.join(", ")}; got ${added.join(", ") || "nothing"}`);
}

console.log(`info tips: ${ids.length} entries, ${files.length} covered files, ${PROBES.length} probes, tests passed`);

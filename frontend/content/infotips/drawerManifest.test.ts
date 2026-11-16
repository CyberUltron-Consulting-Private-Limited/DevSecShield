/**
 * The Explanations drawer's manifest (content/infotips/drawerManifest.ts): every id is a registered tip with text,
 * every id of a run-page view is rendered by some component, every (i) the run finding dialog renders is listed under
 * a dialog tab, and the ids collected on staging run 40 (base of the results redesign) are all listed (page ids under
 * the run views, dialog ids under the dialog tabs).
 * Run (frontend/): npx --yes tsx@4.23.15 content/infotips/drawerManifest.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import { INFO_TIP_LABELS } from "./labels";
import { INFO_TIPS } from "./all";
import { DRAWER_MANIFEST, DRAWER_VIEW_LABEL, drawerIds, type DrawerView } from "./drawerManifest";

const frontend = path.join(__dirname, "..", "..");
const read = (rel: string) => fs.readFileSync(path.join(frontend, rel), "utf8");
function sources(dir: string): string[] {
  return fs.readdirSync(path.join(frontend, dir), { withFileTypes: true }).flatMap((e) => {
    const rel = path.join(dir, e.name);
    if (e.isDirectory()) return e.name === "node_modules" || e.name === "__snapshots__" ? [] : sources(rel);
    return /\.tsx?$/.test(e.name) && !/\.test\.tsx?$/.test(e.name) ? [rel] : [];
  });
}
const views = Object.keys(DRAWER_MANIFEST) as DrawerView[];
const all = new Set(views.flatMap((v) => DRAWER_MANIFEST[v] as readonly string[]));

for (const id of all) {
  assert.ok(id in INFO_TIP_LABELS, `${id}: no label`);
  assert.ok(id in INFO_TIPS, `${id}: no text`);
}
for (const v of views) {
  assert.ok(DRAWER_VIEW_LABEL[v], `${v}: no heading`);
  const ids = DRAWER_MANIFEST[v] as readonly string[];
  assert.equal(new Set(ids).size, ids.length, `${v}: an id listed twice`);
  const listed = drawerIds(v);
  assert.equal(new Set(listed).size, listed.length, `${v}: drawerIds repeats an id`);
  assert.deepEqual(listed.slice(0, ids.length), [...ids], `${v}: its own ids first`);
}

// every listed id is rendered somewhere in the app's components (a manifest entry for a removed tip fails here)
const code = sources("components").map(read).join("\n");
for (const id of all) assert.ok(code.includes(`"${id}"`), `${id}: listed in the drawer but rendered by no component`);

// every (i) of the dialog is listed under a dialog tab
const dialogIds = new Set(views.filter((v) => v.startsWith("dialog.")).flatMap((v) => DRAWER_MANIFEST[v] as readonly string[]));
const dialog = read("components/cbom/results/RunFindingDialog.tsx") + read("components/cbom/results/AiRemediationPanel.tsx");
for (const m of dialog.matchAll(/(?:InfoTip id|infoId)="([^"]+)"/g)) assert.ok(dialogIds.has(m[1]), `dialog tip ${m[1]} is not in a dialog tab of the manifest`);

// staging run 40 (the base): every tip the page and the dialog showed is listed (results redesign: nothing removed)
const BASE_PAGE = ["cbom.agility.code_fixed", "cbom.agility.configurable", "cbom.agility.excl_pq", "cbom.agility.hardware_fixed", "cbom.agility.inferred",
  "cbom.agility.section", "cbom.agility.self_fixable", "cbom.agility.unknown", "cbom.agility.vendor_fixed", "cbom.cal.expiry", "cbom.chart.algorithms",
  "cbom.chart.asset_types", "cbom.chart.cert_expiry", "cbom.chart.cnsa", "cbom.chart.pqc", "cbom.chart.protocols", "cbom.chart.qv", "cbom.chart.qv_fixes",
  "cbom.chart.replacements", "cbom.chart.roadmap", "cbom.chart.weak", "cbom.qgrade.distribution", "cbom.res.algo_types", "cbom.res.col.algorithm",
  "cbom.res.col.quantum", "cbom.res.compliance", "cbom.res.kpi.assets", "cbom.res.kpi.avg_risk", "cbom.res.kpi.certs", "cbom.res.kpi.keys",
  "cbom.res.kpi.qv", "cbom.res.kpi.ready", "cbom.res.kpi.weak", "cbom.res.owasp", "cbom.res.remediation", "cbom.res.severity", "cbom.res.strength",
  "cbom.run.certs", "cbom.run.changes", "cbom.run.col.asset", "cbom.run.col.assets_collected", "cbom.run.col.credits", "cbom.run.col.criticality",
  "cbom.run.col.duration", "cbom.run.col.endpoints", "cbom.run.col.exposure", "cbom.run.col.hndl", "cbom.run.col.kind", "cbom.run.col.outcome",
  "cbom.run.col.priority", "cbom.run.col.source", "cbom.run.col.status", "cbom.run.col.where", "cbom.run.compliance", "cbom.run.covered",
  "cbom.run.deliverables", "cbom.run.downloads", "cbom.run.f.risk", "cbom.run.filter.impact", "cbom.run.filter.quantum", "cbom.run.filter.source",
  "cbom.run.filter.status", "cbom.run.filter.type", "cbom.run.findings", "cbom.run.posture", "cbom.run.provenance", "cbom.run.quantum",
  "cbom.run.readiness", "cbom.run.readiness_actions", "cbom.run.risk_scores", "cbom.run.search", "cbom.run.targets", "cbom.run.top_risks",
  "cbom.run.verify", "cbom.run.view", "cbom.run.waves", "cbsrc.rr.job.assets", "cbsrc.rr.job.attempts", "cbsrc.rr.job.credits", "cbsrc.rr.job.error",
  "cbsrc.rr.job.runs_on", "cbsrc.rr.job.source", "cbsrc.rr.job.status", "results.finding.action", "results.table.impact"];
const BASE_DIALOG = ["cbom.agility.hardware_fixed", "cbom.agility.inferred", "cbom.agility.vendor_fixed", "cbom.ai.panel", "cbom.res.col.fix_class",
  "cbom.run.col.qgrade", "cbom.run.f.compliance", "cbom.run.f.finding", "cbom.run.f.impact", "cbom.run.f.key_size", "cbom.run.f.location",
  "cbom.run.f.origin", "cbom.run.f.owasp", "cbom.run.f.quantum", "cbom.run.f.risk", "cbom.run.f.status", "cbom.run.f.strength",
  "cbom.run.f.suggested_fix", "cbom.run.f.type"];
const pageIds = new Set(views.filter((v) => v.startsWith("run.")).flatMap((v) => DRAWER_MANIFEST[v] as readonly string[]));
assert.deepEqual(BASE_PAGE.filter((id) => !pageIds.has(id)), [], "base page tips missing from the page views");
assert.deepEqual(BASE_DIALOG.filter((id) => !dialogIds.has(id)), [], "base dialog tips missing from the dialog tabs");

console.log(`drawer manifest: ${views.length} views, ${all.size} tips, tests passed`);

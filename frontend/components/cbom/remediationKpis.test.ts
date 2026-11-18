/**
 * "Critical issues fixed" on the CBOM code-scan results page: fixed Critical findings over ALL Critical findings of the
 * scan (the severity distribution counts fixed ones too), as on the SAST results page. It used to divide by
 * fixed + all Critical, which never passed 50 %, so the (i) tip ("share of all its Critical findings") disagreed.
 * Run: npx --yes tsx components/cbom/remediationKpis.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import { criticalFixedPct } from "./remediationKpis";

assert.equal(criticalFixedPct(0, 0), 0, "no Critical finding: 0 %");
assert.equal(criticalFixedPct(2, 2), 100, "every Critical finding fixed: 100 %, not 50 %");
assert.equal(criticalFixedPct(1, 4), 25, "1 of 4 fixed: 25 %");
assert.equal(criticalFixedPct(2, 3), 67, "rounded to a whole percent");
assert.equal(criticalFixedPct(5, 3), 100, "never above 100 % (counts from two reads that may disagree)");
assert.equal(criticalFixedPct(-1, 3), 0, "never below 0 %");

// Wiring: every component that shows "Critical issues fixed" (any letter case: SAST and AI BOM write "Critical Issues
// Fixed") computes it with criticalFixedPct, including the dashboard charts that moved to components/cbom/results
// (CB-38 #120), and none divides by fixed + all Critical.
const frontend = path.resolve(__dirname, "..", "..");
function tsxFiles(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    if (e.name === "node_modules" || e.name.startsWith(".")) return [];
    const abs = path.join(dir, e.name);
    return e.isDirectory() ? tsxFiles(abs) : e.name.endsWith(".tsx") ? [abs] : [];
  });
}
const shows = [...tsxFiles(path.join(frontend, "components")), ...tsxFiles(path.join(frontend, "app"))]
  .filter((f) => /critical issues fixed/i.test(fs.readFileSync(f, "utf8")))
  .map((f) => path.relative(frontend, f));
for (const page of [path.join("components", "cbom", "results", "CbomDashboardCharts.tsx"), path.join("components", "AiBomResults.tsx"),
  path.join("components", "SASTResults.tsx"), path.join("app", "[team_id]", "sast", "page.tsx")]) {
  assert.ok(shows.includes(page), `${page} shows "Critical issues fixed": ${shows.join(", ")}`);
}
for (const rel of shows) {
  const src = fs.readFileSync(path.join(frontend, rel), "utf8");
  assert.match(src, /criticalFixedPct\(/, `${rel} computes "Critical issues fixed" with criticalFixedPct`);
  assert.doesNotMatch(src, /fixed\s*\+\s*critical/i, `${rel} does not divide by fixed + all Critical`);
}
console.log("remediation KPIs: tests passed");

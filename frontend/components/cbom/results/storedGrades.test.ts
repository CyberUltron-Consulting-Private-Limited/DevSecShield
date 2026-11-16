/**
 * CB-19 PR-3: the run table's quantum risk grade chips (the server's facets.q_grade, the grade stored at ingest) and
 * the run heat-map's "Quantum risk" colouring with a cell's asset list.
 * Run (frontend/): npx --yes tsx@4.23.15 components/cbom/results/storedGrades.test.ts
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

import CryptoHeatmap from "../CryptoHeatmap";
import { GRADE_KEYS, gradeText } from "../grade/model";
import type { HeatData } from "../heatmapLogic";
import { DEFAULT_FILTERS, filtersToParams, gradeChips, hasActiveFilters } from "./model";

const h = React.createElement;
const [UNKNOWN, CRITICAL, HIGH, MEDIUM, LOW] = GRADE_KEYS;
const facets = (q_grade: Record<string, number> | null | undefined) =>
  ({ facets: { type: {}, impact: {}, quantum_vulnerable: 0, q_grade } });

test("grade chips come from the server's facet, in grade order, with their words, zeros left out", () => {
  const { chips, note } = gradeChips({
    ...facets({ [UNKNOWN]: 2, [CRITICAL]: 3, [HIGH]: 0, [MEDIUM]: 1, [LOW]: 4, none: 5 }),
    grade_filter: { available: true, reason: null },
  });
  assert.equal(note, null);
  assert.deepEqual(chips.map((c) => [c.grade, c.count]), [[UNKNOWN, 2], [CRITICAL, 3], [MEDIUM, 1], [LOW, 4], ["none", 5]]);
  assert.equal(chips[1].text, gradeText(CRITICAL));
  assert.equal(chips[4].text, "No grade");
});

test("a run graded at view gets no chips and says why; an older server gets neither", () => {
  const unavailable = gradeChips({ ...facets(null), grade_filter: { available: false, reason: "graded at view: x" } });
  assert.deepEqual(unavailable, { chips: [], note: "graded at view: x" });
  assert.deepEqual(gradeChips(facets(undefined)), { chips: [], note: null });
  assert.deepEqual(gradeChips(null), { chips: [], note: null });
});

test("the grade filter goes to the server and counts as an active filter", () => {
  const f = { ...DEFAULT_FILTERS, q_grade: HIGH };
  assert.equal(filtersToParams(f).q_grade, HIGH);
  assert.ok(hasActiveFilters(f));
  assert.equal(filtersToParams(DEFAULT_FILTERS).q_grade, undefined);
  assert.ok(!hasActiveFilters(DEFAULT_FILTERS));
});

test("the table renders the chips and clears the grade with every other filter", () => {
  const src = readFileSync(path.join(__dirname, "RunFindingsTable.tsx"), "utf8");
  assert.match(src, /data-testid=\{`run-results-grade-\$\{c\.grade\}`\}/);
  assert.match(src, /onFilters\(\{ q_grade: filters\.q_grade === c\.grade \? undefined : c\.grade, page: 1 \}\)/);
  assert.match(src, /q_grade: undefined,\n\s*pqc_group: undefined/);
  assert.match(src, /data-testid="run-results-grade-note"/);
});

const DATA: HeatData = {
  rows: ["RSA", "Elliptic curve"],
  columns: ["net-a"],
  cells: [
    { row: "RSA", column: "net-a", count: 3, worst: "High", by_impact: { High: 3 },
      by_grade: { [UNKNOWN]: 2, [MEDIUM]: 1, none: 0 }, worst_grade: MEDIUM },
    { row: "Elliptic curve", column: "net-a", count: 2, worst: "none", by_impact: { none: 2 },
      by_grade: { [UNKNOWN]: 2 }, worst_grade: UNKNOWN },
  ],
};

test("the heat-map colours by the server's worst grade with metric=grade, by impact otherwise", () => {
  const graded = renderToStaticMarkup(h(CryptoHeatmap, { data: DATA, metric: "grade", testId: "hm" }));
  assert.match(graded, /data-testid="heat-cell-RSA-net-a"[^>]*data-worst="[^"]+"/);
  const worst = [...graded.matchAll(/data-testid="heat-cell-([^"]+)"[^>]*data-worst="([^"]+)"/g)].map((m) => [m[1], m[2]]);
  // a known grade is never hidden by an unknown one (the server's worst_grade)
  assert.deepEqual(worst, [["RSA-net-a", MEDIUM], ["Elliptic curve-net-a", UNKNOWN]]);
  assert.match(graded, /bg-amber-400/);  // the medium cell
  assert.match(graded, new RegExp(`worst ${gradeText(MEDIUM)}`));  // the text is always next to the colour
  assert.match(graded, /counts by quantum risk grade/);
  const impact = renderToStaticMarkup(h(CryptoHeatmap, { data: DATA, testId: "hm" }));
  assert.deepEqual([...impact.matchAll(/data-worst="([^"]+)"/g)].map((m) => m[1]), ["High", "none"]);
  assert.match(impact, /counts by impact/);
});

test("RunInsights offers Impact | Quantum risk and lists a selected cell's assets from the cell route", () => {
  const src = readFileSync(path.join(__dirname, "..", "sources", "ChangesPanel.tsx"), "utf8");
  assert.match(src, /data-testid=\{`run-heatmap-metric-\$\{v\}`\}/);
  assert.match(src, /getCbomRunHeatmapCell\(teamId, runId, \{ by, metric, row: cell\.row, column: cell\.column, page,/);
  // an older server ignores metric=grade: the map is coloured by grade only when the cells carry grades
  assert.match(src, /const graded = metric === "grade" && q\.data\.cells\.some\(\(c\) => c\.by_grade\);/);
});

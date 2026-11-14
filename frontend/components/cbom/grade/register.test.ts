/**
 * CB-23 PR-B: the risk register view. Filter parameters, pages flattened without duplicates, the closure trend, the
 * CSV file name, and the summary and table rendered with their gate hooks (every grade, "no grade", not-read rows).
 * Run (frontend/): npx --yes tsx@4.23.15 components/cbom/grade/register.test.ts
 */
import assert from "node:assert/strict";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import {
  GRADE_KEYS,
  RegisterSummaryCard,
  RegisterTable,
  closureTrend,
  csvFileName,
  filterParams,
  registerRows,
  type RegisterPage,
  type RegisterRow,
  type RegisterSummary,
} from "./index";

const [G0, G1, G2, G3, G4] = GRADE_KEYS;
const h = React.createElement;
const render = (el: React.ReactElement) =>
  renderToStaticMarkup(h(QueryClientProvider, { client: new QueryClient() }, el));

function row(key: string, grade: string | null, extra: Partial<RegisterRow> = {}): RegisterRow {
  return {
    item_key: key, item_kind: "asset", q_grade: grade, q_label: null, q_reason: "qv_exceeds", label: `Asset ${key}`,
    asset_type: "certificate", family: "RSA", source_ref: "s", source_name: "linux", application: null,
    exposure: "internal", presence: "present", sources: 1, last_run_id: 3, last_observed_at: "2026-11-14T10:00:00Z",
    model_version: "qg-1+x", updated_at: null, ...extra,
  };
}

assert.deepEqual(filterParams({ grade: G1, family: " ", exposure: undefined, source: " src " }), { grade: G1, source: "src" });
const page = (items: RegisterRow[], next: string | null): RegisterPage => ({ items, total: 3, next_after: next });
assert.deepEqual(registerRows([page([row("a", G1), row("b", G1)], "c"), page([row("b", G1), row("c", G4)], null)])
  .map((r) => r.item_key), ["a", "b", "c"]);
assert.deepEqual(registerRows(undefined), []);
assert.equal(csvFileName(4, new Date("2026-11-14T23:00:00Z")), "quantum-risk-register-team4-2026-11-14.csv");

const summary: RegisterSummary = {
  total: 5, q_grades: { [G0]: 1, [G1]: 2, [G2]: 0, [G3]: 0, [G4]: 1, none: 1 }, q0_reasons: { unknown_verdict: 1 },
  q0_gaps_open: {}, families: { RSA: { [G1]: 2 } },
  closures_by_week: [{ week: "2026-11-02", total: 0, by_cause: {} }, { week: "2026-11-09", total: 3, by_cause: { evidence: 3 } }],
  pending_regrade: 4, estate: { stale: false }, model_version: "qg-1+x", server_time: "",
};
assert.deepEqual(closureTrend(summary), [{ week: "2026-11-02", total: 0 }, { week: "2026-11-09", total: 3 }]);
assert.deepEqual(closureTrend(undefined), []);
const card = render(h(RegisterSummaryCard, { summary }));
assert.match(card, /data-testid="register-total" data-total="5"/);
assert.match(card, /data-testid="posture-q-distribution" data-total="5"/);
assert.match(card, /Unknown verdict 1/);
assert.match(card, /4 assets are being re-graded/);
assert.match(card, /11-09 3/);

const table = render(h(RegisterTable, { rows: [row("cert:1", G1, { sources: 4 }), row("obs:2", null, { q_reason: "not_applicable" }),
                                                row("obs:3", G0, { q_reason: "unknown_verdict", presence: "not_read" })] }));
assert.ok(table.includes(`data-testid="register-row-cert:1" data-q="${G1}"`));
assert.match(table, /Q1 Critical/);
assert.match(table, /linux \(\+3 more\)/);
assert.match(table, /data-testid="register-row-obs:2" data-q="none"/);
assert.match(table, /not read in the latest collection/);
assert.match(render(h(RegisterTable, { rows: [] })), /data-testid="register-empty"/);

console.log("register.test.ts: ok");

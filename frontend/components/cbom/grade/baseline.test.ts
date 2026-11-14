/**
 * CB-25 PR-A "Agility baseline" section rendered with react-dom/server: the enterprise card fed the team baseline (self-
 * fixable headline, every count), the systems table (a row per system, its counts adding up to the team's), the dedupe
 * and not-assessed notes, the drill-down list, and the empty team.
 * Run (frontend/): npx --yes tsx@4.23.15 components/cbom/grade/baseline.test.ts
 */
import assert from "node:assert/strict";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import {
  AgilityBaselineView,
  AgilitySubjectsTable,
  FIX_VALUES,
  baselinePosture,
  dedupeText,
  systemsAddUp,
  type AgilityBaseline,
  type AgilityModel,
  type AgilitySubject,
} from "./index";

const h = React.createElement;
const render = (el: React.ReactElement) => renderToStaticMarkup(h(QueryClientProvider, { client: new QueryClient() }, el));
const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const attr = (html: string, raw: string, name: string) =>
  new RegExp(`data-testid="${esc(raw)}"[^>]*?${name}="([^"]*)"|${name}="([^"]*)"[^>]*?data-testid="${esc(raw)}"`).exec(html)?.slice(1).find((v) => v != null);
const MODEL: AgilityModel = { model: "fx-1", model_version: "fx-1+0", kb_version: "k", classes: [], inferred: "", pq_codes: [],
  self_fixable: ["configurable", "code-fixed"], rules: [], unknown_reasons: { key_provider_not_read: "key provider not read" } } as unknown as AgilityModel;

const zero = Object.fromEntries(FIX_VALUES.map((v) => [v, 0]));
const BASE: AgilityBaseline = {
  as_of: "2026-11-14T12:00:00Z", scope: "current estate", agility_version: "fx-1+abc", assets: 6,
  counts: { ...zero, configurable: 2, "vendor-fixed": 2, "hardware-fixed": 1, unknown: 1 },
  counts_excl_pq: { ...zero, configurable: 2, "vendor-fixed": 1, "hardware-fixed": 1, unknown: 1, none: 1 },
  self_fixable_pct: 40, unknown_reasons: { key_provider_not_read: 1 }, not_assessed: 1,
  dedupe: { method: "asset_keys", observations: 8, merged: 2, not_correlated: 0 },
  systems_total: 2,
  systems: {
    next: null, matched: 2,
    items: [
      { key: "application:payments", label: "Payments", kind: "application", assets: 4, hardest: "hardware-fixed",
        counts: { ...zero, configurable: 2, "vendor-fixed": 1, "hardware-fixed": 1 }, self_fixable_pct: 50 },
      { key: "source:abc", label: "src-c", kind: "source", assets: 2, hardest: "vendor-fixed",
        counts: { ...zero, "vendor-fixed": 1, unknown: 1 }, self_fixable_pct: 0 },
    ],
  },
};

// ---- the enterprise card is the run posture card fed the team's counts; the systems table is the section's own
const posture = baselinePosture(BASE);
assert.deepEqual(posture.fix_classes, BASE.counts);
assert.deepEqual(posture.fix_class_systems, []);
const html = render(h(AgilityBaselineView, { teamId: 1, baseline: BASE, systems: BASE.systems.items, model: MODEL }));
assert.equal(attr(html, "agility-baseline", "data-assets"), "6");
assert.equal(attr(html, "posture-fix-self-fixable", "data-pct"), "40");
for (const v of FIX_VALUES) assert.equal(attr(html, `posture-fix-${v}`, "data-count"), String(BASE.counts[v]));
assert.ok(!html.includes('data-testid="posture-fix-systems-toggle"'), "the run card's own systems table stays hidden");
for (const s of BASE.systems.items) {
  assert.equal(attr(html, `agility-baseline-system-${s.key}`, "data-assets"), String(s.assets));
  for (const v of FIX_VALUES) assert.equal(attr(html, `agility-baseline-system-${s.key}-${v}`, "data-count"), String(s.counts[v]));
}
// per-system sums = enterprise totals, and the page says so only when they do not
assert.equal(systemsAddUp(BASE), true);
assert.ok(!html.includes("agility-baseline-mismatch"));
const broken = { ...BASE, counts: { ...BASE.counts, configurable: 3 } };
assert.equal(systemsAddUp(broken), false);
assert.ok(render(h(AgilityBaselineView, { baseline: broken, systems: broken.systems.items, model: MODEL })).includes("agility-baseline-mismatch"));
assert.equal(systemsAddUp({ ...BASE, systems: { ...BASE.systems, next: "x" } }), null, "not checkable before every system is listed");
// drill-down entry points: one per class that has assets
assert.ok(html.includes('data-testid="agility-baseline-open-hardware-fixed"'));
assert.ok(!html.includes('data-testid="agility-baseline-open-code-fixed"'));
assert.match(dedupeText(BASE) ?? "", /8 observations counted as 6 assets; 2 seen again/);
assert.ok(html.includes('data-testid="agility-baseline-not-assessed"'));

// ---- drill-down rows
const ITEMS: AgilitySubject[] = [
  { key: "cert:1", name: "CN=same.lab", type: "certificate", location: "10.0.0.1:443#chain[0]", origin: "sources_run",
    fix_class: "hardware-fixed", fix_class_floor: null, fix_class_excl_pq: "hardware-fixed", deciding_codes: ["QUANTUM_VULNERABLE"],
    observations: 3, sources: ["src-a", "src-b", "src-c"], system: { key: "application:payments", label: "Payments", kind: "application" } },
  { key: "node|x", name: "web", type: "certificate", location: "Cert:\\LocalMachine\\My\\AB", origin: "sources_run",
    fix_class: "unknown", fix_class_floor: "vendor-fixed", fix_class_excl_pq: "none", deciding_codes: [],
    observations: 1, sources: ["src-c"], system: { key: "source:abc", label: "src-c", kind: "source" } },
];
const list = render(h(AgilitySubjectsTable, { items: ITEMS }));
assert.equal((list.match(/data-testid="agility-baseline-subject"/g) ?? []).length, 2);
assert.ok(list.includes('data-fix-class="hardware-fixed"') && list.includes('data-fix-floor="vendor-fixed"'));
assert.ok(render(h(AgilitySubjectsTable, { items: [] })).includes("No asset matches."));

// ---- empty team: no card, a sentence instead, nothing crashes
const empty: AgilityBaseline = { ...BASE, assets: 0, counts: zero, counts_excl_pq: zero, self_fixable_pct: null, unknown_reasons: {},
  not_assessed: 0, dedupe: { method: "asset_keys", observations: 0, merged: 0, not_correlated: 0 }, systems_total: 0,
  systems: { items: [], next: null, matched: 0 } };
const e = render(h(AgilityBaselineView, { baseline: empty, systems: [], model: MODEL }));
assert.ok(e.includes('data-testid="agility-baseline-empty"') && !e.includes('data-testid="posture-fix"'));
assert.equal(dedupeText(empty), null);

console.log("baseline.test.ts: ok");

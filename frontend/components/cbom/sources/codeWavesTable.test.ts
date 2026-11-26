/**
 * PR #500 takeover: the code scan's remediation-waves table fits a 390 px phone without scrolling sideways. On phones
 * the table keeps Select, Asset and Wave; Impact and Owner hint move under the asset name (sm:hidden meta line) and
 * their columns show from sm (640 px) up. The asset cell may shrink (min-w-0, no fixed 360 px), and the table is not
 * forced wider than its card (no min-width).
 * Run (frontend/): npx --yes tsx@4.23.15 --test components/cbom/sources/codeWavesTable.test.ts
 */
import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

import type { CbomRemediationItem } from "@/utils/api/cbom_ops";

import { CodeWavesTable } from "./WavesControls";

const item = (n: number, over: Partial<CbomRemediationItem> = {}): CbomRemediationItem => ({
  asset_key: `k${n}`, scope: "code", label: `src/very/long/path/to/module_${n}/crypto_helpers.py:MD5`, type: "algorithm",
  impact: "High", finding_codes: ["WEAK_ALGORITHM"], quantum_vulnerable: false, exposure: "internal", hndl: false,
  owner_hint: "payments-team", suggested_wave: 2, wave: 2, wave_source: "suggested", assignment: null, ...over,
});

const html = renderToStaticMarkup(React.createElement(CodeWavesTable, {
  items: [item(1), item(2, { impact: null, owner_hint: null })], selected: new Set<string>(), onToggle: () => undefined,
}));
const cells = (tag: "th" | "td") => [...html.matchAll(new RegExp(`<${tag}\\s[^>]*class="([^"]*)"[^>]*>`, "g"))].map((m) => m[1]);

test("Impact and Owner hint columns show from sm up only", () => {
  const th = cells("th");
  assert.equal(th.length, 5);
  const [sel, asset, impact, wave, owner] = th;
  for (const c of [sel, asset, wave]) assert.ok(!c.includes("hidden"), c);
  for (const c of [impact, owner]) assert.ok(/\bhidden\b/.test(c) && c.includes("sm:table-cell"), c);
  const td = cells("td");
  assert.equal(td.filter((c) => /\bhidden\b/.test(c) && c.includes("sm:table-cell")).length, 4, "2 rows x 2 cells");
});

test("on phones impact and owner hint are read under the asset name", () => {
  const meta = [...html.matchAll(/<span[^>]*data-testid="code-wave-meta-([^"]+)"[^>]*class="([^"]*)"[^>]*>([\s\S]*?)<\/span>/g)];
  assert.equal(meta.length, 2);
  assert.ok(meta[0][2].includes("sm:hidden"));
  assert.match(meta[0][3], /High/);
  assert.match(meta[0][3], /payments-team/);
  assert.match(meta[1][3], /—|No impact/);
});

test("the asset cell can shrink and the table is never wider than its card", () => {
  assert.ok(!html.includes("max-w-[360px]"), "a fixed 360 px asset cell overflows a 390 px phone");
  const td = cells("td");
  assert.ok(td.some((c) => c.includes("min-w-0") && c.includes("w-full")), td.join(" | "));
  assert.match(html, /<table[^>]*class="[^"]*\btable-fixed\b[^"]*\bw-full\b/);
  assert.ok(!/<table[^>]*min-w-/.test(html));
});

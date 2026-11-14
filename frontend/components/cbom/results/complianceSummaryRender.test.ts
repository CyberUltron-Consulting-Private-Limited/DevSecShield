/**
 * #270 render: the compliance mapping as the results page renders it (react-dom/server). Summary first (verdict badge,
 * stacked bar in the matrix's verdict colours, clauses touched, assets affected), every non-zero "N assets" a button,
 * readable finding names instead of raw codes, "How to fix" beside every failing clause, and the regulation's text
 * collapsed (closed <details>) so the visible text is a fraction of the old 617-word wall.
 * Run (frontend/): npx --yes tsx@4.23.15 components/cbom/results/complianceSummaryRender.test.ts
 */
import assert from "node:assert/strict";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { VERDICT_COLOR } from "@/components/compliance/verdictTokens";

import { ENGINE, MAPPING, RBI_TEXT } from "./complianceFixtures";
import { buildComplianceSummary } from "./complianceSummary";
import { ComplianceMappingSection } from "./ComplianceSummary";

const h = React.createElement;
const html = (frameworks: ReturnType<typeof buildComplianceSummary>, extra: Record<string, unknown> = {}) =>
  renderToStaticMarkup(h(ComplianceMappingSection, { frameworks, onDrill: () => undefined, scope: "run", ...extra }));
const visibleText = (markup: string) => markup
  .replace(/<details[^>]*data-testid="compliance-clause-[^"]*-text"[^>]*>[\s\S]*?<\/details>/g, " ")  // collapsed text
  .replace(/<[^>]+>/g, " ").replace(/&[a-z#0-9]+;/g, " ");
const words = (s: string) => s.split(/\s+/).filter(Boolean).length;

// a long KB mapping, as on staging run 12: five frameworks, long clause quotes
const long = (n: number) => Array.from({ length: n }, (_, i) => `word${i}`).join(" ");
const BIG = MAPPING.map((fw) => ({ ...fw, clauses: fw.clauses.map((c) => ({ ...c, title: `${c.title} ${long(60)}` })) }));

const run = buildComplianceSummary({ engine: ENGINE, mapping: BIG });
const out = html(run);

// summary first, then the clause lists
const summaryAt = out.indexOf('data-testid="compliance-summary"');
const firstClause = out.indexOf('data-testid="compliance-clause-');
assert.ok(summaryAt > 0 && firstClause > summaryAt, "the per-framework summary comes before any clause");
for (const [fw, verdict] of [["CERT-In", "Partial"], ["RBI", "Fail"], ["SEBI-CSCRF", "Not assessed"], ["NIST", "Partial"], ["CNSA-2-0", "Fail"]]) {
  const m = new RegExp(`data-testid="compliance-summary-${fw}-verdict"[^>]*>([^<]+)<`).exec(out);
  assert.equal(m?.[1], verdict, fw);
}
// the compact chart: one bar per framework, segments in the matrix's verdict colours with their counts
const nistBar = out.slice(out.indexOf('data-testid="compliance-bar-NIST"'), out.indexOf('data-testid="compliance-summary-NIST-clauses"'));
assert.ok(nistBar.includes(`background:${VERDICT_COLOR.pass}`) && nistBar.includes(`background:${VERDICT_COLOR.fail}`), "verdict colours");
assert.match(nistBar, /data-verdict="pass" data-count="3"/);
assert.match(nistBar, /aria-label="NIST requirements: Pass 3 · Fail 1 · Not BOM-evidenceable 1 · N\/A 1"/);
assert.ok(out.includes('data-testid="compliance-summary-legend"'));
assert.match(out, /data-testid="compliance-bar-RBI">No requirement judged</, "no engine framework: says so, no fake bar");

// every non-zero "N assets" is a button (summary rows and clause rows)
const counts = [...out.matchAll(/<(button|span)[^>]*data-testid="(compliance-(?:summary|clause)-[^"]*-assets)"[^>]*>([^<]*)</g)];
assert.ok(counts.length >= 5 + 7, `asset counts rendered: ${counts.length}`);
for (const [, tag, id, text] of counts) {
  if (/^0 assets$/.test(text) || text === "—") continue;
  assert.equal(tag, "button", `${id} (${text}) is clickable`);
}
assert.match(out, /data-testid="compliance-summary-CERT-In-assets"[^>]*>4 assets</);

// readable labels, never a raw finding code
for (const code of ["SSH_DH_SHA1", "WEAK_CIPHER", "NO_PQ_KEX", "QUANTUM_VULNERABLE"]) assert.ok(!out.includes(code), `no raw ${code}`);
assert.ok(out.includes("SHA-1 based SSH key exchange, Weak cipher suites accepted"));

// "How to fix" beside every failing KB clause
const kbClauses = [...out.matchAll(/<li[^>]*data-testid="(compliance-clause-(?:NIST|RBI|CERT-In)-[^"]+)"/g)].map((m) => m[1]);
assert.equal(kbClauses.length, 5);
for (const id of kbClauses) assert.ok(out.includes(`data-testid="${id}-fix"`), `${id} has How to fix`);
assert.ok(out.includes("Offer only ECDHE key exchange with AEAD ciphers"));

// the regulation's text is collapsed: a closed <details> per clause, out of the visible text
const textBlocks = [...out.matchAll(/<details([^>]*)data-testid="compliance-clause-[^"]*-text"/g)];
assert.equal(textBlocks.length, 7);
assert.ok(textBlocks.every((m) => !/\sopen=/.test(m[1])), "collapsed by default");
assert.ok(out.includes(RBI_TEXT), "the text is still there behind Show text");
const visible = visibleText(out);
assert.ok(!visible.includes(RBI_TEXT) && !visible.includes("word59"), "quotes are not in the visible text");
const total = words(out.replace(/<[^>]+>/g, " "));
assert.ok(words(visible) < total / 2, `visible ${words(visible)} words of ${total}`);

// failing frameworks open, the rest closed; no section for a legacy code scan; a note when a run has nothing
assert.match(out, /<details id="compliance-fw-RBI" open=""/);
assert.equal(renderToStaticMarkup(h(ComplianceMappingSection, { frameworks: [], scope: "scan" })), "");
const noted = html([], { note: "No finding of this run maps to a CERT-In, RBI, SEBI CSCRF, NIST or CNSA 2.0 clause." });
assert.match(noted, /data-testid="run-compliance-note"/);

// without a drill-down handler the counts are plain text (nothing clickable that does nothing)
const plain = renderToStaticMarkup(h(ComplianceMappingSection, { frameworks: run, scope: "run" }));
assert.ok(!/<button[^>]*data-testid="compliance-[^"]*-assets"/.test(plain), "no handler, no count buttons");

console.log("complianceSummaryRender.test.ts: ok");

/**
 * #266 / #267 render and wiring checks for the ONE results template (code scans and Sources runs):
 * - the run findings table renders the trimmed default columns, a Columns chooser, an always-visible (sticky right)
 *   Actions column with Details, and rows that open the finding dialog (tab stop, aria-haspopup=dialog);
 * - the code-scan table in CbomResults.tsx has the same row handlers, chooser and sticky actions;
 * - both finding dialogs scroll their body (no Radix ScrollArea with h-full inside a max-height-only flexbox);
 * - "Standards and regulations" shows once in the run dialog: its Standards tab (each clause once, regulator tabs),
 *   no per-code standards in its Issues tab and no remediation Standards tab; every other KbFindingDetails caller (code-scan Standards tab, Sources asset drawer)
 *   keeps one block per finding code, as before (#282 review);
 * - every cell carries data-col and every run row data-type-label: the gate reads rows by attribute, not position.
 * Run (frontend/): npx --yes tsx@4.23.15 components/cbom/results/findingDialogTable.test.ts
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import KbFindingDetails, { StandardsTabs } from "@/components/cbom/KbFindingDetails";
import type { CbomRunAssetItem, CbomRunAssetPage, KbFindingDetail } from "@/utils/backend_api";

import { RunFindingsTable } from "./RunFindingsTable";

const h = React.createElement;
const render = (el: React.ReactElement) => renderToStaticMarkup(h(QueryClientProvider, { client: new QueryClient() }, el));
const text = (html: string) => html.replace(/<[^>]+>/g, "").replace(/&#x27;/g, "'").replace(/&amp;/g, "&").trim();
const count = (hay: string, needle: string) => hay.split(needle).length - 1;
const read = (...p: string[]) => readFileSync(join(__dirname, ...p), "utf8");

// ------------------------------------------------------------------ run findings table (rendered)
const base = {
  cdx_type: "cryptographic-asset", job_id: 3, source_id: 1, source_name: "k8s-prod", name: null, key_size: null,
  finding_codes: ["TLS_RSA_KEX"], facts: {}, asset_key: "k1", status: "not_started", risk_score: 7.5,
};
const items = [
  { ...base, id: 11, type: "tls_endpoint", location: "10.0.0.5:443", target: "web01", algorithm: null, protocol: "TLS 1.2",
    impact: "High", finding: "Accepts RSA key exchange", quantum_vulnerable: true },
  { ...base, id: 12, asset_key: "k2", type: "certificate", location: "/etc/ssl/a.pem", target: null, algorithm: "RSA",
    protocol: null, impact: "Medium", finding: "RSA 2048", quantum_vulnerable: true, q_grade: "Q1", fix_class: "configurable" },
] as unknown as CbomRunAssetItem[];
const page = {
  total: 2, all_total: 2, findings_total: 2, page: 1, page_size: 50, items,
  facets: { type: { tls_endpoint: 1, certificate: 1 }, impact: { High: 1, Medium: 1 }, quantum_vulnerable: 2 }, targets: [],
} as unknown as CbomRunAssetPage;
const noop = () => undefined;
const html = render(h(RunFindingsTable, {
  teamId: 1, runId: 12, active: false, page, isLoading: false, error: null, onRetry: noop,
  filters: { view: "findings", page: 1, page_size: 50 }, onFilters: noop, sources: [{ id: 1, name: "k8s-prod" }],
  waveOf: () => undefined, selection: new Map(), onSelection: noop, onOpenDetails: noop, onSetStatus: noop, statusPending: false,
}));

const headers = [...html.matchAll(/<th\b[^>]*>([\s\S]*?)<\/th>/g)].map((m) => text(m[1]));
// select + the 6 default data columns + Actions (15 columns before, 2,172 px wide at 1366 px)
assert.equal(headers.length, 8, `8 header cells, got ${headers.length}: ${headers.join(" | ")}`);
for (const [i, name] of ["Impact", "Algorithm", "Where", "Quantum", "Risk score", "Status", "Actions"].entries()) {
  assert.ok(headers[i + 1].startsWith(name), `column ${i + 1} is ${name}, got "${headers[i + 1]}"`);
}
assert.ok(!headers.some((x) => /^(Type|Finding|Strength|Source|Wave|Quantum risk|Fix class)\b/.test(x)), "chooser columns hidden");
assert.ok(!html.includes(">Expand<"), "no expand column: the row opens the dialog");
assert.match(html, /data-testid="run-results-columns"/, "Columns chooser");

const rowTag = (id: number) => new RegExp(`<tr\\b[^>]*data-testid="run-asset-${id}"[^>]*>`).exec(html)?.[0] ?? "";
for (const id of [11, 12]) {
  assert.match(rowTag(id), /tabindex="0"/, `row ${id} is a tab stop`);
  assert.match(rowTag(id), /aria-haspopup="dialog"/, `row ${id} opens a dialog`);
  assert.match(html, new RegExp(`data-testid="run-asset-details-${id}"`), `row ${id} keeps its Details button`);
}
const actionCells = [...html.matchAll(/<td\b[^>]*data-testid="run-asset-actions-\d+"[^>]*>/g)].map((m) => m[0]);
assert.equal(actionCells.length, 2, "one actions cell per row");
for (const c of actionCells) assert.match(c, /md:sticky[^"]*md:right-0/, "actions cell pinned right");
// stable column hooks (#282 review): every header and cell names its column, whatever is hidden
const thCols = [...html.matchAll(/<th\b[^>]*data-col="(\w+)"/g)].map((m) => m[1]);
assert.deepEqual(thCols, ["select", "impact", "algorithm", "where", "quantum", "risk", "status", "actions"]);
const tdCount = [...html.matchAll(/<td\b/g)].length;
assert.equal([...html.matchAll(/<td\b[^>]*data-col="\w+"/g)].length, tdCount, "every cell has data-col");
assert.match(rowTag(11), /data-type-label="TLS endpoint"/, "row carries the rendered type label");
assert.match(rowTag(11), /data-impact="High"[^>]*data-location="10\.0\.0\.5:443"|data-location="10\.0\.0\.5:443"[^>]*data-impact="High"/);
assert.match(/<th\b[^>]*>(?:(?!<\/th>)[\s\S])*Actions/.exec(html.slice(html.lastIndexOf("<th", html.indexOf("Actions"))))?.[0] ?? "",
             /md:sticky/, "Actions header pinned right");

// ------------------------------------------------------------------ KB details: one Standards section
const rbi = { framework: "RBI", id: "CSF 2016 Annex 1 §13", text: "Use strong encryption for data in transit.", source: "https://rbi.org.in/x", note: null };
const kb = (code: string, extra: Partial<KbFindingDetail> = {}): KbFindingDetail => ({
  code, title: code, description: "d", attack: "a", impact: "i", category: "c", cwe: [], owasp_2021: [], owasp_2025: [],
  cves: [], standards: ["NIST SP 800-52r2"], compliance: [rbi], remediation: { summary: "s", steps: [] }, verify: [],
  references: [], ...extra,
} as unknown as KbFindingDetail);
const twoCodes = [kb("TLS_RSA_KEX"), kb("TLS_OLD", { standards: ["NIST SP 800-52r2", "CNSA 2.0"] })];
// default (code-scan Standards tab, Sources drawer): unchanged, one block per code with its own clauses
const perCode = render(h(KbFindingDetails, { details: twoCodes }));
assert.equal(count(perCode, "Standards and regulations"), 2, "per-code attribution kept for other callers");
assert.ok(!perCode.includes('data-testid="kb-standards"'));
// run dialog (mergedStandards): one merged block
const kbHtml = render(h(KbFindingDetails, { details: twoCodes, mergedStandards: true }));
assert.equal(count(kbHtml, "Standards and regulations"), 1, "one Standards and regulations section for two codes");
assert.equal(count(kbHtml, rbi.text), 1, "the RBI clause once");
assert.equal(count(kbHtml, "NIST SP 800-52r2"), 1, "each standard once");
assert.ok(kbHtml.includes("CNSA 2.0"), "standards of every code kept");
assert.equal(count(render(h(KbFindingDetails, { details: [kb("X", { standards: [], compliance: [] })], mergedStandards: true })), "Standards and regulations"), 0,
             "no empty section");

// ------------------------------------------------------------------ dialogs (source wiring: portals do not SSR)
const dialog = read("RunFindingDialog.tsx");
const template = read("..", "..", "CbomResults.tsx");
for (const [name, src, testId] of [["run", dialog, "run-finding-scroll"], ["code", template, "cbom-finding-scroll"]] as const) {
  const body = new RegExp(`<div className=\\{FINDING_DIALOG_BODY\\}[^>]*data-testid="${testId}"`);
  assert.match(src, body, `${name} dialog: the body div is the scroll container`);
  assert.ok(!new RegExp(`<ScrollArea[^>]*data-testid="${testId}"`).test(src), `${name} dialog: no ScrollArea (h-full resolved to auto)`);
  assert.match(src, /<DialogContent\s+className=\{`\$\{FINDING_DIALOG_CONTENT\}/, `${name} dialog: shared dialog layout`);
}
assert.match(dialog, /tabIndex=\{0\}/, "run dialog body is focusable for keyboard scrolling");
// the run dialog's KB details are split into tabs (results redesign): the Issues tab's steps carry no standards, the
// Standards tab shows the merged section ONCE (StandardsTabs = mergeStandards), and the remediation panel's Standards
// tab would repeat them
assert.match(dialog, /<RemediationPanel[^>]*standardsTab=\{false\}/, "no second Standards in the run dialog");
assert.match(dialog, /<KbFindingDetails details=\{a\.details\} variant="steps" \/>/, "Issues tab: steps, no per-code standards");
assert.equal(count(dialog, "<StandardsTabs "), 1, "the run dialog renders the merged standards once");
assert.match(dialog, /<StandardsTabs details=\{a\.details\} \/>/);
assert.ok(!dialog.includes("<AssetDetailPanel") && !/mergedStandards/.test(dialog), "no second KB block (AssetDetailPanel / merged cards) in the dialog");
const stepsHtml = render(h(KbFindingDetails, { details: twoCodes, variant: "steps" }));
assert.equal(count(stepsHtml, "Standards and regulations"), 0, "the steps variant has no Standards section of its own");
const tabsHtml = render(h(StandardsTabs, { details: twoCodes }));
assert.equal(count(tabsHtml, "Standards and regulations"), 1, "one Standards and regulations heading for two codes");
assert.equal(count(tabsHtml, rbi.text), 1, "the RBI clause once");
assert.equal(count(tabsHtml, ">NIST SP 800-52r2<"), 1, "each standard once");
assert.ok(tabsHtml.includes("CNSA 2.0"), "standards of every code kept");
assert.equal(count(render(h(StandardsTabs, { details: [kb("X", { standards: [], compliance: [] })] })), "Standards and regulations"), 0, "no empty section");
// every tab is mounted and hidden when inactive (forceMount), so the remediation request, AI answers and Diff survive
for (const t of ["overview", "issues", "quantum", "standards", "fix", "ai"]) {
  assert.match(dialog, new RegExp(`<TabsContent value="${t}" forceMount className="[^"]*data-\\[state=inactive\\]:hidden`), `tab ${t} stays mounted`);
}
const posture = read("..", "sources", "RunPosture.tsx");
assert.match(posture, /mergedStandards = false/, "the Sources drawer keeps per-code blocks");
assert.match(posture, /<KbFindingDetails details=\{a\.details\} mergedStandards=\{mergedStandards\} \/>/);
// code-scan table: every cell names its column
const codeTable = template.slice(template.indexOf("<TableHead data-col=\"select\""), template.indexOf("{/* Top Cryptographic Risks */}"));
for (const id of ["select", "algorithm", "type", "impact", "strength", "quantum", "fixclass", "risk", "location", "status", "actions"]) {
  assert.equal(count(codeTable, `data-col="${id}"`), 2, `code table header and cell for ${id}`);
}
const remediation = read("..", "..", "RemediationPanel.tsx");
assert.match(remediation, /standardsTab = true/, "the code dialog keeps its Standards tab (its only KB details)");
assert.match(remediation, /\{standardsTab && \(\s*<TabsTrigger value="details"/);

// ------------------------------------------------------------------ code-scan table (same template)
assert.match(template, /\{\.\.\.rowOpenProps\(\(\) => setSelectedFinding\(finding\)/, "code rows open the dialog");
assert.match(template, /<ColumnChooser[^>]*testId="cbom-findings-columns"/, "code table Columns chooser");
assert.match(template, /useColumnPrefs\("scan", SCAN_TABLE_COLUMNS\)/);
assert.match(template, /STICKY_ACTIONS/, "code table actions pinned right");

console.log("finding dialog / table render tests passed");

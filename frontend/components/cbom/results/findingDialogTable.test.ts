/**
 * #266 / #267 render and wiring checks for the ONE results template (code scans and Sources runs):
 * - the run findings table renders the trimmed default columns, a Columns chooser, an always-visible (sticky right)
 *   Actions column with Details, and rows that open the finding dialog (tab stop, aria-haspopup=dialog);
 * - the code-scan table in CbomResults.tsx has the same row handlers, chooser and sticky actions;
 * - both finding dialogs scroll their body (no Radix ScrollArea with h-full inside a max-height-only flexbox);
 * - "Standards and regulations" shows once per dialog: once in the KB details (merged across finding codes, each
 *   clause once) and not again as the remediation panel's Standards tab in the run dialog.
 * Run (frontend/): npx --yes tsx@4.23.15 components/cbom/results/findingDialogTable.test.ts
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import KbFindingDetails from "@/components/cbom/KbFindingDetails";
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
assert.match(/<th\b[^>]*>(?:(?!<\/th>)[\s\S])*Actions/.exec(html.slice(html.lastIndexOf("<th", html.indexOf("Actions"))))?.[0] ?? "",
             /md:sticky/, "Actions header pinned right");

// ------------------------------------------------------------------ KB details: one Standards section
const rbi = { framework: "RBI", id: "CSF 2016 Annex 1 §13", text: "Use strong encryption for data in transit.", source: "https://rbi.org.in/x", note: null };
const kb = (code: string, extra: Partial<KbFindingDetail> = {}): KbFindingDetail => ({
  code, title: code, description: "d", attack: "a", impact: "i", category: "c", cwe: [], owasp_2021: [], owasp_2025: [],
  cves: [], standards: ["NIST SP 800-52r2"], compliance: [rbi], remediation: { summary: "s", steps: [] }, verify: [],
  references: [], ...extra,
} as unknown as KbFindingDetail);
const kbHtml = render(h(KbFindingDetails, { details: [kb("TLS_RSA_KEX"), kb("TLS_OLD", { standards: ["NIST SP 800-52r2", "CNSA 2.0"] })] }));
assert.equal(count(kbHtml, "Standards and regulations"), 1, "one Standards and regulations section for two codes");
assert.equal(count(kbHtml, rbi.text), 1, "the RBI clause once");
assert.equal(count(kbHtml, "NIST SP 800-52r2"), 1, "each standard once");
assert.ok(kbHtml.includes("CNSA 2.0"), "standards of every code kept");
assert.equal(count(render(h(KbFindingDetails, { details: [kb("X", { standards: [], compliance: [] })] })), "Standards and regulations"), 0,
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
// the run dialog's KB details come from AssetDetailPanel; the remediation panel's Standards tab would repeat them
assert.match(dialog, /<RemediationPanel[^>]*standardsTab=\{false\}/, "no second Standards in the run dialog");
const remediation = read("..", "..", "RemediationPanel.tsx");
assert.match(remediation, /standardsTab = true/, "the code dialog keeps its Standards tab (its only KB details)");
assert.match(remediation, /\{standardsTab && \(\s*<TabsTrigger value="details"/);

// ------------------------------------------------------------------ code-scan table (same template)
assert.match(template, /\{\.\.\.rowOpenProps\(\(\) => setSelectedFinding\(finding\)/, "code rows open the dialog");
assert.match(template, /<ColumnChooser[^>]*testId="cbom-findings-columns"/, "code table Columns chooser");
assert.match(template, /useColumnPrefs\("scan", SCAN_TABLE_COLUMNS\)/);
assert.match(template, /STICKY_ACTIONS/, "code table actions pinned right");

console.log("finding dialog / table render tests passed");

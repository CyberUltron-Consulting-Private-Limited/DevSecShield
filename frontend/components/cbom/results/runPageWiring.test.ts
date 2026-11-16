/**
 * CB-38 wiring of the Sources run results page: the AI assistant (PR-6) sits in the finding dialog as on the code
 * page; the Review & Run run dialog is gone (its Results button opens this page). When the Ticketing tab (PR-4) and
 * the run deliverables (PR-8) are on dev, they are mounted here too and checked below. Source checks, like
 * pageWiring.test.ts.
 * Run: npx --yes tsx components/cbom/results/runPageWiring.test.ts
 */
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { RUN_CAPABILITIES, RUN_TICKETING_TAB_AVAILABLE, verifyResultText } from "./model";

const read = (...p: string[]) => readFileSync(join(__dirname, ...p), "utf8");
const dialog = read("RunFindingDialog.tsx");
const review = read("..", "sources", "ReviewRunTab.tsx");

// S14 / results redesign: the AI assistant is an addition to the knowledge-base explanation (Issues tab: KB fix and
// verify commands), for THIS run asset: its panel (opened from the AI tab) is keyed by the asset and its subject is
// the dialog's current asset
const kb = dialog.indexOf('<KbFindingDetails details={a.details} variant="steps" />');
const ai = dialog.indexOf('<AiRemediationPanel key={`ai-${assetId}`} teamId={teamId} subject={{ kind: "run_asset", assetId }} />');
assert.ok(kb > 0 && ai > kb, "AI panel mounted after the KB details (KB fix and verify commands)");
assert.match(dialog, /const assetId = subject \? subject\.assetId : null;/, "the AI subject is the dialog's current asset");
assert.match(dialog, /<aside id="run-finding-ai-sheet" hidden=\{!aiOpen\}/, "the AI panel is inside the dialog and stays mounted while closed");
assert.match(dialog, /aria-controls="run-finding-ai-sheet"/, "Open AI assistant controls the panel");
assert.ok(dialog.indexOf("<CollectedFacts item={item} />", ai) > ai, "the AI panel lists the collected facts it is given");
assert.match(dialog, /import AiRemediationPanel from "\.\/AiRemediationPanel";/);
assert.equal(RUN_CAPABILITIES.ai, true);

// the Review & Run run dialog is removed (the Results button links to the page)
assert.ok(!review.includes("RunDetailsDialog"), "no RunDetailsDialog left");
assert.match(review, /href=\{runResultsHref\(teamId, run\.id\)\}/);

// ONE template (owner decision): the run route renders components/CbomResults.tsx with the run adapter
const route = read("RunResultsRoute.tsx");
assert.match(route, /import CbomResults from "@\/components\/CbomResults";/);
assert.match(route, /const source = useSourcesRunSource\(teamId, runId, \{ initialView: view, onViewChange \}\);/);
assert.match(route, /<CbomResults data=\{undefined\} teamId=\{String\(teamId\)\} source=\{source\} \/>/);
assert.ok(!existsSync(join(__dirname, "RunResultsView.tsx")) && !existsSync(join(__dirname, "RunHeader.tsx")), "no second results page");

// S2: the code page's Results / Ticketing integrations tabs; on a run the Ticketing tab is RunTicketingTab (PR-4)
const template = read("..", "..", "CbomResults.tsx");
assert.match(template, /const hasTicketingTab = run \? RUN_TICKETING_TAB_AVAILABLE : showTabs && onIntegrationSettingsUpdated != null;/);
assert.match(template, /activeTab === "ticketing" && hasTicketingTab && run \? \(\n\s*<RunTicketingTab teamId=\{run\.teamId\} runId=\{run\.runId\} \/>/);
// the run sections sit in the template's Results tab, in the code page's order
const order = ["<RunMetaCards", "<RunPostureCard", "<CbomCryptoCharts", "<RunInsights", "<RunCertificatesSection", "<RunChangesSection",
  "<RunWavesSection", "<RbiCsfRollup", "<CertInLanePosture", "<ComplianceMappingSection", "<RunDashboardSection", "<RunFindingsTable", "<RunTopRisks"];
const at = order.map((tag) => template.indexOf(tag));
assert.ok(at.every((i, n) => i > 0 && (n === 0 || i > at[n - 1])), `sections in order: ${JSON.stringify(order.map((t, n) => [t, at[n]]))}`);
assert.ok(template.indexOf('activeTab === "ticketing" && hasTicketingTab && run') < at[0], "after the tabs");

// header: the code page's download row for a run: CycloneDX JSON / XML / OSCAL, then VEX / Signature / Evidence pack /
// PDF Report (RunDeliverablesMenu, PR-8) and a signature check
const sections = read("RunSections.tsx");
const hdr = sections.slice(sections.indexOf("export function RunHeaderActions"), sections.indexOf("export function RunVerifyButton"));
const order2 = ['id: "run-results-download"', 'id: "run-results-download-xml"', 'id: "run-results-download-oscal"', "<RunDeliverablesMenu teamId={teamId} runId={run.id} active={active} />",
  "<RunVerifyButton teamId={teamId} runId={run.id} />", 'data-testid="run-results-compare"', 'data-testid="run-results-open-sources"'];
const pos = order2.map((s) => hdr.indexOf(s));
assert.ok(pos.every((p, n) => p > 0 && (n === 0 || p > pos[n - 1])), `header buttons in the code page's order: ${JSON.stringify(pos)}`);
assert.match(sections, /verifyCbomRunSignature\(teamId, runId, file\)/);

// One toolbar. A Sources run is /{team}/cbom/{id}/results?run=1, so the route param is still scan_id and
// `team_id && scan_id != null` is true. The code-scan download row is the else of the run row, not a sibling
// (that painted CycloneDX JSON / XML / OSCAL / VEX / Signature / Evidence pack / PDF Report twice).
const headerStart = template.indexOf('data-testid="cbom-results-title"');
const headerEnd = template.indexOf("{importReport && importReportHasNews");
assert.ok(headerStart > 0 && headerEnd > headerStart, "results header is bounded");
const header = template.slice(headerStart, headerEnd);
assert.match(header, /\{run && run\.run \? \(/);
assert.match(header, /\) : team_id && scan_id != null \? \(/);
assert.ok(header.includes("<RunHeaderActions"), "a Sources run keeps RunHeaderActions");
assert.ok(header.includes('data-testid="cbom-scan-header-actions"'), "a code scan keeps its download row");
assert.ok(header.includes("Scan settings"), "a code scan keeps Scan settings");
assert.equal((header.match(/CycloneDX JSON/g) ?? []).length, 1, "the scan row's CycloneDX JSON label is not copied");
assert.ok(!header.includes("Open in CBOM Sources"), "Open in CBOM Sources stays on RunHeaderActions");
assert.ok(!/\{run && run\.run && \(\s*<RunHeaderActions/.test(header), "the run row is not a sibling of the scan row");
assert.ok(!/\{team_id && scan_id != null && \(/.test(header), "the scan row is not an independent sibling");

// /parity (W2b): a run's scan_metadata (compliance readiness, RBI / CERT-In roll-ups, graph, coverage banner) is read by
// the template exactly where a code scan's is
assert.match(template, /const scanMetadata = run \? run\.parity\?\.scan_metadata \?\? null : scanMetadataProp;/);
const adapter = read("source.ts");
assert.match(adapter, /queryFn: \(\) => getCbomRunParity\(teamId, runId\)/);

// finding dialog: the code page's "Remediation, fix code and exploit demo" panel in run mode (PARITY.md S15), between the
// KB details and the AI panel; the panel's existing props are unchanged (run mode is one optional prop)
const rd = read("RunFindingDialog.tsx");
const remAt = rd.indexOf("<RemediationPanel key={`rem-${assetId}`} teamId={String(teamId)} scanType=\"cbom\" scanId={0} findingId={String(assetId)}");
assert.ok(remAt > rd.indexOf("<KbFindingDetails") && remAt < rd.indexOf("<AiRemediationPanel"), "RemediationPanel (Fix & demo tab) between the KB details and the AI panel");
assert.match(rd, /runAsset=\{\{ runId, assetId \}\}/);
assert.match(rd, /layout="cards"/, "Fix & demo: status cards");
assert.match(rd, /missingNote=\{<p [^>]*data-testid="run-finding-fix-missing">/, "older backend: a one-line note instead of an empty tab");
const panel = read("..", "..", "RemediationPanel.tsx");
assert.match(panel, /runAsset\?: \{ runId: number; assetId: number \} \| null;/);
assert.match(panel, /\? getCbomRunAssetRemediation\(parseInt\(teamId, 10\), runAsset\.runId, runAsset\.assetId\)\n\s*: generateFindingRemediation\(/);
assert.match(panel, /if \(runAsset && load\.isError && remediationRouteMissing\(load\.error\) && !data\) return <>\{missingNote \?\? null\}<\/>;/, "older backend: hidden (or the caller's one-line note)");
for (const prop of ["teamId: string;", "scanType:", "scanId: number;", "findingId: string;", "existingRemediation?:", "onRemediationGenerated?:", "snippetStart?:", "line?:"]) {
  assert.ok(panel.includes(prop), `RemediationPanel keeps ${prop}`);
}

// Changes: the code page's DiffView over /runs/{id}/diff, then the run's drift events (/changes)
assert.match(sections, /export function RunDiffBlock[\s\S]*getCbomRunDiff\(teamId, runId\)[\s\S]*<DiffView diff=\{q\.data\} \/>/);
assert.match(sections, /<RunDiffBlock teamId=\{teamId\} runId=\{run\.id\} \/>\n\s*<RunChanges/);

// the dialog's chips come from findingChips (item fields, else the same fields of GET /assets/{id}, else its KB entries)
assert.match(rd, /const chips = findingChips\(item, detailQ\.data\?\.details, detailQ\.data\);/);
// /parity notes: graph / compliance readiness under the charts, RBI CSF and CERT-In next to their roll-ups
assert.match(template, /const runParityNotes = run \? parityNotes\(run\.parityState, run\.parity\) : null;/);
for (const id of ["run-graph-note", "run-compliance-readiness-note", "run-rbi-note", "run-certin-note"]) assert.ok(template.includes(`testId="${id}"`), id);
assert.ok(!template.includes("chartsCodeOnly"), "no 'shown on code scans only' note: under PARITY a run has the graph and compliance");

// the Ticketing tab is on exactly when lane W6's component is in the tree
assert.equal(RUN_TICKETING_TAB_AVAILABLE, existsSync(join(__dirname, "RunTicketingTab.tsx")), "Ticketing tab <=> RunTicketingTab.tsx");

assert.equal(verifyResultText({ valid: true, signature_match: true, digest_match: true }), "Verified: this file is the run's signed CycloneDX JSON, unchanged.");
assert.match(verifyResultText({ valid: false, signature_match: true, digest_match: false }), /differs from the run's CycloneDX JSON/);
assert.match(verifyResultText({ valid: false, signature_match: false, digest_match: true }), /signature does not match/);

console.log("run page wiring tests passed");

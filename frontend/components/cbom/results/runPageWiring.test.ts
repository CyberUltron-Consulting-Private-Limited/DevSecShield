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
// results redesign: on a run the hero header, then the tabs, then Ticketing, or the summary, or one detail view (?section=)
assert.match(template, /<ResultsHero [^]*?\{hasTicketingTab && tabBar\}\n\s*\{activeTab === "ticketing" && hasTicketingTab \? \(\n\s*<RunTicketingTab teamId=\{run\.teamId\} runId=\{run\.runId\} \/>\n\s*\) : section === "" \? \(\n\s*<SummaryView ctx=\{viewCtx\} \/>\n\s*\) : \(\n\s*detailView\(section, viewCtx\)/);
assert.match(template, /const section: ResultsSection = run \? resultsUrl\.section : "";/, "the section is read from the URL every render; ignored on a code scan");
// the run sections sit in the views, each component in exactly one view (the findings table: the summary and, under the
// waves whose copy says "Select findings in the table below", the remediation view); none in the template itself
const viewSrc = (f: string) => read("views", f);
const VIEWS: Record<string, string> = {
  summary: viewSrc("SummaryView.tsx"), collection: viewSrc("CollectionView.tsx"), quantum: viewSrc("QuantumView.tsx"),
  inventory: viewSrc("InventoryView.tsx"), migration: viewSrc("MigrationView.tsx"), compliance: viewSrc("ComplianceView.tsx"),
  remediation: viewSrc("RemediationView.tsx"),
};
const MOUNTED_IN: Record<string, string[]> = {
  "<RunStatusBanner": ["summary"], "<SummaryKpis": ["summary"], "<RunMetaCards": ["summary"], "<PostureSummary": ["summary"],
  "<ExplainPanel": ["summary"], "<TopRisksSummary": ["summary"], "<DrillTiles": ["summary"],
  "<RunCoverageSection": ["collection"], "<QDistributionCard": ["quantum"], "<AgilityPostureCard": ["quantum"],
  "<RunDashboardSection": ["inventory"], "<CertificatesCard": ["inventory"], "<RunInsights": ["inventory"],
  "<RunJobsStatusLine": [], // in RunStatusBanner (summary), never beside the Collection view's targets list
  "<RbiCsfRollup": ["compliance"], "<CertInLanePosture": ["compliance"], "<ComplianceMappingSection": ["compliance"],
  "<RunWavesSection": ["remediation"], "<RunChangesSection": ["remediation"],
  "<RunFindingsTableMount": ["summary", "remediation"], "<CbomCryptoCharts": ["inventory", "migration", "compliance"],
};
for (const [tag, want] of Object.entries(MOUNTED_IN)) {
  const got = Object.entries(VIEWS).filter(([, src]) => src.includes(`${tag} `) || src.includes(`${tag}\n`)).map(([v]) => v);
  assert.deepEqual(got, want, `${tag} is mounted in ${want.join(", ")}`);
}
for (const tag of ["<RunMetaCards", "<RunPostureCard", "<PostureSummary", "<RunInsights", "<RunCertificatesSection", "<RunChangesSection",
  "<RunWavesSection", "<RunDashboardSection", "<RunFindingsTable", "<RunTopRisks", "<ReadinessExplainer", "<RunCoverageSection"]) {
  assert.ok(!template.includes(tag), `${tag} is a view's, not the template's`);
}
// the CbomCryptoCharts cards are split between the three views without overlap, and every card is somewhere (the
// certificate expiry list is CertificatesCard's, in the inventory view)
const PARTS = ["algorithms", "weak", "readiness", "qv", "roadmap", "assetTypes", "certExpiry", "protocols", "graph", "compliance"];
const partsOf = (src: string, name: string) => JSON.parse((src.match(new RegExp(`export const ${name} = (\\[[^\\]]*\\])`)) ?? [])[1] ?? "null") as string[];
const split = [partsOf(VIEWS.inventory, "INVENTORY_CHART_PARTS"), partsOf(VIEWS.migration, "MIGRATION_CHART_PARTS"), partsOf(VIEWS.compliance, "COMPLIANCE_CHART_PARTS")];
assert.deepEqual([...split.flat(), "certExpiry"].sort(), [...PARTS].sort(), "each chart card in exactly one view");
assert.ok(read("views", "CertificatesCard.tsx").includes("<CbomCertificateExpiry"), "the expiry list is in the certificates card");
assert.ok(read("views", "RunStatusBanner.tsx").includes("<RunJobsStatusLine targets={targets} onOpen={onOpenCollection} />"), "the jobs line on the summary");
// the run's views ask the shared components for their run layout (B2)
for (const [v, tags] of Object.entries({ quantum: ["<QDistributionCard", "<AgilityPostureCard"], inventory: ["<CbomCryptoCharts", "<RunDashboardSection"],
  migration: ["<CbomCryptoCharts"], compliance: ["<CbomCryptoCharts"] })) {
  for (const tag of tags) {
    const at = VIEWS[v].indexOf(tag);
    assert.ok(/variant="run"/.test(VIEWS[v].slice(at, VIEWS[v].indexOf("/>", at))), `${v}: ${tag} variant="run"`);
  }
}
// B3: the finding dialog navigates the findings table and is opened from it through useDialogNav
assert.match(template, /const \{ nav: dialogNav, openFromTable \} = useDialogNav\(\{/);
assert.match(template, /pageItems=\{run\.page\?\.items\} nav=\{dialogNav\} onSetStatus=\{run\.setStatus\}/);
for (const v of ["summary", "remediation"]) assert.ok(VIEWS[v].includes("<RunFindingsTableMount run={run} onOpenDetails={ctx.openFromTable} />"), v);
assert.match(template, /<InfoTipDrawerProvider view=\{`run\.\$\{section \|\| "summary"\}`\}>/);
assert.ok(read("views", "ResultsHero.tsx").includes("<ExplanationsButton"), "the Explanations button in the hero");
assert.deepEqual(partsOf(VIEWS.inventory, "INVENTORY_DASHBOARD_PARTS").sort(),
  ["progress", "owasp", "risk", "controls", "algoTypes", "strength", "quantum", "riskScores", "metrics"].sort(), "the dashboard's KPI tiles are the summary's");
// each view's component is mounted by the template's switch, once
for (const v of ["CollectionView", "QuantumView", "InventoryView", "MigrationView", "ComplianceView", "RemediationView"]) {
  assert.equal(template.split(`<${v} ctx={ctx} />`).length - 1, 1, v);
}
// the dialogs are mounted outside the section switch (after it), so a view change never unmounts them
const switchEnd = template.indexOf("detailView(section, viewCtx)");
assert.ok(template.indexOf("<RunFindingDialog") > switchEnd && template.indexOf("<CompareDialog") > switchEnd, "dialogs outside the switch");

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
// `team_id && scan_id != null` is true. A run renders ResultsHero (RunHeaderActions) and the code-scan header is the
// else of that branch, not a sibling (a sibling painted CycloneDX JSON / XML / OSCAL / VEX / Signature / Evidence pack /
// PDF Report twice).
const hero = read("views", "ResultsHero.tsx");
assert.ok(hero.includes("<RunHeaderActions teamId={teamId} run={run}"), "a Sources run keeps RunHeaderActions (in its hero)");
assert.ok(hero.includes("<RunHeaderMeta teamId={teamId} run={run} sources={sources} />"), "and its status line");
assert.match(template, /\{run && run\.run && viewCtx \? \([^]*?<InfoTipDrawerProvider [^]*?<ResultsHero [^]*?\n\s*\) : \(\n\s*<>\n\s*\{\/\* Header: the export buttons/,
             "the code header is the else of the run branch");
const headerStart = template.indexOf('data-testid="cbom-results-title"');
const headerEnd = template.indexOf("<ImportNotesCard report={importReport} />");
assert.ok(headerStart > template.indexOf("<ResultsHero") && headerEnd > headerStart, "results header is bounded");
const header = template.slice(headerStart, headerEnd);
assert.match(header, /\{team_id && scan_id != null \? \(/);
assert.ok(!header.includes("<RunHeaderActions"), "the run row is not in the code header");
assert.ok(header.includes('data-testid="cbom-scan-header-actions"'), "a code scan keeps its download row");
assert.ok(header.includes("Scan settings"), "a code scan keeps Scan settings");
assert.equal((header.match(/CycloneDX JSON/g) ?? []).length, 1, "the scan row's CycloneDX JSON label is not copied");
assert.ok(!header.includes("Open in CBOM Sources"), "Open in CBOM Sources stays on RunHeaderActions");
assert.ok(!/\{team_id && scan_id != null && \(/.test(header), "the scan row is not an independent sibling");
assert.equal((template.match(/<ResultsHero /g) ?? []).length, 1, "one run header, on every view (outside the section switch)");
assert.ok(template.indexOf("<ResultsHero") < template.indexOf('section === "" ? ('), "the hero is above the switch");

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
// (results redesign: the graph note in the Inventory view, the others in the Compliance view, from the template's notes)
assert.match(template, /parityNotes: runParityNotes,/);
assert.ok(VIEWS.inventory.includes('testId="run-graph-note"'), "run-graph-note");
for (const id of ["run-compliance-readiness-note", "run-rbi-note", "run-certin-note"]) assert.ok(VIEWS.compliance.includes(`testId="${id}"`), id);
for (const src of [template, ...Object.values(VIEWS)]) {
  assert.ok(!src.includes("chartsCodeOnly"), "no 'shown on code scans only' note: under PARITY a run has the graph and compliance");
}

// the Ticketing tab is on exactly when lane W6's component is in the tree
assert.equal(RUN_TICKETING_TAB_AVAILABLE, existsSync(join(__dirname, "RunTicketingTab.tsx")), "Ticketing tab <=> RunTicketingTab.tsx");

assert.equal(verifyResultText({ valid: true, signature_match: true, digest_match: true }), "Verified: this file is the run's signed CycloneDX JSON, unchanged.");
assert.match(verifyResultText({ valid: false, signature_match: true, digest_match: false }), /differs from the run's CycloneDX JSON/);
assert.match(verifyResultText({ valid: false, signature_match: false, digest_match: true }), /signature does not match/);

console.log("run page wiring tests passed");

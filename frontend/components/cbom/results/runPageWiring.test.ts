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

// S14: the AI assistant under the knowledge-base explanation, for this run asset
const kb = dialog.indexOf("<AssetDetailPanel");
const ai = dialog.indexOf('<AiRemediationPanel teamId={teamId} subject={{ kind: "run_asset", assetId }} />');
assert.ok(kb > 0 && ai > kb, "AI panel mounted below AssetDetailPanel (KB fix and verify commands)");
assert.match(dialog, /import AiRemediationPanel from "\.\/AiRemediationPanel";/);
assert.equal(RUN_CAPABILITIES.ai, true);

// the Review & Run run dialog is removed (the Results button links to the page)
assert.ok(!review.includes("RunDetailsDialog"), "no RunDetailsDialog left");
assert.match(review, /href=\{runResultsHref\(teamId, run\.id\)\}/);

// ONE template (owner decision): the run route renders components/CbomResults.tsx with the run adapter
const route = read("..", "..", "..", "app", "[team_id]", "cbom", "runs", "[run_id]", "results", "page.tsx");
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
  "<RunWavesSection", "<RbiCsfRollup", "<CertInLanePosture", "<RunComplianceSection", "<RunDashboardSection", "<RunFindingsTable", "<RunTopRisks"];
const at = order.map((tag) => template.indexOf(tag));
assert.ok(at.every((i, n) => i > 0 && (n === 0 || i > at[n - 1])), `sections in order: ${JSON.stringify(order.map((t, n) => [t, at[n]]))}`);
assert.ok(template.indexOf('activeTab === "ticketing" && hasTicketingTab && run') < at[0], "after the tabs");

// header: the code page's download row for a run: CycloneDX JSON / XML / OSCAL, then VEX / Signature / Evidence pack /
// PDF Report (RunDeliverablesMenu, PR-8) and a signature check
const sections = read("RunSections.tsx");
const hdr = sections.slice(sections.indexOf("export function RunHeaderActions"), sections.indexOf("export function RunVerifyButton"));
const order2 = ['id: "run-results-download"', 'id: "run-results-download-xml"', 'id: "run-results-download-oscal"', "<RunDeliverablesMenu teamId={teamId} runId={run.id} active={active} />",
  "<RunVerifyButton teamId={teamId} runId={run.id} />", 'data-testid="run-results-open-sources"'];
const pos = order2.map((s) => hdr.indexOf(s));
assert.ok(pos.every((p, n) => p > 0 && (n === 0 || p > pos[n - 1])), `header buttons in the code page's order: ${JSON.stringify(pos)}`);
assert.match(sections, /verifyCbomRunSignature\(teamId, runId, file\)/);

// /parity (W2b): a run's scan_metadata (compliance readiness, RBI / CERT-In roll-ups, graph, coverage banner) is read by
// the template exactly where a code scan's is
assert.match(template, /const scanMetadata = run \? run\.parity\?\.scan_metadata \?\? null : scanMetadataProp;/);
const adapter = read("source.ts");
assert.match(adapter, /queryFn: \(\) => getCbomRunParity\(teamId, runId\)/);

// the Ticketing tab is on exactly when lane W6's component is in the tree
assert.equal(RUN_TICKETING_TAB_AVAILABLE, existsSync(join(__dirname, "RunTicketingTab.tsx")), "Ticketing tab <=> RunTicketingTab.tsx");

assert.equal(verifyResultText({ valid: true, signature_match: true, digest_match: true }), "Verified: this file is the run's signed CycloneDX JSON, unchanged.");
assert.match(verifyResultText({ valid: false, signature_match: true, digest_match: false }), /differs from the run's CycloneDX JSON/);
assert.match(verifyResultText({ valid: false, signature_match: false, digest_match: true }), /signature does not match/);

console.log("run page wiring tests passed");

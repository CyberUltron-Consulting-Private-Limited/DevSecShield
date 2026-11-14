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

import { RUN_CAPABILITIES, RUN_TICKETING_TAB_AVAILABLE } from "./model";

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

// S2: Results / Ticketing tabs; the Ticketing tab is RunTicketingTab for this run (PR-4)
const view = read("RunResultsView.tsx");
assert.match(view, /import RunTicketingTab from "\.\/RunTicketingTab";/);
assert.match(view, /<RunTicketingTab teamId=\{teamId\} runId=\{runId\} \/>/);
assert.match(view, /\["results", "Results", BarChart3\], \["ticketing", "Ticketing", Ticket\]/);
assert.match(view, /data-testid=\{`run-results-tab-\$\{key\}`\}/);
// the results sections render only on the Results tab: the metadata cards and the findings table sit in its branch
const ticketingBranch = view.indexOf('tab === "ticketing" && RUN_TICKETING_TAB_AVAILABLE ?');
assert.ok(ticketingBranch > 0 && view.indexOf("<RunMetaCards", ticketingBranch) > ticketingBranch && view.indexOf("<RunFindingsTable", ticketingBranch) > ticketingBranch);

// the Ticketing tab is on exactly when lane W6's component is in the tree
assert.equal(RUN_TICKETING_TAB_AVAILABLE, existsSync(join(__dirname, "RunTicketingTab.tsx")), "Ticketing tab <=> RunTicketingTab.tsx");

console.log("run page wiring tests passed");

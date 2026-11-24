// Run: npx tsx --test components/cbom/sources/runLifecycleQa2.test.ts
// Staging QA round 2, lane one minors in the UI: the Review & Run "Runs" table names what started each run (item 11),
// the run header never shows "Queued" and "Running" together (item 13), and a label the collector now spells
// differently reads "old → new" in the compare dialog (item 09).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { runTriggerLabel } from "../results/resultRows";

const read = (rel: string) => readFileSync(join(__dirname, rel), "utf8");

// item 11: a Trigger column, one cell per run, from the same label the run page prints
const review = read("ReviewRunTab.tsx");
// under the run number, not a column of its own: the table fits its card at 1366 px (review of #497, m2)
assert.ok(!review.includes("<TableHead>Trigger"), "no column of its own");
assert.ok(review.includes("data-testid={`review-run-trigger-${run.id}`}"), "a line per run");
assert.ok(review.indexOf("review-run-trigger-") < review.indexOf("formatDateTime(run.created_at)"), "under the number");
assert.ok(review.includes('{runTriggerLabel(run) ?? "—"}'), "the run page's own label");
assert.equal(runTriggerLabel({ trigger: "scheduled", schedule_id: 2, schedule_name: "qa2-q1-daily-drift-db-net" }),
  "Scheduled: qa2-q1-daily-drift-db-net");
assert.equal(runTriggerLabel({ trigger: "manual" }), "Manual");
assert.equal(runTriggerLabel({ trigger: "scheduled", schedule_id: 9, schedule_name: null }), "Scheduled (schedule #9, deleted)");
const tips = read("../../../content/infotips/text/cbsrc-run.ts");
assert.ok(tips.includes("and under it what started the run"), "the run column's tip says so");

// item 13: the badge is the one state word; no "Running" text beside a "Queued" badge
const header = read("../results/RunSections.tsx");
const meta = header.slice(header.indexOf("export function RunHeaderMeta"), header.indexOf("run-results-credits"));
assert.ok(!meta.includes("<span>Running</span>"), "no second state word");
assert.ok(meta.includes("<RunStatusBadge status={run.status}"), "the badge stays");

// item 09: the collector change shows both spellings
const changes = read("ChangesPanel.tsx");
assert.ok(changes.includes("x.label_before ? `${x.label_before} → ${x.label}` : x.label"), "old → new label");
console.log("run lifecycle QA2 tests passed");

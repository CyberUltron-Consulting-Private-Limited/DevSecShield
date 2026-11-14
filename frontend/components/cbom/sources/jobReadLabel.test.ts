// Run: npx --yes tsx components/cbom/sources/jobReadLabel.test.ts
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { jobReadLabel, jobTargetsLine, type JobReadInput } from "./jobReadLabel";

const job = (over: Partial<JobReadInput>): JobReadInput => ({
  status: "success", outcome: "ok", asset_count: 0, counts: null, targets: [], ...over,
});

// C4: the Azure source of the report: one subscription, 11 assets read, 2 vaults whose keys were refused
{
  const azure = job({
    outcome: "partial", asset_count: 17, assets_read: 11, gaps: 2,
    counts: { total: 1, ok: 0, partial: 1, failed: 0, skipped: 0 },
    targets: [{ status: "partial" }],
  });
  assert.deepEqual(jobReadLabel(azure), ["amber", "Partly read · 11 read, 2 gaps"]);
  assert.equal(jobTargetsLine(azure), "Targets: 0 fully read · 1 partly read · 0 failed · 0 skipped of 1");
}

// a job stored before the fix (outcome "failed" from the target counts) that read assets is never "Nothing read"
{
  const old = job({
    outcome: "failed", asset_count: 17, assets_read: 11, gaps: 2,
    counts: { total: 1, ok: 0, failed: 1, skipped: 0 }, targets: [{ status: "error" }],
  });
  const [tone, label] = jobReadLabel(old);
  assert.equal(tone, "amber");
  assert.equal(label, "Partly read · 11 read, 2 gaps");
  assert.ok(!label.includes("Nothing read") && !label.includes("0 read"));
}

// nothing read: says the gaps, never "0 read"
assert.deepEqual(jobReadLabel(job({ outcome: "failed", assets_read: 0, gaps: 1, targets: [{ status: "error" }] })),
  ["red", "Nothing read · 1 gap"]);
assert.deepEqual(jobReadLabel(job({ outcome: "failed", targets: [{ status: "error" }] })), ["red", "Nothing read"]);

// all read
assert.deepEqual(jobReadLabel(job({ outcome: "ok", assets_read: 40, gaps: 0, targets: [{ status: "ok" }] })),
  ["green", "All targets read · 40 read"]);
assert.deepEqual(jobReadLabel(job({ outcome: "ok", assets_read: 3, gaps: 0, targets: [{ status: "timeout" }] })),
  ["amber", "Read, with errors · 3 read"]);
// older API without the counts: the outcome alone, as before
assert.deepEqual(jobReadLabel(job({ outcome: "partial" })), ["amber", "Partly read"]);
assert.deepEqual(jobReadLabel(job({ outcome: "ok" })), ["green", "All targets read"]);
// still running
assert.deepEqual(jobReadLabel(job({ outcome: null, status: "pending" })), ["blue", "Waiting"]);
assert.deepEqual(jobReadLabel(job({ outcome: null, status: "claimed" })), ["blue", "Running"]);
assert.equal(jobTargetsLine(job({ counts: null })), null);

// RunResults takes its badge from this helper (no second copy of the outcome labels)
{
  const src = readFileSync(join(__dirname, "RunResults.tsx"), "utf8");
  assert.ok(src.includes("jobReadLabel(job)") && src.includes("jobTargetsLine(job)"));
  assert.ok(!src.includes('failed: ["red", "Nothing read"]'));
}

console.log("jobReadLabel: ok");

/**
 * Hermetic tests for where a CBOM result came from (CBOM landing page, M1x).
 * Run: npx --yes tsx components/cbom/resultOrigin.test.ts
 */
import assert from "node:assert/strict";
import { groupSourcesRuns, hasCbomResults, originLabel, sourcesRunsHref, type CbomSourcesRun } from "./resultOrigin";

// X1 (team 13, run #8): two sources of one run, no code scan
const x1: CbomSourcesRun[] = [
  { run_id: 8, job_id: 51, source_name: "range-172.17.0.4-32", source_kind: "network_range",
    finished_at: "2026-11-11T04:50:39Z", asset_count: 2, endpoints_probed: 1 },
  { run_id: 8, job_id: 50, source_name: "x1-ssh-lab", source_kind: "linux_servers",
    finished_at: "2026-11-11T04:50:39Z", asset_count: 7, endpoints_probed: 0 },
];

// the Table tab is not "No scans yet" when only a Sources run exists
assert.equal(hasCbomResults([], x1), true);
assert.equal(hasCbomResults([], []), false);
assert.equal(hasCbomResults(undefined, undefined), false);
assert.equal(hasCbomResults([{ id: 74 }], []), true);

// one row per run: both sources, 9 assets, one endpoint probed
assert.deepEqual(groupSourcesRuns(x1), [
  { run_id: 8, sources: ["range-172.17.0.4-32", "x1-ssh-lab"], finished_at: "2026-11-11T04:50:39Z", asset_count: 9,
    endpoints_probed: 1 },
]);
// newest run first; a source collected in an older run stays on that run's row
const two = groupSourcesRuns([
  ...x1.slice(0, 1),
  { run_id: 9, job_id: 60, source_name: "x1-ssh-lab", source_kind: "linux_servers",
    finished_at: "2026-11-11T06:00:00Z", asset_count: 6, endpoints_probed: 0 },
]);
assert.deepEqual(two.map((g) => [g.run_id, g.sources]), [[9, ["x1-ssh-lab"]], [8, ["range-172.17.0.4-32"]]]);
assert.deepEqual(groupSourcesRuns(null), []);

// every row says where it came from
assert.equal(originLabel({ kind: "sources_run", run_id: 8, source_name: "range-172.17.0.4-32" }),
  "Sources run #8: range-172.17.0.4-32");
assert.equal(originLabel({ kind: "sources_run", run_id: 8 }), "Sources run #8: source");
assert.equal(originLabel({ kind: "code_scan", scan_id: 74, scan_title: "x1 cbom code" }), "Code scan: x1 cbom code");
assert.equal(originLabel(undefined), "Code scan");  // a response from before the field existed
assert.equal(sourcesRunsHref("13"), "/13/cbom/sources?tab=review");

console.log("resultOrigin: all assertions passed");

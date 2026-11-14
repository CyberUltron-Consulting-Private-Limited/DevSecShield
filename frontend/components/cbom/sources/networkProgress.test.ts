/**
 * A running network range shows "N of M addresses" on the Network tab (discovery rows) and in Review & Run (the run's
 * job table) (round 5 customer testing: only a growing asset count, and "Running on the scan node" until the end).
 * Older scan nodes report nothing: those rows show what they showed before.
 * Run: npx --yes tsx components/cbom/sources/networkProgress.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

import { addressProgress } from "./logic"

assert.equal(addressProgress({ status: "claimed", progress: { done: 120, total: 254 } }), "120 of 254 addresses")
assert.equal(addressProgress({ status: "claimed", progress: { done: 0, total: 1 } }), "0 of 1 address")
assert.equal(addressProgress({ status: "claimed", progress: { done: 70000, total: 65536 } }), `${(65536).toLocaleString()} of ${(65536).toLocaleString()} addresses`)
// an older node (no field / null), a job not running, or nonsense: nothing extra is shown
assert.equal(addressProgress({ status: "claimed" }), null)
assert.equal(addressProgress({ status: "claimed", progress: null }), null)
assert.equal(addressProgress({ status: "success", progress: { done: 254, total: 254 } }), null)
assert.equal(addressProgress({ status: "pending", progress: { done: 0, total: 254 } }), null)
assert.equal(addressProgress({ status: "claimed", progress: { done: 0, total: 0 } }), null)

// the run jobs table moved out of ReviewRunTab's (removed) run dialog into results/RunJobsTable.tsx (CB-38); the run
// results page renders it in "What was covered"
for (const [file, use] of [["NetworkTab.tsx", "const progress = addressProgress(live);"],
                           ["../results/RunJobsTable.tsx", "{addressProgress(job)}"],
                           ["../results/RunSections.tsx", '<RunJobsTable jobs={jobs} testIdPrefix="run-job" />']] as const) {
  const src = fs.readFileSync(path.join(__dirname, file), "utf8")
  assert.ok(src.includes(use), `${file} shows the running range's address progress`)
}
console.log("network progress tests passed")

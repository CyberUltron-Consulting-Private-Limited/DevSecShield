// N7 / N9 (owner bug list 14 Nov 2026): the Network TLS tab's estimate and a range test's readiness label.
// Run: npx --yes tsx components/cbom/sources/networkEstimate.test.ts
import assert from "node:assert/strict"

import type { CbomSource } from "@/utils/backend_api"

import { sampleDetail, sweepTotals, totalsLine } from "./networkEstimate"

const range = (target_count: number, enabled = true) => ({ kind: "network_range", target_count, enabled }) as unknown as CbomSource

// N7: the API's totals win; the reported case is 252 unique, not 510
const reported = [range(254, false), range(126), range(126), range(2), range(2)]
assert.equal(reported.reduce((s, r) => s + r.target_count, 0), 510, "the old sum")
const totals = sweepTotals(reported, { addresses: 252, ranges_enabled: 4, ranges_disabled: 1 })
assert.equal(totals.addresses, 252)
assert.equal(totalsLine(totals, 3), "252 unique addresses across 4 enabled ranges after the never-scan list, 3 ports. 1 disabled range is not counted.")
// an API without network_totals: disabled ranges are still left out
assert.deepEqual(sweepTotals(reported, undefined), { addresses: 256, ranges_enabled: 4, ranges_disabled: 1 })
assert.equal(totalsLine({ addresses: 1, ranges_enabled: 1, ranges_disabled: 0 }, 1), "1 unique address across 1 enabled range after the never-scan list, 1 port.")
assert.equal(totalsLine({ addresses: 0, ranges_enabled: 0, ranges_disabled: 2 }, 2), "0 unique addresses across 0 enabled ranges after the never-scan list, 2 ports. 2 disabled ranges are not counted.")

// N9: the label carries the sample size the node probed
const samples = (ready: number, total: number) => ({
  samples: Array.from({ length: total }, (_, i) => ({ target: `10.0.0.${i + 1}`, status: i < ready ? "ready" : "unreachable" })),
})
assert.equal(sampleDetail("partial", samples(18, 25)), "18 of 25 sampled")
assert.equal(sampleDetail("passed", samples(25, 25)), "25 of 25 sampled")
assert.equal(sampleDetail("failed", samples(0, 5)), "0 of 5 sampled") // an older node's 5-address test says so too
assert.equal(sampleDetail("pending", samples(0, 25)), null)
assert.equal(sampleDetail("never", {}), null)
assert.equal(sampleDetail("partial", { samples: [{ target: "-", status: "skipped_never_scan" }] }), null)
assert.equal(sampleDetail("partial", { summary: "x" }), null)

console.log("networkEstimate.test.ts: ok")

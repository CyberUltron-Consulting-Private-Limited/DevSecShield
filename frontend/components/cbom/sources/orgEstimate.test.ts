/**
 * F1 (#140, owner decision): an AWS organisation run reads and charges every member account. Each validation records
 * the charge per run on the source, and the change from the previous count, so a new charge is visible in Cloud &
 * Identity before the next scheduled run takes it.
 * Run: npx --yes tsx components/cbom/sources/orgEstimate.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

import { orgEstimateLines, orgEstimateStale } from "./logic"

const n = (v: number) => v.toLocaleString()
assert.deepEqual(orgEstimateLines({ accounts: 1000, credits_per_account: 4, credits_per_run: 4000 }),
  { estimate: `Estimated per run: ${n(1000)} accounts × 4 credits = ${n(4000)} credits`, change: null })
assert.deepEqual(orgEstimateLines({ accounts: 1000, credits_per_account: 4, credits_per_run: 4000,
  changed_from: { accounts: 200, credits_per_run: 800 }, changed_at: "2026-11-14T10:00:00Z" }),
  { estimate: `Estimated per run: ${n(1000)} accounts × 4 credits = ${n(4000)} credits`,
    change: `Changed from 200 accounts (800 credits) on ${new Date("2026-11-14T10:00:00Z").toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" })}` })
assert.equal(orgEstimateLines({ accounts: 1, credits_per_account: 4, credits_per_run: 4 })?.estimate, "Estimated per run: 1 account × 4 credits = 4 credits")
assert.equal(orgEstimateLines(null), null)
assert.equal(orgEstimateLines(undefined), null)

// an organisation validated before F1 (count stopped at 200, no estimate) is asked to re-validate; others are not
const org = (r: object | null) => ({ kind: "aws_account", config: { scope: "organization" }, last_test_result: r })
assert.equal(orgEstimateStale(org({ member_accounts: 200 })), true)
assert.equal(orgEstimateStale(org({ member_accounts: 37 })), true)
assert.equal(orgEstimateStale(org({ member_accounts: 200, estimate: { accounts: 200 } })), false)
assert.equal(orgEstimateStale(org({ member_accounts: 1000 })), false)
assert.equal(orgEstimateStale(org(null)), false)
assert.equal(orgEstimateStale({ kind: "aws_account", config: { scope: "account" }, last_test_result: { member_accounts: 5 } }), false)

// the validation panel renders it (from a fresh validation and from the stored source)
const tab = fs.readFileSync(path.join(__dirname, "CloudIdentityTab.tsx"), "utf8")
for (const use of ["estimate: test.estimate ?? null", "estimate: source.last_test_result.estimate ?? null",
                   'data-testid="aws-org-estimate"', "orgEstimateLines(view.estimate)?.change",
                   "orgEstimateStale(s)", "Re-validate to update the charge estimate"]) {
  assert.ok(tab.includes(use), use)
}
console.log("org estimate tests passed")

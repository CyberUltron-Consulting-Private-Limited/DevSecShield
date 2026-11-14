/**
 * Owner bugs of 14 Nov 2026 on the Certificates card (Cloud & Identity tab):
 * C8: the AD CS card said "Passed" for two days after its server was gone, then "Connected" next to "Failed".
 *     One status now comes from the newer of the last test and the last collection (backend `last_collect`,
 *     tests/test_cbom_ca_connectors_b3.py), and a result older than CA_STATUS_STALE_HOURS says "Not checked since ...".
 * C6: Keyfactor, DigiCert, Sectigo, Venafi and "other" have no collector: no API key is asked for, and the card says
 *     plainly that nothing is read from them.
 * Run: npx --yes tsx components/cbom/sources/caCardStatus.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

import { CA_STATUS_STALE_HOURS, caCardStatus, worstCardStatus, type CaStatusInput } from "./caCardStatus"

const NOW = new Date("2026-11-14T12:00:00Z")
const base: CaStatusInput = { last_test_status: "never", last_test_at: null, last_test_summary: null, last_collect: null }
const hoursAgo = (h: number) => new Date(NOW.getTime() - h * 3600_000).toISOString()

assert.equal(CA_STATUS_STALE_HOURS, 24)

// never checked
assert.deepEqual([caCardStatus(base, NOW).kind, caCardStatus(base, NOW).label], ["never", "Not checked"])

// a fresh pass
let s = caCardStatus({ ...base, last_test_status: "passed", last_test_at: hoursAgo(1), last_test_summary: "3 of 3 samples ready" }, NOW)
assert.deepEqual([s.kind, s.tone, s.label, s.basis], ["passed", "green", "Passed", "test"])
assert.ok(s.detail?.includes("3 of 3 samples ready") && s.detail.includes("14 Nov 2026, 11:00 UTC"), s.detail ?? "")

// C8 (1): a pass two days ago with nothing since is not "Passed"
s = caCardStatus({ ...base, last_test_status: "passed", last_test_at: hoursAgo(48) }, NOW)
assert.deepEqual([s.kind, s.tone, s.label], ["stale", "amber", "Not checked since 12 Nov 2026, 12:00 UTC"])
assert.ok(s.detail?.startsWith("Last test: Passed"), s.detail ?? "")
s = caCardStatus({ ...base, last_test_status: "failed", last_test_at: hoursAgo(25) }, NOW)
assert.equal(s.kind, "stale", "a stale failure is not a current one either")

// C8 (2): the server is gone, the run's collection failed after the old pass: one status, Failed
s = caCardStatus({
  ...base,
  last_test_status: "passed",
  last_test_at: hoursAgo(48),
  last_collect: { status: "failed", at: hoursAgo(2), summary: "WinRM: connection refused", job_id: 9, run_id: 4 },
}, NOW)
assert.deepEqual([s.kind, s.tone, s.label, s.basis], ["failed", "red", "Failed", "collection"])
assert.ok(s.detail?.includes("WinRM: connection refused") && s.detail.includes("collection"), s.detail ?? "")

// a newer test wins over an older collection, and the other way round
s = caCardStatus({ ...base, last_test_status: "passed", last_test_at: hoursAgo(1),
  last_collect: { status: "failed", at: hoursAgo(3), summary: "x", job_id: 1, run_id: 1 } }, NOW)
assert.deepEqual([s.kind, s.basis], ["passed", "test"])
s = caCardStatus({ ...base, last_test_status: "failed", last_test_at: hoursAgo(5),
  last_collect: { status: "partial", at: hoursAgo(1), summary: null, job_id: 1, run_id: 1 } }, NOW)
assert.deepEqual([s.kind, s.label], ["partial", "Partly read"])
s = caCardStatus({ ...base, last_collect: { status: "ok", at: hoursAgo(1), summary: null, job_id: 1, run_id: 1 } }, NOW)
assert.deepEqual([s.kind, s.label, s.basis], ["passed", "Passed", "collection"])

// a test waiting for its node, and a test no node ran
assert.equal(caCardStatus({ ...base, last_test_status: "pending", last_test_at: null }, NOW).kind, "testing")
assert.equal(caCardStatus({ ...base, last_test_status: "error", last_test_at: hoursAgo(1) }, NOW).kind, "error")
// a clock a little ahead of the server's never makes a result "stale"
assert.equal(caCardStatus({ ...base, last_test_status: "passed", last_test_at: new Date(NOW.getTime() + 60_000).toISOString() }, NOW).kind, "passed")

// the row header shows the worst of its sources
const ok = caCardStatus({ ...base, last_test_status: "passed", last_test_at: hoursAgo(1) }, NOW)
const stale = caCardStatus({ ...base, last_test_status: "passed", last_test_at: hoursAgo(30) }, NOW)
const failed = caCardStatus({ ...base, last_collect: { status: "failed", at: hoursAgo(1), summary: null, job_id: 1, run_id: 1 } }, NOW)
assert.equal(worstCardStatus([ok, stale]).kind, "stale")
assert.equal(worstCardStatus([ok, stale, failed]).kind, "failed")
assert.equal(worstCardStatus([ok]).kind, "passed")

// ---- the tab uses it: never "Connected" for a CA a scan node reads, one status per card
const cloud = fs.readFileSync(path.join(__dirname, "CloudIdentityTab.tsx"), "utf8")
assert.ok(cloud.includes("headerStatus={"), "the CA rows pass their own header status")
assert.ok(/onNode\s*\?\s*\(\s*<CaStatusBadge status=\{worstCardStatus\(rowSources\.map/.test(cloud), "node CAs: the worst derived status")
assert.ok(!/<TestStatusBadge status=\{source\.last_test_status\}/.test(cloud.slice(cloud.indexOf("function NodeTestLine"), cloud.indexOf("function CaDialog"))),
  "the node line no longer shows the raw last test next to a header status")

// ---- C6: no key for a CA ZeroShield does not read
const dialog = cloud.slice(cloud.indexOf("function CaDialog"), cloud.indexOf("function IdpDialog"))
assert.ok(!dialog.includes("api_key") && !dialog.includes('id="ca-api-key"') && !dialog.includes("apiKey"), "no API key field, state or secret")
assert.ok(cloud.includes(
  'const CLM_NOT_COLLECTED = "Not collected: ZeroShield has no connector for this product yet. Nothing is read from it, no key is needed and it is never charged; only its name and API address are saved. Certificates it issued are found where other sources see them: network TLS scans, Certificate Transparency and cloud accounts.";'))
assert.ok(cloud.includes('<StatusBadge tone="zinc">Not collected</StatusBadge>'), "the row says it is not collected, not Connected")

console.log("caCardStatus: ok")

/**
 * Lab UI r1 F2: GET /{team}/cbom/sources/runs/6/diff?against=4 returned counts.not_read 6 (a stopped TLS target), but
 * the Compare dialog listed only resolved / opened / added / removed / changed, and the run's "Changes" had nothing,
 * so the target silently dropped out. Both now list "not read in this run" apart from "resolved", grouped by the
 * reason the server gives (the coverage row's detail; backend tests/test_cbom_r1_not_read.py).
 * Browser check after a rebuild: r1 bin/run compare.js (run 6 vs 4): a "diff-not-read" block with 6 items and the
 * "did not answer on any listed port" reason; the run's Changes show "Not read: 6".
 * Run: npx --yes tsx components/cbom/sources/notRead.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

import { NOT_READ_NO_REASON, groupNotRead } from "./logic"

// the shape of the r1 diff-6-vs-4 not_read items (two certificates and an endpoint of the stopped 172.31.67.4)
const why = "172.31.67.4 did not answer on any listed port (443, 8443); filtered, down or no host at this address"
const items = [
  { key: "a", label: "CN=tls-c.r1.test · 172.31.67.4:443#chain[0]", type: "certificate", asset_removed: true, codes: ["QUANTUM_VULNERABLE"], source_name: "range-172.31.67.0-29", reason: why },
  { key: "b", label: "HTTPS 172.31.67.4:443", type: "tls_endpoint", asset_removed: true, codes: ["NO_PQ_KEX"], source_name: "range-172.31.67.0-29", reason: why },
  { key: "c", label: "DSA host key", type: "ssh_host_key", asset_removed: true, codes: [], source_name: "linux-a", reason: "sudo was refused" },
  { key: "d", label: "old row", type: "certificate", asset_removed: false, codes: ["X"], source_name: "linux-a", reason: null },
]
const groups = groupNotRead(items)
assert.deepEqual(groups.map((g) => [g.source, g.reason, g.items.map((i) => i.key)]), [
  ["range-172.31.67.0-29", why, ["a", "b"]],
  ["linux-a", "sudo was refused", ["c"]],
  ["linux-a", NOT_READ_NO_REASON, ["d"]], // an older server without "reason"
])
assert.deepEqual(groupNotRead([]), [])

// the views render it, apart from "resolved"
const panel = fs.readFileSync(path.join(__dirname, "ChangesPanel.tsx"), "utf8")
const diffView = panel.slice(panel.indexOf("export function DiffView"), panel.indexOf("export function CompareDialog"))
assert.ok(diffView.includes('<NotReadList items={diff.not_read} total={diff.counts?.not_read} testId="diff-not-read" />'),
  "Compare dialog and code-scan changes (DiffView) list not-read items")
assert.ok(!/AssetList title="[^"]*"\s+items=\{diff\.not_read\}/.test(diffView), "not in an AssetList next to resolved")
const runChanges = panel.slice(panel.indexOf("export function RunChanges"), panel.indexOf("function AssetList"))
assert.ok(runChanges.includes('<NotReadList items={q.data.not_read} total={q.data.not_read_count} testId="run-changes-not-read" />'),
  "the run's Changes list them")
assert.ok(runChanges.includes("Not read: {q.data.not_read_count}"), "and count them")
const notRead = panel.slice(panel.indexOf("export function NotReadList"), panel.indexOf("export function DiffView"))
assert.ok(notRead.includes('tone="amber"') && notRead.includes("border-dashed") && !notRead.includes('tone="green"'),
  "visually apart from resolved (green)")
const types = fs.readFileSync(path.join(__dirname, "../../../utils/api/cbom_ops.ts"), "utf8")
assert.ok(types.includes("  not_read?: CbomDiffAsset[]\n  rule_changes?"), "CbomDiff has not_read")
assert.ok(types.includes("  reason?: string | null\n}"), "a not-read item carries its reason")
assert.ok(types.includes("  not_read_count?: number\n}"), "CbomRunChanges has not_read")

console.log("not read tests passed")

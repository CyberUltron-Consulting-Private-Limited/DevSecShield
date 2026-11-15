/**
 * Staging QA B6-1 (14 Nov 2026): every scan node said "1.0.0" while staging-lab-node ran pre-#234 code, and nothing
 * told anyone to update. The API now gives each node `update` (backend node_release.node_update, tests in
 * backend/tests/test_cbom_b6_node_update.py); the Scan nodes tab shows "Update available" with what is missing, a
 * banner counting the nodes behind, and how to update in place.
 * Run: npx --yes tsx components/cbom/sources/nodeUpdate.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

import { NODE_UPDATE_STEPS, nodeUpdateBadge, nodesNeedingUpdate } from "./nodeUpdate"

const server = "1.0.0+5d41b4cc9a1f"
const lab = { state: "update_available", reason: "no_build_id", server_build: server,
  message: `Runs 1.0.0 with no build id (an image built by hand or before build ids existed), so it is older than the server's node build ${server}.` } as const

// the staging lab node: amber "Update available", and what is missing
assert.deepEqual(nodeUpdateBadge(lab), { tone: "amber", label: "Update available",
  short: "No build id: older than the server's node build", message: lab.message })
assert.equal(nodeUpdateBadge({ ...lab, reason: "older_version" })?.short, "Older than the current release")
// #361: the badge names the release to install when the API says which one it is
assert.equal(nodeUpdateBadge({ ...lab, reason: "older_version", server_version: "1.0.1" })?.label, "Update available: 1.0.1")
assert.equal(nodeUpdateBadge({ ...lab, server_version: null })?.label, "Update available")
assert.equal(nodeUpdateBadge({ ...lab, reason: "different_build" })?.short, "Not the server's node build")
// a node ahead of the server is said so, without asking for an update
assert.equal(nodeUpdateBadge({ state: "newer", reason: "newer_version", server_build: server, message: "Runs 1.2.0" })?.label, "Newer than server")
// nothing to say: current, unknown, an older API without the field
assert.equal(nodeUpdateBadge({ state: "current", reason: "same_build", server_build: server, message: null }), null)
assert.equal(nodeUpdateBadge({ state: "unknown", reason: "no_server_build", server_build: null, message: null }), null)
// a node the server could not compare (PR #286 review): no badge, the list still renders
assert.equal(nodeUpdateBadge({ state: "unknown", reason: "compare_failed", server_build: "1.2.3", message: null }), null)
assert.equal(nodeUpdateBadge(undefined), null)
assert.equal(nodesNeedingUpdate([{ update: lab }, { update: { ...lab, state: "current", reason: "same_build", message: null } }, {}]), 1)
// the update keeps the node's registration: same state volume, no registration token
assert.match(NODE_UPDATE_STEPS, /same name, settings and state volume and no registration token/)

// the tab uses it: the version cell, a banner, the details dialog
const tab = fs.readFileSync(path.join(__dirname, "ScanNodesTab.tsx"), "utf8")
assert.match(tab, /<NodeVersion node=\{node\} \/>/)
assert.ok(!tab.includes('{node.node_version ?? "—"}</TableCell>'), "the bare version cell is gone")
assert.match(tab, /data-testid="nodes-update-available"/)
assert.match(tab, /nodesNeedingUpdate\(nodes\)/)
assert.match(tab, /<Detail label="Update" value=/)

console.log("nodeUpdate.test.ts: ok")

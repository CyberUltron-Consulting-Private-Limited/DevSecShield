/**
 * Lab UI r1 N1: Reset on an agent pool node opened "Register <node> again" with a standalone Helm command and a fresh
 * 24-hour zsr_ token. The server now issues no token for a pool node (registration_token null); the tab then says the
 * pod enrolls again by itself and shows nothing to copy. Standalone nodes keep the wizard.
 * Browser check after a rebuild: r1 bin/run node_reset.js on the pool node (r1-k8s-worker-1): no "Register ... again"
 * card, the "node-reenrolling" notice instead; node_reset_simple.js on a standalone node: the wizard as before.
 * Run: npx --yes tsx components/cbom/sources/nodeReset.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

import { POOL_NODE_REENROLLS, offersRegistrationToken, registrationOutcome } from "./logic"

assert.deepEqual(registrationOutcome({ registration_token: null }), { wizard: false, note: POOL_NODE_REENROLLS })
assert.equal(POOL_NODE_REENROLLS, "The pod enrolls again by itself within a minute.")
assert.deepEqual(registrationOutcome({ registration_token: "zsr_abc" }), { wizard: true, token: "zsr_abc" })

// "New registration token" only for a standalone node that has not registered; a reset pool node is offered Reset
assert.equal(offersRegistrationToken({ pool_id: null, status: "pending_registration" }), true)
assert.equal(offersRegistrationToken({ status: "registration_expired" }), true)
assert.equal(offersRegistrationToken({ pool_id: 3, status: "pending_registration" }), false)
assert.equal(offersRegistrationToken({ pool_id: null, status: "online" }), false)

const tab = fs.readFileSync(path.join(__dirname, "ScanNodesTab.tsx"), "utf8")
const success = tab.slice(tab.indexOf("const tokenMutation"), tab.indexOf("const deleteMutation"))
assert.ok(success.includes("const outcome = registrationOutcome(data);"), "the outcome decides")
assert.ok(success.indexOf("if (!outcome.wizard)") < success.indexOf("setWizardOpen(true)"), "no wizard for a pool node")
assert.ok(success.includes("token: outcome.token"), "the wizard only gets a real token")
assert.ok(tab.includes('data-testid="node-reenrolling"'), "the notice is on the page")
assert.ok(tab.includes("{offersRegistrationToken(node) ? ("), "the row menu asks the same rule")
const api = fs.readFileSync(path.join(__dirname, "../../../utils/backend_api.ts"), "utf8")
assert.ok(api.includes("registration_token: string | null }> => {"), "the reset response type allows no token")

console.log("node reset tests passed")

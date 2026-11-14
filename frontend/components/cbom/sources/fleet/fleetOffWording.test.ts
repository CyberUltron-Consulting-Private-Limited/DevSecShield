/**
 * #227: with every fleet flag off the Fleet tab said "Ask your administrator if you expected to see it here": a SaaS
 * customer has no administrator who can turn it on; only ZeroShield can. It now says the feature isn't enabled on
 * this deployment and names ZeroShield support, with a link (the same wording as the AWS-off message, #223).
 * Run: npx --yes tsx components/cbom/sources/fleet/fleetOffWording.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

const tab = fs.readFileSync(path.join(__dirname, "FleetTab.tsx"), "utf8")
assert.ok(!/administrator/i.test(tab), "no administrator a SaaS customer does not have")
assert.ok(tab.includes('title="Fleet onboarding isn\'t enabled on this ZeroShield deployment"'), "says why")
assert.ok(tab.includes('const FLEET_SUPPORT_EMAIL = "support@zeroshield.ai"'), "whom to contact")
assert.ok(tab.includes("href={`mailto:${FLEET_SUPPORT_EMAIL}`}"), "with a link")
assert.ok(tab.includes('data-testid="fleet-off"'), "testable")
console.log("fleet off wording: ok")

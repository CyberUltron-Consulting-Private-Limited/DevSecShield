/**
 * CB-10 lockout guards in the UI: run results name the new target status (the scan node stopped using a refused
 * credential), and the HSM form no longer promises that a blank token label reads every token (with several tokens
 * the node refuses the source, so a PIN is never tried on a token it was not entered for, issue #211).
 * Run: npx --yes tsx components/cbom/sources/lockoutGuards.test.ts
 */
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const results = readFileSync(join(__dirname, "RunResults.tsx"), "utf8")
assert.match(results, /skipped_credential_refused: "Skipped: credential refused"/)
assert.match(results, /TARGET_TONE[^;]*skipped_credential_refused: "amber"/)

const hsm = readFileSync(join(__dirname, "ClustersDatabasesTab.tsx"), "utf8")
assert.doesNotMatch(hsm, /Blank reads every initialised token/)
assert.match(hsm, /a PIN is only ever tried on the token it belongs to/)
const tips = readFileSync(join(__dirname, "..", "..", "..", "content", "infotips.ts"), "utf8")
assert.doesNotMatch(tips, /Blank reads every initialised token/)

console.log("lockout guard UI tests passed")

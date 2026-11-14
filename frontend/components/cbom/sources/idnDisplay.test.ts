/**
 * CB-09: stored A-labels are shown as the names the customer typed, and the ServersTab form saves the list it shows.
 * Expected values are the backend's own (backend/tests/test_cbom_cb09_idna2008.py, the `idna` package).
 * Run: npx --yes tsx components/cbom/sources/idnDisplay.test.ts
 */
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

import { decodePunycode, displayHostLines, toUnicodeHost } from "./idnDisplay"

assert.equal(toUnicodeHost("xn--fa-hia.lab"), "faß.lab")
assert.equal(toUnicodeHost("xn--bcher-kva.example"), "bücher.example")
assert.equal(toUnicodeHost("xn--c2ba8etc5a.xn--h2brj9c"), "टेस्ट.भारत")
assert.equal(toUnicodeHost("xn--r8jz45g.xn--zckzah"), "例え.テスト")
assert.equal(toUnicodeHost("xn--a-xmb.example"), "ςa.example")
assert.equal(toUnicodeHost("XN--BCHER-KVA.example"), "bücher.example")
// Shown as stored: ASCII names, addresses, and labels that do not decode
for (const same of ["fass.lab", "10.0.0.0/24", "fd00::1-fd00::5", "xn--a.example", "xn--.lab", "xn--abc-.lab", "xn--zz9999999999.lab"]) {
  assert.equal(toUnicodeHost(same), same, same)
}
assert.equal(decodePunycode("bcher-kva"), "bücher")
assert.equal(decodePunycode("!!"), null)

assert.equal(displayHostLines(["xn--fa-hia.lab", "10.0.0.5", "plain.lab"]), "faß.lab\n10.0.0.5\nplain.lab")
assert.equal(displayHostLines(undefined), "")

// The Servers form shows stored targets and never-scan lines as U-labels, compares them in the same form, and lists
// the API's IDNA notes (faß.lab is scanned as xn--fa-hia.lab, not fass.lab) under the target count before saving.
const tab = readFileSync(join(__dirname, "ServersTab.tsx"), "utf8")
assert.match(tab, /targets: displayHostLines\(cfg\.targets\)/)
assert.match(tab, /exclusions: displayHostLines\(cfg\.exclusions\)/)
assert.match(tab, /const stored = displayHostLines\(cfg\.targets\)/)
assert.match(tab, /data-testid="servers-idn-notes"/)
const api = readFileSync(join(__dirname, "..", "..", "..", "utils", "backend_api.ts"), "utf8")
assert.match(api, /interface CbomTargetCount \{[^}]*notes\?: string\[\]/)

console.log("idnDisplay: all assertions passed")

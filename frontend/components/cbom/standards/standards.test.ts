/**
 * CB-16: the asset drawer's Standards section, rendered with react-dom/server from the asset detail API's
 * `standards` rows: one row per standard with its status, tone and reasons; "approved" names the FIPS standard and
 * category; an unseen status is never a pass; nothing on an older backend or for an asset with no algorithm.
 * Run (frontend/): npx --yes tsx@4.23.15 components/cbom/standards/standards.test.ts
 */
import assert from "node:assert/strict"
import React from "react"
import { renderToStaticMarkup } from "react-dom/server"

import { StandardsDrawerSection } from "./Standards"
import { statusText, statusTone, type StandardRow } from "./model"

// the shape backend/utilities/cbom_sources/standards.py `rows` sends (test_cbom_cb16_standards.py checks the API side)
const RSA_CERT: StandardRow[] = [
  { id: "fips_203_204_205", label: "FIPS 203/204/205", status: "not_applicable", reasons: ["no post-quantum algorithm"] },
  { id: "cnsa_2_0", label: "NSA CNSA 2.0", status: "not_compliant", reasons: ["RSA: quantum-vulnerable public-key algorithm"] },
  { id: "sp800_131a", label: "NIST SP 800-131A", status: "acceptable", reasons: ["RSA-2048: 112-bit security"] },
]
const KEM: StandardRow = { id: "fips_203_204_205", label: "FIPS 203/204/205", status: "approved", reasons: ["category 3"],
                           standard: "FIPS 203", category: 3 }

const html = renderToStaticMarkup(React.createElement(StandardsDrawerSection, { standards: RSA_CERT }))
assert.match(html, /data-testid="asset-standards"/)
assert.match(html, /data-testid="asset-standard-cnsa_2_0" data-status="not_compliant" data-tone="fail"/)
assert.match(html, /data-testid="asset-standard-sp800_131a" data-status="acceptable" data-tone="pass"/)
assert.match(html, /data-testid="asset-standard-fips_203_204_205" data-status="not_applicable" data-tone="na"/)
assert.match(html, /RSA-2048: 112-bit security/)
assert.match(html, />Not compliant</)

const kem = renderToStaticMarkup(React.createElement(StandardsDrawerSection, { standards: [KEM] }))
assert.match(kem, /data-category="3"/)
assert.match(kem, /Approved: FIPS 203 category 3/)

assert.equal(statusTone("unknown"), "unknown")
assert.equal(statusTone("a-future-status"), "unknown")  // never a pass
assert.equal(statusText({ status: "a-future-status" }), "a-future-status")
assert.equal(statusTone("disallowed"), "fail")

for (const empty of [undefined, null, []]) {
  assert.equal(renderToStaticMarkup(React.createElement(StandardsDrawerSection, { standards: empty })), "")
}
console.log("standards.test.ts: ok")

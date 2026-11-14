// npx tsx components/cbom/results/refundLabel.test.ts
import assert from "node:assert/strict"

import { refundLabel } from "./refundLabel"

assert.equal(refundLabel({ credits: 0.8, refunded: false, credits_refunded: 0 }), null)
assert.equal(refundLabel({ credits: 0.8, refunded: true, credits_refunded: 0.8 }), "refunded")
assert.equal(refundLabel({ credits: 0.8, refunded: true, credits_refunded: 0.4 }), "0.4 refunded")
assert.equal(refundLabel({ credits: 1, refunded: true, credits_refunded: 0.66 }), "0.66 refunded")
assert.equal(refundLabel({ credits: 0.8, refunded: true }), "refunded") // an API from before CB-14
assert.equal(refundLabel({ credits: 0.8, refunded: true, credits_refunded: 0 }), null) // nothing was left to give back
console.log("refundLabel: ok")

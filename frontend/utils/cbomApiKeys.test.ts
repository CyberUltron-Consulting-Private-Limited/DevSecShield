// npx tsx utils/cbomApiKeys.test.ts
import assert from "node:assert/strict"

import { createFormProblem, EXPIRY_CHOICES, maskedKey, statusLabel } from "./api/cbom_api_keys"

assert.equal(createFormProblem("", ["cbom.read"]), "Enter a name")
assert.equal(createFormProblem("   ", ["cbom.read"]), "Enter a name")
assert.match(createFormProblem("-bad", ["cbom.read"]) ?? "", /letters, digits/)
assert.match(createFormProblem("x".repeat(65), ["cbom.read"]) ?? "", /1-64/)
assert.equal(createFormProblem("cmdb-sync", []), "Choose at least one scope")
assert.equal(createFormProblem("cmdb-sync", ["cbom.sources:write"]), null)
assert.equal(createFormProblem("CMDB nightly 2026.11", ["cbom.read"]), null)

assert.equal(statusLabel({ status: "revoked", expires_at: null }), "Revoked")
assert.equal(statusLabel({ status: "expired", expires_at: "2026-01-01T00:00:00Z" }), "Expired")
assert.equal(statusLabel({ status: "active", expires_at: null }), "Active, no expiry")
assert.equal(statusLabel({ status: "active", expires_at: "2027-01-01T00:00:00Z" }), "Active")

assert.equal(maskedKey("zsk_", "Ab9_"), "zsk_…Ab9_")
assert.deepEqual(EXPIRY_CHOICES.map((c) => c.days), [30, 90, 365, null])
assert.ok(EXPIRY_CHOICES.every((c) => c.days === null || (c.days >= 1 && c.days <= 730)))

console.log("cbomApiKeys.test.ts: all assertions passed")

// Run: npx --yes tsx utils/api/cbomGatePolicy.test.ts
import assert from "node:assert/strict"

import { cleanException, policyFileText, splitList, type GatePolicy } from "./cbomGatePolicy"

assert.deepEqual(splitList("MD5, 3DES\nRC4,, md5 \n"), ["MD5", "3DES", "RC4"], "split, trim, drop blanks and repeats")
assert.deepEqual(splitList(""), [])
assert.deepEqual(cleanException({ rule: null, algorithm: " RSA-1024 ", location: "", reason: " HSM ", expires: "2027-01-31" }),
  { rule: null, algorithm: "RSA-1024", location: null, reason: "HSM", expires: "2027-01-31" })
const policy: GatePolicy = {
  version: 1, name: "Team", block_codes: ["WEAK_ALGORITHM"], banned_algorithms: ["MD5"],
  min_key_bits: { rsa: 2048, dsa: 2048, dh: 2048, ec: 256, symmetric: 128 }, quantum_vulnerable: "warn",
  deprecated: "warn", exceptions: [],
}
const file = JSON.parse(policyFileText(policy, "zeroshield.cbom-gate-policy"))
assert.equal(file.kind, "zeroshield.cbom-gate-policy", "the file names its format (the offline gate checks it)")
assert.deepEqual({ ...file, kind: undefined }, { ...policy, kind: undefined })
console.log("cbomGatePolicy: ok")

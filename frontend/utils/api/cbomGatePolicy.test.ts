// Run: npx --yes tsx utils/api/cbomGatePolicy.test.ts
import assert from "node:assert/strict"

import { boundedLocation, cleanException, policyFileText, splitList, type GatePolicy } from "./cbomGatePolicy"

assert.deepEqual(splitList("MD5, 3DES\nRC4,, md5 \n"), ["MD5", "3DES", "RC4"], "split, trim, drop blanks and repeats")
assert.deepEqual(splitList(""), [])
assert.deepEqual(cleanException({ rule: "min_key_size", code: "X", algorithm: " RSA-1024 ", location: "vendor/*", reason: " HSM ", expires: "2027-01-31" }),
  { rule: "min_key_size", code: null, algorithm: "RSA-1024", location: "vendor/*", reason: "HSM", expires: "2027-01-31" })
assert.deepEqual(cleanException({ rule: "finding_code", code: " hardcoded_key ", algorithm: "MD5", location: "app/b.py", reason: "r", expires: "2027-01-31" }),
  { rule: "finding_code", code: "HARDCODED_KEY", algorithm: null, location: "app/b.py", reason: "r", expires: "2027-01-31" })
for (const glob of ["*", "**", "/*", "*/*.py", "", "./*"]) assert.equal(boundedLocation(glob), false, glob)
for (const glob of ["vendor/hsm/*", "app/keys.py", "keys.py", "*/legacy/*"]) assert.equal(boundedLocation(glob), true, glob)
const policy: GatePolicy = {
  version: 1, name: "Team", block_codes: ["WEAK_ALGORITHM"], banned_algorithms: ["MD5"],
  min_key_bits: { rsa: 2048, dsa: 2048, dh: 2048, ec: 224, symmetric: 128 }, quantum_vulnerable: "warn",
  deprecated: "warn", exceptions: [],
}
const file = JSON.parse(policyFileText(policy, "zeroshield.cbom-gate-policy"))
assert.equal(file.kind, "zeroshield.cbom-gate-policy", "the file names its format (the offline gate checks it)")
assert.deepEqual({ ...file, kind: undefined }, { ...policy, kind: undefined })
console.log("cbomGatePolicy: ok")

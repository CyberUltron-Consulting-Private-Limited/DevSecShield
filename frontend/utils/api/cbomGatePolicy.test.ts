// Run: npx --yes tsx utils/api/cbomGatePolicy.test.ts
import assert from "node:assert/strict"

import { boundedLocation, cleanException, matchingPreset, policyFileText, splitList, type GatePolicy } from "./cbomGatePolicy"

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

// staging QA2 m9: after a save the editor remounts; the preset dropdown starts at the preset the saved rules equal
{
  const cnsa: GatePolicy = { ...policy, name: "CNSA", quantum_vulnerable: "fail", deprecated: "fail",
    min_key_bits: { rsa: 3072, dsa: 3072, dh: 3072, ec: 384, symmetric: 256 } }
  const presets = { "sp800-131a": policy, "cnsa-2.0": cnsa }
  assert.equal(matchingPreset({ ...cnsa, name: "qa2-q4 CNSA", exceptions: [{ rule: "min_key_size", algorithm: "RSA-1024",
    location: "vendor/*", reason: "r", expires: "2027-01-31" }] }, presets), "cnsa-2.0", "name and exceptions aside")
  assert.equal(matchingPreset({ ...cnsa, banned_algorithms: ["md5", "RC4"] }, presets), null,
    "edited rules match no preset (custom)")
  assert.equal(matchingPreset(policy, presets), "sp800-131a")
  assert.equal(matchingPreset(null, presets), null)
}

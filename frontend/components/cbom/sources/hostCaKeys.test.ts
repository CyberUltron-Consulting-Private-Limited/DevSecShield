/**
 * #59 in the Servers form: the "Host certificates" host key policy and its host-CA keys.
 * Run: npx --yes tsx components/cbom/sources/hostCaKeys.test.ts
 */
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

import { hostCaKeysProblem, hostCaLines } from "./hostCaKeys"

const KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMGzbTgEQMHDW0D40GPLBAYzohHukYrsarVfTN0dv8S4 host-ca@bank"
assert.equal(hostCaKeysProblem(KEY), null)
assert.equal(hostCaKeysProblem(`# our host CA\n${KEY}\n\necdsa-sha2-nistp256 AAAAE2VjZHNh host-ca-2`), null)
assert.deepEqual(hostCaLines(`# c\n${KEY}\n`), [KEY])
assert.match(hostCaKeysProblem("") ?? "", /at least one host CA/)
assert.match(hostCaKeysProblem("-----BEGIN OPENSSH PRIVATE KEY-----") ?? "", /Line 1 is a private key/)
assert.match(hostCaKeysProblem(`@cert-authority *.bank.local ${KEY}`) ?? "", /Line 1 is a known_hosts line/)
assert.match(hostCaKeysProblem("ssh-ed25519-cert-v01@openssh.com AAAA") ?? "", /Line 1 is a certificate/)
assert.match(hostCaKeysProblem(`${KEY}\nnot a key`) ?? "", /Line 2 is not an SSH public key/)
assert.match(hostCaKeysProblem(Array.from({ length: 21 }, () => KEY).join("\n")) ?? "", /At most 20/)

const tab = readFileSync(join(__dirname, "ServersTab.tsx"), "utf8")
assert.match(tab, /type HostKeyPolicy = "tofu" \| "pinned" \| "host_ca";/)
assert.match(tab, /value: "host_ca", title: "Host certificates"/)
assert.match(tab, /host_ca_keys: hostCaLines\(form\.hostCaKeys\)/)
assert.match(tab, /hostCaKeysProblem\(form\.hostCaKeys\)/)
assert.match(tab, /data-testid="servers-host-ca-keys"/)
// a password may go to a server proven by a host CA, as to a pinned one
assert.match(tab, /form\.credentialType === "password" && !VERIFIED_POLICIES\.has\(form\.hostKeyPolicy\)/)
const results = readFileSync(join(__dirname, "RunResults.tsx"), "utf8")
assert.match(results, /host_key_mismatch: "Host certificate refused"/)

console.log("host CA form rules: tests passed")

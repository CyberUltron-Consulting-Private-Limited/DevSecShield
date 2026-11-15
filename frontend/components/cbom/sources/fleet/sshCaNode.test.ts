/**
 * #61: the "On my scan node" SSH CA: ZeroShield gets only the CA's public key; the key stays on the node.
 * Run: npx --yes tsx components/cbom/sources/fleet/sshCaNode.test.ts
 */
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

import { nodeCaKeyProblem } from "./sshCaNode"

const KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMGzbTgEQMHDW0D40GPLBAYzohHukYrsarVfTN0dv8S4 ca@bank"
assert.equal(nodeCaKeyProblem(KEY), null)
assert.equal(nodeCaKeyProblem("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY= ca"), null)
assert.match(nodeCaKeyProblem("") ?? "", /Paste the public key/)
assert.match(nodeCaKeyProblem("-----BEGIN OPENSSH PRIVATE KEY-----") ?? "", /private key/)
assert.match(nodeCaKeyProblem("ssh-rsa AAAAB3NzaC1yc2E=") ?? "", /Ed25519 or ECDSA P-256/)
assert.match(nodeCaKeyProblem("ssh-ed25519-cert-v01@openssh.com AAAA") ?? "", /not a certificate/)

const tab = readFileSync(join(__dirname, "SshCaSection.tsx"), "utf8")
assert.match(tab, /<SelectItem value="node" className="cursor-pointer">On my scan node \(I keep the key\)<\/SelectItem>/)
assert.match(tab, /\{ name: name\.trim\(\), provider, public_key: nodeKey\.trim\(\), default_ttl_s: Number\(ttl\) \}/)
assert.match(tab, /data-testid="ssh-ca-node-public-key"/)
assert.match(tab, /ZS_SSH_CA_KEY/)
const api = readFileSync(join(__dirname, "..", "..", "..", "..", "utils", "api", "cbom_ssh_ca.ts"), "utf8")
assert.match(api, /export type SshCaProvider = "builtin" \| "vault" \| "node"/)
assert.match(api, /public_key\?: string/)

console.log("node SSH CA form: tests passed")

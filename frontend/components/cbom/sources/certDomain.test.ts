/**
 * #368: a Unicode domain (bücher.example) whose punycode (xn--bcher-kva.example) is already listed was silently
 * dropped by the server (it stores names in their ASCII form and removes duplicates) with no "already in the list".
 * The form now converts an internationalised name to its ASCII form before the duplicate check, as the server does,
 * and says which listed name it duplicates. Also: each CLM product's API address example is its own (#368 b).
 * Run: npx --yes tsx components/cbom/sources/certDomain.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

import { CA_API_URL_EXAMPLE, alreadyListed, normalizeDomain } from "./certDomain"

// ASCII names as before
assert.deepEqual(normalizeDomain(" Example.COM. "), { value: "example.com", error: null })
assert.equal(normalizeDomain("").error, "Enter a domain such as example.com")
assert.match(normalizeDomain("not a domain").error ?? "", /is not a domain name/)
assert.match(normalizeDomain("example.123").error ?? "", /is not a domain name/)
// internationalised names: their ASCII (punycode) form, as the server stores them
assert.deepEqual(normalizeDomain("bücher.example"), { value: "xn--bcher-kva.example", error: null })
assert.deepEqual(normalizeDomain("BÜCHER.Example."), { value: "xn--bcher-kva.example", error: null })
assert.match(normalizeDomain("bü cher.example").error ?? "", /is not a domain name/)
// the duplicate message names what it duplicates
assert.equal(alreadyListed("bücher.example", "xn--bcher-kva.example"), "bücher.example is already in the list (as xn--bcher-kva.example)")
assert.equal(alreadyListed("example.com", "example.com"), "example.com is already in the list")
assert.equal(alreadyListed(" Example.com ", "example.com"), "example.com is already in the list")

// the tab uses them for both domain lists
const tab = fs.readFileSync(path.join(__dirname, "CloudIdentityTab.tsx"), "utf8")
assert.ok(tab.includes('from "./certDomain"'), "the tab imports the shared rules")
assert.ok(!tab.includes("function normalizeDomain("), "a second copy of the rule stays in the tab")
assert.equal((tab.match(/alreadyListed\(/g) ?? []).length, 2, "both domain lists say what a duplicate duplicates")

// #368 (b): each CLM product its own example address (Venafi's /vedsdk only for Venafi)
assert.equal(CA_API_URL_EXAMPLE.venafi, "https://tpp.example.com/vedsdk")
assert.equal(CA_API_URL_EXAMPLE.keyfactor, "https://keyfactor.example.com/KeyfactorAPI")
assert.equal(CA_API_URL_EXAMPLE.digicert, "https://www.digicert.com/services/v2")
assert.equal(CA_API_URL_EXAMPLE.sectigo, "https://cert-manager.com/api")
assert.equal(CA_API_URL_EXAMPLE.other, "https://clm.example.com/api")
const others = Object.entries(CA_API_URL_EXAMPLE).filter(([k]) => k !== "venafi")
assert.ok(others.every(([, v]) => !v.includes("vedsdk")), "a non-Venafi product shows Venafi's path")
assert.ok(tab.includes("CA_API_URL_EXAMPLE[provider]"), "the dialog's placeholder follows the product")
assert.ok(!tab.includes(': "https://tpp.example.com/vedsdk"'), "one placeholder for every CLM product")

console.log("certDomain: ok")

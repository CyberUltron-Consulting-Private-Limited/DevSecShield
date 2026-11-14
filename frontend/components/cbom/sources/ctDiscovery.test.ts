// Certificate Transparency card: what it says follows the server (CB-08: promises match the code).
// Run: npx tsx components/cbom/sources/ctDiscovery.test.ts
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { ctProviderSentence, ctRunCredits } from "./logic"

// 1. Providers are named from the server's list, in its order
assert.equal(ctProviderSentence(["certspotter", "crtsh"]), "Cert Spotter (then crt.sh when it cannot answer)")
assert.equal(ctProviderSentence(["crtsh"]), "crt.sh")
assert.equal(ctProviderSentence([]), "a public CT search service")
assert.equal(ctProviderSentence(undefined), "a public CT search service")

// 2. The per-run cost is the server's rate times the domains it searches, rounded like the server (cents)
assert.equal(ctRunCredits(0.2, 2), 0.4)
assert.equal(ctRunCredits(0.2, 1000), 200)
assert.equal(ctRunCredits(0.2, 3), 0.6) // not 0.6000000000000001
assert.equal(ctRunCredits(undefined, 3), null)

// 3. The saved-domains copy ("does not query ... yet") is shown only while the server has CT discovery off; with it on,
//    the CT card (which searches) replaces it, and its cost comes from the overview's rates, not a number in the UI.
const tab = readFileSync(join(__dirname, "CloudIdentityTab.tsx"), "utf8")
assert.match(tab, /settings\.ct_discovery_enabled \? \(\s*<CtDiscovery[\s\S]*?\) : \(\s*<CertDomains /)
assert.ok(tab.includes("const rate = overview.data?.rates?.ct_domain;"))
assert.ok(!/0\.2 credits/.test(tab), "no hard-coded CT price in the UI")
assert.ok(tab.includes('kind: "ct_logs", name: "Certificate Transparency", config, import_saved_domains: true'))
console.log("ctDiscovery.test.ts: ok")

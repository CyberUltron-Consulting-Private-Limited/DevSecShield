/**
 * CB-03 / GAP S2: the scan node refuses a ZeroShield API URL that is not https:// (claim answers carry decrypted
 * credentials; scan_node/zs_scan_node/agent.py), and a TLS client cannot talk to the plain-HTTP port 80. The install
 * command is built from this deployment's API URL, so when that URL is http:// or port 80 the wizard says so before
 * the customer runs a command that cannot work, instead of the node exiting on their host.
 * Run: npx --yes tsx components/cbom/sources/nodeInsecureApi.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

import { insecureApiWarning } from "./logic"

for (const ok of ["https://api.dss.test", "https://devsec-api.zeroshield.ai/", "https://api.example:443", "https://api.example:8443/v1"]) {
  assert.equal(insecureApiWarning(ok), null, ok)
}
const http = insecureApiWarning("http://devsec-staging-api.zeroshield.ai")
assert.ok(http && http.includes("http://devsec-staging-api.zeroshield.ai"), "names the URL")
assert.ok(http && /refuses/.test(http) && /https:\/\//.test(http), "says the node refuses it and what is needed")
assert.ok(insecureApiWarning("HTTP://API.EXAMPLE"), "scheme is case-insensitive")
assert.ok(insecureApiWarning("http://api.example:8080"), "any http:// port")
const port80 = insecureApiWarning("https://api.example:80")
assert.ok(port80 && /port 80/.test(port80), "https on port 80 is the plain-HTTP port")
assert.ok(insecureApiWarning("not a url"), "an unparsable URL cannot work either")
// the node's own rule (agent.py: ZS_API_URL.startswith("https://"), case-sensitive): the UI warns exactly then
for (const refused of ["HTTPS://api.example", "Https://api.example", "https:api.example", "https:/api.example", " http://x"]) {
  assert.ok(insecureApiWarning(refused), `the node refuses ${refused}`)
}
assert.equal(insecureApiWarning("  https://api.example  "), null, "the node strips the value too")
assert.equal(insecureApiWarning(""), null, "no URL configured: nothing to judge")

// the wizard and the agent-pool card show it next to the commands they build from the API URL
const tab = fs.readFileSync(path.join(__dirname, "ScanNodesTab.tsx"), "utf8")
assert.ok(tab.includes('data-testid="node-api-insecure"'), "wizard warning")
assert.ok(tab.includes("insecureApiWarning(apiBaseURL)"), "computed from the URL the command uses")
const pools = fs.readFileSync(path.join(__dirname, "AgentPoolsCard.tsx"), "utf8")
assert.ok(pools.includes('data-testid="pool-api-insecure"') && pools.includes("insecureApiWarning(apiUrl)"), "pool card warning")
// that both RENDER is proven by nodeInsecureApiRender.test.ts (the real components, mounted in jsdom)

console.log("insecure API URL tests passed")

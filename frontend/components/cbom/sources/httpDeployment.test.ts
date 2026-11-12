/**
 * CB-08: on a ZeroShield deployment that is not served over HTTPS, the Scan nodes tab printed a `docker run` / Helm
 * command and told the customer to open outbound port 80, but the scan node refuses any ZS_API_URL that is not https://
 * (scan_node/zs_scan_node/agent.py, "ZS_API_URL must be the ZeroShield API URL over https://"): the command could never
 * work. Now the tab says so instead of a command, gives no port advice and does not create a node whose token is useless.
 * Live check: G3 on an http variant build (cbom/cb-08/live/).
 * Run: npx --yes tsx components/cbom/sources/httpDeployment.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

import * as logic from "./logic"

const tab = fs.readFileSync(path.join(__dirname, "ScanNodesTab.tsx"), "utf8")
const pools = fs.readFileSync(path.join(__dirname, "AgentPoolsCard.tsx"), "utf8")
const agent = fs.readFileSync(path.join(__dirname, "../../../../scan_node/zs_scan_node/agent.py"), "utf8")

// the behaviour the copy follows: the node accepts https:// only (ZS_ALLOW_INSECURE_HTTP is a lab switch, never shown)
assert.ok(agent.includes('if not (self.api_url.startswith("https://") or (insecure_ok and self.api_url.startswith("http://"))):'),
  "the scan node still refuses a non-https API URL; if that changed, change this copy too")

// no port 80 advice, and no install command built from a plain-HTTP address
assert.ok(!tab.includes('url.protocol === "http:" ? "80"'), "the Scan nodes tab must not tell customers to open port 80")
assert.ok(tab.includes("const apiProblem = nodeApiProblem(apiBaseURL);"), "the tab checks the API address once")
assert.ok(tab.includes("const command = created && !apiProblem"), "no command is built for a plain-HTTP API")
assert.ok(tab.includes('data-testid="node-api-not-https"'), "the tab says why instead")
assert.ok(tab.includes("disabled={createMutation.isPending || !!apiProblem}"), "no node (and no useless token) is created")
assert.ok(pools.includes("nodeApiProblem(apiUrl)"), "the host-agent Helm command follows the same rule")

const { NODE_API_NOT_HTTPS, nodeApiPort, nodeApiProblem } = logic as unknown as {
  NODE_API_NOT_HTTPS: string
  nodeApiPort: (url: string) => string | null
  nodeApiProblem: (url: string) => string | null
}
assert.equal(NODE_API_NOT_HTTPS, "This ZeroShield deployment is not served over HTTPS; scan nodes refuse it. Ask your administrator to serve the API over HTTPS.")
assert.equal(nodeApiProblem("https://devsecshieldapi.zeroshield.ai"), null)
assert.equal(nodeApiProblem("https://api.dss.test:8443/"), null)
assert.equal(nodeApiProblem("http://devsec-staging-api.zeroshield.ai"), NODE_API_NOT_HTTPS)
assert.equal(nodeApiProblem("HTTP://API.EXAMPLE"), NODE_API_NOT_HTTPS)
assert.equal(nodeApiProblem(""), NODE_API_NOT_HTTPS)
assert.equal(nodeApiProblem("not a url"), NODE_API_NOT_HTTPS)
assert.equal(nodeApiPort("https://devsecshieldapi.zeroshield.ai"), "443")
assert.equal(nodeApiPort("https://api.dss.test:8443"), "8443")
assert.equal(nodeApiPort("http://devsec-staging-api.zeroshield.ai"), null, "no port for a deployment nodes cannot use")
assert.equal(nodeApiPort("http://api.example:80"), null)
console.log("http deployment tests passed")

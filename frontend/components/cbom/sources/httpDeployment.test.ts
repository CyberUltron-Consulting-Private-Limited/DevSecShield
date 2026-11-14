/**
 * CB-08: a ZeroShield deployment that is not served over HTTPS. The scan node refuses a plain-HTTP API unless it is
 * started with the lab switch ZS_ALLOW_INSECURE_HTTP=1 (scan_node/zs_scan_node/agent.py; Helm `allowInsecureHttp`;
 * the AMI's /etc/zs-node/env). So the wizard's warning (logic.insecureApiWarning, CB-03) says so, no port 80 is ever
 * advised, "Create node" keeps working (deploy/local is a plain-HTTP lab) and the command is shown only inside a
 * "Test lab only" block that carries the switch and the warning. Every token the UI mints is shown. Review
 * 5876424957: rendered, not grepped (the wizard's warning itself: nodeInsecureApiRender.test.ts, jsdom).
 * Live check: cbom/cb-08/live/ (http and https variant builds in Chromium).
 * Run: npx --yes tsx components/cbom/sources/httpDeployment.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { createElement as h, type ReactElement } from "react"
import { renderToStaticMarkup } from "react-dom/server"

import { helmAgentCommand, insecureApiWarning, installCommand, labSwitchHelps, nodeApiPort } from "./logic"
import { ApiEgressRow, NodeInstallCommand, PoolHelmCommand } from "./NodeInstall"

// block and cell tags become spaces; inline tags (the syntax highlighter's token spans) join their text
const text = (el: ReactElement) =>
  renderToStaticMarkup(el).replace(/<\/?(td|th|tr|p|div|li|ul|table|tbody|pre|button|h\d)\b[^>]*>/g, " ").replace(/<[^>]+>/g, "")
    .replace(/&#x27;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, "&").replace(/[ \t]+/g, " ")

const HTTP = "http://devsec-staging-api.zeroshield.ai"
const HTTPS = "https://devsecshieldapi.zeroshield.ai"
const TOKEN = "zsr_TESTONLY_cb08"
const IMAGE = "localhost/zeroshield/cbom-scan-node:1.0.0"

async function main() {
  // the behaviour the copy follows: https://, or http:// only with the lab switch
  const agent = fs.readFileSync(path.join(__dirname, "../../../../scan_node/zs_scan_node/agent.py"), "utf8")
  assert.ok(agent.includes('insecure_ok = os.environ.get("ZS_ALLOW_INSECURE_HTTP") == "1"'))
  assert.ok(agent.includes('if not (self.api_url.startswith("https://") or (insecure_ok and self.api_url.startswith("http://"))):'))
  const helm = fs.readFileSync(path.join(__dirname, "../../../../deploy/helm/cbom-scan-node/templates/_helpers.tpl"), "utf8")
  assert.ok(helm.includes("{{- if .Values.allowInsecureHttp }}\n- name: ZS_ALLOW_INSECURE_HTTP"), "the Helm switch")

  // the warning (logic.insecureApiWarning, CB-03; also nodeInsecureApi*.test.ts) names the lab switch for http://
  const warning = insecureApiWarning(HTTP)
  assert.ok(warning && warning.includes("The scan node refuses http:// unless it is started with ZS_ALLOW_INSECURE_HTTP=1"), warning ?? "")
  assert.ok(warning && /credentials unencrypted/.test(warning) && /"Test lab only"/.test(warning))
  assert.ok(!/ZS_ALLOW_INSECURE_HTTP/.test(insecureApiWarning("HTTP://API.EXAMPLE") ?? ""), "upper case: the switch does not help")
  for (const url of [HTTPS, "https://api.dss.test:8443/"]) assert.equal(insecureApiWarning(url), null, url)
  // the lab switch helps exactly where agent.py accepts it: a lower-case http:// URL (after strip)
  for (const url of [HTTP, " http://x ", "http://api.example:80"]) assert.ok(labSwitchHelps(url), url)
  for (const url of [HTTPS, "HTTP://API.EXAMPLE", "ftp://x", "ws://x", "", "not a url"]) assert.ok(!labSwitchHelps(url), url)
  assert.equal(nodeApiPort(HTTPS), "443")
  assert.equal(nodeApiPort("https://api.dss.test:8443"), "8443")
  assert.equal(nodeApiPort(HTTP), null, "no port advice (never 80) for a plain-HTTP API")
  assert.equal(nodeApiPort("http://api.example:80"), null)
  assert.equal(nodeApiPort("https://api.example:80"), null, "port 80 is the plain-HTTP port")
  assert.equal(nodeApiPort("ftp://x"), null)

  // the lab switch in each command, and only when asked for
  const opts = { token: TOKEN, apiUrl: HTTP, image: IMAGE, name: "lab-1" }
  assert.ok(installCommand("docker", { ...opts, insecureHttp: true }).includes("  -e ZS_ALLOW_INSECURE_HTTP=1 \\"))
  assert.ok(!installCommand("docker", { ...opts, apiUrl: HTTPS }).includes("ZS_ALLOW_INSECURE_HTTP"))
  assert.ok(installCommand("helm", { ...opts, insecureHttp: true }).includes("--set allowInsecureHttp=true"))
  assert.ok(installCommand("ami", { ...opts, insecureHttp: true }).includes("      ZS_ALLOW_INSECURE_HTTP=1"))
  assert.ok(helmAgentCommand({ poolToken: TOKEN, apiUrl: HTTP, image: IMAGE, insecureHttp: true }).includes("--set allowInsecureHttp=true"))
  assert.ok(!helmAgentCommand({ poolToken: TOKEN, apiUrl: HTTPS, image: IMAGE }).includes("allowInsecureHttp"))

  // rendered pieces

  const labDocker = text(h(NodeInstallCommand, { apiUrl: HTTP, method: "docker", token: TOKEN, name: "lab-1", image: IMAGE }))
  assert.match(labDocker, /Test lab only/)
  assert.match(labDocker, /credentials travel unencrypted/)
  assert.ok(labDocker.includes("-e ZS_ALLOW_INSECURE_HTTP=1") && labDocker.includes(TOKEN), "the lab command carries the switch and the token")
  const prodDocker = text(h(NodeInstallCommand, { apiUrl: HTTPS, method: "docker", token: TOKEN, name: "n1", image: IMAGE }))
  assert.ok(prodDocker.includes(`ZS_API_URL='${HTTPS}'`) && prodDocker.includes(TOKEN))
  assert.ok(!/Test lab only|ZS_ALLOW_INSECURE_HTTP/.test(prodDocker), "no lab switch on an https deployment")
  const labHelm = text(h(NodeInstallCommand, { apiUrl: HTTP, method: "helm", token: TOKEN, name: "lab-1", image: IMAGE }))
  assert.ok(labHelm.includes("--set allowInsecureHttp=true") && /Test lab only/.test(labHelm))
  // the OVA has no switch: its properties (and token) are still shown, with why it cannot reach this API
  const labOva = text(h(NodeInstallCommand, { apiUrl: HTTP, method: "ova", token: TOKEN, name: "lab-1", image: IMAGE }))
  assert.ok(labOva.includes(TOKEN) && labOva.includes("The OVA has no plain-HTTP switch"), labOva)

  const labPool = text(h(PoolHelmCommand, { apiUrl: HTTP, poolToken: TOKEN, image: IMAGE }))
  assert.ok(labPool.includes("--set allowInsecureHttp=true") && labPool.includes(TOKEN) && /Test lab only/.test(labPool))
  const prodPool = text(h(PoolHelmCommand, { apiUrl: HTTPS, poolToken: TOKEN, image: IMAGE }))
  assert.ok(prodPool.includes(TOKEN) && !/allowInsecureHttp|Test lab only/.test(prodPool))

  const row = (apiUrl: string) => text(h("table", null, h("tbody", null, h(ApiEgressRow, { apiUrl }))))
  assert.match(row(HTTPS), /devsecshieldapi\.zeroshield\.ai 443 Jobs in, results out \(HTTPS\)/)
  assert.match(row("https://api.dss.test:8443"), / 8443 /)
  assert.ok(!/\b80\b/.test(row(HTTP)) && row(HTTP).includes("—") && /test-lab nodes only/.test(row(HTTP)), row(HTTP))
  assert.match(row("https://api.example:80"), /— Not usable as it is/)

  // the whole tab, as a customer first sees it
  const { default: ScanNodesTab } = await import("./ScanNodesTab")
  const { cbomSourcesKeys } = await import("./keys")
  const tab = (apiUrl: string) => {
    const client = new QueryClient()
    client.setQueryData(cbomSourcesKeys.nodes(7), { nodes: [], server_time: "2026-11-12T12:00:00Z" })
    return text(h(QueryClientProvider, { client }, h(ScanNodesTab, { teamId: 7, onNavigate: () => {}, apiUrl })))
  }
  const httpTab = tab(HTTP)
  assert.ok(!/port 80\b/.test(httpTab) && !httpTab.includes("on port 80"), "no port 80 advice")
  assert.match(httpTab, /One node per network segment\. /)
  assert.ok(!/connects out to ZeroShield on port/.test(httpTab), "no port for a plain-HTTP API")
  assert.match(httpTab, /It only connects out to devsec-staging-api\.zeroshield\.ai\./)
  assert.match(httpTab, /Add your first scan node/)
  const httpsTab = tab(HTTPS)
  assert.match(httpsTab, /Each connects out to ZeroShield on port 443 only\./)
  assert.match(httpsTab, /It only connects out to devsecshieldapi\.zeroshield\.ai on port 443\./)
  console.log("http deployment tests passed")
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})

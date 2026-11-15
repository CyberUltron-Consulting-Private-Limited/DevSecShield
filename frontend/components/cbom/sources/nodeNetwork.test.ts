/**
 * #181 (SOC table without host-agent nodes), #200 (DNS in the outbound table and the claims), #202 (TLS inspection
 * needs a proxy and its CA), #203 (an inspecting proxy can read credentials and jobs).
 * Run: npx --yes tsx components/cbom/sources/nodeNetwork.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import type { CbomScanNode } from "@/utils/backend_api";

import { DNS_EGRESS, inspectionWarning, socNodes, wizardProxyProblem } from "./nodeNetwork";

const node = (id: number, mode?: "agent" | "agentless") => ({ id, name: `n${id}`, mode, source_ips: [] }) as unknown as CbomScanNode;
const soc = socNodes([node(1, "agentless"), node(2, "agent"), node(3), node(4, "agent")]);
assert.deepEqual(soc.listed.map((n) => n.id), [1, 3]);
assert.equal(soc.agents, 2);

assert.equal(wizardProxyProblem({ tlsInspect: false, proxyUrl: "", proxyCa: "" }), null);
assert.match(wizardProxyProblem({ tlsInspect: true, proxyUrl: "", proxyCa: "" }) ?? "", /Enter the proxy/);
assert.match(wizardProxyProblem({ tlsInspect: true, proxyUrl: "http://p:8080", proxyCa: " " }) ?? "", /CA certificate/);
assert.equal(wizardProxyProblem({ tlsInspect: true, proxyUrl: "http://p:8080", proxyCa: "-----BEGIN CERTIFICATE-----" }), null);

const warning = inspectionWarning("devsecshieldapi.zeroshield.ai");
assert.match(warning, /registration token and node credential/);
assert.match(warning, /logins/);
assert.match(warning, /exempt devsecshieldapi\.zeroshield\.ai from TLS inspection/);
assert.match(DNS_EGRESS.port, /^53/);

const here = path.dirname(new URL(import.meta.url).pathname);
const nodesTab = fs.readFileSync(path.join(here, "ScanNodesTab.tsx"), "utf8");
assert.match(nodesTab, /data-testid="node-egress-dns"/);
assert.match(nodesTab, /inspectionWarning\(apiHost\(apiUrl\)\)/);
assert.match(nodesTab, /wizardProxyProblem\(wizard\)/);
assert.match(nodesTab, /to your DNS resolver \(port 53\)/);
const network = fs.readFileSync(path.join(here, "NetworkTab.tsx"), "utf8");
assert.match(network, /soc\.listed\.map/);
assert.doesNotMatch(network, /\{nodes\.map\(\(n\) => \(\s*<SocRow/);
// the backend refuses the same as the wizard (#202)
const schemas = fs.readFileSync(path.join(here, "../../../../backend/utilities/cbom_sources/schemas.py"), "utf8");
assert.match(schemas, /def proxy_inspect_problem/);
console.log("nodeNetwork.test.ts: ok");

// Scan-node network facts shown to customers (#181, #200, #202, #203), kept apart from the tabs so they are tested
// without a browser.
import type { CbomScanNode } from "@/utils/backend_api";

/** #200: a node also looks names up (the API host, and target host names) through its DNS resolver. */
export const DNS_EGRESS = {
  destination: "Your DNS resolver",
  port: "53 (UDP and TCP)",
  usedFor: "Looking up the ZeroShield API host and your targets' host names",
} as const;

/** #181: only agentless nodes scan networks; host-agent nodes (agent mode, one per Kubernetes node) never do. */
export function socNodes(nodes: CbomScanNode[]): { listed: CbomScanNode[]; agents: number } {
  const listed = nodes.filter((n) => n.mode !== "agent");
  return { listed, agents: nodes.length - listed.length };
}

/** #202: "My proxy inspects TLS" needs the proxy and the proxy's CA (backend schemas.proxy_inspect_problem). */
export function wizardProxyProblem(w: { tlsInspect: boolean; proxyUrl: string; proxyCa: string }): string | null {
  if (!w.tlsInspect) return null;
  if (!w.proxyUrl.trim()) return "Enter the proxy that inspects TLS, or untick \"My proxy inspects TLS\".";
  if (!w.proxyCa.trim()) return "Upload the CA certificate your proxy signs with, so the node trusts only that proxy.";
  return null;
}

/** #203: what an inspecting proxy can read, and the bypass to ask for. */
export function inspectionWarning(apiHostName: string): string {
  return `A proxy that inspects TLS can read everything the node sends and receives: its registration token and node ` +
    `credential, and the jobs it runs, which carry the server and database logins they use. Ask your proxy team to ` +
    `exempt ${apiHostName} from TLS inspection (a bypass rule), then untick this box.`;
}

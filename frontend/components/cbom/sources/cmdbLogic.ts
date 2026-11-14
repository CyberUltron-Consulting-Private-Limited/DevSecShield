// CMDB import dialog logic (#225), kept apart from the dialog so it is tested without a browser.
import type { CmdbPlanCreate } from "@/utils/api/integrations";
import type { CbomScanNode } from "@/utils/backend_api";

/** Segments that more than one agentless scan node serves: the import needs a choice for each (#225). */
export function sharedSegments(nodes: CbomScanNode[]): { segment: string; nodes: CbomScanNode[] }[] {
  const by = new Map<string, { segment: string; nodes: CbomScanNode[] }>();
  for (const n of nodes) {
    const seg = (n.segment ?? "").trim();
    if (!seg || n.mode === "agent") continue;
    const slot = by.get(seg.toLowerCase()) ?? { segment: seg, nodes: [] };
    slot.nodes.push(n);
    by.set(seg.toLowerCase(), slot);
  }
  return Array.from(by.values()).filter((s) => s.nodes.length > 1).sort((a, b) => a.segment.localeCompare(b.segment));
}

export function createLine(c: CmdbPlanCreate): string {
  const cfg = (c.config ?? {}) as Record<string, string | number | undefined>;
  const what = c.kind === "network_range" ? `network range ${c.cidr}`
    : c.kind === "linux_servers" ? `${c.targets?.length ?? 0} Linux hosts`
    : c.kind === "windows_servers" ? `${c.targets?.length ?? 0} Windows hosts, WinRM login from the vault`
    : c.kind === "database" ? `${cfg.engine} database ${cfg.host}:${cfg.port}`
    : c.kind === "kubernetes" ? `Kubernetes cluster ${cfg.api_url}`
    : `HSM ${cfg.module}${cfg.token_label ? ` token ${cfg.token_label}` : ""}`;
  const where = c.node_name ? ` on ${c.node_name}${c.segment ? ` (segment ${c.segment})` : ""}` : " on the chosen scan node";
  return what + where;
}

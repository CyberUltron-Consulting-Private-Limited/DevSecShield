// CMDB import dialog logic (#225), kept apart from the dialog so it is tested without a browser.
import type { CmdbPlan, CmdbPlanCreate } from "@/utils/api/integrations";
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

/** #367: the nodes the import offers: registered agentless nodes only (an agent-mode node collects only its own host;
 * one that never registered cannot run a job), with how many were left out and why. */
export function importNodes(nodes: CbomScanNode[]): { usable: CbomScanNode[]; agents: number; waiting: number } {
  const agentless = nodes.filter((n) => n.mode !== "agent");
  const usable = agentless.filter((n) => n.status === "online" || n.status === "offline");
  return { usable, agents: nodes.length - agentless.length, waiting: agentless.length - usable.length };
}

export function leftOutLine(left: { agents: number; waiting: number }): string | null {
  const parts = [
    left.agents ? `${left.agents} host-agent node${left.agents === 1 ? "" : "s"} (they collect only their own host)` : "",
    left.waiting ? `${left.waiting} node${left.waiting === 1 ? "" : "s"} not registered yet` : "",
  ].filter(Boolean);
  return parts.length ? `Not offered: ${parts.join("; ")}.` : null;
}

/** #367: a picker for each segment the file uses that more than one registered node serves (from the preview). */
export function segmentPickers(plan: CmdbPlan | null, usable: CbomScanNode[]): { segment: string; rows: number; nodes: CbomScanNode[] }[] {
  const byId = new Map(usable.map((n) => [n.id, n]));
  return (plan?.segments ?? [])
    .filter((s) => s.nodes.length > 1)
    .map((s) => ({ segment: s.segment, rows: s.rows, nodes: s.nodes.map((n) => byId.get(n.id)).filter((n): n is CbomScanNode => !!n) }))
    .filter((s) => s.nodes.length > 1);
}

/** #363: the engines whose logins need the server's CA, and their names. */
export const CA_ENGINES: { value: string; label: string }[] = [
  { value: "*", label: "Every engine below without its own" },
  { value: "mysql", label: "MySQL" },
  { value: "mssql", label: "SQL Server" },
  { value: "oracle", label: "Oracle" },
  { value: "mongodb", label: "MongoDB" },
  { value: "redis", label: "Redis" },
];

/** #366: classes that keep the dialog's content inside the dialog at every width. */
export const DIALOG_LAYOUT = {
  content: "sm:max-w-3xl max-h-[90vh] overflow-y-auto overflow-x-hidden",
  body: "space-y-4 min-w-0",
  // the shared Textarea sizes to its content (field-sizing: content): a long CSV line widened the whole dialog
  csv: "font-mono text-xs min-h-[140px] max-h-[40vh] [field-sizing:fixed] w-full max-w-full min-w-0 overflow-auto whitespace-pre",
  text: "min-w-0 break-words [overflow-wrap:anywhere]",
} as const;

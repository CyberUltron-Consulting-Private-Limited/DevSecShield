"use client";

/**
 * AI BOM-specific visualizations. Every chart is built from the SAME primitives
 * the other scanners use — shadcn Card/Table/Badge, Recharts via
 * components/ui/chart, @xyflow/react (the platform's graph lib), and the shared
 * severity palette — so the AI BOM page stays visually native to DevSecShield.
 *
 * Each section is an independent component; AiBomVisualizations composes them.
 */

import { useMemo, useState } from "react";
import {
  Bar,
  BarChart,
  Cell,
  XAxis,
  YAxis,
} from "recharts";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
} from "@/components/ui/chart";
import {
  HoverCard,
  HoverCardContent,
  HoverCardTrigger,
} from "@/components/ui/hover-card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Network,
  Activity,
  EyeOff,
  MapPin,
  FileText,
} from "lucide-react";
import {
  ComplianceMatrix,
  type AttestHandler,
  type Compliance,
  type FrameworkGroup,
} from "@/components/compliance/ComplianceMatrix";
import { FRAMEWORK_GROUPS_AIBOM_WITH_INDIA } from "@/components/compliance/frameworkLabels";
import {
  buildModelCandidates,
  fillModelCardRows,
  pickDefaultModel,
} from "@/components/ai-bom/modelCardDisplay";
import { BomGraphCard } from "@/components/bom/BomGraphCard";
import { pickBomGraph } from "@/components/bom/layout";
import type { BomGraph } from "@/components/bom/types";

export type { AttestHandler, Compliance } from "@/components/compliance/ComplianceMatrix";

// ── shared tokens (mirror getImpactBadgeClass + the locked risk bands) ──────
const C = {
  pass: "#10b981", // emerald-500
  pass_with_evidence: "#14b8a6", // teal-500 (satisfied by attestation; counts as pass)
  fail: "#dc2626", // red-600  (== critical)
  out_of_scope: "#64748b", // slate-500 (framework doesn't apply — NOT fail/na)
  not_bom_evidenceable: "#8b5cf6", // violet-500 (process evidence; attestable)
  na: "#a1a1aa", // zinc-400 (truly neither)
  low: "#3b82f6", // blue-500
  medium: "#f59e0b", // amber-500
  high: "#f97316", // orange-500
  critical: "#dc2626", // red-600
};
// 0-100 normalized -> band (the LOCKED scale: low<=33, medium<=66, else high)
const bandColor = (band?: string) =>
  band === "high" ? C.high : band === "medium" ? C.medium : C.low;

// ── types (the FE-exposed run-object shapes) ────────────────────────────────
interface GNode {
  id: string;
  label: string;
  kind: string;
  type?: string;
  cluster?: boolean;
  is_cluster?: boolean;
  cluster_count?: number;
  clustered_count?: number;
  member_ids?: string[];
}
interface GEdge {
  source: string;
  target: string;
  rel: string;
}
export interface Graph {
  nodes: GNode[];
  edges: GEdge[];
  meta?: {
    raw_node_count?: number;
    view_node_count?: number;
    clustered_members?: number;
    max_nodes?: number;
  };
}
export interface Scores {
  risk_normalized?: number;
  risk_band?: string;
  by_component?: Record<string, number>;
}
type Json = Record<string, unknown>;

// ════════════════════════════════════════════════════════════════════════════
// 1. Compliance coverage — thin wrapper over shared ComplianceMatrix (Phase 0).
// Keeps local attestation file picker affordance for AIBOM/SBOM.
// ════════════════════════════════════════════════════════════════════════════
export function ComplianceCoverage({
  compliance,
  groups = FRAMEWORK_GROUPS_AIBOM_WITH_INDIA,
  defaultGroup = "all",
  onAttest,
}: {
  compliance?: Compliance;
  groups?: FrameworkGroup[];
  defaultGroup?: string;
  onAttest?: AttestHandler;
}) {
  return (
    <ComplianceMatrix
      compliance={compliance}
      title="Regulatory Compliance Readiness"
      icon="shield"
      enableAttestation
      onAttest={onAttest}
      groups={groups}
      defaultGroup={defaultGroup}
      className="col-span-full"
    />
  );
}

// ════════════════════════════════════════════════════════════════════════════
// 2. Typed-edge dependency graph (trained_on / depends_on / served_by / deployed_at).
// ════════════════════════════════════════════════════════════════════════════
export function DependencyGraph({
  graph,
  graphCompact,
  graphExpanded,
}: {
  graph?: Graph | BomGraph | null;
  graphCompact?: Graph | BomGraph | null;
  graphExpanded?: Graph | BomGraph | null;
}) {
  const compact = useMemo(
    () =>
      pickBomGraph({
        mode: "compact",
        full: graph as BomGraph | null | undefined,
        compact: graphCompact as BomGraph | null | undefined,
        expanded: graphExpanded as BomGraph | null | undefined,
      }),
    [graph, graphCompact, graphExpanded]
  );
  const expanded = useMemo(
    () =>
      pickBomGraph({
        mode: "expanded",
        full: graph as BomGraph | null | undefined,
        compact: graphCompact as BomGraph | null | undefined,
        expanded: graphExpanded as BomGraph | null | undefined,
      }),
    [graph, graphCompact, graphExpanded]
  );
  if (!compact || (compact.nodes?.length ?? 0) === 0) return null;
  return (
    <BomGraphCard
      lane="aibom"
      graph={compact}
      expandedGraph={expanded}
      title="AI Supply-Chain Graph"
      description="Typed lineage — model → training data, libraries, serving vendor, and deployment sites."
      icon={<Network className="w-4 h-4 text-indigo-500" />}
      heightClass="h-[340px]"
    />
  );
}

// ════════════════════════════════════════════════════════════════════════════
// 3. Risk heatmap by component — the LOCKED 0-100 scale + band.
// ════════════════════════════════════════════════════════════════════════════
export function RiskHeatmap({ scores }: { scores?: Scores }) {
  const data = useMemo(() => {
    const byc = scores?.by_component ?? {};
    return Object.entries(byc)
      .map(([id, v]) => ({ name: id, value: Number(v) }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 12);
  }, [scores]);
  if (data.length === 0) return null;
  const max = Math.max(1, ...data.map((d) => d.value));
  const tone = (v: number) =>
    v / max <= 0.34 ? C.low : v / max <= 0.66 ? C.medium : C.high;
  const band = scores?.risk_band;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <Activity className="w-4 h-4 text-orange-500" /> Risk by Component
        </CardTitle>
        <CardDescription>
          Normalized risk{" "}
          <span className="font-semibold text-zinc-700 dark:text-zinc-300">
            {scores?.risk_normalized ?? 0}/100
          </span>{" "}
          ·{" "}
          <span
            className="rounded px-1.5 py-0.5 text-xs font-semibold text-white"
            style={{ background: bandColor(band) }}
          >
            {(band ?? "low").toUpperCase()}
          </span>{" "}
          band (locked scale)
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ChartContainer config={{}} className="aspect-auto h-[240px] w-full">
          <BarChart data={data} layout="vertical" margin={{ left: 8, right: 16 }}>
            <XAxis type="number" hide />
            <YAxis dataKey="name" type="category" width={150} tickLine={false} axisLine={false} className="text-[10px]" />
            <ChartTooltip content={<ChartTooltipContent />} />
            <Bar dataKey="value" radius={3}>
              {data.map((d, i) => (
                <Cell key={i} fill={tone(d.value)} />
              ))}
            </Bar>
          </BarChart>
        </ChartContainer>
      </CardContent>
    </Card>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// 4. Shadow AI — unsanctioned / ungoverned components (existing severity styling).
// ════════════════════════════════════════════════════════════════════════════
function humanizeRisk(raw: unknown): string {
  const s = String(raw ?? "").trim();
  if (!s) return "Ungoverned / third-party AI surface";
  return s.replace(/_/g, " ");
}

function transparencyLines(f: Json): string[] {
  const lines: string[] = [];
  const compliance = f.compliance_controls;
  if (compliance && typeof compliance === "object" && !Array.isArray(compliance)) {
    for (const [k, v] of Object.entries(compliance as Record<string, unknown>)) {
      if (k && v != null && String(v).trim()) lines.push(`${k}: ${String(v)}`);
    }
  }
  const owasp = f.owasp_top_10_llm;
  if (owasp && typeof owasp === "object" && !Array.isArray(owasp)) {
    for (const [k, v] of Object.entries(owasp as Record<string, unknown>)) {
      if (k && v != null && String(v).trim()) lines.push(String(v));
      else if (k) lines.push(k);
    }
  }
  const license = String(f.license_type ?? "").trim();
  if (license) lines.push(`License: ${license}`);
  return lines;
}

export function ShadowAI({
  findings,
  onOpenFinding,
}: {
  findings?: Json[];
  onOpenFinding?: (finding: Json) => void;
}) {
  const shadow = (findings ?? []).filter(
    (f) =>
      String(f.risk_category ?? "").includes("missing_model_card_lineage") ||
      String(f.asset_type ?? "") === "external_provider"
  );
  const [openKey, setOpenKey] = useState<string | null>(null);
  return (
    <Card data-testid="shadow-ai-card">
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <EyeOff className="w-4 h-4 text-amber-500" /> Shadow AI
          {shadow.length > 0 && (
            <span className="text-xs font-normal text-zinc-500">({shadow.length})</span>
          )}
        </CardTitle>
        <CardDescription>
          Ungoverned / third-party AI surfaces (no model-card lineage or external
          provider).
        </CardDescription>
      </CardHeader>
      <CardContent>
        {shadow.length === 0 ? (
          <p className="text-sm text-zinc-500 py-6 text-center">
            No shadow-AI components detected.
          </p>
        ) : (
          <ul className="max-h-[28rem] space-y-2 overflow-y-auto pr-1">
            {shadow.map((f, i) => {
              const key = String(f.id ?? i);
              const name = String(f.asset_name ?? f.title ?? "—");
              const typeLine = `${String(f.asset_type ?? "")}${
                f.provider ? ` · ${f.provider}` : ""
              }`;
              const location = String(f.location ?? "").trim();
              const description = String(f.description ?? "").trim() || "—";
              const fix = String(f.suggested_fix ?? "").trim() || "—";
              const transparency = transparencyLines(f);
              const snippet = String(f.snippet ?? "").trim();
              return (
                <li
                  key={key}
                  onMouseEnter={() => setOpenKey(key)}
                  onFocusCapture={() => setOpenKey(key)}
                  onClick={() => setOpenKey(key)}
                  onMouseLeave={(e) => {
                    const to = e.relatedTarget as HTMLElement | null;
                    if (to?.closest?.('[data-slot="hover-card-content"]')) return;
                    // Portal gap: relatedTarget can be null while moving to content
                    if (!to) return;
                    setOpenKey((cur) => (cur === key ? null : cur));
                  }}
                >
                  <HoverCard
                    open={openKey === key}
                    onOpenChange={(next) => {
                      if (next) setOpenKey(key);
                    }}
                    openDelay={0}
                    closeDelay={200}
                  >
                    <HoverCardTrigger asChild>
                      <div
                        data-testid="shadow-ai-row"
                        data-shadow-open={openKey === key ? "true" : "false"}
                        className="flex w-full items-start justify-between gap-2 rounded-lg border border-amber-200 dark:border-amber-900/40 bg-amber-50/60 dark:bg-amber-900/10 px-3 py-2 cursor-default"
                      >
                        <div className="min-w-0 flex-1">
                          <div className="text-sm font-medium text-zinc-800 dark:text-zinc-100 break-all whitespace-normal">
                            {name}
                          </div>
                          <div className="text-xs text-zinc-500 break-words whitespace-normal">
                            {typeLine}
                          </div>
                        </div>
                        <Badge
                          data-testid="shadow-ai-impact"
                          className="shrink-0 bg-amber-500 hover:bg-amber-600 text-white"
                        >
                          {String(f.impact ?? "review")}
                        </Badge>
                      </div>
                    </HoverCardTrigger>
                    <HoverCardContent
                      align="start"
                      side="bottom"
                      className="w-80 max-w-sm space-y-3 text-xs z-[100]"
                      onMouseEnter={() => setOpenKey(key)}
                      onMouseLeave={() =>
                        setOpenKey((cur) => (cur === key ? null : cur))
                      }
                    >
                      <div>
                        <p className="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">
                          Asset
                        </p>
                        <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100 break-all">
                          {name}
                        </p>
                      </div>
                      <div>
                        <p className="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">
                          Why
                        </p>
                        <p className="text-sm text-zinc-700 dark:text-zinc-300">
                          {humanizeRisk(f.risk_category)}
                          {f.impact ? ` · ${String(f.impact)}` : ""}
                        </p>
                      </div>
                      <div>
                        <p className="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">
                          Description
                        </p>
                        <p className="text-sm text-zinc-700 dark:text-zinc-300 whitespace-pre-wrap break-words">
                          {description}
                        </p>
                      </div>
                      <div>
                        <p className="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">
                          How to fix
                        </p>
                        <p className="text-sm text-zinc-700 dark:text-zinc-300 whitespace-pre-wrap break-words">
                          {fix}
                        </p>
                      </div>
                      <div>
                        <p className="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">
                          Location
                        </p>
                        <p className="text-sm font-mono text-zinc-700 dark:text-zinc-300 break-all">
                          {location || "Location not recorded"}
                        </p>
                        {snippet ? (
                          <pre className="mt-1 max-h-24 overflow-auto rounded border border-zinc-200 bg-zinc-50 p-2 text-[10px] dark:border-zinc-700 dark:bg-zinc-900 whitespace-pre-wrap break-all">
                            {snippet}
                          </pre>
                        ) : null}
                      </div>
                      {transparency.length > 0 && (
                        <div>
                          <p className="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">
                            Transparency
                          </p>
                          <ul className="mt-1 space-y-0.5 text-sm text-zinc-700 dark:text-zinc-300">
                            {transparency.map((line, idx) => (
                              <li key={idx} className="break-words">
                                {line}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                      {onOpenFinding && (
                        <Button
                          type="button"
                          size="sm"
                          variant="outline"
                          className="h-8 w-full cursor-pointer"
                          onClick={(e) => {
                            e.preventDefault();
                            e.stopPropagation();
                            setOpenKey(null);
                            onOpenFinding(f);
                          }}
                        >
                          View full finding
                        </Button>
                      )}
                    </HoverCardContent>
                  </HoverCard>
                </li>
              );
            })}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// 5. Per-site drift / validation (deployed_at sites from the CycloneDX BOM).
// ════════════════════════════════════════════════════════════════════════════
interface Site {
  name: string;
  drift_status?: string;
  last_validated?: string;
  version?: string;
}
function extractSites(aiBomJson?: Json): Site[] {
  const comps = (aiBomJson?.components as Json[] | undefined) ?? [];
  const out: Site[] = [];
  for (const c of comps) {
    const props = (c.properties as { name: string; value: string }[] | undefined) ?? [];
    const site: Record<string, string> = {};
    for (const p of props) if (p.name?.startsWith("site:")) site[p.name.slice(5)] = p.value;
    if (Object.keys(site).length) out.push({ name: String(c.name ?? "site"), ...site });
  }
  return out;
}
export function MultiSiteDrift({ aiBomJson }: { aiBomJson?: Json }) {
  const sites = useMemo(() => extractSites(aiBomJson), [aiBomJson]);
  if (sites.length === 0) return null;
  return (
    <Card className="col-span-full">
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <MapPin className="w-4 h-4 text-rose-500" /> Deployment Sites & Drift
        </CardTitle>
        <CardDescription>
          Per-site version, last validation, and drift status (deployed_at edges).
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Site</TableHead>
              <TableHead>Version</TableHead>
              <TableHead>Last validated</TableHead>
              <TableHead>Drift</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {sites.map((s, i) => {
              const drifted = s.drift_status === "drift-detected";
              return (
                <TableRow key={i}>
                  <TableCell className="font-medium">{s.name}</TableCell>
                  <TableCell className="text-zinc-600 dark:text-zinc-400">{s.version ?? "—"}</TableCell>
                  <TableCell className="text-zinc-600 dark:text-zinc-400">{s.last_validated ?? "—"}</TableCell>
                  <TableCell>
                    <Badge
                      className={
                        drifted
                          ? "bg-red-600 hover:bg-red-700 text-white"
                          : "bg-blue-500 hover:bg-blue-600 text-white"
                      }
                    >
                      {s.drift_status ?? "not-assessed"}
                    </Badge>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// 6. Model-card detail panel (architecture / metrics / considerations).
// Never shows empty blanks; multi-model Select when inventory has >1 model.
// ════════════════════════════════════════════════════════════════════════════
export function ModelCardPanel({
  aiBomJson,
  findings,
}: {
  aiBomJson?: Json;
  findings?: Json[];
}) {
  const candidates = useMemo(
    () => buildModelCandidates(aiBomJson, findings),
    [aiBomJson, findings],
  );
  const defaultPick = useMemo(() => pickDefaultModel(candidates), [candidates]);
  // User override only — stale ids fall back to the computed default (no effect).
  const [userSelectedId, setUserSelectedId] = useState<string | null>(null);
  const selectedId =
    userSelectedId && candidates.some((c) => c.id === userSelectedId)
      ? userSelectedId
      : (defaultPick?.candidate.id ?? "");

  if (!defaultPick || candidates.length === 0) return null;

  const selected =
    candidates.find((c) => c.id === selectedId) ?? defaultPick.candidate;
  const reason =
    selected.id === defaultPick.candidate.id
      ? defaultPick.reason
      : "selected manually from inventoried models";
  const rows = fillModelCardRows(selected.component);
  const displayRows: [string, string][] = [
    ["Name", rows.name],
    ["Version", rows.version],
    ["Approach", rows.approach],
    ["Task", rows.task],
    ["Architecture family", rows.architectureFamily],
    ["Model architecture", rows.modelArchitecture],
    ["Card source", rows.cardSource],
  ];

  return (
    <Card data-testid="aibom-model-card-panel">
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <FileText className="w-4 h-4 text-violet-500" /> Model Card
        </CardTitle>
        <CardDescription>Architecture, task, and lineage metadata.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {candidates.length > 1 && (
          <div className="space-y-1.5">
            <label className="text-xs font-medium uppercase tracking-wide text-zinc-500">
              Model
            </label>
            <Select value={selected.id} onValueChange={setUserSelectedId}>
              <SelectTrigger className="h-9 w-full cursor-pointer" data-testid="aibom-model-card-select">
                <SelectValue placeholder="Select a model" />
              </SelectTrigger>
              <SelectContent>
                {candidates.map((c) => (
                  <SelectItem key={c.id} value={c.id}>
                    {c.name}
                    {c.hasCard ? "" : " (inferred)"}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        )}
        <p
          className="text-xs text-zinc-600 dark:text-zinc-400 rounded-md border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900/40 px-3 py-2"
          data-testid="aibom-model-card-banner"
        >
          Showing <span className="font-medium text-zinc-900 dark:text-zinc-100">{rows.name}</span>
          {" — "}
          {reason}
        </p>
        <dl className="divide-y divide-zinc-100 dark:divide-zinc-800">
          {displayRows.map(([k, v]) => (
            <div key={k} className="flex items-start justify-between gap-4 py-2">
              <dt className="text-xs font-medium uppercase tracking-wide text-zinc-500">{k}</dt>
              <dd className="text-sm text-right text-zinc-800 dark:text-zinc-200">{v}</dd>
            </div>
          ))}
        </dl>
      </CardContent>
    </Card>
  );
}

// ── composer ────────────────────────────────────────────────────────────────
export function AiBomVisualizations({
  compliance,
  graph,
  graphCompact,
  graphExpanded,
  scores,
  aiBomJson,
  findings,
  onAttest,
  onOpenFinding,
}: {
  compliance?: Compliance;
  graph?: Graph | BomGraph | null;
  graphCompact?: Graph | BomGraph | null;
  graphExpanded?: Graph | BomGraph | null;
  scores?: Scores;
  aiBomJson?: Json;
  findings?: Json[];
  onAttest?: AttestHandler;
  onOpenFinding?: (finding: Json) => void;
}) {
  const has =
    compliance ||
    graph ||
    graphCompact ||
    scores ||
    aiBomJson ||
    (findings && findings.length);
  if (!has) return null;
  return (
    <section className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-zinc-900 dark:text-zinc-100">
          AI Governance &amp; Lineage
        </h2>
        <p className="text-sm text-zinc-500">
          Healthcare AI-BOM insights — compliance readiness, supply-chain
          lineage, deployment drift, and model provenance.
        </p>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <ComplianceCoverage compliance={compliance} onAttest={onAttest} />
        <DependencyGraph
          graph={graph}
          graphCompact={graphCompact}
          graphExpanded={graphExpanded}
        />
        <MultiSiteDrift aiBomJson={aiBomJson} />
        <ModelCardPanel aiBomJson={aiBomJson} findings={findings} />
        <RiskHeatmap scores={scores} />
        <ShadowAI findings={findings} onOpenFinding={onOpenFinding} />
      </div>
    </section>
  );
}

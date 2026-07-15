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
  ReactFlow,
  Background,
  Controls,
  type Node,
  type Edge,
  MarkerType,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  Bar,
  BarChart,
  CartesianGrid,
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
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import {
  ShieldCheck,
  Network,
  Activity,
  EyeOff,
  MapPin,
  FileText,
} from "lucide-react";

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
const FRAMEWORK_LABELS: Record<string, string> = {
  fda_524b: "FDA §524B",
  eu_ai_act_annexIV: "EU AI Act (Annex IV)",
  gmlp: "GMLP (IMDRF)",
  hipaa: "HIPAA",
  nist_rmf: "NIST AI RMF",
  rbi_free_ai: "RBI FREE-AI",
  rbi_free_ai_supply: "RBI FREE-AI (Supply Chain)",
};
const VERDICT_BADGE: Record<string, string> = {
  pass: "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200",
  pass_with_evidence: "bg-teal-100 text-teal-800 dark:bg-teal-900/40 dark:text-teal-200",
  fail: "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-200",
  out_of_scope: "bg-slate-100 text-slate-700 dark:bg-slate-700/50 dark:text-slate-200",
  not_bom_evidenceable: "bg-violet-100 text-violet-800 dark:bg-violet-900/40 dark:text-violet-200",
  na: "bg-zinc-100 text-zinc-700 dark:bg-zinc-700/50 dark:text-zinc-200",
};
const VERDICT_LABEL: Record<string, string> = {
  pass: "Pass",
  pass_with_evidence: "Pass (evidence)",
  fail: "Fail",
  out_of_scope: "Out of scope",
  not_bom_evidenceable: "Not BOM-evidenceable",
  na: "N/A",
};
// 0-100 normalized -> band (the LOCKED scale: low<=33, medium<=66, else high)
const bandColor = (band?: string) =>
  band === "high" ? C.high : band === "medium" ? C.medium : C.low;

// ── types (the FE-exposed run-object shapes) ────────────────────────────────
type VerdictState =
  | "pass"
  | "pass_with_evidence"
  | "fail"
  | "out_of_scope"
  | "not_bom_evidenceable"
  | "na";
interface Requirement {
  id: string;
  title: string;
  verdict: VerdictState;
  evidence?: string;
  attestable?: boolean;
}
interface FrameworkCoverage {
  pass: number;
  pass_with_evidence?: number;
  fail: number;
  out_of_scope?: number;
  not_bom_evidenceable?: number;
  na: number;
  coverage: number | null;
  requirements?: Requirement[];
}
export type Compliance = Record<string, FrameworkCoverage | string>;
interface GNode {
  id: string;
  label: string;
  kind: string;
  type?: string;
}
interface GEdge {
  source: string;
  target: string;
  rel: string;
}
export interface Graph {
  nodes: GNode[];
  edges: GEdge[];
}
export interface Scores {
  risk_normalized?: number;
  risk_band?: string;
  by_component?: Record<string, number>;
}
type Json = Record<string, unknown>;

// ════════════════════════════════════════════════════════════════════════════
// 1. Compliance coverage per framework — pass / fail / NA kept DISTINCT.
// ════════════════════════════════════════════════════════════════════════════
export function ComplianceCoverage({ compliance }: { compliance?: Compliance }) {
  const frameworks = useMemo(
    () =>
      Object.entries(compliance ?? {})
        .filter(([k, v]) => k !== "disclaimer" && typeof v === "object")
        .map(([k, v]) => ({ key: k, ...(v as FrameworkCoverage) })),
    [compliance]
  );
  const [active, setActive] = useState<string | null>(null);
  // Minimal evidence-attachment affordance: a captured attestation marks the
  // requirement locally; the backend flips not_bom_evidenceable -> pass_with_evidence
  // when run_all() is re-run with this evidence (aibom.compliance.engine evidence=).
  const [attested, setAttested] = useState<Record<string, string>>({});

  if (frameworks.length === 0) return null;
  const data = frameworks.map((f) => ({
    name: FRAMEWORK_LABELS[f.key] ?? f.key,
    key: f.key,
    pass: f.pass,
    pass_with_evidence: f.pass_with_evidence ?? 0,
    fail: f.fail,
    out_of_scope: f.out_of_scope ?? 0,
    not_bom_evidenceable: f.not_bom_evidenceable ?? 0,
    na: f.na,
    coverage: f.coverage == null ? "n/a" : `${Math.round(f.coverage * 100)}%`,
  }));
  const cfg: ChartConfig = {
    pass: { label: "Pass", color: C.pass },
    pass_with_evidence: { label: "Pass (evidence)", color: C.pass_with_evidence },
    fail: { label: "Fail", color: C.fail },
    out_of_scope: { label: "Out of scope", color: C.out_of_scope },
    not_bom_evidenceable: { label: "Not BOM-evidenceable", color: C.not_bom_evidenceable },
    na: { label: "N/A", color: C.na },
  };
  const reqs = frameworks.find((f) => f.key === active)?.requirements ?? [];

  return (
    <Card className="col-span-full">
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-600" /> Regulatory
          Compliance Readiness
        </CardTitle>
        <CardDescription>
          Per-framework verdicts (advisory). Coverage = pass / (pass + fail).
          <span className="font-medium"> Out of scope</span> (framework doesn&apos;t
          apply) and <span className="font-medium">Not BOM-evidenceable</span>
          (process evidence) are reported separately — never folded into pass or
          fail. Click a bar for per-requirement detail.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ChartContainer config={cfg} className="aspect-auto h-[260px] w-full">
          <BarChart
            data={data}
            layout="vertical"
            margin={{ top: 4, right: 16, bottom: 4, left: 8 }}
          >
            <CartesianGrid horizontal={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
            <XAxis type="number" hide />
            <YAxis
              dataKey="name"
              type="category"
              width={150}
              tickLine={false}
              axisLine={false}
              className="text-xs"
            />
            <ChartTooltip content={<ChartTooltipContent />} />
            <Bar dataKey="pass" stackId="a" fill={C.pass} radius={[3, 0, 0, 3]} cursor="pointer"
              onClick={(_, i) => setActive(data[i].key)} />
            <Bar dataKey="pass_with_evidence" stackId="a" fill={C.pass_with_evidence} cursor="pointer"
              onClick={(_, i) => setActive(data[i].key)} />
            <Bar dataKey="fail" stackId="a" fill={C.fail} cursor="pointer"
              onClick={(_, i) => setActive(data[i].key)} />
            <Bar dataKey="out_of_scope" stackId="a" fill={C.out_of_scope} cursor="pointer"
              onClick={(_, i) => setActive(data[i].key)} />
            <Bar dataKey="not_bom_evidenceable" stackId="a" fill={C.not_bom_evidenceable} cursor="pointer"
              onClick={(_, i) => setActive(data[i].key)} />
            <Bar dataKey="na" stackId="a" fill={C.na} radius={[0, 3, 3, 0]} cursor="pointer"
              onClick={(_, i) => setActive(data[i].key)} />
          </BarChart>
        </ChartContainer>

        <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5 text-xs text-zinc-600 dark:text-zinc-400">
          <span className="flex items-center gap-1.5"><span className="size-2.5 rounded-sm" style={{ background: C.pass }} /> Pass</span>
          <span className="flex items-center gap-1.5"><span className="size-2.5 rounded-sm" style={{ background: C.pass_with_evidence }} /> Pass (evidence)</span>
          <span className="flex items-center gap-1.5"><span className="size-2.5 rounded-sm" style={{ background: C.fail }} /> Fail</span>
          <span className="flex items-center gap-1.5"><span className="size-2.5 rounded-sm" style={{ background: C.out_of_scope }} /> Out of scope</span>
          <span className="flex items-center gap-1.5"><span className="size-2.5 rounded-sm" style={{ background: C.not_bom_evidenceable }} /> Not BOM-evidenceable</span>
          <span className="flex items-center gap-1.5"><span className="size-2.5 rounded-sm" style={{ background: C.na }} /> N/A</span>
        </div>

        {active && reqs.length > 0 && (
          <div className="mt-4 rounded-lg border border-zinc-200 dark:border-zinc-800">
            <div className="px-3 py-2 text-sm font-medium border-b border-zinc-200 dark:border-zinc-800">
              {FRAMEWORK_LABELS[active] ?? active} — requirements
            </div>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-24">Verdict</TableHead>
                  <TableHead className="w-28">ID</TableHead>
                  <TableHead>Requirement</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {reqs.map((r) => {
                  const att = attested[r.id];
                  const v = att ? "pass_with_evidence" : r.verdict;
                  return (
                  <TableRow key={r.id}>
                    <TableCell>
                      <Badge className={VERDICT_BADGE[v] ?? VERDICT_BADGE.na}>
                        {VERDICT_LABEL[v] ?? v}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-zinc-600 dark:text-zinc-400">{r.id}</TableCell>
                    <TableCell className="text-sm">
                      {r.title}
                      {r.evidence && !att && (
                        <div className="text-xs text-zinc-500">{r.evidence}</div>
                      )}
                      {att && (
                        <div className="text-xs text-teal-600 dark:text-teal-400">
                          attested: {att} (pending re-evaluation)
                        </div>
                      )}
                      {(r.verdict === "not_bom_evidenceable" || r.attestable) && !att && (
                        <label className="mt-1 inline-flex cursor-pointer items-center gap-1 text-xs text-violet-600 dark:text-violet-400 hover:underline">
                          <input
                            type="file"
                            className="hidden"
                            onChange={(e) => {
                              const f = e.target.files?.[0];
                              if (f) setAttested((s) => ({ ...s, [r.id]: f.name }));
                            }}
                          />
                          + Attach attestation
                        </label>
                      )}
                    </TableCell>
                  </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// 2. Typed-edge dependency graph (trained_on / depends_on / served_by / deployed_at).
// ════════════════════════════════════════════════════════════════════════════
const KIND_COLOR: Record<string, string> = {
  model: "#6366f1", // indigo-500
  dataset: "#0ea5e9", // sky-500
  framework: "#a855f7", // purple-500
  service: "#14b8a6", // teal-500
  infra: "#f59e0b", // amber-500 (deployment site)
};
const REL_LABEL: Record<string, string> = {
  trained_on: "trained on",
  depends_on: "depends on",
  served_by: "served by",
  deployed_at: "deployed at",
};

export function DependencyGraph({ graph }: { graph?: Graph }) {
  const { nodes, edges } = useMemo(() => {
    const gn = graph?.nodes ?? [];
    const ge = graph?.edges ?? [];
    // simple layered layout: models left, their neighbours fanned right.
    const models = gn.filter((n) => n.kind === "model");
    const others = gn.filter((n) => n.kind !== "model");
    const nodes: Node[] = [
      ...models.map((n, i) => ({
        id: n.id,
        position: { x: 40, y: 60 + i * 120 },
        data: { label: n.label },
        style: nodeStyle(n.kind),
      })),
      ...others.map((n, i) => ({
        id: n.id,
        position: { x: 360, y: 20 + i * 70 },
        data: { label: `${n.label}` },
        style: nodeStyle(n.kind),
      })),
    ];
    const edges: Edge[] = ge.map((e, i) => ({
      id: `e${i}`,
      source: e.source,
      target: e.target,
      label: REL_LABEL[e.rel] ?? e.rel,
      animated: e.rel === "deployed_at",
      markerEnd: { type: MarkerType.ArrowClosed },
      labelStyle: { fontSize: 10, fill: "#71717a" },
      style: { stroke: "#a1a1aa" },
    }));
    return { nodes, edges };
  }, [graph]);

  if (nodes.length === 0) return null;
  return (
    <Card className="col-span-full">
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <Network className="w-4 h-4 text-indigo-500" /> AI Supply-Chain Graph
        </CardTitle>
        <CardDescription>
          Typed lineage — model → training data, libraries, serving vendor, and
          deployment sites.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="h-[340px] w-full rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50/50 dark:bg-zinc-900/40">
          <ReactFlow nodes={nodes} edges={edges} fitView proOptions={{ hideAttribution: true }}>
            <Background gap={16} className="text-zinc-200 dark:text-zinc-800" />
            <Controls showInteractive={false} />
          </ReactFlow>
        </div>
        <div className="mt-3 flex flex-wrap gap-4 text-xs text-zinc-600 dark:text-zinc-400">
          {Object.entries(KIND_COLOR).map(([k, c]) => (
            <span key={k} className="flex items-center gap-1.5">
              <span className="size-2.5 rounded-full" style={{ background: c }} /> {k}
            </span>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
function nodeStyle(kind: string): React.CSSProperties {
  return {
    background: KIND_COLOR[kind] ?? "#71717a",
    color: "white",
    border: "none",
    borderRadius: 8,
    fontSize: 11,
    fontWeight: 600,
    padding: "6px 10px",
    width: 160,
  };
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
export function ShadowAI({ findings }: { findings?: Json[] }) {
  const shadow = (findings ?? []).filter(
    (f) =>
      String(f.risk_category ?? "").includes("missing_model_card_lineage") ||
      String(f.asset_type ?? "") === "external_provider"
  );
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <EyeOff className="w-4 h-4 text-amber-500" /> Shadow AI
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
          <ul className="space-y-2">
            {shadow.slice(0, 8).map((f, i) => (
              <li
                key={i}
                className="flex items-center justify-between rounded-lg border border-amber-200 dark:border-amber-900/40 bg-amber-50/60 dark:bg-amber-900/10 px-3 py-2"
              >
                <div>
                  <div className="text-sm font-medium text-zinc-800 dark:text-zinc-100">
                    {String(f.asset_name ?? f.title ?? "—")}
                  </div>
                  <div className="text-xs text-zinc-500">
                    {String(f.asset_type ?? "")}
                    {f.provider ? ` · ${f.provider}` : ""}
                  </div>
                </div>
                <Badge className="bg-amber-500 hover:bg-amber-600 text-white">
                  {String(f.impact ?? "review")}
                </Badge>
              </li>
            ))}
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
                      {s.drift_status ?? "unknown"}
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
// ════════════════════════════════════════════════════════════════════════════
export function ModelCardPanel({ aiBomJson }: { aiBomJson?: Json }) {
  const model = useMemo(() => {
    const comps = (aiBomJson?.components as Json[] | undefined) ?? [];
    return comps.find((c) => c.type === "machine-learning-model");
  }, [aiBomJson]);
  if (!model) return null;
  const mc = (model.modelCard as Json | undefined) ?? {};
  const mp = (mc.modelParameters as Json | undefined) ?? {};
  // CycloneDX `modelParameters.approach` is an object ({type: "supervised"}),
  // not a string — read its `.type` so it doesn't render as "[object Object]".
  const approach = mp.approach as Json | string | undefined;
  const approachStr =
    approach && typeof approach === "object"
      ? String((approach as Json).type ?? "—")
      : String(approach ?? "—");
  const rows: [string, string][] = [
    ["Name", String(model.name ?? "—")],
    ["Version", String(model.version ?? "—")],
    ["Approach", approachStr],
    ["Task", String(mp.task ?? "—")],
    ["Architecture family", String(mp.architectureFamily ?? "—")],
    ["Model architecture", String(mp.modelArchitecture ?? "—")],
  ];
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <FileText className="w-4 h-4 text-violet-500" /> Model Card
        </CardTitle>
        <CardDescription>Architecture, task, and lineage metadata.</CardDescription>
      </CardHeader>
      <CardContent>
        <dl className="divide-y divide-zinc-100 dark:divide-zinc-800">
          {rows.map(([k, v]) => (
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
  scores,
  aiBomJson,
  findings,
}: {
  compliance?: Compliance;
  graph?: Graph;
  scores?: Scores;
  aiBomJson?: Json;
  findings?: Json[];
}) {
  const has =
    compliance || graph || scores || aiBomJson || (findings && findings.length);
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
        <ComplianceCoverage compliance={compliance} />
        <DependencyGraph graph={graph} />
        <MultiSiteDrift aiBomJson={aiBomJson} />
        <ModelCardPanel aiBomJson={aiBomJson} />
        <RiskHeatmap scores={scores} />
        <ShadowAI findings={findings} />
      </div>
    </section>
  );
}

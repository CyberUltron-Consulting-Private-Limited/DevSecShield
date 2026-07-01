"use client";

/**
 * CBOM crypto-asset visualizations (C9).
 *
 * Binds the five `cbom_distributions` arrays the aibom CBOM lane's normalizer
 * (aibom/src/aibom/cbom/normalize.py::normalize_crypto) carries through to the
 * run-object, using the SAME primitives every other DevSecShield scanner uses —
 * shadcn Card, Recharts via components/ui/chart, and the shared severity palette
 * — so the CBOM page stays visually native (matches CbomResults /
 * AiBomVisualizations). Each chart empty-guards; on the crypto fixture all five
 * render non-empty (see aibom/tests test_cbom_chart_data_contract — C10).
 *
 * Charts: Algorithm distribution · Weak-crypto findings (severity-toned) · PQC
 * readiness gauge (nistQuantumSecurityLevel) · Certificate expiry · Protocol /
 * TLS · Asset-type breakdown · Crypto dependency graph. The last two (F1) are
 * fed by the I1 `cbom_graph` {nodes, edges} projection and render only when it
 * is present (legacy worker scans carry none).
 */

import { useMemo } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MarkerType,
  type Node,
  type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  Bar,
  BarChart,
  Cell,
  PolarAngleAxis,
  RadialBar,
  RadialBarChart,
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
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import { Badge } from "@/components/ui/badge";
import {
  BarChart3,
  ShieldAlert,
  Atom,
  ShieldCheck,
  Network,
  Layers,
  Share2,
} from "lucide-react";
import type { CbomGraph } from "@/utils/backend_api";

// ── shared palette (mirrors getStrengthBadgeClass + the severity tokens) ─────
const C = {
  weak: "#dc2626", // red-600
  moderate: "#f59e0b", // amber-500
  strong: "#10b981", // emerald-500
  quantumSafe: "#3b82f6", // blue-500
  quantumVuln: "#f97316", // orange-500
  neutral: "#64748b", // slate-500
  primitive: "#6366f1", // indigo-500
};

// ── the FE-exposed run-object shape (carried by normalize_crypto) ────────────
export interface CbomDistributions {
  /** algorithm assets grouped by CycloneDX cryptographic primitive */
  algorithms: Record<string, number>;
  /** weak-crypto flags grouped by flag code (WEAK_ALGORITHM, …) */
  weakness: Record<string, number>;
  /** post-quantum readiness derived from nistQuantumSecurityLevel */
  pqc: {
    quantum_vulnerable: number;
    quantum_safe: number;
    readiness_pct: number;
  };
  /** one row per detected certificate */
  certificates: Array<{
    name: string;
    not_valid_after: string | null;
    self_signed: boolean;
    expired: boolean;
  }>;
  /** protocol assets grouped by label (e.g. "TLS 1.0") */
  protocols: Record<string, number>;
}

const PRIMITIVE_LABELS: Record<string, string> = {
  "block-cipher": "Block cipher",
  "stream-cipher": "Stream cipher",
  hash: "Hash",
  pke: "Public-key",
  signature: "Signature",
  "key-agree": "Key agreement",
  kem: "KEM",
  mac: "MAC",
  drbg: "DRBG",
  ae: "Authenticated encryption",
  combiner: "Combiner",
  other: "Other",
  unknown: "Unknown",
};

const WEAKNESS_LABELS: Record<string, string> = {
  WEAK_ALGORITHM: "Weak algorithm",
  WEAK_CIPHER_MODE: "Weak cipher mode",
  WEAK_CIPHER_SUITE: "Weak cipher suite",
  WEAK_KEY_SIZE: "Weak key size",
  WEAK_PROTOCOL: "Weak protocol",
  WEAK_PADDING: "Weak padding",
  WEAK_RNG: "Weak RNG",
  STATIC_IV: "Static IV",
  REUSED_NONCE: "Reused nonce",
  HARDCODED_KEY: "Hardcoded key",
  WEAK_CERTIFICATE_SIGNATURE: "Weak cert signature",
  WEAK_CERTIFICATE_KEY: "Weak cert key",
  SELF_SIGNED_LEAF: "Self-signed leaf",
  EXPIRED_CERTIFICATE: "Expired certificate",
  QUANTUM_VULNERABLE: "Quantum-vulnerable",
};

// Weakness codes graded Medium (a future/lower-severity exposure) — everything
// else in the weak-crypto set is High. Mirrors the C8 scorer's severity bands
// (QUANTUM_VULNERABLE / SELF_SIGNED_LEAF = warning/Medium; the rest = error/High).
const WEAKNESS_MEDIUM = new Set<string>([
  "QUANTUM_VULNERABLE",
  "SELF_SIGNED_LEAF",
]);
const weaknessTone = (k: string) => (WEAKNESS_MEDIUM.has(k) ? C.quantumVuln : C.weak);

// ── asset-type breakdown (CycloneDX cryptoProperties.assetType) ──────────────
const ASSET_TYPE_LABELS: Record<string, string> = {
  algorithm: "Algorithm",
  certificate: "Certificate",
  protocol: "Protocol",
  "related-crypto-material": "Key / material",
  library: "Library",
  other: "Other",
};
const ASSET_TYPE_COLOR: Record<string, string> = {
  algorithm: C.primitive, // indigo
  certificate: C.strong, // emerald
  protocol: C.quantumSafe, // blue
  "related-crypto-material": C.moderate, // amber
  library: C.neutral, // slate
  other: C.neutral,
};
/** Bucket key a graph node contributes to in the asset-type breakdown. */
const assetTypeKey = (n: CbomGraph["nodes"][number]) =>
  n.asset_type || (n.kind === "framework" ? "library" : "other");

const labelPrimitive = (k: string) =>
  PRIMITIVE_LABELS[k] ?? k.replace(/[-_]/g, " ");
const labelWeakness = (k: string) =>
  WEAKNESS_LABELS[k] ?? k.replace(/_/g, " ").toLowerCase();

const countConfig = {
  count: { label: "Count", color: C.primitive },
} satisfies ChartConfig;

function EmptyChart({ message }: { message: string }) {
  return (
    <div className="flex h-[260px] items-center justify-center text-sm text-zinc-500 dark:text-zinc-400">
      {message}
    </div>
  );
}

/** 1 — Algorithm distribution: crypto algorithm assets by primitive. */
function AlgorithmDistribution({ data }: { data: Record<string, number> }) {
  const rows = useMemo(
    () =>
      Object.entries(data ?? {})
        .map(([k, count]) => ({ name: labelPrimitive(k), count }))
        .filter((d) => d.count > 0)
        .sort((a, b) => b.count - a.count),
    [data],
  );
  return (
    <Card className="border-zinc-200 dark:border-zinc-800">
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <BarChart3 className="w-4 h-4" />
          Algorithm distribution
        </CardTitle>
        <CardDescription>Crypto algorithms by primitive</CardDescription>
      </CardHeader>
      <CardContent>
        {rows.length === 0 ? (
          <EmptyChart message="No algorithm assets detected" />
        ) : (
          <ChartContainer config={countConfig} className="aspect-auto h-[260px] w-full">
            <BarChart data={rows} layout="vertical" margin={{ top: 0, right: 8, bottom: 0, left: 0 }}>
              <XAxis type="number" hide />
              <YAxis dataKey="name" type="category" width={130} tickLine={false} axisLine={false} className="text-[10px]" />
              <ChartTooltip content={<ChartTooltipContent />} />
              <Bar dataKey="count" fill={C.primitive} radius={3} />
            </BarChart>
          </ChartContainer>
        )}
      </CardContent>
    </Card>
  );
}

/** 2 — Weak-crypto findings: weakness flags by code, toned by severity. */
function WeakCryptoFindings({ data }: { data: Record<string, number> }) {
  const rows = useMemo(
    () =>
      Object.entries(data ?? {})
        .map(([k, count]) => ({ name: labelWeakness(k), count, fill: weaknessTone(k) }))
        .filter((d) => d.count > 0)
        .sort((a, b) => b.count - a.count),
    [data],
  );
  return (
    <Card className="border-zinc-200 dark:border-zinc-800">
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-red-600 dark:text-red-400" />
          Weak-crypto findings
        </CardTitle>
        <CardDescription>Weak / deprecated crypto by category (High red · Medium orange)</CardDescription>
      </CardHeader>
      <CardContent>
        {rows.length === 0 ? (
          <EmptyChart message="No weak crypto detected" />
        ) : (
          <ChartContainer config={countConfig} className="aspect-auto h-[260px] w-full">
            <BarChart data={rows} layout="vertical" margin={{ top: 0, right: 8, bottom: 0, left: 0 }}>
              <XAxis type="number" hide />
              <YAxis dataKey="name" type="category" width={130} tickLine={false} axisLine={false} className="text-[10px]" />
              <ChartTooltip content={<ChartTooltipContent />} />
              <Bar dataKey="count" radius={3}>
                {rows.map((d, i) => (
                  <Cell key={i} fill={d.fill} />
                ))}
              </Bar>
            </BarChart>
          </ChartContainer>
        )}
      </CardContent>
    </Card>
  );
}

/** 3 — PQC readiness gauge: nistQuantumSecurityLevel-derived readiness %. */
function PqcReadinessGauge({ pqc }: { pqc: CbomDistributions["pqc"] }) {
  const safe = pqc?.quantum_safe ?? 0;
  const vuln = pqc?.quantum_vulnerable ?? 0;
  const total = safe + vuln;
  const pct = pqc?.readiness_pct ?? 0;
  const gaugeData = [{ name: "readiness", value: pct, fill: C.quantumSafe }];
  const gaugeConfig = {
    value: { label: "Readiness", color: C.quantumSafe },
  } satisfies ChartConfig;
  return (
    <Card className="border-zinc-200 dark:border-zinc-800">
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <Atom className="w-4 h-4 text-blue-600 dark:text-blue-400" />
          PQC readiness
        </CardTitle>
        <CardDescription>Quantum-safe share (nistQuantumSecurityLevel)</CardDescription>
      </CardHeader>
      <CardContent>
        {total === 0 ? (
          <EmptyChart message="No quantum-relevant algorithms" />
        ) : (
          <div className="flex flex-col items-center">
            <div className="relative">
              <ChartContainer config={gaugeConfig} className="mx-auto aspect-square h-[200px]">
                <RadialBarChart
                  data={gaugeData}
                  startAngle={90}
                  endAngle={-270}
                  innerRadius={72}
                  outerRadius={100}
                >
                  <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
                  <RadialBar dataKey="value" cornerRadius={8} background fill={C.quantumSafe} />
                </RadialBarChart>
              </ChartContainer>
              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <p className="text-3xl font-bold tabular-nums text-zinc-900 dark:text-zinc-100">{pct}%</p>
                <p className="text-xs text-zinc-500 dark:text-zinc-400">quantum-safe</p>
              </div>
            </div>
            <div className="flex gap-2 mt-3">
              <Badge variant="outline" className="border-blue-500/50 text-blue-600 dark:text-blue-400">
                Safe: {safe}
              </Badge>
              <Badge variant="outline" className="border-orange-500/50 text-orange-600 dark:text-orange-400">
                Vulnerable: {vuln}
              </Badge>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

/** 4 — Certificate expiry: detected certs by validity status. */
function CertificateExpiry({ certificates }: { certificates: CbomDistributions["certificates"] }) {
  const rows = useMemo(() => {
    const certs = certificates ?? [];
    const valid = certs.filter((c) => !c.expired).length;
    const expired = certs.filter((c) => c.expired).length;
    const selfSigned = certs.filter((c) => c.self_signed).length;
    return [
      { name: "Valid", count: valid, fill: C.strong },
      { name: "Expired", count: expired, fill: C.weak },
      { name: "Self-signed", count: selfSigned, fill: C.moderate },
    ].filter((d) => d.count > 0);
  }, [certificates]);
  return (
    <Card className="border-zinc-200 dark:border-zinc-800">
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
          Certificate expiry
        </CardTitle>
        <CardDescription>X.509 certificates by validity</CardDescription>
      </CardHeader>
      <CardContent>
        {rows.length === 0 ? (
          <EmptyChart message="No certificates detected" />
        ) : (
          <ChartContainer config={countConfig} className="aspect-auto h-[260px] w-full">
            <BarChart data={rows} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
              <XAxis dataKey="name" tickLine={false} axisLine={false} className="text-[10px]" />
              <YAxis allowDecimals={false} width={28} tickLine={false} axisLine={false} className="text-[10px]" />
              <ChartTooltip content={<ChartTooltipContent />} />
              <Bar dataKey="count" radius={3}>
                {rows.map((d, i) => (
                  <Cell key={i} fill={d.fill} />
                ))}
              </Bar>
            </BarChart>
          </ChartContainer>
        )}
      </CardContent>
    </Card>
  );
}

/** 5 — Protocol / TLS: protocol assets by label, weak versions in red. */
function ProtocolTls({ data }: { data: Record<string, number> }) {
  const rows = useMemo(
    () =>
      Object.entries(data ?? {})
        .map(([name, count]) => {
          const weak = /ssl|tls\s*1\.[01]\b/i.test(name);
          return { name, count, fill: weak ? C.weak : C.strong };
        })
        .filter((d) => d.count > 0)
        .sort((a, b) => b.count - a.count),
    [data],
  );
  return (
    <Card className="border-zinc-200 dark:border-zinc-800">
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <Network className="w-4 h-4" />
          Protocol / TLS
        </CardTitle>
        <CardDescription>Transport-security protocols in use</CardDescription>
      </CardHeader>
      <CardContent>
        {rows.length === 0 ? (
          <EmptyChart message="No protocols detected" />
        ) : (
          <ChartContainer config={countConfig} className="aspect-auto h-[260px] w-full">
            <BarChart data={rows} layout="vertical" margin={{ top: 0, right: 8, bottom: 0, left: 0 }}>
              <XAxis type="number" hide />
              <YAxis dataKey="name" type="category" width={90} tickLine={false} axisLine={false} className="text-[10px]" />
              <ChartTooltip content={<ChartTooltipContent />} />
              <Bar dataKey="count" radius={3}>
                {rows.map((d, i) => (
                  <Cell key={i} fill={d.fill} />
                ))}
              </Bar>
            </BarChart>
          </ChartContainer>
        )}
      </CardContent>
    </Card>
  );
}

/** 6 — Asset-type breakdown: crypto inventory grouped by CycloneDX assetType. */
function AssetTypeDistribution({ graph }: { graph: CbomGraph }) {
  const rows = useMemo(() => {
    const buckets: Record<string, number> = {};
    for (const n of graph.nodes ?? []) {
      const k = assetTypeKey(n);
      buckets[k] = (buckets[k] ?? 0) + 1;
    }
    // stable, spec-ordered so the breakdown reads consumers → primitives → libs
    const ORDER = ["algorithm", "certificate", "protocol", "related-crypto-material", "library", "other"];
    return ORDER.filter((k) => buckets[k] > 0).map((k) => ({
      name: ASSET_TYPE_LABELS[k] ?? k,
      count: buckets[k],
      fill: ASSET_TYPE_COLOR[k] ?? C.neutral,
    }));
  }, [graph]);
  return (
    <Card className="border-zinc-200 dark:border-zinc-800">
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <Layers className="w-4 h-4 text-indigo-500" />
          Asset types
        </CardTitle>
        <CardDescription>Crypto inventory by CycloneDX asset class</CardDescription>
      </CardHeader>
      <CardContent>
        {rows.length === 0 ? (
          <EmptyChart message="No crypto assets detected" />
        ) : (
          <ChartContainer config={countConfig} className="aspect-auto h-[260px] w-full">
            <BarChart data={rows} layout="vertical" margin={{ top: 0, right: 8, bottom: 0, left: 0 }}>
              <XAxis type="number" hide />
              <YAxis dataKey="name" type="category" width={110} tickLine={false} axisLine={false} className="text-[10px]" />
              <ChartTooltip content={<ChartTooltipContent />} />
              <Bar dataKey="count" radius={3}>
                {rows.map((d, i) => (
                  <Cell key={i} fill={d.fill} />
                ))}
              </Bar>
            </BarChart>
          </ChartContainer>
        )}
      </CardContent>
    </Card>
  );
}

// ── crypto dependency graph (I1 cbom_graph) ──────────────────────────────────
// Human-readable labels for the CycloneDX ref relationships the C9 emitter links
// (cert → its signature-digest + subject-public-key algorithms, protocol → its
// cipher-suite algorithms, related material → the algorithm that produced it).
const REL_LABEL: Record<string, string> = {
  signatureAlgorithm: "signed with",
  subjectPublicKey: "public key",
  algorithmRef: "produced by",
  cryptoRefArray: "uses",
  algorithms: "uses",
  signed_by: "signed by",
  used_by: "used by",
};

function cryptoNodeStyle(n: CbomGraph["nodes"][number]): React.CSSProperties {
  const bg = ASSET_TYPE_COLOR[assetTypeKey(n)] ?? C.neutral;
  // weak assets get a red ring; quantum-vulnerable (but not weak) an orange one.
  const ring = n.weak ? C.weak : n.quantum_vulnerable ? C.quantumVuln : "transparent";
  return {
    background: bg,
    color: "white",
    border: `2px solid ${ring}`,
    borderRadius: 8,
    fontSize: 11,
    fontWeight: 600,
    padding: "6px 10px",
    width: 168,
  };
}

/** 7 — Crypto dependency graph: cert/protocol/material lineage → algorithms. */
function CryptoDependencyGraph({ graph }: { graph: CbomGraph }) {
  const { nodes, edges } = useMemo(() => {
    const gn = graph.nodes ?? [];
    const ge = graph.edges ?? [];
    // column layout by asset class: consumers left → primitives → libraries right
    const COLS = ["certificate", "protocol", "related-crypto-material", "algorithm", "library", "other"];
    const colIndex: Record<string, number> = {};
    COLS.forEach((c, i) => (colIndex[c] = i));
    const perCol: Record<number, number> = {};
    const nodes: Node[] = gn.map((n) => {
      const col = colIndex[assetTypeKey(n)] ?? COLS.length - 1;
      const row = perCol[col] ?? 0;
      perCol[col] = row + 1;
      return {
        id: n.id,
        position: { x: 40 + col * 210, y: 24 + row * 66 },
        data: { label: n.label },
        style: cryptoNodeStyle(n),
      };
    });
    const edges: Edge[] = ge.map((e, i) => ({
      id: `e${i}`,
      source: e.source,
      target: e.target,
      label: REL_LABEL[e.rel] ?? e.rel,
      markerEnd: { type: MarkerType.ArrowClosed },
      labelStyle: { fontSize: 10, fill: "#71717a" },
      style: { stroke: "#a1a1aa" },
    }));
    return { nodes, edges };
  }, [graph]);

  return (
    <Card className="border-zinc-200 dark:border-zinc-800 col-span-full">
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <Share2 className="w-4 h-4 text-indigo-500" />
          Crypto dependency graph
        </CardTitle>
        <CardDescription>
          CycloneDX lineage — certificate / protocol / key material → the algorithm assets they reference
        </CardDescription>
      </CardHeader>
      <CardContent>
        {nodes.length === 0 ? (
          <EmptyChart message="No crypto assets to graph" />
        ) : (
          <>
            <div className="h-[360px] w-full rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50/50 dark:bg-zinc-900/40">
              <ReactFlow nodes={nodes} edges={edges} fitView proOptions={{ hideAttribution: true }}>
                <Background gap={16} className="text-zinc-200 dark:text-zinc-800" />
                <Controls showInteractive={false} />
              </ReactFlow>
            </div>
            <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5 text-xs text-zinc-600 dark:text-zinc-400">
              {["algorithm", "certificate", "protocol", "related-crypto-material", "library"].map((k) => (
                <span key={k} className="flex items-center gap-1.5">
                  <span className="size-2.5 rounded-full" style={{ background: ASSET_TYPE_COLOR[k] }} />
                  {ASSET_TYPE_LABELS[k]}
                </span>
              ))}
              <span className="flex items-center gap-1.5">
                <span className="size-2.5 rounded-sm border-2" style={{ borderColor: C.weak }} /> weak
              </span>
              <span className="flex items-center gap-1.5">
                <span className="size-2.5 rounded-sm border-2" style={{ borderColor: C.quantumVuln }} /> quantum-vulnerable
              </span>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

/**
 * Composes the CBOM crypto charts. Renders nothing when the run-object carries
 * no `cbom_distributions` (e.g. a legacy worker CBOM scan) so the existing
 * dashboard charts remain the sole view in that case. The two graph-fed
 * visualizations (asset-type breakdown + crypto dependency graph, F1) render
 * only when the I1 `cbom_graph` projection is present.
 */
export function CbomCryptoCharts({
  distributions,
  graph,
}: {
  distributions?: CbomDistributions | null;
  graph?: CbomGraph | null;
}) {
  if (!distributions) return null;
  const hasGraph = !!graph && (graph.nodes?.length ?? 0) > 0;
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <AlgorithmDistribution data={distributions.algorithms} />
        <WeakCryptoFindings data={distributions.weakness} />
        <PqcReadinessGauge pqc={distributions.pqc} />
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {hasGraph && <AssetTypeDistribution graph={graph} />}
        <CertificateExpiry certificates={distributions.certificates} />
        <ProtocolTls data={distributions.protocols} />
      </div>
      {hasGraph && (
        <div className="grid grid-cols-1 gap-6">
          <CryptoDependencyGraph graph={graph} />
        </div>
      )}
    </div>
  );
}

export default CbomCryptoCharts;

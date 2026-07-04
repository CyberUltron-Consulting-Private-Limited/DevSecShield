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
 * TLS · Asset-type breakdown · Crypto dependency graph. Asset-type + dependency
 * graph (F1) are fed by the I1 `cbom_graph` {nodes, edges} projection. The PQC
 * readiness detail (F2 — quantum-vulnerable list + CNSA 2.0 migration roadmap)
 * is fed by `distributions.pqc.migration`. All render only when their backing
 * payload is present (legacy worker scans carry none).
 */

import { useMemo, useState } from "react";
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
  BarChart3,
  ShieldAlert,
  Atom,
  ShieldCheck,
  Network,
  Layers,
  Share2,
  ShieldX,
  Rocket,
  CalendarClock,
  Scale,
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
    /** hybrid-KEX (classical + PQC) algorithm count (F2) */
    hybrid?: number;
    /** NIST quantum-security-level histogram (0 = vulnerable, 1-5 = safe cat) */
    nist_level_distribution?: Record<string, number>;
    /** one row per quantum-vulnerable algorithm — the F2 list + roadmap source */
    migration?: PqcMigrationRow[];
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

/** One quantum-vulnerable algorithm's PQC migration plan (F2, C7 grader). */
export interface PqcMigrationRow {
  name: string;
  primitive: string | null;
  key_size: string | null;
  curve: string | null;
  nist_quantum_security_level: number | null;
  /** NIST-standardized target family (e.g. "ML-KEM (FIPS 203) / ML-DSA (FIPS 204)") */
  migration_target: string | null;
  /** parameter-sized target matched to the asset's strength (e.g. "ML-KEM-768 …") */
  migration_roadmap: string | null;
  impact: string | null;
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

// ── PQC readiness (F2) ───────────────────────────────────────────────────────
// Impact-badge tone matching CbomResults.getImpactBadgeClass (High=orange,
// Medium=amber, Low=blue), so the quantum-vulnerable list reads identically to
// the findings table.
const impactBadgeClass = (impact: string | null): string => {
  const i = (impact ?? "").toLowerCase();
  if (i === "critical") return "border-red-500/50 text-red-600 dark:text-red-400";
  if (i === "high") return "border-orange-500/50 text-orange-600 dark:text-orange-400";
  if (i === "medium") return "border-amber-500/50 text-amber-600 dark:text-amber-400";
  return "border-blue-500/50 text-blue-600 dark:text-blue-400";
};

// CNSA 2.0 National Security System transition milestones (NSA public advisory,
// 2022 — a clean-room encoding of the published timeline, not tool output). The
// C7 grader cites the same milestones in each QUANTUM_VULNERABLE finding message.
const CNSA_MILESTONES: Array<{ year: string; label: string }> = [
  { year: "2025", label: "Software / firmware signing" },
  { year: "2030", label: "Networking & traditional protocols" },
  { year: "2033", label: "Operating systems" },
  { year: "2035", label: "All National Security Systems" },
];

/** Short primitive/param descriptor for a vulnerable algorithm row. */
const migrationDescriptor = (r: PqcMigrationRow): string => {
  const parts: string[] = [];
  if (r.primitive) parts.push(labelPrimitive(r.primitive));
  if (r.key_size) parts.push(`${r.key_size}-bit`);
  else if (r.curve) parts.push(r.curve);
  return parts.join(" · ") || "—";
};

const countConfig = {
  count: { label: "Count", color: C.primitive },
} satisfies ChartConfig;

// ── compliance tri-state matrix (F3) ─────────────────────────────────────────
// The CBOM lane's run_cbom_compliance fills result.compliance with the SAME
// tri-state verdict shape the AIBOM compliance engine uses (pass /
// pass_with_evidence / fail / out_of_scope / not_bom_evidenceable / na +
// coverage + a per-requirement drilldown). Coverage = pass / (pass + fail); the
// other states are reported SEPARATELY, never folded into pass or fail. Palette +
// verdict labels mirror AiBomVisualizations.ComplianceCoverage so the two BOM
// pages read identically.
export type ComplianceVerdict =
  | "pass"
  | "pass_with_evidence"
  | "fail"
  | "out_of_scope"
  | "not_bom_evidenceable"
  | "na";

export interface ComplianceRequirement {
  id: string;
  title: string;
  verdict: ComplianceVerdict;
  evidence?: string;
  source?: string;
}

export interface FrameworkCoverage {
  pass: number;
  pass_with_evidence?: number;
  fail: number;
  out_of_scope?: number;
  not_bom_evidenceable?: number;
  na: number;
  coverage: number | null;
  requirements?: ComplianceRequirement[];
}

/** result.compliance as surfaced through scan-metadata (a `disclaimer` string
 *  rides alongside the per-framework objects — filtered out before rendering). */
export type CbomCompliance = Record<string, FrameworkCoverage | string>;

const VERDICT_COLOR: Record<ComplianceVerdict, string> = {
  pass: "#10b981", // emerald-500
  pass_with_evidence: "#14b8a6", // teal-500 (satisfied by attestation; counts as pass)
  fail: "#dc2626", // red-600
  out_of_scope: "#64748b", // slate-500 (framework doesn't apply — NOT fail/na)
  not_bom_evidenceable: "#8b5cf6", // violet-500 (process evidence; attestable)
  na: "#a1a1aa", // zinc-400
};
const VERDICT_BADGE: Record<ComplianceVerdict, string> = {
  pass: "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200",
  pass_with_evidence: "bg-teal-100 text-teal-800 dark:bg-teal-900/40 dark:text-teal-200",
  fail: "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-200",
  out_of_scope: "bg-slate-100 text-slate-700 dark:bg-slate-700/50 dark:text-slate-200",
  not_bom_evidenceable: "bg-violet-100 text-violet-800 dark:bg-violet-900/40 dark:text-violet-200",
  na: "bg-zinc-100 text-zinc-700 dark:bg-zinc-700/50 dark:text-zinc-200",
};
const VERDICT_LABEL: Record<ComplianceVerdict, string> = {
  pass: "Pass",
  pass_with_evidence: "Pass (evidence)",
  fail: "Fail",
  out_of_scope: "Out of scope",
  not_bom_evidenceable: "Not BOM-evidenceable",
  na: "N/A",
};
const VERDICT_ORDER: ComplianceVerdict[] = [
  "pass",
  "pass_with_evidence",
  "fail",
  "out_of_scope",
  "not_bom_evidenceable",
  "na",
];

// The 10 CBOM compliance frameworks the aibom lane registers. Kept in lockstep
// with aibom compliance.CBOM_FRAMEWORKS + the chart-data-contract test's
// _EXPECTED_FRAMEWORKS — a framework missing here renders its raw snake_case key.
const CBOM_FRAMEWORK_LABELS: Record<string, string> = {
  nist_1800_38b: "NIST SP 1800-38B",
  nist_800_57: "NIST SP 800-57",
  omb_m_23_02: "OMB M-23-02",
  eu_cra: "EU CRA",
  eu_dora: "EU DORA",
  pci_dss_4: "PCI-DSS 4.0",
  fips_140_3: "FIPS 140-3",
  bsi_tr_02102: "BSI TR-02102",
  nist_1800_38c: "NIST SP 1800-38C",
  cnsa_2_0: "CNSA 2.0",
};

// Framework-filter groups (the "frameworks" toggle). Disjoint by regulatory
// regime so the chips partition the 10 frameworks cleanly (3 + 3 + 4).
const FRAMEWORK_GROUPS: Array<{ id: string; label: string; keys: string[] }> = [
  { id: "all", label: "All", keys: [] },
  {
    id: "quantum",
    label: "Quantum-safe",
    keys: ["nist_1800_38b", "nist_1800_38c", "cnsa_2_0"],
  },
  {
    id: "baseline",
    label: "Baseline crypto",
    keys: ["nist_800_57", "fips_140_3", "bsi_tr_02102"],
  },
  {
    id: "regulatory",
    label: "Regulatory",
    keys: ["pci_dss_4", "eu_cra", "eu_dora", "omb_m_23_02"],
  },
];

const labelFramework = (k: string) => CBOM_FRAMEWORK_LABELS[k] ?? k;
const isFailingVerdict = (v: ComplianceVerdict) =>
  v === "fail" || v === "not_bom_evidenceable";

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
            <div className="flex flex-wrap justify-center gap-2 mt-3">
              <Badge variant="outline" className="border-blue-500/50 text-blue-600 dark:text-blue-400">
                Safe: {safe}
              </Badge>
              <Badge variant="outline" className="border-orange-500/50 text-orange-600 dark:text-orange-400">
                Vulnerable: {vuln}
              </Badge>
              {(pqc?.hybrid ?? 0) > 0 && (
                <Badge variant="outline" className="border-emerald-500/50 text-emerald-600 dark:text-emerald-400">
                  Hybrid: {pqc.hybrid}
                </Badge>
              )}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

/** F2a — Quantum-vulnerable list: every algorithm broken by Shor's algorithm. */
function QuantumVulnerableList({ migration }: { migration: PqcMigrationRow[] }) {
  return (
    <Card className="border-zinc-200 dark:border-zinc-800">
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <ShieldX className="w-4 h-4 text-orange-500" />
          Quantum-vulnerable algorithms
        </CardTitle>
        <CardDescription>
          Public-key assets broken by a cryptographically-relevant quantum computer
          (NIST level 0)
        </CardDescription>
      </CardHeader>
      <CardContent>
        {migration.length === 0 ? (
          <div className="flex h-[220px] flex-col items-center justify-center gap-2 text-center">
            <ShieldCheck className="h-8 w-8 text-emerald-500" />
            <p className="text-sm font-medium text-zinc-700 dark:text-zinc-300">
              No quantum-vulnerable algorithms
            </p>
            <p className="text-xs text-zinc-500 dark:text-zinc-400">
              Every inventoried algorithm is quantum-resistant at its parameter size.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-zinc-100 dark:divide-zinc-800">
            {migration.map((r, i) => (
              <div key={`${r.name}-${i}`} className="flex items-center justify-between gap-3 py-2.5">
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium text-zinc-900 dark:text-zinc-100">
                    {r.name}
                  </p>
                  <p className="truncate text-xs text-zinc-500 dark:text-zinc-400">
                    {migrationDescriptor(r)}
                  </p>
                </div>
                <div className="flex shrink-0 items-center gap-1.5">
                  <Badge variant="outline" className="border-orange-500/50 text-orange-600 dark:text-orange-400">
                    Level {r.nist_quantum_security_level ?? 0}
                  </Badge>
                  <Badge variant="outline" className={impactBadgeClass(r.impact)}>
                    {r.impact ?? "—"}
                  </Badge>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

/** F2b — Migration roadmap: CNSA 2.0 timeline + per-algorithm sized PQC target. */
function MigrationRoadmap({ migration }: { migration: PqcMigrationRow[] }) {
  return (
    <Card className="border-zinc-200 dark:border-zinc-800">
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <Rocket className="w-4 h-4 text-blue-500" />
          PQC migration roadmap
        </CardTitle>
        <CardDescription>
          NIST-standardized replacement per algorithm, against the CNSA 2.0 timeline
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* CNSA 2.0 milestone strip */}
        <div>
          <p className="mb-2 flex items-center gap-1.5 text-xs font-medium text-zinc-500 dark:text-zinc-400">
            <CalendarClock className="h-3.5 w-3.5" />
            CNSA 2.0 transition milestones
          </p>
          <ol className="flex flex-wrap gap-2">
            {CNSA_MILESTONES.map((m) => (
              <li
                key={m.year}
                className="flex-1 min-w-[120px] rounded-md border border-zinc-200 bg-zinc-50/60 p-2 dark:border-zinc-800 dark:bg-zinc-900/40"
              >
                <p className="text-sm font-semibold tabular-nums text-blue-600 dark:text-blue-400">{m.year}</p>
                <p className="text-[11px] leading-tight text-zinc-600 dark:text-zinc-400">{m.label}</p>
              </li>
            ))}
          </ol>
        </div>
        {/* Per-algorithm target */}
        {migration.length === 0 ? (
          <p className="rounded-md border border-emerald-200 bg-emerald-50/60 p-3 text-xs text-emerald-700 dark:border-emerald-900/50 dark:bg-emerald-950/30 dark:text-emerald-300">
            No migration required — the inventory carries no quantum-vulnerable algorithms.
          </p>
        ) : (
          <div>
            <p className="mb-2 text-xs font-medium text-zinc-500 dark:text-zinc-400">
              Recommended replacements
            </p>
            <div className="space-y-2">
              {migration.map((r, i) => (
                <div
                  key={`${r.name}-${i}`}
                  className="flex items-center gap-2 rounded-md border border-zinc-200 p-2 dark:border-zinc-800"
                >
                  <Badge variant="outline" className="shrink-0 border-orange-500/50 text-orange-600 dark:text-orange-400">
                    {r.name}
                  </Badge>
                  <span className="shrink-0 text-zinc-400" aria-hidden>→</span>
                  <span className="min-w-0 flex-1 truncate text-sm font-medium text-emerald-600 dark:text-emerald-400">
                    {r.migration_roadmap ?? r.migration_target ?? "ML-KEM / ML-DSA"}
                  </span>
                </div>
              ))}
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

/** 8 — Compliance tri-state matrix: all CBOM frameworks with a per-requirement
 *  drilldown + framework-group + failures-only controls (F3). Verdicts and
 *  palette mirror AiBomVisualizations.ComplianceCoverage. */
function CbomComplianceMatrix({ compliance }: { compliance: CbomCompliance }) {
  const frameworks = useMemo(
    () =>
      Object.entries(compliance ?? {})
        .filter(([k, v]) => k !== "disclaimer" && typeof v === "object" && v !== null)
        .map(([k, v]) => ({ key: k, ...(v as FrameworkCoverage) })),
    [compliance]
  );
  const [group, setGroup] = useState<string>("all");
  const [active, setActive] = useState<string | null>(null);
  const [failingOnly, setFailingOnly] = useState(false);

  const shown = useMemo(() => {
    const keys = FRAMEWORK_GROUPS.find((g) => g.id === group)?.keys ?? [];
    return keys.length === 0
      ? frameworks
      : frameworks.filter((f) => keys.includes(f.key));
  }, [frameworks, group]);

  if (frameworks.length === 0) return null;

  const data = shown.map((f) => ({
    key: f.key,
    name: labelFramework(f.key),
    pass: f.pass,
    pass_with_evidence: f.pass_with_evidence ?? 0,
    fail: f.fail,
    out_of_scope: f.out_of_scope ?? 0,
    not_bom_evidenceable: f.not_bom_evidenceable ?? 0,
    na: f.na,
  }));

  const cfg: ChartConfig = Object.fromEntries(
    VERDICT_ORDER.map((v) => [v, { label: VERDICT_LABEL[v], color: VERDICT_COLOR[v] }])
  );

  // keep the drilldown target inside the currently-filtered set
  const activeFw =
    active && shown.some((f) => f.key === active)
      ? shown.find((f) => f.key === active)!
      : null;
  const reqsAll = activeFw?.requirements ?? [];
  const reqs = failingOnly ? reqsAll.filter((r) => isFailingVerdict(r.verdict)) : reqsAll;

  const chipCls = (on: boolean) =>
    `rounded-full border px-3 py-1 text-xs font-medium transition-colors cursor-pointer ${
      on
        ? "border-blue-500/60 bg-blue-500/10 text-blue-600 dark:text-blue-300"
        : "border-zinc-200 dark:border-zinc-700 text-zinc-500 dark:text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200"
    }`;

  return (
    <Card className="border-zinc-200 dark:border-zinc-800 col-span-full">
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <Scale className="w-4 h-4 text-emerald-600" />
          Crypto compliance readiness
        </CardTitle>
        <CardDescription>
          Per-framework tri-state verdicts (advisory). Coverage = pass / (pass + fail).
          <span className="font-medium"> Out of scope</span> (framework doesn&apos;t apply) and{" "}
          <span className="font-medium">Not BOM-evidenceable</span> (process evidence) are reported
          separately — never folded into pass or fail. Click a bar for per-requirement detail.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {/* controls: framework-group filter + failures-only toggle */}
        <div className="mb-4 flex flex-wrap items-center gap-2">
          <span className="text-xs font-medium text-zinc-500 dark:text-zinc-400 mr-1">Frameworks</span>
          {FRAMEWORK_GROUPS.map((g) => (
            <button
              key={g.id}
              type="button"
              className={chipCls(group === g.id)}
              onClick={() => {
                setGroup(g.id);
                setActive(null);
              }}
            >
              {g.label}
            </button>
          ))}
          <span className="mx-1 h-4 w-px bg-zinc-200 dark:bg-zinc-700" aria-hidden />
          <button
            type="button"
            className={chipCls(failingOnly)}
            onClick={() => setFailingOnly((v) => !v)}
          >
            Failures only
          </button>
        </div>

        {data.length === 0 ? (
          <EmptyChart message="No frameworks in this group" />
        ) : (
          <div style={{ height: Math.max(160, data.length * 34 + 40) }}>
            <ChartContainer config={cfg} className="aspect-auto h-full w-full">
              <BarChart data={data} layout="vertical" margin={{ top: 4, right: 16, bottom: 4, left: 8 }}>
                <XAxis type="number" hide />
                <YAxis
                  dataKey="name"
                  type="category"
                  width={140}
                  tickLine={false}
                  axisLine={false}
                  className="text-xs"
                />
                <ChartTooltip content={<ChartTooltipContent />} />
                {VERDICT_ORDER.map((v, i) => (
                  <Bar
                    key={v}
                    dataKey={v}
                    stackId="a"
                    fill={VERDICT_COLOR[v]}
                    cursor="pointer"
                    radius={
                      i === 0
                        ? [3, 0, 0, 3]
                        : i === VERDICT_ORDER.length - 1
                          ? [0, 3, 3, 0]
                          : undefined
                    }
                    onClick={(_, idx) => setActive(data[idx].key)}
                  />
                ))}
              </BarChart>
            </ChartContainer>
          </div>
        )}

        <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5 text-xs text-zinc-600 dark:text-zinc-400">
          {VERDICT_ORDER.map((v) => (
            <span key={v} className="flex items-center gap-1.5">
              <span className="size-2.5 rounded-sm" style={{ background: VERDICT_COLOR[v] }} />
              {VERDICT_LABEL[v]}
            </span>
          ))}
        </div>

        {activeFw && (
          <div className="mt-4 rounded-lg border border-zinc-200 dark:border-zinc-800">
            <div className="px-3 py-2 text-sm font-medium border-b border-zinc-200 dark:border-zinc-800 flex items-center justify-between">
              <span>
                {labelFramework(activeFw.key)} — requirements
                {activeFw.coverage != null && (
                  <span className="ml-2 text-xs font-normal text-zinc-500">
                    coverage {Math.round(activeFw.coverage * 100)}%
                  </span>
                )}
              </span>
              <button
                type="button"
                className="text-xs text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300 cursor-pointer"
                onClick={() => setActive(null)}
              >
                Close
              </button>
            </div>
            {reqs.length === 0 ? (
              <div className="px-3 py-4 text-sm text-zinc-500">
                No {failingOnly ? "failing " : ""}requirements.
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-36">Verdict</TableHead>
                    <TableHead className="w-24">ID</TableHead>
                    <TableHead>Requirement</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {reqs.map((r) => (
                    <TableRow key={r.id}>
                      <TableCell>
                        <Badge className={VERDICT_BADGE[r.verdict] ?? VERDICT_BADGE.na}>
                          {VERDICT_LABEL[r.verdict] ?? r.verdict}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-zinc-600 dark:text-zinc-400">{r.id}</TableCell>
                      <TableCell className="text-sm">
                        {r.title}
                        {r.evidence && <div className="text-xs text-zinc-500 mt-0.5">{r.evidence}</div>}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </div>
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
 * only when the I1 `cbom_graph` projection is present; the compliance tri-state
 * matrix (F3) renders only when `cbom_compliance` carries ≥1 framework.
 */
export function CbomCryptoCharts({
  distributions,
  graph,
  compliance,
}: {
  distributions?: CbomDistributions | null;
  graph?: CbomGraph | null;
  compliance?: CbomCompliance | null;
}) {
  if (!distributions) return null;
  const hasGraph = !!graph && (graph.nodes?.length ?? 0) > 0;
  const hasCompliance =
    !!compliance &&
    Object.entries(compliance).some(
      ([k, v]) => k !== "disclaimer" && typeof v === "object" && v !== null
    );
  const pqc = distributions.pqc;
  const migration = pqc?.migration ?? [];
  // The PQC readiness detail (F2 list + roadmap) renders whenever the scan graded
  // any quantum-relevant algorithm — even a fully quantum-safe repo, where the
  // panel reassures ("no migration required") rather than starving.
  const hasPqcDetail = (pqc?.quantum_vulnerable ?? 0) + (pqc?.quantum_safe ?? 0) > 0;
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <AlgorithmDistribution data={distributions.algorithms} />
        <WeakCryptoFindings data={distributions.weakness} />
        <PqcReadinessGauge pqc={distributions.pqc} />
      </div>
      {hasPqcDetail && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <QuantumVulnerableList migration={migration} />
          <MigrationRoadmap migration={migration} />
        </div>
      )}
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
      {hasCompliance && (
        <div className="grid grid-cols-1 gap-6">
          <CbomComplianceMatrix compliance={compliance!} />
        </div>
      )}
    </div>
  );
}

export default CbomCryptoCharts;

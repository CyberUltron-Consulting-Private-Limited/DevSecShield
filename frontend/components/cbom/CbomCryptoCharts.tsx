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

import { useMemo } from "react";
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
import { Button } from "@/components/ui/button";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import {
  HoverCard,
  HoverCardContent,
  HoverCardTrigger,
} from "@/components/ui/hover-card";
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
} from "lucide-react";
import CertCalendar from "@/components/cbom/CertCalendar";
import CryptoHeatmap from "@/components/cbom/CryptoHeatmap";
import { codeHeatmap, type CodeHeatRow } from "@/components/cbom/heatmapLogic";
import { BomGraphCard } from "@/components/bom/BomGraphCard";
import { pickBomGraph } from "@/components/bom/layout";
import type { BomGraph } from "@/components/bom/types";
import type { CbomFinding, CbomGraph } from "@/utils/backend_api";
import { filterFindingsByRelatedRefs } from "@/utils/relatedFindingMatch";
import { quantumCounts, type QuantumFields } from "@/components/cbom/quantumFilter";
import { ComplianceMatrix, type AttestHandler, type Compliance } from "@/components/compliance/ComplianceMatrix";
import { FRAMEWORK_GROUPS_CBOM_WITH_INDIA } from "@/components/compliance/frameworkLabels";
import {
  enrichPqcMigrationFromFindings,
  groupPqcMigrationRows,
  migrationDescriptor,
  pqcAccordionDefaultCollapsed,
  pqcDescription,
  pqcHowToFix,
} from "@/components/cbom/pqcMigrationGroup";
import { InfoTip } from "@/components/ui/info-tip";

export type {
  ComplianceVerdict,
  ComplianceRequirement,
  FrameworkCoverage,
} from "@/components/compliance/types";
export type CbomCompliance = Compliance;
export type { PqcMigrationGroup } from "@/components/cbom/pqcMigrationGroup";
export {
  enrichPqcMigrationFromFindings,
  groupPqcMigrationRows,
  pqcAccordionDefaultCollapsed,
  pqcDescription,
  pqcHowToFix,
  pqcMigrationGroupKey,
} from "@/components/cbom/pqcMigrationGroup";

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
    near_expiry?: boolean;
    weak_signature?: boolean;
    weak_key_size?: boolean;
    signature_algorithm?: string | null;
    key_size?: string | null;
    location?: string | null;
    bom_ref?: string | null;
  }>;
  /**
   * Cert/key-related related-crypto-material (private/public/secret keys +
   * opaque keystore credentials). Sibling of `certificates` for the expiry UI.
   */
  key_material?: Array<{
    name: string;
    material_kind: string;
    container_format?: string | null;
    parse_status?: string | null;
    location?: string | null;
    bom_ref?: string | null;
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
  /** Source file / discovery path (additive — grouped UX + HoverCard) */
  location?: string | null;
  /** Inventory bom-ref for View-finding join */
  bom_ref?: string | null;
  description?: string | null;
  suggested_fix?: string | null;
  finding_codes?: string[] | null;
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

const countConfig = {
  count: { label: "Count", color: C.primitive },
} satisfies ChartConfig;

// ── compliance tri-state matrix (F3) — shared ComplianceMatrix (Phase 0) ─────
// Default group remains All (never India / CERT-In in Phase 0).

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
        <InfoTip id="cbom.chart.algorithms" />
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
        <InfoTip id="cbom.chart.weak" />
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

/** 3 — PQC readiness gauge. Counts EVERY cryptographic asset of the scan (findings and clean inventory,
 * quantumFilter.inventoryRows) by the results table's Quantum column ("Quantum-safe" / "Broken today" /
 * "Quantum-vulnerable", quantumFilter.quantumCounts): an algorithm that is broken today is not quantum-ready. Same
 * rows and rule as the PDF and the scan list. Falls back to the stored ``distributions.pqc`` only when the page has
 * no rows. */
function PqcReadinessGauge({ pqc, rows }: { pqc: CbomDistributions["pqc"]; rows?: QuantumFields[] | null }) {
  const counts = rows && rows.length > 0 ? quantumCounts(rows) : null;
  const safe = counts ? counts.safe : pqc?.quantum_safe ?? 0;
  const vuln = counts ? counts.vulnerable : pqc?.quantum_vulnerable ?? 0;
  const broken = counts ? counts.broken : 0;
  const total = safe + vuln + broken;
  const pct = counts ? counts.readinessPct ?? 0 : pqc?.readiness_pct ?? 0;
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
        <InfoTip id="cbom.chart.pqc" />
        </CardTitle>
        <CardDescription>Quantum-safe share of every crypto asset (findings and clean inventory); algorithms broken today are not quantum-ready</CardDescription>
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
                Quantum-safe: {safe}
              </Badge>
              {broken > 0 && (
                <Badge variant="outline" className="border-amber-500/60 text-amber-700 dark:text-amber-400"
                  title="Already broken without a quantum computer: replace it now">
                  Broken today: {broken}
                </Badge>
              )}
              <Badge variant="outline" className="border-orange-500/50 text-orange-600 dark:text-orange-400">
                Quantum-vulnerable: {vuln}
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

/** HoverCard detail for one quantum-vulnerable instance (Shadow AI pattern). */
function PqcInstanceHover({
  row,
  onOpenFinding,
}: {
  row: PqcMigrationRow;
  onOpenFinding?: (finding: CbomFinding) => void;
}) {
  const location = String(row.location ?? "").trim();
  const description = pqcDescription(row);
  const fix = pqcHowToFix(row);
  const codes = (row.finding_codes ?? []).filter(Boolean);
  const why = [
    `Quantum-vulnerable (NIST level ${row.nist_quantum_security_level ?? 0})`,
    row.impact ? String(row.impact) : "",
    codes.length ? codes.join(", ") : "",
  ]
    .filter(Boolean)
    .join(" · ");
  return (
    <HoverCard openDelay={250} closeDelay={100}>
      <HoverCardTrigger asChild>
        <li
          data-testid="pqc-instance-row"
          className="flex items-start justify-between gap-2 rounded-md border border-orange-200/80 bg-orange-50/40 px-2.5 py-2 dark:border-orange-900/40 dark:bg-orange-950/20 cursor-default"
        >
          <div className="min-w-0 flex-1">
            <p className="truncate font-mono text-xs text-zinc-700 dark:text-zinc-300">
              {location || "Location not recorded"}
            </p>
            {row.impact && row.impact !== "—" ? (
              <p className="mt-0.5 text-[11px] text-zinc-500">{row.impact}</p>
            ) : null}
          </div>
          <Badge variant="outline" className={`shrink-0 text-[10px] ${impactBadgeClass(row.impact)}`}>
            Level {row.nist_quantum_security_level ?? 0}
          </Badge>
        </li>
      </HoverCardTrigger>
      <HoverCardContent
        align="start"
        side="left"
        className="w-80 max-w-sm space-y-3 text-xs"
        data-testid="pqc-instance-hover"
      >
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">Asset</p>
          <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100 break-all">{row.name}</p>
          <p className="text-xs text-zinc-500">{migrationDescriptor(row)}</p>
        </div>
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">Why</p>
          <p className="text-sm text-zinc-700 dark:text-zinc-300" data-testid="pqc-hover-why">
            {why}
          </p>
        </div>
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">Description</p>
          <p
            className="text-sm text-zinc-700 dark:text-zinc-300 whitespace-pre-wrap break-words"
            data-testid="pqc-hover-description"
          >
            {description}
          </p>
        </div>
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">How to fix</p>
          <p
            className="text-sm text-zinc-700 dark:text-zinc-300 whitespace-pre-wrap break-words"
            data-testid="pqc-hover-fix"
          >
            {fix}
          </p>
        </div>
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">Location</p>
          <p
            className="text-sm font-mono text-zinc-700 dark:text-zinc-300 break-all"
            data-testid="pqc-hover-location"
          >
            {location || "Location not recorded"}
          </p>
        </div>
        {onOpenFinding && (
          <Button
            type="button"
            size="sm"
            variant="outline"
            className="h-8 w-full cursor-pointer"
            data-testid="pqc-view-finding"
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              onOpenFinding({
                id: String(row.bom_ref || row.name),
                bom_ref: row.bom_ref ?? null,
                title: row.name,
                description: description === "—" ? "" : description,
                // a migration row without an impact is clean inventory (no finding), never a Medium finding
                impact: row.impact || "Info",
                risk_score: 0,
                status: "open",
                compliance_controls: [],
                owasp_top_10: [],
                suggested_fix: fix === "—" ? null : fix,
                algorithm_name: row.name,
                location: location || null,
              });
            }}
          >
            View finding
          </Button>
        )}
      </HoverCardContent>
    </HoverCard>
  );
}

/** F2a — Quantum-vulnerable list: Accordion groups + instance HoverCards. */
function QuantumVulnerableList({
  migration,
  onOpenFinding,
}: {
  migration: PqcMigrationRow[];
  onOpenFinding?: (finding: CbomFinding) => void;
}) {
  const groups = useMemo(() => groupPqcMigrationRows(migration), [migration]);
  const collapseDefault = pqcAccordionDefaultCollapsed(groups, migration.length);
  // Remount when the group set changes (fixture ↔ legacy scan) so default
  // expanded/collapsed state resets. Uncontrolled Accordion — controlled
  // value[] was sticking closed after mode switches in headless verify.
  // Use short index values — long keys with `/()|` broke Radix toggles.
  const accordionKey = groups.map((g) => g.key).join("\n");
  const defaultOpen = collapseDefault
    ? []
    : groups.map((_, gi) => `vuln-${gi}`);

  return (
    <Card className="border-zinc-200 dark:border-zinc-800" data-testid="pqc-vulnerable-list">
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <ShieldX className="w-4 h-4 text-orange-500" />
          Quantum-vulnerable algorithms
          <InfoTip id="cbom.chart.qv" />
          {migration.length > 0 && (
            <span className="text-xs font-normal text-zinc-500">
              ({groups.length} group{groups.length === 1 ? "" : "s"} · {migration.length})
            </span>
          )}
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
            <InfoTip id="cbom.chart.qv_none" />
            </p>
            <p className="text-xs text-zinc-500 dark:text-zinc-400">
              Every inventoried algorithm is quantum-resistant at its parameter size.
            </p>
          </div>
        ) : (
          <div className="max-h-[28rem] overflow-y-auto pr-1">
            <Accordion
              key={accordionKey}
              type="multiple"
              defaultValue={defaultOpen}
              className="w-full"
            >
              {groups.map((g, gi) => (
                <AccordionItem
                  key={g.key}
                  value={`vuln-${gi}`}
                  data-testid="pqc-vuln-group"
                >
                  <AccordionTrigger className="py-2.5 hover:no-underline">
                    <div className="flex min-w-0 flex-1 items-center justify-between gap-2 pr-2">
                      <div className="min-w-0 text-left">
                        <p className="truncate text-sm font-medium text-zinc-900 dark:text-zinc-100">
                          {g.name}
                        </p>
                        <p className="truncate text-xs text-zinc-500 dark:text-zinc-400">
                          {g.descriptor}
                        </p>
                      </div>
                      <div className="flex shrink-0 items-center gap-1.5">
                        <Badge
                          variant="secondary"
                          className="tabular-nums"
                          data-testid="pqc-group-count"
                        >
                          {g.instances.length}
                        </Badge>
                        <Badge
                          variant="outline"
                          className="border-orange-500/50 text-orange-600 dark:text-orange-400"
                        >
                          Level {g.nistLevel}
                        </Badge>
                        <Badge variant="outline" className={impactBadgeClass(g.maxImpact)}>
                          {g.maxImpact ?? "—"}
                        </Badge>
                      </div>
                    </div>
                  </AccordionTrigger>
                  <AccordionContent>
                    <ul className="space-y-1.5 pb-1">
                      {g.instances.map((r, i) => (
                        <PqcInstanceHover
                          key={r.bom_ref || `${r.name}-${r.location}-${i}`}
                          row={r}
                          onOpenFinding={onOpenFinding}
                        />
                      ))}
                    </ul>
                  </AccordionContent>
                </AccordionItem>
              ))}
            </Accordion>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

/** F2b — Migration roadmap: CNSA strip + Accordion groups matching the list. */
function MigrationRoadmap({
  migration,
  onOpenFinding,
}: {
  migration: PqcMigrationRow[];
  onOpenFinding?: (finding: CbomFinding) => void;
}) {
  const groups = useMemo(() => groupPqcMigrationRows(migration), [migration]);
  const collapseDefault = pqcAccordionDefaultCollapsed(groups, migration.length);
  const accordionKey = `roadmap:${groups.map((g) => g.key).join("\n")}`;
  const defaultOpen = collapseDefault
    ? []
    : groups.map((_, gi) => `road-${gi}`);

  return (
    <Card className="border-zinc-200 dark:border-zinc-800" data-testid="pqc-migration-roadmap">
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <Rocket className="w-4 h-4 text-blue-500" />
          PQC migration roadmap
          <InfoTip id="cbom.chart.roadmap" />
          {migration.length > 0 && (
            <span className="text-xs font-normal text-zinc-500">
              ({groups.length} target{groups.length === 1 ? "" : "s"})
            </span>
          )}
        </CardTitle>
        <CardDescription>
          NIST-standardized replacement per algorithm, against the CNSA 2.0 timeline
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div>
          <p className="mb-2 flex items-center gap-1.5 text-xs font-medium text-zinc-500 dark:text-zinc-400">
            <CalendarClock className="h-3.5 w-3.5" />
            CNSA 2.0 transition milestones
            <InfoTip id="cbom.chart.cnsa" />
          </p>
          <ol className="flex flex-wrap gap-2">
            {CNSA_MILESTONES.map((m) => (
              <li
                key={m.year}
                className="flex-1 min-w-[120px] rounded-md border border-zinc-200 bg-zinc-50/60 p-2 dark:border-zinc-800 dark:bg-zinc-900/40"
              >
                <p className="text-sm font-semibold tabular-nums text-blue-600 dark:text-blue-400">
                  {m.year}
                </p>
                <p className="text-[11px] leading-tight text-zinc-600 dark:text-zinc-400">
                  {m.label}
                </p>
              </li>
            ))}
          </ol>
        </div>
        {migration.length === 0 ? (
          <p className="rounded-md border border-emerald-200 bg-emerald-50/60 p-3 text-xs text-emerald-700 dark:border-emerald-900/50 dark:bg-emerald-950/30 dark:text-emerald-300">
            No migration required — the inventory carries no quantum-vulnerable algorithms.
          </p>
        ) : (
          <div>
            <p className="mb-2 text-xs font-medium text-zinc-500 dark:text-zinc-400">
              Recommended replacements
            <InfoTip id="cbom.chart.replacements" />
            </p>
            <div className="max-h-[28rem] overflow-y-auto pr-1">
              <Accordion
                key={accordionKey}
                type="multiple"
                defaultValue={defaultOpen}
                className="w-full"
              >
                {groups.map((g, gi) => (
                  <AccordionItem
                    key={g.key}
                    value={`road-${gi}`}
                    data-testid="pqc-roadmap-group"
                  >
                    <AccordionTrigger className="py-2.5 hover:no-underline">
                      <div className="flex min-w-0 flex-1 items-center gap-2 pr-2">
                        <Badge
                          variant="outline"
                          className="shrink-0 border-orange-500/50 text-orange-600 dark:text-orange-400"
                        >
                          {g.name}
                        </Badge>
                        <span className="shrink-0 text-zinc-400" aria-hidden>
                          →
                        </span>
                        <span className="min-w-0 flex-1 truncate text-left text-sm font-medium text-emerald-600 dark:text-emerald-400">
                          {g.roadmap}
                        </span>
                        {g.instances.length > 1 && (
                          <Badge
                            variant="secondary"
                            className="shrink-0 tabular-nums"
                            data-testid="pqc-roadmap-count"
                          >
                            ×{g.instances.length}
                          </Badge>
                        )}
                      </div>
                    </AccordionTrigger>
                    <AccordionContent>
                      <ul className="space-y-1.5 pb-1">
                        {g.instances.map((r, i) => (
                          <PqcInstanceHover
                            key={r.bom_ref || `${r.name}-${r.location}-${i}`}
                            row={r}
                            onOpenFinding={onOpenFinding}
                          />
                        ))}
                      </ul>
                    </AccordionContent>
                  </AccordionItem>
                ))}
              </Accordion>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

/** 4 — Certificate expiry + related key/keystore material. */
const CERT_LIST_CAP = 8;

type CertRow = NonNullable<CbomDistributions["certificates"]>[number];
type KeyMaterialRow = NonNullable<CbomDistributions["key_material"]>[number];

function certRowsFromGraph(graph?: CbomGraph | null): CertRow[] {
  if (!graph?.nodes?.length) return [];
  return graph.nodes
    .filter((n) => n.asset_type === "certificate")
    .map((n) => ({
      name: n.label || n.id,
      not_valid_after: null,
      self_signed: false,
      expired: false,
      bom_ref: n.id,
    }));
}

function certRowsFromFindings(findings?: CbomFinding[] | null): CertRow[] {
  if (!findings?.length) return [];
  return findings
    .filter((f) => f.asset_type === "certificate")
    .map((f) => ({
      name: f.algorithm_name || f.title,
      not_valid_after: f.not_valid_after ?? null,
      self_signed: Boolean(f.self_signed),
      expired: Boolean(f.expired),
      location: f.location,
      bom_ref: f.bom_ref,
    }));
}

function keyMaterialFromFindings(findings?: CbomFinding[] | null): KeyMaterialRow[] {
  if (!findings?.length) return [];
  const rows: KeyMaterialRow[] = [];
  for (const f of findings) {
    if (f.asset_type !== "related-crypto-material") continue;
    const kind = f.material_kind || "key";
    if (
      !["private-key", "public-key", "secret-key", "key", "credential"].includes(kind)
    ) {
      continue;
    }
    rows.push({
      name: f.algorithm_name || f.title,
      material_kind: kind,
      container_format: f.container_format ?? null,
      location: f.location,
      bom_ref: f.bom_ref,
    });
  }
  return rows;
}

function keyMaterialFromGraph(graph?: CbomGraph | null): KeyMaterialRow[] {
  if (!graph?.nodes?.length) return [];
  return graph.nodes
    .filter((n) => n.asset_type === "related-crypto-material")
    .map((n) => ({
      name: n.label || n.id,
      material_kind: "key",
      bom_ref: n.id,
    }));
}

function resolveCertificates(
  distributions: CbomDistributions | null | undefined,
  graph?: CbomGraph | null,
  findings?: CbomFinding[] | null,
): CertRow[] {
  const fromDist = distributions?.certificates ?? [];
  if (fromDist.length > 0) return fromDist;
  const fromGraph = certRowsFromGraph(graph);
  if (fromGraph.length > 0) return fromGraph;
  return certRowsFromFindings(findings);
}

function resolveKeyMaterial(
  distributions: CbomDistributions | null | undefined,
  graph?: CbomGraph | null,
  findings?: CbomFinding[] | null,
): KeyMaterialRow[] {
  const fromDist = distributions?.key_material ?? [];
  if (fromDist.length > 0) return fromDist;
  const fromFindings = keyMaterialFromFindings(findings);
  if (fromFindings.length > 0) return fromFindings;
  return keyMaterialFromGraph(graph);
}

function CertificateExpiry({
  certificates,
  keyMaterial,
}: {
  certificates: CertRow[];
  keyMaterial: KeyMaterialRow[];
}) {
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
  const listRows = useMemo(() => {
    const certs = certificates ?? [];
    const sorted = [...certs].sort((a, b) => {
      const rank = (c: CertRow) => (c.expired ? 0 : c.near_expiry ? 1 : 2);
      const d = rank(a) - rank(b);
      return d !== 0 ? d : a.name.localeCompare(b.name);
    });
    return sorted.slice(0, CERT_LIST_CAP);
  }, [certificates]);
  const materialList = useMemo(() => {
    const mats = keyMaterial ?? [];
    return [...mats]
      .sort((a, b) => a.name.localeCompare(b.name))
      .slice(0, CERT_LIST_CAP);
  }, [keyMaterial]);
  const certCount = certificates?.length ?? 0;
  const matCount = keyMaterial?.length ?? 0;
  const overflow = Math.max(0, certCount - CERT_LIST_CAP);
  const matOverflow = Math.max(0, matCount - CERT_LIST_CAP);
  const emptyBoth = certCount === 0 && matCount === 0;

  const emptyMessage =
    matCount === 0 && certCount === 0
      ? "No X.509 certificates or key material in this scan"
      : certCount === 0
        ? `No X.509 certificates — ${matCount} key/keystore asset${matCount === 1 ? "" : "s"} inventoried (keys have no notAfter)`
        : "No X.509 certificates in this scan";

  return (
    <Card className="border-zinc-200 dark:border-zinc-800">
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
          Certificate expiry
        <InfoTip id="cbom.chart.cert_expiry" />
        </CardTitle>
        <CardDescription>
          X.509 validity and related key / keystore material
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {emptyBoth ? (
          <EmptyChart message={emptyMessage} />
        ) : (
          <>
            <div className="space-y-2">
              <p className="text-xs font-medium uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
                X.509 certificates ({certCount})
              </p>
              {certCount === 0 ? (
                <p className="text-sm text-zinc-500 dark:text-zinc-400">{emptyMessage}</p>
              ) : (
                <>
                  {rows.length > 0 && (
                    <ChartContainer config={countConfig} className="aspect-auto h-[160px] w-full">
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
                  <div className="space-y-2">
                    {listRows.map((c, i) => (
                      <div
                        key={`${c.name}-${c.not_valid_after ?? ""}-${i}`}
                        className="flex items-start justify-between gap-2 rounded-md border border-zinc-200 p-2 dark:border-zinc-800"
                      >
                        <div className="min-w-0 flex-1">
                          <p className="truncate text-sm font-medium text-zinc-900 dark:text-zinc-100">
                            {c.name}
                          </p>
                          <p className="truncate text-xs text-zinc-500 dark:text-zinc-400">
                            {c.not_valid_after
                              ? `Expires ${c.not_valid_after.slice(0, 10)}`
                              : "Expiry unknown"}
                            {c.location ? ` · ${c.location}` : ""}
                          </p>
                        </div>
                        <div className="flex shrink-0 flex-wrap justify-end gap-1">
                          {c.expired && (
                            <Badge variant="outline" className="border-red-500/50 text-red-600 dark:text-red-400">
                              Expired
                            </Badge>
                          )}
                          {!c.expired && c.near_expiry && (
                            <Badge variant="outline" className="border-orange-500/50 text-orange-600 dark:text-orange-400">
                              Near expiry
                            </Badge>
                          )}
                          {c.self_signed && (
                            <Badge variant="outline" className="border-amber-500/50 text-amber-700 dark:text-amber-400">
                              Self-signed
                            </Badge>
                          )}
                          {!c.expired && !c.near_expiry && !c.self_signed && (
                            <Badge variant="outline" className="border-emerald-500/50 text-emerald-600 dark:text-emerald-400">
                              Valid
                            </Badge>
                          )}
                        </div>
                      </div>
                    ))}
                    {overflow > 0 && (
                      <p className="text-xs text-zinc-500 dark:text-zinc-400">
                        +{overflow} more
                      </p>
                    )}
                  </div>
                </>
              )}
            </div>

            <div className="space-y-2 border-t border-zinc-200 pt-3 dark:border-zinc-800">
              <p className="text-xs font-medium uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
                Key / keystore material ({matCount})
              </p>
              {matCount === 0 ? (
                <p className="text-sm text-zinc-500 dark:text-zinc-400">
                  No private keys or keystore containers in this scan
                </p>
              ) : (
                <div className="space-y-2">
                  {materialList.map((m, i) => (
                    <div
                      key={`${m.name}-${m.material_kind}-${i}`}
                      className="flex items-start justify-between gap-2 rounded-md border border-zinc-200 p-2 dark:border-zinc-800"
                    >
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm font-medium text-zinc-900 dark:text-zinc-100">
                          {m.name}
                        </p>
                        <p className="truncate text-xs text-zinc-500 dark:text-zinc-400">
                          {m.location || "location unknown"}
                          {m.container_format ? ` · ${m.container_format}` : ""}
                          {m.parse_status === "opaque" ? " · opaque (no password parse)" : ""}
                        </p>
                      </div>
                      <Badge variant="outline" className="border-slate-500/50 text-slate-600 dark:text-slate-300">
                        {m.material_kind}
                      </Badge>
                    </div>
                  ))}
                  {matOverflow > 0 && (
                    <p className="text-xs text-zinc-500 dark:text-zinc-400">
                      +{matOverflow} more
                    </p>
                  )}
                </div>
              )}
            </div>
          </>
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
        <InfoTip id="cbom.chart.protocols" />
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
        <InfoTip id="cbom.chart.asset_types" />
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

// ── crypto dependency graph (I1 cbom_graph) via shared BomGraphCard ──────────

/** 7 — Crypto dependency graph: cert/protocol/material lineage → algorithms. */
function CryptoDependencyGraph({
  graph,
  graphCompact,
  graphExpanded,
}: {
  graph?: CbomGraph | null;
  graphCompact?: CbomGraph | BomGraph | null;
  graphExpanded?: CbomGraph | BomGraph | null;
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
      lane="cbom"
      graph={compact}
      expandedGraph={expanded}
      title="Crypto dependency graph"
      description="Folders contain crypto assets; libraries provide them; each asset belongs to an algorithm family. Certificate / protocol / key lineage from the CycloneDX file. Riskiest assets first; the rest are folded into +N nodes."
      icon={<Share2 className="w-4 h-4 text-indigo-500" />}
      heightClass="h-[360px]"
    />
  );
}

/** 8 — Compliance tri-state matrix via shared ComplianceMatrix (Phase 0). */
function CbomComplianceMatrix({
  compliance,
  onAttest,
}: {
  compliance: CbomCompliance;
  onAttest?: AttestHandler;
}) {
  return (
    <ComplianceMatrix
      compliance={compliance}
      title="Crypto compliance readiness"
      icon="scale"
      groups={FRAMEWORK_GROUPS_CBOM_WITH_INDIA}
      defaultGroup="all"
      enableFailingOnly
      enableAttestation
      onAttest={onAttest}
      className="border-zinc-200 dark:border-zinc-800 col-span-full"
    />
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
  graphCompact,
  graphExpanded,
  compliance,
  onAttest,
  findings,
  inventory,
  onOpenFinding,
}: {
  distributions?: CbomDistributions | null;
  graph?: CbomGraph | null;
  graphCompact?: CbomGraph | BomGraph | null;
  graphExpanded?: CbomGraph | BomGraph | null;
  compliance?: CbomCompliance | null;
  onAttest?: AttestHandler;
  /** Findings list for bom_ref → Dialog join (optional; HoverCard still works). */
  findings?: CbomFinding[] | null;
  /** Every row of the scan (findings + clean inventory) for the readiness gauge; the findings when absent. */
  inventory?: QuantumFields[] | null;
  onOpenFinding?: (finding: CbomFinding) => void;
}) {
  if (!distributions) return null;
  const hasGraph =
    (!!graph && (graph.nodes?.length ?? 0) > 0) ||
    (!!graphCompact && (graphCompact.nodes?.length ?? 0) > 0);
  const hasCompliance =
    !!compliance &&
    Object.entries(compliance).some(
      ([k, v]) => k !== "disclaimer" && typeof v === "object" && v !== null
    );
  const pqc = distributions.pqc;
  // Legacy scans: migration[] lacks location/bom_ref — join from findings so
  // Accordion instances show real paths without requiring a rescan.
  const migration = enrichPqcMigrationFromFindings(
    pqc?.migration ?? [],
    findings ?? [],
  );
  // The PQC readiness detail (F2 list + roadmap) renders whenever the scan graded
  // any quantum-relevant algorithm — even a fully quantum-safe repo, where the
  // panel reassures ("no migration required") rather than starving.
  const hasPqcDetail = (pqc?.quantum_vulnerable ?? 0) + (pqc?.quantum_safe ?? 0) > 0;

  const openPqcFinding = (partial: CbomFinding) => {
    if (!onOpenFinding) return;
    const list = findings ?? [];
    const ref = (partial.bom_ref || "").trim();
    if (ref && list.length) {
      const matched = filterFindingsByRelatedRefs(list, [ref]);
      if (matched[0]) {
        onOpenFinding(matched[0]);
        return;
      }
    }
    // Title + location (works for legacy findings without bom_ref)
    const title = (partial.title || partial.algorithm_name || "").toLowerCase();
    const loc = (partial.location || "").toLowerCase();
    if (title && loc && list.length) {
      const byLoc = list.find(
        (f) =>
          (f.algorithm_name || f.title || "").toLowerCase() === title &&
          (f.location || "").toLowerCase() === loc,
      );
      if (byLoc) {
        onOpenFinding(byLoc);
        return;
      }
    }
    onOpenFinding(partial);
  };

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <AlgorithmDistribution data={distributions.algorithms} />
        <WeakCryptoFindings data={distributions.weakness} />
        <PqcReadinessGauge pqc={distributions.pqc} rows={inventory ?? findings} />
      </div>
      {hasPqcDetail && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <QuantumVulnerableList migration={migration} onOpenFinding={openPqcFinding} />
          <MigrationRoadmap migration={migration} onOpenFinding={openPqcFinding} />
        </div>
      )}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {graph && (graph.nodes?.length ?? 0) > 0 && (
          <AssetTypeDistribution graph={graph} />
        )}
        <CertificateExpiry
          certificates={resolveCertificates(distributions, graph, findings)}
          keyMaterial={resolveKeyMaterial(distributions, graph, findings)}
        />
        <ProtocolTls data={distributions.protocols} />
      </div>
      <CodeHeatmapAndCalendar
        findings={findings ?? []}
        certificates={resolveCertificates(distributions, graph, findings)}
      />
      {hasGraph && (
        <div className="grid grid-cols-1 gap-6">
          <CryptoDependencyGraph
            graph={graph}
            graphCompact={graphCompact}
            graphExpanded={graphExpanded}
          />
        </div>
      )}
      {hasCompliance && (
        <div className="grid grid-cols-1 gap-6">
          <CbomComplianceMatrix compliance={compliance!} onAttest={onAttest} />
        </div>
      )}
    </div>
  );
}

/** Heat-map (algorithm family x asset type, worst impact) from the scan's rows, and the certificate calendar from
 * ``cbom_distributions.certificates``: the same views a collection run shows, built from data this page has. */
function CodeHeatmapAndCalendar({ findings, certificates }: { findings: CbomFinding[]; certificates: CertRow[] }) {
  const heat = useMemo(() => codeHeatmap(findings as unknown as CodeHeatRow[]), [findings]);
  const certs = useMemo(
    () => certificates.filter((c) => c.not_valid_after).map((c) => ({ name: c.name, not_after: c.not_valid_after, location: c.location })),
    [certificates],
  );
  if (heat.rows.length === 0 && certs.length === 0) return null;
  return (
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
      {heat.rows.length > 0 && (
        <Card>
          <CardContent className="pt-6">
            <CryptoHeatmap data={heat} title="Algorithm family × asset type" testId="code-heatmap" />
          </CardContent>
        </Card>
      )}
      {certs.length > 0 && (
        <Card>
          <CardContent className="pt-6">
            <CertCalendar certs={certs} testId="code-cert-calendar" />
          </CardContent>
        </Card>
      )}
    </div>
  );
}

export default CbomCryptoCharts;

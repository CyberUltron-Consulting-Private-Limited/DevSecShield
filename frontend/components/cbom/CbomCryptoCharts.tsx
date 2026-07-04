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
 * Charts: Algorithm distribution · Weak-crypto findings · PQC readiness gauge
 * (nistQuantumSecurityLevel) · Certificate expiry · Protocol / TLS.
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
import {
  BarChart3,
  ShieldAlert,
  Atom,
  ShieldCheck,
  Network,
} from "lucide-react";

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
  WEAK_KEY_SIZE: "Weak key size",
  WEAK_PROTOCOL: "Weak protocol",
  EXPIRED_CERTIFICATE: "Expired certificate",
  QUANTUM_VULNERABLE: "Quantum-vulnerable",
};

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

/** 2 — Weak-crypto findings: weakness flags by code. */
function WeakCryptoFindings({ data }: { data: Record<string, number> }) {
  const rows = useMemo(
    () =>
      Object.entries(data ?? {})
        .map(([k, count]) => ({ name: labelWeakness(k), count }))
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
        <CardDescription>Weak / deprecated crypto by category</CardDescription>
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
              <Bar dataKey="count" fill={C.weak} radius={3} />
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

/**
 * Composes the five CBOM crypto charts. Renders nothing when the run-object
 * carries no `cbom_distributions` (e.g. a legacy worker CBOM scan) so the
 * existing dashboard charts remain the sole view in that case.
 */
export function CbomCryptoCharts({ distributions }: { distributions?: CbomDistributions | null }) {
  if (!distributions) return null;
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <AlgorithmDistribution data={distributions.algorithms} />
        <WeakCryptoFindings data={distributions.weakness} />
        <PqcReadinessGauge pqc={distributions.pqc} />
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <CertificateExpiry certificates={distributions.certificates} />
        <ProtocolTls data={distributions.protocols} />
      </div>
    </div>
  );
}

export default CbomCryptoCharts;

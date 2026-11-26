// 3 — PQC readiness gauge of the crypto charts (CbomCryptoCharts), on code scans and Sources runs.
//
// Code scan: counts EVERY cryptographic asset of the scan (findings and clean inventory, quantumFilter.inventoryRows)
// by the results table's Quantum column (quantumFilter.quantumCounts): an algorithm that is broken today is not
// quantum-ready. Same rows and rule as the PDF and the scan list. Falls back to the stored ``distributions.pqc`` when
// the page has no rows.
// Sources run (staging QA round 4, C): the number is posture's readiness over the JUDGED assets (Rule P: passed in as
// ``pqc.readiness_pct`` by model.applyPostureToDistributions, never recounted here); the card says so, and a withheld
// readiness reads "Withheld" with posture's reason instead of 0 %.

import { PolarAngleAxis, RadialBar, RadialBarChart } from "recharts";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ChartContainer, type ChartConfig } from "@/components/ui/chart";
import { InfoTip } from "@/components/ui/info-tip";
import { Atom } from "lucide-react";
import { quantumCounts, type QuantumFields } from "@/components/cbom/quantumFilter";
import { pqcGaugeCopy } from "@/components/cbom/results/readinessExplain";
import type { CbomReadinessBasis } from "@/utils/backend_api";

const QUANTUM_SAFE = "#3b82f6"; // blue-500, CbomCryptoCharts' C.quantumSafe

export interface PqcGaugeInput {
  quantum_vulnerable: number;
  quantum_safe: number;
  readiness_pct: number | null;
  /** algorithms broken today (MD5, SHA-1, DES ...): judged, not quantum-safe. A code scan's engine pqc.broken_today
   * (PR #500 takeover); older engines and Sources runs omit it (a run's figures are posture's, Rule P) */
  broken_today?: number;
  hybrid?: number;
  /** a Sources run's posture readiness_basis (why a readiness is withheld) */
  readiness_basis?: CbomReadinessBasis | null;
}

export function PqcReadinessGauge({ pqc, rows, scope = "code" }: {
  pqc: PqcGaugeInput | null | undefined;
  rows?: QuantumFields[] | null;
  scope?: "run" | "code";
}) {
  // a run never counts rows here (Rule P): its figures are posture's
  const counts = scope === "code" && rows && rows.length > 0 ? quantumCounts(rows) : null;
  const safe = counts ? counts.safe : pqc?.quantum_safe ?? 0;
  const vuln = counts ? counts.vulnerable : pqc?.quantum_vulnerable ?? 0;
  const broken = counts ? counts.broken : pqc?.broken_today ?? 0;
  const total = safe + vuln + broken;
  const readiness = counts ? counts.readinessPct : pqc?.readiness_pct;
  const copy = pqcGaugeCopy(scope, readiness, pqc?.readiness_basis);
  const pct = readiness ?? 0;
  const gaugeData = [{ name: "readiness", value: copy.withheld || readiness == null ? 0 : pct, fill: QUANTUM_SAFE }];
  const gaugeConfig = { value: { label: "Readiness", color: QUANTUM_SAFE } } satisfies ChartConfig;
  const noNumber = scope === "run" && readiness == null;
  return (
    <Card className="border-zinc-200 dark:border-zinc-800">
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <Atom className="w-4 h-4 text-blue-600 dark:text-blue-400" />
          PQC readiness
        <InfoTip id="cbom.chart.pqc" />
        </CardTitle>
        <CardDescription>{copy.description}</CardDescription>
      </CardHeader>
      <CardContent>
        {total === 0 && !noNumber ? (
          <div className="flex h-[260px] items-center justify-center text-sm text-zinc-500 dark:text-zinc-400">
            No quantum-relevant algorithms
          </div>
        ) : (
          <div className="flex flex-col items-center">
            <div className="relative">
              <ChartContainer config={gaugeConfig} className="mx-auto aspect-square h-[200px]">
                <RadialBarChart data={gaugeData} startAngle={90} endAngle={-270} innerRadius={72} outerRadius={100}>
                  <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
                  <RadialBar dataKey="value" cornerRadius={8} background fill={QUANTUM_SAFE} />
                </RadialBarChart>
              </ChartContainer>
              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <p className={`font-bold tabular-nums text-zinc-900 dark:text-zinc-100 ${noNumber ? "text-xl" : "text-3xl"}`}
                   data-testid="pqc-readiness-value">{copy.value}</p>
                <p className="text-xs text-zinc-500 dark:text-zinc-400">{noNumber ? "no percentage" : "quantum-safe"}</p>
              </div>
            </div>
            {copy.withheld && (
              <p className="mt-2 max-w-xs text-center text-xs text-zinc-600 dark:text-zinc-400" data-testid="pqc-readiness-withheld">
                {copy.withheld}
              </p>
            )}
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
                  Hybrid: {pqc?.hybrid}
                </Badge>
              )}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

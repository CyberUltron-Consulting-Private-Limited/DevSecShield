"use client";

/**
 * Cross-BOM CERT-In Guidelines posture — team dashboard only.
 * Per-scan pages use `CertInLanePosture` with a BOM lane.
 */

import { useMemo, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
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
import { Scale } from "lucide-react";
import type { AttestHandler } from "@/components/compliance/ComplianceMatrix";
import { CertInRequirementDrilldown } from "@/components/certin/CertInRequirementDrilldown";
import {
  CERTIN_DIM_LABELS,
  CERTIN_VERDICT_COLORS,
  type CertInDimRollup,
  type CertInRollupData,
} from "@/components/certin/certinShared";
import type { RelatedFindingFields } from "@/utils/relatedFindingMatch";

export type { CertInRollupData } from "@/components/certin/certinShared";

function dimTotal(d: CertInDimRollup): number {
  return (
    (d.pass ?? 0) +
    (d.pass_with_evidence ?? 0) +
    (d.fail ?? 0) +
    (d.out_of_scope ?? 0) +
    (d.not_bom_evidenceable ?? 0) +
    (d.na ?? 0)
  );
}

export function CertInRollup({
  rollup,
  onAttest,
  onViewFindings,
  findings,
  refAliases,
}: {
  rollup?: CertInRollupData | null;
  onAttest?: AttestHandler;
  onViewFindings?: (refs: string[]) => void;
  findings?: RelatedFindingFields[] | null;
  refAliases?: Record<string, string>;
}) {
  const dims = useMemo(() => {
    const raw = rollup?.certin_posture;
    if (!raw || typeof raw !== "object") return [];
    return Object.entries(raw)
      .map(([key, v]) => ({
        key,
        ...(v as CertInDimRollup),
      }))
      .filter((d) => dimTotal(d) > 0);
  }, [rollup]);

  const [active, setActive] = useState<string | null>(null);

  if (dims.length === 0) return null;

  const C = CERTIN_VERDICT_COLORS;
  const chartData = dims.map((p) => ({
    key: p.key,
    name: CERTIN_DIM_LABELS[p.key] ?? p.key,
    pass: p.pass ?? 0,
    pass_with_evidence: p.pass_with_evidence ?? 0,
    fail: p.fail ?? 0,
    out_of_scope: p.out_of_scope ?? 0,
    not_bom_evidenceable: p.not_bom_evidenceable ?? 0,
    na: p.na ?? 0,
  }));

  const totalVerdicts = chartData.reduce(
    (sum, d) =>
      sum +
      d.pass +
      d.pass_with_evidence +
      d.fail +
      d.out_of_scope +
      d.not_bom_evidenceable +
      d.na,
    0,
  );

  const cfg: ChartConfig = {
    pass: { label: "Pass", color: C.pass },
    pass_with_evidence: {
      label: "Pass (evidence)",
      color: C.pass_with_evidence,
    },
    fail: { label: "Fail", color: C.fail },
    out_of_scope: { label: "Out of scope", color: C.out_of_scope },
    not_bom_evidenceable: {
      label: "Not BOM-evidenceable",
      color: C.not_bom_evidenceable,
    },
    na: { label: "N/A", color: C.na },
  };

  const activeReqs = dims.find((p) => p.key === active)?.requirements ?? [];

  return (
    <Card className="col-span-full">
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <Scale className="w-4 h-4 text-teal-600" />
          CERT-In Guidelines posture (advisory)
        </CardTitle>
        <CardDescription>
          {rollup?.disclaimer ??
            "Advisory mapping to CERT-In Technical Guidelines v2.0. Does not constitute certification."}{" "}
          {rollup?.hbom_note ?? "HBOM deferred — not in product scope."}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {totalVerdicts === 0 ? (
          <p className="text-sm text-muted-foreground flex items-center justify-center h-[220px]">
            No CERT-In verdicts yet — run an AI BOM, CBOM, or SBOM scan
          </p>
        ) : (
          <ChartContainer config={cfg} className="aspect-auto h-[280px] w-full">
            <BarChart
              data={chartData}
              layout="vertical"
              margin={{ top: 4, right: 16, bottom: 4, left: 8 }}
            >
              <CartesianGrid
                horizontal={false}
                className="stroke-zinc-200 dark:stroke-zinc-800"
              />
              <XAxis type="number" hide />
              <YAxis
                dataKey="name"
                type="category"
                width={220}
                tickLine={false}
                axisLine={false}
                className="text-xs"
              />
              <ChartTooltip content={<ChartTooltipContent />} />
              {(
                [
                  "pass",
                  "pass_with_evidence",
                  "fail",
                  "out_of_scope",
                  "not_bom_evidenceable",
                  "na",
                ] as const
              ).map((k, i, arr) => (
                <Bar
                  key={k}
                  dataKey={k}
                  stackId="a"
                  fill={C[k]}
                  radius={
                    i === 0
                      ? [3, 0, 0, 3]
                      : i === arr.length - 1
                        ? [0, 3, 3, 0]
                        : undefined
                  }
                  cursor="pointer"
                  onClick={(_, idx) => setActive(chartData[idx]?.key ?? null)}
                />
              ))}
            </BarChart>
          </ChartContainer>
        )}

        {active && activeReqs.length > 0 && (
          <CertInRequirementDrilldown
            dimKey={active}
            requirements={activeReqs}
            onClose={() => setActive(null)}
            onAttest={onAttest}
            onViewFindings={onViewFindings}
            findings={findings}
            refAliases={refAliases}
          />
        )}
      </CardContent>
    </Card>
  );
}

export default CertInRollup;

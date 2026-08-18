"use client";

/**
 * Lane-scoped CERT-In posture chart for a single BOM scan results page.
 * Cross-BOM rollup stays on the team dashboard (`CertInRollup`).
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
  CERTIN_LANE_DIMS,
  CERTIN_LANE_META,
  CERTIN_VERDICT_COLORS,
  type CertInDimRollup,
  type CertInLane,
  type CertInRollupData,
} from "@/components/certin/certinShared";
import type { RelatedFindingFields } from "@/utils/relatedFindingMatch";

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

export function CertInLanePosture({
  lane,
  rollup,
  onAttest,
  onViewFindings,
  findings,
  refAliases,
}: {
  lane: CertInLane;
  rollup?: CertInRollupData | null;
  onAttest?: AttestHandler;
  onViewFindings?: (refs: string[]) => void;
  findings?: RelatedFindingFields[] | null;
  refAliases?: Record<string, string>;
}) {
  const laneKeys = CERTIN_LANE_DIMS[lane];
  const meta = CERTIN_LANE_META[lane];

  const dims = useMemo(() => {
    const raw = rollup?.certin_posture;
    if (!raw || typeof raw !== "object") return [];
    return laneKeys
      .filter((key) => key in raw)
      .map((key) => ({
        key,
        ...(raw[key] as CertInDimRollup),
      }))
      .filter((d) => dimTotal(d) > 0);
  }, [rollup, laneKeys]);

  const [active, setActive] = useState<string | null>(null);

  if (dims.length === 0) return null;

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

  const C = CERTIN_VERDICT_COLORS;
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
    <Card className="col-span-full border-zinc-200 dark:border-zinc-800">
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <Scale className="w-4 h-4 text-teal-600" />
          {meta.title}
        </CardTitle>
        <CardDescription>
          {meta.description} {rollup?.hbom_note ?? "HBOM deferred — not in product scope."}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {totalVerdicts === 0 ? (
          <p className="text-sm text-muted-foreground flex items-center justify-center h-[220px]">
            {meta.empty}
          </p>
        ) : (
          <ChartContainer config={cfg} className="aspect-auto h-[240px] w-full">
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

export default CertInLanePosture;

"use client";

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
import { ShieldCheck } from "lucide-react";
import type { AttestHandler } from "@/components/compliance/ComplianceMatrix";
import {
  RbiCsfRequirementDrilldown,
  type RbiCsfRequirement,
} from "@/components/rbi/RbiCsfRequirementDrilldown";
import type { RelatedFindingFields } from "@/utils/relatedFindingMatch";

const C = {
  pass: "#10b981",
  pass_with_evidence: "#14b8a6",
  fail: "#dc2626",
  out_of_scope: "#64748b",
  not_bom_evidenceable: "#8b5cf6",
  na: "#a1a1aa",
};

const PILLAR_LABELS: Record<string, string> = {
  governance: "RBI CSF — Governance",
  identification: "RBI CSF — Risk Identification",
  protection: "RBI CSF — Risk Protection",
  detection: "RBI CSF — Threat Detection",
  response: "RBI CSF — Response & Recovery",
};

type PillarRollup = {
  pass?: number;
  pass_with_evidence?: number;
  fail?: number;
  out_of_scope?: number;
  not_bom_evidenceable?: number;
  na?: number;
  coverage?: number | null;
  requirements?: RbiCsfRequirement[];
};

export type RbiCsfRollupData = {
  rbi_csf_rollup?: Record<string, PillarRollup>;
  disclaimer?: string;
};

export function RbiCsfRollup({
  rollup,
  onAttest,
  onViewFindings,
  findings,
  refAliases,
}: {
  rollup?: RbiCsfRollupData | null;
  onAttest?: AttestHandler;
  onViewFindings?: (refs: string[]) => void;
  findings?: RelatedFindingFields[] | null;
  refAliases?: Record<string, string>;
}) {
  const pillars = useMemo(() => {
    const raw = rollup?.rbi_csf_rollup;
    if (!raw || typeof raw !== "object") return [];
    return Object.entries(raw).map(([key, v]) => ({ key, ...(v as PillarRollup) }));
  }, [rollup]);

  const [active, setActive] = useState<string | null>(null);

  if (pillars.length === 0) return null;

  const chartData = pillars.map((p) => ({
    key: p.key,
    name: PILLAR_LABELS[p.key] ?? p.key,
    pass: p.pass ?? 0,
    pass_with_evidence: p.pass_with_evidence ?? 0,
    fail: p.fail ?? 0,
    out_of_scope: p.out_of_scope ?? 0,
    not_bom_evidenceable: p.not_bom_evidenceable ?? 0,
    na: p.na ?? 0,
    coverage: p.coverage == null ? "n/a" : `${Math.round((p.coverage ?? 0) * 100)}%`,
  }));

  // The API always returns all five pillar keys, so `pillars.length` is non-zero
  // whenever any BOM scan exists — the guard above never fires for a scan whose
  // stored compliance predates the FREE-AI frameworks. That case yields all-zero
  // counts, which Recharts draws as zero-length bars: axis labels and gridlines
  // with no visible data. Detect "no verdicts at all" and show an empty state
  // instead, matching the sibling dashboard panels.
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
    pass_with_evidence: { label: "Pass (evidence)", color: C.pass_with_evidence },
    fail: { label: "Fail", color: C.fail },
    out_of_scope: { label: "Out of scope", color: C.out_of_scope },
    not_bom_evidenceable: { label: "Not BOM-evidenceable", color: C.not_bom_evidenceable },
    na: { label: "N/A", color: C.na },
  };

  const activeReqs = pillars.find((p) => p.key === active)?.requirements ?? [];

  return (
    <Card className="col-span-full">
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-600" />
          RBI CSF Posture Rollup
        </CardTitle>
        <CardDescription>
          FREE-AI requirement verdicts aggregated into the five RBI Cyber Security Framework
          pillars. Coverage = pass / (pass + fail); process-only controls are reported separately.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {totalVerdicts === 0 ? (
          <p className="text-sm text-muted-foreground flex items-center justify-center h-[220px]">
            No FREE-AI verdicts yet — run an AI BOM, CBOM, or SBOM scan
          </p>
        ) : (
        <ChartContainer config={cfg} className="aspect-auto h-[220px] w-full">
          <BarChart data={chartData} layout="vertical" margin={{ top: 4, right: 16, bottom: 4, left: 8 }}>
            <CartesianGrid horizontal={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
            <XAxis type="number" hide />
            <YAxis dataKey="name" type="category" width={200} tickLine={false} axisLine={false} className="text-xs" />
            <ChartTooltip content={<ChartTooltipContent />} />
            {(["pass", "pass_with_evidence", "fail", "out_of_scope", "not_bom_evidenceable", "na"] as const).map(
              (k, i, arr) => (
                <Bar
                  key={k}
                  dataKey={k}
                  stackId="a"
                  fill={C[k]}
                  radius={i === 0 ? [3, 0, 0, 3] : i === arr.length - 1 ? [0, 3, 3, 0] : undefined}
                  cursor="pointer"
                  onClick={(_, idx) => setActive(chartData[idx]?.key ?? null)}
                />
              )
            )}
          </BarChart>
        </ChartContainer>
        )}

        {active && activeReqs.length > 0 && (
          <RbiCsfRequirementDrilldown
            pillarKey={active}
            pillarLabel={PILLAR_LABELS[active] ?? active}
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

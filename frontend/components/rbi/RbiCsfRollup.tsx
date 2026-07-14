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
import { ShieldCheck } from "lucide-react";

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
  requirements?: Array<{
    id: string;
    framework: string;
    verdict: string;
    title: string;
    _scanner?: string;
  }>;
};

export type RbiCsfRollupData = {
  rbi_csf_rollup?: Record<string, PillarRollup>;
  disclaimer?: string;
};

function verdictBadge(v: string) {
  const map: Record<string, string> = {
    pass: "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-300",
    pass_with_evidence: "bg-teal-100 text-teal-800 dark:bg-teal-900/30 dark:text-teal-300",
    fail: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300",
    out_of_scope: "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300",
    not_bom_evidenceable: "bg-violet-100 text-violet-800 dark:bg-violet-900/30 dark:text-violet-300",
    na: "bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400",
  };
  return (
    <Badge variant="outline" className={map[v] ?? ""}>
      {v.replace(/_/g, " ")}
    </Badge>
  );
}

export function RbiCsfRollup({ rollup }: { rollup?: RbiCsfRollupData | null }) {
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

        {active && activeReqs.length > 0 && (
          <div className="mt-4 rounded-lg border border-zinc-200 dark:border-zinc-800">
            <div className="px-3 py-2 text-sm font-medium border-b border-zinc-200 dark:border-zinc-800">
              {PILLAR_LABELS[active] ?? active} — contributing requirements
            </div>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-24">Verdict</TableHead>
                  <TableHead className="w-28">ID</TableHead>
                  <TableHead>Requirement</TableHead>
                  <TableHead className="w-24">Source</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {activeReqs.map((r) => (
                  <TableRow key={`${r.framework}-${r.id}`}>
                    <TableCell>{verdictBadge(r.verdict)}</TableCell>
                    <TableCell className="font-mono text-xs">{r.id}</TableCell>
                    <TableCell className="text-sm">{r.title}</TableCell>
                    <TableCell className="text-xs text-zinc-500">{r.framework}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

"use client";

import { useParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { getTeamDashboard } from "@/utils/backend_api";
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { Skeleton } from "@/components/ui/skeleton";
import {
  XAxis,
  YAxis,
  CartesianGrid,
  AreaChart,
  Area,
  RadialBarChart,
  RadialBar,
} from "recharts";
import { Card, CardContent } from "@/components/ui/card";
import { LayoutDashboard, LineChart, Link2, Shield, Bug, PlayCircle, CheckCircle, Circle, Wrench, Percent } from "lucide-react";

const SCAN_TYPE_LABELS: Record<string, string> = {
  sast: "SAST",
  llm: "LLM",
  mcp: "MCP",
  iac: "IAC",
  leakage: "Leakage",
  sbom_sca: "SBOM/SCA",
  agent_discovery: "Agent Discovery",
  dast: "DAST",
  cbom: "CBOM",
  ai_bom: "AI BOM",
};

/** Blue shades for chart fills (light to dark) */
const BLUE_SHADES = {
  blue1: "#93c5fd",
  blue2: "#60a5fa",
  blue3: "#3b82f6",
  blue4: "#2563eb",
  blue5: "#1d4ed8",
  blue6: "#1e40af",
  blue7: "#1e3a8a",
} as const;

function aggregateByDate(
  data: { date: string; count: number }[]
): { date: string; count: number }[] {
  const map = new Map<string, number>();
  for (const { date, count } of data) {
    const d = typeof date === "string" ? date : String(date);
    map.set(d, (map.get(d) ?? 0) + count);
  }
  return Array.from(map.entries())
    .map(([date, count]) => ({ date, count }))
    .sort((a, b) => a.date.localeCompare(b.date));
}

function formatDateLabel(dateStr: string): string {
  try {
    const d = new Date(dateStr);
    return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
  }
  catch (error) {
    console.error("Error formatting date label:", error);
    return dateStr;
  }
}

export default function TeamPage() {
  const params = useParams();
  const team_id = params?.team_id as string | undefined;

  const { data: dashboard, isLoading } = useQuery({
    queryKey: ["team-dashboard", team_id],
    queryFn: () => getTeamDashboard(Number(team_id)),
    enabled: !!team_id,
  });

  if (isLoading || !dashboard) {
    return (
      <div className="flex flex-col h-full min-h-[calc(100vh-2rem)] bg-background">
        <Skeleton className="h-24 w-full rounded-none" />
        <main className="flex-1 p-6 overflow-auto">
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            <Skeleton className="min-h-[280px] rounded-lg" />
            <Skeleton className="min-h-[280px] rounded-lg" />
            <Skeleton className="min-h-[280px] rounded-lg" />
          </div>
          <Skeleton className="mt-6 min-h-[300px] rounded-lg" />
        </main>
      </div>
    );
  }

  const scansByDate = aggregateByDate(dashboard.scans_created_at_data ?? []);

  /** Scan activity by type — bar chart */
  const scanTypeData = Object.entries(dashboard.scan_type_count ?? {})
    .filter(([, v]) => v > 0)
    .map(([key, value]) => ({
      name: SCAN_TYPE_LABELS[key] ?? key,
      scans: value,
    }));

  /** Vulnerabilities by severity — radial chart (GuardrailsDashboardData color scheme) */
  const vulnSeverityOrder = ["low", "medium", "high", "critical"] as const;
  const vulnChartKeys = [
    { key: "low" as const, label: "Low", color: "hsl(142 71% 45%)" },
    { key: "medium" as const, label: "Medium", color: "hsl(48 96% 53%)" },
    { key: "high" as const, label: "High", color: "hsl(25 95% 53%)" },
    { key: "critical" as const, label: "Critical", color: "hsl(0 84% 60%)" },
  ];
  const vulnChartConfig = {
    value: { label: "Count" },
    ...Object.fromEntries(
      vulnChartKeys.map(({ key, label, color }) => [key, { label, color }])
    ),
  } satisfies ChartConfig;
  const vulnDataRaw = Object.entries(
    dashboard.high_and_critical_vuln_in_past_month ?? {}
  )
    .filter(([, v]) => v > 0)
    .map(([key, value]) => ({
      name: vulnChartKeys.find((k) => k.key === key)?.label ?? key.charAt(0).toUpperCase() + key.slice(1),
      severityKey: key,
      actualCount: value,
      fill: vulnChartKeys.find((k) => k.key === key)?.color ?? "hsl(0 0% 50%)",
    }));
  const vulnMax = Math.max(1, ...vulnDataRaw.map((d) => d.actualCount));
  const vulnRadialData = vulnDataRaw.map((d) => ({
    ...d,
    count: (d.actualCount / vulnMax) * 100,
  }));

  const scansAreaData = scansByDate.map((d) => ({
    date: d.date,
    count: d.count,
  }));

  const maxScanCount = Math.max(1, ...scanTypeData.map((d) => d.scans));

  const scansAreaChartConfig = {
    count: { label: "Scans", color: BLUE_SHADES.blue5 },
  } satisfies ChartConfig;

  const integrationsChartConfig = {
    Guardrails: { label: "Guardrails", color: "#dc2626" }, // red-600 for stroke + gradient
    cicd: { label: "CI/CD", color: BLUE_SHADES.blue6 },
  } satisfies ChartConfig;

  /** Scan status distribution (radial) */
  const scanStatusDist = dashboard.scan_status_distribution ?? {
    not_started: 0,
    running: 0,
    completed: 0,
    failed: 0,
  };
  const scanStatusOrder = ["not_started", "running", "completed", "failed"] as const;
  const scanStatusLabels: Record<string, string> = {
    not_started: "Not started",
    running: "Running",
    completed: "Completed",
    failed: "Failed",
  };
  const scanStatusColors: Record<string, string> = {
    not_started: "hsl(215 20% 55%)",
    running: "hsl(217 91% 60%)",
    completed: "hsl(142 71% 45%)",
    failed: "hsl(0 84% 60%)",
  };
  const scanStatusRadialData = scanStatusOrder
    .filter((k) => (scanStatusDist[k] ?? 0) > 0)
    .map((k) => {
      const count = scanStatusDist[k] ?? 0;
      return {
        name: scanStatusLabels[k],
        statusKey: k,
        actualCount: count,
        fill: scanStatusColors[k],
      };
    });
  const scanStatusMax = Math.max(1, ...scanStatusRadialData.map((d) => d.actualCount));
  const scanStatusRadialChartData = scanStatusRadialData.map((d) => ({
    ...d,
    count: (d.actualCount / scanStatusMax) * 100,
  }));
  const scanStatusChartConfig = {
    count: { label: "Scans" },
    ...Object.fromEntries(
      scanStatusOrder.map((k) => [k, { label: scanStatusLabels[k], color: scanStatusColors[k] }])
    ),
  } satisfies ChartConfig;

  /** Per-day dict -> sorted array for area charts */
  function perDayDictToArray(d: Record<string, number>): { date: string; count: number }[] {
    return Object.entries(d)
      .map(([date, count]) => ({ date, count }))
      .sort((a, b) => a.date.localeCompare(b.date));
  }
  const findingsPerDayData = perDayDictToArray(dashboard.findings_per_day ?? {});
  const fixesPerDayData = perDayDictToArray(dashboard.fixes_per_day ?? {});
  const falsePositiveData = perDayDictToArray(dashboard.false_positive_trends ?? {});

  /** Remediations status distribution: date -> { not_started, in_progress, fixed, ignored } */
  const remediationsDist = dashboard.remediations_status_distribution ?? {};
  const remediationsAreaData = Object.entries(remediationsDist)
    .map(([date, v]) => ({
      date,
      label: formatDateLabel(date),
      not_started: v.not_started ?? 0,
      in_progress: v.in_progress ?? 0,
      fixed: v.fixed ?? 0,
      ignored: v.ignored ?? 0,
    }))
    .sort((a, b) => a.date.localeCompare(b.date));

  const remediationsChartConfig = {
    not_started: { label: "Not started", color: "hsl(215 20% 55%)" },
    in_progress: { label: "In progress", color: "hsl(217 91% 60%)" },
    fixed: { label: "Fixed", color: "hsl(142 71% 45%)" },
    ignored: { label: "Ignored", color: "hsl(38 92% 50%)" },
  } satisfies ChartConfig;

  const findingsPerDayChartConfig = { count: { label: "Findings", color: BLUE_SHADES.blue5 } } satisfies ChartConfig;
  const fixesPerDayChartConfig = { count: { label: "Fixes", color: "hsl(142 71% 45%)" } } satisfies ChartConfig;
  const falsePositiveChartConfig = { count: { label: "Ignored", color: "hsl(38 92% 50%)" } } satisfies ChartConfig;

  const card = dashboard.card_data ?? {
    total_findings: 0,
    total_started_scans: 0,
    total_completed_scans: 0,
    total_not_started_scans: 0,
    total_fixed_findings: 0,
    remediation_percentage: 0,
  };

  return (
    <div className="flex flex-col h-full min-h-[calc(100vh-2rem)] bg-neutral-900">

      <main className="flex-1 p-6 overflow-auto mt-5">
        {/* Your Team's Recent Activity — summary cards + bar, radial, area charts */}
        <section className="pb-6">
          <h2 className="text-base font-medium flex items-center gap-2 mb-1">
            <div className="bg-blue-600 rounded-md p-1.5">
              <LineChart className="size-5" />
            </div>
            Your Team's Recent Activity
          </h2>
          {/* Summary stat cards — same style as SAST page: icon top-left, value + label below */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6">
            <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
              <CardContent className="p-0">
                <div className="flex flex-col items-start gap-2">
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-zinc-500/15 dark:bg-zinc-400/10">
                    <Bug className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
                  </div>
                  <div>
                    <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Total findings</p>
                    <p className="text-xl font-bold text-zinc-900 dark:text-white tabular-nums">{card.total_findings}</p>
                    <p className="text-xs text-zinc-500 dark:text-zinc-400">All scans</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
              <CardContent className="p-0">
                <div className="flex flex-col items-start gap-2">
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-blue-500/15 dark:bg-blue-500/10">
                    <PlayCircle className="h-4 w-4 text-blue-500" />
                  </div>
                  <div>
                    <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Started scans</p>
                    <p className="text-xl font-bold text-zinc-900 dark:text-white tabular-nums">{card.total_started_scans}</p>
                    <p className="text-xs text-zinc-500 dark:text-zinc-400">In progress</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
              <CardContent className="p-0">
                <div className="flex flex-col items-start gap-2">
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-green-500/15 dark:bg-green-500/10">
                    <CheckCircle className="h-4 w-4 text-green-500" />
                  </div>
                  <div>
                    <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Completed scans</p>
                    <p className="text-xl font-bold text-zinc-900 dark:text-white tabular-nums">{card.total_completed_scans}</p>
                    <p className="text-xs text-zinc-500 dark:text-zinc-400">Success</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
              <CardContent className="p-0">
                <div className="flex flex-col items-start gap-2">
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-zinc-500/15 dark:bg-zinc-400/10">
                    <Circle className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
                  </div>
                  <div>
                    <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Not started</p>
                    <p className="text-xl font-bold text-zinc-900 dark:text-white tabular-nums">{card.total_not_started_scans}</p>
                    <p className="text-xs text-zinc-500 dark:text-zinc-400">Idle</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
              <CardContent className="p-0">
                <div className="flex flex-col items-start gap-2">
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-amber-500/15 dark:bg-amber-500/10">
                    <Wrench className="h-4 w-4 text-amber-500" />
                  </div>
                  <div>
                    <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Fixed findings</p>
                    <p className="text-xl font-bold text-zinc-900 dark:text-white tabular-nums">{card.total_fixed_findings}</p>
                    <p className="text-xs text-zinc-500 dark:text-zinc-400">Remediated</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
              <CardContent className="p-0">
                <div className="flex flex-col items-start gap-2">
                  <div className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${card.remediation_percentage >= 70 ? "bg-green-500/15 dark:bg-green-500/10" : card.remediation_percentage >= 40 ? "bg-amber-500/15 dark:bg-amber-500/10" : "bg-red-500/15 dark:bg-red-500/10"}`}>
                    <Percent className={`h-4 w-4 ${card.remediation_percentage >= 70 ? "text-green-500" : card.remediation_percentage >= 40 ? "text-amber-500" : "text-red-500"}`} />
                  </div>
                  <div>
                    <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Remediation</p>
                    <p className="text-xl font-bold text-zinc-900 dark:text-white tabular-nums">{card.remediation_percentage}%</p>
                    <p className="text-xs text-zinc-500 dark:text-zinc-400">Fixed / total</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mt-9">
          {/* Scan activity by type — custom bar chart (same pattern as GuardrailsDashboardData) */}
          <div className="min-h-[380px] flex flex-col pr-2">
            <h2 className="text-base font-medium">Scan activity by type</h2>
            <p className="text-sm text-muted-foreground mb-4 mt-1">Security scans run in the last 30 days, grouped by scan type (SAST, IAC, LLM, etc.)</p>
            <div className="flex-1 min-h-[280px] flex flex-col justify-end">
              {scanTypeData.length === 0 ? (
                <p className="text-sm text-muted-foreground flex items-center justify-center h-[280px]">
                  No scan data
                </p>
              ) : (
                <>
                  <ScrollArea className="w-full min-h-[200px]">
                    <div className="flex gap-2 items-end min-w-max pb-2 min-h-[180px] justify-center">
                      {scanTypeData.map(({ name, scans }) => (
                        <Tooltip key={name}>
                          <TooltipTrigger asChild>
                            <div className="flex flex-col items-center gap-1 shrink-0 min-w-10 h-[180px] justify-end cursor-pointer">
                              <div
                                className="w-10 bg-blue-500/80 dark:bg-blue-600/80 rounded-t min-h-[4px] transition-all"
                                style={{
                                  height: maxScanCount > 0 ? `${Math.max(8, (scans / maxScanCount) * 140)}px` : "8px",
                                }}
                              />
                              <span className="text-[10px] text-zinc-500 dark:text-zinc-400 font-mono text-center max-w-14 truncate">
                                {name.length > 5 ? `${name.slice(0, 5)}...` : name}
                              </span>
                            </div>
                          </TooltipTrigger>
                          <TooltipContent side="top" className="font-medium bg-zinc-800 text-zinc-100 border border-zinc-600 *:last:bg-zinc-800 *:last:fill-zinc-800">
                            <span className="font-normal text-zinc-300">{name}</span>
                            <br />
                            <span className="font-mono tabular-nums">{scans}</span> scan{scans !== 1 ? "s" : ""}
                          </TooltipContent>
                        </Tooltip>
                      ))}
                    </div>
                    <ScrollBar orientation="horizontal" />
                  </ScrollArea>
                  <p className="text-xs text-muted-foreground text-center mt-3">
                    Bar height is proportional to scan count; hover for exact numbers.
                  </p>
                </>
              )}
            </div>
          </div>

          {/* Vulnerabilities by severity — radial (GuardrailsDashboardData colors + legend) */}
          <div className="min-h-[380px] flex flex-col">
            <h2 className="text-base font-medium">Vulnerabilities by severity (last 30 days)</h2>
            <p className="text-sm text-muted-foreground mb-4 mt-1">From IAC, SBOM/SCA, and SAST scans</p>
            <div className="flex-1 min-h-[280px]">
              {vulnRadialData.length === 0 ? (
                <p className="text-sm text-muted-foreground flex items-center justify-center h-[280px]">
                  No vulnerability data
                </p>
              ) : (
                <>
                  <ChartContainer
                    config={vulnChartConfig}
                    className="mx-auto aspect-square max-h-[280px] w-full cursor-pointer"
                  >
                    <RadialBarChart
                      data={vulnRadialData}
                      innerRadius={40}
                      outerRadius={100}
                      startAngle={90}
                      endAngle={-270}
                    >
                      <ChartTooltip
                        cursor={false}
                        content={
                          <ChartTooltipContent
                            nameKey="name"
                            formatter={(_, name, __, ___, payload) => {
                              const count = (payload as { actualCount?: number } | undefined)?.actualCount ?? 0;
                              return (
                                <span className="font-medium">
                                  <span className="text-muted-foreground">{name}: </span>
                                  <span className="font-mono font-semibold tabular-nums text-foreground">
                                    {count}
                                  </span>
                                </span>
                              );
                            }}
                          />
                        }
                      />
                      <RadialBar dataKey="count" background className="cursor-pointer" />
                    </RadialBarChart>
                  </ChartContainer>
                  <div className="mt-4 pt-3 border-t border-zinc-200 dark:border-zinc-700 flex flex-wrap gap-x-4 gap-y-1.5 justify-center">
                    {vulnChartKeys.map(({ label, color }) => (
                      <div key={label} className="flex items-center gap-1.5 text-xs">
                        <span
                          className="shrink-0 w-3 h-3 rounded-full"
                          style={{ backgroundColor: color }}
                          aria-hidden
                        />
                        <span className="text-zinc-600 dark:text-zinc-400">{label}</span>
                      </div>
                    ))}
                  </div>
                  <p className="text-xs text-muted-foreground text-center mt-3">
                    Segment size shows relative count per severity; hover for exact numbers.
                  </p>
                </>
              )}
            </div>
          </div>

          {/* Scans over time — area line chart */}
          <div className="min-h-[380px] flex flex-col">
            <h2 className="text-base font-medium">Daily scan volume</h2>
            <p className="text-sm text-muted-foreground mb-4 mt-1">Number of scans created each day; use this to see activity trends over time</p>
            <div className="flex-1 min-h-[280px]">
              {scansByDate.length === 0 ? (
                <p className="text-sm text-muted-foreground flex items-center justify-center h-[280px]">
                  No scans yet
                </p>
              ) : (
                <>
                  <ChartContainer
                    config={scansAreaChartConfig}
                    className="aspect-auto h-[280px] w-full pb-8 cursor-pointer"
                  >
                    <AreaChart data={scansAreaData} margin={{ bottom: 28 }}>
                      <defs>
                        <linearGradient id="fillScansTeam" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="var(--color-count)" stopOpacity={0.8} />
                          <stop offset="95%" stopColor="var(--color-count)" stopOpacity={0.1} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                      <XAxis
                        dataKey="date"
                        tickLine={false}
                        axisLine={false}
                        tickMargin={8}
                        minTickGap={20}
                        tickFormatter={(value) => formatDateLabel(value)}
                        tick={({ payload, x, y }) => (
                          <g transform={`translate(${x},${y})`}>
                            <foreignObject x={-24} y={0} width={48} height={28} className="overflow-visible">
                              <div className="text-[10px] text-center text-zinc-600 dark:text-zinc-400 wrap-break-word leading-tight w-full">
                                {payload.value ? formatDateLabel(String(payload.value)) : ""}
                              </div>
                            </foreignObject>
                          </g>
                        )}
                      />
                      <YAxis hide domain={[0, "auto"]} />
                      <ChartTooltip
                        cursor={false}
                        content={
                          <ChartTooltipContent
                            labelFormatter={(value) => formatDateLabel(String(value))}
                            formatter={(value) => [value, "Scans"]}
                            indicator="dot"
                          />
                        }
                      />
                      <Area
                        dataKey="count"
                        type="monotone"
                        fill="url(#fillScansTeam)"
                        stroke="var(--color-count)"
                        strokeWidth={2}
                      />
                    </AreaChart>
                  </ChartContainer>
                  <p className="text-xs text-muted-foreground text-center mt-3">
                    Hover over a point to see scans for that day.
                  </p>
                </>
              )}
            </div>
          </div>

          {/* Scan status distribution — radial */}
          <div className="min-h-[380px] flex flex-col">
            <h2 className="text-base font-medium">Scan status distribution</h2>
            <p className="text-sm text-muted-foreground mb-4 mt-1">All scans in this team by status (not started, running, completed, failed)</p>
            <div className="flex-1 min-h-[280px]">
              {scanStatusRadialChartData.length === 0 ? (
                <p className="text-sm text-muted-foreground flex items-center justify-center h-[280px]">
                  No scan status data
                </p>
              ) : (
                <>
                  <ChartContainer
                    config={scanStatusChartConfig}
                    className="mx-auto aspect-square max-h-[280px] w-full cursor-pointer"
                  >
                    <RadialBarChart
                      data={scanStatusRadialChartData}
                      innerRadius={40}
                      outerRadius={100}
                      startAngle={90}
                      endAngle={-270}
                    >
                      <ChartTooltip
                        cursor={false}
                        content={
                          <ChartTooltipContent
                            nameKey="name"
                            formatter={(_, name, __, ___, payload) => {
                              const count = (payload as { actualCount?: number } | undefined)?.actualCount ?? 0;
                              return (
                                <span className="font-medium">
                                  <span className="text-muted-foreground">{name}: </span>
                                  <span className="font-mono font-semibold tabular-nums text-foreground">
                                    {count}
                                  </span>
                                </span>
                              );
                            }}
                          />
                        }
                      />
                      <RadialBar dataKey="count" background className="cursor-pointer" />
                    </RadialBarChart>
                  </ChartContainer>
                  <div className="mt-4 pt-3 border-t border-zinc-200 dark:border-zinc-700 flex flex-wrap gap-x-4 gap-y-1.5 justify-center">
                    {scanStatusOrder.map((k) => (
                      <div key={k} className="flex items-center gap-1.5 text-xs">
                        <span
                          className="shrink-0 w-3 h-3 rounded-full"
                          style={{ backgroundColor: scanStatusColors[k] }}
                          aria-hidden
                        />
                        <span className="text-zinc-600 dark:text-zinc-400">{scanStatusLabels[k]}</span>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </div>
          </div>
          </div>
        </section>

        {/* Findings & Remediation — area/line charts */}
        <section className="pb-6 mt-10">
          <h2 className="text-base font-medium flex items-center gap-2 mb-1">
            <div className="bg-blue-600 rounded-md p-1.5">
              <Shield className="size-5" />
            </div>
            Findings & Remediation
          </h2>
          <p className="text-sm text-muted-foreground mb-4 mt-1">Finding counts and remediation status over time (from scan findings)</p>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-9">
            {/* Remediations status distribution — area */}
            <div className="min-h-[320px] flex flex-col">
              <h2 className="text-base font-medium">Remediations status per day</h2>
              <p className="text-sm text-muted-foreground mb-4 mt-1">Daily counts: new (not started / in progress), fixed, and ignored findings</p>
              <div className="flex-1 min-h-[260px]">
                {remediationsAreaData.length === 0 ? (
                  <p className="text-sm text-muted-foreground flex items-center justify-center h-[260px]">
                    No remediation data
                  </p>
                ) : (
                  <ChartContainer
                    config={remediationsChartConfig}
                    className="aspect-auto h-[260px] w-full pb-8 cursor-pointer"
                  >
                    <AreaChart data={remediationsAreaData} margin={{ bottom: 28 }}>
                      <defs>
                        <linearGradient id="fillRemNotStarted" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="var(--color-not_started)" stopOpacity={0.8} />
                          <stop offset="95%" stopColor="var(--color-not_started)" stopOpacity={0.1} />
                        </linearGradient>
                        <linearGradient id="fillRemInProgress" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="var(--color-in_progress)" stopOpacity={0.8} />
                          <stop offset="95%" stopColor="var(--color-in_progress)" stopOpacity={0.1} />
                        </linearGradient>
                        <linearGradient id="fillRemFixed" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="var(--color-fixed)" stopOpacity={0.8} />
                          <stop offset="95%" stopColor="var(--color-fixed)" stopOpacity={0.1} />
                        </linearGradient>
                        <linearGradient id="fillRemIgnored" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="var(--color-ignored)" stopOpacity={0.8} />
                          <stop offset="95%" stopColor="var(--color-ignored)" stopOpacity={0.1} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                      <XAxis
                        dataKey="date"
                        tickLine={false}
                        axisLine={false}
                        tickMargin={8}
                        minTickGap={20}
                        tickFormatter={(value) => formatDateLabel(String(value))}
                      />
                      <YAxis hide domain={[0, "auto"]} />
                      <ChartTooltip
                        cursor={false}
                        content={
                          <ChartTooltipContent
                            labelFormatter={(value) => formatDateLabel(String(value))}
                            indicator="dot"
                          />
                        }
                      />
                      <Area dataKey="not_started" type="monotone" stackId="1" fill="url(#fillRemNotStarted)" stroke="var(--color-not_started)" strokeWidth={2} />
                      <Area dataKey="in_progress" type="monotone" stackId="1" fill="url(#fillRemInProgress)" stroke="var(--color-in_progress)" strokeWidth={2} />
                      <Area dataKey="fixed" type="monotone" stackId="1" fill="url(#fillRemFixed)" stroke="var(--color-fixed)" strokeWidth={2} />
                      <Area dataKey="ignored" type="monotone" stackId="1" fill="url(#fillRemIgnored)" stroke="var(--color-ignored)" strokeWidth={2} />
                    </AreaChart>
                  </ChartContainer>
                )}
              </div>
            </div>

            {/* Findings per day */}
            <div className="min-h-[320px] flex flex-col">
              <h2 className="text-base font-medium">Findings per day</h2>
              <p className="text-sm text-muted-foreground mb-4 mt-1">Number of findings created each day (created_at)</p>
              <div className="flex-1 min-h-[260px]">
                {findingsPerDayData.length === 0 ? (
                  <p className="text-sm text-muted-foreground flex items-center justify-center h-[260px]">
                    No findings data
                  </p>
                ) : (
                  <ChartContainer
                    config={findingsPerDayChartConfig}
                    className="aspect-auto h-[260px] w-full pb-8 cursor-pointer"
                  >
                    <AreaChart data={findingsPerDayData} margin={{ bottom: 28 }}>
                      <defs>
                        <linearGradient id="fillFindingsPerDay" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="var(--color-count)" stopOpacity={0.8} />
                          <stop offset="95%" stopColor="var(--color-count)" stopOpacity={0.1} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                      <XAxis
                        dataKey="date"
                        tickLine={false}
                        axisLine={false}
                        tickMargin={8}
                        minTickGap={20}
                        tickFormatter={(value) => formatDateLabel(String(value))}
                      />
                      <YAxis hide domain={[0, "auto"]} />
                      <ChartTooltip
                        cursor={false}
                        content={
                          <ChartTooltipContent
                            labelFormatter={(value) => formatDateLabel(String(value))}
                            formatter={(value) => [value, "Findings"]}
                            indicator="dot"
                          />
                        }
                      />
                      <Area dataKey="count" type="monotone" fill="url(#fillFindingsPerDay)" stroke="var(--color-count)" strokeWidth={2} />
                    </AreaChart>
                  </ChartContainer>
                )}
              </div>
            </div>

            {/* Fixes per day */}
            <div className="min-h-[320px] flex flex-col">
              <h2 className="text-base font-medium">Fixes per day</h2>
              <p className="text-sm text-muted-foreground mb-4 mt-1">Number of findings marked fixed each day</p>
              <div className="flex-1 min-h-[260px]">
                {fixesPerDayData.length === 0 ? (
                  <p className="text-sm text-muted-foreground flex items-center justify-center h-[260px]">
                    No fixes data
                  </p>
                ) : (
                  <ChartContainer
                    config={fixesPerDayChartConfig}
                    className="aspect-auto h-[260px] w-full pb-8 cursor-pointer"
                  >
                    <AreaChart data={fixesPerDayData} margin={{ bottom: 28 }}>
                      <defs>
                        <linearGradient id="fillFixesPerDay" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="var(--color-count)" stopOpacity={0.8} />
                          <stop offset="95%" stopColor="var(--color-count)" stopOpacity={0.1} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                      <XAxis
                        dataKey="date"
                        tickLine={false}
                        axisLine={false}
                        tickMargin={8}
                        minTickGap={20}
                        tickFormatter={(value) => formatDateLabel(String(value))}
                      />
                      <YAxis hide domain={[0, "auto"]} />
                      <ChartTooltip
                        cursor={false}
                        content={
                          <ChartTooltipContent
                            labelFormatter={(value) => formatDateLabel(String(value))}
                            formatter={(value) => [value, "Fixes"]}
                            indicator="dot"
                          />
                        }
                      />
                      <Area dataKey="count" type="monotone" fill="url(#fillFixesPerDay)" stroke="var(--color-count)" strokeWidth={2} />
                    </AreaChart>
                  </ChartContainer>
                )}
              </div>
            </div>

            {/* False positive trends (ignored per day) */}
            <div className="min-h-[320px] flex flex-col">
              <h2 className="text-base font-medium">False positive trends</h2>
              <p className="text-sm text-muted-foreground mb-4 mt-1">Number of findings marked ignored per day</p>
              <div className="flex-1 min-h-[260px]">
                {falsePositiveData.length === 0 ? (
                  <p className="text-sm text-muted-foreground flex items-center justify-center h-[260px]">
                    No ignored findings data
                  </p>
                ) : (
                  <ChartContainer
                    config={falsePositiveChartConfig}
                    className="aspect-auto h-[260px] w-full pb-8 cursor-pointer"
                  >
                    <AreaChart data={falsePositiveData} margin={{ bottom: 28 }}>
                      <defs>
                        <linearGradient id="fillFalsePositive" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="var(--color-count)" stopOpacity={0.8} />
                          <stop offset="95%" stopColor="var(--color-count)" stopOpacity={0.1} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                      <XAxis
                        dataKey="date"
                        tickLine={false}
                        axisLine={false}
                        tickMargin={8}
                        minTickGap={20}
                        tickFormatter={(value) => formatDateLabel(String(value))}
                      />
                      <YAxis hide domain={[0, "auto"]} />
                      <ChartTooltip
                        cursor={false}
                        content={
                          <ChartTooltipContent
                            labelFormatter={(value) => formatDateLabel(String(value))}
                            formatter={(value) => [value, "Ignored"]}
                            indicator="dot"
                          />
                        }
                      />
                      <Area dataKey="count" type="monotone" fill="url(#fillFalsePositive)" stroke="var(--color-count)" strokeWidth={2} />
                    </AreaChart>
                  </ChartContainer>
                )}
              </div>
            </div>
          </div>
        </section>

        {/* Integrations created over time */}
        <section className="pb-6 mt-10">
          <h2 className="text-base font-medium flex items-center gap-2 mb-1">
            <div className="bg-blue-600 rounded-md p-1.5">
            <Link2 className="size-5" />
            </div>
            Your Team's Integrations
          </h2>
          <p className="text-sm text-muted-foreground mb-4 mt-1">Guardrails and CI/CD integrations created by date</p>
          <div className="min-h-[220px] mt-9">
            {(() => {
              const guardrailsByDate = aggregateByDate(
                dashboard.guardrails_integrations_created_at_data ?? []
              );
              const cicdByDate = aggregateByDate(
                dashboard.cicd_integrations_created_at_data ?? []
              );
              const allDates = new Set([
                ...guardrailsByDate.map((d) => d.date),
                ...cicdByDate.map((d) => d.date),
              ]);
              const integrationsBarData = Array.from(allDates)
                .sort()
                .map((date) => {
                  const g = guardrailsByDate.find((x) => x.date === date)?.count ?? 0;
                  const c = cicdByDate.find((x) => x.date === date)?.count ?? 0;
                  return {
                    label: formatDateLabel(date),
                    Guardrails: g,
                    cicd: c,
                    total: g + c,
                  };
                })
                .filter((d) => d.total > 0);
              if (integrationsBarData.length === 0) {
                return (
                  <p className="text-sm text-muted-foreground flex items-center justify-center h-[220px]">
                    No integrations yet
                  </p>
                );
              }
              return (
                <ChartContainer
                  config={integrationsChartConfig}
                  className="aspect-auto h-[220px] w-full pb-8 cursor-pointer"
                >
                  <AreaChart data={integrationsBarData} margin={{ bottom: 28 }}>
                    <defs>
                      <linearGradient id="fillIntegrationsGuardrails" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#f87171" stopOpacity={0.9} />
                        <stop offset="50%" stopColor="#dc2626" stopOpacity={0.5} />
                        <stop offset="100%" stopColor="#991b1b" stopOpacity={0.15} />
                      </linearGradient>
                      <linearGradient id="fillIntegrationsCicd" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="var(--color-cicd)" stopOpacity={0.8} />
                        <stop offset="95%" stopColor="var(--color-cicd)" stopOpacity={0.1} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                    <XAxis
                      dataKey="label"
                      tickLine={false}
                      axisLine={false}
                      tickMargin={8}
                      minTickGap={20}
                      tickFormatter={(value) => String(value)}
                    />
                    <YAxis hide domain={[0, "auto"]} />
                    <ChartTooltip
                      cursor={false}
                      content={<ChartTooltipContent indicator="dot" />}
                    />
                    <Area
                      dataKey="Guardrails"
                      type="monotone"
                      fill="url(#fillIntegrationsGuardrails)"
                      stroke="var(--color-Guardrails)"
                      strokeWidth={2}
                    />
                    <Area
                      dataKey="cicd"
                      type="monotone"
                      fill="url(#fillIntegrationsCicd)"
                      stroke="var(--color-cicd)"
                      strokeWidth={2}
                    />
                  </AreaChart>
                </ChartContainer>
              );
            })()}
          </div>
        </section>
      </main>
    </div>
  );
}

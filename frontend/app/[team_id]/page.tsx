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
import { LayoutDashboard, LineChart, Link2 } from "lucide-react";

const SCAN_TYPE_LABELS: Record<string, string> = {
  sast: "SAST",
  llm: "LLM",
  mcp: "MCP",
  iac: "IAC",
  leakage: "Leakage",
  sbom_sca: "SBOM/SCA",
  agent_discovery: "Agent Discovery",
  dast: "DAST",
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

  return (
    <div className="flex flex-col h-full min-h-[calc(100vh-2rem)] bg-neutral-900">

      <main className="flex-1 p-6 overflow-auto mt-5">
        {/* Your Team's Recent Activity — bar, radial, area charts */}
        <section className="pb-6">
          <h2 className="text-base font-medium flex items-center gap-2 mb-1">
            <div className="bg-blue-600 rounded-md p-1.5">
              <LineChart className="size-5" />
            </div>
            Your Team's Recent Activity
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-9">
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

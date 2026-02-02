"use client";

import { useParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { getTeamDashboard } from "@/utils/backend_api";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import { Skeleton } from "@/components/ui/skeleton";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  AreaChart,
  Area,
  PieChart,
  Pie,
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
  const scanTypeData = Object.entries(dashboard.scan_type_count ?? {})
    .filter(([, v]) => v > 0)
    .map(([key, value]) => ({
      name: SCAN_TYPE_LABELS[key] ?? key,
      scans: value,
    }));

  const vulnSeverityOrder = ["low", "medium", "high", "critical"] as const;
  const vulnSeverityColors = {
    low: "#15803d",
    medium: "#a16207",
    high: "#c2410c",
    critical: "#b91c1c",
  } satisfies Record<string, string>;
  const vulnChartConfig = {
    value: { label: "Count" },
    ...Object.fromEntries(
      vulnSeverityOrder.map((key) => [
        key,
        {
          label: key.charAt(0).toUpperCase() + key.slice(1),
          color: vulnSeverityColors[key],
        },
      ])
    ),
  } satisfies ChartConfig;
  const vulnData = Object.entries(
    dashboard.high_and_critical_vuln_in_past_month ?? {}
  )
    .filter(([, v]) => v > 0)
    .map(([key, value]) => ({
      name: key.charAt(0).toUpperCase() + key.slice(1),
      severityKey: key,
      value,
      fill: `var(--color-${key})`,
    }));

  const scansAreaData = scansByDate.map((d) => ({
    date: d.date,
    count: d.count,
  }));

  const scanTypesChartConfig = {
    scans: { label: "Scans", color: BLUE_SHADES.blue5 },
  } satisfies ChartConfig;

  const scansAreaChartConfig = {
    count: { label: "Scans", color: BLUE_SHADES.blue5 },
  } satisfies ChartConfig;

  const integrationsChartConfig = {
    Guardrails: { label: "Guardrails", color: BLUE_SHADES.blue4 },
    cicd: { label: "CI/CD", color: BLUE_SHADES.blue6 },
  } satisfies ChartConfig;

  return (
    <div className="flex flex-col h-full min-h-[calc(100vh-2rem)] bg-neutral-900">
      <header className="px-6 py-4 border-b border-border">
        <h1 className="text-3xl font-bold text-zinc-900 dark:text-white mb-2 flex items-center gap-2">
          Team Dashboard
        </h1>
        <p className="text-zinc-600 dark:text-zinc-400">
          Overview of scans, integrations, and vulnerabilities for this team.
        </p>
      </header>

      <main className="flex-1 p-6 overflow-auto">
        {/* Row 1: three charts in one card */}
        <Card className="mb-6 bg-neutral-950/20 border-border">
          <CardHeader className="">
            <CardTitle className="text-lg font-semibold flex items-center gap-2">
              <div className="bg-blue-600 rounded-md p-1.5">
                <LineChart className="size-4" />
              </div>
              Your Team's Recent Activity
            </CardTitle>
            
          </CardHeader>
          <CardContent>
            <section className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Scan types (past 30 days) */}
          <div className="min-h-[380px] flex flex-col">
            <h2 className="text-base font-medium">Scan activity by type</h2>
            <p className="text-sm text-muted-foreground mb-4 mt-1">Security scans run in the last 30 days, grouped by scan type (SAST, IAC, LLM, etc.)</p>
            <div className="flex-1 min-h-[280px]">
              {scanTypeData.length === 0 ? (
                <p className="text-sm text-muted-foreground flex items-center justify-center h-[280px]">
                  No scan data
                </p>
              ) : (
                <ChartContainer
                  config={scanTypesChartConfig}
                  className="aspect-auto h-[280px] w-full"
                >
                  <BarChart
                    accessibilityLayer
                    data={scanTypeData}
                    margin={{ top: 8, right: 8, bottom: 56, left: 0 }}
                  >
                    <CartesianGrid vertical={false} />
                    <XAxis
                      dataKey="name"
                      tickLine={false}
                      tickMargin={10}
                      axisLine={false}
                      angle={-90}
                      textAnchor="end"
                      height={56}
                      interval={0}
                      tickFormatter={(value) => {
                        const s = String(value);
                        return s.length > 8 ? `${s.slice(0, 8)}...` : s;
                      }}
                    />
                    <YAxis type="number" tickLine={false} axisLine={false} />
                    <ChartTooltip
                      cursor={false}
                      content={<ChartTooltipContent />}
                    />
                    <Bar dataKey="scans" fill="var(--color-scans)" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ChartContainer>
              )}
            </div>
          </div>

          {/* Vulnerabilities by severity */}
          <div className="min-h-[380px] flex flex-col">
            <h2 className="text-base font-medium">Vulnerabilities by severity (last 30 days)</h2>
            <p className="text-sm text-muted-foreground mb-4 mt-1">From IAC, SBOM/SCA, and SAST scans</p>
            <div className="flex-1 min-h-[280px]">
              {vulnData.length === 0 ? (
                <p className="text-sm text-muted-foreground flex items-center justify-center h-[280px]">
                  No vulnerability data
                </p>
              ) : (
                <ChartContainer
                  config={vulnChartConfig}
                  className="mx-auto aspect-square max-h-[280px] w-full"
                >
                  <PieChart>
                    <ChartTooltip
                      cursor={false}
                      content={<ChartTooltipContent hideLabel />}
                    />
                    <Pie
                      data={vulnData}
                      dataKey="value"
                      nameKey="name"
                    />
                  </PieChart>
                </ChartContainer>
              )}
            </div>
          </div>

          {/* Scans over time */}
          <div className="min-h-[380px] flex flex-col">
            <h2 className="text-base font-medium">Daily scan volume</h2>
            <p className="text-sm text-muted-foreground mb-4 mt-1">Number of scans created each day; use this to see activity trends over time</p>
            <div className="flex-1 min-h-[280px]">
              {scansByDate.length === 0 ? (
                <p className="text-sm text-muted-foreground flex items-center justify-center h-[280px]">
                  No scans yet
                </p>
              ) : (
                <ChartContainer
                  config={scansAreaChartConfig}
                  className="aspect-auto h-[280px] w-full"
                >
                  <AreaChart data={scansAreaData}>
                    <defs>
                      <linearGradient id="fillScansTeam" x1="0" y1="0" x2="0" y2="1">
                        <stop
                          offset="5%"
                          stopColor="var(--color-count)"
                          stopOpacity={0.8}
                        />
                        <stop
                          offset="95%"
                          stopColor="var(--color-count)"
                          stopOpacity={0.1}
                        />
                      </linearGradient>
                    </defs>
                    <CartesianGrid vertical={false} />
                    <XAxis
                      dataKey="date"
                      tickLine={false}
                      axisLine={false}
                      tickMargin={8}
                      minTickGap={32}
                      tickFormatter={(value) => formatDateLabel(value)}
                    />
                    <ChartTooltip
                      cursor={false}
                      content={
                        <ChartTooltipContent
                          labelFormatter={(value) => formatDateLabel(String(value))}
                          indicator="dot"
                        />
                      }
                    />
                    <Area
                      dataKey="count"
                      type="natural"
                      fill="url(#fillScansTeam)"
                      stroke="var(--color-count)"
                      strokeWidth={2}
                    />
                  </AreaChart>
                </ChartContainer>
              )}
            </div>
          </div>
            </section>
          </CardContent>
        </Card>

        {/* Integrations created over time */}
        <section className="pb-6">
          <h2 className="text-base font-medium flex items-center gap-2 mb-1">
            <div className="bg-blue-600 rounded-md p-1.5">
            <Link2 className="size-5" />
            </div>
            Your Team's Integrations
          </h2>
          <p className="text-sm text-muted-foreground mb-4 mt-1">Guardrails and CI/CD integrations created by date; stacked by type</p>
          <div className="min-h-[220px]">
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
                  className="aspect-auto h-[220px] w-full"
                >
                  <BarChart accessibilityLayer data={integrationsBarData}>
                    <CartesianGrid vertical={false} />
                    <XAxis
                      dataKey="label"
                      tickLine={false}
                      tickMargin={10}
                      axisLine={false}
                      tickFormatter={(value) => String(value)}
                    />
                    <ChartTooltip
                      cursor={false}
                      content={<ChartTooltipContent indicator="dashed" />}
                    />
                    <Bar dataKey="Guardrails" fill="var(--color-Guardrails)" radius={4} stackId="a" />
                    <Bar dataKey="cicd" fill="var(--color-cicd)" radius={4} stackId="a" />
                  </BarChart>
                </ChartContainer>
              );
            })()}
          </div>
        </section>
      </main>
    </div>
  );
}

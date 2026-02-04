"use client";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import { Area, AreaChart, CartesianGrid, PolarAngleAxis, PolarGrid, Radar, RadarChart, RadialBar, RadialBarChart, XAxis, YAxis } from "recharts";
import type { GuardrailsDashboardData as DashboardData } from "@/utils/backend_api";
import {
  BarChart3,
  CheckCircle,
  XCircle,
  Hourglass,
  Play,
  Square,
  Activity,
  AlertTriangle,
  PieChart,
  TrendingUp,
} from "lucide-react";

const metricCardDefs = [
  { key: "total_logs" as const, title: "Total Logs", description: "Total number of logs", icon: BarChart3 },
  { key: "successful_logs" as const, title: "Successful", description: "Successfully processed logs", icon: CheckCircle },
  { key: "failed_logs" as const, title: "Failed", description: "Failed logs", icon: XCircle },
  { key: "pending_logs" as const, title: "Pending", description: "Logs waiting to be processed", icon: Hourglass },
  { key: "started_logs" as const, title: "Started", description: "Logs currently being processed", icon: Play },
  { key: "not_started_logs" as const, title: "Not Started", description: "Logs not yet started", icon: Square },
];

const riskSeverityOrder = ["critical", "high", "medium", "low"] as const;
const riskColors: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-green-500",
};
const riskLabels: Record<string, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

const riskChartKeys = [
  { key: "critical" as const, label: "Critical", color: "hsl(0 84% 60%)" },
  { key: "high" as const, label: "High", color: "hsl(25 95% 53%)" },
  { key: "medium" as const, label: "Medium", color: "hsl(48 96% 53%)" },
  { key: "low" as const, label: "Low", color: "hsl(142 71% 45%)" },
];

const riskChartConfig = {
  count: { label: "Count" },
  ...Object.fromEntries(
    riskChartKeys.map(({ key, label, color }) => [key, { label, color }])
  ),
} satisfies ChartConfig;

const riskRadarChartConfig = {
  subject: { label: "Severity" },
  count: { label: "Count", color: "hsl(0 84% 60%)" },
} satisfies ChartConfig;

const highCriticalAreaChartConfig = {
  date: { label: "Date" },
  count: { label: "High/Critical risks", color: "hsl(0 84% 60%)" },
} satisfies ChartConfig;

const logStatusChartKeys = [
  { key: "successful_logs" as const, label: "Successful", color: "var(--chart-1)" },
  { key: "failed_logs" as const, label: "Failed", color: "var(--chart-2)" },
  { key: "pending_logs" as const, label: "Pending", color: "var(--chart-3)" },
  { key: "started_logs" as const, label: "Started", color: "var(--chart-4)" },
  { key: "not_started_logs" as const, label: "Not started", color: "var(--chart-5)" },
];

const logStatusChartConfig = {
  count: { label: "Count" },
  ...Object.fromEntries(
    logStatusChartKeys.map(({ key, label, color }) => [key, { label, color }])
  ),
} satisfies ChartConfig;

export interface GuardrailsDashboardDataProps {
  dashboardData: DashboardData | null | undefined;
}

export function GuardrailsDashboardData({ dashboardData }: GuardrailsDashboardDataProps) {
  if (dashboardData == null) {
    return (
      <div className="text-center py-8 text-zinc-500 dark:text-zinc-400 text-sm">
        No dashboard data available.
      </div>
    );
  }

  const {
    card_data,
    recent_daily_detections_usage,
    high_or_critical_risks_daily_usage = {},
    past_30_days_risk_score_data,
    past_60_days_risk_score_data,
  } = dashboardData;

  const highCriticalAreaData = Object.entries(high_or_critical_risks_daily_usage)
    .map(([dateStr, count]) => ({ date: dateStr, count }))
    .sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime());
  const areaChartData = highCriticalAreaData.length > 0 ? highCriticalAreaData : [{ date: new Date().toISOString().slice(0, 10), count: 0 }];

  const dailyEntries = Object.entries(recent_daily_detections_usage).sort(
    (a, b) => new Date(a[0]).getTime() - new Date(b[0]).getTime()
  );
  const maxDaily = dailyEntries.length > 0 ? Math.max(...dailyEntries.map(([, v]) => v)) : 0;

  const radialChartData = logStatusChartKeys.map(({ key, label, color }) => ({
    name: label,
    actualCount: card_data[key] ?? 0,
    fill: color,
  }));
  const maxCount = Math.max(1, ...radialChartData.map((d) => d.actualCount));
  const radialChartDataNormalized = radialChartData.map((d) => ({
    ...d,
    count: maxCount > 0 ? (d.actualCount / maxCount) * 100 : 0,
  }));

  const riskRadarData30 = riskChartKeys.map(({ key, label }) => ({
    subject: label,
    count: past_30_days_risk_score_data[key] ?? 0,
  }));

  const riskRadarData60 = riskChartKeys.map(({ key, label }) => ({
    subject: label,
    count: past_60_days_risk_score_data[key] ?? 0,
  }));

  return (
    <div className="space-y-8">
      {/* Metric cards */}
      <div className="flex flex-row gap-3 overflow-x-auto">
        {metricCardDefs.map(({ key, title, icon: Icon }) => (
          <div
            key={key}
            className="flex-1 min-w-0 border border-zinc-200 dark:border-zinc-800 rounded-lg p-4 bg-transparent hover:bg-zinc-50 dark:hover:bg-zinc-900/50 transition-colors"
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wide">
                {title}
              </span>
              <Icon className="w-4 h-4 text-zinc-400 dark:text-zinc-500" />
            </div>
            <div className="text-2xl font-semibold text-zinc-900 dark:text-zinc-100">
              {card_data[key] ?? 0}
            </div>
          </div>
        ))}
      </div>

      {/* Log status distribution + Recent daily detections + Risk score distribution */}
      <div className="w-full">
        <div className="flex gap-6 w-full">
          <Card className="border-zinc-200 dark:border-zinc-800 flex-1 min-w-0">
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <PieChart className="w-4 h-4" />
                  Log status distribution
                </CardTitle>
                <CardDescription>
                  Proportion of logs by status (successful, failed, pending, started, not started)
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ChartContainer
                  config={logStatusChartConfig}
                  className="mx-auto aspect-square max-h-[280px]"
                >
                  <RadialBarChart
                    data={radialChartDataNormalized}
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
                <div className="mt-10 pt-3 border-t border-zinc-200 dark:border-zinc-700 flex flex-wrap gap-x-4 gap-y-1.5 justify-center">
                  {logStatusChartKeys.map(({ label, color }) => (
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
              </CardContent>
            </Card>
          <Card className="border-zinc-200 dark:border-zinc-800 flex-1 min-w-0 flex flex-col justify-between">
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Activity className="w-4 h-4" />
                  Daily Detections
                </CardTitle>
                <CardDescription>
                  Number of detections in the last 30 days 
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ScrollArea className="w-full min-h-[160px] mt-auto">
                  <div className="flex gap-2 items-end min-w-max pb-2 min-h-[140px]">
                    {dailyEntries.slice(-14).map(([dateStr, count]) => (
                      <Tooltip key={dateStr}>
                        <TooltipTrigger asChild>
                          <div className="flex flex-col items-center gap-1 shrink-0 min-w-8 h-[140px] justify-end cursor-default">
                            <div
                              className="w-8 bg-blue-500/80 dark:bg-blue-600/80 rounded-t min-h-[4px] transition-all"
                              style={{
                                height: maxDaily > 0 ? `${Math.max(8, (count / maxDaily) * 120)}px` : "8px",
                              }}
                            />
                            <span className="text-[10px] text-zinc-500 dark:text-zinc-400 font-mono">
                              {dateStr.slice(5)}
                            </span>
                          </div>
                        </TooltipTrigger>
                        <TooltipContent side="top" className="font-medium bg-zinc-800 text-zinc-100 border border-zinc-600 *:last:bg-zinc-800 *:last:fill-zinc-800">
                          <span className="font-normal text-zinc-300">
                            {new Date(dateStr).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}
                          </span>
                          <br />
                          <span className="font-mono tabular-nums">{count}</span> detection{count !== 1 ? "s" : ""}
                        </TooltipContent>
                      </Tooltip>
                    ))}
                  </div>
                  <ScrollBar orientation="horizontal" />
                </ScrollArea>
              </CardContent>
            </Card>
          {/* Risk score distribution: 30 / 60 days with tabs */}
          <Card className="border-zinc-200 dark:border-zinc-800 flex-1 min-w-0 overflow-hidden">
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <AlertTriangle className="w-4 h-4" />
                Risk score distribution
              </CardTitle>
              <CardDescription>
                Counts by severity. Switch between past 30 and 60 days.
              </CardDescription>
            </CardHeader>
            <CardContent className="overflow-hidden px-6 sm:px-8">
              <Tabs defaultValue="30" className="">
                <TabsList className="grid w-full max-w-[240px] grid-cols-2 dark:bg-transparent mb-15">
                  <TabsTrigger className="data-[state=active]:bg-blue-600 cursor-pointer" value="30">Past 30 days</TabsTrigger>
                  <TabsTrigger className="data-[state=active]:bg-blue-600 cursor-pointer" value="60">Past 60 days</TabsTrigger>
                </TabsList>
                <TabsContent value="30" className="mt-4">
                  <div className="min-w-0 h-[360px] flex items-center justify-center">
                    <ChartContainer config={riskRadarChartConfig} className="h-[340px] w-[340px] shrink-0">
                    <RadarChart data={riskRadarData30} margin={{ top: 8, right: 24, bottom: 8, left: 24 }}>
                      <ChartTooltip cursor={false} content={<ChartTooltipContent nameKey="subject" formatter={(value, name) => [value, name ?? "Count"]} />} />
                      <PolarAngleAxis dataKey="subject" />
                      <PolarGrid />
                      <Radar
                        dataKey="count"
                        fill="hsl(0 84% 60%)"
                        fillOpacity={0.6}
                        dot={{ r: 4, fillOpacity: 1 }}
                      />
                    </RadarChart>
                  </ChartContainer>
                  </div>
                </TabsContent>
                <TabsContent value="60" className="mt-4">
                  <div className="min-w-0 h-[360px] flex items-center justify-center">
                    <ChartContainer config={riskRadarChartConfig} className="h-[340px] w-[340px] shrink-0">
                    <RadarChart data={riskRadarData60} margin={{ top: 8, right: 24, bottom: 8, left: 24 }}>
                      <ChartTooltip cursor={false} content={<ChartTooltipContent nameKey="subject" formatter={(value, name) => [value, name ?? "Count"]} />} />
                      <PolarAngleAxis dataKey="subject" />
                      <PolarGrid />
                      <Radar
                        dataKey="count"
                        fill="hsl(0 84% 60%)"
                        fillOpacity={0.6}
                        dot={{ r: 4, fillOpacity: 1 }}
                      />
                    </RadarChart>
                  </ChartContainer>
                  </div>
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* High or critical risks daily usage — area chart */}
      <Card className="border-zinc-200 dark:border-zinc-800 w-full">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <TrendingUp className="w-4 h-4" />
              High or critical risks by day
            </CardTitle>
            <CardDescription>
              Daily count of high- or critical-severity risks (past 30 days)
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer
              config={highCriticalAreaChartConfig}
              className="aspect-auto h-[260px] w-full pb-8"
            >
              <AreaChart data={areaChartData} margin={{ bottom: 28 }}>
                <defs>
                  <linearGradient id="fillHighCritical" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="hsl(0 84% 60%)" stopOpacity={0.8} />
                    <stop offset="95%" stopColor="hsl(0 84% 60%)" stopOpacity={0.1} />
                  </linearGradient>
                </defs>
                <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                <XAxis
                  dataKey="date"
                  tickLine={false}
                  axisLine={false}
                  tickMargin={8}
                  minTickGap={20}
                  tickFormatter={(value) => {
                    const date = new Date(value);
                    const m = date.getMonth() + 1;
                    const d = date.getDate();
                    return `${m.toString().padStart(2, "0")}/${d.toString().padStart(2, "0")}`;
                  }}
                  tick={({ payload, x, y }) => (
                    <g transform={`translate(${x},${y})`}>
                      <foreignObject x={-24} y={0} width={48} height={28} className="overflow-visible">
                        <div className="text-[10px] text-center text-zinc-600 dark:text-zinc-400 wrap-break-word leading-tight w-full">
                          {payload.value
                            ? (() => {
                                const date = new Date(payload.value);
                                const m = date.getMonth() + 1;
                                const d = date.getDate();
                                return `${m.toString().padStart(2, "0")}/${d.toString().padStart(2, "0")}`;
                              })()
                            : ""}
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
                      labelFormatter={(value) =>
                        new Date(value).toLocaleDateString("en-US", {
                          month: "short",
                          day: "numeric",
                          year: "numeric",
                        })
                      }
                      formatter={(value) => [value, "High/Critical risks"]}
                    />
                  }
                />
                <Area
                  dataKey="count"
                  type="monotone"
                  fill="url(#fillHighCritical)"
                  stroke="hsl(0 84% 60%)"
                  strokeWidth={2}
                />
              </AreaChart>
            </ChartContainer>
          </CardContent>
        </Card>
    </div>
  );
}

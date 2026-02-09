"use client";

import { useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { RadialBarChart, RadialBar } from "recharts";
import { Users } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import {
  getTeamsDashboard,
  getTeams,
  type TeamListItem,
} from "@/utils/backend_api";

const UTILIZATION_COLORS = [
  "#3b82f6", "#60a5fa", "#93c5fd", "#dc2626", "#f87171"
] as const;

const CREDIT_RADIAL_COLORS = [
  "#3b82f6", "#10b981", "#f59e0b", "#8b5cf6", "#ec4899", "#06b6d4", "#84cc16", "#ef4444"
] as const;

/** Parse team key from dashboard (format: "teamId-teamName") */
function parseTeamKey(key: string): { team_id: number; team_name: string } | null {
  const dashIdx = key.indexOf("-");
  if (dashIdx <= 0) return null;
  const id = parseInt(key.slice(0, dashIdx), 10);
  if (isNaN(id)) return null;
  return { team_id: id, team_name: key.slice(dashIdx + 1) };
}

export default function HomePage() {
  const router = useRouter();

  const { data: teams, isLoading: teamsLoading } = useQuery({
    queryKey: ["teams"],
    queryFn: getTeams,
    retry: 1,
  });

  const { data: teamsDashboard, isLoading: dashboardLoading } = useQuery({
    queryKey: ["teams-dashboard"],
    queryFn: getTeamsDashboard,
  });

  const utilEntries = teamsDashboard?.team_utilization_data
    ? Object.entries(teamsDashboard.team_utilization_data)
    : [];
  const creditEntries = teamsDashboard?.credit_balance_data
    ? Object.entries(teamsDashboard.credit_balance_data)
    : [];

  const agg = utilEntries.reduce(
    (acc, [, v]) => ({
      sast: acc.sast + (v?.sast_scans ?? 0),
      iac: acc.iac + (v?.iac_scans ?? 0),
      sbom_sca: acc.sbom_sca + (v?.sbom_sca_scans ?? 0),
      guardrails: acc.guardrails + (v?.guardrails_integrations ?? 0),
      cicd: acc.cicd + (v?.cicd_integrations ?? 0),
    }),
    { sast: 0, iac: 0, sbom_sca: 0, guardrails: 0, cicd: 0 }
  );

  const utilLabels = [
    { key: "sast", label: "SAST", value: agg.sast },
    { key: "iac", label: "IAC", value: agg.iac },
    { key: "sbom_sca", label: "SBOM/SCA", value: agg.sbom_sca },
    { key: "guardrails", label: "Guardrails", value: agg.guardrails },
    { key: "cicd", label: "CI/CD", value: agg.cicd },
  ];

  const utilMax = Math.max(1, ...utilLabels.map((d) => d.value));
  const MIN_RADIAL_PCT = 4;
  const utilRadialData = utilLabels.map((d, i) => ({
    name: d.label,
    value: d.value === 0 ? MIN_RADIAL_PCT : (d.value / utilMax) * 100,
    actualValue: d.value,
    fill: UTILIZATION_COLORS[i % UTILIZATION_COLORS.length],
  }));

  const creditRadialData = creditEntries
    .map(([key, item]) => {
      const parsed = parseTeamKey(key);
      if (!parsed || item == null) return null;
      return { ...parsed, actualValue: item?.credit_balance ?? 0 };
    })
    .filter(Boolean) as { team_id: number; team_name: string; actualValue: number }[];
  const creditMax = Math.max(1, ...creditRadialData.map((d) => d.actualValue));
  const creditChartData = creditRadialData.map((d, i) => ({
    name: d.team_name,
    value: d.actualValue === 0 ? MIN_RADIAL_PCT : (d.actualValue / creditMax) * 100,
    actualValue: d.actualValue,
    fill: CREDIT_RADIAL_COLORS[i % CREDIT_RADIAL_COLORS.length],
  }));

  const utilChartConfig = Object.fromEntries(
    utilLabels.map((d, i) => [
      d.key,
      { label: d.label, color: UTILIZATION_COLORS[i % UTILIZATION_COLORS.length] },
    ])
  ) as ChartConfig;

  const creditChartConfig = creditRadialData.reduce(
    (acc, d, i) => {
      acc[d.team_name] = { label: d.team_name, color: CREDIT_RADIAL_COLORS[i % CREDIT_RADIAL_COLORS.length] };
      return acc;
    },
    {} as Record<string, { label: string; color: string }>
  );

  return (
    <div className="flex flex-col h-full min-h-[calc(100vh-2rem)] bg-background">

      <main className="flex-1 p-6 overflow-auto">
        {/* 2 radial charts from teams dashboard route */}
        <section className="pb-8">
          <h2 className="text-base font-medium flex items-center gap-2 mb-1">
            <div className="bg-blue-600 rounded-md p-1.5">
              <Users className="size-5" />
            </div>
            All Your Teams
          </h2>
          <p className="text-sm text-muted-foreground mb-4 mt-1">
            Utilization and credit balance across all teams you belong to.
          </p>
          {dashboardLoading ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-6">
              <Skeleton className="min-h-[320px] rounded-lg" />
              <Skeleton className="min-h-[320px] rounded-lg" />
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-6">
              {/* Radial 1: Utilization */}
              <Card className="min-h-[360px] flex flex-col">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">Utilization across all teams</CardTitle>
                  <CardDescription>
                    Total scans (SAST, IAC, SBOM/SCA) and integrations (Guardrails, CI/CD) aggregated across all your teams. Segment size reflects relative proportion.
                  </CardDescription>
                </CardHeader>
                <CardContent className="flex-1 flex flex-col items-center">
                  {utilRadialData.length === 0 ? (
                    <p className="text-sm text-muted-foreground flex-1 flex items-center">No utilization data yet</p>
                  ) : (
                    <>
                      <ChartContainer
                        config={{ ...utilChartConfig, value: { label: "Count" } }}
                        className="mx-auto aspect-square max-h-[200px] w-full"
                      >
                        <RadialBarChart data={utilRadialData} innerRadius={40} outerRadius={90} startAngle={90} endAngle={-270}>
                          <ChartTooltip
                            cursor={false}
                            content={
                              <ChartTooltipContent
                                nameKey="name"
                                formatter={(_, name, __, ___, payload) => {
                                  const v = (payload as { actualValue?: number })?.actualValue ?? 0;
                                  return (
                                    <span className="font-medium">
                                      <span className="text-muted-foreground">{name}: </span>
                                      <span className="font-mono font-semibold tabular-nums">{v}</span>
                                    </span>
                                  );
                                }}
                              />
                            }
                          />
                          <RadialBar dataKey="value" background className="cursor-pointer" />
                        </RadialBarChart>
                      </ChartContainer>
                      <div className="mt-3 pt-3 border-t w-full flex flex-wrap gap-x-4 gap-y-1.5 justify-center">
                        {utilRadialData.map((d) => (
                          <div key={d.name} className="flex items-center gap-1.5 text-xs">
                            <span
                              className="shrink-0 w-3 h-3 rounded-full"
                              style={{ backgroundColor: d.fill }}
                              aria-hidden
                            />
                            <span className="text-muted-foreground">{d.name}</span>
                            <span className="font-mono font-medium tabular-nums">{d.actualValue}</span>
                          </div>
                        ))}
                      </div>
                      <p className="text-xs text-muted-foreground text-center mt-2">
                        Hover over segments for details.
                      </p>
                    </>
                  )}
                </CardContent>
              </Card>

              {/* Radial 2: Credit balance */}
              <Card className="min-h-[360px] flex flex-col">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">Credit balance by team</CardTitle>
                  <CardDescription>
                    Available scan credits per team. Each segment represents one team; size is proportional to its share of total credits.
                  </CardDescription>
                </CardHeader>
                <CardContent className="flex-1 flex flex-col items-center">
                  {creditChartData.length === 0 ? (
                    <p className="text-sm text-muted-foreground flex-1 flex items-center">No teams</p>
                  ) : (
                    <>
                      <ChartContainer
                        config={{ ...creditChartConfig, value: { label: "Credits" } }}
                        className="mx-auto aspect-square max-h-[200px] w-full"
                      >
                        <RadialBarChart data={creditChartData} innerRadius={40} outerRadius={90} startAngle={90} endAngle={-270}>
                          <ChartTooltip
                            cursor={false}
                            content={
                              <ChartTooltipContent
                                nameKey="name"
                                formatter={(_, name, __, ___, payload) => {
                                  const v = (payload as { actualValue?: number })?.actualValue ?? 0;
                                  return (
                                    <span className="font-medium">
                                      <span className="text-muted-foreground">{name}: </span>
                                      <span className="font-mono font-semibold tabular-nums">{v}</span> credits
                                    </span>
                                  );
                                }}
                              />
                            }
                          />
                          <RadialBar dataKey="value" background className="cursor-pointer" />
                        </RadialBarChart>
                      </ChartContainer>
                      <div className="mt-3 pt-3 border-t w-full flex flex-wrap gap-x-4 gap-y-1.5 justify-center max-h-16 overflow-y-auto">
                        {creditChartData.map((d) => (
                          <div key={d.name} className="flex items-center gap-1.5 text-xs">
                            <span
                              className="shrink-0 w-3 h-3 rounded-full"
                              style={{ backgroundColor: d.fill }}
                              aria-hidden
                            />
                            <span className="text-muted-foreground truncate max-w-24">{d.name}</span>
                            <span className="font-mono font-medium tabular-nums">{d.actualValue}</span>
                          </div>
                        ))}
                      </div>
                      <p className="text-xs text-muted-foreground text-center mt-2">
                        Hover over segments for details.
                      </p>
                    </>
                  )}
                </CardContent>
              </Card>
            </div>
          )}
        </section>

        {/* Teams table — uses same query as sidebar */}
        <section>
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Teams</CardTitle>
              <CardDescription>Click a row to open the team</CardDescription>
            </CardHeader>
            <CardContent>
              {teamsLoading ? (
                <div className="space-y-2">
                  <Skeleton className="h-10 w-full" />
                  <Skeleton className="h-10 w-full" />
                  <Skeleton className="h-10 w-3/4" />
                </div>
              ) : !teams?.length ? (
                <p className="text-sm text-muted-foreground py-6 text-center">No teams yet.</p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Team</TableHead>
                      <TableHead>Members</TableHead>
                      <TableHead>Credits</TableHead>
                      <TableHead>Created</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(teams as TeamListItem[]).map((t) => (
                      <TableRow
                        key={t.team_id}
                        className="cursor-pointer hover:bg-muted/50"
                        onClick={() => router.push(`/${t.team_id}`)}
                      >
                        <TableCell className="font-medium">{t.team_name}</TableCell>
                        <TableCell className="text-muted-foreground">
                          {t.team_members?.length ? t.team_members.join(", ") : "—"}
                        </TableCell>
                        <TableCell className="font-mono tabular-nums">{t.team_credit_balance}</TableCell>
                        <TableCell className="text-muted-foreground text-sm">
                          {t.team_created_at
                            ? new Date(t.team_created_at).toLocaleDateString(undefined, {
                                month: "short",
                                day: "numeric",
                                year: "numeric",
                              })
                            : "—"}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </section>
      </main>
    </div>
  );
}

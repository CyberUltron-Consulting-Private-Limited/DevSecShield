"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuLabel,
  DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Plus, MoreVertical, Pencil, Trash2, RefreshCcw, Loader2, Eye, Clock, Search, X, Shield, AlertTriangle, Check, ScanSearch, Target, Percent, AlertCircle, Activity, Filter, ChevronDown, ArrowUpDown, DollarSign, TrendingUp, TrendingDown } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { singleFlight } from "@/utils/single_flight";
import {
  getDASTScans,
  deleteDASTScan,
  renameDASTScan,
  createDASTScan,
  type DASTListItem,
  type DASTListDashboardData,
} from "@/utils/backend_api";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { showErrorToast } from "@/utils/error-handler";
import { formatDateIst as formatDate, formatChartDateIst } from "@/utils/datetime";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DastProfilesTab } from "@/components/dast/DastProfilesTab";
import { Progress } from "@/components/ui/progress";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  ChartLegend,
  ChartLegendContent,
  type ChartConfig,
} from "@/components/ui/chart";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  PolarAngleAxis,
  PolarGrid,
  Radar,
  RadarChart,
  XAxis,
  YAxis,
} from "recharts";

type ScanStatus = "pending" | "started" | "retry" | "failure" | "success" | "not_started";

type RiskScoreFilter = "all" | "critical" | "high" | "medium" | "low";
type TableSortBy =
  | "none"
  | "created_asc"
  | "created_desc"
  | "risk_desc"
  | "risk_asc"
  | "credits_desc"
  | "credits_asc";

const RISK_SCORE_LABELS: Record<RiskScoreFilter, string> = {
  all: "Risk score",
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

const SORT_BY_LABELS: Record<TableSortBy, string> = {
  none: "Sort by",
  created_asc: "Created (oldest)",
  created_desc: "Created (newest)",
  risk_desc: "Risk score (high first)",
  risk_asc: "Risk score (low first)",
  credits_desc: "Credits (high first)",
  credits_asc: "Credits (low first)",
};

function getDisplayRiskScore(c: DASTListItem): number | null {
  if (c.average_risk_score == null) return null;
  return Math.round(Math.min(10, Math.max(0, Number(c.average_risk_score))) * 10) / 10;
}

function matchesRiskScoreFilter(score: number | null, filter: RiskScoreFilter): boolean {
  if (filter === "all") return true;
  if (score == null) return false;
  if (filter === "critical") return score >= 9;
  if (filter === "high") return score >= 7 && score < 9;
  if (filter === "medium") return score >= 5 && score < 7;
  if (filter === "low") return score < 5;
  return true;
}

// ─── Dashboard Tab ──────────────────────────────────────────────────────────────

function DASTDashboard({ dashboardData }: { dashboardData: DASTListDashboardData }) {
  const card = dashboardData.card_data;

  const severityPieData = useMemo(() => {
    const d = dashboardData.severity_distribution;
    return [
      { name: "Critical", value: d?.critical ?? 0, fill: "#dc2626" },
      { name: "High", value: d?.high ?? 0, fill: "#ea580c" },
      { name: "Medium", value: d?.medium ?? 0, fill: "#ca8a04" },
      { name: "Low", value: d?.low ?? 0, fill: "#2563eb" },
    ];
  }, [dashboardData.severity_distribution]);

  const issuesOverTimeData = useMemo(() => {
    return Object.entries(dashboardData.issues_over_time)
      .map(([date, v]) => ({ date, ...v }))
      .sort((a, b) => a.date.localeCompare(b.date));
  }, [dashboardData.issues_over_time]);

  const areaConfig = {
    critical: { label: "Critical", color: "hsl(0 72% 51%)" },
    high: { label: "High", color: "hsl(25 95% 53%)" },
    medium: { label: "Medium", color: "hsl(45 93% 47%)" },
    low: { label: "Low", color: "hsl(217 91% 60%)" },
  } satisfies ChartConfig;

  const securityPostureData = useMemo(() => {
    const overview = dashboardData.security_posture_overview ?? {};
    return Object.entries(overview).map(([category, count], i) => ({
      xLabel: `S${i + 1}`,
      category: category.replace(/_/g, " "),
      count: typeof count === "number" ? count : 0,
    }));
  }, [dashboardData.security_posture_overview]);

  const securityPostureConfig = { count: { label: "Count", color: "hsl(220 70% 50%)" } } satisfies ChartConfig;

  const owaspBarData = useMemo(() => {
    const issues = dashboardData.owasp_top_10_issues ?? {};
    return Object.entries(issues).map(([name, count]) => ({
      name: name.includes(" - ") ? name.split(" - ")[1]?.slice(0, 20) ?? name : name.slice(0, 20),
      fullName: name,
      count: typeof count === "number" ? count : 0,
    }));
  }, [dashboardData.owasp_top_10_issues]);

  const avgRiskCategoryData = useMemo(() => {
    const perCategory = dashboardData.average_risk_score_per_category ?? {};
    return Object.entries(perCategory).map(([category, score]) => ({
      category: category.replace(/_/g, " "),
      score: typeof score === "number" ? score : 0,
    }));
  }, [dashboardData.average_risk_score_per_category]);

  const confidencePieData = useMemo(() => {
    const d = dashboardData.average_risk_score_per_confidence;
    return [
      { name: "High", value: typeof d?.high === "number" ? d.high : 0, fill: "#16a34a" },
      { name: "Medium", value: typeof d?.medium === "number" ? d.medium : 0, fill: "#ca8a04" },
      { name: "Low", value: typeof d?.low === "number" ? d.low : 0, fill: "#2563eb" },
    ];
  }, [dashboardData.average_risk_score_per_confidence]);

  const complianceBarData = useMemo(() => {
    const violations = dashboardData.compliance_violations ?? {};
    return Object.entries(violations).map(([name, count]) => ({
      name,
      count: typeof count === "number" ? count : 0,
    }));
  }, [dashboardData.compliance_violations]);

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
          <CardContent className="p-0">
            <div className="flex flex-col items-start gap-2">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-blue-500/15 dark:bg-blue-500/10">
                <ScanSearch className="h-4 w-4 text-blue-500" />
              </div>
              <div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Total scans</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_scans}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
          <CardContent className="p-0">
            <div className="flex flex-col items-start gap-2">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-red-500/15 dark:bg-red-500/10">
                <Target className="h-4 w-4 text-red-500" />
              </div>
              <div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Total critical</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_critical_issues}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
          <CardContent className="p-0">
            <div className="flex flex-col items-start gap-2">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-orange-500/15 dark:bg-orange-500/10">
                <AlertCircle className="h-4 w-4 text-orange-500" />
              </div>
              <div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Total high</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_high_issues}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
          <CardContent className="p-0">
            <div className="flex flex-col items-start gap-2">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-amber-500/15 dark:bg-amber-500/10">
                <AlertTriangle className="h-4 w-4 text-amber-500" />
              </div>
              <div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Total medium</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_medium_issues}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
          <CardContent className="p-0">
            <div className="flex flex-col items-start gap-2">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-blue-500/15 dark:bg-blue-500/10">
                <Shield className="h-4 w-4 text-blue-500" />
              </div>
              <div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Total low</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_low_issues}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
          <CardContent className="p-0">
            <div className="flex flex-col items-start gap-2">
              <div
                className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${
                  card.average_risk_score >= 7
                    ? "bg-red-500/15 dark:bg-red-500/10"
                    : card.average_risk_score >= 5
                      ? "bg-amber-500/15 dark:bg-amber-500/10"
                      : "bg-green-500/15 dark:bg-green-500/10"
                }`}
              >
                <Activity
                  className={`h-4 w-4 ${
                    card.average_risk_score >= 7 ? "text-red-500" : card.average_risk_score >= 5 ? "text-amber-500" : "text-green-500"
                  }`}
                />
              </div>
              <div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Avg risk score</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.average_risk_score.toFixed(1)}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="items-center pb-2">
            <CardTitle className="text-base">Severity Distribution</CardTitle>
            <CardDescription>Critical / High / Medium / Low</CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer
              config={{
                Critical: { label: "Critical" },
                High: { label: "High" },
                Medium: { label: "Medium" },
                Low: { label: "Low" },
              }}
              className="mx-auto aspect-square max-h-[280px]"
            >
              <PieChart>
                <ChartTooltip content={<ChartTooltipContent />} />
                <ChartLegend content={<ChartLegendContent nameKey="name" />} />
                <Pie
                  data={severityPieData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={90}
                  paddingAngle={2}
                >
                  {severityPieData.map((entry) => (
                    <Cell key={entry.name} fill={entry.fill} />
                  ))}
                </Pie>
              </PieChart>
            </ChartContainer>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Issues Over Time</CardTitle>
            <CardDescription>Stacked by severity</CardDescription>
          </CardHeader>
          <CardContent>
            {issuesOverTimeData.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No data yet</p>
            ) : (
              <ChartContainer config={areaConfig} className="h-[280px] w-full">
                <AreaChart data={issuesOverTimeData}>
                  <CartesianGrid vertical={false} />
                  <XAxis
                    dataKey="date"
                    tickLine={false}
                    axisLine={false}
                    tickMargin={8}
                    tickFormatter={(v) => formatChartDateIst(v)}
                  />
                  <YAxis tickLine={false} axisLine={false} allowDecimals={false} />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <ChartLegend content={<ChartLegendContent />} />
                  <Area type="monotone" dataKey="critical" stackId="a" fill="var(--color-critical)" stroke="var(--color-critical)" fillOpacity={0.4} />
                  <Area type="monotone" dataKey="high" stackId="a" fill="var(--color-high)" stroke="var(--color-high)" fillOpacity={0.4} />
                  <Area type="monotone" dataKey="medium" stackId="a" fill="var(--color-medium)" stroke="var(--color-medium)" fillOpacity={0.4} />
                  <Area type="monotone" dataKey="low" stackId="a" fill="var(--color-low)" stroke="var(--color-low)" fillOpacity={0.4} />
                </AreaChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="items-center pb-2">
            <CardTitle className="text-base">Security Posture Overview</CardTitle>
            <CardDescription>By category</CardDescription>
          </CardHeader>
          <CardContent>
            {securityPostureData.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No data yet</p>
            ) : (
              <>
                <ChartContainer config={securityPostureConfig} className="mx-auto aspect-square max-h-[280px]">
                  <RadarChart data={securityPostureData}>
                    <ChartTooltip
                      cursor={false}
                      content={
                        <ChartTooltipContent
                          labelFormatter={(_, payload) => (payload?.[0]?.payload as { category?: string })?.category ?? "—"}
                          formatter={(v) => [v, "Count"]}
                        />
                      }
                    />
                    <PolarAngleAxis dataKey="xLabel" />
                    <PolarGrid />
                    <Radar dataKey="count" fill="var(--color-count)" fillOpacity={0.6} dot={{ r: 4, fillOpacity: 1 }} />
                  </RadarChart>
                </ChartContainer>
                <div className="mt-4 pt-3 border-t border-zinc-200 dark:border-zinc-700 flex flex-wrap gap-x-4 gap-y-2 justify-center text-xs text-zinc-600 dark:text-zinc-400">
                  {securityPostureData.map((d) => (
                    <span key={d.xLabel}>
                      <span className="font-medium text-zinc-800 dark:text-zinc-200">{d.xLabel}</span>
                      <span className="mx-1.5">=</span>
                      <span>{d.category}</span>
                    </span>
                  ))}
                </div>
              </>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">OWASP Top 10</CardTitle>
            <CardDescription>Issue count by category</CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer config={{ count: { label: "Count", color: "hsl(217 91% 60%)" } }} className="h-[280px] w-full">
              <BarChart data={owaspBarData} layout="vertical" margin={{ left: 8, right: 8 }}>
                <CartesianGrid horizontal={false} />
                <XAxis type="number" tickLine={false} axisLine={false} allowDecimals={false} />
                <YAxis type="category" dataKey="name" tickLine={false} axisLine={false} width={120} tick={{ fontSize: 11 }} />
                <ChartTooltip content={<ChartTooltipContent />} formatter={(value) => [value, "Count"]} />
                <Bar dataKey="count" radius={[0, 4, 4, 0]} fill="var(--color-count)" />
              </BarChart>
            </ChartContainer>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Average Risk Score per Category</CardTitle>
            <CardDescription>Five vulnerability categories</CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer config={{ score: { label: "Score", color: "hsl(25 95% 53%)" } }} className="h-[280px] w-full">
              <BarChart data={avgRiskCategoryData}>
                <CartesianGrid vertical={false} />
                <XAxis dataKey="category" tickLine={false} axisLine={false} tick={{ fontSize: 11 }} />
                <YAxis tickLine={false} axisLine={false} allowDecimals={true} />
                <ChartTooltip content={<ChartTooltipContent />} />
                <Bar dataKey="score" radius={[4, 4, 0, 0]} fill="var(--color-score)" />
              </BarChart>
            </ChartContainer>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="items-center pb-2">
            <CardTitle className="text-base">Average Risk Score per Confidence</CardTitle>
            <CardDescription>High / Medium / Low</CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer
              config={{
                High: { label: "High" },
                Medium: { label: "Medium" },
                Low: { label: "Low" },
              }}
              className="mx-auto aspect-square max-h-[240px]"
            >
              <PieChart>
                <ChartTooltip content={<ChartTooltipContent />} />
                <ChartLegend content={<ChartLegendContent nameKey="name" />} />
                <Pie
                  data={confidencePieData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  innerRadius={40}
                  outerRadius={80}
                  paddingAngle={2}
                >
                  {confidencePieData.map((entry) => (
                    <Cell key={entry.name} fill={entry.fill} />
                  ))}
                </Pie>
              </PieChart>
            </ChartContainer>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Compliance Violations</CardTitle>
            <CardDescription>PCI DSS, ISO 27001–27004</CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer config={{ count: { label: "Violations", color: "hsl(0 72% 51%)" } }} className="h-[240px] w-full">
              <BarChart data={complianceBarData}>
                <CartesianGrid vertical={false} />
                <XAxis dataKey="name" tickLine={false} axisLine={false} />
                <YAxis tickLine={false} axisLine={false} allowDecimals={false} />
                <ChartTooltip content={<ChartTooltipContent />} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]} fill="var(--color-count)" />
              </BarChart>
            </ChartContainer>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// ─── Main Page ──────────────────────────────────────────────────────────────────

export default function DASTPage() {
  const router = useRouter();
  const params = useParams();
  const team_id = params?.team_id as string;
  const [scans, setScans] = useState<DASTListItem[]>([]);
  const [renameDialogOpen, setRenameDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [selectedScan, setSelectedScan] = useState<DASTListItem | null>(null);
  const [newName, setNewName] = useState("");
  const [newScanTitle, setNewScanTitle] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [riskScoreFilter, setRiskScoreFilter] = useState<RiskScoreFilter>("all");
  const [sortBy, setSortBy] = useState<TableSortBy>("none");
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ["dast-scans", team_id],
    queryFn: () => getDASTScans(parseInt(team_id)),
    enabled: !!team_id,
  });

  useEffect(() => {
    if (query.data) {
      setScans(query.data.scans_list_data ?? []);
    }
    if (query.error) {
      showErrorToast(query.error, "Error fetching DAST scans");
    }
  }, [query.data, query.error]);

  const deleteDASTScanMutation = useMutation({
    mutationFn: ({ team_id, scan_id }: { team_id: number; scan_id: number }) => deleteDASTScan(team_id, scan_id),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ["dast-scans", variables.team_id.toString()] });
      toast.success("DAST scan deleted successfully");
    },
    onError: (error) => showErrorToast(error),
  });

  const renameDASTScanMutation = useMutation({
    mutationFn: renameDASTScan,
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ["dast-scans", variables.team_id.toString()] });
      toast.success("DAST scan renamed successfully");
    },
    onError: (error) => showErrorToast(error),
  });

  // One create per click burst (double-click, Enter twice): isPending disables Create only after a re-render.
  const [createGuard] = useState(singleFlight);
  const createDASTScanMutation = useMutation({
    mutationFn: ({ team_id, title }: { team_id: number; title: string }) => createDASTScan(team_id, title),
    onSuccess: (scan_id, variables) => {
      queryClient.invalidateQueries({ queryKey: ["dast-scans", variables.team_id.toString()] });
      setCreateDialogOpen(false);
      setNewScanTitle("");
      router.push(`/${variables.team_id}/dast/${scan_id}`);
    },
    onError: (error) => showErrorToast(error),
  });

  const getStatusBadge = (status: ScanStatus) => {
    const variants = {
      not_started: { variant: "outline" as const, className: "text-zinc-500 dark:text-zinc-500" },
      pending: { variant: "outline" as const, className: "text-zinc-600 dark:text-zinc-400" },
      started: { variant: "secondary" as const, className: "bg-blue-500 hover:bg-blue-600 text-white" },
      retry: { variant: "secondary" as const, className: "bg-yellow-500 hover:bg-yellow-600 text-white" },
      failure: { variant: "destructive" as const, className: "" },
      success: { variant: "default" as const, className: "bg-green-500 hover:bg-green-600 text-white" },
    };
    const config = variants[status];
    const labels = {
      not_started: "Not Started",
      pending: "Pending",
      started: "Started",
      retry: "Retry",
      failure: "Failure",
      success: "Success",
    };
    return (
      <Badge variant={config.variant} className={config.className}>
        {labels[status]}
      </Badge>
    );
  };

  const handleRename = (scan: DASTListItem) => {
    setSelectedScan(scan);
    setNewName(scan.title);
    setRenameDialogOpen(true);
  };

  const handleDelete = (scan: DASTListItem) => {
    setSelectedScan(scan);
    setDeleteDialogOpen(true);
  };

  const confirmRename = () => {
    if (selectedScan && newName.trim() && team_id) {
      renameDASTScanMutation.mutate({ team_id: parseInt(team_id), scan_id: selectedScan.id, title: newName.trim() });
      setRenameDialogOpen(false);
      setSelectedScan(null);
      setNewName("");
    }
  };

  const confirmDelete = () => {
    if (selectedScan && team_id) {
      deleteDASTScanMutation.mutate({ team_id: parseInt(team_id), scan_id: selectedScan.id });
      setDeleteDialogOpen(false);
      setSelectedScan(null);
    }
  };

  const confirmCreate = () => {
    if (newScanTitle.trim() && team_id) {
      if (!createGuard.tryStart()) return;
      createDASTScanMutation.mutate({ team_id: parseInt(team_id), title: newScanTitle.trim() }, { onSettled: () => createGuard.done() });
    }
  };

  const hasActiveFilters =
    searchQuery !== "" || statusFilter !== "all" || riskScoreFilter !== "all" || sortBy !== "none";

  const filteredScans = scans
    .filter((c) => {
      if (searchQuery && !c.title.toLowerCase().includes(searchQuery.toLowerCase())) return false;
      if (statusFilter !== "all" && c.scan_status !== statusFilter) return false;
      const score = getDisplayRiskScore(c);
      if (!matchesRiskScoreFilter(score, riskScoreFilter)) return false;
      return true;
    })
    .sort((a, b) => {
      if (sortBy === "created_asc") return new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
      if (sortBy === "created_desc") return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
      const scoreA = getDisplayRiskScore(a) ?? -1;
      const scoreB = getDisplayRiskScore(b) ?? -1;
      if (sortBy === "risk_desc") return scoreB - scoreA;
      if (sortBy === "risk_asc") return scoreA - scoreB;
      const credA = a.estimated_credits != null ? Number(a.estimated_credits) : -1;
      const credB = b.estimated_credits != null ? Number(b.estimated_credits) : -1;
      if (sortBy === "credits_desc") return credB - credA;
      if (sortBy === "credits_asc") return credA - credB;
      return 0;
    });

  const clearFilters = () => {
    setSearchQuery("");
    setStatusFilter("all");
    setRiskScoreFilter("all");
    setSortBy("none");
  };

  const dashboardData = query.data?.dashboard_data;

  return (
    <div className="flex h-screen bg-white dark:bg-zinc-900">
      <div className="flex-1 p-8 overflow-auto">
        <div className="max-w-7xl mx-auto">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h1 className="text-3xl font-bold text-zinc-900 dark:text-white mb-2">DAST Scans</h1>
              <p className="text-zinc-600 dark:text-zinc-400">Manage and view all your DAST scans.</p>
            </div>
            <div className="flex flex-row items-center gap-2">
              <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => setCreateDialogOpen(true)}>
                <Plus className="h-4 w-4 mr-2" />
                New Scan
              </Button>
              <Button
                className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
                onClick={() => query.refetch()}
              >
                <RefreshCcw className="h-4 w-4 mr-2" />
                Refresh
              </Button>
            </div>
          </div>

          {query.isLoading ? (
            <div className="flex h-64 items-center justify-center">
              <Loader2 className="size-10 animate-spin text-blue-600" />
            </div>
          ) : query.isError ? (
            <div className="text-center py-12">
              <p className="text-zinc-600 dark:text-zinc-400 mb-4">Error fetching DAST scans. Please try again later.</p>
            </div>
          ) : (
            <Tabs defaultValue="dashboard" className="w-full">
              <TabsList className="mb-4 bg-transparent">
                <TabsTrigger value="dashboard" className="cursor-pointer data-[state=active]:bg-blue-600 data-[state=active]:text-white">
                  Dashboard
                </TabsTrigger>
                <TabsTrigger value="table" className="cursor-pointer data-[state=active]:bg-blue-600 data-[state=active]:text-white">
                  Table
                </TabsTrigger>
                <TabsTrigger value="profiles" className="cursor-pointer data-[state=active]:bg-blue-600 data-[state=active]:text-white">
                  Profiles
                </TabsTrigger>
              </TabsList>

              <TabsContent value="dashboard">
                {dashboardData ? (
                  <DASTDashboard dashboardData={dashboardData} />
                ) : (
                  <p className="text-center text-sm text-zinc-500 py-12">No dashboard data available.</p>
                )}
              </TabsContent>

              <TabsContent value="table">
                {scans.length > 0 && (
                  <div className="flex flex-wrap items-center gap-3 mb-4">
                    <div className="relative flex-1 min-w-[200px] max-w-sm">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-400" />
                      <Input
                        placeholder="Search by title..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="pl-9 h-9 cursor-text"
                      />
                    </div>
                    <Select value={statusFilter} onValueChange={setStatusFilter}>
                      <SelectTrigger className="h-9 min-w-[150px] cursor-pointer">
                        <SelectValue placeholder="Scan status" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All statuses</SelectItem>
                        <SelectItem value="not_started">Not Started</SelectItem>
                        <SelectItem value="pending">Pending</SelectItem>
                        <SelectItem value="started">Started</SelectItem>
                        <SelectItem value="retry">Retry</SelectItem>
                        <SelectItem value="success">Success</SelectItem>
                        <SelectItem value="failure">Failure</SelectItem>
                      </SelectContent>
                    </Select>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button
                          variant="outline"
                          size="sm"
                          className={`h-9 gap-1.5 cursor-pointer border-2 ${
                            riskScoreFilter === "critical"
                              ? "border-red-500 bg-red-50 text-red-700 dark:bg-red-950/30 dark:text-red-300"
                              : riskScoreFilter === "high"
                                ? "border-orange-500 bg-orange-50 text-orange-700 dark:bg-orange-950/30 dark:text-orange-300"
                                : riskScoreFilter === "medium"
                                  ? "border-amber-500 bg-amber-50 text-amber-700 dark:bg-amber-950/30 dark:text-amber-300"
                                  : riskScoreFilter === "low"
                                    ? "border-blue-500 bg-blue-50 text-blue-700 dark:bg-blue-950/30 dark:text-blue-300"
                                    : "border-zinc-200 dark:border-zinc-700"
                          }`}
                        >
                          <Filter className="h-2 w-2 shrink-0 text-zinc-400" />
                          <span className="capitalize font-normal">{RISK_SCORE_LABELS[riskScoreFilter]}</span>
                          <ChevronDown className="h-3 w-3 opacity-70 shrink-0" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="start" className="min-w-[180px]">
                        <DropdownMenuLabel className="text-xs font-normal text-zinc-500">Filter by risk score</DropdownMenuLabel>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setRiskScoreFilter("all")}>
                          {riskScoreFilter === "all" ? <Check className="h-4 w-4" /> : <span className="w-4" />}
                          All
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setRiskScoreFilter("critical")}>
                          {riskScoreFilter === "critical" ? <Check className="h-4 w-4" /> : <AlertTriangle className="h-4 w-4 text-red-500" />}
                          Critical (≥9)
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setRiskScoreFilter("high")}>
                          {riskScoreFilter === "high" ? <Check className="h-4 w-4" /> : <AlertTriangle className="h-4 w-4 text-orange-500" />}
                          High (7–9)
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setRiskScoreFilter("medium")}>
                          {riskScoreFilter === "medium" ? <Check className="h-4 w-4" /> : <Shield className="h-4 w-4 text-amber-500" />}
                          Medium (5–7)
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setRiskScoreFilter("low")}>
                          {riskScoreFilter === "low" ? <Check className="h-4 w-4" /> : <Shield className="h-4 w-4 text-blue-500" />}
                          Low (&lt;5)
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button
                          variant="outline"
                          size="sm"
                          className={`h-9 gap-1.5 cursor-pointer border-2 ${
                            sortBy !== "none" ? "border-violet-500 bg-violet-50 text-violet-700 dark:bg-violet-950/30 dark:text-violet-300" : "border-zinc-200 dark:border-zinc-700"
                          }`}
                        >
                          <ArrowUpDown className="h-2 w-2 shrink-0 text-zinc-400" />
                          <span className="capitalize font-normal">{SORT_BY_LABELS[sortBy]}</span>
                          <ChevronDown className="h-3 w-3 opacity-70 shrink-0" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="start" className="min-w-[200px]">
                        <DropdownMenuLabel className="text-xs font-normal text-zinc-500">Sort by</DropdownMenuLabel>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setSortBy("none")}>
                          {sortBy === "none" ? <Check className="h-4 w-4" /> : <span className="w-4" />}
                          Default
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setSortBy("created_desc")}>
                          Created (newest)
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setSortBy("created_asc")}>
                          Created (oldest)
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setSortBy("risk_desc")}>
                          Risk score (high first)
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setSortBy("risk_asc")}>
                          Risk score (low first)
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setSortBy("credits_desc")}>
                          Credits (high first)
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setSortBy("credits_asc")}>
                          Credits (low first)
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                    {hasActiveFilters && (
                      <Button variant="ghost" size="sm" className="h-9 text-zinc-500 hover:text-zinc-700 cursor-pointer" onClick={clearFilters}>
                        <X className="h-4 w-4 mr-1" />
                        Clear filters
                      </Button>
                    )}
                  </div>
                )}

                {scans.length === 0 ? (
                  <div className="text-center py-12">
                    <p className="text-zinc-600 dark:text-zinc-400 mb-4">No scans yet. Create your first DAST scan to get started.</p>
                    <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => setCreateDialogOpen(true)}>
                      <Plus className="h-4 w-4 mr-2" />
                      Create New Scan
                    </Button>
                  </div>
                ) : filteredScans.length === 0 ? (
                  <div className="text-center py-12">
                    <p className="text-zinc-600 dark:text-zinc-400 mb-4">No scans match your filters.</p>
                    <Button variant="outline" className="cursor-pointer" onClick={clearFilters}>
                      <X className="h-4 w-4 mr-2" />
                      Clear filters
                    </Button>
                  </div>
                ) : (
                  <ScrollArea className="w-full border rounded-lg">
                    <div className="min-w-max">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead className="w-[160px] min-w-[120px]">Title</TableHead>
                            <TableHead>Created at</TableHead>
                            <TableHead>Last updated</TableHead>
                            <TableHead>Scan status</TableHead>
                            <TableHead className="w-[180px]">Vulnerabilities</TableHead>
                            <TableHead className="w-[90px]">Risk score</TableHead>
                            <TableHead className="w-[140px]">Target URL</TableHead>
                            <TableHead className="w-[90px]">URLs scanned</TableHead>
                            <TableHead className="w-[90px]">Coverage %</TableHead>
                            <TableHead className="w-[80px]">Credits</TableHead>
                            <TableHead>Owner</TableHead>
                            <TableHead className="text-right w-[80px]">Actions</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {filteredScans.map((scan) => (
                            <TableRow
                              key={scan.id}
                              className="hover:bg-zinc-50 dark:hover:bg-zinc-800 cursor-pointer"
                              onClick={(e) => {
                                const target = e.target as HTMLElement;
                                if (target.closest("button") || target.closest("[role='menuitem']")) return;
                                const dest =
                                  (scan.scan_status?.toLowerCase() ?? "") === "success"
                                    ? `/${team_id}/dast/${scan.id}/results`
                                    : `/${team_id}/dast/${scan.id}`;
                                router.push(dest);
                              }}
                            >
                              <TableCell className="font-medium max-w-[160px] min-w-[120px]">
                                <Link
                                  href={
                                    (scan.scan_status?.toLowerCase() ?? "") === "success"
                                      ? `/${team_id}/dast/${scan.id}/results`
                                      : `/${team_id}/dast/${scan.id}`
                                  }
                                  className="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 hover:underline cursor-pointer truncate block"
                                  title={scan.title}
                                >
                                  {scan.title}
                                </Link>
                              </TableCell>
                              <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm">{formatDate(scan.created_at)}</TableCell>
                              <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm">{formatDate(scan.last_updated)}</TableCell>
                              <TableCell className="text-sm">
                                <div className="flex flex-col gap-1.5">
                                  {getStatusBadge(scan.scan_status as ScanStatus)}
                                  {scan.info?.current != null && scan.scan_status !== "success" && scan.scan_status !== "failure" && (
                                    <div className="flex items-center gap-2">
                                      <Progress value={scan.info.current} className="h-1.5 flex-1" />
                                      <span className="text-xs text-zinc-500 tabular-nums">{scan.info.current}%</span>
                                    </div>
                                  )}
                                </div>
                              </TableCell>
                              <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm">
                                {scan.risk_data ? (
                                  <div className="flex items-center gap-2 flex-wrap">
                                    {[
                                      { label: "Critical", n: scan.risk_data.total_critical, dot: "bg-red-500" },
                                      { label: "High", n: scan.risk_data.total_high, dot: "bg-orange-500" },
                                      { label: "Medium", n: scan.risk_data.total_medium, dot: "bg-amber-500" },
                                      { label: "Low", n: scan.risk_data.total_low, dot: "bg-blue-500" },
                                    ].map(({ label, n, dot }) => (
                                      <span key={label} className="flex items-center gap-1.5 shrink-0" title={label}>
                                        <span className={`h-2 w-2 rounded-full shrink-0 ${dot}`} aria-hidden />
                                        <span className="tabular-nums">{typeof n === "number" ? n : 0}</span>
                                      </span>
                                    ))}
                                  </div>
                                ) : "—"}
                              </TableCell>
                              <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm tabular-nums">
                                {getDisplayRiskScore(scan) != null ? getDisplayRiskScore(scan) : "—"}
                              </TableCell>
                              <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm max-w-[140px] truncate" title={scan.target_url ?? undefined}>
                                {scan.target_url ?? "—"}
                              </TableCell>
                              <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm tabular-nums">{scan.urls_scanned ?? "—"}</TableCell>
                              <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm tabular-nums">
                                {scan.coverage_percentage != null ? `${Number(scan.coverage_percentage).toFixed(1)}%` : "—"}
                              </TableCell>
                              <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm tabular-nums">
                                {scan.estimated_credits != null ? scan.estimated_credits : "—"}
                              </TableCell>
                              <TableCell className="text-zinc-600 dark:text-zinc-400">
                                {scan.owner_user_full_name != null && scan.owner_user_full_name !== "" || scan.owner_user_email ? (
                                  <div className="flex items-center gap-2">
                                    <Avatar className="h-8 w-8 shrink-0">
                                      <AvatarFallback className="bg-blue-600 text-white text-xs font-medium">
                                        {scan.owner_user_full_name
                                          ? scan.owner_user_full_name
                                              .trim()
                                              .split(/\s+/)
                                              .map((p) => p.charAt(0))
                                              .slice(0, 2)
                                              .join("")
                                              .toUpperCase() || (scan.owner_user_email?.[0] ?? "?").toUpperCase()
                                          : (scan.owner_user_email?.[0] ?? "?").toUpperCase()}
                                      </AvatarFallback>
                                    </Avatar>
                                    <div className="min-w-0">
                                      {scan.owner_user_full_name != null && scan.owner_user_full_name !== "" && (
                                        <span className="block truncate max-w-[160px]" title={scan.owner_user_email ?? ""}>
                                          {scan.owner_user_full_name}
                                        </span>
                                      )}
                                      {scan.owner_user_email != null && scan.owner_user_email !== "" && (
                                        <span className="block text-xs text-zinc-500 dark:text-zinc-400 truncate max-w-[160px]">
                                          {scan.owner_user_email}
                                        </span>
                                      )}
                                    </div>
                                  </div>
                                ) : (
                                  "—"
                                )}
                              </TableCell>
                              <TableCell className="text-right">
                                <DropdownMenu>
                                  <DropdownMenuTrigger asChild>
                                    <Button variant="ghost" size="icon" className="h-8 w-8 cursor-pointer" onClick={(e) => e.stopPropagation()}>
                                      <MoreVertical className="h-4 w-4" />
                                    </Button>
                                  </DropdownMenuTrigger>
                                  <DropdownMenuContent align="end" onClick={(e) => e.stopPropagation()}>
                                    {(scan.scan_status?.toLowerCase() ?? "") === "success" && (
                                      <DropdownMenuItem
                                        className="cursor-pointer"
                                        onClick={() => router.push(`/${team_id}/dast/${scan.id}/results?origin=list`)}
                                      >
                                        <Eye className="h-4 w-4 mr-2" />
                                        View Results
                                      </DropdownMenuItem>
                                    )}
                                    <DropdownMenuItem className="cursor-pointer" onClick={() => handleRename(scan)}>
                                      <Pencil className="h-4 w-4 mr-2" />
                                      Rename
                                    </DropdownMenuItem>
                                    <DropdownMenuItem className="cursor-pointer" onClick={() => handleDelete(scan)} variant="destructive">
                                      <Trash2 className="h-4 w-4 mr-2" />
                                      Delete
                                    </DropdownMenuItem>
                                  </DropdownMenuContent>
                                </DropdownMenu>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </div>
                    <ScrollBar orientation="horizontal" />
                  </ScrollArea>
                )}
              </TabsContent>

              <TabsContent value="profiles">
                <DastProfilesTab />
              </TabsContent>
            </Tabs>
          )}

          <Dialog open={renameDialogOpen} onOpenChange={setRenameDialogOpen}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Rename Scan</DialogTitle>
                <DialogDescription>Enter a new name for this scan.</DialogDescription>
              </DialogHeader>
              <div className="py-4">
                <Input
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  placeholder="Scan name"
                  onKeyDown={(e) => e.key === "Enter" && confirmRename()}
                />
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => { setRenameDialogOpen(false); setNewName(""); }} className="cursor-pointer">
                  Cancel
                </Button>
                <Button onClick={confirmRename} disabled={!newName.trim()} className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer">
                  Save
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          <Dialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Delete Scan</DialogTitle>
                <DialogDescription>Are you sure you want to delete &quot;{selectedScan?.title}&quot;? This action cannot be undone.</DialogDescription>
              </DialogHeader>
              <DialogFooter>
                <Button variant="outline" onClick={() => { setDeleteDialogOpen(false); setSelectedScan(null); }} className="cursor-pointer">
                  Cancel
                </Button>
                <Button variant="destructive" onClick={confirmDelete} className="cursor-pointer">
                  Delete
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Create New Scan</DialogTitle>
                <DialogDescription>Enter a title for your new DAST scan.</DialogDescription>
              </DialogHeader>
              <div className="py-4">
                <Input
                  value={newScanTitle}
                  onChange={(e) => setNewScanTitle(e.target.value)}
                  placeholder="Scan title"
                  onKeyDown={(e) => e.key === "Enter" && confirmCreate()}
                />
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => { setCreateDialogOpen(false); setNewScanTitle(""); }} className="cursor-pointer">
                  Cancel
                </Button>
                <Button
                  onClick={confirmCreate}
                  disabled={!newScanTitle.trim() || createDASTScanMutation.isPending}
                  className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
                >
                  {createDASTScanMutation.isPending ? "Creating..." : "Create"}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      </div>
    </div>
  );
}

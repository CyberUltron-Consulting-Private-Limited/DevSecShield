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
import {
  Plus,
  MoreVertical,
  Pencil,
  Trash2,
  RefreshCcw,
  Loader2,
  Eye,
  Search,
  X,
  Shield,
  AlertTriangle,
  Check,
  Filter,
  ChevronDown,
  ArrowUpDown,
  DollarSign,
  TrendingUp,
  TrendingDown,
  Smartphone,
  Activity,
  Target,
  AlertCircle,
  CalendarPlus,
  CalendarCheck,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import {
  createMobileScan,
  deleteMobileScan,
  getMobileScans,
  renameMobileScan,
  type MobileConversation,
  type MobileListDashboardData,
} from "@/utils/backend_api";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { showErrorToast } from "@/utils/error-handler";
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

function getDisplayRiskScore(c: MobileConversation): number | null {
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

function getScanProgress(info: MobileConversation["info"]): number | null {
  if (info != null && typeof info === "object" && typeof (info as { current?: number }).current === "number") {
    return (info as { current?: number }).current ?? null;
  }
  return null;
}

function MobileScanListDashboard({ dashboardData }: { dashboardData: MobileListDashboardData }) {
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

  const categoryBarData = useMemo(() => {
    return Object.entries(dashboardData.category_distribution ?? {})
      .map(([name, count]) => ({
        name: name.replace(/_/g, " "),
        count: typeof count === "number" ? count : 0,
      }))
      .filter((d) => d.count > 0)
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
  }, [dashboardData.category_distribution]);

  const severityRadarData = useMemo(
    () => [
      { severity: "Critical", count: dashboardData.severity_distribution?.critical ?? 0 },
      { severity: "High", count: dashboardData.severity_distribution?.high ?? 0 },
      { severity: "Medium", count: dashboardData.severity_distribution?.medium ?? 0 },
      { severity: "Low", count: dashboardData.severity_distribution?.low ?? 0 },
    ],
    [dashboardData.severity_distribution]
  );

  const barConfig = { count: { label: "Findings", color: "hsl(220 70% 50%)" } } satisfies ChartConfig;
  const radarConfig = { count: { label: "Findings", color: "hsl(220 70% 50%)" } } satisfies ChartConfig;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-7 gap-4">
        <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
          <CardContent className="p-0">
            <div className="flex flex-col items-start gap-2">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-blue-500/15 dark:bg-blue-500/10">
                <Smartphone className="h-4 w-4 text-blue-500" />
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
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-violet-500/15 dark:bg-violet-500/10">
                <Target className="h-4 w-4 text-violet-500" />
              </div>
              <div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Findings</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_findings}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
          <CardContent className="p-0">
            <div className="flex flex-col items-start gap-2">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-red-500/15 dark:bg-red-500/10">
                <AlertCircle className="h-4 w-4 text-red-500" />
              </div>
              <div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Critical</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_critical}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
          <CardContent className="p-0">
            <div className="flex flex-col items-start gap-2">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-orange-500/15 dark:bg-orange-500/10">
                <AlertTriangle className="h-4 w-4 text-orange-500" />
              </div>
              <div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">High</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_high}</p>
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
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Medium</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_medium}</p>
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
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Low</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_low}</p>
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
                    card.average_risk_score >= 7
                      ? "text-red-500"
                      : card.average_risk_score >= 5
                        ? "text-amber-500"
                        : "text-green-500"
                  }`}
                />
              </div>
              <div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Avg risk score</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">
                  {Number(card.average_risk_score ?? 0).toFixed(1)}
                </p>
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
          <CardHeader className="items-center pb-2">
            <CardTitle className="text-base">Severity Radar</CardTitle>
            <CardDescription>Finding counts by severity</CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer config={radarConfig} className="mx-auto aspect-square max-h-[280px]">
              <RadarChart data={severityRadarData}>
                <ChartTooltip cursor={false} content={<ChartTooltipContent />} />
                <PolarAngleAxis dataKey="severity" />
                <PolarGrid />
                <Radar dataKey="count" fill="var(--color-count)" fillOpacity={0.6} dot={{ r: 4, fillOpacity: 1 }} />
              </RadarChart>
            </ChartContainer>
          </CardContent>
        </Card>

        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Categories</CardTitle>
            <CardDescription>Top finding categories</CardDescription>
          </CardHeader>
          <CardContent>
            {categoryBarData.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No category data yet</p>
            ) : (
              <ChartContainer config={barConfig} className="aspect-auto h-[280px] w-full">
                <BarChart data={categoryBarData} layout="vertical" margin={{ left: 12, right: 12 }}>
                  <CartesianGrid horizontal={false} />
                  <XAxis type="number" tickLine={false} axisLine={false} allowDecimals={false} />
                  <YAxis
                    type="category"
                    dataKey="name"
                    tickLine={false}
                    axisLine={false}
                    width={100}
                    tickFormatter={(v) => (String(v).length > 14 ? `${String(v).slice(0, 14)}…` : String(v))}
                  />
                  <ChartTooltip cursor={false} content={<ChartTooltipContent />} />
                  <Bar dataKey="count" fill="var(--color-count)" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>

        <Card className="border-zinc-200 dark:border-zinc-800 flex flex-col lg:col-span-3">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Top Mobile Risks</CardTitle>
            <CardDescription>Highest impact findings across scans</CardDescription>
          </CardHeader>
          <CardContent className="flex-1 min-h-0">
            {!dashboardData.top_risks || dashboardData.top_risks.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No risk data yet</p>
            ) : (
              <ScrollArea className="h-[280px] w-full">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Title</TableHead>
                      <TableHead>Category</TableHead>
                      <TableHead>Impact</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {dashboardData.top_risks.slice(0, 10).map((risk, i) => (
                      <TableRow key={i} className="hover:bg-zinc-50 dark:hover:bg-zinc-800">
                        <TableCell className="font-medium text-zinc-900 dark:text-white max-w-[320px] truncate" title={risk.title}>
                          {risk.title || "Unknown"}
                        </TableCell>
                        <TableCell className="text-zinc-600 dark:text-zinc-400">
                          {(risk.category || "general").replace(/_/g, " ")}
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant="outline"
                            className={
                              (risk.impact || "").toLowerCase() === "critical"
                                ? "border-red-500/50 text-red-600 dark:text-red-400"
                                : (risk.impact || "").toLowerCase() === "high"
                                  ? "border-orange-500/50 text-orange-600 dark:text-orange-400"
                                  : (risk.impact || "").toLowerCase() === "medium"
                                    ? "border-amber-500/50 text-amber-600 dark:text-amber-400"
                                    : "border-blue-500/50 text-blue-600 dark:text-blue-400"
                            }
                          >
                            {risk.impact || "Low"}
                          </Badge>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                <ScrollBar orientation="vertical" />
              </ScrollArea>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

export default function MobileScansPage() {
  const router = useRouter();
  const params = useParams();
  const team_id = params?.team_id as string;
  const [conversations, setConversations] = useState<MobileConversation[]>([]);
  const [renameDialogOpen, setRenameDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [selectedConversation, setSelectedConversation] = useState<MobileConversation | null>(null);
  const [newName, setNewName] = useState("");
  const [newScanTitle, setNewScanTitle] = useState("Mobile App Security Scan");
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [riskScoreFilter, setRiskScoreFilter] = useState<RiskScoreFilter>("all");
  const [sortBy, setSortBy] = useState<TableSortBy>("none");
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ["mobile-scans", team_id],
    queryFn: () => getMobileScans(parseInt(team_id, 10)),
    enabled: !!team_id,
  });

  useEffect(() => {
    setConversations([]);
  }, [team_id]);

  useEffect(() => {
    if (query.data) {
      setConversations(query.data.scans_list_data ?? []);
    }
    if (query.error) {
      showErrorToast(query.error, "Error fetching Mobile App Security scans");
    }
  }, [query.data, query.error]);

  const deleteMutation = useMutation({
    mutationFn: ({ teamId, scanId }: { teamId: number; scanId: number }) =>
      deleteMobileScan(teamId, scanId),
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ["mobile-scans", variables.teamId.toString()] });
      toast.success("Mobile scan deleted successfully");
    },
    onError: (error) => showErrorToast(error),
  });

  const renameMutation = useMutation({
    mutationFn: renameMobileScan,
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ["mobile-scans", variables.team_id.toString()] });
      toast.success("Mobile scan renamed successfully");
    },
    onError: (error) => showErrorToast(error),
  });

  const createMutation = useMutation({
    mutationFn: ({ teamId, title }: { teamId: number; title: string }) =>
      createMobileScan(teamId, title),
    onSuccess: (scanId, variables) => {
      queryClient.invalidateQueries({ queryKey: ["mobile-scans", variables.teamId.toString()] });
      setCreateDialogOpen(false);
      setNewScanTitle("Mobile App Security Scan");
      router.push(`/${variables.teamId}/mobile/${scanId}`);
    },
    onError: (error) => showErrorToast(error),
  });

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  const getStatusBadge = (status: ScanStatus) => {
    const variants = {
      not_started: { variant: "outline" as const, className: "text-zinc-500 dark:text-zinc-500" },
      pending: { variant: "outline" as const, className: "text-zinc-600 dark:text-zinc-400" },
      started: { variant: "secondary" as const, className: "bg-blue-500 hover:bg-blue-600 text-white" },
      retry: { variant: "secondary" as const, className: "bg-yellow-500 hover:bg-yellow-600 text-white" },
      failure: { variant: "destructive" as const, className: "" },
      success: { variant: "default" as const, className: "bg-green-500 hover:bg-green-600 text-white" },
    };
    const config = variants[status] ?? variants.pending;
    const labels: Record<string, string> = {
      not_started: "Not Started",
      pending: "Pending",
      started: "Started",
      retry: "Retry",
      failure: "Failure",
      success: "Success",
    };
    return (
      <Badge variant={config.variant} className={config.className}>
        {labels[status] ?? status}
      </Badge>
    );
  };

  const handleRename = (conversation: MobileConversation) => {
    setSelectedConversation(conversation);
    setNewName(conversation.title);
    setRenameDialogOpen(true);
  };

  const handleDelete = (conversation: MobileConversation) => {
    setSelectedConversation(conversation);
    setDeleteDialogOpen(true);
  };

  const confirmRename = () => {
    if (selectedConversation && newName.trim() && team_id) {
      renameMutation.mutate({
        team_id: parseInt(team_id, 10),
        scan_id: selectedConversation.id,
        title: newName.trim(),
      });
      setRenameDialogOpen(false);
      setSelectedConversation(null);
      setNewName("");
    }
  };

  const confirmDelete = () => {
    if (selectedConversation && team_id) {
      deleteMutation.mutate({
        teamId: parseInt(team_id, 10),
        scanId: selectedConversation.id,
      });
      setDeleteDialogOpen(false);
      setSelectedConversation(null);
    }
  };

  const confirmCreate = () => {
    if (newScanTitle.trim() && team_id) {
      createMutation.mutate({
        teamId: parseInt(team_id, 10),
        title: newScanTitle.trim(),
      });
    }
  };

  const hasActiveFilters =
    searchQuery !== "" || statusFilter !== "all" || riskScoreFilter !== "all" || sortBy !== "none";

  const filteredConversations = conversations
    .filter((c) => {
      const q = searchQuery.toLowerCase();
      if (
        q &&
        !c.title.toLowerCase().includes(q) &&
        !(c.app_name || "").toLowerCase().includes(q) &&
        !(c.file_name || "").toLowerCase().includes(q) &&
        !(c.package_name || "").toLowerCase().includes(q)
      ) {
        return false;
      }
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

  const scanHref = (scan: MobileConversation) =>
    (scan.scan_status?.toLowerCase() ?? "") === "success"
      ? `/${team_id}/mobile/${scan.id}/results`
      : `/${team_id}/mobile/${scan.id}`;

  return (
    <div className="flex h-screen bg-white dark:bg-zinc-900">
      <div className="flex-1 p-8 overflow-auto">
        <div className="max-w-7xl mx-auto">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h1 className="text-3xl font-bold text-zinc-900 dark:text-white mb-2">Mobile App Security</h1>
              <p className="text-zinc-600 dark:text-zinc-400">
                Static analysis for Android and iOS app binaries (APK / IPA).
              </p>
            </div>
            <div className="flex flex-row items-center gap-2">
              <Button
                className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
                onClick={() => setCreateDialogOpen(true)}
              >
                <Plus className="h-4 w-4 mr-2" />
                New Scan
              </Button>
              <Button
                className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
                onClick={() => queryClient.invalidateQueries({ queryKey: ["mobile-scans", team_id] })}
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
              <p className="text-zinc-600 dark:text-zinc-400 mb-4">
                Error in fetching scans, please try again later
              </p>
            </div>
          ) : (
            <Tabs defaultValue="dashboard" className="w-full">
              <TabsList className="mb-4 bg-transparent">
                <TabsTrigger
                  value="dashboard"
                  className="cursor-pointer data-[state=active]:bg-blue-600 data-[state=active]:text-white"
                >
                  Dashboard
                </TabsTrigger>
                <TabsTrigger
                  value="table"
                  className="cursor-pointer data-[state=active]:bg-blue-600 data-[state=active]:text-white"
                >
                  Table
                </TabsTrigger>
              </TabsList>

              <TabsContent value="dashboard">
                {dashboardData ? (
                  <MobileScanListDashboard dashboardData={dashboardData} />
                ) : (
                  <p className="text-center text-sm text-zinc-500 py-12">No dashboard data available.</p>
                )}
              </TabsContent>

              <TabsContent value="table">
                {conversations.length > 0 && (
                  <div className="flex flex-wrap items-center gap-3 mb-4">
                    <div className="relative flex-1 min-w-[200px] max-w-sm">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-400" />
                      <Input
                        placeholder="Search by title, app, or file..."
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
                              ? "border-red-500 bg-red-50 text-red-700 hover:bg-red-100 dark:bg-red-950/30 dark:text-red-300 dark:hover:bg-red-950/50"
                              : riskScoreFilter === "high"
                                ? "border-orange-500 bg-orange-50 text-orange-700 hover:bg-orange-100 dark:bg-orange-950/30 dark:text-orange-300 dark:hover:bg-orange-950/50"
                                : riskScoreFilter === "medium"
                                  ? "border-amber-500 bg-amber-50 text-amber-700 hover:bg-amber-100 dark:bg-amber-950/30 dark:text-amber-300 dark:hover:bg-amber-950/50"
                                  : riskScoreFilter === "low"
                                    ? "border-blue-500 bg-blue-50 text-blue-700 hover:bg-blue-100 dark:bg-blue-950/30 dark:text-blue-300 dark:hover:bg-blue-950/50"
                                    : "border-zinc-200 dark:border-zinc-700"
                          }`}
                        >
                          <Filter className="h-2 w-2 shrink-0 text-zinc-400" />
                          <span className="capitalize font-normal">{RISK_SCORE_LABELS[riskScoreFilter]}</span>
                          <ChevronDown className="h-3 w-3 opacity-70 shrink-0" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="start" className="min-w-[180px]">
                        <DropdownMenuLabel className="text-xs font-normal text-zinc-500">
                          Filter by risk score
                        </DropdownMenuLabel>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setRiskScoreFilter("all")}>
                          {riskScoreFilter === "all" ? <Check className="h-4 w-4" /> : <span className="w-4" />}
                          All
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          className="cursor-pointer gap-2"
                          onClick={() => setRiskScoreFilter("critical")}
                        >
                          {riskScoreFilter === "critical" ? (
                            <Check className="h-4 w-4" />
                          ) : (
                            <AlertTriangle className="h-4 w-4 text-red-500" />
                          )}
                          Critical (≥9)
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setRiskScoreFilter("high")}>
                          {riskScoreFilter === "high" ? (
                            <Check className="h-4 w-4" />
                          ) : (
                            <AlertTriangle className="h-4 w-4 text-orange-500" />
                          )}
                          High (7–9)
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          className="cursor-pointer gap-2"
                          onClick={() => setRiskScoreFilter("medium")}
                        >
                          {riskScoreFilter === "medium" ? (
                            <Check className="h-4 w-4" />
                          ) : (
                            <Shield className="h-4 w-4 text-amber-500" />
                          )}
                          Medium (5–7)
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setRiskScoreFilter("low")}>
                          {riskScoreFilter === "low" ? (
                            <Check className="h-4 w-4" />
                          ) : (
                            <Shield className="h-4 w-4 text-blue-500" />
                          )}
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
                            sortBy !== "none"
                              ? "border-violet-500 bg-violet-50 text-violet-700 hover:bg-violet-100 dark:bg-violet-950/30 dark:text-violet-300 dark:hover:bg-violet-950/50"
                              : "border-zinc-200 dark:border-zinc-700"
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
                          {sortBy === "created_desc" ? <Check className="h-4 w-4" /> : <CalendarPlus className="h-4 w-4" />}
                          Created (newest)
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setSortBy("created_asc")}>
                          {sortBy === "created_asc" ? <Check className="h-4 w-4" /> : <CalendarCheck className="h-4 w-4" />}
                          Created (oldest)
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setSortBy("risk_desc")}>
                          {sortBy === "risk_desc" ? <Check className="h-4 w-4" /> : <TrendingDown className="h-4 w-4" />}
                          Risk score (high first)
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setSortBy("risk_asc")}>
                          {sortBy === "risk_asc" ? <Check className="h-4 w-4" /> : <TrendingUp className="h-4 w-4" />}
                          Risk score (low first)
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setSortBy("credits_desc")}>
                          {sortBy === "credits_desc" ? <Check className="h-4 w-4" /> : <DollarSign className="h-4 w-4" />}
                          Credits (high first)
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setSortBy("credits_asc")}>
                          {sortBy === "credits_asc" ? <Check className="h-4 w-4" /> : <DollarSign className="h-4 w-4" />}
                          Credits (low first)
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>

                    {hasActiveFilters && (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-9 text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300 cursor-pointer"
                        onClick={clearFilters}
                      >
                        <X className="h-4 w-4 mr-1" />
                        Clear filters
                      </Button>
                    )}
                  </div>
                )}

                {conversations.length === 0 ? (
                  <div className="text-center py-12">
                    <p className="text-zinc-600 dark:text-zinc-400 mb-4">
                      No scans yet. Create your first Mobile App Security scan to get started.
                    </p>
                    <Button
                      className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
                      onClick={() => setCreateDialogOpen(true)}
                    >
                      <Plus className="h-4 w-4 mr-2" />
                      Create New Scan
                    </Button>
                  </div>
                ) : filteredConversations.length === 0 ? (
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
                            <TableHead className="w-[180px] min-w-[140px]">Title</TableHead>
                            <TableHead>Created at</TableHead>
                            <TableHead>Last updated</TableHead>
                            <TableHead>Scan status</TableHead>
                            <TableHead className="w-[200px]">Risks</TableHead>
                            <TableHead className="w-[90px]">Risk score</TableHead>
                            <TableHead className="w-[180px]">App / File</TableHead>
                            <TableHead className="w-[90px]">Credits</TableHead>
                            <TableHead>Owner</TableHead>
                            <TableHead className="text-right w-[80px]">Actions</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {filteredConversations.map((conversation) => {
                            const progress = getScanProgress(conversation.info);
                            return (
                              <TableRow
                                key={conversation.id}
                                className="hover:bg-zinc-50 dark:hover:bg-zinc-800 cursor-pointer"
                                onClick={(e) => {
                                  const target = e.target as HTMLElement;
                                  if (target.closest("button") || target.closest("[role='menuitem']")) return;
                                  router.push(scanHref(conversation));
                                }}
                              >
                                <TableCell className="font-medium max-w-[180px] min-w-[140px]">
                                  <Link
                                    href={scanHref(conversation)}
                                    className="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 hover:underline cursor-pointer truncate block"
                                    title={conversation.title}
                                  >
                                    {conversation.title}
                                  </Link>
                                </TableCell>
                                <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm">
                                  {formatDate(conversation.created_at)}
                                </TableCell>
                                <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm">
                                  {formatDate(conversation.last_updated)}
                                </TableCell>
                                <TableCell className="text-sm">
                                  <div className="flex flex-col gap-1.5">
                                    {getStatusBadge(conversation.scan_status as ScanStatus)}
                                    {progress != null &&
                                      conversation.scan_status !== "success" &&
                                      conversation.scan_status !== "failure" && (
                                        <div className="flex items-center gap-2">
                                          <Progress value={progress} className="h-1.5 flex-1" />
                                          <span className="text-xs text-zinc-500 tabular-nums">{progress}%</span>
                                        </div>
                                      )}
                                  </div>
                                </TableCell>
                                <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm">
                                  {conversation.risk_data ? (
                                    <div className="flex items-center gap-2 flex-wrap">
                                      {[
                                        {
                                          label: "Critical",
                                          n: conversation.risk_data.total_critical,
                                          dot: "bg-red-500",
                                        },
                                        {
                                          label: "High",
                                          n: conversation.risk_data.total_high,
                                          dot: "bg-orange-500",
                                        },
                                        {
                                          label: "Medium",
                                          n: conversation.risk_data.total_medium,
                                          dot: "bg-amber-500",
                                        },
                                        {
                                          label: "Low",
                                          n: conversation.risk_data.total_low,
                                          dot: "bg-blue-500",
                                        },
                                      ].map(({ label, n, dot }) => (
                                        <span key={label} className="flex items-center gap-1.5 shrink-0" title={label}>
                                          <span className={`h-2 w-2 rounded-full shrink-0 ${dot}`} aria-hidden />
                                          <span className="tabular-nums">{typeof n === "number" ? n : 0}</span>
                                        </span>
                                      ))}
                                    </div>
                                  ) : (
                                    "—"
                                  )}
                                </TableCell>
                                <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm tabular-nums">
                                  {getDisplayRiskScore(conversation) != null
                                    ? getDisplayRiskScore(conversation)
                                    : "—"}
                                </TableCell>
                                <TableCell
                                  className="text-zinc-600 dark:text-zinc-400 text-sm max-w-[180px]"
                                  title={conversation.package_name ?? conversation.file_name ?? undefined}
                                >
                                  <span className="flex items-center gap-1.5 truncate">
                                    <Smartphone className="h-3.5 w-3.5 shrink-0 text-blue-500" aria-hidden />
                                    <span className="truncate">
                                      {conversation.app_name || conversation.file_name || "—"}
                                    </span>
                                  </span>
                                </TableCell>
                                <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm tabular-nums">
                                  {conversation.estimated_credits != null
                                    ? conversation.estimated_credits
                                    : "—"}
                                </TableCell>
                                <TableCell className="text-zinc-600 dark:text-zinc-400">
                                  {(conversation.owner_user_full_name != null &&
                                    conversation.owner_user_full_name !== "") ||
                                  conversation.owner_user_email ? (
                                    <div className="flex items-center gap-2">
                                      <Avatar className="h-8 w-8 shrink-0">
                                        <AvatarFallback className="bg-blue-600 text-white text-xs font-medium">
                                          {conversation.owner_user_full_name
                                            ? conversation.owner_user_full_name
                                                .trim()
                                                .split(/\s+/)
                                                .map((p) => p.charAt(0))
                                                .slice(0, 2)
                                                .join("")
                                                .toUpperCase() ||
                                              (conversation.owner_user_email?.[0] ?? "?").toUpperCase()
                                            : (conversation.owner_user_email?.[0] ?? "?").toUpperCase()}
                                        </AvatarFallback>
                                      </Avatar>
                                      <div className="min-w-0">
                                        {conversation.owner_user_full_name != null &&
                                          conversation.owner_user_full_name !== "" && (
                                            <span
                                              className="block truncate max-w-[160px]"
                                              title={conversation.owner_user_email ?? ""}
                                            >
                                              {conversation.owner_user_full_name}
                                            </span>
                                          )}
                                        {conversation.owner_user_email != null &&
                                          conversation.owner_user_email !== "" && (
                                            <span className="block text-xs text-zinc-500 dark:text-zinc-400 truncate max-w-[160px]">
                                              {conversation.owner_user_email}
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
                                      <Button variant="ghost" size="icon" className="h-8 w-8 cursor-pointer">
                                        <MoreVertical className="h-4 w-4" />
                                      </Button>
                                    </DropdownMenuTrigger>
                                    <DropdownMenuContent align="end">
                                      {(conversation.scan_status?.toLowerCase() ?? "") === "success" && (
                                        <DropdownMenuItem
                                          className="cursor-pointer"
                                          onClick={() =>
                                            router.push(`/${team_id}/mobile/${conversation.id}/results`)
                                          }
                                        >
                                          <Eye className="h-4 w-4 mr-2" />
                                          View Results
                                        </DropdownMenuItem>
                                      )}
                                      <DropdownMenuItem
                                        className="cursor-pointer"
                                        onClick={() => handleRename(conversation)}
                                      >
                                        <Pencil className="h-4 w-4 mr-2" />
                                        Rename
                                      </DropdownMenuItem>
                                      <DropdownMenuItem
                                        className="cursor-pointer"
                                        onClick={() => handleDelete(conversation)}
                                        variant="destructive"
                                      >
                                        <Trash2 className="h-4 w-4 mr-2" />
                                        Delete
                                      </DropdownMenuItem>
                                    </DropdownMenuContent>
                                  </DropdownMenu>
                                </TableCell>
                              </TableRow>
                            );
                          })}
                        </TableBody>
                      </Table>
                    </div>
                    <ScrollBar orientation="horizontal" />
                  </ScrollArea>
                )}
              </TabsContent>
            </Tabs>
          )}
        </div>
      </div>

      <Dialog open={renameDialogOpen} onOpenChange={setRenameDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Rename Scan</DialogTitle>
            <DialogDescription>Enter a new name for this Mobile App Security scan.</DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <Input
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="Scan name"
              onKeyDown={(e) => {
                if (e.key === "Enter") confirmRename();
              }}
            />
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              className="cursor-pointer"
              onClick={() => {
                setRenameDialogOpen(false);
                setNewName("");
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={confirmRename}
              disabled={!newName.trim()}
              className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
            >
              Save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Scan</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete &quot;{selectedConversation?.title}&quot;? This action cannot be
              undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              className="cursor-pointer"
              onClick={() => {
                setDeleteDialogOpen(false);
                setSelectedConversation(null);
              }}
            >
              Cancel
            </Button>
            <Button variant="destructive" className="cursor-pointer" onClick={confirmDelete}>
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New Mobile App Security Scan</DialogTitle>
            <DialogDescription>Give this scan a title, then upload an APK or IPA on the next screen.</DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <Input
              value={newScanTitle}
              onChange={(e) => setNewScanTitle(e.target.value)}
              placeholder="Scan title"
              onKeyDown={(e) => {
                if (e.key === "Enter") confirmCreate();
              }}
            />
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              className="cursor-pointer"
              onClick={() => {
                setCreateDialogOpen(false);
                setNewScanTitle("Mobile App Security Scan");
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={confirmCreate}
              disabled={!newScanTitle.trim() || createMutation.isPending}
              className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
            >
              {createMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

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
  Plus, MoreVertical, Pencil, Trash2, RefreshCcw, Loader2, Eye, Clock,
  CheckCircle, CalendarPlus, CalendarCheck, Search, X, GitBranch, FileArchive,
  MinusCircle, Shield, AlertTriangle, Activity, ChevronDown, ArrowUpDown,
  Check, Filter, DollarSign, TrendingUp, TrendingDown, Lock, ShieldAlert,
  ShieldCheck, Key,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import {
  deleteCBOMScan,
  getCBOMScans,
  renameCBOMScan,
  createCBOMScan,
} from "@/utils/backend_api";
import type { CBOMConversation, CBOMDashboardData } from "@/utils/backend_api";
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

function CBOMScanListDashboard({ dashboardData }: { dashboardData: CBOMDashboardData }) {
  const card = dashboardData.card_data;
  const remediation = dashboardData.remediation_actions_required;
  const totalFindings = remediation.total_findings || 1;

  const severityRadarData = useMemo(() => [
    { severity: "Critical", count: dashboardData.severity_distribution.critical },
    { severity: "High", count: dashboardData.severity_distribution.high },
    { severity: "Medium", count: dashboardData.severity_distribution.medium },
    { severity: "Low", count: dashboardData.severity_distribution.low },
  ], [dashboardData.severity_distribution]);

  const radarConfig = { count: { label: "Findings", color: "hsl(220 70% 50%)" } } satisfies ChartConfig;

  const algorithmTypeData = useMemo(() => {
    return Object.entries(dashboardData.algorithm_type_distribution)
      .map(([name, count]) => ({ name: name.replace(/_/g, " "), count }))
      .filter((d) => d.count > 0)
      .sort((a, b) => b.count - a.count);
  }, [dashboardData.algorithm_type_distribution]);

  const barConfig = { count: { label: "Assets", color: "hsl(220 70% 50%)" } } satisfies ChartConfig;

  const strengthData = useMemo(() => {
    const COLORS: Record<string, string> = {
      weak: "hsl(0 72% 51%)",
      moderate: "hsl(45 93% 47%)",
      strong: "hsl(142 71% 45%)",
      quantum_safe: "hsl(220 70% 50%)",
    };
    return Object.entries(dashboardData.strength_distribution)
      .map(([name, count]) => ({
        name: name === "quantum_safe" ? "Quantum-Safe" : name.charAt(0).toUpperCase() + name.slice(1),
        count,
        fill: COLORS[name] ?? "hsl(220 9% 46%)",
      }))
      .filter((d) => d.count > 0);
  }, [dashboardData.strength_distribution]);

  const quantumData = useMemo(() => [
    { name: "Safe", count: dashboardData.quantum_readiness.quantum_safe, fill: "hsl(142 71% 45%)" },
    { name: "Vulnerable", count: dashboardData.quantum_readiness.quantum_vulnerable, fill: "hsl(0 72% 51%)" },
    { name: "Unknown", count: dashboardData.quantum_readiness.unknown, fill: "hsl(220 9% 46%)" },
  ].filter((d) => d.count > 0), [dashboardData.quantum_readiness]);

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-7 gap-3">
        {[
          { label: "Crypto Assets", value: card.total_crypto_assets, icon: Lock },
          { label: "Weak Algorithms", value: card.total_weak_algorithms, icon: ShieldAlert },
          { label: "Quantum Vulnerable", value: card.total_quantum_vulnerable, icon: AlertTriangle },
          { label: "Certificates", value: card.total_certificates, icon: ShieldCheck },
          { label: "Keys", value: card.total_keys, icon: Key },
          { label: "Quantum Readiness", value: `${card.quantum_readiness_score}%`, icon: Shield },
          { label: "Avg Risk Score", value: card.average_risk_score?.toFixed(1) ?? "N/A", icon: Activity },
        ].map((c) => (
          <Card key={c.label} className="bg-zinc-900 border-zinc-800">
            <CardContent className="p-4 flex flex-col gap-1">
              <div className="flex items-center gap-2">
                <c.icon className="size-4 text-zinc-400" />
                <span className="text-xs text-zinc-400">{c.label}</span>
              </div>
              <span className="text-xl font-bold text-white">{c.value}</span>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Remediation Progress */}
      <Card className="bg-zinc-900 border-zinc-800">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm text-zinc-300">Remediation Progress</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          <div className="flex items-center gap-4 text-sm text-zinc-400">
            <span>Fixed: <span className="text-green-400 font-medium">{remediation.total_fixed}</span></span>
            <span>In Progress: <span className="text-yellow-400 font-medium">{remediation.total_in_progress}</span></span>
            <span>Not Started: <span className="text-zinc-300 font-medium">{remediation.total_not_started}</span></span>
            <span>Ignored: <span className="text-zinc-500 font-medium">{remediation.total_ignored}</span></span>
          </div>
          <Progress value={(remediation.total_fixed / totalFindings) * 100} className="h-2" />
          <p className="text-xs text-zinc-500">{remediation.total_fixed}/{totalFindings} findings resolved</p>
        </CardContent>
      </Card>

      {/* Charts Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Severity Radar */}
        <Card className="bg-zinc-900 border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-zinc-300">Severity Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <ChartContainer config={radarConfig} className="mx-auto aspect-square max-h-[260px]">
              <RadarChart data={severityRadarData}>
                <PolarGrid className="fill-zinc-800/30" />
                <PolarAngleAxis dataKey="severity" className="text-xs text-zinc-500" />
                <ChartTooltip content={<ChartTooltipContent />} />
                <Radar dataKey="count" fill="hsl(220 70% 50%)" fillOpacity={0.4} stroke="hsl(220 70% 50%)" strokeWidth={2} />
              </RadarChart>
            </ChartContainer>
          </CardContent>
        </Card>

        {/* Algorithm Type Distribution */}
        <Card className="bg-zinc-900 border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-zinc-300">Algorithm Type Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <ChartContainer config={barConfig} className="mx-auto aspect-square max-h-[260px]">
              <BarChart data={algorithmTypeData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" className="stroke-zinc-800" />
                <XAxis type="number" className="text-xs text-zinc-500" />
                <YAxis dataKey="name" type="category" className="text-xs text-zinc-500" width={120} />
                <ChartTooltip content={<ChartTooltipContent />} />
                <Bar dataKey="count" fill="hsl(220 70% 50%)" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ChartContainer>
          </CardContent>
        </Card>

        {/* Strength Distribution */}
        <Card className="bg-zinc-900 border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-zinc-300">Crypto Strength Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <ChartContainer config={barConfig} className="mx-auto aspect-square max-h-[260px]">
              <BarChart data={strengthData}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-zinc-800" />
                <XAxis dataKey="name" className="text-xs text-zinc-500" />
                <YAxis className="text-xs text-zinc-500" />
                <ChartTooltip content={<ChartTooltipContent />} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {strengthData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ChartContainer>
          </CardContent>
        </Card>

        {/* Quantum Readiness */}
        <Card className="bg-zinc-900 border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-zinc-300">Quantum Readiness</CardTitle>
          </CardHeader>
          <CardContent>
            <ChartContainer config={barConfig} className="mx-auto aspect-square max-h-[260px]">
              <BarChart data={quantumData}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-zinc-800" />
                <XAxis dataKey="name" className="text-xs text-zinc-500" />
                <YAxis className="text-xs text-zinc-500" />
                <ChartTooltip content={<ChartTooltipContent />} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {quantumData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ChartContainer>
          </CardContent>
        </Card>
      </div>

      {/* Top Risks */}
      {dashboardData.top_risks?.length > 0 && (
        <Card className="bg-zinc-900 border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-zinc-300">Top Cryptographic Risks</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow className="border-zinc-800 hover:bg-transparent">
                  <TableHead className="text-zinc-400">Algorithm</TableHead>
                  <TableHead className="text-zinc-400">Type</TableHead>
                  <TableHead className="text-zinc-400">Strength</TableHead>
                  <TableHead className="text-zinc-400">Quantum Safe</TableHead>
                  <TableHead className="text-zinc-400">Impact</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {dashboardData.top_risks.slice(0, 10).map((risk, i) => (
                  <TableRow key={i} className="border-zinc-800 hover:bg-zinc-800/50">
                    <TableCell className="text-zinc-200 font-medium">{risk.algorithm_name}</TableCell>
                    <TableCell className="text-zinc-400">{risk.algorithm_type?.replace(/_/g, " ")}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className={
                        risk.crypto_strength === "weak" ? "border-red-500/50 text-red-400" :
                        risk.crypto_strength === "moderate" ? "border-yellow-500/50 text-yellow-400" :
                        risk.crypto_strength === "strong" ? "border-green-500/50 text-green-400" :
                        "border-blue-500/50 text-blue-400"
                      }>{risk.crypto_strength}</Badge>
                    </TableCell>
                    <TableCell>
                      {risk.quantum_safe ? (
                        <Badge variant="outline" className="border-green-500/50 text-green-400">Yes</Badge>
                      ) : (
                        <Badge variant="outline" className="border-red-500/50 text-red-400">No</Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-zinc-400 max-w-[200px] truncate">{risk.impact}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Status & Risk Helpers ──────────────────────────────────────────────────────

function statusBadge(status: string) {
  const map: Record<string, { color: string; icon: React.ReactNode; label: string }> = {
    success: { color: "text-emerald-400", icon: <CheckCircle className="size-3" />, label: "Success" },
    failure: { color: "text-red-400", icon: <MinusCircle className="size-3" />, label: "Failure" },
    pending: { color: "text-yellow-400", icon: <Clock className="size-3" />, label: "Pending" },
    started: { color: "text-blue-400", icon: <RefreshCcw className="size-3 animate-spin" />, label: "Started" },
    not_started: { color: "text-zinc-400", icon: <Clock className="size-3" />, label: "Not Started" },
    retry: { color: "text-orange-400", icon: <RefreshCcw className="size-3" />, label: "Retry" },
  };
  const s = map[status] ?? map.not_started;
  return (
    <Badge variant="outline" className={`gap-1 border-zinc-700 ${s!.color}`}>
      {s!.icon} {s!.label}
    </Badge>
  );
}

// ─── Main Page ──────────────────────────────────────────────────────────────────

export default function CBOMPage() {
  const params = useParams();
  const router = useRouter();
  const team_id = parseInt((params?.team_id as string) ?? "0", 10);

  const queryClient = useQueryClient();
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ["cbom-scans", team_id],
    queryFn: () => getCBOMScans(team_id),
    enabled: !!team_id,
  });

  const conversations = data?.scans_list_data ?? [];
  const dashboardData = data?.dashboard_data ?? null;

  const [activeTab, setActiveTab] = useState<"dashboard" | "table">("dashboard");
  const [filterQuery, setFilterQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<ScanStatus | "all">("all");
  const [riskFilter, setRiskFilter] = useState<RiskScoreFilter>("all");
  const [sortBy, setSortBy] = useState<TableSortBy>("none");

  const [newTitle, setNewTitle] = useState("");
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [isRenameOpen, setIsRenameOpen] = useState(false);
  const [isDeleteOpen, setIsDeleteOpen] = useState(false);
  const [selectedScan, setSelectedScan] = useState<CBOMConversation | null>(null);

  const createMutation = useMutation({
    mutationFn: () => createCBOMScan(team_id, newTitle.trim()),
    onSuccess: (scan_id) => {
      queryClient.invalidateQueries({ queryKey: ["cbom-scans", team_id] });
      setIsCreateOpen(false);
      setNewTitle("");
      router.push(`/${team_id}/cbom/${scan_id}`);
    },
    onError: (error) => showErrorToast(error, "Error creating CBOM scan"),
  });

  const renameMutation = useMutation({
    mutationFn: () => renameCBOMScan({ team_id, scan_id: selectedScan!.id, title: newTitle.trim() }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["cbom-scans", team_id] });
      setIsRenameOpen(false);
      setNewTitle("");
      setSelectedScan(null);
    },
    onError: (error) => showErrorToast(error, "Error renaming CBOM scan"),
  });

  const deleteMutation = useMutation({
    mutationFn: () => deleteCBOMScan(team_id, selectedScan!.id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["cbom-scans", team_id] });
      setIsDeleteOpen(false);
      setSelectedScan(null);
    },
    onError: (error) => showErrorToast(error, "Error deleting CBOM scan"),
  });

  const filteredConversations = useMemo(() => {
    let list = [...conversations];

    if (filterQuery) {
      const q = filterQuery.toLowerCase();
      list = list.filter((c) => c.title?.toLowerCase().includes(q));
    }
    if (statusFilter !== "all") {
      list = list.filter((c) => c.scan_status === statusFilter);
    }
    if (riskFilter !== "all") {
      list = list.filter((c) => {
        const score = c.risk_data
          ? Math.round(((c.risk_data.total_critical * 10 + c.risk_data.total_high * 7 + c.risk_data.total_medium * 5 + c.risk_data.total_low * 2) / Math.max(1, c.risk_data.total_critical + c.risk_data.total_high + c.risk_data.total_medium + c.risk_data.total_low)) * 10) / 10
          : null;
        return matchesRiskScoreFilter(score, riskFilter);
      });
    }

    switch (sortBy) {
      case "created_asc":
        list.sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
        break;
      case "created_desc":
        list.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
        break;
      case "credits_desc":
        list.sort((a, b) => (b.estimated_credits ?? 0) - (a.estimated_credits ?? 0));
        break;
      case "credits_asc":
        list.sort((a, b) => (a.estimated_credits ?? 0) - (b.estimated_credits ?? 0));
        break;
    }

    return list;
  }, [conversations, filterQuery, statusFilter, riskFilter, sortBy]);

  if (!team_id) {
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-400">Team not found</p>
      </div>
    );
  }

  if (isError) {
    return (
      <div className="flex h-screen w-full items-center justify-center flex-col gap-4">
        <p className="text-zinc-400">Error loading CBOM scans</p>
        <Button variant="ghost" onClick={() => refetch()} className="text-white hover:bg-zinc-800">
          <RefreshCcw className="size-4 mr-2" /> Retry
        </Button>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <Loader2 className="size-10 animate-spin text-blue-600" />
      </div>
    );
  }

  return (
    <ScrollArea className="h-screen">
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white">CBOM Scans</h1>
            <p className="text-sm text-zinc-400 mt-1">Cryptography Bill of Materials — analyze cryptographic assets across your codebase</p>
          </div>
          <Button
            onClick={() => { setNewTitle(""); setIsCreateOpen(true); }}
            className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
          >
            <Plus className="size-4 mr-2" /> New CBOM Scan
          </Button>
        </div>

        {/* Tabs */}
        <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as "dashboard" | "table")}>
          <TabsList className="bg-zinc-800 border border-zinc-700">
            <TabsTrigger value="dashboard" className="data-[state=active]:bg-zinc-700 text-zinc-300 cursor-pointer">Dashboard</TabsTrigger>
            <TabsTrigger value="table" className="data-[state=active]:bg-zinc-700 text-zinc-300 cursor-pointer">All Scans</TabsTrigger>
          </TabsList>

          <TabsContent value="dashboard" className="mt-4">
            {dashboardData ? (
              <CBOMScanListDashboard dashboardData={dashboardData} />
            ) : (
              <div className="text-center text-zinc-500 py-12">No dashboard data available. Run a CBOM scan to see analytics.</div>
            )}
          </TabsContent>

          <TabsContent value="table" className="mt-4 space-y-4">
            {/* Filters */}
            <div className="flex items-center gap-3 flex-wrap">
              <div className="relative flex-1 min-w-[200px] max-w-sm">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 size-4 text-zinc-500" />
                <Input
                  placeholder="Search scans..."
                  className="pl-9 bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500"
                  value={filterQuery}
                  onChange={(e) => setFilterQuery(e.target.value)}
                />
                {filterQuery && (
                  <button onClick={() => setFilterQuery("")} className="absolute right-3 top-1/2 -translate-y-1/2 cursor-pointer">
                    <X className="size-4 text-zinc-500 hover:text-white" />
                  </button>
                )}
              </div>

              <Select value={statusFilter} onValueChange={(v) => setStatusFilter(v as ScanStatus | "all")}>
                <SelectTrigger className="w-[140px] bg-zinc-800 border-zinc-700 text-zinc-300">
                  <Filter className="size-3 mr-1" />
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-zinc-800 border-zinc-700">
                  <SelectItem value="all">All statuses</SelectItem>
                  <SelectItem value="success">Success</SelectItem>
                  <SelectItem value="failure">Failure</SelectItem>
                  <SelectItem value="pending">Pending</SelectItem>
                  <SelectItem value="started">Started</SelectItem>
                  <SelectItem value="not_started">Not Started</SelectItem>
                </SelectContent>
              </Select>

              <Select value={sortBy} onValueChange={(v) => setSortBy(v as TableSortBy)}>
                <SelectTrigger className="w-[180px] bg-zinc-800 border-zinc-700 text-zinc-300">
                  <ArrowUpDown className="size-3 mr-1" />
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-zinc-800 border-zinc-700">
                  {Object.entries(SORT_BY_LABELS).map(([k, v]) => (
                    <SelectItem key={k} value={k}>{v}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* Table */}
            {filteredConversations.length === 0 ? (
              <div className="text-center text-zinc-500 py-12">
                {conversations.length === 0
                  ? "No CBOM scans yet. Create one to get started."
                  : "No scans match your filters."}
              </div>
            ) : (
              <div className="rounded-lg border border-zinc-800 overflow-hidden">
                <Table>
                  <TableHeader>
                    <TableRow className="border-zinc-800 hover:bg-transparent">
                      <TableHead className="text-zinc-400">Name</TableHead>
                      <TableHead className="text-zinc-400">Status</TableHead>
                      <TableHead className="text-zinc-400">Risks</TableHead>
                      <TableHead className="text-zinc-400">Source</TableHead>
                      <TableHead className="text-zinc-400">Credits</TableHead>
                      <TableHead className="text-zinc-400">Created</TableHead>
                      <TableHead className="text-zinc-400 text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredConversations.map((scan) => {
                      const risk = scan.risk_data;
                      return (
                        <TableRow key={scan.id} className="border-zinc-800 hover:bg-zinc-800/50 cursor-pointer" onClick={() => router.push(`/${team_id}/cbom/${scan.id}`)}>
                          <TableCell className="text-zinc-200 font-medium max-w-[200px] truncate">{scan.title || `Scan #${scan.id}`}</TableCell>
                          <TableCell>{statusBadge(scan.scan_status)}</TableCell>
                          <TableCell>
                            {risk ? (
                              <div className="flex items-center gap-2 text-xs">
                                {risk.total_critical > 0 && <span className="text-red-400">C:{risk.total_critical}</span>}
                                {risk.total_high > 0 && <span className="text-orange-400">H:{risk.total_high}</span>}
                                {risk.total_medium > 0 && <span className="text-yellow-400">M:{risk.total_medium}</span>}
                                {risk.total_low > 0 && <span className="text-blue-400">L:{risk.total_low}</span>}
                                {risk.total_quantum_vulnerable != null && risk.total_quantum_vulnerable > 0 && (
                                  <Badge variant="outline" className="border-red-500/50 text-red-400 text-[10px] py-0">QV:{risk.total_quantum_vulnerable}</Badge>
                                )}
                              </div>
                            ) : (
                              <span className="text-zinc-500 text-xs">—</span>
                            )}
                          </TableCell>
                          <TableCell>
                            {scan.zip_file_used ? (
                              <Badge variant="outline" className="border-zinc-700 text-zinc-400 gap-1"><FileArchive className="size-3" /> Zip</Badge>
                            ) : scan.cbom_file_used ? (
                              <Badge variant="outline" className="border-zinc-700 text-zinc-400 gap-1"><Lock className="size-3" /> CBOM File</Badge>
                            ) : scan.repo_url ? (
                              <Badge variant="outline" className="border-zinc-700 text-zinc-400 gap-1"><GitBranch className="size-3" /> Repo</Badge>
                            ) : (
                              <span className="text-zinc-500 text-xs">—</span>
                            )}
                          </TableCell>
                          <TableCell className="text-zinc-400 text-sm">{scan.estimated_credits != null && scan.estimated_credits >= 0 ? scan.estimated_credits : "—"}</TableCell>
                          <TableCell className="text-zinc-500 text-xs">{new Date(scan.created_at).toLocaleDateString()}</TableCell>
                          <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                            <DropdownMenu>
                              <DropdownMenuTrigger asChild>
                                <Button variant="ghost" size="sm" className="h-8 w-8 p-0 text-zinc-400 hover:text-white cursor-pointer">
                                  <MoreVertical className="size-4" />
                                </Button>
                              </DropdownMenuTrigger>
                              <DropdownMenuContent align="end" className="bg-zinc-800 border-zinc-700">
                                <DropdownMenuItem className="text-zinc-300 focus:bg-zinc-700 cursor-pointer" onClick={() => router.push(`/${team_id}/cbom/${scan.id}`)}>
                                  <Eye className="size-4 mr-2" /> View
                                </DropdownMenuItem>
                                {scan.scan_status === "success" && (
                                  <DropdownMenuItem className="text-zinc-300 focus:bg-zinc-700 cursor-pointer" onClick={() => router.push(`/${team_id}/cbom/${scan.id}/results`)}>
                                    <Eye className="size-4 mr-2" /> Results
                                  </DropdownMenuItem>
                                )}
                                <DropdownMenuSeparator className="bg-zinc-700" />
                                <DropdownMenuItem className="text-zinc-300 focus:bg-zinc-700 cursor-pointer" onClick={() => { setSelectedScan(scan); setNewTitle(scan.title); setIsRenameOpen(true); }}>
                                  <Pencil className="size-4 mr-2" /> Rename
                                </DropdownMenuItem>
                                <DropdownMenuItem className="text-red-400 focus:bg-zinc-700 cursor-pointer" onClick={() => { setSelectedScan(scan); setIsDeleteOpen(true); }}>
                                  <Trash2 className="size-4 mr-2" /> Delete
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
            )}
          </TabsContent>
        </Tabs>
      </div>

      {/* Create Dialog */}
      <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
        <DialogContent className="bg-zinc-900 border-zinc-800">
          <DialogHeader>
            <DialogTitle className="text-white">Create CBOM Scan</DialogTitle>
            <DialogDescription className="text-zinc-400">Give your scan a name to get started.</DialogDescription>
          </DialogHeader>
          <Input
            placeholder="Scan name..."
            className="bg-zinc-800 border-zinc-700 text-white"
            value={newTitle}
            onChange={(e) => setNewTitle(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && newTitle.trim() && createMutation.mutate()}
          />
          <DialogFooter>
            <Button variant="ghost" onClick={() => setIsCreateOpen(false)} className="text-zinc-400 hover:text-white cursor-pointer">Cancel</Button>
            <Button onClick={() => createMutation.mutate()} disabled={!newTitle.trim() || createMutation.isPending} className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer">
              {createMutation.isPending ? <Loader2 className="size-4 animate-spin mr-2" /> : <Plus className="size-4 mr-2" />}
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Rename Dialog */}
      <Dialog open={isRenameOpen} onOpenChange={setIsRenameOpen}>
        <DialogContent className="bg-zinc-900 border-zinc-800">
          <DialogHeader>
            <DialogTitle className="text-white">Rename Scan</DialogTitle>
          </DialogHeader>
          <Input
            className="bg-zinc-800 border-zinc-700 text-white"
            value={newTitle}
            onChange={(e) => setNewTitle(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && newTitle.trim() && renameMutation.mutate()}
          />
          <DialogFooter>
            <Button variant="ghost" onClick={() => setIsRenameOpen(false)} className="text-zinc-400 hover:text-white cursor-pointer">Cancel</Button>
            <Button onClick={() => renameMutation.mutate()} disabled={!newTitle.trim() || renameMutation.isPending} className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer">
              {renameMutation.isPending ? <Loader2 className="size-4 animate-spin mr-2" /> : <Pencil className="size-4 mr-2" />}
              Rename
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Dialog */}
      <Dialog open={isDeleteOpen} onOpenChange={setIsDeleteOpen}>
        <DialogContent className="bg-zinc-900 border-zinc-800">
          <DialogHeader>
            <DialogTitle className="text-white">Delete Scan</DialogTitle>
            <DialogDescription className="text-zinc-400">
              Are you sure you want to delete &quot;{selectedScan?.title}&quot;? This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setIsDeleteOpen(false)} className="text-zinc-400 hover:text-white cursor-pointer">Cancel</Button>
            <Button variant="destructive" onClick={() => deleteMutation.mutate()} disabled={deleteMutation.isPending} className="cursor-pointer">
              {deleteMutation.isPending ? <Loader2 className="size-4 animate-spin mr-2" /> : <Trash2 className="size-4 mr-2" />}
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <ScrollBar orientation="vertical" />
    </ScrollArea>
  );
}

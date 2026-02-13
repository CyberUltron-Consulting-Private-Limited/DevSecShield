"use client";

import Link from "next/link";
import { useRouter, useParams } from "next/navigation";
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
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Plus, MoreVertical, Pencil, Trash2, RefreshCcw, Loader2, Eye, Clock, Play, CheckCircle, XCircle, CalendarPlus, CalendarCheck, Search, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { MCPConversation, deleteMCPConversation, getMCPConversations, renameMCPConversation, createMCPConversation } from "@/utils/backend_api";
import type { ScanListDashboardData } from "@/utils/backend_api";
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
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import { Bar, BarChart, CartesianGrid, XAxis, YAxis, RadialBar, RadialBarChart } from "recharts";

type ScanStatus = "pending" | "started" | "retry" | "failure" | "success" | "not_started";

/** List item with optional fields from backend */
type MCPListItem = MCPConversation & {
  owner_user_email?: string | null;
  owner_user_full_name?: string | null;
  scan_metadata?: Record<string, unknown> | null;
  info?: { current?: number } | null;
};

// ─── Dashboard (no repos/zip, no risk charts) ───────────────────────────────────
function ScanListDashboardSimple({ dashboardData }: { dashboardData: ScanListDashboardData }) {
  const card = dashboardData.card_data;
  const scansPerDayData = useMemo(() => {
    return Object.entries(dashboardData.scans_per_day)
      .map(([date, count]) => ({ date, scans: count }))
      .sort((a, b) => a.date.localeCompare(b.date));
  }, [dashboardData.scans_per_day]);
  const statusData = useMemo(() => [
    { status: "success", count: card.success_scans, fill: "hsl(142 71% 45%)" },
    { status: "started", count: card.started_scans, fill: "hsl(217 91% 60%)" },
    { status: "pending", count: card.pending_scans, fill: "hsl(220 9% 46%)" },
    { status: "failure", count: card.failure_scans, fill: "hsl(0 72% 51%)" },
    { status: "not_started", count: card.not_started_scans, fill: "hsl(270 50% 60%)" },
  ], [card]);
  const barConfig = { scans: { label: "Scans", color: "hsl(220 70% 50%)" } } satisfies ChartConfig;
  const radialConfig = { count: { label: "Scans" } } satisfies ChartConfig;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-7 gap-4">
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Not Started</CardTitle>
            <Clock className="h-4 w-4 text-zinc-400" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-zinc-900 dark:text-white">{card.not_started_scans}</div>
            <p className="text-xs text-zinc-500 dark:text-zinc-400">Idle</p>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Pending</CardTitle>
            <Clock className="h-4 w-4 text-zinc-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-zinc-900 dark:text-white">{card.pending_scans}</div>
            <p className="text-xs text-zinc-500 dark:text-zinc-400">Queued</p>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Started</CardTitle>
            <Play className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-zinc-900 dark:text-white">{card.started_scans}</div>
            <p className="text-xs text-zinc-500 dark:text-zinc-400">In progress</p>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Success</CardTitle>
            <CheckCircle className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-zinc-900 dark:text-white">{card.success_scans}</div>
            <p className="text-xs text-zinc-500 dark:text-zinc-400">Completed</p>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Failure</CardTitle>
            <XCircle className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-zinc-900 dark:text-white">{card.failure_scans}</div>
            <p className="text-xs text-zinc-500 dark:text-zinc-400">Failed</p>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Created today</CardTitle>
            <CalendarPlus className="h-4 w-4 text-zinc-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-zinc-900 dark:text-white">{card.scans_created_today}</div>
            <p className="text-xs text-zinc-500 dark:text-zinc-400">New scans</p>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Updated today</CardTitle>
            <CalendarCheck className="h-4 w-4 text-zinc-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-zinc-900 dark:text-white">{card.scans_updated_today}</div>
            <p className="text-xs text-zinc-500 dark:text-zinc-400">Last 24h</p>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Scans Per Day</CardTitle>
            <CardDescription>Number of scans created each day</CardDescription>
          </CardHeader>
          <CardContent>
            {scansPerDayData.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No scan activity yet</p>
            ) : (
              <ChartContainer config={barConfig} className="h-[280px] w-full">
                <BarChart data={scansPerDayData}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="date" tickLine={false} axisLine={false} tickMargin={8} tickFormatter={(v) => new Date(v).toLocaleDateString("en-US", { month: "short", day: "numeric" })} />
                  <YAxis tickLine={false} axisLine={false} allowDecimals={false} />
                  <ChartTooltip cursor={false} content={<ChartTooltipContent hideLabel />} />
                  <Bar dataKey="scans" fill="var(--color-scans)" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="items-center pb-2">
            <CardTitle className="text-base">Scan Status Breakdown</CardTitle>
            <CardDescription>Distribution of scan outcomes</CardDescription>
          </CardHeader>
          <CardContent>
            {statusData.every((s) => s.count === 0) ? (
              <p className="text-center text-sm text-zinc-500 py-8">No scans yet</p>
            ) : (
              <ChartContainer config={radialConfig} className="mx-auto aspect-square max-h-[280px]">
                <RadialBarChart data={statusData} innerRadius={30} outerRadius={110}>
                  <ChartTooltip cursor={false} content={<ChartTooltipContent nameKey="status" hideLabel />} />
                  <RadialBar dataKey="count" background />
                </RadialBarChart>
              </ChartContainer>
            )}
            <div className="flex flex-wrap items-center justify-center gap-4 mt-3 text-sm text-zinc-600 dark:text-zinc-400">
              <span className="flex items-center gap-1.5"><span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: "hsl(142 71% 45%)" }} />Success</span>
              <span className="flex items-center gap-1.5"><span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: "hsl(217 91% 60%)" }} />Started</span>
              <span className="flex items-center gap-1.5"><span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: "hsl(220 9% 46%)" }} />Pending</span>
              <span className="flex items-center gap-1.5"><span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: "hsl(0 72% 51%)" }} />Failure</span>
              <span className="flex items-center gap-1.5"><span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: "hsl(270 50% 60%)" }} />Not Started</span>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}


export default function MCPPage() {
  const router = useRouter();
  const params = useParams();
  const team_id = params?.team_id as string | undefined;
  const [conversations, setConversations] = useState<MCPListItem[]>([]);
  const [renameDialogOpen, setRenameDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [selectedConversation, setSelectedConversation] = useState<MCPListItem | null>(null);
  const [metadataDialogOpen, setMetadataDialogOpen] = useState(false);
  const [metadataScan, setMetadataScan] = useState<MCPListItem | null>(null);
  const [newName, setNewName] = useState("");
  const [newScanTitle, setNewScanTitle] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [createdAtSort, setCreatedAtSort] = useState<"none" | "asc" | "desc">("none");
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ['mcp-conversations', team_id],
    queryFn: () => getMCPConversations(Number(team_id)),
    enabled: !!team_id,
  });

  useEffect(() => {
    if (query.data?.scans_list_data) {
      setConversations(query.data.scans_list_data as MCPListItem[]);
    }
    if (query.error) {
      showErrorToast(query.error, 'Error fetching MCP conversations');
    }
  }, [query.data, query.error]);

  const hasActiveFilters = searchQuery !== "" || statusFilter !== "all" || createdAtSort !== "none";
  const filteredConversations = conversations
    .filter((c) => {
      if (searchQuery && !c.title.toLowerCase().includes(searchQuery.toLowerCase())) return false;
      if (statusFilter !== "all" && c.scan_status !== statusFilter) return false;
      return true;
    })
    .sort((a, b) => {
      if (createdAtSort === "asc") return new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
      if (createdAtSort === "desc") return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
      return 0;
    });
  const clearFilters = () => { setSearchQuery(""); setStatusFilter("all"); setCreatedAtSort("none"); };
  const dashboardData = query.data?.dashboard_data as ScanListDashboardData | undefined;

  const deleteMCPConversationMutation = useMutation({
    mutationFn: ({ team_id, scan_id }: { team_id: number; scan_id: number }) => deleteMCPConversation(team_id, scan_id),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['mcp-conversations', String(variables.team_id)] });
      toast.success('MCP conversation deleted successfully');
    },
    onError: (error) => {
      showErrorToast(error);
    }
  });

  const renameMCPConversationMutation = useMutation({
    mutationFn: renameMCPConversation,
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['mcp-conversations', String(variables.team_id)] });
      toast.success('MCP conversation renamed successfully');
    },
    onError: (error) => {
      showErrorToast(error);
    }
  });

  const createMCPConversationMutation = useMutation({
    mutationFn: (title: string) => createMCPConversation(Number(team_id), title),
    onSuccess: (conversationId) => {
      queryClient.invalidateQueries({ queryKey: ['mcp-conversations', team_id] });
      setCreateDialogOpen(false);
      setNewScanTitle("");
      router.push(`/${team_id}/mcp/${conversationId}`);
    },
    onError: (error) => {
      showErrorToast(error);
    }
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

  const handleRename = (conversation: MCPListItem) => {
    setSelectedConversation(conversation);
    setNewName(conversation.title);
    setRenameDialogOpen(true);
  };

  const handleDelete = (conversation: MCPListItem) => {
    setSelectedConversation(conversation);
    setDeleteDialogOpen(true);
  };

  const confirmRename = () => {
    if (selectedConversation && newName.trim() && team_id) {
      renameMCPConversationMutation.mutate({ team_id: Number(team_id), conversation_id: selectedConversation.id, title: newName.trim() });
      setRenameDialogOpen(false);
      setSelectedConversation(null);
      setNewName("");
    }
  };

  const confirmDelete = () => {
    if (selectedConversation && team_id) {
      deleteMCPConversationMutation.mutate({ team_id: Number(team_id), scan_id: selectedConversation.id });
      setDeleteDialogOpen(false);
      setSelectedConversation(null);
    }
  };

  const confirmCreate = () => {
    if (newScanTitle.trim() && team_id) {
      createMCPConversationMutation.mutate(newScanTitle.trim());
    }
  };

  return (
    <div className="flex h-screen bg-white dark:bg-zinc-900">
      <div className="flex-1 p-8 overflow-auto">
        <div className="max-w-7xl mx-auto">
          {/* Header */}
          <div className="flex items-center justify-between mb-6">
            <div>
              <h1 className="text-3xl font-bold text-zinc-900 dark:text-white mb-2">MCP Scans</h1>
              <p className="text-zinc-600 dark:text-zinc-400">Manage and view all your MCP server scan conversations.</p>
            </div>
            <div className="flex flex-row items-center gap-2">
              <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => setCreateDialogOpen(true)}>
                <Plus className="h-4 w-4 mr-2" />New Scan
              </Button>
              <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => queryClient.invalidateQueries({ queryKey: ['mcp-conversations', team_id] })}>
                <RefreshCcw className="h-4 w-4 mr-2" />Refresh
              </Button>
            </div>
          </div>

          {query.isLoading ? (
            <div className="flex h-64 items-center justify-center">
              <Loader2 className="size-10 animate-spin text-blue-600" />
            </div>
          ) : query.isError ? (
            <div className="text-center py-12">
              <p className="text-zinc-600 dark:text-zinc-400 mb-4">Error in fetching conversations, please try again later</p>
            </div>
          ) : (
            <Tabs defaultValue="dashboard" className="w-full">
              <TabsList className="mb-4 bg-transparent">
                <TabsTrigger value="dashboard" className="cursor-pointer data-[state=active]:bg-blue-600 data-[state=active]:text-white">Dashboard</TabsTrigger>
                <TabsTrigger value="table" className="cursor-pointer data-[state=active]:bg-blue-600 data-[state=active]:text-white">Table</TabsTrigger>
              </TabsList>

              <TabsContent value="dashboard">
                {dashboardData ? (
                  <ScanListDashboardSimple dashboardData={dashboardData} />
                ) : (
                  <p className="text-center text-sm text-zinc-500 py-12">No dashboard data available.</p>
                )}
              </TabsContent>

              <TabsContent value="table">
                {conversations.length > 0 && (
                  <div className="flex flex-wrap items-center gap-3 mb-4">
                    <div className="relative flex-1 min-w-[200px] max-w-sm">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-400" />
                      <Input placeholder="Search by title..." value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} className="pl-9 h-9 cursor-text" />
                    </div>
                    <Select value={statusFilter} onValueChange={setStatusFilter}>
                      <SelectTrigger className="h-9 min-w-[150px] cursor-pointer"><SelectValue placeholder="Scan status" /></SelectTrigger>
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
                    <div className="text-zinc-600 dark:text-zinc-400 text-sm">Sort by</div>
                    <Select value={createdAtSort} onValueChange={(v) => setCreatedAtSort(v as "none" | "asc" | "desc")}>
                      <SelectTrigger className="h-9 min-w-[170px] cursor-pointer"><SelectValue placeholder="Created at" /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="none">Default</SelectItem>
                        <SelectItem value="desc">Newest</SelectItem>
                        <SelectItem value="asc">Oldest</SelectItem>
                      </SelectContent>
                    </Select>
                    {hasActiveFilters && (
                      <Button variant="ghost" size="sm" className="h-9 text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300 cursor-pointer" onClick={clearFilters}>
                        <X className="h-4 w-4 mr-1" />Clear filters
                      </Button>
                    )}
                  </div>
                )}

                {conversations.length === 0 ? (
                  <div className="text-center py-12">
                    <p className="text-zinc-600 dark:text-zinc-400 mb-4">No scans yet. Create your first MCP scan to get started.</p>
                    <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => setCreateDialogOpen(true)}>
                      <Plus className="h-4 w-4 mr-2" />Create New Scan
                    </Button>
                  </div>
                ) : filteredConversations.length === 0 ? (
                  <div className="text-center py-12">
                    <p className="text-zinc-600 dark:text-zinc-400 mb-4">No scans match your filters.</p>
                    <Button variant="outline" className="cursor-pointer" onClick={clearFilters}><X className="h-4 w-4 mr-2" />Clear filters</Button>
                  </div>
                ) : (
                  <div className="border rounded-lg overflow-hidden">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead className="w-[220px]">Title</TableHead>
                          <TableHead>Owner</TableHead>
                          <TableHead>Created at</TableHead>
                          <TableHead>Last updated</TableHead>
                          <TableHead>Scan status</TableHead>
                          <TableHead className="w-[180px]">View scan metadata</TableHead>
                          <TableHead className="text-right w-[80px]">Actions</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {filteredConversations.map((conversation) => (
                          <TableRow
                            key={conversation.id}
                            className="hover:bg-zinc-50 dark:hover:bg-zinc-800 cursor-pointer"
                            onClick={(e) => {
                              const target = e.target as HTMLElement;
                              if (target.closest("button") || target.closest("[role='menuitem']")) return;
                              const dest = (conversation.scan_status?.toLowerCase() ?? "") === "success"
                                ? `/${team_id}/mcp/${conversation.id}/results`
                                : `/${team_id}/mcp/${conversation.id}`;
                              router.push(dest);
                            }}
                          >
                            <TableCell className="font-medium">
                              <Link
                                href={(conversation.scan_status?.toLowerCase() ?? "") === "success" ? `/${team_id}/mcp/${conversation.id}/results` : `/${team_id}/mcp/${conversation.id}`}
                                className="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 hover:underline cursor-pointer"
                              >
                                {conversation.title}
                              </Link>
                            </TableCell>
                            <TableCell className="text-zinc-600 dark:text-zinc-400">
                              {conversation.owner_user_full_name != null && conversation.owner_user_full_name !== "" || conversation.owner_user_email ? (
                                <div className="flex items-center gap-2">
                                  <Avatar className="h-8 w-8 shrink-0">
                                    <AvatarFallback className="bg-blue-600 text-white text-xs font-medium">
                                      {conversation.owner_user_full_name
                                        ? conversation.owner_user_full_name.trim().split(/\s+/).map((p) => p.charAt(0)).slice(0, 2).join("").toUpperCase() || (conversation.owner_user_email?.[0] ?? "?").toUpperCase()
                                        : (conversation.owner_user_email?.[0] ?? "?").toUpperCase()}
                                    </AvatarFallback>
                                  </Avatar>
                                  <div className="min-w-0">
                                    {conversation.owner_user_full_name != null && conversation.owner_user_full_name !== "" && (
                                      <span className="block truncate max-w-[160px]" title={conversation.owner_user_email ?? ""}>{conversation.owner_user_full_name}</span>
                                    )}
                                    {conversation.owner_user_email != null && conversation.owner_user_email !== "" && (
                                      <span className="block text-xs text-zinc-500 dark:text-zinc-400 truncate max-w-[160px]">{conversation.owner_user_email}</span>
                                    )}
                                  </div>
                                </div>
                              ) : ("—")}
                            </TableCell>
                            <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm">{formatDate(conversation.created_at)}</TableCell>
                            <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm">{formatDate(conversation.last_updated)}</TableCell>
                            <TableCell className="text-sm">
                              <div className="flex flex-col gap-1.5">
                                {getStatusBadge(conversation.scan_status as ScanStatus)}
                                {conversation.info?.current != null && conversation.scan_status !== "success" && conversation.scan_status !== "failure" && (
                                  <div className="flex items-center gap-2">
                                    <Progress value={conversation.info.current} className="h-1.5 flex-1" />
                                    <span className="text-xs text-zinc-500 tabular-nums">{conversation.info.current}%</span>
                                  </div>
                                )}
                              </div>
                            </TableCell>
                            <TableCell>
                              <Button variant="outline" size="sm" className="cursor-pointer" onClick={(e) => { e.stopPropagation(); setMetadataScan(conversation); setMetadataDialogOpen(true); }}>
                                <Eye className="h-4 w-4 mr-1.5" />View
                              </Button>
                            </TableCell>
                            <TableCell className="text-right">
                              <DropdownMenu>
                                <DropdownMenuTrigger asChild onClick={(e) => e.stopPropagation()}>
                                  <Button variant="ghost" size="icon" className="h-8 w-8 cursor-pointer"><MoreVertical className="h-4 w-4" /></Button>
                                </DropdownMenuTrigger>
                                <DropdownMenuContent align="end">
                                  {(conversation.scan_status?.toLowerCase() ?? "") === "success" && (
                                    <DropdownMenuItem className="cursor-pointer" onClick={() => router.push(`/${team_id}/mcp/${conversation.id}/results?origin=list`)}>
                                      <Eye className="h-4 w-4 mr-2" />View Results
                                    </DropdownMenuItem>
                                  )}
                                  <DropdownMenuItem className="cursor-pointer" onClick={() => handleRename(conversation)}>
                                    <Pencil className="h-4 w-4 mr-2" />Rename
                                  </DropdownMenuItem>
                                  <DropdownMenuItem className="cursor-pointer" onClick={() => handleDelete(conversation)} variant="destructive">
                                    <Trash2 className="h-4 w-4 mr-2" />Delete
                                  </DropdownMenuItem>
                                </DropdownMenuContent>
                              </DropdownMenu>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                )}
              </TabsContent>
            </Tabs>
          )}
        </div>
      </div>

      {/* Rename Dialog */}
      <Dialog open={renameDialogOpen} onOpenChange={setRenameDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Rename Conversation</DialogTitle>
            <DialogDescription>
              Enter a new name for this conversation.
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <Input
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="Conversation name"
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  confirmRename();
                }
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

      {/* Delete Dialog */}
      <Dialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Conversation</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete &quot;{selectedConversation?.title}&quot;? This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" className="cursor-pointer" onClick={() => { setDeleteDialogOpen(false); setSelectedConversation(null); }}>Cancel</Button>
            <Button variant="destructive" className="cursor-pointer" onClick={confirmDelete}>Delete</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Scan metadata dialog */}
      <Dialog open={metadataDialogOpen} onOpenChange={setMetadataDialogOpen}>
        <DialogContent className="max-w-lg max-h-[80vh] overflow-auto">
          <DialogHeader>
            <DialogTitle>Scan metadata</DialogTitle>
            <DialogDescription>{metadataScan ? `Metadata for "${metadataScan.title}"` : "Scan metadata"}</DialogDescription>
          </DialogHeader>
          <div className="py-2">
            {metadataScan?.scan_metadata && typeof metadataScan.scan_metadata === "object" && Object.keys(metadataScan.scan_metadata).length > 0 ? (
              <dl className="space-y-2 text-sm">
                {Object.entries(metadataScan.scan_metadata).map(([key, value]) => (
                  <div key={key} className="flex gap-2 border-b border-zinc-200 dark:border-zinc-700 pb-2">
                    <dt className="font-medium text-zinc-700 dark:text-zinc-300 shrink-0 min-w-[120px]">{key}</dt>
                    <dd className="text-zinc-600 dark:text-zinc-400 break-all">{value !== null && typeof value === "object" ? JSON.stringify(value) : String(value)}</dd>
                  </div>
                ))}
              </dl>
            ) : (
              <p className="text-zinc-500 dark:text-zinc-400 text-sm">No metadata for this scan.</p>
            )}
          </div>
        </DialogContent>
      </Dialog>

      {/* Create Scan Dialog */}
      <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create New Scan</DialogTitle>
            <DialogDescription>
              Enter a title for your new MCP scan conversation.
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <Input
              value={newScanTitle}
              onChange={(e) => setNewScanTitle(e.target.value)}
              placeholder="Scan title"
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  confirmCreate();
                }
              }}
            />
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              className="cursor-pointer"
              onClick={() => {
                setCreateDialogOpen(false);
                setNewScanTitle("");
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={confirmCreate}
              disabled={!newScanTitle.trim() || !team_id || createMCPConversationMutation.isPending}
              className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
            >
              {createMCPConversationMutation.isPending ? "Creating..." : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

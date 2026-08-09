"use client";
/* eslint-disable */
/**
 * @deprecated Full Guardrails list UI retained for internal reference.
 * Not mounted from user-facing nav. Prefer GuardrailsDeprecatedNotice.
 */

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
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Plus, MoreVertical, Pencil, Trash2, RefreshCcw, Loader2, Copy, Check, X, Search, Activity, AlertTriangle, CheckCircle2, Clock, XCircle, PieChart } from "lucide-react";
import { useEffect, useState } from "react";
import { GuardrailsIntegration, deleteGuardrailsIntegration, getGuardrailsIntegrations, renameGuardrailsIntegration, createGuardrailsIntegration, SettingsData } from "@/utils/backend_api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import { RadialBarChart, RadialBar, RadarChart, Radar, PolarGrid, PolarAngleAxis, Area, AreaChart, CartesianGrid, XAxis, YAxis } from "recharts";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { showErrorToast } from "@/utils/error-handler";
import { formatDateIst as formatDate, formatDateOnlyIst, formatMediumDateIst } from "@/utils/datetime";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";

const defaultLanguages = ["ARM Assembly", "AppleScript", "C", "C#", "C++", "COBOL", "Erlang", "Fortran", "Go", "Java", "JavaScript", "Kotlin", "Lua", "Mathematica/Wolfram Language", "PHP", "Pascal", "Perl", "PowerShell", "Python", "R", "Ruby", "Rust", "Scala", "Swift", "Visual Basic .NET", "jq"];

export function DeprecatedGuardrailsPage() {
  const params = useParams();
  const team_id = params?.team_id as string | undefined;
  const router = useRouter();
  const [integrations, setIntegrations] = useState<GuardrailsIntegration[]>([]);
  const [renameDialogOpen, setRenameDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [selectedIntegration, setSelectedIntegration] = useState<GuardrailsIntegration | null>(null);
  const [newName, setNewName] = useState("");
  const [copiedKeyId, setCopiedKeyId] = useState<number | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [createdAtSort, setCreatedAtSort] = useState<"none" | "asc" | "desc">("none");

  // Form state
  const [formTitle, setFormTitle] = useState("");
  const [formSettings, setFormSettings] = useState<SettingsData>({
    anonymize_context: { preamble: "", threshold: 0.1, allowed_names: [] },
    toxicity_context: { threshold: 0.1 },
    tokenlimit_context: { max_tokens: 2000 },
    promptinjection_context: { threshold: 0.1 },
    regex_context: { regex_patterns: [], redact: false },
    code_context: { languages: defaultLanguages, is_blocked: true },
    secrets_context: { redact_mode: "REDACT_PARTIAL" },
  });
  
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ['guardrails-integrations', team_id],
    queryFn: () => getGuardrailsIntegrations(Number(team_id)),
    enabled: !!team_id,
  });
  const dashboardData = query.data?.dashboard_data ?? null;

  useEffect(() => {
    if (query.data?.integrations) {
      setIntegrations(query.data.integrations);
    }
    if (query.error) {
      showErrorToast(query.error, 'Error fetching guardrails integrations');
    }
  }, [query.data, query.error]);

  const deleteGuardrailsIntegrationMutation = useMutation({
    mutationFn: (integration_id: number) => deleteGuardrailsIntegration(Number(team_id), integration_id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['guardrails-integrations', team_id] });
      setDeleteDialogOpen(false);
      setSelectedIntegration(null);
      toast.success('Guardrails integration deleted successfully');
    },
    onError: (error) => {
      showErrorToast(error);
    }
  });

  const renameGuardrailsIntegrationMutation = useMutation({
    mutationFn: ({ integration_id, title }: { integration_id: number; title: string }) =>
      renameGuardrailsIntegration({ team_id: Number(team_id), integration_id, title }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['guardrails-integrations', team_id] });
      toast.success('Guardrails integration renamed successfully');
    },
    onError: (error) => {
      showErrorToast(error);
    }
  });

  const createGuardrailsIntegrationMutation = useMutation({
    mutationFn: (data: { title: string }) => createGuardrailsIntegration(Number(team_id), data),
    onSuccess: (data: { integration_id: number }) => {
      queryClient.invalidateQueries({ queryKey: ['guardrails-integrations', team_id] });
      setCreateDialogOpen(false);
      setFormTitle("");
      setFormSettings({
        anonymize_context: { preamble: "", threshold: 0.1, allowed_names: [] },
        toxicity_context: { threshold: 0.1 },
        tokenlimit_context: { max_tokens: 2000 },
        promptinjection_context: { threshold: 0.1 },
        regex_context: { regex_patterns: [], redact: false },
        code_context: { languages: defaultLanguages, is_blocked: true },
        secrets_context: { redact_mode: "REDACT_PARTIAL" },
      });
      router.push(`/${team_id}/guardrails/${data.integration_id}`);
    },
    onError: (error) => {
      showErrorToast(error);
    }
  });

  const redactApiKey = (apiKey: string) => {
    // Show first 4 and last 4 characters, redact the middle
    const start = apiKey.substring(0, 4);
    const end = apiKey.substring(apiKey.length - 4);
    return `${start}${"*******"}${end}`;
  };

  const copyApiKey = async (apiKey: string, integrationId: number) => {
    try {
      await navigator.clipboard.writeText(apiKey);
      setCopiedKeyId(integrationId);
      toast.success("API key copied to clipboard");
      setTimeout(() => {
        setCopiedKeyId(null);
      }, 2000);
    } catch (error) {
      toast.error("Failed to copy API key");
    }
  };

  const handleRename = (integration: GuardrailsIntegration) => {
    setSelectedIntegration(integration);
    setNewName(integration.title);
    setRenameDialogOpen(true);
  };

  const handleDelete = (integration: GuardrailsIntegration) => {
    setSelectedIntegration(integration);
    setDeleteDialogOpen(true);
  };

  const confirmRename = () => {
    if (selectedIntegration && newName.trim()) {
      renameGuardrailsIntegrationMutation.mutate({ integration_id: selectedIntegration.id, title: newName.trim() });
    }
  };

  const confirmDelete = () => {
    if (selectedIntegration) {
      deleteGuardrailsIntegrationMutation.mutate(selectedIntegration.id);
    }
  };

  const hasActiveFilters = searchQuery !== "" || createdAtSort !== "none";
  const filteredIntegrations = integrations
    .filter((i) => !searchQuery || i.title.toLowerCase().includes(searchQuery.toLowerCase()))
    .sort((a, b) => {
      if (createdAtSort === "asc") return new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
      if (createdAtSort === "desc") return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
      return 0;
    });
  const clearFilters = () => { setSearchQuery(""); setCreatedAtSort("none"); };

  return (
    <div className="flex h-screen bg-white dark:bg-zinc-900">
      <div className="flex-1 p-8 overflow-auto">
        <div className="max-w-7xl mx-auto">
          {/* Header */}
          <div className="flex items-center justify-between mb-8">
            <div>
              <h1 className="text-3xl font-bold text-zinc-900 dark:text-white mb-2">
                Guardrails Integrations
              </h1>
              <p className="text-zinc-600 dark:text-zinc-400">
                Manage and view all your active guardrails integrations.
              </p>
            </div>
            <div className="flex flex-row items-center gap-2">
              <Button 
                className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
                onClick={() => queryClient.invalidateQueries({ queryKey: ['guardrails-integrations', team_id] })}
              >
                <RefreshCcw className="h-4 w-4 mr-2" />
                Refresh
              </Button>
              <Button 
                className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
                onClick={() => setCreateDialogOpen(true)}
              >
                <Plus className="h-4 w-4 mr-2" />
                Create Integration
              </Button>
            </div>
          </div>

          {/* Integrations Table */}
          {query.isError ? (
            <div className="text-center py-12">
              <p className="text-zinc-600 dark:text-zinc-400 mb-4">
                Error in fetching integrations, please try again later
              </p>
            </div>
          ) : query.isLoading ? (
            <div className="flex h-full items-center justify-center">
              <Loader2 className="size-10 animate-spin text-blue-600" />
            </div>
          ) : integrations.length === 0 ? (
            <div className="text-center py-12">
              <p className="text-zinc-600 dark:text-zinc-400 mb-4">
                No integrations yet. Create your first guardrails integration to get started.
              </p>
            </div>
          ) : (
            <>
              {/* Filter bar */}
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
                <div className="text-zinc-600 dark:text-zinc-400 text-sm">Sort by</div>
                <Select value={createdAtSort} onValueChange={(v) => setCreatedAtSort(v as "none" | "asc" | "desc")}>
                  <SelectTrigger className="h-9 min-w-[170px] cursor-pointer">
                    <SelectValue placeholder="Created at" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none" className="cursor-pointer">Default</SelectItem>
                    <SelectItem value="desc" className="cursor-pointer">Newest</SelectItem>
                    <SelectItem value="asc" className="cursor-pointer">Oldest</SelectItem>
                  </SelectContent>
                </Select>
                {hasActiveFilters && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-9 text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300 cursor-pointer"
                    onClick={clearFilters}
                  >
                    <X className="h-4 w-4 mr-1" />Clear filters
                  </Button>
                )}
              </div>

              {filteredIntegrations.length === 0 ? (
                <div className="text-center py-12">
                  <p className="text-zinc-600 dark:text-zinc-400 mb-4">No integrations match your filters.</p>
                  <Button variant="outline" className="cursor-pointer" onClick={clearFilters}>
                    <X className="h-4 w-4 mr-2" />Clear filters
                  </Button>
                </div>
              ) : (
            <div className="border rounded-lg overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[300px]">Title</TableHead>
                    <TableHead>Owner</TableHead>
                    <TableHead>Created At</TableHead>
                    <TableHead>Last Updated</TableHead>
                    <TableHead>API Key</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredIntegrations.map((integration) => (
                    <TableRow key={integration.id} className="hover:bg-zinc-50 dark:hover:bg-zinc-800">
                      <TableCell className="font-medium">
                        <Link
                          href={`/${team_id}/guardrails/${integration.id}`}
                          className="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 hover:underline cursor-pointer"
                        >
                          {integration.title}
                        </Link>
                      </TableCell>
                      <TableCell className="text-zinc-600 dark:text-zinc-400">
                        {integration.owner_user_full_name != null && integration.owner_user_full_name !== "" || integration.owner_user_email ? (
                          <div className="flex items-center gap-2">
                            <Avatar className="h-8 w-8 shrink-0">
                              <AvatarFallback className="bg-blue-600 text-white text-xs font-medium">
                                {integration.owner_user_full_name
                                  ? integration.owner_user_full_name
                                      .trim()
                                      .split(/\s+/)
                                      .map((p) => p.charAt(0))
                                      .slice(0, 2)
                                      .join("")
                                      .toUpperCase() || (integration.owner_user_email?.[0] ?? "?").toUpperCase()
                                  : (integration.owner_user_email?.[0] ?? "?").toUpperCase()}
                              </AvatarFallback>
                            </Avatar>
                            <div className="min-w-0">
                              {integration.owner_user_full_name != null && integration.owner_user_full_name !== "" && (
                                <span className="block truncate max-w-[160px]" title={integration.owner_user_email ?? ""}>
                                  {integration.owner_user_full_name}
                                </span>
                              )}
                              {integration.owner_user_email != null && integration.owner_user_email !== "" && (
                                <span className="block text-xs text-zinc-500 dark:text-zinc-400 truncate max-w-[160px]">
                                  {integration.owner_user_email}
                                </span>
                              )}
                            </div>
                          </div>
                        ) : (
                          "—"
                        )}
                      </TableCell>
                      <TableCell className="text-zinc-600 dark:text-zinc-400">
                        {formatDate(integration.created_at)}
                      </TableCell>
                      <TableCell className="text-zinc-600 dark:text-zinc-400">
                        {formatDate(integration.last_updated)}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <code className="text-sm bg-zinc-100 dark:bg-zinc-800 px-2 py-1 rounded font-mono">
                            {redactApiKey(integration.api_key)}
                          </code>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-7 w-7 cursor-pointer"
                            onClick={() => copyApiKey(integration.api_key, integration.id)}
                            title="Copy API key"
                          >
                            {copiedKeyId === integration.id ? (
                              <Check className="h-4 w-4 text-green-600" />
                            ) : (
                              <Copy className="h-4 w-4" />
                            )}
                          </Button>
                        </div>
                      </TableCell>
                      <TableCell className="text-right">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-8 w-8 cursor-pointer"
                            >
                              <MoreVertical className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem
                              className="cursor-pointer"
                              onClick={() => handleRename(integration)}
                            >
                              <Pencil className="h-4 w-4 mr-2" />
                              Rename
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              className="cursor-pointer"
                              onClick={() => handleDelete(integration)}
                              variant="destructive"
                            >
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
              )}
            </>
          )}

          {/* Dashboard: radial + radar (below table) — only when there are integrations */}
          {integrations.length > 0 && query.isLoading && (
            <div className="mt-8 flex items-center gap-2 text-zinc-500 dark:text-zinc-400">
              <Loader2 className="h-4 w-4 animate-spin" />
              <span className="text-sm">Loading dashboard…</span>
            </div>
          )}
          {integrations.length > 0 && dashboardData && (
            <div className="mt-8 space-y-6">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 w-full">
                {/* Log summary — radial chart */}
                <Card className="border-zinc-200 dark:border-zinc-800 flex-1 min-w-0">
                  <CardHeader>
                    <CardTitle className="text-base flex items-center gap-2">
                      <PieChart className="w-4 h-4" />
                      Log summary
                    </CardTitle>
                    <CardDescription>
                      Total: {dashboardData.card_data.total_logs} — proportion by status
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    {(() => {
                      const logKeys = [
                        { key: "success_logs" as const, label: "Success", color: "hsl(142 71% 45%)" },
                        { key: "failure_logs" as const, label: "Failure", color: "hsl(0 84% 60%)" },
                        { key: "pending_logs" as const, label: "Pending", color: "hsl(48 96% 53%)" },
                        { key: "started_logs" as const, label: "Started", color: "hsl(217 91% 60%)" },
                        { key: "not_started_logs" as const, label: "Not started", color: "hsl(262 83% 58%)" },
                      ];
                      const cd = dashboardData.card_data;
                      const radialData = logKeys.map(({ key, label, color }) => ({
                        name: label,
                        actualCount: cd[key] ?? 0,
                        fill: color,
                      }));
                      const maxCount = Math.max(1, ...radialData.map((d) => d.actualCount));
                      const radialDataNorm = radialData.map((d) => ({
                        ...d,
                        count: maxCount > 0 ? (d.actualCount / maxCount) * 100 : 0,
                      }));
                      const logChartConfig: ChartConfig = {
                        count: { label: "Count" },
                        ...Object.fromEntries(logKeys.map(({ label, color }) => [label, { label, color }])),
                      };
                      return (
                        <ChartContainer
                          config={logChartConfig}
                          className="mx-auto aspect-square max-h-[280px]"
                        >
                          <RadialBarChart
                            data={radialDataNorm}
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
                                  formatter={(_, __, ___, ____, payload) => {
                                    const count = (payload as { actualCount?: number } | undefined)?.actualCount ?? 0;
                                    return <span className="font-medium font-mono tabular-nums">{count}</span>;
                                  }}
                                />
                              }
                            />
                            <RadialBar dataKey="count" background className="cursor-pointer" />
                          </RadialBarChart>
                        </ChartContainer>
                      );
                    })()}
                    <div className="mt-4 pt-3 border-t border-zinc-200 dark:border-zinc-700 flex flex-wrap gap-x-4 gap-y-1.5 justify-center">
                      {["Success", "Failure", "Pending", "Started", "Not started"].map((label, i) => {
                        const colors = ["hsl(142 71% 45%)", "hsl(0 84% 60%)", "hsl(48 96% 53%)", "hsl(217 91% 60%)", "hsl(262 83% 58%)"];
                        return (
                          <div key={label} className="flex items-center gap-1.5 text-xs">
                            <span className="shrink-0 w-3 h-3 rounded-full" style={{ backgroundColor: colors[i] }} aria-hidden />
                            <span className="text-zinc-600 dark:text-zinc-400">{label}</span>
                          </div>
                        );
                      })}
                    </div>
                  </CardContent>
                </Card>

                {/* Past 30 days risk scores — radar chart */}
                <Card className="border-zinc-200 dark:border-zinc-800 flex-1 min-w-0">
                  <CardHeader>
                    <CardTitle className="text-base flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4" />
                      Past 30 days — risk scores
                    </CardTitle>
                    <CardDescription>
                      Counts by severity (Critical, High, Medium, Low)
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    {(() => {
                      const riskKeys = [
                        { key: "critical" as const, label: "Critical" },
                        { key: "high" as const, label: "High" },
                        { key: "medium" as const, label: "Medium" },
                        { key: "low" as const, label: "Low" },
                      ];
                      const riskData = riskKeys.map(({ key, label }) => ({
                        subject: label,
                        count: dashboardData.past_30_days_risk_score_data[key] ?? 0,
                      }));
                      const radarConfig: ChartConfig = {
                        subject: { label: "Severity" },
                        count: { label: "Count", color: "hsl(0 84% 60%)" },
                      };
                      return (
                        <ChartContainer config={radarConfig} className="mx-auto aspect-square max-h-[280px]">
                          <RadarChart data={riskData} margin={{ top: 8, right: 24, bottom: 8, left: 24 }}>
                            <ChartTooltip cursor={false} content={<ChartTooltipContent nameKey="subject" formatter={(value, name) => [value, name ?? "Count"]} />} />
                            <PolarAngleAxis dataKey="subject" />
                            <PolarGrid />
                            <Radar dataKey="count" fill="hsl(0 84% 60%)" fillOpacity={0.6} dot={{ r: 4, fillOpacity: 1 }} />
                          </RadarChart>
                        </ChartContainer>
                      );
                    })()}
                  </CardContent>
                </Card>
              </div>

              {/* High/critical risks per day (last 14 days) — line/area chart */}
              {(() => {
                const daily = dashboardData.high_or_critical_risks_daily_usage || {};
                const sortedEntries = Object.entries(daily)
                  .sort(([a], [b]) => a.localeCompare(b))
                  .slice(-14);
                const chartData = sortedEntries.length > 0
                  ? sortedEntries.map(([dateStr, count]) => ({ date: dateStr, count }))
                  : [];
                const highCriticalChartConfig: ChartConfig = {
                  date: { label: "Date" },
                  count: { label: "High / critical risks", color: "hsl(0 84% 60%)" },
                };
                if (chartData.length === 0) return null;
                return (
                  <Card className="border-zinc-200 dark:border-zinc-800 w-full">
                    <CardHeader>
                      <CardTitle className="text-base flex items-center gap-2">
                        <Activity className="w-4 h-4" />
                        High / critical risks by day (last 14 days)
                      </CardTitle>
                      <CardDescription>
                        Daily count of high- or critical-severity risks; dates on x-axis
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <ChartContainer config={highCriticalChartConfig} className="aspect-auto h-[280px] w-full pb-8">
                        <AreaChart data={chartData} margin={{ top: 8, right: 8, bottom: 28, left: 0 }}>
                          <defs>
                            <linearGradient id="fillGuardrailsHighCritical" x1="0" y1="0" x2="0" y2="1">
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
                            minTickGap={24}
                            height={40}
                            tickFormatter={(v) => {
                              return formatDateOnlyIst(v);
                            }}
                          />
                          <YAxis hide domain={[0, "auto"]} />
                          <ChartTooltip
                            cursor={false}
                            content={
                              <ChartTooltipContent
                                labelFormatter={(v) => formatMediumDateIst(v)}
                              />
                            }
                          />
                          <Area type="monotone" dataKey="count" fill="url(#fillGuardrailsHighCritical)" stroke="hsl(0 84% 60%)" strokeWidth={2} />
                        </AreaChart>
                      </ChartContainer>
                    </CardContent>
                  </Card>
                );
              })()}
            </div>
          )}
        </div>
      </div>

      {/* Rename Dialog */}
      <Dialog open={renameDialogOpen} onOpenChange={setRenameDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Rename Integration</DialogTitle>
            <DialogDescription>
              Enter a new name for this integration.
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <Input
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="Integration name"
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
            <DialogTitle>Delete Integration</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete "{selectedIntegration?.title}"? This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              className="cursor-pointer"
              onClick={() => {
                setDeleteDialogOpen(false);
                setSelectedIntegration(null);
              }}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              className="cursor-pointer"
              onClick={confirmDelete}
            >
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Create Dialog */}
      <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Guardrails Integration</DialogTitle>
            <DialogDescription>
              Enter a name for your guardrails integration. You can configure settings later from the integration dashboard.
            </DialogDescription>
          </DialogHeader>
          
          <div className="py-4">
            <div className="space-y-2">
              <Label htmlFor="title" className="cursor-pointer">Title *</Label>
              <Input
                id="title"
                value={formTitle}
                onChange={(e) => setFormTitle(e.target.value)}
                placeholder="Integration name"
                required
                onKeyDown={(e) => {
                  if (e.key === "Enter" && formTitle.trim()) {
                    createGuardrailsIntegrationMutation.mutate({
                      title: formTitle.trim(),
                    });
                  }
                }}
              />
            </div>
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              className="cursor-pointer"
              onClick={() => {
                setCreateDialogOpen(false);
                setFormTitle("");
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={() => {
                if (!formTitle.trim()) {
                  toast.error("Title is required");
                  return;
                }
                
                createGuardrailsIntegrationMutation.mutate({
                  title: formTitle.trim(),
                });
              }}
              disabled={!formTitle.trim() || createGuardrailsIntegrationMutation.isPending}
              className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
            >
              {createGuardrailsIntegrationMutation.isPending && (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              )}
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}


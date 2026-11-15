"use client";

import Link from "next/link";
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
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Plus, RefreshCcw, Loader2, MoreVertical, Pencil, Trash2, Search, X, TrendingUp } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { CicdIntegration, getCicdIntegrations, createCicdIntegration, CreateCicdIntegrationData, deleteCicdIntegration, renameCicdIntegration } from "@/utils/backend_api";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import { Area, AreaChart, CartesianGrid, XAxis, YAxis } from "recharts";
import { useQuery, useQueryClient, useMutation } from "@tanstack/react-query";
import { showErrorToast } from "@/utils/error-handler";
import { formatDateIst as formatDate, formatDateOnlyIst, formatMediumDateIst } from "@/utils/datetime";
import { toast } from "@/utils/toast";
import { useRouter, useParams } from "next/navigation";
import ApiKeyRevealDialog from "@/components/cicd/ApiKeyRevealDialog";
import { hasIssuedKey, keyStateLabel } from "@/components/cicd/apiKey";
import { singleFlight } from "@/components/cicd/singleFlight";

const vulnsOverTimeChartConfig = {
  date: { label: "Date" },
  Critical: { label: "Critical", color: "hsl(0 84% 60%)" },
  High: { label: "High", color: "hsl(25 95% 53%)" },
  Medium: { label: "Medium", color: "hsl(48 96% 53%)" },
  Low: { label: "Low", color: "hsl(142 71% 45%)" },
} satisfies ChartConfig;

export default function CicdPage() {
  const params = useParams();
  const team_id = params?.team_id as string | undefined;
  const queryClient = useQueryClient();
  const [integrations, setIntegrations] = useState<CicdIntegration[]>([]);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [renameDialogOpen, setRenameDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [selectedIntegration, setSelectedIntegration] = useState<CicdIntegration | null>(null);
  const [newName, setNewName] = useState("");
  // issue #99: the one-time key of the integration just created; shown in ApiKeyRevealDialog, never stored
  const [issued, setIssued] = useState<{ integrationId: number; apiKey: string; scanType: string } | null>(null);
  const [formTitle, setFormTitle] = useState("");
  const [formScanType, setFormScanType] = useState<"sast" | "dast" | "cbom" | "">("");
  const [searchQuery, setSearchQuery] = useState("");
  const [createdAtSort, setCreatedAtSort] = useState<"none" | "asc" | "desc">("none");
  const router = useRouter();
  const query = useQuery({ 
    queryKey: ['cicd-integrations', team_id], 
    queryFn: () => getCicdIntegrations(Number(team_id)),
    enabled: !!team_id,
  });

  const dashboardData = query.data?.dashboard_data;
  const vulnsOverTimeChartArray = useMemo(() => {
    if (!dashboardData || typeof dashboardData !== "object") return [];
    return Object.entries(dashboardData)
      .map(([date, counts]) => ({
        date,
        Critical: counts?.Critical ?? 0,
        High: counts?.High ?? 0,
        Medium: counts?.Medium ?? 0,
        Low: counts?.Low ?? 0,
      }))
      .sort((a, b) => a.date.localeCompare(b.date));
  }, [dashboardData]);

  const hasVulnsOverTimeData = vulnsOverTimeChartArray.length > 0 && vulnsOverTimeChartArray.some(
    (d) => d.Critical > 0 || d.High > 0 || d.Medium > 0 || d.Low > 0
  );

  useEffect(() => {
    if (query.data?.integrations) {
      setIntegrations(query.data.integrations);
    }
    if (query.error) {
      showErrorToast(query.error, 'Error fetching CI/CD integrations');
    }
  }, [query.data, query.error]);

  const createCicdIntegrationMutation = useMutation({
    mutationFn: (data: CreateCicdIntegrationData) => createCicdIntegration(Number(team_id), data),
    onSuccess: (data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['cicd-integrations', team_id] });
      setCreateDialogOpen(false);
      setFormTitle("");
      setFormScanType("");
      // (createCicdIntegration already toasts "CI/CD integration created")
      // Show the key once before leaving this page (the create answer is the only place it exists)
      if (hasIssuedKey(data)) {
        setIssued({ integrationId: data.integration_id, apiKey: data.api_key, scanType: variables.scan_type });
      } else {
        router.push(`/${team_id}/ci_cd/${data.integration_id}`);
      }
    },
    onError: (error) => {
      showErrorToast(error);
    }
  });

  // One create at a time: a double Enter (or Enter then a click) before isPending re-renders would start two creates,
  // and only the second integration's one-time key would be shown (components/cicd/singleFlight.ts).
  const createAsync = createCicdIntegrationMutation.mutateAsync;
  const createOnce = useMemo(() => singleFlight((data: CreateCicdIntegrationData) => createAsync(data)), [createAsync]);
  const submitCreate = () => {
    if (!formTitle.trim()) {
      toast.error("Title is required");
      return;
    }
    if (!formScanType) {
      toast.error("Scan type is required");
      return;
    }
    if (createCicdIntegrationMutation.isPending) return;
    createOnce({ title: formTitle.trim(), scan_type: formScanType as "sast" | "dast" | "cbom" });
  };

  const deleteCicdIntegrationMutation = useMutation({
    mutationFn: (integration_id: number) => deleteCicdIntegration(Number(team_id), integration_id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cicd-integrations', team_id] });
      toast.success('CI/CD integration deleted');
      setDeleteDialogOpen(false);
      setSelectedIntegration(null);
    },
    onError: (error) => {
      showErrorToast(error);
    }
  });

  const renameCicdIntegrationMutation = useMutation({
    mutationFn: ({ integration_id, title }: { integration_id: number; title: string }) =>
      renameCicdIntegration({ team_id: Number(team_id), integration_id, title }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cicd-integrations', team_id] });
      toast.success('CI/CD integration renamed');
      setRenameDialogOpen(false);
      setSelectedIntegration(null);
      setNewName("");
    },
    onError: (error) => {
      showErrorToast(error);
    }
  });

  const handleRename = (integration: CicdIntegration) => {
    setSelectedIntegration(integration);
    setNewName(integration.title);
    setRenameDialogOpen(true);
  };

  const handleDelete = (integration: CicdIntegration) => {
    setSelectedIntegration(integration);
    setDeleteDialogOpen(true);
  };

  const confirmRename = () => {
    if (selectedIntegration && newName.trim()) {
      renameCicdIntegrationMutation.mutate({ integration_id: selectedIntegration.id, title: newName.trim() });
    }
  };

  const confirmDelete = () => {
    if (selectedIntegration) {
      deleteCicdIntegrationMutation.mutate(selectedIntegration.id);
    }
  };


  const hasActiveFilters = searchQuery !== "" || createdAtSort !== "none";
  const filteredIntegrations = integrations
    .filter((i) => {
      if (searchQuery && !i.title.toLowerCase().includes(searchQuery.toLowerCase())) return false;
      return true;
    })
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
                CI/CD Integrations
              </h1>
              <p className="text-zinc-600 dark:text-zinc-400">
                Manage and view all your CI/CD integrations.
              </p>
            </div>
            <div className="flex flex-row items-center gap-2">
              <Button 
                className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
                onClick={() => queryClient.invalidateQueries({ queryKey: ['cicd-integrations'] })}
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
                No integrations yet. Create your first CI/CD integration to get started.
              </p>
              <Button 
                className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
                onClick={() => setCreateDialogOpen(true)}
              >
                <Plus className="h-4 w-4 mr-2" />
                Create Integration
              </Button>
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
                    <TableHead>Scan Type</TableHead>
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
                          href={`/${team_id}/ci_cd/${integration.id}`}
                          className="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 hover:underline cursor-pointer"
                        >
                          {integration.title}
                        </Link>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="capitalize">
                          {integration.scan_type}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-zinc-600 dark:text-zinc-400">
                        {formatDate(integration.created_at)}
                      </TableCell>
                      <TableCell className="text-zinc-600 dark:text-zinc-400">
                        {formatDate(integration.last_updated)}
                      </TableCell>
                      <TableCell>
                        <span
                          className={`text-sm ${integration.api_key_state === "revoked" ? "text-red-700 dark:text-red-300" : "text-zinc-700 dark:text-zinc-300"}`}
                          title="The key is shown once, when it is issued. Open the integration to rotate or revoke it."
                        >
                          {keyStateLabel(integration)}
                        </span>
                      </TableCell>
                      <TableCell className="text-right">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-8 w-8 cursor-pointer"
                              aria-label={`Actions for ${integration.title}`}
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

              {/* Vulnerabilities over time (all integrations) - below table */}
              {!query.isLoading && !query.isError && (
                <Card className="mt-6 border-zinc-200 dark:border-zinc-800">
                  <CardHeader>
                    <CardTitle className="text-base flex items-center gap-2">
                      <TrendingUp className="w-4 h-4" />
                      Vulnerabilities over time by severity
                    </CardTitle>
                    <CardDescription>
                      Count of findings per scan date across all integrations (Critical, High, Medium, Low)
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    {!hasVulnsOverTimeData ? (
                      <div className="flex items-center justify-center min-h-[280px] text-zinc-500 dark:text-zinc-400 text-sm">
                        No vulnerability data to display. Run scans to see trends over time.
                      </div>
                    ) : (
                      <ChartContainer config={vulnsOverTimeChartConfig} className="aspect-auto h-[280px] w-full pb-8">
                        <AreaChart data={vulnsOverTimeChartArray} margin={{ top: 8, right: 8, bottom: 28, left: 0 }}>
                          <defs>
                            <linearGradient id="fillCicdListCritical" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="hsl(0 84% 60%)" stopOpacity={0.8} />
                              <stop offset="95%" stopColor="hsl(0 84% 60%)" stopOpacity={0.1} />
                            </linearGradient>
                            <linearGradient id="fillCicdListHigh" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="hsl(25 95% 53%)" stopOpacity={0.8} />
                              <stop offset="95%" stopColor="hsl(25 95% 53%)" stopOpacity={0.1} />
                            </linearGradient>
                            <linearGradient id="fillCicdListMedium" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="hsl(48 96% 53%)" stopOpacity={0.8} />
                              <stop offset="95%" stopColor="hsl(48 96% 53%)" stopOpacity={0.1} />
                            </linearGradient>
                            <linearGradient id="fillCicdListLow" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="hsl(142 71% 45%)" stopOpacity={0.8} />
                              <stop offset="95%" stopColor="hsl(142 71% 45%)" stopOpacity={0.1} />
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
                          <Area type="monotone" dataKey="Critical" fill="url(#fillCicdListCritical)" stroke="hsl(0 84% 60%)" strokeWidth={2} />
                          <Area type="monotone" dataKey="High" fill="url(#fillCicdListHigh)" stroke="hsl(25 95% 53%)" strokeWidth={2} />
                          <Area type="monotone" dataKey="Medium" fill="url(#fillCicdListMedium)" stroke="hsl(48 96% 53%)" strokeWidth={2} />
                          <Area type="monotone" dataKey="Low" fill="url(#fillCicdListLow)" stroke="hsl(142 71% 45%)" strokeWidth={2} />
                        </AreaChart>
                      </ChartContainer>
                    )}
                  </CardContent>
                </Card>
              )}
            </>
          )}
        </div>
      </div>

      <ApiKeyRevealDialog
        apiKey={issued?.apiKey ?? null}
        scanType={issued?.scanType ?? "sast"}
        title="Integration created: save your API key"
        onDone={() => {
          const id = issued?.integrationId;
          setIssued(null);
          if (id) router.push(`/${team_id}/ci_cd/${id}`);
        }}
      />

      {/* Create Dialog */}
      <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create CI/CD Integration</DialogTitle>
            <DialogDescription>
              Enter the details for your new CI/CD integration.
            </DialogDescription>
          </DialogHeader>
          
          <div className="py-4 space-y-4">
            <div className="space-y-2">
              <Label htmlFor="title" className="cursor-pointer">Title *</Label>
              <Input
                id="title"
                value={formTitle}
                onChange={(e) => setFormTitle(e.target.value)}
                placeholder="Integration name"
                required
                onKeyDown={(e) => {
                  if (e.key === "Enter" && formTitle.trim() && formScanType && !createCicdIntegrationMutation.isPending) submitCreate();
                }}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="scan_type" className="cursor-pointer">Scan Type *</Label>
              <Select
                value={formScanType}
                onValueChange={(value) => setFormScanType(value as "sast" | "dast" | "cbom")}
              >
                <SelectTrigger id="scan_type" className="cursor-pointer">
                  <SelectValue placeholder="Select scan type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="sast" className="cursor-pointer">SAST</SelectItem>
                  <SelectItem value="dast" className="cursor-pointer">DAST</SelectItem>
                  <SelectItem value="cbom" className="cursor-pointer">CBOM</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              className="cursor-pointer"
              onClick={() => {
                setCreateDialogOpen(false);
                setFormTitle("");
                setFormScanType("");
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={submitCreate}
              disabled={!formTitle.trim() || !formScanType || createCicdIntegrationMutation.isPending}
              className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
            >
              {createCicdIntegrationMutation.isPending && (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              )}
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

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
                setSelectedIntegration(null);
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={confirmRename}
              disabled={!newName.trim() || renameCicdIntegrationMutation.isPending}
              className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
            >
              {renameCicdIntegrationMutation.isPending && (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              )}
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
              disabled={deleteCicdIntegrationMutation.isPending}
            >
              {deleteCicdIntegrationMutation.isPending && (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              )}
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}


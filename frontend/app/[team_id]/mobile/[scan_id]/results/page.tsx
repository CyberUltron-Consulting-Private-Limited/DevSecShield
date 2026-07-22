"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft,
  Loader2,
  Search,
  X,
  Shield,
  AlertTriangle,
  Smartphone,
  Activity,
  Target,
  AlertCircle,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { toast } from "sonner";
import {
  getMobileScanData,
  type MobileFinding,
  type RemediationData,
} from "@/utils/backend_api";
import RemediationPanel from "@/components/RemediationPanel";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
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
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  ChartLegend,
  ChartLegendContent,
  type ChartConfig,
} from "@/components/ui/chart";
import { Cell, Pie, PieChart } from "recharts";

const PAGE_SIZE = 10;

type OwaspOrCompliance = Record<string, string> | Array<Record<string, string>> | null | undefined;

function getOwaspComplianceEntries(val: OwaspOrCompliance): [string, string][] {
  if (val == null) return [];
  if (Array.isArray(val)) {
    return val.flatMap((item) => {
      if (item && typeof item === "object") {
        return Object.entries(item).filter(([, v]) => v != null && String(v).trim() !== "") as [string, string][];
      }
      return [];
    });
  }
  if (typeof val === "object") {
    return Object.entries(val).filter(([, v]) => v != null && String(v).trim() !== "") as [string, string][];
  }
  return [];
}

function getOwaspComplianceCount(val: OwaspOrCompliance): number {
  return getOwaspComplianceEntries(val).length;
}

const GENERIC_SUGGESTED_FIX =
  "Review and remediate according to mobile security best practices.";

function hasScannerSuggestedFix(fix?: string | null): boolean {
  const trimmed = (fix ?? "").trim();
  return !!trimmed && trimmed !== GENERIC_SUGGESTED_FIX;
}

function impactClass(impact: string) {
  const i = impact.toLowerCase();
  if (i === "critical") return "bg-red-600 hover:bg-red-600";
  if (i === "high") return "bg-orange-500 hover:bg-orange-500";
  if (i === "medium") return "bg-amber-500 hover:bg-amber-500";
  if (i === "low") return "bg-blue-500 hover:bg-blue-500";
  return "bg-zinc-500";
}

export default function MobileResultsPage() {
  const params = useParams();
  const team_id = parseInt((params?.team_id as string) ?? "0", 10);
  const scan_id = parseInt((params?.scan_id as string) ?? "0", 10);
  const hasValidIds = !!team_id && !!scan_id;
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [selectedFinding, setSelectedFinding] = useState<MobileFinding | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ["mobile-conversation-data", team_id, scan_id],
    queryFn: getMobileScanData,
    enabled: hasValidIds,
  });

  const findings: MobileFinding[] = query.data?.findings ?? [];
  const dashboard = query.data?.dashboard;
  const summary = dashboard?.mobile_summary || query.data?.scan_metadata?.mobile_summary;

  const categories = useMemo(() => {
    const set = new Set<string>();
    findings.forEach((f) => {
      if (f.category) set.add(f.category);
    });
    return Array.from(set).sort();
  }, [findings]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return findings.filter((f) => {
      const matchesSearch =
        !q ||
        f.title.toLowerCase().includes(q) ||
        (f.description || "").toLowerCase().includes(q) ||
        (f.category || "").toLowerCase().includes(q) ||
        (f.location || "").toLowerCase().includes(q) ||
        (f.rule_id || "").toLowerCase().includes(q);
      const matchesSeverity =
        severityFilter === "all" ||
        (f.impact || "").toLowerCase() === severityFilter.toLowerCase();
      const matchesCategory =
        categoryFilter === "all" || (f.category || "") === categoryFilter;
      return matchesSearch && matchesSeverity && matchesCategory;
    });
  }, [findings, search, severityFilter, categoryFilter]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));

  useEffect(() => {
    setCurrentPage(1);
  }, [search, severityFilter, categoryFilter]);

  useEffect(() => {
    if (currentPage > totalPages) {
      setCurrentPage(totalPages);
    }
  }, [currentPage, totalPages]);

  const paginatedFindings = useMemo(() => {
    const start = (currentPage - 1) * PAGE_SIZE;
    return filtered.slice(start, start + PAGE_SIZE);
  }, [filtered, currentPage]);

  const pageStart = filtered.length === 0 ? 0 : (currentPage - 1) * PAGE_SIZE + 1;
  const pageEnd = Math.min(currentPage * PAGE_SIZE, filtered.length);

  const hasActiveFilters =
    search.trim() !== "" || severityFilter !== "all" || categoryFilter !== "all";

  const pieData = useMemo(() => {
    const sev = dashboard?.severity_distribution || {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    };
    return [
      { name: "Critical", value: sev.critical, fill: "#dc2626" },
      { name: "High", value: sev.high, fill: "#ea580c" },
      { name: "Medium", value: sev.medium, fill: "#ca8a04" },
      { name: "Low", value: sev.low, fill: "#2563eb" },
    ].filter((d) => d.value > 0);
  }, [dashboard]);

  const complianceMetrics = dashboard?.compliance_controls_metrics ?? {};
  const owaspMetrics = dashboard?.owasp_top_10_metrics ?? {};
  const topCompliance = Object.entries(complianceMetrics)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 8);
  const topOwasp = Object.entries(owaspMetrics)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 8);

  const chartConfig = {
    Critical: { label: "Critical" },
    High: { label: "High" },
    Medium: { label: "Medium" },
    Low: { label: "Low" },
  } satisfies ChartConfig;

  if (!hasValidIds) {
    toast.error("Team or scan id not found");
    return null;
  }

  if (query.isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-white dark:bg-zinc-900">
        <Loader2 className="size-10 animate-spin text-blue-600" />
      </div>
    );
  }

  if (query.isError) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-white dark:bg-zinc-900 text-zinc-500">
        Failed to load results
      </div>
    );
  }

  const card = dashboard?.card_data;

  return (
    <div className="min-h-screen bg-white dark:bg-zinc-900">
      <div className="max-w-7xl mx-auto p-6 md:p-8 space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3 min-w-0">
            <Button variant="ghost" size="icon" className="shrink-0" asChild>
              <Link href={`/${team_id}/mobile`}>
                <ArrowLeft className="size-4" />
              </Link>
            </Button>
            <div className="min-w-0">
              <h1 className="text-2xl font-bold text-zinc-900 dark:text-white truncate">
                {query.data?.title || "Mobile App Security Results"}
              </h1>
              <p className="text-sm text-zinc-500 truncate">
                {[summary?.app_name, summary?.package_name, summary?.version_name, summary?.platform]
                  .filter(Boolean)
                  .join(" · ") || "Static analysis results"}
              </p>
            </div>
          </div>
          <Button variant="outline" className="shrink-0" asChild>
            <Link href={`/${team_id}/mobile/${scan_id}`}>Chat with results</Link>
          </Button>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
          <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
            <CardContent className="p-0">
              <div className="flex flex-col items-start gap-2">
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-blue-500/15">
                  <Target className="h-4 w-4 text-blue-500" />
                </div>
                <div>
                  <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Findings</p>
                  <p className="text-xl font-bold">{card?.total_findings ?? findings.length}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
            <CardContent className="p-0">
              <div className="flex flex-col items-start gap-2">
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-red-500/15">
                  <AlertCircle className="h-4 w-4 text-red-500" />
                </div>
                <div>
                  <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Critical</p>
                  <p className="text-xl font-bold">{card?.total_critical ?? 0}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
            <CardContent className="p-0">
              <div className="flex flex-col items-start gap-2">
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-orange-500/15">
                  <AlertTriangle className="h-4 w-4 text-orange-500" />
                </div>
                <div>
                  <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">High</p>
                  <p className="text-xl font-bold">{card?.total_high ?? 0}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
            <CardContent className="p-0">
              <div className="flex flex-col items-start gap-2">
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-amber-500/15">
                  <AlertTriangle className="h-4 w-4 text-amber-500" />
                </div>
                <div>
                  <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Medium</p>
                  <p className="text-xl font-bold">{card?.total_medium ?? 0}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
            <CardContent className="p-0">
              <div className="flex flex-col items-start gap-2">
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-blue-500/15">
                  <Shield className="h-4 w-4 text-blue-500" />
                </div>
                <div>
                  <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Low</p>
                  <p className="text-xl font-bold">{card?.total_low ?? 0}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
            <CardContent className="p-0">
              <div className="flex flex-col items-start gap-2">
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-green-500/15">
                  <Activity className="h-4 w-4 text-green-500" />
                </div>
                <div>
                  <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Security score</p>
                  <p className="text-xl font-bold">{card?.security_score ?? summary?.security_score ?? "—"}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {pieData.length > 0 && (
          <Card className="border-zinc-200 dark:border-zinc-800">
            <CardHeader>
              <CardTitle className="text-base">Severity distribution</CardTitle>
              <CardDescription>Breakdown of findings by impact level</CardDescription>
            </CardHeader>
            <CardContent>
              <ChartContainer config={chartConfig} className="mx-auto aspect-square max-h-[260px]">
                <PieChart>
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <ChartLegend content={<ChartLegendContent nameKey="name" />} />
                  <Pie
                    data={pieData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={90}
                    paddingAngle={2}
                  >
                    {pieData.map((entry) => (
                      <Cell key={entry.name} fill={entry.fill} />
                    ))}
                  </Pie>
                </PieChart>
              </ChartContainer>
            </CardContent>
          </Card>
        )}

        {(topCompliance.length > 0 || topOwasp.length > 0) && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {topCompliance.length > 0 && (
              <Card className="border-zinc-200 dark:border-zinc-800">
                <CardHeader>
                  <CardTitle className="text-base">Compliance mappings</CardTitle>
                  <CardDescription>MASVS, CWE, CVSS, and MSTG references from code findings</CardDescription>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-2 text-sm">
                    {topCompliance.map(([label, count]) => (
                      <li key={label} className="flex items-start justify-between gap-3">
                        <span className="text-zinc-600 dark:text-zinc-400 break-words">{label}</span>
                        <Badge variant="secondary" className="shrink-0 tabular-nums">
                          {count}
                        </Badge>
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            )}
            {topOwasp.length > 0 && (
              <Card className="border-zinc-200 dark:border-zinc-800">
                <CardHeader>
                  <CardTitle className="text-base">OWASP Mobile Top 10</CardTitle>
                  <CardDescription>Mapped mobile risk categories from code findings</CardDescription>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-2 text-sm">
                    {topOwasp.map(([label, count]) => (
                      <li key={label} className="flex items-start justify-between gap-3">
                        <span className="text-zinc-600 dark:text-zinc-400 break-words">{label}</span>
                        <Badge variant="secondary" className="shrink-0 tabular-nums">
                          {count}
                        </Badge>
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            )}
          </div>
        )}

        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader>
            <CardTitle>Findings</CardTitle>
            <CardDescription>
              {findings.length} findings from static analysis. Click a row to view full details.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex flex-wrap items-center gap-3">
              <div className="relative flex-1 min-w-[220px] max-w-md">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-400" />
                <Input
                  type="search"
                  placeholder="Search title, description, location..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="pl-9 h-9 w-full"
                />
              </div>
              <Select value={severityFilter} onValueChange={setSeverityFilter}>
                <SelectTrigger className="h-9 min-w-[160px] w-[160px] shrink-0">
                  <SelectValue placeholder="Severity" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All severities</SelectItem>
                  <SelectItem value="Critical">Critical</SelectItem>
                  <SelectItem value="High">High</SelectItem>
                  <SelectItem value="Medium">Medium</SelectItem>
                  <SelectItem value="Low">Low</SelectItem>
                </SelectContent>
              </Select>
              <Select value={categoryFilter} onValueChange={setCategoryFilter}>
                <SelectTrigger className="h-9 min-w-[180px] w-[180px] shrink-0">
                  <SelectValue placeholder="Category" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All categories</SelectItem>
                  {categories.map((cat) => (
                    <SelectItem key={cat} value={cat}>
                      {cat.replace(/_/g, " ")}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {hasActiveFilters && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-9 shrink-0"
                  onClick={() => {
                    setSearch("");
                    setSeverityFilter("all");
                    setCategoryFilter("all");
                  }}
                >
                  <X className="h-4 w-4 mr-1" />
                  Clear filters
                </Button>
              )}
            </div>

            {hasActiveFilters && (
              <p className="text-sm text-zinc-500">
                Showing {filtered.length} of {findings.length} findings
              </p>
            )}

            {filtered.length > 0 && (
              <p className="text-sm text-zinc-500">
                Page {currentPage} of {totalPages} · {pageStart}–{pageEnd} of {filtered.length}
              </p>
            )}

            <ScrollArea className="w-full rounded-md border border-zinc-200 dark:border-zinc-800">
              <div className="min-w-[900px]">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="min-w-[280px]">Title</TableHead>
                      <TableHead className="min-w-[120px]">Category</TableHead>
                      <TableHead className="min-w-[90px]">Impact</TableHead>
                      <TableHead className="min-w-[100px]">Standards</TableHead>
                      <TableHead className="min-w-[220px]">Location</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filtered.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={5} className="text-center text-zinc-500 py-12">
                          No findings match your filters
                        </TableCell>
                      </TableRow>
                    ) : (
                      paginatedFindings.map((f) => (
                        <TableRow
                          key={f.id}
                          className="cursor-pointer hover:bg-zinc-50 dark:hover:bg-zinc-800/60"
                          onClick={() => setSelectedFinding(f)}
                        >
                          <TableCell className="align-top">
                            <p className="font-medium text-zinc-900 dark:text-white whitespace-normal break-words">
                              {f.title}
                            </p>
                            {f.description && f.description !== f.title && (
                              <p className="text-sm text-zinc-500 mt-1 whitespace-normal break-words line-clamp-3">
                                {f.description}
                              </p>
                            )}
                          </TableCell>
                          <TableCell className="align-top text-sm capitalize">
                            {(f.category || "—").replace(/_/g, " ")}
                          </TableCell>
                          <TableCell className="align-top">
                            <Badge className={impactClass(f.impact)}>{f.impact}</Badge>
                          </TableCell>
                          <TableCell className="align-top text-sm text-zinc-600 dark:text-zinc-400 tabular-nums">
                            {(() => {
                              const count =
                                getOwaspComplianceCount(f.compliance_controls as OwaspOrCompliance) +
                                getOwaspComplianceCount(f.owasp_top_10 as OwaspOrCompliance);
                              return count > 0 ? count : "—";
                            })()}
                          </TableCell>
                          <TableCell className="align-top text-sm text-zinc-500 whitespace-normal break-all">
                            {f.location || "—"}
                          </TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
              </div>
              <ScrollBar orientation="horizontal" />
            </ScrollArea>

            {filtered.length > PAGE_SIZE && (
              <div className="flex items-center justify-between gap-4 pt-2">
                <p className="text-sm text-zinc-500">
                  {pageStart}–{pageEnd} of {filtered.length} findings
                </p>
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-9"
                    disabled={currentPage <= 1}
                    onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                  >
                    <ChevronLeft className="h-4 w-4 mr-1" />
                    Previous
                  </Button>
                  <span className="text-sm text-zinc-600 dark:text-zinc-400 tabular-nums min-w-[100px] text-center">
                    Page {currentPage} of {totalPages}
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-9"
                    disabled={currentPage >= totalPages}
                    onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                  >
                    Next
                    <ChevronRight className="h-4 w-4 ml-1" />
                  </Button>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <Dialog open={!!selectedFinding} onOpenChange={(open) => !open && setSelectedFinding(null)}>
        <DialogContent className="sm:max-w-3xl max-h-[90vh] flex flex-col p-0 gap-0 overflow-hidden">
          <DialogHeader className="px-6 pt-6 pb-2 shrink-0 border-b border-zinc-200 dark:border-zinc-800">
            <DialogTitle className="pr-8 text-left whitespace-normal break-words">
              {selectedFinding?.title}
            </DialogTitle>
          </DialogHeader>
          {selectedFinding && (
            <ScrollArea className="h-[70vh] min-h-[200px] w-full px-6 pb-6">
              <dl className="space-y-4 text-sm pt-4 pr-4 pb-4">
                <div>
                  <dt className="font-medium text-zinc-700 dark:text-zinc-300">Impact</dt>
                  <dd className="mt-1">
                    <Badge className={impactClass(selectedFinding.impact)}>{selectedFinding.impact}</Badge>
                  </dd>
                </div>
                {selectedFinding.category && (
                  <div>
                    <dt className="font-medium text-zinc-700 dark:text-zinc-300">Category</dt>
                    <dd className="mt-1 capitalize">{selectedFinding.category.replace(/_/g, " ")}</dd>
                  </div>
                )}
                {(selectedFinding.description || selectedFinding.title) && (
                  <div>
                    <dt className="font-medium text-zinc-700 dark:text-zinc-300">Description</dt>
                    <dd className="mt-1 text-zinc-600 dark:text-zinc-400 whitespace-pre-wrap break-words">
                      {selectedFinding.description || selectedFinding.title}
                    </dd>
                  </div>
                )}
                {selectedFinding.location && (
                  <div>
                    <dt className="font-medium text-zinc-700 dark:text-zinc-300">Location</dt>
                    <dd className="mt-1 font-mono text-xs break-all text-zinc-600 dark:text-zinc-400">
                      {selectedFinding.location}
                    </dd>
                  </div>
                )}
                {selectedFinding.rule_id && (
                  <div>
                    <dt className="font-medium text-zinc-700 dark:text-zinc-300">Rule</dt>
                    <dd className="mt-1 font-mono text-xs break-all">{selectedFinding.rule_id}</dd>
                  </div>
                )}
                {getOwaspComplianceEntries(selectedFinding.owasp_top_10 as OwaspOrCompliance).length > 0 && (
                  <div>
                    <dt className="font-medium text-zinc-700 dark:text-zinc-300">OWASP Mobile Top 10</dt>
                    <dd className="mt-2 flex flex-wrap gap-2">
                      {getOwaspComplianceEntries(selectedFinding.owasp_top_10 as OwaspOrCompliance).map(
                        ([, description]) => (
                          <Badge key={description} variant="outline" className="font-normal whitespace-normal">
                            {description}
                          </Badge>
                        )
                      )}
                    </dd>
                  </div>
                )}
                {getOwaspComplianceEntries(selectedFinding.compliance_controls as OwaspOrCompliance).length > 0 && (
                  <div>
                    <dt className="font-medium text-zinc-700 dark:text-zinc-300">Compliance & standards</dt>
                    <dd className="mt-2 space-y-2">
                      {getOwaspComplianceEntries(selectedFinding.compliance_controls as OwaspOrCompliance).map(
                        ([key, description]) => (
                          <div key={key} className="text-zinc-600 dark:text-zinc-400 break-words">
                            {key === "MSTG" || key === "OWASP_MSTG" ? (
                              <a
                                href={description}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-blue-600 hover:underline dark:text-blue-400"
                              >
                                OWASP MSTG reference
                              </a>
                            ) : (
                              description
                            )}
                          </div>
                        )
                      )}
                    </dd>
                  </div>
                )}
                {hasScannerSuggestedFix(selectedFinding.suggested_fix) ? (
                  <div>
                    <dt className="font-medium text-zinc-700 dark:text-zinc-300">Suggested fix</dt>
                    <dd className="mt-1 text-zinc-600 dark:text-zinc-400 whitespace-pre-wrap break-words">
                      {selectedFinding.suggested_fix}
                    </dd>
                  </div>
                ) : (
                  <div>
                    <dt className="font-medium text-zinc-700 dark:text-zinc-300">Suggested fix</dt>
                    <dd className="mt-1 text-zinc-500 dark:text-zinc-400">
                      No specific fix was provided for this finding. Use AI Remediation below for tailored
                      guidance.
                    </dd>
                  </div>
                )}
                {selectedFinding.id && (
                  <div className="pt-2 border-t border-zinc-200 dark:border-zinc-800">
                    <RemediationPanel
                      teamId={String(team_id)}
                      scanType="mobile"
                      scanId={scan_id}
                      findingId={selectedFinding.id}
                      existingRemediation={selectedFinding.remediation as RemediationData | null | undefined}
                      onRemediationGenerated={(data) => {
                        setSelectedFinding((prev) =>
                          prev ? { ...prev, remediation: data } : prev
                        );
                        queryClient.invalidateQueries({
                          queryKey: ["mobile-conversation-data", team_id, scan_id],
                        });
                      }}
                    />
                  </div>
                )}
              </dl>
              <ScrollBar orientation="vertical" />
            </ScrollArea>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

"use client";

import { useState, useMemo } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { 
  AlertTriangle, 
  Shield, 
  Search, 
  ArrowLeft,
  Brain,
  CheckCircle2,
  XCircle,
  TrendingUp,
  BarChart3
} from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Button } from "@/components/ui/button";
import { useRouter, useSearchParams } from "next/navigation";
import probeDisplayNames from "@/probe_display_names.json";

interface ProbeSummary {
  probe?: string;
  detector?: string;
  passed?: number;
  total?: number;
  hit_rate?: number;
}

interface LLMResultsData {
  status?: string;
  model_name?: string;
  total_tests?: number;
  total_hits?: number;
  hit_rate_percent?: number;
  risk_level?: string;
  probes_used?: string[];
  probes_summary?: Record<string, ProbeSummary>;
}

interface LLMResultsProps {
  data: LLMResultsData;
  conversationId?: number;
}

export default function LLMResults({ data, conversationId }: LLMResultsProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const origin = searchParams.get("origin") || "chat";
  const [searchQuery, setSearchQuery] = useState("");
  const [sortBy, setSortBy] = useState<string>("hit_rate");

  // Helper function to get display name for a probe
  const getProbeDisplayName = (probeName: string): string => {
    return (probeDisplayNames as Record<string, string>)[probeName] || probeName;
  };

  // Safe data extraction with fallbacks
  const status = data?.status || "unknown";
  const modelName = data?.model_name || "Unknown Model";
  const totalTests = data?.total_tests || 0;
  const totalHits = data?.total_hits || 0;
  const hitRatePercent = data?.hit_rate_percent || 0;
  const riskLevel = data?.risk_level || "unknown";
  const probesUsed = Array.isArray(data?.probes_used) ? data.probes_used : [];
  const probesSummary = data?.probes_summary || {};

  // Convert probes_summary object to array for easier processing
  const probeSummaries = useMemo(() => {
    return Object.entries(probesSummary).map(([key, summary]) => ({
      key,
      ...summary,
    }));
  }, [probesSummary]);

  // Filter and sort probe summaries
  const filteredProbes = useMemo(() => {
    let filtered = probeSummaries.filter((probe) => {
      const searchLower = searchQuery.toLowerCase();
      const probeName = probe.probe || "";
      const probeDisplayName = getProbeDisplayName(probeName);

      return (
        probeName.toLowerCase().includes(searchLower) ||
        probeDisplayName.toLowerCase().includes(searchLower)
      );
    });

    // Sort
    filtered.sort((a, b) => {
      switch (sortBy) {
        case "hit_rate":
          return (b.hit_rate || 0) - (a.hit_rate || 0);
        case "probe":
          const aDisplayName = getProbeDisplayName(a.probe || "");
          const bDisplayName = getProbeDisplayName(b.probe || "");
          return aDisplayName.localeCompare(bDisplayName);
        case "passed":
          return (b.passed || 0) - (a.passed || 0);
        case "total":
          return (b.total || 0) - (a.total || 0);
        default:
          return 0;
      }
    });

    return filtered;
  }, [probeSummaries, searchQuery, sortBy]);

  const getRiskLevelBadge = (level?: string) => {
    const risk = (level || "unknown").toLowerCase();
    const variants: Record<string, { className: string }> = {
      critical: { className: "bg-red-600 hover:bg-red-700 text-white" },
      high: { className: "bg-red-500 hover:bg-red-600 text-white" },
      medium: { className: "bg-orange-500 hover:bg-orange-600 text-white" },
      low: { className: "bg-green-500 hover:bg-green-600 text-white" },
    };
    const variant = variants[risk] || { className: "bg-gray-500 hover:bg-gray-600 text-white" };
    return (
      <Badge variant="outline" className={variant.className}>
        {level?.toUpperCase() || "UNKNOWN"}
      </Badge>
    );
  };

  const getStatusBadge = (status?: string) => {
    const stat = (status || "unknown").toLowerCase();
    if (stat === "completed") {
      return (
        <Badge variant="outline" className="bg-green-500 hover:bg-green-600 text-white">
          COMPLETED
        </Badge>
      );
    }
    return (
      <Badge variant="outline" className="bg-gray-500 hover:bg-gray-600 text-white">
        {status?.toUpperCase() || "UNKNOWN"}
      </Badge>
    );
  };

  const getHitRateColor = (hitRate: number) => {
    if (hitRate >= 50) return "text-red-600 dark:text-red-400";
    if (hitRate >= 25) return "text-orange-600 dark:text-orange-400";
    if (hitRate > 0) return "text-yellow-600 dark:text-yellow-400";
    return "text-green-600 dark:text-green-400";
  };

  return (
    <div className="container mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          {conversationId && (
            <Button
              variant="outline"
              size="icon"
              onClick={() => {
                const backRoute = origin === "list" 
                  ? `/home/llm` 
                  : `/home/llm/${conversationId}`;
                router.push(backRoute);
              }}
              className="cursor-pointer"
            >
              <ArrowLeft className="h-4 w-4" />
            </Button>
          )}
          <div>
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-white">LLM Security Scan Results</h1>
            <p className="text-sm text-zinc-600 dark:text-zinc-400 mt-1">
              Large Language Model security benchmark results
              {modelName && ` • Model: ${modelName}`}
            </p>
          </div>
        </div>
        {getStatusBadge(status)}
      </div>

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Tests</CardTitle>
            <BarChart3 className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{totalTests}</div>
            <p className="text-xs text-muted-foreground">Tests executed</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Hits</CardTitle>
            <AlertTriangle className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">{totalHits}</div>
            <p className="text-xs text-muted-foreground">Vulnerabilities detected</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Hit Rate</CardTitle>
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className={`text-2xl font-bold ${getHitRateColor(hitRatePercent)}`}>
              {hitRatePercent.toFixed(2)}%
            </div>
            <p className="text-xs text-muted-foreground">Vulnerability rate</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Risk Level</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              {getRiskLevelBadge(riskLevel)}
            </div>
            <p className="text-xs text-muted-foreground mt-2">Overall security risk</p>
          </CardContent>
        </Card>
      </div>

      {/* Probes Used Summary */}
      {probesUsed.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Brain className="h-5 w-5" />
              Probes Used ({probesUsed.length})
            </CardTitle>
            <CardDescription>
              Security probes that were executed during the scan
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {probesUsed.map((probe, idx) => (
                <Badge key={idx} variant="outline" className="text-xs">
                  {getProbeDisplayName(probe)}
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Filters and Search */}
      <Card>
        <CardHeader>
          <CardTitle>Filters</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search probes..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>
            <Select value={sortBy} onValueChange={setSortBy}>
              <SelectTrigger>
                <SelectValue placeholder="Sort By" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="hit_rate">Hit Rate (High to Low)</SelectItem>
                <SelectItem value="probe">Probe Name</SelectItem>
                <SelectItem value="passed">Passed (High to Low)</SelectItem>
                <SelectItem value="total">Total Tests (High to Low)</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Probe Results Table */}
      <Card>
        <CardHeader>
          <CardTitle>Probe Results ({filteredProbes.length})</CardTitle>
          <CardDescription>
            Detailed results for each security probe
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[600px]">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Probe</TableHead>
                  <TableHead>Passed</TableHead>
                  <TableHead>Total</TableHead>
                  <TableHead>Hit Rate</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredProbes.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center py-8 text-muted-foreground">
                      No probe results found matching your filters.
                    </TableCell>
                  </TableRow>
                ) : (
                  filteredProbes.map((probe, index) => {
                    const probeName = probe.probe || "Unknown";
                    const probeDisplayName = getProbeDisplayName(probeName);
                    const passed = probe.passed || 0;
                    const total = probe.total || 0;
                    const hitRate = probe.hit_rate || 0;
                    const failed = total - passed;

                    return (
                      <TableRow key={`${probe.key}-${index}`}>
                        <TableCell className="max-w-md">
                          <Accordion type="single" collapsible className="w-full">
                            <AccordionItem value={`item-${index}`} className="border-none">
                              <AccordionTrigger className="py-0 hover:no-underline">
                                <div className="text-left">
                                  <div className="font-semibold text-sm">
                                    {probeDisplayName}
                                  </div>
                                </div>
                              </AccordionTrigger>
                              <AccordionContent className="pt-2 pb-0">
                                <div className="space-y-2 text-sm">
                                  <div className="grid grid-cols-2 gap-2 pt-2">
                                    <div>
                                      <div className="text-xs text-muted-foreground">Passed</div>
                                      <div className="font-semibold text-green-600">{passed}</div>
                                    </div>
                                    <div>
                                      <div className="text-xs text-muted-foreground">Failed</div>
                                      <div className="font-semibold text-red-600">{failed}</div>
                                    </div>
                                  </div>
                                </div>
                              </AccordionContent>
                            </AccordionItem>
                          </Accordion>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <CheckCircle2 className="w-4 h-4 text-green-500" />
                            <span className="font-semibold">{passed}</span>
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="font-semibold">{total}</div>
                        </TableCell>
                        <TableCell>
                          <div className={`font-semibold ${getHitRateColor(hitRate * 100)}`}>
                            {(hitRate * 100).toFixed(2)}%
                          </div>
                        </TableCell>
                        <TableCell>
                          {hitRate === 0 ? (
                            <Badge variant="outline" className="bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200">
                              Secure
                            </Badge>
                          ) : hitRate < 0.25 ? (
                            <Badge variant="outline" className="bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200">
                              Low Risk
                            </Badge>
                          ) : hitRate < 0.5 ? (
                            <Badge variant="outline" className="bg-orange-100 dark:bg-orange-900 text-orange-800 dark:text-orange-200">
                              Medium Risk
                            </Badge>
                          ) : (
                            <Badge variant="outline" className="bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200">
                              High Risk
                            </Badge>
                          )}
                        </TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}


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
  FileText, 
  Search, 
  ArrowLeft,
  Code,
  ExternalLink,
  Clock,
  CheckCircle2,
  XCircle,
  AlertCircle
} from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Button } from "@/components/ui/button";
import { useRouter, useSearchParams } from "next/navigation";

interface Location {
  line?: number;
  col?: number;
  offset?: number;
}

interface Metavar {
  start?: Location;
  end?: Location;
  abstract_content?: string;
  propagated_value?: {
    svalue_start?: Location;
    svalue_end?: Location;
    svalue_abstract_content?: string;
  };
}

interface Metadata {
  likelihood?: string;
  impact?: string;
  confidence?: string;
  category?: string;
  subcategory?: string[];
  cwe?: string[];
  cwe2020_top25?: boolean;
  cwe2021_top25?: boolean;
  cwe2022_top25?: boolean;
  "display-name"?: string;
  "functional-categories"?: string[];
  owasp?: string[];
  references?: string[];
  technology?: string[];
  license?: string;
  vulnerability_class?: string[];
  source?: string;
  shortlink?: string;
  semgrep?: {
    rule?: {
      origin?: string;
      r_id?: number;
      rule_id?: string;
      rv_id?: number;
      url?: string;
      version_id?: string;
    };
  };
}

interface DataflowTrace {
  taint_source?: Array<string | Array<{
    path?: string;
    start?: Location;
    end?: Location;
  }>>;
  intermediate_vars?: Array<{
    location?: {
      path?: string;
      start?: Location;
      end?: Location;
    };
    content?: string;
  }>;
  taint_sink?: Array<string | Array<{
    path?: string;
    start?: Location;
    end?: Location;
  }>>;
}

interface SASTResult {
  check_id?: string;
  path?: string;
  start?: Location;
  end?: Location;
  extra?: {
    metavars?: Record<string, Metavar>;
    message?: string;
    metadata?: Metadata;
    severity?: string;
    fingerprint?: string;
    lines?: string;
    is_ignored?: boolean;
    validation_state?: string;
    dataflow_trace?: DataflowTrace;
    engine_kind?: string;
  };
  severity?: string;
  fingerprint?: string;
  lines?: string;
  snippet?: string;
  is_ignored?: boolean;
  validation_state?: string;
  dataflow_trace?: DataflowTrace;
  engine_kind?: string;
}

interface SASTError {
  code?: number;
  level?: string;
  type?: string;
  message?: string;
  path?: string;
  rule_id?: string;
}

interface SASTResultsData {
  version?: string;
  results?: SASTResult[];
  errors?: SASTError[];
  paths?: {
    scanned?: string[];
    skipped?: Array<{
      path?: string;
      reason?: string;
    }>;
  };
  time?: {
    rules_parse_time?: number;
    profiling_times?: {
      config_time?: number;
      core_time?: number;
      ignores_time?: number;
      total_time?: number;
    };
    scanning_time?: {
      total_time?: number;
      per_file_time?: {
        mean?: number;
        std_dev?: number;
      };
    };
  };
  engine_requested?: string;
  interfile_languages_used?: string[];
  skipped_rules?: string[];
}

interface SASTResultsProps {
  data: SASTResultsData;
  conversationId?: number;
}

export default function SASTResults({ data, conversationId }: SASTResultsProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const origin = searchParams.get("origin") || "chat";
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [checkFilter, setCheckFilter] = useState<string>("all");
  const [sortBy, setSortBy] = useState<string>("severity");

  // Parse path to show only from repo_xxxxxxx onwards
  const getRelativePath = (path?: string): string => {
    if (!path) return "Unknown";
    try {
      const repoIndex = path.indexOf("repo_");
      if (repoIndex !== -1) {
        return path.substring(repoIndex);
      }
      return path;
    } catch {
      return path;
    }
  };

  const getFileName = (filePath?: string) => {
    if (!filePath) return "Unknown";
    const relativePath = getRelativePath(filePath);
    return relativePath.split('\\').pop()?.split('/').pop() || relativePath;
  };

  // Safe data extraction with fallbacks
  const results: SASTResult[] = Array.isArray(data?.results) ? data.results : [];
  const errors: SASTError[] = Array.isArray(data?.errors) ? data.errors : [];
  const scannedPaths = Array.isArray(data?.paths?.scanned) ? data.paths.scanned : [];
  const skippedPaths = Array.isArray(data?.paths?.skipped) ? data.paths.skipped : [];

  // Calculate statistics
  const stats = useMemo(() => {
    const total = results.length;
    const bySeverity = results.reduce((acc, result) => {
      const severity = result.severity || result.extra?.severity || "UNKNOWN";
      acc[severity] = (acc[severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const byCheck = results.reduce((acc, result) => {
      const checkId = result.check_id || "Unknown";
      const checkName = checkId.split('.').pop() || checkId;
      acc[checkName] = (acc[checkName] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const byFile = results.reduce((acc, result) => {
      const file = getRelativePath(result.path);
      acc[file] = (acc[file] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const byCWE = results.reduce((acc, result) => {
      const cweList = result.extra?.metadata?.cwe || [];
      cweList.forEach((cwe) => {
        const cweId = cwe.split(':')[0] || cwe;
        acc[cweId] = (acc[cweId] || 0) + 1;
      });
      return acc;
    }, {} as Record<string, number>);

    const ignoredCount = results.filter((r) => r.is_ignored || r.extra?.is_ignored).length;
    const uniqueFiles = new Set(results.map((r) => r.path).filter(Boolean)).size;

    return {
      total,
      bySeverity,
      byCheck,
      byFile,
      byCWE,
      ignoredCount,
      uniqueFiles,
      errors: errors.length,
      scannedFiles: scannedPaths.length,
      skippedFiles: skippedPaths.length,
    };
  }, [results, errors, scannedPaths, skippedPaths]);

  // Filter and sort results
  const filteredResults = useMemo(() => {
    let filtered = results.filter((result) => {
      const searchLower = searchQuery.toLowerCase();
      const checkId = result.check_id || "";
      const message = result.extra?.message || "";
      const path = getRelativePath(result.path);
      const displayName = result.extra?.metadata?.["display-name"] || "";

      const matchesSearch =
        checkId.toLowerCase().includes(searchLower) ||
        message.toLowerCase().includes(searchLower) ||
        path.toLowerCase().includes(searchLower) ||
        displayName.toLowerCase().includes(searchLower);

      const severity = result.severity || result.extra?.severity || "UNKNOWN";
      const matchesSeverity =
        severityFilter === "all" || severity === severityFilter;

      const checkName = checkId.split('.').pop() || checkId;
      const matchesCheck =
        checkFilter === "all" || checkName === checkFilter;

      return matchesSearch && matchesSeverity && matchesCheck;
    });

    // Sort
    filtered.sort((a, b) => {
      switch (sortBy) {
        case "severity":
          const severityOrder: Record<string, number> = {
            ERROR: 4,
            WARNING: 3,
            INFO: 2,
            UNKNOWN: 1,
          };
          const aSev = a.severity || a.extra?.severity || "UNKNOWN";
          const bSev = b.severity || b.extra?.severity || "UNKNOWN";
          return (severityOrder[bSev] || 0) - (severityOrder[aSev] || 0);
        case "check":
          return (a.check_id || "").localeCompare(b.check_id || "");
        case "file":
          return getRelativePath(a.path).localeCompare(getRelativePath(b.path));
        case "line":
          return (a.start?.line || 0) - (b.start?.line || 0);
        default:
          return 0;
      }
    });

    return filtered;
  }, [results, searchQuery, severityFilter, checkFilter, sortBy]);

  const getSeverityBadge = (severity?: string) => {
    const sev = severity || "UNKNOWN";
    const variants: Record<string, { className: string }> = {
      ERROR: { className: "bg-red-500 hover:bg-red-600 text-white" },
      WARNING: { className: "bg-orange-500 hover:bg-orange-600 text-white" },
      INFO: { className: "bg-blue-500 hover:bg-blue-600 text-white" },
    };
    const variant = variants[sev] || { className: "bg-gray-500 hover:bg-gray-600 text-white" };
    return (
      <Badge variant="outline" className={variant.className}>
        {sev}
      </Badge>
    );
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
                  ? `/home/sast` 
                  : `/home/sast/${conversationId}`;
                router.push(backRoute);
              }}
              className="cursor-pointer"
            >
              <ArrowLeft className="h-4 w-4" />
            </Button>
          )}
          <div>
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-white">SAST Scan Results</h1>
            <p className="text-sm text-zinc-600 dark:text-zinc-400 mt-1">
              Static Application Security Testing results
              {data.version && ` • Version ${data.version}`}
              {data.engine_requested && ` • Engine: ${data.engine_requested}`}
            </p>
          </div>
        </div>
      </div>

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Findings</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total}</div>
            <p className="text-xs text-muted-foreground">{stats.uniqueFiles} unique files</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Files Scanned</CardTitle>
            <FileText className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.scannedFiles}</div>
            <p className="text-xs text-muted-foreground">
              {stats.skippedFiles > 0 && `${stats.skippedFiles} skipped`}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">By Severity</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="space-y-1">
              {Object.entries(stats.bySeverity).map(([severity, count]) => (
                <div key={severity} className="flex items-center justify-between text-xs">
                  <span>{severity}:</span>
                  <span className="font-semibold">{count}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Scan Errors</CardTitle>
            <XCircle className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">{stats.errors}</div>
            <p className="text-xs text-muted-foreground">Analysis errors</p>
          </CardContent>
        </Card>
      </div>

      {/* Filters and Search */}
      <Card>
        <CardHeader>
          <CardTitle>Filters</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search findings..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger>
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severities</SelectItem>
                <SelectItem value="ERROR">Error</SelectItem>
                <SelectItem value="WARNING">Warning</SelectItem>
                <SelectItem value="INFO">Info</SelectItem>
              </SelectContent>
            </Select>
            <Select value={checkFilter} onValueChange={setCheckFilter}>
              <SelectTrigger>
                <SelectValue placeholder="Check Type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Checks</SelectItem>
                {Object.keys(stats.byCheck).slice(0, 20).map((check) => (
                  <SelectItem key={check} value={check}>
                    {check}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={sortBy} onValueChange={setSortBy}>
              <SelectTrigger>
                <SelectValue placeholder="Sort By" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="severity">Severity</SelectItem>
                <SelectItem value="check">Check ID</SelectItem>
                <SelectItem value="file">File Name</SelectItem>
                <SelectItem value="line">Line Number</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Results Table */}
      <Card>
        <CardHeader>
          <CardTitle>Security Findings ({filteredResults.length})</CardTitle>
          <CardDescription>
            Showing {filteredResults.length} of {results.length} findings
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[600px]">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Check</TableHead>
                  <TableHead>File</TableHead>
                  <TableHead>Location</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredResults.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center py-8 text-muted-foreground">
                      No findings found matching your filters.
                    </TableCell>
                  </TableRow>
                ) : (
                  filteredResults.map((result, index) => {
                    const checkId = result.check_id || "Unknown";
                    const checkName = checkId.split('.').pop() || checkId;
                    const severity = result.severity || result.extra?.severity || "UNKNOWN";
                    const message = result.extra?.message || "No description available";
                    const metadata = result.extra?.metadata;
                    const dataflowTrace = result.dataflow_trace || result.extra?.dataflow_trace;
                    const isIgnored = result.is_ignored || result.extra?.is_ignored || false;
                    const validationState = result.validation_state || result.extra?.validation_state || "NO_VALIDATOR";
                    const snippet = result.snippet || result.lines || result.extra?.lines || "";

                    return (
                      <TableRow key={`${result.fingerprint || result.extra?.fingerprint || index}-${index}`}>
                        <TableCell className="max-w-md">
                          <Accordion type="single" collapsible className="w-full">
                            <AccordionItem value={`item-${index}`} className="border-none">
                              <AccordionTrigger className="py-0 hover:no-underline">
                                <div className="text-left">
                                  <div className="font-semibold text-sm">
                                    {checkName}
                                  </div>
                                  <div className="text-xs text-muted-foreground mt-1 line-clamp-2">
                                    {metadata?.["display-name"] || checkId}
                                  </div>
                                </div>
                              </AccordionTrigger>
                              <AccordionContent className="pt-2 pb-0">
                                <div className="space-y-3 text-sm">
                                  <div>
                                    <div className="font-medium mb-1">Message:</div>
                                    <div className="text-muted-foreground">{message}</div>
                                  </div>
                                  {metadata && (
                                    <>
                                      {metadata.likelihood && (
                                        <div>
                                          <div className="font-medium mb-1">Likelihood:</div>
                                          <Badge variant="outline">{metadata.likelihood}</Badge>
                                        </div>
                                      )}
                                      {metadata.impact && (
                                        <div>
                                          <div className="font-medium mb-1">Impact:</div>
                                          <Badge variant="outline">{metadata.impact}</Badge>
                                        </div>
                                      )}
                                      {metadata.confidence && (
                                        <div>
                                          <div className="font-medium mb-1">Confidence:</div>
                                          <Badge variant="outline">{metadata.confidence}</Badge>
                                        </div>
                                      )}
                                      {metadata.cwe && metadata.cwe.length > 0 && (
                                        <div>
                                          <div className="font-medium mb-1">CWE:</div>
                                          <div className="flex flex-wrap gap-1">
                                            {metadata.cwe.map((cwe, idx) => (
                                              <Badge key={idx} variant="outline" className="text-xs">
                                                {cwe}
                                              </Badge>
                                            ))}
                                          </div>
                                        </div>
                                      )}
                                      {metadata.owasp && metadata.owasp.length > 0 && (
                                        <div>
                                          <div className="font-medium mb-1">OWASP:</div>
                                          <div className="flex flex-wrap gap-1">
                                            {metadata.owasp.map((owasp, idx) => (
                                              <Badge key={idx} variant="outline" className="text-xs bg-purple-100 dark:bg-purple-900">
                                                {owasp}
                                              </Badge>
                                            ))}
                                          </div>
                                        </div>
                                      )}
                                      {metadata.vulnerability_class && metadata.vulnerability_class.length > 0 && (
                                        <div>
                                          <div className="font-medium mb-1">Vulnerability Class:</div>
                                          <div className="flex flex-wrap gap-1">
                                            {metadata.vulnerability_class.map((vuln, idx) => (
                                              <Badge key={idx} variant="outline" className="text-xs">
                                                {vuln}
                                              </Badge>
                                            ))}
                                          </div>
                                        </div>
                                      )}
                                      {metadata.references && metadata.references.length > 0 && (
                                        <div>
                                          <div className="font-medium mb-1">References:</div>
                                          <div className="flex flex-wrap gap-2">
                                            {metadata.references.map((ref, idx) => (
                                              <a
                                                key={idx}
                                                href={ref}
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                className="text-blue-500 hover:underline flex items-center gap-1 text-xs"
                                              >
                                                <ExternalLink className="w-3 h-3" />
                                                Reference {idx + 1}
                                              </a>
                                            ))}
                                          </div>
                                        </div>
                                      )}
                                    </>
                                  )}
                                  {snippet && (
                                    <div>
                                      <div className="font-medium mb-1">Code Snippet:</div>
                                      <div className="text-muted-foreground font-mono text-xs bg-zinc-100 dark:bg-zinc-800 p-2 rounded">
                                        {snippet}
                                      </div>
                                    </div>
                                  )}
                                  {result.fingerprint || result.extra?.fingerprint ? (
                                    <div>
                                      <div className="font-medium mb-1">Fingerprint:</div>
                                      <div className="text-muted-foreground font-mono text-xs">
                                        {(result.fingerprint || result.extra?.fingerprint || "").substring(0, 50)}...
                                      </div>
                                    </div>
                                  ) : null}
                                </div>
                              </AccordionContent>
                            </AccordionItem>
                          </Accordion>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <FileText className="w-4 h-4 text-muted-foreground" />
                            <div>
                              <div className="font-medium text-sm max-w-xs truncate">
                                {getFileName(result.path)}
                              </div>
                              <div className="text-xs text-muted-foreground font-mono truncate max-w-xs">
                                {getRelativePath(result.path)}
                              </div>
                            </div>
                          </div>
                        </TableCell>
                        <TableCell>
                          <div>
                            <div className="font-medium text-sm">
                              Line {result.start?.line || "?"}
                              {result.end?.line && result.end.line !== result.start?.line && `-${result.end.line}`}
                            </div>
                            <div className="text-xs text-muted-foreground">
                              Col {result.start?.col || "?"}
                              {result.end?.col && result.end.col !== result.start?.col && `-${result.end.col}`}
                            </div>
                          </div>
                        </TableCell>
                        <TableCell>{getSeverityBadge(severity)}</TableCell>
                        <TableCell>
                          <div className="space-y-1">
                            {isIgnored ? (
                              <Badge variant="outline" className="bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200">
                                Ignored
                              </Badge>
                            ) : (
                              <Badge variant="outline" className="bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200">
                                Active
                              </Badge>
                            )}
                            {validationState !== "NO_VALIDATOR" && (
                              <div className="text-xs text-muted-foreground">
                                {validationState}
                              </div>
                            )}
                          </div>
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

      {/* Errors Section */}
      {errors.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertCircle className="h-5 w-5 text-orange-500" />
              Scan Errors ({errors.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[200px]">
              <div className="space-y-2">
                {errors.map((error, idx) => (
                  <div key={idx} className="p-3 bg-orange-50 dark:bg-orange-900/20 rounded border border-orange-200 dark:border-orange-800">
                    <div className="font-medium text-sm">{error.type || "Error"}</div>
                    <div className="text-xs text-muted-foreground">{error.message || "No message"}</div>
                    {error.path && (
                      <div className="text-xs font-mono text-muted-foreground mt-1">{getRelativePath(error.path)}</div>
                    )}
                  </div>
                ))}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      )}
    </div>
  );
}


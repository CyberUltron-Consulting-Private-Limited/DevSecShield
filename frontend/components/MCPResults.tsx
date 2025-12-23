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
  Server,
  Code,
  ExternalLink,
  XCircle,
  AlertCircle
} from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Button } from "@/components/ui/button";
import { useRouter, useSearchParams } from "next/navigation";

interface ToolInputSchema {
  type?: string;
  properties?: Record<string, any>;
  required?: string[];
  additionalProperties?: boolean;
  $schema?: string;
}

interface MCPTool {
  name?: string;
  description?: string;
  input_schema?: ToolInputSchema;
}

interface MCPIssue {
  issue_code?: string;
  issue_message?: string;
  issue_type?: string;
  server?: string;
  tool?: MCPTool | null;
  issue_severity?: string;
}

interface MCPResultsData {
  final_issues?: MCPIssue[];
  error_messages?: string[];
}

interface MCPResultsProps {
  data: MCPResultsData;
  conversationId?: number;
}

export default function MCPResults({ data, conversationId }: MCPResultsProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const origin = searchParams.get("origin") || "chat";
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [issueTypeFilter, setIssueTypeFilter] = useState<string>("all");
  const [issueCodeFilter, setIssueCodeFilter] = useState<string>("all");
  const [sortBy, setSortBy] = useState<string>("severity");

  // Safe data extraction with fallbacks
  const issues: MCPIssue[] = Array.isArray(data?.final_issues) ? data.final_issues : [];
  const errorMessages: string[] = Array.isArray(data?.error_messages) ? data.error_messages : [];

  // Calculate statistics
  const stats = useMemo(() => {
    const total = issues.length;
    const bySeverity = issues.reduce((acc, issue) => {
      const severity = issue.issue_severity || "unknown";
      acc[severity] = (acc[severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const byIssueType = issues.reduce((acc, issue) => {
      const type = issue.issue_type || "unknown";
      acc[type] = (acc[type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const byIssueCode = issues.reduce((acc, issue) => {
      const code = issue.issue_code || "Unknown";
      acc[code] = (acc[code] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const byServer = issues.reduce((acc, issue) => {
      const server = issue.server || "Unknown";
      acc[server] = (acc[server] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return {
      total,
      bySeverity,
      byIssueType,
      byIssueCode,
      byServer,
      errors: errorMessages.length,
    };
  }, [issues, errorMessages]);

  // Filter and sort issues
  const filteredIssues = useMemo(() => {
    let filtered = issues.filter((issue) => {
      const searchLower = searchQuery.toLowerCase();
      const code = issue.issue_code || "";
      const message = issue.issue_message || "";
      const server = issue.server || "";
      const toolName = issue.tool?.name || "";

      const matchesSearch =
        code.toLowerCase().includes(searchLower) ||
        message.toLowerCase().includes(searchLower) ||
        server.toLowerCase().includes(searchLower) ||
        toolName.toLowerCase().includes(searchLower);

      const severity = issue.issue_severity || "unknown";
      const matchesSeverity =
        severityFilter === "all" || severity === severityFilter;

      const issueType = issue.issue_type || "unknown";
      const matchesIssueType =
        issueTypeFilter === "all" || issueType === issueTypeFilter;

      const issueCode = issue.issue_code || "";
      const matchesIssueCode =
        issueCodeFilter === "all" || issueCode === issueCodeFilter;

      return matchesSearch && matchesSeverity && matchesIssueType && matchesIssueCode;
    });

    // Sort
    filtered.sort((a, b) => {
      switch (sortBy) {
        case "severity":
          const severityOrder: Record<string, number> = {
            critical: 5,
            high: 4,
            medium: 3,
            low: 2,
            unknown: 1,
          };
          const aSev = (a.issue_severity || "unknown").toLowerCase();
          const bSev = (b.issue_severity || "unknown").toLowerCase();
          return (severityOrder[bSev] || 0) - (severityOrder[aSev] || 0);
        case "code":
          return (a.issue_code || "").localeCompare(b.issue_code || "");
        case "type":
          return (a.issue_type || "").localeCompare(b.issue_type || "");
        case "server":
          return (a.server || "").localeCompare(b.server || "");
        default:
          return 0;
      }
    });

    return filtered;
  }, [issues, searchQuery, severityFilter, issueTypeFilter, issueCodeFilter, sortBy]);

  const getSeverityBadge = (severity?: string) => {
    const sev = (severity || "unknown").toLowerCase();
    const variants: Record<string, { className: string }> = {
      critical: { className: "bg-red-600 hover:bg-red-700 text-white" },
      high: { className: "bg-red-500 hover:bg-red-600 text-white" },
      medium: { className: "bg-orange-500 hover:bg-orange-600 text-white" },
      low: { className: "bg-yellow-500 hover:bg-yellow-600 text-white" },
    };
    const variant = variants[sev] || { className: "bg-gray-500 hover:bg-gray-600 text-white" };
    return (
      <Badge variant="outline" className={variant.className}>
        {severity?.toUpperCase() || "UNKNOWN"}
      </Badge>
    );
  };

  const getIssueTypeBadge = (issueType?: string) => {
    const type = issueType || "unknown";
    const typeColors: Record<string, string> = {
      untrusted_content_tool: "bg-purple-500 hover:bg-purple-600",
      private_data_tool: "bg-pink-500 hover:bg-pink-600",
      public_sink_tool: "bg-cyan-500 hover:bg-cyan-600",
      destructive_tool: "bg-red-500 hover:bg-red-600",
    };
    const color = typeColors[type] || "bg-gray-500 hover:bg-gray-600";
    return (
      <Badge variant="outline" className={`${color} text-white text-xs`}>
        {type.replace(/_/g, " ").replace(/\b\w/g, (l) => l.toUpperCase())}
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
                  ? `/home/mcp` 
                  : `/home/mcp/${conversationId}`;
                router.push(backRoute);
              }}
              className="cursor-pointer"
            >
              <ArrowLeft className="h-4 w-4" />
            </Button>
          )}
          <div>
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-white">MCP Scan Results</h1>
            <p className="text-sm text-zinc-600 dark:text-zinc-400 mt-1">
              Model Context Protocol security analysis results
            </p>
          </div>
        </div>
      </div>

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Issues</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total}</div>
            <p className="text-xs text-muted-foreground">Security issues found</p>
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
                  <span className="capitalize">{severity}:</span>
                  <span className="font-semibold">{count}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">By Issue Type</CardTitle>
            <Code className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="space-y-1">
              {Object.entries(stats.byIssueType).slice(0, 3).map(([type, count]) => (
                <div key={type} className="flex items-center justify-between text-xs">
                  <span className="truncate">{type.replace(/_/g, " ")}:</span>
                  <span className="font-semibold ml-2">{count}</span>
                </div>
              ))}
              {Object.keys(stats.byIssueType).length > 3 && (
                <div className="text-xs text-muted-foreground">
                  +{Object.keys(stats.byIssueType).length - 3} more
                </div>
              )}
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
            <p className="text-xs text-muted-foreground">Server errors</p>
          </CardContent>
        </Card>
      </div>

      {/* Filters and Search */}
      <Card>
        <CardHeader>
          <CardTitle>Filters</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
            <div className="relative md:col-span-2">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search issues..."
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
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
                <SelectItem value="unknown">Unknown</SelectItem>
              </SelectContent>
            </Select>
            <Select value={issueTypeFilter} onValueChange={setIssueTypeFilter}>
              <SelectTrigger>
                <SelectValue placeholder="Issue Type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                {Object.keys(stats.byIssueType).map((type) => (
                  <SelectItem key={type} value={type}>
                    {type.replace(/_/g, " ")}
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
                <SelectItem value="code">Issue Code</SelectItem>
                <SelectItem value="type">Issue Type</SelectItem>
                <SelectItem value="server">Server</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Results Table */}
      <Card>
        <CardHeader>
          <CardTitle>Security Issues ({filteredIssues.length})</CardTitle>
          <CardDescription>
            Showing {filteredIssues.length} of {issues.length} issues
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[600px]">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Issue Code</TableHead>
                  <TableHead>Server</TableHead>
                  <TableHead>Tool</TableHead>
                  <TableHead>Issue Type</TableHead>
                  <TableHead>Severity</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredIssues.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center py-8 text-muted-foreground">
                      No issues found matching your filters.
                    </TableCell>
                  </TableRow>
                ) : (
                  filteredIssues.map((issue, index) => {
                    const tool = issue.tool;
                    const issueCode = issue.issue_code || "Unknown";
                    const issueMessage = issue.issue_message || "No description available";
                    const server = issue.server || "Unknown";
                    const issueType = issue.issue_type || "unknown";
                    const severity = issue.issue_severity || "unknown";

                    return (
                      <TableRow key={`${issueCode}-${server}-${tool?.name || "no-tool"}-${index}`}>
                        <TableCell className="max-w-md">
                          <Accordion type="single" collapsible className="w-full">
                            <AccordionItem value={`item-${index}`} className="border-none">
                              <AccordionTrigger className="py-0 hover:no-underline">
                                <div className="text-left">
                                  <div className="font-semibold text-sm font-mono">
                                    {issueCode}
                                  </div>
                                  <div className="text-xs text-muted-foreground mt-1 line-clamp-2">
                                    {issueMessage}
                                  </div>
                                </div>
                              </AccordionTrigger>
                              <AccordionContent className="pt-2 pb-0">
                                <div className="space-y-3 text-sm">
                                  <div>
                                    <div className="font-medium mb-1">Issue Message:</div>
                                    <div className="text-muted-foreground">{issueMessage}</div>
                                  </div>
                                  {tool && (
                                    <>
                                      <div>
                                        <div className="font-medium mb-1">Tool Name:</div>
                                        <div className="text-muted-foreground font-mono">{tool.name || "N/A"}</div>
                                      </div>
                                      {tool.description && (
                                        <div>
                                          <div className="font-medium mb-1">Tool Description:</div>
                                          <div className="text-muted-foreground">{tool.description}</div>
                                        </div>
                                      )}
                                      {tool.input_schema && (
                                        <div>
                                          <div className="font-medium mb-1">Input Schema:</div>
                                          <div className="text-muted-foreground font-mono text-xs bg-zinc-100 dark:bg-zinc-800 p-2 rounded overflow-x-auto">
                                            <pre className="whitespace-pre-wrap break-words">
                                              {JSON.stringify(tool.input_schema, null, 2)}
                                            </pre>
                                          </div>
                                        </div>
                                      )}
                                    </>
                                  )}
                                  {!tool && (
                                    <div>
                                      <div className="font-medium mb-1">Tool:</div>
                                      <div className="text-muted-foreground italic">No tool associated with this issue</div>
                                    </div>
                                  )}
                                  {issueCode && issueCode.startsWith("TF") && (
                                    <div>
                                      <div className="font-medium mb-1">Reference:</div>
                                      <a
                                        href={`https://explorer.invariantlabs.ai/docs/mcp-scan/issue-code-reference/#${issueCode}`}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="text-blue-500 hover:underline flex items-center gap-1 text-xs"
                                      >
                                        <ExternalLink className="w-3 h-3" />
                                        View Issue Code Reference
                                      </a>
                                    </div>
                                  )}
                                </div>
                              </AccordionContent>
                            </AccordionItem>
                          </Accordion>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <Server className="w-4 h-4 text-muted-foreground" />
                            <div className="font-medium text-sm">
                              {server}
                            </div>
                          </div>
                        </TableCell>
                        <TableCell>
                          {tool ? (
                            <div className="font-mono text-sm">
                              {tool.name || "N/A"}
                            </div>
                          ) : (
                            <span className="text-muted-foreground italic text-sm">No tool</span>
                          )}
                        </TableCell>
                        <TableCell>{getIssueTypeBadge(issueType)}</TableCell>
                        <TableCell>{getSeverityBadge(severity)}</TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </ScrollArea>
        </CardContent>
      </Card>

      {/* Error Messages Section */}
      {errorMessages.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertCircle className="h-5 w-5 text-orange-500" />
              Scan Errors ({errorMessages.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[200px]">
              <div className="space-y-2">
                {errorMessages.map((error, idx) => (
                  <div key={idx} className="p-3 bg-orange-50 dark:bg-orange-900/20 rounded border border-orange-200 dark:border-orange-800">
                    <div className="text-sm text-orange-800 dark:text-orange-200">{error}</div>
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


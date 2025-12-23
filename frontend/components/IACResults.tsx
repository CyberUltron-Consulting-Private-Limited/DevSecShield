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
  ExternalLink,
  ArrowLeft,
  Cloud,
  Code
} from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Button } from "@/components/ui/button";
import { useRouter, useSearchParams } from "next/navigation";

interface IACResult {
  rule_id: string;
  long_id: string;
  rule_description: string;
  rule_provider: string;
  rule_service: string;
  impact: string;
  resolution: string;
  links: string[];
  description: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  warning: boolean;
  status: number;
  resource: string;
  location: {
    filename: string;
    start_line: number;
    end_line: number;
  };
}

interface IACResultsData {
  results: IACResult[];
}

interface IACResultsProps {
  data: IACResultsData;
  conversationId?: number;
}

export default function IACResults({ data, conversationId }: IACResultsProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const origin = searchParams.get("origin") || "chat";
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [providerFilter, setProviderFilter] = useState<string>("all");
  const [sortBy, setSortBy] = useState<string>("severity");

  const results = data.results || [];

  // Calculate statistics
  const stats = useMemo(() => {
    const total = results.length;
    const bySeverity = results.reduce((acc, result) => {
      const severity = result.severity || "Unknown";
      acc[severity] = (acc[severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const byProvider = results.reduce((acc, result) => {
      const provider = result.rule_provider || "Unknown";
      acc[provider] = (acc[provider] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const byService = results.reduce((acc, result) => {
      const service = result.rule_service || "Unknown";
      acc[service] = (acc[service] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const uniqueResources = new Set(results.map((r) => r.resource)).size;
    const uniqueFiles = new Set(results.map((r) => r.location.filename)).size;

    return {
      total,
      bySeverity,
      byProvider,
      byService,
      uniqueResources,
      uniqueFiles,
    };
  }, [results]);

  // Filter and sort results
  const filteredResults = useMemo(() => {
    let filtered = results.filter((result) => {
      const searchLower = searchQuery.toLowerCase();
      const matchesSearch =
        result.rule_id.toLowerCase().includes(searchLower) ||
        result.long_id.toLowerCase().includes(searchLower) ||
        result.rule_description.toLowerCase().includes(searchLower) ||
        result.description.toLowerCase().includes(searchLower) ||
        result.resource.toLowerCase().includes(searchLower) ||
        result.location.filename.toLowerCase().includes(searchLower);

      const matchesSeverity =
        severityFilter === "all" || result.severity === severityFilter;

      const matchesProvider =
        providerFilter === "all" || result.rule_provider === providerFilter;

      return matchesSearch && matchesSeverity && matchesProvider;
    });

    // Sort
    filtered.sort((a, b) => {
      switch (sortBy) {
        case "severity":
          const severityOrder: Record<string, number> = {
            CRITICAL: 4,
            HIGH: 3,
            MEDIUM: 2,
            LOW: 1,
            Unknown: 0,
          };
          return (
            (severityOrder[b.severity] || 0) -
            (severityOrder[a.severity] || 0)
          );
        case "provider":
          return a.rule_provider.localeCompare(b.rule_provider);
        case "service":
          return a.rule_service.localeCompare(b.rule_service);
        case "resource":
          return a.resource.localeCompare(b.resource);
        case "file":
          return a.location.filename.localeCompare(b.location.filename);
        default:
          return 0;
      }
    });

    return filtered;
  }, [results, searchQuery, severityFilter, providerFilter, sortBy]);

  const getSeverityBadge = (severity: string) => {
    const variants: Record<string, { className: string }> = {
      CRITICAL: { className: "bg-red-500 hover:bg-red-600 text-white" },
      HIGH: { className: "bg-orange-500 hover:bg-orange-600 text-white" },
      MEDIUM: { className: "bg-yellow-500 hover:bg-yellow-600 text-white" },
      LOW: { className: "bg-blue-500 hover:bg-blue-600 text-white" },
    };
    const variant = variants[severity] || { className: "bg-gray-500 hover:bg-gray-600 text-white" };
    return (
      <Badge variant="outline" className={variant.className}>
        {severity}
      </Badge>
    );
  };

  const getProviderBadge = (provider: string) => {
    return (
      <Badge variant="outline" className="text-xs">
        {provider.toUpperCase()}
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
                  ? `/home/iac` 
                  : `/home/iac/${conversationId}`;
                router.push(backRoute);
              }}
              className="cursor-pointer"
            >
              <ArrowLeft className="h-4 w-4" />
            </Button>
          )}
          <div>
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-white">IAC Scan Results</h1>
            <p className="text-sm text-zinc-600 dark:text-zinc-400 mt-1">
              Infrastructure as Code security analysis results
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
            <p className="text-xs text-muted-foreground">{stats.uniqueResources} unique resources</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Files Scanned</CardTitle>
            <FileText className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.uniqueFiles}</div>
            <p className="text-xs text-muted-foreground">Files with issues</p>
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
            <CardTitle className="text-sm font-medium">By Provider</CardTitle>
            <Cloud className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="space-y-1">
              {Object.entries(stats.byProvider).slice(0, 3).map(([provider, count]) => (
                <div key={provider} className="flex items-center justify-between text-xs">
                  <span>{provider}:</span>
                  <span className="font-semibold">{count}</span>
                </div>
              ))}
              {Object.keys(stats.byProvider).length > 3 && (
                <div className="text-xs text-muted-foreground">
                  +{Object.keys(stats.byProvider).length - 3} more
                </div>
              )}
            </div>
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
                <SelectItem value="CRITICAL">Critical</SelectItem>
                <SelectItem value="HIGH">High</SelectItem>
                <SelectItem value="MEDIUM">Medium</SelectItem>
                <SelectItem value="LOW">Low</SelectItem>
              </SelectContent>
            </Select>
            <Select value={providerFilter} onValueChange={setProviderFilter}>
              <SelectTrigger>
                <SelectValue placeholder="Provider" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Providers</SelectItem>
                {Object.keys(stats.byProvider).map((provider) => (
                  <SelectItem key={provider} value={provider}>
                    {provider.toUpperCase()}
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
                <SelectItem value="provider">Provider</SelectItem>
                <SelectItem value="service">Service</SelectItem>
                <SelectItem value="resource">Resource</SelectItem>
                <SelectItem value="file">File</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Results Table */}
      <Card>
        <CardHeader>
          <CardTitle>Security Issues ({filteredResults.length})</CardTitle>
          <CardDescription>
            Showing {filteredResults.length} of {results.length} issues
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[600px]">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Rule</TableHead>
                  <TableHead>Resource</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Provider</TableHead>
                  <TableHead>Service</TableHead>
                  <TableHead>Location</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredResults.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center py-8 text-muted-foreground">
                      No issues found matching your filters.
                    </TableCell>
                  </TableRow>
                ) : (
                  filteredResults.map((result, index) => (
                    <TableRow key={`${result.rule_id}-${result.resource}-${index}`}>
                      <TableCell className="max-w-md">
                        <Accordion type="single" collapsible className="w-full">
                          <AccordionItem value={`item-${index}`} className="border-none">
                            <AccordionTrigger className="py-0 hover:no-underline">
                              <div className="text-left">
                                <div className="font-semibold text-sm">
                                  {result.rule_id}
                                </div>
                                <div className="text-xs text-muted-foreground mt-1 line-clamp-2">
                                  {result.rule_description}
                                </div>
                              </div>
                            </AccordionTrigger>
                            <AccordionContent className="pt-2 pb-0">
                              <div className="space-y-3 text-sm">
                                <div>
                                  <div className="font-medium mb-1">Description:</div>
                                  <div className="text-muted-foreground">
                                    {result.description}
                                  </div>
                                </div>
                                <div>
                                  <div className="font-medium mb-1">Impact:</div>
                                  <div className="text-muted-foreground">
                                    {result.impact}
                                  </div>
                                </div>
                                <div>
                                  <div className="font-medium mb-1">Resolution:</div>
                                  <div className="text-green-600 dark:text-green-400">
                                    {result.resolution}
                                  </div>
                                </div>
                                {result.links && result.links.length > 0 && (
                                  <div>
                                    <div className="font-medium mb-1">References:</div>
                                    <div className="flex flex-wrap gap-2">
                                      {result.links.map((link, idx) => (
                                        <a
                                          key={idx}
                                          href={link}
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
                                <div>
                                  <div className="font-medium mb-1">Long ID:</div>
                                  <div className="text-muted-foreground font-mono text-xs">
                                    {result.long_id}
                                  </div>
                                </div>
                              </div>
                            </AccordionContent>
                          </AccordionItem>
                        </Accordion>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Code className="w-4 h-4 text-muted-foreground" />
                          <div>
                            <div className="font-medium text-sm">{result.resource}</div>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>{getSeverityBadge(result.severity)}</TableCell>
                      <TableCell>{getProviderBadge(result.rule_provider)}</TableCell>
                      <TableCell>
                        <Badge variant="outline" className="text-xs">
                          {result.rule_service}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div>
                          <div className="font-medium text-xs">
                            {result.location.filename.split('\\').pop() || result.location.filename.split('/').pop()}
                          </div>
                          <div className="text-xs text-muted-foreground">
                            Lines {result.location.start_line}-{result.location.end_line}
                          </div>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}


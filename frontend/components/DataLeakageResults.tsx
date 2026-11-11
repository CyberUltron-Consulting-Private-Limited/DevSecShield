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
  Key,
  Lock,
  Eye,
  EyeOff
} from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Button } from "@/components/ui/button";
import { useRouter, useSearchParams } from "next/navigation";

interface LeakageResult {
  RuleID: string;
  Description: string;
  StartLine: number;
  EndLine: number;
  StartColumn: number;
  EndColumn: number;
  Match: string;
  Secret: string;
  File: string;
  SymlinkFile?: string;
  Commit?: string;
  Entropy: number;
  Author?: string;
  Email?: string;
  Date?: string;
  Message?: string;
  Tags?: string[];
  Fingerprint: string;
  snippet?: string;
}

interface DataLeakageResultsData {
  results?: LeakageResult[];
}

interface DataLeakageResultsProps {
  data: LeakageResult[] | DataLeakageResultsData;
  conversationId?: number;
}

export default function DataLeakageResults({ data, conversationId }: DataLeakageResultsProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const origin = searchParams.get("origin") || "chat";
  const [searchQuery, setSearchQuery] = useState("");
  const [ruleFilter, setRuleFilter] = useState<string>("all");
  const [sortBy, setSortBy] = useState<string>("entropy");
  const [showSecrets, setShowSecrets] = useState<boolean>(false);

  // Handle both array and object formats
  const results: LeakageResult[] = Array.isArray(data) ? data : (data.results || []);

  // Calculate statistics
  const stats = useMemo(() => {
    const total = results.length;
    const byRule = results.reduce((acc, result) => {
      const rule = result.RuleID || "Unknown";
      acc[rule] = (acc[rule] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const byFile = results.reduce((acc, result) => {
      const file = result.File || "Unknown";
      acc[file] = (acc[file] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const uniqueFiles = new Set(results.map((r) => r.File)).size;
    const avgEntropy = results.reduce((sum, r) => sum + (r.Entropy || 0), 0) / total || 0;
    const highEntropy = results.filter((r) => (r.Entropy || 0) > 4.5).length;

    return {
      total,
      byRule,
      byFile,
      uniqueFiles,
      avgEntropy,
      highEntropy,
    };
  }, [results]);

  // Filter and sort results
  const filteredResults = useMemo(() => {
    let filtered = results.filter((result) => {
      const searchLower = searchQuery.toLowerCase();
      const matchesSearch =
        result.RuleID.toLowerCase().includes(searchLower) ||
        result.Description.toLowerCase().includes(searchLower) ||
        result.File.toLowerCase().includes(searchLower) ||
        result.Secret.toLowerCase().includes(searchLower) ||
        (result.Match && result.Match.toLowerCase().includes(searchLower));

      const matchesRule =
        ruleFilter === "all" || result.RuleID === ruleFilter;

      return matchesSearch && matchesRule;
    });

    // Sort
    filtered.sort((a, b) => {
      switch (sortBy) {
        case "entropy":
          return (b.Entropy || 0) - (a.Entropy || 0);
        case "rule":
          return a.RuleID.localeCompare(b.RuleID);
        case "file":
          return a.File.localeCompare(b.File);
        case "line":
          return a.StartLine - b.StartLine;
        default:
          return 0;
      }
    });

    return filtered;
  }, [results, searchQuery, ruleFilter, sortBy]);

  const getRuleBadge = (ruleId: string) => {
    const ruleColors: Record<string, string> = {
      "github-pat": "bg-purple-500 hover:bg-purple-600",
      "github-fine-grained-pat": "bg-purple-600 hover:bg-purple-700",
      "openai-api-key": "bg-green-500 hover:bg-green-600",
      "anthropic-api-key": "bg-blue-500 hover:bg-blue-600",
      "azure-ad-client-secret": "bg-cyan-500 hover:bg-cyan-600",
      "gcp-api-key": "bg-yellow-500 hover:bg-yellow-600",
      "huggingface-access-token": "bg-pink-500 hover:bg-pink-600",
      "generic-api-key": "bg-gray-500 hover:bg-gray-600",
    };
    const color = ruleColors[ruleId] || "bg-gray-500 hover:bg-gray-600";
    return (
      <Badge variant="outline" className={`${color} text-white`}>
        {ruleId}
      </Badge>
    );
  };

  const maskSecret = (secret: string) => {
    if (!secret || secret.length < 8) return "***";
    return `${secret.substring(0, 4)}${"*".repeat(Math.min(secret.length - 8, 20))}${secret.substring(secret.length - 4)}`;
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
                aria-label="Back"
              onClick={() => {
                const backRoute = origin === "list" 
                  ? `/home/leakage` 
                  : `/home/leakage/${conversationId}`;
                router.push(backRoute);
              }}
              className="cursor-pointer"
            >
              <ArrowLeft className="h-4 w-4" />
            </Button>
          )}
          <div>
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-white">Data Leakage Scan Results</h1>
            <p className="text-sm text-zinc-600 dark:text-zinc-400 mt-1">
              Secret detection and credential exposure analysis
            </p>
          </div>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => setShowSecrets(!showSecrets)}
          className="cursor-pointer"
        >
          {showSecrets ? (
            <>
              <EyeOff className="h-4 w-4 mr-2" />
              Hide Secrets
            </>
          ) : (
            <>
              <Eye className="h-4 w-4 mr-2" />
              Show Secrets
            </>
          )}
        </Button>
      </div>

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Secrets Found</CardTitle>
            <Key className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total}</div>
            <p className="text-xs text-muted-foreground">{stats.uniqueFiles} unique files</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">High Entropy Secrets</CardTitle>
            <Lock className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">{stats.highEntropy}</div>
            <p className="text-xs text-muted-foreground">Entropy &gt; 4.5</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Average Entropy</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.avgEntropy.toFixed(2)}</div>
            <p className="text-xs text-muted-foreground">Entropy score</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">By Rule Type</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="space-y-1 max-h-20 overflow-y-auto">
              {Object.entries(stats.byRule).slice(0, 4).map(([rule, count]) => (
                <div key={rule} className="flex items-center justify-between text-xs">
                  <span className="truncate">{rule}:</span>
                  <span className="font-semibold ml-2">{count}</span>
                </div>
              ))}
              {Object.keys(stats.byRule).length > 4 && (
                <div className="text-xs text-muted-foreground">
                  +{Object.keys(stats.byRule).length - 4} more
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
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search secrets..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>
            <Select value={ruleFilter} onValueChange={setRuleFilter}>
              <SelectTrigger>
                <SelectValue placeholder="Rule Type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Rules</SelectItem>
                {Object.keys(stats.byRule).map((rule) => (
                  <SelectItem key={rule} value={rule}>
                    {rule}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={sortBy} onValueChange={setSortBy}>
              <SelectTrigger>
                <SelectValue placeholder="Sort By" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="entropy">Entropy (High to Low)</SelectItem>
                <SelectItem value="rule">Rule Type</SelectItem>
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
          <CardTitle>Detected Secrets ({filteredResults.length})</CardTitle>
          <CardDescription>
            Showing {filteredResults.length} of {results.length} secrets
            {!showSecrets && " • Secrets are masked for security"}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[600px]">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Rule</TableHead>
                  <TableHead>Secret</TableHead>
                  <TableHead>File</TableHead>
                  <TableHead>Location</TableHead>
                  <TableHead>Entropy</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredResults.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center py-8 text-muted-foreground">
                      No secrets found matching your filters.
                    </TableCell>
                  </TableRow>
                ) : (
                  filteredResults.map((result, index) => (
                    <TableRow key={`${result.Fingerprint}-${index}`}>
                      <TableCell className="max-w-md">
                        <Accordion type="single" collapsible className="w-full">
                          <AccordionItem value={`item-${index}`} className="border-none">
                            <AccordionTrigger className="py-0 hover:no-underline">
                              <div className="text-left">
                                <div className="font-semibold text-sm">
                                  {getRuleBadge(result.RuleID)}
                                </div>
                                <div className="text-xs text-muted-foreground mt-1 line-clamp-2">
                                  {result.Description}
                                </div>
                              </div>
                            </AccordionTrigger>
                            <AccordionContent className="pt-2 pb-0">
                              <div className="space-y-3 text-sm">
                                <div>
                                  <div className="font-medium mb-1">Description:</div>
                                  <div className="text-muted-foreground">
                                    {result.Description}
                                  </div>
                                </div>
                                <div>
                                  <div className="font-medium mb-1">Fingerprint:</div>
                                  <div className="text-muted-foreground font-mono text-xs">
                                    {result.Fingerprint}
                                  </div>
                                </div>
                                {result.Tags && result.Tags.length > 0 && (
                                  <div>
                                    <div className="font-medium mb-1">Tags:</div>
                                    <div className="flex flex-wrap gap-1">
                                      {result.Tags.map((tag, idx) => (
                                        <Badge key={idx} variant="outline" className="text-xs">
                                          {tag}
                                        </Badge>
                                      ))}
                                    </div>
                                  </div>
                                )}
                                {result.Commit && (
                                  <div>
                                    <div className="font-medium mb-1">Commit:</div>
                                    <div className="text-muted-foreground font-mono text-xs">
                                      {result.Commit}
                                    </div>
                                  </div>
                                )}
                                {result.Author && (
                                  <div>
                                    <div className="font-medium mb-1">Author:</div>
                                    <div className="text-muted-foreground text-xs">
                                      {result.Author} {result.Email && `(${result.Email})`}
                                    </div>
                                  </div>
                                )}
                                {result.Date && (
                                  <div>
                                    <div className="font-medium mb-1">Date:</div>
                                    <div className="text-muted-foreground text-xs">
                                      {result.Date}
                                    </div>
                                  </div>
                                )}
                                {result.snippet && (
                                  <div>
                                    <div className="font-medium mb-1">Code Snippet:</div>
                                    <div className="text-muted-foreground font-mono text-xs bg-zinc-100 dark:bg-zinc-800 p-2 rounded">
                                      {result.snippet}
                                    </div>
                                  </div>
                                )}
                              </div>
                            </AccordionContent>
                          </AccordionItem>
                        </Accordion>
                      </TableCell>
                      <TableCell>
                        <div className="font-mono text-xs">
                          {showSecrets ? (
                            <div className="break-all text-red-600 dark:text-red-400">
                              {result.Secret}
                            </div>
                          ) : (
                            <div className="text-muted-foreground">
                              {maskSecret(result.Secret)}
                            </div>
                          )}
                        </div>
                        {result.Match && result.Match !== result.Secret && (
                          <div className="text-xs text-muted-foreground mt-1">
                            Match: {showSecrets ? result.Match : maskSecret(result.Match)}
                          </div>
                        )}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <FileText className="w-4 h-4 text-muted-foreground" />
                          <div>
                            <div className="font-medium text-sm max-w-xs truncate">
                              {result.File.split('\\').pop()?.split('/').pop() || result.File}
                            </div>
                            <div className="text-xs text-muted-foreground font-mono truncate max-w-xs">
                              {result.File}
                            </div>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div>
                          <div className="font-medium text-sm">
                            Line {result.StartLine}
                            {result.EndLine !== result.StartLine && `-${result.EndLine}`}
                          </div>
                          <div className="text-xs text-muted-foreground">
                            Col {result.StartColumn}-{result.EndColumn}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div>
                          <div className={`font-semibold ${
                            (result.Entropy || 0) > 4.5 
                              ? "text-red-600 dark:text-red-400" 
                              : (result.Entropy || 0) > 3.5 
                              ? "text-orange-600 dark:text-orange-400" 
                              : "text-yellow-600 dark:text-yellow-400"
                          }`}>
                            {(result.Entropy || 0).toFixed(2)}
                          </div>
                          <div className="text-xs text-muted-foreground">
                            {(result.Entropy || 0) > 4.5 ? "High" : (result.Entropy || 0) > 3.5 ? "Medium" : "Low"}
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


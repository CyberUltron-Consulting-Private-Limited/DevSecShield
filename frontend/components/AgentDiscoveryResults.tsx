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
  Bot,
  FileText,
  Code,
  Wrench
} from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Button } from "@/components/ui/button";
import { useRouter, useSearchParams } from "next/navigation";

interface AgentDiscoveryResult {
  id?: string;
  file_path?: string;
  role?: string;
  system_prompt?: string;
  framework?: string;
  risk?: string;
  risk_reason?: string;
  tools?: string[];
}

interface AgentDiscoveryResultsData {
  results?: AgentDiscoveryResult[];
}

interface AgentDiscoveryResultsProps {
  data: AgentDiscoveryResult[] | AgentDiscoveryResultsData;
  conversationId?: number;
}

export default function AgentDiscoveryResults({ data, conversationId }: AgentDiscoveryResultsProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const origin = searchParams.get("origin") || "chat";
  const [searchQuery, setSearchQuery] = useState("");
  const [riskFilter, setRiskFilter] = useState<string>("all");
  const [frameworkFilter, setFrameworkFilter] = useState<string>("all");
  const [sortBy, setSortBy] = useState<string>("risk");

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

  // Handle both array and object formats
  const results: AgentDiscoveryResult[] = Array.isArray(data) ? data : (data.results || []);

  // Calculate statistics
  const stats = useMemo(() => {
    const total = results.length;
    const byRisk = results.reduce((acc, result) => {
      const risk = result.risk || "unknown";
      acc[risk] = (acc[risk] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const byFramework = results.reduce((acc, result) => {
      const framework = result.framework || "Unknown";
      acc[framework] = (acc[framework] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const uniqueFiles = new Set(results.map((r) => r.file_path).filter(Boolean)).size;
    const totalTools = results.reduce((sum, r) => sum + (r.tools?.length || 0), 0);
    const uniqueTools = new Set(
      results.flatMap((r) => r.tools || [])
    ).size;

    return {
      total,
      byRisk,
      byFramework,
      uniqueFiles,
      totalTools,
      uniqueTools,
    };
  }, [results]);

  // Filter and sort results
  const filteredResults = useMemo(() => {
    let filtered = results.filter((result) => {
      const searchLower = searchQuery.toLowerCase();
      const filePath = getRelativePath(result.file_path);
      const role = result.role || "";
      const systemPrompt = result.system_prompt || "";
      const framework = result.framework || "";
      const riskReason = result.risk_reason || "";
      const tools = (result.tools || []).join(" ").toLowerCase();

      const matchesSearch =
        filePath.toLowerCase().includes(searchLower) ||
        role.toLowerCase().includes(searchLower) ||
        systemPrompt.toLowerCase().includes(searchLower) ||
        framework.toLowerCase().includes(searchLower) ||
        riskReason.toLowerCase().includes(searchLower) ||
        tools.includes(searchLower);

      const risk = result.risk || "unknown";
      const matchesRisk =
        riskFilter === "all" || risk === riskFilter;

      const frameworkName = result.framework || "unknown";
      const matchesFramework =
        frameworkFilter === "all" || frameworkName === frameworkFilter;

      return matchesSearch && matchesRisk && matchesFramework;
    });

    // Sort
    filtered.sort((a, b) => {
      switch (sortBy) {
        case "risk":
          const riskOrder: Record<string, number> = {
            critical: 5,
            high: 4,
            medium: 3,
            low: 2,
            unknown: 1,
          };
          const aRisk = (a.risk || "unknown").toLowerCase();
          const bRisk = (b.risk || "unknown").toLowerCase();
          return (riskOrder[bRisk] || 0) - (riskOrder[aRisk] || 0);
        case "framework":
          return (a.framework || "").localeCompare(b.framework || "");
        case "file":
          return getRelativePath(a.file_path).localeCompare(getRelativePath(b.file_path));
        case "role":
          return (a.role || "").localeCompare(b.role || "");
        default:
          return 0;
      }
    });

    return filtered;
  }, [results, searchQuery, riskFilter, frameworkFilter, sortBy]);

  const getRiskBadge = (risk?: string) => {
    const riskLevel = (risk || "unknown").toLowerCase();
    const variants: Record<string, { className: string }> = {
      critical: { className: "bg-red-600 hover:bg-red-700 text-white" },
      high: { className: "bg-red-500 hover:bg-red-600 text-white" },
      medium: { className: "bg-orange-500 hover:bg-orange-600 text-white" },
      low: { className: "bg-green-500 hover:bg-green-600 text-white" },
    };
    const variant = variants[riskLevel] || { className: "bg-gray-500 hover:bg-gray-600 text-white" };
    return (
      <Badge variant="outline" className={variant.className}>
        {risk?.toUpperCase() || "UNKNOWN"}
      </Badge>
    );
  };

  const getFrameworkBadge = (framework?: string) => {
    const frameworkColors: Record<string, string> = {
      "Langchain": "bg-blue-500 hover:bg-blue-600",
      "AutoGPT": "bg-purple-500 hover:bg-purple-600",
      "BabyAGI": "bg-pink-500 hover:bg-pink-600",
      "CrewAI": "bg-cyan-500 hover:bg-cyan-600",
    };
    const color = frameworkColors[framework || ""] || "bg-gray-500 hover:bg-gray-600";
    return (
      <Badge variant="outline" className={`${color} text-white`}>
        {framework || "Unknown"}
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
                  ? `/home/agent_discovery` 
                  : `/home/agent_discovery/${conversationId}`;
                router.push(backRoute);
              }}
              className="cursor-pointer"
            >
              <ArrowLeft className="h-4 w-4" />
            </Button>
          )}
          <div>
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-white">Agent Discovery Results</h1>
            <p className="text-sm text-zinc-600 dark:text-zinc-400 mt-1">
              AI agent discovery and security analysis results
            </p>
          </div>
        </div>
      </div>

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Agents Found</CardTitle>
            <Bot className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total}</div>
            <p className="text-xs text-muted-foreground">{stats.uniqueFiles} unique files</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">By Risk Level</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="space-y-1">
              {Object.entries(stats.byRisk).map(([risk, count]) => (
                <div key={risk} className="flex items-center justify-between text-xs">
                  <span className="capitalize">{risk}:</span>
                  <span className="font-semibold">{count}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">By Framework</CardTitle>
            <Code className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="space-y-1">
              {Object.entries(stats.byFramework).slice(0, 3).map(([framework, count]) => (
                <div key={framework} className="flex items-center justify-between text-xs">
                  <span>{framework}:</span>
                  <span className="font-semibold">{count}</span>
                </div>
              ))}
              {Object.keys(stats.byFramework).length > 3 && (
                <div className="text-xs text-muted-foreground">
                  +{Object.keys(stats.byFramework).length - 3} more
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Tools</CardTitle>
            <Wrench className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.totalTools}</div>
            <p className="text-xs text-muted-foreground">{stats.uniqueTools} unique tools</p>
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
                placeholder="Search agents..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>
            <Select value={riskFilter} onValueChange={setRiskFilter}>
              <SelectTrigger>
                <SelectValue placeholder="Risk Level" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Risk Levels</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
            <Select value={frameworkFilter} onValueChange={setFrameworkFilter}>
              <SelectTrigger>
                <SelectValue placeholder="Framework" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Frameworks</SelectItem>
                {Object.keys(stats.byFramework).map((framework) => (
                  <SelectItem key={framework} value={framework}>
                    {framework}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={sortBy} onValueChange={setSortBy}>
              <SelectTrigger>
                <SelectValue placeholder="Sort By" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="risk">Risk Level</SelectItem>
                <SelectItem value="framework">Framework</SelectItem>
                <SelectItem value="file">File Name</SelectItem>
                <SelectItem value="role">Role</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Results Table */}
      <Card>
        <CardHeader>
          <CardTitle>Discovered Agents ({filteredResults.length})</CardTitle>
          <CardDescription>
            Showing {filteredResults.length} of {results.length} agents
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[600px]">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Agent</TableHead>
                  <TableHead>File</TableHead>
                  <TableHead>Framework</TableHead>
                  <TableHead>Risk</TableHead>
                  <TableHead>Tools</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredResults.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center py-8 text-muted-foreground">
                      No agents found matching your filters.
                    </TableCell>
                  </TableRow>
                ) : (
                  filteredResults.map((agent, index) => {
                    const role = agent.role || "Unknown";
                    const systemPrompt = agent.system_prompt || "No system prompt";
                    const framework = agent.framework || "Unknown";
                    const risk = agent.risk || "unknown";
                    const riskReason = agent.risk_reason || "No risk reason provided";
                    const tools = agent.tools || [];
                    const filePath = getRelativePath(agent.file_path);

                    return (
                      <TableRow key={`${agent.id || index}-${index}`}>
                        <TableCell className="max-w-md">
                          <Accordion type="single" collapsible className="w-full">
                            <AccordionItem value={`item-${index}`} className="border-none">
                              <AccordionTrigger className="py-0 hover:no-underline">
                                <div className="text-left">
                                  <div className="font-semibold text-sm">
                                    {role}
                                  </div>
                                  <div className="text-xs text-muted-foreground mt-1 line-clamp-2">
                                    {systemPrompt}
                                  </div>
                                </div>
                              </AccordionTrigger>
                              <AccordionContent className="pt-2 pb-0">
                                <div className="space-y-3 text-sm">
                                  <div>
                                    <div className="font-medium mb-1">Role:</div>
                                    <div className="text-muted-foreground">{role}</div>
                                  </div>
                                  <div>
                                    <div className="font-medium mb-1">System Prompt:</div>
                                    <div className="text-muted-foreground">{systemPrompt}</div>
                                  </div>
                                  <div>
                                    <div className="font-medium mb-1">Risk Reason:</div>
                                    <div className="text-muted-foreground">{riskReason}</div>
                                  </div>
                                  {tools.length > 0 && (
                                    <div>
                                      <div className="font-medium mb-1">Tools ({tools.length}):</div>
                                      <div className="flex flex-wrap gap-1">
                                        {tools.map((tool, idx) => (
                                          <Badge key={idx} variant="outline" className="text-xs">
                                            {tool}
                                          </Badge>
                                        ))}
                                      </div>
                                    </div>
                                  )}
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
                                {getFileName(filePath)}
                              </div>
                              <div className="text-xs text-muted-foreground font-mono truncate max-w-xs">
                                {filePath}
                              </div>
                            </div>
                          </div>
                        </TableCell>
                        <TableCell>{getFrameworkBadge(framework)}</TableCell>
                        <TableCell>{getRiskBadge(risk)}</TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1 max-w-xs">
                            {tools.slice(0, 3).map((tool, idx) => (
                              <Badge key={idx} variant="outline" className="text-xs">
                                {tool}
                              </Badge>
                            ))}
                            {tools.length > 3 && (
                              <Badge variant="outline" className="text-xs bg-zinc-100 dark:bg-zinc-800">
                                +{tools.length - 3}
                              </Badge>
                            )}
                            {tools.length === 0 && (
                              <span className="text-xs text-muted-foreground italic">No tools</span>
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
    </div>
  );
}


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
  ExternalLink,
  Globe,
  Code,
} from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Button } from "@/components/ui/button";
import { useRouter, useSearchParams, usePathname } from "next/navigation";

interface ZAPAlert {
  sourceid?: string;
  other?: string;
  method?: string;
  evidence?: string;
  pluginId?: string;
  cweid?: string;
  confidence?: string;
  sourceMessageId?: number;
  wascid?: string;
  description?: string;
  messageId?: string;
  inputVector?: string;
  url?: string;
  tags?: Record<string, string>;
  reference?: string;
  solution?: string;
  alert?: string;
  param?: string;
  attack?: string;
  name?: string;
  risk?: string;
  id?: string;
  alertRef?: string;
}

interface ZAPResultsProps {
  data: ZAPAlert[];
  conversationId?: number;
}

export default function ZAPResults({ data, conversationId }: ZAPResultsProps) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const origin = searchParams.get("origin") || "chat";
  const [searchQuery, setSearchQuery] = useState("");
  const [riskFilter, setRiskFilter] = useState<string>("all");
  const [confidenceFilter, setConfidenceFilter] = useState<string>("all");
  const [sortBy, setSortBy] = useState<string>("risk");

  // Check if we're in CI/CD context
  const isCicdContext = pathname.includes("ci_cd");
  let integrationId: string | null = null;
  if (isCicdContext) {
    const pathParts = pathname.split('/').filter(Boolean);
    const cicdIndex = pathParts.indexOf('ci_cd');
    if (cicdIndex !== -1 && cicdIndex + 1 < pathParts.length) {
      integrationId = pathParts[cicdIndex + 1];
    }
  }

  // Safe data extraction with comprehensive fallbacks
  const alerts: ZAPAlert[] = Array.isArray(data) ? data : (data ? [data] : []);

  // Calculate statistics with fallbacks
  const stats = useMemo(() => {
    const validAlerts = alerts.filter(alert => {
      if (!alert || typeof alert !== 'object') return false;
      // Filter out alerts with specific keyword in the alert name (case-insensitive)
      const alertName = (alert?.alert || alert?.name || "").toString();
      return !alertName.toLowerCase().includes('zap');
    });
    const total = validAlerts.length;
    
    const byRisk = validAlerts.reduce((acc, alert) => {
      const risk = (alert?.risk && typeof alert.risk === 'string') ? alert.risk : "Unknown";
      acc[risk] = (acc[risk] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const byConfidence = validAlerts.reduce((acc, alert) => {
      const confidence = (alert?.confidence && typeof alert.confidence === 'string') ? alert.confidence : "Unknown";
      acc[confidence] = (acc[confidence] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const byCWE = validAlerts.reduce((acc, alert) => {
      const cweid = alert?.cweid;
      if (cweid && typeof cweid === 'string' && cweid !== "-1" && cweid !== "-") {
        acc[cweid] = (acc[cweid] || 0) + 1;
      }
      return acc;
    }, {} as Record<string, number>);

    const uniqueUrls = new Set(validAlerts.map((a) => a?.url).filter(url => url && typeof url === 'string')).size;
    const byMethod = validAlerts.reduce((acc, alert) => {
      const method = (alert?.method && typeof alert.method === 'string') ? alert.method : "Unknown";
      acc[method] = (acc[method] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return {
      total,
      byRisk,
      byConfidence,
      byCWE,
      uniqueUrls,
      byMethod,
    };
  }, [alerts]);

  // Filter and sort results with fallbacks
  const filteredAlerts = useMemo(() => {
    const validAlerts = alerts.filter(alert => alert && typeof alert === 'object');
    let filtered = validAlerts.filter((alert) => {
      // Filter out alerts with specific keyword in the alert name (case-insensitive)
      const alertName = (alert?.alert || alert?.name || "").toString();
      if (alertName.toLowerCase().includes('zap')) {
        return false;
      }

      const searchLower = searchQuery.toLowerCase();
      const description = (alert?.description || "").toString();
      const url = (alert?.url || "").toString();
      const param = (alert?.param || "").toString();

      const matchesSearch =
        alertName.toLowerCase().includes(searchLower) ||
        description.toLowerCase().includes(searchLower) ||
        url.toLowerCase().includes(searchLower) ||
        param.toLowerCase().includes(searchLower);

      const risk = (alert?.risk && typeof alert.risk === 'string') ? alert.risk : "Unknown";
      const matchesRisk = riskFilter === "all" || risk === riskFilter;

      const confidence = (alert?.confidence && typeof alert.confidence === 'string') ? alert.confidence : "Unknown";
      const matchesConfidence = confidenceFilter === "all" || confidence === confidenceFilter;

      return matchesSearch && matchesRisk && matchesConfidence;
    });

    // Sort
    filtered.sort((a, b) => {
      switch (sortBy) {
        case "risk":
          const riskOrder: Record<string, number> = {
            Critical: 5,
            High: 4,
            Medium: 3,
            Low: 2,
            Informational: 1,
            Unknown: 0,
          };
          const aRisk = a.risk || "Unknown";
          const bRisk = b.risk || "Unknown";
          return (riskOrder[bRisk] || 0) - (riskOrder[aRisk] || 0);
        case "confidence":
          const confOrder: Record<string, number> = {
            High: 3,
            Medium: 2,
            Low: 1,
            Unknown: 0,
          };
          const aConf = a.confidence || "Unknown";
          const bConf = b.confidence || "Unknown";
          return (confOrder[bConf] || 0) - (confOrder[aConf] || 0);
        case "name":
          return (a.alert || a.name || "").localeCompare(b.alert || b.name || "");
        case "url":
          return (a.url || "").localeCompare(b.url || "");
        default:
          return 0;
      }
    });

    return filtered;
  }, [alerts, searchQuery, riskFilter, confidenceFilter, sortBy]);

  // Early return if no valid data
  if (!data || (Array.isArray(data) && data.length === 0 && alerts.length === 0)) {
    return (
      <div className="container mx-auto p-6">
        <div className="text-center py-12">
          <p className="text-zinc-600 dark:text-zinc-400 mb-4">
            No scan results available.
          </p>
        </div>
      </div>
    );
  }

  const getRiskBadge = (risk?: string) => {
    const riskLevel = risk || "Unknown";
    const variants: Record<string, { className: string }> = {
      Critical: { className: "bg-red-600 hover:bg-red-700 text-white" },
      High: { className: "bg-red-500 hover:bg-red-600 text-white" },
      Medium: { className: "bg-orange-500 hover:bg-orange-600 text-white" },
      Low: { className: "bg-yellow-500 hover:bg-yellow-600 text-white" },
      Informational: { className: "bg-blue-500 hover:bg-blue-600 text-white" },
    };
    const variant = variants[riskLevel] || { className: "bg-gray-500 hover:bg-gray-600 text-white" };
    return (
      <Badge variant="outline" className={variant.className}>
        {riskLevel}
      </Badge>
    );
  };

  const getConfidenceBadge = (confidence?: string) => {
    const conf = confidence || "Unknown";
    const variants: Record<string, { className: string }> = {
      High: { className: "bg-green-500 hover:bg-green-600 text-white" },
      Medium: { className: "bg-yellow-500 hover:bg-yellow-600 text-white" },
      Low: { className: "bg-orange-500 hover:bg-orange-600 text-white" },
    };
    const variant = variants[conf] || { className: "bg-gray-500 hover:bg-gray-600 text-white" };
    return (
      <Badge variant="outline" className={variant.className}>
        {conf}
      </Badge>
    );
  };

  return (
    <div className="container mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          {(conversationId || isCicdContext) && (
            <Button
              variant="outline"
              size="icon"
              onClick={() => {
                let backRoute: string;
                if (isCicdContext && integrationId) {
                  backRoute = `/home/ci_cd/${integrationId}`;
                } else if (conversationId) {
                  backRoute = origin === "list" 
                    ? `/home/dast` 
                    : `/home/dast/${conversationId}`;
                } else {
                  backRoute = `/home/dast`;
                }
                router.push(backRoute);
              }}
              className="cursor-pointer"
            >
              <ArrowLeft className="h-4 w-4 cursor-pointer" />
            </Button>
          )}
          <div>
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-white">Form Authenticated DAST Scan Results</h1>
            <p className="text-sm text-zinc-600 dark:text-zinc-400 mt-1">
              Dynamic Application Security Testing results
            </p>
          </div>
        </div>
      </div>

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Alerts</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total}</div>
            <p className="text-xs text-muted-foreground">{stats.uniqueUrls} unique URLs</p>
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
                  <span>{risk}:</span>
                  <span className="font-semibold">{count}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">By Confidence</CardTitle>
            <FileText className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="space-y-1">
              {Object.entries(stats.byConfidence).map(([confidence, count]) => (
                <div key={confidence} className="flex items-center justify-between text-xs">
                  <span>{confidence}:</span>
                  <span className="font-semibold">{count}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">CWE IDs</CardTitle>
            <Code className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{Object.keys(stats.byCWE).length}</div>
            <p className="text-xs text-muted-foreground">Unique CWE identifiers</p>
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
                placeholder="Search alerts..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9 cursor-text"
              />
            </div>
            <Select value={riskFilter} onValueChange={setRiskFilter}>
              <SelectTrigger className="cursor-pointer">
                <SelectValue placeholder="Risk Level" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all" className="cursor-pointer">All Risk Levels</SelectItem>
                <SelectItem value="Critical" className="cursor-pointer">Critical</SelectItem>
                <SelectItem value="High" className="cursor-pointer">High</SelectItem>
                <SelectItem value="Medium" className="cursor-pointer">Medium</SelectItem>
                <SelectItem value="Low" className="cursor-pointer">Low</SelectItem>
                <SelectItem value="Informational" className="cursor-pointer">Informational</SelectItem>
              </SelectContent>
            </Select>
            <Select value={confidenceFilter} onValueChange={setConfidenceFilter}>
              <SelectTrigger className="cursor-pointer">
                <SelectValue placeholder="Confidence" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all" className="cursor-pointer">All Confidence Levels</SelectItem>
                <SelectItem value="High" className="cursor-pointer">High</SelectItem>
                <SelectItem value="Medium" className="cursor-pointer">Medium</SelectItem>
                <SelectItem value="Low" className="cursor-pointer">Low</SelectItem>
              </SelectContent>
            </Select>
            <Select value={sortBy} onValueChange={setSortBy}>
              <SelectTrigger className="cursor-pointer">
                <SelectValue placeholder="Sort By" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="risk" className="cursor-pointer">Risk Level</SelectItem>
                <SelectItem value="confidence" className="cursor-pointer">Confidence</SelectItem>
                <SelectItem value="name" className="cursor-pointer">Alert Name</SelectItem>
                <SelectItem value="url" className="cursor-pointer">URL</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Results Table */}
      <Card>
        <CardHeader>
          <CardTitle>Security Alerts ({filteredAlerts.length})</CardTitle>
          <CardDescription>
            Showing {filteredAlerts.length} of {alerts.length} alerts
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[600px]">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Alert</TableHead>
                  <TableHead>URL</TableHead>
                  <TableHead>Method</TableHead>
                  <TableHead>Risk</TableHead>
                  <TableHead>Confidence</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredAlerts.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center py-8 text-muted-foreground">
                      No alerts found matching your filters.
                    </TableCell>
                  </TableRow>
                ) : (
                  filteredAlerts
                    .filter(alert => alert && typeof alert === 'object')
                    .map((alert, index) => {
                    // Comprehensive fallbacks for all fields
                    
                    const alertName = alert?.alert || alert?.name || "Unknown Alert";
                    const description = alert?.description || "No description available";
                    const solution = alert?.solution || "";
                    const reference = typeof alert?.reference === 'string' ? alert.reference : "";
                    const url = alert?.url || "";
                    const method = alert?.method || "N/A";
                    const param = alert?.param || "";
                    const evidence = alert?.evidence || "";
                    const cweid = alert?.cweid && alert.cweid !== "-1" && alert.cweid !== "-" ? String(alert.cweid) : null;
                    const tags = (alert?.tags && typeof alert.tags === 'object' && !Array.isArray(alert.tags)) ? alert.tags : {};

                    return (
                      <TableRow key={`${alert.id || alert.alertRef || index}-${index}`}>
                        <TableCell className="max-w-md">
                          <Accordion type="single" collapsible className="w-full">
                            <AccordionItem value={`item-${index}`} className="border-none">
                              <AccordionTrigger className="py-0 hover:no-underline cursor-pointer">
                                <div className="text-left">
                                  <div className="font-semibold text-sm">
                                    {alertName}
                                  </div>
                                  <div className="text-xs text-muted-foreground mt-1 line-clamp-2">
                                    {description.length > 100 ? `${description.substring(0, 100)}...` : description}
                                  </div>
                                </div>
                              </AccordionTrigger>
                              <AccordionContent className="pt-2 pb-0">
                                <div className="space-y-3 text-sm">
                                  <div>
                                    <div className="font-medium mb-1">Description:</div>
                                    <div className="text-muted-foreground">{description}</div>
                                  </div>
                                  {solution && (
                                    <div>
                                      <div className="font-medium mb-1">Solution:</div>
                                      <div className="text-muted-foreground whitespace-pre-wrap">{solution}</div>
                                    </div>
                                  )}
                                  {param && (
                                    <div>
                                      <div className="font-medium mb-1">Parameter:</div>
                                      <div className="text-muted-foreground font-mono text-xs bg-zinc-100 dark:bg-zinc-800 p-2 rounded">
                                        {param}
                                      </div>
                                    </div>
                                  )}
                                  {evidence && (
                                    <div>
                                      <div className="font-medium mb-1">Evidence:</div>
                                      <div className="text-muted-foreground font-mono text-xs bg-zinc-100 dark:bg-zinc-800 p-2 rounded">
                                        {evidence}
                                      </div>
                                    </div>
                                  )}
                                  {cweid && (
                                    <div>
                                      <div className="font-medium mb-1">CWE ID:</div>
                                      <Badge variant="outline" className="text-xs">
                                        CWE-{cweid}
                                      </Badge>
                                    </div>
                                  )}
                                  {tags && typeof tags === 'object' && Object.keys(tags).length > 0 && (
                                    <div>
                                      <div className="font-medium mb-1">Tags:</div>
                                      <div className="flex flex-wrap gap-1">
                                        {Object.entries(tags).slice(0, 5).map(([key, value], idx) => (
                                          <Badge key={idx} variant="outline" className="text-xs">
                                            {String(key)}
                                          </Badge>
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                  {reference && typeof reference === 'string' && (
                                    <div>
                                      <div className="font-medium mb-1">Reference:</div>
                                      <div className="flex flex-wrap gap-2">
                                        {reference.split('\n').filter(Boolean).filter(ref => ref.trim().startsWith('http')).map((ref, idx) => (
                                          <a
                                            key={idx}
                                            href={ref.trim()}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="text-blue-500 hover:underline flex items-center gap-1 text-xs cursor-pointer"
                                          >
                                            <ExternalLink className="w-3 h-3 cursor-pointer" />
                                            Reference {idx + 1}
                                          </a>
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                  {alert.other && (
                                    <div>
                                      <div className="font-medium mb-1">Other Info:</div>
                                      <div className="text-muted-foreground font-mono text-xs bg-zinc-100 dark:bg-zinc-800 p-2 rounded whitespace-pre-wrap">
                                        {alert.other}
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
                            <Globe className="w-4 h-4 text-muted-foreground" />
                            <div>
                              <div className="font-medium text-sm max-w-xs truncate">
                                {url}
                              </div>
                            </div>
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline">{method}</Badge>
                        </TableCell>
                        <TableCell>{getRiskBadge(alert.risk)}</TableCell>
                        <TableCell>{getConfidenceBadge(alert.confidence)}</TableCell>
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


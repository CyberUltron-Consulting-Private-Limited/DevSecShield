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
  Package, 
  Search, 
  ExternalLink,
  CheckCircle2,
  XCircle,
  Info,
  TrendingUp,
  ArrowLeft
} from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Button } from "@/components/ui/button";
import { useRouter, useSearchParams } from "next/navigation";

interface SbomMatch {
  vulnerability: {
    id: string;
    severity: string;
    description: string;
    cvss?: Array<{
      version: string;
      vector: string;
      metrics: {
        baseScore: number;
        exploitabilityScore: number;
        impactScore: number;
      };
    }>;
    epss?: Array<{
      cve: string;
      epss: number;
      percentile: number;
    }>;
    cwes?: Array<{
      cve: string;
      cwe: string;
    }>;
    fix: {
      state: string;
      versions?: string[];
    };
    risk: number;
  };
  relatedVulnerabilities?: Array<{
    id: string;
    severity: string;
    description: string;
    urls?: string[];
    cvss?: Array<{
      version: string;
      vector: string;
      metrics: {
        baseScore: number;
      };
    }>;
  }>;
  artifact: {
    name: string;
    version: string;
    type: string;
    language?: string;
    locations?: Array<{
      path: string;
    }>;
    purl?: string;
  };
  matchDetails?: Array<{
    fix?: {
      suggestedVersion?: string;
    };
  }>;
}

interface SbomResultsData {
  matches: SbomMatch[];
  source?: {
    type: string;
    target: string;
  };
  descriptor?: {
    name: string;
    version: string;
    timestamp?: string;
  };
}

interface SbomResultsProps {
  data: SbomResultsData;
  conversationId?: number;
}

export default function SbomResults({ data, conversationId }: SbomResultsProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const origin = searchParams.get("origin") || "chat";
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [fixFilter, setFixFilter] = useState<string>("all");
  const [sortBy, setSortBy] = useState<string>("risk");

  const matches = data.matches || [];

  // Calculate statistics
  const stats = useMemo(() => {
    const total = matches.length;
    const bySeverity = matches.reduce((acc, match) => {
      const severity = match.vulnerability.severity || "Unknown";
      acc[severity] = (acc[severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const fixable = matches.filter(
      (m) => m.vulnerability.fix.state === "fixed" && m.vulnerability.fix.versions?.length
    ).length;

    const avgRisk = matches.reduce((sum, m) => sum + (m.vulnerability.risk || 0), 0) / total || 0;

    const uniquePackages = new Set(matches.map((m) => `${m.artifact.name}@${m.artifact.version}`)).size;

    return {
      total,
      bySeverity,
      fixable,
      notFixable: total - fixable,
      avgRisk,
      uniquePackages,
    };
  }, [matches]);

  // Filter and sort matches
  const filteredMatches = useMemo(() => {
    let filtered = matches.filter((match) => {
      const searchLower = searchQuery.toLowerCase();
      const matchesSearch =
        match.vulnerability.id.toLowerCase().includes(searchLower) ||
        match.vulnerability.description.toLowerCase().includes(searchLower) ||
        match.artifact.name.toLowerCase().includes(searchLower) ||
        match.artifact.version.toLowerCase().includes(searchLower) ||
        match.relatedVulnerabilities?.some((rv) =>
          rv.id.toLowerCase().includes(searchLower)
        );

      const matchesSeverity =
        severityFilter === "all" || match.vulnerability.severity === severityFilter;

      const matchesFix =
        fixFilter === "all" ||
        (fixFilter === "fixed" &&
          match.vulnerability.fix.state === "fixed" &&
          match.vulnerability.fix.versions?.length) ||
        (fixFilter === "not-fixed" && match.vulnerability.fix.state !== "fixed");

      return matchesSearch && matchesSeverity && matchesFix;
    });

    // Sort
    filtered.sort((a, b) => {
      switch (sortBy) {
        case "risk":
          return (b.vulnerability.risk || 0) - (a.vulnerability.risk || 0);
        case "severity":
          const severityOrder: Record<string, number> = {
            Critical: 4,
            High: 3,
            Medium: 2,
            Low: 1,
            Unknown: 0,
          };
          return (
            (severityOrder[b.vulnerability.severity] || 0) -
            (severityOrder[a.vulnerability.severity] || 0)
          );
        case "package":
          return a.artifact.name.localeCompare(b.artifact.name);
        case "cvss":
          const aScore =
            a.vulnerability.cvss?.[0]?.metrics.baseScore ||
            a.relatedVulnerabilities?.[0]?.cvss?.[0]?.metrics.baseScore ||
            0;
          const bScore =
            b.vulnerability.cvss?.[0]?.metrics.baseScore ||
            b.relatedVulnerabilities?.[0]?.cvss?.[0]?.metrics.baseScore ||
            0;
          return bScore - aScore;
        default:
          return 0;
      }
    });

    return filtered;
  }, [matches, searchQuery, severityFilter, fixFilter, sortBy]);

  const getSeverityBadge = (severity: string) => {
    const variants: Record<string, { className: string }> = {
      Critical: { className: "bg-red-500 hover:bg-red-600 text-white" },
      High: { className: "bg-orange-500 hover:bg-orange-600 text-white" },
      Medium: { className: "bg-yellow-500 hover:bg-yellow-600 text-white" },
      Low: { className: "bg-blue-500 hover:bg-blue-600 text-white" },
    };
    const variant = variants[severity] || { className: "bg-gray-500 hover:bg-gray-600 text-white" };
    return (
      <Badge variant="outline" className={variant.className}>
        {severity}
      </Badge>
    );
  };

  const getFixBadge = (fix: SbomMatch["vulnerability"]["fix"]) => {
    if (fix.state === "fixed" && fix.versions?.length) {
      return (
        <Badge variant="outline" className="bg-green-500 hover:bg-green-600 text-white">
          <CheckCircle2 className="w-3 h-3 mr-1" />
          Fixed ({fix.versions[0]})
        </Badge>
      );
    }
    return (
      <Badge variant="outline" className="bg-gray-500 hover:bg-gray-600 text-white">
        <XCircle className="w-3 h-3 mr-1" />
        Not Fixed
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
                  ? `/home/sbom_sca` 
                  : `/home/sbom_sca/${conversationId}`;
                router.push(backRoute);
              }}
              className="cursor-pointer"
            >
              <ArrowLeft className="h-4 w-4" />
            </Button>
          )}
          <div>
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-white">SBOM/SCA Scan Results</h1>
            {/* <p className="text-sm text-zinc-600 dark:text-zinc-400 mt-1">
              {data.source?.target && `Scanned: ${data.source.target}`}
              {data.descriptor?.timestamp && ` • ${new Date(data.descriptor.timestamp).toLocaleString()}`}
            </p> */}
          </div>
        </div>
      </div>

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Vulnerabilities</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total}</div>
            <p className="text-xs text-muted-foreground">{stats.uniquePackages} unique packages</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Fixable</CardTitle>
            <CheckCircle2 className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">{stats.fixable}</div>
            <p className="text-xs text-muted-foreground">{stats.notFixable} not fixable</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Average Risk Score</CardTitle>
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{(stats.avgRisk * 100).toFixed(1)}%</div>
            <p className="text-xs text-muted-foreground">Risk assessment</p>
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
                placeholder="Search vulnerabilities..."
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
                <SelectItem value="Critical">Critical</SelectItem>
                <SelectItem value="High">High</SelectItem>
                <SelectItem value="Medium">Medium</SelectItem>
                <SelectItem value="Low">Low</SelectItem>
              </SelectContent>
            </Select>
            <Select value={fixFilter} onValueChange={setFixFilter}>
              <SelectTrigger>
                <SelectValue placeholder="Fix Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All</SelectItem>
                <SelectItem value="fixed">Fixable</SelectItem>
                <SelectItem value="not-fixed">Not Fixable</SelectItem>
              </SelectContent>
            </Select>
            <Select value={sortBy} onValueChange={setSortBy}>
              <SelectTrigger>
                <SelectValue placeholder="Sort By" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="risk">Risk Score</SelectItem>
                <SelectItem value="severity">Severity</SelectItem>
                <SelectItem value="cvss">CVSS Score</SelectItem>
                <SelectItem value="package">Package Name</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Results Table */}
      <Card>
        <CardHeader>
          <CardTitle>Vulnerabilities ({filteredMatches.length})</CardTitle>
          <CardDescription>
            Showing {filteredMatches.length} of {matches.length} vulnerabilities
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[600px]">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Vulnerability</TableHead>
                  <TableHead>Package</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>CVSS</TableHead>
                  <TableHead>EPSS</TableHead>
                  <TableHead>Fix Status</TableHead>
                  <TableHead>Risk</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredMatches.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-8 text-muted-foreground">
                      No vulnerabilities found matching your filters.
                    </TableCell>
                  </TableRow>
                ) : (
                  filteredMatches.map((match, index) => {
                    const primaryCVE = match.relatedVulnerabilities?.[0];
                    const cvssScore =
                      match.vulnerability.cvss?.[0]?.metrics.baseScore ||
                      primaryCVE?.cvss?.[0]?.metrics.baseScore ||
                      0;
                    const epssScore = match.vulnerability.epss?.[0]?.epss || 0;

                    return (
                      <TableRow key={`${match.vulnerability.id}-${match.artifact.name}-${index}`}>
                        <TableCell className="max-w-md">
                          <Accordion type="single" collapsible className="w-full">
                            <AccordionItem value={`item-${index}`} className="border-none">
                              <AccordionTrigger className="py-0 hover:no-underline">
                                <div className="text-left">
                                  <div className="font-semibold text-sm">
                                    {match.vulnerability.id}
                                  </div>
                                  <div className="text-xs text-muted-foreground mt-1 line-clamp-2">
                                    {match.vulnerability.description}
                                  </div>
                                </div>
                              </AccordionTrigger>
                              <AccordionContent className="pt-2 pb-0">
                                <div className="space-y-3 text-sm">
                                  <div>
                                    <div className="font-medium mb-1">Description:</div>
                                    <div className="text-muted-foreground">
                                      {match.vulnerability.description}
                                    </div>
                                  </div>
                                  {primaryCVE && (
                                    <div>
                                      <div className="font-medium mb-1">CVE:</div>
                                      <div className="flex items-center gap-2">
                                        <Badge variant="outline">{primaryCVE.id}</Badge>
                                        {primaryCVE.urls && primaryCVE.urls.length > 0 && (
                                          <a
                                            href={primaryCVE.urls[0]}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="text-blue-500 hover:underline flex items-center gap-1"
                                          >
                                            <ExternalLink className="w-3 h-3" />
                                            View
                                          </a>
                                        )}
                                      </div>
                                    </div>
                                  )}
                                  {match.vulnerability.cwes && match.vulnerability.cwes.length > 0 && (
                                    <div>
                                      <div className="font-medium mb-1">CWEs:</div>
                                      <div className="flex flex-wrap gap-1">
                                        {match.vulnerability.cwes.map((cwe, idx) => (
                                          <Badge key={idx} variant="outline" className="text-xs">
                                            {cwe.cwe}
                                          </Badge>
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                  {match.artifact.locations && match.artifact.locations.length > 0 && (
                                    <div>
                                      <div className="font-medium mb-1">Location:</div>
                                      <div className="text-muted-foreground font-mono text-xs">
                                        {match.artifact.locations[0].path}
                                      </div>
                                    </div>
                                  )}
                                  {match.matchDetails?.[0]?.fix?.suggestedVersion && (
                                    <div>
                                      <div className="font-medium mb-1">Suggested Fix:</div>
                                      <div className="text-green-600 font-mono text-xs">
                                        Upgrade to {match.matchDetails[0].fix.suggestedVersion}
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
                            <Package className="w-4 h-4 text-muted-foreground" />
                            <div>
                              <div className="font-medium text-sm">{match.artifact.name}</div>
                              <div className="text-xs text-muted-foreground">
                                v{match.artifact.version}
                              </div>
                              {match.artifact.language && (
                                <Badge variant="outline" className="text-xs mt-1">
                                  {match.artifact.language}
                                </Badge>
                              )}
                            </div>
                          </div>
                        </TableCell>
                        <TableCell>{getSeverityBadge(match.vulnerability.severity)}</TableCell>
                        <TableCell>
                          {cvssScore > 0 ? (
                            <div>
                              <div className="font-semibold">{cvssScore.toFixed(1)}</div>
                              <div className="text-xs text-muted-foreground">
                                {cvssScore >= 9.0
                                  ? "Critical"
                                  : cvssScore >= 7.0
                                  ? "High"
                                  : cvssScore >= 4.0
                                  ? "Medium"
                                  : "Low"}
                              </div>
                            </div>
                          ) : (
                            <span className="text-muted-foreground text-xs">N/A</span>
                          )}
                        </TableCell>
                        <TableCell>
                          {epssScore > 0 ? (
                            <div>
                              <div className="font-semibold">{(epssScore * 100).toFixed(2)}%</div>
                              <div className="text-xs text-muted-foreground">
                                {match.vulnerability.epss?.[0]?.percentile
                                  ? `P${(match.vulnerability.epss[0].percentile * 100).toFixed(0)}`
                                  : ""}
                              </div>
                            </div>
                          ) : (
                            <span className="text-muted-foreground text-xs">N/A</span>
                          )}
                        </TableCell>
                        <TableCell>{getFixBadge(match.vulnerability.fix)}</TableCell>
                        <TableCell>
                          <div className="font-semibold">
                            {(match.vulnerability.risk * 100).toFixed(1)}%
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


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
  BookOpen,
} from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Button } from "@/components/ui/button";
import { useRouter, useSearchParams, usePathname } from "next/navigation";

interface WapitiClassification {
  desc: string;
  sol: string;
  ref: Record<string, string>;
  wstg?: string[];
}

interface WapitiVulnerabilityInstance {
  method?: string;
  path?: string;
  info?: string;
  level?: number;
  parameter?: string | null;
  referer?: string;
  module?: string;
  http_request?: string;
  curl_command?: string;
  wstg?: string[];
}

interface WapitiResultsData {
  classifications: Record<string, WapitiClassification>;
  vulnerabilities: Record<string, WapitiVulnerabilityInstance[]>;
}

interface WapitiResultsProps {
  data: WapitiResultsData;
  conversationId?: number;
}

export default function WapitiResults({ data, conversationId }: WapitiResultsProps) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const origin = searchParams.get("origin") || "chat";
  const [searchQuery, setSearchQuery] = useState("");
  const [sortBy, setSortBy] = useState<string>("name");

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
  if (!data || typeof data !== 'object') {
    return (
      <div className="container mx-auto p-6">
        <div className="text-center py-12">
          <p className="text-zinc-600 dark:text-zinc-400 mb-4">
            Invalid or missing scan results data.
          </p>
        </div>
      </div>
    );
  }
  
  const classifications = (data?.classifications && typeof data.classifications === 'object' && !Array.isArray(data.classifications)) 
    ? data.classifications 
    : {};
  
  const vulnerabilities = (data?.vulnerabilities && typeof data.vulnerabilities === 'object' && !Array.isArray(data.vulnerabilities))
    ? data.vulnerabilities
    : {};
  
  // Get vulnerability entries that have at least one instance
  const vulnerabilityEntries = Object.entries(vulnerabilities)
    .filter(([name, instances]) => 
      name && 
      Array.isArray(instances) && 
      instances.length > 0 &&
      instances.some(instance => instance && typeof instance === 'object')
    );

  // Calculate statistics with fallbacks
  const stats = useMemo(() => {
    // Count total vulnerability instances
    const total = vulnerabilityEntries.reduce((acc, [, instances]) => {
      return acc + (Array.isArray(instances) ? instances.filter(i => i && typeof i === 'object').length : 0);
    }, 0);
    
    // Count WSTG references from classifications for found vulnerabilities
    const totalWSTG = vulnerabilityEntries.reduce((acc, [vulnName]) => {
      const classification = classifications[vulnName];
      if (!classification || typeof classification !== 'object') return acc;
      const wstg = classification.wstg;
      return acc + (Array.isArray(wstg) ? wstg.length : 0);
    }, 0);
    
    // Count references from classifications for found vulnerabilities
    const totalReferences = vulnerabilityEntries.reduce((acc, [vulnName]) => {
      const classification = classifications[vulnName];
      if (!classification || typeof classification !== 'object') return acc;
      const ref = classification.ref;
      return acc + (ref && typeof ref === 'object' && !Array.isArray(ref) ? Object.keys(ref).length : 0);
    }, 0);

    return {
      total,
      totalWSTG,
      totalReferences,
    };
  }, [vulnerabilityEntries, classifications]);

  // Flatten vulnerabilities: create entries for each vulnerability instance
  const vulnerabilityInstances = useMemo(() => {
    const instances: Array<{
      vulnerabilityName: string;
      instance: WapitiVulnerabilityInstance;
      classification: WapitiClassification | undefined;
    }> = [];
    
    vulnerabilityEntries.forEach(([vulnName, vulnInstances]) => {
      const classification = classifications[vulnName];
      if (Array.isArray(vulnInstances)) {
        vulnInstances.forEach(instance => {
          if (instance && typeof instance === 'object') {
            instances.push({
              vulnerabilityName: vulnName,
              instance,
              classification: classification && typeof classification === 'object' ? classification : undefined,
            });
          }
        });
      }
    });
    
    return instances;
  }, [vulnerabilityEntries, classifications]);

  // Filter and sort results with fallbacks
  const filteredVulnerabilities = useMemo(() => {
    let filtered = vulnerabilityInstances.filter(({ vulnerabilityName, instance, classification }) => {
      if (!vulnerabilityName || !instance) return false;
      
      const searchLower = searchQuery.toLowerCase();
      const name = vulnerabilityName.toLowerCase();
      const desc = (classification?.desc && typeof classification.desc === 'string' ? classification.desc : "").toLowerCase();
      const sol = (classification?.sol && typeof classification.sol === 'string' ? classification.sol : "").toLowerCase();
      const path = (instance.path && typeof instance.path === 'string' ? instance.path : "").toLowerCase();
      const info = (instance.info && typeof instance.info === 'string' ? instance.info : "").toLowerCase();
      const wstg = Array.isArray(classification?.wstg) 
        ? classification.wstg.filter(c => typeof c === 'string').join(" ").toLowerCase()
        : "";

      const matchesSearch =
        name.includes(searchLower) ||
        desc.includes(searchLower) ||
        sol.includes(searchLower) ||
        path.includes(searchLower) ||
        info.includes(searchLower) ||
        wstg.includes(searchLower);

      return matchesSearch;
    });

    // Sort
    filtered.sort((a, b) => {
      switch (sortBy) {
        case "name":
          return a.vulnerabilityName.localeCompare(b.vulnerabilityName);
        default:
          return 0;
      }
    });

    return filtered;
  }, [vulnerabilityInstances, searchQuery, sortBy]);

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
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-white">Header/Cookie Authenticated DAST Scan Results</h1>
            <p className="text-sm text-zinc-600 dark:text-zinc-400 mt-1">
              Dynamic Application Security Testing results
            </p>
          </div>
        </div>
      </div>

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Vulnerabilities</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total}</div>
            <p className="text-xs text-muted-foreground">Vulnerability instances found</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">WSTG References</CardTitle>
            <BookOpen className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.totalWSTG}</div>
            <p className="text-xs text-muted-foreground">Web Security Testing Guide references</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">External References</CardTitle>
            <ExternalLink className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.totalReferences}</div>
            <p className="text-xs text-muted-foreground">Reference links available</p>
          </CardContent>
        </Card>
      </div>

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
                placeholder="Search vulnerabilities..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9 cursor-text"
              />
            </div>
            <Select value={sortBy} onValueChange={setSortBy}>
              <SelectTrigger className="cursor-pointer">
                <SelectValue placeholder="Sort By" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="name" className="cursor-pointer">Vulnerability Name</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Results Table */}
      <Card>
        <CardHeader>
          <CardTitle>Security Vulnerabilities ({filteredVulnerabilities.length})</CardTitle>
          <CardDescription>
            Showing {filteredVulnerabilities.length} of {vulnerabilityInstances.length} vulnerability instances
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[600px]">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Vulnerability</TableHead>
                  <TableHead>Path</TableHead>
                  <TableHead>Method</TableHead>
                  <TableHead>WSTG</TableHead>
                  <TableHead>References</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredVulnerabilities.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center py-8 text-muted-foreground">
                      No vulnerabilities found matching your filters.
                    </TableCell>
                  </TableRow>
                ) : (
                  filteredVulnerabilities
                    .map(({ vulnerabilityName, instance, classification }, index) => {
                    // Comprehensive fallbacks for all fields
                    const desc = (classification?.desc && typeof classification.desc === 'string') 
                      ? classification.desc 
                      : "No description available";
                    const sol = (classification?.sol && typeof classification.sol === 'string') 
                      ? classification.sol 
                      : "";
                    const refs = (classification?.ref && typeof classification.ref === 'object' && !Array.isArray(classification.ref)) 
                      ? classification.ref 
                      : {};
                    const wstg = Array.isArray(classification?.wstg) 
                      ? classification.wstg.filter(code => typeof code === 'string')
                      : [];
                    
                    const path = (instance?.path && typeof instance.path === 'string') ? instance.path : "N/A";
                    const method = (instance?.method && typeof instance.method === 'string') ? instance.method : "N/A";
                    const info = (instance?.info && typeof instance.info === 'string') ? instance.info : "";
                    const level = instance?.level ?? null;
                    const parameter = (instance?.parameter && typeof instance.parameter === 'string') ? instance.parameter : null;
                    const httpRequest = (instance?.http_request && typeof instance.http_request === 'string') ? instance.http_request : "";
                    const curlCommand = (instance?.curl_command && typeof instance.curl_command === 'string') ? instance.curl_command : "";

                    return (
                      <TableRow key={`${vulnerabilityName}-${index}-${path}`}>
                        <TableCell className="max-w-md">
                          <Accordion type="single" collapsible className="w-full">
                            <AccordionItem value={`item-${index}`} className="border-none">
                              <AccordionTrigger className="py-0 hover:no-underline cursor-pointer">
                                <div className="text-left">
                                  <div className="font-semibold text-sm">
                                    {vulnerabilityName}
                                  </div>
                                  {info && (
                                    <div className="text-xs text-muted-foreground mt-1 line-clamp-2">
                                      {info.length > 100 ? `${info.substring(0, 100)}...` : info}
                                    </div>
                                  )}
                                </div>
                              </AccordionTrigger>
                              <AccordionContent className="pt-2 pb-0">
                                <div className="space-y-3 text-sm">
                                  <div>
                                    <div className="font-medium mb-1">Description:</div>
                                    <div className="text-muted-foreground">{desc}</div>
                                  </div>
                                  {sol && (
                                    <div>
                                      <div className="font-medium mb-1">Solution:</div>
                                      <div className="text-muted-foreground whitespace-pre-wrap">{sol}</div>
                                    </div>
                                  )}
                                  {info && (
                                    <div>
                                      <div className="font-medium mb-1">Details:</div>
                                      <div className="text-muted-foreground">{info}</div>
                                    </div>
                                  )}
                                  {path && path !== "N/A" && (
                                    <div>
                                      <div className="font-medium mb-1">Path:</div>
                                      <div className="text-muted-foreground font-mono text-xs bg-zinc-100 dark:bg-zinc-800 p-2 rounded">
                                        {path}
                                      </div>
                                    </div>
                                  )}
                                  {parameter && (
                                    <div>
                                      <div className="font-medium mb-1">Parameter:</div>
                                      <div className="text-muted-foreground font-mono text-xs bg-zinc-100 dark:bg-zinc-800 p-2 rounded">
                                        {parameter}
                                      </div>
                                    </div>
                                  )}
                                  {level !== null && (
                                    <div>
                                      <div className="font-medium mb-1">Severity Level:</div>
                                      <Badge variant="outline" className="text-xs">
                                        Level {level}
                                      </Badge>
                                    </div>
                                  )}
                                  {httpRequest && (
                                    <div>
                                      <div className="font-medium mb-1">HTTP Request:</div>
                                      <div className="text-muted-foreground font-mono text-xs bg-zinc-100 dark:bg-zinc-800 p-2 rounded whitespace-pre-wrap max-h-40 overflow-y-auto">
                                        {httpRequest}
                                      </div>
                                    </div>
                                  )}
                                  {curlCommand && (
                                    <div>
                                      <div className="font-medium mb-1">cURL Command:</div>
                                      <div className="text-muted-foreground font-mono text-xs bg-zinc-100 dark:bg-zinc-800 p-2 rounded">
                                        {curlCommand}
                                      </div>
                                    </div>
                                  )}
                                  {wstg.length > 0 && (
                                    <div>
                                      <div className="font-medium mb-1">WSTG Codes:</div>
                                      <div className="flex flex-wrap gap-1">
                                        {wstg.map((code, idx) => (
                                          <Badge key={idx} variant="outline" className="text-xs">
                                            {code}
                                          </Badge>
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                  {refs && typeof refs === 'object' && Object.keys(refs).length > 0 && (
                                    <div>
                                      <div className="font-medium mb-1">References:</div>
                                      <div className="flex flex-col gap-2">
                                        {Object.entries(refs)
                                          .filter(([refName, refUrl]) => refName && refUrl && typeof refUrl === 'string' && refUrl.trim().startsWith('http'))
                                          .map(([refName, refUrl], idx) => (
                                            <a
                                              key={idx}
                                              href={String(refUrl).trim()}
                                              target="_blank"
                                              rel="noopener noreferrer"
                                              className="text-blue-500 hover:underline flex items-center gap-1 text-xs cursor-pointer"
                                            >
                                              <ExternalLink className="w-3 h-3 cursor-pointer" />
                                              {String(refName)}
                                            </a>
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
                          <div className="text-sm text-muted-foreground font-mono max-w-xs truncate">
                            {path}
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline">{method}</Badge>
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1">
                            {wstg.slice(0, 3).map((code, idx) => (
                              <Badge key={idx} variant="outline" className="text-xs">
                                {code}
                              </Badge>
                            ))}
                            {wstg.length > 3 && (
                              <Badge variant="outline" className="text-xs">
                                +{wstg.length - 3}
                              </Badge>
                            )}
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="text-sm text-muted-foreground">
                            {Object.keys(refs).length} reference{Object.keys(refs).length !== 1 ? 's' : ''}
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


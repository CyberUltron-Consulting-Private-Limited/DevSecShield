"use client";

// Search, filters and keyset paging for the source tables (issue #225). The server does the searching and filtering
// (GET .../sources/items?q=&kind=&segment=&status=&limit=&after=), so a team with thousands of sources loads one page
// at a time. Used by the Servers tab (its own rows and actions) and by Review & Run ("All sources").

import { keepPreviousData, useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { Loader2, Search, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { Button } from "@/components/ui/button";
import { InfoTip } from "@/components/ui/info-tip";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { listCbomScanNodes, listCbomSourcesPage, type CbomSource } from "@/utils/backend_api";

import { cbomSourcesKeys } from "./keys";
import { EmptyState, ErrorBlock, LoadingBlock, NodeStatusBadge, SectionCard, TestStatusBadge } from "./shared";
import {
  EMPTY_FILTERS, filtersActive, segmentOptions, shownLine, sourceListParams, STATUS_OPTIONS,
  type SourceFilters, type SourceStatusFilter,
} from "./sourceQuery";

const ALL = "__all";

/** One infinite query per (group, kinds, filters); invalidating ["cbom-sources", team] refreshes every loaded page. */
export function usePagedSources(teamId: number, group: string | undefined, kinds: string[], filters: SourceFilters,
                                refetchInterval?: (sources: CbomSource[]) => number | false) {
  const base = sourceListParams(group, kinds, filters, null);
  const query = useInfiniteQuery({
    queryKey: [...cbomSourcesKeys.sources(teamId, group), "page", JSON.stringify(base)],
    queryFn: ({ pageParam }) => listCbomSourcesPage(teamId, sourceListParams(group, kinds, filters, pageParam)),
    initialPageParam: null as number | null,
    getNextPageParam: (last) => last.next_after ?? undefined,
    enabled: Number.isFinite(teamId),
    placeholderData: keepPreviousData,
    retry: 1,
    refetchInterval: (q) => (refetchInterval ? refetchInterval(q.state.data?.pages.flatMap((p) => p.sources) ?? []) : false),
  });
  const sources = useMemo(() => query.data?.pages.flatMap((p) => p.sources) ?? [], [query.data]);
  const total = query.data?.pages[0]?.total ?? 0;
  const serverTime = query.data?.pages[query.data.pages.length - 1]?.server_time;
  return { query, sources, total, serverTime };
}

export function SourceFilterBar({
  teamId, filters, onChange, kinds, idPrefix,
}: {
  teamId: number;
  filters: SourceFilters;
  onChange: (next: SourceFilters) => void;
  kinds: { value: string; label: string }[];
  idPrefix: string;
}) {
  const [text, setText] = useState(filters.q); // the box; filters.q follows it after a pause (only this bar sets q)
  useEffect(() => {
    if (text === filters.q) return;
    const timer = setTimeout(() => onChange({ ...filters, q: text }), 300); // search as you type, one request per pause
    return () => clearTimeout(timer);
  }, [text, filters, onChange]);
  const nodes = useQuery({ queryKey: cbomSourcesKeys.nodes(teamId), queryFn: () => listCbomScanNodes(teamId), retry: 1 });
  const segments = segmentOptions(nodes.data?.nodes ?? []);

  return (
    <div className="flex flex-wrap items-center gap-2 mb-3" data-testid={`${idPrefix}-filters`}>
      <div className="relative min-w-[220px] flex-1 max-w-sm">
        <Search className="h-4 w-4 absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-400" aria-hidden />
        <Input
          id={`${idPrefix}-search`}
          aria-label="Search sources by name, host, IP address, owner or application"
          placeholder="Search name, host, IP, owner, application"
          className="pl-8"
          value={text}
          onChange={(e) => setText(e.target.value)}
          maxLength={128}
          data-testid={`${idPrefix}-search`}
        />
      </div>
      <InfoTip id="cbsrc.sources.search" />
      {kinds.length > 1 && <InfoTip id="cbsrc.sources.filter_kind" />}
      {kinds.length > 1 && (
        <Select value={filters.kind || ALL} onValueChange={(v) => onChange({ ...filters, kind: v === ALL ? "" : v })}>
          <SelectTrigger className="w-[180px] cursor-pointer" aria-label="Filter by type" data-testid={`${idPrefix}-kind`}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL} className="cursor-pointer">Every type</SelectItem>
            {kinds.map((k) => <SelectItem key={k.value} value={k.value} className="cursor-pointer">{k.label}</SelectItem>)}
          </SelectContent>
        </Select>
      )}
      {segments.length > 0 && <InfoTip id="cbsrc.sources.filter_segment" />}
      {segments.length > 0 && (
        <Select value={filters.segment || ALL} onValueChange={(v) => onChange({ ...filters, segment: v === ALL ? "" : v })}>
          <SelectTrigger className="w-[180px] cursor-pointer" aria-label="Filter by segment" data-testid={`${idPrefix}-segment`}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL} className="cursor-pointer">Every segment</SelectItem>
            {segments.map((s) => <SelectItem key={s} value={s} className="cursor-pointer">{s}</SelectItem>)}
          </SelectContent>
        </Select>
      )}
      <InfoTip id="cbsrc.sources.filter_status" />
      <Select value={filters.status || ALL} onValueChange={(v) => onChange({ ...filters, status: (v === ALL ? "" : v) as SourceStatusFilter })}>
        <SelectTrigger className="w-[170px] cursor-pointer" aria-label="Filter by status" data-testid={`${idPrefix}-status`}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {STATUS_OPTIONS.map((o) => (
            <SelectItem key={o.value || ALL} value={o.value || ALL} className="cursor-pointer">{o.label}</SelectItem>
          ))}
        </SelectContent>
      </Select>
      {filtersActive(filters) && (
        <Button variant="ghost" size="sm" className="cursor-pointer" onClick={() => { setText(""); onChange(EMPTY_FILTERS); }} data-testid={`${idPrefix}-clear`}>
          <X className="h-4 w-4 mr-1" />
          Clear
        </Button>
      )}
    </div>
  );
}

export function LoadMoreFooter({
  shown, total, filters, hasMore, loading, onMore, idPrefix,
}: {
  shown: number; total: number; filters: SourceFilters; hasMore: boolean; loading: boolean; onMore: () => void; idPrefix: string;
}) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 mt-3 text-sm text-zinc-600 dark:text-zinc-400">
      <span data-testid={`${idPrefix}-shown`}>{shownLine(shown, total, filters)}</span>
      {hasMore && (
        <Button variant="outline" size="sm" className="cursor-pointer" disabled={loading} onClick={onMore} data-testid={`${idPrefix}-more`}>
          {loading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
          Load more
        </Button>
      )}
    </div>
  );
}

const ALL_KINDS = [
  { value: "linux_servers", label: "Linux servers" },
  { value: "windows_servers", label: "Windows servers" },
  { value: "active_directory", label: "Active Directory" },
  { value: "database", label: "Databases" },
  { value: "kubernetes", label: "Kubernetes clusters" },
  { value: "key_manager", label: "HSMs and key managers" },
  { value: "container_images", label: "Container images" },
  { value: "network_range", label: "Network ranges" },
  { value: "appliance", label: "Network appliances" },
  { value: "aws_account", label: "AWS accounts" },
  { value: "azure_subscription", label: "Azure" },
  { value: "gcp_project", label: "Google Cloud" },
  { value: "oci_tenancy", label: "Oracle Cloud" },
  { value: "ca_connector", label: "Certificate authorities" },
  { value: "idp", label: "Identity providers" },
];

/** Review & Run: every source of the team, searchable and filterable, one page at a time. */
export function SourceBrowser({ teamId }: { teamId: number }) {
  const [filters, setFilters] = useState<SourceFilters>(EMPTY_FILTERS);
  const { query, sources, total } = usePagedSources(teamId, undefined, [], filters);

  return (
    <SectionCard infoId="cbsrc.sources.all" title="All sources" description="Search and filter every source this team has; each run covers the enabled ones in the groups you choose.">
      <SourceFilterBar teamId={teamId} filters={filters} onChange={setFilters} kinds={ALL_KINDS} idPrefix="review-sources" />
      {query.isLoading ? (
        <LoadingBlock />
      ) : query.isError ? (
        <ErrorBlock error={query.error} onRetry={() => query.refetch()} />
      ) : sources.length === 0 ? (
        <EmptyState title={filtersActive(filters) ? "No source matches" : "No sources yet"}
                    body={filtersActive(filters) ? "Change the search or clear the filters." : "Sources you add on the other tabs appear here."} />
      ) : (
        <>
          <ScrollArea className="w-full border rounded-lg">
            <div className="min-w-max">
              <Table data-testid="review-sources-table">
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Type <InfoTip id="cbsrc.col.type" /></TableHead>
                    <TableHead className="text-right">Targets <InfoTip id="cbsrc.col.targets" /></TableHead>
                    <TableHead>Scan node <InfoTip id="cbsrc.col.node" /></TableHead>
                    <TableHead>Segment <InfoTip id="cbsrc.col.segment" /></TableHead>
                    <TableHead>Last test <InfoTip id="cbsrc.col.last_test" /></TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {sources.map((s) => (
                    <TableRow key={s.id} data-testid={`review-source-${s.id}`} className={s.enabled ? undefined : "opacity-60"}>
                      <TableCell className="font-medium text-zinc-900 dark:text-white max-w-[260px] truncate" title={s.name}>
                        {s.name}{!s.enabled && <span className="ml-2 text-xs text-zinc-500">(disabled)</span>}
                      </TableCell>
                      <TableCell className="text-zinc-600 dark:text-zinc-400">{s.kind_label}</TableCell>
                      <TableCell className="text-right text-zinc-600 dark:text-zinc-400">{s.target_count.toLocaleString()}</TableCell>
                      <TableCell className="text-zinc-600 dark:text-zinc-400">
                        {s.node_id ? <span className="inline-flex items-center gap-2">{s.node_name}<NodeStatusBadge status={s.node_status} /></span> : "—"}
                      </TableCell>
                      <TableCell className="text-zinc-600 dark:text-zinc-400">{s.node_segment || "—"}</TableCell>
                      <TableCell><TestStatusBadge status={s.last_test_status} /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </ScrollArea>
          <LoadMoreFooter shown={sources.length} total={total} filters={filters} hasMore={!!query.hasNextPage}
                          loading={query.isFetchingNextPage} onMore={() => query.fetchNextPage()} idPrefix="review-sources" />
        </>
      )}
    </SectionCard>
  );
}

"use client";

// The repository inventory: every discovered repository with why it is (not) in scope, the policy that covers it and
// its last scans; filters and pages; bulk include / exclude / reset, pin to a policy, and Scan now (priced first).

import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ExternalLink, Loader2, Play } from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";

import { refusalReason } from "@/components/cbom/sources/logic";
import { EmptyState, ErrorBlock, LoadingBlock, SectionCard, StatusBadge } from "@/components/cbom/sources/shared";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  bulkScmRepositories,
  listScmPolicies,
  listScmRepositories,
  type ScmConnection,
  type ScmProduct,
  type ScmRepositoryQuery,
} from "@/utils/api/scm";
import { toast } from "@/utils/toast";

import { scmKeys } from "./keys";
import { PRODUCT_LABEL, reasonLabel, sizeLabel, toggleIds } from "./logic";
import RunDialog from "./RunDialog";

const ALL = "__all__";
const PAGE_SIZE = 50;
const SCAN_TONE: Record<string, "green" | "red" | "blue" | "zinc"> = { success: "green", failure: "red", cancelled: "zinc" };

export default function InventoryTab({ teamId, isAdmin, connections, onImport }: {
  teamId: number;
  isAdmin: boolean;
  connections: ScmConnection[];
  onImport: () => void;
}) {
  const qc = useQueryClient();
  const [query, setQuery] = useState<ScmRepositoryQuery>({ scope: "in", page: 1, page_size: PAGE_SIZE });
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<number[]>([]);
  const [runOpen, setRunOpen] = useState(false);
  const [pinTo, setPinTo] = useState<string>("");
  const effective = useMemo(() => ({ ...query, q: search.trim() || undefined }), [query, search]);
  const repos = useQuery({
    queryKey: scmKeys.repos(teamId, JSON.stringify(effective)),
    queryFn: () => listScmRepositories(teamId, effective),
    placeholderData: keepPreviousData,
    refetchInterval: 30000,
  });
  const policies = useQuery({ queryKey: scmKeys.policies(teamId), queryFn: () => listScmPolicies(teamId) });
  const bulk = useMutation({
    mutationFn: (body: Parameters<typeof bulkScmRepositories>[1]) => bulkScmRepositories(teamId, body),
    onSuccess: (data) => {
      toast.success(`${data.changed} repositories updated`);
      setSelected([]);
      qc.invalidateQueries({ queryKey: scmKeys.all(teamId) });
    },
    onError: (err) => toast.error(refusalReason(err) ?? "Could not update the repositories"),
  });
  const set = (patch: Partial<ScmRepositoryQuery>) => setQuery((q) => ({ ...q, ...patch, page: 1 }));
  const items = repos.data?.items ?? [];
  const pageIds = items.map((r) => r.id);
  const allOnPage = pageIds.length > 0 && pageIds.every((id) => selected.includes(id));
  const pages = repos.data ? Math.max(1, Math.ceil(repos.data.total / PAGE_SIZE)) : 1;

  if (!connections.length) {
    return (
      <EmptyState
        title="No repositories yet"
        body="Connect a GitHub organisation, GitLab group or Bitbucket workspace: every repository is discovered, and filters decide which ones are scanned."
        action={isAdmin ? <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={onImport}>Import repositories</Button> : undefined}
      />
    );
  }

  return (
    <SectionCard
      title="Repository inventory"
      description={repos.data ? `${repos.data.facets.in_scope.toLocaleString("en-US")} in scope of ${Object.values(repos.data.facets.reasons).reduce((a, b) => a + b, 0).toLocaleString("en-US")} discovered` : undefined}
    >
      <div className="flex flex-wrap gap-2 mb-4">
        <Input aria-label="Search repositories" placeholder="Search owner/name" className="w-full sm:w-64" value={search}
               onChange={(e) => { setSearch(e.target.value); setQuery((q) => ({ ...q, page: 1 })); }} />
        <Select value={String(query.connection_id ?? ALL)} onValueChange={(v) => set({ connection_id: v === ALL ? undefined : Number(v) })}>
          <SelectTrigger className="w-full sm:w-44 cursor-pointer" aria-label="Connection"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>All connections</SelectItem>
            {connections.map((c) => <SelectItem key={c.id} value={String(c.id)}>{c.name}</SelectItem>)}
          </SelectContent>
        </Select>
        <Select value={query.scope ?? "all"} onValueChange={(v) => set({ scope: v as ScmRepositoryQuery["scope"] })}>
          <SelectTrigger className="w-full sm:w-40 cursor-pointer" aria-label="Scope"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="in">In scope</SelectItem>
            <SelectItem value="out">Out of scope</SelectItem>
            <SelectItem value="all">All visible</SelectItem>
            <SelectItem value="removed">Removed</SelectItem>
          </SelectContent>
        </Select>
        <Select value={query.language ?? ALL} onValueChange={(v) => set({ language: v === ALL ? undefined : v })}>
          <SelectTrigger className="w-full sm:w-40 cursor-pointer" aria-label="Language"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>Any language</SelectItem>
            {Object.entries(repos.data?.facets.languages ?? {}).filter(([l]) => l).sort((a, b) => b[1] - a[1]).map(([l, n]) => (
              <SelectItem key={l} value={l}>{l} ({n})</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={query.reason ?? ALL} onValueChange={(v) => set({ reason: v === ALL ? undefined : v })}>
          <SelectTrigger className="w-full sm:w-56 cursor-pointer" aria-label="Reason"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>Any reason</SelectItem>
            {Object.entries(repos.data?.facets.reasons ?? {}).map(([r, n]) => (
              <SelectItem key={r} value={r}>{reasonLabel(r)} ({n})</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={query.scanned ?? ALL} onValueChange={(v) => set({ scanned: v === ALL ? undefined : (v as "never" | "yes") })}>
          <SelectTrigger className="w-full sm:w-40 cursor-pointer" aria-label="Scanned"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>Scanned or not</SelectItem>
            <SelectItem value="never">Never scanned</SelectItem>
            <SelectItem value="yes">Scanned</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {isAdmin && selected.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 mb-3 rounded-lg border border-blue-500/40 bg-blue-500/5 p-3" role="region" aria-label="Bulk actions">
          <span className="text-sm font-medium mr-2">{selected.length} selected</span>
          <Button size="sm" className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => setRunOpen(true)}>
            <Play className="h-4 w-4 mr-1.5" />Scan now
          </Button>
          <Button size="sm" variant="outline" className="cursor-pointer" disabled={bulk.isPending} onClick={() => bulk.mutate({ repo_ids: selected, action: "include" })}>Include</Button>
          <Button size="sm" variant="outline" className="cursor-pointer" disabled={bulk.isPending} onClick={() => bulk.mutate({ repo_ids: selected, action: "exclude" })}>Exclude</Button>
          <Button size="sm" variant="outline" className="cursor-pointer" disabled={bulk.isPending} onClick={() => bulk.mutate({ repo_ids: selected, action: "reset" })}>Back to filters</Button>
          <Select value={pinTo} onValueChange={(v) => { setPinTo(""); bulk.mutate(v === "none" ? { repo_ids: selected, action: "unpin_policy" } : { repo_ids: selected, action: "pin_policy", policy_id: Number(v) }); }}>
            <SelectTrigger className="h-8 w-44 cursor-pointer" aria-label="Pin to a policy"><SelectValue placeholder="Pin to a policy" /></SelectTrigger>
            <SelectContent>
              {(policies.data?.policies ?? []).map((p) => <SelectItem key={p.id} value={String(p.id)}>{p.name}</SelectItem>)}
              <SelectItem value="none">No pinned policy</SelectItem>
            </SelectContent>
          </Select>
          <Button size="sm" variant="ghost" className="cursor-pointer" onClick={() => setSelected([])}>Clear</Button>
        </div>
      )}

      {repos.isLoading ? <LoadingBlock /> : repos.isError ? <ErrorBlock error={repos.error} onRetry={() => repos.refetch()} /> : !items.length ? (
        <EmptyState title="No repositories match" body="Change the filters above, or the connection's import filters." />
      ) : (
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                {isAdmin && (
                  <TableHead className="w-8">
                    <input type="checkbox" aria-label="Select every repository on this page" className="h-4 w-4 accent-blue-600 cursor-pointer"
                           checked={allOnPage} onChange={(e) => setSelected((s) => toggleIds(s, pageIds, e.target.checked))} />
                  </TableHead>
                )}
                <TableHead>Repository</TableHead>
                <TableHead>Language</TableHead>
                <TableHead>Size</TableHead>
                <TableHead>Scope</TableHead>
                <TableHead>Policy</TableHead>
                <TableHead>Last scans</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((r) => (
                <TableRow key={r.id}>
                  {isAdmin && (
                    <TableCell>
                      <input type="checkbox" aria-label={`Select ${r.full_name}`} className="h-4 w-4 accent-blue-600 cursor-pointer"
                             checked={selected.includes(r.id)} onChange={(e) => setSelected((s) => toggleIds(s, [r.id], e.target.checked))} />
                    </TableCell>
                  )}
                  <TableCell className="min-w-[220px]">
                    <div className="flex items-center gap-1.5">
                      <span className="font-medium break-all">{r.full_name}</span>
                      {r.web_url && (
                        <a href={r.web_url} target="_blank" rel="noopener noreferrer" aria-label={`Open ${r.full_name} on the provider`} className="text-zinc-500 hover:text-blue-600">
                          <ExternalLink className="h-3.5 w-3.5" />
                        </a>
                      )}
                    </div>
                    <span className="text-xs text-zinc-500">{r.connection} · {r.default_branch}{r.archived ? " · archived" : ""}{r.fork ? " · fork" : ""}</span>
                  </TableCell>
                  <TableCell>{r.language ?? <span className="text-zinc-500">Unknown</span>}</TableCell>
                  <TableCell className="whitespace-nowrap">{sizeLabel(r.size_kb)}</TableCell>
                  <TableCell>
                    <StatusBadge tone={r.in_scope ? "green" : r.removed_at ? "red" : "zinc"} title={reasonLabel(r.scope_reason)}>
                      {r.in_scope ? "In scope" : r.removed_at ? "Removed" : "Out"}
                    </StatusBadge>
                    <span className="block text-xs text-zinc-500 mt-1">{reasonLabel(r.scope_reason)}</span>
                  </TableCell>
                  <TableCell>
                    {r.policy ? (
                      <span title={r.policy.why === "pinned" ? "Pinned to this policy" : "First policy whose selector matches"}>
                        {r.policy.name}
                        <span className="block text-xs text-zinc-500">{r.policy.why === "pinned" ? "pinned" : "by selector"}{r.policy.on_push ? " · on push" : ""}</span>
                      </span>
                    ) : <span className="text-zinc-500 text-sm">{r.in_scope ? "No policy" : "-"}</span>}
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {Object.entries(r.last_scans).map(([p, s]) => s && (
                        <Link key={p} href={`/${teamId}/${p}/${s.scan_id}`} title={`${PRODUCT_LABEL[p as ScmProduct]}: ${s.status}${s.findings !== undefined ? `, ${s.findings} findings` : ""}`}>
                          <StatusBadge tone={SCAN_TONE[s.status] ?? "blue"}>{PRODUCT_LABEL[p as ScmProduct]}{s.findings !== undefined ? ` ${s.findings}` : ""}</StatusBadge>
                        </Link>
                      ))}
                      {!Object.keys(r.last_scans).length && <span className="text-xs text-zinc-500">Not scanned</span>}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      <div className="flex flex-wrap items-center justify-between gap-2 mt-4 text-sm text-zinc-600 dark:text-zinc-400">
        <span>{repos.data ? `${repos.data.total.toLocaleString("en-US")} repositories · page ${query.page} of ${pages}` : ""}{repos.isFetching && <Loader2 className="inline h-3.5 w-3.5 ml-2 animate-spin" />}</span>
        <div className="flex gap-2">
          <Button size="sm" variant="outline" className="cursor-pointer" disabled={(query.page ?? 1) <= 1} onClick={() => setQuery((q) => ({ ...q, page: (q.page ?? 1) - 1 }))}>Previous</Button>
          <Button size="sm" variant="outline" className="cursor-pointer" disabled={(query.page ?? 1) >= pages} onClick={() => setQuery((q) => ({ ...q, page: (q.page ?? 1) + 1 }))}>Next</Button>
        </div>
      </div>
      {runOpen && (
        <RunDialog teamId={teamId} open={runOpen} onOpenChange={setRunOpen}
                   target={{ repo_ids: selected }} chooseProducts title={`Scan ${selected.length} repositories now`} />
      )}
    </SectionCard>
  );
}

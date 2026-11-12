"use client";

// The roll-up across repositories: the same issue in many repositories is one finding with a repository count
// (backend/utilities/scm/rollup.py); open one to see every repository and location it is in.

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { ExternalLink } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import { EmptyState, ErrorBlock, LoadingBlock, SectionCard, StatCard, StatusBadge } from "@/components/cbom/sources/shared";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { getScmFinding, getScmRollup, listScmFindings, type ScmFinding, type ScmProduct } from "@/utils/api/scm";

import { scmKeys } from "./keys";
import { PRODUCT_LABEL, PRODUCTS } from "./logic";

const ALL = "__all__";
const SEV_TONE: Record<string, "red" | "amber" | "blue" | "zinc"> = { critical: "red", high: "red", medium: "amber", low: "blue", info: "zinc" };

function FindingDetail({ teamId, finding, onClose }: { teamId: number; finding: ScmFinding; onClose: () => void }) {
  const q = useQuery({ queryKey: scmKeys.finding(teamId, finding.id), queryFn: () => getScmFinding(teamId, finding.id) });
  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="break-words">{finding.title}</DialogTitle>
          <DialogDescription>
            {PRODUCT_LABEL[finding.product]} · in {finding.repo_count} repositories, {finding.occurrence_count} places in all
          </DialogDescription>
        </DialogHeader>
        {q.isLoading ? <LoadingBlock /> : q.isError || !q.data ? <ErrorBlock error={q.error} onRetry={() => q.refetch()} /> : (
          <ul className="divide-y divide-zinc-200 dark:divide-zinc-800 text-sm">
            {q.data.repositories.map((r) => (
              <li key={r.repo_id} className="py-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium break-all">{r.repo}</span>
                  {r.web_url && <a href={r.web_url} target="_blank" rel="noopener noreferrer" aria-label={`Open ${r.repo}`} className="text-zinc-500 hover:text-blue-600"><ExternalLink className="h-3.5 w-3.5" /></a>}
                  {r.scan_id && <Link className="text-xs text-blue-600 hover:underline" href={`/${teamId}/${finding.product}/${r.scan_id}`}>scan #{r.scan_id}</Link>}
                  <span className="text-xs text-zinc-500">{r.count}×</span>
                </div>
                {r.locations.length > 0 && <p className="text-xs text-zinc-500 break-all">{r.locations.join(" · ")}</p>}
              </li>
            ))}
          </ul>
        )}
      </DialogContent>
    </Dialog>
  );
}

export default function FindingsTab({ teamId }: { teamId: number }) {
  const [product, setProduct] = useState<string>(ALL);
  const [severity, setSeverity] = useState<string>(ALL);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [opened, setOpened] = useState<ScmFinding | null>(null);
  const rollup = useQuery({ queryKey: scmKeys.rollup(teamId), queryFn: () => getScmRollup(teamId), refetchInterval: 30000 });
  const query = { product: product === ALL ? undefined : (product as ScmProduct), severity: severity === ALL ? undefined : severity, q: search.trim() || undefined, page };
  const findings = useQuery({
    queryKey: scmKeys.findings(teamId, JSON.stringify(query)),
    queryFn: () => listScmFindings(teamId, query),
    placeholderData: keepPreviousData,
  });
  const r = rollup.data;
  const totals = r ? Object.values(r.products).reduce((acc, p) => ({ open: acc.open + (p?.findings_open ?? 0), occ: acc.occ + (p?.occurrences ?? 0) }), { open: 0, occ: 0 }) : null;
  return (
    <div className="space-y-4">
      {rollup.isError ? <ErrorBlock error={rollup.error} onRetry={() => rollup.refetch()} /> : r && totals && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <StatCard label="Repositories scanned" value={`${r.repos_scanned.toLocaleString("en-US")} / ${r.repos_in_scope.toLocaleString("en-US")}`} hint="in scope" />
          <StatCard label="Distinct open findings" value={totals.open.toLocaleString("en-US")} />
          <StatCard label="Occurrences across repositories" value={totals.occ.toLocaleString("en-US")} />
          <StatCard label="De-duplication" value={totals.open ? `${(totals.occ / totals.open).toFixed(1)}×` : "-"} hint="occurrences per distinct finding" />
        </div>
      )}
      <SectionCard title="Findings across repositories" description="Most widespread first. A rescan of a repository replaces what it found there; a finding fixed everywhere is resolved.">
        <div className="flex flex-wrap gap-2 mb-4">
          <Input aria-label="Search findings" placeholder="Search titles" className="w-full sm:w-64" value={search} onChange={(e) => { setSearch(e.target.value); setPage(1); }} />
          <Select value={product} onValueChange={(v) => { setProduct(v); setPage(1); }}>
            <SelectTrigger className="w-full sm:w-44 cursor-pointer" aria-label="Product"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL}>All products</SelectItem>
              {PRODUCTS.map((p) => <SelectItem key={p} value={p}>{PRODUCT_LABEL[p]}</SelectItem>)}
            </SelectContent>
          </Select>
          <Select value={severity} onValueChange={(v) => { setSeverity(v); setPage(1); }}>
            <SelectTrigger className="w-full sm:w-40 cursor-pointer" aria-label="Severity"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL}>Any severity</SelectItem>
              {["critical", "high", "medium", "low", "info"].map((s) => <SelectItem key={s} value={s}>{s[0].toUpperCase() + s.slice(1)}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>
        {findings.isLoading ? <LoadingBlock /> : findings.isError || !findings.data ? <ErrorBlock error={findings.error} onRetry={() => findings.refetch()} /> : !findings.data.items.length ? (
          <EmptyState title="No findings yet" body="Findings appear here as repository scans finish." />
        ) : (
          <>
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow><TableHead>Finding</TableHead><TableHead>Product</TableHead><TableHead>Severity</TableHead><TableHead>Repositories</TableHead><TableHead>Places</TableHead></TableRow>
                </TableHeader>
                <TableBody>
                  {findings.data.items.map((f) => (
                    <TableRow key={f.id}>
                      <TableCell className="min-w-[240px]">
                        <button type="button" className="text-left font-medium hover:underline cursor-pointer break-words" onClick={() => setOpened(f)}>{f.title}</button>
                      </TableCell>
                      <TableCell>{PRODUCT_LABEL[f.product]}</TableCell>
                      <TableCell><StatusBadge tone={SEV_TONE[f.severity] ?? "zinc"}>{f.severity}</StatusBadge></TableCell>
                      <TableCell className="font-semibold">{f.repo_count}</TableCell>
                      <TableCell>{f.occurrence_count}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            <div className="flex justify-between items-center mt-3 text-sm text-zinc-600 dark:text-zinc-400">
              <span>{findings.data.total.toLocaleString("en-US")} findings</span>
              <div className="flex gap-2">
                <Button size="sm" variant="outline" className="cursor-pointer" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Previous</Button>
                <Button size="sm" variant="outline" className="cursor-pointer" disabled={page * findings.data.page_size >= findings.data.total} onClick={() => setPage((p) => p + 1)}>Next</Button>
              </div>
            </div>
          </>
        )}
      </SectionCard>
      {opened && <FindingDetail teamId={teamId} finding={opened} onClose={() => setOpened(null)} />}
    </div>
  );
}

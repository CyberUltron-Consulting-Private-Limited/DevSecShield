"use client";

// Runs and the queue: each run (manual, scheduled, push) with its price, what is waiting, running and finished, the
// queue's caps, and Cancel (scans that have not started are refunded).

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronDown, ChevronRight, Loader2 } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import { refusalReason } from "@/components/cbom/sources/logic";
import { ConfirmDialog, EmptyState, ErrorBlock, LoadingBlock, SectionCard, StatCard, StatusBadge } from "@/components/cbom/sources/shared";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { cancelScmRun, getScmRun, listScmRuns, type ScmRun } from "@/utils/api/scm";
import { toast } from "@/utils/toast";

import { scmKeys } from "./keys";
import { capsText, formatCredits, PRODUCT_LABEL } from "./logic";

const RUN_TONE: Record<string, "green" | "blue" | "zinc"> = { done: "green", running: "blue", queued: "blue", cancelled: "zinc" };
const REQ_TONE: Record<string, "green" | "blue" | "red" | "zinc" | "amber"> = {
  queued: "zinc", dispatching: "blue", dispatched: "blue", done: "green", failed: "red", skipped: "amber", cancelled: "zinc",
};
const REQ_LABEL: Record<string, string> = {
  queued: "Waiting", dispatching: "Starting", dispatched: "Running", done: "Done", failed: "Failed", skipped: "Skipped", cancelled: "Cancelled",
};
const TRIGGER: Record<string, string> = { manual: "Manual", schedule: "Scheduled", push: "Push" };

function RunRequests({ teamId, run }: { teamId: number; run: ScmRun }) {
  const [page, setPage] = useState(1);
  const q = useQuery({ queryKey: scmKeys.run(teamId, run.id, page), queryFn: () => getScmRun(teamId, run.id, page), refetchInterval: 10000 });
  if (q.isLoading) return <LoadingBlock />;
  if (q.isError || !q.data) return <ErrorBlock error={q.error} onRetry={() => q.refetch()} />;
  const total = Object.values(run.requests).reduce((a, b) => a + b, 0);
  return (
    <div className="overflow-x-auto">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Repository</TableHead><TableHead>Product</TableHead><TableHead>Status</TableHead><TableHead>Credits</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {q.data.requests.map((r) => (
            <TableRow key={r.id}>
              <TableCell className="break-all">{r.repo}<span className="block text-xs text-zinc-500">{r.branch}</span></TableCell>
              <TableCell>{PRODUCT_LABEL[r.product] ?? r.product}</TableCell>
              <TableCell>
                {r.scan_id ? (
                  <Link href={`/${teamId}/${r.product}/${r.scan_id}`}><StatusBadge tone={REQ_TONE[r.status] ?? "zinc"}>{REQ_LABEL[r.status] ?? r.status}</StatusBadge></Link>
                ) : <StatusBadge tone={REQ_TONE[r.status] ?? "zinc"}>{REQ_LABEL[r.status] ?? r.status}</StatusBadge>}
                {r.error && <span className="block text-xs text-zinc-500 mt-1">{r.error}</span>}
              </TableCell>
              <TableCell className="whitespace-nowrap">{formatCredits(r.credits)}{r.refunded ? " (refunded)" : ""}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {total > 50 && (
        <div className="flex justify-end gap-2 mt-2">
          <Button size="sm" variant="outline" className="cursor-pointer" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Previous</Button>
          <Button size="sm" variant="outline" className="cursor-pointer" disabled={page * 50 >= total} onClick={() => setPage((p) => p + 1)}>Next</Button>
        </div>
      )}
    </div>
  );
}

export default function RunsTab({ teamId, isAdmin }: { teamId: number; isAdmin: boolean }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: scmKeys.runs(teamId), queryFn: () => listScmRuns(teamId), refetchInterval: 10000 });
  const [open, setOpen] = useState<number | null>(null);
  const [cancelling, setCancelling] = useState<ScmRun | null>(null);
  const cancel = useMutation({
    mutationFn: (id: number) => cancelScmRun(teamId, id),
    onSuccess: (r) => { toast.success(`Cancelled; ${formatCredits(r.refunded)} refunded`); setCancelling(null); qc.invalidateQueries({ queryKey: scmKeys.all(teamId) }); qc.invalidateQueries({ queryKey: ["teams"] }); qc.invalidateQueries({ queryKey: scmKeys.team(teamId) }); },
    onError: (err) => toast.error(refusalReason(err) ?? "Could not cancel the run"),
  });
  if (q.isLoading) return <LoadingBlock />;
  if (q.isError || !q.data) return <ErrorBlock error={q.error} onRetry={() => q.refetch()} />;
  const { runs, queue } = q.data;
  const s = queue.by_status;
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard label="Waiting" value={(s.queued ?? 0).toLocaleString("en-US")} hint={Object.entries(queue.queued_by_trigger).map(([t, n]) => `${TRIGGER[t] ?? t} ${n}`).join(" · ") || undefined} />
        <StatCard label="Running" value={((s.dispatched ?? 0) + (s.dispatching ?? 0)).toLocaleString("en-US")} hint={capsText(queue.max_inflight, queue.team_max_inflight)} />
        <StatCard label="Done" value={(s.done ?? 0).toLocaleString("en-US")} tone="green" />
        <StatCard label="Failed or skipped" value={((s.failed ?? 0) + (s.skipped ?? 0)).toLocaleString("en-US")} tone={(s.failed ?? 0) > 0 ? "red" : undefined} />
      </div>
      <SectionCard title="Runs" description="Push scans go first, then scans started by hand, then scheduled ones; teams share the scanners fairly.">
        {!runs.length ? <EmptyState title="No runs yet" body="Start one from the inventory (Scan now) or a policy (Run now), or let a schedule or a push start it." /> : (
          <ul className="divide-y divide-zinc-200 dark:divide-zinc-800">
            {runs.map((r) => {
              const waiting = r.requests.queued ?? 0;
              const expanded = open === r.id;
              return (
                <li key={r.id} className="py-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <button type="button" className="flex items-center gap-2 text-left cursor-pointer" aria-expanded={expanded} onClick={() => setOpen(expanded ? null : r.id)}>
                      {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                      <span className="font-medium">Run #{r.id}</span>
                      <StatusBadge tone="zinc">{TRIGGER[r.trigger] ?? r.trigger}</StatusBadge>
                      <StatusBadge tone={RUN_TONE[r.status] ?? "zinc"}>{r.status}</StatusBadge>
                      {r.status === "running" && <Loader2 className="h-3.5 w-3.5 animate-spin text-blue-600" />}
                    </button>
                    <div className="flex items-center gap-3 text-sm text-zinc-600 dark:text-zinc-400">
                      <span>{Object.entries(r.requests).map(([k, n]) => `${REQ_LABEL[k] ?? k} ${n}`).join(" · ")}</span>
                      <span>{formatCredits(r.credits)}{r.refunded ? `, ${formatCredits(r.refunded)} refunded` : ""}</span>
                      {isAdmin && waiting > 0 && r.status !== "cancelled" && (
                        <Button size="sm" variant="outline" className="cursor-pointer" onClick={() => setCancelling(r)}>Cancel</Button>
                      )}
                    </div>
                  </div>
                  <p className="text-xs text-zinc-500 ml-6">{r.created_at ? new Date(r.created_at).toLocaleString() : ""}{r.totals.commit ? ` · commit ${r.totals.commit.slice(0, 10)}` : ""}</p>
                  {expanded && <div className="mt-3"><RunRequests teamId={teamId} run={r} /></div>}
                </li>
              );
            })}
          </ul>
        )}
      </SectionCard>
      <ConfirmDialog
        open={Boolean(cancelling)}
        onOpenChange={(v) => !v && setCancelling(null)}
        title={`Cancel run #${cancelling?.id ?? ""}?`}
        description={`The ${cancelling?.requests.queued ?? 0} scans that have not started are cancelled and refunded. Scans already running finish (cancel them on their scan page).`}
        confirmLabel="Cancel the waiting scans"
        destructive
        pending={cancel.isPending}
        onConfirm={() => cancelling && cancel.mutate(cancelling.id)}
      />
    </div>
  );
}

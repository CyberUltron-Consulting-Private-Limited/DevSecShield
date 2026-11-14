"use client";

// Ticketing tab of a CBOM Sources run (CB-38 PR-4), the run's counterpart of the code-scan page's Ticketing tab:
// the run's findings with their Jira issue, select and "Create Jira tickets" (one issue per asset; an asset that
// already has one, from this run or an earlier run of the same source, keeps it), the outcome per asset, and the team's
// Jira project for CBOM Sources (a team admin sets it; credentials stay in Team settings and never reach the browser).

import Link from "next/link";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ExternalLink, Loader2, Save, Ticket } from "lucide-react";
import { useMemo, useState } from "react";

import { JiraIcon } from "@/components/icons/arcticons-jira";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { cbomSourcesKeys } from "@/components/cbom/sources/keys";
import { ErrorBlock, LoadingBlock, StatusBadge, Truncate, type Tone } from "@/components/cbom/sources/shared";
import { toast } from "@/utils/toast";
import {
  createCbomRunTickets,
  getCbomRunTicketAssets,
  getCbomSourcesTicketing,
  updateCbomSourcesTicketing,
  type CbomImpact,
  type CbomRunTicketsResult,
  type CbomSourcesTicketing,
} from "@/utils/backend_api";

import {
  batchFailure,
  batches,
  hasTicket,
  isTicketable,
  mergeResults,
  normalizeProjectKey,
  outcomes,
  resultSummary,
  safeTicketUrl,
  selectableIds,
  ticketingState,
  type TicketOutcome,
} from "./runTicketing";

const PAGE_SIZE = 100;
const IMPACT_TONE: Record<CbomImpact, Tone> = { Critical: "red", High: "red", Medium: "amber", Low: "blue" };
const OUTCOME_TONE: Record<TicketOutcome["state"], Tone> = {
  created: "green", existing: "blue", failed: "red", deferred: "amber", skipped: "zinc",
};
const OUTCOME_LABEL: Record<TicketOutcome["state"], string> = {
  created: "Created", existing: "Already had one", failed: "Failed", deferred: "Retry", skipped: "Not a finding",
};

const ticketingKey = (teamId: number) => [...cbomSourcesKeys.all(teamId), "ticketing"] as const;

function TicketLink({ ticketKey, url }: { ticketKey: string | null | undefined; url: string | null | undefined }) {
  if (!ticketKey) return <span className="text-xs text-zinc-500">—</span>;
  const href = safeTicketUrl(url);
  if (!href) return <span className="font-mono text-xs">{ticketKey}</span>;
  return (
    <a href={href} target="_blank" rel="noopener noreferrer"
       className="inline-flex items-center gap-1 font-mono text-xs text-blue-600 hover:underline dark:text-blue-400">
      {ticketKey}
      <ExternalLink className="h-3 w-3" aria-hidden />
    </a>
  );
}

function ProjectSettings({ teamId, ticketing }: { teamId: number; ticketing: CbomSourcesTicketing }) {
  const queryClient = useQueryClient();
  const [project, setProject] = useState(ticketing.jira_project_key ?? "");
  const [issueType, setIssueType] = useState(ticketing.jira_issue_type);
  const checked = normalizeProjectKey(project);
  const save = useMutation({
    mutationFn: () => updateCbomSourcesTicketing(teamId, {
      jira_project_key: checked.value,
      jira_issue_type: issueType.trim() || null,
      expected_version: ticketing.row_version,
    }),
    onSuccess: (saved) => queryClient.setQueryData(ticketingKey(teamId), saved),
  });

  if (!ticketing.is_admin) {
    return (
      <p className="text-sm text-zinc-600 dark:text-zinc-400" data-testid="run-ticketing-project-readonly">
        Jira project for CBOM Sources: <span className="font-mono">{ticketing.jira_project_key ?? "not set"}</span>
        {" · "}issue type {ticketing.jira_issue_type}. A team admin can change it.
      </p>
    );
  }
  return (
    <form
      className="flex flex-wrap items-end gap-3"
      data-testid="run-ticketing-project-form"
      onSubmit={(e) => { e.preventDefault(); if (!checked.error) save.mutate(); }}
    >
      <div className="space-y-1">
        <Label htmlFor="run-ticketing-project">Jira project for CBOM Sources</Label>
        <Input id="run-ticketing-project" value={project} onChange={(e) => setProject(e.target.value)}
               placeholder="e.g. SEC or 10000" className="w-48" aria-invalid={checked.error ? true : undefined}
               aria-describedby="run-ticketing-project-help" />
      </div>
      <div className="space-y-1">
        <Label htmlFor="run-ticketing-issue-type">Issue type</Label>
        <Input id="run-ticketing-issue-type" value={issueType} onChange={(e) => setIssueType(e.target.value)}
               placeholder={ticketing.issue_type_default} className="w-40" maxLength={64} />
      </div>
      <Button type="submit" disabled={save.isPending || checked.error != null}
              className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" data-testid="run-ticketing-project-save">
        {save.isPending ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Save className="w-4 h-4 mr-2" />}
        Save
      </Button>
      <p id="run-ticketing-project-help" className={`basis-full text-xs ${checked.error ? "text-red-600" : "text-zinc-500"}`}>
        {checked.error ?? "One project for every Sources run of this team. Leave it empty to stop creating tickets."}
      </p>
    </form>
  );
}

export default function RunTicketingTab({ teamId, runId }: { teamId: number; runId: number }) {
  const queryClient = useQueryClient();
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [lastResult, setLastResult] = useState<TicketOutcome[] | null>(null);

  const ticketingQuery = useQuery({ queryKey: ticketingKey(teamId), queryFn: () => getCbomSourcesTicketing(teamId) });
  const assetsQuery = useQuery({
    queryKey: cbomSourcesKeys.runAssets(teamId, runId, `tickets:${page}`),
    queryFn: () => getCbomRunTicketAssets(teamId, runId, page, PAGE_SIZE),
    placeholderData: keepPreviousData,
  });

  // findings only (an API without view=findings lists every asset: clean inventory is filtered here, never ticketed)
  const items = useMemo(() => (assetsQuery.data?.items ?? []).filter(isTicketable), [assetsQuery.data]);
  const selectable = useMemo(() => selectableIds(items), [items]);
  const state = ticketingState(ticketingQuery.data);
  const canCreate = state === "ready";

  const create = useMutation({
    // every batch is reported: a batch that fails as a whole (network, 504, a project cleared meanwhile) lists its
    // assets as failed and never hides what the earlier batches created
    mutationFn: async (ids: number[]): Promise<CbomRunTicketsResult> => {
      const results: CbomRunTicketsResult[] = [];
      for (const batch of batches(ids)) {
        try {
          results.push(await createCbomRunTickets(teamId, runId, batch));
        } catch (error) {
          results.push(batchFailure(batch, error));
        }
      }
      return mergeResults(results);
    },
    onSuccess: (result) => {
      setLastResult(outcomes(result, items));
      setSelected(new Set());
      const message = resultSummary(result);
      if (result.failed.length) toast.error(message);
      else toast.success(message);
    },
    onSettled: () => void queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.run(teamId, runId) }),
  });

  const toggle = (id: number) => setSelected((cur) => {
    const next = new Set(cur);
    if (next.has(id)) next.delete(id); else next.add(id);
    return next;
  });
  const allOnPage = selectable.length > 0 && selectable.every((id) => selected.has(id));

  if (ticketingQuery.isLoading || assetsQuery.isLoading) return <LoadingBlock />;
  if (ticketingQuery.isError) return <ErrorBlock error={ticketingQuery.error} onRetry={() => void ticketingQuery.refetch()} />;
  if (assetsQuery.isError) return <ErrorBlock error={assetsQuery.error} onRetry={() => void assetsQuery.refetch()} />;
  const ticketing = ticketingQuery.data!;
  const data = assetsQuery.data!;
  // findings_total comes with the findings view; an older API counts every asset, and the label says so
  const countsFindings = typeof data.findings_total === "number";
  const total = countsFindings ? data.findings_total! : data.total;
  const noun = countsFindings ? (total === 1 ? "finding" : "findings") : (total === 1 ? "asset" : "assets");
  const pages = Math.max(1, Math.ceil(data.total / PAGE_SIZE));

  return (
    <div className="space-y-4" data-testid="run-ticketing">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <span className="inline-flex items-center justify-center rounded-md bg-blue-600 p-1.5">
              <JiraIcon size={18} className="text-white" />
            </span>
            Jira tickets for this run
          </CardTitle>
          <CardDescription>
            One Jira issue per finding. An asset that already has an issue (from this run or an earlier run of the same
            source) keeps it; no duplicate is opened.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {state === "not_connected" ? (
            <p className="text-sm text-amber-700 dark:text-amber-400" role="status" data-testid="run-ticketing-not-connected">
              Jira is not connected for this team, so tickets cannot be created yet. A team admin connects Jira in{" "}
              <Link href={`/${teamId}/settings`} className="underline">Team settings</Link>; existing tickets stay listed below.
            </p>
          ) : (
            <>
              {state === "no_project" && (
                <p className="text-sm text-amber-700 dark:text-amber-400" role="status" data-testid="run-ticketing-no-project">
                  No Jira project is set for CBOM Sources yet.{" "}
                  {ticketing.is_admin ? "Set it below to create tickets." : "Ask a team admin to set it."}
                </p>
              )}
              {/* keyed by the saved version: the form starts again from what the server holds after every save */}
              <ProjectSettings key={ticketing.row_version} teamId={teamId} ticketing={ticketing} />
            </>
          )}
        </CardContent>
      </Card>

      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm text-zinc-600 dark:text-zinc-400" data-testid="run-ticketing-count">
          {total} {noun} in this run. Select findings without a ticket, then create Jira tickets.
        </p>
        <Button
          type="button"
          disabled={!canCreate || selected.size === 0 || create.isPending}
          onClick={() => create.mutate([...selected])}
          className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
          data-testid="run-ticketing-create"
          title={canCreate ? undefined : "Connect Jira and set the project first"}
        >
          {create.isPending ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Ticket className="w-4 h-4 mr-2" />}
          Create Jira tickets{selected.size > 0 ? ` (${selected.size})` : ""}
        </Button>
      </div>

      {lastResult && lastResult.length > 0 && (
        <div className="rounded-lg border p-3 space-y-1" role="status" data-testid="run-ticketing-result">
          {lastResult.map((r) => (
            <div key={`${r.state}-${r.asset_id}`} className="flex flex-wrap items-center gap-2 text-sm"
                 data-testid={`run-ticketing-result-${r.asset_id}`} data-state={r.state}>
              <StatusBadge tone={OUTCOME_TONE[r.state]}>{OUTCOME_LABEL[r.state]}</StatusBadge>
              <span className="font-mono text-xs text-zinc-700 dark:text-zinc-300">{r.label}</span>
              {r.ticket_key && <TicketLink ticketKey={r.ticket_key} url={r.ticket_url} />}
              {r.error && <span className="text-xs text-red-600 dark:text-red-400">{r.error}</span>}
            </div>
          ))}
        </div>
      )}

      {items.length === 0 ? (
        <p className="text-sm text-zinc-500" data-testid="run-ticketing-empty">No findings on this page: nothing to ticket.</p>
      ) : (
        <ScrollArea className="w-full border rounded-lg">
          <div className="min-w-max">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-6">
                    <input type="checkbox" className="cursor-pointer" aria-label="Select every finding without a ticket on this page"
                           disabled={!canCreate || selectable.length === 0} checked={allOnPage}
                           onChange={() => setSelected(allOnPage ? new Set() : new Set(selectable))} />
                  </TableHead>
                  <TableHead>Impact</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Where</TableHead>
                  <TableHead>Finding</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Jira</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((a) => (
                  <TableRow key={a.id} data-testid={`run-ticket-asset-${a.id}`} data-ticket={a.ticket_key ?? ""}>
                    <TableCell>
                      {!hasTicket(a) && (
                        <input type="checkbox" className="cursor-pointer" disabled={!canCreate}
                               aria-label={`Select ${a.location} for a Jira ticket`} checked={selected.has(a.id)}
                               onChange={() => toggle(a.id)} />
                      )}
                    </TableCell>
                    <TableCell>
                      {a.impact ? <StatusBadge tone={IMPACT_TONE[a.impact]}>{a.impact}</StatusBadge>
                        : <StatusBadge tone="amber">Quantum</StatusBadge>}
                    </TableCell>
                    <TableCell className="text-zinc-600 dark:text-zinc-400">{a.type}</TableCell>
                    <TableCell className="max-w-[260px]">
                      <Truncate text={a.location} className="font-mono text-xs" />
                      {a.target && a.target !== a.location && <Truncate text={a.target} className="text-xs text-zinc-500" />}
                    </TableCell>
                    <TableCell className="max-w-[320px]"><Truncate text={a.finding} className="text-zinc-600 dark:text-zinc-400" /></TableCell>
                    <TableCell className="text-zinc-600 dark:text-zinc-400">{a.source_name ?? "—"}</TableCell>
                    <TableCell><TicketLink ticketKey={a.ticket_key} url={a.ticket_url} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <ScrollBar orientation="horizontal" />
        </ScrollArea>
      )}

      {pages > 1 && (
        <div className="flex items-center justify-end gap-2 text-sm">
          <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous</Button>
          <span className="text-zinc-500">Page {page} of {pages}</span>
          <Button variant="outline" size="sm" disabled={page >= pages} onClick={() => setPage(page + 1)}>Next</Button>
        </div>
      )}
    </div>
  );
}

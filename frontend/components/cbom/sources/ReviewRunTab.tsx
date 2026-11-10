"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Ban, Calculator, Eye, GitCompare, Loader2, Play } from "lucide-react";
import { useState, type ReactNode } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  cancelCbomRun,
  estimateCbomSources,
  getCbomRun,
  getCbomSourcesOverview,
  listCbomRuns,
  startCbomRun,
  type CbomEstimate,
  type CbomIncludeKey,
  type CbomJobStatus,
  type CbomPlanItem,
  type CbomRun,
  type CbomSourceGroup,
  type CbomSourcesOverview,
} from "@/utils/backend_api";

import { CompareDialog, RunChanges } from "./ChangesPanel";
import { cbomSourcesKeys, TERMINAL_RUN } from "./keys";
import RunResults from "./RunResults";
import { CriticalityCard } from "./RunPosture";
import SchedulesCard from "./SchedulesCard";
import { startRefusal } from "./startRefusal";
import { SourceMetadataCard } from "./SourceMetadata";
import { addressProgress, credits, formatDateTime, mixedGroupScope, newRequestId, pluralize, windowLine, windowStartNotice } from "./logic";
import {
  Checkbox2,
  ConfirmDialog,
  EmptyState,
  ErrorBlock,
  JobStatusBadge,
  LoadingBlock,
  RunStatusBadge,
  SectionCard,
  StatusBadge,
  Truncate,
  type Tone,
} from "./shared";

type IncludeState = Record<CbomIncludeKey, boolean>;

const INCLUDE_OPTIONS: { key: CbomIncludeKey; label: string; groups: CbomSourceGroup[] }[] = [
  { key: "servers", label: "Servers", groups: ["servers"] },
  { key: "kubernetes", label: "Kubernetes", groups: ["kubernetes"] },
  { key: "databases", label: "Databases", groups: ["databases"] },
  { key: "cloud", label: "Cloud", groups: ["cloud", "identity"] },
  { key: "network", label: "Network", groups: ["network"] },
];

const GROUP_LABEL: Record<CbomSourceGroup, string> = {
  servers: "Servers",
  kubernetes: "Kubernetes",
  databases: "Databases",
  cloud: "Cloud",
  identity: "Certificates and identity",
  network: "Network TLS",
};

const KIND_SHORT: Record<string, string> = {
  linux_servers: "Linux",
  windows_servers: "Windows",
  active_directory: "Active Directory",
  aws_account: "AWS",
  azure_subscription: "Azure",
  gcp_project: "Google Cloud",
  ca_connector: "CA",
  idp: "IdP",
  host_agent: "Host agent",
  container_images: "Container images",
};

const JOB_ORDER: CbomJobStatus[] = ["pending", "claimed", "success", "failure", "cancelled", "expired"];
const JOB_WORD: Record<CbomJobStatus, string> = {
  pending: "waiting",
  claimed: "running",
  success: "done",
  failure: "failed",
  cancelled: "cancelled",
  expired: "expired",
};

const TAB_LINK: Record<string, string> = {
  servers: "Open Servers",
  "k8s-db": "Open Kubernetes & Databases",
  cloud: "Open Cloud & Identity",
  network: "Open Network TLS",
  evidence: "Answer it on Evidence",
  "scan-nodes": "Check the node",
};

// ---------------------------------------------------------------------------- helpers
function httpStatus(err: unknown): number | undefined {
  return (err as { response?: { status?: number } } | null)?.response?.status;
}

function isActiveRun(status: string | undefined): boolean {
  return status === "queued" || status === "running";
}

function kindsSummary(byKind: Record<string, number> | undefined): string {
  const parts = Object.entries(byKind ?? {})
    .filter(([, n]) => n > 0)
    .map(([kind, n]) => `${n} ${KIND_SHORT[kind] ?? kind}`);
  return parts.join(", ");
}

/** Scan nodes the group's sources run through; cloud-side sources are reached from ZeroShield's own cloud. */
function reachedThrough(items: CbomPlanItem[], cloudSide: boolean): string {
  const names = Array.from(new Set(items.map((i) => i.node_name).filter((n): n is string => !!n)));
  const viaCloud = cloudSide && items.some((i) => !i.node_id);
  const nodes = names.length === 0 ? null : names.length === 1 ? names[0] : `${names.length} scan nodes`;
  if (viaCloud && nodes) return `ZeroShield cloud and ${nodes}`;
  if (viaCloud) return "ZeroShield cloud";
  if (nodes) return nodes;
  return items.length ? "No scan node assigned" : "—";
}

function groupStatus(sources: number, issues: number): ReactNode {
  if (!sources) return <StatusBadge tone="zinc">Not configured</StatusBadge>;
  if (issues) return <StatusBadge tone="amber">{pluralize(issues, "issue")}</StatusBadge>;
  return <StatusBadge tone="green">Ready</StatusBadge>;
}

function skipBadge(item: CbomPlanItem): [Tone, string] {
  if (item.status === "gap" || item.kind === "evidence") return ["amber", "Gap"];
  const reason = (item.reason ?? "").toLowerCase();
  if ((item.kind === "scan_node" && item.status === "waiting") || reason.includes("offline")) return ["red", "Offline"];
  if (reason.includes("not available yet") || reason.startsWith("already queued") || reason === "disabled" || reason.startsWith("0 targets")) {
    return ["amber", "Partial"];
  }
  return ["red", "Blocked"];
}

function skipTab(item: CbomPlanItem): string | null {
  const g = item.group ?? item.kind;
  if (g === "servers") return "servers";
  if (g === "kubernetes" || g === "databases" || g === "database") return "k8s-db";
  if (g === "cloud" || g === "identity") return "cloud";
  if (g === "network" || g === "network_range") return "network";
  if (g === "evidence") return "evidence";
  if (g === "scan_node") return "scan-nodes";
  return null;
}

function skipText(item: CbomPlanItem): string {
  const reason = item.reason ?? "Skipped";
  return item.name && !reason.includes(item.name) ? `${item.name}: ${reason}` : reason;
}

function jobSummary(counts: CbomRun["job_counts"]): string {
  if (!counts) return "—";
  const parts = JOB_ORDER.filter((s) => (counts[s] ?? 0) > 0).map((s) => `${counts[s]} ${JOB_WORD[s]}`);
  return parts.length ? parts.join(" · ") : "No jobs";
}

function defaultInclude(overview: CbomSourcesOverview): IncludeState {
  const groups = overview.plan.groups ?? {};
  const state = {} as IncludeState;
  for (const opt of INCLUDE_OPTIONS) state[opt.key] = opt.groups.some((g) => (groups[g]?.queued ?? 0) > 0);
  return state;
}

function sameInclude(a: IncludeState, b: IncludeState): boolean {
  return INCLUDE_OPTIONS.every((o) => a[o.key] === b[o.key]);
}

// ---------------------------------------------------------------------------- tab
export default function ReviewRunTab({ teamId, onNavigate }: { teamId: number; onNavigate: (tab: string) => void }) {
  const queryClient = useQueryClient();
  const [detailsRunId, setDetailsRunId] = useState<number | null>(null);
  const [compareRunId, setCompareRunId] = useState<number | null>(null);
  const [cancelling, setCancelling] = useState<CbomRun | null>(null);

  const overviewQuery = useQuery({
    queryKey: cbomSourcesKeys.overview(teamId),
    queryFn: () => getCbomSourcesOverview(teamId),
    enabled: Number.isFinite(teamId),
    retry: 1,
    refetchInterval: 30000,
    // the Start card's defaults come from this data: never from a copy cached before sources were added
    refetchOnMount: "always",
  });

  const runsQuery = useQuery({
    queryKey: cbomSourcesKeys.runs(teamId),
    queryFn: () => listCbomRuns(teamId),
    enabled: Number.isFinite(teamId),
    retry: 1,
    refetchInterval: (query) => (query.state.data?.runs.some((r) => !TERMINAL_RUN.has(r.status)) ? 6000 : 30000),
  });

  const invalidate = () => queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) });

  const cancelMutation = useMutation({
    mutationFn: (run: CbomRun) => cancelCbomRun(teamId, run.id),
    onSuccess: (data) => {
      setCancelling(null);
      // The API toast shows the refunded amount; say what happens to work already on a node.
      const running = data.run.job_counts?.claimed ?? 0;
      if (running > 0) toast.info(`Jobs already running on a node finish (${pluralize(running, "job")} still running)`);
    },
    onError: (err) => {
      if (httpStatus(err) === 404) setCancelling(null);
    },
    onSettled: () => {
      invalidate();
      // A refund changes the credit balance shown in the app sidebar.
      queryClient.invalidateQueries({ queryKey: ["teams"] });
    },
  });

  // Wait for this visit's own fetch: other tabs share this cache entry and may have loaded it before the
  // network ranges or cloud sources existed, and the Start card takes its include defaults from the first data.
  if (overviewQuery.isLoading || (!overviewQuery.isFetchedAfterMount && overviewQuery.isFetching)) return <LoadingBlock />;
  if (overviewQuery.isError && !overviewQuery.data) return <ErrorBlock error={overviewQuery.error} onRetry={() => overviewQuery.refetch()} />;
  const overview = overviewQuery.data;
  if (!overview) return <LoadingBlock />;

  const plan = overview.plan;
  const items = plan.items ?? [];
  const skipped = plan.skipped ?? [];
  const totalSources = Object.values(overview.groups ?? {}).reduce((sum, g) => sum + (g?.sources ?? 0), 0);
  const runs = runsQuery.data?.runs ?? [];

  const rows: { key: string; label: string; scope: ReactNode; through: string; lastTest: ReactNode; credits: ReactNode; status: ReactNode }[] = [];

  rows.push({
    key: "code",
    label: "Code and pipelines",
    scope: pluralize(overview.code.cbom_scans, "CBOM scan"),
    through: "ZeroShield cloud",
    lastTest: "—",
    credits: "Charged per code scan",
    status: overview.code.cbom_scans > 0 ? <StatusBadge tone="green">Ready</StatusBadge> : <StatusBadge tone="zinc">Not configured</StatusBadge>,
  });

  const groupRow = (group: CbomSourceGroup, label: string, scope: (sources: number, units: number, kinds: string) => ReactNode, cloudSide = false) => {
    const g = overview.groups?.[group];
    const sources = g?.sources ?? 0;
    const units = g?.units ?? 0;
    const groupItems = items.filter((i) => i.group === group);
    const issues = skipped.filter((i) => i.group === group).length;
    const failed = g?.failed_tests ?? 0;
    // scan-node jobs wait for their scan window (the network row prints the team window itself)
    const windowNote = group === "network" ? null : windowLine(groupItems);
    rows.push({
      key: group,
      label,
      scope: !sources ? "Nothing configured" : windowNote ? (
        <>
          <span>{scope(sources, units, kindsSummary(g?.by_kind))}</span>
          <span className="block text-xs text-zinc-500" data-testid={`review-window-${group}`}>{windowNote}</span>
        </>
      ) : scope(sources, units, kindsSummary(g?.by_kind)),
      through: sources ? reachedThrough(groupItems, cloudSide) : "—",
      lastTest: !sources ? "—" : failed ? <span className="text-red-600 dark:text-red-400">{failed} failed</span> : "No failed tests",
      credits: sources ? credits(plan.groups?.[group]?.credits ?? 0) : "—",
      status: groupStatus(sources, issues),
    });
  };

  groupRow("servers", "Linux and Windows servers", (s, u, k) => `${pluralize(s, "source")} · ${pluralize(u, "target")}${k ? ` (${k})` : ""}`);
  groupRow("kubernetes", "Kubernetes", (_s, u) => mixedGroupScope("kubernetes", overview.groups?.kubernetes?.by_kind, u));
  groupRow("databases", "Databases", (_s, u) => mixedGroupScope("databases", overview.groups?.databases?.by_kind, u));
  groupRow("cloud", "Cloud", (_s, u, k) => `${pluralize(u, "account")}${k ? ` (${k})` : ""}`, true);
  groupRow(
    "identity",
    "Certificates and identity",
    (s, _u, k) =>
      `${pluralize(s, "connector")}${k ? ` (${k})` : ""}${overview.settings.cert_domains ? ` · ${pluralize(overview.settings.cert_domains, "certificate domain")}` : ""}`,
    true,
  );
  groupRow("network", "Network TLS", (s, u) => (
    <>
      <span>
        {pluralize(s, "range")} · {pluralize(u, "address", "addresses")} · {pluralize(overview.settings.ports, "port")}
      </span>
      <span className="block text-xs text-zinc-500">
        {overview.settings.stop_all_network ? (
          <span className="text-red-600 dark:text-red-400">Network scanning is stopped</span>
        ) : overview.settings.in_window_now ? (
          "In the scan window now"
        ) : overview.settings.next_window_start ? (
          `Next window starts ${formatDateTime(overview.settings.next_window_start)}`
        ) : (
          "No scan window set"
        )}
      </span>
    </>
  ));

  const gaps = Math.max(0, overview.evidence.areas - overview.evidence.answered);
  rows.push({
    key: "evidence",
    label: "Evidence",
    scope: `${pluralize(overview.evidence.areas, "area")} · ${pluralize(overview.evidence.vendors, "vendor")}`,
    through: "Questionnaires",
    lastTest: `${overview.evidence.answered} of ${overview.evidence.areas} answered`,
    credits: "No charge",
    status: gaps ? <StatusBadge tone="amber">{pluralize(gaps, "gap")}</StatusBadge> : <StatusBadge tone="green">Ready</StatusBadge>,
  });

  return (
    <div className="space-y-6">
      <p className="text-sm text-zinc-600 dark:text-zinc-400 max-w-3xl">
        Everything this scan will cover, what it will skip and why. Nothing is skipped silently.
      </p>

      <SectionCard title="Coverage" description={`${pluralize(totalSources, "source")} configured`}>
        <ScrollArea className="w-full border rounded-lg">
          <div className="min-w-max">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Source</TableHead>
                  <TableHead>In scope</TableHead>
                  <TableHead>Reached through</TableHead>
                  <TableHead>Last test</TableHead>
                  <TableHead>Credits</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((row) => (
                  <TableRow key={row.key} className="hover:bg-zinc-50 dark:hover:bg-zinc-800" data-testid={`review-coverage-${row.key}`}>
                    <TableCell className="font-medium text-zinc-900 dark:text-white">{row.label}</TableCell>
                    <TableCell className="text-zinc-600 dark:text-zinc-400 max-w-[340px] whitespace-normal">{row.scope}</TableCell>
                    <TableCell className="text-zinc-600 dark:text-zinc-400 max-w-[220px]">
                      <Truncate text={row.through} />
                    </TableCell>
                    <TableCell className="text-zinc-600 dark:text-zinc-400">{row.lastTest}</TableCell>
                    <TableCell className="text-zinc-600 dark:text-zinc-400">{row.credits}</TableCell>
                    <TableCell>{row.status}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <ScrollBar orientation="horizontal" />
        </ScrollArea>
      </SectionCard>

      <CriticalityCard teamId={teamId} />
      <SourceMetadataCard teamId={teamId} />

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 items-start">
        <div className="xl:col-span-2 min-w-0">
          <SectionCard title="Will be skipped unless you fix it" description={pluralize(skipped.length, "item")}>
            {skipped.length === 0 ? (
              <EmptyState title="Nothing will be skipped" body="Every configured source can be collected and every evidence area has an answer." />
            ) : (
              <ul className="divide-y divide-zinc-200 dark:divide-zinc-800" data-testid="review-skipped">
                {skipped.map((item, index) => {
                  const [tone, label] = skipBadge(item);
                  const tab = skipTab(item);
                  return (
                    <li key={`${item.kind}-${item.source_id ?? item.node_id ?? item.area_key ?? item.name}-${index}`} className="flex items-start gap-3 py-3 first:pt-0 last:pb-0">
                      <span className="shrink-0 pt-0.5">
                        <StatusBadge tone={tone}>{label}</StatusBadge>
                      </span>
                      <div className="min-w-0 flex-1 text-sm text-zinc-700 dark:text-zinc-300 break-words">
                        {skipText(item)}
                        {tab && (
                          <>
                            {" "}
                            <button
                              type="button"
                              className="text-blue-600 dark:text-blue-400 hover:underline cursor-pointer"
                              onClick={() => onNavigate(tab)}
                            >
                              {TAB_LINK[tab]}
                            </button>
                          </>
                        )}
                      </div>
                    </li>
                  );
                })}
              </ul>
            )}
          </SectionCard>
        </div>

        <SectionCard title="What you get after the scan">
          <ul className="list-disc pl-5 space-y-2 text-sm text-zinc-700 dark:text-zinc-300">
            <li>Collection jobs queued per source for your scan nodes</li>
            <li>A run record with the credits charged and refunded</li>
            <li>
              A proof trail: the CBOM Sources audit log, the scan node source IPs to tell your SOC, and the read-only AWS role whose
              calls appear in your CloudTrail
            </li>
            <li>Evidence gaps listed as Q0, never assumed safe</li>
          </ul>
          <p className="text-xs text-zinc-500 mt-4">Results feed the CBOM report once the collector for each source type ships.</p>
        </SectionCard>
      </div>

      {totalSources === 0 ? (
        <SectionCard title="Start a scan" id="cbom-review-start">
          <EmptyState
            title="Nothing to scan yet"
            body="Add a scan node inside the network you want covered, then the servers, clusters, databases or ranges it can reach."
            action={
              <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => onNavigate("scan-nodes")}>
                Add a scan node
              </Button>
            }
          />
        </SectionCard>
      ) : (
        <StartCard key={`start-${teamId}`} teamId={teamId} overview={overview} />
      )}

      <SectionCard title="Runs" description="The 50 most recent collection runs for this team">
        {runsQuery.isLoading ? (
          <LoadingBlock />
        ) : runsQuery.isError && !runsQuery.data ? (
          <ErrorBlock error={runsQuery.error} onRetry={() => runsQuery.refetch()} />
        ) : runs.length === 0 ? (
          <EmptyState
            title="No runs yet"
            body="Estimate the credits, then start a scan. Each run appears here with its jobs and credits."
            action={
              <Button
                variant="outline"
                className="cursor-pointer"
                onClick={() => document.getElementById("cbom-review-start")?.scrollIntoView({ behavior: "smooth", block: "center" })}
              >
                <Calculator className="h-4 w-4 mr-2" />
                Estimate credits
              </Button>
            }
          />
        ) : (
          <ScrollArea className="w-full border rounded-lg">
            <div className="min-w-max">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Run</TableHead>
                    <TableHead>Started</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Jobs</TableHead>
                    <TableHead className="text-right">Assets</TableHead>
                    <TableHead>Credits</TableHead>
                    <TableHead>
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {runs.map((run) => (
                    <TableRow key={run.id} className="hover:bg-zinc-50 dark:hover:bg-zinc-800" data-testid={`review-run-${run.id}`}>
                      <TableCell className="font-medium text-zinc-900 dark:text-white">#{run.id}</TableCell>
                      <TableCell className="text-zinc-600 dark:text-zinc-400">{formatDateTime(run.created_at)}</TableCell>
                      <TableCell>
                        <RunStatusBadge status={run.status} />
                      </TableCell>
                      <TableCell className="text-zinc-600 dark:text-zinc-400">{jobSummary(run.job_counts)}</TableCell>
                      <TableCell className="text-right text-zinc-600 dark:text-zinc-400" data-testid={`review-run-assets-${run.id}`}>
                        {run.asset_count ?? 0}
                      </TableCell>
                      <TableCell className="text-zinc-600 dark:text-zinc-400">
                        {credits(run.credits.charged)} charged / {credits(run.credits.refunded)} refunded
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center justify-end gap-2">
                          <Button
                            size="sm"
                            variant="outline"
                            className="cursor-pointer"
                            data-testid={`review-run-details-${run.id}`}
                            onClick={() => setDetailsRunId(run.id)}
                          >
                            <Eye className="h-4 w-4 mr-1.5" />
                            Results
                          </Button>
                          {TERMINAL_RUN.has(run.status) && runs.length > 1 && (
                            <Button
                              size="sm"
                              variant="outline"
                              className="cursor-pointer"
                              data-testid={`review-run-compare-${run.id}`}
                              onClick={() => setCompareRunId(run.id)}
                            >
                              <GitCompare className="h-4 w-4 mr-1.5" />
                              Compare
                            </Button>
                          )}
                          {isActiveRun(run.status) && ((run.job_counts?.pending ?? 0) + (run.job_counts?.claimed ?? 0)) > 0 &&
                            (overview.viewer?.is_admin || overview.viewer?.user_id === run.owner_user_id) && (
                            <Button
                              size="sm"
                              variant="outline"
                              className="cursor-pointer text-red-600 dark:text-red-400"
                              data-testid={`review-run-cancel-${run.id}`}
                              onClick={() => setCancelling(run)}
                            >
                              <Ban className="h-4 w-4 mr-1.5" />
                              Cancel
                            </Button>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            <ScrollBar orientation="horizontal" />
          </ScrollArea>
        )}
      </SectionCard>

      {detailsRunId !== null && (
        <RunDetailsDialog key={detailsRunId} teamId={teamId} runId={detailsRunId} onClose={() => setDetailsRunId(null)} />
      )}
      {compareRunId !== null && (
        <CompareDialog key={compareRunId} teamId={teamId} runId={compareRunId} runs={runs} onClose={() => setCompareRunId(null)} />
      )}

      <SchedulesCard teamId={teamId} />

      <ConfirmDialog
        open={!!cancelling}
        onOpenChange={(v) => !v && setCancelling(null)}
        title={cancelling ? `Cancel run #${cancelling.id}?` : "Cancel run?"}
        description="Jobs not yet picked up are cancelled and refunded at once. Running jobs are told to stop and are refunded when they stop; what they collected so far is kept. Only the person who started the run or a team admin can cancel it."
        confirmLabel="Cancel run"
        destructive
        pending={cancelMutation.isPending}
        onConfirm={() => cancelling && cancelMutation.mutate(cancelling)}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------- start card
const NOTICE_CLASS = {
  green: "text-sm text-green-600 dark:text-green-400",
  amber: "text-sm text-amber-600 dark:text-amber-400",
  red: "text-sm text-red-600 dark:text-red-400",
} as const;

interface Snapshot {
  estimate: CbomEstimate;
  include: IncludeState;
  requestId: string;
}

function StartCard({ teamId, overview }: { teamId: number; overview: CbomSourcesOverview }) {
  const queryClient = useQueryClient();
  // Mounted once the overview has loaded, so the defaults come from the first load without an effect.
  const [include, setInclude] = useState<IncludeState>(() => defaultInclude(overview));
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [socAck, setSocAck] = useState(false);
  const [socError, setSocError] = useState<string | null>(null);
  const [notice, setNotice] = useState<{ tone: "green" | "amber" | "red"; text: string } | null>(null);

  // The estimate is a snapshot of one set of groups; a late response for other groups never shows.
  const current = snapshot && sameInclude(snapshot.include, include) ? snapshot : null;
  const anyIncluded = INCLUDE_OPTIONS.some((o) => include[o.key]);
  const planGroups = overview.plan.groups ?? {};

  const estimateMutation = useMutation({
    mutationFn: (inc: IncludeState) => estimateCbomSources(teamId, inc),
    // One client_request_id per estimate snapshot: a double click or a retry replays instead of charging twice.
    onSuccess: (data, inc) => setSnapshot({ estimate: data, include: inc, requestId: newRequestId() }),
  });

  const startMutation = useMutation({
    mutationFn: ({ snap, ack }: { snap: Snapshot; ack: boolean }) =>
      startCbomRun(teamId, {
        include: snap.include,
        client_request_id: snap.requestId,
        expected_credits: snap.estimate.total_credits,
        soc_ack: snap.include.network ? ack : false,
      }),
    onSuccess: (data) => {
      setSnapshot(null);
      setNotice({
        tone: "green",
        text: data.replayed
          ? `Run #${data.run.id} was already started from this estimate; nothing was charged again.`
          : `Run #${data.run.id} queued: ${credits(data.run.credits.charged)} credits charged. Follow it under Runs below.`,
      });
      queryClient.invalidateQueries({ queryKey: ["teams"] });
    },
    onError: (err) => {
      // the server's reason (credits, rate limit, validation, estimate changed, already queued) stays on the card
      const refusal = startRefusal(err);
      if (refusal.clearEstimate) setSnapshot(null);
      setNotice({ tone: refusal.tone, text: refusal.text });
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) }),
  });

  const toggle = (key: CbomIncludeKey, value: boolean) => {
    setInclude({ ...include, [key]: value });
    setSnapshot(null);
    setNotice(null);
    setSocError(null);
  };

  const estimate = current?.estimate ?? null;
  const queued = estimate ? estimate.items.filter((i) => i.status === "queued") : [];
  const waiting = queued.filter((i) => i.waiting_for_node).length;
  const balance = estimate?.credit_balance ?? overview.credit_balance;
  const canStart = !!estimate && (estimate.total_credits > 0 || queued.length > 0);
  const groupEntries = estimate
    ? (Object.entries(estimate.groups ?? {}) as [CbomSourceGroup, NonNullable<CbomEstimate["groups"][CbomSourceGroup]>][])
    : [];

  const start = () => {
    if (!current || !canStart) return;
    if (include.network && !socAck) {
      setSocError("Confirm that your SOC has agreed the network ranges and scan windows");
      return;
    }
    setSocError(null);
    setNotice(null);
    startMutation.mutate({ snap: current, ack: socAck });
  };

  return (
    <SectionCard title="Start a scan" description="Choose what to collect, estimate the credits, then start." id="cbom-review-start">
      <div className="space-y-5">
        <div className="flex flex-wrap gap-x-6 gap-y-3" role="group" aria-label="Groups to include" data-testid="review-include">
          {INCLUDE_OPTIONS.map((opt) => {
            const queuedCount = opt.groups.reduce((sum, g) => sum + (planGroups[g]?.queued ?? 0), 0);
            return (
              <Checkbox2 key={opt.key} id={`review-include-${opt.key}`} checked={include[opt.key]} onChange={(v) => toggle(opt.key, v)}>
                {opt.label} <span className="text-zinc-500">· {queuedCount} ready</span>
              </Checkbox2>
            );
          })}
        </div>

        <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 p-4 space-y-3" data-testid="review-estimate-result">
          {estimate ? (
            <>
              <p className="text-zinc-700 dark:text-zinc-300">
                Credits required:{" "}
                <span className="font-semibold text-blue-600 dark:text-blue-400" data-testid="review-credits-required">
                  {credits(estimate.total_credits)}
                </span>
              </p>
              {groupEntries.length > 0 ? (
                <ul className="space-y-1 text-sm text-zinc-600 dark:text-zinc-400">
                  {groupEntries.map(([group, g]) => (
                    <li key={group}>
                      {GROUP_LABEL[group] ?? group}: {credits(g.credits)} credits · {pluralize(g.queued, "source")} queued
                      {g.skipped ? ` · ${g.skipped} skipped` : ""}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-zinc-600 dark:text-zinc-400">No sources in the chosen groups.</p>
              )}
              <p className="text-sm text-zinc-600 dark:text-zinc-400">
                Team balance: <span className="font-medium text-zinc-900 dark:text-white">{credits(balance)}</span> credits
              </p>
              {estimate.total_credits > balance && (
                <p className="text-sm text-red-600 dark:text-red-400">
                  Not enough credits: this run needs {credits(estimate.total_credits)} and the team has {credits(balance)}.
                </p>
              )}
              {queued.length === 0 && (
                <p className="text-sm text-amber-600 dark:text-amber-400">
                  Every source in the chosen groups will be skipped; see the list above.
                </p>
              )}
              {windowStartNotice(queued) && (
                <p className="text-sm text-amber-600 dark:text-amber-400" data-testid="review-window-notice">
                  {windowStartNotice(queued)}
                </p>
              )}
              {waiting > 0 && (
                <p className="text-sm text-amber-600 dark:text-amber-400">
                  {pluralize(waiting, "source")} will wait for an offline scan node. They are charged now and refunded if they
                  expire unclaimed.
                </p>
              )}
              <p className="text-xs text-zinc-500">This estimate is a snapshot; changing the groups clears it.</p>
            </>
          ) : (
            <p className="text-sm text-zinc-600 dark:text-zinc-400">
              {estimateMutation.isError
                ? "Could not estimate the credits. Try again."
                : "Estimate the credits to see what this scan charges against your team balance."}
            </p>
          )}
        </div>

        <div className="space-y-1.5">
          <Checkbox2
            id="review-soc-ack"
            checked={socAck}
            onChange={(v) => {
              setSocAck(v);
              if (v) setSocError(null);
            }}
          >
            Our SOC has agreed the network ranges and scan windows
            {include.network && <span className="text-red-500">*</span>}
          </Checkbox2>
          {socError && (
            <p className="text-sm text-red-500 dark:text-red-400" role="alert">
              {socError}
            </p>
          )}
        </div>

        {notice && (
          <p
            className={NOTICE_CLASS[notice.tone]}
            role={notice.tone === "green" ? "status" : "alert"}
            data-testid="review-start-notice"
          >
            {notice.text}
          </p>
        )}

        <div className="flex flex-wrap gap-3">
          <Button
            variant="outline"
            className="cursor-pointer"
            disabled={!anyIncluded || estimateMutation.isPending}
            data-testid="review-estimate"
            onClick={() => {
              setNotice(null);
              estimateMutation.mutate({ ...include });
            }}
          >
            {estimateMutation.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Calculator className="h-4 w-4 mr-2" />}
            Estimate credits required
          </Button>
          <Button
            className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
            disabled={!canStart || startMutation.isPending}
            data-testid="review-start"
            onClick={start}
          >
            {startMutation.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Play className="h-4 w-4 mr-2" />}
            Start scan
          </Button>
        </div>
        {!anyIncluded && <p className="text-xs text-zinc-500">Choose at least one group to estimate.</p>}
      </div>
    </SectionCard>
  );
}

// ---------------------------------------------------------------------------- run details
function RunDetailsDialog({ teamId, runId, onClose }: { teamId: number; runId: number; onClose: () => void }) {
  const runQuery = useQuery({
    queryKey: cbomSourcesKeys.run(teamId, runId),
    queryFn: () => getCbomRun(teamId, runId),
    enabled: Number.isFinite(teamId),
    retry: 1,
    refetchInterval: (query) => {
      if (httpStatus(query.state.error) === 404) return false;
      const status = query.state.data?.status;
      return !status || isActiveRun(status) ? 6000 : false;
    },
  });
  const run = runQuery.data;
  const jobs = run?.jobs ?? [];
  const skippedAtStart = run?.breakdown?.skipped ?? [];

  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-6xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Run #{runId}</DialogTitle>
          <DialogDescription>
            {run ? (
              <>
                <RunStatusBadge status={run.status} /> · started {formatDateTime(run.created_at)} · {credits(run.credits.charged)} charged,{" "}
                {credits(run.credits.refunded)} refunded
              </>
            ) : (
              "Loading the run"
            )}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 min-w-0">
          {runQuery.isLoading ? (
            <LoadingBlock />
          ) : runQuery.isError && !run ? (
            <ErrorBlock
              message={httpStatus(runQuery.error) === 404 ? "This run no longer exists." : undefined}
              error={runQuery.error}
              onRetry={httpStatus(runQuery.error) === 404 ? undefined : () => runQuery.refetch()}
            />
          ) : jobs.length === 0 ? (
            <EmptyState title="No jobs in this run" />
          ) : (
            <ScrollArea className="w-full border rounded-lg">
              <div className="min-w-max">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Source</TableHead>
                      <TableHead>Runs on</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead className="text-right">Assets</TableHead>
                      <TableHead className="text-right">Credits</TableHead>
                      <TableHead className="text-right">Attempts</TableHead>
                      <TableHead>Error</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {jobs.map((job) => (
                      <TableRow key={job.id} data-testid={`review-job-${job.id}`}>
                        <TableCell className="font-medium text-zinc-900 dark:text-white max-w-[220px]">
                          <Truncate text={job.source_name ?? `Source ${job.source_id ?? "—"}`} />
                        </TableCell>
                        <TableCell className="text-zinc-600 dark:text-zinc-400 max-w-[180px]">
                          <Truncate text={job.runner === "cloud" ? "ZeroShield cloud" : job.node_name ?? "—"} />
                        </TableCell>
                        <TableCell className="max-w-[260px]">
                          <JobStatusBadge status={job.status} title={job.waiting_reason} />
                          {job.waiting_reason && (
                            <p className="mt-1 whitespace-normal text-xs text-zinc-500">{job.waiting_reason}</p>
                          )}
                          {addressProgress(job) && (
                            <p className="mt-0.5 whitespace-normal text-xs text-zinc-700 dark:text-zinc-300" data-testid={`review-job-progress-${job.id}`}>
                              {addressProgress(job)}
                            </p>
                          )}
                        </TableCell>
                        <TableCell className="text-right text-zinc-600 dark:text-zinc-400">{job.asset_count ?? 0}</TableCell>
                        <TableCell className="text-right text-zinc-600 dark:text-zinc-400 whitespace-nowrap">
                          {credits(job.credits)}
                          {job.refunded && <span className="ml-1 text-xs text-green-600 dark:text-green-400">refunded</span>}
                        </TableCell>
                        <TableCell className="text-right text-zinc-600 dark:text-zinc-400">{job.attempts}</TableCell>
                        <TableCell className="max-w-[260px] text-zinc-600 dark:text-zinc-400">
                          {job.error ? <Truncate text={job.error} className="text-red-600 dark:text-red-400" /> : "—"}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              <ScrollBar orientation="horizontal" />
            </ScrollArea>
          )}

          {skippedAtStart.length > 0 && (
            <div className="space-y-1.5">
              <p className="text-sm font-medium text-zinc-900 dark:text-white">Skipped when the run started</p>
              <ul className="list-disc pl-5 space-y-1 text-sm text-zinc-600 dark:text-zinc-400">
                {skippedAtStart.map((item, index) => (
                  <li key={`${item.source_id ?? item.name}-${index}`} className="break-words">
                    {skipText(item)}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {run && jobs.length > 0 && (
            <div className="border-t border-zinc-200 dark:border-zinc-800 pt-4 space-y-2">
              <p className="text-sm font-medium text-zinc-900 dark:text-white">Changes</p>
              <RunChanges teamId={teamId} runId={runId} finished={TERMINAL_RUN.has(run.status)} />
            </div>
          )}
          {run && jobs.length > 0 && (
            <div className="border-t border-zinc-200 dark:border-zinc-800 pt-4">
              <RunResults teamId={teamId} runId={runId} active={isActiveRun(run.status)} />
            </div>
          )}
          {run && isActiveRun(run.status) && (
            <p className="text-xs text-zinc-500">Updates every few seconds while the run is active.</p>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" className="cursor-pointer" onClick={onClose}>
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

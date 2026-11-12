"use client";

// Fleet inventory: where targets come from (an AWS account read through its validated role, a CSV/JSON import, the
// API) and every target with the policy decision on it: which policy won, how many others matched, and why.
// The targets table sizes its columns from its own width (a container query), not the window's: beside the sidebar
// a 768 px tablet leaves it less room than a 390 px phone, and the decision column must stay on screen.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Cloud, FileUp, Pause, Play, RefreshCcw, Trash2 } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { toast } from "@/utils/toast";

import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import {
  createCbomInventorySource,
  deleteCbomInventorySource,
  getCbomInventoryTarget,
  importCbomInventory,
  listCbomInventorySources,
  listCbomInventoryTargets,
  syncCbomInventorySource,
  updateCbomInventorySource,
  type CbomDecisionAction,
  type CbomImportResult,
  type CbomInventorySource,
  type CbomInventoryTarget,
  type CbomTargetFilters,
} from "@/utils/api/cbom_fleet";

import { formatDateTime, refusalReason } from "../logic";
import { ConfirmDialog, EmptyState, ErrorBlock, Field, LoadingBlock, SectionCard, StatusBadge, Truncate, type Tone } from "../shared";
import { DECISION_LABEL, coverageGaps, decisionText, targetLabel } from "./fleetLogic";
import { cbomFleetKeys, refreshFleet } from "./keys";
import type { FleetSectionProps } from "./sections";
import { useOpener } from "./useOpener";

const KINDS = ["linux_host", "windows_host", "database", "k8s_cluster", "load_balancer", "certificate", "kms_key", "secret", "other"];
const KIND_LABEL: Record<string, string> = {
  linux_host: "Linux host", windows_host: "Windows host", database: "Database", k8s_cluster: "Kubernetes", load_balancer: "Load balancer",
  certificate: "Certificate", kms_key: "KMS key", secret: "Secret", other: "Other",
};
const SERVICES = ["ec2", "rds", "eks", "elb", "acm", "kms", "secretsmanager"];
const DECISION_TONE: Record<CbomDecisionAction, Tone> = { collect: "green", never_scan: "red", unmanaged: "zinc" };
const SEARCH_DEBOUNCE_MS = 300;
const SYNC_TONE: Record<string, Tone> = { ok: "green", partial: "amber", failed: "red", running: "blue", queued: "blue", never: "zinc" };

function errorText(err: unknown, fallback: string): string {
  return refusalReason(err) ?? fallback;
}

function gaps(source: CbomInventorySource): string[] {
  return coverageGaps(source.coverage);
}

// ---------------------------------------------------------------------------- import
function ImportDialog({ teamId, open, onOpenChange, onCloseAutoFocus }: {
  teamId: number; open: boolean; onOpenChange: (v: boolean) => void; onCloseAutoFocus: (e: Event) => void;
}) {
  const queryClient = useQueryClient();
  const [format, setFormat] = useState<"csv" | "json">("csv");
  const [content, setContent] = useState("");
  const [result, setResult] = useState<CbomImportResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const run = useMutation({
    mutationFn: (dryRun: boolean) => importCbomInventory(teamId, { format, content, dry_run: dryRun }),
    onSuccess: (data) => {
      setResult(data);
      setError(null);
      if (!data.dry_run) {
        toast.success(`Imported: ${data.created} new, ${data.updated} updated, ${data.unchanged} unchanged`);
        refreshFleet(queryClient, teamId, ["targets", "sources", "policies"]); // the policies' counts change too
      }
    },
    onError: (err) => setError(errorText(err, "Could not import the file")),
  });
  const readFile = async (file: File | undefined) => {
    if (!file) return;
    setFormat(file.name.toLowerCase().endsWith(".json") ? "json" : "csv");
    setContent(await file.text());
    setResult(null);
  };
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-2xl max-h-[90vh] overflow-y-auto" onCloseAutoFocus={onCloseAutoFocus}>
        <DialogHeader>
          <DialogTitle>Import targets</DialogTitle>
          <DialogDescription>
            CSV with a header row (external_id, kind, address, hostname, tag:&lt;key&gt; columns...) or JSON. Up to 10,000 rows. Importing the
            same file again changes nothing; targets the file no longer lists are marked missing.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <Field label="Format" htmlFor="fleet-import-format">
            <Select value={format} onValueChange={(v) => setFormat(v as "csv" | "json")}>
              <SelectTrigger id="fleet-import-format" className="w-40 cursor-pointer">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="csv" className="cursor-pointer">CSV</SelectItem>
                <SelectItem value="json" className="cursor-pointer">JSON</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          <Field label="File" htmlFor="fleet-import-file" hint="Or paste the content below">
            <Input id="fleet-import-file" type="file" accept=".csv,.json,text/csv,application/json" onChange={(e) => readFile(e.target.files?.[0])} />
          </Field>
          <Field label="Content" htmlFor="fleet-import-content">
            <Textarea
              id="fleet-import-content"
              rows={8}
              className="font-mono text-xs"
              value={content}
              placeholder={"external_id,kind,address,tag:env\nweb-01,linux_host,10.0.1.5,prod"}
              onChange={(e) => {
                setContent(e.target.value);
                setResult(null);
              }}
            />
          </Field>
          {error && <p className="text-sm text-red-600 dark:text-red-400" role="alert">{error}</p>}
          {result && (
            <div className="rounded-md border border-zinc-200 dark:border-zinc-800 p-3 text-sm space-y-1" role="status">
              <p className="font-medium">
                {result.dry_run ? "Preview (nothing saved): " : "Saved: "}
                {result.created} new · {result.updated} updated · {result.unchanged} unchanged · {result.missing} missing
                {result.skipped ? ` · ${result.skipped} skipped` : ""}
              </p>
              {result.skipped > 0 && (
                <p className="text-amber-700 dark:text-amber-400">Skipped: another inventory source already lists them, so they stay with it.</p>
              )}
              {result.missing_skipped && <p className="text-amber-700 dark:text-amber-400">Rows failed, so nothing was marked missing.</p>}
              {result.error_count > 0 && (
                <ul className="text-red-600 dark:text-red-400 list-disc pl-5 max-h-40 overflow-y-auto">
                  {result.errors.map((e) => (
                    <li key={`${e.row ?? e.external_id}-${e.error}`}>{e.row != null ? `Row ${e.row}` : e.external_id}: {e.error}</li>
                  ))}
                  {result.error_count > result.errors.length && <li>... and {result.error_count - result.errors.length} more</li>}
                </ul>
              )}
            </div>
          )}
        </div>
        <DialogFooter className="gap-2">
          <Button variant="outline" className="cursor-pointer" disabled={!content.trim() || run.isPending} onClick={() => run.mutate(true)}>
            Preview
          </Button>
          <Button className="cursor-pointer bg-blue-600 hover:bg-blue-700 text-white" disabled={!content.trim() || run.isPending} onClick={() => run.mutate(false)}>
            Import
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------- AWS source
function AwsSourceDialog({ teamId, open, onOpenChange, accounts, onCloseAutoFocus }: {
  teamId: number; open: boolean; onOpenChange: (v: boolean) => void; accounts: { id: number; name: string; validated: boolean }[];
  onCloseAutoFocus: (e: Event) => void;
}) {
  const queryClient = useQueryClient();
  const [name, setName] = useState("aws-inventory");
  const [account, setAccount] = useState<number | null>(null);
  const [regions, setRegions] = useState("ap-south-1");
  const [services, setServices] = useState<string[]>(SERVICES);
  const [every, setEvery] = useState(60);
  const [error, setError] = useState<string | null>(null);
  const save = useMutation({
    mutationFn: () => createCbomInventorySource(teamId, {
      kind: "aws", name, sync_every_min: every,
      config: { aws_account_source_id: account, regions: regions.split(/[\s,]+/).filter(Boolean), services },
    }),
    onSuccess: () => {
      toast.success("AWS inventory added; the first sync starts now");
      refreshFleet(queryClient, teamId, ["sources"]);
      onOpenChange(false);
    },
    onError: (err) => setError(errorText(err, "Could not add the AWS inventory")),
  });
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-xl" onCloseAutoFocus={onCloseAutoFocus}>
        <DialogHeader>
          <DialogTitle>Discover from an AWS account</DialogTitle>
          <DialogDescription>
            Lists EC2, RDS, EKS, load balancers, ACM certificates, KMS keys and Secrets Manager secrets (names and tags only) through the
            account&apos;s validated read-only role.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <Field label="Name" htmlFor="fleet-aws-name" required>
            <Input id="fleet-aws-name" value={name} onChange={(e) => setName(e.target.value)} />
          </Field>
          <Field label="AWS account" htmlFor="fleet-aws-account" required hint="Add and validate it on Cloud & Identity first">
            <Select value={account ? String(account) : ""} onValueChange={(v) => setAccount(Number(v))}>
              <SelectTrigger id="fleet-aws-account" className="w-full cursor-pointer">
                <SelectValue placeholder={accounts.length ? "Choose an AWS account" : "No AWS account yet"} />
              </SelectTrigger>
              <SelectContent>
                {accounts.map((a) => (
                  <SelectItem key={a.id} value={String(a.id)} className="cursor-pointer">
                    {a.name}{a.validated ? "" : " (not validated)"}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          <Field label="Regions" htmlFor="fleet-aws-regions" hint="Comma-separated, e.g. ap-south-1, us-east-1">
            <Input id="fleet-aws-regions" value={regions} onChange={(e) => setRegions(e.target.value)} />
          </Field>
          <fieldset className="space-y-2">
            <legend className="text-sm font-medium">Services</legend>
            <div className="flex flex-wrap gap-3">
              {SERVICES.map((s) => (
                <label key={s} className="flex items-center gap-1.5 text-sm cursor-pointer">
                  <input
                    type="checkbox"
                    checked={services.includes(s)}
                    onChange={(e) => setServices((cur) => (e.target.checked ? [...cur, s] : cur.filter((x) => x !== s)))}
                  />
                  {s}
                </label>
              ))}
            </div>
          </fieldset>
          <Field label="Sync every (minutes)" htmlFor="fleet-aws-every" hint="15 at least">
            <Input id="fleet-aws-every" type="number" min={15} value={every} onChange={(e) => setEvery(Number(e.target.value))} className="w-32" />
          </Field>
          {error && <p className="text-sm text-red-600 dark:text-red-400" role="alert">{error}</p>}
        </div>
        <DialogFooter>
          <Button className="cursor-pointer bg-blue-600 hover:bg-blue-700 text-white" disabled={!account || save.isPending} onClick={() => save.mutate()}>
            Add and sync
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function SourcesTable({ teamId }: { teamId: number }) {
  const queryClient = useQueryClient();
  const [removing, setRemoving] = useState<CbomInventorySource | null>(null);
  const [awsOpen, setAwsOpen] = useState(false);
  const opener = useOpener();
  const sources = useQuery({
    queryKey: cbomFleetKeys.inventorySources(teamId),
    queryFn: () => listCbomInventorySources(teamId),
    refetchInterval: (q) => (q.state.data?.sources.some((s) => s.syncing) ? 5000 : 30_000),
  });
  // a sync that finishes brings targets: refresh them (and the policies' counts) when a source's last sync moves
  const lastSyncs = (sources.data?.sources ?? []).map((s) => `${s.id}:${s.last_sync_at ?? ""}`).join(",");
  const seenSyncs = useRef(lastSyncs);
  useEffect(() => {
    if (lastSyncs === seenSyncs.current) return;
    const first = seenSyncs.current === ""; // the sources' first load: nothing finished yet
    seenSyncs.current = lastSyncs;
    if (!first) refreshFleet(queryClient, teamId, ["targets", "policies"]);
  }, [lastSyncs, queryClient, teamId]);
  const sync = useMutation({
    mutationFn: (id: number) => syncCbomInventorySource(teamId, id),
    onSuccess: () => { toast.success("Sync queued"); refreshFleet(queryClient, teamId, ["sources"]); },
    onError: (err) => toast.error(errorText(err, "Could not start the sync")),
  });
  const toggle = useMutation({
    mutationFn: (s: CbomInventorySource) => updateCbomInventorySource(teamId, s.id, { enabled: !s.enabled, expected_version: s.row_version }),
    onSuccess: () => refreshFleet(queryClient, teamId, ["sources"]),
    onError: (err) => {
      toast.error(errorText(err, "Could not change the source"));
      refreshFleet(queryClient, teamId, ["sources"]); // a 409: show the latest version
    },
  });
  const remove = useMutation({
    mutationFn: (id: number) => deleteCbomInventorySource(teamId, id),
    onSuccess: (res) => {
      setRemoving(null);
      toast.success(`Source deleted; ${res.targets_removed} target(s) removed from the inventory`);
      refreshFleet(queryClient, teamId, ["sources", "targets", "policies"]);
    },
    onError: (err) => toast.error(errorText(err, "Could not delete the source")),
  });
  if (sources.isLoading) return <LoadingBlock />;
  if (!sources.data) return <ErrorBlock error={sources.error} onRetry={() => sources.refetch()} />;
  const rows = sources.data.sources;
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-sm font-semibold text-zinc-900 dark:text-white">Inventory sources</h3>
        <Button variant="outline" size="sm" className="cursor-pointer" onClick={(e) => { opener.remember(e); setAwsOpen(true); }} data-testid="fleet-add-aws">
          <Cloud className="h-4 w-4 mr-1.5" />
          Discover from AWS
        </Button>
      </div>
      {rows.length === 0 ? (
        <p className="text-sm text-zinc-600 dark:text-zinc-400">No inventory source yet: import a file, discover an AWS account, or PUT targets through the API.</p>
      ) : (
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Kind</TableHead>
                <TableHead className="text-right">Targets</TableHead>
                <TableHead>Last sync</TableHead>
                <TableHead><span className="sr-only">Actions</span></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((s) => {
                const missing = gaps(s);
                return (
                  <TableRow key={s.id} data-testid={`fleet-source-${s.id}`}>
                    <TableCell className="font-medium max-w-[220px]">
                      <Truncate text={s.name} />
                      {!s.enabled && <StatusBadge tone="zinc">Paused</StatusBadge>}
                    </TableCell>
                    <TableCell>{s.kind.toUpperCase()}{s.kind === "aws" ? ` · ${(s.config.regions ?? []).join(", ")}` : ""}</TableCell>
                    <TableCell className="text-right">{(s.target_count ?? 0).toLocaleString()}</TableCell>
                    <TableCell className="max-w-[320px]">
                      <StatusBadge tone={SYNC_TONE[s.last_sync_status] ?? "zinc"}>{s.last_sync_status}</StatusBadge>
                      <span className="text-xs text-zinc-500 ml-2">{s.last_sync_at ? formatDateTime(s.last_sync_at) : ""}</span>
                      {s.last_sync_summary?.error && <p className="text-xs text-red-600 dark:text-red-400 mt-1">{String(s.last_sync_summary.error)}</p>}
                      {missing.length > 0 && <p className="text-xs text-amber-700 dark:text-amber-400 mt-1" title={missing.join("\n")}>Not read: {missing.slice(0, 3).join("; ")}{missing.length > 3 ? " ..." : ""}</p>}
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-right">
                      {s.kind === "aws" && (
                        <Button variant="ghost" size="icon" className="cursor-pointer" aria-label={`Sync ${s.name} now`} disabled={s.syncing || !s.enabled || sync.isPending} onClick={() => sync.mutate(s.id)}>
                          <RefreshCcw className="h-4 w-4" />
                        </Button>
                      )}
                      {s.kind === "aws" && (
                        <Button variant="ghost" size="icon" className="cursor-pointer" aria-label={s.enabled ? `Pause ${s.name}` : `Resume ${s.name}`} onClick={() => toggle.mutate(s)}>
                          {s.enabled ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
                        </Button>
                      )}
                      <Button variant="ghost" size="icon" className="cursor-pointer" aria-label={`Delete ${s.name}`} onClick={() => setRemoving(s)}>
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>
      )}
      {awsOpen && (
        <AwsSourceDialog teamId={teamId} open={awsOpen} onOpenChange={setAwsOpen} accounts={sources.data.aws_accounts} onCloseAutoFocus={opener.onCloseAutoFocus} />
      )}
      <ConfirmDialog
        open={removing !== null}
        onOpenChange={(v) => !v && setRemoving(null)}
        title={`Delete ${removing?.name ?? "this source"}?`}
        description="Its targets are removed from the inventory at once: policies stop collecting them at the next Apply (a job running on them is stopped). Importing or syncing them again brings them back."
        confirmLabel="Delete"
        destructive
        pending={remove.isPending}
        onConfirm={() => removing && remove.mutate(removing.id)}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------- targets
function TargetDetail({ teamId, targetId, onClose, onCloseAutoFocus }: {
  teamId: number; targetId: number; onClose: () => void; onCloseAutoFocus: (e: Event) => void;
}) {
  const detail = useQuery({ queryKey: cbomFleetKeys.target(teamId, targetId), queryFn: () => getCbomInventoryTarget(teamId, targetId) });
  const d = detail.data;
  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-2xl max-h-[90vh] overflow-y-auto" onCloseAutoFocus={onCloseAutoFocus}>
        <DialogHeader>
          <DialogTitle className="break-all">{d ? targetLabel(d.target) : "Target"}</DialogTitle>
          <DialogDescription className="break-all">{d?.target.external_id}</DialogDescription>
        </DialogHeader>
        {detail.isLoading && <LoadingBlock />}
        {detail.isError && <ErrorBlock error={detail.error} onRetry={() => detail.refetch()} />}
        {d && (
          <div className="space-y-4 text-sm">
            <div className="rounded-md border border-zinc-200 dark:border-zinc-800 p-3 space-y-2" data-testid="fleet-target-decision">
              <div className="flex items-center gap-2">
                <StatusBadge tone={DECISION_TONE[d.decision.action]}>{DECISION_LABEL[d.decision.action]}</StatusBadge>
                <span className="text-zinc-700 dark:text-zinc-300">{d.decision.reason}</span>
              </div>
              {d.matched_policies.length > 0 ? (
                <div>
                  <p className="text-xs text-zinc-500 mb-1">Matching policies, in the order they apply (the first one wins):</p>
                  <ol className="list-decimal pl-5 space-y-0.5">
                    {d.matched_policies.map((p) => (
                      <li key={p.id} className={p.won ? "font-semibold" : "text-zinc-500"}>
                        {p.name} · priority {p.priority}{p.won ? " · won" : " · overridden"}
                      </li>
                    ))}
                  </ol>
                  {d.decision.policy_id == null && d.decision.action === "never_scan" && (
                    <p className="text-xs text-zinc-500 mt-1">The team&apos;s never-scan list overrides every policy.</p>
                  )}
                </div>
              ) : (
                <p className="text-xs text-zinc-500">No policy matches this target.</p>
              )}
              {d.managed_source && <p className="text-xs text-zinc-500">Collected by the managed source {d.managed_source.name}.</p>}
              {d.target.pending && (
                <p className="text-xs text-amber-700 dark:text-amber-400">
                  Waiting for a running job: its managed source changes when that job ends (retried every minute).
                </p>
              )}
              {d.target.deleted_at && (
                <p className="text-xs text-zinc-500">Removed from the inventory on {formatDateTime(d.target.deleted_at)}; it is not collected.</p>
              )}
            </div>
            <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1">
              <dt className="text-zinc-500">Kind</dt><dd>{KIND_LABEL[d.target.kind] ?? d.target.kind}</dd>
              <dt className="text-zinc-500">Addresses</dt><dd className="break-all">{d.target.addresses.join(", ") || d.target.address || "—"}</dd>
              <dt className="text-zinc-500">Account / region</dt><dd>{[d.target.account_id, d.target.region].filter(Boolean).join(" / ") || "—"}</dd>
              <dt className="text-zinc-500">Platform</dt><dd>{d.target.platform ?? "—"}</dd>
              <dt className="text-zinc-500">Last seen</dt><dd>{formatDateTime(d.target.last_seen_at)}{d.target.missing_since ? ` (missing since ${formatDateTime(d.target.missing_since)})` : ""}</dd>
            </dl>
            <div>
              <p className="text-zinc-500 mb-1">Tags</p>
              <div className="flex flex-wrap gap-1">
                {Object.entries(d.target.tags).map(([k, v]) => (
                  <span key={k} className="rounded bg-zinc-100 dark:bg-zinc-800 px-1.5 py-0.5 text-xs font-mono break-all">{k}={v}</span>
                ))}
                {Object.keys(d.target.tags).length === 0 && <span className="text-xs text-zinc-500">none</span>}
              </div>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

function TargetsTable({ teamId }: { teamId: number }) {
  const [filters, setFilters] = useState<CbomTargetFilters>({ limit: 50 });
  const [cursors, setCursors] = useState<number[]>([0]);
  const [open, setOpen] = useState<number | null>(null);
  const opener = useOpener();
  const page = { ...filters, cursor: cursors[cursors.length - 1] };
  const targets = useQuery({
    queryKey: cbomFleetKeys.targets(teamId, JSON.stringify(page)),
    queryFn: () => listCbomInventoryTargets(teamId, page),
    placeholderData: (prev) => prev,
    // a large inventory is evaluated by the fleet worker after a write: poll until the decisions are current
    refetchInterval: (q) => (q.state.data?.evaluation?.stale ? 3000 : false),
  });
  const set = (patch: Partial<CbomTargetFilters>) => {
    setFilters((f) => ({ ...f, ...patch }));
    setCursors([0]);
  };
  // Search and tag are typed: one request when the typing pauses, not one per key (the read limiter answers 429). The
  // tag key and value are separate fields: a key may contain colons (aws:cloudformation:stack-name).
  const [text, setText] = useState({ q: "", tagKey: "", tagValue: "" });
  useEffect(() => {
    const q = text.q.trim() || undefined;
    const tag_key = text.tagKey.trim() || undefined;
    const tag_value = tag_key ? text.tagValue.trim() || undefined : undefined;
    if (q === filters.q && tag_key === filters.tag_key && tag_value === filters.tag_value) return;
    const timer = setTimeout(() => {
      setFilters((f) => ({ ...f, q, tag_key, tag_value }));
      setCursors([0]);
    }, SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [text, filters.q, filters.tag_key, filters.tag_value]);
  const data = targets.data;
  return (
    <div className="space-y-3 @container">
      <div className="flex flex-wrap items-end gap-2">
        <Field label="Search" htmlFor="fleet-q" className="w-48">
          <Input id="fleet-q" placeholder="name, address or ID" value={text.q} onChange={(e) => setText((t) => ({ ...t, q: e.target.value }))} />
        </Field>
        <Field label="Tag key" htmlFor="fleet-tag-key" className="w-40">
          <Input id="fleet-tag-key" placeholder="e.g. env" value={text.tagKey} onChange={(e) => setText((t) => ({ ...t, tagKey: e.target.value }))} />
        </Field>
        <Field label="Tag value" htmlFor="fleet-tag-value" className="w-36">
          <Input id="fleet-tag-value" placeholder="any value" disabled={!text.tagKey.trim()} value={text.tagValue}
            onChange={(e) => setText((t) => ({ ...t, tagValue: e.target.value }))} />
        </Field>
        <Field label="Kind" htmlFor="fleet-kind" className="w-40">
          <Select value={filters.kind ?? "all"} onValueChange={(v) => set({ kind: v === "all" ? undefined : v })}>
            <SelectTrigger id="fleet-kind" className="cursor-pointer"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all" className="cursor-pointer">Every kind</SelectItem>
              {KINDS.map((k) => <SelectItem key={k} value={k} className="cursor-pointer">{KIND_LABEL[k]}</SelectItem>)}
            </SelectContent>
          </Select>
        </Field>
        <Field label="Decision" htmlFor="fleet-decision" className="w-40">
          <Select value={filters.decision ?? "all"} onValueChange={(v) => set({ decision: v === "all" ? undefined : (v as CbomDecisionAction) })}>
            <SelectTrigger id="fleet-decision" className="cursor-pointer"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all" className="cursor-pointer">Any decision</SelectItem>
              {(["collect", "never_scan", "unmanaged"] as const).map((k) => <SelectItem key={k} value={k} className="cursor-pointer">{DECISION_LABEL[k]}</SelectItem>)}
            </SelectContent>
          </Select>
        </Field>
        <Field label="Missing" htmlFor="fleet-missing" className="w-36">
          <Select value={filters.missing ?? "no"} onValueChange={(v) => set({ missing: v as "yes" | "no" | "all" })}>
            <SelectTrigger id="fleet-missing" className="cursor-pointer"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="no" className="cursor-pointer">Present</SelectItem>
              <SelectItem value="yes" className="cursor-pointer">Missing</SelectItem>
              <SelectItem value="all" className="cursor-pointer">All</SelectItem>
            </SelectContent>
          </Select>
        </Field>
      </div>
      {targets.isLoading && <LoadingBlock />}
      {!data && targets.isError && <ErrorBlock error={targets.error} onRetry={() => targets.refetch()} />}
      {data?.evaluation?.stale && (
        <p className="text-xs text-zinc-600 dark:text-zinc-400" role="status" data-testid="fleet-targets-updating">
          The decisions are being updated after a change; this list refreshes when they are.
        </p>
      )}
      {data && data.total === 0 && <EmptyState title="No targets" body="Import a file, discover an AWS account, or change the filters." />}
      {data && data.total > 0 && (
        <>
          <p className="text-xs text-zinc-500" data-testid="fleet-target-total">{data.total.toLocaleString()} targets</p>
          <div className="overflow-x-auto">
            {/* below 672 px the columns share the width (fixed layout): a long host name is cut, not the decision */}
            <Table className="@max-2xl:table-fixed">
              <TableHeader>
                <TableRow>
                  <TableHead className="@max-2xl:w-[55%]">Target</TableHead>
                  <TableHead className="hidden @2xl:table-cell">Kind</TableHead>
                  <TableHead className="hidden @5xl:table-cell">Tags</TableHead>
                  <TableHead className="hidden @5xl:table-cell">Where</TableHead>
                  <TableHead>Decision (which policy won)</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.targets.map((t: CbomInventoryTarget) => (
                  <TableRow key={t.id} className="cursor-pointer hover:bg-zinc-50 dark:hover:bg-zinc-800" data-testid={`fleet-target-${t.id}`}
                    onClick={(e) => { opener.remember(e); setOpen(t.id); }}>
                    <TableCell className="max-w-[260px]">
                      <button type="button" className="block w-full text-left cursor-pointer font-medium text-zinc-900 dark:text-white">
                        <Truncate text={targetLabel(t)} />
                      </button>
                      <p className="text-xs text-zinc-500 truncate" title={t.external_id}>{t.address && t.hostname ? `${t.address} · ` : ""}{t.external_id}</p>
                    </TableCell>
                    <TableCell className="hidden @2xl:table-cell whitespace-nowrap">{KIND_LABEL[t.kind] ?? t.kind}</TableCell>
                    <TableCell className="hidden @5xl:table-cell max-w-[240px]">
                      <div className="flex flex-wrap gap-1">
                        {Object.entries(t.tags).slice(0, 4).map(([k, v]) => (
                          <span key={k} className="rounded bg-zinc-100 dark:bg-zinc-800 px-1.5 py-0.5 text-xs font-mono truncate max-w-[200px]" title={`${k}=${v}`}>{k}={v}</span>
                        ))}
                        {Object.keys(t.tags).length > 4 && <span className="text-xs text-zinc-500">+{Object.keys(t.tags).length - 4}</span>}
                      </div>
                    </TableCell>
                    <TableCell className="hidden @5xl:table-cell text-xs text-zinc-600 dark:text-zinc-400 whitespace-nowrap">{[t.region, t.account_id].filter(Boolean).join(" · ") || "—"}</TableCell>
                    <TableCell className="max-w-[300px]">
                      <StatusBadge tone={DECISION_TONE[t.decision.action] ?? "zinc"}>{DECISION_LABEL[t.decision.action] ?? t.decision.action}</StatusBadge>
                      {t.deleted_at && <StatusBadge tone="zinc">Removed</StatusBadge>}
                      {t.pending && (
                        <span title="Its managed source has a job running: the change is applied when it ends">
                          <StatusBadge tone="amber">Waiting for a running job</StatusBadge>
                        </span>
                      )}
                      <p className="text-xs text-zinc-600 dark:text-zinc-400 mt-1 wrap-anywhere @2xl:truncate" title={t.decision.reason}>{decisionText(t.decision, data.policies)}</p>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" className="cursor-pointer" disabled={cursors.length <= 1} onClick={() => setCursors((c) => c.slice(0, -1))}>Previous</Button>
            <Button variant="outline" size="sm" className="cursor-pointer" disabled={data.next_cursor == null} onClick={() => data.next_cursor != null && setCursors((c) => [...c, data.next_cursor as number])}>Next</Button>
          </div>
        </>
      )}
      {open !== null && <TargetDetail teamId={teamId} targetId={open} onClose={() => setOpen(null)} onCloseAutoFocus={opener.onCloseAutoFocus} />}
    </div>
  );
}

export default function InventorySection({ teamId }: FleetSectionProps) {
  const [importOpen, setImportOpen] = useState(false);
  const opener = useOpener();
  return (
    <SectionCard
      id="fleet-inventory"
      title="Inventory"
      description="Every host, database, cluster, certificate, key and secret your inventory sources list, with the policy that decides how each is collected."
      actions={
        <Button className="cursor-pointer bg-blue-600 hover:bg-blue-700 text-white" size="sm" onClick={(e) => { opener.remember(e); setImportOpen(true); }} data-testid="fleet-import">
          <FileUp className="h-4 w-4 mr-1.5" />
          Import CSV / JSON
        </Button>
      }
    >
      <div className="space-y-8">
        <SourcesTable teamId={teamId} />
        <TargetsTable teamId={teamId} />
      </div>
      {importOpen && <ImportDialog teamId={teamId} open={importOpen} onOpenChange={setImportOpen} onCloseAutoFocus={opener.onCloseAutoFocus} />}
    </SectionCard>
  );
}

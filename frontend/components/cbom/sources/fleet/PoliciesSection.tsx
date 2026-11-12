"use client";

// Fleet policies: a selector over tags and fields, and what to do with what it matches (collect how and when, or never
// scan). Shown in the order they apply: highest priority first, then the older policy; the first match wins, and the
// team's never-scan list overrides every policy.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Pencil, Plus, Trash2, Wand2, X } from "lucide-react";
import { useState } from "react";
import { toast } from "@/utils/toast";

import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { listCbomScanNodes } from "@/utils/backend_api";
import {
  createCbomPolicy,
  deleteCbomPolicy,
  listCbomCredentials,
  listCbomPolicies,
  previewCbomPolicy,
  reconcileCbomFleet,
  updateCbomPolicy,
  type CbomFleetPolicy,
  type CbomPolicyAction,
  type CbomPolicyPreview,
  type CbomPolicySchedule,
  type CbomPolicyWrite,
} from "@/utils/api/cbom_fleet";

import { cbomSourcesKeys } from "../keys";
import { refusalReason } from "../logic";
import { ConfirmDialog, EmptyState, ErrorBlock, Field, LoadingBlock, NodeSelect, SectionCard, StatusBadge } from "../shared";
import { OP_LABEL, actionText, draftFromSelector, selectorFromDraft, selectorText, type Condition, type SelectorDraft } from "./fleetLogic";
import { cbomFleetKeys } from "./keys";
import type { FleetSectionProps } from "./sections";

const FIELDS = ["kind", "account_id", "region", "platform"];
const WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];

function errorText(err: unknown, fallback: string): string {
  return refusalReason(err) ?? fallback;
}

interface Draft {
  name: string;
  priority: number;
  selector: SelectorDraft | null; // null: edited as JSON
  selectorJson: string;
  neverScan: boolean;
  credentialId: number | null;
  nodeId: number | null;
  tier: 1 | 2;
  batchSize: number;
  schedule: "none" | CbomPolicySchedule["frequency"];
  timeOfDay: string;
  weekday: number;
  monthday: number;
}

function draftOf(p?: CbomFleetPolicy | null): Draft {
  const a: CbomPolicyAction = p?.action ?? {};
  return {
    name: p?.name ?? "",
    priority: p?.priority ?? 100,
    selector: draftFromSelector(p?.selector ?? {}),
    selectorJson: JSON.stringify(p?.selector ?? {}, null, 2),
    neverScan: !!a.never_scan,
    credentialId: a.credential_id ?? null,
    nodeId: a.node_id ?? null,
    tier: a.tier === 2 ? 2 : 1,
    batchSize: a.batch_size ?? 100,
    schedule: a.schedule?.frequency ?? "none",
    timeOfDay: a.schedule?.time_of_day ?? "02:00",
    weekday: a.schedule?.weekday ?? 6,
    monthday: a.schedule?.monthday ?? 1,
  };
}

function bodyOf(d: Draft): CbomPolicyWrite {
  let selector: Record<string, unknown>;
  if (d.selector) selector = selectorFromDraft(d.selector);
  else {
    try {
      selector = JSON.parse(d.selectorJson || "{}");
    } catch {
      throw new Error("The selector is not valid JSON");
    }
  }
  const action: CbomPolicyAction = d.neverScan
    ? { never_scan: true }
    : {
        transport: "ssh",
        credential_id: d.credentialId,
        node_id: d.nodeId,
        tier: d.tier,
        batch_size: d.batchSize,
        schedule: d.schedule === "none" ? null : {
          frequency: d.schedule, time_of_day: d.timeOfDay,
          weekday: d.schedule === "weekly" ? d.weekday : null, monthday: d.schedule === "monthly" ? d.monthday : null,
        },
      };
  return { name: d.name.trim(), priority: d.priority, selector, action };
}

function ConditionRow({ c, onChange, onRemove, index }: { c: Condition; onChange: (c: Condition) => void; onRemove: () => void; index: number }) {
  return (
    <div className="flex flex-wrap items-center gap-2" data-testid={`policy-condition-${index}`}>
      <Select value={c.on} onValueChange={(v) => onChange({ ...c, on: v as "tag" | "field", key: v === "field" ? "kind" : "" })}>
        <SelectTrigger className="w-24 cursor-pointer" aria-label="Condition on"><SelectValue /></SelectTrigger>
        <SelectContent>
          <SelectItem value="tag" className="cursor-pointer">Tag</SelectItem>
          <SelectItem value="field" className="cursor-pointer">Field</SelectItem>
        </SelectContent>
      </Select>
      {c.on === "tag" ? (
        <Input className="w-36" aria-label="Tag key" placeholder="env" value={c.key} onChange={(e) => onChange({ ...c, key: e.target.value })} />
      ) : (
        <Select value={c.key} onValueChange={(v) => onChange({ ...c, key: v })}>
          <SelectTrigger className="w-36 cursor-pointer" aria-label="Field"><SelectValue /></SelectTrigger>
          <SelectContent>
            {FIELDS.map((f) => <SelectItem key={f} value={f} className="cursor-pointer">{f}</SelectItem>)}
          </SelectContent>
        </Select>
      )}
      <Select value={c.op} onValueChange={(v) => onChange({ ...c, op: v as Condition["op"] })}>
        <SelectTrigger className="w-32 cursor-pointer" aria-label="Operator"><SelectValue /></SelectTrigger>
        <SelectContent>
          {(Object.keys(OP_LABEL) as Condition["op"][]).map((op) => <SelectItem key={op} value={op} className="cursor-pointer">{OP_LABEL[op]}</SelectItem>)}
        </SelectContent>
      </Select>
      {c.op !== "exists" && (
        <Input className="w-40" aria-label="Value" placeholder={c.op === "in" ? "prod, stage" : "prod"} value={c.value} onChange={(e) => onChange({ ...c, value: e.target.value })} />
      )}
      <Button variant="ghost" size="icon" className="cursor-pointer" aria-label="Remove condition" onClick={onRemove}>
        <X className="h-4 w-4" />
      </Button>
    </div>
  );
}

function PolicyForm({ teamId, editing, onDone }: { teamId: number; editing: CbomFleetPolicy | null; onDone: () => void }) {
  const queryClient = useQueryClient();
  const [d, setD] = useState<Draft>(() => draftOf(editing));
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<CbomPolicyPreview | null>(null);
  const set = <K extends keyof Draft>(k: K, v: Draft[K]) => { setD((cur) => ({ ...cur, [k]: v })); setPreview(null); };
  const creds = useQuery({ queryKey: cbomFleetKeys.credentials(teamId), queryFn: () => listCbomCredentials(teamId) });
  const nodes = useQuery({ queryKey: cbomSourcesKeys.nodes(teamId), queryFn: () => listCbomScanNodes(teamId) });
  const agentless = (nodes.data?.nodes ?? []).filter((n) => (n.mode ?? "agentless") !== "agent");
  const body = () => {
    try { return bodyOf(d); } catch (e) { setError((e as Error).message); return null; }
  };
  const save = useMutation({
    mutationFn: (b: CbomPolicyWrite) => (editing
      ? updateCbomPolicy(teamId, editing.id, { ...b, expected_version: editing.row_version })
      : createCbomPolicy(teamId, b)),
    onSuccess: () => {
      toast.success(editing ? "Policy saved" : "Policy added");
      queryClient.invalidateQueries({ queryKey: cbomFleetKeys.all(teamId) });
      onDone();
    },
    onError: (err) => setError(errorText(err, "Could not save the policy")),
  });
  const previewRun = useMutation({
    mutationFn: (b: CbomPolicyWrite) => previewCbomPolicy(teamId, { policy: b }),
    onSuccess: (data) => { setPreview(data); setError(null); },
    onError: (err) => setError(errorText(err, "Could not preview the policy")),
  });
  const conditions = d.selector?.conditions ?? [];
  const setConditions = (next: Condition[]) => set("selector", { mode: d.selector?.mode ?? "all", conditions: next });
  return (
    <Dialog open onOpenChange={(v) => !v && onDone()}>
      <DialogContent className="sm:max-w-3xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{editing ? `Edit ${editing.name}` : "Add a policy"}</DialogTitle>
          <DialogDescription>Higher priority wins; on a tie the older policy wins. The never-scan list always wins.</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="grid sm:grid-cols-[1fr_140px] gap-3">
            <Field label="Name" htmlFor="policy-name" required>
              <Input id="policy-name" value={d.name} onChange={(e) => set("name", e.target.value)} placeholder="prod-weekly" />
            </Field>
            <Field label="Priority" htmlFor="policy-priority" hint="0 to 1,000,000">
              <Input id="policy-priority" type="number" min={0} value={d.priority} onChange={(e) => set("priority", Number(e.target.value))} />
            </Field>
          </div>
          <fieldset className="space-y-2">
            <legend className="text-sm font-medium">Targets it matches</legend>
            {d.selector ? (
              <>
                {conditions.length > 1 && (
                  <Select value={d.selector.mode} onValueChange={(v) => set("selector", { mode: v as "all" | "any", conditions })}>
                    <SelectTrigger className="w-56 cursor-pointer" aria-label="Combine conditions"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all" className="cursor-pointer">All conditions must hold</SelectItem>
                      <SelectItem value="any" className="cursor-pointer">Any condition is enough</SelectItem>
                    </SelectContent>
                  </Select>
                )}
                {conditions.length === 0 && <p className="text-sm text-zinc-500">No condition: the policy matches every target.</p>}
                {conditions.map((c, i) => (
                  <ConditionRow key={i} index={i} c={c} onChange={(next) => setConditions(conditions.map((x, j) => (j === i ? next : x)))}
                    onRemove={() => setConditions(conditions.filter((_, j) => j !== i))} />
                ))}
                <Button variant="outline" size="sm" className="cursor-pointer" disabled={conditions.length >= 20}
                  onClick={() => setConditions([...conditions, { on: "tag", key: "", op: "eq", value: "" }])}>
                  <Plus className="h-4 w-4 mr-1" /> Add condition
                </Button>
              </>
            ) : (
              <Field label="Selector (JSON)" htmlFor="policy-selector-json" hint="This selector uses 'not' or nesting, so it is edited as JSON">
                <Textarea id="policy-selector-json" rows={6} className="font-mono text-xs" value={d.selectorJson} onChange={(e) => set("selectorJson", e.target.value)} />
              </Field>
            )}
          </fieldset>
          <fieldset className="space-y-3">
            <legend className="text-sm font-medium">What happens to them</legend>
            <label className="flex items-center gap-2 text-sm cursor-pointer">
              <input type="checkbox" checked={d.neverScan} onChange={(e) => set("neverScan", e.target.checked)} data-testid="policy-never-scan" />
              Never scan them
            </label>
            {!d.neverScan && (
              <div className="grid sm:grid-cols-2 gap-3">
                <Field label="Credential (SSH)" htmlFor="policy-credential" required hint="Add one in Credentials below">
                  <Select value={d.credentialId ? String(d.credentialId) : ""} onValueChange={(v) => set("credentialId", Number(v))}>
                    <SelectTrigger id="policy-credential" className="cursor-pointer"><SelectValue placeholder="Choose a credential" /></SelectTrigger>
                    <SelectContent>
                      {(creds.data?.credentials ?? []).map((c) => (
                        <SelectItem key={c.id} value={String(c.id)} className="cursor-pointer">{c.name} · {c.credential_type}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </Field>
                <Field label="Scan node" htmlFor="policy-node" required>
                  <NodeSelect id="policy-node" nodes={agentless} value={d.nodeId} onChange={(v) => set("nodeId", v)} />
                </Field>
                <Field label="Tier" htmlFor="policy-tier">
                  <Select value={String(d.tier)} onValueChange={(v) => set("tier", Number(v) as 1 | 2)}>
                    <SelectTrigger id="policy-tier" className="cursor-pointer"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="1" className="cursor-pointer">Tier 1 (no sudo)</SelectItem>
                      <SelectItem value="2" className="cursor-pointer">Tier 2 (read-only sudo lines)</SelectItem>
                    </SelectContent>
                  </Select>
                </Field>
                <Field label="Batch size" htmlFor="policy-batch" hint="Targets per managed source, 25 to 1,000">
                  <Input id="policy-batch" type="number" min={25} max={1000} value={d.batchSize} onChange={(e) => set("batchSize", Number(e.target.value))} />
                </Field>
                <Field label="Schedule" htmlFor="policy-schedule">
                  <Select value={d.schedule} onValueChange={(v) => set("schedule", v as Draft["schedule"])}>
                    <SelectTrigger id="policy-schedule" className="cursor-pointer"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="none" className="cursor-pointer">On demand</SelectItem>
                      <SelectItem value="daily" className="cursor-pointer">Daily</SelectItem>
                      <SelectItem value="weekly" className="cursor-pointer">Weekly</SelectItem>
                      <SelectItem value="monthly" className="cursor-pointer">Monthly</SelectItem>
                    </SelectContent>
                  </Select>
                </Field>
                {d.schedule !== "none" && (
                  <div className="flex gap-2">
                    <Field label="Time" htmlFor="policy-time">
                      <Input id="policy-time" type="time" value={d.timeOfDay} onChange={(e) => set("timeOfDay", e.target.value)} />
                    </Field>
                    {d.schedule === "weekly" && (
                      <Field label="Day" htmlFor="policy-weekday">
                        <Select value={String(d.weekday)} onValueChange={(v) => set("weekday", Number(v))}>
                          <SelectTrigger id="policy-weekday" className="w-36 cursor-pointer"><SelectValue /></SelectTrigger>
                          <SelectContent>
                            {WEEKDAYS.map((w, i) => <SelectItem key={w} value={String(i)} className="cursor-pointer">{w}</SelectItem>)}
                          </SelectContent>
                        </Select>
                      </Field>
                    )}
                    {d.schedule === "monthly" && (
                      <Field label="Day of month" htmlFor="policy-monthday">
                        <Input id="policy-monthday" type="number" min={1} max={28} value={d.monthday} onChange={(e) => set("monthday", Number(e.target.value))} />
                      </Field>
                    )}
                  </div>
                )}
              </div>
            )}
          </fieldset>
          {error && <p className="text-sm text-red-600 dark:text-red-400" role="alert">{error}</p>}
          {preview && (
            <div className="rounded-md border border-zinc-200 dark:border-zinc-800 p-3 text-sm space-y-1" role="status" data-testid="policy-preview">
              <p className="font-medium">Matches {preview.matched} · would collect {preview.would_collect} · never scan {preview.never_scan}</p>
              {preview.conflicts.map((c, i) => (
                <p key={i} className="text-amber-700 dark:text-amber-400">
                  Overlaps on {c.targets} target(s): {c.winner ?? "this policy"} wins over {c.loser ?? "this policy"}
                </p>
              ))}
            </div>
          )}
        </div>
        <DialogFooter className="gap-2">
          <Button variant="outline" className="cursor-pointer" disabled={previewRun.isPending || !d.name.trim()} onClick={() => { const b = body(); if (b) previewRun.mutate(b); }}>
            Preview
          </Button>
          <Button className="cursor-pointer bg-blue-600 hover:bg-blue-700 text-white" disabled={save.isPending || !d.name.trim()} onClick={() => { const b = body(); if (b) save.mutate(b); }}>
            {editing ? "Save" : "Add policy"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function PoliciesSection({ teamId }: FleetSectionProps) {
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState<CbomFleetPolicy | null | "new">(null);
  const [removing, setRemoving] = useState<CbomFleetPolicy | null>(null);
  const policies = useQuery({ queryKey: cbomFleetKeys.policies(teamId), queryFn: () => listCbomPolicies(teamId) });
  const refresh = () => queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) });
  const toggle = useMutation({
    mutationFn: (p: CbomFleetPolicy) => updateCbomPolicy(teamId, p.id, { enabled: !p.enabled, expected_version: p.row_version }),
    onSuccess: refresh,
    onError: (err) => toast.error(errorText(err, "Could not change the policy")),
  });
  const remove = useMutation({
    mutationFn: (id: number) => deleteCbomPolicy(teamId, id),
    onSuccess: () => { setRemoving(null); refresh(); },
    onError: (err) => toast.error(errorText(err, "Could not delete the policy")),
  });
  const apply = useMutation({
    mutationFn: () => reconcileCbomFleet(teamId),
    onSuccess: (r) => {
      refresh();
      if (!r.materialize) toast.success(`Decisions refreshed (${r.decisions_changed} changed); managed sources are turned off in this deployment`);
      else toast.success(`Applied: ${r.sources_created} sources added, ${r.sources_updated} updated, ${r.sources_removed} removed, ${r.deferred} waiting for a running job`);
      r.problems.slice(0, 3).forEach((p) => toast.error(p));
    },
    onError: (err) => toast.error(errorText(err, "Could not apply the policies")),
  });
  const data = policies.data;
  return (
    <SectionCard
      id="fleet-policies"
      title="Policies"
      description={data?.order ? `Applied in this order: ${data.order}. The never-scan list overrides every policy.` : "Tag policies decide how each target is collected."}
      actions={
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" size="sm" className="cursor-pointer" disabled={apply.isPending} onClick={() => apply.mutate()} data-testid="fleet-reconcile"
            title={data?.materialize ? "Create and update the managed sources and schedules now" : "Managed sources are turned off; this refreshes the decisions"}>
            <Wand2 className="h-4 w-4 mr-1.5" /> Apply policies
          </Button>
          <Button size="sm" className="cursor-pointer bg-blue-600 hover:bg-blue-700 text-white" onClick={() => setEditing("new")} data-testid="fleet-add-policy">
            <Plus className="h-4 w-4 mr-1.5" /> Add policy
          </Button>
        </div>
      }
    >
      {policies.isLoading && <LoadingBlock />}
      {!data && policies.isError && <ErrorBlock error={policies.error} onRetry={() => policies.refetch()} />}
      {data && data.policies.length === 0 && <EmptyState title="No policy yet" body="Add one, e.g. env is prod: collect weekly over SSH; env is pci: never scan." />}
      {data && data.policies.length > 0 && (
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-10">#</TableHead>
                <TableHead>Policy</TableHead>
                <TableHead>Matches</TableHead>
                <TableHead>Does</TableHead>
                <TableHead className="text-right">Targets (won / matched)</TableHead>
                <TableHead><span className="sr-only">Actions</span></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.policies.map((p) => (
                <TableRow key={p.id} data-testid={`fleet-policy-${p.id}`}>
                  <TableCell>{p.precedence ?? "—"}</TableCell>
                  <TableCell className="font-medium">
                    {p.name}
                    <span className="block text-xs text-zinc-500">priority {p.priority}</span>
                    {!p.enabled && <StatusBadge tone="zinc">Disabled</StatusBadge>}
                  </TableCell>
                  <TableCell className="max-w-[260px] text-sm break-words">{selectorText(p.selector)}</TableCell>
                  <TableCell className="max-w-[260px] text-sm">{actionText(p.action)}</TableCell>
                  <TableCell className="text-right whitespace-nowrap">{p.won_targets ?? 0} / {p.matched_targets ?? 0}</TableCell>
                  <TableCell className="whitespace-nowrap text-right">
                    <Button variant="ghost" size="sm" className="cursor-pointer" onClick={() => toggle.mutate(p)}>{p.enabled ? "Disable" : "Enable"}</Button>
                    <Button variant="ghost" size="icon" className="cursor-pointer" aria-label={`Edit ${p.name}`} onClick={() => setEditing(p)}>
                      <Pencil className="h-4 w-4" />
                    </Button>
                    <Button variant="ghost" size="icon" className="cursor-pointer" aria-label={`Delete ${p.name}`} onClick={() => setRemoving(p)}>
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      {editing !== null && <PolicyForm teamId={teamId} editing={editing === "new" ? null : editing} onDone={() => setEditing(null)} />}
      <ConfirmDialog
        open={removing !== null}
        onOpenChange={(v) => !v && setRemoving(null)}
        title={`Delete ${removing?.name ?? "this policy"}?`}
        description="Its targets fall to the next matching policy. Its managed sources and schedule go at the next Apply (a source with a running job waits for it)."
        confirmLabel="Delete"
        destructive
        pending={remove.isPending}
        onConfirm={() => removing && remove.mutate(removing.id)}
      />
    </SectionCard>
  );
}

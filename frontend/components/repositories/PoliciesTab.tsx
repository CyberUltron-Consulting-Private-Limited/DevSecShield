"use client";

// Scan policies per repository group: a selector (the same rules as the import filters), products, branch, schedule
// and scan-on-push. Policies are tried in order; the first whose selector matches a repository covers it (a repository
// pinned to a policy stays with it). The editor previews which repositories the policy would take and one run's price.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2, Pencil, Play, Plus, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";

import { refusalReason } from "@/components/cbom/sources/logic";
import { Checkbox2, ConfirmDialog, EmptyState, ErrorBlock, Field, LoadingBlock, SectionCard, StatusBadge } from "@/components/cbom/sources/shared";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  createScmPolicy,
  deleteScmPolicy,
  listScmPolicies,
  previewScmPolicy,
  updateScmPolicy,
  type ScmFilters,
  type ScmPolicy,
  type ScmPolicyBody,
  type ScmProduct,
  type ScmSchedule,
} from "@/utils/api/scm";
import { toast } from "@/utils/toast";

import FiltersForm from "./FiltersForm";
import { scmKeys } from "./keys";
import { filtersError, filtersFrom, formatCredits, nameError, PRODUCT_LABEL, PRODUCTS, repoCount, scheduleText } from "./logic";
import RunDialog from "./RunDialog";

const WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
// the server sends its list (GET /policies iac_modes); this is only the fallback while it loads
const IAC_MODES = ["terraform", "k8s", "helm", "aws_cloudformation", "ansible", "pulumi", "aws_cdk"];

function bodyFrom(p: ScmPolicy | null, nextPosition: number): ScmPolicyBody {
  return {
    name: p?.name ?? "",
    position: p?.position ?? nextPosition,
    enabled: p?.enabled ?? true,
    selector: filtersFrom(p?.selector ?? {}),
    products: p?.products ?? ["sbom_sca"],
    branch: p?.branch ?? "",
    on_push: p?.on_push ?? false,
    schedule: { frequency: "off", time_of_day: "02:00", timezone: "UTC", ...(p?.schedule ?? {}) } as ScmSchedule,
    options: p?.options ?? {},
    expected_version: p?.row_version ?? null,
  };
}

function PolicyEditor({ teamId, policy, nextPosition, iacModeList, onClose }: {
  teamId: number;
  policy: ScmPolicy | null;
  nextPosition: number;
  iacModeList: string[];
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [body, setBody] = useState<ScmPolicyBody>(() => bodyFrom(policy, nextPosition));
  const [debounced, setDebounced] = useState<ScmFilters>(body.selector);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(body.selector), 400);
    return () => clearTimeout(t);
  }, [body.selector]);
  // the preview follows the debounced selector; Save sends the current one, so both must be valid
  const problem = filtersError(body.selector) ?? filtersError(debounced) ?? (body.products.length ? null : "Choose at least one product");
  const [touched, setTouched] = useState(false);
  const nameProblem = nameError(body.name);
  const preview = useQuery({
    queryKey: ["scm", teamId, "policy-preview", policy?.id ?? 0, JSON.stringify(debounced), body.products.join(","), body.position],
    queryFn: () => previewScmPolicy(teamId, { selector: debounced, products: body.products, position: body.position, policy_id: policy?.id ?? null }),
    enabled: !problem,
    placeholderData: (prev) => prev,
  });
  const save = useMutation({
    mutationFn: () => (policy ? updateScmPolicy(teamId, policy.id, body) : createScmPolicy(teamId, body)),
    onSuccess: () => {
      toast.success(policy ? "Policy saved" : "Policy created");
      qc.invalidateQueries({ queryKey: scmKeys.all(teamId) });
      onClose();
    },
  });
  const set = (patch: Partial<ScmPolicyBody>) => setBody((b) => ({ ...b, ...patch }));
  const sched = body.schedule;
  const iacModes = body.options.iac_modes ?? iacModeList;

  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-3xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{policy ? `Edit ${policy.name}` : "New scan policy"}</DialogTitle>
          <DialogDescription>Which repositories this policy covers, what scans them, and when.</DialogDescription>
        </DialogHeader>
        <div className="space-y-5">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Field label="Name" htmlFor="pol-name" required className="md:col-span-2" error={touched || body.name ? nameProblem : null}>
              <Input id="pol-name" value={body.name} onChange={(e) => set({ name: e.target.value })} onBlur={() => setTouched(true)} placeholder="PCI repositories nightly" />
            </Field>
            <Field label="Order" htmlFor="pol-pos" hint="Lower is tried first.">
              <Input id="pol-pos" inputMode="numeric" value={String(body.position)} onChange={(e) => set({ position: Math.max(0, Number(e.target.value) || 0) })} />
            </Field>
          </div>
          <div className="space-y-2">
            <p className="text-sm font-medium">Repositories it covers</p>
            <FiltersForm idPrefix="pol-sel" value={body.selector} onChange={(selector) => set({ selector })} />
          </div>
          <div className="space-y-2">
            <p className="text-sm font-medium">Scan with</p>
            <div className="flex flex-wrap gap-x-5 gap-y-2">
              {PRODUCTS.map((p) => (
                <Checkbox2 key={p} id={`pol-product-${p}`} checked={body.products.includes(p)}
                           onChange={(on) => set({ products: on ? [...body.products, p] : body.products.filter((x) => x !== p) })}>
                  {PRODUCT_LABEL[p]}
                </Checkbox2>
              ))}
            </div>
            {body.products.includes("iac") && (
              <div className="flex flex-wrap gap-x-4 gap-y-1 pl-1 pt-1" aria-label="IaC frameworks">
                {iacModeList.map((m) => (
                  <Checkbox2 key={m} id={`pol-iac-${m}`} checked={iacModes.includes(m)}
                             onChange={(on) => set({ options: { ...body.options, iac_modes: on ? [...iacModes, m] : iacModes.filter((x) => x !== m) } })}>
                    {m}
                  </Checkbox2>
                ))}
              </div>
            )}
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Field label="Branch" htmlFor="pol-branch" hint="Empty: each repository's default branch.">
              <Input id="pol-branch" value={body.branch} onChange={(e) => set({ branch: e.target.value })} placeholder="default branch" />
            </Field>
            <div className="space-y-2 md:pt-7">
              <Checkbox2 id="pol-push" checked={body.on_push} onChange={(v) => set({ on_push: v })}>
                Scan on every push to that branch (needs the connection&apos;s webhook)
              </Checkbox2>
              <Checkbox2 id="pol-enabled" checked={body.enabled} onChange={(v) => set({ enabled: v })}>
                Enabled (a disabled policy covers no repository, never fires and ignores pushes)
              </Checkbox2>
            </div>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Field label="Schedule" htmlFor="pol-freq">
              <Select value={sched.frequency} onValueChange={(v) => set({ schedule: { ...sched, frequency: v as ScmSchedule["frequency"] } })}>
                <SelectTrigger id="pol-freq" className="cursor-pointer"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="off">Off</SelectItem>
                  <SelectItem value="daily">Daily</SelectItem>
                  <SelectItem value="weekly">Weekly</SelectItem>
                  <SelectItem value="monthly">Monthly</SelectItem>
                </SelectContent>
              </Select>
            </Field>
            {sched.frequency !== "off" && (
              <>
                <Field label="Time" htmlFor="pol-time">
                  <Input id="pol-time" type="time" value={sched.time_of_day} onChange={(e) => set({ schedule: { ...sched, time_of_day: e.target.value } })} />
                </Field>
                {sched.frequency === "weekly" && (
                  <Field label="Day" htmlFor="pol-wday">
                    <Select value={String(sched.weekday ?? 6)} onValueChange={(v) => set({ schedule: { ...sched, weekday: Number(v) } })}>
                      <SelectTrigger id="pol-wday" className="cursor-pointer"><SelectValue /></SelectTrigger>
                      <SelectContent>{WEEKDAYS.map((d, i) => <SelectItem key={d} value={String(i)}>{d}</SelectItem>)}</SelectContent>
                    </Select>
                  </Field>
                )}
                {sched.frequency === "monthly" && (
                  <Field label="Day of month" htmlFor="pol-mday" hint="1 to 28">
                    <Input id="pol-mday" inputMode="numeric" value={String(sched.monthday ?? 1)}
                           onChange={(e) => set({ schedule: { ...sched, monthday: Math.min(28, Math.max(1, Number(e.target.value) || 1)) } })} />
                  </Field>
                )}
                <Field label="Time zone" htmlFor="pol-tz" hint="IANA name, e.g. Asia/Kolkata">
                  <Input id="pol-tz" value={sched.timezone} onChange={(e) => set({ schedule: { ...sched, timezone: e.target.value } })} />
                </Field>
              </>
            )}
          </div>
          <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 p-4 text-sm space-y-1" aria-live="polite" data-testid="policy-preview">
            {problem ? <p className="text-red-500" role="alert">{problem}</p> : preview.data ? (
              <>
                <p className="font-semibold text-zinc-900 dark:text-white">
                  Covers {repoCount(preview.data.repos)} in scope; one run costs about {formatCredits(preview.data.credits_per_run)}
                  {preview.isFetching && <Loader2 className="inline h-4 w-4 ml-2 animate-spin text-blue-600" />}
                </p>
                {Object.entries(preview.data.taken_by_other_policies).map(([name, n]) => (
                  <p key={name} className="text-zinc-600 dark:text-zinc-400">{n} matching repositories are covered first by the policy {name} (earlier in the order).</p>
                ))}
                {preview.data.sample.length > 0 && <p className="text-xs text-zinc-500 break-words">e.g. {preview.data.sample.slice(0, 6).join(", ")}</p>}
                <p className="text-xs text-zinc-500">{scheduleText(sched)}{body.on_push ? "; also on every push" : ""}.</p>
              </>
            ) : preview.isError ? <p className="text-red-500" role="alert">{refusalReason(preview.error) ?? "Could not preview."}</p> : (
              <p className="flex items-center gap-2 text-zinc-600"><Loader2 className="h-4 w-4 animate-spin" />Counting…</p>
            )}
          </div>
          {save.isError && <p className="text-sm text-red-500" role="alert">{refusalReason(save.error) ?? "Could not save the policy."}</p>}
        </div>
        {/* the editor is taller than a laptop screen: Save stays in view while the dialog scrolls */}
        <DialogFooter className="sticky -bottom-6 -mx-6 -mb-6 border-t border-zinc-200 dark:border-zinc-800 bg-background px-6 py-4">
          <Button variant="outline" className="cursor-pointer" onClick={onClose}>Cancel</Button>
          <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" disabled={Boolean(problem) || save.isPending}
                  onClick={() => { setTouched(true); if (!nameProblem) save.mutate(); }}>
            {save.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}{policy ? "Save" : "Create policy"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function PoliciesTab({ teamId, isAdmin }: { teamId: number; isAdmin: boolean }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: scmKeys.policies(teamId), queryFn: () => listScmPolicies(teamId) });
  const [editing, setEditing] = useState<ScmPolicy | null | "new">(null);
  const [running, setRunning] = useState<ScmPolicy | null>(null);
  const [deleting, setDeleting] = useState<ScmPolicy | null>(null);
  const remove = useMutation({
    mutationFn: (id: number) => deleteScmPolicy(teamId, id),
    onSuccess: () => { toast.success("Policy deleted"); setDeleting(null); qc.invalidateQueries({ queryKey: scmKeys.all(teamId) }); },
    onError: (err) => toast.error(refusalReason(err) ?? "Could not delete the policy"),
  });
  const policies = q.data?.policies ?? [];
  const nextPosition = policies.length ? Math.max(...policies.map((p) => p.position)) + 10 : 100;
  return (
    <SectionCard
      title="Scan policies"
      description="Tried in order: the first policy whose selector matches a repository covers it. Scheduled runs and push scans are charged per run."
      actions={isAdmin && (
        <Button size="sm" className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => setEditing("new")}>
          <Plus className="h-4 w-4 mr-1.5" />New policy
        </Button>
      )}
    >
      {q.isLoading ? <LoadingBlock /> : q.isError ? <ErrorBlock error={q.error} onRetry={() => q.refetch()} /> : !policies.length ? (
        <EmptyState title="No scan policies" body="A policy picks a group of repositories (by name, topic, language) and scans them on a schedule and/or on every push." />
      ) : (
        <ul className="divide-y divide-zinc-200 dark:divide-zinc-800">
          {policies.map((p) => (
            <li key={p.id} className="py-3 flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0 space-y-1">
                <p className="font-medium flex flex-wrap items-center gap-2">
                  <span className="text-xs text-zinc-500">#{p.position}</span>{p.name}
                  {!p.enabled && <StatusBadge tone="zinc">Disabled</StatusBadge>}
                  {p.on_push && <StatusBadge tone="blue">On push</StatusBadge>}
                </p>
                <p className="text-sm text-zinc-600 dark:text-zinc-400">
                  {p.products.map((x: ScmProduct) => PRODUCT_LABEL[x]).join(", ")} on {p.branch || "the default branch"} · {scheduleText(p.schedule)}
                  {" "}· covers {repoCount(p.repos_matched ?? 0)}
                </p>
                {p.next_run_at && <p className="text-xs text-zinc-500">Next run {new Date(p.next_run_at).toLocaleString()}</p>}
                {p.last_message && <p className="text-xs text-zinc-500">Last: {p.last_message}</p>}
              </div>
              {isAdmin && (
                <div className="flex gap-2">
                  <Button size="sm" variant="outline" className="cursor-pointer" onClick={() => setRunning(p)} disabled={!p.repos_matched}>
                    <Play className="h-4 w-4 mr-1.5" />Run now
                  </Button>
                  <Button size="icon" variant="outline" className="cursor-pointer h-8 w-8" aria-label={`Edit ${p.name}`} onClick={() => setEditing(p)}>
                    <Pencil className="h-4 w-4" />
                  </Button>
                  <Button size="icon" variant="outline" className="cursor-pointer h-8 w-8" aria-label={`Delete ${p.name}`} onClick={() => setDeleting(p)}>
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
      {editing && (
        <PolicyEditor teamId={teamId} policy={editing === "new" ? null : editing} nextPosition={nextPosition}
                      iacModeList={q.data?.iac_modes?.length ? q.data.iac_modes : IAC_MODES} onClose={() => setEditing(null)} />
      )}
      {running && (
        <RunDialog teamId={teamId} open onOpenChange={(v) => !v && setRunning(null)} target={{ policy_id: running.id }} title={`Run ${running.name} now`} />
      )}
      <ConfirmDialog
        open={Boolean(deleting)}
        onOpenChange={(v) => !v && setDeleting(null)}
        title={`Delete ${deleting?.name ?? "this policy"}?`}
        description="Its schedule stops. Repositories pinned to it fall back to the other policies. Queued scans keep running."
        confirmLabel="Delete"
        destructive
        pending={remove.isPending}
        onConfirm={() => deleting && remove.mutate(deleting.id)}
      />
    </SectionCard>
  );
}

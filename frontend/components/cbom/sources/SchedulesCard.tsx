"use client";

// Recurring collection runs (Review & Run): daily / weekly / monthly at a time in the team's window time zone.
// A slot charges credits like "Start scan" (skipped, with the reason, when the team has too few); network ranges need
// the SOC acknowledgement kept with the schedule; sources already queued are skipped.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CalendarClock, Pause, Pencil, Play, Trash2 } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  cbomOpsKeys,
  createCbomSchedule,
  deleteCbomSchedule,
  listCbomSchedules,
  updateCbomSchedule,
  type CbomFrequency,
  type CbomSchedule,
} from "@/utils/api/cbom_ops";

import { formatDateTime } from "./logic";
import { deleteScheduleText, SCHEDULE_GROUPS, scheduleBody, scheduleDraft, type ScheduleDraft } from "./scheduleForm";
import { Checkbox2, ConfirmDialog, EmptyState, ErrorBlock, Field, LoadingBlock, SectionCard, StatusBadge } from "./shared";

const WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];

function errorText(err: unknown): string {
  const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
  return typeof detail === "string" ? detail : "Could not save the schedule";
}

function when(s: CbomSchedule): string {
  if (s.frequency === "daily") return `Daily at ${s.time_of_day}`;
  if (s.frequency === "weekly") return `${WEEKDAYS[s.weekday ?? 0]}s at ${s.time_of_day}`;
  return `Monthly on day ${s.monthday} at ${s.time_of_day}`;
}

/** Add a schedule, or edit ``editing``: the same fields, and the server applies the same checks to both. */
function ScheduleForm({ teamId, timezone, editing, onDone }: {
  teamId: number; timezone: string; editing?: CbomSchedule | null; onDone: () => void;
}) {
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState<ScheduleDraft>(() => scheduleDraft(editing));
  const set = <K extends keyof ScheduleDraft>(key: K, value: ScheduleDraft[K]) => setDraft((d) => ({ ...d, [key]: value }));
  const [error, setError] = useState<string | null>(null);
  const prefix = editing ? `sched-${editing.id}` : "sched";
  const save = useMutation({
    mutationFn: () => editing
      ? updateCbomSchedule(teamId, editing.id, scheduleBody(draft, editing))
      : createCbomSchedule(teamId, scheduleBody(draft)),
    onSuccess: () => {
      toast.success(editing ? "Schedule saved" : "Schedule added");
      queryClient.invalidateQueries({ queryKey: cbomOpsKeys.schedules(teamId) });
      onDone();
    },
    onError: (err) => setError(errorText(err)),
  });
  return (
    <form className="space-y-3 rounded-md border border-zinc-200 dark:border-zinc-700 p-3"
          data-testid={editing ? `schedule-edit-form-${editing.id}` : "schedule-form"}
          aria-label={editing ? `Edit ${editing.name}` : "Add a schedule"}
          onSubmit={(e) => { e.preventDefault(); setError(null); save.mutate(); }}>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <Field label="Name" htmlFor={`${prefix}-name`} required>
          <Input id={`${prefix}-name`} value={draft.name} maxLength={64} onChange={(e) => set("name", e.target.value)} />
        </Field>
        <Field label="Repeat" htmlFor={`${prefix}-frequency`}>
          <Select value={draft.frequency} onValueChange={(v) => set("frequency", v as CbomFrequency)}>
            <SelectTrigger id={`${prefix}-frequency`} className="cursor-pointer"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="daily" className="cursor-pointer">Daily</SelectItem>
              <SelectItem value="weekly" className="cursor-pointer">Weekly</SelectItem>
              <SelectItem value="monthly" className="cursor-pointer">Monthly</SelectItem>
            </SelectContent>
          </Select>
        </Field>
        {draft.frequency === "weekly" && (
          <Field label="Day" htmlFor={`${prefix}-weekday`}>
            <Select value={String(draft.weekday)} onValueChange={(v) => set("weekday", Number(v))}>
              <SelectTrigger id={`${prefix}-weekday`} className="cursor-pointer"><SelectValue /></SelectTrigger>
              <SelectContent>
                {WEEKDAYS.map((d, i) => <SelectItem key={d} value={String(i)} className="cursor-pointer">{d}</SelectItem>)}
              </SelectContent>
            </Select>
          </Field>
        )}
        {draft.frequency === "monthly" && (
          <Field label="Day of month (1-28)" htmlFor={`${prefix}-monthday`}>
            <Input id={`${prefix}-monthday`} inputMode="numeric" value={String(draft.monthday)}
                   onChange={(e) => set("monthday", Math.max(1, Math.min(28, Number(e.target.value) || 1)))} />
          </Field>
        )}
        {/* the team's time zone: every schedule and scan window uses it (set with the scan window on Network TLS) */}
        <Field label={`Time (${timezone})`} htmlFor={`${prefix}-time`}
               hint="The team's time zone, set with the scan window on Network TLS. The scan window still applies">
          <Input id={`${prefix}-time`} type="time" value={draft.time} onChange={(e) => set("time", e.target.value)} />
        </Field>
      </div>
      <div className="flex flex-wrap gap-4">
        {SCHEDULE_GROUPS.map(([key, label]) => (
          <Checkbox2 key={key} id={`${prefix}-${key}`} checked={!!draft.groups[key]}
                     onChange={(v) => setDraft((d) => ({ ...d, groups: { ...d.groups, [key]: v } }))}>
            {label}
          </Checkbox2>
        ))}
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <Field label="Only sources with criticality" htmlFor={`${prefix}-crit`}>
          <Select value={draft.minCrit} onValueChange={(v) => set("minCrit", v)}>
            <SelectTrigger id={`${prefix}-crit`} className="cursor-pointer"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="any" className="cursor-pointer">Any</SelectItem>
              <SelectItem value="low" className="cursor-pointer">Low or higher</SelectItem>
              <SelectItem value="medium" className="cursor-pointer">Medium or higher</SelectItem>
              <SelectItem value="high" className="cursor-pointer">High or critical</SelectItem>
              <SelectItem value="critical" className="cursor-pointer">Critical only</SelectItem>
            </SelectContent>
          </Select>
        </Field>
        {draft.groups.network && (
          <Checkbox2 id={`${prefix}-soc`} checked={draft.soc} onChange={(v) => set("soc", v)}>
            My SOC has agreed these network ranges and scan windows for every scheduled run
          </Checkbox2>
        )}
      </div>
      {error && <p className="text-xs text-red-600 dark:text-red-400" role="alert">{error}</p>}
      <div className="flex gap-2">
        <Button type="submit" size="sm" className="cursor-pointer" disabled={save.isPending}
                data-testid={editing ? `schedule-save-${editing.id}` : "schedule-save"}>
          {editing ? "Save schedule" : "Add schedule"}
        </Button>
        <Button type="button" size="sm" variant="ghost" className="cursor-pointer" onClick={onDone}>Cancel</Button>
      </div>
      <p className="text-xs text-zinc-500">Each run is charged like a manual run. If the team has too few credits, that run is skipped and listed under Changes.</p>
    </form>
  );
}

export default function SchedulesCard({ teamId }: { teamId: number }) {
  const queryClient = useQueryClient();
  const [adding, setAdding] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [deleting, setDeleting] = useState<CbomSchedule | null>(null);
  const q = useQuery({ queryKey: cbomOpsKeys.schedules(teamId), queryFn: () => listCbomSchedules(teamId), retry: 1 });
  const toggle = useMutation({
    mutationFn: (s: CbomSchedule) => updateCbomSchedule(teamId, s.id, { enabled: !s.enabled, expected_version: s.row_version }),
    onSettled: () => queryClient.invalidateQueries({ queryKey: cbomOpsKeys.schedules(teamId) }),
    onError: (err) => toast.error(errorText(err)),
  });
  const remove = useMutation({
    mutationFn: (s: CbomSchedule) => deleteCbomSchedule(teamId, s.id),
    onSuccess: (_data, s) => {
      toast.success(`Schedule "${s.name}" deleted`);
      setDeleting(null);
      if (editingId === s.id) setEditingId(null);
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: cbomOpsKeys.schedules(teamId) }),
    onError: (err) => toast.error(errorText(err)),
  });
  const confirm = deleting ? deleteScheduleText(deleting) : null;
  return (
    <SectionCard title="Scheduled runs" description="Re-scan on a schedule to see what changed and prove fixes landed">
      <div className="space-y-3" data-testid="schedules-card">
        {q.isLoading ? <LoadingBlock /> : q.isError || !q.data ? <ErrorBlock onRetry={() => q.refetch()} /> : (
          <>
            {q.data.schedules.length === 0 && !adding && (
              <EmptyState title="No schedules" body="A weekly run keeps the inventory current and resolves findings that were fixed." />
            )}
            <ul className="divide-y divide-zinc-200 dark:divide-zinc-800">
              {q.data.schedules.map((s) => (
                <li key={s.id} className="py-2 space-y-2" data-testid={`schedule-${s.id}`}>
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="min-w-0 space-y-0.5">
                      <p className="text-sm font-medium text-zinc-900 dark:text-white flex items-center gap-2">
                        <CalendarClock className="h-4 w-4 text-zinc-500" />{s.name}
                        {!s.enabled && <StatusBadge tone="zinc">Paused</StatusBadge>}
                        {s.last_status === "skipped" && <StatusBadge tone="amber">Last slot skipped</StatusBadge>}
                      </p>
                      <p className="text-xs text-zinc-500">
                        {when(s)} ({q.data.timezone}) · {Object.entries(s.include).filter(([, v]) => v).map(([k]) => k).join(", ")}
                        {s.min_criticality ? ` · criticality ≥ ${s.min_criticality}` : ""}
                        {/* in the team's zone, like the slot time before it: a browser in another zone showed
                            "Daily at 19:11 (Asia/Kolkata) · next Nov 10, 01:41 PM" */}
                        {s.next_run_at ? ` · next ${formatDateTime(s.next_run_at, q.data.timezone)}` : ""}
                      </p>
                      {s.last_message && <p className="text-xs text-zinc-500 break-words">Last: {s.last_message}</p>}
                    </div>
                    <div className="flex gap-2">
                      <Button size="sm" variant="outline" className="cursor-pointer" onClick={() => setEditingId(editingId === s.id ? null : s.id)}
                              aria-label={`Edit ${s.name}`} aria-expanded={editingId === s.id} data-testid={`schedule-edit-${s.id}`}>
                        <Pencil className="h-4 w-4" />
                      </Button>
                      <Button size="sm" variant="outline" className="cursor-pointer" onClick={() => toggle.mutate(s)}
                              aria-label={s.enabled ? `Pause ${s.name}` : `Resume ${s.name}`}>
                        {s.enabled ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
                      </Button>
                      {/* one click deleted the schedule; it now asks first, naming it */}
                      <Button size="sm" variant="outline" className="cursor-pointer text-red-600" onClick={() => setDeleting(s)}
                              aria-label={`Delete ${s.name}`} data-testid={`schedule-delete-${s.id}`}>
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                  {editingId === s.id && (
                    <ScheduleForm key={`${s.id}-${s.row_version}`} teamId={teamId} timezone={q.data.timezone} editing={s}
                                  onDone={() => setEditingId(null)} />
                  )}
                </li>
              ))}
            </ul>
            {adding ? (
              <ScheduleForm teamId={teamId} timezone={q.data.timezone} onDone={() => setAdding(false)} />
            ) : (
              <Button size="sm" variant="outline" className="cursor-pointer" onClick={() => setAdding(true)} data-testid="schedule-add">
                Add a schedule
              </Button>
            )}
          </>
        )}
      </div>
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={confirm?.title ?? "Delete schedule?"}
        description={confirm?.description ?? ""}
        confirmLabel="Delete schedule"
        destructive
        pending={remove.isPending}
        onConfirm={() => deleting && remove.mutate(deleting)}
      />
    </SectionCard>
  );
}

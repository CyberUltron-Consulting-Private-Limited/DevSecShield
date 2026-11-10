"use client";

// Recurring collection runs (Review & Run): daily / weekly / monthly at a time in the team's window time zone.
// A slot charges credits like "Start scan" (skipped, with the reason, when the team has too few); network ranges need
// the SOC acknowledgement kept with the schedule; sources already queued are skipped.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CalendarClock, Pause, Play, Trash2 } from "lucide-react";
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
import { Checkbox2, EmptyState, ErrorBlock, Field, LoadingBlock, SectionCard, StatusBadge } from "./shared";

const GROUPS = [["servers", "Servers"], ["kubernetes", "Kubernetes"], ["databases", "Databases"], ["cloud", "Cloud and identity"],
  ["network", "Network ranges"]] as const;
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

function NewSchedule({ teamId, timezone, onDone }: { teamId: number; timezone: string; onDone: () => void }) {
  const queryClient = useQueryClient();
  const [name, setName] = useState("Weekly CBOM");
  const [frequency, setFrequency] = useState<CbomFrequency>("weekly");
  const [time, setTime] = useState("02:00");
  const [weekday, setWeekday] = useState(6);
  const [monthday, setMonthday] = useState(1);
  const [groups, setGroups] = useState<Record<string, boolean>>({ servers: true, kubernetes: true, databases: true, cloud: true, network: false });
  const [minCrit, setMinCrit] = useState<string>("any");
  const [soc, setSoc] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const save = useMutation({
    mutationFn: () => createCbomSchedule(teamId, {
      name: name.trim(), frequency, time_of_day: time, include: groups,
      ...(frequency === "weekly" ? { weekday } : {}), ...(frequency === "monthly" ? { monthday } : {}),
      min_criticality: minCrit === "any" ? null : minCrit, soc_ack: soc,
    }),
    onSuccess: () => {
      toast.success("Schedule added");
      queryClient.invalidateQueries({ queryKey: cbomOpsKeys.schedules(teamId) });
      onDone();
    },
    onError: (err) => setError(errorText(err)),
  });
  return (
    <form className="space-y-3 rounded-md border border-zinc-200 dark:border-zinc-700 p-3" data-testid="schedule-form"
          onSubmit={(e) => { e.preventDefault(); setError(null); save.mutate(); }}>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <Field label="Name" htmlFor="sched-name" required>
          <Input id="sched-name" value={name} maxLength={64} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="Repeat" htmlFor="sched-frequency">
          <Select value={frequency} onValueChange={(v) => setFrequency(v as CbomFrequency)}>
            <SelectTrigger id="sched-frequency" className="cursor-pointer"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="daily" className="cursor-pointer">Daily</SelectItem>
              <SelectItem value="weekly" className="cursor-pointer">Weekly</SelectItem>
              <SelectItem value="monthly" className="cursor-pointer">Monthly</SelectItem>
            </SelectContent>
          </Select>
        </Field>
        {frequency === "weekly" && (
          <Field label="Day" htmlFor="sched-weekday">
            <Select value={String(weekday)} onValueChange={(v) => setWeekday(Number(v))}>
              <SelectTrigger id="sched-weekday" className="cursor-pointer"><SelectValue /></SelectTrigger>
              <SelectContent>
                {WEEKDAYS.map((d, i) => <SelectItem key={d} value={String(i)} className="cursor-pointer">{d}</SelectItem>)}
              </SelectContent>
            </Select>
          </Field>
        )}
        {frequency === "monthly" && (
          <Field label="Day of month (1-28)" htmlFor="sched-monthday">
            <Input id="sched-monthday" inputMode="numeric" value={String(monthday)}
                   onChange={(e) => setMonthday(Math.max(1, Math.min(28, Number(e.target.value) || 1)))} />
          </Field>
        )}
        <Field label={`Time (${timezone})`} htmlFor="sched-time" hint="The team scan window still applies">
          <Input id="sched-time" type="time" value={time} onChange={(e) => setTime(e.target.value)} />
        </Field>
      </div>
      <div className="flex flex-wrap gap-4">
        {GROUPS.map(([key, label]) => (
          <Checkbox2 key={key} id={`sched-${key}`} checked={!!groups[key]} onChange={(v) => setGroups((g) => ({ ...g, [key]: v }))}>
            {label}
          </Checkbox2>
        ))}
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <Field label="Only sources with criticality" htmlFor="sched-crit">
          <Select value={minCrit} onValueChange={setMinCrit}>
            <SelectTrigger id="sched-crit" className="cursor-pointer"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="any" className="cursor-pointer">Any</SelectItem>
              <SelectItem value="medium" className="cursor-pointer">Medium or higher</SelectItem>
              <SelectItem value="high" className="cursor-pointer">High or critical</SelectItem>
              <SelectItem value="critical" className="cursor-pointer">Critical only</SelectItem>
            </SelectContent>
          </Select>
        </Field>
        {groups.network && (
          <Checkbox2 id="sched-soc" checked={soc} onChange={setSoc}>
            My SOC has agreed these network ranges and scan windows for every scheduled run
          </Checkbox2>
        )}
      </div>
      {error && <p className="text-xs text-red-600 dark:text-red-400" role="alert">{error}</p>}
      <div className="flex gap-2">
        <Button type="submit" size="sm" className="cursor-pointer" disabled={save.isPending} data-testid="schedule-save">Add schedule</Button>
        <Button type="button" size="sm" variant="ghost" className="cursor-pointer" onClick={onDone}>Cancel</Button>
      </div>
      <p className="text-xs text-zinc-500">Each run is charged like a manual run. If the team has too few credits, that run is skipped and listed under Changes.</p>
    </form>
  );
}

export default function SchedulesCard({ teamId }: { teamId: number }) {
  const queryClient = useQueryClient();
  const [adding, setAdding] = useState(false);
  const q = useQuery({ queryKey: cbomOpsKeys.schedules(teamId), queryFn: () => listCbomSchedules(teamId), retry: 1 });
  const toggle = useMutation({
    mutationFn: (s: CbomSchedule) => updateCbomSchedule(teamId, s.id, { enabled: !s.enabled, expected_version: s.row_version }),
    onSettled: () => queryClient.invalidateQueries({ queryKey: cbomOpsKeys.schedules(teamId) }),
    onError: (err) => toast.error(errorText(err)),
  });
  const remove = useMutation({
    mutationFn: (s: CbomSchedule) => deleteCbomSchedule(teamId, s.id),
    onSettled: () => queryClient.invalidateQueries({ queryKey: cbomOpsKeys.schedules(teamId) }),
    onError: (err) => toast.error(errorText(err)),
  });
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
                <li key={s.id} className="py-2 flex flex-wrap items-center justify-between gap-2" data-testid={`schedule-${s.id}`}>
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
                    <Button size="sm" variant="outline" className="cursor-pointer" onClick={() => toggle.mutate(s)}
                            aria-label={s.enabled ? `Pause ${s.name}` : `Resume ${s.name}`}>
                      {s.enabled ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
                    </Button>
                    <Button size="sm" variant="outline" className="cursor-pointer text-red-600" onClick={() => remove.mutate(s)}
                            aria-label={`Delete ${s.name}`}>
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </li>
              ))}
            </ul>
            {adding ? (
              <NewSchedule teamId={teamId} timezone={q.data.timezone} onDone={() => setAdding(false)} />
            ) : (
              <Button size="sm" variant="outline" className="cursor-pointer" onClick={() => setAdding(true)} data-testid="schedule-add">
                Add a schedule
              </Button>
            )}
          </>
        )}
      </div>
    </SectionCard>
  );
}

// Scheduled runs (Review & Run): the add / edit form's values and the body it sends. Pure, so it can be tested with tsx.
// Customer testing (round 5): a schedule could only be paused, resumed or deleted (one click, no confirmation); a
// wrong time or scope meant deleting it and adding it again. The edit form sends the same fields as the add form, so
// the server applies the same checks (backend routers/cbom_ops.py _apply_schedule) and, when the timing changes,
// moves the next run to the new slot in the team's time zone.

import type { CbomFrequency, CbomSchedule, CbomScheduleWrite } from "@/utils/api/cbom_ops";

export const SCHEDULE_GROUPS = [["servers", "Servers"], ["kubernetes", "Kubernetes"], ["databases", "Databases"],
  ["cloud", "Cloud and identity"], ["network", "Network ranges"]] as const;

export interface ScheduleDraft {
  name: string;
  frequency: CbomFrequency;
  time: string;
  weekday: number;
  monthday: number;
  groups: Record<string, boolean>;
  minCrit: string; // "any" | low | medium | high | critical
  soc: boolean;
}

/** The form's starting values: a new weekly schedule, or the schedule being edited. */
export function scheduleDraft(s?: CbomSchedule | null): ScheduleDraft {
  if (!s) {
    return { name: "Weekly CBOM", frequency: "weekly", time: "02:00", weekday: 6, monthday: 1,
      groups: { servers: true, kubernetes: true, databases: true, cloud: true, network: false }, minCrit: "any", soc: false };
  }
  const groups: Record<string, boolean> = {};
  for (const [key] of SCHEDULE_GROUPS) groups[key] = !!s.include?.[key];
  return { name: s.name, frequency: s.frequency, time: s.time_of_day, weekday: s.weekday ?? 0, monthday: s.monthday ?? 1,
    groups, minCrit: s.min_criticality ?? "any", soc: !!s.soc_ack };
}

/** The POST (no ``editing``) or PATCH body.  An edit re-sends the SOC acknowledgement only when it was changed, so
 * saving a schedule never re-stamps who agreed and when. */
export function scheduleBody(d: ScheduleDraft, editing?: CbomSchedule | null): CbomScheduleWrite {
  const body: CbomScheduleWrite = {
    name: d.name.trim(), frequency: d.frequency, time_of_day: d.time, include: { ...d.groups },
    weekday: d.frequency === "weekly" ? d.weekday : null, monthday: d.frequency === "monthly" ? d.monthday : null,
    min_criticality: d.minCrit === "any" ? null : d.minCrit,
  };
  if (!editing) return { ...body, soc_ack: d.soc };
  return { ...body, ...(d.soc !== !!editing.soc_ack ? { soc_ack: d.soc } : {}), expected_version: editing.row_version };
}

/** The confirmation before a schedule is deleted (it names the schedule). */
export function deleteScheduleText(s: Pick<CbomSchedule, "name">): { title: string; description: string } {
  return { title: `Delete schedule "${s.name}"?`,
    description: `"${s.name}" will no longer run. Runs it already started, and their results, are kept.` };
}

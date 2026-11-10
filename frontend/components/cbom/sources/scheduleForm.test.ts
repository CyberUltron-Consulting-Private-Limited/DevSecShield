/**
 * Scheduled runs (round 5 customer testing): a schedule could not be edited (only paused, resumed or deleted), and
 * deleting it was one click with no confirmation. The edit form starts from the schedule and sends the add form's
 * fields with the row version; the delete asks first, naming the schedule.
 * Run: npx --yes tsx components/cbom/sources/scheduleForm.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import type { CbomSchedule } from "@/utils/api/cbom_ops";
import { deleteScheduleText, scheduleBody, scheduleDraft } from "./scheduleForm";

const saved: CbomSchedule = {
  id: 7, name: "Nightly net", enabled: true, frequency: "weekly", time_of_day: "19:11", weekday: 2, monthday: null,
  include: { network: true, servers: false }, source_ids: [], min_criticality: "high", soc_ack: true,
  next_run_at: "2026-11-11T13:41:00Z", last_slot: null, last_run_id: null, last_status: null, last_message: null,
  row_version: 4,
};

// the edit form starts from the schedule
const draft = scheduleDraft(saved);
assert.deepEqual(draft, {
  name: "Nightly net", frequency: "weekly", time: "19:11", weekday: 2, monthday: 1,
  groups: { servers: false, kubernetes: false, databases: false, cloud: false, network: true }, minCrit: "high", soc: true,
});

// a new time and day: the add form's fields, the version, and no re-stamped SOC acknowledgement
assert.deepEqual(scheduleBody({ ...draft, time: "02:30", weekday: 5 }, saved), {
  name: "Nightly net", frequency: "weekly", time_of_day: "02:30", weekday: 5, monthday: null,
  include: { servers: false, kubernetes: false, databases: false, cloud: false, network: true },
  min_criticality: "high", expected_version: 4,
});
// weekly -> daily clears the day; un-ticking the SOC box is sent
const daily = scheduleBody({ ...draft, frequency: "daily", soc: false, minCrit: "any" }, saved);
assert.equal(daily.weekday, null);
assert.equal(daily.soc_ack, false);
assert.equal(daily.min_criticality, null);
// the add form (no schedule) always sends the acknowledgement and no version
const created = scheduleBody(scheduleDraft());
assert.equal(created.soc_ack, false);
assert.equal(created.expected_version, undefined);
assert.equal(created.weekday, 6);
assert.equal(scheduleBody({ ...scheduleDraft(), frequency: "monthly", monthday: 28, name: "  Monthly  " }).name, "Monthly");

// the delete confirmation names the schedule
assert.deepEqual(deleteScheduleText(saved), {
  title: 'Delete schedule "Nightly net"?',
  description: '"Nightly net" will no longer run. Runs it already started, and their results, are kept.',
});

// the card: Edit opens the form for that schedule; the delete button asks first (it never deletes on its own)
const card = fs.readFileSync(path.join(__dirname, "SchedulesCard.tsx"), "utf8");
assert.ok(card.includes("aria-label={`Edit ${s.name}`}"), "each schedule has an Edit button");
assert.ok(card.includes("updateCbomSchedule(teamId, editing.id, scheduleBody(draft, editing))"), "Edit saves with PATCH");
assert.ok(card.includes("onClick={() => setDeleting(s)}"), "the delete button opens the confirmation");
assert.equal((card.match(/remove\.mutate\(/g) ?? []).length, 1, "only the confirmation deletes");
assert.ok(card.includes("onConfirm={() => deleting && remove.mutate(deleting)}"));
console.log("scheduleForm tests passed");

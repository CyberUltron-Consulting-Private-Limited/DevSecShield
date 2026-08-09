/**
 * Hermetic tests for IST display helpers.
 * Run: npx --yes tsx utils/datetime.test.ts
 */
import assert from "node:assert/strict";
import {
  DISPLAY_TIMEZONE,
  DISPLAY_TZ_LABEL,
  formatChartDateIst,
  formatDateIst,
  formatDateOnlyIst,
  formatMediumDateIst,
  formatSlashDateIst,
  parseDisplayDate,
} from "./datetime";

assert.equal(DISPLAY_TIMEZONE, "Asia/Kolkata");
assert.equal(DISPLAY_TZ_LABEL, "IST");

// Fixed UTC instant → IST (+5:30)
{
  const utc = "2026-08-09T14:00:00.000Z"; // 19:30 IST
  const formatted = formatDateIst(utc);
  assert.ok(formatted.includes("IST"), `expected IST label: ${formatted}`);
  assert.ok(
    /9\s*Aug\s*2026|Aug\s*9,?\s*2026/i.test(formatted),
    `expected Aug 9 2026: ${formatted}`,
  );
  assert.ok(
    /7:30|19:30/i.test(formatted.replace(/\s/g, " ")) ||
      /07:30|7:30/.test(formatted),
    `expected 7:30 pm IST from 14:00Z: ${formatted}`,
  );
  // Must NOT still look like bare en-US browser-local without IST
  assert.equal(formatted.endsWith("IST"), true);
}

// Midnight UTC → next calendar morning in IST
{
  const utc = "2026-08-09T20:00:00.000Z"; // 01:30 IST on Aug 10
  const formatted = formatDateIst(utc);
  assert.ok(
    /10\s*Aug\s*2026|Aug\s*10,?\s*2026/i.test(formatted),
    `expected Aug 10 in IST: ${formatted}`,
  );
}

// Date-only chart / calendar day
{
  const d = formatDateOnlyIst("2026-01-15T00:00:00.000Z");
  assert.ok(/15/.test(d) && /Jan/i.test(d), `date-only: ${d}`);
  assert.ok(!d.includes("IST"), `date-only should omit IST label: ${d}`);
}

{
  const chart = formatChartDateIst("2026-03-05T12:00:00.000Z");
  assert.ok(/Mar/i.test(chart) && /5/.test(chart), `chart: ${chart}`);
}

{
  const medium = formatMediumDateIst("2026-03-05T12:00:00.000Z");
  assert.ok(medium.length > 0, "medium date non-empty");
}

// ISO parsing intact
{
  const d = parseDisplayDate("2026-08-09T14:00:00.000Z");
  assert.ok(d instanceof Date);
  assert.equal(d!.toISOString(), "2026-08-09T14:00:00.000Z");
}

{
  assert.equal(parseDisplayDate("not-a-date"), null);
  assert.equal(parseDisplayDate(null), null);
  assert.equal(parseDisplayDate(undefined), null);
  assert.equal(parseDisplayDate(""), null);
}

// Invalid input falls back gracefully
{
  assert.equal(formatDateIst("garbage-in"), "garbage-in");
  assert.equal(formatDateIst(null), "—");
  assert.equal(formatDateIst(undefined), "—");
}

// Date object input
{
  const d = new Date("2026-08-09T14:00:00.000Z");
  assert.ok(formatDateIst(d).endsWith("IST"));
}

{
  // 2026-08-09T20:00:00Z = Aug 10 01:30 IST → 08/10
  assert.equal(formatSlashDateIst("2026-08-09T20:00:00.000Z"), "08/10");
}

console.log("datetime.test.ts: all assertions passed");

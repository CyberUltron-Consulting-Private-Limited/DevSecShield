"use client";

// Month calendar of certificate expiry dates (UTC), coloured 30 / 60 / 90 days ahead. Hand-built: each day is a
// button; arrow keys move by day and week, Page Up / Page Down change the month, Enter shows that day's
// certificates. On a phone the grid stays seven narrow columns and the list sits below it.

import { ChevronLeft, ChevronRight } from "lucide-react";
import { useMemo, useRef, useState, type KeyboardEvent } from "react";

import { dayKey, daysLeft, expiryBand, groupByDay, monthGrid, parseExpiry, type ExpiryBand } from "./heatmapLogic";
import { InfoTip } from "@/components/ui/info-tip";

export interface CalendarCert {
  name?: string | null;
  not_after: string | null;
  subject?: string | null;
  issuer?: string | null;
  target?: string | null;
  location?: string | null;
  source_name?: string | null;
}

const BAND_TONE: Record<ExpiryBand, string> = {
  expired: "bg-red-800 text-white",
  "30": "bg-red-500 text-white",
  "60": "bg-amber-400 text-zinc-900",
  "90": "bg-yellow-200 text-zinc-900",
  later: "bg-sky-100 text-sky-900 dark:bg-sky-900/40 dark:text-sky-100",
};
const BAND_LABEL: Record<ExpiryBand, string> = {
  expired: "expired", "30": "within 30 days", "60": "within 60 days", "90": "within 90 days", later: "later",
};
const WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

function monthTitle(year: number, month: number): string {
  return new Date(Date.UTC(year, month, 1)).toLocaleString("en-GB", { month: "long", year: "numeric", timeZone: "UTC" });
}

export default function CertCalendar({ certs, now, testId = "cert-calendar" }: {
  certs: CalendarCert[];
  now?: Date;
  testId?: string;
}) {
  const today = useMemo(() => now ?? new Date(), [now]);
  const byDay = useMemo(() => groupByDay(certs), [certs]);
  const upcoming = useMemo(
    () => certs.map((c) => ({ c, d: parseExpiry(c.not_after) })).filter((x): x is { c: CalendarCert; d: Date } => !!x.d)
      .sort((a, b) => a.d.getTime() - b.d.getTime()),
    [certs],
  );
  const firstAhead = upcoming.find((x) => x.d.getTime() >= today.getTime())?.d ?? today;
  const [cursor, setCursor] = useState<{ y: number; m: number }>({ y: firstAhead.getUTCFullYear(), m: firstAhead.getUTCMonth() });
  const [focusDay, setFocusDay] = useState<number>(firstAhead.getUTCMonth() === cursor.m ? firstAhead.getUTCDate() : 1);
  const [selected, setSelected] = useState<string | null>(null);
  const refs = useRef<Map<number, HTMLButtonElement | null>>(new Map());
  const weeks = monthGrid(cursor.y, cursor.m);
  const daysInMonth = new Date(Date.UTC(cursor.y, cursor.m + 1, 0)).getUTCDate();

  const counts = { expired: 0, "30": 0, "60": 0, "90": 0, later: 0 } as Record<ExpiryBand, number>;
  for (const { d } of upcoming) counts[expiryBand(daysLeft(d, today))] += 1;

  const shift = (delta: number) => {
    const d = new Date(Date.UTC(cursor.y, cursor.m + delta, 1));
    setCursor({ y: d.getUTCFullYear(), m: d.getUTCMonth() });
    setFocusDay(1);
  };
  const focus = (day: number) => {
    if (day < 1) {
      const prev = new Date(Date.UTC(cursor.y, cursor.m, 0));
      setCursor({ y: prev.getUTCFullYear(), m: prev.getUTCMonth() });
      setFocusDay(prev.getUTCDate() + day);
      return;
    }
    if (day > daysInMonth) {
      const next = new Date(Date.UTC(cursor.y, cursor.m + 1, 1));
      setCursor({ y: next.getUTCFullYear(), m: next.getUTCMonth() });
      setFocusDay(day - daysInMonth);
      return;
    }
    setFocusDay(day);
    refs.current.get(day)?.focus();
  };
  const onKey = (e: KeyboardEvent<HTMLButtonElement>, day: number) => {
    const step: Record<string, number> = { ArrowLeft: -1, ArrowRight: 1, ArrowUp: -7, ArrowDown: 7 };
    if (step[e.key] !== undefined) {
      e.preventDefault();
      focus(day + step[e.key]);
    } else if (e.key === "PageUp" || e.key === "PageDown") {
      e.preventDefault();
      shift(e.key === "PageUp" ? -1 : 1);
    }
  };

  const listed = selected ? (byDay.get(selected) ?? []).map((c) => ({ c, d: parseExpiry(c.not_after)! }))
    : upcoming.filter((x) => x.d.getTime() >= today.getTime()).slice(0, 5);

  return (
    <div className="space-y-2 min-w-0" data-testid={testId}>
      <div className="flex items-center justify-between gap-2">
        <p className="text-sm font-medium text-zinc-900 dark:text-white">Certificate expiry <InfoTip id="cbom.cal.expiry" /></p>
        <div className="flex items-center gap-1">
          <button type="button" aria-label="Previous month" className="rounded p-1 hover:bg-zinc-100 dark:hover:bg-zinc-800 cursor-pointer"
                  onClick={() => shift(-1)} data-testid={`${testId}-prev`}><ChevronLeft className="h-4 w-4" /></button>
          <span className="text-sm text-zinc-700 dark:text-zinc-300 min-w-[8.5rem] text-center" aria-live="polite" data-testid={`${testId}-month`}>
            {monthTitle(cursor.y, cursor.m)}
          </span>
          <button type="button" aria-label="Next month" className="rounded p-1 hover:bg-zinc-100 dark:hover:bg-zinc-800 cursor-pointer"
                  onClick={() => shift(1)} data-testid={`${testId}-next`}><ChevronRight className="h-4 w-4" /></button>
        </div>
      </div>
      <div className="flex flex-wrap gap-1.5 text-xs" data-testid={`${testId}-bands`}>
        {(Object.keys(BAND_LABEL) as ExpiryBand[]).filter((b) => b !== "later").map((b) => (
          <span key={b} className={`rounded px-1.5 py-0.5 ${BAND_TONE[b]}`}>{counts[b]} {BAND_LABEL[b]}</span>
        ))}
      </div>
      <div role="grid" aria-label={`Certificates expiring in ${monthTitle(cursor.y, cursor.m)}`} className="grid grid-cols-7 gap-1">
        <div role="row" className="contents">
          {WEEKDAYS.map((w) => (
            <div key={w} role="columnheader" className="text-center text-[11px] text-zinc-500">{w}</div>
          ))}
        </div>
        {weeks.map((week, wi) => (
          <div key={wi} role="row" className="contents">
            {week.map((date, di) => {
              if (!date) return <div key={di} role="gridcell" aria-hidden="true" className="h-9 sm:h-10" />;
              const key = dayKey(date);
              const due = byDay.get(key) ?? [];
              const soonest = due.map((c) => parseExpiry(c.not_after)!).sort((a, b) => a.getTime() - b.getTime())[0];
              const band = soonest ? expiryBand(daysLeft(soonest, today)) : null;
              const day = date.getUTCDate();
              const isToday = key === dayKey(today);
              return (
                <div key={di} role="gridcell">
                  <button
                    type="button"
                    ref={(el) => { refs.current.set(day, el); }}
                    tabIndex={day === focusDay ? 0 : -1}
                    aria-label={`${day} ${monthTitle(cursor.y, cursor.m)}${due.length ? `: ${due.length} certificate${due.length === 1 ? "" : "s"} expire (${BAND_LABEL[band!]})` : ""}`}
                    aria-pressed={selected === key}
                    data-testid={due.length ? `${testId}-day-${key}` : undefined}
                    onFocus={() => setFocusDay(day)}
                    onKeyDown={(e) => onKey(e, day)}
                    onClick={() => setSelected(selected === key ? null : key)}
                    className={`relative h-9 sm:h-10 w-full rounded text-xs cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                      band ? BAND_TONE[band] : "text-zinc-700 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800"} ${
                      isToday ? "outline outline-1 outline-zinc-400" : ""} ${selected === key ? "ring-2 ring-zinc-900 dark:ring-white" : ""}`}
                  >
                    {day}
                    {due.length > 1 && <span className="absolute right-0.5 top-0 text-[9px] font-semibold">{due.length}</span>}
                  </button>
                </div>
              );
            })}
          </div>
        ))}
      </div>
      <div aria-live="polite" data-testid={`${testId}-list`}>
        <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400 mb-1">
          {selected ? `Expiring on ${selected}` : listed.length ? "Next to expire" : "No certificate expires after today"}
        </p>
        <ul className="space-y-1">
          {listed.map(({ c, d }, i) => (
            <li key={i} className="text-xs text-zinc-700 dark:text-zinc-300 break-words [overflow-wrap:anywhere]">
              <span className={`mr-1.5 rounded px-1 ${BAND_TONE[expiryBand(daysLeft(d, today))]}`}>{dayKey(d)}</span>
              {c.subject || c.name || "certificate"}
              {(c.target || c.location) && <span className="text-zinc-500"> · {c.target || c.location}</span>}
              {c.issuer && <span className="text-zinc-500"> · issued by {c.issuer}</span>}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

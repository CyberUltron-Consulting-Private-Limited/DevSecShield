"use client";

// Algorithm family x source (or asset type) heat-map, coloured by the worst impact in each cell. Hand-built CSS
// grid (no chart library): every cell with assets is a button, arrow keys move between cells (roving tabindex),
// Enter or a click shows the counts by impact. The box is as wide as its columns (a 3-column table does not leave an
// empty band beside it) and scrolls sideways only when the columns do not fit, e.g. on a phone.
// metric="grade" (CB-19 PR-3, run heat-map only): cells are coloured by the worst known quantum risk grade the server
// sent (worst_grade; Q0 Unknown only when the cell has no known grade) and the detail counts them by grade.

import { useMemo, useRef, useState, type KeyboardEvent } from "react";

import { GRADE_BUCKETS, GRADE_KEYS, gradeText, isGrade, type GradeBucket } from "./grade/model";
import { IMPACT_ORDER, type HeatCell, type HeatData, type HeatImpact } from "./heatmapLogic";

const TONE: Record<HeatImpact, string> = {
  Critical: "bg-red-700 text-white",
  High: "bg-red-500 text-white",
  Medium: "bg-amber-400 text-zinc-900",
  Low: "bg-sky-300 text-zinc-900",
  none: "bg-emerald-100 text-emerald-900 dark:bg-emerald-900/40 dark:text-emerald-100",
};
const LABEL: Record<HeatImpact, string> = { Critical: "Critical", High: "High", Medium: "Medium", Low: "Low", none: "No finding" };
// the risk palette of the grade chips (grade/model.ts PALETTE), solid for a cell; text always next to the colour
// in GRADE_KEYS' order (unknown, critical, high, medium, low), then "none"
const GRADE_CELL = ["bg-zinc-400 text-zinc-900", "bg-red-600 text-white", "bg-orange-500 text-white",
  "bg-amber-400 text-zinc-900", "bg-green-600 text-white"];
const GRADE_TONE = {
  ...Object.fromEntries(GRADE_KEYS.map((k, i) => [k, GRADE_CELL[i]])),
  none: "bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-300",
} as Record<GradeBucket, string>;
const gradeLabel = (g: GradeBucket): string => (g === "none" ? "No grade" : gradeText(g) ?? g);
const cellGrade = (cell: HeatCell): GradeBucket => (isGrade(cell.worst_grade) ? cell.worst_grade : "none");

export default function CryptoHeatmap({ data, title = "Algorithm families", columnLabel, testId = "crypto-heatmap",
  metric = "impact", onSelect }: {
  data: HeatData;
  title?: string;
  columnLabel?: (column: string) => string;
  testId?: string;
  /** "grade": colour and count by quantum risk grade (the cells must carry by_grade / worst_grade) */
  metric?: "impact" | "grade";
  /** the selected cell (null when none), e.g. to list its assets below the map */
  onSelect?: (cell: HeatCell | null) => void;
}) {
  const byGrade = metric === "grade";
  const byKey = useMemo(() => new Map(data.cells.map((c) => [`${c.row}\u0000${c.column}`, c])), [data.cells]);
  const [active, setActive] = useState<[number, number]>([0, 0]);
  const [selected, setSelected] = useState<[number, number] | null>(null);
  const refs = useRef<Map<string, HTMLButtonElement | null>>(new Map());
  const label = (c: string) => (columnLabel ? columnLabel(c) : c);

  if (data.rows.length === 0 || data.columns.length === 0) {
    return <p className="text-xs text-zinc-500" data-testid={`${testId}-empty`}>No assets to map.</p>;
  }

  const move = (r: number, c: number) => {
    const row = Math.max(0, Math.min(data.rows.length - 1, r));
    const col = Math.max(0, Math.min(data.columns.length - 1, c));
    setActive([row, col]);
    refs.current.get(`${row}:${col}`)?.focus();
  };
  const onKey = (e: KeyboardEvent<HTMLButtonElement>, r: number, c: number) => {
    const step: Record<string, [number, number]> = { ArrowUp: [-1, 0], ArrowDown: [1, 0], ArrowLeft: [0, -1], ArrowRight: [0, 1] };
    if (step[e.key]) {
      e.preventDefault();
      move(r + step[e.key][0], c + step[e.key][1]);
    } else if (e.key === "Home") {
      e.preventDefault();
      move(r, 0);
    } else if (e.key === "End") {
      e.preventDefault();
      move(r, data.columns.length - 1);
    }
  };
  const chosen = selected ? byKey.get(`${data.rows[selected[0]]}\u0000${data.columns[selected[1]]}`) : undefined;

  return (
    <div className="space-y-2 min-w-0" data-testid={testId}>
      <p className="text-sm font-medium text-zinc-900 dark:text-white">{title}</p>
      <div className="overflow-x-auto w-fit max-w-full rounded-md border border-zinc-200 dark:border-zinc-800">
        <div
          role="grid"
          aria-label={`${title}: algorithm family by ${data.columns.length} columns, coloured by worst impact`}
          className="grid gap-px bg-zinc-200 dark:bg-zinc-800"
          style={{ gridTemplateColumns: `minmax(8.5rem, max-content) repeat(${data.columns.length}, minmax(4.75rem, 11rem))` }}
        >
          <div role="row" className="contents">
            <div role="columnheader" className="bg-white dark:bg-zinc-950 px-2 py-1.5 text-xs font-medium text-zinc-500 sticky left-0 z-10">
              Family
            </div>
            {data.columns.map((col) => (
              <div key={col} role="columnheader" title={label(col)}
                   className="bg-white dark:bg-zinc-950 px-2 py-1.5 text-xs font-medium text-zinc-600 dark:text-zinc-300 truncate min-w-0">
                {label(col)}
              </div>
            ))}
          </div>
          {data.rows.map((row, r) => (
            <div key={row} role="row" className="contents">
              <div role="rowheader" className="bg-white dark:bg-zinc-950 px-2 py-1.5 text-xs text-zinc-800 dark:text-zinc-200 sticky left-0 z-10 whitespace-nowrap">
                {row}
              </div>
              {data.columns.map((col, c) => {
                const cell = byKey.get(`${row}\u0000${col}`);
                const isActive = active[0] === r && active[1] === c;
                const isSelected = !!selected && selected[0] === r && selected[1] === c;
                return (
                  <div key={col} role="gridcell" className="bg-white dark:bg-zinc-950">
                    <button
                      type="button"
                      ref={(el) => { refs.current.set(`${r}:${c}`, el); }}
                      tabIndex={isActive ? 0 : -1}
                      aria-label={cell ? `${row} in ${label(col)}: ${cell.count} asset${cell.count === 1 ? "" : "s"}, worst ${byGrade ? gradeLabel(cellGrade(cell)) : LABEL[cell.worst]}` : `${row} in ${label(col)}: none`}
                      aria-pressed={isSelected}
                      data-testid={cell ? `heat-cell-${row}-${col}` : undefined}
                      onFocus={() => setActive([r, c])}
                      onKeyDown={(e) => onKey(e, r, c)}
                      data-worst={cell ? (byGrade ? cellGrade(cell) : cell.worst) : undefined}
                      onClick={() => {
                        setSelected(isSelected ? null : [r, c]);
                        onSelect?.(isSelected || !cell ? null : cell);
                      }}
                      className={`h-9 w-full text-xs font-semibold cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-inset ${
                        cell ? (byGrade ? GRADE_TONE[cellGrade(cell)] : TONE[cell.worst]) : "text-zinc-300 dark:text-zinc-700"} ${isSelected ? "ring-2 ring-inset ring-zinc-900 dark:ring-white" : ""}`}
                    >
                      {cell ? cell.count : "·"}
                    </button>
                  </div>
                );
              })}
            </div>
          ))}
        </div>
      </div>
      <div className="flex flex-wrap gap-2 text-xs text-zinc-600 dark:text-zinc-400" aria-hidden="true">
        {byGrade
          ? GRADE_BUCKETS.map((g) => (
            <span key={g} className="inline-flex items-center gap-1"><span className={`h-3 w-3 rounded-sm ${GRADE_TONE[g].split(" ")[0]}`} />{gradeLabel(g)}</span>
          ))
          : IMPACT_ORDER.map((i) => (
            <span key={i} className="inline-flex items-center gap-1"><span className={`h-3 w-3 rounded-sm ${TONE[i].split(" ")[0]}`} />{LABEL[i]}</span>
          ))}
      </div>
      <p className="text-xs text-zinc-600 dark:text-zinc-400 min-h-[1rem]" aria-live="polite" data-testid={`${testId}-detail`}>
        {chosen
          ? `${chosen.row} in ${label(chosen.column)}: ${chosen.count} asset${chosen.count === 1 ? "" : "s"} — ` +
            (byGrade
              ? GRADE_BUCKETS.filter((g) => chosen.by_grade?.[g]).map((g) => `${chosen.by_grade?.[g]} ${gradeLabel(g)}`).join(", ")
              : IMPACT_ORDER.filter((i) => chosen.by_impact[i]).map((i) => `${chosen.by_impact[i]} ${LABEL[i].toLowerCase()}`).join(", "))
          : `Select a cell for its counts by ${byGrade ? "quantum risk grade" : "impact"} (arrow keys move between cells).`}
      </p>
    </div>
  );
}

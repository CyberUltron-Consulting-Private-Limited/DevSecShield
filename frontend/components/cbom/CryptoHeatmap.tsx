"use client";

// Algorithm family x source (or asset type) heat-map, coloured by the worst impact in each cell. Hand-built CSS
// grid (no chart library): every cell with assets is a button, arrow keys move between cells (roving tabindex),
// Enter or a click shows the counts by impact; the grid scrolls sideways on small screens.

import { useMemo, useRef, useState, type KeyboardEvent } from "react";

import { IMPACT_ORDER, type HeatData, type HeatImpact } from "./heatmapLogic";

const TONE: Record<HeatImpact, string> = {
  Critical: "bg-red-700 text-white",
  High: "bg-red-500 text-white",
  Medium: "bg-amber-400 text-zinc-900",
  Low: "bg-sky-300 text-zinc-900",
  none: "bg-emerald-100 text-emerald-900 dark:bg-emerald-900/40 dark:text-emerald-100",
};
const LABEL: Record<HeatImpact, string> = { Critical: "Critical", High: "High", Medium: "Medium", Low: "Low", none: "No finding" };

export default function CryptoHeatmap({ data, title = "Algorithm families", columnLabel, testId = "crypto-heatmap" }: {
  data: HeatData;
  title?: string;
  columnLabel?: (column: string) => string;
  testId?: string;
}) {
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
      <div className="overflow-x-auto rounded-md border border-zinc-200 dark:border-zinc-800">
        <div
          role="grid"
          aria-label={`${title}: algorithm family by ${data.columns.length} columns, coloured by worst impact`}
          className="grid gap-px bg-zinc-200 dark:bg-zinc-800 min-w-max"
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
                      aria-label={cell ? `${row} in ${label(col)}: ${cell.count} asset${cell.count === 1 ? "" : "s"}, worst ${LABEL[cell.worst]}` : `${row} in ${label(col)}: none`}
                      aria-pressed={isSelected}
                      data-testid={cell ? `heat-cell-${row}-${col}` : undefined}
                      onFocus={() => setActive([r, c])}
                      onKeyDown={(e) => onKey(e, r, c)}
                      onClick={() => setSelected(isSelected ? null : [r, c])}
                      className={`h-9 w-full text-xs font-semibold cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-inset ${
                        cell ? TONE[cell.worst] : "text-zinc-300 dark:text-zinc-700"} ${isSelected ? "ring-2 ring-inset ring-zinc-900 dark:ring-white" : ""}`}
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
        {IMPACT_ORDER.map((i) => (
          <span key={i} className="inline-flex items-center gap-1"><span className={`h-3 w-3 rounded-sm ${TONE[i].split(" ")[0]}`} />{LABEL[i]}</span>
        ))}
      </div>
      <p className="text-xs text-zinc-600 dark:text-zinc-400 min-h-[1rem]" aria-live="polite" data-testid={`${testId}-detail`}>
        {chosen
          ? `${chosen.row} in ${label(chosen.column)}: ${chosen.count} asset${chosen.count === 1 ? "" : "s"} — ` +
            IMPACT_ORDER.filter((i) => chosen.by_impact[i]).map((i) => `${chosen.by_impact[i]} ${LABEL[i].toLowerCase()}`).join(", ")
          : "Select a cell for its counts by impact (arrow keys move between cells)."}
      </p>
    </div>
  );
}

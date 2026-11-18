// Staging QA round 4 (E): below 768 px the findings table's Details / Action column is off-screen (it is pinned to the
// right edge only from md up), and nothing said that a tap on the row opens the finding. Each row of both findings
// tables (code scan and Sources run) now starts with this "Open" chevron on narrow widths: a real button (keyboard and
// screen readers reach it) that opens the same dialog as a tap on the row.

import { ChevronRight } from "lucide-react";

export function RowOpenButton({ label, onOpen }: { label: string; onOpen: () => void }) {
  return (
    <button type="button" aria-label={label} title={label} data-testid="row-open"
            className="md:hidden inline-flex size-7 shrink-0 items-center justify-center rounded-md border border-zinc-200 text-zinc-600 hover:bg-zinc-100 hover:text-zinc-900 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800 cursor-pointer"
            onClick={(e) => { e.stopPropagation(); onOpen(); }}>
      <ChevronRight className="size-4" aria-hidden />
      <span className="sr-only">Open</span>
    </button>
  );
}

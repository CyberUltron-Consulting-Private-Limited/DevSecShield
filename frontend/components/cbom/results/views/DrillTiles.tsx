"use client";

// Drill down (results redesign 00-C): one tile per detail view with the figure that view shows (selectors.ts reads the
// same payloads; no chart is mounted here). "Open" pushes a history entry, so Back returns to the summary.

import { ChevronRight, Loader2 } from "lucide-react";

import { CARD_ARROW, CLICKABLE_CARD, cardOpenProps } from "../findingTable";

import { InfoTip } from "@/components/ui/info-tip";
import type { InfoTipId } from "@/content/infotips";

import type { TileFigure } from "./selectors";
import { SECTION_META } from "./types";
import { DETAIL_SECTIONS, type DetailSection } from "./url";

export function DrillTile({ section, title, infoId, figure, holds, onOpen }: {
  section: DetailSection; title: string; infoId: InfoTipId; figure: TileFigure; holds: string; onOpen: () => void;
}) {
  return (
    // the whole tile opens the view (its "Open" button stays the keyboard stop); hover shows that it is clickable
    <li className={`flex flex-col gap-2 rounded-xl border border-zinc-200 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-900 min-w-0 ${CLICKABLE_CARD}`}
        data-testid={`results-tile-${section}`} {...cardOpenProps(onOpen)}>
      <h3 className="text-sm font-semibold text-zinc-900 dark:text-white">{title} <InfoTip id={infoId} /></h3>
      <p className="text-sm text-zinc-700 dark:text-zinc-300 tabular-nums [overflow-wrap:anywhere]" data-testid={`results-tile-${section}-value`}
         aria-busy={figure.loading || undefined}>
        {figure.loading ? <Loader2 className="inline h-4 w-4 animate-spin text-zinc-400" aria-label="Loading" /> : figure.value}
      </p>
      <p className="text-xs text-zinc-500 dark:text-zinc-400" data-testid={`results-tile-${section}-note`}>{figure.note ?? holds}</p>
      <button type="button" onClick={onOpen} aria-label={`Open ${title}`}
              className="mt-auto inline-flex items-center gap-0.5 self-start text-sm font-medium text-blue-600 group-hover:underline hover:underline dark:text-blue-400 cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded"
              data-testid={`results-tile-${section}-open`}>
        Open <ChevronRight className={`h-4 w-4 ${CARD_ARROW}`} aria-hidden />
      </button>
    </li>
  );
}

export function DrillTiles({ figures, onOpen }: {
  figures: Record<DetailSection, TileFigure>;
  onOpen: (section: DetailSection) => void;
}) {
  return (
    <section className="space-y-3" data-testid="results-drill">
      <h2 className="text-base font-semibold text-zinc-900 dark:text-white">Drill down <InfoTip id="cbom.run.drill" /></h2>
      <ul className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
        {DETAIL_SECTIONS.map((s) => (
          <DrillTile key={s} section={s} title={SECTION_META[s].title} infoId={SECTION_META[s].tip} holds={SECTION_META[s].holds}
                     figure={figures[s]} onOpen={() => onOpen(s)} />
        ))}
      </ul>
    </section>
  );
}
